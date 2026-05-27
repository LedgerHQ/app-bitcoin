#!/usr/bin/env python3
"""Bitcoin app playground CLI.

A single-shot CLI for exercising the Ledger Bitcoin app's APDU commands
against speculos or a real device. Each subcommand maps to one APDU so you
can watch the corresponding UX flow on the device screen.

Wallet-policy subcommands accept a fully-resolved policy via inline flags:

    --template "wsh(or_d(pk(@0/**),pkh(@1/**)))"
    --key      "[f5acc2fd/48'/1'/0'/2']tpubDE...XYZ"
    --key      "[d34db33f/48'/1'/0'/2']tpubDC...ABC"
    --name     "Joint account"

Run from the repo root, e.g.

    python dev-tools/playground/cli.py get-fingerprint
    python dev-tools/playground/cli.py get-xpub "m/86'/1'/0'" --display
    python dev-tools/playground/cli.py register-wallet \\
        --name "Joint account" \\
        --template "wsh(or_d(pk(@0/**),pkh(@1/**)))" \\
        --key "[f5acc2fd/...]tpub..." --key "[d34db33f/...]tpub..."

Standard single-sig policies (pkh, sh(wpkh), wpkh, tr with a single key)
do not need registration; pass `--name ""` (the default) for those.

Speculos is expected to be already running (default 127.0.0.1:9999).
"""

import argparse
import sys
from pathlib import Path
from typing import List, Optional, Tuple

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parents[1]
for p in (_REPO_ROOT, _HERE):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from bitcoin_client.ledger_bitcoin import (  # noqa: E402
    Chain,
    MusigPartialSignature,
    MusigPubNonce,
    TransportClient,
    WalletPolicy,
    createClient,
)
from bitcoin_client.ledger_bitcoin.client_base import Client  # noqa: E402
from bitcoin_client.ledger_bitcoin.psbt import PSBT  # noqa: E402

from presets import (  # noqa: E402
    cache_file_path,
    cached_registration,
    store_registration,
)


# ----- connection -----------------------------------------------------------

CHAIN_BY_NAME = {
    "main": Chain.MAIN,
    "test": Chain.TEST,
    "regtest": Chain.REGTEST,
    "signet": Chain.SIGNET,
}


def open_client(args: argparse.Namespace) -> Client:
    if args.target == "speculos":
        transport = TransportClient(
            interface="tcp",
            server=args.host,
            port=args.port,
            debug=args.debug,
        )
    else:  # hid
        transport = TransportClient(interface="hid", debug=args.debug)
    return createClient(transport, chain=CHAIN_BY_NAME[args.chain], debug=args.debug)


# ----- policy building & registration ---------------------------------------

def _build_policy(args: argparse.Namespace) -> WalletPolicy:
    keys = list(args.keys or [])
    if not args.template:
        raise SystemExit("--template is required")
    if not keys:
        raise SystemExit("at least one --key is required")
    return WalletPolicy(args.name or "", args.template, keys)


def ensure_registered(
    client: Client,
    master_fpr_hex: str,
    policy: WalletPolicy,
    refresh: bool,
) -> Optional[bytes]:
    """Return the wallet HMAC for `policy`, registering on-device if needed,
    or `None` for standard policies (empty name) that don't require it.

    The cache is keyed on `(master_fpr, policy.id)` so any change to the
    template or keys silently invalidates it.
    """
    if policy.name == "":
        return None

    wallet_id = policy.id
    if not refresh:
        cached = cached_registration(master_fpr_hex, wallet_id)
        if cached is not None:
            print(
                f"[cache] using cached HMAC for {policy.name!r} "
                f"(fingerprint {master_fpr_hex}). Pass --no-cache to re-register.",
                file=sys.stderr,
            )
            return cached

    print(
        f"[register] registering wallet policy {policy.name!r} on device — "
        "approve on screen...",
        file=sys.stderr,
    )
    wallet_id, wallet_hmac = client.register_wallet(policy)
    store_registration(master_fpr_hex, wallet_id, wallet_hmac)
    print(f"[register] id:   {wallet_id.hex()}", file=sys.stderr)
    print(f"[register] hmac: {wallet_hmac.hex()}", file=sys.stderr)
    return wallet_hmac


# ----- helpers --------------------------------------------------------------

def load_psbt(path: Path) -> PSBT:
    psbt = PSBT()
    psbt.deserialize(path.read_text().strip())
    return psbt


def make_fake_psbt(policy: WalletPolicy, n_inputs: int, n_outputs: int) -> PSBT:
    """Build a fake-but-valid-looking PSBT spending from `policy`.

    Reuses `test_utils.txmaker.createPsbt`, which only needs the *xpubs* from
    the wallet's keys_info to derive credible prevout scripts — no private
    keys involved. The synthetic prevouts won't exist on any chain, but the
    PSBT is well-formed enough for the app to display and sign.
    """
    from test_utils.txmaker import createPsbt  # local import (heavy)

    if n_inputs < 1 or n_outputs < 1:
        raise SystemExit("--inputs and --outputs must be >= 1")

    input_amounts = [100_000_000 + 10_000_000 * i for i in range(n_inputs)]
    total_in = sum(input_amounts)
    fee = 1_000

    if n_outputs == 1:
        # Send everything (minus fee) back to ourselves as change.
        output_amounts = [total_in - fee]
        output_is_change = [True]
    else:
        n_recipients = n_outputs - 1
        change_amount = max(10_000, total_in // (n_outputs + 1))
        per_recipient = (total_in - change_amount - fee) // n_recipients
        output_amounts = [per_recipient] * n_recipients + [
            total_in - per_recipient * n_recipients - fee
        ]
        output_is_change = [False] * n_recipients + [True]

    return createPsbt(policy, input_amounts, output_amounts, output_is_change)


def sign_psbt_musig2(
    client: Client,
    policy: WalletPolicy,
    wallet_hmac: Optional[bytes],
    psbt: PSBT,
    external_xprivs: List[str],
) -> List[Tuple[int, object]]:
    """Drive both rounds of a BIP-327 musig2 signing session.

    Round 1 (silent on the device): the device returns its `MusigPubNonce`
    for each musig input. We add it to the PSBT, then each external
    `HotMusig2Cosigner` (one per `external_xprivs[i]`) adds theirs. Round 2
    (interactive — review on device): the device returns its
    `MusigPartialSignature`; external cosigners then contribute theirs.

    If `external_xprivs` is empty, only round 1 is performed and the
    returned tuples are the device's pubnonces. To complete signing, supply
    every cosigner's xpriv.
    """
    from test_utils.musig2 import HotMusig2Cosigner  # noqa: E402

    externals = [HotMusig2Cosigner(policy, xpriv) for xpriv in external_xprivs]

    # ---- Round 1 -----------------------------------------------------------
    print(
        "[musig2] Round 1: fetching pubnonces from device (silent, no UX)...",
        file=sys.stderr,
    )
    round1 = client.sign_psbt(psbt, policy, wallet_hmac)
    for input_index, obj in round1:
        if not isinstance(obj, MusigPubNonce):
            raise RuntimeError(
                f"Expected MusigPubNonce in round 1, got {type(obj).__name__}: {obj}"
            )
        psbt.inputs[input_index].musig2_pub_nonces[
            (obj.participant_pubkey, obj.aggregate_pubkey, obj.tapleaf_hash)
        ] = obj.pubnonce

    if not externals:
        print(
            "[musig2] no external cosigners supplied (--external-xpriv); "
            "stopping after round 1. Pass each cosigner xpriv to complete signing.",
            file=sys.stderr,
        )
        return round1

    print(
        f"[musig2] device added {len(round1)} pubnonce(s); "
        f"now collecting from {len(externals)} external cosigner(s)...",
        file=sys.stderr,
    )
    for cosigner in externals:
        cosigner.generate_public_nonces(psbt)

    # ---- Round 2 -----------------------------------------------------------
    print(
        "[musig2] Round 2: requesting partial signatures from device — "
        "review and confirm transaction on device...",
        file=sys.stderr,
    )
    round2 = client.sign_psbt(psbt, policy, wallet_hmac)
    for input_index, obj in round2:
        if not isinstance(obj, MusigPartialSignature):
            raise RuntimeError(
                f"Expected MusigPartialSignature in round 2, got {type(obj).__name__}: {obj}"
            )
        psbt.inputs[input_index].musig2_partial_sigs[
            (obj.participant_pubkey, obj.aggregate_pubkey, obj.tapleaf_hash)
        ] = obj.partial_signature
    print(
        f"[musig2] device added {len(round2)} partial signature(s); "
        f"now collecting from {len(externals)} external cosigner(s)...",
        file=sys.stderr,
    )
    for cosigner in externals:
        cosigner.generate_partial_signatures(psbt)

    return round2


def print_signatures(results: List[Tuple[int, object]]) -> None:
    if not results:
        print("(no signatures returned)")
        return
    for input_index, obj in results:
        print(f"Input #{input_index}: {obj}")


# ----- subcommands ----------------------------------------------------------

def cmd_get_fingerprint(args: argparse.Namespace) -> None:
    with open_client(args) as client:
        fpr = client.get_master_fingerprint()
    print(fpr.hex())


def cmd_get_xpub(args: argparse.Namespace) -> None:
    with open_client(args) as client:
        if args.display:
            print("Confirm on device...", file=sys.stderr)
        xpub = client.get_extended_pubkey(args.path, display=args.display)
    print(xpub)


def cmd_register_wallet(args: argparse.Namespace) -> None:
    policy = _build_policy(args)
    if policy.name == "":
        raise SystemExit(
            "register-wallet requires a non-empty --name "
            "(standard single-sig policies don't need registration)."
        )
    with open_client(args) as client:
        master_fpr = client.get_master_fingerprint().hex()
        print(f"Resolved policy:\n  {policy.descriptor_template}", file=sys.stderr)
        for k in policy.keys_info:
            print(f"  {k}", file=sys.stderr)
        print("Approve registration on device...", file=sys.stderr)
        wallet_id, wallet_hmac = client.register_wallet(policy)
    store_registration(master_fpr, wallet_id, wallet_hmac)
    print(f"id:   {wallet_id.hex()}")
    print(f"hmac: {wallet_hmac.hex()}")


def cmd_get_address(args: argparse.Namespace) -> None:
    policy = _build_policy(args)
    with open_client(args) as client:
        master_fpr = client.get_master_fingerprint().hex()
        hmac = ensure_registered(client, master_fpr, policy, refresh=args.no_cache)
        if args.display:
            print("Confirm address on device...", file=sys.stderr)
        addr = client.get_wallet_address(
            policy, hmac, args.change, args.index, args.display
        )
    print(addr)


def cmd_sign_psbt(args: argparse.Namespace) -> None:
    policy = _build_policy(args)
    external_xprivs = list(getattr(args, "external_xprivs", None) or [])

    with open_client(args) as client:
        master_fpr = client.get_master_fingerprint().hex()
        hmac = ensure_registered(client, master_fpr, policy, refresh=args.no_cache)

        if args.fixture:
            print(f"[psbt] loading {args.fixture}", file=sys.stderr)
            psbt = load_psbt(Path(args.fixture))
        else:
            print(
                f"[psbt] generating fake PSBT ({args.inputs} in / {args.outputs} out)...",
                file=sys.stderr,
            )
            psbt = make_fake_psbt(policy, args.inputs, args.outputs)

            # TUI-only hook: a callable that mutates the generated PSBT
            # before signing. Not exposed via argparse.
            mutator = getattr(args, "psbt_mutator", None)
            if mutator is not None:
                print("[psbt] applying preset mutator", file=sys.stderr)
                psbt = mutator(psbt)

        if "musig(" in policy.descriptor_template:
            results = sign_psbt_musig2(client, policy, hmac, psbt, external_xprivs)
        else:
            print("Review and confirm transaction on device...", file=sys.stderr)
            results = client.sign_psbt(psbt, policy, hmac)

    print_signatures(results)


def cmd_make_psbt(args: argparse.Namespace) -> None:
    policy = _build_policy(args)
    psbt = make_fake_psbt(policy, args.inputs, args.outputs)
    b64 = psbt.serialize()
    if args.output:
        Path(args.output).write_text(b64 + "\n")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(b64)


def cmd_sign_message(args: argparse.Namespace) -> None:
    with open_client(args) as client:
        print("Confirm message on device...", file=sys.stderr)
        sig = client.sign_message(args.message, args.path)
    print(sig)


# ----- argparse plumbing ----------------------------------------------------

def _add_policy_args(p: argparse.ArgumentParser, *, with_name_default: bool = True) -> None:
    """Add the four flags every policy subcommand shares."""
    p.add_argument(
        "--template", required=True,
        help='BIP-388 descriptor template, e.g. "wsh(or_d(pk(@0/**),pkh(@1/**)))"',
    )
    p.add_argument(
        "--key", "-k", action="append", dest="keys", required=True,
        help='one BIP-388 key-info string "[fpr/origin]xpub"; repeat for multi-key policies',
    )
    p.add_argument(
        "--name", default="" if with_name_default else None,
        help=(
            "WalletPolicy name. Leave empty for standard single-sig policies; "
            "any non-empty value triggers on-device registration and HMAC caching."
        ),
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="playground",
        description="Bitcoin app playground CLI (speculos / real device).",
        epilog=f"Registration cache: {cache_file_path()}",
    )
    p.add_argument(
        "--target", choices=["speculos", "hid"], default="speculos",
        help="connection target (default: speculos)",
    )
    p.add_argument("--host", default="127.0.0.1", help="speculos host (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=9999, help="speculos APDU port (default: 9999)")
    p.add_argument(
        "--chain", choices=list(CHAIN_BY_NAME), default="test",
        help="Bitcoin network (default: test)",
    )
    p.add_argument("--debug", action="store_true", help="dump APDUs on stderr")

    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("get-fingerprint", help="GET_MASTER_FINGERPRINT (no UX)")
    sp.set_defaults(func=cmd_get_fingerprint)

    sp = sub.add_parser("get-xpub", help="GET_EXTENDED_PUBKEY")
    sp.add_argument("path", help='BIP-32 derivation path, e.g. "m/86\'/1\'/0\'"')
    sp.add_argument("--display", action="store_true", help="confirm xpub on device")
    sp.set_defaults(func=cmd_get_xpub)

    sp = sub.add_parser("register-wallet", help="REGISTER_WALLET")
    _add_policy_args(sp)
    sp.set_defaults(func=cmd_register_wallet)

    sp = sub.add_parser("get-address", help="GET_WALLET_ADDRESS")
    _add_policy_args(sp)
    sp.add_argument("--change", type=int, default=0, choices=[0, 1])
    sp.add_argument("--index", type=int, default=0)
    sp.add_argument("--display", action="store_true", help="confirm address on device")
    sp.add_argument("--no-cache", action="store_true", help="force re-registration")
    sp.set_defaults(func=cmd_get_address)

    sp = sub.add_parser("sign-psbt", help="SIGN_PSBT")
    _add_policy_args(sp)
    sp.add_argument(
        "--fixture",
        help="path to a PSBT file (base64); default is to generate a fake PSBT",
    )
    sp.add_argument("--inputs", type=int, default=1, help="(generated) number of inputs")
    sp.add_argument("--outputs", type=int, default=2, help="(generated) number of outputs")
    sp.add_argument("--no-cache", action="store_true", help="force re-registration")
    sp.add_argument(
        "--external-xpriv", action="append", dest="external_xprivs",
        help=(
            "musig2-only: xpriv for one external cosigner to drive round-2 signing. "
            "Repeat once per non-device cosigner. Without it, sign-psbt stops after "
            "round 1 and prints the device's pubnonce(s)."
        ),
    )
    sp.set_defaults(func=cmd_sign_psbt)

    sp = sub.add_parser(
        "make-psbt",
        help="generate a fake PSBT for a wallet policy (no device interaction, does not sign)",
    )
    _add_policy_args(sp)
    sp.add_argument("--inputs", type=int, default=1)
    sp.add_argument("--outputs", type=int, default=2)
    sp.add_argument("-o", "--output", help="write to file (default: stdout)")
    sp.set_defaults(func=cmd_make_psbt)

    sp = sub.add_parser("sign-message", help="SIGN_MESSAGE")
    sp.add_argument("path", help='BIP-32 derivation path, e.g. "m/44\'/1\'/0\'/0/0"')
    sp.add_argument("message", help="message text")
    sp.set_defaults(func=cmd_sign_message)

    return p


def main(argv: Optional[List[str]] = None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()

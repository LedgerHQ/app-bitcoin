# This module contains a utility function to create test PSBTs spending from an arbitrary wallet policy.
# It creates transactions spending non-existing UTXOs, and fills in the PSBTs with enough information to
# satisfy the requirements of the Ledger bitcoin app.
# It does not guarantee BIP-174 compliant PSBTs, as some fields that are not required in the
# Ledger bitcoin app might not be filled in.


import argparse
import sys
import os
from io import BytesIO
from random import randint
import re

from typing import List, Tuple, Optional, Union

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from bitcoin_client.ledger_bitcoin import WalletPolicy
from bitcoin_client.ledger_bitcoin.key import ExtendedKey, KeyOriginInfo, taproot_tweak_pubkey
from bitcoin_client.ledger_bitcoin.psbt import PSBT, PartiallySignedInput, PartiallySignedOutput
from bitcoin_client.ledger_bitcoin.tx import CScriptWitness, CTransaction, CTxIn, CTxInWitness, CTxOut, COutPoint, CTxWitness, uint256_from_str

from embit.bip32 import HDKey
from embit.bip39 import mnemonic_to_seed
from embit.descriptor import Descriptor
from embit.networks import NETWORKS
from embit.script import Script

from bitcoin_client.ledger_bitcoin.embit.descriptor.miniscript import Miniscript
from test_utils import bip0340, sha256, hash160
from test_utils.bip0327 import cbytes, key_agg
from test_utils.wallet_policy import DescriptorTemplate, KeyPlaceholder, MuSig2KeyPlaceholder, PlainKeyPlaceholder, ShDescriptorTemplate, ShWpkhDescriptorTemplate, ShWshDescriptorTemplate, TrDescriptorTemplate, WshDescriptorTemplate, WpkhDescriptorTemplate, PkhDescriptorTemplate, derive_plain_descriptor, tapleaf_hash


# BIP-328 chaincode used by BIP-388 to derive a synthetic xpub from an
# aggregated musig2 public key. Pinned constant; see the reference
# implementation in bitcoin_client.ledger_bitcoin.client.aggr_xpub.
_BIP328_CHAINCODE = bytes.fromhex(
    "868087ca02a6f974c4598924c36b57762d32cb45717167e300622c7167e38965"
)


def _musig_root_aggregate(placeholder: MuSig2KeyPlaceholder, keys_info: List[str]) -> Tuple[bytes, List[bytes]]:
    """Returns `(aggregate_pubkey, sorted_root_participants)` for a musig
    placeholder. The aggregate is the 33-byte compressed result of BIP-327
    KeyAgg over the sorted participant root pubkeys — i.e. the input to the
    BIP-328 synthetic-xpub derivation, before any BIP-32 or taproot tweaks.
    This is the form expected by BIP-373's MUSIG2_PARTICIPANT_PUBKEYS field.
    """
    participant_pubkeys: List[bytes] = []
    for idx in placeholder.key_indexes:
        key_info = keys_info[idx]
        origin_end = key_info.find("]")
        xpub_str = key_info if origin_end == -1 else key_info[origin_end + 1:]
        participant_pubkeys.append(ExtendedKey.deserialize(xpub_str).pubkey)

    sorted_participants = sorted(participant_pubkeys)
    aggregate = cbytes(key_agg(sorted_participants).Q)
    return aggregate, sorted_participants


SPECULOS_SEED = "glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin"
master_key = HDKey.from_seed(mnemonic_to_seed(SPECULOS_SEED))
master_key_fpr = master_key.derive("m/0'").fingerprint
privkey_initial = bytearray(32)


def _count_keys_in_template(descriptor_template: str) -> int:
    """Returns the number of distinct key placeholders (@0, @1, ...) in the descriptor template."""
    indices = [int(m) for m in re.findall(r'@(\d+)', descriptor_template)]
    if not indices:
        return 0
    return max(indices) + 1


def _derive_key_info_from_path(derivation_path: str) -> str:
    """Derives an xpub at *derivation_path* from SPECULOS_SEED and returns a
    key-info string in the format ``[master_fpr/path]tpub``."""
    child = master_key.derive(derivation_path)
    path_for_origin = derivation_path.lstrip("m").lstrip("/")
    xpub = child.to_public(version=NETWORKS["test"]["xpub"]).to_base58()
    if path_for_origin:
        return f"[{master_key_fpr.hex()}/{path_for_origin}]{xpub}"
    return xpub


def _random_tpub() -> str:
    """Returns a random tpub (no key origin information) derived from a random seed."""
    random_seed = os.urandom(32)
    rand_key = HDKey.from_seed(random_seed, version=NETWORKS["test"]["xprv"])
    return rand_key.to_public().to_base58()


def random_numbers_with_sum(n: int, s: int) -> List[int]:
    """Returns a list of n random numbers with sum s."""
    assert n > 1

    separators = list(sorted([randint(0, s) for _ in range(n - 1)]))
    return [
        separators[0],
        *[separators[i + 1] - separators[i]
            for i in range(len(separators) - 1)],
        s - separators[-1]
    ]


def random_bytes(n: int) -> bytes:
    """Returns n random bytes. Not cryptographically secure."""
    return bytes([randint(0, 255) for _ in range(n)])


def random_txid() -> bytes:
    """Returns 32 random bytes. Not cryptographically secure."""
    return random_bytes(32)

def random_p2tr() -> bytes:
    """Returns 32 random bytes. Not cryptographically secure."""
    global privkey_initial
    # Using non-random sequence for the sake of tests
    privkey_initial = sha256(privkey_initial)
    pubkey = bip0340.point_mul(bip0340.G, int.from_bytes(privkey_initial, 'big'))

    return b'\x51\x20' + (pubkey[0]).to_bytes(32, 'big')


def getScriptPubkeyFromWallet(wallet: WalletPolicy, change: bool, address_index: int) -> Script:
    desc_tmpl = DescriptorTemplate.from_string(wallet.descriptor_template)

    def _derive_key(placeholder: KeyPlaceholder) -> bytes:
        """Returns the 33-byte compressed derived pubkey for *placeholder*."""
        der_subpath = [
            placeholder.num1 if not change else placeholder.num2,
            address_index
        ]
        root_pubkey, _ = get_placeholder_root_key(placeholder, wallet.keys_info)
        return root_pubkey.derive_pub_path(der_subpath).pubkey

    if isinstance(desc_tmpl, TrDescriptorTemplate):
        internal_key = _derive_key(desc_tmpl.key)[1:]  # x-only (drop parity byte)

        taptree_hash = b''
        if desc_tmpl.tree is not None:
            taptree_hash = desc_tmpl.get_taptree_hash(wallet.keys_info, change, address_index)

        _, output_key = taproot_tweak_pubkey(internal_key, taptree_hash)
        return Script(b'\x51\x20' + output_key)

    elif isinstance(desc_tmpl, WshDescriptorTemplate):
        # Compile the inner miniscript to obtain the witness script, then wrap in P2WSH.
        inner_desc_str = derive_plain_descriptor(
            desc_tmpl.inner_script, wallet.keys_info, change, address_index)
        witness_script: bytes = Miniscript.read_from(
            BytesIO(inner_desc_str.encode()), taproot=False).compile()
        return Script(b'\x00\x20' + sha256(witness_script))

    elif isinstance(desc_tmpl, WpkhDescriptorTemplate):
        pubkey = _derive_key(desc_tmpl.key)
        return Script(b'\x00\x14' + hash160(pubkey))

    elif isinstance(desc_tmpl, ShWpkhDescriptorTemplate):
        # BIP-49 wrapped segwit: scriptPubKey = OP_HASH160 <hash160(redeemScript)> OP_EQUAL
        # where redeemScript = OP_0 <hash160(pubkey)>
        pubkey = _derive_key(desc_tmpl.key)
        redeem_script = b'\x00\x14' + hash160(pubkey)
        return Script(b'\xa9\x14' + hash160(redeem_script) + b'\x87')

    elif isinstance(desc_tmpl, PkhDescriptorTemplate):
        pubkey = _derive_key(desc_tmpl.key)
        return Script(b'\x76\xa9\x14' + hash160(pubkey) + b'\x88\xac')

    else:
        raise ValueError(f"Unsupported descriptor type: {type(desc_tmpl).__name__}")


def createFakeWalletTransaction(n_inputs: int, n_outputs: int, output_amount: int, wallet: WalletPolicy) -> Tuple[CTransaction, int, int, int]:
    """
    Creates a (fake) transaction that has n_inputs inputs and n_outputs outputs, with a random output equal to output_amount.
    Each output of the transaction is a spend to wallet (possibly to a change address); the change/address_index of the
    derivation of the selected output are also returned.
    """
    assert n_inputs > 0 and n_outputs > 0

    selected_output_index = randint(0, n_outputs - 1)
    selected_output_change = randint(0, 1)
    selected_output_address_index = randint(0, 10_000)

    vout: List[CTxOut] = []
    for i in range(n_outputs):
        if i == selected_output_index:
            scriptPubKey: bytes = getScriptPubkeyFromWallet(
                wallet, selected_output_change, selected_output_address_index).data
            vout.append(CTxOut(output_amount, scriptPubKey))
        else:
            # could use any other script for the other outputs; doesn't really matter
            scriptPubKey: bytes = getScriptPubkeyFromWallet(
                wallet, randint(0, 1), randint(0, 10_000)).data
            vout.append(CTxOut(randint(0, 100_000_000), scriptPubKey))

    vin: List[CTxIn] = []
    for _ in range(n_inputs):
        txIn = CTxIn()
        txIn.prevout = COutPoint(
            uint256_from_str(random_txid()), randint(0, 20))
        txIn.nSequence = 0
        txIn.scriptSig = random_bytes(80)  # dummy
        vin.append(txIn)

    tx = CTransaction()
    tx.vin = vin
    tx.vout = vout
    tx.nVersion = 2
    tx.nLockTime = 0

    tx.wit = CTxWitness()

    # if segwit, add witness_utxo
    if Script(getScriptPubkeyFromWallet(wallet, 0, 0)).script_type in ["p2wpkh", "p2wsh", "p2tr"]:
        for _ in range(n_inputs):
            script_wit = CScriptWitness()
            script_wit.stack = [random_bytes(64)]  # dummy
            in_wit = CTxInWitness()
            in_wit.scriptWitness = script_wit
            tx.wit.vtxinwit.append(in_wit)

    tx.rehash()

    return tx, selected_output_index, selected_output_change, selected_output_address_index


def get_placeholder_root_key(placeholder: KeyPlaceholder, keys_info: List[str]) -> Tuple[ExtendedKey, Optional[KeyOriginInfo]]:
    if isinstance(placeholder, PlainKeyPlaceholder):
        key_info = keys_info[placeholder.key_index]
        key_origin_end_pos = key_info.find("]")
        if key_origin_end_pos == -1:
            xpub = key_info
            root_key_origin = None
        else:
            xpub = key_info[key_origin_end_pos+1:]
            root_key_origin = KeyOriginInfo.from_string(
                key_info[1:key_origin_end_pos])
        root_pubkey = ExtendedKey.deserialize(xpub)
        return root_pubkey, root_key_origin
    elif isinstance(placeholder, MuSig2KeyPlaceholder):
        aggregated_pubkey, _ = _musig_root_aggregate(placeholder, keys_info)

        # get the version from the first participant's key info
        first_key_info = keys_info[placeholder.key_indexes[0]]
        origin_end = first_key_info.find("]")
        first_xpub_str = first_key_info if origin_end == -1 else first_key_info[origin_end + 1:]
        version = ExtendedKey.deserialize(first_xpub_str).version

        synthetic = ExtendedKey(
            version,
            0,
            b"\x00\x00\x00\x00",
            0,
            _BIP328_CHAINCODE,
            None,
            aggregated_pubkey,
        )
        # Aggregated keys have no single origin; return None and let
        # callers compute a fingerprint from the aggregate pubkey if needed.
        return synthetic, None
    else:
        raise ValueError(f"Unsupported placeholder type: {type(placeholder).__name__}")


def fill_inout(wallet_policy: WalletPolicy, inout: Union[PartiallySignedInput, PartiallySignedOutput], is_change: bool, address_index: int):
    desc_tmpl = DescriptorTemplate.from_string(
        wallet_policy.descriptor_template)

    if isinstance(desc_tmpl, TrDescriptorTemplate):
        keypath_der_subpath = [
            desc_tmpl.key.num1 if not is_change else desc_tmpl.key.num2,
            address_index
        ]

        keypath_pubkey, _ = get_placeholder_root_key(
            desc_tmpl.key, wallet_policy.keys_info)

        inout.tap_internal_key = keypath_pubkey.derive_pub_path(
            keypath_der_subpath).pubkey[1:]

        if desc_tmpl.tree is not None:
            inout.tap_merkle_root = desc_tmpl.get_taptree_hash(
                wallet_policy.keys_info, is_change, address_index)

        for placeholder, tapleaf_desc in desc_tmpl.placeholders():
            if isinstance(placeholder, MuSig2KeyPlaceholder):
                # BIP-373: emit PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS mapping the
                # aggregate key to the sorted root participants.
                aggregate, sorted_participants = _musig_root_aggregate(
                    placeholder, wallet_policy.keys_info)
                inout.musig2_participant_pubkeys[aggregate] = sorted_participants

            root_pubkey, root_pubkey_origin = get_placeholder_root_key(
                placeholder, wallet_policy.keys_info)

            placeholder_der_subpath = [
                placeholder.num1 if not is_change else placeholder.num2,
                address_index
            ]

            leaf_script = None
            if tapleaf_desc is not None:
                leaf_desc = derive_plain_descriptor(
                    tapleaf_desc, wallet_policy.keys_info, is_change, address_index)
                s = BytesIO(leaf_desc.encode())
                desc: Miniscript = Miniscript.read_from(s, taproot=True)
                leaf_script = desc.compile()

            derived_pubkey = root_pubkey.derive_pub_path(
                placeholder_der_subpath)

            if root_pubkey_origin is not None:
                derived_key_origin = KeyOriginInfo(
                    root_pubkey_origin.fingerprint, root_pubkey_origin.path + placeholder_der_subpath)

                leaf_hashes = []
                if leaf_script is not None:
                    # In BIP-388 compliant wallet policies, there will be only one tapleaf with a given key
                    leaf_hashes = [tapleaf_hash(leaf_script)]

                inout.tap_bip32_paths[derived_pubkey.pubkey[1:]] = (
                    leaf_hashes, derived_key_origin)
            else:
                # No key origin info: treat the xpub as the root key, so compute its own fingerprint
                # and use placeholder_der_subpath as the full derivation path.
                fpr = hash160(root_pubkey.pubkey)[:4]
                derived_key_origin = KeyOriginInfo(fpr, placeholder_der_subpath)

                leaf_hashes = []
                if leaf_script is not None:
                    leaf_hashes = [tapleaf_hash(leaf_script)]

                inout.tap_bip32_paths[derived_pubkey.pubkey[1:]] = (
                    leaf_hashes, derived_key_origin)
    else:
        if isinstance(desc_tmpl, WshDescriptorTemplate):
            # add witnessScript
            desc_str = derive_plain_descriptor(
                wallet_policy.descriptor_template, wallet_policy.keys_info, is_change, address_index)
            s = BytesIO(desc_str.encode())
            desc: Descriptor = Descriptor.read_from(s)
            inout.witness_script = desc.witness_script().data
        elif isinstance(desc_tmpl, ShWpkhDescriptorTemplate):
            # BIP-49 wrapped segwit: redeemScript = OP_0 <hash160(pubkey)>
            root_pubkey, _ = get_placeholder_root_key(
                desc_tmpl.key, wallet_policy.keys_info)
            der_subpath = [
                desc_tmpl.key.num1 if not is_change else desc_tmpl.key.num2,
                address_index,
            ]
            derived_pubkey = root_pubkey.derive_pub_path(der_subpath).pubkey
            inout.redeem_script = b"\x00\x14" + hash160(derived_pubkey)
        elif isinstance(desc_tmpl, ShWshDescriptorTemplate):
            # sh(wsh(SCRIPT)): redeemScript = OP_0 <sha256(witnessScript)>, witnessScript = compiled inner
            inner_desc_str = derive_plain_descriptor(
                desc_tmpl.inner_script, wallet_policy.keys_info, is_change, address_index)
            # technically incorrect to use miniscript here, as this might both work for non-standard or unsafe scripts,
            # and not work for some descriptors that are not miniscript, like things with sortedmulti.
            # Good enough for the purposes of this tool.
            witness_script = Miniscript.read_from(
                BytesIO(inner_desc_str.encode()), taproot=False).compile()
            inout.witness_script = witness_script
            inout.redeem_script = b'\x00\x20' + sha256(witness_script)
        elif isinstance(desc_tmpl, ShDescriptorTemplate):
            # sh(SCRIPT): redeemScript = compiled inner script
            inner_desc_str = derive_plain_descriptor(
                desc_tmpl.inner_script, wallet_policy.keys_info, is_change, address_index)
            # As above, technically incorrect to use miniscript here.
            inout.redeem_script = Miniscript.read_from(
                BytesIO(inner_desc_str.encode()), taproot=False).compile()

        for placeholder, _ in desc_tmpl.placeholders():
            root_pubkey, root_pubkey_origin = get_placeholder_root_key(
                placeholder, wallet_policy.keys_info)

            placeholder_der_subpath = [
                placeholder.num1 if not is_change else placeholder.num2,
                address_index
            ]

            derived_pubkey = root_pubkey.derive_pub_path(
                placeholder_der_subpath)

            if root_pubkey_origin is not None:
                derived_key_origin = KeyOriginInfo(
                    root_pubkey_origin.fingerprint, root_pubkey_origin.path + placeholder_der_subpath)

                inout.hd_keypaths[derived_pubkey.pubkey] = derived_key_origin
            else:
                fpr = hash160(root_pubkey.pubkey)[:4]
                derived_key_origin = KeyOriginInfo(fpr, placeholder_der_subpath)
                inout.hd_keypaths[derived_pubkey.pubkey] = derived_key_origin

def createPsbt(wallet_policy: WalletPolicy, input_amounts: List[int], output_amounts: List[int], output_is_change: List[bool]) -> PSBT:
    assert len(output_amounts) == len(output_is_change)
    assert sum(output_amounts) <= sum(input_amounts)

    vin: List[CTxIn] = [CTxIn() for _ in input_amounts]
    vout: List[CTxOut] = [CTxOut() for _ in output_amounts]

    # create some credible prevout transactions
    prevouts: List[CTransaction] = []
    prevout_ns: List[int] = []
    prevout_path_change: List[int] = []
    prevout_path_addr_idx: List[int] = []
    for i, prevout_amount in enumerate(input_amounts):
        n_inputs = randint(1, 10)
        n_outputs = randint(1, 10)
        prevout, idx, is_change, addr_idx = createFakeWalletTransaction(
            n_inputs, n_outputs, prevout_amount, wallet_policy)
        prevouts.append(prevout)
        prevout_ns.append(idx)
        prevout_path_change.append(is_change)
        prevout_path_addr_idx.append(addr_idx)

        vin[i].prevout = COutPoint(prevout.sha256, idx)
        vin[i].scriptSig = b''
        vin[i].nSequence = 0

    psbt = PSBT()
    psbt.version = 0

    tx = CTransaction()
    tx.nVersion = 2
    tx.vin = vin
    tx.vout = vout
    tx.wit = CTxWitness()

    change_address_index = randint(0, 10_000)
    global privkey_initial
    privkey_initial = bytearray([0xB6] * 32)
    for i, output_amount in enumerate(output_amounts):
        tx.vout[i].nValue = output_amount
        if output_is_change[i]:
            script = getScriptPubkeyFromWallet(
                wallet_policy, output_is_change[i], change_address_index)

            tx.vout[i].scriptPubKey = script.data
        else:
            # a random P2TR output
            tx.vout[i].scriptPubKey = random_p2tr()

    # Fill the global xpub map: each root key in the wallet policy maps to its key origin info
    for key_info_str in wallet_policy.keys_info:
        key_origin_end_pos = key_info_str.find("]")
        if key_origin_end_pos == -1:
            root_pubkey = ExtendedKey.deserialize(key_info_str)
            fpr = hash160(root_pubkey.pubkey)[:4]
            key_origin = KeyOriginInfo(fpr, [])
        else:
            root_pubkey = ExtendedKey.deserialize(key_info_str[key_origin_end_pos + 1:])
            key_origin = KeyOriginInfo.from_string(key_info_str[1:key_origin_end_pos])
        psbt.xpub[root_pubkey.serialize()] = key_origin

    psbt.inputs = [PartiallySignedInput(0) for _ in input_amounts]
    psbt.outputs = [PartiallySignedOutput(0) for _ in output_amounts]

    desc_tmpl = DescriptorTemplate.from_string(
        wallet_policy.descriptor_template)

    for input_index, input in enumerate(psbt.inputs):
        if desc_tmpl.is_segwit():
            # add witness UTXO
            input.witness_utxo = prevouts[input_index].vout[prevout_ns[input_index]]

        if desc_tmpl.is_legacy() or (desc_tmpl.is_segwit() and not desc_tmpl.is_taproot()):
            # add non_witness_utxo for legacy or segwitv0
            input.non_witness_utxo = prevouts[input_index]

        is_change = bool(prevout_path_change[input_index])
        address_index = prevout_path_addr_idx[input_index]

        fill_inout(wallet_policy, input, is_change, address_index)

    # only for the change output, we need to do the same
    for output_index, output in enumerate(psbt.outputs):
        if output_is_change[output_index]:
            fill_inout(wallet_policy, output, is_change=True,
                       address_index=change_address_index)

    psbt.tx = tx

    return psbt


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create a test PSBT from a BIP-388 wallet policy."
    )
    parser.add_argument(
        "--descriptor", "-d",
        help="Descriptor template, e.g. tr(@0/**) or wsh(multi(2,@0/**,@1/**)).",
    )
    parser.add_argument(
        "--key", "-k",
        action="append",
        dest="keys",
        metavar="KEY",
        help=(
            "Key for @N (repeat for each key, in order). "
            "Supply a tpub, a BIP-32 derivation path to derive from the "
            "default Speculos mnemonic (e.g. m/48\'/1\'/0\'/2\'), "
            "or 'r' for a random key."
        ),
    )
    parser.add_argument(
        "--inputs", "-i",
        type=int,
        help="Number of inputs (default: 2).",
    )
    parser.add_argument(
        "--outputs", "-o",
        type=int,
        help="Number of outputs (default: 2).",
    )
    parser.add_argument(
        "--change", "-c",
        help="0-based index of the change output, or 'no' for no change (default: random).",
    )
    args = parser.parse_args()

    # ------------------------------------------------------------------ #
    # Descriptor template
    # ------------------------------------------------------------------ #
    descriptor_template: str = args.descriptor or ""
    if not descriptor_template:
        descriptor_template = input("Descriptor template: ").strip()
    if not descriptor_template:
        print("Error: descriptor template cannot be empty.", file=sys.stderr)
        sys.exit(1)

    n_keys = _count_keys_in_template(descriptor_template)
    if n_keys == 0:
        print(
            "Error: no key placeholders (@0, @1, …) found in descriptor template.",
            file=sys.stderr,
        )
        sys.exit(1)

    # ------------------------------------------------------------------ #
    # Keys
    # ------------------------------------------------------------------ #
    provided_keys: List[str] = list(args.keys) if args.keys else []
    keys_info: List[str] = []
    default_is_random = False  # flips to True after the first derivation-path key is used
    for i in range(n_keys):
        if i < len(provided_keys):
            key_str = provided_keys[i].strip()
        else:
            default_path = f"m/48'/1'/{i}'/2'"
            if default_is_random:
                raw = input(
                    f"Key @{i} [default: random, or enter a derivation path]: "
                ).strip()
                key_str = raw if raw else "r"
            else:
                raw = input(
                    f"Key @{i} [default: derive from {default_path}, or 'r' for random]: "
                ).strip()
                key_str = raw if raw else default_path

        # Treat as a derivation path when it starts with 'm'; 'r' for random; otherwise use as-is (tpub).
        if key_str.lower() == "r":
            keys_info.append(_random_tpub())
        elif re.match(r"^m(/|$)", key_str):
            keys_info.append(_derive_key_info_from_path(key_str))
            default_is_random = True
        else:
            keys_info.append(key_str)

    # ------------------------------------------------------------------ #
    # Number of inputs / outputs
    # ------------------------------------------------------------------ #
    n_inputs: int
    if args.inputs is not None:
        n_inputs = args.inputs
    else:
        raw = input("Number of inputs [default: 2]: ").strip()
        n_inputs = int(raw) if raw else 2

    n_outputs: int
    if args.outputs is not None:
        n_outputs = args.outputs
    else:
        raw = input("Number of outputs [default: 2]: ").strip()
        n_outputs = int(raw) if raw else 2

    # ------------------------------------------------------------------ #
    # Change output index
    # ------------------------------------------------------------------ #
    no_change = False
    change_index: int
    if args.change is not None:
        if args.change.lower() == "no":
            no_change = True
        else:
            change_index = int(args.change)
    else:
        default_change = randint(0, n_outputs - 1)
        raw = input(
            f"Change output index [default: {default_change}, or 'no' for no change]: "
        ).strip()
        if raw.lower() == "no":
            no_change = True
        elif raw:
            change_index = int(raw)
        else:
            change_index = default_change

    # ------------------------------------------------------------------ #
    # Build PSBT
    # ------------------------------------------------------------------ #
    wallet_policy = WalletPolicy("cli-wallet", descriptor_template, keys_info)

    input_amounts = [10000 + 10000 * idx for idx in range(n_inputs)]
    total_in = sum(input_amounts)
    out_amounts = [total_in // n_outputs - idx for idx in range(n_outputs)]

    output_is_change = (
        [False] * n_outputs
        if no_change
        else [idx == change_index for idx in range(n_outputs)]
    )

    psbt = createPsbt(wallet_policy, input_amounts, out_amounts, output_is_change)

    print(f"\nWallet policy:")
    print(f"  Descriptor template: {wallet_policy.descriptor_template}")
    for i, key_info in enumerate(wallet_policy.keys_info):
        print(f"  Key @{i}: {key_info}")
    print("\nPSBT:")
    print(psbt.serialize())


if __name__ == "__main__":
    main()

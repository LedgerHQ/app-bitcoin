from io import BytesIO, BufferedReader
from copy import deepcopy
from typing import List, Optional, Union
from bitcoinrpc.authproxy import AuthServiceProxy
from test_utils.bitcoin.key import get_taproot_output_key
from test_utils.bitcoin.common import hash160
from test_utils.bitcoin.tx import CTransaction
from test_utils.bitcoin.psbt import PSBT, PartiallySignedInput, PartiallySignedOutput
from test_utils.bitcoin.key import ExtendedKey, KeyOriginInfo
from test_utils.bitcoin._script import is_p2pkh, is_p2tr

# Change accordingly
txid = "TODO"

rpc_user = "TODO"
rpc_password = "TODO"

rpc_port = 18332


speculos_root_ext_privkey = ExtendedKey.deserialize(
    "tprv8ZgxMBicQKsPfDTA8ufnUdCDy8qXUDnxd8PYWprimNdtVSk4mBMdkAPF6X1cemMjf6LyznfhwbPCsxfiof4BM4DkE8TQtV3HBw2krSqFqHA"
)
speculos_root_ext_pubkey = ExtendedKey.deserialize(
    "tpubD6NzVbkrYhZ4YgUx2ZLNt2rLYAMTdYysCRzKoLu2BeSHKvzqPaBDvf17GeBPnExUVPkuBpx4kniP964e2MxyzzazcXLptxLXModSVCVEV1T"
)

speculos_master_key_fingerprint = hash160(speculos_root_ext_pubkey.pubkey)[0:4]

H = 0x80000000
coin_type = 1  # testnet


def step_to_str(step: int):
    if step >= H:
        return f"{step ^ H}'"
    else:
        return f"{step}"


def path_to_str(path: List[int]) -> str:
    return "/".join(["m"] + [step_to_str(step) for step in path])


def find_pubkey_path(
    pkh: bytes,
    purposes: List[int] = [44, 49, 84],
    max_account: int = 3,
    max_address_index: int = 10,
) -> Optional[List[int]]:
    """Iterates over plausible bip44/49/84 paths to find what was the path that generated it.
    Returns None if not found.
    """

    for purpose in purposes:
        tmp = speculos_root_ext_privkey.derive_priv(purpose ^ H)
        tmp = tmp.derive_priv(coin_type ^ H)
        for account in range(max_account):
            tmp2 = tmp.derive_priv(account ^ H)
            for change in [0, 1]:
                tmp3 = tmp2.derive_priv(change)
                for address_index in range(max_address_index):
                    path = [
                        purpose ^ H,
                        coin_type ^ H,
                        account ^ H,
                        change,
                        address_index,
                    ]
                    expected_privkey = tmp3.derive_priv(address_index)

                    if hash160(expected_privkey.pubkey) == pkh:
                        return path
    return None


def find_pubkey_path_taproot(
    pk: bytes,
    purposes: List[int] = [86],
    max_account: int = 3,
    max_address_index: int = 10,
) -> Optional[List[int]]:
    """Iterates over plausible paths to find what was the path that generated the key for a P2TR address.
    Tweaks the pubkey with the hash of itself as suggested in BIP-341.
    """

    for purpose in purposes:
        tmp = speculos_root_ext_privkey.derive_priv(purpose ^ H)
        tmp = tmp.derive_priv(coin_type ^ H)
        for account in range(max_account):
            tmp2 = tmp.derive_priv(account ^ H)
            for change in [0, 1]:
                tmp3 = tmp2.derive_priv(change)
                for address_index in range(max_address_index):
                    path = [
                        purpose ^ H,
                        coin_type ^ H,
                        account ^ H,
                        change,
                        address_index,
                    ]
                    expected_privkey = tmp3.derive_priv(address_index)

                    tweaked_pubkey = get_taproot_output_key(
                        expected_privkey.pubkey)

                    if pk == tweaked_pubkey:
                        return path
    return None


# rpc_user and rpc_password are set in the bitcoin.conf file
rpc_connection = AuthServiceProxy(
    f"http://{rpc_user}:{rpc_password}@127.0.0.1:{rpc_port}"
)


def get_tx_from_id(txid: str) -> CTransaction:
    """Queries bitcoin-core to get a raw transaction from the id, then deserializes it
    to return a CTtransaction."""

    rawtx: str = rpc_connection.getrawtransaction(txid)

    tx = CTransaction()
    tx.deserialize(BufferedReader(BytesIO(bytes.fromhex(rawtx))))
    tx.rehash()

    return tx


def psbt_to_dict(psbt: PSBT) -> dict:
    """Simple utility to convert a PSBT into a combination of plain dicts and lists."""

    clone = deepcopy(psbt)

    res = vars(clone)

    res["inputs"] = [vars(inp) for inp in clone.inputs]
    res["outputs"] = [vars(outp) for outp in clone.outputs]

    return res


def fill_p2tr_inout(scriptPubKey: bytes, inout: Union[PartiallySignedInput, PartiallySignedOutput]) -> None:
    """Fills the info of a PSBT PartiallySignedInput or PartiallySignedOutput"""

    assert(is_p2tr(scriptPubKey))

    pubkey = scriptPubKey[2:]

    path = find_pubkey_path_taproot(pubkey)

    if path is None:
        print("Path not found")
        return

    print("Path:", path_to_str(path))

    internal_privkey = speculos_root_ext_privkey.derive_priv_path(path)
    internal_pubkey = internal_privkey.pubkey[1:]

    print("Internal pubkey:", internal_pubkey.hex())

    inout.tap_internal_key = internal_pubkey

    koo = KeyOriginInfo(speculos_master_key_fingerprint, path)
    inout.tap_bip32_paths[internal_pubkey] = (list(), koo)


def run():
    tx = get_tx_from_id(txid)

    rawtx: bytes = tx.serialize()

    psbt_raw = rpc_connection.converttopsbt(rawtx.hex(), True)

    psbt = PSBT()
    psbt.deserialize(psbt_raw)

    for i in range(len(psbt.tx.vin)):
        print(f"Input #{i}")
        scriptSig = tx.vin[i].scriptSig

        non_witness_utxo = get_tx_from_id("%064x" % tx.vin[i].prevout.hash)

        witness_utxo = non_witness_utxo.vout[tx.vin[i].prevout.n]
        scriptPubKey = witness_utxo.scriptPubKey

        if is_p2pkh(scriptPubKey):
            print("Input is P2PKH")
            # add non_witness_utxo, witness info, redeem script, etc.
            psbt.inputs[i].non_witness_utxo = non_witness_utxo

            pkh = scriptPubKey[3:23]
            path = find_pubkey_path(pkh)

            if not path:
                raise ValueError(
                    f"Unable to generate pubkey with hash: {pkh.hex()}")

            # add pubkey and origin info to PSBT
            privkey = speculos_root_ext_privkey.derive_priv_path(path)
            pubkey = privkey.pubkey
            psbt.inputs[i].hd_keypaths[pubkey] = KeyOriginInfo(
                speculos_master_key_fingerprint, path
            )

            # extract expected pubkey and signature for this input
            sig_len = scriptSig[0]
            sig = scriptSig[1: 1 + sig_len]

            assert scriptSig[1 + sig_len] == 33  # pubkey len

            pubkey = scriptSig[1 + sig_len + 1:]

            assert len(sig) == sig_len and len(pubkey) == 33

            print(f"  Expected pubkey for input {i}   : {pubkey.hex()}")
            print(f"  Expected signature for input {i}: {sig.hex()}")
            print(f"  Path for input {i}              : {path_to_str(path)}")

            key_path_info = path_to_str(path[:3]).replace(
                "m", speculos_master_key_fingerprint.hex(), 1
            )
            account_ext_pubkey = speculos_root_ext_privkey.derive_priv_path(
                path[:3]
            ).neutered()
            key_info = f"[{key_path_info}]{account_ext_pubkey.to_string()}/**"
            policy = f"pkh({key_info})"

            print(f"  Expected wallet policy        : {policy}")
        elif is_p2tr(scriptPubKey):
            psbt.inputs[i].witness_utxo = witness_utxo

            fill_p2tr_inout(scriptPubKey, psbt.inputs[i])
        else:
            print(
                f"We don't know how to handle this script type for input: {scriptPubKey.hex()}. Skipping")

        print()

    for i in range(len(psbt.tx.vout)):
        print(f"Output #{i}")
        scriptPubKey = tx.vout[i].scriptPubKey

        if is_p2tr(scriptPubKey):
            fill_p2tr_inout(scriptPubKey, psbt.outputs[i])
        else:
            print(
                f"We don't know how to handle this script type for output: {scriptPubKey.hex()}. Skipping")

    print("Final psbt:")
    print(psbt.serialize())


if __name__ == "__main__":
    run()

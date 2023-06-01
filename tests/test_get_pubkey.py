from bitcoin_client.bitcoin_base_cmd import AddrType
from utils import automation


@automation("automations/accept_pubkey.json")
def test_get_public_key(cmd):
    # legacy address
    pub_key, addr, bip32_chain_code = cmd.get_public_key(
        addr_type=AddrType.Legacy,
        bip32_path="m/44'/133'/0'/0/0",
        display=True
    )

    assert pub_key == bytes.fromhex("04"
                                    "749c3f99dd136601daa824ecf40ae144c1a7de432bf22dbb23c81c7b6077d431"
                                    "da107d9809ccd29fe9ae29dee4d713a0cd16ceb88be6ab1c6b06ac7a4ee1daf2")
    assert addr == "t1LBsxhHpmugntmxBVBNh6MSvq2CmUE6g9X"
    assert bip32_chain_code == bytes.fromhex("8b6440cbb7301fb7f6f8d11ca87fbec223ad012abae58a3b3bb2a651f2d51dbe")


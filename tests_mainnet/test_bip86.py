from ledger_bitcoin import Client, WalletPolicy

from test_utils import SpeculosGlobals, mnemonic

MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


@mnemonic(MNEMONIC)
def test_bip86(client: Client, speculos_globals: SpeculosGlobals):
    # Test vectors for BIP-0086: https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki

    fpr = speculos_globals.master_key_fingerprint.hex()

    # test for a native taproot wallet (bech32m addresses, per BIP-0086)

    wallet = WalletPolicy(
        name="",
        descriptor_template="tr(@0/**)",
        keys_info=[
            f"[{fpr}/86'/0'/0']xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ",
        ],
    )

    # Account 0, first receiving address = m/86'/0'/0'/0/0
    res = client.get_wallet_address(wallet, None, 0, 0, False)
    assert res == "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"

    # Account 0, second receiving address = m/86'/0'/0'/0/1
    res = client.get_wallet_address(wallet, None, 0, 1, False)
    assert res == "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"

    # Account 1, first change address = m/86'/0'/0'/1/0
    res = client.get_wallet_address(wallet, None, 1, 0, False)
    assert res == "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7"

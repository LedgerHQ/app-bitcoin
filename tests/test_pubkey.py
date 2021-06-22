from bitcoin_client.bitcoin_base_cmd import AddrType


def test_get_public_key(cmd):
    # legacy address

    paths =[
        "m/44'/175'/0'/0/0",
        "m/44'/175'/0'/0/1",
        "m/44'/175'/0'/0/2",
        "m/44'/175'/0'/0/3",
        "m/44'/175'/0'/0/4",
        "m/44'/175'/0'/1/0",
        "m/44'/175'/0'/1/1",
        "m/44'/175'/0'/1/2",
        "m/44'/175'/0'/1/3",
        "m/44'/175'/0'/1/4",
    ]

    addrs = []

    for path in paths:
        pub_key, addr, bip32_chain_code = cmd.get_public_key(
            addr_type=AddrType.Legacy,
            bip32_path=path,
            display=False
        )
        addrs.append(addr)

    print("ADDRESSES:")
    print(addrs)
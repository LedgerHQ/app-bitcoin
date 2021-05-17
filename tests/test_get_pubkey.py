from bitcoin_client.bitcoin_base_cmd import AddrType


def test_get_public_key(cmd):
    # legacy address
    pub_key, addr, bip32_chain_code = cmd.get_public_key(
        addr_type=AddrType.Legacy,
        bip32_path="m/44'/1'/0'/0/0",
        display=False
    )

    assert pub_key == bytes.fromhex("04"
                                    "ee8608207e21028426f69e76447d7e3d5e077049f5e683c3136c2314762a4718"
                                    "b45f5224b05ebbad09f43594b7bd8dc0eff4519a07cbab37ecc66e0001ab959a")
    assert addr == "mz5vLWdM1wHVGSmXUkhKVvZbJ2g4epMXSm"
    assert bip32_chain_code == bytes.fromhex("0322c8f681e7274e767cee09b8e41770e6d2afd504fd5f85dfaab3e1ff6cdfcc")

    # P2SH-P2WPKH address
    pub_key, addr, bip32_chain_code = cmd.get_public_key(
        addr_type=AddrType.P2SH_P2WPKH,
        bip32_path="m/49'/1'/0'/0/0",
        display=False
    )

    assert pub_key == bytes.fromhex("04"
                                    "a80f007194d53d37f6f99539f635390588c4e1c328b098295f61af40d60cb28a"
                                    "7b5649e8121c89148fbab7d693108654685b4e939d9c1bc55a71b43f389929fe")
    assert addr == "2MyHkbusvLomaarGYMqyq7q9pSBYJRwWcsw"
    assert bip32_chain_code == bytes.fromhex("dc699bc018541f456df1ebd4dea516a633a6260e0a701eba143449adc2ca63f3")

    # bech32 address
    pub_key, addr, bip32_chain_code = cmd.get_public_key(
        addr_type=AddrType.BECH32,
        bip32_path="m/84'/1'/0'/0/0",
        display=False
    )

    assert pub_key == bytes.fromhex("04"
                                    "7cb75d34b005c4eb9f62bbf2c457d7638e813e757efcec8fa68677d950b63662"
                                    "648e4f638cabc4e4383fa3fe8348456e46fa56742dcf500a5b50dc1d403492f0")
    assert addr == "tb1qzdr7s2sr0dwmkwx033r4nujzk86u0cy6fmzfjk"
    assert bip32_chain_code == bytes.fromhex("efd851020a3827ba0d3fd4375910f0ed55dbe8c5d740b37559e993b1d623a956")

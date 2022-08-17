def test_get_coin_version(cmd):
    (p2pkh_prefix, p2sh_prefix, coin_family, coin_name, coin_ticker) = cmd.get_coin_version()

    assert (p2pkh_prefix,
            p2sh_prefix,
            coin_family,
            coin_name,
            coin_ticker) == (0x1CB8, 0x1CBD, 0x01, "Zcash", "ZEC")

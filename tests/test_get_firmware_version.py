def test_get_version(cmd):
    major, minor, patch = cmd.get_firmware_version()  # type: int, int , int

    assert (1, 4, 8) <= (major, minor, patch) < (1, 6, 0)

from bitcoin_client.bitcoin_base_cmd import AddrType
from utils import automation


@automation("automations/sign_message.json")
def test_sign_message(cmd):
    result = cmd.sign_message(
            message = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks.",
            bip32_path = "m/44'/1'/0'/0/0"
    )

    assert result == "MUUCIQDkeGEVZZiRjMfh+z4ELx81gBdBwIK1IIEHkXZ6FiqcqQIgfaAberpvF+XbOCM5Cd/ljogNyU3w2OIL8eYCyZ6Ru2k="


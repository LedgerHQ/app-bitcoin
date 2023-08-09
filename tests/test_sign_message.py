from bitcoin_client.bitcoin_base_cmd import AddrType
from utils import automation


@automation("automations/sign_message.json")
def test_sign_message(cmd):
    result = cmd.sign_message(
            message = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks.",
            bip32_path = "m/44'/1'/0'/0/0"
    )

    assert result == "MEQCIANoKhOE+1y3y4Rg5vp1b98a3ecMgDxNUTLLpFSxRVWeAiAad+PJ2XhxreRsvaqLGDC5xcD1uJhQ5F/mGo7yR8qWGQ=="


import pytest
from typing import List, Optional
from helpers.basetest import BaseTestBtc
from helpers.deviceappproxy.deviceappbtc import DeviceAppBtc
from conftest import ledgerjs_test_data, LedgerjsApdu


@pytest.mark.manual
@pytest.mark.btc
class TestLedgerjsBtcTx(BaseTestBtc):

    # Some test data deactivated as they pre-date the last version of the btc tx parser
    # ledgerjs_test_data = [ test_btc_get_wallet_public_key, test_btc3, test_btc4,
    #                        test_sign_message,]
    #                        # test_btc_sig_p2sh_seg, test_btc_seg_multi, test_btc2]

    @pytest.mark.parametrize('test_data', ledgerjs_test_data())
    def test_replay_ledgerjs_tests(self, test_data: List[LedgerjsApdu]) -> None:
        """
        Verify the Btc app with test Tx extracted from the ledjerjs package 
        that are supposedly known to work.
        """
        apdus = test_data
        btc = DeviceAppBtc()
        response: Optional[bytes] = None
        # All apdus shall return 9000 + potentially some data
        for apdu in apdus:      
            for command in apdu.commands:
                response = btc.send_raw_apdu(bytes.fromhex(command))
            if apdu.expected_resp is not None:
                self.check_raw_apdu_resp(apdu.expected_resp, response)
            elif apdu.check_sig_format is not None and apdu.check_sig_format is True:
                self.check_signature(response)  # Only format is checked

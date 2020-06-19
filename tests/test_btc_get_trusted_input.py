# Note on APDU payload chunks splitting:
# --------------------------------------
# The BTC app tx parser requires the tx data to be sent in chunks. For some tx fields 
# it doesn't matter where the field is cut but for others it does and the rule is unclear.
#
# The tx data splitting into the appropriate payload chunks is now delegated to the
# APDU-level DeviceAppBtc class.

import pytest
from helpers.basetest import BaseTestBtc
from helpers.deviceappproxy.deviceappbtc import DeviceAppBtc
from helpers.txparser.transaction import Tx, TxParse
from conftest import btc_gti_test_data, TrustedInputTestData


@pytest.mark.btc
class TestBtcTxGetTrustedInput(BaseTestBtc):
    """
    Tests of the GetTrustedInput APDU
    """
    # test_data = [standard_tx, segwit_tx]

    # def test_get_trusted_input(self, testdata: TrustedInputTestData) -> None:
    @pytest.mark.parametrize("testdata", btc_gti_test_data())
    def test_get_trusted_input(self, testdata: TrustedInputTestData) -> None:
        """
        Perform a GetTrustedInput for a non-segwit tx on Nano device.
        """
        btc = DeviceAppBtc()
        tx: Tx = TxParse.from_raw(raw_tx=testdata.tx)

        # Get TrustedInputs for all requested outputs in the tx
        prevout_idx = [idx for idx in range(testdata.num_outputs)] if testdata.num_outputs is not None \
            else [testdata.prevout_idx]

        trusted_inputs = [
            btc.get_trusted_input(
                prev_out_index=idx,
                parsed_tx=tx)
            for idx in prevout_idx]

        # Check each TrustedInput content
        prevout_amounts = [output.value for output in tx.outputs]
        for (trusted_input, idx, amount) in zip(trusted_inputs, prevout_idx, prevout_amounts):
            self.check_trusted_input(
                trusted_input,
                out_index=idx.to_bytes(4, 'little'),
                out_amount=amount.buf
            )

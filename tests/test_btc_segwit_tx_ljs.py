"""
Ledger BTC app unit tests, Segwit BTC tx, 2 inputs from 2 Segwit utxo txs
"""
import pytest
from helpers.basetest import BaseTestBtc
from helpers.deviceappproxy.deviceappbtc import DeviceAppBtc, BTC_P1
from helpers.txparser.transaction import TxHashMode, TxParse
from conftest import SignTxTestData


@pytest.mark.btc
@pytest.mark.manual
class TestBtcSegwitTxLjs(BaseTestBtc):

    @pytest.mark.parametrize("use_trusted_inputs", [True, False])
    def test_sign_tx_with_multiple_trusted_segwit_inputs(self,
                                                         use_trusted_inputs: bool,
                                                         segwit_sign_tx_test_data: SignTxTestData) -> None:
        """
        Submit segwit input as TrustedInput for signature.
        """
        # Start test
        tx_to_sign = segwit_sign_tx_test_data.tx_to_sign
        utxos = segwit_sign_tx_test_data.utxos
        output_paths = segwit_sign_tx_test_data.output_paths
        change_path = segwit_sign_tx_test_data.change_path
        # expected_der_sig = test_data.expected_sig

        btc = DeviceAppBtc()
        parsed_tx = TxParse.from_raw(raw_tx=tx_to_sign)
        parsed_utxos = [TxParse.from_raw(raw_tx=utxo) for utxo in utxos]

        if use_trusted_inputs:
            hash_mode_1 = TxHashMode(TxHashMode.SegwitBtc | TxHashMode.Trusted | TxHashMode.NoScript)
            hash_mode_2 = TxHashMode(TxHashMode.SegwitBtc | TxHashMode.Trusted | TxHashMode.WithScript)

            # 1. Get trusted inputs
            print("\n--* Get Trusted Inputs")
            # Data to submit is: prevout_index (BE) || utxo tx
            output_indexes = [_input.prev_tx_out_index for _input in parsed_tx.inputs]
            tx_inputs = [
                btc.get_trusted_input(
                    prev_out_index=out_idx.val,
                    parsed_tx=parsed_utxo
                )
                for (out_idx, parsed_utxo, utxo) in zip(output_indexes, parsed_utxos, utxos)]
            print("    OK")

            prevout_hashes = [_input.prev_tx_hash for _input in parsed_tx.inputs]
            # UTXO tx's are ordered in the same order as the inputs in the tx to sign, so the input index is used
            # to address the correct UTXO. Ideally we should rely on the UTXO tx's hash in the tx to sign to retrieve
            # the correct UTXO from the list.
            out_amounts = [utxo.outputs[_input.prev_tx_out_index.val].value.buf
                           for utxo, _input in zip(parsed_utxos, parsed_tx.inputs)]

            for tx_input, out_idx, out_amount, prevout_hash \
                    in zip(tx_inputs, output_indexes, out_amounts, prevout_hashes):
                self.check_trusted_input(
                    trusted_input=tx_input,
                    out_index=out_idx.buf,      # LE for comparison w/ out_idx in trusted_input
                    out_amount=out_amount,      # utxo output #1 is requested in tx to sign input
                    out_hash=prevout_hash       # prevout hash in tx to sign
                )
        else:
            hash_mode_1 = TxHashMode(TxHashMode.SegwitBtc | TxHashMode.Untrusted | TxHashMode.NoScript)
            hash_mode_2 = TxHashMode(TxHashMode.SegwitBtc | TxHashMode.Untrusted | TxHashMode.WithScript)
            tx_inputs = parsed_tx.inputs

        # 2.0 Get public keys for output paths & compute their hashes
        print("\n--* Get Wallet Public Key - for each tx output path")
        wpk_responses = [btc.get_wallet_public_key(output_path) for output_path in output_paths]
        print("    OK")
        pubkeys_data = [self.split_pubkey_data(data) for data in wpk_responses]
        for pubkey in pubkeys_data:
            print(pubkey)

        # 2.1 Construct a pseudo-tx without input script, to be hashed 1st. The original segwit input
        #     being replaced with the previously obtained TrustedInput, it is prefixed with the marker
        #     byte for TrustedInputs (0x01) that the BTC app expects in order to check the Trusted Input's HMAC.
        print("\n--* Untrusted Transaction Input Hash Start - Hash tx to sign first w/ all inputs "
              "having a null script length")
        btc.untrusted_hash_tx_input_start(
            mode=hash_mode_1,
            parsed_tx=parsed_tx,
            inputs=tx_inputs,
            parsed_utxos=parsed_utxos)
        print("    OK")

        # 2.2 Finalize the input-centric-, pseudo-tx hash with the remainder of that tx
        # 2.2.1 Start with change address path
        print("\n--* Untrusted Transaction Input Hash Finalize Full - Handle change address")
        btc.untrusted_hash_tx_input_finalize(
            p1=BTC_P1.CHANGE_PATH,    # to derive BIP 32 change address
            data=change_path)
        print("    OK")

        # 2.2.2 Continue w/ tx to sign outputs & scripts
        print("\n--* Untrusted Transaction Input Hash Finalize Full - Continue w/ hash of tx output")
        response = btc.untrusted_hash_tx_input_finalize(
            p1=BTC_P1.MORE_BLOCKS,
            data=parsed_tx)
        assert response == bytes.fromhex("0000")
        print("    OK")
        # We're done w/ the hashing of the pseudo-tx with all inputs w/o scriptSig.

        # 3. Sign each input individually. Because inputs are segwit, hash each input with its scriptSig
        #    and sequence individually, each in a pseudo-tx w/o output_count, outputs nor locktime.
        print("\n--* Untrusted Transaction Input Hash Start, step 2 - Hash again each input individually (only 1)")
        # Hash & sign each input individually
        for idx, (tx_input, output_path) in enumerate(zip(tx_inputs, output_paths)):
            # 3.1 Send pseudo-tx w/ sigScript
            btc.untrusted_hash_tx_input_start(
                # continue prev. started tx hash
                mode=hash_mode_2,
                parsed_tx=parsed_tx,
                parsed_utxos=parsed_utxos,
                inputs=[tx_input],
                input_num=idx)
            print("    Final hash OK")

            # 3.2 Sign tx at last. Param is:
            # Num_derivs||Dest output path||User validation code length (0x00)||tx locktime||sigHashType(always 0x01)
            print("\n--* Untrusted Transaction Hash Sign")
            response = btc.untrusted_hash_sign(
                output_path=output_path,
                parsed_tx=parsed_tx)

            self.check_signature(response)  # Check sig format only
            print("    Signature OK\n")

from typing import List
import pytest
from helpers.basetest import BaseTestZcash
from helpers.deviceappproxy.deviceappbtc import DeviceAppBtc, BTC_P1
from helpers.txparser.transaction import Tx, TxHashMode, TxParse
from conftest import zcash2_prefix_cmds, SignTxTestData, LedgerjsApdu


@pytest.mark.zcash
class TestLedgerjsZcashTx2(BaseTestZcash):

    @pytest.mark.manual
    @pytest.mark.parametrize('use_trusted_inputs', [True, False])
    @pytest.mark.parametrize('prefix_cmds', zcash2_prefix_cmds())
    def test_sign_zcash_tx_with_trusted_zec_ovw_inputs(self,
                                                       zcash2_sign_tx_test_data: SignTxTestData,
                                                       use_trusted_inputs: bool,
                                                       prefix_cmds: List[List[LedgerjsApdu]]) -> None:
        """
        Replay of real Zcash tx with inputs from a standard tx, trusted inputs on
        """
        tx_to_sign = zcash2_sign_tx_test_data.tx_to_sign
        utxos = zcash2_sign_tx_test_data.utxos
        output_paths = zcash2_sign_tx_test_data.output_paths
        change_path = zcash2_sign_tx_test_data.change_path

        btc = DeviceAppBtc()
        parsed_tx: Tx = TxParse.from_raw(raw_tx=tx_to_sign)
        parsed_utxos: List[Tx] = [TxParse.from_raw(raw_tx=utxo) for utxo in utxos]

        # 0. Send the Get Version raw apdus (apdus from LedgerJS logs)
        self.send_ljs_apdus(apdus=prefix_cmds, device=btc)

        if use_trusted_inputs:
            hash_mode_1 = TxHashMode(TxHashMode.ZcashSapling | TxHashMode.Trusted | TxHashMode.NoScript)
            hash_mode_2 = TxHashMode(TxHashMode.ZcashSapling | TxHashMode.Trusted | TxHashMode.WithScript)

            # 1. Get Trusted Input (if required by the test)
            print("\n--* Get Trusted Input - from utxos")
            output_indexes = [_input.prev_tx_out_index for _input in parsed_tx.inputs]
            tx_inputs = [
                btc.get_trusted_input(
                    prev_out_index=out_idx.val,
                    parsed_tx=parsed_utxo)
                for (out_idx, parsed_utxo, utxo) in zip(output_indexes, parsed_utxos, utxos)]
            print("    OK")

            out_amounts = [_output.value.buf for parsed_utxo in parsed_utxos for _output in parsed_utxo.outputs]
            requested_amounts = [out_amounts[out_idx.val] for out_idx in output_indexes]
            prevout_hashes = [_input.prev_tx_hash for _input in parsed_tx.inputs]
            for tx_input, out_idx, req_amount, prevout_hash \
                    in zip(tx_inputs, output_indexes, requested_amounts, prevout_hashes):
                self.check_trusted_input(
                    trusted_input=tx_input,
                    out_index=out_idx.buf,      # LE for comparison w/ out_idx in trusted_input
                    out_amount=req_amount,      # utxo output #1 is requested in tx to sign input
                    out_hash=prevout_hash)      # prevout hash in tx to sign
        else:
            hash_mode_1 = TxHashMode(TxHashMode.ZcashSapling | TxHashMode.Untrusted | TxHashMode.NoScript)
            hash_mode_2 = TxHashMode(TxHashMode.ZcashSapling | TxHashMode.Untrusted | TxHashMode.WithScript)
            tx_inputs = parsed_tx.inputs

        # 2.0 Get public keys for output paths & compute their hashes
        print("\n--* Get Wallet Public Key - for each tx output path")
        wpk_responses = [btc.get_wallet_public_key(output_path) for output_path in output_paths]
        print("    OK")
        pubkeys_data = [self.split_pubkey_data(data) for data in wpk_responses]
        for pubkey in pubkeys_data:
            print(pubkey)

        # 2.1 Construct a pseudo-tx without input script, to be hashed 1st.
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

        # 2.2.3. Zcash-specific: "When using Overwinter/Sapling, UNTRUSTED HASH SIGN is
        #        called with an empty authorization and nExpiryHeight following the first
        #        UNTRUSTED HASH TRANSACTION INPUT FINALIZE FULL"
        print("\n--* Untrusted Has Sign - with empty Auth & nExpiryHeight")
        _ = btc.untrusted_hash_sign(
            parsed_tx=parsed_tx,
            output_path=None)     # For untrusted_hash_sign() to behave as described in above comment

        # 3. Sign each input individually. Because tx to sign is Zcash Sapling, hash each input with its scriptSig
        #    and sequence individually, each in a pseudo-tx w/o output_count, outputs nor locktime.
        print("\n--* Untrusted Transaction Input Hash Start, step 2 - Hash again each input individually (only 1)")
        # Inputs are P2WPKH, so use 0x1976a914{20-byte-pubkey-hash}88ac from utxo as scriptSig in this step.
        #
        # From btc.asc: "The input scripts shall be prepared by the host for the transaction signing process as
        #   per bitcoin rules : the current input script being signed shall be the previous output script (or the
        #   redeeming script when consuming a P2SH output, or the scriptCode when consuming a BIP 143 output), and
        #   other input script shall be null."
        for idx, (tx_input, output_path) in enumerate(zip(tx_inputs, output_paths)):
            # 3.1 Send pseudo-tx w/ sigScript
            btc.untrusted_hash_tx_input_start(
                # continue prev. started tx hash
                mode=hash_mode_2,
                parsed_tx=parsed_tx,
                parsed_utxos=parsed_utxos,
                input_num=idx,
                inputs=[tx_input])
            print("    Final hash OK")

            # 3.2 Sign tx at last. Param is:
            # Num_derivs || output path || User validation code len (0x00) || tx locktime|| sigHashType (always 0x01)
            print("\n--* Untrusted Transaction Hash Sign")
            response = btc.untrusted_hash_sign(
                output_path=output_path,
                parsed_tx=parsed_tx)

            self.check_signature(response)  # Check sig format only
            # self.check_signature(response, expected_der_sig)  # Not supported yet
            print("    Signature OK\n")

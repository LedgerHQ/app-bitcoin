from typing import Optional, List, cast, Union
from .apduabstract import ApduSet, ApduDict, CApdu, BytesOrStr
from .deviceappproxy import DeviceAppProxy
# Dependency to txparser could be avoided but at the expense of a more complex design
# which I don't have time for.
from ..txparser.transaction import Tx, TxType, TxVarInt, TxHashMode, ZcashExtHeader, ZcashExtFooter, lbstr, TxInput


class BTC_P1:
    # GetPublicKey
    SHOW_ADDR = bytes.fromhex("00")
    HIDE_ADDR = bytes.fromhex("01")
    VAL_TOKEN = bytes.fromhex("02")
    # GetTrustedInput, UntrustedHashTxInputStart
    FIRST_BLOCK = bytes.fromhex("00")
    NEXT_BLOCK = bytes.fromhex("80")
    # UntrustedHashTxInputFinalize
    MORE_BLOCKS = bytes.fromhex("00")
    LAST_BLOCK = bytes.fromhex("80")
    CHANGE_PATH = bytes.fromhex("ff")


class BTC_P2:
    # GetPublicKey
    LEGACY_ADDR = bytes.fromhex("00")
    P2SH_P2WPKH_ADDR = bytes.fromhex("01")
    BECH32_ADDR = bytes.fromhex("02")
    # UntrustedHashTxInputStart
    STD_INPUTS = bytes.fromhex("00")
    SEGWIT_INPUTS = bytes.fromhex("02")
    BCH_ADDR = bytes.fromhex("03")
    OVW_RULES = bytes.fromhex("04")  # Overwinter rules (Bitcoin Cash)
    SPL_RULES = bytes.fromhex("05")  # Sapling rules (Zcash, Komodo)
    TX_NEXT_INPUT = bytes.fromhex("80")


class DeviceAppBtc(DeviceAppProxy):
    default_chunk_size = 50
    default_mnemonic = "dose bike detect wedding history hazard blast surprise hundred ankle" \
                       "sorry charge ozone often gauge photo sponsor faith business taste front" \
                       "differ bounce chaos"

    apdus: ApduDict = {
        "GetWalletPublicKey": CApdu(cla='e0', ins='40', data=[], typ=CApdu.Type.INOUT),
        "GetTrustedInput": CApdu(cla='e0', ins='42', p2='00', data=[], typ=CApdu.Type.INOUT),
        "UntrustedHashTxInputStart": CApdu(cla='e0', ins='44', data=[], typ=CApdu.Type.IN),
        "UntrustedHashSign": CApdu(cla='e0', ins='48', p1='00', p2='00', data=[], typ=CApdu.Type.INOUT),
        "UntrustedHashTxInputFinalize": CApdu(cla='e0', ins='4a', p2='00', data=[], typ=CApdu.Type.INOUT),
        # Other APDUs supported by the BTC app not needed for these tests
    }

    def __init__(self,
                 mnemonic: str = default_mnemonic) -> None:
        self.btc = ApduSet(DeviceAppBtc.apdus, max_lc=DeviceAppBtc.default_chunk_size)
        self._tx_endianness: str = 'little'
        super().__init__(mnemonic=mnemonic, chunk_size=DeviceAppBtc.default_chunk_size)

    @staticmethod
    def _get_input_index(tx: Tx, _input: bytes, endianness: lbstr = 'little'):
        # Extract prev tx output idx from given input
        standard_idx_offset = 33
        trusted_input_idx_offset = 38
        if _input[0] in (0x00, 0x02):  # legacy or segwit BTC tx input
            out_idx: int = int.from_bytes(
                _input[standard_idx_offset:standard_idx_offset + 4], endianness)
        elif (_input[0], _input[1]) == (0x01, 0x38):  # TrustedInput
            out_idx: int = int.from_bytes(
                _input[trusted_input_idx_offset:trusted_input_idx_offset + 4], endianness)
        else:
            raise ValueError("Invalid input format, must begin with a 0x00, 0x01 or 0x02 byte")
        # search in the parsed tx inputs the one w/ the out_index found
        for inp in tx.inputs:
            if inp.prev_tx_out_index.val == out_idx:
                return tx.inputs.index(inp)
        return None

    @staticmethod
    def _get_utxo_from_input(tx_input: TxInput, utxos: List[Tx]) -> Tx:
        # For now, test must order UTXOs in the same order as their matching hash in the tx to sign
        # Nice to have for later?: utxos = [{"1st four bytes of utxo_tx hash" = utxo_tx}, ...].
        utxo = [utxo for utxo in utxos if tx_input.prev_tx_hash.hex() == utxo.hash]
        if len(utxo) > 1:
            raise ValueError("The UTXO list used in this test contains several UTXOs with an identical hash")
        return utxo[0]

    def _get_formatted_inputs(self,
                              mode: TxHashMode,
                              parsed_tx: Tx,
                              parsed_utxos: List[Tx],
                              tx_inputs: Optional[List[bytes]]) -> List[bytes]:
        """
        Returns a list of inputs formatted as either relaxed, Segwit or trusted inputs, up to
        but not including the input script length byte
        """
        if mode.is_relaxed_input_hash:
            # Inputs from untrusted legacy BTC tx
            # 00||input from tx (i.e. prevout hash||prevout index)
            formatted_input = [
                bytes.fromhex("00") + _input.prev_tx_hash + _input.prev_tx_out_index.buf
                for _input in parsed_tx.inputs
            ]
        elif mode.is_trusted_input_hash:
            # TrustedInputs from legacy BTC, Segwit BTC or Zcash Ovw/Sapling txs
            assert tx_inputs is not None
            # 01||len(trusted_input)||trusted_input
            formatted_input = [
                bytes.fromhex("01") + bytes([len(_input)]) + _input
                for _input in tx_inputs
            ]
        elif mode.is_segwit_input_hash or mode.is_sapling_input_hash:
            # Inputs from non-trusted Segwit or Zcash Sapling tx
            assert parsed_utxos is not None
            # 02||input from tx (i.e. prevout hash||prevout index)||prevout_amount
            # with prev_amount in a utxo
            formatted_input: List = []
            for _input in parsed_tx.inputs:
                utxo: Tx = self._get_utxo_from_input(tx_input=_input, utxos=parsed_utxos)
                amount: bytes = utxo.outputs[_input.prev_tx_out_index.val].value.buf
                formatted_input.append(bytes.fromhex("02") + _input.prev_tx_hash
                                       + _input.prev_tx_out_index.buf + amount)
        elif mode.is_bcash_input_hash:
            # TODO: write code for Bitcoin cash inputs hash
            raise NotImplementedError("Support for Bcash tx in tests not yet active")
        else:
            raise ValueError(f"Invalid hash mode '{mode}'")
        return formatted_input

    # Class API reflects app APDU interface
    def get_trusted_input(self,
                          prev_out_index: int,
                          parsed_tx: Tx) -> bytes:
        """
        Computes the lengths of the chunks that will be sent as APDU payloads. Depending on the APDU
        the BTC app accepts payloads (composed from the tx and other data) of specific lengths
        See https://blog.ledger.com/btchip-doc/bitcoin-technical-beta.html#_get_trusted_input.
        See also https://github.com/zcash/zips/blob/master/protocol/protocol.pdf p. 81 for Zcash tx description
        """
        prevout_idx_be: bytes = prev_out_index.to_bytes(4, 'big')
        # APDU accepts chunks in the order below:
        # 1. desired prevout index (BE) || tx version (|| VersionGroupId if Zcash) || tx input count
        payload_chunks: List[bytes] = [
            prevout_idx_be + parsed_tx.version.buf + cast(ZcashExtHeader, parsed_tx.header.ext).version_group_id.buf
            + parsed_tx.input_count.buf
            if parsed_tx.type in (TxType.Zcash, TxType.ZcashSapling)
            else prevout_idx_be + parsed_tx.version.buf + parsed_tx.input_count.buf
        ]
        # 2. For each input:
        #    prevout hash || prevout index || input script length || input script (if present) || input sequence
        for _input in parsed_tx.inputs:
            payload_chunks.append(_input.prev_tx_hash + _input.prev_tx_out_index.buf + _input.script_len.buf
                                  + _input.script + _input.sequence_nb.buf)
        # 3. tx output count
        payload_chunks.append(parsed_tx.output_count.buf)
        # 3. For each output:
        #    output value || output script length || output script (if present)
        for _output in parsed_tx.outputs:
            payload_chunks.append(_output.value.buf + _output.script_len.buf + _output.script)
        # 4. tx locktime & Zcash data if present
        if parsed_tx.type in (TxType.Zcash, TxType.ZcashSapling):
            # BTC app inner protocol requires that a length varint be present before the zcash data from the tx
            # (although this length byte doesn't exist in the Zcash tx).
            footer: ZcashExtFooter = cast(ZcashExtFooter, parsed_tx.footer.ext)
            footer_buf: bytes = b''.join(v.buf if hasattr(v, 'buf') else v for v in list(footer.__dict__.values()) if v)
            payload_chunks.extend([parsed_tx.lock_time.buf + TxVarInt.to_bytes(len(footer_buf), 'little'), footer_buf])
        else:
            payload_chunks.append(parsed_tx.lock_time.buf)

        return self.send_apdu(*self.btc.apdu("GetTrustedInput", p1="00", p2="00", data=payload_chunks))

    def get_wallet_public_key(self,
                              data: BytesOrStr) -> bytes:
        return self.send_apdu(*self.btc.apdu("GetWalletPublicKey", p1="00", p2="00", data=[data]))

    def untrusted_hash_tx_input_start(self,
                                      parsed_tx: Tx,
                                      parsed_utxos: List[Tx],
                                      inputs: Optional[List[bytes]] = None,
                                      input_num: Optional[int] = None,
                                      mode: TxHashMode = TxHashMode(TxHashMode.LegacyBtc | TxHashMode.Trusted
                                                                    | TxHashMode.WithScript),
                                      endianness: lbstr = 'little') -> bytes:
        """Hash the inputs of the tx data"""
        def _get_p2() -> BytesOrStr:
            if mode.is_hash_with_script:
                return "80"
            elif mode.is_segwit_input_hash:
                return "02"
            elif mode.is_bcash_input_hash:
                return "03"
            elif mode.is_zcash_input_hash:
                return "04"
            elif mode.is_sapling_input_hash:
                return "05"
            raise ValueError(f"Invalid hash mode requested")

        def pubkey_hash_from_script(pubkey_script: bytes) -> bytes:
            idx: int = 0
            slen: int = len(pubkey_script[idx:])
            if slen < 20:
                raise ValueError("scriptPubkey length cannot be < 20 bytes")
            while slen > 20 and pubkey_script[idx] != 20:  # length of pubkey hash, always 20
                idx += 1
                slen = len(pubkey_script[idx:])
            return pubkey_script[idx + 1:idx + 1 + 20]

        if mode.is_trusted_input_hash and not inputs:
            raise ValueError("Argument 'inputs' cannot be None when the mode argument's 'Trusted' bit is set")
        if mode.is_btc_or_bcash_input_hash and not input_num:
            raise ValueError("Argument 'input_num' cannot be None when either of the mode argument's 'Bitcoin' or"
                             "BitcoinCash bits are set")

        # Format all inputs in the tx according to their nature (relaxed, trusted or legacy segwit)
        formatted_inputs: List[bytes] = self._get_formatted_inputs(
            mode=mode,
            parsed_tx=parsed_tx,
            parsed_utxos=parsed_utxos,
            tx_inputs=inputs if mode.is_trusted_input_hash else None)

        scripts: List[bytes] = []
        inputs_iter = parsed_tx.inputs if input_num is None else [parsed_tx.inputs[input_num]]
        for cur_input_num, _input in enumerate(inputs_iter):
            utxo_tx = self._get_utxo_from_input(tx_input=_input, utxos=parsed_utxos)
            script_pubkey = utxo_tx.outputs[_input.prev_tx_out_index.val].script

            if mode.is_btc_or_bcash_input_hash:
                # From btc.asc: "The input scripts shall be prepared by the host for the transaction signing process as
                #   per bitcoin rules: the current input script being signed shall be the previous output script (or the
                #   redeeming script when consuming a P2SH output, or the scriptCode when consuming a BIP 143 output),
                #   and other input script shall be null."
                scripts.append(script_pubkey if cur_input_num == input_num else None)
            elif mode.is_segwit_zcash_or_sapling_input_hash:
                # From btc.asc: "When using Segregated Witness Inputs or Overwinter/Sapling, the signing mechanism
                #   differs slightly :
                #   - The transaction shall be processed first with all inputs having a null script length
                #   - Then each input to sign shall be processed as part of a pseudo transaction with a single input
                #     and no outputs.
                if mode.is_segwit_input_hash and mode.is_hash_with_script \
                      and script_pubkey[0:3] != bytes.fromhex("76a914") and script_pubkey[-2:] != bytes.fromhex("88ac"):
                    # Segwit consensus rules state that if an input from the tx to sign refers to a Segwit prev_tx,
                    # then the input script to hash with that input shall be:
                    # 19 || 76a914 || 20-byte pubkey hash from prev_tx's requested output || 88ac
                    scripts.append(bytes.fromhex("76a914") + pubkey_hash_from_script(script_pubkey)
                                   + bytes.fromhex("88ac"))
                else:
                    scripts.append(script_pubkey)
            else:
                raise NotImplementedError(f"Unsupported hashing mode provided: {mode}")

        # version || input count
        # Note: input_count is set to 1 when sending inputs individually with their script
        version_chunk = parsed_tx.version.buf + cast(ZcashExtHeader, parsed_tx.header.ext).version_group_id.buf \
            if mode.is_zcash_input_hash or mode.is_sapling_input_hash \
            else parsed_tx.version.buf
        payload_chunks = [
            version_chunk + bytes.fromhex("01")
            if mode.is_hash_with_script and mode.is_segwit_zcash_or_sapling_input_hash
            else version_chunk + parsed_tx.input_count.buf
        ]
        # Compose a list of: input || script_len (possibly 0) || script (possibly None) || sequence_nb
        for f_input, script in zip(formatted_inputs, scripts):
            input_idx = self._get_input_index(parsed_tx, f_input, endianness)
            # add input with or without input script, depending on hashing phase
            if mode.is_segwit_zcash_or_sapling_input_hash:
                if mode.is_hash_with_script:
                    payload_chunks.extend(
                        [  # [input||script_len, script||sequence]
                            f_input + TxVarInt.to_bytes(len(script), 'little'),
                            script + parsed_tx.inputs[input_idx].sequence_nb.buf
                        ])
                else:   # Hash inputs w/o scripts
                    payload_chunks.extend(
                        [  # [input||0 (no script), sequence]
                            f_input + b'\x00', parsed_tx.inputs[input_idx].sequence_nb.buf
                        ])
            else:   # BTC or BCash tx
                if script is not None:
                    payload_chunks.extend(
                        [  # [input||script_len, script||sequence]
                            f_input + TxVarInt.to_bytes(len(script), 'little'),
                            script + parsed_tx.inputs[input_idx].sequence_nb.buf
                        ])
                else:
                    payload_chunks.extend(
                        [  # [input||script_len (00), sequence]
                            f_input + b'\x00', parsed_tx.inputs[input_idx].sequence_nb.buf
                        ])

        p2 = _get_p2()
        return self.send_apdu(*self.btc.apdu("UntrustedHashTxInputStart", p1="00", p2=p2, data=payload_chunks))

    def untrusted_hash_tx_input_finalize(self,
                                         p1: BytesOrStr,
                                         data: Union[BytesOrStr, Tx]) -> bytes:
        """
        Submit either tx outputs or change path to hashing, depending on value of p1 argument
        """
        param1: bytes = bytes.fromhex(p1) if type(p1) is str else p1
        if param1 in [b'\x00', b'\x80']:
            # Tx outputs path submission
            parsed_tx: Tx = data
            # output_count||repeated(output_amount||scriptPubkey)
            payload_chunks = [parsed_tx.output_count.buf]
            payload_chunks.extend([
                _output.value.buf + _output.script_len.buf + _output.script
                for _output in parsed_tx.outputs
            ])
            payload_chunks = [b''.join(payload_chunks)]
        elif param1 == b'\xFF':
            payload_chunks = [data]
        else:
            raise ValueError(f"Invalid value for parameter p1: {p1}")
        return self.send_apdu(*self.btc.apdu("UntrustedHashTxInputFinalize", p1=p1, p2="00", data=payload_chunks))

    def untrusted_hash_sign(self,
                            parsed_tx: Tx,
                            output_path: Optional[bytes] = None) -> bytes:
        """
        Perform hash signature with following payload:
            Num_derivs||Dest output path||User validation code length (0x00)||tx locktime||sigHashType(always 0x01)
        Supports Zcash app-specific intermediate signing on an empty ouput path/expiry_height by passing
        output_path = None
        """
        if (parsed_tx.type is TxType.Zcash and cast(ZcashExtHeader, parsed_tx.header.ext).overwintered_flag is True) \
                or parsed_tx.type is TxType.ZcashSapling:   # See Zcash consensus rules
            _output_path = bytes.fromhex("0000") if output_path is None else output_path
            exp_height = bytes.fromhex("00000000") if (output_path is None or parsed_tx.footer.ext is None) \
                else cast(ZcashExtFooter, parsed_tx.footer.ext).expiry_height.buf[::-1]  # big endian, as per BTC doc
        else:
            _output_path = output_path
            exp_height = None
        data = _output_path + bytes.fromhex("00") + parsed_tx.lock_time.buf + bytes.fromhex("01")
        if exp_height:
            data += exp_height

        return self.send_apdu(*self.btc.apdu("UntrustedHashSign", p1="00", p2="00", data=[data]),
                              p1_msb_means_next=False)

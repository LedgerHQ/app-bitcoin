from ctypes import ArgumentError
import sys

from dataclasses import dataclass

from typing import List, Mapping, Optional

from enum import IntEnum

from test_utils.bitcoin.common import ByteStreamParser, sha256


class BitcoinCommandBuilder:
    CLA_BITCOIN = 0xE1
    CLA_FRAMEWORK = 0xF8


class BitcoinInsType(IntEnum):
    GET_EXTENDED_PUBKEY = 0x00
    REGISTER_WALLET = 0x02
    GET_WALLET_ADDRESS = 0x03
    SIGN_PSBT = 0x04
    GET_MASTER_FINGERPRINT = 0x05
    SIGN_MESSAGE = 0x10


class FrameworkInsType(IntEnum):
    CONTINUE_INTERRUPTED = 0x01


class ClientCommandCode(IntEnum):
    YIELD = 0x10
    GET_PREIMAGE = 0x40
    GET_MERKLE_LEAF_PROOF = 0x41
    GET_MERKLE_LEAF_INDEX = 0x42
    GET_MORE_ELEMENTS = 0xA0

"""
Parses from standard input a transcript of a complete APDU exchange with the app, formatted as following:

```
=> e10200004e4d010c436f6c642073746f726167651d73682877736828736f727465646d756c746928322c40302c40312929290241fc0818760d7008dedb0e806aba44336b3a366c429e10dc626fa712089f939a
<= 4141fc0818760d7008dedb0e806aba44336b3a366c429e10dc626fa712089f939a0200e000
=> f80100004246441351818a3f426bccdf2d0e5e7e0c9a5023d09f06a3084e5ed9ac7d09d20001011ff8e5d0d3724c1bc905b0ff9ed0ae11980391e98f4e692cf48b3b342876f5bf
<= 400046441351818a3f426bccdf2d0e5e7e0c9a5023d09f06a3084e5ed9ac7d09d200e000
=> f80100008c8a8a005b37363232336136652f3438272f31272f30272f31275d747075624445374e51796d7234414674634a5869395461575a7472684164793851794b6d543455366239715942794178437a6f794d4a387a7735643878564c56706254524145715038705655786a4c4532764474317253466a6169533844537a3151634e5a3844317178554d7831672f2a2a
<= 4141fc0818760d7008dedb0e806aba44336b3a366c429e10dc626fa712089f939a0201e000
=> f8010000421ff8e5d0d3724c1bc905b0ff9ed0ae11980391e98f4e692cf48b3b342876f5bf010146441351818a3f426bccdf2d0e5e7e0c9a5023d09f06a3084e5ed9ac7d09d200
<= 40001ff8e5d0d3724c1bc905b0ff9ed0ae11980391e98f4e692cf48b3b342876f5bfe000
=> f80100008c8a8a005b66356163633266642f3438272f31272f30272f31275d747075624446417145474e7961643335596748387a787678465a714e556f507472356d446f6a7337777a6258514248545a347848655658473677324876734b766a4270615270546d6a59446a64506735773263365776753851426b794d44726d4257644379716b444d3772655373592f2a2a
<= a47f78a76a965d19df634511401803db2af6c5883033bb8d1f1249f93317cdc9ff96c09cfacf89f836ded409b7315b9d7f242db8033e4de4db1cb4c2751539889000
```

and produces a more human-readable representation of the transcript:

=> REGISTER_WALLET(serialized_wallet=010c436f6c642073746f726167651d73682877736828736f727465646d756c746928322c40302c40312929290241fc0818760d7008dedb0e806aba44336b3a366c429e10dc626fa712089f939a)
<= ⏸ GET_MERKLE_LEAF_PROOF(root=41fc0818760d7008dedb0e806aba44336b3a366c429e10dc626fa712089f939a,tree_size=2,leaf_index=0)
=> ▶ <leaf_hash:46441351818a3f426bccdf2d0e5e7e0c9a5023d09f06a3084e5ed9ac7d09d200><proof_length:1><n_proof_elements:1><proof:[1ff8e5d0d3724c1bc905b0ff9ed0ae11980391e98f4e692cf48b3b342876f5bf]>
<= ⏸ GET_PREIMAGE(hash=46441351818a3f426bccdf2d0e5e7e0c9a5023d09f06a3084e5ed9ac7d09d200)
=> ▶ <preimage_len:138><payload_size: 138><payload:005b37363232336136652f3438272f31272f30272f31275d747075624445374e51796d7234414674634a5869395461575a7472684164793851794b6d543455366239715942794178437a6f794d4a387a7735643878564c56706254524145715038705655786a4c4532764474317253466a6169533844537a3151634e5a3844317178554d7831672f2a2a>)
<= ⏸ GET_MERKLE_LEAF_PROOF(root=41fc0818760d7008dedb0e806aba44336b3a366c429e10dc626fa712089f939a,tree_size=2,leaf_index=1)
=> ▶ <leaf_hash:1ff8e5d0d3724c1bc905b0ff9ed0ae11980391e98f4e692cf48b3b342876f5bf><proof_length:1><n_proof_elements:1><proof:[46441351818a3f426bccdf2d0e5e7e0c9a5023d09f06a3084e5ed9ac7d09d200]>
<= ⏸ GET_PREIMAGE(hash=1ff8e5d0d3724c1bc905b0ff9ed0ae11980391e98f4e692cf48b3b342876f5bf)
=> ▶ <preimage_len:138><payload_size: 138><payload:005b66356163633266642f3438272f31272f30272f31275d747075624446417145474e7961643335596748387a787678465a714e556f507472356d446f6a7337777a6258514248545a347848655658473677324876734b766a4270615270546d6a59446a64506735773263365776753851426b794d44726d4257644379716b444d3772655373592f2a2a>)
<= a47f78a76a965d19df634511401803db2af6c5883033bb8d1f1249f93317cdc9ff96c09cfacf89f836ded409b7315b9d7f242db8033e4de4db1cb4c275153988 9000

It must be run from the root of the repository.
"""


@dataclass
class APDU:
    cla: int
    ins: int
    p1: int
    p2: int
    lc: int
    data: bytes

    @classmethod
    def from_raw(cls, apdu_raw: bytes):
        cla = apdu_raw[0]
        ins = apdu_raw[1]
        p1 = apdu_raw[2]
        p2 = apdu_raw[3]
        lc = apdu_raw[4]
        data = apdu_raw[5:]
        assert len(data) == lc

        return cls(cla, ins, p1, p2, lc, data)

    def serialize(self) -> bytes:
        return b''.join([
            self.cla.to_bytes(1, byteorder="big"),
            self.ins.to_bytes(1, byteorder="big"),
            self.p1.to_bytes(1, byteorder="big"),
            self.p2.to_bytes(1, byteorder="big"),
            self.lc.to_bytes(1, byteorder="big"),
            self.data
        ])


class CommandContext:
    def __init__(self):
        self.clear()

    def clear(self):
        self.known_preimages: Mapping[bytes, bytes] = {}
        # add some common known preimages (small numbers used as indices)
        for i in range(256):
            i_bytes = i.to_bytes(1, byteorder="big")
            self.known_preimages[sha256(i_bytes)] = i_bytes
            # also add the same prefixed with 0, as encoded in Merkle tree leafs
            self.known_preimages[sha256(b'\0' + i_bytes)] = b'\0' + i_bytes

        self.merkle_root_names: Mapping[bytes, str] = {}

        # state only relevant during SIGN_PSBT command
        self.sign_psbt__n_inputs: Optional[int] = None
        self.sign_psbt__input_map_commitment_hashes: Mapping[bytes, int] = {}
        self.sign_psbt__n_outputs: Optional[int] = None
        self.sign_psbt__output_map_commitment_hashes: Mapping[bytes, int] = {}

        # state only relevant during GET_PREIMAGE client command
        self.get_preimage__hash: Optional[bytes] = None

        # state only relevant during GET_MERKLE_LEAF_PROOF client command
        self.get_merkle_leaf_proof__root: Optional[bytes] = None
        self.get_merkle_leaf_proof__leaf_index: Optional[int] = None


H = 0x80000000


def format_path_item(path_item: int) -> str:
    if not 0 <= path_item < 2**32:
        raise ValueError("Invalid path")
    return str(path_item) if path_item < H else f"{str(path_item ^ H)}'"


def format_bip32_path(path: List[int]) -> str:
    return "m" if len(path) == 0 else "m/" + "/".join(map(format_path_item, path))


def format_hash_image(image: bytes, context: CommandContext) -> str:
    """
    Given the context of the current command and a bytes `image` of 32 bytes, outputs the hexadecimal representation of
    `image` if not a known preimage in the context, or represents it as "sha256(<preimage>)=<image>" if a preimage is
    known.
    """
    if len(image) != 32:
        raise ArgumentError("image must be exactly 32 bytes long")

    return f"sha256({context.known_preimages[image].hex()})={image.hex()}" if image in context.known_preimages else image.hex()


def format_merkle_root(root: bytes, context: CommandContext) -> str:
    """
    Given the context of the current command and a bytes `root` of 32 bytes, outputs the hexadecimal representation of
    `root` if the name of this Merkle tree is not set in the context, or represents it as "<root_name=root>" if a preimage is
    known.
    """
    if len(root) != 32:
        raise ArgumentError("image must be exactly 32 bytes long")

    return f"<{context.merkle_root_names[root]}={root.hex()}>" if root in context.merkle_root_names else root.hex()


class BitcoinCommandFormatter:
    ins_type: BitcoinInsType

    @staticmethod
    def format_request(apdu: APDU, stream: ByteStreamParser, context: CommandContext):
        raise NotImplementedError

    @staticmethod
    def format_response(response: bytes, sw: int, context: CommandContext):
        if len(response) == 0:
            print("<= {:04x}".format(sw))
        else:
            print("<= {} {:04x}".format(response.hex(), sw))


class GetExtendedPubkeyCommandFormatter(BitcoinCommandFormatter):
    ins_type = BitcoinInsType.GET_EXTENDED_PUBKEY

    @staticmethod
    def format_request(apdu: APDU, stream: ByteStreamParser, context: CommandContext):
        assert len(apdu.data) >= 2
        assert apdu.p1 == 0 and apdu.p2 == 0

        display = apdu.data[0]
        assert display == 0 or display == 1

        bip32_path_len = apdu.data[1]

        assert len(apdu.data) == 1 + 1 + 4 * bip32_path_len

        bip32_path = list(int.from_bytes(
            apdu.data[2 + 4*i: 2 + 4*i + 4], byteorder="big") for i in range(bip32_path_len))

        print(
            f"=> GET_EXTENDED_PUBKEY(display={display},path=\"{format_bip32_path(bip32_path)}\")")


class RegisterWalletCommandFormatter(BitcoinCommandFormatter):
    ins_type = BitcoinInsType.REGISTER_WALLET

    @staticmethod
    def format_request(apdu: APDU, stream: ByteStreamParser, context: CommandContext):
        assert len(apdu.data) >= 1
        wallet_len = apdu.data[0]
        assert len(apdu.data) == 1 + wallet_len

        print(f"=> REGISTER_WALLET(serialized_wallet={apdu.data[1:].hex()})")


class GetWalletAddressCommandFormatter(BitcoinCommandFormatter):
    ins_type = BitcoinInsType.GET_WALLET_ADDRESS

    @staticmethod
    def format_request(apdu: APDU, stream: ByteStreamParser, context: CommandContext):
        assert len(apdu.data) == 1 + 32 + 32 + 1 + 4

        display = apdu.data[0]
        assert display == 0 or display == 1
        wallet_id = apdu.data[1:1+32]
        wallet_hmac = apdu.data[1+32:1+32+32]
        change = apdu.data[1+32+32]
        address_index = int.from_bytes(
            apdu.data[1+32+32+1: 1+32+32+1 + 4], byteorder="big")

        print(
            f"=> GET_WALLET_ADDRESS(wallet_id={wallet_id.hex()}, wallet_hmac={wallet_hmac.hex()}, change={change}, address_index={address_index})")


class SignPsbtCommandFormatter(BitcoinCommandFormatter):
    ins_type = BitcoinInsType.SIGN_PSBT

    @staticmethod
    def format_request(apdu: APDU, stream: ByteStreamParser, context: CommandContext):
        global_map_commitment_size = stream.read_varint()
        global_map_commitment_keys_root = stream.read_bytes(32)
        global_map_commitment_values_root = stream.read_bytes(32)

        context.merkle_root_names[global_map_commitment_keys_root] = "global_map_commitment_keys_root"
        context.merkle_root_names[global_map_commitment_values_root] = "global_map_commitment_values_root"

        n_inputs = stream.read_varint()
        inputs_map_commitments_tree_root = stream.read_bytes(32)
        context.merkle_root_names[inputs_map_commitments_tree_root] = "inputs_map_commitments_tree_root"
        context.sign_psbt__n_inputs = n_inputs

        n_outputs = stream.read_varint()
        outputs_map_commitments_tree_root = stream.read_bytes(32)
        context.merkle_root_names[outputs_map_commitments_tree_root] = "outputs_map_commitments_tree_root"
        context.sign_psbt__n_outputs = n_outputs

        print(
            f"=> SIGN_PSBT(global_map_commitment=<{global_map_commitment_size},{format_merkle_root(global_map_commitment_keys_root, context)},{format_merkle_root(global_map_commitment_values_root, context)}>,n_inputs={n_inputs},inp_root_hash={format_merkle_root(inputs_map_commitments_tree_root, context)},n_outputs={n_outputs},outp_root_hash={format_merkle_root(outputs_map_commitments_tree_root, context)})")


class GetMasterFingerprintCommandFormatter(BitcoinCommandFormatter):
    ins_type = BitcoinInsType.GET_MASTER_FINGERPRINT

    @staticmethod
    def format_request(apdu: APDU, stream: ByteStreamParser, context: CommandContext):
        assert len(apdu.data) == 0
        print("=> GET_MASTER_FINGERPRINT()")


class SignMessageCommandFormatter(BitcoinCommandFormatter):
    ins_type = BitcoinInsType.SIGN_MESSAGE

    @staticmethod
    def format_request(apdu: APDU, stream: ByteStreamParser, context: CommandContext):
        bip32_path_len = stream.read_bytes(1)[0]
        bip32_path = [stream.read_uint(4, 'big')
                      for _ in range(bip32_path_len)]

        message_length = stream.read_varint()
        message_merkle_root = stream.read_bytes(32)
        stream.assert_empty()

        print(
            f"=> SIGN_MESSAGE(path=\"{format_bip32_path(bip32_path)}\",message_length={message_length},message_tree_hash={format_merkle_root(message_merkle_root, context)})")


bitcoin_command_formatters: List[BitcoinCommandFormatter] = [GetExtendedPubkeyCommandFormatter, RegisterWalletCommandFormatter,
                                                             GetWalletAddressCommandFormatter, SignPsbtCommandFormatter, GetMasterFingerprintCommandFormatter, SignMessageCommandFormatter]
bitcoin_command_formatters_map: Mapping[BitcoinInsType, BitcoinCommandFormatter] = {
    f.ins_type: f for f in bitcoin_command_formatters
}


class ClientCommandFormatter:
    code: ClientCommandCode

    @staticmethod
    def format_cmd_request(response: bytes, stream: ByteStreamParser, context: CommandContext):
        raise NotImplementedError

    @staticmethod
    def format_cmd_response(apdu: APDU, stream: ByteStreamParser, context: CommandContext):
        raise NotImplementedError


class YieldClientCommandFormatter(ClientCommandFormatter):
    code = ClientCommandCode.YIELD

    @staticmethod
    def format_cmd_request(response: bytes, stream: ByteStreamParser, context: CommandContext):
        print(f"<= ⏸ YIELD({response[1:].hex()})")

    @staticmethod
    def format_cmd_response(apdu: APDU, stream: ByteStreamParser, context: CommandContext):
        assert len(apdu.data) == 0
        print(f"=> ▶")


class GetPreimageClientCommandFormatter(ClientCommandFormatter):
    code = ClientCommandCode.GET_PREIMAGE

    @staticmethod
    def format_cmd_request(response: bytes, stream: ByteStreamParser, context: CommandContext):
        # skip first byte, but it must be 0
        if stream.read_bytes(1) != b'\0':
            raise RuntimeError(
                "Unexpected: the first byte of GET_PREIMAGE command should be 0")

        context.get_preimage__hash = stream.read_bytes(32)
        stream.assert_empty()

        print(f"<= ⏸ GET_PREIMAGE(hash={context.get_preimage__hash.hex()})")

    @staticmethod
    def format_cmd_response(apdu: APDU, stream: ByteStreamParser, context: CommandContext):
        preimage_len = stream.read_varint()
        payload_size = stream.read_bytes(1)[0]
        payload = stream.read_bytes(payload_size)

        # If returning a preimage for leaf of the input commitments Merkle tree, the payload is
        # an input's map commitment. We parse it and name the keys and values Merkle trees for easier reference
        if context.get_preimage__hash in context.sign_psbt__input_map_commitment_hashes:
            assert preimage_len == payload_size

            payload_stream = ByteStreamParser(payload)
            assert payload_stream.read_bytes(1) == b'\0'  # skip initial zero

            input_map_commitment_size = payload_stream.read_varint()
            input_map_commitment_keys_root = payload_stream.read_bytes(32)
            input_map_commitment_values_root = payload_stream.read_bytes(32)

            in_index = context.sign_psbt__input_map_commitment_hashes[context.get_preimage__hash]

            context.merkle_root_names[
                input_map_commitment_keys_root] = f"input_{in_index}_map_commitment_keys_root"
            context.merkle_root_names[
                input_map_commitment_values_root] = f"input_{in_index}_map_commitment_values_root"

        # Same as above for output map commitments
        if context.get_preimage__hash in context.sign_psbt__output_map_commitment_hashes:
            assert preimage_len == payload_size

            payload_stream = ByteStreamParser(payload)
            assert payload_stream.read_bytes(1) == b'\0'  # skip initial zero

            output_map_commitment_size = payload_stream.read_varint()
            output_map_commitment_keys_root = payload_stream.read_bytes(32)
            output_map_commitment_values_root = payload_stream.read_bytes(32)

            out_index = context.sign_psbt__output_map_commitment_hashes[context.get_preimage__hash]

            context.merkle_root_names[
                output_map_commitment_keys_root] = f"output_{out_index}_map_commitment_keys_root"
            context.merkle_root_names[
                output_map_commitment_values_root] = f"output_{out_index}_map_commitment_values_root"

        print(
            f"=> ▶ <preimage_len:{preimage_len}><payload_size: {payload_size}><payload:{payload.hex()}>)")

        context.get_preimage__hash = None


class GetMerkleLeafProofClientCommandFormatter(ClientCommandFormatter):
    code = ClientCommandCode.GET_MERKLE_LEAF_PROOF

    @staticmethod
    def format_cmd_request(response: bytes, stream: ByteStreamParser, context: CommandContext):
        root = stream.read_bytes(32)
        tree_size = stream.read_varint()
        leaf_index = stream.read_varint()
        stream.assert_empty()

        context.get_merkle_leaf_proof__root = root
        context.get_merkle_leaf_proof__leaf_index = leaf_index

        print(
            f"<= ⏸ GET_MERKLE_LEAF_PROOF(root={format_merkle_root(root, context)},tree_size={tree_size},leaf_index={leaf_index})")

    @staticmethod
    def format_cmd_response(apdu: APDU, stream: ByteStreamParser, context: CommandContext):
        leaf_hash = stream.read_bytes(32)
        proof_length = stream.read_bytes(1)[0]
        n_proof_elements = stream.read_bytes(1)[0]
        proof: List[bytes] = []
        while True:
            try:
                proof_el = stream.read_bytes(32)
                proof.append(proof_el)
            except ValueError:
                break
        stream.assert_empty()

        assert context.get_merkle_leaf_proof__root is not None and context.get_merkle_leaf_proof__leaf_index is not None

        # If it's a leaf of the inputs_map_commitments_tree or the outputs_map_commitments_tree_root, we store the corresponding hash
        if context.get_merkle_leaf_proof__root in context.merkle_root_names:
            root_name = context.merkle_root_names[context.get_merkle_leaf_proof__root]
            if root_name == 'inputs_map_commitments_tree_root':
                context.sign_psbt__input_map_commitment_hashes[
                    leaf_hash] = context.get_merkle_leaf_proof__leaf_index
            if root_name == 'outputs_map_commitments_tree_root':
                context.sign_psbt__output_map_commitment_hashes[
                    leaf_hash] = context.get_merkle_leaf_proof__leaf_index

        proof_str = f"[{','.join(proof_el.hex() for proof_el in proof)}]"

        print(
            f"=> ▶ <leaf_hash:{format_hash_image(leaf_hash, context)}><proof_length:{proof_length}><n_proof_elements:{n_proof_elements}><proof:{proof_str}>")

        context.get_merkle_leaf_proof__root = None
        context.get_merkle_leaf_proof__leaf_index = None


class GetMerkleLeafIndexClientCommandFormatter(ClientCommandFormatter):
    code = ClientCommandCode.GET_MERKLE_LEAF_INDEX

    @staticmethod
    def format_cmd_request(response: bytes, stream: ByteStreamParser, context: CommandContext):
        root = stream.read_bytes(32)
        leaf_hash = stream.read_bytes(32)
        stream.assert_empty()

        print(
            f"<= ⏸ GET_MERKLE_LEAF_INDEX(root={format_merkle_root(root, context)},leaf_hash={format_hash_image(leaf_hash, context)})")

    @staticmethod
    def format_cmd_response(apdu: APDU, stream: ByteStreamParser, context: CommandContext):
        found = stream.read_bytes(1)[0]
        assert 0 <= found <= 1
        leaf_index = stream.read_varint()
        print(f"=> ▶ <found:{found}><leaf_index:{leaf_index}>")


class GetMoreElementsClientCommandFormatter(ClientCommandFormatter):
    code = ClientCommandCode.GET_MORE_ELEMENTS

    @staticmethod
    def format_cmd_request(response: bytes, stream: ByteStreamParser, context: CommandContext):
        stream.assert_empty()
        print(f"<= ⏸ GET_MORE_ELEMENTS()")

    @staticmethod
    def format_cmd_response(apdu: APDU, stream: ByteStreamParser, context: CommandContext):
        n_elems = stream.read_bytes(1)[0]
        elem_len = stream.read_bytes(1)[0]
        elements = [stream.read_bytes(elem_len)
                    for _ in range(n_elems)]
        elements_str = f"[{','.join(el.hex() for el in elements)}]"
        print(
            f"=> ▶ <n_elems:{n_elems}><elem_len:{elem_len}><elements:{elements_str}>")


client_command_formatters: List[ClientCommandFormatter] = [YieldClientCommandFormatter, GetPreimageClientCommandFormatter,
                                                           GetMerkleLeafProofClientCommandFormatter, GetMerkleLeafIndexClientCommandFormatter, GetMoreElementsClientCommandFormatter]

client_command_formatters_map: Mapping[ClientCommandCode, ClientCommandFormatter] = {
    f.code: f for f in client_command_formatters
}


def run():
    # True if expecting an APDU going to the HWW (line starting with '=>'),
    # False if expecting a response (line starting with '<=')
    reading_apdu_in = True

    processing_command: Optional[int] = None

    processing_client_command: Optional[int] = None

    # context specific to the currently running command (if any)
    context = CommandContext()

    for line in sys.stdin:
        line_pieces = line.strip().split(' ')

        assert len(line_pieces) == 2

        apdu_raw = bytes.fromhex(line_pieces[1])

        if reading_apdu_in:
            # APDU request
            assert line_pieces[0] == '=>'

            apdu = APDU.from_raw(apdu_raw)

            if apdu.cla == BitcoinCommandBuilder.CLA_BITCOIN:
                try:
                    ins_type = BitcoinInsType(apdu.ins)
                except ValueError:
                    ins_type = None

                processing_command = ins_type
                context.clear()

                stream = ByteStreamParser(apdu.data)

                if ins_type in bitcoin_command_formatters_map:
                    bitcoin_command_formatters_map[ins_type].format_request(
                        apdu, stream, context)
                else:
                    print(f"=> {apdu.serialize().hex()}")

            elif apdu.cla == BitcoinCommandBuilder.CLA_FRAMEWORK:
                try:
                    ins_type = FrameworkInsType(apdu.ins)
                except ValueError:
                    ins_type = None

                if ins_type == FrameworkInsType.CONTINUE_INTERRUPTED:
                    if processing_client_command == None:
                        raise RuntimeError(
                            "Unexpected CONTINUE_INTERRUPTED with no interrupted command")

                    stream = ByteStreamParser(apdu.data)

                    if processing_client_command in client_command_formatters_map:
                        client_command_formatters_map[processing_client_command].format_cmd_response(
                            apdu, stream, context)
                    else:
                        # unknown command
                        print(f"=> ▶ {apdu.data.hex()}")

                    processing_client_command = None
                else:
                    # Unknown command, invalid logs or this tool needs to be updated!
                    raise RuntimeError("Unknown framework APDU")
            else:
                print(f"=> {apdu.serialize().hex()}")
        else:
            # APDU response
            assert line_pieces[0] == '<='
            assert len(apdu_raw) >= 2

            sw = int.from_bytes(apdu_raw[-2:], byteorder="big")
            response = apdu_raw[:-2]

            if sw == 0xE000:
                if processing_command is None:
                    raise RuntimeError(
                        "Unexpected INTERRUPTED_EXECUTION when no command was running")

                assert len(response) > 0
                stream = ByteStreamParser(response)
                processing_client_command = stream.read_bytes(1)[0]

                if processing_client_command in client_command_formatters_map:
                    client_command_formatters_map[processing_client_command].format_cmd_request(
                        response, stream, context)
                else:
                    # unknown command
                    print(f"<= ⏸ {response.hex()}")

            else:
                assert processing_command is not None

                if processing_command in bitcoin_command_formatters_map:
                    bitcoin_command_formatters_map[processing_command].format_response(
                        response, sw, context)
                else:
                    if len(response) == 0:
                        print("<= {:04x}".format(sw))
                    else:
                        print("<= {} {:04x}".format(response.hex(), sw))

                # Either an error or a success response; either way the command is done
                processing_command = None

        reading_apdu_in = not reading_apdu_in


if __name__ == "__main__":
    run()

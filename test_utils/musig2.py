"""
This module contains a complete, minimal, standalone MuSig cosigner implementation.
It is NOT a cryptographically secure implementation, and it is only to be used for
testing purposes.

In lack of a library for wallet policies in python, a minimal version of it for
the purpose of parsing and processing tr() descriptors is implemented here, using
embit for the the final task of compiling simple miniscript descriptors to Script.

The main objects and methods exported in this class are:

- PsbtMusig2Cosigner: an abstract class that represents a cosigner in MuSig2.
- HotMusig2Cosigner: an implementation of PsbtMusig2Cosigner that contains a hot
  extended private key. Useful for tests.
- run_musig2_test: tests a full signing cycle for a generic list of PsbtMusig2Cosigners.
"""


import hashlib
import hmac
from io import BytesIO
import re
from re import Match

import secrets
import struct
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple, Union
from abc import ABC, abstractmethod

import sys
import os

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import base58

from test_utils.taproot_sighash import SIGHASH_DEFAULT, TaprootSignatureHash
from test_utils import bip0327, bip0340, hash160, sha256
from test_utils import taproot
from test_utils.wallet_policy import (
    PlainKeyPlaceholder,
    MuSig2KeyPlaceholder,
    KeyPlaceholder,
    extract_placeholders,
)

from bitcoin_client.ledger_bitcoin._embit.descriptor.miniscript import Miniscript
from bitcoin_client.ledger_bitcoin.psbt import PSBT, PartiallySignedInput
from bitcoin_client.ledger_bitcoin.key import G, ExtendedKey, bytes_to_point, point_add, point_mul, point_to_bytes
from bitcoin_client.ledger_bitcoin.wallet import WalletPolicy


HARDENED_INDEX = 0x80000000


def tapleaf_hash(script: Optional[bytes], leaf_version=b'\xC0') -> Optional[bytes]:
    if script is None:
        return None
    return taproot.tagged_hash(
        "TapLeaf",
        leaf_version + taproot.ser_script(script)
    )




def unsorted_musig(pubkeys: Iterable[bytes], version_bytes: bytes) -> Tuple[str, bip0327.KeyAggContext]:
    """
    Constructs the musig2 aggregated extended public key from an unsorted list of
    compressed public keys, and the version bytes.
    """

    assert all(len(pk) == 33 for pk in pubkeys)
    assert len(version_bytes) == 4

    depth = b'\x00'
    fingerprint = b'\x00\x00\x00\x00'
    child_number = b'\x00\x00\x00\x00'

    key_agg_ctx = bip0327.key_agg(pubkeys)
    Q = key_agg_ctx.Q
    compressed_pubkey = (
        b'\x02' if Q[1] % 2 == 0 else b'\x03') + bip0327.get_xonly_pk(key_agg_ctx)
    chaincode = bytes.fromhex(
        "868087ca02a6f974c4598924c36b57762d32cb45717167e300622c7167e38965")
    ext_pubkey = version_bytes + depth + fingerprint + \
        child_number + chaincode + compressed_pubkey
    return base58.b58encode_check(ext_pubkey).decode(), key_agg_ctx


def musig(pubkeys: Iterable[bytes], version_bytes: bytes) -> Tuple[str, bip0327.KeyAggContext]:
    """
    Constructs the musig2 aggregated extended public key from a list of compressed public keys,
    and the version bytes. The keys are sorted, as required by the `the musig()` key expression
    in descriptors.
    """
    return unsorted_musig(sorted(pubkeys), version_bytes)


def aggregate_musig_pubkey(keys_info: Iterable[str]) -> Tuple[str, bip0327.KeyAggContext]:
    """
    Constructs the musig2 aggregated extended public key from the list of keys info
    of the participating keys.
    """

    pubkeys: list[bytes] = []
    versions: Set[str] = set()
    for ki in keys_info:
        start = ki.find(']')
        xpub = ki[start + 1:]
        xpub_bytes = base58.b58decode_check(xpub)
        versions.add(xpub_bytes[:4])
        pubkeys.append(xpub_bytes[-33:])

    if len(versions) > 1:
        raise ValueError(
            "All the extended public keys should be from the same network")

    return musig(pubkeys, versions.pop())


def derive_from_key_info(key_info: str, steps: List[int]) -> str:
    start = key_info.find(']')
    pk = ExtendedKey.deserialize(key_info[start + 1:])
    return pk.derive_pub_path(steps).to_string()


def derive_plain_descriptor(desc_tmpl: str, keys_info: List[str], is_change: bool, address_index: int):
    """
    Given a wallet policy, and the change/address_index combination, computes the corresponding descriptor.
    It replaces /** with /<0;1>/*
    It also replaces each musig() key expression with the corresponding xpub.
    The resulting descriptor can be used with descriptor libraries that do not support musig or wallet policies.
    """

    desc_tmpl = desc_tmpl.replace("/**", "/<0;1>/*")
    desc_tmpl = desc_tmpl.replace("*", str(address_index))

    # Replace each <M;N> with M if is_change is False, otherwise with N
    def replace_m_n(match: Match[str]):
        m, n = match.groups()
        return m if not is_change else n

    desc_tmpl = re.sub(r'<([^;]+);([^>]+)>', replace_m_n, desc_tmpl)

    # Replace musig(...) expressions
    def replace_musig(match: Match[str]):
        musig_content = match.group(1)
        steps = [int(x) for x in match.group(2).split("/")]

        assert len(steps) == 2

        key_indexes = [int(i.strip('@')) for i in musig_content.split(',')]
        key_infos = [keys_info[i] for i in key_indexes]
        agg_xpub = aggregate_musig_pubkey(key_infos)[0]

        return derive_from_key_info(agg_xpub, steps)

    desc_tmpl = re.sub(r'musig\(([^)]+)\)/(\d+/\d+)', replace_musig, desc_tmpl)

    # Replace @i/a/b with the i-th element in keys_info, deriving the key appropriately
    # to get a plain xpub
    def replace_key_index(match):
        index, step1, step2 = [int(x) for x in match.group(1).split('/')]
        return derive_from_key_info(keys_info[index], [step1, step2])

    desc_tmpl = re.sub(r'@(\d+/\d+/\d+)', replace_key_index, desc_tmpl)

    return desc_tmpl


class Tree:
    """
    Recursive structure that represents a taptree, or one of its subtrees.
    It can either contain a single descriptor template (if it's a tapleaf), or exactly two child Trees.
    """

    def __init__(self, content: Union[str, Tuple['Tree', 'Tree']]):
        if isinstance(content, str):
            self.script = content
            self.left, self.right = (None, None)
        else:
            self.script = None
            self.left, self.right = content

    @property
    def is_leaf(self) -> bool:
        return self.script is not None

    def __str__(self):
        if self.is_leaf:
            return self.script
        else:
            return f'{{{str(self.left)},{str(self.right)}}}'

    def placeholders(self) -> Iterator[Tuple[KeyPlaceholder, str]]:
        """
        Generates an iterator over the placeholders contained in the scripts of the tree's leaf nodes.

        Yields:
            Iterator[Tuple[KeyPlaceholder, str]]: An iterator over tuples containing a KeyPlaceholder and its associated script.
        """

        if self.is_leaf:
            assert self.script is not None
            for placeholder in extract_placeholders(self.script):
                yield (placeholder, self.script)
        else:
            assert self.left is not None and self.right is not None
            for placeholder, script in self.left.placeholders():
                yield (placeholder, script)
            for placeholder, script in self.right.placeholders():
                yield (placeholder, script)

    def get_taptree_hash(self, keys_info: List[str], is_change: bool, address_index: int) -> bytes:
        if self.is_leaf:
            assert self.script is not None
            leaf_desc = derive_plain_descriptor(
                self.script, keys_info, is_change, address_index)

            s = BytesIO(leaf_desc.encode())
            desc: Miniscript = Miniscript.read_from(
                s, taproot=True)

            return tapleaf_hash(desc.compile())

        else:
            assert self.left is not None and self.right is not None
            left_h = self.left.get_taptree_hash(
                keys_info, is_change, address_index)
            right_h = self.right.get_taptree_hash(
                keys_info, is_change, address_index)
            if left_h <= right_h:
                return taproot.tagged_hash("TapBranch", left_h + right_h)
            else:
                return taproot.tagged_hash("TapBranch", right_h + left_h)


class TrDescriptorTemplate:
    """
    Represents a descriptor template for a tr(KEY) or a tr(KEY,TREE).
    This is minimal implementation in order to enable iterating over the placeholders,
    and compile the corresponding leaf scripts.
    """

    def __init__(self, key: KeyPlaceholder, tree=Optional[Tree]):
        self.key: KeyPlaceholder = key
        self.tree: Optional[Tree] = tree

    @classmethod
    def from_string(cls, input_string: str) -> "TrDescriptorTemplate":
        parser = cls.Parser(input_string.replace("/**", "/<0;1>/*"))
        return parser.parse()

    class Parser:
        def __init__(self, input):
            self.input = input
            self.index = 0
            self.length = len(input)

        def parse(self) -> "TrDescriptorTemplate":
            if self.input.startswith('tr('):
                self.consume('tr(')
                key = self.parse_keyplaceholder()
                tree = None
                if self.peek() == ',':
                    self.consume(',')
                    tree = self.parse_tree()
                self.consume(')')
                return TrDescriptorTemplate(key, tree)
            else:
                raise Exception(
                    "Syntax error: Input does not start with 'tr('")

        def parse_keyplaceholder(self) -> KeyPlaceholder:
            if self.peek() == '@':
                self.consume('@')
                key_index = self.parse_num()
                self.consume('/<')
                num1 = self.parse_num()
                self.consume(';')
                num2 = self.parse_num()
                self.consume('>/*')
                return PlainKeyPlaceholder(key_index, num1, num2)
            elif self.input[self.index:self.index+6] == 'musig(':
                self.consume('musig(')
                key_indexes = self.parse_key_indexes()
                self.consume(')/<')
                num1 = self.parse_num()
                self.consume(';')
                num2 = self.parse_num()
                self.consume('>/*')
                return MuSig2KeyPlaceholder(key_indexes, num1, num2)
            else:
                raise Exception("Syntax error in key placeholder")

        def parse_tree(self) -> Tree:
            if self.peek() == '{':
                self.consume('{')
                tree1 = self.parse_tree()
                self.consume(',')
                tree2 = self.parse_tree()
                self.consume('}')
                return Tree((tree1, tree2))
            else:
                return Tree(self.parse_script())

        def parse_script(self) -> str:
            start = self.index
            nesting = 0
            while self.index < self.length and (nesting > 0 or self.input[self.index] not in ('}', ',', ')')):
                if self.input[self.index] == '(':
                    nesting = nesting + 1
                elif self.input[self.index] == ')':
                    nesting = nesting - 1

                self.index += 1
            return self.input[start:self.index]

        def parse_key_indexes(self) -> List[int]:
            nums = []
            self.consume('@')
            nums.append(self.parse_num())
            while self.peek() == ',':
                self.consume(',@')
                nums.append(self.parse_num())
            return nums

        def parse_num(self) -> int:
            start = self.index
            while self.index < self.length and self.input[self.index].isdigit():
                self.index += 1
            return int(self.input[start:self.index])

        def consume(self, char: str) -> None:
            if self.input[self.index:self.index+len(char)] == char:
                self.index += len(char)
            else:
                raise Exception(
                    f"Syntax error: Expected '{char}'; rest: {self.input[self.index:]}")

        def peek(self):
            return self.input[self.index] if self.index < self.length else None

    def placeholders(self) -> Iterator[Tuple[KeyPlaceholder, Optional[str]]]:
        """
        Generates an iterator over the placeholders contained in the template and its tree, also
        yielding the corresponding leaf script descriptor (or None for the keypath placeholder).

        Yields:
            Iterator[Tuple[KeyPlaceholder, Optional[str]]]: An iterator over tuples containing a KeyPlaceholder and an optional associated script.
        """

        yield (self.key, None)

        if self.tree is not None:
            for placeholder, script in self.tree.placeholders():
                yield (placeholder, script)

    def get_taptree_hash(self, keys_info: List[str], is_change: bool, address_index: int) -> bytes:
        if self.tree is None:
            raise ValueError("There is no taptree")
        return self.tree.get_taptree_hash(keys_info, is_change, address_index)


class PsbtMusig2Cosigner(ABC):
    @abstractmethod
    def get_participant_pubkey(self) -> bip0327.Point:
        """
        This method should returns this cosigner's public key.
        """
        pass

    @abstractmethod
    def generate_public_nonces(self, psbt: PSBT) -> None:
        """
        This method should generate public nonces and modify the given Psbt object in-place.
        It should raise an exception in case of failure.
        """
        pass

    @abstractmethod
    def generate_partial_signatures(self, psbt: PSBT) -> None:
        """
        Receives a PSBT that contains all the participants' public nonces, and adds this participant's partial signature.
        It should raise an exception in case of failure.
        """
        pass


def find_change_and_addr_index_for_musig(input_psbt: PartiallySignedInput, placeholder: MuSig2KeyPlaceholder, agg_xpub: ExtendedKey):
    num1, num2 = placeholder.num1, placeholder.num2

    agg_xpub_fingerprint = hash160(agg_xpub.pubkey)[0:4]

    # Iterate through tap key origins in the input
    # TODO: this might be made more precise (e.g. use the leaf_hash from the tap_bip32_paths items)
    for xonly, (_, key_origin) in input_psbt.tap_bip32_paths.items():
        der_path = key_origin.path
        # Check if the fingerprint matches the expected pattern and the derivation path has the correct structure
        if key_origin.fingerprint == agg_xpub_fingerprint and len(der_path) == 2 and der_path[0] < HARDENED_INDEX and der_path[1] < HARDENED_INDEX and (der_path[0] == num1 or der_path[0] == num2):
            if xonly != agg_xpub.derive_pub_path(der_path).pubkey[1:]:
                continue

            # Determine if the address is a change address and extract the address index
            is_change = (der_path[0] == num2)
            addr_index = int(der_path[1])
            return is_change, addr_index

    return None


def get_bip32_tweaks(ext_key: ExtendedKey, steps: List[int]) -> List[bytes]:
    """
    Generate BIP32 tweaks for a series of derivation steps on an extended key.

    Args:
        ext_key (ExtendedKey): The extended public key.
        steps (List[int]): A list of derivation steps (must be unhardened).

    Returns:
        List[bytes]: The list of additive tweaks for those derivation steps.
    """

    result = []

    cur_pubkey = ext_key.pubkey
    cur_chaincode = ext_key.chaincode

    for step in steps:
        if step < 0 or step >= HARDENED_INDEX:
            raise ValueError("Invalid unhardened derivation step")

        data = cur_pubkey + struct.pack(">L", step)
        Ihmac = hmac.new(cur_chaincode, data, hashlib.sha512).digest()
        Il = Ihmac[:32]
        Ir = Ihmac[32:]

        result.append(Il)

        Il_int = int.from_bytes(Il, 'big')
        child_pubkey_point = point_add(point_mul(G, Il_int),
                                       bytes_to_point(cur_pubkey))
        child_pubkey = point_to_bytes(child_pubkey_point)

        cur_pubkey = child_pubkey
        cur_chaincode = Ir

    return result


def process_placeholder(
    wallet_policy: WalletPolicy,
    psbt_input: PartiallySignedInput,
    placeholder: MuSig2KeyPlaceholder,
    keyagg_ctx: bip0327.KeyAggContext,
    agg_xpub: ExtendedKey,
    tapleaf_desc: Optional[str],
    desc_tmpl: TrDescriptorTemplate
) -> Optional[Tuple[List[bytes], List[bool], Optional[bytes], bytes]]:
    """
    This method encapsulates all the precomputations that are done for a certain
    wallet policy, psbt input and musig() placeholder that are common to both the
    nonce generation and the partial signature generation flows.

    Returs a tuple containing:
    - tweaks: a list of tweaks to be applied to the aggregate musig key
    - is_xonly_tweak: a list of boolean of the same length of tweaks, specifying for
      each of them if it's a plain tweak or an x-only tweak
    - leaf_script: the compiled leaf script, or None for a taproot keypath spend
    - aggpk_tweaked: the value of the aggregate pubkey after applying the tweaks
    """
    res = find_change_and_addr_index_for_musig(
        psbt_input, placeholder, agg_xpub)
    if res is None:
        return None
    is_change, address_index = res

    leaf_script = None
    if tapleaf_desc is not None:
        leaf_desc = derive_plain_descriptor(
            tapleaf_desc, wallet_policy.keys_info, is_change, address_index)
        s = BytesIO(leaf_desc.encode())
        desc: Miniscript = Miniscript.read_from(s, taproot=True)
        leaf_script = desc.compile()

    tweaks = []
    is_xonly_tweak = []

    # Compute bip32 tweaks
    bip32_steps = [
        placeholder.num2 if is_change else placeholder.num1,
        address_index
    ]
    bip32_tweaks = get_bip32_tweaks(agg_xpub, bip32_steps)
    for tweak in bip32_tweaks:
        tweaks.append(tweak)
        is_xonly_tweak.append(False)

    # aggregate key after the bip_32 derivations (but before the taptweak, if any)
    der_key = agg_xpub.derive_pub_path(bip32_steps)

    # x-only tweak, only if spending the keypath
    if tapleaf_desc is None:
        t = der_key.pubkey[-32:]
        if desc_tmpl.tree is not None:
            t += desc_tmpl.get_taptree_hash(
                wallet_policy.keys_info, is_change, address_index)
        tweaks.append(taproot.tagged_hash("TapTweak", t))
        is_xonly_tweak.append(True)

    keyagg_ctx = aggregate_musig_pubkey(
        wallet_policy.keys_info[i] for i in placeholder.key_indexes)[1]

    for tweak, is_xonly in zip(tweaks, is_xonly_tweak):
        keyagg_ctx = bip0327.apply_tweak(keyagg_ctx, tweak, is_xonly)

    aggpk_tweaked = bip0327.cbytes(keyagg_ctx.Q)

    return (tweaks, is_xonly_tweak, leaf_script, aggpk_tweaked)


class HotMusig2Cosigner(PsbtMusig2Cosigner):
    """
    Implements a PsbtMusig2Cosigner for a given wallet policy and a private
    that appears as one of the key in a musig() key expression.
    """

    def __init__(self, wallet_policy: WalletPolicy, privkey: str) -> None:
        super().__init__()

        self.wallet_policy = wallet_policy
        self.privkey = ExtendedKey.deserialize(privkey)

        assert self.privkey.to_string() == privkey

        self.musig_psbt_sessions: Dict[bytes, bytes] = {}

        assert self.privkey.is_private

    def compute_psbt_session_id(self, psbt: PSBT) -> bytes:
        psbt.tx.rehash()
        return sha256(psbt.tx.hash + self.wallet_policy.id)

    def get_participant_pubkey(self) -> bip0327.Point:
        return bip0327.cpoint(self.privkey.pubkey)

    def generate_public_nonces(self, psbt: PSBT) -> None:
        desc_tmpl = TrDescriptorTemplate.from_string(
            self.wallet_policy.descriptor_template)

        psbt_session_id = self.compute_psbt_session_id(psbt)

        # root of all pseudorandomness for this psbt session
        rand_seed = secrets.token_bytes(32)

        for placeholder_index, (placeholder, tapleaf_desc) in enumerate(desc_tmpl.placeholders()):
            if not isinstance(placeholder, MuSig2KeyPlaceholder):
                continue

            agg_xpub_str, keyagg_ctx = aggregate_musig_pubkey(
                self.wallet_policy.keys_info[i] for i in placeholder.key_indexes)
            agg_xpub = ExtendedKey.deserialize(agg_xpub_str)

            for input_index, input in enumerate(psbt.inputs):
                result = process_placeholder(
                    self.wallet_policy, input, placeholder, keyagg_ctx, agg_xpub, tapleaf_desc, desc_tmpl)
                if result is None:
                    continue

                (_, _, leaf_script, aggpk_tweaked) = result

                rand_i_j = sha256(
                    rand_seed +
                    input_index.to_bytes(4, byteorder='big') +
                    placeholder_index.to_bytes(4, byteorder='big')
                )

                # secnonce: bytearray
                # pubnonce: bytes
                _, pubnonce = bip0327.nonce_gen_internal(
                    rand_=rand_i_j,
                    sk=None,
                    pk=self.privkey.pubkey,
                    aggpk=aggpk_tweaked,
                    msg=None,
                    extra_in=None
                )

                pubnonce_identifier = (
                    self.privkey.pubkey,
                    aggpk_tweaked,
                    tapleaf_hash(leaf_script)
                )

                assert len(aggpk_tweaked) == 33

                input.musig2_pub_nonces[pubnonce_identifier] = pubnonce

        self.musig_psbt_sessions[psbt_session_id] = rand_seed

    def generate_partial_signatures(self, psbt: PSBT) -> None:
        desc_tmpl = TrDescriptorTemplate.from_string(
            self.wallet_policy.descriptor_template)

        psbt_session_id = self.compute_psbt_session_id(psbt)

        # Get the session's randomness seed, while simultaneously deleting it from the open sessions
        rand_seed = self.musig_psbt_sessions.pop(psbt_session_id, None)

        if rand_seed is None:
            raise ValueError(
                "No musig signing session for this psbt")

        for placeholder_index, (placeholder, tapleaf_desc) in enumerate(desc_tmpl.placeholders()):
            if not isinstance(placeholder, MuSig2KeyPlaceholder):
                continue

            agg_xpub_str, keyagg_ctx = aggregate_musig_pubkey(
                self.wallet_policy.keys_info[i] for i in placeholder.key_indexes)
            agg_xpub = ExtendedKey.deserialize(agg_xpub_str)

            for input_index, input in enumerate(psbt.inputs):
                result = process_placeholder(
                    self.wallet_policy, input, placeholder, keyagg_ctx, agg_xpub, tapleaf_desc, desc_tmpl)
                if result is None:
                    continue

                (tweaks, is_xonly_tweak, leaf_script, aggpk_tweaked) = result

                rand_i_j = sha256(
                    rand_seed +
                    input_index.to_bytes(4, byteorder='big') +
                    placeholder_index.to_bytes(4, byteorder='big')
                )

                secnonce, pubnonce = bip0327.nonce_gen_internal(
                    rand_=rand_i_j,
                    sk=None,
                    pk=self.privkey.pubkey,
                    aggpk=aggpk_tweaked,
                    msg=None,
                    extra_in=None
                )

                pubkeys_in_musig: List[ExtendedKey] = []
                my_key_index_in_musig: Optional[int] = None
                for i in placeholder.key_indexes:
                    k_i = self.wallet_policy.keys_info[i]
                    xpub_i = k_i[k_i.find(']') + 1:]
                    pubkeys_in_musig.append(ExtendedKey.deserialize(xpub_i))

                    if xpub_i == self.privkey.neutered().to_string():
                        my_key_index_in_musig = i

                if my_key_index_in_musig is None:
                    raise ValueError("No internal key found in musig")

                # sort the keys in ascending order
                pubkeys_in_musig = list(
                    sorted(pubkeys_in_musig, key=lambda x: x.pubkey))

                nonces: List[bytes] = []
                for participant_key in pubkeys_in_musig:
                    participant_pubnonce_identifier = (
                        participant_key.pubkey,
                        aggpk_tweaked,
                        tapleaf_hash(leaf_script)
                    )

                    if participant_key.pubkey == self.privkey.pubkey and input.musig2_pub_nonces[participant_pubnonce_identifier] != pubnonce:
                        raise ValueError(
                            f"Public nonce in psbt didn't match the expected one for cosigner {self.privkey.pubkey}")

                    assert len(aggpk_tweaked) == 33

                    if participant_pubnonce_identifier in input.musig2_pub_nonces:
                        nonces.append(
                            input.musig2_pub_nonces[participant_pubnonce_identifier])
                    else:
                        raise ValueError(
                            f"Missing pubnonce for pubkey {participant_key.pubkey.hex()} in psbt")

                if leaf_script is None:
                    sighash = TaprootSignatureHash(
                        txTo=psbt.tx,
                        spent_utxos=[
                            psbt.inputs[i].witness_utxo for i in range(len(psbt.inputs))],
                        hash_type=input.sighash or SIGHASH_DEFAULT,
                        input_index=input_index,
                    )
                else:
                    sighash = TaprootSignatureHash(
                        txTo=psbt.tx,
                        spent_utxos=[
                            psbt.inputs[i].witness_utxo for i in range(len(psbt.inputs))],
                        hash_type=input.sighash or SIGHASH_DEFAULT,
                        input_index=input_index,
                        scriptpath=True,
                        script=leaf_script
                    )

                aggnonce = bip0327.nonce_agg(nonces)

                session_ctx = bip0327.SessionContext(
                    aggnonce=aggnonce,
                    pubkeys=[pk.pubkey for pk in pubkeys_in_musig],
                    tweaks=tweaks,
                    is_xonly=is_xonly_tweak,
                    msg=sighash)

                partial_sig = bip0327.sign(
                    secnonce, self.privkey.privkey, session_ctx)

                pubnonce_identifier = (
                    self.privkey.pubkey,
                    aggpk_tweaked,
                    tapleaf_hash(leaf_script)
                )

                input.musig2_partial_sigs[pubnonce_identifier] = partial_sig


def run_musig2_test(wallet_policy: WalletPolicy, psbt: PSBT, cosigners: List[PsbtMusig2Cosigner], sighashes: list[bytes]):
    """
    This performs the following steps:
        - go through all the cosigners to let them add their pubnonce;
        - go through all the cosigners to let them add their partial signature;
        - aggregate the partial signatures to produce the final Schnorr signature;
        - verify that the produced signature is valid for the provided sighash.

    The sighashes (one per input) are given as argument and are assumed to be correct.
    """

    if len(psbt.inputs) != len(sighashes):
        raise ValueError("The length of the sighashes array is incorrect")

    for signer in cosigners:
        signer.generate_public_nonces(psbt)

    for signer in cosigners:
        signer.generate_partial_signatures(psbt)

    desc_tmpl = TrDescriptorTemplate.from_string(
        wallet_policy.descriptor_template)

    for placeholder, tapleaf_desc in desc_tmpl.placeholders():
        if not isinstance(placeholder, MuSig2KeyPlaceholder):
            continue

        agg_xpub_str, keyagg_ctx = aggregate_musig_pubkey(
            wallet_policy.keys_info[i] for i in placeholder.key_indexes)
        agg_xpub = ExtendedKey.deserialize(agg_xpub_str)

        for input_index, input in enumerate(psbt.inputs):
            result = process_placeholder(
                wallet_policy, input, placeholder, keyagg_ctx, agg_xpub, tapleaf_desc, desc_tmpl)

            if result is None:
                raise RuntimeError(
                    "Unexpected: processing the musig placeholder failed")

            (tweaks, is_xonly_tweak, leaf_script, aggpk_tweaked) = result

            assert len(aggpk_tweaked) == 33

            pubkeys_in_musig: List[ExtendedKey] = []
            for i in placeholder.key_indexes:
                k_i = wallet_policy.keys_info[i]
                xpub_i = k_i[k_i.find(']') + 1:]
                pubkeys_in_musig.append(ExtendedKey.deserialize(xpub_i))

            # sort the keys in ascending order
            pubkeys_in_musig = list(
                sorted(pubkeys_in_musig, key=lambda x: x.pubkey))

            nonces: List[bytes] = []
            for participant_key in pubkeys_in_musig:
                pubnonce_identifier = (
                    participant_key.pubkey,
                    aggpk_tweaked,
                    tapleaf_hash(leaf_script)
                )

                if pubnonce_identifier in input.musig2_pub_nonces:
                    nonces.append(
                        input.musig2_pub_nonces[pubnonce_identifier])
                else:
                    raise ValueError(
                        f"Missing pubnonce for pubkey {participant_key.pubkey.hex()} in psbt")

            aggnonce = bip0327.nonce_agg(nonces)

            sighash = sighashes[input_index]

            session_ctx = bip0327.SessionContext(
                aggnonce=aggnonce,
                pubkeys=[pk.pubkey for pk in pubkeys_in_musig],
                tweaks=tweaks,
                is_xonly=is_xonly_tweak,
                msg=sighash)

            # collect partial signatures
            psigs: List[bytes] = []

            for participant_key in pubkeys_in_musig:
                pubnonce_identifier = (
                    participant_key.pubkey,
                    bytes(aggpk_tweaked),
                    tapleaf_hash(leaf_script)
                )

                if pubnonce_identifier in input.musig2_partial_sigs:
                    psigs.append(
                        input.musig2_partial_sigs[pubnonce_identifier])
                else:
                    raise ValueError(
                        f"Missing partial signature for pubkey {participant_key.pubkey.hex()} in psbt")

            sig = bip0327.partial_sig_agg(psigs, session_ctx)

            aggpk_tweaked_xonly = aggpk_tweaked[1:]
            assert (bip0340.schnorr_verify(sighash, aggpk_tweaked_xonly, sig))

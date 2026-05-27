# This is a partial implementation of BIP-0388: https://github.com/bitcoin/bips/blob/master/bip-0388.mediawiki
# It is used to manipulate wallet policies, but it has incomplete error checking and does not support all the
# possible types of descriptor templates from the BIP.
# Only to be used for testing purposes.

import sys
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from io import BytesIO
import re
from typing import Iterator, List, Optional, Tuple, Type, Union

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from bitcoin_client.ledger_bitcoin.embit.descriptor.miniscript import Miniscript
from bitcoin_client.ledger_bitcoin.key import ExtendedKey
from test_utils.taproot import ser_script, tagged_hash


def tapleaf_hash(script: Optional[bytes], leaf_version=b'\xC0') -> Optional[bytes]:
    if script is None:
        return None
    return tagged_hash(
        "TapLeaf",
        leaf_version + ser_script(script)
    )


@dataclass
class PlainKeyPlaceholder:
    key_index: int
    num1: int
    num2: int


@dataclass
class MuSig2KeyPlaceholder:
    """A `musig(@i,@j,...)/<num1;num2>/*` placeholder. The key indexes refer
    to entries in the wallet's keys_info; the participant pubkeys are
    aggregated via BIP-327 to form a single synthetic key, after which the
    `/<num1;num2>/*` derivation is applied."""
    key_indexes: List[int]
    num1: int
    num2: int


KeyPlaceholder = Union[PlainKeyPlaceholder, MuSig2KeyPlaceholder]


def parse_placeholder(placeholder_str: str) -> KeyPlaceholder:
    """Parses a placeholder string to create a KeyPlaceholder object."""
    if placeholder_str.startswith('musig('):
        close = placeholder_str.index(')')
        keys_part = placeholder_str[len('musig('):close]
        key_indexes = [int(k.strip().lstrip('@')) for k in keys_part.split(',')]
        m = re.match(r'/<(\d+);(\d+)>/\*', placeholder_str[close + 1:])
        if m is None:
            raise ValueError(f"Invalid musig placeholder string: {placeholder_str!r}")
        return MuSig2KeyPlaceholder(key_indexes, int(m.group(1)), int(m.group(2)))
    elif placeholder_str.startswith('@'):
        parts = placeholder_str.split('/')
        key_index = int(parts[0].strip('@'))

        # Remove '<' from the start and '>' from the end
        nums_part = parts[1][1:-1]
        num1, num2 = map(int, nums_part.split(';'))

        return PlainKeyPlaceholder(key_index, num1, num2)
    else:
        raise ValueError("Invalid placeholder string")


def extract_placeholders(desc_tmpl: str) -> List[KeyPlaceholder]:
    """Extracts and parses all placeholders in a descriptor template, from left to right."""

    pattern = r'musig\((?:@\d+,)*(?:@\d+)\)/<\d+;\d+>/\*|@\d+/<\d+;\d+>/\*'
    matches = [(match.group(), match.start())
               for match in re.finditer(pattern, desc_tmpl)]
    sorted_matches = sorted(matches, key=lambda x: x[1])
    return [parse_placeholder(match[0]) for match in sorted_matches]


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
    def replace_m_n(match: re.Match[str]):
        m, n = match.groups()
        return m if not is_change else n

    desc_tmpl = re.sub(r'<([^;]+);([^>]+)>', replace_m_n, desc_tmpl)

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
            right_h = self.left.get_taptree_hash(
                keys_info, is_change, address_index)
            if left_h <= right_h:
                return tagged_hash("TapBranch", left_h + right_h)
            else:
                return tagged_hash("TapBranch", right_h + left_h)


class GenericParser(ABC):
    def __init__(self, input: str):
        self.input = input
        self.index = 0
        self.length = len(input)

    @abstractmethod
    def parse(self):
        pass

    def parse_keyplaceholder(self):
        if self.peek() == '@':
            self.consume('@')
            key_index = self.parse_num()
            self.consume('/<')
            num1 = self.parse_num()
            self.consume(';')
            num2 = self.parse_num()
            self.consume('>/*')
            return PlainKeyPlaceholder(key_index, num1, num2)
        elif self.input.startswith('musig(', self.index):
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
                nesting += 1
            elif self.input[self.index] == ')':
                nesting -= 1

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

    def consume(self, char: str):
        if self.input[self.index:self.index+len(char)] == char:
            self.index += len(char)
        else:
            raise Exception(
                f"Syntax error: Expected '{char}'; rest: {self.input[self.index:]}")

    def peek(self) -> Optional[str]:
        return self.input[self.index] if self.index < self.length else None


class DescriptorTemplate(ABC):
    """
    Represents a generic descriptor template.
    This is a base class for all specific descriptor templates.
    """

    @abstractmethod
    def __init__(self):
        pass

    @classmethod
    @abstractmethod
    def from_string(cls, input_string: str) -> 'DescriptorTemplate':
        pass

    @abstractmethod
    def placeholders(self) -> Iterator[Tuple[KeyPlaceholder, Optional[str]]]:
        pass

    @staticmethod
    def get_descriptor_type(input_string: str) -> Type['DescriptorTemplate']:
        if input_string.startswith('tr('):
            return TrDescriptorTemplate
        elif input_string.startswith('wsh('):
            return WshDescriptorTemplate
        elif input_string.startswith('wpkh('):
            return WpkhDescriptorTemplate
        elif input_string.startswith('sh(wpkh('):
            return ShWpkhDescriptorTemplate
        elif input_string.startswith('sh(wsh('):
            return ShWshDescriptorTemplate
        elif input_string.startswith('sh('):
            return ShDescriptorTemplate
        elif input_string.startswith('pkh('):
            return PkhDescriptorTemplate
        else:
            raise ValueError("Unknown descriptor type")

    @classmethod
    def from_string(cls, input_string: str) -> 'DescriptorTemplate':
        descriptor_type = cls.get_descriptor_type(input_string)
        return descriptor_type.from_string(input_string)

    def is_legacy(self) -> bool:
        return isinstance(self, (PkhDescriptorTemplate, ShDescriptorTemplate))

    def is_segwit(self) -> bool:
        return isinstance(self, (WshDescriptorTemplate, WpkhDescriptorTemplate,
                                 ShWpkhDescriptorTemplate, ShWshDescriptorTemplate,
                                 TrDescriptorTemplate))

    def is_taproot(self) -> bool:
        return isinstance(self, TrDescriptorTemplate)


class TrDescriptorTemplate(DescriptorTemplate):
    """
    Represents a descriptor template for a tr(KEY) or a tr(KEY,TREE).
    This is minimal implementation in order to enable iterating over the placeholders,
    and compile the corresponding leaf scripts.
    """

    def __init__(self, key: KeyPlaceholder, tree=Optional[Tree]):
        self.key: KeyPlaceholder = key
        self.tree: Optional[Tree] = tree

    @classmethod
    def from_string(cls, input_string):
        parser = cls.Parser(input_string.replace("/**", "/<0;1>/*"))
        return parser.parse()

    class Parser(GenericParser):
        def parse(self) -> 'TrDescriptorTemplate':
            self.consume('tr(')
            key = self.parse_keyplaceholder()
            tree = None
            if self.peek() == ',':
                self.consume(',')
                tree = self.parse_tree()
            self.consume(')')
            return TrDescriptorTemplate(key, tree)

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


class WshDescriptorTemplate(DescriptorTemplate):
    """
    Represents a wsh(SCRIPT) descriptor template.
    This is minimal implementation in order to enable iterating over the placeholders,
    and compile the corresponding leaf scripts.
    """

    def __init__(self, inner_script: str):
        self.inner_script = inner_script

    @classmethod
    def from_string(cls, input_string):
        parser = cls.Parser(input_string.replace("/**", "/<0;1>/*"))
        return parser.parse()

    class Parser(GenericParser):
        def parse(self) -> 'WshDescriptorTemplate':
            if self.input.startswith('wsh('):
                self.consume('wsh(')
                inner_script = self.parse_script()
                self.consume(')')
                return WshDescriptorTemplate(inner_script)
            else:
                raise Exception(
                    "Syntax error: Input does not start with 'tr('")

    def placeholders(self) -> Iterator[Tuple[KeyPlaceholder, Optional[str]]]:
        for placeholder in extract_placeholders(self.inner_script):
            yield (placeholder, None)


class WpkhDescriptorTemplate(DescriptorTemplate):
    """
    Represents a wpkh(KEY) descriptor template.
    This is minimal implementation in order to enable iterating over the placeholders,
    and compile the corresponding leaf scripts.
    """

    def __init__(self, key: KeyPlaceholder):
        self.key = key

    @classmethod
    def from_string(cls, input_string):
        parser = cls.Parser(input_string.replace("/**", "/<0;1>/*"))
        return parser.parse()

    class Parser(GenericParser):
        def parse(self) -> 'WpkhDescriptorTemplate':
            self.consume('wpkh(')
            key = self.parse_keyplaceholder()
            self.consume(')')
            return WpkhDescriptorTemplate(key)

    def placeholders(self) -> Iterator[Tuple[KeyPlaceholder, Optional[str]]]:
        yield (self.key, None)


class PkhDescriptorTemplate(DescriptorTemplate):
    """
    Represents a pkh(KEY) descriptor template.
    This is minimal implementation in order to enable iterating over the placeholders,
    and compile the corresponding leaf scripts.
    """

    def __init__(self, key: KeyPlaceholder):
        self.key = key

    @classmethod
    def from_string(cls, input_string):
        parser = cls.Parser(input_string.replace("/**", "/<0;1>/*"))
        return parser.parse()

    class Parser(GenericParser):
        def parse(self) -> 'PkhDescriptorTemplate':
            self.consume('pkh(')
            key = self.parse_keyplaceholder()
            self.consume(')')
            return PkhDescriptorTemplate(key)

    def placeholders(self) -> Iterator[Tuple[KeyPlaceholder, Optional[str]]]:
        yield (self.key, None)


class ShWpkhDescriptorTemplate(DescriptorTemplate):
    """
    Represents a sh(wpkh(KEY)) descriptor template — BIP-49 wrapped segwit.
    """

    def __init__(self, key: KeyPlaceholder):
        self.key = key

    @classmethod
    def from_string(cls, input_string):
        parser = cls.Parser(input_string.replace("/**", "/<0;1>/*"))
        return parser.parse()

    class Parser(GenericParser):
        def parse(self) -> 'ShWpkhDescriptorTemplate':
            self.consume('sh(wpkh(')
            key = self.parse_keyplaceholder()
            self.consume('))')
            return ShWpkhDescriptorTemplate(key)

    def placeholders(self) -> Iterator[Tuple[KeyPlaceholder, Optional[str]]]:
        yield (self.key, None)


class ShWshDescriptorTemplate(DescriptorTemplate):
    """
    Represents a sh(wsh(SCRIPT)) descriptor template.
    """

    def __init__(self, inner_script: str):
        self.inner_script = inner_script

    @classmethod
    def from_string(cls, input_string):
        parser = cls.Parser(input_string.replace("/**", "/<0;1>/*"))
        return parser.parse()

    class Parser(GenericParser):
        def parse(self) -> 'ShWshDescriptorTemplate':
            self.consume('sh(wsh(')
            inner_script = self.parse_script()
            self.consume('))')
            return ShWshDescriptorTemplate(inner_script)

    def placeholders(self) -> Iterator[Tuple[KeyPlaceholder, Optional[str]]]:
        for placeholder in extract_placeholders(self.inner_script):
            yield (placeholder, None)


class ShDescriptorTemplate(DescriptorTemplate):
    """
    Represents a legacy sh(SCRIPT) descriptor template — bare P2SH, where
    SCRIPT is neither wpkh(...) nor wsh(...) (those have their own
    classes). Used for `sh(multi(...))`, `sh(sortedmulti(...))`,
    `sh(pkh(...))`, etc.
    """

    def __init__(self, inner_script: str):
        self.inner_script = inner_script

    @classmethod
    def from_string(cls, input_string):
        parser = cls.Parser(input_string.replace("/**", "/<0;1>/*"))
        return parser.parse()

    class Parser(GenericParser):
        def parse(self) -> 'ShDescriptorTemplate':
            self.consume('sh(')
            inner_script = self.parse_script()
            self.consume(')')
            return ShDescriptorTemplate(inner_script)

    def placeholders(self) -> Iterator[Tuple[KeyPlaceholder, Optional[str]]]:
        for placeholder in extract_placeholders(self.inner_script):
            yield (placeholder, None)

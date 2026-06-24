#![cfg_attr(not(test), no_std)]

extern crate alloc;

// TODO:
// - add type checks
// - add malleability checks
// - add stack limits and other safety checks

mod cleartext;
mod time;

pub use cleartext::*;

use alloc::{boxed::Box, string::String, vec, vec::Vec};

#[cfg(test)]
use alloc::{format, string::ToString};

use core::str::FromStr;

use hex::{self, FromHex};

use bitcoin::{
    bip32::{ChildNumber, Xpub},
    consensus::{encode, Decodable, Encodable},
    io::Read,
    VarInt,
};

const HARDENED_INDEX: u32 = 0x80000000u32;
const MAX_OLDER_AFTER: u32 = 2147483647; // maximum allowed in older/after

// Maximum key count for `multi`/`sortedmulti` (OP_CHECKMULTISIG consensus limit).
const MAX_KEYS_MULTI: usize = 20;
// Maximum key count for the Taproot `multi_a`/`sortedmulti_a` variants.
const MAX_KEYS_MULTI_A: usize = 999;
// Maximum recursion depth for descriptor parsing. Bounds host-provided nesting
// (e.g. `andor(...andor(...))` or `{{{...}}}`) to keep stack usage finite on
// the constrained VM. Well above any realistic policy depth.
const MAX_PARSE_DEPTH: usize = 64;
// Maximum byte length of a serialized descriptor template accepted by
// `WalletPolicy::deserialize`. Practical policies are far below this.
const MAX_SERIALIZED_DESCRIPTORTEMPLATE_LEN: usize = 4096;
// Maximum number of key information entries accepted by `WalletPolicy::deserialize`.
// Matches the largest multi-key fragment we can produce (`multi_a`/`sortedmulti_a`).
const MAX_SERIALIZED_KEY_COUNT: usize = MAX_KEYS_MULTI_A;
// Maximum length of a serialized BIP-32 derivation path.
const MAX_BIP32_DERIVATION_PATH_LEN: usize = 32;

/// Error type for descriptor template / wallet policy parsing and serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Input string was empty when content was expected.
    EmptyInput,
    /// Parsing succeeded but left unconsumed input.
    TrailingInput,
    /// A required syntactic token was missing or unexpected.
    InvalidSyntax,
    /// Hex-encoded data was not valid hex.
    InvalidHex,
    /// A key, xpub, fingerprint, hash, or compressed-key byte was invalid.
    InvalidKey,
    /// A numeric literal was out of range or had illegal leading zeros.
    NumberOutOfRange,
    /// A data field was the wrong length.
    InvalidLength,
    /// An unrecognized descriptor fragment keyword was encountered.
    UnrecognizedFragment,
    /// A multisig/sortedmulti fragment had fewer than 2 key placeholders.
    TooFewKeyExpressions,
    /// The threshold `k` in `thresh(k, ...)` exceeds the number of sub-scripts.
    ThreshExceedsScripts,
    /// A key placeholder index was out of range for the key-information list.
    InvalidKeyIndex,
    /// The top-level descriptor type is not supported.
    InvalidTopLevelPolicy,
    /// Writing a descriptor to a `String` buffer failed.
    FormatError,
    /// `sh`/`wsh`/`wpkh`/`musig` used in a position that is not allowed by the spec.
    InvalidScriptContext,
    /// Too many keys for a multisig fragment.
    TooManyKeys,
    /// Invalid multisig quorum (threshold).
    InvalidMultisigQuorum,
    /// Descriptor template nesting exceeds [`MAX_PARSE_DEPTH`].
    NestingTooDeep,
}

/// The parsing context, tracking which top-level descriptor we are inside.
/// This determines which fragments and key expression forms are valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseContext {
    /// Top-level: no enclosing descriptor yet.
    TopLevel,
    /// Inside a `sh()` descriptor (legacy P2SH).
    Legacy,
    /// Inside a top-level `wsh()` descriptor (native segwit).
    Segwit,
    /// Inside `sh(wsh())` (wrapped segwit).
    WrappedSegwit,
    /// Inside a `tr()` descriptor (BIP-390: musig allowed).
    Taproot,
}

impl ParseContext {
    fn musig_allowed(self) -> bool {
        matches!(self, ParseContext::Taproot)
    }

    /// `sh()` is only allowed at the top level.
    fn sh_allowed(self) -> bool {
        matches!(self, ParseContext::TopLevel)
    }

    /// `wpkh()` is only allowed at the top level or inside `sh()`.
    fn wpkh_allowed(self) -> bool {
        matches!(self, ParseContext::TopLevel | ParseContext::Legacy)
    }

    /// `wsh()` is only allowed at the top level or inside `sh()`.
    fn wsh_allowed(self) -> bool {
        matches!(self, ParseContext::TopLevel | ParseContext::Legacy)
    }

    /// `tr()` is only allowed at the top level.
    fn tr_allowed(self) -> bool {
        matches!(self, ParseContext::TopLevel)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeyOrigin {
    pub fingerprint: u32,
    pub derivation_path: Vec<ChildNumber>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeyInformation {
    pub pubkey: Xpub,
    pub origin_info: Option<KeyOrigin>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum KeyExpressionType {
    PlainKey(u32),
    Musig(Vec<u32>),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeyExpression {
    pub key_type: KeyExpressionType,
    pub num1: u32,
    pub num2: u32,
}

impl KeyExpression {
    pub fn plain(key_index: u32, num1: u32, num2: u32) -> Self {
        KeyExpression {
            key_type: KeyExpressionType::PlainKey(key_index),
            num1,
            num2,
        }
    }

    pub fn is_plain(&self) -> bool {
        matches!(self.key_type, KeyExpressionType::PlainKey(_))
    }

    pub fn musig(key_indices: Vec<u32>, num1: u32, num2: u32) -> Self {
        KeyExpression {
            key_type: KeyExpressionType::Musig(key_indices),
            num1,
            num2,
        }
    }

    pub fn is_musig(&self) -> bool {
        matches!(self.key_type, KeyExpressionType::Musig(_))
    }

    /// Returns the key index for a plain key expression.
    /// Returns `None` for musig key expressions.
    pub fn plain_key_index(&self) -> Option<u32> {
        match &self.key_type {
            KeyExpressionType::PlainKey(idx) => Some(*idx),
            KeyExpressionType::Musig(_) => None,
        }
    }

    /// Returns the key indices for a musig key expression.
    /// Returns `None` for plain key expressions.
    pub fn musig_key_indices(&self) -> Option<&Vec<u32>> {
        match &self.key_type {
            KeyExpressionType::Musig(indices) => Some(indices),
            KeyExpressionType::PlainKey(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum DescriptorTemplate {
    Sh(Box<DescriptorTemplate>),
    Wsh(Box<DescriptorTemplate>),
    Pkh(KeyExpression),
    Wpkh(KeyExpression),
    Sortedmulti(u32, Vec<KeyExpression>),
    Sortedmulti_a(u32, Vec<KeyExpression>),
    Tr(KeyExpression, Option<TapTree>),

    Zero,
    One,
    Pk(KeyExpression),
    Pk_k(KeyExpression),
    Pk_h(KeyExpression),
    Older(u32),
    After(u32),
    Sha256([u8; 32]),
    Ripemd160([u8; 20]),
    Hash256([u8; 32]),
    Hash160([u8; 20]),
    Andor(
        Box<DescriptorTemplate>,
        Box<DescriptorTemplate>,
        Box<DescriptorTemplate>,
    ),
    And_v(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    And_b(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    And_n(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    Or_b(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    Or_c(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    Or_d(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    Or_i(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    Thresh(u32, Vec<DescriptorTemplate>),
    Multi(u32, Vec<KeyExpression>),
    Multi_a(u32, Vec<KeyExpression>),

    // wrappers
    A(Box<DescriptorTemplate>),
    S(Box<DescriptorTemplate>),
    C(Box<DescriptorTemplate>),
    T(Box<DescriptorTemplate>),
    D(Box<DescriptorTemplate>),
    V(Box<DescriptorTemplate>),
    J(Box<DescriptorTemplate>),
    N(Box<DescriptorTemplate>),
    L(Box<DescriptorTemplate>),
    U(Box<DescriptorTemplate>),
}

pub struct DescriptorTemplateIter<'a> {
    fragments: Vec<(&'a DescriptorTemplate, Option<&'a DescriptorTemplate>)>, // Store DescriptorTemplate and its associated leaf context
    placeholders: Vec<(&'a KeyExpression, Option<&'a DescriptorTemplate>)>, // Placeholders also carry the leaf context
}

impl<'a> From<&'a DescriptorTemplate> for DescriptorTemplateIter<'a> {
    fn from(desc: &'a DescriptorTemplate) -> Self {
        DescriptorTemplateIter {
            fragments: vec![(desc, None)], // Initially, there is no associated leaf context
            placeholders: Vec::new(),
        }
    }
}

impl<'a> Iterator for DescriptorTemplateIter<'a> {
    type Item = (&'a KeyExpression, Option<&'a DescriptorTemplate>);

    fn next(&mut self) -> Option<Self::Item> {
        while self.placeholders.len() > 0 || self.fragments.len() > 0 {
            // If there are pending placeholders, pop and return one
            if let Some(item) = self.placeholders.pop() {
                return Some(item);
            }

            let next_fragment = self.fragments.pop();
            if next_fragment.is_none() {
                break;
            }
            let (frag, tapleaf_desc) = next_fragment.unwrap();
            match frag {
                DescriptorTemplate::Sh(sub)
                | DescriptorTemplate::Wsh(sub)
                | DescriptorTemplate::A(sub)
                | DescriptorTemplate::S(sub)
                | DescriptorTemplate::C(sub)
                | DescriptorTemplate::T(sub)
                | DescriptorTemplate::D(sub)
                | DescriptorTemplate::V(sub)
                | DescriptorTemplate::J(sub)
                | DescriptorTemplate::N(sub)
                | DescriptorTemplate::L(sub)
                | DescriptorTemplate::U(sub) => {
                    self.fragments.push((sub, tapleaf_desc));
                }

                DescriptorTemplate::Andor(sub1, sub2, sub3) => {
                    self.fragments.push((sub3, tapleaf_desc));
                    self.fragments.push((sub2, tapleaf_desc));
                    self.fragments.push((sub1, tapleaf_desc));
                }

                DescriptorTemplate::Or_b(sub1, sub2)
                | DescriptorTemplate::Or_c(sub1, sub2)
                | DescriptorTemplate::Or_d(sub1, sub2)
                | DescriptorTemplate::Or_i(sub1, sub2)
                | DescriptorTemplate::And_v(sub1, sub2)
                | DescriptorTemplate::And_b(sub1, sub2)
                | DescriptorTemplate::And_n(sub1, sub2) => {
                    self.fragments.push((sub2, tapleaf_desc));
                    self.fragments.push((sub1, tapleaf_desc));
                }

                DescriptorTemplate::Tr(key, tree) => {
                    self.placeholders.push((key, None));
                    if let Some(t) = tree {
                        let mut leaves: Vec<_> = t.tapleaves().collect();
                        leaves.reverse();
                        for leaf in leaves {
                            self.fragments.push((leaf, Some(leaf)));
                        }
                    }
                }

                DescriptorTemplate::Pkh(key)
                | DescriptorTemplate::Wpkh(key)
                | DescriptorTemplate::Pk(key)
                | DescriptorTemplate::Pk_k(key)
                | DescriptorTemplate::Pk_h(key) => {
                    return Some((key, tapleaf_desc));
                }

                DescriptorTemplate::Sortedmulti(_, keys)
                | DescriptorTemplate::Sortedmulti_a(_, keys)
                | DescriptorTemplate::Multi(_, keys)
                | DescriptorTemplate::Multi_a(_, keys) => {
                    // Push keys onto the keys stack in reverse order
                    for key in keys.iter().rev() {
                        self.placeholders.push((key, tapleaf_desc));
                    }
                }

                DescriptorTemplate::Thresh(_, descs) => {
                    for desc in descs.iter().rev() {
                        self.fragments.push((desc, tapleaf_desc));
                    }
                }

                DescriptorTemplate::Zero
                | DescriptorTemplate::One
                | DescriptorTemplate::Older(_)
                | DescriptorTemplate::After(_)
                | DescriptorTemplate::Sha256(_)
                | DescriptorTemplate::Ripemd160(_)
                | DescriptorTemplate::Hash256(_)
                | DescriptorTemplate::Hash160(_) => {
                    // nothing to do, there are no placeholders for these
                }
            }
        }

        None
    }
}

/// Mutable iterator over the key placeholders of a [`DescriptorTemplate`].
///
/// Yields `&mut KeyExpression` in the same traversal order as
/// [`DescriptorTemplateIter`] (the immutable counterpart), so that in-place
/// mutations preserve the canonical ordering expected by
/// `are_key_derivations_canonical`.
///
/// Uses raw pointers internally to satisfy Rust's aliasing rules while still
/// providing a safe interface through the `placeholders_mut` method.
pub struct DescriptorTemplateIterMut<'a> {
    fragments: Vec<*mut DescriptorTemplate>,
    placeholders: Vec<*mut KeyExpression>,
    _marker: core::marker::PhantomData<&'a mut DescriptorTemplate>,
}

impl<'a> Iterator for DescriptorTemplateIterMut<'a> {
    type Item = &'a mut KeyExpression;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(ptr) = self.placeholders.pop() {
                // SAFETY: ptr was derived from a uniquely-borrowed &mut KeyExpression
                // that lives for 'a; no other reference to it exists.
                return Some(unsafe { &mut *ptr });
            }

            let frag_ptr = self.fragments.pop()?;
            // SAFETY: ptr was derived from a uniquely-borrowed &mut DescriptorTemplate
            // that lives for 'a; we create only one &mut at a time per pointer.
            let frag = unsafe { &mut *frag_ptr };

            match frag {
                DescriptorTemplate::Sh(sub)
                | DescriptorTemplate::Wsh(sub)
                | DescriptorTemplate::A(sub)
                | DescriptorTemplate::S(sub)
                | DescriptorTemplate::C(sub)
                | DescriptorTemplate::T(sub)
                | DescriptorTemplate::D(sub)
                | DescriptorTemplate::V(sub)
                | DescriptorTemplate::J(sub)
                | DescriptorTemplate::N(sub)
                | DescriptorTemplate::L(sub)
                | DescriptorTemplate::U(sub) => {
                    self.fragments.push(sub.as_mut() as *mut DescriptorTemplate);
                }

                DescriptorTemplate::Andor(sub1, sub2, sub3) => {
                    self.fragments
                        .push(sub3.as_mut() as *mut DescriptorTemplate);
                    self.fragments
                        .push(sub2.as_mut() as *mut DescriptorTemplate);
                    self.fragments
                        .push(sub1.as_mut() as *mut DescriptorTemplate);
                }

                DescriptorTemplate::Or_b(sub1, sub2)
                | DescriptorTemplate::Or_c(sub1, sub2)
                | DescriptorTemplate::Or_d(sub1, sub2)
                | DescriptorTemplate::Or_i(sub1, sub2)
                | DescriptorTemplate::And_v(sub1, sub2)
                | DescriptorTemplate::And_b(sub1, sub2)
                | DescriptorTemplate::And_n(sub1, sub2) => {
                    self.fragments
                        .push(sub2.as_mut() as *mut DescriptorTemplate);
                    self.fragments
                        .push(sub1.as_mut() as *mut DescriptorTemplate);
                }

                DescriptorTemplate::Tr(key, tree) => {
                    self.placeholders.push(key as *mut KeyExpression);
                    if let Some(t) = tree {
                        // Traverse the TapTree to collect mutable pointers to all
                        // leaves in left-to-right order (matching TapleavesIter),
                        // then reverse so we pop them in the correct order.
                        let mut leaf_ptrs: Vec<*mut DescriptorTemplate> = Vec::new();
                        let mut stack: Vec<*mut TapTree> = vec![t as *mut TapTree];
                        while let Some(node_ptr) = stack.pop() {
                            // SAFETY: node_ptr is derived from a valid &mut TapTree
                            // that lives for 'a; each node is visited exactly once.
                            let node = unsafe { &mut *node_ptr };
                            match node {
                                TapTree::Script(dt) => {
                                    leaf_ptrs.push(dt.as_mut() as *mut DescriptorTemplate);
                                }
                                TapTree::Branch(left, right) => {
                                    stack.push(&mut **right as *mut TapTree);
                                    stack.push(&mut **left as *mut TapTree);
                                }
                            }
                        }
                        leaf_ptrs.reverse();
                        self.fragments.extend(leaf_ptrs);
                    }
                }

                DescriptorTemplate::Pkh(key)
                | DescriptorTemplate::Wpkh(key)
                | DescriptorTemplate::Pk(key)
                | DescriptorTemplate::Pk_k(key)
                | DescriptorTemplate::Pk_h(key) => {
                    // SAFETY: key is a field of frag which is valid for 'a.
                    return Some(unsafe { &mut *(key as *mut KeyExpression) });
                }

                DescriptorTemplate::Sortedmulti(_, keys)
                | DescriptorTemplate::Sortedmulti_a(_, keys)
                | DescriptorTemplate::Multi(_, keys)
                | DescriptorTemplate::Multi_a(_, keys) => {
                    for key in keys.iter_mut().rev() {
                        self.placeholders.push(key as *mut KeyExpression);
                    }
                }

                DescriptorTemplate::Thresh(_, descs) => {
                    for desc in descs.iter_mut().rev() {
                        self.fragments.push(desc as *mut DescriptorTemplate);
                    }
                }

                DescriptorTemplate::Zero
                | DescriptorTemplate::One
                | DescriptorTemplate::Older(_)
                | DescriptorTemplate::After(_)
                | DescriptorTemplate::Sha256(_)
                | DescriptorTemplate::Ripemd160(_)
                | DescriptorTemplate::Hash256(_)
                | DescriptorTemplate::Hash160(_) => {
                    // no key placeholders in terminal fragments
                }
            }
        }
    }
}

impl DescriptorTemplate {
    /// Determines if root fragment is a wrapper.
    fn is_wrapper(&self) -> bool {
        match &self {
            DescriptorTemplate::A(_) => true,
            DescriptorTemplate::S(_) => true,
            DescriptorTemplate::C(_) => true,
            DescriptorTemplate::T(_) => true,
            DescriptorTemplate::D(_) => true,
            DescriptorTemplate::V(_) => true,
            DescriptorTemplate::J(_) => true,
            DescriptorTemplate::N(_) => true,
            DescriptorTemplate::L(_) => true,
            DescriptorTemplate::U(_) => true,
            _ => false,
        }
    }
    pub fn placeholders(&self) -> DescriptorTemplateIter<'_> {
        DescriptorTemplateIter::from(self)
    }
    pub fn placeholders_mut(&mut self) -> DescriptorTemplateIterMut<'_> {
        DescriptorTemplateIterMut {
            fragments: vec![self as *mut DescriptorTemplate],
            placeholders: Vec::new(),
            _marker: core::marker::PhantomData,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TapTree {
    Script(Box<DescriptorTemplate>),
    Branch(Box<TapTree>, Box<TapTree>),
}

impl TapTree {
    pub fn tapleaves(&self) -> TapleavesIter<'_> {
        TapleavesIter::new(self)
    }
}

pub struct TapleavesIter<'a> {
    stack: Vec<&'a TapTree>,
}

impl<'a> TapleavesIter<'a> {
    fn new(root: &'a TapTree) -> Self {
        TapleavesIter { stack: vec![root] }
    }
}

impl<'a> Iterator for TapleavesIter<'a> {
    type Item = &'a DescriptorTemplate;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(node) = self.stack.pop() {
            match node {
                TapTree::Script(descriptor) => return Some(descriptor),
                TapTree::Branch(left, right) => {
                    self.stack.push(right);
                    self.stack.push(left);
                }
            }
        }
        None
    }
}

impl core::fmt::Display for TapTree {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TapTree::Script(desc) => write!(f, "{}", desc),
            TapTree::Branch(left, right) => write!(f, "{{{},{}}}", left, right),
        }
    }
}

impl core::fmt::Display for KeyOrigin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:08x}", self.fingerprint)?;
        for step in &self.derivation_path {
            write!(f, "/{}", step)?;
        }
        Ok(())
    }
}

impl core::convert::TryFrom<&str> for KeyOrigin {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        // parse a string in the form "76223a6e/48'/1'/0'/1'"
        // the key origin info between [] is optional and might not be present
        if s.is_empty() {
            return Err(ParseError::EmptyInput);
        }
        let parts: Vec<&str> = s.split('/').collect();
        if parts[0].len() != 8 {
            return Err(ParseError::InvalidLength);
        }
        let fingerprint = u32::from_str_radix(parts[0], 16).map_err(|_| ParseError::InvalidKey)?;
        let derivation_path = parts[1..]
            .iter()
            .map(|x| ChildNumber::from_str(x).map_err(|_| ParseError::InvalidKey))
            .collect::<Result<Vec<ChildNumber>, Self::Error>>()?;
        Ok(KeyOrigin {
            fingerprint,
            derivation_path,
        })
    }
}

impl core::fmt::Display for KeyInformation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.origin_info {
            Some(origin_info) => write!(f, "[{}]{}", origin_info, self.pubkey),
            None => write!(f, "{}", self.pubkey),
        }
    }
}

impl core::fmt::Display for KeyExpression {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.key_type {
            KeyExpressionType::PlainKey(key_index) => {
                if self.num1 == 0 && self.num2 == 1 {
                    write!(f, "@{}/**", key_index)
                } else {
                    write!(f, "@{}/<{};{}>/*", key_index, self.num1, self.num2)
                }
            }
            KeyExpressionType::Musig(key_indices) => {
                write!(f, "musig(")?;
                for (i, idx) in key_indices.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "@{}", idx)?;
                }
                if self.num1 == 0 && self.num2 == 1 {
                    write!(f, ")/**")
                } else {
                    write!(f, ")/<{};{}>/*", self.num1, self.num2)
                }
            }
        }
    }
}

impl TryFrom<&str> for KeyInformation {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if s.is_empty() {
            return Err(ParseError::EmptyInput);
        }
        let (origin_info, pubkey_pos) = if s.starts_with('[') {
            let end = s.find(']').ok_or(ParseError::InvalidKey)?;
            (Some(KeyOrigin::try_from(&s[1..end])?), end + 1)
        } else {
            (None, 0)
        };
        let pubkey = Xpub::from_str(&s[pubkey_pos..]).map_err(|_| ParseError::InvalidKey)?;
        Ok(KeyInformation {
            pubkey,
            origin_info,
        })
    }
}

pub trait ToDescriptor {
    fn to_descriptor(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<String, ParseError>;
}

// Return type for all hand-rolled parser functions: (remaining_input, parsed_value)
type ParseResult<'a, T> = Result<(&'a str, T), ParseError>;

// Parses a decimal u32 (no leading zeros unless "0"), value <= max.
fn parse_number_up_to(input: &str, max: u32) -> ParseResult<'_, u32> {
    if input.is_empty() || !input.starts_with(|c: char| c.is_ascii_digit()) {
        return Err(ParseError::InvalidSyntax);
    }
    // reject leading zeros on multi-digit numbers
    if input.starts_with('0') && input.len() > 1 && input.as_bytes()[1].is_ascii_digit() {
        return Err(ParseError::NumberOutOfRange);
    }
    let end = input
        .bytes()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(input.len());
    let num: u32 = input[..end]
        .parse()
        .map_err(|_| ParseError::NumberOutOfRange)?;
    if num > max {
        return Err(ParseError::NumberOutOfRange);
    }
    Ok((&input[end..], num))
}

// Entry-point: parse a complete descriptor template string.
fn parse_descriptor_template(input: &str) -> Result<DescriptorTemplate, ParseError> {
    let (rest, descriptor) = parse_descriptor(input, ParseContext::TopLevel, 0)?;
    if rest.is_empty() {
        Ok(descriptor)
    } else {
        Err(ParseError::TrailingInput)
    }
}

// Parses a derivation-step number like "44" or "44'".
fn parse_derivation_step_number(input: &str) -> ParseResult<'_, u32> {
    let (rest, num) = parse_number_up_to(input, HARDENED_INDEX - 1)?;
    if rest.starts_with('\'') {
        Ok((&rest[1..], num + HARDENED_INDEX))
    } else {
        Ok((rest, num))
    }
}

// Parses the derivation suffix: /** or /<num1;num2>/*
fn parse_derivation_suffix(input: &str) -> ParseResult<'_, (u32, u32)> {
    if !input.starts_with('/') {
        return Err(ParseError::InvalidSyntax);
    }
    let rest = &input[1..];

    if rest.starts_with("**") {
        Ok((&rest[2..], (0u32, 1u32)))
    } else if rest.starts_with('<') {
        let rest = &rest[1..];
        let (rest, num1) = parse_derivation_step_number(rest)?;
        if !rest.starts_with(';') {
            return Err(ParseError::InvalidSyntax);
        }
        let (rest, num2) = parse_derivation_step_number(&rest[1..])?;
        if !rest.starts_with(">/*") {
            return Err(ParseError::InvalidSyntax);
        }
        Ok((&rest[3..], (num1, num2)))
    } else {
        Err(ParseError::InvalidSyntax)
    }
}

// Parses a key expression: @N/** or @N/<num1;num2>/*
// When the context allows musig, also accepts: musig(@N1,@N2,...)/** or musig(@N1,@N2,...)/<num1;num2>/*
// musig() is only valid inside tr() (BIP-390).
fn parse_key_expression(input: &str, ctx: ParseContext) -> ParseResult<'_, KeyExpression> {
    if input.starts_with("musig(") {
        if !ctx.musig_allowed() {
            return Err(ParseError::InvalidScriptContext);
        }
        return parse_musig_key_expression(input);
    }
    if !input.starts_with('@') {
        return Err(ParseError::InvalidSyntax);
    }
    let (rest, key_index) = parse_number_up_to(&input[1..], u32::MAX)?;
    let (rest, (num1, num2)) = parse_derivation_suffix(rest)?;

    Ok((rest, KeyExpression::plain(key_index, num1, num2)))
}

// Parses a musig key expression: musig(@N1,@N2,...)/** or musig(@N1,@N2,...)/<num1;num2>/*
// Per BIP-390, all participant key indices must be distinct.
fn parse_musig_key_expression(input: &str) -> ParseResult<'_, KeyExpression> {
    let mut rest = &input[6..]; // skip "musig("
    let mut key_indices = Vec::new();
    loop {
        if !rest.starts_with('@') {
            return Err(ParseError::InvalidSyntax);
        }
        let (r, idx) = parse_number_up_to(&rest[1..], u32::MAX)?;
        if key_indices.contains(&idx) {
            return Err(ParseError::InvalidKey);
        }
        key_indices.push(idx);
        rest = r;
        if rest.starts_with(',') {
            rest = &rest[1..];
        } else {
            break;
        }
    }
    if key_indices.len() < 2 {
        return Err(ParseError::TooFewKeyExpressions);
    }
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    rest = &rest[1..]; // skip ')'
    let (rest, (num1, num2)) = parse_derivation_suffix(rest)?;

    Ok((rest, KeyExpression::musig(key_indices, num1, num2)))
}

// Parses a descriptor, optionally preceded by a wrapper prefix like "asc:".
//
// `depth` is the current recursion depth; it is incremented on every call and
// rejected if it exceeds [`MAX_PARSE_DEPTH`]. This bounds stack usage on
// untrusted input that nests descriptors arbitrarily deeply (e.g.
// `andor(0,0,andor(0,0,...))` or `tr(@0,{{{{...}}}})`). A chain of wrapper
// letters like `aaaa:0` does not grow recursion depth because wrappers are
// applied iteratively in this function, not by re-entry.
fn parse_descriptor(
    input: &str,
    ctx: ParseContext,
    depth: usize,
) -> ParseResult<'_, DescriptorTemplate> {
    if depth >= MAX_PARSE_DEPTH {
        return Err(ParseError::NestingTooDeep);
    }
    let depth = depth + 1;

    // A wrapper prefix is a run of ASCII alphabetic chars followed by ':'.
    // Fragment keywords are always followed by '(' instead, so no ambiguity.
    let alpha_end = input
        .bytes()
        .position(|b| !b.is_ascii_alphabetic())
        .unwrap_or(input.len());
    let (input, wrappers) = if alpha_end > 0 && input.as_bytes().get(alpha_end) == Some(&b':') {
        let wrappers = &input[..alpha_end];
        (&input[alpha_end + 1..], wrappers)
    } else {
        (input, "")
    };

    let (input, inner) = parse_inner_descriptor(input, ctx, depth)?;

    // Apply wrappers in reverse character order (rightmost char = outermost wrapper)
    let mut result = inner;
    for wrapper in wrappers.chars().rev() {
        result = match wrapper {
            'a' => DescriptorTemplate::A(Box::new(result)),
            's' => DescriptorTemplate::S(Box::new(result)),
            'c' => DescriptorTemplate::C(Box::new(result)),
            't' => DescriptorTemplate::T(Box::new(result)),
            'd' => DescriptorTemplate::D(Box::new(result)),
            'v' => DescriptorTemplate::V(Box::new(result)),
            'j' => DescriptorTemplate::J(Box::new(result)),
            'n' => DescriptorTemplate::N(Box::new(result)),
            'l' => DescriptorTemplate::L(Box::new(result)),
            'u' => DescriptorTemplate::U(Box::new(result)),
            _ => return Err(ParseError::InvalidSyntax),
        };
    }
    Ok((input, result))
}

fn parse_inner_descriptor(
    input: &str,
    ctx: ParseContext,
    depth: usize,
) -> ParseResult<'_, DescriptorTemplate> {
    // Longer names checked before shorter to avoid premature prefix matches.
    if input.starts_with("sortedmulti_a(") {
        return parse_threshold_kp_fragment(
            input,
            "sortedmulti_a",
            DescriptorTemplate::Sortedmulti_a,
            ctx,
            MAX_KEYS_MULTI_A,
        );
    }
    if input.starts_with("sortedmulti(") {
        return parse_threshold_kp_fragment(
            input,
            "sortedmulti",
            DescriptorTemplate::Sortedmulti,
            ctx,
            MAX_KEYS_MULTI,
        );
    }
    if input.starts_with("multi_a(") {
        return parse_threshold_kp_fragment(
            input,
            "multi_a",
            DescriptorTemplate::Multi_a,
            ctx,
            MAX_KEYS_MULTI_A,
        );
    }
    if input.starts_with("multi(") {
        return parse_threshold_kp_fragment(
            input,
            "multi",
            DescriptorTemplate::Multi,
            ctx,
            MAX_KEYS_MULTI,
        );
    }
    if input.starts_with("thresh(") {
        return parse_thresh(input, ctx, depth);
    }
    if input.starts_with("wsh(") {
        if !ctx.wsh_allowed() {
            return Err(ParseError::InvalidScriptContext);
        }
        let inner_ctx = match ctx {
            ParseContext::TopLevel => ParseContext::Segwit,
            ParseContext::Legacy => ParseContext::WrappedSegwit,
            // `wsh_allowed` returns true only for `TopLevel`/`Legacy`; if a new
            // `ParseContext` variant is added in the future, default to rejecting
            // rather than panicking on hostile input.
            _ => return Err(ParseError::InvalidScriptContext),
        };

        let (rest, [script]) = parse_n_subscripts(&input[4..], inner_ctx, depth)?;
        return Ok((rest, DescriptorTemplate::Wsh(Box::new(script))));
    }
    if input.starts_with("sh(") {
        if !ctx.sh_allowed() {
            return Err(ParseError::InvalidScriptContext);
        }
        let (rest, [script]) = parse_n_subscripts(&input[3..], ParseContext::Legacy, depth)?;
        return Ok((rest, DescriptorTemplate::Sh(Box::new(script))));
    }
    if input.starts_with("wpkh(") {
        if !ctx.wpkh_allowed() {
            return Err(ParseError::InvalidScriptContext);
        }
        return parse_kp_fragment(input, "wpkh", DescriptorTemplate::Wpkh, ctx);
    }
    if input.starts_with("pkh(") {
        return parse_kp_fragment(input, "pkh", DescriptorTemplate::Pkh, ctx);
    }
    if input.starts_with("tr(") {
        if !ctx.tr_allowed() {
            return Err(ParseError::InvalidScriptContext);
        }
        return parse_tr(input, depth);
    }
    if input.starts_with("pk_k(") {
        return parse_kp_fragment(input, "pk_k", DescriptorTemplate::Pk_k, ctx);
    }
    if input.starts_with("pk_h(") {
        return parse_kp_fragment(input, "pk_h", DescriptorTemplate::Pk_h, ctx);
    }
    if input.starts_with("pk(") {
        return parse_kp_fragment(input, "pk", DescriptorTemplate::Pk, ctx);
    }
    if input.starts_with("older(") {
        return parse_num_fragment(input, "older", MAX_OLDER_AFTER, DescriptorTemplate::Older);
    }
    if input.starts_with("after(") {
        return parse_num_fragment(input, "after", MAX_OLDER_AFTER, DescriptorTemplate::After);
    }
    if input.starts_with("sha256(") {
        return parse_hex32_fragment(input, "sha256", DescriptorTemplate::Sha256);
    }
    if input.starts_with("hash256(") {
        return parse_hex32_fragment(input, "hash256", DescriptorTemplate::Hash256);
    }
    if input.starts_with("ripemd160(") {
        return parse_hex20_fragment(input, "ripemd160", DescriptorTemplate::Ripemd160);
    }
    if input.starts_with("hash160(") {
        return parse_hex20_fragment(input, "hash160", DescriptorTemplate::Hash160);
    }
    if input.starts_with("andor(") {
        let (rest, [x, y, z]) = parse_n_subscripts(&input[6..], ctx, depth)?;
        return Ok((
            rest,
            DescriptorTemplate::Andor(Box::new(x), Box::new(y), Box::new(z)),
        ));
    }
    if input.starts_with("and_b(") {
        let (rest, [x, y]) = parse_n_subscripts(&input[6..], ctx, depth)?;
        return Ok((rest, DescriptorTemplate::And_b(Box::new(x), Box::new(y))));
    }
    if input.starts_with("and_v(") {
        let (rest, [x, y]) = parse_n_subscripts(&input[6..], ctx, depth)?;
        return Ok((rest, DescriptorTemplate::And_v(Box::new(x), Box::new(y))));
    }
    if input.starts_with("and_n(") {
        let (rest, [x, y]) = parse_n_subscripts(&input[6..], ctx, depth)?;
        return Ok((rest, DescriptorTemplate::And_n(Box::new(x), Box::new(y))));
    }
    if input.starts_with("or_b(") {
        let (rest, [x, y]) = parse_n_subscripts(&input[5..], ctx, depth)?;
        return Ok((rest, DescriptorTemplate::Or_b(Box::new(x), Box::new(y))));
    }
    if input.starts_with("or_c(") {
        let (rest, [x, y]) = parse_n_subscripts(&input[5..], ctx, depth)?;
        return Ok((rest, DescriptorTemplate::Or_c(Box::new(x), Box::new(y))));
    }
    if input.starts_with("or_d(") {
        let (rest, [x, y]) = parse_n_subscripts(&input[5..], ctx, depth)?;
        return Ok((rest, DescriptorTemplate::Or_d(Box::new(x), Box::new(y))));
    }
    if input.starts_with("or_i(") {
        let (rest, [x, y]) = parse_n_subscripts(&input[5..], ctx, depth)?;
        return Ok((rest, DescriptorTemplate::Or_i(Box::new(x), Box::new(y))));
    }
    // Simple terminals: bare "0" and "1"
    if input.starts_with('0') {
        return Ok((&input[1..], DescriptorTemplate::Zero));
    }
    if input.starts_with('1') {
        return Ok((&input[1..], DescriptorTemplate::One));
    }
    Err(ParseError::UnrecognizedFragment)
}

// Parses a named fragment that wraps a single key expression: name(@...)
fn parse_kp_fragment<'a>(
    input: &'a str,
    name: &str,
    constructor: fn(KeyExpression) -> DescriptorTemplate,
    ctx: ParseContext,
) -> ParseResult<'a, DescriptorTemplate> {
    let rest = &input[name.len()..]; // caller already checked starts_with(name)
    let (rest, kp) = parse_key_expression(&rest[1..], ctx)?; // skip '('
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    Ok((&rest[1..], constructor(kp)))
}

// Parses "name(n)" where n is a number <= max.
fn parse_num_fragment<'a>(
    input: &'a str,
    name: &str,
    max: u32,
    constructor: fn(u32) -> DescriptorTemplate,
) -> ParseResult<'a, DescriptorTemplate> {
    let rest = &input[name.len()..]; // caller already checked starts_with(name)
    let (rest, num) = parse_number_up_to(&rest[1..], max)?; // skip '('
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    Ok((&rest[1..], constructor(num)))
}

// Parses "name(<40 hex chars>)".
fn parse_hex20_fragment<'a>(
    input: &'a str,
    name: &str,
    constructor: fn([u8; 20]) -> DescriptorTemplate,
) -> ParseResult<'a, DescriptorTemplate> {
    let rest = &input[name.len() + 1..]; // skip name and '('
    if rest.len() < 40 {
        return Err(ParseError::InvalidLength);
    }
    let bytes = <[u8; 20]>::from_hex(&rest[..40]).map_err(|_| ParseError::InvalidHex)?;
    let rest = &rest[40..];
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    Ok((&rest[1..], constructor(bytes)))
}

// Parses "name(<64 hex chars>)".
fn parse_hex32_fragment<'a>(
    input: &'a str,
    name: &str,
    constructor: fn([u8; 32]) -> DescriptorTemplate,
) -> ParseResult<'a, DescriptorTemplate> {
    let rest = &input[name.len() + 1..]; // skip name and '('
    if rest.len() < 64 {
        return Err(ParseError::InvalidLength);
    }
    let bytes = <[u8; 32]>::from_hex(&rest[..64]).map_err(|_| ParseError::InvalidHex)?;
    let rest = &rest[64..];
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    Ok((&rest[1..], constructor(bytes)))
}

// Parses "name(threshold,<key1>,<key1>,...)".
fn parse_threshold_kp_fragment<'a>(
    input: &'a str,
    name: &str,
    constructor: fn(u32, Vec<KeyExpression>) -> DescriptorTemplate,
    ctx: ParseContext,
    max_keys: usize,
) -> ParseResult<'a, DescriptorTemplate> {
    let rest = &input[name.len() + 1..]; // skip name and '('
    let (mut rest, threshold) = parse_number_up_to(rest, u32::MAX)?;
    let mut keys: Vec<KeyExpression> = Vec::new();
    loop {
        if !rest.starts_with(',') {
            break;
        }
        if keys.len() >= max_keys {
            return Err(ParseError::TooManyKeys);
        }
        match parse_key_expression(&rest[1..], ctx) {
            Ok((r, kp)) => {
                keys.push(kp);
                rest = r;
            }
            Err(ParseError::InvalidScriptContext) => return Err(ParseError::InvalidScriptContext),
            Err(_) => break,
        }
    }
    if keys.len() < 2 {
        return Err(ParseError::TooFewKeyExpressions);
    }
    if threshold == 0 || (threshold as usize) > keys.len() {
        return Err(ParseError::InvalidMultisigQuorum);
    }
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    Ok((&rest[1..], constructor(threshold, keys)))
}

// Parses exactly `N` comma-separated sub-descriptors followed by ')'.
// Called after the opening '(' of the enclosing fragment has been consumed.
fn parse_n_subscripts<const N: usize>(
    input: &str,
    ctx: ParseContext,
    depth: usize,
) -> ParseResult<'_, [DescriptorTemplate; N]> {
    let mut rest = input;
    let mut scripts: Vec<DescriptorTemplate> = Vec::with_capacity(N);
    for i in 0..N {
        let (r, desc) = parse_descriptor(rest, ctx, depth)?;
        scripts.push(desc);
        rest = r;
        if i + 1 < N {
            if !rest.starts_with(',') {
                return Err(ParseError::InvalidSyntax);
            }
            rest = &rest[1..];
        }
    }
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    let array: [DescriptorTemplate; N] = scripts
        .try_into()
        .ok()
        .expect("loop pushed exactly N elements");
    Ok((&rest[1..], array))
}

#[cfg(test)]
fn parse_wsh(input: &str) -> ParseResult<'_, DescriptorTemplate> {
    if !input.starts_with("wsh(") {
        return Err(ParseError::InvalidSyntax);
    }
    let (rest, [script]) = parse_n_subscripts(&input[4..], ParseContext::Segwit, 0)?;
    Ok((rest, DescriptorTemplate::Wsh(Box::new(script))))
}

#[cfg(test)]
fn parse_sortedmulti(input: &str) -> ParseResult<'_, DescriptorTemplate> {
    parse_threshold_kp_fragment(
        input,
        "sortedmulti",
        DescriptorTemplate::Sortedmulti,
        ParseContext::TopLevel,
        MAX_KEYS_MULTI,
    )
}

fn parse_thresh(
    input: &str,
    ctx: ParseContext,
    depth: usize,
) -> ParseResult<'_, DescriptorTemplate> {
    // input starts with "thresh("
    let (rest, k) = parse_number_up_to(&input[7..], u32::MAX)?;
    if !rest.starts_with(',') {
        return Err(ParseError::InvalidSyntax);
    }
    // parse first script (mandatory)
    let (rest, first) = parse_descriptor(&rest[1..], ctx, depth)?;
    let mut scripts = vec![first];
    let mut rest = rest;
    loop {
        if !rest.starts_with(',') {
            break;
        }
        match parse_descriptor(&rest[1..], ctx, depth) {
            Ok((r, desc)) => {
                scripts.push(desc);
                rest = r;
            }
            Err(ParseError::NestingTooDeep) => return Err(ParseError::NestingTooDeep),
            Err(_) => break,
        }
    }
    if k == 0 {
        return Err(ParseError::InvalidMultisigQuorum);
    }
    if (k as usize) > scripts.len() {
        return Err(ParseError::ThreshExceedsScripts);
    }
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    Ok((&rest[1..], DescriptorTemplate::Thresh(k, scripts)))
}

fn parse_tr(input: &str, depth: usize) -> ParseResult<'_, DescriptorTemplate> {
    // input starts with "tr("
    let (rest, key_placeholder) = parse_key_expression(&input[3..], ParseContext::Taproot)?;
    let (rest, tree) = if rest.starts_with(',') {
        let (rest, tree) = parse_tap_tree(&rest[1..], depth)?;
        (rest, Some(tree))
    } else {
        (rest, None)
    };
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    Ok((&rest[1..], DescriptorTemplate::Tr(key_placeholder, tree)))
}

fn parse_tap_tree(input: &str, depth: usize) -> ParseResult<'_, TapTree> {
    if depth >= MAX_PARSE_DEPTH {
        return Err(ParseError::NestingTooDeep);
    }
    let depth = depth + 1;
    if input.starts_with('{') {
        let (rest, left) = parse_tap_tree(&input[1..], depth)?;
        if !rest.starts_with(',') {
            return Err(ParseError::InvalidSyntax);
        }
        let (rest, right) = parse_tap_tree(&rest[1..], depth)?;
        if !rest.starts_with('}') {
            return Err(ParseError::InvalidSyntax);
        }
        Ok((&rest[1..], TapTree::Branch(Box::new(left), Box::new(right))))
    } else {
        let (rest, desc) = parse_descriptor(input, ParseContext::Taproot, depth)?;
        Ok((rest, TapTree::Script(Box::new(desc))))
    }
}

impl FromStr for DescriptorTemplate {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse_descriptor_template(input)
    }
}

fn write_display_wrapper(
    f: &mut core::fmt::Formatter<'_>,
    ch: char,
    inner: &DescriptorTemplate,
) -> core::fmt::Result {
    write!(f, "{}", ch)?;
    if !inner.is_wrapper() {
        write!(f, ":")?;
    }
    write!(f, "{}", inner)
}

impl core::fmt::Display for DescriptorTemplate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DescriptorTemplate::Sh(inner) => write!(f, "sh({})", inner),
            DescriptorTemplate::Wsh(inner) => write!(f, "wsh({})", inner),
            DescriptorTemplate::Pkh(kp) => write!(f, "pkh({})", kp),
            DescriptorTemplate::Wpkh(kp) => write!(f, "wpkh({})", kp),
            DescriptorTemplate::Sortedmulti(k, kps) => {
                write!(f, "sortedmulti({}", k)?;
                for kp in kps {
                    write!(f, ",{}", kp)?;
                }
                write!(f, ")")
            }
            DescriptorTemplate::Sortedmulti_a(k, kps) => {
                write!(f, "sortedmulti_a({}", k)?;
                for kp in kps {
                    write!(f, ",{}", kp)?;
                }
                write!(f, ")")
            }
            DescriptorTemplate::Tr(kp, None) => write!(f, "tr({})", kp),
            DescriptorTemplate::Tr(kp, Some(tree)) => write!(f, "tr({},{})", kp, tree),
            DescriptorTemplate::Zero => write!(f, "0"),
            DescriptorTemplate::One => write!(f, "1"),
            DescriptorTemplate::Pk(kp) => write!(f, "pk({})", kp),
            DescriptorTemplate::Pk_k(kp) => write!(f, "pk_k({})", kp),
            DescriptorTemplate::Pk_h(kp) => write!(f, "pk_h({})", kp),
            DescriptorTemplate::Older(n) => write!(f, "older({})", n),
            DescriptorTemplate::After(n) => write!(f, "after({})", n),
            DescriptorTemplate::Sha256(hash) => write!(f, "sha256({})", hex::encode(hash)),
            DescriptorTemplate::Ripemd160(hash) => write!(f, "ripemd160({})", hex::encode(hash)),
            DescriptorTemplate::Hash256(hash) => write!(f, "hash256({})", hex::encode(hash)),
            DescriptorTemplate::Hash160(hash) => write!(f, "hash160({})", hex::encode(hash)),
            DescriptorTemplate::Andor(x, y, z) => write!(f, "andor({},{},{})", x, y, z),
            DescriptorTemplate::And_v(x, y) => write!(f, "and_v({},{})", x, y),
            DescriptorTemplate::And_b(x, y) => write!(f, "and_b({},{})", x, y),
            DescriptorTemplate::And_n(x, y) => write!(f, "and_n({},{})", x, y),
            DescriptorTemplate::Or_b(x, y) => write!(f, "or_b({},{})", x, y),
            DescriptorTemplate::Or_c(x, y) => write!(f, "or_c({},{})", x, y),
            DescriptorTemplate::Or_d(x, y) => write!(f, "or_d({},{})", x, y),
            DescriptorTemplate::Or_i(x, y) => write!(f, "or_i({},{})", x, y),
            DescriptorTemplate::Thresh(k, descs) => {
                write!(f, "thresh({}", k)?;
                for desc in descs {
                    write!(f, ",{}", desc)?;
                }
                write!(f, ")")
            }
            DescriptorTemplate::Multi(k, kps) => {
                write!(f, "multi({}", k)?;
                for kp in kps {
                    write!(f, ",{}", kp)?;
                }
                write!(f, ")")
            }
            DescriptorTemplate::Multi_a(k, kps) => {
                write!(f, "multi_a({}", k)?;
                for kp in kps {
                    write!(f, ",{}", kp)?;
                }
                write!(f, ")")
            }
            DescriptorTemplate::A(inner) => write_display_wrapper(f, 'a', inner),
            DescriptorTemplate::S(inner) => write_display_wrapper(f, 's', inner),
            DescriptorTemplate::C(inner) => write_display_wrapper(f, 'c', inner),
            DescriptorTemplate::T(inner) => write_display_wrapper(f, 't', inner),
            DescriptorTemplate::D(inner) => write_display_wrapper(f, 'd', inner),
            DescriptorTemplate::V(inner) => write_display_wrapper(f, 'v', inner),
            DescriptorTemplate::J(inner) => write_display_wrapper(f, 'j', inner),
            DescriptorTemplate::N(inner) => write_display_wrapper(f, 'n', inner),
            DescriptorTemplate::L(inner) => write_display_wrapper(f, 'l', inner),
            DescriptorTemplate::U(inner) => write_display_wrapper(f, 'u', inner),
        }
    }
}

/// A BIP-388 wallet policy: a parsed [`DescriptorTemplate`] together with the
/// list of [`KeyInformation`] entries it references, and the original textual
/// template the policy was constructed from.
///
/// Once constructed, a `WalletPolicy` is immutable. Fields are private so the
/// parsed template cannot drift from the raw string used to compute the
/// registration HMAC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletPolicy {
    descriptor_template: DescriptorTemplate,
    key_information: Vec<KeyInformation>,
    descriptor_template_raw: String,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SegwitVersion {
    Legacy,
    SegwitV0,
    Taproot,
}

impl SegwitVersion {
    pub fn is_segwit(&self) -> bool {
        matches!(self, SegwitVersion::SegwitV0 | SegwitVersion::Taproot)
    }
}

impl WalletPolicy {
    pub fn new(
        descriptor_template_str: &str,
        key_information: Vec<KeyInformation>,
    ) -> Result<Self, ParseError> {
        let descriptor_template = DescriptorTemplate::from_str(descriptor_template_str)?;

        Ok(Self {
            descriptor_template,
            key_information,
            descriptor_template_raw: String::from(descriptor_template_str),
        })
    }

    /// The parsed descriptor template AST.
    pub fn descriptor_template(&self) -> &DescriptorTemplate {
        &self.descriptor_template
    }

    /// The list of key information entries referenced by the template's
    /// `@i` placeholders.
    pub fn key_information(&self) -> &[KeyInformation] {
        &self.key_information
    }

    /// The exact textual template that was passed to [`WalletPolicy::new`].
    /// This string is what gets HMACed during account registration, so it is
    /// preserved byte-for-byte rather than re-derived via `Display`.
    pub fn descriptor_template_raw(&self) -> &str {
        &self.descriptor_template_raw
    }

    pub fn serialize(&self) -> Vec<u8> {
        // `consensus_encode` only fails when its writer fails. Writing to a `Vec`
        // is infallible, so all `expect`s below are unreachable in practice.
        let mut result = Vec::<u8>::new();

        let len = VarInt(self.descriptor_template_raw().len() as u64);
        len.consensus_encode(&mut result)
            .expect("writing to Vec is infallible");
        result.extend_from_slice(self.descriptor_template_raw().as_bytes());

        // number of keys
        VarInt(self.key_information.len() as u64)
            .consensus_encode(&mut result)
            .expect("writing to Vec is infallible");
        for key_info in &self.key_information {
            // serialize key information
            match &key_info.origin_info {
                None => {
                    result.push(0);
                }
                Some(k) => {
                    result.push(1);
                    result.extend_from_slice(&k.fingerprint.to_be_bytes());
                    VarInt(k.derivation_path.len() as u64)
                        .consensus_encode(&mut result)
                        .expect("writing to Vec is infallible");
                    for step in k.derivation_path.iter() {
                        result.extend_from_slice(&u32::from(*step).to_le_bytes());
                    }
                }
            }
            // serialize pubkey
            result.extend_from_slice(&key_info.pubkey.encode());
        }

        result
    }

    pub fn deserialize<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        // Deserialize descriptor template. Reject lengths exceeding
        // `MAX_SERIALIZED_DESCRIPTORTEMPLATE_LEN` before allocating to prevent a hostile
        // `VarInt` from triggering an unbounded allocation.
        let VarInt(desc_len) = VarInt::consensus_decode(r)?;
        if desc_len > MAX_SERIALIZED_DESCRIPTORTEMPLATE_LEN as u64 {
            return Err(encode::Error::ParseFailed("Descriptor template too long"));
        }
        let mut desc_bytes = vec![0u8; desc_len as usize];
        r.read_exact(&mut desc_bytes)?;
        let descriptor_template_str = String::from_utf8(desc_bytes)
            .map_err(|_| encode::Error::ParseFailed("Invalid UTF-8 in descriptor"))?;

        // Deserialize key_information vector. Same bound check before allocating.
        let VarInt(key_count) = VarInt::consensus_decode(r)?;
        if key_count > MAX_SERIALIZED_KEY_COUNT as u64 {
            return Err(encode::Error::ParseFailed("Too many keys"));
        }
        let mut key_information = Vec::with_capacity(key_count as usize);
        for _ in 0..key_count {
            let mut flag = [0u8; 1];
            r.read_exact(&mut flag)?;
            let origin_info = match flag[0] {
                0 => None,
                1 => {
                    let mut fp_buf = [0; 4];
                    r.read_exact(&mut fp_buf)?;
                    let fingerprint = u32::from_be_bytes(fp_buf);
                    let VarInt(dp_len) = VarInt::consensus_decode(r)?;
                    // keys used in wallet policies must leave space for the final change/address_index derivation steps
                    if dp_len > (MAX_BIP32_DERIVATION_PATH_LEN - 2) as u64 {
                        return Err(encode::Error::ParseFailed("Derivation path too long"));
                    }
                    let mut derivation_path = Vec::with_capacity(dp_len as usize);
                    for _ in 0..dp_len {
                        let mut step_bytes = [0u8; 4];
                        r.read_exact(&mut step_bytes)?;
                        derivation_path.push(ChildNumber::from(u32::from_le_bytes(step_bytes)));
                    }
                    Some(KeyOrigin {
                        fingerprint,
                        derivation_path,
                    })
                }
                _ => {
                    return Err(encode::Error::ParseFailed("Invalid key information flag"));
                }
            };
            // Deserialize pubkey.
            let mut xpub_bytes = vec![0u8; 78];
            r.read_exact(&mut xpub_bytes)?;

            key_information.push(KeyInformation {
                origin_info,
                pubkey: Xpub::decode(&xpub_bytes)
                    .map_err(|_| encode::Error::ParseFailed("Invalid xpub"))?,
            });
        }

        // test that the stream is indeed exhausted
        let mut buf = [0u8; 1];
        match r.read(&mut buf)? {
            0 => {}
            _ => {
                return Err(encode::Error::ParseFailed(
                    "Extra data after deserializing WalletPolicy",
                ));
            }
        }

        Ok(
            WalletPolicy::new(&descriptor_template_str, key_information).map_err(|_| {
                encode::Error::ParseFailed("Invalid descriptor template or key information")
            })?,
        )
    }

    pub fn get_segwit_version(&self) -> Result<SegwitVersion, ParseError> {
        match &self.descriptor_template {
            DescriptorTemplate::Tr(_, _) => Ok(SegwitVersion::Taproot),
            DescriptorTemplate::Pkh(_) => Ok(SegwitVersion::Legacy),
            DescriptorTemplate::Wpkh(_) | DescriptorTemplate::Wsh(_) => Ok(SegwitVersion::SegwitV0),
            DescriptorTemplate::Sh(inner) => match inner.as_ref() {
                DescriptorTemplate::Wpkh(_) | DescriptorTemplate::Wsh(_) => {
                    Ok(SegwitVersion::SegwitV0)
                }
                _ => Ok(SegwitVersion::Legacy),
            },
            _ => Err(ParseError::InvalidTopLevelPolicy),
        }
    }
}

fn write_key_expression(
    w: &mut String,
    key_information: &[KeyInformation],
    kp: &KeyExpression,
    is_change: bool,
    address_index: u32,
) -> Result<(), ParseError> {
    use core::fmt::Write;
    let change_step = if is_change { kp.num2 } else { kp.num1 };
    match &kp.key_type {
        KeyExpressionType::PlainKey(key_index) => {
            let key_info = key_information
                .get(*key_index as usize)
                .ok_or(ParseError::InvalidKeyIndex)?;
            write!(w, "{}/{}/{}", key_info, change_step, address_index)
                .map_err(|_| ParseError::FormatError)
        }
        KeyExpressionType::Musig(key_indices) => {
            w.push_str("musig(");
            for (i, key_index) in key_indices.iter().enumerate() {
                if i > 0 {
                    w.push(',');
                }
                let key_info = key_information
                    .get(*key_index as usize)
                    .ok_or(ParseError::InvalidKeyIndex)?;
                write!(w, "{}", key_info).map_err(|_| ParseError::FormatError)?;
            }
            write!(w, ")/{}/{}", change_step, address_index).map_err(|_| ParseError::FormatError)
        }
    }
}

// Writes a comma-separated list of key expressions to a buffer.
fn write_key_expressions(
    w: &mut String,
    key_information: &[KeyInformation],
    kps: &[KeyExpression],
    is_change: bool,
    address_index: u32,
) -> Result<(), ParseError> {
    for (i, kp) in kps.iter().enumerate() {
        if i > 0 {
            w.push(',');
        }
        write_key_expression(w, key_information, kp, is_change, address_index)?;
    }
    Ok(())
}

// Writes a wrapper fragment to a buffer.
fn write_wrapper(
    w: &mut String,
    name: &str,
    inner: &DescriptorTemplate,
    key_information: &[KeyInformation],
    is_change: bool,
    address_index: u32,
) -> Result<(), ParseError> {
    w.push_str(name);
    if !inner.is_wrapper() {
        w.push(':');
    }
    inner.write_to(w, key_information, is_change, address_index)
}

impl TapTree {
    fn write_to(
        &self,
        w: &mut String,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<(), ParseError> {
        match self {
            TapTree::Script(desc) => desc.write_to(w, key_information, is_change, address_index),
            TapTree::Branch(left, right) => {
                w.push('{');
                left.write_to(w, key_information, is_change, address_index)?;
                w.push(',');
                right.write_to(w, key_information, is_change, address_index)?;
                w.push('}');
                Ok(())
            }
        }
    }
}

impl DescriptorTemplate {
    fn write_to(
        &self,
        w: &mut String,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<(), ParseError> {
        use core::fmt::Write;

        match self {
            DescriptorTemplate::Sh(inner) => {
                w.push_str("sh(");
                inner.write_to(w, key_information, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Wsh(inner) => {
                w.push_str("wsh(");
                inner.write_to(w, key_information, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Pkh(kp) => {
                w.push_str("pkh(");
                write_key_expression(w, key_information, kp, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Wpkh(kp) => {
                w.push_str("wpkh(");
                write_key_expression(w, key_information, kp, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Sortedmulti(threshold, kps) => {
                write!(w, "sortedmulti({},", threshold).map_err(|_| ParseError::FormatError)?;
                write_key_expressions(w, key_information, kps, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Sortedmulti_a(threshold, kps) => {
                write!(w, "sortedmulti_a({},", threshold).map_err(|_| ParseError::FormatError)?;
                write_key_expressions(w, key_information, kps, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Tr(kp, tap_tree) => {
                w.push_str("tr(");
                write_key_expression(w, key_information, kp, is_change, address_index)?;
                if let Some(tree) = tap_tree {
                    w.push(',');
                    tree.write_to(w, key_information, is_change, address_index)?;
                }
                w.push(')');
            }
            DescriptorTemplate::Zero => w.push('0'),
            DescriptorTemplate::One => w.push('1'),
            DescriptorTemplate::Pk(kp) => {
                w.push_str("pk(");
                write_key_expression(w, key_information, kp, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Pk_k(kp) => {
                w.push_str("pk_k(");
                write_key_expression(w, key_information, kp, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Pk_h(kp) => {
                w.push_str("pk_h(");
                write_key_expression(w, key_information, kp, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Older(n) => {
                write!(w, "older({})", n).map_err(|_| ParseError::FormatError)?;
            }
            DescriptorTemplate::After(n) => {
                write!(w, "after({})", n).map_err(|_| ParseError::FormatError)?;
            }
            DescriptorTemplate::Sha256(hash) => {
                w.push_str("sha256(");
                w.push_str(&hex::encode(hash));
                w.push(')');
            }
            DescriptorTemplate::Ripemd160(hash) => {
                w.push_str("ripemd160(");
                w.push_str(&hex::encode(hash));
                w.push(')');
            }
            DescriptorTemplate::Hash256(hash) => {
                w.push_str("hash256(");
                w.push_str(&hex::encode(hash));
                w.push(')');
            }
            DescriptorTemplate::Hash160(hash) => {
                w.push_str("hash160(");
                w.push_str(&hex::encode(hash));
                w.push(')');
            }
            DescriptorTemplate::Andor(x, y, z) => {
                w.push_str("andor(");
                x.write_to(w, key_information, is_change, address_index)?;
                w.push(',');
                y.write_to(w, key_information, is_change, address_index)?;
                w.push(',');
                z.write_to(w, key_information, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::And_v(x, y) => {
                w.push_str("and_v(");
                x.write_to(w, key_information, is_change, address_index)?;
                w.push(',');
                y.write_to(w, key_information, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::And_b(x, y) => {
                w.push_str("and_b(");
                x.write_to(w, key_information, is_change, address_index)?;
                w.push(',');
                y.write_to(w, key_information, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::And_n(x, y) => {
                w.push_str("and_n(");
                x.write_to(w, key_information, is_change, address_index)?;
                w.push(',');
                y.write_to(w, key_information, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Or_b(x, z) => {
                w.push_str("or_b(");
                x.write_to(w, key_information, is_change, address_index)?;
                w.push(',');
                z.write_to(w, key_information, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Or_c(x, z) => {
                w.push_str("or_c(");
                x.write_to(w, key_information, is_change, address_index)?;
                w.push(',');
                z.write_to(w, key_information, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Or_d(x, z) => {
                w.push_str("or_d(");
                x.write_to(w, key_information, is_change, address_index)?;
                w.push(',');
                z.write_to(w, key_information, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Or_i(x, z) => {
                w.push_str("or_i(");
                x.write_to(w, key_information, is_change, address_index)?;
                w.push(',');
                z.write_to(w, key_information, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Thresh(k, sub_templates) => {
                write!(w, "thresh({}", k).map_err(|_| ParseError::FormatError)?;
                for template in sub_templates {
                    w.push(',');
                    template.write_to(w, key_information, is_change, address_index)?;
                }
                w.push(')');
            }
            DescriptorTemplate::Multi(threshold, kps) => {
                write!(w, "multi({},", threshold).map_err(|_| ParseError::FormatError)?;
                write_key_expressions(w, key_information, kps, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Multi_a(threshold, kps) => {
                write!(w, "multi_a({},", threshold).map_err(|_| ParseError::FormatError)?;
                write_key_expressions(w, key_information, kps, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::A(inner) => {
                write_wrapper(w, "a", inner, key_information, is_change, address_index)?;
            }
            DescriptorTemplate::S(inner) => {
                write_wrapper(w, "s", inner, key_information, is_change, address_index)?;
            }
            DescriptorTemplate::C(inner) => {
                write_wrapper(w, "c", inner, key_information, is_change, address_index)?;
            }
            DescriptorTemplate::T(inner) => {
                write_wrapper(w, "t", inner, key_information, is_change, address_index)?;
            }
            DescriptorTemplate::D(inner) => {
                write_wrapper(w, "d", inner, key_information, is_change, address_index)?;
            }
            DescriptorTemplate::V(inner) => {
                write_wrapper(w, "v", inner, key_information, is_change, address_index)?;
            }
            DescriptorTemplate::J(inner) => {
                write_wrapper(w, "j", inner, key_information, is_change, address_index)?;
            }
            DescriptorTemplate::N(inner) => {
                write_wrapper(w, "n", inner, key_information, is_change, address_index)?;
            }
            DescriptorTemplate::L(inner) => {
                write_wrapper(w, "l", inner, key_information, is_change, address_index)?;
            }
            DescriptorTemplate::U(inner) => {
                write_wrapper(w, "u", inner, key_information, is_change, address_index)?;
            }
        }
        Ok(())
    }
}

impl ToDescriptor for TapTree {
    fn to_descriptor(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<String, ParseError> {
        let mut result = String::new();
        self.write_to(&mut result, key_information, is_change, address_index)?;
        Ok(result)
    }
}

impl ToDescriptor for DescriptorTemplate {
    fn to_descriptor(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<String, ParseError> {
        let mut result = String::new();
        self.write_to(&mut result, key_information, is_change, address_index)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: u32 = HARDENED_INDEX;
    const MAX_STEP: &'static str = "2147483647";
    const MAX_STEP_H: &'static str = "2147483647'";

    #[test]
    fn test_parse_derivation_step_number() {
        let test_cases_success = vec![
            ("0", ("", 0)),
            ("0'", ("", H)),
            ("1", ("", 1)),
            ("1'", ("", 1 + H)),
            (MAX_STEP, ("", H - 1)),
            (MAX_STEP_H, ("", H - 1 + H)),
            // only ' is supported as hardened symbol, so this must leave the h or H unparsed
            ("5h", ("h", 5)),
            ("5H", ("H", 5)),
        ];

        for (input, expected) in test_cases_success {
            let result = parse_derivation_step_number(input);
            assert_eq!(result, Ok(expected));
        }

        let test_cases_err = vec!["", "a", stringify!(H), concat!(stringify!(H), "'")];

        for input in test_cases_err {
            assert!(parse_derivation_step_number(input).is_err());
        }
    }

    fn make_key_origin_info(fpr: u32, der_path: Vec<u32>) -> KeyOrigin {
        KeyOrigin {
            fingerprint: fpr,
            derivation_path: der_path.into_iter().map(ChildNumber::from).collect(),
        }
    }

    fn koi(key_origin_str: &str) -> KeyInformation {
        KeyInformation::try_from(key_origin_str).unwrap()
    }

    #[test]
    fn test_parse_key_origin() {
        let test_cases_success = vec![
            (
                "012345af/0'/1'/3",
                make_key_origin_info(0x012345af, vec![0 + H, 1 + H, 3]),
            ),
            (
                "012345af/2147483647'/1'/3/6/7/42/12/54/23/56/89",
                make_key_origin_info(
                    0x012345af,
                    vec![2147483647 + H, 1 + H, 3, 6, 7, 42, 12, 54, 23, 56, 89],
                ),
            ),
            ("012345af", make_key_origin_info(0x012345af, vec![])),
        ];

        for (input, expected) in test_cases_success {
            assert_eq!(KeyOrigin::try_from(input), Ok(expected));
        }

        let test_cases_err = vec![
            "[01234567/0'/1'/3]",
            "0123456/0'/1'/3",
            "012345678/0'/1'/3",
            "012345ag/0'/1'/2147483648",
        ];

        for input in test_cases_err {
            assert!(KeyOrigin::try_from(input).is_err());
        }
    }

    #[test]
    fn test_parse_key_expression() {
        let test_cases_success = vec![
            ("@0/**", KeyExpression::plain(0, 0, 1)),
            ("@4294967295/**", KeyExpression::plain(4294967295, 0, 1)), // u32::MAX
            ("@1/<0;1>/*", KeyExpression::plain(1, 0, 1)),
            ("@2/<3;4>/*", KeyExpression::plain(2, 3, 4)),
            ("@3/<1;9>/*", KeyExpression::plain(3, 1, 9)),
        ];

        for (input, expected) in test_cases_success {
            let result = parse_key_expression(input, ParseContext::TopLevel);
            assert_eq!(result, Ok(("", expected)));
        }

        let test_cases_err = vec![
            "@0",
            "@0**",
            "@a/**",
            "@0/*",
            "@0/<0;1>",       // missing /*
            "@0/<0,1>/*",     // , instead of ;
            "@4294967296/**", // too large
            "0/**",
        ];

        for input in test_cases_err {
            assert!(parse_key_expression(input, ParseContext::TopLevel).is_err());
        }
    }

    #[test]
    fn test_parse_sortedmulti() {
        let input = "sortedmulti(2,@0/**,@1/**)";
        let expected = Ok((
            "",
            DescriptorTemplate::Sortedmulti(
                2,
                vec![KeyExpression::plain(0, 0, 1), KeyExpression::plain(1, 0, 1)],
            ),
        ));
        assert_eq!(parse_sortedmulti(input), expected);
    }

    #[test]
    fn test_parse_wsh_sortedmulti() {
        let input = "wsh(sortedmulti(2,@0/**,@1/**))";
        let expected = Ok((
            "",
            DescriptorTemplate::Wsh(Box::new(DescriptorTemplate::Sortedmulti(
                2,
                vec![KeyExpression::plain(0, 0, 1), KeyExpression::plain(1, 0, 1)],
            ))),
        ));
        assert_eq!(parse_wsh(input), expected);
    }

    #[test]
    fn test_parse_tr() {
        let input = "tr(@0/**)";
        let expected = Ok((
            "",
            DescriptorTemplate::Tr(KeyExpression::plain(0, 0, 1), None),
        ));
        assert_eq!(parse_tr(input, 0), expected);

        let input = "tr(@0/**,pkh(@1/**))";
        let expected = Ok((
            "",
            DescriptorTemplate::Tr(
                KeyExpression::plain(0, 0, 1),
                Some(TapTree::Script(Box::new(DescriptorTemplate::Pkh(
                    KeyExpression::plain(1, 0, 1),
                )))),
            ),
        ));
        assert_eq!(parse_tr(input, 0), expected);

        let input = "tr(@0/<2;1>/*,{pkh(@1/<2;7>/*),pk(@2/**)})";
        let expected = Ok((
            "",
            DescriptorTemplate::Tr(
                KeyExpression::plain(0, 2, 1),
                Some(TapTree::Branch(
                    Box::new(TapTree::Script(Box::new(DescriptorTemplate::Pkh(
                        KeyExpression::plain(1, 2, 7),
                    )))),
                    Box::new(TapTree::Script(Box::new(DescriptorTemplate::Pk(
                        KeyExpression::plain(2, 0, 1),
                    )))),
                )),
            ),
        ));
        assert_eq!(parse_tr(input, 0), expected);

        // failure cases
        assert!(parse_tr("tr(@0/**,)", 0).is_err());
        assert!(parse_tr("tr(pkh(@0/**))", 0).is_err());
        assert!(parse_tr("tr(@0))", 0).is_err());
        assert!(parse_tr("tr(@0/*))", 0).is_err());
        assert!(parse_tr("tr(@0/*/0)", 0).is_err());
    }

    #[test]
    fn test_parse_valid_descriptor_templates() {
        assert!(parse_descriptor("sln:older(12960)", ParseContext::TopLevel, 0).is_ok());
        assert!(parse_thresh(
            "thresh(3,pk(@0/**),s:pk(@1/**),s:pk(@2/**),sln:older(12960))",
            ParseContext::TopLevel,
            0,
        )
        .is_ok());

        let test_cases = vec![
            "wsh(sortedmulti(2,@0/**,@1/**))",
            "sh(wsh(sortedmulti(2,@0/**,@1/**)))",
            "wsh(c:pk_k(@0/**))",
            "wsh(or_d(pk(@0/**),pkh(@1/**)))",
            "wsh(thresh(3,pk(@0/**),s:pk(@1/**),s:pk(@2/**),sln:older(12960)))",
        ];

        for input in test_cases {
            let result = parse_descriptor_template(input);
            assert!(result.is_ok())
        }
    }

    #[test]
    fn test_wallet_policy() {
        let wallet = WalletPolicy::new(
            &"sh(wsh(sortedmulti(2,@0/**,@1/**)))".to_string(),
            vec![
                koi("[76223a6e/48'/1'/0'/1']tpubDE7NQymr4AFtcJXi9TaWZtrhAdy8QyKmT4U6b9qYByAxCzoyMJ8zw5d8xVLVpbTRAEqP8pVUxjLE2vDt1rSFjaiS8DSz1QcNZ8D1qxUMx1g"),
                koi("[f5acc2fd/48'/1'/0'/1']tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY"),
            ]
        );

        assert!(wallet.is_ok());
    }

    #[test]
    fn test_descriptortemplate_placeholders_iterator() {
        fn format_kp(kp: &KeyExpression) -> String {
            let key_index = kp.plain_key_index().expect("expected plain key in test");
            format!("@{}/<{};{}>/*", key_index, kp.num1, kp.num2)
        }

        struct TestCase {
            descriptor: &'static str,
            expected: Vec<&'static str>,
        }
        impl TestCase {
            fn new(descriptor: &'static str, expected: &[&'static str]) -> Self {
                Self {
                    descriptor,
                    expected: Vec::from(expected),
                }
            }
        }

        // Define a list of test cases
        let test_cases = vec![
            TestCase::new("0", &[]),
            TestCase::new("after(12345)", &[]),
            TestCase::new("pkh(@0/**)", &["@0/<0;1>/*"]),
            TestCase::new("wpkh(@0/<11;67>/*)", &["@0/<11;67>/*"]),
            TestCase::new("tr(@0/**)", &["@0/<0;1>/*"]),
            TestCase::new(
                "wsh(or_i(and_v(v:pkh(@4/<3;7>/*),older(65535)),or_d(multi(2,@0/**,@3/**),and_v(v:thresh(1,pkh(@5/<99;101>/*),a:pkh(@1/**)),older(64231)))))",
                &["@4/<3;7>/*", "@0/<0;1>/*", "@3/<0;1>/*", "@5/<99;101>/*", "@1/<0;1>/*"]
            ),
            TestCase::new(
                "tr(@0/**,{sortedmulti_a(1,@1/**,@2/**),or_b(pk(@3/**),s:pk(@4/**))})",
                &["@0/<0;1>/*", "@1/<0;1>/*", "@2/<0;1>/*", "@3/<0;1>/*", "@4/<0;1>/*"]
            ),
            TestCase::new(
                "tr(@0/**,{{{sortedmulti_a(1,@1/**,@2/**,@3/**,@4/**,@5/**),multi_a(2,@6/**,@7/**,@8/**)},{multi_a(2,@9/**,@10/**,@11/**,@12/**),pk(@13/**)}},{{multi_a(2,@14/**,@15/**),multi_a(3,@16/**,@17/**,@18/**)},{multi_a(2,@19/**,@20/**),pk(@21/**)}}})",
                &["@0/<0;1>/*", "@1/<0;1>/*", "@2/<0;1>/*", "@3/<0;1>/*", "@4/<0;1>/*", "@5/<0;1>/*", "@6/<0;1>/*", "@7/<0;1>/*", "@8/<0;1>/*", "@9/<0;1>/*", "@10/<0;1>/*", "@11/<0;1>/*", "@12/<0;1>/*", "@13/<0;1>/*", "@14/<0;1>/*", "@15/<0;1>/*", "@16/<0;1>/*", "@17/<0;1>/*", "@18/<0;1>/*", "@19/<0;1>/*", "@20/<0;1>/*", "@21/<0;1>/*"]
            ),
        ];

        for case in test_cases {
            let desc = DescriptorTemplate::from_str(case.descriptor).unwrap();
            let iter = DescriptorTemplateIter::from(&desc);
            let results: Vec<_> = iter.map(|(k, _)| format_kp(k)).collect();

            assert_eq!(results, case.expected);
        }
    }

    #[test]
    fn test_display_roundtrip() {
        let cases = vec![
            "0",
            "1",
            "pkh(@0/**)",
            "wpkh(@0/**)",
            "wpkh(@0/<11;67>/*)",
            "wsh(sortedmulti(2,@0/**,@1/**))",
            "sh(wsh(sortedmulti(2,@0/**,@1/**)))",
            "wsh(c:pk_k(@0/**))",
            "wsh(or_d(pk(@0/**),pkh(@1/**)))",
            "wsh(thresh(3,pk(@0/**),s:pk(@1/**),s:pk(@2/**),sln:older(12960)))",
            "sln:older(12960)",
            "tr(@0/**)",
            "tr(@0/**,pkh(@1/**))",
            "tr(@0/<2;1>/*,{pkh(@1/<2;7>/*),pk(@2/**)})",
            "after(12345)",
            "older(65535)",
            "sha256(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)",
            "ripemd160(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)",
            "hash256(bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)",
            "hash160(bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)",
            "wsh(andor(pk(@0/**),older(1),pk(@1/**)))",
            "wsh(or_i(and_v(v:pkh(@4/<3;7>/*),older(65535)),or_d(multi(2,@0/**,@3/**),and_v(v:thresh(1,pkh(@5/<99;101>/*),a:pkh(@1/**)),older(64231)))))",
            "tr(@0/**,{sortedmulti_a(1,@1/**,@2/**),or_b(pk(@3/**),s:pk(@4/**))})",
        ];

        for s in cases {
            let parsed = DescriptorTemplate::from_str(s)
                .unwrap_or_else(|e| panic!("parse failed for {:?}: {:?}", s, e));
            let displayed = parsed.to_string();
            assert_eq!(displayed, s, "roundtrip failed for {:?}", s);
        }
    }

    #[test]
    fn test_musig_inside_tr_parses() {
        // musig() as the internal key of tr()
        let result = DescriptorTemplate::from_str("tr(musig(@0,@1)/**)");
        assert!(
            result.is_ok(),
            "musig as tr internal key should parse: {:?}",
            result
        );

        // musig() inside a tr() taptree leaf
        let result = DescriptorTemplate::from_str("tr(@0/**,pk(musig(@1,@2)/**))");
        assert!(
            result.is_ok(),
            "musig inside tr taptree should parse: {:?}",
            result
        );

        // musig() with more than two keys
        let result = DescriptorTemplate::from_str("tr(musig(@0,@1,@2)/**)");
        assert!(
            result.is_ok(),
            "musig with 3 keys should parse: {:?}",
            result
        );

        // musig() with <num1;num2>/* derivation
        let result = DescriptorTemplate::from_str("tr(musig(@0,@1)/<3;4>/*)");
        assert!(
            result.is_ok(),
            "musig with custom derivation should parse: {:?}",
            result
        );
    }

    #[test]
    fn test_musig_outside_tr_rejected() {
        // musig() inside wpkh() should fail
        assert_eq!(
            DescriptorTemplate::from_str("wpkh(musig(@0,@1)/**)"),
            Err(ParseError::InvalidScriptContext)
        );

        // musig() inside pkh() should fail
        assert_eq!(
            DescriptorTemplate::from_str("pkh(musig(@0,@1)/**)"),
            Err(ParseError::InvalidScriptContext)
        );

        // musig() inside wsh(sortedmulti()) should fail
        assert_eq!(
            DescriptorTemplate::from_str("wsh(sortedmulti(2,musig(@0,@1)/**,@2/**))"),
            Err(ParseError::InvalidScriptContext)
        );

        // musig() inside sh() should fail
        assert_eq!(
            DescriptorTemplate::from_str("sh(pk(musig(@0,@1)/**))"),
            Err(ParseError::InvalidScriptContext)
        );

        // musig() inside wsh(pk()) should fail
        assert_eq!(
            DescriptorTemplate::from_str("wsh(pk(musig(@0,@1)/**))"),
            Err(ParseError::InvalidScriptContext)
        );
    }

    #[test]
    fn test_musig_nested_not_allowed() {
        // musig() inside musig() is not valid because musig() arguments
        // must be plain @N key references, not nested key expressions
        assert!(
            DescriptorTemplate::from_str("tr(musig(musig(@0,@1),@2)/**)").is_err(),
            "nested musig should not parse"
        );
    }

    #[test]
    fn test_musig_display_roundtrip() {
        let cases = vec![
            "tr(musig(@0,@1)/**)",
            "tr(musig(@0,@1)/<3;4>/*)",
            "tr(musig(@0,@1,@2)/**)",
            "tr(@0/**,pk(musig(@1,@2)/**))",
        ];
        for s in cases {
            let parsed = DescriptorTemplate::from_str(s)
                .unwrap_or_else(|e| panic!("parse failed for {:?}: {:?}", s, e));
            let displayed = parsed.to_string();
            assert_eq!(displayed, s, "roundtrip failed for {:?}", s);
        }
    }

    #[test]
    fn test_sh_only_allowed_top_level() {
        // sh() at top level is valid
        assert!(DescriptorTemplate::from_str("sh(wsh(sortedmulti(2,@0/**,@1/**)))").is_ok());
        assert!(DescriptorTemplate::from_str("sh(sortedmulti(2,@0/**,@1/**))").is_ok());

        // sh() inside wsh() is not allowed
        assert_eq!(
            DescriptorTemplate::from_str("wsh(sh(pk(@0/**)))"),
            Err(ParseError::InvalidScriptContext)
        );

        // sh() inside sh() is not allowed
        assert_eq!(
            DescriptorTemplate::from_str("sh(sh(pk(@0/**)))"),
            Err(ParseError::InvalidScriptContext)
        );

        // sh() inside tr() taptree is not allowed
        assert_eq!(
            DescriptorTemplate::from_str("tr(@0/**,sh(pk(@1/**)))"),
            Err(ParseError::InvalidScriptContext)
        );
    }

    #[test]
    fn test_wsh_only_allowed_top_level_or_inside_sh() {
        // wsh() at top level is valid
        assert!(DescriptorTemplate::from_str("wsh(sortedmulti(2,@0/**,@1/**))").is_ok());

        // wsh() inside sh() is valid
        assert!(DescriptorTemplate::from_str("sh(wsh(sortedmulti(2,@0/**,@1/**)))").is_ok());

        // wsh() inside wsh() is not allowed
        assert_eq!(
            DescriptorTemplate::from_str("wsh(wsh(pk(@0/**)))"),
            Err(ParseError::InvalidScriptContext)
        );

        // wsh() inside tr() taptree is not allowed
        assert_eq!(
            DescriptorTemplate::from_str("tr(@0/**,wsh(pk(@1/**)))"),
            Err(ParseError::InvalidScriptContext)
        );

        // wsh() inside sh(wsh()) is not allowed (double wrapping)
        assert_eq!(
            DescriptorTemplate::from_str("sh(wsh(wsh(pk(@0/**))))"),
            Err(ParseError::InvalidScriptContext)
        );
    }

    #[test]
    fn test_tr_only_allowed_top_level() {
        // tr() at top level is valid
        assert!(DescriptorTemplate::from_str("tr(@0/**)").is_ok());
        assert!(DescriptorTemplate::from_str("tr(@0/**,pk(@1/**))").is_ok());

        // tr() inside sh() is not allowed
        assert_eq!(
            DescriptorTemplate::from_str("sh(tr(@0/**))"),
            Err(ParseError::InvalidScriptContext)
        );

        // tr() inside wsh() is not allowed
        assert_eq!(
            DescriptorTemplate::from_str("wsh(tr(@0/**))"),
            Err(ParseError::InvalidScriptContext)
        );

        // tr() inside tr() taptree is not allowed
        assert_eq!(
            DescriptorTemplate::from_str("tr(@0/**,tr(@1/**))"),
            Err(ParseError::InvalidScriptContext)
        );
    }

    #[test]
    fn test_musig_not_allowed_in_wsh_inside_tr() {
        // musig() inside wsh() even within a tapscript should fail,
        // because wsh() is not allowed inside tr() in the first place
        assert_eq!(
            DescriptorTemplate::from_str("tr(@0/**,wsh(pk(musig(@1,@2)/**)))"),
            Err(ParseError::InvalidScriptContext)
        );
    }

    #[test]
    fn test_parser_rejects_zero_threshold() {
        assert_eq!(
            DescriptorTemplate::from_str("wsh(multi(0,@0/**,@1/**))"),
            Err(ParseError::InvalidMultisigQuorum)
        );
        assert_eq!(
            DescriptorTemplate::from_str("wsh(sortedmulti(0,@0/**,@1/**))"),
            Err(ParseError::InvalidMultisigQuorum)
        );
        assert_eq!(
            DescriptorTemplate::from_str("tr(@0/**,multi_a(0,@1/**,@2/**))"),
            Err(ParseError::InvalidMultisigQuorum)
        );
        assert_eq!(
            DescriptorTemplate::from_str("tr(@0/**,sortedmulti_a(0,@1/**,@2/**))"),
            Err(ParseError::InvalidMultisigQuorum)
        );
        assert_eq!(
            DescriptorTemplate::from_str("wsh(thresh(0,pk(@0/**)))"),
            Err(ParseError::InvalidMultisigQuorum)
        );
    }

    #[test]
    fn test_parser_rejects_threshold_exceeds_keys() {
        assert_eq!(
            DescriptorTemplate::from_str("wsh(multi(3,@0/**,@1/**))"),
            Err(ParseError::InvalidMultisigQuorum)
        );
        assert_eq!(
            DescriptorTemplate::from_str("wsh(sortedmulti(3,@0/**,@1/**))"),
            Err(ParseError::InvalidMultisigQuorum)
        );
        assert_eq!(
            DescriptorTemplate::from_str("tr(@0/**,multi_a(3,@1/**,@2/**))"),
            Err(ParseError::InvalidMultisigQuorum)
        );
        assert_eq!(
            DescriptorTemplate::from_str("tr(@0/**,sortedmulti_a(3,@1/**,@2/**))"),
            Err(ParseError::InvalidMultisigQuorum)
        );
    }

    #[test]
    fn test_parser_rejects_duplicate_musig_keys() {
        assert_eq!(
            DescriptorTemplate::from_str("tr(musig(@0,@0)/**)"),
            Err(ParseError::InvalidKey)
        );
        assert_eq!(
            DescriptorTemplate::from_str("tr(@0/**,pk(musig(@1,@1)/**))"),
            Err(ParseError::InvalidKey)
        );
        assert_eq!(
            DescriptorTemplate::from_str("tr(musig(@0,@1,@0)/**)"),
            Err(ParseError::InvalidKey)
        );
    }

    #[test]
    fn test_parser_rejects_too_many_keys_multi() {
        // multi/sortedmulti cap at 20 keys
        let mut s = String::from("wsh(multi(2");
        for i in 0..21 {
            s.push_str(&format!(",@{}/**", i));
        }
        s.push_str("))");
        assert_eq!(
            DescriptorTemplate::from_str(&s),
            Err(ParseError::TooManyKeys)
        );

        // Exactly 20 keys must still parse
        let mut s = String::from("wsh(multi(2");
        for i in 0..20 {
            s.push_str(&format!(",@{}/**", i));
        }
        s.push_str("))");
        assert!(DescriptorTemplate::from_str(&s).is_ok());
    }

    #[test]
    fn test_parser_accepts_more_than_20_keys_multi_a() {
        // multi_a allows >20 keys (Taproot OP_CHECKSIGADD pattern)
        let mut s = String::from("tr(@0/**,multi_a(2");
        for i in 1..=50 {
            s.push_str(&format!(",@{}/**", i));
        }
        s.push_str("))");
        assert!(DescriptorTemplate::from_str(&s).is_ok());
    }

    #[test]
    fn test_parser_rejects_deeply_nested_descriptors() {
        // Wrapper chains do NOT grow recursion depth — they are applied
        // iteratively inside `parse_descriptor`. A long chain should still
        // parse fine.
        let mut s = String::new();
        for _ in 0..1000 {
            s.push('j');
        }
        s.push_str(":0");
        assert!(DescriptorTemplate::from_str(&s).is_ok());

        // Andor nesting recurses through `parse_descriptor` — beyond the
        // depth limit, parsing must reject without overflowing the stack.
        let mut s = String::new();
        for _ in 0..(MAX_PARSE_DEPTH + 5) {
            s.push_str("andor(0,");
        }
        s.push('0');
        for _ in 0..(MAX_PARSE_DEPTH + 5) {
            s.push_str(",0)");
        }
        assert_eq!(
            DescriptorTemplate::from_str(&s),
            Err(ParseError::NestingTooDeep)
        );

        // Same for taproot tree braces.
        let mut s = String::from("tr(@0/**,");
        for _ in 0..(MAX_PARSE_DEPTH + 5) {
            s.push('{');
        }
        s.push_str("pk(@1/**)");
        for _ in 0..(MAX_PARSE_DEPTH + 5) {
            s.push_str(",pk(@2/**)}");
        }
        s.push(')');
        assert_eq!(
            DescriptorTemplate::from_str(&s),
            Err(ParseError::NestingTooDeep)
        );

        // A taproot tree nested up to the limit must still succeed. Build a
        // left-leaning tree of depth `MAX_PARSE_DEPTH - 4` (a few slots are
        // consumed by `tr(` and the script wrapping at the bottom).
        let inner_depth = MAX_PARSE_DEPTH - 4;
        let mut s = String::from("tr(@0/**,");
        for _ in 0..inner_depth {
            s.push('{');
        }
        s.push_str("pk(@1/**)");
        for _ in 0..inner_depth {
            s.push_str(",pk(@2/**)}");
        }
        s.push(')');
        assert!(DescriptorTemplate::from_str(&s).is_ok());
    }

    #[test]
    fn test_deserialize_rejects_oversized_descriptor() {
        use bitcoin::consensus::Encodable;
        let mut buf = Vec::<u8>::new();
        // Encode a VarInt that exceeds the descriptor-length cap. The reader
        // must reject before allocating.
        VarInt((MAX_SERIALIZED_DESCRIPTORTEMPLATE_LEN as u64) + 1)
            .consensus_encode(&mut buf)
            .unwrap();
        let mut cursor = bitcoin::io::Cursor::new(buf);
        let err = WalletPolicy::deserialize(&mut cursor)
            .err()
            .expect("expected error");
        assert!(matches!(err, encode::Error::ParseFailed(_)));
    }

    #[test]
    fn test_deserialize_rejects_oversized_key_count() {
        use bitcoin::consensus::Encodable;
        let mut buf = Vec::<u8>::new();
        // Minimal valid descriptor: empty descriptor template.
        VarInt(0).consensus_encode(&mut buf).unwrap();
        // Key count way above the cap.
        VarInt((MAX_SERIALIZED_KEY_COUNT as u64) + 1)
            .consensus_encode(&mut buf)
            .unwrap();
        let mut cursor = bitcoin::io::Cursor::new(buf);
        let err = WalletPolicy::deserialize(&mut cursor)
            .err()
            .expect("expected error");
        assert!(matches!(err, encode::Error::ParseFailed(_)));
    }

    #[test]
    fn test_to_descriptor_exact_output() {
        let xpub_str = "tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P";
        let keys = vec![
            KeyInformation::try_from(xpub_str).unwrap(),
            KeyInformation::try_from(xpub_str).unwrap(),
        ];
        let dt = DescriptorTemplate::from_str("wsh(sortedmulti(2,@0/**,@1/**))").unwrap();
        let out = dt.to_descriptor(&keys, false, 7).unwrap();
        let expected = format!("wsh(sortedmulti(2,{}/0/7,{}/0/7))", xpub_str, xpub_str);
        assert_eq!(out, expected);

        let dt = DescriptorTemplate::from_str("wsh(thresh(1,pk(@0/**),s:pk(@1/**)))").unwrap();
        let out = dt.to_descriptor(&keys, true, 3).unwrap();
        let expected = format!("wsh(thresh(1,pk({}/1/3),s:pk({}/1/3)))", xpub_str, xpub_str);
        assert_eq!(out, expected);
    }
}

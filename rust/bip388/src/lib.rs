#![cfg_attr(not(test), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

// TODO:
// - add type checks
// - add malleability checks
// - add stack limits and other safety checks

pub mod arena;
mod cleartext;
pub mod embedded;
mod parser;
mod time;

pub use cleartext::*;

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, string::String, vec, vec::Vec};

#[cfg(test)]
use alloc::{format, string::ToString};

#[cfg(feature = "alloc")]
use core::str::FromStr;

#[cfg(feature = "wallet-policy")]
use bitcoin::{
    bip32::{ChildNumber, Xpub},
    consensus::{encode, Decodable, Encodable},
    io::Read,
    VarInt,
};

pub(crate) const HARDENED_INDEX: u32 = 0x80000000u32;
pub(crate) const MAX_OLDER_AFTER: u32 = 2147483647; // maximum allowed in older/after

// Maximum key count for `multi`/`sortedmulti` (OP_CHECKMULTISIG consensus limit).
pub(crate) const MAX_KEYS_MULTI: usize = 20;
// Maximum key count for the Taproot `multi_a`/`sortedmulti_a` variants.
pub(crate) const MAX_KEYS_MULTI_A: usize = 999;
// Maximum recursion depth for descriptor parsing. Bounds host-provided nesting
// (e.g. `andor(...andor(...))` or `{{{...}}}`) to keep stack usage finite on
// the constrained VM. Well above any realistic policy depth.
pub(crate) const MAX_PARSE_DEPTH: usize = 64;
// Maximum byte length of a serialized descriptor template accepted by
// `WalletPolicy::deserialize`. Practical policies are far below this.
#[cfg(feature = "wallet-policy")]
const MAX_SERIALIZED_DESCRIPTORTEMPLATE_LEN: usize = 4096;
// Maximum number of key information entries accepted by `WalletPolicy::deserialize`.
// Matches the largest multi-key fragment we can produce (`multi_a`/`sortedmulti_a`).
#[cfg(feature = "wallet-policy")]
const MAX_SERIALIZED_KEY_COUNT: usize = MAX_KEYS_MULTI_A;
// Maximum length of a serialized BIP-32 derivation path.
#[cfg(feature = "wallet-policy")]
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
    /// The arena backing ran out of space while building the parsed template
    /// (only reachable with a fixed-capacity, no-alloc backing; the `Vec`-backed
    /// arena used in the default build effectively never returns this).
    ArenaFull,
}

/// The parsing context, tracking which top-level descriptor we are inside.
/// This determines which fragments and key expression forms are valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParseContext {
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
    pub(crate) fn musig_allowed(self) -> bool {
        matches!(self, ParseContext::Taproot)
    }

    /// `sh()` is only allowed at the top level.
    pub(crate) fn sh_allowed(self) -> bool {
        matches!(self, ParseContext::TopLevel)
    }

    /// `wpkh()` is only allowed at the top level or inside `sh()`.
    pub(crate) fn wpkh_allowed(self) -> bool {
        matches!(self, ParseContext::TopLevel | ParseContext::Legacy)
    }

    /// `wsh()` is only allowed at the top level or inside `sh()`.
    pub(crate) fn wsh_allowed(self) -> bool {
        matches!(self, ParseContext::TopLevel | ParseContext::Legacy)
    }

    /// `tr()` is only allowed at the top level.
    pub(crate) fn tr_allowed(self) -> bool {
        matches!(self, ParseContext::TopLevel)
    }
}

#[cfg(feature = "wallet-policy")]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeyOrigin {
    pub fingerprint: u32,
    pub derivation_path: Vec<ChildNumber>,
}

#[cfg(feature = "wallet-policy")]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeyInformation {
    pub pubkey: Xpub,
    pub origin_info: Option<KeyOrigin>,
}

#[cfg(feature = "alloc")]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum KeyExpressionType {
    PlainKey(u32),
    Musig(Vec<u32>),
}

#[cfg(feature = "alloc")]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeyExpression {
    pub key_type: KeyExpressionType,
    pub num1: u32,
    pub num2: u32,
}

#[cfg(feature = "alloc")]
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

#[cfg(feature = "alloc")]
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

#[cfg(feature = "alloc")]
pub struct DescriptorTemplateIter<'a> {
    fragments: Vec<(&'a DescriptorTemplate, Option<&'a DescriptorTemplate>)>, // Store DescriptorTemplate and its associated leaf context
    placeholders: Vec<(&'a KeyExpression, Option<&'a DescriptorTemplate>)>, // Placeholders also carry the leaf context
}

#[cfg(feature = "alloc")]
impl<'a> From<&'a DescriptorTemplate> for DescriptorTemplateIter<'a> {
    fn from(desc: &'a DescriptorTemplate) -> Self {
        DescriptorTemplateIter {
            fragments: vec![(desc, None)], // Initially, there is no associated leaf context
            placeholders: Vec::new(),
        }
    }
}

#[cfg(feature = "alloc")]
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
#[cfg(feature = "alloc")]
pub struct DescriptorTemplateIterMut<'a> {
    fragments: Vec<*mut DescriptorTemplate>,
    placeholders: Vec<*mut KeyExpression>,
    _marker: core::marker::PhantomData<&'a mut DescriptorTemplate>,
}

#[cfg(feature = "alloc")]
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

#[cfg(feature = "alloc")]
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
#[cfg(feature = "alloc")]
pub enum TapTree {
    Script(Box<DescriptorTemplate>),
    Branch(Box<TapTree>, Box<TapTree>),
}

#[cfg(feature = "alloc")]
impl TapTree {
    pub fn tapleaves(&self) -> TapleavesIter<'_> {
        TapleavesIter::new(self)
    }
}

#[cfg(feature = "alloc")]
pub struct TapleavesIter<'a> {
    stack: Vec<&'a TapTree>,
}

#[cfg(feature = "alloc")]
impl<'a> TapleavesIter<'a> {
    fn new(root: &'a TapTree) -> Self {
        TapleavesIter { stack: vec![root] }
    }
}

#[cfg(feature = "alloc")]
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

#[cfg(feature = "alloc")]
impl core::fmt::Display for TapTree {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TapTree::Script(desc) => write!(f, "{}", desc),
            TapTree::Branch(left, right) => write!(f, "{{{},{}}}", left, right),
        }
    }
}

#[cfg(feature = "wallet-policy")]
impl core::fmt::Display for KeyOrigin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:08x}", self.fingerprint)?;
        for step in &self.derivation_path {
            write!(f, "/{}", step)?;
        }
        Ok(())
    }
}

#[cfg(feature = "wallet-policy")]
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

#[cfg(feature = "wallet-policy")]
impl core::fmt::Display for KeyInformation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.origin_info {
            Some(origin_info) => write!(f, "[{}]{}", origin_info, self.pubkey),
            None => write!(f, "{}", self.pubkey),
        }
    }
}

#[cfg(feature = "alloc")]
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

#[cfg(feature = "wallet-policy")]
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

#[cfg(feature = "alloc")]
pub trait ToDescriptor {
    fn to_descriptor(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<String, ParseError>;
}

#[cfg(feature = "alloc")]
impl FromStr for DescriptorTemplate {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut a = arena::VecArena::new();
        let root = parser::parse_descriptor_template(input, &mut a)?;
        Ok(arena_to_owned(&a, root))
    }
}

/// Materialize the owned [`DescriptorTemplate`] enum from a parsed arena.
///
/// This bridge keeps the historical owned-AST consumers working while the
/// parser builds the flat arena representation. It is removed once all
/// consumers operate directly on arena cursors.
#[cfg(feature = "alloc")]
fn arena_to_owned(arena: &arena::VecArena, root: arena::NodeId) -> DescriptorTemplate {
    node_to_owned(arena::Cursor::new(arena, root))
}

#[cfg(feature = "alloc")]
fn node_to_owned<A: arena::ArenaRead>(cur: arena::Cursor<'_, A>) -> DescriptorTemplate {
    use arena::DescriptorNode as DN;
    // Peel a linear wrapper spine iteratively so a long wrapper chain (e.g.
    // `jjjj…:0`) doesn't recurse once per wrapper. Combinator/tap nesting is
    // bounded by the parser depth limit, so `build_owned`'s recursion is bounded.
    let mut wraps: Vec<fn(Box<DescriptorTemplate>) -> DescriptorTemplate> = Vec::new();
    let mut cur = cur;
    loop {
        let (ctor, child): (fn(Box<DescriptorTemplate>) -> DescriptorTemplate, _) = match cur.view()
        {
            DN::A(c) => (DescriptorTemplate::A, c),
            DN::S(c) => (DescriptorTemplate::S, c),
            DN::C(c) => (DescriptorTemplate::C, c),
            DN::T(c) => (DescriptorTemplate::T, c),
            DN::D(c) => (DescriptorTemplate::D, c),
            DN::V(c) => (DescriptorTemplate::V, c),
            DN::J(c) => (DescriptorTemplate::J, c),
            DN::N(c) => (DescriptorTemplate::N, c),
            DN::L(c) => (DescriptorTemplate::L, c),
            DN::U(c) => (DescriptorTemplate::U, c),
            view => {
                let mut result = build_owned(view);
                while let Some(w) = wraps.pop() {
                    result = w(Box::new(result));
                }
                return result;
            }
        };
        wraps.push(ctor);
        cur = child;
    }
}

#[cfg(feature = "alloc")]
fn build_owned<A: arena::ArenaRead>(view: arena::DescriptorNode<'_, A>) -> DescriptorTemplate {
    use arena::DescriptorNode as DN;
    use DescriptorTemplate as DT;
    match view {
        DN::Sh(c) => DT::Sh(Box::new(node_to_owned(c))),
        DN::Wsh(c) => DT::Wsh(Box::new(node_to_owned(c))),
        DN::A(c) => DT::A(Box::new(node_to_owned(c))),
        DN::S(c) => DT::S(Box::new(node_to_owned(c))),
        DN::C(c) => DT::C(Box::new(node_to_owned(c))),
        DN::T(c) => DT::T(Box::new(node_to_owned(c))),
        DN::D(c) => DT::D(Box::new(node_to_owned(c))),
        DN::V(c) => DT::V(Box::new(node_to_owned(c))),
        DN::J(c) => DT::J(Box::new(node_to_owned(c))),
        DN::N(c) => DT::N(Box::new(node_to_owned(c))),
        DN::L(c) => DT::L(Box::new(node_to_owned(c))),
        DN::U(c) => DT::U(Box::new(node_to_owned(c))),
        DN::Pkh(kv) => DT::Pkh(keyview_to_owned(kv)),
        DN::Wpkh(kv) => DT::Wpkh(keyview_to_owned(kv)),
        DN::Pk(kv) => DT::Pk(keyview_to_owned(kv)),
        DN::PkK(kv) => DT::Pk_k(keyview_to_owned(kv)),
        DN::PkH(kv) => DT::Pk_h(keyview_to_owned(kv)),
        DN::Tr(kv, tree) => DT::Tr(keyview_to_owned(kv), tree.map(taptree_to_owned)),
        DN::Zero => DT::Zero,
        DN::One => DT::One,
        DN::Older(n) => DT::Older(n),
        DN::After(n) => DT::After(n),
        DN::Sha256(b) => DT::Sha256(b.try_into().expect("sha256 fragment is 32 bytes")),
        DN::Hash256(b) => DT::Hash256(b.try_into().expect("hash256 fragment is 32 bytes")),
        DN::Ripemd160(b) => DT::Ripemd160(b.try_into().expect("ripemd160 fragment is 20 bytes")),
        DN::Hash160(b) => DT::Hash160(b.try_into().expect("hash160 fragment is 20 bytes")),
        DN::Andor(x, y, z) => DT::Andor(
            Box::new(node_to_owned(x)),
            Box::new(node_to_owned(y)),
            Box::new(node_to_owned(z)),
        ),
        DN::AndV(x, y) => DT::And_v(Box::new(node_to_owned(x)), Box::new(node_to_owned(y))),
        DN::AndB(x, y) => DT::And_b(Box::new(node_to_owned(x)), Box::new(node_to_owned(y))),
        DN::AndN(x, y) => DT::And_n(Box::new(node_to_owned(x)), Box::new(node_to_owned(y))),
        DN::OrB(x, y) => DT::Or_b(Box::new(node_to_owned(x)), Box::new(node_to_owned(y))),
        DN::OrC(x, y) => DT::Or_c(Box::new(node_to_owned(x)), Box::new(node_to_owned(y))),
        DN::OrD(x, y) => DT::Or_d(Box::new(node_to_owned(x)), Box::new(node_to_owned(y))),
        DN::OrI(x, y) => DT::Or_i(Box::new(node_to_owned(x)), Box::new(node_to_owned(y))),
        DN::Thresh(k, list) => DT::Thresh(k, list.iter().map(node_to_owned).collect()),
        DN::Multi(k, keys) => DT::Multi(k, keys.iter().map(keyview_to_owned).collect()),
        DN::MultiA(k, keys) => DT::Multi_a(k, keys.iter().map(keyview_to_owned).collect()),
        DN::Sortedmulti(k, keys) => DT::Sortedmulti(k, keys.iter().map(keyview_to_owned).collect()),
        DN::SortedmultiA(k, keys) => {
            DT::Sortedmulti_a(k, keys.iter().map(keyview_to_owned).collect())
        }
        DN::TapNode(_) => unreachable!("tap-tree node reached via node_to_owned"),
    }
}

/// Materializes an owned [`KeyExpression`] from a borrowed arena [`KeyView`].
/// Used at API boundaries where an owned key value is required (e.g. collecting
/// a wallet policy's placeholders for PSBT filling).
#[cfg(feature = "alloc")]
pub fn keyview_to_owned<A: arena::ArenaRead>(kv: arena::KeyView<'_, A>) -> KeyExpression {
    if let Some(idx) = kv.plain_key_index() {
        KeyExpression::plain(idx, kv.num1(), kv.num2())
    } else {
        let members = kv.musig_key_indices().expect("musig key").to_vec();
        KeyExpression::musig(members, kv.num1(), kv.num2())
    }
}

#[cfg(feature = "alloc")]
fn taptree_to_owned<A: arena::ArenaRead>(tc: arena::TapCursor<'_, A>) -> TapTree {
    if let Some(script) = tc.leaf_script() {
        TapTree::Script(Box::new(node_to_owned(script)))
    } else {
        let (l, r) = tc.branch().expect("tap node is leaf or branch");
        TapTree::Branch(Box::new(taptree_to_owned(l)), Box::new(taptree_to_owned(r)))
    }
}

// Test-only thin wrappers exposing the historical owned-returning parser API,
// backed by the arena parser + `arena_to_owned`, so the existing unit tests
// keep exercising the same surface.
#[cfg(test)]
pub(crate) use parser::parse_derivation_step_number;

#[cfg(test)]
fn parse_descriptor_template(input: &str) -> Result<DescriptorTemplate, ParseError> {
    let mut a = arena::VecArena::new();
    let root = parser::parse_descriptor_template(input, &mut a)?;
    Ok(arena_to_owned(&a, root))
}

#[cfg(test)]
fn parse_descriptor(
    input: &str,
    ctx: ParseContext,
    depth: usize,
) -> Result<(&str, DescriptorTemplate), ParseError> {
    let mut a = arena::VecArena::new();
    let (rest, id) = parser::parse_descriptor(input, ctx, depth, &mut a)?;
    Ok((rest, arena_to_owned(&a, id)))
}

#[cfg(test)]
fn parse_thresh(
    input: &str,
    ctx: ParseContext,
    depth: usize,
) -> Result<(&str, DescriptorTemplate), ParseError> {
    let mut a = arena::VecArena::new();
    let (rest, id) = parser::parse_thresh(input, ctx, depth, &mut a)?;
    Ok((rest, arena_to_owned(&a, id)))
}

#[cfg(test)]
fn parse_tr(input: &str, depth: usize) -> Result<(&str, DescriptorTemplate), ParseError> {
    let mut a = arena::VecArena::new();
    let (rest, id) = parser::parse_tr(input, depth, &mut a)?;
    Ok((rest, arena_to_owned(&a, id)))
}

#[cfg(test)]
fn parse_key_expression(
    input: &str,
    ctx: ParseContext,
) -> Result<(&str, KeyExpression), ParseError> {
    let mut a = arena::VecArena::new();
    let (rest, kid) = parser::parse_key_expression(input, ctx, &mut a)?;
    Ok((rest, keyview_to_owned(arena::key_view(&a, kid))))
}

#[cfg(test)]
fn parse_wsh(input: &str) -> Result<(&str, DescriptorTemplate), ParseError> {
    use arena::ArenaStore;
    if !input.starts_with("wsh(") {
        return Err(ParseError::InvalidSyntax);
    }
    let mut a = arena::VecArena::new();
    let (rest, [script]) =
        parser::parse_n_subscripts::<1, _>(&input[4..], ParseContext::Segwit, 0, &mut a)?;
    let wsh = a
        .push_node(arena::Node::with_a(arena::NodeTag::Wsh, script.0))
        .map_err(|_| ParseError::ArenaFull)?;
    Ok((rest, arena_to_owned(&a, wsh)))
}

#[cfg(test)]
fn parse_sortedmulti(input: &str) -> Result<(&str, DescriptorTemplate), ParseError> {
    let mut a = arena::VecArena::new();
    let (rest, id) = parser::parse_threshold_kp_fragment(
        input,
        "sortedmulti",
        arena::NodeTag::Sortedmulti,
        ParseContext::TopLevel,
        MAX_KEYS_MULTI,
        &mut a,
    )?;
    Ok((rest, arena_to_owned(&a, id)))
}

#[cfg(feature = "alloc")]
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

#[cfg(feature = "alloc")]
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
#[cfg(feature = "wallet-policy")]
pub struct WalletPolicy {
    // Flat arena form of the parsed template + its root. All computation
    // (script derivation, taproot hashing, placeholders, cleartext/confusion
    // score) runs over this via cursors; there is no owned AST representation.
    arena: arena::VecArena,
    root: arena::NodeId,
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

#[cfg(feature = "wallet-policy")]
impl WalletPolicy {
    pub fn new(
        descriptor_template_str: &str,
        key_information: Vec<KeyInformation>,
    ) -> Result<Self, ParseError> {
        let mut arena = arena::VecArena::new();
        let root = parser::parse_descriptor_template(descriptor_template_str, &mut arena)?;

        Ok(Self {
            arena,
            root,
            key_information,
            descriptor_template_raw: String::from(descriptor_template_str),
        })
    }

    /// A cursor over the flat (arena) form of the parsed template — the single
    /// representation that all computation (script derivation, taproot hashing,
    /// placeholders, cleartext/confusion score) operates on.
    pub fn descriptor_cursor(&self) -> arena::Cursor<'_, arena::VecArena> {
        arena::Cursor::new(&self.arena, self.root)
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

    /// Upper bound on how many descriptor templates map to the same cleartext
    /// (see the `cleartext` module). Computed over the arena via the cursor
    /// path; mirrors the historical `descriptor_template().confusion_score()`.
    pub fn confusion_score(&self) -> u64 {
        let cur = self.descriptor_cursor();
        let mut scratch = alloc::vec![0u32; cur.expanded_key_occurrences()];
        cur.confusion_score(&mut scratch)
    }

    /// Human-readable description lines for this policy, plus whether every
    /// part has a cleartext form. Computed over the arena via the cursor path;
    /// mirrors the historical `descriptor_template().to_cleartext()`.
    pub fn to_cleartext(&self) -> (Vec<String>, bool) {
        let cur = self.descriptor_cursor();
        let mut canon = alloc::vec![arena::KeyExprRec::plain(0, 0, 0); cur.placeholder_count()];
        let mut leaf = alloc::vec![0u32; cur.tapleaf_count()];
        let mut sink = arena::VecLineSink::new();
        let all_have_cleartext = cur.to_cleartext(&mut sink, &mut canon, &mut leaf);
        (sink.into_lines(), all_have_cleartext)
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
        self.descriptor_cursor().segwit_version()
    }
}

#[cfg(feature = "alloc")]
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
#[cfg(feature = "alloc")]
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
#[cfg(feature = "alloc")]
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

#[cfg(feature = "alloc")]
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

#[cfg(feature = "alloc")]
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

#[cfg(feature = "alloc")]
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

#[cfg(feature = "alloc")]
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
    fn test_cursor_render_matches_owned_display() {
        // The arena cursor renderer (used by the no-alloc build) must produce
        // byte-identical output to the owned `Display` for every shape.
        let cases = vec![
            "0",
            "1",
            "pkh(@0/**)",
            "wpkh(@0/<11;67>/*)",
            "sh(wsh(sortedmulti(2,@0/**,@1/**)))",
            "wsh(c:pk_k(@0/**))",
            "wsh(or_d(pk(@0/**),pkh(@1/**)))",
            "wsh(thresh(3,pk(@0/**),s:pk(@1/**),s:pk(@2/**),sln:older(12960)))",
            "tr(@0/**)",
            "tr(@0/<2;1>/*,{pkh(@1/<2;7>/*),pk(@2/**)})",
            "tr(musig(@0,@1)/**)",
            "tr(@0/**,pk(musig(@1,@2,@3)/<5;6>/*))",
            "sha256(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)",
            "ripemd160(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)",
            "wsh(andor(pk(@0/**),older(1),pk(@1/**)))",
            "wsh(or_i(and_v(v:pkh(@4/<3;7>/*),older(65535)),or_d(multi(2,@0/**,@3/**),and_v(v:thresh(1,pkh(@5/<99;101>/*),a:pkh(@1/**)),older(64231)))))",
            "tr(@0/**,{sortedmulti_a(1,@1/**,@2/**),or_b(pk(@3/**),s:pk(@4/**))})",
        ];

        for s in cases {
            let mut a = arena::VecArena::new();
            let root = parser::parse_descriptor_template(s, &mut a)
                .unwrap_or_else(|e| panic!("parse failed for {:?}: {:?}", s, e));
            let mut rendered = String::new();
            arena::Cursor::new(&a, root)
                .write_template(&mut rendered)
                .expect("render");
            assert_eq!(rendered, s, "cursor render mismatch for {:?}", s);
            assert_eq!(
                rendered,
                DescriptorTemplate::from_str(s).unwrap().to_string(),
                "cursor render disagrees with owned Display for {:?}",
                s
            );
        }
    }

    #[test]
    fn test_cursor_placeholders_match_owned() {
        let cases = vec![
            "pkh(@0/**)",
            "wsh(multi(2,@0/**,@1/**,@2/**))",
            "wsh(or_d(pk(@0/**),pkh(@1/**)))",
            "tr(@0/**)",
            "tr(@0/**,pkh(@1/**))",
            "tr(@0/<2;1>/*,{pkh(@1/<2;7>/*),pk(@2/**)})",
            "tr(musig(@0,@1)/**,{multi_a(1,@2/**,@3/**),pk(@4/**)})",
            "wsh(or_i(and_v(v:pkh(@4/<3;7>/*),older(65535)),or_d(multi(2,@0/**,@3/**),and_v(v:thresh(1,pkh(@5/<99;101>/*),a:pkh(@1/**)),older(64231)))))",
        ];

        for s in cases {
            let owned = DescriptorTemplate::from_str(s).unwrap();
            let mut owned_keys: Vec<String> = Vec::new();
            let mut owned_ctx: Vec<Option<String>> = Vec::new();
            for (kp, ctx) in owned.placeholders() {
                owned_keys.push(kp.to_string());
                owned_ctx.push(ctx.map(|c| c.to_string()));
            }

            let mut a = arena::VecArena::new();
            let root = parser::parse_descriptor_template(s, &mut a).unwrap();
            let mut cur_keys: Vec<String> = Vec::new();
            let mut cur_ctx: Vec<Option<String>> = Vec::new();
            arena::Cursor::new(&a, root).for_each_placeholder(&mut |kv, leaf| {
                let mut ks = String::new();
                kv.write_to(&mut ks).unwrap();
                cur_keys.push(ks);
                cur_ctx.push(leaf.map(|c| {
                    let mut s = String::new();
                    c.write_template(&mut s).unwrap();
                    s
                }));
            });

            assert_eq!(
                cur_keys, owned_keys,
                "placeholder keys mismatch for {:?}",
                s
            );
            assert_eq!(
                cur_ctx, owned_ctx,
                "placeholder leaf-context mismatch for {:?}",
                s
            );
        }
    }

    // Reference implementations mirroring the owned (private) confusion-score
    // helpers, computed from the public `placeholders()` iterator.
    #[cfg(test)]
    fn ref_orderings_count(dt: &DescriptorTemplate) -> u64 {
        let mut counts: alloc::collections::BTreeMap<u32, u32> =
            alloc::collections::BTreeMap::new();
        for (kp, _) in dt.placeholders() {
            match &kp.key_type {
                KeyExpressionType::PlainKey(i) => *counts.entry(*i).or_insert(0) += 1,
                KeyExpressionType::Musig(g) => {
                    for &m in g {
                        *counts.entry(m).or_insert(0) += 1;
                    }
                }
            }
        }
        let mut product = 1u64;
        for &k in counts.values() {
            let mut f = 1u64;
            for i in 1..=k as u64 {
                f = f.saturating_mul(i);
            }
            product = product.saturating_mul(f);
        }
        product
    }

    #[cfg(test)]
    fn ref_canonical(dt: &DescriptorTemplate) -> bool {
        let mut pairs: alloc::collections::BTreeMap<KeyExpressionType, Vec<(u32, u32)>> =
            alloc::collections::BTreeMap::new();
        for (kp, _) in dt.placeholders() {
            pairs
                .entry(kp.key_type.clone())
                .or_default()
                .push((kp.num1, kp.num2));
        }
        for v in pairs.values_mut() {
            v.sort();
            for (i, &(n1, n2)) in v.iter().enumerate() {
                if (n1, n2) != (2 * i as u32, 2 * i as u32 + 1) {
                    return false;
                }
            }
        }
        true
    }

    #[test]
    fn test_cursor_confusion_helpers_match_owned() {
        let cases = vec![
            "wsh(multi(2,@0/**,@1/**))",
            // index 0 repeated 3x across key path + two leaves -> 3! = 6
            "tr(@0/**,{pk(@0/<2;3>/*),pk(@0/<4;5>/*)})",
            // non-canonical: a single key with pair (2,3) instead of (0,1)
            "wpkh(@0/<2;3>/*)",
            // canonical musig + repeated members
            "tr(musig(@0,@1)/**,{multi_a(1,@0/<2;3>/*,@1/<2;3>/*),pk(@2/**)})",
            "wsh(or_i(and_v(v:pkh(@4/<3;7>/*),older(65535)),or_d(multi(2,@0/**,@3/**),and_v(v:thresh(1,pkh(@5/<99;101>/*),a:pkh(@1/**)),older(64231)))))",
        ];
        for s in cases {
            let owned = DescriptorTemplate::from_str(s).unwrap();
            let mut a = arena::VecArena::new();
            let root = parser::parse_descriptor_template(s, &mut a).unwrap();
            let cur = arena::Cursor::new(&a, root);

            let mut ord_scratch = vec![0u32; cur.expanded_key_occurrences()];
            assert_eq!(
                cur.key_derivation_orderings_count(&mut ord_scratch),
                ref_orderings_count(&owned),
                "orderings count mismatch for {:?}",
                s
            );

            let mut can_scratch = vec![arena::KeyExprRec::plain(0, 0, 1); cur.placeholder_count()];
            assert_eq!(
                cur.are_key_derivations_canonical(&mut can_scratch),
                ref_canonical(&owned),
                "canonical mismatch for {:?}",
                s
            );
        }
    }

    #[test]
    fn test_cursor_confusion_score_matches_owned() {
        let cases = vec![
            "pkh(@0/**)",
            "wpkh(@0/**)",
            "sh(wpkh(@0/**))",
            "wsh(multi(2,@0/**,@1/**,@2/**))",
            "wsh(multi(3,@0/**,@1/**,@2/**))",
            "sh(wsh(sortedmulti(2,@0/**,@1/**)))",
            "tr(@0/**)",
            "tr(@0/**,pk(@1/**))",
            "tr(@0/**,{pk(@1/**),pk(@2/**)})",
            "tr(@0/**,{pk(@1/**),{pk(@2/**),pk(@3/**)}})",
            "tr(musig(@0,@1)/**)",
            "tr(musig(@0,@1)/**,{pk(@2/**),multi_a(2,@3/**,@4/**)})",
            "tr(@0/**,{pk(@0/<2;3>/*),pk(@0/<4;5>/*)})",
            "tr(@0/**,and_v(v:pk(@1/**),older(144)))",
            "tr(@0/**,multi_a(2,@1/**,@2/**))",
            "tr(@0/**,sortedmulti_a(1,@1/**,@2/**))",
            "wsh(or_i(and_v(v:pkh(@4/<3;7>/*),older(65535)),or_d(multi(2,@0/**,@3/**),and_v(v:thresh(1,pkh(@5/<99;101>/*),a:pkh(@1/**)),older(64231)))))",
        ];
        for s in cases {
            let owned = DescriptorTemplate::from_str(s).unwrap();
            let expected = owned.confusion_score();

            let mut a = arena::VecArena::new();
            let root = parser::parse_descriptor_template(s, &mut a).unwrap();
            let cur = arena::Cursor::new(&a, root);
            let mut scratch = vec![0u32; cur.expanded_key_occurrences()];
            let got = cur.confusion_score(&mut scratch);

            assert_eq!(got, expected, "confusion score mismatch for {:?}", s);
        }
    }

    #[test]
    fn test_slice_arena_matches_vec_arena() {
        // The no-alloc SliceArena backing must produce identical confusion
        // scores and cleartext to the alloc VecArena backing.
        let cases = vec![
            "pkh(@0/**)",
            "wsh(multi(2,@0/**,@1/**,@2/**))",
            "wsh(multi(3,@0/**,@1/**,@2/**))",
            "sh(wsh(sortedmulti(2,@0/**,@1/**)))",
            "tr(@0/**)",
            "tr(@0/**,{pk(@1/**),{pk(@2/**),pk(@3/**)}})",
            "tr(musig(@0,@1)/**,{pk(@2/**),multi_a(2,@3/**,@4/**)})",
            "tr(@0/**,and_v(v:pk(@1/**),older(144)))",
            "wsh(or_i(and_v(v:pkh(@4/<3;7>/*),older(65535)),or_d(multi(2,@0/**,@3/**),and_v(v:thresh(1,pkh(@5/<99;101>/*),a:pkh(@1/**)),older(64231)))))",
        ];
        for s in cases {
            // VecArena (alloc) reference.
            let mut va = arena::VecArena::new();
            let vroot = parser::parse_descriptor_template(s, &mut va).unwrap();
            let vc = arena::Cursor::new(&va, vroot);
            let mut vsc = vec![0u32; vc.expanded_key_occurrences()];
            let v_score = vc.confusion_score(&mut vsc);
            let mut vcanon = vec![arena::KeyExprRec::plain(0, 0, 1); vc.placeholder_count()];
            let mut vleaf = vec![0u32; vc.tapleaf_count()];
            let mut vsink = arena::VecLineSink::new();
            let v_hct = vc.to_cleartext(&mut vsink, &mut vcanon, &mut vleaf);
            let v_lines = vsink.into_lines();

            // SliceArena (no-alloc backing) over caller-provided slices.
            let mut nodes = vec![arena::Node::new(arena::NodeTag::Zero); 1024];
            let mut keys = vec![arena::KeyExprRec::plain(0, 0, 1); 1024];
            let mut links = vec![arena::Link { val: 0, next: 0 }; 1024];
            let mut members = vec![0u32; 1024];
            let mut bytes = vec![0u8; 1024];
            let mut sa =
                arena::SliceArena::new(&mut nodes, &mut keys, &mut links, &mut members, &mut bytes);
            let sroot = parser::parse_descriptor_template(s, &mut sa).unwrap();
            let sc = arena::Cursor::new(&sa, sroot);
            let mut ssc = vec![0u32; sc.expanded_key_occurrences()];
            let s_score = sc.confusion_score(&mut ssc);
            let mut scanon = vec![arena::KeyExprRec::plain(0, 0, 1); sc.placeholder_count()];
            let mut sleaf = vec![0u32; sc.tapleaf_count()];
            let mut ssink = arena::VecLineSink::new();
            let s_hct = sc.to_cleartext(&mut ssink, &mut scanon, &mut sleaf);
            let s_lines = ssink.into_lines();

            assert_eq!(
                v_score, s_score,
                "confusion score backing mismatch for {:?}",
                s
            );
            assert_eq!(
                v_lines, s_lines,
                "cleartext lines backing mismatch for {:?}",
                s
            );
            assert_eq!(v_hct, s_hct, "has_cleartext backing mismatch for {:?}", s);
        }
    }

    #[test]
    fn test_embedded_public_api() {
        // Drive the public no-alloc API: measure -> size pools -> parse ->
        // confusion_score, and check it matches the owned implementation.
        assert_eq!(
            crate::embedded::measure("tr(musig(@0,@0)/**)"),
            Err(ParseError::InvalidKey)
        );

        let cases = vec![
            "wsh(multi(2,@0/**,@1/**,@2/**))",
            "tr(musig(@0,@1)/**,{pk(@2/**),multi_a(2,@3/**,@4/**)})",
            "tr(@0/**,and_v(v:pk(@1/**),older(144)))",
            "wsh(thresh(2,pk(@0/**),s:pk(@1/**),sln:older(10)))",
        ];
        for s in cases {
            let c = crate::embedded::measure(s).unwrap();
            let mut nodes = vec![arena::Node::new(arena::NodeTag::Zero); c.nodes as usize];
            let mut keys = vec![arena::KeyExprRec::plain(0, 0, 1); c.keys as usize];
            let mut links = vec![arena::Link { val: 0, next: 0 }; c.links as usize];
            let mut members = vec![0u32; c.members as usize];
            let mut bytes = vec![0u8; c.bytes as usize];
            let mut sa =
                arena::SliceArena::new(&mut nodes, &mut keys, &mut links, &mut members, &mut bytes);
            let root = crate::embedded::parse(s, &mut sa).unwrap();
            let cur = arena::Cursor::new(&sa, root);
            let mut scratch = vec![0u32; cur.expanded_key_occurrences()];
            assert_eq!(
                cur.confusion_score(&mut scratch),
                DescriptorTemplate::from_str(s).unwrap().confusion_score(),
                "embedded confusion score mismatch for {:?}",
                s
            );
        }
    }

    #[test]
    fn test_buf_line_sink_matches_vec_sink() {
        let s = "tr(@0/**,{pk(@1/**),and_v(v:pk(@2/**),older(144))})";
        let mut a = arena::VecArena::new();
        let root = parser::parse_descriptor_template(s, &mut a).unwrap();
        let cur = arena::Cursor::new(&a, root);

        let mut canon = vec![arena::KeyExprRec::plain(0, 0, 1); cur.placeholder_count()];
        let mut leaf = vec![0u32; cur.tapleaf_count()];
        let mut vsink = arena::VecLineSink::new();
        cur.to_cleartext(&mut vsink, &mut canon, &mut leaf);
        let v_lines = vsink.into_lines();

        let mut buf = vec![0u8; 4096];
        let mut spans = vec![arena::LineSpan::default(); 64];
        let mut canon2 = vec![arena::KeyExprRec::plain(0, 0, 1); cur.placeholder_count()];
        let mut leaf2 = vec![0u32; cur.tapleaf_count()];
        let n = {
            let mut bsink = arena::BufLineSink::new(&mut buf, &mut spans);
            cur.to_cleartext(&mut bsink, &mut canon2, &mut leaf2);
            assert!(!bsink.overflowed());
            bsink.line_count()
        };
        let buf_lines: Vec<String> = (0..n)
            .map(|i| {
                let sp = spans[i];
                String::from_utf8(buf[sp.offset as usize..(sp.offset + sp.len) as usize].to_vec())
                    .unwrap()
            })
            .collect();
        assert_eq!(buf_lines, v_lines);
    }

    #[test]
    fn test_cursor_segwit_version_matches_owned() {
        // get_segwit_version only inspects the top-level template, so an empty
        // key-information list is fine here.
        let cases = vec![
            ("pkh(@0/**)", SegwitVersion::Legacy),
            ("wpkh(@0/**)", SegwitVersion::SegwitV0),
            ("wsh(multi(2,@0/**,@1/**))", SegwitVersion::SegwitV0),
            ("sh(wpkh(@0/**))", SegwitVersion::SegwitV0),
            ("sh(wsh(multi(2,@0/**,@1/**)))", SegwitVersion::SegwitV0),
            ("tr(@0/**)", SegwitVersion::Taproot),
        ];
        for (s, expected) in cases {
            let wp_version = WalletPolicy::new(s, vec![]).unwrap().get_segwit_version();
            assert_eq!(wp_version, Ok(expected));

            let mut a = arena::VecArena::new();
            let root = parser::parse_descriptor_template(s, &mut a).unwrap();
            let got = arena::Cursor::new(&a, root).segwit_version();
            assert_eq!(got, Ok(expected), "segwit version mismatch for {:?}", s);
            assert_eq!(
                got, wp_version,
                "cursor vs WalletPolicy segwit version for {:?}",
                s
            );
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

    /// The cursor-based `placeholders()` iterator must visit placeholders in the
    /// exact same order as the owned `DescriptorTemplateIter`, with the same
    /// per-placeholder tap-leaf context. Compared via the key/leaf `Display`
    /// (cursor side uses the byte-identical `write_to` / `write_template`).
    #[test]
    fn cursor_placeholders_match_owned_order() {
        use core::fmt::Write;

        let corpus = [
            "pkh(@0/**)",
            "wsh(multi(2,@0/**,@1/**,@2/**))",
            "wsh(sortedmulti(2,@0/**,@1/**))",
            "tr(@0/**)",
            "tr(@0/**,pk(@1/**))",
            "tr(@0/**,{pk(@1/**),{pk(@2/**),pk(@3/**)}})",
            "tr(@0/**,multi_a(2,@1/**,@2/**))",
            "wsh(or_d(pk(@0/**),and_v(v:pk(@1/**),older(65535))))",
            "wsh(andor(pk(@0/**),older(144),pk(@1/**)))",
            "wsh(thresh(2,pk(@0/**),s:pk(@1/**),s:pk(@2/**)))",
            "tr(musig(@0,@1)/**)",
            "tr(@0/**,pk(musig(@1,@2)/**))",
            "tr(@0/**,{multi_a(2,@1/**,@2/**),pk(@3/**)})",
        ];

        let render_cursor_key = |kv: arena::KeyView<'_, arena::VecArena>| -> alloc::string::String {
            let mut s = alloc::string::String::new();
            kv.write_to(&mut s).unwrap();
            s
        };
        let render_cursor_leaf =
            |leaf: Option<arena::Cursor<'_, arena::VecArena>>| -> Option<alloc::string::String> {
                leaf.map(|c| {
                    let mut s = alloc::string::String::new();
                    c.write_template(&mut s).unwrap();
                    s
                })
            };

        for template in corpus {
            let mut a = arena::VecArena::new();
            let root = parser::parse_descriptor_template(template, &mut a).unwrap();
            let owned = arena_to_owned(&a, root);
            let cursor = arena::Cursor::new(&a, root);

            let owned_seq: Vec<(String, Option<String>)> = owned
                .placeholders()
                .map(|(kp, leaf)| {
                    let mut k = String::new();
                    write!(k, "{}", kp).unwrap();
                    (k, leaf.map(|d| format!("{}", d)))
                })
                .collect();

            let cursor_seq: Vec<(String, Option<String>)> = cursor
                .placeholders()
                .map(|(kv, leaf)| (render_cursor_key(kv), render_cursor_leaf(leaf)))
                .collect();

            assert_eq!(
                owned_seq, cursor_seq,
                "placeholder order/context mismatch for {template}"
            );
        }
    }
}

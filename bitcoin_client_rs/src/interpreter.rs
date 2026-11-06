//! The interpreter of the client commands: the requests that the device sends to the client while
//! it processes a command, to get the data that the command refers to (preimages, elements of
//! Merkle trees), and to yield values.

use core::convert::TryFrom;
use core::fmt::{self, Debug};

use bitcoin::{
    consensus::encode::{self},
    hashes::{sha256, Hash, HashEngine},
};

use crate::protocol::UncheckedVarInt;

use crate::{apdu::ClientCommandCode, merkle::MerkleTree};

/// Interpreter for the client commands.
///
/// It keeps track of:
///   - the known preimages;
///   - the known Merkle trees of lists of elements.
///
/// Moreover, it contains the state of the interpreted client commands: a queue of the elements
/// that did not fit in an answer to GET_PREIMAGE (a preimage too long for a single message) or to
/// GET_MERKLE_LEAF_PROOF (a Merkle proof too long for a single message). The device gets them with
/// one or more GET_MORE_ELEMENTS client commands.
///
/// Finally, it keeps track of the yielded values (that is, the values that the device sends with a
/// YIELD client command).
#[derive(Debug)]
pub struct ClientCommandInterpreter {
    yielded: Vec<Vec<u8>>,
    queue: Vec<Vec<u8>>,
    known_preimages: Vec<([u8; 32], Vec<u8>)>,
    trees: Vec<MerkleTree>,
}

impl Default for ClientCommandInterpreter {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientCommandInterpreter {
    /// Creates an interpreter with no known preimages or Merkle trees.
    pub fn new() -> Self {
        Self {
            yielded: Vec::new(),
            queue: Vec::new(),
            known_preimages: Vec::new(),
            trees: Vec::new(),
        }
    }

    /// Adds a preimage to the list of known preimages.
    /// The client must respond with `element` when a GET_PREIMAGE command is sent with
    /// `sha256(element)` in its request.
    pub fn add_known_preimage(&mut self, element: Vec<u8>) {
        let mut engine = sha256::Hash::engine();
        engine.input(&element);
        let hash = sha256::Hash::from_engine(engine).to_byte_array();
        self.known_preimages.push((hash, element));
    }

    /// Adds a known Merkleized list, and returns its Merkle root.
    ///
    /// Builds the Merkle tree of `elements`, and adds it to the Merkle trees known to the client,
    /// so that the GET_MERKLE_LEAF_INDEX and GET_MERKLE_LEAF_PROOF client commands are answered
    /// for it. Moreover, adds all the leaves (after adding the `0x00` prefix) to the known
    /// preimages: if `el` is one of `elements`, the client responds with `0x00 || el` to a
    /// GET_PREIMAGE client command for `sha256(0x00 || el)`.
    pub fn add_known_list(&mut self, elements: &[impl AsRef<[u8]>]) -> [u8; 32] {
        let mut leaves = Vec::with_capacity(elements.len());
        for element in elements {
            let mut preimage = vec![0x00];
            preimage.extend_from_slice(element.as_ref());
            let mut engine = sha256::Hash::engine();
            engine.input(&preimage);
            let hash = sha256::Hash::from_engine(engine).to_byte_array();
            self.known_preimages.push((hash, preimage));
            leaves.push(hash);
        }
        let tree = MerkleTree::new(leaves);
        let root_hash = *tree.root_hash();
        self.trees.push(tree);
        root_hash
    }

    /// Adds a known Merkleized map: the Merkle tree of its keys, sorted, and the Merkle tree of the
    /// corresponding values, with the same semantics as [`add_known_list`](Self::add_known_list)
    /// applied separately to the two lists.
    ///
    /// Duplicate keys are not rejected, but the device requires the keys of a map to be strictly
    /// increasing, so it rejects such a map.
    pub fn add_known_mapping(&mut self, mapping: &[(Vec<u8>, Vec<u8>)]) {
        let mut sorted: Vec<&(Vec<u8>, Vec<u8>)> = mapping.iter().collect();
        sorted.sort_by(|(k1, _), (k2, _)| k1.as_slice().cmp(k2));

        let mut keys = Vec::with_capacity(sorted.len());
        let mut values = Vec::with_capacity(sorted.len());
        for (key, value) in sorted {
            keys.push(key.as_slice());
            values.push(value.as_slice());
        }
        self.add_known_list(&keys);
        self.add_known_list(&values);
    }

    /// Interprets a client command, which is the data of a device response with the
    /// `InterruptedExecution` status, and returns the data to send back with a CONTINUE command.
    /// Updates the state of the interpreter.
    pub fn execute(&mut self, command: Vec<u8>) -> Result<Vec<u8>, InterpreterError> {
        if command.is_empty() {
            return Err(InterpreterError::EmptyInput);
        }
        match ClientCommandCode::try_from(command[0]) {
            Ok(ClientCommandCode::Yield) => {
                self.yielded.push(command[1..].to_vec());
                Ok(Vec::new())
            }
            Ok(ClientCommandCode::GetPreimage) => {
                get_preimage_command(&mut self.queue, &self.known_preimages, &command[1..])
            }
            Ok(ClientCommandCode::GetMerkleLeafProof) => {
                get_merkle_leaf_proof(&mut self.queue, &self.trees, &command[1..])
            }
            Ok(ClientCommandCode::GetMerkleLeafIndex) => {
                get_merkle_leaf_index(&self.trees, &command[1..])
            }
            Ok(ClientCommandCode::GetMoreElements) => get_more_elements(&mut self.queue),
            Err(()) => Err(InterpreterError::UnknownCommand(command[0])),
        }
    }

    /// Consumes the interpreter and returns the yielded results.
    pub fn yielded(self) -> Vec<Vec<u8>> {
        self.yielded
    }
}

fn get_preimage_command(
    queue: &mut Vec<Vec<u8>>,
    known_preimages: &[([u8; 32], Vec<u8>)],
    request: &[u8],
) -> Result<Vec<u8>, InterpreterError> {
    if request.len() != 33 || request[0] != b'\0' {
        return Err(InterpreterError::UnsupportedRequest(
            ClientCommandCode::GetPreimage as u8,
        ));
    };

    let (_, preimage) = known_preimages
        .iter()
        .find(|(hash, _)| hash == &request[1..])
        .ok_or(InterpreterError::UnknownHash)?;

    let preimage_len_out = encode::serialize(&UncheckedVarInt(preimage.len() as u64));

    // We can send at most 255 - len(preimage_len_out) - 1 bytes in a single message;
    //the rest will be stored for GET_MORE_ELEMENTS
    let max_payload_size = 255 - preimage_len_out.len() - 1;

    let payload_size = if preimage.len() > max_payload_size {
        max_payload_size
    } else {
        preimage.len()
    };

    if payload_size < preimage.len() {
        for byte in &preimage[payload_size..] {
            queue.push(vec![*byte]);
        }
    }

    let mut response = preimage_len_out;
    response.extend_from_slice(&(payload_size as u8).to_be_bytes());
    response.extend_from_slice(&preimage[..payload_size]);
    Ok(response)
}

fn get_merkle_leaf_proof(
    queue: &mut Vec<Vec<u8>>,
    trees: &[MerkleTree],
    request: &[u8],
) -> Result<Vec<u8>, InterpreterError> {
    if !queue.is_empty() {
        return Err(InterpreterError::UnexpectedQueue);
    } else if request.len() < 34 {
        return Err(InterpreterError::UnsupportedRequest(
            ClientCommandCode::GetMerkleLeafProof as u8,
        ));
    };

    let root = &request[0..32];
    let (tree_size, read): (UncheckedVarInt, usize) = encode::deserialize_partial(&request[32..])
        .map_err(|_| {
        InterpreterError::UnsupportedRequest(ClientCommandCode::GetMerkleLeafProof as u8)
    })?;

    // deserialize consumes the entire vector.
    let leaf_index: UncheckedVarInt = encode::deserialize(&request[32 + read..]).map_err(|_| {
        InterpreterError::UnsupportedRequest(ClientCommandCode::GetMerkleLeafProof as u8)
    })?;

    let tree = trees
        .iter()
        .find(|tree| tree.root_hash() == root)
        .ok_or(InterpreterError::UnknownMerkleRoot)?;

    if leaf_index >= tree_size || tree_size.0 != tree.size() as u64 {
        return Err(InterpreterError::InvalidIndexOrSize);
    }

    let proof = tree
        .get_leaf_proof(leaf_index.0 as usize)
        .ok_or(InterpreterError::InvalidIndexOrSize)?;

    let len_proof = proof.len();
    let mut first_part_proof = Vec::new();
    let mut n_response_elements = 0;
    for (i, p) in proof.into_iter().enumerate() {
        // how many elements we can fit in 255 - 32 - 1 - 1 = 221 bytes ?
        // response: 6 array of 32 bytes.
        if i < 6 {
            first_part_proof.extend(p);
            n_response_elements += 1;
        } else {
            // Add to the queue any proof elements that do not fit the response
            queue.push(p);
        }
    }

    let mut response = tree.get_leaf(leaf_index.0 as usize).unwrap().to_vec();
    response.extend_from_slice(&(len_proof as u8).to_be_bytes());
    response.extend_from_slice(&(n_response_elements as u8).to_be_bytes());
    response.extend_from_slice(&first_part_proof);
    Ok(response)
}

fn get_merkle_leaf_index(
    trees: &[MerkleTree],
    request: &[u8],
) -> Result<Vec<u8>, InterpreterError> {
    if request.len() < 64 {
        return Err(InterpreterError::UnsupportedRequest(
            ClientCommandCode::GetMerkleLeafIndex as u8,
        ));
    }
    let root = &request[0..32];
    let hash = &request[32..64];

    let tree = trees
        .iter()
        .find(|tree| tree.root_hash() == root)
        .ok_or(InterpreterError::UnknownMerkleRoot)?;

    let leaf_index = match tree.get_leaf_index(hash) {
        Some(index) => index,
        None => return Ok(vec![0, 0]),
    };

    let mut response = 1_u8.to_be_bytes().to_vec();
    response.extend(encode::serialize(&UncheckedVarInt(leaf_index as u64)));
    Ok(response)
}

fn get_more_elements(queue: &mut Vec<Vec<u8>>) -> Result<Vec<u8>, InterpreterError> {
    if queue.is_empty() {
        return Err(InterpreterError::UnexpectedQueue);
    }

    // The queue must contain only element of the same length.
    let element_length = queue[0].len();
    if queue.iter().any(|e| e.len() != element_length) {
        return Err(InterpreterError::UnexpectedQueue);
    }

    let mut response_elements = Vec::new();
    let mut n_added_elements = 0;
    for element in queue.iter() {
        if response_elements.len() + element_length <= 253 {
            response_elements.extend_from_slice(element);
            n_added_elements += 1;
        }
    }
    *queue = queue[n_added_elements..].to_vec();

    let mut response = (n_added_elements as u8).to_be_bytes().to_vec();
    response.extend((element_length as u8).to_be_bytes());
    response.extend(response_elements);
    Ok(response)
}

/// Returns a serialized Merkleized map commitment, encoded as the concatenation of:
///     - the number of key/value pairs, as a Bitcoin-style varint;
///     - the root of the Merkle tree of the keys
///     - the root of the Merkle tree of the values.
pub fn get_merkleized_map_commitment(mapping: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut sorted: Vec<&(Vec<u8>, Vec<u8>)> = mapping.iter().collect();
    sorted.sort_by(|(k1, _), (k2, _)| k1.as_slice().cmp(k2));

    let mut keys_hashes: Vec<[u8; 32]> = Vec::with_capacity(sorted.len());
    let mut values_hashes: Vec<[u8; 32]> = Vec::with_capacity(sorted.len());
    for (key, value) in &sorted {
        let mut preimage = vec![0x00];
        preimage.extend_from_slice(key);
        let mut engine = sha256::Hash::engine();
        engine.input(&preimage);
        keys_hashes.push(sha256::Hash::from_engine(engine).to_byte_array());

        let mut preimage = vec![0x00];
        preimage.extend_from_slice(value);
        let mut engine = sha256::Hash::engine();
        engine.input(&preimage);
        values_hashes.push(sha256::Hash::from_engine(engine).to_byte_array());
    }

    let mut commitment = encode::serialize(&UncheckedVarInt(sorted.len() as u64));
    commitment.extend(MerkleTree::new(keys_hashes).root_hash());
    commitment.extend(MerkleTree::new(values_hashes).root_hash());
    commitment
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterpreterError {
    /// The client command is empty.
    EmptyInput,
    /// The client command has an unknown code.
    UnknownCommand(u8),
    /// The request of the client command with this code is malformed or unsupported.
    UnsupportedRequest(u8),
    /// GET_MERKLE_LEAF_PROOF: the leaf index or the tree size does not match the known tree.
    InvalidIndexOrSize,
    /// GET_PREIMAGE: no known preimage has the requested hash.
    UnknownHash,
    /// No known Merkle tree has the requested root.
    UnknownMerkleRoot,
    /// The client command is not valid in the current state of the queue of elements left from a
    /// previous answer.
    UnexpectedQueue,
}

impl fmt::Display for InterpreterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => f.write_str("Empty interpreter request"),
            Self::UnknownCommand(command) => {
                write!(f, "Unknown interpreter command: {:#04x}", command)
            }
            Self::UnsupportedRequest(command) => {
                write!(f, "Unsupported interpreter request: {:#04x}", command)
            }
            Self::InvalidIndexOrSize => f.write_str("Invalid index or size"),
            Self::UnknownHash => f.write_str("Unknown preimage hash"),
            Self::UnknownMerkleRoot => f.write_str("Unknown Merkle root"),
            Self::UnexpectedQueue => f.write_str("Unexpected interpreter queue state"),
        }
    }
}

impl std::error::Error for InterpreterError {}

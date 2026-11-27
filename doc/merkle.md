# Merkle trees and Merkleized maps

The app makes extensive usage of [Merkle trees](https://en.wikipedia.org/wiki/Merkle_tree) in order to commit to (possibly large) sets of data that are stored on the client and revealed to the Hardware Wallet when needed. This allows to safely operate on sets of data that are too large to be stored on the limited device memory.

By checking a Merkle proof to a previously committed-to Merkle tree, the Hardware Wallet is certain that a compromised client cannot do anything unexpected (e.g.: lie on some data, or maliciously choose what data to reveal based on the previous interaction of a multi-step protocol, etc.).

Operations on Merkle trees are composed to create commitments to more complex data structures like maps.

## Data structures
### Merkle trees
#### Definition

A Merkle tree allows to create a commitment to an arbitrarily large list of values; short membership proofs can be provided that can be verified solely with the knowledge of a single hash (the Merkle tree root).

Our implementation of Merkle trees loosely follows the structure defined in [RFC 6962](https://www.rfc-editor.org/rfc/pdfrfc/rfc6962.txt.pdf), using SHA-256 as the hash function. We refer to the linked document for a more detailed description. Only one difference (the hash of the empty list) is defined below.

We call a *byte string* an arbitrary array of bytes, where each byte is a value between `0` and `255`. A *hash function* takes as input an arbitrary length byte string, and produces a fixed-length output. Outputs of SHA-256 are 32 bytes long.

Following the notation of RFC 6962, we are given an ordered list of inputs `D[n] = {d(0), d(1), ..., d(n-1)}`, where each element `d(i)` is a byte string. We denote with `||` the concatenation operator, and with `D[a:b]` the list `{d(a), d(a+1), ..., d(b - 1)}`.

We define the Merkle Tree Hash (MTH) (also called the *Merkle root*) as follows.

The hash of the empty list is `MTH({}) = 0`, a string of 32 bytes identically equal to `0`. *This definition differs from RFC 6962*.

The hash of a 1-element list (*leaf node*) is:

    MTH({d(0)}) = SHA-256(0x00 || d(0))

For `n > 1`, let `k` be the largest power of `2` strictly smaller than `n`. Then the hash of a list `D[n]` (*internal node*) is:

    MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))

Note that the 1-byte prefix `0x00` is prepended when computing the leaf hashes, while `0x01` is prepended for internal nodes; this domain separation prevents collision attacks where different trees with the same Merkle Tree hash could be produced.

#### Merkle proofs

The Merkle proof (called *Merkle audit path* in the language of RFC 6962) for a leaf node is the minimal set of additional nodes that is necessary to compute the Merkle Tree Hash. See section 2.1.3. of RFC 6962 for some examples.

For any non-root node of the tree (either internal or leaf), let the *brother* be the unique other node sharing the same parent, that is the unique other node whose hash is combined together to compute an internal node.

In the typical tree-like representation of the Merkle tree, the Merkle proof for a leaf is the list of the brothers of all the nodes on the path from that leaf to the root (excluding the root itself).

#### Remarks

- As long as the size `n` of a Merkle tree is known, the exact structure of the tree (the sequence of hashes necessary to compute each internal node, and the Merkle Tree Hash) is deterministic.
- For any internal node, the left sub-tree is a complete binary tree.
- Assuming collision-resistance of SHA-256, it is intractable to find two trees with the same Merkle root.

<!-- TODO: Size and leaf index in Merkle proof; how we use Merkle proofs -->

### Merkleized maps

A *map* of size `n` is an arbitrary set of key-value pairs `{(k(0), v(0)), (k(1), v(1)), ..., (k(n-1), v(n-1))}`, where each `k(i)` and each `v(j)` is a byte string, and all the keys are different. Without loss of generality, we assume that the list `{k(0), k(1), ..., k(n-1)}` is sorted lexicographically.

We define a **Merkleized map commitment** as the pair `(keys_root, values_root)`, where

    keys_root = MTH({k(0), k(1), ..., k(n - 1)})

and

    values_root = MTH({v(0), v(1), ..., v(n - 1)})

#### Serialization

A Merkleized map commitment is serialized as a string of bytes containing, in sequence:
- the number of key-value pairs, encoded as a Bitcoin-style varint;
- the 32 bytes `keys_root`;
- the 32 bytes `values_root`.

Therefore, the length of a serialized Merkleized map commitment is between `65` and `73` bytes long.

## Client side operations

In this section we describe the operations that might be performed in a protocol where a hardware wallet (HWW) knows some hashes, Merkle tree hashes or Merkleized map commitments, while the client knows the corresponding preimages, leaf values and maps.

### get_preimage

Given a 32-byte hash `el_hash`, the HWW asks the client to provide its preimage.

***Security considerations***:

Once the client responds with a byte string `el`, the hardware wallet must verify that indeed `SHA-256(el) == el_hash`.

### get_merkle_leaf_proof

Given a 32-byte hash `mth` and an index `i`, the HWW asks the client to provide the hash of the leaf with index `i`, together with its Merkle proof in the Merkle tree whose root is `mth`.

***Security considerations***:

The HWW must verify that the proof provided by the client is valid.

### get_merkle_leaf_index

Given a 32-byte hash `leaf_hash` of a leaf and a 32-byte hash `mth`, the HWW asks the client what is the index of the leaf whose hash is `leaf_hash` in the Merkle tree whose root is `mth`.

***Security considerations***:

The HWW cannot trust that the answer is truthful. Therefore, this should only be used as a step in a more complex protocol (for example, once the response is given, the HWW asks and verifies the Merkle proof for that element).

### Get the value corresponding to a key in the map

Once the HWW knows a Merkleized map commitment, a common step in a protocol might be "retrieve the value `v` in the map corresponding to the key `k`". This can be achieved by composing a number of elementary operations on the Merkle trees of keys and values.

#### Validate the tree of keys

The map is valid only if the list of keys is indeed sorted in strict lexicographical order. Therefore, before using a client-provided Merkleized map commitment, the HWW must check that the list of keys is valid. Otherwise, a malicious client might provide different values for the same keys, therefore being able to choose which one to reveal later in the protocol.

Therefore, the HWW should iterate in order over the `n` keys, and retrieve each key (using the protocols for `get_merkle_leaf_proof` and `get_preimage`), while checking that the returned keys are indeed in strict lexicographical order.

*Remark: the protocol described above has communication and computational cost O(n log n). A more efficient protocol with cost O(n) to verify the integrity of the Merkle tree is possible, but it does not rely on the existing primitives and is left as a possible future improvement*.

#### Get the value corresponding to key `k`

Once the integrity of a Merkleized map commitment `(keys_root, values_root)` is verified, the HWW can request the client to provide the value corresponding to a certain key `k` as follows:

1) `i := get_merkle_leaf_index(keys_root, SHA-256(k))`
2) Check that `i` is correct with `get_merkle_leaf_proof(keys_root, i)`
3) Get `v_hash` with `get_merkle_leaf_proof(values_root, i)`
4) Get `v` with `get_preimage(v_hash)`

It is crucial that step 2 is not skipped, or the client might provide the value corresponding to a different key instead.

***Security considerations***:

Unless the HWW keeps track of the fact that a key is present (which is possible during validation if the key is known), the client can always lie by omission (refuse to provide a certain value). Protocols in the HWW must take this possibility into account.

## Future use cases

At this time, all of the Merkle trees are built on top of a static list or map. For future applications, a useful property of the construction chosen is that:
- it is not difficult to compute `MTH(D[n+1])` given the knowledge of the Merkle tree for `D[n]` and the additional element `d(n)`;
- similarly, it is not difficult to compute `MTH(D'[n])` for a list `D'[n]` that is identically equal to `D[n]` except for one element.

This can allow future constructions and protocols where the client is responsible for maintaining dynamic data structures, while guaranteeing integrity with Merkle proofs. One example is the outsourcing of storage/memory on the client side.

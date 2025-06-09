# Purpose
This C source code file is designed to implement a family of functions for handling binary Merkle trees using the SHA-256 hash function. The code is structured to be included multiple times with different configurations, allowing for the creation of Merkle trees with varying widths. The primary functionality revolves around creating, managing, and verifying Merkle trees, which are data structures used to efficiently and securely verify the contents of large data sets. The file provides a set of APIs for hashing leaf nodes, committing to a tree, appending new leaves, finalizing the tree to obtain the root hash, and generating and verifying proofs of inclusion. These operations are crucial for applications that require data integrity and verification, such as blockchain technologies.

The code is modular and can be customized by defining specific macros before including the file, which allows for flexibility in the size of the hash and the naming of the tree structures. It includes both public APIs for interacting with the Merkle tree and internal functions for performing the necessary cryptographic operations. The file also makes use of advanced CPU instructions, such as AVX, to optimize performance for certain operations. The implementation is aligned with the specifications used in the Solana protocol, as indicated by the reference to the Solana Foundation's documentation. Overall, this file serves as a comprehensive toolkit for developers needing to implement Merkle trees in their applications, providing both the core functionality and the flexibility to adapt to different use cases.
# Imports and Dependencies

---
- `fd_bmtree.h`
- `../sha256/fd_sha256.h`
- `../../util/tmpl/fd_smallset.c`
- `x86intrin.h`


# Functions

---
### fd\_bmtree\_hash\_leaf<!-- {{#callable:fd_bmtree_hash_leaf}} -->
The `fd_bmtree_hash_leaf` function computes the SHA-256 hash of a data block prefixed with a specified prefix and stores the result in a binary Merkle tree node.
- **Inputs**:
    - `node`: A pointer to an `fd_bmtree_node_t` structure where the resulting hash will be stored.
    - `data`: A pointer to the data block that will be hashed.
    - `data_sz`: The size of the data block in bytes.
    - `prefix_sz`: The size of the prefix to be used in the hash computation.
- **Control Flow**:
    - Initialize a SHA-256 context using `fd_sha256_init`.
    - Append the prefix to the SHA-256 context using `fd_sha256_append`.
    - Append the data block to the SHA-256 context using `fd_sha256_append`.
    - Finalize the SHA-256 hash computation using `fd_sha256_fini`, storing the result in `node->hash`.
    - Return the `node` pointer.
- **Output**: A pointer to the `fd_bmtree_node_t` structure containing the computed hash.


---
### fd\_bmtree\_private\_merge<!-- {{#callable:fd_bmtree_private_merge}} -->
The `fd_bmtree_private_merge` function computes the SHA-256 hash of a concatenated prefix and two node hashes, storing the result in the provided node.
- **Inputs**:
    - `node`: A pointer to an `fd_bmtree_node_t` structure where the resulting hash will be stored.
    - `a`: A constant pointer to an `fd_bmtree_node_t` structure representing the first node whose hash will be used in the merge.
    - `b`: A constant pointer to an `fd_bmtree_node_t` structure representing the second node whose hash will be used in the merge.
    - `hash_sz`: An unsigned long integer specifying the size of the hash to be used from each node.
    - `prefix_sz`: An unsigned long integer specifying the size of the prefix to be used in the hash computation.
- **Control Flow**:
    - If the system supports AVX instructions, load the prefix and node hashes into AVX registers.
    - Store the loaded data into a memory buffer, aligning it as necessary.
    - Compute the SHA-256 hash of the concatenated data using the `fd_sha256_hash` function and store the result in the `node`.
    - If AVX is not supported, use a series of SHA-256 operations to compute the hash of the concatenated prefix and node hashes, storing the result in `node->hash`.
    - Return the `node` pointer.
- **Output**: A pointer to the `fd_bmtree_node_t` structure where the resulting hash is stored.


---
### fd\_bmtree\_depth<!-- {{#callable:fd_bmtree_depth}} -->
The `fd_bmtree_depth` function calculates the number of layers in a binary Merkle tree given the number of leaf nodes.
- **Inputs**:
    - `leaf_cnt`: The number of leaf nodes in the binary Merkle tree.
- **Control Flow**:
    - The function uses a conditional operation `fd_ulong_if` to determine the output based on the value of `leaf_cnt`.
    - If `leaf_cnt` is less than or equal to 1, the function returns `leaf_cnt` as the depth.
    - If `leaf_cnt` is greater than 1, the function calculates the depth by finding the most significant bit of `leaf_cnt - 1` using `fd_ulong_find_msb_w_default` and adds 2 to it.
- **Output**: The function returns an unsigned long integer representing the number of layers in the binary Merkle tree.


---
### fd\_bmtree\_node\_cnt<!-- {{#callable:fd_bmtree_node_cnt}} -->
The `fd_bmtree_node_cnt` function calculates the total number of nodes in a binary Merkle tree given the number of leaf nodes.
- **Inputs**:
    - `leaf_cnt`: The number of leaf nodes in the binary Merkle tree.
- **Control Flow**:
    - Check if `leaf_cnt` is zero; if so, return zero as there are no nodes.
    - Initialize a counter `cnt` to zero and decrement `leaf_cnt` by one.
    - Iterate over 64 possible layers, right-shifting `leaf_cnt` by the loop index `i` to calculate the number of nodes at each layer and add it to `cnt`.
    - Add a correction factor to `cnt` based on the most significant bit of the original `leaf_cnt` using `fd_ulong_find_msb_w_default`.
    - Return the total node count `cnt`.
- **Output**: The function returns the total number of nodes in the binary Merkle tree, including both leaf and internal nodes, as an unsigned long integer.


---
### fd\_bmtree\_commit\_align<!-- {{#callable:fd_bmtree_commit_align}} -->
The `fd_bmtree_commit_align` function returns the alignment requirement for a memory region to be used as a `bmtree_commit_t`.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a constant function, meaning it does not modify any state and always returns the same value.
    - It directly returns the value of the macro `FD_BMTREE_COMMIT_ALIGN`.
- **Output**: The function outputs an `ulong` representing the alignment requirement for a `bmtree_commit_t`.


---
### fd\_bmtree\_commit\_footprint<!-- {{#callable:fd_bmtree_commit_footprint}} -->
The `fd_bmtree_commit_footprint` function calculates the memory footprint required for a binary Merkle tree commit structure based on the number of layers in the inclusion proof.
- **Inputs**:
    - `inclusion_proof_layer_cnt`: The number of layers in the inclusion proof for the binary Merkle tree.
- **Control Flow**:
    - Calculate the number of nodes in a complete binary tree with the given number of layers using the formula (2^n)-1.
    - Add the size of an extra `fd_bmtree_node_t` to the total size to avoid branches when appending commits.
    - Calculate the size of an array of `ulong` needed for inclusion proofs, which is ((2^n)+63)/64.
    - Sum the sizes of the `fd_bmtree_commit_t`, the nodes, and the `ulong` array.
    - Align the total size to the alignment required by `fd_bmtree_commit_align()`.
- **Output**: The function returns the aligned memory footprint size in bytes as an `ulong`.
- **Functions called**:
    - [`fd_bmtree_commit_align`](#fd_bmtree_commit_align)


---
### fd\_bmtree\_commit\_init<!-- {{#callable:fd_bmtree_commit_init}} -->
The `fd_bmtree_commit_init` function initializes a binary Merkle tree commitment state in a given memory region with specified hash size, prefix size, and inclusion proof layer count.
- **Inputs**:
    - `mem`: A pointer to a memory region that is assumed to be unused and has the required alignment and footprint for a `fd_bmtree_commit_t` structure.
    - `hash_sz`: The size of the hash used in the Merkle tree.
    - `prefix_sz`: The size of the prefix used in the Merkle tree.
    - `inclusion_proof_layer_cnt`: The number of layers in the inclusion proof, which determines the size of the inclusion proof array.
- **Control Flow**:
    - Cast the `mem` pointer to a `fd_bmtree_commit_t` pointer and store it in `state`.
    - Calculate the size of the inclusion proof array as `(1UL << inclusion_proof_layer_cnt) - 1UL` and store it in `inclusion_proof_sz`.
    - Initialize `state->leaf_cnt` to 0, `state->hash_sz` to `hash_sz`, `state->prefix_sz` to `prefix_sz`, and `state->inclusion_proof_sz` to `inclusion_proof_sz`.
    - Set `state->inclusion_proofs_valid` to point to the memory location immediately after the `state->inclusion_proofs` array.
    - Use `fd_memset` to zero out the `state->inclusion_proofs_valid` array, which is sized to accommodate the inclusion proof size divided by `ipfset_MAX`.
    - Return the `state` pointer.
- **Output**: Returns a pointer to the initialized `fd_bmtree_commit_t` structure, which is the same as the input `mem` pointer cast to the appropriate type.


---
### fd\_bmtree\_commit\_append<!-- {{#callable:fd_bmtree_commit_append}} -->
The `fd_bmtree_commit_append` function appends new leaf nodes to a binary Merkle tree, updating the tree's state and inclusion proofs.
- **Inputs**:
    - `state`: A pointer to an `fd_bmtree_commit_t` structure representing the current state of the Merkle tree, assumed to be valid and in a calculation state.
    - `new_leaf`: A pointer to an array of `fd_bmtree_node_t` structures representing the new leaf nodes to be appended, indexed from 0 to `new_leaf_cnt`.
    - `new_leaf_cnt`: An unsigned long integer representing the number of new leaf nodes to append.
- **Control Flow**:
    - Initialize `leaf_cnt` from `state->leaf_cnt` and `node_buf` from `state->node_buf`.
    - Iterate over each new leaf node using a loop from 0 to `new_leaf_cnt`.
    - For each new leaf, copy it into a temporary node `tmp`.
    - Initialize `layer`, `inc_idx`, and `cursor` for tree traversal.
    - While the right node in the last pair is available (i.e., `cursor` is even), update the inclusion proofs and merge nodes to form new branch nodes, moving up one layer each iteration.
    - After exiting the loop, place the left node (or root node) into the buffer and update the inclusion proofs.
    - Update `state->leaf_cnt` with the new `leaf_cnt`.
- **Output**: Returns a pointer to the updated `fd_bmtree_commit_t` state.
- **Functions called**:
    - [`fd_bmtree_private_merge`](#fd_bmtree_private_merge)


---
### fd\_bmtree\_commit\_fini<!-- {{#callable:fd_bmtree_commit_fini}} -->
The `fd_bmtree_commit_fini` function finalizes a binary Merkle tree commitment by computing the root hash from the given state.
- **Inputs**:
    - `state`: A pointer to an `fd_bmtree_commit_t` structure representing the current state of the Merkle tree commitment.
- **Control Flow**:
    - Retrieve the number of leaves (`leaf_cnt`) and the node buffer (`node_buf`) from the state.
    - Calculate the pointer to the root node based on the depth of the tree derived from the number of leaves.
    - Check if the number of leaves is not a power of two, indicating further hashing is required.
    - If further hashing is needed, determine the starting layer where the number of nodes is odd and initialize a temporary node with the first node of this layer.
    - Iteratively ascend the tree, merging nodes until reaching the root, updating the inclusion proofs along the way.
    - Assign the final computed node to the root node if further hashing was performed.
- **Output**: A pointer to the hash of the root node, which is the final result of the Merkle tree commitment.
- **Functions called**:
    - [`fd_bmtree_depth`](#fd_bmtree_depth)
    - [`fd_bmtree_private_merge`](#fd_bmtree_private_merge)


---
### fd\_bmtree\_get\_proof<!-- {{#callable:fd_bmtree_get_proof}} -->
The `fd_bmtree_get_proof` function generates a Merkle proof for a specified leaf index in a binary Merkle tree.
- **Inputs**:
    - `state`: A pointer to an `fd_bmtree_commit_t` structure representing the state of the Merkle tree.
    - `dest`: A pointer to a memory location where the generated Merkle proof will be stored.
    - `leaf_idx`: An unsigned long integer representing the index of the leaf for which the proof is to be generated.
- **Control Flow**:
    - Retrieve the number of leaves (`leaf_cnt`) and hash size (`hash_sz`) from the `state` structure.
    - Check if `leaf_idx` is greater than or equal to `leaf_cnt`; if so, return 0 indicating an invalid index.
    - Initialize `inc_idx` to `leaf_idx * 2`, `layer` to 0, and `layer_cnt` to `leaf_cnt`.
    - Enter a loop that continues while `layer_cnt` is greater than 1.
    - Calculate `sibling_idx` using XOR operation on `inc_idx` and a shifted value based on `layer`.
    - Determine `max_idx_for_layer` using `fd_ulong_insert_lsb` to find the maximum valid index for the current layer.
    - Adjust `sibling_idx` to `inc_idx` if it exceeds `max_idx_for_layer`, indicating a double link.
    - Check if `sibling_idx` is out of bounds of `state->inclusion_proof_sz`; if so, return -1 indicating an error.
    - Copy the hash from `state->inclusion_proofs` at `sibling_idx` to `dest` at the current `layer` offset.
    - Increment `layer`, halve `layer_cnt`, and update `inc_idx` for the next iteration.
    - Return the number of layers processed as the proof depth.
- **Output**: Returns the number of layers in the proof if successful, 0 if the leaf index is invalid, or -1 if an error occurs during proof generation.


---
### fd\_bmtree\_from\_proof<!-- {{#callable:fd_bmtree_from_proof}} -->
The `fd_bmtree_from_proof` function reconstructs the root of a binary Merkle tree from a given leaf node and its proof path.
- **Inputs**:
    - `leaf`: A pointer to the leaf node from which the Merkle tree root is to be reconstructed.
    - `leaf_idx`: The index of the leaf node in the Merkle tree.
    - `root`: A pointer to where the reconstructed root node will be stored.
    - `proof`: A pointer to the proof path, which is an array of hashes needed to reconstruct the root.
    - `proof_depth`: The depth of the proof path, indicating how many layers of the tree are involved in the reconstruction.
    - `hash_sz`: The size of each hash in the proof path.
    - `prefix_sz`: The size of the prefix used in the hash computation.
- **Control Flow**:
    - Initialize a temporary array `tmp` to store nodes during reconstruction, with `tmp[0]` set to the input leaf node.
    - Check if the provided proof depth is sufficient for the given leaf index; return NULL if not.
    - Initialize `inc_idx` to twice the leaf index to track the position in the tree.
    - Iterate over each layer of the proof path up to the proof depth.
    - For each layer, copy the corresponding hash from the proof into `tmp[1]`.
    - Determine the left and right nodes for merging based on the current `inc_idx` and layer.
    - Merge the nodes using [`fd_bmtree_private_merge`](#fd_bmtree_private_merge) to compute the parent node hash.
    - Update `inc_idx` to move up the tree by inserting bits into the least significant positions.
    - After processing all layers, copy the final computed node into the root pointer.
- **Output**: Returns a pointer to the reconstructed root node, or NULL if the proof depth is insufficient.
- **Functions called**:
    - [`fd_bmtree_depth`](#fd_bmtree_depth)
    - [`fd_bmtree_private_merge`](#fd_bmtree_private_merge)


---
### fd\_bmtree\_commitp\_insert\_with\_proof<!-- {{#callable:fd_bmtree_commitp_insert_with_proof}} -->
The function `fd_bmtree_commitp_insert_with_proof` inserts a new leaf into a binary Merkle tree, verifies the proof of inclusion, and optionally updates the root node.
- **Inputs**:
    - `state`: A pointer to the `fd_bmtree_commit_t` structure representing the current state of the Merkle tree.
    - `idx`: An unsigned long integer representing the index at which the new leaf should be inserted.
    - `new_leaf`: A pointer to a `fd_bmtree_node_t` structure representing the new leaf node to be inserted.
    - `proof`: A pointer to a constant unsigned char array containing the proof of inclusion for the new leaf.
    - `proof_depth`: An unsigned long integer representing the depth of the proof.
    - `opt_root`: An optional pointer to a `fd_bmtree_node_t` structure where the root node will be stored if not NULL.
- **Control Flow**:
    - Calculate the initial index for inclusion proof and check if it exceeds the proof size, returning 0 if it does.
    - Verify the proof depth against the inclusion proof size and return 0 if the depth is invalid.
    - Initialize the node buffer with the new leaf and iterate over the proof depth to verify sibling nodes and compute parent nodes.
    - For each layer, check if the sibling node exists and matches the proof; if not, return 0.
    - Compute the parent index and update the node buffer with the merged node from the current and sibling nodes.
    - Continue merging nodes up the tree until reaching the root or an invalid state is detected.
    - Cache the nodes from the main branch and the inclusion proof in the state structure.
    - If `opt_root` is not NULL, store the root node in `opt_root`.
    - Return 1 to indicate successful insertion and proof verification.
- **Output**: Returns an integer, 1 if the insertion and proof verification are successful, or 0 if any verification fails.
- **Functions called**:
    - [`fd_bmtree_private_merge`](#fd_bmtree_private_merge)


---
### fd\_bmtree\_commitp\_fini<!-- {{#callable:fd_bmtree_commitp_fini}} -->
The `fd_bmtree_commitp_fini` function finalizes a binary Merkle tree commitment by computing the root hash from a given number of leaf nodes, ensuring all necessary nodes are present and valid.
- **Inputs**:
    - `state`: A pointer to an `fd_bmtree_commit_t` structure representing the current state of the Merkle tree commitment.
    - `leaf_cnt`: An unsigned long integer representing the number of leaf nodes in the Merkle tree.
- **Control Flow**:
    - Check if `leaf_cnt` is zero; if so, return NULL as no computation is needed.
    - If `leaf_cnt` is not a power of two, further hashing is required to compute the root hash.
    - Determine the starting layer where the number of nodes is odd and calculate the initial index for inclusion proofs.
    - Verify the inclusion proof index is within bounds and that the node exists; if not, return NULL.
    - Ascend the tree, merging nodes to compute branch nodes until reaching the root, checking for sibling nodes as needed.
    - Cache the computed path in the inclusion proofs for future reference.
    - Verify that all necessary nodes up to the root index are present and valid; if any are missing, return NULL.
    - Update the `leaf_cnt` in the state and return the root hash.
- **Output**: Returns a pointer to the root hash of the Merkle tree if successful, or NULL if any validation fails.
- **Functions called**:
    - [`fd_bmtree_private_merge`](#fd_bmtree_private_merge)



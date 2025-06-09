# Purpose
The provided C header file, `fd_bmtree.h`, defines a set of APIs for constructing and manipulating binary Merkle trees using the SHA-256 hash function. This file is part of a larger library and is intended to be included in other C source files to provide functionality related to Merkle trees, which are commonly used in cryptographic applications for data integrity and verification. The header outlines the core operations for constructing Merkle trees, such as creating leaf and branch nodes, and provides methods for generating and verifying inclusion proofs. These proofs are essential for verifying that a particular data element is part of a larger dataset without revealing the entire dataset, a feature widely used in blockchain and distributed ledger technologies.

The file defines several key data structures and functions. The `fd_bmtree_node_t` structure represents a node in the Merkle tree, storing the hash of the node. The `fd_bmtree_commit_t` structure is used to manage the state of a Merkle tree during its construction, supporting both leaf-based and proof-based commitment calculations. Functions such as [`fd_bmtree_hash_leaf`](#fd_bmtree_hash_leaf), [`fd_bmtree_commit_init`](#fd_bmtree_commit_init), [`fd_bmtree_commit_append`](#fd_bmtree_commit_append), and [`fd_bmtree_commit_fini`](#fd_bmtree_commit_fini) provide the necessary operations to build and finalize a Merkle tree, while functions like [`fd_bmtree_get_proof`](#fd_bmtree_get_proof) and [`fd_bmtree_from_proof`](#fd_bmtree_from_proof) handle the creation and verification of inclusion proofs. The header also includes constants and macros to facilitate the alignment and memory footprint calculations required for efficient tree operations. Overall, this file provides a comprehensive interface for working with binary Merkle trees, emphasizing cryptographic security and efficient data handling.
# Imports and Dependencies

---
- `../../util/fd_util_base.h`


# Global Variables

---
### fd\_bmtree\_leaf\_prefix
- **Type**: `uchar const[32UL]`
- **Description**: The `fd_bmtree_leaf_prefix` is a constant array of 32 unsigned characters, aligned to 32 bytes, used as a prefix for leaf nodes in a binary Merkle tree. It is initialized with the string "\x00SOLANA_MERKLE_SHREDS_LEAF", where the first byte is 0x00, followed by the ASCII representation of the string "SOLANA_MERKLE_SHREDS_LEAF". This prefix is used to ensure second preimage resistance in the Merkle tree's hash calculations.
- **Use**: This variable is used as a prefix in the hash calculation of leaf nodes within the Merkle tree to enhance security by preventing second preimage attacks.


---
### fd\_bmtree\_node\_prefix
- **Type**: `uchar const[32UL]`
- **Description**: The `fd_bmtree_node_prefix` is a globally defined constant array of unsigned characters, specifically 32 bytes long, aligned to 32 bytes. It is initialized with a specific byte sequence that starts with a byte value of 0x01 followed by the string 'SOLANA_MERKLE_SHREDS_NODE'. This prefix is used in the context of binary Merkle trees, particularly for nodes in the tree.
- **Use**: This variable is used as a prefix in hashing operations for constructing or verifying nodes within a binary Merkle tree, ensuring consistency and uniqueness in the hashing process.


---
### fd\_bmtree\_hash\_leaf
- **Type**: `function pointer`
- **Description**: `fd_bmtree_hash_leaf` is a function that computes the SHA-256 hash of a given data blob prefixed by a specified number of bytes from a predefined leaf prefix. This function is used to create a leaf node in a binary Merkle tree, which is a fundamental step in constructing the tree.
- **Use**: This function is used to hash data into a leaf node format for inclusion in a binary Merkle tree.


---
### fd\_bmtree\_commit\_init
- **Type**: `fd_bmtree_commit_t *`
- **Description**: The `fd_bmtree_commit_init` is a function that initializes a binary Merkle tree commitment structure. It takes a memory pointer, hash size, prefix size, and inclusion proof layer count as parameters, and returns a pointer to an `fd_bmtree_commit_t` structure. This structure is used to compute the root of a binary Merkle tree incrementally, supporting both leaf-based and proof-based commitment calculations.
- **Use**: This function is used to set up the initial state for a binary Merkle tree commitment calculation, preparing the necessary memory and configuration for subsequent operations.


---
### fd\_bmtree\_commit\_append
- **Type**: `function pointer`
- **Description**: `fd_bmtree_commit_append` is a function that appends a range of new leaf nodes to an existing binary Merkle tree commitment state. It takes a pointer to the current state of the Merkle tree, a pointer to the new leaf nodes, and the count of new leaf nodes to be appended.
- **Use**: This function is used to incrementally build a binary Merkle tree by adding new leaf nodes to the existing tree structure.


---
### fd\_bmtree\_commit\_fini
- **Type**: `function pointer`
- **Description**: The `fd_bmtree_commit_fini` is a function that finalizes the calculation of a binary Merkle tree's root hash. It takes a pointer to a `fd_bmtree_commit_t` structure, which contains the intermediate state of the Merkle tree computation, and returns a pointer to an unsigned character array representing the root hash of the tree.
- **Use**: This function is used to complete the calculation of a Merkle tree's root hash after all leaf nodes have been processed.


---
### fd\_bmtree\_from\_proof
- **Type**: `fd_bmtree_node_t *`
- **Description**: The `fd_bmtree_from_proof` function is a global function that derives the root of a Merkle tree from a given leaf node and its inclusion proof. It takes a leaf node, its index, a buffer for the root, a proof array, the depth of the proof, the size of the hash, and the prefix size as parameters. The function returns a pointer to the root node if the proof is valid, otherwise it returns NULL.
- **Use**: This function is used to verify the inclusion of a leaf node in a Merkle tree by reconstructing the root from the leaf and its proof.


---
### fd\_bmtree\_commitp\_fini
- **Type**: `uchar *`
- **Description**: The `fd_bmtree_commitp_fini` function is a global function that finalizes a proof-based calculation of a binary Merkle tree. It returns a pointer to the root of the tree if the entire tree is verified to be correct for a commitment of a specified number of leaf nodes, otherwise it returns NULL.
- **Use**: This function is used to conclude a proof-based Merkle tree calculation and verify the correctness of the tree structure.


# Data Structures

---
### fd\_bmtree\_node
- **Type**: `struct`
- **Members**:
    - `hash`: An array of 32 unsigned characters representing the hash of the node, where the last bytes may not be meaningful.
- **Description**: The `fd_bmtree_node` structure is a packed data structure used to represent a node in a binary Merkle tree, specifically designed to store the hash value of the node. The hash is typically a SHA-256 hash, which is 32 bytes long, making the structure AVX-friendly and allowing for efficient hash operations. This structure is fundamental in the construction and manipulation of binary Merkle trees, which are used for secure data verification and integrity checks.


---
### fd\_bmtree\_node\_t
- **Type**: `struct`
- **Members**:
    - `hash`: An array of 32 unsigned characters representing the hash of a tree node.
- **Description**: The `fd_bmtree_node_t` structure represents a node in a binary Merkle tree, specifically storing the hash value of the node. This hash is typically generated using the SHA-256 algorithm, and the structure is designed to be AVX-friendly, allowing for efficient processing and storage of hash values. The structure is packed to ensure that the hash data is stored contiguously in memory, which is crucial for performance in cryptographic operations.


---
### fd\_bmtree\_commit\_private
- **Type**: `struct`
- **Members**:
    - `leaf_cnt`: Number of leaves added so far.
    - `hash_sz`: Size of the hash, up to 32 bytes.
    - `prefix_sz`: Size of the prefix, up to 26 bytes.
    - `inclusion_proof_sz`: Size of the inclusion proof.
    - `node_buf`: Buffer for nodes, indexed by layer, with 0 being the leaf layer.
    - `inclusion_proofs_valid`: Pointer to a dense bit set used in proof-based commits.
    - `inclusion_proofs`: Array storing hashes of internal nodes for inclusion proofs.
- **Description**: The `fd_bmtree_commit_private` structure is used to manage the internal state of a binary Merkle tree during its construction and verification processes. It tracks the number of leaf nodes added (`leaf_cnt`), manages node data across different layers (`node_buf`), and handles inclusion proofs for verifying node inclusion in the tree (`inclusion_proofs`). The structure supports both leaf-based and proof-based commitment calculations, allowing for efficient computation and verification of the tree's root hash. The `hash_sz` and `prefix_sz` fields define the size constraints for hashing operations, while `inclusion_proofs_valid` is used to manage proof validity in proof-based calculations.


---
### fd\_bmtree\_commit\_t
- **Type**: `struct`
- **Members**:
    - `leaf_cnt`: Stores the number of leaf nodes added so far.
    - `hash_sz`: Indicates the size of the hash, up to 32 bytes.
    - `prefix_sz`: Specifies the size of the prefix, up to 26 bytes.
    - `inclusion_proof_sz`: Holds the size of the inclusion proof.
    - `node_buf`: An array of nodes used to buffer branch nodes during tree construction.
    - `inclusion_proofs_valid`: A dense bit set indicating valid inclusion proofs.
    - `inclusion_proofs`: Stores hashes of internal nodes for inclusion proofs.
- **Description**: The `fd_bmtree_commit_t` structure is designed to manage the intermediate state during the incremental computation of a binary Merkle tree's root. It supports two types of commitment calculations: leaf-based and proof-based, but only one at a time. The structure efficiently handles the accumulation of leaf nodes and the buffering of branch nodes, ultimately deriving the root hash in the finalization phase. It is optimized for trees with non-power-of-two leaf counts, ensuring that branch nodes with single children are correctly managed. The structure is capable of handling trees with up to 2^63 leaves, although practical usage is limited by time constraints. It also supports inclusion proofs, which are stored separately to maintain efficient cache utilization.


# Functions

---
### fd\_bmtree\_commit\_leaf\_cnt<!-- {{#callable:fd_bmtree_commit_leaf_cnt}} -->
The `fd_bmtree_commit_leaf_cnt` function returns the number of leaf nodes that have been appended to a binary Merkle tree commitment so far.
- **Inputs**:
    - `bmt`: A pointer to a constant `fd_bmtree_commit_t` structure representing the current state of a binary Merkle tree commitment.
- **Control Flow**:
    - The function accesses the `leaf_cnt` member of the `fd_bmtree_commit_t` structure pointed to by `bmt`.
    - It returns the value of `leaf_cnt`, which indicates the number of leaf nodes appended to the tree.
- **Output**: The function returns an `ulong` representing the number of leaf nodes appended to the binary Merkle tree commitment.


# Function Declarations (Public API)

---
### fd\_bmtree\_hash\_leaf<!-- {{#callable_declaration:fd_bmtree_hash_leaf}} -->
Compute the SHA-256 hash of a data blob with a specified prefix.
- **Description**: This function computes the SHA-256 hash of a given data blob, prefixed by a specified number of bytes from a predefined prefix. It is typically used as the first step in creating a Merkle tree, where each leaf node is derived from hashing a data blob with a prefix. The function requires a valid node structure to store the resulting hash and expects the data and node memory regions not to overlap. The prefix size should be either FD_BMTREE_LONG_PREFIX_SZ or FD_BMTREE_SHORT_PREFIX_SZ.
- **Inputs**:
    - `node`: A pointer to an fd_bmtree_node_t structure where the resulting hash will be stored. Must not overlap with the data memory region.
    - `data`: A pointer to the data blob to be hashed. The caller retains ownership and it must not overlap with the node memory region.
    - `data_sz`: The size in bytes of the data blob to be hashed. Must be a valid size for the data provided.
    - `prefix_sz`: The number of bytes from the fd_bmtree_leaf_prefix to prepend to the data before hashing. Typically FD_BMTREE_LONG_PREFIX_SZ or FD_BMTREE_SHORT_PREFIX_SZ.
- **Output**: Returns a pointer to the node structure containing the computed hash.
- **See also**: [`fd_bmtree_hash_leaf`](fd_bmtree.c.driver.md#fd_bmtree_hash_leaf)  (Implementation)


---
### fd\_bmtree\_commit\_align<!-- {{#callable_declaration:fd_bmtree_commit_align}} -->
Return the alignment requirement for a binary Merkle tree commitment structure.
- **Description**: This function provides the alignment requirement for memory regions used to store a `fd_bmtree_commit_t` structure. It is essential to ensure that any memory allocated for a binary Merkle tree commitment is aligned according to this requirement to avoid undefined behavior. This function should be called before allocating memory for a Merkle tree commitment to determine the correct alignment.
- **Inputs**: None
- **Output**: Returns the alignment requirement in bytes for a `fd_bmtree_commit_t` structure.
- **See also**: [`fd_bmtree_commit_align`](fd_bmtree.c.driver.md#fd_bmtree_commit_align)  (Implementation)


---
### fd\_bmtree\_commit\_footprint<!-- {{#callable_declaration:fd_bmtree_commit_footprint}} -->
Calculate the memory footprint required for a binary Merkle tree commitment.
- **Description**: This function calculates the memory footprint needed for a binary Merkle tree commitment structure, given a specified number of inclusion proof layers. It is useful when setting up memory allocations for Merkle tree operations, ensuring that enough space is reserved to accommodate the tree's nodes and inclusion proofs. The function should be called before initializing a Merkle tree commitment to determine the appropriate memory size. The number of layers specified should not exceed the expected maximum layers of the tree to ensure all inclusion proofs can be retrieved.
- **Inputs**:
    - `inclusion_proof_layer_cnt`: Specifies the number of layers for which inclusion proofs should be stored. It must be a non-negative integer, and the function assumes this value is within a reasonable range for the application. Invalid values may lead to incorrect memory size calculations.
- **Output**: Returns the size in bytes of the memory footprint required for the Merkle tree commitment structure.
- **See also**: [`fd_bmtree_commit_footprint`](fd_bmtree.c.driver.md#fd_bmtree_commit_footprint)  (Implementation)


---
### fd\_bmtree\_commit\_init<!-- {{#callable_declaration:fd_bmtree_commit_init}} -->
Initializes a binary Merkle tree commitment state.
- **Description**: This function initializes a memory region to be used as a binary Merkle tree commitment state, setting up the necessary parameters for hash size, prefix size, and inclusion proof layers. It should be called before any commitment calculations are performed, ensuring that the memory provided is unused and meets the required alignment and footprint. The function prepares the state for either leaf-based or proof-based commitment calculations, depending on the subsequent operations. Inclusion proofs can be generated if the tree does not exceed the specified number of layers.
- **Inputs**:
    - `mem`: A pointer to a memory region that is assumed to be unused and must have the required alignment and footprint for a fd_bmtree_commit_t structure. The caller retains ownership.
    - `hash_sz`: The size of the hash in bytes, which must be less than or equal to 32.
    - `prefix_sz`: The size of the prefix in bytes, typically FD_BMTREE_LONG_PREFIX_SZ or FD_BMTREE_SHORT_PREFIX_SZ, and must not exceed FD_BMTREE_LONG_PREFIX_SZ.
    - `inclusion_proof_layer_cnt`: The number of layers for which inclusion proofs can be generated. If the tree grows beyond this number of layers, inclusion proofs may not be available.
- **Output**: Returns a pointer to the initialized fd_bmtree_commit_t structure, ready for commitment calculations.
- **See also**: [`fd_bmtree_commit_init`](fd_bmtree.c.driver.md#fd_bmtree_commit_init)  (Implementation)


---
### fd\_bmtree\_depth<!-- {{#callable_declaration:fd_bmtree_depth}} -->
Calculates the depth of a binary Merkle tree given the number of leaf nodes.
- **Description**: Use this function to determine the number of layers in a binary Merkle tree, including both the leaf and root layers, based on the specified number of leaf nodes. This is useful for understanding the structure and height of the tree when planning operations such as inclusion proofs or tree traversal. The function handles edge cases where the number of leaves is zero or one, returning the appropriate depth for these scenarios.
- **Inputs**:
    - `leaf_cnt`: The number of leaf nodes in the binary Merkle tree. It must be a non-negative integer within the range [0, ULONG_MAX]. The function will return a depth of 0 for 0 leaves and 1 for 1 leaf, while larger numbers will result in a calculated depth based on the binary tree structure.
- **Output**: The function returns an unsigned long integer representing the depth of the binary Merkle tree, which includes both the leaf and root layers.
- **See also**: [`fd_bmtree_depth`](fd_bmtree.c.driver.md#fd_bmtree_depth)  (Implementation)


---
### fd\_bmtree\_node\_cnt<!-- {{#callable_declaration:fd_bmtree_node_cnt}} -->
Calculate the total number of nodes in a binary Merkle tree given the number of leaf nodes.
- **Description**: This function is used to determine the total number of nodes in a binary Merkle tree when the number of leaf nodes is known. It is useful in scenarios where you need to allocate resources or understand the structure of the tree based on its leaf count. The function expects a non-negative number of leaf nodes and returns zero if the leaf count is zero, indicating an empty tree. It is a constant function, meaning it does not modify any state and is safe to call multiple times with the same input.
- **Inputs**:
    - `leaf_cnt`: The number of leaf nodes in the binary Merkle tree. It must be a non-negative integer within the range [0, ULONG_MAX]. If the value is zero, the function returns zero, indicating an empty tree.
- **Output**: The function returns an unsigned long integer representing the total number of nodes in the binary Merkle tree, including both leaf and internal nodes.
- **See also**: [`fd_bmtree_node_cnt`](fd_bmtree.c.driver.md#fd_bmtree_node_cnt)  (Implementation)


---
### fd\_bmtree\_commit\_append<!-- {{#callable_declaration:fd_bmtree_commit_append}} -->
Appends a range of new leaf nodes to the binary Merkle tree state.
- **Description**: Use this function to add a sequence of new leaf nodes to an existing binary Merkle tree commitment state. This function should be called when you have a set of new leaf nodes that need to be incorporated into the tree. The state must be valid and in a leaf-based calculation mode before calling this function. The function updates the state with the new leaf nodes and maintains the necessary internal structures to ensure the tree's integrity. It is assumed that the total number of leaves, including the new ones, is significantly less than 2^63, which is practically always true.
- **Inputs**:
    - `state`: A pointer to a valid fd_bmtree_commit_t structure that is currently in a leaf-based calculation. The caller retains ownership and must ensure it is not null.
    - `new_leaf`: A pointer to an array of fd_bmtree_node_t structures representing the new leaf nodes to be appended. The array is indexed from 0 to new_leaf_cnt-1. The caller retains ownership and must ensure it is not null.
    - `new_leaf_cnt`: The number of new leaf nodes to append, represented as an unsigned long. It must be a non-negative value.
- **Output**: Returns a pointer to the updated fd_bmtree_commit_t state, allowing for further operations or inspection.
- **See also**: [`fd_bmtree_commit_append`](fd_bmtree.c.driver.md#fd_bmtree_commit_append)  (Implementation)


---
### fd\_bmtree\_commit\_fini<!-- {{#callable_declaration:fd_bmtree_commit_fini}} -->
Finalizes a binary Merkle tree commitment and returns the root hash.
- **Description**: Use this function to complete the calculation of a binary Merkle tree's root hash after all leaf nodes have been appended. It should be called when the tree is in a leaf-based calculation state and contains at least one leaf. The function finalizes the commitment by deriving the root node, and the returned pointer to the root hash remains valid as long as the state is not reinitialized for a new calculation. This function is essential for obtaining the final commitment of the tree.
- **Inputs**:
    - `state`: A pointer to a valid fd_bmtree_commit_t structure that is in a leaf-based calculation state. It must have at least one leaf node appended. The caller retains ownership, and the state must not be null.
- **Output**: Returns a pointer to the root hash of the Merkle tree, which is a memory region of size BMTREE_HASH_SZ. The pointer remains valid until the state is reinitialized for a new calculation.
- **See also**: [`fd_bmtree_commit_fini`](fd_bmtree.c.driver.md#fd_bmtree_commit_fini)  (Implementation)


---
### fd\_bmtree\_get\_proof<!-- {{#callable_declaration:fd_bmtree_get_proof}} -->
Writes an inclusion proof for a specified leaf to a destination buffer.
- **Description**: Use this function to obtain an inclusion proof for a specific leaf in a binary Merkle tree. The function requires a valid, sealed `fd_bmtree_commit_t` state that has been initialized with sufficient inclusion proof layers to cover the tree's height. The inclusion proof is written to the provided destination buffer, excluding the root hash, and the function returns the number of hashes written. If the state was initialized with insufficient inclusion proof layers, the function returns -1 and does not modify the destination buffer.
- **Inputs**:
    - `state`: A pointer to a valid, sealed `fd_bmtree_commit_t` structure representing the Merkle tree. It must have been initialized with enough inclusion proof layers to cover the tree's height.
    - `dest`: A pointer to a memory buffer where the inclusion proof will be written. The buffer must be large enough to hold the proof, which is up to `hash_sz * (tree depth - 1)` bytes.
    - `leaf_idx`: The index of the leaf for which the inclusion proof is requested. It must be less than the number of leaves in the tree.
- **Output**: Returns the number of hashes written to `dest` if successful, or -1 if the inclusion proof layers were insufficient. The `dest` buffer is not modified if the function returns -1.
- **See also**: [`fd_bmtree_get_proof`](fd_bmtree.c.driver.md#fd_bmtree_get_proof)  (Implementation)


---
### fd\_bmtree\_from\_proof<!-- {{#callable_declaration:fd_bmtree_from_proof}} -->
Derives the root of a Merkle tree from a leaf node and its inclusion proof.
- **Description**: This function is used to compute the root hash of a Merkle tree given a specific leaf node, its index, and an inclusion proof. It is useful for verifying that a particular leaf is part of a Merkle tree with a known root. The function requires the leaf node, its index, a buffer for the root, the inclusion proof, and parameters specifying the proof depth, hash size, and prefix size. The inclusion proof must be valid and of sufficient depth to correspond to the specified leaf index. If the proof is valid, the root hash is stored in the provided root buffer; otherwise, the function returns NULL, indicating an invalid proof.
- **Inputs**:
    - `leaf`: A pointer to the leaf node for which the root is being derived. Must not be null.
    - `leaf_idx`: The index of the leaf node in the Merkle tree. Must be in the range [0, ULONG_MAX).
    - `root`: A pointer to a buffer where the computed root hash will be stored. Must not be null.
    - `proof`: A pointer to the inclusion proof, which is a sequence of hashes. Must not be null and should be ordered from leaf to root, excluding the root.
    - `proof_depth`: The depth of the inclusion proof, indicating the number of hashes in the proof. Must be in the range [0, 63].
    - `hash_sz`: The size of each hash in the proof, in bytes. Must be in the range [1, 32].
    - `prefix_sz`: The size of the prefix used for hash calculations, typically either FD_BMTREE_LONG_PREFIX_SZ or FD_BMTREE_SHORT_PREFIX_SZ.
- **Output**: Returns a pointer to the root if the proof is valid, or NULL if the proof is invalid. The root buffer is updated with the root hash if the proof is valid.
- **See also**: [`fd_bmtree_from_proof`](fd_bmtree.c.driver.md#fd_bmtree_from_proof)  (Implementation)


---
### fd\_bmtree\_commitp\_insert\_with\_proof<!-- {{#callable_declaration:fd_bmtree_commitp_insert_with_proof}} -->
Inserts a leaf node into a proof-based Merkle tree calculation with optional proof verification.
- **Description**: This function is used to insert a new leaf node at a specified index in a proof-based Merkle tree calculation. It optionally verifies the provided proof against the current state of the tree. The function should be called when you want to add a leaf node and potentially validate its inclusion proof in an ongoing proof-based commitment calculation. The function requires that the depth of the tree at the specified index does not exceed the inclusion proof layer count specified during initialization. If the function returns success and an optional root pointer is provided, it will store the highest known node in the branch containing the index. If the function fails, the state remains unchanged.
- **Inputs**:
    - `state`: A pointer to a valid fd_bmtree_commit_t structure representing the current state of the proof-based Merkle tree calculation. The caller retains ownership and must ensure it is properly initialized.
    - `idx`: The index at which to insert the new leaf node. It must be within the bounds of the tree as determined by the inclusion proof layer count.
    - `new_leaf`: A pointer to the new leaf node to be inserted. The caller retains ownership and must ensure it is not null.
    - `proof`: A pointer to the proof data, which is an array of hashes ordered from leaf to root, excluding the root. It can be null if proof_depth is zero.
    - `proof_depth`: The depth of the proof, indicating how many hashes are included in the proof. It must be less than the inclusion proof layer count and can be zero.
    - `opt_root`: An optional pointer to a fd_bmtree_node_t where the highest known node in the branch will be stored if the function succeeds. It can be null if the caller does not need this information.
- **Output**: Returns 1 if the leaf and proof are consistent with the current state, or 0 if not. If successful and opt_root is provided, it will be updated with the highest known node in the branch.
- **See also**: [`fd_bmtree_commitp_insert_with_proof`](fd_bmtree.c.driver.md#fd_bmtree_commitp_insert_with_proof)  (Implementation)


---
### fd\_bmtree\_commitp\_fini<!-- {{#callable_declaration:fd_bmtree_commitp_fini}} -->
Finalize a proof-based Merkle tree calculation and return the root hash.
- **Description**: Use this function to complete a proof-based Merkle tree calculation and obtain the root hash, provided the tree is consistent with the given number of leaf nodes. It should be called after all necessary leaf nodes and proofs have been inserted using the appropriate functions. The function will return NULL if the tree cannot be conclusively determined to be correct, such as when the number of leaf nodes is zero or if the internal consistency checks fail.
- **Inputs**:
    - `state`: A pointer to a valid fd_bmtree_commit_t structure that has been initialized for a proof-based calculation. The caller retains ownership and must ensure it is not null.
    - `leaf_cnt`: The number of leaf nodes expected in the tree. Must be greater than zero. If the count is not a power of two, additional internal processing will be performed to complete the tree.
- **Output**: Returns a pointer to the root hash of the tree if the calculation is successful and the tree is consistent with the specified number of leaf nodes. Returns NULL if the tree cannot be conclusively determined to be correct.
- **See also**: [`fd_bmtree_commitp_fini`](fd_bmtree.c.driver.md#fd_bmtree_commitp_fini)  (Implementation)



# Purpose
This C header file defines an optimized implementation of a binary Merkle tree using the SHA-256 hash function, specifically designed to enhance performance at the cost of increased memory usage. It introduces data structures such as `fd_wbmtree32_leaf_t` and `fd_wbmtree32_node_t` to represent leaves and nodes of the tree, respectively, and a main structure `fd_wbmtree32_t` that includes a SHA-256 batch object for processing. The file also declares several functions for managing the Merkle tree, including initialization ([`fd_wbmtree32_init`](#fd_wbmtree32_init)), appending leaves ([`fd_wbmtree32_append`](#fd_wbmtree32_append)), and finalizing the tree ([`fd_wbmtree32_fini`](#fd_wbmtree32_fini)). The implementation leverages streaming SHA-256 APIs to achieve its performance goals, and it ensures proper memory alignment for efficient processing.
# Imports and Dependencies

---
- `../sha256/fd_sha256.h`


# Global Variables

---
### fd\_wbmtree32\_init
- **Type**: `function pointer`
- **Description**: The `fd_wbmtree32_init` is a function that initializes a binary Merkle tree structure (`fd_wbmtree32_t`) using a specified memory region and a maximum number of leaves (`leaf_cnt`). It returns a pointer to the initialized `fd_wbmtree32_t` structure.
- **Use**: This function is used to set up a binary Merkle tree for further operations, such as appending leaves or finalizing the tree.


---
### fd\_wbmtree32\_fini
- **Type**: `function pointer`
- **Description**: The `fd_wbmtree32_fini` is a function pointer that takes a pointer to a `fd_wbmtree32_t` structure as its argument and returns a pointer to an unsigned character array (`uchar *`). This function is likely used to finalize or clean up the binary Merkle tree structure, possibly returning a hash or some final data representation of the tree.
- **Use**: This function is used to finalize the operations on a `fd_wbmtree32_t` structure, potentially returning a final hash or data representation.


# Data Structures

---
### fd\_wbmtree32\_leaf
- **Type**: `struct`
- **Members**:
    - `data`: A pointer to an array of unsigned characters representing the data contained in the leaf.
    - `data_len`: An unsigned long integer representing the length of the data in the leaf.
- **Description**: The `fd_wbmtree32_leaf` structure represents a leaf node in a binary Merkle tree optimized for performance using the SHA-256 hash function. It contains a pointer to the data and the length of the data, allowing it to store and manage the data associated with a leaf in the tree.


---
### fd\_wbmtree32\_leaf\_t
- **Type**: `struct`
- **Members**:
    - `data`: A pointer to an unsigned char array representing the data of the leaf.
    - `data_len`: An unsigned long representing the length of the data in the leaf.
- **Description**: The `fd_wbmtree32_leaf_t` structure represents a leaf in a binary Merkle tree optimized for performance using the SHA-256 hash function. It contains a pointer to the data and the length of the data, allowing it to store and manage the data associated with a leaf node in the tree.


---
### fd\_wbmtree32\_node
- **Type**: `struct`
- **Members**:
    - `hash`: An array of 33 unsigned characters representing the hash value of the node.
- **Description**: The `fd_wbmtree32_node` structure is a component of a binary Merkle tree implementation optimized for performance using the SHA-256 hash function. It contains a single member, `hash`, which stores a 33-byte hash value, likely used to represent the hash of a node in the Merkle tree. This structure is part of a larger system that balances performance and memory usage, specifically designed to work with streaming SHA-256 APIs.


---
### fd\_wbmtree32\_node\_t
- **Type**: `struct`
- **Members**:
    - `hash`: An array of 33 unsigned characters representing the hash value of the node.
- **Description**: The `fd_wbmtree32_node_t` structure represents a node in a binary Merkle tree optimized for performance using the SHA-256 hash function. Each node contains a hash value, which is stored as an array of 33 unsigned characters, likely to accommodate a 256-bit hash with an additional byte for other purposes such as null-termination or metadata.


---
### fd\_wbmtree32
- **Type**: `struct`
- **Members**:
    - `sha256_batch`: A batch of SHA-256 hash computations used for processing the tree nodes.
    - `leaf_cnt_max`: The maximum number of leaves that the tree can accommodate.
    - `leaf_cnt`: The current number of leaves in the tree.
    - `data`: An array of nodes representing the data in the tree, each containing a hash.
- **Description**: The `fd_wbmtree32` structure represents a binary Merkle tree optimized for performance using the SHA-256 hash function. It is aligned to 128 bytes to match the alignment of the `fd_sha256_batch` object, ensuring efficient memory access. The structure includes a batch of SHA-256 computations, a maximum leaf count, a current leaf count, and an array of nodes, each storing a hash. This design allows for efficient streaming and processing of data in a Merkle tree format, balancing performance with memory usage.


---
### fd\_wbmtree32\_t
- **Type**: `struct`
- **Members**:
    - `sha256_batch`: An instance of fd_sha256_batch_t used for SHA-256 hashing operations.
    - `leaf_cnt_max`: The maximum number of leaves that the tree can accommodate.
    - `leaf_cnt`: The current number of leaves in the tree.
    - `data`: An array of fd_wbmtree32_node_t structures representing the nodes of the tree.
- **Description**: The `fd_wbmtree32_t` structure represents a binary Merkle tree optimized for performance using the SHA-256 hash function. It is aligned to 128 bytes and includes a SHA-256 batch object for hashing, a maximum leaf count, a current leaf count, and an array of nodes. This structure is designed to efficiently handle streaming data for cryptographic operations, trading off memory usage for speed.


# Function Declarations (Public API)

---
### fd\_wbmtree32\_align<!-- {{#callable_declaration:fd_wbmtree32_align}} -->
Retrieve the alignment requirement for the fd_wbmtree32_t structure.
- **Description**: Use this function to obtain the alignment requirement for the fd_wbmtree32_t structure, which is necessary when allocating memory for instances of this structure. This function is useful to ensure that memory allocations are correctly aligned, which is critical for performance and correctness on many architectures. It should be called whenever you need to allocate or manage memory for fd_wbmtree32_t structures to ensure proper alignment.
- **Inputs**: None
- **Output**: Returns the alignment requirement in bytes for the fd_wbmtree32_t structure.
- **See also**: [`fd_wbmtree32_align`](fd_wbmtree.c.driver.md#fd_wbmtree32_align)  (Implementation)


---
### fd\_wbmtree32\_footprint<!-- {{#callable_declaration:fd_wbmtree32_footprint}} -->
Calculate the memory footprint required for a binary Merkle tree with a specified number of leaves.
- **Description**: Use this function to determine the amount of memory needed to store a binary Merkle tree that can accommodate a given number of leaves. This is useful for allocating memory before initializing the tree. The function rounds up the number of leaves to the nearest even number to ensure proper tree structure, which may affect the calculated footprint.
- **Inputs**:
    - `leaf_cnt`: The number of leaves for which the memory footprint is to be calculated. It must be a non-negative integer. The function will round up to the nearest even number if an odd number is provided.
- **Output**: Returns the size in bytes of the memory footprint required for the binary Merkle tree with the specified number of leaves.
- **See also**: [`fd_wbmtree32_footprint`](fd_wbmtree.c.driver.md#fd_wbmtree32_footprint)  (Implementation)


---
### fd\_wbmtree32\_init<!-- {{#callable_declaration:fd_wbmtree32_init}} -->
Initialize a binary Merkle tree structure in the provided memory.
- **Description**: This function initializes a binary Merkle tree structure using the SHA-256 hash function in the memory provided by the caller. It should be called when you need to set up a new Merkle tree with a specified maximum number of leaves. The memory provided must be aligned according to the alignment requirements of the fd_wbmtree32 structure, and its size must be sufficient to accommodate the tree structure for the given number of leaves. The function will zero out the memory and prepare the structure for use, setting the initial leaf count to zero. It is important to ensure that the memory is correctly aligned and non-null before calling this function, as misalignment or null memory will result in a warning and a null return.
- **Inputs**:
    - `mem`: A pointer to the memory where the Merkle tree structure will be initialized. This memory must be aligned to the alignment requirements of fd_wbmtree32 and must not be null. If the memory is null or misaligned, the function will log a warning and return null.
    - `leaf_cnt`: The maximum number of leaves the Merkle tree can accommodate. This value determines the size of the memory footprint required for the tree structure.
- **Output**: Returns a pointer to the initialized fd_wbmtree32 structure on success, or null if the memory is null or misaligned.
- **See also**: [`fd_wbmtree32_init`](fd_wbmtree.c.driver.md#fd_wbmtree32_init)  (Implementation)


---
### fd\_wbmtree32\_append<!-- {{#callable_declaration:fd_wbmtree32_append}} -->
Appends leaves to a binary Merkle tree and updates its state.
- **Description**: This function appends a specified number of leaves to an existing binary Merkle tree structure, updating the tree's state with the new leaves. It should be used when you need to add more data to a Merkle tree that has been initialized and has not yet reached its maximum leaf capacity. The function requires a buffer for intermediate data processing, and it is crucial that the total number of leaves after appending does not exceed the tree's maximum capacity. The function assumes that the Merkle tree has been properly initialized and that the buffer provided is large enough to handle the appended data.
- **Inputs**:
    - `bmt`: A pointer to an initialized fd_wbmtree32_t structure representing the binary Merkle tree. The tree must not have reached its maximum leaf capacity.
    - `leaf`: A pointer to an array of fd_wbmtree32_leaf_t structures representing the leaves to be appended. Each leaf contains data and its length.
    - `leaf_cnt`: The number of leaves to append. Must be a positive number such that the total leaf count does not exceed the tree's maximum capacity.
    - `mbuf`: A pointer to a buffer used for intermediate data processing. The buffer must be large enough to accommodate the data being appended.
- **Output**: None
- **See also**: [`fd_wbmtree32_append`](fd_wbmtree.c.driver.md#fd_wbmtree32_append)  (Implementation)


---
### fd\_wbmtree32\_fini<!-- {{#callable_declaration:fd_wbmtree32_fini}} -->
Finalize the Merkle tree and return the root hash.
- **Description**: Use this function to complete the construction of a binary Merkle tree based on the SHA-256 hash function and retrieve the root hash. It should be called after all leaves have been appended to the tree using `fd_wbmtree32_append`. The function assumes that the number of leaves does not exceed the maximum specified during initialization. It processes the tree to compute the root hash, which is returned as a pointer to the hash value. The function modifies the internal state of the tree, making it unusable for further appends without reinitialization.
- **Inputs**:
    - `bmt`: A pointer to an initialized `fd_wbmtree32_t` structure representing the Merkle tree. The structure must have been initialized with `fd_wbmtree32_init` and populated with leaves using `fd_wbmtree32_append`. The `leaf_cnt` must not exceed `leaf_cnt_max`. The caller retains ownership and must ensure the pointer is not null.
- **Output**: Returns a pointer to the root hash of the Merkle tree. The hash is 32 bytes long and is located within the `fd_wbmtree32_t` structure.
- **See also**: [`fd_wbmtree32_fini`](fd_wbmtree.c.driver.md#fd_wbmtree32_fini)  (Implementation)



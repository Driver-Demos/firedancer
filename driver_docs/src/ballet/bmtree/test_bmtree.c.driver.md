# Purpose
This C source code file is a comprehensive test suite for verifying the functionality of a binary Merkle tree (bmtree) implementation. The code is structured to test various aspects of Merkle tree operations, including tree construction, leaf insertion, proof generation, and root verification. It includes functions to test the construction of 20-byte and 32-byte trees, validate inclusion proofs, and benchmark the performance of tree operations. The file imports binary reference proofs and uses them to verify the correctness of the generated proofs against expected results. The main function orchestrates these tests, ensuring that the tree operations conform to expected behaviors and performance metrics.

The code is designed to be executed as a standalone program, as indicated by the presence of a [`main`](#main) function. It does not define public APIs or external interfaces but rather focuses on internal validation of the Merkle tree implementation. The tests cover a range of scenarios, including different tree sizes and configurations, and utilize various helper functions to facilitate the testing process. The file also includes logging and error-checking mechanisms to provide detailed feedback on test outcomes, ensuring that any discrepancies are promptly identified and reported.
# Imports and Dependencies

---
- `../fd_ballet.h`


# Global Variables

---
### memory
- **Type**: `uchar array`
- **Description**: The `memory` variable is a global array of unsigned characters (uchar) with a size defined by the constant `MEMORY_SZ`, which is set to 70 megabytes. It is aligned according to the `FD_BMTREE_COMMIT_ALIGN` attribute, ensuring that the memory address of the array is aligned to a specific boundary required for efficient access or processing.
- **Use**: This variable is used as a memory buffer for operations related to the construction and management of binary Merkle trees in the code.


---
### inc\_proof
- **Type**: `uchar array`
- **Description**: The `inc_proof` variable is a global array of unsigned characters with a size of 63*32 bytes. It is used to store inclusion proofs for a Merkle tree, which are used to verify the presence of a leaf node in the tree without needing to traverse the entire structure.
- **Use**: This variable is used in the `test_inclusion` function to store and manipulate inclusion proofs for verifying Merkle tree operations.


# Functions

---
### test\_bmtree20\_commit<!-- {{#callable:test_bmtree20_commit}} -->
The `test_bmtree20_commit` function tests the construction and finalization of a 20-byte Merkle tree with a specified number of leaves and verifies the computed root against an expected root value.
- **Inputs**:
    - `leaf_cnt`: The number of leaves to be added to the Merkle tree.
    - `expected_root`: A pointer to the expected root hash value for the Merkle tree, used for verification.
- **Control Flow**:
    - Initialize a Merkle tree with a depth of 20, a single leaf per node, and no additional options.
    - Set up a leaf node with a hash initialized to zero.
    - Iterate over the number of leaves specified by `leaf_cnt`, appending each leaf to the tree and verifying the leaf count after each append operation.
    - Finalize the Merkle tree to compute the root hash and verify that the leaf count remains consistent.
    - Compare the computed root hash with the expected root hash; if they do not match, log an error message with the details.
- **Output**: The function does not return a value but logs an error if the computed root does not match the expected root.


---
### test\_bmtree20\_commitp<!-- {{#callable:test_bmtree20_commitp}} -->
The `test_bmtree20_commitp` function tests the construction and verification of a 20-byte Merkle tree by inserting leaves in a specific order and comparing the computed root with an expected root.
- **Inputs**:
    - `leaf_cnt`: The number of leaves to be inserted into the Merkle tree.
    - `expected_root`: A pointer to the expected root hash of the Merkle tree, used for verification.
- **Control Flow**:
    - Check if the memory footprint for the tree is within the allowed size using `fd_bmtree_commit_footprint` and `fd_bmtree_depth` functions.
    - Initialize a Merkle tree with `fd_bmtree_commit_init` using the provided memory, depth, and other parameters.
    - Log the number of leaves (`leaf_cnt`) being processed.
    - Initialize a leaf node with a hash of zeroes.
    - Iterate over even indices up to `leaf_cnt`, setting the leaf hash to the index value and inserting it into the tree with `fd_bmtree_commitp_insert_with_proof`.
    - Iterate over odd indices up to `leaf_cnt`, setting the leaf hash to the index value and inserting it into the tree with `fd_bmtree_commitp_insert_with_proof`.
    - Finalize the tree with `fd_bmtree_commitp_fini` to compute the root hash.
    - Verify that the computed root hash matches the `expected_root` using `fd_memeq`.
- **Output**: The function does not return a value but performs tests to ensure the Merkle tree is constructed correctly and the computed root matches the expected root.


---
### hash\_leaf<!-- {{#callable:hash_leaf}} -->
The `hash_leaf` function hashes a given string into a leaf node of a binary Merkle tree and verifies the operation's success.
- **Inputs**:
    - `leaf`: A pointer to an `fd_bmtree_node_t` structure where the hash of the leaf will be stored.
    - `leaf_cstr`: A constant character pointer to the string that will be hashed into the leaf node.
- **Control Flow**:
    - The function calls `fd_bmtree_hash_leaf` with the provided leaf node, the string to hash, the length of the string, and a constant value of 1UL.
    - It uses `FD_TEST` to assert that the result of `fd_bmtree_hash_leaf` is equal to the input `leaf`, ensuring the hashing operation was successful.
- **Output**: The function does not return a value; it modifies the `leaf` node in place and uses assertions to verify correctness.


---
### test\_inclusion<!-- {{#callable:test_inclusion}} -->
The `test_inclusion` function tests the inclusion proofs of a binary Merkle tree by constructing a tree, generating proofs, and verifying the integrity of the tree and proofs through various corruption scenarios.
- **Inputs**:
    - `leaf_cnt`: The number of leaves in the binary Merkle tree to be tested.
- **Control Flow**:
    - Initialize constants and verify the tree depth is within limits.
    - Calculate the memory footprint and initialize two Merkle tree structures, `tree` and `ptree`, with aligned memory.
    - Initialize a leaf node and append `leaf_cnt` leaves to the `tree`, verifying the leaf count at each step.
    - Finalize the `tree` to obtain the root hash.
    - For each leaf, generate a proof and verify it against the root hash using `fd_bmtree_from_proof` and `fd_memeq`.
    - Insert the leaf with proof into `ptree` and verify the root hash consistency.
    - If there are multiple leaves, intentionally corrupt the proof, root, and leaf to test the robustness of the proof verification and insertion functions.
    - Finalize the `ptree` and verify the final root hash against the original root hash.
    - Attempt to generate a proof for a non-existent leaf index to ensure it fails.
- **Output**: The function does not return a value but uses assertions to verify the correctness of the Merkle tree operations and inclusion proofs.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, performs a series of tests on binary Merkle tree operations, and logs the results.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the environment using `fd_boot` with command-line arguments.
    - Perform internal checks to validate alignment and footprint of binary Merkle tree operations.
    - Test the depth and node count of binary Merkle trees using a naive division algorithm for various leaf counts.
    - Iterate over leaf counts from 1 to 256 and call [`test_inclusion`](#test_inclusion) to verify inclusion proofs.
    - For leaf counts from 2 to 10,000,000, calculate expected depth and node count, and verify against `fd_bmtree_depth` and `fd_bmtree_node_cnt`.
    - Test 20-byte tree construction with various leaf counts and expected roots using [`test_bmtree20_commit`](#test_bmtree20_commit) and [`test_bmtree20_commitp`](#test_bmtree20_commitp).
    - Benchmark the performance of 20-byte tree construction and log the results.
    - Test 32-byte tree construction using predefined leaf data and verify the final root against an expected hash.
    - Initialize a 20-byte tree, append leaves, and verify proofs against reference data.
    - Log a success message and halt the program.
- **Output**: The function returns an integer, specifically 0, indicating successful execution.
- **Functions called**:
    - [`test_inclusion`](#test_inclusion)
    - [`test_bmtree20_commit`](#test_bmtree20_commit)
    - [`test_bmtree20_commitp`](#test_bmtree20_commitp)
    - [`hash_leaf`](#hash_leaf)



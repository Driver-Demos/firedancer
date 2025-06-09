# Purpose
This C source code file is a comprehensive test suite for a system that handles data shreds, specifically in the context of Solana's blockchain infrastructure. The code is structured to test various functionalities related to the creation, signing, and verification of data and parity shreds, which are essential components in Solana's data transmission and error correction processes. The file includes multiple test functions that validate the behavior of the system under different scenarios, such as batch processing, interleaved processing, and handling of new data formats. It also tests the system's ability to handle chained Merkle shreds, which are used for data integrity verification.

The code imports several headers and libraries that provide the necessary functions and data structures for handling shreds, error correction, and cryptographic operations. Key components include the `fd_shredder` for creating shreds, `fd_fec_resolver` for resolving Forward Error Correction (FEC) sets, and cryptographic functions for signing and verifying data. The file defines a main function that initializes the system, registers metrics, and executes a series of test cases to ensure the system's robustness and correctness. The tests cover a wide range of scenarios, including performance testing, signature verification, and error handling, making this file a critical component for validating the integrity and reliability of the shred handling system in a blockchain environment.
# Imports and Dependencies

---
- `stdio.h`
- `fd_shredder.h`
- `fd_fec_resolver.h`
- `../../ballet/shred/fd_shred.h`
- `../../ballet/shred/fd_fec_set.h`
- `../../ballet/base58/fd_base58.h`
- `../../ballet/hex/fd_hex.h`
- `../../util/archive/fd_ar.h`
- `../../disco/metrics/fd_metrics.h`


# Global Variables

---
### perf\_test\_entry\_batch
- **Type**: `uchar array`
- **Description**: `perf_test_entry_batch` is a global array of unsigned characters with a size defined by `PERF_TEST_SZ`, which is 10 megabytes. This array is used to store data for performance testing purposes, specifically simulating a batch of entries for testing the performance of the system.
- **Use**: This variable is used in the `perf_test` function to initialize and store data for performance testing, simulating a large batch of entries.


---
### fec\_set\_memory
- **Type**: `uchar array`
- **Description**: The `fec_set_memory` is a global array of unsigned characters (uchar) with a size determined by the product of 16, 2048, and the sum of `FD_REEDSOL_DATA_SHREDS_MAX` and `FD_REEDSOL_PARITY_SHREDS_MAX`. This array is used to store memory for Forward Error Correction (FEC) sets, which are used in data recovery and error correction processes.
- **Use**: This variable is used to allocate memory for FEC sets, which are essential for handling data shreds and parity shreds in the error correction process.


---
### res\_mem
- **Type**: `uchar array`
- **Description**: The `res_mem` variable is a global array of unsigned characters with a size of 1 megabyte (1024 * 1024 bytes). It is aligned according to the `FD_FEC_RESOLVER_ALIGN` attribute, which ensures that the memory is aligned to a specific boundary required by the FEC resolver.
- **Use**: This variable is used to store memory for the FEC resolver instances, which are responsible for handling Forward Error Correction (FEC) operations in the code.


---
### metrics\_scratch
- **Type**: `uchar[]`
- **Description**: The `metrics_scratch` variable is a global array of unsigned characters (uchar) used as a scratchpad for metrics data. It is defined with a size determined by the `FD_METRICS_FOOTPRINT(0, 0)` macro, which calculates the required footprint for metrics storage. The array is aligned according to the `FD_METRICS_ALIGN` attribute to ensure proper memory alignment for performance or hardware requirements.
- **Use**: This variable is used to store temporary metrics data during the execution of the program, likely for performance monitoring or debugging purposes.


---
### \_shredder
- **Type**: `fd_shredder_t`
- **Description**: The `_shredder` variable is a global array of type `fd_shredder_t` with a single element. It is used to manage the shredding process, which involves breaking down data into smaller pieces (shreds) for processing or transmission.
- **Use**: This variable is used to initialize and manage the state of a shredder instance, which is crucial for operations involving data shredding and reconstruction.


---
### fec\_set\_memory\_1
- **Type**: `uchar array`
- **Description**: `fec_set_memory_1` is a global array of unsigned characters with a size determined by multiplying 2048 by the constant `FD_REEDSOL_DATA_SHREDS_MAX`. This array is used to store data shreds for Forward Error Correction (FEC) operations.
- **Use**: It is used to allocate memory for data shreds in FEC operations, ensuring that there is sufficient space to store the maximum number of data shreds as defined by `FD_REEDSOL_DATA_SHREDS_MAX`.


---
### fec\_set\_memory\_2
- **Type**: `uchar array`
- **Description**: `fec_set_memory_2` is a global array of unsigned characters (uchar) with a size determined by multiplying 2048 by the constant `FD_REEDSOL_PARITY_SHREDS_MAX`. This array is used to store memory related to Forward Error Correction (FEC) parity shreds.
- **Use**: It is used to allocate memory for FEC parity shreds in the context of data redundancy and error correction processes.


# Data Structures

---
### signer\_ctx
- **Type**: `struct`
- **Members**:
    - `sha512`: An array of one fd_sha512_t structure used for SHA-512 hashing.
    - `public_key`: A pointer to an unsigned char representing the public key.
    - `private_key`: A pointer to an unsigned char representing the private key.
- **Description**: The `signer_ctx` structure is designed to hold cryptographic context for signing operations, specifically using the SHA-512 hashing algorithm. It contains a SHA-512 context, a public key, and a private key, which are essential for generating digital signatures. The structure is used in conjunction with functions that initialize the context and perform signing operations, ensuring that the cryptographic processes are securely managed.


---
### signer\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `sha512`: An array of one `fd_sha512_t` structure used for SHA-512 hashing operations.
    - `public_key`: A pointer to an unsigned character array representing the public key.
    - `private_key`: A pointer to an unsigned character array representing the private key.
- **Description**: The `signer_ctx_t` structure is designed to manage cryptographic signing contexts, specifically for operations involving SHA-512 hashing and Ed25519 signatures. It contains a SHA-512 hashing context, and pointers to both the public and private keys, which are used in the signing process. This structure is essential for initializing and managing the state required for cryptographic operations, ensuring that the necessary keys and hashing contexts are readily available for signing data.


# Functions

---
### signer\_ctx\_init<!-- {{#callable:signer_ctx_init}} -->
The `signer_ctx_init` function initializes a `signer_ctx_t` structure by setting up a SHA-512 context and assigning the private and public keys from a given private key.
- **Inputs**:
    - `ctx`: A pointer to a `signer_ctx_t` structure that will be initialized.
    - `private_key`: A constant pointer to an unsigned character array representing the private key, where the first 32 bytes are the private key and the next 32 bytes are the public key.
- **Control Flow**:
    - Call `fd_sha512_new` with `ctx->sha512` to create a new SHA-512 context.
    - Initialize the SHA-512 context by calling `fd_sha512_init` and check the result with `FD_TEST`.
    - Set `ctx->public_key` to point to the public key portion of the `private_key` (offset by 32 bytes).
    - Set `ctx->private_key` to point to the start of the `private_key`.
- **Output**: The function does not return a value; it initializes the `signer_ctx_t` structure pointed to by `ctx`.


---
### test\_signer<!-- {{#callable:test_signer}} -->
The `test_signer` function generates an Ed25519 signature for a given Merkle root using a provided signer context.
- **Inputs**:
    - `_ctx`: A pointer to a `signer_ctx_t` structure, which contains the public and private keys and a SHA-512 context for signing.
    - `signature`: A pointer to an array where the generated signature will be stored.
    - `merkle_root`: A pointer to a constant array representing the Merkle root to be signed.
- **Control Flow**:
    - Cast the `_ctx` input to a `signer_ctx_t` pointer to access the signing context.
    - Call the `fd_ed25519_sign` function to generate a signature using the provided Merkle root, the public and private keys from the context, and the SHA-512 context.
- **Output**: The function does not return a value, but it outputs the generated signature into the `signature` array.


---
### sets\_eq<!-- {{#callable:sets_eq}} -->
The `sets_eq` function checks if two `fd_fec_set_t` structures are equivalent by comparing their data and parity shreds.
- **Inputs**:
    - `a`: A pointer to the first `fd_fec_set_t` structure to compare.
    - `b`: A pointer to the second `fd_fec_set_t` structure to compare.
- **Control Flow**:
    - Check if one of the input pointers is NULL while the other is not; if so, return 0 indicating inequality.
    - Compare the `data_shred_cnt` and `parity_shred_cnt` fields of both structures; if they differ, return 0 indicating inequality.
    - Iterate over each data shred in the first structure and compare it with the corresponding data shred in the second structure using `fd_memeq`; if any pair is not equal, log the difference and return 0.
    - Iterate over each parity shred in the first structure and compare it with the corresponding parity shred in the second structure using `fd_memeq`; if any pair is not equal, log the difference and return 0.
    - If all checks pass, return 1 indicating the structures are equivalent.
- **Output**: Returns 1 if the two `fd_fec_set_t` structures are equivalent, otherwise returns 0.


---
### allocate\_fec\_set<!-- {{#callable:allocate_fec_set}} -->
The `allocate_fec_set` function initializes the data and parity shreds of a given FEC set with memory addresses, incrementing the pointer by a fixed size for each shred, and returns the updated pointer.
- **Inputs**:
    - `set`: A pointer to an `fd_fec_set_t` structure where the data and parity shreds will be initialized.
    - `ptr`: A pointer to a memory location that will be used to initialize the data and parity shreds in the FEC set.
- **Control Flow**:
    - Iterate over the maximum number of data shreds (`FD_REEDSOL_DATA_SHREDS_MAX`) and assign each shred in `set->data_shreds` to the current `ptr` value, then increment `ptr` by 2048 bytes.
    - Iterate over the maximum number of parity shreds (`FD_REEDSOL_PARITY_SHREDS_MAX`) and assign each shred in `set->parity_shreds` to the current `ptr` value, then increment `ptr` by 2048 bytes.
    - Check that the final `ptr` value does not exceed the allocated `fec_set_memory` size using `FD_TEST`.
    - Return the updated `ptr` value.
- **Output**: The function returns the updated pointer `ptr` after initializing the FEC set's shreds.


---
### test\_one\_batch<!-- {{#callable:test_one_batch}} -->
The `test_one_batch` function tests the process of creating, processing, and verifying a batch of shreds using a shredder and FEC resolvers.
- **Inputs**: None
- **Control Flow**:
    - Initialize a signer context with a private key.
    - Create a new shredder and join it to the current context.
    - Initialize metadata for the entry batch and set it to complete.
    - Initialize a batch in the shredder with test data and metadata.
    - Allocate memory for FEC sets and initialize them.
    - Create and join three FEC resolvers with different memory offsets and configurations.
    - Iterate over a loop to process multiple FEC sets, adding data and parity shreds to the resolvers and checking their completion status.
    - Finalize the batch in the shredder.
    - Delete the FEC resolvers after processing.
- **Output**: The function does not return any value; it performs tests and asserts conditions using `FD_TEST` to ensure the correctness of the shredder and FEC resolver operations.
- **Functions called**:
    - [`signer_ctx_init`](#signer_ctx_init)
    - [`fd_shredder_new`](fd_shredder.c.driver.md#fd_shredder_new)
    - [`fd_shredder_join`](fd_shredder.c.driver.md#fd_shredder_join)
    - [`fd_shredder_init_batch`](fd_shredder.c.driver.md#fd_shredder_init_batch)
    - [`allocate_fec_set`](#allocate_fec_set)
    - [`fd_fec_resolver_footprint`](fd_fec_resolver.c.driver.md#fd_fec_resolver_footprint)
    - [`fd_fec_resolver_join`](fd_fec_resolver.c.driver.md#fd_fec_resolver_join)
    - [`fd_fec_resolver_new`](fd_fec_resolver.c.driver.md#fd_fec_resolver_new)
    - [`fd_shredder_next_fec_set`](fd_shredder.c.driver.md#fd_shredder_next_fec_set)
    - [`sets_eq`](#sets_eq)
    - [`fd_shredder_fini_batch`](fd_shredder.c.driver.md#fd_shredder_fini_batch)
    - [`fd_fec_resolver_delete`](fd_fec_resolver.c.driver.md#fd_fec_resolver_delete)
    - [`fd_fec_resolver_leave`](fd_fec_resolver.c.driver.md#fd_fec_resolver_leave)


---
### test\_interleaved<!-- {{#callable:test_interleaved}} -->
The `test_interleaved` function tests the interleaving of FEC (Forward Error Correction) sets using a shredder and resolver setup.
- **Inputs**: None
- **Control Flow**:
    - Initialize a `signer_ctx_t` structure with a private key.
    - Create a new shredder instance and join it, verifying its creation.
    - Initialize a batch for the shredder with test data and metadata indicating block completion.
    - Allocate memory for two FEC sets and four output FEC sets.
    - Retrieve two FEC sets from the shredder using [`fd_shredder_next_fec_set`](fd_shredder.c.driver.md#fd_shredder_next_fec_set).
    - Finalize the shredder batch.
    - Create and join a new FEC resolver with the allocated output FEC sets.
    - Iterate over the data shreds of the first FEC set, adding them to the resolver and checking the result.
    - Add a parity shred from the first FEC set to the resolver, checking for completion and equality with the output FEC set.
    - Add a parity shred from the second FEC set to the resolver, checking for completion and equality with the output FEC set.
    - Delete the FEC resolver after use.
- **Output**: The function does not return any value; it performs tests and assertions to verify the interleaving of FEC sets.
- **Functions called**:
    - [`signer_ctx_init`](#signer_ctx_init)
    - [`fd_shredder_new`](fd_shredder.c.driver.md#fd_shredder_new)
    - [`fd_shredder_join`](fd_shredder.c.driver.md#fd_shredder_join)
    - [`fd_shredder_init_batch`](fd_shredder.c.driver.md#fd_shredder_init_batch)
    - [`allocate_fec_set`](#allocate_fec_set)
    - [`fd_shredder_next_fec_set`](fd_shredder.c.driver.md#fd_shredder_next_fec_set)
    - [`fd_shredder_fini_batch`](fd_shredder.c.driver.md#fd_shredder_fini_batch)
    - [`fd_fec_resolver_join`](fd_fec_resolver.c.driver.md#fd_fec_resolver_join)
    - [`fd_fec_resolver_new`](fd_fec_resolver.c.driver.md#fd_fec_resolver_new)
    - [`sets_eq`](#sets_eq)
    - [`fd_fec_resolver_delete`](fd_fec_resolver.c.driver.md#fd_fec_resolver_delete)
    - [`fd_fec_resolver_leave`](fd_fec_resolver.c.driver.md#fd_fec_resolver_leave)


---
### test\_rolloff<!-- {{#callable:test_rolloff}} -->
The `test_rolloff` function tests the behavior of a shredder and FEC resolver system when handling multiple FEC sets, ensuring that completed sets are correctly identified and processed while others are ignored.
- **Inputs**: None
- **Control Flow**:
    - Initialize a `signer_ctx_t` structure with a private key and create a new shredder instance using [`fd_shredder_new`](fd_shredder.c.driver.md#fd_shredder_new) and [`fd_shredder_join`](fd_shredder.c.driver.md#fd_shredder_join).
    - Prepare metadata for an entry batch and initialize the shredder batch with [`fd_shredder_init_batch`](fd_shredder.c.driver.md#fd_shredder_init_batch).
    - Allocate memory for three FEC sets and four output FEC sets using [`allocate_fec_set`](#allocate_fec_set).
    - Retrieve the next three FEC sets from the shredder using [`fd_shredder_next_fec_set`](fd_shredder.c.driver.md#fd_shredder_next_fec_set).
    - Finalize the shredder batch with [`fd_shredder_fini_batch`](fd_shredder.c.driver.md#fd_shredder_fini_batch).
    - Create and join a new FEC resolver using [`fd_fec_resolver_new`](fd_fec_resolver.c.driver.md#fd_fec_resolver_new) and [`fd_fec_resolver_join`](fd_fec_resolver.c.driver.md#fd_fec_resolver_join).
    - Add data shreds from the first two FEC sets to the resolver, marking them as 'OKAY'.
    - Add data shreds from the third FEC set, causing the first set to be ignored and the second and third sets to be in progress.
    - Add parity shreds to the resolver, marking the first set as 'IGNORED', and completing the second and third sets, verifying the output FEC sets match expectations.
    - Delete the FEC resolver using [`fd_fec_resolver_delete`](fd_fec_resolver.c.driver.md#fd_fec_resolver_delete) and [`fd_fec_resolver_leave`](fd_fec_resolver.c.driver.md#fd_fec_resolver_leave).
- **Output**: The function does not return any value; it performs tests and assertions to verify the correct behavior of the shredder and FEC resolver system.
- **Functions called**:
    - [`signer_ctx_init`](#signer_ctx_init)
    - [`fd_shredder_new`](fd_shredder.c.driver.md#fd_shredder_new)
    - [`fd_shredder_join`](fd_shredder.c.driver.md#fd_shredder_join)
    - [`fd_shredder_init_batch`](fd_shredder.c.driver.md#fd_shredder_init_batch)
    - [`allocate_fec_set`](#allocate_fec_set)
    - [`fd_shredder_next_fec_set`](fd_shredder.c.driver.md#fd_shredder_next_fec_set)
    - [`fd_shredder_fini_batch`](fd_shredder.c.driver.md#fd_shredder_fini_batch)
    - [`fd_fec_resolver_join`](fd_fec_resolver.c.driver.md#fd_fec_resolver_join)
    - [`fd_fec_resolver_new`](fd_fec_resolver.c.driver.md#fd_fec_resolver_new)
    - [`sets_eq`](#sets_eq)
    - [`fd_fec_resolver_delete`](fd_fec_resolver.c.driver.md#fd_fec_resolver_delete)
    - [`fd_fec_resolver_leave`](fd_fec_resolver.c.driver.md#fd_fec_resolver_leave)


---
### perf\_test<!-- {{#callable:perf_test}} -->
The `perf_test` function performs a performance test by initializing, processing, and finalizing batches of entry data using a shredder, measuring the time taken for these operations over multiple iterations.
- **Inputs**: None
- **Control Flow**:
    - Initialize the `perf_test_entry_batch` array with sequential byte values.
    - Set up a metadata structure `meta` with `block_complete` set to 1.
    - Initialize a `signer_ctx` with a private key.
    - Create and join a shredder instance using the initialized signer context.
    - Allocate memory for a FEC set using `fec_set_memory`.
    - Start a timer using `fd_log_wallclock`.
    - Iterate 100 times, each time initializing a batch in the shredder with the entry batch and metadata, processing FEC sets, and finalizing the batch.
    - Stop the timer and calculate the elapsed time.
    - Log the performance results in terms of nanoseconds per 10 MB entry batch and Gbps.
- **Output**: The function does not return any value; it logs the performance results to the console.
- **Functions called**:
    - [`signer_ctx_init`](#signer_ctx_init)
    - [`fd_shredder_new`](fd_shredder.c.driver.md#fd_shredder_new)
    - [`fd_shredder_join`](fd_shredder.c.driver.md#fd_shredder_join)
    - [`fd_shredder_init_batch`](fd_shredder.c.driver.md#fd_shredder_init_batch)
    - [`fd_shredder_count_fec_sets`](fd_shredder.h.driver.md#fd_shredder_count_fec_sets)
    - [`fd_shredder_next_fec_set`](fd_shredder.c.driver.md#fd_shredder_next_fec_set)
    - [`fd_shredder_fini_batch`](fd_shredder.c.driver.md#fd_shredder_fini_batch)


---
### test\_new\_formats<!-- {{#callable:test_new_formats}} -->
The `test_new_formats` function tests the handling of new FEC (Forward Error Correction) formats by reading and processing shreds from two test files, verifying the completion of FEC sets, and ensuring the correct number of sets are completed.
- **Inputs**: None
- **Control Flow**:
    - Initialize a signer context with a private key.
    - Allocate memory for four FEC sets.
    - Create a new FEC resolver with specific parameters and join it.
    - Decode a base58 public key from a string and store it in a buffer.
    - Open a file containing chained test data and initialize it for reading.
    - Iterate over the file, reading shreds and adding them to the FEC resolver, checking for completion of FEC sets.
    - Verify that four FEC sets are completed and close the file.
    - Decode another base58 public key for a resigned test.
    - Open a file containing resigned test data and initialize it for reading.
    - Iterate over the file, reading shreds and adding them to the FEC resolver, checking for completion of FEC sets.
    - Verify that one FEC set is completed and close the file.
    - Delete the FEC resolver after leaving it.
- **Output**: The function does not return any value; it performs tests and uses assertions to verify expected outcomes.
- **Functions called**:
    - [`signer_ctx_init`](#signer_ctx_init)
    - [`allocate_fec_set`](#allocate_fec_set)
    - [`fd_fec_resolver_join`](fd_fec_resolver.c.driver.md#fd_fec_resolver_join)
    - [`fd_fec_resolver_new`](fd_fec_resolver.c.driver.md#fd_fec_resolver_new)
    - [`fd_fec_resolver_add_shred`](fd_fec_resolver.c.driver.md#fd_fec_resolver_add_shred)
    - [`fd_fec_resolver_delete`](fd_fec_resolver.c.driver.md#fd_fec_resolver_delete)
    - [`fd_fec_resolver_leave`](fd_fec_resolver.c.driver.md#fd_fec_resolver_leave)


---
### test\_shred\_version<!-- {{#callable:test_shred_version}} -->
The `test_shred_version` function tests the behavior of the shredder and FEC resolver when using an inverted shred version.
- **Inputs**: None
- **Control Flow**:
    - Initialize a `signer_ctx_t` structure with a private key.
    - Create a new shredder instance with an inverted shred version and join it.
    - Initialize a batch for the shredder with test data and metadata indicating block completion.
    - Allocate memory for FEC sets and initialize them.
    - Create a new FEC resolver and join it.
    - Retrieve the next FEC set from the shredder and parse the first data shred.
    - Attempt to add the parsed shred to the FEC resolver and check if it is rejected due to version mismatch.
    - Delete the FEC resolver instance.
- **Output**: The function does not return any value; it performs tests and uses assertions to validate expected behavior.
- **Functions called**:
    - [`signer_ctx_init`](#signer_ctx_init)
    - [`fd_shredder_new`](fd_shredder.c.driver.md#fd_shredder_new)
    - [`fd_shredder_join`](fd_shredder.c.driver.md#fd_shredder_join)
    - [`fd_shredder_init_batch`](fd_shredder.c.driver.md#fd_shredder_init_batch)
    - [`allocate_fec_set`](#allocate_fec_set)
    - [`fd_fec_resolver_join`](fd_fec_resolver.c.driver.md#fd_fec_resolver_join)
    - [`fd_fec_resolver_new`](fd_fec_resolver.c.driver.md#fd_fec_resolver_new)
    - [`fd_shredder_next_fec_set`](fd_shredder.c.driver.md#fd_shredder_next_fec_set)
    - [`fd_fec_resolver_add_shred`](fd_fec_resolver.c.driver.md#fd_fec_resolver_add_shred)
    - [`fd_fec_resolver_delete`](fd_fec_resolver.c.driver.md#fd_fec_resolver_delete)
    - [`fd_fec_resolver_leave`](fd_fec_resolver.c.driver.md#fd_fec_resolver_leave)


---
### fake\_resign<!-- {{#callable:fake_resign}} -->
The `fake_resign` function recalculates and updates the signature of a given shred using a Merkle tree root hash.
- **Inputs**:
    - `shred`: A pointer to an `fd_shred_t` structure representing the shred to be resigned.
    - `sign_ctx`: A pointer to a `signer_ctx_t` structure containing the signing context, including the public and private keys.
- **Control Flow**:
    - Retrieve the variant and type of the shred to determine if it is a data shred.
    - Calculate the index of the shred based on whether it is a data or parity shred.
    - Determine the depth of the Merkle tree and calculate the size of the data protected by the Merkle tree and Reed-Solomon coding.
    - Initialize memory for the Merkle tree and calculate the hash of the leaf node using the shred data.
    - Retrieve the Merkle proof nodes from the shred and initialize a Merkle tree commit structure.
    - Insert the leaf node into the Merkle tree with the proof and calculate the root hash.
    - Use the [`test_signer`](#test_signer) function to sign the shred with the calculated Merkle root hash.
- **Output**: The function does not return a value; it updates the signature of the shred in place.
- **Functions called**:
    - [`test_signer`](#test_signer)


---
### test\_shred\_reject<!-- {{#callable:test_shred_reject}} -->
The `test_shred_reject` function tests the rejection and acceptance of shreds based on their validity and signature correctness in a FEC (Forward Error Correction) resolver context.
- **Inputs**: None
- **Control Flow**:
    - Initialize a signer context with a private key and create a shredder instance.
    - Join the shredder and initialize a batch with test data and metadata.
    - Allocate memory for FEC sets and join a FEC resolver with specific parameters.
    - Iterate over data shreds, parsing each shred and testing its acceptance or rejection based on its validity and signature using macros `SIGN_ACCEPT` and `SIGN_REJECT`.
    - Modify shred data and test the rejection due to invalid signatures or data inconsistencies.
    - Test various conditions for both data and parity shreds to ensure correct rejection or acceptance based on index, flags, and other parameters.
    - Conclude by cleaning up the FEC resolver.
- **Output**: The function does not return any value; it performs tests and assertions to validate the behavior of shred acceptance and rejection.
- **Functions called**:
    - [`signer_ctx_init`](#signer_ctx_init)
    - [`fd_shredder_new`](fd_shredder.c.driver.md#fd_shredder_new)
    - [`fd_shredder_join`](fd_shredder.c.driver.md#fd_shredder_join)
    - [`fd_shredder_init_batch`](fd_shredder.c.driver.md#fd_shredder_init_batch)
    - [`allocate_fec_set`](#allocate_fec_set)
    - [`fd_fec_resolver_join`](fd_fec_resolver.c.driver.md#fd_fec_resolver_join)
    - [`fd_fec_resolver_new`](fd_fec_resolver.c.driver.md#fd_fec_resolver_new)
    - [`fd_shredder_next_fec_set`](fd_shredder.c.driver.md#fd_shredder_next_fec_set)
    - [`fd_fec_resolver_add_shred`](fd_fec_resolver.c.driver.md#fd_fec_resolver_add_shred)


---
### test\_merkle\_root<!-- {{#callable:test_merkle_root}} -->
The `test_merkle_root` function verifies the correct writing of Merkle roots in shreds under various conditions using a shredder and FEC resolver.
- **Inputs**: None
- **Control Flow**:
    - Initialize a `signer_ctx_t` structure with a private key.
    - Create a new shredder and join it, verifying its creation.
    - Set up a public key from the private key and initialize metadata for a batch.
    - Initialize a batch in the shredder with test data and metadata.
    - Allocate memory for FEC sets and output sets.
    - Join a new FEC resolver with specified parameters and output sets.
    - Retrieve the next FEC set from the shredder.
    - Parse the first data shred and verify its parsing.
    - Add the parsed shred to the FEC resolver and verify the Merkle root is written correctly on success.
    - Parse the second data shred, modify its payload, and verify the Merkle root is not written on rejection.
    - Parse the first data shred again, modify its payload, and verify the Merkle root is not written on being ignored.
    - Parse a parity shred and verify the Merkle root is not written if the output is NULL.
- **Output**: The function does not return a value; it uses assertions to verify the correctness of Merkle root handling in shreds.
- **Functions called**:
    - [`signer_ctx_init`](#signer_ctx_init)
    - [`fd_shredder_new`](fd_shredder.c.driver.md#fd_shredder_new)
    - [`fd_shredder_join`](fd_shredder.c.driver.md#fd_shredder_join)
    - [`fd_shredder_init_batch`](fd_shredder.c.driver.md#fd_shredder_init_batch)
    - [`allocate_fec_set`](#allocate_fec_set)
    - [`fd_fec_resolver_join`](fd_fec_resolver.c.driver.md#fd_fec_resolver_join)
    - [`fd_fec_resolver_new`](fd_fec_resolver.c.driver.md#fd_fec_resolver_new)
    - [`fd_shredder_next_fec_set`](fd_shredder.c.driver.md#fd_shredder_next_fec_set)
    - [`fd_fec_resolver_add_shred`](fd_fec_resolver.c.driver.md#fd_fec_resolver_add_shred)


---
### test\_force\_complete<!-- {{#callable:test_force_complete}} -->
The `test_force_complete` function tests the behavior of the FEC resolver when attempting to forcefully complete a set of shreds, handling various error conditions and ensuring successful completion when all conditions are met.
- **Inputs**: None
- **Control Flow**:
    - Initialize a `signer_ctx_t` structure with a private key and create a shredder using [`fd_shredder_new`](fd_shredder.c.driver.md#fd_shredder_new) and [`fd_shredder_join`](fd_shredder.c.driver.md#fd_shredder_join).
    - Prepare metadata for the entry batch and initialize the shredder batch with [`fd_shredder_init_batch`](fd_shredder.c.driver.md#fd_shredder_init_batch).
    - Allocate memory for FEC sets and initialize them using [`allocate_fec_set`](#allocate_fec_set).
    - Retrieve the next FEC set from the shredder using [`fd_shredder_next_fec_set`](fd_shredder.c.driver.md#fd_shredder_next_fec_set) and finalize the batch with [`fd_shredder_fini_batch`](fd_shredder.c.driver.md#fd_shredder_fini_batch).
    - Join a new FEC resolver and add shreds to it, skipping one to simulate a gap.
    - Attempt to forcefully complete the FEC set with [`fd_fec_resolver_force_complete`](fd_fec_resolver.c.driver.md#fd_fec_resolver_force_complete), expecting rejection due to missing shreds.
    - Add the missing shred and modify the last shred to simulate a signature error, then attempt force completion again, expecting rejection.
    - Restore the last shred's original state and successfully force complete the FEC set.
    - Clean up by deleting the FEC resolver.
- **Output**: The function does not return any value; it uses assertions (`FD_TEST`) to verify expected outcomes during the test.
- **Functions called**:
    - [`signer_ctx_init`](#signer_ctx_init)
    - [`fd_shredder_new`](fd_shredder.c.driver.md#fd_shredder_new)
    - [`fd_shredder_join`](fd_shredder.c.driver.md#fd_shredder_join)
    - [`fd_shredder_init_batch`](fd_shredder.c.driver.md#fd_shredder_init_batch)
    - [`allocate_fec_set`](#allocate_fec_set)
    - [`fd_shredder_next_fec_set`](fd_shredder.c.driver.md#fd_shredder_next_fec_set)
    - [`fd_shredder_fini_batch`](fd_shredder.c.driver.md#fd_shredder_fini_batch)
    - [`fd_fec_resolver_join`](fd_fec_resolver.c.driver.md#fd_fec_resolver_join)
    - [`fd_fec_resolver_new`](fd_fec_resolver.c.driver.md#fd_fec_resolver_new)
    - [`fd_fec_resolver_force_complete`](fd_fec_resolver.c.driver.md#fd_fec_resolver_force_complete)
    - [`fd_fec_resolver_delete`](fd_fec_resolver.c.driver.md#fd_fec_resolver_delete)
    - [`fd_fec_resolver_leave`](fd_fec_resolver.c.driver.md#fd_fec_resolver_leave)


---
### test\_chained\_merkle\_shreds<!-- {{#callable:test_chained_merkle_shreds}} -->
The function `test_chained_merkle_shreds` tests the creation and verification of chained Merkle shreds, ensuring that the final Merkle root matches the expected value after processing multiple slots and sets.
- **Inputs**: None
- **Control Flow**:
    - Initialize expected and actual Merkle root arrays and a canary value for memory checks.
    - Decode initial and expected final Merkle root values from hex strings.
    - Set data size to 30000 and verify that the number of data and parity shreds, as well as FEC sets, are as expected (32 each for data and parity shreds, 1 FEC set).
    - Initialize a performance test entry batch with sequential values and set up metadata and signer context.
    - Create a new shredder and join it, ensuring it is initialized correctly.
    - Allocate memory for data and parity shreds, filling them with the canary value for overflow detection.
    - Iterate over slots, skipping slot 11, and for each slot, iterate over FEC sets to create shreds, update the Merkle root, and verify shred properties.
    - For each data shred, check for overflow, correct indexing, and verify the Merkle root after adding shreds to the resolver.
    - Ensure at least one coding shred is added to complete a set and verify the set equality with the output FEC set.
    - Repeat similar checks for parity shreds, ensuring correct indexing and Merkle root verification.
    - After processing all slots and sets, verify that the final chained Merkle root matches the expected value.
- **Output**: The function does not return a value; it performs tests and assertions to verify the correctness of chained Merkle shreds and their final Merkle root.
- **Functions called**:
    - [`fd_shredder_count_data_shreds`](fd_shredder.h.driver.md#fd_shredder_count_data_shreds)
    - [`fd_shredder_count_parity_shreds`](fd_shredder.h.driver.md#fd_shredder_count_parity_shreds)
    - [`fd_shredder_count_fec_sets`](fd_shredder.h.driver.md#fd_shredder_count_fec_sets)
    - [`signer_ctx_init`](#signer_ctx_init)
    - [`fd_shredder_new`](fd_shredder.c.driver.md#fd_shredder_new)
    - [`fd_shredder_join`](fd_shredder.c.driver.md#fd_shredder_join)
    - [`allocate_fec_set`](#allocate_fec_set)
    - [`fd_shredder_init_batch`](fd_shredder.c.driver.md#fd_shredder_init_batch)
    - [`fd_shredder_next_fec_set`](fd_shredder.c.driver.md#fd_shredder_next_fec_set)
    - [`fd_shredder_fini_batch`](fd_shredder.c.driver.md#fd_shredder_fini_batch)
    - [`fd_fec_resolver_join`](fd_fec_resolver.c.driver.md#fd_fec_resolver_join)
    - [`fd_fec_resolver_new`](fd_fec_resolver.c.driver.md#fd_fec_resolver_new)
    - [`fd_fec_resolver_add_shred`](fd_fec_resolver.c.driver.md#fd_fec_resolver_add_shred)
    - [`sets_eq`](#sets_eq)
    - [`fd_fec_resolver_delete`](fd_fec_resolver.c.driver.md#fd_fec_resolver_delete)
    - [`fd_fec_resolver_leave`](fd_fec_resolver.c.driver.md#fd_fec_resolver_leave)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, registers metrics, and executes a series of test functions to validate various aspects of the system's functionality.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments passed to the program.
- **Control Flow**:
    - Call `fd_boot` to initialize the environment with command-line arguments.
    - Register metrics using `fd_metrics_register` with a new metrics object created by `fd_metrics_new`.
    - Declare `perf_test` as a void function to suppress unused variable warnings.
    - Execute a series of test functions: [`test_interleaved`](#test_interleaved), [`test_one_batch`](#test_one_batch), [`test_rolloff`](#test_rolloff), [`test_new_formats`](#test_new_formats), [`test_shred_version`](#test_shred_version), [`test_shred_reject`](#test_shred_reject), [`test_merkle_root`](#test_merkle_root), [`test_force_complete`](#test_force_complete), and [`test_chained_merkle_shreds`](#test_chained_merkle_shreds).
    - Log a notice indicating the tests passed using `FD_LOG_NOTICE`.
    - Call `fd_halt` to clean up and terminate the program.
- **Output**: The function returns an integer value of 0, indicating successful execution.
- **Functions called**:
    - [`test_interleaved`](#test_interleaved)
    - [`test_one_batch`](#test_one_batch)
    - [`test_rolloff`](#test_rolloff)
    - [`test_new_formats`](#test_new_formats)
    - [`test_shred_version`](#test_shred_version)
    - [`test_shred_reject`](#test_shred_reject)
    - [`test_merkle_root`](#test_merkle_root)
    - [`test_force_complete`](#test_force_complete)
    - [`test_chained_merkle_shreds`](#test_chained_merkle_shreds)



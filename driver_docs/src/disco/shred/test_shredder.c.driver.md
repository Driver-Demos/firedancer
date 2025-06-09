# Purpose
This C source code file is a comprehensive test suite for a "shredder" component, which is likely part of a larger system dealing with data sharding and error correction, possibly in a blockchain or distributed ledger context, as suggested by references to Solana and Merkle data. The file includes various test functions that validate the functionality of the shredder, including its ability to process data into shreds, handle forward error correction (FEC) sets, and manage Merkle tree-based data structures. The code defines several test scenarios, such as performance tests, tests for different types of shreds (e.g., chained, resigned), and tests for batch processing and skipping. It also includes performance benchmarks to measure the efficiency of the shredder in processing large data batches.

The file imports several headers and binary fixtures, indicating that it is part of a larger codebase with dependencies on other components. It defines a main function that initializes the test environment, runs the various test functions, and logs the results. The use of macros, such as `FD_TEST`, suggests a custom testing framework is in place. The code is structured to ensure that the shredder's output matches expected results, using assertions and logging to verify correctness. The presence of performance tests indicates an emphasis on both functional correctness and efficiency, making this file a critical component for ensuring the reliability and performance of the shredder within its application context.
# Imports and Dependencies

---
- `fd_shredder.h`
- `../../ballet/shred/fd_shred.h`
- `../../ballet/hex/fd_hex.h`
- `../../util/net/fd_pcap.h`
- `stdio.h`


# Global Variables

---
### perf\_test\_entry\_batch
- **Type**: `uchar array`
- **Description**: `perf_test_entry_batch` is a global array of unsigned characters with a size defined by `PERF_TEST_SZ`, which is 10 megabytes. This array is used to store data for performance testing, specifically for handling large batches of entries in the context of the application.
- **Use**: This variable is used to hold data for performance testing of entry batch processing, simulating a large number of transactions.


---
### skip\_test\_data
- **Type**: `uchar array`
- **Description**: `skip_test_data` is a global array of unsigned characters with a size defined by the macro `SKIP_TEST_SZ`, which is set to 1 megabyte (1024 * 1024 bytes). This array is used to store data for testing purposes in the `test_skip_batch` function.
- **Use**: The `skip_test_data` array is filled with random unsigned characters and used as input data for testing the functionality of batch processing in the `test_skip_batch` function.


---
### fec\_set\_memory\_1
- **Type**: `uchar array`
- **Description**: `fec_set_memory_1` is a global array of unsigned characters with a size determined by multiplying 2048 by the constant `FD_REEDSOL_DATA_SHREDS_MAX`. This array is used to store data shreds for forward error correction (FEC) operations.
- **Use**: It is used to allocate memory for data shreds in FEC operations, where each data shred is 2048 bytes in size.


---
### fec\_set\_memory\_2
- **Type**: `uchar array`
- **Description**: `fec_set_memory_2` is a global array of unsigned characters with a size determined by multiplying 2048 by the constant `FD_REEDSOL_PARITY_SHREDS_MAX`. This array is used to store parity shreds in the context of Forward Error Correction (FEC) operations.
- **Use**: This variable is used to hold parity shreds during FEC set operations, particularly in functions that process or verify parity shreds.


---
### \_shredder
- **Type**: `fd_shredder_t`
- **Description**: The `_shredder` variable is a global array of type `fd_shredder_t` with a single element. It is used to manage and process data shreds and parity shreds in the context of a shredding operation, likely related to data integrity and redundancy mechanisms.
- **Use**: This variable is used to initialize, join, and manage shredding operations, including creating and processing forward error correction (FEC) sets.


# Data Structures

---
### signer\_ctx
- **Type**: `struct`
- **Members**:
    - `sha512`: An array of one `fd_sha512_t` structure used for SHA-512 hashing operations.
    - `public_key`: A pointer to an unsigned character array representing the public key.
    - `private_key`: A pointer to an unsigned character array representing the private key.
- **Description**: The `signer_ctx` structure is designed to hold cryptographic context for signing operations, specifically using the Ed25519 algorithm. It includes a SHA-512 hashing context, which is essential for the signing process, and pointers to the public and private keys. The structure is initialized with a private key, from which the public key is derived by offsetting 32 bytes, aligning with the Ed25519 key format where the first 32 bytes are the private key and the next 32 bytes are the public key.


---
### signer\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `sha512`: An array of one fd_sha512_t structure used for SHA-512 hashing operations.
    - `public_key`: A pointer to an unsigned char array representing the public key, derived from the private key.
    - `private_key`: A pointer to an unsigned char array representing the private key.
- **Description**: The `signer_ctx_t` structure is designed to manage cryptographic signing contexts, specifically for operations involving SHA-512 hashing and Ed25519 signatures. It holds a SHA-512 hashing context, a public key, and a private key, which are used together to sign data securely. The structure is initialized with a private key, from which the public key is derived, and is used in functions that perform cryptographic signing of data, such as generating signatures for Merkle roots.


# Functions

---
### signer\_ctx\_init<!-- {{#callable:signer_ctx_init}} -->
The `signer_ctx_init` function initializes a `signer_ctx_t` structure by setting up a SHA-512 context and assigning the private and public keys from a given private key input.
- **Inputs**:
    - `ctx`: A pointer to a `signer_ctx_t` structure that will be initialized.
    - `private_key`: A constant pointer to an unsigned character array representing the private key, where the first 32 bytes are the private key and the next 32 bytes are the public key.
- **Control Flow**:
    - The function begins by initializing a SHA-512 context using `fd_sha512_init` and `fd_sha512_new`, and checks the result with `FD_TEST` to ensure successful initialization.
    - The public key in the `ctx` structure is set to point to the second half (offset by 32 bytes) of the `private_key` array.
    - The private key in the `ctx` structure is set to point to the beginning of the `private_key` array.
- **Output**: The function does not return a value; it initializes the `signer_ctx_t` structure pointed to by `ctx`.


---
### test\_signer<!-- {{#callable:test_signer}} -->
The `test_signer` function generates an Ed25519 signature for a given Merkle root using a provided signer context.
- **Inputs**:
    - `_ctx`: A pointer to a `signer_ctx_t` structure, which contains the public and private keys and a SHA-512 context.
    - `signature`: A pointer to an unsigned character array where the generated signature will be stored.
    - `merkle_root`: A constant pointer to an unsigned character array representing the Merkle root to be signed.
- **Control Flow**:
    - Cast the `_ctx` parameter to a `signer_ctx_t` pointer to access the signing context.
    - Call the `fd_ed25519_sign` function with the signature buffer, Merkle root, a fixed size of 32 bytes, and the public and private keys from the context, along with the SHA-512 context.
- **Output**: The function does not return a value; it outputs the generated signature into the provided `signature` buffer.


---
### test\_shredder\_pcap<!-- {{#callable:test_shredder_pcap}} -->
The `test_shredder_pcap` function tests the functionality of a shredder by comparing generated data and parity shreds against expected values from a pcap file.
- **Inputs**: None
- **Control Flow**:
    - Initialize a signer context with a private key.
    - Create a new shredder instance and join it.
    - Verify the number of FEC sets, data shreds, and parity shreds from the binary size against expected values.
    - Open a pcap file in memory and create an iterator for it.
    - Initialize metadata for entry batches and set block completion flag.
    - Initialize a shredder batch and iterate over FEC sets to verify data shreds against pcap data.
    - Log errors if any data shreds do not match the expected values from the pcap.
    - Finalize the shredder batch and start a dummy batch to reset indices.
    - Re-initialize the shredder batch and iterate over FEC sets to verify parity shreds against pcap data.
    - Log errors if any parity shreds do not match the expected values from the pcap.
    - Finalize the shredder batch.
    - Delete the pcap iterator and close the file.
- **Output**: The function does not return any value; it performs tests and logs errors if any discrepancies are found.
- **Functions called**:
    - [`signer_ctx_init`](#signer_ctx_init)
    - [`fd_shredder_new`](fd_shredder.c.driver.md#fd_shredder_new)
    - [`fd_shredder_join`](fd_shredder.c.driver.md#fd_shredder_join)
    - [`fd_shredder_count_fec_sets`](fd_shredder.h.driver.md#fd_shredder_count_fec_sets)
    - [`fd_shredder_count_data_shreds`](fd_shredder.h.driver.md#fd_shredder_count_data_shreds)
    - [`fd_shredder_count_parity_shreds`](fd_shredder.h.driver.md#fd_shredder_count_parity_shreds)
    - [`fd_shredder_init_batch`](fd_shredder.c.driver.md#fd_shredder_init_batch)
    - [`fd_shredder_next_fec_set`](fd_shredder.c.driver.md#fd_shredder_next_fec_set)
    - [`fd_shredder_fini_batch`](fd_shredder.c.driver.md#fd_shredder_fini_batch)


---
### test\_skip\_batch<!-- {{#callable:test_skip_batch}} -->
The `test_skip_batch` function tests the functionality of shredders by processing and skipping batches of data, ensuring that all shredders maintain consistent state and output.
- **Inputs**: None
- **Control Flow**:
    - Initialize a random number generator and a signer context with a private key.
    - Define and initialize four shredders, ensuring they are properly joined and ready for use.
    - Prepare metadata and allocate memory for data and parity shreds.
    - Fill the `skip_test_data` buffer with random data using the random number generator.
    - Iterate over the data buffer, processing it in batches using a randomly selected shredder, while other shredders skip the batch.
    - For each batch, initialize the selected shredder, process the data to generate FEC sets, and update data and parity shred counts.
    - Ensure all shredders have consistent data and parity index offsets after processing each batch.
    - Increment the slot number every 200,000 bytes processed, resetting data and parity shred counts.
    - Process a final set with the first shredder and compare the outputs of all shredders to ensure consistency.
- **Output**: The function does not return a value but performs tests to ensure shredders process and skip batches correctly, maintaining consistent state across all shredders.
- **Functions called**:
    - [`signer_ctx_init`](#signer_ctx_init)
    - [`fd_shredder_new`](fd_shredder.c.driver.md#fd_shredder_new)
    - [`fd_shredder_join`](fd_shredder.c.driver.md#fd_shredder_join)
    - [`fd_shredder_init_batch`](fd_shredder.c.driver.md#fd_shredder_init_batch)
    - [`fd_shredder_count_fec_sets`](fd_shredder.h.driver.md#fd_shredder_count_fec_sets)
    - [`fd_shredder_next_fec_set`](fd_shredder.c.driver.md#fd_shredder_next_fec_set)
    - [`fd_shredder_fini_batch`](fd_shredder.c.driver.md#fd_shredder_fini_batch)
    - [`fd_shredder_skip_batch`](fd_shredder.c.driver.md#fd_shredder_skip_batch)


---
### \_internal\_test\_shredder\_count<!-- {{#callable:_internal_test_shredder_count}} -->
The function `_internal_test_shredder_count` tests the correctness of shredder count functions for data shreds, parity shreds, and FEC sets based on different data sizes and shred types.
- **Inputs**:
    - `type`: An unsigned long integer representing the type of shred, which influences the behavior of the shredder functions.
- **Control Flow**:
    - Initialize and test the shredder count functions for zero data size with the given type.
    - Determine if the shred type is chained or resigned and calculate the overhead accordingly.
    - Iterate over data sizes from 1 to 999,999, calculating expected data shreds, parity shreds, and FEC sets using a reference implementation logic.
    - For each data size, verify that the calculated values match the results from the shredder count functions.
    - Determine the maximum data size for which the FEC set count remains 1 and verify shred limits.
    - Initialize a shredder and prepare memory for FEC sets and metadata.
    - Iterate over data sizes from 1 to 99,999, initializing batches and verifying that the shredder produces the expected number of data and parity shreds.
- **Output**: The function does not return a value but performs a series of tests to ensure the shredder count functions produce correct results for various data sizes and shred types.
- **Functions called**:
    - [`fd_shredder_count_data_shreds`](fd_shredder.h.driver.md#fd_shredder_count_data_shreds)
    - [`fd_shredder_count_parity_shreds`](fd_shredder.h.driver.md#fd_shredder_count_parity_shreds)
    - [`fd_shredder_count_fec_sets`](fd_shredder.h.driver.md#fd_shredder_count_fec_sets)
    - [`signer_ctx_init`](#signer_ctx_init)
    - [`fd_shredder_new`](fd_shredder.c.driver.md#fd_shredder_new)
    - [`fd_shredder_join`](fd_shredder.c.driver.md#fd_shredder_join)
    - [`fd_shredder_init_batch`](fd_shredder.c.driver.md#fd_shredder_init_batch)
    - [`fd_shredder_next_fec_set`](fd_shredder.c.driver.md#fd_shredder_next_fec_set)
    - [`fd_shredder_fini_batch`](fd_shredder.c.driver.md#fd_shredder_fini_batch)


---
### test\_shredder\_count<!-- {{#callable:test_shredder_count}} -->
The `test_shredder_count` function tests the internal shredder count functionality using the Merkle data shred type.
- **Inputs**: None
- **Control Flow**:
    - The function calls [`_internal_test_shredder_count`](#_internal_test_shredder_count) with `FD_SHRED_TYPE_MERKLE_DATA` as the argument.
    - No other operations or logic are performed within this function.
- **Output**: The function does not return any value; it is a void function intended for testing purposes.
- **Functions called**:
    - [`_internal_test_shredder_count`](#_internal_test_shredder_count)


---
### test\_shredder\_count\_chained<!-- {{#callable:test_shredder_count_chained}} -->
The function `test_shredder_count_chained` tests the internal shredder counting mechanism for the `FD_SHRED_TYPE_MERKLE_DATA_CHAINED` type.
- **Inputs**: None
- **Control Flow**:
    - The function calls [`_internal_test_shredder_count`](#_internal_test_shredder_count) with the argument `FD_SHRED_TYPE_MERKLE_DATA_CHAINED`.
- **Output**: The function does not return any value; it is a void function used for testing purposes.
- **Functions called**:
    - [`_internal_test_shredder_count`](#_internal_test_shredder_count)


---
### test\_shredder\_count\_resigned<!-- {{#callable:test_shredder_count_resigned}} -->
The function `test_shredder_count_resigned` tests the internal shredder count functionality for the `FD_SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED` type.
- **Inputs**: None
- **Control Flow**:
    - The function `test_shredder_count_resigned` is defined as a static void function, meaning it does not return any value and is only accessible within the file it is defined.
    - It calls another function [`_internal_test_shredder_count`](#_internal_test_shredder_count) with the argument `FD_SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED`.
    - The function [`_internal_test_shredder_count`](#_internal_test_shredder_count) is responsible for testing the shredder count logic for the specified shred type.
- **Output**: The function does not produce any output as it is a void function and is used for testing purposes.
- **Functions called**:
    - [`_internal_test_shredder_count`](#_internal_test_shredder_count)


---
### test\_chained\_merkle\_shreds<!-- {{#callable:test_chained_merkle_shreds}} -->
The `test_chained_merkle_shreds` function tests the creation and validation of chained Merkle shreds, ensuring correct data and parity shred counts, and verifying the final Merkle root.
- **Inputs**: None
- **Control Flow**:
    - Initialize expected and actual Merkle root arrays and a canary value.
    - Decode initial and expected final Merkle roots from hex strings into byte arrays.
    - Set data size to 30000 and verify that the number of data and parity shreds, as well as FEC sets, are as expected.
    - Initialize a performance test entry batch with sequential byte values.
    - Initialize metadata and signer context for the shredder.
    - Create a new shredder instance and join it to a shredder pointer.
    - Allocate memory for data and parity shreds in FEC sets.
    - Fill FEC set memory with the canary value to detect overflows.
    - Loop over slots, skipping slot 11, and set parent offset based on slot number.
    - Within each slot, loop over FEC sets, marking the last set as block complete.
    - Initialize a batch for the shredder, generate the next FEC set, and finalize the batch.
    - Perform checks on each FEC set to ensure data and parity shred counts are correct and that no overflow occurs.
    - Verify that data and parity shred indexes are correct and that shreds are correctly resigned if necessary.
    - Parse each shred to ensure it is valid.
    - After processing all slots and sets, verify that the final chained Merkle root matches the expected value.
- **Output**: The function does not return a value but performs a series of tests to ensure the correctness of the chained Merkle shreds process, including verifying the final Merkle root.
- **Functions called**:
    - [`fd_shredder_count_data_shreds`](fd_shredder.h.driver.md#fd_shredder_count_data_shreds)
    - [`fd_shredder_count_parity_shreds`](fd_shredder.h.driver.md#fd_shredder_count_parity_shreds)
    - [`fd_shredder_count_fec_sets`](fd_shredder.h.driver.md#fd_shredder_count_fec_sets)
    - [`signer_ctx_init`](#signer_ctx_init)
    - [`fd_shredder_new`](fd_shredder.c.driver.md#fd_shredder_new)
    - [`fd_shredder_join`](fd_shredder.c.driver.md#fd_shredder_join)
    - [`fd_shredder_init_batch`](fd_shredder.c.driver.md#fd_shredder_init_batch)
    - [`fd_shredder_next_fec_set`](fd_shredder.c.driver.md#fd_shredder_next_fec_set)
    - [`fd_shredder_fini_batch`](fd_shredder.c.driver.md#fd_shredder_fini_batch)


---
### perf\_test<!-- {{#callable:perf_test}} -->
The `perf_test` function measures the performance of processing a 10 MB entry batch using a shredder, calculating the time taken and data throughput.
- **Inputs**: None
- **Control Flow**:
    - Initialize the `perf_test_entry_batch` array with values from 0 to `PERF_TEST_SZ-1`.
    - Create and initialize a `fd_entry_batch_meta_t` structure to zero.
    - Initialize a `signer_ctx_t` structure with a private key.
    - Create a new shredder instance and join it to a shredder context.
    - Set up a `fd_fec_set_t` structure with memory for data and parity shreds.
    - Start a timer using `fd_log_wallclock`.
    - Loop 100 times to simulate processing the entry batch:
    -   - Initialize the shredder batch with the entry batch data.
    -   - Calculate the number of FEC sets required for the batch size.
    -   - Iterate over each FEC set, processing it with the shredder.
    -   - Finalize the shredder batch.
    - Stop the timer and calculate the elapsed time.
    - Log the performance results in terms of nanoseconds per 10 MB and Gbps throughput.
- **Output**: The function does not return a value but logs the performance metrics of the shredder processing.
- **Functions called**:
    - [`signer_ctx_init`](#signer_ctx_init)
    - [`fd_shredder_new`](fd_shredder.c.driver.md#fd_shredder_new)
    - [`fd_shredder_join`](fd_shredder.c.driver.md#fd_shredder_join)
    - [`fd_shredder_init_batch`](fd_shredder.c.driver.md#fd_shredder_init_batch)
    - [`fd_shredder_count_fec_sets`](fd_shredder.h.driver.md#fd_shredder_count_fec_sets)
    - [`fd_shredder_next_fec_set`](fd_shredder.c.driver.md#fd_shredder_next_fec_set)
    - [`fd_shredder_fini_batch`](fd_shredder.c.driver.md#fd_shredder_fini_batch)


---
### perf\_test2<!-- {{#callable:perf_test2}} -->
The `perf_test2` function performs a performance test on a data shredding process, measuring the time and data throughput for processing a 1 MB entry batch.
- **Inputs**: None
- **Control Flow**:
    - Allocate a new anonymous workspace with a size determined by `fd_cstr_to_shmem_page_sz("gigantic")` and check its validity.
    - Allocate memory for `entry_batch` and `fec_memory` within the workspace, ensuring proper alignment and size.
    - Initialize the `entry_batch` with sequential byte values from 0 to `PERF_TEST2_SZ-1`.
    - Initialize a `fd_entry_batch_meta_t` structure to zero.
    - Initialize a `signer_ctx_t` structure with a test private key.
    - Create and join a new `fd_shredder_t` instance, checking its validity.
    - Set up `fd_fec_set_t` structure to point to the allocated `fec_memory` for data and parity shreds.
    - Start a performance test loop for a fixed number of iterations (30).
    - In each iteration, initialize a shredding batch with the `entry_batch` and process it to count and handle FEC sets.
    - Accumulate the total bytes produced by calculating the size of data and parity shreds processed.
    - Finalize the shredding batch after processing all FEC sets.
    - Measure the elapsed time for the entire process using `fd_log_wallclock()`.
    - Delete the anonymous workspace to free resources.
    - Log the performance results, including time per batch and data throughput in Gbps.
- **Output**: The function does not return any value but logs the performance metrics of the shredding process, including the time taken per 1 MB entry batch and the data throughput in Gbps.
- **Functions called**:
    - [`signer_ctx_init`](#signer_ctx_init)
    - [`fd_shredder_new`](fd_shredder.c.driver.md#fd_shredder_new)
    - [`fd_shredder_join`](fd_shredder.c.driver.md#fd_shredder_join)
    - [`fd_shredder_init_batch`](fd_shredder.c.driver.md#fd_shredder_init_batch)
    - [`fd_shredder_count_fec_sets`](fd_shredder.h.driver.md#fd_shredder_count_fec_sets)
    - [`fd_shredder_next_fec_set`](fd_shredder.c.driver.md#fd_shredder_next_fec_set)
    - [`fd_shredder_fini_batch`](fd_shredder.c.driver.md#fd_shredder_fini_batch)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, performs a series of tests on the shredding and FEC (Forward Error Correction) functionalities, and logs the results.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Call `fd_boot` to initialize the environment with command-line arguments.
    - Verify the maximum BMTREE depth using `FD_TEST`.
    - Check if the size of `fd_shredder_t` matches its footprint and log a warning if not.
    - Execute a series of test functions: [`test_skip_batch`](#test_skip_batch), [`test_shredder_count`](#test_shredder_count), [`test_shredder_count_chained`](#test_shredder_count_chained), [`test_shredder_count_resigned`](#test_shredder_count_resigned), [`test_chained_merkle_shreds`](#test_chained_merkle_shreds), [`perf_test`](#perf_test), and [`perf_test2`](#perf_test2).
    - If `FD_HAS_HOSTED` is defined, execute [`test_shredder_pcap`](#test_shredder_pcap).
    - Log a notice indicating the tests passed.
    - Call `fd_halt` to clean up and terminate the program.
- **Output**: The function returns an integer value `0`, indicating successful execution.
- **Functions called**:
    - [`fd_shredder_footprint`](fd_shredder.h.driver.md#fd_shredder_footprint)
    - [`test_skip_batch`](#test_skip_batch)
    - [`test_shredder_count`](#test_shredder_count)
    - [`test_shredder_count_chained`](#test_shredder_count_chained)
    - [`test_shredder_count_resigned`](#test_shredder_count_resigned)
    - [`test_chained_merkle_shreds`](#test_chained_merkle_shreds)
    - [`perf_test`](#perf_test)
    - [`perf_test2`](#perf_test2)
    - [`test_shredder_pcap`](#test_shredder_pcap)



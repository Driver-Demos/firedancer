# Purpose
This C source code file is designed to test the functionality of a transaction verification system, specifically focusing on the verification of digital signatures within transactions. The file includes several static arrays representing different types of transactions, both valid and invalid, with varying numbers of signatures. These transactions are used as test cases to ensure the robustness and correctness of the verification process. The code is structured to load these transactions, parse them, and then verify their signatures using a series of test functions. Each test function sets up a verification context, loads a transaction, and checks whether the transaction is verified successfully, deduplicated, or fails verification, depending on the test scenario.

The file includes functions for setting up and freeing the verification context, which involves memory allocation and initialization of structures used in the verification process. The [`load_test_txn`](#load_test_txn) function is responsible for converting hexadecimal transaction data into a format suitable for processing. The main function orchestrates the execution of various test scenarios, each designed to validate different aspects of the transaction verification logic, such as handling valid transactions, detecting invalid signatures, and managing deduplication of transactions. The code is part of a larger system, as indicated by the inclusion of external headers and the use of specific data structures and functions like `fd_txn_verify`, which are likely defined elsewhere in the project.
# Imports and Dependencies

---
- `fd_verify_tile.h`
- `../../ballet/hex/fd_hex.h`


# Global Variables

---
### valid\_txn\_1sig
- **Type**: `char *[]`
- **Description**: The `valid_txn_1sig` variable is a static array of strings, each representing a hexadecimal component of a valid transaction with a single signature. This array includes various parts of the transaction such as the transaction ID, signature, and other related data.
- **Use**: This variable is used to load and verify a valid transaction with a single signature in the test functions.


---
### invalid\_txn\_same\_1sig
- **Type**: `char *[]`
- **Description**: The `invalid_txn_same_1sig` is a static array of strings, each representing a hexadecimal component of a transaction. This transaction is designed to be invalid due to all account fields being zeroed, which results in an invalid signature.
- **Use**: This variable is used to test the verification process of transactions, specifically to ensure that transactions with invalid signatures are correctly identified as invalid.


---
### invalid\_txn\_1sig\_same\_64bit
- **Type**: `char *[]`
- **Description**: The `invalid_txn_1sig_same_64bit` is a static array of strings, each representing a hexadecimal component of a transaction. This transaction is designed to be invalid, specifically with a signature that has the same low 64-bit as a valid one, but the overall signature is incorrect.
- **Use**: This variable is used to test the verification process of transactions, ensuring that invalid transactions with specific signature characteristics are correctly identified as invalid.


---
### valid\_txn\_2sigs
- **Type**: `char*[]`
- **Description**: The `valid_txn_2sigs` variable is a static array of strings, each representing a hexadecimal component of a valid transaction with two signatures. This array includes various elements such as transaction identifiers, signatures, and other transaction-related data.
- **Use**: This variable is used to load and verify a transaction with two signatures in the test functions.


---
### invalid\_txn\_2sigs
- **Type**: `char *[]`
- **Description**: The `invalid_txn_2sigs` variable is a static array of strings, each representing a hexadecimal-encoded component of a transaction with two signatures, where one of the signatures is intentionally invalid. This array is used to simulate and test the behavior of the transaction verification system when handling transactions with invalid signatures.
- **Use**: This variable is used in test cases to verify that the transaction verification system correctly identifies and handles transactions with invalid signatures.


# Functions

---
### load\_test\_txn<!-- {{#callable:load_test_txn}} -->
The `load_test_txn` function decodes an array of hexadecimal strings into a byte array and calculates the length of the resulting transaction.
- **Inputs**:
    - `hex`: An array of strings, each representing a hexadecimal value to be decoded.
    - `hex_sz`: The size of the `hex` array, in bytes.
    - `tx_len`: A pointer to an unsigned long where the function will store the length of the decoded transaction in bytes.
- **Control Flow**:
    - Initialize `hex_len` to 0 to keep track of the total length of hexadecimal strings.
    - Iterate over each string in the `hex` array, calculating the total length of all strings combined and storing it in `hex_len`.
    - Set `*tx_len` to half of `hex_len`, as each byte is represented by two hexadecimal characters.
    - Allocate memory for the transaction byte array `tx` with a size of `hex_len / 2`.
    - Reset `hex_len` to 0 to reuse it for tracking the position in the byte array.
    - Iterate over each string in the `hex` array again, decoding each hexadecimal string into its byte representation and storing it in the `tx` array.
    - Return the pointer to the `tx` byte array.
- **Output**: A pointer to a dynamically allocated byte array containing the decoded transaction data.


---
### setup\_verify\_ctx<!-- {{#callable:setup_verify_ctx}} -->
The `setup_verify_ctx` function initializes a verification context by setting up a transaction cache and SHA-512 contexts for signature verification.
- **Inputs**:
    - `ctx`: A pointer to an `fd_verify_ctx_t` structure that will be initialized.
    - `mem`: A pointer to a memory location where the transaction cache will be allocated.
- **Control Flow**:
    - The function begins by zeroing out the `ctx` structure using `fd_memset`.
    - It calculates the alignment and footprint for the transaction cache using `fd_tcache_align` and `fd_tcache_footprint`.
    - If the footprint is invalid (zero), it logs an error and exits.
    - Memory is allocated for the transaction cache using `aligned_alloc`, and the allocation is verified.
    - A new transaction cache is created and joined using `fd_tcache_new` and `fd_tcache_join`, respectively.
    - If joining the transaction cache fails, it logs an error and exits.
    - The transaction cache properties (depth, map count, sync, ring, and map) are set in the `ctx` structure.
    - The transaction cache is reset using `fd_tcache_reset`.
    - Memory is allocated for SHA-512 contexts using `aligned_alloc`.
    - For each SHA-512 context, a new context is created and joined using `fd_sha512_new` and `fd_sha512_join`, respectively.
    - If joining a SHA-512 context fails, it logs an error and exits.
    - The SHA-512 contexts are stored in the `ctx->sha` array.
- **Output**: The function does not return a value; it initializes the `ctx` structure and allocates memory for the transaction cache and SHA-512 contexts.


---
### free\_verify\_ctx<!-- {{#callable:free_verify_ctx}} -->
The `free_verify_ctx` function deallocates memory associated with a verification context and its SHA resources.
- **Inputs**:
    - `ctx`: A pointer to an `fd_verify_ctx_t` structure, which contains the verification context including SHA resources.
    - `mem`: A pointer to a memory block that was previously allocated and needs to be freed.
- **Control Flow**:
    - Call `free(mem)` to deallocate the memory block pointed to by `mem`.
    - Call `free(ctx->sha[0])` to deallocate the memory block associated with the SHA resources, assuming all SHA resources were allocated in a single block and the first element holds the address.
- **Output**: The function does not return any value; it performs memory deallocation.


---
### test\_verify\_success<!-- {{#callable:test_verify_success}} -->
The `test_verify_success` function tests the verification of valid transactions with one or two signatures, ensuring correct deduplication and verification results.
- **Inputs**: None
- **Control Flow**:
    - Initialize a verification context and memory using [`setup_verify_ctx`](#setup_verify_ctx).
    - Load a valid transaction with two signatures using [`load_test_txn`](#load_test_txn) and parse it with `fd_txn_parse`.
    - Verify the transaction using [`fd_txn_verify`](fd_verify_tile.h.driver.md#fd_txn_verify) and check for success with `FD_TEST`.
    - Verify the same transaction again to test deduplication, expecting deduplication results.
    - Load a valid transaction with one signature, parse, and verify it, checking for success and deduplication results.
    - Free the payload and verification context memory.
- **Output**: The function does not return any value; it performs tests and logs results using `FD_TEST` and `FD_LOG_NOTICE`.
- **Functions called**:
    - [`setup_verify_ctx`](#setup_verify_ctx)
    - [`load_test_txn`](#load_test_txn)
    - [`fd_txn_verify`](fd_verify_tile.h.driver.md#fd_txn_verify)
    - [`free_verify_ctx`](#free_verify_ctx)


---
### test\_verify\_invalid\_sigs\_success<!-- {{#callable:test_verify_invalid_sigs_success}} -->
The function `test_verify_invalid_sigs_success` tests the verification of a transaction with invalid signatures to ensure it fails as expected.
- **Inputs**:
    - `void`: This function does not take any input parameters.
- **Control Flow**:
    - Initialize a verification context `ctx` and memory `mem` using [`setup_verify_ctx`](#setup_verify_ctx).
    - Log the start of the test with `FD_LOG_NOTICE`.
    - Load an invalid transaction with two signatures using [`load_test_txn`](#load_test_txn) and parse it into `txn` using `fd_txn_parse`.
    - Call [`fd_txn_verify`](fd_verify_tile.h.driver.md#fd_txn_verify) to verify the transaction, expecting it to fail, and assert the result with `FD_TEST`.
    - Repeat the verification to ensure no deduplication occurs for failed transactions, asserting the result again.
    - Free the allocated payload and verification context memory.
- **Output**: The function does not return any value; it uses assertions to validate the expected behavior of transaction verification.
- **Functions called**:
    - [`setup_verify_ctx`](#setup_verify_ctx)
    - [`load_test_txn`](#load_test_txn)
    - [`fd_txn_verify`](fd_verify_tile.h.driver.md#fd_txn_verify)
    - [`free_verify_ctx`](#free_verify_ctx)


---
### test\_verify\_invalid\_dedup\_success<!-- {{#callable:test_verify_invalid_dedup_success}} -->
The function `test_verify_invalid_dedup_success` tests the transaction verification process, specifically focusing on handling invalid transactions with duplicate signatures and ensuring they are not incorrectly deduplicated.
- **Inputs**:
    - `void`: This function does not take any input parameters.
- **Control Flow**:
    - Initialize a verification context and memory allocation using [`setup_verify_ctx`](#setup_verify_ctx).
    - Load an invalid transaction with a signature identical to a valid one and parse it.
    - Verify the invalid transaction and check that it fails verification using `FD_TEST`.
    - Load and parse a valid transaction with one signature, verify it, and ensure it succeeds without deduplication.
    - Reset the transaction cache to test deduplication behavior.
    - Verify the valid transaction again to ensure it succeeds.
    - Load the invalid transaction again, verify it, and ensure it is deduplicated.
    - Reset the transaction cache again to test with deduplication disabled.
    - Verify the valid transaction with deduplication disabled and ensure it succeeds.
    - Verify the invalid transaction with deduplication disabled and ensure it fails.
    - Free the payload and verification context resources.
- **Output**: The function does not return any value; it uses assertions to validate the expected behavior of transaction verification and deduplication.
- **Functions called**:
    - [`setup_verify_ctx`](#setup_verify_ctx)
    - [`load_test_txn`](#load_test_txn)
    - [`fd_txn_verify`](fd_verify_tile.h.driver.md#fd_txn_verify)
    - [`free_verify_ctx`](#free_verify_ctx)


---
### test\_verify\_invalid\_dedup\_with\_collision\_success<!-- {{#callable:test_verify_invalid_dedup_with_collision_success}} -->
The function `test_verify_invalid_dedup_with_collision_success` tests the verification of transactions with signature collisions, ensuring that invalid transactions with the same low 64-bit signature as a valid one are not deduplicated and fail verification.
- **Inputs**: None
- **Control Flow**:
    - Initialize a verification context and memory using [`setup_verify_ctx`](#setup_verify_ctx).
    - Load a valid transaction with one signature and parse it into a buffer.
    - Verify the valid transaction, expecting a success result.
    - Free the payload memory and load an invalid transaction with the same low 64-bit signature as the valid one.
    - Parse the invalid transaction and verify it, expecting a failure result due to signature verification failure.
    - Free the payload memory and clean up the verification context.
- **Output**: The function does not return any value; it performs assertions to verify expected outcomes of transaction verification.
- **Functions called**:
    - [`setup_verify_ctx`](#setup_verify_ctx)
    - [`load_test_txn`](#load_test_txn)
    - [`fd_txn_verify`](fd_verify_tile.h.driver.md#fd_txn_verify)
    - [`free_verify_ctx`](#free_verify_ctx)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, runs a series of transaction verification tests, logs the results, and then halts the program.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - The function begins by calling `fd_boot` to initialize the environment with the command-line arguments.
    - It then sequentially calls four test functions: [`test_verify_success`](#test_verify_success), [`test_verify_invalid_sigs_success`](#test_verify_invalid_sigs_success), [`test_verify_invalid_dedup_success`](#test_verify_invalid_dedup_success), and [`test_verify_invalid_dedup_with_collision_success`](#test_verify_invalid_dedup_with_collision_success), each of which performs specific transaction verification tests.
    - After the tests, it logs a notice message indicating success with `FD_LOG_NOTICE`.
    - Finally, it calls `fd_halt` to clean up and terminate the program, returning 0 to indicate successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution.
- **Functions called**:
    - [`test_verify_success`](#test_verify_success)
    - [`test_verify_invalid_sigs_success`](#test_verify_invalid_sigs_success)
    - [`test_verify_invalid_dedup_success`](#test_verify_invalid_dedup_success)
    - [`test_verify_invalid_dedup_with_collision_success`](#test_verify_invalid_dedup_with_collision_success)



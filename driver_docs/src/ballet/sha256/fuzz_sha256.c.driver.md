# Purpose
This C source code file is designed to perform fuzz testing on the SHA-256 hashing functionality. It is structured to be used with a fuzzing framework, as indicated by the presence of the [`LLVMFuzzerInitialize`](#LLVMFuzzerInitialize) and [`LLVMFuzzerTestOneInput`](#LLVMFuzzerTestOneInput) functions, which are standard entry points for fuzz testing in LLVM's libFuzzer. The code includes functionality for both single message hashing and batch message hashing using the SHA-256 algorithm. It initializes the necessary data structures and performs hashing operations, ensuring that the computed hashes match expected results. The code also includes assertions to verify the correctness of the hashing process, which helps in identifying any discrepancies during fuzz testing.

The file imports several utility headers and defines constants and static variables to manage the hashing process. It uses the `fd_sha256` and `fd_sha256_batch` functions from the `fd_sha256.h` header to perform the hashing operations. The code is not intended to be a standalone executable but rather a component of a larger testing framework. It does not define public APIs or external interfaces but instead focuses on internal testing of the SHA-256 implementation. The use of assertions and the `FD_FUZZ_MUST_BE_COVERED` macro suggests a focus on ensuring code coverage and robustness during fuzz testing.
# Imports and Dependencies

---
- `assert.h`
- `stdio.h`
- `stdlib.h`
- `../../util/fd_util.h`
- `../../util/sanitize/fd_fuzz.h`
- `fd_sha256.h`


# Global Variables

---
### batch\_sha
- **Type**: `fd_sha256_batch_t[1]`
- **Description**: The `batch_sha` variable is a static array of type `fd_sha256_batch_t` with a single element. It is used to manage the state of a batch SHA-256 hashing operation.
- **Use**: This variable is used to initialize, add messages to, and finalize a batch SHA-256 hashing process.


---
### hash1
- **Type**: `uchar array`
- **Description**: The `hash1` variable is a static array of unsigned characters with a size defined by `FD_SHA256_HASH_SZ`, which represents the size of a SHA-256 hash. It is used to store the result of a SHA-256 hash operation.
- **Use**: `hash1` is used to store the hash result of a single message processed by the `fd_sha256_fini` function.


---
### hash2
- **Type**: `uchar array`
- **Description**: `hash2` is a static array of unsigned characters with a size defined by `FD_SHA256_HASH_SZ`, which represents the size of a SHA-256 hash. It is used to store the result of a SHA-256 hash operation.
- **Use**: `hash2` is used to store the hash result of a single message processed by the `fd_sha256_hash` function.


---
### ref\_hash
- **Type**: `uchar array`
- **Description**: The `ref_hash` is a static array of unsigned characters with a size defined by `FD_SHA256_HASH_SZ`, which represents the size of a SHA-256 hash. It is used to store a reference hash value for comparison purposes during the batch hashing process.
- **Use**: `ref_hash` is used to store the result of a SHA-256 hash computation for comparison against batch hash results to ensure correctness.


---
### hash\_mem
- **Type**: `uchar array`
- **Description**: The `hash_mem` variable is a static array of unsigned characters (uchar) with a size determined by the product of `FD_SHA256_HASH_SZ` and `BATCH_CNT`. It is used to store the hash outputs for a batch of messages processed by the SHA-256 hashing function.
- **Use**: `hash_mem` is used to allocate memory for storing the hash results of multiple messages in a batch processing operation.


---
### hashes
- **Type**: `uchar *`
- **Description**: The `hashes` variable is an array of pointers to unsigned characters, with a size defined by the constant `BATCH_CNT`. Each element in the array is intended to point to a memory location where a SHA-256 hash result is stored.
- **Use**: This variable is used to store the results of batch SHA-256 hash computations, with each pointer in the array pointing to a specific hash result in memory.


---
### messages
- **Type**: `char const *[BATCH_CNT]`
- **Description**: The `messages` variable is a static array of constant character pointers, with a size defined by the macro `BATCH_CNT`. It is used to store pointers to segments of input data for batch processing.
- **Use**: This variable is used to hold pointers to individual message segments for batch SHA-256 hashing operations.


---
### msg\_sizes
- **Type**: `ulong array`
- **Description**: The `msg_sizes` variable is a static array of unsigned long integers with a size defined by the constant `BATCH_CNT`, which is set to 32. This array is used to store the sizes of individual messages when performing batch SHA-256 hashing operations.
- **Use**: `msg_sizes` is used to keep track of the size of each message in a batch during the batch hashing process.


# Functions

---
### LLVMFuzzerInitialize<!-- {{#callable:LLVMFuzzerInitialize}} -->
The `LLVMFuzzerInitialize` function initializes the environment for fuzz testing by setting environment variables, bootstrapping the system, registering a cleanup function, and configuring logging behavior.
- **Inputs**:
    - `argc`: A pointer to an integer representing the number of command-line arguments.
    - `argv`: A pointer to an array of strings representing the command-line arguments.
- **Control Flow**:
    - Set the environment variable 'FD_LOG_BACKTRACE' to '0' to disable backtraces in logs.
    - Call `fd_boot` with `argc` and `argv` to perform system-specific initialization.
    - Register `fd_halt` to be called on program exit using `atexit`.
    - Set the core logging level to 3 using `fd_log_level_core_set`, which will cause the program to crash on warning logs.
    - Return 0 to indicate successful initialization.
- **Output**: The function returns an integer value of 0, indicating successful initialization.


---
### LLVMFuzzerTestOneInput<!-- {{#callable:LLVMFuzzerTestOneInput}} -->
The function `LLVMFuzzerTestOneInput` performs SHA-256 hashing on input data, both as a single message and in batches, to verify the consistency of the hashing process.
- **Inputs**:
    - `fuzz_data`: A pointer to the input data to be hashed, represented as an array of unsigned characters.
    - `fuzz_sz`: The size of the input data in bytes, represented as an unsigned long integer.
- **Control Flow**:
    - The function begins by casting the input data to a character pointer for single message hashing.
    - It initializes a SHA-256 context and processes the input data to produce a hash, storing the result in `hash1`.
    - The function then directly hashes the input data again using a different method, storing the result in `hash2`, and asserts that both hashes are identical.
    - If the input size is greater than or equal to `BATCH_CNT`, the function proceeds to batch hashing.
    - It initializes a batch SHA-256 context and divides the input data into `BATCH_CNT` segments, each of which is hashed individually.
    - Each segment's hash is stored in a pre-allocated memory space, and the function asserts that each batch hash matches the reference hash computed separately.
    - If the input size is less than `BATCH_CNT`, the function simply marks the code path as covered without performing batch hashing.
    - The function returns 0 to indicate successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution without errors.
- **Functions called**:
    - [`fd_sha256_init`](fd_sha256.c.driver.md#fd_sha256_init)
    - [`fd_sha256_append`](fd_sha256.c.driver.md#fd_sha256_append)
    - [`fd_sha256_fini`](fd_sha256.c.driver.md#fd_sha256_fini)
    - [`fd_sha256_hash`](fd_sha256.c.driver.md#fd_sha256_hash)
    - [`fd_sha256_batch_add`](fd_sha256.h.driver.md#fd_sha256_batch_add)
    - [`fd_sha256_batch_fini`](fd_sha256.h.driver.md#fd_sha256_batch_fini)



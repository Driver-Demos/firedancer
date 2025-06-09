# Purpose
This C source code file is designed to test and benchmark the Proof of History (PoH) functionality, which is a cryptographic technique used to verify the passage of time between events. The file includes several test functions that validate the behavior of the `fd_poh_append` and `fd_poh_mixin` functions against expected outcomes derived from a simple SHA-256 hashing API. The tests ensure that these functions behave correctly under various conditions, such as zero iterations, single iterations, and with mixin values. Additionally, the file defines test vectors that simulate real-world scenarios, such as those from the Solana blockchain, to further validate the PoH implementation.

The file also includes a benchmarking function, [`bench_poh_sequential`](#bench_poh_sequential), which measures the performance of the `fd_poh_append` function by calculating the number of hashes processed per second. This is crucial for understanding the efficiency of the PoH implementation in a sequential processing context. The main function orchestrates the execution of these tests and benchmarks, ensuring that the PoH functionality is both correct and performant. The inclusion of test vectors and benchmarking highlights the file's role in both validation and performance assessment of the PoH system.
# Imports and Dependencies

---
- `../fd_ballet.h`


# Global Variables

---
### solana\_mainnet\_block\_0\_steps
- **Type**: `fd_poh_test_step_t const[]`
- **Description**: The `solana_mainnet_block_0_steps` is a static constant array of `fd_poh_test_step_t` structures. Each element in the array represents a step in the proof of history (PoH) process for Solana's mainnet block 0, with the first step having 800,000 iterations and the second step indicating the end of the list with -1.
- **Use**: This variable is used to define the sequence of steps for testing the PoH process for Solana's mainnet block 0.


---
### solana\_mainnet\_block\_1\_steps
- **Type**: ``fd_poh_test_step_t const[]``
- **Description**: The `solana_mainnet_block_1_steps` is a static constant array of `fd_poh_test_step_t` structures, which define a sequence of steps for processing a Solana mainnet block. Each step in the array can either specify a number of iterations for the `fd_poh_append` function or a mixin value for the `fd_poh_mixin` function. The array ends with a step where `n` is set to -1, indicating the end of the sequence.
- **Use**: This variable is used to define the sequence of operations for processing Solana mainnet block 1 in the `test_poh_vector` function.


---
### poh\_test\_vectors
- **Type**: ``fd_poh_test_vector_t const[]``
- **Description**: The `poh_test_vectors` is a static constant array of `fd_poh_test_vector_t` structures. Each element in the array represents a test vector for the Proof of History (PoH) mechanism, containing a name, pre-computed hash values (`pre` and `post`), and a sequence of steps (`steps`) to be executed. The array is terminated by an entry with a `name` set to `NULL`, indicating the end of the test vectors.
- **Use**: This variable is used to store predefined test vectors for validating the correctness of the PoH implementation by comparing the computed hash results against expected values.


# Data Structures

---
### fd\_poh\_test\_step
- **Type**: `struct`
- **Members**:
    - `mixin`: An array of unsigned characters used as a value to pass to the fd_poh_mixin function, aligned to 32 bytes.
    - `n`: An integer representing the number of iterations for fd_poh_append, with special values 0 for calling fd_poh_mixin and -1 for indicating the end of the list.
- **Description**: The `fd_poh_test_step` structure is designed to represent a single step in a sequence of operations for testing the Proof of History (PoH) functionality. It contains a `mixin` field, which is an array of bytes used in the `fd_poh_mixin` function, and an `n` field, which determines the number of iterations for the `fd_poh_append` function. The `n` field also has special values: 0 to trigger a call to `fd_poh_mixin` instead of `fd_poh_append`, and -1 to signify the end of the test steps list. This structure is used in conjunction with other structures to define a series of operations that simulate the PoH process.


---
### fd\_poh\_test\_step\_t
- **Type**: `struct`
- **Members**:
    - `mixin`: An array of unsigned characters used as a value to pass to fd_poh_mixin, aligned to 32 bytes.
    - `n`: An integer indicating the number of iterations for fd_poh_append, or a special value to indicate calling fd_poh_mixin or the end of the list.
- **Description**: The `fd_poh_test_step_t` structure is used to define a step in a sequence of operations for testing the Proof of History (PoH) functionality. Each step can either specify a number of iterations for the `fd_poh_append` function or provide a mixin value for the `fd_poh_mixin` function. The `n` field determines the operation to perform, with a value of 0 indicating a mixin operation, a positive value indicating the number of append iterations, and -1 indicating the end of the sequence. The `mixin` field holds the data to be used in mixin operations, ensuring alignment for efficient processing.


---
### fd\_poh\_test\_vector
- **Type**: `struct`
- **Members**:
    - `pre`: An array of 32 unsigned characters, aligned to 32 bytes, representing the initial state before processing.
    - `post`: An array of 32 unsigned characters, aligned to 32 bytes, representing the expected state after processing.
    - `name`: A constant character pointer to a string that names the test vector.
    - `steps`: A constant pointer to an array of `fd_poh_test_step_t` structures, defining the sequence of steps to be executed.
- **Description**: The `fd_poh_test_vector` structure is designed to encapsulate a test vector for the Proof of History (PoH) process, including the initial and expected final states, a descriptive name, and a sequence of steps to be executed. Each step in the sequence can either append a number of iterations or mix in a specific value, allowing for comprehensive testing of the PoH functionality.


---
### fd\_poh\_test\_vector\_t
- **Type**: `struct`
- **Members**:
    - `pre`: An array of 32 unsigned characters, aligned to 32 bytes, representing the initial state before processing steps.
    - `post`: An array of 32 unsigned characters, aligned to 32 bytes, representing the expected final state after processing steps.
    - `name`: A constant character pointer to a string that names the test vector.
    - `steps`: A constant pointer to an array of `fd_poh_test_step_t` structures, defining the sequence of operations to be applied.
- **Description**: The `fd_poh_test_vector_t` structure is used to define a test vector for verifying the correctness of Proof of History (PoH) operations. It contains a pre-state (`pre`), a post-state (`post`), a name for identification, and a sequence of steps (`steps`) that describe the operations to be performed on the pre-state to achieve the post-state. This structure is crucial for testing and validating the PoH implementation against known expected outcomes.


# Functions

---
### test\_poh\_append\_nop<!-- {{#callable:test_poh_append_nop}} -->
The function `test_poh_append_nop` verifies that calling `fd_poh_append` with zero iterations does not alter the state of the PoH (Proof of History) hash.
- **Inputs**: None
- **Control Flow**:
    - Initialize an array `poh` of size `FD_SHA256_HASH_SZ` with zeros.
    - Create a pattern `want` by filling it with values starting from 0x40 to 0x40 + `FD_SHA256_HASH_SZ`.
    - Copy the pattern `want` into `poh` using `fd_memcpy`.
    - Call `fd_poh_append` with `poh` and zero iterations.
    - Use `FD_TEST` to assert that `poh` remains unchanged by comparing it with `want` using `memcmp`.
- **Output**: The function does not return any value; it performs an assertion to ensure the PoH state is unchanged.


---
### test\_poh\_append\_one<!-- {{#callable:test_poh_append_one}} -->
The function `test_poh_append_one` verifies that a single round of the `fd_poh_append` function produces the same result as a simple SHA-256 hashing operation.
- **Inputs**: None
- **Control Flow**:
    - Initialize an array `pre` with a pattern of bytes starting from 0x40.
    - Copy the `pre` array into a `poh` array and perform one round of `fd_poh_append` on `poh`.
    - Initialize a SHA-256 context `sha`, append the `pre` array to it, and finalize the hash to get the `expected` result.
    - Compare the `poh` array with the `expected` hash result.
    - If they do not match, log an error with the differing values.
- **Output**: The function does not return a value but logs an error if the `poh` result does not match the expected SHA-256 hash.


---
### test\_poh\_mixin<!-- {{#callable:test_poh_mixin}} -->
The `test_poh_mixin` function verifies that the `fd_poh_mixin` function produces the same result as a direct SHA-256 hash of concatenated input patterns.
- **Inputs**: None
- **Control Flow**:
    - Initialize an array `pre` with a pattern of bytes starting from 0x40.
    - Initialize an array `mixin` with a pattern of bytes starting from 0x60.
    - Copy the `pre` array into a `poh` array and apply the `fd_poh_mixin` function with `mixin` as the argument.
    - Initialize a SHA-256 context and append both `pre` and `mixin` to it, then finalize the hash to get the `expected` result.
    - Compare the `poh` result from `fd_poh_mixin` with the `expected` SHA-256 hash result.
    - Log an error if the `poh` result does not match the `expected` result.
- **Output**: The function does not return a value but logs an error if the `fd_poh_mixin` result does not match the expected SHA-256 hash.


---
### test\_poh\_vector<!-- {{#callable:test_poh_vector}} -->
The `test_poh_vector` function validates a sequence of Proof of History (PoH) operations against expected results for a given test vector.
- **Inputs**:
    - `t`: A pointer to a constant `fd_poh_test_vector_t` structure containing the initial state (`pre`), expected final state (`post`), a name for the test, and a sequence of steps (`steps`) to perform.
- **Control Flow**:
    - Initialize a 32-byte array `poh` with the `pre` value from the test vector `t`.
    - Iterate over each step in the `steps` array of the test vector until a step with `n` less than 0 is encountered.
    - For each step, if `n` is 0, call `fd_poh_mixin` with `poh` and the step's `mixin` value; otherwise, call `fd_poh_append` with `poh` and `n`.
    - After processing all steps, compare the resulting `poh` with the `post` value from the test vector.
    - Log an error message if the `poh` does not match the `post` value, otherwise log a success message.
- **Output**: The function does not return a value but logs a success or failure message based on whether the computed PoH state matches the expected `post` state.


---
### bench\_poh\_sequential<!-- {{#callable:bench_poh_sequential}} -->
The `bench_poh_sequential` function benchmarks the performance of the Proof of History (PoH) append operation by measuring the time taken to perform a large number of sequential hash operations.
- **Inputs**: None
- **Control Flow**:
    - Initialize a zeroed array `poh` of size `FD_SHA256_HASH_SZ` to store the hash state.
    - Set `batch_sz` to 1024, which determines the number of hashes per append operation.
    - Perform a warmup loop with 1000 iterations, calling `fd_poh_append` with `poh` and `batch_sz` to prepare the system for accurate benchmarking.
    - Record the start time using `fd_log_wallclock`, execute the warmup loop, and then calculate the elapsed time by subtracting the start time from the current time.
    - Perform the actual benchmark with 100,000 iterations, again calling `fd_poh_append` with `poh` and `batch_sz`, and measure the elapsed time similarly.
    - Calculate the total number of hashes performed as `iter * batch_sz`.
    - Convert the elapsed time from nanoseconds to seconds.
    - Log the performance in megahashes per second (MH/s) using `FD_LOG_NOTICE`.
- **Output**: The function does not return any value; it logs the performance result of the PoH append operation in MH/s.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, runs a series of tests and benchmarks for Proof of History (PoH) operations, and then terminates the program.
- **Inputs**:
    - `argc`: The count of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Call `fd_boot` to initialize the environment with command-line arguments.
    - Execute [`test_poh_append_nop`](#test_poh_append_nop) to verify that zero iterations of PoH append is a no-op.
    - Execute [`test_poh_append_one`](#test_poh_append_one) to verify that one iteration of PoH append matches the simple hashing API.
    - Execute [`test_poh_mixin`](#test_poh_mixin) to verify that PoH mixin matches the simple hashing API.
    - Iterate over `poh_test_vectors` and call [`test_poh_vector`](#test_poh_vector) for each test vector to validate PoH operations against expected results.
    - Execute [`bench_poh_sequential`](#bench_poh_sequential) to benchmark the performance of sequential PoH appends.
    - Log a notice indicating all tests passed.
    - Call `fd_halt` to terminate the program.
- **Output**: The function returns an integer value `0`, indicating successful execution.
- **Functions called**:
    - [`test_poh_append_nop`](#test_poh_append_nop)
    - [`test_poh_append_one`](#test_poh_append_one)
    - [`test_poh_mixin`](#test_poh_mixin)
    - [`test_poh_vector`](#test_poh_vector)
    - [`bench_poh_sequential`](#bench_poh_sequential)



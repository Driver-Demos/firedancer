# Purpose
This C source code file is designed to test and benchmark the SHA-512 hashing algorithm implementation. It includes various components that facilitate the testing of SHA-512 functionality, including single-shot, incremental, and batched hashing processes. The file imports necessary headers and test vectors, and it conditionally includes additional test vectors if the `HAS_CAVP_TEST_VECTORS` macro is defined. The code defines several static assertions to ensure that the alignment and footprint of the SHA-512 structures are as expected, which is crucial for maintaining consistency and correctness in memory usage.

The main function initializes the necessary components, such as random number generators and memory for SHA-512 operations, and then proceeds to test the SHA-512 implementation against predefined test vectors. It verifies the correctness of the hashing process by comparing the computed hashes with expected values. The code also benchmarks the performance of the SHA-512 implementation by measuring the throughput of hashing operations on different data sizes and configurations, including single, incremental, and batched hashing. The file concludes with cleanup operations to release allocated resources. This file is a comprehensive test suite for validating and measuring the performance of a SHA-512 hashing implementation, ensuring its reliability and efficiency.
# Imports and Dependencies

---
- `../fd_ballet.h`
- `fd_sha512_test_vector.c`
- `cavp/sha512_short.inc`
- `cavp/sha512_long.inc`


# Functions

---
### test\_sha512\_vectors<!-- {{#callable:test_sha512_vectors}} -->
The function `test_sha512_vectors` tests the SHA-512 hashing implementation against a set of test vectors using single-shot, incremental, and streamlined hashing methods.
- **Inputs**:
    - `vec`: A pointer to an array of `fd_sha512_test_vector_t` structures, each containing a message, its size, and the expected hash.
    - `sha`: A pointer to an `fd_sha512_t` structure used for SHA-512 hashing operations.
    - `rng`: A pointer to an `fd_rng_t` structure used for generating random numbers during incremental hashing tests.
- **Control Flow**:
    - Initialize a 64-byte hash buffer aligned to 64 bytes.
    - Iterate over each test vector until a null message is encountered.
    - For each vector, extract the message, its size, and the expected hash.
    - Perform single-shot hashing: initialize, append the message, finalize, and compare the result with the expected hash.
    - If the hash does not match the expected value, log an error with the size and both the obtained and expected hashes.
    - Perform incremental hashing: initialize, append the message in random-sized chunks, finalize, and compare the result with the expected hash.
    - If the hash does not match the expected value, log an error with the size and both the obtained and expected hashes.
    - Perform streamlined hashing using a single function call and compare the result with the expected hash.
    - If the hash does not match the expected value, log an error with the size and both the obtained and expected hashes.
- **Output**: The function does not return a value but logs errors if any of the hash computations do not match the expected results.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes and tests the SHA-512 hashing functionality, including random vector tests, batch processing, benchmarking, and cleanup.
- **Inputs**:
    - `argc`: The number of command-line arguments.
    - `argv`: An array of command-line argument strings.
- **Control Flow**:
    - Initialize the environment and random number generator.
    - Verify SHA-512 alignment and footprint constants.
    - Test SHA-512 object creation and joining with various memory alignments.
    - Run tests on random SHA-512 vectors using the [`test_sha512_vectors`](#test_sha512_vectors) function.
    - Perform batch processing tests with random data and verify the results.
    - Optionally test NIST CAVP message fixtures if available.
    - Benchmark SHA-512 hashing performance on small and large data sizes using incremental, streamlined, and batched methods.
    - Test SHA-512 hashing on a large input size and verify the result against a known hash.
    - Clean up by leaving and deleting SHA-512 and RNG objects.
    - Log a success message and halt the program.
- **Output**: The function returns an integer status code, 0 for successful execution.
- **Functions called**:
    - [`test_sha512_vectors`](#test_sha512_vectors)



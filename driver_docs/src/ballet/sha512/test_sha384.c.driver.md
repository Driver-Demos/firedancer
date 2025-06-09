# Purpose
This C source code file is designed to perform unit testing for the SHA-384 cryptographic hash function implementation. It includes a series of static assertions to verify the alignment and footprint of the `fd_sha384_t` data structure, ensuring that it meets the expected specifications. The code is structured to conditionally compile based on the presence of `HAS_CAVP_TEST_VECTORS`, which indicates whether the CAVP (Cryptographic Algorithm Validation Program) test vectors are available for use. If these vectors are available, the code defines a structure for test vectors and includes test data from external files. The main functionality of the code is to validate the SHA-384 implementation against known test vectors, checking both single-shot and incremental hashing processes, and ensuring that the computed hashes match the expected results.

The file serves as an executable test suite, with a [`main`](#main) function that initializes necessary components, such as a random number generator and SHA-384 context, and then runs the tests using the provided CAVP vectors. It includes comprehensive error logging to report any discrepancies between computed and expected hash values. The code also includes cleanup routines to properly release resources after testing. If the `HAS_CAVP_TEST_VECTORS` is not defined, the code will log a warning and skip the tests, indicating that the test vectors are required for execution. This file is crucial for validating the correctness and reliability of the SHA-384 implementation in the broader software system.
# Imports and Dependencies

---
- `../fd_ballet.h`
- `cavp/sha384_short.inc`
- `cavp/sha384_long.inc`


# Data Structures

---
### fd\_sha384\_test\_vector
- **Type**: `struct`
- **Members**:
    - `msg`: A pointer to a constant character array representing the message to be hashed.
    - `sz`: An unsigned long integer representing the size of the message.
    - `hash`: An array of unsigned characters storing the computed SHA-384 hash of the message.
- **Description**: The `fd_sha384_test_vector` structure is used to represent a test vector for SHA-384 hashing, containing a message, its size, and the expected hash result. It is primarily used in testing scenarios to verify the correctness of SHA-384 hash computations by comparing the computed hash against the expected hash stored in the structure.


---
### fd\_sha384\_test\_vector\_t
- **Type**: `struct`
- **Members**:
    - `msg`: A pointer to a constant character array representing the message to be hashed.
    - `sz`: An unsigned long integer representing the size of the message.
    - `hash`: An array of unsigned characters storing the expected SHA-384 hash of the message.
- **Description**: The `fd_sha384_test_vector_t` structure is used to represent test vectors for SHA-384 hashing, containing a message, its size, and the expected hash result. It is primarily used in testing scenarios to verify the correctness of SHA-384 hash computations by comparing the computed hash against the expected hash stored in the structure.


# Functions

---
### test\_sha384\_vectors<!-- {{#callable:test_sha384_vectors}} -->
The `test_sha384_vectors` function tests the SHA-384 hashing implementation against known test vectors using single-shot, incremental, and streamlined hashing methods.
- **Inputs**:
    - `vec`: A pointer to an array of `fd_sha384_test_vector_t` structures, each containing a message, its size, and the expected SHA-384 hash.
    - `sha`: A pointer to an `fd_sha384_t` structure used for SHA-384 hashing operations.
    - `rng`: A pointer to an `fd_rng_t` structure used for generating random numbers during incremental hashing tests.
- **Control Flow**:
    - Initialize a buffer `hash` to store the computed hash, aligned to 64 bytes.
    - Iterate over each test vector in `vec` until a null message is encountered.
    - For each vector, extract the message, its size, and the expected hash.
    - Perform single-shot hashing by initializing the SHA-384 context, appending the message, finalizing the hash, and comparing it to the expected hash.
    - If the computed hash does not match the expected hash, log an error with the size and both hashes.
    - Perform incremental hashing by initializing the SHA-384 context, then repeatedly appending random-sized chunks of the message, optionally appending zero-length data, and finalizing the hash.
    - Compare the incremental hash to the expected hash and log an error if they do not match.
    - Perform streamlined hashing by directly hashing the message and comparing the result to the expected hash, logging an error if they do not match.
- **Output**: The function does not return a value but logs errors if any of the computed hashes do not match the expected hashes.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment and logs a warning if the `HAS_CAVP_TEST_VECTORS` flag is not set, then halts execution.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Call `fd_boot` to initialize the environment with command-line arguments.
    - Log a warning message indicating that the unit test requires `HAS_CAVP_TEST_VECTORS`.
    - Call `fd_halt` to terminate the program.
    - Return 0 to indicate successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution.



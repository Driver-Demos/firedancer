# Purpose
This C source code file is an executable program designed to test the implementation of HMAC (Hash-based Message Authentication Code) using SHA-256, SHA-384, and SHA-512 hash functions. The file includes necessary headers for HMAC and SHA implementations and defines a structure `fd_hmac_test_vector` to hold test vectors, which consist of keys, messages, and expected hash outputs. The test vectors are based on RFC 2104, a standard for HMAC, and are used to verify the correctness of the HMAC implementations for each SHA variant.

The main function iterates over predefined test vectors for each SHA variant, computes the HMAC for each vector, and compares the computed hash with the expected hash. If the computed hash does not match the expected hash, an error is logged. The program uses macros for logging and testing, such as `FD_TEST`, `FD_LOG_ERR`, and `FD_LOG_INFO`, to provide feedback on the test results. The file is structured to ensure that each HMAC variant is tested independently, and it logs a success message if all tests pass. This file is crucial for validating the integrity and correctness of the HMAC implementations in the broader software system.
# Imports and Dependencies

---
- `fd_hmac.h`
- `../sha256/fd_sha256.h`
- `../sha512/fd_sha512.h`


# Global Variables

---
### fd\_hmac\_sha256\_test\_vector
- **Type**: ``fd_hmac_test_vector_t const[]``
- **Description**: The `fd_hmac_sha256_test_vector` is a static constant array of `fd_hmac_test_vector_t` structures, each containing test vectors for HMAC-SHA256 as defined in RFC 2104. Each element in the array includes a key, a message, and the expected hash result for the HMAC-SHA256 operation.
- **Use**: This variable is used to store predefined test vectors for validating the correctness of the HMAC-SHA256 implementation.


---
### fd\_hmac\_sha384\_test\_vector
- **Type**: `fd_hmac_test_vector_t const[]`
- **Description**: The `fd_hmac_sha384_test_vector` is an array of `fd_hmac_test_vector_t` structures, each containing test vectors for HMAC-SHA384 as specified in RFC 2104. Each element in the array includes a key, message, and the expected hash result for the HMAC-SHA384 operation.
- **Use**: This variable is used to validate the correctness of the HMAC-SHA384 implementation by comparing computed hash results against expected values.


---
### fd\_hmac\_sha512\_test\_vector
- **Type**: ``fd_hmac_test_vector_t const[]``
- **Description**: The `fd_hmac_sha512_test_vector` is an array of `fd_hmac_test_vector_t` structures, each containing test vectors for HMAC-SHA512 as defined by RFC 2104. Each element in the array includes a key, message, and the expected hash result for the HMAC-SHA512 operation. The array is terminated by a zero-initialized structure to indicate the end of the test vectors.
- **Use**: This variable is used to provide test vectors for validating the correctness of the HMAC-SHA512 implementation.


# Data Structures

---
### fd\_hmac\_test\_vector
- **Type**: `struct`
- **Members**:
    - `key`: A pointer to a constant character array representing the HMAC key.
    - `key_sz`: An unsigned long representing the size of the HMAC key.
    - `msg`: A pointer to a constant character array representing the message to be hashed.
    - `msg_sz`: An unsigned long representing the size of the message.
    - `hash`: An array of unsigned characters storing the resulting hash, with a fixed size of 64 bytes.
- **Description**: The `fd_hmac_test_vector` structure is designed to hold test vectors for HMAC (Hash-based Message Authentication Code) operations. It contains fields for the key and message, along with their respective sizes, and a buffer to store the resulting hash. This structure is used to verify the correctness of HMAC implementations by comparing computed hashes against expected values.


---
### fd\_hmac\_test\_vector\_t
- **Type**: `struct`
- **Members**:
    - `key`: A pointer to a constant character array representing the HMAC key.
    - `key_sz`: An unsigned long integer representing the size of the HMAC key.
    - `msg`: A pointer to a constant character array representing the message to be hashed.
    - `msg_sz`: An unsigned long integer representing the size of the message.
    - `hash`: An array of unsigned characters storing the resulting hash, with a fixed size of 64 bytes.
- **Description**: The `fd_hmac_test_vector_t` structure is designed to hold test vectors for HMAC (Hash-based Message Authentication Code) operations. It contains fields for the key and message, along with their respective sizes, and a field for the expected hash result. This structure is used to verify the correctness of HMAC implementations by comparing computed hashes against known expected values.


# Functions

---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, performs HMAC-SHA256, HMAC-SHA384, and HMAC-SHA512 tests using predefined test vectors, and logs the results.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Call `fd_boot` to initialize the environment with command-line arguments.
    - Declare a 64-byte aligned array `hash` to store the computed hash values.
    - Iterate over `fd_hmac_sha256_test_vector` to perform HMAC-SHA256 tests:
    -   - Extract key, key size, message, message size, and expected hash from the test vector.
    -   - Compute the HMAC-SHA256 hash using `fd_hmac_sha256` and compare it with the expected hash.
    -   - Log an error if the computed hash does not match the expected hash.
    - Log success message for HMAC-SHA256 tests if all tests pass.
    - Iterate over `fd_hmac_sha384_test_vector` to perform HMAC-SHA384 tests following similar steps as HMAC-SHA256.
    - Log success message for HMAC-SHA384 tests if all tests pass.
    - Iterate over `fd_hmac_sha512_test_vector` to perform HMAC-SHA512 tests following similar steps as HMAC-SHA256.
    - Log success message for HMAC-SHA512 tests if all tests pass.
    - Log a notice indicating all tests passed.
    - Call `fd_halt` to clean up and terminate the program.
    - Return 0 to indicate successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution.



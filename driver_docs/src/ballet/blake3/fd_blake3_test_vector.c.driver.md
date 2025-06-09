# Purpose
This C source code file defines a set of test vectors for the BLAKE3 cryptographic hash function. The file is not intended to be compiled directly but serves as a data source for testing the correctness of BLAKE3 implementations. It includes a structure `fd_blake3_test_vector` that holds a message, its size, and the expected hash output. The test vectors are derived from standard test vectors available in a JSON format from the BLAKE3 team's repository, ensuring that they are consistent with the official specifications.

The file defines an array of `fd_blake3_test_vector_t` structures, each initialized with a specific message and its corresponding hash value. The messages range from empty strings to sequences of bytes of varying lengths, and the hash values are represented as arrays of 32 unsigned characters. The use of a macro `_(v)` simplifies the representation of hexadecimal values in the hash arrays. The array is terminated with a NULL entry to indicate the end of the test vectors. This file is typically used in conjunction with a BLAKE3 implementation to verify that the hash function produces the expected outputs for the given inputs, thus serving as a critical component in the validation and testing of cryptographic software.
# Global Variables

---
### fd\_blake3\_test\_vector
- **Type**: ``fd_blake3_test_vector_t const[]``
- **Description**: The `fd_blake3_test_vector` is a static constant array of `fd_blake3_test_vector_t` structures, which are used to store test vectors for the BLAKE3 cryptographic hash function. Each element in the array contains a message, its size, and the corresponding hash value. The array is terminated with a null message to indicate the end of the test vectors.
- **Use**: This variable is used to provide predefined test vectors for verifying the correctness of the BLAKE3 hash function implementation.


# Data Structures

---
### fd\_blake3\_test\_vector
- **Type**: `struct`
- **Members**:
    - `msg`: A pointer to a constant character array representing the message to be hashed.
    - `sz`: An unsigned long integer representing the size of the message.
    - `hash`: An array of 32 unsigned characters representing the BLAKE3 hash of the message.
- **Description**: The `fd_blake3_test_vector` structure is used to store test vectors for the BLAKE3 cryptographic hash function. Each instance of this structure contains a message, its size, and the corresponding 32-byte hash output. This structure is primarily used for testing and validation purposes, ensuring that the BLAKE3 implementation produces the expected hash results for given input messages.


---
### fd\_blake3\_test\_vector\_t
- **Type**: `struct`
- **Members**:
    - `msg`: A pointer to a constant character array representing the message to be hashed.
    - `sz`: An unsigned long integer representing the size of the message in bytes.
    - `hash`: An array of 32 unsigned characters representing the BLAKE3 hash of the message.
- **Description**: The `fd_blake3_test_vector_t` structure is used to store test vectors for the BLAKE3 cryptographic hash function. It contains a message, its size, and the corresponding hash value. This structure is part of a set of predefined test vectors used to verify the correctness of BLAKE3 implementations by comparing the computed hash against the expected hash stored in the structure.



# Purpose
This C source code file is designed to provide a set of test vectors for verifying the correctness of SHA-256 hash implementations. The file contains a static array of structures, each representing a test vector with a message, its size, and the corresponding SHA-256 hash. These test vectors were precomputed using the OpenSSL SHA-256 implementation on a Red Hat Enterprise Linux 8 system. The file is not intended to be compiled directly; instead, it serves as a reference or a data source for testing purposes in other programs or libraries that implement SHA-256 hashing.

The primary technical component of this file is the `fd_sha256_test_vector_t` structure, which holds the message, its length, and the expected hash value. The array `fd_sha256_test_vector` is populated with multiple test cases, each containing a different message and its corresponding hash. The file also includes a commented-out section that describes how the input test strings were generated, although this code is not active. This file does not define any public APIs or external interfaces; it is a standalone data file meant to be included in other projects for testing the accuracy of SHA-256 hash functions.
# Global Variables

---
### \_sz
- **Type**: `double`
- **Description**: The variable `_sz` is a global variable of type `double` initialized to `0.f`. It is used in a loop to generate test strings for OpenSSL by incrementally increasing its value until it reaches 4096.
- **Use**: `_sz` is used to determine the size of the test strings generated in the loop.


---
### fac
- **Type**: `double`
- **Description**: The variable `fac` is a global variable of type `double` that is initialized to the square root of the square root of 2. This value is approximately 1.189207115002721.
- **Use**: It is used as a factor to increment the size `_sz` in a loop that generates test strings for OpenSSL.


---
### fd\_sha256\_test\_vector
- **Type**: `fd_sha256_test_vector_t const[]`
- **Description**: The `fd_sha256_test_vector` is a static constant array of `fd_sha256_test_vector_t` structures. Each element in the array represents a test vector for SHA-256 hashing, containing a message string, its length, and the corresponding SHA-256 hash value. The array is terminated with a null message and a zero-length entry to indicate the end of the test vectors.
- **Use**: This variable is used to store predefined test vectors for verifying the correctness of SHA-256 hash implementations.


# Data Structures

---
### fd\_sha256\_test\_vector
- **Type**: `struct`
- **Members**:
    - `msg`: A pointer to a constant character string representing the message to be hashed.
    - `sz`: An unsigned long integer representing the size of the message.
    - `hash`: An array of 32 unsigned characters representing the SHA-256 hash of the message.
- **Description**: The `fd_sha256_test_vector` structure is designed to hold test vectors for SHA-256 hashing. It contains a message, its size, and the corresponding SHA-256 hash. This structure is used to verify the correctness of SHA-256 implementations by comparing the computed hash of the message with the expected hash stored in the structure.


---
### fd\_sha256\_test\_vector\_t
- **Type**: `struct`
- **Members**:
    - `msg`: A pointer to a constant character string representing the message to be hashed.
    - `sz`: An unsigned long integer representing the size of the message in bytes.
    - `hash`: An array of 32 unsigned characters representing the SHA-256 hash of the message.
- **Description**: The `fd_sha256_test_vector_t` structure is designed to hold test vectors for SHA-256 hashing. It contains a message, its size, and the corresponding SHA-256 hash. This structure is used to verify the correctness of SHA-256 implementations by comparing the computed hash of the message with the precomputed hash stored in the structure.



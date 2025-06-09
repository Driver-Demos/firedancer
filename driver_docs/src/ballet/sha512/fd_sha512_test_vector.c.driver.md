# Purpose
This C source code file is designed to provide a set of test vectors for verifying the correctness of SHA-512 hash computations. The file contains a static array of structures, `fd_sha512_test_vector_t`, each of which holds a message string, its length, and the corresponding SHA-512 hash. These test vectors were precomputed using the OpenSSL SHA-512 implementation on a Red Hat Enterprise Linux 8 system. The file is not intended to be compiled directly; instead, it serves as a reference or a data source for testing the accuracy of SHA-512 implementations in other programs or libraries.

The code includes a commented-out section that describes how the input test strings were generated using a random number generator. This section is not meant to be executed but provides context on how the test data was created. The main component of the file is the array of `fd_sha512_test_vector_t` structures, which is defined as a constant and static, indicating that it is intended for internal use within a single translation unit. The file does not define any public APIs or external interfaces, and its primary purpose is to serve as a data repository for validating SHA-512 hash functions.
# Global Variables

---
### \_sz
- **Type**: `double`
- **Description**: The variable `_sz` is a global variable of type `double` initialized to `0.f`. It is used in a loop to generate test strings for OpenSSL by incrementally increasing its value.
- **Use**: `_sz` is used to control the size of the generated test strings in a loop, starting from 0 and increasing based on a factor.


---
### fac
- **Type**: `double`
- **Description**: The variable `fac` is a global variable of type `double` that is initialized to the square root of the square root of 2. This value is approximately 1.189207115002721.
- **Use**: It is used as a factor to increment the size `_sz` in a loop until `_sz` reaches 4096.


---
### fd\_sha512\_test\_vector
- **Type**: `fd_sha512_test_vector_t const[]`
- **Description**: The `fd_sha512_test_vector` is a static constant array of `fd_sha512_test_vector_t` structures, each containing a message string, its length, and the corresponding SHA-512 hash. This array is used to store precomputed test vectors for verifying the correctness of SHA-512 hash computations.
- **Use**: This variable is used to provide a set of test vectors for validating the implementation of the SHA-512 hashing algorithm.


# Data Structures

---
### fd\_sha512\_test\_vector
- **Type**: `struct`
- **Members**:
    - `msg`: A pointer to a constant character string representing the message to be hashed.
    - `sz`: An unsigned long integer representing the size of the message.
    - `hash`: An array of 64 unsigned characters representing the SHA-512 hash of the message.
- **Description**: The `fd_sha512_test_vector` structure is designed to hold test vectors for SHA-512 hashing, consisting of a message, its size, and the resulting hash. It is used to verify the correctness of SHA-512 implementations by comparing the computed hash of a message against a known correct hash. The structure includes a pointer to the message, the size of the message, and an array to store the 64-byte hash result.


---
### fd\_sha512\_test\_vector\_t
- **Type**: `struct`
- **Members**:
    - `msg`: A pointer to a constant character string representing the message to be hashed.
    - `sz`: An unsigned long integer representing the size of the message.
    - `hash`: An array of 64 unsigned characters representing the SHA-512 hash of the message.
- **Description**: The `fd_sha512_test_vector_t` structure is designed to hold test vectors for SHA-512 hashing. It contains a message, its size, and the corresponding SHA-512 hash. This structure is used to verify the correctness of SHA-512 implementations by comparing the computed hash of the message with the precomputed hash stored in the structure.



# Purpose
This C source code file implements a 32-bit version of the MurmurHash3 algorithm, a non-cryptographic hash function known for its speed and efficiency. The file defines a static function [`fd_murmur3_32_`](#fd_murmur3_32_) that performs the core hashing operations, and a public function [`fd_murmur3_32`](#fd_murmur3_32) that serves as an interface to the static function. The static function processes input data in chunks of four bytes, applying a series of bitwise operations and multiplications to generate a hash value. It also handles any remaining bytes that do not fit into a complete four-byte chunk, ensuring that all input data contributes to the final hash.

The code is designed to be part of a larger library, as indicated by the inclusion of a header file `fd_murmur3.h` and the use of utility functions like `FD_LOAD` and `fd_uint_rotate_left`, which are likely defined elsewhere in the project. The public function [`fd_murmur3_32`](#fd_murmur3_32) provides a simple API for users to compute hash values by calling the internal static function. This separation of concerns allows the internal implementation to remain hidden while exposing a clean and straightforward interface for external use. The use of constants and bitwise operations ensures that the hash function is both fast and effective at distributing input data uniformly across the hash space.
# Imports and Dependencies

---
- `fd_murmur3.h`


# Functions

---
### fd\_murmur3\_32\_<!-- {{#callable:fd_murmur3_32_}} -->
The `fd_murmur3_32_` function computes a 32-bit hash value for a given data input using the Murmur3 hashing algorithm.
- **Inputs**:
    - `_data`: A pointer to the input data to be hashed.
    - `sz`: The size of the input data in bytes.
    - `seed`: An initial seed value for the hash computation.
- **Control Flow**:
    - Initialize constants and variables for the Murmur3 algorithm.
    - Set the initial hash value to the provided seed.
    - Process the input data in 4-byte chunks, updating the hash value with each chunk using bitwise operations and rotations.
    - Handle any remaining bytes (less than 4) by processing them separately and updating the hash.
    - Finalize the hash by mixing in the size of the data and applying additional bitwise operations and multiplications to ensure a uniform distribution.
    - Return the computed 32-bit hash value.
- **Output**: A 32-bit unsigned integer representing the hash of the input data.


---
### fd\_murmur3\_32<!-- {{#callable:fd_murmur3_32}} -->
The `fd_murmur3_32` function computes a 32-bit hash value for a given data input using the Murmur3 hashing algorithm.
- **Inputs**:
    - `_data`: A pointer to the input data to be hashed.
    - `sz`: The size of the input data in bytes.
    - `seed`: An initial seed value for the hash computation.
- **Control Flow**:
    - The function `fd_murmur3_32` is a wrapper that calls the static function [`fd_murmur3_32_`](#fd_murmur3_32_) with the same arguments.
    - In [`fd_murmur3_32_`](#fd_murmur3_32_), the input data is cast to a `uchar` pointer for byte-wise operations.
    - Constants for the Murmur3 algorithm are initialized, including two constants `c1` and `c2`, two rotation amounts `r1` and `r2`, and two additional constants `m` and `n`.
    - The initial hash value is set to the provided seed.
    - A loop processes the input data in 4-byte chunks, updating the hash with each chunk using multiplication, bitwise rotation, and XOR operations.
    - After processing full 4-byte chunks, any remaining bytes (1 to 3) are processed in a switch statement, updating the hash with similar operations.
    - The hash is finalized by mixing in the size of the input data and applying a series of bitwise operations and multiplications to ensure a uniform distribution of hash values.
    - The final hash value is returned.
- **Output**: A 32-bit unsigned integer representing the hash of the input data.
- **Functions called**:
    - [`fd_murmur3_32_`](#fd_murmur3_32_)



# Purpose
This C header file provides an interface for computing Murmur3 hashes, specifically the Murmur3-32 variant, which is a non-cryptographic hash function known for its speed and simplicity. The file defines a function [`fd_murmur3_32`](#fd_murmur3_32) that computes a 32-bit hash from a given data input and seed, ensuring idempotency by returning the same hash for identical inputs. Additionally, it includes two inline functions, [`fd_pchash`](#fd_pchash) and [`fd_pchash_inverse`](#fd_pchash_inverse), which are used to compute and reverse a hash of a program counter, respectively, using a series of bitwise operations and multiplications. These functions are designed to be efficient and are likely intended for use in scenarios where quick, consistent hashing of data or program counters is required, such as in hash tables or for generating unique identifiers.
# Imports and Dependencies

---
- `../fd_ballet_base.h`


# Functions

---
### fd\_pchash<!-- {{#callable:fd_pchash}} -->
The `fd_pchash` function computes a hash value from a given program counter using a series of bitwise operations and multiplications, similar to the Murmur3 hash algorithm.
- **Inputs**:
    - `pc`: An unsigned integer representing the program counter to be hashed.
- **Control Flow**:
    - Initialize variable `x` with the value of `pc`.
    - Multiply `x` by the constant `0xcc9e2d51U`.
    - Rotate `x` left by 15 bits using `fd_uint_rotate_left`.
    - Multiply `x` by the constant `0x1b873593U`.
    - Rotate `x` left by 13 bits using `fd_uint_rotate_left`.
    - Multiply `x` by 5 and add the constant `0xe6546b64U`.
    - Rotate `x` left by 13 bits using `fd_uint_rotate_left`.
    - Multiply `x` by 5 and add the constant `0xe6546b64U`.
    - XOR `x` with 8.
    - XOR `x` with `x` right-shifted by 16 bits.
    - Multiply `x` by the constant `0x85ebca6bU`.
    - XOR `x` with `x` right-shifted by 13 bits.
    - Multiply `x` by the constant `0xc2b2ae35U`.
    - XOR `x` with `x` right-shifted by 16 bits.
    - Return the final value of `x`.
- **Output**: The function returns an unsigned integer representing the hash value computed from the input program counter.


---
### fd\_pchash\_inverse<!-- {{#callable:fd_pchash_inverse}} -->
The `fd_pchash_inverse` function reverses the hash transformation applied by `fd_pchash` to retrieve the original program counter value.
- **Inputs**:
    - `hash`: A 32-bit unsigned integer representing the hash value to be inverted.
- **Control Flow**:
    - Initialize `x` with the input `hash`.
    - Apply a series of bitwise XOR operations and multiplications with specific constants to `x` to reverse the hash transformation.
    - Use the `fd_uint_rotate_right` function to perform right bit rotations on `x` at specific steps.
    - Continue applying transformations to `x` to reverse the effects of the original `fd_pchash` function.
    - Return the final value of `x`, which is the original program counter value.
- **Output**: The function returns a 32-bit unsigned integer representing the original program counter value before hashing.


# Function Declarations (Public API)

---
### fd\_murmur3\_32<!-- {{#callable_declaration:fd_murmur3_32}} -->
Computes the Murmur3-32 hash of a given data block.
- **Description**: This function calculates a 32-bit hash using the Murmur3 algorithm, which is suitable for non-cryptographic hashing purposes. It requires a pointer to the data block, the size of the data in bytes, and a seed value to initialize the hash computation. The function is idempotent, meaning it will consistently return the same hash value for the same input data and seed. This function is useful for generating hash values for data integrity checks, hash tables, or other applications where a fast, non-cryptographic hash is needed.
- **Inputs**:
    - `data`: A pointer to the data block to be hashed. The data should be a contiguous memory region and can be freed after the function returns. Must not be null.
    - `sz`: The size of the data block in bytes. Must accurately represent the number of bytes to be hashed.
    - `seed`: An unsigned integer used to seed the hash function, allowing for different hash results for the same data.
- **Output**: Returns a 32-bit unsigned integer representing the hash of the input data.
- **See also**: [`fd_murmur3_32`](fd_murmur3.c.driver.md#fd_murmur3_32)  (Implementation)



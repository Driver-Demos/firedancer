# Purpose
This C header file provides an implementation of the Poseidon hash function over the BN254 scalar field. The Poseidon hash function is a cryptographic hash function designed for use in zero-knowledge proofs and other cryptographic protocols. The implementation is based on the Rust library "light-poseidon" and the Circom library, which are both well-regarded in the cryptographic community. The file defines several key structures and functions necessary for initializing, appending data to, and finalizing a Poseidon hash calculation. The primary structures include `fd_poseidon_t`, which maintains the state of the hash calculation, and `fd_poseidon_par_t`, which holds parameters such as the Ark and MDS matrices used in the hash function.

The file defines a public API for using the Poseidon hash function, including functions like `fd_poseidon_init`, [`fd_poseidon_append`](#fd_poseidon_append), and [`fd_poseidon_fini`](#fd_poseidon_fini). These functions manage the lifecycle of a hash calculation, from initialization through data appending to finalization, where the hash result is produced. The header also includes a convenience function, [`fd_poseidon_hash`](#fd_poseidon_hash), which performs a complete hash operation on a series of bytes. The implementation supports both big-endian and little-endian byte orders, providing flexibility for different system architectures. The file is intended to be included in other C source files that require Poseidon hashing functionality, making it a reusable component in cryptographic applications.
# Imports and Dependencies

---
- `../fd_ballet_base.h`
- `./fd_bn254_scalar.h`


# Global Variables

---
### fd\_poseidon\_append
- **Type**: `function pointer`
- **Description**: `fd_poseidon_append` is a function that appends a specified number of bytes from a data source to an in-progress Poseidon hash calculation. It is part of the implementation of the Poseidon hash function over the BN254 scalar field, which is used for cryptographic operations. The function takes a pointer to a Poseidon state, a pointer to the data to be appended, and the size of the data in bytes.
- **Use**: This function is used to add data to the Poseidon hash state during the hash calculation process.


---
### fd\_poseidon\_fini
- **Type**: `function`
- **Description**: The `fd_poseidon_fini` function is used to complete a Poseidon hash calculation. It takes a pointer to a `fd_poseidon_t` structure, which represents the current state of the hash calculation, and a 32-byte array where the resulting hash will be stored. The function returns a pointer to the hash array or NULL if the input state pointer is NULL.
- **Use**: This function finalizes the Poseidon hash computation and stores the result in the provided hash buffer.


# Data Structures

---
### fd\_poseidon\_hash\_result
- **Type**: `struct`
- **Members**:
    - `v`: An array of unsigned characters with a size defined by FD_POSEIDON_HASH_SZ.
- **Description**: The `fd_poseidon_hash_result` structure is designed to store the result of a Poseidon hash computation. It contains a single member, `v`, which is an array of unsigned characters with a fixed size, defined by the macro `FD_POSEIDON_HASH_SZ`. This structure is used to hold the hash value, which is a 32-byte result of the Poseidon hash function over the BN254 scalar field, ensuring compatibility with cryptographic operations that require fixed-size hash outputs.


---
### fd\_poseidon\_hash\_result\_t
- **Type**: `struct`
- **Members**:
    - `v`: An array of unsigned characters with a fixed size of 32 bytes, representing the hash result.
- **Description**: The `fd_poseidon_hash_result_t` structure is designed to store the result of a Poseidon hash computation. It contains a single member, `v`, which is an array of 32 unsigned characters. This array holds the hash value, which is a 256-bit number, resulting from the Poseidon hash function applied over the BN254 scalar field. The structure is used to encapsulate the hash output in a standardized format for further processing or storage.


---
### fd\_poseidon\_t
- **Type**: `struct`
- **Members**:
    - `state`: An array of fd_bn254_scalar_t representing the current state of the Poseidon hash calculation.
    - `cnt`: A counter indicating how many elements have been appended to the hash calculation.
    - `big_endian`: An integer flag indicating the endianness of the input and output data (0 for little endian, 1 for big endian).
- **Description**: The `fd_poseidon_t` structure is used to maintain the state of a Poseidon hash calculation over the BN254 scalar field. It includes an array to store the current state of the hash, a counter to track the number of elements appended, and a flag to specify the endianness of the data being processed. This structure is central to the implementation of the Poseidon hash function, allowing for the initialization, appending of data, and finalization of the hash calculation.


---
### fd\_poseidon\_par
- **Type**: `struct`
- **Members**:
    - `ark`: A pointer to an array of fd_bn254_scalar_t representing the round constants for the Poseidon hash function.
    - `mds`: A pointer to an array of fd_bn254_scalar_t representing the MDS (Maximum Distance Separable) matrix for the Poseidon hash function.
- **Description**: The `fd_poseidon_par` structure is used to encapsulate parameters necessary for the Poseidon hash function, specifically the round constants (`ark`) and the MDS matrix (`mds`). These parameters are essential for the cryptographic operations performed by the Poseidon hash function, which operates over the BN254 scalar field. The structure is designed to hold pointers to these arrays, allowing for flexible and efficient manipulation of the hash function's parameters.


---
### fd\_poseidon\_par\_t
- **Type**: `struct`
- **Members**:
    - `ark`: A pointer to an array of BN254 scalar values used as the round constants in the Poseidon hash function.
    - `mds`: A pointer to an array of BN254 scalar values used as the MDS matrix in the Poseidon hash function.
- **Description**: The `fd_poseidon_par_t` structure is used to store parameters necessary for the Poseidon hash function, specifically the round constants (`ark`) and the MDS matrix (`mds`). These parameters are essential for the cryptographic operations performed by the Poseidon hash function, which operates over the BN254 scalar field. The structure is designed to hold pointers to these arrays, allowing for flexible and efficient access to the parameters during hash computations.


# Functions

---
### fd\_poseidon\_hash<!-- {{#callable:fd_poseidon_hash}} -->
The `fd_poseidon_hash` function computes a Poseidon hash over a given byte array and stores the result in a specified result structure.
- **Inputs**:
    - `result`: A pointer to an `fd_poseidon_hash_result_t` structure where the hash result will be stored.
    - `bytes`: A pointer to the byte array that will be hashed.
    - `bytes_len`: The length of the byte array to be hashed.
    - `big_endian`: An integer indicating whether the input and output should be treated as big endian (non-zero) or little endian (zero).
- **Control Flow**:
    - Initialize a `fd_poseidon_t` structure with the specified endianness using `fd_poseidon_init`.
    - Iterate over the byte array in chunks of 32 bytes, appending each chunk to the Poseidon state using [`fd_poseidon_append`](fd_poseidon.c.driver.md#fd_poseidon_append).
    - Finalize the Poseidon hash computation with [`fd_poseidon_fini`](fd_poseidon.c.driver.md#fd_poseidon_fini), storing the result in the provided result structure.
    - Return the negation of the result from [`fd_poseidon_fini`](fd_poseidon.c.driver.md#fd_poseidon_fini) to indicate success or failure.
- **Output**: Returns an integer that is the negation of the result from [`fd_poseidon_fini`](fd_poseidon.c.driver.md#fd_poseidon_fini), indicating success (0) or failure (non-zero).
- **Functions called**:
    - [`fd_poseidon_append`](fd_poseidon.c.driver.md#fd_poseidon_append)
    - [`fd_poseidon_fini`](fd_poseidon.c.driver.md#fd_poseidon_fini)


# Function Declarations (Public API)

---
### fd\_poseidon\_append<!-- {{#callable_declaration:fd_poseidon_append}} -->
Appends a scalar to an in-progress Poseidon hash calculation.
- **Description**: Use this function to add a scalar value, represented by a byte array, to an ongoing Poseidon hash calculation. This function should be called after initializing the Poseidon state with `fd_poseidon_init` and before finalizing the hash with `fd_poseidon_fini`. The function supports appending up to 12 elements, and each element must be a valid BN254 scalar. If the input data is less than 32 bytes, it will be padded with zeros. The function returns NULL if the input is invalid, such as when the position is NULL, the size is zero or greater than 32, or if the maximum number of elements has been appended.
- **Inputs**:
    - `pos`: A pointer to an initialized Poseidon state. Must not be NULL. The caller retains ownership.
    - `data`: A pointer to the byte array representing the scalar to append. Must not be NULL unless sz is zero. The caller retains ownership.
    - `sz`: The size of the data in bytes. Must be between 1 and 32 inclusive. If not, the function returns NULL.
- **Output**: Returns the updated Poseidon state on success, or NULL if an error occurs.
- **See also**: [`fd_poseidon_append`](fd_poseidon.c.driver.md#fd_poseidon_append)  (Implementation)


---
### fd\_poseidon\_fini<!-- {{#callable_declaration:fd_poseidon_fini}} -->
Completes a Poseidon hash calculation and stores the result.
- **Description**: This function finalizes an in-progress Poseidon hash calculation, storing the resulting hash in the provided buffer. It should be called after all data has been appended using `fd_poseidon_append`. The function requires a valid Poseidon state object, which must have been initialized and used to append data. If the state object is null or no data has been appended, the function returns null. The hash buffer must be a 32-byte memory region, and the function will populate it with the hash result, respecting the endianness specified during initialization.
- **Inputs**:
    - `pos`: A pointer to a `fd_poseidon_t` structure representing the current state of the Poseidon hash calculation. Must not be null and should have been initialized and used to append data.
    - `hash`: A 32-byte buffer where the resulting hash will be stored. The buffer must be properly aligned and is expected to be writable by the caller.
- **Output**: Returns a pointer to the hash buffer on success, or null if the state object is null or no data has been appended.
- **See also**: [`fd_poseidon_fini`](fd_poseidon.c.driver.md#fd_poseidon_fini)  (Implementation)



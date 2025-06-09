# Purpose
This C source code file implements the SipHash-1-3 cryptographic hash function, a variant of the SipHash family designed for fast and secure hashing of data. The code is a modified version of an existing implementation, as indicated by the comments referencing the original authors and contributors. The primary purpose of this file is to provide a robust hashing mechanism that can be used to generate a fixed-size hash value from variable-length input data, which is particularly useful for hash tables, checksums, and other applications requiring data integrity verification.

The file defines several key functions: [`fd_siphash13_init`](#fd_siphash13_init), [`fd_siphash13_append`](#fd_siphash13_append), [`fd_siphash13_append_fast`](#fd_siphash13_append_fast), [`fd_siphash13_fini`](#fd_siphash13_fini), and [`fd_siphash13_hash`](#fd_siphash13_hash). These functions collectively manage the initialization, processing, and finalization of the hash computation. The [`fd_siphash13_init`](#fd_siphash13_init) function sets up the initial state of the hash using a pair of keys, while [`fd_siphash13_append`](#fd_siphash13_append) and [`fd_siphash13_append_fast`](#fd_siphash13_append_fast) allow for incremental data processing. The [`fd_siphash13_fini`](#fd_siphash13_fini) function finalizes the hash computation, and [`fd_siphash13_hash`](#fd_siphash13_hash) provides a complete hash calculation in a single call. The code is structured to handle data in blocks, optimizing for performance, and includes mechanisms to handle any remaining bytes after processing full blocks. The use of static and inline functions, along with attributes for alignment and fallthrough, indicates a focus on performance optimization.
# Imports and Dependencies

---
- `fd_siphash13.h`


# Global Variables

---
### fd\_siphash13\_initial
- **Type**: `static const ulong[4]`
- **Description**: The `fd_siphash13_initial` is a static constant array of four unsigned long integers, each initialized with a specific 64-bit hexadecimal value. These values are aligned to a 64-byte boundary for performance optimization.
- **Use**: This array is used as the initial state vector for the SipHash-1-3 algorithm, providing a starting point for the hash computation.


# Functions

---
### fd\_siphash13\_init<!-- {{#callable:fd_siphash13_init}} -->
The `fd_siphash13_init` function initializes a SipHash-1-3 state with given keys.
- **Inputs**:
    - `sip`: A pointer to an `fd_siphash13_t` structure that will be initialized.
    - `k0`: The first 64-bit key used for initializing the SipHash state.
    - `k1`: The second 64-bit key used for initializing the SipHash state.
- **Control Flow**:
    - The function begins by zeroing out the memory of the `fd_siphash13_t` structure pointed to by `sip` using `memset`.
    - It then initializes a local pointer `v` to the `v` array within the `sip` structure.
    - The function sets the elements of `v` to the predefined constants from `fd_siphash13_initial`.
    - Each element of `v` is then XORed with the provided keys `k0` and `k1` to finalize the initialization.
    - Finally, the function returns the pointer to the initialized `fd_siphash13_t` structure.
- **Output**: A pointer to the initialized `fd_siphash13_t` structure.


---
### fd\_siphash1N\_core<!-- {{#callable:fd_siphash1N_core}} -->
The `fd_siphash1N_core` function processes a buffer of data in blocks, updating a state vector using the SipHash algorithm.
- **Inputs**:
    - `v`: A state vector of 4 unsigned long integers, which is updated during the hash computation.
    - `buf`: A pointer to a buffer of unsigned characters, representing the data to be hashed.
    - `n`: The number of 8-byte blocks in the buffer to process.
- **Control Flow**:
    - Initialize a variable `m` to store each 8-byte block of data from the buffer.
    - Iterate over each block of data in the buffer, from index 0 to n-1.
    - For each block, cast the corresponding part of the buffer to an unsigned long and store it in `m`.
    - XOR the third element of the state vector `v` with `m`.
    - Call the macro `FD_SIPHASH_ROUND` to perform a round of the SipHash algorithm on the state vector `v`.
    - XOR the first element of the state vector `v` with `m`.
- **Output**: The function does not return a value; it modifies the state vector `v` in place.


---
### fd\_siphash13\_append<!-- {{#callable:fd_siphash13_append}} -->
The `fd_siphash13_append` function appends data to a SipHash state, processing it in blocks and buffering any remaining bytes.
- **Inputs**:
    - `sip`: A pointer to the `fd_siphash13_t` structure representing the current state of the SipHash.
    - `data`: A pointer to the data to be appended to the SipHash state.
    - `sz`: The size in bytes of the data to be appended.
- **Control Flow**:
    - Initialize local variables `v`, `buf`, and `buf_used` from the `sip` structure.
    - Increment the total byte count `sip->n` by `sz`.
    - Check if there are any buffered bytes from a previous append using `buf_used`.
    - If there are buffered bytes and the new data is not enough to complete a block, copy the data to the buffer and return.
    - If the new data completes a block, copy enough data to complete the block, update the hash using [`fd_siphash1N_core`](#fd_siphash1N_core), and adjust `data` and `sz` to reflect the processed bytes.
    - Process the bulk of the data in 8-byte blocks using [`fd_siphash1N_core`](#fd_siphash1N_core).
    - Buffer any remaining bytes that do not form a complete block.
- **Output**: Returns a pointer to the updated `fd_siphash13_t` structure.
- **Functions called**:
    - [`fd_siphash1N_core`](#fd_siphash1N_core)


---
### fd\_siphash13\_append\_fast<!-- {{#callable:fd_siphash13_append_fast}} -->
The `fd_siphash13_append_fast` function appends data to a SipHash state, updating the state with the provided data in blocks of 8 bytes.
- **Inputs**:
    - `sip`: A pointer to the `fd_siphash13_t` structure representing the current state of the SipHash.
    - `data`: A pointer to the data to be appended to the SipHash state.
    - `sz`: The size of the data to be appended, in bytes.
- **Control Flow**:
    - Increment the `n` field of the `sip` structure by `sz` to account for the new data size.
    - Call [`fd_siphash1N_core`](#fd_siphash1N_core) to process the data in blocks of 8 bytes, passing the state vector `sip->v`, the data pointer, and the number of 8-byte blocks (`sz >> 3`).
    - Return the updated `sip` structure.
- **Output**: Returns a pointer to the updated `fd_siphash13_t` structure.
- **Functions called**:
    - [`fd_siphash1N_core`](#fd_siphash1N_core)


---
### fd\_siphash13\_fini<!-- {{#callable:fd_siphash13_fini}} -->
The `fd_siphash13_fini` function finalizes the SipHash-1-3 hashing process by processing any remaining data and performing finalization rounds to produce the hash value.
- **Inputs**:
    - `sip`: A pointer to an `fd_siphash13_t` structure containing the state of the hash computation, including the internal state array `v`, buffer `buf`, and the total number of bytes processed `n`.
- **Control Flow**:
    - Unpack the internal state `v`, buffer `buf`, and the number of bytes processed `n` from the `sip` structure.
    - Calculate the number of bytes used in the buffer `buf_used` as `n & 7UL`.
    - Initialize a variable `b` with the value `n << 56UL` to prepare for processing the last block.
    - Use a switch statement to process the remaining bytes in the buffer, updating `b` with the appropriate byte values shifted into place.
    - Call [`fd_siphash1N_core`](#fd_siphash1N_core) to process the last block using the updated `b`.
    - XOR the third element of `v` with `0xff` to prepare for finalization.
    - Perform three rounds of the SipHash compression function using `FD_SIPHASH_ROUND` macro to finalize the hash.
    - Compute the final hash value by XORing all elements of `v` and return the result.
- **Output**: The function returns an `ulong` representing the final hash value computed by the SipHash-1-3 algorithm.
- **Functions called**:
    - [`fd_siphash1N_core`](#fd_siphash1N_core)


---
### fd\_siphash13\_hash<!-- {{#callable:fd_siphash13_hash}} -->
The `fd_siphash13_hash` function computes a 64-bit hash of the input data using the SipHash-1-3 algorithm with two 64-bit keys.
- **Inputs**:
    - `data`: A pointer to the input data to be hashed.
    - `data_sz`: The size of the input data in bytes.
    - `k0`: The first 64-bit key used in the hashing process.
    - `k1`: The second 64-bit key used in the hashing process.
- **Control Flow**:
    - Initialize a 4-element array `v` with predefined constants and XOR it with the keys `k0` and `k1`.
    - Iterate over the input data in 8-byte blocks, XOR each block with `v[3]`, perform a SipHash round, and then XOR the block with `v[0]`.
    - Handle any remaining bytes (less than 8) by constructing a final block `b` with the size of the data and the remaining bytes, then XOR `b` with `v[3]`, perform a SipHash round, and XOR `b` with `v[0]`.
    - Finalize the hash by XORing `v[2]` with 0xff, performing three additional SipHash rounds, and combining the elements of `v` to produce the final hash value.
- **Output**: A 64-bit unsigned long integer representing the hash of the input data.



# Purpose
This C header file defines the interface for a SipHash1-3 implementation, a cryptographic hash function known for its efficiency and security in generating short, fixed-size hash values from arbitrary input data. The file provides a set of APIs to initialize, update, and finalize the hash computation, as well as a streamlined function for hashing small messages. The core of the implementation is encapsulated in the `fd_siphash13_t` structure, which maintains the state of the hash computation, including the internal state vector and a buffer for input data. The file also defines a macro, `FD_SIPHASH_ROUND`, which implements the round function of the SipHash1-3 algorithm, a critical component of the hash computation process.

The header file is designed to be included in other C source files, providing a public API for the SipHash1-3 functionality. It includes function prototypes for initializing the hash state (`fd_siphash13_init`), appending data to the hash ([`fd_siphash13_append`](#fd_siphash13_append) and [`fd_siphash13_append_fast`](#fd_siphash13_append_fast)), and finalizing the hash to produce the output value ([`fd_siphash13_fini`](#fd_siphash13_fini)). Additionally, it offers a convenience function, [`fd_siphash13_hash`](#fd_siphash13_hash), which combines initialization, data appending, and finalization into a single call, optimized for small data sizes. The file ensures proper alignment and footprint for the hash state structure, which is crucial for performance and correctness on various hardware architectures. This implementation is a modified version of an existing SipHash library, with contributions from multiple authors, and is intended for use in applications requiring fast and secure hashing.
# Imports and Dependencies

---
- `../fd_ballet_base.h`


# Global Variables

---
### fd\_siphash13\_append
- **Type**: `function pointer`
- **Description**: `fd_siphash13_append` is a function that appends data to an ongoing SipHash1-3 calculation. It takes a pointer to a `fd_siphash13_t` structure, a constant pointer to the data to be appended, and the size of the data in bytes.
- **Use**: This function is used to add data to the hash calculation in a SipHash1-3 process, allowing for incremental hashing of data.


---
### fd\_siphash13\_append\_fast
- **Type**: `function pointer`
- **Description**: `fd_siphash13_append_fast` is a function pointer that represents an optimized version of the `fd_siphash13_append` function. It is designed to append data to a SipHash1-3 state, with the requirement that both the internal state counter `sip->n` and the size of the data `sz` are multiples of 8 bytes.
- **Use**: This function is used to efficiently append data to a SipHash1-3 state when alignment constraints are met, improving performance over the general `fd_siphash13_append` function.


# Data Structures

---
### fd\_siphash13\_private
- **Type**: `struct`
- **Members**:
    - `v`: An array of four unsigned long integers used for internal state.
    - `n`: An unsigned long integer representing the number of bytes processed.
    - `buf`: An array of eight unsigned characters used as a buffer for input data.
- **Description**: The `fd_siphash13_private` structure is a private data structure used in the implementation of the SipHash1-3 algorithm, which is a cryptographic hash function. It is aligned to 128 bytes for performance reasons and contains an internal state array `v` of four unsigned long integers, a counter `n` for the number of bytes processed, and a buffer `buf` for storing input data. This structure is used internally by the SipHash1-3 functions to maintain state across multiple function calls and to compute the final hash value.


---
### fd\_siphash13\_t
- **Type**: `struct`
- **Members**:
    - `v`: An array of four unsigned long integers used in the SipHash1-3 algorithm.
    - `n`: An unsigned long integer representing the number of bytes processed.
    - `buf`: An array of eight unsigned characters used as a buffer for input data.
- **Description**: The `fd_siphash13_t` structure is a private data structure used to implement the SipHash1-3 algorithm, which is a cryptographic hash function designed for fast hashing of short messages. It contains an array `v` of four unsigned long integers that are used in the hash computation, a counter `n` that tracks the number of bytes processed, and a buffer `buf` for storing input data. The structure is aligned to 128 bytes to optimize performance on certain hardware architectures.


# Function Declarations (Public API)

---
### fd\_siphash13\_append<!-- {{#callable_declaration:fd_siphash13_append}} -->
Appends data to an ongoing SipHash1-3 calculation.
- **Description**: Use this function to add data to a SipHash1-3 hash calculation that has been initialized with `fd_siphash13_init`. It processes the input data in chunks, updating the hash state accordingly. This function can handle unaligned data and will buffer any remaining bytes that do not complete a full block. It must be called with a valid `fd_siphash13_t` structure that has been properly initialized. The function is designed to handle any size of data, including zero-length inputs, and will update the internal state of the hash calculation.
- **Inputs**:
    - `sip`: A pointer to an `fd_siphash13_t` structure representing the current state of the SipHash1-3 calculation. Must not be null and must be initialized with `fd_siphash13_init` before use. The caller retains ownership.
    - `data`: A pointer to the data to be appended to the hash calculation. Must not be null if `sz` is greater than zero. The caller retains ownership of the data.
    - `sz`: The size in bytes of the data to append. Can be zero, in which case the function does nothing.
- **Output**: Returns a pointer to the `fd_siphash13_t` structure provided in `sip`, allowing for function call chaining.
- **See also**: [`fd_siphash13_append`](fd_siphash13.c.driver.md#fd_siphash13_append)  (Implementation)


---
### fd\_siphash13\_append\_fast<!-- {{#callable_declaration:fd_siphash13_append_fast}} -->
Appends data to a SipHash1-3 state for hashing.
- **Description**: Use this function to append data to an existing SipHash1-3 state when the data size and the current state size are both multiples of 8 bytes. This function is optimized for aligned data and should be used when performance is critical and the alignment constraints can be met. It updates the internal state of the SipHash1-3 context with the provided data, preparing it for finalization. Ensure that the SipHash1-3 state has been properly initialized before calling this function.
- **Inputs**:
    - `sip`: A pointer to an initialized fd_siphash13_t structure representing the current SipHash1-3 state. Must not be null and must be aligned according to FD_SIPHASH13_ALIGN.
    - `data`: A pointer to the data to be appended. The data must be aligned and the size must be a multiple of 8 bytes. Must not be null.
    - `sz`: The size of the data in bytes. Must be a multiple of 8.
- **Output**: Returns a pointer to the updated fd_siphash13_t structure.
- **See also**: [`fd_siphash13_append_fast`](fd_siphash13.c.driver.md#fd_siphash13_append_fast)  (Implementation)


---
### fd\_siphash13\_fini<!-- {{#callable_declaration:fd_siphash13_fini}} -->
Completes a SipHash1-3 calculation and returns the hash value.
- **Description**: Use this function to finalize a SipHash1-3 hashing operation after initializing and appending data to the hash state. It processes any remaining data in the buffer and performs the finalization rounds to produce the hash value. This function should be called after all data has been appended using `fd_siphash13_append` or `fd_siphash13_append_fast`. The input state must be properly initialized and should not be used after this function is called unless reinitialized.
- **Inputs**:
    - `sip`: A pointer to an `fd_siphash13_t` structure representing the current state of the SipHash1-3 calculation. Must not be null and should be initialized using `fd_siphash13_init` before use. The state is consumed by this function and should not be reused without reinitialization.
- **Output**: Returns the computed hash value as an unsigned long integer.
- **See also**: [`fd_siphash13_fini`](fd_siphash13.c.driver.md#fd_siphash13_fini)  (Implementation)


---
### fd\_siphash13\_hash<!-- {{#callable_declaration:fd_siphash13_hash}} -->
Computes a SipHash1-3 hash for the given data.
- **Description**: Use this function to compute a SipHash1-3 hash of a data buffer with a specified size and two 64-bit keys. This function is suitable for scenarios where a quick, secure hash is needed, particularly for small message sizes. It combines initialization, data appending, and finalization into a single call, making it efficient for one-off hash computations. Ensure that the data pointer is valid and that the size accurately reflects the data length. The function is pure, meaning it has no side effects and its output depends only on its inputs.
- **Inputs**:
    - `data`: Pointer to the data to be hashed. Must not be null and should point to a valid memory region of at least 'sz' bytes.
    - `sz`: The size of the data in bytes. Must accurately represent the length of the data to be hashed.
    - `k0`: The first 64-bit key used in the hash computation. Provides part of the key material for the hash.
    - `k1`: The second 64-bit key used in the hash computation. Complements 'k0' to form the complete key material for the hash.
- **Output**: Returns a 64-bit unsigned long integer representing the computed hash value.
- **See also**: [`fd_siphash13_hash`](fd_siphash13.c.driver.md#fd_siphash13_hash)  (Implementation)



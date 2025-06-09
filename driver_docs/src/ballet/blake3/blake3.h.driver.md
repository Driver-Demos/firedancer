# Purpose
This C header file defines the interface for the BLAKE3 cryptographic hash function, which is known for its speed and security. It includes necessary constants, such as version information and lengths for keys, outputs, blocks, and chunks, which are crucial for the hash function's operation. The file declares two main structures: `blake3_chunk_state` and `blake3_hasher`, which manage the internal state of the hashing process. Additionally, it provides function prototypes for initializing, updating, finalizing, and resetting the hash computation, as well as for handling keyed and derived key operations. The use of `extern "C"` ensures compatibility with C++ compilers, allowing the functions to be used in C++ projects.
# Imports and Dependencies

---
- `stddef.h`
- `stdint.h`


# Data Structures

---
### blake3\_chunk\_state
- **Type**: `struct`
- **Members**:
    - `cv`: An array of 8 uint32_t values representing the chaining value.
    - `chunk_counter`: A uint64_t value that counts the number of chunks processed.
    - `buf`: A buffer of size BLAKE3_BLOCK_LEN to hold data blocks.
    - `buf_len`: A uint8_t value indicating the length of data currently in the buffer.
    - `blocks_compressed`: A uint8_t value tracking the number of blocks compressed.
    - `flags`: A uint8_t value used for storing flags related to the chunk state.
- **Description**: The `blake3_chunk_state` struct is a private implementation detail of the BLAKE3 cryptographic hash function, used to manage the state of a single chunk of data being processed. It includes a chaining value (`cv`), a counter for the number of chunks processed (`chunk_counter`), a buffer (`buf`) to temporarily hold data blocks, and several uint8_t fields (`buf_len`, `blocks_compressed`, `flags`) to track the buffer's current length, the number of blocks compressed, and any relevant flags, respectively. This struct is integral to the internal workings of the BLAKE3 hashing process, particularly in managing the state of data chunks as they are hashed.


---
### blake3\_hasher
- **Type**: `struct`
- **Members**:
    - `key`: An array of 8 uint32_t values used as the key for the hashing process.
    - `chunk`: A blake3_chunk_state structure that maintains the state of the current chunk being processed.
    - `cv_stack_len`: A uint8_t value representing the current length of the chaining value stack.
    - `cv_stack`: An array of uint8_t values used to store chaining values for lazy merging, with a size of (BLAKE3_MAX_DEPTH + 1) * BLAKE3_OUT_LEN.
- **Description**: The `blake3_hasher` structure is a core component of the BLAKE3 hashing algorithm, designed to manage the state of the hashing process. It includes a key for keyed hashing, a chunk state to track the current chunk being processed, and a stack for chaining values to facilitate lazy merging of chunks. This design allows for efficient and flexible hashing, accommodating additional input without immediate merging, which is a deviation from the reference implementation's approach.


# Function Declarations (Public API)

---
### fd\_blake3\_hasher\_init<!-- {{#callable_declaration:fd_blake3_hasher_init}} -->
Initializes a BLAKE3 hasher for default hashing.
- **Description**: Use this function to initialize a `blake3_hasher` structure for performing default BLAKE3 hashing operations. This function must be called before any other operations on the hasher, such as updating with input data or finalizing the hash. It sets up the hasher with the default initialization vector and prepares it for processing data. Ensure that the `blake3_hasher` structure is properly allocated and not null before calling this function.
- **Inputs**:
    - `self`: A pointer to a `blake3_hasher` structure that will be initialized. Must not be null. The caller is responsible for allocating this structure before calling the function.
- **Output**: None
- **See also**: [`fd_blake3_hasher_init`](blake3.c.driver.md#fd_blake3_hasher_init)  (Implementation)


---
### fd\_blake3\_hasher\_init\_keyed<!-- {{#callable_declaration:fd_blake3_hasher_init_keyed}} -->
Initializes a BLAKE3 hasher with a secret key.
- **Description**: Use this function to initialize a BLAKE3 hasher instance with a specific secret key, enabling keyed hashing. This is useful for scenarios where you need to authenticate data or create a message authentication code (MAC). The function must be called before any hashing operations are performed with the `blake3_hasher` instance. Ensure that the `key` provided is exactly `BLAKE3_KEY_LEN` bytes long. The `blake3_hasher` instance should not be used until it has been properly initialized with this function or another initialization function.
- **Inputs**:
    - `self`: A pointer to a `blake3_hasher` structure that will be initialized. The caller must allocate this structure and ensure it is not null.
    - `key`: A pointer to an array of `uint8_t` with a length of `BLAKE3_KEY_LEN` (32 bytes). This key is used to initialize the hasher for keyed hashing. The caller retains ownership of the key, and it must not be null.
- **Output**: None
- **See also**: [`fd_blake3_hasher_init_keyed`](blake3.c.driver.md#fd_blake3_hasher_init_keyed)  (Implementation)


---
### fd\_blake3\_hasher\_init\_derive\_key<!-- {{#callable_declaration:fd_blake3_hasher_init_derive_key}} -->
Initializes a BLAKE3 hasher for key derivation using a context string.
- **Description**: Use this function to initialize a BLAKE3 hasher when you need to derive a key from a specific context string. This is particularly useful in scenarios where you want to generate a unique key based on a given context. The function must be called before any update or finalize operations on the hasher. Ensure that the context string is null-terminated, as its length is determined using `strlen`. The function does not handle null pointers for the `self` or `context` parameters, so they must be valid and non-null.
- **Inputs**:
    - `self`: A pointer to a `blake3_hasher` structure that will be initialized. Must not be null. The caller retains ownership.
    - `context`: A null-terminated string representing the context for key derivation. Must not be null. The length of the context is determined using `strlen`, so it should be properly null-terminated.
- **Output**: None
- **See also**: [`fd_blake3_hasher_init_derive_key`](blake3.c.driver.md#fd_blake3_hasher_init_derive_key)  (Implementation)


---
### fd\_blake3\_hasher\_init\_derive\_key\_raw<!-- {{#callable_declaration:fd_blake3_hasher_init_derive_key_raw}} -->
Initializes a BLAKE3 hasher for key derivation using a raw context.
- **Description**: Use this function to initialize a BLAKE3 hasher for deriving a key from a given context. This is particularly useful when you need to derive keys in a cryptographic application where the context is provided as a raw byte array. The function must be called before any update or finalize operations on the hasher. Ensure that the context provided is valid and that the hasher structure is properly allocated before calling this function.
- **Inputs**:
    - `self`: A pointer to a blake3_hasher structure that will be initialized. Must not be null and should be allocated by the caller.
    - `context`: A pointer to the raw context data used for key derivation. Must not be null and should point to a valid memory location containing at least context_len bytes.
    - `context_len`: The length of the context data in bytes. Must accurately represent the size of the data pointed to by context.
- **Output**: None
- **See also**: [`fd_blake3_hasher_init_derive_key_raw`](blake3.c.driver.md#fd_blake3_hasher_init_derive_key_raw)  (Implementation)


---
### fd\_blake3\_hasher\_update<!-- {{#callable_declaration:fd_blake3_hasher_update}} -->
Updates the BLAKE3 hasher state with new input data.
- **Description**: Use this function to feed additional input data into an existing BLAKE3 hasher state. It must be called after initializing the hasher with one of the initialization functions. The function handles input of any length, including zero-length input, without causing undefined behavior. It processes the input in chunks, optimizing for performance when possible, and updates the internal state of the hasher accordingly. This function does not produce a hash output; it prepares the state for finalization.
- **Inputs**:
    - `self`: A pointer to a blake3_hasher structure that has been initialized. The caller retains ownership and must ensure it is not null.
    - `input`: A pointer to the input data to be hashed. The data must be valid for the length specified by input_len. If input_len is zero, this can be null.
    - `input_len`: The length of the input data in bytes. It can be zero, in which case the function returns immediately without processing.
- **Output**: None
- **See also**: [`fd_blake3_hasher_update`](blake3.c.driver.md#fd_blake3_hasher_update)  (Implementation)


---
### fd\_blake3\_hasher\_finalize<!-- {{#callable_declaration:fd_blake3_hasher_finalize}} -->
Finalize the BLAKE3 hash computation and write the output.
- **Description**: Use this function to complete the BLAKE3 hashing process and obtain the hash output. It should be called after all input data has been provided to the hasher using `fd_blake3_hasher_update`. The function writes the computed hash to the provided output buffer. Ensure that the output buffer is large enough to hold the desired length of the hash output. This function does not modify the state of the hasher, allowing for further operations if needed.
- **Inputs**:
    - `self`: A pointer to a `blake3_hasher` structure that has been initialized and updated with input data. Must not be null.
    - `out`: A pointer to a buffer where the hash output will be written. Must not be null and should have enough space to accommodate `out_len` bytes.
    - `out_len`: The number of bytes to write to the output buffer. It should be a positive value and can be up to the maximum output length defined by the BLAKE3 specification.
- **Output**: None
- **See also**: [`fd_blake3_hasher_finalize`](blake3.c.driver.md#fd_blake3_hasher_finalize)  (Implementation)


---
### fd\_blake3\_hasher\_finalize\_seek<!-- {{#callable_declaration:fd_blake3_hasher_finalize_seek}} -->
Produces a hash output from the hasher state with a specified seek position.
- **Description**: Use this function to finalize the hashing process and obtain a hash output from the current state of the BLAKE3 hasher, starting at a specified seek position. This function should be called after all input data has been processed with `fd_blake3_hasher_update`. It is useful when you need to generate a hash output that is not necessarily from the beginning of the hash stream. The function handles cases where the output length is zero by returning immediately without performing any operations.
- **Inputs**:
    - `self`: A pointer to a `blake3_hasher` structure representing the current state of the hasher. Must not be null and should be properly initialized and updated with input data before calling this function.
    - `seek`: A 64-bit unsigned integer specifying the position in the hash output stream from which to start producing the output.
    - `out`: A pointer to a buffer where the hash output will be written. Must not be null if `out_len` is greater than zero.
    - `out_len`: The number of bytes to write to the `out` buffer. If zero, the function returns immediately without writing any data.
- **Output**: None
- **See also**: [`fd_blake3_hasher_finalize_seek`](blake3.c.driver.md#fd_blake3_hasher_finalize_seek)  (Implementation)


---
### fd\_blake3\_hasher\_reset<!-- {{#callable_declaration:fd_blake3_hasher_reset}} -->
Resets the state of a BLAKE3 hasher to its initial state.
- **Description**: Use this function to reset a BLAKE3 hasher object to its initial state, effectively clearing any accumulated data and preparing it for a new hashing operation. This function should be called when you want to reuse an existing hasher object for a new hash computation without reallocating or reinitializing it. Ensure that the hasher has been properly initialized before calling this function.
- **Inputs**:
    - `self`: A pointer to a blake3_hasher object. Must not be null. The hasher should have been previously initialized using one of the initialization functions.
- **Output**: None
- **See also**: [`fd_blake3_hasher_reset`](blake3.c.driver.md#fd_blake3_hasher_reset)  (Implementation)



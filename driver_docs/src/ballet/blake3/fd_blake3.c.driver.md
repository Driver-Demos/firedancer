# Purpose
This C source code file provides a wrapper around the BLAKE3 cryptographic hash function, integrating it with a custom memory management and alignment system. The file includes several functions that manage the lifecycle of a `fd_blake3_t` structure, which represents a BLAKE3 hashing context. Key functions include [`fd_blake3_new`](#fd_blake3_new), which initializes a new hashing context in shared memory, [`fd_blake3_join`](#fd_blake3_join) and [`fd_blake3_leave`](#fd_blake3_leave), which manage access to the context, and [`fd_blake3_delete`](#fd_blake3_delete), which cleans up the context. The file also includes functions for initializing the hash ([`fd_blake3_init`](#fd_blake3_init)), appending data to be hashed ([`fd_blake3_append`](#fd_blake3_append)), and finalizing the hash computation with different output lengths ([`fd_blake3_fini`](#fd_blake3_fini), [`fd_blake3_fini_512`](#fd_blake3_fini_512), and [`fd_blake3_fini_varlen`](#fd_blake3_fini_varlen)).

The code is designed to be integrated into larger systems, providing a consistent interface for BLAKE3 hashing operations while ensuring proper memory alignment and management. It leverages the BLAKE3 reference implementation, with potential for optimization through custom memory operations and AVX2 routines. The file is not a standalone executable but rather a component intended to be included in other projects, offering a public API for BLAKE3 hashing that abstracts away the underlying implementation details. This modular approach allows for easy replacement or enhancement of the hashing implementation to target specific hardware capabilities without altering the interface exposed to the rest of the application.
# Imports and Dependencies

---
- `fd_blake3.h`
- `blake3_impl.h`
- `blake3_dispatch.c`
- `blake3.c`


# Functions

---
### fd\_blake3\_align<!-- {{#callable:fd_blake3_align}} -->
The `fd_blake3_align` function returns the alignment requirement for BLAKE3 operations.
- **Inputs**: None
- **Control Flow**:
    - The function is called without any parameters.
    - It directly returns the value of the macro `FD_BLAKE3_ALIGN`.
- **Output**: The function returns an `ulong` representing the alignment requirement for BLAKE3 operations.


---
### fd\_blake3\_footprint<!-- {{#callable:fd_blake3_footprint}} -->
The `fd_blake3_footprint` function returns the memory footprint size required for a BLAKE3 hashing context.
- **Inputs**: None
- **Control Flow**:
    - The function is defined to return an unsigned long integer (`ulong`).
    - It directly returns the value of the macro `FD_BLAKE3_FOOTPRINT`.
- **Output**: The function outputs an unsigned long integer representing the memory footprint size for a BLAKE3 hashing context.


---
### fd\_blake3\_new<!-- {{#callable:fd_blake3_new}} -->
The `fd_blake3_new` function initializes a new BLAKE3 hashing context in a given shared memory region, ensuring proper alignment and setting a magic number for validation.
- **Inputs**:
    - `shmem`: A pointer to a shared memory region where the BLAKE3 hashing context will be initialized.
- **Control Flow**:
    - Cast the `shmem` pointer to a `fd_blake3_t` pointer named `sha`.
    - Check if `shmem` is NULL; if so, log a warning and return NULL.
    - Check if `shmem` is not aligned according to [`fd_blake3_align`](#fd_blake3_align); if so, log a warning and return NULL.
    - Retrieve the memory footprint size using [`fd_blake3_footprint`](#fd_blake3_footprint).
    - Zero out the memory region pointed to by `sha` using `fd_memset`.
    - Use memory fence operations to ensure memory ordering before and after setting the `magic` field of `sha` to `FD_BLAKE3_MAGIC`.
    - Return the pointer to the initialized `fd_blake3_t` structure.
- **Output**: A pointer to the initialized `fd_blake3_t` structure, or NULL if initialization fails due to NULL or misaligned input.
- **Functions called**:
    - [`fd_blake3_align`](#fd_blake3_align)
    - [`fd_blake3_footprint`](#fd_blake3_footprint)


---
### fd\_blake3\_join<!-- {{#callable:fd_blake3_join}} -->
The `fd_blake3_join` function validates and returns a pointer to a `fd_blake3_t` structure if the input shared memory is correctly aligned and initialized.
- **Inputs**:
    - `shsha`: A pointer to shared memory that is expected to contain a `fd_blake3_t` structure.
- **Control Flow**:
    - Check if `shsha` is NULL; if so, log a warning and return NULL.
    - Check if `shsha` is aligned according to [`fd_blake3_align`](#fd_blake3_align); if not, log a warning and return NULL.
    - Cast `shsha` to a `fd_blake3_t` pointer named `sha`.
    - Check if `sha->magic` equals `FD_BLAKE3_MAGIC`; if not, log a warning and return NULL.
    - Return the `sha` pointer.
- **Output**: A pointer to a `fd_blake3_t` structure if all checks pass, otherwise NULL.
- **Functions called**:
    - [`fd_blake3_align`](#fd_blake3_align)


---
### fd\_blake3\_leave<!-- {{#callable:fd_blake3_leave}} -->
The `fd_blake3_leave` function checks if the input `fd_blake3_t` pointer is non-null and returns it as a void pointer, logging a warning if it is null.
- **Inputs**:
    - `sha`: A pointer to an `fd_blake3_t` structure, which represents a BLAKE3 hashing context.
- **Control Flow**:
    - Check if the `sha` pointer is null using `FD_UNLIKELY`; if it is, log a warning message 'NULL sha' and return `NULL`.
    - If `sha` is not null, cast it to a `void *` and return it.
- **Output**: Returns the input `sha` pointer cast to a `void *`, or `NULL` if the input was null.


---
### fd\_blake3\_delete<!-- {{#callable:fd_blake3_delete}} -->
The `fd_blake3_delete` function validates and clears a BLAKE3 state object, ensuring it is properly aligned and has a valid magic number before setting the magic number to zero.
- **Inputs**:
    - `shsha`: A pointer to a BLAKE3 state object that is to be deleted.
- **Control Flow**:
    - Check if the input pointer `shsha` is NULL and log a warning if it is, returning NULL.
    - Verify if `shsha` is aligned according to `fd_blake3_align()` and log a warning if it is not, returning NULL.
    - Cast `shsha` to a `fd_blake3_t` pointer named `sha`.
    - Check if the `magic` field of `sha` matches `FD_BLAKE3_MAGIC` and log a warning if it does not, returning NULL.
    - Use memory fence operations to ensure memory ordering, then set the `magic` field of `sha` to zero.
    - Return the `sha` pointer cast back to a `void *`.
- **Output**: A pointer to the BLAKE3 state object if successful, or NULL if any validation checks fail.
- **Functions called**:
    - [`fd_blake3_align`](#fd_blake3_align)


---
### fd\_blake3\_init<!-- {{#callable:fd_blake3_init}} -->
The `fd_blake3_init` function initializes a BLAKE3 hashing context by setting up its internal hasher state.
- **Inputs**:
    - `sha`: A pointer to an `fd_blake3_t` structure that represents the BLAKE3 hashing context to be initialized.
- **Control Flow**:
    - Call the [`fd_blake3_hasher_init`](blake3.c.driver.md#fd_blake3_hasher_init) function with the `hasher` member of the `sha` structure to initialize the hasher state.
    - Return the `sha` pointer.
- **Output**: Returns the pointer to the initialized `fd_blake3_t` structure.
- **Functions called**:
    - [`fd_blake3_hasher_init`](blake3.c.driver.md#fd_blake3_hasher_init)


---
### fd\_blake3\_append<!-- {{#callable:fd_blake3_append}} -->
The `fd_blake3_append` function updates the BLAKE3 hash state with new data.
- **Inputs**:
    - `sha`: A pointer to an `fd_blake3_t` structure representing the current state of the BLAKE3 hash.
    - `data`: A pointer to the data to be appended to the hash.
    - `sz`: The size in bytes of the data to be appended.
- **Control Flow**:
    - The function calls [`fd_blake3_hasher_update`](blake3.c.driver.md#fd_blake3_hasher_update) with the hasher from the `sha` structure, the data pointer, and the size of the data.
    - The function returns the updated `sha` structure.
- **Output**: A pointer to the updated `fd_blake3_t` structure.
- **Functions called**:
    - [`fd_blake3_hasher_update`](blake3.c.driver.md#fd_blake3_hasher_update)


---
### fd\_blake3\_fini<!-- {{#callable:fd_blake3_fini}} -->
The `fd_blake3_fini` function finalizes the BLAKE3 hashing process and writes the resulting 32-byte hash to the provided buffer.
- **Inputs**:
    - `sha`: A pointer to an `fd_blake3_t` structure, which contains the state of the BLAKE3 hasher.
    - `hash`: A pointer to a buffer where the 32-byte hash result will be stored.
- **Control Flow**:
    - The function calls [`fd_blake3_hasher_finalize`](blake3.c.driver.md#fd_blake3_hasher_finalize), passing the hasher from the `sha` structure, the `hash` buffer cast to `uchar *`, and the fixed size of 32 bytes.
    - The function returns the `hash` pointer after the hash has been written to it.
- **Output**: A pointer to the buffer where the 32-byte hash has been stored, which is the same as the input `hash` pointer.
- **Functions called**:
    - [`fd_blake3_hasher_finalize`](blake3.c.driver.md#fd_blake3_hasher_finalize)


---
### fd\_blake3\_fini\_512<!-- {{#callable:fd_blake3_fini_512}} -->
The `fd_blake3_fini_512` function finalizes a BLAKE3 hash computation and writes a 512-bit hash to the provided buffer.
- **Inputs**:
    - `sha`: A pointer to an `fd_blake3_t` structure representing the BLAKE3 hashing state.
    - `hash`: A pointer to a buffer where the 512-bit hash result will be stored.
- **Control Flow**:
    - The function calls [`fd_blake3_hasher_finalize`](blake3.c.driver.md#fd_blake3_hasher_finalize) with the hasher from the `sha` structure, the `hash` buffer cast to `uchar *`, and a length of 64 bytes to finalize the hash computation.
    - The finalized hash is written to the `hash` buffer.
- **Output**: Returns the `hash` pointer, which now contains the 512-bit hash result.
- **Functions called**:
    - [`fd_blake3_hasher_finalize`](blake3.c.driver.md#fd_blake3_hasher_finalize)


---
### fd\_blake3\_fini\_varlen<!-- {{#callable:fd_blake3_fini_varlen}} -->
The `fd_blake3_fini_varlen` function finalizes a BLAKE3 hash computation and writes the resulting hash of a specified length to a provided buffer.
- **Inputs**:
    - `sha`: A pointer to an `fd_blake3_t` structure representing the BLAKE3 hashing state.
    - `hash`: A pointer to a buffer where the resulting hash will be stored.
    - `hash_len`: An unsigned long integer specifying the desired length of the hash output.
- **Control Flow**:
    - The function calls [`fd_blake3_hasher_finalize`](blake3.c.driver.md#fd_blake3_hasher_finalize), passing the hasher from the `sha` structure, the `hash` buffer, and the `hash_len` to finalize the hash computation.
    - The finalized hash is written to the `hash` buffer.
    - The function returns the `hash` buffer.
- **Output**: A pointer to the buffer containing the finalized hash.
- **Functions called**:
    - [`fd_blake3_hasher_finalize`](blake3.c.driver.md#fd_blake3_hasher_finalize)



# Purpose
This C source code file provides a comprehensive implementation of the Keccak-256 cryptographic hash function, which is a variant of the SHA-3 standard. The file defines a series of functions that manage the lifecycle of a Keccak-256 hashing operation, including initialization, data appending, and finalization to produce the hash output. The code is structured to handle memory alignment and integrity checks, ensuring that the operations are performed on correctly aligned memory blocks and that the state of the hash object is valid. The functions [`fd_keccak256_new`](#fd_keccak256_new), [`fd_keccak256_join`](#fd_keccak256_join), [`fd_keccak256_leave`](#fd_keccak256_leave), and [`fd_keccak256_delete`](#fd_keccak256_delete) manage the creation, validation, and deletion of the hash state in shared memory, while [`fd_keccak256_init`](#fd_keccak256_init), [`fd_keccak256_append`](#fd_keccak256_append), and [`fd_keccak256_fini`](#fd_keccak256_fini) handle the core hashing process.

The file is intended to be part of a larger library, as indicated by the inclusion of header files and the use of macros for logging and memory operations. It provides a public API for performing Keccak-256 hashing, with functions like [`fd_keccak256_hash`](#fd_keccak256_hash) offering a straightforward interface for hashing data in a single call. The code emphasizes robustness and correctness, with checks for null pointers, memory alignment, and state integrity. This implementation is suitable for applications requiring secure hashing, such as data integrity verification and cryptographic applications.
# Imports and Dependencies

---
- `fd_keccak256.h`
- `fd_keccak256_private.h`


# Functions

---
### fd\_keccak256\_align<!-- {{#callable:fd_keccak256_align}} -->
The `fd_keccak256_align` function returns the alignment requirement for the Keccak-256 hashing context.
- **Inputs**: None
- **Control Flow**:
    - The function is defined to return an unsigned long integer.
    - It directly returns the value of the macro `FD_KECCAK256_ALIGN`.
- **Output**: The function returns an unsigned long integer representing the alignment requirement for the Keccak-256 hashing context.


---
### fd\_keccak256\_footprint<!-- {{#callable:fd_keccak256_footprint}} -->
The function `fd_keccak256_footprint` returns the memory footprint size required for a Keccak-256 hash context.
- **Inputs**: None
- **Control Flow**:
    - The function is defined to return an unsigned long integer.
    - It directly returns the value of the macro `FD_KECCAK256_FOOTPRINT`.
- **Output**: The function outputs an unsigned long integer representing the memory footprint size for a Keccak-256 hash context.


---
### fd\_keccak256\_new<!-- {{#callable:fd_keccak256_new}} -->
The `fd_keccak256_new` function initializes a new Keccak-256 hashing context in a given shared memory region.
- **Inputs**:
    - `shmem`: A pointer to a shared memory region where the Keccak-256 context will be initialized.
- **Control Flow**:
    - Cast the `shmem` pointer to a `fd_keccak256_t` pointer named `sha`.
    - Check if `shmem` is NULL; if so, log a warning and return NULL.
    - Check if `shmem` is aligned according to [`fd_keccak256_align`](#fd_keccak256_align); if not, log a warning and return NULL.
    - Retrieve the footprint size using [`fd_keccak256_footprint`](#fd_keccak256_footprint).
    - Zero out the memory region pointed to by `sha` using `fd_memset`.
    - Set a memory fence using `FD_COMPILER_MFENCE`.
    - Set the `magic` field of `sha` to `FD_KECCAK256_MAGIC` using a volatile store.
    - Set another memory fence using `FD_COMPILER_MFENCE`.
    - Return the pointer to the initialized `fd_keccak256_t` structure.
- **Output**: A pointer to the initialized `fd_keccak256_t` structure, or NULL if initialization fails due to NULL or misaligned `shmem`.
- **Functions called**:
    - [`fd_keccak256_align`](#fd_keccak256_align)
    - [`fd_keccak256_footprint`](#fd_keccak256_footprint)


---
### fd\_keccak256\_join<!-- {{#callable:fd_keccak256_join}} -->
The `fd_keccak256_join` function validates and returns a pointer to a `fd_keccak256_t` structure if the input shared memory is correctly aligned and initialized.
- **Inputs**:
    - `shsha`: A pointer to shared memory that is expected to contain a `fd_keccak256_t` structure.
- **Control Flow**:
    - Check if `shsha` is NULL; if so, log a warning and return NULL.
    - Check if `shsha` is aligned according to [`fd_keccak256_align`](#fd_keccak256_align); if not, log a warning and return NULL.
    - Cast `shsha` to a `fd_keccak256_t` pointer named `sha`.
    - Check if `sha->magic` equals `FD_KECCAK256_MAGIC`; if not, log a warning and return NULL.
    - Return the `sha` pointer.
- **Output**: A pointer to a `fd_keccak256_t` structure if all checks pass, otherwise NULL.
- **Functions called**:
    - [`fd_keccak256_align`](#fd_keccak256_align)


---
### fd\_keccak256\_leave<!-- {{#callable:fd_keccak256_leave}} -->
The `fd_keccak256_leave` function checks if the provided `fd_keccak256_t` pointer is non-null and returns it as a void pointer.
- **Inputs**:
    - `sha`: A pointer to an `fd_keccak256_t` structure, which represents the state of a Keccak-256 hash operation.
- **Control Flow**:
    - Check if the `sha` pointer is NULL using `FD_UNLIKELY`; if it is NULL, log a warning and return NULL.
    - If `sha` is not NULL, cast it to a void pointer and return it.
- **Output**: Returns the input `sha` pointer cast to a void pointer, or NULL if the input is NULL.


---
### fd\_keccak256\_delete<!-- {{#callable:fd_keccak256_delete}} -->
The `fd_keccak256_delete` function validates and clears a `fd_keccak256_t` structure by setting its magic number to zero, effectively marking it as deleted.
- **Inputs**:
    - `shsha`: A pointer to a `fd_keccak256_t` structure that is to be deleted.
- **Control Flow**:
    - Check if `shsha` is NULL and log a warning if true, returning NULL.
    - Check if `shsha` is aligned according to `fd_keccak256_align()` and log a warning if not, returning NULL.
    - Cast `shsha` to a `fd_keccak256_t` pointer named `sha`.
    - Check if `sha->magic` is equal to `FD_KECCAK256_MAGIC` and log a warning if not, returning NULL.
    - Use memory fence operations to ensure memory ordering and set `sha->magic` to 0, marking it as deleted.
    - Return the `sha` pointer cast back to a `void *`.
- **Output**: A pointer to the `fd_keccak256_t` structure that was deleted, or NULL if any validation checks fail.
- **Functions called**:
    - [`fd_keccak256_align`](#fd_keccak256_align)


---
### fd\_keccak256\_init<!-- {{#callable:fd_keccak256_init}} -->
The `fd_keccak256_init` function initializes a `fd_keccak256_t` structure by zeroing its state and setting the padding start index to zero.
- **Inputs**:
    - `sha`: A pointer to a `fd_keccak256_t` structure that will be initialized.
- **Control Flow**:
    - The function uses `fd_memset` to set all bytes of the `state` array within the `sha` structure to zero.
    - The `padding_start` field of the `sha` structure is set to zero.
    - The function returns the pointer to the initialized `fd_keccak256_t` structure.
- **Output**: A pointer to the initialized `fd_keccak256_t` structure.


---
### fd\_keccak256\_append<!-- {{#callable:fd_keccak256_append}} -->
The `fd_keccak256_append` function appends data to a Keccak-256 hash state, processing it in blocks and updating the state accordingly.
- **Inputs**:
    - `sha`: A pointer to the `fd_keccak256_t` structure representing the current state of the Keccak-256 hash.
    - `_data`: A pointer to the data to be appended to the hash state.
    - `sz`: The size of the data to be appended, in bytes.
- **Control Flow**:
    - Check if the size of the data (`sz`) is zero; if so, return the current hash state without modification.
    - Unpack the current state, state bytes, and padding start from the `sha` structure.
    - Cast the input data to a byte array for processing.
    - Iterate over each byte of the input data, XORing it with the corresponding byte in the state bytes array.
    - Increment the state index after each byte is processed.
    - If the state index reaches the rate limit (`FD_KECCAK256_RATE`), process the current state with [`fd_keccak256_core`](fd_keccak256_private.h.driver.md#fd_keccak256_core) and reset the state index to zero.
    - Update the `padding_start` in the `sha` structure with the current state index.
    - Return the updated `sha` structure.
- **Output**: Returns a pointer to the updated `fd_keccak256_t` structure, representing the new state of the hash after appending the data.
- **Functions called**:
    - [`fd_keccak256_core`](fd_keccak256_private.h.driver.md#fd_keccak256_core)


---
### fd\_keccak256\_fini<!-- {{#callable:fd_keccak256_fini}} -->
The `fd_keccak256_fini` function finalizes the Keccak-256 hashing process by appending padding, processing the final block, and copying the hash result to the provided output buffer.
- **Inputs**:
    - `sha`: A pointer to an `fd_keccak256_t` structure that holds the current state of the Keccak-256 hash computation.
    - `hash`: A pointer to a buffer where the final hash result will be stored.
- **Control Flow**:
    - Unpack the state, state_bytes, and padding_start from the `sha` structure.
    - Append the terminating message byte by XORing the byte at `padding_start` with 0x01 and the last byte of the rate with 0x80.
    - Call [`fd_keccak256_core`](fd_keccak256_private.h.driver.md#fd_keccak256_core) to process the final block of the state.
    - Copy the resulting hash from the state to the provided `hash` buffer using `fd_memcpy`.
- **Output**: Returns a pointer to the `hash` buffer containing the final hash result.
- **Functions called**:
    - [`fd_keccak256_core`](fd_keccak256_private.h.driver.md#fd_keccak256_core)


---
### fd\_keccak256\_hash<!-- {{#callable:fd_keccak256_hash}} -->
The `fd_keccak256_hash` function computes the Keccak-256 hash of the given data and stores the result in the provided hash buffer.
- **Inputs**:
    - `_data`: A pointer to the input data that needs to be hashed.
    - `sz`: The size in bytes of the input data.
    - `_hash`: A pointer to the buffer where the resulting hash will be stored.
- **Control Flow**:
    - Initialize a `fd_keccak256_t` structure `sha` using [`fd_keccak256_init`](#fd_keccak256_init).
    - Append the input data to the `sha` structure using [`fd_keccak256_append`](#fd_keccak256_append), passing the data pointer and its size.
    - Finalize the hash computation and store the result in the provided hash buffer using [`fd_keccak256_fini`](#fd_keccak256_fini).
    - Return the pointer to the hash buffer.
- **Output**: A pointer to the buffer containing the computed Keccak-256 hash.
- **Functions called**:
    - [`fd_keccak256_init`](#fd_keccak256_init)
    - [`fd_keccak256_append`](#fd_keccak256_append)
    - [`fd_keccak256_fini`](#fd_keccak256_fini)



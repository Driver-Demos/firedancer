# Purpose
This C source code file implements a SHA-256 hashing algorithm, providing both incremental and one-shot hashing functionalities. The code is structured to handle memory alignment and initialization of SHA-256 contexts, as well as the core hashing operations. It includes functions to create, join, leave, and delete SHA-256 contexts, ensuring proper memory alignment and initialization through checks and logging warnings for misaligned or null pointers. The core hashing logic is implemented in a function derived from OpenSSL's SHA-256 implementation, with optimizations for specific machine capabilities and a focus on strictness and documentation.

The file defines a set of functions that form a public API for SHA-256 operations, including [`fd_sha256_new`](#fd_sha256_new), [`fd_sha256_join`](#fd_sha256_join), [`fd_sha256_leave`](#fd_sha256_leave), [`fd_sha256_delete`](#fd_sha256_delete), [`fd_sha256_init`](#fd_sha256_init), [`fd_sha256_append`](#fd_sha256_append), [`fd_sha256_fini`](#fd_sha256_fini), [`fd_sha256_hash`](#fd_sha256_hash), and [`fd_sha256_hash_32`](#fd_sha256_hash_32). These functions allow for the creation and management of SHA-256 contexts, appending data to be hashed, and finalizing the hash computation. The code is designed to be flexible, allowing for different implementations of the core hashing function based on available hardware capabilities, such as using SHA extensions if available. The file is intended to be part of a larger library, as indicated by the inclusion of a header file and the use of macros for configuration and logging.
# Imports and Dependencies

---
- `fd_sha256.h`


# Functions

---
### fd\_sha256\_align<!-- {{#callable:fd_sha256_align}} -->
The `fd_sha256_align` function returns the alignment requirement for SHA-256 operations.
- **Inputs**: None
- **Control Flow**:
    - The function is defined to return a value of type `ulong`.
    - It directly returns the value of the macro `FD_SHA256_ALIGN`.
- **Output**: The function outputs an `ulong` value representing the alignment requirement for SHA-256 operations, as defined by the `FD_SHA256_ALIGN` macro.


---
### fd\_sha256\_footprint<!-- {{#callable:fd_sha256_footprint}} -->
The `fd_sha256_footprint` function returns the constant value `FD_SHA256_FOOTPRINT`, which represents the memory footprint required for a SHA-256 context.
- **Inputs**: None
- **Control Flow**:
    - The function is defined to return an unsigned long integer (`ulong`).
    - It directly returns the constant `FD_SHA256_FOOTPRINT`.
- **Output**: The function outputs an unsigned long integer representing the memory footprint for a SHA-256 context.


---
### fd\_sha256\_new<!-- {{#callable:fd_sha256_new}} -->
The `fd_sha256_new` function initializes a new SHA-256 context in shared memory, ensuring proper alignment and setting a magic number for validation.
- **Inputs**:
    - `shmem`: A pointer to the shared memory where the SHA-256 context will be initialized.
- **Control Flow**:
    - Cast the `shmem` pointer to a `fd_sha256_t` pointer named `sha`.
    - Check if `shmem` is NULL; if so, log a warning and return NULL.
    - Check if `shmem` is not aligned according to [`fd_sha256_align`](#fd_sha256_align); if not, log a warning and return NULL.
    - Retrieve the footprint size using [`fd_sha256_footprint`](#fd_sha256_footprint).
    - Clear the memory at `sha` using `fd_memset` with the footprint size.
    - Use memory fences (`FD_COMPILER_MFENCE`) to ensure memory operations are completed before setting the magic number.
    - Set the `magic` field of `sha` to `FD_SHA256_MAGIC` using a volatile store.
    - Return the pointer to the initialized `sha`.
- **Output**: A pointer to the initialized `fd_sha256_t` structure, or NULL if initialization fails due to NULL or misaligned `shmem`.
- **Functions called**:
    - [`fd_sha256_align`](#fd_sha256_align)
    - [`fd_sha256_footprint`](#fd_sha256_footprint)


---
### fd\_sha256\_join<!-- {{#callable:fd_sha256_join}} -->
The `fd_sha256_join` function validates and returns a pointer to a SHA-256 context if the input is correctly aligned and initialized.
- **Inputs**:
    - `shsha`: A pointer to a memory location that is expected to hold a SHA-256 context.
- **Control Flow**:
    - Check if the input pointer `shsha` is NULL; if so, log a warning and return NULL.
    - Check if `shsha` is aligned according to the required alignment for SHA-256 contexts; if not, log a warning and return NULL.
    - Cast `shsha` to a `fd_sha256_t` pointer and check if its `magic` field matches the expected `FD_SHA256_MAGIC`; if not, log a warning and return NULL.
    - If all checks pass, return the `fd_sha256_t` pointer.
- **Output**: A pointer to a `fd_sha256_t` structure if the input is valid, otherwise NULL.
- **Functions called**:
    - [`fd_sha256_align`](#fd_sha256_align)


---
### fd\_sha256\_leave<!-- {{#callable:fd_sha256_leave}} -->
The `fd_sha256_leave` function checks if the given SHA-256 context pointer is non-null and returns it as a void pointer, logging a warning if it is null.
- **Inputs**:
    - `sha`: A pointer to an `fd_sha256_t` structure representing the SHA-256 context.
- **Control Flow**:
    - Check if the `sha` pointer is null using `FD_UNLIKELY`; if it is, log a warning message 'NULL sha' and return `NULL`.
    - If the `sha` pointer is not null, cast it to a `void *` and return it.
- **Output**: Returns the input `sha` pointer cast to a `void *`, or `NULL` if the input was null.


---
### fd\_sha256\_delete<!-- {{#callable:fd_sha256_delete}} -->
The `fd_sha256_delete` function validates and deletes a SHA-256 context by resetting its magic number to zero.
- **Inputs**:
    - `shsha`: A pointer to the SHA-256 context to be deleted.
- **Control Flow**:
    - Check if the input pointer `shsha` is NULL; if so, log a warning and return NULL.
    - Check if `shsha` is aligned according to [`fd_sha256_align`](#fd_sha256_align); if not, log a warning and return NULL.
    - Cast `shsha` to a `fd_sha256_t` pointer and store it in `sha`.
    - Check if the `magic` field of `sha` is equal to `FD_SHA256_MAGIC`; if not, log a warning and return NULL.
    - Use memory fences to ensure memory operations are completed, then set the `magic` field of `sha` to 0.
    - Return the `sha` pointer cast back to a `void *`.
- **Output**: A pointer to the deleted SHA-256 context, or NULL if any validation checks fail.
- **Functions called**:
    - [`fd_sha256_align`](#fd_sha256_align)


---
### fd\_sha256\_core\_ref<!-- {{#callable:fd_sha256_core_ref}} -->
The `fd_sha256_core_ref` function processes blocks of data to update the SHA-256 hash state using a reference implementation derived from OpenSSL.
- **Inputs**:
    - `state`: A pointer to an array of 8 unsigned integers representing the current state of the SHA-256 hash.
    - `block`: A pointer to a constant array of unsigned characters representing the data block to be processed.
    - `block_cnt`: An unsigned long integer representing the number of 512-bit blocks to process.
- **Control Flow**:
    - Initialize constants and macros for SHA-256 operations, including rotation and logical functions.
    - Cast the input block to an array of unsigned integers for processing.
    - Iterate over each block, updating the hash state for each 512-bit block.
    - For the first 16 words of the block, perform byte swapping and compute intermediate hash values using SHA-256 functions and constants.
    - For the remaining 48 words, compute additional intermediate hash values using previously computed values and update the hash state.
    - Update the input state with the computed hash values after processing each block.
    - Repeat the process for the specified number of blocks.
- **Output**: The function updates the input state array to reflect the processed hash state after processing the specified number of blocks.


---
### fd\_sha256\_init<!-- {{#callable:fd_sha256_init}} -->
The `fd_sha256_init` function initializes a SHA-256 context structure with the standard initial hash values and resets the buffer usage and bit count.
- **Inputs**:
    - `sha`: A pointer to an `fd_sha256_t` structure that will be initialized for SHA-256 hashing.
- **Control Flow**:
    - Set the first eight elements of the `state` array in the `sha` structure to the standard initial hash values for SHA-256.
    - Set `buf_used` in the `sha` structure to 0, indicating no data is currently buffered.
    - Set `bit_cnt` in the `sha` structure to 0, indicating no bits have been processed yet.
    - Return the pointer to the initialized `sha` structure.
- **Output**: A pointer to the initialized `fd_sha256_t` structure.


---
### fd\_sha256\_append<!-- {{#callable:fd_sha256_append}} -->
The `fd_sha256_append` function appends data to an ongoing SHA-256 hash computation, updating the internal state and buffer as necessary.
- **Inputs**:
    - `sha`: A pointer to an `fd_sha256_t` structure representing the current state of the SHA-256 computation.
    - `_data`: A pointer to the data to be appended to the SHA-256 computation.
    - `sz`: The size in bytes of the data to be appended.
- **Control Flow**:
    - Check if the size `sz` is zero; if so, return the current SHA-256 state without changes.
    - Unpack the internal state, buffer, and counters from the `sha` structure.
    - Update the bit count in the `sha` structure by adding `sz` shifted left by 3 (to convert bytes to bits).
    - If there are buffered bytes from previous appends, check if the new data can complete the current block; if not, buffer the new data and return.
    - If the new data completes the current block, copy enough data to complete the block, update the hash using `fd_sha256_core`, and reset the buffer usage counter.
    - Process the bulk of the data in blocks using `fd_sha256_core` if there are enough bytes to form complete blocks.
    - Buffer any remaining bytes that do not form a complete block and update the buffer usage counter.
- **Output**: Returns a pointer to the updated `fd_sha256_t` structure.


---
### fd\_sha256\_fini<!-- {{#callable:fd_sha256_fini}} -->
The `fd_sha256_fini` function finalizes the SHA-256 hash computation by processing any remaining data, appending padding, and storing the resulting hash.
- **Inputs**:
    - `sha`: A pointer to an `fd_sha256_t` structure containing the current state of the SHA-256 computation.
    - `_hash`: A pointer to a memory location where the final 256-bit (32-byte) hash will be stored.
- **Control Flow**:
    - Unpack the current state, buffer, buffer usage, and bit count from the `sha` structure.
    - Append the terminating message byte `0x80` to the buffer and increment the buffer usage.
    - Check if there is enough space in the buffer to append the message length; if not, clear the buffer, process it, and reset the buffer usage.
    - Clear the buffer up to the last 64 bits, append the message length in bits, and process the buffer to finalize the hash.
    - Perform byte swaps on the state to convert it to big-endian format.
    - Copy the final hash from the state to the `_hash` output buffer.
- **Output**: A pointer to the `_hash` buffer containing the finalized 256-bit hash.


---
### fd\_sha256\_hash<!-- {{#callable:fd_sha256_hash}} -->
The `fd_sha256_hash` function computes the SHA-256 hash of a given data buffer and stores the result in a provided hash buffer.
- **Inputs**:
    - `_data`: A pointer to the input data buffer to be hashed.
    - `sz`: The size of the input data buffer in bytes.
    - `_hash`: A pointer to the buffer where the resulting SHA-256 hash will be stored.
- **Control Flow**:
    - Initialize the SHA-256 state with predefined constants.
    - Calculate the number of complete blocks in the input data and process them using `fd_sha256_core`.
    - Copy any remaining data into a buffer, append the padding byte 0x80, and handle any necessary padding to align the data to the block size.
    - If the buffer is too full to append the message length, process the buffer and reset it.
    - Append the message length in bits to the buffer and process it to finalize the hash.
    - Byte-swap the state to convert it to big-endian format and copy the result to the output hash buffer.
- **Output**: A pointer to the buffer containing the computed SHA-256 hash.


---
### fd\_sha256\_hash\_32<!-- {{#callable:fd_sha256_hash_32}} -->
The `fd_sha256_hash_32` function computes the SHA-256 hash of a fixed 32-byte input data and stores the result in the provided hash buffer.
- **Inputs**:
    - `_data`: A pointer to the input data to be hashed, expected to be 32 bytes in size.
    - `_hash`: A pointer to a buffer where the resulting 32-byte hash will be stored.
- **Control Flow**:
    - Initialize a buffer and state array with predefined SHA-256 initial hash values.
    - Set the size of the data to be hashed to 32 bytes.
    - Calculate the number of complete blocks in the data and process them using `fd_sha256_core` if any exist.
    - Copy any remaining bytes into a buffer, append a '1' bit (0x80), and increment the buffer usage counter.
    - If the buffer usage exceeds the maximum allowed minus 8 bytes, pad the buffer with zeros, process it, and reset the buffer usage counter.
    - Calculate the total bit count of the data, pad the buffer with zeros up to the last 8 bytes, store the bit count in the last 8 bytes, and process the buffer.
    - Byte-swap the state array to convert it to big-endian format.
    - Copy the final hash value from the state array to the provided hash buffer.
- **Output**: A pointer to the hash buffer containing the 32-byte SHA-256 hash of the input data.



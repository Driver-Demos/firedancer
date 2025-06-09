# Purpose
This C source code file implements the SHA-512 and SHA-384 cryptographic hash functions, providing both incremental and one-shot hashing capabilities. The file defines a set of functions to initialize, update, and finalize the hash computation, as well as to perform a complete hash operation in a single call. The code is structured to handle memory alignment and buffer management, ensuring efficient processing of input data. It includes a reference implementation of the SHA-512 core algorithm, derived from OpenSSL's implementation, and is designed to be easily replaceable with optimized versions for specific hardware capabilities, such as AVX2.

The file defines several key functions, including [`fd_sha512_new`](#fd_sha512_new), [`fd_sha512_join`](#fd_sha512_join), [`fd_sha512_append`](#fd_sha512_append), and [`fd_sha512_fini`](#fd_sha512_fini), which manage the lifecycle of a SHA-512 computation. The [`fd_sha512_core_ref`](#fd_sha512_core_ref) function implements the core hashing logic, processing data blocks and updating the hash state. The code also includes conditional compilation to select between different core implementations based on available hardware features. This file is intended to be part of a larger library, as indicated by the inclusion of a header file (`fd_sha512.h`) and the use of macros for configuration and logging. The implementation is designed to be robust, with checks for null pointers and alignment, and it provides detailed logging for error conditions.
# Imports and Dependencies

---
- `fd_sha512.h`


# Functions

---
### fd\_sha512\_align<!-- {{#callable:fd_sha512_align}} -->
The `fd_sha512_align` function returns the alignment requirement for SHA-512 operations.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of the macro `FD_SHA512_ALIGN`.
- **Output**: The function outputs an `ulong` representing the alignment requirement for SHA-512 operations.


---
### fd\_sha512\_footprint<!-- {{#callable:fd_sha512_footprint}} -->
The `fd_sha512_footprint` function returns the constant value `FD_SHA512_FOOTPRINT`, which represents the memory footprint required for a SHA-512 context.
- **Inputs**: None
- **Control Flow**:
    - The function is defined to return an unsigned long integer (`ulong`).
    - It directly returns the value of the macro `FD_SHA512_FOOTPRINT`.
- **Output**: The function outputs an unsigned long integer representing the memory footprint for a SHA-512 context.


---
### fd\_sha512\_new<!-- {{#callable:fd_sha512_new}} -->
The `fd_sha512_new` function initializes a new SHA-512 context in a given shared memory region, ensuring proper alignment and setting a magic number for validation.
- **Inputs**:
    - `shmem`: A pointer to a shared memory region where the SHA-512 context will be initialized.
- **Control Flow**:
    - Cast the `shmem` pointer to a `fd_sha512_t` pointer named `sha`.
    - Check if `shmem` is NULL; if so, log a warning and return NULL.
    - Check if `shmem` is properly aligned using [`fd_sha512_align`](#fd_sha512_align); if not, log a warning and return NULL.
    - Retrieve the footprint size using [`fd_sha512_footprint`](#fd_sha512_footprint).
    - Clear the memory region pointed to by `sha` using `fd_memset` with the footprint size.
    - Use memory fences (`FD_COMPILER_MFENCE`) to ensure memory operations are completed before setting the magic number.
    - Set the `magic` field of `sha` to `FD_SHA512_MAGIC` using a volatile write.
    - Return the `sha` pointer cast back to a `void *`.
- **Output**: A pointer to the initialized SHA-512 context, or NULL if initialization fails due to NULL or misaligned input.
- **Functions called**:
    - [`fd_sha512_align`](#fd_sha512_align)
    - [`fd_sha512_footprint`](#fd_sha512_footprint)


---
### fd\_sha512\_join<!-- {{#callable:fd_sha512_join}} -->
The `fd_sha512_join` function validates and returns a pointer to a `fd_sha512_t` structure if the input shared memory is correctly aligned and initialized.
- **Inputs**:
    - `shsha`: A pointer to shared memory that is expected to contain a `fd_sha512_t` structure.
- **Control Flow**:
    - Check if `shsha` is NULL; if so, log a warning and return NULL.
    - Check if `shsha` is aligned according to [`fd_sha512_align`](#fd_sha512_align); if not, log a warning and return NULL.
    - Cast `shsha` to a `fd_sha512_t` pointer and store it in `sha`.
    - Check if `sha->magic` equals `FD_SHA512_MAGIC`; if not, log a warning and return NULL.
    - Return the `sha` pointer.
- **Output**: A pointer to a `fd_sha512_t` structure if all checks pass, otherwise NULL.
- **Functions called**:
    - [`fd_sha512_align`](#fd_sha512_align)


---
### fd\_sha512\_leave<!-- {{#callable:fd_sha512_leave}} -->
The `fd_sha512_leave` function checks if the given SHA-512 context pointer is non-null and returns it as a void pointer, logging a warning if it is null.
- **Inputs**:
    - `sha`: A pointer to an `fd_sha512_t` structure representing the SHA-512 context.
- **Control Flow**:
    - Check if the `sha` pointer is null using `FD_UNLIKELY`; if it is, log a warning and return `NULL`.
    - If the `sha` pointer is not null, cast it to a `void *` and return it.
- **Output**: Returns the input `sha` pointer cast to a `void *`, or `NULL` if the input is null.


---
### fd\_sha512\_delete<!-- {{#callable:fd_sha512_delete}} -->
The `fd_sha512_delete` function validates and deletes a SHA-512 context by resetting its magic number to zero.
- **Inputs**:
    - `shsha`: A pointer to the SHA-512 context to be deleted.
- **Control Flow**:
    - Check if the input pointer `shsha` is NULL; if so, log a warning and return NULL.
    - Check if `shsha` is properly aligned according to [`fd_sha512_align`](#fd_sha512_align); if not, log a warning and return NULL.
    - Cast `shsha` to a `fd_sha512_t` pointer named `sha`.
    - Verify that the `magic` field of `sha` matches `FD_SHA512_MAGIC`; if not, log a warning and return NULL.
    - Use memory fence operations to ensure memory ordering, then set the `magic` field of `sha` to zero.
    - Return the `sha` pointer cast back to a `void *`.
- **Output**: Returns a pointer to the deleted SHA-512 context if successful, or NULL if any validation checks fail.
- **Functions called**:
    - [`fd_sha512_align`](#fd_sha512_align)


---
### fd\_sha512\_core\_ref<!-- {{#callable:fd_sha512_core_ref}} -->
The `fd_sha512_core_ref` function processes blocks of data to update the SHA-512 hash state using a reference implementation based on OpenSSL's SHA-512 algorithm.
- **Inputs**:
    - `state`: A pointer to an array of 8 unsigned long integers representing the current state of the hash, which must be 64-byte aligned.
    - `block`: A pointer to the input data block, ideally 128-byte aligned, with a size of 128 bytes multiplied by the block count.
    - `block_cnt`: An unsigned long integer representing the number of 128-byte blocks to process, which must be positive.
- **Control Flow**:
    - Initialize constants and macros for SHA-512 operations, including rotation and bitwise operations.
    - Cast the input block to an array of unsigned long integers for processing.
    - Iterate over each block, initializing working variables a through h from the current state.
    - For the first 16 iterations, load and byte-swap each word from the block, compute T1 and T2 using SHA-512 specific functions, and update the working variables.
    - For the remaining 64 iterations, compute additional words using sigma functions, update T1 and T2, and continue updating the working variables.
    - After processing all 80 iterations, update the state array by adding the working variables to the current state.
    - Advance the block pointer by 16 words and decrement the block count, repeating the process until all blocks are processed.
- **Output**: The function updates the input state array to reflect the processed hash state after processing the specified number of blocks.


---
### fd\_sha384\_init<!-- {{#callable:fd_sha384_init}} -->
The `fd_sha384_init` function initializes a SHA-384 context by setting its internal state to predefined constants and resetting its buffer usage and bit count.
- **Inputs**:
    - `sha`: A pointer to an `fd_sha512_t` structure that represents the SHA-384 context to be initialized.
- **Control Flow**:
    - The function sets the first eight elements of the `state` array in the `sha` structure to specific constants that are the initial hash values for SHA-384.
    - The `buf_used` field of the `sha` structure is set to 0, indicating that no data has been buffered yet.
    - The `bit_cnt_lo` and `bit_cnt_hi` fields of the `sha` structure are set to 0, indicating that no bits have been processed yet.
    - The function returns the pointer to the initialized `sha` structure.
- **Output**: A pointer to the initialized `fd_sha512_t` structure, which is ready for use in SHA-384 hashing operations.


---
### fd\_sha512\_init<!-- {{#callable:fd_sha512_init}} -->
The `fd_sha512_init` function initializes a SHA-512 context structure with predefined initial hash values and resets its buffer and bit counters.
- **Inputs**:
    - `sha`: A pointer to an `fd_sha512_t` structure that will be initialized for SHA-512 hashing.
- **Control Flow**:
    - The function sets the `state` array of the `sha` structure to the initial hash values specified by the SHA-512 standard.
    - The `buf_used` field of the `sha` structure is set to 0, indicating that no data is currently buffered.
    - The `bit_cnt_lo` and `bit_cnt_hi` fields are set to 0, resetting the bit count for the hashing process.
    - The function returns the pointer to the initialized `fd_sha512_t` structure.
- **Output**: A pointer to the initialized `fd_sha512_t` structure.


---
### fd\_sha512\_append<!-- {{#callable:fd_sha512_append}} -->
The `fd_sha512_append` function appends data to an ongoing SHA-512 hash computation, updating the internal state and buffer of the hash context.
- **Inputs**:
    - `sha`: A pointer to an `fd_sha512_t` structure representing the current state of the SHA-512 hash computation.
    - `_data`: A pointer to the data to be appended to the hash computation.
    - `sz`: The size in bytes of the data to be appended.
- **Control Flow**:
    - Check if the size of the data (`sz`) is zero; if so, return the current hash state as no data needs to be appended.
    - Unpack the current state, buffer, and bit count from the `sha` structure.
    - Update the bit count to reflect the new data size being appended.
    - If there are buffered bytes from previous appends, check if the new data can complete the current block; if not, buffer the new data and return.
    - If the new data completes the current block, update the hash state using `fd_sha512_core` and reset the buffer usage.
    - Process the bulk of the new data in blocks, updating the hash state for each block using `fd_sha512_core`.
    - Buffer any leftover bytes that do not complete a block, updating the buffer usage in the `sha` structure.
    - Return the updated `sha` structure.
- **Output**: A pointer to the updated `fd_sha512_t` structure, reflecting the new state of the hash computation after appending the data.


---
### fd\_sha512\_fini<!-- {{#callable:fd_sha512_fini}} -->
The `fd_sha512_fini` function finalizes the SHA-512 hashing process by padding the message, processing any remaining data, and producing the final hash output.
- **Inputs**:
    - `sha`: A pointer to an `fd_sha512_t` structure containing the current state of the SHA-512 hash computation.
    - `_hash`: A pointer to a memory location where the final hash value will be stored.
- **Control Flow**:
    - Unpack the current state, buffer, buffer usage, and bit count from the `sha` structure.
    - Append a terminating byte (0x80) to the buffer and increment the buffer usage counter.
    - Check if there is enough space in the buffer to append the message length; if not, pad the buffer with zeros, process the buffer, and reset the buffer usage counter.
    - Pad the buffer with zeros up to the last 128 bits, append the message length in bits to the last 128 bits of the buffer, and process the buffer to finalize the hash.
    - Unpack the final hash state into the provided `_hash` memory location, performing byte swaps as necessary.
- **Output**: Returns a pointer to the memory location where the final hash value is stored.


---
### fd\_sha384\_fini<!-- {{#callable:fd_sha384_fini}} -->
The `fd_sha384_fini` function finalizes a SHA-384 hash computation by completing the SHA-512 process and copying the relevant portion of the hash to the output buffer.
- **Inputs**:
    - `sha`: A pointer to an `fd_sha512_t` structure representing the SHA-512 context that has been used for hashing.
    - `_hash`: A pointer to a buffer where the resulting SHA-384 hash will be stored.
- **Control Flow**:
    - Declare a local buffer `hash` with size `FD_SHA512_HASH_SZ` and align it to 64 bytes.
    - Call [`fd_sha512_fini`](#fd_sha512_fini) with `sha` and `hash` to finalize the SHA-512 hash computation.
    - Copy the first `FD_SHA384_HASH_SZ` bytes from `hash` to `_hash` using `memcpy`.
    - Return the `_hash` pointer.
- **Output**: A pointer to the buffer `_hash` containing the finalized SHA-384 hash.
- **Functions called**:
    - [`fd_sha512_fini`](#fd_sha512_fini)


---
### fd\_sha512\_hash<!-- {{#callable:fd_sha512_hash}} -->
The `fd_sha512_hash` function computes the SHA-512 hash of a given data buffer and stores the result in a provided hash buffer.
- **Inputs**:
    - `_data`: A pointer to the input data buffer to be hashed.
    - `sz`: The size of the input data buffer in bytes.
    - `_hash`: A pointer to the buffer where the resulting SHA-512 hash will be stored.
- **Control Flow**:
    - Initialize the SHA-512 state with predefined constants.
    - Calculate the number of complete 128-byte blocks in the input data and process them using `fd_sha512_core`.
    - Determine the number of remaining bytes after processing complete blocks and copy them to a buffer if necessary.
    - Append the padding byte 0x80 to the buffer and increment the buffer usage counter.
    - If the buffer usage exceeds the maximum allowed minus 16 bytes, pad the buffer with zeros, process it, and reset the buffer usage counter.
    - Calculate the bit count of the input data and store it in the last 16 bytes of the buffer in big-endian format.
    - Process the final buffer using `fd_sha512_core`.
    - Convert the state to big-endian format and store it in the output hash buffer.
- **Output**: A pointer to the buffer containing the computed SHA-512 hash.


---
### fd\_sha384\_hash<!-- {{#callable:fd_sha384_hash}} -->
The `fd_sha384_hash` function computes the SHA-384 hash of a given data buffer and stores the result in a provided hash buffer.
- **Inputs**:
    - `_data`: A pointer to the input data buffer to be hashed.
    - `sz`: The size of the input data buffer in bytes.
    - `_hash`: A pointer to the buffer where the resulting SHA-384 hash will be stored.
- **Control Flow**:
    - Initialize the SHA-384 state with predefined constants specific to SHA-384.
    - Calculate the number of complete 128-byte blocks in the input data and process them using `fd_sha512_core`.
    - Copy any remaining bytes of data into a buffer, append the padding byte 0x80, and handle the padding if necessary.
    - If the buffer is too full to append the length, process the buffer and reset it.
    - Append the length of the input data in bits to the buffer, ensuring it is in big-endian format, and process the final block.
    - Store the first six 64-bit words of the state into the output hash buffer, converting them to big-endian format.
- **Output**: A pointer to the buffer containing the computed SHA-384 hash.



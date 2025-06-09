# Purpose
This C source file is part of a larger codebase related to the "fd_types" module, specifically dealing with encoding and decoding operations for various data structures. The file includes functions for decoding and encoding transaction data (`fd_flamenco_txn_*` functions) and synchronizing tower data (`fd_tower_sync_*` functions). The primary focus of the code is on handling binary encoding and decoding contexts, which are used to serialize and deserialize data structures efficiently. The file also includes functions for walking through IP address structures ([`fd_gossip_ip4_addr_walk`](#fd_gossip_ip4_addr_walk) and [`fd_gossip_ip6_addr_walk`](#fd_gossip_ip6_addr_walk)), which suggests a focus on network-related data processing.

The code is structured to handle specific data types and operations, such as transactions and tower synchronization, with a clear emphasis on error handling and data integrity checks. The use of macros like `FD_UNLIKELY` indicates performance considerations, likely optimizing for common execution paths. The file is not a standalone executable but rather a component intended to be compiled as part of a larger system, as indicated by the preprocessor directive checking for inclusion in the correct compilation unit. The functions defined here are likely part of a library or module that provides specific functionality related to data serialization and deserialization, with some functions marked for testing purposes only.
# Imports and Dependencies

---
- `fd_types_custom.h`
- `fd_bincode.h`
- `fd_types.h`
- `fd_types_meta.h`
- `stdio.h`


# Functions

---
### fd\_flamenco\_txn\_decode\_footprint<!-- {{#callable:fd_flamenco_txn_decode_footprint}} -->
The `fd_flamenco_txn_decode_footprint` function calculates the memory footprint required to decode a transaction and resets the context data pointer after processing.
- **Inputs**:
    - `ctx`: A pointer to a `fd_bincode_decode_ctx_t` structure, which contains the data and data end pointers for decoding.
    - `total_sz`: A pointer to an unsigned long integer that accumulates the total size of the decoded transaction footprint.
- **Control Flow**:
    - Increment the `total_sz` by the size of `fd_flamenco_txn_t` to account for the transaction structure.
    - Store the current data pointer from the context in `start_data` to preserve its initial state.
    - Call [`fd_flamenco_txn_decode_footprint_inner`](#fd_flamenco_txn_decode_footprint_inner) with the context and `total_sz` to perform the actual decoding and footprint calculation.
    - Reset the context's data pointer to `start_data` to restore its original state before returning.
    - Return the error code from [`fd_flamenco_txn_decode_footprint_inner`](#fd_flamenco_txn_decode_footprint_inner).
- **Output**: Returns an integer error code indicating the success or failure of the decoding process.
- **Functions called**:
    - [`fd_flamenco_txn_decode_footprint_inner`](#fd_flamenco_txn_decode_footprint_inner)


---
### fd\_flamenco\_txn\_decode\_footprint\_inner<!-- {{#callable:fd_flamenco_txn_decode_footprint_inner}} -->
The function `fd_flamenco_txn_decode_footprint_inner` decodes a transaction from a binary context and updates the total size of the decoded data.
- **Inputs**:
    - `ctx`: A pointer to a `fd_bincode_decode_ctx_t` structure, which contains the binary data to be decoded and the end of the data buffer.
    - `total_sz`: A pointer to an `ulong` that accumulates the total size of the decoded data.
- **Control Flow**:
    - Check if the current data pointer in the context has reached or exceeded the end of the data buffer, returning an overflow error if true.
    - Calculate the buffer size as the difference between the end of the data buffer and the current data pointer.
    - Initialize a `fd_flamenco_txn_t` structure and a size variable to zero.
    - Call `fd_txn_parse_core` to parse the transaction data, passing the current data pointer, buffer size, transaction storage, and size pointer.
    - If the parsing fails (indicated by a zero result), return a specific error code (-1000001).
    - Update the context's data pointer by advancing it by the size of the parsed data.
    - Add the size of the parsed data to the total size accumulator.
    - Return 0 to indicate successful decoding.
- **Output**: The function returns an integer status code: 0 for success, a specific error code (-1000001) if parsing fails, or an overflow error code if the data pointer exceeds the buffer.


---
### fd\_flamenco\_txn\_encode\_global<!-- {{#callable:FD_FN_UNUSED::fd_flamenco_txn_encode_global}} -->
The `fd_flamenco_txn_encode_global` function is a placeholder function that logs an error message indicating it is only for testing purposes.
- **Inputs**:
    - `self`: A pointer to a constant `fd_flamenco_txn_t` structure, representing the transaction to be encoded.
    - `ctx`: A pointer to a `fd_bincode_encode_ctx_t` structure, representing the encoding context.
- **Control Flow**:
    - The function takes two parameters, `self` and `ctx`, but does not use them, as indicated by the `(void)` cast.
    - It logs an error message using `FD_LOG_ERR`, stating that the function only exists for testing purposes.
- **Output**: The function does not return any value as it is intended to log an error and terminate execution.


---
### fd\_flamenco\_txn\_decode\_global<!-- {{#callable:FD_FN_UNUSED::fd_flamenco_txn_decode_global}} -->
The `fd_flamenco_txn_decode_global` function is a placeholder function that logs an error message indicating it only exists for testing purposes.
- **Inputs**:
    - `mem`: A void pointer intended to represent memory, but is unused in this function.
    - `ctx`: A pointer to a `fd_bincode_decode_ctx_t` structure, which is also unused in this function.
- **Control Flow**:
    - The function takes two parameters, `mem` and `ctx`, but does not use them, as indicated by the `(void)` cast.
    - The function logs an error message using `FD_LOG_ERR`, stating that it only exists for testing purposes.
- **Output**: The function returns a `void *`, but since it only logs an error and does not perform any operations, the return value is effectively unused.


---
### fd\_flamenco\_txn\_decode<!-- {{#callable:fd_flamenco_txn_decode}} -->
The `fd_flamenco_txn_decode` function initializes and decodes a `fd_flamenco_txn_t` transaction from a binary context into a provided memory region.
- **Inputs**:
    - `mem`: A pointer to the memory region where the decoded transaction will be stored.
    - `ctx`: A pointer to the `fd_bincode_decode_ctx_t` structure that provides the binary context for decoding.
- **Control Flow**:
    - Cast the `mem` pointer to a `fd_flamenco_txn_t` pointer and store it in `self`.
    - Initialize the `fd_flamenco_txn_t` structure using `fd_flamenco_txn_new`.
    - Calculate the allocation region starting after the `fd_flamenco_txn_t` structure and store its address in `alloc_mem`.
    - Call [`fd_flamenco_txn_decode_inner`](#fd_flamenco_txn_decode_inner) to perform the actual decoding of the transaction data into the memory region.
    - Return the pointer to the initialized and decoded `fd_flamenco_txn_t` structure.
- **Output**: Returns a pointer to the initialized and decoded `fd_flamenco_txn_t` structure.
- **Functions called**:
    - [`fd_flamenco_txn_decode_inner`](#fd_flamenco_txn_decode_inner)


---
### fd\_flamenco\_txn\_decode\_inner<!-- {{#callable:fd_flamenco_txn_decode_inner}} -->
The `fd_flamenco_txn_decode_inner` function decodes a transaction from a binary context into a structured transaction object, updating the context's data pointer accordingly.
- **Inputs**:
    - `struct_mem`: A pointer to memory where the decoded transaction structure (`fd_flamenco_txn_t`) will be stored.
    - `alloc_mem`: A pointer to a pointer for managing additional memory allocations, though it is not used in this function.
    - `ctx`: A pointer to a `fd_bincode_decode_ctx_t` structure that contains the binary data to be decoded and the endpoint of the data.
- **Control Flow**:
    - Cast `struct_mem` to a `fd_flamenco_txn_t` pointer named `self`.
    - Calculate the buffer size `bufsz` as the difference between `ctx->dataend` and `ctx->data`.
    - Initialize `sz` to 0 and call `fd_txn_parse_core` with the current data, buffer size, transaction storage, counters, and size pointer.
    - Check if `fd_txn_parse_core` returns a non-zero result; if not, log an error and return immediately.
    - Copy the decoded data into `self->raw` and set `self->raw_sz` to the size of the decoded data.
    - Advance the `ctx->data` pointer by the size of the decoded data.
- **Output**: The function does not return a value but modifies the `struct_mem` to contain the decoded transaction and updates the `ctx->data` pointer.


---
### fd\_gossip\_ip4\_addr\_walk<!-- {{#callable:fd_gossip_ip4_addr_walk}} -->
The `fd_gossip_ip4_addr_walk` function iterates over an IPv4 address structure, invoking a callback function for each byte of the address to facilitate processing or inspection.
- **Inputs**:
    - `w`: A pointer to a context or state that is passed to the callback function `fun`.
    - `self`: A pointer to a `fd_gossip_ip4_addr_t` structure representing the IPv4 address to be processed.
    - `fun`: A callback function of type `fd_types_walk_fn_t` that is called for each element of the IPv4 address.
    - `name`: A constant character pointer representing the name associated with the IPv4 address, passed to the callback function.
    - `level`: An unsigned integer representing the current depth level in a hierarchical structure, used for tracking or formatting purposes.
- **Control Flow**:
    - Invoke the callback function `fun` with the entire IPv4 address structure, indicating the start of an array with type `FD_FLAMENCO_TYPE_ARR` and increment the level.
    - Cast the IPv4 address structure to a `uchar` pointer to access individual bytes.
    - Iterate over each of the 4 bytes of the IPv4 address, calling the callback function `fun` for each byte with type `FD_FLAMENCO_TYPE_UCHAR`.
    - Invoke the callback function `fun` again with the entire IPv4 address structure, indicating the end of an array with type `FD_FLAMENCO_TYPE_ARR_END` and decrement the level.
- **Output**: The function does not return a value; it operates by invoking the provided callback function `fun` with various parameters.


---
### fd\_gossip\_ip6\_addr\_walk<!-- {{#callable:fd_gossip_ip6_addr_walk}} -->
The `fd_gossip_ip6_addr_walk` function iterates over each byte of an IPv6 address and applies a specified function to each byte, as well as to the entire address before and after the iteration.
- **Inputs**:
    - `w`: A pointer to a context or state that is passed to the function `fun`.
    - `self`: A constant pointer to an `fd_gossip_ip6_addr_t` structure representing the IPv6 address to be processed.
    - `fun`: A function pointer of type `fd_types_walk_fn_t` that is applied to each byte of the IPv6 address and the address as a whole.
    - `name`: A constant character pointer representing the name associated with the IPv6 address.
    - `level`: An unsigned integer representing the current level of depth in a hierarchical structure, which is incremented and decremented during the function execution.
- **Control Flow**:
    - The function `fun` is called with the entire IPv6 address, indicating the start of processing an array of type `FD_FLAMENCO_TYPE_ARR` with the name 'ip6_addr'.
    - A loop iterates over each of the 16 bytes of the IPv6 address, calling `fun` for each byte with type `FD_FLAMENCO_TYPE_UCHAR` and the name 'uchar'.
    - After processing all bytes, `fun` is called again with the entire IPv6 address, indicating the end of processing the array with type `FD_FLAMENCO_TYPE_ARR_END` and the name 'ip6_addr'.
- **Output**: The function does not return a value; it operates by invoking the provided function `fun` with various parameters.


---
### fd\_tower\_sync\_encode<!-- {{#callable:fd_tower_sync_encode}} -->
The `fd_tower_sync_encode` function is intended to encode a `fd_tower_sync_t` structure into a binary format using a given encoding context, but it is currently not implemented.
- **Inputs**:
    - `self`: A pointer to a constant `fd_tower_sync_t` structure that is intended to be encoded.
    - `ctx`: A pointer to a `fd_bincode_encode_ctx_t` structure that provides the context for encoding the data.
- **Control Flow**:
    - The function logs an error message indicating that the implementation is pending.
- **Output**: The function returns an integer, but since it is not implemented, the return value is not defined.


---
### fd\_tower\_sync\_decode\_footprint\_inner<!-- {{#callable:fd_tower_sync_decode_footprint_inner}} -->
The function `fd_tower_sync_decode_footprint_inner` decodes a binary-encoded tower sync structure, updating the total size and handling potential overflow errors.
- **Inputs**:
    - `ctx`: A pointer to a `fd_bincode_decode_ctx_t` structure, which contains the data to be decoded and the endpoint of the data.
    - `total_sz`: A pointer to an `ulong` that accumulates the total size of the decoded data.
- **Control Flow**:
    - Initialize error variable `err` to 0.
    - Check if the current data pointer exceeds the data end; return overflow error if true.
    - Decode a 64-bit unsigned integer footprint from the context and store any error in `err`.
    - Initialize `root` to 0 and set up a new context `root_ctx` to decode the root value.
    - Decode the root value using `fd_bincode_uint64_decode_unsafe` and handle potential overflow.
    - Check for errors after decoding the root; return if any error is found.
    - Decode the length of lockout offsets using [`fd_bincode_compact_u16_decode`](fd_bincode.h.driver.md#fd_bincode_compact_u16_decode) and store in `lockout_offsets_len`.
    - Calculate the maximum lockout offsets and update `total_sz` with alignment and footprint size.
    - Iterate over each lockout offset, decode its footprint, and update `total_sz`.
    - For each lockout offset, decode it and perform a checked addition with `root`; handle overflow errors.
    - Decode a hash footprint and update `total_sz`.
    - Decode a boolean value to determine if an additional 64-bit integer footprint should be decoded.
    - If the boolean is true, decode the additional 64-bit integer footprint.
    - Decode another hash footprint and update `total_sz`.
    - Return 0 if all operations are successful.
- **Output**: Returns 0 on success, or an error code if any decoding operation fails or if an overflow is detected.
- **Functions called**:
    - [`fd_bincode_compact_u16_decode`](fd_bincode.h.driver.md#fd_bincode_compact_u16_decode)
    - [`fd_lockout_offset_decode_footprint_inner`](fd_types.c.driver.md#fd_lockout_offset_decode_footprint_inner)
    - [`fd_lockout_offset_decode_inner`](fd_types.c.driver.md#fd_lockout_offset_decode_inner)
    - [`fd_hash_decode_footprint_inner`](fd_types.c.driver.md#fd_hash_decode_footprint_inner)
    - [`fd_bincode_bool_decode`](fd_bincode.h.driver.md#fd_bincode_bool_decode)


---
### fd\_tower\_sync\_decode\_footprint<!-- {{#callable:fd_tower_sync_decode_footprint}} -->
The `fd_tower_sync_decode_footprint` function calculates the memory footprint required for decoding a `fd_tower_sync_t` structure and resets the context data pointer after processing.
- **Inputs**:
    - `ctx`: A pointer to a `fd_bincode_decode_ctx_t` structure, which contains the data and data end pointers for decoding.
    - `total_sz`: A pointer to an unsigned long integer that accumulates the total size of the decoded data.
- **Control Flow**:
    - Increment the `total_sz` by the size of `fd_tower_sync_t`.
    - Store the current data pointer from `ctx` in `start_data`.
    - Call [`fd_tower_sync_decode_footprint_inner`](#fd_tower_sync_decode_footprint_inner) with `ctx` and `total_sz` to perform the inner decoding and footprint calculation.
    - Reset the `ctx->data` pointer to `start_data` to restore the original data pointer.
    - Return the error code from [`fd_tower_sync_decode_footprint_inner`](#fd_tower_sync_decode_footprint_inner).
- **Output**: Returns an integer error code indicating the success or failure of the decoding process.
- **Functions called**:
    - [`fd_tower_sync_decode_footprint_inner`](#fd_tower_sync_decode_footprint_inner)


---
### fd\_tower\_sync\_decode\_inner<!-- {{#callable:fd_tower_sync_decode_inner}} -->
The `fd_tower_sync_decode_inner` function decodes a serialized `fd_tower_sync_t` structure from a binary context, handling root, lockout offsets, hash, and optional timestamp fields.
- **Inputs**:
    - `struct_mem`: A pointer to the memory location where the `fd_tower_sync_t` structure will be decoded into.
    - `alloc_mem`: A pointer to a pointer used for memory allocation during the decoding process.
    - `ctx`: A pointer to the `fd_bincode_decode_ctx_t` context, which contains the binary data to be decoded.
- **Control Flow**:
    - Cast `struct_mem` to `fd_tower_sync_t` and set `has_root` to 1.
    - Decode a 64-bit unsigned integer from `ctx` into `self->root` and update `has_root` based on whether `root` is `ULONG_MAX`.
    - Decode a compact 16-bit unsigned integer from `ctx` into `lockout_offsets_len`.
    - Determine `lockout_offsets_max` as the maximum of `lockout_offsets_len` and 32.
    - Allocate memory for `self->lockouts` using [`deq_fd_vote_lockout_t_join_new`](fd_types.h.driver.md#deq_fd_vote_lockout_t_join_new) with `alloc_mem` and `lockout_offsets_max`.
    - Initialize `last_slot` to 0 if `root` is `ULONG_MAX`, otherwise to `root`.
    - Iterate over `lockout_offsets_len` to decode lockout offsets and populate `self->lockouts`.
    - For each lockout offset, decode it using [`fd_lockout_offset_decode_inner`](fd_types.c.driver.md#fd_lockout_offset_decode_inner), calculate `elem->slot`, and update `last_slot`.
    - Decode `self->hash` using [`fd_hash_decode_inner`](fd_types.c.driver.md#fd_hash_decode_inner).
    - Decode a boolean from `ctx` to determine if `self->timestamp` should be decoded, and if so, decode it as a 64-bit integer.
    - Decode `self->block_id` using [`fd_hash_decode_inner`](fd_types.c.driver.md#fd_hash_decode_inner).
- **Output**: The function does not return a value; it populates the `fd_tower_sync_t` structure pointed to by `struct_mem` with decoded data.
- **Functions called**:
    - [`fd_bincode_compact_u16_decode_unsafe`](fd_bincode.h.driver.md#fd_bincode_compact_u16_decode_unsafe)
    - [`deq_fd_vote_lockout_t_join_new`](fd_types.h.driver.md#deq_fd_vote_lockout_t_join_new)
    - [`fd_lockout_offset_decode_inner`](fd_types.c.driver.md#fd_lockout_offset_decode_inner)
    - [`fd_hash_decode_inner`](fd_types.c.driver.md#fd_hash_decode_inner)
    - [`fd_bincode_bool_decode_unsafe`](fd_bincode.h.driver.md#fd_bincode_bool_decode_unsafe)


---
### fd\_tower\_sync\_decode<!-- {{#callable:fd_tower_sync_decode}} -->
The `fd_tower_sync_decode` function initializes a `fd_tower_sync_t` structure and decodes data from a binary context into it.
- **Inputs**:
    - `mem`: A pointer to a memory region where the `fd_tower_sync_t` structure will be initialized and decoded.
    - `ctx`: A pointer to a `fd_bincode_decode_ctx_t` structure that provides the context for binary decoding.
- **Control Flow**:
    - Cast the `mem` pointer to a `fd_tower_sync_t` pointer named `self`.
    - Call [`fd_tower_sync_new`](fd_types.c.driver.md#fd_tower_sync_new) to initialize the `fd_tower_sync_t` structure at `self`.
    - Calculate the allocation region starting after the `fd_tower_sync_t` structure in memory.
    - Create a pointer `alloc_mem` pointing to the allocation region.
    - Call [`fd_tower_sync_decode_inner`](#fd_tower_sync_decode_inner) to perform the actual decoding of data from `ctx` into the `fd_tower_sync_t` structure using `alloc_mem`.
    - Return the pointer `self` which now contains the decoded data.
- **Output**: A pointer to the initialized and decoded `fd_tower_sync_t` structure.
- **Functions called**:
    - [`fd_tower_sync_new`](fd_types.c.driver.md#fd_tower_sync_new)
    - [`fd_tower_sync_decode_inner`](#fd_tower_sync_decode_inner)


---
### fd\_tower\_sync\_decode\_inner\_global<!-- {{#callable:fd_tower_sync_decode_inner_global}} -->
The `fd_tower_sync_decode_inner_global` function is a placeholder for decoding a global tower sync structure from a binary context, but it is not yet implemented.
- **Inputs**:
    - `struct_mem`: A pointer to the memory location where the decoded structure will be stored.
    - `alloc_mem`: A pointer to a pointer used for managing additional memory allocations during decoding.
    - `ctx`: A pointer to a `fd_bincode_decode_ctx_t` structure that provides the context for binary decoding, including data pointers and limits.
- **Control Flow**:
    - The function currently logs an error message indicating that it is not implemented.
- **Output**: The function does not produce any output as it is not implemented.


# Function Declarations (Public API)

---
### fd\_hash\_decode\_inner<!-- {{#callable_declaration:fd_hash_decode_inner}} -->
Decodes a hash from a binary context into a structure.
- **Description**: Use this function to decode a hash from a binary context and store it in a provided memory structure. This function is typically called as part of a larger decoding process where a hash needs to be extracted from a binary stream. It is important to ensure that the context is properly initialized and that the memory provided is sufficient to hold the decoded hash. The function does not handle any memory allocation or deallocation, so the caller must manage the memory lifecycle.
- **Inputs**:
    - `struct_mem`: A pointer to the memory location where the decoded hash will be stored. Must not be null and should be large enough to hold the hash.
    - `alloc_mem`: A pointer to a pointer used for memory allocation tracking. The function does not modify this parameter, so it can be null if allocation tracking is not needed.
    - `ctx`: A pointer to the decoding context, which contains the binary data to be decoded. Must not be null and should be properly initialized before calling this function.
- **Output**: None
- **See also**: [`fd_hash_decode_inner`](fd_types.c.driver.md#fd_hash_decode_inner)  (Implementation)


---
### fd\_hash\_decode\_footprint\_inner<!-- {{#callable_declaration:fd_hash_decode_footprint_inner}} -->
Calculates the memory footprint required for decoding a hash.
- **Description**: This function is used to determine the amount of memory needed to decode a hash from a binary encoding context. It should be called when you need to calculate the memory footprint before performing the actual decoding operation. The function checks if the current position in the context has reached the end of the data, in which case it returns an overflow error. It is important to ensure that the context is properly initialized and that the data pointer is within valid bounds before calling this function.
- **Inputs**:
    - `ctx`: A pointer to an fd_bincode_decode_ctx_t structure representing the binary decoding context. The data pointer within this context must not exceed the dataend pointer, otherwise an overflow error is returned.
    - `total_sz`: A pointer to an unsigned long where the function will add the size of the hash to the existing total size. The caller retains ownership and must ensure this pointer is valid.
- **Output**: Returns an integer indicating success or an overflow error if the data pointer exceeds the dataend pointer in the context.
- **See also**: [`fd_hash_decode_footprint_inner`](fd_types.c.driver.md#fd_hash_decode_footprint_inner)  (Implementation)


---
### fd\_lockout\_offset\_decode\_inner<!-- {{#callable_declaration:fd_lockout_offset_decode_inner}} -->
Decodes a lockout offset structure from a binary context.
- **Description**: This function is used to decode a `fd_lockout_offset_t` structure from a binary encoding context. It should be called when you need to extract lockout offset data from a binary stream, typically as part of a larger decoding process. The function requires a valid memory location to store the decoded structure and a decoding context that provides the binary data. It is important to ensure that the context has sufficient data available to decode the required fields, as the function does not perform bounds checking.
- **Inputs**:
    - `struct_mem`: A pointer to the memory location where the decoded `fd_lockout_offset_t` structure will be stored. Must not be null.
    - `alloc_mem`: A pointer to a memory allocation pointer, which is not used in this function. Can be null.
    - `ctx`: A pointer to a `fd_bincode_decode_ctx_t` structure that provides the binary data to decode. Must not be null and should have sufficient data available for decoding.
- **Output**: None
- **See also**: [`fd_lockout_offset_decode_inner`](fd_types.c.driver.md#fd_lockout_offset_decode_inner)  (Implementation)


---
### fd\_lockout\_offset\_decode\_footprint\_inner<!-- {{#callable_declaration:fd_lockout_offset_decode_footprint_inner}} -->
Calculates the footprint required for decoding a lockout offset.
- **Description**: This function is used to determine the memory footprint required to decode a lockout offset from a binary encoding context. It should be called when you need to calculate the size needed for decoding operations involving lockout offsets. The function expects the decoding context to be valid and not exceed its data boundaries. It returns an error code if the context data pointer is at or beyond the data end, indicating an overflow condition.
- **Inputs**:
    - `ctx`: A pointer to a `fd_bincode_decode_ctx_t` structure representing the binary decoding context. It must not be null and should have valid data and dataend pointers. The function will return an overflow error if `ctx->data` is greater than or equal to `ctx->dataend`.
    - `total_sz`: A pointer to an `ulong` where the function will accumulate the total size required for decoding. The caller must ensure this pointer is valid and initialized before calling the function.
- **Output**: Returns an integer error code. Returns `FD_BINCODE_ERR_OVERFLOW` if the data pointer exceeds the data end, otherwise returns 0 on success.
- **See also**: [`fd_lockout_offset_decode_footprint_inner`](fd_types.c.driver.md#fd_lockout_offset_decode_footprint_inner)  (Implementation)



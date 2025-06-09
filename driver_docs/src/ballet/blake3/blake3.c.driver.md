# Purpose
This C source code file is part of the BLAKE3 cryptographic hash function implementation. It provides the core functionality for hashing data using the BLAKE3 algorithm, which is known for its speed and security. The file includes functions for initializing, updating, and finalizing a hash computation, as well as handling different modes such as keyed hashing and key derivation. The code is structured around the concept of "chunk states" and "output" structures, which manage the state of the hash computation and the intermediate results, respectively. The use of SIMD (Single Instruction, Multiple Data) parallelism is evident in functions like [`compress_chunks_parallel`](#compress_chunks_parallel) and [`compress_parents_parallel`](#compress_parents_parallel), which optimize the hashing process by processing multiple chunks or parent nodes simultaneously.

The file defines several inline functions and utility functions that handle the internal mechanics of the BLAKE3 algorithm, such as managing chunk states, computing chaining values, and handling the tree structure of the hash computation. It also includes functions for merging chaining values and managing the hash state stack, which are crucial for the algorithm's performance and correctness. The code is designed to be efficient and portable, with careful attention to memory operations and alignment. This file is intended to be part of a larger library, as indicated by the inclusion of header files like "blake3.h" and "blake3_impl.h", and it does not define a standalone executable. Instead, it provides the core hashing functionality that can be used by other parts of the BLAKE3 library or by external applications that require cryptographic hashing capabilities.
# Imports and Dependencies

---
- `assert.h`
- `stdbool.h`
- `string.h`
- `blake3.h`
- `blake3_impl.h`


# Data Structures

---
### output\_t
- **Type**: `struct`
- **Members**:
    - `input_cv`: An array of 8 32-bit unsigned integers representing the input chaining value.
    - `counter`: A 64-bit unsigned integer used as a counter for the number of blocks processed.
    - `block`: An array of bytes with length defined by BLAKE3_BLOCK_LEN, representing a block of input data.
    - `block_len`: An 8-bit unsigned integer indicating the length of the current block.
    - `flags`: An 8-bit unsigned integer used to store flags that modify the behavior of the hash function.
- **Description**: The `output_t` structure is a key component in the BLAKE3 hashing algorithm, encapsulating the state of a hash output. It holds the input chaining value, a counter for the number of blocks processed, a block of input data, the length of this block, and flags that influence the hashing process. This structure is used to manage and manipulate the intermediate state during the hash computation, ensuring that the correct data and parameters are applied at each step of the algorithm.


# Functions

---
### blake3\_version<!-- {{#callable:blake3_version}} -->
The `blake3_version` function returns the version string of the BLAKE3 hashing algorithm.
- **Inputs**: None
- **Control Flow**:
    - The function is defined to return a constant character pointer.
    - It directly returns the macro `BLAKE3_VERSION_STRING`.
- **Output**: A constant character pointer to the version string of the BLAKE3 hashing algorithm.


---
### chunk\_state\_init<!-- {{#callable:chunk_state_init}} -->
The `chunk_state_init` function initializes a `blake3_chunk_state` structure with a given key and flags, setting its internal state to default values.
- **Inputs**:
    - `self`: A pointer to a `blake3_chunk_state` structure that will be initialized.
    - `key`: A constant array of 8 `uint32_t` values representing the key used for initialization.
    - `flags`: A `uint8_t` value representing the flags to be set in the chunk state.
- **Control Flow**:
    - Copy the provided key into the chaining value (`cv`) of the `blake3_chunk_state` structure using `fd_memcpy`.
    - Set the `chunk_counter` of the `blake3_chunk_state` to 0.
    - Clear the buffer (`buf`) of the `blake3_chunk_state` by setting all its bytes to 0 using `memset`.
    - Set the `buf_len` of the `blake3_chunk_state` to 0, indicating an empty buffer.
    - Set the `blocks_compressed` of the `blake3_chunk_state` to 0, indicating no blocks have been compressed yet.
    - Assign the provided `flags` to the `flags` field of the `blake3_chunk_state`.
- **Output**: The function does not return a value; it initializes the `blake3_chunk_state` structure in place.


---
### chunk\_state\_reset<!-- {{#callable:chunk_state_reset}} -->
The `chunk_state_reset` function reinitializes a `blake3_chunk_state` structure with a given key and chunk counter, resetting its internal state for a new chunk of data.
- **Inputs**:
    - `self`: A pointer to a `blake3_chunk_state` structure that is to be reset.
    - `key`: A constant array of 8 `uint32_t` values representing the key used for the BLAKE3 hash function.
    - `chunk_counter`: A `uint64_t` value representing the chunk counter to be set in the `blake3_chunk_state` structure.
- **Control Flow**:
    - Copy the provided key into the chaining value (`cv`) of the `blake3_chunk_state` structure using `fd_memcpy`.
    - Set the `chunk_counter` of the `blake3_chunk_state` structure to the provided `chunk_counter` value.
    - Reset the `blocks_compressed` field of the `blake3_chunk_state` structure to 0.
    - Clear the buffer (`buf`) of the `blake3_chunk_state` structure by setting all its bytes to 0 using `memset`.
    - Set the `buf_len` field of the `blake3_chunk_state` structure to 0.
- **Output**: This function does not return a value; it modifies the `blake3_chunk_state` structure in place.


---
### chunk\_state\_len<!-- {{#callable:chunk_state_len}} -->
The `chunk_state_len` function calculates the total length of data processed in a BLAKE3 chunk state by summing the lengths of compressed blocks and the current buffer.
- **Inputs**:
    - `self`: A pointer to a `blake3_chunk_state` structure, which contains the state of a BLAKE3 chunk including the number of blocks compressed and the length of the current buffer.
- **Control Flow**:
    - The function multiplies `BLAKE3_BLOCK_LEN` by the number of blocks compressed (`self->blocks_compressed`) to get the total length of compressed blocks.
    - It adds the length of the current buffer (`self->buf_len`) to the total length of compressed blocks.
    - The sum of these two values is returned as the total length of data processed in the chunk state.
- **Output**: The function returns a `size_t` value representing the total length of data processed in the chunk state, including both compressed blocks and the current buffer.


---
### chunk\_state\_fill\_buf<!-- {{#callable:chunk_state_fill_buf}} -->
The `chunk_state_fill_buf` function fills the buffer of a BLAKE3 chunk state with input data up to the block length or the input length, whichever is smaller.
- **Inputs**:
    - `self`: A pointer to a `blake3_chunk_state` structure, which holds the current state of the chunk being processed.
    - `input`: A pointer to the input data to be copied into the chunk state's buffer.
    - `input_len`: The length of the input data in bytes.
- **Control Flow**:
    - Calculate the number of bytes to take from the input, which is the minimum of the remaining space in the buffer and the input length.
    - Copy the calculated number of bytes from the input to the buffer in the chunk state.
    - Update the buffer length in the chunk state by adding the number of bytes taken.
    - Return the number of bytes taken from the input.
- **Output**: The function returns the number of bytes copied from the input to the buffer.


---
### chunk\_state\_maybe\_start\_flag<!-- {{#callable:chunk_state_maybe_start_flag}} -->
The `chunk_state_maybe_start_flag` function determines if a chunk is at the start by checking if any blocks have been compressed, returning a start flag if none have been compressed.
- **Inputs**:
    - `self`: A pointer to a `blake3_chunk_state` structure, which holds the state of a chunk in the BLAKE3 hashing process.
- **Control Flow**:
    - Check if `self->blocks_compressed` is equal to 0.
    - If true, return the constant `CHUNK_START`.
    - If false, return 0.
- **Output**: Returns a `uint8_t` value, which is `CHUNK_START` if no blocks have been compressed, otherwise 0.


---
### make\_output<!-- {{#callable:make_output}} -->
The `make_output` function initializes and returns an `output_t` structure with specified input chaining value, block data, block length, counter, and flags.
- **Inputs**:
    - `input_cv`: A constant array of 8 uint32_t values representing the input chaining value.
    - `block`: A constant array of bytes with length `BLAKE3_BLOCK_LEN` representing the block data.
    - `block_len`: A uint8_t value representing the length of the block.
    - `counter`: A uint64_t value representing the counter.
    - `flags`: A uint8_t value representing the flags.
- **Control Flow**:
    - An `output_t` structure named `ret` is declared.
    - The `input_cv` array is copied into `ret.input_cv` using `fd_memcpy`.
    - The `block` array is copied into `ret.block` using `fd_memcpy`.
    - The `block_len` is assigned to `ret.block_len`.
    - The `counter` is assigned to `ret.counter`.
    - The `flags` are assigned to `ret.flags`.
    - The initialized `output_t` structure `ret` is returned.
- **Output**: The function returns an `output_t` structure containing the initialized values.


---
### output\_chaining\_value<!-- {{#callable:output_chaining_value}} -->
The `output_chaining_value` function computes a chaining value from an `output_t` structure and stores it in a 32-byte array.
- **Inputs**:
    - `self`: A pointer to an `output_t` structure containing the input chaining value, block, block length, counter, and flags.
    - `cv`: A 32-byte array where the resulting chaining value will be stored.
- **Control Flow**:
    - Copy the input chaining value from `self->input_cv` to a local `cv_words` array.
    - Call [`fd_blake3_compress_in_place`](blake3_dispatch.c.driver.md#fd_blake3_compress_in_place) to compress the block data in `self` using the local `cv_words`, block, block length, counter, and flags.
    - Store the resulting compressed chaining value from `cv_words` into the `cv` array.
- **Output**: The function does not return a value but modifies the `cv` array to contain the computed chaining value.
- **Functions called**:
    - [`fd_blake3_compress_in_place`](blake3_dispatch.c.driver.md#fd_blake3_compress_in_place)
    - [`store_cv_words`](blake3_impl.h.driver.md#store_cv_words)


---
### output\_root\_bytes<!-- {{#callable:output_root_bytes}} -->
The `output_root_bytes` function generates a sequence of bytes from a BLAKE3 hash output starting at a specified position and writes them into a provided buffer.
- **Inputs**:
    - `self`: A pointer to an `output_t` structure containing the input chaining value, block, block length, counter, and flags for the BLAKE3 hash.
    - `seek`: A 64-bit unsigned integer specifying the starting position within the hash output from which to begin writing bytes.
    - `out`: A pointer to a buffer where the generated bytes will be written.
    - `out_len`: The number of bytes to write into the output buffer.
- **Control Flow**:
    - Initialize `output_block_counter` to the block index derived from `seek` divided by 64.
    - Calculate `offset_within_block` as the remainder of `seek` divided by 64.
    - Enter a loop that continues until `out_len` is zero.
    - Within the loop, call [`fd_blake3_compress_xof`](blake3_dispatch.c.driver.md#fd_blake3_compress_xof) to fill `wide_buf` with 64 bytes of hash output for the current block counter.
    - Determine the number of bytes available to copy from `wide_buf` based on `offset_within_block`.
    - Copy the appropriate number of bytes from `wide_buf` to `out`, updating `out`, `out_len`, and `offset_within_block` accordingly.
    - Increment `output_block_counter` and reset `offset_within_block` to zero for the next iteration.
- **Output**: The function does not return a value; it writes the specified number of bytes into the provided output buffer.
- **Functions called**:
    - [`fd_blake3_compress_xof`](blake3_dispatch.c.driver.md#fd_blake3_compress_xof)


---
### chunk\_state\_update<!-- {{#callable:chunk_state_update}} -->
The `chunk_state_update` function processes input data in chunks, updating the state of a BLAKE3 chunk by filling its buffer and compressing data as needed.
- **Inputs**:
    - `self`: A pointer to a `blake3_chunk_state` structure representing the current state of the chunk being processed.
    - `input`: A pointer to the input data to be processed, represented as an array of `uint8_t`.
    - `input_len`: The length of the input data in bytes, represented as a `size_t`.
- **Control Flow**:
    - Check if there is any data in the buffer (`self->buf_len > 0`).
    - If the buffer is not empty, fill the buffer with as much input data as possible using [`chunk_state_fill_buf`](#chunk_state_fill_buf), and adjust the input pointer and length accordingly.
    - If there is still input data remaining after filling the buffer, compress the buffer in place using [`fd_blake3_compress_in_place`](blake3_dispatch.c.driver.md#fd_blake3_compress_in_place), increment the `blocks_compressed` counter, reset the buffer length to 0, and clear the buffer.
    - While there is more input data than a block length (`BLAKE3_BLOCK_LEN`), compress each block of input data in place, increment the `blocks_compressed` counter, and adjust the input pointer and length accordingly.
    - Finally, fill the buffer with any remaining input data using [`chunk_state_fill_buf`](#chunk_state_fill_buf).
- **Output**: The function does not return a value; it updates the state of the `blake3_chunk_state` structure in place.
- **Functions called**:
    - [`chunk_state_fill_buf`](#chunk_state_fill_buf)
    - [`fd_blake3_compress_in_place`](blake3_dispatch.c.driver.md#fd_blake3_compress_in_place)
    - [`chunk_state_maybe_start_flag`](#chunk_state_maybe_start_flag)


---
### chunk\_state\_output<!-- {{#callable:chunk_state_output}} -->
The `chunk_state_output` function generates an output structure from a given BLAKE3 chunk state by setting appropriate flags and calling the [`make_output`](#make_output) function.
- **Inputs**:
    - `self`: A pointer to a `blake3_chunk_state` structure, which contains the current state of a BLAKE3 chunk including chaining value, buffer, buffer length, chunk counter, and flags.
- **Control Flow**:
    - Calculate `block_flags` by combining the chunk state's flags, the result of `chunk_state_maybe_start_flag(self)`, and the `CHUNK_END` flag.
    - Call [`make_output`](#make_output) with the chunk state's chaining value (`cv`), buffer (`buf`), buffer length (`buf_len`), chunk counter, and the calculated `block_flags`.
    - Return the output structure generated by [`make_output`](#make_output).
- **Output**: An `output_t` structure containing the chaining value, block, block length, counter, and flags derived from the chunk state.
- **Functions called**:
    - [`chunk_state_maybe_start_flag`](#chunk_state_maybe_start_flag)
    - [`make_output`](#make_output)


---
### parent\_output<!-- {{#callable:parent_output}} -->
The `parent_output` function creates an `output_t` structure representing a parent node in the BLAKE3 hash tree using a given block, key, and flags.
- **Inputs**:
    - `block`: A byte array of length `BLAKE3_BLOCK_LEN` representing the block data for the parent node.
    - `key`: An array of 8 `uint32_t` values representing the key used in the BLAKE3 hash function.
    - `flags`: A `uint8_t` value representing the flags to be used, which are combined with the `PARENT` flag.
- **Control Flow**:
    - The function calls [`make_output`](#make_output) with the provided `key`, `block`, `BLAKE3_BLOCK_LEN`, a counter value of 0, and the `flags` combined with the `PARENT` flag.
    - The [`make_output`](#make_output) function constructs and returns an `output_t` structure with the provided parameters.
- **Output**: An `output_t` structure representing the parent node in the BLAKE3 hash tree.
- **Functions called**:
    - [`make_output`](#make_output)


---
### left\_len<!-- {{#callable:left_len}} -->
The `left_len` function calculates the number of bytes that should be allocated to the left subtree when dividing input data larger than one chunk, ensuring at least one byte remains for the right subtree.
- **Inputs**:
    - `content_len`: The total length of the content in bytes, which should be greater than `BLAKE3_CHUNK_LEN`.
- **Control Flow**:
    - Subtract 1 from `content_len` to ensure at least one byte is reserved for the right subtree.
    - Calculate the number of full chunks by dividing the adjusted `content_len` by `BLAKE3_CHUNK_LEN`.
    - Use [`round_down_to_power_of_2`](blake3_impl.h.driver.md#round_down_to_power_of_2) to find the largest power-of-2 number of chunks that can fit in the calculated full chunks.
    - Multiply the result by `BLAKE3_CHUNK_LEN` to get the byte length for the left subtree.
- **Output**: The function returns the number of bytes that should be allocated to the left subtree, which is a power-of-2 multiple of `BLAKE3_CHUNK_LEN`.
- **Functions called**:
    - [`round_down_to_power_of_2`](blake3_impl.h.driver.md#round_down_to_power_of_2)


---
### compress\_chunks\_parallel<!-- {{#callable:compress_chunks_parallel}} -->
The `compress_chunks_parallel` function uses SIMD parallelism to hash multiple chunks of input data simultaneously, producing chunk chaining values.
- **Inputs**:
    - `input`: A pointer to the input data to be hashed.
    - `input_len`: The length of the input data in bytes.
    - `key`: An array of 8 uint32_t values representing the key used for hashing.
    - `chunk_counter`: A uint64_t value representing the starting chunk counter.
    - `flags`: A uint8_t value representing flags that modify the hashing behavior.
    - `out`: A pointer to the output buffer where the resulting chunk chaining values will be stored.
- **Control Flow**:
    - Initialize an array to hold pointers to chunks of the input data.
    - Iterate over the input data, dividing it into chunks of size `BLAKE3_CHUNK_LEN` and storing pointers to these chunks in the array.
    - Call [`fd_blake3_hash_many`](blake3_dispatch.c.driver.md#fd_blake3_hash_many) to hash the chunks in parallel using SIMD, storing the results in the output buffer.
    - Check if there is a remaining partial chunk of data that was not processed in the loop.
    - If a partial chunk exists, initialize a `blake3_chunk_state`, update it with the remaining data, and compute its output.
    - Store the chaining value of the partial chunk in the output buffer and return the total number of chunks processed, including the partial chunk if present.
- **Output**: The function returns the number of chunks processed, including any partial chunk.
- **Functions called**:
    - [`fd_blake3_hash_many`](blake3_dispatch.c.driver.md#fd_blake3_hash_many)
    - [`chunk_state_init`](#chunk_state_init)
    - [`chunk_state_update`](#chunk_state_update)
    - [`chunk_state_output`](#chunk_state_output)
    - [`output_chaining_value`](#output_chaining_value)


---
### compress\_parents\_parallel<!-- {{#callable:compress_parents_parallel}} -->
The `compress_parents_parallel` function uses SIMD parallelism to hash up to a maximum number of parent nodes at once, writing out the parent chaining values and returning the number of parents hashed, with special handling for any odd leftover child chaining value.
- **Inputs**:
    - `child_chaining_values`: A pointer to an array of child chaining values represented as bytes.
    - `num_chaining_values`: The number of chaining values in the child_chaining_values array.
    - `key`: An array of 8 uint32_t values representing the key used for hashing.
    - `flags`: A uint8_t value representing flags that modify the hashing behavior.
    - `out`: A pointer to an array where the output parent chaining values will be written.
- **Control Flow**:
    - The function begins by asserting that the number of chaining values is at least 2 and does not exceed twice the maximum SIMD degree, if BLAKE3_TESTING is defined.
    - An array `parents_array` is initialized to store pointers to pairs of child chaining values.
    - A loop iterates to fill `parents_array` with pointers to pairs of child chaining values until fewer than two pairs remain.
    - The [`fd_blake3_hash_many`](blake3_dispatch.c.driver.md#fd_blake3_hash_many) function is called to hash the parent nodes in parallel, using the `parents_array` and writing the results to `out`.
    - If there is an odd child chaining value left over, it is copied directly to the output array `out`.
    - The function returns the number of parent nodes hashed, plus one if there was an odd child chaining value left over.
- **Output**: The function returns the number of parent nodes hashed, plus one if there was an odd child chaining value left over.
- **Functions called**:
    - [`fd_blake3_hash_many`](blake3_dispatch.c.driver.md#fd_blake3_hash_many)


---
### fd\_blake3\_compress\_subtree\_wide<!-- {{#callable:fd_blake3_compress_subtree_wide}} -->
The `fd_blake3_compress_subtree_wide` function recursively compresses a large input into a wide array of chaining values using the BLAKE3 hash function, optimizing for SIMD parallelism.
- **Inputs**:
    - `input`: A pointer to the input data to be compressed.
    - `input_len`: The length of the input data in bytes.
    - `key`: An array of 8 32-bit unsigned integers representing the key for the BLAKE3 hash function.
    - `chunk_counter`: A 64-bit unsigned integer representing the starting chunk counter for the input data.
    - `flags`: A byte representing flags that modify the behavior of the compression.
    - `out`: A pointer to the output buffer where the resulting chaining values will be stored.
- **Control Flow**:
    - Check if the input length is less than or equal to the product of the SIMD degree and BLAKE3_CHUNK_LEN; if true, call [`compress_chunks_parallel`](#compress_chunks_parallel) and return its result.
    - Calculate the lengths of the left and right subtrees using [`left_len`](#left_len) and divide the input accordingly.
    - Adjust the chunk counter for the right subtree based on the left subtree's length.
    - Allocate space for child outputs using `cv_array` and determine the degree of parallelism.
    - Recursively call `fd_blake3_compress_subtree_wide` for both left and right subtrees to fill `cv_array` and `right_cvs`.
    - If both left and right subtree results are 1, copy the results directly to the output to ensure at least two outputs and return 2.
    - Otherwise, perform one layer of parent node compression using [`compress_parents_parallel`](#compress_parents_parallel) and return its result.
- **Output**: The function returns the number of chaining values written to the output buffer, which is determined by the compression process.
- **Functions called**:
    - [`fd_blake3_simd_degree`](blake3_dispatch.c.driver.md#fd_blake3_simd_degree)
    - [`compress_chunks_parallel`](#compress_chunks_parallel)
    - [`left_len`](#left_len)
    - [`compress_parents_parallel`](#compress_parents_parallel)


---
### compress\_subtree\_to\_parent\_node<!-- {{#callable:compress_subtree_to_parent_node}} -->
The `compress_subtree_to_parent_node` function compresses a subtree of input data into a parent node, producing two chaining values without compressing the final parent node.
- **Inputs**:
    - `input`: A pointer to the input data to be compressed.
    - `input_len`: The length of the input data in bytes.
    - `key`: An array of 8 uint32_t values representing the key used for compression.
    - `chunk_counter`: A uint64_t value representing the chunk counter for the input data.
    - `flags`: A uint8_t value representing flags that modify the compression behavior.
    - `out`: An array of 2 * BLAKE3_OUT_LEN bytes where the output chaining values will be stored.
- **Control Flow**:
    - Assert that input_len is greater than BLAKE3_CHUNK_LEN if BLAKE3_TESTING is defined.
    - Call fd_blake3_compress_subtree_wide to compress the input data into an array of chaining values stored in cv_array.
    - Assert that the number of chaining values (num_cvs) is less than or equal to MAX_SIMD_DEGREE_OR_2.
    - If num_cvs is greater than 2, repeatedly call compress_parents_parallel to reduce the number of chaining values to 2, updating cv_array with the results each time.
    - Copy the final two chaining values from cv_array to the output array out.
- **Output**: The function outputs two chaining values stored in the out array, representing the compressed parent node of the input subtree.
- **Functions called**:
    - [`fd_blake3_compress_subtree_wide`](#fd_blake3_compress_subtree_wide)
    - [`compress_parents_parallel`](#compress_parents_parallel)


---
### hasher\_init\_base<!-- {{#callable:hasher_init_base}} -->
The `hasher_init_base` function initializes a BLAKE3 hasher structure with a given key and flags, setting up its internal state for hashing operations.
- **Inputs**:
    - `self`: A pointer to a `blake3_hasher` structure that will be initialized.
    - `key`: A constant array of 8 `uint32_t` values representing the key used for the hasher initialization.
    - `flags`: A `uint8_t` value representing the flags to be used during the initialization of the hasher.
- **Control Flow**:
    - Copy the provided key into the `key` field of the `blake3_hasher` structure using `fd_memcpy`.
    - Initialize the `chunk` field of the `blake3_hasher` structure by calling [`chunk_state_init`](#chunk_state_init) with the provided key and flags.
    - Set the `cv_stack_len` field of the `blake3_hasher` structure to 0, indicating an empty chaining value stack.
- **Output**: This function does not return a value; it initializes the state of the `blake3_hasher` structure pointed to by `self`.
- **Functions called**:
    - [`chunk_state_init`](#chunk_state_init)


---
### fd\_blake3\_hasher\_init<!-- {{#callable:fd_blake3_hasher_init}} -->
The `fd_blake3_hasher_init` function initializes a BLAKE3 hasher object with a default initialization vector and no flags.
- **Inputs**:
    - `self`: A pointer to a `blake3_hasher` structure that will be initialized.
- **Control Flow**:
    - The function calls [`hasher_init_base`](#hasher_init_base) with the `self` pointer, a predefined initialization vector `IV`, and a flag value of `0`.
- **Output**: The function does not return a value; it initializes the `blake3_hasher` structure pointed to by `self`.
- **Functions called**:
    - [`hasher_init_base`](#hasher_init_base)


---
### fd\_blake3\_hasher\_init\_keyed<!-- {{#callable:fd_blake3_hasher_init_keyed}} -->
The `fd_blake3_hasher_init_keyed` function initializes a BLAKE3 hasher with a specific key for keyed hashing.
- **Inputs**:
    - `self`: A pointer to a `blake3_hasher` structure that will be initialized.
    - `key`: A constant array of 32 bytes (`uint8_t`) representing the key used for keyed hashing.
- **Control Flow**:
    - Declare a local array `key_words` of 8 `uint32_t` elements.
    - Call [`load_key_words`](blake3_impl.h.driver.md#load_key_words) to convert the byte array `key` into `key_words`.
    - Call [`hasher_init_base`](#hasher_init_base) with `self`, `key_words`, and `KEYED_HASH` to initialize the hasher with the provided key.
- **Output**: This function does not return a value; it initializes the `blake3_hasher` structure pointed to by `self`.
- **Functions called**:
    - [`load_key_words`](blake3_impl.h.driver.md#load_key_words)
    - [`hasher_init_base`](#hasher_init_base)


---
### fd\_blake3\_hasher\_init\_derive\_key\_raw<!-- {{#callable:fd_blake3_hasher_init_derive_key_raw}} -->
The `fd_blake3_hasher_init_derive_key_raw` function initializes a BLAKE3 hasher for deriving a key from a given context.
- **Inputs**:
    - `self`: A pointer to a `blake3_hasher` structure that will be initialized for key derivation.
    - `context`: A pointer to the context data from which the key will be derived.
    - `context_len`: The length of the context data in bytes.
- **Control Flow**:
    - Initialize a temporary `blake3_hasher` called `context_hasher` with a base state using the `IV` and `DERIVE_KEY_CONTEXT` flags.
    - Update the `context_hasher` with the provided context data using [`fd_blake3_hasher_update`](#fd_blake3_hasher_update).
    - Finalize the `context_hasher` to produce a context key, storing it in a `context_key` array.
    - Convert the `context_key` from bytes to words using [`load_key_words`](blake3_impl.h.driver.md#load_key_words), storing the result in `context_key_words`.
    - Initialize the provided `self` hasher with the derived `context_key_words` and `DERIVE_KEY_MATERIAL` flags using [`hasher_init_base`](#hasher_init_base).
- **Output**: The function does not return a value; it initializes the `self` hasher for key derivation based on the provided context.
- **Functions called**:
    - [`hasher_init_base`](#hasher_init_base)
    - [`fd_blake3_hasher_update`](#fd_blake3_hasher_update)
    - [`fd_blake3_hasher_finalize`](#fd_blake3_hasher_finalize)
    - [`load_key_words`](blake3_impl.h.driver.md#load_key_words)


---
### fd\_blake3\_hasher\_init\_derive\_key<!-- {{#callable:fd_blake3_hasher_init_derive_key}} -->
The `fd_blake3_hasher_init_derive_key` function initializes a BLAKE3 hasher for key derivation using a given context string.
- **Inputs**:
    - `self`: A pointer to a `blake3_hasher` structure that will be initialized.
    - `context`: A constant character pointer to the context string used for key derivation.
- **Control Flow**:
    - The function calls [`fd_blake3_hasher_init_derive_key_raw`](#fd_blake3_hasher_init_derive_key_raw), passing the `self` pointer, the `context` string, and the length of the `context` string obtained using `strlen`.
- **Output**: This function does not return a value; it initializes the `blake3_hasher` structure pointed to by `self` for key derivation.
- **Functions called**:
    - [`fd_blake3_hasher_init_derive_key_raw`](#fd_blake3_hasher_init_derive_key_raw)


---
### hasher\_merge\_cv\_stack<!-- {{#callable:hasher_merge_cv_stack}} -->
The `hasher_merge_cv_stack` function reduces the length of the chaining value stack in a BLAKE3 hasher by merging parent nodes until the stack length matches the number of 1-bits in the total length of input processed.
- **Inputs**:
    - `self`: A pointer to a `blake3_hasher` structure, which contains the state of the BLAKE3 hash computation, including the chaining value stack.
    - `total_len`: A `uint64_t` representing the total length of the input data processed so far, used to determine the target length of the chaining value stack after merging.
- **Control Flow**:
    - Calculate `post_merge_stack_len` as the number of 1-bits in `total_len` using the [`popcnt`](blake3_impl.h.driver.md#popcnt) function.
    - Enter a loop that continues as long as the current length of the chaining value stack (`self->cv_stack_len`) is greater than `post_merge_stack_len`.
    - Within the loop, identify the parent node in the chaining value stack that needs to be merged.
    - Create an `output_t` structure by calling [`parent_output`](#parent_output) with the parent node, the hasher's key, and the current chunk flags.
    - Update the parent node in the chaining value stack with the new chaining value by calling [`output_chaining_value`](#output_chaining_value).
    - Reduce the length of the chaining value stack by one.
- **Output**: The function does not return a value; it modifies the `cv_stack` and `cv_stack_len` fields of the `blake3_hasher` structure in place.
- **Functions called**:
    - [`popcnt`](blake3_impl.h.driver.md#popcnt)
    - [`parent_output`](#parent_output)
    - [`output_chaining_value`](#output_chaining_value)


---
### hasher\_push\_cv<!-- {{#callable:hasher_push_cv}} -->
The `hasher_push_cv` function adds a new chaining value to the BLAKE3 hasher's stack, ensuring the stack is merged appropriately before the addition.
- **Inputs**:
    - `self`: A pointer to a `blake3_hasher` structure, representing the current state of the BLAKE3 hasher.
    - `new_cv`: An array of bytes representing the new chaining value to be added to the hasher's stack.
    - `chunk_counter`: A 64-bit unsigned integer representing the current chunk counter, used to determine the merging of the stack.
- **Control Flow**:
    - Call [`hasher_merge_cv_stack`](#hasher_merge_cv_stack) with `self` and `chunk_counter` to merge the stack as needed before adding the new chaining value.
    - Copy the `new_cv` into the `cv_stack` at the position determined by `cv_stack_len`.
    - Increment the `cv_stack_len` to reflect the addition of the new chaining value.
- **Output**: This function does not return a value; it modifies the state of the `blake3_hasher` structure by adding a new chaining value to its stack.
- **Functions called**:
    - [`hasher_merge_cv_stack`](#hasher_merge_cv_stack)


---
### fd\_blake3\_hasher\_update<!-- {{#callable:fd_blake3_hasher_update}} -->
The `fd_blake3_hasher_update` function processes input data to update the state of a BLAKE3 hasher, handling chunking and subtree compression for efficient hashing.
- **Inputs**:
    - `self`: A pointer to a `blake3_hasher` structure representing the current state of the hasher.
    - `input`: A pointer to the input data to be hashed.
    - `input_len`: The length of the input data in bytes.
- **Control Flow**:
    - Check if `input_len` is zero and return immediately if true to avoid undefined behavior with null pointers.
    - Convert `input` to a `uint8_t` pointer `input_bytes` for byte-wise operations.
    - If there are partial chunk bytes in `self->chunk`, complete the current chunk by updating it with as much of `input_bytes` as needed, then finalize and reset the chunk if more input remains.
    - Enter a loop to process input in chunks, aiming to hash the largest power-of-2 subtree possible, using SIMD parallelism for efficiency.
    - Within the loop, adjust `subtree_len` to ensure it evenly divides the total number of chunks processed so far, then either hash a single chunk or compress a subtree into chaining values (CVs).
    - Update the chunk counter and adjust `input_bytes` and `input_len` accordingly after processing each subtree.
    - If any input remains that is less than a full chunk, update the chunk state with it and ensure the CV stack is merged appropriately.
- **Output**: The function does not return a value; it updates the state of the `blake3_hasher` structure to reflect the processed input data.
- **Functions called**:
    - [`chunk_state_len`](#chunk_state_len)
    - [`chunk_state_update`](#chunk_state_update)
    - [`chunk_state_output`](#chunk_state_output)
    - [`output_chaining_value`](#output_chaining_value)
    - [`hasher_push_cv`](#hasher_push_cv)
    - [`chunk_state_reset`](#chunk_state_reset)
    - [`round_down_to_power_of_2`](blake3_impl.h.driver.md#round_down_to_power_of_2)
    - [`chunk_state_init`](#chunk_state_init)
    - [`compress_subtree_to_parent_node`](#compress_subtree_to_parent_node)
    - [`hasher_merge_cv_stack`](#hasher_merge_cv_stack)


---
### fd\_blake3\_hasher\_finalize<!-- {{#callable:fd_blake3_hasher_finalize}} -->
The `fd_blake3_hasher_finalize` function finalizes the BLAKE3 hash computation and writes the hash output to a specified buffer.
- **Inputs**:
    - `self`: A pointer to a `blake3_hasher` structure representing the current state of the hash computation.
    - `out`: A pointer to a buffer where the final hash output will be written.
    - `out_len`: The length of the output buffer, specifying how many bytes of the hash output to write.
- **Control Flow**:
    - The function calls [`fd_blake3_hasher_finalize_seek`](#fd_blake3_hasher_finalize_seek) with the `seek` parameter set to 0, passing along the `self`, `out`, and `out_len` parameters.
    - The [`fd_blake3_hasher_finalize_seek`](#fd_blake3_hasher_finalize_seek) function handles the actual finalization process, including any necessary merging of hash states and writing the final hash output to the buffer.
- **Output**: The function does not return a value; it writes the final hash output to the provided buffer.
- **Functions called**:
    - [`fd_blake3_hasher_finalize_seek`](#fd_blake3_hasher_finalize_seek)


---
### fd\_blake3\_hasher\_finalize\_seek<!-- {{#callable:fd_blake3_hasher_finalize_seek}} -->
The `fd_blake3_hasher_finalize_seek` function finalizes the BLAKE3 hash computation for a given hasher state, allowing for a specified output seek position and length.
- **Inputs**:
    - `self`: A pointer to a `blake3_hasher` structure representing the current state of the hash computation.
    - `seek`: A `uint64_t` value indicating the position in the output stream from which to start writing the hash output.
    - `out`: A pointer to a `uint8_t` array where the hash output will be written.
    - `out_len`: A `size_t` value specifying the number of bytes to write to the `out` array.
- **Control Flow**:
    - Check if `out_len` is zero and return immediately if true, avoiding undefined behavior from null pointer operations.
    - Determine if the `cv_stack` is empty; if so, treat the current chunk as the root and output the root bytes directly.
    - If the chunk state has bytes, finalize the chunk and perform a roll-up merge with the subtree stack, ensuring no subtrees need merging with each other first.
    - If the chunk state is empty, start the merge from the top of the stack, which is a chunk hash.
    - Iterate over the remaining chaining values (CVs) in the stack, performing parent node compression and updating the output.
    - Output the final root bytes using the computed output state, seek position, and specified output length.
- **Output**: The function writes the finalized hash output to the `out` array, starting at the specified seek position and for the specified length.
- **Functions called**:
    - [`chunk_state_output`](#chunk_state_output)
    - [`output_root_bytes`](#output_root_bytes)
    - [`chunk_state_len`](#chunk_state_len)
    - [`parent_output`](#parent_output)
    - [`output_chaining_value`](#output_chaining_value)


---
### fd\_blake3\_hasher\_reset<!-- {{#callable:fd_blake3_hasher_reset}} -->
The `fd_blake3_hasher_reset` function resets a BLAKE3 hasher to its initial state, ready for a new hashing operation.
- **Inputs**:
    - `self`: A pointer to a `blake3_hasher` structure that represents the hasher to be reset.
- **Control Flow**:
    - Call [`chunk_state_reset`](#chunk_state_reset) on the `chunk` member of the `blake3_hasher` structure, passing the hasher's key and a chunk counter of 0.
    - Set the `cv_stack_len` member of the `blake3_hasher` structure to 0.
- **Output**: This function does not return a value; it modifies the state of the `blake3_hasher` structure pointed to by `self`.
- **Functions called**:
    - [`chunk_state_reset`](#chunk_state_reset)



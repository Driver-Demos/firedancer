# Purpose
This C source code file is part of the BLAKE3 cryptographic hash function implementation. It provides core functionality for the compression and hashing processes that are central to the BLAKE3 algorithm. The file includes several key functions, such as [`fd_blake3_compress_in_place_portable`](#fd_blake3_compress_in_place_portable) and [`fd_blake3_compress_xof_portable`](#fd_blake3_compress_xof_portable), which perform the compression operations on input data blocks. These functions utilize a series of transformations and bitwise operations to mix the input data and produce a compressed output, which is a fundamental step in generating the final hash value. The code also includes utility functions like [`rotr32`](#rotr32) for bit rotation and [`g`](#g) for mixing state variables, which are integral to the BLAKE3's cryptographic operations.

The file is designed to be part of a larger library, as indicated by its inclusion of a header file (`blake3_impl.h`) and its use of constants and macros like `BLAKE3_BLOCK_LEN` and `BLAKE3_OUT_LEN`. It defines internal functions that are likely intended for use within the BLAKE3 library rather than as a public API. The functions are marked as `INLINE`, suggesting an emphasis on performance optimization by allowing the compiler to embed these functions directly into the calling code. The file's purpose is to provide a portable implementation of the BLAKE3 compression and hashing routines, ensuring compatibility across different platforms and architectures.
# Imports and Dependencies

---
- `blake3_impl.h`
- `string.h`


# Functions

---
### rotr32<!-- {{#callable:rotr32}} -->
The `rotr32` function performs a bitwise right rotation on a 32-bit unsigned integer by a specified number of bits.
- **Inputs**:
    - `w`: A 32-bit unsigned integer to be rotated.
    - `c`: The number of bit positions to rotate the integer `w` to the right.
- **Control Flow**:
    - The function shifts the bits of `w` to the right by `c` positions using the right shift operator `>>`.
    - It then shifts the bits of `w` to the left by `(32 - c)` positions using the left shift operator `<<`.
    - The results of the two shifts are combined using the bitwise OR operator `|` to complete the rotation.
- **Output**: The function returns a 32-bit unsigned integer that is the result of rotating `w` to the right by `c` positions.


---
### g<!-- {{#callable:g}} -->
The function `g` performs a series of operations on a state array using specified indices and additional input values, involving addition and bitwise rotation.
- **Inputs**:
    - `state`: A pointer to an array of uint32_t values representing the state to be modified.
    - `a`: An index into the state array indicating the position to be modified.
    - `b`: An index into the state array indicating the position to be used in calculations.
    - `c`: An index into the state array indicating the position to be modified.
    - `d`: An index into the state array indicating the position to be modified.
    - `x`: A uint32_t value to be added to the state at index `a`.
    - `y`: A uint32_t value to be added to the state at index `a` in a subsequent operation.
- **Control Flow**:
    - Add the value at state[b] and x to state[a].
    - Perform a bitwise XOR between state[d] and state[a], then rotate the result right by 16 bits and store it back in state[d].
    - Add the value at state[d] to state[c].
    - Perform a bitwise XOR between state[b] and state[c], then rotate the result right by 12 bits and store it back in state[b].
    - Add the value at state[b] and y to state[a].
    - Perform a bitwise XOR between state[d] and state[a], then rotate the result right by 8 bits and store it back in state[d].
    - Add the value at state[d] to state[c].
    - Perform a bitwise XOR between state[b] and state[c], then rotate the result right by 7 bits and store it back in state[b].
- **Output**: The function modifies the state array in place, with no return value.
- **Functions called**:
    - [`rotr32`](#rotr32)


---
### round\_fn<!-- {{#callable:round_fn}} -->
The `round_fn` function performs a single round of the BLAKE3 cryptographic hash function's compression operation by mixing columns and rows of the state array using a message schedule.
- **Inputs**:
    - `state`: A 16-element array of uint32_t representing the current state of the hash function.
    - `msg`: A pointer to an array of uint32_t representing the message block to be processed.
    - `round`: A size_t value indicating the current round number, used to select the appropriate message schedule.
- **Control Flow**:
    - Retrieve the message schedule for the current round from the MSG_SCHEDULE array.
    - Perform column mixing by calling the [`g`](#g) function four times with different indices and message schedule values.
    - Perform row mixing by calling the [`g`](#g) function four more times with different indices and message schedule values.
- **Output**: The function modifies the `state` array in place, updating it with the results of the column and row mixing operations.
- **Functions called**:
    - [`g`](#g)


---
### compress\_pre<!-- {{#callable:compress_pre}} -->
The `compress_pre` function initializes a state array for the BLAKE3 hash function by loading block data and chaining values, then performs a series of compression rounds.
- **Inputs**:
    - `state`: An array of 16 uint32_t elements that will be initialized and modified to represent the internal state of the hash function.
    - `cv`: An array of 8 uint32_t elements representing the chaining value from the previous hash state.
    - `block`: An array of bytes with length BLAKE3_BLOCK_LEN, representing the input data block to be processed.
    - `block_len`: A uint8_t value representing the length of the block.
    - `counter`: A uint64_t value used to keep track of the number of blocks processed, affecting the hash output.
    - `flags`: A uint8_t value representing various flags that modify the behavior of the hash function.
- **Control Flow**:
    - Load 16 32-bit words from the input block into the `block_words` array using the [`load32`](blake3_impl.h.driver.md#load32) function.
    - Initialize the first 8 elements of the `state` array with the chaining values from `cv`.
    - Set the next 4 elements of the `state` array with predefined initialization vector values `IV`.
    - Set the 12th and 13th elements of the `state` array with the lower and higher parts of the `counter`, respectively.
    - Set the 14th element of the `state` array with the `block_len` and the 15th element with the `flags`.
    - Perform 7 rounds of the compression function by calling [`round_fn`](#round_fn) with the `state` and `block_words` arrays.
- **Output**: The function modifies the `state` array in place, which is used in subsequent hash computations.
- **Functions called**:
    - [`load32`](blake3_impl.h.driver.md#load32)
    - [`counter_low`](blake3_impl.h.driver.md#counter_low)
    - [`counter_high`](blake3_impl.h.driver.md#counter_high)
    - [`round_fn`](#round_fn)


---
### fd\_blake3\_compress\_in\_place\_portable<!-- {{#callable:fd_blake3_compress_in_place_portable}} -->
The `fd_blake3_compress_in_place_portable` function performs an in-place compression of a BLAKE3 hash chain value using a given block, block length, counter, and flags.
- **Inputs**:
    - `cv`: An array of 8 uint32_t values representing the chaining value to be compressed.
    - `block`: A constant array of bytes with length BLAKE3_BLOCK_LEN, representing the input block to be compressed.
    - `block_len`: A uint8_t value representing the length of the block.
    - `counter`: A uint64_t value used as a counter in the compression process.
    - `flags`: A uint8_t value representing flags that modify the behavior of the compression.
- **Control Flow**:
    - Initialize a 16-element uint32_t array `state`.
    - Call [`compress_pre`](#compress_pre) to prepare the `state` array using the input parameters `cv`, `block`, `block_len`, `counter`, and `flags`.
    - Update each element of the `cv` array by XORing corresponding elements from the `state` array.
- **Output**: The function modifies the input `cv` array in place, updating it with the compressed chaining value.
- **Functions called**:
    - [`compress_pre`](#compress_pre)


---
### fd\_blake3\_compress\_xof\_portable<!-- {{#callable:fd_blake3_compress_xof_portable}} -->
The `fd_blake3_compress_xof_portable` function performs a BLAKE3 compression operation on a given input block and outputs a 64-byte result using a portable implementation.
- **Inputs**:
    - `cv`: A constant 8-element array of 32-bit unsigned integers representing the chaining value.
    - `block`: A constant array of bytes with length `BLAKE3_BLOCK_LEN` representing the input block to be compressed.
    - `block_len`: An 8-bit unsigned integer representing the length of the block.
    - `counter`: A 64-bit unsigned integer used as a counter in the compression process.
    - `flags`: An 8-bit unsigned integer representing flags that modify the compression behavior.
    - `out`: An array of 64 bytes where the output of the compression will be stored.
- **Control Flow**:
    - Initialize a 16-element array `state` of 32-bit unsigned integers.
    - Call [`compress_pre`](#compress_pre) to prepare the `state` array using the input parameters `cv`, `block`, `block_len`, `counter`, and `flags`.
    - Perform XOR operations between elements of `state` and `cv`, storing the results in the `out` array using [`store32`](blake3_impl.h.driver.md#store32).
    - The first 8 elements of `out` are computed by XORing corresponding elements of `state` and the next 8 elements of `state`.
    - The next 8 elements of `out` are computed by XORing the remaining elements of `state` with the elements of `cv`.
- **Output**: The function outputs a 64-byte array `out` containing the result of the BLAKE3 compression operation.
- **Functions called**:
    - [`compress_pre`](#compress_pre)
    - [`store32`](blake3_impl.h.driver.md#store32)


---
### hash\_one\_portable<!-- {{#callable:hash_one_portable}} -->
The `hash_one_portable` function processes a sequence of input blocks using the BLAKE3 hash function, updating a chaining value and storing the final hash output.
- **Inputs**:
    - `input`: A pointer to the input data to be hashed, represented as an array of bytes.
    - `blocks`: The number of blocks in the input data to be processed.
    - `key`: An array of 8 uint32_t values representing the key used for hashing.
    - `counter`: A 64-bit counter value used in the hashing process.
    - `flags`: A set of flags that modify the behavior of the hash function.
    - `flags_start`: Flags to be applied at the start of the hashing process.
    - `flags_end`: Flags to be applied at the end of the hashing process.
    - `out`: An array where the final hash output will be stored, with a length defined by BLAKE3_OUT_LEN.
- **Control Flow**:
    - Initialize the chaining value (cv) by copying the key into it.
    - Set the initial block flags by combining the provided flags with flags_start.
    - Enter a loop that continues while there are blocks to process.
    - If processing the last block, combine block_flags with flags_end.
    - Call [`fd_blake3_compress_in_place_portable`](#fd_blake3_compress_in_place_portable) to compress the current block and update the chaining value.
    - Advance the input pointer by the block length and decrement the block count.
    - Reset block_flags to the initial flags for the next iteration.
    - After processing all blocks, store the final chaining value into the output array.
- **Output**: The function outputs the final hash value into the provided `out` array, which is of length BLAKE3_OUT_LEN.
- **Functions called**:
    - [`fd_blake3_compress_in_place_portable`](#fd_blake3_compress_in_place_portable)
    - [`store_cv_words`](blake3_impl.h.driver.md#store_cv_words)


---
### fd\_blake3\_hash\_many\_portable<!-- {{#callable:fd_blake3_hash_many_portable}} -->
The `fd_blake3_hash_many_portable` function hashes multiple input data blocks using the BLAKE3 hash function in a portable manner.
- **Inputs**:
    - `inputs`: A pointer to an array of pointers, each pointing to a block of input data to be hashed.
    - `num_inputs`: The number of input data blocks to be hashed.
    - `blocks`: The number of blocks in each input data to be processed.
    - `key`: A 256-bit key (array of 8 uint32_t) used for the BLAKE3 hash function.
    - `counter`: A 64-bit counter value used in the hashing process.
    - `increment_counter`: A boolean flag indicating whether the counter should be incremented after processing each input.
    - `flags`: Flags used to control the hashing process.
    - `flags_start`: Flags to be applied at the start of the hashing process for each input.
    - `flags_end`: Flags to be applied at the end of the hashing process for each input.
    - `out`: A pointer to the output buffer where the hash results will be stored.
- **Control Flow**:
    - The function enters a loop that continues until all input data blocks have been processed (i.e., `num_inputs` is greater than 0).
    - Within the loop, it calls [`hash_one_portable`](#hash_one_portable) to hash the current input data block using the provided parameters.
    - If `increment_counter` is true, the counter is incremented by 1 after hashing each input block.
    - The input pointer is advanced to the next input block, and `num_inputs` is decremented by 1.
    - The output pointer is advanced by `BLAKE3_OUT_LEN` to store the next hash result.
- **Output**: The function does not return a value; it writes the hash results to the output buffer pointed to by `out`.
- **Functions called**:
    - [`hash_one_portable`](#hash_one_portable)



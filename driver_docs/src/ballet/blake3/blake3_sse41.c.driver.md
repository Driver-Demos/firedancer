# Purpose
This C source code file is part of the BLAKE3 cryptographic hash function implementation, specifically optimized for SSE4.1 instruction set extensions. The file provides functions to perform the BLAKE3 compression and hashing operations using SIMD (Single Instruction, Multiple Data) instructions to enhance performance on compatible hardware. The code includes several inline functions that define low-level operations such as loading, storing, adding, and XORing 128-bit vectors, as well as rotating bits within these vectors. These operations are fundamental to the BLAKE3 algorithm's compression function, which is executed in multiple rounds to mix the input data thoroughly.

The file defines several key functions, including [`fd_blake3_compress_in_place_sse41`](#fd_blake3_compress_in_place_sse41), [`fd_blake3_compress_xof_sse41`](#fd_blake3_compress_xof_sse41), and [`fd_blake3_hash_many_sse41`](#fd_blake3_hash_many_sse41), which handle the core compression and hashing tasks. The [`fd_blake3_compress_in_place_sse41`](#fd_blake3_compress_in_place_sse41) function updates a chaining value in place, while [`fd_blake3_compress_xof_sse41`](#fd_blake3_compress_xof_sse41) produces an extended output format. The [`fd_blake3_hash_many_sse41`](#fd_blake3_hash_many_sse41) function processes multiple inputs in parallel, leveraging the SSE4.1 optimizations to compute hashes efficiently. The code is structured to handle both single and multiple input blocks, with functions like [`fd_blake3_hash4_sse41`](#fd_blake3_hash4_sse41) and [`hash_one_sse41`](#hash_one_sse41) providing the necessary logic to manage different input sizes and configurations. Overall, this file is a specialized component of the BLAKE3 library, focusing on performance optimization through SIMD instructions for cryptographic hashing.
# Imports and Dependencies

---
- `blake3_impl.h`
- `immintrin.h`


# Functions

---
### loadu<!-- {{#callable:loadu}} -->
The `loadu` function loads 16 bytes of data from an unaligned memory address into a 128-bit SIMD register.
- **Inputs**:
    - `src`: A pointer to an array of 16 bytes (uint8_t) that represents the source data to be loaded into the SIMD register.
- **Control Flow**:
    - The function casts the input pointer `src` to a pointer of type `const __m128i *`, which is suitable for loading into a 128-bit SIMD register.
    - It then uses the `_mm_loadu_si128` intrinsic to load the 16 bytes from the unaligned memory address into a 128-bit SIMD register.
- **Output**: The function returns a 128-bit SIMD register (`__m128i`) containing the loaded data.


---
### storeu<!-- {{#callable:storeu}} -->
The `storeu` function stores a 128-bit integer from an `__m128i` source into a 16-byte destination array without alignment requirements.
- **Inputs**:
    - `src`: A 128-bit integer of type `__m128i` that is to be stored.
    - `dest`: A pointer to a 16-byte array of type `uint8_t` where the 128-bit integer will be stored.
- **Control Flow**:
    - The function uses the intrinsic `_mm_storeu_si128` to store the 128-bit integer from `src` into the memory location pointed to by `dest`.
- **Output**: The function does not return a value; it performs an in-place operation on the `dest` array.


---
### addv<!-- {{#callable:addv}} -->
The `addv` function performs a SIMD addition of two 128-bit integer vectors using the `_mm_add_epi32` intrinsic.
- **Inputs**:
    - `a`: A 128-bit integer vector of type `__m128i`.
    - `b`: A 128-bit integer vector of type `__m128i`.
- **Control Flow**:
    - The function takes two 128-bit integer vectors as input.
    - It uses the `_mm_add_epi32` intrinsic to add the corresponding 32-bit integers in the vectors `a` and `b`.
    - The result of the addition is returned as a new 128-bit integer vector.
- **Output**: A 128-bit integer vector of type `__m128i` containing the element-wise sum of the input vectors.


---
### xorv<!-- {{#callable:xorv}} -->
The `xorv` function performs a bitwise XOR operation on two 128-bit integer vectors using SSE2 intrinsics.
- **Inputs**:
    - `a`: A 128-bit integer vector of type `__m128i`.
    - `b`: A 128-bit integer vector of type `__m128i`.
- **Control Flow**:
    - The function takes two 128-bit integer vectors as input.
    - It applies the `_mm_xor_si128` intrinsic to perform a bitwise XOR operation on the two input vectors.
    - The result of the XOR operation is returned.
- **Output**: A 128-bit integer vector of type `__m128i` that is the result of the bitwise XOR operation on the input vectors.


---
### set1<!-- {{#callable:set1}} -->
The `set1` function initializes a 128-bit SIMD register with four copies of a given 32-bit integer.
- **Inputs**:
    - `x`: A 32-bit unsigned integer to be replicated across all four 32-bit lanes of the SIMD register.
- **Control Flow**:
    - The function takes a 32-bit unsigned integer `x` as input.
    - It casts `x` to a 32-bit signed integer.
    - It calls the intrinsic `_mm_set1_epi32` to set all four 32-bit lanes of a 128-bit SIMD register to the value of `x`.
- **Output**: A 128-bit SIMD register (`__m128i`) with all four 32-bit lanes set to the input integer `x`.


---
### set4<!-- {{#callable:set4}} -->
The `set4` function initializes a 128-bit SIMD vector with four 32-bit integer values in a specified order.
- **Inputs**:
    - `a`: The first 32-bit unsigned integer to be set in the SIMD vector.
    - `b`: The second 32-bit unsigned integer to be set in the SIMD vector.
    - `c`: The third 32-bit unsigned integer to be set in the SIMD vector.
    - `d`: The fourth 32-bit unsigned integer to be set in the SIMD vector.
- **Control Flow**:
    - The function takes four 32-bit unsigned integers as input parameters.
    - Each input integer is cast to a 32-bit signed integer.
    - The function calls the intrinsic `_mm_setr_epi32` to create a 128-bit SIMD vector with the input integers in the order they are provided.
- **Output**: A 128-bit SIMD vector (`__m128i`) containing the four input integers in the specified order.


---
### rot16<!-- {{#callable:rot16}} -->
The `rot16` function performs a byte-wise rotation of a 128-bit integer using a specific shuffle pattern.
- **Inputs**:
    - `x`: A 128-bit integer of type `__m128i` that is to be rotated.
- **Control Flow**:
    - The function uses the `_mm_shuffle_epi8` intrinsic to shuffle the bytes of the input `x`.
    - A specific shuffle pattern is applied using `_mm_set_epi8` to rearrange the bytes, effectively rotating the 128-bit integer.
- **Output**: The function returns a 128-bit integer of type `__m128i` with its bytes rearranged according to the specified shuffle pattern.


---
### rot12<!-- {{#callable:rot12}} -->
The `rot12` function performs a 12-bit rotation on each 32-bit integer within a 128-bit SIMD vector using bitwise operations.
- **Inputs**:
    - `x`: A 128-bit SIMD vector (__m128i) containing four 32-bit integers to be rotated.
- **Control Flow**:
    - The function shifts each 32-bit integer in the input vector `x` to the right by 12 bits using `_mm_srli_epi32`.
    - It shifts each 32-bit integer in the input vector `x` to the left by 20 bits (32 - 12) using `_mm_slli_epi32`.
    - The results of the two shifts are combined using a bitwise XOR operation via the [`xorv`](#xorv) function.
- **Output**: A 128-bit SIMD vector (__m128i) where each 32-bit integer has been rotated 12 bits to the right.
- **Functions called**:
    - [`xorv`](#xorv)


---
### rot8<!-- {{#callable:rot8}} -->
The `rot8` function performs an 8-byte rotation on a 128-bit integer using the `_mm_shuffle_epi8` intrinsic.
- **Inputs**:
    - `x`: A 128-bit integer of type `__m128i` that represents the input vector to be rotated.
- **Control Flow**:
    - The function takes a 128-bit integer `x` as input.
    - It uses the `_mm_shuffle_epi8` intrinsic to rearrange the bytes of `x` according to a specified pattern.
    - The pattern is defined by the `_mm_set_epi8` intrinsic, which specifies the new order of bytes after the rotation.
- **Output**: A 128-bit integer of type `__m128i` that is the result of rotating the input vector `x` by 8 bytes.


---
### rot7<!-- {{#callable:rot7}} -->
The `rot7` function performs a bitwise rotation of each 32-bit integer in a 128-bit SIMD vector by 7 bits to the right.
- **Inputs**:
    - `x`: A 128-bit SIMD vector (__m128i) containing four 32-bit integers to be rotated.
- **Control Flow**:
    - The function shifts each 32-bit integer in the input vector `x` to the right by 7 bits using `_mm_srli_epi32`.
    - It shifts each 32-bit integer in the input vector `x` to the left by 25 bits (32 - 7) using `_mm_slli_epi32`.
    - The results of the two shifts are combined using a bitwise XOR operation via the [`xorv`](#xorv) function.
- **Output**: A 128-bit SIMD vector (__m128i) where each 32-bit integer has been rotated 7 bits to the right.
- **Functions called**:
    - [`xorv`](#xorv)


---
### g1<!-- {{#callable:g1}} -->
The `g1` function performs a series of SIMD operations on four 128-bit integer vectors, modifying them in place using addition, XOR, and rotation operations.
- **Inputs**:
    - `row0`: A pointer to a 128-bit integer vector (__m128i) that will be modified in place.
    - `row1`: A pointer to a 128-bit integer vector (__m128i) that will be modified in place.
    - `row2`: A pointer to a 128-bit integer vector (__m128i) that will be modified in place.
    - `row3`: A pointer to a 128-bit integer vector (__m128i) that will be modified in place.
    - `m`: A 128-bit integer vector (__m128i) used as an operand in the addition operation.
- **Control Flow**:
    - Add the vector `m` to `*row0` and then add `*row1` to the result, storing the result back in `*row0`.
    - XOR the updated `*row0` with `*row3` and store the result in `*row3`.
    - Rotate the bits in `*row3` by 16 positions to the left.
    - Add the updated `*row3` to `*row2` and store the result in `*row2`.
    - XOR the updated `*row2` with `*row1` and store the result in `*row1`.
    - Rotate the bits in `*row1` by 12 positions to the left.
- **Output**: The function modifies the input vectors `row0`, `row1`, `row2`, and `row3` in place, with no return value.
- **Functions called**:
    - [`addv`](#addv)
    - [`xorv`](#xorv)
    - [`rot16`](#rot16)
    - [`rot12`](#rot12)


---
### g2<!-- {{#callable:g2}} -->
The `g2` function performs a series of SIMD operations on four 128-bit integer vectors, modifying them through addition, XOR, and rotation operations using a given modifier vector.
- **Inputs**:
    - `row0`: A pointer to a 128-bit integer vector (__m128i) representing the first row to be modified.
    - `row1`: A pointer to a 128-bit integer vector (__m128i) representing the second row to be modified.
    - `row2`: A pointer to a 128-bit integer vector (__m128i) representing the third row to be modified.
    - `row3`: A pointer to a 128-bit integer vector (__m128i) representing the fourth row to be modified.
    - `m`: A 128-bit integer vector (__m128i) used as a modifier in the operations.
- **Control Flow**:
    - Add the modifier vector `m` to `row0` and then add `row1` to the result, storing the result back in `row0`.
    - XOR the modified `row0` with `row3` and store the result in `row3`.
    - Rotate the bits of `row3` by 8 positions to the left.
    - Add the modified `row3` to `row2` and store the result in `row2`.
    - XOR the modified `row2` with `row1` and store the result in `row1`.
    - Rotate the bits of `row1` by 7 positions to the left.
- **Output**: The function modifies the input vectors `row0`, `row1`, `row2`, and `row3` in place, with no return value.
- **Functions called**:
    - [`addv`](#addv)
    - [`xorv`](#xorv)
    - [`rot8`](#rot8)
    - [`rot7`](#rot7)


---
### diagonalize<!-- {{#callable:diagonalize}} -->
The `diagonalize` function rearranges the elements of three 128-bit integer vectors to facilitate parallel processing in cryptographic operations.
- **Inputs**:
    - `row0`: A pointer to a 128-bit integer vector (__m128i) representing the first row to be shuffled.
    - `row2`: A pointer to a 128-bit integer vector (__m128i) representing the second row to be shuffled.
    - `row3`: A pointer to a 128-bit integer vector (__m128i) representing the third row to be shuffled.
- **Control Flow**:
    - The function uses the `_mm_shuffle_epi32` intrinsic to rearrange the 32-bit elements within each of the input vectors.
    - For `row0`, the elements are rearranged in the order of indices 2, 1, 0, 3.
    - For `row3`, the elements are rearranged in the order of indices 1, 0, 3, 2.
    - For `row2`, the elements are rearranged in the order of indices 0, 3, 2, 1.
- **Output**: The function modifies the input vectors in place, returning no explicit output.


---
### undiagonalize<!-- {{#callable:undiagonalize}} -->
The `undiagonalize` function reorders the elements of three 128-bit integer vectors to reverse a previous diagonalization operation.
- **Inputs**:
    - `row0`: A pointer to a 128-bit integer vector (__m128i) representing the first row to be undiagonalized.
    - `row2`: A pointer to a 128-bit integer vector (__m128i) representing the second row to be undiagonalized.
    - `row3`: A pointer to a 128-bit integer vector (__m128i) representing the third row to be undiagonalized.
- **Control Flow**:
    - The function takes three pointers to __m128i variables, representing rows of data.
    - It applies the `_mm_shuffle_epi32` intrinsic to each row with specific shuffle masks to reorder the elements.
    - For `row0`, the elements are shuffled with the mask `_MM_SHUFFLE(0, 3, 2, 1)`, effectively rotating the elements to the right.
    - For `row3`, the elements are shuffled with the mask `_MM_SHUFFLE(1, 0, 3, 2)`, swapping the first two elements with the last two.
    - For `row2`, the elements are shuffled with the mask `_MM_SHUFFLE(2, 1, 0, 3)`, rotating the elements to the left.
- **Output**: The function modifies the input vectors in place, returning no explicit output.


---
### compress\_pre<!-- {{#callable:compress_pre}} -->
The `compress_pre` function initializes and processes a set of SIMD registers for the BLAKE3 hash function using a series of rounds with specific permutations and transformations.
- **Inputs**:
    - `rows`: An array of four __m128i registers that will be initialized and modified by the function.
    - `cv`: A constant array of eight 32-bit unsigned integers representing the chaining value.
    - `block`: A constant array of bytes representing the input block to be processed, with a length defined by BLAKE3_BLOCK_LEN.
    - `block_len`: An 8-bit unsigned integer representing the length of the block.
    - `counter`: A 64-bit unsigned integer used as a counter in the hash function.
    - `flags`: An 8-bit unsigned integer representing flags that modify the behavior of the hash function.
- **Control Flow**:
    - Initialize the `rows` array with values derived from the chaining value, initialization vector, counter, block length, and flags.
    - Load four 128-bit message words from the input block into `m0`, `m1`, `m2`, and `m3`.
    - Perform seven rounds of transformations, each consisting of permutations and mixing operations using the [`g1`](#g1) and [`g2`](#g2) functions.
    - In each round, shuffle and blend the message words, apply the [`g1`](#g1) and [`g2`](#g2) functions to the `rows`, and perform diagonalization and undiagonalization operations.
    - Update the message words `m0`, `m1`, `m2`, and `m3` with the results of the transformations for the next round.
- **Output**: The function modifies the `rows` array in place, which is used in subsequent hash computations.
- **Functions called**:
    - [`loadu`](#loadu)
    - [`set4`](#set4)
    - [`counter_low`](blake3_impl.h.driver.md#counter_low)
    - [`counter_high`](blake3_impl.h.driver.md#counter_high)
    - [`g1`](#g1)
    - [`g2`](#g2)
    - [`diagonalize`](#diagonalize)
    - [`undiagonalize`](#undiagonalize)


---
### fd\_blake3\_compress\_in\_place\_sse41<!-- {{#callable:fd_blake3_compress_in_place_sse41}} -->
The `fd_blake3_compress_in_place_sse41` function performs an in-place compression of a BLAKE3 hash state using SSE4.1 instructions.
- **Inputs**:
    - `cv`: A pointer to an array of 8 uint32_t values representing the chaining value to be compressed.
    - `block`: A pointer to an array of bytes representing the input block to be compressed, with a length defined by BLAKE3_BLOCK_LEN.
    - `block_len`: A uint8_t value representing the length of the block.
    - `counter`: A uint64_t value representing the counter for the number of blocks processed.
    - `flags`: A uint8_t value representing the flags used to control the compression process.
- **Control Flow**:
    - Initialize an array of four __m128i vectors named 'rows'.
    - Call the 'compress_pre' function to prepare the 'rows' array using the input parameters.
    - Perform XOR operations on the 'rows' array to combine the results of the compression.
    - Store the results back into the 'cv' array using the 'storeu' function.
- **Output**: The function modifies the input chaining value 'cv' in place, updating it with the compressed result.
- **Functions called**:
    - [`compress_pre`](#compress_pre)
    - [`storeu`](#storeu)
    - [`xorv`](#xorv)


---
### fd\_blake3\_compress\_xof\_sse41<!-- {{#callable:fd_blake3_compress_xof_sse41}} -->
The `fd_blake3_compress_xof_sse41` function performs a BLAKE3 compression operation using SSE4.1 instructions and outputs a 64-byte result.
- **Inputs**:
    - `cv`: A constant 8-element array of 32-bit unsigned integers representing the chaining value.
    - `block`: A constant array of bytes with length `BLAKE3_BLOCK_LEN` representing the input block to be compressed.
    - `block_len`: An 8-bit unsigned integer representing the length of the block.
    - `counter`: A 64-bit unsigned integer used as a counter in the compression process.
    - `flags`: An 8-bit unsigned integer representing flags that modify the compression behavior.
    - `out`: An array of 64 bytes where the output of the compression will be stored.
- **Control Flow**:
    - Initialize a 4-element array of `__m128i` called `rows` to store intermediate values.
    - Call [`compress_pre`](#compress_pre) to prepare the `rows` array using the input parameters `cv`, `block`, `block_len`, `counter`, and `flags`.
    - Perform XOR operations between pairs of `rows` elements and store the results in the `out` array at specific offsets.
    - The first 16 bytes of `out` are filled with the XOR of `rows[0]` and `rows[2]`.
    - The next 16 bytes of `out` are filled with the XOR of `rows[1]` and `rows[3]`.
    - The third 16 bytes of `out` are filled with the XOR of `rows[2]` and the loaded first half of `cv`.
    - The last 16 bytes of `out` are filled with the XOR of `rows[3]` and the loaded second half of `cv`.
- **Output**: The function outputs a 64-byte array `out` containing the result of the BLAKE3 compression operation.
- **Functions called**:
    - [`compress_pre`](#compress_pre)
    - [`storeu`](#storeu)
    - [`xorv`](#xorv)
    - [`loadu`](#loadu)


---
### round\_fn<!-- {{#callable:round_fn}} -->
The `round_fn` function performs a series of vectorized operations on two arrays of 128-bit integers, `v` and `m`, using a predefined message schedule and a specified round index to update the state of `v`.
- **Inputs**:
    - `v`: An array of 16 __m128i vectors representing the current state of the hash function.
    - `m`: An array of 16 __m128i vectors representing the message block to be processed.
    - `r`: A size_t index representing the current round in the message schedule.
- **Control Flow**:
    - The function begins by adding elements from the message array `m` to the state array `v` using indices from the `MSG_SCHEDULE` for the current round `r`.
    - It then performs a series of additions between elements of `v` and other elements of `v`, effectively mixing the state.
    - The function applies XOR operations between certain elements of `v` and others, followed by bitwise rotations (rot16, rot12, rot8, rot7) to further mix the state.
    - This process is repeated for different sets of indices from the `MSG_SCHEDULE`, ensuring that all elements of `v` are involved in the mixing process.
    - The function completes by performing additional XOR and rotation operations to finalize the state for the current round.
- **Output**: The function does not return a value; it modifies the `v` array in place to reflect the updated state after the round operations.
- **Functions called**:
    - [`addv`](#addv)
    - [`xorv`](#xorv)
    - [`rot16`](#rot16)
    - [`rot12`](#rot12)
    - [`rot8`](#rot8)
    - [`rot7`](#rot7)


---
### transpose\_vecs<!-- {{#callable:transpose_vecs}} -->
The `transpose_vecs` function rearranges the elements of four 128-bit vectors to interleave their 32-bit and 64-bit lanes.
- **Inputs**:
    - `vecs`: An array of four 128-bit vectors (`__m128i`) that need to be transposed.
- **Control Flow**:
    - Unpack the lower 32-bit lanes of the first two vectors and store the result in `ab_01`.
    - Unpack the higher 32-bit lanes of the first two vectors and store the result in `ab_23`.
    - Unpack the lower 32-bit lanes of the last two vectors and store the result in `cd_01`.
    - Unpack the higher 32-bit lanes of the last two vectors and store the result in `cd_23`.
    - Interleave the 64-bit lanes of `ab_01` and `cd_01` to form `abcd_0`.
    - Interleave the 64-bit lanes of `ab_01` and `cd_01` to form `abcd_1`.
    - Interleave the 64-bit lanes of `ab_23` and `cd_23` to form `abcd_2`.
    - Interleave the 64-bit lanes of `ab_23` and `cd_23` to form `abcd_3`.
    - Assign the transposed vectors back to the original array `vecs`.
- **Output**: The function modifies the input array `vecs` in place, resulting in the transposed vectors.


---
### transpose\_msg\_vecs<!-- {{#callable:transpose_msg_vecs}} -->
The `transpose_msg_vecs` function loads and transposes message vectors from input data for cryptographic processing.
- **Inputs**:
    - `inputs`: A pointer to an array of pointers, each pointing to a block of input data of type `uint8_t`.
    - `block_offset`: The offset in bytes from the start of each input block to begin loading data.
    - `out`: An array of 16 `__m128i` vectors where the transposed data will be stored.
- **Control Flow**:
    - Load 16 `__m128i` vectors from the input data at specified block offsets into the `out` array.
    - Prefetch the next block of data for each input to optimize memory access.
    - Call [`transpose_vecs`](#transpose_vecs) on each set of 4 vectors in the `out` array to transpose them.
- **Output**: The function does not return a value; it modifies the `out` array in place to contain the transposed message vectors.
- **Functions called**:
    - [`loadu`](#loadu)
    - [`transpose_vecs`](#transpose_vecs)


---
### load\_counters<!-- {{#callable:load_counters}} -->
The `load_counters` function initializes two 128-bit SIMD registers with counter values, optionally incrementing them based on a boolean flag.
- **Inputs**:
    - `counter`: A 64-bit unsigned integer representing the initial counter value.
    - `increment_counter`: A boolean flag indicating whether to increment the counter values.
    - `out_lo`: A pointer to a 128-bit SIMD register where the lower part of the counter will be stored.
    - `out_hi`: A pointer to a 128-bit SIMD register where the higher part of the counter will be stored.
- **Control Flow**:
    - Create a mask using the `increment_counter` flag to determine if the counter should be incremented.
    - Set a 128-bit SIMD register `add0` with values {3, 2, 1, 0}.
    - Compute `add1` by performing a bitwise AND between `mask` and `add0`.
    - Calculate the lower part of the counter `l` by adding `add1` to the lower 32 bits of `counter`.
    - Determine if there is a carry by comparing `add1` and `l` using a bitwise XOR and a greater-than comparison.
    - Compute the higher part of the counter `h` by subtracting the carry from the higher 32 bits of `counter`.
    - Store the results in the provided `out_lo` and `out_hi` pointers.
- **Output**: The function outputs two 128-bit SIMD registers, `out_lo` and `out_hi`, containing the lower and higher parts of the counter, respectively.


---
### fd\_blake3\_hash4\_sse41<!-- {{#callable:fd_blake3_hash4_sse41}} -->
The `fd_blake3_hash4_sse41` function computes the BLAKE3 hash for four input blocks using SSE4.1 SIMD instructions.
- **Inputs**:
    - `inputs`: A pointer to an array of four pointers, each pointing to a block of input data to be hashed.
    - `blocks`: The number of blocks to process for each input.
    - `key`: An array of 8 uint32_t values representing the key used in the BLAKE3 hash function.
    - `counter`: A 64-bit counter value used in the hashing process.
    - `increment_counter`: A boolean flag indicating whether the counter should be incremented for each block.
    - `flags`: A uint8_t value representing flags used in the hashing process.
    - `flags_start`: A uint8_t value representing the start flags for the first block.
    - `flags_end`: A uint8_t value representing the end flags for the last block.
    - `out`: A pointer to an output buffer where the resulting hash will be stored.
- **Control Flow**:
    - Initialize eight 128-bit vectors `h_vecs` with the key values using [`set1`](#set1) function.
    - Load the counter values into `counter_low_vec` and `counter_high_vec` using [`load_counters`](#load_counters).
    - Set the initial `block_flags` by combining `flags` and `flags_start`.
    - Iterate over each block, updating `block_flags` with `flags_end` for the last block.
    - For each block, set up the message vectors using [`transpose_msg_vecs`](#transpose_msg_vecs) and initialize the state vector `v` with `h_vecs`, IV constants, counter vectors, block length, and block flags.
    - Perform seven rounds of the BLAKE3 compression function using [`round_fn`](#round_fn).
    - Update `h_vecs` by XORing the first eight elements of `v` with the last eight elements.
    - Reset `block_flags` to `flags` for the next iteration.
    - Transpose the `h_vecs` to prepare for output storage.
    - Store the transposed `h_vecs` into the output buffer `out` using [`storeu`](#storeu).
- **Output**: The function outputs the computed BLAKE3 hash for the four input blocks into the provided `out` buffer.
- **Functions called**:
    - [`set1`](#set1)
    - [`load_counters`](#load_counters)
    - [`transpose_msg_vecs`](#transpose_msg_vecs)
    - [`round_fn`](#round_fn)
    - [`xorv`](#xorv)
    - [`transpose_vecs`](#transpose_vecs)
    - [`storeu`](#storeu)


---
### hash\_one\_sse41<!-- {{#callable:hash_one_sse41}} -->
The `hash_one_sse41` function computes a BLAKE3 hash for a single input using SSE4.1 instructions.
- **Inputs**:
    - `input`: A pointer to the input data to be hashed.
    - `blocks`: The number of 64-byte blocks in the input data.
    - `key`: A 256-bit key used for the hash function, represented as an array of 8 uint32_t values.
    - `counter`: A 64-bit counter value used in the hash computation.
    - `flags`: Flags that modify the behavior of the hash function.
    - `flags_start`: Flags indicating the start of the input data.
    - `flags_end`: Flags indicating the end of the input data.
    - `out`: A pointer to an array where the resulting hash will be stored, with a length of BLAKE3_OUT_LEN bytes.
- **Control Flow**:
    - Initialize a 256-bit chaining value (cv) by copying the key into it.
    - Set the initial block flags by combining the provided flags with flags_start.
    - Enter a loop that processes each block of the input data.
    - If the current block is the last one, add flags_end to the block flags.
    - Call [`fd_blake3_compress_in_place_sse41`](#fd_blake3_compress_in_place_sse41) to compress the current block and update the chaining value.
    - Advance the input pointer by the block length and decrement the block count.
    - Reset the block flags to the initial flags for the next iteration.
    - After processing all blocks, copy the final chaining value into the output buffer.
- **Output**: The function outputs the computed BLAKE3 hash into the provided `out` buffer, which is BLAKE3_OUT_LEN bytes long.
- **Functions called**:
    - [`fd_blake3_compress_in_place_sse41`](#fd_blake3_compress_in_place_sse41)


---
### fd\_blake3\_hash\_many\_sse41<!-- {{#callable:fd_blake3_hash_many_sse41}} -->
The `fd_blake3_hash_many_sse41` function computes BLAKE3 hashes for multiple input data blocks using SSE4.1 instructions, optimizing for parallel processing of up to four inputs at a time.
- **Inputs**:
    - `inputs`: A pointer to an array of pointers, each pointing to a block of input data to be hashed.
    - `num_inputs`: The number of input data blocks to be hashed.
    - `blocks`: The number of blocks in each input data to be processed.
    - `key`: A 256-bit key (array of 8 uint32_t) used in the hashing process.
    - `counter`: A 64-bit counter value used in the hashing process, which can be incremented.
    - `increment_counter`: A boolean flag indicating whether the counter should be incremented after processing each set of inputs.
    - `flags`: A byte of flags used to control the hashing process.
    - `flags_start`: A byte of flags indicating the start of a hashing operation.
    - `flags_end`: A byte of flags indicating the end of a hashing operation.
    - `out`: A pointer to the output buffer where the resulting hashes will be stored.
- **Control Flow**:
    - The function first processes inputs in groups of four (defined by DEGREE) using the [`fd_blake3_hash4_sse41`](#fd_blake3_hash4_sse41) function, which hashes four inputs in parallel using SSE4.1 instructions.
    - If `increment_counter` is true, the counter is incremented by the DEGREE value after processing each group of four inputs.
    - The input pointer and output buffer pointer are advanced by the DEGREE value and the corresponding output length, respectively, after each group is processed.
    - Once fewer than four inputs remain, the function processes each remaining input individually using the [`hash_one_sse41`](#hash_one_sse41) function.
    - If `increment_counter` is true, the counter is incremented by one after processing each individual input.
    - The input pointer and output buffer pointer are advanced by one and the output length, respectively, after each input is processed.
- **Output**: The function outputs the computed BLAKE3 hashes into the provided output buffer, with each hash being BLAKE3_OUT_LEN bytes long.
- **Functions called**:
    - [`fd_blake3_hash4_sse41`](#fd_blake3_hash4_sse41)
    - [`hash_one_sse41`](#hash_one_sse41)



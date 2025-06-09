# Purpose
This C source code file is part of the BLAKE3 cryptographic hash function implementation, specifically optimized for SSE2 (Streaming SIMD Extensions 2) instructions. The file provides functions to perform the BLAKE3 compression and hashing operations using SIMD parallelism to enhance performance on processors that support SSE2. The code includes several inline functions that define low-level operations such as loading, storing, adding, and XORing 128-bit vectors, as well as rotating bits within these vectors. These operations are fundamental to the BLAKE3 algorithm, which is a cryptographic hash function known for its speed and security.

The file defines several key functions, such as [`fd_blake3_compress_in_place_sse2`](#fd_blake3_compress_in_place_sse2), [`fd_blake3_compress_xof_sse2`](#fd_blake3_compress_xof_sse2), and [`fd_blake3_hash_many_sse2`](#fd_blake3_hash_many_sse2), which handle the core compression and hashing logic. These functions utilize the defined inline operations to process input data blocks, apply the BLAKE3 compression rounds, and produce hash outputs. The code is structured to handle multiple inputs simultaneously, leveraging the DEGREE constant to process up to four inputs in parallel, which is a common optimization technique in cryptographic implementations to maximize throughput. The file does not define a public API directly but provides essential components that are likely integrated into a larger library or application that implements the BLAKE3 hash function.
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
    - The function takes a pointer to a 16-byte array as input.
    - It casts this pointer to a pointer of type `__m128i`, which is a 128-bit integer type used in SIMD operations.
    - The function then uses the `_mm_loadu_si128` intrinsic to load the 16 bytes from the unaligned memory address into a 128-bit SIMD register.
- **Output**: The function returns a `__m128i` type, which is a 128-bit SIMD register containing the loaded data.


---
### storeu<!-- {{#callable:storeu}} -->
The `storeu` function stores a 128-bit integer from an `__m128i` source into a 16-byte destination array without alignment requirements.
- **Inputs**:
    - `src`: A 128-bit integer of type `__m128i` that is the source data to be stored.
    - `dest`: A pointer to a 16-byte array of type `uint8_t` where the source data will be stored.
- **Control Flow**:
    - The function uses the intrinsic `_mm_storeu_si128` to store the 128-bit integer from `src` into the memory location pointed to by `dest`.
- **Output**: The function does not return a value; it performs an in-place operation on the `dest` array.


---
### addv<!-- {{#callable:addv}} -->
The `addv` function performs a SIMD addition of two 128-bit integer vectors using the `_mm_add_epi32` intrinsic.
- **Inputs**:
    - `a`: A 128-bit integer vector of type `__m128i` representing the first operand.
    - `b`: A 128-bit integer vector of type `__m128i` representing the second operand.
- **Control Flow**:
    - The function directly returns the result of the `_mm_add_epi32` intrinsic, which adds the packed 32-bit integers in the two input vectors `a` and `b`.
- **Output**: The function returns a 128-bit integer vector of type `__m128i` containing the element-wise sum of the input vectors `a` and `b`.


---
### xorv<!-- {{#callable:xorv}} -->
The `xorv` function performs a bitwise XOR operation on two 128-bit integer vectors using SSE2 intrinsics.
- **Inputs**:
    - `a`: A 128-bit integer vector of type `__m128i`.
    - `b`: Another 128-bit integer vector of type `__m128i`.
- **Control Flow**:
    - The function takes two 128-bit integer vectors as input.
    - It applies the `_mm_xor_si128` intrinsic to perform a bitwise XOR operation on the two vectors.
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
    - It calls the intrinsic function `_mm_set1_epi32` to create a 128-bit SIMD register with all four 32-bit lanes set to the value of `x`.
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
    - The `_mm_setr_epi32` intrinsic is called with the casted integers to create a 128-bit SIMD vector with the integers set in the order they are passed (a, b, c, d).
- **Output**: A 128-bit SIMD vector (`__m128i`) containing the four input integers in the specified order.


---
### rot16<!-- {{#callable:rot16}} -->
The `rot16` function performs a 16-bit rotation on the 16-bit elements of a 128-bit SIMD vector using shuffle operations.
- **Inputs**:
    - `x`: A 128-bit SIMD vector (__m128i) containing 16-bit elements to be rotated.
- **Control Flow**:
    - The function first applies the `_mm_shufflelo_epi16` intrinsic to shuffle the lower 64 bits of the input vector `x` using the shuffle control mask `0xB1`.
    - Then, it applies the `_mm_shufflehi_epi16` intrinsic to shuffle the upper 64 bits of the result from the previous step using the same shuffle control mask `0xB1`.
    - The function returns the resulting 128-bit SIMD vector after both shuffle operations.
- **Output**: A 128-bit SIMD vector (__m128i) with its 16-bit elements rotated by 16 bits.


---
### rot12<!-- {{#callable:rot12}} -->
The `rot12` function performs a 12-bit rotation on each 32-bit integer within a 128-bit SIMD vector using bitwise operations.
- **Inputs**:
    - `x`: A 128-bit SIMD vector (__m128i) containing four 32-bit integers to be rotated.
- **Control Flow**:
    - The function shifts each 32-bit integer in the input vector `x` to the right by 12 bits using `_mm_srli_epi32`.
    - It shifts each 32-bit integer in the input vector `x` to the left by 20 bits (32 - 12) using `_mm_slli_epi32`.
    - The results of the right and left shifts are combined using a bitwise XOR operation via the [`xorv`](#xorv) function.
- **Output**: A 128-bit SIMD vector (__m128i) with each 32-bit integer rotated 12 bits to the right.
- **Functions called**:
    - [`xorv`](#xorv)


---
### rot8<!-- {{#callable:rot8}} -->
The `rot8` function performs an 8-bit rotation on each 32-bit integer within a 128-bit SIMD vector using bitwise operations.
- **Inputs**:
    - `x`: A 128-bit SIMD vector (__m128i) containing four 32-bit integers to be rotated.
- **Control Flow**:
    - The function shifts each 32-bit integer in the input vector `x` to the right by 8 bits using `_mm_srli_epi32`.
    - It shifts each 32-bit integer in the input vector `x` to the left by 24 bits (32 - 8) using `_mm_slli_epi32`.
    - The results of the two shifts are combined using a bitwise XOR operation via the [`xorv`](#xorv) function.
- **Output**: A 128-bit SIMD vector (__m128i) where each 32-bit integer has been rotated 8 bits to the right.
- **Functions called**:
    - [`xorv`](#xorv)


---
### rot7<!-- {{#callable:rot7}} -->
The `rot7` function performs a bitwise rotation of each 32-bit integer in a 128-bit SIMD vector by 7 bits to the right.
- **Inputs**:
    - `x`: A 128-bit SIMD vector (__m128i) containing four 32-bit integers to be rotated.
- **Control Flow**:
    - The function takes a 128-bit SIMD vector `x` as input.
    - It performs a logical right shift of each 32-bit integer in `x` by 7 bits using `_mm_srli_epi32`.
    - It performs a logical left shift of each 32-bit integer in `x` by 25 bits (32 - 7) using `_mm_slli_epi32`.
    - The results of the right and left shifts are combined using a bitwise XOR operation via the [`xorv`](#xorv) function.
    - The resulting 128-bit SIMD vector is returned.
- **Output**: A 128-bit SIMD vector (__m128i) where each 32-bit integer has been rotated 7 bits to the right.
- **Functions called**:
    - [`xorv`](#xorv)


---
### g1<!-- {{#callable:g1}} -->
The `g1` function performs a series of SIMD operations on four 128-bit integer vectors, modifying them in place using addition, XOR, and rotation operations.
- **Inputs**:
    - `row0`: A pointer to a 128-bit integer vector (__m128i) representing the first row.
    - `row1`: A pointer to a 128-bit integer vector (__m128i) representing the second row.
    - `row2`: A pointer to a 128-bit integer vector (__m128i) representing the third row.
    - `row3`: A pointer to a 128-bit integer vector (__m128i) representing the fourth row.
    - `m`: A 128-bit integer vector (__m128i) used as an input for the operations.
- **Control Flow**:
    - Add the vector `m` to `*row0` and then add `*row1` to the result, storing the result back in `*row0`.
    - XOR the updated `*row0` with `*row3` and store the result in `*row3`.
    - Rotate the bits of `*row3` by 16 positions and store the result back in `*row3`.
    - Add the updated `*row3` to `*row2` and store the result back in `*row2`.
    - XOR the updated `*row2` with `*row1` and store the result in `*row1`.
    - Rotate the bits of `*row1` by 12 positions and store the result back in `*row1`.
- **Output**: The function modifies the input vectors `row0`, `row1`, `row2`, and `row3` in place, with no return value.
- **Functions called**:
    - [`addv`](#addv)
    - [`xorv`](#xorv)
    - [`rot16`](#rot16)
    - [`rot12`](#rot12)


---
### g2<!-- {{#callable:g2}} -->
The `g2` function performs a series of SIMD operations on four 128-bit integer vectors, modifying them in place using addition, XOR, and bit rotation operations.
- **Inputs**:
    - `row0`: A pointer to a 128-bit integer vector (__m128i) representing the first row.
    - `row1`: A pointer to a 128-bit integer vector (__m128i) representing the second row.
    - `row2`: A pointer to a 128-bit integer vector (__m128i) representing the third row.
    - `row3`: A pointer to a 128-bit integer vector (__m128i) representing the fourth row.
    - `m`: A 128-bit integer vector (__m128i) used as an input to the function.
- **Control Flow**:
    - Add the vector `m` to `row0` and then add `row1` to the result, storing it back in `row0`.
    - XOR the updated `row0` with `row3` and store the result in `row3`.
    - Rotate the bits in `row3` by 8 positions to the left.
    - Add the updated `row3` to `row2` and store the result in `row2`.
    - XOR the updated `row2` with `row1` and store the result in `row1`.
    - Rotate the bits in `row1` by 7 positions to the left.
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
    - The function begins by shuffling the elements of the vector pointed to by `row0` using the `_mm_shuffle_epi32` intrinsic with the shuffle mask `_MM_SHUFFLE(2, 1, 0, 3)`, which rearranges the elements to a new order.
    - Next, the function shuffles the elements of the vector pointed to by `row3` using the shuffle mask `_MM_SHUFFLE(1, 0, 3, 2)`, changing the order of its elements.
    - Finally, the function shuffles the elements of the vector pointed to by `row2` using the shuffle mask `_MM_SHUFFLE(0, 3, 2, 1)`, resulting in a new element order.
- **Output**: The function does not return a value; it modifies the input vectors in place.


---
### undiagonalize<!-- {{#callable:undiagonalize}} -->
The `undiagonalize` function reorders the elements of three 128-bit integer vectors to reverse a previous diagonalization transformation.
- **Inputs**:
    - `row0`: A pointer to a 128-bit integer vector (__m128i) representing the first row to be undiagonalized.
    - `row2`: A pointer to a 128-bit integer vector (__m128i) representing the second row to be undiagonalized.
    - `row3`: A pointer to a 128-bit integer vector (__m128i) representing the third row to be undiagonalized.
- **Control Flow**:
    - The function takes three pointers to __m128i variables, representing rows of data.
    - It applies the `_mm_shuffle_epi32` intrinsic to each row with specific shuffle masks to reorder the elements.
    - For `row0`, the shuffle mask `_MM_SHUFFLE(0, 3, 2, 1)` is used, which reorders the elements to reverse the diagonalization.
    - For `row3`, the shuffle mask `_MM_SHUFFLE(1, 0, 3, 2)` is used.
    - For `row2`, the shuffle mask `_MM_SHUFFLE(2, 1, 0, 3)` is used.
    - The function modifies the input vectors in place, effectively reversing the diagonalization transformation applied earlier.
- **Output**: The function does not return a value; it modifies the input vectors in place.


---
### blend\_epi16<!-- {{#callable:blend_epi16}} -->
The `blend_epi16` function blends two 128-bit integer vectors based on a mask derived from an immediate 16-bit integer.
- **Inputs**:
    - `a`: A 128-bit integer vector (__m128i) representing the first input vector.
    - `b`: A 128-bit integer vector (__m128i) representing the second input vector.
    - `imm8`: A 16-bit integer (int16_t) used to create a mask for blending the vectors.
- **Control Flow**:
    - Initialize a constant vector `bits` with specific bit values for each 16-bit lane.
    - Create a mask vector by setting all lanes to the value of `imm8`.
    - Perform a bitwise AND operation between the mask and the `bits` vector.
    - Compare the result of the AND operation with the `bits` vector to create a boolean mask.
    - Use the boolean mask to blend the vectors `a` and `b` using bitwise operations: select elements from `b` where the mask is true, and from `a` where the mask is false.
    - Return the resulting blended vector.
- **Output**: A 128-bit integer vector (__m128i) that is a blend of the input vectors `a` and `b` based on the mask derived from `imm8`.


---
### compress\_pre<!-- {{#callable:compress_pre}} -->
The `compress_pre` function initializes and processes a set of SIMD registers for the BLAKE3 hash function using a series of rounds with specific permutations and transformations.
- **Inputs**:
    - `rows`: An array of four __m128i registers that will be initialized and modified by the function.
    - `cv`: A constant array of eight 32-bit unsigned integers representing the chaining value.
    - `block`: A constant array of bytes representing the input block to be processed, with a length defined by BLAKE3_BLOCK_LEN.
    - `block_len`: An 8-bit unsigned integer representing the length of the block.
    - `counter`: A 64-bit unsigned integer used as a counter for the hash function.
    - `flags`: An 8-bit unsigned integer representing flags that modify the behavior of the hash function.
- **Control Flow**:
    - Load the first half of the chaining value into the first row and the second half into the second row.
    - Initialize the third row with a set of predefined constants (IV).
    - Initialize the fourth row with the counter, block length, and flags.
    - Load the input block into four __m128i registers (m0, m1, m2, m3).
    - Perform seven rounds of transformations, each consisting of shuffling, blending, and applying the g1 and g2 functions to the rows.
    - Each round involves diagonalizing and undiagonalizing the rows to ensure proper mixing of data.
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
    - [`blend_epi16`](#blend_epi16)


---
### fd\_blake3\_compress\_in\_place\_sse2<!-- {{#callable:fd_blake3_compress_in_place_sse2}} -->
The `fd_blake3_compress_in_place_sse2` function performs an in-place compression of a BLAKE3 hash state using SSE2 instructions.
- **Inputs**:
    - `cv`: An array of 8 uint32_t values representing the chaining value to be compressed.
    - `block`: A constant array of bytes with length BLAKE3_BLOCK_LEN, representing the input block to be compressed.
    - `block_len`: A uint8_t value indicating the length of the block.
    - `counter`: A uint64_t value used as a counter in the compression process.
    - `flags`: A uint8_t value representing flags that modify the behavior of the compression.
- **Control Flow**:
    - Initialize an array `rows` of four __m128i values to hold intermediate state.
    - Call [`compress_pre`](#compress_pre) to prepare the `rows` array using the input parameters `cv`, `block`, `block_len`, `counter`, and `flags`.
    - Perform XOR operations on the `rows` array to combine the results of the compression.
    - Store the results back into the `cv` array using the [`storeu`](#storeu) function.
- **Output**: The function modifies the `cv` array in place, updating it with the compressed state.
- **Functions called**:
    - [`compress_pre`](#compress_pre)
    - [`storeu`](#storeu)
    - [`xorv`](#xorv)


---
### fd\_blake3\_compress\_xof\_sse2<!-- {{#callable:fd_blake3_compress_xof_sse2}} -->
The `fd_blake3_compress_xof_sse2` function performs a BLAKE3 compression operation using SSE2 instructions and outputs a 64-byte result.
- **Inputs**:
    - `cv`: A constant 8-element array of 32-bit unsigned integers representing the chaining value.
    - `block`: A constant array of bytes with length `BLAKE3_BLOCK_LEN` representing the input block to be compressed.
    - `block_len`: An 8-bit unsigned integer representing the length of the block.
    - `counter`: A 64-bit unsigned integer used as a counter in the compression process.
    - `flags`: An 8-bit unsigned integer representing flags that modify the compression behavior.
    - `out`: An array of 64 bytes where the output of the compression will be stored.
- **Control Flow**:
    - Initialize an array `rows` of four `__m128i` elements to store intermediate values.
    - Call [`compress_pre`](#compress_pre) to prepare the `rows` array using the input parameters `cv`, `block`, `block_len`, `counter`, and `flags`.
    - Perform XOR operations between pairs of `rows` and store the results in the `out` array at different offsets.
    - The first XOR operation is between `rows[0]` and `rows[2]`, stored at `out[0]`.
    - The second XOR operation is between `rows[1]` and `rows[3]`, stored at `out[16]`.
    - The third XOR operation is between `rows[2]` and the loaded value from `cv[0]`, stored at `out[32]`.
    - The fourth XOR operation is between `rows[3]` and the loaded value from `cv[4]`, stored at `out[48]`.
- **Output**: The function outputs a 64-byte array `out` containing the result of the BLAKE3 compression operation.
- **Functions called**:
    - [`compress_pre`](#compress_pre)
    - [`storeu`](#storeu)
    - [`xorv`](#xorv)
    - [`loadu`](#loadu)


---
### round\_fn<!-- {{#callable:round_fn}} -->
The `round_fn` function performs a series of vectorized operations on two arrays of 128-bit integers, `v` and `m`, using a predefined message schedule and a specified round index `r`.
- **Inputs**:
    - `v`: An array of 16 __m128i vectors representing the current state of the hash function.
    - `m`: An array of 16 __m128i vectors representing the message block to be processed.
    - `r`: A size_t value representing the current round index, used to access the message schedule.
- **Control Flow**:
    - The function begins by adding elements from the message array `m` to the state array `v` using indices from the `MSG_SCHEDULE` for the current round `r`.
    - It then performs a series of additions between elements of `v` and other elements of `v`, effectively mixing the state.
    - The function applies XOR operations between certain elements of `v` and other elements of `v`, followed by bitwise rotations (rot16, rot12, rot8, rot7) to further mix the state.
    - This process is repeated multiple times with different indices from the `MSG_SCHEDULE` to ensure thorough mixing of the state.
- **Output**: The function modifies the `v` array in place, updating its elements to reflect the mixed state after the round operations.
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
    - `vecs`: An array of four 128-bit vectors (`__m128i`) that will be transposed.
- **Control Flow**:
    - Unpack the lower 32-bit lanes of the first two vectors into `ab_01` and the higher 32-bit lanes into `ab_23`.
    - Unpack the lower 32-bit lanes of the last two vectors into `cd_01` and the higher 32-bit lanes into `cd_23`.
    - Interleave the 64-bit lanes of `ab_01` and `cd_01` to form `abcd_0` and `abcd_1`.
    - Interleave the 64-bit lanes of `ab_23` and `cd_23` to form `abcd_2` and `abcd_3`.
    - Store the results back into the original `vecs` array, effectively transposing the vectors.
- **Output**: The function modifies the input array `vecs` in place, resulting in transposed vectors.


---
### transpose\_msg\_vecs<!-- {{#callable:transpose_msg_vecs}} -->
The `transpose_msg_vecs` function loads and transposes message vectors from input data into a specified output array using SIMD operations.
- **Inputs**:
    - `inputs`: A pointer to an array of pointers, each pointing to a block of input data of type `uint8_t`.
    - `block_offset`: A size_t value representing the offset in bytes from the start of each input block to begin loading data.
    - `out`: An array of 16 `__m128i` elements where the transposed message vectors will be stored.
- **Control Flow**:
    - Load 16 `__m128i` vectors from the input data at specified offsets using the [`loadu`](#loadu) function.
    - Prefetch the next block of data for each input to optimize memory access.
    - Call [`transpose_vecs`](#transpose_vecs) on each set of 4 vectors in the output array to transpose them.
- **Output**: The function does not return a value; it modifies the `out` array in place to contain the transposed message vectors.
- **Functions called**:
    - [`loadu`](#loadu)
    - [`transpose_vecs`](#transpose_vecs)


---
### load\_counters<!-- {{#callable:load_counters}} -->
The `load_counters` function initializes two 128-bit vectors with counter values, optionally incrementing them, and stores the results in the provided output pointers.
- **Inputs**:
    - `counter`: A 64-bit unsigned integer representing the initial counter value.
    - `increment_counter`: A boolean flag indicating whether to increment the counter values.
    - `out_lo`: A pointer to a 128-bit integer where the lower part of the counter will be stored.
    - `out_hi`: A pointer to a 128-bit integer where the higher part of the counter will be stored.
- **Control Flow**:
    - Create a mask using the `increment_counter` flag to determine if the counter should be incremented.
    - Initialize a vector `add0` with values {3, 2, 1, 0}.
    - Compute `add1` by performing a bitwise AND between the mask and `add0`.
    - Calculate the lower part of the counter (`l`) by adding `add1` to the lower 32 bits of the `counter`.
    - Determine if there is a carry by comparing `add1` and `l` using a signed comparison with a bias of 0x80000000.
    - Compute the higher part of the counter (`h`) by subtracting the carry from the higher 32 bits of the `counter`.
    - Store the results in the provided `out_lo` and `out_hi` pointers.
- **Output**: The function outputs two 128-bit vectors through the pointers `out_lo` and `out_hi`, representing the lower and higher parts of the counter, respectively.


---
### fd\_blake3\_hash4\_sse2<!-- {{#callable:fd_blake3_hash4_sse2}} -->
The `fd_blake3_hash4_sse2` function computes the BLAKE3 hash for four inputs in parallel using SSE2 instructions.
- **Inputs**:
    - `inputs`: A pointer to an array of four input data buffers, each containing the data to be hashed.
    - `blocks`: The number of blocks to process for each input.
    - `key`: An array of 8 uint32_t values representing the key used in the BLAKE3 hash function.
    - `counter`: A 64-bit counter value used in the hash computation.
    - `increment_counter`: A boolean flag indicating whether the counter should be incremented for each block.
    - `flags`: A uint8_t value representing the flags used in the BLAKE3 hash function.
    - `flags_start`: A uint8_t value representing the start flags for the hash computation.
    - `flags_end`: A uint8_t value representing the end flags for the hash computation.
    - `out`: A pointer to the output buffer where the resulting hash will be stored.
- **Control Flow**:
    - Initialize eight 128-bit vectors `h_vecs` with the key values using [`set1`](#set1) function.
    - Load the counter values into `counter_low_vec` and `counter_high_vec` using [`load_counters`](#load_counters).
    - Set the initial `block_flags` by combining `flags` and `flags_start`.
    - Iterate over each block of data, updating `block_flags` with `flags_end` for the last block.
    - For each block, set up the message vectors using [`transpose_msg_vecs`](#transpose_msg_vecs) and initialize the state vector `v`.
    - Perform seven rounds of the BLAKE3 compression function using [`round_fn`](#round_fn).
    - Update `h_vecs` by XORing the first and second halves of the state vector `v`.
    - Reset `block_flags` to `flags` for the next iteration.
    - After processing all blocks, transpose the `h_vecs` to prepare for output.
    - Store the transposed `h_vecs` into the output buffer `out` using [`storeu`](#storeu).
- **Output**: The function outputs the computed BLAKE3 hash for the four input buffers into the `out` buffer.
- **Functions called**:
    - [`set1`](#set1)
    - [`load_counters`](#load_counters)
    - [`transpose_msg_vecs`](#transpose_msg_vecs)
    - [`round_fn`](#round_fn)
    - [`xorv`](#xorv)
    - [`transpose_vecs`](#transpose_vecs)
    - [`storeu`](#storeu)


---
### hash\_one\_sse2<!-- {{#callable:hash_one_sse2}} -->
The `hash_one_sse2` function computes a BLAKE3 hash for a single input block using SSE2 instructions.
- **Inputs**:
    - `input`: A pointer to the input data to be hashed.
    - `blocks`: The number of 64-byte blocks in the input data.
    - `key`: A 256-bit key used for hashing, represented as an array of 8 uint32_t values.
    - `counter`: A 64-bit counter value used in the hashing process.
    - `flags`: Flags that modify the behavior of the hash function.
    - `flags_start`: Flags indicating the start of the input data.
    - `flags_end`: Flags indicating the end of the input data.
    - `out`: A pointer to an array where the resulting hash will be stored, with a length of BLAKE3_OUT_LEN bytes.
- **Control Flow**:
    - Initialize the chaining value (cv) by copying the key into it.
    - Set the initial block flags by combining the provided flags with flags_start.
    - Enter a loop that processes each block of the input data.
    - If the current block is the last one, add flags_end to the block flags.
    - Call [`fd_blake3_compress_in_place_sse2`](#fd_blake3_compress_in_place_sse2) to compress the current block and update the chaining value.
    - Advance the input pointer by the block length and decrement the block count.
    - Reset the block flags to the initial flags for the next iteration.
    - After processing all blocks, copy the final chaining value into the output buffer.
- **Output**: The function outputs the computed hash into the provided `out` buffer, which is of length BLAKE3_OUT_LEN bytes.
- **Functions called**:
    - [`fd_blake3_compress_in_place_sse2`](#fd_blake3_compress_in_place_sse2)


---
### fd\_blake3\_hash\_many\_sse2<!-- {{#callable:fd_blake3_hash_many_sse2}} -->
The `fd_blake3_hash_many_sse2` function computes BLAKE3 hashes for multiple input data blocks using SSE2 instructions, processing up to four inputs in parallel.
- **Inputs**:
    - `inputs`: A pointer to an array of pointers, each pointing to a block of input data to be hashed.
    - `num_inputs`: The number of input data blocks to be hashed.
    - `blocks`: The number of blocks in each input data to be processed.
    - `key`: A 256-bit key used for the BLAKE3 hash function.
    - `counter`: A 64-bit counter value used in the hash computation.
    - `increment_counter`: A boolean flag indicating whether the counter should be incremented after processing each input.
    - `flags`: Flags used to modify the behavior of the hash function.
    - `flags_start`: Flags to be applied at the start of the hash computation.
    - `flags_end`: Flags to be applied at the end of the hash computation.
    - `out`: A pointer to the output buffer where the resulting hashes will be stored.
- **Control Flow**:
    - The function enters a loop to process inputs in batches of four (defined by DEGREE) using the [`fd_blake3_hash4_sse2`](#fd_blake3_hash4_sse2) function, which handles four inputs in parallel.
    - If `increment_counter` is true, the counter is incremented by four after processing each batch of four inputs.
    - The input pointer and output pointer are advanced by four inputs and four hash outputs, respectively, and `num_inputs` is decremented by four.
    - Once fewer than four inputs remain, the function enters a second loop to process each remaining input individually using the [`hash_one_sse2`](#hash_one_sse2) function.
    - If `increment_counter` is true, the counter is incremented by one after processing each individual input.
    - The input pointer and output pointer are advanced by one input and one hash output, respectively, and `num_inputs` is decremented by one.
- **Output**: The function outputs the computed BLAKE3 hashes for each input data block into the provided output buffer.
- **Functions called**:
    - [`fd_blake3_hash4_sse2`](#fd_blake3_hash4_sse2)
    - [`hash_one_sse2`](#hash_one_sse2)



# Purpose
This C source code file is part of the BLAKE3 cryptographic hash function implementation, specifically optimized for AVX-512 instruction set extensions. The file provides highly efficient implementations of the BLAKE3 compression and hashing functions using SIMD (Single Instruction, Multiple Data) operations to process multiple data blocks in parallel. The code defines several inline functions for loading, storing, and manipulating 128-bit, 256-bit, and 512-bit vectors, which are essential for leveraging the AVX-512 capabilities to perform operations like addition, XOR, and bitwise rotations on multiple data elements simultaneously.

The file includes functions for compressing data blocks ([`fd_blake3_compress_xof_avx512`](#fd_blake3_compress_xof_avx512) and [`fd_blake3_compress_in_place_avx512`](#fd_blake3_compress_in_place_avx512)) and for hashing multiple inputs ([`fd_blake3_hash_many_avx512`](#fd_blake3_hash_many_avx512)). These functions utilize the defined inline operations to perform the BLAKE3 hashing rounds efficiently. The code is structured to handle different levels of parallelism, processing 4, 8, or 16 inputs at a time, depending on the available data and the AVX-512 capabilities. This file is intended to be part of a larger library, providing optimized hashing functionality for applications that require high-performance cryptographic operations. It does not define a public API directly but rather serves as an internal component of the BLAKE3 implementation, focusing on performance optimization through parallel processing.
# Imports and Dependencies

---
- `blake3_impl.h`
- `immintrin.h`


# Functions

---
### loadu\_128<!-- {{#callable:loadu_128}} -->
The `loadu_128` function loads 128 bits of data from an unaligned memory address into a `__m128i` SIMD register.
- **Inputs**:
    - `src`: A pointer to an array of 16 `uint8_t` values representing the source data to be loaded.
- **Control Flow**:
    - The function casts the `src` pointer to a `const __m128i *` type.
    - It then calls the intrinsic `_mm_loadu_si128`, which loads 128 bits from the specified memory address into a `__m128i` variable.
- **Output**: Returns a `__m128i` value containing the loaded 128 bits of data.


---
### loadu\_256<!-- {{#callable:loadu_256}} -->
Loads 32 bytes from memory into a 256-bit integer.
- **Inputs**:
    - `src`: A pointer to an array of 32 bytes (uint8_t) that will be loaded into a 256-bit integer.
- **Control Flow**:
    - The function uses the intrinsic `_mm256_loadu_si256` to load the data from the provided memory address.
    - The input pointer `src` is cast to a `__m256i` type to match the expected input type of the intrinsic.
- **Output**: Returns a `__m256i` type representing the loaded 256-bit integer from the specified memory location.


---
### loadu\_512<!-- {{#callable:loadu_512}} -->
The `loadu_512` function loads 64 bytes of unaligned data from a source pointer into a 512-bit SIMD integer.
- **Inputs**:
    - `src`: A pointer to an array of 64 bytes (uint8_t) from which the data will be loaded.
- **Control Flow**:
    - The function directly calls the `_mm512_loadu_si512` intrinsic to perform the loading operation.
    - The input pointer `src` is cast to a `__m512i` type to match the expected input type of the intrinsic.
- **Output**: Returns a `__m512i` type containing the loaded 512 bits of data from the specified source.


---
### storeu\_128<!-- {{#callable:storeu_128}} -->
Stores a 128-bit integer into a 16-byte destination array.
- **Inputs**:
    - `src`: A `__m128i` type representing the 128-bit integer to be stored.
    - `dest`: A pointer to an array of 16 `uint8_t` elements where the 128-bit integer will be stored.
- **Control Flow**:
    - The function directly calls the `_mm_storeu_si128` intrinsic to store the 128-bit integer from `src` into the memory location pointed to by `dest`.
    - The `_mm_storeu_si128` intrinsic handles unaligned memory access, allowing the function to store the data without requiring the destination to be aligned.
- **Output**: The function does not return a value; it modifies the memory at the destination address to contain the stored 128-bit integer.


---
### storeu\_256<!-- {{#callable:storeu_256}} -->
Stores a 256-bit integer into a 16-byte destination array.
- **Inputs**:
    - `src`: A 256-bit integer represented as a `__m256i` type, which contains the data to be stored.
    - `dest`: A pointer to an array of 16 bytes where the 256-bit integer will be stored.
- **Control Flow**:
    - The function uses the `_mm256_storeu_si256` intrinsic to store the 256-bit integer from `src` into the memory location pointed to by `dest`.
    - The function does not perform any checks or transformations on the input data before storing it.
- **Output**: The function does not return a value; it directly modifies the memory at the location pointed to by `dest`.


---
### add\_128<!-- {{#callable:add_128}} -->
Adds two 128-bit integer vectors using SIMD operations.
- **Inputs**:
    - `a`: The first `__m128i` vector containing four 32-bit integers.
    - `b`: The second `__m128i` vector containing four 32-bit integers.
- **Control Flow**:
    - The function directly calls the `_mm_add_epi32` intrinsic, which performs element-wise addition of the two input vectors.
    - The result of the addition is returned as a new `__m128i` vector.
- **Output**: Returns a `__m128i` vector that contains the sum of the corresponding elements of the input vectors `a` and `b`.


---
### add\_256<!-- {{#callable:add_256}} -->
Adds two 256-bit integer vectors using AVX2 intrinsics.
- **Inputs**:
    - `a`: A `__m256i` type representing the first 256-bit integer vector.
    - `b`: A `__m256i` type representing the second 256-bit integer vector.
- **Control Flow**:
    - The function directly calls the `_mm256_add_epi32` intrinsic to perform the addition of the two input vectors.
    - The result of the addition is returned as a `__m256i` type.
- **Output**: Returns a `__m256i` type representing the sum of the two input vectors.


---
### add\_512<!-- {{#callable:add_512}} -->
Adds two 512-bit integers using AVX-512 intrinsics.
- **Inputs**:
    - `a`: A `__m512i` type representing the first 512-bit integer.
    - `b`: A `__m512i` type representing the second 512-bit integer.
- **Control Flow**:
    - The function directly calls the `_mm512_add_epi32` intrinsic to perform the addition of the two 512-bit integers.
    - The result of the addition is returned immediately.
- **Output**: Returns a `__m512i` type representing the sum of the two input 512-bit integers.


---
### xor\_128<!-- {{#callable:xor_128}} -->
Performs a bitwise XOR operation on two 128-bit integer vectors.
- **Inputs**:
    - `a`: The first `__m128i` vector to be XORed.
    - `b`: The second `__m128i` vector to be XORed.
- **Control Flow**:
    - The function directly calls the intrinsic `_mm_xor_si128` to perform the XOR operation.
    - It takes two `__m128i` inputs and returns the result of the XOR operation.
- **Output**: Returns a `__m128i` vector that is the result of the bitwise XOR of the two input vectors.


---
### xor\_256<!-- {{#callable:xor_256}} -->
Performs a bitwise XOR operation on two 256-bit integer vectors.
- **Inputs**:
    - `a`: A `__m256i` type representing the first 256-bit integer vector.
    - `b`: A `__m256i` type representing the second 256-bit integer vector.
- **Control Flow**:
    - The function directly calls the intrinsic `_mm256_xor_si256` to perform the XOR operation.
    - The result of the XOR operation is returned immediately.
- **Output**: Returns a `__m256i` type that contains the result of the bitwise XOR of the two input vectors.


---
### xor\_512<!-- {{#callable:xor_512}} -->
Performs a bitwise XOR operation on two 512-bit integer vectors.
- **Inputs**:
    - `a`: A `__m512i` type representing the first 512-bit integer vector.
    - `b`: A `__m512i` type representing the second 512-bit integer vector.
- **Control Flow**:
    - The function directly calls the intrinsic `_mm512_xor_si512` to perform the XOR operation.
    - It takes two input vectors `a` and `b`, and computes the bitwise XOR for each corresponding bit in the vectors.
- **Output**: Returns a `__m512i` type representing the result of the bitwise XOR operation between the two input vectors.


---
### set1\_128<!-- {{#callable:set1_128}} -->
The `set1_128` function creates a 128-bit vector where all four 32-bit integers are set to the same value.
- **Inputs**:
    - `x`: A 32-bit unsigned integer that will be replicated across all lanes of the resulting 128-bit vector.
- **Control Flow**:
    - The function takes a single input argument, `x`, which is a 32-bit unsigned integer.
    - It casts `x` to a signed 32-bit integer and uses the `_mm_set1_epi32` intrinsic to create a 128-bit vector.
    - The resulting vector contains four copies of the integer value derived from `x`.
- **Output**: Returns a `__m128i` type representing a 128-bit vector with all four 32-bit integers set to the value of `x`.


---
### set1\_256<!-- {{#callable:set1_256}} -->
The `set1_256` function initializes a 256-bit vector with all elements set to a specified 32-bit integer value.
- **Inputs**:
    - `x`: A 32-bit unsigned integer that will be replicated across all elements of the resulting 256-bit vector.
- **Control Flow**:
    - The function takes a single input argument, `x`, which is cast to a signed 32-bit integer.
    - It then calls the intrinsic function `_mm256_set1_epi32`, which creates a 256-bit vector where all four 32-bit integers are set to the value of `x`.
- **Output**: Returns a `__m256i` type representing a 256-bit vector with all elements initialized to the value of `x`.


---
### set1\_512<!-- {{#callable:set1_512}} -->
The `set1_512` function creates a 512-bit vector where all elements are set to the specified 32-bit integer value.
- **Inputs**:
    - `x`: A 32-bit unsigned integer that will be replicated across all elements of the resulting 512-bit vector.
- **Control Flow**:
    - The function takes a single input argument, `x`, which is cast to a signed 32-bit integer.
    - The `_mm512_set1_epi32` intrinsic is called with the casted value, which generates a 512-bit vector with all 16 elements set to the value of `x`.
- **Output**: Returns a `__m512i` type representing a 512-bit vector where each of the 16 32-bit integers is equal to the input value `x`.


---
### set4<!-- {{#callable:set4}} -->
The `set4` function initializes a 128-bit SIMD vector with four 32-bit integers.
- **Inputs**:
    - `a`: The first 32-bit unsigned integer to be set in the SIMD vector.
    - `b`: The second 32-bit unsigned integer to be set in the SIMD vector.
    - `c`: The third 32-bit unsigned integer to be set in the SIMD vector.
    - `d`: The fourth 32-bit unsigned integer to be set in the SIMD vector.
- **Control Flow**:
    - The function takes four 32-bit unsigned integers as input.
    - Each integer is cast to a signed 32-bit integer.
    - The `_mm_setr_epi32` intrinsic is called to create a 128-bit vector with the integers in the order a, b, c, d.
- **Output**: The function returns a `__m128i` type representing a 128-bit SIMD vector containing the four input integers.


---
### rot16\_128<!-- {{#callable:rot16_128}} -->
The `rot16_128` function performs a right rotation of 32-bit integers in a 128-bit vector by 16 bits.
- **Inputs**:
    - `x`: A `__m128i` type input vector containing four 32-bit integers to be rotated.
- **Control Flow**:
    - The function takes a single input parameter `x` of type `__m128i`.
    - It calls the intrinsic function `_mm_ror_epi32` which performs a right rotation on each of the four 32-bit integers in the vector `x` by 16 bits.
    - The result of the rotation is returned as a new `__m128i` vector.
- **Output**: The output is a `__m128i` type vector containing the four 32-bit integers from the input vector `x`, each rotated right by 16 bits.


---
### rot16\_256<!-- {{#callable:rot16_256}} -->
The `rot16_256` function performs a right rotation of 32-bit integers in a 256-bit vector by 16 bits.
- **Inputs**:
    - `x`: A `__m256i` type vector containing four 32-bit integers to be rotated.
- **Control Flow**:
    - The function directly calls the intrinsic `_mm256_ror_epi32` which handles the rotation operation.
    - The intrinsic takes the input vector and the number of bits to rotate (16 in this case) as parameters.
- **Output**: Returns a `__m256i` type vector with the 32-bit integers rotated to the right by 16 bits.


---
### rot16\_512<!-- {{#callable:rot16_512}} -->
Performs a 16-bit right rotation on a 512-bit integer.
- **Inputs**:
    - `x`: A `__m512i` type representing a 512-bit integer to be rotated.
- **Control Flow**:
    - The function directly calls the intrinsic `_mm512_ror_epi32` to perform the rotation.
    - The intrinsic rotates the bits of the input `x` to the right by 16 positions.
- **Output**: Returns a `__m512i` type containing the result of the right rotation.


---
### rot12\_128<!-- {{#callable:rot12_128}} -->
Performs a right rotation of 12 bits on a 128-bit integer.
- **Inputs**:
    - `x`: A `__m128i` type representing a 128-bit integer to be rotated.
- **Control Flow**:
    - The function directly calls the intrinsic `_mm_ror_epi32` to perform the rotation.
    - The intrinsic rotates the 32-bit integers within the 128-bit integer `x` by 12 bits to the right.
- **Output**: Returns a `__m128i` type containing the result of the right rotation of `x` by 12 bits.


---
### rot12\_256<!-- {{#callable:rot12_256}} -->
Performs a right rotation of 12 bits on each 32-bit integer in a 256-bit vector.
- **Inputs**:
    - `x`: A `__m256i` type vector containing four 32-bit integers to be rotated.
- **Control Flow**:
    - The function directly calls the intrinsic `_mm256_ror_epi32` which performs a right rotation on each 32-bit integer in the input vector `x` by 12 bits.
    - The result of the rotation is returned as a new `__m256i` vector.
- **Output**: Returns a `__m256i` vector where each 32-bit integer has been right-rotated by 12 bits.


---
### rot12\_512<!-- {{#callable:rot12_512}} -->
Performs a right rotation of 12 bits on a 512-bit integer.
- **Inputs**:
    - `x`: A `__m512i` type representing a 512-bit integer to be rotated.
- **Control Flow**:
    - The function directly calls the intrinsic `_mm512_ror_epi32` to perform the rotation.
    - The intrinsic takes the input `x` and rotates it right by 12 bits.
- **Output**: Returns a `__m512i` type representing the result of the right rotation.


---
### rot8\_128<!-- {{#callable:rot8_128}} -->
The `rot8_128` function performs a right rotation of 8 bits on a 128-bit integer.
- **Inputs**:
    - `x`: A `__m128i` type representing a 128-bit integer on which the rotation operation will be performed.
- **Control Flow**:
    - The function directly calls the intrinsic `_mm_ror_epi32` to perform the rotation.
    - The intrinsic takes the input `x` and rotates it right by 8 bits.
- **Output**: Returns a `__m128i` type that contains the result of the right rotation of the input by 8 bits.


---
### rot8\_256<!-- {{#callable:rot8_256}} -->
Performs a right rotation of 8 bits on a 256-bit integer.
- **Inputs**:
    - `x`: A `__m256i` type variable representing a 256-bit integer to be rotated.
- **Control Flow**:
    - The function directly calls the intrinsic `_mm256_ror_epi32` to perform the rotation.
    - The intrinsic rotates the 32-bit integers within the 256-bit integer `x` to the right by 8 bits.
- **Output**: Returns a `__m256i` type variable that contains the result of the right rotation of the input `x`.


---
### rot8\_512<!-- {{#callable:rot8_512}} -->
Performs a right rotation of 32-bit integers in a 512-bit vector by 8 bits.
- **Inputs**:
    - `x`: A `__m512i` type vector containing 16 packed 32-bit integers to be rotated.
- **Control Flow**:
    - The function directly calls the intrinsic `_mm512_ror_epi32` which performs the rotation.
    - The rotation is applied to all 32-bit integers in the input vector `x`.
- **Output**: Returns a `__m512i` type vector with the 32-bit integers rotated right by 8 bits.


---
### rot7\_128<!-- {{#callable:rot7_128}} -->
The `rot7_128` function performs a right rotation of a 128-bit integer by 7 bits.
- **Inputs**:
    - `x`: A `__m128i` type representing a 128-bit integer that will be rotated.
- **Control Flow**:
    - The function directly calls the intrinsic `_mm_ror_epi32` to perform the rotation.
    - The intrinsic takes the input `x` and rotates it right by 7 bits.
- **Output**: Returns a `__m128i` type that contains the result of the right rotation of the input by 7 bits.


---
### rot7\_256<!-- {{#callable:rot7_256}} -->
The `rot7_256` function performs a right rotation of 32-bit integers in a 256-bit vector by 7 bits.
- **Inputs**:
    - `x`: A `__m256i` type vector containing four 32-bit integers to be rotated.
- **Control Flow**:
    - The function directly calls the intrinsic `_mm256_ror_epi32` which handles the rotation operation.
    - The intrinsic takes the input vector `x` and the number of bits to rotate (7) as parameters.
- **Output**: Returns a `__m256i` type vector with the 32-bit integers rotated to the right by 7 bits.


---
### rot7\_512<!-- {{#callable:rot7_512}} -->
Performs a right rotation of 32-bit integers in a 512-bit vector by 7 bits.
- **Inputs**:
    - `x`: A `__m512i` type vector containing 16 packed 32-bit integers to be rotated.
- **Control Flow**:
    - The function directly calls the intrinsic `_mm512_ror_epi32` which performs the rotation.
    - The rotation is applied to each of the 32-bit integers in the `__m512i` vector.
- **Output**: Returns a `__m512i` vector with the 32-bit integers rotated right by 7 bits.


---
### g1<!-- {{#callable:g1}} -->
The `g1` function performs a series of arithmetic and bitwise operations on four `__m128i` vectors, modifying their values based on a given input vector.
- **Inputs**:
    - `row0`: A pointer to the first `__m128i` vector that will be modified by the function.
    - `row1`: A pointer to the second `__m128i` vector that will be used in calculations.
    - `row2`: A pointer to the third `__m128i` vector that will be modified by the function.
    - `row3`: A pointer to the fourth `__m128i` vector that will be modified by the function.
    - `m`: An `__m128i` vector that serves as an input for arithmetic operations.
- **Control Flow**:
    - The function first adds the value of `m` to `row0` and `row1`, storing the result back in `row0`.
    - Next, it performs a bitwise XOR operation between `row3` and the updated `row0`, storing the result in `row3`.
    - The `row3` vector is then rotated 16 bits to the right.
    - The updated `row3` is added to `row2`, and the result is stored back in `row2`.
    - A bitwise XOR operation is performed between `row1` and the updated `row2`, with the result stored in `row1`.
    - Finally, `row1` is rotated 12 bits to the right.
- **Output**: The function modifies the input vectors `row0`, `row1`, `row2`, and `row3` in place, resulting in updated values based on the specified arithmetic and bitwise operations.
- **Functions called**:
    - [`add_128`](#add_128)
    - [`xor_128`](#xor_128)
    - [`rot16_128`](#rot16_128)
    - [`rot12_128`](#rot12_128)


---
### g2<!-- {{#callable:g2}} -->
The `g2` function performs a series of arithmetic and bitwise operations on four `__m128i` vectors, modifying their values based on a given input vector.
- **Inputs**:
    - `row0`: A pointer to the first `__m128i` vector that will be modified.
    - `row1`: A pointer to the second `__m128i` vector that will be used in calculations.
    - `row2`: A pointer to the third `__m128i` vector that will be modified.
    - `row3`: A pointer to the fourth `__m128i` vector that will be modified.
    - `m`: An `__m128i` vector used as an additive constant in the calculations.
- **Control Flow**:
    - The function begins by adding the value of `m` to `row0` and `row1`, storing the result back in `row0`.
    - Next, it performs a bitwise XOR operation between `row3` and the updated `row0`, storing the result in `row3`.
    - The `row3` vector is then rotated 8 bits to the right.
    - The updated `row3` is added to `row2`, and the result is stored back in `row2`.
    - Finally, `row1` is updated by performing a bitwise XOR with `row2`, and then it is rotated 7 bits to the right.
- **Output**: The function modifies the input vectors `row0`, `row1`, `row2`, and `row3` in place, resulting in updated values based on the specified arithmetic and bitwise operations.
- **Functions called**:
    - [`add_128`](#add_128)
    - [`xor_128`](#xor_128)
    - [`rot8_128`](#rot8_128)
    - [`rot7_128`](#rot7_128)


---
### diagonalize<!-- {{#callable:diagonalize}} -->
The `diagonalize` function rearranges the elements of three `__m128i` vectors by applying specific shuffles to each vector.
- **Inputs**:
    - `row0`: A pointer to the first `__m128i` vector that will be shuffled.
    - `row2`: A pointer to the second `__m128i` vector that will be shuffled.
    - `row3`: A pointer to the third `__m128i` vector that will be shuffled.
- **Control Flow**:
    - The function first shuffles the elements of `row0` using `_mm_shuffle_epi32` with the `_MM_SHUFFLE(2, 1, 0, 3)` mask, which moves the first three elements to the front and keeps the last element in place.
    - Next, it shuffles `row3` with the `_MM_SHUFFLE(1, 0, 3, 2)` mask, which swaps the first two elements and keeps the last two in their positions.
    - Finally, it shuffles `row2` using the `_MM_SHUFFLE(0, 3, 2, 1)` mask, which moves the last element to the front and shifts the others accordingly.
- **Output**: The function modifies the input vectors in place, resulting in `row0`, `row2`, and `row3` being rearranged according to the specified shuffle patterns.


---
### undiagonalize<!-- {{#callable:undiagonalize}} -->
The `undiagonalize` function rearranges the elements of three `__m128i` vectors to reverse the effects of a previous diagonalization operation.
- **Inputs**:
    - `row0`: A pointer to the first `__m128i` vector that will be modified.
    - `row2`: A pointer to the second `__m128i` vector that will be modified.
    - `row3`: A pointer to the third `__m128i` vector that will be modified.
- **Control Flow**:
    - The function takes three pointers to `__m128i` vectors as input.
    - It applies the `_mm_shuffle_epi32` intrinsic to `row0`, `row2`, and `row3` to rearrange their elements according to specified shuffle masks.
    - The shuffling of `row0` moves the last element to the first position and shifts the others to the right.
    - The shuffling of `row3` swaps the first two elements and keeps the last two in place.
    - The shuffling of `row2` reverses the order of its first three elements while keeping the last element in place.
- **Output**: The function modifies the input vectors in place, resulting in `row0`, `row2`, and `row3` being rearranged to their undiagonalized states.


---
### compress\_pre<!-- {{#callable:compress_pre}} -->
The `compress_pre` function prepares and processes input data for the BLAKE3 compression algorithm using SIMD operations.
- **Inputs**:
    - `rows`: An array of four `__m128i` vectors that will hold the state of the compression.
    - `cv`: An array of eight 32-bit unsigned integers representing the chaining values.
    - `block`: A pointer to a block of data of length `BLAKE3_BLOCK_LEN` that will be compressed.
    - `block_len`: An 8-bit unsigned integer representing the length of the block.
    - `counter`: A 64-bit unsigned integer used to track the number of blocks processed.
    - `flags`: An 8-bit unsigned integer representing various flags for the compression process.
- **Control Flow**:
    - The function initializes the `rows` array with values derived from the `cv`, `counter`, `block_len`, and `flags`.
    - It loads four 128-bit chunks from the `block` into local variables `m0`, `m1`, `m2`, and `m3`.
    - The first round of processing permutes the message words and applies the [`g1`](#g1) and [`g2`](#g2) functions to mix the state.
    - Subsequent rounds (2 to 7) continue to apply fixed permutations and mixing operations to the state using the [`g1`](#g1) and [`g2`](#g2) functions.
    - The function uses diagonalization and undiagonalization to rearrange the state vectors between rounds.
- **Output**: The function modifies the `rows` array in place, preparing it for further processing in the BLAKE3 compression algorithm.
- **Functions called**:
    - [`loadu_128`](#loadu_128)
    - [`set4`](#set4)
    - [`counter_low`](blake3_impl.h.driver.md#counter_low)
    - [`counter_high`](blake3_impl.h.driver.md#counter_high)
    - [`g1`](#g1)
    - [`g2`](#g2)
    - [`diagonalize`](#diagonalize)
    - [`undiagonalize`](#undiagonalize)


---
### fd\_blake3\_compress\_xof\_avx512<!-- {{#callable:fd_blake3_compress_xof_avx512}} -->
Compresses a BLAKE3 block using AVX512 instructions.
- **Inputs**:
    - `cv`: An array of 8 `uint32_t` values representing the current state of the hash.
    - `block`: A `uint8_t` array of length `BLAKE3_BLOCK_LEN` containing the data block to be compressed.
    - `block_len`: A `uint8_t` indicating the length of the block being processed.
    - `counter`: A `uint64_t` value used to track the position of the block in the input.
    - `flags`: A `uint8_t` value representing various flags for the compression operation.
    - `out`: A `uint8_t` array of length 64 where the output of the compression will be stored.
- **Control Flow**:
    - The function initializes an array of 4 `__m128i` vectors to hold intermediate results.
    - It calls [`compress_pre`](#compress_pre) to load the current state and the block data into the `rows` array.
    - The function then performs XOR operations between the rows and the current state, storing the results in the output array.
    - Each output segment is stored in the `out` array at specific offsets.
- **Output**: The function produces a 64-byte output in the `out` array, which contains the result of the compression operation.
- **Functions called**:
    - [`compress_pre`](#compress_pre)
    - [`storeu_128`](#storeu_128)
    - [`xor_128`](#xor_128)
    - [`loadu_128`](#loadu_128)


---
### fd\_blake3\_compress\_in\_place\_avx512<!-- {{#callable:fd_blake3_compress_in_place_avx512}} -->
Compresses a BLAKE3 block in place using AVX512 instructions.
- **Inputs**:
    - `cv`: An array of 8 `uint32_t` values representing the current state of the hash.
    - `block`: A pointer to an array of `uint8_t` representing the block of data to be compressed.
    - `block_len`: A `uint8_t` value indicating the length of the block.
    - `counter`: A `uint64_t` value used to track the position of the block in the input stream.
    - `flags`: A `uint8_t` value representing various flags that modify the compression behavior.
- **Control Flow**:
    - The function initializes an array of 4 `__m128i` vectors to hold intermediate results.
    - It calls the [`compress_pre`](#compress_pre) function to prepare the state and load the input block into the vectors.
    - The function then performs XOR operations between specific rows of the vectors and the current state, updating the state in place.
    - Finally, it stores the results back into the `cv` array.
- **Output**: The function modifies the `cv` array in place, updating it with the results of the compression operation.
- **Functions called**:
    - [`compress_pre`](#compress_pre)
    - [`storeu_128`](#storeu_128)
    - [`xor_128`](#xor_128)


---
### round\_fn4<!-- {{#callable:round_fn4}} -->
Performs a series of operations on two arrays of 128-bit integers, modifying the first array based on values from the second and a predefined message schedule.
- **Inputs**:
    - `v`: An array of 16 `__m128i` integers that will be modified during the function execution.
    - `m`: An array of 16 `__m128i` integers used as input for the operations performed on `v`.
    - `r`: A size_t index used to access specific elements in the `MSG_SCHEDULE` array.
- **Control Flow**:
    - The function begins by adding specific elements from the `m` array to the first four elements of the `v` array based on the `MSG_SCHEDULE` index.
    - Subsequent additions are performed between elements of `v` and the results of previous operations.
    - XOR operations are applied to the last four elements of `v` using the results of the additions.
    - The function then rotates the last four elements of `v` and continues to perform additions and XOR operations in a structured manner.
    - This process is repeated multiple times, with different indices from the `MSG_SCHEDULE` being used for each round of operations.
- **Output**: The function modifies the input array `v` in place, resulting in a transformed state of `v` after all operations are completed.
- **Functions called**:
    - [`add_128`](#add_128)
    - [`xor_128`](#xor_128)
    - [`rot16_128`](#rot16_128)
    - [`rot12_128`](#rot12_128)
    - [`rot8_128`](#rot8_128)
    - [`rot7_128`](#rot7_128)


---
### transpose\_vecs\_128<!-- {{#callable:transpose_vecs_128}} -->
Transposes four `__m128i` vectors by interleaving their 32-bit and 64-bit lanes.
- **Inputs**:
    - `vecs`: An array of four `__m128i` vectors that will be transposed.
- **Control Flow**:
    - Unpacks the lower 32-bit lanes of the first two vectors and the upper 32-bit lanes of the first two vectors to create intermediate vectors.
    - Unpacks the lower 32-bit lanes of the last two vectors and the upper 32-bit lanes of the last two vectors to create additional intermediate vectors.
    - Interleaves the lower 64-bit lanes of the intermediate vectors to form the first two transposed vectors.
    - Interleaves the upper 64-bit lanes of the intermediate vectors to form the last two transposed vectors.
    - Stores the results back into the original array of vectors.
- **Output**: The function modifies the input array `vecs` in place, resulting in the transposed vectors.


---
### transpose\_msg\_vecs4<!-- {{#callable:transpose_msg_vecs4}} -->
Transposes 4 sets of 128-bit message vectors from input arrays into an output array.
- **Inputs**:
    - `inputs`: A pointer to an array of pointers, where each pointer points to an array of `uint8_t` data representing the input message vectors.
    - `block_offset`: A size_t value indicating the offset in bytes from which to start reading the input data for transposition.
    - `out`: An array of `__m128i` (128-bit integer vectors) where the transposed output will be stored.
- **Control Flow**:
    - The function loads 128-bit chunks of data from the input arrays into the output array in a specific order.
    - It iterates over 4 rows of input data, loading 4 chunks for each row and storing them in the output array.
    - After loading the data, it prefetches additional data to optimize memory access for subsequent operations.
    - Finally, it calls [`transpose_vecs_128`](#transpose_vecs_128) four times to transpose the loaded vectors in the output array.
- **Output**: The function does not return a value; instead, it populates the `out` array with the transposed 128-bit vectors.
- **Functions called**:
    - [`loadu_128`](#loadu_128)
    - [`transpose_vecs_128`](#transpose_vecs_128)


---
### load\_counters4<!-- {{#callable:load_counters4}} -->
The `load_counters4` function loads and prepares counter values for processing in a SIMD-friendly manner.
- **Inputs**:
    - `counter`: A 64-bit unsigned integer representing the base value of the counter.
    - `increment_counter`: A boolean flag indicating whether to increment the counter values.
    - `out_lo`: A pointer to a `__m128i` variable where the lower 128 bits of the counter values will be stored.
    - `out_hi`: A pointer to a `__m128i` variable where the higher 128 bits of the counter values will be stored.
- **Control Flow**:
    - The function first determines a mask based on the `increment_counter` flag, which is used to conditionally modify the counter values.
    - A vector `mask_vec` is created, which contains the mask replicated across all lanes.
    - A vector `deltas` is initialized with values 0, 1, 2, and 3, which represent the increments to be applied to the base counter.
    - The `deltas` vector is ANDed with the `mask_vec` to conditionally zero out the deltas if `increment_counter` is false.
    - The base counter is added to the modified `deltas` vector to compute the final counter values.
    - The lower 128 bits of the resulting counter values are converted to 32-bit integers and stored in `out_lo`, while the upper 128 bits are stored in `out_hi`.
- **Output**: The function does not return a value; instead, it populates the `out_lo` and `out_hi` pointers with the lower and upper parts of the counter values, respectively.


---
### fd\_blake3\_hash4\_avx512<!-- {{#callable:fd_blake3_hash4_avx512}} -->
Computes the BLAKE3 hash for multiple input blocks using AVX512 instructions.
- **Inputs**:
    - `inputs`: An array of pointers to input byte arrays, where each array represents a block of data to be hashed.
    - `blocks`: The number of blocks of data to process.
    - `key`: An array of 8 32-bit unsigned integers representing the key used for hashing.
    - `counter`: A 64-bit unsigned integer used to differentiate between different hash computations.
    - `increment_counter`: A boolean flag indicating whether to increment the counter for each block processed.
    - `flags`: A byte representing flags that modify the behavior of the hashing process.
    - `flags_start`: A byte representing additional flags to apply at the start of the hashing process.
    - `flags_end`: A byte representing additional flags to apply at the end of the hashing process.
    - `out`: A pointer to an output buffer where the resulting hash will be stored.
- **Control Flow**:
    - Initialize hash vectors from the provided key using [`set1_128`](#set1_128).
    - Load the counter values into vectors using [`load_counters4`](#load_counters4).
    - Combine the initial flags with `flags_start` to create `block_flags`.
    - Iterate over each block of input data, processing it in groups of four.
    - For each block, update `block_flags` if it is the last block.
    - Prepare message vectors by transposing the input data using [`transpose_msg_vecs4`](#transpose_msg_vecs4).
    - Initialize the state vector `v` with hash vectors, IV, counter, block length, and flags.
    - Perform multiple rounds of hashing using [`round_fn4`](#round_fn4).
    - Update the hash vectors by XORing the results from the state vector.
    - After processing all blocks, transpose the final hash vectors and store the results in the output buffer.
- **Output**: The output is a buffer containing the computed BLAKE3 hash, organized in 128-bit chunks.
- **Functions called**:
    - [`set1_128`](#set1_128)
    - [`load_counters4`](#load_counters4)
    - [`transpose_msg_vecs4`](#transpose_msg_vecs4)
    - [`round_fn4`](#round_fn4)
    - [`xor_128`](#xor_128)
    - [`transpose_vecs_128`](#transpose_vecs_128)
    - [`storeu_128`](#storeu_128)


---
### round\_fn8<!-- {{#callable:round_fn8}} -->
The `round_fn8` function performs a series of operations on two arrays of 256-bit integers, applying additions, XORs, and rotations based on a message schedule.
- **Inputs**:
    - `v`: An array of 16 `__m256i` vectors representing the state to be modified.
    - `m`: An array of 16 `__m256i` vectors representing the message schedule used for the operations.
    - `r`: A size_t index used to access specific elements in the message schedule.
- **Control Flow**:
    - The function begins by adding specific elements from the message array `m` to the state array `v` based on the current round index `r`.
    - It then performs a series of additions between elements of `v` and updates the state with XOR operations.
    - The function applies rotations to certain elements of `v` to mix the data further.
    - This process is repeated multiple times, with different elements from `m` being added and further modifications to `v` occurring in each round.
    - The function concludes by performing additional XORs and rotations to finalize the state.
- **Output**: The function modifies the input state array `v` in place, resulting in a transformed state that reflects the operations performed based on the message schedule.
- **Functions called**:
    - [`add_256`](#add_256)
    - [`xor_256`](#xor_256)
    - [`rot16_256`](#rot16_256)
    - [`rot12_256`](#rot12_256)
    - [`rot8_256`](#rot8_256)
    - [`rot7_256`](#rot7_256)


---
### transpose\_vecs\_256<!-- {{#callable:transpose_vecs_256}} -->
Transposes an array of 256-bit vectors by interleaving their 32-bit lanes.
- **Inputs**:
    - `vecs`: An array of 8 `__m256i` vectors, each representing 256 bits of data.
- **Control Flow**:
    - Unpacks the lower and upper 32-bit lanes of the first four vectors (vecs[0] to vecs[3]) into separate variables.
    - Unpacks the lower and upper 32-bit lanes of the last four vectors (vecs[4] to vecs[7]) into separate variables.
    - Interleaves the unpacked 64-bit lanes from the first and second pairs of vectors.
    - Permutes the interleaved results to form the final transposed vectors.
- **Output**: The function modifies the input array `vecs` in place, resulting in a transposed arrangement of the original vectors.


---
### transpose\_msg\_vecs8<!-- {{#callable:transpose_msg_vecs8}} -->
Transposes 8 vectors of 256-bit messages from input arrays into an output array.
- **Inputs**:
    - `inputs`: A pointer to an array of pointers, where each pointer points to an array of 8-bit unsigned integers (uint8_t). Each array represents a message vector.
    - `block_offset`: A size_t value indicating the offset in bytes from which to start reading the input message vectors.
    - `out`: An array of 256-bit vectors (type `__m256i`) where the transposed output will be stored.
- **Control Flow**:
    - The function loads 16 vectors of 256 bits each from the input arrays, using the specified block offset.
    - It uses the [`loadu_256`](#loadu_256) function to load the vectors from the input arrays into the output array.
    - After loading the first 8 vectors, it prefetches the next set of data to optimize memory access.
    - Finally, it calls [`transpose_vecs_256`](#transpose_vecs_256) twice to transpose the loaded vectors in the output array.
- **Output**: The function does not return a value; instead, it populates the `out` array with the transposed vectors.
- **Functions called**:
    - [`loadu_256`](#loadu_256)
    - [`transpose_vecs_256`](#transpose_vecs_256)


---
### load\_counters8<!-- {{#callable:load_counters8}} -->
The `load_counters8` function loads and prepares 8 64-bit counters for output, optionally incrementing them.
- **Inputs**:
    - `counter`: A 64-bit unsigned integer representing the base value for the counters.
    - `increment_counter`: A boolean flag indicating whether to increment the counters.
    - `out_lo`: A pointer to an `__m256i` variable where the lower 32 bits of the counters will be stored.
    - `out_hi`: A pointer to an `__m256i` variable where the higher 32 bits of the counters will be stored.
- **Control Flow**:
    - A mask is created based on the `increment_counter` flag, which determines if the counters should be incremented or not.
    - A vector of deltas (0 to 7) is created, which will be used to calculate the final counter values.
    - The deltas are masked with the previously created mask to determine which deltas to apply based on the increment flag.
    - The base counter value is added to the masked deltas to compute the final counter values.
    - The resulting 64-bit counters are converted to 32-bit integers and stored in the provided output pointers.
- **Output**: The function outputs two `__m256i` variables: `out_lo` contains the lower 32 bits of the counters, and `out_hi` contains the higher 32 bits.


---
### fd\_blake3\_hash8\_avx512<!-- {{#callable:fd_blake3_hash8_avx512}} -->
Computes the BLAKE3 hash for multiple input blocks using AVX512 instructions.
- **Inputs**:
    - `inputs`: An array of pointers to input byte arrays, where each array represents a block of data to be hashed.
    - `blocks`: The number of blocks of data to process.
    - `key`: An array of 8 32-bit unsigned integers representing the key used for hashing.
    - `counter`: A 64-bit unsigned integer used to differentiate between different hash computations.
    - `increment_counter`: A boolean flag indicating whether to increment the counter for each block processed.
    - `flags`: A byte representing flags that modify the behavior of the hashing process.
    - `flags_start`: A byte representing additional flags to apply at the start of the hashing process.
    - `flags_end`: A byte representing additional flags to apply at the end of the hashing process.
    - `out`: A pointer to an output buffer where the resulting hash will be stored.
- **Control Flow**:
    - Initialize hash vectors `h_vecs` with the provided key values.
    - Load the counter values into `counter_low_vec` and `counter_high_vec` based on the `increment_counter` flag.
    - Set the initial block flags by combining `flags` with `flags_start`.
    - Iterate over each block of input data, processing them one by one.
    - For each block, update the block flags to include `flags_end` if it is the last block.
    - Prepare the message vectors by transposing the input data for AVX512 processing.
    - Perform multiple rounds of hashing using the [`round_fn8`](#round_fn8) function, updating the hash vectors.
    - After processing all blocks, transpose the final hash vectors and store the results in the output buffer.
- **Output**: The function outputs the computed BLAKE3 hash into the provided output buffer, which contains the hash result for the processed input blocks.
- **Functions called**:
    - [`set1_256`](#set1_256)
    - [`load_counters8`](#load_counters8)
    - [`transpose_msg_vecs8`](#transpose_msg_vecs8)
    - [`round_fn8`](#round_fn8)
    - [`xor_256`](#xor_256)
    - [`transpose_vecs_256`](#transpose_vecs_256)
    - [`storeu_256`](#storeu_256)


---
### round\_fn16<!-- {{#callable:round_fn16}} -->
The `round_fn16` function performs a series of operations on two arrays of 16 `__m512i` vectors, applying additions, XORs, and rotations based on a message schedule.
- **Inputs**:
    - `v`: An array of 16 `__m512i` vectors that will be modified during the function.
    - `m`: An array of 16 `__m512i` vectors representing the message schedule used for the operations.
    - `r`: A size_t index used to access specific elements in the message schedule.
- **Control Flow**:
    - The function begins by adding specific elements from the message array `m` to the vector array `v` based on the current round index `r`.
    - It performs a series of additions and XOR operations on the vectors, modifying their values iteratively.
    - The function applies rotations to certain vectors after performing XOR operations to introduce diffusion.
    - This process is repeated for multiple rounds, with the results of previous operations influencing subsequent calculations.
    - Finally, the modified vectors are stored back into the original array `v`.
- **Output**: The function modifies the input array `v` in place, resulting in a transformed set of vectors based on the operations defined by the message schedule and the round index.
- **Functions called**:
    - [`add_512`](#add_512)
    - [`xor_512`](#xor_512)
    - [`rot16_512`](#rot16_512)
    - [`rot12_512`](#rot12_512)
    - [`rot8_512`](#rot8_512)
    - [`rot7_512`](#rot7_512)


---
### unpack\_lo\_128<!-- {{#callable:unpack_lo_128}} -->
The `unpack_lo_128` function interleaves the lower 128 bits of two 512-bit vectors.
- **Inputs**:
    - `a`: A 512-bit vector from which the lower 128 bits will be extracted.
    - `b`: Another 512-bit vector from which the lower 128 bits will be interleaved with the first vector.
- **Control Flow**:
    - The function uses the `_mm512_shuffle_i32x4` intrinsic to perform a shuffle operation on the two input vectors.
    - The shuffle operation is defined by the constant `LO_IMM8`, which specifies how the lanes of the input vectors are combined.
- **Output**: Returns a 512-bit vector containing the interleaved lower 128 bits of the input vectors `a` and `b`.


---
### unpack\_hi\_128<!-- {{#callable:unpack_hi_128}} -->
The `unpack_hi_128` function extracts the high 128 bits from two 512-bit vectors.
- **Inputs**:
    - `a`: A `__m512i` type vector containing 512 bits.
    - `b`: Another `__m512i` type vector containing 512 bits.
- **Control Flow**:
    - The function uses the `_mm512_shuffle_i32x4` intrinsic to perform a shuffle operation on the input vectors.
    - The shuffle pattern is defined by the constant `HI_IMM8`, which specifies which lanes to select from the input vectors.
- **Output**: Returns a `__m512i` type vector containing the high 128 bits from the input vectors `a` and `b`.


---
### transpose\_vecs\_512<!-- {{#callable:transpose_vecs_512}} -->
Transposes a 16-element array of 512-bit vectors by interleaving their 32-bit, 64-bit, and 128-bit lanes.
- **Inputs**:
    - `vecs`: An array of 16 `__m512i` vectors, each representing a 512-bit integer.
- **Control Flow**:
    - The function begins by unpacking the 32-bit lanes of the input vectors into two sets for each pair of vectors.
    - Next, it interleaves the unpacked 32-bit lanes into 64-bit lanes.
    - Then, it interleaves the 64-bit lanes into 128-bit lanes.
    - Finally, it interleaves the 128-bit lanes again to produce the final transposed output.
- **Output**: The function modifies the input array `vecs` in place, resulting in a transposed arrangement of the original vectors.
- **Functions called**:
    - [`unpack_lo_128`](#unpack_lo_128)
    - [`unpack_hi_128`](#unpack_hi_128)


---
### transpose\_msg\_vecs16<!-- {{#callable:transpose_msg_vecs16}} -->
Transposes 16 vectors of 512 bits each from the input array into the output array.
- **Inputs**:
    - `inputs`: A pointer to an array of pointers, where each pointer points to an array of `uint8_t` data.
    - `block_offset`: An offset indicating the starting position in each input array from which to read data.
    - `out`: An array of 16 `__m512i` types where the transposed data will be stored.
- **Control Flow**:
    - The function loads 16 blocks of 512 bits from the input arrays starting at the specified `block_offset` into the `out` array.
    - It uses the [`loadu_512`](#loadu_512) function to perform unaligned loads of the data.
    - After loading the data, it prefetches the next set of data for each input to optimize memory access.
    - Finally, it calls [`transpose_vecs_512`](#transpose_vecs_512) to transpose the loaded vectors.
- **Output**: The function does not return a value; instead, it populates the `out` array with the transposed vectors.
- **Functions called**:
    - [`loadu_512`](#loadu_512)
    - [`transpose_vecs_512`](#transpose_vecs_512)


---
### load\_counters16<!-- {{#callable:load_counters16}} -->
Loads 16 counters into two 512-bit vectors, adjusting for carry and incrementing if specified.
- **Inputs**:
    - `counter`: A 64-bit unsigned integer representing the starting value of the counters.
    - `increment_counter`: A boolean flag indicating whether to increment the counters.
    - `out_lo`: A pointer to a `__m512i` variable where the lower 512 bits of the counters will be stored.
    - `out_hi`: A pointer to a `__m512i` variable where the higher 512 bits of the counters will be stored.
- **Control Flow**:
    - A mask is created based on the `increment_counter` flag, which determines whether to increment the counters or not.
    - Deltas are initialized to a vector containing values from 15 down to 0.
    - The deltas are masked with the previously created mask to determine which deltas to apply.
    - The low words of the counters are calculated by adding the masked deltas to the initial counter value.
    - Carry bits are computed to determine if any of the additions resulted in an overflow.
    - The high words of the counters are calculated by adding the carry bits to the upper part of the initial counter.
- **Output**: The function outputs two 512-bit vectors: `out_lo` contains the lower 512 bits of the counters, and `out_hi` contains the higher 512 bits, adjusted for any carry from the low words.


---
### fd\_blake3\_hash16\_avx512<!-- {{#callable:fd_blake3_hash16_avx512}} -->
Computes a 16-way BLAKE3 hash using AVX-512 instructions.
- **Inputs**:
    - `inputs`: An array of pointers to input byte arrays, each representing a block of data to be hashed.
    - `blocks`: The number of blocks of data to process.
    - `key`: An array of 8 32-bit unsigned integers representing the hash key.
    - `counter`: A 64-bit unsigned integer used to differentiate between different hash invocations.
    - `increment_counter`: A boolean flag indicating whether to increment the counter for each block.
    - `flags`: A byte representing flags that modify the hashing behavior.
    - `flags_start`: A byte representing additional flags to apply at the start of the hashing process.
    - `flags_end`: A byte representing additional flags to apply at the end of the hashing process.
    - `out`: A pointer to an output buffer where the resulting hash will be stored.
- **Control Flow**:
    - Initialize hash vectors `h_vecs` with the provided key values.
    - Load the counter values into `counter_low_vec` and `counter_high_vec` based on the `increment_counter` flag.
    - Set the initial block flags by combining the provided flags with `flags_start`.
    - Iterate over each block of input data, updating the block flags as necessary.
    - For each block, prepare the message vectors by transposing the input data.
    - Initialize the state vector `v` with hash vectors, initialization vectors, counter values, and block flags.
    - Perform multiple rounds of hashing by calling [`round_fn16`](#round_fn16) with the state vector and message vectors.
    - Update the hash vectors by XORing the state vector results.
    - After processing all blocks, transpose the hash vectors for output.
    - Store the final hash result into the output buffer.
- **Output**: The function outputs a 64-byte hash result stored in the provided output buffer.
- **Functions called**:
    - [`set1_512`](#set1_512)
    - [`load_counters16`](#load_counters16)
    - [`transpose_msg_vecs16`](#transpose_msg_vecs16)
    - [`round_fn16`](#round_fn16)
    - [`xor_512`](#xor_512)
    - [`transpose_vecs_512`](#transpose_vecs_512)


---
### hash\_one\_avx512<!-- {{#callable:hash_one_avx512}} -->
Hashes input data using the BLAKE3 compression function with AVX512 optimizations.
- **Inputs**:
    - `input`: Pointer to the input data to be hashed.
    - `blocks`: The number of blocks of data to process.
    - `key`: An array of 8 32-bit unsigned integers representing the hash key.
    - `counter`: A 64-bit unsigned integer used as a counter for the hashing process.
    - `flags`: Flags that modify the behavior of the hashing process.
    - `flags_start`: Flags to be applied at the start of the hashing process.
    - `flags_end`: Flags to be applied at the end of the hashing process.
    - `out`: An array where the resulting hash output will be stored.
- **Control Flow**:
    - Initializes a state vector `cv` by copying the `key` into it.
    - Combines the `flags` and `flags_start` into `block_flags`.
    - Enters a loop that continues until all blocks are processed.
    - If processing the last block, updates `block_flags` to include `flags_end`.
    - Calls [`fd_blake3_compress_in_place_avx512`](#fd_blake3_compress_in_place_avx512) to compress the current block of data.
    - Updates the input pointer to the next block and decrements the block count.
    - Resets `block_flags` to the original `flags` for the next iteration.
    - After processing all blocks, copies the final state vector `cv` to the output array.
- **Output**: The resulting hash value is stored in the `out` array, which has a length defined by `BLAKE3_OUT_LEN`.
- **Functions called**:
    - [`fd_blake3_compress_in_place_avx512`](#fd_blake3_compress_in_place_avx512)


---
### fd\_blake3\_hash\_many\_avx512<!-- {{#callable:fd_blake3_hash_many_avx512}} -->
Hashes multiple inputs using the BLAKE3 hashing algorithm with AVX512 optimizations.
- **Inputs**:
    - `inputs`: An array of pointers to the input byte arrays to be hashed.
    - `num_inputs`: The number of input arrays provided.
    - `blocks`: The number of blocks to process for each input.
    - `key`: An array of 8 32-bit unsigned integers representing the BLAKE3 key.
    - `counter`: A 64-bit unsigned integer used to differentiate the hashes.
    - `increment_counter`: A boolean flag indicating whether to increment the counter after each hash.
    - `flags`: Flags to modify the behavior of the hashing process.
    - `flags_start`: Flags to apply at the start of the hashing process.
    - `flags_end`: Flags to apply at the end of the hashing process.
    - `out`: A pointer to the output buffer where the resulting hashes will be stored.
- **Control Flow**:
    - The function processes the input arrays in batches of 16, 8, 4, or 1, depending on the number of remaining inputs.
    - For each batch, it calls the appropriate hashing function ([`fd_blake3_hash16_avx512`](#fd_blake3_hash16_avx512), [`fd_blake3_hash8_avx512`](#fd_blake3_hash8_avx512), [`fd_blake3_hash4_avx512`](#fd_blake3_hash4_avx512), or [`hash_one_avx512`](#hash_one_avx512)) to compute the hash.
    - If `increment_counter` is true, the counter is incremented by the number of hashes processed in the current batch.
    - The output pointer is updated to point to the next available space in the output buffer after each batch.
- **Output**: The function writes the computed hashes to the output buffer pointed to by `out`, with each hash being of length defined by `BLAKE3_OUT_LEN`.
- **Functions called**:
    - [`fd_blake3_hash16_avx512`](#fd_blake3_hash16_avx512)
    - [`fd_blake3_hash8_avx512`](#fd_blake3_hash8_avx512)
    - [`fd_blake3_hash4_avx512`](#fd_blake3_hash4_avx512)
    - [`hash_one_avx512`](#hash_one_avx512)



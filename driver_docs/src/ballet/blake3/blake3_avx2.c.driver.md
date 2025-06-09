# Purpose
This C source file is part of the BLAKE3 cryptographic hash function implementation, specifically optimized for AVX2 (Advanced Vector Extensions 2) instruction set. The file provides functions to perform hashing operations on multiple inputs simultaneously using SIMD (Single Instruction, Multiple Data) operations, which are facilitated by AVX2. The primary function, [`fd_blake3_hash_many_avx2`](#fd_blake3_hash_many_avx2), processes multiple input blocks in parallel, leveraging the AVX2 capabilities to enhance performance by handling eight inputs at a time (as defined by the `DEGREE` constant). This function is designed to be part of a larger library, as indicated by its inclusion of other functions like [`fd_blake3_hash_many_sse41`](#fd_blake3_hash_many_sse41) and [`fd_blake3_hash_many_portable`](#fd_blake3_hash_many_portable), which provide alternative implementations for different hardware capabilities.

The file defines several inline functions that perform essential operations such as loading, storing, adding, and rotating 256-bit vectors, which are crucial for the BLAKE3 compression function. The [`round_fn`](#round_fn) function implements the core transformation rounds of the BLAKE3 algorithm, applying a series of vectorized operations to the input data. The use of AVX2 instructions allows for efficient parallel processing of data, making this implementation suitable for high-performance applications. The file does not define a public API directly but provides internal functions that are likely used by higher-level functions in the BLAKE3 library to perform hashing operations.
# Imports and Dependencies

---
- `blake3_impl.h`
- `immintrin.h`


# Functions

---
### loadu<!-- {{#callable:loadu}} -->
The `loadu` function loads 32 bytes of unaligned data from a source array into a 256-bit AVX2 register.
- **Inputs**:
    - `src`: A pointer to an array of 32 bytes (uint8_t) from which data is to be loaded.
- **Control Flow**:
    - The function casts the input pointer `src` to a pointer of type `const __m256i *`.
    - It then uses the `_mm256_loadu_si256` intrinsic to load 32 bytes of data from the unaligned memory location pointed to by the casted pointer into a 256-bit AVX2 register.
- **Output**: The function returns a 256-bit AVX2 register (`__m256i`) containing the loaded data.


---
### storeu<!-- {{#callable:storeu}} -->
The `storeu` function stores a 256-bit integer from a source register into a destination memory location without alignment requirements.
- **Inputs**:
    - `src`: A 256-bit integer of type `__m256i` that is to be stored.
    - `dest`: A pointer to a 16-byte array of type `uint8_t` where the 256-bit integer will be stored.
- **Control Flow**:
    - The function uses the `_mm256_storeu_si256` intrinsic to store the 256-bit integer from the `src` register into the memory location pointed to by `dest`.
- **Output**: The function does not return a value; it performs an in-place store operation on the provided memory location.


---
### addv<!-- {{#callable:addv}} -->
The `addv` function performs a vectorized addition of two 256-bit integer vectors using AVX2 instructions.
- **Inputs**:
    - `a`: A 256-bit integer vector of type `__m256i`.
    - `b`: Another 256-bit integer vector of type `__m256i`.
- **Control Flow**:
    - The function takes two 256-bit integer vectors as input.
    - It uses the AVX2 intrinsic `_mm256_add_epi32` to perform element-wise addition of the two vectors.
- **Output**: The function returns a 256-bit integer vector of type `__m256i` that is the result of the element-wise addition of the input vectors.


---
### xorv<!-- {{#callable:xorv}} -->
The `xorv` function performs a bitwise XOR operation on two 256-bit integer vectors using AVX2 intrinsics.
- **Inputs**:
    - `a`: A 256-bit integer vector of type `__m256i`.
    - `b`: Another 256-bit integer vector of type `__m256i`.
- **Control Flow**:
    - The function takes two 256-bit integer vectors as input.
    - It applies the `_mm256_xor_si256` intrinsic to perform a bitwise XOR operation on the two input vectors.
    - The result of the XOR operation is returned.
- **Output**: A 256-bit integer vector of type `__m256i` that is the result of the bitwise XOR operation on the input vectors.


---
### set1<!-- {{#callable:set1}} -->
The `set1` function initializes a 256-bit AVX2 vector with eight copies of a given 32-bit integer.
- **Inputs**:
    - `x`: A 32-bit unsigned integer to be replicated across all elements of the AVX2 vector.
- **Control Flow**:
    - The function takes a 32-bit unsigned integer `x` as input.
    - It casts `x` to a 32-bit signed integer.
    - It calls the AVX2 intrinsic `_mm256_set1_epi32` to create a 256-bit vector with all elements set to the casted value.
- **Output**: A 256-bit AVX2 vector (`__m256i`) with all elements set to the input integer `x`.


---
### rot16<!-- {{#callable:rot16}} -->
The `rot16` function performs a byte-wise shuffle on a 256-bit integer vector to rotate its elements by 16 bits.
- **Inputs**:
    - `x`: A 256-bit integer vector (__m256i) to be rotated.
- **Control Flow**:
    - The function takes a 256-bit integer vector `x` as input.
    - It uses the `_mm256_shuffle_epi8` intrinsic to shuffle the bytes of `x` according to a specified pattern.
    - The pattern is defined by `_mm256_set_epi8`, which rearranges the bytes to achieve a 16-bit rotation.
- **Output**: A 256-bit integer vector (__m256i) with its elements rotated by 16 bits.


---
### rot12<!-- {{#callable:rot12}} -->
The `rot12` function performs a 12-bit rotation on each 32-bit lane of a 256-bit AVX2 vector.
- **Inputs**:
    - `x`: A 256-bit AVX2 vector of type `__m256i` containing multiple 32-bit integers to be rotated.
- **Control Flow**:
    - The function takes a 256-bit vector `x` as input.
    - It performs a logical right shift by 12 bits on each 32-bit lane of the vector using `_mm256_srli_epi32`.
    - It performs a logical left shift by 20 bits (32 - 12) on each 32-bit lane of the vector using `_mm256_slli_epi32`.
    - The results of the right and left shifts are combined using a bitwise OR operation with `_mm256_or_si256`.
- **Output**: A 256-bit AVX2 vector of type `__m256i` with each 32-bit lane rotated 12 bits to the right.


---
### rot8<!-- {{#callable:rot8}} -->
The `rot8` function performs an 8-bit rotation on a 256-bit integer using AVX2 intrinsics.
- **Inputs**:
    - `x`: A 256-bit integer of type `__m256i` that is to be rotated.
- **Control Flow**:
    - The function uses the `_mm256_shuffle_epi8` intrinsic to rearrange the bytes of the input `x` according to a specified shuffle pattern.
    - The shuffle pattern is defined by `_mm256_set_epi8`, which specifies the new order of bytes to achieve an 8-bit rotation.
- **Output**: A 256-bit integer of type `__m256i` that is the result of the 8-bit rotation of the input.


---
### rot7<!-- {{#callable:rot7}} -->
The `rot7` function performs a bitwise rotation of each 32-bit integer in a 256-bit AVX2 vector by 7 bits to the right.
- **Inputs**:
    - `x`: A 256-bit AVX2 vector (__m256i) containing eight 32-bit integers to be rotated.
- **Control Flow**:
    - The function takes a 256-bit vector `x` as input.
    - It uses the `_mm256_srli_epi32` intrinsic to shift each 32-bit integer in `x` right by 7 bits.
    - It uses the `_mm256_slli_epi32` intrinsic to shift each 32-bit integer in `x` left by 25 bits (32 - 7).
    - The function combines the results of the right and left shifts using the `_mm256_or_si256` intrinsic to achieve a circular rotation.
- **Output**: A 256-bit AVX2 vector (__m256i) with each 32-bit integer rotated 7 bits to the right.


---
### round\_fn<!-- {{#callable:round_fn}} -->
The `round_fn` function performs a series of vectorized arithmetic and bitwise operations on two arrays of 256-bit integers, `v` and `m`, based on a predefined message schedule for a given round `r`.
- **Inputs**:
    - `v`: An array of 16 __m256i vectors representing the current state of the hash function.
    - `m`: An array of 16 __m256i vectors representing the message block to be processed.
    - `r`: A size_t value representing the current round index used to access the message schedule.
- **Control Flow**:
    - The function begins by adding elements from the message array `m` to the state array `v` using indices from the `MSG_SCHEDULE` for the current round `r`.
    - It then performs a series of additions between elements of `v` and updates the state with XOR operations followed by rotations of 16 bits.
    - The function continues with further additions, XOR operations, and rotations of 12 bits, 8 bits, and 7 bits, modifying the state array `v` in each step.
    - This sequence of operations is repeated for different indices of the message schedule, effectively mixing the state and message data.
- **Output**: The function modifies the `v` array in place, updating its state based on the operations performed.
- **Functions called**:
    - [`addv`](#addv)
    - [`xorv`](#xorv)
    - [`rot16`](#rot16)
    - [`rot12`](#rot12)
    - [`rot8`](#rot8)
    - [`rot7`](#rot7)


---
### transpose\_vecs<!-- {{#callable:transpose_vecs}} -->
The `transpose_vecs` function rearranges the elements of an array of eight 256-bit vectors to transpose their data layout using AVX2 intrinsics.
- **Inputs**:
    - `vecs`: An array of eight 256-bit vectors (`__m256i`) that will be transposed.
- **Control Flow**:
    - Interleave 32-bit lanes of the input vectors to create intermediate vectors with specific lane arrangements.
    - Interleave 64-bit lanes of the intermediate vectors to further rearrange the data.
    - Interleave 128-bit lanes of the resulting vectors to complete the transposition, updating the original input vectors with the transposed data.
- **Output**: The function modifies the input array `vecs` in place, transposing its data layout.


---
### transpose\_msg\_vecs<!-- {{#callable:transpose_msg_vecs}} -->
The `transpose_msg_vecs` function loads and transposes message vectors from input data into AVX2 registers for further processing.
- **Inputs**:
    - `inputs`: A pointer to an array of 8 pointers, each pointing to a block of input data of type `uint8_t`.
    - `block_offset`: The offset in bytes from the start of each input block to the data to be loaded and transposed.
    - `out`: An array of 16 `__m256i` AVX2 registers where the transposed message vectors will be stored.
- **Control Flow**:
    - Load 8 `__m256i` vectors from the input data at the specified block offset into the first 8 elements of the `out` array.
    - Load another 8 `__m256i` vectors from the input data at the next block offset into the next 8 elements of the `out` array.
    - Prefetch the next block of data for each input to optimize memory access.
    - Call [`transpose_vecs`](#transpose_vecs) on the first 8 elements of `out` to transpose them.
    - Call [`transpose_vecs`](#transpose_vecs) on the next 8 elements of `out` to transpose them.
- **Output**: The function does not return a value; it modifies the `out` array in place to contain the transposed message vectors.
- **Functions called**:
    - [`loadu`](#loadu)
    - [`transpose_vecs`](#transpose_vecs)


---
### load\_counters<!-- {{#callable:load_counters}} -->
The `load_counters` function initializes two 256-bit vectors with counter values, optionally incrementing them, and stores the results in the provided output pointers.
- **Inputs**:
    - `counter`: A 64-bit unsigned integer representing the initial counter value.
    - `increment_counter`: A boolean flag indicating whether to increment the counter values.
    - `out_lo`: A pointer to a 256-bit vector where the lower part of the counter values will be stored.
    - `out_hi`: A pointer to a 256-bit vector where the higher part of the counter values will be stored.
- **Control Flow**:
    - Create a 256-bit mask vector based on the `increment_counter` flag, where all elements are either 0 or -1.
    - Define a 256-bit vector `add0` with elements from 0 to 7, representing the increment values for each lane.
    - Compute `add1` by bitwise ANDing `mask` with `add0`, resulting in either the original `add0` or a zero vector based on `increment_counter`.
    - Calculate the lower part of the counter vector `l` by adding `add1` to a vector filled with the lower 32 bits of `counter`.
    - Determine the carry vector by comparing the adjusted `add1` and `l` vectors using a signed comparison with a bias of 0x80000000.
    - Compute the higher part of the counter vector `h` by subtracting the carry vector from a vector filled with the higher 32 bits of `counter`.
    - Store the results in the provided `out_lo` and `out_hi` pointers.
- **Output**: The function outputs two 256-bit vectors, `out_lo` and `out_hi`, representing the lower and higher parts of the counter values, respectively.


---
### fd\_blake3\_hash8\_avx2<!-- {{#callable:fd_blake3_hash8_avx2}} -->
The `fd_blake3_hash8_avx2` function computes the BLAKE3 hash for multiple blocks of input data using AVX2 vector instructions.
- **Inputs**:
    - `inputs`: A pointer to an array of pointers, each pointing to a block of input data to be hashed.
    - `blocks`: The number of blocks to process.
    - `key`: An array of 8 uint32_t values used as the key for the hash function.
    - `counter`: A 64-bit counter value used in the hash computation.
    - `increment_counter`: A boolean flag indicating whether the counter should be incremented for each block.
    - `flags`: A uint8_t value representing flags used in the hash computation.
    - `flags_start`: A uint8_t value representing flags to be applied at the start of the hash computation.
    - `flags_end`: A uint8_t value representing flags to be applied at the end of the hash computation.
    - `out`: A pointer to the output buffer where the resulting hash will be stored.
- **Control Flow**:
    - Initialize 8 vector registers `h_vecs` with the key values using [`set1`](#set1) function.
    - Load the counter values into `counter_low_vec` and `counter_high_vec` using [`load_counters`](#load_counters).
    - Set `block_flags` by combining `flags` and `flags_start`.
    - Iterate over each block, updating `block_flags` with `flags_end` for the last block.
    - For each block, set up the message vectors using [`transpose_msg_vecs`](#transpose_msg_vecs).
    - Initialize the vector `v` with `h_vecs`, IV constants, counter vectors, block length, and block flags.
    - Perform 7 rounds of the BLAKE3 compression function using [`round_fn`](#round_fn).
    - Update `h_vecs` by XORing the first 8 elements of `v` with the last 8 elements.
    - Reset `block_flags` to `flags` for the next iteration.
    - Transpose the `h_vecs` and store the result in the output buffer `out`.
- **Output**: The function outputs the computed BLAKE3 hash into the `out` buffer, with each of the 8 `h_vecs` stored sequentially.
- **Functions called**:
    - [`set1`](#set1)
    - [`load_counters`](#load_counters)
    - [`transpose_msg_vecs`](#transpose_msg_vecs)
    - [`round_fn`](#round_fn)
    - [`xorv`](#xorv)
    - [`transpose_vecs`](#transpose_vecs)
    - [`storeu`](#storeu)


---
### fd\_blake3\_hash\_many\_avx2<!-- {{#callable:fd_blake3_hash_many_avx2}} -->
The `fd_blake3_hash_many_avx2` function processes multiple input blocks using the BLAKE3 hash algorithm with AVX2 optimizations, handling a specified number of inputs and adjusting the counter as needed.
- **Inputs**:
    - `inputs`: A pointer to an array of pointers, each pointing to a block of input data to be hashed.
    - `num_inputs`: The number of input blocks to be processed.
    - `blocks`: The number of blocks in each input to be processed.
    - `key`: A 256-bit key used for hashing, represented as an array of 8 uint32_t values.
    - `counter`: A 64-bit counter value used in the hashing process.
    - `increment_counter`: A boolean flag indicating whether the counter should be incremented after processing each set of blocks.
    - `flags`: A uint8_t value representing flags used in the hashing process.
    - `flags_start`: A uint8_t value representing the starting flags for the first block.
    - `flags_end`: A uint8_t value representing the ending flags for the last block.
    - `out`: A pointer to the output buffer where the hash results will be stored.
- **Control Flow**:
    - The function enters a loop that continues as long as `num_inputs` is greater than or equal to `DEGREE` (8).
    - Within the loop, it calls [`fd_blake3_hash8_avx2`](#fd_blake3_hash8_avx2) to process 8 inputs at a time using AVX2 instructions.
    - If `increment_counter` is true, the counter is incremented by `DEGREE` after processing each set of inputs.
    - The input pointer is advanced by `DEGREE` to process the next set of inputs, and `num_inputs` is decremented by `DEGREE`.
    - The output pointer is advanced by `DEGREE * BLAKE3_OUT_LEN` to store the next set of hash results.
    - After the loop, if there are remaining inputs (less than `DEGREE`), it calls either [`fd_blake3_hash_many_sse41`](blake3_sse41.c.driver.md#fd_blake3_hash_many_sse41) or [`fd_blake3_hash_many_portable`](blake3_portable.c.driver.md#fd_blake3_hash_many_portable) depending on the availability of AVX support.
- **Output**: The function outputs the hash results of the input data into the buffer pointed to by `out`, with each input block producing a hash of length `BLAKE3_OUT_LEN`.
- **Functions called**:
    - [`fd_blake3_hash8_avx2`](#fd_blake3_hash8_avx2)
    - [`fd_blake3_hash_many_sse41`](blake3_sse41.c.driver.md#fd_blake3_hash_many_sse41)
    - [`fd_blake3_hash_many_portable`](blake3_portable.c.driver.md#fd_blake3_hash_many_portable)


# Function Declarations (Public API)

---
### fd\_blake3\_hash\_many\_sse41<!-- {{#callable_declaration:fd_blake3_hash_many_sse41}} -->
Computes BLAKE3 hashes for multiple inputs using SSE4.1 instructions.
- **Description**: This function computes the BLAKE3 hash for a set of input data blocks using SSE4.1 instructions for optimization. It is designed to process multiple inputs in parallel, leveraging SIMD capabilities for improved performance. The function requires a key, a counter, and various flags to control the hashing process. It is suitable for use in environments where SSE4.1 is supported and can handle a large number of inputs efficiently. The caller must ensure that the inputs and output buffers are properly allocated and that the key is correctly initialized before calling this function.
- **Inputs**:
    - `inputs`: A pointer to an array of pointers, each pointing to a block of input data to be hashed. The input data must be properly aligned and allocated. The caller retains ownership and must ensure the validity of these pointers.
    - `num_inputs`: The number of input blocks to be hashed. Must be greater than zero. If zero, the function does nothing.
    - `blocks`: The number of blocks in each input to be processed. Must be a positive integer.
    - `key`: An array of 8 uint32_t values representing the key used for hashing. Must be properly initialized before calling the function.
    - `counter`: A 64-bit counter value used in the hashing process. It can be incremented based on the increment_counter flag.
    - `increment_counter`: A boolean flag indicating whether the counter should be incremented after processing each input.
    - `flags`: A uint8_t value representing additional flags for the hashing process. These flags modify the behavior of the hash function.
    - `flags_start`: A uint8_t value representing flags to be applied at the start of the hashing process.
    - `flags_end`: A uint8_t value representing flags to be applied at the end of the hashing process.
    - `out`: A pointer to a buffer where the resulting hash values will be stored. The buffer must be large enough to hold the output for all inputs. The caller is responsible for allocating and managing this buffer.
- **Output**: None
- **See also**: [`fd_blake3_hash_many_sse41`](blake3_sse41.c.driver.md#fd_blake3_hash_many_sse41)  (Implementation)


---
### fd\_blake3\_hash\_many\_portable<!-- {{#callable_declaration:fd_blake3_hash_many_portable}} -->
Hashes multiple input data blocks using the BLAKE3 algorithm.
- **Description**: This function computes the BLAKE3 hash for multiple input data blocks, processing each input sequentially. It is designed to handle a specified number of input blocks, using a provided key and counter. The function allows for optional counter incrementation after each input is processed. It also supports setting specific flags for the start and end of the hashing process. The function must be called with valid input pointers and a pre-allocated output buffer to store the resulting hashes.
- **Inputs**:
    - `inputs`: A pointer to an array of pointers, each pointing to a block of input data to be hashed. Must not be null.
    - `num_inputs`: The number of input blocks to process. Must be greater than zero.
    - `blocks`: The number of blocks in each input to be processed. Must be greater than zero.
    - `key`: An array of 8 uint32_t values representing the key for the hash function. Must not be null.
    - `counter`: A 64-bit counter value used in the hashing process. Can be any uint64_t value.
    - `increment_counter`: A boolean flag indicating whether the counter should be incremented after processing each input.
    - `flags`: A uint8_t value representing flags to be used during the hashing process. Can be any uint8_t value.
    - `flags_start`: A uint8_t value representing flags to be applied at the start of the hashing process. Can be any uint8_t value.
    - `flags_end`: A uint8_t value representing flags to be applied at the end of the hashing process. Can be any uint8_t value.
    - `out`: A pointer to a buffer where the output hash will be stored. Must be pre-allocated and large enough to hold the hash results for all inputs.
- **Output**: None
- **See also**: [`fd_blake3_hash_many_portable`](blake3_portable.c.driver.md#fd_blake3_hash_many_portable)  (Implementation)



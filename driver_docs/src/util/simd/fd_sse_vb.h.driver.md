# Purpose
This C source code file is a specialized utility for handling SIMD (Single Instruction, Multiple Data) operations using SSE (Streaming SIMD Extensions) intrinsics, specifically targeting operations on vectors of 8-bit unsigned integers (uchars). The file defines a set of macros and inline functions that facilitate the creation, manipulation, and computation of 128-bit vectors, where each vector is composed of 16 lanes, each holding an 8-bit unsigned integer. The code provides a comprehensive suite of operations, including vector construction, memory operations, arithmetic and bitwise operations, logical and conditional operations, and conversion and reduction operations. These operations are designed to leverage the parallel processing capabilities of SSE to perform efficient data processing tasks.

The file is intended to be included indirectly through a header file named `fd_sse.h`, as indicated by the preprocessor directive at the beginning. This suggests that the code is part of a larger library or framework that provides SIMD utilities. The macros and functions defined in this file are designed to be robust and efficient, using intrinsics like `_mm_setr_epi8`, `_mm_shuffle_epi8`, and `_mm_load_si128` to directly map to SSE instructions. The use of macros over static inline functions is preferred where possible to minimize the risk of compiler optimizations interfering with the intended behavior. The file does not define a public API or external interfaces directly but provides foundational components that can be used to build higher-level SIMD operations in applications requiring high-performance data processing.
# Functions

---
### vb\_bcast\_pair<!-- {{#callable:vb_bcast_pair}} -->
The `vb_bcast_pair` function creates a 128-bit SIMD vector with alternating copies of two given unsigned 8-bit integers.
- **Inputs**:
    - `b0`: An unsigned 8-bit integer (uchar) to be broadcasted into the vector.
    - `b1`: Another unsigned 8-bit integer (uchar) to be broadcasted into the vector.
- **Control Flow**:
    - The function takes two unsigned 8-bit integers, `b0` and `b1`, as input.
    - It uses the `_mm_setr_epi8` intrinsic to create a 128-bit SIMD vector.
    - The vector is filled with alternating values of `b0` and `b1`, repeated eight times to fill all 16 lanes of the vector.
- **Output**: A 128-bit SIMD vector (`vb_t`) containing the pattern [b0, b1, b0, b1, ..., b0, b1].


---
### vb\_bcast\_quad<!-- {{#callable:vb_bcast_quad}} -->
The `vb_bcast_quad` function creates a 128-bit SIMD vector by repeating a sequence of four unsigned 8-bit integers four times.
- **Inputs**:
    - `b0`: The first unsigned 8-bit integer to be included in the vector.
    - `b1`: The second unsigned 8-bit integer to be included in the vector.
    - `b2`: The third unsigned 8-bit integer to be included in the vector.
    - `b3`: The fourth unsigned 8-bit integer to be included in the vector.
- **Control Flow**:
    - The function takes four unsigned 8-bit integers as input parameters.
    - It casts each of these integers to a signed 8-bit integer (char).
    - It uses the `_mm_setr_epi8` intrinsic to create a 128-bit SIMD vector.
    - The vector is constructed by repeating the sequence of the four input integers four times, resulting in a total of 16 elements in the vector.
- **Output**: A 128-bit SIMD vector (`vb_t`) containing the repeated sequence of the four input integers.


---
### vb\_bcast\_oct<!-- {{#callable:vb_bcast_oct}} -->
The `vb_bcast_oct` function creates a 128-bit SIMD vector with two repetitions of eight 8-bit unsigned integers.
- **Inputs**:
    - `b0`: The first 8-bit unsigned integer to be included in the vector.
    - `b1`: The second 8-bit unsigned integer to be included in the vector.
    - `b2`: The third 8-bit unsigned integer to be included in the vector.
    - `b3`: The fourth 8-bit unsigned integer to be included in the vector.
    - `b4`: The fifth 8-bit unsigned integer to be included in the vector.
    - `b5`: The sixth 8-bit unsigned integer to be included in the vector.
    - `b6`: The seventh 8-bit unsigned integer to be included in the vector.
    - `b7`: The eighth 8-bit unsigned integer to be included in the vector.
- **Control Flow**:
    - The function takes eight 8-bit unsigned integers as input parameters.
    - Each input integer is cast to a signed 8-bit integer (char) and passed to the `_mm_setr_epi8` intrinsic.
    - The `_mm_setr_epi8` intrinsic is used to create a 128-bit SIMD vector with the first eight elements set to the input integers in order, followed by the same eight integers repeated in the same order.
- **Output**: The function returns a `vb_t` type, which is a 128-bit SIMD vector containing two repetitions of the input integers.


---
### vb\_expand\_pair<!-- {{#callable:vb_expand_pair}} -->
The `vb_expand_pair` function creates a 128-bit SIMD vector with the first half filled with repeated instances of the first input byte and the second half filled with repeated instances of the second input byte.
- **Inputs**:
    - `b0`: An unsigned 8-bit integer (uchar) that will be repeated in the first half of the vector.
    - `b1`: An unsigned 8-bit integer (uchar) that will be repeated in the second half of the vector.
- **Control Flow**:
    - The function takes two unsigned 8-bit integers, `b0` and `b1`, as inputs.
    - It uses the `_mm_setr_epi8` intrinsic to create a 128-bit SIMD vector.
    - The first eight elements of the vector are set to `b0`, and the last eight elements are set to `b1`.
- **Output**: A 128-bit SIMD vector (`vb_t`) with the first half filled with `b0` and the second half filled with `b1`.


---
### vb\_expand\_quad<!-- {{#callable:vb_expand_quad}} -->
The `vb_expand_quad` function creates a 128-bit SIMD vector with each of the four input bytes repeated four times in sequence.
- **Inputs**:
    - `b0`: An unsigned 8-bit integer (uchar) representing the first byte to be expanded.
    - `b1`: An unsigned 8-bit integer (uchar) representing the second byte to be expanded.
    - `b2`: An unsigned 8-bit integer (uchar) representing the third byte to be expanded.
    - `b3`: An unsigned 8-bit integer (uchar) representing the fourth byte to be expanded.
- **Control Flow**:
    - The function takes four unsigned 8-bit integers as input parameters.
    - Each input byte is cast to a signed 8-bit integer (char) and repeated four times in sequence.
    - The `_mm_setr_epi8` intrinsic is used to create a 128-bit SIMD vector with the specified pattern of bytes.
- **Output**: A 128-bit SIMD vector (`vb_t`) where each of the input bytes is repeated four times in sequence, resulting in a pattern of [b0, b0, b0, b0, b1, b1, b1, b1, b2, b2, b2, b2, b3, b3, b3, b3].


---
### vb\_expand\_oct<!-- {{#callable:vb_expand_oct}} -->
The `vb_expand_oct` function creates a 128-bit SIMD vector with each input byte duplicated consecutively.
- **Inputs**:
    - `b0`: The first unsigned 8-bit integer (uchar) to be expanded and duplicated.
    - `b1`: The second unsigned 8-bit integer (uchar) to be expanded and duplicated.
    - `b2`: The third unsigned 8-bit integer (uchar) to be expanded and duplicated.
    - `b3`: The fourth unsigned 8-bit integer (uchar) to be expanded and duplicated.
    - `b4`: The fifth unsigned 8-bit integer (uchar) to be expanded and duplicated.
    - `b5`: The sixth unsigned 8-bit integer (uchar) to be expanded and duplicated.
    - `b6`: The seventh unsigned 8-bit integer (uchar) to be expanded and duplicated.
    - `b7`: The eighth unsigned 8-bit integer (uchar) to be expanded and duplicated.
- **Control Flow**:
    - The function takes eight unsigned 8-bit integers as input parameters.
    - Each input byte is cast to a signed 8-bit integer (char) and duplicated in the resulting vector.
    - The `_mm_setr_epi8` intrinsic is used to create a 128-bit SIMD vector with the specified pattern of duplicated bytes.
- **Output**: A 128-bit SIMD vector (`vb_t`) where each input byte is duplicated consecutively, resulting in a pattern like [b0, b0, b1, b1, ..., b7, b7].


---
### vb\_ld<!-- {{#callable:vb_ld}} -->
The `vb_ld` function loads 16 unsigned 8-bit integers from a 16-byte aligned memory location into a SIMD vector.
- **Inputs**:
    - `p`: A pointer to a 16-byte aligned memory location containing 16 unsigned 8-bit integers (uchar).
- **Control Flow**:
    - The function casts the input pointer `p` to a pointer of type `__m128i const *`.
    - It then uses the `_mm_load_si128` intrinsic to load the 16 bytes from the memory location pointed to by `p` into a SIMD vector of type `vb_t` (which is defined as `__m128i`).
- **Output**: A SIMD vector (`vb_t`) containing the 16 unsigned 8-bit integers loaded from the memory location pointed to by `p`.


---
### vb\_st<!-- {{#callable:vb_st}} -->
The `vb_st` function stores a 128-bit vector of unsigned 8-bit integers into a 16-byte aligned memory location.
- **Inputs**:
    - `p`: A pointer to a 16-byte aligned memory location where the vector will be stored.
    - `i`: A 128-bit vector of unsigned 8-bit integers (type `vb_t`) to be stored at the memory location pointed to by `p`.
- **Control Flow**:
    - The function uses the `_mm_store_si128` intrinsic to store the 128-bit vector `i` into the memory location pointed to by `p`.
- **Output**: The function does not return any value; it performs a side effect by writing to the memory location pointed to by `p`.


---
### vb\_ldu<!-- {{#callable:vb_ldu}} -->
The `vb_ldu` function loads a 16-byte vector of unsigned 8-bit integers from an unaligned memory address into a SIMD register.
- **Inputs**:
    - `p`: A pointer to a memory location from which a 16-byte vector of unsigned 8-bit integers will be loaded.
- **Control Flow**:
    - The function casts the input pointer `p` to a pointer of type `__m128i const *`.
    - It then uses the `_mm_loadu_si128` intrinsic to load the 16-byte data from the unaligned memory location pointed to by `p` into a SIMD register.
- **Output**: A `vb_t` type, which is a `__m128i` vector containing the loaded 16 unsigned 8-bit integers.


---
### vb\_stu<!-- {{#callable:vb_stu}} -->
The `vb_stu` function stores a 128-bit vector of unsigned 8-bit integers to a potentially unaligned memory location.
- **Inputs**:
    - `p`: A pointer to the memory location where the vector will be stored; it does not need to be aligned.
    - `i`: A 128-bit vector of unsigned 8-bit integers (`vb_t`) to be stored at the memory location pointed to by `p`.
- **Control Flow**:
    - The function uses the `_mm_storeu_si128` intrinsic to store the 128-bit vector `i` at the memory location pointed to by `p`.
- **Output**: The function does not return a value; it performs a side effect by writing to the memory location pointed to by `p`.


---
### vb\_extract\_variable<!-- {{#callable:vb_extract_variable}} -->
The `vb_extract_variable` function extracts a specific unsigned 8-bit integer from a 128-bit SIMD vector at a given index.
- **Inputs**:
    - `a`: A 128-bit SIMD vector (`vb_t`) containing 16 unsigned 8-bit integers.
    - `n`: An integer representing the index (0 to 15) of the element to extract from the vector.
- **Control Flow**:
    - A union is defined to allow type punning between a 128-bit SIMD vector and an array of 16 unsigned 8-bit integers.
    - The SIMD vector `a` is stored into the union's `m` member, which is an array of `__m128i`.
    - The function returns the `n`-th element from the union's `i` member, which is an array of 16 `uchar`.
- **Output**: The function returns the `n`-th unsigned 8-bit integer from the SIMD vector `a`.


---
### vb\_insert\_variable<!-- {{#callable:vb_insert_variable}} -->
The `vb_insert_variable` function inserts a given unsigned 8-bit integer into a specified position within a 128-bit vector of unsigned 8-bit integers and returns the modified vector.
- **Inputs**:
    - `a`: A 128-bit vector (`vb_t`) containing 16 unsigned 8-bit integers.
    - `n`: An integer specifying the position (0 to 15) in the vector where the new value should be inserted.
    - `v`: An unsigned 8-bit integer (`uchar`) to be inserted into the vector at the specified position.
- **Control Flow**:
    - A union is defined to allow type punning between a 128-bit vector and an array of 16 unsigned 8-bit integers.
    - The input vector `a` is stored into the union's 128-bit vector member using `_mm_store_si128`.
    - The specified position `n` in the union's array member is updated with the new value `v`.
    - The modified vector is loaded back from the union's 128-bit vector member using `_mm_load_si128` and returned.
- **Output**: A 128-bit vector (`vb_t`) with the specified position updated to the new value, while the rest of the vector remains unchanged.


---
### vb\_rol<!-- {{#callable:vb_rol}} -->
The `vb_rol` function performs a bitwise left rotation on each byte of a 128-bit vector by a specified number of bits.
- **Inputs**:
    - `a`: A 128-bit vector (`vb_t`) where each lane holds an unsigned 8-bit integer.
    - `imm`: An integer specifying the number of bits to rotate each byte in the vector to the left; only the lower 3 bits are used, effectively limiting the rotation to 0-7 bits.
- **Control Flow**:
    - The function calculates the left shift of the vector `a` by `imm & 7` bits using `vb_shl`.
    - It calculates the right shift of the vector `a` by `(-imm) & 7` bits using `vb_shr`.
    - The results of the left and right shifts are combined using a bitwise OR operation with `vb_or`.
- **Output**: A 128-bit vector (`vb_t`) where each byte has been rotated left by the specified number of bits.


---
### vb\_ror<!-- {{#callable:vb_ror}} -->
The `vb_ror` function performs a bitwise right rotation on each byte of a 128-bit vector by a specified number of bits.
- **Inputs**:
    - `a`: A 128-bit vector (`vb_t`) where each lane holds an unsigned 8-bit integer.
    - `imm`: An integer specifying the number of bits to rotate each byte to the right; only the lower 3 bits are used, so the value is effectively modulo 8.
- **Control Flow**:
    - The function calculates `imm & 7` to ensure the rotation amount is within 0 to 7 bits.
    - It performs a right shift on the vector `a` by the calculated number of bits using `vb_shr`.
    - It performs a left shift on the vector `a` by the complement of the calculated number of bits using `vb_shl`.
    - The results of the right and left shifts are combined using a bitwise OR operation via `vb_or`.
    - The combined result is returned as the output of the function.
- **Output**: A 128-bit vector (`vb_t`) where each byte has been right-rotated by the specified number of bits.


---
### vb\_rol\_variable<!-- {{#callable:vb_rol_variable}} -->
The `vb_rol_variable` function performs a variable bitwise left rotation on each byte of a 128-bit vector of unsigned 8-bit integers.
- **Inputs**:
    - `a`: A 128-bit vector (`vb_t`) where each lane holds an unsigned 8-bit integer.
    - `n`: An integer specifying the number of bits to rotate each byte in the vector to the left.
- **Control Flow**:
    - The function calculates `n & 7` to determine the effective number of bits to rotate, as only the lower 3 bits are relevant for an 8-bit rotation.
    - It performs a left shift on the vector `a` by `n & 7` bits using `vb_shl_variable`.
    - It performs a right shift on the vector `a` by `(-n) & 7` bits using `vb_shr_variable`.
    - The results of the left and right shifts are combined using a bitwise OR operation with `vb_or` to complete the rotation.
- **Output**: A 128-bit vector (`vb_t`) with each byte rotated left by the specified number of bits.


---
### vb\_ror\_variable<!-- {{#callable:vb_ror_variable}} -->
The `vb_ror_variable` function performs a variable right rotation on a vector of 8-bit unsigned integers.
- **Inputs**:
    - `a`: A vector of 8-bit unsigned integers (`vb_t`) to be rotated.
    - `n`: An integer specifying the number of positions to rotate the vector to the right.
- **Control Flow**:
    - The function calculates `n & 7` to ensure the rotation amount is within the range of 0 to 7 bits.
    - It calls `vb_shr_variable` to perform a right shift on the vector `a` by `n & 7` bits.
    - It calls `vb_shl_variable` to perform a left shift on the vector `a` by `(-n) & 7` bits.
    - The results of the two shifts are combined using `vb_or` to produce the final rotated vector.
- **Output**: The function returns a vector of 8-bit unsigned integers (`vb_t`) that is the result of the right rotation of the input vector `a` by `n` positions.


---
### vb\_sum\_all<!-- {{#callable:vb_sum_all}} -->
The `vb_sum_all` function computes the sum of all elements in a 128-bit vector of unsigned 8-bit integers and returns a vector where each element is the broadcasted sum.
- **Inputs**:
    - `x`: A 128-bit vector (`vb_t`) containing 16 unsigned 8-bit integers.
- **Control Flow**:
    - The function first uses `_mm_sad_epu8` to compute the sum of the lower and upper halves of the vector `x`, resulting in two 64-bit sums.
    - It then uses `_mm_shuffle_epi8` to extract and broadcast the low byte of each 64-bit sum.
    - Finally, it adds these two broadcasted values using `_mm_add_epi8` to produce the final result, which is a vector where each element is the sum of all elements in the original vector `x`.
- **Output**: A 128-bit vector (`vb_t`) where each element is the sum of all elements in the input vector `x`, broadcasted across all lanes.


---
### vb\_min\_all<!-- {{#callable:vb_min_all}} -->
The `vb_min_all` function computes the minimum value across all elements of a 128-bit vector of unsigned 8-bit integers and broadcasts this minimum value across all elements of the vector.
- **Inputs**:
    - `x`: A 128-bit vector (`vb_t`) containing 16 unsigned 8-bit integers.
- **Control Flow**:
    - The function first compares the vector `x` with a shuffled version of itself, where the second half of the vector is moved to the first half, and vice versa, using `_mm_min_epu8` to find the minimum of each pair of elements.
    - It then repeats a similar process with different shuffling patterns to progressively reduce the vector to a single minimum value by comparing and minimizing across different segments of the vector.
    - The shuffling and minimizing operations are repeated multiple times with different patterns to ensure that the minimum value is found across all elements.
    - Finally, the function returns the vector `x` where all elements are set to the minimum value found.
- **Output**: A 128-bit vector (`vb_t`) where all 16 elements are set to the minimum value found in the input vector `x`.
- **Functions called**:
    - [`vb_bcast_quad`](#vb_bcast_quad)
    - [`vb_bcast_pair`](#vb_bcast_pair)


---
### vb\_max\_all<!-- {{#callable:vb_max_all}} -->
The `vb_max_all` function computes the maximum value across all lanes of a 128-bit vector of unsigned 8-bit integers and broadcasts this maximum value to all lanes of the vector.
- **Inputs**:
    - `x`: A 128-bit vector (`vb_t`) containing 16 unsigned 8-bit integers.
- **Control Flow**:
    - The function begins by comparing the vector `x` with a shuffled version of itself, where the second half of the vector is moved to the first half, and vice versa, using `_mm_max_epu8` to keep the maximum values in each lane.
    - This process is repeated with different shuffle patterns to progressively reduce the vector to a single maximum value, first comparing groups of 8, then 4, then 2, and finally all lanes.
    - The final result is a vector where all lanes contain the maximum value found in the original vector `x`.
- **Output**: A 128-bit vector (`vb_t`) where each lane contains the maximum value found in the input vector `x`.
- **Functions called**:
    - [`vb_bcast_quad`](#vb_bcast_quad)
    - [`vb_bcast_pair`](#vb_bcast_pair)



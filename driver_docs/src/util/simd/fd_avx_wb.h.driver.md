# Purpose
This C header file provides a set of macros and inline functions for working with 256-bit wide SIMD (Single Instruction, Multiple Data) operations using the AVX (Advanced Vector Extensions) instruction set. The file is designed to handle vectors of unsigned 8-bit integers (uchars) and offers a comprehensive suite of operations for constructing, manipulating, and performing arithmetic and logical operations on these vectors. The primary data type used is `__m256i`, which represents a 256-bit integer vector, and the file defines a type alias `wb_t` for this purpose. The file includes a variety of operations such as vector construction, broadcasting, permutation, arithmetic, bitwise, logical, and conditional operations, as well as memory operations for loading and storing vectors. Additionally, it provides conversion functions to transform vector elements into different data types and reduction operations to compute aggregate values like sum, minimum, and maximum across vector elements.

The file is intended to be included indirectly through another header (`fd_avx.h`), as indicated by the preprocessor directive at the beginning. This suggests that it is part of a larger library or framework for SIMD operations. The use of macros and inline functions is emphasized to ensure efficient execution by minimizing function call overhead and allowing the compiler to optimize the code effectively. The file does not define public APIs or external interfaces directly but rather provides low-level building blocks for SIMD operations that can be utilized by higher-level code. The detailed implementation of various operations reflects a focus on performance and flexibility, catering to applications that require high-speed data processing using SIMD parallelism.
# Functions

---
### wb\_bcast\_pair<!-- {{#callable:wb_bcast_pair}} -->
The `wb_bcast_pair` function creates a 256-bit vector with alternating repetitions of two given unsigned 8-bit integers.
- **Inputs**:
    - `b0`: An unsigned 8-bit integer (uchar) to be repeated in the vector.
    - `b1`: Another unsigned 8-bit integer (uchar) to be repeated in the vector.
- **Control Flow**:
    - The function takes two unsigned 8-bit integers, `b0` and `b1`, as input.
    - It uses the `_mm256_setr_epi8` intrinsic to create a 256-bit vector.
    - The vector is filled with alternating values of `b0` and `b1`, repeated 16 times each, resulting in a total of 32 elements.
- **Output**: A 256-bit vector (`wb_t`) containing 32 elements, with `b0` and `b1` alternating.


---
### wb\_bcast\_quad<!-- {{#callable:wb_bcast_quad}} -->
The `wb_bcast_quad` function creates a 256-bit vector with a repeated sequence of four 8-bit unsigned integers.
- **Inputs**:
    - `b0`: An unsigned 8-bit integer to be placed in the vector.
    - `b1`: An unsigned 8-bit integer to be placed in the vector.
    - `b2`: An unsigned 8-bit integer to be placed in the vector.
    - `b3`: An unsigned 8-bit integer to be placed in the vector.
- **Control Flow**:
    - The function takes four unsigned 8-bit integers as input parameters.
    - Each input integer is cast to a signed 8-bit integer (char) and used to populate a 256-bit vector.
    - The sequence [b0, b1, b2, b3] is repeated eight times to fill the 32 lanes of the vector.
    - The function returns the constructed 256-bit vector.
- **Output**: A 256-bit vector (`wb_t`) containing the sequence [b0, b1, b2, b3] repeated eight times.


---
### wb\_bcast\_oct<!-- {{#callable:wb_bcast_oct}} -->
The `wb_bcast_oct` function creates a 256-bit vector with repeated sequences of eight 8-bit unsigned integers.
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
    - Each input integer is cast to a signed 8-bit integer (char) and used to populate a 256-bit vector.
    - The vector is constructed using the `_mm256_setr_epi8` intrinsic, which sets the vector's elements in a specified order.
    - The eight input integers are repeated four times to fill the 32 lanes of the 256-bit vector.
- **Output**: The function returns a 256-bit vector (`wb_t`) containing the repeated sequence of the eight input integers.


---
### wb\_bcast\_hex<!-- {{#callable:wb_bcast_hex}} -->
The `wb_bcast_hex` function creates a 256-bit vector with two repeated sequences of 16 unsigned 8-bit integers (uchars) using AVX intrinsics.
- **Inputs**:
    - `b0`: The first unsigned 8-bit integer to be included in the vector.
    - `b1`: The second unsigned 8-bit integer to be included in the vector.
    - `b2`: The third unsigned 8-bit integer to be included in the vector.
    - `b3`: The fourth unsigned 8-bit integer to be included in the vector.
    - `b4`: The fifth unsigned 8-bit integer to be included in the vector.
    - `b5`: The sixth unsigned 8-bit integer to be included in the vector.
    - `b6`: The seventh unsigned 8-bit integer to be included in the vector.
    - `b7`: The eighth unsigned 8-bit integer to be included in the vector.
    - `b8`: The ninth unsigned 8-bit integer to be included in the vector.
    - `b9`: The tenth unsigned 8-bit integer to be included in the vector.
    - `b10`: The eleventh unsigned 8-bit integer to be included in the vector.
    - `b11`: The twelfth unsigned 8-bit integer to be included in the vector.
    - `b12`: The thirteenth unsigned 8-bit integer to be included in the vector.
    - `b13`: The fourteenth unsigned 8-bit integer to be included in the vector.
    - `b14`: The fifteenth unsigned 8-bit integer to be included in the vector.
    - `b15`: The sixteenth unsigned 8-bit integer to be included in the vector.
- **Control Flow**:
    - The function takes 16 unsigned 8-bit integers as input parameters.
    - Each input integer is cast to a signed 8-bit integer (char) and passed to the `_mm256_setr_epi8` intrinsic.
    - The `_mm256_setr_epi8` intrinsic is used to create a 256-bit vector with the first 16 elements set to the input integers in order, followed by the same 16 integers repeated in the same order.
- **Output**: The function returns a 256-bit vector (`wb_t`) containing two sequences of the 16 input unsigned 8-bit integers.


---
### wb\_expand\_pair<!-- {{#callable:wb_expand_pair}} -->
The `wb_expand_pair` function creates a 256-bit vector with the first half filled with repeated instances of `b0` and the second half with repeated instances of `b1`.
- **Inputs**:
    - `b0`: An unsigned 8-bit integer (uchar) to be repeated in the first half of the vector.
    - `b1`: An unsigned 8-bit integer (uchar) to be repeated in the second half of the vector.
- **Control Flow**:
    - The function takes two uchar inputs, `b0` and `b1`.
    - It uses the `_mm256_setr_epi8` intrinsic to create a 256-bit vector.
    - The first 16 bytes of the vector are filled with the value of `b0`, repeated 16 times.
    - The next 16 bytes of the vector are filled with the value of `b1`, repeated 16 times.
- **Output**: A 256-bit vector (`wb_t`) where the first 16 bytes are filled with `b0` and the next 16 bytes are filled with `b1`.


---
### wb\_expand\_quad<!-- {{#callable:wb_expand_quad}} -->
The `wb_expand_quad` function creates a 256-bit vector with each of the four input bytes repeated eight times consecutively.
- **Inputs**:
    - `b0`: An unsigned 8-bit integer (uchar) to be repeated in the first 8 positions of the vector.
    - `b1`: An unsigned 8-bit integer (uchar) to be repeated in the next 8 positions of the vector.
    - `b2`: An unsigned 8-bit integer (uchar) to be repeated in the following 8 positions of the vector.
    - `b3`: An unsigned 8-bit integer (uchar) to be repeated in the last 8 positions of the vector.
- **Control Flow**:
    - The function takes four unsigned 8-bit integers as input parameters.
    - Each input byte is cast to a signed 8-bit integer (char) and repeated eight times in the resulting vector.
    - The function uses the `_mm256_setr_epi8` intrinsic to set the 32 bytes of the 256-bit vector, arranging them in the specified order.
- **Output**: A 256-bit vector (`wb_t`) where each of the input bytes is repeated eight times consecutively.


---
### wb\_expand\_oct<!-- {{#callable:wb_expand_oct}} -->
The `wb_expand_oct` function takes eight unsigned 8-bit integers and returns a 256-bit vector where each input integer is repeated four times consecutively.
- **Inputs**:
    - `b0`: An unsigned 8-bit integer to be repeated four times in the output vector.
    - `b1`: An unsigned 8-bit integer to be repeated four times in the output vector.
    - `b2`: An unsigned 8-bit integer to be repeated four times in the output vector.
    - `b3`: An unsigned 8-bit integer to be repeated four times in the output vector.
    - `b4`: An unsigned 8-bit integer to be repeated four times in the output vector.
    - `b5`: An unsigned 8-bit integer to be repeated four times in the output vector.
    - `b6`: An unsigned 8-bit integer to be repeated four times in the output vector.
    - `b7`: An unsigned 8-bit integer to be repeated four times in the output vector.
- **Control Flow**:
    - The function is defined as a static inline function, which suggests it is intended for use within the same translation unit and optimized for performance.
    - It uses the `_mm256_setr_epi8` intrinsic to construct a 256-bit vector (`__m256i`) from the input bytes.
    - Each input byte (`b0` to `b7`) is cast to a `char` and repeated four times in sequence to fill the 32-byte vector.
- **Output**: A 256-bit vector (`wb_t`, which is a typedef for `__m256i`) where each of the eight input bytes is repeated four times consecutively.


---
### wb\_expand\_hex<!-- {{#callable:wb_expand_hex}} -->
The `wb_expand_hex` function duplicates each of the 16 input unsigned 8-bit integers (uchars) and returns them as a 256-bit vector using AVX2 intrinsics.
- **Inputs**:
    - `b0`: An unsigned 8-bit integer (uchar) to be duplicated in the vector.
    - `b1`: An unsigned 8-bit integer (uchar) to be duplicated in the vector.
    - `b2`: An unsigned 8-bit integer (uchar) to be duplicated in the vector.
    - `b3`: An unsigned 8-bit integer (uchar) to be duplicated in the vector.
    - `b4`: An unsigned 8-bit integer (uchar) to be duplicated in the vector.
    - `b5`: An unsigned 8-bit integer (uchar) to be duplicated in the vector.
    - `b6`: An unsigned 8-bit integer (uchar) to be duplicated in the vector.
    - `b7`: An unsigned 8-bit integer (uchar) to be duplicated in the vector.
    - `b8`: An unsigned 8-bit integer (uchar) to be duplicated in the vector.
    - `b9`: An unsigned 8-bit integer (uchar) to be duplicated in the vector.
    - `b10`: An unsigned 8-bit integer (uchar) to be duplicated in the vector.
    - `b11`: An unsigned 8-bit integer (uchar) to be duplicated in the vector.
    - `b12`: An unsigned 8-bit integer (uchar) to be duplicated in the vector.
    - `b13`: An unsigned 8-bit integer (uchar) to be duplicated in the vector.
    - `b14`: An unsigned 8-bit integer (uchar) to be duplicated in the vector.
    - `b15`: An unsigned 8-bit integer (uchar) to be duplicated in the vector.
- **Control Flow**:
    - The function takes 16 unsigned 8-bit integers as input parameters.
    - Each input integer is cast to a signed 8-bit integer (char) and duplicated.
    - The duplicated values are arranged in a 256-bit vector using the `_mm256_setr_epi8` intrinsic, which sets the vector with the specified bytes in the given order.
    - The function returns the constructed 256-bit vector.
- **Output**: A 256-bit vector (`wb_t`) where each of the 16 input uchars is duplicated, resulting in a vector of 32 bytes.


---
### wb\_exch\_adj\_hex<!-- {{#callable:wb_exch_adj_hex}} -->
The `wb_exch_adj_hex` function swaps the two 128-bit lanes of a 256-bit vector of unsigned 8-bit integers.
- **Inputs**:
    - `x`: A 256-bit vector of unsigned 8-bit integers (type `wb_t`).
- **Control Flow**:
    - The function takes a 256-bit vector `x` as input.
    - It uses the `_mm256_permute2f128_si256` intrinsic to swap the two 128-bit lanes of the vector.
    - The intrinsic is called with the same vector `x` for both source operands and a control value of `1`, which specifies the lane swap operation.
- **Output**: A 256-bit vector with its two 128-bit lanes swapped.


---
### wb\_ld<!-- {{#callable:wb_ld}} -->
The `wb_ld` function loads a 256-bit vector of 32 unsigned 8-bit integers from a 32-byte aligned memory location.
- **Inputs**:
    - `p`: A pointer to a 32-byte aligned memory location containing 32 unsigned 8-bit integers (uchar).
- **Control Flow**:
    - The function takes a pointer `p` as input, which is expected to be aligned to a 32-byte boundary.
    - It casts the pointer `p` to a pointer of type `__m256i const *`, which is suitable for AVX operations.
    - The function then uses the `_mm256_load_si256` intrinsic to load the 256-bit data from the memory location pointed to by `p` into a `__m256i` vector register.
    - The loaded vector is returned as the result of the function.
- **Output**: A `wb_t` type, which is a 256-bit vector containing 32 unsigned 8-bit integers loaded from the specified memory location.


---
### wb\_st<!-- {{#callable:wb_st}} -->
The `wb_st` function stores a 256-bit vector of unsigned 8-bit integers into a specified memory location.
- **Inputs**:
    - `p`: A pointer to a memory location where the 256-bit vector will be stored; it should be 32-byte aligned.
    - `i`: A 256-bit vector of type `wb_t` (which is an alias for `__m256i`) containing 32 unsigned 8-bit integers to be stored.
- **Control Flow**:
    - The function uses the `_mm256_store_si256` intrinsic to store the 256-bit vector `i` into the memory location pointed to by `p`.
- **Output**: The function does not return any value; it performs a side effect by writing data to the memory location pointed to by `p`.


---
### wb\_ldu<!-- {{#callable:wb_ldu}} -->
The `wb_ldu` function loads a 256-bit vector of unsigned 8-bit integers from an unaligned memory address.
- **Inputs**:
    - `p`: A pointer to a memory location from which the 256-bit vector will be loaded; the memory does not need to be aligned.
- **Control Flow**:
    - The function casts the input pointer `p` to a pointer of type `__m256i const *` to ensure it is treated as a 256-bit integer vector.
    - It then calls the intrinsic function `_mm256_loadu_si256` to load the 256-bit vector from the memory location pointed to by `p`.
- **Output**: The function returns a `wb_t` type, which is a 256-bit vector containing 32 unsigned 8-bit integers loaded from the specified memory location.


---
### wb\_stu<!-- {{#callable:wb_stu}} -->
The `wb_stu` function stores a 256-bit vector of unsigned 8-bit integers to a memory location that does not need to be aligned.
- **Inputs**:
    - `p`: A pointer to the memory location where the 256-bit vector will be stored; the location does not need to be aligned.
    - `i`: A 256-bit vector of unsigned 8-bit integers (type `wb_t`) to be stored at the memory location pointed to by `p`.
- **Control Flow**:
    - The function uses the `_mm256_storeu_si256` intrinsic to store the 256-bit vector `i` at the memory location pointed to by `p`.
- **Output**: The function does not return any value; it performs a side effect by storing data at the specified memory location.


---
### wb\_extract\_variable<!-- {{#callable:wb_extract_variable}} -->
The `wb_extract_variable` function extracts a specific unsigned 8-bit integer from a 256-bit vector at a given index.
- **Inputs**:
    - `a`: A 256-bit vector (`wb_t`) containing 32 unsigned 8-bit integers.
    - `n`: An integer representing the index (0 to 31) of the byte to extract from the vector.
- **Control Flow**:
    - A union is defined to allow type punning between a 256-bit vector and an array of 32 unsigned 8-bit integers.
    - The 256-bit vector `a` is stored into the union's vector member using `_mm256_store_si256`.
    - The byte at index `n` is accessed from the union's array member and returned.
- **Output**: The function returns the unsigned 8-bit integer located at the specified index `n` in the vector `a`.


---
### wb\_insert\_variable<!-- {{#callable:wb_insert_variable}} -->
The `wb_insert_variable` function replaces a specific byte in a 256-bit vector with a new value at a given index.
- **Inputs**:
    - `a`: A 256-bit vector (`wb_t`) containing 32 unsigned 8-bit integers.
    - `n`: An integer representing the index (0 to 31) of the byte to be replaced in the vector.
    - `v`: An unsigned 8-bit integer (`uchar`) that will replace the byte at index `n` in the vector.
- **Control Flow**:
    - A union is defined to allow type punning between a 256-bit vector and an array of 32 bytes.
    - The input vector `a` is stored into the union's 256-bit vector field using `_mm256_store_si256`.
    - The byte at index `n` in the union's byte array is replaced with the new value `v`.
    - The modified 256-bit vector is loaded back from the union's vector field using `_mm256_load_si256`.
- **Output**: The function returns a new 256-bit vector (`wb_t`) with the byte at index `n` replaced by `v`.


---
### wb\_rol<!-- {{#callable:wb_rol}} -->
The `wb_rol` function performs a bitwise left rotation on each 8-bit lane of a 256-bit vector by a specified number of bits.
- **Inputs**:
    - `a`: A 256-bit vector (`wb_t`) where each 8-bit lane holds an unsigned 8-bit integer.
    - `imm`: An integer specifying the number of bits to rotate left, which is masked to the range 0-7.
- **Control Flow**:
    - The function masks the `imm` value with 7 to ensure it is within the range 0-7.
    - It performs a left shift on the vector `a` by the masked `imm` value using `wb_shl`.
    - It performs a right shift on the vector `a` by the negated and masked `imm` value using `wb_shr`.
    - The results of the left and right shifts are combined using a bitwise OR operation with `wb_or`.
- **Output**: A 256-bit vector (`wb_t`) with each 8-bit lane rotated left by the specified number of bits.


---
### wb\_ror<!-- {{#callable:wb_ror}} -->
The `wb_ror` function performs a bitwise right rotation on each 8-bit lane of a 256-bit vector by a specified number of bits.
- **Inputs**:
    - `a`: A 256-bit vector (`wb_t`) where each 8-bit lane holds an unsigned 8-bit integer.
    - `imm`: An integer specifying the number of bits to rotate right, which is masked to the range 0-7.
- **Control Flow**:
    - The function masks the `imm` value with 7 to ensure it is within the range 0-7.
    - It performs a right logical shift on the vector `a` by the masked `imm` value using `wb_shr`.
    - It performs a left logical shift on the vector `a` by the negated and masked `imm` value using `wb_shl`.
    - The results of the two shifts are combined using a bitwise OR operation with `wb_or` to achieve the rotation effect.
- **Output**: A 256-bit vector (`wb_t`) with each 8-bit lane rotated right by the specified number of bits.


---
### wb\_rol\_variable<!-- {{#callable:wb_rol_variable}} -->
The `wb_rol_variable` function performs a variable bitwise left rotation on a vector of 8-bit unsigned integers.
- **Inputs**:
    - `a`: A vector of 8-bit unsigned integers (type `wb_t`) to be rotated.
    - `n`: An integer specifying the number of positions to rotate the vector `a` to the left.
- **Control Flow**:
    - The function calculates `n & 7` to ensure the rotation amount is within the range of 0 to 7 bits.
    - It calls `wb_shl_variable` to perform a left shift on `a` by `n & 7` bits.
    - It calls `wb_shr_variable` to perform a right shift on `a` by `(-n) & 7` bits.
    - The results of the left and right shifts are combined using `wb_or` to produce the final rotated vector.
- **Output**: The function returns a vector of 8-bit unsigned integers (type `wb_t`) that is the result of rotating the input vector `a` to the left by `n` positions.


---
### wb\_ror\_variable<!-- {{#callable:wb_ror_variable}} -->
The `wb_ror_variable` function performs a variable bitwise right rotation on a vector of 8-bit unsigned integers.
- **Inputs**:
    - `a`: A vector of 8-bit unsigned integers (type `wb_t`) to be rotated.
    - `n`: An integer specifying the number of positions to rotate the vector `a` to the right.
- **Control Flow**:
    - The function calculates `n & 7` to ensure the rotation amount is within the range of 0 to 7 bits.
    - It calls `wb_shr_variable` to perform a right shift on `a` by `n & 7` bits.
    - It calls `wb_shl_variable` to perform a left shift on `a` by `(-n) & 7` bits.
    - The results of the two shifts are combined using `wb_or` to complete the rotation.
- **Output**: The function returns a vector of 8-bit unsigned integers (type `wb_t`) that is the result of the right rotation of the input vector `a` by `n` positions.


---
### wb\_expand\_internal\_8<!-- {{#callable:wb_expand_internal_8}} -->
The `wb_expand_internal_8` function extracts and zero-extends a group of 8 unsigned 8-bit integers from a 256-bit vector based on a specified index.
- **Inputs**:
    - `a`: A 256-bit vector (`wb_t`) containing 32 unsigned 8-bit integers.
    - `imm`: An integer index (0 to 3) specifying which group of 8 integers to extract and expand.
- **Control Flow**:
    - The function uses a switch statement to determine the action based on the value of `imm`.
    - If `imm` is 0, it extracts the lower 128 bits of `a` and converts the first 8 bytes to 32-bit integers.
    - If `imm` is 1, it extracts the lower 128 bits of `a`, shifts it right by 8 bytes, and converts the next 8 bytes to 32-bit integers.
    - If `imm` is 2, it extracts the upper 128 bits of `a` and converts the first 8 bytes to 32-bit integers.
    - If `imm` is 3, it extracts the upper 128 bits of `a`, shifts it right by 8 bytes, and converts the next 8 bytes to 32-bit integers.
    - The function returns a zeroed 256-bit vector if none of the cases match, although this is unreachable.
- **Output**: A 256-bit vector (`__m256i`) containing 8 zero-extended 32-bit integers.


---
### wb\_expand\_internal\_4<!-- {{#callable:wb_expand_internal_4}} -->
The `wb_expand_internal_4` function extracts a 128-bit segment from a 256-bit vector and zero-extends it to a 128-bit integer vector based on the specified immediate value.
- **Inputs**:
    - `a`: A 256-bit vector of type `wb_t` (which is an alias for `__m256i`) containing 32 unsigned 8-bit integers.
    - `imm`: An integer immediate value that determines which 128-bit segment of the vector `a` to extract and process.
- **Control Flow**:
    - The function uses a switch statement to handle different cases based on the value of `imm` ranging from 0 to 7.
    - For each case, it extracts a 128-bit segment from the 256-bit vector `a` using `_mm256_extractf128_si256` and optionally shifts it using `_mm_bsrli_si128` to align the desired 4-byte group.
    - The extracted segment is then zero-extended to a 128-bit integer vector using `_mm_cvtepu8_epi32`.
    - If `imm` is not in the range 0 to 7, the function returns a zero-initialized 128-bit vector using `_mm_setzero_si128`, although this is marked as unreachable.
- **Output**: A 128-bit integer vector (`__m128i`) that contains zero-extended 32-bit integers derived from a 4-byte group within the specified segment of the input vector `a`.


---
### wb\_sum\_all<!-- {{#callable:wb_sum_all}} -->
The `wb_sum_all` function computes the sum of all 8-bit unsigned integers in a 256-bit vector and returns a vector where each byte is the broadcasted sum.
- **Inputs**:
    - `x`: A 256-bit vector (`wb_t`) containing 32 unsigned 8-bit integers.
- **Control Flow**:
    - The function starts by using `_mm256_sad_epu8` to compute the sum of absolute differences between the input vector `x` and a zero vector, resulting in four 64-bit integers each representing the sum of 8 bytes from `x`.
    - It then uses `_mm256_permute2f128_si256` to shuffle the 128-bit lanes of the vector, effectively summing the first and third 64-bit integers with the second and fourth, respectively.
    - Finally, it uses `_mm256_shuffle_epi8` and `_mm256_add_epi8` to broadcast the low byte of each 64-bit sum across the vector and sum them, resulting in a vector where each byte is the total sum of the original vector's bytes.
- **Output**: A 256-bit vector (`wb_t`) where each byte contains the sum of all bytes in the input vector `x`.


---
### wb\_min\_all<!-- {{#callable:wb_min_all}} -->
The `wb_min_all` function computes the minimum value across all lanes of a 256-bit vector of unsigned 8-bit integers and broadcasts this minimum value across all lanes of the vector.
- **Inputs**:
    - `x`: A 256-bit vector (`wb_t`) where each lane contains an unsigned 8-bit integer.
- **Control Flow**:
    - The function first computes the minimum of the two 128-bit halves of the input vector using `_mm256_min_epu8` and `_mm256_permute2f128_si256`.
    - It then shuffles the vector to compare and find the minimum across different lanes using `_mm256_shuffle_epi8` with specific patterns.
    - This process is repeated with different shuffle patterns to progressively reduce the vector to a single minimum value.
    - Finally, the minimum value is broadcasted across all lanes of the vector.
- **Output**: A 256-bit vector (`wb_t`) where each lane contains the minimum value found in the original input vector.
- **Functions called**:
    - [`wb_bcast_quad`](#wb_bcast_quad)
    - [`wb_bcast_pair`](#wb_bcast_pair)


---
### wb\_max\_all<!-- {{#callable:wb_max_all}} -->
The `wb_max_all` function computes the maximum value across all lanes of a 256-bit vector of unsigned 8-bit integers and broadcasts this maximum value to all lanes of the vector.
- **Inputs**:
    - `x`: A 256-bit vector (`wb_t`) where each lane holds an unsigned 8-bit integer.
- **Control Flow**:
    - The function first computes the maximum of the input vector `x` and its permuted version, which swaps the lower and upper 128-bit lanes.
    - It then performs a series of shuffle and maximum operations to progressively reduce the vector, comparing and shuffling the elements to find the maximum value across all lanes.
    - The final result is a vector where all lanes contain the maximum value found in the original vector `x`.
- **Output**: A 256-bit vector (`wb_t`) where each lane contains the maximum value found in the input vector `x`.
- **Functions called**:
    - [`wb_bcast_quad`](#wb_bcast_quad)
    - [`wb_bcast_pair`](#wb_bcast_pair)



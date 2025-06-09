# Purpose
This C source code file is a specialized utility for handling vector operations using AVX (Advanced Vector Extensions) intrinsics, specifically targeting operations on vectors of unsigned 64-bit integers (ulongs). The file defines a set of macros and inline functions that provide a comprehensive API for constructing, manipulating, and performing arithmetic, logical, and memory operations on these vector types. The primary data type used is `wv_t`, which is an alias for the `__m256i` type, representing a 256-bit wide vector that can hold four 64-bit unsigned integers. The code includes constructors for creating vectors, predefined constants, memory operations for loading and storing vectors, and a variety of arithmetic and binary operations. Additionally, it provides conversion functions to transform these vectors into other data types and reduction operations to compute aggregate values like sums, minimums, and maximums across vector elements.

The file is intended to be included indirectly through a header file named `fd_avx.h`, as indicated by the initial preprocessor directive. This suggests that the code is part of a larger library or framework that provides SIMD (Single Instruction, Multiple Data) capabilities, likely for performance-critical applications that benefit from parallel processing. The use of macros and inline functions is a deliberate choice to optimize performance by minimizing function call overhead and allowing the compiler to better optimize the generated machine code. The file also includes conditional compilation to handle differences in compiler capabilities, such as specific optimizations for Clang and support for AVX-512 instructions when available. Overall, this file provides a focused and efficient interface for vectorized operations on 64-bit unsigned integers, leveraging the power of AVX intrinsics to enhance computational performance.
# Functions

---
### wv\_bcast\_pair<!-- {{#callable:wv_bcast_pair}} -->
The `wv_bcast_pair` function creates a 256-bit vector with two 64-bit unsigned integers repeated in an alternating pattern.
- **Inputs**:
    - `v0`: The first unsigned long integer to be broadcasted in the vector.
    - `v1`: The second unsigned long integer to be broadcasted in the vector.
- **Control Flow**:
    - The function takes two unsigned long integers, `v0` and `v1`, as inputs.
    - It casts these integers to long and uses the `_mm256_setr_epi64x` intrinsic to create a 256-bit vector.
    - The vector is constructed with the pattern `[v0, v1, v0, v1]`, meaning each input is repeated twice in an alternating sequence.
- **Output**: A 256-bit vector (`wv_t`) containing the pattern `[v0, v1, v0, v1]`.


---
### wv\_bcast\_wide<!-- {{#callable:wv_bcast_wide}} -->
The `wv_bcast_wide` function creates a 256-bit vector with two pairs of 64-bit unsigned integers, each pair containing the same value.
- **Inputs**:
    - `v0`: The first unsigned long integer to be broadcasted into the vector.
    - `v1`: The second unsigned long integer to be broadcasted into the vector.
- **Control Flow**:
    - The function takes two unsigned long integers, `v0` and `v1`, as input parameters.
    - It casts these unsigned long integers to long integers.
    - It uses the `_mm256_setr_epi64x` intrinsic to create a 256-bit vector with the pattern `[v0, v0, v1, v1]`.
- **Output**: A 256-bit vector (`wv_t`) containing the values `[v0, v0, v1, v1]`.


---
### wv\_permute<!-- {{#callable:wv_permute}} -->
The `wv_permute` function rearranges the elements of a 256-bit vector of unsigned 64-bit integers based on specified indices.
- **Inputs**:
    - `x`: A 256-bit vector of unsigned 64-bit integers (`wv_t`) to be permuted.
    - `imm_i0`: An integer index (0-3) specifying which element of `x` to place in the first position of the result.
    - `imm_i1`: An integer index (0-3) specifying which element of `x` to place in the second position of the result.
    - `imm_i2`: An integer index (0-3) specifying which element of `x` to place in the third position of the result.
    - `imm_i3`: An integer index (0-3) specifying which element of `x` to place in the fourth position of the result.
- **Control Flow**:
    - The function begins by storing the input vector `x` into a union `t` that can be accessed as an array of unsigned long integers.
    - The function then creates another union `u` to store the permuted result.
    - Each element of `u` is assigned from `t` based on the indices `imm_i0`, `imm_i1`, `imm_i2`, and `imm_i3`.
    - Finally, the function returns a new 256-bit vector loaded from the permuted union `u`.
- **Output**: A 256-bit vector (`wv_t`) with elements rearranged according to the specified indices.


---
### wv\_ld<!-- {{#callable:wv_ld}} -->
The `wv_ld` function loads a 256-bit vector of four unsigned 64-bit integers from a 32-byte aligned memory location into a SIMD register.
- **Inputs**:
    - `p`: A pointer to a constant unsigned long integer, representing the 32-byte aligned memory location from which the vector is to be loaded.
- **Control Flow**:
    - The function takes a pointer `p` to a memory location.
    - It casts the pointer `p` to a pointer of type `__m256i const *`.
    - It uses the `_mm256_load_si256` intrinsic to load a 256-bit vector from the memory location pointed to by the casted pointer.
    - The loaded vector is returned as the function's result.
- **Output**: A 256-bit vector (`wv_t`) containing four unsigned 64-bit integers loaded from the specified memory location.


---
### wv\_st<!-- {{#callable:wv_st}} -->
The `wv_st` function stores a vector of unsigned 64-bit integers into a specified memory location.
- **Inputs**:
    - `p`: A pointer to a memory location where the vector will be stored; it should be 32-byte aligned.
    - `i`: A vector of type `wv_t` (which is an alias for `__m256i`) containing the data to be stored.
- **Control Flow**:
    - The function uses the `_mm256_store_si256` intrinsic to store the vector `i` into the memory location pointed to by `p`.
- **Output**: The function does not return any value; it performs a side effect by writing data to the memory location pointed to by `p`.


---
### wv\_ldu<!-- {{#callable:wv_ldu}} -->
The `wv_ldu` function loads a 256-bit vector of unsigned 64-bit integers from an unaligned memory address.
- **Inputs**:
    - `p`: A pointer to the memory location from which the 256-bit vector is to be loaded; it does not need to be aligned.
- **Control Flow**:
    - The function casts the input pointer `p` to a pointer of type `__m256i const *`, which is suitable for AVX2 operations.
    - It then uses the `_mm256_loadu_si256` intrinsic to load a 256-bit vector from the memory location pointed to by the casted pointer.
- **Output**: A 256-bit vector (`wv_t`) containing four unsigned 64-bit integers loaded from the specified memory location.


---
### wv\_stu<!-- {{#callable:wv_stu}} -->
The `wv_stu` function stores a vector of unsigned 64-bit integers to a memory location without requiring alignment.
- **Inputs**:
    - `p`: A pointer to the memory location where the vector will be stored; it does not need to be aligned.
    - `i`: A vector of type `wv_t` (which is an alias for `__m256i`) containing the unsigned 64-bit integers to be stored.
- **Control Flow**:
    - The function uses the `_mm256_storeu_si256` intrinsic to store the vector `i` at the memory location pointed to by `p`.
- **Output**: The function does not return any value; it performs a side effect by storing data at the specified memory location.


---
### wv\_extract\_variable<!-- {{#callable:wv_extract_variable}} -->
The `wv_extract_variable` function extracts a 64-bit unsigned integer from a specified lane of a 256-bit vector.
- **Inputs**:
    - `a`: A 256-bit vector of type `wv_t` (which is an alias for `__m256i`) containing four 64-bit unsigned integers.
    - `n`: An integer specifying the lane index (0 to 3) from which to extract the 64-bit unsigned integer.
- **Control Flow**:
    - A union is defined to allow type punning between a 256-bit vector and an array of four 64-bit unsigned integers.
    - The 256-bit vector `a` is stored into the union's vector member using `_mm256_store_si256`.
    - The function returns the `n`-th element from the union's array of 64-bit unsigned integers.
- **Output**: A 64-bit unsigned integer extracted from the specified lane of the input vector.


---
### wv\_insert\_variable<!-- {{#callable:wv_insert_variable}} -->
The `wv_insert_variable` function replaces a specified element in a 256-bit vector of unsigned 64-bit integers with a new value.
- **Inputs**:
    - `a`: A 256-bit vector (`wv_t`) containing four unsigned 64-bit integers.
    - `n`: An integer index (0 to 3) indicating which element in the vector to replace.
    - `v`: An unsigned long integer value to insert into the vector at the specified index.
- **Control Flow**:
    - The function begins by declaring a union `t` that can store a 256-bit vector or an array of four unsigned long integers.
    - The input vector `a` is stored into the union's vector member using `_mm256_store_si256`.
    - The element at index `n` in the union's unsigned long array is replaced with the new value `v`.
    - The modified vector is then loaded back from the union's vector member using `_mm256_load_si256` and returned.
- **Output**: A 256-bit vector (`wv_t`) with the specified element replaced by the new value.


---
### wv\_rol<!-- {{#callable:wv_rol}} -->
The `wv_rol` function performs a bitwise left rotation on each 64-bit lane of a 256-bit vector by a specified number of bits.
- **Inputs**:
    - `a`: A 256-bit vector (`wv_t`) containing four 64-bit unsigned integers to be rotated.
    - `imm`: An integer specifying the number of bits to rotate each 64-bit lane to the left.
- **Control Flow**:
    - The function calculates the effective rotation amount by taking `imm & 63`, ensuring it is within the range of 0 to 63 bits.
    - It performs a left shift on the vector `a` by the calculated rotation amount using `wv_shl`.
    - It performs a right shift on the vector `a` by the complement of the rotation amount using `wv_shr`.
    - The results of the left and right shifts are combined using a bitwise OR operation with `wv_or` to complete the rotation.
- **Output**: A 256-bit vector (`wv_t`) where each 64-bit lane has been rotated left by the specified number of bits.


---
### wv\_ror<!-- {{#callable:wv_ror}} -->
The `wv_ror` function performs a bitwise right rotation on each 64-bit lane of a 256-bit vector by a specified number of bits.
- **Inputs**:
    - `a`: A 256-bit vector (`wv_t`) containing four 64-bit unsigned integers to be rotated.
    - `imm`: An integer specifying the number of bits to rotate each 64-bit lane to the right.
- **Control Flow**:
    - The function calculates `imm & 63` to ensure the rotation amount is within the valid range of 0 to 63 bits.
    - It performs a right shift on the vector `a` by the calculated number of bits using `wv_shr`.
    - It performs a left shift on the vector `a` by the complement of the calculated number of bits using `wv_shl`.
    - The results of the right and left shifts are combined using a bitwise OR operation with `wv_or`.
    - The combined result is returned as the output of the function.
- **Output**: A 256-bit vector (`wv_t`) where each 64-bit lane has been right-rotated by the specified number of bits.


---
### wv\_rol\_variable<!-- {{#callable:wv_rol_variable}} -->
The `wv_rol_variable` function performs a variable bitwise left rotation on a vector of unsigned 64-bit integers.
- **Inputs**:
    - `a`: A vector of unsigned 64-bit integers (`wv_t`) to be rotated.
    - `n`: An integer specifying the number of positions to rotate the vector `a` to the left.
- **Control Flow**:
    - The function calculates `n & 63` to ensure the rotation count is within the range of 0 to 63 bits.
    - It performs a left shift on the vector `a` by `n & 63` bits using `wv_shl_variable`.
    - It performs a right shift on the vector `a` by `(-n) & 63` bits using `wv_shr_variable`.
    - The results of the left and right shifts are combined using a bitwise OR operation with `wv_or`.
- **Output**: The function returns a vector of unsigned 64-bit integers (`wv_t`) that is the result of rotating the input vector `a` to the left by `n` positions.


---
### wv\_ror\_variable<!-- {{#callable:wv_ror_variable}} -->
The `wv_ror_variable` function performs a variable right rotation on a vector of unsigned 64-bit integers.
- **Inputs**:
    - `a`: A vector of unsigned 64-bit integers (`wv_t`) to be rotated.
    - `n`: An integer specifying the number of positions to rotate the vector to the right.
- **Control Flow**:
    - The function calculates `n & 63` to ensure the rotation amount is within the valid range of 0 to 63 bits.
    - It calls `wv_shr_variable` to perform a right shift on the vector `a` by `n & 63` bits.
    - It calls `wv_shl_variable` to perform a left shift on the vector `a` by `(-n) & 63` bits.
    - It combines the results of the right and left shifts using `wv_or` to achieve the right rotation effect.
- **Output**: A vector of unsigned 64-bit integers (`wv_t`) that is the result of rotating the input vector `a` to the right by `n` positions.


---
### wv\_rol\_vector<!-- {{#callable:wv_rol_vector}} -->
The `wv_rol_vector` function performs a bitwise left rotation on each 64-bit integer in a vector by a specified number of bits, using another vector to determine the rotation amount for each element.
- **Inputs**:
    - `a`: A vector of 64-bit unsigned integers (`wv_t`) to be rotated.
    - `b`: A vector of 64-bit integers (`wl_t`) specifying the number of bits to rotate each corresponding element in `a`.
- **Control Flow**:
    - Broadcast the constant value 63 into a vector `m` using `wl_bcast` to ensure the rotation amount is within the valid range of 0 to 63 bits.
    - Perform a bitwise AND operation between `b` and `m` to limit the rotation amount for each element in `b` to 63 bits.
    - Shift the elements of `a` to the left by the amounts specified in the modified `b` using `wv_shl_vector`.
    - Negate the elements of `b`, perform a bitwise AND with `m`, and shift the elements of `a` to the right by these amounts using `wv_shr_vector`.
    - Combine the results of the left and right shifts using a bitwise OR operation with `wv_or` to achieve the rotation effect.
- **Output**: A vector of 64-bit unsigned integers (`wv_t`) where each element is the result of rotating the corresponding element in `a` to the left by the number of bits specified in `b`.


---
### wv\_ror\_vector<!-- {{#callable:wv_ror_vector}} -->
The `wv_ror_vector` function performs a bitwise right rotation on each 64-bit lane of a vector by a specified number of bits, using another vector to determine the rotation amount for each lane.
- **Inputs**:
    - `a`: A vector of type `wv_t` containing four 64-bit unsigned integers, each of which will be rotated.
    - `b`: A vector of type `wl_t` containing four 64-bit integers, each specifying the number of bits to rotate the corresponding lane in `a`.
- **Control Flow**:
    - Broadcast the constant value 63 into a vector `m` using `wl_bcast` to ensure the rotation amount is within the valid range of 0 to 63 bits.
    - Perform a bitwise AND between each lane of `b` and `m` to limit the rotation amount to 63 bits, then right shift each lane of `a` by the resulting values using `wv_shr_vector`.
    - Negate each lane of `b`, perform a bitwise AND with `m`, and left shift each lane of `a` by the resulting values using `wv_shl_vector`.
    - Combine the results of the right and left shifts using a bitwise OR operation with `wv_or` to achieve the effect of a right rotation.
- **Output**: A vector of type `wv_t` containing the result of the right rotation for each lane of the input vector `a`.


---
### wv\_min<!-- {{#callable:wv_min}} -->
The `wv_min` function returns a vector containing the minimum values from corresponding lanes of two input vectors.
- **Inputs**:
    - `a`: A vector of type `wv_t` containing four unsigned 64-bit integers.
    - `b`: A vector of type `wv_t` containing four unsigned 64-bit integers.
- **Control Flow**:
    - The function uses the `wv_lt` macro to compare corresponding lanes of vectors `a` and `b` to determine which values are smaller.
    - The `wv_if` macro is then used to select the smaller value from each lane, returning a new vector with these minimum values.
- **Output**: A vector of type `wv_t` containing the minimum values from each corresponding lane of the input vectors `a` and `b`.


---
### wv\_max<!-- {{#callable:wv_max}} -->
The `wv_max` function returns a vector containing the maximum values from corresponding lanes of two input vectors.
- **Inputs**:
    - `a`: A vector of type `wv_t` containing unsigned 64-bit integers.
    - `b`: A vector of type `wv_t` containing unsigned 64-bit integers.
- **Control Flow**:
    - The function calls `wv_gt(a, b)` to compare each lane of vector `a` with the corresponding lane of vector `b` to determine which is greater.
    - It then uses `wv_if` to select the greater value from each lane, returning a new vector with the maximum values.
- **Output**: A vector of type `wv_t` where each lane contains the maximum value from the corresponding lanes of the input vectors `a` and `b`.


---
### wv\_to\_wf<!-- {{#callable:wv_to_wf}} -->
The `wv_to_wf` function converts a vector of unsigned 64-bit integers to a vector of single-precision floating-point numbers, inserting the result into a specified position of an existing vector.
- **Inputs**:
    - `v`: A vector of type `wv_t` containing four unsigned 64-bit integers.
    - `f`: A vector of type `wf_t` where the converted floating-point values will be inserted.
    - `imm_hi`: An integer that determines the position in the vector `f` where the converted values will be inserted; if non-zero, the values are inserted into the high half, otherwise into the low half.
- **Control Flow**:
    - The function begins by storing the input vector `v` into a union `t` that allows access to its elements as an array of unsigned long integers.
    - Each element of `t` is then cast to a float and stored in a union `u` that allows access to its elements as an array of floats.
    - A 128-bit vector `w` is loaded with the floating-point values from `u`.
    - Depending on the value of `imm_hi`, the function inserts the 128-bit vector `w` into either the high or low half of the 256-bit vector `f` using `_mm256_insertf128_ps`.
- **Output**: The function returns a vector of type `wf_t` with the converted floating-point values inserted into the specified half of the input vector `f`.


---
### wv\_to\_wi<!-- {{#callable:wv_to_wi}} -->
The `wv_to_wi` function converts a vector of unsigned 64-bit integers to a vector of signed 32-bit integers, inserting the result into a specified half of a destination vector.
- **Inputs**:
    - `v`: A vector of unsigned 64-bit integers (`wv_t`) to be converted.
    - `i`: A destination vector of signed 32-bit integers (`wi_t`) where the result will be inserted.
    - `imm_hi`: An integer flag indicating whether to insert the result into the high (1) or low (0) half of the destination vector.
- **Control Flow**:
    - Extracts the lower 128 bits of the input vector `v` and casts it to a 128-bit float vector `v01`.
    - Extracts the upper 128 bits of the input vector `v` and casts it to a 128-bit float vector `v23`.
    - Shuffles the elements of `v01` and `v23` to create a new 128-bit integer vector `w`.
    - Depending on the value of `imm_hi`, inserts `w` into either the high or low 128 bits of the destination vector `i`.
- **Output**: Returns a vector of signed 32-bit integers (`wv_t`) with the converted values inserted into the specified half.


---
### wv\_to\_wu<!-- {{#callable:wv_to_wu}} -->
The `wv_to_wu` function converts a vector of unsigned 64-bit integers into a vector of unsigned 32-bit integers, optionally inserting the result into the high or low half of a destination vector.
- **Inputs**:
    - `v`: A vector of type `wv_t` containing four unsigned 64-bit integers.
    - `u`: A vector of type `wu_t` where the result will be inserted.
    - `imm_hi`: An integer flag indicating whether to insert the result into the high (1) or low (0) half of the destination vector `u`.
- **Control Flow**:
    - Extracts the lower 128 bits from the input vector `v` and casts it to a 128-bit floating-point vector `v01`.
    - Extracts the upper 128 bits from the input vector `v` and casts it to a 128-bit floating-point vector `v23`.
    - Shuffles the elements of `v01` and `v23` to create a new 128-bit integer vector `w` containing the lower 32 bits of each 64-bit integer from `v`.
    - Depending on the value of `imm_hi`, inserts `w` into either the high or low half of the destination vector `u`.
- **Output**: Returns a vector of type `wu_t` with the converted and inserted values.


---
### wv\_to\_wd<!-- {{#callable:wv_to_wd}} -->
The `wv_to_wd` function converts a vector of four 64-bit unsigned integers into a vector of four 64-bit double-precision floating-point numbers.
- **Inputs**:
    - `v`: A vector of four 64-bit unsigned integers (`wv_t`).
- **Control Flow**:
    - The function uses a union to store the input vector `v` into an array of four unsigned long integers.
    - Each element of this array is then cast to a double and stored in another union that holds an array of four doubles.
    - Finally, the function loads these doubles into a 256-bit vector of doubles and returns it.
- **Output**: A vector of four 64-bit double-precision floating-point numbers (`wd_t`).


---
### wv\_sum\_all<!-- {{#callable:wv_sum_all}} -->
The `wv_sum_all` function computes the sum of all elements in a 256-bit vector of unsigned 64-bit integers and broadcasts the result across all lanes of the vector.
- **Inputs**:
    - `x`: A 256-bit vector of unsigned 64-bit integers (`wv_t`) containing the elements to be summed.
- **Control Flow**:
    - The function first adds the two 128-bit halves of the input vector `x` using `_mm256_add_epi64` and `_mm256_permute2f128_si256` to rearrange the halves.
    - It then adds the resulting vector to itself after permuting the elements within each 128-bit half using `_mm256_permute_pd` and `_mm256_castsi256_pd` to ensure all elements are summed.
    - The final result is a vector where each lane contains the sum of all original elements in `x`.
- **Output**: A 256-bit vector (`wv_t`) where each lane contains the sum of all elements in the input vector `x`.


---
### wv\_min\_all<!-- {{#callable:wv_min_all}} -->
The `wv_min_all` function computes the minimum value across all lanes of a 256-bit vector of unsigned 64-bit integers and broadcasts this minimum value to all lanes of the resulting vector.
- **Inputs**:
    - `x`: A 256-bit vector (`wv_t`) containing four unsigned 64-bit integers.
- **Control Flow**:
    - The function first uses [`wv_min`](#wv_min) to compare the input vector `x` with a permuted version of itself, where the high and low 128-bit lanes are swapped, to find the minimum value between these lanes.
    - It then further reduces the vector by comparing it with another permuted version, where the elements within each 128-bit lane are shuffled, to find the overall minimum value.
    - The final result is a vector where all lanes contain the minimum value found across the original input vector.
- **Output**: A 256-bit vector (`wv_t`) where each lane contains the minimum value found in the input vector `x`.
- **Functions called**:
    - [`wv_min`](#wv_min)


---
### wv\_max\_all<!-- {{#callable:wv_max_all}} -->
The `wv_max_all` function computes the maximum value across all lanes of a vector and broadcasts this maximum value to all lanes of the resulting vector.
- **Inputs**:
    - `x`: A vector of type `wv_t` containing four 64-bit unsigned integers.
- **Control Flow**:
    - The function first uses [`wv_max`](#wv_max) to compare the input vector `x` with a permuted version of itself, where the high and low 128-bit lanes are swapped, to find the maximum value between these lanes.
    - It then uses [`wv_max`](#wv_max) again to compare the result with another permuted version of the vector, where the elements are shuffled within the 128-bit lanes, to find the maximum value across all elements.
    - The final result is a vector where all lanes contain the maximum value found across the original vector `x`.
- **Output**: A vector of type `wv_t` where all lanes contain the maximum value found in the input vector `x`.
- **Functions called**:
    - [`wv_max`](#wv_max)


---
### wv\_gather<!-- {{#callable:wv_gather}} -->
The `wv_gather` function gathers 64-bit integer elements from a base array using indices from a vector, with a compile-time decision on which half of the vector to use based on the `imm_hi` flag.
- **Inputs**:
    - `b`: A pointer to an array of unsigned long integers (ulong const *), serving as the base array from which elements are gathered.
    - `i`: A vector of indices (wi_t) used to specify which elements to gather from the base array.
    - `imm_hi`: An integer flag that determines which half of the index vector to use; if non-zero, the higher half is used, otherwise the lower half is used.
- **Control Flow**:
    - The function checks the value of `imm_hi` to decide which half of the index vector `i` to use.
    - If `imm_hi` is non-zero, it extracts the higher 128-bit half of the vector `i` and uses it to gather elements from the base array `b`.
    - If `imm_hi` is zero, it extracts the lower 128-bit half of the vector `i` and uses it to gather elements from the base array `b`.
    - The function returns the gathered elements as a vector of 64-bit integers.
- **Output**: The function returns a vector of 64-bit integers (wv_t) containing the gathered elements from the base array `b`.



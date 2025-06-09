# Purpose
This C source code file provides a specialized set of macros and inline functions for handling vector operations using AVX (Advanced Vector Extensions) intrinsics, specifically targeting operations on vectors of 64-bit integers. The file defines a type `wl_t` as a vector of four 64-bit integers using the `__m256i` type, which is a fundamental AVX data type. The code includes a variety of operations such as vector construction, memory operations, arithmetic, binary, logical, and conditional operations, as well as conversions between different vector types. These operations are implemented using AVX intrinsics, which allow for efficient parallel processing by leveraging the SIMD (Single Instruction, Multiple Data) capabilities of modern CPUs.

The file is intended to be included indirectly through a header file named `fd_avx.h`, as indicated by the preprocessor directive at the beginning. This suggests that the file is part of a larger library or framework that provides AVX-based utilities. The code is structured to provide a consistent API for vector operations, with a focus on performance and compatibility across different compilers and hardware capabilities. It includes conditional compilation to handle differences between compilers (e.g., GCC and Clang) and hardware features (e.g., AVX512). The use of macros and inline functions ensures that the operations are both efficient and flexible, allowing for compile-time optimizations and reducing the overhead associated with function calls.
# Functions

---
### wl\_bcast\_pair<!-- {{#callable:wl_bcast_pair}} -->
The `wl_bcast_pair` function creates a 256-bit vector with two long integers repeated in an alternating pattern.
- **Inputs**:
    - `l0`: The first long integer to be broadcasted in the vector.
    - `l1`: The second long integer to be broadcasted in the vector.
- **Control Flow**:
    - The function takes two long integers, l0 and l1, as input parameters.
    - It uses the `_mm256_setr_epi64x` intrinsic to create a 256-bit vector with the pattern [l0, l1, l0, l1].
    - The function returns this vector.
- **Output**: A 256-bit vector (`wl_t`) containing the pattern [l0, l1, l0, l1].


---
### wl\_bcast\_wide<!-- {{#callable:wl_bcast_wide}} -->
The `wl_bcast_wide` function creates a vector of four 64-bit integers where the first two elements are copies of the first input and the last two elements are copies of the second input.
- **Inputs**:
    - `l0`: The first long integer to be broadcasted into the first two elements of the vector.
    - `l1`: The second long integer to be broadcasted into the last two elements of the vector.
- **Control Flow**:
    - The function takes two long integer inputs, `l0` and `l1`.
    - It uses the `_mm256_setr_epi64x` intrinsic to create a 256-bit vector (`__m256i`) with four 64-bit integer lanes.
    - The first two lanes of the vector are set to `l0`, and the last two lanes are set to `l1`.
    - The function returns this constructed vector.
- **Output**: A 256-bit vector (`__m256i`) containing four 64-bit integers, with the first two elements set to `l0` and the last two elements set to `l1`.


---
### wl\_permute<!-- {{#callable:wl_permute}} -->
The `wl_permute` function rearranges the elements of a 256-bit vector of four 64-bit integers based on specified indices.
- **Inputs**:
    - `x`: A 256-bit vector (`wl_t`) containing four 64-bit integers.
    - `imm_i0`: An integer index (0-3) specifying which element of `x` to place in the first position of the result.
    - `imm_i1`: An integer index (0-3) specifying which element of `x` to place in the second position of the result.
    - `imm_i2`: An integer index (0-3) specifying which element of `x` to place in the third position of the result.
    - `imm_i3`: An integer index (0-3) specifying which element of `x` to place in the fourth position of the result.
- **Control Flow**:
    - The function begins by storing the input vector `x` into a union `t` that allows access to the vector's elements as an array of four long integers.
    - The function then creates another union `u` to store the permuted result.
    - Each element of `u.l` is assigned a value from `t.l` based on the indices `imm_i0`, `imm_i1`, `imm_i2`, and `imm_i3`.
    - Finally, the function loads the permuted elements from `u` back into a 256-bit vector and returns it.
- **Output**: A 256-bit vector (`wl_t`) with its elements rearranged according to the specified indices.


---
### wl\_ld<!-- {{#callable:wl_ld}} -->
The `wl_ld` function loads a 256-bit vector of four 64-bit integers from a 32-byte aligned memory location.
- **Inputs**:
    - `p`: A pointer to a constant long integer, representing the 32-byte aligned memory location from which the vector is to be loaded.
- **Control Flow**:
    - The function casts the input pointer `p` to a pointer of type `__m256i const *`.
    - It then uses the `_mm256_load_si256` intrinsic to load a 256-bit vector from the memory location pointed to by the casted pointer.
- **Output**: A `wl_t` type, which is a 256-bit vector containing four 64-bit integers loaded from the specified memory location.


---
### wl\_st<!-- {{#callable:wl_st}} -->
The `wl_st` function stores a vector of four 64-bit integers into a 32-byte aligned memory location.
- **Inputs**:
    - `p`: A pointer to a 32-byte aligned memory location where the vector will be stored.
    - `i`: A vector of type `wl_t` (which is an alias for `__m256i`) containing four 64-bit integers to be stored.
- **Control Flow**:
    - The function uses the `_mm256_store_si256` intrinsic to store the vector `i` into the memory location pointed to by `p`.
- **Output**: The function does not return any value; it performs a side effect by storing data in memory.


---
### wl\_ldu<!-- {{#callable:wl_ldu}} -->
The `wl_ldu` function loads a 256-bit vector of integers from an unaligned memory address into a `wl_t` type using AVX2 intrinsics.
- **Inputs**:
    - `p`: A pointer to a memory location from which a 256-bit vector of integers will be loaded; the memory does not need to be aligned.
- **Control Flow**:
    - The function casts the input pointer `p` to a pointer of type `__m256i const *`.
    - It then uses the `_mm256_loadu_si256` intrinsic to load a 256-bit vector from the memory location pointed to by the casted pointer.
- **Output**: The function returns a `wl_t` type, which is a 256-bit vector containing the loaded integers.


---
### wl\_stu<!-- {{#callable:wl_stu}} -->
The `wl_stu` function stores a vector of four 64-bit integers into a memory location that does not need to be aligned.
- **Inputs**:
    - `p`: A pointer to the memory location where the vector will be stored; alignment is not required.
    - `i`: A vector of type `wl_t` (which is an alias for `__m256i`) containing four 64-bit integers to be stored.
- **Control Flow**:
    - The function uses the `_mm256_storeu_si256` intrinsic to store the vector `i` into the memory location pointed to by `p`.
- **Output**: The function does not return any value; it performs an in-place operation on the memory location pointed to by `p`.


---
### wl\_extract\_variable<!-- {{#callable:wl_extract_variable}} -->
The `wl_extract_variable` function extracts a specific 64-bit integer from a vector of four 64-bit integers based on a given index.
- **Inputs**:
    - `a`: A vector of type `wl_t` (which is an alias for `__m256i`) containing four 64-bit integers.
    - `n`: An integer index specifying which of the four 64-bit integers to extract from the vector, where `n` should be in the range 0 to 3.
- **Control Flow**:
    - A union is defined with two members: an array of `__m256i` and an array of `long` integers, both of size 4.
    - The vector `a` is stored into the `__m256i` member of the union using `_mm256_store_si256`.
    - The function returns the `n`-th element from the `long` array member of the union, effectively extracting the `n`-th 64-bit integer from the vector.
- **Output**: The function returns a `long` integer, which is the `n`-th 64-bit integer extracted from the input vector `a`.


---
### wl\_insert\_variable<!-- {{#callable:wl_insert_variable}} -->
The `wl_insert_variable` function replaces a specified element in a 256-bit vector of four 64-bit integers with a new value and returns the modified vector.
- **Inputs**:
    - `a`: A 256-bit vector (`wl_t`) containing four 64-bit integers.
    - `n`: An integer index (0 to 3) indicating which element in the vector to replace.
    - `v`: A 64-bit integer value to insert into the vector at the specified index.
- **Control Flow**:
    - A union is defined to facilitate type punning between a 256-bit vector and an array of four 64-bit integers.
    - The input vector `a` is stored into the union's vector member, allowing access to its elements as an array of longs.
    - The element at index `n` in the array is replaced with the new value `v`.
    - The modified array is then loaded back into a 256-bit vector and returned.
- **Output**: A 256-bit vector (`wl_t`) with the specified element replaced by the new value.


---
### wl\_rol<!-- {{#callable:wl_rol}} -->
The `wl_rol` function performs a bitwise left rotation on each 64-bit integer in a vector of four 64-bit integers by a specified number of bits.
- **Inputs**:
    - `a`: A vector of four 64-bit integers (type `wl_t`) to be rotated.
    - `imm`: An integer specifying the number of bits to rotate each 64-bit integer in the vector to the left.
- **Control Flow**:
    - The function takes a vector `a` and an integer `imm` as inputs.
    - It calculates `imm & 63` to ensure the rotation amount is within the range of 0 to 63 bits.
    - It performs a left shift on the vector `a` by `imm & 63` bits using `wl_shl`.
    - It performs a right logical shift on the vector `a` by `(-imm) & 63` bits using `wl_shru`.
    - It combines the results of the left and right shifts using a bitwise OR operation with `wl_or`.
    - The result is returned as the output of the function.
- **Output**: A vector of four 64-bit integers (type `wl_t`) where each integer has been left-rotated by the specified number of bits.


---
### wl\_ror<!-- {{#callable:wl_ror}} -->
The `wl_ror` function performs a bitwise right rotation on each 64-bit lane of a vector long (`wl_t`) by a specified number of bits.
- **Inputs**:
    - `a`: A vector long (`wl_t`) where each lane is a signed 64-bit integer to be rotated.
    - `imm`: An integer specifying the number of bits to rotate each lane to the right.
- **Control Flow**:
    - The function calculates `imm & 63` to ensure the rotation amount is within the valid range of 0 to 63 bits.
    - It performs an unsigned right shift on the vector `a` by the calculated shift amount using `wl_shru`.
    - It performs a left shift on the vector `a` by the complement of the calculated shift amount using `wl_shl`.
    - The results of the two shifts are combined using a bitwise OR operation with `wl_or` to complete the rotation.
- **Output**: A vector long (`wl_t`) with each lane rotated to the right by the specified number of bits.


---
### wl\_rol\_variable<!-- {{#callable:wl_rol_variable}} -->
The `wl_rol_variable` function performs a variable bitwise left rotation on a vector of 64-bit integers using AVX intrinsics.
- **Inputs**:
    - `a`: A vector of 64-bit integers (`wl_t`) to be rotated.
    - `n`: An integer specifying the number of positions to rotate the vector `a` to the left.
- **Control Flow**:
    - The function calculates `n & 63` to ensure the rotation count is within the valid range of 0 to 63 bits.
    - It performs a left shift on the vector `a` by `n & 63` bits using `wl_shl_variable`.
    - It performs a right shift on the vector `a` by `(-n) & 63` bits using `wl_shru_variable`.
    - The results of the left and right shifts are combined using a bitwise OR operation with `wl_or`.
- **Output**: The function returns a vector of 64-bit integers (`wl_t`) that is the result of rotating the input vector `a` to the left by `n` positions.


---
### wl\_ror\_variable<!-- {{#callable:wl_ror_variable}} -->
The `wl_ror_variable` function performs a variable bitwise right rotation on a vector of 64-bit integers.
- **Inputs**:
    - `a`: A vector of 64-bit integers (`wl_t`) to be rotated.
    - `n`: An integer specifying the number of positions to rotate the vector `a` to the right.
- **Control Flow**:
    - The function calculates `n & 63` to ensure the rotation amount is within the range of 0 to 63 bits.
    - It performs an unsigned right shift on `a` by `n & 63` bits using `wl_shru_variable`.
    - It performs a left shift on `a` by `(-n) & 63` bits using `wl_shl_variable`.
    - The results of the two shifts are combined using a bitwise OR operation with `wl_or`.
- **Output**: The function returns a vector of 64-bit integers (`wl_t`) that is the result of rotating the input vector `a` to the right by `n` positions.


---
### wl\_rol\_vector<!-- {{#callable:wl_rol_vector}} -->
The `wl_rol_vector` function performs a bitwise rotate left operation on each 64-bit integer in a vector, using another vector to specify the number of positions to rotate.
- **Inputs**:
    - `a`: A vector of 64-bit integers (`wl_t`) to be rotated.
    - `b`: A vector of 64-bit integers (`wl_t`) specifying the number of positions to rotate each corresponding element in `a`.
- **Control Flow**:
    - Broadcast the constant 63 into a vector `m` using `wl_bcast` to ensure shifts are within 0-63 range.
    - Compute the bitwise AND of `b` and `m` to get the effective left shift amounts for each element.
    - Compute the bitwise AND of the negation of `b` and `m` to get the effective right shift amounts for each element.
    - Perform a left shift on `a` using the effective left shift amounts with `wl_shl_vector`.
    - Perform a right shift on `a` using the effective right shift amounts with `wl_shru_vector`.
    - Combine the results of the left and right shifts using a bitwise OR with `wl_or` to achieve the rotate left effect.
- **Output**: A vector of 64-bit integers (`wl_t`) where each element is the result of rotating the corresponding element in `a` left by the number of positions specified in `b`.


---
### wl\_ror\_vector<!-- {{#callable:wl_ror_vector}} -->
The `wl_ror_vector` function performs a bitwise right rotation on each 64-bit element of a vector `a` by the corresponding amount specified in vector `b`, using AVX2 intrinsics.
- **Inputs**:
    - `a`: A vector of type `wl_t` containing four 64-bit signed integers, which are the values to be rotated.
    - `b`: A vector of type `wl_t` containing four 64-bit signed integers, which specify the number of positions to rotate the corresponding elements in `a` to the right.
- **Control Flow**:
    - Create a vector `m` with all elements set to 63 using `wl_bcast(63L)` to mask the shift amounts.
    - Compute the bitwise AND of vector `b` and `m` to ensure the shift amounts are within the range of 0 to 63.
    - Perform a logical right shift on vector `a` by the masked shift amounts using `wl_shru_vector`.
    - Compute the bitwise AND of the negated vector `b` and `m` to determine the complementary left shift amounts.
    - Perform a logical left shift on vector `a` by the complementary shift amounts using `wl_shl_vector`.
    - Combine the results of the right and left shifts using a bitwise OR operation with `wl_or`.
- **Output**: A vector of type `wl_t` containing the result of the bitwise right rotation for each element of `a` by the corresponding element in `b`.


---
### wl\_abs<!-- {{#callable:wl_abs}} -->
The `wl_abs` function computes the absolute value of each element in a vector of signed 64-bit integers.
- **Inputs**:
    - `a`: A vector of signed 64-bit integers (`wl_t`) for which the absolute values are to be computed.
- **Control Flow**:
    - The function checks if each element in the vector `a` is less than zero using `wl_lt(a, wl_zero())`.
    - If an element is less than zero, it negates the element using `wl_neg(a)`.
    - If an element is not less than zero, it retains the original value of the element.
    - The function uses `wl_if` to select between the negated value and the original value based on the condition check, effectively computing the absolute value.
- **Output**: A vector of signed 64-bit integers (`wl_t`) where each element is the absolute value of the corresponding element in the input vector `a`.


---
### wl\_min<!-- {{#callable:wl_min}} -->
The `wl_min` function returns a vector containing the minimum values from corresponding lanes of two input vector longs.
- **Inputs**:
    - `a`: A vector long (`wl_t`) containing four signed 64-bit integers.
    - `b`: A vector long (`wl_t`) containing four signed 64-bit integers.
- **Control Flow**:
    - The function uses the `wl_lt` macro to compare each lane of vector `a` with the corresponding lane of vector `b` to create a condition vector.
    - The `wl_if` macro is then used to select the value from `a` if the condition is true (i.e., `a` is less than `b`), otherwise it selects the value from `b`.
    - The result is a new vector long where each lane contains the minimum value from the corresponding lanes of `a` and `b`.
- **Output**: A vector long (`wl_t`) where each lane contains the minimum value from the corresponding lanes of the input vectors `a` and `b`.


---
### wl\_max<!-- {{#callable:wl_max}} -->
The `wl_max` function returns a vector containing the maximum values from corresponding lanes of two input vector longs.
- **Inputs**:
    - `a`: A vector long (`wl_t`) containing four signed 64-bit integers.
    - `b`: A vector long (`wl_t`) containing four signed 64-bit integers.
- **Control Flow**:
    - The function compares each corresponding pair of 64-bit integers in vectors `a` and `b` using the `wl_gt` macro, which checks if elements in `a` are greater than those in `b`.
    - It uses the `wl_if` macro to select elements from `a` where the condition is true (i.e., `a` is greater than `b`) and from `b` where the condition is false.
- **Output**: A vector long (`wl_t`) containing the maximum values from each pair of corresponding lanes in `a` and `b`.


---
### wl\_shr<!-- {{#callable:wl_shr}} -->
The `wl_shr` function performs an arithmetic right shift on a vector of signed 64-bit integers, treating negative numbers correctly by using a two's complement approach.
- **Inputs**:
    - `a`: A vector of signed 64-bit integers (`wl_t`) to be right-shifted.
    - `imm`: An integer representing the number of bits to shift, which should be a compile-time constant between 0 and 63.
- **Control Flow**:
    - Determine if each element in vector `a` is negative by comparing it to zero, resulting in a vector `c` where each element is either 0 or -1 (binary compatible with `wl_t`).
    - Perform a bitwise XOR between `a` and `c` to prepare for the arithmetic shift, effectively flipping the bits of negative numbers to handle two's complement representation.
    - Right shift the result of the XOR operation by `imm` bits using `_mm256_srli_epi64`, treating the numbers as unsigned for the shift operation.
    - Perform another XOR with `c` to restore the correct two's complement representation of the shifted numbers.
    - Return the final result as a vector of signed 64-bit integers.
- **Output**: A vector of signed 64-bit integers (`wl_t`) that is the result of the arithmetic right shift of the input vector `a` by `imm` bits.


---
### wl\_shr\_variable<!-- {{#callable:wl_shr_variable}} -->
The `wl_shr_variable` function performs an arithmetic right shift on a vector of signed 64-bit integers by a variable number of bits, handling negative numbers correctly.
- **Inputs**:
    - `a`: A vector of signed 64-bit integers (`wl_t`) to be right-shifted.
    - `n`: An integer specifying the number of bits to shift each element in the vector `a` to the right.
- **Control Flow**:
    - Determine if each element in vector `a` is negative by comparing it to zero, storing the result in `c`.
    - Perform a bitwise XOR between `a` and `c` to prepare for the shift operation, effectively converting negative numbers to their two's complement positive form.
    - Shift the prepared vector right by `n` bits using `_mm256_srl_epi64`, where `n` is inserted into a zeroed 128-bit vector at position 0.
    - Perform a bitwise XOR between the shifted result and `c` to convert the result back to the correct signed form, ensuring that the arithmetic shift is correctly applied to negative numbers.
- **Output**: A vector of signed 64-bit integers (`wl_t`) where each element is the result of an arithmetic right shift of the corresponding element in `a` by `n` bits.


---
### wl\_shr\_vector<!-- {{#callable:wl_shr_vector}} -->
The `wl_shr_vector` function performs an arithmetic right shift on a vector of signed 64-bit integers, handling negative values correctly by using a two's complement approach.
- **Inputs**:
    - `a`: A vector of signed 64-bit integers (`wl_t`) to be right-shifted.
    - `n`: A vector of unsigned 64-bit integers (`wl_t`) representing the number of bits to shift each corresponding element in `a`.
- **Control Flow**:
    - Determine if each element in vector `a` is negative by comparing it to zero, storing the result in `c`.
    - Perform a bitwise XOR between `a` and `c` to prepare for the arithmetic shift, effectively flipping the bits of negative numbers to handle two's complement.
    - Use `_mm256_srlv_epi64` to perform a logical right shift on the XORed result by the number of bits specified in `n`.
    - Perform another XOR with `c` to restore the original sign of the numbers, completing the arithmetic right shift.
- **Output**: A vector of signed 64-bit integers (`wl_t`) where each element has been right-shifted by the corresponding number of bits specified in `n`, with negative numbers handled correctly using two's complement.


---
### wl\_to\_wf<!-- {{#callable:wl_to_wf}} -->
The `wl_to_wf` function converts a vector of long integers to a vector of floats and inserts it into a specified position in an existing float vector.
- **Inputs**:
    - `l`: A vector of long integers (`wl_t`) to be converted to floats.
    - `f`: A vector of floats (`wf_t`) where the converted floats will be inserted.
    - `imm_hi`: An integer flag indicating the position (0 or 1) in the float vector `f` where the converted floats should be inserted.
- **Control Flow**:
    - Store the long integer vector `l` into a temporary union `t` for conversion.
    - Convert each long integer in `t` to a float and store them in a union `u`.
    - Load the converted floats from `u` into a 128-bit float vector `v`.
    - Depending on the value of `imm_hi`, insert the 128-bit float vector `v` into the lower or upper half of the 256-bit float vector `f`.
- **Output**: A 256-bit float vector (`wf_t`) with the converted floats from `l` inserted into the specified position in `f`.


---
### wl\_to\_wi<!-- {{#callable:wl_to_wi}} -->
The `wl_to_wi` function converts a vector of 64-bit integers to a vector of 32-bit integers, inserting the result into a specified half of a destination vector.
- **Inputs**:
    - `l`: A `wl_t` type vector containing four 64-bit integers.
    - `i`: A `wi_t` type vector where the converted integers will be inserted.
    - `imm_hi`: An integer flag indicating whether to insert the result into the high (1) or low (0) half of the destination vector.
- **Control Flow**:
    - Extracts the lower 128 bits of the input vector `l` and casts it to a 128-bit float vector `v01`.
    - Extracts the upper 128 bits of the input vector `l` and casts it to a 128-bit float vector `v23`.
    - Shuffles the elements of `v01` and `v23` to create a new 128-bit integer vector `v`.
    - Depending on the value of `imm_hi`, inserts `v` into either the high or low 128 bits of the destination vector `i`.
- **Output**: Returns a `wl_t` vector with the converted 32-bit integers inserted into the specified half of the destination vector.


---
### wl\_to\_wu<!-- {{#callable:wl_to_wu}} -->
The `wl_to_wu` function converts a vector of signed 64-bit integers to a vector of unsigned 32-bit integers, inserting the result into a specified position of an existing vector.
- **Inputs**:
    - `l`: A vector of signed 64-bit integers (`wl_t`) to be converted.
    - `u`: A vector of unsigned 32-bit integers (`wu_t`) where the converted values will be inserted.
    - `imm_hi`: An integer flag indicating whether to insert the converted values into the high (1) or low (0) 128-bit lane of the vector `u`.
- **Control Flow**:
    - Extract the lower 128 bits of the input vector `l` and cast it to a 128-bit floating-point vector `v01`.
    - Extract the upper 128 bits of the input vector `l` and cast it to a 128-bit floating-point vector `v23`.
    - Shuffle the elements of `v01` and `v23` to create a new 128-bit integer vector `v` containing the lower 32 bits of each 64-bit integer from `l`.
    - Depending on the value of `imm_hi`, insert `v` into either the high or low 128-bit lane of the vector `u`.
- **Output**: A vector of unsigned 32-bit integers (`wu_t`) with the converted values from `l` inserted into the specified lane.


---
### wl\_to\_wd<!-- {{#callable:wl_to_wd}} -->
The `wl_to_wd` function converts a vector of four 64-bit integers into a vector of four 64-bit double-precision floating-point numbers.
- **Inputs**:
    - `l`: A vector of four 64-bit signed integers (`wl_t`).
- **Control Flow**:
    - The function uses a union to store the input vector `l` into an array of four 64-bit integers.
    - It then converts each of these integers to a double-precision floating-point number, storing them in another union.
    - Finally, it loads these doubles into a 256-bit vector of doubles and returns it.
- **Output**: A 256-bit vector of four double-precision floating-point numbers (`wd_t`).


---
### wl\_sum\_all<!-- {{#callable:wl_sum_all}} -->
The `wl_sum_all` function computes the sum of all elements in a vector of 64-bit integers and returns a vector where each element is the computed sum.
- **Inputs**:
    - `x`: A vector of 64-bit integers (`wl_t`) containing four elements to be summed.
- **Control Flow**:
    - The function first adds the two halves of the vector `x` using `_mm256_add_epi64` and `_mm256_permute2f128_si256` to rearrange the elements.
    - It then adds the resulting vector to itself after permuting the elements with `_mm256_permute_pd` to ensure all elements are summed together.
    - The final result is a vector where each element is the sum of the original vector's elements.
- **Output**: A vector (`wl_t`) where each element is the sum of all elements in the input vector `x`.


---
### wl\_min\_all<!-- {{#callable:wl_min_all}} -->
The `wl_min_all` function computes the minimum value across all elements of a vector of 64-bit integers and broadcasts this minimum value across all elements of the vector.
- **Inputs**:
    - `x`: A vector of type `wl_t` containing four 64-bit signed integers.
- **Control Flow**:
    - The function first computes the minimum of the input vector `x` and a permuted version of itself using `_mm256_permute2f128_si256`, which swaps the lower and upper 128-bit lanes of the vector.
    - It then computes the minimum of the resulting vector and another permuted version of itself using `_mm256_permute_pd`, which permutes the elements within the 128-bit lanes.
    - The final result is a vector where all elements are the minimum value found in the original vector `x`.
- **Output**: A vector of type `wl_t` where all elements are the minimum value found in the input vector `x`.
- **Functions called**:
    - [`wl_min`](#wl_min)


---
### wl\_max\_all<!-- {{#callable:wl_max_all}} -->
The `wl_max_all` function computes the maximum value across all elements of a vector of 64-bit integers and broadcasts this maximum value to all elements of the vector.
- **Inputs**:
    - `x`: A vector of type `wl_t` containing four 64-bit signed integers.
- **Control Flow**:
    - The function first uses [`wl_max`](#wl_max) to compare the input vector `x` with a permuted version of itself, where the high and low 128-bit lanes are swapped, to find the maximum value between these lanes.
    - It then uses [`wl_max`](#wl_max) again to compare the result with another permuted version of the vector, where the elements are shuffled to compare across the remaining elements, ensuring the maximum value is found across all elements.
    - The final result is a vector where all elements are set to the maximum value found.
- **Output**: A vector of type `wl_t` where all four 64-bit integers are set to the maximum value found in the input vector `x`.
- **Functions called**:
    - [`wl_max`](#wl_max)


---
### wl\_gather<!-- {{#callable:wl_gather}} -->
The `wl_gather` function retrieves a vector of 64-bit integers from a base array using indices from a vector, with the choice of indices determined by a compile-time constant.
- **Inputs**:
    - `b`: A pointer to a constant array of long integers, serving as the base array from which values are gathered.
    - `i`: A vector of indices (`wi_t` type) used to specify which elements to gather from the base array.
    - `imm_hi`: An integer that acts as a compile-time constant to determine which half of the index vector to use for gathering.
- **Control Flow**:
    - The function checks the value of `imm_hi` to decide which half of the index vector `i` to use.
    - If `imm_hi` is non-zero, it extracts the second half of the index vector `i` using `_mm256_extractf128_si256(i, 1)` and uses it to gather elements from the base array `b`.
    - If `imm_hi` is zero, it extracts the first half of the index vector `i` using `_mm256_extractf128_si256(i, 0)` and uses it to gather elements from the base array `b`.
    - The gathered elements are returned as a vector of 64-bit integers.
- **Output**: A vector of 64-bit integers (`wl_t` type) containing the gathered elements from the base array `b`.



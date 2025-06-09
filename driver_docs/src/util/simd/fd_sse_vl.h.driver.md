# Purpose
This C source code file provides a specialized API for handling vector operations on 64-bit signed integers using SIMD (Single Instruction, Multiple Data) instructions, specifically targeting Intel's SSE (Streaming SIMD Extensions) and AVX (Advanced Vector Extensions) instruction sets. The file defines a set of macros and inline functions to perform various operations on vectors of two 64-bit integers, encapsulated in the `__m128i` data type. The operations include vector construction, memory loading and storing, arithmetic operations (such as addition, subtraction, and negation), bitwise operations (like AND, OR, XOR), logical comparisons, and conditional operations. Additionally, the file provides conversion functions to transform these vector long types into other vector types, such as floating-point or integer vectors, and includes reduction operations to compute sums, minimums, and maximums across vector elements.

The code is structured to ensure compatibility with different levels of SIMD support, using conditional compilation to leverage AVX-512 features when available, while providing emulations for missing operations in earlier instruction sets. The file is intended to be included indirectly through a header file (`fd_sse.h`), as indicated by the initial preprocessor directive, which enforces this inclusion pattern. This design suggests that the file is part of a larger library or framework that provides SIMD utilities, and it is likely intended for use in performance-critical applications where vectorized operations can significantly enhance computational efficiency. The use of macros and inline functions aims to minimize overhead and maximize the potential for compiler optimizations, making the API both robust and efficient for developers working with low-level data processing tasks.
# Functions

---
### vl\_ld<!-- {{#callable:vl_ld}} -->
The `vl_ld` function loads a 128-bit vector of two 64-bit integers from a 16-byte aligned memory location into a `vl_t` type.
- **Inputs**:
    - `p`: A pointer to a constant long integer, representing the 16-byte aligned memory location from which the vector long is to be loaded.
- **Control Flow**:
    - The function casts the input pointer `p` to a pointer of type `__m128i const *`.
    - It then uses the `_mm_load_si128` intrinsic to load the 128-bit data from the memory location pointed to by the casted pointer.
- **Output**: A `vl_t` type, which is a 128-bit vector containing two 64-bit integers loaded from the specified memory location.


---
### vl\_st<!-- {{#callable:vl_st}} -->
The `vl_st` function stores a vector long (`vl_t`) into a 16-byte aligned memory location pointed to by a long pointer.
- **Inputs**:
    - `p`: A pointer to a long where the vector long will be stored; it must be 16-byte aligned.
    - `i`: A vector long (`vl_t`) that contains the data to be stored at the memory location pointed to by `p`.
- **Control Flow**:
    - The function uses the `_mm_store_si128` intrinsic to store the vector long `i` into the memory location pointed to by `p`.
- **Output**: The function does not return any value; it performs a side effect by writing data to the memory location pointed to by `p`.


---
### vl\_ldu<!-- {{#callable:vl_ldu}} -->
The `vl_ldu` function loads a vector of two 64-bit integers from an unaligned memory address into a `vl_t` type using SIMD instructions.
- **Inputs**:
    - `p`: A pointer to a memory location from which the vector long is to be loaded; it does not need to be aligned.
- **Control Flow**:
    - The function casts the input pointer `p` to a pointer of type `__m128i const *`.
    - It then uses the `_mm_loadu_si128` intrinsic to load the data from the memory location pointed to by the casted pointer into a `__m128i` type, which is equivalent to `vl_t`.
- **Output**: The function returns a `vl_t` type, which is a vector containing two 64-bit integers loaded from the specified memory location.


---
### vl\_stu<!-- {{#callable:vl_stu}} -->
The `vl_stu` function stores a vector long (`vl_t`) into a memory location that does not need to be aligned.
- **Inputs**:
    - `p`: A pointer to the memory location where the vector long will be stored; it does not need to be aligned.
    - `i`: The vector long (`vl_t`) to be stored at the memory location pointed to by `p`.
- **Control Flow**:
    - The function uses the `_mm_storeu_si128` intrinsic to store the vector long `i` into the memory location pointed to by `p`.
- **Output**: The function does not return any value; it performs a side effect by storing data in memory.


---
### vl\_extract\_variable<!-- {{#callable:vl_extract_variable}} -->
The `vl_extract_variable` function extracts a 64-bit integer from a specified lane of a vector long (`vl_t`).
- **Inputs**:
    - `a`: A vector long (`vl_t`), which is a 128-bit data type containing two 64-bit integers.
    - `n`: An integer specifying the lane (0 or 1) from which to extract the 64-bit integer.
- **Control Flow**:
    - A union is defined to allow type punning between `__m128i` and an array of two `long` integers.
    - The vector long `a` is stored into the union's `__m128i` member using `_mm_store_si128`.
    - The function returns the `n`-th element from the union's `long` array.
- **Output**: The function returns a `long` integer extracted from the specified lane of the input vector long.


---
### vl\_insert\_variable<!-- {{#callable:vl_insert_variable}} -->
The `vl_insert_variable` function replaces a specified element in a vector of two 64-bit integers with a new value and returns the updated vector.
- **Inputs**:
    - `a`: A vector of type `vl_t` (which is a `__m128i` type) containing two 64-bit integers.
    - `n`: An integer index (0 or 1) indicating which element in the vector `a` should be replaced.
    - `v`: A long integer value to insert into the vector at the specified index `n`.
- **Control Flow**:
    - A union `t` is declared to facilitate type punning between `__m128i` and an array of two long integers.
    - The vector `a` is stored into the `m` member of the union `t` using `_mm_store_si128`.
    - The element at index `n` in the `l` array of the union `t` is replaced with the value `v`.
    - The updated vector is loaded from the `m` member of the union `t` using `_mm_load_si128` and returned.
- **Output**: The function returns a `vl_t` vector with the specified element replaced by the new value.


---
### vl\_rol<!-- {{#callable:vl_rol}} -->
The `vl_rol` function performs a bitwise left rotation on a vector of two 64-bit integers by a specified number of bits.
- **Inputs**:
    - `a`: A vector of two 64-bit integers (type `vl_t`) to be rotated.
    - `imm`: An integer specifying the number of bits to rotate the vector to the left.
- **Control Flow**:
    - The function calculates the effective number of bits to rotate by taking `imm & 63`, ensuring the shift is within the 0-63 range.
    - It performs a left shift on the vector `a` by the calculated number of bits using `vl_shl`.
    - It performs a right logical shift on the vector `a` by the complement of the calculated number of bits using `vl_shru`.
    - The results of the left and right shifts are combined using a bitwise OR operation with `vl_or` to complete the rotation.
- **Output**: The function returns a vector of two 64-bit integers (`vl_t`) that have been left-rotated by the specified number of bits.


---
### vl\_ror<!-- {{#callable:vl_ror}} -->
The `vl_ror` function performs a bitwise right rotation on a vector of two 64-bit integers by a specified number of bits.
- **Inputs**:
    - `a`: A vector of two 64-bit integers (of type `vl_t`) to be rotated.
    - `imm`: An integer specifying the number of bits to rotate the vector to the right.
- **Control Flow**:
    - The function calculates the effective number of bits to rotate by taking `imm & 63`, ensuring the shift amount is within the range of 0 to 63.
    - It performs an unsigned right shift on the vector `a` by the calculated number of bits using `vl_shru`.
    - It performs a left shift on the vector `a` by the complement of the calculated number of bits using `vl_shl`.
    - The results of the two shifts are combined using a bitwise OR operation with `vl_or`.
- **Output**: The function returns a new vector of type `vl_t` that is the result of the right rotation of the input vector `a` by `imm` bits.


---
### vl\_rol\_variable<!-- {{#callable:vl_rol_variable}} -->
The `vl_rol_variable` function performs a variable bitwise left rotation on a vector of two 64-bit integers.
- **Inputs**:
    - `a`: A `vl_t` type representing a vector of two 64-bit integers to be rotated.
    - `n`: An integer specifying the number of positions to rotate the bits to the left.
- **Control Flow**:
    - The function calculates `n & 63` to ensure the rotation count is within the range of 0 to 63 bits.
    - It performs a left shift on the vector `a` by `n & 63` bits using `vl_shl_variable`.
    - It performs a right shift on the vector `a` by `(-n) & 63` bits using `vl_shru_variable`.
    - The results of the left and right shifts are combined using a bitwise OR operation with `vl_or`.
- **Output**: The function returns a `vl_t` type, which is the result of the left rotation of the input vector `a` by `n` positions.


---
### vl\_ror\_variable<!-- {{#callable:vl_ror_variable}} -->
The `vl_ror_variable` function performs a variable right rotation on a vector of two 64-bit integers.
- **Inputs**:
    - `a`: A vector of two 64-bit integers (type `vl_t`) to be rotated.
    - `n`: An integer specifying the number of positions to rotate the vector to the right.
- **Control Flow**:
    - The function first calculates `n & 63` to ensure the rotation amount is within the range of 0 to 63 bits.
    - It then performs an unsigned right shift on the vector `a` by `n & 63` bits using `vl_shru_variable`.
    - Simultaneously, it performs a left shift on the vector `a` by `(-n) & 63` bits using `vl_shl_variable`.
    - The results of the two shifts are combined using a bitwise OR operation via `vl_or`.
    - The combined result is returned as the output of the function.
- **Output**: A vector of two 64-bit integers (type `vl_t`) that is the result of right rotating the input vector `a` by `n` positions.


---
### vl\_rol\_vector<!-- {{#callable:vl_rol_vector}} -->
The `vl_rol_vector` function performs a bitwise left rotation on each 64-bit integer in a vector by a specified number of bits, using another vector to determine the rotation amount for each integer.
- **Inputs**:
    - `a`: A vector of 64-bit integers (`vl_t`) to be rotated.
    - `b`: A vector of 64-bit integers (`vl_t`) specifying the number of bits to rotate each corresponding integer in vector `a`.
- **Control Flow**:
    - Create a mask `m` with all bits set except the 6 least significant bits, using `vl_bcast(63L)`, to ensure the rotation amount is within 0 to 63 bits.
    - Perform a bitwise AND between vector `b` and mask `m` to limit the rotation amount to 0-63 bits for each element.
    - Perform a left shift on vector `a` by the masked rotation amounts using `vl_shl_vector`.
    - Perform a right shift on vector `a` by the negated masked rotation amounts using `vl_shru_vector`.
    - Combine the results of the left and right shifts using a bitwise OR operation with `vl_or` to achieve the rotation effect.
- **Output**: A vector of 64-bit integers (`vl_t`) where each integer has been left-rotated by the specified number of bits.


---
### vl\_ror\_vector<!-- {{#callable:vl_ror_vector}} -->
The `vl_ror_vector` function performs a bitwise right rotation on each 64-bit integer in a vector `a` by the corresponding amount specified in vector `b`, with rotation amounts masked to 63 bits.
- **Inputs**:
    - `a`: A vector of type `vl_t` containing two 64-bit integers to be rotated.
    - `b`: A vector of type `vl_t` containing two 64-bit integers specifying the number of positions to rotate the corresponding integers in `a`.
- **Control Flow**:
    - Create a mask `m` with all bits set except the 6 least significant bits (i.e., 63L) using `vl_bcast` to ensure rotation amounts are within 0-63.
    - Perform a bitwise AND between `b` and `m` to mask the rotation amounts, ensuring they are within the valid range.
    - Calculate the right-shifted version of `a` using `vl_shru_vector` with the masked rotation amounts.
    - Calculate the left-shifted version of `a` using `vl_shl_vector` with the negated and masked rotation amounts.
    - Combine the right-shifted and left-shifted results using `vl_or` to achieve the effect of a bitwise right rotation.
- **Output**: A vector of type `vl_t` containing the result of the bitwise right rotation of each 64-bit integer in `a` by the corresponding amount in `b`.


---
### vl\_abs<!-- {{#callable:vl_abs}} -->
The `vl_abs` function computes the absolute value of a vector long by conditionally negating negative elements.
- **Inputs**:
    - `a`: A vector long (`vl_t`) containing two signed 64-bit integers.
- **Control Flow**:
    - The function checks if the vector long `a` is less than zero using `vl_lt(a, vl_zero())`.
    - If `a` is less than zero, it negates `a` using `vl_neg(a)`.
    - If `a` is not less than zero, it returns `a` as is.
    - The function uses `vl_if` to select between the negated value and the original value based on the condition.
- **Output**: A vector long (`vl_t`) representing the absolute value of the input vector long `a`.


---
### vl\_min<!-- {{#callable:vl_min}} -->
The `vl_min` function returns a vector containing the minimum values from corresponding lanes of two input vector longs.
- **Inputs**:
    - `a`: A vector long (`vl_t`) containing two signed 64-bit integers.
    - `b`: A vector long (`vl_t`) containing two signed 64-bit integers.
- **Control Flow**:
    - The function compares the two input vector longs `a` and `b` using the `vl_lt` macro to determine which vector has smaller values in each lane.
    - It then uses the `vl_if` macro to select the smaller value from each lane of the two vectors, returning a new vector long with the minimum values.
- **Output**: A vector long (`vl_t`) containing the minimum values from each corresponding lane of the input vectors `a` and `b`.


---
### vl\_max<!-- {{#callable:vl_max}} -->
The `vl_max` function returns a vector containing the maximum values from corresponding lanes of two input vector longs.
- **Inputs**:
    - `a`: A vector long (`vl_t`) containing two 64-bit signed integers.
    - `b`: A vector long (`vl_t`) containing two 64-bit signed integers.
- **Control Flow**:
    - The function uses the `vl_gt` macro to compare the two input vectors `a` and `b` element-wise, resulting in a vector condition.
    - The `vl_if` macro is then used to select elements from `a` or `b` based on the vector condition, effectively choosing the maximum value for each lane.
    - The result is returned as a new vector long containing the maximum values from each lane of the input vectors.
- **Output**: A vector long (`vl_t`) containing the maximum values from each corresponding lane of the input vectors `a` and `b`.


---
### vl\_shr<!-- {{#callable:vl_shr}} -->
The `vl_shr` function performs an arithmetic right shift on a vector of two 64-bit signed integers, treating the vector as signed integers and using a compile-time constant shift amount.
- **Inputs**:
    - `a`: A vector of two 64-bit signed integers (type `vl_t`).
    - `imm`: An integer representing the number of bits to shift, which should be a compile-time constant.
- **Control Flow**:
    - Determine if each element in vector `a` is negative by comparing it to zero, resulting in a vector `c` that acts as a mask.
    - Perform a bitwise XOR between `a` and `c` to prepare for the shift operation, effectively flipping the bits of negative numbers to handle the arithmetic shift correctly.
    - Right shift the result of the XOR operation by `imm` bits using `_mm_srli_epi64`, which treats the numbers as unsigned during the shift.
    - Perform another XOR with the mask `c` to restore the sign of the original numbers, completing the arithmetic right shift.
- **Output**: A vector of two 64-bit signed integers (type `vl_t`) that have been right-shifted by `imm` bits, with sign extension for negative numbers.


---
### vl\_shr\_variable<!-- {{#callable:vl_shr_variable}} -->
The `vl_shr_variable` function performs an arithmetic right shift on a vector of two 64-bit integers by a variable number of bits, while preserving the sign of the integers.
- **Inputs**:
    - `a`: A vector of two 64-bit signed integers (type `vl_t`) to be right-shifted.
    - `n`: An integer specifying the number of bits to shift the vector `a` to the right.
- **Control Flow**:
    - Determine if the vector `a` is negative by comparing it to zero, storing the result in `c`.
    - Perform a bitwise XOR between `a` and `c` to prepare for the arithmetic shift, effectively flipping the bits if `a` is negative.
    - Insert the shift amount `n` into a zero-initialized vector at the first position using `_mm_insert_epi64`.
    - Perform a logical right shift on the XOR result using `_mm_srl_epi64` with the shift amount vector.
    - XOR the shifted result with `c` to restore the sign of the original vector `a`.
- **Output**: Returns a vector of two 64-bit signed integers (`vl_t`) that is the result of the arithmetic right shift of `a` by `n` bits.


---
### vl\_shr\_vector<!-- {{#callable:vl_shr_vector}} -->
The `vl_shr_vector` function performs an arithmetic right shift on a vector of signed 64-bit integers, taking into account the sign of the integers.
- **Inputs**:
    - `a`: A vector of signed 64-bit integers (vl_t) to be right-shifted.
    - `n`: A vector of unsigned 64-bit integers (vl_t) representing the number of positions to shift each corresponding element in 'a'.
- **Control Flow**:
    - Determine if each element in vector 'a' is negative by comparing it to zero, storing the result in 'c'.
    - Perform a bitwise XOR between 'a' and 'c' to prepare for the shift operation, effectively flipping the bits of negative numbers.
    - Use the intrinsic `_mm_srlv_epi64` to perform a logical right shift on the XORed result by the amounts specified in 'n'.
    - Perform another bitwise XOR between the shifted result and 'c' to restore the sign of the original negative numbers, completing the arithmetic shift.
- **Output**: A vector of signed 64-bit integers (vl_t) where each element is the result of an arithmetic right shift of the corresponding element in 'a' by the number of positions specified in 'n'.


---
### vl\_to\_vf<!-- {{#callable:vl_to_vf}} -->
The `vl_to_vf` function converts a vector of long integers to a vector of floats, inserting the converted values into specified positions of an existing float vector based on a control flag.
- **Inputs**:
    - `l`: A vector of long integers (`vl_t`) from which two 64-bit integers will be extracted and converted to floats.
    - `f`: A vector of floats (`vf_t`) into which the converted float values will be inserted.
    - `imm_hi`: An integer flag that determines the positions in the float vector `f` where the converted values will be inserted.
- **Control Flow**:
    - Extract the first 64-bit integer from the vector `l` and convert it to a float, storing it in `f0`.
    - Extract the second 64-bit integer from the vector `l` and convert it to a float, storing it in `f1`.
    - Check the value of `imm_hi`.
    - If `imm_hi` is true (non-zero), insert `f0` and `f1` into positions 2 and 3 of the float vector `f`, respectively.
    - If `imm_hi` is false (zero), insert `f0` and `f1` into positions 0 and 1 of the float vector `f`, respectively.
- **Output**: A vector of floats (`vf_t`) with the converted long integers inserted into specified positions.


---
### vl\_to\_vi<!-- {{#callable:vl_to_vi}} -->
The `vl_to_vi` function converts a vector of long integers to a vector of integers, optionally interleaving with another vector of integers based on a control flag.
- **Inputs**:
    - `l`: A vector of long integers (`vl_t`) to be converted.
    - `i`: A vector of integers (`vi_t`) to be interleaved with the converted long integers.
    - `imm_hi`: An integer flag that determines the interleaving pattern; if non-zero, a different shuffle pattern is applied.
- **Control Flow**:
    - Cast the vector of long integers `l` to a vector of floats `_l`.
    - Cast the vector of integers `i` to a vector of floats `_i`.
    - Check the `imm_hi` flag to determine the shuffle pattern.
    - If `imm_hi` is non-zero, shuffle `_i` and `_l` using the pattern `_MM_SHUFFLE(2,0,1,0)`.
    - If `imm_hi` is zero, shuffle `_l` and `_i` using the pattern `_MM_SHUFFLE(3,2,2,0)`.
    - Cast the shuffled vector of floats back to a vector of integers and return it.
- **Output**: A vector of integers (`vl_t`) resulting from the conversion and optional interleaving of the input vectors.


---
### vl\_to\_vu<!-- {{#callable:vl_to_vu}} -->
The `vl_to_vu` function converts a vector of signed 64-bit integers to a vector of unsigned 32-bit integers, optionally interleaving with another vector based on a control flag.
- **Inputs**:
    - `l`: A vector of signed 64-bit integers (`vl_t`) to be converted.
    - `u`: A vector of unsigned 32-bit integers (`vu_t`) to be interleaved with the converted vector.
    - `imm_hi`: An integer flag that determines the interleaving pattern of the vectors.
- **Control Flow**:
    - The function casts the input vector `l` to a vector of floats (`vf_t`) and assigns it to `_l`.
    - Similarly, it casts the input vector `u` to a vector of floats and assigns it to `_u`.
    - If `imm_hi` is true, it interleaves `_u` and `_l` using the shuffle pattern `_MM_SHUFFLE(2,0,1,0)`.
    - If `imm_hi` is false, it interleaves `_l` and `_u` using the shuffle pattern `_MM_SHUFFLE(3,2,2,0)`.
    - Finally, it casts the resulting float vector back to a vector of signed 64-bit integers and returns it.
- **Output**: A vector of signed 64-bit integers (`vl_t`) that represents the interleaved result of the conversion and shuffle operations.


---
### vl\_to\_vd<!-- {{#callable:vl_to_vd}} -->
The function `vl_to_vd` converts a vector of two 64-bit integers into a vector of two doubles.
- **Inputs**:
    - `l`: A vector of type `vl_t` containing two 64-bit signed integers.
- **Control Flow**:
    - The function extracts the first 64-bit integer from the input vector `l` and casts it to a double.
    - It then extracts the second 64-bit integer from the input vector `l` and casts it to a double.
    - The two doubles are combined into a vector of type `vd_t` using the `_mm_setr_pd` intrinsic.
- **Output**: A vector of type `vd_t` containing two doubles, each corresponding to the casted values of the 64-bit integers from the input vector.


---
### vl\_sum\_all<!-- {{#callable:vl_sum_all}} -->
The `vl_sum_all` function computes the sum of two 64-bit integers stored in a vector and returns a vector with both lanes containing this sum.
- **Inputs**:
    - `x`: A vector of type `vl_t` containing two 64-bit signed integers.
- **Control Flow**:
    - The function takes a vector `x` as input, which contains two 64-bit integers.
    - It uses `vl_permute` to swap the two integers in the vector, effectively creating a new vector with the integers in reverse order.
    - The function then adds the original vector `x` and the permuted vector using `vl_add`, resulting in a vector where each lane contains the sum of the two integers.
    - The result is returned as a vector with both lanes containing the sum of the original two integers.
- **Output**: A vector of type `vl_t` where both lanes contain the sum of the two integers from the input vector.


---
### vl\_min\_all<!-- {{#callable:vl_min_all}} -->
The `vl_min_all` function computes the minimum value of a vector of two 64-bit integers and broadcasts this minimum value across both lanes of the vector.
- **Inputs**:
    - `x`: A vector of type `vl_t` containing two 64-bit signed integers.
- **Control Flow**:
    - The function calls `vl_permute` on the input vector `x` with parameters `1` and `0`, effectively swapping the two lanes of the vector.
    - It then calls [`vl_min`](#vl_min) with the original vector `x` and the permuted vector to compute the minimum of the two integers in the vector.
    - The result of [`vl_min`](#vl_min) is returned, which is a vector where both lanes contain the minimum value of the original vector.
- **Output**: A vector of type `vl_t` where both lanes contain the minimum value of the input vector `x`.
- **Functions called**:
    - [`vl_min`](#vl_min)


---
### vl\_max\_all<!-- {{#callable:vl_max_all}} -->
The `vl_max_all` function returns a vector where each lane contains the maximum value from the input vector `x`.
- **Inputs**:
    - `x`: A vector of type `vl_t` containing two 64-bit signed integers.
- **Control Flow**:
    - The function calls `vl_permute` on `x` with parameters `1` and `0`, which swaps the two lanes of the vector.
    - It then calls [`vl_max`](#vl_max) with the original vector `x` and the permuted vector to compute the maximum of the two lanes.
    - The result of [`vl_max`](#vl_max) is returned, which is a vector where both lanes contain the maximum value from the original vector `x`.
- **Output**: A vector of type `vl_t` where both lanes contain the maximum value from the input vector `x`.
- **Functions called**:
    - [`vl_max`](#vl_max)


---
### \_vl\_gather<!-- {{#callable:_vl_gather}} -->
The function `_vl_gather` gathers 64-bit integers from a specified memory location using indices from a vector.
- **Inputs**:
    - `b`: A pointer to a constant array of long integers from which values will be gathered.
    - `i`: A vector of indices (`vi_t`) used to specify which elements to gather from the array `b`.
- **Control Flow**:
    - The function uses the `_mm_i32gather_epi64` intrinsic to gather 64-bit integers from the memory location pointed to by `b` using the indices specified in `i`.
    - The gathered integers are returned as a vector of type `vl_t`.
- **Output**: A vector of type `vl_t` containing the gathered 64-bit integers from the specified indices.



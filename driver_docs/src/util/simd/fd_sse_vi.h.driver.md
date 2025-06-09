# Purpose
This C source code file provides a comprehensive set of macros and inline functions for handling SIMD (Single Instruction, Multiple Data) operations on vectors of 32-bit integers using SSE (Streaming SIMD Extensions) intrinsics. The file defines a type `vi_t` as a vector of four 32-bit integers, leveraging the `__m128i` data type from the SSE instruction set. It includes a variety of operations such as vector construction, memory operations, arithmetic, binary, logical, conditional, conversion, reduction, and miscellaneous operations like gathering and transposing. The code is structured to offer efficient vectorized operations, which are crucial for performance-critical applications that require parallel processing capabilities.

The file is intended to be included indirectly through a header file named `fd_sse.h`, as indicated by the preprocessor directive at the beginning. This ensures that the SIMD operations are encapsulated and can be reused across different parts of a program. The macros and inline functions are designed to mirror other vector types (such as floating-point vectors) as closely as possible, providing a consistent API for developers. The use of macros over static inline functions is preferred where feasible to minimize the risk of compiler optimizations interfering with the intended behavior. This file does not define public APIs or external interfaces directly but rather serves as a utility for internal use within a larger system that requires SIMD processing capabilities.
# Functions

---
### vi\_bcast\_pair<!-- {{#callable:vi_bcast_pair}} -->
The `vi_bcast_pair` function creates a 128-bit vector with two pairs of 32-bit integers, where each pair consists of the same two integers repeated.
- **Inputs**:
    - `i0`: The first integer to be broadcasted in the vector.
    - `i1`: The second integer to be broadcasted in the vector.
- **Control Flow**:
    - The function takes two integer inputs, `i0` and `i1`.
    - It uses the `_mm_setr_epi32` intrinsic to create a 128-bit vector with the pattern `[i0, i1, i0, i1]`.
    - The function returns this vector.
- **Output**: A 128-bit vector of type `vi_t` (which is an alias for `__m128i`) containing the integers `[i0, i1, i0, i1]`.


---
### vi\_bcast\_wide<!-- {{#callable:vi_bcast_wide}} -->
The `vi_bcast_wide` function creates a vector of four 32-bit integers with the first two elements set to `i0` and the last two elements set to `i1`.
- **Inputs**:
    - `i0`: The first integer value to be broadcasted to the first two elements of the vector.
    - `i1`: The second integer value to be broadcasted to the last two elements of the vector.
- **Control Flow**:
    - The function takes two integer inputs, `i0` and `i1`.
    - It uses the `_mm_setr_epi32` intrinsic to create a 128-bit vector (`__m128i`) with the elements arranged as `[i0, i0, i1, i1]`.
    - The function returns this vector.
- **Output**: A 128-bit vector (`__m128i`) with the elements `[i0, i0, i1, i1]`.


---
### vi\_ld<!-- {{#callable:vi_ld}} -->
The `vi_ld` function loads a 128-bit vector of four 32-bit integers from a 16-byte aligned memory location into a SIMD register.
- **Inputs**:
    - `p`: A pointer to a 16-byte aligned memory location containing four 32-bit integers to be loaded.
- **Control Flow**:
    - The function takes a pointer `p` to a 16-byte aligned memory location.
    - It casts the pointer `p` to a pointer of type `__m128i const *`.
    - It uses the `_mm_load_si128` intrinsic to load the 128-bit data from the memory location into a SIMD register of type `vi_t` (which is defined as `__m128i`).
    - The loaded SIMD register is returned.
- **Output**: A `vi_t` type, which is a 128-bit SIMD register containing the four 32-bit integers loaded from the specified memory location.


---
### vi\_st<!-- {{#callable:vi_st}} -->
The `vi_st` function stores a vector of four 32-bit integers into a 16-byte aligned memory location.
- **Inputs**:
    - `p`: A pointer to an integer array where the vector will be stored; it must be 16-byte aligned.
    - `i`: A vector of type `vi_t` (which is an alias for `__m128i`) containing four 32-bit integers to be stored.
- **Control Flow**:
    - The function uses the `_mm_store_si128` intrinsic to store the vector `i` into the memory location pointed to by `p`.
- **Output**: The function does not return a value; it performs a side effect by writing to the memory location pointed to by `p`.


---
### vi\_ldu<!-- {{#callable:vi_ldu}} -->
The `vi_ldu` function loads a 128-bit vector of four 32-bit integers from an unaligned memory address into a SIMD register.
- **Inputs**:
    - `p`: A pointer to a memory location from which the 128-bit vector of four 32-bit integers will be loaded; the memory does not need to be aligned.
- **Control Flow**:
    - The function casts the input pointer `p` to a pointer of type `__m128i const *`, which is suitable for SIMD operations.
    - It then uses the `_mm_loadu_si128` intrinsic to load the 128-bit data from the unaligned memory location pointed to by `p` into a SIMD register.
- **Output**: The function returns a `vi_t` type, which is a 128-bit vector containing four 32-bit integers loaded from the specified memory location.


---
### vi\_stu<!-- {{#callable:vi_stu}} -->
The `vi_stu` function stores a vector of four 32-bit integers into a memory location that does not need to be aligned.
- **Inputs**:
    - `p`: A pointer to the memory location where the vector of integers will be stored; the location does not need to be aligned.
    - `i`: A vector of four 32-bit signed integers (of type `vi_t`) to be stored at the memory location pointed to by `p`.
- **Control Flow**:
    - The function uses the `_mm_storeu_si128` intrinsic to store the vector `i` into the memory location pointed to by `p`.
- **Output**: The function does not return any value; it performs a side effect by storing data in memory.


---
### vi\_extract\_variable<!-- {{#callable:vi_extract_variable}} -->
The `vi_extract_variable` function extracts an integer from a specified lane of a 128-bit SIMD vector of integers.
- **Inputs**:
    - `a`: A 128-bit SIMD vector (`vi_t`) containing four 32-bit integers.
    - `n`: An integer specifying the lane (0 to 3) from which to extract the integer.
- **Control Flow**:
    - A union is defined to allow type punning between a 128-bit SIMD vector and an array of four integers.
    - The SIMD vector `a` is stored into the union's `m` member using `_mm_store_si128`.
    - The integer at the specified lane `n` is accessed from the union's `i` array and returned.
- **Output**: The function returns the integer located at the specified lane `n` of the SIMD vector `a`.


---
### vi\_insert\_variable<!-- {{#callable:vi_insert_variable}} -->
The `vi_insert_variable` function replaces an integer at a specified index in a 128-bit SIMD vector with a new integer value.
- **Inputs**:
    - `a`: A 128-bit SIMD vector of type `vi_t` (alias for `__m128i`) containing four 32-bit integers.
    - `n`: An integer index (0 to 3) specifying which element in the vector `a` to replace.
    - `v`: An integer value to insert into the vector `a` at the specified index `n`.
- **Control Flow**:
    - A union is declared to facilitate type punning between `__m128i` and an array of four integers.
    - The SIMD vector `a` is stored into the union's `__m128i` member using `_mm_store_si128`.
    - The integer at index `n` in the union's integer array is replaced with the new value `v`.
    - The modified vector is loaded back from the union's `__m128i` member using `_mm_load_si128` and returned.
- **Output**: A 128-bit SIMD vector of type `vi_t` with the integer at index `n` replaced by `v`.


---
### vi\_rol<!-- {{#callable:vi_rol}} -->
The `vi_rol` function performs a bitwise left rotation on each 32-bit lane of a vector integer by a specified number of bits.
- **Inputs**:
    - `a`: A vector integer (`vi_t`) where each 32-bit lane holds a signed 32-bit two's-complement integer.
    - `imm`: An integer specifying the number of bits to rotate left, which is masked to 5 bits (0-31) to ensure valid rotation.
- **Control Flow**:
    - The function first calculates the left shift of the vector `a` by `imm & 31` bits using `vi_shl`.
    - It then calculates the right shift of the vector `a` by `(-imm) & 31` bits using `vi_shru`, effectively performing a left rotation.
    - The results of the left and right shifts are combined using a bitwise OR operation (`vi_or`) to produce the final rotated vector.
- **Output**: A vector integer (`vi_t`) with each 32-bit lane rotated left by the specified number of bits.


---
### vi\_ror<!-- {{#callable:vi_ror}} -->
The `vi_ror` function performs a bitwise right rotation on each 32-bit lane of a vector of integers by a specified number of bits.
- **Inputs**:
    - `a`: A vector of 32-bit signed integers (`vi_t`) on which the right rotation will be performed.
    - `imm`: An integer specifying the number of bits to rotate each lane of the vector to the right.
- **Control Flow**:
    - The function calculates the effective number of bits to rotate by taking `imm & 31`, ensuring the shift amount is within the range of 0 to 31 bits.
    - It performs an unsigned right shift on the vector `a` by the calculated number of bits using `vi_shru(a, imm & 31)`.
    - It performs a left shift on the vector `a` by the complement of the calculated number of bits using `vi_shl(a, (-imm) & 31)`.
    - The results of the two shifts are combined using a bitwise OR operation with `vi_or`.
- **Output**: The function returns a vector of 32-bit signed integers (`vi_t`) where each lane has been right-rotated by the specified number of bits.


---
### vi\_rol\_variable<!-- {{#callable:vi_rol_variable}} -->
The `vi_rol_variable` function performs a variable bitwise left rotation on each 32-bit lane of a vector integer.
- **Inputs**:
    - `a`: A vector integer (`vi_t`) where each 32-bit lane holds a signed 32-bit integer.
    - `n`: An integer specifying the number of bits to rotate left, which is masked to 5 bits (0-31) to ensure valid rotation.
- **Control Flow**:
    - The function first calculates the left shift of vector `a` by `n & 31` bits using `vi_shl_variable`.
    - It then calculates the right shift of vector `a` by `(-n) & 31` bits using `vi_shru_variable`.
    - The results of the left and right shifts are combined using a bitwise OR operation via `vi_or`.
- **Output**: The function returns a vector integer (`vi_t`) where each 32-bit lane has been rotated left by `n` bits.


---
### vi\_ror\_variable<!-- {{#callable:vi_ror_variable}} -->
The `vi_ror_variable` function performs a variable bitwise right rotation on a vector of 32-bit integers.
- **Inputs**:
    - `a`: A vector of 32-bit integers (`vi_t`) to be rotated.
    - `n`: An integer specifying the number of positions to rotate the vector `a` to the right.
- **Control Flow**:
    - The function calculates `n & 31` to ensure the rotation amount is within the range of 0 to 31 bits.
    - It performs an unsigned right shift on vector `a` by `n & 31` bits using `vi_shru_variable`.
    - It performs a left shift on vector `a` by `(-n) & 31` bits using `vi_shl_variable`.
    - The results of the two shifts are combined using a bitwise OR operation with `vi_or`.
    - The combined result is returned as the output of the function.
- **Output**: A vector of 32-bit integers (`vi_t`) that is the result of rotating the input vector `a` to the right by `n` positions.


---
### vi\_rol\_vector<!-- {{#callable:vi_rol_vector}} -->
The `vi_rol_vector` function performs a bitwise left rotation on each 32-bit lane of a vector `a` by the corresponding amount specified in vector `b`, using SIMD operations.
- **Inputs**:
    - `a`: A vector of type `vi_t` where each lane contains a signed 32-bit integer to be rotated.
    - `b`: A vector of type `vi_t` where each lane specifies the number of positions to rotate the corresponding lane in vector `a`.
- **Control Flow**:
    - Create a vector `m` with all lanes set to 31 using `vi_bcast(31)` to mask the shift amounts.
    - Compute the bitwise AND of vector `b` and `m` to ensure the shift amount is within 0 to 31, and use it to perform a left shift on vector `a` using `vi_shl_vector`.
    - Compute the bitwise AND of the negation of vector `b` and `m`, and use it to perform a right shift on vector `a` using `vi_shru_vector`.
    - Combine the results of the left and right shifts using a bitwise OR operation with `vi_or` to achieve the rotation effect.
- **Output**: A vector of type `vi_t` where each lane contains the result of rotating the corresponding lane in vector `a` by the amount specified in vector `b`.


---
### vi\_ror\_vector<!-- {{#callable:vi_ror_vector}} -->
The `vi_ror_vector` function performs a bitwise right rotation on each 32-bit lane of a vector `a` by the corresponding amount specified in vector `b`.
- **Inputs**:
    - `a`: A vector of type `vi_t` where each lane contains a signed 32-bit integer to be rotated.
    - `b`: A vector of type `vi_t` where each lane specifies the number of positions to rotate the corresponding lane in vector `a` to the right.
- **Control Flow**:
    - Broadcast the integer 31 to all lanes of a vector `m` using `vi_bcast(31)` to create a mask for the rotation amount.
    - Perform a bitwise AND between vector `b` and the mask `m` to ensure the rotation amount is within 0 to 31 bits.
    - Compute the right-shifted version of `a` using `vi_shru_vector(a, vi_and(b, m))`, which shifts each lane of `a` to the right by the amount specified in `b` masked by `m`.
    - Compute the left-shifted version of `a` using `vi_shl_vector(a, vi_and(vi_neg(b), m))`, which shifts each lane of `a` to the left by the negated amount specified in `b` masked by `m`.
    - Combine the results of the right and left shifts using a bitwise OR operation with `vi_or` to achieve the effect of a right rotation.
- **Output**: A vector of type `vi_t` where each lane contains the result of the right rotation of the corresponding lane in vector `a` by the amount specified in vector `b`.


---
### vi\_sum\_all<!-- {{#callable:vi_sum_all}} -->
The `vi_sum_all` function computes the sum of all elements in a 128-bit vector of four 32-bit integers and returns a vector with the sum broadcasted to all elements.
- **Inputs**:
    - `x`: A 128-bit vector of four 32-bit signed integers (vi_t) to be summed.
- **Control Flow**:
    - The function takes a vector `x` and applies the horizontal add intrinsic `_mm_hadd_epi32` to sum adjacent pairs of elements, resulting in a vector with two sums: `x01` and `x23`.
    - The function applies `_mm_hadd_epi32` again to the resulting vector, summing the two sums to produce a single sum `xsum` in the first element of the vector.
    - The function returns a vector with the sum `xsum` broadcasted to all four elements.
- **Output**: A 128-bit vector (vi_t) where each of the four 32-bit integers is the sum of the original vector's elements.


---
### vi\_min\_all<!-- {{#callable:vi_min_all}} -->
The `vi_min_all` function computes the minimum value across all lanes of a 128-bit vector of 32-bit integers and broadcasts this minimum value to all lanes of the vector.
- **Inputs**:
    - `x`: A 128-bit vector of 32-bit signed integers (`vi_t`).
- **Control Flow**:
    - Shuffle the input vector `x` to rearrange its elements using `_mm_shuffle_epi32` with the shuffle mask `_MM_SHUFFLE(1, 0, 3, 2)`, resulting in a new vector `y` with elements reordered as `[x2, x3, x0, x1]`.
    - Compute the element-wise minimum of `x` and `y` using `_mm_min_epi32`, updating `x` to contain the minimum values of the pairs `[x0, x2]` and `[x1, x3]`, resulting in `[x02, x13, ..., ...]`.
    - Shuffle the updated vector `x` again using `_mm_shuffle_epi32` with the shuffle mask `_MM_SHUFFLE(2, 3, 0, 1)`, resulting in a new vector `y` with elements reordered as `[x13, x02, ..., ...]`.
    - Compute the element-wise minimum of the updated `x` and `y` using `_mm_min_epi32`, updating `x` to contain the minimum value across all original elements, resulting in `[xmin, ..., ..., ...]`.
- **Output**: A 128-bit vector of 32-bit signed integers (`vi_t`) where all lanes contain the minimum value found in the input vector `x`.


---
### vi\_max\_all<!-- {{#callable:vi_max_all}} -->
The `vi_max_all` function computes the maximum value from a vector of four 32-bit integers and returns a vector with all elements set to this maximum value.
- **Inputs**:
    - `x`: A vector of four 32-bit signed integers (`vi_t`).
- **Control Flow**:
    - Shuffle the input vector `x` to rearrange its elements using `_mm_shuffle_epi32` with the shuffle mask `_MM_SHUFFLE(1, 0, 3, 2)`, resulting in a new vector `y`.
    - Compute the element-wise maximum of `x` and `y` using `_mm_max_epi32`, updating `x` to hold the maximum values of the pairs (x0, x2) and (x1, x3).
    - Shuffle the updated vector `x` again using `_mm_shuffle_epi32` with the shuffle mask `_MM_SHUFFLE(2, 3, 0, 1)`, resulting in a new vector `y`.
    - Compute the element-wise maximum of `x` and `y` again using `_mm_max_epi32`, updating `x` to hold the maximum value across all elements.
    - Return the vector `x`, which now contains the maximum value of the original vector in all four positions.
- **Output**: A vector (`vi_t`) where all four elements are set to the maximum value found in the input vector `x`.



# Purpose
This C source code file provides a specialized utility for handling SIMD (Single Instruction, Multiple Data) operations using SSE (Streaming SIMD Extensions) for vectorized processing of unsigned 32-bit integers. The file defines a set of macros and inline functions that facilitate the creation, manipulation, and conversion of 128-bit vectors (`__m128i`) where each lane holds a 32-bit unsigned integer. The code is structured to offer a comprehensive API for vector operations, including constructors, memory operations, arithmetic, binary, logical, and conditional operations, as well as conversions between different vector types. The use of macros and inline functions is emphasized to ensure efficient execution and to minimize the risk of compiler optimizations interfering with the intended operations.

The file is intended to be included indirectly through a header file (`fd_sse.h`), as indicated by the preprocessor directive at the beginning. This suggests that the code is part of a larger library or framework that provides SIMD utilities. The API is designed to be robust and mirrors other vector types (such as `vc` and `vf`) to maintain consistency across different data types. The file also includes advanced operations like vector permutation, element extraction and insertion, and matrix transposition, which are crucial for high-performance computing tasks that require parallel processing capabilities. The code is highly specialized and provides narrow functionality focused on SIMD operations, making it a valuable component for applications that require efficient data processing using vectorized instructions.
# Functions

---
### vu\_bcast\_pair<!-- {{#callable:vu_bcast_pair}} -->
The `vu_bcast_pair` function creates a vector of four 32-bit integers with the pattern [u0, u1, u0, u1] from two unsigned integers.
- **Inputs**:
    - `u0`: An unsigned 32-bit integer to be broadcasted to the first and third positions in the vector.
    - `u1`: An unsigned 32-bit integer to be broadcasted to the second and fourth positions in the vector.
- **Control Flow**:
    - Convert the unsigned integer u0 to a signed integer i0.
    - Convert the unsigned integer u1 to a signed integer i1.
    - Use the `_mm_setr_epi32` intrinsic to create a vector with the pattern [i0, i1, i0, i1].
- **Output**: A `vu_t` vector containing the integers [u0, u1, u0, u1] as 32-bit signed integers.


---
### vu\_bcast\_wide<!-- {{#callable:vu_bcast_wide}} -->
The `vu_bcast_wide` function creates a vector of four 32-bit integers where the first two elements are copies of the first input and the last two elements are copies of the second input.
- **Inputs**:
    - `u0`: An unsigned 32-bit integer to be broadcasted to the first two elements of the vector.
    - `u1`: An unsigned 32-bit integer to be broadcasted to the last two elements of the vector.
- **Control Flow**:
    - Convert the unsigned integer `u0` to a signed integer `i0`.
    - Convert the unsigned integer `u1` to a signed integer `i1`.
    - Use the `_mm_setr_epi32` intrinsic to create a vector with elements `[i0, i0, i1, i1]`.
- **Output**: A `vu_t` vector containing four 32-bit integers in the format `[u0, u0, u1, u1]`.


---
### vu\_ld<!-- {{#callable:vu_ld}} -->
The `vu_ld` function loads a 128-bit vector of four unsigned 32-bit integers from a 16-byte aligned memory location into a SIMD register.
- **Inputs**:
    - `p`: A pointer to a 16-byte aligned memory location containing four unsigned 32-bit integers.
- **Control Flow**:
    - The function casts the input pointer `p` to a pointer of type `__m128i const *`.
    - It then uses the `_mm_load_si128` intrinsic to load the 128-bit data from the memory location pointed to by `p` into a SIMD register.
- **Output**: A `vu_t` type, which is a 128-bit vector containing four unsigned 32-bit integers loaded from the specified memory location.


---
### vu\_st<!-- {{#callable:vu_st}} -->
The `vu_st` function stores a vector of unsigned 32-bit integers into a 16-byte aligned memory location.
- **Inputs**:
    - `p`: A pointer to a 16-byte aligned memory location where the vector will be stored.
    - `i`: A vector of type `vu_t` (which is an alias for `__m128i`) containing four unsigned 32-bit integers to be stored.
- **Control Flow**:
    - The function uses the intrinsic `_mm_store_si128` to store the vector `i` into the memory location pointed to by `p`.
- **Output**: The function does not return any value; it performs a side effect by storing data in memory.


---
### vu\_ldu<!-- {{#callable:vu_ldu}} -->
The `vu_ldu` function loads a 128-bit vector of unsigned 32-bit integers from an unaligned memory address into a SIMD register.
- **Inputs**:
    - `p`: A pointer to a memory location from which the 128-bit vector of unsigned 32-bit integers is to be loaded; the memory does not need to be aligned.
- **Control Flow**:
    - The function casts the input pointer `p` to a pointer of type `__m128i const *`, which is suitable for SIMD operations.
    - It then uses the `_mm_loadu_si128` intrinsic to load a 128-bit vector from the memory location pointed to by the casted pointer.
    - The loaded vector is returned as the result of the function.
- **Output**: A `vu_t` type, which is a 128-bit vector containing four unsigned 32-bit integers loaded from the specified memory location.


---
### vu\_stu<!-- {{#callable:vu_stu}} -->
The `vu_stu` function stores a vector of unsigned 32-bit integers into a memory location that does not need to be aligned.
- **Inputs**:
    - `p`: A pointer to the memory location where the vector will be stored; it does not need to be aligned.
    - `i`: A vector of unsigned 32-bit integers (`vu_t`) to be stored at the memory location pointed to by `p`.
- **Control Flow**:
    - The function uses the `_mm_storeu_si128` intrinsic to store the vector `i` into the memory location pointed to by `p`.
- **Output**: The function does not return any value; it performs a side effect by storing data in memory.


---
### vu\_extract\_variable<!-- {{#callable:vu_extract_variable}} -->
The `vu_extract_variable` function extracts a 32-bit unsigned integer from a specified lane of a 128-bit SIMD vector.
- **Inputs**:
    - `a`: A 128-bit SIMD vector of type `vu_t` containing four 32-bit unsigned integers.
    - `n`: An integer specifying the lane index (0 to 3) from which to extract the unsigned integer.
- **Control Flow**:
    - A union is defined to allow type punning between a 128-bit SIMD vector and an array of four unsigned integers.
    - The SIMD vector `a` is stored into the union's `__m128i` member using `_mm_store_si128`.
    - The function returns the `n`-th element from the union's unsigned integer array.
- **Output**: The function returns the 32-bit unsigned integer located at the specified lane index `n` of the input vector `a`.


---
### vu\_insert\_variable<!-- {{#callable:vu_insert_variable}} -->
The `vu_insert_variable` function replaces a specified element in a 128-bit vector of unsigned integers with a new value.
- **Inputs**:
    - `a`: A 128-bit vector of unsigned integers (`vu_t`) from which an element will be replaced.
    - `n`: An integer index (0 to 3) indicating which element in the vector `a` should be replaced.
    - `v`: An unsigned integer value that will replace the element at index `n` in the vector `a`.
- **Control Flow**:
    - The function begins by declaring a union `t` that can store a 128-bit vector or an array of four unsigned integers.
    - The vector `a` is stored into the union's 128-bit vector member using `_mm_store_si128`.
    - The element at index `n` in the union's unsigned integer array is replaced with the value `v`.
    - The modified 128-bit vector is then loaded back from the union and returned using `_mm_load_si128`.
- **Output**: A 128-bit vector (`vu_t`) with the element at index `n` replaced by the value `v`.


---
### vu\_rol<!-- {{#callable:vu_rol}} -->
The `vu_rol` function performs a bitwise left rotation on each 32-bit lane of a vector of unsigned integers by a specified number of bits.
- **Inputs**:
    - `a`: A vector of unsigned integers (`vu_t`) on which the rotation operation is to be performed.
    - `imm`: An integer specifying the number of bits to rotate each element of the vector to the left.
- **Control Flow**:
    - The function calculates the left shift of the vector `a` by `imm & 31` bits using `vu_shl`.
    - It calculates the right shift of the vector `a` by `(-imm) & 31` bits using `vu_shr`.
    - The results of the left and right shifts are combined using a bitwise OR operation with `vu_or`.
    - The combined result is returned as the output of the function.
- **Output**: A vector of unsigned integers (`vu_t`) where each element has been rotated left by the specified number of bits.


---
### vu\_ror<!-- {{#callable:vu_ror}} -->
The `vu_ror` function performs a bitwise right rotation on each 32-bit lane of a vector of unsigned integers by a specified number of bits.
- **Inputs**:
    - `a`: A vector of unsigned 32-bit integers (`vu_t`) on which the right rotation is to be performed.
    - `imm`: An integer specifying the number of bits to rotate each element of the vector to the right.
- **Control Flow**:
    - The function calculates the effective number of bits to rotate by taking `imm & 31`, ensuring the shift amount is within the range of 0 to 31 bits.
    - It performs a logical right shift on the vector `a` by the calculated number of bits using `vu_shr`.
    - It performs a logical left shift on the vector `a` by the complement of the calculated number of bits using `vu_shl`.
    - The results of the right and left shifts are combined using a bitwise OR operation via `vu_or` to complete the rotation.
- **Output**: The function returns a vector of unsigned 32-bit integers (`vu_t`) where each element has been rotated to the right by the specified number of bits.


---
### vu\_rol\_variable<!-- {{#callable:vu_rol_variable}} -->
The `vu_rol_variable` function performs a variable bitwise left rotation on a vector of unsigned 32-bit integers.
- **Inputs**:
    - `a`: A vector of unsigned 32-bit integers (`vu_t`) to be rotated.
    - `n`: An integer specifying the number of positions to rotate the vector `a` to the left.
- **Control Flow**:
    - The function calculates `n & 31` to ensure the rotation count is within the range of 0 to 31 bits.
    - It performs a left shift on the vector `a` by `n & 31` bits using `vu_shl_variable`.
    - It performs a right shift on the vector `a` by `(-n) & 31` bits using `vu_shr_variable`.
    - The results of the left and right shifts are combined using a bitwise OR operation with `vu_or`.
- **Output**: The function returns a vector of unsigned 32-bit integers (`vu_t`) that is the result of the left rotation of the input vector `a` by `n` positions.


---
### vu\_ror\_variable<!-- {{#callable:vu_ror_variable}} -->
The `vu_ror_variable` function performs a variable bitwise right rotation on a vector of unsigned 32-bit integers.
- **Inputs**:
    - `a`: A vector of unsigned 32-bit integers (`vu_t`) to be rotated.
    - `n`: An integer specifying the number of positions to rotate the vector `a` to the right.
- **Control Flow**:
    - The function calculates `n & 31` to ensure the rotation amount is within the range of 0 to 31 bits.
    - It calls `vu_shr_variable` to perform a right shift on `a` by `n & 31` bits.
    - It calls `vu_shl_variable` to perform a left shift on `a` by `(-n) & 31` bits.
    - It combines the results of the two shifts using `vu_or` to achieve the right rotation effect.
- **Output**: The function returns a vector of unsigned 32-bit integers (`vu_t`) that is the result of rotating the input vector `a` to the right by `n` positions.


---
### vu\_rol\_vector<!-- {{#callable:vu_rol_vector}} -->
The `vu_rol_vector` function performs a bitwise left rotation on each 32-bit lane of a vector of unsigned integers by a specified number of bits, where the number of bits to rotate is provided as a vector of signed integers.
- **Inputs**:
    - `a`: A vector of unsigned 32-bit integers (`vu_t`) to be rotated.
    - `b`: A vector of signed 32-bit integers (`vi_t`) specifying the number of bits to rotate each corresponding lane in `a`.
- **Control Flow**:
    - Broadcast the integer value 31 to all lanes of a vector `m` using `vi_bcast` to create a mask for bitwise operations.
    - Perform a bitwise AND between each lane of `b` and `m` to ensure the shift amount is within the range of 0 to 31, and use this result to left shift each lane of `a` using `vu_shl_vector`.
    - Negate each lane of `b`, perform a bitwise AND with `m`, and use this result to right shift each lane of `a` using `vu_shr_vector`.
    - Combine the results of the left and right shifts using a bitwise OR operation with `vu_or` to achieve the rotation effect.
- **Output**: A vector of unsigned 32-bit integers (`vu_t`) where each lane has been left rotated by the specified number of bits.


---
### vu\_ror\_vector<!-- {{#callable:vu_ror_vector}} -->
The `vu_ror_vector` function performs a bitwise right rotation on each 32-bit lane of a vector of unsigned integers by a specified number of bits, using another vector of integers to determine the rotation amount for each lane.
- **Inputs**:
    - `a`: A vector of unsigned 32-bit integers (`vu_t`) to be rotated.
    - `b`: A vector of signed 32-bit integers (`vi_t`) specifying the number of bits to rotate each corresponding lane in `a`.
- **Control Flow**:
    - Broadcast the integer value 31 to all lanes of a vector `m` using `vi_bcast` to create a mask for bitwise operations.
    - Perform a bitwise AND between each lane of `b` and `m` to ensure the rotation amount is within the range of 0 to 31 bits.
    - Use `vu_shr_vector` to perform a logical right shift on `a` by the masked values of `b`.
    - Negate `b` using `vi_neg`, mask it with `m`, and use `vu_shl_vector` to perform a logical left shift on `a` by these masked negated values.
    - Combine the results of the right and left shifts using `vu_or` to achieve the effect of a right rotation for each lane.
- **Output**: A vector of unsigned 32-bit integers (`vu_t`) where each lane has been right-rotated by the specified number of bits.


---
### vu\_bswap<!-- {{#callable:vu_bswap}} -->
The `vu_bswap` function performs a byte swap operation on a vector of unsigned 32-bit integers, effectively reversing the byte order within each 32-bit lane.
- **Inputs**:
    - `a`: A vector of unsigned 32-bit integers (`vu_t`) on which the byte swap operation is to be performed.
- **Control Flow**:
    - Create a mask `m` with the pattern [0x00FF00FF, 0x00FF00FF, 0x00FF00FF, 0x00FF00FF] using `vu_bcast` to isolate specific byte pairs.
    - Rotate the input vector `a` by 16 bits to swap 16-bit pairs, storing the result in `t`.
    - Perform a bitwise AND NOT operation between the mask `m` and the result of left-shifting `t` by 8 bits, isolating the swapped 8-bit pairs.
    - Perform a bitwise AND operation between the mask `m` and the result of right-shifting `t` by 8 bits, isolating the other swapped 8-bit pairs.
    - Combine the results of the previous two operations using a bitwise OR to produce the final byte-swapped vector.
- **Output**: A vector of unsigned 32-bit integers (`vu_t`) with the byte order reversed within each 32-bit lane.
- **Functions called**:
    - [`vu_rol`](#vu_rol)


---
### vu\_to\_vd\_core<!-- {{#callable:vu_to_vd_core}} -->
The `vu_to_vd_core` function converts a vector of unsigned 32-bit integers to a vector of double-precision floating-point numbers, handling values greater than 2^31 using two's complement and floating-point arithmetic tricks.
- **Inputs**:
    - `u`: A vector of unsigned 32-bit integers (`vu_t`) to be converted to double-precision floating-point numbers.
- **Control Flow**:
    - Compare each element of `u` with zero to determine if it is less than 2^31, storing the result in `c`.
    - Convert `u` to double-precision floating-point numbers, storing the result in `d`.
    - Add 2^32 to `d` to handle values greater than 2^31, storing the result in `ds`.
    - Convert `c` to a 64-bit integer vector `cl`.
    - Blend `d` and `ds` based on `cl` to produce the final result, effectively converting `u` to double-precision floating-point numbers.
- **Output**: A vector of double-precision floating-point numbers (`__m128d`) representing the converted values from the input vector `u`.


---
### vu\_to\_vf<!-- {{#callable:vu_to_vf}} -->
The `vu_to_vf` function converts a vector of unsigned 32-bit integers to a vector of single-precision floating-point numbers, ensuring correct rounding by first converting to double-precision.
- **Inputs**:
    - `u`: A vector of unsigned 32-bit integers (`vu_t`).
- **Control Flow**:
    - The function first converts the input vector `u` to a double-precision floating-point vector using [`vu_to_vd_core`](#vu_to_vd_core) and `vu_to_vd` functions.
    - The double-precision vector is then converted to a single-precision floating-point vector using `_mm_cvtpd_ps`.
    - The two resulting single-precision vectors are concatenated using `_mm_shuffle_ps` to form the final single-precision floating-point vector.
- **Output**: A vector of single-precision floating-point numbers (`vf_t`) representing the converted values from the input vector.
- **Functions called**:
    - [`vu_to_vd_core`](#vu_to_vd_core)


---
### vu\_sum\_all<!-- {{#callable:vu_sum_all}} -->
The `vu_sum_all` function computes the sum of all elements in a 128-bit vector of unsigned 32-bit integers and returns a vector where each lane contains this sum.
- **Inputs**:
    - `x`: A 128-bit vector of unsigned 32-bit integers (`vu_t`).
- **Control Flow**:
    - The function first applies the `_mm_hadd_epi32` intrinsic to horizontally add adjacent pairs of 32-bit integers in the vector `x`, resulting in a vector where the first two lanes contain the sums of the first and second pairs of the original vector.
    - The function then applies `_mm_hadd_epi32` again to the result, which sums the two values in the first two lanes, effectively computing the total sum of the original vector's elements.
    - The final result is a vector where each lane contains the total sum of the original vector's elements.
- **Output**: A 128-bit vector (`vu_t`) where each lane contains the sum of all elements in the input vector `x`.


---
### vu\_min\_all<!-- {{#callable:vu_min_all}} -->
The `vu_min_all` function computes the minimum value across all lanes of a vector of unsigned 32-bit integers and broadcasts this minimum value to all lanes of the resulting vector.
- **Inputs**:
    - `x`: A vector of unsigned 32-bit integers (`vu_t`) containing four lanes.
- **Control Flow**:
    - Shuffle the input vector `x` to rearrange its lanes using `_mm_shuffle_epi32` with the order (1, 0, 3, 2).
    - Compute the minimum of the original and shuffled vectors using `_mm_min_epu32`, resulting in a vector with the minimum values of pairs of lanes.
    - Shuffle the resulting vector again with the order (2, 3, 0, 1) to further rearrange the lanes.
    - Compute the minimum of the vector from the previous step and its shuffled version to find the overall minimum value across all lanes.
    - Return the vector with the minimum value broadcasted to all lanes.
- **Output**: A vector of unsigned 32-bit integers (`vu_t`) where all lanes contain the minimum value found in the input vector `x`.


---
### vu\_max\_all<!-- {{#callable:vu_max_all}} -->
The `vu_max_all` function computes the maximum value across all lanes of a 128-bit vector of unsigned 32-bit integers and broadcasts this maximum value to all lanes of the vector.
- **Inputs**:
    - `x`: A 128-bit vector of unsigned 32-bit integers (`vu_t`).
- **Control Flow**:
    - Shuffle the input vector `x` to rearrange its elements using `_mm_shuffle_epi32` with the shuffle mask `_MM_SHUFFLE(1, 0, 3, 2)`, resulting in a new vector `y`.
    - Compute the element-wise maximum of `x` and `y` using `_mm_max_epu32`, updating `x` to hold the maximum values of the first and second pairs of elements.
    - Shuffle the updated vector `x` again using `_mm_shuffle_epi32` with the shuffle mask `_MM_SHUFFLE(2, 3, 0, 1)`, resulting in a new vector `y`.
    - Compute the element-wise maximum of `x` and `y` again using `_mm_max_epu32`, updating `x` to hold the maximum value across all elements.
    - Return the vector `x`, which now contains the maximum value in all lanes.
- **Output**: A 128-bit vector (`vu_t`) where all lanes contain the maximum value found in the input vector `x`.


---
### vu\_gather<!-- {{#callable:vu_gather}} -->
The `vu_gather` function retrieves a vector of unsigned 32-bit integers from a base array using specified indices.
- **Inputs**:
    - `b`: A pointer to the base array of unsigned integers from which values are gathered.
    - `i`: A vector of indices (of type `vi_t`) specifying which elements to gather from the base array.
- **Control Flow**:
    - The function uses the `_mm_i32gather_epi32` intrinsic to gather elements from the base array `b` at positions specified by the vector `i`.
    - The gathered elements are returned as a vector of type `vu_t`.
- **Output**: A vector (`vu_t`) containing the gathered unsigned 32-bit integers from the specified indices of the base array.



# Purpose
This C source code file is a specialized utility for handling SIMD (Single Instruction, Multiple Data) operations using AVX (Advanced Vector Extensions) instructions, specifically targeting operations on vectors of unsigned 32-bit integers. The file defines a set of macros and inline functions that facilitate the creation, manipulation, and transformation of 256-bit wide vectors, where each vector consists of eight 32-bit unsigned integers. The code provides a comprehensive suite of operations, including vector construction, arithmetic operations, logical operations, memory operations, and conversions between different data types. It also includes specialized functions for vector permutation, broadcasting, and reduction operations, such as summing or finding the minimum or maximum value across all elements in a vector.

The file is intended to be included indirectly through a header file named `fd_avx.h`, as indicated by the preprocessor directive at the beginning. This suggests that the file is part of a larger library or framework that provides AVX-based SIMD utilities. The code is structured to maximize performance by leveraging AVX intrinsics, which are low-level operations that map directly to AVX instructions, allowing for efficient parallel processing of data. The use of macros and inline functions ensures that the operations are both flexible and efficient, minimizing overhead and enabling the compiler to optimize the generated machine code. The file does not define a public API or external interfaces directly but rather serves as an internal component of a broader SIMD utility library.
# Functions

---
### wu\_bcast\_pair<!-- {{#callable:wu_bcast_pair}} -->
The `wu_bcast_pair` function creates a 256-bit AVX vector with a repeated pattern of two unsigned integers.
- **Inputs**:
    - `u0`: An unsigned 32-bit integer to be broadcasted in the vector.
    - `u1`: Another unsigned 32-bit integer to be broadcasted in the vector.
- **Control Flow**:
    - Convert the unsigned integers `u0` and `u1` to signed integers `i0` and `i1`.
    - Use the `_mm256_setr_epi32` intrinsic to create a 256-bit vector with the pattern `[i0, i1, i0, i1, i0, i1, i0, i1]`.
- **Output**: A 256-bit AVX vector (`wu_t`) containing the pattern `[u0, u1, u0, u1, u0, u1, u0, u1]`.


---
### wu\_bcast\_lohi<!-- {{#callable:wu_bcast_lohi}} -->
The `wu_bcast_lohi` function creates a 256-bit vector with the first four lanes filled with the first input integer and the last four lanes filled with the second input integer.
- **Inputs**:
    - `u0`: An unsigned 32-bit integer to be broadcasted to the first four lanes of the vector.
    - `u1`: An unsigned 32-bit integer to be broadcasted to the last four lanes of the vector.
- **Control Flow**:
    - Convert the unsigned integer `u0` to a signed integer `i0`.
    - Convert the unsigned integer `u1` to a signed integer `i1`.
    - Use the `_mm256_setr_epi32` intrinsic to create a 256-bit vector with the first four lanes set to `i0` and the last four lanes set to `i1`.
- **Output**: A 256-bit vector (`wu_t`) with the first four lanes containing the integer value of `u0` and the last four lanes containing the integer value of `u1`.


---
### wu\_bcast\_quad<!-- {{#callable:wu_bcast_quad}} -->
The `wu_bcast_quad` function creates a 256-bit AVX vector with a repeated sequence of four unsigned 32-bit integers.
- **Inputs**:
    - `u0`: The first unsigned 32-bit integer to be included in the vector.
    - `u1`: The second unsigned 32-bit integer to be included in the vector.
    - `u2`: The third unsigned 32-bit integer to be included in the vector.
    - `u3`: The fourth unsigned 32-bit integer to be included in the vector.
- **Control Flow**:
    - Convert each of the input unsigned integers (u0, u1, u2, u3) to signed integers (i0, i1, i2, i3).
    - Use the `_mm256_setr_epi32` intrinsic to create a 256-bit AVX vector with the pattern [i0, i1, i2, i3, i0, i1, i2, i3].
- **Output**: A 256-bit AVX vector (`wu_t`) containing the sequence [u0, u1, u2, u3, u0, u1, u2, u3] as signed integers.


---
### wu\_bcast\_wide<!-- {{#callable:wu_bcast_wide}} -->
The `wu_bcast_wide` function creates a 256-bit AVX vector with each pair of consecutive lanes holding the same unsigned 32-bit integer from the input arguments.
- **Inputs**:
    - `u0`: An unsigned 32-bit integer to be broadcasted to the first two lanes of the vector.
    - `u1`: An unsigned 32-bit integer to be broadcasted to the third and fourth lanes of the vector.
    - `u2`: An unsigned 32-bit integer to be broadcasted to the fifth and sixth lanes of the vector.
    - `u3`: An unsigned 32-bit integer to be broadcasted to the seventh and eighth lanes of the vector.
- **Control Flow**:
    - Convert each input unsigned integer (u0, u1, u2, u3) to a signed integer (i0, i1, i2, i3).
    - Use the `_mm256_setr_epi32` intrinsic to create a 256-bit vector with the pattern [i0, i0, i1, i1, i2, i2, i3, i3].
    - Return the created vector.
- **Output**: A 256-bit AVX vector (`wu_t`) with the pattern [u0, u0, u1, u1, u2, u2, u3, u3], where each pair of lanes contains the same unsigned 32-bit integer.


---
### wu\_exch\_adj\_quad<!-- {{#callable:wu_exch_adj_quad}} -->
The `wu_exch_adj_quad` function rearranges the 32-bit integer lanes of a 256-bit vector by swapping the lower and upper 128-bit halves.
- **Inputs**:
    - `x`: A 256-bit vector of type `wu_t` (which is an alias for `__m256i`), containing eight 32-bit unsigned integers.
- **Control Flow**:
    - The function takes a 256-bit vector `x` as input.
    - It uses the `_mm256_permute2f128_si256` intrinsic to swap the lower and upper 128-bit halves of the vector `x`.
    - The intrinsic is called with the same vector `x` for both source operands and a control value of `1`, which specifies the permutation pattern.
- **Output**: A 256-bit vector of type `wu_t` with the lower and upper 128-bit halves swapped, effectively rearranging the lanes from [u0, u1, u2, u3, u4, u5, u6, u7] to [u4, u5, u6, u7, u0, u1, u2, u3].


---
### wu\_ld<!-- {{#callable:wu_ld}} -->
The `wu_ld` function loads a 256-bit vector of eight 32-bit unsigned integers from a 32-byte aligned memory location.
- **Inputs**:
    - `p`: A pointer to a 32-byte aligned memory location containing eight 32-bit unsigned integers.
- **Control Flow**:
    - The function casts the input pointer `p` to a pointer of type `__m256i const *`.
    - It then uses the `_mm256_load_si256` intrinsic to load the 256-bit vector from the memory location pointed to by the casted pointer.
- **Output**: A `wu_t` type, which is a 256-bit vector containing eight 32-bit unsigned integers loaded from the specified memory location.


---
### wu\_st<!-- {{#callable:wu_st}} -->
The `wu_st` function stores a vector of eight 32-bit unsigned integers into a 32-byte aligned memory location.
- **Inputs**:
    - `p`: A pointer to a 32-byte aligned memory location where the vector will be stored.
    - `i`: A vector of type `wu_t` (which is an alias for `__m256i`) containing eight 32-bit unsigned integers to be stored.
- **Control Flow**:
    - The function uses the `_mm256_store_si256` intrinsic to store the vector `i` into the memory location pointed to by `p`.
- **Output**: The function does not return any value; it performs a side effect by storing data in memory.


---
### wu\_ldu<!-- {{#callable:wu_ldu}} -->
The `wu_ldu` function loads an unaligned 256-bit vector of unsigned 32-bit integers from memory into a `wu_t` type using AVX2 intrinsics.
- **Inputs**:
    - `p`: A pointer to a memory location from which the 256-bit vector of unsigned 32-bit integers is to be loaded; the pointer does not need to be aligned.
- **Control Flow**:
    - The function casts the input pointer `p` to a pointer of type `__m256i const *`, which is suitable for AVX2 operations.
    - It then uses the `_mm256_loadu_si256` intrinsic to load a 256-bit vector from the memory location pointed to by the casted pointer.
- **Output**: The function returns a `wu_t` type, which is a 256-bit vector containing eight unsigned 32-bit integers loaded from the specified memory location.


---
### wu\_stu<!-- {{#callable:wu_stu}} -->
The `wu_stu` function stores a 256-bit vector of unsigned 32-bit integers to a memory location that does not need to be aligned.
- **Inputs**:
    - `p`: A pointer to the memory location where the 256-bit vector will be stored; alignment is not required.
    - `i`: A 256-bit vector of unsigned 32-bit integers (`wu_t`) to be stored at the memory location pointed to by `p`.
- **Control Flow**:
    - The function uses the `_mm256_storeu_si256` intrinsic to store the vector `i` at the memory location `p`.
- **Output**: The function does not return any value; it performs a side effect by storing data at the specified memory location.


---
### wu\_extract\_variable<!-- {{#callable:wu_extract_variable}} -->
The `wu_extract_variable` function extracts a specific unsigned 32-bit integer from a vector of eight such integers, based on a given index.
- **Inputs**:
    - `a`: A vector of type `wu_t` (which is an alias for `__m256i`) containing eight unsigned 32-bit integers.
    - `n`: An integer representing the index of the element to extract from the vector, where the index should be between 0 and 7.
- **Control Flow**:
    - A union is defined with two members: an array of `__m256i` and an array of `uint` with 8 elements.
    - The vector `a` is stored into the `m` member of the union using `_mm256_store_si256`.
    - The function returns the `n`-th element from the `u` member of the union, which corresponds to the `n`-th unsigned integer in the vector.
- **Output**: The function returns an unsigned 32-bit integer, which is the `n`-th element of the input vector `a`.


---
### wu\_insert\_variable<!-- {{#callable:wu_insert_variable}} -->
The `wu_insert_variable` function replaces a specific element in a 256-bit vector of unsigned integers with a new value at a specified index.
- **Inputs**:
    - `a`: A 256-bit vector of unsigned integers (`wu_t`) from which an element will be replaced.
    - `n`: An integer index (0 to 7) indicating the position in the vector where the new value will be inserted.
    - `v`: An unsigned integer value to be inserted into the vector at the specified index.
- **Control Flow**:
    - A union is declared to facilitate type punning between a 256-bit vector and an array of 8 unsigned integers.
    - The input vector `a` is stored into the union's 256-bit vector member using `_mm256_store_si256`.
    - The element at index `n` in the union's unsigned integer array is replaced with the new value `v`.
    - The modified 256-bit vector is loaded back from the union and returned using `_mm256_load_si256`.
- **Output**: A 256-bit vector (`wu_t`) with the element at index `n` replaced by the value `v`.


---
### wu\_rol<!-- {{#callable:wu_rol}} -->
The `wu_rol` function performs a bitwise left rotation on each 32-bit lane of a vector of unsigned integers by a specified number of bits.
- **Inputs**:
    - `a`: A vector of unsigned 32-bit integers (`wu_t`) on which the rotation is to be performed.
    - `imm`: An integer specifying the number of bits to rotate left; only the lower 5 bits are used, effectively limiting the rotation to a maximum of 31 bits.
- **Control Flow**:
    - The function calculates the effective rotation amount by taking the bitwise AND of `imm` with 31, ensuring the rotation is within 0 to 31 bits.
    - It performs a left shift on the vector `a` by the calculated rotation amount.
    - It performs a right shift on the vector `a` by the complement of the rotation amount (also masked with 31).
    - The results of the left and right shifts are combined using a bitwise OR operation to complete the rotation.
- **Output**: The function returns a vector of unsigned 32-bit integers (`wu_t`) where each element has been rotated left by the specified number of bits.


---
### wu\_ror<!-- {{#callable:wu_ror}} -->
The `wu_ror` function performs a bitwise right rotation on each 32-bit lane of a vector of unsigned integers by a specified number of bits.
- **Inputs**:
    - `a`: A vector of unsigned 32-bit integers (`wu_t`) on which the right rotation is to be performed.
    - `imm`: An integer specifying the number of bits to rotate each lane of the vector to the right.
- **Control Flow**:
    - The function calculates the effective number of bits to rotate by taking `imm & 31`, ensuring the rotation amount is within the range of 0 to 31 bits.
    - It performs a right shift on the vector `a` by the calculated number of bits using `wu_shr`.
    - It performs a left shift on the vector `a` by the complement of the calculated number of bits using `wu_shl`.
    - The results of the right and left shifts are combined using a bitwise OR operation (`wu_or`) to complete the rotation.
- **Output**: A vector of unsigned 32-bit integers (`wu_t`) where each lane has been right-rotated by the specified number of bits.


---
### wu\_rol\_variable<!-- {{#callable:wu_rol_variable}} -->
The `wu_rol_variable` function performs a variable bitwise left rotation on each 32-bit lane of a vector of unsigned integers.
- **Inputs**:
    - `a`: A vector of unsigned 32-bit integers (`wu_t`) to be rotated.
    - `n`: An integer specifying the number of positions to rotate each element in the vector to the left.
- **Control Flow**:
    - The function calculates `n & 31` to ensure the rotation amount is within the range of 0 to 31 bits.
    - It performs a left shift on the vector `a` by `n & 31` bits using `wu_shl_variable`.
    - It performs a right shift on the vector `a` by `(-n) & 31` bits using `wu_shr_variable`.
    - The results of the left and right shifts are combined using a bitwise OR operation with `wu_or`.
- **Output**: The function returns a vector of unsigned 32-bit integers (`wu_t`) where each element has been rotated left by `n` positions.


---
### wu\_ror\_variable<!-- {{#callable:wu_ror_variable}} -->
The `wu_ror_variable` function performs a variable bitwise right rotation on a vector of unsigned 32-bit integers.
- **Inputs**:
    - `a`: A vector of unsigned 32-bit integers (`wu_t`) to be rotated.
    - `n`: An integer specifying the number of positions to rotate the vector `a` to the right.
- **Control Flow**:
    - The function calculates `n & 31` to ensure the rotation amount is within the range of 0 to 31 bits.
    - It calls `wu_shr_variable(a, n & 31)` to perform a right shift on `a` by `n & 31` bits.
    - It calls `wu_shl_variable(a, (-n) & 31)` to perform a left shift on `a` by `(-n) & 31` bits.
    - The results of the two shifts are combined using a bitwise OR operation via `wu_or` to complete the rotation.
- **Output**: The function returns a vector of unsigned 32-bit integers (`wu_t`) that is the result of the right rotation of the input vector `a` by `n` positions.


---
### wu\_rol\_vector<!-- {{#callable:wu_rol_vector}} -->
The `wu_rol_vector` function performs a bitwise left rotation on each 32-bit lane of a vector of unsigned integers by a specified number of bits, using another vector to determine the rotation amount for each lane.
- **Inputs**:
    - `a`: A vector of unsigned 32-bit integers (`wu_t`) on which the bitwise left rotation is to be performed.
    - `b`: A vector of signed 32-bit integers (`wi_t`) specifying the number of bits to rotate each corresponding lane in vector `a`.
- **Control Flow**:
    - Broadcast the integer value 31 to all lanes of a vector `m` using `wi_bcast(31)` to create a mask for bitwise operations.
    - Perform a bitwise AND operation between vector `b` and the mask `m` to ensure the rotation amount is within the range [0, 31].
    - Shift the vector `a` left by the masked rotation amounts using `wu_shl_vector`.
    - Negate the vector `b`, mask it with `m`, and shift the vector `a` right by these masked amounts using `wu_shr_vector`.
    - Combine the results of the left and right shifts using a bitwise OR operation with `wu_or` to achieve the rotation effect.
- **Output**: A vector of unsigned 32-bit integers (`wu_t`) where each lane has been rotated left by the specified number of bits.


---
### wu\_ror\_vector<!-- {{#callable:wu_ror_vector}} -->
The `wu_ror_vector` function performs a bitwise right rotation on each 32-bit lane of a vector of unsigned integers by a specified number of bits, using another vector to determine the rotation amount for each lane.
- **Inputs**:
    - `a`: A vector of unsigned 32-bit integers (`wu_t`) to be rotated.
    - `b`: A vector of signed 32-bit integers (`wi_t`) specifying the number of bits to rotate each corresponding lane in `a`.
- **Control Flow**:
    - Broadcast the constant value 31 to all lanes of a vector `m` using `wi_bcast(31)`.
    - Perform a bitwise AND between each lane of `b` and `m` to ensure the rotation amount is within 0 to 31 bits.
    - Right shift each lane of `a` by the corresponding lane in the result of the AND operation using `wu_shr_vector`.
    - Negate each lane of `b`, perform a bitwise AND with `m`, and left shift each lane of `a` by the corresponding lane in this result using `wu_shl_vector`.
    - Combine the results of the right and left shifts using a bitwise OR operation with `wu_or` to achieve the rotation effect.
- **Output**: A vector of unsigned 32-bit integers (`wu_t`) where each lane has been right-rotated by the specified number of bits.


---
### wu\_bswap<!-- {{#callable:wu_bswap}} -->
The `wu_bswap` function performs a byte swap operation on a vector of unsigned 32-bit integers, effectively reversing the byte order within each 32-bit lane.
- **Inputs**:
    - `a`: A vector of unsigned 32-bit integers (`wu_t`) on which the byte swap operation is to be performed.
- **Control Flow**:
    - Create a mask `m` using `wu_bcast` with the value `0x00FF00FFU` to isolate specific byte positions.
    - Rotate the input vector `a` by 16 bits to swap 16-bit pairs, storing the result in `t`.
    - Perform a bitwise AND NOT operation between `m` and `t` shifted left by 8 bits, and a bitwise AND operation between `m` and `t` shifted right by 8 bits.
    - Combine the results of the previous operations using a bitwise OR to complete the byte swap, effectively swapping 8-bit pairs.
- **Output**: A vector of unsigned 32-bit integers (`wu_t`) with the byte order reversed within each 32-bit lane.
- **Functions called**:
    - [`wu_rol`](#wu_rol)


---
### wu\_to\_wd<!-- {{#callable:wu_to_wd}} -->
The `wu_to_wd` function converts a vector of unsigned 32-bit integers to a vector of double-precision floating-point numbers, handling values greater than 2^31 using two's complement and floating-point arithmetic tricks.
- **Inputs**:
    - `u`: A vector of unsigned 32-bit integers (`wu_t`) to be converted.
    - `imm_hi`: An integer flag indicating which half of the vector to process; 0 for the lower half and 1 for the upper half.
- **Control Flow**:
    - Extracts either the lower or upper 128-bit half of the input vector `u` based on `imm_hi` using `_mm256_extractf128_si256`.
    - Compares the extracted 128-bit integer vector to zero using `_mm_cmpgt_epi32` to create a mask `c` that is 0 if the value is less than 2^31 and -1 otherwise.
    - Converts the extracted 128-bit integer vector to a 256-bit double-precision floating-point vector `d` using `_mm256_cvtepi32_pd`.
    - Adds 2^32 to `d` to create `ds`, which corrects the conversion for values originally greater than 2^31.
    - Converts the mask `c` to a 256-bit integer vector `cl` using `_mm256_cvtepi32_epi64`.
    - Blends `d` and `ds` using `_mm256_blendv_pd` based on the mask `cl` to produce the final result.
- **Output**: A 256-bit vector of double-precision floating-point numbers (`__m256d`) representing the converted values from the input vector.


---
### wu\_to\_wf<!-- {{#callable:wu_to_wf}} -->
The `wu_to_wf` function converts a vector of unsigned 32-bit integers to a vector of single-precision floating-point numbers, handling potential roundoff errors by first converting to double-precision.
- **Inputs**:
    - `a`: A vector of unsigned 32-bit integers (`wu_t`).
- **Control Flow**:
    - The function calls [`wu_to_wd`](#wu_to_wd) twice to convert the lower and upper halves of the input vector `a` to double-precision floating-point numbers.
    - Each half is then converted to single-precision floating-point numbers using `_mm256_cvtpd_ps`.
    - The two resulting single-precision vectors are concatenated using `_mm256_setr_m128` to form the final result.
- **Output**: A vector of single-precision floating-point numbers (`wf_t`) corresponding to the input unsigned integers.
- **Functions called**:
    - [`wu_to_wd`](#wu_to_wd)


---
### wu\_sum\_all<!-- {{#callable:wu_sum_all}} -->
The `wu_sum_all` function computes the sum of all elements in a 256-bit vector of unsigned 32-bit integers and returns a vector where each lane contains this sum.
- **Inputs**:
    - `x`: A 256-bit vector (`wu_t`) containing eight unsigned 32-bit integers.
- **Control Flow**:
    - The function first adds the lower and upper 128-bit halves of the input vector `x` using `_mm256_add_epi32` and `_mm256_permute2f128_si256`, resulting in a vector where each lane contains the sum of corresponding elements from the two halves.
    - It then performs a horizontal addition on the vector using `_mm256_hadd_epi32`, which sums adjacent pairs of elements, reducing the vector to four sums.
    - Finally, another horizontal addition is performed to sum these four values into a single sum, which is then broadcasted across all lanes of the resulting vector.
- **Output**: A 256-bit vector (`wu_t`) where each lane contains the sum of all elements in the input vector `x`.


---
### wu\_min\_all<!-- {{#callable:wu_min_all}} -->
The `wu_min_all` function computes the minimum value across all lanes of a 256-bit vector of unsigned 32-bit integers and broadcasts this minimum value across all lanes of the vector.
- **Inputs**:
    - `x`: A 256-bit vector (`wu_t`) containing eight unsigned 32-bit integers.
- **Control Flow**:
    - Permute the input vector `x` to swap its two 128-bit halves, storing the result in `y`.
    - Compute the element-wise minimum of `x` and `y`, updating `x`.
    - Shuffle the elements of `x` to rearrange them, storing the result in `y`.
    - Compute the element-wise minimum of `x` and `y`, updating `x`.
    - Shuffle the elements of `x` again to rearrange them, storing the result in `y`.
    - Compute the element-wise minimum of `x` and `y`, updating `x` to contain the minimum value across all lanes.
- **Output**: A 256-bit vector (`wu_t`) where all lanes contain the minimum value found in the original input vector `x`.


---
### wu\_max\_all<!-- {{#callable:wu_max_all}} -->
The `wu_max_all` function computes the maximum value across all lanes of a 256-bit vector of unsigned 32-bit integers and broadcasts this maximum value to all lanes of the vector.
- **Inputs**:
    - `x`: A 256-bit vector (`wu_t`) containing eight unsigned 32-bit integers.
- **Control Flow**:
    - Permute the input vector `x` to swap its two 128-bit halves, storing the result in `y`.
    - Compute the element-wise maximum of `x` and `y`, updating `x`.
    - Shuffle the elements of `x` to rearrange them, storing the result in `y`.
    - Compute the element-wise maximum of `x` and `y`, updating `x`.
    - Shuffle the elements of `x` again to rearrange them, storing the result in `y`.
    - Compute the element-wise maximum of `x` and `y`, updating `x` to contain the maximum value across all lanes in each lane.
- **Output**: A 256-bit vector (`wu_t`) where each lane contains the maximum value found in the original input vector `x`.


---
### wu\_gather<!-- {{#callable:wu_gather}} -->
The `wu_gather` function gathers 32-bit integers from a base array using specified indices and returns them as a vector.
- **Inputs**:
    - `b`: A pointer to the base array of unsigned integers from which values will be gathered.
    - `i`: A vector of indices (of type `wi_t`) specifying which elements to gather from the base array.
- **Control Flow**:
    - The function uses the `_mm256_i32gather_epi32` intrinsic to gather 32-bit integers from the base array `b` at the positions specified by the indices in `i`.
    - The gathered integers are returned as a 256-bit vector of type `wu_t`.
- **Output**: A 256-bit vector (`wu_t`) containing the gathered 32-bit integers from the base array at the specified indices.



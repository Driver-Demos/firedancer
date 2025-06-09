# Purpose
This C source code file provides a comprehensive set of macros and inline functions for handling 256-bit wide vector operations using AVX (Advanced Vector Extensions) intrinsics, specifically targeting operations on vectors of 32-bit signed integers. The file defines a type `wi_t` as a 256-bit integer vector (`__m256i`) and offers a variety of operations such as vector construction, arithmetic, logical, and memory operations, as well as conversions and reductions. The code is structured to mirror other vector APIs, ensuring consistency and ease of use across different data types. It emphasizes the use of macros for operations where possible to optimize performance and reduce the risk of compiler inefficiencies.

The file is intended to be included indirectly through a header file (`fd_avx.h`), as indicated by the initial preprocessor directive. This suggests that the code is part of a larger library or framework that provides SIMD (Single Instruction, Multiple Data) capabilities. The operations defined in this file include constructors for creating vectors, arithmetic operations like addition and multiplication, logical operations such as AND and OR, and memory operations for loading and storing vectors. Additionally, it provides conversion functions to transform vectors into different data types and reduction functions to compute aggregate values like sums or minimums across vector elements. The file is designed to be a utility for developers working with high-performance computing applications that require efficient data processing using SIMD instructions.
# Functions

---
### wi\_bcast\_pair<!-- {{#callable:wi_bcast_pair}} -->
The `wi_bcast_pair` function creates a 256-bit vector with alternating pairs of two given integers, repeated four times.
- **Inputs**:
    - `i0`: The first integer to be broadcasted in the vector.
    - `i1`: The second integer to be broadcasted in the vector.
- **Control Flow**:
    - The function takes two integer inputs, `i0` and `i1`.
    - It uses the `_mm256_setr_epi32` intrinsic to create a 256-bit vector.
    - The vector is constructed by repeating the sequence `[i0, i1]` four times, resulting in `[i0, i1, i0, i1, i0, i1, i0, i1]`.
- **Output**: A 256-bit vector (`wi_t`) containing the integers `i0` and `i1` in an alternating pattern, repeated four times.


---
### wi\_bcast\_lohi<!-- {{#callable:wi_bcast_lohi}} -->
The `wi_bcast_lohi` function creates a 256-bit vector with the first four 32-bit lanes set to a given integer `i0` and the last four lanes set to another integer `i1`.
- **Inputs**:
    - `i0`: The integer value to be broadcasted to the first four lanes of the vector.
    - `i1`: The integer value to be broadcasted to the last four lanes of the vector.
- **Control Flow**:
    - The function uses the `_mm256_setr_epi32` intrinsic to create a 256-bit vector.
    - The first four lanes of the vector are set to the value of `i0`.
    - The last four lanes of the vector are set to the value of `i1`.
- **Output**: A 256-bit vector (`wi_t`) with the specified broadcasted integer values in its lanes.


---
### wi\_bcast\_quad<!-- {{#callable:wi_bcast_quad}} -->
The `wi_bcast_quad` function creates a 256-bit vector with two sets of four 32-bit integers, each set containing the same four integers in the same order.
- **Inputs**:
    - `i0`: The first integer to be included in the vector.
    - `i1`: The second integer to be included in the vector.
    - `i2`: The third integer to be included in the vector.
    - `i3`: The fourth integer to be included in the vector.
- **Control Flow**:
    - The function takes four integer inputs: i0, i1, i2, and i3.
    - It uses the `_mm256_setr_epi32` intrinsic to create a 256-bit vector.
    - The vector is constructed with the integers arranged as [i0, i1, i2, i3, i0, i1, i2, i3].
    - The function returns this constructed vector.
- **Output**: A 256-bit vector (`wi_t`) containing two sets of the four input integers, each set in the order [i0, i1, i2, i3].


---
### wi\_bcast\_wide<!-- {{#callable:wi_bcast_wide}} -->
The `wi_bcast_wide` function creates a 256-bit AVX vector with each pair of consecutive elements set to the same integer value from the input arguments.
- **Inputs**:
    - `i0`: The first integer value to be broadcasted to the first two elements of the vector.
    - `i1`: The second integer value to be broadcasted to the third and fourth elements of the vector.
    - `i2`: The third integer value to be broadcasted to the fifth and sixth elements of the vector.
    - `i3`: The fourth integer value to be broadcasted to the seventh and eighth elements of the vector.
- **Control Flow**:
    - The function takes four integer inputs: i0, i1, i2, and i3.
    - It uses the `_mm256_setr_epi32` intrinsic to create a 256-bit vector with the pattern [i0, i0, i1, i1, i2, i2, i3, i3].
    - The function returns this vector.
- **Output**: A 256-bit AVX vector (`wi_t`) with the specified pattern of repeated integer values.


---
### wi\_exch\_adj\_quad<!-- {{#callable:wi_exch_adj_quad}} -->
The `wi_exch_adj_quad` function rearranges the elements of a 256-bit integer vector by swapping the lower and upper 128-bit lanes.
- **Inputs**:
    - `x`: A 256-bit integer vector (`wi_t`) containing eight 32-bit signed integers.
- **Control Flow**:
    - The function takes a 256-bit integer vector `x` as input.
    - It uses the `_mm256_permute2f128_si256` intrinsic to swap the lower and upper 128-bit lanes of the vector `x`.
    - The intrinsic is called with the same vector `x` for both source operands and a control value of `1`, which specifies the lane swap operation.
- **Output**: A 256-bit integer vector with the lower and upper 128-bit lanes of the input vector swapped.


---
### wi\_ld<!-- {{#callable:wi_ld}} -->
The `wi_ld` function loads a 256-bit vector of 8 signed 32-bit integers from a 32-byte aligned memory location.
- **Inputs**:
    - `p`: A pointer to a 32-byte aligned memory location containing 8 signed 32-bit integers.
- **Control Flow**:
    - The function casts the input pointer `p` to a pointer of type `__m256i const *`.
    - It then uses the `_mm256_load_si256` intrinsic to load the 256-bit vector from the memory location pointed to by the casted pointer.
- **Output**: A `wi_t` type, which is a 256-bit vector containing 8 signed 32-bit integers loaded from the specified memory location.


---
### wi\_st<!-- {{#callable:wi_st}} -->
The `wi_st` function stores a vector of 8 signed 32-bit integers into a 32-byte aligned memory location.
- **Inputs**:
    - `p`: A pointer to an integer array where the vector will be stored; it must be 32-byte aligned.
    - `i`: A vector of type `wi_t` (which is an alias for `__m256i`) containing 8 signed 32-bit integers to be stored.
- **Control Flow**:
    - The function uses the `_mm256_store_si256` intrinsic to store the vector `i` into the memory location pointed to by `p`.
- **Output**: The function does not return a value; it performs a side effect by writing to the memory location pointed to by `p`.


---
### wi\_ldu<!-- {{#callable:wi_ldu}} -->
The `wi_ldu` function loads a 256-bit vector of integers from an unaligned memory address into a `wi_t` type using AVX2 intrinsics.
- **Inputs**:
    - `p`: A pointer to a memory location from which the 256-bit vector of integers will be loaded; the pointer does not need to be aligned.
- **Control Flow**:
    - The function takes a pointer `p` as input, which points to the memory location of the data to be loaded.
    - It casts the pointer `p` to a pointer of type `__m256i const *`, which is suitable for AVX2 operations.
    - The function then uses the `_mm256_loadu_si256` intrinsic to load the data from the unaligned memory location into a `__m256i` type, which is aliased as `wi_t`.
- **Output**: The function returns a `wi_t` type, which is a 256-bit vector containing the loaded integers.


---
### wi\_stu<!-- {{#callable:wi_stu}} -->
The `wi_stu` function stores a 256-bit integer vector to a memory location without requiring alignment.
- **Inputs**:
    - `p`: A pointer to the memory location where the 256-bit integer vector will be stored.
    - `i`: A 256-bit integer vector of type `wi_t` (which is defined as `__m256i`) to be stored at the memory location pointed to by `p`.
- **Control Flow**:
    - The function uses the `_mm256_storeu_si256` intrinsic to store the 256-bit integer vector `i` at the memory location pointed to by `p`.
    - The intrinsic `_mm256_storeu_si256` allows storing the vector without requiring the memory address to be aligned to 32 bytes.
- **Output**: The function does not return any value; it performs a side effect by storing the vector at the specified memory location.


---
### wi\_extract\_variable<!-- {{#callable:wi_extract_variable}} -->
The `wi_extract_variable` function extracts an integer from a specified lane of a 256-bit AVX vector.
- **Inputs**:
    - `a`: A 256-bit AVX vector (`wi_t`) containing eight 32-bit integers.
    - `n`: An integer specifying the lane index (0 to 7) from which to extract the integer.
- **Control Flow**:
    - A union is defined with a 256-bit AVX vector and an array of eight integers to facilitate type punning.
    - The AVX vector `a` is stored into the union's 256-bit vector member using `_mm256_store_si256`.
    - The integer at the specified lane `n` is accessed from the union's integer array and returned.
- **Output**: The function returns the integer located at the specified lane `n` of the input AVX vector `a`.


---
### wi\_insert\_variable<!-- {{#callable:wi_insert_variable}} -->
The `wi_insert_variable` function replaces an integer at a specified index in a 256-bit vector of integers with a new integer value.
- **Inputs**:
    - `a`: A 256-bit vector of integers (`wi_t`) where each lane holds a signed 32-bit integer.
    - `n`: An integer representing the index (0 to 7) of the lane in the vector `a` to be replaced.
    - `v`: An integer value to insert into the specified lane of the vector `a`.
- **Control Flow**:
    - A union is defined to allow type punning between a 256-bit vector and an array of 8 integers.
    - The vector `a` is stored into the union's 256-bit vector member using `_mm256_store_si256`.
    - The integer `v` is assigned to the `n`-th position of the union's integer array member.
    - The modified vector is loaded back from the union's 256-bit vector member using `_mm256_load_si256` and returned.
- **Output**: A 256-bit vector of integers (`wi_t`) with the `n`-th lane replaced by the integer `v`.


---
### wi\_rol<!-- {{#callable:wi_rol}} -->
The `wi_rol` function performs a bitwise left rotation on each 32-bit lane of a vector of integers by a specified number of bits.
- **Inputs**:
    - `a`: A vector of 32-bit signed integers (`wi_t`) on which the rotation operation is to be performed.
    - `imm`: An integer specifying the number of bits to rotate each element of the vector to the left.
- **Control Flow**:
    - The function first calculates the left shift of the vector `a` by `imm & 31` bits using `wi_shl`.
    - It then calculates the right shift of the vector `a` by `(-imm) & 31` bits using `wi_shru`.
    - The results of the left and right shifts are combined using a bitwise OR operation (`wi_or`) to produce the final rotated vector.
- **Output**: A vector of 32-bit signed integers (`wi_t`) where each element is the result of rotating the corresponding element of the input vector `a` to the left by `imm` bits.


---
### wi\_ror<!-- {{#callable:wi_ror}} -->
The `wi_ror` function performs a bitwise right rotation on each 32-bit lane of a vector of integers by a specified number of bits.
- **Inputs**:
    - `a`: A vector of 32-bit signed integers (`wi_t`) on which the right rotation is to be performed.
    - `imm`: An integer specifying the number of bits to rotate each element of the vector to the right.
- **Control Flow**:
    - The function calculates the effective number of bits to rotate by taking `imm & 31`, ensuring the shift amount is within the range of 0 to 31.
    - It performs an unsigned right shift on the vector `a` by the calculated number of bits using `wi_shru(a, imm & 31)`.
    - It performs a left shift on the vector `a` by the complement of the calculated number of bits using `wi_shl(a, (-imm) & 31)`.
    - The results of the two shifts are combined using a bitwise OR operation with `wi_or`.
- **Output**: The function returns a vector of 32-bit signed integers (`wi_t`) where each element has been right-rotated by the specified number of bits.


---
### wi\_rol\_variable<!-- {{#callable:wi_rol_variable}} -->
The `wi_rol_variable` function performs a variable bitwise left rotation on each 32-bit lane of a vector of integers.
- **Inputs**:
    - `a`: A vector of 32-bit signed integers (`wi_t`) to be rotated.
    - `n`: An integer specifying the number of positions to rotate each element in the vector `a` to the left.
- **Control Flow**:
    - The function calculates `n & 31` to ensure the rotation count is within the range of 0 to 31 bits.
    - It performs a left shift on the vector `a` by `n & 31` bits using `wi_shl_variable`.
    - It performs a right logical shift on the vector `a` by `(-n) & 31` bits using `wi_shru_variable`.
    - The results of the left and right shifts are combined using a bitwise OR operation with `wi_or`.
- **Output**: The function returns a vector of 32-bit signed integers (`wi_t`) where each element has been rotated left by `n` positions.


---
### wi\_ror\_variable<!-- {{#callable:wi_ror_variable}} -->
The `wi_ror_variable` function performs a variable bitwise right rotation on each 32-bit lane of a vector of integers.
- **Inputs**:
    - `a`: A vector of 32-bit signed integers (`wi_t`) to be rotated.
    - `n`: An integer specifying the number of positions to rotate each element in the vector to the right.
- **Control Flow**:
    - The function calculates the right shift of vector `a` by `n & 31` positions using `wi_shru_variable`.
    - It calculates the left shift of vector `a` by `(-n) & 31` positions using `wi_shl_variable`.
    - The results of the two shifts are combined using a bitwise OR operation with `wi_or`.
- **Output**: A vector of 32-bit signed integers (`wi_t`) where each element has been right-rotated by `n` positions.


---
### wi\_rol\_vector<!-- {{#callable:wi_rol_vector}} -->
The `wi_rol_vector` function performs a bitwise left rotation on each 32-bit lane of a vector `a` by the corresponding amount specified in vector `b`, using AVX intrinsics.
- **Inputs**:
    - `a`: A vector of type `wi_t` where each 32-bit lane holds a signed 32-bit integer, representing the values to be rotated.
    - `b`: A vector of type `wi_t` where each 32-bit lane holds a signed 32-bit integer, representing the number of positions to rotate the corresponding lane in vector `a`.
- **Control Flow**:
    - Broadcast the integer value 31 to all lanes of a vector `m` using `wi_bcast(31)` to create a mask for bitwise operations.
    - Perform a bitwise AND between vector `b` and the mask `m` to ensure the shift amount is within the range [0, 31].
    - Shift each lane of vector `a` to the left by the amount specified in the corresponding lane of the masked vector `b` using `wi_shl_vector`.
    - Negate vector `b` and perform a bitwise AND with the mask `m` to prepare for the right shift operation.
    - Shift each lane of vector `a` to the right (unsigned) by the amount specified in the corresponding lane of the negated and masked vector `b` using `wi_shru_vector`.
    - Combine the results of the left and right shifts using a bitwise OR operation with `wi_or` to achieve the effect of a bitwise rotation.
- **Output**: A vector of type `wi_t` where each lane contains the result of rotating the corresponding lane in vector `a` by the amount specified in vector `b`.


---
### wi\_ror\_vector<!-- {{#callable:wi_ror_vector}} -->
The `wi_ror_vector` function performs a bitwise right rotation on each 32-bit lane of a vector of integers by a specified number of bits, using another vector to determine the rotation amount for each lane.
- **Inputs**:
    - `a`: A vector of 32-bit signed integers (`wi_t`) to be rotated.
    - `b`: A vector of 32-bit signed integers (`wi_t`) specifying the number of bits to rotate each corresponding lane in vector `a`.
- **Control Flow**:
    - Create a vector `m` with all lanes set to 31 using `wi_bcast(31)` to mask the rotation amount to a maximum of 31 bits.
    - Perform a bitwise AND between vector `b` and `m` to ensure the rotation amount is within 0 to 31 bits.
    - Compute the right shift of vector `a` by the masked rotation amount using `wi_shru_vector`.
    - Compute the left shift of vector `a` by the negated masked rotation amount using `wi_shl_vector`.
    - Combine the results of the right and left shifts using a bitwise OR operation with `wi_or` to achieve the rotation effect.
    - Return the resulting vector.
- **Output**: A vector of 32-bit signed integers (`wi_t`) where each lane is the result of rotating the corresponding lane in `a` to the right by the number of bits specified in `b`.


---
### wi\_sum\_all<!-- {{#callable:wi_sum_all}} -->
The `wi_sum_all` function computes the sum of all elements in a 256-bit vector of 32-bit integers and returns a vector where each element is the computed sum.
- **Inputs**:
    - `x`: A 256-bit vector of 32-bit integers (`wi_t`) containing the elements to be summed.
- **Control Flow**:
    - The function first adds the lower and upper 128-bit halves of the input vector `x` using `_mm256_add_epi32` and `_mm256_permute2f128_si256`, resulting in a vector where each element is the sum of corresponding elements from the two halves.
    - It then performs a horizontal addition on the resulting vector using `_mm256_hadd_epi32`, which sums adjacent pairs of elements, reducing the vector to four sums.
    - Finally, another horizontal addition is performed to sum these four elements into a single sum, which is then broadcasted across all elements of the resulting vector.
- **Output**: A 256-bit vector (`wi_t`) where each element is the sum of all elements in the input vector `x`.


---
### wi\_min\_all<!-- {{#callable:wi_min_all}} -->
The `wi_min_all` function computes the minimum value across all lanes of a 256-bit integer vector and broadcasts this minimum value across all lanes of the resulting vector.
- **Inputs**:
    - `x`: A 256-bit integer vector (`wi_t`) containing eight 32-bit signed integers.
- **Control Flow**:
    - Permute the input vector `x` to swap its two 128-bit halves, storing the result in `y`.
    - Compute the element-wise minimum of `x` and `y`, updating `x`.
    - Shuffle the elements of `x` to rearrange them, storing the result in `y`.
    - Compute the element-wise minimum of `x` and `y`, updating `x`.
    - Shuffle the elements of `x` again to rearrange them, storing the result in `y`.
    - Compute the element-wise minimum of `x` and `y`, updating `x` to contain the minimum value across all lanes.
- **Output**: A 256-bit integer vector (`wi_t`) where all lanes contain the minimum value found in the input vector `x`.


---
### wi\_max\_all<!-- {{#callable:wi_max_all}} -->
The `wi_max_all` function computes the maximum value across all lanes of a 256-bit vector of 32-bit integers and broadcasts this maximum value to all lanes of the vector.
- **Inputs**:
    - `x`: A 256-bit vector of 32-bit signed integers (`wi_t`).
- **Control Flow**:
    - Permute the input vector `x` to swap its two 128-bit halves, storing the result in `y`.
    - Compute the element-wise maximum of `x` and `y`, updating `x`.
    - Shuffle the elements of `x` to rearrange them, storing the result in `y`.
    - Compute the element-wise maximum of `x` and `y`, updating `x`.
    - Shuffle the elements of `x` again to rearrange them, storing the result in `y`.
    - Compute the element-wise maximum of `x` and `y`, updating `x` to contain the maximum value across all lanes in each lane.
- **Output**: A 256-bit vector where each lane contains the maximum value found in the original input vector `x`.



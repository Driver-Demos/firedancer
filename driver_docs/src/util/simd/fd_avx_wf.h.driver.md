# Purpose
This C source code file is a specialized utility for handling SIMD (Single Instruction, Multiple Data) operations using AVX (Advanced Vector Extensions) instructions, specifically targeting vectorized operations on single-precision floating-point numbers. The file defines a set of macros and inline functions that facilitate the creation, manipulation, and computation of 256-bit wide vectors, where each vector consists of eight 32-bit floating-point elements. The code provides a comprehensive API for constructing vectors, performing arithmetic and logical operations, memory operations, and conversions between different data types, all optimized for AVX instructions. The file is intended to be included indirectly through a header file named `fd_avx.h`, as indicated by the preprocessor directive at the beginning, which ensures that the file is not included directly.

The functionality provided by this file is broad within the context of SIMD operations, covering a wide range of operations such as arithmetic (addition, subtraction, multiplication, division), logical operations, conditional operations, and data type conversions. It also includes specialized operations like fast reciprocal and square root calculations, which are optimized for performance but may not provide full precision. The file defines a public API for vector operations, which can be used by other parts of a program to leverage the performance benefits of AVX instructions. The use of macros and inline functions is prevalent to ensure that the operations are executed efficiently, minimizing the overhead that might be introduced by function calls. This file is a critical component for applications that require high-performance computing capabilities, such as scientific simulations, graphics processing, or any domain where large-scale numerical computations are necessary.
# Functions

---
### wf\_bcast\_pair<!-- {{#callable:wf_bcast_pair}} -->
The `wf_bcast_pair` function creates a vector of eight single-precision floating-point values by alternating two input floats across the vector.
- **Inputs**:
    - `f0`: The first float value to be broadcasted in the vector.
    - `f1`: The second float value to be broadcasted in the vector.
- **Control Flow**:
    - The function uses the `_mm256_setr_ps` intrinsic to create a vector of eight floats.
    - The values `f0` and `f1` are alternated in the vector, resulting in the pattern `[f0, f1, f0, f1, f0, f1, f0, f1]`.
- **Output**: A `wf_t` type vector containing the pattern `[f0, f1, f0, f1, f0, f1, f0, f1]`.


---
### wf\_bcast\_lohi<!-- {{#callable:wf_bcast_lohi}} -->
The `wf_bcast_lohi` function creates a vector of eight single-precision floating-point values, where the first four elements are set to `f0` and the last four elements are set to `f1`.
- **Inputs**:
    - `f0`: A single-precision floating-point value to be broadcasted to the first four elements of the vector.
    - `f1`: A single-precision floating-point value to be broadcasted to the last four elements of the vector.
- **Control Flow**:
    - The function uses the `_mm256_setr_ps` intrinsic to create a vector of eight floats.
    - The first four elements of the vector are set to the value of `f0`.
    - The last four elements of the vector are set to the value of `f1`.
- **Output**: The function returns a `wf_t` type, which is a vector of eight single-precision floating-point values with the specified broadcast pattern.


---
### wf\_bcast\_quad<!-- {{#callable:wf_bcast_quad}} -->
The `wf_bcast_quad` function creates a vector of eight single-precision floating-point values by repeating a sequence of four input floats twice.
- **Inputs**:
    - `f0`: The first float value to be included in the vector.
    - `f1`: The second float value to be included in the vector.
    - `f2`: The third float value to be included in the vector.
    - `f3`: The fourth float value to be included in the vector.
- **Control Flow**:
    - The function takes four float inputs: f0, f1, f2, and f3.
    - It calls the `_mm256_setr_ps` intrinsic function with these four floats repeated twice, creating a vector of eight floats.
    - The resulting vector is returned, containing the sequence [f0, f1, f2, f3, f0, f1, f2, f3].
- **Output**: A vector of type `wf_t` (which is an alias for `__m256`), containing the sequence [f0, f1, f2, f3, f0, f1, f2, f3].


---
### wf\_bcast\_wide<!-- {{#callable:wf_bcast_wide}} -->
The `wf_bcast_wide` function creates a vector of eight single-precision floating-point values where each pair of adjacent elements is a duplicate of one of the four input floats.
- **Inputs**:
    - `f0`: The first float value to be duplicated in the vector.
    - `f1`: The second float value to be duplicated in the vector.
    - `f2`: The third float value to be duplicated in the vector.
    - `f3`: The fourth float value to be duplicated in the vector.
- **Control Flow**:
    - The function takes four float inputs: f0, f1, f2, and f3.
    - It uses the `_mm256_setr_ps` intrinsic to create a 256-bit AVX vector.
    - The vector is constructed such that the first two elements are f0, the next two are f1, the following two are f2, and the last two are f3.
- **Output**: A 256-bit AVX vector (`wf_t`) containing eight floats arranged as [f0, f0, f1, f1, f2, f2, f3, f3].


---
### wf\_exch\_adj\_quad<!-- {{#callable:wf_exch_adj_quad}} -->
The `wf_exch_adj_quad` function rearranges the elements of a vector of eight single-precision floating-point numbers by swapping the first and second 128-bit lanes.
- **Inputs**:
    - `f`: A vector of type `wf_t` containing eight single-precision floating-point numbers.
- **Control Flow**:
    - The function takes a vector `f` as input, which is of type `wf_t` (an alias for `__m256`).
    - It uses the `_mm256_permute2f128_ps` intrinsic to permute the 128-bit lanes of the input vector `f`.
    - The intrinsic is called with the same vector `f` for both source operands and a control value of `1`, which swaps the two 128-bit lanes of the vector.
- **Output**: A vector of type `wf_t` with the first and second 128-bit lanes swapped, resulting in the order [f4, f5, f6, f7, f0, f1, f2, f3].


---
### wf\_extract<!-- {{#callable:wf_extract}} -->
The `wf_extract` function extracts a specific float value from a vector of floats based on a given lane index.
- **Inputs**:
    - `a`: A vector of floats (`wf_t`), which is an AVX 256-bit wide vector containing 8 single-precision floating point values.
    - `imm`: An integer representing the lane index from which to extract the float; it should be a compile-time constant in the range 0 to 7.
- **Control Flow**:
    - Calculate `avx_lane` by right-shifting `imm` by 2 to determine which 128-bit lane to extract from the 256-bit vector.
    - Calculate `sse_lane` by performing a bitwise AND of `imm` with 3 to determine the specific float within the 128-bit lane.
    - Use `_mm256_extractf128_ps` to extract the 128-bit lane from the vector `a` based on `avx_lane`.
    - If `sse_lane` is non-zero, use `_mm_extract_epi32` and `_mm_insert_epi32` to extract and insert the specific float within the 128-bit lane.
    - Convert the resulting 128-bit vector to a single float using `_mm_cvtss_f32`.
- **Output**: A single float value extracted from the specified lane of the input vector.


---
### wf\_extract\_variable<!-- {{#callable:wf_extract_variable}} -->
The `wf_extract_variable` function extracts a specific float value from a vector of eight floats based on a given index.
- **Inputs**:
    - `a`: A vector of type `wf_t` (which is an AVX 256-bit vector) containing eight 32-bit wide lanes, each holding a single precision IEEE 754 floating point value.
    - `n`: An integer index specifying which lane (0 to 7) of the vector `a` to extract the float from.
- **Control Flow**:
    - Declare a local array `f` of eight floats with a specific attribute `W_ATTR` for alignment or optimization purposes.
    - Store the contents of the vector `a` into the array `f` using the `_mm256_store_ps` intrinsic, which transfers the vector's data into the array.
    - Return the float at the index `n` from the array `f`.
- **Output**: A single float value extracted from the specified lane `n` of the input vector `a`.


---
### wf\_insert\_variable<!-- {{#callable:wf_insert_variable}} -->
The `wf_insert_variable` function replaces a specific element in a vector of floats with a new float value and returns the modified vector.
- **Inputs**:
    - `a`: A vector of 8 single-precision floating point values (type `wf_t`).
    - `n`: An integer index (0 to 7) indicating which element in the vector to replace.
    - `v`: A single-precision floating point value to insert into the vector at the specified index.
- **Control Flow**:
    - Store the elements of the vector `a` into a local array `f` of 8 floats using `_mm256_store_ps`.
    - Replace the element at index `n` in the array `f` with the new value `v`.
    - Load the modified array `f` back into a vector using `_mm256_load_ps` and return it.
- **Output**: A vector of 8 single-precision floating point values (`wf_t`) with the element at index `n` replaced by `v`.


---
### wf\_to\_wl<!-- {{#callable:wf_to_wl}} -->
The `wf_to_wl` function converts a 128-bit portion of a 256-bit vector of floats (`wf_t`) into a 256-bit vector of longs (`__m256i`).
- **Inputs**:
    - `f`: A 256-bit vector of floats (`wf_t`) from which a 128-bit portion will be extracted and converted.
    - `imm_hi`: An integer that determines which 128-bit portion of the input vector `f` to extract; if non-zero, the higher 128 bits are extracted, otherwise the lower 128 bits are extracted.
- **Control Flow**:
    - A union is used to store the extracted 128-bit portion of the input vector `f` as an array of four floats.
    - The `_mm_store_ps` function is used to extract either the lower or higher 128 bits of `f` based on the value of `imm_hi`.
    - Each float in the extracted portion is cast to a long and stored in another union as an array of four longs.
    - The `_mm256_load_si256` function is used to load the array of longs into a 256-bit vector of longs (`__m256i`).
- **Output**: A 256-bit vector of longs (`__m256i`) containing the converted values from the selected 128-bit portion of the input vector `f`.


---
### wf\_to\_wv<!-- {{#callable:wf_to_wv}} -->
The `wf_to_wv` function converts a 256-bit vector of single-precision floating-point values to a 256-bit vector of unsigned long integers, using a specified half of the input vector.
- **Inputs**:
    - `f`: A 256-bit vector (`wf_t`) containing eight single-precision floating-point values.
    - `imm_hi`: An integer that determines which half of the input vector `f` to process; if non-zero, the upper half is used, otherwise the lower half is used.
- **Control Flow**:
    - A union is used to store the selected half of the input vector `f` as an array of four floats.
    - The `_mm_store_ps` function extracts either the lower or upper 128-bit half of the vector `f` based on the value of `imm_hi` and stores it in the float array of the union.
    - Each float in the array is cast to an unsigned long and stored in another union's unsigned long array.
    - The `_mm256_load_si256` function loads the unsigned long array into a 256-bit integer vector and returns it.
- **Output**: A 256-bit vector (`__m256i`) containing four unsigned long integers converted from the selected half of the input vector `f`.


---
### wf\_to\_wu\_fast<!-- {{#callable:wf_to_wu_fast}} -->
The `wf_to_wu_fast` function converts a vector of single-precision floating-point numbers to a vector of unsigned 32-bit integers, handling values in the range [0, 2^32) efficiently.
- **Inputs**:
    - `a`: A vector of single-precision floating-point numbers (`wf_t`) assumed to be in the range [0, 2^32).
- **Control Flow**:
    - Broadcasts the value 2^31 to all elements of a vector `s`.
    - Compares each element of `a` with `s` to create a condition vector `c` where each element is -1 if the corresponding element in `a` is less than 2^31, and 0 otherwise.
    - Subtracts `s` from `a` to get `as`, which is `a - 2^31`.
    - Uses the condition vector `c` to select between `a` and `as`, converting the result to a signed integer vector `u`.
    - Adds 2^31 to each element of `u` to get `us`, which is `a + 2^31` if `a` was less than 2^31, and `a` otherwise.
    - Blends `us` and `u` based on the condition vector `c` to produce the final result, which is cast to an unsigned integer vector.
- **Output**: A vector of unsigned 32-bit integers (`__m256i`) representing the converted values from the input vector `a`.


---
### wf\_sum\_all<!-- {{#callable:wf_sum_all}} -->
The `wf_sum_all` function computes the sum of all elements in a vector of floats and returns a vector where each element is the sum.
- **Inputs**:
    - `x`: A vector of floats (`wf_t`) containing 8 single-precision floating point values.
- **Control Flow**:
    - The function first adds the two 128-bit halves of the 256-bit vector `x` using `_mm256_permute2f128_ps` and `_mm256_add_ps`, resulting in a vector where each element is the sum of corresponding elements from the two halves.
    - It then performs a horizontal addition on the vector using `_mm256_hadd_ps`, which sums adjacent pairs of elements, reducing the vector to four sums.
    - Finally, another horizontal addition is performed to sum the remaining elements, resulting in a vector where each element is the total sum of the original vector.
- **Output**: A vector of floats (`wf_t`) where each element is the sum of all elements in the input vector `x`.


---
### wf\_min\_all<!-- {{#callable:wf_min_all}} -->
The `wf_min_all` function computes the minimum value across all elements of a vector of floats and broadcasts this minimum value across all elements of the vector.
- **Inputs**:
    - `x`: A vector of 8 single-precision floating point values (wf_t) to find the minimum value from.
- **Control Flow**:
    - Permute the input vector `x` to swap its two 128-bit lanes, storing the result in `y`.
    - Compute the element-wise minimum of `x` and `y`, updating `x` with the result.
    - Permute `x` to swap adjacent pairs of elements, storing the result in `y`.
    - Compute the element-wise minimum of `x` and `y`, updating `x` with the result.
    - Permute `x` to swap adjacent elements, storing the result in `y`.
    - Compute the element-wise minimum of `x` and `y`, updating `x` with the result.
    - Return the vector `x`, which now contains the minimum value of the original vector broadcasted across all elements.
- **Output**: A vector (wf_t) where each element is the minimum value found in the input vector `x`, broadcasted across all elements.


---
### wf\_max\_all<!-- {{#callable:wf_max_all}} -->
The `wf_max_all` function computes the maximum value across all elements of a vector of floats and broadcasts this maximum value across all elements of the vector.
- **Inputs**:
    - `x`: A vector of floats (`wf_t`) containing 8 single-precision floating point values.
- **Control Flow**:
    - Permute the input vector `x` to swap its two 128-bit lanes, storing the result in `y`.
    - Compute the element-wise maximum of `x` and `y`, updating `x`.
    - Permute `x` to swap adjacent pairs of elements, storing the result in `y`.
    - Compute the element-wise maximum of `x` and `y`, updating `x`.
    - Permute `x` to swap adjacent elements, storing the result in `y`.
    - Compute the element-wise maximum of `x` and `y`, updating `x`.
- **Output**: A vector of floats (`wf_t`) where each element is the maximum value found in the input vector `x`.



# Purpose
This C source code file provides a specialized API for handling vectorized operations on single-precision floating-point numbers using SIMD (Single Instruction, Multiple Data) instructions, specifically targeting the SSE (Streaming SIMD Extensions) instruction set. The file defines a series of macros and inline functions that facilitate the creation, manipulation, and arithmetic operations on vectors of floats, where each vector is represented by the `__m128` data type. The code is structured to offer a broad range of functionalities, including vector construction, memory operations, arithmetic and logical operations, conditional operations, and conversions between different data types. The operations are designed to work on vectors with four 32-bit floating-point lanes, and the code assumes that the input values are not exotic (e.g., no NaNs or infinities).

The file is intended to be included indirectly through a header file named `fd_sse.h`, as indicated by the preprocessor directive at the beginning. This suggests that the code is part of a larger library or framework that provides SIMD utilities. The API is designed to be efficient and robust, preferring macros over inline functions where possible to minimize the risk of compiler optimizations affecting performance. The file also includes detailed comments explaining the behavior and limitations of each operation, such as the handling of exotic values and the precision of certain arithmetic operations. This documentation is crucial for developers who need to perform high-performance computations on floating-point data using SIMD instructions, ensuring they understand the constraints and expected behavior of the provided functions.
# Functions

---
### vf\_bcast\_pair<!-- {{#callable:vf_bcast_pair}} -->
The `vf_bcast_pair` function creates a vector float with a specific pattern by broadcasting two input float values in an alternating sequence.
- **Inputs**:
    - `f0`: The first float value to be broadcasted in the vector.
    - `f1`: The second float value to be broadcasted in the vector.
- **Control Flow**:
    - The function takes two float inputs, `f0` and `f1`.
    - It uses the `_mm_setr_ps` intrinsic to create a vector float (`vf_t`) with the pattern `[f0, f1, f0, f1]`.
    - The function returns this vector float.
- **Output**: A vector float (`vf_t`) with the pattern `[f0, f1, f0, f1]`.


---
### vf\_bcast\_wide<!-- {{#callable:vf_bcast_wide}} -->
The `vf_bcast_wide` function creates a vector float with the first two elements set to the first input float and the last two elements set to the second input float.
- **Inputs**:
    - `f0`: The first float value to be broadcasted to the first two elements of the vector.
    - `f1`: The second float value to be broadcasted to the last two elements of the vector.
- **Control Flow**:
    - The function uses the `_mm_setr_ps` intrinsic to create a vector float.
    - The intrinsic is called with the arguments `f0, f0, f1, f1`, setting the first two elements of the vector to `f0` and the last two elements to `f1`.
- **Output**: A vector float (`vf_t`) with the pattern `[f0, f0, f1, f1]`.


---
### vf\_extract\_variable<!-- {{#callable:vf_extract_variable}} -->
The `vf_extract_variable` function extracts a specific float value from a vector of four floats based on a given index.
- **Inputs**:
    - `a`: A vector of type `vf_t` (which is a `__m128` type) containing four single-precision floating point values.
    - `n`: An integer index specifying which element (0 to 3) to extract from the vector.
- **Control Flow**:
    - Declare a local array `f` of four floats with vector alignment attributes.
    - Store the contents of the vector `a` into the array `f` using `_mm_store_ps`.
    - Return the float at index `n` from the array `f`.
- **Output**: A single float value extracted from the vector at the specified index `n`.


---
### vf\_insert\_variable<!-- {{#callable:vf_insert_variable}} -->
The `vf_insert_variable` function replaces a specified element in a vector of four floats with a new float value and returns the modified vector.
- **Inputs**:
    - `a`: A vector of four single-precision floating point values (type `vf_t`).
    - `n`: An integer index (0 to 3) indicating which element in the vector to replace.
    - `v`: A single-precision floating point value to insert into the vector at the specified index.
- **Control Flow**:
    - The function begins by declaring an array `f` of four floats with a special attribute `V_ATTR` for alignment or optimization purposes.
    - The `_mm_store_ps` intrinsic is used to store the contents of the vector `a` into the array `f`.
    - The element at index `n` in the array `f` is replaced with the new float value `v`.
    - The modified array `f` is then loaded back into a vector using the `_mm_load_ps` intrinsic.
    - The function returns the newly created vector with the updated element.
- **Output**: The function returns a vector of type `vf_t` with the specified element replaced by the new float value.


---
### vf\_to\_vu\_fast<!-- {{#callable:vf_to_vu_fast}} -->
The `vf_to_vu_fast` function converts a vector of floating-point numbers to a vector of unsigned integers, assuming the input floats are already integral values within the range [0, 2^32).
- **Inputs**:
    - `a`: A vector of four single-precision floating-point numbers (vf_t) assumed to be integral values in the range [0, 2^32).
- **Control Flow**:
    - Broadcasts the value 2^31 into a vector `s`.
    - Compares each element of `a` with `s` to create a condition vector `c` where each element is -1 if the corresponding element in `a` is less than 2^31, and 0 otherwise.
    - Subtracts `s` from `a` to get `as`, which is used to adjust values greater than or equal to 2^31.
    - Uses the condition vector `c` to select between `a` and `as`, converting the result to a signed integer vector `u`.
    - Adds 2^31 to each element of `u` to get `us`, effectively converting signed integers back to unsigned integers.
    - Blends `us` and `u` based on the condition vector `c` to produce the final result, which is cast to an integer vector.
- **Output**: A vector of four 32-bit unsigned integers (__m128i) representing the converted values from the input vector.


---
### vf\_sum\_all<!-- {{#callable:vf_sum_all}} -->
The `vf_sum_all` function computes the sum of all elements in a vector of four single-precision floating-point numbers and returns a vector with this sum broadcasted to all elements.
- **Inputs**:
    - `x`: A vector of type `vf_t` containing four single-precision floating-point numbers.
- **Control Flow**:
    - The function first applies the `_mm_hadd_ps` intrinsic to the input vector `x`, which horizontally adds adjacent pairs of elements, resulting in a vector where the first two elements are the sums of the original pairs.
    - The function then applies `_mm_hadd_ps` again to the result, which adds the two sums from the previous step, resulting in a vector where the first element is the total sum of the original vector, and the remaining elements are undefined.
    - The function returns this vector, effectively broadcasting the total sum to all elements.
- **Output**: A vector of type `vf_t` where all elements contain the sum of the original input vector's elements.


---
### vf\_min\_all<!-- {{#callable:vf_min_all}} -->
The `vf_min_all` function computes the minimum value across all elements of a vector float and returns a vector with this minimum value broadcasted to all lanes.
- **Inputs**:
    - `x`: A vector float (`vf_t`) containing four single-precision floating point values.
- **Control Flow**:
    - Permute the input vector `x` to rearrange its elements using `_mm_permute_ps` with the shuffle pattern (1, 0, 3, 2).
    - Compute the element-wise minimum between the original vector `x` and the permuted vector `y` using `_mm_min_ps`.
    - Permute the resulting vector again with a different shuffle pattern (2, 3, 0, 1).
    - Compute the element-wise minimum again between the current vector `x` and the newly permuted vector `y`.
    - Return the vector `x`, which now contains the minimum value of the original vector broadcasted across all lanes.
- **Output**: A vector float (`vf_t`) where all lanes contain the minimum value found in the input vector `x`.


---
### vf\_max\_all<!-- {{#callable:vf_max_all}} -->
The `vf_max_all` function computes the maximum value from a vector of four single-precision floating-point numbers and returns a vector with all elements set to this maximum value.
- **Inputs**:
    - `x`: A vector of four single-precision floating-point numbers (type `vf_t`).
- **Control Flow**:
    - Permute the input vector `x` to rearrange its elements using `_mm_permute_ps` with the shuffle order (1, 0, 3, 2).
    - Compute the element-wise maximum between the original vector `x` and the permuted vector `y` using `_mm_max_ps`.
    - Permute the resulting vector again with a different shuffle order (2, 3, 0, 1).
    - Compute the element-wise maximum again between the current vector `x` and the newly permuted vector `y`.
    - Return the vector `x`, which now has all elements set to the maximum value found in the original vector.
- **Output**: A vector of four single-precision floating-point numbers, each set to the maximum value found in the input vector `x`.



# Purpose
This C source code file provides a specialized API for handling vectorized double-precision floating-point operations using SIMD (Single Instruction, Multiple Data) instructions, specifically targeting the SSE (Streaming SIMD Extensions) instruction set. The file defines a set of macros and inline functions to perform various operations on vectors of doubles, encapsulated in the `vd_t` type, which is an alias for the `__m128d` type used in SSE for handling two double-precision floating-point numbers simultaneously. The operations include vector construction, arithmetic operations, memory operations, logical operations, and conversions between different data types, all optimized for performance using SIMD instructions.

The code is structured to provide a comprehensive set of functionalities for vector double operations, including constructors, arithmetic operations, logical operations, and conversions, while ensuring compatibility with the SSE instruction set. It emphasizes performance by using macros and inline functions to minimize overhead and maximize the use of SIMD capabilities. The file is intended to be included indirectly through a header file (`fd_sse.h`), as indicated by the preprocessor directive at the beginning, ensuring that it is part of a larger library or framework. The API is designed to be robust, with careful handling of edge cases and undefined behaviors, particularly concerning exotic floating-point values and signed zeros, which are common concerns in high-performance computing scenarios.
# Functions

---
### vd\_extract<!-- {{#callable:vd_extract}} -->
The `vd_extract` function extracts a double-precision floating-point value from a specified lane of a vector double.
- **Inputs**:
    - `a`: A vector double (`vd_t`), which is a data type representing a pair of double-precision floating-point values.
    - `imm`: An integer index (0 or 1) specifying which of the two double values in the vector to extract.
- **Control Flow**:
    - Declare an array `d` of two doubles with vector attributes.
    - Store the contents of the vector double `a` into the array `d` using `_mm_store_pd`.
    - Return the double value at the index `imm` from the array `d`.
- **Output**: A double-precision floating-point value extracted from the specified lane of the input vector double.


---
### vd\_insert<!-- {{#callable:vd_insert}} -->
The `vd_insert` function replaces a specified element in a vector of doubles with a new double value and returns the modified vector.
- **Inputs**:
    - `a`: A vector of doubles (`vd_t`) from which an element will be replaced.
    - `imm`: An integer index (0 or 1) indicating which element in the vector `a` should be replaced.
    - `v`: A double value that will replace the element at the specified index in the vector `a`.
- **Control Flow**:
    - The function begins by declaring a local array `d` of two doubles to temporarily store the elements of the vector `a`.
    - The `_mm_store_pd` intrinsic is used to store the elements of vector `a` into the array `d`.
    - The element at index `imm` in the array `d` is replaced with the new double value `v`.
    - The modified array `d` is then loaded back into a vector using the `_mm_load_pd` intrinsic.
    - The function returns the newly formed vector with the updated element.
- **Output**: The function returns a vector of doubles (`vd_t`) with the specified element replaced by the new value.


---
### vd\_extract\_variable<!-- {{#callable:vd_extract_variable}} -->
The `vd_extract_variable` function extracts a double precision floating point value from a specified lane of a vector double.
- **Inputs**:
    - `a`: A vector double (`vd_t`) from which a double precision floating point value is to be extracted.
    - `n`: An integer index (0 or 1) specifying which lane of the vector double to extract the value from.
- **Control Flow**:
    - Declare a local array `d` of two doubles with vector attributes.
    - Store the contents of the vector double `a` into the array `d` using `_mm_store_pd`.
    - Return the double value at index `n` from the array `d`.
- **Output**: A double precision floating point value extracted from the specified lane of the input vector double.


---
### vd\_insert\_variable<!-- {{#callable:vd_insert_variable}} -->
The `vd_insert_variable` function replaces a specified element in a vector double with a new double value.
- **Inputs**:
    - `a`: A vector double (`vd_t`) containing two double precision floating point values.
    - `n`: An integer index (0 or 1) indicating which element of the vector double to replace.
    - `v`: A double precision floating point value to insert into the vector double at the specified index.
- **Control Flow**:
    - The function begins by declaring an array `d` of two doubles to temporarily store the elements of the vector double `a`.
    - The `_mm_store_pd` intrinsic is used to store the elements of `a` into the array `d`.
    - The element at index `n` in the array `d` is replaced with the new value `v`.
    - The modified array `d` is then loaded back into a vector double using the `_mm_load_pd` intrinsic.
    - The function returns the newly formed vector double with the updated value.
- **Output**: The function returns a new vector double (`vd_t`) with the specified element replaced by the new value.


---
### vd\_to\_vf<!-- {{#callable:vd_to_vf}} -->
The `vd_to_vf` function converts a vector of double-precision floating-point values to a vector of single-precision floating-point values and conditionally shuffles the result with another vector based on a flag.
- **Inputs**:
    - `d`: A vector of double-precision floating-point values (`vd_t`).
    - `f`: A vector of single-precision floating-point values (`vf_t`).
    - `imm_hi`: An integer flag that determines the shuffle operation to be performed.
- **Control Flow**:
    - Convert the double-precision vector `d` to a single-precision vector `_d` using `_mm_cvtpd_ps`, resulting in `[d0 d1 0 0]`.
    - Check the value of `imm_hi`.
    - If `imm_hi` is non-zero, shuffle `_d` with `f` using `_MM_SHUFFLE(1,0,1,0)`, effectively placing the converted values in the higher lanes of the result.
    - If `imm_hi` is zero, shuffle `_d` with `f` using `_MM_SHUFFLE(3,2,1,0)`, placing the converted values in the lower lanes of the result.
    - Return the shuffled vector `_d`.
- **Output**: A vector of single-precision floating-point values (`vf_t`) with the converted and shuffled values.


---
### vd\_to\_vi\_fast<!-- {{#callable:vd_to_vi_fast}} -->
The `vd_to_vi_fast` function converts a vector of double-precision floating-point values to a vector of 32-bit integers, optionally shuffling the result with another vector based on a control flag.
- **Inputs**:
    - `d`: A vector of double-precision floating-point values (vd_t) to be converted to integers.
    - `i`: A vector of 32-bit integers (vi_t) used for shuffling the result.
    - `imm_hi`: An integer flag indicating whether to shuffle the converted values into the higher or lower lanes of the result vector.
- **Control Flow**:
    - Convert the double-precision vector `d` to a vector of 32-bit integers using `_mm_cvtpd_epi32` and cast it to a single-precision float vector `vf_t`.
    - Cast the integer vector `i` to a single-precision float vector `vf_t`.
    - If `imm_hi` is true, shuffle the converted vector `_d` with `_i` using `_MM_SHUFFLE(1,0,1,0)` to place the converted values in the higher lanes.
    - If `imm_hi` is false, shuffle the converted vector `_d` with `_i` using `_MM_SHUFFLE(3,2,1,0)` to place the converted values in the lower lanes.
    - Return the shuffled vector cast back to a 32-bit integer vector `vi_t`.
- **Output**: A vector of 32-bit integers (vi_t) with the converted and optionally shuffled values from the input double-precision vector.


---
### vd\_to\_vu\_fast<!-- {{#callable:vd_to_vu_fast}} -->
The `vd_to_vu_fast` function converts a vector of double-precision floating-point values to a vector of unsigned integers, optimizing for different hardware capabilities.
- **Inputs**:
    - `d`: A vector of double-precision floating-point values (vd_t) to be converted.
    - `u`: A vector of unsigned integers (vu_t) used for shuffling the result.
    - `imm_hi`: An integer flag indicating the position in the result vector where the converted values should be placed.
- **Control Flow**:
    - Check if the AVX512F and AVX512VL instruction sets are available.
    - If available, use `_mm_cvtpd_epu32` to convert the double vector `d` directly to an unsigned integer vector `v`.
    - If not available, emulate the conversion by subtracting 2^31 from `d`, converting the result to signed integers, and then adjusting using two's complement to get the unsigned result.
    - Use conditional operations to handle values less than 2^31 differently from those greater or equal.
    - Return the result by shuffling the converted vector `v` and the input vector `u` based on the `imm_hi` flag.
- **Output**: A vector of unsigned integers (vu_t) with the converted values from the input double vector `d`.


---
### vd\_to\_vl<!-- {{#callable:vd_to_vl}} -->
The `vd_to_vl` function converts a vector of two double-precision floating-point numbers into a vector of two long integers.
- **Inputs**:
    - `d`: A vector of type `vd_t` (which is an alias for `__m128d`), containing two double-precision floating-point numbers.
- **Control Flow**:
    - A union `t` is declared to store the double values from the input vector `d`.
    - Another union `u` is declared to store the converted long integer values.
    - The double values from `d` are stored into the `t` union using `_mm_store_pd`.
    - Each double value in `t` is cast to a long and stored in the corresponding position in the `u` union.
    - The long integer values are loaded from the `u` union and returned as a `__m128i` vector using `_mm_load_si128`.
- **Output**: A `__m128i` vector containing two long integers, each converted from the corresponding double in the input vector.


---
### vd\_to\_vv<!-- {{#callable:vd_to_vv}} -->
The `vd_to_vv` function converts a vector of two double-precision floating-point numbers into a vector of two unsigned long integers.
- **Inputs**:
    - `d`: A vector of type `vd_t` containing two double-precision floating-point numbers.
- **Control Flow**:
    - The function begins by declaring two unions: one for storing the double values and another for storing the unsigned long integers.
    - The double values from the input vector `d` are stored into the double array of the first union using `_mm_store_pd`.
    - Each double value is then cast to an unsigned long and stored in the unsigned long array of the second union.
    - Finally, the function returns the `__m128i` vector from the second union using `_mm_load_si128`.
- **Output**: A `__m128i` vector containing the two unsigned long integer representations of the input double values.


---
### vd\_sum\_all<!-- {{#callable:vd_sum_all}} -->
The `vd_sum_all` function computes the sum of the two double-precision floating-point elements in a vector and returns a vector with both elements set to this sum.
- **Inputs**:
    - `x`: A vector of type `vd_t` containing two double-precision floating-point numbers.
- **Control Flow**:
    - The function uses the `_mm_hadd_pd` intrinsic to horizontally add the two elements of the input vector `x`.
    - The result is a vector where both elements are set to the sum of the original two elements in `x`.
- **Output**: A vector of type `vd_t` where both elements are the sum of the two elements in the input vector `x`.


---
### vd\_min\_all<!-- {{#callable:vd_min_all}} -->
The `vd_min_all` function computes the minimum value of two double-precision floating-point numbers in a vector and returns a vector with both elements set to this minimum value.
- **Inputs**:
    - `a`: A vector of type `vd_t` containing two double-precision floating-point numbers.
- **Control Flow**:
    - The function takes a vector `a` as input, which contains two double-precision floating-point numbers.
    - It uses the `_mm_permute_pd` intrinsic to swap the two elements in the vector `a`.
    - The `_mm_min_pd` intrinsic is then used to compute the minimum of the original vector `a` and the permuted vector.
    - The result is a vector where both elements are set to the minimum of the two original elements in `a`.
- **Output**: A vector of type `vd_t` where both elements are set to the minimum value of the two elements in the input vector `a`.


---
### vd\_max\_all<!-- {{#callable:vd_max_all}} -->
The `vd_max_all` function returns a vector double where both elements are the maximum of the two elements in the input vector double.
- **Inputs**:
    - `a`: A vector double (`vd_t`) containing two double precision floating point values.
- **Control Flow**:
    - The function takes a vector double `a` as input.
    - It uses the `_mm_permute_pd` intrinsic to swap the two elements of `a`.
    - The `_mm_max_pd` intrinsic is then used to compute the element-wise maximum of the original and permuted vectors.
    - The result is a vector double where both elements are the maximum of the two original elements.
- **Output**: A vector double (`vd_t`) where both elements are the maximum of the two elements in the input vector double.



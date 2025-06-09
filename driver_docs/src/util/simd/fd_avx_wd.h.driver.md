# Purpose
This C source code file is a specialized utility for handling vectorized double-precision floating-point operations using AVX (Advanced Vector Extensions) instructions. It defines a set of macros and inline functions to perform various arithmetic, logical, and memory operations on vectors of doubles, specifically leveraging the AVX intrinsic functions provided by Intel. The file is intended to be included indirectly through a header file named `fd_avx.h`, as indicated by the preprocessor directive at the beginning, which ensures that it is not included directly. The primary data type used is `wd_t`, which represents a vector of four double-precision floating-point numbers, and the operations are designed to work on these vectors efficiently.

The code provides a comprehensive API for constructing vectors, performing arithmetic operations (such as addition, subtraction, multiplication, and division), and executing logical and conditional operations. It also includes functions for loading and storing vectors from memory, handling predefined constants, and converting between different data types. The file emphasizes performance and precision, with specific attention to avoiding exotic floating-point values like NaNs and infinities, and it provides fast approximations for certain operations like reciprocal and reciprocal square root. The use of macros and inline functions is preferred to minimize the risk of compiler optimizations affecting performance. This file is part of a broader library that likely deals with SIMD (Single Instruction, Multiple Data) operations, providing a focused and efficient interface for AVX-based vector computations.
# Functions

---
### wd\_bcast\_pair<!-- {{#callable:wd_bcast_pair}} -->
The `wd_bcast_pair` function creates a vector of four double-precision floating-point numbers with a specific pattern using two input doubles.
- **Inputs**:
    - `d0`: The first double-precision floating-point number to be used in the vector.
    - `d1`: The second double-precision floating-point number to be used in the vector.
- **Control Flow**:
    - The function takes two double arguments, `d0` and `d1`.
    - It calls the `_mm256_setr_pd` intrinsic function with the arguments `d0`, `d1`, `d0`, and `d1`.
    - The intrinsic function constructs a 256-bit vector with the pattern `[d0, d1, d0, d1]`.
- **Output**: The function returns a 256-bit vector (`wd_t`) containing the doubles `[d0, d1, d0, d1]`.


---
### wd\_bcast\_wide<!-- {{#callable:wd_bcast_wide}} -->
The `wd_bcast_wide` function creates a vector of four double-precision floating-point numbers where the first two elements are set to the first input value and the last two elements are set to the second input value.
- **Inputs**:
    - `d0`: The first double-precision floating-point value to be broadcasted to the first two elements of the vector.
    - `d1`: The second double-precision floating-point value to be broadcasted to the last two elements of the vector.
- **Control Flow**:
    - The function takes two double-precision floating-point numbers as input parameters.
    - It uses the `_mm256_setr_pd` intrinsic to create a 256-bit vector (`__m256d`) with the first two elements set to `d0` and the last two elements set to `d1`.
    - The function returns this vector.
- **Output**: A 256-bit vector (`__m256d`) containing four double-precision floating-point numbers arranged as [d0, d0, d1, d1].


---
### wd\_extract<!-- {{#callable:wd_extract}} -->
The `wd_extract` function extracts a specific double-precision floating-point value from a 256-bit vector of doubles based on a given index.
- **Inputs**:
    - `a`: A 256-bit vector of doubles (`wd_t`) from which a double value is to be extracted.
    - `imm`: An integer index (0 to 3) specifying which double value to extract from the vector.
- **Control Flow**:
    - The function begins by declaring an array `d` of four doubles to store the elements of the vector `a`.
    - The `_mm256_store_pd` intrinsic is used to store the four double values from the vector `a` into the array `d`.
    - The function returns the double value at the index specified by `imm` from the array `d`.
- **Output**: A double-precision floating-point value extracted from the specified index of the input vector.


---
### wd\_insert<!-- {{#callable:wd_insert}} -->
The `wd_insert` function replaces a specific 64-bit lane in a vector of doubles with a new double value.
- **Inputs**:
    - `a`: A vector of doubles (`wd_t`) where one of the lanes will be replaced.
    - `imm`: An integer representing the index of the 64-bit lane to be replaced, which should be a compile-time constant between 0 and 3.
    - `v`: A double value that will replace the value in the specified lane of the vector.
- **Control Flow**:
    - A union is used to convert the double `v` into a long integer representation `t.i`.
    - The vector `a` is cast to an integer vector using `_mm256_castpd_si256`.
    - The integer representation of `v` (`t.i`) is inserted into the specified lane `imm` of the integer vector using `_mm256_insert_epi64`.
    - The modified integer vector is cast back to a vector of doubles using `_mm256_castsi256_pd`.
- **Output**: A new vector of doubles (`wd_t`) with the specified lane replaced by the new double value.


---
### wd\_extract\_variable<!-- {{#callable:wd_extract_variable}} -->
The `wd_extract_variable` function extracts a double-precision floating-point value from a specified lane of a vector double.
- **Inputs**:
    - `a`: A vector double (`wd_t`) from which a double-precision floating-point value is to be extracted.
    - `n`: An integer index (0 to 3) specifying which lane of the vector double to extract the value from.
- **Control Flow**:
    - Declare an array `d` of four doubles with a specific attribute `W_ATTR`.
    - Store the contents of the vector double `a` into the array `d` using `_mm256_store_pd`.
    - Return the double value at index `n` from the array `d`.
- **Output**: A double-precision floating-point value extracted from the specified lane of the input vector double.


---
### wd\_insert\_variable<!-- {{#callable:wd_insert_variable}} -->
The `wd_insert_variable` function replaces a specified element in a vector of four doubles with a new double value and returns the updated vector.
- **Inputs**:
    - `a`: A vector of four double precision floating point values (wd_t).
    - `n`: An integer index (0 to 3) specifying which element in the vector to replace.
    - `v`: A double precision floating point value to insert into the vector at the specified index.
- **Control Flow**:
    - Store the elements of the vector 'a' into a local array 'd' of four doubles.
    - Replace the element at index 'n' in the array 'd' with the new value 'v'.
    - Load the modified array 'd' back into a vector and return it.
- **Output**: A vector of four double precision floating point values (wd_t) with the specified element replaced by the new value.


---
### wd\_to\_wl<!-- {{#callable:wd_to_wl}} -->
The `wd_to_wl` function converts a vector of four double-precision floating-point values to a vector of four long integers.
- **Inputs**:
    - `d`: A vector of four double-precision floating-point values (`wd_t`).
- **Control Flow**:
    - The function begins by declaring two unions: one for storing the double values and another for storing the long integer values.
    - The double values from the input vector `d` are stored into the double array of the first union using `_mm256_store_pd`.
    - Each double value in the array is then cast to a long integer and stored in the corresponding position in the long array of the second union.
    - Finally, the function returns the long integer vector by loading the long array using `_mm256_load_si256`.
- **Output**: A vector of four long integers (`__m256i`).


---
### wd\_to\_wv<!-- {{#callable:wd_to_wv}} -->
The `wd_to_wv` function converts a vector of four double-precision floating-point values (`wd_t`) into a vector of four unsigned long integers (`__m256i`).
- **Inputs**:
    - `d`: A vector of four double-precision floating-point values (`wd_t`).
- **Control Flow**:
    - The function uses a union to store the input vector `d` into an array of four doubles.
    - It then casts each double to an unsigned long and stores them in another union.
    - Finally, it loads these unsigned long values into a `__m256i` vector and returns it.
- **Output**: A `__m256i` vector containing the unsigned long integer representations of the input double values.


---
### wd\_to\_wu\_fast<!-- {{#callable:wd_to_wu_fast}} -->
The `wd_to_wu_fast` function converts a vector of double-precision floating-point numbers to a vector of unsigned integers, optimizing for different hardware capabilities.
- **Inputs**:
    - `d`: A vector of double-precision floating-point numbers (wd_t) assumed to hold integer values in the range [0, 2^32).
    - `u`: A vector of unsigned integers (wu_t) where the converted values will be inserted.
    - `imm_hi`: An integer flag indicating whether to insert the converted values into the high (1) or low (0) part of the vector.
- **Control Flow**:
    - Check if the hardware supports AVX-512F and AVX-512VL; if so, use `_mm256_cvtpd_epu32` to convert the double vector `d` to unsigned integers directly.
    - If the hardware does not support the above, emulate the conversion by subtracting 2^31 from `d`, converting the result to signed integers using `_mm256_cvtpd_epi32`, and then adjusting the result back to unsigned integers using two's complement arithmetic.
    - Use `_mm_blendv_ps` to select between the adjusted and non-adjusted results based on whether the original values were less than 2^31.
    - Insert the resulting vector of unsigned integers into the specified part (high or low) of the vector `u` using `_mm256_insertf128_si256`.
- **Output**: A vector of unsigned integers (wu_t) with the converted values inserted into either the high or low part, as specified by `imm_hi`.


---
### wd\_sum\_all<!-- {{#callable:wd_sum_all}} -->
The `wd_sum_all` function computes the sum of all elements in a vector of doubles and broadcasts the result across all elements of the vector.
- **Inputs**:
    - `x`: A vector of four double-precision floating-point numbers (wd_t type).
- **Control Flow**:
    - The function first adds the two halves of the vector using `_mm256_add_pd` and `_mm256_permute2f128_pd` to create a vector where the first two elements are the sum of the first and second halves of the original vector.
    - It then uses `_mm256_hadd_pd` to horizontally add the elements of the vector, resulting in a vector where all elements are the sum of the original vector's elements.
- **Output**: A vector of four double-precision floating-point numbers where each element is the sum of the input vector's elements.


---
### wd\_min\_all<!-- {{#callable:wd_min_all}} -->
The `wd_min_all` function computes the minimum value across all elements of a vector of doubles and broadcasts this minimum value across all elements of the resulting vector.
- **Inputs**:
    - `a`: A vector of type `wd_t` containing four double-precision floating-point values.
- **Control Flow**:
    - The function first computes the minimum of the vector `a` and its permuted version using `_mm256_permute2f128_pd` to swap the lower and upper 128-bit lanes.
    - It then computes the minimum of the resulting vector and another permuted version of itself using `_mm256_permute_pd` to swap the elements within the 128-bit lanes.
    - The final result is a vector where all elements are the minimum value found in the original vector `a`.
- **Output**: A vector of type `wd_t` where all elements are the minimum value from the input vector `a`.


---
### wd\_max\_all<!-- {{#callable:wd_max_all}} -->
The `wd_max_all` function computes the maximum value across all elements of a vector of doubles and broadcasts this maximum value across all elements of the vector.
- **Inputs**:
    - `a`: A vector of doubles (`wd_t`) containing four double-precision floating-point values.
- **Control Flow**:
    - The function first computes the maximum of the two halves of the vector `a` using `_mm256_max_pd` and `_mm256_permute2f128_pd` to permute the halves.
    - It then computes the maximum of the resulting vector by comparing adjacent pairs using `_mm256_max_pd` and `_mm256_permute_pd`.
- **Output**: A vector of doubles (`wd_t`) where each element is the maximum value found in the input vector `a`.



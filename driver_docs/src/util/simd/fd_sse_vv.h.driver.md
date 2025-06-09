# Purpose
This C source code file provides a specialized API for handling vector operations on unsigned 64-bit integers (ulongs) using SIMD (Single Instruction, Multiple Data) instructions, specifically targeting the SSE (Streaming SIMD Extensions) instruction set. The file defines a set of macros and inline functions to perform various operations on vectors of two 64-bit unsigned integers, encapsulated in the `__m128i` data type. The operations include vector construction, memory loading and storing, arithmetic operations (such as addition and subtraction), bitwise operations (such as AND, OR, XOR), logical operations, conditional operations, and conversions between different vector types. The code is designed to be used as part of a larger SIMD utility library, as indicated by the inclusion guard that requires the file to be included through a specific header (`fd_sse.h`).

The file is structured to provide efficient and robust vector operations by leveraging the capabilities of the SSE instruction set, with some operations conditionally optimized for AVX-512 if available. The use of macros allows for compile-time optimizations, while inline functions provide flexibility for operations that require more complex logic or type handling. The code also includes workarounds for limitations in the pre-AVX-512 instruction set, such as emulating certain operations that are not natively supported. This file is intended to be included in other C source files to provide SIMD functionality, and it does not define a standalone executable or public API. Instead, it serves as a utility for developers working with low-level vectorized operations in performance-critical applications.
# Functions

---
### vv\_ld<!-- {{#callable:vv_ld}} -->
The `vv_ld` function loads a 128-bit vector of two unsigned long integers from a 16-byte aligned memory location into a SIMD register.
- **Inputs**:
    - `p`: A pointer to a memory location containing two unsigned long integers, which must be 16-byte aligned.
- **Control Flow**:
    - The function casts the input pointer `p` to a pointer of type `__m128i const *`, which is suitable for SIMD operations.
    - It then uses the `_mm_load_si128` intrinsic to load the 128-bit data from the memory location pointed to by `p` into a SIMD register.
- **Output**: A `vv_t` type, which is a 128-bit SIMD register containing the loaded vector of two unsigned long integers.


---
### vv\_st<!-- {{#callable:vv_st}} -->
The `vv_st` function stores a vector of two unsigned 64-bit integers into a 16-byte aligned memory location.
- **Inputs**:
    - `p`: A pointer to a 16-byte aligned memory location where the vector will be stored.
    - `i`: A vector of type `vv_t` (which is an alias for `__m128i`) containing two unsigned 64-bit integers to be stored.
- **Control Flow**:
    - The function uses the intrinsic `_mm_store_si128` to store the vector `i` into the memory location pointed to by `p`.
- **Output**: The function does not return any value; it performs a side effect by writing to the memory location pointed to by `p`.


---
### vv\_ldu<!-- {{#callable:vv_ldu}} -->
The `vv_ldu` function loads a vector of two unsigned 64-bit integers from an unaligned memory address into a `vv_t` type using SIMD instructions.
- **Inputs**:
    - `p`: A pointer to a memory location from which the vector of unsigned 64-bit integers will be loaded; the memory does not need to be aligned.
- **Control Flow**:
    - The function casts the input pointer `p` to a pointer of type `__m128i const *`, which is suitable for SIMD operations.
    - It then uses the `_mm_loadu_si128` intrinsic to load the data from the unaligned memory location pointed to by `p` into a `__m128i` type, which is equivalent to `vv_t`.
- **Output**: The function returns a `vv_t` type, which is a vector containing two unsigned 64-bit integers loaded from the specified memory location.


---
### vv\_stu<!-- {{#callable:vv_stu}} -->
The `vv_stu` function stores a vector of two unsigned 64-bit integers into a memory location that does not need to be aligned.
- **Inputs**:
    - `p`: A pointer to the memory location where the vector will be stored; it does not need to be aligned.
    - `i`: A vector of type `vv_t` (which is an alias for `__m128i`) containing two unsigned 64-bit integers to be stored.
- **Control Flow**:
    - The function uses the intrinsic `_mm_storeu_si128` to store the vector `i` into the memory location pointed to by `p`.
- **Output**: The function does not return any value; it performs a side effect by storing data at the specified memory location.


---
### vv\_extract\_variable<!-- {{#callable:vv_extract_variable}} -->
The `vv_extract_variable` function extracts a 64-bit unsigned integer from a specified lane of a 128-bit SIMD vector.
- **Inputs**:
    - `a`: A 128-bit SIMD vector (`vv_t`) containing two 64-bit unsigned integers.
    - `n`: An integer specifying the lane (0 or 1) from which to extract the 64-bit unsigned integer.
- **Control Flow**:
    - A union is defined to allow type punning between a 128-bit SIMD vector and an array of two 64-bit unsigned integers.
    - The SIMD vector `a` is stored into the union's `__m128i` member using `_mm_store_si128`.
    - The function returns the `n`-th element from the union's `ulong` array, effectively extracting the 64-bit unsigned integer from the specified lane.
- **Output**: A 64-bit unsigned integer extracted from the specified lane of the input SIMD vector.


---
### vv\_insert\_variable<!-- {{#callable:vv_insert_variable}} -->
The `vv_insert_variable` function inserts a 64-bit unsigned integer into a specified lane of a 128-bit vector and returns the modified vector.
- **Inputs**:
    - `a`: A 128-bit vector of type `vv_t` (which is an alias for `__m128i`) containing two 64-bit unsigned integers.
    - `n`: An integer specifying the lane (0 or 1) in the vector `a` where the value `v` should be inserted.
    - `v`: A 64-bit unsigned integer (`ulong`) to be inserted into the vector `a` at the specified lane `n`.
- **Control Flow**:
    - A union is defined to allow type punning between `__m128i` and an array of two `ulong` values.
    - The input vector `a` is stored into the union's `__m128i` member using `_mm_store_si128`.
    - The `ulong` value `v` is inserted into the `n`-th position of the union's `ulong` array.
    - The modified vector is loaded back from the union's `__m128i` member using `_mm_load_si128` and returned.
- **Output**: A 128-bit vector of type `vv_t` with the specified lane `n` replaced by the value `v`.


---
### vv\_rol<!-- {{#callable:vv_rol}} -->
The `vv_rol` function performs a bitwise left rotation on a vector of two 64-bit unsigned integers by a specified number of bits.
- **Inputs**:
    - `a`: A vector of two 64-bit unsigned integers (type `vv_t`) to be rotated.
    - `imm`: An integer specifying the number of bits to rotate the vector to the left.
- **Control Flow**:
    - The function calculates the effective number of bits to rotate by taking `imm & 63`, ensuring the shift amount is within the range of 0 to 63 bits.
    - It performs a left shift on the vector `a` by the calculated number of bits using `vv_shl`.
    - It performs a right shift on the vector `a` by the negative of the calculated number of bits using `vv_shr`.
    - The results of the left and right shifts are combined using a bitwise OR operation (`vv_or`) to produce the final rotated vector.
- **Output**: The function returns a vector of two 64-bit unsigned integers (`vv_t`) that is the result of the left rotation operation.


---
### vv\_ror<!-- {{#callable:vv_ror}} -->
The `vv_ror` function performs a bitwise right rotation on a vector of two 64-bit unsigned integers by a specified number of bits.
- **Inputs**:
    - `a`: A vector of two 64-bit unsigned integers (type `vv_t`) to be rotated.
    - `imm`: An integer specifying the number of bits to rotate the vector to the right.
- **Control Flow**:
    - The function calculates the effective number of bits to rotate by taking `imm & 63`, ensuring the shift amount is within the range of 0 to 63.
    - It performs a right shift on the vector `a` by the calculated number of bits using `vv_shr`.
    - It performs a left shift on the vector `a` by the complement of the calculated number of bits using `vv_shl`.
    - The results of the right and left shifts are combined using a bitwise OR operation with `vv_or` to produce the final rotated vector.
- **Output**: The function returns a vector of two 64-bit unsigned integers (`vv_t`) that is the result of the right rotation operation.


---
### vv\_rol\_variable<!-- {{#callable:vv_rol_variable}} -->
The `vv_rol_variable` function performs a variable bitwise left rotation on a vector of two 64-bit unsigned integers.
- **Inputs**:
    - `a`: A vector of two 64-bit unsigned integers (type `vv_t`) to be rotated.
    - `n`: An integer specifying the number of bits to rotate the vector `a` to the left.
- **Control Flow**:
    - The function calculates `n & 63` to ensure the rotation amount is within the range of 0 to 63 bits.
    - It performs a left shift on the vector `a` by `n & 63` bits using `vv_shl_variable`.
    - It performs a right shift on the vector `a` by `(-n) & 63` bits using `vv_shr_variable`.
    - The results of the left and right shifts are combined using a bitwise OR operation with `vv_or`.
    - The combined result is returned as the output of the function.
- **Output**: A vector of two 64-bit unsigned integers (type `vv_t`) that is the result of rotating the input vector `a` to the left by `n` bits.


---
### vv\_ror\_variable<!-- {{#callable:vv_ror_variable}} -->
The `vv_ror_variable` function performs a variable bitwise right rotation on a vector of two 64-bit unsigned integers.
- **Inputs**:
    - `a`: A vector of two 64-bit unsigned integers (type `vv_t`) to be rotated.
    - `n`: An integer specifying the number of positions to rotate the vector to the right.
- **Control Flow**:
    - The function first calculates `n & 63` to ensure the rotation amount is within the range of 0 to 63 bits.
    - It then performs a right shift on the vector `a` by `n & 63` bits using `vv_shr_variable`.
    - Simultaneously, it performs a left shift on the vector `a` by `(-n) & 63` bits using `vv_shl_variable`.
    - The results of the two shifts are combined using a bitwise OR operation via `vv_or`.
    - The combined result is returned as the output of the function.
- **Output**: A vector of two 64-bit unsigned integers (type `vv_t`) that is the result of rotating the input vector `a` to the right by `n` positions.


---
### vv\_rol\_vector<!-- {{#callable:vv_rol_vector}} -->
The `vv_rol_vector` function performs a bitwise left rotation on each 64-bit integer in a vector by a specified number of bits, using another vector to determine the rotation amount for each integer.
- **Inputs**:
    - `a`: A vector of 64-bit unsigned integers (`vv_t`) to be rotated.
    - `b`: A vector of 64-bit integers (`vl_t`) specifying the number of bits to rotate each corresponding integer in `a`.
- **Control Flow**:
    - A constant vector `m` is created with all elements set to 63, which is used to mask the rotation amount to ensure it is within the range of 0 to 63 bits.
    - The function calculates the left rotation by shifting the elements of `a` left by the masked values of `b` using `vv_shl_vector`.
    - It calculates the right rotation by shifting the elements of `a` right by the masked negated values of `b` using `vv_shr_vector`.
    - The results of the left and right shifts are combined using a bitwise OR operation (`vv_or`) to produce the final rotated vector.
- **Output**: A vector of 64-bit unsigned integers (`vv_t`) where each integer has been rotated left by the specified number of bits.


---
### vv\_ror\_vector<!-- {{#callable:vv_ror_vector}} -->
The `vv_ror_vector` function performs a bitwise right rotation on each 64-bit lane of a vector `a` by a variable amount specified in vector `b`.
- **Inputs**:
    - `a`: A vector of type `vv_t` containing two 64-bit unsigned integers to be rotated.
    - `b`: A vector of type `vl_t` specifying the number of positions to rotate each corresponding 64-bit lane in `a` to the right.
- **Control Flow**:
    - Broadcast the constant value 63 into a vector `m` using `vl_bcast` to ensure the shift amount is within the valid range of 0 to 63 bits.
    - Perform a bitwise AND operation between `b` and `m` to get the effective right shift amount for each lane.
    - Perform a right shift on vector `a` using the effective shift amount obtained from the previous step using `vv_shr_vector`.
    - Negate the vector `b` and perform a bitwise AND with `m` to get the effective left shift amount for each lane.
    - Perform a left shift on vector `a` using the effective shift amount obtained from the previous step using `vv_shl_vector`.
    - Combine the results of the right and left shifts using a bitwise OR operation with `vv_or` to achieve the rotation effect.
- **Output**: The function returns a vector of type `vv_t` where each 64-bit lane has been right-rotated by the specified amount in `b`.


---
### vv\_min<!-- {{#callable:vv_min}} -->
The `vv_min` function returns a vector containing the minimum values from two input vectors, element-wise.
- **Inputs**:
    - `a`: A vector of type `vv_t` containing two 64-bit unsigned integers.
    - `b`: A vector of type `vv_t` containing two 64-bit unsigned integers.
- **Control Flow**:
    - The function compares each element of vector `a` with the corresponding element of vector `b` using the `vv_lt` function to determine if elements in `a` are less than those in `b`.
    - It uses the `vv_if` function to select elements from `a` where `a` is less than `b`, otherwise it selects elements from `b`.
    - The result is a new vector containing the minimum values from each pair of elements in `a` and `b`.
- **Output**: A vector of type `vv_t` containing the minimum values from the corresponding elements of vectors `a` and `b`.


---
### vv\_max<!-- {{#callable:vv_max}} -->
The `vv_max` function returns a vector containing the maximum values from corresponding lanes of two input vectors.
- **Inputs**:
    - `a`: A vector of type `vv_t` containing two 64-bit unsigned integers.
    - `b`: A vector of type `vv_t` containing two 64-bit unsigned integers.
- **Control Flow**:
    - The function compares the two input vectors `a` and `b` using the `vv_gt` macro, which checks if elements in `a` are greater than those in `b`.
    - It then uses the `vv_if` macro to select elements from `a` where `a` is greater than `b`, and from `b` otherwise.
    - The result is a new vector where each lane contains the maximum value from the corresponding lanes of `a` and `b`.
- **Output**: A vector of type `vv_t` containing the maximum values from each corresponding lane of the input vectors `a` and `b`.


---
### vv\_to\_vf<!-- {{#callable:vv_to_vf}} -->
The `vv_to_vf` function converts a vector of unsigned 64-bit integers to a vector of floats, inserting the converted values into specified positions of an existing float vector based on a control flag.
- **Inputs**:
    - `v`: A vector of unsigned 64-bit integers (`vv_t`) from which two elements will be extracted and converted to floats.
    - `f`: A vector of floats (`vf_t`) into which the converted float values will be inserted.
    - `imm_hi`: An integer flag that determines the positions in the float vector `f` where the converted values will be inserted.
- **Control Flow**:
    - Extract the first element from the vector `v` and convert it to a float, storing it in `f0`.
    - Extract the second element from the vector `v` and convert it to a float, storing it in `f1`.
    - Check the value of `imm_hi`. If it is non-zero, insert `f0` and `f1` into positions 2 and 3 of the float vector `f`, respectively.
    - If `imm_hi` is zero, insert `f0` and `f1` into positions 0 and 1 of the float vector `f`, respectively.
    - Return the modified float vector `f`.
- **Output**: A vector of floats (`vf_t`) with the converted values from the vector `v` inserted into specified positions.


---
### vv\_to\_vi<!-- {{#callable:vv_to_vi}} -->
The `vv_to_vi` function converts a vector of unsigned 64-bit integers to a vector of signed 32-bit integers, optionally interleaving with another vector based on a control flag.
- **Inputs**:
    - `v`: A vector of unsigned 64-bit integers (vv_t) to be converted.
    - `i`: A vector of signed 32-bit integers (vi_t) to be interleaved with the converted vector.
    - `imm_hi`: An integer flag that determines the interleaving pattern of the vectors.
- **Control Flow**:
    - Cast the input vector `v` to a vector of single-precision floats (`vf_t`).
    - Cast the input vector `i` to a vector of single-precision floats (`vf_t`).
    - Check the `imm_hi` flag to determine the interleaving pattern.
    - If `imm_hi` is true, shuffle the vectors using the pattern `_MM_SHUFFLE(2,0,1,0)`.
    - If `imm_hi` is false, shuffle the vectors using the pattern `_MM_SHUFFLE(3,2,2,0)`.
    - Cast the shuffled vector back to a vector of signed 32-bit integers (`vv_t`).
- **Output**: A vector of signed 32-bit integers (vv_t) resulting from the conversion and optional interleaving of the input vectors.


---
### vv\_to\_vu<!-- {{#callable:vv_to_vu}} -->
The `vv_to_vu` function converts a vector of unsigned 64-bit integers to another vector of unsigned 64-bit integers, optionally shuffling the elements based on a compile-time constant.
- **Inputs**:
    - `v`: A vector of unsigned 64-bit integers (`vv_t`) to be converted.
    - `u`: A vector of unsigned 64-bit integers (`vu_t`) used in the shuffle operation.
    - `imm_hi`: An integer flag that determines the shuffle pattern to be applied.
- **Control Flow**:
    - The function casts the input vectors `v` and `u` from integer to floating-point representations using `_mm_castsi128_ps`.
    - It checks the value of `imm_hi` to decide which shuffle pattern to apply using `_mm_shuffle_ps`.
    - If `imm_hi` is non-zero, it shuffles the vectors using the pattern `_MM_SHUFFLE(2,0,1,0)`.
    - If `imm_hi` is zero, it shuffles the vectors using the pattern `_MM_SHUFFLE(3,2,2,0)`.
    - Finally, it casts the shuffled floating-point vector back to an integer vector using `_mm_castps_si128` and returns it.
- **Output**: The function returns a vector of unsigned 64-bit integers (`vv_t`) that is a shuffled combination of the input vectors `v` and `u`.


---
### vv\_to\_vd<!-- {{#callable:vv_to_vd}} -->
The `vv_to_vd` function converts a vector of two unsigned 64-bit integers into a vector of two double-precision floating-point numbers.
- **Inputs**:
    - `v`: A vector of type `vv_t` containing two unsigned 64-bit integers.
- **Control Flow**:
    - Extracts the first 64-bit integer from the input vector `v` using `_mm_extract_epi64` and casts it to a `double`.
    - Extracts the second 64-bit integer from the input vector `v` using `_mm_extract_epi64` and casts it to a `double`.
    - Creates a new vector of type `vd_t` with the two double values using `_mm_setr_pd`.
- **Output**: A vector of type `vd_t` containing two double-precision floating-point numbers corresponding to the two unsigned 64-bit integers from the input vector.


---
### vv\_sum\_all<!-- {{#callable:vv_sum_all}} -->
The `vv_sum_all` function computes the sum of two 64-bit unsigned integers stored in a vector and returns a vector with both lanes containing this sum.
- **Inputs**:
    - `x`: A vector of type `vv_t` containing two 64-bit unsigned integers.
- **Control Flow**:
    - The function takes a vector `x` as input, which contains two 64-bit unsigned integers.
    - It uses `vv_permute` to swap the two lanes of the vector `x`, effectively creating a new vector with the lanes reversed.
    - The function then adds the original vector `x` and the permuted vector using `vv_add`, resulting in a vector where each lane contains the sum of the two original integers.
- **Output**: A vector of type `vv_t` where both lanes contain the sum of the two 64-bit unsigned integers from the input vector.


---
### vv\_min\_all<!-- {{#callable:vv_min_all}} -->
The `vv_min_all` function computes the minimum value of a vector of two unsigned 64-bit integers and broadcasts this minimum value across both lanes of the vector.
- **Inputs**:
    - `x`: A vector of type `vv_t` containing two unsigned 64-bit integers.
- **Control Flow**:
    - The function calls `vv_permute` on the input vector `x` with parameters `1` and `0`, which swaps the two lanes of the vector.
    - It then calls [`vv_min`](#vv_min) with the original vector `x` and the permuted vector to compute the minimum of the two lanes.
    - The result of [`vv_min`](#vv_min) is returned, which is a vector with the minimum value broadcasted to both lanes.
- **Output**: A vector of type `vv_t` where both lanes contain the minimum value of the input vector's lanes.
- **Functions called**:
    - [`vv_min`](#vv_min)


---
### vv\_max\_all<!-- {{#callable:vv_max_all}} -->
The `vv_max_all` function returns a vector where each lane contains the maximum value from the input vector `x`.
- **Inputs**:
    - `x`: A vector of type `vv_t` containing two 64-bit unsigned integers.
- **Control Flow**:
    - The function calls `vv_permute` on the input vector `x` with parameters 1 and 0, effectively swapping the two lanes of the vector.
    - It then calls [`vv_max`](#vv_max) with the original vector `x` and the permuted vector to compute the maximum of the two lanes.
    - The result of [`vv_max`](#vv_max) is returned, which is a vector where both lanes contain the maximum value from the original vector `x`.
- **Output**: A vector of type `vv_t` where both lanes contain the maximum value from the input vector `x`.
- **Functions called**:
    - [`vv_max`](#vv_max)


---
### \_vv\_gather<!-- {{#callable:_vv_gather}} -->
The function `_vv_gather` gathers 64-bit integers from a base array using 32-bit indices specified in a vector.
- **Inputs**:
    - `b`: A pointer to an array of unsigned long integers, serving as the base address for gathering elements.
    - `i`: A vector of 32-bit integers (`vi_t`) used as indices to gather elements from the base array `b`.
- **Control Flow**:
    - The function uses the intrinsic `_mm_i32gather_epi64` to gather 64-bit integers from the base array `b` using the indices specified in the vector `i`.
    - The gathered elements are returned as a vector of type `vv_t`, which is an alias for `__m128i`.
- **Output**: A vector of type `vv_t` containing the gathered 64-bit integers from the base array `b`.



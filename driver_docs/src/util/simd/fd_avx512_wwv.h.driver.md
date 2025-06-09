# Purpose
This C source code file provides a specialized set of macros and inline functions for handling vector operations using AVX-512 SIMD (Single Instruction, Multiple Data) instructions, specifically targeting operations on vectors of unsigned 64-bit integers (ulongs). The file defines a type `wwv_t` as a vector of 512 bits, which can hold eight 64-bit unsigned integers. It includes a variety of operations such as vector construction, memory loading and storing, arithmetic operations (addition, subtraction, multiplication), binary operations (bitwise AND, OR, XOR), and comparison operations. The code is designed to leverage the AVX-512 instruction set to perform these operations efficiently in parallel, which is particularly useful in high-performance computing scenarios where processing large datasets or performing complex calculations quickly is essential.

The file is intended to be included indirectly through another header file (`fd_avx512.h`), as indicated by the preprocessor directive at the beginning. This suggests that it is part of a larger library or framework that provides SIMD utilities. The macros and inline functions defined here are designed to be robust and efficient, minimizing the risk of compiler optimizations interfering with the intended operations. The file does not define a public API or external interfaces directly but provides low-level building blocks that can be used to implement higher-level functionality. The use of macros over static inline functions where possible indicates a focus on performance and reducing overhead, which is critical in SIMD operations.
# Global Variables

---
### \_wwv\_transpose\_t0
- **Type**: `wwv_t`
- **Description**: The variable `_wwv_transpose_t0` is a temporary variable of type `wwv_t`, which is defined as a vector of 64-bit unsigned integers using the AVX-512 intrinsic type `__m512i`. It is used in the process of transposing an 8x8 matrix of unsigned long integers, specifically during the outer 4x4 transpose of 2x2 blocks.
- **Use**: This variable is used to store intermediate results during the matrix transposition operation, facilitating the rearrangement of data blocks.


---
### \_wwv\_transpose\_t1
- **Type**: `wwv_t`
- **Description**: The variable `_wwv_transpose_t1` is a vector of type `wwv_t`, which is an alias for `__m512i`, representing a 512-bit integer vector. It is initialized using the `_mm512_shuffle_i64x2` intrinsic, which shuffles 64-bit integers from two source vectors, `_wwv_transpose_r1` and `_wwv_transpose_r3`, according to the control mask `0x88`. This operation is part of a larger process to transpose an 8x8 matrix of unsigned 64-bit integers.
- **Use**: This variable is used as an intermediate step in the outer 4x4 transpose of 2x2 blocks within the `wwv_transpose_8x8` macro.


---
### \_wwv\_transpose\_t2
- **Type**: `wwv_t`
- **Description**: The variable `_wwv_transpose_t2` is a global variable of type `wwv_t`, which is defined as a vector of 64-bit unsigned integers using the AVX-512 intrinsic type `__m512i`. It is initialized using the `_mm512_shuffle_i64x2` intrinsic function, which shuffles 64-bit integers from two source vectors, `_wwv_transpose_r0` and `_wwv_transpose_r2`, according to the control mask `0xdd`.
- **Use**: This variable is used in the process of transposing an 8x8 matrix of unsigned long integers, specifically in the outer 4x4 transpose of 2x2 blocks.


---
### \_wwv\_transpose\_t3
- **Type**: `wwv_t`
- **Description**: The variable `_wwv_transpose_t3` is a vector of type `wwv_t`, which is an alias for `__m512i`, representing a 512-bit integer vector. It is initialized using the `_mm512_shuffle_i64x2` intrinsic, which shuffles 64-bit integers from two source vectors, `_wwv_transpose_r1` and `_wwv_transpose_r3`, based on the control mask `0xdd`.
- **Use**: This variable is used in the process of transposing an 8x8 matrix of unsigned 64-bit integers, specifically during the outer 4x4 transpose of 2x2 blocks.


---
### \_wwv\_transpose\_t4
- **Type**: `wwv_t`
- **Description**: The variable `_wwv_transpose_t4` is a vector of type `wwv_t`, which is an alias for `__m512i`, representing a 512-bit integer vector. It is initialized using the `_mm512_shuffle_i64x2` intrinsic, which shuffles 64-bit integers from two source vectors, `_wwv_transpose_r4` and `_wwv_transpose_r6`, according to the control mask `0x88`. This operation is part of a larger process to transpose an 8x8 matrix of unsigned 64-bit integers.
- **Use**: This variable is used in the process of transposing an 8x8 matrix of unsigned 64-bit integers by shuffling elements between vectors.


---
### \_wwv\_transpose\_t5
- **Type**: `wwv_t`
- **Description**: The variable `_wwv_transpose_t5` is a vector of type `wwv_t`, which is an alias for `__m512i`, representing a 512-bit integer vector. It is initialized using the `_mm512_shuffle_i64x2` intrinsic, which shuffles 64-bit integers from two source vectors, `_wwv_transpose_r5` and `_wwv_transpose_r7`, according to the control mask `0x88`. This operation is part of a larger process to transpose an 8x8 matrix of unsigned 64-bit integers.
- **Use**: `_wwv_transpose_t5` is used in the process of transposing an 8x8 matrix by shuffling elements from two vectors to form part of the transposed matrix.


---
### \_wwv\_transpose\_t6
- **Type**: `wwv_t`
- **Description**: The variable `_wwv_transpose_t6` is a vector of type `wwv_t`, which is defined as `__m512i`, a 512-bit integer vector type used in AVX-512 operations. It is initialized using the `_mm512_shuffle_i64x2` intrinsic, which shuffles 64-bit integers from two source vectors, `_wwv_transpose_r4` and `_wwv_transpose_r6`, according to the control mask `0xdd`. This operation is part of a larger process to transpose an 8x8 matrix of unsigned 64-bit integers.
- **Use**: This variable is used in the process of transposing an 8x8 matrix of unsigned 64-bit integers by shuffling elements from two source vectors.


---
### \_wwv\_transpose\_t7
- **Type**: `wwv_t`
- **Description**: The variable `_wwv_transpose_t7` is a global variable of type `wwv_t`, which is defined as a vector of 64-bit unsigned integers using the AVX-512 intrinsic type `__m512i`. It is initialized using the `_mm512_shuffle_i64x2` intrinsic function, which shuffles 64-bit integers from two source vectors, `_wwv_transpose_r5` and `_wwv_transpose_r7`, according to the control mask `0xdd`.
- **Use**: This variable is used in the process of transposing an 8x8 matrix of unsigned long integers, specifically as part of the intermediate steps in the `wwv_transpose_8x8` macro.


# Functions

---
### wwv\_ld<!-- {{#callable:wwv_ld}} -->
The `wwv_ld` function loads a 512-bit vector of eight 64-bit unsigned integers from a 64-byte aligned memory location.
- **Inputs**:
    - `m`: A pointer to a constant unsigned long integer array, which must be 64-byte aligned, from which the vector will be loaded.
- **Control Flow**:
    - The function uses the intrinsic `_mm512_load_epi64` to load a 512-bit vector from the memory location pointed to by `m`.
- **Output**: The function returns a `wwv_t` type, which is a 512-bit vector containing eight 64-bit unsigned integers loaded from the specified memory location.


---
### wwv\_st<!-- {{#callable:wwv_st}} -->
The `wwv_st` function stores the contents of a vector of unsigned 64-bit integers into a memory location.
- **Inputs**:
    - `m`: A pointer to a memory location where the vector's contents will be stored; it should be 64-byte aligned.
    - `x`: A vector of type `wwv_t` containing eight unsigned 64-bit integers to be stored.
- **Control Flow**:
    - The function uses the intrinsic `_mm512_store_epi64` to store the vector `x` into the memory location pointed to by `m`.
- **Output**: The function does not return a value; it performs a side effect by storing data in the memory location pointed to by `m`.


---
### wwv\_ldu<!-- {{#callable:wwv_ldu}} -->
The `wwv_ldu` function loads a 512-bit vector of unsigned 64-bit integers from an unaligned memory address.
- **Inputs**:
    - `m`: A pointer to the memory location from which the 512-bit vector of unsigned 64-bit integers is to be loaded.
- **Control Flow**:
    - The function uses the `_mm512_loadu_epi64` intrinsic to load a 512-bit vector from the memory address pointed to by `m`.
    - The intrinsic allows loading from an unaligned memory address, which means `m` does not need to be 64-byte aligned.
- **Output**: A `wwv_t` type, which is a 512-bit vector containing eight unsigned 64-bit integers loaded from the specified memory location.


---
### wwv\_stu<!-- {{#callable:wwv_stu}} -->
The `wwv_stu` function stores a 512-bit vector of unsigned 64-bit integers into a memory location with arbitrary alignment.
- **Inputs**:
    - `m`: A pointer to the memory location where the vector will be stored; it can have arbitrary alignment.
    - `x`: A `wwv_t` type, which is a 512-bit vector containing eight unsigned 64-bit integers to be stored.
- **Control Flow**:
    - The function uses the `_mm512_storeu_epi64` intrinsic to store the vector `x` into the memory location pointed to by `m`.
- **Output**: The function does not return any value; it performs a side effect by storing data into the memory location pointed to by `m`.


---
### wwv\_rol\_variable<!-- {{#callable:wwv_rol_variable}} -->
The `wwv_rol_variable` function performs a variable left rotation on each 64-bit lane of a 512-bit vector of unsigned long integers.
- **Inputs**:
    - `a`: A 512-bit vector (`wwv_t`) containing eight 64-bit unsigned long integers to be rotated.
    - `n`: An unsigned long integer specifying the number of positions to rotate each 64-bit lane to the left.
- **Control Flow**:
    - The function calculates `n & 63UL` to ensure the rotation amount is within the range of 0 to 63, as each lane is 64 bits wide.
    - It performs a left shift on the vector `a` by `n & 63UL` positions using `wwv_shl`.
    - It performs a right shift on the vector `a` by `(-n) & 63UL` positions using `wwv_shr`, effectively calculating the equivalent right shift for the left rotation.
    - The results of the left and right shifts are combined using a bitwise OR operation (`wwv_or`) to complete the rotation.
- **Output**: A 512-bit vector (`wwv_t`) where each 64-bit lane has been left-rotated by `n` positions.


---
### wwv\_ror\_variable<!-- {{#callable:wwv_ror_variable}} -->
The `wwv_ror_variable` function performs a variable right rotation on a vector of unsigned 64-bit integers.
- **Inputs**:
    - `a`: A vector of unsigned 64-bit integers (wwv_t) to be rotated.
    - `n`: An unsigned long integer specifying the number of positions to rotate the vector to the right.
- **Control Flow**:
    - The function calculates the effective number of positions to rotate by taking the bitwise AND of n with 63 (n & 63UL).
    - It performs a right shift on the vector 'a' by the calculated number of positions using `wwv_shr`.
    - It performs a left shift on the vector 'a' by the negative of the calculated number of positions using `wwv_shl`.
    - The results of the right and left shifts are combined using a bitwise OR operation with `wwv_or`.
    - The combined result is returned as the output of the function.
- **Output**: A vector of unsigned 64-bit integers (wwv_t) that is the result of rotating the input vector 'a' to the right by 'n' positions.


---
### wwv\_rol\_vector<!-- {{#callable:wwv_rol_vector}} -->
The `wwv_rol_vector` function performs a bitwise left rotation on each 64-bit lane of a vector `a` by the corresponding amount specified in vector `b`, using AVX-512 intrinsics.
- **Inputs**:
    - `a`: A vector of type `wwv_t` containing 64-bit unsigned integers to be rotated.
    - `b`: A vector of type `wwv_t` containing the rotation amounts for each corresponding lane in vector `a`.
- **Control Flow**:
    - Create a mask `m` with all lanes set to 63 using `wwv_bcast(63UL)` to ensure rotation amounts are within valid range.
    - Compute the bitwise AND of vector `b` and mask `m` to get valid left rotation amounts for each lane.
    - Compute the bitwise AND of the negation of vector `b` and mask `m` to get valid right rotation amounts for each lane.
    - Perform a left shift on vector `a` by the computed left rotation amounts using `wwv_shl_vector`.
    - Perform a right shift on vector `a` by the computed right rotation amounts using `wwv_shr_vector`.
    - Combine the results of the left and right shifts using a bitwise OR operation with `wwv_or` to achieve the final rotated vector.
- **Output**: The function returns a vector of type `wwv_t` where each 64-bit lane has been left-rotated by the corresponding amount specified in vector `b`.


---
### wwv\_ror\_vector<!-- {{#callable:wwv_ror_vector}} -->
The `wwv_ror_vector` function performs a bitwise right rotation on each 64-bit integer in a vector by a variable amount specified by another vector.
- **Inputs**:
    - `a`: A vector of 64-bit unsigned integers to be rotated.
    - `b`: A vector specifying the number of positions to rotate each corresponding integer in vector 'a'.
- **Control Flow**:
    - Create a mask vector 'm' with all elements set to 63, which is used to ensure the rotation amount is within the valid range of 0 to 63 bits.
    - Perform a bitwise AND between vector 'b' and the mask 'm' to get the effective right rotation amounts for each element.
    - Shift each element in vector 'a' to the right by the effective rotation amounts using `wwv_shr_vector`.
    - Negate vector 'b', perform a bitwise AND with the mask 'm', and shift each element in vector 'a' to the left by these amounts using `wwv_shl_vector`.
    - Combine the results of the right and left shifts using a bitwise OR to complete the rotation.
- **Output**: A vector of 64-bit unsigned integers, where each element is the result of rotating the corresponding element in 'a' to the right by the amount specified in 'b'.



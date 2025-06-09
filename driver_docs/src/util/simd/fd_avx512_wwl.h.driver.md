# Purpose
This C source code file provides a specialized set of macros and inline functions for handling vector operations using AVX-512 SIMD (Single Instruction, Multiple Data) instructions, specifically targeting operations on vectors of 64-bit integers. The file defines a type `wwl_t` as a vector of eight 64-bit integers and provides a comprehensive API for various operations on these vectors. These operations include arithmetic, binary, comparison, conditional, and conversion operations, as well as memory operations for loading and storing vectors. The code is structured to leverage the AVX-512 instruction set to perform operations in parallel, which can significantly enhance performance for applications that require high-throughput data processing.

The file is intended to be included indirectly through a header file named `fd_avx512.h`, as indicated by the preprocessor directive at the beginning. This suggests that the file is part of a larger library or framework that provides SIMD utilities. The macros and inline functions defined here are designed to be robust and efficient, minimizing the risk of compiler optimizations interfering with the intended operations. The use of macros allows for flexibility and performance optimization, while the inline functions provide additional functionality where macros are not suitable. The file does not define public APIs or external interfaces directly but rather serves as an internal component of a broader SIMD utility library, providing essential building blocks for vectorized computations.
# Global Variables

---
### \_wwl\_transpose\_t0
- **Type**: `wwl_t`
- **Description**: The variable `_wwl_transpose_t0` is a vector of type `wwl_t`, which is defined as `__m512i`, representing a 512-bit integer vector. It is initialized using the `_mm512_shuffle_i64x2` intrinsic, which shuffles 64-bit integers from two source vectors, `_wwl_transpose_r0` and `_wwl_transpose_r2`, according to the control mask `0x88`. This operation is part of a larger process to transpose an 8x8 matrix of 64-bit integers.
- **Use**: This variable is used in the process of transposing an 8x8 matrix of 64-bit integers by shuffling elements from two source vectors.


---
### \_wwl\_transpose\_t1
- **Type**: `wwl_t`
- **Description**: The variable `_wwl_transpose_t1` is a global variable of type `wwl_t`, which is defined as a vector of signed 64-bit two's complement integers using the AVX-512 intrinsic type `__m512i`. It is initialized using the `_mm512_shuffle_i64x2` intrinsic function, which shuffles 64-bit integers from two source vectors, `_wwl_transpose_r1` and `_wwl_transpose_r3`, according to the control mask `0x88`. This operation is part of a larger process to transpose an 8x8 matrix of 64-bit integers.
- **Use**: This variable is used in the process of transposing an 8x8 matrix of 64-bit integers, specifically in the outer 4x4 transpose of 2x2 blocks.


---
### \_wwl\_transpose\_t2
- **Type**: `wwl_t`
- **Description**: The variable `_wwl_transpose_t2` is a vector of signed 64-bit integers, defined using the AVX-512 intrinsic `_mm512_shuffle_i64x2`. It is part of a sequence of operations that perform a 4x4 transpose of 2x2 blocks within an 8x8 matrix of long integers.
- **Use**: It is used to store intermediate results during the transposition of matrix rows into columns.


---
### \_wwl\_transpose\_t3
- **Type**: `wwl_t`
- **Description**: The variable `_wwl_transpose_t3` is a vector of type `wwl_t`, which is defined as `__m512i`, a 512-bit integer vector type used in AVX-512 SIMD operations. It is initialized using the `_mm512_shuffle_i64x2` intrinsic, which shuffles 64-bit integers from two source vectors, `_wwl_transpose_r1` and `_wwl_transpose_r3`, according to the control mask `0xdd`. This operation is part of a larger process to transpose an 8x8 matrix of 64-bit integers.
- **Use**: This variable is used in the process of transposing an 8x8 matrix of 64-bit integers, specifically handling the shuffling of elements from two source vectors.


---
### \_wwl\_transpose\_t4
- **Type**: `wwl_t`
- **Description**: The variable `_wwl_transpose_t4` is a vector of type `wwl_t`, which is defined as `__m512i`, representing a 512-bit integer vector. It is initialized using the `_mm512_shuffle_i64x2` intrinsic, which shuffles 64-bit integers from two source vectors, `_wwl_transpose_r4` and `_wwl_transpose_r6`, according to the control mask `0x88`. This operation is part of a larger process to transpose an 8x8 matrix of 64-bit integers.
- **Use**: This variable is used in the process of transposing an 8x8 matrix of 64-bit integers, specifically in the outer 4x4 transpose of 2x2 blocks.


---
### \_wwl\_transpose\_t5
- **Type**: `wwl_t`
- **Description**: The variable `_wwl_transpose_t5` is a global variable of type `wwl_t`, which is defined as a vector of signed 64-bit integers using the AVX-512 instruction set. It is initialized using the `_mm512_shuffle_i64x2` intrinsic, which shuffles 64-bit integers from two source vectors, `_wwl_transpose_r5` and `_wwl_transpose_r7`, according to the control mask `0x88`. This operation is part of a larger process to transpose an 8x8 matrix of 64-bit integers.
- **Use**: This variable is used in the process of transposing an 8x8 matrix of 64-bit integers, specifically as an intermediate step in the outer 4x4 transpose of 2x2 blocks.


---
### \_wwl\_transpose\_t6
- **Type**: `wwl_t`
- **Description**: The variable `_wwl_transpose_t6` is a global variable of type `wwl_t`, which is defined as a vector of signed 64-bit two's complement integers using the AVX-512 intrinsic type `__m512i`. It is initialized using the `_mm512_shuffle_i64x2` intrinsic function, which shuffles 64-bit integers from two source vectors, `_wwl_transpose_r4` and `_wwl_transpose_r6`, according to the control mask `0xdd`.
- **Use**: This variable is used in the process of transposing an 8x8 matrix of 64-bit integers, specifically as part of the outer 4x4 transpose of 2x2 blocks.


---
### \_wwl\_transpose\_t7
- **Type**: `wwl_t`
- **Description**: The variable `_wwl_transpose_t7` is a global variable of type `wwl_t`, which is defined as a 512-bit integer vector (`__m512i`). It is initialized using the `_mm512_shuffle_i64x2` intrinsic function, which shuffles 64-bit integers from two source vectors, `_wwl_transpose_r5` and `_wwl_transpose_r7`, according to the control mask `0xdd`. This operation is part of a larger process to transpose an 8x8 matrix of 64-bit integers.
- **Use**: This variable is used in the process of transposing an 8x8 matrix of 64-bit integers, specifically in the outer 4x4 transpose of 2x2 blocks.


# Functions

---
### wwl\_ld<!-- {{#callable:wwl_ld}} -->
The `wwl_ld` function loads a 512-bit vector of eight 64-bit integers from a 64-byte aligned memory location.
- **Inputs**:
    - `m`: A pointer to a constant long integer array, which must be 64-byte aligned, from which the 512-bit vector will be loaded.
- **Control Flow**:
    - The function uses the `_mm512_load_epi64` intrinsic to load eight 64-bit integers from the memory location pointed to by `m` into a 512-bit vector.
- **Output**: A `wwl_t` type, which is a 512-bit vector containing eight 64-bit integers loaded from the specified memory location.


---
### wwl\_st<!-- {{#callable:wwl_st}} -->
The `wwl_st` function stores the elements of a 512-bit vector of 64-bit integers into a memory location.
- **Inputs**:
    - `m`: A pointer to a memory location where the vector elements will be stored; it should be 64-byte aligned.
    - `x`: A 512-bit vector of 64-bit integers (type `wwl_t`) to be stored in memory.
- **Control Flow**:
    - The function uses the `_mm512_store_epi64` intrinsic to store the 512-bit vector `x` into the memory location pointed to by `m`.
- **Output**: The function does not return a value; it performs a side effect by modifying the memory location pointed to by `m`.


---
### wwl\_ldu<!-- {{#callable:wwl_ldu}} -->
The `wwl_ldu` function loads a 512-bit vector of eight 64-bit integers from an unaligned memory address.
- **Inputs**:
    - `m`: A pointer to the memory location from which the 512-bit vector of eight 64-bit integers is to be loaded; the memory can be unaligned.
- **Control Flow**:
    - The function uses the `_mm512_loadu_epi64` intrinsic to load a 512-bit vector from the memory address pointed to by `m`.
- **Output**: The function returns a `wwl_t` type, which is a 512-bit vector containing eight 64-bit integers loaded from the specified memory location.


---
### wwl\_stu<!-- {{#callable:wwl_stu}} -->
The `wwl_stu` function stores a 512-bit vector of eight 64-bit integers into a memory location with arbitrary alignment.
- **Inputs**:
    - `m`: A pointer to the memory location where the vector will be stored; it can have arbitrary alignment.
    - `x`: A `wwl_t` type, which is a 512-bit vector containing eight 64-bit signed integers.
- **Control Flow**:
    - The function calls the intrinsic `_mm512_storeu_epi64` to store the vector `x` into the memory location pointed to by `m`.
- **Output**: The function does not return any value; it performs a side effect by storing data into the memory location pointed to by `m`.


---
### wwl\_rol\_variable<!-- {{#callable:wwl_rol_variable}} -->
The `wwl_rol_variable` function performs a variable left rotation on a vector of 64-bit integers using AVX-512 intrinsics.
- **Inputs**:
    - `a`: A vector of 64-bit integers (wwl_t) to be rotated.
    - `n`: A long integer specifying the number of positions to rotate the vector elements to the left.
- **Control Flow**:
    - The function calculates the left shift of vector 'a' by 'n & 63L' positions using `wwl_shl`.
    - It calculates the unsigned right shift of vector 'a' by '(-n) & 63L' positions using `wwl_shru`.
    - The results of the left and right shifts are combined using a bitwise OR operation via `wwl_or`.
    - The combined result is returned as the output of the function.
- **Output**: A vector of 64-bit integers (wwl_t) where each element has been left-rotated by 'n' positions.


---
### wwl\_ror\_variable<!-- {{#callable:wwl_ror_variable}} -->
The `wwl_ror_variable` function performs a variable right rotation on a vector of 64-bit integers using AVX-512 intrinsics.
- **Inputs**:
    - `a`: A vector of 64-bit integers (`wwl_t`) to be rotated.
    - `n`: A long integer specifying the number of positions to rotate the vector to the right.
- **Control Flow**:
    - The function calculates `n & 63L` to ensure the rotation amount is within the range of 0 to 63 bits.
    - It performs an unsigned right shift on the vector `a` by `n & 63L` positions using `wwl_shru`.
    - It performs a left shift on the vector `a` by `(-n) & 63L` positions using `wwl_shl`.
    - The results of the two shifts are combined using a bitwise OR operation with `wwl_or`.
    - The combined result is returned as the output of the function.
- **Output**: A vector of 64-bit integers (`wwl_t`) that has been right-rotated by `n` positions.


---
### wwl\_rol\_vector<!-- {{#callable:wwl_rol_vector}} -->
The `wwl_rol_vector` function performs a vectorized left rotation on each 64-bit integer in a vector `a` by the corresponding amount specified in vector `b`.
- **Inputs**:
    - `a`: A vector of 64-bit integers (`wwl_t`) to be rotated.
    - `b`: A vector of 64-bit integers (`wwl_t`) specifying the number of positions to rotate each corresponding element in `a`.
- **Control Flow**:
    - Broadcast the constant 63 to all elements of a vector `m` using `wwl_bcast(63L)` to ensure shift amounts are within valid range.
    - Perform a bitwise AND between each element of `b` and `m` to limit the shift amount to 63, then left shift each element of `a` by the corresponding result using `wwl_shl_vector`.
    - Negate each element of `b`, perform a bitwise AND with `m`, and then perform an unsigned right shift on each element of `a` by the corresponding result using `wwl_shru_vector`.
    - Combine the results of the left and right shifts using a bitwise OR operation with `wwl_or` to achieve the rotation effect.
- **Output**: A vector of 64-bit integers (`wwl_t`) where each element is the result of rotating the corresponding element in `a` to the left by the number of positions specified in `b`.


---
### wwl\_ror\_vector<!-- {{#callable:wwl_ror_vector}} -->
The `wwl_ror_vector` function performs a bitwise right rotation on each 64-bit element of a vector `a` by the corresponding element in vector `b` using AVX-512 intrinsics.
- **Inputs**:
    - `a`: A vector of type `wwl_t` containing 64-bit signed integers to be rotated.
    - `b`: A vector of type `wwl_t` containing 64-bit signed integers specifying the number of positions to rotate each corresponding element in `a`.
- **Control Flow**:
    - Broadcast the constant 63 into a vector `m` using `wwl_bcast(63L)` to ensure shifts are within 0-63 range.
    - Perform a bitwise AND between each element of `b` and `m` to get the effective right shift amount for each element.
    - Perform an unsigned right shift on `a` by the effective shift amounts using `wwl_shru_vector`.
    - Negate each element of `b`, perform a bitwise AND with `m` to get the effective left shift amount, and then perform a left shift on `a` using `wwl_shl_vector`.
    - Combine the results of the right and left shifts using a bitwise OR operation with `wwl_or` to achieve the rotation effect.
- **Output**: A vector of type `wwl_t` where each element is the result of a right rotation of the corresponding element in `a` by the number of positions specified in `b`.



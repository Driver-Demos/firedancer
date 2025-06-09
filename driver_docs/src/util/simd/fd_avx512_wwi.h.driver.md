# Purpose
This C header file provides a comprehensive set of macros and inline functions for handling 512-bit wide vector operations using Intel's AVX-512 instruction set. The file defines a type `wwi_t` as a vector of sixteen 32-bit signed integers, leveraging the `__m512i` data type. It includes a variety of operations such as vector construction, arithmetic, binary, comparison, and conditional operations, all tailored to work with these wide vectors. The file is designed to be included indirectly through another header (`fd_avx512.h`), ensuring that it is part of a larger framework or library.

The functionality provided is broad, covering essential operations needed for high-performance computing tasks that require parallel processing of integer data. The macros and functions are designed to mirror other APIs, ensuring consistency and ease of use. The file includes operations for loading and storing vectors, performing arithmetic and logical operations, and even more complex tasks like vector permutation and transposition. This makes it a powerful tool for developers working on applications that can benefit from SIMD (Single Instruction, Multiple Data) parallelism, such as scientific computing, data analysis, and real-time processing tasks. The use of macros over static inline functions where possible is a deliberate choice to optimize performance and minimize the risk of compiler interference.
# Global Variables

---
### \_wwi\_transpose\_t0
- **Type**: `wwi_t`
- **Description**: The variable `_wwi_transpose_t0` is a global variable of type `wwi_t`, which is a vector type where each 32-bit wide lane holds a signed two's complement 32-bit integer. It is initialized using the `wwi_select` macro, which selects and permutes elements from two `wwi_t` vectors based on a permutation vector `p`. This variable is part of a sequence of operations to perform a transpose on a matrix represented by vectors.
- **Use**: This variable is used in the process of transposing a matrix by selecting and permuting elements from two input vectors.


---
### \_wwi\_transpose\_t1
- **Type**: `wwi_t`
- **Description**: The variable `_wwi_transpose_t1` is a global variable of type `wwi_t`, which is defined as a vector where each 32-bit wide lane holds a signed two's complement 32-bit integer. It is initialized using the `wwi_select` macro, which selects and permutes elements from two `wwi_t` vectors based on a permutation vector.
- **Use**: This variable is used in the process of transposing matrices, specifically in the `wwi_transpose_2x8x8` macro, to hold intermediate results during the transpose operation.


---
### \_wwi\_transpose\_t2
- **Type**: `wwi_t`
- **Description**: The variable `_wwi_transpose_t2` is a global variable of type `wwi_t`, which is a vector type where each 32-bit wide lane holds a signed 32-bit integer. It is initialized using the `wwi_select` macro, which selects and permutes elements from two `wwi_t` vectors based on a permutation vector.
- **Use**: This variable is used in the process of transposing 2x8x8 matrices, specifically in the outer 2x2 transpose of 4x4 blocks.


---
### \_wwi\_transpose\_t3
- **Type**: `wwi_t`
- **Description**: The variable `_wwi_transpose_t3` is a global variable of type `wwi_t`, which is a vector type where each 32-bit wide lane holds a signed two's complement 32-bit integer. It is initialized using the `wwi_select` macro, which selects and permutes elements from two `wwi_t` vectors based on a permutation vector.
- **Use**: This variable is used in the process of transposing matrices, specifically in the `wwi_transpose_2x8x8` macro, to hold intermediate results during the transpose operation.


---
### \_wwi\_transpose\_t4
- **Type**: `wwi_t`
- **Description**: The variable `_wwi_transpose_t4` is a global variable of type `wwi_t`, which is a vector type where each 32-bit wide lane holds a signed two's complement 32-bit integer. It is initialized using the `wwi_select` macro, which selects and permutes elements from two `wwi_t` vectors based on a permutation vector.
- **Use**: This variable is used in the process of transposing matrices, specifically in the `wwi_transpose_2x8x8` macro, to hold intermediate results during the transpose operation.


---
### \_wwi\_transpose\_t5
- **Type**: `wwi_t`
- **Description**: The variable `_wwi_transpose_t5` is a global variable of type `wwi_t`, which is defined as a vector where each 32-bit wide lane holds a signed two's complement 32-bit integer. It is initialized using the `wwi_select` macro, which selects and permutes elements from two `wwi_t` vectors based on a permutation vector.
- **Use**: This variable is used in the process of transposing matrices, specifically in the `wwi_transpose_2x8x8` macro, to hold intermediate results during the transpose operation.


---
### \_wwi\_transpose\_t6
- **Type**: `wwi_t`
- **Description**: The variable `_wwi_transpose_t6` is a global variable of type `wwi_t`, which is defined as a vector where each 32-bit wide lane holds a signed two's complement 32-bit integer. It is initialized using the `wwi_select` macro, which selects and permutes elements from two `wwi_t` vectors based on a permutation vector.
- **Use**: This variable is used in the process of transposing matrices, specifically in the `wwi_transpose_2x8x8` macro, to hold intermediate results during the transpose operation.


---
### \_wwi\_transpose\_t7
- **Type**: `wwi_t`
- **Description**: The variable `_wwi_transpose_t7` is a global variable of type `wwi_t`, which is a vector type where each 32-bit wide lane holds a signed 32-bit integer. It is initialized using the `wwi_select` macro, which selects and permutes elements from two `wwi_t` vectors based on a permutation vector.
- **Use**: This variable is used in the context of transposing matrices, specifically as part of the process of transposing 2x8x8 matrices in SIMD operations.


---
### \_wwi\_transpose\_t8
- **Type**: `wwi_t`
- **Description**: The variable `_wwi_transpose_t8` is a global variable of type `wwi_t`, which is defined as a 512-bit wide vector containing sixteen 32-bit signed integers. It is initialized using the `_mm512_shuffle_i32x4` intrinsic, which shuffles 128-bit lanes of two input vectors, `_wwi_transpose_r8` and `_wwi_transpose_rc`, according to the control mask `0x88`. This operation is part of a larger process to transpose a 16x16 matrix of integers.
- **Use**: This variable is used in the process of transposing a 16x16 matrix of integers by shuffling 128-bit lanes of input vectors.


---
### \_wwi\_transpose\_t9
- **Type**: `wwi_t`
- **Description**: The variable `_wwi_transpose_t9` is a global variable of type `wwi_t`, which is defined as a vector of 16 signed 32-bit integers using the AVX-512 SIMD instruction set. It is initialized using the `_mm512_shuffle_i32x4` intrinsic, which shuffles 128-bit lanes of two input vectors, `_wwi_transpose_r9` and `_wwi_transpose_rd`, according to the control mask `0x88`. This operation is part of a larger process to transpose a 16x16 matrix of integers.
- **Use**: This variable is used in the process of transposing a 16x16 matrix of integers by shuffling 128-bit lanes of two input vectors.


---
### \_wwi\_transpose\_ta
- **Type**: `wwi_t`
- **Description**: The variable `_wwi_transpose_ta` is a global variable of type `wwi_t`, which is a vector type where each 32-bit lane holds a signed 32-bit integer. It is initialized using the `_mm512_shuffle_i32x4` intrinsic, which shuffles 128-bit lanes of two input vectors, `_wwi_transpose_ra` and `_wwi_transpose_re`, according to the control mask `0x88`. This operation is part of a larger process to transpose a 16x16 matrix of integers.
- **Use**: This variable is used in the process of transposing a 16x16 matrix by shuffling and rearranging vector lanes.


---
### \_wwi\_transpose\_tb
- **Type**: `wwi_t`
- **Description**: The variable `_wwi_transpose_tb` is a global variable of type `wwi_t`, which is a vector type where each 32-bit lane holds a signed 32-bit integer. It is initialized using the `_mm512_shuffle_i32x4` intrinsic, which shuffles 128-bit lanes of two input vectors, `_wwi_transpose_rb` and `_wwi_transpose_rf`, according to the control mask `0x88`. This operation is part of a larger process to transpose a 16x16 matrix of integers using AVX-512 instructions.
- **Use**: This variable is used in the process of transposing a 16x16 matrix of integers, specifically as part of the outer 4x4 transpose of 4x4 blocks.


---
### \_wwi\_transpose\_tc
- **Type**: `wwi_t`
- **Description**: The variable `_wwi_transpose_tc` is a global variable of type `wwi_t`, which is a vector type where each 32-bit lane holds a signed 32-bit integer. It is initialized using the `_mm512_shuffle_i32x4` intrinsic, which shuffles 128-bit lanes of two input vectors, `_wwi_transpose_r8` and `_wwi_transpose_rc`, according to the control mask `0xdd`. This operation is part of a larger process to transpose a 16x16 matrix of integers.
- **Use**: This variable is used in the process of transposing a 16x16 matrix by shuffling and rearranging vector lanes.


---
### \_wwi\_transpose\_td
- **Type**: `wwi_t`
- **Description**: The variable `_wwi_transpose_td` is a global variable of type `wwi_t`, which is a vector type where each 32-bit lane holds a signed 32-bit integer. It is initialized using the `_mm512_shuffle_i32x4` intrinsic, which shuffles 128-bit lanes of two input vectors, `_wwi_transpose_r9` and `_wwi_transpose_rd`, according to the control mask `0xdd`. This operation is part of a larger matrix transpose operation.
- **Use**: This variable is used in the process of transposing a 16x16 matrix of integers, specifically as part of the outer 4x4 transpose of 4x4 blocks.


---
### \_wwi\_transpose\_te
- **Type**: `wwi_t`
- **Description**: The variable `_wwi_transpose_te` is a global variable of type `wwi_t`, which is a vector type where each 32-bit wide lane holds a signed two's complement 32-bit integer. It is initialized using the `_mm512_shuffle_i32x4` intrinsic, which shuffles 128-bit lanes of two input vectors, `_wwi_transpose_ra` and `_wwi_transpose_re`, according to the control mask `0xdd`. This operation is part of a larger matrix transposition process.
- **Use**: This variable is used in the process of transposing a 16x16 matrix of integers, specifically in the outer 4x4 transpose of 4x4 blocks.


---
### \_wwi\_transpose\_tf
- **Type**: `wwi_t`
- **Description**: The variable `_wwi_transpose_tf` is a global variable of type `wwi_t`, which is a vector type where each 32-bit lane holds a signed 32-bit integer. It is initialized using the `_mm512_shuffle_i32x4` intrinsic, which shuffles 128-bit lanes of two input vectors, `_wwi_transpose_rb` and `_wwi_transpose_rf`, according to the control mask `0xdd`. This operation is part of a larger matrix transpose operation for 16x16 matrices.
- **Use**: This variable is used in the process of transposing a 16x16 matrix by shuffling 128-bit lanes of two vectors.


---
### \_wwi\_transpose\_p
- **Type**: `wwi_t`
- **Description**: The variable `_wwi_transpose_p` is a global variable of type `wwi_t`, which is a vector type where each 32-bit wide lane holds a signed 32-bit integer. It is initialized using the `wwi` macro with specific integer values that define the permutation order for vector operations.
- **Use**: This variable is used as a permutation vector in SIMD operations to rearrange or select elements from other vectors.


---
### \_wwi\_transpose\_q
- **Type**: `wwi_t`
- **Description**: The variable `_wwi_transpose_q` is a global variable of type `wwi_t`, which is a vector type where each 32-bit lane holds a signed 32-bit integer. It is initialized using the `wwi` macro with specific integer values, creating a vector with the elements [4, 5, 6, 7, 20, 21, 22, 23, 12, 13, 14, 15, 28, 29, 30, 31].
- **Use**: This variable is used in the `wwi_transpose_2x8x8` macro to select and permute elements from two vectors during matrix transposition operations.


# Functions

---
### wwi\_ld<!-- {{#callable:wwi_ld}} -->
The `wwi_ld` function loads a 512-bit vector of 16 32-bit integers from a 64-byte aligned memory location into a `wwi_t` type using AVX-512 intrinsics.
- **Inputs**:
    - `m`: A pointer to a constant integer array that is 64-byte aligned, from which the 512-bit vector will be loaded.
- **Control Flow**:
    - The function uses the `_mm512_load_epi32` intrinsic to load 16 consecutive 32-bit integers from the memory location pointed to by `m` into a `wwi_t` vector.
- **Output**: A `wwi_t` type, which is a 512-bit vector containing 16 32-bit integers loaded from the specified memory location.


---
### wwi\_st<!-- {{#callable:wwi_st}} -->
The `wwi_st` function stores a 512-bit vector of 16 32-bit integers into a memory location.
- **Inputs**:
    - `m`: A pointer to an integer array where the vector elements will be stored; it should be 64-byte aligned.
    - `x`: A 512-bit vector of type `wwi_t` containing 16 32-bit integers to be stored.
- **Control Flow**:
    - The function uses the `_mm512_store_epi32` intrinsic to store the 16 32-bit integers from the vector `x` into the memory location pointed to by `m`.
- **Output**: The function does not return a value; it performs a side effect by modifying the memory pointed to by `m`.


---
### wwi\_ldu<!-- {{#callable:wwi_ldu}} -->
The `wwi_ldu` function loads a 512-bit vector of 16 32-bit integers from an unaligned memory address into a `wwi_t` type using AVX-512 instructions.
- **Inputs**:
    - `m`: A pointer to a memory location from which the 512-bit vector of 16 32-bit integers will be loaded. The memory address does not need to be aligned.
- **Control Flow**:
    - The function uses the `_mm512_loadu_epi32` intrinsic to load a 512-bit vector from the memory location pointed to by `m`.
- **Output**: A `wwi_t` type, which is a 512-bit vector containing 16 32-bit integers loaded from the specified memory location.


---
### wwi\_stu<!-- {{#callable:wwi_stu}} -->
The `wwi_stu` function stores a 512-bit vector of 16 32-bit integers into a memory location with arbitrary alignment.
- **Inputs**:
    - `m`: A pointer to the memory location where the vector will be stored; it can have arbitrary alignment.
    - `x`: A 512-bit vector of type `wwi_t` containing 16 32-bit integers to be stored.
- **Control Flow**:
    - The function uses the intrinsic `_mm512_storeu_epi32` to store the vector `x` into the memory location pointed to by `m`.
- **Output**: The function does not return any value; it performs a side effect by storing data into the memory location pointed to by `m`.


---
### wwi\_rol\_variable<!-- {{#callable:wwi_rol_variable}} -->
The `wwi_rol_variable` function performs a variable bitwise left rotation on each 32-bit lane of a 512-bit vector of integers.
- **Inputs**:
    - `a`: A 512-bit vector of signed 32-bit integers (type `wwi_t`).
    - `n`: An integer specifying the number of positions to rotate each 32-bit lane to the left.
- **Control Flow**:
    - The function calculates `n & 31` to ensure the shift amount is within the range of 0 to 31, as each lane is 32 bits wide.
    - It performs a left shift on the vector `a` by `n & 31` positions using `wwi_shl`.
    - It performs an unsigned right shift on the vector `a` by `(-n) & 31` positions using `wwi_shru`.
    - The results of the left and right shifts are combined using a bitwise OR operation with `wwi_or`.
- **Output**: A 512-bit vector of signed 32-bit integers, where each lane has been rotated left by `n` positions.


---
### wwi\_ror\_variable<!-- {{#callable:wwi_ror_variable}} -->
The `wwi_ror_variable` function performs a variable right rotation on a vector of 32-bit integers.
- **Inputs**:
    - `a`: A vector of 32-bit integers (type `wwi_t`) to be rotated.
    - `n`: An integer specifying the number of positions to rotate the vector to the right.
- **Control Flow**:
    - The function calculates `n & 31` to ensure the rotation amount is within the range of 0 to 31.
    - It performs an unsigned right shift on the vector `a` by `n & 31` positions using `wwi_shru`.
    - It performs a left shift on the vector `a` by `(-n) & 31` positions using `wwi_shl`.
    - The results of the two shifts are combined using a bitwise OR operation with `wwi_or`.
    - The combined result is returned as the output of the function.
- **Output**: A vector of 32-bit integers (type `wwi_t`) that is the result of rotating the input vector `a` to the right by `n` positions.


---
### wwi\_rol\_vector<!-- {{#callable:wwi_rol_vector}} -->
The `wwi_rol_vector` function performs a bitwise left rotation on each 32-bit lane of a vector `a` by the corresponding amount specified in vector `b`, using AVX-512 intrinsics.
- **Inputs**:
    - `a`: A vector of type `wwi_t` where each lane contains a 32-bit signed integer to be rotated.
    - `b`: A vector of type `wwi_t` where each lane contains a 32-bit signed integer specifying the number of positions to rotate the corresponding lane in `a`.
- **Control Flow**:
    - Broadcast the integer 31 to all lanes of a vector `m` using `wwi_bcast(31)` to create a mask for the rotation amount.
    - Perform a bitwise AND between each lane of `b` and `m` to ensure the rotation amount is within the range [0, 31].
    - Shift each lane of `a` left by the corresponding masked value from `b` using `wwi_shl_vector`.
    - Negate each lane of `b`, mask it with `m`, and shift each lane of `a` right by this value using `wwi_shru_vector`.
    - Combine the results of the left and right shifts using a bitwise OR operation with `wwi_or` to complete the rotation.
- **Output**: A vector of type `wwi_t` where each lane contains the result of rotating the corresponding lane in `a` left by the amount specified in `b`.


---
### wwi\_ror\_vector<!-- {{#callable:wwi_ror_vector}} -->
The `wwi_ror_vector` function performs a bitwise right rotation on each 32-bit lane of a vector `a` by the corresponding amount specified in vector `b`, using AVX-512 intrinsics.
- **Inputs**:
    - `a`: A vector of type `wwi_t` where each lane holds a signed 32-bit integer, representing the data to be rotated.
    - `b`: A vector of type `wwi_t` where each lane holds a signed 32-bit integer, representing the number of positions to rotate the corresponding lane in `a` to the right.
- **Control Flow**:
    - A constant vector `m` is created with all lanes set to 31 using `wwi_bcast(31)`, which is used to mask the shift amounts.
    - The function calculates the right shift amount for each lane by performing a bitwise AND between `b` and `m`, and then performs an unsigned right shift on `a` using `wwi_shru_vector`.
    - The function calculates the left shift amount for each lane by negating `b`, performing a bitwise AND with `m`, and then performs a left shift on `a` using `wwi_shl_vector`.
    - The results of the right and left shifts are combined using a bitwise OR operation with `wwi_or`, effectively completing the right rotation for each lane.
- **Output**: The function returns a vector of type `wwi_t` where each lane contains the result of the right rotation operation on the corresponding lane of `a`.



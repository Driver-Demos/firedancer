# Purpose
This C source code file provides a specialized set of macros and inline functions for handling SIMD (Single Instruction, Multiple Data) operations using the AVX-512 instruction set, specifically targeting 512-bit wide vectors of unsigned 32-bit integers. The file defines a type `wwu_t` as a vector of 16 unsigned 32-bit integers and offers a comprehensive API for constructing, manipulating, and performing arithmetic, logical, and memory operations on these vectors. The code is structured to leverage the AVX-512 intrinsics for high-performance computing tasks, making it suitable for applications that require efficient parallel processing of large datasets, such as scientific computing, graphics processing, or machine learning.

The file is intended to be included indirectly through a higher-level header (`fd_avx512.h`), as indicated by the preprocessor directive at the beginning. It provides a broad range of functionality, including vector construction, broadcasting, permutation, selection, arithmetic operations (addition, subtraction, multiplication), bitwise operations (AND, OR, XOR, NOT), and various comparison and conditional operations. Additionally, it includes utilities for vector unpacking, transposition, and conversion between different vector types. The use of macros over static inline functions is emphasized to ensure robust performance and minimize the risk of compiler optimizations interfering with the intended behavior. This file does not define a public API or external interfaces directly but serves as a foundational component for other modules that require SIMD capabilities.
# Global Variables

---
### \_wwu\_transpose\_t0
- **Type**: `wwu_t`
- **Description**: The variable `_wwu_transpose_t0` is a global variable of type `wwu_t`, which is defined as a vector type `__m512i`. It is initialized using the `wwu_select` macro, which selects and permutes elements from two `wwu_t` vectors based on a permutation vector `p`. This variable is part of a larger operation to transpose matrices using AVX-512 SIMD instructions.
- **Use**: This variable is used in the process of transposing 16x16 or 8x8 matrices by selecting and permuting elements from input vectors.


---
### \_wwu\_transpose\_t1
- **Type**: `wwu_t`
- **Description**: The variable `_wwu_transpose_t1` is a global variable of type `wwu_t`, which is defined as a vector type `__m512i` representing a 512-bit wide vector with 16 lanes, each holding a 32-bit unsigned integer. It is initialized using the `wwu_select` macro, which selects and permutes elements from two input vectors based on a permutation vector.
- **Use**: This variable is used in the process of transposing matrices, specifically in the `wwu_transpose_16x16` macro, to hold intermediate results during the transpose operation.


---
### \_wwu\_transpose\_t2
- **Type**: `wwu_t`
- **Description**: The variable `_wwu_transpose_t2` is a global variable of type `wwu_t`, which is defined as a vector type `__m512i` that holds 16 unsigned 32-bit integers. It is initialized using the `wwu_select` macro, which selects and permutes elements from two `wwu_t` vectors based on a permutation vector.
- **Use**: This variable is used in the process of transposing 2x8x8 matrices, specifically in the outer 2x2 transpose of 4x4 blocks.


---
### \_wwu\_transpose\_t3
- **Type**: `wwu_t`
- **Description**: The variable `_wwu_transpose_t3` is a global variable of type `wwu_t`, which is defined as a vector where each 32-bit wide lane holds an unsigned 32-bit integer. It is initialized using the `wwu_select` macro, which selects and permutes elements from two `wwu_t` vectors based on a permutation vector.
- **Use**: This variable is used in the process of transposing matrices, specifically in the `wwu_transpose_2x8x8` macro, to hold intermediate results during the transpose operation.


---
### \_wwu\_transpose\_t4
- **Type**: `wwu_t`
- **Description**: The variable `_wwu_transpose_t4` is a vector of type `wwu_t`, which is defined as `__m512i`, representing a 512-bit wide vector where each 32-bit lane holds an unsigned 32-bit integer. It is initialized using the `wwu_select` macro, which selects and permutes elements from two input vectors based on a permutation vector.
- **Use**: This variable is used in the process of transposing 8x8 matrices, specifically as an intermediate step in the `wwu_transpose_2x8x8` macro.


---
### \_wwu\_transpose\_t5
- **Type**: `wwu_t`
- **Description**: The variable `_wwu_transpose_t5` is a global variable of type `wwu_t`, which is defined as a vector type `__m512i` that holds 16 unsigned 32-bit integers. It is initialized using the `wwu_select` macro, which selects and permutes elements from two `wwu_t` vectors based on a permutation vector.
- **Use**: This variable is used in the process of transposing 2x8x8 matrices, specifically in the outer 2x2 transpose of 4x4 blocks.


---
### \_wwu\_transpose\_t6
- **Type**: `wwu_t`
- **Description**: The variable `_wwu_transpose_t6` is a global variable of type `wwu_t`, which is defined as a vector where each 32-bit wide lane holds an unsigned 32-bit integer. It is initialized using the `wwu_select` macro, which selects and permutes elements from two `wwu_t` vectors based on a permutation vector.
- **Use**: This variable is used in the process of transposing 2x8x8 matrices, specifically in the outer 2x2 transpose of 4x4 blocks.


---
### \_wwu\_transpose\_t7
- **Type**: `wwu_t`
- **Description**: The variable `_wwu_transpose_t7` is a global variable of type `wwu_t`, which is a vector type where each 32-bit wide lane holds an unsigned 32-bit integer. It is initialized using the `wwu_select` macro, which selects and permutes elements from two `wwu_t` vectors based on a permutation vector.
- **Use**: This variable is used in the process of transposing 2x8x8 matrices, specifically in the `wwu_transpose_2x8x8` macro, to hold intermediate results during the transpose operation.


---
### \_wwu\_transpose\_t8
- **Type**: `wwu_t`
- **Description**: The variable `_wwu_transpose_t8` is a vector of unsigned 32-bit integers, defined using the `__m512i` type, which is part of the AVX-512 SIMD instruction set. It is initialized by shuffling 32-bit integer elements from two other vectors, `_wwu_transpose_r8` and `_wwu_transpose_rc`, using the `_mm512_shuffle_i32x4` intrinsic with a control mask of `0x88`.
- **Use**: This variable is used in the process of transposing a 16x16 matrix of unsigned integers, specifically in the outer 4x4 transpose of 4x4 blocks.


---
### \_wwu\_transpose\_t9
- **Type**: `wwu_t`
- **Description**: The variable `_wwu_transpose_t9` is a global variable of type `wwu_t`, which is defined as a vector where each 32-bit wide lane holds an unsigned 32-bit integer. It is initialized using the `_mm512_shuffle_i32x4` intrinsic, which shuffles 128-bit lanes of two input vectors, `_wwu_transpose_r9` and `_wwu_transpose_rd`, according to the control mask `0x88`. This operation is part of a larger process to transpose a 16x16 matrix of unsigned integers.
- **Use**: This variable is used in the process of transposing a 16x16 matrix of unsigned integers, specifically as part of the outer 4x4 transpose of 4x4 blocks.


---
### \_wwu\_transpose\_ta
- **Type**: `wwu_t`
- **Description**: The variable `_wwu_transpose_ta` is a global variable of type `wwu_t`, which is defined as a vector of 16 unsigned 32-bit integers using the AVX-512 SIMD instruction set. It is initialized using the `_mm512_shuffle_i32x4` intrinsic, which shuffles 128-bit lanes of two input vectors, `_wwu_transpose_ra` and `_wwu_transpose_re`, according to the control mask `0x88`. This operation is part of a larger transpose operation for a 16x16 matrix of unsigned integers.
- **Use**: This variable is used in the process of transposing a 16x16 matrix of unsigned integers, specifically as an intermediate step in shuffling 128-bit lanes of the matrix rows.


---
### \_wwu\_transpose\_tb
- **Type**: `wwu_t`
- **Description**: The variable `_wwu_transpose_tb` is a global variable of type `wwu_t`, which is defined as a vector of 16 unsigned 32-bit integers using the AVX-512 SIMD instruction set. It is initialized using the `_mm512_shuffle_i32x4` intrinsic, which shuffles 128-bit lanes of two input vectors, `_wwu_transpose_rb` and `_wwu_transpose_rf`, according to the control mask `0x88`. This operation is part of a larger process to transpose a 16x16 matrix of unsigned integers.
- **Use**: This variable is used in the process of transposing a 16x16 matrix of unsigned integers, specifically as part of the outer 4x4 transpose of 4x4 blocks.


---
### \_wwu\_transpose\_tc
- **Type**: `wwu_t`
- **Description**: The variable `_wwu_transpose_tc` is a global variable of type `wwu_t`, which is defined as a vector where each 32-bit wide lane holds an unsigned 32-bit integer. It is initialized using the `_mm512_shuffle_i32x4` intrinsic, which shuffles 128-bit lanes of two input vectors, `_wwu_transpose_r8` and `_wwu_transpose_rc`, according to the control mask `0xdd`. This operation is part of a larger matrix transposition process.
- **Use**: This variable is used in the process of transposing a 16x16 matrix of unsigned 32-bit integers, specifically handling the shuffling of certain rows to form part of the transposed matrix.


---
### \_wwu\_transpose\_td
- **Type**: `wwu_t`
- **Description**: The variable `_wwu_transpose_td` is a global variable of type `wwu_t`, which is defined as a vector where each 32-bit wide lane holds an unsigned 32-bit integer. It is initialized using the `_mm512_shuffle_i32x4` intrinsic, which shuffles 128-bit lanes of two input vectors, `_wwu_transpose_r9` and `_wwu_transpose_rd`, according to the control mask `0xdd`. This operation is part of a larger transpose operation for 16x16 matrices.
- **Use**: This variable is used in the process of transposing a 16x16 matrix by shuffling 128-bit lanes of input vectors.


---
### \_wwu\_transpose\_te
- **Type**: `wwu_t`
- **Description**: The variable `_wwu_transpose_te` is a global variable of type `wwu_t`, which is defined as a vector of 16 unsigned 32-bit integers using the AVX-512 intrinsic type `__m512i`. It is initialized using the `_mm512_shuffle_i32x4` intrinsic function, which shuffles 128-bit lanes of two input vectors, `_wwu_transpose_ra` and `_wwu_transpose_re`, according to the control mask `0xdd`. This operation is part of a larger set of operations for transposing a 16x16 matrix of unsigned integers.
- **Use**: This variable is used in the process of transposing a 16x16 matrix of unsigned integers, specifically as part of the outer 4x4 transpose of 4x4 blocks.


---
### \_wwu\_transpose\_tf
- **Type**: `wwu_t`
- **Description**: The variable `_wwu_transpose_tf` is a global variable of type `wwu_t`, which is defined as a vector type `__m512i`. It is initialized using the `_mm512_shuffle_i32x4` intrinsic function, which shuffles 128-bit lanes of the input vectors `_wwu_transpose_rb` and `_wwu_transpose_rf` according to the control mask `0xdd`. This operation is part of a larger set of operations for transposing matrices using AVX-512 intrinsics.
- **Use**: This variable is used in the process of transposing 16x16 matrices by shuffling 128-bit lanes of input vectors.


---
### \_wwu\_transpose\_p
- **Type**: `wwu_t`
- **Description**: The variable `_wwu_transpose_p` is a global variable of type `wwu_t`, which is defined as a vector where each 32-bit wide lane holds an unsigned 32-bit integer. It is initialized using the `wwu` macro with specific indices that likely represent a permutation pattern for vector operations.
- **Use**: This variable is used as a permutation pattern in vector operations, specifically in the `wwu_transpose_2x8x8` macro to facilitate the transposition of 8x8 matrices.


---
### \_wwu\_transpose\_q
- **Type**: `wwu_t`
- **Description**: The variable `_wwu_transpose_q` is a global variable of type `wwu_t`, which is a vector type where each 32-bit wide lane holds an unsigned 32-bit integer. It is initialized using the `wwu` macro with specific unsigned integer values, creating a vector with these values in its lanes.
- **Use**: This variable is used in matrix transposition operations, specifically in the `wwu_transpose_2x8x8` macro, to select and permute elements from two 8x8 matrices.


# Functions

---
### wwu\_ld<!-- {{#callable:wwu_ld}} -->
The `wwu_ld` function loads a 512-bit vector of 16 unsigned 32-bit integers from a 64-byte aligned memory location.
- **Inputs**:
    - `m`: A pointer to a 64-byte aligned memory location containing 16 unsigned 32-bit integers.
- **Control Flow**:
    - The function uses the `_mm512_load_epi32` intrinsic to load 16 unsigned 32-bit integers from the memory location pointed to by `m` into a 512-bit vector.
- **Output**: A 512-bit vector (`wwu_t`) containing the 16 unsigned 32-bit integers loaded from the memory location.


---
### wwu\_st<!-- {{#callable:wwu_st}} -->
The `wwu_st` function stores a 512-bit vector of 16 unsigned 32-bit integers into a memory location.
- **Inputs**:
    - `m`: A pointer to a memory location where the 512-bit vector will be stored; it should be 64-byte aligned.
    - `x`: A 512-bit vector of type `wwu_t` containing 16 unsigned 32-bit integers to be stored.
- **Control Flow**:
    - The function uses the `_mm512_store_epi32` intrinsic to store the 512-bit vector `x` into the memory location pointed to by `m`.
- **Output**: The function does not return a value; it performs a side effect by storing data in memory.


---
### wwu\_ldu<!-- {{#callable:wwu_ldu}} -->
The `wwu_ldu` function loads a 512-bit vector of 16 unsigned 32-bit integers from an unaligned memory address.
- **Inputs**:
    - `m`: A pointer to a memory location from which the 512-bit vector of unsigned 32-bit integers will be loaded.
- **Control Flow**:
    - The function uses the `_mm512_loadu_epi32` intrinsic to load a 512-bit vector from the memory address pointed to by `m`.
- **Output**: A `wwu_t` type, which is a 512-bit vector containing 16 unsigned 32-bit integers loaded from the specified memory location.


---
### wwu\_stu<!-- {{#callable:wwu_stu}} -->
The `wwu_stu` function stores a 512-bit vector of unsigned 32-bit integers into a memory location with arbitrary alignment.
- **Inputs**:
    - `m`: A pointer to the memory location where the vector will be stored; it can have arbitrary alignment.
    - `x`: A 512-bit vector of unsigned 32-bit integers (type `wwu_t`) to be stored at the memory location pointed to by `m`.
- **Control Flow**:
    - The function uses the `_mm512_storeu_epi32` intrinsic to store the vector `x` into the memory location `m`.
- **Output**: This function does not return any value; it performs a side effect by storing data into the memory location pointed to by `m`.


---
### wwu\_rol\_variable<!-- {{#callable:wwu_rol_variable}} -->
The `wwu_rol_variable` function performs a variable bitwise left rotation on each 32-bit lane of a vector of unsigned 32-bit integers.
- **Inputs**:
    - `a`: A vector of unsigned 32-bit integers (`wwu_t`) to be rotated.
    - `n`: An unsigned integer specifying the number of positions to rotate each lane in the vector.
- **Control Flow**:
    - The function calculates `n & 31U` to ensure the rotation amount is within the range of 0 to 31 bits.
    - It performs a left shift on the vector `a` by `n & 31U` bits using `wwu_shl`.
    - It performs a right shift on the vector `a` by `(-n) & 31U` bits using `wwu_shr`.
    - The results of the left and right shifts are combined using a bitwise OR operation with `wwu_or`.
- **Output**: The function returns a vector of unsigned 32-bit integers (`wwu_t`) where each lane has been rotated left by the specified number of bits.


---
### wwu\_ror\_variable<!-- {{#callable:wwu_ror_variable}} -->
The `wwu_ror_variable` function performs a variable bitwise right rotation on each 32-bit lane of a vector of unsigned integers.
- **Inputs**:
    - `a`: A vector of unsigned 32-bit integers (`wwu_t`) to be rotated.
    - `n`: An unsigned integer (`uint`) specifying the number of positions to rotate each lane to the right.
- **Control Flow**:
    - The function calculates the effective rotation amount by taking `n & 31U`, ensuring it is within the range of 0 to 31 bits.
    - It performs a right shift on the vector `a` by the effective rotation amount using `wwu_shr`.
    - It performs a left shift on the vector `a` by the complement of the effective rotation amount using `wwu_shl`.
    - The results of the right and left shifts are combined using a bitwise OR operation with `wwu_or`.
- **Output**: A vector of unsigned 32-bit integers (`wwu_t`) where each lane has been right-rotated by `n` positions.


---
### wwu\_rol\_vector<!-- {{#callable:wwu_rol_vector}} -->
The `wwu_rol_vector` function performs a bitwise left rotation on each 32-bit lane of a vector `a` by the corresponding amount specified in vector `b`, using AVX-512 intrinsics.
- **Inputs**:
    - `a`: A vector of type `wwu_t` where each lane contains a 32-bit unsigned integer to be rotated.
    - `b`: A vector of type `wwu_t` where each lane contains a 32-bit unsigned integer specifying the number of positions to rotate the corresponding lane in `a`.
- **Control Flow**:
    - Create a vector `m` with all lanes set to 31 using `wwu_bcast(31U)` to mask the rotation amount.
    - Compute the bitwise AND of vector `b` and `m` to ensure the rotation amount is within 0 to 31.
    - Perform a left shift on vector `a` by the masked rotation amount using `wwu_shl_vector`.
    - Compute the bitwise AND of the negated vector `b` and `m` to determine the right shift amount.
    - Perform a right shift on vector `a` by the computed right shift amount using `wwu_shr_vector`.
    - Combine the results of the left and right shifts using a bitwise OR operation with `wwu_or`.
- **Output**: A vector of type `wwu_t` where each lane contains the result of rotating the corresponding lane in `a` to the left by the amount specified in `b`.


---
### wwu\_ror\_vector<!-- {{#callable:wwu_ror_vector}} -->
The `wwu_ror_vector` function performs a bitwise right rotation on each 32-bit lane of a vector `a` by the corresponding amount specified in vector `b`.
- **Inputs**:
    - `a`: A vector of type `wwu_t` where each lane contains a 32-bit unsigned integer to be rotated.
    - `b`: A vector of type `wwu_t` where each lane specifies the number of positions to rotate the corresponding lane in `a` to the right.
- **Control Flow**:
    - Broadcast the constant value 31 into a vector `m` using `wwu_bcast` to mask the shift amounts.
    - Compute the bitwise AND of vector `b` and `m` to ensure the shift amounts are within the range [0, 31].
    - Perform a logical right shift on vector `a` by the masked shift amounts using `wwu_shr_vector`.
    - Negate vector `b` and compute the bitwise AND with `m` to get the complementary shift amounts.
    - Perform a logical left shift on vector `a` by the complementary shift amounts using `wwu_shl_vector`.
    - Combine the results of the right and left shifts using a bitwise OR operation with `wwu_or` to complete the rotation.
- **Output**: A vector of type `wwu_t` where each lane contains the result of the right rotation of the corresponding lane in `a` by the amount specified in `b`.



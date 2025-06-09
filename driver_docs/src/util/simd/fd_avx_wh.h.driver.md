# Purpose
This C header file provides a specialized API for handling SIMD (Single Instruction, Multiple Data) operations using AVX (Advanced Vector Extensions) on vectors of unsigned 16-bit integers, commonly referred to as "ushorts." The file defines a type `wh_t` as a vector of 16 ushorts, leveraging the `__m256i` type from the AVX instruction set. The API includes a variety of operations such as constructors, memory operations, element extraction and insertion, arithmetic operations, binary operations, and logical operations. These operations are implemented using AVX intrinsics, which allow for efficient parallel processing of data by performing the same operation on multiple data points simultaneously.

The file is intended to be included indirectly through another header, `fd_avx.h`, as indicated by the preprocessor directive at the beginning. This suggests that the file is part of a larger library or framework that provides SIMD utilities. The API is designed to be robust and efficient, using macros where possible to minimize the risk of compiler optimizations interfering with the intended behavior. The operations provided by this file are essential for applications that require high-performance computing, such as graphics processing, scientific simulations, or any domain where large datasets need to be processed in parallel. The use of AVX intrinsics ensures that the operations are executed with optimal performance on supported hardware.
# Functions

---
### wh\_ld<!-- {{#callable:wh_ld}} -->
The `wh_ld` function loads a 256-bit vector of 16 unsigned 16-bit integers from a 32-byte aligned memory location.
- **Inputs**:
    - `p`: A pointer to a 32-byte aligned memory location containing 16 unsigned 16-bit integers (ushort).
- **Control Flow**:
    - The function casts the input pointer `p` to a pointer of type `__m256i const *`.
    - It then uses the `_mm256_load_si256` intrinsic to load a 256-bit vector from the memory location pointed to by the casted pointer.
- **Output**: A 256-bit vector (`wh_t` type, which is an alias for `__m256i`) containing the 16 unsigned 16-bit integers loaded from the memory location.


---
### wh\_st<!-- {{#callable:wh_st}} -->
The `wh_st` function stores a vector of 16 unsigned 16-bit integers into a 32-byte aligned memory location.
- **Inputs**:
    - `p`: A pointer to a 32-byte aligned memory location where the vector will be stored.
    - `i`: A vector of type `wh_t` (which is an alias for `__m256i`) containing 16 unsigned 16-bit integers to be stored.
- **Control Flow**:
    - The function uses the `_mm256_store_si256` intrinsic to store the vector `i` into the memory location pointed to by `p`.
- **Output**: The function does not return any value; it performs a side effect by writing data to the memory location pointed to by `p`.


---
### wh\_ldu<!-- {{#callable:wh_ldu}} -->
The `wh_ldu` function loads a 256-bit vector of unsigned 16-bit integers from an unaligned memory location.
- **Inputs**:
    - `p`: A pointer to a memory location from which the 256-bit vector of unsigned 16-bit integers is to be loaded. The memory location does not need to be aligned.
- **Control Flow**:
    - The function takes a pointer `p` as input, which points to the memory location.
    - It casts the pointer `p` to a pointer of type `__m256i const *`, which is suitable for AVX operations.
    - The function then uses the `_mm256_loadu_si256` intrinsic to load a 256-bit vector from the unaligned memory location pointed to by `p`.
- **Output**: The function returns a `wh_t` type, which is a 256-bit vector containing 16 unsigned 16-bit integers loaded from the specified memory location.


---
### wh\_stu<!-- {{#callable:wh_stu}} -->
The `wh_stu` function stores a 256-bit vector of unsigned 16-bit integers into a memory location that does not need to be aligned.
- **Inputs**:
    - `p`: A pointer to the memory location where the vector should be stored; alignment is not required.
    - `i`: A 256-bit vector of unsigned 16-bit integers (type `wh_t`) to be stored at the memory location pointed to by `p`.
- **Control Flow**:
    - The function uses the `_mm256_storeu_si256` intrinsic to store the vector `i` into the memory location pointed to by `p`.
- **Output**: The function does not return any value; it performs a side effect by storing data in memory.


---
### wh\_extract\_variable<!-- {{#callable:wh_extract_variable}} -->
The `wh_extract_variable` function extracts a 16-bit unsigned integer from a specified lane of a 256-bit vector.
- **Inputs**:
    - `a`: A 256-bit vector (`wh_t`) containing 16 lanes, each holding a 16-bit unsigned integer.
    - `n`: An integer specifying the lane index (0 to 15) from which to extract the 16-bit unsigned integer.
- **Control Flow**:
    - A union is defined with a 256-bit vector and an array of 16 unsigned shorts to facilitate type punning.
    - The 256-bit vector `a` is stored into the union's vector member using `_mm256_store_si256`.
    - The function returns the `n`-th element from the union's array of unsigned shorts.
- **Output**: A 16-bit unsigned integer extracted from the specified lane `n` of the input vector `a`.


---
### wh\_insert\_variable<!-- {{#callable:wh_insert_variable}} -->
The `wh_insert_variable` function replaces a specific 16-bit lane in a 256-bit vector with a new value and returns the modified vector.
- **Inputs**:
    - `a`: A 256-bit vector (`wh_t`) containing 16 unsigned 16-bit integers.
    - `n`: An integer representing the index of the lane to be replaced, which should be between 0 and 15.
    - `v`: A 16-bit unsigned integer (`ushort`) to insert into the specified lane of the vector.
- **Control Flow**:
    - A union is declared to allow type punning between a 256-bit vector and an array of 16 unsigned 16-bit integers.
    - The input vector `a` is stored into the union's 256-bit vector member using `_mm256_store_si256`.
    - The specified lane `n` in the union's array of 16 unsigned 16-bit integers is replaced with the new value `v`.
    - The modified 256-bit vector is loaded from the union and returned using `_mm256_load_si256`.
- **Output**: A 256-bit vector (`wh_t`) with the specified lane replaced by the new value.


---
### wh\_rol<!-- {{#callable:wh_rol}} -->
The `wh_rol` function performs a bitwise left rotation on each 16-bit lane of a 256-bit vector of unsigned 16-bit integers by a specified number of bits.
- **Inputs**:
    - `a`: A 256-bit vector (`wh_t`) where each lane is a 16-bit unsigned integer.
    - `imm`: An integer specifying the number of bits to rotate left, which is masked to the range [0, 15].
- **Control Flow**:
    - The function first calculates the left shift of vector `a` by `imm & 15` bits using `wh_shl`.
    - It then calculates the right shift of vector `a` by `(-imm) & 15` bits using `wh_shr`.
    - The results of the left and right shifts are combined using a bitwise OR operation via `wh_or`.
    - The combined result is returned as the output of the function.
- **Output**: A 256-bit vector (`wh_t`) where each 16-bit lane has been rotated left by the specified number of bits.


---
### wh\_ror<!-- {{#callable:wh_ror}} -->
The `wh_ror` function performs a bitwise right rotation on each 16-bit lane of a vector of unsigned 16-bit integers by a specified number of bits.
- **Inputs**:
    - `a`: A vector of type `wh_t` (which is an alias for `__m256i`), representing a vector of 16 unsigned 16-bit integers.
    - `imm`: An integer specifying the number of bits to rotate each 16-bit lane to the right.
- **Control Flow**:
    - The function calculates `imm & 15` to ensure the shift amount is within the range of 0 to 15 bits.
    - It performs a right logical shift on the vector `a` by `imm & 15` bits using `wh_shr`.
    - It performs a left logical shift on the vector `a` by `(-imm) & 15` bits using `wh_shl`.
    - The results of the two shifts are combined using a bitwise OR operation with `wh_or`.
    - The combined result is returned as the output of the function.
- **Output**: A vector of type `wh_t` where each 16-bit lane has been right-rotated by the specified number of bits.


---
### wh\_rol\_variable<!-- {{#callable:wh_rol_variable}} -->
The `wh_rol_variable` function performs a variable bitwise left rotation on each 16-bit lane of a 256-bit vector of unsigned 16-bit integers.
- **Inputs**:
    - `a`: A 256-bit vector (`wh_t`) where each lane contains a 16-bit unsigned integer.
    - `n`: An integer specifying the number of bits to rotate each lane to the left.
- **Control Flow**:
    - The function calculates `n & 15` to ensure the rotation amount is within the range of 0 to 15 bits.
    - It performs a left shift on the vector `a` by `n & 15` bits using `wh_shl_variable`.
    - It performs a right shift on the vector `a` by `(-n) & 15` bits using `wh_shr_variable`.
    - The results of the left and right shifts are combined using a bitwise OR operation with `wh_or`.
- **Output**: A 256-bit vector (`wh_t`) where each 16-bit lane has been rotated left by `n` bits.


---
### wh\_ror\_variable<!-- {{#callable:wh_ror_variable}} -->
The `wh_ror_variable` function performs a variable right rotation on each 16-bit lane of a vector of unsigned 16-bit integers.
- **Inputs**:
    - `a`: A vector of type `wh_t` (which is an alias for `__m256i`) containing 16 unsigned 16-bit integers.
    - `n`: An integer specifying the number of positions to rotate each 16-bit lane to the right.
- **Control Flow**:
    - The function calculates `n & 15` to ensure the rotation amount is within the range [0, 15].
    - It calls `wh_shr_variable(a, n & 15)` to perform a right shift on each lane by the calculated amount.
    - It calls `wh_shl_variable(a, (-n) & 15)` to perform a left shift on each lane by the complement of the calculated amount.
    - The results of the two shifts are combined using the `wh_or` function, which performs a bitwise OR operation on corresponding lanes of the two vectors.
- **Output**: The function returns a vector of type `wh_t` where each 16-bit lane has been right-rotated by the specified number of positions.



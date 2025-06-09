# Purpose
This C header file provides a set of macros and inline functions for working with 256-bit SIMD (Single Instruction, Multiple Data) vector operations using AVX (Advanced Vector Extensions) instructions, specifically targeting operations on vectors of 16-bit signed integers. The file defines a type `ws_t` as a 256-bit integer vector (`__m256i`) and provides a comprehensive API for constructing, manipulating, and performing arithmetic, binary, and logical operations on these vectors. The operations include vector construction, broadcasting, loading and storing from memory, element extraction and insertion, arithmetic operations like addition and multiplication, bitwise operations, and logical comparisons. The file is designed to be included indirectly through another header (`fd_avx.h`), ensuring that it is part of a larger library or framework.

The code is structured to maximize performance by using macros for operations that can be efficiently implemented this way, while also providing inline functions for more complex operations. This approach helps to minimize the risk of compiler optimizations interfering with the intended performance characteristics. The file includes both immediate and variable versions of certain operations, allowing for flexibility in how operations are specified at compile time versus runtime. The use of AVX instructions allows for parallel processing of multiple data elements, making this file particularly useful in high-performance computing scenarios where vectorized operations can significantly enhance computational throughput.
# Functions

---
### ws\_ld<!-- {{#callable:ws_ld}} -->
The `ws_ld` function loads a 256-bit vector of 16 short integers from a 32-byte aligned memory location.
- **Inputs**:
    - `p`: A pointer to a 32-byte aligned memory location containing 16 short integers to be loaded into a vector.
- **Control Flow**:
    - The function casts the input pointer `p` to a pointer of type `__m256i const *`.
    - It then uses the `_mm256_load_si256` intrinsic to load the 256-bit vector from the memory location pointed to by the casted pointer.
- **Output**: A 256-bit vector (`ws_t`) containing the 16 short integers loaded from the specified memory location.


---
### ws\_st<!-- {{#callable:ws_st}} -->
The `ws_st` function stores a 256-bit vector of 16 signed 16-bit integers into a 32-byte aligned memory location.
- **Inputs**:
    - `p`: A pointer to a 32-byte aligned memory location where the vector will be stored.
    - `i`: A 256-bit vector of type `ws_t` (which is an alias for `__m256i`) containing 16 signed 16-bit integers to be stored.
- **Control Flow**:
    - The function uses the `_mm256_store_si256` intrinsic to store the 256-bit vector `i` into the memory location pointed to by `p`.
- **Output**: The function does not return any value; it performs a side effect by writing to the memory location pointed to by `p`.


---
### ws\_ldu<!-- {{#callable:ws_ldu}} -->
The `ws_ldu` function loads a 256-bit vector of 16-bit integers from an unaligned memory address into a `__m256i` type.
- **Inputs**:
    - `p`: A pointer to a memory location from which a 256-bit vector of 16-bit integers will be loaded; the memory does not need to be aligned.
- **Control Flow**:
    - The function casts the input pointer `p` to a pointer of type `__m256i const *`.
    - It then uses the `_mm256_loadu_si256` intrinsic to load a 256-bit vector from the memory location pointed to by `p`.
- **Output**: The function returns a `ws_t` type, which is a `__m256i` vector containing the loaded 16-bit integers.


---
### ws\_stu<!-- {{#callable:ws_stu}} -->
The `ws_stu` function stores a 256-bit vector of 16-bit integers into a memory location that does not need to be aligned.
- **Inputs**:
    - `p`: A pointer to the memory location where the 256-bit vector will be stored; alignment is not required.
    - `i`: A 256-bit vector of 16-bit integers to be stored at the memory location pointed to by `p`.
- **Control Flow**:
    - The function uses the `_mm256_storeu_si256` intrinsic to store the vector `i` into the memory location pointed to by `p`.
- **Output**: The function does not return any value; it performs a side effect by storing data in memory.


---
### ws\_extract\_variable<!-- {{#callable:ws_extract_variable}} -->
The `ws_extract_variable` function extracts a short integer from a specified lane of a 256-bit vector containing 16 short integers.
- **Inputs**:
    - `a`: A 256-bit vector (`ws_t`) containing 16 short integers.
    - `n`: An integer specifying the lane index (0 to 15) from which to extract the short integer.
- **Control Flow**:
    - A union is defined to allow type punning between a 256-bit vector and an array of 16 short integers.
    - The 256-bit vector `a` is stored into the union's vector member using `_mm256_store_si256`.
    - The short integer at the specified lane `n` is accessed from the union's short array member and returned.
- **Output**: The function returns the short integer located at the specified lane `n` of the input vector `a`.


---
### ws\_insert\_variable<!-- {{#callable:ws_insert_variable}} -->
The `ws_insert_variable` function replaces a specific element in a 256-bit vector of 16-bit integers with a new value at a specified index.
- **Inputs**:
    - `a`: A 256-bit vector (`ws_t`) containing 16 signed 16-bit integers.
    - `n`: An integer index specifying which element in the vector to replace, should be between 0 and 15.
    - `v`: A short integer value to insert into the vector at the specified index.
- **Control Flow**:
    - A union is declared to allow type punning between a 256-bit vector and an array of 16 short integers.
    - The input vector `a` is stored into the union's 256-bit vector member using `_mm256_store_si256`.
    - The element at index `n` in the union's short array is replaced with the new value `v`.
    - The modified 256-bit vector is loaded back from the union and returned using `_mm256_load_si256`.
- **Output**: A 256-bit vector (`ws_t`) with the element at index `n` replaced by the value `v`.


---
### ws\_rol<!-- {{#callable:ws_rol}} -->
The `ws_rol` function performs a bitwise left rotation on each 16-bit lane of a 256-bit vector by a specified number of bits.
- **Inputs**:
    - `a`: A 256-bit vector (`ws_t`) where each 16-bit lane holds a signed 16-bit integer.
    - `imm`: An integer specifying the number of bits to rotate left, masked to the range [0, 15].
- **Control Flow**:
    - The function calculates the left shift of the vector `a` by `imm & 15` bits using `ws_shl`.
    - It calculates the right shift of the vector `a` by `(-imm) & 15` bits using `ws_shru`.
    - The results of the left and right shifts are combined using a bitwise OR operation via `ws_or`.
    - The combined result is returned as the output of the function.
- **Output**: A 256-bit vector (`ws_t`) with each 16-bit lane rotated left by the specified number of bits.


---
### ws\_ror<!-- {{#callable:ws_ror}} -->
The `ws_ror` function performs a bitwise right rotation on each 16-bit lane of a 256-bit vector by a specified number of bits.
- **Inputs**:
    - `a`: A 256-bit vector (`ws_t`) where each 16-bit lane holds a signed 16-bit integer.
    - `imm`: An integer specifying the number of bits to rotate each lane to the right.
- **Control Flow**:
    - The function calculates `imm & 15` to ensure the rotation amount is within the range of 0 to 15 bits.
    - It performs an unsigned right shift on the vector `a` by `imm & 15` bits using `ws_shru`.
    - It performs a left shift on the vector `a` by `(-imm) & 15` bits using `ws_shl`.
    - The results of the two shifts are combined using a bitwise OR operation with `ws_or`.
- **Output**: The function returns a 256-bit vector (`ws_t`) where each 16-bit lane has been right-rotated by the specified number of bits.


---
### ws\_rol\_variable<!-- {{#callable:ws_rol_variable}} -->
The `ws_rol_variable` function performs a variable bitwise left rotation on each 16-bit lane of a 256-bit vector.
- **Inputs**:
    - `a`: A 256-bit vector (`ws_t`) where each 16-bit lane holds a signed 16-bit integer.
    - `n`: An integer specifying the number of positions to rotate each 16-bit lane to the left.
- **Control Flow**:
    - The function calculates `n & 15` to ensure the rotation amount is within the range of 0 to 15 bits.
    - It calls `ws_shl_variable(a, n & 15)` to perform a left shift on each lane by the calculated amount.
    - It calls `ws_shru_variable(a, (-n) & 15)` to perform a right shift on each lane by the complement of the calculated amount, effectively rotating the bits that overflowed from the left shift.
    - The results of the left and right shifts are combined using `ws_or` to produce the final rotated vector.
- **Output**: The function returns a 256-bit vector (`ws_t`) with each 16-bit lane rotated left by the specified number of positions.


---
### ws\_ror\_variable<!-- {{#callable:ws_ror_variable}} -->
The `ws_ror_variable` function performs a variable bitwise right rotation on each 16-bit lane of a 256-bit vector.
- **Inputs**:
    - `a`: A 256-bit vector (`ws_t`) where each lane is a signed 16-bit integer.
    - `n`: An integer specifying the number of positions to rotate each lane to the right.
- **Control Flow**:
    - The function calculates `n & 15` to ensure the rotation amount is within the range of 0 to 15 bits.
    - It calls `ws_shru_variable(a, n&15)` to perform an unsigned right shift on each lane by `n & 15` bits.
    - It calls `ws_shl_variable(a, (-n)&15)` to perform a left shift on each lane by `(-n) & 15` bits, effectively rotating the bits that were shifted out back to the left side.
    - The results of the two shifts are combined using `ws_or` to produce the final rotated vector.
- **Output**: A 256-bit vector (`ws_t`) with each 16-bit lane rotated right by `n` positions.



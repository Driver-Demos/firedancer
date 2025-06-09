# Purpose
This C source code file is a specialized utility for handling vector conditionals using AVX (Advanced Vector Extensions) SIMD (Single Instruction, Multiple Data) instructions. It defines a set of macros and inline functions to manipulate vectors of integers, where each 32-bit lane represents a boolean condition. The file is designed to be included indirectly through a header file (`fd_avx.h`), as indicated by the initial preprocessor directive. The primary data type used is `wc_t`, which is an alias for `__m256i`, representing a 256-bit vector of integers. The code provides a comprehensive API for constructing, manipulating, and performing operations on these vector conditionals, including logical, binary, and conditional operations, as well as memory operations for loading and storing vector data.

The file is not a standalone executable but rather a component intended to be included in other C programs that require efficient SIMD operations. It does not define public APIs or external interfaces directly but provides a robust set of internal utilities for vector conditional operations. The code is highly specialized, focusing on optimizing operations for 32-bit lanes, with some support for 64-bit lanes. It includes various constructors for creating vector conditionals, predefined constants for true and false vectors, and functions for memory operations, element extraction and insertion, and conversion between different vector types. The file also includes advanced operations like transposing an 8x8 matrix of vector conditionals, showcasing its utility in high-performance computing scenarios where SIMD operations can significantly enhance computational efficiency.
# Functions

---
### wc\_bcast<!-- {{#callable:wc_bcast}} -->
The `wc_bcast` function creates a vector conditional where all lanes are set to either 0 or -1 based on the logical value of the input integer.
- **Inputs**:
    - `c0`: An integer representing a C-style logical value, where zero is false and non-zero is true.
- **Control Flow**:
    - Convert the input integer `c0` to a C-style logical value, setting it to -1 if non-zero and 0 if zero.
    - Use the `FD_COMPILER_FORGET` macro to prevent the compiler from optimizing away the conversion of `c0`.
    - Return a 256-bit vector with all lanes set to the value of `c0` using the `_mm256_set1_epi32` intrinsic.
- **Output**: A 256-bit vector (`__m256i`) where each 32-bit lane is set to the logical value of the input integer, either 0 or -1.


---
### wc\_bcast\_pair<!-- {{#callable:wc_bcast_pair}} -->
The `wc_bcast_pair` function creates a vector conditional with alternating values based on two input integers, broadcasting them across an AVX 256-bit register.
- **Inputs**:
    - `c0`: An integer representing a logical value to be broadcasted to even lanes of the vector; non-zero values are treated as true (-1) and zero as false (0).
    - `c1`: An integer representing a logical value to be broadcasted to odd lanes of the vector; non-zero values are treated as true (-1) and zero as false (0).
- **Control Flow**:
    - Convert c0 to -1 if non-zero, otherwise 0.
    - Convert c1 to -1 if non-zero, otherwise 0.
    - Return a 256-bit vector with the pattern [c0, c1, c0, c1, c0, c1, c0, c1].
- **Output**: A 256-bit AVX vector (`wc_t`) with the pattern [c0, c1, c0, c1, c0, c1, c0, c1], where c0 and c1 are either 0 or -1 based on their logical values.


---
### wc\_bcast\_lohi<!-- {{#callable:wc_bcast_lohi}} -->
The `wc_bcast_lohi` function creates a vector conditional with the first four lanes set to the logical value of `c0` and the last four lanes set to the logical value of `c1`.
- **Inputs**:
    - `c0`: An integer representing a logical value, where non-zero is treated as true and zero as false.
    - `c1`: An integer representing a logical value, where non-zero is treated as true and zero as false.
- **Control Flow**:
    - Convert `c0` to -1 if non-zero or 0 if zero using `-!!c0`.
    - Convert `c1` to -1 if non-zero or 0 if zero using `-!!c1`.
    - Return a vector with the first four lanes set to the value of `c0` and the last four lanes set to the value of `c1` using `_mm256_setr_epi32`.
- **Output**: A `wc_t` vector conditional with the first four lanes set to the logical value of `c0` and the last four lanes set to the logical value of `c1`.


---
### wc\_bcast\_quad<!-- {{#callable:wc_bcast_quad}} -->
The `wc_bcast_quad` function creates a vector conditional with four pairs of 32-bit integer lanes, each pair representing the logical negation of the input integers.
- **Inputs**:
    - `c0`: An integer representing a logical condition for the first and fifth lanes.
    - `c1`: An integer representing a logical condition for the second and sixth lanes.
    - `c2`: An integer representing a logical condition for the third and seventh lanes.
    - `c3`: An integer representing a logical condition for the fourth and eighth lanes.
- **Control Flow**:
    - Convert each input integer (c0, c1, c2, c3) to -1 if non-zero (true) or 0 if zero (false) using the expression '-!!c'.
    - Use the `_mm256_setr_epi32` intrinsic to create a 256-bit vector with the pattern [c0, c1, c2, c3, c0, c1, c2, c3].
- **Output**: A 256-bit vector (`wc_t`) with eight 32-bit integer lanes, where each lane is either 0 or -1 based on the logical negation of the input integers.


---
### wc\_bcast\_wide<!-- {{#callable:wc_bcast_wide}} -->
The `wc_bcast_wide` function creates a vector conditional with each pair of adjacent lanes set to the same logical value based on the input integers.
- **Inputs**:
    - `c0`: An integer representing a logical value for the first pair of lanes.
    - `c1`: An integer representing a logical value for the second pair of lanes.
    - `c2`: An integer representing a logical value for the third pair of lanes.
    - `c3`: An integer representing a logical value for the fourth pair of lanes.
- **Control Flow**:
    - Convert each input integer (c0, c1, c2, c3) to a logical value where non-zero becomes -1 (true) and zero becomes 0 (false).
    - Use the `_mm256_setr_epi32` intrinsic to create a 256-bit vector with the pattern [c0, c0, c1, c1, c2, c2, c3, c3].
- **Output**: A 256-bit vector (`wc_t`) where each pair of adjacent lanes is set to the same logical value based on the input integers.


---
### wc\_exch\_adj\_quad<!-- {{#callable:wc_exch_adj_quad}} -->
The `wc_exch_adj_quad` function rearranges the 128-bit lanes of a 256-bit vector conditional by swapping the first and second 128-bit lanes.
- **Inputs**:
    - `c`: A 256-bit vector conditional of type `wc_t` (which is a typedef for `__m256i`).
- **Control Flow**:
    - The function takes a 256-bit vector conditional `c` as input.
    - It uses the `_mm256_permute2f128_si256` intrinsic to swap the two 128-bit lanes of the input vector.
    - The intrinsic is called with the same vector `c` for both source operands and a control value of `1`, which specifies the lane swap operation.
- **Output**: The function returns a 256-bit vector conditional with its 128-bit lanes swapped, effectively changing the order of the elements from [c4 c5 c6 c7 c0 c1 c2 c3] to [c0 c1 c2 c3 c4 c5 c6 c7].


---
### wc\_ld<!-- {{#callable:wc_ld}} -->
The `wc_ld` function loads 8 integers from a 32-byte aligned memory location and returns them as a vector conditional, where each lane is set to 0 if the integer is zero and -1 otherwise.
- **Inputs**:
    - `p`: A pointer to a 32-byte aligned memory location containing 8 integers.
- **Control Flow**:
    - Load 8 integers from the memory location pointed to by `p` using `_mm256_load_si256`.
    - Compare the loaded integers to zero using `_mm256_cmpeq_epi32`, resulting in a vector where each lane is set to -1 if the integer is zero and 0 otherwise.
    - Invert the comparison result using `_mm256_xor_si256` with a vector of -1s, effectively setting each lane to 0 if the integer is zero and -1 otherwise.
- **Output**: A `wc_t` vector conditional where each lane is 0 if the corresponding integer in the input is zero, and -1 otherwise.


---
### wc\_ld\_fast<!-- {{#callable:wc_ld_fast}} -->
The `wc_ld_fast` function loads a 256-bit vector of integers from a 32-byte aligned memory location into a `wc_t` type using AVX2 intrinsics.
- **Inputs**:
    - `p`: A pointer to a constant integer array, which must be 32-byte aligned, from which the 256-bit vector will be loaded.
- **Control Flow**:
    - The function uses the AVX2 intrinsic `_mm256_load_si256` to load a 256-bit vector from the memory location pointed to by `p`.
    - The pointer `p` is cast to a `__m256i const *` to match the expected input type for the intrinsic.
- **Output**: The function returns a `wc_t` type, which is a 256-bit vector of integers loaded from the specified memory location.


---
### wc\_st<!-- {{#callable:wc_st}} -->
The `wc_st` function stores a vector conditional `wc_t` at a 32-byte aligned memory location pointed to by an integer pointer.
- **Inputs**:
    - `p`: A pointer to an integer array where the vector conditional will be stored; it must be 32-byte aligned.
    - `c`: A vector conditional of type `wc_t` that represents a vector of integers, where each 32-bit lane is either 0 or -1.
- **Control Flow**:
    - The function uses the `_mm256_store_si256` intrinsic to store the vector conditional `c` into the memory location pointed to by `p`.
- **Output**: The function does not return a value; it performs a side effect by storing data at the specified memory location.


---
### wc\_ldu<!-- {{#callable:wc_ldu}} -->
The `wc_ldu` function loads an unaligned 256-bit vector from memory, compares each 32-bit lane to zero, and returns a vector conditional where each lane is set to -1 if the comparison is false and 0 if true.
- **Inputs**:
    - `p`: A pointer to a memory location from which a 256-bit vector is to be loaded; the pointer does not need to be aligned.
- **Control Flow**:
    - Load a 256-bit vector from the memory location pointed to by `p` using `_mm256_loadu_si256`, which allows for unaligned memory access.
    - Compare each 32-bit lane of the loaded vector to zero using `_mm256_cmpeq_epi32`, resulting in a vector where each lane is set to -1 if the lane is zero and 0 otherwise.
    - Invert the comparison result using `_mm256_xor_si256` with a vector of all -1s, effectively flipping the bits so that each lane is set to -1 if the original lane was non-zero and 0 if it was zero.
- **Output**: A `wc_t` type vector conditional, where each 32-bit lane is set to -1 if the corresponding lane in the loaded vector was non-zero, and 0 if it was zero.


---
### wc\_ldu\_fast<!-- {{#callable:wc_ldu_fast}} -->
The `wc_ldu_fast` function loads a 256-bit vector of integers from an unaligned memory address into a `wc_t` type using AVX2 instructions.
- **Inputs**:
    - `p`: A pointer to a memory location from which a 256-bit vector of integers will be loaded; the memory does not need to be aligned.
- **Control Flow**:
    - The function uses the `_mm256_loadu_si256` intrinsic to load a 256-bit vector from the memory location pointed to by `p`.
    - The pointer `p` is cast to a `__m256i const *` type to match the expected input type for the intrinsic.
- **Output**: The function returns a `wc_t` type, which is a 256-bit vector of integers loaded from the specified memory location.


---
### wc\_stu<!-- {{#callable:wc_stu}} -->
The `wc_stu` function stores a vector conditional `wc_t` at a specified memory location without requiring alignment.
- **Inputs**:
    - `p`: A pointer to the memory location where the vector conditional will be stored; it does not need to be aligned.
    - `c`: A vector conditional of type `wc_t` that represents a vector of integers, where each 32-bit lane is either 0 (true) or -1 (false).
- **Control Flow**:
    - The function uses the `_mm256_storeu_si256` intrinsic to store the vector conditional `c` at the memory location pointed to by `p`.
    - The intrinsic allows for unaligned memory access, meaning `p` does not need to be aligned to a 32-byte boundary.
- **Output**: The function does not return a value; it performs a side effect by storing the vector conditional at the specified memory location.


---
### wc\_narrow<!-- {{#callable:wc_narrow}} -->
The `wc_narrow` function combines two 256-bit vector conditionals into a single 256-bit vector by selecting specific lanes from each input.
- **Inputs**:
    - `a`: A 256-bit vector conditional of type `wc_t` representing the first input vector.
    - `b`: A 256-bit vector conditional of type `wc_t` representing the second input vector.
- **Control Flow**:
    - Extracts the lower 128 bits from vector `a` and casts them to a 128-bit floating-point vector `a01`.
    - Extracts the upper 128 bits from vector `a` and casts them to a 128-bit floating-point vector `a23`.
    - Extracts the lower 128 bits from vector `b` and casts them to a 128-bit floating-point vector `b01`.
    - Extracts the upper 128 bits from vector `b` and casts them to a 128-bit floating-point vector `b23`.
    - Shuffles the elements of `a01` and `a23` to create a new 128-bit vector by selecting the 0th and 2nd elements from each.
    - Shuffles the elements of `b01` and `b23` to create another 128-bit vector by selecting the 0th and 2nd elements from each.
    - Combines the two shuffled 128-bit vectors into a single 256-bit vector conditional.
- **Output**: A 256-bit vector conditional of type `wc_t` that contains selected lanes from the input vectors `a` and `b`.



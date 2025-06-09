# Purpose
This C source code file is a specialized utility for handling SIMD (Single Instruction, Multiple Data) operations using SSE (Streaming SIMD Extensions) instructions. It defines a set of macros and inline functions to manipulate vector conditionals, which are vectors of integers where each 32-bit lane represents a boolean condition (true or false). The file provides a comprehensive API for constructing, manipulating, and converting these vector conditionals, allowing for efficient parallel processing of data. The code is designed to work with 32-bit lanes, with some support for 64-bit lanes, and includes operations for logical, binary, and conditional manipulations, as well as memory operations for loading and storing vector conditionals.

The file is intended to be included indirectly through a header file named `fd_sse.h`, as indicated by the initial preprocessor directive. It does not define a public API or external interfaces directly but provides a set of utilities that can be used by other parts of a program to perform SIMD operations efficiently. The use of macros and inline functions is emphasized to ensure performance and to avoid potential issues with compiler optimizations. The code also includes several predefined constants and operations for converting vector conditionals to other vector types, such as floats and integers, and for performing reductions and transpositions on 4x4 matrices of vector conditionals.
# Functions

---
### vc\_bcast<!-- {{#callable:vc_bcast}} -->
The `vc_bcast` function creates a vector conditional with all lanes set to either 0 or -1 based on the logical value of the input integer.
- **Inputs**:
    - `c0`: An integer representing a C-style logical value, where zero is false and non-zero is true.
- **Control Flow**:
    - Convert the input integer `c0` to a C-style logical value, setting it to -1 if non-zero and 0 if zero.
    - Use the `FD_COMPILER_FORGET` macro to prevent the compiler from optimizing away the conversion of `c0`.
    - Return a 128-bit SIMD vector with all four 32-bit lanes set to the value of `c0` using the `_mm_set1_epi32` intrinsic.
- **Output**: A 128-bit SIMD vector (`__m128i`) with all lanes set to either 0 or -1, representing the logical value of the input.


---
### vc\_bcast\_pair<!-- {{#callable:vc_bcast_pair}} -->
The `vc_bcast_pair` function creates a vector conditional with alternating values based on two input integers, each converted to a vector conditional format.
- **Inputs**:
    - `c0`: An integer representing a logical value, where non-zero is treated as true and zero as false.
    - `c1`: An integer representing a logical value, where non-zero is treated as true and zero as false.
- **Control Flow**:
    - Convert `c0` to -1 if non-zero (true) or 0 if zero (false).
    - Convert `c1` to -1 if non-zero (true) or 0 if zero (false).
    - Return a vector conditional with the pattern [c0, c1, c0, c1] using the converted values.
- **Output**: A `vc_t` vector conditional with the pattern [c0, c1, c0, c1], where each element is either 0 or -1 based on the logical values of the inputs.


---
### vc\_bcast\_wide<!-- {{#callable:vc_bcast_wide}} -->
The `vc_bcast_wide` function creates a vector conditional with two pairs of lanes, each pair initialized to the logical value of the respective input integer.
- **Inputs**:
    - `c0`: An integer representing a logical value, where non-zero is treated as true and zero as false.
    - `c1`: An integer representing a logical value, where non-zero is treated as true and zero as false.
- **Control Flow**:
    - Convert `c0` to a logical value by setting it to -1 if non-zero, otherwise 0.
    - Convert `c1` to a logical value by setting it to -1 if non-zero, otherwise 0.
    - Return a vector conditional with the first two lanes set to the logical value of `c0` and the last two lanes set to the logical value of `c1`.
- **Output**: A `vc_t` vector conditional with the first two lanes set to the logical value of `c0` and the last two lanes set to the logical value of `c1`.


---
### vc\_ld<!-- {{#callable:vc_ld}} -->
The `vc_ld` function loads a 128-bit vector from a 16-byte aligned memory location and converts it into a proper vector conditional format.
- **Inputs**:
    - `p`: A pointer to a 16-byte aligned memory location containing four 32-bit integers.
- **Control Flow**:
    - Load a 128-bit vector from the memory location pointed to by `p` using `_mm_load_si128`.
    - Compare the loaded vector with a zero vector using `_mm_cmpeq_epi32`, resulting in a vector where each lane is either 0 (if the corresponding lane in the loaded vector is zero) or -1 (if the corresponding lane in the loaded vector is non-zero).
    - XOR the result with a vector of all -1s using `_mm_xor_si128`, effectively converting the comparison result into a proper vector conditional format where 0 indicates true and -1 indicates false.
- **Output**: A `vc_t` type, which is a 128-bit vector conditional where each 32-bit lane is either 0 (true) or -1 (false) based on the comparison with zero.


---
### vc\_ld\_fast<!-- {{#callable:vc_ld_fast}} -->
The `vc_ld_fast` function loads a 128-bit SIMD vector from a 16-byte aligned memory location, assuming the data is already in a proper vector conditional format.
- **Inputs**:
    - `p`: A pointer to a constant integer array, which should be 16-byte aligned and contain data in a proper vector conditional format (0 for true, -1 for false).
- **Control Flow**:
    - The function directly calls the intrinsic `_mm_load_si128` to load a 128-bit SIMD vector from the memory location pointed to by `p`.
- **Output**: The function returns a `vc_t` type, which is a 128-bit SIMD vector loaded from the specified memory location.


---
### vc\_st<!-- {{#callable:vc_st}} -->
The `vc_st` function stores a vector conditional `vc_t` at a 16-byte aligned memory location pointed to by an integer pointer.
- **Inputs**:
    - `p`: A pointer to an integer array where the vector conditional will be stored; it must be 16-byte aligned.
    - `c`: A vector conditional of type `vc_t` (which is an alias for `__m128i`) representing the data to be stored.
- **Control Flow**:
    - The function uses the intrinsic `_mm_store_si128` to store the vector conditional `c` into the memory location pointed to by `p`.
- **Output**: The function does not return a value; it performs a side effect by storing data at the specified memory location.


---
### vc\_ldu<!-- {{#callable:vc_ldu}} -->
The `vc_ldu` function loads a 128-bit vector from an unaligned memory address and converts it into a vector conditional format.
- **Inputs**:
    - `p`: A pointer to a memory location from which a 128-bit vector is to be loaded; the memory does not need to be aligned.
- **Control Flow**:
    - The function begins by loading a 128-bit vector from the memory location pointed to by `p` using `_mm_loadu_si128`, which allows for unaligned memory access.
    - It then compares each 32-bit integer in the loaded vector to zero using `_mm_cmpeq_epi32`, resulting in a vector where each lane is either all ones (if the original value was zero) or all zeros (if the original value was non-zero).
    - Finally, it applies a bitwise XOR operation with a vector of all ones (`_mm_set1_epi32(-1)`), effectively inverting the result of the comparison, so that zero values become -1 (true) and non-zero values become 0 (false).
- **Output**: The function returns a `vc_t` type, which is a 128-bit vector where each 32-bit lane is either 0 (indicating true) or -1 (indicating false), representing a vector conditional.


---
### vc\_ldu\_fast<!-- {{#callable:vc_ldu_fast}} -->
The `vc_ldu_fast` function loads a 128-bit vector from an unaligned memory address into a `vc_t` type without any additional processing.
- **Inputs**:
    - `p`: A pointer to a memory location from which a 128-bit vector is to be loaded; it is expected to be unaligned.
- **Control Flow**:
    - The function directly calls the intrinsic `_mm_loadu_si128` to load a 128-bit vector from the memory location pointed to by `p`.
    - The pointer `p` is cast to a `__m128i const *` type to match the expected input type for `_mm_loadu_si128`.
- **Output**: The function returns a `vc_t` type, which is a 128-bit vector loaded from the specified memory location.


---
### vc\_stu<!-- {{#callable:vc_stu}} -->
The `vc_stu` function stores a vector conditional (`vc_t`) into a memory location that does not need to be aligned.
- **Inputs**:
    - `p`: A pointer to the memory location where the vector conditional will be stored; it does not need to be aligned.
    - `c`: The vector conditional (`vc_t`) to be stored at the memory location pointed to by `p`.
- **Control Flow**:
    - The function uses the `_mm_storeu_si128` intrinsic to store the vector conditional `c` into the memory location pointed to by `p`.
- **Output**: The function does not return any value; it performs an in-place operation on the memory location pointed to by `p`.


---
### vc\_expand<!-- {{#callable:vc_expand}} -->
The `vc_expand` function expands a vector conditional by duplicating either the first two or the last two lanes based on the `imm_hi` flag.
- **Inputs**:
    - `c`: A vector conditional (`vc_t`) which is a vector of integers where each 32-bit wide lane is either 0 or -1.
    - `imm_hi`: An integer flag that determines which lanes to expand; if non-zero, the last two lanes are expanded, otherwise the first two lanes are expanded.
- **Control Flow**:
    - The function checks the value of `imm_hi` to decide which lanes to expand.
    - If `imm_hi` is non-zero, it uses `_mm_shuffle_epi32` to shuffle the vector `c` such that the last two lanes are duplicated.
    - If `imm_hi` is zero, it directly uses the vector `c` without shuffling.
    - The resulting vector is then converted from 32-bit integers to 64-bit integers using `_mm_cvtepi32_epi64`.
- **Output**: A `vc_t` vector where either the first two lanes or the last two lanes are duplicated to form a paired lane conditional.



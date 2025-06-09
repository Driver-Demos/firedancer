# Purpose
This C source code file provides specialized functions for finding the least significant bit (LSB) set in various integer types, including `uchar`, `ushort`, `uint`, `ulong`, and `uint128`. The file is not meant to be included directly but is instead included by another header file, `fd_bits.h`. The code is optimized for different architectures, particularly x86 with BMI (Bit Manipulation Instruction Set) support, and provides alternative implementations for other architectures. The functions are defined as `static inline`, indicating they are intended for use within the same translation unit to improve performance by avoiding function call overhead.

The file includes two main sets of functions: `fd_<type>_find_lsb` and `fd_<type>_find_lsb_w_default`. The first set of functions returns the position of the LSB set in the input value, while the second set provides a default return value if the input is zero. For x86 architectures with BMI support, the code uses inline assembly to leverage specific instructions like `tzcnt` and `bsf` for efficient bit scanning. The use of inline assembly and conditional move instructions (`cmov`) helps optimize performance by reducing branch mispredictions and dependencies. The file is a part of a broader library, likely focused on bit manipulation, and does not define public APIs or external interfaces directly, as it is intended to be included by other components within the library.
# Functions

---
### fd\_uchar\_find\_lsb<!-- {{#callable:fd_uchar_find_lsb}} -->
The `fd_uchar_find_lsb` function finds the position of the least significant bit set to 1 in an unsigned char value.
- **Inputs**:
    - `x`: An unsigned char value whose least significant set bit position is to be found.
- **Control Flow**:
    - The function casts the input `x` to an `int` type.
    - It then calls the `__builtin_ffs` function, which finds the position of the first set bit (1-based index) in the integer representation of `x`.
    - The function subtracts 1 from the result of `__builtin_ffs` to convert the 1-based index to a 0-based index, which is the position of the least significant set bit.
- **Output**: The function returns an integer representing the 0-based index of the least significant bit set to 1 in the input `x`, or -1 if no bits are set.


---
### fd\_ushort\_find\_lsb<!-- {{#callable:fd_ushort_find_lsb}} -->
The `fd_ushort_find_lsb` function finds the position of the least significant bit set to 1 in a `ushort` integer, returning -1 if no bits are set.
- **Inputs**:
    - `x`: A `ushort` integer whose least significant set bit position is to be found.
- **Control Flow**:
    - The function casts the `ushort` input `x` to an `int`.
    - It then calls the `__builtin_ffs` function, which finds the position of the first set bit (1-based index) in the integer.
    - The result of `__builtin_ffs` is decremented by 1 to convert the 1-based index to a 0-based index, which is the expected output.
- **Output**: The function returns an `int` representing the 0-based index of the least significant bit set to 1 in the input `ushort`. If no bits are set, it returns -1.


---
### fd\_uint\_find\_lsb<!-- {{#callable:fd_uint_find_lsb}} -->
The `fd_uint_find_lsb` function finds the position of the least significant bit set to 1 in an unsigned integer.
- **Inputs**:
    - `x`: An unsigned integer (`uint`) whose least significant set bit position is to be found.
- **Control Flow**:
    - The function uses the GCC built-in function `__builtin_ffs` to find the position of the first set bit (1-based index) in the integer `x`.
    - It casts `x` to an `int` before calling `__builtin_ffs`.
    - The function returns the result of `__builtin_ffs` minus 1 to convert the 1-based index to a 0-based index.
- **Output**: The function returns an integer representing the 0-based index of the least significant bit set to 1 in `x`, or -1 if `x` is 0.


---
### fd\_ulong\_find\_lsb<!-- {{#callable:fd_ulong_find_lsb}} -->
The `fd_ulong_find_lsb` function finds the position of the least significant bit set to 1 in an unsigned long integer.
- **Inputs**:
    - `x`: An unsigned long integer whose least significant set bit position is to be found.
- **Control Flow**:
    - The function casts the input `x` to a `long` type.
    - It then calls the built-in function `__builtin_ffsl` to find the position of the first set bit (1-based index) in the `long` representation of `x`.
    - The function returns the result of `__builtin_ffsl` minus 1 to convert the 1-based index to a 0-based index.
- **Output**: The function returns an integer representing the 0-based index of the least significant bit set to 1 in the input `x`, or -1 if `x` is 0.


---
### fd\_uint128\_find\_lsb<!-- {{#callable:fd_uint128_find_lsb}} -->
The `fd_uint128_find_lsb` function finds the position of the least significant bit set to 1 in a 128-bit unsigned integer.
- **Inputs**:
    - `x`: A 128-bit unsigned integer (`uint128`) whose least significant set bit position is to be found.
- **Control Flow**:
    - The function casts the lower 64 bits of `x` to `ulong` and assigns it to `xl`.
    - The function shifts `x` right by 64 bits, casts it to `ulong`, and assigns it to `xh`.
    - It checks if `xl` is zero and assigns the result to `c`.
    - If `xl` is zero (`c` is true), it uses `xh` to find the least significant bit; otherwise, it uses `xl`.
    - The function calculates the position of the least significant bit using `__builtin_ffsl` and adjusts the result based on whether `xl` was zero.
- **Output**: The function returns an integer representing the position of the least significant bit set to 1 in the 128-bit integer `x`, or -1 if `x` is zero.


---
### fd\_uchar\_find\_lsb\_w\_default<!-- {{#callable:fd_uchar_find_lsb_w_default}} -->
The `fd_uchar_find_lsb_w_default` function returns the position of the least significant bit set in an unsigned char, or a default value if no bits are set.
- **Inputs**:
    - `x`: An unsigned char value whose least significant bit position is to be found.
    - `d`: An integer default value to return if no bits are set in x.
- **Control Flow**:
    - Check if the input `x` is zero.
    - If `x` is zero, return the default value `d`.
    - If `x` is not zero, call `fd_uchar_find_lsb(x)` to find the position of the least significant bit set in `x`.
- **Output**: Returns an integer representing the position of the least significant bit set in `x`, or the default value `d` if `x` is zero.
- **Functions called**:
    - [`fd_uchar_find_lsb`](#fd_uchar_find_lsb)


---
### fd\_ushort\_find\_lsb\_w\_default<!-- {{#callable:fd_ushort_find_lsb_w_default}} -->
The `fd_ushort_find_lsb_w_default` function returns the position of the least significant bit set in a `ushort` integer, or a default value if the integer is zero.
- **Inputs**:
    - `x`: A `ushort` integer whose least significant bit position is to be found.
    - `d`: An integer representing the default value to return if `x` is zero.
- **Control Flow**:
    - Check if `x` is zero.
    - If `x` is zero, return the default value `d`.
    - If `x` is not zero, call `fd_ushort_find_lsb(x)` to find the position of the least significant bit set in `x`.
- **Output**: Returns an integer representing the position of the least significant bit set in `x`, or the default value `d` if `x` is zero.
- **Functions called**:
    - [`fd_ushort_find_lsb`](#fd_ushort_find_lsb)


---
### fd\_uint\_find\_lsb\_w\_default<!-- {{#callable:fd_uint_find_lsb_w_default}} -->
The `fd_uint_find_lsb_w_default` function returns the index of the least significant bit set in an unsigned integer, or a default value if the integer is zero.
- **Inputs**:
    - `x`: An unsigned integer (uint) whose least significant bit is to be found.
    - `d`: An integer representing the default value to return if x is zero.
- **Control Flow**:
    - Check if the input integer x is zero.
    - If x is zero, return the default value d.
    - If x is not zero, call the function [`fd_uint_find_lsb`](#fd_uint_find_lsb) to find the index of the least significant bit set in x and return that value.
- **Output**: An integer representing the index of the least significant bit set in x, or the default value d if x is zero.
- **Functions called**:
    - [`fd_uint_find_lsb`](#fd_uint_find_lsb)


---
### fd\_ulong\_find\_lsb\_w\_default<!-- {{#callable:fd_ulong_find_lsb_w_default}} -->
The `fd_ulong_find_lsb_w_default` function returns the index of the least significant bit set in an unsigned long integer, or a default value if no bits are set.
- **Inputs**:
    - `x`: An unsigned long integer whose least significant bit set is to be found.
    - `d`: An integer representing the default value to return if no bits are set in x.
- **Control Flow**:
    - Check if the input `x` is zero.
    - If `x` is zero, return the default value `d`.
    - If `x` is not zero, call `fd_ulong_find_lsb(x)` to find the index of the least significant bit set in `x`.
- **Output**: Returns an integer representing the index of the least significant bit set in `x`, or the default value `d` if `x` is zero.
- **Functions called**:
    - [`fd_ulong_find_lsb`](#fd_ulong_find_lsb)


---
### fd\_uint128\_find\_lsb\_w\_default<!-- {{#callable:fd_uint128_find_lsb_w_default}} -->
The `fd_uint128_find_lsb_w_default` function returns the position of the least significant bit set in a 128-bit unsigned integer, or a default value if the integer is zero.
- **Inputs**:
    - `x`: A 128-bit unsigned integer whose least significant bit position is to be found.
    - `d`: An integer representing the default value to return if the input integer x is zero.
- **Control Flow**:
    - Check if the input integer x is zero.
    - If x is zero, return the default value d.
    - If x is not zero, call the function [`fd_uint128_find_lsb`](#fd_uint128_find_lsb) to find and return the position of the least significant bit set in x.
- **Output**: An integer representing the position of the least significant bit set in x, or the default value d if x is zero.
- **Functions called**:
    - [`fd_uint128_find_lsb`](#fd_uint128_find_lsb)



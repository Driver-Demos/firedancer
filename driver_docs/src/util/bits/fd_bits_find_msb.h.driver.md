# Purpose
This C source code file is designed to provide utility functions for finding the most significant bit (MSB) in various integer types, including `uchar`, `ushort`, `uint`, `ulong`, and `uint128`. The file is not intended to be included directly; instead, it is included by another header file, `fd_bits.h`. The functions are implemented as static inline functions, which suggests that they are meant to be used within the same translation unit to optimize performance by avoiding function call overhead. The code includes architecture-specific optimizations, particularly for x86 architectures, using inline assembly to leverage processor instructions like `lzcnt` and `bsr` for efficient bit manipulation. These optimizations are conditional, allowing the code to adapt to different hardware capabilities, such as the presence of 128-bit integers or specific x86 instructions.

The file provides two sets of functions: one set for finding the MSB directly and another set that includes a default value to return when the input is zero. This dual functionality is useful for applications where a default behavior is needed when no bits are set. The use of inline assembly and conditional compilation directives indicates a focus on performance and portability across different architectures. The functions are marked with `FD_FN_CONST`, suggesting that they are pure functions with no side effects, which can be beneficial for compiler optimizations. Overall, this file is a specialized utility for bit manipulation, providing efficient and portable solutions for determining the MSB in various integer types.
# Functions

---
### fd\_uchar\_find\_msb<!-- {{#callable:fd_uchar_find_msb}} -->
The `fd_uchar_find_msb` function calculates the position of the most significant bit (MSB) set to 1 in an unsigned char value.
- **Inputs**:
    - `x`: An unsigned char value for which the most significant bit position is to be found.
- **Control Flow**:
    - The function casts the input `x` to an unsigned integer type.
    - It uses the built-in function `__builtin_clz` to count the number of leading zeros in the integer representation of `x`.
    - The result of `__builtin_clz` is subtracted from 31 to determine the position of the most significant bit set to 1.
- **Output**: The function returns an integer representing the zero-based index of the most significant bit set to 1 in the input value.


---
### fd\_ushort\_find\_msb<!-- {{#callable:fd_ushort_find_msb}} -->
The `fd_ushort_find_msb` function calculates the position of the most significant bit (MSB) set to 1 in a given unsigned short integer.
- **Inputs**:
    - `x`: An unsigned short integer whose most significant bit position is to be found.
- **Control Flow**:
    - The function casts the input `x` from `ushort` to `uint` to ensure compatibility with the `__builtin_clz` function.
    - It then calls the `__builtin_clz` function, which counts the number of leading zeros in the binary representation of the input integer.
    - The result of `__builtin_clz` is subtracted from 31 to determine the position of the most significant bit set to 1.
- **Output**: The function returns an integer representing the zero-based index of the most significant bit set to 1 in the binary representation of the input `ushort`.


---
### fd\_uint\_find\_msb<!-- {{#callable:fd_uint_find_msb}} -->
The `fd_uint_find_msb` function calculates the position of the most significant bit (MSB) set to 1 in a given unsigned integer.
- **Inputs**:
    - `x`: An unsigned integer (`uint`) whose most significant bit position is to be found.
- **Control Flow**:
    - The function uses the built-in function `__builtin_clz` to count the number of leading zeros in the binary representation of `x`.
    - It subtracts the count of leading zeros from 31 to determine the position of the most significant bit set to 1.
- **Output**: The function returns an integer representing the zero-based index of the most significant bit set to 1 in the input `x`.


---
### fd\_ulong\_find\_msb<!-- {{#callable:fd_ulong_find_msb}} -->
The `fd_ulong_find_msb` function calculates the index of the most significant bit set to 1 in an unsigned long integer.
- **Inputs**:
    - `x`: An unsigned long integer whose most significant bit set to 1 is to be found.
- **Control Flow**:
    - The function uses the built-in function `__builtin_clzl` to count the number of leading zeros in the binary representation of `x`.
    - It subtracts the result from 63, which is the maximum index for a 64-bit unsigned long, to find the index of the most significant bit set to 1.
- **Output**: The function returns an integer representing the index of the most significant bit set to 1 in the input unsigned long integer.


---
### fd\_uint128\_find\_msb<!-- {{#callable:fd_uint128_find_msb}} -->
The `fd_uint128_find_msb` function calculates the index of the most significant bit set in a 128-bit unsigned integer.
- **Inputs**:
    - `x`: A 128-bit unsigned integer (`uint128`) whose most significant bit is to be found.
- **Control Flow**:
    - The function casts the lower 64 bits of `x` to `ulong` and assigns it to `xl`.
    - The function shifts `x` right by 64 bits, casts the result to `ulong`, and assigns it to `xh`.
    - It checks if `xh` is zero and assigns the result to `c`.
    - The function calculates the most significant bit index using the formula `(127-((c)<<6)) - __builtin_clzl( fd_ulong_if( c, xl, xh ) )`.
    - The `fd_ulong_if` function is used to select between `xl` and `xh` based on the value of `c`.
- **Output**: The function returns an integer representing the index of the most significant bit set in the 128-bit unsigned integer `x`.


---
### fd\_uchar\_find\_msb\_w\_default<!-- {{#callable:fd_uchar_find_msb_w_default}} -->
The `fd_uchar_find_msb_w_default` function returns the most significant bit position of an unsigned char, or a default value if the input is zero.
- **Inputs**:
    - `x`: An unsigned char whose most significant bit position is to be found.
    - `d`: An integer representing the default value to return if the input `x` is zero.
- **Control Flow**:
    - Check if the input `x` is zero.
    - If `x` is zero, return the default value `d`.
    - If `x` is not zero, call the [`fd_uchar_find_msb`](#fd_uchar_find_msb) function to find and return the most significant bit position of `x`.
- **Output**: Returns an integer representing the most significant bit position of `x`, or the default value `d` if `x` is zero.
- **Functions called**:
    - [`fd_uchar_find_msb`](#fd_uchar_find_msb)


---
### fd\_ushort\_find\_msb\_w\_default<!-- {{#callable:fd_ushort_find_msb_w_default}} -->
The `fd_ushort_find_msb_w_default` function returns the most significant bit position of a `ushort` integer, or a default value if the integer is zero.
- **Inputs**:
    - `x`: A `ushort` integer whose most significant bit position is to be found.
    - `d`: An integer representing the default value to return if `x` is zero.
- **Control Flow**:
    - Check if `x` is zero.
    - If `x` is zero, return the default value `d`.
    - If `x` is not zero, call `fd_ushort_find_msb(x)` to find and return the most significant bit position of `x`.
- **Output**: Returns an integer representing the most significant bit position of `x`, or `d` if `x` is zero.
- **Functions called**:
    - [`fd_ushort_find_msb`](#fd_ushort_find_msb)


---
### fd\_uint\_find\_msb\_w\_default<!-- {{#callable:fd_uint_find_msb_w_default}} -->
The `fd_uint_find_msb_w_default` function returns the most significant bit position of a given unsigned integer, or a default value if the integer is zero.
- **Inputs**:
    - `x`: An unsigned integer (`uint`) whose most significant bit position is to be found.
    - `d`: An integer representing the default value to return if `x` is zero.
- **Control Flow**:
    - Check if the input `x` is zero.
    - If `x` is zero, return the default value `d`.
    - If `x` is not zero, call the [`fd_uint_find_msb`](#fd_uint_find_msb) function to find and return the most significant bit position of `x`.
- **Output**: An integer representing the most significant bit position of `x`, or the default value `d` if `x` is zero.
- **Functions called**:
    - [`fd_uint_find_msb`](#fd_uint_find_msb)


---
### fd\_ulong\_find\_msb\_w\_default<!-- {{#callable:fd_ulong_find_msb_w_default}} -->
The `fd_ulong_find_msb_w_default` function returns the most significant bit position of an unsigned long integer, or a default value if the integer is zero.
- **Inputs**:
    - `x`: An unsigned long integer whose most significant bit position is to be found.
    - `d`: An integer representing the default value to return if `x` is zero.
- **Control Flow**:
    - Check if the input `x` is zero.
    - If `x` is zero, return the default value `d`.
    - If `x` is not zero, call `fd_ulong_find_msb(x)` to find and return the most significant bit position of `x`.
- **Output**: Returns an integer representing the most significant bit position of `x`, or `d` if `x` is zero.
- **Functions called**:
    - [`fd_ulong_find_msb`](#fd_ulong_find_msb)


---
### fd\_uint128\_find\_msb\_w\_default<!-- {{#callable:fd_uint128_find_msb_w_default}} -->
The `fd_uint128_find_msb_w_default` function returns the most significant bit position of a 128-bit unsigned integer, or a default value if the integer is zero.
- **Inputs**:
    - `x`: A 128-bit unsigned integer whose most significant bit position is to be found.
    - `d`: An integer representing the default value to return if the input `x` is zero.
- **Control Flow**:
    - Check if the input `x` is zero.
    - If `x` is zero, return the default value `d`.
    - If `x` is not zero, call the [`fd_uint128_find_msb`](#fd_uint128_find_msb) function to find and return the most significant bit position of `x`.
- **Output**: An integer representing the most significant bit position of `x`, or the default value `d` if `x` is zero.
- **Functions called**:
    - [`fd_uint128_find_msb`](#fd_uint128_find_msb)



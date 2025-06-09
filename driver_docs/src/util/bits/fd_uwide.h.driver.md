# Purpose
The provided C header file, `fd_uwide.h`, defines a set of operations for handling 128-bit unsigned integer arithmetic on platforms that do not natively support 128-bit wide integers. The file achieves this by representing a 128-bit number as a pair of 64-bit unsigned long integers (`ulong`). The operations include addition, subtraction, multiplication, division, and bitwise shifts, all tailored to work with this dual-`ulong` representation. The functions are implemented as inline static functions, which suggests they are intended for use within a larger codebase where performance is critical, as inlining can reduce function call overhead.

The file provides a comprehensive suite of arithmetic operations, including functions for addition (`fd_uwide_add`), subtraction (`fd_uwide_sub`), multiplication (`fd_uwide_mul`), and division (`fd_uwide_div` and `fd_uwide_divrem`). It also includes utility functions for incrementing and decrementing (`fd_uwide_inc` and `fd_uwide_dec`), finding the most significant bit ([`fd_uwide_find_msb`](#fd_uwide_find_msb)), and performing bitwise shifts (`fd_uwide_sl` and `fd_uwide_sr`). The division functions are particularly detailed, employing approximation techniques to handle division efficiently. The file is structured to be included in other C source files, providing a robust API for 128-bit arithmetic operations, and is likely part of a larger library focused on high-performance computing or cryptographic applications where such precision is necessary.
# Imports and Dependencies

---
- `fd_bits.h`


# Global Variables

---
### fd\_uwide\_add
- **Type**: `static inline ulong`
- **Description**: The `fd_uwide_add` function is a static inline function that performs addition on two 128-bit unsigned integers, represented as pairs of 64-bit unsigned long integers. It computes the sum of two such 128-bit numbers along with an optional carry-in, and returns the carry-out from the addition.
- **Use**: This function is used to perform precise 128-bit addition on platforms that do not support native 128-bit integer operations.


---
### fd\_uwide\_inc
- **Type**: `function`
- **Description**: The `fd_uwide_inc` function is a static inline function designed to perform an increment operation on a 128-bit unsigned integer represented by two 64-bit unsigned long integers (`ulong`). It takes two pointers to `ulong` for the high and low parts of the result, two `ulong` values representing the high and low parts of the input number, and a `ulong` value to increment by. The function calculates the incremented value and stores the result in the provided pointers.
- **Use**: This function is used to increment a 128-bit unsigned integer by a 64-bit unsigned integer, updating the result in the provided high and low part pointers.


---
### fd\_uwide\_sub
- **Type**: `function`
- **Description**: `fd_uwide_sub` is a static inline function that performs subtraction on two 128-bit unsigned integers, represented as pairs of 64-bit unsigned long integers. It computes the result of subtracting one 128-bit integer from another, taking into account a borrow input, and returns the borrow out.
- **Use**: This function is used to perform precise subtraction of large integers on platforms that do not support native 128-bit arithmetic.


---
### fd\_uwide\_dec
- **Type**: `function`
- **Description**: The `fd_uwide_dec` function is a static inline function designed to perform subtraction on a 128-bit unsigned integer represented as two 64-bit unsigned long integers (`ulong`). It computes the result of subtracting a 64-bit unsigned integer `y` from a 128-bit integer `<xh, xl>`, where `xh` and `xl` are the high and low parts of the 128-bit integer, respectively. The result is stored in the memory locations pointed to by `_zh` and `_zl`, which represent the high and low parts of the resulting 128-bit integer.
- **Use**: This function is used to perform precise subtraction of a 64-bit integer from a 128-bit integer, updating the result in the provided memory locations.


---
### fd\_uwide\_mul
- **Type**: `function`
- **Description**: The `fd_uwide_mul` function is a static inline function that computes the exact product of two unsigned long integers, `x` and `y`, and stores the result as a 128-bit wide integer represented by two unsigned long integers, `_zh` and `_zl`. This function is designed to handle multiplication on platforms that do not support 128-bit wide integers natively.
- **Use**: This function is used to perform precise multiplication of two 64-bit integers, storing the result in a 128-bit format.


---
### fd\_uwide\_sl
- **Type**: `function`
- **Description**: The `fd_uwide_sl` function is a static inline function that performs a left shift operation on a 128-bit unsigned integer represented by two 64-bit unsigned long integers (`xh` and `xl`). It shifts the combined 128-bit value by `s` bits and stores the result in `_zh` and `_zl`. The function also returns an inexact flag indicating if any non-zero bits were lost during the shift.
- **Use**: This function is used to perform left shift operations on 128-bit integers, handling cases where the shift amount is large and ensuring that the result is stored correctly in the provided pointers.


---
### fd\_uwide\_sr
- **Type**: `function`
- **Description**: The `fd_uwide_sr` function is a static inline function that performs a right shift operation on a 128-bit unsigned integer represented by two 64-bit unsigned long integers (`xh` and `xl`). It shifts the combined 128-bit value to the right by `s` bits and stores the result in the locations pointed to by `_zh` and `_zl`. The function also returns an inexact flag indicating if any non-zero bits were lost during the shift.
- **Use**: This function is used to perform right shift operations on 128-bit integers, which are represented as two 64-bit parts, and to check if any significant bits are lost in the process.


---
### fd\_uwide\_div
- **Type**: `function`
- **Description**: The `fd_uwide_div` function is a static function that performs division of a 128-bit unsigned integer, represented as two 64-bit unsigned long integers (`xh` and `xl`), by a 64-bit unsigned long integer (`y`). It computes the quotient, storing the high and low parts of the result in the pointers `_zh` and `_zl`, respectively. The function handles special cases such as division by zero and optimizes for cases where the divisor is a power of two.
- **Use**: This function is used to perform division of large unsigned integers on platforms that do not support 128-bit wide integer operations natively.


---
### fd\_uwide\_divrem
- **Type**: `function`
- **Description**: The `fd_uwide_divrem` function is a static inline function that performs division of a 128-bit unsigned integer, represented by two 64-bit unsigned long integers (`xh` and `xl`), by a 64-bit unsigned long integer (`y`). It calculates both the quotient and the remainder of the division. If `y` is zero, it returns a remainder of `ULONG_MAX` to signal an error.
- **Use**: This function is used to compute both the quotient and remainder of a division operation on a 128-bit unsigned integer divided by a 64-bit unsigned integer.


# Functions

---
### fd\_uwide\_find\_msb<!-- {{#callable:fd_uwide_find_msb}} -->
The `fd_uwide_find_msb` function calculates the most significant bit position of a 128-bit unsigned integer represented by two 64-bit unsigned long integers.
- **Inputs**:
    - `xh`: The high 64 bits of the 128-bit unsigned integer.
    - `xl`: The low 64 bits of the 128-bit unsigned integer.
- **Control Flow**:
    - Initialize an integer `off` to 0.
    - Check if `xh` is non-zero; if true, set `off` to 64 and assign `xh` to `xl`.
    - Return the sum of `off` and the result of `fd_ulong_find_msb(xl)`, which finds the most significant bit of `xl`.
- **Output**: The function returns an integer representing the position of the most significant bit in the 128-bit unsigned integer.
- **Functions called**:
    - [`fd_ulong_find_msb`](fd_bits_find_msb.h.driver.md#fd_ulong_find_msb)


---
### fd\_uwide\_find\_msb\_def<!-- {{#callable:fd_uwide_find_msb_def}} -->
The `fd_uwide_find_msb_def` function returns the most significant bit position of a 128-bit unsigned integer represented by two `ulong` values, or a default value if the integer is zero.
- **Inputs**:
    - `xh`: The high 64 bits of the 128-bit unsigned integer.
    - `xl`: The low 64 bits of the 128-bit unsigned integer.
    - `def`: The default value to return if the 128-bit integer is zero.
- **Control Flow**:
    - The function checks if either `xh` or `xl` is non-zero using a bitwise OR operation.
    - If the result of the OR operation is non-zero, it calls `fd_uwide_find_msb(xh, xl)` to find the most significant bit position.
    - If the result of the OR operation is zero, it returns the `def` value.
- **Output**: The function returns an integer representing the most significant bit position of the 128-bit integer, or the default value if the integer is zero.
- **Functions called**:
    - [`fd_uwide_find_msb`](#fd_uwide_find_msb)


---
### fd\_uwide\_private\_div\_approx\_init<!-- {{#callable:fd_uwide_private_div_approx_init}} -->
The function `fd_uwide_private_div_approx_init` computes an approximation factor for division of a 128-bit wide integer by a divisor in the range [2^63, 2^64).
- **Inputs**:
    - `d`: An unsigned long integer representing the divisor, which is in the range [2^63, 2^64).
- **Control Flow**:
    - Calculate m as the upper 32 bits of d plus 1, ensuring m is in the range (2^31, 2^32].
    - Compute the result as the integer division of -m by m, subtracting UINT_MAX to adjust the range, resulting in an approximation factor for division.
- **Output**: The function returns an unsigned long integer that serves as an approximation factor for division, which is in the range [0, 2^32).


---
### fd\_uwide\_private\_div\_approx<!-- {{#callable:fd_uwide_private_div_approx}} -->
The `fd_uwide_private_div_approx` function computes an approximate quotient of a 128-bit division operation, specifically for cases where the dividend is less than the divisor.
- **Inputs**:
    - `n`: An unsigned long integer representing the dividend, which is in the range [0, d).
    - `m`: An unsigned long integer, which is the output of `fd_uwide_private_div_approx_init` for the desired divisor `d`.
- **Control Flow**:
    - The function begins by extracting the high 32 bits of `n` into `nh` and the low 32 bits into `nl`.
    - It calculates the approximate quotient by adding `n`, `nh` multiplied by `m`, and the result of `nl` multiplied by `m` right-shifted by 32 bits.
    - The function returns the computed approximate quotient.
- **Output**: The function returns an unsigned long integer that is an approximation of the quotient, which is in the range [n, 2^64) and less than or equal to the floor of (n * 2^64 / d).



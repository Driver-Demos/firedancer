# Purpose
This C header file provides a robust and portable implementation of integer square root functions for various integer types, including unsigned and signed integers of different widths. The primary functionality is to compute the floor of the square root of a given integer, ensuring exact results without overflow issues. The implementation is based on a fixed-point iteration method that efficiently converges to the correct integer square root. The file includes functions for unsigned integers ([`fd_uint_sqrt`](#fd_uint_sqrt), [`fd_ulong_sqrt`](#fd_ulong_sqrt)) and their signed counterparts ([`fd_schar_sqrt`](#fd_schar_sqrt), [`fd_short_sqrt`](#fd_short_sqrt), [`fd_int_sqrt`](#fd_int_sqrt), [`fd_long_sqrt`](#fd_long_sqrt)), as well as variations that handle absolute values and real parts of square roots for signed integers.

The file is structured to handle different integer widths and types, including optimizations for platforms that support 128-bit integers. It uses a combination of lookup tables for small values and iterative methods for larger values, ensuring both performance and accuracy. The header file is designed to be included in other C programs, providing a set of inline functions that can be used to calculate integer square roots across various data types. The functions are defined with `FD_FN_CONST` to suggest that they are pure functions, meaning their return value is determined only by their input values, which can help with compiler optimizations.
# Imports and Dependencies

---
- `../bits/fd_bits.h`


# Functions

---
### fd\_uint\_sqrt<!-- {{#callable:fd_uint_sqrt}} -->
The `fd_uint_sqrt` function computes the floor of the square root of an unsigned integer using a fixed-point iteration method.
- **Inputs**:
    - `x`: An unsigned integer for which the floor of the square root is to be calculated.
- **Control Flow**:
    - If x is less than 21, a precomputed value from a lookup table is returned.
    - Find the most significant bit (MSB) of x to determine an initial guess for y.
    - Convert y and x to unsigned long for wider arithmetic operations.
    - Iteratively compute a new y using the formula (_y*_y + _y + _x) / ((_y<<1)+1UL) until convergence is reached (i.e., when the new y equals the old y).
    - Return the converged value of y as the result.
- **Output**: The function returns an unsigned integer representing the floor of the square root of the input x.


---
### fd\_ulong\_sqrt<!-- {{#callable:fd_ulong_sqrt}} -->
The `fd_ulong_sqrt` function computes the integer square root of an unsigned long integer using a fixed-point iteration method.
- **Inputs**:
    - `x`: An unsigned long integer for which the integer square root is to be calculated.
- **Control Flow**:
    - Check if x is less than 21; if so, return a precomputed value from a lookup table.
    - Find the most significant bit (MSB) of x using `fd_ulong_find_msb`.
    - Initialize y based on whether the MSB is odd or even, using a fixed-point approximation.
    - Enter a loop to iteratively refine y using a fixed-point iteration method until convergence.
    - In each iteration, calculate d as 2*y + 1, and compute partial quotients and remainders for x and y.
    - Combine the partial results and adjust for any carry.
    - Check for convergence by comparing y with the newly computed value; if they are equal, break the loop.
    - Return the converged value of y as the integer square root of x.
- **Output**: The function returns the integer square root of the input unsigned long integer x.


---
### fd\_uchar\_sqrt<!-- {{#callable:fd_uchar_sqrt}} -->
The `fd_uchar_sqrt` function computes the integer square root of an unsigned char by casting it to an unsigned int and using the [`fd_uint_sqrt`](#fd_uint_sqrt) function.
- **Inputs**:
    - `x`: An unsigned char representing the number for which the integer square root is to be calculated.
- **Control Flow**:
    - The function casts the input `x` from an unsigned char to an unsigned int.
    - It calls the [`fd_uint_sqrt`](#fd_uint_sqrt) function with the casted value to compute the integer square root.
    - The result from [`fd_uint_sqrt`](#fd_uint_sqrt) is cast back to an unsigned char and returned.
- **Output**: The function returns the integer square root of the input `x` as an unsigned char.
- **Functions called**:
    - [`fd_uint_sqrt`](#fd_uint_sqrt)


---
### fd\_ushort\_sqrt<!-- {{#callable:fd_ushort_sqrt}} -->
The `fd_ushort_sqrt` function calculates the integer square root of an unsigned short integer by leveraging the [`fd_uint_sqrt`](#fd_uint_sqrt) function.
- **Inputs**:
    - `x`: An unsigned short integer for which the integer square root is to be calculated.
- **Control Flow**:
    - The function casts the input `x` from `ushort` to `uint`.
    - It calls the [`fd_uint_sqrt`](#fd_uint_sqrt) function with the casted value to compute the integer square root.
    - The result from [`fd_uint_sqrt`](#fd_uint_sqrt) is cast back to `ushort` and returned.
- **Output**: The function returns the integer square root of the input `x` as an unsigned short integer.
- **Functions called**:
    - [`fd_uint_sqrt`](#fd_uint_sqrt)


---
### fd\_schar\_sqrt<!-- {{#callable:fd_schar_sqrt}} -->
The `fd_schar_sqrt` function computes the floor of the square root of a signed char integer by casting it to an unsigned char and using the [`fd_uchar_sqrt`](#fd_uchar_sqrt) function.
- **Inputs**:
    - `x`: A signed char integer whose square root is to be computed.
- **Control Flow**:
    - The function casts the signed char input `x` to an unsigned char.
    - It calls the [`fd_uchar_sqrt`](#fd_uchar_sqrt) function with the casted unsigned char value.
    - The result from [`fd_uchar_sqrt`](#fd_uchar_sqrt) is cast back to a signed char and returned.
- **Output**: The function returns a signed char representing the floor of the square root of the input value.
- **Functions called**:
    - [`fd_uchar_sqrt`](#fd_uchar_sqrt)


---
### fd\_short\_sqrt<!-- {{#callable:fd_short_sqrt}} -->
The `fd_short_sqrt` function computes the integer square root of a given short integer by converting it to an unsigned short and using the [`fd_ushort_sqrt`](#fd_ushort_sqrt) function.
- **Inputs**:
    - `x`: A short integer for which the integer square root is to be calculated.
- **Control Flow**:
    - The function takes a short integer `x` as input.
    - It casts `x` to an unsigned short integer.
    - It calls the [`fd_ushort_sqrt`](#fd_ushort_sqrt) function with the casted value to compute the integer square root.
    - The result from [`fd_ushort_sqrt`](#fd_ushort_sqrt) is cast back to a short integer and returned.
- **Output**: The function returns the integer square root of the input short integer `x`, cast as a short.
- **Functions called**:
    - [`fd_ushort_sqrt`](#fd_ushort_sqrt)


---
### fd\_int\_sqrt<!-- {{#callable:fd_int_sqrt}} -->
The `fd_int_sqrt` function computes the integer square root of a given integer by converting it to an unsigned integer and using the [`fd_uint_sqrt`](#fd_uint_sqrt) function.
- **Inputs**:
    - `x`: An integer value for which the integer square root is to be calculated.
- **Control Flow**:
    - The function casts the input integer `x` to an unsigned integer type `uint`.
    - It calls the [`fd_uint_sqrt`](#fd_uint_sqrt) function with the casted unsigned integer value.
    - The result from [`fd_uint_sqrt`](#fd_uint_sqrt) is cast back to an integer and returned.
- **Output**: The function returns the integer square root of the input `x`, which is the largest integer `y` such that `y*y <= x`.
- **Functions called**:
    - [`fd_uint_sqrt`](#fd_uint_sqrt)


---
### fd\_long\_sqrt<!-- {{#callable:fd_long_sqrt}} -->
The `fd_long_sqrt` function computes the floor of the square root of a given long integer.
- **Inputs**:
    - `x`: A long integer for which the floor of the square root is to be calculated.
- **Control Flow**:
    - The function casts the input long integer `x` to an unsigned long integer.
    - It calls the [`fd_ulong_sqrt`](#fd_ulong_sqrt) function with the casted value to compute the floor of the square root.
    - The result from [`fd_ulong_sqrt`](#fd_ulong_sqrt) is cast back to a long integer and returned.
- **Output**: The function returns a long integer representing the floor of the square root of the input value.
- **Functions called**:
    - [`fd_ulong_sqrt`](#fd_ulong_sqrt)


---
### fd\_schar\_re\_sqrt<!-- {{#callable:fd_schar_re_sqrt}} -->
The `fd_schar_re_sqrt` function computes the floor of the real square root of a signed char, returning zero for non-positive inputs.
- **Inputs**:
    - `x`: A signed char (schar) input for which the real square root is to be computed.
- **Control Flow**:
    - The function checks if the input `x` is greater than zero.
    - If `x` is positive, it computes the square root using [`fd_uchar_sqrt`](#fd_uchar_sqrt) after casting `x` to an unsigned char (uchar).
    - If `x` is not positive, it returns zero.
- **Output**: The function returns a signed char (schar) which is the floor of the square root of `x` if `x` is positive, otherwise it returns zero.
- **Functions called**:
    - [`fd_uchar_sqrt`](#fd_uchar_sqrt)


---
### fd\_short\_re\_sqrt<!-- {{#callable:fd_short_re_sqrt}} -->
The `fd_short_re_sqrt` function computes the floor of the real square root of a short integer, returning zero for non-positive inputs.
- **Inputs**:
    - `x`: A short integer input for which the floor of the real square root is to be computed.
- **Control Flow**:
    - The function checks if the input `x` is greater than zero.
    - If `x` is positive, it computes the floor of the square root of `x` using [`fd_ushort_sqrt`](#fd_ushort_sqrt) after casting `x` to an unsigned short.
    - If `x` is not positive, it returns zero.
- **Output**: The function returns a short integer representing the floor of the real square root of `x` if `x` is positive, otherwise it returns zero.
- **Functions called**:
    - [`fd_ushort_sqrt`](#fd_ushort_sqrt)


---
### fd\_int\_re\_sqrt<!-- {{#callable:fd_int_re_sqrt}} -->
The `fd_int_re_sqrt` function computes the floor of the square root of a non-negative integer, returning zero for negative inputs.
- **Inputs**:
    - `x`: An integer input for which the function computes the floor of the square root if it is non-negative.
- **Control Flow**:
    - The function checks if the input integer `x` is greater than zero.
    - If `x` is greater than zero, it computes the floor of the square root of `x` using the [`fd_uint_sqrt`](#fd_uint_sqrt) function after casting `x` to an unsigned integer.
    - If `x` is not greater than zero, the function returns zero.
- **Output**: The function returns an integer which is the floor of the square root of `x` if `x` is positive, otherwise it returns zero.
- **Functions called**:
    - [`fd_uint_sqrt`](#fd_uint_sqrt)


---
### fd\_long\_re\_sqrt<!-- {{#callable:fd_long_re_sqrt}} -->
The `fd_long_re_sqrt` function computes the floor of the square root of a given long integer if it is positive, otherwise it returns zero.
- **Inputs**:
    - `x`: A long integer input for which the function computes the floor of the square root if positive.
- **Control Flow**:
    - The function checks if the input `x` is greater than 0.
    - If `x` is greater than 0, it computes the square root using [`fd_ulong_sqrt`](#fd_ulong_sqrt) after casting `x` to an unsigned long.
    - If `x` is not greater than 0, it returns 0.
- **Output**: The function returns a long integer which is the floor of the square root of `x` if `x` is positive, otherwise it returns 0.
- **Functions called**:
    - [`fd_ulong_sqrt`](#fd_ulong_sqrt)


---
### fd\_schar\_sqrt\_abs<!-- {{#callable:fd_schar_sqrt_abs}} -->
The function `fd_schar_sqrt_abs` computes the floor of the square root of the absolute value of a signed char integer.
- **Inputs**:
    - `x`: A signed char integer whose absolute value's square root is to be computed.
- **Control Flow**:
    - The function first computes the absolute value of the input `x` using `fd_schar_abs(x)`.
    - It then calculates the square root of this absolute value using [`fd_uchar_sqrt`](#fd_uchar_sqrt).
    - The result is cast back to a signed char and returned.
- **Output**: The function returns a signed char representing the floor of the square root of the absolute value of the input.
- **Functions called**:
    - [`fd_uchar_sqrt`](#fd_uchar_sqrt)


---
### fd\_short\_sqrt\_abs<!-- {{#callable:fd_short_sqrt_abs}} -->
The `fd_short_sqrt_abs` function computes the floor of the square root of the absolute value of a given short integer.
- **Inputs**:
    - `x`: A short integer whose absolute value's square root is to be computed.
- **Control Flow**:
    - The function first computes the absolute value of the input short integer `x` using `fd_short_abs(x)`.
    - It then calculates the square root of this absolute value using `fd_ushort_sqrt()`.
    - The result is cast back to a short integer and returned.
- **Output**: A short integer representing the floor of the square root of the absolute value of the input.
- **Functions called**:
    - [`fd_ushort_sqrt`](#fd_ushort_sqrt)


---
### fd\_int\_sqrt\_abs<!-- {{#callable:fd_int_sqrt_abs}} -->
The `fd_int_sqrt_abs` function computes the integer square root of the absolute value of a given integer.
- **Inputs**:
    - `x`: An integer whose absolute value's integer square root is to be calculated.
- **Control Flow**:
    - The function first computes the absolute value of the input integer `x` using `fd_int_abs(x)`.
    - It then calculates the integer square root of this absolute value using `fd_uint_sqrt()`.
    - The result is cast to an integer and returned.
- **Output**: The function returns the integer square root of the absolute value of the input integer `x`.
- **Functions called**:
    - [`fd_uint_sqrt`](#fd_uint_sqrt)


---
### fd\_long\_sqrt\_abs<!-- {{#callable:fd_long_sqrt_abs}} -->
The `fd_long_sqrt_abs` function computes the floor of the square root of the absolute value of a given long integer.
- **Inputs**:
    - `x`: A long integer whose absolute value's square root is to be computed.
- **Control Flow**:
    - The function first computes the absolute value of the input `x` using `fd_long_abs(x)`.
    - It then calculates the square root of this absolute value using `fd_ulong_sqrt()`, which is designed to handle unsigned long integers.
    - Finally, the result is cast back to a long integer and returned.
- **Output**: The function returns a long integer representing the floor of the square root of the absolute value of the input.
- **Functions called**:
    - [`fd_ulong_sqrt`](#fd_ulong_sqrt)



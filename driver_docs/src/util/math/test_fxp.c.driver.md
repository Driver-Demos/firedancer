# Purpose
This C source code file is designed to perform and test fixed-point arithmetic operations using 128-bit integers, specifically focusing on addition, subtraction, multiplication, division, and square root calculations. The file includes a series of inline functions that implement these operations with various rounding modes, such as round-toward-zero, round-away-from-zero, and round-to-nearest, among others. The code is structured to handle edge cases and stress test the limits of these operations by generating random bit patterns with specific characteristics. The file also includes functions for logarithmic and exponential calculations, with different implementations depending on the availability of double precision support.

The main function serves as a comprehensive test suite for these fixed-point arithmetic operations. It initializes a random number generator and iteratively tests each arithmetic function against its reference implementation to ensure accuracy and consistency. The tests are designed to log errors if discrepancies are found, and they also measure the unit in the last place (ULP) differences for approximation functions. The code is conditionally compiled based on the availability of 128-bit integer support, ensuring that it only runs on compatible systems. This file is primarily intended for internal testing and validation of fixed-point arithmetic operations rather than being a public API or library for external use.
# Imports and Dependencies

---
- `../fd_util.h`
- `fd_fxp.h`
- `math.h`


# Functions

---
### make\_rand\_fxp<!-- {{#callable:make_rand_fxp}} -->
The `make_rand_fxp` function generates a random fixed-point number by manipulating a 64-bit input based on control bits that determine shift, direction, and inversion operations.
- **Inputs**:
    - `x`: A 64-bit unsigned long integer representing the initial random value to be manipulated.
    - `_ctl`: A pointer to an unsigned integer that contains control bits used to determine the operations on the input value.
- **Control Flow**:
    - Retrieve the control bits from the location pointed to by `_ctl` and store them in a local variable `ctl`.
    - Extract the shift amount `s` from the least significant 6 bits of `ctl`, then right-shift `ctl` by 6 bits.
    - Extract the direction `d` from the least significant bit of `ctl`, then right-shift `ctl` by 1 bit.
    - Extract the invert flag `i` from the least significant bit of `ctl`, then right-shift `ctl` by 1 bit.
    - Update the value pointed to by `_ctl` with the modified `ctl`.
    - Shift the input `x` left by `s` bits if `d` is 1, otherwise shift `x` right by `s` bits.
    - Invert the bits of `x` if `i` is 1, otherwise leave `x` unchanged.
    - Return the final manipulated value of `x`.
- **Output**: The function returns a 64-bit unsigned long integer that is the result of the random manipulations applied to the input `x`.


---
### split\_hi<!-- {{#callable:split_hi}} -->
The `split_hi` function extracts the higher 64 bits from a 128-bit unsigned integer and returns it as a 64-bit unsigned integer.
- **Inputs**:
    - `x`: A 128-bit unsigned integer (`uint128`) from which the higher 64 bits are to be extracted.
- **Control Flow**:
    - The function takes a 128-bit unsigned integer `x` as input.
    - It performs a right bitwise shift of 64 positions on `x`, effectively moving the higher 64 bits to the lower 64-bit position.
    - The result of the shift is cast to a 64-bit unsigned integer (`ulong`) and returned.
- **Output**: A 64-bit unsigned integer (`ulong`) representing the higher 64 bits of the input 128-bit unsigned integer.


---
### split\_lo<!-- {{#callable:split_lo}} -->
The `split_lo` function extracts the lower 64 bits from a 128-bit unsigned integer.
- **Inputs**:
    - `x`: A 128-bit unsigned integer (`uint128`) from which the lower 64 bits are to be extracted.
- **Control Flow**:
    - The function takes a 128-bit unsigned integer `x` as input.
    - It casts `x` to a 64-bit unsigned long integer (`ulong`), effectively extracting the lower 64 bits of `x`.
- **Output**: The function returns the lower 64 bits of the input 128-bit unsigned integer as a 64-bit unsigned long integer (`ulong`).


---
### fd\_fxp\_add\_ref<!-- {{#callable:fd_fxp_add_ref}} -->
The `fd_fxp_add_ref` function performs addition of two unsigned long integers with 128-bit precision and returns the lower 64 bits of the result while storing the upper 64 bits in a provided pointer.
- **Inputs**:
    - `x`: An unsigned long integer representing the first operand for addition.
    - `y`: An unsigned long integer representing the second operand for addition.
    - `_c`: A pointer to an unsigned long integer where the upper 64 bits of the result will be stored.
- **Control Flow**:
    - Convert both input operands `x` and `y` to 128-bit integers.
    - Perform the addition of the two 128-bit integers.
    - Store the upper 64 bits of the result in the location pointed to by `_c` using the [`split_hi`](#split_hi) function.
    - Return the lower 64 bits of the result using the [`split_lo`](#split_lo) function.
- **Output**: The function returns the lower 64 bits of the 128-bit addition result as an unsigned long integer.
- **Functions called**:
    - [`split_hi`](#split_hi)
    - [`split_lo`](#split_lo)


---
### fd\_fxp\_sub\_ref<!-- {{#callable:fd_fxp_sub_ref}} -->
The `fd_fxp_sub_ref` function performs subtraction of two unsigned long integers with borrow handling and returns the lower 64 bits of the result.
- **Inputs**:
    - `x`: The minuend, an unsigned long integer.
    - `y`: The subtrahend, an unsigned long integer.
    - `_b`: A pointer to an unsigned long where the borrow flag will be stored.
- **Control Flow**:
    - Calculate the borrow flag `b` by checking if `x` is less than `y` and cast it to an unsigned long.
    - Perform the subtraction using 128-bit arithmetic: `z = (((uint128)b)<<64) + ((uint128)x) - ((uint128)y)`.
    - Store the borrow flag `b` in the location pointed to by `_b`.
    - Return the lower 64 bits of the result `z` using the [`split_lo`](#split_lo) function.
- **Output**: The function returns the lower 64 bits of the 128-bit result of the subtraction.
- **Functions called**:
    - [`split_lo`](#split_lo)


---
### fd\_fxp\_mul\_rtz\_ref<!-- {{#callable:fd_fxp_mul_rtz_ref}} -->
The `fd_fxp_mul_rtz_ref` function performs a fixed-point multiplication of two unsigned long integers, right-truncates the result by 30 bits, and returns the lower 64 bits while storing the upper 64 bits in a provided pointer.
- **Inputs**:
    - `x`: An unsigned long integer representing the first operand for multiplication.
    - `y`: An unsigned long integer representing the second operand for multiplication.
    - `_c`: A pointer to an unsigned long where the upper 64 bits of the result will be stored.
- **Control Flow**:
    - The function casts the input operands `x` and `y` to `uint128` and multiplies them, storing the result in `z`.
    - The result `z` is right-shifted by 30 bits to truncate the lower bits.
    - The upper 64 bits of the truncated result are stored in the location pointed to by `_c` using the [`split_hi`](#split_hi) function.
    - The function returns the lower 64 bits of the truncated result using the [`split_lo`](#split_lo) function.
- **Output**: The function returns the lower 64 bits of the 128-bit result after right-truncating by 30 bits.
- **Functions called**:
    - [`split_hi`](#split_hi)
    - [`split_lo`](#split_lo)


---
### fd\_fxp\_mul\_raz\_ref<!-- {{#callable:fd_fxp_mul_raz_ref}} -->
The `fd_fxp_mul_raz_ref` function performs fixed-point multiplication of two unsigned long integers with rounding towards zero and stores the high part of the result in a provided pointer.
- **Inputs**:
    - `x`: An unsigned long integer representing the first operand for multiplication.
    - `y`: An unsigned long integer representing the second operand for multiplication.
    - `_c`: A pointer to an unsigned long integer where the high part of the result will be stored.
- **Control Flow**:
    - The function casts the input operands `x` and `y` to `uint128` and multiplies them.
    - It adds a constant value `(1UL<<30)-1UL` to the product to facilitate rounding towards zero.
    - The result is right-shifted by 30 bits to adjust the fixed-point position.
    - The high part of the result is extracted using [`split_hi`](#split_hi) and stored in the location pointed to by `_c`.
    - The low part of the result is extracted using [`split_lo`](#split_lo) and returned as the function's output.
- **Output**: The function returns the low part of the 128-bit result of the multiplication, right-shifted by 30 bits.
- **Functions called**:
    - [`split_hi`](#split_hi)
    - [`split_lo`](#split_lo)


---
### fd\_fxp\_mul\_rnz\_ref<!-- {{#callable:fd_fxp_mul_rnz_ref}} -->
The `fd_fxp_mul_rnz_ref` function performs a fixed-point multiplication of two unsigned long integers with rounding towards the nearest zero and returns the lower 64 bits of the result while storing the higher 64 bits in a provided pointer.
- **Inputs**:
    - `x`: An unsigned long integer representing the first operand for multiplication.
    - `y`: An unsigned long integer representing the second operand for multiplication.
    - `_c`: A pointer to an unsigned long integer where the higher 64 bits of the result will be stored.
- **Control Flow**:
    - The function casts the input operands `x` and `y` to `uint128` and multiplies them.
    - It adds a constant value of `(1UL<<29)-1UL` to the product to facilitate rounding towards the nearest zero.
    - The result is right-shifted by 30 bits to adjust the fixed-point position.
    - The higher 64 bits of the result are extracted using [`split_hi`](#split_hi) and stored in the location pointed to by `_c`.
    - The lower 64 bits of the result are extracted using [`split_lo`](#split_lo) and returned as the function's output.
- **Output**: The function returns the lower 64 bits of the fixed-point multiplication result as an unsigned long integer.
- **Functions called**:
    - [`split_hi`](#split_hi)
    - [`split_lo`](#split_lo)


---
### fd\_fxp\_mul\_rna\_ref<!-- {{#callable:fd_fxp_mul_rna_ref}} -->
The `fd_fxp_mul_rna_ref` function performs fixed-point multiplication of two unsigned long integers with rounding to the nearest even integer and returns the lower 64 bits of the result, while storing the higher 64 bits in a provided pointer.
- **Inputs**:
    - `x`: An unsigned long integer representing the first operand for multiplication.
    - `y`: An unsigned long integer representing the second operand for multiplication.
    - `_c`: A pointer to an unsigned long integer where the higher 64 bits of the result will be stored.
- **Control Flow**:
    - The function casts the input operands `x` and `y` to `uint128` and multiplies them.
    - It adds `1UL<<29` to the product to facilitate rounding to the nearest even integer.
    - The result is right-shifted by 30 bits to adjust the fixed-point position.
    - The higher 64 bits of the result are extracted using [`split_hi`](#split_hi) and stored in the location pointed to by `_c`.
    - The lower 64 bits of the result are extracted using [`split_lo`](#split_lo) and returned as the function's output.
- **Output**: The function returns the lower 64 bits of the fixed-point multiplication result as an unsigned long integer.
- **Functions called**:
    - [`split_hi`](#split_hi)
    - [`split_lo`](#split_lo)


---
### fd\_fxp\_mul\_rne\_ref<!-- {{#callable:fd_fxp_mul_rne_ref}} -->
The `fd_fxp_mul_rne_ref` function performs fixed-point multiplication of two unsigned long integers with rounding to the nearest even integer and returns the lower 64 bits of the result, while storing the upper 64 bits in a provided pointer.
- **Inputs**:
    - `x`: An unsigned long integer representing the first operand for multiplication.
    - `y`: An unsigned long integer representing the second operand for multiplication.
    - `_c`: A pointer to an unsigned long where the upper 64 bits of the result will be stored.
- **Control Flow**:
    - The function begins by casting the inputs `x` and `y` to `uint128` and multiplying them, storing the result in `z`.
    - The lower 30 bits of `z` are extracted into `f` using a bitwise AND operation with `(1UL<<30)-1UL`.
    - The result `z` is right-shifted by 30 bits to prepare for rounding.
    - A conditional check is performed to determine if rounding is necessary: if `f` is greater than `1UL<<29` or if `f` equals `1UL<<29` and the least significant bit of `z` is 1, `z` is incremented by 1 to round up.
    - The upper 64 bits of `z` are stored in the location pointed to by `_c` using the [`split_hi`](#split_hi) function.
    - The function returns the lower 64 bits of `z` using the [`split_lo`](#split_lo) function.
- **Output**: The function returns the lower 64 bits of the rounded result of the multiplication as an unsigned long integer.
- **Functions called**:
    - [`split_lo`](#split_lo)
    - [`split_hi`](#split_hi)


---
### fd\_fxp\_mul\_rno\_ref<!-- {{#callable:fd_fxp_mul_rno_ref}} -->
The `fd_fxp_mul_rno_ref` function performs fixed-point multiplication of two unsigned long integers with rounding to the nearest even number and returns the lower 64 bits of the result, while storing the upper 64 bits in a provided pointer.
- **Inputs**:
    - `x`: An unsigned long integer representing the first operand for multiplication.
    - `y`: An unsigned long integer representing the second operand for multiplication.
    - `_c`: A pointer to an unsigned long where the upper 64 bits of the result will be stored.
- **Control Flow**:
    - The function begins by casting the inputs `x` and `y` to `uint128` and multiplying them, storing the result in `z`.
    - The lower 30 bits of `z` are extracted and stored in `f`.
    - The result `z` is right-shifted by 30 bits.
    - A conditional check is performed: if `f` is greater than `1UL<<29` or if `f` equals `1UL<<29` and the least significant bit of `z` is 0, `z` is incremented by 1 to round to the nearest even number.
    - The upper 64 bits of `z` are stored in the location pointed to by `_c`.
    - The function returns the lower 64 bits of `z`.
- **Output**: The function returns an unsigned long integer representing the lower 64 bits of the fixed-point multiplication result after rounding.
- **Functions called**:
    - [`split_lo`](#split_lo)
    - [`split_hi`](#split_hi)


---
### fd\_fxp\_div\_rtz\_ref<!-- {{#callable:fd_fxp_div_rtz_ref}} -->
The `fd_fxp_div_rtz_ref` function performs fixed-point division of two unsigned long integers with rounding towards zero, and returns the quotient while storing the high part of the result in a provided pointer.
- **Inputs**:
    - `x`: The dividend, an unsigned long integer.
    - `_y`: The divisor, an unsigned long integer.
    - `_c`: A pointer to an unsigned long where the high part of the division result will be stored.
- **Control Flow**:
    - Check if the divisor `_y` is zero; if so, set the value pointed by `_c` to `ULONG_MAX` and return 0.
    - Convert the dividend `x` to a 128-bit integer and left shift it by 30 bits to prepare for fixed-point division.
    - Convert the divisor `_y` to a 128-bit integer.
    - Perform the division of the shifted dividend by the divisor, resulting in a 128-bit quotient `z`.
    - Store the high 64 bits of `z` in the location pointed to by `_c`.
    - Return the low 64 bits of `z` as the function result.
- **Output**: The function returns the low 64 bits of the quotient from the division of `x` by `_y`, and stores the high 64 bits in the location pointed to by `_c`.
- **Functions called**:
    - [`split_hi`](#split_hi)
    - [`split_lo`](#split_lo)


---
### fd\_fxp\_div\_raz\_ref<!-- {{#callable:fd_fxp_div_raz_ref}} -->
The `fd_fxp_div_raz_ref` function performs a fixed-point division with rounding away from zero, handling division by zero by setting a carry to `ULONG_MAX` and returning zero.
- **Inputs**:
    - `x`: The dividend, a 64-bit unsigned long integer.
    - `_y`: The divisor, a 64-bit unsigned long integer.
    - `_c`: A pointer to a 64-bit unsigned long integer where the carry (high bits of the result) will be stored.
- **Control Flow**:
    - Check if the divisor `_y` is zero; if so, set the carry `_c` to `ULONG_MAX` and return 0.
    - Shift the dividend `x` left by 30 bits to prepare for fixed-point division.
    - Convert the divisor `_y` to a 128-bit integer for precision.
    - Calculate the quotient `z` by dividing the shifted dividend by the divisor, adding the divisor minus one to the dividend before division to achieve rounding away from zero.
    - Store the high 64 bits of the quotient `z` in the location pointed to by `_c`.
    - Return the low 64 bits of the quotient `z`.
- **Output**: The function returns the low 64 bits of the quotient from the fixed-point division.
- **Functions called**:
    - [`split_hi`](#split_hi)
    - [`split_lo`](#split_lo)


---
### fd\_fxp\_div\_rnz\_ref<!-- {{#callable:fd_fxp_div_rnz_ref}} -->
The `fd_fxp_div_rnz_ref` function performs a fixed-point division of two unsigned long integers with rounding to the nearest zero, and returns the quotient while storing the high part of the result in a provided pointer.
- **Inputs**:
    - `x`: The dividend, an unsigned long integer.
    - `_y`: The divisor, an unsigned long integer.
    - `_c`: A pointer to an unsigned long where the high part of the result will be stored.
- **Control Flow**:
    - Check if the divisor `_y` is zero; if so, set `*_c` to `ULONG_MAX` and return 0.
    - Shift the dividend `x` left by 30 bits to create a 128-bit integer `ex`.
    - Convert the divisor `_y` to a 128-bit integer `y`.
    - Calculate the quotient `z` by dividing `ex` plus half of `y-1` by `y`.
    - Store the high 64 bits of `z` in `*_c` using the [`split_hi`](#split_hi) function.
    - Return the low 64 bits of `z` using the [`split_lo`](#split_lo) function.
- **Output**: The function returns the low 64 bits of the quotient as an unsigned long integer.
- **Functions called**:
    - [`split_hi`](#split_hi)
    - [`split_lo`](#split_lo)


---
### fd\_fxp\_div\_rna\_ref<!-- {{#callable:fd_fxp_div_rna_ref}} -->
The `fd_fxp_div_rna_ref` function performs fixed-point division with rounding to the nearest even, handling division by zero by setting a carry to `ULONG_MAX` and returning zero.
- **Inputs**:
    - `x`: The dividend, a 64-bit unsigned long integer.
    - `_y`: The divisor, a 64-bit unsigned long integer.
    - `_c`: A pointer to a 64-bit unsigned long integer where the carry (high part of the result) will be stored.
- **Control Flow**:
    - Check if the divisor `_y` is zero; if so, set the carry `_c` to `ULONG_MAX` and return 0.
    - Shift the dividend `x` left by 30 bits to form a 128-bit integer `ex`.
    - Convert the divisor `_y` to a 128-bit integer `y`.
    - Calculate the quotient `z` by dividing `ex + (y >> 1)` by `y`, effectively rounding to the nearest even.
    - Store the high 64 bits of `z` in `_c` using [`split_hi`](#split_hi).
    - Return the low 64 bits of `z` using [`split_lo`](#split_lo).
- **Output**: The function returns the low 64 bits of the division result as a 64-bit unsigned long integer.
- **Functions called**:
    - [`split_hi`](#split_hi)
    - [`split_lo`](#split_lo)


---
### fd\_fxp\_div\_rne\_ref<!-- {{#callable:fd_fxp_div_rne_ref}} -->
The `fd_fxp_div_rne_ref` function performs fixed-point division with rounding to nearest even, handling division by zero and returning both the quotient and the carry.
- **Inputs**:
    - `x`: The dividend, a 64-bit unsigned long integer.
    - `_y`: The divisor, a 64-bit unsigned long integer.
    - `_c`: A pointer to a 64-bit unsigned long integer where the carry (high part of the result) will be stored.
- **Control Flow**:
    - Check if the divisor `_y` is zero; if so, set the carry to `ULONG_MAX` and return 0 as the quotient.
    - Shift the dividend `x` left by 30 bits to prepare for fixed-point division.
    - Convert the divisor `_y` to a 128-bit integer for division.
    - Perform the division of the shifted dividend by the divisor to get the quotient `z`.
    - Calculate the remainder `r2` by subtracting the product of `z` and `y` from the shifted dividend, then shift `r2` left by 1 bit.
    - Check if `r2` is greater than `y` or if `r2` equals `y` and `z` is odd; if either condition is true, increment `z` to round to the nearest even.
    - Store the high 64 bits of `z` in the location pointed to by `_c`.
    - Return the low 64 bits of `z` as the result.
- **Output**: The function returns the low 64 bits of the quotient as a 64-bit unsigned long integer, and stores the high 64 bits of the quotient in the location pointed to by `_c`.
- **Functions called**:
    - [`split_hi`](#split_hi)
    - [`split_lo`](#split_lo)


---
### fd\_fxp\_div\_rno\_ref<!-- {{#callable:fd_fxp_div_rno_ref}} -->
The `fd_fxp_div_rno_ref` function performs fixed-point division with rounding to nearest odd, handling division by zero by setting a carry to `ULONG_MAX` and returning zero.
- **Inputs**:
    - `x`: The dividend, a 64-bit unsigned long integer.
    - `_y`: The divisor, a 64-bit unsigned long integer.
    - `_c`: A pointer to a 64-bit unsigned long integer where the carry or high part of the result will be stored.
- **Control Flow**:
    - Check if the divisor `_y` is zero; if so, set the carry `_c` to `ULONG_MAX` and return 0.
    - Shift the dividend `x` left by 30 bits to prepare for fixed-point division.
    - Convert the divisor `_y` to a 128-bit integer for division.
    - Perform the division of the shifted dividend by the divisor, storing the result in `z`.
    - Calculate the remainder `r2` by subtracting the product of `z` and `y` from the shifted dividend, then shift `r2` left by 1 bit.
    - If `r2` is greater than `y` or `r2` equals `y` and `z` is even, increment `z` by 1 to round to the nearest odd.
    - Store the high 64 bits of `z` in the location pointed to by `_c`.
    - Return the low 64 bits of `z` as the function result.
- **Output**: The function returns the low 64 bits of the division result, and the high 64 bits are stored in the location pointed to by `_c`.
- **Functions called**:
    - [`split_hi`](#split_hi)
    - [`split_lo`](#split_lo)


---
### test\_fd\_fxp\_sqrt\_rtz<!-- {{#callable:test_fd_fxp_sqrt_rtz}} -->
The function `test_fd_fxp_sqrt_rtz` checks if a given fixed-point square root approximation is correct by comparing it against a reference value.
- **Inputs**:
    - `x`: An unsigned long integer representing the value for which the square root is being approximated.
    - `y`: An unsigned long integer representing the square root approximation of x.
- **Control Flow**:
    - Check if x is zero; if so, return 1 if y is non-zero, otherwise return 0.
    - Check if y is within the range [2^15, 2^(32+15)]; if not, return 1 indicating an invalid approximation.
    - Calculate xw as x shifted left by 30 bits, representing x in a fixed-point format.
    - Calculate ysq as y squared, representing the square of the approximation.
    - Return true if ysq is greater than xw or if the difference between xw and ysq is greater than twice y, indicating the approximation is not valid.
- **Output**: Returns an integer indicating whether the square root approximation y is valid for the input x, with 0 indicating valid and 1 indicating invalid.


---
### test\_fd\_fxp\_sqrt\_raz<!-- {{#callable:test_fd_fxp_sqrt_raz}} -->
The function `test_fd_fxp_sqrt_raz` checks if a given fixed-point square root approximation is valid based on certain conditions.
- **Inputs**:
    - `x`: An unsigned long integer representing the value to be checked against the square of y.
    - `y`: An unsigned long integer representing the value whose square is compared to x.
- **Control Flow**:
    - Check if x is zero; if so, return 1 if y is non-zero, otherwise return 0.
    - Check if y is within the range [2^15, 2^(32+15)]; if not, return 1.
    - Calculate xw as x shifted left by 30 bits, and ysq as y squared.
    - Return true if xw is greater than ysq or if the difference ysq-xw is greater than (2*y - 2).
- **Output**: Returns an integer indicating whether the fixed-point square root approximation is valid (0) or not (1).


---
### test\_fd\_fxp\_sqrt\_rnz<!-- {{#callable:test_fd_fxp_sqrt_rnz}} -->
The function `test_fd_fxp_sqrt_rnz` checks if a given fixed-point number `y` is a valid square root approximation for another fixed-point number `x` using a specific rounding method.
- **Inputs**:
    - `x`: An unsigned long integer representing the fixed-point number for which the square root is being tested.
    - `y`: An unsigned long integer representing the candidate square root approximation of `x`.
- **Control Flow**:
    - Check if `x` is zero; if so, return whether `y` is non-zero.
    - Check if `y` is within the valid range [2^15, 2^(32+15)]; if not, return 1 indicating an invalid approximation.
    - Calculate `xw` as `x` shifted left by 30 bits, representing `x` in a higher precision.
    - Calculate `ysq` as `y` squared, minus `y`, plus 1, representing a specific rounding adjustment.
    - Return true if `ysq` is greater than `xw` or if the difference `xw - ysq` is greater than or equal to `y` shifted left by 1.
- **Output**: Returns an integer indicating whether `y` is a valid square root approximation for `x` under the rounding method used.


---
### fd\_fxp\_log2\_ref<!-- {{#callable:fd_fxp_log2_ref}} -->
The `fd_fxp_log2_ref` function calculates the fixed-point representation of the base-2 logarithm of an unsigned long integer and adjusts the exponent accordingly.
- **Inputs**:
    - `x`: An unsigned long integer for which the base-2 logarithm is to be calculated.
    - `_e`: A pointer to an integer where the adjusted exponent will be stored.
- **Control Flow**:
    - Check if the input `x` is zero; if so, set the exponent to `INT_MIN` and return 0.
    - Calculate the base-2 logarithm of `x` using the `log2` function and store it in `ef`.
    - Find the most significant bit of `x` using `fd_ulong_find_msb` and store it in `e`.
    - Adjust the exponent by subtracting 30 from `e` and store the result in the location pointed to by `_e`.
    - Calculate the fixed-point representation by subtracting `e` from `ef`, multiplying by `1UL<<30`, rounding the result, and casting it to `ulong`.
- **Output**: The function returns the fixed-point representation of the base-2 logarithm of `x` as an unsigned long integer.


---
### fd\_fxp\_exp2\_ref<!-- {{#callable:fd_fxp_exp2_ref}} -->
The `fd_fxp_exp2_ref` function computes the fixed-point representation of 2 raised to the power of a given input `x`, with a check for overflow.
- **Inputs**:
    - `x`: An unsigned long integer representing the fixed-point input value for which the exponential base 2 is to be calculated.
- **Control Flow**:
    - Check if the input `x` is greater than or equal to `0x880000000UL`; if true, return `ULONG_MAX` to indicate overflow.
    - Calculate the exponential base 2 of `x` by first converting `x` to a double, scaling it by `1./(double)(1UL<<30)`, and then using the `exp2` function.
    - Multiply the result by `(double)(1UL<<30)` to convert it back to a fixed-point representation.
    - Round the result to the nearest unsigned long integer and return it.
- **Output**: The function returns an unsigned long integer representing the fixed-point result of 2 raised to the power of the input `x`, or `ULONG_MAX` if the input is too large.


---
### fd\_fxp\_rexp2\_ref<!-- {{#callable:fd_fxp_rexp2_ref}} -->
The `fd_fxp_rexp2_ref` function computes the fixed-point representation of the reciprocal of 2 raised to the power of a given input `x`, using double precision floating-point arithmetic.
- **Inputs**:
    - `x`: An unsigned long integer representing the fixed-point input value for which the reciprocal exponential base 2 is to be calculated.
- **Control Flow**:
    - The function casts the input `x` to a double and multiplies it by -1 divided by 2^30, effectively scaling and negating the input for the exponential calculation.
    - The `exp2` function is called with the scaled input to compute 2 raised to the power of the scaled input.
    - The result of `exp2` is then multiplied by 2^30 to convert it back to a fixed-point representation.
    - The `round` function is used to round the result to the nearest unsigned long integer.
    - The rounded result is cast to an unsigned long and returned.
- **Output**: The function returns an unsigned long integer representing the fixed-point result of the reciprocal exponential base 2 of the input `x`.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment and logs a warning if the `FD_HAS_INT128` capability is not available, then halts the program.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Call `fd_boot` to initialize the environment with the command-line arguments.
    - Log a warning message indicating that the unit test requires `FD_HAS_INT128` capability.
    - Call `fd_halt` to terminate the program.
    - Return 0 to indicate successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution.



# Purpose
The provided C header file, `fd_fxp.h`, is a comprehensive library for performing fixed-point arithmetic operations with a focus on portability and precision. It is designed to handle arithmetic operations such as addition, subtraction, multiplication, division, square root, logarithm, and exponential functions using fixed-point representations. The library is optimized for platforms that support 64-bit unsigned integer arithmetic and is particularly tailored for fixed-point numbers with 30 fractional bits. This file includes a variety of functions that implement different rounding modes, ensuring that operations can be performed with the desired precision and rounding behavior.

The file is structured to provide both private and public APIs, with the private API handling internal operations like expansion and contraction of numbers to and from a wider representation. The public API offers a range of arithmetic functions, each with multiple variants to accommodate different rounding strategies, such as rounding towards zero, away from zero, and various forms of nearest rounding. The library also includes fast variants of these functions for scenarios where performance is critical and the user can guarantee certain conditions (e.g., no overflow). Additionally, the file contains approximations for logarithmic and exponential functions, which are implemented using polynomial approximations to achieve high precision. Overall, this header file serves as a robust toolkit for developers needing precise fixed-point arithmetic in their applications.
# Imports and Dependencies

---
- `fd_sqrt.h`
- `../bits/fd_uwide.h`


# Functions

---
### fd\_fxp\_private\_expand<!-- {{#callable:fd_fxp_private_expand}} -->
Expands a 64-bit unsigned integer into two 64-bit parts representing a fixed-point format.
- **Inputs**:
    - `_yh`: Pointer to a 64-bit unsigned integer where the high part of the expanded value will be stored.
    - `_yl`: Pointer to a 64-bit unsigned integer where the low part of the expanded value will be stored.
    - `x`: A 64-bit unsigned integer to be expanded.
- **Control Flow**:
    - The function shifts the input `x` right by 34 bits and stores the result in the location pointed to by `_yh`.
    - The function shifts the input `x` left by 30 bits and stores the result in the location pointed to by `_yl`.
- **Output**: The function does not return a value; instead, it modifies the values at the memory locations pointed to by `_yh` and `_yl` to represent the expanded fixed-point format.


---
### fd\_fxp\_private\_contract<!-- {{#callable:fd_fxp_private_contract}} -->
The `fd_fxp_private_contract` function combines two 64-bit unsigned integers into a single 64-bit result while also extracting the high bits into a separate variable.
- **Inputs**:
    - `xh`: The high 64 bits of a 128-bit unsigned integer representation.
    - `xl`: The low 64 bits of a 128-bit unsigned integer representation.
    - `_c`: A pointer to a variable where the high bits (after shifting) will be stored.
- **Control Flow**:
    - The function first shifts `xh` right by 30 bits and stores the result in the variable pointed to by `_c`.
    - Then, it combines the shifted `xh` (left-shifted by 34 bits) with the low bits `xl` (right-shifted by 30 bits) using a bitwise OR operation to produce the final result.
- **Output**: The function returns a 64-bit unsigned integer that represents the combined value of the shifted `xh` and `xl`.


---
### fd\_fxp\_private\_split<!-- {{#callable:fd_fxp_private_split}} -->
Splits a `uint128` value into its lower 64 bits and stores the upper 64 bits in a provided pointer.
- **Inputs**:
    - `x`: A `uint128` value that is to be split into high and low parts.
    - `_h`: A pointer to an `ulong` where the upper 64 bits of `x` will be stored.
- **Control Flow**:
    - The function first shifts `x` right by 64 bits to isolate the upper 64 bits.
    - It assigns the result of the shift to the location pointed to by `_h`.
    - Finally, it returns the lower 64 bits of `x` by casting `x` to `ulong`.
- **Output**: Returns the lower 64 bits of the `uint128` value `x`.


---
### fd\_fxp\_add<!-- {{#callable:fd_fxp_add}} -->
The `fd_fxp_add` function performs fixed-point addition of two unsigned long integers with overflow detection.
- **Inputs**:
    - `x`: The first operand of type `ulong` to be added.
    - `y`: The second operand of type `ulong` to be added.
    - `_c`: A pointer to a `ulong` where the carry-out (if any) will be stored.
- **Control Flow**:
    - The function first checks if `x` is greater than the bitwise negation of `y` to determine if there is a carry-out.
    - The result of the addition `x + y` is computed and returned.
- **Output**: Returns the sum of `x` and `y` as a `ulong`, while also updating the value pointed to by `_c` to indicate if there was a carry-out.


---
### fd\_fxp\_add\_fast<!-- {{#callable:fd_fxp_add_fast}} -->
The `fd_fxp_add_fast` function performs a fast addition of two 64-bit unsigned integers.
- **Inputs**:
    - `x`: The first operand of type `ulong` (unsigned long) to be added.
    - `y`: The second operand of type `ulong` (unsigned long) to be added.
- **Control Flow**:
    - The function directly returns the sum of `x` and `y` without any checks or additional logic.
    - It utilizes the built-in addition operator for `ulong` types, which is efficient and straightforward.
- **Output**: The function returns the result of the addition as a `ulong`, which is the sum of `x` and `y`.


---
### fd\_fxp\_sub<!-- {{#callable:fd_fxp_sub}} -->
The `fd_fxp_sub` function performs fixed-point subtraction of two unsigned long integers and detects if an underflow occurs.
- **Inputs**:
    - `x`: The first operand of type `ulong` from which the second operand will be subtracted.
    - `y`: The second operand of type `ulong` that will be subtracted from the first operand.
    - `_b`: A pointer to a `ulong` where the underflow flag will be stored; it will be set to 1 if `x` is less than `y`, otherwise it will be set to 0.
- **Control Flow**:
    - The function first checks if `x` is less than `y` and sets the value pointed to by `_b` accordingly.
    - It then performs the subtraction `x - y` and returns the result.
- **Output**: The function returns the result of the subtraction `x - y` as a `ulong`.


---
### fd\_fxp\_sub\_fast<!-- {{#callable:fd_fxp_sub_fast}} -->
`fd_fxp_sub_fast` performs fast fixed-point subtraction of two unsigned long integers.
- **Inputs**:
    - `x`: The first operand of type `ulong` from which the second operand will be subtracted.
    - `y`: The second operand of type `ulong` which will be subtracted from the first operand.
- **Control Flow**:
    - The function directly returns the result of the subtraction operation `x - y`.
    - No additional checks or operations are performed, making it a straightforward and efficient implementation.
- **Output**: The function returns the result of the subtraction as a `ulong`, which is the difference between `x` and `y`.


---
### fd\_fxp\_mul\_rtz<!-- {{#callable:fd_fxp_mul_rtz}} -->
Computes the fixed-point multiplication of two unsigned long integers with rounding toward zero.
- **Inputs**:
    - `x`: The first multiplicand, an unsigned long integer.
    - `y`: The second multiplicand, an unsigned long integer.
    - `_c`: A pointer to an unsigned long integer where the carry (if any) will be stored.
- **Control Flow**:
    - Calls `fd_uwide_mul` to perform a 64-bit multiplication of `x` and `y`, storing the high and low parts in `zh` and `zl` respectively.
    - The multiplication is guaranteed to not overflow as the maximum result is within the bounds of 128 bits.
    - Calls [`fd_fxp_private_contract`](#fd_fxp_private_contract) to contract the 128-bit result back into a 64-bit fixed-point representation, while also updating the carry value pointed to by `_c`.
- **Output**: Returns the lower 64 bits of the fixed-point multiplication result.
- **Functions called**:
    - [`fd_fxp_private_contract`](#fd_fxp_private_contract)


---
### fd\_fxp\_mul\_raz<!-- {{#callable:fd_fxp_mul_raz}} -->
Multiplies two fixed-point numbers and rounds away from zero.
- **Inputs**:
    - `x`: The first multiplicand, a fixed-point number represented as an unsigned long.
    - `y`: The second multiplicand, a fixed-point number represented as an unsigned long.
    - `_c`: A pointer to an unsigned long where the carry (if any) will be stored.
- **Control Flow**:
    - Calls `fd_uwide_mul` to perform a wide multiplication of `x` and `y`, storing the high and low parts in `zh` and `zl` respectively.
    - Increments the high and low parts (`zh` and `zl`) by (1 << 30) - 1 using `fd_uwide_inc` to account for rounding away from zero.
    - Calls [`fd_fxp_private_contract`](#fd_fxp_private_contract) to contract the result back into a fixed-point representation and returns the result.
- **Output**: Returns the low 64 bits of the result of the multiplication, rounded away from zero, while storing any overflow in the variable pointed to by `_c'.
- **Functions called**:
    - [`fd_fxp_private_contract`](#fd_fxp_private_contract)


---
### fd\_fxp\_mul\_rnz<!-- {{#callable:fd_fxp_mul_rnz}} -->
The `fd_fxp_mul_rnz` function performs fixed-point multiplication of two unsigned long integers with rounding to the nearest value.
- **Inputs**:
    - `x`: The first multiplicand, an unsigned long integer.
    - `y`: The second multiplicand, an unsigned long integer.
    - `_c`: A pointer to an unsigned long integer where the carry (high bits) will be stored.
- **Control Flow**:
    - The function first calls `fd_uwide_mul` to multiply `x` and `y`, storing the result in two variables `zh` (high bits) and `zl` (low bits).
    - Next, it calls `fd_uwide_inc` to increment the high and low parts of the result by (1UL << 29) - 1, which adjusts the result for rounding.
    - Finally, it calls [`fd_fxp_private_contract`](#fd_fxp_private_contract) to combine the high and low parts into a single fixed-point result, returning the low part and storing the high part in `_c`.
- **Output**: The function returns the low 64 bits of the fixed-point multiplication result, with rounding applied, and updates the carry value in the provided pointer.
- **Functions called**:
    - [`fd_fxp_private_contract`](#fd_fxp_private_contract)


---
### fd\_fxp\_mul\_rna<!-- {{#callable:fd_fxp_mul_rna}} -->
The `fd_fxp_mul_rna` function performs fixed-point multiplication of two unsigned long integers with rounding away from zero.
- **Inputs**:
    - `x`: The first multiplicand, an unsigned long integer.
    - `y`: The second multiplicand, an unsigned long integer.
    - `_c`: A pointer to an unsigned long integer where the carry will be stored.
- **Control Flow**:
    - The function first calls `fd_uwide_mul` to multiply `x` and `y`, storing the high and low parts of the result in `zh` and `zl` respectively.
    - Next, it calls `fd_uwide_inc` to increment the high and low parts of the result by 2^29, which is necessary for rounding away from zero.
    - Finally, it calls [`fd_fxp_private_contract`](#fd_fxp_private_contract) to contract the 128-bit result back into a 64-bit fixed-point representation and returns the result.
- **Output**: The function returns the low 64 bits of the fixed-point multiplication result, with rounding applied, and updates the carry value through the pointer provided.
- **Functions called**:
    - [`fd_fxp_private_contract`](#fd_fxp_private_contract)


---
### fd\_fxp\_mul\_rne<!-- {{#callable:fd_fxp_mul_rne}} -->
Computes the fixed-point multiplication of two unsigned long integers with round-to-nearest-even behavior.
- **Inputs**:
    - `x`: The first multiplicand, an unsigned long integer.
    - `y`: The second multiplicand, an unsigned long integer.
    - `_c`: A pointer to an unsigned long integer where the high part of the result will be stored.
- **Control Flow**:
    - Calls `fd_uwide_mul` to perform a wide multiplication of `x` and `y`, storing the high and low parts in `zh` and `zl` respectively.
    - Calculates a rounding adjustment `t` based on the 30th bit of the low part `zl` to determine how to round the result.
    - Calls `fd_uwide_inc` to increment the high and low parts by the calculated adjustment `t`.
    - Returns the final result by calling [`fd_fxp_private_contract`](#fd_fxp_private_contract), which combines the high and low parts and updates the carry pointer.
- **Output**: Returns the lower 64 bits of the result of the multiplication, rounded to the nearest even number, while also updating the carry value if there is an overflow.
- **Functions called**:
    - [`fd_fxp_private_contract`](#fd_fxp_private_contract)


---
### fd\_fxp\_mul\_rno<!-- {{#callable:fd_fxp_mul_rno}} -->
The `fd_fxp_mul_rno` function performs fixed-point multiplication of two unsigned long integers with rounding towards the nearest odd value.
- **Inputs**:
    - `x`: The first multiplicand, an unsigned long integer.
    - `y`: The second multiplicand, an unsigned long integer.
    - `_c`: A pointer to an unsigned long integer where the high part of the result will be stored.
- **Control Flow**:
    - The function begins by performing a wide multiplication of `x` and `y` using `fd_uwide_mul`, which produces two parts: `zh` (high) and `zl` (low).
    - It calculates a temporary variable `t` based on the 30th bit of `zl` to determine how to round the result.
    - The function then increments the high and low parts of the result using `fd_uwide_inc` with the calculated `t`.
    - Finally, it calls [`fd_fxp_private_contract`](#fd_fxp_private_contract) to contract the result back to a fixed-point representation and returns the low part.
- **Output**: The function returns the low part of the fixed-point multiplication result, which is adjusted for rounding towards the nearest odd value.
- **Functions called**:
    - [`fd_fxp_private_contract`](#fd_fxp_private_contract)


---
### fd\_fxp\_mul\_rtz\_fast<!-- {{#callable:fd_fxp_mul_rtz_fast}} -->
Performs fast fixed-point multiplication of two unsigned long integers with rounding toward zero.
- **Inputs**:
    - `x`: The first multiplicand, an unsigned long integer.
    - `y`: The second multiplicand, an unsigned long integer.
- **Control Flow**:
    - The function computes the product of `x` and `y` using standard multiplication.
    - The result of the multiplication is then right-shifted by 30 bits to adjust for the fixed-point representation.
- **Output**: Returns the result of the fixed-point multiplication, which is the product of `x` and `y` divided by 2^30.


---
### fd\_fxp\_mul\_raz\_fast<!-- {{#callable:fd_fxp_mul_raz_fast}} -->
The `fd_fxp_mul_raz_fast` function performs fixed-point multiplication of two unsigned long integers with rounding away from zero.
- **Inputs**:
    - `x`: An unsigned long integer representing the first multiplicand.
    - `y`: An unsigned long integer representing the second multiplicand.
- **Control Flow**:
    - The function computes the product of `x` and `y` using standard multiplication.
    - It adds a constant value of (1UL << 30) - 1 to the product to facilitate rounding away from zero.
    - The result is then right-shifted by 30 bits to adjust for the fixed-point representation.
- **Output**: Returns the result of the fixed-point multiplication as an unsigned long integer, rounded away from zero.


---
### fd\_fxp\_mul\_rnz\_fast<!-- {{#callable:fd_fxp_mul_rnz_fast}} -->
Multiplies two unsigned long integers in fixed-point representation with rounding towards nearest, using a fast bit-shifting method.
- **Inputs**:
    - `x`: The first multiplicand, an unsigned long integer.
    - `y`: The second multiplicand, an unsigned long integer.
- **Control Flow**:
    - Calculates the product of `x` and `y` using standard multiplication.
    - Adds a rounding adjustment of (1UL << 29) - 1 to the product to account for fixed-point rounding.
    - Right shifts the result by 30 bits to convert the fixed-point representation back to an integer.
- **Output**: Returns the result of the fixed-point multiplication as an unsigned long integer.


---
### fd\_fxp\_mul\_rna\_fast<!-- {{#callable:fd_fxp_mul_rna_fast}} -->
Computes the fixed-point multiplication of two unsigned long integers with rounding towards the nearest integer.
- **Inputs**:
    - `x`: The first multiplicand, an unsigned long integer.
    - `y`: The second multiplicand, an unsigned long integer.
- **Control Flow**:
    - The function multiplies `x` and `y` to get the product.
    - It adds a constant value of (1UL << 29) to the product to facilitate rounding.
    - The result is then right-shifted by 30 bits to adjust for the fixed-point representation.
- **Output**: Returns the result of the fixed-point multiplication as an unsigned long integer, rounded to the nearest integer.


---
### fd\_fxp\_mul\_rne\_fast<!-- {{#callable:fd_fxp_mul_rne_fast}} -->
The `fd_fxp_mul_rne_fast` function performs fast fixed-point multiplication of two unsigned long integers with rounding to the nearest value.
- **Inputs**:
    - `x`: An unsigned long integer representing the first multiplicand.
    - `y`: An unsigned long integer representing the second multiplicand.
- **Control Flow**:
    - The function computes the product of `x` and `y`, storing the result in `z`.
    - It calculates a rounding adjustment `t` based on the value of the 30th bit of `z`.
    - The adjustment `t` is determined by adding `2^29 - 1` if the 30th bit of `z` is 0, or `2^29` if it is 1.
    - Finally, the function returns the result of `(z + t) >> 30`, effectively performing a right shift to scale the result.
- **Output**: The function returns an unsigned long integer that represents the fixed-point multiplication result of `x` and `y`, rounded to the nearest value.


---
### fd\_fxp\_mul\_rno\_fast<!-- {{#callable:fd_fxp_mul_rno_fast}} -->
Computes the fixed-point multiplication of two unsigned long integers with rounding towards the nearest odd value.
- **Inputs**:
    - `x`: The first operand of type `ulong` to be multiplied.
    - `y`: The second operand of type `ulong` to be multiplied.
- **Control Flow**:
    - Calculates the product `z` of `x` and `y`.
    - Determines the value of `t` based on the 30th bit of `z` to adjust for rounding.
    - Returns the final result by right-shifting the sum of `z` and `t` by 30.
- **Output**: Returns the result of the multiplication adjusted for fixed-point representation, effectively rounding the result towards the nearest odd integer.


---
### fd\_fxp\_mul\_rdn<!-- {{#callable:fd_fxp_mul_rdn}} -->
Performs fixed-point multiplication of two unsigned long integers with rounding down.
- **Inputs**:
    - `x`: The first operand for multiplication, represented as an unsigned long integer.
    - `y`: The second operand for multiplication, represented as an unsigned long integer.
    - `_c`: A pointer to an unsigned long integer where the carry-out from the multiplication will be stored.
- **Control Flow**:
    - Calls the [`fd_fxp_mul_rtz`](#fd_fxp_mul_rtz) function to perform the multiplication with rounding towards zero.
    - The [`fd_fxp_mul_rtz`](#fd_fxp_mul_rtz) function internally handles the multiplication and rounding logic.
- **Output**: Returns the result of the multiplication as an unsigned long integer.
- **Functions called**:
    - [`fd_fxp_mul_rtz`](#fd_fxp_mul_rtz)


---
### fd\_fxp\_mul\_rup<!-- {{#callable:fd_fxp_mul_rup}} -->
The `fd_fxp_mul_rup` function performs fixed-point multiplication of two unsigned long integers with rounding up.
- **Inputs**:
    - `x`: The first operand of type `ulong` to be multiplied.
    - `y`: The second operand of type `ulong` to be multiplied.
    - `_c`: A pointer to a `ulong` where the carry will be stored.
- **Control Flow**:
    - The function calls [`fd_fxp_mul_raz`](#fd_fxp_mul_raz), which performs the actual multiplication with rounding away from zero.
    - The result of the multiplication is returned directly.
- **Output**: Returns the result of the multiplication as a `ulong`, with rounding applied according to the specified method.
- **Functions called**:
    - [`fd_fxp_mul_raz`](#fd_fxp_mul_raz)


---
### fd\_fxp\_mul\_rnd<!-- {{#callable:fd_fxp_mul_rnd}} -->
The `fd_fxp_mul_rnd` function performs fixed-point multiplication of two unsigned long integers with rounding towards the nearest value.
- **Inputs**:
    - `x`: The first operand of type `ulong` to be multiplied.
    - `y`: The second operand of type `ulong` to be multiplied.
    - `_c`: A pointer to a `ulong` where the carry (if any) will be stored.
- **Control Flow**:
    - The function calls [`fd_fxp_mul_rnz`](#fd_fxp_mul_rnz), which handles the multiplication and rounding.
    - The multiplication is performed in a way that ensures the result is rounded to the nearest fixed-point representation.
- **Output**: Returns the result of the fixed-point multiplication as a `ulong`, with the carry stored in the location pointed to by `_c`.
- **Functions called**:
    - [`fd_fxp_mul_rnz`](#fd_fxp_mul_rnz)


---
### fd\_fxp\_mul\_rnu<!-- {{#callable:fd_fxp_mul_rnu}} -->
The `fd_fxp_mul_rnu` function performs fixed-point multiplication with rounding towards the nearest value, handling overflow through an additional carry.
- **Inputs**:
    - `x`: The first operand of type `ulong` to be multiplied.
    - `y`: The second operand of type `ulong` to be multiplied.
    - `_c`: A pointer to a `ulong` where the carry resulting from the multiplication will be stored.
- **Control Flow**:
    - The function calls [`fd_fxp_mul_rna`](#fd_fxp_mul_rna), which performs the actual multiplication with rounding towards the nearest value.
    - The result of the multiplication is returned directly from the [`fd_fxp_mul_rna`](#fd_fxp_mul_rna) function.
- **Output**: Returns the result of the fixed-point multiplication of `x` and `y`, rounded to the nearest value, while also updating the carry if necessary.
- **Functions called**:
    - [`fd_fxp_mul_rna`](#fd_fxp_mul_rna)


---
### fd\_fxp\_mul\_rdn\_fast<!-- {{#callable:fd_fxp_mul_rdn_fast}} -->
The `fd_fxp_mul_rdn_fast` function performs fixed-point multiplication of two unsigned long integers with rounding down.
- **Inputs**:
    - `x`: An unsigned long integer representing the first operand in the multiplication.
    - `y`: An unsigned long integer representing the second operand in the multiplication.
- **Control Flow**:
    - The function calls [`fd_fxp_mul_rtz_fast`](#fd_fxp_mul_rtz_fast) to perform the multiplication with truncation rounding.
    - The result of the multiplication is then returned directly.
- **Output**: The function returns an unsigned long integer that is the result of the multiplication of `x` and `y`, rounded down.
- **Functions called**:
    - [`fd_fxp_mul_rtz_fast`](#fd_fxp_mul_rtz_fast)


---
### fd\_fxp\_mul\_rup\_fast<!-- {{#callable:fd_fxp_mul_rup_fast}} -->
The `fd_fxp_mul_rup_fast` function performs fixed-point multiplication of two unsigned long integers with rounding up.
- **Inputs**:
    - `x`: The first operand of type `ulong` to be multiplied.
    - `y`: The second operand of type `ulong` to be multiplied.
- **Control Flow**:
    - The function calls [`fd_fxp_mul_raz_fast`](#fd_fxp_mul_raz_fast) to perform the multiplication with rounding up.
    - The result of the multiplication is returned directly.
- **Output**: Returns the result of the multiplication of `x` and `y`, rounded up, as an unsigned long integer.
- **Functions called**:
    - [`fd_fxp_mul_raz_fast`](#fd_fxp_mul_raz_fast)


---
### fd\_fxp\_mul\_rnd\_fast<!-- {{#callable:fd_fxp_mul_rnd_fast}} -->
The `fd_fxp_mul_rnd_fast` function performs fast fixed-point multiplication with rounding towards zero.
- **Inputs**:
    - `x`: An unsigned long integer representing the first operand in the fixed-point multiplication.
    - `y`: An unsigned long integer representing the second operand in the fixed-point multiplication.
- **Control Flow**:
    - The function calls [`fd_fxp_mul_rnz_fast`](#fd_fxp_mul_rnz_fast) with the inputs `x` and `y`.
    - The [`fd_fxp_mul_rnz_fast`](#fd_fxp_mul_rnz_fast) function computes the product of `x` and `y`, adds a rounding adjustment, and then shifts the result right by 30 bits to account for the fixed-point representation.
- **Output**: Returns the result of the fixed-point multiplication, rounded towards zero, as an unsigned long integer.
- **Functions called**:
    - [`fd_fxp_mul_rnz_fast`](#fd_fxp_mul_rnz_fast)


---
### fd\_fxp\_mul\_rnu\_fast<!-- {{#callable:fd_fxp_mul_rnu_fast}} -->
The `fd_fxp_mul_rnu_fast` function performs fixed-point multiplication with rounding towards the nearest value, using a fast implementation.
- **Inputs**:
    - `x`: An unsigned long integer representing the first operand in the fixed-point multiplication.
    - `y`: An unsigned long integer representing the second operand in the fixed-point multiplication.
- **Control Flow**:
    - The function calls [`fd_fxp_mul_rna_fast`](#fd_fxp_mul_rna_fast) with the inputs `x` and `y`.
    - The [`fd_fxp_mul_rna_fast`](#fd_fxp_mul_rna_fast) function computes the product of `x` and `y`, adds a rounding adjustment, and shifts the result to account for the fixed-point representation.
- **Output**: Returns the result of the fixed-point multiplication of `x` and `y`, rounded to the nearest value.
- **Functions called**:
    - [`fd_fxp_mul_rna_fast`](#fd_fxp_mul_rna_fast)


---
### fd\_fxp\_div\_rtz<!-- {{#callable:fd_fxp_div_rtz}} -->
Performs fixed-point division of two unsigned long integers with round toward zero (RTZ) behavior.
- **Inputs**:
    - `x`: The numerator in the fixed-point division, represented as an unsigned long.
    - `y`: The denominator in the fixed-point division, represented as an unsigned long.
    - `_c`: A pointer to an unsigned long where the high part of the result will be stored.
- **Control Flow**:
    - Checks if the denominator `y` is zero; if so, sets `_c` to ULONG_MAX and returns 0UL to handle division by zero.
    - Calls [`fd_fxp_private_expand`](#fd_fxp_private_expand) to expand `x` into two parts, `zh` and `zl`, which represent the high and low parts of the fixed-point number.
    - Calls `fd_uwide_div` to perform the division of the expanded numerator by the denominator, storing the result in `zh` and `zl`.
    - Stores the high part of the result in `_c` and returns the low part `zl`.
- **Output**: Returns the low part of the result of the fixed-point division, while the high part is stored in the variable pointed to by `_c`.
- **Functions called**:
    - [`fd_fxp_private_expand`](#fd_fxp_private_expand)


---
### fd\_fxp\_div\_raz<!-- {{#callable:fd_fxp_div_raz}} -->
The `fd_fxp_div_raz` function performs fixed-point division with rounding away from zero.
- **Inputs**:
    - `x`: The numerator in the fixed-point division, represented as an unsigned long.
    - `y`: The denominator in the fixed-point division, represented as an unsigned long.
    - `_c`: A pointer to an unsigned long where the high part of the result will be stored.
- **Control Flow**:
    - The function first checks if the denominator `y` is zero to handle division by zero, setting `_c` to ULONG_MAX and returning 0 if true.
    - It then expands the numerator `x` into two parts, `zh` and `zl`, using the [`fd_fxp_private_expand`](#fd_fxp_private_expand) function.
    - Next, it increments the high part `zh` and low part `zl` by `y - 1` using the `fd_uwide_inc` function to prepare for rounding up.
    - Finally, it performs the division of the expanded numerator by `y` using `fd_uwide_div`, stores the high part in `_c`, and returns the low part `zl`.
- **Output**: The function returns the low part of the result of the division, while the high part is stored in the variable pointed to by `_c`.
- **Functions called**:
    - [`fd_fxp_private_expand`](#fd_fxp_private_expand)


---
### fd\_fxp\_div\_rnz<!-- {{#callable:fd_fxp_div_rnz}} -->
Performs fixed-point division of two unsigned long integers with rounding towards nearest, returning the quotient and storing the carry.
- **Inputs**:
    - `x`: The dividend, an unsigned long integer representing the numerator in the division.
    - `y`: The divisor, an unsigned long integer representing the denominator in the division.
    - `_c`: A pointer to an unsigned long integer where the carry (the high part of the result) will be stored.
- **Control Flow**:
    - Checks if the divisor `y` is zero; if so, sets the carry to ULONG_MAX and returns 0.
    - Expands the dividend `x` into a higher precision format suitable for fixed-point arithmetic.
    - Increments the expanded dividend by half of the divisor to prepare for rounding.
    - Performs the division of the expanded dividend by the divisor.
    - Stores the high part of the result in the variable pointed to by `_c` and returns the low part of the result.
- **Output**: Returns the low part of the quotient from the division of `x` by `y`, while the high part is stored in the variable pointed to by `_c`.
- **Functions called**:
    - [`fd_fxp_private_expand`](#fd_fxp_private_expand)


---
### fd\_fxp\_div\_rna<!-- {{#callable:fd_fxp_div_rna}} -->
Performs fixed-point division of two unsigned long integers with rounding towards the nearest integer.
- **Inputs**:
    - `x`: The numerator, an unsigned long integer representing the dividend in fixed-point format.
    - `y`: The denominator, an unsigned long integer representing the divisor in fixed-point format.
    - `_c`: A pointer to an unsigned long integer where the carry (high part of the result) will be stored.
- **Control Flow**:
    - Checks if the denominator `y` is zero; if so, sets the carry `_c` to ULONG_MAX and returns 0.
    - Expands the numerator `x` into two parts `zh` and `zl` using the [`fd_fxp_private_expand`](#fd_fxp_private_expand) function.
    - Increments the high part `zh` and low part `zl` by half of `y` using `fd_uwide_inc` to prepare for division.
    - Divides the expanded numerator by the denominator `y` using `fd_uwide_div`, storing the result back in `zh` and `zl`.
    - Sets the carry `_c` to the high part `zh` and returns the low part `zl` as the result.
- **Output**: Returns the low part of the result of the division, which is the quotient of `x` divided by `y` in fixed-point format.
- **Functions called**:
    - [`fd_fxp_private_expand`](#fd_fxp_private_expand)


---
### fd\_fxp\_div\_rne<!-- {{#callable:fd_fxp_div_rne}} -->
Performs fixed-point division with rounding to nearest even.
- **Inputs**:
    - `x`: The numerator in the fixed-point division, represented as an unsigned long.
    - `y`: The denominator in the fixed-point division, represented as an unsigned long.
    - `_c`: A pointer to an unsigned long where the high part of the result will be stored.
- **Control Flow**:
    - Check if the denominator `y` is zero; if so, set `_c` to ULONG_MAX and return 0.
    - Expand the numerator `x` into two parts `zh` and `zl` using [`fd_fxp_private_expand`](#fd_fxp_private_expand).
    - Perform the division using `fd_uwide_divrem`, which computes both the quotient and the remainder.
    - Calculate the floor of half of `y` to assist in rounding.
    - Determine if rounding up is necessary based on the remainder and the quotient's parity.
    - Increment the high part `zh` and low part `zl` if rounding up is required.
    - Store the high part of the result in `_c` and return the low part `zl`.
- **Output**: Returns the low part of the result of the fixed-point division, while the high part is stored in the variable pointed to by `_c`.
- **Functions called**:
    - [`fd_fxp_private_expand`](#fd_fxp_private_expand)


---
### fd\_fxp\_div\_rno<!-- {{#callable:fd_fxp_div_rno}} -->
The `fd_fxp_div_rno` function performs fixed-point division of two unsigned long integers with rounding towards the nearest odd integer.
- **Inputs**:
    - `x`: The numerator, an unsigned long integer representing the fixed-point value to be divided.
    - `y`: The denominator, an unsigned long integer representing the fixed-point value by which to divide.
    - `_c`: A pointer to an unsigned long integer where the high part of the result will be stored.
- **Control Flow**:
    - Check if the denominator `y` is zero; if so, set `_c` to ULONG_MAX and return 0UL to handle division by zero.
    - Expand the numerator `x` into two parts, `zh` and `zl`, using the [`fd_fxp_private_expand`](#fd_fxp_private_expand) function.
    - Perform the division using `fd_uwide_divrem`, which computes the quotient and remainder of the expanded numerator divided by `y`.
    - Calculate the floor of `y/2` and store it in `flhy` to assist in rounding.
    - Increment the high part of the result based on the remainder to achieve rounding towards the nearest odd integer.
    - Store the high part of the result in `_c` and return the low part of the result.
- **Output**: Returns the low part of the result of the division, which is the quotient of `x` divided by `y`, rounded towards the nearest odd integer.
- **Functions called**:
    - [`fd_fxp_private_expand`](#fd_fxp_private_expand)


---
### fd\_fxp\_div\_rtz\_fast<!-- {{#callable:fd_fxp_div_rtz_fast}} -->
Performs fast fixed-point division with round toward zero.
- **Inputs**:
    - `x`: The numerator in the fixed-point division, represented as an unsigned long.
    - `y`: The denominator in the fixed-point division, represented as an unsigned long.
- **Control Flow**:
    - The function first shifts `x` left by 30 bits to scale it appropriately for fixed-point representation.
    - It then performs integer division of the scaled `x` by `y`.
    - The result of the division is returned directly.
- **Output**: Returns the result of the division as an unsigned long, which represents the fixed-point result of x/y with truncation.


---
### fd\_fxp\_div\_raz\_fast<!-- {{#callable:fd_fxp_div_raz_fast}} -->
Performs fast fixed-point division of two unsigned long integers with rounding towards zero.
- **Inputs**:
    - `x`: The numerator, an unsigned long integer that represents the fixed-point value to be divided.
    - `y`: The denominator, an unsigned long integer that represents the fixed-point value by which to divide.
- **Control Flow**:
    - The function first shifts `x` left by 30 bits to scale it appropriately for fixed-point division.
    - It then performs integer division of the scaled `x` by `y`.
    - The result of the division is returned directly.
- **Output**: Returns the result of the division as an unsigned long integer, which represents the fixed-point result of the division of `x` by `y`.


---
### fd\_fxp\_div\_rnz\_fast<!-- {{#callable:fd_fxp_div_rnz_fast}} -->
Performs fast fixed-point division of two unsigned long integers with rounding towards nearest, ensuring non-zero results.
- **Inputs**:
    - `x`: The numerator, an unsigned long integer representing the fixed-point value to be divided.
    - `y`: The denominator, an unsigned long integer representing the fixed-point value by which to divide. Must be non-zero.
- **Control Flow**:
    - The function first checks if `y` is zero to prevent division by zero, returning 0 and setting the carry to ULONG_MAX if true.
    - The numerator `x` is left-shifted by 30 bits to scale it appropriately for fixed-point division.
    - The function computes the division of the scaled numerator by the denominator `y`.
    - The result is adjusted by adding half of `y` (specifically, (y-1) >> 1) to achieve rounding towards the nearest integer.
- **Output**: Returns the result of the division as an unsigned long integer, representing the fixed-point result of the division, with rounding applied.


---
### fd\_fxp\_div\_rna\_fast<!-- {{#callable:fd_fxp_div_rna_fast}} -->
The `fd_fxp_div_rna_fast` function performs fast fixed-point division with rounding towards the nearest integer, using a specific formula to adjust the dividend.
- **Inputs**:
    - `x`: The numerator in the fixed-point division, represented as an unsigned long integer.
    - `y`: The denominator in the fixed-point division, represented as an unsigned long integer.
- **Control Flow**:
    - The function computes the result of the division by first shifting `x` left by 30 bits to scale it appropriately for fixed-point representation.
    - It then adds half of `y` (i.e., `y >> 1`) to the scaled `x` to implement rounding towards the nearest integer.
    - Finally, it performs the division of the adjusted numerator by `y` and returns the result.
- **Output**: The function returns the result of the fixed-point division as an unsigned long integer, which is the quotient of the adjusted numerator divided by the denominator.


---
### fd\_fxp\_div\_rne\_fast<!-- {{#callable:fd_fxp_div_rne_fast}} -->
Performs fast fixed-point division with round-to-nearest-even behavior.
- **Inputs**:
    - `x`: The numerator in the fixed-point division, represented as an unsigned long.
    - `y`: The denominator in the fixed-point division, represented as an unsigned long.
- **Control Flow**:
    - The function first shifts `x` left by 30 bits to scale it appropriately for fixed-point arithmetic.
    - It then performs integer division of the scaled numerator `n` by the denominator `y` to obtain the quotient `q`.
    - The remainder `r` is calculated by subtracting the product of `q` and `y` from `n`.
    - A threshold value `flhy` is computed as half of `y` to determine rounding behavior.
    - Finally, the function returns the quotient `q` adjusted by a rounding condition based on the value of `r` compared to `flhy`.
- **Output**: Returns the result of the division as an unsigned long, rounded to the nearest even number in case of ties.


---
### fd\_fxp\_div\_rno\_fast<!-- {{#callable:fd_fxp_div_rno_fast}} -->
Performs fast fixed-point division with round towards odd behavior.
- **Inputs**:
    - `x`: The numerator in the fixed-point division, represented as an unsigned long.
    - `y`: The denominator in the fixed-point division, represented as an unsigned long.
- **Control Flow**:
    - The function first shifts `x` left by 30 bits to scale it appropriately for fixed-point arithmetic.
    - It then performs integer division of the scaled `x` by `y` to obtain the quotient `q`.
    - The remainder `r` is calculated by subtracting the product of `q` and `y` from the scaled `x`.
    - A threshold value `flhy` is computed as half of `y` to assist in rounding.
    - Finally, the function returns the quotient `q` adjusted by a rounding condition based on the value of `r`.
- **Output**: Returns the result of the division as an unsigned long, with rounding applied based on the remainder.


---
### fd\_fxp\_div\_rdn<!-- {{#callable:fd_fxp_div_rdn}} -->
The `fd_fxp_div_rdn` function performs fixed-point division with rounding down.
- **Inputs**:
    - `x`: The numerator in the fixed-point division, represented as an unsigned long.
    - `y`: The denominator in the fixed-point division, represented as an unsigned long.
    - `_c`: A pointer to an unsigned long where the carry (if any) will be stored.
- **Control Flow**:
    - The function first calls [`fd_fxp_div_rtz`](#fd_fxp_div_rtz) to perform the division operation.
    - If the denominator `y` is zero, it sets the carry `_c` to ULONG_MAX and returns 0.
    - The result of the division is computed and returned.
- **Output**: The function returns the result of the fixed-point division, rounded down.
- **Functions called**:
    - [`fd_fxp_div_rtz`](#fd_fxp_div_rtz)


---
### fd\_fxp\_div\_rup<!-- {{#callable:fd_fxp_div_rup}} -->
The `fd_fxp_div_rup` function performs fixed-point division with rounding up.
- **Inputs**:
    - `x`: The numerator in the fixed-point division, represented as an unsigned long.
    - `y`: The denominator in the fixed-point division, represented as an unsigned long.
    - `_c`: A pointer to an unsigned long where the carry (if any) will be stored.
- **Control Flow**:
    - The function calls [`fd_fxp_div_raz`](#fd_fxp_div_raz) to perform the division operation.
    - If `y` is zero, the function will handle the division by zero case by returning a specific value.
- **Output**: The function returns the result of the division, rounded up, as an unsigned long.
- **Functions called**:
    - [`fd_fxp_div_raz`](#fd_fxp_div_raz)


---
### fd\_fxp\_div\_rnd<!-- {{#callable:fd_fxp_div_rnd}} -->
The `fd_fxp_div_rnd` function performs fixed-point division with rounding, returning the result of dividing `x` by `y`.
- **Inputs**:
    - `x`: The numerator in the fixed-point division, represented as an unsigned long.
    - `y`: The denominator in the fixed-point division, represented as an unsigned long.
    - `_c`: A pointer to an unsigned long where the carry (if any) will be stored.
- **Control Flow**:
    - The function first calls [`fd_fxp_div_rnz`](#fd_fxp_div_rnz) with the same parameters to perform the division.
    - If `y` is zero, the division is undefined, and the function will handle this case by returning a specific value.
- **Output**: The function returns the result of the fixed-point division of `x` by `y`, rounded according to the specified rounding mode.
- **Functions called**:
    - [`fd_fxp_div_rnz`](#fd_fxp_div_rnz)


---
### fd\_fxp\_div\_rnu<!-- {{#callable:fd_fxp_div_rnu}} -->
The `fd_fxp_div_rnu` function performs fixed-point division with rounding towards the nearest integer, handling overflow by returning a special value.
- **Inputs**:
    - `ulong x`: The numerator in the fixed-point division operation, represented as an unsigned long integer.
    - `ulong y`: The denominator in the fixed-point division operation, represented as an unsigned long integer.
    - `ulong * _c`: A pointer to an unsigned long integer where the carry (if any) from the division operation will be stored.
- **Control Flow**:
    - The function calls [`fd_fxp_div_rna`](#fd_fxp_div_rna), which performs the actual division operation with rounding towards the nearest integer.
    - The result of the division is returned directly from the [`fd_fxp_div_rna`](#fd_fxp_div_rna) function.
- **Output**: The function returns the result of the fixed-point division of `x` by `y`, rounded to the nearest integer, while also updating the carry value pointed to by `_c`.
- **Functions called**:
    - [`fd_fxp_div_rna`](#fd_fxp_div_rna)


---
### fd\_fxp\_div\_rdn\_fast<!-- {{#callable:fd_fxp_div_rdn_fast}} -->
The `fd_fxp_div_rdn_fast` function performs fixed-point division with rounding down.
- **Inputs**:
    - `x`: The numerator in the fixed-point division, represented as an unsigned long.
    - `y`: The denominator in the fixed-point division, represented as an unsigned long.
- **Control Flow**:
    - The function calls [`fd_fxp_div_rtz_fast`](#fd_fxp_div_rtz_fast) to perform the division operation.
    - The [`fd_fxp_div_rtz_fast`](#fd_fxp_div_rtz_fast) function computes the result by shifting `x` left by 30 bits and dividing by `y`.
- **Output**: The function returns the result of the fixed-point division, rounded down, as an unsigned long.
- **Functions called**:
    - [`fd_fxp_div_rtz_fast`](#fd_fxp_div_rtz_fast)


---
### fd\_fxp\_div\_rup\_fast<!-- {{#callable:fd_fxp_div_rup_fast}} -->
`fd_fxp_div_rup_fast` performs a fixed-point division of two unsigned long integers with rounding up.
- **Inputs**:
    - `x`: The numerator, an unsigned long integer representing the fixed-point value to be divided.
    - `y`: The denominator, an unsigned long integer representing the fixed-point value by which to divide.
- **Control Flow**:
    - The function calls [`fd_fxp_div_raz_fast`](#fd_fxp_div_raz_fast) to perform the division operation.
    - The [`fd_fxp_div_raz_fast`](#fd_fxp_div_raz_fast) function computes the division and applies rounding away from zero.
- **Output**: Returns the result of the division as an unsigned long integer, rounded up.
- **Functions called**:
    - [`fd_fxp_div_raz_fast`](#fd_fxp_div_raz_fast)


---
### fd\_fxp\_div\_rnd\_fast<!-- {{#callable:fd_fxp_div_rnd_fast}} -->
Performs fast fixed-point division with rounding towards zero.
- **Inputs**:
    - `x`: The numerator in the fixed-point division, represented as an unsigned long.
    - `y`: The denominator in the fixed-point division, represented as an unsigned long.
- **Control Flow**:
    - The function calls [`fd_fxp_div_rnz_fast`](#fd_fxp_div_rnz_fast) to perform the division.
    - If `y` is zero, the function will handle this case by returning a specific value indicating an error (not shown in this function).
- **Output**: Returns the result of the fixed-point division of `x` by `y`, rounded towards zero.
- **Functions called**:
    - [`fd_fxp_div_rnz_fast`](#fd_fxp_div_rnz_fast)


---
### fd\_fxp\_div\_rnu\_fast<!-- {{#callable:fd_fxp_div_rnu_fast}} -->
Performs fixed-point division with round-to-nearest-up behavior.
- **Inputs**:
    - `x`: The numerator in the fixed-point division, represented as an unsigned long.
    - `y`: The denominator in the fixed-point division, represented as an unsigned long.
- **Control Flow**:
    - Calls the [`fd_fxp_div_rna_fast`](#fd_fxp_div_rna_fast) function to perform the division operation.
    - The [`fd_fxp_div_rna_fast`](#fd_fxp_div_rna_fast) function handles the actual division logic.
- **Output**: Returns the result of the fixed-point division as an unsigned long.
- **Functions called**:
    - [`fd_fxp_div_rna_fast`](#fd_fxp_div_rna_fast)


---
### fd\_fxp\_sqrt\_rtz<!-- {{#callable:fd_fxp_sqrt_rtz}} -->
Computes the square root of a fixed-point number using a right rounding method.
- **Inputs**:
    - `x`: An unsigned long integer representing the fixed-point number for which the square root is to be calculated.
- **Control Flow**:
    - The function first checks if the input `x` is zero, returning zero if true.
    - It calculates `s`, the largest integer such that `x * 2^(2s)` does not overflow, which helps in scaling `x` appropriately.
    - An initial guess for the square root `y` is computed by scaling `x` and taking its square root.
    - If `s` is 15, the function returns the initial guess `y` directly, as no further iterations are needed.
    - If `s` is less than 15, the function expands `x` into two parts for fixed-point iteration.
    - A loop is initiated to refine the estimate of the square root using the formula `y' = floor((y(y+1) + 2^30 * x) / (2y + 1))` until convergence is achieved.
- **Output**: Returns the computed square root of `x` as an unsigned long integer, rounded towards zero.
- **Functions called**:
    - [`fd_ulong_sqrt`](fd_sqrt.h.driver.md#fd_ulong_sqrt)
    - [`fd_fxp_private_expand`](#fd_fxp_private_expand)


---
### fd\_fxp\_sqrt\_raz<!-- {{#callable:fd_fxp_sqrt_raz}} -->
Calculates the square root of a fixed-point number using raz rounding.
- **Inputs**:
    - `x`: An unsigned long integer representing the fixed-point number for which the square root is to be calculated.
- **Control Flow**:
    - The function first checks if the input `x` is zero, returning zero if true.
    - It calculates an initial guess for the square root based on the most significant bit of `x`.
    - If the calculated shift `s` is 15, it returns the initial guess adjusted for any residual.
    - The function expands `x` into high and low parts for precise calculations.
    - It enters a loop where it iteratively refines the guess for the square root using a modified Newton's method until convergence is achieved.
- **Output**: Returns the computed square root of `x` as an unsigned long integer, rounded away from zero.
- **Functions called**:
    - [`fd_ulong_sqrt`](fd_sqrt.h.driver.md#fd_ulong_sqrt)
    - [`fd_fxp_private_expand`](#fd_fxp_private_expand)


---
### fd\_fxp\_sqrt\_rnz<!-- {{#callable:fd_fxp_sqrt_rnz}} -->
Calculates the square root of a fixed-point number using round-nearest towards zero (RNZ) rounding.
- **Inputs**:
    - `x`: An unsigned long integer representing the fixed-point number for which the square root is to be calculated.
- **Control Flow**:
    - The function first checks if the input `x` is zero, returning zero if true.
    - It calculates an initial guess for the square root by determining the position of the most significant bit of `x` and adjusting the value accordingly.
    - If the calculated shift value `s` is 15, it returns the initial guess adjusted for any residual error.
    - The function then expands `x` into a higher precision format suitable for the iterative calculation.
    - It enters a loop where it repeatedly refines the guess for the square root using a specific iterative formula until convergence is achieved.
    - The loop continues until the new guess does not change from the previous guess.
- **Output**: Returns the computed square root of `x` as an unsigned long integer, rounded according to the RNZ method.
- **Functions called**:
    - [`fd_ulong_sqrt`](fd_sqrt.h.driver.md#fd_ulong_sqrt)
    - [`fd_fxp_private_expand`](#fd_fxp_private_expand)


---
### fd\_fxp\_sqrt\_rna<!-- {{#callable:fd_fxp_sqrt_rna}} -->
Calculates the square root of a fixed-point number using the nearest rounding mode.
- **Inputs**:
    - `x`: An unsigned long integer representing the fixed-point number for which the square root is to be calculated.
- **Control Flow**:
    - The function calls [`fd_fxp_sqrt_rnz`](#fd_fxp_sqrt_rnz) to compute the square root with nearest rounding.
    - The [`fd_fxp_sqrt_rnz`](#fd_fxp_sqrt_rnz) function performs an initial approximation of the square root and iteratively refines it until convergence.
- **Output**: Returns an unsigned long integer representing the square root of the input fixed-point number.
- **Functions called**:
    - [`fd_fxp_sqrt_rnz`](#fd_fxp_sqrt_rnz)


---
### fd\_fxp\_sqrt\_rne<!-- {{#callable:fd_fxp_sqrt_rne}} -->
Computes the square root of a fixed-point number using round-to-nearest-even rounding.
- **Inputs**:
    - `x`: An unsigned long integer representing the fixed-point number for which the square root is to be calculated.
- **Control Flow**:
    - The function calls [`fd_fxp_sqrt_rnz`](#fd_fxp_sqrt_rnz) to compute the square root with round-to-nearest-zero rounding.
    - The [`fd_fxp_sqrt_rnz`](#fd_fxp_sqrt_rnz) function handles the actual computation and rounding logic.
- **Output**: Returns an unsigned long integer representing the square root of the input fixed-point number.
- **Functions called**:
    - [`fd_fxp_sqrt_rnz`](#fd_fxp_sqrt_rnz)


---
### fd\_fxp\_sqrt\_rno<!-- {{#callable:fd_fxp_sqrt_rno}} -->
Computes the square root of a fixed-point number using a specific rounding mode.
- **Inputs**:
    - `x`: An unsigned long integer representing the fixed-point number for which the square root is to be calculated.
- **Control Flow**:
    - The function calls [`fd_fxp_sqrt_rnz`](#fd_fxp_sqrt_rnz) to compute the square root, which handles the rounding mode internally.
    - If `x` is zero, it immediately returns zero.
    - The function uses an iterative method to refine the square root approximation until convergence is achieved.
- **Output**: Returns the computed square root as an unsigned long integer, rounded according to the specified mode.
- **Functions called**:
    - [`fd_fxp_sqrt_rnz`](#fd_fxp_sqrt_rnz)


---
### fd\_fxp\_sqrt\_rtz\_fast<!-- {{#callable:fd_fxp_sqrt_rtz_fast}} -->
Computes the square root of a fixed-point number using right shift for fast approximation.
- **Inputs**:
    - `x`: An unsigned long integer representing the fixed-point number for which the square root is to be calculated.
- **Control Flow**:
    - The function first left shifts `x` by 30 bits to scale it appropriately for fixed-point representation.
    - It then calls the [`fd_ulong_sqrt`](fd_sqrt.h.driver.md#fd_ulong_sqrt) function to compute the square root of the scaled value.
    - Finally, the result from [`fd_ulong_sqrt`](fd_sqrt.h.driver.md#fd_ulong_sqrt) is returned directly.
- **Output**: Returns the square root of the input `x` scaled back to the original fixed-point representation.
- **Functions called**:
    - [`fd_ulong_sqrt`](fd_sqrt.h.driver.md#fd_ulong_sqrt)


---
### fd\_fxp\_sqrt\_raz\_fast<!-- {{#callable:fd_fxp_sqrt_raz_fast}} -->
Calculates the square root of a fixed-point number with rounding away from zero.
- **Inputs**:
    - `x`: An unsigned long integer representing the fixed-point number for which the square root is to be calculated.
- **Control Flow**:
    - The input `x` is left-shifted by 30 bits to scale it appropriately for fixed-point arithmetic.
    - The square root of the scaled value is computed using the [`fd_ulong_sqrt`](fd_sqrt.h.driver.md#fd_ulong_sqrt) function.
    - The residual `r` is calculated as the difference between the scaled input and the square of the computed square root.
    - If there is a non-zero residual, the result is incremented by 1 to round up, ensuring correct rounding away from zero.
- **Output**: Returns the computed square root as an unsigned long integer, rounded away from zero.
- **Functions called**:
    - [`fd_ulong_sqrt`](fd_sqrt.h.driver.md#fd_ulong_sqrt)


---
### fd\_fxp\_sqrt\_rnz\_fast<!-- {{#callable:fd_fxp_sqrt_rnz_fast}} -->
Calculates the square root of a fixed-point number using a fast approximation method.
- **Inputs**:
    - `x`: An unsigned long integer representing the fixed-point number for which the square root is to be calculated.
- **Control Flow**:
    - The input `x` is left-shifted by 30 bits to scale it appropriately for fixed-point arithmetic.
    - The function [`fd_ulong_sqrt`](fd_sqrt.h.driver.md#fd_ulong_sqrt) is called to compute the integer square root of the scaled value.
    - The residual `r` is calculated as the difference between the scaled input and the square of the computed square root.
    - The function returns the computed square root plus one if the residual is greater than the square root, effectively rounding up.
- **Output**: Returns an unsigned long integer representing the square root of the input fixed-point number, rounded as necessary.
- **Functions called**:
    - [`fd_ulong_sqrt`](fd_sqrt.h.driver.md#fd_ulong_sqrt)


---
### fd\_fxp\_sqrt\_rna\_fast<!-- {{#callable:fd_fxp_sqrt_rna_fast}} -->
Calculates the square root of a fixed-point number using a fast approximation method.
- **Inputs**:
    - `x`: An unsigned long integer representing the fixed-point number for which the square root is to be calculated.
- **Control Flow**:
    - The function calls [`fd_fxp_sqrt_rnz_fast`](#fd_fxp_sqrt_rnz_fast) to compute the square root.
    - The [`fd_fxp_sqrt_rnz_fast`](#fd_fxp_sqrt_rnz_fast) function performs a fast approximation of the square root by shifting the input left by 30 bits and using the `fd_ulong_sqrt` function to compute the integer square root.
    - It then calculates the remainder to determine if the result needs to be adjusted up or down based on the residual.
- **Output**: Returns an unsigned long integer representing the square root of the input fixed-point number, rounded according to the nearest rounding mode.
- **Functions called**:
    - [`fd_fxp_sqrt_rnz_fast`](#fd_fxp_sqrt_rnz_fast)


---
### fd\_fxp\_sqrt\_rne\_fast<!-- {{#callable:fd_fxp_sqrt_rne_fast}} -->
The `fd_fxp_sqrt_rne_fast` function computes the square root of a fixed-point number using round-to-nearest-even rounding.
- **Inputs**:
    - `x`: An unsigned long integer representing the fixed-point number for which the square root is to be calculated.
- **Control Flow**:
    - The function calls [`fd_fxp_sqrt_rnz_fast`](#fd_fxp_sqrt_rnz_fast) to compute the square root with round-to-nearest-zero rounding.
    - The result from [`fd_fxp_sqrt_rnz_fast`](#fd_fxp_sqrt_rnz_fast) is returned directly as the output.
- **Output**: Returns an unsigned long integer representing the square root of the input fixed-point number, rounded to the nearest even value.
- **Functions called**:
    - [`fd_fxp_sqrt_rnz_fast`](#fd_fxp_sqrt_rnz_fast)


---
### fd\_fxp\_sqrt\_rno\_fast<!-- {{#callable:fd_fxp_sqrt_rno_fast}} -->
Computes the square root of a fixed-point number using a fast rounding mode.
- **Inputs**:
    - `x`: An unsigned long integer representing the fixed-point number for which the square root is to be calculated.
- **Control Flow**:
    - The function calls [`fd_fxp_sqrt_rnz_fast`](#fd_fxp_sqrt_rnz_fast) to compute the square root.
    - The [`fd_fxp_sqrt_rnz_fast`](#fd_fxp_sqrt_rnz_fast) function performs the actual computation of the square root using a fast method.
- **Output**: Returns the square root of the input `x` as an unsigned long integer, rounded according to the fast rounding mode.
- **Functions called**:
    - [`fd_fxp_sqrt_rnz_fast`](#fd_fxp_sqrt_rnz_fast)


---
### fd\_fxp\_sqrt\_rdn<!-- {{#callable:fd_fxp_sqrt_rdn}} -->
The `fd_fxp_sqrt_rdn` function computes the square root of a fixed-point number, rounding down.
- **Inputs**:
    - `x`: An unsigned long integer representing the fixed-point number for which the square root is to be calculated.
- **Control Flow**:
    - The function first calls [`fd_fxp_sqrt_rtz`](#fd_fxp_sqrt_rtz) to compute the square root with round-toward-zero behavior.
    - The result from [`fd_fxp_sqrt_rtz`](#fd_fxp_sqrt_rtz) is returned directly as the output.
- **Output**: Returns an unsigned long integer representing the square root of the input `x`, rounded down.
- **Functions called**:
    - [`fd_fxp_sqrt_rtz`](#fd_fxp_sqrt_rtz)


---
### fd\_fxp\_sqrt\_rup<!-- {{#callable:fd_fxp_sqrt_rup}} -->
Calculates the square root of a fixed-point number, rounding up.
- **Inputs**:
    - `x`: An unsigned long integer representing the fixed-point number for which the square root is to be calculated.
- **Control Flow**:
    - The function calls [`fd_fxp_sqrt_raz`](#fd_fxp_sqrt_raz) to compute the square root with rounding away from zero.
    - The [`fd_fxp_sqrt_raz`](#fd_fxp_sqrt_raz) function performs the actual square root calculation and handles the rounding logic.
- **Output**: Returns an unsigned long integer representing the rounded-up square root of the input fixed-point number.
- **Functions called**:
    - [`fd_fxp_sqrt_raz`](#fd_fxp_sqrt_raz)


---
### fd\_fxp\_sqrt\_rnd<!-- {{#callable:fd_fxp_sqrt_rnd}} -->
Computes the square root of a fixed-point number with rounding.
- **Inputs**:
    - `x`: An unsigned long integer representing the fixed-point number for which the square root is to be calculated.
- **Control Flow**:
    - If `x` is zero, the function immediately returns zero.
    - The function calculates an initial guess for the square root based on the most significant bit of `x`.
    - If the initial guess is sufficient (i.e., `s` equals 15), it returns the guess directly.
    - If further refinement is needed, it enters a loop where it iteratively improves the guess using a fixed-point iteration formula until convergence is achieved.
- **Output**: Returns the computed square root of `x`, rounded according to the specified rounding mode.
- **Functions called**:
    - [`fd_fxp_sqrt_rnz`](#fd_fxp_sqrt_rnz)


---
### fd\_fxp\_sqrt\_rnu<!-- {{#callable:fd_fxp_sqrt_rnu}} -->
Computes the square root of a fixed-point number using the [`fd_fxp_sqrt_rnz`](#fd_fxp_sqrt_rnz) function.
- **Inputs**:
    - `x`: An unsigned long integer representing the fixed-point number for which the square root is to be calculated.
- **Control Flow**:
    - The function calls [`fd_fxp_sqrt_rnz`](#fd_fxp_sqrt_rnz) with the input `x`.
    - The [`fd_fxp_sqrt_rnz`](#fd_fxp_sqrt_rnz) function performs the actual computation of the square root.
- **Output**: Returns the square root of the input fixed-point number as an unsigned long integer.
- **Functions called**:
    - [`fd_fxp_sqrt_rnz`](#fd_fxp_sqrt_rnz)


---
### fd\_fxp\_sqrt\_rdn\_fast<!-- {{#callable:fd_fxp_sqrt_rdn_fast}} -->
Computes the square root of a fixed-point number using round down fast method.
- **Inputs**:
    - `x`: An unsigned long integer representing the fixed-point number for which the square root is to be calculated.
- **Control Flow**:
    - Calls the [`fd_fxp_sqrt_rtz_fast`](#fd_fxp_sqrt_rtz_fast) function to compute the square root of `x`.
    - The [`fd_fxp_sqrt_rtz_fast`](#fd_fxp_sqrt_rtz_fast) function performs a left shift on `x` by 30 bits and then computes the square root using `fd_ulong_sqrt`.
- **Output**: Returns the computed square root as an unsigned long integer.
- **Functions called**:
    - [`fd_fxp_sqrt_rtz_fast`](#fd_fxp_sqrt_rtz_fast)


---
### fd\_fxp\_sqrt\_rup\_fast<!-- {{#callable:fd_fxp_sqrt_rup_fast}} -->
Computes the fixed-point square root of a given unsigned long integer using a fast approximation method.
- **Inputs**:
    - `x`: An unsigned long integer for which the square root is to be computed.
- **Control Flow**:
    - The function calls [`fd_fxp_sqrt_raz_fast`](#fd_fxp_sqrt_raz_fast) to compute the square root.
    - The [`fd_fxp_sqrt_raz_fast`](#fd_fxp_sqrt_raz_fast) function performs the square root calculation using a fast approximation method.
- **Output**: Returns the computed square root as an unsigned long integer.
- **Functions called**:
    - [`fd_fxp_sqrt_raz_fast`](#fd_fxp_sqrt_raz_fast)


---
### fd\_fxp\_sqrt\_rnd\_fast<!-- {{#callable:fd_fxp_sqrt_rnd_fast}} -->
Calculates the square root of a fixed-point number with rounding towards zero.
- **Inputs**:
    - `x`: An unsigned long integer representing the fixed-point number for which the square root is to be calculated.
- **Control Flow**:
    - The function first checks if the input `x` is zero, returning zero if true.
    - It calculates the scale factor `s` based on the most significant bit of `x` to avoid overflow during calculations.
    - An initial guess for the square root is computed using `fd_ulong_sqrt` and adjusted based on the scale factor.
    - If the scale factor indicates that no further iterations are needed, the function returns the computed square root.
    - If further iterations are needed, it enters a loop where it refines the guess using a fixed-point iteration until convergence is achieved.
- **Output**: Returns an unsigned long integer representing the square root of the input fixed-point number, rounded towards zero.
- **Functions called**:
    - [`fd_fxp_sqrt_rnz_fast`](#fd_fxp_sqrt_rnz_fast)


---
### fd\_fxp\_sqrt\_rnu\_fast<!-- {{#callable:fd_fxp_sqrt_rnu_fast}} -->
Computes the square root of a fixed-point number using a fast rounding mode.
- **Inputs**:
    - `x`: An unsigned long integer representing the fixed-point number for which the square root is to be calculated.
- **Control Flow**:
    - The function calls [`fd_fxp_sqrt_rnz_fast`](#fd_fxp_sqrt_rnz_fast) to compute the square root.
    - The [`fd_fxp_sqrt_rnz_fast`](#fd_fxp_sqrt_rnz_fast) function performs the square root calculation using a fast method.
- **Output**: Returns the square root of the input fixed-point number as an unsigned long integer.
- **Functions called**:
    - [`fd_fxp_sqrt_rnz_fast`](#fd_fxp_sqrt_rnz_fast)


---
### fd\_fxp\_log2\_approx<!-- {{#callable:fd_fxp_log2_approx}} -->
Approximates the logarithm base 2 of a fixed-point number.
- **Inputs**:
    - `x`: A non-zero unsigned long integer representing the fixed-point number for which the logarithm is to be calculated.
    - `_e`: A pointer to an integer where the exponent part of the logarithm will be stored.
- **Control Flow**:
    - Checks if the input `x` is zero; if so, sets `_e` to INT_MIN and returns 0.
    - Finds the index of the most significant bit of `x` to determine the integer part of the logarithm.
    - Calculates `y`, which represents the fractional part of `x` after extracting the integer part.
    - Computes a fixed-point approximation of `x` using a derived formula involving `y`.
    - Uses a series of polynomial approximations to compute the fractional part of the logarithm.
    - Sets the exponent `_e` based on the integer part calculated earlier and returns the final approximation.
- **Output**: Returns an unsigned long integer representing the fixed-point approximation of log2(x) scaled by 2^30.


---
### fd\_fxp\_exp2\_approx<!-- {{#callable:fd_fxp_exp2_approx}} -->
`fd_fxp_exp2_approx` computes an approximate value of `exp2(x/2^30)` using a fixed-point representation.
- **Inputs**:
    - `x`: An unsigned long integer representing the fixed-point input value, where the upper bits represent the integer part and the lower 30 bits represent the fractional part.
- **Control Flow**:
    - The function first extracts the integer part `i` by right-shifting `x` by 30 bits.
    - If `i` is greater than or equal to 34, the function returns `ULONG_MAX` to indicate overflow.
    - The fractional part `d` is obtained by masking `x` with `(1UL << 30) - 1`.
    - A series of polynomial approximations are applied to compute `y`, which approximates `exp2(x/2^30)`.
    - The final result is computed by adjusting `y` based on the value of `i` and returning the appropriately scaled result.
- **Output**: Returns an unsigned long integer representing the approximate value of `exp2(x/2^30)`, or `ULONG_MAX` if the result would overflow.


---
### fd\_fxp\_rexp2\_approx<!-- {{#callable:fd_fxp_rexp2_approx}} -->
Approximates the value of exp2(-x/2^30) using a polynomial minimax approximation.
- **Inputs**:
    - `x`: An unsigned long integer representing the input value for which the exponential function is to be approximated.
- **Control Flow**:
    - The function first extracts the integer part `i` by right-shifting `x` by 30 bits.
    - If `i` is greater than or equal to 31, the function returns 0, indicating an overflow condition.
    - The fractional part `d` is obtained by masking `x` with ((1UL<<30)-1UL).
    - A series of polynomial calculations are performed to compute the approximation of exp2(-x/2^30) using the value of `d`.
    - The final result is computed by adjusting the polynomial result `y` based on the value of `i`.
- **Output**: Returns an unsigned long integer that approximates exp2(-x/2^30), or 0 if the input is too large.



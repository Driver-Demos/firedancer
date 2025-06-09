# Purpose
This C header file, `fd_float.h`, provides a set of utility functions for handling and manipulating IEEE-754 floating-point numbers, specifically focusing on single and double precision formats. The file includes functions to convert between floating-point numbers and their bitwise representations, extract components such as the sign, exponent, and mantissa, and classify the bit patterns into categories like zero, denormalized numbers, infinity, and NaN (Not a Number). The functions are designed to operate on the bit-level representation of floating-point numbers, allowing for precise control and manipulation of these values, which is particularly useful in environments where floating-point arithmetic needs to be handled with care, such as in low-level programming or systems with specific hardware constraints.

The file defines a series of inline functions that perform operations on 32-bit and 64-bit floating-point numbers, using unions to reinterpret the bit patterns. It provides a robust alternative to standard C library functions like `fpclassify`, ensuring consistent behavior across different compilers and hardware configurations. The header is structured to be included in other C source files, offering a public API for floating-point bit manipulation. It also includes conditional compilation for double precision operations, ensuring compatibility with systems that support 64-bit floating-point numbers. This file is a specialized utility for developers needing precise control over floating-point representations, often required in scientific computing, graphics, or systems programming.
# Imports and Dependencies

---
- `fd_bits.h`


# Functions

---
### fd\_fltbits<!-- {{#callable:fd_fltbits}} -->
The `fd_fltbits` function converts a floating-point number into its equivalent 32-bit unsigned integer representation.
- **Inputs**:
    - `f`: A floating-point number (float) to be converted into a 32-bit unsigned integer representation.
- **Control Flow**:
    - A union is defined with a 32-bit unsigned integer array and a float array, allowing for reinterpretation of the float as an integer.
    - The input float is assigned to the float array within the union.
    - The function returns the 32-bit unsigned integer representation of the float by accessing the integer array within the union.
- **Output**: A 32-bit unsigned integer (`ulong`) representing the bit pattern of the input float.


---
### fd\_fltbits\_sign<!-- {{#callable:fd_fltbits_sign}} -->
The `fd_fltbits_sign` function extracts the sign bit from a 32-bit unsigned integer representing a floating-point number in IEEE-754 format.
- **Inputs**:
    - `u`: A 32-bit unsigned integer representing a floating-point number in IEEE-754 format.
- **Control Flow**:
    - The function shifts the input `u` right by 31 bits, effectively isolating the most significant bit, which is the sign bit in IEEE-754 single precision format.
- **Output**: The function returns a 1-bit unsigned long integer representing the sign of the floating-point number, where 0 indicates a positive number and 1 indicates a negative number.


---
### fd\_fltbits\_bexp<!-- {{#callable:fd_fltbits_bexp}} -->
The `fd_fltbits_bexp` function extracts the biased exponent from a 32-bit unsigned integer representing a single-precision floating-point number.
- **Inputs**:
    - `u`: A 32-bit unsigned integer representing a single-precision floating-point number.
- **Control Flow**:
    - The function shifts the input `u` right by 23 bits to align the biased exponent bits to the least significant bits.
    - It then applies a bitwise AND operation with `255UL` to isolate the 8 bits of the biased exponent.
- **Output**: The function returns an 8-bit unsigned long integer representing the biased exponent of the input floating-point number.


---
### fd\_fltbits\_mant<!-- {{#callable:fd_fltbits_mant}} -->
The `fd_fltbits_mant` function extracts the 23-bit mantissa from a 32-bit unsigned integer representing a floating-point number in IEEE-754 single precision format.
- **Inputs**:
    - `u`: A 32-bit unsigned integer representing a floating-point number in IEEE-754 single precision format.
- **Control Flow**:
    - The function performs a bitwise AND operation between the input `u` and the constant `8388607UL` (which is `0x7FFFFF` in hexadecimal) to isolate the 23 least significant bits, which represent the mantissa in the IEEE-754 single precision format.
- **Output**: The function returns a 23-bit unsigned long integer representing the mantissa of the input floating-point number.


---
### fd\_fltbits\_unbias<!-- {{#callable:fd_fltbits_unbias}} -->
The `fd_fltbits_unbias` function converts an 8-bit biased exponent to its corresponding unbiased exponent by subtracting 127.
- **Inputs**:
    - `b`: An 8-bit unsigned long integer representing a biased exponent.
- **Control Flow**:
    - The function takes the input `b`, which is an 8-bit biased exponent.
    - It converts `b` to a long integer and subtracts 127 from it to obtain the unbiased exponent.
- **Output**: A long integer representing the unbiased exponent, which ranges from -127 to 128.


---
### fd\_fltbits\_bias<!-- {{#callable:fd_fltbits_bias}} -->
The `fd_fltbits_bias` function calculates the biased exponent for a given unbiased exponent in the IEEE-754 single precision floating-point format.
- **Inputs**:
    - `e`: An integer representing the unbiased exponent, which should be in the range [-127, 128].
- **Control Flow**:
    - The function takes a single input, `e`, which is an unbiased exponent.
    - It adds 127 to the input `e` to convert it to a biased exponent, as per the IEEE-754 single precision floating-point format.
    - The result is cast to an `ulong` type and returned.
- **Output**: The function returns an `ulong` representing the biased exponent corresponding to the input unbiased exponent.


---
### fd\_fltbits\_pack<!-- {{#callable:fd_fltbits_pack}} -->
The `fd_fltbits_pack` function combines a sign bit, a biased exponent, and a mantissa into a single 32-bit unsigned integer representing a floating-point number in IEEE-754 single precision format.
- **Inputs**:
    - `s`: A 1-bit unsigned long representing the sign bit of the floating-point number.
    - `b`: An 8-bit unsigned long representing the biased exponent of the floating-point number.
    - `m`: A 23-bit unsigned long representing the mantissa of the floating-point number.
- **Control Flow**:
    - The function shifts the sign bit `s` 31 positions to the left.
    - The function shifts the biased exponent `b` 23 positions to the left.
    - The function performs a bitwise OR operation to combine the shifted sign bit, shifted biased exponent, and mantissa `m` into a single 32-bit unsigned long.
- **Output**: A 32-bit unsigned long representing the packed floating-point number in IEEE-754 single precision format.


---
### fd\_float<!-- {{#callable:fd_float}} -->
The `fd_float` function converts a 32-bit unsigned integer into a floating-point number by reinterpreting its bit pattern.
- **Inputs**:
    - `u`: A 32-bit unsigned integer whose bit pattern is to be reinterpreted as a float.
- **Control Flow**:
    - A union is defined with two members: an array of one unsigned integer and an array of one float.
    - The input unsigned integer `u` is cast to a 32-bit unsigned integer and assigned to the union's unsigned integer array.
    - The function returns the float from the union's float array, effectively reinterpreting the bit pattern of the input integer as a float.
- **Output**: A floating-point number that shares the same bit pattern as the input unsigned integer.


---
### fd\_fltbits\_is\_zero<!-- {{#callable:fd_fltbits_is_zero}} -->
The `fd_fltbits_is_zero` function checks if a given 32-bit unsigned integer, representing the bit pattern of a floating-point number, corresponds to a zero value in IEEE-754 single precision format.
- **Inputs**:
    - `u`: A 32-bit unsigned integer representing the bit pattern of a floating-point number.
- **Control Flow**:
    - The function calls `fd_fltbits_bexp(u)` to extract the biased exponent from the input bit pattern.
    - It checks if the biased exponent is zero, which is a condition for zero or denormal numbers in IEEE-754 format.
    - The function calls `fd_fltbits_mant(u)` to extract the mantissa from the input bit pattern.
    - It checks if the mantissa is zero, which is a condition for zero numbers in IEEE-754 format.
    - The function returns the result of a bitwise AND operation between the two conditions, indicating if the input represents a zero value.
- **Output**: Returns 1 if the input bit pattern represents a zero value (either +0 or -0) in IEEE-754 single precision format, otherwise returns 0.
- **Functions called**:
    - [`fd_fltbits_bexp`](#fd_fltbits_bexp)
    - [`fd_fltbits_mant`](#fd_fltbits_mant)


---
### fd\_fltbits\_is\_denorm<!-- {{#callable:fd_fltbits_is_denorm}} -->
The function `fd_fltbits_is_denorm` checks if a given 32-bit unsigned integer, representing the bit pattern of a floating-point number, corresponds to a denormalized number in IEEE-754 single precision format.
- **Inputs**:
    - `u`: A 32-bit unsigned integer representing the bit pattern of a floating-point number.
- **Control Flow**:
    - Extracts the biased exponent from the input using `fd_fltbits_bexp(u)` and checks if it is zero.
    - Extracts the mantissa from the input using `fd_fltbits_mant(u)` and checks if it is non-zero.
    - Returns the result of a bitwise AND operation between the two checks, indicating if the number is denormalized.
- **Output**: Returns 1 if the input represents a denormalized floating-point number, otherwise returns 0.
- **Functions called**:
    - [`fd_fltbits_bexp`](#fd_fltbits_bexp)
    - [`fd_fltbits_mant`](#fd_fltbits_mant)


---
### fd\_fltbits\_is\_inf<!-- {{#callable:fd_fltbits_is_inf}} -->
The `fd_fltbits_is_inf` function checks if a given 32-bit unsigned integer, representing the bit pattern of a floating-point number, corresponds to positive or negative infinity in IEEE-754 single precision format.
- **Inputs**:
    - `u`: A 32-bit unsigned integer representing the bit pattern of a floating-point number.
- **Control Flow**:
    - The function extracts the biased exponent from the input using `fd_fltbits_bexp(u)` and checks if it equals 255, which is the biased exponent for infinity in IEEE-754 single precision format.
    - It then extracts the mantissa from the input using `fd_fltbits_mant(u)` and checks if it equals 0, which is required for the number to be classified as infinity.
    - The function returns the result of a bitwise AND operation between the two conditions, indicating if both are true.
- **Output**: The function returns an integer value of 1 if the input represents positive or negative infinity, otherwise it returns 0.
- **Functions called**:
    - [`fd_fltbits_bexp`](#fd_fltbits_bexp)
    - [`fd_fltbits_mant`](#fd_fltbits_mant)


---
### fd\_fltbits\_is\_nan<!-- {{#callable:fd_fltbits_is_nan}} -->
The `fd_fltbits_is_nan` function checks if a given 32-bit unsigned integer, representing the bit pattern of a floating-point number, corresponds to a NaN (Not-a-Number) value in IEEE-754 single precision format.
- **Inputs**:
    - `u`: A 32-bit unsigned integer representing the bit pattern of a floating-point number.
- **Control Flow**:
    - The function extracts the biased exponent from the input using `fd_fltbits_bexp(u)` and checks if it equals 255, which is the maximum value for the exponent in IEEE-754 single precision format, indicating a special value (infinity or NaN).
    - It then extracts the mantissa using `fd_fltbits_mant(u)` and checks if it is not equal to 0, which differentiates NaN from infinity (where the mantissa would be 0).
    - The function returns the result of a bitwise AND operation between the two conditions, which will be 1 if both conditions are true (indicating a NaN) and 0 otherwise.
- **Output**: An integer value, 1 if the input represents a NaN value, and 0 otherwise.
- **Functions called**:
    - [`fd_fltbits_bexp`](#fd_fltbits_bexp)
    - [`fd_fltbits_mant`](#fd_fltbits_mant)


---
### fd\_fltbits\_is\_normal<!-- {{#callable:fd_fltbits_is_normal}} -->
The function `fd_fltbits_is_normal` checks if a given 32-bit unsigned integer representing a floating-point number is a normal number according to IEEE-754 standards.
- **Inputs**:
    - `u`: A 32-bit unsigned integer representing the bit pattern of a floating-point number.
- **Control Flow**:
    - The function calls [`fd_fltbits_is_zero`](#fd_fltbits_is_zero) with `u` to check if the number is zero.
    - It calls [`fd_fltbits_is_denorm`](#fd_fltbits_is_denorm) with `u` to check if the number is denormalized.
    - It calls [`fd_fltbits_is_inf`](#fd_fltbits_is_inf) with `u` to check if the number is infinite.
    - It calls [`fd_fltbits_is_nan`](#fd_fltbits_is_nan) with `u` to check if the number is NaN.
    - The function returns the logical AND of the negations of the results from the above checks, indicating the number is normal if none of these conditions are true.
- **Output**: Returns 1 if the input represents a normal floating-point number, otherwise returns 0.
- **Functions called**:
    - [`fd_fltbits_is_zero`](#fd_fltbits_is_zero)
    - [`fd_fltbits_is_denorm`](#fd_fltbits_is_denorm)
    - [`fd_fltbits_is_inf`](#fd_fltbits_is_inf)
    - [`fd_fltbits_is_nan`](#fd_fltbits_is_nan)


---
### fd\_dblbits<!-- {{#callable:fd_dblbits}} -->
The `fd_dblbits` function converts a double-precision floating-point number into its equivalent 64-bit unsigned integer representation by reinterpreting the bit pattern.
- **Inputs**:
    - `f`: A double-precision floating-point number to be converted into its 64-bit unsigned integer bit representation.
- **Control Flow**:
    - A union is defined with two members: an array of one `ulong` and an array of one `double`.
    - The input double `f` is assigned to the double array member of the union.
    - The function returns the `ulong` representation of the double by accessing the `ulong` array member of the union.
- **Output**: A 64-bit unsigned integer (`ulong`) representing the bit pattern of the input double-precision floating-point number.


---
### fd\_dblbits\_sign<!-- {{#callable:fd_dblbits_sign}} -->
The `fd_dblbits_sign` function extracts the sign bit from a 64-bit unsigned integer representing a double-precision floating-point number.
- **Inputs**:
    - `u`: A 64-bit unsigned integer representing the bit pattern of a double-precision floating-point number.
- **Control Flow**:
    - The function performs a right bitwise shift of 63 positions on the input `u`.
- **Output**: The function returns a 1-bit unsigned long integer representing the sign bit of the double-precision floating-point number.


---
### fd\_dblbits\_bexp<!-- {{#callable:fd_dblbits_bexp}} -->
The function `fd_dblbits_bexp` extracts the 11-bit biased exponent from a 64-bit unsigned integer representing a double-precision floating-point number.
- **Inputs**:
    - `u`: A 64-bit unsigned integer representing the bit pattern of a double-precision floating-point number.
- **Control Flow**:
    - The function shifts the input `u` right by 52 bits to align the exponent bits to the least significant bits.
    - It then applies a bitwise AND operation with `2047UL` (which is `0x7FF` in hexadecimal) to isolate the 11-bit biased exponent.
- **Output**: The function returns the 11-bit biased exponent extracted from the input.


---
### fd\_dblbits\_mant<!-- {{#callable:fd_dblbits_mant}} -->
The `fd_dblbits_mant` function extracts the 52-bit mantissa from a 64-bit unsigned integer representing a double-precision floating-point number.
- **Inputs**:
    - `u`: A 64-bit unsigned integer representing the bit pattern of a double-precision floating-point number.
- **Control Flow**:
    - The function performs a bitwise AND operation between the input `u` and the constant `4503599627370495UL` (which is `0xFFFFFFFFFFFFF` in hexadecimal) to isolate the lower 52 bits of `u`.
- **Output**: The function returns a 52-bit unsigned long integer representing the mantissa of the double-precision floating-point number.


---
### fd\_dblbits\_unbias<!-- {{#callable:fd_dblbits_unbias}} -->
The function `fd_dblbits_unbias` converts a biased 11-bit exponent to an unbiased exponent for double precision floating-point numbers.
- **Inputs**:
    - `b`: An 11-bit unsigned long integer representing a biased exponent.
- **Control Flow**:
    - The function takes the input `b`, which is a biased exponent.
    - It converts `b` to a long integer and subtracts 1023 from it to obtain the unbiased exponent.
- **Output**: A long integer representing the unbiased exponent, which ranges from -1023 to 1024.


---
### fd\_dblbits\_bias<!-- {{#callable:fd_dblbits_bias}} -->
The `fd_dblbits_bias` function calculates the biased exponent for a given unbiased exponent in double precision floating-point representation.
- **Inputs**:
    - `e`: A long integer representing the unbiased exponent, which ranges from -1023 to 1024.
- **Control Flow**:
    - The function takes an input `e`, which is an unbiased exponent.
    - It adds 1023 to `e` to convert it to a biased exponent as per IEEE-754 double precision format.
    - The result is cast to an unsigned long integer and returned.
- **Output**: An unsigned long integer representing the biased exponent, which is an 11-bit value.


---
### fd\_dblbits\_pack<!-- {{#callable:fd_dblbits_pack}} -->
The `fd_dblbits_pack` function combines a sign bit, a biased exponent, and a mantissa into a single 64-bit unsigned long integer representing a double-precision floating-point number.
- **Inputs**:
    - `s`: A 1-bit unsigned long representing the sign of the double-precision floating-point number.
    - `b`: An 11-bit unsigned long representing the biased exponent of the double-precision floating-point number.
    - `m`: A 52-bit unsigned long representing the mantissa of the double-precision floating-point number.
- **Control Flow**:
    - The function shifts the sign bit `s` 63 positions to the left.
    - The function shifts the biased exponent `b` 52 positions to the left.
    - The function performs a bitwise OR operation to combine the shifted sign, shifted biased exponent, and mantissa into a single 64-bit unsigned long integer.
- **Output**: A 64-bit unsigned long integer representing the packed double-precision floating-point number.


---
### fd\_double<!-- {{#callable:fd_double}} -->
The `fd_double` function reinterprets a 64-bit unsigned integer as a double-precision floating-point number without changing the bit pattern.
- **Inputs**:
    - `u`: A 64-bit unsigned integer representing the bit pattern of a double-precision floating-point number.
- **Control Flow**:
    - A union is defined with two members: an array of one 64-bit unsigned integer and an array of one double.
    - The input unsigned integer `u` is assigned to the first element of the union's unsigned integer array.
    - The function returns the first element of the union's double array, effectively reinterpreting the bit pattern of `u` as a double.
- **Output**: A double-precision floating-point number that shares the same bit pattern as the input unsigned integer.


---
### fd\_dblbits\_is\_zero<!-- {{#callable:fd_dblbits_is_zero}} -->
The `fd_dblbits_is_zero` function checks if a given 64-bit unsigned integer, representing the bit pattern of a double-precision floating-point number, corresponds to a zero value.
- **Inputs**:
    - `u`: A 64-bit unsigned integer representing the bit pattern of a double-precision floating-point number.
- **Control Flow**:
    - The function calls `fd_dblbits_bexp(u)` to extract the biased exponent from the bit pattern and checks if it is zero.
    - It calls `fd_dblbits_mant(u)` to extract the mantissa from the bit pattern and checks if it is zero.
    - The function returns the result of a bitwise AND operation between the two checks, indicating if both the biased exponent and mantissa are zero.
- **Output**: The function returns an integer value of 1 if the input represents a zero value (both biased exponent and mantissa are zero), otherwise it returns 0.
- **Functions called**:
    - [`fd_dblbits_bexp`](#fd_dblbits_bexp)
    - [`fd_dblbits_mant`](#fd_dblbits_mant)


---
### fd\_dblbits\_is\_denorm<!-- {{#callable:fd_dblbits_is_denorm}} -->
The function `fd_dblbits_is_denorm` checks if a given 64-bit unsigned integer representing a double-precision floating-point number is a denormalized number.
- **Inputs**:
    - `u`: A 64-bit unsigned integer representing the bit pattern of a double-precision floating-point number.
- **Control Flow**:
    - Extracts the biased exponent from the input using `fd_dblbits_bexp(u)` and checks if it is zero.
    - Extracts the mantissa from the input using `fd_dblbits_mant(u)` and checks if it is non-zero.
    - Returns the logical AND of the two conditions, indicating the number is denormalized if both are true.
- **Output**: Returns 1 if the input represents a denormalized double-precision floating-point number, otherwise returns 0.
- **Functions called**:
    - [`fd_dblbits_bexp`](#fd_dblbits_bexp)
    - [`fd_dblbits_mant`](#fd_dblbits_mant)


---
### fd\_dblbits\_is\_inf<!-- {{#callable:fd_dblbits_is_inf}} -->
The function `fd_dblbits_is_inf` checks if a given 64-bit unsigned integer representing a double-precision floating-point number is positive or negative infinity.
- **Inputs**:
    - `u`: A 64-bit unsigned integer representing the bit pattern of a double-precision floating-point number.
- **Control Flow**:
    - The function calls `fd_dblbits_bexp(u)` to extract the biased exponent from the input `u` and checks if it equals 2047, which is the biased exponent for infinity in double-precision floating-point representation.
    - The function calls `fd_dblbits_mant(u)` to extract the mantissa from the input `u` and checks if it equals 0, which is required for the number to be classified as infinity.
    - The function returns the result of a bitwise AND operation between the two conditions, indicating if both conditions are true.
- **Output**: The function returns an integer value of 1 if the input represents positive or negative infinity, otherwise it returns 0.
- **Functions called**:
    - [`fd_dblbits_bexp`](#fd_dblbits_bexp)
    - [`fd_dblbits_mant`](#fd_dblbits_mant)


---
### fd\_dblbits\_is\_nan<!-- {{#callable:fd_dblbits_is_nan}} -->
The function `fd_dblbits_is_nan` checks if a given 64-bit unsigned integer, representing a double-precision floating-point number, is a NaN (Not a Number).
- **Inputs**:
    - `u`: A 64-bit unsigned integer representing the bit pattern of a double-precision floating-point number.
- **Control Flow**:
    - The function calls `fd_dblbits_bexp(u)` to extract the biased exponent from the input `u`.
    - It checks if the biased exponent is equal to 2047, which is the maximum value for the exponent in double-precision, indicating a special value (infinity or NaN).
    - The function calls `fd_dblbits_mant(u)` to extract the mantissa from the input `u`.
    - It checks if the mantissa is not equal to 0, which differentiates NaN from infinity (where the mantissa would be 0).
    - The function returns the result of a bitwise AND operation between the two conditions, indicating if the input represents a NaN.
- **Output**: An integer value, 1 if the input represents a NaN, otherwise 0.
- **Functions called**:
    - [`fd_dblbits_bexp`](#fd_dblbits_bexp)
    - [`fd_dblbits_mant`](#fd_dblbits_mant)


---
### fd\_dblbits\_is\_normal<!-- {{#callable:fd_dblbits_is_normal}} -->
The function `fd_dblbits_is_normal` checks if a given 64-bit unsigned integer representing a double-precision floating-point number is a normal number according to IEEE-754 standards.
- **Inputs**:
    - `u`: A 64-bit unsigned integer representing the bit pattern of a double-precision floating-point number.
- **Control Flow**:
    - The function calls [`fd_dblbits_is_zero`](#fd_dblbits_is_zero) with `u` to check if the number is zero.
    - It calls [`fd_dblbits_is_denorm`](#fd_dblbits_is_denorm) with `u` to check if the number is denormalized.
    - It calls [`fd_dblbits_is_inf`](#fd_dblbits_is_inf) with `u` to check if the number is infinite.
    - It calls [`fd_dblbits_is_nan`](#fd_dblbits_is_nan) with `u` to check if the number is NaN.
    - The function returns the logical AND of the negations of the results from the above checks, indicating the number is normal if none of these conditions are true.
- **Output**: Returns 1 if the number is normal, otherwise returns 0.
- **Functions called**:
    - [`fd_dblbits_is_zero`](#fd_dblbits_is_zero)
    - [`fd_dblbits_is_denorm`](#fd_dblbits_is_denorm)
    - [`fd_dblbits_is_inf`](#fd_dblbits_is_inf)
    - [`fd_dblbits_is_nan`](#fd_dblbits_is_nan)



# Purpose
This C source code file is designed to perform and test saturated arithmetic operations on various integer types, including `ulong`, `long`, `uint`, and `uint128`, if the platform supports 128-bit integers. The file includes functions that implement saturated addition, subtraction, and multiplication for these types, ensuring that operations do not overflow or underflow beyond the limits of the data types. The code uses inline functions to define these operations, which are then tested against reference implementations to verify correctness. The main function orchestrates these tests, using a random number generator to create test cases that stress the limits of the arithmetic operations.

The file is structured as an executable C program, with a [`main`](#main) function that serves as the entry point. It includes a series of macros to automate the testing of each arithmetic operation across different data types. The code is designed to be robust, with logging mechanisms to report errors if the results of the operations deviate from expected outcomes. Additionally, the code is conditional on the availability of 128-bit integer support, and it gracefully handles cases where this feature is not available by skipping the tests. This file is a comprehensive test suite for verifying the correctness and reliability of saturated arithmetic operations in environments that support extended integer types.
# Imports and Dependencies

---
- `../fd_util.h`
- `math.h`


# Functions

---
### make\_test\_rand\_ulong<!-- {{#callable:make_test_rand_ulong}} -->
The `make_test_rand_ulong` function generates a modified 64-bit unsigned long integer by applying random bit shifts and optional inversion based on control bits.
- **Inputs**:
    - `x`: A 64-bit unsigned long integer that serves as the base random value to be modified.
    - `_ctl`: A pointer to a 32-bit unsigned integer that contains control bits used to determine the shift amount, direction, and inversion of the input value.
- **Control Flow**:
    - Extract the least significant 8 bits from the control integer pointed to by `_ctl` and store it in `ctl`.
    - Determine the shift amount `s` by taking the least significant 6 bits of `ctl` and then right-shift `ctl` by 6 bits.
    - Determine the shift direction `d` by taking the least significant bit of `ctl` and then right-shift `ctl` by 1 bit.
    - Determine whether to invert the result `i` by taking the least significant bit of `ctl` and then right-shift `ctl` by 1 bit.
    - Update the original control integer pointed to by `_ctl` with the modified `ctl`.
    - Shift the input `x` left by `s` bits if `d` is 1, otherwise shift it right by `s` bits.
    - Return the bitwise NOT of `x` if `i` is 1, otherwise return `x` as is.
- **Output**: A 64-bit unsigned long integer that has been randomly modified by shifting and possibly inverting the input value `x`.


---
### make\_test\_rand\_uint<!-- {{#callable:make_test_rand_uint}} -->
The `make_test_rand_uint` function generates a modified random 32-bit unsigned integer by applying bitwise operations based on control bits from a given control variable.
- **Inputs**:
    - `x`: A random 32-bit unsigned integer that will be modified.
    - `_ctl`: A pointer to a control variable containing at least 8 bits, which will be used to determine the operations applied to 'x'.
- **Control Flow**:
    - Extract the least significant 8 bits from the control variable pointed to by '_ctl'.
    - Determine the shift amount 's' by taking the least significant 5 bits of 'ctl' and then right shift 'ctl' by 6 bits.
    - Determine the direction 'd' by taking the least significant bit of 'ctl' and then right shift 'ctl' by 1 bit.
    - Determine the invert flag 'i' by taking the least significant bit of 'ctl' and then right shift 'ctl' by 1 bit.
    - Update the control variable pointed to by '_ctl' with the modified 'ctl'.
    - Shift 'x' left by 's' bits if 'd' is 1, otherwise shift 'x' right by 's' bits.
    - Invert 'x' if 'i' is 1, otherwise leave 'x' unchanged.
    - Return the modified 'x'.
- **Output**: A modified 32-bit unsigned integer based on the operations determined by the control variable.


---
### make\_test\_rand\_uint128<!-- {{#callable:make_test_rand_uint128}} -->
The `make_test_rand_uint128` function generates a modified 128-bit unsigned integer by applying random bit shifts and optional inversion based on control bits.
- **Inputs**:
    - `x`: A 128-bit unsigned integer that serves as the base value for random modification.
    - `_ctl`: A pointer to a 32-bit unsigned integer that contains control bits used to determine the shift amount, direction, and inversion.
- **Control Flow**:
    - Extract the least significant 8 bits from the control integer pointed to by `_ctl` and store it in `ctl`.
    - Determine the shift amount `s` by masking the lower 5 bits of `ctl` and then right-shift `ctl` by 6 bits.
    - Determine the shift direction `d` by masking the next bit of `ctl` and then right-shift `ctl` by 1 bit.
    - Determine whether to invert the result `i` by masking the next bit of `ctl` and then right-shift `ctl` by 1 bit.
    - Update the original control integer pointed to by `_ctl` with the modified `ctl`.
    - Shift the input `x` left by `s` bits if `d` is 1, otherwise shift it right by `s` bits.
    - Invert the result if `i` is 1, otherwise return the result as is.
- **Output**: A 128-bit unsigned integer that has been randomly modified by shifting and possibly inverting the input `x`.


---
### fd\_ulong\_sat\_add\_ref<!-- {{#callable:fd_ulong_sat_add_ref}} -->
The `fd_ulong_sat_add_ref` function performs a saturated addition of two unsigned long integers, returning the maximum possible value if an overflow occurs.
- **Inputs**:
    - `x`: The first unsigned long integer to be added.
    - `y`: The second unsigned long integer to be added.
- **Control Flow**:
    - Initialize a 128-bit unsigned integer `ref` with the value of `x`.
    - Add `y` to `ref`.
    - Check if `ref` exceeds `ULONG_MAX`.
    - If `ref` exceeds `ULONG_MAX`, return `ULONG_MAX`.
    - Otherwise, return the value of `ref` cast to an unsigned long.
- **Output**: The function returns the result of the addition as an unsigned long, or `ULONG_MAX` if the addition results in an overflow.


---
### fd\_ulong\_sat\_sub\_ref<!-- {{#callable:fd_ulong_sat_sub_ref}} -->
The `fd_ulong_sat_sub_ref` function performs a subtraction of two unsigned long integers and returns the result, ensuring that the result does not go below zero by saturating at zero if the second operand is greater than the first.
- **Inputs**:
    - `x`: The minuend, an unsigned long integer from which another unsigned long integer is to be subtracted.
    - `y`: The subtrahend, an unsigned long integer to be subtracted from the first unsigned long integer.
- **Control Flow**:
    - Initialize a 128-bit unsigned integer `ref` with the value of `x`.
    - Subtract `y` from `ref`.
    - Check if `y` is greater than `x`.
    - If `y` is greater than `x`, return 0 to prevent underflow.
    - Otherwise, cast `ref` to an unsigned long and return it as the result.
- **Output**: The function returns an unsigned long integer which is the result of the subtraction, saturated at zero if the subtraction would result in a negative value.


---
### fd\_ulong\_sat\_mul\_ref<!-- {{#callable:fd_ulong_sat_mul_ref}} -->
The `fd_ulong_sat_mul_ref` function performs a multiplication of two unsigned long integers with saturation, ensuring the result does not exceed the maximum value for an unsigned long integer.
- **Inputs**:
    - `x`: An unsigned long integer representing the first operand for multiplication.
    - `y`: An unsigned long integer representing the second operand for multiplication.
- **Control Flow**:
    - Initialize a 128-bit integer `ref` with the value of `x` and multiply it by `y`.
    - Check if either `x` or `y` is zero; if so, return 0 as the result of the multiplication.
    - Check for overflow conditions: if `ref` is less than `x` or `y`, or if dividing `ref` by `x` does not yield `y`, or if `ref` exceeds `ULONG_MAX`, return `ULONG_MAX`.
    - If none of the overflow conditions are met, return `ref` cast to an unsigned long integer.
- **Output**: The function returns the product of `x` and `y` as an unsigned long integer, saturated to `ULONG_MAX` if overflow occurs.


---
### fd\_long\_sat\_add\_ref<!-- {{#callable:fd_long_sat_add_ref}} -->
The `fd_long_sat_add_ref` function performs saturated addition of two long integers, ensuring the result does not exceed the limits of a long integer.
- **Inputs**:
    - `x`: The first long integer to be added.
    - `y`: The second long integer to be added.
- **Control Flow**:
    - Initialize an int128 variable `ref` with the value of `x`.
    - Add `y` to `ref`.
    - Check if `ref` exceeds `LONG_MAX`; if so, return `LONG_MAX`.
    - Check if `ref` is less than `LONG_MIN`; if so, return `LONG_MIN`.
    - If neither condition is met, cast `ref` to a long and return it.
- **Output**: The function returns a long integer which is the saturated sum of `x` and `y`, constrained within the range of a long integer.


---
### fd\_long\_sat\_sub\_ref<!-- {{#callable:fd_long_sat_sub_ref}} -->
The `fd_long_sat_sub_ref` function performs a subtraction of two long integers with saturation, ensuring the result does not exceed the limits of a long integer.
- **Inputs**:
    - `x`: The minuend, a long integer from which another long integer is subtracted.
    - `y`: The subtrahend, a long integer to be subtracted from the minuend.
- **Control Flow**:
    - Convert the input long integer `x` to a 128-bit integer `ref`.
    - Subtract the input long integer `y` from `ref`.
    - Check if `ref` exceeds `LONG_MAX`; if so, return `LONG_MAX`.
    - Check if `ref` is less than `LONG_MIN`; if so, return `LONG_MIN`.
    - If `ref` is within the range of a long integer, cast `ref` back to a long and return it.
- **Output**: The function returns a long integer that is the saturated result of subtracting `y` from `x`, constrained within the range of `LONG_MIN` to `LONG_MAX`.


---
### fd\_uint\_sat\_add\_ref<!-- {{#callable:fd_uint_sat_add_ref}} -->
The `fd_uint_sat_add_ref` function performs saturated addition of two unsigned integers, returning the maximum unsigned integer value if overflow occurs.
- **Inputs**:
    - `x`: An unsigned integer to be added.
    - `y`: Another unsigned integer to be added.
- **Control Flow**:
    - Initialize a 128-bit unsigned integer `ref` with the value of `x`.
    - Add `y` to `ref`.
    - Check if `ref` exceeds `UINT_MAX`.
    - If `ref` exceeds `UINT_MAX`, return `UINT_MAX`.
    - Otherwise, cast `ref` to a 32-bit unsigned integer and return it.
- **Output**: The function returns the result of the saturated addition of `x` and `y`, which is either the sum if no overflow occurs or `UINT_MAX` if overflow occurs.


---
### fd\_uint\_sat\_sub\_ref<!-- {{#callable:fd_uint_sat_sub_ref}} -->
The `fd_uint_sat_sub_ref` function performs a subtraction of two unsigned integers with saturation, returning zero if the result would be negative.
- **Inputs**:
    - `x`: The minuend, an unsigned integer from which another unsigned integer is to be subtracted.
    - `y`: The subtrahend, an unsigned integer to be subtracted from the minuend.
- **Control Flow**:
    - Initialize a 128-bit unsigned integer `ref` with the value of `x`.
    - Subtract `y` from `ref`.
    - Check if `y` is greater than `x`.
    - If `y` is greater than `x`, return 0 to indicate saturation at zero.
    - Otherwise, cast `ref` to a 32-bit unsigned integer and return it.
- **Output**: The function returns the result of the subtraction as a 32-bit unsigned integer, or zero if the subtraction would result in a negative value.


---
### fd\_uint\_sat\_mul\_ref<!-- {{#callable:fd_uint_sat_mul_ref}} -->
The `fd_uint_sat_mul_ref` function performs a saturated multiplication of two unsigned integers, returning the maximum unsigned integer value if an overflow occurs.
- **Inputs**:
    - `x`: An unsigned integer representing the first operand for multiplication.
    - `y`: An unsigned integer representing the second operand for multiplication.
- **Control Flow**:
    - Initialize a variable `ref` of type `ulong` with the value of `x` and multiply it by `y`.
    - Check if either `x` or `y` is zero; if so, return 0 as the result.
    - Check for overflow conditions: if `ref` is less than `x` or `y`, or if dividing `ref` by `x` does not yield `y`, or if `ref` exceeds `UINT_MAX`, return `UINT_MAX`.
    - If none of the overflow conditions are met, cast `ref` to `uint` and return it as the result.
- **Output**: The function returns an unsigned integer which is the result of the saturated multiplication of `x` and `y`, or `UINT_MAX` if an overflow occurs.


---
### fd\_uint128\_sat\_add\_ref<!-- {{#callable:fd_uint128_sat_add_ref}} -->
The `fd_uint128_sat_add_ref` function performs a saturated addition of two 128-bit unsigned integers, returning the maximum possible value if an overflow occurs.
- **Inputs**:
    - `x`: The first 128-bit unsigned integer to be added.
    - `y`: The second 128-bit unsigned integer to be added.
- **Control Flow**:
    - Calculate the sum of x and y and store it in res.
    - Check if the result res is less than x, which indicates an overflow has occurred.
    - If an overflow is detected, return UINT128_MAX; otherwise, return the calculated result res.
- **Output**: The function returns the result of the saturated addition of x and y, which is either the sum or UINT128_MAX if an overflow occurs.


---
### fd\_uint128\_sat\_mul\_ref<!-- {{#callable:fd_uint128_sat_mul_ref}} -->
The `fd_uint128_sat_mul_ref` function performs a multiplication of two 128-bit unsigned integers and returns the result, saturating to the maximum 128-bit value if an overflow occurs.
- **Inputs**:
    - `x`: The first 128-bit unsigned integer operand for multiplication.
    - `y`: The second 128-bit unsigned integer operand for multiplication.
- **Control Flow**:
    - Calculate the product of `x` and `y` and store it in `res`.
    - Determine if an overflow occurred by checking if both `x` and `y` are non-zero and if `res` is less than either `x` or `y`, or if dividing `res` by `x` does not yield `y`.
    - Use the `fd_uint128_if` function to return `UINT128_MAX` if an overflow is detected, otherwise return `res`.
- **Output**: The function returns the product of `x` and `y` as a 128-bit unsigned integer, or `UINT128_MAX` if an overflow occurs.


---
### fd\_uint128\_sat\_sub\_ref<!-- {{#callable:fd_uint128_sat_sub_ref}} -->
The `fd_uint128_sat_sub_ref` function performs a subtraction of two 128-bit unsigned integers and returns the result, ensuring that the result does not underflow by returning zero if the subtraction would result in a negative value.
- **Inputs**:
    - `x`: The minuend, a 128-bit unsigned integer.
    - `y`: The subtrahend, a 128-bit unsigned integer.
- **Control Flow**:
    - Subtracts `y` from `x` and stores the result in `res`.
    - Checks if `res` is greater than `x`, which would indicate an underflow (since `res` should be less than or equal to `x` if no underflow occurred).
    - Uses `fd_uint128_if` to return 0 if an underflow is detected (i.e., `res > x`), otherwise returns `res`.
- **Output**: Returns the result of the subtraction if no underflow occurs, otherwise returns 0.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, checks for the `FD_HAS_INT128` capability, and either runs a series of unit tests for saturated arithmetic operations or logs a warning and halts if the capability is not present.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Call `fd_boot` to initialize the environment with command-line arguments.
    - Check if `FD_HAS_INT128` is defined; if not, log a warning and halt execution.
    - Define a macro `TEST` to compare reference and actual results of saturated arithmetic operations.
    - Run a series of tests for `ulong`, `long`, `uint`, and `uint128` (if available) using the `TEST` macro to ensure correctness of arithmetic operations.
    - Initialize a random number generator and perform 100 million iterations of random tests for each arithmetic operation.
    - Log progress every 10 million iterations.
    - Delete the random number generator and log a success message if all tests pass.
    - Call `fd_halt` to clean up and exit the program.
- **Output**: The function returns an integer, specifically 0, indicating successful execution.



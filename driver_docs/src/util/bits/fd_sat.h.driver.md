# Purpose
This C header file, `fd_sat.h`, provides a collection of functions for performing saturating arithmetic operations on various data types, including `__uint128_t`, `ulong`, `long`, `uint`, and `double`. Saturating arithmetic operations are designed to handle overflow and underflow by capping the result at the maximum or minimum value representable by the data type, rather than wrapping around. This file defines functions for addition, subtraction, and multiplication, mimicking the behavior of Rust's saturating operations. The functions utilize built-in overflow detection mechanisms provided by the compiler, such as `__builtin_uaddl_overflow` and `__builtin_saddl_overflow`, to determine if an overflow has occurred and adjust the result accordingly.

The file is structured to be included in other C source files, providing a reusable API for saturating arithmetic operations. It includes conditional compilation to support 128-bit integers if available, and it uses inline functions to ensure efficient execution. The header file is part of a larger codebase, as indicated by the inclusion of `fd_bits.h` and the use of macros like `FD_PROTOTYPES_BEGIN` and `FD_PROTOTYPES_END`, which suggest a standardized way of defining function prototypes. The file also includes placeholders for future optimization and hardening, indicating that the current implementations are preliminary and may be improved over time.
# Imports and Dependencies

---
- `fd_bits.h`


# Functions

---
### fd\_uint128\_sat\_add<!-- {{#callable:__uint128_t::fd_uint128_sat_add}} -->
The `fd_uint128_sat_add` function performs a saturating addition of two 128-bit unsigned integers, returning the maximum possible value if an overflow occurs.
- **Inputs**:
    - `x`: The first operand, a 128-bit unsigned integer.
    - `y`: The second operand, a 128-bit unsigned integer.
- **Control Flow**:
    - Calculate the sum of x and y, storing the result in res.
    - Check if the result is less than x, which indicates an overflow has occurred.
    - If an overflow is detected, return UINT128_MAX; otherwise, return the calculated result.
- **Output**: The function returns the sum of x and y as a 128-bit unsigned integer, or UINT128_MAX if the addition overflows.


---
### fd\_uint128\_sat\_mul<!-- {{#callable:__uint128_t::fd_uint128_sat_mul}} -->
The `fd_uint128_sat_mul` function performs a saturating multiplication of two 128-bit unsigned integers, returning the maximum possible value if an overflow occurs.
- **Inputs**:
    - `x`: The first operand, a 128-bit unsigned integer.
    - `y`: The second operand, a 128-bit unsigned integer.
- **Control Flow**:
    - Calculate the product of x and y, storing the result in res.
    - Determine if an overflow occurred by checking if both x and y are non-zero and if res is less than either x or y, or if dividing res by x does not yield y.
    - Use the fd_uint128_if function to return UINT128_MAX if an overflow is detected, otherwise return the calculated product res.
- **Output**: The function returns a 128-bit unsigned integer, which is either the product of x and y or UINT128_MAX if an overflow is detected.


---
### fd\_uint128\_sat\_sub<!-- {{#callable:__uint128_t::fd_uint128_sat_sub}} -->
The `fd_uint128_sat_sub` function performs a saturating subtraction of two 128-bit unsigned integers, returning zero if the result would be negative.
- **Inputs**:
    - `x`: The minuend, a 128-bit unsigned integer.
    - `y`: The subtrahend, a 128-bit unsigned integer.
- **Control Flow**:
    - Calculate the result of subtracting `y` from `x` and store it in `res`.
    - Check if `res` is greater than `x`, which indicates an underflow occurred.
    - If underflow is detected, return 0; otherwise, return `res`.
- **Output**: The function returns the result of the subtraction if no underflow occurs; otherwise, it returns 0.


---
### fd\_ulong\_sat\_add<!-- {{#callable:fd_ulong_sat_add}} -->
The `fd_ulong_sat_add` function performs a saturating addition of two unsigned long integers, returning the maximum possible value if an overflow occurs.
- **Inputs**:
    - `x`: The first unsigned long integer to be added.
    - `y`: The second unsigned long integer to be added.
- **Control Flow**:
    - Declare a variable `res` to store the result of the addition.
    - Use the `__builtin_uaddl_overflow` function to add `x` and `y`, storing the result in `res` and checking for overflow, which is indicated by the return value `cf`.
    - If `cf` is true (indicating an overflow), return `ULONG_MAX`; otherwise, return the result `res`.
- **Output**: The function returns the result of adding `x` and `y`, or `ULONG_MAX` if the addition overflows.


---
### fd\_ulong\_sat\_mul<!-- {{#callable:fd_ulong_sat_mul}} -->
The `fd_ulong_sat_mul` function performs a multiplication of two unsigned long integers and returns the result, saturating to `ULONG_MAX` if an overflow occurs.
- **Inputs**:
    - `x`: The first unsigned long integer to be multiplied.
    - `y`: The second unsigned long integer to be multiplied.
- **Control Flow**:
    - The function attempts to multiply `x` and `y` using the `__builtin_umull_overflow` intrinsic, which checks for overflow and stores the result in `res`.
    - If an overflow is detected (`cf` is non-zero), the function returns `ULONG_MAX`.
    - If no overflow occurs, the function returns the computed result `res`.
- **Output**: The function returns the product of `x` and `y`, or `ULONG_MAX` if the multiplication overflows.


---
### fd\_ulong\_sat\_sub<!-- {{#callable:fd_ulong_sat_sub}} -->
The `fd_ulong_sat_sub` function performs a saturating subtraction of two unsigned long integers, returning zero if an underflow occurs.
- **Inputs**:
    - `x`: The minuend, an unsigned long integer.
    - `y`: The subtrahend, an unsigned long integer.
- **Control Flow**:
    - Declare a variable `res` to store the result of the subtraction.
    - Use the `__builtin_usubl_overflow` function to perform the subtraction of `x` and `y`, storing the result in `res` and checking for underflow, which sets `cf` to a non-zero value if underflow occurs.
    - Return the result of `fd_ulong_if`, which returns `0UL` if `cf` is non-zero (indicating underflow), otherwise returns `res`.
- **Output**: The function returns the result of the subtraction if no underflow occurs, otherwise it returns zero.


---
### fd\_long\_sat\_add<!-- {{#callable:fd_long_sat_add}} -->
The `fd_long_sat_add` function performs a saturating addition of two long integers, ensuring the result does not overflow.
- **Inputs**:
    - `x`: The first operand of type long for the addition.
    - `y`: The second operand of type long for the addition.
- **Control Flow**:
    - Declare a variable `res` to store the result of the addition.
    - Use the `__builtin_saddl_overflow` function to perform the addition of `x` and `y`, storing the result in `res` and checking for overflow, which is indicated by the variable `cf`.
    - If an overflow occurs (`cf` is true), determine the result based on the sign of `x` using a bitwise trick, returning either `LONG_MAX` or `LONG_MIN` to saturate the result.
    - If no overflow occurs, return the computed result `res`.
- **Output**: The function returns a long integer which is the result of the saturating addition of `x` and `y`, capped at `LONG_MAX` or `LONG_MIN` in case of overflow.


---
### fd\_long\_sat\_sub<!-- {{#callable:fd_long_sat_sub}} -->
The `fd_long_sat_sub` function performs a saturating subtraction of two long integers, ensuring the result does not overflow or underflow.
- **Inputs**:
    - `x`: The minuend, a long integer from which another long integer is to be subtracted.
    - `y`: The subtrahend, a long integer to be subtracted from the minuend.
- **Control Flow**:
    - The function uses the GCC built-in function `__builtin_ssubl_overflow` to perform the subtraction and check for overflow, storing the result in `res` and the overflow flag in `cf`.
    - If an overflow is detected (`cf` is non-zero), the function returns a saturated value based on the sign of `x`, calculated as `(long)((ulong)x >> 63) + LONG_MAX`.
    - If no overflow is detected, the function returns the result of the subtraction stored in `res`.
- **Output**: The function returns a long integer which is the result of the saturating subtraction of `x` and `y`, ensuring it does not exceed the limits of the long integer type.


---
### fd\_uint\_sat\_add<!-- {{#callable:fd_uint_sat_add}} -->
The `fd_uint_sat_add` function performs a saturating addition of two unsigned integers, returning the maximum possible value if an overflow occurs.
- **Inputs**:
    - `x`: The first unsigned integer operand for the addition.
    - `y`: The second unsigned integer operand for the addition.
- **Control Flow**:
    - The function attempts to add the two unsigned integers `x` and `y` using the `__builtin_uadd_overflow` intrinsic, which checks for overflow and stores the result in `res`.
    - If an overflow is detected (indicated by `cf` being non-zero), the function returns `UINT_MAX`, the maximum value for an unsigned integer.
    - If no overflow occurs, the function returns the result of the addition stored in `res`.
- **Output**: The function returns the result of the addition if no overflow occurs, otherwise it returns `UINT_MAX`.


---
### fd\_uint\_sat\_mul<!-- {{#callable:fd_uint_sat_mul}} -->
The `fd_uint_sat_mul` function performs a saturating multiplication of two unsigned integers, returning the maximum unsigned integer value if an overflow occurs.
- **Inputs**:
    - `x`: The first unsigned integer operand for multiplication.
    - `y`: The second unsigned integer operand for multiplication.
- **Control Flow**:
    - The function attempts to multiply `x` and `y` using the `__builtin_umul_overflow` intrinsic, which checks for overflow and stores the result in `res`.
    - If an overflow is detected (`cf` is non-zero), the function returns `UINT_MAX`.
    - If no overflow occurs, the function returns the result of the multiplication stored in `res`.
- **Output**: The function returns the product of `x` and `y` if no overflow occurs, otherwise it returns `UINT_MAX` to indicate saturation.


---
### fd\_uint\_sat\_sub<!-- {{#callable:fd_uint_sat_sub}} -->
The `fd_uint_sat_sub` function performs a saturating subtraction of two unsigned integers, returning zero if an underflow occurs.
- **Inputs**:
    - `x`: The minuend, an unsigned integer from which another unsigned integer is to be subtracted.
    - `y`: The subtrahend, an unsigned integer to be subtracted from the minuend.
- **Control Flow**:
    - The function uses the GCC built-in function `__builtin_usub_overflow` to attempt the subtraction of `y` from `x`, storing the result in `res` and setting `cf` to indicate if an underflow occurred.
    - If `cf` is true (indicating an underflow), the function returns 0; otherwise, it returns the result of the subtraction `res`.
- **Output**: The function returns the result of the subtraction if no underflow occurs, otherwise it returns 0.


---
### fd\_double\_sat\_add<!-- {{#callable:fd_double_sat_add}} -->
The `fd_double_sat_add` function performs addition on two double-precision floating-point numbers without implementing any saturation logic.
- **Inputs**:
    - `x`: The first double-precision floating-point number to be added.
    - `y`: The second double-precision floating-point number to be added.
- **Control Flow**:
    - The function takes two double arguments, `x` and `y`.
    - It computes the sum of `x` and `y` using the `+` operator.
    - The result of the addition is returned directly without any checks for overflow or saturation.
- **Output**: The function returns the sum of the two input double-precision floating-point numbers.


---
### fd\_double\_sat\_mul<!-- {{#callable:fd_double_sat_mul}} -->
The `fd_double_sat_mul` function performs a multiplication of two double precision floating-point numbers without implementing any saturation logic.
- **Inputs**:
    - `x`: The first double precision floating-point number to be multiplied.
    - `y`: The second double precision floating-point number to be multiplied.
- **Control Flow**:
    - The function takes two double precision floating-point numbers as input.
    - It multiplies the two input numbers together using the `*` operator.
    - The result of the multiplication is returned directly without any additional checks or logic.
- **Output**: The function returns the product of the two input double precision floating-point numbers as a double.


---
### fd\_double\_sat\_sub<!-- {{#callable:fd_double_sat_sub}} -->
The `fd_double_sat_sub` function performs a subtraction of two double precision floating-point numbers without implementing any saturation logic.
- **Inputs**:
    - `x`: The minuend, a double precision floating-point number.
    - `y`: The subtrahend, a double precision floating-point number.
- **Control Flow**:
    - The function takes two double precision floating-point numbers as input.
    - It calculates the result of subtracting the second number (y) from the first number (x).
    - The function returns the result of the subtraction without any additional checks or saturation logic.
- **Output**: The function returns the result of the subtraction as a double precision floating-point number.



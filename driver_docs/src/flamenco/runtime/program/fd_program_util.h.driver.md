# Purpose
This C header file, `native_program_util.h`, provides utility functions for performing arithmetic operations on unsigned long integers with overflow checking. The file is part of a larger codebase, likely related to the Firedancer project, as indicated by the inclusion of headers like `fd_flamenco_base.h` and `fd_executor_err.h`. The primary functionality offered by this file is to safely add and subtract unsigned long integers while handling potential overflow conditions. The functions [`fd_ulong_checked_add`](#fd_ulong_checked_add) and [`fd_ulong_checked_sub`](#FD_FN_UNUSEDfd_ulong_checked_sub) use built-in functions to detect overflow and return specific error codes if an overflow occurs. Additionally, the file provides variants of these functions, [`fd_ulong_checked_add_expect`](#fd_ulong_checked_add_expect) and [`fd_ulong_checked_sub_expect`](#fd_ulong_checked_sub_expect), which log an error message if an overflow is detected, using a provided expectation string.

The file is structured to be included in other C source files, as it defines inline functions and uses include guards to prevent multiple inclusions. It does not define a public API or external interface but rather serves as a utility component within a larger system, likely intended for internal use by other parts of the Firedancer project. The use of inline functions suggests a focus on performance, minimizing function call overhead for these arithmetic operations. The file's inclusion of error handling and logging mechanisms indicates its role in ensuring robust and reliable execution of arithmetic operations within the broader application context.
# Imports and Dependencies

---
- `../../fd_flamenco_base.h`
- `../fd_executor_err.h`


# Functions

---
### fd\_ulong\_checked\_add<!-- {{#callable:fd_ulong_checked_add}} -->
The `fd_ulong_checked_add` function performs an addition of two unsigned long integers and checks for overflow, returning a status code based on the result.
- **Inputs**:
    - `a`: The first unsigned long integer to be added.
    - `b`: The second unsigned long integer to be added.
    - `out`: A pointer to an unsigned long where the result of the addition will be stored if no overflow occurs.
- **Control Flow**:
    - The function uses the GCC built-in function `__builtin_uaddl_overflow` to add `a` and `b`, storing the result in the location pointed to by `out` and checking for overflow.
    - The result of the overflow check is stored in the integer `cf`.
    - The function returns a status code using `fd_int_if`, which returns `FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS` if overflow occurred (`cf` is true), or `FD_EXECUTOR_INSTR_SUCCESS` if no overflow occurred (`cf` is false).
- **Output**: An integer status code indicating success or overflow error.


---
### fd\_ulong\_checked\_sub<!-- {{#callable:FD_FN_UNUSED::fd_ulong_checked_sub}} -->
The `fd_ulong_checked_sub` function performs subtraction of two unsigned long integers with overflow checking and returns an error code if overflow occurs.
- **Inputs**:
    - `a`: The minuend, an unsigned long integer.
    - `b`: The subtrahend, an unsigned long integer.
    - `out`: A pointer to an unsigned long where the result of the subtraction will be stored if no overflow occurs.
- **Control Flow**:
    - The function uses the `__builtin_usubl_overflow` intrinsic to perform the subtraction of `b` from `a` and checks for overflow.
    - The result of the subtraction is stored in the location pointed to by `out` if no overflow occurs.
    - The function checks the overflow flag `cf` returned by `__builtin_usubl_overflow`.
    - If `cf` is true (indicating overflow), the function returns `FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS`.
    - If `cf` is false (indicating no overflow), the function returns `FD_EXECUTOR_INSTR_SUCCESS`.
- **Output**: The function returns an integer status code: `FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS` if overflow occurs, otherwise `FD_EXECUTOR_INSTR_SUCCESS`.


---
### fd\_ulong\_checked\_add\_expect<!-- {{#callable:fd_ulong_checked_add_expect}} -->
The `fd_ulong_checked_add_expect` function attempts to add two unsigned long integers and logs an error message if an overflow occurs.
- **Inputs**:
    - `a`: The first unsigned long integer to be added.
    - `b`: The second unsigned long integer to be added.
    - `expect`: A constant character string containing the error message to log if an overflow occurs.
- **Control Flow**:
    - Initialize `out` to `ULONG_MAX` to store the result of the addition.
    - Call [`fd_ulong_checked_add`](#fd_ulong_checked_add) with `a`, `b`, and `out` to perform the addition and check for overflow.
    - If an overflow is detected (indicated by a non-zero return value from [`fd_ulong_checked_add`](#fd_ulong_checked_add)), log the error message specified by `expect` using `FD_LOG_ERR`.
    - Return the value of `out`, which is either the sum of `a` and `b` or `ULONG_MAX` if an overflow occurred.
- **Output**: The function returns the sum of `a` and `b` if no overflow occurs; otherwise, it returns `ULONG_MAX`.
- **Functions called**:
    - [`fd_ulong_checked_add`](#fd_ulong_checked_add)


---
### fd\_ulong\_checked\_sub\_expect<!-- {{#callable:fd_ulong_checked_sub_expect}} -->
The `fd_ulong_checked_sub_expect` function performs a checked subtraction of two unsigned long integers and logs an error message if an overflow occurs.
- **Inputs**:
    - `a`: The minuend, an unsigned long integer.
    - `b`: The subtrahend, an unsigned long integer.
    - `expect`: A constant character string containing the error message to log if the subtraction overflows.
- **Control Flow**:
    - Initialize the variable `out` to `ULONG_MAX` to store the result of the subtraction.
    - Call [`fd_ulong_checked_sub`](#FD_FN_UNUSEDfd_ulong_checked_sub) with `a`, `b`, and `out` to perform the subtraction and check for overflow.
    - If [`fd_ulong_checked_sub`](#FD_FN_UNUSEDfd_ulong_checked_sub) indicates an overflow (using `FD_UNLIKELY` for branch prediction optimization), log the error message contained in `expect` using `FD_LOG_ERR`.
    - Return the value of `out`, which is either the result of the subtraction or `ULONG_MAX` if an overflow occurred.
- **Output**: The function returns the result of the subtraction if no overflow occurs, otherwise it returns `ULONG_MAX`.
- **Functions called**:
    - [`FD_FN_UNUSED::fd_ulong_checked_sub`](#FD_FN_UNUSEDfd_ulong_checked_sub)



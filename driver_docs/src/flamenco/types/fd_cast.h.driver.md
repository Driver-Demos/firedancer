# Purpose
This C header file defines a function for casting a `double` to an `unsigned long` using a saturating cast approach, similar to Rust's behavior since version 1.45. The function, [`fd_rust_cast_double_to_ulong`](#fd_rust_cast_double_to_ulong), ensures that if the `double` value is negative or NaN, it returns 0, and if the value exceeds `ULONG_MAX`, it returns `ULONG_MAX`. This approach prevents undefined behavior by handling edge cases explicitly, such as infinity and NaN, and is conditionally compiled only if `FD_HAS_DOUBLE` is defined. The file includes necessary utility functions from `fd_float.h` to manipulate the bit representation of the `double` for these checks.
# Imports and Dependencies

---
- `../../util/bits/fd_float.h`


# Functions

---
### fd\_rust\_cast\_double\_to\_ulong<!-- {{#callable:fd_rust_cast_double_to_ulong}} -->
The function `fd_rust_cast_double_to_ulong` casts a double to an unsigned long, saturating to 0 for negative or NaN values and to ULONG_MAX for values exceeding ULONG_MAX, mimicking Rust's saturating cast behavior.
- **Inputs**:
    - `f`: A double precision floating-point number to be cast to an unsigned long.
- **Control Flow**:
    - Convert the double `f` to its bit representation as an unsigned long `u`.
    - Check if the exponent part of `u` is all 1s, indicating infinity or NaN.
    - If the mantissa of `u` is 0, return `ULONG_MAX` (indicating infinity).
    - If the mantissa is not 0, return 0 (indicating NaN).
    - Check if the sign bit of `u` is 1, indicating a negative value, and return 0 if true.
    - Check if `f` is greater than or equal to `ULONG_MAX`, and return `ULONG_MAX` if true.
    - If none of the above conditions are met, cast `f` to an unsigned long and return it.
- **Output**: An unsigned long integer that is the result of casting the input double, with saturation applied for special cases.



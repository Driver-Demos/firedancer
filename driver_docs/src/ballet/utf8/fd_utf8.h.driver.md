# Purpose
This C header file defines a function prototype for [`fd_utf8_verify`](#fd_utf8_verify), which is designed to validate whether a given byte array contains valid UTF-8 encoded data. The function adheres to the UTF-8 validation rules similar to those used in Rust's `std::str::from_utf8`, ensuring that each code point is correctly encoded in one to four bytes, with specific ranges for each byte length. It also handles zero bytes as valid one-byte code points and checks for proper use of control and continuation characters, although it does not verify if the code points are valid Unicode characters. The header file includes necessary preprocessor directives to prevent multiple inclusions and relies on a base header file, `fd_ballet_base.h`, for additional dependencies or definitions.
# Imports and Dependencies

---
- `../fd_ballet_base.h`


# Function Declarations (Public API)

---
### fd\_utf8\_verify<!-- {{#callable_declaration:fd_utf8_verify}} -->
Checks if a byte array contains valid UTF-8 encoding.
- **Description**: Use this function to verify whether a given byte array adheres to UTF-8 encoding rules, as defined by Rust's std::str::from_utf8. It is suitable for validating strings that may contain zero bytes, which are treated as valid one-byte code points. The function does not check for valid Unicode characters beyond encoding rules. It should be called with a pointer to the byte array and the size of the array. The function assumes that the pointer and size do not cause overflow and ignores the pointer if the size is zero.
- **Inputs**:
    - `str`: A pointer to the first byte of the UTF-8 string. It must not be null unless the size is zero. The caller retains ownership of the data.
    - `sz`: The number of bytes in the string. It must be a non-negative value, and the function assumes that str+sz does not overflow.
- **Output**: Returns 1 if the byte array is valid UTF-8, otherwise returns 0.
- **See also**: [`fd_utf8_verify`](fd_utf8.c.driver.md#fd_utf8_verify)  (Implementation)



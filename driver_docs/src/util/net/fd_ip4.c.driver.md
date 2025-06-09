# Purpose
This C source code file provides a utility function for converting a string representation of an IPv4 address into its numerical form. The primary function, [`fd_cstr_to_ip4_addr`](#fd_cstr_to_ip4_addr), takes a string `s` representing an IPv4 address and converts it into a 32-bit unsigned integer, storing the result in the variable pointed to by `out`. The function uses a helper function, [`__fd_cstr_to_uchar`](#__fd_cstr_to_uchar), to convert each segment of the IP address from a string to an unsigned character, ensuring that each segment is within the valid range for an IPv4 address octet (0-255). The code includes basic error checking to ensure that the input string is correctly formatted and that each segment is a valid number.

The file includes headers for additional utilities and definitions, suggesting it is part of a larger codebase. The function [`fd_cstr_to_ip4_addr`](#fd_cstr_to_ip4_addr) is likely intended to be used by other components of the system that require IP address manipulation, providing a narrow but essential functionality within the broader context of network programming. The use of `FD_UNLIKELY` hints at performance considerations, likely optimizing for the common case where inputs are valid. The code does not define a public API or external interface directly but provides a utility function that could be part of a library for internal use within a larger application.
# Imports and Dependencies

---
- `fd_ip4.h`
- `../fd_util.h`
- `stdlib.h`


# Functions

---
### \_\_fd\_cstr\_to\_uchar<!-- {{#callable:__fd_cstr_to_uchar}} -->
The function `__fd_cstr_to_uchar` converts a string representation of a number to an unsigned char, returning -1 if the conversion is invalid or out of bounds.
- **Inputs**:
    - `cstr`: A constant character pointer to a null-terminated string representing a number to be converted to an unsigned char.
- **Control Flow**:
    - Initialize a pointer `endptr` to NULL for tracking the end of the parsed number.
    - Use `strtoul` to convert the string `cstr` to an unsigned long integer, storing the end of the parsed string in `endptr`.
    - Check if the conversion failed (i.e., `cstr` equals `endptr`), if there are leftover characters in the string (i.e., `endptr[0]` is not null), or if the value exceeds `UCHAR_MAX`.
    - If any of the above conditions are true, return -1 indicating an error.
    - If the conversion is successful and within bounds, return the converted value cast to an integer.
- **Output**: Returns an integer representing the converted unsigned char value, or -1 if the conversion is invalid or out of bounds.


---
### fd\_cstr\_to\_ip4\_addr<!-- {{#callable:fd_cstr_to_ip4_addr}} -->
The function `fd_cstr_to_ip4_addr` converts a string representation of an IPv4 address into a 32-bit unsigned integer format.
- **Inputs**:
    - `s`: A constant character pointer representing the string of the IPv4 address to be converted.
    - `out`: A pointer to an unsigned integer where the converted IPv4 address will be stored.
- **Control Flow**:
    - Copy the input string `s` into a local buffer `_s` with a maximum length of 15 characters, ensuring null-termination.
    - Tokenize the string `_s` using the period character '.' as a delimiter, expecting exactly 4 tokens.
    - Convert each token to an unsigned char using the helper function [`__fd_cstr_to_uchar`](#__fd_cstr_to_uchar).
    - Check if any conversion resulted in a negative value, indicating an error, and return 0 if so.
    - Combine the four converted values into a single 32-bit unsigned integer using the macro `FD_IP4_ADDR` and store it in the location pointed to by `out`.
    - Return 1 to indicate successful conversion.
- **Output**: Returns 1 if the conversion is successful and 0 if there is an error in the conversion process.
- **Functions called**:
    - [`__fd_cstr_to_uchar`](#__fd_cstr_to_uchar)



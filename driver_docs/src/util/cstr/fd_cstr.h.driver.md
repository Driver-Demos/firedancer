# Purpose
The provided C header file, `fd_cstr.h`, defines a comprehensive set of APIs for manipulating null-terminated character strings, commonly referred to as "cstr" in C programming. This file is designed to be included in other C source files, providing a broad range of functionalities for string conversion, manipulation, and utility operations. The header includes functions for converting strings to various data types, such as integers and floating-point numbers, with specific handling for different bases and formats. It also includes functions for hashing strings, comparing strings in a case-insensitive manner, and determining the length of strings without relying on POSIX support.

Additionally, the file provides functions for constructing and appending to strings, including formatted output similar to `printf`, and appending various data types as text. It also includes utilities for tokenizing strings based on delimiters and appending UTF-8 encoded Unicode code points. The header file further addresses common pitfalls with the standard `ctype.h` functions by providing macros that ensure these functions return strictly 0 or 1, enhancing cross-platform consistency and security. Overall, this header file serves as a robust library for developers needing advanced string handling capabilities in C, with a focus on safety, portability, and ease of use.
# Imports and Dependencies

---
- `../bits/fd_bits.h`


# Global Variables

---
### fd\_cstr\_to\_cstr
- **Type**: ``char const *``
- **Description**: The `fd_cstr_to_cstr` function is a global function that takes a constant character string pointer `s` as input and returns the same pointer `s`. This function does not modify the input string and simply returns it as is.
- **Use**: This function is used to return the input C-style string pointer for type system completeness and to facilitate generic programming practices.


---
### fd\_cstr\_printf
- **Type**: `function pointer`
- **Description**: `fd_cstr_printf` is a function that formats a string according to a specified format and writes it into a buffer. It is similar to the standard `printf` function but is designed to work with a specified buffer size, ensuring that the resulting string is null-terminated and does not exceed the buffer's capacity.
- **Use**: This function is used to safely format and store a string in a buffer, with optional tracking of the string's length.


---
### fd\_cstr\_append\_printf
- **Type**: `function pointer`
- **Description**: `fd_cstr_append_printf` is a function that appends formatted output to a character string. It takes a character pointer `p` where the formatted string will be appended, a format string `fmt`, and a variable number of arguments for formatting. The function is marked with the `__attribute__((format(printf,2,3)))` attribute, which enables the compiler to check the format string and arguments for consistency, similar to the `printf` function.
- **Use**: This function is used to append formatted text to an existing character string buffer, ensuring the buffer has enough space for the formatted output and a null terminator.


# Functions

---
### fd\_cstr\_hash\_append<!-- {{#callable:fd_cstr_hash_append}} -->
The `fd_cstr_hash_append` function updates a given hash value by appending the hash of a null-terminated string using a variant of the djb2 hash algorithm.
- **Inputs**:
    - `hash`: An unsigned long integer representing the current hash value to be updated.
    - `key`: A pointer to a constant character string (cstr) that is null-terminated, which will be used to update the hash.
- **Control Flow**:
    - Check if the `key` is not NULL using `FD_LIKELY` macro.
    - If `key` is not NULL, cast it to an unsigned char pointer `p`.
    - Enter an infinite loop to process each character in the string pointed to by `p`.
    - Retrieve the current character `c` from `p`.
    - If `c` is the null character (end of string), break the loop using `FD_UNLIKELY` macro.
    - Update the `hash` by multiplying it by 33 and XORing it with `c`.
    - Increment the pointer `p` to process the next character.
    - Return the updated `hash`.
- **Output**: The function returns an updated hash value as an unsigned long integer after processing the input string.


---
### fd\_cstr\_hash<!-- {{#callable:fd_cstr_hash}} -->
The `fd_cstr_hash` function computes a hash value for a null-terminated string using a variant of the djb2 hash algorithm.
- **Inputs**:
    - `key`: A pointer to a null-terminated character string (cstr) that is to be hashed.
- **Control Flow**:
    - The function calls [`fd_cstr_hash_append`](#fd_cstr_hash_append) with an initial hash value of 5381UL and the provided `key`.
    - [`fd_cstr_hash_append`](#fd_cstr_hash_append) iterates over each character in the `key` string, updating the hash value by multiplying the current hash by 33 and XORing it with the character value.
    - If `key` is NULL, it is treated as an empty string, and the initial hash value is returned.
- **Output**: The function returns an unsigned long integer representing the hash value of the input string.
- **Functions called**:
    - [`fd_cstr_hash_append`](#fd_cstr_hash_append)


---
### fd\_cstr\_init<!-- {{#callable:fd_cstr_init}} -->
The `fd_cstr_init` function initializes a buffer for writing a C-style string by returning the buffer pointer.
- **Inputs**:
    - `buf`: A pointer to a character array (buffer) where the C-style string will be written.
- **Control Flow**:
    - The function takes a single argument, `buf`, which is a pointer to a character array.
    - It simply returns the same pointer `buf` without any modification.
- **Output**: The function returns the same pointer `buf` that was passed as an argument, indicating where the first character of the C-style string should be written.


---
### fd\_cstr\_fini<!-- {{#callable:fd_cstr_fini}} -->
The `fd_cstr_fini` function sets the character at the given pointer to a null terminator, effectively marking the end of a C-style string.
- **Inputs**:
    - `p`: A pointer to a character, which is expected to be the location where the null terminator should be placed.
- **Control Flow**:
    - The function takes a single character pointer `p` as input.
    - It dereferences the pointer and assigns the null character '\0' to the location pointed by `p`.
    - This operation effectively terminates a C-style string at the given location.
- **Output**: The function does not return any value; it modifies the character at the pointer location to be a null terminator.


---
### fd\_cstr\_append\_char<!-- {{#callable:fd_cstr_append_char}} -->
The `fd_cstr_append_char` function appends a single character to a C-style string and returns the updated pointer position.
- **Inputs**:
    - `p`: A pointer to the current position in the C-style string where the character will be appended.
    - `c`: The character to append to the C-style string.
- **Control Flow**:
    - The function dereferences the pointer `p` and assigns the character `c` to that location.
    - The pointer `p` is then incremented to point to the next position in the string.
    - The updated pointer `p` is returned.
- **Output**: The function returns the updated pointer `p`, which now points to the position immediately after the appended character.


---
### fd\_cstr\_append\_text<!-- {{#callable:fd_cstr_append_text}} -->
The `fd_cstr_append_text` function appends a specified number of characters from a source string to a destination string and returns a pointer to the end of the appended text.
- **Inputs**:
    - `p`: A pointer to the destination string where the text will be appended.
    - `t`: A pointer to the source string containing the text to be appended.
    - `n`: The number of characters to append from the source string to the destination string.
- **Control Flow**:
    - The function calls `fd_memcpy` to copy `n` characters from the source string `t` to the destination string `p`.
    - After copying, the function returns a pointer to the position in the destination string immediately following the last appended character.
- **Output**: A pointer to the position in the destination string immediately after the appended text.


---
### fd\_cstr\_append\_cstr<!-- {{#callable:fd_cstr_append_cstr}} -->
The `fd_cstr_append_cstr` function appends a null-terminated string `s` to a destination buffer `p` and returns a pointer to the end of the appended string.
- **Inputs**:
    - `p`: A pointer to the destination buffer where the string `s` will be appended.
    - `s`: A pointer to the null-terminated string to be appended to `p`; if `s` is NULL, the function does nothing.
- **Control Flow**:
    - Check if the input string `s` is NULL using `FD_UNLIKELY`; if so, return `p` immediately as a no-op.
    - Calculate the length `n` of the string `s` using `strlen`.
    - Copy `n` characters from `s` to `p` using `fd_memcpy`.
    - Return a pointer to the position in `p` immediately after the last copied character.
- **Output**: A pointer to the position in the destination buffer `p` immediately after the appended string `s`.


---
### fd\_cstr\_append\_cstr\_safe<!-- {{#callable:fd_cstr_append_cstr_safe}} -->
The `fd_cstr_append_cstr_safe` function appends up to `n` characters from a source C-string `s` to a destination buffer `p`, ensuring safe copying even if `s` is NULL.
- **Inputs**:
    - `p`: A pointer to the destination buffer where the characters from the source string will be appended.
    - `s`: A pointer to the source C-string to be appended to the destination buffer; can be NULL.
    - `n`: The maximum number of characters to append from the source string to the destination buffer.
- **Control Flow**:
    - Check if the source string `s` is NULL; if so, return the destination pointer `p` immediately without any operation.
    - Calculate the minimum of the length of the source string `s` and the maximum number of characters `n` to determine how many characters to copy.
    - Use `fd_memcpy` to copy the determined number of characters from the source string `s` to the destination buffer `p`.
    - Return the pointer to the position in the destination buffer immediately after the last copied character.
- **Output**: Returns a pointer to the position in the destination buffer `p` immediately after the last appended character.


---
### fd\_cstr\_append\_uint\_as\_text<!-- {{#callable:fd_cstr_append_uint_as_text}} -->
The function `fd_cstr_append_uint_as_text` appends a formatted unsigned integer as text to a character buffer, with optional padding and prefix.
- **Inputs**:
    - `p`: A pointer to the character buffer where the formatted text will be appended.
    - `ws`: A character used for left-padding the formatted number if necessary.
    - `pm`: A character used as a prefix for the formatted number, such as '+' or '-', or '\0' for no prefix.
    - `x`: The unsigned integer to be formatted and appended as text.
    - `n`: The total number of characters to be used for the formatted number, including padding and prefix.
- **Control Flow**:
    - Initialize `p0` to point to the start of the buffer `p` and increment `p` by `n` to point to the end of the space allocated for the number.
    - Initialize `q` to point to the same location as `p`.
    - Use a do-while loop to convert the integer `x` to its decimal representation, storing each digit in reverse order starting from `q` and moving backwards.
    - If a prefix character `pm` is provided, insert it before the most significant digit by decrementing `q`.
    - Fill any remaining space between `p0` and `q` with the padding character `ws`.
    - Return the pointer `p`, which now points to the end of the appended text.
- **Output**: A pointer to the end of the buffer `p`, where the next character can be appended.


---
### fd\_cstr\_append\_ulong\_as\_text<!-- {{#callable:fd_cstr_append_ulong_as_text}} -->
The function `fd_cstr_append_ulong_as_text` appends a formatted unsigned long integer as text to a character buffer, with optional padding and prefix.
- **Inputs**:
    - `p`: A pointer to the character buffer where the formatted text will be appended.
    - `ws`: A character used for left-padding the formatted number if necessary.
    - `pm`: A character used as a prefix for the number, such as '+' or '-', or '\0' for no prefix.
    - `x`: The unsigned long integer to be converted to text and appended.
    - `n`: The total number of characters to be used for the formatted number, including padding and prefix.
- **Control Flow**:
    - Initialize `p0` to point to the start of the buffer `p`.
    - Advance `p` by `n` characters to reserve space for the formatted number.
    - Set `q` to point to the current position of `p`.
    - Convert the number `x` to a string by repeatedly taking the remainder of `x` divided by 10, converting it to a character, and storing it in the buffer backwards from `q`.
    - If a prefix character `pm` is provided, prepend it to the number by storing it at the position before `q`.
    - Fill any remaining space between `p0` and `q` with the padding character `ws`.
    - Return the updated pointer `p`, which now points to the end of the formatted string.
- **Output**: A pointer to the end of the buffer `p`, where the next character can be appended.


---
### fd\_cstr\_append\_uint128\_as\_text<!-- {{#callable:fd_cstr_append_uint128_as_text}} -->
The function `fd_cstr_append_uint128_as_text` appends a 128-bit unsigned integer as a text representation to a character buffer, with optional padding and prefix.
- **Inputs**:
    - `p`: A pointer to the character buffer where the text representation of the integer will be appended.
    - `ws`: A character used for left-padding the text representation if necessary.
    - `pm`: A character used as a prefix for the text representation, such as '+' or '-', or '\0' for no prefix.
    - `x`: The 128-bit unsigned integer to be converted to text and appended to the buffer.
    - `n`: The total number of characters to be used for the text representation, including padding and prefix.
- **Control Flow**:
    - Initialize `p0` to point to the start of the buffer `p` and increment `p` by `n` to point to the end of the intended text representation.
    - Initialize `q` to point to the current position of `p`.
    - Use a do-while loop to convert the integer `x` to its decimal representation by repeatedly taking the modulus with 10, converting the result to a character, and storing it in the buffer, decrementing `q` each time.
    - If a prefix character `pm` is provided, store it in the buffer before the number by decrementing `q` and placing `pm` there.
    - Use a while loop to fill any remaining space between `p0` and `q` with the padding character `ws`.
    - Return the updated pointer `p`, which now points to the end of the appended text.
- **Output**: The function returns a pointer to the end of the buffer where the text representation of the integer has been appended.


---
### fd\_cstr\_append\_uchar\_as\_text<!-- {{#callable:fd_cstr_append_uchar_as_text}} -->
The function `fd_cstr_append_uchar_as_text` appends the textual representation of an unsigned char to a character string buffer.
- **Inputs**:
    - `p`: A pointer to the character buffer where the text representation will be appended.
    - `ws`: A character used for left-padding the converted value.
    - `pm`: A prefix character to use, such as '+' or '-', with '\0' indicating no prefix.
    - `x`: The unsigned char value to be converted to text and appended.
    - `n`: The number of characters to use for the text representation, including padding and prefix.
- **Control Flow**:
    - The function casts the unsigned char `x` to an unsigned int.
    - It calls [`fd_cstr_append_uint_as_text`](#fd_cstr_append_uint_as_text) with the cast value and other parameters to perform the actual appending operation.
- **Output**: A pointer to the character buffer after the text representation of the unsigned char has been appended.
- **Functions called**:
    - [`fd_cstr_append_uint_as_text`](#fd_cstr_append_uint_as_text)


---
### fd\_cstr\_append\_ushort\_as\_text<!-- {{#callable:fd_cstr_append_ushort_as_text}} -->
The function `fd_cstr_append_ushort_as_text` appends a `ushort` value as text to a character string buffer, with optional padding and prefix, by converting it to an `uint` and using [`fd_cstr_append_uint_as_text`](#fd_cstr_append_uint_as_text).
- **Inputs**:
    - `p`: A pointer to the character buffer where the text representation of the `ushort` will be appended.
    - `ws`: A character used for left padding the converted value.
    - `pm`: A prefix character to use (e.g., '+', '-'), or '\0' to indicate no prefix.
    - `x`: The `ushort` value to be converted and appended as text.
    - `n`: The number of characters to use for the text representation, including padding and prefix.
- **Control Flow**:
    - The function casts the `ushort` value `x` to an `uint`.
    - It calls [`fd_cstr_append_uint_as_text`](#fd_cstr_append_uint_as_text) with the casted `uint` value and the other parameters to perform the actual appending operation.
- **Output**: Returns a pointer to the position in the buffer immediately after the appended text.
- **Functions called**:
    - [`fd_cstr_append_uint_as_text`](#fd_cstr_append_uint_as_text)


---
### fd\_cstr\_append\_fxp10\_as\_text<!-- {{#callable:fd_cstr_append_fxp10_as_text}} -->
The function `fd_cstr_append_fxp10_as_text` formats a fixed-point decimal number as a string and appends it to a given character buffer.
- **Inputs**:
    - `p`: A pointer to the character buffer where the formatted string will be appended.
    - `ws`: A character used for left-padding the formatted number.
    - `pm`: A prefix character (e.g., '+' or '-') to be added before the number, or '\0' if no prefix is needed.
    - `f`: The number of decimal places in the fixed-point representation.
    - `x`: The fixed-point number to be formatted, represented as an integer.
    - `n`: The total number of characters to be used for the formatted output, including padding and prefix.
- **Control Flow**:
    - Initialize a pointer `p0` to the start of the buffer `p` and advance `p` by `n` characters.
    - Set a pointer `q` to the current position of `p`.
    - While `f` is greater than zero, extract the least significant digit of `x`, convert it to a character, and place it in the buffer at `--q`; decrement `f` and divide `x` by 10.
    - Insert a decimal point character at `--q`.
    - Extract and convert the remaining digits of `x` to characters, placing them in the buffer at `--q` until `x` is zero.
    - If a prefix character `pm` is provided, insert it at `--q`.
    - Left-pad the buffer with the whitespace character `ws` from `p0` to `q`.
    - Return the pointer `p`, which now points to the end of the formatted string.
- **Output**: A pointer to the end of the formatted string in the buffer `p`.


---
### fd\_cstr\_append\_utf8<!-- {{#callable:fd_cstr_append_utf8}} -->
The `fd_cstr_append_utf8` function appends the UTF-8 encoding of a Unicode code point to a character string buffer.
- **Inputs**:
    - `p`: A pointer to a character buffer where the UTF-8 encoded character will be appended.
    - `rune`: A Unicode code point represented as an unsigned integer to be encoded in UTF-8 and appended to the buffer.
- **Control Flow**:
    - Check if the rune is less than or equal to 0x7f; if true, append it as a single byte.
    - If the rune is less than or equal to 0x7ff, encode it as two bytes and append both to the buffer.
    - If the rune is less than or equal to 0xffff, encode it as three bytes and append all three to the buffer.
    - If the rune is less than or equal to 0x10ffff, encode it as four bytes and append all four to the buffer.
    - If the rune is greater than 0x10ffff, append the UTF-8 replacement character (0xef, 0xbf, 0xbd) to the buffer.
- **Output**: Returns a pointer to the position in the buffer immediately after the last appended character.


# Function Declarations (Public API)

---
### fd\_cstr\_to\_cstr<!-- {{#callable_declaration:fd_cstr_to_cstr}} -->
Returns the input C string as is.
- **Description**: Use this function when you need to pass through a C string without modification. It is primarily intended for type system completeness and to facilitate generic programming practices. The function assumes that the input is a valid, non-null pointer to a null-terminated string. The lifetime and ownership of the returned pointer are the same as those of the input string.
- **Inputs**:
    - `s`: A pointer to a null-terminated C string. Must not be null. The caller retains ownership of the string, and the function does not modify it.
- **Output**: Returns the same pointer to the input C string.
- **See also**: [`fd_cstr_to_cstr`](fd_cstr.c.driver.md#fd_cstr_to_cstr)  (Implementation)


---
### fd\_cstr\_to\_char<!-- {{#callable_declaration:fd_cstr_to_char}} -->
Returns the first character of a null-terminated string.
- **Description**: Use this function to obtain the first character of a null-terminated string. It is useful when you need to quickly access the initial character of a string for operations like parsing or validation. The function assumes that the input string is non-null and properly null-terminated. If the string is empty, it will return the null character '\0'. This function is primarily intended for type system completeness and generic programming practices.
- **Inputs**:
    - `s`: A pointer to a null-terminated string. Must not be null. The caller retains ownership of the string, and it must remain valid for the duration of the function call.
- **Output**: The first character of the input string, or '\0' if the string is empty.
- **See also**: [`fd_cstr_to_char`](fd_cstr.c.driver.md#fd_cstr_to_char)  (Implementation)


---
### fd\_cstr\_to\_schar<!-- {{#callable_declaration:fd_cstr_to_schar}} -->
Converts a C string to a signed char.
- **Description**: This function converts a null-terminated C string to a signed char, interpreting the string as an integer in base 0. It handles leading whitespace and signs, and interprets the number as octal if prefixed with '0', hexadecimal if prefixed with '0x', and decimal otherwise. This function should be used when you need to convert a string representation of a number to a signed char. The caller must ensure that the input string is non-null and points to a valid C string.
- **Inputs**:
    - `s`: A pointer to a null-terminated C string representing a number. Must not be null, and the caller retains ownership of the string.
- **Output**: The function returns the signed char representation of the number in the string.
- **See also**: [`fd_cstr_to_schar`](fd_cstr.c.driver.md#fd_cstr_to_schar)  (Implementation)


---
### fd\_cstr\_to\_short<!-- {{#callable_declaration:fd_cstr_to_short}} -->
Converts a null-terminated string to a short integer.
- **Description**: Use this function to convert a null-terminated character string into a short integer. It is suitable for parsing strings that represent integer values, including those with leading whitespace, signs, and different bases (octal, hexadecimal, or decimal) based on standard C conventions. The caller must ensure that the input string is non-null and properly null-terminated. This function does not handle errors explicitly, so invalid or out-of-range inputs may lead to undefined behavior or incorrect results.
- **Inputs**:
    - `cstr`: A pointer to a null-terminated character string representing an integer. Must not be null. The string can include leading whitespace and signs, and it can represent numbers in octal, hexadecimal, or decimal format.
- **Output**: Returns the short integer value represented by the input string. The behavior is undefined for invalid or out-of-range inputs.
- **See also**: [`fd_cstr_to_short`](fd_cstr.c.driver.md#fd_cstr_to_short)  (Implementation)


---
### fd\_cstr\_to\_int<!-- {{#callable_declaration:fd_cstr_to_int}} -->
Converts a null-terminated string to an integer.
- **Description**: Use this function to convert a null-terminated character string to an integer value. It interprets the string in a manner similar to the `strtol` function with a base of 0, which means it can handle strings representing numbers in decimal, octal (if prefixed with 0), or hexadecimal (if prefixed with 0x). The caller must ensure that the input string is non-null and points to a valid null-terminated string. This function does not handle errors or invalid input strings, so the caller should ensure the string is a valid representation of an integer.
- **Inputs**:
    - `s`: A pointer to a null-terminated character string representing an integer. Must not be null. The caller retains ownership of the string.
- **Output**: Returns the integer value represented by the string. If the string does not represent a valid integer, the behavior is undefined.
- **See also**: [`fd_cstr_to_int`](fd_cstr.c.driver.md#fd_cstr_to_int)  (Implementation)


---
### fd\_cstr\_to\_long<!-- {{#callable_declaration:fd_cstr_to_long}} -->
Converts a null-terminated string to a long integer.
- **Description**: Use this function to convert a null-terminated character string to a long integer, interpreting the string as a number in base 0, which allows for automatic base detection (octal, decimal, or hexadecimal). This function should be called when you need to parse a string representation of a number into a long integer. Ensure that the input string is non-null and properly null-terminated to avoid undefined behavior.
- **Inputs**:
    - `cstr`: A pointer to a null-terminated character string representing a number. The string must not be null, and it should be properly formatted to represent a valid number in octal, decimal, or hexadecimal format.
- **Output**: Returns the long integer value represented by the input string.
- **See also**: [`fd_cstr_to_long`](fd_cstr.c.driver.md#fd_cstr_to_long)  (Implementation)


---
### fd\_cstr\_to\_uchar<!-- {{#callable_declaration:fd_cstr_to_uchar}} -->
Converts a C-style string to an unsigned char.
- **Description**: This function is used to convert a null-terminated C-style string into an unsigned char value. It should be called when you need to interpret a string representation of a number as an unsigned char. The input string must be non-null and properly null-terminated. The function handles leading whitespace and supports decimal, octal, and hexadecimal formats based on the string's prefix. It does not perform any error checking on the input string, so malformed strings may lead to undefined behavior.
- **Inputs**:
    - `s`: A pointer to a null-terminated C-style string representing a number. Must not be null. The caller retains ownership of the string.
- **Output**: The function returns the unsigned char value represented by the input string.
- **See also**: [`fd_cstr_to_uchar`](fd_cstr.c.driver.md#fd_cstr_to_uchar)  (Implementation)


---
### fd\_cstr\_to\_ushort<!-- {{#callable_declaration:fd_cstr_to_ushort}} -->
Converts a null-terminated string to an unsigned short integer.
- **Description**: This function is used to convert a null-terminated character string into an unsigned short integer. It should be called when you need to interpret a string representation of a number as an unsigned short. The function expects the input string to be non-null and properly null-terminated. It handles leading whitespace and signs, and interprets the number in octal, hexadecimal, or decimal based on the string's prefix. The caller must ensure that the string is a valid representation of a number within the range of an unsigned short to avoid unexpected results.
- **Inputs**:
    - `cstr`: A pointer to a null-terminated string representing a number. Must not be null. The string should be a valid representation of a number that fits within the range of an unsigned short.
- **Output**: The function returns the unsigned short integer value represented by the input string.
- **See also**: [`fd_cstr_to_ushort`](fd_cstr.c.driver.md#fd_cstr_to_ushort)  (Implementation)


---
### fd\_cstr\_to\_uint<!-- {{#callable_declaration:fd_cstr_to_uint}} -->
Converts a null-terminated string to an unsigned integer.
- **Description**: This function is used to convert a null-terminated character string into an unsigned integer. It should be called when you need to interpret a string as an unsigned integer value. The function expects the input string to be non-null and properly null-terminated. It handles leading whitespace and supports decimal, octal, and hexadecimal formats based on the string's prefix. The caller must ensure that the input string is valid and within the range of an unsigned integer to avoid undefined behavior.
- **Inputs**:
    - `cstr`: A pointer to a null-terminated string representing the number to convert. The string must not be null, and it should be formatted correctly as a number in decimal, octal, or hexadecimal form.
- **Output**: Returns the unsigned integer value represented by the input string.
- **See also**: [`fd_cstr_to_uint`](fd_cstr.c.driver.md#fd_cstr_to_uint)  (Implementation)


---
### fd\_cstr\_to\_ulong<!-- {{#callable_declaration:fd_cstr_to_ulong}} -->
Converts a null-terminated string to an unsigned long integer.
- **Description**: This function is used to convert a null-terminated character string into an unsigned long integer. It is useful when you need to interpret a string representation of a number as an unsigned long. The function handles strings with leading whitespace and signs, and it automatically detects the base of the number: octal if prefixed with '0', hexadecimal if prefixed with '0x', and decimal otherwise. It is important to ensure that the input string is non-null and points to a valid null-terminated string to avoid undefined behavior.
- **Inputs**:
    - `cstr`: A pointer to a null-terminated character string representing the number to be converted. The string must not be null, and it should be a valid C string.
- **Output**: The function returns the unsigned long integer value represented by the input string.
- **See also**: [`fd_cstr_to_ulong`](fd_cstr.c.driver.md#fd_cstr_to_ulong)  (Implementation)


---
### fd\_cstr\_to\_float<!-- {{#callable_declaration:fd_cstr_to_float}} -->
Converts a C-style string to a float.
- **Description**: Use this function to convert a null-terminated character string representing a floating-point number into a float. It is essential that the input string is non-null and properly formatted as a floating-point number, as the function does not handle null pointers or invalid formats. This function is useful when you need to parse floating-point numbers from strings, such as when reading data from text files or user input.
- **Inputs**:
    - `s`: A pointer to a null-terminated character string representing a floating-point number. Must not be null. The caller retains ownership of the string.
- **Output**: Returns the floating-point value represented by the input string.
- **See also**: [`fd_cstr_to_float`](fd_cstr.c.driver.md#fd_cstr_to_float)  (Implementation)


---
### fd\_cstr\_to\_double<!-- {{#callable_declaration:fd_cstr_to_double}} -->
Converts a C-style string to a double precision floating-point number.
- **Description**: Use this function to convert a null-terminated string representing a floating-point number into a double. It is essential that the input string is non-null and properly formatted as a floating-point number, as the function does not perform error checking or validation. This function is useful when parsing numeric data from text sources. Be aware that if the string does not represent a valid floating-point number, the behavior is undefined, and the function may return zero or another unexpected value.
- **Inputs**:
    - `s`: A pointer to a null-terminated string representing a floating-point number. Must not be null. The caller retains ownership of the string.
- **Output**: Returns the double precision floating-point number represented by the input string.
- **See also**: [`fd_cstr_to_double`](fd_cstr.c.driver.md#fd_cstr_to_double)  (Implementation)


---
### fd\_cstr\_to\_ulong\_octal<!-- {{#callable_declaration:fd_cstr_to_ulong_octal}} -->
Converts a null-terminated string representing an octal number to an unsigned long integer.
- **Description**: Use this function to convert a string that represents an octal number into its corresponding unsigned long integer value. This is particularly useful when dealing with UNIX-style file permissions or other octal-based data. The input string must be a valid null-terminated C string and should represent a valid octal number. The function assumes the input is in octal format and does not handle any prefixes or signs. It is the caller's responsibility to ensure the input string is non-null and correctly formatted.
- **Inputs**:
    - `s`: A pointer to a null-terminated string representing an octal number. The string must not be null, and the caller retains ownership of the string. The function does not handle invalid or malformed octal strings, so the input should be validated before calling.
- **Output**: Returns the unsigned long integer value corresponding to the octal number represented by the input string.
- **See also**: [`fd_cstr_to_ulong_octal`](fd_cstr.c.driver.md#fd_cstr_to_ulong_octal)  (Implementation)


---
### fd\_cstr\_to\_ulong\_seq<!-- {{#callable_declaration:fd_cstr_to_ulong_seq}} -->
Parses a string into a sequence of unsigned long integers.
- **Description**: This function converts a comma-separated string of ranges into a sequence of unsigned long integers, storing the result in the provided array. Each range in the string can be a single integer, a simple range (e.g., "4-8"), or a range with a stride (e.g., "1-10/3"). The function handles whitespace and is robust against overflow. It returns the number of elements parsed, which may exceed the provided array's capacity, in which case the sequence is truncated. The function returns 0 if the input string is NULL, malformed, or represents an empty sequence.
- **Inputs**:
    - `cstr`: A pointer to a null-terminated string representing the sequence to parse. If NULL, the function returns 0.
    - `seq`: A pointer to an array of unsigned long integers where the parsed sequence will be stored. Must not be NULL if seq_max is non-zero.
    - `seq_max`: The maximum number of elements that can be stored in the seq array. If the parsed sequence exceeds this length, it will be truncated.
- **Output**: Returns the actual number of elements parsed from the string. If the sequence length exceeds seq_max, the returned value will be greater than seq_max.
- **See also**: [`fd_cstr_to_ulong_seq`](fd_cstr.c.driver.md#fd_cstr_to_ulong_seq)  (Implementation)


---
### fd\_cstr\_casecmp<!-- {{#callable_declaration:fd_cstr_casecmp}} -->
Compares two strings case-insensitively.
- **Description**: Use this function to compare two null-terminated strings without considering case differences. It is useful when you need to determine if two strings are equivalent in a case-insensitive manner. The function expects both input strings to be valid, non-null pointers to null-terminated character arrays. It returns an integer indicating the lexicographical relationship between the strings, similar to the behavior of standard string comparison functions.
- **Inputs**:
    - `a`: A pointer to the first null-terminated string to compare. Must not be null.
    - `b`: A pointer to the second null-terminated string to compare. Must not be null.
- **Output**: An integer less than, equal to, or greater than zero if the first string is found, respectively, to be less than, to match, or be greater than the second string, ignoring case differences.
- **See also**: [`fd_cstr_casecmp`](fd_cstr.c.driver.md#fd_cstr_casecmp)  (Implementation)


---
### fd\_cstr\_nlen<!-- {{#callable_declaration:fd_cstr_nlen}} -->
Determines the length of a string up to a maximum limit.
- **Description**: This function calculates the length of a null-terminated string pointed to by `s`, but will not exceed `m` characters. It is useful when you need to ensure that the length calculation does not go beyond a certain limit, which can help prevent buffer overflows or excessive processing. The function should be used when the string may not be null-terminated within the first `m` characters, or when you want to limit the length calculation for performance reasons. It is equivalent to the standard `strnlen` function and does not require POSIX support.
- **Inputs**:
    - `s`: A pointer to the null-terminated string whose length is to be determined. The caller must ensure that `s` is not null and points to a valid memory location.
    - `m`: The maximum number of characters to examine in the string. It must be a non-negative value.
- **Output**: Returns the number of characters in the string, up to a maximum of `m`. If the string is shorter than `m`, the actual length is returned.
- **See also**: [`fd_cstr_nlen`](fd_cstr.c.driver.md#fd_cstr_nlen)  (Implementation)


---
### fd\_cstr\_printf<!-- {{#callable_declaration:fd_cstr_printf}} -->
Formats a string into a buffer with a specified size.
- **Description**: This function formats a string according to a specified format and writes it into a provided buffer, ensuring that the resulting string is null-terminated and does not exceed the buffer size. It is useful for safely formatting strings into fixed-size buffers, preventing buffer overflows. The function should be called with a valid buffer and a non-zero size to perform the formatting. If the buffer is null or the size is zero, the function performs no operation other than setting the optional length to zero if provided.
- **Inputs**:
    - `buf`: A pointer to the buffer where the formatted string will be written. Must not be null if sz is non-zero. The caller retains ownership.
    - `sz`: The size of the buffer in bytes. Must be greater than zero to perform formatting.
    - `opt_len`: An optional pointer to a ulong where the length of the formatted string will be stored. Can be null if the length is not needed.
    - `fmt`: A printf-style format string that specifies how to format the data. Must not be null.
    - `...`: Additional arguments that match the format specifiers in fmt.
- **Output**: Returns the pointer to the buffer buf. If opt_len is provided, it will contain the length of the formatted string.
- **See also**: [`fd_cstr_printf`](fd_cstr.c.driver.md#fd_cstr_printf)  (Implementation)


---
### fd\_cstr\_printf\_check<!-- {{#callable_declaration:fd_cstr_printf_check}} -->
Formats a string into a buffer and checks if it fits.
- **Description**: This function formats a string according to a specified format and writes it into a provided buffer, ensuring that the entire formatted string, including the null-terminating character, fits within the buffer size. It should be used when you need to safely format strings into a buffer with a size constraint, and you want to verify if the entire string was successfully written. The function returns 1 if the entire string fits, and 0 if it was truncated or if there was a formatting error. If the buffer is null or the size is zero, the function performs no operation other than setting the optional length to zero if provided.
- **Inputs**:
    - `buf`: A pointer to the buffer where the formatted string will be written. Must not be null unless sz is zero. The caller retains ownership.
    - `sz`: The size of the buffer in bytes. Must be greater than zero for any writing to occur.
    - `opt_len`: An optional pointer to a ulong where the function will store the length of the formatted string, excluding the null terminator. Can be null if the length is not needed.
    - `fmt`: A format string as in printf, specifying how to format the subsequent arguments. Must not be null.
    - `...`: Additional arguments to be formatted according to the format string. These must match the format specifiers in fmt.
- **Output**: Returns 1 if the entire formatted string, including the null terminator, was written to the buffer; returns 0 if the string was truncated or if there was a formatting error.
- **See also**: [`fd_cstr_printf_check`](fd_cstr.c.driver.md#fd_cstr_printf_check)  (Implementation)


---
### fd\_cstr\_append\_printf<!-- {{#callable_declaration:fd_cstr_append_printf}} -->
Appends formatted text to a buffer using a printf-style format string.
- **Description**: Use this function to append formatted text to an existing character buffer. It is useful when you need to build a string incrementally with formatted data. The buffer must be non-null and have sufficient space to accommodate the formatted output. The function returns a pointer to the end of the appended string, allowing for further concatenations. If the buffer is null, the function returns null, indicating an error. This function does not perform bounds checking, so ensure the buffer is large enough to prevent overflow.
- **Inputs**:
    - `buf`: A pointer to the character buffer where the formatted text will be appended. Must not be null. The caller is responsible for ensuring the buffer has enough space to hold the formatted output.
    - `fmt`: A printf-style format string that specifies how to format the subsequent arguments. Must not be null.
- **Output**: Returns a pointer to the end of the appended string within the buffer, or null if the buffer is null.
- **See also**: [`fd_cstr_append_printf`](fd_cstr.c.driver.md#fd_cstr_append_printf)  (Implementation)


---
### fd\_cstr\_tokenize<!-- {{#callable_declaration:fd_cstr_tokenize}} -->
Tokenize a string into substrings based on a delimiter.
- **Description**: Use this function to split a null-terminated string into tokens, separated by a specified delimiter character. The function modifies the input string in place, replacing delimiters with null characters to terminate each token. It stores pointers to the start of each token in the provided array, up to a maximum specified number of tokens. The function returns the total number of tokens found, which may exceed the capacity of the array. It is important to ensure that the input string is not null before calling this function, as a null input will result in no tokens being processed.
- **Inputs**:
    - `tok`: An array of character pointers where the function will store pointers to the start of each token. The array must have at least 'tok_max' elements. The caller retains ownership and must ensure it is not null if 'tok_max' is greater than zero.
    - `tok_max`: The maximum number of tokens to store in the 'tok' array. Must be a non-negative integer.
    - `cstr`: A null-terminated string to be tokenized. The string is modified in place, so the caller must ensure it is writable and not null.
    - `delim`: A character used as the delimiter to separate tokens. Must be a non-null, non-whitespace character.
- **Output**: Returns the total number of tokens found in the input string. If this number exceeds 'tok_max', only the first 'tok_max' tokens are stored in 'tok'.
- **See also**: [`fd_cstr_tokenize`](fd_cstr.c.driver.md#fd_cstr_tokenize)  (Implementation)



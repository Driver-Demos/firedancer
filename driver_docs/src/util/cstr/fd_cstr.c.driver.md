# Purpose
This C source code file provides a collection of utility functions for handling and converting C-style strings (`cstr`). The primary focus of the file is to facilitate the conversion of string representations to various data types, such as `char`, `int`, `long`, `float`, and `double`, using functions like [`fd_cstr_to_int`](#fd_cstr_to_int) and [`fd_cstr_to_float`](#fd_cstr_to_float). Additionally, it includes functions for more specialized conversions, such as [`fd_cstr_to_ulong_octal`](#fd_cstr_to_ulong_octal) for octal numbers and [`fd_cstr_to_ulong_seq`](#fd_cstr_to_ulong_seq) for parsing sequences of unsigned long integers. The file also offers string manipulation utilities, including case-insensitive comparison ([`fd_cstr_casecmp`](#fd_cstr_casecmp)), length calculation with a maximum limit ([`fd_cstr_nlen`](#fd_cstr_nlen)), and formatted string operations ([`fd_cstr_printf`](#fd_cstr_printf), [`fd_cstr_printf_check`](#fd_cstr_printf_check), and [`fd_cstr_append_printf`](#fd_cstr_append_printf)). Furthermore, it provides a tokenization function ([`fd_cstr_tokenize`](#fd_cstr_tokenize)) to split strings into tokens based on a specified delimiter.

The code is structured to be a utility library, likely intended for inclusion in larger projects where string manipulation and conversion are required. It does not define a main function, indicating that it is not an executable but rather a set of functions to be used by other parts of a program. The use of conditional compilation (`#if FD_HAS_DOUBLE`) suggests that the code is designed to be flexible and adaptable to different environments or configurations. The file includes standard library headers for string and character operations, and it uses variadic functions to handle formatted output, demonstrating a broad functionality aimed at enhancing string handling capabilities in C programs.
# Imports and Dependencies

---
- `fd_cstr.h`
- `stdio.h`
- `stdlib.h`
- `stdarg.h`
- `strings.h`
- `ctype.h`


# Functions

---
### fd\_cstr\_to\_cstr<!-- {{#callable:fd_cstr_to_cstr}} -->
The `fd_cstr_to_cstr` function returns the input C-style string as is, without any modification.
- **Inputs**:
    - `cstr`: A constant character pointer representing a C-style string.
- **Control Flow**:
    - The function takes a single input parameter, `cstr`, which is a constant character pointer.
    - It directly returns the input `cstr` without any processing or modification.
- **Output**: The function returns the same constant character pointer that was passed as input.


---
### fd\_cstr\_to\_char<!-- {{#callable:fd_cstr_to_char}} -->
The `fd_cstr_to_char` function returns the first character of a given C-style string.
- **Inputs**:
    - `cstr`: A pointer to a constant character string from which the first character will be extracted.
- **Control Flow**:
    - The function directly accesses the first character of the input string `cstr` using array indexing.
    - It returns this character as the output.
- **Output**: The function returns the first character of the input string `cstr` as a `char` type.


---
### fd\_cstr\_to\_schar<!-- {{#callable:fd_cstr_to_schar}} -->
The function `fd_cstr_to_schar` converts a C-style string to a signed char (schar) using base 0 conversion.
- **Inputs**:
    - `cstr`: A constant character pointer representing the C-style string to be converted to a signed char.
- **Control Flow**:
    - The function calls `strtol` with the input string `cstr`, a null pointer for the end pointer, and base 0 to automatically detect the base of the number in the string.
    - The result of `strtol` is cast to a `schar` type and returned.
- **Output**: A signed char (schar) representing the converted value from the input string.


---
### fd\_cstr\_to\_short<!-- {{#callable:fd_cstr_to_short}} -->
The `fd_cstr_to_short` function converts a C-style string to a short integer using base 0 conversion.
- **Inputs**:
    - `cstr`: A pointer to a null-terminated string representing a number to be converted to a short integer.
- **Control Flow**:
    - The function calls `strtol` with the input string `cstr`, a null pointer for the end pointer, and a base of 0, which allows automatic base detection.
    - The result of `strtol` is cast to a `short` type and returned.
- **Output**: A short integer representing the converted value of the input string.


---
### fd\_cstr\_to\_int<!-- {{#callable:fd_cstr_to_int}} -->
The `fd_cstr_to_int` function converts a C-style string to an integer using base 0 conversion.
- **Inputs**:
    - `cstr`: A constant character pointer representing the C-style string to be converted to an integer.
- **Control Flow**:
    - The function calls `strtol` with the input string `cstr`, a null pointer for the end pointer, and base 0 to automatically detect the base of the number in the string.
    - The result of `strtol` is cast to an `int` type and returned.
- **Output**: The function returns the integer value obtained from converting the input string.


---
### fd\_cstr\_to\_long<!-- {{#callable:fd_cstr_to_long}} -->
The function `fd_cstr_to_long` converts a C-style string to a long integer using base 0.
- **Inputs**:
    - `cstr`: A constant character pointer representing the C-style string to be converted to a long integer.
- **Control Flow**:
    - The function calls the `strtol` function, passing the input string `cstr`, a NULL pointer for the end pointer, and 0 for the base, which allows automatic base detection.
    - The result of `strtol` is cast to a `long` type and returned.
- **Output**: A long integer representing the converted value of the input string.


---
### fd\_cstr\_to\_uchar<!-- {{#callable:fd_cstr_to_uchar}} -->
The `fd_cstr_to_uchar` function converts a C-style string to an unsigned char by interpreting the string as an unsigned long integer and casting it to an unsigned char.
- **Inputs**:
    - `cstr`: A constant character pointer representing the C-style string to be converted to an unsigned char.
- **Control Flow**:
    - The function calls `strtoul` with the input string `cstr`, a null pointer for the end pointer, and a base of 0 to automatically detect the base of the number in the string.
    - The result of `strtoul`, which is an unsigned long, is then cast to an unsigned char.
    - The function returns this casted value.
- **Output**: An unsigned char representing the converted value of the input string.


---
### fd\_cstr\_to\_ushort<!-- {{#callable:fd_cstr_to_ushort}} -->
The `fd_cstr_to_ushort` function converts a string to an unsigned short integer using base 0 conversion.
- **Inputs**:
    - `cstr`: A constant character pointer to the string that needs to be converted to an unsigned short integer.
- **Control Flow**:
    - The function calls `strtoul` with the input string `cstr`, a null pointer for the end pointer, and base 0 to automatically detect the base of the number in the string.
    - The result of `strtoul` is cast to an `ushort` type and returned.
- **Output**: An unsigned short integer (`ushort`) representing the converted value from the input string.


---
### fd\_cstr\_to\_uint<!-- {{#callable:fd_cstr_to_uint}} -->
The `fd_cstr_to_uint` function converts a C-style string to an unsigned integer using base 0 conversion.
- **Inputs**:
    - `cstr`: A constant character pointer representing the C-style string to be converted to an unsigned integer.
- **Control Flow**:
    - The function calls `strtoul` with the input string `cstr`, a null pointer for the end pointer, and base 0 to automatically detect the base of the number in the string.
    - The result of `strtoul` is cast to an unsigned integer type `uint`.
    - The function returns the converted unsigned integer value.
- **Output**: The function returns the unsigned integer representation of the input string.


---
### fd\_cstr\_to\_ulong<!-- {{#callable:fd_cstr_to_ulong}} -->
The `fd_cstr_to_ulong` function converts a string to an unsigned long integer using base 0, which automatically detects the base of the input string.
- **Inputs**:
    - `cstr`: A constant character pointer representing the string to be converted to an unsigned long integer.
- **Control Flow**:
    - The function calls the `strtoul` function with the input string `cstr`, a null pointer for the end pointer, and base 0 to automatically determine the base of the number in the string.
    - The result of `strtoul` is cast to an `ulong` type and returned.
- **Output**: The function returns the converted value as an `ulong` type, which is an unsigned long integer.


---
### fd\_cstr\_to\_float<!-- {{#callable:fd_cstr_to_float}} -->
The `fd_cstr_to_float` function converts a C-style string to a floating-point number of type `float`.
- **Inputs**:
    - `cstr`: A constant character pointer representing the C-style string to be converted to a float.
- **Control Flow**:
    - The function calls the standard library function `strtof`, passing the input string `cstr` and `NULL` as the second argument to ignore the end pointer.
    - The `strtof` function attempts to convert the initial portion of the string to a `float` value.
- **Output**: The function returns the converted floating-point number of type `float`.


---
### fd\_cstr\_to\_double<!-- {{#callable:fd_cstr_to_double}} -->
The `fd_cstr_to_double` function converts a C-style string to a double-precision floating-point number.
- **Inputs**:
    - `cstr`: A constant character pointer representing the C-style string to be converted to a double.
- **Control Flow**:
    - The function calls the standard library function `strtod`, passing the input string `cstr` and a `NULL` pointer for the end pointer argument.
    - The `strtod` function attempts to convert the initial portion of the string to a double, ignoring any trailing characters that are not part of the number.
- **Output**: The function returns the double-precision floating-point number obtained from the conversion of the input string.


---
### fd\_cstr\_to\_ulong\_octal<!-- {{#callable:fd_cstr_to_ulong_octal}} -->
The function `fd_cstr_to_ulong_octal` converts a string representing an octal number into an unsigned long integer.
- **Inputs**:
    - `cstr`: A constant character pointer to a string that represents an octal number.
- **Control Flow**:
    - The function calls the standard library function `strtoul` with the base set to 8, which interprets the input string as an octal number.
    - The result of `strtoul` is cast to an `ulong` type and returned.
- **Output**: An unsigned long integer representing the octal value of the input string.


---
### fd\_cstr\_to\_ulong\_seq<!-- {{#callable:fd_cstr_to_ulong_seq}} -->
The `fd_cstr_to_ulong_seq` function parses a string to extract a sequence of unsigned long integers, storing them in an array and returning the count of numbers parsed.
- **Inputs**:
    - `cstr`: A constant character pointer representing the input string containing the sequence of numbers to be parsed.
    - `seq`: A pointer to an array of unsigned long integers where the parsed sequence will be stored.
    - `seq_max`: An unsigned long integer representing the maximum number of elements that can be stored in the `seq` array.
- **Control Flow**:
    - Initialize `seq_cnt` to 0 to keep track of the number of elements parsed.
    - Check if `cstr` is NULL; if so, return `seq_cnt` as 0.
    - Iterate over the string `cstr` to parse numbers, skipping whitespace characters.
    - Use `strtoul` to convert the string to an unsigned long integer, handling errors if conversion fails.
    - Check for a range indicated by a '-' character, and optionally a stride indicated by '/' or ':'.
    - Validate the parsed range and stride, ensuring they are well-formed and do not cause overflow.
    - Append the parsed numbers to the `seq` array, incrementing `seq_cnt` for each number added.
    - Continue parsing until the end of the string is reached or a malformed sequence is detected.
    - Return the total count of numbers successfully parsed and stored in `seq`.
- **Output**: The function returns an unsigned long integer representing the number of elements successfully parsed and stored in the `seq` array.


---
### fd\_cstr\_casecmp<!-- {{#callable:fd_cstr_casecmp}} -->
The `fd_cstr_casecmp` function performs a case-insensitive comparison of two C-style strings.
- **Inputs**:
    - `a`: A pointer to the first null-terminated string to be compared.
    - `b`: A pointer to the second null-terminated string to be compared.
- **Control Flow**:
    - The function directly calls the `strcasecmp` function from the standard library, passing the two input strings `a` and `b` as arguments.
- **Output**: The function returns an integer less than, equal to, or greater than zero if the first string is found, respectively, to be less than, to match, or be greater than the second string, ignoring case differences.


---
### fd\_cstr\_nlen<!-- {{#callable:fd_cstr_nlen}} -->
The `fd_cstr_nlen` function calculates the length of a string up to a maximum specified length.
- **Inputs**:
    - `s`: A pointer to the input string whose length is to be calculated.
    - `m`: The maximum number of characters to consider when calculating the string length.
- **Control Flow**:
    - The function directly calls the standard library function `strnlen` with the provided string `s` and maximum length `m`.
- **Output**: The function returns the length of the string `s`, but not more than `m` characters.


---
### fd\_cstr\_printf<!-- {{#callable:fd_cstr_printf}} -->
The `fd_cstr_printf` function formats a string according to a specified format and writes it to a buffer, ensuring the buffer is null-terminated and optionally returning the length of the formatted string.
- **Inputs**:
    - `buf`: A pointer to the buffer where the formatted string will be written.
    - `sz`: The size of the buffer, indicating the maximum number of characters to write.
    - `opt_len`: An optional pointer to a variable where the length of the formatted string will be stored.
    - `fmt`: A format string that specifies how to format the subsequent arguments.
    - `...`: A variable number of arguments to be formatted according to the format string.
- **Control Flow**:
    - Check if the buffer is null or the size is zero; if so, set `opt_len` to 0 and return the buffer.
    - Initialize a variable argument list and start processing the format string with `vsnprintf`.
    - Calculate the length of the formatted string, ensuring it does not exceed the buffer size minus one, and null-terminate the buffer at this length.
    - End the variable argument list processing.
    - If `opt_len` is provided, store the length of the formatted string in it.
    - Return the buffer.
- **Output**: The function returns the pointer to the buffer containing the formatted string.


---
### fd\_cstr\_printf\_check<!-- {{#callable:fd_cstr_printf_check}} -->
The `fd_cstr_printf_check` function formats a string into a buffer and checks if the formatted string fits within the buffer size.
- **Inputs**:
    - `buf`: A pointer to the buffer where the formatted string will be stored.
    - `sz`: The size of the buffer.
    - `opt_len`: An optional pointer to store the length of the formatted string.
    - `fmt`: A format string that specifies how to format the data.
    - `...`: A variable number of arguments to be formatted according to the format string.
- **Control Flow**:
    - Check if the buffer pointer `buf` is NULL or if the size `sz` is zero; if so, set `opt_len` to 0 (if provided) and return 0.
    - Initialize a variable argument list `ap` and start it with `va_start`, using `fmt` as the last fixed argument.
    - Use `vsnprintf` to format the string according to `fmt` and the variable arguments, storing the result in `buf` and capturing the return value in `ret`.
    - Calculate the length of the formatted string using `fd_ulong_if` to ensure it does not exceed `sz-1` and store it in `len`.
    - Null-terminate the buffer at position `len`.
    - End the variable argument list with `va_end`.
    - If `opt_len` is provided, store the length of the formatted string in it.
    - Return 1 if the formatted string length `len` matches the return value `ret` from `vsnprintf`, otherwise return 0.
- **Output**: Returns 1 if the formatted string fits within the buffer size, otherwise returns 0.


---
### fd\_cstr\_append\_printf<!-- {{#callable:fd_cstr_append_printf}} -->
The `fd_cstr_append_printf` function appends formatted data to a given buffer using a format string and variable arguments.
- **Inputs**:
    - `buf`: A pointer to the buffer where the formatted string will be appended.
    - `fmt`: A constant character pointer representing the format string, followed by a variable number of arguments to be formatted.
- **Control Flow**:
    - Check if the buffer pointer `buf` is NULL; if so, return NULL immediately.
    - Initialize a `va_list` to handle the variable arguments and start it with `va_start`.
    - Use `vsprintf` to format the string according to `fmt` and the variable arguments, storing the result in `buf`.
    - End the use of `va_list` with `va_end`.
    - Calculate the return pointer by adding the result of `fd_ulong_if` to `buf`, which checks if `ret` is negative and returns 0UL if true, otherwise returns the number of characters written.
- **Output**: Returns a pointer to the end of the formatted string within the buffer, or NULL if the buffer was initially NULL.


---
### fd\_cstr\_tokenize<!-- {{#callable:fd_cstr_tokenize}} -->
The `fd_cstr_tokenize` function tokenizes a given string into substrings based on a specified delimiter and stores the tokens in an array.
- **Inputs**:
    - `tok`: A pointer to an array of character pointers where the tokens will be stored.
    - `tok_max`: The maximum number of tokens that can be stored in the `tok` array.
    - `p`: The input string to be tokenized.
    - `delim`: The character used as a delimiter to separate tokens in the input string.
- **Control Flow**:
    - Check if the input string `p` is NULL; if so, return 0.
    - Initialize `tok_cnt` to 0 to keep track of the number of tokens found.
    - Enter an infinite loop to process the input string.
    - Skip leading whitespace characters in the input string `p`.
    - If the end of the string is reached (null character), break the loop.
    - If the current token count is less than `tok_max`, store the start of the token in the `tok` array.
    - Increment the token count `tok_cnt`.
    - Continue to find the end of the current token by searching for the delimiter or the end of the string.
    - If the end of the string is reached, break the loop.
    - Terminate the current token by replacing the delimiter with a null character and move to the next character.
    - Return the total number of tokens found, `tok_cnt`.
- **Output**: The function returns the number of tokens found and stored in the `tok` array.



# Purpose
This C source code file implements a JSON lexer, which is responsible for tokenizing JSON data. The lexer processes a JSON string and identifies various tokens such as numbers, strings, booleans, null values, and structural characters like brackets and commas. The file defines several functions to manage the state of the lexer, parse different types of JSON tokens, and handle errors. Key functions include [`json_lex_state_new`](#json_lex_state_new) and [`json_lex_state_delete`](#json_lex_state_delete) for initializing and cleaning up the lexer state, [`json_lex_next_token`](#json_lex_next_token) for scanning the next token, and specialized functions like [`json_lex_parse_number`](#json_lex_parse_number) and [`json_lex_parse_string`](#json_lex_parse_string) for parsing specific token types. The lexer also includes functionality to validate UTF-8 encoding and handle escape sequences within JSON strings.

The code is structured to be part of a larger system, likely a JSON parser, where it serves as a foundational component for reading and interpreting JSON data. It provides a narrow but essential functionality focused on lexical analysis, which is a preliminary step in parsing. The file does not define a public API or external interfaces directly but rather provides internal functions that are likely used by other components of a JSON parsing library. The use of static functions and the absence of a `main` function suggest that this file is intended to be compiled as part of a library rather than as a standalone executable.
# Imports and Dependencies

---
- `json_lex.h`
- `stdio.h`
- `stdlib.h`
- `stdarg.h`


# Global Variables

---
### json\_lex\_append\_prepare
- **Type**: `static char*`
- **Description**: The `json_lex_append_prepare` function is a static function that prepares a JSON lexer state for appending additional text to a string. It ensures that there is enough allocated space in the `last_str` buffer of the `json_lex_state_t` structure to accommodate the new text, including a null terminator.
- **Use**: This function is used to manage memory allocation for appending text to a JSON lexer state's string buffer, ensuring sufficient space is available.


# Functions

---
### json\_lex\_state\_new<!-- {{#callable:json_lex_state_new}} -->
The `json_lex_state_new` function initializes a `json_lex_state` structure with a given JSON string, its size, and a scratchpad for memory allocation.
- **Inputs**:
    - `state`: A pointer to a `json_lex_state` structure that will be initialized.
    - `json`: A pointer to a constant character array representing the JSON string to be lexed.
    - `json_sz`: An unsigned long integer representing the size of the JSON string.
    - `spad`: A pointer to a `fd_spad_t` structure used for memory allocation.
- **Control Flow**:
    - Assigns the JSON string pointer to the `json` field of the `state` structure.
    - Sets the `json_sz` field of the `state` structure to the size of the JSON string.
    - Initializes the `pos` field to 0, indicating the starting position for lexing.
    - Sets the `last_tok` field to `JSON_TOKEN_ERROR`, indicating no valid token has been parsed yet.
    - Initializes the `last_bool` field to 0, indicating no boolean value has been parsed yet.
    - Sets the `last_str` field to point to `last_str_firstbuf`, a buffer for storing the last parsed string.
    - Initializes `last_str_sz` to 0, indicating no string has been parsed yet.
    - Sets `last_str_alloc` to the size of `last_str_firstbuf`, indicating the initial allocation size for strings.
    - Initializes the first character of `last_str_firstbuf` to the null terminator, indicating an empty string.
    - Assigns the `spad` pointer to the `spad` field of the `state` structure for memory management.
- **Output**: This function does not return a value; it initializes the provided `json_lex_state` structure.


---
### json\_lex\_state\_delete<!-- {{#callable:json_lex_state_delete}} -->
The `json_lex_state_delete` function is a placeholder for deleting or cleaning up a `json_lex_state` structure, but currently does nothing.
- **Inputs**:
    - `state`: A pointer to a `json_lex_state` structure that is intended to be deleted or cleaned up.
- **Control Flow**:
    - The function takes a single argument, `state`, which is a pointer to a `json_lex_state` structure.
    - The function body contains a single statement that casts `state` to void, effectively doing nothing with it.
- **Output**: The function does not return any value or perform any operations.


---
### json\_lex\_parse\_number<!-- {{#callable:json_lex_parse_number}} -->
The `json_lex_parse_number` function parses a numeric constant from a JSON string, determining if it is an integer or a floating-point number, and stores it in the lexer state.
- **Inputs**:
    - `state`: A pointer to a `json_lex_state` structure that holds the current state of the JSON lexer, including the JSON string, its size, and other parsing-related data.
    - `start_pos`: A pointer to the starting position in the JSON string from which the number parsing should begin.
- **Control Flow**:
    - Initialize `pos` to `start_pos` and `end_pos` to the end of the JSON string.
    - Check for a negative sign and increment `pos` if present.
    - Iterate over digits to parse the integer part of the number.
    - Check for a decimal point to identify a floating-point number and parse the fractional part if present.
    - Check for an exponent part (indicated by 'e' or 'E') and parse it if present, marking the number as a float.
    - Ensure the number ends with a valid terminating character (whitespace or punctuation).
    - If the number is malformed, set the error position in the state and return `JSON_TOKEN_ERROR`.
    - Copy the parsed number into the state's `last_str` buffer and update its size.
    - Set the current position in the state to the end of the parsed number.
    - Return `JSON_TOKEN_FLOAT` if the number is a float, otherwise return `JSON_TOKEN_INTEGER`.
- **Output**: Returns `JSON_TOKEN_FLOAT` if the parsed number is a floating-point number, `JSON_TOKEN_INTEGER` if it is an integer, or `JSON_TOKEN_ERROR` if the number is malformed.
- **Functions called**:
    - [`json_lex_sprintf`](#json_lex_sprintf)


---
### json\_lex\_validate\_encoding<!-- {{#callable:json_lex_validate_encoding}} -->
The function `json_lex_validate_encoding` checks a segment of text for valid UTF-8 encoding and returns a pointer to the first invalid character if an error is found, or NULL if the text is valid.
- **Inputs**:
    - `t`: A pointer to the start of the text segment to be validated.
    - `t_end`: A pointer to the end of the text segment to be validated.
- **Control Flow**:
    - Initialize a static lookup table `case_table` to determine the number of bytes in a UTF-8 character based on the first byte.
    - Iterate over the text segment from `t` to `t_end`.
    - For each character, use the lookup table to determine the expected number of bytes for the UTF-8 character.
    - Check if the subsequent bytes match the expected UTF-8 encoding pattern using the `MATCH` macro.
    - If a character does not match the expected pattern, return a pointer to the invalid character.
    - If all characters are valid, return NULL.
- **Output**: A pointer to the first invalid character in the text if an error is found, or NULL if the text is valid.


---
### json\_lex\_parse\_string<!-- {{#callable:json_lex_parse_string}} -->
The `json_lex_parse_string` function parses a JSON string from a given position, handling escape sequences and validating UTF-8 encoding, and returns a token indicating success or error.
- **Inputs**:
    - `state`: A pointer to a `json_lex_state` structure that holds the current state of the JSON lexer, including the JSON text, its size, and the current position.
    - `start_pos`: A pointer to the starting position in the JSON text where the string parsing should begin, typically pointing to the opening quote of the string.
- **Control Flow**:
    - Initialize the last string size and set the first character of the last string to null terminator.
    - Set `pos` to the character after the starting quote and define `end_pos` as the end of the JSON text.
    - Enter a loop that continues until `pos` reaches `end_pos`.
    - If a closing quote is found, update the position in the state and return `JSON_TOKEN_STRING`.
    - If the current character is not a backslash, find the next quote or backslash, validate the encoding, and copy the text if valid.
    - If an escape sequence is detected, handle simple escapes or hexadecimal escapes, appending the decoded character to the string.
    - If an error is encountered, update the position in the state, format an error message, and return `JSON_TOKEN_ERROR`.
    - If the loop ends without finding a closing quote, report an unterminated string error and return `JSON_TOKEN_ERROR`.
- **Output**: Returns a long integer representing a token: `JSON_TOKEN_STRING` if the string is successfully parsed, or `JSON_TOKEN_ERROR` if an error occurs.
- **Functions called**:
    - [`json_lex_validate_encoding`](#json_lex_validate_encoding)
    - [`json_lex_sprintf`](#json_lex_sprintf)
    - [`json_lex_append_prepare`](#json_lex_append_prepare)
    - [`json_lex_append_char`](#json_lex_append_char)


---
### json\_lex\_error<!-- {{#callable:json_lex_error}} -->
The `json_lex_error` function reports a lexical error in JSON parsing by updating the position in the state and formatting an error message.
- **Inputs**:
    - `state`: A pointer to a `json_lex_state` structure that holds the current state of the JSON lexer.
    - `pos`: A pointer to a character in the JSON string where the error occurred.
- **Control Flow**:
    - Calculate the position of the error by subtracting the start of the JSON string from the error position pointer and store it in the state's `pos` field.
    - Call [`json_lex_sprintf`](#json_lex_sprintf) to format an error message indicating a lexical error at the calculated position.
    - Return the constant `JSON_TOKEN_ERROR` to indicate an error token.
- **Output**: Returns `JSON_TOKEN_ERROR`, a constant indicating a lexical error in the JSON parsing process.
- **Functions called**:
    - [`json_lex_sprintf`](#json_lex_sprintf)


---
### json\_lex\_next\_token<!-- {{#callable:json_lex_next_token}} -->
The `json_lex_next_token` function scans the JSON input from the current position in the lexer state and identifies the next token, updating the lexer state accordingly.
- **Inputs**:
    - `state`: A pointer to a `json_lex_state` structure that holds the current state of the JSON lexer, including the JSON string, its size, the current position, and the last token identified.
- **Control Flow**:
    - Initialize `pos` to the current position in the JSON string and `end_pos` to the end of the JSON string.
    - Enter a loop that continues until `pos` reaches `end_pos`.
    - Skip whitespace characters by incrementing `pos` and continuing the loop.
    - Check for single-character tokens like '[', ']', '{', '}', ',', and ':'; update the position and return the corresponding token if found.
    - Check for the keywords 'null', 'true', and 'false'; verify the full keyword is present, update the position, and return the corresponding token, or call [`json_lex_error`](#json_lex_error) if the keyword is malformed.
    - For numbers, call [`json_lex_parse_number`](#json_lex_parse_number) to handle parsing and return the token.
    - For strings, call [`json_lex_parse_string`](#json_lex_parse_string) to handle parsing and return the token.
    - For any unrecognized character, call [`json_lex_error`](#json_lex_error) to handle the error and return the error token.
    - If the end of the JSON string is reached without finding a token, update the position and return `JSON_TOKEN_END`.
- **Output**: Returns a long integer representing the type of the next JSON token found, or an error token if an error occurs.
- **Functions called**:
    - [`json_lex_error`](#json_lex_error)
    - [`json_lex_parse_number`](#json_lex_parse_number)
    - [`json_lex_parse_string`](#json_lex_parse_string)


---
### json\_lex\_get\_text<!-- {{#callable:json_lex_get_text}} -->
The `json_lex_get_text` function retrieves the last parsed JSON string and optionally its size from a given lexer state.
- **Inputs**:
    - `state`: A pointer to a `json_lex_state_t` structure, which holds the state of the JSON lexer, including the last parsed string and its size.
    - `sz`: A pointer to an unsigned long where the size of the last parsed string will be stored, or NULL if the size is not needed.
- **Control Flow**:
    - Check if the `sz` pointer is not NULL.
    - If `sz` is not NULL, set the value it points to the size of the last parsed string stored in `state->last_str_sz`.
    - Return the pointer to the last parsed string stored in `state->last_str`.
- **Output**: Returns a pointer to the last parsed JSON string stored in the lexer state.


---
### json\_lex\_as\_int<!-- {{#callable:json_lex_as_int}} -->
The function `json_lex_as_int` converts a string representation of a decimal number stored in a `json_lex_state_t` structure to a long integer.
- **Inputs**:
    - `lex`: A pointer to a `json_lex_state_t` structure, which contains the string representation of a number to be converted.
- **Control Flow**:
    - Initialize a pointer `i` to the start of the string and `i_end` to the end of the string using `lex->last_str` and `lex->last_str_sz` respectively.
    - Check if the string starts with a '-' character to determine if the number is negative, and adjust the pointer `i` accordingly.
    - Initialize a long integer `n` to 0 to accumulate the numeric value.
    - Iterate over each character in the string from `i` to `i_end`, converting each character to its numeric value and accumulating it into `n`.
    - Return the accumulated value `n`, negated if the number was determined to be negative.
- **Output**: A long integer representing the converted value of the string.


---
### json\_lex\_as\_float<!-- {{#callable:json_lex_as_float}} -->
The function `json_lex_as_float` converts a string stored in a `json_lex_state_t` structure to a double-precision floating-point number.
- **Inputs**:
    - `lex`: A pointer to a `json_lex_state_t` structure, which contains the string to be converted to a float.
- **Control Flow**:
    - The function calls `strtod`, passing `lex->last_str` as the string to convert and `NULL` for the end pointer, to convert the string to a double.
- **Output**: A double-precision floating-point number representing the converted value of the string.


---
### json\_lex\_append\_prepare<!-- {{#callable:json_lex_append_prepare}} -->
The `json_lex_append_prepare` function reserves space at the end of a string for additional text, ensuring sufficient memory allocation and returning a pointer to the new space.
- **Inputs**:
    - `lex`: A pointer to a `json_lex_state_t` structure, which holds the current state of the JSON lexer, including the string being constructed.
    - `sz`: An unsigned long integer representing the size of additional space to reserve at the end of the string.
- **Control Flow**:
    - Calculate the new size of the string by adding `sz` to `lex->last_str_sz`.
    - Check if the new size plus one (for the null terminator) exceeds the current allocation (`lex->last_str_alloc`).
    - If the allocation is insufficient, double the allocation size until it can accommodate the new size plus the null terminator.
    - Allocate new memory for the string using `fd_spad_alloc` and copy the existing string content to the new memory location.
    - Set a null terminator at the end of the reserved space.
    - Update `lex->last_str_sz` to the new size.
    - Return a pointer to the start of the newly reserved space in the string.
- **Output**: A pointer to the newly reserved space at the end of the string, where additional text can be appended.


---
### json\_lex\_append\_char<!-- {{#callable:json_lex_append_char}} -->
The `json_lex_append_char` function appends a Unicode character to a JSON lexer state, encoding it in UTF-8 format.
- **Inputs**:
    - `lex`: A pointer to a `json_lex_state_t` structure representing the current state of the JSON lexer.
    - `ch`: An unsigned integer representing the Unicode character to be appended, which will be encoded in UTF-8.
- **Control Flow**:
    - Check if the character `ch` is less than 0x80; if true, prepare space for 1 byte and store the character directly.
    - If `ch` is less than 0x800, prepare space for 2 bytes and encode the character using two UTF-8 bytes.
    - If `ch` is less than 0x10000, prepare space for 3 bytes and encode the character using three UTF-8 bytes.
    - If `ch` is less than 0x110000, prepare space for 4 bytes and encode the character using four UTF-8 bytes.
- **Output**: The function does not return a value; it modifies the `json_lex_state_t` structure by appending the UTF-8 encoded character to its string buffer.
- **Functions called**:
    - [`json_lex_append_prepare`](#json_lex_append_prepare)


---
### json\_lex\_sprintf<!-- {{#callable:json_lex_sprintf}} -->
The `json_lex_sprintf` function formats a string using a variable argument list and stores it in a buffer, dynamically resizing the buffer if necessary.
- **Inputs**:
    - `lex`: A pointer to a `json_lex_state_t` structure, which holds the state of the JSON lexer, including the buffer for the formatted string.
    - `format`: A C-style format string that specifies how to format the subsequent arguments.
    - `...`: A variable number of arguments that are formatted according to the `format` string.
- **Control Flow**:
    - Initialize a variable argument list `ap` using `va_start` with `format` as the last fixed argument.
    - Use `vsnprintf` to attempt to format the string into `lex->last_str` with the current buffer size `lex->last_str_alloc`.
    - Check if the formatted string fits in the current buffer; if not, double the buffer size until it can fit.
    - Allocate a new buffer with the updated size using `fd_spad_alloc` and reformat the string into this new buffer.
    - Update `lex->last_str_sz` with the size of the formatted string if successful, or set it to 0 and clear the buffer if formatting fails.
- **Output**: The function does not return a value, but it updates the `last_str` and `last_str_sz` fields of the `json_lex_state_t` structure pointed to by `lex` with the formatted string and its size, respectively.


# Function Declarations (Public API)

---
### json\_lex\_append\_prepare<!-- {{#callable_declaration:json_lex_append_prepare}} -->
Reserve space at the end of the string for additional text.
- **Description**: This function is used to ensure that there is enough space in the string buffer of a JSON lexer state to append additional text. It should be called before adding new text to the buffer to prevent buffer overflow. The function adjusts the buffer size if necessary, ensuring that the new size can accommodate the additional text plus a null terminator. It returns a pointer to the location in the buffer where the new text can be safely written. This function must be used in conjunction with a properly initialized `json_lex_state_t` structure.
- **Inputs**:
    - `lex`: A pointer to a `json_lex_state_t` structure representing the current state of the JSON lexer. Must not be null.
    - `sz`: The size of the additional text to be appended, in bytes. Must be a positive integer.
- **Output**: Returns a pointer to the location in the buffer where the new text can be written.
- **See also**: [`json_lex_append_prepare`](#json_lex_append_prepare)  (Implementation)


---
### json\_lex\_append\_char<!-- {{#callable_declaration:json_lex_append_char}} -->
Append a Unicode character to the JSON lexer state as UTF-8.
- **Description**: This function appends a Unicode character to the current string being processed in the JSON lexer state, encoding it in UTF-8 format. It should be used when a character needs to be added to the lexer state during JSON parsing. The function handles characters in the full Unicode range up to U+10FFFF, ensuring they are correctly encoded in UTF-8. It assumes that the lexer state has been properly initialized and is in a valid state for appending characters.
- **Inputs**:
    - `lex`: A pointer to a json_lex_state_t structure representing the current state of the JSON lexer. Must not be null, and the lexer state should be properly initialized before calling this function.
    - `ch`: An unsigned integer representing the Unicode character to append. Valid values are in the range 0 to 0x10FFFF. Characters outside this range are not handled by this function.
- **Output**: None
- **See also**: [`json_lex_append_char`](#json_lex_append_char)  (Implementation)



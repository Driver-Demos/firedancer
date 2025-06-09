# Purpose
This C header file defines the interface for a JSON lexical scanner, which is responsible for tokenizing JSON text. It includes definitions for various JSON token types, such as brackets, braces, colons, commas, and literals like null, boolean, integers, floats, and strings. The file declares a `json_lex_state` structure to maintain the state of the lexical analysis, including the input JSON text, current position, and the last token parsed. It provides function prototypes for initializing and deleting the lexical state, retrieving the next token, and converting token strings to integers or floats. Additionally, it includes a utility function for formatting strings within the lexical state. This header is essential for parsing JSON data in applications that require a custom JSON lexer.
# Imports and Dependencies

---
- `../../util/fd_util.h`


# Global Variables

---
### json\_lex\_get\_text
- **Type**: `function`
- **Description**: The `json_lex_get_text` function is a global function that retrieves the last lexical text result from a JSON lexical state. This result can be a string, a number represented as text, or an error message, and it is encoded in UTF-8.
- **Use**: This function is used to obtain the textual representation of the last token parsed by the JSON lexical scanner.


# Data Structures

---
### json\_lex\_state
- **Type**: `struct`
- **Members**:
    - `json`: Pointer to the input JSON text.
    - `json_sz`: Size of the input JSON text.
    - `pos`: Current position in the JSON text being parsed.
    - `last_tok`: The last token parsed from the JSON text.
    - `last_bool`: Value of the last boolean token parsed.
    - `last_str`: Pointer to the last string, number (as text), or error message parsed.
    - `last_str_sz`: Size of the last string parsed.
    - `last_str_alloc`: Allocated size for the last string buffer.
    - `last_str_firstbuf`: Buffer for storing the first 512 bytes of the last string.
    - `spad`: Pointer to a scratchpad memory structure used during parsing.
- **Description**: The `json_lex_state` structure is used to maintain the state of a JSON lexical scanner. It holds the input JSON text and its size, tracks the current parsing position, and stores information about the last token parsed, including its type and value. The structure also manages memory for the last string or error message encountered, using a buffer for efficient storage. Additionally, it includes a pointer to a scratchpad memory structure to assist with parsing operations.


---
### json\_lex\_state\_t
- **Type**: `struct`
- **Members**:
    - `json`: Pointer to the input JSON text.
    - `json_sz`: Size of the input JSON text.
    - `pos`: Current position in the JSON text being parsed.
    - `last_tok`: Last token parsed from the JSON text.
    - `last_bool`: Value of the last boolean token parsed.
    - `last_str`: Pointer to the last string, number (as text), or error message parsed.
    - `last_str_sz`: Size of the last string parsed.
    - `last_str_alloc`: Allocated size for the last string buffer.
    - `last_str_firstbuf`: Buffer for storing the first 512 bytes of the last string.
    - `spad`: Pointer to an fd_spad_t structure for additional state or context.
- **Description**: The `json_lex_state_t` structure is used to maintain the state of a JSON lexical scanner, which processes JSON text to identify and categorize tokens such as brackets, braces, colons, commas, and various data types like null, boolean, integer, float, and string. It keeps track of the input JSON text, the current parsing position, the last token parsed, and the value of the last boolean or string token. Additionally, it manages memory for the last string parsed and uses a buffer for efficient storage. The structure also includes a pointer to an `fd_spad_t` for any additional state or context needed during parsing.


# Function Declarations (Public API)

---
### json\_lex\_state\_new<!-- {{#callable_declaration:json_lex_state_new}} -->
Initialize a JSON lexical state with the provided JSON text.
- **Description**: This function sets up a new JSON lexical state, preparing it for parsing operations. It initializes the state with the given JSON text and its size, and sets the initial parsing position and token state. This function should be called before any parsing operations are performed on the JSON text. The caller must ensure that the `state` pointer is valid and that the `json` pointer points to a valid JSON string of the specified size. The `spad` parameter is optional and can be used for additional parsing context if needed.
- **Inputs**:
    - `state`: A pointer to a `json_lex_state_t` structure that will be initialized. Must not be null.
    - `json`: A pointer to the JSON text to be parsed. Must not be null and should point to a valid JSON string.
    - `json_sz`: The size of the JSON text in bytes. Must accurately reflect the length of the JSON string.
    - `spad`: A pointer to an `fd_spad_t` structure for additional parsing context. Can be null if not used.
- **Output**: None
- **See also**: [`json_lex_state_new`](json_lex.c.driver.md#json_lex_state_new)  (Implementation)


---
### json\_lex\_state\_delete<!-- {{#callable_declaration:json_lex_state_delete}} -->
Deletes a JSON lexical state.
- **Description**: Use this function to clean up and delete a JSON lexical state when it is no longer needed. This function should be called to release any resources associated with the lexical state after parsing is complete. It is important to ensure that the state has been properly initialized before calling this function. The function does not perform any operations on the state, so it is safe to call even if the state is in an error condition or has not been fully utilized.
- **Inputs**:
    - `state`: A pointer to a `json_lex_state_t` structure representing the lexical state to be deleted. The pointer must not be null, and the state should have been previously initialized using `json_lex_state_new`. The caller retains ownership of the memory for the state structure itself.
- **Output**: None
- **See also**: [`json_lex_state_delete`](json_lex.c.driver.md#json_lex_state_delete)  (Implementation)


---
### json\_lex\_next\_token<!-- {{#callable_declaration:json_lex_next_token}} -->
Retrieve the next JSON token from the input stream.
- **Description**: Use this function to parse the next token from a JSON input stream, advancing the current position within the stream. It must be called with a valid and initialized `json_lex_state_t` structure. The function handles various JSON elements such as brackets, braces, commas, colons, literals like null, true, and false, numbers, and strings. It updates the state with the type of token found and any associated data, such as boolean values. If the end of the input is reached, it returns a special token indicating the end. In case of an error, it returns an error token.
- **Inputs**:
    - `state`: A pointer to a `json_lex_state_t` structure representing the current state of the JSON lexer. It must be initialized with the JSON text and its size before calling this function. The function updates this state with the position of the next token and the type of token found. The caller retains ownership and must ensure the pointer is not null.
- **Output**: Returns a long integer representing the type of the next token found in the JSON input. Possible return values include specific tokens for JSON elements, an end-of-input token, or an error token if an invalid sequence is encountered.
- **See also**: [`json_lex_next_token`](json_lex.c.driver.md#json_lex_next_token)  (Implementation)


---
### json\_lex\_get\_text<!-- {{#callable_declaration:json_lex_get_text}} -->
Retrieve the last parsed lexical text from the JSON lexer state.
- **Description**: This function is used to obtain the last string, number (as text), or error message that was parsed by the JSON lexer. It should be called after a token has been processed to access the associated text. The function provides a pointer to the text and optionally returns the size of the text if the `sz` parameter is not null. The caller should ensure that the `state` has been properly initialized and that a token has been parsed before calling this function.
- **Inputs**:
    - `state`: A pointer to a `json_lex_state_t` structure representing the current state of the JSON lexer. Must not be null and should be properly initialized.
    - `sz`: A pointer to an unsigned long where the size of the last parsed text will be stored. Can be null if the size is not needed. If not null, it will be set to the size of the last parsed text.
- **Output**: Returns a pointer to the last parsed lexical text, which can be a string, number (as text), or error message. The text is UTF-8 encoded.
- **See also**: [`json_lex_get_text`](json_lex.c.driver.md#json_lex_get_text)  (Implementation)


---
### json\_lex\_as\_int<!-- {{#callable_declaration:json_lex_as_int}} -->
Converts the last parsed JSON string to an integer.
- **Description**: Use this function to convert the last parsed JSON string, stored in the lexical state, into a long integer. This function assumes that the string represents a decimal number. It should be called after a successful parsing operation that results in a numeric string. The function handles negative numbers and returns the corresponding long integer value. Ensure that the lexical state has a valid string representation of a number before calling this function to avoid undefined behavior.
- **Inputs**:
    - `lex`: A pointer to a json_lex_state_t structure containing the lexical state. The structure must have a valid last_str field representing a numeric string in decimal format. The caller retains ownership and must ensure the pointer is not null.
- **Output**: Returns the long integer value represented by the last parsed JSON string. If the string represents a negative number, the return value will be negative.
- **See also**: [`json_lex_as_int`](json_lex.c.driver.md#json_lex_as_int)  (Implementation)


---
### json\_lex\_as\_float<!-- {{#callable_declaration:json_lex_as_float}} -->
Convert the last parsed string to a floating-point number.
- **Description**: Use this function to convert the last parsed JSON token, stored as a string in the lexical state, into a floating-point number. This function should be called after a successful token parsing operation that results in a numeric string representation. It is particularly useful when the last token is expected to be a floating-point number. Ensure that the lexical state has been properly initialized and that the last token is indeed a valid numeric string to avoid undefined behavior.
- **Inputs**:
    - `lex`: A pointer to a json_lex_state_t structure representing the current state of the JSON lexical scanner. The structure must be initialized and must contain a valid last_str field representing a numeric string. The caller retains ownership of this pointer, and it must not be null.
- **Output**: Returns the floating-point number represented by the last parsed string in the lexical state. If the string is not a valid representation of a floating-point number, the behavior is undefined.
- **See also**: [`json_lex_as_float`](json_lex.c.driver.md#json_lex_as_float)  (Implementation)


---
### json\_lex\_sprintf<!-- {{#callable_declaration:json_lex_sprintf}} -->
Replaces the string in the lexical state with a formatted string.
- **Description**: This function formats a string according to the specified format and arguments, and stores the result in the `last_str` field of the provided lexical state. It is typically used to update the string representation of the last parsed token or error message. The function dynamically allocates more memory if the formatted string exceeds the current allocation size. It must be called with a valid `json_lex_state_t` object that has been properly initialized. The function handles formatting errors by setting the string to an empty value.
- **Inputs**:
    - `lex`: A pointer to a `json_lex_state_t` structure where the formatted string will be stored. Must not be null and should be properly initialized before calling this function.
    - `format`: A C string that contains the format string as in `printf`. Must not be null. The format string specifies how subsequent arguments are converted for output.
    - `...`: A variable number of arguments that are formatted according to the format string. The number and types of these arguments must match the format specifiers in the format string.
- **Output**: None
- **See also**: [`json_lex_sprintf`](json_lex.c.driver.md#json_lex_sprintf)  (Implementation)



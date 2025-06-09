# Purpose
The provided C source code file implements a parser for TOML (Tom's Obvious, Minimal Language) configuration files. The code is designed to read and interpret TOML data, converting it into a structured format that can be stored in a "pod" (presumably a data structure for holding parsed data). The parser is implemented as a backtracking recursive descent parser, which allows it to handle the hierarchical and nested nature of TOML files. The code includes functions for parsing various TOML constructs such as keys, values, arrays, tables, and different data types like strings, integers, floats, and dates.

Key components of the code include the `fd_toml_parser_t` structure, which maintains the state of the parser, including the current position in the input data, error status, and buffers for temporary data storage. The parser functions are organized to handle different TOML syntax elements, with utility functions for handling specific parsing tasks like whitespace, comments, and escape sequences. The code also includes error handling mechanisms, with functions to report errors and manage memory efficiently during parsing. This file is intended to be part of a larger library, as indicated by its inclusion of external headers and its focus on parsing logic rather than standalone execution.
# Imports and Dependencies

---
- `fd_toml.h`
- `../../util/fd_util.h`
- `ctype.h`
- `math.h`
- `time.h`


# Data Structures

---
### fd\_toml\_cur
- **Type**: `struct`
- **Members**:
    - `lineno`: Stores the current line number being processed in the TOML data.
    - `data`: Points to the current position in the TOML data being parsed.
- **Description**: The `fd_toml_cur` structure is a cursor object used in the TOML parsing process. It maintains the current line number and a pointer to the current position in the TOML data, allowing the parser to track its progress through the input. This structure is designed to be safely copied via assignment, facilitating backtracking during parsing.


---
### fd\_toml\_cur\_t
- **Type**: `struct`
- **Members**:
    - `lineno`: Stores the current line number being processed by the parser.
    - `data`: Points to the current position in the TOML data being parsed.
- **Description**: The `fd_toml_cur_t` structure is a cursor object used in the TOML parser to track the current position within the TOML data being processed. It contains a line number to keep track of the current line in the data, which is useful for error reporting and debugging, and a pointer to the current data position, allowing the parser to efficiently navigate through the TOML input. This structure is designed to be safely copied via assignment, facilitating backtracking during parsing.


---
### fd\_toml\_parser
- **Type**: `struct`
- **Members**:
    - `c`: A cursor object used for backtracking and tracking the current position in the TOML data.
    - `data_end`: A pointer to the end of the TOML data, marking one past the end of file.
    - `pod`: A user-provided memory region where parsed data is stored.
    - `error`: An integer indicating if a fatal error occurred during parsing.
    - `scratch`: A buffer used for temporarily storing strings during parsing.
    - `scratch_cur`: A pointer to the next free byte in the scratch buffer.
    - `scratch_end`: A pointer to the end of the scratch buffer, marking one past the last valid byte.
    - `key_len`: The length of the current key being parsed.
    - `key`: A character array storing the current key as a C-style string.
- **Description**: The `fd_toml_parser` structure is designed to manage the state of a TOML parser, including the current position in the data, error tracking, and temporary storage for keys and values. It uses a cursor (`fd_toml_cur_t`) to facilitate backtracking and line number tracking, and it maintains a scratch buffer for handling strings during parsing. The structure also includes a user-provided memory region (`pod`) for storing parsed data, and it tracks errors that occur during parsing with an integer flag. The `key` array and `key_len` field are used to manage the current key being processed.


---
### fd\_toml\_parser\_t
- **Type**: `struct`
- **Members**:
    - `c`: A cursor object representing the current position in the TOML data being parsed.
    - `data_end`: A pointer to the end of the TOML data, marking one past the last character.
    - `pod`: A user-provided buffer where parsed TOML data is stored.
    - `error`: An integer indicating if a fatal error occurred during parsing.
    - `scratch`: A buffer used for temporary storage of strings during parsing.
    - `scratch_cur`: A pointer to the next free byte in the scratch buffer.
    - `scratch_end`: A pointer to the end of the scratch buffer, marking one past the last byte.
    - `key_len`: The length of the current key being parsed.
    - `key`: A character array storing the current key as a C-string, with a maximum length defined by FD_TOML_PATH_MAX.
- **Description**: The `fd_toml_parser_t` structure is used to maintain the state of the TOML parser, including the current position in the input data, buffers for temporary storage, and error handling. It facilitates the parsing of TOML data into a structured format stored in a user-provided buffer, handling keys and values, and managing memory efficiently during the parsing process.


---
### fd\_toml\_dec
- **Type**: `struct`
- **Members**:
    - `res`: Stores the result of the parsed integer value.
    - `len`: Indicates the length of the parsed integer string.
    - `neg`: A flag indicating if the parsed integer is negative.
- **Description**: The `fd_toml_dec` structure is used to represent a decimal integer parsed from a TOML file. It contains fields to store the result of the parsed integer (`res`), the length of the parsed integer string (`len`), and a flag (`neg`) to indicate if the integer is negative. This structure is part of the TOML parsing process, specifically for handling decimal integers.


---
### fd\_toml\_dec\_t
- **Type**: `struct`
- **Members**:
    - `res`: Stores the result of the parsed decimal integer.
    - `len`: Indicates the length of the parsed integer string.
    - `neg`: A flag indicating if the parsed integer is negative.
- **Description**: The `fd_toml_dec_t` structure is used to represent a parsed decimal integer from a TOML file. It contains fields to store the result of the parsing (`res`), the length of the parsed integer string (`len`), and a flag (`neg`) to indicate if the integer is negative. This structure is part of the TOML parsing process, specifically for handling decimal integers, and is used to facilitate the conversion of string representations of numbers into their numeric form.


# Functions

---
### fd\_toml\_str\_init<!-- {{#callable:fd_toml_str_init}} -->
Initializes the scratch buffer pointer in the `fd_toml_parser_t` structure.
- **Inputs**:
    - `parser`: A pointer to an instance of `fd_toml_parser_t`, which holds the state of the TOML parser.
- **Control Flow**:
    - The function directly assigns the base of the scratch buffer (`parser->scratch`) to the current scratch pointer (`parser->scratch_cur`).
- **Output**: The function does not return a value; it modifies the state of the `fd_toml_parser_t` instance by updating the `scratch_cur` pointer.


---
### fd\_toml\_str\_append<!-- {{#callable:fd_toml_str_append}} -->
Appends a specified amount of data to the scratch buffer of a TOML parser.
- **Inputs**:
    - `parser`: A pointer to an `fd_toml_parser_t` structure that holds the state of the TOML parser.
    - `data`: A pointer to the data to be appended to the scratch buffer.
    - `sz`: The size in bytes of the data to be appended.
- **Control Flow**:
    - Checks if there is enough space in the scratch buffer to append the new data.
    - If there is insufficient space, sets an error code in the parser and returns 0.
    - If there is enough space, copies the data into the scratch buffer at the current position.
    - Updates the current position in the scratch buffer to reflect the new end after appending the data.
    - Returns 1 to indicate success.
- **Output**: Returns 1 on successful appending of data, or 0 if there was an error due to insufficient space.


---
### fd\_toml\_str\_append\_utf8<!-- {{#callable:fd_toml_str_append_utf8}} -->
Appends the UTF-8 encoding of a given Unicode code point to the scratch buffer of a TOML parser.
- **Inputs**:
    - `parser`: A pointer to an instance of `fd_toml_parser_t`, which holds the state of the TOML parser including the scratch buffer.
    - `rune`: A long integer representing a Unicode code point to be appended in UTF-8 encoding.
- **Control Flow**:
    - Checks if there is enough space in the scratch buffer to append up to 4 bytes (the maximum size of a UTF-8 encoded character).
    - If there is insufficient space, it sets an error code in the parser and returns 0.
    - If there is enough space, it calls `fd_cstr_append_utf8` to append the UTF-8 representation of the `rune` to the scratch buffer.
    - Updates the current position in the scratch buffer to reflect the newly appended data.
    - Returns 1 to indicate success.
- **Output**: Returns 1 on successful appending of the UTF-8 encoded character, or 0 if there was an error due to insufficient space.


---
### fd\_toml\_advance\_inline<!-- {{#callable:fd_toml_advance_inline}} -->
Advances the parser's cursor by a specified number of characters.
- **Inputs**:
    - `parser`: A pointer to the `fd_toml_parser_t` structure that maintains the state of the TOML parser.
    - `n`: An unsigned long integer representing the number of characters to advance the parser's cursor.
- **Control Flow**:
    - The function directly increments the `data` pointer of the `fd_toml_cur` structure within the `parser` by `n` characters.
    - No bounds checking is performed, so it is assumed that the caller ensures that advancing by `n` does not exceed the limits of the data being parsed.
- **Output**: This function does not return a value; it modifies the internal state of the parser by moving the cursor forward.


---
### fd\_toml\_upsert\_empty\_pod<!-- {{#callable:fd_toml_upsert_empty_pod}} -->
Inserts a new empty subpod into the given `fd_toml_parser_t` if it does not already exist.
- **Inputs**:
    - `parser`: A pointer to an `fd_toml_parser_t` structure that contains the current state of the TOML parser, including the pod and key.
- **Control Flow**:
    - Checks if a subpod with the specified key exists in the current pod using `fd_pod_query_subpod`.
    - If the subpod does not exist, allocates memory for a new subpod using `fd_pod_new` and `fd_pod_join`.
    - Attempts to insert the new subpod into the pod with `fd_pod_insert`.
    - If the insertion fails, sets an error code in the parser and returns 0.
    - If the insertion is successful, cleans up the subpod using `fd_pod_delete` and `fd_pod_leave`.
    - Returns 1 to indicate success.
- **Output**: Returns 1 if the operation is successful, or 0 if an error occurs during insertion.


---
### fd\_toml\_parse\_ws<!-- {{#callable:fd_toml_parse_ws}} -->
The `fd_toml_parse_ws` function skips whitespace characters (spaces and tabs) in the TOML parser.
- **Inputs**:
    - `parser`: A pointer to a `fd_toml_parser_t` structure that holds the current state of the TOML parser.
- **Control Flow**:
    - The function enters a while loop that continues as long as there are available characters to parse.
    - Within the loop, it checks the first character of the current data in the parser.
    - If the character is not a space (' ') or a tab ('\t'), the loop breaks.
    - If the character is a space or tab, the function advances the parser's cursor by one character using [`fd_toml_advance_inline`](#fd_toml_advance_inline).
- **Output**: The function returns 1 to indicate successful parsing of whitespace.
- **Functions called**:
    - [`fd_toml_avail`](#fd_toml_avail)
    - [`fd_toml_advance_inline`](#fd_toml_advance_inline)


---
### fd\_toml\_parse\_comment<!-- {{#callable:fd_toml_parse_comment}} -->
Parses a TOML comment starting with '#' and advances the parser cursor until the end of the comment.
- **Inputs**:
    - `parser`: A pointer to an `fd_toml_parser_t` structure that maintains the state of the TOML parser.
- **Control Flow**:
    - Check if there are available bytes to parse using [`fd_toml_avail`](#fd_toml_avail).
    - If the first character is not '#', return 0 indicating no comment was found.
    - Advance the cursor to skip the '#' character.
    - Enter a loop that continues as long as there are available bytes.
    - Within the loop, check if the current character is a valid non-eol character (tab, printable ASCII, or non-ASCII).
    - If valid, advance the cursor to the next character; otherwise, break the loop.
    - Return 1 indicating a successful comment parse.
- **Output**: Returns 1 if a comment was successfully parsed, otherwise returns 0.
- **Functions called**:
    - [`fd_toml_avail`](#fd_toml_avail)
    - [`fd_toml_advance_inline`](#fd_toml_advance_inline)


---
### fd\_toml\_parse\_quotation\_mark<!-- {{#callable:fd_toml_parse_quotation_mark}} -->
Parses a quotation mark from the TOML input stream.
- **Inputs**:
    - `parser`: A pointer to an `fd_toml_parser_t` structure that maintains the state of the TOML parser.
- **Control Flow**:
    - Checks if there are available bytes to parse using [`fd_toml_avail`](#fd_toml_avail).
    - If no bytes are available, returns 0 indicating failure.
    - Checks if the current character is a quotation mark ("), returning 0 if it is not.
    - Advances the parser cursor by one character using [`fd_toml_advance_inline`](#fd_toml_advance_inline).
    - Returns 1 indicating success if the quotation mark was successfully parsed.
- **Output**: Returns 1 if a quotation mark was successfully parsed, otherwise returns 0.
- **Functions called**:
    - [`fd_toml_avail`](#fd_toml_avail)
    - [`fd_toml_advance_inline`](#fd_toml_advance_inline)


---
### fd\_toml\_parse\_basic\_unescaped<!-- {{#callable:fd_toml_parse_basic_unescaped}} -->
Parses a basic unescaped character in TOML format.
- **Inputs**:
    - `parser`: A pointer to an `fd_toml_parser_t` structure that holds the current state of the parser, including the cursor position and the data being parsed.
- **Control Flow**:
    - First, it checks if there are any bytes available for parsing using [`fd_toml_avail`](#fd_toml_avail). If not, it returns 0.
    - It retrieves the current character from the parser's data.
    - It checks if the character is a valid basic unescaped character (space, tab, specific ASCII characters, or non-ASCII). If not, it returns 0.
    - If the character is valid, it appends the character to the current string buffer using [`fd_toml_str_append_byte`](#fd_toml_str_append_byte).
    - The parser cursor is then advanced by one character using [`fd_toml_advance`](#fd_toml_advance).
    - Finally, it returns 1 to indicate success.
- **Output**: Returns 1 if a valid basic unescaped character was parsed and appended; otherwise, returns 0.
- **Functions called**:
    - [`fd_toml_avail`](#fd_toml_avail)
    - [`fd_toml_str_append_byte`](#fd_toml_str_append_byte)
    - [`fd_toml_advance`](#fd_toml_advance)


---
### fd\_toml\_parse\_basic\_char<!-- {{#callable:fd_toml_parse_basic_char}} -->
Parses a basic character from the TOML input, handling both unescaped and escaped characters.
- **Inputs**:
    - `parser`: A pointer to an `fd_toml_parser_t` structure that maintains the state of the TOML parser.
- **Control Flow**:
    - The function first attempts to parse a basic unescaped character using [`fd_toml_parse_basic_unescaped`](#fd_toml_parse_basic_unescaped).
    - If the first parsing attempt fails, it then attempts to parse an escaped character using [`fd_toml_parse_escaped`](#fd_toml_parse_escaped).
    - If both parsing attempts fail, the function returns 0, indicating no character was parsed.
- **Output**: Returns 1 if a basic character (either unescaped or escaped) was successfully parsed, otherwise returns 0.
- **Functions called**:
    - [`fd_toml_parse_basic_unescaped`](#fd_toml_parse_basic_unescaped)
    - [`fd_toml_parse_escaped`](#fd_toml_parse_escaped)


---
### fd\_toml\_parse\_literal\_char<!-- {{#callable:fd_toml_parse_literal_char}} -->
Parses a literal character from the TOML input and appends it to the parser's scratch buffer.
- **Inputs**:
    - `parser`: A pointer to an `fd_toml_parser_t` structure that holds the current state of the parser, including the input data and the scratch buffer.
- **Control Flow**:
    - First, it checks if there are any characters available for parsing using [`fd_toml_avail`](#fd_toml_avail). If not, it returns 0.
    - It retrieves the first character from the parser's current data.
    - It checks if the character is a valid literal character based on specified ranges (tab, space, and non-ASCII characters). If the character is invalid, it returns 0.
    - If the character is valid, it appends the character to the scratch buffer using [`fd_toml_str_append_byte`](#fd_toml_str_append_byte).
    - Finally, it advances the parser's cursor by one character using [`fd_toml_advance`](#fd_toml_advance) and returns 1 to indicate success.
- **Output**: Returns 1 if a valid literal character was parsed and appended, or 0 if no character was available or if the character was invalid.
- **Functions called**:
    - [`fd_toml_avail`](#fd_toml_avail)
    - [`fd_toml_str_append_byte`](#fd_toml_str_append_byte)
    - [`fd_toml_advance`](#fd_toml_advance)


---
### fd\_toml\_parse\_literal\_string<!-- {{#callable:fd_toml_parse_literal_string}} -->
Parses a TOML literal string enclosed in apostrophes.
- **Inputs**:
    - `parser`: A pointer to the `fd_toml_parser_t` structure that maintains the state of the parser.
- **Control Flow**:
    - Checks for the opening apostrophe using [`fd_toml_parse_apostrophe`](#fd_toml_parse_apostrophe) and returns 0 if not found.
    - Initializes the string buffer using [`fd_toml_str_init`](#fd_toml_str_init).
    - Enters a loop to parse literal characters using [`fd_toml_parse_literal_char`](#fd_toml_parse_literal_char) until no more valid characters are found.
    - Checks for the closing apostrophe using [`fd_toml_parse_apostrophe`](#fd_toml_parse_apostrophe) and returns 0 if not found.
    - Returns 1 to indicate successful parsing of the literal string.
- **Output**: Returns 1 if the literal string is successfully parsed, otherwise returns 0.
- **Functions called**:
    - [`fd_toml_parse_apostrophe`](#fd_toml_parse_apostrophe)
    - [`fd_toml_str_init`](#fd_toml_str_init)
    - [`fd_toml_parse_literal_char`](#fd_toml_parse_literal_char)


---
### fd\_toml\_parse\_quoted\_key<!-- {{#callable:fd_toml_parse_quoted_key}} -->
Parses a quoted key in TOML format, which can be either a basic string or a literal string.
- **Inputs**:
    - `parser`: A pointer to an `fd_toml_parser_t` structure that holds the current state of the parser.
- **Control Flow**:
    - The function first attempts to parse a basic string using [`fd_toml_parse_basic_string`](#fd_toml_parse_basic_string).
    - If the basic string parsing is successful, it returns 1.
    - If the basic string parsing fails, it attempts to parse a literal string using [`fd_toml_parse_literal_string`](#fd_toml_parse_literal_string).
    - If the literal string parsing is successful, it returns 1.
    - If both parsing attempts fail, it returns 0.
- **Output**: Returns 1 if a quoted key is successfully parsed (either as a basic or literal string), otherwise returns 0.
- **Functions called**:
    - [`fd_toml_parse_basic_string`](#fd_toml_parse_basic_string)
    - [`fd_toml_parse_literal_string`](#fd_toml_parse_literal_string)


---
### fd\_toml\_is\_unquoted\_key\_char<!-- {{#callable:fd_toml_is_unquoted_key_char}} -->
The `fd_toml_is_unquoted_key_char` function checks if a given character is valid as an unquoted key character in TOML syntax.
- **Inputs**:
    - `c`: An integer representing a character to be checked.
- **Control Flow**:
    - The function evaluates whether the character `c` falls within the ranges of uppercase letters (A-Z), lowercase letters (a-z), digits (0-9), or is one of the special characters '-' or '_'.
    - It uses bitwise OR operations to combine the results of these checks into a single integer value.
- **Output**: Returns a non-zero integer (true) if `c` is a valid unquoted key character, otherwise returns 0 (false).


---
### fd\_toml\_parse\_simple\_key<!-- {{#callable:fd_toml_parse_simple_key}} -->
Parses a simple key from TOML format, which can be either quoted or unquoted.
- **Inputs**:
    - `parser`: A pointer to an `fd_toml_parser_t` structure that holds the current state of the TOML parser, including the cursor position and the current key being parsed.
- **Control Flow**:
    - The function first attempts to parse a quoted key using [`fd_toml_parse_quoted_key`](#fd_toml_parse_quoted_key). If successful, it proceeds to the 'add' section.
    - If the quoted key parsing fails, it attempts to parse an unquoted key using [`fd_toml_parse_unquoted_key`](#fd_toml_parse_unquoted_key). If successful, it also proceeds to the 'add' section.
    - If both parsing attempts fail, the function returns 0, indicating no key was parsed.
    - In the 'add' section, it calculates the total length of the key by combining the length of the previously stored key and the newly parsed suffix.
    - If the total key length exceeds the maximum allowed size, a warning is logged, and an error is set before returning 0.
    - If the key length is valid, the new key is constructed by appending the parsed suffix to the existing key, and the function returns 1 to indicate success.
- **Output**: Returns 1 if a simple key was successfully parsed and added to the parser's state; returns 0 if parsing fails or if the key is too long.
- **Functions called**:
    - [`fd_toml_parse_quoted_key`](#fd_toml_parse_quoted_key)
    - [`fd_toml_parse_unquoted_key`](#fd_toml_parse_unquoted_key)


---
### fd\_toml\_parse\_dot\_sep<!-- {{#callable:fd_toml_parse_dot_sep}} -->
Parses a dot separator in TOML syntax, ensuring whitespace around it.
- **Inputs**:
    - `parser`: A pointer to the `fd_toml_parser_t` structure that maintains the state of the TOML parser.
- **Control Flow**:
    - Calls [`fd_toml_parse_ws`](#fd_toml_parse_ws) to skip any whitespace before the dot.
    - Uses the `EXPECT_CHAR` macro to check for the presence of a '.' character.
    - Calls [`fd_toml_parse_ws`](#fd_toml_parse_ws) again to skip any whitespace after the dot.
    - Returns 1 to indicate successful parsing.
- **Output**: Returns 1 on successful parsing of the dot separator; otherwise, it returns 0 if parsing fails.
- **Functions called**:
    - [`fd_toml_parse_ws`](#fd_toml_parse_ws)


---
### fd\_toml\_parse\_dotted\_key<!-- {{#callable:fd_toml_parse_dotted_key}} -->
Parses a dotted key in TOML format, which consists of a simple key followed by zero or more dot-separated simple keys.
- **Inputs**:
    - `parser`: A pointer to an `fd_toml_parser_t` structure that holds the current state of the parser, including the input data and the current position in the data.
- **Control Flow**:
    - The function first attempts to parse a simple key using [`fd_toml_parse_simple_key`](#fd_toml_parse_simple_key). If this fails, it returns 0.
    - It enters a loop that continues as long as there are more characters available to parse.
    - Within the loop, it attempts to parse a dot separator using [`fd_toml_parse_dot_sep`](#fd_toml_parse_dot_sep). If this fails, the loop breaks.
    - If the dot separator is successfully parsed, it checks if there is enough space in the `key` buffer to add a trailing dot. If not, it sets an error and returns 0.
    - The function then adds a dot to the `key` and attempts to parse another simple key. If this fails, it returns 0.
    - The loop continues until no more dot-separated simple keys can be parsed.
- **Output**: Returns 1 if the dotted key is successfully parsed, or 0 if an error occurs during parsing.
- **Functions called**:
    - [`fd_toml_parse_simple_key`](#fd_toml_parse_simple_key)
    - [`fd_toml_avail`](#fd_toml_avail)
    - [`fd_toml_parse_dot_sep`](#fd_toml_parse_dot_sep)


---
### fd\_toml\_parse\_keyval\_sep<!-- {{#callable:fd_toml_parse_keyval_sep}} -->
Parses the key-value separator in TOML syntax, which is expected to be an equals sign surrounded by optional whitespace.
- **Inputs**:
    - `parser`: A pointer to an `fd_toml_parser_t` structure that maintains the state of the TOML parser.
- **Control Flow**:
    - Calls [`fd_toml_parse_ws`](#fd_toml_parse_ws) to skip any leading whitespace.
    - Checks if there are available characters to parse; if not, returns 0.
    - Checks if the current character is an equals sign ('='); if not, returns 0.
    - Advances the parser cursor past the equals sign.
    - Calls [`fd_toml_parse_ws`](#fd_toml_parse_ws) again to skip any trailing whitespace.
    - Returns 1 to indicate successful parsing of the key-value separator.
- **Output**: Returns 1 if the key-value separator is successfully parsed, otherwise returns 0.
- **Functions called**:
    - [`fd_toml_parse_ws`](#fd_toml_parse_ws)
    - [`fd_toml_avail`](#fd_toml_avail)
    - [`fd_toml_advance_inline`](#fd_toml_advance_inline)


---
### fd\_toml\_parse\_ml\_basic\_string\_delim<!-- {{#callable:fd_toml_parse_ml_basic_string_delim}} -->
Parses a multi-line basic string delimiter consisting of three consecutive double quotes.
- **Inputs**:
    - `parser`: A pointer to an `fd_toml_parser_t` structure that maintains the state of the parser.
- **Control Flow**:
    - Checks if the remaining data in the parser is sufficient to read three characters.
    - Verifies that the first three characters are all double quotes ('"').
    - Advances the parser's cursor by three characters if the checks pass.
    - Returns 1 on success, or 0 if any check fails.
- **Output**: Returns 1 if the delimiter is successfully parsed, otherwise returns 0.
- **Functions called**:
    - [`fd_toml_advance_inline`](#fd_toml_advance_inline)


---
### fd\_toml\_parse\_mlb\_unescaped<!-- {{#callable:fd_toml_parse_mlb_unescaped}} -->
Parses unescaped characters in a TOML multiline basic string.
- **Inputs**:
    - `parser`: A pointer to the `fd_toml_parser_t` structure that maintains the state of the TOML parser.
- **Control Flow**:
    - The function calls [`fd_toml_parse_basic_unescaped`](#fd_toml_parse_basic_unescaped) with the provided `parser`.
    - The result of the call to [`fd_toml_parse_basic_unescaped`](#fd_toml_parse_basic_unescaped) is returned directly.
- **Output**: Returns an integer indicating success (1) or failure (0) of parsing unescaped characters.
- **Functions called**:
    - [`fd_toml_parse_basic_unescaped`](#fd_toml_parse_basic_unescaped)


---
### fd\_toml\_parse\_mlb\_escaped\_nl<!-- {{#callable:fd_toml_parse_mlb_escaped_nl}} -->
Parses a multiline TOML escaped newline sequence.
- **Inputs**:
    - `parser`: A pointer to the `fd_toml_parser_t` structure that maintains the state of the parser.
- **Control Flow**:
    - Checks if there are at least 2 characters available for parsing; if not, returns 0.
    - Verifies that the first character is a backslash ('\'); if not, returns 0.
    - Advances the parser cursor by 1 character.
    - Calls [`fd_toml_parse_ws`](#fd_toml_parse_ws) to parse any whitespace following the backslash.
    - Checks if there is at least one character available; if not, returns 0.
    - Checks if the next character is a newline ('\n'); if not, returns 0.
    - Enters a loop to consume any whitespace characters (spaces, tabs, newlines) until a non-whitespace character is encountered.
- **Output**: Returns 1 if the parsing of the escaped newline sequence is successful, otherwise returns 0.
- **Functions called**:
    - [`fd_toml_avail`](#fd_toml_avail)
    - [`fd_toml_advance_inline`](#fd_toml_advance_inline)
    - [`fd_toml_parse_ws`](#fd_toml_parse_ws)
    - [`fd_toml_advance`](#fd_toml_advance)


---
### fd\_toml\_parse\_mlb\_quotes<!-- {{#callable:fd_toml_parse_mlb_quotes}} -->
Parses multiline basic quotes in TOML format.
- **Inputs**:
    - `parser`: A pointer to a `fd_toml_parser_t` structure that maintains the state of the parser.
- **Control Flow**:
    - Initializes a pointer `begin` to the current position in the parser's data.
    - Counts the number of consecutive double quotes ("), advancing the parser's cursor for each quote found.
    - If no quotes are found or if more than five quotes are found, returns 0.
    - If fewer than three quotes are found, appends the quotes to the parser's scratch buffer and returns 1.
    - If exactly three quotes are found, returns 0 without appending.
    - If more than three quotes are found, backtracks the cursor by three positions, adjusts the quote count, appends the remaining quotes to the scratch buffer, and returns 1.
- **Output**: Returns 1 on successful parsing of quotes, 0 on failure.
- **Functions called**:
    - [`fd_toml_avail`](#fd_toml_avail)
    - [`fd_toml_advance_inline`](#fd_toml_advance_inline)
    - [`fd_toml_str_append`](#fd_toml_str_append)


---
### fd\_toml\_parse\_ml\_basic\_body<!-- {{#callable:fd_toml_parse_ml_basic_body}} -->
Parses the body of a multiline basic string in TOML format.
- **Inputs**:
    - `parser`: A pointer to an `fd_toml_parser_t` structure that maintains the state of the parser.
- **Control Flow**:
    - The function first enters a loop to parse any content in the multiline basic string until no more content can be parsed.
    - It then enters an infinite loop where it attempts to parse quotes followed by content, breaking if either fails.
    - After parsing, it attempts to parse any trailing quotes.
- **Output**: Returns 1 on successful parsing of the multiline basic body, or 0 if an error occurs.
- **Functions called**:
    - [`fd_toml_parse_mlb_content`](#fd_toml_parse_mlb_content)
    - [`fd_toml_parse_mlb_quotes`](#fd_toml_parse_mlb_quotes)


---
### fd\_toml\_parse\_ml\_basic\_string<!-- {{#callable:fd_toml_parse_ml_basic_string}} -->
Parses a multiline basic string in TOML format.
- **Inputs**:
    - `parser`: A pointer to the `fd_toml_parser_t` structure that maintains the state of the parser.
- **Control Flow**:
    - Checks for the presence of the multiline basic string delimiter using [`fd_toml_parse_ml_basic_string_delim`](#fd_toml_parse_ml_basic_string_delim).
    - If the delimiter is found, it checks if there are available characters to parse.
    - If the first character is a newline, it advances the parser cursor.
    - Initializes the string buffer using [`fd_toml_str_init`](#fd_toml_str_init).
    - Parses the body of the multiline basic string using [`fd_toml_parse_ml_basic_body`](#fd_toml_parse_ml_basic_body).
    - Finally, checks for the closing delimiter using [`fd_toml_parse_ml_basic_string_delim`](#fd_toml_parse_ml_basic_string_delim).
- **Output**: Returns 1 on successful parsing of the multiline basic string, or 0 if any parsing step fails.
- **Functions called**:
    - [`fd_toml_parse_ml_basic_string_delim`](#fd_toml_parse_ml_basic_string_delim)
    - [`fd_toml_avail`](#fd_toml_avail)
    - [`fd_toml_advance`](#fd_toml_advance)
    - [`fd_toml_str_init`](#fd_toml_str_init)
    - [`fd_toml_parse_ml_basic_body`](#fd_toml_parse_ml_basic_body)


---
### fd\_toml\_parse\_mll\_quotes<!-- {{#callable:fd_toml_parse_mll_quotes}} -->
Parses multiline literal quotes in a TOML document.
- **Inputs**:
    - `parser`: A pointer to the `fd_toml_parser_t` structure that holds the current state of the parser.
- **Control Flow**:
    - Initializes a pointer `begin` to the current position in the parser's data.
    - Counts the number of consecutive single quotes (`'`) encountered in the input.
    - If no quotes are found or if more than 5 quotes are found, returns 0.
    - If fewer than 3 quotes are found, appends them to the current string buffer and returns 1.
    - If exactly 3 quotes are found, returns 0 without appending.
    - If more than 3 quotes are found, backtracks the cursor by 3 positions, adjusts the quote count, and appends the remaining quotes to the string buffer before returning 1.
- **Output**: Returns 1 on success (quotes processed), 0 on failure (invalid quote count).
- **Functions called**:
    - [`fd_toml_avail`](#fd_toml_avail)
    - [`fd_toml_advance_inline`](#fd_toml_advance_inline)
    - [`fd_toml_str_append`](#fd_toml_str_append)


---
### fd\_toml\_parse\_mll\_content<!-- {{#callable:fd_toml_parse_mll_content}} -->
Parses a single character from the TOML input and appends it to the current string buffer if it is valid.
- **Inputs**:
    - `parser`: A pointer to the `fd_toml_parser_t` structure that holds the current state of the parser, including the input data and the current position.
- **Control Flow**:
    - Checks if there are any bytes available for parsing using [`fd_toml_avail`](#fd_toml_avail).
    - Retrieves the current character from the parser's data.
    - Validates the character against a set of acceptable ranges (whitespace, printable ASCII, and non-ASCII characters).
    - If the character is valid, it appends the character to the parser's scratch buffer using [`fd_toml_str_append_byte`](#fd_toml_str_append_byte).
    - Advances the parser's cursor by one character using [`fd_toml_advance`](#fd_toml_advance).
- **Output**: Returns 1 if a character was successfully parsed and appended, or 0 if there was an error or if the character was invalid.
- **Functions called**:
    - [`fd_toml_avail`](#fd_toml_avail)
    - [`fd_toml_str_append_byte`](#fd_toml_str_append_byte)
    - [`fd_toml_advance`](#fd_toml_advance)


---
### fd\_toml\_parse\_ml\_literal\_body<!-- {{#callable:fd_toml_parse_ml_literal_body}} -->
Parses the body of a multiline literal in TOML format.
- **Inputs**:
    - `parser`: A pointer to an `fd_toml_parser_t` structure that maintains the state of the parser.
- **Control Flow**:
    - The function first enters a loop to parse any initial content using [`fd_toml_parse_mll_content`](#fd_toml_parse_mll_content) until no more content can be parsed.
    - It then enters an infinite loop where it attempts to parse quotes using [`fd_toml_parse_mll_quotes`](#fd_toml_parse_mll_quotes) followed by content using [`fd_toml_parse_mll_content`](#fd_toml_parse_mll_content).
    - If quotes are successfully parsed, it continues to parse additional content until no more can be parsed.
    - Finally, it attempts to parse any trailing quotes before returning success.
- **Output**: Returns 1 on successful parsing of the multiline literal body, or 0 if an error occurs.
- **Functions called**:
    - [`fd_toml_parse_mll_content`](#fd_toml_parse_mll_content)
    - [`fd_toml_parse_mll_quotes`](#fd_toml_parse_mll_quotes)


---
### fd\_toml\_parse\_ml\_literal\_string\_delim<!-- {{#callable:fd_toml_parse_ml_literal_string_delim}} -->
Parses the delimiter for a multiline literal string in TOML format.
- **Inputs**:
    - `parser`: A pointer to the `fd_toml_parser_t` structure that holds the current state of the parser.
- **Control Flow**:
    - Checks if there are at least three characters available in the input data.
    - Verifies that the next three characters are all single quotes (''').
    - Advances the parser cursor by three characters if the checks pass.
    - Returns 1 to indicate success or 0 to indicate failure.
- **Output**: Returns 1 if the delimiter is successfully parsed; otherwise, returns 0.
- **Functions called**:
    - [`fd_toml_advance_inline`](#fd_toml_advance_inline)


---
### fd\_toml\_parse\_ml\_literal\_string<!-- {{#callable:fd_toml_parse_ml_literal_string}} -->
Parses a multiline literal string from a TOML document.
- **Inputs**:
    - `parser`: A pointer to an `fd_toml_parser_t` structure that maintains the state of the parser.
- **Control Flow**:
    - Checks for the opening delimiter of the multiline literal string using [`fd_toml_parse_ml_literal_string_delim`](#fd_toml_parse_ml_literal_string_delim).
    - If the delimiter is not found, returns 0 indicating failure.
    - Checks if there are available characters to parse using [`fd_toml_avail`](#fd_toml_avail).
    - If the first character is a newline, advances the parser cursor.
    - Initializes the string buffer for the parser using [`fd_toml_str_init`](#fd_toml_str_init).
    - Parses the body of the multiline literal string using [`fd_toml_parse_ml_literal_body`](#fd_toml_parse_ml_literal_body).
    - Checks for the closing delimiter of the multiline literal string using [`fd_toml_parse_ml_literal_string_delim`](#fd_toml_parse_ml_literal_string_delim).
    - Returns 1 indicating success if all checks pass.
- **Output**: Returns 1 on successful parsing of the multiline literal string, or 0 on failure.
- **Functions called**:
    - [`fd_toml_parse_ml_literal_string_delim`](#fd_toml_parse_ml_literal_string_delim)
    - [`fd_toml_avail`](#fd_toml_avail)
    - [`fd_toml_advance`](#fd_toml_advance)
    - [`fd_toml_str_init`](#fd_toml_str_init)
    - [`fd_toml_parse_ml_literal_body`](#fd_toml_parse_ml_literal_body)


---
### fd\_toml\_parse\_string<!-- {{#callable:fd_toml_parse_string}} -->
Parses a TOML string from the input and appends it to the parser's pod.
- **Inputs**:
    - `parser`: A pointer to an `fd_toml_parser_t` structure that holds the current state of the parser.
- **Control Flow**:
    - The function first attempts to parse a multiline basic string using [`fd_toml_parse_ml_basic_string`](#fd_toml_parse_ml_basic_string).
    - If that fails, it tries to parse a basic string with [`fd_toml_parse_basic_string`](#fd_toml_parse_basic_string).
    - Next, it attempts to parse a multiline literal string with [`fd_toml_parse_ml_literal_string`](#fd_toml_parse_ml_literal_string).
    - Finally, it tries to parse a literal string using [`fd_toml_parse_literal_string`](#fd_toml_parse_literal_string).
    - If any of these parsing attempts succeed, it proceeds to append a null byte to the parsed string.
    - Then, it inserts the parsed string into the pod using `fd_pod_insert`.
    - If any parsing attempt fails, the function returns 0, indicating failure.
- **Output**: Returns 1 on successful parsing and insertion of the string into the pod, or 0 on failure.
- **Functions called**:
    - [`fd_toml_parse_ml_basic_string`](#fd_toml_parse_ml_basic_string)
    - [`fd_toml_parse_basic_string`](#fd_toml_parse_basic_string)
    - [`fd_toml_parse_ml_literal_string`](#fd_toml_parse_ml_literal_string)
    - [`fd_toml_parse_literal_string`](#fd_toml_parse_literal_string)
    - [`fd_toml_str_append_byte`](#fd_toml_str_append_byte)


---
### fd\_toml\_parse\_boolean<!-- {{#callable:fd_toml_parse_boolean}} -->
Parses a boolean value from the TOML input.
- **Inputs**:
    - `parser`: A pointer to the `fd_toml_parser_t` structure that holds the current parsing state and data.
- **Control Flow**:
    - Checks if there are enough characters left in the input to read 'true' or 'false'.
    - If the first four characters match 'true', advances the cursor and sets the boolean value to 1.
    - If the first five characters match 'false', advances the cursor and sets the boolean value to 0.
    - If a valid boolean is found, attempts to insert the boolean value into the parser's pod.
    - If insertion fails, sets an error code and returns 0.
    - Returns 1 if a boolean value is successfully parsed and inserted.
- **Output**: Returns 1 if a boolean value ('true' or 'false') is successfully parsed and inserted into the pod; otherwise, returns 0.
- **Functions called**:
    - [`fd_toml_advance_inline`](#fd_toml_advance_inline)


---
### fd\_toml\_parse\_ws\_comment\_newline\_inner<!-- {{#callable:fd_toml_parse_ws_comment_newline_inner}} -->
Parses whitespace, comments, and newlines in a TOML document.
- **Inputs**:
    - `parser`: A pointer to the `fd_toml_parser_t` structure that maintains the state of the parser.
- **Control Flow**:
    - Checks if there are available characters to parse using [`fd_toml_avail`](#fd_toml_avail).
    - If the current character is a space or tab, it advances the cursor by one character and returns 1.
    - Calls [`fd_toml_parse_comment`](#fd_toml_parse_comment) to parse a comment if the current character is not whitespace.
    - Checks again for available characters after parsing the comment.
    - If the next character is a newline, it advances the cursor and returns 1.
    - If the conditions are not met, it returns 0.
- **Output**: Returns 1 on successful parsing of whitespace, comments, and newlines, or 0 if parsing fails.
- **Functions called**:
    - [`fd_toml_avail`](#fd_toml_avail)
    - [`fd_toml_advance_inline`](#fd_toml_advance_inline)
    - [`fd_toml_parse_comment`](#fd_toml_parse_comment)
    - [`fd_toml_advance`](#fd_toml_advance)


---
### fd\_toml\_parse\_ws\_comment\_newline<!-- {{#callable:fd_toml_parse_ws_comment_newline}} -->
Parses whitespace, comments, and newlines in a TOML file.
- **Inputs**:
    - `parser`: A pointer to an `fd_toml_parser_t` structure that maintains the state of the parser.
- **Control Flow**:
    - The function enters a loop that continues as long as [`fd_toml_parse_ws_comment_newline_inner`](#fd_toml_parse_ws_comment_newline_inner) returns a truthy value.
    - Within the loop, it calls [`fd_toml_parse_ws_comment_newline_inner`](#fd_toml_parse_ws_comment_newline_inner), which handles parsing whitespace, comments, and newlines.
    - If [`fd_toml_parse_ws_comment_newline_inner`](#fd_toml_parse_ws_comment_newline_inner) returns false, the loop terminates.
- **Output**: Returns 1 on success, indicating that whitespace, comments, and newlines were successfully parsed.
- **Functions called**:
    - [`fd_toml_parse_ws_comment_newline_inner`](#fd_toml_parse_ws_comment_newline_inner)


---
### fd\_toml\_parse\_inline\_table\_sep<!-- {{#callable:fd_toml_parse_inline_table_sep}} -->
Parses an inline table separator in TOML syntax.
- **Inputs**:
    - `parser`: A pointer to the `fd_toml_parser_t` structure that maintains the state of the parser.
- **Control Flow**:
    - Calls [`fd_toml_parse_ws`](#fd_toml_parse_ws) to skip any whitespace before the separator.
    - Checks if there are any characters available to parse; if not, returns 0.
    - Checks if the current character is a comma (','); if not, returns 0.
    - Advances the parser cursor by one character to skip the comma.
    - Calls [`fd_toml_parse_ws`](#fd_toml_parse_ws) again to skip any whitespace after the separator.
    - Returns 1 to indicate successful parsing of the inline table separator.
- **Output**: Returns 1 if the inline table separator is successfully parsed, otherwise returns 0.
- **Functions called**:
    - [`fd_toml_parse_ws`](#fd_toml_parse_ws)
    - [`fd_toml_avail`](#fd_toml_avail)
    - [`fd_toml_advance_inline`](#fd_toml_advance_inline)


---
### fd\_toml\_parse\_inline\_table\_keyvals<!-- {{#callable:fd_toml_parse_inline_table_keyvals}} -->
Parses key-value pairs in an inline TOML table.
- **Inputs**:
    - `parser`: A pointer to the `fd_toml_parser_t` structure that maintains the state of the parser.
- **Control Flow**:
    - Calls [`fd_toml_parse_keyval`](#fd_toml_parse_keyval) to parse the first key-value pair; if it fails, returns 0.
    - Stores the current cursor position in `backtrack` for potential backtracking.
    - Enters an infinite loop to parse additional key-value pairs.
    - Calls [`fd_toml_parse_inline_table_sep`](#fd_toml_parse_inline_table_sep) to check for a separator; if it fails, restores the cursor position from `backtrack` and breaks the loop.
    - Calls [`fd_toml_parse_keyval`](#fd_toml_parse_keyval) again to parse the next key-value pair; if it fails, returns 0.
    - Updates `backtrack` to the current cursor position for the next iteration.
- **Output**: Returns 1 on success, indicating that the inline table key-value pairs were successfully parsed.
- **Functions called**:
    - [`fd_toml_parse_keyval`](#fd_toml_parse_keyval)
    - [`fd_toml_parse_inline_table_sep`](#fd_toml_parse_inline_table_sep)


---
### fd\_toml\_parse\_inline\_table<!-- {{#callable:fd_toml_parse_inline_table}} -->
Parses an inline table in TOML format.
- **Inputs**:
    - `parser`: A pointer to the `fd_toml_parser_t` structure that holds the current state of the parser.
- **Control Flow**:
    - The function starts by expecting a '{' character to indicate the beginning of an inline table.
    - Whitespace is parsed after the opening brace.
    - The current key length is stored, and a check is performed to ensure that the key can accommodate additional characters.
    - An empty pod is inserted into the parser's data structure.
    - A dot is appended to the key to signify the start of key-value pairs in the inline table.
    - A loop is initiated to parse key-value pairs using the [`fd_toml_parse_inline_table_keyvals`](#fd_toml_parse_inline_table_keyvals) function until no more pairs can be parsed.
    - Whitespace is parsed before expecting a '}' character to close the inline table.
    - The key length is restored to its original value, and the function returns success.
- **Output**: Returns 1 on successful parsing of the inline table, or 0 if an error occurs.
- **Functions called**:
    - [`fd_toml_parse_ws`](#fd_toml_parse_ws)
    - [`fd_toml_upsert_empty_pod`](#fd_toml_upsert_empty_pod)
    - [`fd_toml_parse_inline_table_keyvals`](#fd_toml_parse_inline_table_keyvals)


---
### fd\_toml\_parse\_zero\_prefixable\_int<!-- {{#callable:fd_toml_parse_zero_prefixable_int}} -->
Parses a zero-prefixable integer from the TOML input, allowing underscores as digit separators.
- **Inputs**:
    - `parser`: A pointer to the `fd_toml_parser_t` structure that holds the current state of the TOML parser.
    - `dec`: A pointer to the `fd_toml_dec_t` structure where the parsed integer result and its length will be stored.
- **Control Flow**:
    - The function initializes a loop to read characters from the parser's current data.
    - It checks if the current character is an underscore and if underscores are allowed; if so, it advances the parser and checks the next character.
    - If the character is a digit, it updates the `digits` variable by multiplying the current value by 10 and adding the new digit, while checking for overflow.
    - The loop continues until a non-digit and non-underscore character is encountered, at which point it breaks out of the loop.
    - Finally, it assigns the parsed value to `dec->res` and the length to `dec->len`, returning 1 to indicate success.
- **Output**: Returns 1 on successful parsing of a zero-prefixable integer, or 0 if an error occurs, such as overflow or invalid input.
- **Functions called**:
    - [`fd_toml_advance_inline`](#fd_toml_advance_inline)
    - [`fd_toml_avail`](#fd_toml_avail)


---
### fd\_toml\_parse\_hex\_int<!-- {{#callable:fd_toml_parse_hex_int}} -->
Parses a hexadecimal integer from a TOML string.
- **Inputs**:
    - `parser`: A pointer to a `fd_toml_parser_t` structure that holds the current state of the parser.
- **Control Flow**:
    - Checks if there are at least 3 characters available in the input for a valid hex integer.
    - Validates that the first two characters are '0' and 'x', indicating the start of a hex integer.
    - Ensures that the third character is a valid hexadecimal digit.
    - Advances the parser cursor past the '0x' prefix.
    - Enters a loop to read hexadecimal digits, allowing underscores as separators.
    - Shifts the accumulated result left by 4 bits and adds the value of the current hex digit.
    - Checks for overflow conditions during the accumulation of the result.
    - Inserts the parsed long value into the provided POD structure.
    - Returns 1 on successful parsing or 0 on failure.
- **Output**: Returns 1 if a valid hexadecimal integer was parsed and inserted into the POD, or 0 if parsing failed.
- **Functions called**:
    - [`fd_toml_avail`](#fd_toml_avail)
    - [`fd_toml_advance_inline`](#fd_toml_advance_inline)
    - [`fd_toml_xdigit`](#fd_toml_xdigit)


---
### fd\_toml\_is\_odigit<!-- {{#callable:fd_toml_is_odigit}} -->
The `fd_toml_is_odigit` function checks if a given character represents an octal digit (0-7).
- **Inputs**:
    - `c`: An integer representing a character to be checked.
- **Control Flow**:
    - The function evaluates whether the input character `c` is greater than or equal to '0' and less than '8'.
    - It returns 1 (true) if the condition is satisfied, indicating that `c` is an octal digit; otherwise, it returns 0 (false).
- **Output**: Returns 1 if `c` is an octal digit (0-7), otherwise returns 0.


---
### fd\_toml\_is\_bdigit<!-- {{#callable:fd_toml_is_bdigit}} -->
The `fd_toml_is_bdigit` function checks if a given character is a binary digit (either '0' or '1').
- **Inputs**:
    - `c`: An integer representing a character to be checked.
- **Control Flow**:
    - The function evaluates if the input character `c` is equal to '0' or '1'.
    - It returns 1 (true) if `c` is a binary digit, otherwise it returns 0 (false).
- **Output**: The function returns an integer: 1 if the character is a binary digit ('0' or '1'), and 0 otherwise.


---
### fd\_toml\_parse\_bin\_int<!-- {{#callable:fd_toml_parse_bin_int}} -->
Parses a binary integer from a TOML string.
- **Inputs**:
    - `parser`: A pointer to a `fd_toml_parser_t` structure that holds the current state of the parser.
- **Control Flow**:
    - Checks if there are at least 3 characters available for parsing.
    - Validates that the first character is '0' and the second is 'b'.
    - Ensures that the third character is a valid binary digit (either '0' or '1').
    - Advances the parser cursor past the '0b' prefix.
    - Enters a loop to parse binary digits, allowing underscores as separators.
    - Detects overflow conditions during the parsing of binary digits.
    - Inserts the parsed binary integer into the provided pod structure.
    - Returns 1 on successful parsing or 0 on failure.
- **Output**: Returns 1 if the binary integer is successfully parsed and inserted into the pod; otherwise, returns 0.
- **Functions called**:
    - [`fd_toml_avail`](#fd_toml_avail)
    - [`fd_toml_is_bdigit`](#fd_toml_is_bdigit)
    - [`fd_toml_advance_inline`](#fd_toml_advance_inline)


---
### fd\_toml\_parse\_exp<!-- {{#callable:fd_toml_parse_exp}} -->
Parses an exponential notation in TOML format.
- **Inputs**:
    - `parser`: A pointer to the `fd_toml_parser_t` structure that holds the current state of the parser.
    - `exp`: A pointer to the `fd_toml_dec_t` structure where the parsed exponential value will be stored.
- **Control Flow**:
    - Checks if there are at least 2 characters available for parsing; if not, returns 0.
    - Validates that the first character is 'e' or 'E'; if not, returns 0.
    - Advances the parser cursor by one character.
    - Checks for an optional sign ('-' or '+') for the exponent and sets the `neg` field in `exp` accordingly.
    - Advances the cursor again and checks if there is at least one digit available for the exponent; if not, returns 0.
    - Validates that the first digit of the exponent is between '0' and '9'; if not, returns 0.
    - Calls [`fd_toml_parse_zero_prefixable_int`](#fd_toml_parse_zero_prefixable_int) to parse the rest of the exponent and store it in `exp`.
- **Output**: Returns 1 on successful parsing of the exponential notation, or 0 if parsing fails.
- **Functions called**:
    - [`fd_toml_avail`](#fd_toml_avail)
    - [`fd_toml_advance_inline`](#fd_toml_advance_inline)
    - [`fd_toml_parse_zero_prefixable_int`](#fd_toml_parse_zero_prefixable_int)


---
### fd\_toml\_parse\_frac<!-- {{#callable:fd_toml_parse_frac}} -->
Parses a fractional part of a TOML number.
- **Inputs**:
    - `parser`: A pointer to the `fd_toml_parser_t` structure that holds the current state of the parser.
    - `frac`: A pointer to the `fd_toml_dec_t` structure where the parsed fractional value will be stored.
- **Control Flow**:
    - Checks if there are at least two characters available for parsing; if not, returns 0.
    - Validates that the first character is a decimal point ('.'); if not, returns 0.
    - Advances the parser cursor by one character to skip the decimal point.
    - Checks if the next character is a digit (0-9); if not, returns 0.
    - Calls [`fd_toml_parse_zero_prefixable_int`](#fd_toml_parse_zero_prefixable_int) to parse the digits following the decimal point; if it fails, returns 0.
    - If all checks pass, returns 1 indicating successful parsing.
- **Output**: Returns 1 on successful parsing of the fractional part, or 0 if parsing fails.
- **Functions called**:
    - [`fd_toml_avail`](#fd_toml_avail)
    - [`fd_toml_advance_inline`](#fd_toml_advance_inline)
    - [`fd_toml_parse_zero_prefixable_int`](#fd_toml_parse_zero_prefixable_int)


---
### fd\_toml\_parse\_float\_normal<!-- {{#callable:fd_toml_parse_float_normal}} -->
Parses a normal floating-point number from a TOML string and inserts it into a provided data structure.
- **Inputs**:
    - `parser`: A pointer to a `fd_toml_parser_t` structure that holds the current state of the TOML parser, including the input data and the output data structure.
- **Control Flow**:
    - Initializes a `fd_toml_dec_t` structure to hold the integer part of the float.
    - Calls [`fd_toml_parse_dec_int_`](#fd_toml_parse_dec_int_) to parse the integer part; if it fails, returns 0.
    - Checks if there are more characters available to parse; if not, returns 0.
    - Converts the parsed integer to a float and initializes a flag `ok` to track if a fractional part was parsed.
    - Attempts to parse a fractional part using [`fd_toml_parse_frac`](#fd_toml_parse_frac); if successful, adjusts the float value accordingly.
    - Attempts to parse an exponent part using [`fd_toml_parse_exp`](#fd_toml_parse_exp); if successful, adjusts the float value based on the exponent.
    - Inserts the final float value into the output data structure using `fd_pod_insert_float`; if this fails, sets an error and returns 0.
    - Returns 1 to indicate successful parsing and insertion.
- **Output**: Returns 1 on successful parsing and insertion of the float, or 0 if an error occurs during parsing or insertion.
- **Functions called**:
    - [`fd_toml_parse_dec_int_`](#fd_toml_parse_dec_int_)
    - [`fd_toml_avail`](#fd_toml_avail)
    - [`fd_toml_parse_frac`](#fd_toml_parse_frac)
    - [`fd_toml_parse_exp`](#fd_toml_parse_exp)


---
### fd\_toml\_parse\_float<!-- {{#callable:fd_toml_parse_float}} -->
Parses a floating-point number from a TOML file using a parser.
- **Inputs**:
    - `parser`: A pointer to an `fd_toml_parser_t` structure that maintains the state of the TOML parser.
- **Control Flow**:
    - First, it attempts to parse a normal float using the [`fd_toml_parse_float_normal`](#fd_toml_parse_float_normal) function.
    - If the normal float parsing fails, it then attempts to parse special float values (like 'inf' or 'nan') using [`fd_float_parse_float_special`](#fd_float_parse_float_special).
    - If both parsing attempts fail, the function returns 0, indicating failure; otherwise, it returns 1 for success.
- **Output**: Returns 1 if a float is successfully parsed, otherwise returns 0.
- **Functions called**:
    - [`fd_toml_parse_float_normal`](#fd_toml_parse_float_normal)
    - [`fd_float_parse_float_special`](#fd_float_parse_float_special)


---
### fd\_toml\_parse\_full\_date<!-- {{#callable:fd_toml_parse_full_date}} -->
Parses a full date in the format YYYY-MM-DD from a TOML string.
- **Inputs**:
    - `parser`: A pointer to the `fd_toml_parser_t` structure that contains the current parsing state and data.
    - `time`: A pointer to a `struct tm` where the parsed date will be stored.
- **Control Flow**:
    - Checks if there are at least 10 characters available for parsing; if not, returns 0.
    - Validates that the first four characters are digits, followed by a hyphen, then two more digits, another hyphen, and finally two more digits.
    - Copies the first 10 characters into a temporary string and advances the parser cursor by 10 characters.
    - Attempts to parse the date string using `strptime`; if it fails, logs a warning and returns 0.
    - If successful, returns 1.
- **Output**: Returns 1 on successful parsing of the date, or 0 if parsing fails.
- **Functions called**:
    - [`fd_toml_avail`](#fd_toml_avail)
    - [`fd_toml_advance_inline`](#fd_toml_advance_inline)


---
### fd\_toml\_parse\_time\_delim<!-- {{#callable:fd_toml_parse_time_delim}} -->
Parses a time delimiter character from the TOML input.
- **Inputs**:
    - `parser`: A pointer to the `fd_toml_parser_t` structure that holds the current state of the TOML parser.
- **Control Flow**:
    - Checks if there are available characters to parse using [`fd_toml_avail`](#fd_toml_avail).
    - If no characters are available, returns 0 indicating failure.
    - Checks the first character of the input data in the parser's cursor.
    - If the character is 'T', 't', or a space, it proceeds; otherwise, it returns 0.
    - Advances the parser's cursor by one character using [`fd_toml_advance_inline`](#fd_toml_advance_inline).
    - Returns 1 indicating success.
- **Output**: Returns 1 if a valid time delimiter is found ('T', 't', or space), otherwise returns 0.
- **Functions called**:
    - [`fd_toml_avail`](#fd_toml_avail)
    - [`fd_toml_advance_inline`](#fd_toml_advance_inline)


---
### fd\_toml\_parse\_time\_secfrac<!-- {{#callable:fd_toml_parse_time_secfrac}} -->
Parses the fractional part of a time value in TOML format and stores it in nanoseconds.
- **Inputs**:
    - `parser`: A pointer to the `fd_toml_parser_t` structure that maintains the state of the TOML parser.
    - `pnanos`: A pointer to an unsigned long variable where the parsed fractional seconds in nanoseconds will be stored.
- **Control Flow**:
    - Checks if at least two characters are available for parsing; if not, returns 0.
    - Validates that the first character is a dot ('.'); if not, returns 0.
    - Checks if the next character is a digit; if not, returns 0.
    - Advances the parser cursor by one character.
    - Initializes `secfrac` to 0 and `len` to 0 for accumulating the parsed digits.
    - Enters a loop to read digits while they are available and valid, updating `secfrac` and incrementing `len`.
    - If `len` exceeds 9, logs a warning and returns 0.
    - Pads `secfrac` with zeros to ensure it represents nanoseconds (9 digits).
    - Stores the final value in `*pnanos` and returns 1.
- **Output**: Returns 1 on successful parsing of the fractional part, or 0 if parsing fails.
- **Functions called**:
    - [`fd_toml_avail`](#fd_toml_avail)
    - [`fd_toml_advance_inline`](#fd_toml_advance_inline)


---
### fd\_toml\_parse\_partial\_time<!-- {{#callable:fd_toml_parse_partial_time}} -->
Parses a partial time string in the format HH:MM:SS and optionally a fractional second, returning the total time in nanoseconds.
- **Inputs**:
    - `parser`: A pointer to the `fd_toml_parser_t` structure that holds the current parsing state.
    - `pnanos`: A pointer to an unsigned long variable where the parsed time in nanoseconds will be stored.
- **Control Flow**:
    - Checks if there are at least 8 characters available for parsing; if not, returns 0.
    - Validates the format of the time string, ensuring it matches HH:MM:SS; if not, returns 0.
    - Copies the time string into a temporary character array and advances the parser cursor.
    - Attempts to parse the time string into a `struct tm` using `strptime`; if it fails, logs a warning and returns 0.
    - Calculates the total time in seconds and converts it to nanoseconds.
    - Checks for an optional fractional second component and adds it to the total if present.
    - Stores the final result in the variable pointed to by `pnanos` and returns 1.
- **Output**: Returns 1 on successful parsing of the time, or 0 if parsing fails.
- **Functions called**:
    - [`fd_toml_avail`](#fd_toml_avail)
    - [`fd_toml_advance_inline`](#fd_toml_advance_inline)
    - [`fd_toml_parse_time_secfrac`](#fd_toml_parse_time_secfrac)


---
### fd\_toml\_parse\_time\_numoffset<!-- {{#callable:fd_toml_parse_time_numoffset}} -->
Parses a time zone offset in the format of either '+HH:MM' or '-HH:MM' and returns the corresponding offset in seconds.
- **Inputs**:
    - `parser`: A pointer to a `fd_toml_parser_t` structure that holds the current state of the TOML parser, including the current position in the input data.
    - `psec`: A pointer to a long integer where the parsed time offset in seconds will be stored.
- **Control Flow**:
    - Checks if there are available characters to parse; if not, returns 0.
    - Determines if the offset is positive or negative based on the first character ('+' or '-') and advances the parser cursor.
    - Validates that there are enough characters remaining for a valid time offset format.
    - Checks that the next characters conform to the expected format of two digits, a colon, and two more digits.
    - Copies the relevant characters into a temporary string and advances the parser cursor.
    - Attempts to parse the time string into a `struct tm` using `strptime`; if it fails, logs a warning and returns 0.
    - Calculates the absolute offset in seconds and assigns it to the location pointed to by `psec`, applying the sign determined earlier.
- **Output**: Returns 1 on successful parsing of the time offset, or 0 if parsing fails.
- **Functions called**:
    - [`fd_toml_avail`](#fd_toml_avail)
    - [`fd_toml_advance_inline`](#fd_toml_advance_inline)


---
### fd\_toml\_parse\_full\_time<!-- {{#callable:fd_toml_parse_full_time}} -->
Parses a full time representation from a TOML parser and updates the provided nanoseconds value.
- **Inputs**:
    - `parser`: A pointer to a `fd_toml_parser_t` structure that holds the state of the TOML parser.
    - `pnanos`: A pointer to an unsigned long variable where the parsed time in nanoseconds will be stored.
- **Control Flow**:
    - The function first attempts to parse a partial time using [`fd_toml_parse_partial_time`](#fd_toml_parse_partial_time), storing the result in `pnanos`. If this fails, it returns 0.
    - Next, it attempts to parse a time offset using [`fd_toml_parse_time_offset`](#fd_toml_parse_time_offset), storing the result in `off_sec`. If this fails, it returns 0.
    - If both parsing steps succeed, it adds the offset (in seconds) to the previously parsed nanoseconds value.
- **Output**: Returns 1 on successful parsing of the full time, or 0 if any parsing step fails.
- **Functions called**:
    - [`fd_toml_parse_partial_time`](#fd_toml_parse_partial_time)
    - [`fd_toml_parse_time_offset`](#fd_toml_parse_time_offset)


---
### fd\_toml\_parse\_offset\_date\_time<!-- {{#callable:fd_toml_parse_offset_date_time}} -->
Parses an offset date-time from a TOML string and converts it to nanoseconds since the epoch.
- **Inputs**:
    - `parser`: A pointer to a `fd_toml_parser_t` structure that holds the state of the TOML parser.
    - `pnanos`: A pointer to an `ulong` where the resulting nanoseconds since the epoch will be stored.
- **Control Flow**:
    - Initializes a `struct tm` variable to hold the parsed date.
    - Calls [`fd_toml_parse_full_date`](#fd_toml_parse_full_date) to parse the date part; if it fails, returns 0.
    - Calls [`fd_toml_parse_time_delim`](#fd_toml_parse_time_delim) to parse the time delimiter; if it fails, returns 0.
    - Calls [`fd_toml_parse_full_time`](#fd_toml_parse_full_time) to parse the time part; if it fails, returns 0.
    - Calculates the total nanoseconds by converting the parsed date to UTC seconds using `timegm` and adds the nanoseconds from the time part.
    - Returns 1 to indicate successful parsing.
- **Output**: Returns 1 on success, indicating that the offset date-time was successfully parsed and stored in `pnanos`; returns 0 on failure.
- **Functions called**:
    - [`fd_toml_parse_full_date`](#fd_toml_parse_full_date)
    - [`fd_toml_parse_time_delim`](#fd_toml_parse_time_delim)
    - [`fd_toml_parse_full_time`](#fd_toml_parse_full_time)


---
### fd\_toml\_parse\_local\_date\_time<!-- {{#callable:fd_toml_parse_local_date_time}} -->
Parses a local date and time from a TOML format string and returns the corresponding nanoseconds since the epoch.
- **Inputs**:
    - `parser`: A pointer to a `fd_toml_parser_t` structure that maintains the state of the TOML parser.
    - `pnanos`: A pointer to an `ulong` variable where the parsed local date and time in nanoseconds will be stored.
- **Control Flow**:
    - Initializes a `struct tm` variable to hold the parsed date.
    - Calls [`fd_toml_parse_full_date`](#fd_toml_parse_full_date) to parse the full date; if it fails, returns 0.
    - Calls [`fd_toml_parse_time_delim`](#fd_toml_parse_time_delim) to parse the time delimiter; if it fails, returns 0.
    - Calls [`fd_toml_parse_partial_time`](#fd_toml_parse_partial_time) to parse the partial time; if it fails, returns 0.
    - Calculates the total nanoseconds by converting the `struct tm` date to time using `mktime` and multiplying by 1e9.
    - Stores the result in the variable pointed to by `pnanos` and returns 1 to indicate success.
- **Output**: Returns 1 on successful parsing of the local date and time, or 0 if any parsing step fails.
- **Functions called**:
    - [`fd_toml_parse_full_date`](#fd_toml_parse_full_date)
    - [`fd_toml_parse_time_delim`](#fd_toml_parse_time_delim)
    - [`fd_toml_parse_partial_time`](#fd_toml_parse_partial_time)


---
### fd\_toml\_parse\_local\_date<!-- {{#callable:fd_toml_parse_local_date}} -->
Parses a local date from a TOML format and converts it to nanoseconds since the epoch.
- **Inputs**:
    - `parser`: A pointer to a `fd_toml_parser_t` structure that holds the state of the TOML parser.
    - `pnanos`: A pointer to an `ulong` where the resulting nanoseconds since the epoch will be stored.
- **Control Flow**:
    - Initializes a `struct tm` variable to hold the parsed date.
    - Calls [`fd_toml_parse_full_date`](#fd_toml_parse_full_date) to parse the full date from the TOML input.
    - If the date parsing fails, returns 0.
    - Converts the parsed date to seconds since the epoch using `mktime`.
    - Multiplies the result by 1e9 to convert seconds to nanoseconds.
    - Stores the result in the location pointed to by `pnanos` and returns 1.
- **Output**: Returns 1 on successful parsing and conversion, or 0 if an error occurs.
- **Functions called**:
    - [`fd_toml_parse_full_date`](#fd_toml_parse_full_date)


---
### fd\_toml\_parse\_local\_time<!-- {{#callable:fd_toml_parse_local_time}} -->
Parses a local time from a TOML string.
- **Inputs**:
    - `parser`: A pointer to the `fd_toml_parser_t` structure that holds the state of the TOML parser.
    - `pnanos`: A pointer to an unsigned long variable where the parsed local time in nanoseconds will be stored.
- **Control Flow**:
    - Calls the [`fd_toml_parse_partial_time`](#fd_toml_parse_partial_time) function to parse the local time.
    - The function returns the result of the parsing operation directly.
- **Output**: Returns an integer indicating success (1) or failure (0) of the parsing operation.
- **Functions called**:
    - [`fd_toml_parse_partial_time`](#fd_toml_parse_partial_time)


---
### fd\_toml\_parse\_date\_time<!-- {{#callable:fd_toml_parse_date_time}} -->
Parses various date-time formats from a TOML file and inserts the resulting timestamp in nanoseconds into a provided data structure.
- **Inputs**:
    - `parser`: A pointer to a `fd_toml_parser_t` structure that holds the current state of the parser, including the input data and the output storage.
- **Control Flow**:
    - The function attempts to parse a date-time value by calling several parsing functions in sequence: [`fd_toml_parse_offset_date_time`](#fd_toml_parse_offset_date_time), [`fd_toml_parse_local_date_time`](#fd_toml_parse_local_date_time), [`fd_toml_parse_local_date`](#fd_toml_parse_local_date), and [`fd_toml_parse_local_time`](#fd_toml_parse_local_time).
    - If any of these parsing functions succeed, the resulting timestamp in nanoseconds is stored in the `unix_nanos` variable.
    - If all parsing attempts fail, the function returns 0, indicating no valid date-time was found.
    - If a valid date-time is parsed, it attempts to insert the timestamp into the `pod` structure using `fd_pod_insert_ulong`.
    - If the insertion fails, it sets an error code in the parser and returns 0; otherwise, it returns 1 to indicate success.
- **Output**: Returns 1 if a valid date-time was parsed and inserted successfully, or 0 if parsing failed or if there was an error during insertion.
- **Functions called**:
    - [`fd_toml_parse_offset_date_time`](#fd_toml_parse_offset_date_time)
    - [`fd_toml_parse_local_date_time`](#fd_toml_parse_local_date_time)
    - [`fd_toml_parse_local_date`](#fd_toml_parse_local_date)
    - [`fd_toml_parse_local_time`](#fd_toml_parse_local_time)


---
### fd\_toml\_parse\_val<!-- {{#callable:fd_toml_parse_val}} -->
Parses a TOML value from the input data using a recursive descent parser.
- **Inputs**:
    - `parser`: A pointer to an `fd_toml_parser_t` structure that holds the current state of the parser, including the cursor position and the data to be parsed.
- **Control Flow**:
    - The function attempts to parse various types of TOML values in a specific order: string, boolean, array, inline table, date-time, float, and integer.
    - For each type, it calls the corresponding parsing function and checks the return value.
    - If a parsing function returns success (1), the function immediately returns 1, indicating a successful parse.
    - If all parsing attempts fail, the function returns 0, indicating that no valid TOML value was found.
- **Output**: Returns 1 if a valid TOML value is successfully parsed, otherwise returns 0.
- **Functions called**:
    - [`fd_toml_parse_string`](#fd_toml_parse_string)
    - [`fd_toml_parse_boolean`](#fd_toml_parse_boolean)
    - [`fd_toml_parse_array`](#fd_toml_parse_array)
    - [`fd_toml_parse_inline_table`](#fd_toml_parse_inline_table)
    - [`fd_toml_parse_date_time`](#fd_toml_parse_date_time)
    - [`fd_toml_parse_float`](#fd_toml_parse_float)
    - [`fd_toml_parse_integer`](#fd_toml_parse_integer)


---
### fd\_toml\_parse\_keyval<!-- {{#callable:fd_toml_parse_keyval}} -->
Parses a key-value pair from a TOML configuration file.
- **Inputs**:
    - `parser`: A pointer to an `fd_toml_parser_t` structure that maintains the state of the parser.
- **Control Flow**:
    - The function first saves the current length of the key in `old_key_len`.
    - It attempts to parse the key using [`fd_toml_parse_key`](#fd_toml_parse_key), returning 0 on failure.
    - It checks for duplicate keys in the provided pod using `fd_pod_query`, logging a warning and setting an error if a duplicate is found.
    - It then parses the key-value separator using [`fd_toml_parse_keyval_sep`](#fd_toml_parse_keyval_sep), returning 0 on failure.
    - Finally, it parses the value using [`fd_toml_parse_val`](#fd_toml_parse_val), returning 0 on failure.
    - If all parsing steps succeed, it logs the added key and resets the key length to its original value before returning 1.
- **Output**: Returns 1 on successful parsing of a key-value pair, or 0 if any parsing step fails.
- **Functions called**:
    - [`fd_toml_parse_key`](#fd_toml_parse_key)
    - [`fd_toml_parse_keyval_sep`](#fd_toml_parse_keyval_sep)
    - [`fd_toml_parse_val`](#fd_toml_parse_val)


---
### fd\_toml\_parse\_array\_table<!-- {{#callable:fd_toml_parse_array_table}} -->
Parses a TOML array table and updates the parser's key.
- **Inputs**:
    - `parser`: A pointer to the `fd_toml_parser_t` structure that holds the current state of the parser.
- **Control Flow**:
    - Checks if there are at least two characters available for parsing.
    - Validates that the first two characters are the opening brackets for an array table ('[[').
    - Advances the parser cursor past the opening brackets.
    - Parses whitespace after the opening brackets.
    - Initializes the parser's key to an empty string.
    - Calls [`fd_toml_parse_key`](#fd_toml_parse_key) to parse the key for the array table.
    - Queries the number of existing entries in the subpod associated with the parsed key.
    - Appends the array index to the key path.
    - Checks for potential out-of-bounds access when appending the index.
    - Logs the addition of the array table with the constructed key.
    - Parses whitespace after the key.
    - Validates that the next two characters are the closing brackets for the array table (']]').
    - Advances the parser cursor past the closing brackets.
- **Output**: Returns 1 on successful parsing of the array table, or 0 if any validation fails.
- **Functions called**:
    - [`fd_toml_avail`](#fd_toml_avail)
    - [`fd_toml_advance_inline`](#fd_toml_advance_inline)
    - [`fd_toml_parse_ws`](#fd_toml_parse_ws)
    - [`fd_toml_parse_key`](#fd_toml_parse_key)


---
### fd\_toml\_parse\_table<!-- {{#callable:fd_toml_parse_table}} -->
Parses a TOML table structure and updates the parser state.
- **Inputs**:
    - `parser`: A pointer to an `fd_toml_parser_t` structure that holds the current state of the TOML parser.
- **Control Flow**:
    - Attempts to parse an array table using [`fd_toml_parse_array_table`](#fd_toml_parse_array_table) and checks for success.
    - If the array table parsing fails, it attempts to parse a standard table using [`fd_toml_parse_std_table`](#fd_toml_parse_std_table).
    - If both parsing attempts fail, the function returns 0 indicating failure.
    - If either parsing succeeds, it calls [`fd_toml_upsert_empty_pod`](#fd_toml_upsert_empty_pod) to ensure the parser's pod is updated.
    - It checks if the key length exceeds the maximum allowed size, setting an error if it does.
    - If the key length is valid, it appends a trailing dot to the key and returns 1 indicating success.
- **Output**: Returns 1 on successful parsing of a table, or 0 if parsing fails.
- **Functions called**:
    - [`fd_toml_parse_array_table`](#fd_toml_parse_array_table)
    - [`fd_toml_parse_std_table`](#fd_toml_parse_std_table)
    - [`fd_toml_upsert_empty_pod`](#fd_toml_upsert_empty_pod)


---
### fd\_toml\_parse\_expression<!-- {{#callable:fd_toml_parse_expression}} -->
Parses a TOML expression, which can be a key-value pair, a table, or a comment.
- **Inputs**:
    - `parser`: A pointer to an `fd_toml_parser_t` structure that holds the current state of the parser, including the cursor position and the data to be parsed.
- **Control Flow**:
    - The function begins by calling [`fd_toml_parse_ws`](#fd_toml_parse_ws) to skip any whitespace.
    - It attempts to parse a key-value pair using [`fd_toml_parse_keyval`](#fd_toml_parse_keyval), and if successful, it calls [`fd_toml_parse_ws`](#fd_toml_parse_ws) again to skip any whitespace following the key-value pair.
    - If parsing a key-value pair fails, it attempts to parse a table using [`fd_toml_parse_table`](#fd_toml_parse_table) and again skips whitespace if successful.
    - Regardless of whether a key-value pair or table was parsed, it attempts to parse a comment using [`fd_toml_parse_comment`](#fd_toml_parse_comment) at the end.
    - The function returns 1 to indicate successful parsing of an expression.
- **Output**: Returns 1 if an expression is successfully parsed; otherwise, it returns 0.
- **Functions called**:
    - [`fd_toml_parse_ws`](#fd_toml_parse_ws)
    - [`fd_toml_parse_keyval`](#fd_toml_parse_keyval)
    - [`fd_toml_parse_table`](#fd_toml_parse_table)
    - [`fd_toml_parse_comment`](#fd_toml_parse_comment)


---
### fd\_toml\_parse\_toml<!-- {{#callable:fd_toml_parse_toml}} -->
Parses a TOML document using a given parser.
- **Inputs**:
    - `parser`: A pointer to an `fd_toml_parser_t` structure that holds the state of the parser, including the current position in the input data and any errors encountered.
- **Control Flow**:
    - The function first attempts to parse an expression using [`fd_toml_parse_expression`](#fd_toml_parse_expression). If this fails, it returns 0.
    - It enters an infinite loop where it checks for errors, availability of data, and whether the current character is a newline.
    - If a newline is found, it advances the parser cursor and attempts to parse another expression.
    - The loop continues until an error occurs, there is no more data to parse, or a non-newline character is encountered.
- **Output**: Returns 1 if the parsing is successful, otherwise returns 0 if an error occurs or parsing fails.
- **Functions called**:
    - [`fd_toml_parse_expression`](#fd_toml_parse_expression)
    - [`fd_toml_avail`](#fd_toml_avail)
    - [`fd_toml_advance`](#fd_toml_advance)


---
### fd\_toml\_parse<!-- {{#callable:fd_toml_parse}} -->
Parses a TOML formatted string into a structured format.
- **Inputs**:
    - `toml`: A pointer to the TOML data to be parsed.
    - `toml_sz`: The size of the TOML data in bytes.
    - `pod`: A pointer to a buffer where parsed data will be stored.
    - `scratch`: A scratch buffer used during parsing.
    - `scratch_sz`: The size of the scratch buffer.
    - `opt_err`: An optional pointer to an error information structure.
- **Control Flow**:
    - If `opt_err` is NULL, a dummy error structure is used.
    - If `toml_sz` is zero, the function returns success immediately.
    - If `scratch_sz` is zero, a warning is logged and an error is returned.
    - A `fd_toml_parser_t` structure is initialized with the provided TOML data and buffers.
    - The [`fd_toml_parse_toml`](#fd_toml_parse_toml) function is called to perform the actual parsing.
    - The line number of the last parsed line is stored in `opt_err`.
    - If parsing fails or there are unparsed bytes left, an appropriate error is returned.
- **Output**: Returns `FD_TOML_SUCCESS` on successful parsing, or an error code indicating the type of failure.
- **Functions called**:
    - [`fd_toml_parse_toml`](#fd_toml_parse_toml)
    - [`fd_toml_avail`](#fd_toml_avail)


---
### fd\_toml\_strerror<!-- {{#callable:fd_toml_strerror}} -->
The `fd_toml_strerror` function returns a string description of a TOML parsing error based on the provided error code.
- **Inputs**:
    - `err`: An integer error code representing the type of error encountered during TOML parsing.
- **Control Flow**:
    - The function uses a `switch` statement to evaluate the value of the `err` input.
    - For each case, it returns a corresponding error message string.
    - If the error code does not match any predefined cases, it defaults to returning 'unknown error'.
- **Output**: A constant string that describes the error associated with the provided error code.


# Function Declarations (Public API)

---
### fd\_toml\_parse\_keyval<!-- {{#callable_declaration:fd_toml_parse_keyval}} -->
Parses a key-value pair from a TOML parser.
- **Description**: Use this function to parse a key-value pair from a TOML parser, ensuring that the key is unique within the current context. It should be called when a key-value pair is expected in the TOML data. The function will handle parsing errors and duplicate keys by setting an error code in the parser. It is important to ensure that the parser is properly initialized and that the input data is correctly formatted before calling this function.
- **Inputs**:
    - `parser`: A pointer to an fd_toml_parser_t structure representing the current state of the TOML parser. This parameter must not be null, and the parser should be properly initialized before calling this function. The function will modify the parser's state and may set an error code if parsing fails or a duplicate key is encountered.
- **Output**: Returns 1 on successful parsing of a key-value pair, or 0 if parsing fails or a duplicate key is detected. The parser's error field will be set in case of an error.
- **See also**: [`fd_toml_parse_keyval`](#fd_toml_parse_keyval)  (Implementation)


---
### fd\_toml\_parse\_val<!-- {{#callable_declaration:fd_toml_parse_val}} -->
Parses a TOML value from the parser state.
- **Description**: Use this function to parse a single TOML value from the current state of the parser. It attempts to match and parse various TOML data types such as strings, booleans, arrays, inline tables, date-times, floats, and integers. The function should be called when a value is expected in the TOML input. It returns an integer indicating success or failure, and the parser's state is updated accordingly. Ensure that the parser is properly initialized before calling this function.
- **Inputs**:
    - `parser`: A pointer to an fd_toml_parser_t structure representing the current state of the TOML parser. The parser must be initialized and must not be null. The function will update the parser's state as it parses the value.
- **Output**: Returns 1 if a value was successfully parsed, or 0 if no value could be parsed. The parser's state is updated to reflect the parsing result.
- **See also**: [`fd_toml_parse_val`](#fd_toml_parse_val)  (Implementation)



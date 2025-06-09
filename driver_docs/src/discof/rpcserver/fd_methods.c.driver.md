# Purpose
This C source code file is designed to parse JSON data and manage the storage and retrieval of parsed JSON values. It provides a focused functionality centered around JSON parsing, utilizing a lexer to read JSON tokens and handle syntax errors. The code defines several macros and functions to facilitate the parsing process, including [`json_values_parse`](#json_values_parse), which recursively processes JSON objects and arrays, storing the parsed values in a structured format. The file also includes functions for initializing and managing a `json_values` structure, which holds the parsed data and its associated paths, allowing for efficient storage and retrieval.

The code is part of a larger system, as indicated by the inclusion of headers like "fd_methods.h" and "fd_webserver.h", suggesting integration with a web server framework. It defines internal functions and macros rather than public APIs, focusing on the internal mechanics of JSON parsing and value management. The file provides utility functions such as [`json_add_value`](#json_add_value) for adding parsed values, [`json_get_value`](#json_get_value) for retrieving values by path, and [`json_values_printout`](#json_values_printout) for outputting the stored values and their paths. This code is likely intended to be part of a library or module that handles JSON data within a larger application, particularly in contexts where JSON data needs to be parsed, stored, and accessed efficiently.
# Imports and Dependencies

---
- `stdio.h`
- `stdlib.h`
- `assert.h`
- `fd_methods.h`
- `fd_webserver.h`
- `../../util/fd_util.h`


# Functions

---
### json\_values\_parse<!-- {{#callable:json_values_parse}} -->
The [`json_values_parse`](#json_values_parse) function parses a JSON structure from a lexical state, storing the parsed values and their paths in a structured format.
- **Inputs**:
    - `lex`: A pointer to a `json_lex_state_t` structure that maintains the current state of the JSON lexer, including the current position and last token.
    - `values`: A pointer to a `json_values` structure where parsed JSON values will be stored, along with their paths.
    - `path`: A pointer to a `json_path` structure that tracks the current path in the JSON structure being parsed, used to index values.
- **Control Flow**:
    - Check if the current path length exceeds the maximum allowed path length and report a syntax error if so.
    - Read the next token from the lexer and handle errors if the token is invalid.
    - Use a switch statement to handle different JSON token types, such as objects, arrays, strings, integers, floats, booleans, and nulls.
    - For JSON objects, expect a string key followed by a colon and recursively parse the value, handling commas between key-value pairs.
    - For JSON arrays, recursively parse each element, handling commas between elements.
    - For leaf values (strings, integers, floats, booleans, nulls), store the value in the `values` structure indexed by the current path.
    - Handle unexpected tokens and report syntax errors for invalid JSON structures.
    - Decrement the path length before returning to maintain the correct path state.
- **Output**: Returns 1 if the JSON structure is successfully parsed, or 0 if a syntax error occurs.
- **Functions called**:
    - [`json_lex_get_text`](json_lex.c.driver.md#json_lex_get_text)
    - [`fd_webserver_json_keyword`](keywords.c.driver.md#fd_webserver_json_keyword)
    - [`json_values_parse`](#json_values_parse)
    - [`json_add_value`](#json_add_value)
    - [`json_lex_as_int`](json_lex.c.driver.md#json_lex_as_int)
    - [`json_lex_as_float`](json_lex.c.driver.md#json_lex_as_float)


---
### json\_values\_new<!-- {{#callable:json_values_new}} -->
The `json_values_new` function initializes a `json_values` structure by setting its initial state and buffer allocation.
- **Inputs**:
    - `values`: A pointer to a `json_values` structure that will be initialized.
- **Control Flow**:
    - Set the `num_values` field of the `values` structure to 0, indicating no values are currently stored.
    - Assign the `buf` field of the `values` structure to point to `buf_init`, which is presumably a pre-allocated buffer.
    - Set the `buf_sz` field to 0, indicating the buffer currently holds no data.
    - Set the `buf_alloc` field to the size of `buf_init`, establishing the initial buffer allocation size.
- **Output**: The function does not return a value; it initializes the provided `json_values` structure in place.


---
### json\_values\_delete<!-- {{#callable:json_values_delete}} -->
The `json_values_delete` function is a placeholder for deleting a `json_values` structure, but currently does nothing.
- **Inputs**:
    - `values`: A pointer to a `json_values` structure that is intended to be deleted.
- **Control Flow**:
    - The function takes a single argument, `values`, which is a pointer to a `json_values` structure.
    - The function body contains a single statement that casts the `values` parameter to void, effectively ignoring it.
    - No operations are performed on the `values` parameter, and the function returns immediately.
- **Output**: The function does not return any value or perform any operations.


---
### json\_add\_value<!-- {{#callable:json_add_value}} -->
The `json_add_value` function adds a new JSON value to a `json_values` structure, ensuring buffer space is sufficient and updating the path and data storage.
- **Inputs**:
    - `values`: A pointer to a `json_values` structure where the new value will be added.
    - `path`: A pointer to a `json_path` structure that describes the path to the JSON value being added.
    - `data`: A pointer to the data to be added as a JSON value.
    - `data_sz`: The size of the data to be added.
    - `spad`: A pointer to a `fd_spad_t` structure used for memory allocation.
- **Control Flow**:
    - Check if the number of values in `values` has reached `JSON_MAX_PATHS`; if so, return without adding the value.
    - Calculate the new buffer size needed to accommodate the new data and ensure it is 8-byte aligned.
    - If the new buffer size exceeds the current allocation, double the buffer allocation size until it can accommodate the new data, then allocate new memory and copy existing data to it.
    - Increment the `num_values` counter and set up a new entry in the `values` array with the provided path and data.
    - Copy the path elements from the input `path` to the new entry's path.
    - Copy the data to the buffer at the calculated offset and update the buffer size.
- **Output**: The function does not return a value; it modifies the `json_values` structure in place to include the new JSON value.


---
### json\_get\_value<!-- {{#callable:json_get_value}} -->
The `json_get_value` function retrieves a JSON value from a structured collection based on a specified path.
- **Inputs**:
    - `values`: A pointer to a `json_values` structure containing JSON values and their associated paths.
    - `path_elems`: An array of unsigned integers representing the path elements to locate the desired JSON value.
    - `path_sz`: An unsigned integer indicating the number of elements in the `path_elems` array.
    - `data_sz`: A pointer to an unsigned long where the size of the retrieved data will be stored.
- **Control Flow**:
    - Iterate over each value in the `values` structure.
    - For each value, check if the length of its path matches `path_sz`.
    - If the lengths match, compare each element of the path with `path_elems`.
    - If all elements match, set `*data_sz` to the size of the data and return a pointer to the data in the buffer.
    - If any element does not match, break out of the inner loop and continue with the next value.
    - If no matching path is found, set `*data_sz` to 0 and return `NULL`.
- **Output**: A pointer to the data associated with the specified path if found, otherwise `NULL`.


---
### json\_get\_value\_multi<!-- {{#callable:json_get_value_multi}} -->
The `json_get_value_multi` function retrieves a JSON value from a list of values based on a specified path, starting from a given position, and updates the position for subsequent searches.
- **Inputs**:
    - `values`: A pointer to a `json_values` structure containing the JSON values and their paths.
    - `path_elems`: A pointer to an array of unsigned integers representing the path elements to search for.
    - `path_sz`: An unsigned integer representing the size of the path, i.e., the number of elements in `path_elems`.
    - `data_sz`: A pointer to an unsigned long where the size of the found data will be stored.
    - `pos`: A pointer to an unsigned integer representing the starting position for the search, which will be updated to the next position after a successful search.
- **Control Flow**:
    - Iterates over the JSON values starting from the position indicated by `*pos`.
    - For each value, checks if the path length matches `path_sz`.
    - If the path lengths match, iterates over the path elements to check for a match with `path_elems`.
    - If a match is found, updates `*data_sz` with the size of the data, updates `*pos` to the next position, and returns a pointer to the data.
    - If no match is found after iterating through all values, sets `*data_sz` to 0, updates `*pos` to the total number of values, and returns `NULL`.
- **Output**: Returns a pointer to the data associated with the matched path if found, otherwise returns `NULL`.


---
### json\_values\_printout<!-- {{#callable:json_values_printout}} -->
The `json_values_printout` function iterates over a collection of JSON values and prints each value's path and data type to the standard output.
- **Inputs**:
    - `values`: A pointer to a `struct json_values` which contains the JSON values and their associated paths to be printed.
- **Control Flow**:
    - Iterate over each JSON value in the `values` structure using a for loop.
    - For each value, retrieve its path and data using the `data_offset` and `data_sz` fields.
    - Iterate over each element in the path to determine the type of JSON token (object, array, string, integer, float, boolean, or null).
    - Use a switch statement to handle each token type, printing the appropriate representation to the standard output.
    - For string tokens, print the string data; for integer, float, and boolean tokens, assert the data size and print the value; for null tokens, print 'NULL'.
    - After processing all elements in the path, print a newline character.
- **Output**: The function outputs the path and data type of each JSON value to the standard output (stdout).
- **Functions called**:
    - [`un_fd_webserver_json_keyword`](keywords.c.driver.md#un_fd_webserver_json_keyword)



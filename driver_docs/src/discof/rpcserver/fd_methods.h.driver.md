# Purpose
This C header file defines data structures and functions for handling JSON data in a structured and efficient manner. It provides a mechanism to parse JSON data and store the results in a way that allows for quick retrieval of values based on their paths within the JSON structure. The file introduces two primary data structures: `json_path` and `json_values`. The `json_path` structure represents a path to a value in a JSON data tree, allowing for the identification of specific elements such as object members, array members, and various data types like strings, integers, and booleans. The `json_values` structure is designed to store multiple parsed JSON values, each associated with a path, and is optimized for efficient access to these values.

The header file also declares several functions that operate on these data structures. These include functions to initialize and destroy a `json_values` structure, add parsed values, retrieve values based on their paths, and print out the stored values and paths. Additionally, it provides a function to parse a block of JSON data, integrating with a lexical analysis state (`json_lex_state_t`). This file is intended to be included in other C source files, providing a public API for JSON parsing and manipulation, and is part of a larger system, likely related to an RPC server given the directory structure indicated by the header guard.
# Imports and Dependencies

---
- `json_lex.h`


# Global Variables

---
### json\_get\_value
- **Type**: `function`
- **Description**: The `json_get_value` function is designed to retrieve a specific value from a JSON data structure based on a given path. It takes a `json_values` structure, which contains parsed JSON data, a path represented as an array of unsigned integers, the size of the path, and a pointer to store the size of the data found. If the path is valid, it returns a pointer to the data; otherwise, it returns NULL.
- **Use**: This function is used to access specific data within a parsed JSON structure by following a predefined path.


---
### json\_get\_value\_multi
- **Type**: `function`
- **Description**: The `json_get_value_multi` function is a global function that retrieves a value from a `json_values` structure at a specified path. It allows for iterative retrieval of values, meaning it can be used to find multiple values that match the given path by updating the position pointer `pos`.
- **Use**: This function is used to iteratively retrieve values from a JSON data structure by specifying a path and updating the position for subsequent calls.


# Data Structures

---
### json\_path
- **Type**: `struct`
- **Members**:
    - `len`: Stores the number of elements in the path.
    - `elems`: An array of unsigned integers representing the path elements, with a maximum size defined by JSON_MAX_PATH.
- **Description**: The `json_path` structure is designed to represent a path through a JSON syntax tree, allowing for efficient navigation and retrieval of values within JSON data. Each element in the path can represent different types of JSON components, such as object members, array indices, or various value types, encoded as integers. The structure is compact, with a fixed maximum path length, making it suitable for use in scenarios where paths need to be stored and accessed quickly.


---
### json\_values
- **Type**: `struct`
- **Members**:
    - `num_values`: Stores the number of leaf values in the JSON data.
    - `values`: An array of structures, each containing a path to a data value and its offset and size in the buffer.
    - `buf`: A dynamic buffer that contains all the data values.
    - `buf_sz`: The current size of the buffer.
    - `buf_alloc`: The allocated size of the buffer.
    - `buf_init`: A statically allocated initial buffer of 2048 bytes.
- **Description**: The `json_values` structure is designed to represent the result of parsing a JSON data structure, where each leaf value (such as strings, numbers, booleans, etc.) is stored with its complete path in the JSON syntax tree. It is optimized for efficient retrieval of values at predetermined paths, using a compact and efficient format. The structure includes a dynamic buffer to store the data values, and an array of value descriptors that include the path and buffer offset for each value. This allows for quick access and manipulation of JSON data.


# Function Declarations (Public API)

---
### json\_values\_new<!-- {{#callable_declaration:json_values_new}} -->
Initialize a json_values structure.
- **Description**: Use this function to initialize a json_values structure before it is used to store parsed JSON data. This function sets up the initial state of the json_values structure, ensuring that it is ready to store paths and data values. It must be called before any other operations are performed on the json_values structure to avoid undefined behavior.
- **Inputs**:
    - `values`: A pointer to a json_values structure that will be initialized. Must not be null. The caller retains ownership and is responsible for ensuring the structure is properly allocated before calling this function.
- **Output**: None
- **See also**: [`json_values_new`](fd_methods.c.driver.md#json_values_new)  (Implementation)


---
### json\_values\_delete<!-- {{#callable_declaration:json_values_delete}} -->
Destroy a json_values structure.
- **Description**: Use this function to properly dispose of a json_values structure when it is no longer needed. This function should be called to release any resources associated with the json_values structure, ensuring that memory is managed correctly. It is important to call this function after you are done using the json_values to prevent memory leaks. The function does not perform any operations on the input parameter, but it is a placeholder for potential future resource management.
- **Inputs**:
    - `values`: A pointer to a json_values structure that is intended to be destroyed. The pointer must not be null, and the caller retains ownership of the memory.
- **Output**: None
- **See also**: [`json_values_delete`](fd_methods.c.driver.md#json_values_delete)  (Implementation)


---
### json\_add\_value<!-- {{#callable_declaration:json_add_value}} -->
Adds a parsed JSON value to a json_values structure.
- **Description**: Use this function to store a parsed JSON value along with its path in a json_values structure. It is essential to ensure that the json_values structure has been initialized and has not reached its maximum capacity of JSON_MAX_PATHS before calling this function. The function handles dynamic memory allocation for storing the data, and it will ignore the addition if the maximum number of values is already present. This function is useful for building a collection of JSON values that can be efficiently queried later.
- **Inputs**:
    - `values`: A pointer to a json_values structure where the parsed value will be added. Must be initialized and not null. The structure should not have reached its maximum capacity of JSON_MAX_PATHS.
    - `path`: A pointer to a json_path structure representing the path to the JSON value. Must not be null and should be properly initialized with a valid path.
    - `data`: A pointer to the data representing the JSON value to be added. Must not be null and should point to a valid memory location containing the data.
    - `data_sz`: The size in bytes of the data to be added. Must be a positive value and should accurately reflect the size of the data pointed to by the data parameter.
    - `spad`: A pointer to an fd_spad_t structure used for memory allocation. Must not be null and should be properly initialized for memory operations.
- **Output**: None
- **See also**: [`json_add_value`](fd_methods.c.driver.md#json_add_value)  (Implementation)


---
### json\_get\_value<!-- {{#callable_declaration:json_get_value}} -->
Retrieve a JSON value from a specified path.
- **Description**: Use this function to obtain a pointer to a JSON value stored within a `json_values` structure, based on a specified path. The function searches for a path that matches the provided path elements and returns a pointer to the corresponding data if found. It is essential to ensure that the `json_values` structure has been properly initialized and populated with data before calling this function. If the specified path is not found, the function returns `NULL` and sets the size of the data to zero. This function is useful for accessing specific JSON data efficiently when the path is known.
- **Inputs**:
    - `values`: A pointer to a `json_values` structure containing parsed JSON data. Must not be null and should be initialized and populated with data.
    - `path_elems`: A pointer to an array of `uint` representing the path elements to the desired JSON value. Must not be null.
    - `path_sz`: The number of elements in the `path_elems` array. Must be a non-negative integer.
    - `data_sz`: A pointer to a `ulong` where the size of the retrieved data will be stored. Must not be null.
- **Output**: Returns a pointer to the JSON value if the path is found, or `NULL` if the path is not found. The size of the data is stored in `data_sz`.
- **See also**: [`json_get_value`](fd_methods.c.driver.md#json_get_value)  (Implementation)


---
### json\_get\_value\_multi<!-- {{#callable_declaration:json_get_value_multi}} -->
Retrieve a value from a JSON structure using a path, allowing for iterative access.
- **Description**: This function is used to retrieve a value from a JSON structure by specifying a path to the desired value. It is particularly useful when you need to access multiple values iteratively, as it allows you to continue from the last position using the `pos` parameter. The function must be called with a valid `json_values` structure that has been populated with parsed JSON data. The `pos` parameter should be initialized to zero before the first call and will be updated to the next position after each call. If the specified path is found, the function returns a pointer to the data and updates `data_sz` with the size of the data. If the path is not found, it returns NULL and sets `data_sz` to zero.
- **Inputs**:
    - `values`: A pointer to a `json_values` structure containing parsed JSON data. Must not be null and should be properly initialized and populated before calling this function.
    - `path_elems`: A pointer to an array of `uint` representing the path elements to the desired value. The array should not be null and must contain at least `path_sz` elements.
    - `path_sz`: The number of elements in the `path_elems` array. Must be a non-negative integer.
    - `data_sz`: A pointer to an `ulong` where the size of the retrieved data will be stored. Must not be null.
    - `pos`: A pointer to a `uint` that indicates the current position in the iteration. Should be initialized to zero before the first call and will be updated by the function.
- **Output**: Returns a pointer to the data if the path is found, or NULL if not. Updates `data_sz` with the size of the data if found, or sets it to zero if not. Updates `pos` to the next position for iteration.
- **See also**: [`json_get_value_multi`](fd_methods.c.driver.md#json_get_value_multi)  (Implementation)


---
### json\_values\_printout<!-- {{#callable_declaration:json_values_printout}} -->
Dump the values and paths to stdout.
- **Description**: Use this function to print all the JSON values and their corresponding paths stored in a `json_values` structure to the standard output. It is useful for debugging or inspecting the contents of the JSON data structure. The function iterates over each value, printing its path and data type, and handles various JSON data types such as objects, arrays, strings, integers, floats, booleans, and nulls. Ensure that the `json_values` structure is properly initialized and populated before calling this function.
- **Inputs**:
    - `values`: A pointer to a `json_values` structure containing the JSON data to be printed. This structure must be initialized and populated with valid JSON data. The function does not modify this structure.
- **Output**: None
- **See also**: [`json_values_printout`](fd_methods.c.driver.md#json_values_printout)  (Implementation)


---
### json\_values\_parse<!-- {{#callable_declaration:json_values_parse}} -->
Parses JSON data and stores the values with their paths.
- **Description**: This function is used to parse JSON data from a lexical state and store the resulting values and their corresponding paths in a structured format. It should be called when you need to extract and organize JSON data into a `json_values` structure for efficient retrieval. The function expects a valid JSON lexical state and a path structure to track the current position in the JSON hierarchy. It handles various JSON data types, including objects, arrays, strings, numbers, booleans, and nulls, and reports syntax errors if the JSON is malformed or too deeply nested. The function must be called with a properly initialized `json_lex_state_t`, `json_values`, and `json_path`.
- **Inputs**:
    - `lex`: A pointer to a `json_lex_state_t` structure representing the current state of JSON lexical analysis. It must be initialized and not null.
    - `values`: A pointer to a `json_values` structure where parsed JSON values and their paths will be stored. It must be initialized and not null.
    - `path`: A pointer to a `json_path` structure used to track the current path in the JSON hierarchy. It must be initialized and not null, and its length must not exceed `JSON_MAX_PATH`.
- **Output**: Returns 1 on successful parsing of the JSON data, or 0 if a syntax error is encountered.
- **See also**: [`json_values_parse`](fd_methods.c.driver.md#json_values_parse)  (Implementation)



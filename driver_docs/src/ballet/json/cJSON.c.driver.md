# Purpose
The provided C source code is part of the cJSON library, which is a lightweight JSON parser and printer written in C. This file implements the core functionality of the cJSON library, including parsing JSON strings into cJSON objects, printing cJSON objects back into JSON strings, and managing memory for these operations. The code defines various functions to handle JSON data types such as objects, arrays, strings, numbers, booleans, and null values. It also includes utility functions for creating, deleting, and manipulating cJSON objects, as well as functions for comparing JSON objects and handling JSON arrays and objects.

The file includes several public API functions, such as [`cJSON_Parse`](#cJSON_Parse), [`cJSON_Print`](#cJSON_Print), [`cJSON_GetObjectItem`](#cJSON_GetObjectItem), and [`cJSON_AddItemToObject`](#cJSON_AddItemToObject), which are intended to be used by other programs that include the cJSON library. These functions provide a straightforward interface for working with JSON data in C, allowing users to parse JSON strings, access and modify JSON objects, and serialize cJSON objects back into JSON format. The code also includes internal utility functions and macros to support these operations, such as memory management hooks and functions for handling locale-specific number formatting. Overall, this file is a comprehensive implementation of a JSON library in C, providing essential functionality for JSON parsing and manipulation.
# Imports and Dependencies

---
- `string.h`
- `stdio.h`
- `math.h`
- `stdlib.h`
- `limits.h`
- `ctype.h`
- `float.h`
- `locale.h`
- `cJSON.h`


# Global Variables

---
### global\_error
- **Type**: `error`
- **Description**: The `global_error` variable is a static instance of the `error` struct, which contains two fields: a pointer to a JSON string (`json`) and a position index (`position`). It is initialized with `NULL` for the JSON string and `0` for the position index.
- **Use**: This variable is used to store and track the position of errors encountered during JSON parsing operations.


---
### global\_hooks
- **Type**: `internal_hooks`
- **Description**: The `global_hooks` variable is a static instance of the `internal_hooks` structure, which contains function pointers for memory allocation, deallocation, and reallocation. It is initialized with default functions `internal_malloc`, `internal_free`, and `internal_realloc`, which are typically mapped to the standard C library functions `malloc`, `free`, and `realloc`. This allows for custom memory management strategies to be implemented by replacing these function pointers.
- **Use**: `global_hooks` is used throughout the cJSON library to manage memory allocation and deallocation, providing a centralized mechanism to customize memory handling.


# Data Structures

---
### error
- **Type**: `struct`
- **Members**:
    - `json`: A pointer to an unsigned char representing the JSON data associated with the error.
    - `position`: A size_t value indicating the position in the JSON data where the error occurred.
- **Description**: The `error` structure is used to represent an error state in JSON parsing, specifically within the cJSON library. It contains a pointer to the JSON data and a position index, which together indicate where in the JSON data the error was encountered. This structure is utilized to track and report errors during the parsing process, allowing for more precise error handling and debugging.


---
### internal\_hooks
- **Type**: `struct`
- **Members**:
    - `allocate`: A function pointer for memory allocation, taking a size_t argument and returning a void pointer.
    - `deallocate`: A function pointer for memory deallocation, taking a void pointer argument.
    - `reallocate`: A function pointer for memory reallocation, taking a void pointer and a size_t argument, returning a void pointer.
- **Description**: The `internal_hooks` structure is designed to encapsulate custom memory management functions for allocation, deallocation, and reallocation of memory. This allows the cJSON library to use user-defined memory management routines instead of the default `malloc`, `free`, and `realloc` functions, providing flexibility for different memory management strategies or environments.


---
### parse\_buffer
- **Type**: `struct`
- **Members**:
    - `content`: A pointer to the unsigned char array representing the content to be parsed.
    - `length`: The total length of the content array.
    - `offset`: The current position within the content array being parsed.
    - `depth`: Indicates the current level of nesting within arrays or objects at the current offset.
    - `hooks`: A structure containing function pointers for memory allocation, deallocation, and reallocation.
- **Description**: The `parse_buffer` structure is used in the context of parsing JSON data. It holds the content to be parsed, tracks the current position and depth of parsing, and provides hooks for memory management. This structure is essential for managing the state and progress of the parsing process, allowing for efficient and controlled parsing of JSON data.


---
### printbuffer
- **Type**: `struct`
- **Members**:
    - `buffer`: A pointer to an unsigned char array that holds the data to be printed.
    - `length`: The total size of the buffer in bytes.
    - `offset`: The current position in the buffer where new data will be written.
    - `depth`: Tracks the current nesting depth for formatted printing.
    - `noalloc`: A boolean indicating if the buffer should not be reallocated.
    - `format`: A boolean indicating if the print should be formatted.
    - `hooks`: A structure containing function pointers for memory allocation and deallocation.
- **Description**: The `printbuffer` structure is used in the cJSON library to manage the buffer where JSON data is printed. It contains information about the buffer's size, the current position for writing, and whether the output should be formatted. Additionally, it includes a depth counter for managing nested structures and a set of hooks for custom memory management. This structure is crucial for efficiently handling JSON serialization in a flexible and customizable manner.


# Functions

---
### cJSON\_GetErrorPtr<!-- {{#callable:cJSON_GetErrorPtr}} -->
Returns a pointer to the error message in the global error state.
- **Inputs**: None
- **Control Flow**:
    - Accesses the `global_error` structure which contains the JSON string and the current position of the error.
    - Calculates the address of the error message by adding the position to the base address of the JSON string.
    - Returns the pointer to the error message.
- **Output**: A pointer to a constant character string that represents the error message, or NULL if there is no error.


---
### cJSON\_GetStringValue<!-- {{#callable:cJSON_GetStringValue}} -->
Retrieves the string value from a `cJSON` item if it is of type string.
- **Inputs**:
    - `item`: A pointer to a `cJSON` object that is expected to be of type string.
- **Control Flow**:
    - The function first checks if the `item` is a string using the [`cJSON_IsString`](#cJSON_IsString) function.
    - If `item` is not a string, the function returns NULL.
    - If `item` is a string, the function returns the `valuestring` member of the `item`.
- **Output**: Returns a pointer to the string value of the `cJSON` item if it is a string; otherwise, it returns NULL.
- **Functions called**:
    - [`cJSON_IsString`](#cJSON_IsString)


---
### cJSON\_GetNumberValue<!-- {{#callable:cJSON_GetNumberValue}} -->
Retrieves the numeric value of a `cJSON` item if it is a number, otherwise returns NaN.
- **Inputs**:
    - `item`: A pointer to a `cJSON` object that is expected to represent a number.
- **Control Flow**:
    - The function first checks if the `item` is a number using the [`cJSON_IsNumber`](#cJSON_IsNumber) function.
    - If `item` is not a number, it returns NaN (Not a Number) by casting the constant `NAN` to a double.
    - If `item` is a number, it retrieves the value stored in `item->valuedouble` and returns it.
- **Output**: Returns the numeric value of the `cJSON` item as a double, or NaN if the item is not a number.
- **Functions called**:
    - [`cJSON_IsNumber`](#cJSON_IsNumber)


---
### cJSON\_Version<!-- {{#callable:cJSON_Version}} -->
Returns the version of the cJSON library as a string.
- **Inputs**: None
- **Control Flow**:
    - A static character array `version` of size 15 is declared to hold the version string.
    - The `sprintf` function is used to format the version string using the major, minor, and patch version numbers defined by `CJSON_VERSION_MAJOR`, `CJSON_VERSION_MINOR`, and `CJSON_VERSION_PATCH`.
    - The formatted version string is returned.
- **Output**: A pointer to a string containing the version of the cJSON library.


---
### case\_insensitive\_strcmp<!-- {{#callable:case_insensitive_strcmp}} -->
Compares two strings in a case-insensitive manner.
- **Inputs**:
    - `string1`: A pointer to the first string to compare.
    - `string2`: A pointer to the second string to compare.
- **Control Flow**:
    - Checks if either `string1` or `string2` is NULL, returning 1 if so.
    - If both strings point to the same memory location, returns 0.
    - Iterates through both strings, comparing their characters in a case-insensitive manner using `tolower`.
    - If a null terminator is reached in both strings simultaneously, returns 0.
    - Returns the difference between the first non-matching characters after converting them to lowercase.
- **Output**: Returns 0 if the strings are equal, a negative value if `string1` is less than `string2`, and a positive value if `string1` is greater than `string2`.


---
### internal\_malloc<!-- {{#callable:CJSON_CDECL::internal_malloc}} -->
Allocates memory of the specified size using `malloc`.
- **Inputs**:
    - `size`: The number of bytes to allocate.
- **Control Flow**:
    - Calls `malloc` with the specified size.
    - Returns the pointer to the allocated memory.
- **Output**: A pointer to the allocated memory block, or NULL if the allocation fails.


---
### internal\_free<!-- {{#callable:CJSON_CDECL::internal_free}} -->
The `internal_free` function deallocates memory previously allocated for a given pointer.
- **Inputs**:
    - `pointer`: A pointer to the memory block that needs to be freed.
- **Control Flow**:
    - The function directly calls the `free` function to release the memory pointed to by `pointer`.
    - No checks are performed on the pointer; if it is NULL, `free` will safely do nothing.
- **Output**: This function does not return a value; it simply frees the memory.


---
### internal\_realloc<!-- {{#callable:CJSON_CDECL::internal_realloc}} -->
The `internal_realloc` function reallocates memory for a given pointer to a specified size.
- **Inputs**:
    - `pointer`: A pointer to the memory block that needs to be reallocated.
    - `size`: The new size in bytes for the memory block.
- **Control Flow**:
    - The function calls the standard library function `realloc` with the provided `pointer` and `size`.
    - It returns the pointer to the newly allocated memory, which may be the same as the original pointer or a new location.
- **Output**: Returns a pointer to the reallocated memory block, or NULL if the allocation fails.


---
### cJSON\_strdup<!-- {{#callable:cJSON_strdup}} -->
The `cJSON_strdup` function duplicates a given string using a specified memory allocation hook.
- **Inputs**:
    - `string`: A pointer to the string to be duplicated, which must not be NULL.
    - `hooks`: A pointer to an `internal_hooks` structure that provides custom memory allocation functions.
- **Control Flow**:
    - The function first checks if the input `string` is NULL; if it is, the function returns NULL immediately.
    - It calculates the length of the input string and allocates memory for the duplicate string using the provided `hooks->allocate` function.
    - If memory allocation fails (i.e., returns NULL), the function returns NULL.
    - If allocation is successful, it copies the content of the original string into the newly allocated memory using `memcpy`.
    - Finally, it returns a pointer to the newly duplicated string.
- **Output**: Returns a pointer to the newly allocated duplicate of the input string, or NULL if the input string is NULL or memory allocation fails.


---
### cJSON\_InitHooks<!-- {{#callable:cJSON_InitHooks}} -->
Initializes or resets memory allocation hooks for cJSON.
- **Inputs**:
    - `hooks`: A pointer to a `cJSON_Hooks` structure that contains custom memory allocation functions.
- **Control Flow**:
    - If `hooks` is NULL, the function resets the global memory allocation hooks to use the default `malloc`, `free`, and `realloc` functions.
    - If `hooks` is not NULL, it checks if the `malloc_fn` and `free_fn` members of the `hooks` structure are not NULL and assigns them to the global hooks.
    - The `reallocate` function is set to `realloc` only if the default `malloc` and `free` functions are being used.
- **Output**: The function does not return a value; it modifies the global memory allocation hooks used by cJSON.


---
### cJSON\_New\_Item<!-- {{#callable:cJSON_New_Item}} -->
Creates a new `cJSON` item by allocating memory and initializing it.
- **Inputs**:
    - `hooks`: A pointer to an `internal_hooks` structure that contains memory allocation functions.
- **Control Flow**:
    - Calls the `allocate` function from the `hooks` structure to allocate memory for a new `cJSON` item.
    - If the memory allocation is successful, it initializes the allocated memory to zero using `memset`.
    - Returns the pointer to the newly created `cJSON` item or NULL if allocation fails.
- **Output**: Returns a pointer to the newly created `cJSON` item, or NULL if memory allocation fails.


---
### cJSON\_Delete<!-- {{#callable:cJSON_Delete}} -->
The `cJSON_Delete` function recursively frees a `cJSON` structure and all its children.
- **Inputs**:
    - `item`: A pointer to the `cJSON` structure to be deleted.
- **Control Flow**:
    - The function enters a loop that continues until `item` is NULL.
    - Within the loop, it stores the next item in `next` before processing the current item.
    - If the current item is not a reference and has children, it recursively calls `cJSON_Delete` on the child.
    - If the current item is not a reference and has a string value, it deallocates the string.
    - If the current item is not a constant string and has a string key, it deallocates the key.
    - Finally, it deallocates the current item itself and moves to the next item.
- **Output**: The function does not return a value; it frees the memory associated with the `cJSON` structure and its children.


---
### get\_decimal\_point<!-- {{#callable:get_decimal_point}} -->
The `get_decimal_point` function retrieves the decimal point character based on the current locale settings.
- **Inputs**: None
- **Control Flow**:
    - If `ENABLE_LOCALES` is defined, the function calls `localeconv()` to obtain the current locale's formatting information.
    - It then returns the first character of the `decimal_point` string from the `lconv` structure.
    - If `ENABLE_LOCALES` is not defined, it directly returns the character '.' as the decimal point.
- **Output**: The function returns an `unsigned char` representing the decimal point character, which is either the locale-specific character or '.'.


---
### parse\_number<!-- {{#callable:parse_number}} -->
Parses a number from a JSON input buffer and populates a cJSON item with the parsed value.
- **Inputs**:
    - `item`: A pointer to a `cJSON` structure where the parsed number will be stored.
    - `input_buffer`: A pointer to a `parse_buffer` structure containing the JSON input data to be parsed.
- **Control Flow**:
    - Checks if the `input_buffer` and its content are valid; if not, returns false.
    - Iterates through the input buffer, copying valid number characters into a temporary string while replacing '.' with the locale-specific decimal point.
    - Uses `strtod` to convert the temporary string to a double, checking for parsing errors.
    - Assigns the parsed double to `item->valuedouble` and calculates the integer representation, ensuring it does not overflow.
    - Updates the `input_buffer` offset to reflect the number of characters consumed during parsing.
    - Returns true if parsing is successful, otherwise returns false.
- **Output**: Returns true if the number was successfully parsed and stored in the `item`, otherwise returns false.
- **Functions called**:
    - [`get_decimal_point`](#get_decimal_point)


---
### cJSON\_SetNumberHelper<!-- {{#callable:cJSON_SetNumberHelper}} -->
Sets the integer and double values of a `cJSON` object based on a provided double value.
- **Inputs**:
    - `object`: A pointer to a `cJSON` object that will be modified to store the number.
    - `number`: A double value that will be set in the `cJSON` object.
- **Control Flow**:
    - The function first checks if the `number` is greater than or equal to `INT_MAX` and sets the `valueint` field of the `object` to `INT_MAX` if true.
    - If the `number` is less than or equal to `INT_MIN`, it sets the `valueint` field to `INT_MIN`.
    - If the `number` is within the range of `INT_MIN` and `INT_MAX`, it casts the `number` to an integer and assigns it to `valueint`.
    - Finally, it sets the `valuedouble` field of the `object` to the original `number` and returns this value.
- **Output**: Returns the double value that was set in the `valuedouble` field of the `cJSON` object.


---
### cJSON\_SetValuestring<!-- {{#callable:cJSON_SetValuestring}} -->
Sets the value of a `cJSON` object to a new string.
- **Inputs**:
    - `object`: A pointer to a `cJSON` object that is expected to be of type `cJSON_String`.
    - `valuestring`: A pointer to a string that will be set as the new value for the `cJSON` object.
- **Control Flow**:
    - Checks if the `object` is of type `cJSON_String` and not a reference; if not, returns NULL.
    - If the length of `valuestring` is less than or equal to the current length of `object->valuestring`, it copies `valuestring` into `object->valuestring` and returns it.
    - If `valuestring` is longer, it duplicates `valuestring` using [`cJSON_strdup`](#cJSON_strdup) and assigns it to `object->valuestring`, freeing the old value if it exists.
    - Returns the new string value assigned to `object->valuestring`.
- **Output**: Returns a pointer to the new string value set in the `cJSON` object, or NULL if the operation fails.
- **Functions called**:
    - [`cJSON_strdup`](#cJSON_strdup)
    - [`cJSON_free`](#cJSON_free)


---
### ensure<!-- {{#callable:ensure}} -->
Reallocates the buffer in a `printbuffer` structure to ensure it can accommodate additional data.
- **Inputs**:
    - `p`: A pointer to a `printbuffer` structure that contains the current buffer, its length, and offset.
    - `needed`: The additional size in bytes that is required to be accommodated in the buffer.
- **Control Flow**:
    - Checks if the `printbuffer` pointer `p` or its buffer is NULL, returning NULL if true.
    - Validates that the current offset is within the bounds of the buffer length.
    - Checks if the requested `needed` size exceeds `INT_MAX`, returning NULL if it does.
    - Calculates the total size needed by adding the current offset and 1 to `needed`.
    - If the total size is less than or equal to the current buffer length, returns a pointer to the current buffer at the offset.
    - If `noalloc` is set in the `printbuffer`, returns NULL to indicate no allocation is allowed.
    - Calculates a new buffer size, doubling the `needed` size or capping it at `INT_MAX` to prevent overflow.
    - Attempts to reallocate the buffer using the provided reallocation hook, or allocates a new buffer if the hook is not available.
    - Copies the existing data from the old buffer to the new buffer if a new allocation was made.
    - Updates the `printbuffer` structure with the new buffer and its new length, returning a pointer to the buffer at the current offset.
- **Output**: Returns a pointer to the buffer at the current offset in the `printbuffer`, or NULL if allocation fails or other conditions are not met.


---
### update\_offset<!-- {{#callable:update_offset}} -->
Updates the offset of a `printbuffer` by the length of the string starting from the current offset.
- **Inputs**:
    - `buffer`: A pointer to a `printbuffer` structure that contains the current offset and the buffer to be updated.
- **Control Flow**:
    - Checks if the `buffer` or `buffer->buffer` is NULL; if so, the function returns immediately.
    - Calculates the pointer to the current position in the buffer using `buffer->offset`.
    - Updates the `offset` of the `buffer` by adding the length of the string starting from the current offset, determined using `strlen`.
- **Output**: The function does not return a value; it modifies the `offset` field of the `printbuffer` directly.


---
### compare\_double<!-- {{#callable:compare_double}} -->
Compares two double precision floating-point numbers for equality within a relative tolerance.
- **Inputs**:
    - `a`: The first double value to compare.
    - `b`: The second double value to compare.
- **Control Flow**:
    - Calculates the maximum absolute value between `a` and `b` using `fabs`.
    - Checks if the absolute difference between `a` and `b` is less than or equal to the product of the maximum value and `DBL_EPSILON`.
- **Output**: Returns `cJSON_bool` indicating whether the two double values are considered equal within the defined tolerance.


---
### print\_number<!-- {{#callable:print_number}} -->
The `print_number` function formats a `cJSON` number item into a string representation and writes it to a specified output buffer.
- **Inputs**:
    - `item`: A pointer to a `cJSON` structure representing the number to be printed.
    - `output_buffer`: A pointer to a `printbuffer` structure where the formatted number will be written.
- **Control Flow**:
    - The function first checks if the `output_buffer` is NULL, returning false if it is.
    - It checks if the number is NaN or Infinity, and if so, formats it as 'null'.
    - If the number can be represented as an integer, it formats it as an integer.
    - If the number is a floating-point value, it attempts to format it with 15 decimal places of precision.
    - It verifies if the formatted string can accurately represent the original number; if not, it tries with 17 decimal places.
    - The function checks for buffer overrun or formatting errors, returning false if any occur.
    - It ensures there is enough space in the `output_buffer` and copies the formatted number into it, replacing locale-specific decimal points with '.'
    - Finally, it updates the offset of the `output_buffer` and returns true.
- **Output**: Returns true if the number was successfully formatted and written to the output buffer; otherwise, returns false.
- **Functions called**:
    - [`get_decimal_point`](#get_decimal_point)
    - [`compare_double`](#compare_double)
    - [`ensure`](#ensure)


---
### parse\_hex4<!-- {{#callable:parse_hex4}} -->
Parses a 4-character hexadecimal string into an unsigned integer.
- **Inputs**:
    - `input`: A pointer to an array of unsigned characters representing a 4-character hexadecimal string.
- **Control Flow**:
    - Initializes an unsigned integer `h` to 0 and a size_t variable `i` to 0.
    - Iterates over the first 4 characters of the input string.
    - For each character, checks if it is a valid hexadecimal digit (0-9, A-F, a-f).
    - If valid, converts the character to its corresponding integer value and adds it to `h`, shifting `h` left by 4 bits for each character except the last.
    - If an invalid character is encountered, returns 0 immediately.
    - After processing all characters, returns the accumulated value in `h`.
- **Output**: Returns the parsed unsigned integer value corresponding to the hexadecimal input, or 0 if the input is invalid.


---
### utf16\_literal\_to\_utf8<!-- {{#callable:utf16_literal_to_utf8}} -->
Converts a UTF-16 literal to UTF-8 encoding.
- **Inputs**:
    - `input_pointer`: A pointer to the start of the UTF-16 literal input.
    - `input_end`: A pointer to the end of the input buffer.
    - `output_pointer`: A pointer to a pointer where the UTF-8 output will be written.
- **Control Flow**:
    - Checks if the input length is less than 6 bytes, which is insufficient for a valid UTF-16 sequence.
    - Parses the first UTF-16 sequence to obtain the code point.
    - Validates the first code point to ensure it is not a surrogate.
    - If the first code point indicates a surrogate pair, it checks for a valid second sequence and calculates the combined code point.
    - Determines the length of the UTF-8 encoding based on the code point value.
    - Encodes the code point into UTF-8 format, writing the result to the output pointer.
    - Returns the length of the UTF-16 sequence processed or 0 on failure.
- **Output**: Returns the length of the UTF-16 sequence processed, or 0 if an error occurred.
- **Functions called**:
    - [`parse_hex4`](#parse_hex4)


---
### parse\_string<!-- {{#callable:parse_string}} -->
Parses a JSON string from a buffer and populates a cJSON item.
- **Inputs**:
    - `item`: A pointer to a `cJSON` structure where the parsed string will be stored.
    - `input_buffer`: A pointer to a `parse_buffer` structure containing the JSON string to be parsed.
- **Control Flow**:
    - Checks if the first character in the buffer is a double quote ('"'); if not, it jumps to the fail label.
    - Calculates the size of the output string by iterating through the input buffer until the closing double quote is found, accounting for escape sequences.
    - Allocates memory for the output string based on the calculated size.
    - Iterates through the input string, copying characters to the output while handling escape sequences appropriately.
    - Handles UTF-16 escape sequences by converting them to UTF-8.
    - Sets the type of the `item` to `cJSON_String` and assigns the parsed string to `item->valuestring`.
    - Updates the offset in the input buffer to point to the next character after the closing double quote.
    - Returns true if parsing is successful; otherwise, it jumps to the fail label.
- **Output**: Returns true if the string is successfully parsed; otherwise, returns false.
- **Functions called**:
    - [`utf16_literal_to_utf8`](#utf16_literal_to_utf8)


---
### print\_string\_ptr<!-- {{#callable:print_string_ptr}} -->
The `print_string_ptr` function formats a string for JSON output, escaping necessary characters.
- **Inputs**:
    - `input`: A pointer to the input string that needs to be formatted.
    - `output_buffer`: A pointer to a `printbuffer` structure where the formatted string will be stored.
- **Control Flow**:
    - The function first checks if the `output_buffer` is NULL and returns false if it is.
    - If the `input` string is NULL, it allocates space for an empty JSON string and returns true.
    - It iterates through the `input` string to count the number of characters that need to be escaped.
    - The total output length is calculated based on the original string length and the number of escape characters.
    - The function ensures that the `output_buffer` has enough space for the formatted string.
    - If no characters need to be escaped, it copies the string directly into the output buffer.
    - If there are characters to escape, it constructs the output string by copying characters and adding escape sequences as necessary.
    - Finally, it null-terminates the output string and returns true.
- **Output**: Returns true if the string was successfully formatted and stored in the output buffer; otherwise, returns false.
- **Functions called**:
    - [`ensure`](#ensure)


---
### print\_string<!-- {{#callable:print_string}} -->
The `print_string` function renders a JSON string item into a formatted output buffer.
- **Inputs**:
    - `item`: A pointer to a `cJSON` structure representing the JSON item to be printed, specifically expected to be of type string.
    - `p`: A pointer to a `printbuffer` structure that holds the output buffer where the rendered string will be stored.
- **Control Flow**:
    - The function calls [`print_string_ptr`](#print_string_ptr), passing the `valuestring` of the `item` cast to an `unsigned char*` along with the output buffer `p`.
    - The [`print_string_ptr`](#print_string_ptr) function handles the actual rendering of the string, including any necessary escaping.
- **Output**: Returns a boolean value indicating success (true) or failure (false) of the printing operation.
- **Functions called**:
    - [`print_string_ptr`](#print_string_ptr)


---
### buffer\_skip\_whitespace<!-- {{#callable:buffer_skip_whitespace}} -->
The `buffer_skip_whitespace` function advances the offset of a `parse_buffer` structure to skip over any leading whitespace characters.
- **Inputs**:
    - `buffer`: A pointer to a `parse_buffer` structure that contains the content to be parsed.
- **Control Flow**:
    - The function first checks if the `buffer` or its `content` is NULL, returning NULL if either is the case.
    - It then checks if the first index of the buffer can be accessed; if not, it returns the buffer as is.
    - A while loop is used to increment the `offset` of the buffer as long as the current character is a whitespace character (ASCII value <= 32).
    - After the loop, if the `offset` equals the `length` of the buffer, it decrements the `offset` by one to avoid going out of bounds.
    - Finally, the function returns the updated `buffer`.
- **Output**: The function returns a pointer to the updated `parse_buffer` with the `offset` adjusted to skip leading whitespace.


---
### skip\_utf8\_bom<!-- {{#callable:skip_utf8_bom}} -->
The `skip_utf8_bom` function skips the UTF-8 Byte Order Mark (BOM) in a given parse buffer.
- **Inputs**:
    - `buffer`: A pointer to a `parse_buffer` structure that contains the content to be checked for a UTF-8 BOM.
- **Control Flow**:
    - The function first checks if the `buffer` is NULL, if its content is NULL, or if the offset is not zero; if any of these conditions are true, it returns NULL.
    - Next, it checks if there are at least 4 bytes available to read in the buffer and if the first three bytes match the UTF-8 BOM (0xEF, 0xBB, 0xBF).
    - If the BOM is found, it increments the `offset` of the buffer by 3 to skip over the BOM.
    - Finally, it returns the modified buffer.
- **Output**: Returns the updated `parse_buffer` pointer, or NULL if the input conditions are not met.


---
### cJSON\_ParseWithOpts<!-- {{#callable:cJSON_ParseWithOpts}} -->
Parses a JSON string with options for null termination.
- **Inputs**:
    - `value`: A pointer to the JSON string to be parsed.
    - `return_parse_end`: A pointer to a pointer that will be set to the end of the parsed JSON string.
    - `require_null_terminated`: A boolean indicating whether the JSON string must be null-terminated.
- **Control Flow**:
    - Checks if the input string `value` is NULL; if so, returns NULL.
    - Calculates the length of the input string, adding space for a null terminator if required.
    - Calls the [`cJSON_ParseWithLengthOpts`](#cJSON_ParseWithLengthOpts) function with the calculated length and other parameters.
- **Output**: Returns a pointer to a `cJSON` object representing the parsed JSON, or NULL if parsing fails.
- **Functions called**:
    - [`cJSON_ParseWithLengthOpts`](#cJSON_ParseWithLengthOpts)


---
### cJSON\_ParseWithLengthOpts<!-- {{#callable:cJSON_ParseWithLengthOpts}} -->
Parses a JSON string with specified length options and returns a cJSON object.
- **Inputs**:
    - `value`: A pointer to the JSON string to be parsed.
    - `buffer_length`: The length of the JSON string to be parsed.
    - `return_parse_end`: A pointer to a string pointer that will be set to the end of the parsed JSON.
    - `require_null_terminated`: A boolean indicating whether the JSON string must be null-terminated.
- **Control Flow**:
    - Initializes a parse buffer and resets the global error state.
    - Checks if the input string is NULL or if the buffer length is zero, and jumps to the fail label if true.
    - Sets up the parse buffer with the input string and its length.
    - Attempts to create a new cJSON item to hold the parsed data.
    - Calls the [`parse_value`](#parse_value) function to parse the JSON value from the buffer.
    - If `require_null_terminated` is true, checks for a null terminator after parsing.
    - If `return_parse_end` is provided, sets it to the end of the parsed JSON.
    - Returns the parsed cJSON item or NULL if parsing fails, cleaning up any allocated memory.
- **Output**: Returns a pointer to a cJSON object representing the parsed JSON, or NULL if parsing fails.
- **Functions called**:
    - [`cJSON_New_Item`](#cJSON_New_Item)
    - [`parse_value`](#parse_value)
    - [`buffer_skip_whitespace`](#buffer_skip_whitespace)
    - [`skip_utf8_bom`](#skip_utf8_bom)
    - [`cJSON_Delete`](#cJSON_Delete)


---
### cJSON\_Parse<!-- {{#callable:cJSON_Parse}} -->
Parses a JSON string and returns a `cJSON` object.
- **Inputs**:
    - `value`: A pointer to a null-terminated string containing the JSON data to be parsed.
- **Control Flow**:
    - Calls [`cJSON_ParseWithOpts`](#cJSON_ParseWithOpts) with the provided JSON string and default options (no specific parsing options).
- **Output**: Returns a pointer to a `cJSON` object representing the parsed JSON data, or NULL if parsing fails.
- **Functions called**:
    - [`cJSON_ParseWithOpts`](#cJSON_ParseWithOpts)


---
### cJSON\_ParseWithLength<!-- {{#callable:cJSON_ParseWithLength}} -->
Parses a JSON string with a specified buffer length.
- **Inputs**:
    - `value`: A pointer to the JSON string to be parsed.
    - `buffer_length`: The length of the JSON string to be parsed.
- **Control Flow**:
    - Calls [`cJSON_ParseWithLengthOpts`](#cJSON_ParseWithLengthOpts) with the provided value and buffer length, along with default options (0, 0).
    - The function does not perform any additional checks or processing beyond the call to [`cJSON_ParseWithLengthOpts`](#cJSON_ParseWithLengthOpts).
- **Output**: Returns a pointer to a `cJSON` object representing the parsed JSON data, or NULL if parsing fails.
- **Functions called**:
    - [`cJSON_ParseWithLengthOpts`](#cJSON_ParseWithLengthOpts)


---
### print<!-- {{#callable:print}} -->
The `print` function serializes a `cJSON` object into a JSON formatted string.
- **Inputs**:
    - `item`: A pointer to a `cJSON` object that needs to be serialized.
    - `format`: A boolean indicating whether the output should be formatted (pretty-printed) or not.
    - `hooks`: A pointer to an `internal_hooks` structure that provides custom memory allocation functions.
- **Control Flow**:
    - A static buffer of size 256 is created to hold the serialized JSON string.
    - Memory is allocated for the buffer using the provided allocation function from `hooks`.
    - The function [`print_value`](#print_value) is called to serialize the `item` into the buffer.
    - If the buffer needs to be reallocated, the `reallocate` function is used; otherwise, a new buffer is allocated to copy the serialized string.
    - The function handles memory cleanup in case of failure, ensuring no memory leaks occur.
- **Output**: Returns a pointer to the serialized JSON string, or NULL if an error occurs.
- **Functions called**:
    - [`print_value`](#print_value)
    - [`update_offset`](#update_offset)


---
### cJSON\_Print<!-- {{#callable:cJSON_Print}} -->
The `cJSON_Print` function converts a `cJSON` object into a formatted JSON string.
- **Inputs**:
    - `item`: A pointer to a `cJSON` object that needs to be converted to a JSON string.
- **Control Flow**:
    - The function calls the [`print`](#print) function with the provided `item`, a boolean value `true` for formatting, and a pointer to `global_hooks` for memory management.
    - The [`print`](#print) function handles the actual conversion of the `cJSON` object to a string, managing memory allocation and formatting.
- **Output**: Returns a pointer to a dynamically allocated string containing the JSON representation of the `cJSON` object, or NULL if an error occurs.
- **Functions called**:
    - [`print`](#print)


---
### cJSON\_PrintUnformatted<!-- {{#callable:cJSON_PrintUnformatted}} -->
The `cJSON_PrintUnformatted` function serializes a `cJSON` object into a JSON string without formatting.
- **Inputs**:
    - `item`: A pointer to a `cJSON` object that needs to be serialized.
- **Control Flow**:
    - The function calls the [`print`](#print) function with the `item`, a formatting flag set to false, and a pointer to global memory allocation hooks.
    - The [`print`](#print) function handles the serialization of the `cJSON` object into a string representation.
- **Output**: Returns a pointer to a string containing the serialized JSON representation of the `cJSON` object, or NULL if an error occurs.
- **Functions called**:
    - [`print`](#print)


---
### cJSON\_PrintBuffered<!-- {{#callable:cJSON_PrintBuffered}} -->
The `cJSON_PrintBuffered` function generates a JSON string representation of a `cJSON` item using a pre-allocated buffer.
- **Inputs**:
    - `item`: A pointer to the `cJSON` item that needs to be converted to a JSON string.
    - `prebuffer`: An integer specifying the size of the pre-allocated buffer to be used for the output string.
    - `fmt`: A boolean value indicating whether the output should be formatted (pretty-printed) or not.
- **Control Flow**:
    - The function first checks if the `prebuffer` is negative; if so, it returns NULL.
    - It allocates a buffer of size `prebuffer` using the global memory allocation hooks.
    - If the buffer allocation fails, it returns NULL.
    - The function initializes the `printbuffer` structure with the allocated buffer and other parameters.
    - It calls the [`print_value`](#print_value) function to generate the JSON string representation of the `item` into the buffer.
    - If [`print_value`](#print_value) fails, it deallocates the buffer and returns NULL.
    - Finally, it returns the pointer to the buffer containing the JSON string.
- **Output**: Returns a pointer to the generated JSON string if successful, or NULL if an error occurs.
- **Functions called**:
    - [`print_value`](#print_value)


---
### cJSON\_PrintPreallocated<!-- {{#callable:cJSON_PrintPreallocated}} -->
The `cJSON_PrintPreallocated` function formats a `cJSON` object into a preallocated buffer.
- **Inputs**:
    - `item`: A pointer to the `cJSON` object that needs to be printed.
    - `buffer`: A pointer to a preallocated character buffer where the formatted JSON string will be stored.
    - `length`: An integer representing the size of the preallocated buffer.
    - `format`: A boolean indicating whether the output should be formatted (pretty-printed) or not.
- **Control Flow**:
    - The function first initializes a `printbuffer` structure to hold the output buffer details.
    - It checks if the provided length is negative or if the buffer is NULL, returning false if either condition is met.
    - The function sets up the `printbuffer` with the provided buffer, its length, and formatting options.
    - Finally, it calls the [`print_value`](#print_value) function to perform the actual printing of the `cJSON` object into the buffer.
- **Output**: Returns a boolean value indicating success (true) or failure (false) of the printing operation.
- **Functions called**:
    - [`print_value`](#print_value)


---
### parse\_value<!-- {{#callable:parse_value}} -->
Parses a JSON value from the input buffer and populates the provided `cJSON` item.
- **Inputs**:
    - `item`: A pointer to a `cJSON` structure where the parsed value will be stored.
    - `input_buffer`: A pointer to a `parse_buffer` structure containing the JSON input to be parsed.
- **Control Flow**:
    - Checks if the `input_buffer` or its content is NULL, returning false if so.
    - Attempts to parse the string 'null' and updates the `item` type to `cJSON_NULL` if successful.
    - Attempts to parse the string 'false' and updates the `item` type to `cJSON_False` if successful.
    - Attempts to parse the string 'true' and updates the `item` type to `cJSON_True` if successful.
    - Checks if the first character is a double quote, indicating a string, and calls [`parse_string`](#parse_string) if so.
    - Checks if the first character is a digit or a minus sign, indicating a number, and calls [`parse_number`](#parse_number) if so.
    - Checks if the first character is a square bracket, indicating an array, and calls [`parse_array`](#parse_array) if so.
    - Checks if the first character is a curly brace, indicating an object, and calls [`parse_object`](#parse_object) if so.
    - Returns false if none of the above conditions are met.
- **Output**: Returns true if a value was successfully parsed and stored in the `item`, otherwise returns false.
- **Functions called**:
    - [`parse_string`](#parse_string)
    - [`parse_number`](#parse_number)
    - [`parse_array`](#parse_array)
    - [`parse_object`](#parse_object)


---
### print\_value<!-- {{#callable:print_value}} -->
The `print_value` function serializes a `cJSON` item into a string representation and writes it to a specified output buffer.
- **Inputs**:
    - `item`: A pointer to a `cJSON` structure representing the JSON item to be printed.
    - `output_buffer`: A pointer to a `printbuffer` structure that holds the output buffer where the serialized string will be written.
- **Control Flow**:
    - The function first checks if either `item` or `output_buffer` is NULL, returning false if so.
    - It then uses a switch statement to determine the type of the `cJSON` item.
    - For `cJSON_NULL`, `cJSON_False`, and `cJSON_True`, it allocates space in the output buffer and copies the corresponding string representation.
    - For `cJSON_Number`, it calls the [`print_number`](#print_number) function to handle the serialization.
    - For `cJSON_Raw`, it checks if the `valuestring` is NULL, allocates space, and copies the raw string.
    - For `cJSON_String`, `cJSON_Array`, and `cJSON_Object`, it calls their respective print functions to handle serialization.
    - If the item type does not match any known types, it returns false.
- **Output**: The function returns true if the serialization is successful, otherwise it returns false.
- **Functions called**:
    - [`ensure`](#ensure)
    - [`print_number`](#print_number)
    - [`print_string`](#print_string)
    - [`print_array`](#print_array)
    - [`print_object`](#print_object)


---
### parse\_array<!-- {{#callable:parse_array}} -->
Parses a JSON array from the input buffer and populates a `cJSON` item.
- **Inputs**:
    - `item`: A pointer to a `cJSON` structure where the parsed array will be stored.
    - `input_buffer`: A pointer to a `parse_buffer` structure that contains the JSON input data and its parsing state.
- **Control Flow**:
    - Checks if the current depth of parsing exceeds the nesting limit, returning false if it does.
    - Increments the depth of the input buffer.
    - Validates that the first character in the buffer is a '[' indicating the start of an array.
    - Skips whitespace and checks for an empty array case (i.e., '[]').
    - Enters a loop to parse each element of the array, allocating new `cJSON` items and linking them in a list.
    - After parsing each value, it checks for commas to continue parsing additional elements.
    - Finally, it checks for the closing bracket ']' to ensure the array is properly terminated.
- **Output**: Returns true if the array was successfully parsed and populated; otherwise, it returns false and cleans up any allocated items.
- **Functions called**:
    - [`buffer_skip_whitespace`](#buffer_skip_whitespace)
    - [`cJSON_New_Item`](#cJSON_New_Item)
    - [`parse_value`](#parse_value)
    - [`cJSON_Delete`](#cJSON_Delete)


---
### print\_array<!-- {{#callable:print_array}} -->
The `print_array` function renders a JSON array to a specified output buffer.
- **Inputs**:
    - `item`: A pointer to a `cJSON` structure representing the array to be printed.
    - `output_buffer`: A pointer to a `printbuffer` structure where the rendered output will be stored.
- **Control Flow**:
    - The function first checks if the `output_buffer` is NULL and returns false if it is.
    - It ensures space for the opening square bracket '[' in the output buffer.
    - It iterates through each element of the array, calling [`print_value`](#print_value) to render each element into the output buffer.
    - After each element, if there is a next element, it adds a comma and possibly a space based on the formatting option.
    - Finally, it ensures space for the closing square bracket ']' and updates the output buffer accordingly.
- **Output**: Returns true if the array was successfully printed; otherwise, it returns false.
- **Functions called**:
    - [`ensure`](#ensure)
    - [`print_value`](#print_value)
    - [`update_offset`](#update_offset)


---
### parse\_object<!-- {{#callable:parse_object}} -->
Parses a JSON object from the input buffer and populates the provided cJSON item.
- **Inputs**:
    - `item`: A pointer to a `cJSON` structure where the parsed object will be stored.
    - `input_buffer`: A pointer to a `parse_buffer` structure containing the JSON input data and its current parsing state.
- **Control Flow**:
    - Checks if the current depth of parsing exceeds the nesting limit, returning false if it does.
    - Increments the depth of the input buffer to track the current nesting level.
    - Validates that the first character in the buffer is '{', indicating the start of an object.
    - Handles the case of an empty object by checking if the next character is '}'.
    - Enters a loop to parse key-value pairs, allocating new `cJSON` items for each pair.
    - Parses the key as a string and checks for a colon ':' to separate the key from the value.
    - Parses the value associated with the key and continues until all pairs are processed.
    - Checks for the closing brace '}' to ensure the object is properly terminated.
    - On success, sets the type of the item to `cJSON_Object` and links the parsed items.
- **Output**: Returns true if the object was successfully parsed; otherwise, it returns false and cleans up any allocated memory.
- **Functions called**:
    - [`buffer_skip_whitespace`](#buffer_skip_whitespace)
    - [`cJSON_New_Item`](#cJSON_New_Item)
    - [`parse_string`](#parse_string)
    - [`parse_value`](#parse_value)
    - [`cJSON_Delete`](#cJSON_Delete)


---
### print\_object<!-- {{#callable:print_object}} -->
The `print_object` function formats and outputs a JSON object as a string.
- **Inputs**:
    - `item`: A pointer to a `cJSON` object that represents the JSON object to be printed.
    - `output_buffer`: A pointer to a `printbuffer` structure that holds the output string and its properties.
- **Control Flow**:
    - The function first checks if the `output_buffer` is NULL and returns false if it is.
    - It initializes the output by allocating space for the opening brace '{' and possibly a newline character based on formatting.
    - The function then iterates over each child item of the JSON object.
    - For each child, it prints the key and value, ensuring proper formatting and indentation if specified.
    - After printing all key-value pairs, it appends the closing brace '}' to the output.
- **Output**: Returns true if the object was printed successfully, otherwise returns false.
- **Functions called**:
    - [`ensure`](#ensure)
    - [`print_string_ptr`](#print_string_ptr)
    - [`update_offset`](#update_offset)
    - [`print_value`](#print_value)


---
### cJSON\_GetArraySize<!-- {{#callable:cJSON_GetArraySize}} -->
Returns the number of elements in a `cJSON` array.
- **Inputs**:
    - `array`: A pointer to a `cJSON` object representing an array whose size is to be determined.
- **Control Flow**:
    - Checks if the `array` pointer is NULL; if so, returns 0.
    - Initializes a `child` pointer to the first child of the array.
    - Iterates through the linked list of child elements, incrementing a `size` counter for each child until there are no more children.
    - Returns the total count of children as an integer.
- **Output**: An integer representing the number of elements in the array, or 0 if the array is NULL.


---
### get\_array\_item<!-- {{#callable:get_array_item}} -->
Retrieves an item from a `cJSON` array at a specified index.
- **Inputs**:
    - `array`: A pointer to a `cJSON` object representing the array from which to retrieve the item.
    - `index`: The zero-based index of the item to retrieve from the array.
- **Control Flow**:
    - Check if the `array` pointer is NULL; if it is, return NULL.
    - Initialize `current_child` to the first child of the `array`.
    - Iterate through the linked list of children, decrementing `index` until it reaches zero or `current_child` becomes NULL.
    - Return the `current_child` pointer, which will be the item at the specified index or NULL if the index is out of bounds.
- **Output**: Returns a pointer to the `cJSON` item at the specified index, or NULL if the index is out of bounds or the array is NULL.


---
### cJSON\_GetArrayItem<!-- {{#callable:cJSON_GetArrayItem}} -->
Retrieves an item from a JSON array at a specified index.
- **Inputs**:
    - `array`: A pointer to a `cJSON` object representing the JSON array from which to retrieve the item.
    - `index`: An integer representing the index of the item to retrieve from the array.
- **Control Flow**:
    - Checks if the provided `index` is less than 0; if so, returns NULL.
    - Calls the [`get_array_item`](#get_array_item) function with the `array` and the `index` cast to a size_t to retrieve the item.
- **Output**: Returns a pointer to the `cJSON` item at the specified index in the array, or NULL if the index is invalid.
- **Functions called**:
    - [`get_array_item`](#get_array_item)


---
### get\_object\_item<!-- {{#callable:get_object_item}} -->
The `get_object_item` function retrieves an item from a JSON object by its name, with an option for case sensitivity.
- **Inputs**:
    - `object`: A pointer to a `cJSON` object from which the item is to be retrieved.
    - `name`: A string representing the name of the item to retrieve.
    - `case_sensitive`: A boolean indicating whether the name comparison should be case sensitive.
- **Control Flow**:
    - The function first checks if either the `object` or `name` is NULL, returning NULL if so.
    - It initializes a pointer `current_element` to the first child of the `object`.
    - If `case_sensitive` is true, it iterates through the children of the object, comparing the `name` with each child's string using `strcmp`.
    - If `case_sensitive` is false, it uses a custom case-insensitive comparison function [`case_insensitive_strcmp`](#case_insensitive_strcmp) for the same iteration.
    - If a matching child is found, it is returned; otherwise, NULL is returned.
- **Output**: The function returns a pointer to the `cJSON` item that matches the specified name, or NULL if no match is found or if the input parameters are invalid.
- **Functions called**:
    - [`case_insensitive_strcmp`](#case_insensitive_strcmp)


---
### cJSON\_GetObjectItem<!-- {{#callable:cJSON_GetObjectItem}} -->
Retrieves an item from a JSON object by its key.
- **Inputs**:
    - `object`: A pointer to a `cJSON` object from which the item is to be retrieved.
    - `string`: A pointer to a string representing the key of the item to retrieve.
- **Control Flow**:
    - The function calls [`get_object_item`](#get_object_item) with the provided `object`, `string`, and a case sensitivity flag set to false.
    - The [`get_object_item`](#get_object_item) function iterates through the children of the `object` to find a matching key.
    - If a matching key is found, the corresponding `cJSON` item is returned; otherwise, NULL is returned.
- **Output**: Returns a pointer to the `cJSON` item associated with the specified key, or NULL if the key does not exist.
- **Functions called**:
    - [`get_object_item`](#get_object_item)


---
### cJSON\_GetObjectItemCaseSensitive<!-- {{#callable:cJSON_GetObjectItemCaseSensitive}} -->
Retrieves a cJSON object item by its name in a case-sensitive manner.
- **Inputs**:
    - `object`: A pointer to a `cJSON` object from which the item is to be retrieved.
    - `string`: A pointer to a string representing the name of the item to retrieve.
- **Control Flow**:
    - The function calls [`get_object_item`](#get_object_item) with the provided `object`, `string`, and a boolean value `true` to indicate case sensitivity.
    - The [`get_object_item`](#get_object_item) function iterates through the children of the `object`, comparing each child's string name to the provided `string` using case-sensitive comparison.
- **Output**: Returns a pointer to the `cJSON` item if found; otherwise, returns NULL.
- **Functions called**:
    - [`get_object_item`](#get_object_item)


---
### cJSON\_HasObjectItem<!-- {{#callable:cJSON_HasObjectItem}} -->
The `cJSON_HasObjectItem` function checks if a specified item exists in a JSON object.
- **Inputs**:
    - `object`: A pointer to a `cJSON` object that represents the JSON object to be checked.
    - `string`: A pointer to a string that represents the key of the item to check for in the JSON object.
- **Control Flow**:
    - The function calls [`cJSON_GetObjectItem`](#cJSON_GetObjectItem) with the provided `object` and `string` to attempt to retrieve the item associated with the key.
    - If [`cJSON_GetObjectItem`](#cJSON_GetObjectItem) returns a non-null pointer, the function returns 1 (true), indicating the item exists.
    - If [`cJSON_GetObjectItem`](#cJSON_GetObjectItem) returns null, the function returns 0 (false), indicating the item does not exist.
- **Output**: The function returns a boolean value (1 for true, 0 for false) indicating whether the specified item exists in the JSON object.
- **Functions called**:
    - [`cJSON_GetObjectItem`](#cJSON_GetObjectItem)


---
### suffix\_object<!-- {{#callable:suffix_object}} -->
The `suffix_object` function links two `cJSON` objects in a doubly linked list.
- **Inputs**:
    - `prev`: A pointer to the previous `cJSON` object that will be linked to the next object.
    - `item`: A pointer to the `cJSON` object that will be linked as the next item in the list.
- **Control Flow**:
    - The function sets the `next` pointer of the `prev` object to point to the `item` object.
    - It then sets the `prev` pointer of the `item` object to point back to the `prev` object.
- **Output**: The function does not return a value; it modifies the linked list structure of the `cJSON` objects directly.


---
### create\_reference<!-- {{#callable:create_reference}} -->
Creates a reference to a given `cJSON` item.
- **Inputs**:
    - `item`: A pointer to the `cJSON` item to be referenced.
    - `hooks`: A pointer to `internal_hooks` structure used for memory management.
- **Control Flow**:
    - Check if the `item` is NULL; if so, return NULL.
    - Allocate a new `cJSON` item using [`cJSON_New_Item`](#cJSON_New_Item).
    - If allocation fails, return NULL.
    - Copy the contents of the `item` into the new reference using `memcpy`.
    - Set the `string` field of the new reference to NULL.
    - Set the `type` field to indicate that this is a reference.
    - Set the `next` and `prev` pointers of the new reference to NULL.
    - Return the newly created reference.
- **Output**: Returns a pointer to the newly created reference `cJSON` item, or NULL if the input item is NULL or memory allocation fails.
- **Functions called**:
    - [`cJSON_New_Item`](#cJSON_New_Item)


---
### add\_item\_to\_array<!-- {{#callable:add_item_to_array}} -->
Adds an item to a `cJSON` array.
- **Inputs**:
    - `array`: A pointer to the `cJSON` array to which the item will be added.
    - `item`: A pointer to the `cJSON` item that is to be added to the array.
- **Control Flow**:
    - The function first checks if the `item` or `array` is NULL, or if the `item` is the same as the `array`, returning false if any of these conditions are true.
    - If the array is empty (i.e., it has no children), the `item` is set as the first child of the array, with its `prev` pointer pointing to itself.
    - If the array is not empty, the function appends the `item` to the end of the array by linking it to the last child using the `prev` pointer.
- **Output**: Returns true if the item was successfully added to the array; otherwise, returns false.
- **Functions called**:
    - [`suffix_object`](#suffix_object)


---
### cJSON\_AddItemToArray<!-- {{#callable:cJSON_AddItemToArray}} -->
Adds an item to a cJSON array.
- **Inputs**:
    - `array`: A pointer to the `cJSON` array to which the item will be added.
    - `item`: A pointer to the `cJSON` item that will be added to the array.
- **Control Flow**:
    - The function calls [`add_item_to_array`](#add_item_to_array) with the provided `array` and `item`.
    - The [`add_item_to_array`](#add_item_to_array) function handles the logic of adding the item to the array.
- **Output**: Returns a boolean value indicating whether the item was successfully added to the array.
- **Functions called**:
    - [`add_item_to_array`](#add_item_to_array)


---
### cast\_away\_const<!-- {{#callable:cast_away_const}} -->
The `cast_away_const` function casts a pointer from a constant type to a non-constant type.
- **Inputs**:
    - `string`: A pointer to a constant void type that is to be cast away from its const qualifier.
- **Control Flow**:
    - The function takes a single input parameter of type `const void*`.
    - It directly casts the input pointer to a `void*` type without any checks or modifications.
    - The casted pointer is then returned as the output.
- **Output**: The function returns a pointer of type `void*`, which is the same memory address as the input but without the const qualifier.


---
### add\_item\_to\_object<!-- {{#callable:add_item_to_object}} -->
Adds an item to a JSON object with a specified key.
- **Inputs**:
    - `object`: A pointer to the `cJSON` object where the item will be added.
    - `string`: A constant character pointer representing the key under which the item will be stored.
    - `item`: A pointer to the `cJSON` item that is to be added to the object.
    - `hooks`: A pointer to `internal_hooks` structure for memory management.
    - `constant_key`: A boolean indicating whether the key is constant.
- **Control Flow**:
    - The function first checks if any of the input parameters are NULL or if the object is the same as the item, returning false if so.
    - If `constant_key` is true, it casts away the constness of the string and sets the item type to include the `cJSON_StringIsConst` flag.
    - If `constant_key` is false, it duplicates the string and checks for allocation failure, returning false if the duplication fails.
    - If the item is not constant and has an existing string, it deallocates the old string.
    - The new key and type are assigned to the item, and finally, the item is added to the object using [`add_item_to_array`](#add_item_to_array).
- **Output**: Returns true if the item was successfully added to the object; otherwise, returns false.
- **Functions called**:
    - [`cast_away_const`](#cast_away_const)
    - [`cJSON_strdup`](#cJSON_strdup)
    - [`add_item_to_array`](#add_item_to_array)


---
### cJSON\_AddItemToObject<!-- {{#callable:cJSON_AddItemToObject}} -->
Adds an item to a JSON object with a specified key.
- **Inputs**:
    - `object`: A pointer to the `cJSON` object to which the item will be added.
    - `string`: A string representing the key under which the item will be stored.
    - `item`: A pointer to the `cJSON` item that will be added to the object.
- **Control Flow**:
    - The function first checks if the `object`, `string`, or `item` is NULL; if any are, it returns false.
    - It then calls the [`add_item_to_object`](#add_item_to_object) function, passing the `object`, `string`, `item`, global memory hooks, and a boolean indicating that the key is not constant.
    - The [`add_item_to_object`](#add_item_to_object) function handles the actual addition of the item to the object.
- **Output**: Returns true if the item was successfully added to the object; otherwise, it returns false.
- **Functions called**:
    - [`add_item_to_object`](#add_item_to_object)


---
### cJSON\_AddItemToObjectCS<!-- {{#callable:cJSON_AddItemToObjectCS}} -->
Adds an item to a cJSON object with a constant string key.
- **Inputs**:
    - `object`: A pointer to the `cJSON` object to which the item will be added.
    - `string`: A constant string key for the item being added.
    - `item`: A pointer to the `cJSON` item that is to be added to the object.
- **Control Flow**:
    - Checks if the `object`, `string`, or `item` is NULL; if so, returns false.
    - Calls [`add_item_to_object`](#add_item_to_object) with the provided parameters and a flag indicating that the key is constant.
    - The [`add_item_to_object`](#add_item_to_object) function handles the actual addition of the item to the object.
- **Output**: Returns true if the item was successfully added, otherwise returns false.
- **Functions called**:
    - [`add_item_to_object`](#add_item_to_object)


---
### cJSON\_AddItemReferenceToArray<!-- {{#callable:cJSON_AddItemReferenceToArray}} -->
Adds a reference to an existing `cJSON` item into a specified `cJSON` array.
- **Inputs**:
    - `array`: A pointer to a `cJSON` array where the item reference will be added.
    - `item`: A pointer to the `cJSON` item that is to be referenced and added to the array.
- **Control Flow**:
    - The function first checks if the `array` pointer is NULL; if it is, the function returns false.
    - If the `array` is valid, it calls the [`create_reference`](#create_reference) function to create a reference to the `item`.
    - Then, it calls the [`add_item_to_array`](#add_item_to_array) function to add the created reference to the specified `array`.
- **Output**: Returns true if the item reference was successfully added to the array; otherwise, returns false.
- **Functions called**:
    - [`add_item_to_array`](#add_item_to_array)
    - [`create_reference`](#create_reference)


---
### cJSON\_AddItemReferenceToObject<!-- {{#callable:cJSON_AddItemReferenceToObject}} -->
Adds a reference to a `cJSON` item in a `cJSON` object using a specified string key.
- **Inputs**:
    - `object`: A pointer to the `cJSON` object where the item will be added.
    - `string`: A string key that will be used to reference the item in the object.
    - `item`: A pointer to the `cJSON` item that is to be added as a reference.
- **Control Flow**:
    - Check if the `object` or `string` is NULL; if so, return false.
    - Call [`add_item_to_object`](#add_item_to_object) with the `object`, `string`, and a reference created from `item` using [`create_reference`](#create_reference).
- **Output**: Returns true if the item was successfully added to the object; otherwise, returns false.
- **Functions called**:
    - [`add_item_to_object`](#add_item_to_object)
    - [`create_reference`](#create_reference)


---
### cJSON\_AddNullToObject<!-- {{#callable:cJSON_AddNullToObject}} -->
Adds a null value to a specified key in a cJSON object.
- **Inputs**:
    - `object`: A pointer to the `cJSON` object to which the null value will be added.
    - `name`: A string representing the key under which the null value will be stored.
- **Control Flow**:
    - Creates a new `cJSON` null item using `cJSON_CreateNull()`.
    - Attempts to add the null item to the specified object using `add_item_to_object()`.
    - If the addition is successful, returns the created null item.
    - If the addition fails, deletes the null item and returns NULL.
- **Output**: Returns a pointer to the newly created null item if successful, or NULL if the addition failed.
- **Functions called**:
    - [`cJSON_CreateNull`](#cJSON_CreateNull)
    - [`add_item_to_object`](#add_item_to_object)
    - [`cJSON_Delete`](#cJSON_Delete)


---
### cJSON\_AddTrueToObject<!-- {{#callable:cJSON_AddTrueToObject}} -->
Adds a `true` value to a specified key in a `cJSON` object.
- **Inputs**:
    - `object`: A pointer to the `cJSON` object to which the `true` value will be added.
    - `name`: A string representing the key under which the `true` value will be stored.
- **Control Flow**:
    - Creates a new `cJSON` item representing the boolean value `true` using `cJSON_CreateTrue()`.
    - Attempts to add the created `true` item to the specified `object` using the `add_item_to_object()` function.
    - If the addition is successful, the function returns the created `true` item.
    - If the addition fails, the created item is deleted using `cJSON_Delete()`, and the function returns `NULL`.
- **Output**: Returns a pointer to the newly created `true` item if added successfully, or `NULL` if the addition fails.
- **Functions called**:
    - [`cJSON_CreateTrue`](#cJSON_CreateTrue)
    - [`add_item_to_object`](#add_item_to_object)
    - [`cJSON_Delete`](#cJSON_Delete)


---
### cJSON\_AddFalseToObject<!-- {{#callable:cJSON_AddFalseToObject}} -->
Adds a `false` value to a specified key in a `cJSON` object.
- **Inputs**:
    - `object`: A pointer to the `cJSON` object to which the `false` value will be added.
    - `name`: A string representing the key under which the `false` value will be stored.
- **Control Flow**:
    - Creates a new `cJSON` item representing the `false` value using `cJSON_CreateFalse()`.
    - Attempts to add the `false` item to the specified `object` using the `add_item_to_object()` function.
    - If the addition is successful, returns the pointer to the newly created `false` item.
    - If the addition fails, deletes the `false` item and returns `NULL`.
- **Output**: Returns a pointer to the `cJSON` item representing `false` if added successfully, otherwise returns `NULL`.
- **Functions called**:
    - [`cJSON_CreateFalse`](#cJSON_CreateFalse)
    - [`add_item_to_object`](#add_item_to_object)
    - [`cJSON_Delete`](#cJSON_Delete)


---
### cJSON\_AddBoolToObject<!-- {{#callable:cJSON_AddBoolToObject}} -->
Adds a boolean value to a cJSON object.
- **Inputs**:
    - `object`: A pointer to the `cJSON` object to which the boolean will be added.
    - `name`: A string representing the key under which the boolean value will be stored.
    - `boolean`: The boolean value to be added to the object.
- **Control Flow**:
    - Creates a new `cJSON` item representing the boolean value using `cJSON_CreateBool(boolean)`.
    - Attempts to add the newly created boolean item to the specified object using `add_item_to_object()`.
    - If the addition is successful, returns the created boolean item.
    - If the addition fails, deletes the created boolean item and returns NULL.
- **Output**: Returns a pointer to the newly created boolean item if added successfully, otherwise returns NULL.
- **Functions called**:
    - [`cJSON_CreateBool`](#cJSON_CreateBool)
    - [`add_item_to_object`](#add_item_to_object)
    - [`cJSON_Delete`](#cJSON_Delete)


---
### cJSON\_AddNumberToObject<!-- {{#callable:cJSON_AddNumberToObject}} -->
Adds a number to a cJSON object with a specified name.
- **Inputs**:
    - `object`: A pointer to the `cJSON` object to which the number will be added.
    - `name`: A string representing the name (key) under which the number will be stored in the object.
    - `number`: The double value that will be added to the object.
- **Control Flow**:
    - Creates a new `cJSON` item representing the number using [`cJSON_CreateNumber`](#cJSON_CreateNumber).
    - Attempts to add the newly created number item to the specified object using [`add_item_to_object`](#add_item_to_object).
    - If the addition is successful, returns the created number item.
    - If the addition fails, deletes the created number item and returns NULL.
- **Output**: Returns a pointer to the created `cJSON` number item if successful, or NULL if the addition fails.
- **Functions called**:
    - [`cJSON_CreateNumber`](#cJSON_CreateNumber)
    - [`add_item_to_object`](#add_item_to_object)
    - [`cJSON_Delete`](#cJSON_Delete)


---
### cJSON\_AddStringToObject<!-- {{#callable:cJSON_AddStringToObject}} -->
Adds a string to a cJSON object.
- **Inputs**:
    - `object`: A pointer to the `cJSON` object to which the string will be added.
    - `name`: A constant character pointer representing the name (key) for the string in the object.
    - `string`: A constant character pointer representing the string value to be added.
- **Control Flow**:
    - Creates a new `cJSON` string item using [`cJSON_CreateString`](#cJSON_CreateString) with the provided string.
    - Attempts to add the created string item to the specified object using [`add_item_to_object`](#add_item_to_object).
    - If the addition is successful, returns the created string item.
    - If the addition fails, deletes the created string item and returns NULL.
- **Output**: Returns a pointer to the created string item if successful, or NULL if the addition fails.
- **Functions called**:
    - [`cJSON_CreateString`](#cJSON_CreateString)
    - [`add_item_to_object`](#add_item_to_object)
    - [`cJSON_Delete`](#cJSON_Delete)


---
### cJSON\_AddRawToObject<!-- {{#callable:cJSON_AddRawToObject}} -->
Adds a raw JSON string to a cJSON object.
- **Inputs**:
    - `object`: A pointer to the `cJSON` object to which the raw string will be added.
    - `name`: The key under which the raw string will be stored in the object.
    - `raw`: The raw JSON string to be added to the object.
- **Control Flow**:
    - Creates a new `cJSON` item from the raw string using [`cJSON_CreateRaw`](#cJSON_CreateRaw).
    - Attempts to add the created raw item to the specified object using [`add_item_to_object`](#add_item_to_object).
    - If the addition is successful, returns the created raw item.
    - If the addition fails, deletes the created raw item and returns NULL.
- **Output**: Returns a pointer to the created `cJSON` item if successful, or NULL if the addition fails.
- **Functions called**:
    - [`cJSON_CreateRaw`](#cJSON_CreateRaw)
    - [`add_item_to_object`](#add_item_to_object)
    - [`cJSON_Delete`](#cJSON_Delete)


---
### cJSON\_AddObjectToObject<!-- {{#callable:cJSON_AddObjectToObject}} -->
Adds a new object to an existing JSON object.
- **Inputs**:
    - `object`: A pointer to the `cJSON` object to which the new object will be added.
    - `name`: A string representing the name (key) for the new object being added.
- **Control Flow**:
    - Creates a new `cJSON` object using `cJSON_CreateObject()`.
    - Attempts to add the newly created object to the specified parent object using `add_item_to_object()`.
    - If the addition is successful, returns the newly created object.
    - If the addition fails, deletes the newly created object and returns NULL.
- **Output**: Returns a pointer to the newly added `cJSON` object if successful, or NULL if the addition fails.
- **Functions called**:
    - [`cJSON_CreateObject`](#cJSON_CreateObject)
    - [`add_item_to_object`](#add_item_to_object)
    - [`cJSON_Delete`](#cJSON_Delete)


---
### cJSON\_AddArrayToObject<!-- {{#callable:cJSON_AddArrayToObject}} -->
Adds a new array to a JSON object with a specified name.
- **Inputs**:
    - `object`: A pointer to the `cJSON` object to which the new array will be added.
    - `name`: A string representing the name under which the new array will be stored in the object.
- **Control Flow**:
    - Creates a new array using `cJSON_CreateArray()`.
    - Attempts to add the newly created array to the specified object using `add_item_to_object()`.
    - If the addition is successful, returns a pointer to the newly created array.
    - If the addition fails, deletes the created array and returns NULL.
- **Output**: Returns a pointer to the newly created array if successful, or NULL if the addition fails.
- **Functions called**:
    - [`cJSON_CreateArray`](#cJSON_CreateArray)
    - [`add_item_to_object`](#add_item_to_object)
    - [`cJSON_Delete`](#cJSON_Delete)


---
### cJSON\_DetachItemViaPointer<!-- {{#callable:cJSON_DetachItemViaPointer}} -->
Detaches a specified `cJSON` item from its parent, updating the linked list accordingly.
- **Inputs**:
    - `parent`: A pointer to the `cJSON` object that serves as the parent of the item to be detached.
    - `item`: A pointer to the `cJSON` item that needs to be detached from its parent.
- **Control Flow**:
    - Checks if either `parent` or `item` is NULL; if so, returns NULL.
    - If `item` is not the first child of `parent`, updates the `next` pointer of `item`'s previous sibling.
    - If `item` is not the last child, updates the `prev` pointer of `item`'s next sibling.
    - If `item` is the first child, updates `parent->child` to point to `item`'s next sibling.
    - If `item` is the last child, updates the `prev` pointer of the new last child.
    - Sets `item`'s `prev` and `next` pointers to NULL to detach it completely.
- **Output**: Returns the detached `cJSON` item, or NULL if the input was invalid.


---
### cJSON\_DetachItemFromArray<!-- {{#callable:cJSON_DetachItemFromArray}} -->
Detaches an item from a JSON array at a specified index.
- **Inputs**:
    - `array`: A pointer to the `cJSON` array from which an item will be detached.
    - `which`: An integer index specifying the position of the item to detach from the array.
- **Control Flow**:
    - Checks if the provided index `which` is less than 0; if so, returns NULL.
    - Calls [`get_array_item`](#get_array_item) to retrieve the item at the specified index.
    - Passes the retrieved item and the array to [`cJSON_DetachItemViaPointer`](#cJSON_DetachItemViaPointer) to perform the detachment.
- **Output**: Returns a pointer to the detached `cJSON` item, or NULL if the index was invalid.
- **Functions called**:
    - [`cJSON_DetachItemViaPointer`](#cJSON_DetachItemViaPointer)
    - [`get_array_item`](#get_array_item)


---
### cJSON\_DeleteItemFromArray<!-- {{#callable:cJSON_DeleteItemFromArray}} -->
Deletes an item from a `cJSON` array at a specified index.
- **Inputs**:
    - `array`: A pointer to the `cJSON` array from which an item will be deleted.
    - `which`: An integer index specifying the position of the item to be deleted.
- **Control Flow**:
    - Calls [`cJSON_DetachItemFromArray`](#cJSON_DetachItemFromArray) to detach the item at the specified index from the array.
    - Passes the detached item to [`cJSON_Delete`](#cJSON_Delete) to free its memory.
- **Output**: This function does not return a value; it modifies the array by removing the specified item.
- **Functions called**:
    - [`cJSON_Delete`](#cJSON_Delete)
    - [`cJSON_DetachItemFromArray`](#cJSON_DetachItemFromArray)


---
### cJSON\_DetachItemFromObject<!-- {{#callable:cJSON_DetachItemFromObject}} -->
Detaches an item from a JSON object based on the specified key.
- **Inputs**:
    - `object`: A pointer to the `cJSON` object from which an item is to be detached.
    - `string`: A string representing the key of the item to be detached from the object.
- **Control Flow**:
    - The function first retrieves the item to detach by calling [`cJSON_GetObjectItem`](#cJSON_GetObjectItem) with the provided `object` and `string`.
    - If the item is found, it calls [`cJSON_DetachItemViaPointer`](#cJSON_DetachItemViaPointer) to detach the item from the object.
    - The function returns the detached item or NULL if the item was not found.
- **Output**: Returns a pointer to the detached `cJSON` item, or NULL if the item with the specified key does not exist in the object.
- **Functions called**:
    - [`cJSON_GetObjectItem`](#cJSON_GetObjectItem)
    - [`cJSON_DetachItemViaPointer`](#cJSON_DetachItemViaPointer)


---
### cJSON\_DetachItemFromObjectCaseSensitive<!-- {{#callable:cJSON_DetachItemFromObjectCaseSensitive}} -->
Detaches an item from a JSON object using a case-sensitive key.
- **Inputs**:
    - `object`: A pointer to the `cJSON` object from which an item is to be detached.
    - `string`: A pointer to a string representing the key of the item to be detached.
- **Control Flow**:
    - Calls [`cJSON_GetObjectItemCaseSensitive`](#cJSON_GetObjectItemCaseSensitive) to retrieve the item associated with the provided key from the object.
    - If the item is found, it calls [`cJSON_DetachItemViaPointer`](#cJSON_DetachItemViaPointer) to detach the item from the object and return it.
- **Output**: Returns a pointer to the detached `cJSON` item if found; otherwise, returns NULL.
- **Functions called**:
    - [`cJSON_GetObjectItemCaseSensitive`](#cJSON_GetObjectItemCaseSensitive)
    - [`cJSON_DetachItemViaPointer`](#cJSON_DetachItemViaPointer)


---
### cJSON\_DeleteItemFromObject<!-- {{#callable:cJSON_DeleteItemFromObject}} -->
Deletes an item from a `cJSON` object based on the provided key.
- **Inputs**:
    - `object`: A pointer to the `cJSON` object from which the item will be deleted.
    - `string`: A pointer to a string representing the key of the item to be deleted.
- **Control Flow**:
    - The function calls [`cJSON_DetachItemFromObject`](#cJSON_DetachItemFromObject) to detach the item associated with the provided key from the object.
    - The detached item is then passed to [`cJSON_Delete`](#cJSON_Delete) to free its memory.
- **Output**: This function does not return a value; it performs the deletion operation directly on the provided `cJSON` object.
- **Functions called**:
    - [`cJSON_Delete`](#cJSON_Delete)
    - [`cJSON_DetachItemFromObject`](#cJSON_DetachItemFromObject)


---
### cJSON\_DeleteItemFromObjectCaseSensitive<!-- {{#callable:cJSON_DeleteItemFromObjectCaseSensitive}} -->
Deletes an item from a JSON object in a case-sensitive manner.
- **Inputs**:
    - `object`: A pointer to a `cJSON` object from which an item will be deleted.
    - `string`: A pointer to a string representing the key of the item to be deleted.
- **Control Flow**:
    - The function calls [`cJSON_DetachItemFromObjectCaseSensitive`](#cJSON_DetachItemFromObjectCaseSensitive) to detach the item associated with the provided key from the object.
    - The detached item is then passed to [`cJSON_Delete`](#cJSON_Delete) to free its memory.
- **Output**: This function does not return a value; it performs the deletion operation directly on the provided `cJSON` object.
- **Functions called**:
    - [`cJSON_Delete`](#cJSON_Delete)
    - [`cJSON_DetachItemFromObjectCaseSensitive`](#cJSON_DetachItemFromObjectCaseSensitive)


---
### cJSON\_InsertItemInArray<!-- {{#callable:cJSON_InsertItemInArray}} -->
Inserts a new item into a specified position in a cJSON array.
- **Inputs**:
    - `array`: A pointer to the `cJSON` array where the new item will be inserted.
    - `which`: An integer index specifying the position in the array to insert the new item.
    - `newitem`: A pointer to the `cJSON` item that will be inserted into the array.
- **Control Flow**:
    - Checks if the index `which` is negative; if so, returns false.
    - Retrieves the item currently at the specified index using [`get_array_item`](#get_array_item).
    - If the item at the specified index is NULL, it adds the new item to the end of the array using [`add_item_to_array`](#add_item_to_array).
    - If the item exists, it adjusts the pointers of the new item and the existing item to insert the new item before the existing one.
    - If the existing item is the first child of the array, it updates the array's child pointer to point to the new item.
- **Output**: Returns true if the insertion was successful; otherwise, returns false.
- **Functions called**:
    - [`get_array_item`](#get_array_item)
    - [`add_item_to_array`](#add_item_to_array)


---
### cJSON\_ReplaceItemViaPointer<!-- {{#callable:cJSON_ReplaceItemViaPointer}} -->
Replaces an item in a cJSON structure with a new item.
- **Inputs**:
    - `parent`: A pointer to the `cJSON` structure that contains the item to be replaced.
    - `item`: A pointer to the `cJSON` item that is to be replaced.
    - `replacement`: A pointer to the `cJSON` item that will replace the existing item.
- **Control Flow**:
    - The function first checks if any of the input pointers (`parent`, `item`, or `replacement`) are NULL, returning false if so.
    - If the `replacement` is the same as `item`, the function returns true immediately.
    - The `replacement` item's `next` and `prev` pointers are updated to link it into the list where `item` was.
    - If `item` is the first child of `parent`, the `parent`'s child pointer is updated to point to `replacement`.
    - If `item` is not the first child, the function updates the previous item's `next` pointer to point to `replacement`.
    - The function then deletes the `item` after unlinking it from the list.
- **Output**: Returns true if the replacement was successful, otherwise false.
- **Functions called**:
    - [`cJSON_Delete`](#cJSON_Delete)


---
### cJSON\_ReplaceItemInArray<!-- {{#callable:cJSON_ReplaceItemInArray}} -->
Replaces an item in a `cJSON` array at a specified index with a new item.
- **Inputs**:
    - `array`: A pointer to the `cJSON` array in which the item will be replaced.
    - `which`: An integer index specifying the position of the item to be replaced.
    - `newitem`: A pointer to the new `cJSON` item that will replace the existing item.
- **Control Flow**:
    - The function first checks if the index `which` is less than 0; if so, it returns false.
    - If the index is valid, it retrieves the item at the specified index using [`get_array_item`](#get_array_item).
    - It then calls [`cJSON_ReplaceItemViaPointer`](#cJSON_ReplaceItemViaPointer) to perform the replacement of the item in the array.
- **Output**: Returns true if the replacement was successful, otherwise returns false.
- **Functions called**:
    - [`cJSON_ReplaceItemViaPointer`](#cJSON_ReplaceItemViaPointer)
    - [`get_array_item`](#get_array_item)


---
### replace\_item\_in\_object<!-- {{#callable:replace_item_in_object}} -->
Replaces an item in a JSON object with a new item.
- **Inputs**:
    - `object`: A pointer to the `cJSON` object that contains the item to be replaced.
    - `string`: A string representing the key of the item to be replaced.
    - `replacement`: A pointer to the `cJSON` item that will replace the existing item.
    - `case_sensitive`: A boolean indicating whether the key comparison should be case sensitive.
- **Control Flow**:
    - Checks if the `replacement` or `string` is NULL; if so, returns false.
    - If the `replacement` item is not constant and has a string, it frees the existing string.
    - Duplicates the `string` into the `replacement` item.
    - If the duplication fails, returns false.
    - Clears the constant flag from the `replacement` type.
    - Calls [`cJSON_ReplaceItemViaPointer`](#cJSON_ReplaceItemViaPointer) to replace the item in the object.
- **Output**: Returns true if the item was successfully replaced; otherwise, returns false.
- **Functions called**:
    - [`cJSON_free`](#cJSON_free)
    - [`cJSON_strdup`](#cJSON_strdup)
    - [`cJSON_ReplaceItemViaPointer`](#cJSON_ReplaceItemViaPointer)
    - [`get_object_item`](#get_object_item)


---
### cJSON\_ReplaceItemInObject<!-- {{#callable:cJSON_ReplaceItemInObject}} -->
Replaces an existing item in a JSON object with a new item.
- **Inputs**:
    - `object`: A pointer to the `cJSON` object that contains the item to be replaced.
    - `string`: A string representing the key of the item to be replaced in the JSON object.
    - `newitem`: A pointer to the new `cJSON` item that will replace the existing item.
- **Control Flow**:
    - The function calls [`replace_item_in_object`](#replace_item_in_object), passing the `object`, `string`, `newitem`, and a boolean value `false` to indicate case insensitivity.
    - The [`replace_item_in_object`](#replace_item_in_object) function handles the logic of finding the item by the specified key and replacing it with the new item.
- **Output**: Returns a boolean value indicating whether the replacement was successful.
- **Functions called**:
    - [`replace_item_in_object`](#replace_item_in_object)


---
### cJSON\_ReplaceItemInObjectCaseSensitive<!-- {{#callable:cJSON_ReplaceItemInObjectCaseSensitive}} -->
Replaces an item in a JSON object with a new item, considering case sensitivity.
- **Inputs**:
    - `object`: A pointer to the `cJSON` object that contains the item to be replaced.
    - `string`: A string representing the key of the item to be replaced in the object.
    - `newitem`: A pointer to the new `cJSON` item that will replace the existing item.
- **Control Flow**:
    - The function first checks if the `replacement` item and the `string` key are not null.
    - It then duplicates the `string` key into the `replacement` item.
    - The function calls `cJSON_ReplaceItemViaPointer` to perform the actual replacement in the object, using the result of `get_object_item` to find the existing item.
    - The replacement is done in a case-sensitive manner.
- **Output**: Returns a boolean value indicating whether the replacement was successful.
- **Functions called**:
    - [`replace_item_in_object`](#replace_item_in_object)


---
### cJSON\_CreateNull<!-- {{#callable:cJSON_CreateNull}} -->
Creates a new `cJSON` item representing a null value.
- **Inputs**: None
- **Control Flow**:
    - Calls [`cJSON_New_Item`](#cJSON_New_Item) to allocate a new `cJSON` item.
    - If the item is successfully created, sets its type to `cJSON_NULL`.
- **Output**: Returns a pointer to the newly created `cJSON` item representing null, or NULL if the allocation fails.
- **Functions called**:
    - [`cJSON_New_Item`](#cJSON_New_Item)


---
### cJSON\_CreateTrue<!-- {{#callable:cJSON_CreateTrue}} -->
Creates a new `cJSON` item representing a JSON true value.
- **Inputs**: None
- **Control Flow**:
    - Calls [`cJSON_New_Item`](#cJSON_New_Item) to allocate and initialize a new `cJSON` item.
    - If the item is successfully created, sets its type to `cJSON_True`.
    - Returns the created item.
- **Output**: Returns a pointer to the newly created `cJSON` item representing true, or NULL if the allocation fails.
- **Functions called**:
    - [`cJSON_New_Item`](#cJSON_New_Item)


---
### cJSON\_CreateFalse<!-- {{#callable:cJSON_CreateFalse}} -->
Creates a new `cJSON` item representing a JSON false value.
- **Inputs**: None
- **Control Flow**:
    - Calls [`cJSON_New_Item`](#cJSON_New_Item) to allocate and initialize a new `cJSON` item.
    - If the item is successfully created, sets its type to `cJSON_False`.
    - Returns the created item.
- **Output**: Returns a pointer to the newly created `cJSON` item representing false, or NULL if the allocation fails.
- **Functions called**:
    - [`cJSON_New_Item`](#cJSON_New_Item)


---
### cJSON\_CreateBool<!-- {{#callable:cJSON_CreateBool}} -->
Creates a new `cJSON` item representing a boolean value.
- **Inputs**:
    - `boolean`: A `cJSON_bool` value indicating the boolean state to be represented (true or false).
- **Control Flow**:
    - Calls [`cJSON_New_Item`](#cJSON_New_Item) to allocate a new `cJSON` item.
    - If the item is successfully created, it sets the item's type to `cJSON_True` if the boolean is true, or `cJSON_False` if it is false.
    - Returns the created item.
- **Output**: Returns a pointer to the newly created `cJSON` item representing the boolean value, or NULL if the item could not be created.
- **Functions called**:
    - [`cJSON_New_Item`](#cJSON_New_Item)


---
### cJSON\_CreateNumber<!-- {{#callable:cJSON_CreateNumber}} -->
Creates a new `cJSON` number item from a given double value.
- **Inputs**:
    - `num`: A double value representing the number to be created.
- **Control Flow**:
    - Calls [`cJSON_New_Item`](#cJSON_New_Item) to allocate and initialize a new `cJSON` item.
    - If the item is successfully created, sets its type to `cJSON_Number`.
    - Assigns the double value to the `valuedouble` field of the item.
    - Checks for overflow conditions and assigns the integer value accordingly, using saturation for values exceeding `INT_MAX` or below `INT_MIN`.
    - Returns the created `cJSON` item.
- **Output**: Returns a pointer to the newly created `cJSON` item representing the number, or NULL if the item could not be created.
- **Functions called**:
    - [`cJSON_New_Item`](#cJSON_New_Item)


---
### cJSON\_CreateString<!-- {{#callable:cJSON_CreateString}} -->
Creates a new `cJSON` string item from a given C string.
- **Inputs**:
    - `string`: A pointer to a null-terminated C string that will be used as the value of the new `cJSON` string item.
- **Control Flow**:
    - Calls [`cJSON_New_Item`](#cJSON_New_Item) to allocate and initialize a new `cJSON` item.
    - If the item is successfully created, it sets the item's type to `cJSON_String`.
    - Uses [`cJSON_strdup`](#cJSON_strdup) to duplicate the input string and assigns it to the `valuestring` field of the item.
    - If string duplication fails, it deletes the item and returns NULL.
    - Finally, returns the created `cJSON` string item.
- **Output**: Returns a pointer to the newly created `cJSON` string item, or NULL if the creation or string duplication fails.
- **Functions called**:
    - [`cJSON_New_Item`](#cJSON_New_Item)
    - [`cJSON_strdup`](#cJSON_strdup)
    - [`cJSON_Delete`](#cJSON_Delete)


---
### cJSON\_CreateStringReference<!-- {{#callable:cJSON_CreateStringReference}} -->
Creates a cJSON object that references a string without copying it.
- **Inputs**:
    - `string`: A pointer to a constant character string that will be referenced by the created cJSON object.
- **Control Flow**:
    - Calls [`cJSON_New_Item`](#cJSON_New_Item) to allocate and initialize a new cJSON item.
    - If the item is successfully created, it sets the type of the item to `cJSON_String` combined with `cJSON_IsReference`.
    - The `valuestring` field of the item is set to point to the input string, casted to a non-const type.
- **Output**: Returns a pointer to the newly created cJSON object, or NULL if the allocation fails.
- **Functions called**:
    - [`cJSON_New_Item`](#cJSON_New_Item)
    - [`cast_away_const`](#cast_away_const)


---
### cJSON\_CreateObjectReference<!-- {{#callable:cJSON_CreateObjectReference}} -->
Creates a new `cJSON` object that references an existing `cJSON` object.
- **Inputs**:
    - `child`: A pointer to a constant `cJSON` object that will be referenced by the new object.
- **Control Flow**:
    - Calls [`cJSON_New_Item`](#cJSON_New_Item) to allocate a new `cJSON` item.
    - If the allocation is successful, sets the type of the new item to `cJSON_Object | cJSON_IsReference`.
    - Assigns the `child` parameter to the `child` field of the new item after casting away its const qualifier.
    - Returns the newly created item.
- **Output**: Returns a pointer to the newly created `cJSON` object that references the provided `child` object, or NULL if the allocation fails.
- **Functions called**:
    - [`cJSON_New_Item`](#cJSON_New_Item)
    - [`cast_away_const`](#cast_away_const)


---
### cJSON\_CreateArrayReference<!-- {{#callable:cJSON_CreateArrayReference}} -->
Creates a reference to an existing cJSON array.
- **Inputs**:
    - `child`: A pointer to a constant `cJSON` object that represents the array to be referenced.
- **Control Flow**:
    - Calls [`cJSON_New_Item`](#cJSON_New_Item) to allocate a new `cJSON` item.
    - If allocation is successful, sets the type of the item to `cJSON_Array` and marks it as a reference.
    - Assigns the `child` parameter to the `child` field of the new item after casting away its const qualifier.
    - Returns the newly created item.
- **Output**: Returns a pointer to the newly created `cJSON` item that references the provided array, or NULL if allocation fails.
- **Functions called**:
    - [`cJSON_New_Item`](#cJSON_New_Item)
    - [`cast_away_const`](#cast_away_const)


---
### cJSON\_CreateRaw<!-- {{#callable:cJSON_CreateRaw}} -->
Creates a new `cJSON` item of type `cJSON_Raw` from a raw string.
- **Inputs**:
    - `raw`: A pointer to a null-terminated string that represents the raw JSON data.
- **Control Flow**:
    - Calls [`cJSON_New_Item`](#cJSON_New_Item) to allocate and initialize a new `cJSON` item.
    - If the item is successfully created, sets its type to `cJSON_Raw`.
    - Uses [`cJSON_strdup`](#cJSON_strdup) to duplicate the input string and assign it to the `valuestring` field of the item.
    - If string duplication fails, deletes the item and returns NULL.
    - Finally, returns the created `cJSON` item.
- **Output**: Returns a pointer to the newly created `cJSON` item if successful, or NULL if an error occurs during creation or string duplication.
- **Functions called**:
    - [`cJSON_New_Item`](#cJSON_New_Item)
    - [`cJSON_strdup`](#cJSON_strdup)
    - [`cJSON_Delete`](#cJSON_Delete)


---
### cJSON\_CreateArray<!-- {{#callable:cJSON_CreateArray}} -->
Creates a new `cJSON` array object.
- **Inputs**: None
- **Control Flow**:
    - Calls [`cJSON_New_Item`](#cJSON_New_Item) to allocate and initialize a new `cJSON` item.
    - If the item is successfully created, sets its type to `cJSON_Array`.
    - Returns the newly created item.
- **Output**: Returns a pointer to the newly created `cJSON` array object, or NULL if the allocation fails.
- **Functions called**:
    - [`cJSON_New_Item`](#cJSON_New_Item)


---
### cJSON\_CreateObject<!-- {{#callable:cJSON_CreateObject}} -->
Creates a new `cJSON` object.
- **Inputs**: None
- **Control Flow**:
    - Calls [`cJSON_New_Item`](#cJSON_New_Item) to allocate and initialize a new `cJSON` item.
    - If the item is successfully created, it sets the item's type to `cJSON_Object`.
    - Returns the newly created item.
- **Output**: Returns a pointer to the newly created `cJSON` object, or NULL if memory allocation fails.
- **Functions called**:
    - [`cJSON_New_Item`](#cJSON_New_Item)


---
### cJSON\_CreateIntArray<!-- {{#callable:cJSON_CreateIntArray}} -->
Creates a `cJSON` array from a given array of integers.
- **Inputs**:
    - `numbers`: A pointer to an array of integers that will be converted into a JSON array.
    - `count`: The number of integers in the `numbers` array.
- **Control Flow**:
    - Checks if the `count` is negative or if `numbers` is NULL; if so, returns NULL.
    - Creates a new `cJSON` array using `cJSON_CreateArray()`.
    - Iterates over the `numbers` array up to `count`, creating a `cJSON` number for each integer.
    - If the first number is added, it sets it as the first child of the array; otherwise, it appends it to the previous number using `suffix_object()`.
    - If any number creation fails, it deletes the created array and returns NULL.
    - Finally, it returns the created `cJSON` array.
- **Output**: Returns a pointer to the newly created `cJSON` array containing the integers, or NULL if an error occurs.
- **Functions called**:
    - [`cJSON_CreateArray`](#cJSON_CreateArray)
    - [`cJSON_CreateNumber`](#cJSON_CreateNumber)
    - [`cJSON_Delete`](#cJSON_Delete)
    - [`suffix_object`](#suffix_object)


---
### cJSON\_CreateFloatArray<!-- {{#callable:cJSON_CreateFloatArray}} -->
Creates a `cJSON` array from an array of float numbers.
- **Inputs**:
    - `numbers`: A pointer to an array of `float` values that will be added to the JSON array.
    - `count`: An integer representing the number of elements in the `numbers` array.
- **Control Flow**:
    - Checks if `count` is negative or if `numbers` is NULL; if so, returns NULL.
    - Creates a new `cJSON` array using `cJSON_CreateArray()`.
    - Iterates over the `numbers` array up to `count` times.
    - For each float in `numbers`, creates a `cJSON` number using `cJSON_CreateNumber()`.
    - If the creation of a number fails, deletes the array and returns NULL.
    - Links the created numbers into the array structure.
    - Sets the previous pointer of the first child of the array to the last created number.
- **Output**: Returns a pointer to the newly created `cJSON` array containing the float numbers, or NULL if an error occurs.
- **Functions called**:
    - [`cJSON_CreateArray`](#cJSON_CreateArray)
    - [`cJSON_CreateNumber`](#cJSON_CreateNumber)
    - [`cJSON_Delete`](#cJSON_Delete)
    - [`suffix_object`](#suffix_object)


---
### cJSON\_CreateDoubleArray<!-- {{#callable:cJSON_CreateDoubleArray}} -->
Creates a `cJSON` array from an array of double values.
- **Inputs**:
    - `numbers`: A pointer to an array of double values that will be added to the JSON array.
    - `count`: An integer representing the number of elements in the `numbers` array.
- **Control Flow**:
    - Checks if `count` is negative or if `numbers` is NULL; if so, returns NULL.
    - Creates a new `cJSON` array using `cJSON_CreateArray()`.
    - Iterates over the `numbers` array up to `count` times, creating a `cJSON` number for each element.
    - If the creation of a number fails, deletes the array and returns NULL.
    - Links each newly created number to the previous one in the array.
    - Sets the `prev` pointer of the first child to the last number created.
    - Returns the populated `cJSON` array.
- **Output**: Returns a pointer to a `cJSON` array containing the double values, or NULL if an error occurs.
- **Functions called**:
    - [`cJSON_CreateArray`](#cJSON_CreateArray)
    - [`cJSON_CreateNumber`](#cJSON_CreateNumber)
    - [`cJSON_Delete`](#cJSON_Delete)
    - [`suffix_object`](#suffix_object)


---
### cJSON\_CreateStringArray<!-- {{#callable:cJSON_CreateStringArray}} -->
Creates a cJSON array from an array of strings.
- **Inputs**:
    - `strings`: A pointer to an array of string literals.
    - `count`: The number of strings in the array.
- **Control Flow**:
    - Checks if the count is negative or if the strings pointer is NULL, returning NULL if true.
    - Creates a new cJSON array using `cJSON_CreateArray()`.
    - Iterates over the input strings up to the specified count.
    - For each string, creates a new cJSON string item using `cJSON_CreateString()`.
    - If the creation of a string fails, deletes the previously created array and returns NULL.
    - Links the newly created string items into the array.
    - Sets the previous pointer of the first child to the last created string item.
    - Returns the populated cJSON array.
- **Output**: Returns a pointer to the newly created cJSON array containing the strings, or NULL if an error occurs.
- **Functions called**:
    - [`cJSON_CreateArray`](#cJSON_CreateArray)
    - [`cJSON_CreateString`](#cJSON_CreateString)
    - [`cJSON_Delete`](#cJSON_Delete)
    - [`suffix_object`](#suffix_object)


---
### cJSON\_Duplicate<!-- {{#callable:cJSON_Duplicate}} -->
Duplicates a `cJSON` item, optionally recursively.
- **Inputs**:
    - `item`: A pointer to the `cJSON` item to be duplicated.
    - `recurse`: A boolean flag indicating whether to duplicate child items recursively.
- **Control Flow**:
    - Checks if the input `item` is NULL; if so, it jumps to the fail label.
    - Creates a new `cJSON` item using [`cJSON_New_Item`](#cJSON_New_Item).
    - Copies the type and value properties from the original item to the new item.
    - If the `item` has a string value, it duplicates it using [`cJSON_strdup`](#cJSON_strdup).
    - If the `item` has a child and `recurse` is true, it iterates through the child items, duplicating each one recursively.
    - Links the duplicated child items to the new item.
    - If any allocation fails during the process, it jumps to the fail label.
- **Output**: Returns a pointer to the newly duplicated `cJSON` item, or NULL if duplication fails.
- **Functions called**:
    - [`cJSON_New_Item`](#cJSON_New_Item)
    - [`cJSON_strdup`](#cJSON_strdup)
    - [`cJSON_Delete`](#cJSON_Delete)


---
### skip\_oneline\_comment<!-- {{#callable:skip_oneline_comment}} -->
The `skip_oneline_comment` function advances a given input pointer past a single-line comment in the format '//'.
- **Inputs**:
    - `input`: A pointer to a character pointer that points to the current position in the input string.
- **Control Flow**:
    - The function first increments the `input` pointer by the length of the string '//'.
    - It then enters a loop that continues until the end of the string is reached.
    - Within the loop, it checks each character; if a newline character ('\n') is encountered, it increments the `input` pointer by the length of the newline and exits the function.
- **Output**: The function does not return a value; it modifies the input pointer to skip over the comment.


---
### skip\_multiline\_comment<!-- {{#callable:skip_multiline_comment}} -->
The `skip_multiline_comment` function advances a pointer past a multiline comment in a C-style syntax.
- **Inputs**:
    - `input`: A pointer to a character pointer that points to the current position in the input string.
- **Control Flow**:
    - The function first increments the `input` pointer to skip the initial '/*' of the comment.
    - It then enters a loop that continues until the end of the string is reached.
    - Inside the loop, it checks for the closing '*/' sequence.
    - If the closing sequence is found, it increments the `input` pointer to skip it and exits the function.
- **Output**: The function does not return a value; it modifies the input pointer to point to the character immediately following the end of the multiline comment.


---
### minify\_string<!-- {{#callable:minify_string}} -->
The `minify_string` function reduces a JSON string by removing unnecessary whitespace and handling escape sequences.
- **Inputs**:
    - `input`: A pointer to a pointer to a character array representing the input JSON string.
    - `output`: A pointer to a pointer to a character array where the minified JSON string will be stored.
- **Control Flow**:
    - The function starts by copying the first character from `input` to `output`.
    - It then increments both `input` and `output` pointers to skip the initial quote character.
    - A loop iterates through the characters of the input string until a null terminator is encountered.
    - Within the loop, each character is copied from `input` to `output` unless it is a quote or an escaped quote.
    - If a quote is encountered, it is copied to `output`, and both pointers are incremented to skip the quote.
    - If an escaped quote is found (preceded by a backslash), the next character is also copied to `output`.
- **Output**: The function does not return a value but modifies the `output` pointer to contain the minified version of the input JSON string.


---
### cJSON\_Minify<!-- {{#callable:cJSON_Minify}} -->
The `cJSON_Minify` function removes whitespace and comments from a JSON string to create a minified version.
- **Inputs**:
    - `json`: A pointer to a null-terminated string containing the JSON data to be minified.
- **Control Flow**:
    - The function first checks if the input `json` is NULL; if so, it returns immediately.
    - It initializes a pointer `into` to the start of the `json` string.
    - It enters a loop that continues until the end of the string is reached.
    - Inside the loop, it uses a switch statement to handle different characters:
    -  - Whitespace characters (' ', '	', '', '
') are skipped.
    -  - If a '/' is encountered, it checks for comments: single-line ('//') or multi-line ('/* ... */') and skips them.
    -  - If a double quote ('"') is found, it calls [`minify_string`](#minify_string) to handle the string content.
    -  - For any other character, it copies the character to the `into` pointer and advances both pointers.
    - Finally, it null-terminates the minified string.
- **Output**: The function modifies the input string in place, resulting in a minified version of the JSON string without whitespace and comments.
- **Functions called**:
    - [`skip_oneline_comment`](#skip_oneline_comment)
    - [`skip_multiline_comment`](#skip_multiline_comment)
    - [`minify_string`](#minify_string)


---
### cJSON\_IsInvalid<!-- {{#callable:cJSON_IsInvalid}} -->
Determines if a given `cJSON` item is of type invalid.
- **Inputs**:
    - `item`: A pointer to a `cJSON` object that is being checked for validity.
- **Control Flow**:
    - The function first checks if the `item` pointer is NULL; if it is, the function returns false.
    - If the `item` is not NULL, it checks if the type of the item is `cJSON_Invalid` by performing a bitwise AND operation with 0xFF and comparing it to `cJSON_Invalid`.
    - The result of this comparison is returned as a boolean value.
- **Output**: Returns true if the item is of type invalid, otherwise returns false.


---
### cJSON\_IsFalse<!-- {{#callable:cJSON_IsFalse}} -->
The `cJSON_IsFalse` function checks if a given `cJSON` item represents a JSON false value.
- **Inputs**:
    - `item`: A pointer to a `cJSON` object that is to be checked for the false value.
- **Control Flow**:
    - The function first checks if the `item` pointer is NULL; if it is, the function returns false.
    - If the `item` is not NULL, it checks if the type of the item is equal to `cJSON_False` using a bitwise AND operation.
    - The result of the type check is returned as a boolean value.
- **Output**: Returns true if the `item` is of type `cJSON_False`, otherwise returns false.


---
### cJSON\_IsTrue<!-- {{#callable:cJSON_IsTrue}} -->
The `cJSON_IsTrue` function checks if a given `cJSON` item represents a true boolean value.
- **Inputs**:
    - `item`: A pointer to a `cJSON` object that is to be checked for its boolean value.
- **Control Flow**:
    - The function first checks if the `item` pointer is NULL; if it is, it returns false.
    - If the `item` is not NULL, it checks if the type of the item is equal to `cJSON_True` by performing a bitwise AND operation with 0xff.
- **Output**: Returns true if the `item` is of type `cJSON_True`, otherwise returns false.


---
### cJSON\_IsBool<!-- {{#callable:cJSON_IsBool}} -->
Determines if a given `cJSON` item is of boolean type.
- **Inputs**:
    - `item`: A pointer to a `cJSON` object that is to be checked for boolean type.
- **Control Flow**:
    - The function first checks if the `item` pointer is NULL; if it is, the function returns false.
    - If the `item` is not NULL, it checks if the `type` of the item includes either `cJSON_True` or `cJSON_False` using a bitwise AND operation.
    - The function returns true if the item is a boolean type, otherwise it returns false.
- **Output**: Returns a boolean value indicating whether the `item` is of type boolean (true or false).


---
### cJSON\_IsNull<!-- {{#callable:cJSON_IsNull}} -->
The `cJSON_IsNull` function checks if a given `cJSON` item is of type null.
- **Inputs**:
    - `item`: A pointer to a `cJSON` object that is to be checked for null type.
- **Control Flow**:
    - The function first checks if the `item` pointer is NULL; if it is, the function returns false.
    - If the `item` is not NULL, it checks if the type of the item is equal to `cJSON_NULL` by performing a bitwise AND operation with 0xFF.
    - The result of the type check is returned as a boolean value.
- **Output**: Returns true if the `item` is of type null, otherwise returns false.


---
### cJSON\_IsNumber<!-- {{#callable:cJSON_IsNumber}} -->
Determines if a given `cJSON` item is of type number.
- **Inputs**:
    - `item`: A pointer to a `cJSON` object that is to be checked for its type.
- **Control Flow**:
    - The function first checks if the `item` pointer is NULL; if it is, it returns false.
    - If `item` is not NULL, it checks if the type of the item matches `cJSON_Number` by performing a bitwise AND operation with 0xFF.
    - The result of the type check is returned as a boolean value.
- **Output**: Returns true if the `item` is of type number, otherwise returns false.


---
### cJSON\_IsString<!-- {{#callable:cJSON_IsString}} -->
Determines if a given `cJSON` item is of type string.
- **Inputs**:
    - `item`: A pointer to a `cJSON` object that is to be checked.
- **Control Flow**:
    - The function first checks if the `item` pointer is NULL; if it is, it returns false.
    - If `item` is not NULL, it checks if the type of the item matches `cJSON_String` by performing a bitwise AND operation with 0xFF.
    - The result of the comparison is returned as a boolean value.
- **Output**: Returns true if the item is a string, otherwise returns false.


---
### cJSON\_IsArray<!-- {{#callable:cJSON_IsArray}} -->
The `cJSON_IsArray` function checks if a given `cJSON` item is of type array.
- **Inputs**:
    - `item`: A pointer to a `cJSON` object that is to be checked if it is an array.
- **Control Flow**:
    - The function first checks if the `item` pointer is NULL; if it is, the function returns false.
    - If `item` is not NULL, it checks if the type of the item matches `cJSON_Array` using a bitwise AND operation.
    - The function returns true if the item is an array, otherwise it returns false.
- **Output**: Returns a boolean value indicating whether the provided `cJSON` item is an array (true) or not (false).


---
### cJSON\_IsObject<!-- {{#callable:cJSON_IsObject}} -->
The `cJSON_IsObject` function checks if a given `cJSON` item is of type object.
- **Inputs**:
    - `item`: A pointer to a `cJSON` structure that represents the item to be checked.
- **Control Flow**:
    - The function first checks if the `item` pointer is NULL; if it is, it returns false.
    - If `item` is not NULL, it checks if the type of the item matches `cJSON_Object` by performing a bitwise AND operation with 0xFF.
    - The result of the comparison is returned as a boolean value.
- **Output**: Returns true if the item is an object, otherwise returns false.


---
### cJSON\_IsRaw<!-- {{#callable:cJSON_IsRaw}} -->
The `cJSON_IsRaw` function checks if a given `cJSON` item is of type raw.
- **Inputs**:
    - `item`: A pointer to a `cJSON` object that is to be checked for the raw type.
- **Control Flow**:
    - The function first checks if the `item` pointer is NULL; if it is, the function returns false.
    - If `item` is not NULL, it checks if the type of the item matches `cJSON_Raw` by performing a bitwise AND operation with 0xFF.
    - The result of the comparison is returned as a boolean value.
- **Output**: Returns true if the `item` is of type raw, otherwise returns false.


---
### cJSON\_Compare<!-- {{#callable:cJSON_Compare}} -->
Compares two `cJSON` objects for equality.
- **Inputs**:
    - `a`: A pointer to the first `cJSON` object to compare.
    - `b`: A pointer to the second `cJSON` object to compare.
    - `case_sensitive`: A boolean indicating whether the comparison should be case-sensitive.
- **Control Flow**:
    - Checks if either `a` or `b` is NULL or if their types differ, returning false if so.
    - Validates the type of `a` to ensure it is one of the supported types.
    - If `a` and `b` point to the same object, returns true.
    - For boolean and null types, returns true if they are of the same type.
    - For numbers, compares their values using a helper function for floating-point precision.
    - For strings and raw types, compares their values using `strcmp`.
    - For arrays, iterates through each element, recursively calling `cJSON_Compare` on corresponding elements.
    - For objects, checks each key-value pair in both objects, ensuring all pairs match recursively.
- **Output**: Returns true if the two `cJSON` objects are equal, false otherwise.
- **Functions called**:
    - [`compare_double`](#compare_double)
    - [`get_object_item`](#get_object_item)


---
### cJSON\_ArrayForEach<!-- {{#callable:cJSON_Compare::cJSON_ArrayForEach}} -->
Iterates over each element in a JSON array and compares it with corresponding elements in another JSON object.
- **Inputs**:
    - `b_element`: A pointer to the current element in the JSON array being iterated over.
    - `b`: A pointer to the JSON array that is being traversed.
    - `a`: A pointer to the JSON object that contains elements to be compared against.
    - `case_sensitive`: A boolean flag indicating whether the comparison should be case-sensitive.
- **Control Flow**:
    - The function uses a loop to iterate over each element in the JSON array `b`.
    - For each element `b_element`, it retrieves the corresponding element from the JSON object `a` using [`get_object_item`](#get_object_item).
    - If the retrieved element `a_element` is NULL, the function returns false, indicating a mismatch.
    - If `a_element` is not NULL, it compares `b_element` with `a_element` using `cJSON_Compare`.
    - If the comparison fails, the function returns false.
- **Output**: Returns true if all elements in the array `b` match the corresponding elements in the object `a`, otherwise returns false.
- **Functions called**:
    - [`get_object_item`](#get_object_item)


---
### cJSON\_malloc<!-- {{#callable:cJSON_malloc}} -->
Allocates memory of a specified size using a global memory allocation hook.
- **Inputs**:
    - `size`: The size in bytes of the memory to allocate.
- **Control Flow**:
    - Calls the `allocate` function from the `global_hooks` structure, which is expected to point to a memory allocation function.
    - Returns the pointer to the allocated memory.
- **Output**: Returns a pointer to the allocated memory block, or NULL if the allocation fails.


---
### cJSON\_free<!-- {{#callable:cJSON_free}} -->
Frees the memory allocated for a given object using the global deallocation hook.
- **Inputs**:
    - `object`: A pointer to the memory that needs to be freed.
- **Control Flow**:
    - Calls the `deallocate` function from the `global_hooks` structure, passing the `object` pointer to it.
- **Output**: This function does not return a value; it simply frees the memory associated with the provided object.


# Function Declarations (Public API)

---
### parse\_value<!-- {{#callable_declaration:parse_value}} -->
Parses a JSON value from the input buffer and populates the cJSON item.
- **Description**: Use this function to parse a JSON value from a given input buffer and populate the provided cJSON item with the parsed data. This function should be called when you need to interpret a segment of JSON text into a cJSON structure. It handles various JSON data types such as null, boolean, string, number, array, and object. Ensure that the input buffer is properly initialized and contains valid JSON content. The function returns a boolean indicating success or failure of the parsing operation.
- **Inputs**:
    - `item`: A pointer to a cJSON structure that will be populated with the parsed JSON value. The caller must ensure this is a valid, non-null pointer.
    - `input_buffer`: A pointer to a parse_buffer structure containing the JSON text to be parsed. The buffer must be initialized and contain valid JSON content. If the buffer is null or its content is null, the function returns false.
- **Output**: Returns a cJSON_bool indicating true if the JSON value was successfully parsed and false otherwise.
- **See also**: [`parse_value`](#parse_value)  (Implementation)


---
### print\_value<!-- {{#callable_declaration:print_value}} -->
Renders a cJSON item into a JSON string and writes it to a print buffer.
- **Description**: Use this function to convert a cJSON item into its JSON string representation and store it in the provided print buffer. This function must be called with valid cJSON and printbuffer pointers. It handles various JSON data types, including null, boolean, number, string, array, and object. The function returns false if either input is null or if memory allocation fails during the process.
- **Inputs**:
    - `item`: A pointer to a cJSON structure representing the JSON item to be printed. Must not be null.
    - `output_buffer`: A pointer to a printbuffer structure where the JSON string will be written. Must not be null.
- **Output**: Returns a cJSON_bool indicating success (true) or failure (false).
- **See also**: [`print_value`](#print_value)  (Implementation)


---
### parse\_array<!-- {{#callable_declaration:parse_array}} -->
Parses a JSON array from the input buffer.
- **Description**: Use this function to parse a JSON array from a given input buffer and populate a cJSON item with the parsed data. It should be called when you expect the input buffer to contain a JSON array. The function handles nested arrays up to a predefined limit and skips whitespace as needed. It returns a boolean indicating success or failure, and in case of failure, any partially parsed data is cleaned up.
- **Inputs**:
    - `item`: A pointer to a cJSON structure where the parsed array will be stored. Must not be null.
    - `input_buffer`: A pointer to a parse_buffer structure containing the JSON data to be parsed. Must not be null and should be properly initialized with the JSON content and length.
- **Output**: Returns a cJSON_bool indicating true if the array was successfully parsed, or false if an error occurred (e.g., invalid JSON format, memory allocation failure, or exceeding nesting limit).
- **See also**: [`parse_array`](#parse_array)  (Implementation)


---
### print\_array<!-- {{#callable_declaration:print_array}} -->
Renders a cJSON array to a text buffer.
- **Description**: This function is used to convert a cJSON array into its string representation and store it in the provided print buffer. It should be called when you need to serialize a cJSON array for output. The function requires a valid print buffer to store the output, and it will return false if the buffer is null or if memory allocation fails during the process. The function handles formatted and unformatted output based on the print buffer's settings.
- **Inputs**:
    - `item`: A pointer to a cJSON object representing an array. The array must be properly initialized and must not be null.
    - `output_buffer`: A pointer to a printbuffer structure where the output will be stored. This buffer must be initialized and must not be null. The function will return false if the buffer is null or if memory allocation fails.
- **Output**: Returns a cJSON_bool indicating success (true) or failure (false).
- **See also**: [`print_array`](#print_array)  (Implementation)


---
### parse\_object<!-- {{#callable_declaration:parse_object}} -->
Parses a JSON object from a buffer.
- **Description**: Use this function to parse a JSON object from a given input buffer and populate the provided cJSON item with the parsed data. It should be called when you need to interpret a JSON object from a string buffer. The function expects the buffer to start with a '{' character and will parse until the matching '}' is found. It handles nested objects up to a predefined limit and skips whitespace. If parsing fails, the function returns false and any partially parsed data is cleaned up.
- **Inputs**:
    - `item`: A pointer to a cJSON structure where the parsed object will be stored. Must not be null.
    - `input_buffer`: A pointer to a parse_buffer structure containing the JSON data to be parsed. Must not be null and should point to a buffer starting with a '{' character. The buffer's depth must be less than CJSON_NESTING_LIMIT.
- **Output**: Returns a cJSON_bool indicating success (true) or failure (false). On success, the item is populated with the parsed JSON object. On failure, the item is not modified.
- **See also**: [`parse_object`](#parse_object)  (Implementation)


---
### print\_object<!-- {{#callable_declaration:print_object}} -->
Formats a cJSON object into a JSON string and writes it to a print buffer.
- **Description**: Use this function to serialize a cJSON object into a JSON formatted string, writing the result into a provided print buffer. This function is useful when you need to convert a cJSON object into a JSON string for output or storage. It requires a valid cJSON object and a print buffer to store the output. The function handles both formatted and unformatted output based on the print buffer's settings. Ensure the print buffer is properly initialized before calling this function. If the buffer is null or memory allocation fails, the function returns false.
- **Inputs**:
    - `item`: A pointer to a cJSON object to be serialized. Must not be null.
    - `output_buffer`: A pointer to a printbuffer structure where the JSON string will be written. Must not be null and should be properly initialized.
- **Output**: Returns a cJSON_bool indicating success (true) or failure (false).
- **See also**: [`print_object`](#print_object)  (Implementation)



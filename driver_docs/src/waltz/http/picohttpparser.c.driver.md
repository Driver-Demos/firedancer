# Purpose
This C source code file is part of a library that provides functionality for parsing HTTP requests and responses. The code is designed to efficiently handle HTTP message parsing, including request lines, headers, and chunked transfer encoding. It defines several functions such as [`phr_parse_request`](#phr_parse_request), [`phr_parse_response`](#phr_parse_response), and [`phr_parse_headers`](#phr_parse_headers), which are responsible for parsing HTTP requests, responses, and headers, respectively. These functions are designed to be used in environments where performance is critical, as evidenced by the use of low-level optimizations like SSE4.2 intrinsics for fast character searching and the use of macros to handle common parsing tasks.

The file includes several static helper functions and macros that facilitate the parsing process, such as [`parse_token`](#parse_token), [`parse_http_version`](#parse_http_version), and [`findchar_fast`](#findchar_fast). These components work together to ensure that the parsing is both robust and efficient. The code also includes a chunked transfer decoder, implemented in the [`phr_decode_chunked`](#phr_decode_chunked) function, which processes HTTP messages that use chunked transfer encoding. This file is intended to be part of a larger library, as indicated by the inclusion of a header file (`picohttpparser.h`) and the absence of a `main` function, suggesting that it is not an executable but rather a module to be integrated into other software systems. The code is designed to be portable across different compilers and platforms, with conditional compilation directives to handle platform-specific features.
# Imports and Dependencies

---
- `assert.h`
- `stddef.h`
- `string.h`
- `nmmintrin.h`
- `x86intrin.h`
- `picohttpparser.h`


# Global Variables

---
### token\_char\_map
- **Type**: `const char*`
- **Description**: `token_char_map` is a static constant character pointer that maps ASCII characters to a binary representation indicating whether each character is a valid token character. The map is initialized with a string of null and one values, where a '1' indicates a valid token character and a '0' indicates an invalid one.
- **Use**: This variable is used to quickly check if a character is a valid token character in HTTP parsing operations.


# Functions

---
### findchar\_fast<!-- {{#callable:findchar_fast}} -->
The `findchar_fast` function searches for a character within a specified range in a buffer using SIMD instructions for fast processing on systems with SSE4.2 support.
- **Inputs**:
    - `buf`: A pointer to the start of the buffer where the search begins.
    - `buf_end`: A pointer to the end of the buffer, marking the limit of the search.
    - `ranges`: A pointer to a character range array used to specify the characters to search for.
    - `ranges_size`: The size of the ranges array, indicating how many characters are in the range.
    - `found`: A pointer to an integer that will be set to 1 if a character from the range is found, otherwise it remains 0.
- **Control Flow**:
    - Initialize the `found` flag to 0, indicating no character has been found yet.
    - Check if the system supports SSE4.2 and if the buffer length is at least 16 bytes to use SIMD instructions.
    - Load the character ranges into a 128-bit SIMD register.
    - Iterate over the buffer in 16-byte chunks, loading each chunk into a SIMD register.
    - Use the `_mm_cmpestri` intrinsic to compare the loaded buffer chunk against the character ranges.
    - If a character from the range is found (i.e., the result of `_mm_cmpestri` is not 16), update the buffer pointer to the found position, set `found` to 1, and break the loop.
    - Continue processing the buffer in chunks until the end is reached or a character is found.
    - If SSE4.2 is not supported, suppress unused parameter warnings and return the buffer pointer.
- **Output**: Returns a pointer to the position in the buffer where a character from the specified range is found, or the end of the buffer if no such character is found.


---
### get\_token\_to\_eol<!-- {{#callable:get_token_to_eol}} -->
The `get_token_to_eol` function extracts a token from a buffer until the end of a line or a control character is found.
- **Inputs**:
    - `buf`: A pointer to the start of the buffer from which the token is to be extracted.
    - `buf_end`: A pointer to the end of the buffer, indicating the limit for reading.
    - `token`: A pointer to a location where the start of the token will be stored.
    - `token_len`: A pointer to a size_t variable where the length of the token will be stored.
    - `ret`: A pointer to an integer where the function will store the return status.
- **Control Flow**:
    - Initialize `token_start` to the beginning of the buffer `buf`.
    - If SSE4.2 is available, use [`findchar_fast`](#findchar_fast) to quickly locate a control character using SIMD instructions; if found, jump to `FOUND_CTL`.
    - If SSE4.2 is not available, manually check each character in chunks of 8 bytes for non-printable ASCII characters, jumping to `FOUND_CTL` if found.
    - Continue checking each character until a non-printable ASCII character is found or the end of the buffer is reached.
    - At `FOUND_CTL`, check if the character is a carriage return (`\015`); if so, expect a newline (`\012`) and calculate the token length excluding the CRLF.
    - If the character is a newline (`\012`), calculate the token length excluding the newline.
    - If neither a carriage return nor a newline is found, set `ret` to -1 and return NULL.
    - Set `*token` to `token_start` and return the updated buffer position.
- **Output**: Returns a pointer to the position in the buffer after the end of the line or NULL if an error occurs, with `*token` pointing to the start of the token and `*token_len` containing its length.
- **Functions called**:
    - [`findchar_fast`](#findchar_fast)


---
### is\_complete<!-- {{#callable:is_complete}} -->
The `is_complete` function checks if a buffer contains a complete HTTP message by looking for two consecutive newline sequences.
- **Inputs**:
    - `buf`: A pointer to the start of the buffer to be checked.
    - `buf_end`: A pointer to the end of the buffer.
    - `last_len`: The length of the last segment of data processed, used to optimize the starting point for checking.
    - `ret`: A pointer to an integer where the function will store the result code if the buffer is incomplete.
- **Control Flow**:
    - Initialize `ret_cnt` to 0 and adjust `buf` to start checking from the last 3 characters if `last_len` is greater than or equal to 3.
    - Enter an infinite loop to process each character in the buffer.
    - Use the `CHECK_EOF` macro to ensure the buffer has not been fully processed; if it has, set `*ret` to -2 and return `NULL`.
    - If the current character is a carriage return ('\015'), increment `buf`, check for EOF, and expect a newline ('\012') character; increment `ret_cnt` if successful.
    - If the current character is a newline ('\012'), increment `buf` and `ret_cnt`.
    - For any other character, increment `buf` and reset `ret_cnt` to 0.
    - If `ret_cnt` reaches 2, indicating two consecutive newline sequences, return the current position of `buf`.
    - If the loop exits without finding two consecutive newline sequences, set `*ret` to -2 and return `NULL`.
- **Output**: Returns a pointer to the position in the buffer after the second newline sequence if found, otherwise returns `NULL` and sets `*ret` to -2.


---
### parse\_token<!-- {{#callable:parse_token}} -->
The `parse_token` function extracts a token from a buffer until a specified character is encountered, ensuring the token consists of valid characters.
- **Inputs**:
    - `buf`: A pointer to the start of the buffer from which the token is to be parsed.
    - `buf_end`: A pointer to the end of the buffer, marking the limit for parsing.
    - `token`: A pointer to a location where the start of the parsed token will be stored.
    - `token_len`: A pointer to a size_t variable where the length of the parsed token will be stored.
    - `next_char`: A character that indicates the end of the token.
    - `ret`: A pointer to an integer where the function will store the result of the parsing operation, with -1 indicating an error and -2 indicating end of file.
- **Control Flow**:
    - Initialize `buf_start` to the start of the buffer and declare an integer `found`.
    - Call [`findchar_fast`](#findchar_fast) to locate the first non-token character in the buffer using predefined character ranges.
    - If no non-token character is found, check for end of file using `CHECK_EOF`.
    - Enter a loop to iterate over the buffer until `next_char` is found or an invalid token character is encountered.
    - If `next_char` is found, break the loop.
    - If an invalid token character is found, set `ret` to -1 and return NULL.
    - Increment the buffer pointer and check for end of file using `CHECK_EOF`.
    - After the loop, set `*token` to `buf_start` and `*token_len` to the length of the token.
    - Return the current buffer position.
- **Output**: A pointer to the position in the buffer immediately after the parsed token, or NULL if an error occurs.
- **Functions called**:
    - [`findchar_fast`](#findchar_fast)


---
### parse\_http\_version<!-- {{#callable:parse_http_version}} -->
The `parse_http_version` function parses the HTTP version from a buffer and extracts the minor version number.
- **Inputs**:
    - `buf`: A pointer to the start of the buffer containing the HTTP version string.
    - `buf_end`: A pointer to the end of the buffer, indicating the limit for parsing.
    - `minor_version`: A pointer to an integer where the parsed minor version number will be stored.
    - `ret`: A pointer to an integer where the function will store the result code indicating success or failure of the parsing operation.
- **Control Flow**:
    - Check if the buffer has at least 9 characters to parse a valid HTTP version string; if not, set `ret` to -2 and return NULL.
    - Use the `EXPECT_CHAR_NO_CHECK` macro to sequentially check for the characters 'H', 'T', 'T', 'P', '/', '1', and '.' in the buffer, advancing the buffer pointer after each check.
    - Use the `PARSE_INT` macro to parse the minor version number from the buffer and store it in `minor_version`.
    - Return the updated buffer pointer if parsing is successful.
- **Output**: Returns a pointer to the buffer position after parsing the HTTP version, or NULL if parsing fails.


---
### parse\_headers<!-- {{#callable:parse_headers}} -->
The `parse_headers` function parses HTTP headers from a buffer, storing them in a provided array of header structures.
- **Inputs**:
    - `buf`: A pointer to the start of the buffer containing the HTTP headers to be parsed.
    - `buf_end`: A pointer to the end of the buffer, indicating the limit for parsing.
    - `headers`: An array of `phr_header` structures where parsed headers will be stored.
    - `num_headers`: A pointer to a size_t variable that tracks the number of headers parsed.
    - `max_headers`: The maximum number of headers that can be stored in the `headers` array.
    - `ret`: A pointer to an integer used to store error codes or status during parsing.
- **Control Flow**:
    - The function enters a loop that continues until a complete header is parsed or an error occurs.
    - It checks for end-of-file using the `CHECK_EOF` macro and breaks the loop if a CRLF or LF is encountered, indicating the end of headers.
    - If the number of headers reaches `max_headers`, it sets `ret` to -1 and returns NULL, indicating an error due to exceeding the header limit.
    - If the current header is not a continuation line (not starting with space or tab), it attempts to parse a header name using [`parse_token`](#parse_token).
    - If parsing the header name fails or the name length is zero, it sets `ret` to -1 and returns NULL.
    - It skips spaces and tabs after the colon separating the header name and value.
    - It uses [`get_token_to_eol`](#get_token_to_eol) to parse the header value until the end of the line, handling errors similarly.
    - Trailing spaces and tabs are removed from the header value before storing it in the `headers` array.
- **Output**: Returns a pointer to the position in the buffer after the last parsed header, or NULL if an error occurs.
- **Functions called**:
    - [`parse_token`](#parse_token)
    - [`get_token_to_eol`](#get_token_to_eol)


---
### parse\_request<!-- {{#callable:parse_request}} -->
The `parse_request` function parses an HTTP request from a buffer, extracting the method, path, HTTP version, and headers.
- **Inputs**:
    - `buf`: A pointer to the start of the buffer containing the HTTP request data.
    - `buf_end`: A pointer to the end of the buffer, marking the limit of the data to be parsed.
    - `method`: A pointer to a string where the HTTP method will be stored.
    - `method_len`: A pointer to a size_t variable where the length of the HTTP method will be stored.
    - `path`: A pointer to a string where the request path will be stored.
    - `path_len`: A pointer to a size_t variable where the length of the request path will be stored.
    - `minor_version`: A pointer to an integer where the HTTP minor version will be stored.
    - `headers`: An array of `phr_header` structures where the parsed headers will be stored.
    - `num_headers`: A pointer to a size_t variable indicating the number of headers parsed.
    - `max_headers`: The maximum number of headers that can be stored in the `headers` array.
    - `ret`: A pointer to an integer where the function will store the result code, indicating success or the type of error encountered.
- **Control Flow**:
    - Check for and skip an initial empty line, which some clients add after POST content.
    - Parse the HTTP method using [`parse_token`](#parse_token), storing the result in `method` and `method_len`.
    - Skip any spaces following the method and parse the request path using `ADVANCE_TOKEN`, storing the result in `path` and `path_len`.
    - Ensure that both the method and path have non-zero lengths; if not, set `ret` to -1 and return NULL.
    - Parse the HTTP version using [`parse_http_version`](#parse_http_version), storing the result in `minor_version`.
    - Check for and skip the line terminator (CRLF or LF) after the HTTP version.
    - Call [`parse_headers`](#parse_headers) to parse the headers from the buffer, storing them in the `headers` array and updating `num_headers`.
- **Output**: A pointer to the position in the buffer after the parsed request, or NULL if an error occurs.
- **Functions called**:
    - [`parse_token`](#parse_token)
    - [`parse_http_version`](#parse_http_version)
    - [`parse_headers`](#parse_headers)


---
### phr\_parse\_request<!-- {{#callable:phr_parse_request}} -->
The `phr_parse_request` function parses an HTTP request from a buffer, extracting the method, path, HTTP version, and headers.
- **Inputs**:
    - `buf_start`: A pointer to the start of the buffer containing the HTTP request data.
    - `len`: The length of the buffer.
    - `method`: A pointer to a string where the HTTP method will be stored.
    - `method_len`: A pointer to a size_t where the length of the HTTP method will be stored.
    - `path`: A pointer to a string where the request path will be stored.
    - `path_len`: A pointer to a size_t where the length of the request path will be stored.
    - `minor_version`: A pointer to an integer where the HTTP minor version will be stored.
    - `headers`: An array of `phr_header` structures where the headers will be stored.
    - `num_headers`: A pointer to a size_t indicating the maximum number of headers to parse, which will be updated with the actual number of headers parsed.
    - `last_len`: The length of the last part of the buffer, used to check if the request is complete.
- **Control Flow**:
    - Initialize local variables and reset output parameters to default values.
    - Check if `last_len` is non-zero and use [`is_complete`](#is_complete) to determine if the request is complete; return the result if incomplete.
    - Call [`parse_request`](#parse_request) to parse the request line and headers; return the result if parsing fails.
    - Return the number of bytes parsed from the buffer.
- **Output**: Returns the number of bytes parsed from the buffer, or a negative error code if parsing fails.
- **Functions called**:
    - [`is_complete`](#is_complete)
    - [`parse_request`](#parse_request)


---
### parse\_response<!-- {{#callable:parse_response}} -->
The `parse_response` function parses an HTTP response from a buffer, extracting the HTTP version, status code, message, and headers.
- **Inputs**:
    - `buf`: A pointer to the start of the buffer containing the HTTP response to be parsed.
    - `buf_end`: A pointer to the end of the buffer, marking the limit for parsing.
    - `minor_version`: A pointer to an integer where the minor version of the HTTP protocol will be stored.
    - `status`: A pointer to an integer where the HTTP status code will be stored.
    - `msg`: A pointer to a string where the status message will be stored.
    - `msg_len`: A pointer to a size_t where the length of the status message will be stored.
    - `headers`: A pointer to an array of `phr_header` structures where the parsed headers will be stored.
    - `num_headers`: A pointer to a size_t where the number of parsed headers will be stored.
    - `max_headers`: The maximum number of headers that can be stored in the `headers` array.
    - `ret`: A pointer to an integer where the function will store error codes if parsing fails.
- **Control Flow**:
    - The function begins by parsing the HTTP version using [`parse_http_version`](#parse_http_version); if unsuccessful, it returns NULL.
    - It checks for a space character following the HTTP version and skips any additional spaces.
    - The function then attempts to parse a three-digit status code using the `PARSE_INT_3` macro; if unsuccessful, it returns NULL.
    - It retrieves the status message using [`get_token_to_eol`](#get_token_to_eol), adjusting for any leading spaces, and returns NULL if parsing fails.
    - Finally, it calls [`parse_headers`](#parse_headers) to parse the headers, returning the result of this function.
- **Output**: The function returns a pointer to the position in the buffer after the parsed headers, or NULL if parsing fails at any step.
- **Functions called**:
    - [`parse_http_version`](#parse_http_version)
    - [`get_token_to_eol`](#get_token_to_eol)
    - [`parse_headers`](#parse_headers)


---
### phr\_parse\_response<!-- {{#callable:phr_parse_response}} -->
The `phr_parse_response` function parses an HTTP response from a buffer, extracting the HTTP version, status code, message, and headers.
- **Inputs**:
    - `buf_start`: A pointer to the start of the buffer containing the HTTP response to be parsed.
    - `len`: The length of the buffer in bytes.
    - `minor_version`: A pointer to an integer where the function will store the minor version of the HTTP response.
    - `status`: A pointer to an integer where the function will store the HTTP status code.
    - `msg`: A pointer to a string where the function will store the HTTP status message.
    - `msg_len`: A pointer to a size_t where the function will store the length of the status message.
    - `headers`: An array of `phr_header` structures where the function will store the parsed headers.
    - `num_headers`: A pointer to a size_t indicating the maximum number of headers to parse, which will be updated with the actual number of headers parsed.
    - `last_len`: The length of the last part of the buffer, used to check if the response is complete.
- **Control Flow**:
    - Initialize local variables and set default values for output parameters.
    - Check if `last_len` is non-zero and use [`is_complete`](#is_complete) to determine if the response is complete; return the result if incomplete.
    - Call [`parse_response`](#parse_response) to parse the HTTP version, status code, message, and headers from the buffer.
    - Return the number of bytes parsed from the buffer.
- **Output**: Returns the number of bytes parsed from the buffer, or a negative error code if parsing fails.
- **Functions called**:
    - [`is_complete`](#is_complete)
    - [`parse_response`](#parse_response)


---
### phr\_parse\_headers<!-- {{#callable:phr_parse_headers}} -->
The `phr_parse_headers` function parses HTTP headers from a given buffer and stores them in a provided array of header structures.
- **Inputs**:
    - `buf_start`: A pointer to the start of the buffer containing the HTTP headers to be parsed.
    - `len`: The length of the buffer in bytes.
    - `headers`: An array of `phr_header` structures where the parsed headers will be stored.
    - `num_headers`: A pointer to a size_t variable that initially contains the maximum number of headers to parse and will be updated with the actual number of headers parsed.
    - `last_len`: The length of the last part of the buffer that was previously processed, used to check if the response is complete.
- **Control Flow**:
    - Initialize pointers to the start and end of the buffer and set `max_headers` to the value pointed by `num_headers`.
    - Reset `*num_headers` to 0 to start counting parsed headers.
    - If `last_len` is not zero, call [`is_complete`](#is_complete) to check if the response is complete; if not, return the result code `r`.
    - Call [`parse_headers`](#parse_headers) to parse the headers from the buffer; if parsing fails, return the result code `r`.
    - Return the number of bytes processed from the buffer.
- **Output**: Returns the number of bytes processed from the buffer if successful, or an error code if parsing fails.
- **Functions called**:
    - [`is_complete`](#is_complete)
    - [`parse_headers`](#parse_headers)


---
### decode\_hex<!-- {{#callable:decode_hex}} -->
The `decode_hex` function converts a single hexadecimal character to its integer value or returns -1 if the character is not a valid hexadecimal digit.
- **Inputs**:
    - `ch`: An integer representing a character, which is expected to be a hexadecimal digit ('0'-'9', 'A'-'F', or 'a'-'f').
- **Control Flow**:
    - Check if the character is between '0' and '9'; if true, return the integer value by subtracting '0'.
    - Check if the character is between 'A' and 'F'; if true, return the integer value by subtracting 'A' and adding 10.
    - Check if the character is between 'a' and 'f'; if true, return the integer value by subtracting 'a' and adding 10.
    - If none of the above conditions are met, return -1 indicating an invalid hexadecimal character.
- **Output**: An integer representing the numeric value of the hexadecimal character, or -1 if the character is not a valid hexadecimal digit.


---
### phr\_decode\_chunked<!-- {{#callable:phr_decode_chunked}} -->
The `phr_decode_chunked` function decodes HTTP chunked transfer encoding data from a buffer, updating the buffer size and returning the number of bytes processed or an error code.
- **Inputs**:
    - `decoder`: A pointer to a `phr_chunked_decoder` structure that maintains the state of the decoding process.
    - `buf`: A pointer to a character buffer containing the chunked data to be decoded.
    - `_bufsz`: A pointer to a size_t variable that holds the size of the buffer and is updated to reflect the size of the decoded data.
- **Control Flow**:
    - Initialize local variables `dst`, `src`, and `bufsz` from `_bufsz`, and set `ret` to -2 indicating incomplete data.
    - Enter a loop that processes the buffer based on the current state of the decoder.
    - In the `CHUNKED_IN_CHUNK_SIZE` state, decode the chunk size from hexadecimal digits, updating `bytes_left_in_chunk` and transitioning to `CHUNKED_IN_CHUNK_EXT` state.
    - In the `CHUNKED_IN_CHUNK_EXT` state, skip over any chunk extensions until a newline is found, then transition to `CHUNKED_IN_CHUNK_DATA` if there is data, or handle trailers if `bytes_left_in_chunk` is zero.
    - In the `CHUNKED_IN_CHUNK_DATA` state, move available data to the destination position in the buffer, update `bytes_left_in_chunk`, and transition to `CHUNKED_IN_CHUNK_CRLF` state if the chunk is fully read.
    - In the `CHUNKED_IN_CHUNK_CRLF` state, ensure the presence of a CRLF sequence, then transition back to `CHUNKED_IN_CHUNK_SIZE` for the next chunk.
    - In the `CHUNKED_IN_TRAILERS_LINE_HEAD` and `CHUNKED_IN_TRAILERS_LINE_MIDDLE` states, process trailer lines until the end of the trailers is detected.
    - Handle errors and completion by setting `ret` appropriately and adjusting the buffer to remove processed data.
- **Output**: Returns the number of bytes processed if successful, -1 if an error occurs, or -2 if the data is incomplete.
- **Functions called**:
    - [`decode_hex`](#decode_hex)


---
### phr\_decode\_chunked\_is\_in\_data<!-- {{#callable:phr_decode_chunked_is_in_data}} -->
The function `phr_decode_chunked_is_in_data` checks if the chunked decoder is currently processing chunk data.
- **Inputs**:
    - `decoder`: A pointer to a `phr_chunked_decoder` structure, which holds the state of the chunked decoding process.
- **Control Flow**:
    - The function accesses the `_state` member of the `decoder` structure.
    - It compares the `_state` with the constant `CHUNKED_IN_CHUNK_DATA`.
    - The function returns the result of this comparison.
- **Output**: The function returns an integer value: 1 if the decoder is in the `CHUNKED_IN_CHUNK_DATA` state, otherwise 0.



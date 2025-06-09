# Purpose
This C header file, `picohttpparser.h`, is part of a lightweight HTTP parser library designed for parsing HTTP requests and responses. It defines structures and function prototypes for handling HTTP headers and chunked transfer encoding, which are essential for processing HTTP messages. The `phr_header` structure is used to store HTTP header names and values, while functions like [`phr_parse_request`](#phr_parse_request), [`phr_parse_response`](#phr_parse_response), and [`phr_parse_headers`](#phr_parse_headers) are provided to parse HTTP requests, responses, and headers, respectively. Additionally, the file includes a `phr_chunked_decoder` structure and associated functions to handle HTTP chunked transfer encoding, allowing for the decoding of data that is transmitted in chunks. The header is designed to be compatible with both C and C++ environments, as indicated by the `extern "C"` block, and includes conditional compilation for compatibility with Microsoft compilers.
# Imports and Dependencies

---
- `sys/types.h`


# Data Structures

---
### phr\_header
- **Type**: `struct`
- **Members**:
    - `name`: A pointer to a constant character array representing the name of the header.
    - `name_len`: The length of the header name.
    - `value`: A pointer to a constant character array representing the value of the header.
    - `value_len`: The length of the header value.
- **Description**: The `phr_header` structure is used to represent an HTTP header, containing both the name and value of the header as well as their respective lengths. This structure is part of a library for parsing HTTP requests and responses, and it is used to store header information extracted from HTTP messages. The `name` field can be `NULL` if the header is a continuation of a multiline header.


---
### phr\_chunked\_decoder
- **Type**: `struct`
- **Members**:
    - `bytes_left_in_chunk`: Number of bytes left in the current chunk.
    - `consume_trailer`: Indicates if trailing headers should be consumed.
    - `_hex_count`: Internal counter for hexadecimal digits.
    - `_state`: Internal state of the decoder.
- **Description**: The `phr_chunked_decoder` structure is used to manage the state of decoding HTTP chunked transfer encoding. It keeps track of the number of bytes left to process in the current chunk, whether trailing headers should be consumed, and maintains internal counters and state information necessary for decoding operations. This structure is essential for handling chunked data streams in HTTP communications.


# Function Declarations (Public API)

---
### phr\_parse\_request<!-- {{#callable_declaration:phr_parse_request}} -->
Parses an HTTP request from a buffer.
- **Description**: This function is used to parse an HTTP request from a given buffer, extracting the HTTP method, path, minor version, and headers. It should be called when you have a buffer containing an HTTP request that you need to interpret. The function requires the caller to provide storage for the method, path, and headers, and it will populate these with pointers into the buffer. The function returns the number of bytes consumed if successful, -2 if the request is incomplete, and -1 if parsing fails. It is important to ensure that the buffer is correctly formatted as an HTTP request and that the headers array is large enough to hold all headers. The function can handle partial requests by using the `last_len` parameter to indicate the length of previously processed data.
- **Inputs**:
    - `buf`: A pointer to the start of the buffer containing the HTTP request. Must not be null.
    - `len`: The length of the buffer in bytes. Must be greater than zero.
    - `method`: A pointer to a location where the function will store a pointer to the HTTP method string. Must not be null.
    - `method_len`: A pointer to a size_t where the function will store the length of the HTTP method string. Must not be null.
    - `path`: A pointer to a location where the function will store a pointer to the HTTP path string. Must not be null.
    - `path_len`: A pointer to a size_t where the function will store the length of the HTTP path string. Must not be null.
    - `minor_version`: A pointer to an int where the function will store the HTTP minor version number. Must not be null.
    - `headers`: An array of `struct phr_header` where the function will store the parsed headers. Must not be null and should be pre-allocated with enough space to hold all headers.
    - `num_headers`: A pointer to a size_t that initially contains the number of elements in the `headers` array. On return, it will be updated with the number of headers actually parsed. Must not be null.
    - `last_len`: The length of the previously processed data, used to handle partial requests. Can be zero if not applicable.
- **Output**: Returns the number of bytes consumed if successful, -2 if the request is partial, and -1 if parsing fails.
- **See also**: [`phr_parse_request`](picohttpparser.c.driver.md#phr_parse_request)  (Implementation)


---
### phr\_parse\_response<!-- {{#callable_declaration:phr_parse_response}} -->
Parses an HTTP response from a buffer.
- **Description**: This function is used to parse an HTTP response from a given buffer, extracting the HTTP version, status code, message, and headers. It should be called when you have a buffer containing an HTTP response that you need to interpret. The function initializes output parameters to default values and updates them with parsed data if successful. It handles partial responses by returning a specific code, allowing the caller to provide additional data and retry. The function is designed to be called with a buffer that may contain a complete or partial HTTP response, and it will return the number of bytes consumed if successful, -2 if the response is partial, or -1 if parsing fails.
- **Inputs**:
    - `_buf`: A pointer to the start of the buffer containing the HTTP response. The buffer must be at least 'len' bytes long. The caller retains ownership and must ensure the buffer remains valid for the duration of the call.
    - `len`: The length of the buffer in bytes. Must be a non-negative value.
    - `minor_version`: A pointer to an integer where the function will store the minor version of the HTTP protocol (e.g., 1 for HTTP/1.1). Must not be null.
    - `status`: A pointer to an integer where the function will store the HTTP status code (e.g., 200 for OK). Must not be null.
    - `msg`: A pointer to a location where the function will store a pointer to the start of the status message in the buffer. Must not be null.
    - `msg_len`: A pointer to a size_t where the function will store the length of the status message. Must not be null.
    - `headers`: An array of 'struct phr_header' where the function will store the parsed headers. The array must be large enough to hold the number of headers specified by 'num_headers'.
    - `num_headers`: A pointer to a size_t that specifies the number of headers the 'headers' array can hold. On return, it will be updated to the actual number of headers parsed. Must not be null.
    - `last_len`: The length of the previously parsed data if this is a continuation of a previous call, or 0 if this is the first call. Used to detect incomplete responses.
- **Output**: Returns the number of bytes consumed if successful, -2 if the response is partial, or -1 if parsing fails.
- **See also**: [`phr_parse_response`](picohttpparser.c.driver.md#phr_parse_response)  (Implementation)


---
### phr\_parse\_headers<!-- {{#callable_declaration:phr_parse_headers}} -->
Parses HTTP headers from a buffer.
- **Description**: This function is used to parse HTTP headers from a given buffer, extracting them into an array of `phr_header` structures. It is typically called when processing HTTP messages to extract header information. The function requires the caller to provide a buffer containing the raw HTTP headers, a pre-allocated array of `phr_header` structures to store the parsed headers, and a pointer to a size variable indicating the maximum number of headers that can be stored. The function updates this size variable to reflect the actual number of headers parsed. It also supports partial parsing by accepting a `last_len` parameter, which should be set to zero for the first call and updated with the return value for subsequent calls if the headers are incomplete. The function returns the number of bytes consumed if successful, -2 if the request is partial, and -1 if parsing fails.
- **Inputs**:
    - `buf`: A pointer to the start of the buffer containing the HTTP headers to be parsed. Must not be null.
    - `len`: The length of the buffer in bytes. Must be greater than zero.
    - `headers`: A pointer to an array of `phr_header` structures where the parsed headers will be stored. The array must be pre-allocated and large enough to hold the number of headers specified by `*num_headers`. Must not be null.
    - `num_headers`: A pointer to a size variable that initially contains the maximum number of headers that can be stored in the `headers` array. On return, it is updated to reflect the actual number of headers parsed. Must not be null.
    - `last_len`: The length of the previously parsed portion of the buffer, or zero if this is the first call. Used to handle partial parsing.
- **Output**: Returns the number of bytes consumed if successful, -2 if the request is partial, and -1 if parsing fails.
- **See also**: [`phr_parse_headers`](picohttpparser.c.driver.md#phr_parse_headers)  (Implementation)


---
### phr\_decode\_chunked<!-- {{#callable_declaration:phr_decode_chunked}} -->
Decodes HTTP chunked transfer encoding from a buffer.
- **Description**: Use this function to decode data that is encoded using HTTP chunked transfer encoding. It processes the buffer in place, removing the chunked encoding headers and updating the buffer size to reflect the length of the decoded data. The function should be called repeatedly with new data until it returns a non-negative value, indicating the number of undecoded octets remaining. It returns -2 if the data is incomplete and -1 if an error occurs. Ensure the `phr_chunked_decoder` structure is zero-filled before the first call.
- **Inputs**:
    - `decoder`: A pointer to a `phr_chunked_decoder` structure that maintains the state of the decoding process. Must be zero-filled before the first use.
    - `buf`: A pointer to a buffer containing the chunked-encoded data. The buffer is modified in place to contain the decoded data.
    - `_bufsz`: A pointer to a size_t variable that initially contains the size of the buffer. It is updated to reflect the size of the decoded data after the function returns.
- **Output**: Returns the number of undecoded octets if successful, -2 if the data is incomplete, or -1 if an error occurs.
- **See also**: [`phr_decode_chunked`](picohttpparser.c.driver.md#phr_decode_chunked)  (Implementation)


---
### phr\_decode\_chunked\_is\_in\_data<!-- {{#callable_declaration:phr_decode_chunked_is_in_data}} -->
Check if the chunked decoder is currently processing chunk data.
- **Description**: Use this function to determine if the chunked decoder is in the process of handling chunk data. This can be useful for understanding the current state of the decoder during the decoding process. It should be called with a valid `phr_chunked_decoder` structure that has been properly initialized and used in conjunction with the chunked decoding process.
- **Inputs**:
    - `decoder`: A pointer to a `phr_chunked_decoder` structure. This must be a valid, initialized decoder object. The function will not modify the decoder, and passing a null pointer will result in undefined behavior.
- **Output**: Returns a non-zero value if the decoder is in the middle of processing chunk data, otherwise returns zero.
- **See also**: [`phr_decode_chunked_is_in_data`](picohttpparser.c.driver.md#phr_decode_chunked_is_in_data)  (Implementation)



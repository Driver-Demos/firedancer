# Purpose
This C source code file implements a web server with WebSocket support, focusing on handling HTTP requests and JSON-RPC communication. The file defines a `fd_webserver_t` structure to manage the server's state and provides functions to start the server, handle incoming HTTP requests, and manage WebSocket connections. The server supports HTTP GET, POST, and OPTIONS methods, with specific handling for JSON content types and WebSocket upgrades. The code includes functions for parsing JSON requests, generating HTTP responses, and encoding data in various formats such as Base58, Base64, and hexadecimal.

The file is structured around a central theme of managing web server operations, including request handling, response generation, and WebSocket communication. It defines several static and public functions, indicating that it is part of a larger application where these functions are used to interact with the server. The code also includes error handling mechanisms for protocol errors and JSON parsing errors, ensuring robust server operation. The inclusion of various encoding functions suggests that the server may need to handle different data formats, possibly for secure or efficient data transmission. Overall, this file provides a comprehensive implementation of a web server with WebSocket capabilities, focusing on JSON-RPC communication and data encoding.
# Imports and Dependencies

---
- `../../util/fd_util.h`
- `../../ballet/base64/fd_base64.h`
- `stdlib.h`
- `string.h`
- `stdio.h`
- `errno.h`
- `time.h`
- `signal.h`
- `unistd.h`
- `stdarg.h`
- `strings.h`
- `sys/types.h`
- `sys/socket.h`
- `fd_methods.h`
- `fd_webserver.h`
- `../../waltz/http/fd_http_server_private.h`


# Global Variables

---
### b58digits\_ordered
- **Type**: ``const char[]``
- **Description**: The `b58digits_ordered` is a static constant character array that contains the characters used in the Base58 encoding scheme. This encoding is commonly used in applications like Bitcoin to represent large numbers in a compact and human-readable format without using easily confused characters like '0', 'O', 'I', and 'l'.
- **Use**: This variable is used to map numerical values to their corresponding Base58 characters during encoding processes.


---
### base64\_encoding\_table
- **Type**: `char[]`
- **Description**: The `base64_encoding_table` is a static character array that contains the Base64 encoding alphabet. It includes uppercase and lowercase letters, digits, and two special characters ('+' and '/').
- **Use**: This variable is used to map binary data to Base64 encoded characters during the encoding process.


---
### hex\_encoding\_table
- **Type**: ``const char[]``
- **Description**: The `hex_encoding_table` is a static constant character array that contains the hexadecimal digits '0' through '9' and 'A' through 'F'. It is used to map binary data to its hexadecimal representation.
- **Use**: This variable is used in functions that encode binary data into a hexadecimal string format.


# Data Structures

---
### fd\_websocket\_ctx
- **Type**: `struct`
- **Members**:
    - `ws`: A pointer to an fd_webserver_t structure, representing the associated web server.
    - `connection_id`: An unsigned long integer representing the unique identifier for the connection.
- **Description**: The `fd_websocket_ctx` structure is used to maintain context information for a WebSocket connection within a web server environment. It holds a reference to the web server instance (`ws`) and a unique connection identifier (`connection_id`) to manage and track individual WebSocket connections. This structure is essential for handling WebSocket-specific operations and maintaining the state of each connection.


# Functions

---
### fd\_web\_reply\_flush<!-- {{#callable:fd_web_reply_flush}} -->
The `fd_web_reply_flush` function sends any buffered data in the `quick_buf` of a web server context to the server and resets the buffer size to zero.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure representing the web server context, which contains the buffer and server information.
- **Control Flow**:
    - Check if `ws->quick_size` is non-zero, indicating there is data in the buffer to be sent.
    - If there is data, call `fd_http_server_memcpy` to send the data from `ws->quick_buf` to `ws->server` with the size `ws->quick_size`.
    - Reset `ws->quick_size` to zero, indicating the buffer is now empty.
- **Output**: The function does not return any value; it performs its operations directly on the `fd_webserver_t` structure passed to it.


---
### fd\_web\_reply\_new<!-- {{#callable:fd_web_reply_new}} -->
The `fd_web_reply_new` function initializes a new web reply by resetting various fields in the `fd_webserver_t` structure to prepare for a new HTTP response.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure representing the web server context.
- **Control Flow**:
    - Set `ws->quick_size` to 0, indicating no quick buffer data is currently staged for sending.
    - Call `fd_http_server_stage_trunc` with `ws->server` and 0 to truncate any staged HTTP response data.
    - Set `ws->prev_reply_len` to 0, resetting the length of the previous reply.
    - Set `ws->status_code` to 200, indicating an HTTP OK status for the new reply.
- **Output**: This function does not return a value; it modifies the state of the `fd_webserver_t` structure pointed to by `ws`.


---
### json\_parse\_root<!-- {{#callable:json_parse_root}} -->
The `json_parse_root` function parses a JSON input from a lexer state, handling both single JSON objects and arrays of JSON objects, and processes them using a web server context.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure, representing the web server context used for handling replies and errors.
    - `lex`: A pointer to a `json_lex_state_t` structure, representing the lexer state used for parsing the JSON input.
- **Control Flow**:
    - Check if the next token from the lexer is a left bracket (`[`), indicating an array of JSON requests.
    - If an array is detected, append `[` to the web server reply and enter a loop to process each JSON object in the array.
    - Within the loop, flush the web server reply, initialize a `json_values` structure, and attempt to parse a JSON object.
    - If parsing is successful, call [`fd_webserver_method_generic`](fd_rpc_service.c.driver.md#fd_webserver_method_generic) to process the parsed values; otherwise, report a parse error and break the loop.
    - After processing a JSON object, check the next token: if it's a comma, append `,` to the reply; if it's a right bracket, exit the loop; otherwise, report a parse error and break the loop.
    - Append `]` to the web server reply after processing the array.
    - If the input is not an array, reset the lexer position and attempt to parse a single JSON object.
    - If parsing the single object is successful, process it with [`fd_webserver_method_generic`](fd_rpc_service.c.driver.md#fd_webserver_method_generic); otherwise, report a parse error.
- **Output**: The function does not return a value but modifies the web server context to append replies or errors based on the JSON parsing results.
- **Functions called**:
    - [`json_lex_next_token`](json_lex.c.driver.md#json_lex_next_token)
    - [`fd_web_reply_append`](#fd_web_reply_append)
    - [`fd_web_reply_flush`](#fd_web_reply_flush)
    - [`json_values_new`](fd_methods.c.driver.md#json_values_new)
    - [`json_values_parse`](fd_methods.c.driver.md#json_values_parse)
    - [`fd_webserver_method_generic`](fd_rpc_service.c.driver.md#fd_webserver_method_generic)
    - [`json_lex_get_text`](json_lex.c.driver.md#json_lex_get_text)
    - [`fd_web_reply_error`](#fd_web_reply_error)
    - [`json_values_delete`](fd_methods.c.driver.md#json_values_delete)


---
### fd\_web\_reply\_error<!-- {{#callable:fd_web_reply_error}} -->
The `fd_web_reply_error` function constructs and sends a JSON-RPC error response message to the client using the provided error code, message, and call ID.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure representing the web server context.
    - `errcode`: An integer representing the error code to be included in the JSON-RPC error response.
    - `text`: A constant character pointer to the error message text to be included in the JSON-RPC error response.
    - `call_id`: A constant character pointer to the call ID to be included in the JSON-RPC error response.
- **Control Flow**:
    - Set the `quick_size` of the web server context to 0, indicating that the quick buffer is empty.
    - Truncate the server's staged response to the length of the previous reply using `fd_http_server_stage_trunc`.
    - Format and append the beginning of the JSON-RPC error response string, including the error code, using [`fd_web_reply_sprintf`](#fd_web_reply_sprintf).
    - Encode the provided error message text as a JSON string and append it to the response using [`fd_web_reply_encode_json_string`](#fd_web_reply_encode_json_string).
    - Format and append the closing part of the JSON-RPC error response, including the call ID, using [`fd_web_reply_sprintf`](#fd_web_reply_sprintf).
- **Output**: The function does not return a value; it constructs and sends a JSON-RPC error response to the client through the web server context.
- **Functions called**:
    - [`fd_web_reply_sprintf`](#fd_web_reply_sprintf)
    - [`fd_web_reply_encode_json_string`](#fd_web_reply_encode_json_string)


---
### fd\_web\_protocol\_error<!-- {{#callable:fd_web_protocol_error}} -->
The `fd_web_protocol_error` function sends an HTML-formatted error message to the client and sets the HTTP status code to 400 (Bad Request).
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure representing the web server context.
    - `text`: A constant character pointer to the error message text to be included in the HTML response.
- **Control Flow**:
    - Define HTML document parts DOC1 and DOC2 with static strings for the error message format.
    - Call [`fd_web_reply_new`](#fd_web_reply_new) to initialize a new web reply, resetting the quick buffer and setting the status code to 200.
    - Copy DOC1, the error message text, and DOC2 into the server's memory using `fd_http_server_memcpy`.
    - Set the web server's status code to 400 to indicate a Bad Request.
- **Output**: The function does not return a value; it modifies the web server context to send an error response.
- **Functions called**:
    - [`fd_web_reply_new`](#fd_web_reply_new)


---
### request<!-- {{#callable:request}} -->
The `request` function processes HTTP requests, handling different HTTP methods and returning appropriate server responses based on the request details.
- **Inputs**:
    - `request`: A pointer to a `fd_http_server_request_t` structure containing the HTTP request details, including method, headers, and body.
- **Control Flow**:
    - Initialize the web server context from the request's context.
    - Call [`fd_web_reply_new`](#fd_web_reply_new) to prepare a new web reply.
    - Check if the request method is GET and if the request headers indicate a WebSocket upgrade.
    - If both conditions are true, return a 200 OK response with WebSocket upgrade enabled.
    - If the request method is GET but no WebSocket upgrade is requested, log a protocol error and return a 400 Bad Request response.
    - If the request method is OPTIONS, return a 204 No Content response with appropriate CORS headers.
    - For other methods, check if the request path is "/" and if the content type is "application/json".
    - If the path or content type is incorrect, log a protocol error.
    - If the path and content type are correct, parse the JSON body and process it.
    - Prepare a response based on the web server's status code and attempt to stage the response body.
    - If staging the response body fails, log a warning and return a 500 Internal Server Error response.
    - Return the prepared response.
- **Output**: Returns a `fd_http_server_response_t` structure representing the HTTP response, including status code, content type, and WebSocket upgrade status.
- **Functions called**:
    - [`fd_web_reply_new`](#fd_web_reply_new)
    - [`fd_web_protocol_error`](#fd_web_protocol_error)
    - [`json_lex_state_new`](json_lex.c.driver.md#json_lex_state_new)
    - [`json_parse_root`](#json_parse_root)
    - [`json_lex_state_delete`](json_lex.c.driver.md#json_lex_state_delete)
    - [`fd_web_reply_flush`](#fd_web_reply_flush)


---
### http\_open<!-- {{#callable:http_open}} -->
The `http_open` function sets the send buffer size of a socket to 1 MB and logs an error if the operation fails.
- **Inputs**:
    - `connection_id`: An unsigned long integer representing the connection identifier, which is not used in this function.
    - `sockfd`: An integer representing the socket file descriptor for which the send buffer size is to be set.
    - `ctx`: A pointer to a context object, which is not used in this function.
- **Control Flow**:
    - The function begins by casting the `connection_id` and `ctx` parameters to void to indicate they are unused.
    - A new buffer size of 1 MB (2^20 bytes) is defined.
    - The `setsockopt` function is called to set the socket option `SO_SNDBUF` to the new buffer size for the given socket file descriptor `sockfd`.
    - If `setsockopt` returns -1, indicating an error, the function logs an error message with the error number and description, and aborts execution.
- **Output**: The function does not return any value.


---
### http\_close<!-- {{#callable:http_close}} -->
The `http_close` function is a placeholder for handling the closure of an HTTP connection, but it currently does nothing with its parameters.
- **Inputs**:
    - `connection_id`: An unsigned long integer representing the unique identifier of the connection to be closed.
    - `reason`: An integer indicating the reason for closing the connection.
    - `ctx`: A pointer to a context object, which may contain additional information or state related to the connection.
- **Control Flow**:
    - The function takes three parameters: `connection_id`, `reason`, and `ctx`, but does not use them.
    - Each parameter is explicitly cast to void to suppress unused parameter warnings, indicating that they are intentionally not used in the function body.
- **Output**: The function does not return any value or perform any operations; it is a void function.


---
### ws\_open<!-- {{#callable:ws_open}} -->
The `ws_open` function is a placeholder for handling the opening of a WebSocket connection, but currently does nothing with its parameters.
- **Inputs**:
    - `connection_id`: An unsigned long integer representing the unique identifier for the WebSocket connection.
    - `ctx`: A pointer to a context object, which is typically used to pass additional data or state information needed for the connection.
- **Control Flow**:
    - The function takes two parameters: `connection_id` and `ctx`, but does not use them.
    - Both parameters are explicitly cast to void to suppress unused variable warnings, indicating that they are not currently utilized in the function.
- **Output**: The function does not produce any output or perform any operations.


---
### ws\_close<!-- {{#callable:ws_close}} -->
The `ws_close` function handles the closure of a WebSocket connection by notifying the web server of the closed connection.
- **Inputs**:
    - `connection_id`: An unsigned long integer representing the unique identifier of the WebSocket connection to be closed.
    - `reason`: An integer representing the reason for the closure of the WebSocket connection, which is not used in this function.
    - `ctx`: A pointer to a context object, specifically a `fd_webserver_t` structure, which contains the web server state and callback arguments.
- **Control Flow**:
    - The function begins by casting the `ctx` pointer to a `fd_webserver_t` pointer named `ws`.
    - It then calls the [`fd_webserver_ws_closed`](fd_rpc_service.c.driver.md#fd_webserver_ws_closed) function, passing the `connection_id` and the `cb_arg` from the `ws` context to notify the web server of the closed connection.
- **Output**: The function does not return any value; it is a `void` function.
- **Functions called**:
    - [`fd_webserver_ws_closed`](fd_rpc_service.c.driver.md#fd_webserver_ws_closed)


---
### ws\_message<!-- {{#callable:ws_message}} -->
The `ws_message` function processes a WebSocket message by parsing JSON data and either subscribing to a service or returning a parse error.
- **Inputs**:
    - `conn_id`: The unique identifier for the WebSocket connection.
    - `data`: A pointer to the data received in the WebSocket message, expected to be in JSON format.
    - `data_len`: The length of the data received.
    - `ctx`: A context pointer, expected to be a pointer to an `fd_webserver_t` structure.
- **Control Flow**:
    - If `FD_RPC_VERBOSE` is defined, the function writes the message data to stdout for debugging purposes.
    - The function casts the `ctx` pointer to an `fd_webserver_t` pointer and initializes a new web reply.
    - It initializes a JSON lexer state with the received data and its length.
    - It creates a new `json_values` structure to hold parsed JSON values.
    - The function attempts to parse the JSON data using [`json_values_parse`](fd_methods.c.driver.md#json_values_parse).
    - If parsing is successful, it calls [`fd_webserver_ws_subscribe`](fd_rpc_service.c.driver.md#fd_webserver_ws_subscribe) to handle the subscription logic.
    - If parsing fails, it retrieves the error text from the lexer and sends an error reply using [`fd_web_reply_error`](#fd_web_reply_error).
    - The function cleans up by deleting the `json_values` and `json_lex_state` structures.
    - Finally, it sends the WebSocket reply using [`fd_web_ws_send`](#fd_web_ws_send).
- **Output**: The function does not return a value; it sends a WebSocket reply based on the parsing result.
- **Functions called**:
    - [`fd_web_reply_new`](#fd_web_reply_new)
    - [`json_lex_state_new`](json_lex.c.driver.md#json_lex_state_new)
    - [`json_values_new`](fd_methods.c.driver.md#json_values_new)
    - [`json_values_parse`](fd_methods.c.driver.md#json_values_parse)
    - [`fd_webserver_ws_subscribe`](fd_rpc_service.c.driver.md#fd_webserver_ws_subscribe)
    - [`json_lex_get_text`](json_lex.c.driver.md#json_lex_get_text)
    - [`fd_web_reply_error`](#fd_web_reply_error)
    - [`json_values_delete`](fd_methods.c.driver.md#json_values_delete)
    - [`json_lex_state_delete`](json_lex.c.driver.md#json_lex_state_delete)
    - [`fd_web_ws_send`](#fd_web_ws_send)


---
### fd\_web\_ws\_send<!-- {{#callable:fd_web_ws_send}} -->
The `fd_web_ws_send` function sends any buffered WebSocket data for a specific connection in a web server context.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure representing the web server context.
    - `conn_id`: An unsigned long integer representing the connection ID for which the WebSocket data is to be sent.
- **Control Flow**:
    - Call [`fd_web_reply_flush`](#fd_web_reply_flush) to ensure any buffered data in the web server context is sent.
    - Call `fd_http_server_ws_send` with the server and connection ID to send the WebSocket data.
- **Output**: This function does not return a value; it performs its operations directly on the web server context.
- **Functions called**:
    - [`fd_web_reply_flush`](#fd_web_reply_flush)


---
### fd\_webserver\_start<!-- {{#callable:fd_webserver_start}} -->
The `fd_webserver_start` function initializes and starts a web server on a specified port with given parameters and callbacks.
- **Inputs**:
    - `portno`: The port number on which the web server will listen for incoming connections.
    - `params`: A structure containing parameters for configuring the HTTP server.
    - `spad`: A pointer to a shared memory allocation descriptor used for server memory management.
    - `ws`: A pointer to a `fd_webserver_t` structure that will be initialized and used to manage the web server state.
    - `cb_arg`: A user-defined argument that will be passed to callback functions.
- **Control Flow**:
    - The function begins by zeroing out the `fd_webserver_t` structure pointed to by `ws` to ensure it starts with a clean state.
    - It assigns the `cb_arg` and `spad` to the corresponding fields in the `ws` structure.
    - A `fd_http_server_callbacks_t` structure is initialized with function pointers for handling HTTP requests and WebSocket events.
    - Memory for the server is allocated using `fd_spad_alloc`, and the server is initialized and joined using `fd_http_server_new` and `fd_http_server_join`.
    - The server is set to listen on the specified port using `fd_http_server_listen`, and a test is performed to ensure the server is listening successfully.
    - The function returns 0 to indicate successful execution.
- **Output**: The function returns an integer value of 0, indicating successful initialization and start of the web server.


---
### fd\_webserver\_poll<!-- {{#callable:fd_webserver_poll}} -->
The `fd_webserver_poll` function polls the HTTP server associated with a given webserver instance to process any pending requests or events.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure representing the webserver instance to be polled.
- **Control Flow**:
    - The function calls `fd_http_server_poll` with the server instance from the `fd_webserver_t` structure and a timeout value of 0.
    - The result of `fd_http_server_poll` is returned directly.
- **Output**: The function returns an integer which is the result of the `fd_http_server_poll` function, indicating the status of the polling operation.


---
### fd\_webserver\_fd<!-- {{#callable:fd_webserver_fd}} -->
The `fd_webserver_fd` function retrieves the file descriptor associated with the HTTP server within a web server context.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure representing the web server context.
- **Control Flow**:
    - The function calls `fd_http_server_fd` with the `server` member of the `fd_webserver_t` structure pointed to by `ws`.
    - It returns the result of the `fd_http_server_fd` function call.
- **Output**: The function returns an integer representing the file descriptor of the HTTP server.


---
### fd\_web\_reply\_append<!-- {{#callable:fd_web_reply_append}} -->
The `fd_web_reply_append` function appends a given text to a web server's quick buffer or directly to the server if the buffer limit is exceeded.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure representing the web server context.
    - `text`: A constant character pointer to the text that needs to be appended.
    - `text_sz`: An unsigned long integer representing the size of the text to be appended.
- **Control Flow**:
    - Check if the current quick buffer size plus the text size is less than or equal to the maximum quick buffer size (`FD_WEBSERVER_QUICK_MAX`).
    - If true, append the text to the quick buffer and update the quick buffer size.
    - If false, flush the current quick buffer to the server using [`fd_web_reply_flush`](#fd_web_reply_flush).
    - Check again if the text size is less than or equal to the maximum quick buffer size.
    - If true, copy the text to the quick buffer and set the quick buffer size to the text size.
    - If false, directly copy the text to the server using `fd_http_server_memcpy`.
- **Output**: Returns 0 to indicate successful execution.
- **Functions called**:
    - [`fd_web_reply_flush`](#fd_web_reply_flush)


---
### fd\_web\_reply\_encode\_base58<!-- {{#callable:fd_web_reply_encode_base58}} -->
The `fd_web_reply_encode_base58` function encodes binary data into a Base58 string and appends it to a web server's reply buffer.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure representing the web server context.
    - `data`: A pointer to the binary data that needs to be encoded.
    - `data_sz`: The size of the binary data in bytes.
- **Control Flow**:
    - Check if the size of the data exceeds 400 bytes; if so, return -1 to prevent excessive computation.
    - Initialize variables and count leading zero bytes in the input data.
    - Calculate the size of a temporary buffer needed for encoding and initialize it to zero.
    - Iterate over the input data, performing division and modulus operations to convert it to Base58, storing results in the buffer.
    - Skip leading zeroes in the buffer and calculate the size of the output Base58 string.
    - Fill the output Base58 string with '1' characters for each leading zero in the input data.
    - Convert the buffer values to Base58 characters using a predefined character set and store them in the output string.
    - Append the resulting Base58 string to the web server's reply buffer using [`fd_web_reply_append`](#fd_web_reply_append).
- **Output**: Returns 0 on success, or -1 if the input data size exceeds 400 bytes.
- **Functions called**:
    - [`fd_web_reply_append`](#fd_web_reply_append)


---
### fd\_web\_reply\_encode\_base64<!-- {{#callable:fd_web_reply_encode_base64}} -->
The `fd_web_reply_encode_base64` function encodes binary data into a Base64 string and appends it to a web server's quick buffer, flushing the buffer if necessary.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure representing the web server context, which contains the buffer to store the encoded data.
    - `data`: A pointer to the binary data that needs to be encoded into Base64.
    - `data_sz`: The size of the binary data in bytes.
- **Control Flow**:
    - Iterates over the input data in chunks of up to 3 bytes.
    - Checks if the quick buffer has enough space for 4 more bytes; if not, it flushes the buffer using [`fd_web_reply_flush`](#fd_web_reply_flush).
    - Encodes each 3-byte chunk into 4 Base64 characters using the `base64_encoding_table`.
    - Handles cases where the remaining data is less than 3 bytes by padding with '=' characters as per Base64 encoding rules.
    - Increments the quick buffer size by 4 for each encoded chunk.
- **Output**: Returns 0 upon successful encoding and appending of the Base64 data to the web server's quick buffer.
- **Functions called**:
    - [`fd_web_reply_flush`](#fd_web_reply_flush)


---
### fd\_web\_reply\_encode\_hex<!-- {{#callable:fd_web_reply_encode_hex}} -->
The `fd_web_reply_encode_hex` function encodes binary data into a hexadecimal string and appends it to a web server's quick buffer, flushing the buffer if necessary.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure representing the web server context where the encoded data will be stored.
    - `data`: A pointer to the binary data that needs to be encoded into hexadecimal format.
    - `data_sz`: The size of the binary data to be encoded, specified as an unsigned long integer.
- **Control Flow**:
    - Iterates over each byte of the input data using a loop that runs from 0 to `data_sz`.
    - Checks if adding two more characters to the quick buffer would exceed its maximum size (`FD_WEBSERVER_QUICK_MAX`); if so, it calls [`fd_web_reply_flush`](#fd_web_reply_flush) to clear the buffer.
    - For each byte, it calculates the hexadecimal representation by splitting the byte into two 4-bit nibbles and using these as indices into the `hex_encoding_table` to get the corresponding hexadecimal characters.
    - Appends the two hexadecimal characters to the quick buffer and increments the buffer size by 2.
- **Output**: Returns 0 to indicate successful encoding and appending of the hexadecimal data.
- **Functions called**:
    - [`fd_web_reply_flush`](#fd_web_reply_flush)


---
### fd\_web\_reply\_sprintf<!-- {{#callable:fd_web_reply_sprintf}} -->
The `fd_web_reply_sprintf` function formats a string using a variable argument list and appends it to a web server's quick buffer, flushing the buffer if necessary.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure representing the web server context.
    - `format`: A C-style format string that specifies how subsequent arguments are converted for output.
    - `...`: A variable number of arguments that are formatted according to the format string.
- **Control Flow**:
    - Calculate the remaining space in the quick buffer of the web server context.
    - Initialize a buffer pointer to the current position in the quick buffer.
    - Start processing the variable argument list using `va_start`.
    - Use `vsnprintf` to format the string into the buffer, checking the return value for errors.
    - If the formatted string fits within the remaining buffer space, update the buffer size and return 0.
    - If the formatted string does not fit, flush the current buffer using [`fd_web_reply_flush`](#fd_web_reply_flush).
    - Reinitialize the buffer pointer to the start of the quick buffer and reformat the string.
    - Check the return value of `vsnprintf` again, and if successful, update the buffer size and return 0.
    - If any formatting error occurs, return -1.
- **Output**: Returns 0 on success, indicating the string was successfully formatted and appended; returns -1 on error, indicating a formatting failure.
- **Functions called**:
    - [`fd_web_reply_flush`](#fd_web_reply_flush)


---
### fd\_web\_reply\_encode\_json\_string<!-- {{#callable:fd_web_reply_encode_json_string}} -->
The function `fd_web_reply_encode_json_string` encodes a given string into a JSON-compatible format and appends it to a web server's response buffer.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure representing the web server context where the encoded JSON string will be appended.
    - `str`: A constant character pointer to the string that needs to be encoded into JSON format.
- **Control Flow**:
    - Initialize a buffer with a starting double quote and set the buffer length to 1.
    - Iterate over each character in the input string `str`.
    - Decode the character as a UTF-8 code point, determining the number of bytes it spans if necessary.
    - For special characters like backslash, double quote, newline, tab, and carriage return, append their escaped versions to the buffer.
    - For characters in the printable ASCII range, append them directly to the buffer.
    - For other characters, encode them as Unicode escape sequences and append to the buffer.
    - If the buffer is close to being full, append its contents to the web server's response buffer and reset the buffer length.
    - Continue processing until the end of the string is reached.
    - Append a closing double quote to the buffer and append the final buffer contents to the web server's response.
- **Output**: Returns 0 on success, or a negative error code if an error occurs during encoding or appending to the web server's response.
- **Functions called**:
    - [`fd_web_reply_append`](#fd_web_reply_append)



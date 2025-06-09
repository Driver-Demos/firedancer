# Purpose
This C header file, `fd_webserver.h`, defines the interface for a web server component within a larger software system. The file provides a structured approach to managing web server operations, including starting the server, handling incoming requests, and managing WebSocket connections. The `fd_webserver` structure encapsulates the server's state, including a pointer to the HTTP server, a shared data structure (`spad`), and a buffer for quick responses. The file includes function declarations for starting the server, polling for requests, and managing WebSocket subscriptions and closures. Additionally, it provides utility functions for constructing and sending HTTP responses, including encoding data in various formats such as Base58, Base64, and hexadecimal.

The header file is designed to be included in other C source files, providing a public API for interacting with the web server component. It includes functions for handling JSON keywords, sending WebSocket messages, and formatting HTTP replies. The presence of macros and typedefs suggests that the file is part of a modular system, allowing for easy integration and extension. The file's organization and function declarations indicate a focus on network communication and data encoding, making it a critical component for applications requiring web-based interactions and real-time data exchange.
# Imports and Dependencies

---
- `fd_methods.h`
- `../../waltz/http/fd_http_server.h`


# Global Variables

---
### un\_fd\_webserver\_json\_keyword
- **Type**: `const char*`
- **Description**: The `un_fd_webserver_json_keyword` is a function that takes a long integer as an argument and returns a constant character pointer. This function is likely used to map an identifier to a corresponding JSON keyword string.
- **Use**: This variable is used to retrieve the JSON keyword string associated with a given identifier.


# Data Structures

---
### fd\_webserver
- **Type**: `struct`
- **Members**:
    - `server`: A pointer to an HTTP server instance.
    - `spad`: A pointer to a shared pad structure.
    - `cb_arg`: A generic pointer for callback arguments.
    - `status_code`: An unsigned integer representing the HTTP status code.
    - `prev_reply_len`: An unsigned long indicating the length of the previous reply.
    - `quick_size`: An unsigned long representing the size of the quick buffer.
    - `quick_buf`: A character array used as a quick buffer with a maximum size defined by FD_WEBSERVER_QUICK_MAX.
- **Description**: The `fd_webserver` structure is designed to encapsulate the state and configuration of a web server instance, including pointers to an HTTP server and shared pad, a callback argument, and various fields for managing HTTP responses. It includes a quick buffer for efficient data handling, with a defined maximum size, and tracks the status code and previous reply length for response management.


---
### fd\_webserver\_t
- **Type**: `struct`
- **Members**:
    - `server`: A pointer to an fd_http_server_t structure, representing the HTTP server instance.
    - `spad`: A pointer to an fd_spad_t structure, used for shared data or state.
    - `cb_arg`: A void pointer for callback arguments, allowing user-defined data to be passed to callbacks.
    - `status_code`: An unsigned integer representing the HTTP status code for responses.
    - `prev_reply_len`: A ulong indicating the length of the previous reply sent.
    - `quick_size`: A ulong representing the size of the quick buffer currently in use.
    - `quick_buf`: A character array used as a buffer for quick operations, with a maximum size defined by FD_WEBSERVER_QUICK_MAX.
- **Description**: The `fd_webserver_t` structure is designed to encapsulate the state and configuration of a web server instance, including pointers to the HTTP server and shared data structures, a callback argument for user-defined data, and various fields for managing HTTP responses and quick buffer operations. It provides a flexible framework for handling web server operations, including response management and data encoding.


# Function Declarations (Public API)

---
### fd\_webserver\_start<!-- {{#callable_declaration:fd_webserver_start}} -->
Start a web server on the specified port with given parameters.
- **Description**: This function initializes and starts a web server on the specified port using the provided server parameters and shared memory allocator. It must be called with a valid `fd_webserver_t` structure, which will be initialized by the function. The function sets up necessary callbacks and allocates memory for the server using the provided shared memory allocator. It is essential to ensure that the `fd_webserver_t` structure and the shared memory allocator are properly initialized before calling this function. The function returns immediately after starting the server, and the server will begin listening for incoming connections on the specified port.
- **Inputs**:
    - `portno`: The port number on which the web server will listen for incoming connections. It must be a valid port number (typically between 1024 and 65535).
    - `params`: A structure containing parameters for configuring the HTTP server. The caller must ensure this structure is properly initialized before passing it to the function.
    - `spad`: A pointer to a shared memory allocator used for allocating server resources. This pointer must not be null, and the allocator must be initialized before use.
    - `ws`: A pointer to an `fd_webserver_t` structure that will be initialized by the function. The caller must provide a valid, uninitialized structure.
    - `cb_arg`: A user-defined argument that will be passed to callback functions. This can be null if no user data is needed.
- **Output**: Returns 0 on successful server start. The `fd_webserver_t` structure is initialized and ready for use.
- **See also**: [`fd_webserver_start`](fd_webserver.c.driver.md#fd_webserver_start)  (Implementation)


---
### fd\_webserver\_poll<!-- {{#callable_declaration:fd_webserver_poll}} -->
Polls the web server for incoming HTTP requests.
- **Description**: Use this function to check for and process any incoming HTTP requests on the specified web server. It should be called regularly in the application's main loop to ensure that the server remains responsive to client requests. The function requires a valid web server object that has been previously initialized and started. It does not block, allowing the application to continue executing other tasks. Ensure that the web server object is not null before calling this function to avoid undefined behavior.
- **Inputs**:
    - `ws`: A pointer to a valid `fd_webserver_t` structure representing the web server to be polled. This parameter must not be null, and the web server should be properly initialized and started before calling this function.
- **Output**: Returns an integer status code from the underlying HTTP server polling operation, which can be used to determine the success or failure of the poll.
- **See also**: [`fd_webserver_poll`](fd_webserver.c.driver.md#fd_webserver_poll)  (Implementation)


---
### fd\_webserver\_fd<!-- {{#callable_declaration:fd_webserver_fd}} -->
Retrieve the file descriptor associated with a web server.
- **Description**: Use this function to obtain the file descriptor for a given web server instance, which can be useful for integrating with event loops or performing low-level socket operations. This function should be called with a valid web server instance that has been properly initialized. It is important to ensure that the web server instance is not null before calling this function to avoid undefined behavior.
- **Inputs**:
    - `ws`: A pointer to a valid `fd_webserver_t` instance. This parameter must not be null, and the web server should be properly initialized before calling this function.
- **Output**: Returns the file descriptor associated with the web server instance. The return value is an integer representing the file descriptor.
- **See also**: [`fd_webserver_fd`](fd_webserver.c.driver.md#fd_webserver_fd)  (Implementation)


---
### fd\_webserver\_json\_keyword<!-- {{#callable_declaration:fd_webserver_json_keyword}} -->
Identifies a JSON keyword and returns its corresponding identifier.
- **Description**: This function is used to map a given JSON keyword to its corresponding identifier, which is useful for handling JSON data in web server applications. It takes a keyword and its size as input and returns a long integer representing the keyword's identifier. If the keyword is not recognized, it returns a predefined constant indicating an unknown keyword. This function is typically used in scenarios where JSON data needs to be parsed and specific actions are taken based on recognized keywords.
- **Inputs**:
    - `keyw`: A pointer to a constant character array representing the JSON keyword. It must not be null, and the array should be at least as long as specified by keyw_sz.
    - `keyw_sz`: The size of the keyword in bytes, represented as a size_t. It should match the actual length of the keyword string. If the size does not correspond to a known keyword, the function will return an unknown identifier.
- **Output**: Returns a long integer representing the identifier of the JSON keyword if recognized, or a constant indicating an unknown keyword if not.
- **See also**: [`fd_webserver_json_keyword`](keywords.c.driver.md#fd_webserver_json_keyword)  (Implementation)


---
### un\_fd\_webserver\_json\_keyword<!-- {{#callable_declaration:un_fd_webserver_json_keyword}} -->
Returns the JSON keyword string corresponding to a given identifier.
- **Description**: This function is used to retrieve the JSON keyword string associated with a specific identifier. It is useful when you need to map an identifier to its corresponding JSON keyword in a web server context. The function expects a valid identifier as input and returns a string representing the JSON keyword. If the identifier does not match any known keywords, the function returns a placeholder string "???". This function is typically used in scenarios where JSON keywords are dynamically determined based on identifiers.
- **Inputs**:
    - `id`: A long integer representing the identifier for which the corresponding JSON keyword is requested. The identifier should match one of the predefined constants representing JSON keywords. If the identifier is not recognized, the function returns "???".
- **Output**: A constant character pointer to the JSON keyword string corresponding to the given identifier, or "???" if the identifier is not recognized.
- **See also**: [`un_fd_webserver_json_keyword`](keywords.c.driver.md#un_fd_webserver_json_keyword)  (Implementation)


---
### fd\_webserver\_method\_generic<!-- {{#callable_declaration:fd_webserver_method_generic}} -->
Processes a generic JSON-RPC method request.
- **Description**: This function handles a JSON-RPC method request by extracting necessary fields from the provided JSON values and executing the corresponding method based on the 'method' field. It expects the JSON-RPC version to be '2.0' and requires an 'id' and 'method' field to be present in the JSON object. If any of these fields are missing or invalid, an error is reported using the provided callback argument. This function is typically used within a web server context to process incoming JSON-RPC requests.
- **Inputs**:
    - `values`: A pointer to a 'json_values' structure containing the JSON-RPC request data. It must not be null and should contain valid JSON data with 'jsonrpc', 'id', and 'method' fields.
    - `cb_arg`: A pointer to a context structure used for callback operations. It must not be null and is expected to be a valid 'fd_rpc_ctx_t' object.
- **Output**: None
- **See also**: [`fd_webserver_method_generic`](fd_rpc_service.c.driver.md#fd_webserver_method_generic)  (Implementation)


---
### fd\_webserver\_ws\_subscribe<!-- {{#callable_declaration:fd_webserver_ws_subscribe}} -->
Subscribes to a WebSocket method based on JSON-RPC request data.
- **Description**: This function processes a JSON-RPC request to subscribe to a WebSocket method, validating the JSON-RPC version and extracting the method and ID from the request. It should be called when a new WebSocket subscription request is received. The function expects the JSON-RPC version to be '2.0' and requires both 'method' and 'id' fields in the JSON data. If the method is recognized, it attempts to subscribe to the specified WebSocket method. If any required fields are missing or the method is unknown, an error response is sent back.
- **Inputs**:
    - `values`: A pointer to a 'struct json_values' containing the JSON-RPC request data. Must not be null.
    - `conn_id`: An unsigned long representing the connection ID for the WebSocket. Must be a valid connection identifier.
    - `cb_arg`: A pointer to a context argument, expected to be a 'fd_rpc_ctx_t' type. Must not be null and should be properly initialized.
- **Output**: Returns 1 if the subscription is successful, otherwise returns 0. Sends an error response if the input is invalid or the method is unknown.
- **See also**: [`fd_webserver_ws_subscribe`](fd_rpc_service.c.driver.md#fd_webserver_ws_subscribe)  (Implementation)


---
### fd\_webserver\_ws\_closed<!-- {{#callable_declaration:fd_webserver_ws_closed}} -->
Handles the closure of a WebSocket connection.
- **Description**: This function should be called when a WebSocket connection identified by `conn_id` is closed. It is responsible for cleaning up any associated resources or subscriptions related to the connection. The function expects a context argument `cb_arg` that provides necessary context for managing the connection closure. This function is typically used in the context of a WebSocket server to ensure that resources are properly released when a client disconnects.
- **Inputs**:
    - `conn_id`: An unsigned long integer representing the unique identifier of the WebSocket connection that has been closed. It must correspond to an active connection that is being tracked.
    - `cb_arg`: A pointer to a context object that provides necessary information for handling the connection closure. This pointer must not be null and should be a valid context used by the WebSocket server.
- **Output**: None
- **See also**: [`fd_webserver_ws_closed`](fd_rpc_service.c.driver.md#fd_webserver_ws_closed)  (Implementation)


---
### fd\_web\_ws\_send<!-- {{#callable_declaration:fd_web_ws_send}} -->
Sends a WebSocket message over a specified connection.
- **Description**: Use this function to send a WebSocket message over an existing connection identified by `conn_id` through the web server represented by `ws`. This function should be called after preparing the message content using the appropriate reply functions. It ensures that any pending reply data is flushed before sending the WebSocket message. The function does not return a value and assumes that the connection is valid and active.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure representing the web server. Must not be null, and the server should be properly initialized and running.
    - `conn_id`: An unsigned long integer representing the connection ID over which the WebSocket message will be sent. It should correspond to an active WebSocket connection.
- **Output**: None
- **See also**: [`fd_web_ws_send`](fd_webserver.c.driver.md#fd_web_ws_send)  (Implementation)


---
### fd\_web\_reply\_new<!-- {{#callable_declaration:fd_web_reply_new}} -->
Initialize a new HTTP reply for the web server.
- **Description**: This function prepares the web server for sending a new HTTP reply by resetting relevant fields in the `fd_webserver_t` structure. It sets the status code to 200 (OK), clears any previous reply length, and truncates the server's stage to zero. This function should be called before constructing a new HTTP response to ensure that the server state is correctly initialized for the new reply.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure representing the web server. This must not be null, and the structure should be properly initialized before calling this function.
- **Output**: None
- **See also**: [`fd_web_reply_new`](fd_webserver.c.driver.md#fd_web_reply_new)  (Implementation)


---
### fd\_web\_reply\_error<!-- {{#callable_declaration:fd_web_reply_error}} -->
Send a JSON-RPC error response to the client.
- **Description**: This function is used to send a JSON-RPC formatted error response to a client connected to the web server. It should be called when an error needs to be communicated back to the client, using the specified error code and message. The function formats the error response in JSON-RPC 2.0 format, including the error code, message, and an identifier for the call. It is important to ensure that the `fd_webserver_t` instance is properly initialized and that the `call_id` corresponds to the request being responded to. This function does not return a value and does not handle invalid input explicitly, so care should be taken to provide valid parameters.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure representing the web server instance. Must not be null.
    - `errcode`: An integer representing the error code to be included in the JSON-RPC error response.
    - `text`: A string containing the error message to be included in the JSON-RPC error response. Must not be null.
    - `call_id`: A string representing the identifier of the call being responded to. Must not be null.
- **Output**: None
- **See also**: [`fd_web_reply_error`](fd_webserver.c.driver.md#fd_web_reply_error)  (Implementation)


---
### fd\_web\_reply\_append<!-- {{#callable_declaration:fd_web_reply_append}} -->
Appends text to the web server's reply buffer.
- **Description**: Use this function to append a specified amount of text to the web server's reply buffer. It is suitable for building HTTP responses incrementally. If the text fits within the remaining space of the quick buffer, it is appended directly. Otherwise, the current buffer is flushed, and the text is either added to the buffer or sent directly to the server if it exceeds the buffer's maximum size. This function should be called after initializing the web server and before sending the response.
- **Inputs**:
    - `ws`: A pointer to an initialized `fd_webserver_t` structure representing the web server. Must not be null.
    - `text`: A pointer to the text data to append. The caller retains ownership and must ensure it is valid for the duration of the call. Must not be null.
    - `text_sz`: The size in bytes of the text to append. Must be a non-negative value.
- **Output**: Returns 0 on success. The function does not return error codes for invalid input, but behavior is undefined if preconditions are not met.
- **See also**: [`fd_web_reply_append`](fd_webserver.c.driver.md#fd_web_reply_append)  (Implementation)


---
### fd\_web\_reply\_encode\_base58<!-- {{#callable_declaration:fd_web_reply_encode_base58}} -->
Encodes binary data into a Base58 string and appends it to a web server reply.
- **Description**: Use this function to encode binary data into a Base58 format and append the resulting string to the current reply being constructed for a web server. This function is useful when you need to transmit binary data in a text-friendly format over HTTP. It must be called with a valid web server context and data to encode. The function will not process data sizes greater than 400 bytes, returning an error in such cases. Ensure that the web server context is properly initialized before calling this function.
- **Inputs**:
    - `ws`: A pointer to an initialized fd_webserver_t structure representing the web server context. Must not be null.
    - `data`: A pointer to the binary data to be encoded. The caller retains ownership and it must not be null.
    - `data_sz`: The size of the binary data in bytes. Must be 400 or less; otherwise, the function returns an error.
- **Output**: Returns 0 on success, or -1 if the data size exceeds 400 bytes.
- **See also**: [`fd_web_reply_encode_base58`](fd_webserver.c.driver.md#fd_web_reply_encode_base58)  (Implementation)


---
### fd\_web\_reply\_encode\_base64<!-- {{#callable_declaration:fd_web_reply_encode_base64}} -->
Encodes data into Base64 format and appends it to the webserver's reply buffer.
- **Description**: This function is used to encode a given block of data into Base64 format and append the encoded result to the quick reply buffer of a webserver instance. It should be called when there is a need to include Base64 encoded data in a webserver response. The function manages the buffer size and flushes it if necessary to accommodate new data. It is important to ensure that the webserver instance is properly initialized before calling this function.
- **Inputs**:
    - `ws`: A pointer to an initialized fd_webserver_t structure. This must not be null, and the webserver should be in a state ready to append data to its reply buffer.
    - `data`: A pointer to the data to be encoded. The data should be a valid memory block of at least data_sz bytes. The caller retains ownership of the data.
    - `data_sz`: The size of the data to be encoded, in bytes. It should be a non-negative value.
- **Output**: Returns 0 on success. The encoded data is appended to the webserver's quick reply buffer.
- **See also**: [`fd_web_reply_encode_base64`](fd_webserver.c.driver.md#fd_web_reply_encode_base64)  (Implementation)


---
### fd\_web\_reply\_encode\_hex<!-- {{#callable_declaration:fd_web_reply_encode_hex}} -->
Encodes binary data as a hexadecimal string and appends it to the webserver's reply buffer.
- **Description**: This function is used to convert binary data into a hexadecimal string representation and append it to the reply buffer of a webserver instance. It is typically called when preparing a response that requires data to be encoded in hexadecimal format. The function ensures that the reply buffer does not exceed its maximum capacity by flushing the buffer when necessary. It should be used when the webserver is actively managing replies and the buffer is expected to handle additional data. The function assumes that the webserver instance has been properly initialized and is in a state ready to append data.
- **Inputs**:
    - `ws`: A pointer to an initialized fd_webserver_t structure. This parameter must not be null, and the webserver instance should be ready to handle reply data.
    - `data`: A pointer to the binary data to be encoded. The caller retains ownership of the data, and it must not be null.
    - `data_sz`: The size of the binary data in bytes. It should accurately represent the number of bytes to encode.
- **Output**: Returns 0 on successful encoding and appending of the data.
- **See also**: [`fd_web_reply_encode_hex`](fd_webserver.c.driver.md#fd_web_reply_encode_hex)  (Implementation)


---
### fd\_web\_reply\_sprintf<!-- {{#callable_declaration:fd_web_reply_sprintf}} -->
Formats and appends a formatted string to the web server's reply buffer.
- **Description**: Use this function to append a formatted string to the current reply buffer of a web server. It is designed to handle formatted output similar to printf, using a format string and a variable number of arguments. The function attempts to append the formatted string to the buffer, flushing the buffer if necessary to accommodate the new data. It should be called when constructing a response that requires formatted text. Ensure that the web server structure is properly initialized before calling this function.
- **Inputs**:
    - `ws`: A pointer to an initialized fd_webserver_t structure. Must not be null, as it represents the web server instance whose reply buffer is being modified.
    - `format`: A printf-style format string that specifies how subsequent arguments are converted for output. Must not be null.
    - `...`: A variable number of arguments that are formatted according to the format string. The types and number of these arguments must match the format specifiers in the format string.
- **Output**: Returns 0 on success, indicating the string was successfully appended to the buffer. Returns -1 if an error occurs, such as a formatting error or if the formatted string exceeds the buffer's capacity.
- **See also**: [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)  (Implementation)


---
### fd\_web\_reply\_encode\_json\_string<!-- {{#callable_declaration:fd_web_reply_encode_json_string}} -->
Encodes a string as a JSON string and appends it to a web server reply.
- **Description**: Use this function to encode a given string into a JSON-compatible format and append it to the current reply being constructed for a web server. This function handles special characters by escaping them appropriately and ensures that the string is enclosed in double quotes. It must be called with a valid web server context and a non-null string. If the string contains invalid UTF-8 sequences, the function will return an error. The function appends the encoded string in chunks, ensuring that the buffer does not overflow.
- **Inputs**:
    - `ws`: A pointer to an fd_webserver_t structure representing the web server context. Must not be null. The function appends the encoded string to the reply associated with this context.
    - `str`: A pointer to a null-terminated string to be encoded. Must not be null. The string should be valid UTF-8, as invalid sequences will cause the function to return an error.
- **Output**: Returns 0 on success, or a negative error code if an error occurs, such as invalid UTF-8 input or an append failure.
- **See also**: [`fd_web_reply_encode_json_string`](fd_webserver.c.driver.md#fd_web_reply_encode_json_string)  (Implementation)



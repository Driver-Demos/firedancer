# Purpose
The provided C header file defines the interface for a WebSocket-capable HTTP server, designed to efficiently stream output messages to multiple connected clients. This server is particularly suited for applications that require real-time data streaming, such as serving ongoing RPC data to subscribers or providing WebSocket streams for browser-based GUIs. The server is optimized for high performance and low latency, utilizing a ring buffer for outgoing messages to manage memory efficiently and automatically evict slow clients that cannot keep up with the data flow.

Key components of this server include structures and functions for managing HTTP and WebSocket connections, handling incoming requests, and sending responses. The server operates in a single-threaded event loop, making it suitable for environments where simplicity and performance are critical. The header file defines various constants for HTTP methods and connection close reasons, structures for server parameters, requests, and responses, and callback functions for handling different stages of connection and message processing. The server's API allows for the creation, management, and deletion of server instances, as well as the ability to send and broadcast messages to clients. This file serves as a comprehensive interface for developers to integrate and utilize the HTTP server in their applications, providing both flexibility and control over the server's behavior and performance.
# Imports and Dependencies

---
- `../../util/fd_util_base.h`


# Global Variables

---
### fd\_http\_server\_connection\_close\_reason\_str
- **Type**: `FD_FN_CONST char const *`
- **Description**: The `fd_http_server_connection_close_reason_str` function returns a human-readable string that describes the reason for closing an HTTP connection, based on a given reason code. This function is part of the HTTP server's interface to provide meaningful descriptions for various connection closure scenarios.
- **Use**: This function is used to translate a connection closure reason code into a descriptive string for logging or debugging purposes.


---
### fd\_http\_server\_method\_str
- **Type**: `function pointer`
- **Description**: `fd_http_server_method_str` is a function that takes an unsigned character (`uchar`) representing an HTTP method code and returns a constant character pointer to the string representation of that method. This function is used to map HTTP method codes, such as GET, POST, and OPTIONS, to their corresponding string names.
- **Use**: This function is used to convert HTTP method codes into human-readable string representations for logging or debugging purposes.


---
### fd\_http\_server\_new
- **Type**: `function pointer`
- **Description**: `fd_http_server_new` is a function that initializes a new HTTP server instance using a specified shared memory region, server parameters, and callback functions. It is designed to set up the server's state in a memory region provided by the caller, allowing for efficient handling of HTTP and WebSocket connections.
- **Use**: This function is used to create and initialize an HTTP server instance with specific configurations and callback handlers.


---
### fd\_http\_server\_join
- **Type**: `fd_http_server_t *`
- **Description**: The `fd_http_server_join` function returns a pointer to an `fd_http_server_t` structure, which represents the state of an HTTP server. This function is used to join a caller to an existing HTTP server state, allowing the caller to interact with the server.
- **Use**: This variable is used to obtain a local handle to an HTTP server state, enabling the caller to perform operations on the server.


---
### fd\_http\_server\_leave
- **Type**: `function pointer`
- **Description**: `fd_http_server_leave` is a function pointer that is used to leave the caller's current local join to an HTTP server state. It returns a pointer to the memory region holding the state on success and NULL on failure.
- **Use**: This function is used to disassociate a caller from an HTTP server state, effectively leaving the server context.


---
### fd\_http\_server\_delete
- **Type**: `function pointer`
- **Description**: `fd_http_server_delete` is a function pointer that points to a function designed to unformat a memory region holding an HTTP server state. It takes a single argument, `shhttp`, which is a pointer to the memory region, and returns a pointer to the memory region on success or NULL on failure.
- **Use**: This function is used to delete or unformat the memory region associated with an HTTP server state, ensuring that the caller regains ownership of the memory region.


---
### fd\_http\_server\_listen
- **Type**: `fd_http_server_t *`
- **Description**: The `fd_http_server_listen` variable is a function pointer that returns a pointer to an `fd_http_server_t` structure. It is used to initiate the listening process for an HTTP server on a specified address and port. This function is part of a WebSocket-capable HTTP server designed to efficiently stream messages to multiple clients.
- **Use**: This variable is used to start the server listening on a given network address and port, enabling it to accept incoming connections.


# Data Structures

---
### fd\_http\_server\_params
- **Type**: `struct`
- **Members**:
    - `max_connection_cnt`: Maximum number of concurrent HTTP/1.1 connections open, which are not persistent and close after serving one request.
    - `max_ws_connection_cnt`: Maximum number of concurrent websocket connections open.
    - `max_request_len`: Maximum total length of an HTTP request, including the terminating \r\n\r\n and any body in the case of a POST.
    - `max_ws_recv_frame_len`: Maximum size of an incoming websocket frame from the client, which must be greater than or equal to max_request_len.
    - `max_ws_send_frame_cnt`: Maximum number of outgoing websocket frames that can be queued before the client is disconnected.
    - `outgoing_buffer_sz`: Size of the outgoing data ring used to stage outgoing HTTP response bodies and WebSocket frames.
- **Description**: The `fd_http_server_params` structure defines the configuration parameters for an HTTP server capable of handling both HTTP/1.1 and WebSocket connections. It specifies limits on the number of concurrent connections, the maximum size of HTTP requests and WebSocket frames, and the size of the buffer used for outgoing data. These parameters are crucial for managing server resources and ensuring efficient handling of client requests and data transmission.


---
### fd\_http\_server\_params\_t
- **Type**: `struct`
- **Members**:
    - `max_connection_cnt`: Maximum number of concurrent HTTP/1.1 connections that can be open at any time.
    - `max_ws_connection_cnt`: Maximum number of concurrent WebSocket connections that can be open at any time.
    - `max_request_len`: Maximum length of an HTTP request, including headers and body.
    - `max_ws_recv_frame_len`: Maximum size of an incoming WebSocket frame from a client.
    - `max_ws_send_frame_cnt`: Maximum number of outgoing WebSocket frames that can be queued before disconnecting the client.
    - `outgoing_buffer_sz`: Size of the buffer used to stage outgoing HTTP response bodies and WebSocket frames.
- **Description**: The `fd_http_server_params_t` structure defines the configuration parameters necessary for setting up an HTTP server capable of handling both HTTP/1.1 and WebSocket connections. It specifies limits on the number of concurrent connections, the maximum size of requests and WebSocket frames, and the size of the buffer used for outgoing messages. These parameters are crucial for managing server resources and ensuring efficient handling of client requests and data streaming.


---
### fd\_http\_server\_request
- **Type**: `struct`
- **Members**:
    - `connection_id`: Unique identifier for the connection, which can be recycled after the connection is closed.
    - `method`: Indicates the HTTP method of the request, using predefined constants.
    - `path`: NUL-terminated string representing the path component of the request, which may contain arbitrary content.
    - `ctx`: User-provided context pointer passed during HTTP server construction.
    - `headers`: Contains HTTP request headers such as Content-Type and Accept-Encoding, and a flag for WebSocket upgrade.
    - `post`: Contains the body of the HTTP request and its length, specifically for POST requests.
- **Description**: The `fd_http_server_request` structure represents an HTTP request received by the server, encapsulating details such as the connection ID, HTTP method, request path, and user context. It also includes a nested structure for headers, which holds information about the Content-Type and Accept-Encoding headers, and a flag indicating if the request should be upgraded to a WebSocket. Additionally, it contains a union for handling POST request bodies, providing access to the body data and its length. This structure is essential for processing incoming HTTP requests and managing their associated data within the server.


---
### fd\_http\_server\_request\_t
- **Type**: `struct`
- **Members**:
    - `connection_id`: Unique identifier for the connection, used to track the connection's lifecycle.
    - `method`: Indicates the HTTP method of the request, such as GET or POST.
    - `path`: NUL-terminated string representing the path component of the request.
    - `ctx`: User-provided context pointer associated with the HTTP server.
    - `headers`: Contains HTTP headers like Content-Type and Accept-Encoding, and a flag for WebSocket upgrade.
    - `post`: Contains the body and length of the HTTP request for POST methods.
- **Description**: The `fd_http_server_request_t` structure represents an HTTP request received by the server, encapsulating details such as the connection ID, HTTP method, request path, and user context. It also includes a nested structure for headers, which holds information about the request's Content-Type, Accept-Encoding, and whether a WebSocket upgrade is requested. For POST requests, it contains a union with the request body and its length, allowing the server to handle and process incoming HTTP requests efficiently.


---
### fd\_http\_server\_response
- **Type**: `struct`
- **Members**:
    - `status`: Status code of the HTTP response.
    - `upgrade_websocket`: Indicates if a websocket upgrade response should be sent.
    - `content_type`: Content-Type header for the HTTP response.
    - `cache_control`: Cache-Control header for the HTTP response.
    - `content_encoding`: Content-Encoding header for the HTTP response.
    - `access_control_allow_origin`: Access-Control-Allow-Origin header for CORS.
    - `access_control_allow_methods`: Access-Control-Allow-Methods header for CORS.
    - `access_control_allow_headers`: Access-Control-Allow-Headers header for CORS.
    - `access_control_max_age`: Access-Control-Max-Age header for CORS.
    - `static_body`: Pointer to the static response body data.
    - `static_body_len`: Length of the static response body data.
    - `_body_off`: Internal offset where the body starts in the outgoing buffer.
    - `_body_len`: Internal length of the body in the outgoing buffer.
- **Description**: The `fd_http_server_response` structure is used to define the parameters and content of an HTTP response generated by the server. It includes fields for standard HTTP headers such as status code, content type, and cache control, as well as fields for handling CORS (Cross-Origin Resource Sharing) headers. Additionally, it supports static response bodies, which must have a lifetime that outlives the HTTP server. The structure also contains internal fields for managing the offset and length of the response body within the server's outgoing buffer, which are used for efficient data transmission.


---
### fd\_http\_server\_response\_t
- **Type**: `struct`
- **Members**:
    - `status`: Status code of the HTTP response.
    - `upgrade_websocket`: Indicates if the connection should be upgraded to a WebSocket.
    - `content_type`: Content-Type header for the HTTP response.
    - `cache_control`: Cache-Control header for the HTTP response.
    - `content_encoding`: Content-Encoding header for the HTTP response.
    - `access_control_allow_origin`: Access-Control-Allow-Origin header for CORS.
    - `access_control_allow_methods`: Access-Control-Allow-Methods header for CORS.
    - `access_control_allow_headers`: Access-Control-Allow-Headers header for CORS.
    - `access_control_max_age`: Access-Control-Max-Age header for CORS.
    - `static_body`: Pointer to the static response body data.
    - `static_body_len`: Length of the static response body data.
    - `_body_off`: Internal offset into the outgoing buffer where the body starts.
    - `_body_len`: Internal length of the body in the outgoing buffer.
- **Description**: The `fd_http_server_response_t` structure represents an HTTP response issued by the server handler function in response to an HTTP request. It includes fields for setting the HTTP status code, headers such as Content-Type and Cache-Control, and CORS-related headers. The structure also allows for the specification of a static response body, which must outlive the HTTP server, or the use of a staged body managed by the server. Additionally, it supports WebSocket upgrades by setting the `upgrade_websocket` field. Internal fields `_body_off` and `_body_len` are used for managing the outgoing buffer.


---
### fd\_http\_server\_callbacks
- **Type**: `struct`
- **Members**:
    - `request`: A callback function to handle incoming HTTP requests and return a response.
    - `open`: A callback function called when a regular HTTP connection is established.
    - `close`: A callback function called when an HTTP request is closed, indicating the reason for closure.
    - `ws_open`: A callback function called when a WebSocket connection is opened.
    - `ws_message`: A callback function called when a WebSocket message is received, providing the message data and length.
    - `ws_close`: A callback function called when a WebSocket connection is closed, indicating the reason for closure.
- **Description**: The `fd_http_server_callbacks` structure defines a set of callback functions used by an HTTP server to handle various events related to HTTP and WebSocket connections. These callbacks include handling incoming HTTP requests, managing the lifecycle of HTTP and WebSocket connections (open and close events), and processing WebSocket messages. Each callback function is associated with specific events and is designed to be invoked by the server to perform custom operations, such as generating responses or handling connection-specific logic. The structure allows for flexible and customizable server behavior by enabling the user to define their own implementations for these events.


---
### fd\_http\_server\_callbacks\_t
- **Type**: `struct`
- **Members**:
    - `request`: A callback function to handle incoming HTTP requests and return a response.
    - `open`: A callback function called when a regular HTTP connection is established.
    - `close`: A callback function called when an HTTP request is closed.
    - `ws_open`: A callback function called when a WebSocket connection is opened.
    - `ws_message`: A callback function called when a WebSocket message is received.
    - `ws_close`: A callback function called when a WebSocket connection is closed.
- **Description**: The `fd_http_server_callbacks_t` structure defines a set of callback functions used by the HTTP server to handle various events such as incoming HTTP requests, connection establishment, and WebSocket interactions. Each member of this structure is a function pointer that allows the server to execute user-defined logic in response to these events, providing flexibility in how the server processes requests and manages connections.


---
### fd\_http\_server\_t
- **Type**: `typedef struct fd_http_server_private fd_http_server_t;`
- **Members**:
    - `fd_http_server_private`: An opaque structure representing the internal state and data of the HTTP server.
- **Description**: The `fd_http_server_t` is a typedef for an opaque structure `fd_http_server_private`, which encapsulates the internal state and data of a WebSocket-capable HTTP server. This server is designed to efficiently stream output messages to multiple connected clients, supporting both HTTP and WebSocket protocols. It is optimized for high-performance scenarios where messages need to be broadcasted to many clients, such as serving RPC data to subscribers or providing a WebSocket stream for browser-based GUIs. The server uses a ring buffer for outgoing messages, automatically managing memory and evicting slow clients to maintain performance. The server is intended to be used in a single-threaded event loop and requires frequent polling to handle connections and data transmission.


# Function Declarations (Public API)

---
### fd\_http\_server\_connection\_close\_reason\_str<!-- {{#callable_declaration:fd_http_server_connection_close_reason_str}} -->
Returns a human-readable string describing the reason for a connection closure.
- **Description**: Use this function to obtain a descriptive string for a given connection closure reason code. This is useful for logging or debugging purposes when you need to understand why a connection was closed. The function maps predefined reason codes to their corresponding descriptions. If an unrecognized reason code is provided, the function returns "unknown".
- **Inputs**:
    - `reason`: An integer representing the reason code for a connection closure. Must be one of the predefined FD_HTTP_SERVER_CONNECTION_CLOSE_* constants. If the reason code is not recognized, the function returns "unknown".
- **Output**: A constant character pointer to a string describing the reason for the connection closure, or "unknown" if the reason code is not recognized.
- **See also**: [`fd_http_server_connection_close_reason_str`](fd_http_server.c.driver.md#fd_http_server_connection_close_reason_str)  (Implementation)


---
### fd\_http\_server\_method\_str<!-- {{#callable_declaration:fd_http_server_method_str}} -->
Convert an HTTP method code to its string representation.
- **Description**: Use this function to obtain the string representation of an HTTP method code, which is useful for logging or debugging purposes. The function accepts a method code and returns the corresponding HTTP method as a string. If the method code is not recognized, it returns "unknown". This function is typically used in the context of handling HTTP requests where method codes are defined as constants.
- **Inputs**:
    - `method`: An unsigned character representing the HTTP method code. Valid values are FD_HTTP_SERVER_METHOD_GET (0) and FD_HTTP_SERVER_METHOD_POST (1). If the method code is not recognized, the function returns "unknown".
- **Output**: A constant string representing the HTTP method name (e.g., "GET", "POST") or "unknown" if the method code is not recognized.
- **See also**: [`fd_http_server_method_str`](fd_http_server.c.driver.md#fd_http_server_method_str)  (Implementation)


---
### fd\_http\_server\_align<!-- {{#callable_declaration:fd_http_server_align}} -->
Return the alignment requirement for an HTTP server memory region.
- **Description**: Use this function to determine the alignment requirement for a memory region that will hold an HTTP server. This is necessary when allocating memory for the server to ensure that the memory is correctly aligned, which is a prerequisite for the server's proper operation. The function is constant and does not depend on any input parameters, making it straightforward to use whenever you need to allocate or verify memory alignment for an HTTP server.
- **Inputs**: None
- **Output**: Returns the alignment requirement as an unsigned long integer.
- **See also**: [`fd_http_server_align`](fd_http_server.c.driver.md#fd_http_server_align)  (Implementation)


---
### fd\_http\_server\_footprint<!-- {{#callable_declaration:fd_http_server_footprint}} -->
Calculate the memory footprint required for an HTTP server with specified parameters.
- **Description**: Use this function to determine the amount of memory needed to allocate for an HTTP server based on the provided parameters. This is useful for planning memory allocation before initializing the server. The function calculates the total memory footprint by considering various server components such as connection pools, WebSocket frames, and buffers. It is important to ensure that the parameters provided are within acceptable limits to avoid unexpected behavior.
- **Inputs**:
    - `params`: A structure containing configuration parameters for the HTTP server, such as maximum connection counts and buffer sizes. The values must be set appropriately to reflect the intended server capacity and performance requirements.
- **Output**: Returns the total memory footprint in bytes required to accommodate the server with the given parameters.
- **See also**: [`fd_http_server_footprint`](fd_http_server.c.driver.md#fd_http_server_footprint)  (Implementation)


---
### fd\_http\_server\_new<!-- {{#callable_declaration:fd_http_server_new}} -->
Creates a new HTTP server instance with specified parameters and callbacks.
- **Description**: This function initializes a new HTTP server instance using the provided shared memory region, server parameters, and callback functions. It is designed for use in a single-threaded event loop and is capable of handling both HTTP and WebSocket connections. The function must be called with a properly aligned memory region, and the parameters must be set such that the maximum WebSocket receive frame length is not less than the maximum request length. If any of these conditions are not met, the function will return NULL and log a warning. The server is optimized for streaming output messages to multiple clients and includes built-in memory management for outgoing messages.
- **Inputs**:
    - `shmem`: A pointer to the shared memory region where the server state will be stored. Must not be null and must be aligned according to fd_http_server_align(). The caller retains ownership of this memory.
    - `params`: A structure containing configuration parameters for the server, such as maximum connection counts and buffer sizes. The max_ws_recv_frame_len must be greater than or equal to max_request_len.
    - `callbacks`: A structure containing callback functions for handling HTTP requests, connection events, and WebSocket messages. These callbacks are essential for the server's operation.
    - `callback_ctx`: A user-defined context pointer that will be passed to callback functions. This can be used to maintain state or pass additional information to the callbacks.
- **Output**: Returns a pointer to the initialized HTTP server instance on success, or NULL on failure if preconditions are not met.
- **See also**: [`fd_http_server_new`](fd_http_server.c.driver.md#fd_http_server_new)  (Implementation)


---
### fd\_http\_server\_join<!-- {{#callable_declaration:fd_http_server_join}} -->
Join an HTTP server state from a shared memory region.
- **Description**: This function allows a caller to join an HTTP server state using a pointer to a shared memory region. It is essential to ensure that the memory region is properly aligned and initialized before calling this function. The function checks for a valid magic number to confirm the integrity of the server state. If the memory region is not correctly aligned, initialized, or if the pointer is null, the function will return null and log a warning. This function is typically used after the server state has been created and formatted with the appropriate alignment and footprint.
- **Inputs**:
    - `shhttp`: A pointer to the shared memory region holding the HTTP server state. Must not be null and must be aligned according to fd_http_server_align(). The memory region should be properly initialized with a valid magic number. If these conditions are not met, the function returns null.
- **Output**: Returns a pointer to the local handle of the joined HTTP server state on success, or null on failure.
- **See also**: [`fd_http_server_join`](fd_http_server.c.driver.md#fd_http_server_join)  (Implementation)


---
### fd\_http\_server\_leave<!-- {{#callable_declaration:fd_http_server_leave}} -->
Leaves the current local join to an HTTP server state.
- **Description**: This function is used to leave a previously joined HTTP server state, effectively ending the caller's association with that server state. It should be called when the caller no longer needs to interact with the server state, ensuring that resources are properly released. The function must be called with a valid pointer to an `fd_http_server_t` structure that represents the current join. If the provided pointer is null, the function logs a warning and returns null, indicating that the operation was not successful.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` structure representing the current local join to an HTTP server state. Must not be null. If null, the function logs a warning and returns null.
- **Output**: Returns a pointer to the memory region holding the server state on success, or null if the input was invalid.
- **See also**: [`fd_http_server_leave`](fd_http_server.c.driver.md#fd_http_server_leave)  (Implementation)


---
### fd\_http\_server\_delete<!-- {{#callable_declaration:fd_http_server_delete}} -->
Unformats a memory region holding an HTTP server state.
- **Description**: Use this function to release the memory region previously formatted to hold an HTTP server state, ensuring that no threads are currently joined to the server. This function should be called when the server is no longer needed, and it returns ownership of the memory region back to the caller. It is important to ensure that the pointer provided is correctly aligned and represents a valid HTTP server state; otherwise, the function will log a warning and return NULL.
- **Inputs**:
    - `shhttp`: A pointer to the memory region holding the HTTP server state. It must be non-null, correctly aligned according to fd_http_server_align(), and represent a valid HTTP server state. If these conditions are not met, the function logs a warning and returns NULL.
- **Output**: Returns a pointer to the memory region on success, indicating that the caller now owns the memory. Returns NULL on failure, logging the reason for the failure.
- **See also**: [`fd_http_server_delete`](fd_http_server.c.driver.md#fd_http_server_delete)  (Implementation)


---
### fd\_http\_server\_fd<!-- {{#callable_declaration:fd_http_server_fd}} -->
Retrieve the file descriptor of the HTTP server.
- **Description**: Use this function to obtain the file descriptor associated with the HTTP server, which is necessary for polling incoming connections and data. This function should be called when you need to interact with the server's socket directly, such as integrating with an event loop or performing custom I/O operations. Ensure that the `http` parameter is a valid pointer to an initialized `fd_http_server_t` structure.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` structure representing the HTTP server. Must not be null and should point to a valid, initialized server instance.
- **Output**: Returns the integer file descriptor associated with the HTTP server's socket.
- **See also**: [`fd_http_server_fd`](fd_http_server.c.driver.md#fd_http_server_fd)  (Implementation)


---
### fd\_http\_server\_listen<!-- {{#callable_declaration:fd_http_server_listen}} -->
Start listening for incoming HTTP connections on a specified address and port.
- **Description**: Use this function to configure the HTTP server to listen for incoming connections on a specified IP address and port. This function must be called after the server has been properly initialized and joined. It sets up the server's socket in non-blocking mode and prepares it to accept incoming connections. Ensure that the address and port are valid and not already in use by another service. The server will be ready to handle connections once this function returns successfully.
- **Inputs**:
    - `http`: A pointer to an initialized and joined fd_http_server_t structure. Must not be null. The server configuration and state are managed through this structure.
    - `address`: The IP address on which the server should listen, in network byte order. It should be a valid IPv4 address.
    - `port`: The port number on which the server should listen, in host byte order. It should be a valid port number, typically greater than 1024 to avoid requiring root privileges.
- **Output**: Returns a pointer to the fd_http_server_t structure on success, or logs an error and terminates the program on failure.
- **See also**: [`fd_http_server_listen`](fd_http_server.c.driver.md#fd_http_server_listen)  (Implementation)


---
### fd\_http\_server\_close<!-- {{#callable_declaration:fd_http_server_close}} -->
Close an active HTTP connection.
- **Description**: This function forcibly closes an active HTTP connection identified by the given connection ID. It should be used when a connection needs to be terminated immediately, without a graceful shutdown. The connection ID must correspond to an open connection within the valid range. After closure, the connection ID is released and may be reused for future connections. If a close callback is registered with the server, it will be invoked with the specified reason for closure.
- **Inputs**:
    - `http`: A pointer to an fd_http_server_t structure representing the HTTP server. Must not be null.
    - `conn_id`: The unique identifier for the connection to be closed. Must be an open connection ID within the range [0, max_connection_cnt).
    - `reason`: An integer code indicating the reason for closing the connection. Should be one of the predefined FD_HTTP_SERVER_CONNECTION_CLOSE_* constants.
- **Output**: None
- **See also**: [`fd_http_server_close`](fd_http_server.c.driver.md#fd_http_server_close)  (Implementation)


---
### fd\_http\_server\_ws\_close<!-- {{#callable_declaration:fd_http_server_ws_close}} -->
Closes an active WebSocket connection.
- **Description**: Use this function to forcibly terminate an active WebSocket connection identified by its connection ID. This function should be called when you need to close a WebSocket connection for any reason, such as an error or a client request. The connection ID must be valid and within the range of open WebSocket connections. After calling this function, the connection ID is released and may be reused for future connections. If a `ws_close` callback is registered with the server, it will be invoked with the specified reason for closure.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` structure representing the HTTP server. Must not be null.
    - `ws_conn_id`: The unique identifier for the WebSocket connection to be closed. Must be within the range [0, max_ws_connection_cnt).
    - `reason`: An integer representing the reason for closing the connection. Should be one of the predefined `FD_HTTP_SERVER_CONNECTION_CLOSE_*` codes.
- **Output**: None
- **See also**: [`fd_http_server_ws_close`](fd_http_server.c.driver.md#fd_http_server_ws_close)  (Implementation)


---
### fd\_http\_server\_stage\_trunc<!-- {{#callable_declaration:fd_http_server_stage_trunc}} -->
Truncates the staged data in the HTTP server's outgoing buffer to a specified length.
- **Description**: Use this function to adjust the length of the data currently staged in the HTTP server's outgoing buffer. This is useful when you need to discard part of the staged data before sending it to clients. It must be called after data has been staged using functions like fd_http_server_printf or fd_http_server_memcpy, and before the data is sent using fd_http_server_send or fd_http_server_oring_broadcast. This function does not send or broadcast the data; it only modifies the length of the staged data.
- **Inputs**:
    - `http`: A pointer to an fd_http_server_t structure representing the HTTP server. Must not be null, and the server should be properly initialized and joined.
    - `len`: The new length to truncate the staged data to. It should be less than or equal to the current length of the staged data.
- **Output**: None
- **See also**: [`fd_http_server_stage_trunc`](fd_http_server.c.driver.md#fd_http_server_stage_trunc)  (Implementation)


---
### fd\_http\_server\_stage\_len<!-- {{#callable_declaration:fd_http_server_stage_len}} -->
Retrieve the length of the staged data in the HTTP server.
- **Description**: Use this function to obtain the current length of the data that has been staged in the HTTP server's outgoing buffer. This is useful for determining how much data is ready to be sent to clients. It should be called after data has been staged using functions like fd_http_server_printf or fd_http_server_memcpy, and before sending or broadcasting the data. The function assumes that the HTTP server has been properly initialized and joined.
- **Inputs**:
    - `http`: A pointer to an fd_http_server_t structure representing the HTTP server. Must not be null, and the server should be properly initialized and joined before calling this function.
- **Output**: Returns the length of the data currently staged in the server's outgoing buffer as an unsigned long integer.
- **See also**: [`fd_http_server_stage_len`](fd_http_server.c.driver.md#fd_http_server_stage_len)  (Implementation)


---
### fd\_http\_server\_printf<!-- {{#callable_declaration:fd_http_server_printf}} -->
Appends a formatted string to the HTTP server's outgoing ring buffer.
- **Description**: Use this function to format and append a string to the staging area of the HTTP server's outgoing ring buffer. This function should be called when you need to prepare a message to be sent to connected clients. It is important to ensure that the server is not in an error state before calling this function, as it will return immediately if an error is detected. The function uses a format string and additional arguments to construct the message, similar to printf. If the formatted message exceeds the available buffer space, the server will enter an error state, preventing further operations until the error is cleared. This function is typically used in a single-threaded event loop environment.
- **Inputs**:
    - `http`: A pointer to an fd_http_server_t structure representing the HTTP server. Must not be null and should be a valid, joined server instance.
    - `fmt`: A format string, similar to printf, used to construct the message. Must not be null and should be a valid format string.
    - `...`: Additional arguments required by the format string. These should match the format specifiers in the fmt string.
- **Output**: None
- **See also**: [`fd_http_server_printf`](fd_http_server.c.driver.md#fd_http_server_printf)  (Implementation)


---
### fd\_http\_server\_memcpy<!-- {{#callable_declaration:fd_http_server_memcpy}} -->
Appends data to the staging area of the HTTP server's outgoing ring buffer.
- **Description**: Use this function to add raw data to the staging area of the HTTP server's outgoing ring buffer, which is part of the process for preparing data to be sent to clients. This function should be called when you have data that needs to be staged for sending to connected clients. It is important to ensure that the server is properly initialized and joined before calling this function. If the data causes the buffer to wrap around, clients that are too slow to read the data will be evicted. The function does not handle errors directly but will mark the staging buffer as being in an error state if issues occur, which will affect subsequent operations.
- **Inputs**:
    - `http`: A pointer to an fd_http_server_t structure representing the HTTP server. Must not be null and should be a valid, joined server instance.
    - `data`: A pointer to the data to be copied into the staging area. The data should be valid and the caller retains ownership.
    - `data_len`: The length of the data to be copied. Must be a non-negative value and should not exceed the available space in the buffer.
- **Output**: None
- **See also**: [`fd_http_server_memcpy`](fd_http_server.c.driver.md#fd_http_server_memcpy)  (Implementation)


---
### fd\_http\_server\_unstage<!-- {{#callable_declaration:fd_http_server_unstage}} -->
Clears the contents of the staging buffer in the HTTP server.
- **Description**: Use this function to clear any data that has been staged in the HTTP server's buffer without advancing the ring buffer or evicting any clients. This is useful when you want to discard the current staged data and start fresh without affecting the server's state or client connections. It should be called when the staged data is no longer needed or if an error occurred during staging that requires resetting the buffer.
- **Inputs**:
    - `http`: A pointer to an fd_http_server_t structure representing the HTTP server. Must not be null. The caller retains ownership of the server object.
- **Output**: None
- **See also**: [`fd_http_server_unstage`](fd_http_server.c.driver.md#fd_http_server_unstage)  (Implementation)


---
### fd\_http\_server\_stage\_body<!-- {{#callable_declaration:fd_http_server_stage_body}} -->
Marks the current staging buffer contents as the response body.
- **Description**: Use this function to finalize the staging buffer contents as the body of an HTTP response. It should be called after data has been staged using functions like fd_http_server_printf or fd_http_server_memcpy. This function is essential for preparing the response to be sent to the client. It must be called when the staging buffer is not in an error state, as it will return an error if the buffer is in such a state. After execution, the function resets the staging buffer's error state and updates the response structure with the body offset and length.
- **Inputs**:
    - `http`: A pointer to an fd_http_server_t structure representing the HTTP server. Must not be null. The function will check for any error state in the staging buffer associated with this server.
    - `response`: A pointer to an fd_http_server_response_t structure where the body offset and length will be set. Must not be null. The caller retains ownership of this structure.
- **Output**: Returns 0 on success, indicating the body was staged correctly, or -1 if the staging buffer was in an error state, which is then cleared.
- **See also**: [`fd_http_server_stage_body`](fd_http_server.c.driver.md#fd_http_server_stage_body)  (Implementation)


---
### fd\_http\_server\_ws\_send<!-- {{#callable_declaration:fd_http_server_ws_send}} -->
Send staged WebSocket message to a specific client.
- **Description**: This function sends the contents of the staging buffer as a WebSocket message to a specified client identified by the WebSocket connection ID. It should be called after data has been staged using functions like fd_http_server_printf or fd_http_server_memcpy. The function does not block; it marks the data for sending, which occurs asynchronously as the client is able to read. If the client is too slow and the buffer wraps around, the client will be disconnected. The function returns an error if the staging buffer is in an error state, which is then cleared.
- **Inputs**:
    - `http`: A pointer to an fd_http_server_t structure representing the HTTP server. Must not be null and should be a valid, joined server instance.
    - `ws_conn_id`: The WebSocket connection ID of the client to which the message should be sent. Must be an open connection ID within the range [0, max_ws_connection_cnt). If the connection is closed or invalid, the function returns an error.
- **Output**: Returns 0 on success, or -1 if there is an error with the staging buffer or if the connection is invalid or closed.
- **See also**: [`fd_http_server_ws_send`](fd_http_server.c.driver.md#fd_http_server_ws_send)  (Implementation)


---
### fd\_http\_server\_ws\_broadcast<!-- {{#callable_declaration:fd_http_server_ws_broadcast}} -->
Broadcasts staged WebSocket message to all connected clients.
- **Description**: Use this function to send the currently staged WebSocket message to all connected clients of the HTTP server. It should be called after data has been staged using functions like fd_http_server_printf or fd_http_server_memcpy. The function will clear the staging buffer after broadcasting. If the server is in an error state due to previous operations, the function will return an error and reset the error state. This function is non-blocking and will disconnect clients that are too slow to read the broadcasted message.
- **Inputs**:
    - `http`: A pointer to an fd_http_server_t structure representing the HTTP server. Must not be null. The server should be properly initialized and joined before calling this function. If the server is in an error state, the function will return an error.
- **Output**: Returns 0 on success, or -1 if the server was in an error state, in which case the error state is cleared.
- **See also**: [`fd_http_server_ws_broadcast`](fd_http_server.c.driver.md#fd_http_server_ws_broadcast)  (Implementation)


---
### fd\_http\_server\_poll<!-- {{#callable_declaration:fd_http_server_poll}} -->
Polls the HTTP server for incoming connections and data.
- **Description**: This function should be called frequently in a single-threaded event loop to process incoming connections and data for an HTTP server. It uses the poll system call to check for events on the server's file descriptors, handling new connections and data transmission as needed. The function returns immediately if no events are detected or if the poll is interrupted by a signal. It is essential for maintaining the server's responsiveness and ensuring that connections are serviced promptly.
- **Inputs**:
    - `http`: A pointer to an fd_http_server_t structure representing the HTTP server. Must not be null, and the server should be properly initialized and joined.
    - `poll_timeout`: An integer specifying the timeout for the poll operation in milliseconds. A value of 0 makes the poll non-blocking. Negative values are not recommended as they may cause indefinite blocking.
- **Output**: Returns 1 if there was any work done on the HTTP server, or 0 if no events were detected or the poll was interrupted.
- **See also**: [`fd_http_server_poll`](fd_http_server.c.driver.md#fd_http_server_poll)  (Implementation)



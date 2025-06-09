# Purpose
The provided C source code file implements a robust HTTP server with WebSocket support. It is designed to handle HTTP requests and WebSocket connections, providing functionalities for managing connections, parsing HTTP requests, and handling WebSocket frames. The code includes mechanisms for connection pooling and treap data structures to efficiently manage active connections and their states. It defines several functions for creating, joining, and deleting HTTP server instances, as well as for listening on a specified address and port. The server can accept new connections, read incoming data, and send responses or WebSocket frames.

Key components of the code include the use of connection pools and treaps to manage HTTP and WebSocket connections, the parsing of HTTP requests using the `picohttpparser` library, and the handling of WebSocket frames with masking and opcode validation. The code also defines several utility functions for managing server memory layout and alignment, as well as for logging and error handling. The server supports various HTTP methods and WebSocket operations, and it provides callback mechanisms for handling specific events such as connection opening, message reception, and connection closure. This file is part of a larger system, as indicated by the inclusion of other header and source files, and it is intended to be compiled into an executable or linked as part of a larger application.
# Imports and Dependencies

---
- `fd_http_server_private.h`
- `picohttpparser.h`
- `../../ballet/sha1/fd_sha1.h`
- `../../ballet/base64/fd_base64.h`
- `../../util/net/fd_ip4.h`
- `stdarg.h`
- `stdio.h`
- `errno.h`
- `unistd.h`
- `poll.h`
- `stdlib.h`
- `strings.h`
- `sys/socket.h`
- `netinet/in.h`
- `../../util/tmpl/fd_pool.c`
- `../../util/tmpl/fd_treap.c`


# Functions

---
### fd\_http\_server\_connection\_close\_reason\_str<!-- {{#callable:fd_http_server_connection_close_reason_str}} -->
The function `fd_http_server_connection_close_reason_str` returns a string description of the reason for closing an HTTP server connection based on an integer code.
- **Inputs**:
    - `reason`: An integer representing the reason for closing the HTTP server connection, which corresponds to predefined constants.
- **Control Flow**:
    - The function uses a switch statement to match the input integer `reason` with predefined constants representing different connection close reasons.
    - For each case in the switch statement, a specific string message is returned that describes the reason for the connection closure.
    - If the `reason` does not match any predefined constant, the function returns the string "unknown".
- **Output**: A constant character pointer to a string that describes the reason for the connection closure.


---
### fd\_http\_server\_method\_str<!-- {{#callable:fd_http_server_method_str}} -->
The `fd_http_server_method_str` function returns a string representation of an HTTP method based on the provided method code.
- **Inputs**:
    - `method`: An unsigned character representing the HTTP method code, which is expected to be one of the predefined constants like `FD_HTTP_SERVER_METHOD_GET` or `FD_HTTP_SERVER_METHOD_POST`.
- **Control Flow**:
    - The function uses a switch statement to check the value of the `method` argument.
    - If the `method` matches `FD_HTTP_SERVER_METHOD_GET`, it returns the string "GET".
    - If the `method` matches `FD_HTTP_SERVER_METHOD_POST`, it returns the string "POST".
    - If the `method` does not match any known method, it defaults to returning "unknown".
- **Output**: A constant character pointer to a string representing the HTTP method, such as "GET", "POST", or "unknown" if the method is not recognized.


---
### fd\_http\_server\_align<!-- {{#callable:fd_http_server_align}} -->
The `fd_http_server_align` function returns the alignment requirement for an HTTP server structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a constant function, meaning it does not modify any state and always returns the same value.
    - It directly returns the value of the macro `FD_HTTP_SERVER_ALIGN`.
- **Output**: The function returns an `ulong` representing the alignment requirement for an HTTP server structure.


---
### fd\_http\_server\_footprint<!-- {{#callable:fd_http_server_footprint}} -->
The `fd_http_server_footprint` function calculates the memory footprint required for an HTTP server based on the provided parameters.
- **Inputs**:
    - `params`: A structure of type `fd_http_server_params_t` containing various parameters for the HTTP server, such as maximum connection counts and buffer sizes.
- **Control Flow**:
    - Initialize a variable `l` with `FD_LAYOUT_INIT` to start the layout calculation.
    - Append the size of `fd_http_server_t` to `l` with alignment `FD_HTTP_SERVER_ALIGN`.
    - Append the footprint of the connection pool to `l` using `conn_pool_footprint` and `conn_pool_align`.
    - Append the footprint of the WebSocket connection pool to `l` using `ws_conn_pool_footprint` and `ws_conn_pool_align`.
    - Append the footprint of the connection treap to `l` using `conn_treap_footprint` and `conn_treap_align`.
    - Append the footprint of the WebSocket connection treap to `l` using `ws_conn_treap_footprint` and `ws_conn_treap_align`.
    - Append the size of an array of `struct pollfd` to `l`, calculated based on the total number of connections.
    - Append the size of the request buffer to `l`, calculated as `params.max_request_len * params.max_connection_cnt`.
    - Append the size of the WebSocket receive frame buffer to `l`, calculated as `params.max_ws_recv_frame_len * params.max_ws_connection_cnt`.
    - Append the size of the WebSocket send frame buffer to `l`, calculated as `params.max_ws_send_frame_cnt * params.max_ws_connection_cnt * sizeof(struct fd_http_server_ws_frame)`.
    - Append the size of the outgoing buffer to `l`, which is `params.outgoing_buffer_sz`.
    - Finalize the layout calculation with `FD_LAYOUT_FINI` and return the result.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the HTTP server.
- **Functions called**:
    - [`fd_http_server_align`](#fd_http_server_align)


---
### fd\_http\_server\_new<!-- {{#callable:fd_http_server_new}} -->
The `fd_http_server_new` function initializes a new HTTP server instance using shared memory and specified parameters, and returns a pointer to the server structure.
- **Inputs**:
    - `shmem`: A pointer to the shared memory region where the server will be initialized.
    - `params`: A structure containing parameters for the server, such as maximum connection counts and buffer sizes.
    - `callbacks`: A structure containing callback functions for handling server events.
    - `callback_ctx`: A context pointer that will be passed to callback functions.
- **Control Flow**:
    - Check if `shmem` is NULL or misaligned, logging a warning and returning NULL if so.
    - Verify that WebSocket frame length constraints are met, logging a warning and returning NULL if not.
    - Initialize scratch memory allocation using `shmem`.
    - Allocate memory for the HTTP server structure and various connection pools and treaps using the scratch allocator.
    - Initialize the HTTP server structure with parameters, callbacks, and default values.
    - Join and seed connection pools and treaps for both HTTP and WebSocket connections.
    - Initialize poll file descriptors and connection structures for HTTP and WebSocket connections.
    - Set the server's magic number to indicate successful initialization.
    - Return a pointer to the initialized HTTP server structure.
- **Output**: A pointer to the initialized `fd_http_server_t` structure, or NULL if initialization fails.
- **Functions called**:
    - [`fd_http_server_align`](#fd_http_server_align)


---
### fd\_http\_server\_join<!-- {{#callable:fd_http_server_join}} -->
The `fd_http_server_join` function validates and returns a pointer to an `fd_http_server_t` structure from a shared memory pointer, ensuring it is properly aligned and initialized.
- **Inputs**:
    - `shhttp`: A pointer to a shared memory region that is expected to contain an `fd_http_server_t` structure.
- **Control Flow**:
    - Check if `shhttp` is NULL; if so, log a warning and return NULL.
    - Check if `shhttp` is aligned according to [`fd_http_server_align`](#fd_http_server_align); if not, log a warning and return NULL.
    - Cast `shhttp` to an `fd_http_server_t` pointer and store it in `http`.
    - Check if the `magic` field of `http` matches `FD_HTTP_SERVER_MAGIC`; if not, log a warning and return NULL.
    - Return the `http` pointer.
- **Output**: A pointer to an `fd_http_server_t` structure if successful, or NULL if any validation fails.
- **Functions called**:
    - [`fd_http_server_align`](#fd_http_server_align)


---
### fd\_http\_server\_leave<!-- {{#callable:fd_http_server_leave}} -->
The `fd_http_server_leave` function checks if the provided HTTP server pointer is valid and returns it as a void pointer, logging a warning if the pointer is NULL.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` structure representing the HTTP server instance to be left.
- **Control Flow**:
    - Check if the `http` pointer is NULL using `FD_UNLIKELY` macro.
    - If `http` is NULL, log a warning message 'NULL http' using `FD_LOG_WARNING` and return NULL.
    - If `http` is not NULL, cast it to a void pointer and return it.
- **Output**: Returns a void pointer to the `fd_http_server_t` structure if it is not NULL, otherwise returns NULL.


---
### fd\_http\_server\_delete<!-- {{#callable:fd_http_server_delete}} -->
The `fd_http_server_delete` function safely deletes an HTTP server instance by verifying its alignment and magic number, then resetting its magic number to zero.
- **Inputs**:
    - `shhttp`: A pointer to the shared memory region representing the HTTP server instance to be deleted.
- **Control Flow**:
    - Check if the input pointer `shhttp` is NULL; if so, log a warning and return NULL.
    - Verify if `shhttp` is properly aligned using [`fd_http_server_align`](#fd_http_server_align); if not, log a warning and return NULL.
    - Cast `shhttp` to a `fd_http_server_t` pointer and store it in `http`.
    - Check if the `magic` field of `http` matches `FD_HTTP_SERVER_MAGIC`; if not, log a warning and return NULL.
    - Use memory fences to ensure memory operations are completed, then set the `magic` field of `http` to zero.
    - Return the `http` pointer cast back to a `void *`.
- **Output**: A pointer to the deleted HTTP server instance, or NULL if deletion was unsuccessful due to input validation failures.
- **Functions called**:
    - [`fd_http_server_align`](#fd_http_server_align)


---
### fd\_http\_server\_fd<!-- {{#callable:fd_http_server_fd}} -->
The function `fd_http_server_fd` retrieves the socket file descriptor from a given HTTP server structure.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` structure representing the HTTP server from which the socket file descriptor is to be retrieved.
- **Control Flow**:
    - The function accesses the `socket_fd` member of the `fd_http_server_t` structure pointed to by `http`.
- **Output**: The function returns an integer representing the socket file descriptor of the HTTP server.


---
### fd\_http\_server\_listen<!-- {{#callable:fd_http_server_listen}} -->
The `fd_http_server_listen` function initializes a non-blocking TCP socket, binds it to a specified address and port, and sets it to listen for incoming connections, updating the HTTP server structure with the socket file descriptor.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` structure representing the HTTP server instance to be configured.
    - `address`: An unsigned integer representing the IPv4 address to bind the server to, in network byte order.
    - `port`: An unsigned short integer representing the port number to bind the server to, in host byte order.
- **Control Flow**:
    - Create a non-blocking TCP socket using `socket` with `AF_INET` and `SOCK_STREAM | SOCK_NONBLOCK` flags.
    - Check if socket creation failed and log an error if it did.
    - Set the socket option `SO_REUSEADDR` to allow reuse of local addresses, logging an error if it fails.
    - Initialize a `sockaddr_in` structure with the provided address and port, converting the port to network byte order using `fd_ushort_bswap`.
    - Bind the socket to the specified address and port using `bind`, logging an error if it fails.
    - Set the socket to listen for incoming connections with a backlog equal to the maximum number of connections allowed by the server, logging an error if it fails.
    - Store the socket file descriptor in the `socket_fd` field of the `http` structure.
    - Update the `pollfds` array in the `http` structure to include the new socket file descriptor for polling.
- **Output**: Returns a pointer to the updated `fd_http_server_t` structure with the socket configured for listening.


---
### close\_conn<!-- {{#callable:close_conn}} -->
The `close_conn` function closes a specified connection in an HTTP server, handling both regular and WebSocket connections, and performs necessary cleanup and callback invocations.
- **Inputs**:
    - `http`: A pointer to the `fd_http_server_t` structure representing the HTTP server instance.
    - `conn_idx`: The index of the connection to be closed within the server's connection array.
    - `reason`: An integer representing the reason for closing the connection, used for logging and callback purposes.
- **Control Flow**:
    - The function asserts that the file descriptor for the connection is valid (not -1).
    - If debugging is enabled, it logs the closure of the connection with the reason.
    - Attempts to close the file descriptor for the connection and logs an error if it fails.
    - Sets the file descriptor for the connection to -1 to mark it as closed.
    - Checks if the connection index is within the range of regular connections or WebSocket connections.
    - If it's a regular connection, it invokes the `close` callback if it exists; otherwise, it invokes the `ws_close` callback for WebSocket connections.
    - For regular connections, it checks the connection state and removes it from the treap if necessary, then releases the connection back to the pool.
    - For WebSocket connections, it removes the connection from the treap if it has pending frames and releases it back to the pool.
- **Output**: The function does not return a value; it performs operations to close the connection and clean up resources.
- **Functions called**:
    - [`fd_http_server_connection_close_reason_str`](#fd_http_server_connection_close_reason_str)


---
### fd\_http\_server\_close<!-- {{#callable:fd_http_server_close}} -->
The `fd_http_server_close` function closes a specified HTTP connection on the server for a given reason.
- **Inputs**:
    - `http`: A pointer to the `fd_http_server_t` structure representing the HTTP server instance.
    - `conn_id`: An unsigned long integer representing the connection ID of the connection to be closed.
    - `reason`: An integer representing the reason for closing the connection, which can be used for logging or debugging purposes.
- **Control Flow**:
    - The function calls the [`close_conn`](#close_conn) helper function, passing the `http` server instance, `conn_id`, and `reason` as arguments.
    - The [`close_conn`](#close_conn) function handles the actual closing of the connection, including logging the reason if debugging is enabled, closing the socket, and invoking any registered callbacks for connection closure.
    - The [`close_conn`](#close_conn) function also manages the release of resources associated with the connection, such as removing it from connection pools or treaps.
- **Output**: The function does not return any value.
- **Functions called**:
    - [`close_conn`](#close_conn)


---
### fd\_http\_server\_ws\_close<!-- {{#callable:fd_http_server_ws_close}} -->
The `fd_http_server_ws_close` function closes a WebSocket connection on an HTTP server by invoking the [`close_conn`](#close_conn) function with the appropriate connection index and reason.
- **Inputs**:
    - `http`: A pointer to the `fd_http_server_t` structure representing the HTTP server instance.
    - `ws_conn_id`: An unsigned long integer representing the WebSocket connection ID to be closed.
    - `reason`: An integer representing the reason for closing the connection, which is used for logging and callback purposes.
- **Control Flow**:
    - The function calculates the actual connection index by adding `ws_conn_id` to `http->max_conns` to differentiate WebSocket connections from regular HTTP connections.
    - It calls the [`close_conn`](#close_conn) function with the calculated connection index, the `http` server instance, and the `reason` for closure.
- **Output**: The function does not return any value; it performs the action of closing the specified WebSocket connection.
- **Functions called**:
    - [`close_conn`](#close_conn)


---
### is\_expected\_network\_error<!-- {{#callable:is_expected_network_error}} -->
The function `is_expected_network_error` checks if a given error code corresponds to a known network error that should result in closing the connection.
- **Inputs**:
    - `err`: An integer representing the error code to be checked against known network errors.
- **Control Flow**:
    - The function checks if the input error code matches any of the predefined network error codes such as ENETDOWN, EPROTO, ENOPROTOOPT, etc.
    - If the error code matches any of these, the function returns true (non-zero).
    - If the error code does not match any of these, the function returns false (zero).
- **Output**: The function returns an integer, which is non-zero if the error code is a known network error that should result in closing the connection, and zero otherwise.


---
### accept\_conns<!-- {{#callable:accept_conns}} -->
The `accept_conns` function continuously accepts new incoming connections on a given HTTP server socket, handling errors and managing connection resources.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` structure representing the HTTP server instance.
- **Control Flow**:
    - The function enters an infinite loop to continuously accept new connections.
    - It calls `accept4` to accept a new connection on the server's socket file descriptor.
    - If `accept4` returns -1, it checks if the error is `EAGAIN` to break the loop, or if it's an expected network error to continue, otherwise logs an error and exits.
    - If there are no free connections in the pool, it attempts to evict an existing connection using a treap iterator or round-robin eviction strategy.
    - Acquires a new connection index from the connection pool.
    - Initializes the connection's file descriptor, state, and byte counters.
    - If an open callback is defined, it is called with the new connection's details.
    - Logs the accepted connection if debugging is enabled.
- **Output**: The function does not return a value; it operates by modifying the state of the `fd_http_server_t` structure and its associated resources.
- **Functions called**:
    - [`is_expected_network_error`](#is_expected_network_error)
    - [`close_conn`](#close_conn)


---
### read\_conn\_http<!-- {{#callable:read_conn_http}} -->
The `read_conn_http` function reads and processes HTTP requests from a connection, handling various states and errors, and prepares a response based on the request data.
- **Inputs**:
    - `http`: A pointer to the `fd_http_server_t` structure representing the HTTP server.
    - `conn_idx`: An unsigned long integer representing the index of the connection to be read from.
- **Control Flow**:
    - Check if the connection state is not reading; if so, close the connection with an expected EOF reason.
    - Attempt to read data from the connection's file descriptor into the request buffer.
    - Handle cases where no data is available, the connection is reset by the peer, or a read error occurs.
    - Update the number of bytes read and check if the request exceeds the maximum allowed length, closing the connection if it does.
    - Parse the HTTP request using [`phr_parse_request`](picohttpparser.c.driver.md#phr_parse_request) and handle partial or malformed requests by closing the connection.
    - Determine the HTTP method (GET, POST, OPTIONS) and handle unknown methods by closing the connection.
    - For POST requests, parse the Content-Length header and validate it, closing the connection on errors or overflow.
    - Extract and validate headers like Content-Type and Accept-Encoding, closing the connection on errors.
    - Check for WebSocket upgrade requests and validate necessary headers, closing the connection on errors.
    - Set the connection state to writing header and prepare a request structure for the callback.
    - Invoke the server's request callback to generate a response and handle connection closure by the callback.
    - Insert the connection into a treap if the response does not have a static body.
- **Output**: The function does not return a value; it modifies the state of the connection and may close it or prepare it for writing a response.
- **Functions called**:
    - [`close_conn`](#close_conn)
    - [`is_expected_network_error`](#is_expected_network_error)
    - [`phr_parse_request`](picohttpparser.c.driver.md#phr_parse_request)
    - [`fd_http_server_method_str`](#fd_http_server_method_str)


---
### read\_conn\_ws<!-- {{#callable:read_conn_ws}} -->
The `read_conn_ws` function reads and processes WebSocket frames from a specified connection in an HTTP server, handling various WebSocket frame types and errors.
- **Inputs**:
    - `http`: A pointer to the HTTP server structure (`fd_http_server_t`) containing server state and connection information.
    - `conn_idx`: An unsigned long integer representing the index of the WebSocket connection to read from.
- **Control Flow**:
    - Retrieve the WebSocket connection structure using the connection index.
    - Attempt to read data from the connection's file descriptor into the connection's receive buffer.
    - Check for non-blocking read errors and handle them by returning or closing the connection if necessary.
    - If new data is read, update the number of bytes read and check if there are at least 2 bytes to determine the frame length.
    - Verify that the mask bit is set in the frame; if not, close the connection with a bad mask error.
    - Extract the opcode from the frame and validate it against known opcodes; close the connection if the opcode is unknown.
    - Determine the payload length and handle control frames with oversized payloads by closing the connection.
    - Calculate the total frame length and check for buffer overflow or incomplete frame data, returning if more data is needed.
    - Process the data frame by unmasking the payload using the mask key and handling different opcodes (e.g., close, ping, pong).
    - For ping frames, queue a pong response if not already queued; for pong frames, ignore them.
    - Check for message continuation and opcode consistency, closing the connection if expectations are not met.
    - If the frame is a complete message, process it by invoking the WebSocket message callback and handle any trailing data.
    - If there is trailing data, move it to the start of the buffer and continue processing from the beginning.
- **Output**: The function does not return a value; it processes WebSocket frames and may modify the server state or close connections based on the frame content and errors encountered.
- **Functions called**:
    - [`is_expected_network_error`](#is_expected_network_error)
    - [`close_conn`](#close_conn)


---
### read\_conn<!-- {{#callable:read_conn}} -->
The `read_conn` function determines whether to read data from an HTTP or WebSocket connection based on the connection index and delegates the reading task to the appropriate function.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` structure representing the HTTP server instance.
    - `conn_idx`: An unsigned long integer representing the index of the connection to be read.
- **Control Flow**:
    - Check if `conn_idx` is less than `http->max_conns` to determine if the connection is an HTTP connection.
    - If true, call [`read_conn_http`](#read_conn_http) with `http` and `conn_idx` to handle reading from an HTTP connection.
    - If false, call [`read_conn_ws`](#read_conn_ws) with `http` and `conn_idx` to handle reading from a WebSocket connection.
- **Output**: This function does not return a value; it performs operations based on the connection type.
- **Functions called**:
    - [`read_conn_http`](#read_conn_http)
    - [`read_conn_ws`](#read_conn_ws)


---
### write\_conn\_http<!-- {{#callable:write_conn_http}} -->
The `write_conn_http` function handles the writing of HTTP response headers and bodies to a client connection, including handling WebSocket upgrades.
- **Inputs**:
    - `http`: A pointer to the HTTP server structure (`fd_http_server_t`) containing server state and connection information.
    - `conn_idx`: An unsigned long integer representing the index of the connection in the server's connection array.
- **Control Flow**:
    - Retrieve the connection object from the server's connection array using `conn_idx`.
    - Check the connection state; if it is `FD_HTTP_SERVER_CONNECTION_STATE_READING`, return immediately as no data is staged for writing.
    - If the state is `FD_HTTP_SERVER_CONNECTION_STATE_WRITING_HEADER`, construct the HTTP response header based on the response status code and other response attributes.
    - For a 200 status code with WebSocket upgrade, compute the `Sec-WebSocket-Accept` header and construct a 101 Switching Protocols response.
    - For other status codes (e.g., 204, 400, 404, 405, 500), construct the appropriate HTTP response header with content length and other headers if applicable.
    - If the state is `FD_HTTP_SERVER_CONNECTION_STATE_WRITING_BODY`, determine the response body location and length, either from a static body or from the server's outgoing ring buffer.
    - Send the response data using the `send` system call, handling partial writes and network errors.
    - Update the number of bytes written to the connection's response.
    - If the entire response has been written, transition the connection state to writing the body or close the connection if the body is complete.
    - Handle WebSocket upgrades by releasing the HTTP connection and acquiring a WebSocket connection from the pool, setting up the WebSocket connection state.
- **Output**: The function does not return a value; it performs operations on the server and connection state, potentially modifying the connection's state or closing it.
- **Functions called**:
    - [`close_conn`](#close_conn)
    - [`is_expected_network_error`](#is_expected_network_error)


---
### maybe\_write\_pong<!-- {{#callable:maybe_write_pong}} -->
The `maybe_write_pong` function handles the sending of a WebSocket pong frame in response to a ping from a client, ensuring that the pong is sent only when appropriate conditions are met.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` structure representing the HTTP server context.
    - `conn_idx`: An unsigned long integer representing the index of the WebSocket connection within the server's connection array.
- **Control Flow**:
    - Retrieve the WebSocket connection object from the server's connection array using the provided index.
    - Check if the connection's pong state is `FD_HTTP_SERVER_PONG_STATE_NONE`, indicating no pong is needed, and return 0 if true.
    - Check if the connection is in the middle of writing a data frame, and return 0 if true.
    - If the pong state is `FD_HTTP_SERVER_PONG_STATE_WAITING`, set it to `FD_HTTP_SERVER_PONG_STATE_WRITING` and reset the pong bytes written counter.
    - Prepare a pong frame with the appropriate headers and copy the pong data into the frame.
    - Attempt to send the pong frame using the `send` function, handling errors such as `EAGAIN` and expected network errors.
    - If the send operation is successful, update the pong bytes written counter.
    - If all pong bytes have been written, reset the pong state to `FD_HTTP_SERVER_PONG_STATE_NONE` and return 0.
    - Return 1 if the pong frame is partially sent and more data needs to be written.
- **Output**: The function returns an integer: 0 if the pong frame is successfully sent or not needed, and 1 if the pong frame is partially sent and more data needs to be written.
- **Functions called**:
    - [`is_expected_network_error`](#is_expected_network_error)
    - [`close_conn`](#close_conn)


---
### write\_conn\_ws<!-- {{#callable:write_conn_ws}} -->
The `write_conn_ws` function handles the sending of WebSocket frames over a connection in an HTTP server, managing both the frame headers and data transmission.
- **Inputs**:
    - `http`: A pointer to the `fd_http_server_t` structure representing the HTTP server instance.
    - `conn_idx`: An unsigned long integer representing the index of the WebSocket connection within the server's connection array.
- **Control Flow**:
    - Retrieve the WebSocket connection object using the connection index and server's maximum connections.
    - Check if a pong response needs to be sent using [`maybe_write_pong`](#maybe_write_pong); if so, return early.
    - Check if there are any frames to send; if not, return early.
    - Retrieve the current frame to be sent from the connection's send frame array.
    - Switch based on the current frame state:
    - If the state is `FD_HTTP_SERVER_SEND_FRAME_STATE_HEADER`, construct the WebSocket frame header based on the frame length and send it.
    - If the header is fully sent, transition to `FD_HTTP_SERVER_SEND_FRAME_STATE_DATA` and reset the bytes written counter.
    - If the state is `FD_HTTP_SERVER_SEND_FRAME_STATE_DATA`, send the frame data from the server's outgoing buffer.
    - If the data is fully sent, reset the frame state to header, update the frame index, decrement the frame count, and manage the connection in the treap structure.
- **Output**: The function does not return a value; it performs operations on the server and connection structures to manage WebSocket frame transmission.
- **Functions called**:
    - [`maybe_write_pong`](#maybe_write_pong)
    - [`is_expected_network_error`](#is_expected_network_error)
    - [`close_conn`](#close_conn)


---
### fd\_http\_server\_ws\_send<!-- {{#callable:fd_http_server_ws_send}} -->
The `fd_http_server_ws_send` function sends a WebSocket frame from a staging buffer to a specified WebSocket connection if conditions allow.
- **Inputs**:
    - `http`: A pointer to the `fd_http_server_t` structure representing the HTTP server context.
    - `ws_conn_id`: An unsigned long integer representing the WebSocket connection ID to which the frame should be sent.
- **Control Flow**:
    - Retrieve the WebSocket connection structure using the provided `ws_conn_id`.
    - Check if there is a staging error (`http->stage_err`), reset the error and length, and return -1 if true.
    - Check if the WebSocket connection is closed by verifying the file descriptor; return -1 if closed.
    - Check if the connection's send frame count has reached the maximum allowed; if so, close the connection and return 0.
    - Create a new WebSocket frame with the current staging offset and length.
    - Add the frame to the connection's send frames buffer and increment the send frame count.
    - If this is the first frame in the buffer, insert the connection into the WebSocket connection treap.
    - Update the staging offset and reset the staging length.
    - Return 0 to indicate success.
- **Output**: Returns 0 on success, or -1 if there is a staging error or the connection is closed.
- **Functions called**:
    - [`close_conn`](#close_conn)


---
### fd\_http\_server\_ws\_broadcast<!-- {{#callable:fd_http_server_ws_broadcast}} -->
The `fd_http_server_ws_broadcast` function broadcasts a WebSocket frame to all active WebSocket connections managed by the HTTP server.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` structure representing the HTTP server instance.
- **Control Flow**:
    - Check if there is a staging error in the HTTP server; if so, reset the error and length, and return -1.
    - Create a WebSocket frame using the current stage offset and length from the HTTP server.
    - Iterate over all WebSocket connections up to the maximum allowed connections.
    - For each connection, check if the file descriptor is valid (not -1); if invalid, skip to the next connection.
    - Check if the connection's send frame count has reached the maximum allowed; if so, close the connection due to the client being too slow and continue to the next connection.
    - Add the frame to the connection's send frames buffer and increment the send frame count.
    - If the send frame count is 1, insert the connection into the WebSocket connection treap for processing.
    - Update the stage offset by adding the stage length and reset the stage length to 0.
    - Return 0 to indicate successful broadcasting.
- **Output**: Returns 0 on successful broadcast to all connections, or -1 if there was a staging error.
- **Functions called**:
    - [`close_conn`](#close_conn)


---
### write\_conn<!-- {{#callable:write_conn}} -->
The `write_conn` function determines whether to write data to an HTTP or WebSocket connection based on the connection index and calls the appropriate function to handle the writing.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` structure representing the HTTP server instance.
    - `conn_idx`: An unsigned long integer representing the index of the connection to write to.
- **Control Flow**:
    - Check if `conn_idx` is less than `http->max_conns` to determine if the connection is an HTTP connection.
    - If true, call [`write_conn_http`](#write_conn_http) with `http` and `conn_idx` to handle writing to an HTTP connection.
    - If false, call [`write_conn_ws`](#write_conn_ws) with `http` and `conn_idx` to handle writing to a WebSocket connection.
- **Output**: The function does not return a value; it performs actions based on the connection type.
- **Functions called**:
    - [`write_conn_http`](#write_conn_http)
    - [`write_conn_ws`](#write_conn_ws)


---
### fd\_http\_server\_poll<!-- {{#callable:fd_http_server_poll}} -->
The `fd_http_server_poll` function monitors and manages HTTP and WebSocket connections for a server, handling incoming data and outgoing responses based on the events detected by the `poll` system call.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` structure representing the HTTP server instance, which contains connection information and state.
    - `poll_timeout`: An integer specifying the timeout for the `poll` system call, in milliseconds.
- **Control Flow**:
    - The function calls `poll` on the server's file descriptors to check for events, such as incoming data or readiness to send data, with a specified timeout.
    - If `poll` returns 0 (timeout) or -1 with `errno` set to `EINTR` (interrupted), the function returns 0, indicating no events were processed.
    - If `poll` returns -1 due to other errors, it logs an error and terminates the server.
    - For each file descriptor with events, it checks if the descriptor is for accepting new connections or for existing connections.
    - If it's for accepting new connections, it calls [`accept_conns`](#accept_conns) to handle new incoming connections.
    - For existing connections, it checks for `POLLIN` events to read data using [`read_conn`](#read_conn) and `POLLOUT` events to write data using [`write_conn`](#write_conn).
    - The function skips processing for any file descriptor that has been closed during the loop.
- **Output**: The function returns 1 if any events were processed successfully, or 0 if no events were processed due to a timeout or interruption.
- **Functions called**:
    - [`accept_conns`](#accept_conns)
    - [`read_conn`](#read_conn)
    - [`write_conn`](#write_conn)


---
### fd\_http\_server\_evict\_until<!-- {{#callable:fd_http_server_evict_until}} -->
The `fd_http_server_evict_until` function evicts HTTP and WebSocket connections from a server until a specified offset is reached.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` structure representing the HTTP server.
    - `off`: An unsigned long integer representing the offset threshold for eviction.
- **Control Flow**:
    - Initialize a forward iterator for HTTP connections using `conn_treap_fwd_iter_init` and iterate over the connections treap.
    - For each HTTP connection, check if the connection's response body offset is less than the specified offset `off`.
    - If the condition is met, close the connection using [`close_conn`](#close_conn) with the reason `FD_HTTP_SERVER_CONNECTION_CLOSE_EVICTED`.
    - Break the loop if a connection's response body offset is not less than `off`.
    - Initialize a forward iterator for WebSocket connections using `ws_conn_treap_fwd_iter_init` and iterate over the WebSocket connections treap.
    - For each WebSocket connection, check if the offset of the current send frame is less than the specified offset `off`.
    - If the condition is met, close the WebSocket connection using [`close_conn`](#close_conn) with the reason `FD_HTTP_SERVER_CONNECTION_CLOSE_WS_CLIENT_TOO_SLOW`.
    - Break the loop if a WebSocket connection's send frame offset is not less than `off`.
- **Output**: The function does not return a value; it performs operations directly on the server's connection structures.
- **Functions called**:
    - [`close_conn`](#close_conn)


---
### fd\_http\_server\_reserve<!-- {{#callable:fd_http_server_reserve}} -->
The `fd_http_server_reserve` function ensures that there is enough space in the HTTP server's outgoing buffer to accommodate a specified length of data, handling buffer overflow scenarios by either marking an error or relocating data within the buffer.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` structure representing the HTTP server instance.
    - `len`: An unsigned long integer representing the length of data to reserve space for in the outgoing buffer.
- **Control Flow**:
    - Calculate the remaining space in the buffer by subtracting the current offset and length from the total buffer size.
    - Check if the requested length exceeds the remaining space in the buffer.
    - If the requested length plus the current stage length exceeds the total buffer size, log a warning, mark an error, and exit.
    - If the requested length can fit by relocating data, calculate the new end position, evict necessary data, and move the current data to the start of the buffer.
    - If the requested length fits within the remaining space, calculate the new end position and evict necessary data.
- **Output**: The function does not return a value but modifies the state of the `http` structure, potentially marking an error or adjusting the buffer's data.
- **Functions called**:
    - [`fd_http_server_evict_until`](#fd_http_server_evict_until)


---
### fd\_http\_server\_stage\_trunc<!-- {{#callable:fd_http_server_stage_trunc}} -->
The `fd_http_server_stage_trunc` function sets the length of the staged data in an HTTP server context to a specified value.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` structure, representing the HTTP server context where the staged data length is to be set.
    - `len`: An unsigned long integer representing the new length to set for the staged data.
- **Control Flow**:
    - The function directly assigns the value of `len` to the `stage_len` member of the `http` structure.
- **Output**: This function does not return any value.


---
### fd\_http\_server\_stage\_len<!-- {{#callable:fd_http_server_stage_len}} -->
The `fd_http_server_stage_len` function returns the current length of the staged data in the HTTP server.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` structure representing the HTTP server instance.
- **Control Flow**:
    - The function accesses the `stage_len` member of the `fd_http_server_t` structure pointed to by `http`.
    - It returns the value of `stage_len`.
- **Output**: The function returns an `ulong` representing the length of the staged data.


---
### fd\_http\_server\_printf<!-- {{#callable:fd_http_server_printf}} -->
The `fd_http_server_printf` function formats a string using a variable argument list and appends it to the HTTP server's outgoing buffer, updating the buffer's length accordingly.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` structure representing the HTTP server instance.
    - `fmt`: A constant character pointer representing the format string for the message to be printed.
    - `...`: A variable argument list that provides the values to be formatted according to the format string.
- **Control Flow**:
    - Check if `http->stage_err` is set; if so, return immediately without doing anything.
    - Initialize a `va_list` and calculate the length of the formatted string using `vsnprintf` with a `NULL` buffer to determine the required length.
    - Call [`fd_http_server_reserve`](#fd_http_server_reserve) to ensure there is enough space in the buffer for the formatted string.
    - Check again if `http->stage_err` is set after reserving space; if so, return immediately.
    - Reinitialize the `va_list` and use `vsnprintf` to actually format the string into the buffer at the calculated position.
    - Update `http->stage_len` by adding the length of the newly formatted string.
- **Output**: The function does not return a value; it modifies the state of the `http` object by appending the formatted string to its outgoing buffer.
- **Functions called**:
    - [`fd_http_server_reserve`](#fd_http_server_reserve)


---
### fd\_http\_server\_memcpy<!-- {{#callable:fd_http_server_memcpy}} -->
The `fd_http_server_memcpy` function copies a specified amount of data into a reserved buffer space within an HTTP server structure, updating the length of the staged data.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` structure, representing the HTTP server where data is to be copied.
    - `data`: A constant pointer to an array of unsigned characters (`uchar`), representing the data to be copied.
    - `data_len`: An unsigned long integer representing the length of the data to be copied.
- **Control Flow**:
    - Call [`fd_http_server_reserve`](#fd_http_server_reserve) to ensure there is enough space in the server's buffer for the data to be copied.
    - Check if there is an error in the staging process (`http->stage_err`), and return immediately if an error is present.
    - Use `fd_memcpy` to copy the data from the source to the destination buffer within the server's structure.
    - Update the `stage_len` field of the server structure to reflect the new length of the staged data.
- **Output**: This function does not return a value; it modifies the state of the `fd_http_server_t` structure by copying data into its buffer and updating the staged data length.
- **Functions called**:
    - [`fd_http_server_reserve`](#fd_http_server_reserve)


---
### fd\_http\_server\_unstage<!-- {{#callable:fd_http_server_unstage}} -->
The `fd_http_server_unstage` function resets the staging error and length of an HTTP server object to zero.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` structure representing the HTTP server whose staging error and length are to be reset.
- **Control Flow**:
    - The function sets the `stage_err` field of the `http` structure to 0, indicating no error.
    - The function sets the `stage_len` field of the `http` structure to 0UL, indicating no data is staged.
- **Output**: This function does not return any value.


---
### fd\_http\_server\_stage\_body<!-- {{#callable:fd_http_server_stage_body}} -->
The `fd_http_server_stage_body` function stages the body of an HTTP response by updating the response's body offset and length based on the current staging buffer state, and then resets the staging length.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` structure representing the HTTP server context, which contains the current state of the staging buffer.
    - `response`: A pointer to an `fd_http_server_response_t` structure where the body offset and length will be updated based on the current staging buffer state.
- **Control Flow**:
    - Check if `http->stage_err` is set, indicating an error in the staging process.
    - If an error is present, reset `http->stage_err` and `http->stage_len` to 0 and return -1 to indicate failure.
    - If no error, set `response->_body_off` to `http->stage_off` and `response->_body_len` to `http->stage_len`.
    - Increment `http->stage_off` by `http->stage_len` to move the offset forward.
    - Reset `http->stage_len` to 0 to clear the staging length.
    - Return 0 to indicate success.
- **Output**: Returns 0 on success, or -1 if there was an error in the staging process.



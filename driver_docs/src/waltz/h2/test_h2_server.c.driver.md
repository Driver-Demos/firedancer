# Purpose
The provided C code implements a simple HTTP/2 server designed for testing purposes. It is a single-threaded, blocking server that handles HTTP/2 GET and POST requests, responding with a status code of 200. The server is built using a set of custom HTTP/2 handling functions and structures, such as `fd_h2_conn_t`, `fd_h2_stream_t`, and `fd_h2_tx_op_t`, which manage the connection, stream, and transmission operations, respectively. The server is initialized with a set of callback functions that handle various HTTP/2 events, such as connection establishment, stream creation, and data reception. These callbacks are defined to log events and manage the state of the HTTP/2 streams and connections.

The server listens for incoming TCP connections on a specified IP address and port, which can be configured via command-line arguments. It supports two modes of operation: a simple mode where connections are handled sequentially, and a fork mode where each connection is handled in a separate process. The server reads the HTTP/2 client preface to ensure the client is compatible and then processes incoming requests by reading headers and data, sending appropriate responses, and managing stream states. The code is structured to be a standalone executable, with a [`main`](#main) function that initializes the server, sets up the listening socket, and enters a loop to accept and handle incoming connections.
# Imports and Dependencies

---
- `fd_h2.h`
- `fd_h2_rbuf_sock.h`
- `../../util/fd_util.h`
- `../../util/net/fd_ip4.h`
- `errno.h`
- `stdlib.h`
- `unistd.h`
- `netinet/in.h`
- `sys/socket.h`


# Global Variables

---
### g\_app
- **Type**: `test_h2_app_t *`
- **Description**: `g_app` is a static global pointer to a `test_h2_app_t` structure, which encapsulates the application logic for handling HTTP/2 connections. This structure includes buffers for transmission, connection, stream, and transmission operations, which are essential for managing HTTP/2 communication.
- **Use**: `g_app` is used to access and manipulate the HTTP/2 application state and resources throughout the server's operation.


---
### test\_h2\_callbacks
- **Type**: `fd_h2_callbacks_t`
- **Description**: The `test_h2_callbacks` is a static instance of the `fd_h2_callbacks_t` structure, which is used to define a set of callback functions for handling various HTTP/2 events. These callbacks include functions for stream creation, querying, connection establishment, header processing, data handling, and more. This structure is essential for managing the behavior of the HTTP/2 server in response to different protocol events.
- **Use**: This variable is used to store and manage the callback functions that handle HTTP/2 protocol events in the test HTTP/2 server.


# Data Structures

---
### test\_h2\_app
- **Type**: `struct`
- **Members**:
    - `rbuf_tx`: An array of one fd_h2_rbuf_t, used for managing the transmission buffer.
    - `conn`: An array of one fd_h2_conn_t, representing the HTTP/2 connection.
    - `stream`: An array of one fd_h2_stream_t, representing the HTTP/2 stream.
    - `tx_op`: An array of one fd_h2_tx_op_t, used for managing transmission operations.
- **Description**: The `test_h2_app` structure is designed to encapsulate the components necessary for handling an HTTP/2 application within a test server environment. It includes buffers and operations for managing HTTP/2 connections and streams, facilitating the transmission of data and headers. This structure is integral to the server's ability to process and respond to HTTP/2 requests, maintaining the state and operations required for effective communication over the protocol.


---
### test\_h2\_app\_t
- **Type**: `struct`
- **Members**:
    - `rbuf_tx`: An array of one fd_h2_rbuf_t structure used for transmission buffering.
    - `conn`: An array of one fd_h2_conn_t structure representing the HTTP/2 connection.
    - `stream`: An array of one fd_h2_stream_t structure representing the HTTP/2 stream.
    - `tx_op`: An array of one fd_h2_tx_op_t structure used for managing transmission operations.
- **Description**: The `test_h2_app_t` structure is designed to encapsulate the components necessary for handling an HTTP/2 application within a test server environment. It includes a transmission buffer (`rbuf_tx`), a connection object (`conn`), a stream object (`stream`), and a transmission operation object (`tx_op`). These components work together to manage the lifecycle of HTTP/2 connections and streams, handle data transmission, and ensure proper communication flow in a single-threaded, blocking socket server setup.


# Functions

---
### test\_response\_continue<!-- {{#callable:test_response_continue}} -->
The `test_response_continue` function handles the continuation of an HTTP/2 response by copying transmission operations and cleaning up resources if the stream is closed.
- **Inputs**: None
- **Control Flow**:
    - Retrieve the current stream from the global application context `g_app`.
    - Check if the stream's `stream_id` is zero; if so, exit the function as there is no active stream.
    - Call [`fd_h2_tx_op_copy`](fd_h2_tx.c.driver.md#fd_h2_tx_op_copy) to copy the transmission operation from the connection, stream, and transmission buffer to the transmission operation structure.
    - Check if the stream's state is `FD_H2_STREAM_STATE_CLOSED`.
    - If the stream is closed, log a notice indicating the response is complete.
    - Clear the transmission operation and stream structures using `memset` to reset their memory.
- **Output**: The function does not return any value; it performs operations on global structures and logs messages.
- **Functions called**:
    - [`fd_h2_tx_op_copy`](fd_h2_tx.c.driver.md#fd_h2_tx_op_copy)


---
### test\_response\_init<!-- {{#callable:test_response_init}} -->
The `test_response_init` function initializes and sends an HTTP/2 response for a given stream, logging the process and handling stream state.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection; it is not used in the function.
    - `stream`: A pointer to an `fd_h2_stream_t` structure representing the HTTP/2 stream for which the response is being initialized and sent.
- **Control Flow**:
    - The function begins by logging that it is done reading the request and is sending a response, using the stream's ID.
    - It initializes a buffer `rbuf_tx` for transmitting the response and prepares an HPACK-encoded header indicating a 200 status code.
    - The function calls [`fd_h2_tx`](fd_h2_conn.h.driver.md#fd_h2_tx) to send the header frame with the END_HEADERS flag set.
    - It initializes a transmission operation `tx_op` with the message 'Ok' and the END_STREAM flag, indicating the end of the response stream.
    - The function calls [`test_response_continue`](#test_response_continue) to proceed with the response operation.
    - It checks if the stream state is not closed; if so, it logs that the response is blocked and how many bytes were written.
    - If the stream is closed, it logs that the response is complete.
- **Output**: The function does not return a value; it performs operations related to sending an HTTP/2 response and logs the process.
- **Functions called**:
    - [`fd_h2_tx`](fd_h2_conn.h.driver.md#fd_h2_tx)
    - [`test_response_continue`](#test_response_continue)


---
### test\_cb\_stream\_create<!-- {{#callable:test_cb_stream_create}} -->
The `test_cb_stream_create` function initializes and opens a new HTTP/2 stream if the current stream is not already in use.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
    - `stream_id`: An unsigned integer representing the ID of the stream to be created.
- **Control Flow**:
    - The function begins by casting the `conn` parameter to void to indicate it is unused in this function.
    - It retrieves the current stream from the global application context `g_app`.
    - It checks if the current stream's `stream_id` is already set (i.e., the stream is in use).
    - If the stream is in use, it returns `NULL`.
    - If the stream is not in use, it initializes the stream using `fd_h2_stream_init` and then opens it with [`fd_h2_stream_open`](fd_h2_stream.h.driver.md#fd_h2_stream_open), passing the connection and stream ID.
    - Finally, it returns the newly created stream.
- **Output**: A pointer to the newly created `fd_h2_stream_t` structure, or `NULL` if the stream is already in use.
- **Functions called**:
    - [`fd_h2_stream_open`](fd_h2_stream.h.driver.md#fd_h2_stream_open)


---
### test\_cb\_stream\_query<!-- {{#callable:test_cb_stream_query}} -->
The `test_cb_stream_query` function checks if the current stream's ID matches the given stream ID and returns the stream if it does, otherwise returns NULL.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection; it is not used in this function.
    - `stream_id`: An unsigned integer representing the ID of the stream to be queried.
- **Control Flow**:
    - The function begins by casting the `conn` parameter to void to indicate it is unused.
    - It retrieves the current stream from the global application context `g_app`.
    - The function checks if the `stream_id` of the current stream matches the provided `stream_id`.
    - If the IDs match, the function returns the current stream; otherwise, it returns NULL.
- **Output**: A pointer to an `fd_h2_stream_t` structure if the stream ID matches, otherwise NULL.


---
### test\_cb\_conn\_established<!-- {{#callable:test_cb_conn_established}} -->
The `test_cb_conn_established` function logs a notice indicating that an HTTP/2 connection has been established.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection that has been established.
- **Control Flow**:
    - The function takes a single argument, `conn`, which is a pointer to an `fd_h2_conn_t` structure.
    - The function does not use the `conn` parameter, as indicated by the `(void)conn;` statement, which is used to suppress unused parameter warnings.
    - A log notice is generated using the `FD_LOG_NOTICE` macro to indicate that an HTTP/2 connection has been established.
- **Output**: The function does not return any value; it is a `void` function.


---
### test\_cb\_conn\_final<!-- {{#callable:test_cb_conn_final}} -->
The `test_cb_conn_final` function logs a notice when an HTTP/2 connection is closed, including the error code and its string representation.
- **Inputs**:
    - `conn`: A pointer to the `fd_h2_conn_t` structure representing the HTTP/2 connection that is being closed.
    - `h2_err`: An unsigned integer representing the HTTP/2 error code associated with the connection closure.
    - `closed_by`: An integer indicating who closed the connection, though it is not used in the function body.
- **Control Flow**:
    - The function begins by casting the `conn` and `closed_by` parameters to void to indicate they are unused.
    - It then logs a notice message using `FD_LOG_NOTICE`, which includes the error code `h2_err` and its string representation obtained from [`fd_h2_strerror`](fd_h2_proto.c.driver.md#fd_h2_strerror).
- **Output**: This function does not return any value; it performs logging as a side effect.
- **Functions called**:
    - [`fd_h2_strerror`](fd_h2_proto.c.driver.md#fd_h2_strerror)


---
### test\_cb\_rst\_stream<!-- {{#callable:test_cb_rst_stream}} -->
The `test_cb_rst_stream` function logs a notice about a RST_STREAM event and resets the transmission operation state for a given HTTP/2 stream.
- **Inputs**:
    - `conn`: A pointer to the HTTP/2 connection object (`fd_h2_conn_t`).
    - `stream`: A pointer to the HTTP/2 stream object (`fd_h2_stream_t`) associated with the RST_STREAM event.
    - `error_code`: An unsigned integer representing the error code associated with the RST_STREAM event.
    - `closed_by`: An integer indicating whether the RST_STREAM was received (non-zero) or sent (zero).
- **Control Flow**:
    - The function begins by casting the `conn` parameter to void to indicate it is unused.
    - A log notice is generated, indicating the stream ID, whether the RST_STREAM was received or sent, and the error code with its string representation.
    - The function then clears the `tx_op` field of the global application state `g_app` by setting all bytes to zero.
- **Output**: This function does not return any value; it performs logging and state modification as side effects.
- **Functions called**:
    - [`fd_h2_strerror`](fd_h2_proto.c.driver.md#fd_h2_strerror)


---
### test\_cb\_window\_update<!-- {{#callable:test_cb_window_update}} -->
The `test_cb_window_update` function is a callback that triggers the continuation of a response when a window update is received in an HTTP/2 connection.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
    - `delta`: An unsigned integer representing the amount by which the window size is increased.
- **Control Flow**:
    - The function takes two parameters, `conn` and `delta`, but does not use them directly.
    - It calls the [`test_response_continue`](#test_response_continue) function to proceed with the response handling.
- **Output**: The function does not return any value.
- **Functions called**:
    - [`test_response_continue`](#test_response_continue)


---
### test\_cb\_stream\_window\_update<!-- {{#callable:test_cb_stream_window_update}} -->
The `test_cb_stream_window_update` function is a callback that triggers the continuation of a response when a stream window update is received in an HTTP/2 connection.
- **Inputs**:
    - `conn`: A pointer to the `fd_h2_conn_t` structure representing the HTTP/2 connection.
    - `stream`: A pointer to the `fd_h2_stream_t` structure representing the HTTP/2 stream.
    - `delta`: An unsigned integer representing the change in the window size.
- **Control Flow**:
    - The function takes three parameters: `conn`, `stream`, and `delta`, but does not use them directly.
    - It calls the [`test_response_continue`](#test_response_continue) function to handle the continuation of the response.
- **Output**: The function does not return any value.
- **Functions called**:
    - [`test_response_continue`](#test_response_continue)


---
### test\_cb\_headers<!-- {{#callable:test_cb_headers}} -->
The `test_cb_headers` function processes HTTP/2 header frames, logging each header and handling errors, and initiates a response if the headers or stream are complete.
- **Inputs**:
    - `conn`: A pointer to the HTTP/2 connection object (`fd_h2_conn_t`) associated with the headers being processed.
    - `stream`: A pointer to the HTTP/2 stream object (`fd_h2_stream_t`) associated with the headers being processed.
    - `data`: A pointer to the raw data buffer containing the header block to be processed.
    - `data_sz`: The size of the data buffer in bytes.
    - `flags`: Flags indicating the state of the header block, such as whether it is the end of headers or the end of the stream.
- **Control Flow**:
    - Log the raw header block data for debugging purposes.
    - Initialize an HPACK reader to parse the header block data.
    - Iterate over the header block using the HPACK reader until all headers are processed.
    - For each header, attempt to read the next header field using [`fd_hpack_rd_next`](fd_hpack.c.driver.md#fd_hpack_rd_next).
    - If an error occurs during header reading, log a warning, signal a connection error, and exit the function.
    - Log each successfully read header field name and value.
    - If the `FD_H2_FLAG_END_HEADERS` flag is set, log that the headers are complete for the current stream.
    - If the `FD_H2_FLAG_END_STREAM` flag is set, call [`test_response_init`](#test_response_init) to initiate a response for the stream.
- **Output**: The function does not return a value; it performs logging and may modify the connection or stream state based on the headers processed.
- **Functions called**:
    - [`fd_hpack_rd_done`](fd_hpack.h.driver.md#fd_hpack_rd_done)
    - [`fd_hpack_rd_next`](fd_hpack.c.driver.md#fd_hpack_rd_next)
    - [`fd_h2_strerror`](fd_h2_proto.c.driver.md#fd_h2_strerror)
    - [`fd_h2_conn_error`](fd_h2_conn.h.driver.md#fd_h2_conn_error)
    - [`test_response_init`](#test_response_init)


---
### test\_cb\_data<!-- {{#callable:test_cb_data}} -->
The `test_cb_data` function processes incoming data for an HTTP/2 stream, logging the data and initiating a response if the stream is ending.
- **Inputs**:
    - `conn`: A pointer to the HTTP/2 connection object (`fd_h2_conn_t`) associated with the stream.
    - `stream`: A pointer to the HTTP/2 stream object (`fd_h2_stream_t`) that is receiving the data.
    - `data`: A constant pointer to the data being received.
    - `data_sz`: The size of the data being received, represented as an unsigned long integer.
    - `flags`: Flags associated with the data frame, represented as an unsigned long integer, which may include `FD_H2_FLAG_END_STREAM` to indicate the end of the stream.
- **Control Flow**:
    - Check if the stream's state is illegal (`FD_H2_STREAM_STATE_ILLEGAL`); if so, log a protocol error and return.
    - Log the incoming data using a hex dump for debugging purposes.
    - Check if the `FD_H2_FLAG_END_STREAM` flag is set in the `flags` parameter; if so, call [`test_response_init`](#test_response_init) to initiate a response for the stream.
- **Output**: The function does not return a value; it performs actions such as logging and potentially initiating a response based on the input data and flags.
- **Functions called**:
    - [`fd_h2_conn_error`](fd_h2_conn.h.driver.md#fd_h2_conn_error)
    - [`test_response_init`](#test_response_init)


---
### read\_preface<!-- {{#callable:read_preface}} -->
The `read_preface` function reads and validates the HTTP/2 client preface from a TCP socket to ensure the connection is from a valid HTTP/2 client.
- **Inputs**:
    - `tcp_sock`: An integer representing the file descriptor of the TCP socket from which the client preface is to be read.
- **Control Flow**:
    - Initialize `preface_sz` to 0 and declare a buffer `preface` of size 24 to store the client preface.
    - Enter a loop that continues until `preface_sz` is less than 24, indicating the full preface has not yet been read.
    - Attempt to read from the `tcp_sock` into the `preface` buffer starting at the current `preface_sz` offset, reading up to the remaining buffer size.
    - If the read operation returns a negative result, log a warning about the failure and return 0, indicating an error.
    - If the read operation returns 0, log a warning that the client closed the connection before sending the preface and return 0.
    - If the read data does not match the expected HTTP/2 client preface, log a warning that the client is not a valid HTTP/2 client and return 0.
    - Increment `preface_sz` by the number of bytes successfully read.
    - Once the loop completes, indicating the full preface has been successfully read and validated, return 1.
- **Output**: Returns 1 if the full HTTP/2 client preface is successfully read and validated, otherwise returns 0 if an error occurs or the preface is invalid.


---
### handle\_conn<!-- {{#callable:handle_conn}} -->
The `handle_conn` function manages an HTTP/2 connection over a TCP socket, handling data transmission and reception, and processing HTTP/2 frames.
- **Inputs**:
    - `tcp_sock`: A file descriptor for the TCP socket through which the HTTP/2 connection is established.
- **Control Flow**:
    - Initialize a `test_h2_app_t` structure and static buffers for scratch, receive, and transmit operations.
    - Check if the client preface is correctly read from the TCP socket; if not, return immediately.
    - Set the global application pointer `g_app` to the initialized app structure and initialize the HTTP/2 connection as a server.
    - Set the maximum concurrent streams for the connection to 1.
    - Initialize receive and transmit ring buffers with the respective static buffers.
    - Enter an infinite loop to handle the connection until termination conditions are met.
    - Transmit control frames using [`fd_h2_tx_control`](fd_h2_conn.c.driver.md#fd_h2_tx_control) and the transmit buffer.
    - While there is data in the transmit buffer, send it over the TCP socket using [`fd_h2_rbuf_sendmsg`](fd_h2_rbuf_sock.h.driver.md#fd_h2_rbuf_sendmsg); log and return on error.
    - Check if the connection is marked as dead; if so, log and return.
    - Receive data from the TCP socket into the receive buffer using [`fd_h2_rbuf_recvmsg`](fd_h2_rbuf_sock.h.driver.md#fd_h2_rbuf_recvmsg); handle and log errors appropriately.
    - Process received data using [`fd_h2_rx`](fd_h2_conn.c.driver.md#fd_h2_rx), passing the connection, buffers, and callbacks for further handling.
- **Output**: The function does not return a value; it manages the connection until it is closed or an error occurs.
- **Functions called**:
    - [`read_preface`](#read_preface)
    - [`fd_h2_conn_init_server`](fd_h2_conn.c.driver.md#fd_h2_conn_init_server)
    - [`fd_h2_tx_control`](fd_h2_conn.c.driver.md#fd_h2_tx_control)
    - [`fd_h2_rbuf_used_sz`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_used_sz)
    - [`fd_h2_rbuf_sendmsg`](fd_h2_rbuf_sock.h.driver.md#fd_h2_rbuf_sendmsg)
    - [`fd_h2_rbuf_recvmsg`](fd_h2_rbuf_sock.h.driver.md#fd_h2_rbuf_recvmsg)
    - [`fd_h2_rx`](fd_h2_conn.c.driver.md#fd_h2_rx)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes and runs a simple HTTP/2 server that listens for incoming TCP connections and handles them either in the main process or by forking a new process, based on the specified mode.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the application environment using `fd_boot` with command-line arguments.
    - Initialize HTTP/2 callbacks and set specific callback functions for stream creation, query, connection establishment, finalization, headers, data, reset stream, and window updates.
    - Parse command-line arguments to determine the bind address, port, and mode (either 'simple' or 'fork').
    - Create a TCP socket for listening to incoming connections and bind it to the specified address and port.
    - Set the socket to listen for incoming connections with a backlog of 2.
    - Enter an infinite loop to accept incoming TCP connections.
    - For each accepted connection, log the event and decide whether to handle the connection in the current process or fork a new process based on the mode.
    - If in 'fork' mode, fork a new process to handle the connection and exit the child process after handling.
    - Call [`handle_conn`](#handle_conn) to process the connection, which involves reading the HTTP/2 preface and managing the connection using the initialized callbacks.
    - Close the TCP socket after handling the connection.
    - Log errors and exit if any socket operations fail.
- **Output**: The function returns an integer status code, typically 0, indicating successful execution.
- **Functions called**:
    - [`fd_h2_callbacks_init`](fd_h2_callback.c.driver.md#fd_h2_callbacks_init)
    - [`handle_conn`](#handle_conn)



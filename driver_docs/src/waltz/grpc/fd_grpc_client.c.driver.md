# Purpose
This C source code file implements a gRPC client that communicates over HTTP/2, with optional support for OpenSSL for secure connections. The file provides a comprehensive set of functions to manage the lifecycle of a gRPC client, including memory allocation, connection establishment, request handling, and response processing. The primary technical components include functions for creating and deleting a gRPC client ([`fd_grpc_client_new`](#fd_grpc_client_new) and [`fd_grpc_client_delete`](#fd_grpc_client_delete)), managing stream lifecycles, and handling data transmission over sockets or SSL connections. The code also includes mechanisms for encoding and decoding protocol buffer messages using the nanopb library, and it defines callbacks for handling HTTP/2 events such as headers, data, and stream resets.

The file is designed to be part of a larger system, likely a library, that provides gRPC client functionality. It includes public APIs for creating and managing gRPC client instances, sending requests, and processing responses. The code is structured to handle both secure (SSL) and non-secure (socket) connections, with conditional compilation directives to include OpenSSL-specific functionality when available. The file defines a set of callbacks (`fd_grpc_client_h2_callbacks`) that integrate with an HTTP/2 library, allowing the gRPC client to respond to various HTTP/2 events. This design suggests that the file is intended to be used as a component within a larger application or library that requires gRPC client capabilities, providing a robust and flexible interface for gRPC communication.
# Imports and Dependencies

---
- `fd_grpc_client.h`
- `fd_grpc_client_private.h`
- `../../ballet/nanopb/pb_encode.h`
- `sys/socket.h`
- `../h2/fd_h2_rbuf_sock.h`
- `fd_grpc_codec.h`
- `../openssl/fd_openssl.h`
- `openssl/ssl.h`
- `openssl/err.h`
- `../h2/fd_h2_rbuf_ossl.h`


# Global Variables

---
### fd\_grpc\_client\_h2\_callbacks
- **Type**: `fd_h2_callbacks_t const`
- **Description**: The `fd_grpc_client_h2_callbacks` is a constant instance of the `fd_h2_callbacks_t` structure, which defines a set of callback functions for handling various HTTP/2 events in a gRPC client context. These callbacks include functions for stream creation, querying, connection establishment and finalization, handling headers and data, resetting streams, updating windows, and acknowledging pings.
- **Use**: This variable is used to specify the callback functions that the gRPC client will use to handle HTTP/2 protocol events.


# Functions

---
### fd\_grpc\_client\_align<!-- {{#callable:fd_grpc_client_align}} -->
The `fd_grpc_client_align` function returns the alignment requirement of the `fd_grpc_client_t` type.
- **Inputs**: None
- **Control Flow**:
    - The function simply returns the result of the `alignof` operator applied to `fd_grpc_client_t`.
- **Output**: The function outputs an `ulong` representing the alignment requirement of the `fd_grpc_client_t` type.


---
### fd\_grpc\_client\_footprint<!-- {{#callable:fd_grpc_client_footprint}} -->
The `fd_grpc_client_footprint` function calculates the memory footprint required for a gRPC client with a specified maximum buffer size.
- **Inputs**:
    - `buf_max`: The maximum buffer size for various components of the gRPC client, specified as an unsigned long integer.
- **Control Flow**:
    - Initialize a layout variable `l` with `FD_LAYOUT_INIT`.
    - Append the size and alignment of `fd_grpc_client_t` to the layout `l`.
    - Append the buffer size `buf_max` for `nanopb_tx`, `frame_scratch`, `frame_rx_buf`, and `frame_tx_buf` to the layout `l`.
    - Append the alignment and footprint of the stream pool for the maximum number of streams to the layout `l`.
    - Append the buffer size `buf_max` multiplied by the maximum number of streams to the layout `l`.
    - Finalize the layout `l` with the alignment of `fd_grpc_client_t` and return the total footprint.
- **Output**: The function returns an unsigned long integer representing the total memory footprint required for the gRPC client.
- **Functions called**:
    - [`fd_grpc_client_align`](#fd_grpc_client_align)


---
### fd\_grpc\_client\_new<!-- {{#callable:fd_grpc_client_new}} -->
The `fd_grpc_client_new` function initializes and returns a new gRPC client instance with specified memory, callbacks, metrics, application context, buffer size, and random seed.
- **Inputs**:
    - `mem`: A pointer to the memory block where the client and its associated buffers will be allocated.
    - `callbacks`: A pointer to a structure containing callback functions for handling gRPC client events.
    - `metrics`: A pointer to a structure for tracking metrics related to the gRPC client.
    - `app_ctx`: A pointer to the application-specific context that will be associated with the client.
    - `buf_max`: The maximum size of the buffers used for various operations within the client.
    - `rng_seed`: A seed value for initializing the random number generator used in header matching.
- **Control Flow**:
    - Check if the `mem` pointer is NULL and log a warning if so, returning NULL.
    - Check if `buf_max` is less than 4096 and log a warning if so, returning NULL.
    - Initialize scratch memory allocation using the provided `mem` pointer.
    - Allocate memory for the client structure and various buffers using the scratch allocator.
    - Calculate the end of the allocated memory and verify it matches the expected footprint.
    - Initialize a stream pool for managing gRPC streams and check for successful creation.
    - Set up the client structure with the provided callbacks, context, metrics, and allocated buffers.
    - Initialize receive and transmit buffers for HTTP/2 frames.
    - Initialize a header matcher with the provided random seed and insert standard gRPC headers.
    - Initialize the HTTP/2 connection settings, disabling receive flow control.
    - Set the client version to "0.0.0" and avoid zeroing buffers for performance reasons.
    - Iterate over the stream pool to set up message buffers for each stream.
    - Return the initialized client structure.
- **Output**: A pointer to the newly created `fd_grpc_client_t` structure, or NULL if initialization fails.
- **Functions called**:
    - [`fd_grpc_client_align`](#fd_grpc_client_align)
    - [`fd_grpc_client_footprint`](#fd_grpc_client_footprint)


---
### fd\_grpc\_client\_delete<!-- {{#callable:fd_grpc_client_delete}} -->
The `fd_grpc_client_delete` function returns the pointer to the `fd_grpc_client_t` client passed to it.
- **Inputs**:
    - `client`: A pointer to an `fd_grpc_client_t` structure representing the gRPC client to be deleted.
- **Control Flow**:
    - The function takes a single argument, `client`, which is a pointer to an `fd_grpc_client_t` structure.
    - It immediately returns the `client` pointer without performing any operations on it.
- **Output**: The function returns the same `fd_grpc_client_t` pointer that was passed to it as an argument.


---
### fd\_grpc\_client\_set\_version<!-- {{#callable:fd_grpc_client_set_version}} -->
The `fd_grpc_client_set_version` function sets the version string for a gRPC client, ensuring it does not exceed a maximum length.
- **Inputs**:
    - `client`: A pointer to an `fd_grpc_client_t` structure representing the gRPC client whose version is being set.
    - `version`: A constant character pointer to the version string to be set for the client.
    - `version_len`: An unsigned long integer representing the length of the version string.
- **Control Flow**:
    - Check if the `version_len` exceeds `FD_GRPC_CLIENT_VERSION_LEN_MAX`; if so, log a warning and return without setting the version.
    - If the length is valid, cast `version_len` to an unsigned char and assign it to `client->version_len`.
    - Copy the `version` string into `client->version` using `memcpy` for the specified `version_len`.
- **Output**: The function does not return a value; it modifies the `client` structure in place.


---
### fd\_grpc\_client\_send\_stream\_quota<!-- {{#callable:fd_grpc_client_send_stream_quota}} -->
The `fd_grpc_client_send_stream_quota` function updates the stream's receive window size and sends a WINDOW_UPDATE frame to the transmission buffer.
- **Inputs**:
    - `rbuf_tx`: A pointer to the transmission buffer (fd_h2_rbuf_t) where the WINDOW_UPDATE frame will be pushed.
    - `stream`: A pointer to the gRPC HTTP/2 stream (fd_grpc_h2_stream_t) whose receive window size is to be updated.
    - `bump`: An unsigned integer representing the amount by which the stream's receive window size should be increased.
- **Control Flow**:
    - Create a `fd_h2_window_update_t` structure named `window_update` to represent the WINDOW_UPDATE frame.
    - Set the `typlen` field of the `hdr` sub-structure using `fd_h2_frame_typlen` with the frame type `FD_H2_FRAME_TYPE_WINDOW_UPDATE` and a length of 4 bytes.
    - Set the `r_stream_id` field of the `hdr` sub-structure to the byte-swapped stream ID from the `stream` parameter.
    - Set the `increment` field of the `window_update` structure to the byte-swapped value of `bump`.
    - Push the `window_update` structure into the transmission buffer `rbuf_tx` using `fd_h2_rbuf_push`.
    - Increase the `rx_wnd` field of the `stream` structure by the value of `bump`.
- **Output**: This function does not return a value; it modifies the transmission buffer and the stream's receive window size in place.


---
### fd\_grpc\_client\_send\_stream\_window\_updates<!-- {{#callable:fd_grpc_client_send_stream_window_updates}} -->
The `fd_grpc_client_send_stream_window_updates` function updates the receive window size for gRPC streams when it falls below a certain threshold.
- **Inputs**:
    - `client`: A pointer to an `fd_grpc_client_t` structure representing the gRPC client whose streams' window sizes are to be updated.
- **Control Flow**:
    - Retrieve the connection and transmission buffer from the client structure.
    - Check if the connection has any flags set; if so, exit the function early.
    - Determine the maximum window size and the threshold (half of the maximum window size).
    - Iterate over each stream in the client.
    - For each stream, check if there is enough space in the transmission buffer to send a window update; if not, break the loop.
    - For streams with a receive window size below the threshold, calculate the amount needed to replenish the window to the maximum size.
    - Call [`fd_grpc_client_send_stream_quota`](#fd_grpc_client_send_stream_quota) to send a window update for the stream.
- **Output**: This function does not return a value; it performs operations to update the window sizes of streams within the client.
- **Functions called**:
    - [`fd_grpc_client_send_stream_quota`](#fd_grpc_client_send_stream_quota)


---
### fd\_ossl\_log\_error<!-- {{#callable:fd_ossl_log_error}} -->
The `fd_ossl_log_error` function logs OpenSSL error messages as warnings.
- **Inputs**:
    - `str`: A constant character pointer to the error message string to be logged.
    - `len`: An unsigned long integer representing the length of the error message string.
    - `ctx`: A void pointer to a context, which is not used in this function.
- **Control Flow**:
    - The function begins by explicitly ignoring the `ctx` parameter, indicating it is not used.
    - It then logs the error message using the `FD_LOG_WARNING` macro, formatting the string with the specified length.
    - Finally, the function returns 0, indicating successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution.


---
### fd\_grpc\_client\_rxtx\_ossl<!-- {{#callable:fd_grpc_client_rxtx_ossl}} -->
The `fd_grpc_client_rxtx_ossl` function manages the SSL handshake and data transmission for a gRPC client using OpenSSL.
- **Inputs**:
    - `client`: A pointer to an `fd_grpc_client_t` structure representing the gRPC client.
    - `ssl`: A pointer to an `SSL` structure representing the SSL connection.
    - `charge_busy`: A pointer to an integer that will be set to 1 if any data was read or written, indicating the client was busy.
- **Control Flow**:
    - Check if the SSL handshake is done; if not, attempt to complete it using `SSL_do_handshake`.
    - If the handshake fails with `SSL_ERROR_WANT_READ` or `SSL_ERROR_WANT_WRITE`, return 1 to indicate the operation should be retried.
    - Log an error and return 0 if the handshake fails with any other error.
    - If the handshake is successful, mark it as done in the client structure.
    - Read data from the SSL connection into the client's receive buffer using `fd_h2_rbuf_ssl_read`.
    - If a read error occurs that is not `SSL_ERROR_WANT_READ`, log the error and return 0.
    - If the connection flags are set, call `fd_h2_tx_control` to handle control frames.
    - Process received data using `fd_h2_rx` and update stream windows with [`fd_grpc_client_send_stream_window_updates`](#fd_grpc_client_send_stream_window_updates).
    - Write any pending data from the client's transmit buffer to the SSL connection using `fd_h2_rbuf_ssl_write`.
    - If any data was read or written, set `*charge_busy` to 1.
    - Return 1 to indicate the function completed successfully.
- **Output**: Returns 1 if the operation was successful or should be retried, and 0 if a critical error occurred.
- **Functions called**:
    - [`fd_grpc_client_send_stream_window_updates`](#fd_grpc_client_send_stream_window_updates)


---
### fd\_grpc\_client\_rxtx\_socket<!-- {{#callable:fd_grpc_client_rxtx_socket}} -->
The `fd_grpc_client_rxtx_socket` function handles the reception and transmission of data over a socket for a gRPC client, updating the busy charge status if data was processed.
- **Inputs**:
    - `client`: A pointer to an `fd_grpc_client_t` structure representing the gRPC client.
    - `sock_fd`: An integer representing the socket file descriptor used for communication.
    - `charge_busy`: A pointer to an integer that will be set to 1 if data was received or sent, indicating the client was busy.
- **Control Flow**:
    - Retrieve the connection and initial frame offsets from the client structure.
    - Attempt to receive data from the socket into the client's receive buffer using `fd_h2_rbuf_recvmsg` with non-blocking flags.
    - If receiving data fails, log the error and return 0, indicating disconnection.
    - If the connection has flags set, call `fd_h2_tx_control` to handle control frames.
    - Process received data and prepare outgoing data using `fd_h2_rx` and [`fd_grpc_client_send_stream_window_updates`](#fd_grpc_client_send_stream_window_updates).
    - Attempt to send data from the client's transmit buffer to the socket using `fd_h2_rbuf_sendmsg` with non-blocking flags.
    - If sending data fails, log a warning and return 0.
    - Compare the initial and final frame offsets to determine if any data was processed; if so, set `*charge_busy` to 1.
    - Return 1 to indicate successful processing.
- **Output**: Returns 1 if data was successfully processed, or 0 if there was a disconnection or send error.
- **Functions called**:
    - [`fd_grpc_client_send_stream_window_updates`](#fd_grpc_client_send_stream_window_updates)


---
### fd\_grpc\_client\_request\_continue1<!-- {{#callable:fd_grpc_client_request_continue1}} -->
The `fd_grpc_client_request_continue1` function attempts to continue sending a gRPC request by copying data to the transmission buffer and checking if the request is complete.
- **Inputs**:
    - `client`: A pointer to an `fd_grpc_client_t` structure representing the gRPC client.
- **Control Flow**:
    - Retrieve the current request stream from the client.
    - Copy the transmission operation data from the client to the HTTP/2 stream using `fd_h2_tx_op_copy`.
    - Check if there is any remaining chunk size in the request transmission operation; if so, return 0 indicating the request is not complete.
    - Check if the HTTP/2 stream state is not `FD_H2_STREAM_STATE_CLOSING_TX`; if so, return 0 indicating the request is not complete.
    - Increment the client's metric for transmitted stream chunks.
    - Set the client's request stream to NULL, indicating the request is finished.
    - Invoke the client's `tx_complete` callback to signal the completion of the transmission.
    - Return 1 to indicate the request has been successfully completed.
- **Output**: Returns an integer: 1 if the request is successfully completed, or 0 if it is not yet complete.


---
### fd\_grpc\_client\_request\_continue<!-- {{#callable:fd_grpc_client_request_continue}} -->
The `fd_grpc_client_request_continue` function checks if a gRPC client request can continue by verifying the connection status, request stream, and transmission operation, and then delegates to another function to proceed with the request if conditions are met.
- **Inputs**:
    - `client`: A pointer to an `fd_grpc_client_t` structure representing the gRPC client.
- **Control Flow**:
    - Check if the connection is dead by evaluating the `FD_H2_CONN_FLAGS_DEAD` flag in the client's connection flags; if true, return 0.
    - Check if the `request_stream` is NULL; if true, return 0.
    - Check if the `request_tx_op->chunk_sz` is zero; if true, return 0.
    - Call `fd_grpc_client_request_continue1(client)` to continue the request process.
- **Output**: Returns an integer, 0 if the request cannot continue due to any of the checks failing, or the result of `fd_grpc_client_request_continue1(client)` if the checks pass.
- **Functions called**:
    - [`fd_grpc_client_request_continue1`](#fd_grpc_client_request_continue1)


---
### fd\_grpc\_client\_stream\_acquire\_is\_safe<!-- {{#callable:fd_grpc_client_stream_acquire_is_safe}} -->
The function `fd_grpc_client_stream_acquire_is_safe` checks if a new gRPC client stream can be safely acquired based on quota and resource availability.
- **Inputs**:
    - `client`: A pointer to an `fd_grpc_client_t` structure representing the gRPC client.
- **Control Flow**:
    - Check if the current active stream count plus one exceeds the maximum allowed concurrent streams from the peer settings; if so, log an error and return 0.
    - Check if there is a free stream object available in the stream pool; if not, log an error and return 0.
    - Check if the current stream count has reached the maximum allowed streams for the client; if so, log an error and return 0.
    - If all checks pass, return 1 indicating it is safe to acquire a new stream.
- **Output**: Returns an integer: 1 if it is safe to acquire a new stream, or 0 if it is not safe due to quota or resource constraints.


---
### fd\_grpc\_client\_stream\_acquire<!-- {{#callable:fd_grpc_client_stream_acquire}} -->
The `fd_grpc_client_stream_acquire` function acquires a new gRPC stream for a client, initializing it and updating the client's stream management structures.
- **Inputs**:
    - `client`: A pointer to the `fd_grpc_client_t` structure representing the gRPC client.
    - `request_ctx`: An unsigned long integer representing the context for the request associated with the stream.
- **Control Flow**:
    - Check if the current stream count has reached the maximum allowed streams; if so, log a critical error and exit.
    - Retrieve the connection from the client and determine the next available stream ID, incrementing the stream ID counter by 2.
    - Acquire a stream from the client's stream pool and set its request context to the provided `request_ctx`.
    - Initialize the stream's headers and other fields to default values, indicating no headers received and no message data used.
    - Open the stream using HTTP/2 stream initialization and associate it with the connection and stream ID.
    - Update the client's current request stream, stream IDs, and stream list with the new stream, and increment the stream count.
    - Return the newly acquired and initialized stream.
- **Output**: Returns a pointer to the newly acquired and initialized `fd_grpc_h2_stream_t` structure.


---
### fd\_grpc\_client\_stream\_release<!-- {{#callable:fd_grpc_client_stream_release}} -->
The `fd_grpc_client_stream_release` function releases a gRPC client stream by deallocating resources and updating the stream map.
- **Inputs**:
    - `client`: A pointer to the `fd_grpc_client_t` structure representing the gRPC client.
    - `stream`: A pointer to the `fd_grpc_h2_stream_t` structure representing the stream to be released.
- **Control Flow**:
    - Check if the client's stream count is zero and log a critical error if true, as this indicates a corrupt stream map.
    - If the stream to be released is the current request stream, set the request stream to NULL and reset the request transaction operation.
    - Search for the stream in the client's stream map to find its index.
    - Log a critical error if the stream is not found in the map, indicating a corrupt stream map.
    - If the stream is not the last in the map, replace it with the last stream in the map to maintain a contiguous list.
    - Decrement the client's stream count.
    - Release the stream back to the stream pool.
- **Output**: The function does not return a value; it performs operations to release a stream and update the client's internal state.


---
### fd\_grpc\_client\_request\_is\_blocked<!-- {{#callable:fd_grpc_client_request_is_blocked}} -->
The function `fd_grpc_client_request_is_blocked` checks if a gRPC client request is currently blocked due to various conditions.
- **Inputs**:
    - `client`: A pointer to an `fd_grpc_client_t` structure representing the gRPC client.
- **Control Flow**:
    - Check if the `client` pointer is NULL; if so, return 1 indicating the request is blocked.
    - Check if the connection flags indicate the connection is dead; if so, return 1 indicating the request is blocked.
    - Check if the HTTP/2 handshake is not done; if so, return 1 indicating the request is blocked.
    - Check if the transmission buffer is not empty; if so, return 1 indicating the request is blocked.
    - Check if acquiring a new stream is not safe; if so, return 1 indicating the request is blocked.
    - If none of the above conditions are met, return 0 indicating the request is not blocked.
- **Output**: Returns an integer: 1 if the request is blocked, 0 if it is not.
- **Functions called**:
    - [`fd_grpc_client_stream_acquire_is_safe`](#fd_grpc_client_stream_acquire_is_safe)


---
### fd\_grpc\_client\_request\_start<!-- {{#callable:fd_grpc_client_request_start}} -->
The `fd_grpc_client_request_start` function initiates a gRPC client request by encoding a Protobuf message, preparing HTTP/2 headers, and queuing the request for transmission.
- **Inputs**:
    - `client`: A pointer to the gRPC client structure (`fd_grpc_client_t`) that manages the connection and request state.
    - `host`: A constant character pointer to the host name where the gRPC request is being sent.
    - `host_len`: An unsigned long integer representing the length of the host name.
    - `port`: An unsigned short integer specifying the port number for the gRPC request.
    - `path`: A constant character pointer to the path of the gRPC service being requested.
    - `path_len`: An unsigned long integer representing the length of the path.
    - `request_ctx`: An unsigned long integer used as a context identifier for the request.
    - `fields`: A pointer to a Protobuf message descriptor (`pb_msgdesc_t`) that describes the fields of the message to be encoded.
    - `message`: A constant void pointer to the Protobuf message to be encoded and sent.
    - `auth_token`: A constant character pointer to the authentication token used for bearer authentication.
    - `auth_token_sz`: An unsigned long integer representing the size of the authentication token.
- **Control Flow**:
    - Check if the client is blocked from sending requests using [`fd_grpc_client_request_is_blocked`](#fd_grpc_client_request_is_blocked); if blocked, return 0.
    - Encode the Protobuf message using `pb_encode` into a buffer, logging a warning and returning 0 if encoding fails.
    - Create a gRPC length prefix and copy it to the transmission buffer.
    - Acquire a stream descriptor for the request using [`fd_grpc_client_stream_acquire`](#fd_grpc_client_stream_acquire).
    - Prepare HTTP/2 request headers with `fd_h2_tx_prepare` and generate gRPC request headers with [`fd_grpc_h2_gen_request_hdrs`](fd_grpc_codec.c.driver.md#fd_grpc_h2_gen_request_hdrs), logging a warning and returning 0 if header generation fails.
    - Commit the HTTP/2 headers to the transmission buffer with `fd_h2_tx_commit`.
    - Initialize the transmission operation with `fd_h2_tx_op_init` and continue the request with [`fd_grpc_client_request_continue1`](#fd_grpc_client_request_continue1).
    - Increment the client's metrics for requests sent and active streams.
    - Log a debug message with the request path and serialized size.
    - Return 1 to indicate successful initiation of the request.
- **Output**: Returns an integer: 1 if the request was successfully initiated, or 0 if it was blocked or failed at any step.
- **Functions called**:
    - [`fd_grpc_client_request_is_blocked`](#fd_grpc_client_request_is_blocked)
    - [`fd_grpc_client_stream_acquire`](#fd_grpc_client_stream_acquire)
    - [`fd_grpc_h2_gen_request_hdrs`](fd_grpc_codec.c.driver.md#fd_grpc_h2_gen_request_hdrs)
    - [`fd_grpc_client_request_continue1`](#fd_grpc_client_request_continue1)


---
### fd\_grpc\_h2\_stream\_query<!-- {{#callable:fd_grpc_h2_stream_query}} -->
The `fd_grpc_h2_stream_query` function searches for a stream with a given stream ID within a gRPC client's active streams and returns a pointer to the corresponding HTTP/2 stream if found.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
    - `stream_id`: An unsigned integer representing the ID of the stream to be queried.
- **Control Flow**:
    - Retrieve the gRPC client context from the connection's context.
    - Iterate over the maximum number of streams allowed for the client.
    - For each stream, check if the stream ID matches the given `stream_id`.
    - If a match is found, return a pointer to the corresponding HTTP/2 stream.
    - If no match is found after checking all streams, return `NULL`.
- **Output**: A pointer to the `fd_h2_stream_t` structure corresponding to the stream with the given ID, or `NULL` if no such stream is found.


---
### fd\_grpc\_h2\_conn\_established<!-- {{#callable:fd_grpc_h2_conn_established}} -->
The `fd_grpc_h2_conn_established` function marks the gRPC client's HTTP/2 handshake as complete and triggers the connection established callback.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
- **Control Flow**:
    - Retrieve the gRPC client context from the connection's context.
    - Set the client's `h2_hs_done` flag to 1, indicating the HTTP/2 handshake is complete.
    - Invoke the `conn_established` callback function from the client's callbacks, passing the client's context.
- **Output**: This function does not return any value.


---
### fd\_grpc\_h2\_conn\_final<!-- {{#callable:fd_grpc_h2_conn_final}} -->
The `fd_grpc_h2_conn_final` function handles the finalization of a gRPC HTTP/2 connection by invoking a callback to signal that the connection is dead.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection to be finalized.
    - `h2_err`: An unsigned integer representing the HTTP/2 error code associated with the connection finalization.
    - `closed_by`: An integer indicating who closed the connection (e.g., client or server).
- **Control Flow**:
    - Retrieve the `fd_grpc_client_t` client context from the `conn` structure.
    - Invoke the `conn_dead` callback from the client's callbacks, passing the client context, `h2_err`, and `closed_by` as arguments.
- **Output**: This function does not return any value; it performs an action by invoking a callback.


---
### fd\_grpc\_h2\_cb\_headers<!-- {{#callable:fd_grpc_h2_cb_headers}} -->
The `fd_grpc_h2_cb_headers` function processes HTTP/2 headers received for a gRPC stream, handling errors, and triggering callbacks for the start and end of a response.
- **Inputs**:
    - `conn`: A pointer to the HTTP/2 connection object (`fd_h2_conn_t`) associated with the stream.
    - `h2_stream`: A pointer to the HTTP/2 stream object (`fd_h2_stream_t`) for which headers are being processed.
    - `data`: A pointer to the data buffer containing the HTTP/2 headers.
    - `data_sz`: The size of the data buffer in bytes.
    - `flags`: Flags indicating the state of the headers, such as whether they are the end of the headers or the end of the stream.
- **Control Flow**:
    - Upcast the HTTP/2 stream to a gRPC stream using [`fd_grpc_h2_stream_upcast`](fd_grpc_client_private.h.driver.md#fd_grpc_h2_stream_upcast).
    - Retrieve the gRPC client context from the connection object.
    - Attempt to read and parse the HTTP/2 headers using [`fd_grpc_h2_read_response_hdrs`](fd_grpc_codec.c.driver.md#fd_grpc_h2_read_response_hdrs).
    - If parsing fails, trigger a stream error with `fd_h2_stream_error`, call the `rx_end` callback, and release the stream.
    - If headers are received and the `FD_H2_FLAG_END_HEADERS` flag is set, mark headers as received and call the `rx_start` callback if the status is 200 and the protocol is gRPC.
    - If both `FD_H2_FLAG_END_HEADERS` and `FD_H2_FLAG_END_STREAM` flags are set, call the `rx_end` callback and release the stream.
- **Output**: The function does not return a value; it performs actions such as error handling, invoking callbacks, and releasing resources based on the headers received.
- **Functions called**:
    - [`fd_grpc_h2_stream_upcast`](fd_grpc_client_private.h.driver.md#fd_grpc_h2_stream_upcast)
    - [`fd_grpc_h2_read_response_hdrs`](fd_grpc_codec.c.driver.md#fd_grpc_h2_read_response_hdrs)
    - [`fd_grpc_client_stream_release`](#fd_grpc_client_stream_release)


---
### fd\_grpc\_h2\_cb\_data<!-- {{#callable:fd_grpc_h2_cb_data}} -->
The `fd_grpc_h2_cb_data` function processes incoming gRPC data frames for a specific HTTP/2 stream, handling message headers and payloads, and invoking callbacks upon message completion or stream termination.
- **Inputs**:
    - `conn`: A pointer to the HTTP/2 connection object (`fd_h2_conn_t`) associated with the gRPC client.
    - `h2_stream`: A pointer to the HTTP/2 stream object (`fd_h2_stream_t`) that is receiving the data.
    - `data`: A pointer to the data buffer containing the incoming gRPC data.
    - `data_sz`: The size of the data buffer in bytes.
    - `flags`: Flags indicating the state of the data frame, such as whether it is the end of the stream.
- **Control Flow**:
    - Retrieve the gRPC client and stream objects from the connection and stream pointers.
    - Check if the HTTP/2 status is 200 and if the protocol is gRPC; if not, exit the function.
    - Enter a loop to process the incoming data buffer.
    - If the message buffer has not yet received a complete header, copy header bytes from the data buffer to the message buffer.
    - Once the header is complete, calculate the message size and check if it exceeds the buffer's maximum size; if so, log a warning, send an error, and release the stream.
    - Copy payload bytes from the data buffer to the message buffer until the message is complete.
    - Update the client's metrics for received chunks and bytes.
    - If the message is complete, invoke the client's `rx_msg` callback with the message data and reset the message buffer.
    - Continue processing until all data is consumed.
    - If the `FD_H2_FLAG_END_STREAM` flag is set, check for incomplete messages, log a warning if necessary, and invoke the client's `rx_end` callback.
- **Output**: The function does not return a value; it processes data and invokes callbacks as necessary.
- **Functions called**:
    - [`fd_grpc_h2_stream_upcast`](fd_grpc_client_private.h.driver.md#fd_grpc_h2_stream_upcast)
    - [`fd_grpc_client_stream_release`](#fd_grpc_client_stream_release)


---
### fd\_grpc\_h2\_rst\_stream<!-- {{#callable:fd_grpc_h2_rst_stream}} -->
The `fd_grpc_h2_rst_stream` function handles the termination of a gRPC HTTP/2 stream by logging a warning and releasing the stream resources.
- **Inputs**:
    - `conn`: A pointer to the `fd_h2_conn_t` structure representing the HTTP/2 connection.
    - `stream`: A pointer to the `fd_h2_stream_t` structure representing the HTTP/2 stream to be reset.
    - `error_code`: An unsigned integer representing the error code associated with the stream reset.
    - `closed_by`: An integer indicating who closed the stream (1 if closed by the server, otherwise by the client).
- **Control Flow**:
    - Check if the stream was closed by the server (if `closed_by` is 1).
    - Log a warning message indicating the server terminated the request with the stream ID and error code.
    - If not closed by the server, log a warning message indicating the stream failed with the stream ID and error code.
    - Retrieve the gRPC client context from the connection context.
    - Release the stream resources using [`fd_grpc_client_stream_release`](#fd_grpc_client_stream_release).
- **Output**: This function does not return a value; it performs logging and resource cleanup.
- **Functions called**:
    - [`fd_grpc_client_stream_release`](#fd_grpc_client_stream_release)
    - [`fd_grpc_h2_stream_upcast`](fd_grpc_client_private.h.driver.md#fd_grpc_h2_stream_upcast)


---
### fd\_grpc\_h2\_window\_update<!-- {{#callable:fd_grpc_h2_window_update}} -->
The `fd_grpc_h2_window_update` function triggers the continuation of a gRPC client request when a window update is received.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
    - `increment`: An unsigned integer representing the window size increment, which is not used in this function.
- **Control Flow**:
    - The function takes two parameters: a connection object and an increment value.
    - The increment value is explicitly ignored using a cast to void.
    - The function calls [`fd_grpc_client_request_continue`](#fd_grpc_client_request_continue) with the context of the connection to continue processing the gRPC client request.
- **Output**: The function does not return any value.
- **Functions called**:
    - [`fd_grpc_client_request_continue`](#fd_grpc_client_request_continue)


---
### fd\_grpc\_h2\_stream\_window\_update<!-- {{#callable:fd_grpc_h2_stream_window_update}} -->
The `fd_grpc_h2_stream_window_update` function triggers the continuation of a gRPC client request when a stream window update occurs.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
    - `stream`: A pointer to an `fd_h2_stream_t` structure representing the HTTP/2 stream.
    - `increment`: An unsigned integer representing the increment value for the stream window update.
- **Control Flow**:
    - The function begins by explicitly ignoring the `stream` and `increment` parameters using `(void)stream; (void)increment;` to avoid unused variable warnings.
    - It then calls [`fd_grpc_client_request_continue`](#fd_grpc_client_request_continue) with the connection's context (`conn->ctx`) to attempt to continue sending a gRPC client request.
- **Output**: The function does not return any value; it has a `void` return type.
- **Functions called**:
    - [`fd_grpc_client_request_continue`](#fd_grpc_client_request_continue)


---
### fd\_grpc\_h2\_ping\_ack<!-- {{#callable:fd_grpc_h2_ping_ack}} -->
The `fd_grpc_h2_ping_ack` function handles a gRPC HTTP/2 ping acknowledgment by invoking a callback function.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
- **Control Flow**:
    - Retrieve the `fd_grpc_client_t` client context from the `conn` structure.
    - Invoke the `ping_ack` callback function from the client's callbacks, passing the client's context as an argument.
- **Output**: This function does not return any value.


---
### fd\_grpc\_client\_rbuf\_tx<!-- {{#callable:fd_grpc_client_rbuf_tx}} -->
The `fd_grpc_client_rbuf_tx` function retrieves the transmission buffer for a gRPC client's HTTP/2 frames.
- **Inputs**:
    - `client`: A pointer to an `fd_grpc_client_t` structure representing the gRPC client.
- **Control Flow**:
    - The function accesses the `frame_tx` member of the `fd_grpc_client_t` structure pointed to by `client`.
    - It returns the value of `client->frame_tx`, which is a pointer to an `fd_h2_rbuf_t` structure.
- **Output**: A pointer to an `fd_h2_rbuf_t` structure representing the transmission buffer for HTTP/2 frames.


---
### fd\_grpc\_client\_rbuf\_rx<!-- {{#callable:fd_grpc_client_rbuf_rx}} -->
The `fd_grpc_client_rbuf_rx` function retrieves the receive buffer for a gRPC client.
- **Inputs**:
    - `client`: A pointer to an `fd_grpc_client_t` structure representing the gRPC client.
- **Control Flow**:
    - The function takes a single argument, `client`, which is a pointer to an `fd_grpc_client_t` structure.
    - It directly returns the `frame_rx` member of the `client` structure, which is a pointer to an `fd_h2_rbuf_t` type.
- **Output**: A pointer to an `fd_h2_rbuf_t` structure, representing the receive buffer of the gRPC client.


---
### fd\_grpc\_client\_h2\_conn<!-- {{#callable:fd_grpc_client_h2_conn}} -->
The `fd_grpc_client_h2_conn` function retrieves the HTTP/2 connection associated with a given gRPC client.
- **Inputs**:
    - `client`: A pointer to an `fd_grpc_client_t` structure representing the gRPC client whose HTTP/2 connection is to be retrieved.
- **Control Flow**:
    - The function takes a single argument, `client`, which is a pointer to an `fd_grpc_client_t` structure.
    - It directly accesses the `conn` member of the `fd_grpc_client_t` structure pointed to by `client`.
    - The function returns the value of the `conn` member, which is a pointer to an `fd_h2_conn_t` structure.
- **Output**: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection associated with the provided gRPC client.



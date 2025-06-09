# Purpose
The provided C source code file is part of an implementation for handling HTTP/2 connections, specifically focusing on the management of HTTP/2 frames and connection settings. The code defines functions for initializing HTTP/2 connections for both clients and servers, encoding and generating settings frames, and processing various types of HTTP/2 frames such as DATA, HEADERS, SETTINGS, PING, and GOAWAY. The file includes functions to handle the reception and transmission of these frames, ensuring compliance with the HTTP/2 protocol specifications, such as flow control and error handling.

Key components of the code include structures and functions for managing connection settings (`fd_h2_settings_t`), window sizes, and stream states. The code also defines callback mechanisms (`fd_h2_callbacks_t`) to interact with higher-level application logic, allowing for custom handling of events like receiving headers or data. The file is designed to be part of a larger library, as indicated by the inclusion of multiple header files and the use of static functions for internal operations. It does not define a public API directly but provides essential functionality for managing HTTP/2 connections, making it a critical component of an HTTP/2 communication stack.
# Imports and Dependencies

---
- `fd_h2_conn.h`
- `fd_h2_callback.h`
- `fd_h2_proto.h`
- `fd_h2_rbuf.h`
- `fd_h2_stream.h`
- `float.h`


# Global Variables

---
### fd\_h2\_client\_preface
- **Type**: ``char const[24]``
- **Description**: The `fd_h2_client_preface` is a constant character array of size 24 that contains the HTTP/2 client connection preface string. This string is used to initiate an HTTP/2 connection from the client side, signaling the start of the HTTP/2 communication.
- **Use**: This variable is used to send the initial client preface when establishing an HTTP/2 connection.


---
### fd\_h2\_settings\_initial
- **Type**: `fd_h2_settings_t const`
- **Description**: The `fd_h2_settings_initial` is a constant instance of the `fd_h2_settings_t` structure, which defines initial settings for an HTTP/2 connection. It specifies the maximum number of concurrent streams, the initial window size, the maximum frame size, and the maximum header list size for the connection.
- **Use**: This variable is used to initialize the settings for both client and server HTTP/2 connections, ensuring they start with a predefined configuration.


# Functions

---
### fd\_h2\_conn\_init\_window<!-- {{#callable:fd_h2_conn_init_window}} -->
The `fd_h2_conn_init_window` function initializes the receive and transmit window sizes for an HTTP/2 connection.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection whose window sizes are to be initialized.
- **Control Flow**:
    - Set the maximum receive window size (`rx_wnd_max`) to 65535.
    - Initialize the current receive window size (`rx_wnd`) to the maximum receive window size (`rx_wnd_max`).
    - Calculate and set the receive window watermark (`rx_wnd_wmark`) to 70% of the maximum receive window size.
    - Set the transmit window size (`tx_wnd`) to 65535.
- **Output**: This function does not return a value; it modifies the `conn` structure in place.


---
### fd\_h2\_conn\_init\_client<!-- {{#callable:fd_h2_conn_init_client}} -->
The `fd_h2_conn_init_client` function initializes an HTTP/2 connection structure for a client with default settings and prepares the connection's flow control windows.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure that will be initialized for client use.
- **Control Flow**:
    - The function initializes the `conn` structure with default HTTP/2 settings, setting both `self_settings` and `peer_settings` to `fd_h2_settings_initial`.
    - It sets the `flags` field to `FD_H2_CONN_FLAGS_CLIENT_INITIAL` to indicate the connection is a client.
    - The `tx_stream_next` is set to 1 and `rx_stream_next` is set to 2, which are the initial stream identifiers for a client connection.
    - The function calls [`fd_h2_conn_init_window`](#fd_h2_conn_init_window) to initialize the connection's flow control windows.
    - Finally, the function returns the initialized `conn` pointer.
- **Output**: Returns a pointer to the initialized `fd_h2_conn_t` structure for client use.
- **Functions called**:
    - [`fd_h2_conn_init_window`](#fd_h2_conn_init_window)


---
### fd\_h2\_conn\_init\_server<!-- {{#callable:fd_h2_conn_init_server}} -->
The `fd_h2_conn_init_server` function initializes an HTTP/2 server connection structure with default settings and prepares it for use.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure that will be initialized as a server connection.
- **Control Flow**:
    - The function initializes the `conn` structure with default settings for both self and peer, sets the server-specific flags, and initializes stream identifiers for transmission and reception.
    - It calls [`fd_h2_conn_init_window`](#fd_h2_conn_init_window) to set up the initial window sizes for the connection.
    - Finally, it returns the initialized `conn` structure.
- **Output**: Returns a pointer to the initialized `fd_h2_conn_t` structure.
- **Functions called**:
    - [`fd_h2_conn_init_window`](#fd_h2_conn_init_window)


---
### fd\_h2\_setting\_encode<!-- {{#callable:fd_h2_setting_encode}} -->
The `fd_h2_setting_encode` function encodes an HTTP/2 setting by storing a byte-swapped setting ID and setting value into a buffer.
- **Inputs**:
    - `buf`: A pointer to a buffer where the encoded setting will be stored.
    - `setting_id`: A 16-bit unsigned integer representing the setting ID to be encoded.
    - `setting_value`: A 32-bit unsigned integer representing the setting value to be encoded.
- **Control Flow**:
    - The function uses `FD_STORE` to store the byte-swapped `setting_id` into the buffer at the starting position.
    - It then stores the byte-swapped `setting_value` into the buffer starting at an offset of 2 bytes.
- **Output**: The function does not return a value; it modifies the buffer in place to contain the encoded setting.
- **Functions called**:
    - [`fd_ushort_bswap`](../../util/bits/fd_bits.h.driver.md#fd_ushort_bswap)
    - [`fd_uint_bswap`](../../util/bits/fd_bits.h.driver.md#fd_uint_bswap)


---
### fd\_h2\_gen\_settings<!-- {{#callable:fd_h2_gen_settings}} -->
The `fd_h2_gen_settings` function encodes HTTP/2 settings into a buffer for transmission.
- **Inputs**:
    - `settings`: A pointer to a `fd_h2_settings_t` structure containing the HTTP/2 settings to be encoded.
    - `buf`: A buffer of size `FD_H2_OUR_SETTINGS_ENCODED_SZ` where the encoded settings will be stored.
- **Control Flow**:
    - Initialize a `fd_h2_frame_hdr_t` structure with the type and length of the settings frame.
    - Copy the frame header into the beginning of the buffer using `fd_memcpy`.
    - Encode each HTTP/2 setting using [`fd_h2_setting_encode`](#fd_h2_setting_encode) and store them sequentially in the buffer starting from the 9th byte.
    - The settings encoded include `HEADER_TABLE_SIZE`, `ENABLE_PUSH`, `MAX_CONCURRENT_STREAMS`, `INITIAL_WINDOW_SIZE`, `MAX_FRAME_SIZE`, and `MAX_HEADER_LIST_SIZE`.
- **Output**: The function does not return a value; it populates the provided buffer with the encoded settings.
- **Functions called**:
    - [`fd_h2_frame_typlen`](fd_h2_proto.h.driver.md#fd_h2_frame_typlen)
    - [`fd_h2_setting_encode`](#fd_h2_setting_encode)


---
### fd\_h2\_rx\_data<!-- {{#callable:fd_h2_rx_data}} -->
The `fd_h2_rx_data` function processes a partial HTTP/2 DATA frame, handling flow control, stream state validation, and data delivery to the application layer.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
    - `rbuf_rx`: A pointer to an `fd_h2_rbuf_t` structure representing the receive buffer.
    - `rbuf_tx`: A pointer to an `fd_h2_rbuf_t` structure representing the transmit buffer.
    - `cb`: A pointer to a constant `fd_h2_callbacks_t` structure containing callback functions for stream and connection events.
- **Control Flow**:
    - Check if there is enough space in the transmit buffer for two WINDOW_UPDATE frames; if not, return immediately.
    - Calculate the remaining frame size, available buffer size, stream ID, chunk size, and end-of-stream flag.
    - Query the stream using the callback function and check if the stream is in a valid state (OPEN or CLOSING_TX); if not, send a STREAM_CLOSED error and skip the frame.
    - Check if the chunk size exceeds the connection's receive window; if so, send a FLOW_CONTROL error and return.
    - Subtract the chunk size from the connection's receive window.
    - Check if the chunk size exceeds the stream's receive window; if so, send a FLOW_CONTROL error and skip the frame.
    - Subtract the chunk size from the stream's receive window.
    - Call the stream's data receive function with the appropriate flags.
    - Check if the stream state is ILLEGAL; if so, send a PROTOCOL error and return.
    - Peek into the receive buffer to get the data chunk and call the data callback function with the data and flags.
    - Skip the processed frame data in the receive buffer.
    - Check if the connection's receive window is below the watermark; if so, set the WINDOW_UPDATE flag.
- **Output**: The function does not return a value; it modifies the state of the connection and stream, and may trigger callbacks for data and error handling.
- **Functions called**:
    - [`fd_h2_rbuf_free_sz`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_free_sz)
    - [`fd_h2_rbuf_used_sz`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_used_sz)
    - [`fd_h2_stream_error1`](fd_h2_stream.h.driver.md#fd_h2_stream_error1)
    - [`fd_h2_conn_error`](fd_h2_conn.h.driver.md#fd_h2_conn_error)
    - [`fd_h2_stream_rx_data`](fd_h2_stream.h.driver.md#fd_h2_stream_rx_data)
    - [`fd_h2_rbuf_peek_used`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_peek_used)
    - [`fd_h2_rbuf_skip`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_skip)


---
### fd\_h2\_rx\_headers<!-- {{#callable:fd_h2_rx_headers}} -->
The `fd_h2_rx_headers` function processes HTTP/2 HEADERS frames, handling stream creation, priority, and header continuation, while invoking callbacks for header processing.
- **Inputs**:
    - `conn`: A pointer to the HTTP/2 connection structure (`fd_h2_conn_t`) representing the current connection state.
    - `rbuf_tx`: A pointer to the transmit buffer (`fd_h2_rbuf_t`) used for sending responses or errors.
    - `payload`: A pointer to the payload data of the HEADERS frame.
    - `payload_sz`: The size of the payload data in bytes.
    - `cb`: A pointer to the structure containing callback functions (`fd_h2_callbacks_t`) for handling various HTTP/2 events.
    - `frame_flags`: Flags associated with the HEADERS frame, indicating properties like priority or end of headers.
    - `stream_id`: The identifier of the stream to which the HEADERS frame belongs.
- **Control Flow**:
    - Check if the `stream_id` is zero; if so, report a protocol error and return 0.
    - Query the stream associated with `stream_id` using the callback; if not found, check for protocol errors or create a new stream if allowed.
    - If a new stream is created, initialize it and update connection state variables.
    - Set the connection's current stream ID to `stream_id`.
    - If the PRIORITY flag is set, adjust the payload to skip priority information and check for frame size errors.
    - If the END_HEADERS flag is not set, mark the connection for continuation.
    - Process the headers for the stream using [`fd_h2_stream_rx_headers`](fd_h2_stream.h.driver.md#fd_h2_stream_rx_headers) and check for illegal stream states.
    - Invoke the headers callback to process the received headers.
    - Return 1 to indicate successful processing.
- **Output**: Returns an integer indicating success (1) or failure (0) in processing the HEADERS frame.
- **Functions called**:
    - [`fd_h2_conn_error`](fd_h2_conn.h.driver.md#fd_h2_conn_error)
    - [`fd_h2_stream_error1`](fd_h2_stream.h.driver.md#fd_h2_stream_error1)
    - [`fd_h2_stream_open`](fd_h2_stream.h.driver.md#fd_h2_stream_open)
    - [`fd_h2_stream_rx_headers`](fd_h2_stream.h.driver.md#fd_h2_stream_rx_headers)


---
### fd\_h2\_rx\_priority<!-- {{#callable:fd_h2_rx_priority}} -->
The `fd_h2_rx_priority` function validates the payload size and stream ID for an HTTP/2 PRIORITY frame and returns a status indicating success or failure.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
    - `payload_sz`: An unsigned long integer representing the size of the payload for the PRIORITY frame.
    - `stream_id`: An unsigned integer representing the stream identifier for the PRIORITY frame.
- **Control Flow**:
    - Check if `payload_sz` is not equal to 5; if true, call [`fd_h2_conn_error`](fd_h2_conn.h.driver.md#fd_h2_conn_error) with `FD_H2_ERR_FRAME_SIZE` and return 0.
    - Check if `stream_id` is zero; if true, call [`fd_h2_conn_error`](fd_h2_conn.h.driver.md#fd_h2_conn_error) with `FD_H2_ERR_PROTOCOL` and return 0.
    - If both checks pass, return 1 indicating success.
- **Output**: Returns an integer: 1 if the PRIORITY frame is valid, or 0 if there is an error.
- **Functions called**:
    - [`fd_h2_conn_error`](fd_h2_conn.h.driver.md#fd_h2_conn_error)


---
### fd\_h2\_rx\_continuation<!-- {{#callable:fd_h2_rx_continuation}} -->
The `fd_h2_rx_continuation` function processes HTTP/2 CONTINUATION frames, ensuring protocol compliance and invoking callbacks for header processing.
- **Inputs**:
    - `conn`: A pointer to the HTTP/2 connection structure (`fd_h2_conn_t`) representing the current connection state.
    - `rbuf_tx`: A pointer to the transmit buffer (`fd_h2_rbuf_t`) used for sending data back to the peer.
    - `payload`: A pointer to the payload data of the CONTINUATION frame.
    - `payload_sz`: The size of the payload data in bytes.
    - `cb`: A pointer to the structure containing callback functions (`fd_h2_callbacks_t`) for handling various HTTP/2 events.
    - `frame_flags`: Flags associated with the CONTINUATION frame, indicating specific conditions or actions.
    - `stream_id`: The identifier of the stream to which the CONTINUATION frame belongs.
- **Control Flow**:
    - Check if the stream ID matches the expected stream ID, if the connection is in a continuation state, and if the stream ID is non-zero; if any condition fails, report a protocol error and return 0.
    - If the END_HEADERS flag is set in the frame flags, clear the continuation flag in the connection's flags.
    - Query the stream associated with the given stream ID using the callback; if the stream is not found, report an internal error and return 1.
    - Process the headers for the stream using [`fd_h2_stream_rx_headers`](fd_h2_stream.h.driver.md#fd_h2_stream_rx_headers); if the stream state is illegal, report a protocol error and return 0.
    - Invoke the `headers` callback to process the headers with the provided payload, payload size, and frame flags.
    - Return 1 to indicate successful processing of the CONTINUATION frame.
- **Output**: Returns an integer indicating success (1) or failure (0) in processing the CONTINUATION frame.
- **Functions called**:
    - [`fd_h2_conn_error`](fd_h2_conn.h.driver.md#fd_h2_conn_error)
    - [`fd_h2_stream_error1`](fd_h2_stream.h.driver.md#fd_h2_stream_error1)
    - [`fd_h2_stream_rx_headers`](fd_h2_stream.h.driver.md#fd_h2_stream_rx_headers)


---
### fd\_h2\_rx\_rst\_stream<!-- {{#callable:fd_h2_rx_rst_stream}} -->
The `fd_h2_rx_rst_stream` function processes an HTTP/2 RST_STREAM frame, validating its size and stream ID, and then resets the specified stream if it exists.
- **Inputs**:
    - `conn`: A pointer to the HTTP/2 connection structure (`fd_h2_conn_t`) representing the current connection context.
    - `payload`: A pointer to the payload data of the RST_STREAM frame, expected to contain a 4-byte error code.
    - `payload_sz`: The size of the payload, which should be exactly 4 bytes for a valid RST_STREAM frame.
    - `cb`: A pointer to a structure of callback functions (`fd_h2_callbacks_t`) used to interact with the stream and connection.
    - `stream_id`: The identifier of the stream to be reset, which must be a valid and active stream ID.
- **Control Flow**:
    - Check if the payload size is not equal to 4 bytes; if so, report a frame size error and return 0.
    - Check if the stream ID is zero; if so, report a protocol error and return 0.
    - Check if the stream ID is greater than or equal to the maximum of the next expected receive or transmit stream ID; if so, report a protocol error and return 0.
    - Query the stream using the callback function `stream_query` with the given stream ID.
    - If the stream exists, load the error code from the payload, reset the stream using [`fd_h2_stream_reset`](fd_h2_stream.h.driver.md#fd_h2_stream_reset), and invoke the `rst_stream` callback with the error code.
    - Return 1 to indicate successful processing of the RST_STREAM frame.
- **Output**: Returns an integer, 1 if the RST_STREAM frame was processed successfully, or 0 if an error occurred.
- **Functions called**:
    - [`fd_h2_conn_error`](fd_h2_conn.h.driver.md#fd_h2_conn_error)
    - [`fd_uint_bswap`](../../util/bits/fd_bits.h.driver.md#fd_uint_bswap)
    - [`fd_h2_stream_reset`](fd_h2_stream.h.driver.md#fd_h2_stream_reset)


---
### fd\_h2\_rx\_settings<!-- {{#callable:fd_h2_rx_settings}} -->
The `fd_h2_rx_settings` function processes incoming HTTP/2 SETTINGS frames, updating connection settings and handling protocol errors.
- **Inputs**:
    - `conn`: A pointer to the HTTP/2 connection structure (`fd_h2_conn_t`) that maintains the state of the connection.
    - `rbuf_tx`: A pointer to the transmit buffer (`fd_h2_rbuf_t`) used for sending frames back to the peer.
    - `payload`: A constant pointer to the payload data of the SETTINGS frame.
    - `payload_sz`: The size of the payload data in bytes.
    - `cb`: A constant pointer to a structure of callback functions (`fd_h2_callbacks_t`) used for various connection events.
    - `frame_flags`: Flags associated with the SETTINGS frame, indicating special conditions like ACK.
    - `stream_id`: The stream identifier, which should be zero for SETTINGS frames as they are connection-level.
- **Control Flow**:
    - Check if `stream_id` is non-zero and return a protocol error if true.
    - Check if the connection is in the server initial state and return if true, as the first frame should be SETTINGS, not SETTINGS ACK.
    - If the frame has the ACK flag, verify the payload size is zero and decrement the `setting_tx` counter, handling errors if conditions are not met.
    - If the payload size is not a multiple of 6, return a frame size error.
    - Iterate over the payload in chunks of 6 bytes, processing each setting by its ID and value, updating connection settings or returning errors for invalid values.
    - Prepare an ACK frame header and push it to the transmit buffer if there is enough space, otherwise return an internal error.
    - Clear the WAIT_SETTINGS_0 flag and call the connection established callback if the connection is not handshaking.
- **Output**: Returns 1 on successful processing of the SETTINGS frame, or 0 if an error occurs.
- **Functions called**:
    - [`fd_h2_conn_error`](fd_h2_conn.h.driver.md#fd_h2_conn_error)
    - [`fd_ushort_bswap`](../../util/bits/fd_bits.h.driver.md#fd_ushort_bswap)
    - [`fd_uint_bswap`](../../util/bits/fd_bits.h.driver.md#fd_uint_bswap)
    - [`fd_h2_frame_typlen`](fd_h2_proto.h.driver.md#fd_h2_frame_typlen)
    - [`fd_h2_rbuf_free_sz`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_free_sz)
    - [`fd_h2_rbuf_push`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_push)


---
### fd\_h2\_rx\_push\_promise<!-- {{#callable:fd_h2_rx_push_promise}} -->
The `fd_h2_rx_push_promise` function handles the reception of a PUSH_PROMISE frame by immediately triggering a protocol error on the connection.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection on which the PUSH_PROMISE frame was received.
- **Control Flow**:
    - The function calls [`fd_h2_conn_error`](fd_h2_conn.h.driver.md#fd_h2_conn_error) with the connection and a protocol error code `FD_H2_ERR_PROTOCOL` to indicate a protocol violation.
    - The function returns 0, indicating that the operation did not succeed.
- **Output**: The function returns an integer value of 0, indicating a failure or error in processing the PUSH_PROMISE frame.
- **Functions called**:
    - [`fd_h2_conn_error`](fd_h2_conn.h.driver.md#fd_h2_conn_error)


---
### fd\_h2\_rx\_ping<!-- {{#callable:fd_h2_rx_ping}} -->
The `fd_h2_rx_ping` function processes incoming HTTP/2 PING frames, handling both new PING requests and acknowledgements (PONGs).
- **Inputs**:
    - `conn`: A pointer to the HTTP/2 connection structure (`fd_h2_conn_t`) representing the current connection state.
    - `rbuf_tx`: A pointer to the transmit buffer (`fd_h2_rbuf_t`) used for sending data back to the peer.
    - `payload`: A constant pointer to the payload data of the PING frame, expected to be 8 bytes in size.
    - `payload_sz`: The size of the payload, which should be exactly 8 bytes for a valid PING frame.
    - `cb`: A constant pointer to the callback structure (`fd_h2_callbacks_t`) containing function pointers for handling various events.
    - `frame_flags`: Flags associated with the PING frame, indicating whether it is an ACK or a new PING.
    - `stream_id`: The stream identifier, which should be zero for PING frames as they are connection-level frames.
- **Control Flow**:
    - Check if the payload size is not 8 bytes; if so, report a frame size error and return 0.
    - Check if the stream ID is non-zero; if so, report a protocol error and return 0.
    - If the frame has the ACK flag set, check if there are any outstanding PINGs; if not, ignore the unsolicited ACK, otherwise call the `ping_ack` callback and decrement the `ping_tx` counter.
    - If the frame does not have the ACK flag, prepare a PONG response with the same payload, check if there is enough space in the transmit buffer, and if so, push the PONG frame to the buffer.
    - Return 1 to indicate successful processing of the PING frame.
- **Output**: Returns an integer: 1 if the PING frame was processed successfully, or 0 if there was an error.
- **Functions called**:
    - [`fd_h2_conn_error`](fd_h2_conn.h.driver.md#fd_h2_conn_error)
    - [`fd_h2_frame_typlen`](fd_h2_proto.h.driver.md#fd_h2_frame_typlen)
    - [`fd_h2_rbuf_free_sz`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_free_sz)
    - [`fd_h2_rbuf_push`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_push)


---
### fd\_h2\_tx\_ping<!-- {{#callable:fd_h2_tx_ping}} -->
The `fd_h2_tx_ping` function sends a PING frame over an HTTP/2 connection if conditions allow, updating the connection's ping transmission count.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
    - `rbuf_tx`: A pointer to an `fd_h2_rbuf_t` structure representing the transmission buffer where the PING frame will be pushed.
- **Control Flow**:
    - Retrieve the current ping transmission count from the connection structure.
    - Check if the transmission buffer has enough space for a PING frame and if the ping transmission count is less than `UCHAR_MAX`.
    - If either condition is not met, return 0 indicating the operation is blocked.
    - Create a PING frame with a header and payload initialized to zero.
    - Push the PING frame into the transmission buffer.
    - Increment the connection's ping transmission count by one.
    - Return 1 indicating the PING frame was successfully sent.
- **Output**: Returns 1 if the PING frame is successfully sent, otherwise returns 0 if blocked.
- **Functions called**:
    - [`fd_h2_rbuf_free_sz`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_free_sz)
    - [`fd_h2_frame_typlen`](fd_h2_proto.h.driver.md#fd_h2_frame_typlen)
    - [`fd_h2_rbuf_push`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_push)


---
### fd\_h2\_rx\_goaway<!-- {{#callable:fd_h2_rx_goaway}} -->
The `fd_h2_rx_goaway` function processes an HTTP/2 GOAWAY frame, marking the connection as dead and invoking a callback with the error code.
- **Inputs**:
    - `conn`: A pointer to the `fd_h2_conn_t` structure representing the HTTP/2 connection.
    - `cb`: A pointer to a constant `fd_h2_callbacks_t` structure containing callback functions for connection events.
    - `payload`: A pointer to the payload data of the GOAWAY frame.
    - `payload_sz`: The size of the payload data in bytes.
    - `stream_id`: The stream identifier associated with the frame, which should be zero for a GOAWAY frame.
- **Control Flow**:
    - Check if `stream_id` is non-zero, indicating a protocol error, and return 0 after calling [`fd_h2_conn_error`](fd_h2_conn.h.driver.md#fd_h2_conn_error) with `FD_H2_ERR_PROTOCOL`.
    - Check if `payload_sz` is less than 8, indicating a frame size error, and return 0 after calling [`fd_h2_conn_error`](fd_h2_conn.h.driver.md#fd_h2_conn_error) with `FD_H2_ERR_FRAME_SIZE`.
    - Extract the error code from the payload using [`fd_uint_bswap`](../../util/bits/fd_bits.h.driver.md#fd_uint_bswap) and `FD_LOAD`.
    - Set the connection's flags to `FD_H2_CONN_FLAGS_DEAD` to mark it as dead.
    - Invoke the `conn_final` callback with the connection, error code, and a peer indicator set to 1.
    - Return 1 to indicate successful processing of the GOAWAY frame.
- **Output**: Returns an integer, 1 if the GOAWAY frame was processed successfully, or 0 if there was a protocol or frame size error.
- **Functions called**:
    - [`fd_h2_conn_error`](fd_h2_conn.h.driver.md#fd_h2_conn_error)
    - [`fd_uint_bswap`](../../util/bits/fd_bits.h.driver.md#fd_uint_bswap)


---
### fd\_h2\_rx\_window\_update<!-- {{#callable:fd_h2_rx_window_update}} -->
The `fd_h2_rx_window_update` function processes a WINDOW_UPDATE frame in an HTTP/2 connection, updating the flow control window size for either the entire connection or a specific stream.
- **Inputs**:
    - `conn`: A pointer to the HTTP/2 connection structure (`fd_h2_conn_t`) that represents the current connection state.
    - `rbuf_tx`: A pointer to the transmit buffer (`fd_h2_rbuf_t`) used for sending data.
    - `cb`: A pointer to a structure containing callback functions (`fd_h2_callbacks_t`) for handling various HTTP/2 events.
    - `payload`: A pointer to the payload data of the WINDOW_UPDATE frame, expected to be 4 bytes in size.
    - `payload_sz`: The size of the payload, which should be exactly 4 bytes.
    - `stream_id`: The identifier of the stream for which the window update is intended; a value of 0 indicates a connection-level update.
- **Control Flow**:
    - Check if the payload size is exactly 4 bytes; if not, report a frame size error and return 0.
    - Extract the window size increment from the payload, ensuring it is a 31-bit positive integer.
    - If `stream_id` is 0, perform a connection-level window update:
    -   - Check if the increment is zero; if so, report a protocol error and return 0.
    -   - Attempt to add the increment to the connection's transmit window (`tx_wnd`); if overflow occurs, report a flow control error and return 0.
    -   - Update the connection's transmit window and invoke the `window_update` callback.
    - If `stream_id` is non-zero, perform a stream-level window update:
    -   - Validate the stream ID against the connection's stream limits; if invalid, report a protocol error and return 0.
    -   - Check if the increment is zero; if so, report a protocol error for the stream and return 1.
    -   - Query the stream using the `stream_query` callback; if the stream is not found, report a stream closed error and return 1.
    -   - Attempt to add the increment to the stream's transmit window (`tx_wnd`); if overflow occurs, report a flow control error, reset the stream, and return 1.
    -   - Update the stream's transmit window and invoke the `stream_window_update` callback.
    - Return 1 to indicate successful processing of the WINDOW_UPDATE frame.
- **Output**: Returns an integer: 1 on successful processing of the WINDOW_UPDATE frame, or 0/1 on error depending on the context (connection or stream-level error).
- **Functions called**:
    - [`fd_h2_conn_error`](fd_h2_conn.h.driver.md#fd_h2_conn_error)
    - [`fd_uint_bswap`](../../util/bits/fd_bits.h.driver.md#fd_uint_bswap)
    - [`fd_h2_stream_error1`](fd_h2_stream.h.driver.md#fd_h2_stream_error1)
    - [`fd_h2_stream_error`](fd_h2_stream.h.driver.md#fd_h2_stream_error)


---
### fd\_h2\_rx\_frame<!-- {{#callable:fd_h2_rx_frame}} -->
The `fd_h2_rx_frame` function processes a complete HTTP/2 frame based on its type and delegates handling to specific functions for each frame type.
- **Inputs**:
    - `conn`: A pointer to the HTTP/2 connection structure (`fd_h2_conn_t`) that maintains the state of the connection.
    - `rbuf_tx`: A pointer to the transmit buffer (`fd_h2_rbuf_t`) used for sending data back to the peer.
    - `payload`: A pointer to the payload data of the frame.
    - `payload_sz`: The size of the payload data in bytes.
    - `cb`: A pointer to a structure containing callback functions (`fd_h2_callbacks_t`) for handling various events.
    - `frame_type`: An unsigned integer representing the type of the HTTP/2 frame.
    - `frame_flags`: An unsigned integer representing the flags associated with the frame.
    - `stream_id`: An unsigned integer representing the stream identifier for the frame.
- **Control Flow**:
    - The function uses a switch statement to determine the type of the frame based on `frame_type`.
    - For each frame type, it calls a specific function to handle the frame, passing along the relevant parameters.
    - If the frame type is not recognized, the function returns 1, indicating an error or unhandled frame type.
- **Output**: The function returns an integer, where 1 indicates success or an unhandled frame type, and 0 indicates a connection error.
- **Functions called**:
    - [`fd_h2_rx_headers`](#fd_h2_rx_headers)
    - [`fd_h2_rx_priority`](#fd_h2_rx_priority)
    - [`fd_h2_rx_rst_stream`](#fd_h2_rx_rst_stream)
    - [`fd_h2_rx_settings`](#fd_h2_rx_settings)
    - [`fd_h2_rx_push_promise`](#fd_h2_rx_push_promise)
    - [`fd_h2_rx_continuation`](#fd_h2_rx_continuation)
    - [`fd_h2_rx_ping`](#fd_h2_rx_ping)
    - [`fd_h2_rx_goaway`](#fd_h2_rx_goaway)
    - [`fd_h2_rx_window_update`](#fd_h2_rx_window_update)


---
### fd\_h2\_rx1<!-- {{#callable:fd_h2_rx1}} -->
The `fd_h2_rx1` function processes a single HTTP/2 frame from a connection, handling different frame types and managing buffer states.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
    - `rbuf_rx`: A pointer to an `fd_h2_rbuf_t` structure representing the receive buffer.
    - `rbuf_tx`: A pointer to an `fd_h2_rbuf_t` structure representing the transmit buffer.
    - `scratch`: A pointer to a scratch buffer used for temporary storage during frame processing.
    - `scratch_sz`: The size of the scratch buffer.
    - `cb`: A pointer to an `fd_h2_callbacks_t` structure containing callback functions for handling various events.
- **Control Flow**:
    - Check if there is a remaining DATA frame to process (`conn->rx_frame_rem`), and if so, call [`fd_h2_rx_data`](#fd_h2_rx_data) to handle it.
    - If there is remaining padding (`conn->rx_pad_rem`), skip the padding bytes in the receive buffer and update the padding counter.
    - Peek the frame header from the receive buffer to determine the frame type and size.
    - If the frame size exceeds the maximum allowed by the connection settings, report a frame size error.
    - If a continuation frame is expected but the current frame is not a continuation, report a protocol error.
    - If the frame is padded, read the padding size and adjust the remaining size accordingly, reporting a protocol error if padding is invalid.
    - For DATA frames, set up the connection state to process the data incrementally and call [`fd_h2_rx_data`](#fd_h2_rx_data).
    - For other frame types, ensure the entire frame is available in the buffer, and if not, set suppression to wait for more data.
    - Check if the scratch buffer is large enough to hold the frame payload, and if not, report an internal error or frame size error.
    - Pop the frame payload into the scratch buffer and call [`fd_h2_rx_frame`](#fd_h2_rx_frame) to handle the complete frame.
    - Skip any padding bytes in the receive buffer after processing the frame.
- **Output**: The function does not return a value; it modifies the state of the connection and buffers, and may invoke callbacks or report errors.
- **Functions called**:
    - [`fd_h2_rx_data`](#fd_h2_rx_data)
    - [`fd_h2_rbuf_used_sz`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_used_sz)
    - [`fd_h2_rbuf_skip`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_skip)
    - [`fd_h2_rbuf_pop_copy`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_pop_copy)
    - [`fd_h2_frame_type`](fd_h2_proto.h.driver.md#fd_h2_frame_type)
    - [`fd_h2_frame_length`](fd_h2_proto.h.driver.md#fd_h2_frame_length)
    - [`fd_h2_conn_error`](fd_h2_conn.h.driver.md#fd_h2_conn_error)
    - [`fd_h2_frame_stream_id`](fd_h2_proto.h.driver.md#fd_h2_frame_stream_id)
    - [`fd_h2_rbuf_pop`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_pop)
    - [`fd_h2_rx_frame`](#fd_h2_rx_frame)


---
### fd\_h2\_rx<!-- {{#callable:fd_h2_rx}} -->
The `fd_h2_rx` function processes incoming HTTP/2 frames for a given connection, handling errors, and managing the receive buffer and connection state.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
    - `rbuf_rx`: A pointer to an `fd_h2_rbuf_t` structure representing the receive buffer for incoming data.
    - `rbuf_tx`: A pointer to an `fd_h2_rbuf_t` structure representing the transmit buffer for outgoing data.
    - `scratch`: A pointer to a scratch buffer used for temporary storage during frame processing.
    - `scratch_sz`: The size of the scratch buffer.
    - `cb`: A pointer to a constant `fd_h2_callbacks_t` structure containing callback functions for handling various HTTP/2 events.
- **Control Flow**:
    - Check if the connection is marked as dead and return immediately if so.
    - Check if there is any new data in the receive buffer; if not, return immediately.
    - Check if the receive buffer has enough data to proceed based on the connection's suppression threshold; if not, return immediately.
    - Enter a loop to process frames using [`fd_h2_rx1`](#fd_h2_rx1) until no more data is available, no progress is made, or the connection is marked as dead.
- **Output**: The function does not return a value; it operates by modifying the state of the connection and buffers, and potentially invoking callbacks.
- **Functions called**:
    - [`fd_h2_rbuf_used_sz`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_used_sz)
    - [`fd_h2_rx1`](#fd_h2_rx1)


---
### fd\_h2\_tx\_control<!-- {{#callable:fd_h2_tx_control}} -->
The `fd_h2_tx_control` function manages the transmission of control frames in an HTTP/2 connection based on the connection's current state and flags.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
    - `rbuf_tx`: A pointer to an `fd_h2_rbuf_t` structure representing the transmission buffer.
    - `cb`: A pointer to a constant `fd_h2_callbacks_t` structure containing callback functions for connection events.
- **Control Flow**:
    - Check if the free size of the transmission buffer `rbuf_tx` is less than 128 bytes; if so, return immediately.
    - Determine the least significant bit set in the `conn->flags` ORed with `0x10000u` to decide the next action.
    - If the flag indicates a client initial state, push the HTTP/2 client preface to the transmission buffer and fall through to the server initial case.
    - If the flag indicates a server initial state, generate and push the HTTP/2 settings frame to the transmission buffer, increment the settings transmission counter, and update the connection flags to wait for settings acknowledgment.
    - If the flag indicates a GOAWAY frame should be sent, construct a GOAWAY frame with the connection error code, mark the connection as dead, push the frame to the transmission buffer, and invoke the `conn_final` callback.
    - If the flag indicates a WINDOW_UPDATE frame should be sent, calculate the window increment, check for overflow, construct and push a WINDOW_UPDATE frame to the transmission buffer, reset the receive window, and clear the window update flag.
    - If none of the specific flags are set, do nothing and exit the function.
- **Output**: The function does not return a value; it modifies the state of the connection and the transmission buffer, and may invoke callbacks.
- **Functions called**:
    - [`fd_h2_rbuf_free_sz`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_free_sz)
    - [`fd_uint_find_lsb`](../../util/bits/fd_bits_find_lsb.h.driver.md#fd_uint_find_lsb)
    - [`fd_h2_rbuf_push`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_push)
    - [`fd_h2_gen_settings`](#fd_h2_gen_settings)
    - [`fd_h2_frame_typlen`](fd_h2_proto.h.driver.md#fd_h2_frame_typlen)
    - [`fd_uint_bswap`](../../util/bits/fd_bits.h.driver.md#fd_uint_bswap)
    - [`fd_h2_conn_error`](fd_h2_conn.h.driver.md#fd_h2_conn_error)



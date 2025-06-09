# Purpose
The provided C header file, `fd_h2_conn.h`, is part of a library that implements the HTTP/2 protocol's connection management and frame multiplexing functionalities. It defines the structures and functions necessary to handle HTTP/2 connections, including the state machine for managing connection settings, frame transmission, and reception. The file includes definitions for the `fd_h2_conn` structure, which encapsulates the state of an HTTP/2 connection, including settings for both the local and peer sides, frame handling, and connection lifecycle flags. It also defines the `fd_h2_settings` structure to manage HTTP/2 settings such as window size and frame size limits.

The header file provides a set of functions for initializing and finalizing HTTP/2 connections, handling incoming and outgoing frames, and managing connection errors. Functions like `fd_h2_conn_init_client` and [`fd_h2_conn_init_server`](#fd_h2_conn_init_server) are used to set up connections for client and server roles, respectively. The file also includes inline functions for preparing and committing frames for transmission, as well as checking buffer sizes to ensure frames can be sent. Additionally, it defines constants and macros for managing connection flags and error handling. This header file is intended to be included in other C source files that require HTTP/2 connection management capabilities, providing a comprehensive API for developers working with HTTP/2 in their applications.
# Imports and Dependencies

---
- `fd_h2_rbuf.h`
- `fd_h2_proto.h`


# Global Variables

---
### fd\_h2\_conn\_init\_server
- **Type**: `function pointer`
- **Description**: The `fd_h2_conn_init_server` is a function that initializes an HTTP/2 connection object for use as a server-side connection. It is designed to set up the connection state machine and prepare it for handling HTTP/2 frames, assuming that the client preface has already been received.
- **Use**: This function is used to bootstrap a connection object for server-side HTTP/2 communication, ensuring the connection is ready to process incoming frames.


---
### fd\_h2\_client\_preface
- **Type**: `char const[24]`
- **Description**: The `fd_h2_client_preface` is a constant character array of 24 bytes that represents the client connection preface in the HTTP/2 protocol. This preface is a specific sequence of bytes that a client sends to a server to initiate an HTTP/2 connection, as defined by the HTTP/2 specification.
- **Use**: It is used to verify the initial bytes received from a client to ensure they match the expected HTTP/2 client preface during connection setup.


---
### fd\_h2\_conn\_fini
- **Type**: `function pointer`
- **Description**: `fd_h2_conn_fini` is a function that finalizes or destroys an HTTP/2 connection object of type `fd_h2_conn_t`. It is designed to clean up resources associated with the connection, although in this implementation, it is a no-op since the connection object does not manage external resources.
- **Use**: This function is used to properly close and clean up an HTTP/2 connection object when it is no longer needed.


# Data Structures

---
### fd\_h2\_settings
- **Type**: `struct`
- **Members**:
    - `initial_window_size`: Specifies the initial size of the flow control window for streams.
    - `max_frame_size`: Defines the maximum size of a frame that can be sent or received.
    - `max_header_list_size`: Indicates the maximum size of the header list that the sender is prepared to accept.
    - `max_concurrent_streams`: Limits the maximum number of concurrent streams that can be open at one time.
- **Description**: The `fd_h2_settings` structure is used to store configuration settings for an HTTP/2 connection, as understood by the `fd_h2` implementation. It includes parameters that control the flow of data, such as the initial window size for flow control, the maximum frame size that can be handled, the maximum size of header lists, and the maximum number of concurrent streams allowed. These settings are crucial for managing the performance and resource allocation of HTTP/2 connections.


---
### fd\_h2\_settings\_t
- **Type**: `struct`
- **Members**:
    - `initial_window_size`: Specifies the initial size of the flow control window for streams.
    - `max_frame_size`: Defines the maximum size of a frame that can be sent or received.
    - `max_header_list_size`: Indicates the maximum size of the header list that the sender is prepared to accept.
    - `max_concurrent_streams`: Specifies the maximum number of concurrent streams that can be opened.
- **Description**: The `fd_h2_settings_t` structure is used to store configuration settings for an HTTP/2 connection, as understood by the `fd_h2` implementation. It includes parameters that control the flow of data, such as the initial window size for flow control, the maximum frame size that can be handled, the maximum size of header lists, and the maximum number of concurrent streams allowed. These settings are crucial for managing the performance and resource allocation of HTTP/2 connections.


---
### fd\_h2\_conn
- **Type**: `struct`
- **Members**:
    - `cb`: Pointer to a constant structure of callback functions for the connection.
    - `ctx`: Arbitrary context pointer for use by the caller.
    - `memo`: Arbitrary memory value for use by the caller.
    - `self_settings`: HTTP/2 settings for the local connection.
    - `peer_settings`: HTTP/2 settings for the peer connection.
    - `tx_frame_p`: Pointer to the start of the in-progress transmission frame in the buffer.
    - `tx_payload_off`: Cumulative byte count sent before the payload in the current transmission frame.
    - `rx_suppress`: Offset to skip frame handlers until this receive offset is reached.
    - `rx_frame_rem`: Remaining payload bytes in the current receive frame.
    - `rx_stream_id`: Stream ID of the current receive frame.
    - `rx_stream_next`: Next unused stream ID for receiving.
    - `rx_wnd_wmark`: Threshold for refilling the receive window.
    - `rx_wnd_max`: Maximum size of the receive window.
    - `rx_wnd`: Remaining bytes in the receive window.
    - `tx_stream_next`: Next unused stream ID for transmission.
    - `tx_wnd`: Available transmission quota.
    - `stream_active_cnt`: Array indicating the count of currently active receive and transmit streams.
    - `flags`: Bit set of connection lifecycle flags.
    - `conn_error`: Error code for the connection.
    - `setting_tx`: Number of sent SETTINGS frames pending acknowledgment.
    - `rx_frame_flags`: Flags for the current receive frame.
    - `rx_pad_rem`: Remaining padding bytes in the current receive frame.
    - `ping_tx`: Number of sent PING frames pending acknowledgment.
- **Description**: The `fd_h2_conn` structure represents a framing-layer HTTP/2 connection handle, implementing mandatory behaviors as per RFC 9113, such as negotiating connection settings with a peer. It maintains state information for both transmission and reception of HTTP/2 frames, including settings for the local and peer connections, stream management, window sizes, and error handling. The structure is designed to facilitate the multiplexing of frames over a single connection, handling both control and data frames, and managing the lifecycle of the connection through various flags and counters.


# Functions

---
### fd\_h2\_tx\_check\_sz<!-- {{#callable:fd_h2_tx_check_sz}} -->
The `fd_h2_tx_check_sz` function checks if there is enough space in the transmission buffer to accommodate a frame of a specified maximum size, including additional space for control frames.
- **Inputs**:
    - `rbuf_tx`: A constant pointer to an `fd_h2_rbuf_t` structure representing the transmission buffer.
    - `frame_max`: An unsigned long integer representing the maximum size of the frame to be checked for space in the buffer.
- **Control Flow**:
    - Calculate the total size of the frame by adding 9 bytes to `frame_max` to account for the frame header.
    - Add an additional 64 bytes to the total size to reserve space for control frames, resulting in the required size (`req_sz`).
    - Check if the free space in `rbuf_tx` is greater than or equal to `req_sz` by calling `fd_h2_rbuf_free_sz(rbuf_tx)` and return the result of this comparison.
- **Output**: The function returns an integer value: 1 if there is enough space in the buffer to accommodate the frame, or 0 if there is not.
- **Functions called**:
    - [`fd_h2_rbuf_free_sz`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_free_sz)


---
### fd\_h2\_tx\_prepare<!-- {{#callable:fd_h2_tx_prepare}} -->
The `fd_h2_tx_prepare` function initializes the transmission of an HTTP/2 frame by setting up the frame header in the transmission buffer.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
    - `rbuf_tx`: A pointer to an `fd_h2_rbuf_t` structure representing the transmission buffer where the frame header will be written.
    - `frame_type`: An unsigned integer representing the type of the HTTP/2 frame to be transmitted.
    - `flags`: An unsigned integer representing the flags associated with the HTTP/2 frame.
    - `stream_id`: An unsigned integer representing the stream identifier for the HTTP/2 frame, which is byte-swapped before being used.
- **Control Flow**:
    - Check if `conn->tx_frame_p` is already set, indicating a mismatched call, and log a critical error if so.
    - Set `conn->tx_frame_p` to the current high watermark of `rbuf_tx`.
    - Set `conn->tx_payload_off` to the offset in `rbuf_tx` where the payload will start, which is 9 bytes after the current high watermark.
    - Create a frame header `hdr` with the type-length, flags, and byte-swapped stream ID.
    - Push the frame header `hdr` into the transmission buffer `rbuf_tx`.
- **Output**: The function does not return a value; it modifies the `conn` and `rbuf_tx` structures to prepare for frame transmission.
- **Functions called**:
    - [`fd_h2_frame_typlen`](fd_h2_proto.h.driver.md#fd_h2_frame_typlen)
    - [`fd_h2_rbuf_push`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_push)


---
### fd\_h2\_tx\_commit<!-- {{#callable:fd_h2_tx_commit}} -->
The `fd_h2_tx_commit` function finalizes an HTTP/2 frame by calculating and setting the frame's payload size in the buffer and resetting the connection's frame tracking variables.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection, which contains state information about the current frame being transmitted.
    - `rbuf_tx`: A constant pointer to an `fd_h2_rbuf_t` structure representing the transmission buffer, which holds the data being sent over the connection.
- **Control Flow**:
    - Retrieve the current payload offset (`off0`) from the connection and the high offset (`off1`) from the transmission buffer.
    - Calculate the buffer pointers (`buf0`, `buf1`) and buffer size (`bufsz`) from the transmission buffer.
    - Determine the frame pointer (`frame`) from the connection and calculate the size pointers (`sz0`, `sz1`, `sz2`) for the frame header.
    - Adjust `sz1` and `sz2` if they exceed the buffer's end by wrapping them around using the buffer size.
    - Check if the frame pointer is within the valid range of the buffer; if not, log a critical error and exit.
    - Calculate the write size (`write_sz`) as the difference between `off1` and `off0`.
    - Set the first three bytes of the frame to represent the calculated write size in a big-endian format.
    - Reset the connection's frame pointer and payload offset to indicate the frame is complete.
- **Output**: The function does not return a value; it modifies the state of the `conn` structure to finalize the frame transmission.


---
### fd\_h2\_tx<!-- {{#callable:fd_h2_tx}} -->
The `fd_h2_tx` function constructs and sends an HTTP/2 frame by writing a frame header and payload to a transmission buffer.
- **Inputs**:
    - `rbuf_tx`: A pointer to the transmission buffer (`fd_h2_rbuf_t`) where the frame will be written.
    - `payload`: A pointer to the payload data (`uchar const *`) to be included in the frame.
    - `payload_sz`: The size of the payload data (`ulong`).
    - `frame_type`: The type of the HTTP/2 frame (`uint`).
    - `flags`: Flags associated with the frame (`uint`).
    - `stream_id`: The stream identifier (`uint`) for the frame, which is byte-swapped before being used.
- **Control Flow**:
    - Create a frame header (`fd_h2_frame_hdr_t`) with the type and length calculated using [`fd_h2_frame_typlen`](fd_h2_proto.h.driver.md#fd_h2_frame_typlen), the provided flags, and the byte-swapped stream ID.
    - Push the frame header into the transmission buffer `rbuf_tx` using [`fd_h2_rbuf_push`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_push).
    - Push the payload data into the transmission buffer `rbuf_tx` using [`fd_h2_rbuf_push`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_push).
- **Output**: The function does not return a value; it modifies the transmission buffer `rbuf_tx` by appending the frame header and payload.
- **Functions called**:
    - [`fd_h2_frame_typlen`](fd_h2_proto.h.driver.md#fd_h2_frame_typlen)
    - [`fd_h2_rbuf_push`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_push)


---
### fd\_h2\_conn\_error<!-- {{#callable:fd_h2_conn_error}} -->
The `fd_h2_conn_error` function sets an HTTP/2 connection to a 'GOAWAY' state and records an error code.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
    - `err_code`: An unsigned integer representing the error code to be set for the connection.
- **Control Flow**:
    - The function sets the `flags` field of the `conn` structure to `FD_H2_CONN_FLAGS_SEND_GOAWAY`, indicating that the connection should send a GOAWAY frame.
    - The function sets the `conn_error` field of the `conn` structure to the provided `err_code`, casting it to an unsigned character.
- **Output**: The function does not return any value; it modifies the state of the `conn` structure in place.


# Function Declarations (Public API)

---
### fd\_h2\_conn\_init\_server<!-- {{#callable_declaration:fd_h2_conn_init_server}} -->
Initializes an HTTP/2 connection for server-side use.
- **Description**: This function prepares an `fd_h2_conn_t` object for use as a server-side HTTP/2 connection. It should be called after the client preface has been received from the incoming stream, which is a 24-byte constant string. The function sets up initial connection settings and stream identifiers, and initializes the connection's flow control window. It returns the initialized connection object, which can then be used for further HTTP/2 operations. This function is currently infallible, but callers should still check for a NULL return value to ensure future compatibility.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure that will be initialized. Must not be null. The caller retains ownership of the memory.
- **Output**: Returns the initialized `fd_h2_conn_t` pointer on success, or NULL on failure (though currently infallible).
- **See also**: [`fd_h2_conn_init_server`](fd_h2_conn.c.driver.md#fd_h2_conn_init_server)  (Implementation)


---
### fd\_h2\_rx<!-- {{#callable_declaration:fd_h2_rx}} -->
Consumes incoming bytes from the receive buffer for an HTTP/2 connection.
- **Description**: This function processes as much incoming data from the receive buffer as possible for an HTTP/2 connection, potentially writing control messages to the transmit buffer. It should be called when new data is available in the receive buffer. The function will stop processing if the connection is marked as dead, if no new data is available, or if the receive buffer does not have enough data to progress. It requires a scratch buffer for reassembly, and the size of this buffer must be at least as large as the maximum frame size specified in the connection's settings. This function is essential for handling incoming HTTP/2 frames and managing connection state.
- **Inputs**:
    - `conn`: A pointer to an fd_h2_conn_t structure representing the HTTP/2 connection. Must not be null. The connection should be properly initialized before calling this function.
    - `rbuf_rx`: A pointer to an fd_h2_rbuf_t structure representing the receive buffer. Must not be null. The buffer should contain data to be processed.
    - `rbuf_tx`: A pointer to an fd_h2_rbuf_t structure representing the transmit buffer. Must not be null. This buffer may be written to with control messages.
    - `scratch`: A pointer to a scratch buffer used for reassembly. Must not be null. The buffer is used internally and should be at least scratch_sz in size.
    - `scratch_sz`: The size of the scratch buffer. Must be at least as large as conn->self_settings.max_frame_size.
    - `cb`: A pointer to an fd_h2_callbacks_t structure containing callback functions. Must not be null. These callbacks are used during the processing of frames.
- **Output**: None
- **See also**: [`fd_h2_rx`](fd_h2_conn.c.driver.md#fd_h2_rx)  (Implementation)


---
### fd\_h2\_tx\_control<!-- {{#callable_declaration:fd_h2_tx_control}} -->
Writes control messages to the transmission buffer for an HTTP/2 connection.
- **Description**: This function is used to manage and send control frames for an HTTP/2 connection, such as SETTINGS, GOAWAY, and WINDOW_UPDATE frames. It should be called when initializing a connection or when a timer expires to ensure that the connection state is properly maintained and control messages are sent as needed. The function requires a minimum of 128 bytes of free space in the transmission buffer to operate. If this condition is not met, the function will return immediately without performing any actions. The function also utilizes callbacks to handle final connection states.
- **Inputs**:
    - `conn`: A pointer to an fd_h2_conn_t structure representing the HTTP/2 connection. This must be a valid, initialized connection object.
    - `rbuf_tx`: A pointer to an fd_h2_rbuf_t structure representing the transmission buffer. This buffer must have at least 128 bytes of free space for the function to execute.
    - `cb`: A pointer to a constant fd_h2_callbacks_t structure containing callback functions. These callbacks are used to handle specific connection events, such as finalizing the connection.
- **Output**: None
- **See also**: [`fd_h2_tx_control`](fd_h2_conn.c.driver.md#fd_h2_tx_control)  (Implementation)


---
### fd\_h2\_tx\_ping<!-- {{#callable_declaration:fd_h2_tx_ping}} -->
Attempts to enqueue a PING frame for sending.
- **Description**: This function is used to enqueue a PING frame into the transmission buffer of an HTTP/2 connection. It should be called when a PING frame needs to be sent to maintain the connection or check its status. The function requires that there is enough space in the transmission buffer to accommodate the PING frame and that the number of unacknowledged PING frames is below a certain threshold. If these conditions are not met, the function will not enqueue the PING frame and will return a failure indication.
- **Inputs**:
    - `conn`: A pointer to an fd_h2_conn_t structure representing the HTTP/2 connection. This parameter must not be null, and the connection should be properly initialized before calling this function.
    - `rbuf_tx`: A pointer to an fd_h2_rbuf_t structure representing the transmission buffer. This buffer must have enough space to accommodate a PING frame, and the pointer must not be null.
- **Output**: Returns 1 if the PING frame was successfully enqueued, or 0 if the operation was blocked due to insufficient buffer space or too many unacknowledged PING frames.
- **See also**: [`fd_h2_tx_ping`](fd_h2_conn.c.driver.md#fd_h2_tx_ping)  (Implementation)



# Purpose
The provided C header file, `fd_h2_stream.h`, defines the structure and functions necessary to manage HTTP/2 stream state machines. It is part of a broader HTTP/2 implementation, as indicated by its inclusion of other related headers such as `fd_h2_base.h`, `fd_h2_proto.h`, and `fd_h2_conn.h`. The file primarily focuses on the lifecycle management of HTTP/2 streams, encapsulated within the `fd_h2_stream_t` structure, which tracks the stream's state, transmission and reception windows, and header sequence.

The file defines several states for a stream, such as `IDLE`, `OPEN`, `CLOSING_TX`, `CLOSING_RX`, `CLOSED`, and `ILLEGAL`, and provides inline functions to transition between these states. Functions like `fd_h2_stream_init`, [`fd_h2_stream_open`](#fd_h2_stream_open), [`fd_h2_stream_close_rx`](#fd_h2_stream_close_rx), and [`fd_h2_stream_close_tx`](#fd_h2_stream_close_tx) manage the stream's state transitions based on HTTP/2 protocol events. Additionally, error handling is facilitated through functions like [`fd_h2_stream_error`](#fd_h2_stream_error), which sends a reset stream frame in case of errors. This header file is intended to be included in other C source files that require HTTP/2 stream management functionality, providing a clear API for stream state manipulation within an HTTP/2 connection context.
# Imports and Dependencies

---
- `fd_h2_base.h`
- `fd_h2_proto.h`
- `fd_h2_conn.h`


# Data Structures

---
### fd\_h2\_stream
- **Type**: `struct`
- **Members**:
    - `stream_id`: A unique identifier for the HTTP/2 stream.
    - `tx_wnd`: Represents the transmit quota available for the stream.
    - `rx_wnd`: Indicates the remaining bytes in the receive window for the stream.
    - `state`: Holds the current state of the stream, such as IDLE, OPEN, or CLOSED.
    - `hdrs_seq`: Tracks the sequence of headers received for the stream.
- **Description**: The `fd_h2_stream` structure is designed to manage the state of an HTTP/2 stream within a connection. It includes fields for identifying the stream (`stream_id`), managing flow control through transmit (`tx_wnd`) and receive (`rx_wnd`) windows, and tracking the stream's state (`state`) and header sequence (`hdrs_seq`). This structure is integral to the HTTP/2 protocol's stream management, allowing for the control and monitoring of data flow and state transitions in a network communication context.


# Functions

---
### fd\_h2\_stream\_open<!-- {{#callable:fd_h2_stream_open}} -->
The `fd_h2_stream_open` function initializes an HTTP/2 stream object to the 'OPEN' state with specified stream ID and window sizes from the connection settings.
- **Inputs**:
    - `stream`: A pointer to an `fd_h2_stream_t` object that will be initialized and transitioned to the 'OPEN' state.
    - `conn`: A constant pointer to an `fd_h2_conn_t` object containing connection settings used to initialize the stream's window sizes.
    - `stream_id`: An unsigned integer representing the unique identifier for the stream being opened.
- **Control Flow**:
    - The function assigns the provided `stream_id` to the `stream_id` field of the `stream` object.
    - The `state` field of the `stream` object is set to `FD_H2_STREAM_STATE_OPEN`, indicating the stream is now open.
    - The `tx_wnd` field is initialized with the `initial_window_size` from the peer's settings in the `conn` object.
    - The `rx_wnd` field is initialized with the `initial_window_size` from the self settings in the `conn` object.
    - The `hdrs_seq` field is set to 0, indicating no headers have been processed yet.
    - The function returns the pointer to the initialized `stream` object.
- **Output**: A pointer to the initialized `fd_h2_stream_t` object, now in the 'OPEN' state.


---
### fd\_h2\_stream\_error1<!-- {{#callable:fd_h2_stream_error1}} -->
The `fd_h2_stream_error1` function constructs and sends an HTTP/2 RST_STREAM frame to indicate a stream error.
- **Inputs**:
    - `rbuf_tx`: A pointer to an `fd_h2_rbuf_t` structure where the RST_STREAM frame will be pushed.
    - `stream_id`: An unsigned integer representing the ID of the stream that encountered an error.
    - `h2_err`: An unsigned integer representing the HTTP/2 error code to be sent in the RST_STREAM frame.
- **Control Flow**:
    - Initialize an `fd_h2_rst_stream_t` structure named `rst_stream` with a header and error code.
    - Set the header's `typlen` using [`fd_h2_frame_typlen`](fd_h2_proto.h.driver.md#fd_h2_frame_typlen) with the frame type `FD_H2_FRAME_TYPE_RST_STREAM` and a length of 4 bytes.
    - Set the header's `flags` to 0.
    - Set the header's `r_stream_id` to the byte-swapped value of `stream_id` using `fd_uint_bswap`.
    - Set the `error_code` of `rst_stream` to the byte-swapped value of `h2_err` using `fd_uint_bswap`.
    - Push the `rst_stream` structure into the `rbuf_tx` buffer using [`fd_h2_rbuf_push`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_push).
- **Output**: The function does not return a value; it modifies the `rbuf_tx` buffer by adding an RST_STREAM frame.
- **Functions called**:
    - [`fd_h2_frame_typlen`](fd_h2_proto.h.driver.md#fd_h2_frame_typlen)
    - [`fd_h2_rbuf_push`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_push)


---
### fd\_h2\_stream\_error<!-- {{#callable:fd_h2_stream_error}} -->
The `fd_h2_stream_error` function handles an HTTP/2 stream error by sending a reset stream frame and transitioning the stream state to closed.
- **Inputs**:
    - `stream`: A pointer to an `fd_h2_stream_t` structure representing the HTTP/2 stream that encountered an error.
    - `rbuf_tx`: A pointer to an `fd_h2_rbuf_t` structure used for transmitting the reset stream frame.
    - `h2_err`: An unsigned integer representing the HTTP/2 error code to be sent in the reset stream frame.
- **Control Flow**:
    - Call the [`fd_h2_stream_error1`](#fd_h2_stream_error1) function with `rbuf_tx`, `stream->stream_id`, and `h2_err` to send a reset stream frame with the specified error code.
    - Set the `state` of the `stream` to `FD_H2_STREAM_STATE_CLOSED` to indicate that the stream is now closed.
- **Output**: This function does not return a value; it modifies the state of the `stream` and sends a reset stream frame.
- **Functions called**:
    - [`fd_h2_stream_error1`](#fd_h2_stream_error1)


---
### fd\_h2\_stream\_private\_deactivate<!-- {{#callable:fd_h2_stream_private_deactivate}} -->
The `fd_h2_stream_private_deactivate` function decrements the active stream count for a specific stream type in an HTTP/2 connection.
- **Inputs**:
    - `stream`: A pointer to an `fd_h2_stream_t` structure representing the HTTP/2 stream to be deactivated.
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection associated with the stream.
- **Control Flow**:
    - Calculate the index for the `stream_active_cnt` array by XORing the least significant bit of the stream's ID with the least significant bit of the connection's received stream ID.
    - Decrement the value at the calculated index in the `stream_active_cnt` array of the connection.
- **Output**: This function does not return any value; it modifies the `stream_active_cnt` array within the `conn` structure.


---
### fd\_h2\_stream\_close\_rx<!-- {{#callable:fd_h2_stream_close_rx}} -->
The `fd_h2_stream_close_rx` function transitions the state of an HTTP/2 stream to handle the closure of the receive side, potentially deactivating the stream if both sides are closed.
- **Inputs**:
    - `stream`: A pointer to an `fd_h2_stream_t` structure representing the HTTP/2 stream whose receive side is being closed.
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the connection associated with the stream.
- **Control Flow**:
    - The function checks the current state of the stream using a switch statement.
    - If the stream is in the `FD_H2_STREAM_STATE_OPEN` state, it transitions to `FD_H2_STREAM_STATE_CLOSING_RX`.
    - If the stream is in the `FD_H2_STREAM_STATE_CLOSING_TX` state, it transitions to `FD_H2_STREAM_STATE_CLOSED` and calls [`fd_h2_stream_private_deactivate`](#fd_h2_stream_private_deactivate) to deactivate the stream.
    - For any other state, the stream transitions to `FD_H2_STREAM_STATE_ILLEGAL`.
- **Output**: The function does not return a value; it modifies the state of the stream in place.
- **Functions called**:
    - [`fd_h2_stream_private_deactivate`](#fd_h2_stream_private_deactivate)


---
### fd\_h2\_stream\_close\_tx<!-- {{#callable:fd_h2_stream_close_tx}} -->
The `fd_h2_stream_close_tx` function transitions an HTTP/2 stream's state to handle the closing of the transmission side of the stream.
- **Inputs**:
    - `stream`: A pointer to an `fd_h2_stream_t` structure representing the HTTP/2 stream whose transmission side is being closed.
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the connection associated with the stream.
- **Control Flow**:
    - The function checks the current state of the stream using a switch statement.
    - If the stream is in the `FD_H2_STREAM_STATE_OPEN` state, it transitions to the `FD_H2_STREAM_STATE_CLOSING_TX` state.
    - If the stream is in the `FD_H2_STREAM_STATE_CLOSING_RX` state, it transitions to the `FD_H2_STREAM_STATE_CLOSED` state and calls [`fd_h2_stream_private_deactivate`](#fd_h2_stream_private_deactivate) to update the connection's active stream count.
    - For any other state, the stream's state is set to `FD_H2_STREAM_STATE_ILLEGAL`.
- **Output**: The function does not return a value; it modifies the state of the stream in place.
- **Functions called**:
    - [`fd_h2_stream_private_deactivate`](#fd_h2_stream_private_deactivate)


---
### fd\_h2\_stream\_reset<!-- {{#callable:fd_h2_stream_reset}} -->
The `fd_h2_stream_reset` function transitions an HTTP/2 stream to a closed or illegal state based on its current state and deactivates it if necessary.
- **Inputs**:
    - `stream`: A pointer to an `fd_h2_stream_t` structure representing the HTTP/2 stream to be reset.
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the connection associated with the stream.
- **Control Flow**:
    - The function checks the current state of the stream using a switch statement.
    - If the stream is in the OPEN, CLOSING_TX, or CLOSING_RX state, it sets the stream's state to CLOSED and calls [`fd_h2_stream_private_deactivate`](#fd_h2_stream_private_deactivate) to deactivate the stream.
    - If the stream is in any other state, it sets the stream's state to ILLEGAL.
- **Output**: The function does not return a value; it modifies the state of the stream in place.
- **Functions called**:
    - [`fd_h2_stream_private_deactivate`](#fd_h2_stream_private_deactivate)


---
### fd\_h2\_stream\_rx\_headers<!-- {{#callable:fd_h2_stream_rx_headers}} -->
The `fd_h2_stream_rx_headers` function processes received HTTP/2 headers for a stream, updating the stream state and sequence as necessary based on provided flags.
- **Inputs**:
    - `stream`: A pointer to an `fd_h2_stream_t` structure representing the HTTP/2 stream whose headers are being processed.
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the connection associated with the stream.
    - `flags`: An unsigned long integer representing flags that indicate specific conditions or actions, such as `FD_H2_FLAG_END_STREAM` and `FD_H2_FLAG_END_HEADERS`.
- **Control Flow**:
    - Check if the stream's state is `FD_H2_STREAM_STATE_IDLE`; if so, transition it to `FD_H2_STREAM_STATE_OPEN`.
    - Check if the `FD_H2_FLAG_END_STREAM` flag is set; if true, call [`fd_h2_stream_close_rx`](#fd_h2_stream_close_rx) to handle the stream closure on the receive side.
    - Check if the `FD_H2_FLAG_END_HEADERS` flag is set; if true, increment the `hdrs_seq` field of the stream to indicate the completion of a headers sequence.
- **Output**: The function does not return a value; it modifies the state and header sequence of the provided `fd_h2_stream_t` structure based on the flags.
- **Functions called**:
    - [`fd_h2_stream_close_rx`](#fd_h2_stream_close_rx)


---
### fd\_h2\_stream\_rx\_data<!-- {{#callable:fd_h2_stream_rx_data}} -->
The `fd_h2_stream_rx_data` function processes incoming data frames for an HTTP/2 stream and closes the receive side of the stream if the END_STREAM flag is set.
- **Inputs**:
    - `stream`: A pointer to an `fd_h2_stream_t` structure representing the HTTP/2 stream whose data is being processed.
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the connection associated with the stream.
    - `flags`: An unsigned long integer representing flags associated with the data frame, such as FD_H2_FLAG_END_STREAM.
- **Control Flow**:
    - Check if the `flags` parameter has the `FD_H2_FLAG_END_STREAM` bit set.
    - If the `FD_H2_FLAG_END_STREAM` flag is set, call [`fd_h2_stream_close_rx`](#fd_h2_stream_close_rx) to close the receive side of the stream.
- **Output**: The function does not return a value; it performs operations on the stream and connection objects based on the flags.
- **Functions called**:
    - [`fd_h2_stream_close_rx`](#fd_h2_stream_close_rx)



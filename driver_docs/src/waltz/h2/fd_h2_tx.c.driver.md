# Purpose
The provided C code is part of a library or module that facilitates data transmission over HTTP/2 connections. It specifically implements a function, [`fd_h2_tx_op_copy`](#fd_h2_tx_op_copy), which is responsible for managing the transmission of data from a stream buffer to a connection buffer, adhering to the constraints and state of the HTTP/2 protocol. The function ensures that data is sent in frames that respect the connection's and stream's window sizes, as well as the maximum frame size allowed by the peer's settings. It also handles the state of the stream, ensuring that data is only sent if the stream is in an appropriate state (open or closing for receiving) and manages the end-of-stream condition by setting the `END_STREAM` flag when necessary.

The code is structured to be part of a larger system, as indicated by the inclusion of headers like "fd_h2_tx.h", "fd_h2_conn.h", and "fd_h2_stream.h", which likely define the data structures and constants used in the function. The function does not define a public API or external interface directly but is likely a utility function used internally within the library to handle the low-level details of data transmission in an HTTP/2 context. The use of macros like `FD_UNLIKELY` suggests performance optimizations, hinting that this code is designed for high-performance environments where efficient data handling is critical.
# Imports and Dependencies

---
- `fd_h2_tx.h`
- `fd_h2_conn.h`
- `fd_h2_stream.h`


# Functions

---
### fd\_h2\_tx\_op\_copy<!-- {{#callable:fd_h2_tx_op_copy}} -->
The `fd_h2_tx_op_copy` function manages the transmission of data frames over an HTTP/2 connection, ensuring that data is sent according to the available window sizes and stream states.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
    - `stream`: A pointer to an `fd_h2_stream_t` structure representing the HTTP/2 stream.
    - `rbuf_tx`: A pointer to an `fd_h2_rbuf_t` structure used as the transmission buffer.
    - `tx_op`: A pointer to an `fd_h2_tx_op_t` structure containing the data chunk and its size to be transmitted.
- **Control Flow**:
    - Calculate the minimum transmission quota based on the connection and stream window sizes.
    - Return immediately if the quota is negative or if the stream is closed or in an invalid state for transmission.
    - Enter a loop to send data frames while there is quota available.
    - Calculate the maximum payload size for the current frame based on the remaining chunk size, buffer space, and maximum frame size.
    - Break the loop if the payload size is zero or negative.
    - Determine if the END_STREAM flag should be set and close the stream's transmission if necessary.
    - Prepare the transmission buffer with the frame header and push the data chunk into the buffer.
    - Commit the transmission, updating the chunk pointer, chunk size, and reducing the connection and stream window sizes by the payload size.
    - Repeat the loop until the quota is exhausted.
- **Output**: The function does not return a value; it modifies the state of the connection, stream, and transmission operation structures to reflect the data transmission.
- **Functions called**:
    - [`fd_h2_rbuf_free_sz`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_free_sz)
    - [`fd_h2_stream_close_tx`](fd_h2_stream.h.driver.md#fd_h2_stream_close_tx)
    - [`fd_h2_tx_prepare`](fd_h2_conn.h.driver.md#fd_h2_tx_prepare)
    - [`fd_h2_rbuf_push`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_push)
    - [`fd_h2_tx_commit`](fd_h2_conn.h.driver.md#fd_h2_tx_commit)



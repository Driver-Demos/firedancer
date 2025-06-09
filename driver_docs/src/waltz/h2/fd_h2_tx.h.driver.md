# Purpose
This C header file, `fd_h2_tx.h`, is part of a library designed to facilitate flow-controlled transmission (TX) operations, likely within an HTTP/2 context, as suggested by the naming conventions. It defines a structure, `fd_h2_tx_op_t`, which represents a transmission operation, including a data chunk, its size, and a flag indicating if the stream should be closed after transmission. The file provides a static inline function, `fd_h2_tx_op_init`, to initialize a transmission operation, setting up the data chunk and handling a flag to close the stream if necessary. Additionally, it declares a function, [`fd_h2_tx_op_copy`](#fd_h2_tx_op_copy), which manages the copying of data from the transmission operation to a buffer, respecting various constraints such as buffer capacity and transmission quotas. The file hints at potential future enhancements with a comment about adding a sendmsg-gather API for more efficient transmission of multiple frames.
# Imports and Dependencies

---
- `fd_h2_proto.h`


# Data Structures

---
### fd\_h2\_tx\_op
- **Type**: `struct`
- **Members**:
    - `chunk`: A pointer to the buffer containing the data to be sent.
    - `chunk_sz`: The size of the data chunk to be sent, in bytes.
    - `fin`: A flag indicating whether the stream should be closed after sending the data.
- **Description**: The `fd_h2_tx_op` structure is used to manage a transmission operation in a flow-controlled HTTP/2 environment. It holds a pointer to the data buffer (`chunk`), the size of the data to be transmitted (`chunk_sz`), and a flag (`fin`) to indicate if the stream should be closed after the data is sent. This structure is integral to handling data transmission operations, ensuring that data is sent correctly and efficiently while respecting stream closure requirements.


---
### fd\_h2\_tx\_op\_t
- **Type**: `struct`
- **Members**:
    - `chunk`: A pointer to the buffer containing the data to be sent.
    - `chunk_sz`: The size of the data chunk to be sent, in bytes.
    - `fin`: A flag indicating whether the stream should be closed after sending the data.
- **Description**: The `fd_h2_tx_op_t` structure is used to manage a flow-controlled transmission operation in an HTTP/2 context. It contains a pointer to the data chunk to be sent, the size of this chunk, and a flag to indicate if the stream should be closed after the data is sent. This structure is integral to handling the transmission of data frames in a controlled manner, ensuring that the data is sent according to the constraints of the HTTP/2 protocol.


# Function Declarations (Public API)

---
### fd\_h2\_tx\_op\_copy<!-- {{#callable_declaration:fd_h2_tx_op_copy}} -->
Copies enqueued transmission data to the transmission buffer.
- **Description**: This function is used to transfer as much data as possible from a transmission operation to a transmission buffer, considering various constraints such as buffer space, connection and stream transmission quotas, and the remaining data to be sent. It should be called when there is data ready to be sent and the user wants to move it to the transmission buffer for eventual sending. The function will adjust the transmission operation's state by advancing the data pointer and reducing the size of the remaining data to be sent. It will stop copying data when the buffer is full, the connection or stream transmission quota is exhausted, or there is no more data to send. The function should not be called if the stream is closed.
- **Inputs**:
    - `conn`: A pointer to an fd_h2_conn_t structure representing the connection. It must be valid and properly initialized before calling this function.
    - `stream`: A pointer to an fd_h2_stream_t structure representing the stream. It must be valid, and the stream must not be in the CLOSED state.
    - `rbuf_tx`: A pointer to an fd_h2_rbuf_t structure representing the transmission buffer. It must be valid and have enough space to accommodate the data being copied.
    - `tx_op`: A pointer to an fd_h2_tx_op_t structure representing the transmission operation. It must be valid and initialized with data to be sent.
- **Output**: None
- **See also**: [`fd_h2_tx_op_copy`](fd_h2_tx.c.driver.md#fd_h2_tx_op_copy)  (Implementation)



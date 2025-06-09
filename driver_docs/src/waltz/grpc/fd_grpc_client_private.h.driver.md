# Purpose
This C header file, `fd_grpc_client_private.h`, is part of a gRPC client implementation that operates over HTTP/2 and utilizes TLS for secure communication. The file defines the internal structures and mechanisms necessary for managing gRPC streams and connections. It includes the definition of `fd_grpc_h2_stream_t`, a structure that encapsulates the state of a gRPC request, including buffers for response headers and incoming messages, as well as state flags for tracking the progress of message handling. The file also declares a pool of stream objects, which allows the client to manage multiple concurrent gRPC requests and responses efficiently, even though only one stream can be actively sending requests at any given time.

Additionally, the file outlines the internal state of the gRPC client through the `fd_grpc_client_private` structure. This structure maintains the connection details, including the TCP socket, SSL handle, and HTTP/2 connection buffers. It also manages the lifecycle of gRPC streams, detailing the state transitions between IDLE, OPEN, and CLOSE_TX states, which represent the different phases of a gRPC request's lifecycle. The file is intended for internal use within the gRPC client implementation, providing the necessary infrastructure to handle gRPC communication over HTTP/2 with TLS, but it does not define public APIs or external interfaces directly.
# Imports and Dependencies

---
- `fd_grpc_client.h`
- `../grpc/fd_grpc_codec.h`
- `../h2/fd_h2.h`
- `../../util/tmpl/fd_pool.c`
- `../../waltz/h2/fd_h2_rbuf_ossl.h`


# Data Structures

---
### fd\_grpc\_h2\_stream
- **Type**: `struct`
- **Members**:
    - `s`: An instance of fd_h2_stream_t representing the HTTP/2 stream state.
    - `request_ctx`: A context identifier for the request, stored as an unsigned long.
    - `next`: An unsigned integer used for tracking the next state or operation.
    - `hdrs`: A buffer for storing response headers, represented by fd_grpc_resp_hdrs_t.
    - `msg_buf`: A pointer to a buffer for storing an incoming gRPC message.
    - `msg_buf_max`: The maximum size of the message buffer, stored as an unsigned long.
    - `hdrs_received`: A flag indicating whether headers have been received, stored as a single bit.
    - `msg_buf_used`: The amount of the message buffer currently used, including the header, stored as an unsigned long.
    - `msg_sz`: The size of the next message to be processed, stored as an unsigned long.
- **Description**: The `fd_grpc_h2_stream` structure is designed to manage the state of a gRPC request over an HTTP/2 connection. It encapsulates the HTTP/2 stream state, request context, and manages buffers for response headers and incoming gRPC messages. The structure includes fields for tracking the size and usage of the message buffer, as well as a flag to indicate if headers have been received. This data structure is integral to handling the lifecycle of a gRPC request, from initiation to completion, within a client that supports multiple concurrent streams.


---
### fd\_grpc\_h2\_stream\_t
- **Type**: `struct`
- **Members**:
    - `s`: An instance of fd_h2_stream_t representing the underlying HTTP/2 stream.
    - `request_ctx`: A unique identifier for the request context.
    - `next`: An index or identifier for the next stream or operation.
    - `hdrs`: A buffer for storing response headers of type fd_grpc_resp_hdrs_t.
    - `msg_buf`: A pointer to a buffer for storing an incoming gRPC message.
    - `msg_buf_max`: The maximum size of the message buffer.
    - `hdrs_received`: A flag indicating whether headers have been received (1 if true, 0 if false).
    - `msg_buf_used`: The amount of the message buffer currently used, including the header.
    - `msg_sz`: The size of the next message to be processed.
- **Description**: The fd_grpc_h2_stream_t structure is designed to manage the state of a gRPC request over an HTTP/2 connection. It encapsulates the underlying HTTP/2 stream, tracks the request context, and manages buffers for response headers and incoming gRPC messages. The structure also includes flags and counters to monitor the state of the message processing, such as whether headers have been received and how much of the message buffer is used. This structure is crucial for handling multiple gRPC requests and responses efficiently within a client, allowing for state transitions between IDLE, OPEN, and CLOSE_TX states as part of the gRPC client lifecycle.


---
### fd\_grpc\_client\_private
- **Type**: `struct`
- **Members**:
    - `callbacks`: Pointer to a constant structure of gRPC client callbacks.
    - `ctx`: Pointer to a context for the gRPC client.
    - `matcher`: Array of HTTP/2 header matchers.
    - `conn`: Array representing the HTTP/2 connection.
    - `frame_rx`: Array for the unencrypted HTTP/2 RX frame buffer.
    - `frame_tx`: Array for the unencrypted HTTP/2 TX frame buffer.
    - `ssl_hs_done`: Flag indicating if the SSL handshake is done.
    - `h2_hs_done`: Flag indicating if the HTTP/2 handshake is done.
    - `request_stream`: Pointer to the inflight gRPC request stream.
    - `request_tx_op`: Array representing the request transmission operation.
    - `stream_pool`: Pointer to the pool of gRPC stream objects.
    - `stream_bufs`: Pointer to the buffer for stream data.
    - `stream_ids`: Array of stream IDs for managing active streams.
    - `streams`: Array of pointers to active gRPC streams.
    - `stream_cnt`: Count of active streams.
    - `nanopb_tx`: Pointer to the buffer for nanopb transmission.
    - `nanopb_tx_max`: Maximum size of the nanopb transmission buffer.
    - `frame_scratch`: Pointer to the scratch buffer for frame processing.
    - `frame_scratch_max`: Maximum size of the frame scratch buffer.
    - `frame_rx_buf`: Pointer to the buffer for receiving frames.
    - `frame_rx_buf_max`: Maximum size of the frame receive buffer.
    - `frame_tx_buf`: Pointer to the buffer for transmitting frames.
    - `frame_tx_buf_max`: Maximum size of the frame transmit buffer.
    - `version_len`: Length of the version string.
    - `version`: Character array holding the version string.
    - `metrics`: Pointer to the structure holding client metrics.
- **Description**: The `fd_grpc_client_private` structure encapsulates the internal state and resources of a gRPC client, managing both HTTP/2 and TLS connections. It includes fields for handling callbacks, context, and various buffers for frame transmission and reception. The structure also maintains a pool of stream objects to manage multiple concurrent gRPC requests and responses, with mechanisms to track the state of each stream. Additionally, it holds configuration and operational data such as version information and client metrics, ensuring efficient management of gRPC communication.


# Functions

---
### fd\_grpc\_h2\_stream\_upcast<!-- {{#callable:fd_grpc_h2_stream_upcast}} -->
The function `fd_grpc_h2_stream_upcast` converts a pointer of type `fd_h2_stream_t` to a pointer of type `fd_grpc_h2_stream_t` by adjusting the memory address.
- **Inputs**:
    - `stream`: A pointer to an `fd_h2_stream_t` structure, representing a stream in the HTTP/2 protocol.
- **Control Flow**:
    - The function takes a pointer to an `fd_h2_stream_t` structure as input.
    - It calculates the memory address of the containing `fd_grpc_h2_stream_t` structure by subtracting the offset of the `s` member from the input pointer's address.
    - The function returns the calculated address cast to a pointer of type `fd_grpc_h2_stream_t`.
- **Output**: A pointer to an `fd_grpc_h2_stream_t` structure, which is the containing structure of the input `fd_h2_stream_t` pointer.



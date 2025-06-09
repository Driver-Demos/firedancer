# Purpose
This C header file, `fd_http_server_private.h`, is part of a larger HTTP server implementation, specifically designed to handle HTTP and WebSocket connections. It defines several private structures and constants that are crucial for managing the internal state and operations of the server. The file includes definitions for connection states, WebSocket frame handling, and server configuration parameters. The structures `fd_http_server_connection` and `fd_http_server_ws_connection` are used to manage individual HTTP and WebSocket connections, respectively, including their states, data buffers, and treap fields for efficient connection management. The `fd_http_server_private` structure encapsulates the server's overall state, including socket file descriptors, connection arrays, and callback mechanisms.

This header file is not intended to be a public API but rather serves as an internal component of the HTTP server's implementation. It provides the necessary data structures and constants that facilitate the server's operation, such as managing connection states, handling WebSocket frames, and maintaining server configurations. The use of macros like `FD_HTTP_SERVER_MAGIC` ensures integrity and consistency within the server's operations. The file is designed to be included in other source files within the same module, providing them with the necessary internal details to implement the server's functionality effectively.
# Imports and Dependencies

---
- `fd_http_server.h`


# Data Structures

---
### fd\_http\_server\_connection
- **Type**: `struct`
- **Members**:
    - `state`: Represents the current state of the HTTP server connection.
    - `upgrade_websocket`: Indicates if the connection is being upgraded to a WebSocket.
    - `request_bytes_len`: Stores the length of the request bytes.
    - `sec_websocket_key`: Holds the security key for WebSocket connections.
    - `request_bytes`: Pointer to the request bytes data.
    - `request_bytes_read`: Tracks the number of request bytes that have been read.
    - `response`: Contains the HTTP server response data.
    - `response_bytes_written`: Tracks the number of response bytes that have been written.
    - `left`: Treap field representing the left child node.
    - `right`: Treap field representing the right child node.
    - `parent`: Treap field representing the parent node.
    - `prio`: Treap field representing the priority of the node.
    - `prev`: Treap field representing the previous node in the treap.
    - `next`: Treap field representing the next node in the treap.
- **Description**: The `fd_http_server_connection` structure is designed to manage and track the state of an HTTP server connection, including handling WebSocket upgrades. It contains fields for managing request and response data, such as the length and content of request bytes, the response data, and the number of bytes read or written. Additionally, it includes fields for managing a treap data structure, which is used for efficient node management and traversal within the server's connection handling logic. This structure is crucial for maintaining the state and flow of data in an HTTP server environment.


---
### fd\_http\_server\_ws\_frame
- **Type**: `struct`
- **Members**:
    - `off`: Represents the offset within a WebSocket frame.
    - `len`: Indicates the length of the WebSocket frame.
- **Description**: The `fd_http_server_ws_frame` structure is used to represent a WebSocket frame within the HTTP server context. It contains two members: `off`, which specifies the offset within the frame, and `len`, which denotes the length of the frame. This structure is likely used to manage and process WebSocket frames as part of the server's WebSocket handling functionality.


---
### fd\_http\_server\_ws\_frame\_t
- **Type**: `struct`
- **Members**:
    - `off`: Represents the offset within a WebSocket frame.
    - `len`: Indicates the length of the WebSocket frame.
- **Description**: The `fd_http_server_ws_frame_t` structure is used to represent a WebSocket frame in the context of an HTTP server. It contains two members: `off`, which specifies the offset within the frame, and `len`, which denotes the length of the frame. This structure is likely used to manage and process WebSocket frames as part of the server's WebSocket handling functionality.


---
### fd\_http\_server\_ws\_connection
- **Type**: `struct`
- **Members**:
    - `pong_state`: Indicates the current state of the pong operation.
    - `pong_data_len`: Specifies the length of the pong data.
    - `pong_data`: Holds the pong data with a maximum size of 125 bytes.
    - `pong_bytes_written`: Tracks the number of bytes written for the pong operation.
    - `recv_started_msg`: Indicates if a message reception has started.
    - `recv_last_opcode`: Stores the last opcode received in a message.
    - `recv_bytes_parsed`: Counts the number of bytes parsed from the received message.
    - `recv_bytes_read`: Counts the number of bytes read from the received message.
    - `recv_bytes`: Points to the buffer holding the received bytes.
    - `send_frame_state`: Indicates the current state of the frame sending operation.
    - `send_frame_bytes_written`: Tracks the number of bytes written for the current frame being sent.
    - `send_frame_cnt`: Counts the number of frames to be sent.
    - `send_frame_idx`: Tracks the index of the current frame being sent.
    - `send_frames`: Points to the array of frames to be sent.
    - `left`: Treap field indicating the left child node.
    - `right`: Treap field indicating the right child node.
    - `parent`: Treap field indicating the parent node.
    - `prio`: Treap field indicating the priority of the node.
    - `prev`: Treap field indicating the previous node in the treap.
    - `next`: Treap field indicating the next node in the treap.
- **Description**: The `fd_http_server_ws_connection` structure is designed to manage WebSocket connections within an HTTP server context. It maintains state information for pong operations, message reception, and frame sending, including tracking the number of bytes processed and the current state of operations. Additionally, it includes treap fields for managing the connection within a treap data structure, which is used for efficient connection management and traversal.


---
### fd\_http\_server\_hcache\_private
- **Type**: `struct`
- **Members**:
    - `err`: Indicates if there has been an error while printing.
    - `off`: Represents the offset into the staging buffer.
    - `len`: Denotes the length of the staging buffer.
- **Description**: The `fd_http_server_hcache_private` structure is a private data structure used within the HTTP server implementation to manage a staging buffer. It contains an error flag (`err`) to track any errors that occur during operations, an offset (`off`) to indicate the current position within the buffer, and a length (`len`) to specify the total size of the buffer. This structure is likely used internally to handle temporary data storage during HTTP request or response processing.


---
### fd\_http\_server\_private
- **Type**: `struct`
- **Members**:
    - `socket_fd`: File descriptor for the server socket.
    - `oring`: Pointer to an output ring buffer.
    - `oring_sz`: Size of the output ring buffer.
    - `stage_err`: Error status for the staging process.
    - `stage_off`: Offset in the staging buffer.
    - `stage_len`: Length of the staging buffer.
    - `max_conns`: Maximum number of HTTP connections allowed.
    - `max_ws_conns`: Maximum number of WebSocket connections allowed.
    - `max_request_len`: Maximum length of an HTTP request.
    - `max_ws_recv_frame_len`: Maximum length of a WebSocket received frame.
    - `max_ws_send_frame_cnt`: Maximum count of WebSocket frames to send.
    - `evict_conn_id`: ID of the connection to evict.
    - `evict_ws_conn_id`: ID of the WebSocket connection to evict.
    - `callback_ctx`: Context for callback functions.
    - `callbacks`: Structure containing server callback functions.
    - `magic`: Magic number for structure validation.
    - `conns`: Pointer to an array of HTTP server connections.
    - `ws_conns`: Pointer to an array of WebSocket server connections.
    - `pollfds`: Pointer to an array of poll file descriptors.
    - `conn_treap`: Pointer to a treap data structure for connections.
    - `ws_conn_treap`: Pointer to a treap data structure for WebSocket connections.
- **Description**: The `fd_http_server_private` structure is a comprehensive data structure designed to manage the internal state and configuration of an HTTP server, including WebSocket support. It contains fields for managing socket connections, staging buffers, and connection limits, as well as pointers to arrays of connection objects and poll file descriptors. The structure also includes fields for handling errors, managing callbacks, and maintaining treap data structures for efficient connection management. The presence of a magic number ensures the integrity and validity of the structure during runtime.



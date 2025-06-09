# Purpose
The provided C header file, `fd_h2_callback.h`, defines a callback interface for handling events in an HTTP/2 connection context. This file is part of a broader HTTP/2 implementation, likely serving as a component that allows applications to interact with and respond to various connection and stream events. The primary structure defined in this file is `fd_h2_callbacks`, which acts as a virtual function table containing pointers to callback functions. These functions are invoked to notify the application of specific events, such as the creation and querying of streams, connection establishment and closure, receipt of headers and data, stream termination, and window updates. The callbacks are designed to be implemented by the application using this interface, allowing for custom handling of these events.

Additionally, the file provides a set of no-operation (noop) default functions, which serve as placeholders or stubs for the callback functions. These noop functions are useful for initializing the callback structure with default behavior, ensuring that all function pointers are valid and preventing null pointer dereferences. The [`fd_h2_callbacks_init`](#fd_h2_callbacks_init) function is provided to initialize a `fd_h2_callbacks_t` structure with these noop functions. This header file is intended to be included in other C source files that require HTTP/2 event handling capabilities, and it does not define any public APIs or external interfaces beyond the callback mechanism itself.
# Imports and Dependencies

---
- `fd_h2_base.h`


# Global Variables

---
### fd\_h2\_callbacks\_noop
- **Type**: `fd_h2_callbacks_t const`
- **Description**: The `fd_h2_callbacks_noop` is a constant instance of the `fd_h2_callbacks_t` structure, which serves as a virtual function table for HTTP/2 callback functions. This instance is specifically designed to provide no-operation (noop) implementations for each callback function, meaning that each function in the table does nothing when called.
- **Use**: This variable is used as a default or placeholder callback set where no specific action is required for HTTP/2 events.


---
### fd\_h2\_callbacks\_init
- **Type**: `function pointer`
- **Description**: The `fd_h2_callbacks_init` is a function that initializes a given `fd_h2_callbacks_t` structure with no-op (no operation) functions. This structure is a virtual function table used in the HTTP/2 callback interface to handle various events on connections.
- **Use**: This function is used to set up a `fd_h2_callbacks_t` structure with default no-op implementations for all callback functions.


---
### fd\_h2\_noop\_stream\_create
- **Type**: `function pointer`
- **Description**: The `fd_h2_noop_stream_create` is a function pointer that serves as a stub or default implementation for creating a new HTTP/2 stream object. It is part of a set of no-op (no operation) functions that provide default behavior for the HTTP/2 callback interface.
- **Use**: This function is used as a default handler for stream creation in the HTTP/2 protocol, returning a stream object or NULL if the creation is rejected.


---
### fd\_h2\_noop\_stream\_query
- **Type**: `function pointer`
- **Description**: `fd_h2_noop_stream_query` is a function pointer that serves as a stub or default implementation for querying a previously created HTTP/2 stream associated with a given connection and stream ID. It is part of a set of no-op (no operation) functions that provide default behavior for the HTTP/2 callback interface.
- **Use**: This function pointer is used to provide a default implementation for querying streams in the HTTP/2 callback interface, typically when no specific behavior is required.


# Data Structures

---
### fd\_h2\_callbacks
- **Type**: `struct`
- **Members**:
    - `stream_create`: Function pointer for creating a stream object for a peer-initiated HTTP/2 stream.
    - `stream_query`: Function pointer for querying a previously created stream.
    - `conn_established`: Function pointer for handling connection establishment.
    - `conn_final`: Function pointer for handling connection closure notification.
    - `headers`: Function pointer for delivering incoming HPACK-encoded header data.
    - `data`: Function pointer for delivering incoming raw stream data.
    - `rst_stream`: Function pointer for signaling the termination of a stream.
    - `window_update`: Function pointer for delivering a connection-level WINDOW_UPDATE frame.
    - `stream_window_update`: Function pointer for delivering a stream-level WINDOW_UPDATE frame.
    - `ping_ack`: Function pointer for delivering an acknowledgment of a previously sent PING.
- **Description**: The `fd_h2_callbacks` structure is a virtual function table that defines a set of callback functions used by the HTTP/2 protocol implementation to notify applications of various events on existing connections. These events include stream creation, querying, connection establishment and closure, header and data reception, stream termination, window updates, and ping acknowledgments. Each member of the structure is a function pointer that the application must implement to handle the corresponding event, ensuring that the HTTP/2 connection and stream management is properly integrated with the application's logic.


# Function Declarations (Public API)

---
### fd\_h2\_callbacks\_init<!-- {{#callable_declaration:fd_h2_callbacks_init}} -->
Initialize a callback structure with no-op functions.
- **Description**: Use this function to set up a `fd_h2_callbacks_t` structure with default no-op functions, which can be useful as a starting point for implementing custom callback behavior. This function should be called before using the callback structure in any HTTP/2 connection handling to ensure all function pointers are initialized to valid no-op implementations. It is important to pass a valid pointer to a `fd_h2_callbacks_t` structure, as the function will modify the contents of the structure.
- **Inputs**:
    - `callbacks`: A pointer to a `fd_h2_callbacks_t` structure that will be initialized with no-op functions. Must not be null, as the function will dereference this pointer to set up the structure.
- **Output**: Returns the pointer to the initialized `fd_h2_callbacks_t` structure, which is the same as the input pointer.
- **See also**: [`fd_h2_callbacks_init`](fd_h2_callback.c.driver.md#fd_h2_callbacks_init)  (Implementation)


---
### fd\_h2\_noop\_stream\_create<!-- {{#callable_declaration:fd_h2_noop_stream_create}} -->
Rejects the creation of a new HTTP/2 stream.
- **Description**: This function is a no-operation (noop) implementation of a stream creation callback for an HTTP/2 connection. It is used when the application does not wish to create a new stream for a peer-initiated request. The function always returns NULL, indicating that the stream creation is rejected. This can be useful in scenarios where the application needs to explicitly deny stream creation requests without implementing custom logic.
- **Inputs**:
    - `conn`: A pointer to an fd_h2_conn_t structure representing the HTTP/2 connection. The pointer is not used in this function, and the caller retains ownership.
    - `stream_id`: An unsigned integer representing the ID of the stream to be created. This parameter is not used in this function.
- **Output**: Returns NULL to indicate that the stream creation is rejected.
- **See also**: [`fd_h2_noop_stream_create`](fd_h2_callback.c.driver.md#fd_h2_noop_stream_create)  (Implementation)


---
### fd\_h2\_noop\_stream\_query<!-- {{#callable_declaration:fd_h2_noop_stream_query}} -->
Provides a no-operation implementation for querying a stream.
- **Description**: This function serves as a no-operation (noop) implementation for querying a previously created HTTP/2 stream within a connection. It is part of a set of default functions that can be used when no specific behavior is required for certain callbacks. This function always returns NULL, indicating that no stream is found or no operation is performed. It is useful in scenarios where a placeholder implementation is needed, and it should be used when the application does not need to handle stream queries actively.
- **Inputs**:
    - `conn`: A pointer to an fd_h2_conn_t structure representing the connection. The pointer must not be null, but the function does not use this parameter.
    - `stream_id`: An unsigned integer representing the stream identifier. The function does not use this parameter, and it has no effect on the output.
- **Output**: Always returns NULL, indicating no stream is found or no operation is performed.
- **See also**: [`fd_h2_noop_stream_query`](fd_h2_callback.c.driver.md#fd_h2_noop_stream_query)  (Implementation)


---
### fd\_h2\_noop\_conn\_established<!-- {{#callable_declaration:fd_h2_noop_conn_established}} -->
Provides a no-operation callback for connection establishment.
- **Description**: This function serves as a placeholder callback for when a connection is established in an HTTP/2 context. It is part of a set of no-operation (noop) functions that can be used to initialize a callback structure with default behaviors that do nothing. This is useful in scenarios where specific actions are not required upon connection establishment, allowing the application to avoid implementing unnecessary logic. The function must be used in conjunction with a properly initialized `fd_h2_conn_t` object.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` object representing the connection. The pointer must not be null, and the caller retains ownership of the object. The function does not perform any operations on this parameter.
- **Output**: None
- **See also**: [`fd_h2_noop_conn_established`](fd_h2_callback.c.driver.md#fd_h2_noop_conn_established)  (Implementation)


---
### fd\_h2\_noop\_conn\_final<!-- {{#callable_declaration:fd_h2_noop_conn_final}} -->
Provides a no-operation callback for connection finalization.
- **Description**: This function serves as a no-operation (noop) callback for the `conn_final` event in the HTTP/2 connection lifecycle. It is intended to be used as a default or placeholder implementation when no specific action is required upon the finalization of a connection. This function can be useful in scenarios where a complete callback structure is needed, but certain events do not require handling. It does not perform any operations or modify any state, ensuring that the connection closure process proceeds without additional side effects.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection. The pointer must not be null, but the function does not use this parameter.
    - `h2_err`: An unsigned integer representing the HTTP/2 error code associated with the connection closure. The function does not use this parameter.
    - `closed_by`: An integer indicating who closed the connection (0 for local, 1 for peer). The function does not use this parameter.
- **Output**: None
- **See also**: [`fd_h2_noop_conn_final`](fd_h2_callback.c.driver.md#fd_h2_noop_conn_final)  (Implementation)


---
### fd\_h2\_noop\_headers<!-- {{#callable_declaration:fd_h2_noop_headers}} -->
Provides a no-operation implementation for handling HTTP/2 header data.
- **Description**: This function serves as a placeholder or default implementation for handling incoming HPACK-encoded header data in an HTTP/2 connection. It is part of a set of no-operation callbacks that can be used when no specific action is required for certain events. This function does not perform any operations on the provided data or affect the connection or stream state. It is typically used in scenarios where the application does not need to process header data, allowing the developer to focus on other aspects of the connection handling.
- **Inputs**:
    - `conn`: A pointer to an fd_h2_conn_t structure representing the HTTP/2 connection. Must not be null, but is not used in this function.
    - `stream`: A pointer to an fd_h2_stream_t structure representing the HTTP/2 stream. Must not be null, but is not used in this function.
    - `data`: A pointer to the HPACK-encoded header data. Must not be null, but is not used in this function.
    - `data_sz`: The size of the data in bytes. This value is not used in this function.
    - `flags`: A set of flags indicating the state of the header frame, such as END_STREAM or END_HEADERS. This value is not used in this function.
- **Output**: None
- **See also**: [`fd_h2_noop_headers`](fd_h2_callback.c.driver.md#fd_h2_noop_headers)  (Implementation)


---
### fd\_h2\_noop\_data<!-- {{#callable_declaration:fd_h2_noop_data}} -->
Provide a no-operation handler for incoming raw stream data.
- **Description**: This function serves as a placeholder or default handler for incoming raw stream data in an HTTP/2 connection. It is part of a set of no-operation (noop) callbacks that can be used when no specific action is required for certain events. This function does not perform any operations on the data or affect the connection or stream state. It is typically used during development or in scenarios where data handling is not needed.
- **Inputs**:
    - `conn`: A pointer to an fd_h2_conn_t structure representing the HTTP/2 connection. Must not be null, but the function does not use this parameter.
    - `stream`: A pointer to an fd_h2_stream_t structure representing the HTTP/2 stream. Must not be null, but the function does not use this parameter.
    - `data`: A pointer to the raw data received. Must not be null, but the function does not use this parameter.
    - `data_sz`: The size of the data in bytes. The function does not use this parameter.
    - `flags`: Flags associated with the data. The function does not use this parameter.
- **Output**: None
- **See also**: [`fd_h2_noop_data`](fd_h2_callback.c.driver.md#fd_h2_noop_data)  (Implementation)


---
### fd\_h2\_noop\_rst\_stream<!-- {{#callable_declaration:fd_h2_noop_rst_stream}} -->
Provide a no-operation handler for stream termination.
- **Description**: This function serves as a no-operation (noop) handler for the termination of an HTTP/2 stream. It is part of a set of default callback functions that can be used when no specific action is required upon stream termination. This function can be used in scenarios where the application does not need to perform any cleanup or logging when a stream is terminated. It is important to ensure that this function is only used in contexts where ignoring stream termination is acceptable, as it does not perform any deallocation or state updates.
- **Inputs**:
    - `conn`: A pointer to an fd_h2_conn_t structure representing the HTTP/2 connection. The pointer must not be null, but the function does not use this parameter.
    - `stream`: A pointer to an fd_h2_stream_t structure representing the stream to be terminated. The pointer must not be null, but the function does not use this parameter.
    - `error_code`: An unsigned integer representing the HTTP/2 error code associated with the stream termination. The function does not use this parameter.
    - `closed_by`: An integer indicating who closed the stream (0 for local, 1 for peer). The function does not use this parameter.
- **Output**: None
- **See also**: [`fd_h2_noop_rst_stream`](fd_h2_callback.c.driver.md#fd_h2_noop_rst_stream)  (Implementation)


---
### fd\_h2\_noop\_window\_update<!-- {{#callable_declaration:fd_h2_noop_window_update}} -->
Provides a no-operation handler for connection-level WINDOW_UPDATE frames.
- **Description**: This function serves as a placeholder or default handler for connection-level WINDOW_UPDATE frames in an HTTP/2 connection. It is part of a set of no-operation functions that can be used to initialize callback structures where specific behavior is not required. This function does not perform any actions and can be used when no processing is needed for WINDOW_UPDATE frames. It is typically used in scenarios where the application does not need to handle these frames explicitly.
- **Inputs**:
    - `conn`: A pointer to an fd_h2_conn_t structure representing the HTTP/2 connection. The pointer must not be null, but the function does not use this parameter.
    - `increment`: An unsigned integer representing the window size increment. The function does not use this parameter.
- **Output**: None
- **See also**: [`fd_h2_noop_window_update`](fd_h2_callback.c.driver.md#fd_h2_noop_window_update)  (Implementation)


---
### fd\_h2\_noop\_stream\_window\_update<!-- {{#callable_declaration:fd_h2_noop_stream_window_update}} -->
Provides a no-operation handler for stream-level WINDOW_UPDATE frames.
- **Description**: This function serves as a placeholder or default handler for stream-level WINDOW_UPDATE frames in an HTTP/2 connection. It is part of a set of no-operation functions that can be used to initialize callback structures where specific behavior is not required. This function does not perform any actions and can be used when no stream-level window update handling is needed.
- **Inputs**:
    - `conn`: A pointer to an fd_h2_conn_t structure representing the HTTP/2 connection. The pointer must not be null, but the function does not use this parameter.
    - `stream`: A pointer to an fd_h2_stream_t structure representing the HTTP/2 stream. The pointer must not be null, but the function does not use this parameter.
    - `increment`: An unsigned integer representing the window size increment. The function does not use this parameter.
- **Output**: None
- **See also**: [`fd_h2_noop_stream_window_update`](fd_h2_callback.c.driver.md#fd_h2_noop_stream_window_update)  (Implementation)


---
### fd\_h2\_noop\_ping\_ack<!-- {{#callable_declaration:fd_h2_noop_ping_ack}} -->
Handles a no-operation acknowledgment for a PING frame.
- **Description**: This function serves as a no-operation handler for acknowledging a PING frame in an HTTP/2 connection. It is part of a set of default or stub functions that can be used when no specific action is required upon receiving a PING acknowledgment. This function can be used in scenarios where the application does not need to perform any operations in response to a PING acknowledgment, effectively acting as a placeholder.
- **Inputs**:
    - `conn`: A pointer to an fd_h2_conn_t structure representing the HTTP/2 connection. The pointer must not be null, but the function does not use this parameter, so its state or value does not affect the function's behavior.
- **Output**: None
- **See also**: [`fd_h2_noop_ping_ack`](fd_h2_callback.c.driver.md#fd_h2_noop_ping_ack)  (Implementation)



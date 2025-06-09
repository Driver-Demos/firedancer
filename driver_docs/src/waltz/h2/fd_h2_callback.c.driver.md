# Purpose
This C source code file defines a set of no-operation (noop) callback functions for handling HTTP/2 protocol events. The primary purpose of these functions is to provide a default implementation that does nothing, effectively serving as placeholders or stubs. Each function takes parameters relevant to HTTP/2 operations, such as connection and stream identifiers, but the parameters are not used within the functions, as indicated by the `(void)` casts. This pattern is typical in situations where a complete implementation is not yet needed, or when testing and debugging require a minimal, non-functional setup.

The file also defines a `fd_h2_callbacks_t` structure, `fd_h2_callbacks_noop`, which aggregates these noop functions into a single entity. This structure can be used to initialize other callback structures via the [`fd_h2_callbacks_init`](#fd_h2_callbacks_init) function, which assigns the noop callbacks to a given `fd_h2_callbacks_t` instance. This setup is useful in modular software design, where components can be developed and tested independently, with the noop callbacks serving as a temporary stand-in for actual functionality. The file is likely part of a larger library or framework dealing with HTTP/2 connections, providing a basic template for developers to implement their own specific logic for handling HTTP/2 events.
# Imports and Dependencies

---
- `fd_h2_callback.h`
- `fd_h2_base.h`


# Global Variables

---
### fd\_h2\_callbacks\_noop
- **Type**: `fd_h2_callbacks_t const`
- **Description**: The `fd_h2_callbacks_noop` is a constant instance of the `fd_h2_callbacks_t` structure, which is initialized with a set of no-operation (noop) functions. These functions are placeholders that do nothing and return default values, such as NULL for pointers or void for functions with no return value. This structure is used to define a set of default behaviors for HTTP/2 connection and stream events, where no specific action is required.
- **Use**: This variable is used to initialize callback structures with no-operation functions, providing a default behavior where no specific callback actions are needed.


# Functions

---
### fd\_h2\_noop\_stream\_create<!-- {{#callable:fd_h2_noop_stream_create}} -->
The `fd_h2_noop_stream_create` function is a no-operation function that takes a connection and stream ID as inputs and returns NULL.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the connection.
    - `stream_id`: An unsigned integer representing the stream ID.
- **Control Flow**:
    - The function takes two parameters, `conn` and `stream_id`, but does not use them, as indicated by the `(void)` cast.
    - The function immediately returns `NULL`, indicating no operation is performed.
- **Output**: The function returns `NULL`, indicating that no stream is created.


---
### fd\_h2\_noop\_stream\_query<!-- {{#callable:fd_h2_noop_stream_query}} -->
The `fd_h2_noop_stream_query` function is a no-operation placeholder that takes a connection and stream ID as inputs and always returns `NULL`.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the connection.
    - `stream_id`: An unsigned integer representing the stream ID.
- **Control Flow**:
    - The function takes two parameters, `conn` and `stream_id`, but does not use them, as indicated by the `(void)` cast to suppress unused parameter warnings.
    - The function immediately returns `NULL`, indicating no operation or result.
- **Output**: The function returns `NULL`, indicating that no stream is found or processed.


---
### fd\_h2\_noop\_conn\_established<!-- {{#callable:fd_h2_noop_conn_established}} -->
The `fd_h2_noop_conn_established` function is a no-operation callback for when an HTTP/2 connection is established, taking a connection pointer as input but performing no actions.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
- **Control Flow**:
    - The function takes a single argument, `conn`, which is a pointer to an `fd_h2_conn_t` structure.
    - The function explicitly casts the `conn` parameter to void to indicate that it is intentionally unused.
    - No operations or logic are performed within the function body.
- **Output**: The function does not return any value or produce any output.


---
### fd\_h2\_noop\_conn\_final<!-- {{#callable:fd_h2_noop_conn_final}} -->
The `fd_h2_noop_conn_final` function is a no-operation placeholder for handling the finalization of an HTTP/2 connection.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
    - `h2_err`: An unsigned integer representing the HTTP/2 error code.
    - `closed_by`: An integer indicating who closed the connection.
- **Control Flow**:
    - The function takes three parameters: `conn`, `h2_err`, and `closed_by`, but does not use them.
    - Each parameter is explicitly cast to void to suppress compiler warnings about unused parameters.
- **Output**: The function does not return any value or perform any operations.


---
### fd\_h2\_noop\_headers<!-- {{#callable:fd_h2_noop_headers}} -->
The `fd_h2_noop_headers` function is a no-operation placeholder for handling HTTP/2 headers, taking several parameters but performing no actions with them.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
    - `stream`: A pointer to an `fd_h2_stream_t` structure representing the HTTP/2 stream.
    - `data`: A constant void pointer to the data associated with the headers.
    - `data_sz`: An unsigned long representing the size of the data.
    - `flags`: An unsigned long representing any flags associated with the headers.
- **Control Flow**:
    - The function takes five parameters: `conn`, `stream`, `data`, `data_sz`, and `flags`.
    - Each parameter is explicitly cast to void to indicate that they are unused, effectively making the function a no-op.
    - The function does not perform any operations or return any values.
- **Output**: This function does not produce any output or return a value.


---
### fd\_h2\_noop\_data<!-- {{#callable:fd_h2_noop_data}} -->
The `fd_h2_noop_data` function is a no-operation placeholder for handling data frames in an HTTP/2 connection.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
    - `stream`: A pointer to an `fd_h2_stream_t` structure representing the HTTP/2 stream.
    - `data`: A constant pointer to the data being passed, which is not used in this function.
    - `data_sz`: An unsigned long representing the size of the data, which is not used in this function.
    - `flags`: An unsigned long representing flags associated with the data, which is not used in this function.
- **Control Flow**:
    - The function takes five parameters but does not perform any operations with them.
    - Each parameter is explicitly cast to void to indicate that they are intentionally unused.
- **Output**: This function does not return any value or produce any output.


---
### fd\_h2\_noop\_rst\_stream<!-- {{#callable:fd_h2_noop_rst_stream}} -->
The `fd_h2_noop_rst_stream` function is a no-operation placeholder for handling HTTP/2 RST_STREAM frames, taking in connection, stream, error code, and closed-by parameters without performing any actions.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
    - `stream`: A pointer to an `fd_h2_stream_t` structure representing the HTTP/2 stream.
    - `error_code`: An unsigned integer representing the error code associated with the RST_STREAM frame.
    - `closed_by`: An integer indicating who closed the stream (e.g., client or server).
- **Control Flow**:
    - The function takes four parameters: `conn`, `stream`, `error_code`, and `closed_by`.
    - Each parameter is explicitly cast to void to indicate that they are unused, effectively making the function a no-op.
    - The function does not perform any operations or return any values.
- **Output**: The function does not produce any output or return any value.


---
### fd\_h2\_noop\_window\_update<!-- {{#callable:fd_h2_noop_window_update}} -->
The `fd_h2_noop_window_update` function is a no-operation placeholder for handling window update events in an HTTP/2 connection.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
    - `increment`: An unsigned integer representing the window size increment.
- **Control Flow**:
    - The function takes two parameters: a connection pointer and an increment value.
    - Both parameters are explicitly marked as unused using the `(void)` cast, indicating that the function does not perform any operations with them.
- **Output**: The function does not return any value or perform any operations; it is a no-op function.


---
### fd\_h2\_noop\_stream\_window\_update<!-- {{#callable:fd_h2_noop_stream_window_update}} -->
The `fd_h2_noop_stream_window_update` function is a no-operation placeholder for handling stream window updates in an HTTP/2 connection.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
    - `stream`: A pointer to an `fd_h2_stream_t` structure representing the specific stream within the connection.
    - `increment`: An unsigned integer representing the amount by which the stream's window size should be incremented.
- **Control Flow**:
    - The function takes three parameters: a connection pointer, a stream pointer, and an increment value.
    - All parameters are explicitly marked as unused using the `(void)` cast, indicating that the function does not perform any operations with them.
- **Output**: The function does not produce any output or perform any operations; it is a no-op function.


---
### fd\_h2\_noop\_ping\_ack<!-- {{#callable:fd_h2_noop_ping_ack}} -->
The `fd_h2_noop_ping_ack` function is a no-operation placeholder for handling ping acknowledgments in an HTTP/2 connection.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
- **Control Flow**:
    - The function takes a single argument, `conn`, which is a pointer to an `fd_h2_conn_t` structure.
    - The function body contains a single statement that casts `conn` to void, effectively ignoring the input parameter.
    - No operations or logic are performed within the function.
- **Output**: The function does not return any value or produce any output.


---
### fd\_h2\_callbacks\_init<!-- {{#callable:fd_h2_callbacks_init}} -->
The `fd_h2_callbacks_init` function initializes a given `fd_h2_callbacks_t` structure with default no-operation callbacks.
- **Inputs**:
    - `callbacks`: A pointer to an `fd_h2_callbacks_t` structure that will be initialized with no-operation callbacks.
- **Control Flow**:
    - The function takes a pointer to an `fd_h2_callbacks_t` structure as input.
    - It assigns the `fd_h2_callbacks_noop` structure, which contains no-operation functions, to the dereferenced `callbacks` pointer.
    - The function returns the initialized `callbacks` pointer.
- **Output**: A pointer to the initialized `fd_h2_callbacks_t` structure.



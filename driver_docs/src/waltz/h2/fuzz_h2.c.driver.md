# Purpose
The provided C source code file, `fuzz_h2.c`, is designed to test the robustness and reliability of HTTP/2 connection-level APIs, specifically those defined in the `fd_h2` library. The primary purpose of this file is to identify potential issues such as crashes, infinite loops, and other bugs within the HTTP/2 connection handling logic. It achieves this by simulating various HTTP/2 operations and monitoring the system's response to these operations. The code is structured to work with a fuzzing framework, as indicated by the presence of functions like [`LLVMFuzzerInitialize`](#LLVMFuzzerInitialize) and [`LLVMFuzzerTestOneInput`](#LLVMFuzzerTestOneInput), which are typical entry points for fuzz testing.

The file includes several callback functions that handle different HTTP/2 events, such as stream creation, connection establishment, and data reception. These callbacks are registered in a `fd_h2_callbacks_t` structure, which is used during the fuzzing process to simulate real-world HTTP/2 interactions. The code also manages internal state through structures like `fuzz_h2_ctx_t`, which encapsulates the context for a single fuzzing session, including buffers and connection objects. Additionally, the code uses random number generation to introduce variability in the test inputs, further enhancing the fuzzing process's effectiveness. Overall, this file is a specialized tool for testing and validating the stability of HTTP/2 connection handling in the `fd_h2` library.
# Imports and Dependencies

---
- `assert.h`
- `stdlib.h`
- `fd_h2.h`
- `../../util/fd_util.h`


# Global Variables

---
### fuzz\_h2\_ctx\_t
- **Type**: `struct fuzz_h2_ctx`
- **Description**: The `fuzz_h2_ctx_t` is a structure that encapsulates various components necessary for managing an HTTP/2 connection in a fuzz testing environment. It includes a transmission buffer (`rbuf_tx`), a connection object (`conn`), a stream object (`stream`), and a transmission operation object (`tx_op`). These components are used to simulate and test the behavior of HTTP/2 connections under various conditions.
- **Use**: This variable is used to maintain the state and manage operations of an HTTP/2 connection during fuzz testing, allowing the program to simulate different scenarios and detect potential issues.


---
### fd\_rng\_t
- **Type**: `fd_rng_t`
- **Description**: The `fd_rng_t` type is a data structure used for random number generation. It is part of the Fast Data (FD) library, which provides utilities for high-performance computing. This specific instance, `g_rng`, is a global array of one `fd_rng_t` object, used to maintain the state of the random number generator.
- **Use**: The `g_rng` variable is used to initialize and manage the state of a random number generator for the fuzzing operations in the program.


---
### g\_stream\_cnt
- **Type**: `long`
- **Description**: The `g_stream_cnt` is a static thread-local global variable of type `long` that tracks the number of active HTTP/2 streams in the fuzzing context. It is used to detect stream leaks by ensuring that stream creation and closure are balanced.
- **Use**: `g_stream_cnt` is incremented when a new stream is created and decremented when a stream is closed, helping to ensure that all streams are properly managed and closed.


---
### g\_conn\_final\_cnt
- **Type**: `long`
- **Description**: The `g_conn_final_cnt` is a static thread-local long integer variable that counts the number of times a connection has been finalized in the fuzzing process of HTTP/2 connections. It is incremented in the `cb_conn_final` callback function, which is triggered when a connection is finalized.
- **Use**: This variable is used to track the number of finalized connections to ensure that the connection lifecycle is correctly managed during fuzz testing.


---
### fuzz\_h2\_cb
- **Type**: `fd_h2_callbacks_t`
- **Description**: The `fuzz_h2_cb` is a static instance of the `fd_h2_callbacks_t` structure, which is used to define a set of callback functions for handling various HTTP/2 events. These callbacks include functions for stream creation, querying, connection establishment, finalization, handling headers, data, reset streams, and window updates.
- **Use**: This variable is used to provide the necessary callback functions to the HTTP/2 connection handling logic, allowing it to respond to different events during the fuzz testing process.


# Data Structures

---
### fuzz\_h2\_ctx
- **Type**: `struct`
- **Members**:
    - `rbuf_tx`: An array of one fd_h2_rbuf_t structure, representing the transmission buffer for HTTP/2 operations.
    - `conn`: An array of one fd_h2_conn_t structure, representing the HTTP/2 connection context.
    - `stream`: An array of one fd_h2_stream_t structure, representing the HTTP/2 stream context.
    - `tx_op`: An array of one fd_h2_tx_op_t structure, representing the transmission operation context for HTTP/2.
- **Description**: The `fuzz_h2_ctx` structure is designed to encapsulate the context required for fuzz testing HTTP/2 connection-level APIs. It includes buffers and contexts for managing HTTP/2 connections, streams, and transmission operations, facilitating the testing of various scenarios to identify potential crashes or bugs in the HTTP/2 implementation.


---
### fuzz\_h2\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `rbuf_tx`: An array of one fd_h2_rbuf_t structure used for transmission buffering.
    - `conn`: An array of one fd_h2_conn_t structure representing the connection context.
    - `stream`: An array of one fd_h2_stream_t structure representing the stream context.
    - `tx_op`: An array of one fd_h2_tx_op_t structure used for transmission operations.
- **Description**: The `fuzz_h2_ctx_t` structure is designed to encapsulate the context required for fuzz testing HTTP/2 connection-level APIs. It includes buffers for transmission, a connection context, a stream context, and operations for managing transmission. This structure is used to simulate and test various scenarios in HTTP/2 communication, ensuring robustness against crashes, spinloops, and other potential bugs.


# Functions

---
### test\_response\_continue<!-- {{#callable:test_response_continue}} -->
The `test_response_continue` function checks if a stream is active and performs a copy operation, then cleans up if the stream is closed.
- **Inputs**: None
- **Control Flow**:
    - Check if the current stream's ID is non-zero; if zero, exit the function.
    - Call [`fd_h2_tx_op_copy`](fd_h2_tx.c.driver.md#fd_h2_tx_op_copy) to copy transmission operation data from the context's connection, stream, and transmission buffer to the transmission operation.
    - Check if the stream's state is `FD_H2_STREAM_STATE_CLOSED`.
    - If the stream is closed, decrement the global stream count `g_stream_cnt`.
    - Clear the transmission operation and stream data using `memset`.
- **Output**: The function does not return any value.
- **Functions called**:
    - [`fd_h2_tx_op_copy`](fd_h2_tx.c.driver.md#fd_h2_tx_op_copy)


---
### test\_response\_init<!-- {{#callable:test_response_init}} -->
The `test_response_init` function initializes an HTTP/2 response by sending a status header and preparing a transmission operation for a given stream.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection; it is not used in the function.
    - `stream`: A pointer to an `fd_h2_stream_t` structure representing the HTTP/2 stream for which the response is being initialized.
- **Control Flow**:
    - The function begins by ignoring the `conn` parameter and retrieves the `stream_id` from the `stream` parameter.
    - It sets up a buffer `rbuf_tx` from the global context `g_ctx` to prepare for transmission.
    - A header array `hpack` is defined with a single value representing the HTTP/2 status code 200.
    - The [`fd_h2_tx`](fd_h2_conn.h.driver.md#fd_h2_tx) function is called to send the `hpack` header as a HEADERS frame with the END_HEADERS flag for the specified `stream_id`.
    - A transmission operation `tx_op` is initialized from the global context `g_ctx` with the message "Ok", a length of 2, and the END_STREAM flag using `fd_h2_tx_op_init`.
    - The function calls [`test_response_continue`](#test_response_continue) to proceed with any further response handling.
- **Output**: The function does not return any value; it performs operations to initialize and send an HTTP/2 response for a given stream.
- **Functions called**:
    - [`fd_h2_tx`](fd_h2_conn.h.driver.md#fd_h2_tx)
    - [`test_response_continue`](#test_response_continue)


---
### cb\_stream\_create<!-- {{#callable:cb_stream_create}} -->
The `cb_stream_create` function initializes a new HTTP/2 stream if no stream is currently active and returns a pointer to it.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
    - `stream_id`: An unsigned integer representing the ID of the stream to be created.
- **Control Flow**:
    - The function begins by casting the `conn` and `stream_id` parameters to void to indicate they are unused.
    - It checks if the global context's stream (`g_ctx.stream`) already has a non-zero `stream_id`.
    - If a stream is already active (`stream_id` is non-zero), the function returns `NULL`, indicating that a new stream cannot be created.
    - If no stream is active, it initializes the stream using `fd_h2_stream_init` and increments the global stream count `g_stream_cnt`.
    - Finally, it returns a pointer to the newly initialized stream (`g_ctx.stream`).
- **Output**: A pointer to the newly created `fd_h2_stream_t` structure if successful, or `NULL` if a stream is already active.


---
### cb\_stream\_query<!-- {{#callable:cb_stream_query}} -->
The `cb_stream_query` function checks if a given stream ID matches the current stream's ID in the global context and returns the stream if it matches, otherwise returns NULL.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the connection.
    - `stream_id`: An unsigned integer representing the ID of the stream to query.
- **Control Flow**:
    - Assert that the provided connection pointer `conn` is the same as the global context's connection `g_ctx.conn`.
    - Check if the stream ID of the global context's stream `g_ctx.stream->stream_id` is equal to the provided `stream_id`.
    - If the stream IDs do not match, return NULL.
    - If the stream IDs match, return the stream from the global context `g_ctx.stream`.
- **Output**: Returns a pointer to the `fd_h2_stream_t` structure if the stream ID matches, otherwise returns NULL.


---
### cb\_conn\_established<!-- {{#callable:cb_conn_established}} -->
The `cb_conn_established` function asserts that the provided connection is the same as the global context connection and then returns.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the connection that has been established.
- **Control Flow**:
    - The function begins by asserting that the `conn` argument is equal to the global context's connection `g_ctx.conn`.
    - After the assertion, the function immediately returns without performing any additional operations.
- **Output**: The function does not produce any output or return any value; it simply performs an assertion check and returns.


---
### cb\_conn\_final<!-- {{#callable:cb_conn_final}} -->
The `cb_conn_final` function finalizes an HTTP/2 connection by resetting the stream count and incrementing the connection finalization count.
- **Inputs**:
    - `conn`: A pointer to the `fd_h2_conn_t` structure representing the HTTP/2 connection to be finalized.
    - `h2_err`: An unsigned integer representing the HTTP/2 error code, which is not used in this function.
    - `closed_by`: An integer indicating who closed the connection, expected to be either 0 or 1.
- **Control Flow**:
    - The function asserts that the `conn` pointer matches the global context connection `g_ctx.conn`.
    - It asserts that `closed_by` is either 0 or 1, ensuring valid input.
    - The `h2_err` parameter is explicitly ignored using a cast to void.
    - The global stream count `g_stream_cnt` is reset to 0, indicating no active streams.
    - The global connection finalization count `g_conn_final_cnt` is incremented by 1, tracking the number of times a connection has been finalized.
- **Output**: The function does not return any value; it is a `void` function.


---
### cb\_headers<!-- {{#callable:cb_headers}} -->
The `cb_headers` function processes HTTP/2 headers from a data stream, handling errors and potentially initiating a response if the end of the stream is indicated.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
    - `stream`: A pointer to an `fd_h2_stream_t` structure representing the HTTP/2 stream.
    - `data`: A constant pointer to the data buffer containing the HTTP/2 headers to be processed.
    - `data_sz`: An unsigned long representing the size of the data buffer.
    - `flags`: An unsigned long representing flags that may include `FD_H2_FLAG_END_STREAM` to indicate the end of the stream.
- **Control Flow**:
    - Initialize an `fd_hpack_rd_t` structure for reading HPACK-encoded headers from the data buffer.
    - Enter a loop that continues until all headers are read from the `hpack_rd` structure.
    - Within the loop, allocate a static buffer `scratch_buf` for temporary storage and attempt to read the next header using [`fd_hpack_rd_next`](fd_hpack.c.driver.md#fd_hpack_rd_next).
    - If an error occurs during header reading, call [`fd_h2_conn_error`](fd_h2_conn.h.driver.md#fd_h2_conn_error) with the connection and error code, then return immediately.
    - After processing all headers, check if the `FD_H2_FLAG_END_STREAM` flag is set in `flags`.
    - If the end of the stream is indicated, call [`test_response_init`](#test_response_init) to initiate a response.
- **Output**: The function does not return a value; it performs operations on the connection and stream based on the headers processed.
- **Functions called**:
    - [`fd_hpack_rd_done`](fd_hpack.h.driver.md#fd_hpack_rd_done)
    - [`fd_hpack_rd_next`](fd_hpack.c.driver.md#fd_hpack_rd_next)
    - [`fd_h2_conn_error`](fd_h2_conn.h.driver.md#fd_h2_conn_error)
    - [`test_response_init`](#test_response_init)


---
### cb\_data<!-- {{#callable:cb_data}} -->
The `cb_data` function processes incoming data for an HTTP/2 stream and initiates a response if the data marks the end of the stream.
- **Inputs**:
    - `conn`: A pointer to the HTTP/2 connection object (`fd_h2_conn_t`).
    - `stream`: A pointer to the HTTP/2 stream object (`fd_h2_stream_t`).
    - `data`: A pointer to the data received (void pointer).
    - `data_sz`: The size of the data received (unsigned long).
    - `flags`: Flags associated with the data, indicating specific conditions or states (unsigned long).
- **Control Flow**:
    - The function asserts that the connection (`conn`) is the same as the global context connection (`g_ctx.conn`).
    - The function ignores the `stream`, `data`, `data_sz`, and `flags` parameters by casting them to void, indicating they are unused in the current implementation.
    - It checks if the `flags` parameter has the `FD_H2_FLAG_END_STREAM` flag set, which indicates the end of the stream.
    - If the end of the stream is detected, it calls [`test_response_init`](#test_response_init) to initiate a response for the stream.
- **Output**: The function does not return any value; it is a void function.
- **Functions called**:
    - [`test_response_init`](#test_response_init)


---
### cb\_rst\_stream<!-- {{#callable:cb_rst_stream}} -->
The `cb_rst_stream` function resets a stream by clearing its data and decrementing the global stream count.
- **Inputs**:
    - `conn`: A pointer to the `fd_h2_conn_t` connection object, which should match the global context connection.
    - `stream`: A pointer to the `fd_h2_stream_t` stream object, which is not used in the function.
    - `error_code`: An unsigned integer representing the error code, which is not used in the function.
    - `closed_by`: An integer indicating who closed the stream, expected to be either 0 or 1.
- **Control Flow**:
    - The function begins by asserting that the provided connection matches the global context connection.
    - It asserts that the `closed_by` parameter is either 0 or 1.
    - The function then clears the global context's stream data using `memset`.
    - Finally, it decrements the global stream count `g_stream_cnt`.
- **Output**: The function does not return any value.


---
### cb\_window\_update<!-- {{#callable:cb_window_update}} -->
The `cb_window_update` function is a placeholder callback for handling HTTP/2 window update events, but it currently performs no operations.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
    - `increment`: An unsigned integer representing the window size increment.
- **Control Flow**:
    - The function takes two parameters, `conn` and `increment`, but does not use them.
    - Both parameters are explicitly marked as unused with `(void)` casts to avoid compiler warnings.
    - The function immediately returns without performing any operations.
- **Output**: The function does not produce any output or side effects.


---
### cb\_stream\_window\_update<!-- {{#callable:cb_stream_window_update}} -->
The `cb_stream_window_update` function is a placeholder callback for handling stream window updates in an HTTP/2 connection, but it currently performs no operations.
- **Inputs**:
    - `conn`: A pointer to an `fd_h2_conn_t` structure representing the HTTP/2 connection.
    - `stream`: A pointer to an `fd_h2_stream_t` structure representing the HTTP/2 stream.
    - `increment`: An unsigned integer representing the amount by which the stream's window size should be increased.
- **Control Flow**:
    - The function takes three parameters: a connection, a stream, and an increment value.
    - All parameters are cast to void to indicate they are unused, effectively making the function a no-op.
    - The function returns immediately without performing any operations.
- **Output**: The function does not produce any output or side effects.


---
### LLVMFuzzerInitialize<!-- {{#callable:LLVMFuzzerInitialize}} -->
The `LLVMFuzzerInitialize` function initializes the environment for fuzz testing by setting environment variables, bootstrapping the system, registering a cleanup function, and configuring logging behavior.
- **Inputs**:
    - `argc`: A pointer to an integer representing the number of command-line arguments.
    - `argv`: A pointer to an array of strings representing the command-line arguments.
- **Control Flow**:
    - Set the environment variable 'FD_LOG_BACKTRACE' to '0' to disable backtraces in logs.
    - Call `fd_boot` with `argc` and `argv` to perform system initialization.
    - Register `fd_halt` to be called on program exit using `atexit`.
    - Set the core log level to 1 using `fd_log_level_core_set`, which causes the program to crash on info log messages.
    - Return 0 to indicate successful initialization.
- **Output**: The function returns an integer value of 0, indicating successful initialization.


---
### LLVMFuzzerTestOneInput<!-- {{#callable:LLVMFuzzerTestOneInput}} -->
The function `LLVMFuzzerTestOneInput` tests the HTTP/2 connection-level APIs by simulating data transmission and reception, using a fuzzing approach to identify potential issues like crashes or bugs.
- **Inputs**:
    - `data`: A pointer to an array of unsigned characters representing the input data to be fuzzed.
    - `size`: The size of the input data array, indicating how much data is available for processing.
- **Control Flow**:
    - Initialize the global context `g_ctx` to zero.
    - Check if the input size is less than 4; if so, return -1 as the input is too small to process.
    - Load a seed value from the first 4 bytes of the input data and adjust the data pointer and size accordingly.
    - Create and join a new random number generator using the seed value.
    - Initialize receive and transmit buffers (`rbuf_rx` and `rbuf_tx`) and a scratch buffer for temporary data storage.
    - Determine if the connection should be initialized as a client or server based on the seed value and set the maximum frame size.
    - Reset global counters for stream and connection finalization.
    - Enter a loop to process the input data while there is data remaining.
    - Transmit control frames using [`fd_h2_tx_control`](fd_h2_conn.c.driver.md#fd_h2_tx_control) and update the transmit buffer offsets.
    - Check if the connection is dead; if so, assert conditions and break the loop.
    - Determine the chunk size to process next, ensuring it does not exceed the receive buffer size, and push the data chunk into the receive buffer.
    - Call [`fd_h2_rx`](fd_h2_conn.c.driver.md#fd_h2_rx) to process the received data and handle it according to the HTTP/2 protocol.
    - After exiting the loop, perform a final control frame transmission.
    - Assert conditions to ensure stream and connection states are consistent.
    - Delete the random number generator and return 0 to indicate successful execution.
- **Output**: Returns 0 on successful execution, or -1 if the input size is less than 4.
- **Functions called**:
    - [`fd_h2_conn_init_server`](fd_h2_conn.c.driver.md#fd_h2_conn_init_server)
    - [`fd_h2_tx_control`](fd_h2_conn.c.driver.md#fd_h2_tx_control)
    - [`fd_h2_rbuf_used_sz`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_used_sz)
    - [`fd_h2_rbuf_push`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_push)
    - [`fd_h2_rx`](fd_h2_conn.c.driver.md#fd_h2_rx)



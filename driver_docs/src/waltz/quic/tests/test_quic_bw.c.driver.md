# Purpose
This C source code file is a test program designed to simulate and evaluate the functionality of a QUIC (Quick UDP Internet Connections) protocol implementation. The code sets up a client-server architecture using the QUIC protocol, where both the client and server are initialized with specific configurations and limits. The program includes callback functions to handle various events such as connection finalization, stream notifications, and data reception. It also incorporates network emulation features to simulate packet loss and reordering, allowing for a more comprehensive testing environment. The main function orchestrates the setup, execution, and teardown of the QUIC connections, including the creation of virtual pairs for client-server communication, the initialization of QUIC instances, and the handling of data transmission and reception.

The code is structured to provide detailed logging and metrics collection, which helps in monitoring the performance and behavior of the QUIC connections during the test. It includes mechanisms to measure data rates, packet transmission rates, and connection states, ensuring that the test results are informative and actionable. The program is designed to be executed as a standalone application, with command-line arguments allowing for customization of various parameters such as page size, page count, and network conditions. Overall, this file serves as a comprehensive test suite for validating the robustness and efficiency of a QUIC protocol implementation in a controlled environment.
# Imports and Dependencies

---
- `../fd_quic.h`
- `fd_quic_test_helpers.h`


# Global Variables

---
### conn\_final\_cnt
- **Type**: `unsigned char`
- **Description**: `conn_final_cnt` is a global variable of type `unsigned char` that is initialized to zero. It is used to keep track of the number of times the `my_conn_final` callback function is called, which indicates the finalization of a connection in the QUIC protocol.
- **Use**: This variable is incremented each time a connection is finalized, providing a count of completed connection finalizations.


---
### rx\_tot\_sz
- **Type**: `ulong`
- **Description**: `rx_tot_sz` is a global variable of type `ulong` initialized to zero. It is used to accumulate the total size of data received over a QUIC stream.
- **Use**: This variable is incremented by the size of data received in the `my_stream_rx_cb` callback function, effectively tracking the total amount of data received.


---
### server\_complete
- **Type**: `int`
- **Description**: The `server_complete` variable is a global integer initialized to 0, which is used to indicate whether the server handshake process has been completed successfully.
- **Use**: This variable is set to 1 in the `my_connection_new` function when the server handshake is complete, signaling that the server is ready for further operations.


---
### client\_complete
- **Type**: `int`
- **Description**: The `client_complete` variable is a global integer initialized to 0. It is used to indicate whether the client handshake process has been completed successfully in a QUIC (Quick UDP Internet Connections) protocol implementation.
- **Use**: This variable is set to 1 when the client handshake is complete, signaling that the client is ready for further communication.


---
### server\_conn
- **Type**: `fd_quic_conn_t *`
- **Description**: The `server_conn` is a global pointer variable of type `fd_quic_conn_t *`, initialized to `NULL`. It is intended to hold a reference to a QUIC connection object representing the server side of a QUIC connection.
- **Use**: This variable is used to store the server connection object once the server handshake is complete, allowing further operations on the server connection.


# Functions

---
### my\_conn\_final<!-- {{#callable:my_conn_final}} -->
The `my_conn_final` function increments a global counter each time it is called, indicating the finalization of a QUIC connection.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the QUIC connection being finalized.
    - `quic_ctx`: A pointer to a context object associated with the QUIC connection, which is not used in this function.
- **Control Flow**:
    - The function takes two parameters, `conn` and `quic_ctx`, but does not use them, as indicated by the casting to void.
    - The global variable `conn_final_cnt` is incremented by one each time the function is called.
- **Output**: The function does not return any value.


---
### my\_stream\_notify\_cb<!-- {{#callable:my_stream_notify_cb}} -->
The `my_stream_notify_cb` function is a placeholder callback for stream notifications in a QUIC connection, currently doing nothing with its parameters.
- **Inputs**:
    - `stream`: A pointer to an `fd_quic_stream_t` structure representing the QUIC stream associated with the notification.
    - `stream_ctx`: A void pointer to the context associated with the stream, which can be used to store user-defined data.
    - `notify_type`: An integer representing the type of notification being received for the stream.
- **Control Flow**:
    - The function takes three parameters: a stream, a stream context, and a notification type.
    - All parameters are cast to void, indicating they are unused in the current implementation.
    - The function body is empty, meaning it performs no operations or logic.
- **Output**: The function does not return any value or produce any output.


---
### my\_stream\_rx\_cb<!-- {{#callable:my_stream_rx_cb}} -->
The `my_stream_rx_cb` function updates a global counter with the size of data received on a QUIC stream and returns a success status.
- **Inputs**:
    - `conn`: A pointer to the QUIC connection associated with the stream.
    - `stream_id`: The identifier of the stream on which data is received.
    - `offset`: The offset in the stream where the data starts.
    - `data`: A pointer to the data received on the stream.
    - `data_sz`: The size of the data received.
    - `fin`: An integer indicating if this is the final data for the stream (1 if final, 0 otherwise).
- **Control Flow**:
    - The function begins by explicitly ignoring the input parameters `conn`, `stream_id`, `offset`, `data`, and `fin` using the `(void)` cast to suppress unused variable warnings.
    - The global variable `rx_tot_sz` is incremented by the size of the data received, `data_sz`.
    - The function returns the constant `FD_QUIC_SUCCESS`, indicating successful processing of the received data.
- **Output**: The function returns an integer constant `FD_QUIC_SUCCESS`, indicating successful execution.


---
### my\_connection\_new<!-- {{#callable:my_connection_new}} -->
The `my_connection_new` function logs the completion of a server handshake and updates global variables to indicate the server connection is established.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the QUIC connection.
    - `vp_context`: A void pointer to additional context, which is not used in this function.
- **Control Flow**:
    - The function begins by casting `vp_context` to void to indicate it is unused.
    - A log message is generated to indicate that the server handshake is complete.
    - The global variable `server_complete` is set to 1 to indicate the server connection is established.
    - The global variable `server_conn` is set to the `conn` parameter, storing the connection pointer for future use.
- **Output**: This function does not return any value.


---
### my\_handshake\_complete<!-- {{#callable:my_handshake_complete}} -->
The `my_handshake_complete` function logs a message indicating the completion of a client handshake and sets a flag to indicate this completion.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the QUIC connection; it is not used in the function.
    - `vp_context`: A pointer to a context object, which is not used in the function.
- **Control Flow**:
    - The function begins by casting the `conn` and `vp_context` parameters to void to indicate they are unused.
    - It logs an informational message stating 'client handshake complete'.
    - The function sets the global variable `client_complete` to 1, indicating that the client handshake process is complete.
- **Output**: The function does not return any value.


---
### service\_client<!-- {{#callable:service_client}} -->
The `service_client` function services a QUIC client by invoking the `fd_quic_service` function on the provided QUIC object.
- **Inputs**:
    - `quic`: A pointer to an `fd_quic_t` structure representing the QUIC client to be serviced.
- **Control Flow**:
    - A buffer of 16 unsigned characters is initialized to zero, and the first element is marked as unpredictable to the compiler.
    - The `fd_quic_service` function is called with the `quic` parameter to perform the servicing of the QUIC client.
    - The function returns 0, indicating successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution.


---
### service\_server<!-- {{#callable:service_server}} -->
The `service_server` function services a QUIC server by invoking the `fd_quic_service` function on the provided QUIC server object.
- **Inputs**:
    - `quic`: A pointer to an `fd_quic_t` structure representing the QUIC server to be serviced.
- **Control Flow**:
    - A buffer of 16 unsigned characters is initialized to zero, and the first element is marked as unpredictable to the compiler to prevent certain optimizations.
    - The `fd_quic_service` function is called with the `quic` parameter to perform necessary servicing operations on the QUIC server.
    - The function returns 0, indicating successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes and runs a QUIC client-server test environment, simulating network conditions and measuring performance metrics.
- **Inputs**:
    - `argc`: The number of command-line arguments.
    - `argv`: An array of command-line arguments.
- **Control Flow**:
    - Initialize the environment and QUIC test setup with `fd_boot` and [`fd_quic_test_boot`](fd_quic_test_helpers.c.driver.md#fd_quic_test_boot).
    - Create a random number generator using `fd_rng_new` and `fd_rng_join`.
    - Determine the CPU index and adjust if it exceeds the shared memory CPU count.
    - Parse command-line arguments for page size, page count, NUMA index, loss, reorder, duration, and size, with default values provided.
    - Convert the page size string to a numeric value and log an error if unsupported.
    - Create an anonymous workspace with the specified page size, count, and NUMA index.
    - Define QUIC server and client limits, including connection, stream, and buffer parameters.
    - Create and configure QUIC server and client instances with the specified limits and roles.
    - Set up callback functions for connection and stream events for both server and client.
    - Initialize a virtual pair to simulate a network connection between client and server.
    - Optionally add network emulation for loss and reorder if specified.
    - Initialize the QUIC server and client instances.
    - Establish a connection from the client to the server and verify initial conditions.
    - Run a loop to process client and server services, checking for handshake completion.
    - Verify the client connection state and attempt to send data over a new stream.
    - Enter a loop to continuously service client and server, sending data and logging performance metrics until the specified duration elapses.
    - Close the client and server connections and verify their states.
    - Run additional service loops to ensure all acknowledgments are processed.
    - Clean up resources, including virtual pair, QUIC instances, workspace, and random number generator.
    - Log a success message and halt the program.
- **Output**: The function returns an integer, specifically 0, indicating successful execution.
- **Functions called**:
    - [`fd_quic_test_boot`](fd_quic_test_helpers.c.driver.md#fd_quic_test_boot)
    - [`fd_quic_new_anonymous`](fd_quic_test_helpers.c.driver.md#fd_quic_new_anonymous)
    - [`fd_quic_virtual_pair_init`](fd_quic_test_helpers.c.driver.md#fd_quic_virtual_pair_init)
    - [`fd_quic_netem_init`](fd_quic_test_helpers.c.driver.md#fd_quic_netem_init)
    - [`service_client`](#service_client)
    - [`service_server`](#service_server)
    - [`fd_quic_virtual_pair_fini`](fd_quic_test_helpers.c.driver.md#fd_quic_virtual_pair_fini)



# Purpose
This C source code file is a test program designed to simulate and verify the functionality of a QUIC (Quick UDP Internet Connections) protocol implementation. The code sets up a virtual environment where both a QUIC server and a client are instantiated, configured, and connected to each other. The primary purpose of this file is to test the handshake process, data transmission, and connection management between the client and server using the QUIC protocol. The code includes callback functions to handle events such as new connections, stream data reception, and handshake completion, which are crucial for testing the protocol's behavior in a controlled setting.

The file is structured to initialize the necessary resources, such as random number generators and memory workspaces, and to configure the QUIC protocol parameters, including connection limits and buffer sizes. It then proceeds to create a virtual pair of QUIC instances representing the client and server, and initiates a connection between them. The test involves sending data over multiple streams and verifying the correct handling of packets and connection states. The code also includes logging and assertions to ensure that the expected protocol behavior is observed, such as successful handshakes and data integrity checks. This file is not intended to be a standalone application but rather a test harness for validating the QUIC protocol implementation within a larger software system.
# Imports and Dependencies

---
- `../fd_quic.h`
- `fd_quic_test_helpers.h`
- `../../../util/net/fd_ip4.h`
- `stdio.h`
- `stdlib.h`


# Global Variables

---
### server\_complete
- **Type**: `int`
- **Description**: The `server_complete` variable is a global integer initialized to 0, used to indicate whether the server handshake process has been completed successfully.
- **Use**: This variable is set to 1 in the `my_connection_new` callback function when the server handshake is complete.


---
### client\_complete
- **Type**: `int`
- **Description**: The `client_complete` variable is a global integer initialized to 0, used to indicate the completion status of a client's handshake process in a QUIC (Quick UDP Internet Connections) protocol implementation.
- **Use**: This variable is set to 1 when the client's handshake is complete, signaling that the client-side connection setup has been successfully finalized.


---
### server\_conn
- **Type**: `fd_quic_conn_t *`
- **Description**: The `server_conn` is a global pointer variable of type `fd_quic_conn_t *`, which is initially set to `NULL`. It is intended to hold a reference to a server-side QUIC connection once it is established.
- **Use**: This variable is used to store the server connection object when a new connection is established, allowing the server to manage and interact with the connection throughout its lifecycle.


---
### now
- **Type**: `ulong`
- **Description**: The `now` variable is a global variable of type `ulong` initialized to the value 123. It represents a mock or simulated current time value used in the context of the QUIC protocol testing.
- **Use**: This variable is used as a global clock reference in the test environment, particularly in the `test_clock` function to return the current simulated time.


# Functions

---
### my\_stream\_rx\_cb<!-- {{#callable:my_stream_rx_cb}} -->
The `my_stream_rx_cb` function processes received stream data in a QUIC connection, ensuring it meets specific conditions and logs the data.
- **Inputs**:
    - `conn`: A pointer to the QUIC connection object (`fd_quic_conn_t`) associated with the stream.
    - `stream_id`: The identifier of the stream from which data is received.
    - `offset`: The offset in the stream where the received data starts.
    - `data`: A pointer to the received data buffer.
    - `data_sz`: The size of the received data in bytes.
    - `fin`: An integer indicating if this is the final data segment of the stream (1 if final, 0 otherwise).
- **Control Flow**:
    - The function logs the stream ID, data size, and offset using a debug log.
    - It checks if the offset is aligned to 512 bytes using `FD_TEST` and `fd_ulong_is_aligned`.
    - A hex dump of the received data is logged for debugging purposes.
    - The function verifies that the data size is exactly 512 bytes using `FD_TEST`.
    - It checks that the `fin` flag is not set, indicating that this is not the final segment of the stream.
    - The function compares the first 11 bytes of the data to the string "Hello world" using `memcmp` and verifies this with `FD_TEST`.
    - If all conditions are met, the function returns `FD_QUIC_SUCCESS`.
- **Output**: The function returns `FD_QUIC_SUCCESS` if all checks pass, indicating successful processing of the stream data.


---
### my\_connection\_new<!-- {{#callable:my_connection_new}} -->
The `my_connection_new` function is a callback that marks the server handshake as complete and stores the server connection.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the server connection.
    - `vp_context`: A void pointer to additional context, which is not used in this function.
- **Control Flow**:
    - The function begins by casting `vp_context` to void to indicate it is unused.
    - A log message is generated to indicate that the server handshake is complete.
    - The global variable `server_complete` is set to 1 to mark the handshake as complete.
    - The global variable `server_conn` is set to the provided `conn` pointer, storing the server connection.
- **Output**: This function does not return any value.


---
### my\_handshake\_complete<!-- {{#callable:my_handshake_complete}} -->
The `my_handshake_complete` function logs a notice indicating that a client handshake is complete and sets a global flag to indicate this completion.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the QUIC connection; it is not used in the function.
    - `vp_context`: A void pointer to context data; it is not used in the function.
- **Control Flow**:
    - The function begins by casting the `conn` and `vp_context` parameters to void to indicate they are unused.
    - A log notice is generated with the message 'client handshake complete'.
    - The global variable `client_complete` is set to 1 to indicate that the client handshake process is complete.
- **Output**: The function does not return any value.


---
### test\_clock<!-- {{#callable:test_clock}} -->
The `test_clock` function returns the current value of a global variable `now`, which represents a mock clock time.
- **Inputs**:
    - `ctx`: A void pointer to context data, which is not used in this function.
- **Control Flow**:
    - The function takes a single argument `ctx`, which is a void pointer, and explicitly casts it to void to indicate it is unused.
    - The function returns the value of the global variable `now`.
- **Output**: The function returns an unsigned long integer representing the current mock time stored in the global variable `now`.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes and tests a QUIC (Quick UDP Internet Connections) server-client setup, simulating data transmission and verifying connection metrics.
- **Inputs**:
    - `argc`: The count of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the environment and QUIC test setup with `fd_boot` and [`fd_quic_test_boot`](fd_quic_test_helpers.c.driver.md#fd_quic_test_boot).
    - Create a random number generator using `fd_rng_new` and `fd_rng_join`.
    - Determine the CPU index and adjust if it exceeds the shared memory CPU count.
    - Parse command-line arguments for page size, page count, and NUMA index using `fd_env_strip_cmdline_cstr` and `fd_env_strip_cmdline_ulong`.
    - Convert the page size string to an actual size using `fd_cstr_to_shmem_page_sz` and log an error if unsupported.
    - Create a new anonymous workspace with `fd_wksp_new_anonymous` and verify its creation.
    - Define QUIC limits and calculate the QUIC footprint using `fd_quic_footprint`.
    - Create server and client QUIC instances with [`fd_quic_new_anonymous`](fd_quic_test_helpers.c.driver.md#fd_quic_new_anonymous) and set their configurations and callbacks.
    - Initialize a virtual pair for the server and client QUICs using [`fd_quic_virtual_pair_init`](fd_quic_test_helpers.c.driver.md#fd_quic_virtual_pair_init).
    - Initialize the QUIC instances with `fd_quic_init`.
    - Establish a client connection using `fd_quic_connect` and verify its creation.
    - Run a loop to process services and check for handshake completion, logging information and breaking if both handshakes are complete.
    - Verify connection and packet metrics for both client and server QUICs.
    - Create streams for the client connection using `fd_quic_conn_new_stream` and verify their creation.
    - Send data over the streams in a loop, alternating between streams and logging the result of each send operation.
    - Close the client and server connections using `fd_quic_conn_close`.
    - Run a loop to process services and wait for acknowledgments.
    - Verify the final connection metrics for the client QUIC.
    - Clean up resources by finalizing the virtual pair, deleting QUIC instances, and freeing the workspace and random number generator.
    - Log a final notice of passing the test and halt the QUIC test and program execution.
- **Output**: The function returns an integer, specifically 0, indicating successful execution.
- **Functions called**:
    - [`fd_quic_test_boot`](fd_quic_test_helpers.c.driver.md#fd_quic_test_boot)
    - [`fd_quic_new_anonymous`](fd_quic_test_helpers.c.driver.md#fd_quic_new_anonymous)
    - [`fd_quic_virtual_pair_init`](fd_quic_test_helpers.c.driver.md#fd_quic_virtual_pair_init)
    - [`fd_quic_virtual_pair_fini`](fd_quic_test_helpers.c.driver.md#fd_quic_virtual_pair_fini)
    - [`fd_quic_test_halt`](fd_quic_test_helpers.c.driver.md#fd_quic_test_halt)



# Purpose
This C source code file is a test program designed to repeatedly open and close QUIC (Quick UDP Internet Connections) connections, simulating client-server interactions. The code is structured to create both a client and a server QUIC instance, configure them with specific connection and stream limits, and then establish a virtual pair to facilitate communication between the two. The main functionality revolves around testing the handshake process, data transmission, and connection lifecycle management, including opening new connections, sending data, and closing connections. The program logs various stages of the connection process, such as handshake completion and data reception, and verifies the integrity of the data received.

The code is primarily focused on testing and validating the QUIC protocol's implementation, using callbacks to handle events like stream reception and connection finalization. It includes a main function that initializes the environment, sets up the QUIC instances, and enters a loop to manage the connection state and data transmission. The program uses helper functions and structures to manage the context and state of connections, ensuring that the client and server can repeatedly establish and tear down connections while logging the process. This file is not intended to be a reusable library but rather a standalone executable for testing purposes, as indicated by the presence of a [`main`](#main) function and the use of test-specific logging and validation mechanisms.
# Imports and Dependencies

---
- `../fd_quic.h`
- `fd_quic_test_helpers.h`


# Global Variables

---
### state
- **Type**: `int`
- **Description**: The `state` variable is a global integer used to track the current state of the QUIC connection process in the test program. It is initialized to 0 and is used to control the flow of the connection setup and teardown logic.
- **Use**: This variable is used in a switch statement within the main loop to determine the actions to be taken for managing QUIC connections, such as starting a new connection or handling connection closure.


---
### server\_complete
- **Type**: `int`
- **Description**: The `server_complete` variable is a global integer initialized to 0, used to indicate whether the server handshake process has been completed in a QUIC connection test.
- **Use**: This variable is set to 1 when the server handshake is successfully completed, signaling that the server is ready for further communication.


---
### client\_complete
- **Type**: `int`
- **Description**: The `client_complete` variable is a global integer initialized to 0, used to indicate the completion status of a client's handshake in a QUIC connection test.
- **Use**: This variable is set to 1 when the client's handshake is successfully completed, signaling that the client is ready for further communication.


---
### server\_conn
- **Type**: `fd_quic_conn_t *`
- **Description**: The `server_conn` is a global pointer variable of type `fd_quic_conn_t`, which is used to store the reference to a QUIC connection on the server side. It is initialized to `NULL` and is set when a new server connection is established.
- **Use**: This variable is used to keep track of the current server-side QUIC connection, allowing the program to manage and close the connection as needed.


---
### client\_conn
- **Type**: `fd_quic_conn_t *`
- **Description**: The `client_conn` is a global pointer variable of type `fd_quic_conn_t *`, which is used to manage the client-side QUIC connection in the program. It is initially set to `NULL` and is later assigned a connection object when a new client connection is established.
- **Use**: This variable is used to track and manage the state of the client-side QUIC connection throughout the program, including establishing new connections and closing them when necessary.


---
### pkt\_full
- **Type**: `uchar[]`
- **Description**: `pkt_full` is an external array of unsigned characters, which is likely used to store a complete packet of data for processing or transmission in the QUIC protocol context.
- **Use**: This variable is used to hold the full packet data that is processed or transmitted in the QUIC connection operations.


---
### pkt\_full\_sz
- **Type**: `ulong`
- **Description**: The `pkt_full_sz` is a global variable of type `ulong` that represents the size of the packet data stored in the `pkt_full` array. It is declared as an external variable, indicating that its definition is located in another source file.
- **Use**: This variable is used to determine the size of the packet data for operations involving the `pkt_full` array.


---
### fail
- **Type**: `uchar`
- **Description**: The `fail` variable is a global variable of type `uchar` (unsigned char) initialized to 0. It is used to indicate whether a failure condition has been encountered during the execution of the program.
- **Use**: This variable is set to 1 when a failure condition is detected, such as when received data does not match expected values, and it is used to track the occurrence of such failures.


---
### \_recv
- **Type**: `ulong`
- **Description**: The `_recv` variable is a static global variable of type `ulong` that is initialized to zero. It is used to keep track of the number of successful data receptions in the `my_stream_rx_cb` callback function.
- **Use**: This variable is incremented each time a data packet is successfully received and validated in the `my_stream_rx_cb` function.


---
### now
- **Type**: `ulong`
- **Description**: The `now` variable is a global variable of type `ulong` initialized to a value of 1e18. It represents a simulated clock or timestamp used in the context of the QUIC connection tests.
- **Use**: The `now` variable is used to simulate the passage of time in the test environment, being incremented in a loop to drive the QUIC connection operations.


# Data Structures

---
### my\_context
- **Type**: `struct`
- **Members**:
    - `server`: An integer representing the server state or identifier within the context.
- **Description**: The `my_context` structure is a simple data structure that contains a single integer member named `server`. This structure is used to encapsulate context information related to a server, potentially serving as a placeholder for more complex context data in a larger application. The typedef `my_context_t` is provided for convenience, allowing the structure to be referenced with a shorter name.


---
### my\_context\_t
- **Type**: `struct`
- **Members**:
    - `server`: An integer representing the server state or identifier.
- **Description**: The `my_context_t` structure is a simple data structure that contains a single integer member named `server`. This structure is likely used to store context information related to a server, such as its state or an identifier, within the context of QUIC (Quick UDP Internet Connections) operations. The structure is defined as a typedef of `struct my_context`, allowing it to be used with the alias `my_context_t` for convenience in the code.


# Functions

---
### my\_stream\_rx\_cb<!-- {{#callable:my_stream_rx_cb}} -->
The `my_stream_rx_cb` function processes received data on a QUIC stream, checking for expected data size and content, and logs the results.
- **Inputs**:
    - `conn`: A pointer to the QUIC connection associated with the stream.
    - `stream_id`: The identifier of the stream on which data is received.
    - `offset`: The offset in the stream where the data starts.
    - `data`: A pointer to the received data buffer.
    - `data_sz`: The size of the received data in bytes.
    - `fin`: An integer indicating if this is the final data chunk (fin flag).
- **Control Flow**:
    - The function begins by logging the size and offset of the received data.
    - It performs a hex dump of the received data for debugging purposes.
    - The function checks if the size of the received data is 512 bytes; if not, it logs a warning, sets a failure flag, and returns success.
    - It then checks if the first 11 bytes of the data match the string 'Hello world'; if not, it logs a warning, sets a failure flag, and returns success.
    - If both checks pass, it logs a debug message indicating successful reception.
    - The function increments a global counter `_recv` to track the number of successful receptions.
    - Finally, it returns `FD_QUIC_SUCCESS` to indicate successful processing of the data.
- **Output**: The function returns `FD_QUIC_SUCCESS` to indicate successful processing of the received data, regardless of whether the data was valid or not.


---
### my\_cb\_conn\_final<!-- {{#callable:my_cb_conn_final}} -->
The `my_cb_conn_final` function handles the finalization of a QUIC connection by logging the success or failure of the operation and nullifying the connection context if successful.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the QUIC connection to be finalized.
    - `context`: A void pointer to additional context data, which is not used in this function.
- **Control Flow**:
    - The function begins by casting the `context` to void to indicate it is unused.
    - It retrieves a pointer to a pointer to the connection (`ppconn`) from the `context` field of the `conn` structure.
    - If `ppconn` is not NULL, it logs a success message and sets the dereferenced pointer to NULL, indicating the connection has been finalized.
    - If `ppconn` is NULL, it logs a warning message indicating the finalization failed.
- **Output**: The function does not return a value; it performs logging and modifies the connection context as a side effect.


---
### my\_connection\_new<!-- {{#callable:my_connection_new}} -->
The `my_connection_new` function is a callback that handles the completion of a server-side QUIC connection handshake by setting the connection context and updating the server state.
- **Inputs**:
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection that has completed the handshake.
    - `vp_context`: A void pointer to additional context data, which is not used in this function.
- **Control Flow**:
    - The function begins by casting `vp_context` to void to indicate it is unused.
    - Logs the message 'server handshake complete' to indicate the server-side handshake has been completed.
    - Sets the global variable `server_complete` to 1, marking the server handshake as complete.
    - Assigns the `conn` pointer to the global variable `server_conn`, storing the connection for future reference.
    - Calls `fd_quic_conn_set_context` to associate the `server_conn` pointer with the connection's context.
- **Output**: This function does not return any value; it operates by side effects on global variables and the connection context.


---
### my\_handshake\_complete<!-- {{#callable:my_handshake_complete}} -->
The `my_handshake_complete` function logs the completion of a client handshake, sets a global flag indicating the handshake is complete, and associates the connection with a global client connection pointer.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the QUIC connection for which the handshake has completed.
    - `vp_context`: A void pointer to additional context, which is not used in this function.
- **Control Flow**:
    - The function begins by casting `vp_context` to void to indicate it is unused.
    - A log message is generated to indicate that the client handshake is complete.
    - The global variable `client_complete` is set to 1, marking the handshake as complete.
    - The function `fd_quic_conn_set_context` is called to associate the connection `conn` with the global pointer `client_conn`.
- **Output**: The function does not return any value; it performs logging and updates global state.


---
### test\_clock<!-- {{#callable:test_clock}} -->
The `test_clock` function returns the current value of a global clock variable `now`.
- **Inputs**:
    - `ctx`: A void pointer to context data, which is not used in this function.
- **Control Flow**:
    - The function takes a single argument `ctx`, which is cast to void to indicate it is unused.
    - The function returns the value of the global variable `now`.
- **Output**: The function returns an unsigned long integer representing the current time from the global variable `now`.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes and tests QUIC connections by repeatedly opening and closing them, simulating client-server communication, and logging the process.
- **Inputs**:
    - `argc`: The number of command-line arguments.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the environment and QUIC test framework with `fd_boot` and [`fd_quic_test_boot`](fd_quic_test_helpers.c.driver.md#fd_quic_test_boot).
    - Create a random number generator using `fd_rng_new` and `fd_rng_join`.
    - Determine the CPU index and adjust if it exceeds the shared memory CPU count.
    - Parse command-line arguments for page size, page count, and NUMA index using `fd_env_strip_cmdline_cstr` and `fd_env_strip_cmdline_ulong`.
    - Convert the page size string to an actual size using `fd_cstr_to_shmem_page_sz` and log an error if unsupported.
    - Create a workspace with `fd_wksp_new_anonymous` and verify its creation.
    - Define QUIC limits and calculate the QUIC footprint using `fd_quic_footprint`.
    - Create server and client QUIC instances with [`fd_quic_new_anonymous`](fd_quic_test_helpers.c.driver.md#fd_quic_new_anonymous) and set their callbacks.
    - Initialize a virtual pair for the QUIC instances using [`fd_quic_virtual_pair_init`](fd_quic_test_helpers.c.driver.md#fd_quic_virtual_pair_init).
    - Initialize the QUIC instances with `fd_quic_init`.
    - Enter a loop to simulate sending data over QUIC connections, handling connection states and logging progress.
    - Close any remaining connections and log their status.
    - Clean up resources by finalizing the virtual pair, deleting QUIC instances, and freeing the workspace.
    - Log the completion of the test and halt the environment.
- **Output**: The function returns an integer, specifically 0, indicating successful execution.
- **Functions called**:
    - [`fd_quic_test_boot`](fd_quic_test_helpers.c.driver.md#fd_quic_test_boot)
    - [`fd_quic_new_anonymous`](fd_quic_test_helpers.c.driver.md#fd_quic_new_anonymous)
    - [`fd_quic_virtual_pair_init`](fd_quic_test_helpers.c.driver.md#fd_quic_virtual_pair_init)
    - [`fd_quic_virtual_pair_fini`](fd_quic_test_helpers.c.driver.md#fd_quic_virtual_pair_fini)
    - [`fd_quic_test_halt`](fd_quic_test_helpers.c.driver.md#fd_quic_test_halt)



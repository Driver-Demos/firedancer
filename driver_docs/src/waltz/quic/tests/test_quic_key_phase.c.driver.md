# Purpose
This C source code file is a test program designed to evaluate the functionality of a QUIC (Quick UDP Internet Connections) protocol implementation. The code sets up a client-server architecture using QUIC, where both the client and server are simulated within the same program. The primary focus of the test is to verify the handling of key phase changes during the QUIC connection, which is a critical aspect of maintaining secure communication. The program defines several constants and variables to track the number of streams and key phase changes, and it uses callback functions to handle events such as connection establishment, stream reception, and connection finalization.

The code utilizes a fibre-based concurrency model to simulate asynchronous operations for both the client and server. It initializes QUIC configurations for both roles, sets up the necessary callbacks, and manages the lifecycle of the connections. The test involves sending a predefined number of streams and forcing key phase changes to ensure the QUIC implementation correctly handles these transitions. The program logs various events, such as connection establishment and key phase changes, to provide insights into the test's progress and outcomes. The use of a virtual pair to connect the client and server QUIC instances allows for a controlled testing environment, ensuring that the QUIC protocol's behavior can be thoroughly evaluated.
# Imports and Dependencies

---
- `../fd_quic.h`
- `fd_quic_test_helpers.h`
- `../../../util/fibre/fd_fibre.h`
- `stdlib.h`


# Global Variables

---
### client\_done
- **Type**: `int`
- **Description**: The `client_done` variable is a static integer flag used to indicate the completion status of the client operations in the program. It is initialized to 0, representing that the client operations are not yet complete.
- **Use**: The `client_done` variable is used within the `client_fibre_fn` function to control the execution loop, terminating the loop when the client operations are complete.


---
### server\_done
- **Type**: `int`
- **Description**: The `server_done` variable is a static integer initialized to 0, indicating that the server process is not yet complete. It is used as a flag to control the execution flow of the server fibre function.
- **Use**: This variable is used to signal when the server should stop its operations and terminate its fibre execution.


---
### rcvd
- **Type**: `ulong`
- **Description**: The `rcvd` variable is a static unsigned long integer that keeps track of the number of streams received in the current key phase. It is initialized to zero and is incremented each time a stream is received.
- **Use**: This variable is used to monitor the number of streams received and trigger a key phase change when a predefined number of streams have been received.


---
### tot\_rcvd
- **Type**: `ulong`
- **Description**: The `tot_rcvd` variable is a static global variable of type `ulong` that is used to keep track of the total number of data streams received during the execution of the program. It is initialized to zero and incremented each time a stream is received.
- **Use**: `tot_rcvd` is used to accumulate the total count of received streams across the entire program execution.


---
### tot\_key\_phase\_change
- **Type**: `ulong`
- **Description**: The `tot_key_phase_change` is a static global variable of type `ulong` that is initialized to zero. It is used to keep track of the total number of key phase changes that have occurred during the execution of the program.
- **Use**: This variable is incremented each time a key phase change is detected in the client connection, and it is used to determine when the client has completed the required number of key phase changes.


---
### client\_fibre
- **Type**: `fd_fibre_t *`
- **Description**: The `client_fibre` is a static pointer to an `fd_fibre_t` structure, which represents a fibre (lightweight thread) used for the client-side operations in a QUIC (Quick UDP Internet Connections) protocol test. It is initialized to `NULL` and later assigned a fibre instance that executes the `client_fibre_fn` function, which handles client-side QUIC operations such as establishing connections, sending data, and managing key phase changes.
- **Use**: `client_fibre` is used to manage and execute client-side operations in a QUIC protocol test by running the `client_fibre_fn` function.


---
### server\_fibre
- **Type**: `fd_fibre_t *`
- **Description**: The `server_fibre` is a static pointer to an `fd_fibre_t` structure, initialized to `NULL`. It represents a fibre, which is a lightweight thread of execution, specifically for the server side of a QUIC (Quick UDP Internet Connections) protocol implementation.
- **Use**: This variable is used to manage and execute the server's fibre function, `server_fibre_fn`, which handles server-side operations in the QUIC protocol test.


---
### server\_complete
- **Type**: `int`
- **Description**: The `server_complete` variable is a static integer that serves as a flag to indicate whether the server's handshake process has been completed. It is initialized to 0, representing an incomplete state, and is set to 1 when the server successfully completes the handshake with a client.
- **Use**: This variable is used to track the completion status of the server's handshake process in the QUIC protocol implementation.


---
### client\_complete
- **Type**: `int`
- **Description**: The `client_complete` variable is a static integer that serves as a flag to indicate whether the client-side handshake process has been completed successfully in a QUIC (Quick UDP Internet Connections) protocol implementation.
- **Use**: This variable is set to 1 when the client handshake is complete, signaling that the client is ready for further communication.


---
### server\_conn
- **Type**: `fd_quic_conn_t*`
- **Description**: The `server_conn` is a global pointer variable of type `fd_quic_conn_t*`, which is used to store a reference to a QUIC connection on the server side. It is initially set to `NULL` and is assigned a value when a new connection is established on the server.
- **Use**: This variable is used to track the active QUIC connection on the server, allowing the server to manage and interact with the connection during its lifecycle.


---
### now
- **Type**: `ulong`
- **Description**: The `now` variable is a static global variable of type `ulong` initialized to a value of 1e18. It represents a global 'clock' used throughout the program to simulate or track time.
- **Use**: The `now` variable is used to provide a consistent time reference for various operations, such as scheduling and timing in the QUIC protocol simulation.


# Data Structures

---
### my\_context
- **Type**: `struct`
- **Members**:
    - `server`: An integer representing the server context or identifier.
- **Description**: The `my_context` structure is a simple data structure that contains a single integer member named `server`. This structure is used to encapsulate server-related context or identifiers, potentially for use in network communication or server management tasks. The typedef `my_context_t` is provided for convenience, allowing the structure to be referred to with a shorter name in the code.


---
### my\_context\_t
- **Type**: `struct`
- **Members**:
    - `server`: An integer flag indicating whether the context is for a server.
- **Description**: The `my_context_t` structure is a simple data structure that contains a single integer member named `server`. This member is used as a flag to indicate whether the context is associated with a server. The structure is likely used in the context of managing connections or operations that differentiate between client and server roles in a network communication setup.


---
### client\_args
- **Type**: `struct`
- **Members**:
    - `quic`: A pointer to an fd_quic_t structure representing the client's QUIC instance.
    - `server_quic`: A pointer to an fd_quic_t structure representing the server's QUIC instance.
- **Description**: The `client_args` structure is used to encapsulate the arguments required for a client in a QUIC (Quick UDP Internet Connections) communication setup. It contains pointers to two `fd_quic_t` structures: one for the client's QUIC instance and another for the server's QUIC instance. This structure is likely used to pass these instances to functions that manage or utilize the client-server communication over QUIC.


---
### client\_args\_t
- **Type**: `struct`
- **Members**:
    - `quic`: A pointer to an fd_quic_t structure representing the client's QUIC instance.
    - `server_quic`: A pointer to an fd_quic_t structure representing the server's QUIC instance.
- **Description**: The `client_args_t` structure is used to encapsulate the arguments required for the client-side operations in a QUIC (Quick UDP Internet Connections) communication setup. It contains pointers to two `fd_quic_t` structures, one for the client and one for the server, allowing the client to manage and interact with both its own and the server's QUIC instances. This structure is essential for initializing and running the client-side fibre function, which handles the sending and receiving of data streams over the QUIC protocol.


---
### server\_args
- **Type**: `struct`
- **Members**:
    - `quic`: A pointer to an fd_quic_t structure, representing the QUIC protocol instance associated with the server.
- **Description**: The `server_args` structure is a simple data structure used to encapsulate arguments for server operations in a QUIC protocol context. It contains a single member, `quic`, which is a pointer to an `fd_quic_t` structure. This pointer is used to reference the QUIC protocol instance that the server will use for its operations, such as handling connections and managing data streams. The `server_args` structure is typically used to pass server-specific configuration or state information to functions or threads that perform server-related tasks.


---
### server\_args\_t
- **Type**: `typedef struct`
- **Members**:
    - `quic`: A pointer to an fd_quic_t structure representing the QUIC server instance.
- **Description**: The `server_args_t` structure is used to encapsulate the arguments required for the server fiber function in a QUIC (Quick UDP Internet Connections) test setup. It contains a single member, `quic`, which is a pointer to an `fd_quic_t` structure representing the server's QUIC instance. This structure is used to pass the server's QUIC context to the server fiber function, allowing it to perform operations such as servicing the QUIC connection and handling key phase changes.


# Functions

---
### my\_stream\_rx\_cb<!-- {{#callable:my_stream_rx_cb}} -->
The `my_stream_rx_cb` function is a callback that increments counters for received data on a QUIC stream and returns a success status.
- **Inputs**:
    - `conn`: A pointer to the QUIC connection object associated with the stream.
    - `stream_id`: The identifier of the stream on which data is received.
    - `offset`: The offset in the stream where the data starts.
    - `data`: A pointer to the data received on the stream.
    - `data_sz`: The size of the data received.
    - `fin`: An integer indicating if this is the final data for the stream (1 if final, 0 otherwise).
- **Control Flow**:
    - The function begins by casting all input parameters to void to indicate they are unused.
    - It increments the global `rcvd` counter to track the number of received data events.
    - It increments the global `tot_rcvd` counter to track the total number of received data events across all streams.
    - The function returns `FD_QUIC_SUCCESS` to indicate successful processing of the received data.
- **Output**: The function returns an integer `FD_QUIC_SUCCESS` to indicate successful handling of the received data.


---
### my\_cb\_conn\_final<!-- {{#callable:my_cb_conn_final}} -->
The `my_cb_conn_final` function finalizes a QUIC connection by logging its success and nullifying its context pointer.
- **Inputs**:
    - `conn`: A pointer to the QUIC connection (`fd_quic_conn_t`) that is being finalized.
    - `context`: A void pointer to additional context data, which is not used in this function.
- **Control Flow**:
    - The function casts the context of the connection to a double pointer to `fd_quic_conn_t` using `fd_quic_conn_get_context`.
    - It checks if the context pointer (`ppconn`) is not NULL.
    - If `ppconn` is valid, it logs a success message with the connection pointer and sets the dereferenced pointer to NULL, effectively nullifying the context.
- **Output**: The function does not return any value; it performs logging and modifies the connection context.


---
### my\_connection\_new<!-- {{#callable:my_connection_new}} -->
The `my_connection_new` function handles the event of a new QUIC connection being established on the server side, logging the handshake completion and updating the server connection state.
- **Inputs**:
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the new QUIC connection.
    - `vp_context`: A void pointer to additional context, which is not used in this function.
- **Control Flow**:
    - The function logs a message indicating that the server handshake is complete.
    - It sets the `server_complete` flag to 1, indicating that the server has completed the handshake process.
    - The function checks if `server_conn` is already set, which would indicate an unexpected new connection, and logs an error if so.
    - It assigns the new connection (`conn`) to the `server_conn` global variable.
- **Output**: This function does not return any value; it modifies global state and logs messages.


---
### my\_handshake\_complete<!-- {{#callable:my_handshake_complete}} -->
The `my_handshake_complete` function logs a message indicating that the client's handshake is complete and sets a flag to indicate this completion.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the QUIC connection.
    - `vp_context`: A void pointer to additional context, which is not used in this function.
- **Control Flow**:
    - The function begins by casting the input parameters `conn` and `vp_context` to void to indicate they are unused.
    - It logs an informational message stating 'CLIENT - handshake complete'.
    - The function sets the global variable `client_complete` to 1, indicating that the client's handshake process is complete.
- **Output**: The function does not return any value; it performs logging and sets a global flag.


---
### test\_clock<!-- {{#callable:test_clock}} -->
The `test_clock` function returns the current value of a global variable `now`, which represents a simulated clock time.
- **Inputs**:
    - `ctx`: A void pointer to context data, which is not used in this function.
- **Control Flow**:
    - The function takes a single argument `ctx`, which is cast to void to indicate it is unused.
    - The function returns the value of the global variable `now`.
- **Output**: The function returns an unsigned long integer representing the current simulated time.


---
### test\_fibre\_clock<!-- {{#callable:test_fibre_clock}} -->
The `test_fibre_clock` function returns the current value of the global variable `now` cast to a long integer.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of the global variable `now` cast to a long integer without any additional logic or branching.
- **Output**: The function outputs the current value of the global variable `now` as a long integer.


---
### client\_fibre\_fn<!-- {{#callable:client_fibre_fn}} -->
The `client_fibre_fn` function manages a QUIC client connection, sending data streams and handling key phase changes until a specified number of key phase changes are completed.
- **Inputs**:
    - `vp_arg`: A void pointer to a `client_args_t` structure containing the QUIC client and server instances.
- **Control Flow**:
    - Cast the `vp_arg` to a `client_args_t` pointer to access the client QUIC instance.
    - Initialize connection and stream pointers, and set up a buffer with the message 'Hello World!'.
    - Attempt to establish a QUIC connection using `fd_quic_connect`; log an error if unsuccessful.
    - Set the connection context and wait for the connection to become active by repeatedly calling `fd_quic_service` and `fd_fibre_wait_until`.
    - Once active, log the connection establishment and enter a loop that continues until `client_done` is set to 1.
    - Within the loop, wait until the next service or send time, then service the QUIC connection.
    - Check for unexpected connection termination and log key phase changes, incrementing the total key phase change count.
    - If the number of received streams equals `NUM_STREAMS`, log the event, reset the count, and force a key update.
    - If no stream is available, attempt to create a new one; if unsuccessful, continue the loop.
    - If the current time is past the next send time, send the buffer over the stream and handle the result, logging a warning if the send fails.
    - After exiting the loop, close the connection and continue servicing until the connection is fully closed.
    - Set `server_done` to 1 to signal the server to shut down.
- **Output**: The function does not return a value; it operates as a fibre to manage the client-side QUIC connection and communication.


---
### server\_fibre\_fn<!-- {{#callable:server_fibre_fn}} -->
The `server_fibre_fn` function manages a server's QUIC connection, tracking key phase changes and ensuring periodic wake-ups to service the connection.
- **Inputs**:
    - `vp_arg`: A void pointer to a `server_args_t` structure containing the QUIC server instance to be serviced.
- **Control Flow**:
    - Cast the `vp_arg` to a `server_args_t` pointer to access the server's QUIC instance.
    - Initialize `last_key_phase` to an invalid value to track key phase changes.
    - Set a periodic wake-up interval of 1 millisecond.
    - Enter a loop that continues until `server_done` is set to true.
    - Within the loop, call `fd_quic_service` to service the QUIC instance.
    - Check if a server connection exists (`server_conn`).
    - If `last_key_phase` is uninitialized, set it to the current key phase and log the connection establishment.
    - If the key phase has changed, log the new key phase and update `last_key_phase`.
    - Calculate the next wake-up time as the minimum of the next QUIC wake-up and the periodic interval.
    - Call `fd_fibre_wait_until` to pause execution until the calculated wake-up time.
- **Output**: The function does not return a value; it operates in a loop to manage the server's QUIC connection and log key phase changes.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes and runs a QUIC client-server test using fibers, handling key phase changes and cleaning up resources upon completion.
- **Inputs**:
    - `argc`: The number of command-line arguments.
    - `argv`: An array of command-line argument strings.
- **Control Flow**:
    - Initialize the environment and QUIC test framework with `fd_boot` and [`fd_quic_test_boot`](fd_quic_test_helpers.c.driver.md#fd_quic_test_boot).
    - Create a random number generator using `fd_rng_new` and `fd_rng_join`.
    - Determine the CPU index and adjust if it exceeds the shared memory CPU count.
    - Parse command-line arguments for page size, page count, and NUMA index using `fd_env_strip_cmdline_cstr` and `fd_env_strip_cmdline_ulong`.
    - Convert the page size string to a numeric value with `fd_cstr_to_shmem_page_sz` and log an error if unsupported.
    - Create an anonymous workspace with `fd_wksp_new_anonymous` and verify its creation with `FD_TEST`.
    - Define server and client QUIC limits and create QUIC instances using [`fd_quic_new_anonymous`](fd_quic_test_helpers.c.driver.md#fd_quic_new_anonymous), verifying each with `FD_TEST`.
    - Set callback functions for client and server QUICs, including connection and stream handling callbacks.
    - Initialize a virtual pair for the client and server QUICs using [`fd_quic_virtual_pair_init`](fd_quic_test_helpers.c.driver.md#fd_quic_virtual_pair_init).
    - Initialize the QUIC instances with `fd_quic_init` and verify success with `FD_TEST`.
    - Allocate memory for and initialize fibers using `fd_wksp_alloc_laddr` and `fd_fibre_init`.
    - Set the fiber scheduler clock with `fd_fibre_set_clock`.
    - Create and start fibers for the client and server using `fd_fibre_start`, passing necessary arguments, and verify with `FD_TEST`.
    - Schedule the client and server fibers with `fd_fibre_schedule`.
    - Run the fiber scheduler loop with `fd_fibre_schedule_run` until a negative timeout indicates completion.
    - Log the number of key updates passed and begin cleanup.
    - Finalize the virtual pair with [`fd_quic_virtual_pair_fini`](fd_quic_test_helpers.c.driver.md#fd_quic_virtual_pair_fini) and free resources associated with QUIC instances and the workspace.
    - Delete the random number generator and halt the test framework with [`fd_quic_test_halt`](fd_quic_test_helpers.c.driver.md#fd_quic_test_halt) and `fd_halt`.
- **Output**: The function returns an integer status code, 0 on successful completion.
- **Functions called**:
    - [`fd_quic_test_boot`](fd_quic_test_helpers.c.driver.md#fd_quic_test_boot)
    - [`fd_quic_new_anonymous`](fd_quic_test_helpers.c.driver.md#fd_quic_new_anonymous)
    - [`fd_quic_virtual_pair_init`](fd_quic_test_helpers.c.driver.md#fd_quic_virtual_pair_init)
    - [`fd_quic_virtual_pair_fini`](fd_quic_test_helpers.c.driver.md#fd_quic_virtual_pair_fini)
    - [`fd_quic_test_halt`](fd_quic_test_helpers.c.driver.md#fd_quic_test_halt)



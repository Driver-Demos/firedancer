# Purpose
This C source code file is a test program designed to evaluate the functionality of a QUIC (Quick UDP Internet Connections) protocol implementation. The code sets up a client-server architecture using QUIC, where both the client and server are simulated within the same program. The primary purpose of this file is to test the transmission and reception of data streams over a QUIC connection, ensuring that the protocol's handshake, data transfer, and connection management processes are functioning correctly. The code includes the setup of virtual network conditions, such as packet loss, to simulate real-world network environments and assess the robustness of the QUIC implementation.

The file is structured around several key components: initialization of QUIC contexts for both client and server roles, definition of callback functions for handling connection events and data reception, and the use of fibers to manage concurrent execution of client and server logic. The program uses a test clock to simulate time progression and schedules fibers to run the client and server tasks. The main function orchestrates the setup, execution, and cleanup of the test environment, including memory management and logging of test results. This code is not intended to be a reusable library but rather a standalone executable for testing purposes, as indicated by the presence of a [`main`](#main) function and the absence of public APIs or external interfaces.
# Imports and Dependencies

---
- `../fd_quic.h`
- `fd_quic_test_helpers.h`
- `../../../util/rng/fd_rng.h`
- `../../../util/fibre/fd_fibre.h`
- `stdlib.h`


# Global Variables

---
### client\_done
- **Type**: `int`
- **Description**: The `client_done` variable is a global integer flag used to indicate the completion status of the client operations in the program. It is initialized to 0, representing that the client is not done, and is set to 1 when the client has completed its tasks, specifically when the total number of streams received equals the defined number of streams (`NUM_STREAMS`).
- **Use**: This variable is used in the client fiber function to control the execution loop, allowing the client to continue processing until all streams have been received.


---
### server\_done
- **Type**: `int`
- **Description**: The `server_done` variable is a global integer flag used to indicate the completion status of the server operations in the program. It is initialized to 0, representing that the server is not done.
- **Use**: The `server_done` variable is used in the `server_fibre_fn` function to control the server's main loop, allowing it to continue processing until the flag is set to 1, indicating that the server should shut down.


---
### rcvd
- **Type**: `ulong`
- **Description**: The `rcvd` variable is a global variable of type `ulong` that is used to keep track of the number of data fragments received by the client in a QUIC (Quick UDP Internet Connections) communication setup.
- **Use**: It is incremented each time a data fragment is successfully received by the client, helping to monitor the progress of data reception.


---
### tot\_rcvd
- **Type**: `ulong`
- **Description**: The `tot_rcvd` variable is a global variable of type `ulong` that is initialized to zero. It is used to keep track of the total number of data stream fragments received during the execution of the program.
- **Use**: `tot_rcvd` is incremented each time a data stream fragment is received, and it is used to determine when the client has received the expected number of streams, signaling completion.


---
### client\_fibre
- **Type**: `fd_fibre_t *`
- **Description**: The `client_fibre` is a global pointer variable of type `fd_fibre_t *`, which is used to manage a fibre (lightweight thread) for the client in a QUIC (Quick UDP Internet Connections) communication setup. It is initialized to `NULL` and later assigned a fibre instance that executes the `client_fibre_fn` function, which handles client-side operations such as establishing connections and sending data streams.
- **Use**: This variable is used to store and manage the client-side fibre, allowing it to be scheduled and executed within the fibre scheduling system.


---
### server\_fibre
- **Type**: `fd_fibre_t *`
- **Description**: The `server_fibre` is a global pointer variable of type `fd_fibre_t *`, which is initialized to `NULL`. It is intended to represent a fibre (lightweight thread) associated with the server in a fibre-based concurrency model.
- **Use**: This variable is used to manage and execute server-related tasks within a fibre, allowing the server to perform operations concurrently with other fibres.


---
### net\_fibre
- **Type**: `fd_fibre_t *`
- **Description**: The `net_fibre` is a global pointer to an `fd_fibre_t` structure, which is initially set to `NULL`. This variable is intended to represent a 'network' fibre used for operations such as dropping and packet capturing (pcapping) within the context of the program.
- **Use**: `net_fibre` is used to manage network-related fibre operations, although its specific usage is not detailed in the provided code.


---
### state
- **Type**: `int`
- **Description**: The `state` variable is a global integer initialized to 0. It is likely used to track the current state or status of a process or operation within the program.
- **Use**: This variable is used to store and track the state of a process, potentially being updated as the process progresses.


---
### server\_complete
- **Type**: `int`
- **Description**: The `server_complete` variable is a global integer flag used to indicate the completion of a server-side operation, specifically the completion of a server handshake in a QUIC (Quick UDP Internet Connections) protocol context. It is initialized to 0 and set to 1 when the server handshake is complete.
- **Use**: This variable is used to signal that the server has successfully completed its handshake process.


---
### client\_complete
- **Type**: `int`
- **Description**: The `client_complete` variable is a global integer initialized to 0, which is used to indicate whether the client-side operations in a QUIC (Quick UDP Internet Connections) protocol test have been completed successfully.
- **Use**: This variable is set to 1 when the client handshake is complete, signaling that the client has finished its operations.


---
### pkt\_full
- **Type**: `uchar[]`
- **Description**: `pkt_full` is an external array of unsigned characters (`uchar`) that is declared but not defined in the provided code. It is likely used to store a complete packet of data for network communication or testing purposes.
- **Use**: This variable is used to hold a full packet of data, potentially for transmission or processing in the context of the QUIC protocol.


---
### pkt\_full\_sz
- **Type**: `ulong`
- **Description**: The `pkt_full_sz` is a global variable of type `ulong` that represents the size of a packet. It is declared as an external variable, indicating that its definition is located in another file, and it is used in conjunction with the `pkt_full` array, which likely holds the packet data.
- **Use**: This variable is used to store the size of the packet data contained in the `pkt_full` array, facilitating operations that require knowledge of the packet's size.


---
### fail
- **Type**: `uchar`
- **Description**: The `fail` variable is a global variable of type `uchar` (unsigned char) initialized to 0. It is used to track failure states or conditions in the program.
- **Use**: This variable is used to indicate whether a failure has occurred during the execution of the program, although its specific usage is not detailed in the provided code.


---
### conn\_final\_cnt
- **Type**: `ulong`
- **Description**: `conn_final_cnt` is a static global variable of type `ulong` that keeps track of the number of finalized connections in the QUIC protocol implementation. It is incremented each time a connection reaches its final state, as indicated by the `my_cb_conn_final` callback function.
- **Use**: This variable is used to count and log the total number of connections that have been finalized during the execution of the program.


---
### now
- **Type**: `ulong`
- **Description**: The `now` variable is a global variable of type `ulong` initialized to a value of 1e18. It represents a high precision timestamp or clock value used throughout the program to simulate or track time.
- **Use**: This variable is used as a global clock to synchronize and manage timing for various operations, such as scheduling fibre execution and managing connection timeouts.


# Data Structures

---
### net\_fibre\_args
- **Type**: `struct`
- **Members**:
    - `input`: A pointer to an fd_fibre_pipe_t structure representing the input pipe.
    - `release`: A pointer to an fd_fibre_pipe_t structure representing the release pipe.
    - `thresh`: A float value representing a threshold.
    - `dir`: An integer indicating the direction of data flow, where 0 is client-to-server and 1 is server-to-client.
- **Description**: The `net_fibre_args` structure is used to encapsulate arguments for network fiber operations, specifically for handling input and release pipes, a threshold value, and the direction of data flow between client and server. This structure is likely used in the context of managing network communication fibers, providing necessary parameters for their operation.


---
### net\_fibre\_args\_t
- **Type**: `struct`
- **Members**:
    - `input`: A pointer to an `fd_fibre_pipe_t` structure representing the input pipe for the fibre.
    - `release`: A pointer to an `fd_fibre_pipe_t` structure representing the release pipe for the fibre.
    - `thresh`: A float value representing a threshold parameter for the fibre.
    - `dir`: An integer indicating the direction of data flow, where 0 represents client-to-server and 1 represents server-to-client.
- **Description**: The `net_fibre_args_t` structure is used to encapsulate the arguments required for configuring a network fibre in a fibre-based network simulation. It includes pointers to input and release pipes, a threshold value for controlling some aspect of the fibre's operation, and a direction flag to specify the data flow direction between client and server.


---
### my\_context
- **Type**: `struct`
- **Members**:
    - `server`: An integer representing the server identifier or status within the context.
- **Description**: The `my_context` structure is a simple data structure that contains a single integer member named `server`. This structure is used to encapsulate context information related to a server, potentially serving as a placeholder for more complex context data in a larger application. The typedef `my_context_t` is provided for convenience, allowing the structure to be referenced more succinctly in the code.


---
### my\_context\_t
- **Type**: `struct`
- **Members**:
    - `server`: An integer flag indicating whether the context is for a server.
- **Description**: The `my_context_t` structure is a simple data structure that contains a single integer member named `server`. This member is used as a flag to indicate whether the context is associated with a server. The structure is likely used in the context of managing connections or streams in a network communication setup, where distinguishing between client and server roles is necessary.


---
### client\_args
- **Type**: `struct`
- **Members**:
    - `quic`: A pointer to an fd_quic_t structure representing the client's QUIC instance.
    - `server_quic`: A pointer to an fd_quic_t structure representing the server's QUIC instance.
- **Description**: The `client_args` structure is used to encapsulate the arguments required for a client in a QUIC (Quick UDP Internet Connections) communication setup. It contains pointers to two `fd_quic_t` structures, one for the client's QUIC instance and another for the server's QUIC instance, facilitating the management and operation of QUIC connections between a client and server.


---
### client\_args\_t
- **Type**: `struct`
- **Members**:
    - `quic`: A pointer to an fd_quic_t structure representing the client's QUIC instance.
    - `server_quic`: A pointer to an fd_quic_t structure representing the server's QUIC instance.
- **Description**: The `client_args_t` structure is used to encapsulate the arguments required for the client fiber function in a QUIC (Quick UDP Internet Connections) communication setup. It contains pointers to two `fd_quic_t` structures, one for the client and one for the server, allowing the client fiber to manage and interact with both the client and server QUIC instances during the communication process.


---
### server\_args
- **Type**: `struct`
- **Members**:
    - `quic`: A pointer to an fd_quic_t structure, representing the QUIC protocol instance for the server.
- **Description**: The `server_args` structure is a simple data structure used to encapsulate arguments for server operations in a QUIC protocol context. It contains a single member, `quic`, which is a pointer to an `fd_quic_t` structure. This pointer is used to manage and interact with the QUIC protocol instance associated with the server, facilitating operations such as connection handling and data transmission.


---
### server\_args\_t
- **Type**: `typedef struct server_args server_args_t;`
- **Members**:
    - `quic`: A pointer to an fd_quic_t structure, representing the QUIC protocol instance for the server.
- **Description**: The `server_args_t` structure is used to encapsulate the arguments required for server operations in a QUIC protocol context. It primarily holds a pointer to an `fd_quic_t` instance, which is essential for managing the server-side QUIC operations, such as handling connections and streams. This structure is typically used to pass server-specific configuration and state information to functions that manage server fibers or threads.


# Functions

---
### my\_stream\_notify\_cb<!-- {{#callable:my_stream_notify_cb}} -->
The `my_stream_notify_cb` function is a placeholder callback for stream notifications in a QUIC connection, which currently does nothing with its parameters.
- **Inputs**:
    - `stream`: A pointer to an `fd_quic_stream_t` structure representing the QUIC stream associated with the notification.
    - `ctx`: A pointer to a context-specific data structure, which is not used in this function.
    - `type`: An integer representing the type of notification, which is not used in this function.
- **Control Flow**:
    - The function takes three parameters: a stream, a context, and a type, but does not use any of them.
    - Each parameter is explicitly cast to void to suppress unused variable warnings, indicating that the function is intentionally left as a no-op.
- **Output**: The function does not produce any output or perform any operations.


---
### my\_stream\_rx\_cb<!-- {{#callable:my_stream_rx_cb}} -->
The `my_stream_rx_cb` function processes received data on a QUIC stream, logs the data, increments counters, and checks if all streams have been received to set a completion flag.
- **Inputs**:
    - `conn`: A pointer to the QUIC connection associated with the stream.
    - `stream_id`: The identifier of the stream on which data is received.
    - `offset`: The offset in the stream where the data starts.
    - `data`: A pointer to the received data buffer.
    - `data_sz`: The size of the received data in bytes.
    - `fin`: An integer indicating if this is the final data chunk for the stream (1 if final, 0 otherwise).
- **Control Flow**:
    - The function begins by casting unused parameters to void to suppress compiler warnings.
    - A debug log is generated to display the received data in a hex dump format.
    - Another debug log is generated to indicate successful data reception.
    - The `rcvd` and `tot_rcvd` counters are incremented to track the number of received data chunks and total received streams, respectively.
    - A check is performed to see if the total number of received streams equals `NUM_STREAMS`; if so, the `client_done` flag is set to 1, indicating that the client has completed receiving all streams.
    - The function returns `FD_QUIC_SUCCESS` to indicate successful processing of the received data.
- **Output**: The function returns an integer `FD_QUIC_SUCCESS` to indicate successful processing of the received data.


---
### my\_cb\_conn\_final<!-- {{#callable:my_cb_conn_final}} -->
The `my_cb_conn_final` function finalizes a QUIC connection by clearing its context and incrementing a finalization counter.
- **Inputs**:
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection to be finalized.
    - `context`: A void pointer to additional context data, which is not used in this function.
- **Control Flow**:
    - The function begins by casting the context of the connection to a double pointer to `fd_quic_conn_t` using `fd_quic_conn_get_context`.
    - It checks if the context pointer (`ppconn`) is not NULL.
    - If `ppconn` is not NULL, it sets the dereferenced pointer to NULL, effectively clearing the connection context.
    - Finally, it increments the global `conn_final_cnt` counter to track the number of finalized connections.
- **Output**: The function does not return any value; it modifies the connection context and updates a global counter.


---
### my\_connection\_new<!-- {{#callable:my_connection_new}} -->
The `my_connection_new` function marks the server handshake as complete by setting a global flag.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the QUIC connection.
    - `vp_context`: A void pointer to a context, which is not used in this function.
- **Control Flow**:
    - The function takes two parameters: a connection pointer and a context pointer, both of which are not used in the function body.
    - A global variable `server_complete` is set to 1, indicating that the server handshake is complete.
    - The function does not perform any other operations or return any value.
- **Output**: The function does not return any value.


---
### my\_handshake\_complete<!-- {{#callable:my_handshake_complete}} -->
The `my_handshake_complete` function marks the completion of a client handshake by setting a flag.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the QUIC connection.
    - `vp_context`: A void pointer to additional context, which is not used in this function.
- **Control Flow**:
    - The function begins by casting `vp_context` to void to indicate it is unused.
    - A log statement for handshake completion is commented out.
    - The `client_complete` flag is set to 1, indicating the client handshake is complete.
    - The `conn` parameter is cast to void to indicate it is unused.
- **Output**: The function does not return any value.


---
### test\_clock<!-- {{#callable:test_clock}} -->
The `test_clock` function returns the current value of a global clock variable `now`.
- **Inputs**:
    - `ctx`: A void pointer to context data, which is not used in this function.
- **Control Flow**:
    - The function takes a single argument `ctx`, which is explicitly ignored using `(void)ctx;` to avoid compiler warnings about unused parameters.
    - The function returns the value of the global variable `now`.
- **Output**: The function returns an unsigned long integer representing the current time stored in the global variable `now`.


---
### test\_fibre\_clock<!-- {{#callable:test_fibre_clock}} -->
The function `test_fibre_clock` returns the current value of the global variable `now` cast to a long integer.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of the global variable `now` cast to a long integer without any additional logic or branching.
- **Output**: The function returns a long integer representing the current value of the global variable `now`.


---
### client\_fibre\_fn<!-- {{#callable:client_fibre_fn}} -->
The `client_fibre_fn` function manages a client-side QUIC connection, sending data streams periodically and handling connection and stream lifecycle events.
- **Inputs**:
    - `vp_arg`: A pointer to a `client_args_t` structure containing the QUIC client and server instances.
- **Control Flow**:
    - Initialize local variables including connection and stream pointers, a buffer with 'Hello World!', and timing variables.
    - Enter a loop that continues until `client_done` is set to true.
    - Calculate the next wakeup time based on the next QUIC service time and the next scheduled send time.
    - Wait until the calculated wakeup time using `fd_fibre_wait_until`.
    - Service the QUIC client using `fd_quic_service`.
    - If no connection exists, attempt to establish a new QUIC connection and wait for the handshake to complete.
    - If no stream exists, attempt to create a new stream and handle cases where stream creation fails.
    - Set the next send time and attempt to send data over the stream.
    - If sending is successful and a certain number of sends have been completed, close the connection and wait for it to be reaped.
    - If sending fails, log a warning message.
    - After exiting the loop, close any remaining connection and signal the server to shut down.
- **Output**: The function does not return a value; it operates as a side-effect by managing the QUIC connection and stream lifecycle, sending data, and signaling when the client is done.


---
### server\_fibre\_fn<!-- {{#callable:server_fibre_fn}} -->
The `server_fibre_fn` function manages a server's QUIC service loop, ensuring it wakes up periodically to process QUIC events until a shutdown condition is met.
- **Inputs**:
    - `vp_arg`: A pointer to a `server_args_t` structure containing the server's QUIC instance.
- **Control Flow**:
    - Cast the `vp_arg` to a `server_args_t` pointer to access the server's QUIC instance.
    - Set a wake-up period of 1 millisecond (1e6 nanoseconds).
    - Enter a loop that continues until the `server_done` flag is set to true.
    - Within the loop, call `fd_quic_service` to process any pending QUIC events for the server.
    - Determine the next wake-up time by comparing the next QUIC wake-up time and the next periodic wake-up time.
    - Use `fd_fibre_wait_until` to pause execution until the earlier of the two wake-up times is reached.
- **Output**: The function does not return a value; it operates in a loop until the `server_done` flag is set, managing the server's QUIC service.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes and runs a QUIC protocol test environment, setting up client and server QUIC instances, configuring network emulation, and managing the execution of client-server communication through fibers.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments passed to the program.
- **Control Flow**:
    - Initialize the environment and QUIC test setup with `fd_boot` and [`fd_quic_test_boot`](fd_quic_test_helpers.c.driver.md#fd_quic_test_boot).
    - Create a random number generator instance using `fd_rng_new` and `fd_rng_join`.
    - Determine the CPU index and adjust if it exceeds the shared memory CPU count.
    - Parse command-line arguments for page size, page count, and NUMA index using `fd_env_strip_cmdline_cstr` and `fd_env_strip_cmdline_ulong`.
    - Convert the page size string to a numeric value with `fd_cstr_to_shmem_page_sz` and log an error if unsupported.
    - Create a new anonymous workspace with `fd_wksp_new_anonymous` and log its creation.
    - Define QUIC limits and calculate the QUIC footprint using `fd_quic_footprint`.
    - Create server and client QUIC instances with [`fd_quic_new_anonymous`](fd_quic_test_helpers.c.driver.md#fd_quic_new_anonymous) and set their callbacks and configurations.
    - Initialize a virtual pair for the QUIC instances using [`fd_quic_virtual_pair_init`](fd_quic_test_helpers.c.driver.md#fd_quic_virtual_pair_init).
    - Set up network emulation with [`fd_quic_netem_init`](fd_quic_test_helpers.c.driver.md#fd_quic_netem_init) and attach AIOs for client and server QUIC instances.
    - Initialize the QUIC instances with `fd_quic_init`.
    - Allocate memory for and initialize fibers for client and server using `fd_wksp_alloc_laddr`, `fd_fibre_init`, and `fd_fibre_start`.
    - Schedule the client and server fibers with `fd_fibre_schedule`.
    - Run the fiber scheduler in a loop with `fd_fibre_schedule_run` until completion.
    - Log the number of received stream fragments and tested connections.
    - Clean up resources by finalizing the virtual pair, deleting QUIC instances, and freeing allocated memory.
    - Log the test pass and halt the QUIC test environment with [`fd_quic_test_halt`](fd_quic_test_helpers.c.driver.md#fd_quic_test_halt) and `fd_halt`.
- **Output**: The function returns an integer value of 0, indicating successful execution.
- **Functions called**:
    - [`fd_quic_test_boot`](fd_quic_test_helpers.c.driver.md#fd_quic_test_boot)
    - [`fd_quic_new_anonymous`](fd_quic_test_helpers.c.driver.md#fd_quic_new_anonymous)
    - [`fd_quic_virtual_pair_init`](fd_quic_test_helpers.c.driver.md#fd_quic_virtual_pair_init)
    - [`fd_quic_netem_init`](fd_quic_test_helpers.c.driver.md#fd_quic_netem_init)
    - [`fd_quic_virtual_pair_fini`](fd_quic_test_helpers.c.driver.md#fd_quic_virtual_pair_fini)
    - [`fd_quic_test_halt`](fd_quic_test_helpers.c.driver.md#fd_quic_test_halt)



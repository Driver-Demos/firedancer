# Purpose
This C source code file is a test application for a QUIC (Quick UDP Internet Connections) protocol implementation. It sets up a simulated environment to test the functionality of QUIC connections between a client and a server. The code initializes both client and server QUIC instances with specific configuration limits, such as connection counts and buffer sizes, and establishes a virtual pair to simulate network communication between them. The main functionality includes setting up callbacks for handling new connections, stream data reception, and handshake completion, which are crucial for testing the QUIC protocol's behavior in a controlled environment.

The file includes several key components: it defines callback functions for handling stream data reception ([`my_stream_rx_cb`](#my_stream_rx_cb)), new connections ([`my_connection_new`](#my_connection_new)), and handshake completion ([`my_handshake_complete`](#my_handshake_complete)). It also manages a global clock and uses a loop to simulate the passage of time and the processing of QUIC services. The test involves sending a large number of streams from the client to the server, verifying the integrity of the received data, and ensuring that both client and server complete their handshakes successfully. The code concludes by cleaning up resources, such as closing connections and freeing allocated memory, ensuring that the test environment is properly dismantled after execution. This file is primarily intended for internal testing and validation of the QUIC protocol implementation, rather than providing a public API or external interface.
# Imports and Dependencies

---
- `../fd_quic.h`
- `fd_quic_test_helpers.h`
- `fd_quic_stream_spam.h`


# Global Variables

---
### recvd
- **Type**: `ulong`
- **Description**: The `recvd` variable is a static global variable of type `ulong` initialized to 0. It is used to keep track of the number of data packets successfully received and verified by the server in the QUIC protocol test.
- **Use**: This variable is incremented each time a data packet is successfully received and verified in the `my_stream_rx_cb` callback function.


---
### server\_complete
- **Type**: `int`
- **Description**: The `server_complete` variable is a global integer that acts as a flag to indicate whether the server-side handshake process has been completed successfully. It is initialized to 0, representing an incomplete state, and is set to 1 when the server handshake is complete.
- **Use**: This variable is used to track the completion status of the server handshake in the QUIC connection process.


---
### client\_complete
- **Type**: `int`
- **Description**: The `client_complete` variable is a global integer initialized to 0, used to indicate whether the client-side handshake in a QUIC connection has been completed.
- **Use**: This variable is set to 1 in the `my_handshake_complete` callback function when the client handshake is successfully completed.


---
### server\_conn
- **Type**: `fd_quic_conn_t *`
- **Description**: The `server_conn` is a global pointer variable of type `fd_quic_conn_t *`, which is initially set to `NULL`. It is used to store the connection object for the server once a new connection is established.
- **Use**: This variable is assigned a value in the `my_connection_new` callback function when a new server connection is successfully established.


---
### now
- **Type**: `ulong`
- **Description**: The `now` variable is a global variable of type `ulong` initialized to the value 123. It represents a mock or simulated current time value used in the context of the QUIC protocol testing.
- **Use**: This variable is used as a global 'clock' to provide a consistent time reference for the QUIC protocol operations during testing.


# Data Structures

---
### my\_context
- **Type**: `struct`
- **Members**:
    - `server`: An integer representing the server context or identifier.
- **Description**: The `my_context` structure is a simple data structure that contains a single integer member named `server`. This member is likely used to store a server-related identifier or context within the application, facilitating the management or identification of server-specific operations or states. The structure is typedef'd to `my_context_t` for ease of use throughout the codebase.


---
### my\_context\_t
- **Type**: `struct`
- **Members**:
    - `server`: An integer flag indicating if the context is for a server.
- **Description**: The `my_context_t` structure is a simple data structure that contains a single integer member named `server`. This member is used as a flag to indicate whether the context is associated with a server. The structure is likely used in the context of managing or identifying server-related operations or states within a larger system, such as a QUIC protocol implementation.


# Functions

---
### my\_stream\_rx\_cb<!-- {{#callable:my_stream_rx_cb}} -->
The `my_stream_rx_cb` function processes received stream data in a QUIC connection, verifying its size and content against expected values and logging errors if discrepancies are found.
- **Inputs**:
    - `conn`: A pointer to the QUIC connection object, which is not used in this function.
    - `stream_id`: The identifier of the stream from which data is received.
    - `offset`: The offset in the stream where the received data starts.
    - `data`: A pointer to the received data buffer.
    - `data_sz`: The size of the received data.
    - `fin`: An integer indicating if this is the final piece of data for the stream (non-zero if true).
- **Control Flow**:
    - The function begins by casting the `conn` parameter to void to indicate it is unused.
    - A buffer `payload_buf` of size 4096 bytes is declared to hold the expected payload, and a packet info structure `pkt` is initialized with this buffer.
    - The function [`fd_quic_stream_spam_gen`](fd_quic_stream_spam.c.driver.md#fd_quic_stream_spam_gen) is called to generate the expected payload for the given `stream_id`.
    - A debug log is generated to record the stream ID, data size, and offset of the received data.
    - The function checks if the total size of the received data (offset + data_sz) matches the expected size (`pkt.buf_sz`) when `fin` is true, or if it exceeds the expected size, logging an error if either condition is met.
    - The function compares the received data with the expected data at the given offset using `memcmp`, logging a warning and an error if they do not match.
    - The global variable `recvd` is incremented to count the number of successfully processed data chunks.
    - The function returns `FD_QUIC_SUCCESS` to indicate successful processing.
- **Output**: The function returns `FD_QUIC_SUCCESS` to indicate successful processing of the received stream data.
- **Functions called**:
    - [`fd_quic_stream_spam_gen`](fd_quic_stream_spam.c.driver.md#fd_quic_stream_spam_gen)


---
### my\_connection\_new<!-- {{#callable:my_connection_new}} -->
The `my_connection_new` function is a callback that marks the completion of a server handshake and stores the connection object.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the QUIC connection that has been established.
    - `vp_context`: A void pointer to a context, which is not used in this function.
- **Control Flow**:
    - The function begins by casting `vp_context` to void to indicate it is unused.
    - A debug log message is generated to indicate that the server handshake is complete.
    - The global variable `server_complete` is set to 1, marking the server handshake as complete.
    - The global variable `server_conn` is assigned the value of `conn`, storing the connection object for later use.
- **Output**: This function does not return any value.


---
### my\_handshake\_complete<!-- {{#callable:my_handshake_complete}} -->
The `my_handshake_complete` function logs a debug message indicating the completion of a client handshake and sets a flag to indicate this completion.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the QUIC connection; it is not used in the function.
    - `vp_context`: A void pointer to a context; it is not used in the function.
- **Control Flow**:
    - The function begins by explicitly ignoring the `conn` and `vp_context` parameters using `(void)` casts.
    - A debug log message is generated to indicate that the client handshake is complete.
    - The global variable `client_complete` is set to 1 to signal that the client handshake has been completed.
- **Output**: The function does not return any value.


---
### test\_clock<!-- {{#callable:test_clock}} -->
The `test_clock` function returns the current value of a global clock variable `now`.
- **Inputs**:
    - `ctx`: A void pointer to context data, which is not used in this function.
- **Control Flow**:
    - The function takes a single argument `ctx`, which is explicitly ignored using `(void)ctx;`.
    - The function returns the value of the global variable `now`.
- **Output**: The function returns an unsigned long integer representing the current time from the global variable `now`.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes and tests a QUIC server-client setup, simulating data transmission and handling connections and streams.
- **Inputs**:
    - `argc`: The number of command-line arguments.
    - `argv`: An array of command-line argument strings.
- **Control Flow**:
    - Initialize the environment and QUIC test setup with `fd_boot` and [`fd_quic_test_boot`](fd_quic_test_helpers.c.driver.md#fd_quic_test_boot).
    - Create a random number generator using `fd_rng_new` and `fd_rng_join`.
    - Determine the CPU index and adjust if it exceeds the shared memory CPU count.
    - Parse command-line arguments for page size, page count, and NUMA index using `fd_env_strip_cmdline_cstr` and `fd_env_strip_cmdline_ulong`.
    - Convert the page size string to an actual size using `fd_cstr_to_shmem_page_sz` and log an error if unsupported.
    - Create a workspace with `fd_wksp_new_anonymous` and verify its creation.
    - Define server and client QUIC limits and create QUIC instances for both roles using [`fd_quic_new_anonymous`](fd_quic_test_helpers.c.driver.md#fd_quic_new_anonymous).
    - Set callback functions for server and client QUICs for handling time, new connections, stream reception, handshake completion, and stream notifications.
    - Configure initial maximum stream data for server and client QUICs.
    - Initialize a virtual pair to connect server and client QUICs using [`fd_quic_virtual_pair_init`](fd_quic_test_helpers.c.driver.md#fd_quic_virtual_pair_init).
    - Create and join a stream spammer for generating stream data.
    - Initialize both server and client QUICs with `fd_quic_init`.
    - Establish a client connection using `fd_quic_connect` and verify its creation.
    - Run a loop to process services for both QUICs, checking for handshake completion.
    - Enter a loop to send streams using the spammer until a certain number of streams are received, logging sent streams and running services.
    - Close the client connection with `fd_quic_conn_close`.
    - Run additional service loops to wait for acknowledgments.
    - Clean up resources by finalizing the virtual pair, deleting the spammer, freeing QUIC instances, deleting the workspace, and deleting the random number generator.
    - Log the completion of the test and halt the QUIC test and environment.
- **Output**: The function returns an integer, specifically 0, indicating successful execution.
- **Functions called**:
    - [`fd_quic_test_boot`](fd_quic_test_helpers.c.driver.md#fd_quic_test_boot)
    - [`fd_quic_new_anonymous`](fd_quic_test_helpers.c.driver.md#fd_quic_new_anonymous)
    - [`fd_quic_virtual_pair_init`](fd_quic_test_helpers.c.driver.md#fd_quic_virtual_pair_init)
    - [`fd_quic_stream_spam_join`](fd_quic_stream_spam.c.driver.md#fd_quic_stream_spam_join)
    - [`fd_quic_stream_spam_new`](fd_quic_stream_spam.c.driver.md#fd_quic_stream_spam_new)
    - [`fd_quic_stream_spam_service`](fd_quic_stream_spam.c.driver.md#fd_quic_stream_spam_service)
    - [`fd_quic_virtual_pair_fini`](fd_quic_test_helpers.c.driver.md#fd_quic_virtual_pair_fini)
    - [`fd_quic_stream_spam_delete`](fd_quic_stream_spam.c.driver.md#fd_quic_stream_spam_delete)
    - [`fd_quic_test_halt`](fd_quic_test_helpers.c.driver.md#fd_quic_test_halt)



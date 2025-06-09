# Purpose
This C source code file implements a QUIC client that establishes a connection to a specified server, sends transactions, and handles various connection and stream events. The code is structured around the Fast Data (FD) framework, utilizing its QUIC protocol implementation to manage network communication. The main components include callback functions for handling new connections, handshake completions, connection finalization, and stream notifications. These callbacks are registered with the QUIC client to manage the lifecycle of connections and streams. The code also includes a function to read and decode base64-encoded input from the standard input, which is then sent over the QUIC connection.

The file is designed to be an executable, as indicated by the presence of a [`main`](#main) function, which initializes the necessary resources, configures the QUIC client, and enters a loop to manage the connection and send data. The code sets up a workspace for memory management, configures the QUIC client with limits and settings, and creates a UDP socket for network communication. The [`run_quic_client`](#run_quic_client) function orchestrates the connection lifecycle, including establishing connections, creating streams, and sending data. The file does not define public APIs or external interfaces, as it is intended to be a standalone application demonstrating the use of the FD framework's QUIC capabilities.
# Imports and Dependencies

---
- `../fd_quic.h`
- `fd_quic_test_helpers.h`
- `../../../ballet/base64/fd_base64.h`
- `../../../util/net/fd_ip4.h`
- `stdio.h`
- `errno.h`
- `string.h`


# Global Variables

---
### gbl\_conn
- **Type**: `fd_quic_conn_t *`
- **Description**: `gbl_conn` is a global pointer variable of type `fd_quic_conn_t *`, which is used to manage and track the state of a QUIC connection in the program. It is initialized to `NULL` and is updated throughout the program to point to the current active connection or reset to `NULL` when the connection is closed.
- **Use**: `gbl_conn` is used to store the current active QUIC connection, allowing the program to manage connection state and perform operations such as creating, sending data, and closing the connection.


---
### gbl\_stream
- **Type**: `fd_quic_stream_t *`
- **Description**: `gbl_stream` is a global pointer variable of type `fd_quic_stream_t *`, which is used to manage a QUIC stream in the context of a QUIC client application. It is initialized to `NULL` and is used to track the current active stream associated with a QUIC connection.
- **Use**: `gbl_stream` is used to store the pointer to the current QUIC stream, allowing the application to send data over the stream and manage its lifecycle.


---
### g\_handshake\_complete
- **Type**: `int`
- **Description**: The `g_handshake_complete` is a global integer variable initialized to 0, which indicates whether a QUIC handshake has been completed. It is used as a flag to track the state of the handshake process in the QUIC connection.
- **Use**: This variable is set to 1 in the `cb_conn_handshake_complete` callback function to signal that the handshake process has successfully completed.


---
### g\_conn\_final
- **Type**: `int`
- **Description**: The `g_conn_final` is a global integer variable initialized to 0. It is used as a flag to indicate whether a QUIC connection has reached its final state.
- **Use**: This variable is set to 1 in the `cb_conn_final` callback function to signal that the connection has been finalized.


---
### g\_stream\_notify
- **Type**: `int`
- **Description**: The `g_stream_notify` is a global integer variable initialized to 0. It is used to track notifications related to QUIC streams.
- **Use**: This variable is used to monitor and potentially react to stream notifications within the QUIC client implementation.


---
### sent\_cnt
- **Type**: `ulong`
- **Description**: The `sent_cnt` variable is a global variable of type `ulong` initialized to zero. It is used to keep track of the number of transactions sent in the QUIC client application.
- **Use**: This variable is incremented each time a transaction is successfully sent, as indicated by the `cb_stream_notify` callback function.


# Functions

---
### cb\_conn\_new<!-- {{#callable:cb_conn_new}} -->
The `cb_conn_new` function logs a notice message indicating the creation of a new QUIC connection and its maximum data transmission capacity.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the new QUIC connection.
    - `quic_ctx`: A void pointer to a context object associated with the QUIC connection, which is not used in this function.
- **Control Flow**:
    - The function begins by explicitly ignoring the `quic_ctx` parameter using a cast to void.
    - It then logs a notice message using the `FD_LOG_NOTICE` macro, displaying the maximum data transmission capacity (`tx_max_data`) of the connection pointed to by `conn`.
- **Output**: This function does not return any value; it performs logging as a side effect.


---
### cb\_conn\_handshake\_complete<!-- {{#callable:cb_conn_handshake_complete}} -->
The `cb_conn_handshake_complete` function logs a notice when a QUIC connection handshake is complete and sets a global flag to indicate the handshake completion.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the QUIC connection for which the handshake has completed.
    - `quic_ctx`: A void pointer to a context object, which is not used in this function.
- **Control Flow**:
    - The function begins by casting the `quic_ctx` parameter to void to indicate it is unused.
    - It logs a notice message with the maximum data that can be transmitted (`tx_max_data`) from the `conn` structure.
    - The global variable `g_handshake_complete` is set to 1 to indicate that the handshake is complete.
- **Output**: This function does not return any value.


---
### cb\_conn\_final<!-- {{#callable:cb_conn_final}} -->
The `cb_conn_final` function logs a notice indicating the finalization of a QUIC connection and resets global connection and stream pointers to NULL.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the QUIC connection being finalized.
    - `quic_ctx`: A void pointer to a context associated with the QUIC connection, which is not used in this function.
- **Control Flow**:
    - The function begins by casting the `conn` and `quic_ctx` parameters to void to indicate they are unused.
    - A log notice is generated with the message "cb_conn_final" to indicate the function has been called.
    - The global variable `g_conn_final` is set to 1 to signal that the connection finalization process has occurred.
    - The global pointers `gbl_conn` and `gbl_stream` are set to NULL, effectively resetting the global connection and stream state.
- **Output**: This function does not return any value.


---
### cb\_stream\_notify<!-- {{#callable:cb_stream_notify}} -->
The `cb_stream_notify` function handles notifications for QUIC stream events, incrementing a counter if the stream ends successfully or logging a warning if it ends in failure.
- **Inputs**:
    - `stream`: A pointer to the QUIC stream object associated with the notification.
    - `stream_ctx`: A context pointer associated with the stream, not used in this function.
    - `notify_type`: An integer representing the type of notification received for the stream.
- **Control Flow**:
    - The function begins by explicitly ignoring the `stream` and `stream_ctx` parameters, indicating they are not used in the function body.
    - It checks if the `notify_type` is equal to `FD_QUIC_STREAM_NOTIFY_END`.
    - If the condition is true, it increments the global `sent_cnt` counter, which tracks the number of successfully sent transactions.
    - If the condition is false, it logs a warning message indicating the stream ended in failure, including the `notify_type` in the log message.
- **Output**: The function does not return any value; it modifies the global `sent_cnt` variable or logs a warning message based on the notification type.


---
### findch<!-- {{#callable:findch}} -->
The `findch` function searches for a specified character in a buffer and returns its index or -1 if not found or if a null character is encountered.
- **Inputs**:
    - `buf`: A pointer to the character buffer where the search is performed.
    - `buf_sz`: The size of the buffer, indicating the number of characters to search through.
    - `ch`: The character to search for within the buffer.
- **Control Flow**:
    - Initialize a loop counter `j` to 0 and iterate over the buffer until `j` is less than `buf_sz`.
    - In each iteration, retrieve the current character `cur` from the buffer at index `j`.
    - Check if `cur` is a null character ('\0'); if so, return -1UL indicating the search should stop as the buffer is considered terminated.
    - Check if `cur` matches the character `ch`; if so, return the current index `j` as the position of the character in the buffer.
    - If the loop completes without finding `ch` or encountering a null character, return -1UL to indicate the character was not found.
- **Output**: Returns the index of the first occurrence of the character `ch` in the buffer, or -1UL if the character is not found or a null character is encountered before finding `ch`.


---
### run\_quic\_client<!-- {{#callable:run_quic_client}} -->
The `run_quic_client` function initializes and manages a QUIC client connection, sending data packets over a QUIC stream until all input is processed or an error occurs.
- **Inputs**:
    - `quic`: A pointer to an `fd_quic_t` structure representing the QUIC client instance.
    - `udpsock`: A pointer to an `fd_quic_udpsock_t` structure representing the UDP socket used for network communication.
- **Control Flow**:
    - Initialize a buffer `buf` and its size `buf_sz` to store data packets.
    - Convert the destination IP address string to a numeric format and set the destination port.
    - Set callback functions for connection and stream events in the `quic` structure.
    - Initialize the QUIC client with `fd_quic_init` and set up asynchronous I/O for network transmission.
    - Enter an infinite loop to service the QUIC client and UDP socket.
    - If no global connection (`gbl_conn`) exists, attempt to create a new connection to the specified IP and port.
    - If the connection is not active, continue the loop without further action.
    - If no global stream (`gbl_stream`) exists, create a new stream for the connection.
    - If the buffer size is zero, attempt to read a packet into the buffer using [`read_pkt`](#read_pkt); if no input is available, break the loop.
    - If a connection, stream, and input data are available, send the data over the stream with `fd_quic_stream_send`.
    - If the data is successfully sent, reset the buffer size and stream to indicate readiness for more input.
    - After exiting the loop, if a connection exists, close it with `fd_quic_conn_close`.
    - Continue servicing the QUIC client and UDP socket until the connection is fully closed.
    - Finalize the QUIC client with `fd_quic_fini`.
- **Output**: The function does not return a value; it manages the QUIC client connection and data transmission as a side effect.
- **Functions called**:
    - [`fd_quic_udpsock_service`](fd_quic_test_helpers.c.driver.md#fd_quic_udpsock_service)
    - [`read_pkt`](#read_pkt)


---
### read\_pkt<!-- {{#callable:read_pkt}} -->
The `read_pkt` function reads a line from standard input, decodes it from base64, and stores the result in an output buffer.
- **Inputs**:
    - `out_buf`: A pointer to an unsigned character array where the decoded base64 data will be stored.
    - `out_buf_sz`: A pointer to an unsigned long where the size of the decoded data will be stored.
- **Control Flow**:
    - Declare a buffer `buf` of size 2048 and set `buf_sz` to its size.
    - Attempt to read a line from standard input into `buf` using `fgets`.
    - If `fgets` returns NULL, check for an error using `ferror` and log a warning if an error occurred, then return 1.
    - Find the newline character in `buf` using [`findch`](#findch); if not found, log a warning about the line being too long and return 1.
    - Replace the newline character with a null terminator to properly terminate the string.
    - Decode the base64 encoded string in `buf` into `out_buf` using `fd_base64_decode`.
    - If decoding fails (returns -1), log a warning and a hexdump of the data, then return 1.
    - Set `*out_buf_sz` to the size of the decoded data.
    - Return 0 to indicate success.
- **Output**: Returns 0 on success, indicating the input was read and decoded successfully, or 1 on failure, indicating an error occurred during reading or decoding.
- **Functions called**:
    - [`findch`](#findch)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes and runs a QUIC client to send transactions over a network, then cleans up resources and returns the number of transactions sent.
- **Inputs**:
    - `argc`: The count of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the application environment with `fd_boot` using `argc` and `argv`.
    - Create an anonymous workspace `wksp` with specified size and alignment using `fd_wksp_new_anonymous`.
    - Define QUIC limits in a `fd_quic_limits_t` structure and calculate the required memory footprint with `fd_quic_footprint`.
    - Allocate memory for the QUIC instance using `fd_wksp_alloc_laddr` and create a new QUIC instance with `fd_quic_new`.
    - Convert the string "0.0.0.0" to an IP address and create a UDP socket for the QUIC client using `fd_quic_client_create_udpsock`.
    - Configure the QUIC client settings, including role and timeouts, using `fd_quic_config_from_env`.
    - Run the QUIC client using [`run_quic_client`](#run_quic_client), which handles connection and transaction sending logic.
    - Free allocated resources, including the QUIC instance and UDP socket, and delete the anonymous workspace.
    - Log the number of transactions sent and return this count as the exit status of the program.
- **Output**: The function returns the number of transactions sent as an integer, which is also logged as a notice.
- **Functions called**:
    - [`run_quic_client`](#run_quic_client)
    - [`fd_quic_udpsock_destroy`](fd_quic_test_helpers.c.driver.md#fd_quic_udpsock_destroy)


# Function Declarations (Public API)

---
### read\_pkt<!-- {{#callable_declaration:read_pkt}} -->
Reads a base64-encoded packet from standard input and decodes it.
- **Description**: This function reads a line of base64-encoded data from the standard input, decodes it, and stores the result in the provided output buffer. It should be used when you need to process base64-encoded input data from the user or another input stream. The function expects the input to be a single line terminated by a newline character. If the input line is too long or if there is an error during reading or decoding, the function returns an error code. The function modifies the output buffer and updates the size of the decoded data.
- **Inputs**:
    - `out_buf`: A pointer to a buffer where the decoded data will be stored. The buffer must be large enough to hold the decoded data. The caller retains ownership and must ensure the buffer is not null.
    - `out_buf_sz`: A pointer to a variable where the size of the decoded data will be stored. The caller retains ownership and must ensure the pointer is not null.
- **Output**: Returns 0 on success, with the decoded data stored in out_buf and its size in out_buf_sz. Returns 1 on error, with no changes to out_buf or out_buf_sz.
- **See also**: [`read_pkt`](#read_pkt)  (Implementation)



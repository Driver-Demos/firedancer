# Purpose
This C source code file implements a QUIC client designed to send a flood of QUIC INITIAL frames to a specified server. The primary functionality of this code is to establish a QUIC connection, perform a handshake, and then continuously send data streams to the server. The code is structured to handle the connection lifecycle, including initialization, data transmission, and connection closure. It utilizes various libraries for cryptographic operations (such as SHA-512 and Ed25519 for message signing and verification) and network utilities to manage the QUIC protocol's specifics. The code is intended to be executed as a standalone application, as indicated by the presence of a [`main`](#main) function, which sets up the environment, parses command-line arguments, and manages the execution loop for the client.

The file includes several key components: callback functions for handling stream reception, handshake completion, and connection closure; a [`run_quic_client`](#run_quic_client) function that manages the connection and data transmission; and a [`main`](#main) function that initializes the environment and repeatedly attempts to establish and maintain a connection. The code is designed to be robust, with error handling and logging throughout to ensure that issues are reported and managed appropriately. The use of command-line arguments allows for flexible configuration of the client, such as specifying the destination IP and port, batch size, and other parameters. This file does not define public APIs or external interfaces, as it is intended to be a self-contained executable for testing or demonstration purposes.
# Imports and Dependencies

---
- `../fd_quic.h`
- `fd_quic_test_helpers.h`
- `stdlib.h`
- `stdio.h`
- `../../../ballet/sha512/fd_sha512.h`
- `../../../ballet/ed25519/fd_ed25519.h`
- `../../../waltz/quic/fd_quic_private.h`
- `../../../util/fd_util.h`
- `../../../util/net/fd_eth.h`
- `../../../util/net/fd_ip4.h`


# Global Variables

---
### g\_unreliable
- **Type**: `_Bool`
- **Description**: The `g_unreliable` variable is a static global boolean flag used to indicate whether the QUIC client should treat all packets as acknowledged, effectively simulating an unreliable network condition. This variable is set based on the presence of the `--unreliable` command-line argument.
- **Use**: It is used to determine if packet metas should be reclaimed immediately, simulating an unreliable network.


---
### client\_conn
- **Type**: `fd_quic_conn_t *`
- **Description**: The `client_conn` is a global pointer variable of type `fd_quic_conn_t *`, which is used to manage the state of a QUIC connection from the client side. It is initialized to `NULL` and is updated when a new connection is established or closed.
- **Use**: This variable is used to track the current state of the client's QUIC connection, allowing the program to manage connection lifecycle events such as handshake completion and connection closure.


---
### client\_complete
- **Type**: `int`
- **Description**: The `client_complete` variable is a global integer that acts as a flag to indicate the completion status of a client operation, specifically the QUIC handshake process. It is initialized to 0, representing an incomplete state, and is set to 1 when the client handshake is complete or the connection is closed.
- **Use**: This variable is used to control the flow of the client operation, allowing the program to proceed only after the handshake is complete.


# Functions

---
### my\_stream\_rx\_cb<!-- {{#callable:my_stream_rx_cb}} -->
The `my_stream_rx_cb` function logs received data from a QUIC stream and returns a success status.
- **Inputs**:
    - `conn`: A pointer to the QUIC connection object, which is not used in this function.
    - `stream_id`: The identifier of the stream from which data is received, which is not used in this function.
    - `offset`: The offset in the stream where the data starts.
    - `data`: A pointer to the data received from the stream.
    - `data_sz`: The size of the data received.
    - `fin`: An integer indicating if this is the final data chunk of the stream, which is not used in this function.
- **Control Flow**:
    - The function begins by casting the unused parameters `conn`, `stream_id`, and `fin` to void to suppress compiler warnings about unused variables.
    - It logs a debug message indicating the size and offset of the received data using `FD_LOG_DEBUG`.
    - It logs a hexdump of the received data using `FD_LOG_HEXDUMP_DEBUG`.
    - The function returns `FD_QUIC_SUCCESS` to indicate successful processing of the received data.
- **Output**: The function returns an integer `FD_QUIC_SUCCESS`, indicating successful handling of the received data.


---
### my\_handshake\_complete<!-- {{#callable:my_handshake_complete}} -->
The `my_handshake_complete` function logs a message indicating the completion of a client handshake and sets a flag to signal this completion.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the QUIC connection; it is not used in this function.
    - `vp_context`: A void pointer to context data; it is not used in this function.
- **Control Flow**:
    - The function begins by explicitly ignoring the `conn` and `vp_context` parameters using `(void)` casts.
    - It logs an informational message stating 'client handshake complete' using the `FD_LOG_INFO` macro.
    - The function sets the global variable `client_complete` to 1, indicating that the client handshake process is complete.
- **Output**: This function does not return any value; it is a `void` function.


---
### my\_connection\_closed<!-- {{#callable:my_connection_closed}} -->
The `my_connection_closed` function handles the closure of a QUIC connection by logging the closure reason, resetting the client connection pointer, and marking the client as complete.
- **Inputs**:
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection that has been closed.
    - `vp_context`: A void pointer to additional context, which is not used in this function.
- **Control Flow**:
    - The function begins by casting `vp_context` to void to indicate it is unused.
    - It logs an informational message indicating the client connection has closed, including the closure reason code from the `conn` structure.
    - The global `client_conn` pointer is set to `NULL`, indicating there is no active client connection.
    - The global `client_complete` flag is set to `1`, marking the client process as complete.
- **Output**: This function does not return any value.


---
### run\_quic\_client<!-- {{#callable:run_quic_client}} -->
The `run_quic_client` function initializes and manages a QUIC client connection, sending data in batches to a specified server until the connection is closed or fails.
- **Inputs**:
    - `quic`: A pointer to an `fd_quic_t` structure representing the QUIC client instance.
    - `udpsock`: A constant pointer to an `fd_quic_udpsock_t` structure representing the UDP socket used for QUIC communication.
    - `dst_ip`: An unsigned integer representing the destination IP address of the server.
    - `dst_port`: An unsigned short representing the destination port number of the server.
    - `batch_sz`: An unsigned integer specifying the number of messages to send in each batch.
- **Control Flow**:
    - Initialize local variables and set callback functions for connection events.
    - Set up the QUIC client for network transmission using the provided UDP socket.
    - Initialize the QUIC client and attempt to connect to the server using the provided IP and port.
    - Enter a loop to process QUIC and UDP socket services until the handshake is complete or fails.
    - If the connection is successful, generate and sign reference messages of varying sizes.
    - Create QUIC batches with the generated messages and prepare for transmission.
    - Enter a loop to continuously send data in batches while the connection is active.
    - Within the loop, obtain a free stream, send a message, and update counters for successful transmissions.
    - Periodically log the number of streams and total size of data sent.
    - If the connection is unreliable, reclaim packet metadata to free resources.
    - Upon connection closure or failure, clean up resources and log the completion of the client session.
- **Output**: The function does not return a value; it manages the QUIC client connection and data transmission as a side effect.
- **Functions called**:
    - [`fd_quic_udpsock_service`](fd_quic_test_helpers.c.driver.md#fd_quic_udpsock_service)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes and runs a QUIC client that continuously attempts to connect to a server and send data using specified command-line parameters.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the environment and random number generator.
    - Determine the CPU index and adjust if necessary.
    - Parse command-line arguments for configuration parameters such as page size, page count, NUMA index, destination IP, destination port, gateway, batch size, and unreliability flag.
    - Convert page size string to a numeric value and validate it.
    - Validate the presence and correctness of destination IP, destination port, and gateway address.
    - Create a shared memory workspace with the specified parameters.
    - Initialize QUIC limits from environment variables and calculate the QUIC footprint.
    - Create a new QUIC client instance and configure it for client role.
    - Create a UDP socket for QUIC communication.
    - Enter an infinite loop to continuously run the QUIC client, attempting to connect and send data to the server.
    - Upon termination, clean up resources including QUIC instance, UDP socket, workspace, and random number generator.
    - Log a success message and halt the program.
- **Output**: The function returns an integer, 0, indicating successful execution.
- **Functions called**:
    - [`fd_quic_new_anonymous`](fd_quic_test_helpers.c.driver.md#fd_quic_new_anonymous)
    - [`fd_quic_udpsock_create`](fd_quic_test_helpers.c.driver.md#fd_quic_udpsock_create)
    - [`run_quic_client`](#run_quic_client)
    - [`fd_quic_udpsock_destroy`](fd_quic_test_helpers.c.driver.md#fd_quic_udpsock_destroy)



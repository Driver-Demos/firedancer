# Purpose
This C source code file implements a QUIC client that manages multiple connections using the QUIC protocol. The code is structured around the initialization, management, and termination of QUIC connections, with a focus on handling connection states and lifecycle events. The file includes functions to handle new connections, complete handshakes, and finalize connections, updating the state of each connection accordingly. The [`run_quic_client`](#run_quic_client) function is central to the operation, setting up callbacks for connection events, initializing the QUIC client, and entering a loop to service connections and manage connection states. The code also includes command-line argument parsing to configure the client, such as setting source and destination IPs, port numbers, and the number of connections to maintain.

The file is designed to be an executable, as indicated by the presence of the [`main`](#main) function, which orchestrates the setup and execution of the QUIC client. It initializes necessary resources, such as memory workspaces and UDP sockets, and configures the QUIC client with parameters derived from command-line arguments. The code leverages several external libraries and headers, such as `fd_quic.h` and `fd_ip4.h`, to provide the necessary functionality for network communication and QUIC protocol handling. The file does not define public APIs or external interfaces but rather serves as a standalone application for testing or demonstrating QUIC client capabilities.
# Imports and Dependencies

---
- `../fd_quic.h`
- `fd_quic_test_helpers.h`
- `../../../util/net/fd_ip4.h`
- `stdio.h`
- `string.h`


# Global Variables

---
### g\_conn\_meta
- **Type**: `conn_meta_t[MAX_CONNS]`
- **Description**: `g_conn_meta` is a global array of `conn_meta_t` structures, each representing metadata for a connection in the QUIC protocol. Each element in the array holds a pointer to a connection, an index, and a state indicating the connection's lifecycle stage. The array is sized to accommodate up to `MAX_CONNS` connections, which is defined as 65536.
- **Use**: This variable is used to track and manage the state and metadata of each connection in the QUIC client application.


---
### g\_dead
- **Type**: `int`
- **Description**: The `g_dead` variable is a global integer initialized to the value of `MAX_CONNS`, which is defined as 65536. It represents the number of connections that are currently in a 'dead' state, meaning they are not active or initializing.
- **Use**: `g_dead` is decremented when a new connection is initiated and incremented when a connection is finalized and marked as dead.


---
### g\_init
- **Type**: `int`
- **Description**: The `g_init` variable is a global integer that tracks the number of connections currently in the initialization state. It is initialized to 0 and is incremented or decremented as connections are created or transition to other states.
- **Use**: `g_init` is used to monitor and manage the number of connections that are in the initialization phase within the QUIC client application.


---
### g\_active
- **Type**: `int`
- **Description**: The `g_active` variable is a global integer that tracks the number of active connections in the system. It is initialized to 0 and is incremented or decremented as connections become active or inactive, respectively.
- **Use**: This variable is used to keep a count of currently active connections, which is updated during connection state changes and logged periodically.


# Data Structures

---
### conn\_meta
- **Type**: `struct`
- **Members**:
    - `conn`: A pointer to a `fd_quic_conn_t` structure representing a QUIC connection.
    - `conn_idx`: An unsigned integer representing the index of the connection.
    - `state`: An unsigned integer representing the state of the connection, which can be dead, initializing, or active.
- **Description**: The `conn_meta` structure is used to manage metadata for QUIC connections, including a pointer to the connection object, an index for identifying the connection, and a state indicator to track the connection's lifecycle status. This structure is part of a larger system for handling multiple QUIC connections, allowing for efficient management and state transitions of each connection within the system.


---
### conn\_meta\_t
- **Type**: `struct`
- **Members**:
    - `conn`: A pointer to an fd_quic_conn_t structure representing a QUIC connection.
    - `conn_idx`: An unsigned integer representing the index of the connection.
    - `state`: An unsigned integer representing the state of the connection, which can be dead, initializing, or active.
- **Description**: The `conn_meta_t` structure is used to manage metadata for QUIC connections in a network application. It contains a pointer to the connection object, an index to identify the connection, and a state to track the connection's lifecycle. This structure is part of a larger system that handles multiple connections, allowing for efficient management and tracking of connection states such as dead, initializing, and active.


# Functions

---
### cb\_conn\_new<!-- {{#callable:cb_conn_new}} -->
The `cb_conn_new` function is a placeholder callback for handling new QUIC connections, currently doing nothing with its parameters.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the new QUIC connection.
    - `quic_ctx`: A void pointer to the QUIC context, which can be used to pass additional information or state.
- **Control Flow**:
    - The function takes two parameters, `conn` and `quic_ctx`, but does not use them.
    - Both parameters are explicitly cast to void to suppress unused variable warnings, indicating that the function is a placeholder.
- **Output**: The function does not return any value or produce any output.


---
### cb\_conn\_handshake\_complete<!-- {{#callable:cb_conn_handshake_complete}} -->
The `cb_conn_handshake_complete` function updates the connection state to active and adjusts global counters when a QUIC connection handshake is completed.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the QUIC connection whose handshake has completed.
    - `quic_ctx`: A void pointer to a context object, which is not used in this function.
- **Control Flow**:
    - The function begins by casting the `quic_ctx` parameter to void to indicate it is unused.
    - It retrieves the connection metadata from the global `g_conn_meta` array using the connection index from the `conn` parameter.
    - The state of the connection in the metadata is set to `CONN_STATE_ACTIVE`.
    - The global counter `g_init` is decremented to reflect one less initializing connection.
    - The global counter `g_active` is incremented to reflect one more active connection.
- **Output**: This function does not return any value.


---
### cb\_conn\_final<!-- {{#callable:cb_conn_final}} -->
The `cb_conn_final` function finalizes a QUIC connection by updating its state to dead and adjusting global connection counters accordingly.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the QUIC connection to be finalized.
    - `quic_ctx`: A void pointer to the QUIC context, which is not used in this function.
- **Control Flow**:
    - The function begins by casting the `quic_ctx` to void to indicate it is unused.
    - It retrieves the connection metadata for the given connection index from the global `g_conn_meta` array.
    - The connection pointer in the metadata is set to NULL, indicating the connection is no longer active.
    - A switch statement checks the current state of the connection and adjusts the global counters `g_init`, `g_active`, and `g_dead` based on the state transition to `CONN_STATE_DEAD`.
    - The connection state in the metadata is updated to `CONN_STATE_DEAD`.
- **Output**: The function does not return any value; it modifies global state and connection metadata.


---
### run\_quic\_client<!-- {{#callable:run_quic_client}} -->
The `run_quic_client` function initializes and manages a QUIC client, handling connections and periodically logging connection statistics.
- **Inputs**:
    - `quic`: A pointer to an `fd_quic_t` structure representing the QUIC client instance.
    - `udpsock`: A pointer to an `fd_quic_udpsock_t` structure representing the UDP socket used for network communication.
    - `dst_ip`: An unsigned integer representing the destination IP address for the QUIC connections.
    - `dst_port`: An unsigned short representing the destination port for the QUIC connections.
- **Control Flow**:
    - Set callback functions for new connection, handshake completion, and connection finalization in the `quic` structure.
    - Configure the QUIC client to use the specified UDP socket for network transmission.
    - Initialize the QUIC client using `fd_quic_init` and verify its success with `FD_TEST`.
    - Enter an infinite loop to continuously service the QUIC client and UDP socket.
    - Check if there are any available slots for new connections (`g_dead > 0`).
    - If slots are available, attempt to establish a new connection using `fd_quic_connect` with the specified destination IP and port.
    - If a new connection is successfully established, update the global connection metadata and adjust the connection state counters (`g_dead`, `g_init`).
    - Periodically log the number of active and initializing connections every second.
    - The loop continues indefinitely, managing connections and logging statistics.
- **Output**: The function does not return a value; it runs indefinitely, managing QUIC connections and logging statistics.
- **Functions called**:
    - [`fd_quic_udpsock_service`](fd_quic_test_helpers.c.driver.md#fd_quic_udpsock_service)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes and runs a QUIC client with configurable parameters for IP addresses, ports, and connection limits, managing resources and handling errors throughout the process.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the environment using `fd_boot` with command-line arguments.
    - Extract source IP, destination IP, destination port, number of connections, number of pages, and page size from command-line arguments with default values.
    - Determine CPU and NUMA indices, adjusting if necessary based on system constraints.
    - Convert page size string to a numeric value and validate it, logging an error if unsupported.
    - Check if the number of connections exceeds the maximum allowed and log an error if so.
    - Create a new anonymous workspace with the specified page size, number of pages, and NUMA index, and validate its creation.
    - Define QUIC limits based on the number of connections and calculate the required memory footprint, validating the result.
    - Allocate memory for the QUIC instance and initialize it with the defined limits, validating the instance creation.
    - Initialize a random number generator and configure a test signer for QUIC using TLS test signing context.
    - Convert the source IP string to a numeric address and validate it, logging a notice and returning an error if invalid.
    - Create a UDP socket for the QUIC client and validate its creation.
    - Configure the QUIC client with environment settings, setting specific parameters like role, max stream data, and idle timeout.
    - Convert the destination IP string to a numeric address and validate it, logging a notice and returning an error if invalid.
    - Run the QUIC client using the [`run_quic_client`](#run_quic_client) function with the initialized QUIC instance, UDP socket, destination IP, and port.
    - Free allocated resources for the QUIC instance and UDP socket, and delete the anonymous workspace.
    - Call `fd_halt` to cleanly terminate the program.
    - Return 0 to indicate successful execution.
- **Output**: The function returns an integer, 0 for successful execution or 1 if an error occurs during IP address validation.
- **Functions called**:
    - [`fd_quic_config_test_signer`](fd_quic_test_helpers.c.driver.md#fd_quic_config_test_signer)
    - [`run_quic_client`](#run_quic_client)
    - [`fd_quic_udpsock_destroy`](fd_quic_test_helpers.c.driver.md#fd_quic_udpsock_destroy)



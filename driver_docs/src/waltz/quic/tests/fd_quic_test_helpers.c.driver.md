# Purpose
This C source code file is designed to facilitate testing and simulation of QUIC (Quick UDP Internet Connections) protocol implementations. It provides a suite of functions and utilities to create, configure, and manage QUIC connections, as well as to simulate network conditions such as packet loss and reordering. The file includes functions for setting up QUIC connections with default configurations, handling connection events through callback functions, and managing UDP sockets for network communication. It also includes utilities for logging network traffic to a pcap file, which is useful for debugging and analysis.

The code is structured around several key components: callback functions for handling QUIC connection events, functions for configuring and creating QUIC connections, and utilities for managing network conditions and logging. The file defines a set of default callback implementations for connection events such as new connections, handshake completions, and stream notifications. It also provides functions to create and configure anonymous QUIC connections, including setting up UDP sockets for communication. Additionally, the file includes a network emulator (netem) to simulate packet loss and reordering, which is useful for testing the robustness of QUIC implementations under adverse network conditions. Overall, this file serves as a comprehensive toolkit for testing and simulating QUIC protocol behavior in a controlled environment.
# Imports and Dependencies

---
- `fd_quic_test_helpers.h`
- `../../../util/net/fd_pcapng.h`
- `errno.h`
- `net/if.h`
- `stdlib.h`
- `stdio.h`
- `unistd.h`
- `sys/socket.h`
- `arpa/inet.h`
- `netinet/in.h`
- `../../../ballet/txn/fd_txn.h`
- `../../../util/net/fd_eth.h`
- `../../../util/net/fd_ip4.h`
- `linux/if_link.h`


# Global Variables

---
### fd\_quic\_test\_pcap
- **Type**: `FILE *`
- **Description**: The `fd_quic_test_pcap` is a global variable of type `FILE *` that is used to handle file operations for packet capture (pcap) logging in the QUIC test environment. It is initialized when a pcap file is specified via command line arguments and is used to log QUIC-related data for analysis.
- **Use**: This variable is used to open, write to, and close a pcap file for logging QUIC test data.


---
### test\_ip\_addr\_seq
- **Type**: `uint`
- **Description**: The `test_ip_addr_seq` is a static global variable of type `uint` initialized with an IPv4 address represented by the macro `FD_IP4_ADDR(127, 10, 0, 0)`. This macro likely converts the given IP address components into a single unsigned integer value.
- **Use**: It is used as an IP address counter, incremented for each new QUIC connection to generate unique IP addresses.


# Functions

---
### fd\_quic\_test\_cb\_conn\_new<!-- {{#callable:fd_quic_test_cb_conn_new}} -->
The `fd_quic_test_cb_conn_new` function logs a debug message when a new QUIC connection is created.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the new QUIC connection.
    - `quic_ctx`: A pointer to a context object associated with the QUIC connection.
- **Control Flow**:
    - The function logs a debug message using the `FD_LOG_DEBUG` macro, displaying the memory addresses of the `conn` and `quic_ctx` pointers.
- **Output**: The function does not return any value; it is a void function.


---
### fd\_quic\_test\_cb\_conn\_handshake\_complete<!-- {{#callable:fd_quic_test_cb_conn_handshake_complete}} -->
The function `fd_quic_test_cb_conn_handshake_complete` logs a debug message indicating that a QUIC connection handshake has completed.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the QUIC connection.
    - `quic_ctx`: A void pointer to a context associated with the QUIC connection.
- **Control Flow**:
    - The function logs a debug message using the `FD_LOG_DEBUG` macro, which includes the memory addresses of the `conn` and `quic_ctx` parameters.
- **Output**: The function does not return any value; it is a void function.


---
### fd\_quic\_test\_cb\_conn\_final<!-- {{#callable:fd_quic_test_cb_conn_final}} -->
The `fd_quic_test_cb_conn_final` function logs a debug message indicating the finalization of a QUIC connection.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the QUIC connection being finalized.
    - `quic_ctx`: A pointer to a context object associated with the QUIC connection, typically used for additional data or state management.
- **Control Flow**:
    - The function is called with two parameters: `conn` and `quic_ctx`.
    - A debug log message is generated using the `FD_LOG_DEBUG` macro, which includes the memory addresses of the `conn` and `quic_ctx` pointers.
    - The function does not perform any other operations or return any values.
- **Output**: This function does not return any value; it is a `void` function.


---
### fd\_quic\_test\_cb\_stream\_notify<!-- {{#callable:fd_quic_test_cb_stream_notify}} -->
The `fd_quic_test_cb_stream_notify` function logs a debug message when a QUIC stream notification occurs.
- **Inputs**:
    - `stream`: A pointer to an `fd_quic_stream_t` structure representing the QUIC stream that triggered the notification.
    - `quic_ctx`: A void pointer to the QUIC context associated with the stream.
    - `notify_type`: An integer representing the type of notification that occurred.
- **Control Flow**:
    - The function logs a debug message using the `FD_LOG_DEBUG` macro.
    - The message includes the stream ID, the QUIC context pointer, and the notification type.
- **Output**: The function does not return any value; it is a void function.


---
### fd\_quic\_test\_cb\_stream\_rx<!-- {{#callable:fd_quic_test_cb_stream_rx}} -->
The `fd_quic_test_cb_stream_rx` function logs the reception of data on a QUIC stream and returns a success status.
- **Inputs**:
    - `conn`: A pointer to the QUIC connection (`fd_quic_conn_t *`) associated with the stream receiving data.
    - `stream_id`: An unsigned long integer representing the identifier of the stream receiving data.
    - `offset`: An unsigned long integer indicating the offset in the stream where the data starts.
    - `data`: A pointer to the data buffer (`uchar const *`) containing the received data.
    - `data_sz`: An unsigned long integer representing the size of the data buffer.
    - `fin`: An integer indicating whether this is the final piece of data for the stream (1 if final, 0 otherwise).
- **Control Flow**:
    - Logs the details of the received data on the stream using the `FD_LOG_DEBUG` macro.
    - Returns the constant `FD_QUIC_SUCCESS` to indicate successful handling of the data reception.
- **Output**: The function returns an integer status code, specifically `FD_QUIC_SUCCESS`, indicating successful processing of the received data.


---
### fd\_quic\_test\_cb\_tls\_keylog<!-- {{#callable:fd_quic_test_cb_tls_keylog}} -->
The `fd_quic_test_cb_tls_keylog` function logs TLS key information to a pcap file if logging is enabled.
- **Inputs**:
    - `quic_ctx`: A context pointer for QUIC, which is not used in this function.
    - `line`: A constant character pointer to a line of text representing the TLS key log information.
- **Control Flow**:
    - The function begins by casting the `quic_ctx` to void to indicate it is unused.
    - It checks if the global `fd_quic_test_pcap` file pointer is not NULL, indicating that pcap logging is enabled.
    - If logging is enabled, it calls `fd_pcapng_fwrite_tls_key_log` to write the TLS key log line to the pcap file.
- **Output**: The function does not return any value.


---
### flush\_pcap<!-- {{#callable:flush_pcap}} -->
The `flush_pcap` function flushes the output buffer of the file stream associated with `fd_quic_test_pcap` to ensure all buffered data is written to the file.
- **Inputs**: None
- **Control Flow**:
    - The function calls `fflush` on the global file pointer `fd_quic_test_pcap`.
- **Output**: The function does not return any value.


---
### fd\_quic\_test\_boot<!-- {{#callable:fd_quic_test_boot}} -->
The `fd_quic_test_boot` function initializes logging to a pcap file if the `--pcap` command-line argument is provided.
- **Inputs**:
    - `pargc`: A pointer to an integer representing the number of command-line arguments.
    - `pargv`: A pointer to an array of strings representing the command-line arguments.
- **Control Flow**:
    - The function calls `fd_env_strip_cmdline_cstr` to check if the `--pcap` argument is present in the command-line arguments.
    - If the `--pcap` argument is found, it logs a notice message indicating the pcap file path.
    - It then opens the specified pcap file in append-binary mode and assigns the file pointer to `fd_quic_test_pcap`.
    - The function checks if the file was successfully opened using `FD_TEST`.
    - If successful, it registers the `flush_pcap` function to be called at program exit using `atexit`.
- **Output**: The function does not return any value.


---
### fd\_quic\_test\_halt<!-- {{#callable:fd_quic_test_halt}} -->
The `fd_quic_test_halt` function closes the QUIC test pcap file if it is open and sets the file pointer to NULL.
- **Inputs**: None
- **Control Flow**:
    - Check if the global file pointer `fd_quic_test_pcap` is not NULL, indicating that a pcap file is open.
    - If the file is open, call `fclose` on `fd_quic_test_pcap` to close the file and assert that the operation was successful using `FD_TEST`.
    - Set `fd_quic_test_pcap` to NULL to indicate that no pcap file is currently open.
- **Output**: The function does not return any value.


---
### fd\_quic\_config\_anonymous<!-- {{#callable:fd_quic_config_anonymous}} -->
The `fd_quic_config_anonymous` function initializes a QUIC configuration with default settings and callbacks for a given role.
- **Inputs**:
    - `quic`: A pointer to an `fd_quic_t` structure that will be configured.
    - `role`: An integer representing the role to be assigned to the QUIC configuration.
- **Control Flow**:
    - Retrieve the configuration from the provided `fd_quic_t` structure and set its role to the provided `role` argument.
    - Increment the global `test_ip_addr_seq` variable to generate a new IP address.
    - Set default configuration values for idle timeout, acknowledgment delay, acknowledgment threshold, and initial maximum stream data.
    - Assign default callback functions for various QUIC events such as connection creation, handshake completion, connection finalization, stream notifications, stream reception, and TLS key logging.
    - Set the `now_ctx` callback context to `NULL`.
- **Output**: The function does not return a value; it modifies the `fd_quic_t` structure pointed to by `quic`.


---
### fd\_quic\_config\_test\_signer<!-- {{#callable:fd_quic_config_test_signer}} -->
The `fd_quic_config_test_signer` function configures a QUIC instance with a test signing context and public key for identity verification.
- **Inputs**:
    - `quic`: A pointer to an `fd_quic_t` structure representing the QUIC instance to be configured.
    - `sign_ctx`: A pointer to an `fd_tls_test_sign_ctx_t` structure containing the signing context and public key to be used for the QUIC instance.
- **Control Flow**:
    - Retrieve the configuration structure from the provided QUIC instance.
    - Copy the public key from the signing context to the QUIC configuration's identity public key field.
    - Assign the signing context to the QUIC configuration's sign context field.
    - Set the sign function in the QUIC configuration to `fd_tls_test_sign_sign`.
- **Output**: This function does not return a value; it modifies the configuration of the provided QUIC instance in place.


---
### fd\_quic\_new\_anonymous<!-- {{#callable:fd_quic_new_anonymous}} -->
The `fd_quic_new_anonymous` function initializes a new QUIC instance with anonymous configuration and test signing context.
- **Inputs**:
    - `wksp`: A pointer to the workspace (`fd_wksp_t`) where memory allocations for the QUIC instance will be made.
    - `limits`: A constant pointer to `fd_quic_limits_t` that specifies the resource limits for the QUIC instance.
    - `role`: An integer representing the role of the QUIC instance (e.g., client or server).
    - `rng`: A pointer to a random number generator (`fd_rng_t`) used for cryptographic operations.
- **Control Flow**:
    - Allocate memory for the QUIC instance using `fd_wksp_alloc_laddr` with alignment and footprint based on the provided limits.
    - Create a new QUIC instance with `fd_quic_new` using the allocated memory and limits, and verify its success with `FD_TEST`.
    - Join the newly created QUIC instance with `fd_quic_join` and verify its success with `FD_TEST`.
    - Configure the QUIC instance for anonymous operation using [`fd_quic_config_anonymous`](#fd_quic_config_anonymous) with the specified role.
    - Allocate memory for a test signing context using `fd_wksp_alloc_laddr` and initialize it with `fd_tls_test_sign_ctx` using the provided RNG.
    - Configure the QUIC instance to use the test signing context with [`fd_quic_config_test_signer`](#fd_quic_config_test_signer).
    - Return the configured QUIC instance.
- **Output**: A pointer to the newly created and configured `fd_quic_t` instance.
- **Functions called**:
    - [`fd_quic_config_anonymous`](#fd_quic_config_anonymous)
    - [`fd_quic_config_test_signer`](#fd_quic_config_test_signer)


---
### fd\_quic\_new\_anonymous\_small<!-- {{#callable:fd_quic_new_anonymous_small}} -->
The `fd_quic_new_anonymous_small` function creates a new anonymous QUIC instance with predefined small limits for connection and stream management.
- **Inputs**:
    - `wksp`: A pointer to the workspace (`fd_wksp_t`) where the QUIC instance will be allocated.
    - `role`: An integer representing the role of the QUIC instance (e.g., client or server).
    - `rng`: A pointer to a random number generator (`fd_rng_t`) used for cryptographic operations.
- **Control Flow**:
    - Initialize a `fd_quic_limits_t` structure with predefined small limits for various QUIC parameters such as connection count, handshake count, connection ID count, inflight frame count, transmission buffer size, and stream pool count.
    - Call the [`fd_quic_new_anonymous`](#fd_quic_new_anonymous) function with the workspace, the initialized limits, the role, and the random number generator to create and return a new anonymous QUIC instance.
- **Output**: Returns a pointer to the newly created `fd_quic_t` instance.
- **Functions called**:
    - [`fd_quic_new_anonymous`](#fd_quic_new_anonymous)


---
### fd\_quic\_virtual\_pair\_direct<!-- {{#callable:fd_quic_virtual_pair_direct}} -->
The `fd_quic_virtual_pair_direct` function sets up a direct virtual connection between two QUIC instances by configuring their asynchronous I/O (AIO) network transmission and reception.
- **Inputs**:
    - `pair`: A pointer to an `fd_quic_virtual_pair_t` structure that will hold the configuration of the virtual pair.
    - `quic_a`: A pointer to the first `fd_quic_t` QUIC instance to be connected.
    - `quic_b`: A pointer to the second `fd_quic_t` QUIC instance to be connected.
- **Control Flow**:
    - Assigns `quic_a` to `pair->quic_a` and `quic_b` to `pair->quic_b` to store the QUIC instances in the pair structure.
    - Retrieves the AIO network receive (RX) interface for `quic_a` and `quic_b` using `fd_quic_get_aio_net_rx`.
    - Sets the AIO network transmit (TX) interface of `quic_a` to the RX interface of `quic_b` and vice versa using `fd_quic_set_aio_net_tx`.
    - Stores the RX interfaces in `pair->aio_a2b` and `pair->aio_b2a` to represent the direction of data flow between the two QUIC instances.
- **Output**: The function does not return a value; it modifies the `fd_quic_virtual_pair_t` structure pointed to by `pair` to establish the virtual connection.


---
### fd\_quic\_virtual\_pair\_pcap<!-- {{#callable:fd_quic_virtual_pair_pcap}} -->
The `fd_quic_virtual_pair_pcap` function sets up a virtual QUIC connection pair with packet capture capabilities, allowing network traffic between two QUIC instances to be logged to a pcap file.
- **Inputs**:
    - `pair`: A pointer to an `fd_quic_virtual_pair_t` structure that will hold the virtual pair configuration.
    - `quic_a`: A pointer to the first `fd_quic_t` QUIC instance involved in the virtual pair.
    - `quic_b`: A pointer to the second `fd_quic_t` QUIC instance involved in the virtual pair.
    - `pcap`: A pointer to a `FILE` object where the pcap data will be written.
- **Control Flow**:
    - Assigns `quic_a` and `quic_b` to the `pair` structure's `quic_a` and `quic_b` fields respectively.
    - Retrieves the asynchronous I/O network receive interfaces for both `quic_a` and `quic_b`.
    - Starts the pcapng file with a Layer 3 header using `fd_aio_pcapng_start_l3`.
    - Joins the receive interfaces to the pcapng capture for both directions (b2a and a2b) using `fd_aio_pcapng_join`.
    - Sets the asynchronous I/O network transmit interfaces for `quic_a` and `quic_b` to the pcapng capture interfaces for the opposite direction using `fd_quic_set_aio_net_tx`.
    - Assigns the local pcapng capture interfaces to `pair->aio_a2b` and `pair->aio_b2a`.
- **Output**: The function does not return a value; it modifies the `pair` structure to configure the virtual QUIC pair with pcap logging.


---
### fd\_quic\_virtual\_pair\_init<!-- {{#callable:fd_quic_virtual_pair_init}} -->
The `fd_quic_virtual_pair_init` function initializes a virtual pair of QUIC instances, setting up direct or pcap-based communication between them based on the presence of a pcap file.
- **Inputs**:
    - `pair`: A pointer to an `fd_quic_virtual_pair_t` structure that will be initialized.
    - `quic_a`: A pointer to the first `fd_quic_t` QUIC instance to be paired.
    - `quic_b`: A pointer to the second `fd_quic_t` QUIC instance to be paired.
- **Control Flow**:
    - The function begins by zeroing out the memory of the `pair` structure using `memset`.
    - It checks if the global `fd_quic_test_pcap` file pointer is NULL.
    - If `fd_quic_test_pcap` is NULL, it calls [`fd_quic_virtual_pair_direct`](#fd_quic_virtual_pair_direct) to set up direct communication between `quic_a` and `quic_b`.
    - If `fd_quic_test_pcap` is not NULL, it calls [`fd_quic_virtual_pair_pcap`](#fd_quic_virtual_pair_pcap) to set up communication with pcap logging between `quic_a` and `quic_b`.
- **Output**: The function does not return a value; it initializes the `fd_quic_virtual_pair_t` structure pointed to by `pair`.
- **Functions called**:
    - [`fd_quic_virtual_pair_direct`](#fd_quic_virtual_pair_direct)
    - [`fd_quic_virtual_pair_pcap`](#fd_quic_virtual_pair_pcap)


---
### fd\_quic\_virtual\_pair\_fini<!-- {{#callable:fd_quic_virtual_pair_fini}} -->
The `fd_quic_virtual_pair_fini` function finalizes a QUIC virtual pair by cleaning up pcapng resources and resetting network transmission settings.
- **Inputs**:
    - `pair`: A pointer to an `fd_quic_virtual_pair_t` structure representing the QUIC virtual pair to be finalized.
- **Control Flow**:
    - Check if the `pcapng_a2b` member of the `pair` structure has a non-null `pcapng` field.
    - If it does, call `fd_aio_pcapng_leave` on both `pcapng_a2b` and `pcapng_b2a` to leave the pcapng sessions.
    - Set the asynchronous I/O network transmission targets for `quic_a` and `quic_b` to `NULL` using `fd_quic_set_aio_net_tx`.
- **Output**: This function does not return a value; it performs cleanup operations on the provided `fd_quic_virtual_pair_t` structure.


---
### fd\_aio\_eth\_wrap\_send<!-- {{#callable:fd_aio_eth_wrap_send}} -->
The `fd_aio_eth_wrap_send` function sends a batch of Ethernet packets by wrapping them with a predefined Ethernet header and forwarding them to the next layer in the network stack.
- **Inputs**:
    - `ctx`: A pointer to the context, specifically a `fd_aio_eth_wrap_t` structure, which contains the Ethernet header template and the next layer to send the packet to.
    - `batch`: A pointer to an array of `fd_aio_pkt_info_t` structures, each representing a packet to be sent.
    - `batch_cnt`: The number of packets in the batch to be sent.
    - `opt_batch_idx`: An optional pointer to a variable that is unused in this function.
    - `flush`: An integer flag indicating whether to flush the send operation, typically set to true for the last packet in a batch.
- **Control Flow**:
    - Initialize a static buffer `frame` to hold the Ethernet frame data.
    - Iterate over each packet in the batch using a loop from 0 to `batch_cnt - 1`.
    - For each packet, determine if it is the last packet in the batch and set `flush2` accordingly.
    - Create a new `fd_aio_pkt_info_t` structure `pkt` with the buffer pointing to `frame` and buffer size set to the minimum of the packet size plus 14 bytes (for the Ethernet header) and the size of `frame`.
    - Copy the Ethernet header template from `wrap->template` into the beginning of `frame`.
    - Copy the packet data from `batch[j].buf` into `frame` starting at offset 14.
    - Call `fd_aio_send` to send the packet `pkt` to the next layer specified in `wrap->wrap_next`, with `flush2` indicating whether to flush.
- **Output**: The function returns `FD_AIO_SUCCESS` to indicate successful completion of the send operation.


---
### fd\_aio\_eth\_wrap<!-- {{#callable:fd_aio_eth_wrap}} -->
The `fd_aio_eth_wrap` function initializes an `fd_aio_t` structure within an `fd_aio_eth_wrap_t` wrapper to use a specific send function for Ethernet packet handling.
- **Inputs**:
    - `wrap`: A pointer to an `fd_aio_eth_wrap_t` structure that contains the context and function pointers for Ethernet packet handling.
- **Control Flow**:
    - The function sets the `ctx` field of `wrap->wrap_self` to point to the `wrap` structure itself, establishing the context for the send function.
    - The `send_func` field of `wrap->wrap_self` is set to `fd_aio_eth_wrap_send`, which is the function responsible for sending Ethernet packets.
    - The function returns a pointer to the `wrap_self` field of the `wrap` structure, which is an `fd_aio_t` type.
- **Output**: A pointer to the `fd_aio_t` structure within the `fd_aio_eth_wrap_t` wrapper, which is configured to handle Ethernet packet sending.


---
### fd\_aio\_eth\_unwrap\_send<!-- {{#callable:fd_aio_eth_unwrap_send}} -->
The `fd_aio_eth_unwrap_send` function processes a batch of Ethernet packets by removing the Ethernet header and sending the modified packets to the next stage in the processing pipeline.
- **Inputs**:
    - `ctx`: A pointer to a `fd_aio_eth_wrap_t` structure, which contains context information for the unwrapping process.
    - `batch`: A pointer to an array of `fd_aio_pkt_info_t` structures, each representing a packet to be processed.
    - `batch_cnt`: The number of packets in the batch to be processed.
    - `opt_batch_idx`: An optional pointer to a variable that is not used in this function (indicated by `FD_PARAM_UNUSED`).
    - `flush`: An integer flag indicating whether the operation should be flushed, typically used to ensure all data is processed immediately.
- **Control Flow**:
    - The function begins by casting the `ctx` pointer to a `fd_aio_eth_wrap_t` pointer named `wrap`.
    - A loop iterates over each packet in the `batch`, from index 0 to `batch_cnt - 1`.
    - For each packet, it calculates whether the `flush` flag should be set for the current packet by checking if it is the last packet in the batch.
    - It creates a new `fd_aio_pkt_info_t` structure `pkt` for each packet, adjusting the buffer pointer to skip the first 14 bytes (the Ethernet header) and adjusting the buffer size accordingly.
    - The modified packet `pkt` is then sent using the `fd_aio_send` function, targeting the `unwrap_next` field of the `wrap` structure.
- **Output**: The function returns `FD_AIO_SUCCESS`, indicating successful processing of the packet batch.


---
### fd\_aio\_eth\_unwrap<!-- {{#callable:fd_aio_eth_unwrap}} -->
The `fd_aio_eth_unwrap` function initializes and returns a pointer to an `fd_aio_t` structure for unwrapping Ethernet frames.
- **Inputs**:
    - `wrap`: A pointer to an `fd_aio_eth_wrap_t` structure that contains the context and function pointers for Ethernet frame unwrapping.
- **Control Flow**:
    - The function sets the `ctx` field of `unwrap_self` in the `wrap` structure to point to the `wrap` itself.
    - The function assigns the `fd_aio_eth_unwrap_send` function to the `send_func` field of `unwrap_self`.
    - The function returns a pointer to the `unwrap_self` field of the `wrap` structure.
- **Output**: A pointer to the `unwrap_self` field of the `fd_aio_eth_wrap_t` structure, which is an `fd_aio_t` structure configured for unwrapping Ethernet frames.


---
### fd\_quic\_client\_create\_udpsock<!-- {{#callable:fd_quic_client_create_udpsock}} -->
The `fd_quic_client_create_udpsock` function creates and initializes a UDP socket for a QUIC client, binding it to a specified IP address and setting up necessary resources for data transmission and reception.
- **Inputs**:
    - `udpsock`: A pointer to an `fd_quic_udpsock_t` structure where the created UDP socket information will be stored.
    - `wksp`: A pointer to an `fd_wksp_t` workspace used for memory allocation.
    - `rx_aio`: A constant pointer to an `fd_aio_t` structure for asynchronous I/O operations, specifically for receiving data.
    - `listen_ip`: An unsigned integer representing the IP address to which the UDP socket will be bound.
- **Control Flow**:
    - Initialize default values for MTU, RX depth, and TX depth.
    - Create a UDP socket using `socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)` and check for errors.
    - Set up a `sockaddr_in` structure with the provided `listen_ip` and bind the socket to it, checking for errors.
    - Allocate memory for the UDP socket using `fd_wksp_alloc_laddr` and check for allocation success.
    - Create and join a new UDP socket using `fd_udpsock_new` and `fd_udpsock_join`, checking for errors.
    - Set the UDP socket layer to IP using `fd_udpsock_set_layer`.
    - Initialize the `udpsock` structure with the created socket, file descriptor, and other parameters.
    - Set the RX asynchronous I/O operations using `fd_udpsock_set_rx`.
    - Log a notice indicating the UDP socket is listening on the specified IP and port.
- **Output**: Returns a pointer to the initialized `fd_quic_udpsock_t` structure on success, or `NULL` on failure.


---
### fd\_quic\_udpsock\_create<!-- {{#callable:fd_quic_udpsock_create}} -->
The `fd_quic_udpsock_create` function initializes and configures a UDP socket for QUIC communication, setting up its parameters and binding it to a specified IP and port.
- **Inputs**:
    - `_sock`: A pointer to a pre-allocated `fd_quic_udpsock_t` structure where the socket information will be stored.
    - `pargc`: A pointer to an integer representing the number of command-line arguments.
    - `pargv`: A pointer to an array of strings representing the command-line arguments.
    - `wksp`: A pointer to a `fd_wksp_t` workspace used for memory allocation.
    - `rx_aio`: A constant pointer to an `fd_aio_t` structure for asynchronous I/O operations.
- **Control Flow**:
    - Extracts configuration parameters such as MTU, RX depth, TX depth, listen IP, and listen port from command-line arguments using `fd_env_strip_cmdline_*` functions.
    - Converts the listen IP string to a numeric IP address using `fd_cstr_to_ip4_addr` and logs an error if conversion fails.
    - Creates a UDP socket using `socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)` and logs a warning if socket creation fails.
    - Binds the socket to the specified IP and port using `bind` and logs a warning if binding fails.
    - Allocates memory for the UDP socket using `fd_wksp_alloc_laddr` and logs a warning if allocation fails.
    - Initializes the UDP socket with `fd_udpsock_new` and joins it with `fd_udpsock_join`, logging a warning if joining fails.
    - Sets the socket layer to IP using `fd_udpsock_set_layer`.
    - Configures the `fd_quic_udpsock_t` structure with the created socket, workspace, and asynchronous I/O settings.
    - Logs a notice indicating the UDP socket is listening on the specified IP and port.
- **Output**: Returns a pointer to the initialized `fd_quic_udpsock_t` structure, or `NULL` if any step fails.


---
### fd\_quic\_udpsock\_destroy<!-- {{#callable:fd_quic_udpsock_destroy}} -->
The `fd_quic_udpsock_destroy` function deallocates and closes a QUIC UDP socket based on its type.
- **Inputs**:
    - `udpsock`: A pointer to an `fd_quic_udpsock_t` structure representing the UDP socket to be destroyed.
- **Control Flow**:
    - Check if the `udpsock` pointer is NULL; if so, return NULL immediately.
    - Switch on the `type` of the `udpsock`.
    - If the type is `FD_QUIC_UDPSOCK_TYPE_UDPSOCK`, perform the following actions:
    - Call `fd_udpsock_leave` to leave the UDP socket, then `fd_udpsock_delete` to delete it, and finally `fd_wksp_free_laddr` to free the allocated memory.
    - Close the socket file descriptor using `close`.
    - Return the `udpsock` pointer.
- **Output**: Returns the `udpsock` pointer after it has been destroyed, or NULL if the input was NULL.


---
### fd\_quic\_udpsock\_service<!-- {{#callable:fd_quic_udpsock_service}} -->
The `fd_quic_udpsock_service` function services a UDP socket based on its type.
- **Inputs**:
    - `udpsock`: A constant pointer to an `fd_quic_udpsock_t` structure representing the UDP socket to be serviced.
- **Control Flow**:
    - The function checks the type of the `udpsock` using a switch statement.
    - If the type is `FD_QUIC_UDPSOCK_TYPE_UDPSOCK`, it calls `fd_udpsock_service` with the socket from `udpsock` to perform the service operation.
    - The function does not handle any other types and does not have a default case.
- **Output**: The function does not return any value; it performs an action based on the type of the UDP socket.


---
### fd\_quic\_netem\_init<!-- {{#callable:fd_quic_netem_init}} -->
The `fd_quic_netem_init` function initializes a QUIC network emulator structure with specified drop and reorder thresholds and sets up asynchronous I/O for packet sending.
- **Inputs**:
    - `netem`: A pointer to an `fd_quic_netem_t` structure that will be initialized.
    - `thres_drop`: A float representing the threshold probability for dropping packets.
    - `thres_reorder`: A float representing the threshold probability for reordering packets.
- **Control Flow**:
    - The function initializes the `netem` structure with the provided drop and reorder thresholds.
    - It calls `fd_aio_new` to set up asynchronous I/O for the `netem` structure, associating it with the `fd_quic_netem_send` function.
    - The initialized `netem` structure is returned.
- **Output**: Returns a pointer to the initialized `fd_quic_netem_t` structure.


---
### fd\_quic\_netem\_send<!-- {{#callable:fd_quic_netem_send}} -->
The `fd_quic_netem_send` function simulates network conditions by randomly dropping, reordering, or sending packets based on predefined thresholds.
- **Inputs**:
    - `ctx`: A pointer to a `fd_quic_netem_t` structure that contains the network emulation context, including thresholds for dropping and reordering packets.
    - `batch`: A pointer to an array of `fd_aio_pkt_info_t` structures representing the packets to be processed.
    - `batch_cnt`: The number of packets in the batch to be processed.
    - `opt_batch_idx`: An optional pointer to a variable for batch index, marked as unused in this function.
    - `flush`: An integer flag indicating whether to flush the send operation immediately.
- **Control Flow**:
    - Initialize a pointer to the network emulation context from the input `ctx`.
    - Iterate over each packet in the batch using a loop.
    - For each packet, generate a random number to decide whether to drop, reorder, or send the packet based on thresholds.
    - If the random number is below the drop threshold, skip sending the packet.
    - If the random number is below the reorder threshold, attempt to buffer the packet for reordering; if buffers are full, send the most recent buffered packet and replace it with the current packet.
    - If the packet is neither dropped nor reordered, send it immediately.
    - After processing each packet, check if there are any buffered packets that need to be sent and send them if necessary.
- **Output**: The function returns `FD_AIO_SUCCESS` to indicate successful processing of the packet batch.



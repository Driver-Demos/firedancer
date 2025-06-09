# Purpose
This C source code file is designed to facilitate benchmarking and testing of QUIC (Quick UDP Internet Connections) protocol implementations. It integrates with a larger system, as indicated by the inclusion of headers from specific directories, and is structured to handle network communication using the QUIC protocol. The file defines a context structure, `fd_benchs_ctx_t`, which holds various state information and resources needed for managing QUIC connections, such as connection file descriptors, poll file descriptors, and buffers for sending and receiving data. The code includes functions for initializing the context, handling new QUIC connections, processing incoming packets, and sending data using asynchronous I/O operations.

The file provides a specialized functionality focused on network communication and testing within a larger framework, as evidenced by its integration with other components through included headers and the use of specific data structures and functions. It defines several static functions that manage the lifecycle of QUIC connections, including connection establishment, data transmission, and error handling. The code also includes mechanisms for batching network operations to optimize performance, such as using `recvmmsg` and `sendmmsg` for efficient message handling. The file is not intended to be a standalone executable but rather a component of a larger system, as indicated by the absence of a `main` function and the presence of a `fd_topo_run_tile_t` structure, which suggests it is part of a modular or plugin-based architecture.
# Imports and Dependencies

---
- `../../../../disco/topo/fd_topo.h`
- `../../../../waltz/quic/fd_quic.h`
- `../../../../waltz/quic/tests/fd_quic_test_helpers.h`
- `../../../../waltz/tls/test_tls_helper.h`
- `errno.h`
- `linux/unistd.h`
- `sys/types.h`
- `sys/socket.h`
- `netinet/in.h`
- `string.h`
- `unistd.h`
- `poll.h`
- `stdio.h`
- `stdlib.h`
- `time.h`
- `../../../../disco/stem/fd_stem.c`


# Global Variables

---
### fd\_tile\_benchs
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_benchs` variable is a global instance of the `fd_topo_run_tile_t` structure, which is used to define a tile in a topology for benchmarking purposes. It contains configuration and function pointers necessary for initializing and running a tile, such as alignment, footprint, and initialization functions. The structure is specifically configured for a tile named 'benchs', indicating its role in benchmarking operations.
- **Use**: This variable is used to configure and manage a tile in a topology for benchmarking, providing necessary initialization and execution functions.


# Data Structures

---
### fd\_benchs\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `round_robin_cnt`: Stores the count for round-robin operations.
    - `round_robin_id`: Stores the identifier for round-robin operations.
    - `packet_cnt`: Tracks the number of packets processed.
    - `conn_cnt`: Holds the count of active connections.
    - `conn_fd`: Array of file descriptors for connections.
    - `poll_fd`: Array of pollfd structures for polling connections.
    - `test_signer`: Holds the context for TLS test signing.
    - `no_quic`: Flag indicating whether QUIC is disabled.
    - `quic`: Pointer to a QUIC context.
    - `quic_port`: Stores the port number for QUIC connections.
    - `quic_conn`: Pointer to a QUIC connection.
    - `no_stream`: Tracks the number of streams not available.
    - `service_ratio_idx`: Index for service ratio management.
    - `tx_aio`: Asynchronous I/O context for transmission.
    - `rx_msgs`: Array of mmsghdr structures for receiving messages.
    - `tx_msgs`: Array of mmsghdr structures for transmitting messages.
    - `rx_iovecs`: Array of iovec structures for receiving data.
    - `tx_iovecs`: Array of iovec structures for transmitting data.
    - `rx_bufs`: Buffers for receiving data.
    - `tx_bufs`: Buffers for transmitting data.
    - `tx_idx`: Index for tracking transmission operations.
    - `mem`: Pointer to a workspace memory context.
- **Description**: The `fd_benchs_ctx_t` structure is a comprehensive context used for managing network operations, particularly focusing on QUIC protocol handling and asynchronous I/O operations. It includes fields for managing round-robin operations, connection details, and packet processing. The structure also integrates arrays for handling multiple connections and message buffers, supporting both receiving and transmitting operations. Additionally, it contains fields for managing QUIC-specific operations, such as connection contexts and port management, and provides a workspace memory pointer for efficient data handling.


# Functions

---
### quic\_now<!-- {{#callable:quic_now}} -->
The `quic_now` function returns the current timestamp in UNIX time by calling the `fd_log_wallclock` function.
- **Inputs**:
    - `ctx`: A void pointer to a context, which is not used in this function.
- **Control Flow**:
    - The function takes a single argument, `ctx`, which is not used in the function body.
    - It calls the `fd_log_wallclock` function to get the current wall clock time.
    - The result from `fd_log_wallclock` is cast to an `ulong` and returned as the function's output.
- **Output**: The function returns the current timestamp as an `ulong`, representing the UNIX time.


---
### service\_quic<!-- {{#callable:service_quic}} -->
The `service_quic` function processes incoming data from sockets and passes it to a QUIC engine for further handling.
- **Inputs**:
    - `ctx`: A pointer to an `fd_benchs_ctx_t` structure containing context information for the QUIC service, including socket file descriptors, connection count, and buffers for receiving messages.
- **Control Flow**:
    - Check if QUIC is enabled by verifying `ctx->no_quic` is false.
    - Use `poll` to check for available data on the sockets specified in `ctx->poll_fd`.
    - If `poll` returns 0, exit the function as no data is available.
    - If `poll` returns -1, check for `EINTR` to retry later or log an error if another error occurs.
    - Iterate over each connection in `ctx->poll_fd` to check for events.
    - If `POLLIN` is set, use `recvmmsg` to receive multiple messages into `ctx->rx_msgs` and handle errors if any occur.
    - For each received message, prepare the buffer by setting IP and UDP headers and pass it to the QUIC engine using `fd_quic_process_packet`.
    - If `POLLERR` is set, retrieve and log the socket error using `getsockopt`.
- **Output**: The function does not return a value; it processes incoming data and passes it to the QUIC engine for further handling.


---
### quic\_conn\_new<!-- {{#callable:quic_conn_new}} -->
The `quic_conn_new` function is a placeholder function that is called by the QUIC engine when a new connection is being established, but it currently does nothing with its parameters.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the new QUIC connection.
    - `_ctx`: A pointer to a context object, which is not used in this function.
- **Control Flow**:
    - The function takes two parameters: a connection object and a context object.
    - Both parameters are cast to void to indicate they are unused, effectively making the function a no-op.
- **Output**: The function does not produce any output or perform any operations.


---
### handshake\_complete<!-- {{#callable:handshake_complete}} -->
The `handshake_complete` function logs a notice indicating that a client handshake has been completed.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the QUIC connection.
    - `_ctx`: A void pointer to a context, which is not used in this function.
- **Control Flow**:
    - The function takes two parameters, `conn` and `_ctx`, but does not use them, as indicated by the `(void)` casts.
    - It logs a notice message 'client handshake complete' using the `FD_LOG_NOTICE` macro.
- **Output**: The function does not return any value.


---
### conn\_final<!-- {{#callable:conn_final}} -->
The `conn_final` function sets the `quic_conn` field of a `fd_benchs_ctx_t` context to `NULL` when the context is not `NULL`.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure, which is not used in this function.
    - `_ctx`: A pointer to a `void` type, expected to be cast to a `fd_benchs_ctx_t` structure.
- **Control Flow**:
    - The function begins by casting the `_ctx` parameter to a `fd_benchs_ctx_t` pointer named `ctx`.
    - It checks if `ctx` is not `NULL`.
    - If `ctx` is not `NULL`, it sets the `quic_conn` field of `ctx` to `NULL`.
- **Output**: This function does not return any value; it modifies the `quic_conn` field of the provided context.


---
### scratch\_align<!-- {{#callable:scratch_align}} -->
The `scratch_align` function returns the maximum alignment requirement between the QUIC alignment and the `fd_benchs_ctx_t` structure alignment.
- **Inputs**: None
- **Control Flow**:
    - The function calls `fd_quic_align()` to get the alignment requirement for QUIC.
    - It calls `alignof(fd_benchs_ctx_t)` to get the alignment requirement for the `fd_benchs_ctx_t` structure.
    - It returns the maximum of these two alignment values using `fd_ulong_max()`.
- **Output**: The function returns an `ulong` representing the maximum alignment requirement between QUIC and `fd_benchs_ctx_t`.


---
### populate\_quic\_limits<!-- {{#callable:populate_quic_limits}} -->
The `populate_quic_limits` function initializes a `fd_quic_limits_t` structure with predefined limits for various QUIC parameters.
- **Inputs**:
    - `limits`: A pointer to an `fd_quic_limits_t` structure that will be populated with specific QUIC limit values.
- **Control Flow**:
    - Set `conn_cnt` to 2, indicating the number of connections.
    - Set `handshake_cnt` to the value of `conn_cnt`, implying the same number of handshakes as connections.
    - Set `conn_id_cnt` to 16, defining the number of connection IDs.
    - Set `inflight_frame_cnt` to 1500, specifying the number of inflight frames allowed.
    - Set `tx_buf_sz` to `FD_TXN_MTU`, defining the size of the transmission buffer.
    - Set `stream_pool_cnt` to `1UL<<16`, indicating the number of streams in the pool.
    - Set `stream_id_cnt` to `1UL<<16`, specifying the number of stream IDs.
- **Output**: The function does not return a value; it modifies the `limits` structure in place.


---
### populate\_quic\_config<!-- {{#callable:populate_quic_config}} -->
The `populate_quic_config` function initializes a `fd_quic_config_t` structure with default configuration values for a QUIC client.
- **Inputs**:
    - `config`: A pointer to an `fd_quic_config_t` structure that will be populated with default configuration values.
- **Control Flow**:
    - Set the `role` field of the `config` structure to `FD_QUIC_ROLE_CLIENT`, indicating the configuration is for a client role.
    - Set the `retry` field of the `config` structure to `0`, disabling retry attempts.
    - Set the `initial_rx_max_stream_data` field of the `config` structure to `0`, assuming the server will not initiate streams.
    - Set the `net.dscp` field of the `config` structure to `0`, indicating no specific DSCP value is set.
- **Output**: The function does not return a value; it modifies the `fd_quic_config_t` structure pointed to by the `config` parameter.


---
### scratch\_footprint<!-- {{#callable:scratch_footprint}} -->
The `scratch_footprint` function calculates the memory footprint required for a given tile, including optional QUIC resources if enabled.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure representing the tile for which the memory footprint is being calculated.
- **Control Flow**:
    - Initialize a variable `l` with `FD_LAYOUT_INIT` to start the layout calculation.
    - Append the alignment and size of `fd_benchs_ctx_t` to `l` using `FD_LAYOUT_APPEND`.
    - Check if the `no_quic` flag in the `tile` structure is not set (i.e., QUIC is enabled).
    - If QUIC is enabled, initialize a `fd_quic_limits_t` structure and populate it with default limits using [`populate_quic_limits`](#populate_quic_limits).
    - Calculate the QUIC footprint using `fd_quic_footprint` and append its alignment and size to `l` using `FD_LAYOUT_APPEND`.
    - Finalize the layout calculation with `FD_LAYOUT_FINI`, using [`scratch_align`](#scratch_align) to determine the final alignment, and return the result.
- **Output**: Returns an `ulong` representing the total memory footprint required for the tile, including optional QUIC resources if enabled.
- **Functions called**:
    - [`populate_quic_limits`](#populate_quic_limits)
    - [`scratch_align`](#scratch_align)


---
### before\_frag<!-- {{#callable:before_frag}} -->
The `before_frag` function determines if a given sequence number should be processed based on a round-robin scheduling mechanism.
- **Inputs**:
    - `ctx`: A pointer to an `fd_benchs_ctx_t` structure containing context information, including round-robin parameters.
    - `in_idx`: An unsigned long integer representing the input index, which is not used in this function.
    - `seq`: An unsigned long integer representing the sequence number to be checked.
    - `sig`: An unsigned long integer representing a signature, which is not used in this function.
- **Control Flow**:
    - The function begins by explicitly ignoring the `in_idx` and `sig` parameters using `(void)` casts, indicating they are not used in the function logic.
    - It calculates the modulus of the `seq` parameter with `ctx->round_robin_cnt` to determine the current round-robin position.
    - It compares the result of the modulus operation to `ctx->round_robin_id`.
    - The function returns an integer indicating whether the current sequence number's round-robin position does not match the expected `round_robin_id`.
- **Output**: The function returns an integer, which is 0 if the sequence number's round-robin position matches `ctx->round_robin_id`, and non-zero otherwise.


---
### during\_frag<!-- {{#callable:during_frag}} -->
The `during_frag` function handles the transmission of data chunks either through a direct socket send or via a QUIC connection, depending on the context configuration.
- **Inputs**:
    - `ctx`: A pointer to the `fd_benchs_ctx_t` context structure containing configuration and state information for the operation.
    - `in_idx`: An unused parameter, presumably intended for input index tracking.
    - `seq`: An unused parameter, presumably intended for sequence number tracking.
    - `sig`: An unused parameter, presumably intended for signal tracking.
    - `chunk`: The memory chunk to be sent, represented as an offset or identifier.
    - `sz`: The size of the data chunk to be sent.
    - `ctl`: An unused parameter, presumably intended for control information.
- **Control Flow**:
    - Check if QUIC is not used (`ctx->no_quic` is true).
    - If not using QUIC, send the data chunk using a socket and increment the packet count.
    - If using QUIC, check if the service ratio index has reached 8, reset it, and call [`service_quic`](#service_quic) and `fd_quic_service`.
    - If there is no active QUIC connection (`ctx->quic_conn` is null), attempt to establish a new QUIC connection.
    - If the connection attempt fails, call [`service_quic`](#service_quic) and `fd_quic_service` and return.
    - If a new connection is established, log the event, set the connection context, and call [`service_quic`](#service_quic) and `fd_quic_service`.
    - If a QUIC connection exists, attempt to create a new QUIC stream.
    - If stream creation fails, increment the no-stream counter, call [`service_quic`](#service_quic) and `fd_quic_service`, and return.
    - If a stream is successfully created, send the data chunk over the stream, increment the packet count, and check for errors in the send operation.
- **Output**: The function does not return a value; it performs operations based on the context and updates the state within the `fd_benchs_ctx_t` structure.
- **Functions called**:
    - [`service_quic`](#service_quic)


---
### privileged\_init<!-- {{#callable:privileged_init}} -->
The `privileged_init` function initializes network connections and context for a tile in a topology, setting up sockets and configuring them for QUIC or non-QUIC communication.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile configuration within the topology.
- **Control Flow**:
    - Retrieve the local address of the tile object using `fd_topo_obj_laddr` and store it in `scratch`.
    - Call `fd_log_wallclock` to ensure VDSO is loaded by glibc, which requires calling `mmap` while privileged.
    - Initialize a scratch allocator with `FD_SCRATCH_ALLOC_INIT` using the `scratch` memory.
    - Allocate and zero-initialize a `fd_benchs_ctx_t` context structure using `FD_SCRATCH_ALLOC_APPEND` and `fd_memset`.
    - Set `no_quic` flag in the context based on the tile's configuration and initialize the connection count.
    - If QUIC is not disabled, set the connection count to 1 and verify it does not exceed the maximum allowed connections.
    - Iterate over the number of connections to create and configure UDP sockets.
    - For each socket, set receive and send buffer sizes using `setsockopt`.
    - Attempt to bind each socket to a port, retrying with different ports if necessary, and log errors if binding fails.
    - Connect each socket to the specified destination address and port, logging errors if connection fails.
    - Store the file descriptor of each socket in the context and configure polling if QUIC is enabled.
- **Output**: The function does not return a value; it initializes network connections and context for the specified tile.


---
### unprivileged\_init<!-- {{#callable:unprivileged_init}} -->
The `unprivileged_init` function initializes a context for a tile in a topology, setting up memory and QUIC configurations if required.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the tile to be initialized.
- **Control Flow**:
    - Allocate scratch memory for the tile using `fd_topo_obj_laddr` and initialize it with `FD_SCRATCH_ALLOC_INIT`.
    - Allocate and initialize a `fd_benchs_ctx_t` context structure within the scratch memory.
    - Set initial values for `packet_cnt`, `round_robin_id`, and `round_robin_cnt` in the context.
    - Assign the appropriate workspace memory to `ctx->mem` based on the topology and tile configuration.
    - If QUIC is not disabled (`!ctx->no_quic`), populate QUIC limits and calculate the required memory footprint.
    - Allocate memory for QUIC and initialize a QUIC instance with `fd_quic_new` and `fd_quic_join`.
    - Configure the QUIC instance with [`populate_quic_config`](#populate_quic_config) and set up a test signer using a random number generator.
    - Initialize asynchronous I/O for QUIC transmission with `fd_aio_new` and `fd_aio_join`.
    - Set various QUIC configuration parameters, including role, idle timeout, and callbacks for connection events.
    - Set up receive buffers and message headers for incoming data using `struct iovec` and `struct mmsghdr`.
    - Finalize the scratch memory allocation with `FD_SCRATCH_ALLOC_FINI` and check for overflow errors.
- **Output**: The function does not return a value; it initializes the context and memory for the tile.
- **Functions called**:
    - [`populate_quic_limits`](#populate_quic_limits)
    - [`populate_quic_config`](#populate_quic_config)
    - [`scratch_footprint`](#scratch_footprint)


---
### quic\_tx\_aio\_send\_flush<!-- {{#callable:quic_tx_aio_send_flush}} -->
The `quic_tx_aio_send_flush` function sends all pending messages in the transmission buffer over a network connection and resets the buffer index.
- **Inputs**:
    - `ctx`: A pointer to an `fd_benchs_ctx_t` structure containing the context for the transmission, including the connection file descriptor and the transmission messages.
- **Control Flow**:
    - Check if there are any messages to send by evaluating `ctx->tx_idx`.
    - If there are messages, call `sendmmsg` to send the messages in `ctx->tx_msgs` using the first connection file descriptor in `ctx->conn_fd`.
    - Check the return value of `sendmmsg`; if it is negative, log an error message with the error details.
    - Reset `ctx->tx_idx` to 0 to indicate that the transmission buffer is empty.
- **Output**: This function does not return a value; it performs its operations directly on the provided context.


---
### quic\_tx\_aio\_send<!-- {{#callable:quic_tx_aio_send}} -->
The `quic_tx_aio_send` function processes a batch of packets by stripping unnecessary headers, preparing them for transmission, and optionally flushing them if needed.
- **Inputs**:
    - `_ctx`: A pointer to the context (`fd_benchs_ctx_t`) which contains transmission buffers and state information.
    - `batch`: A pointer to an array of `fd_aio_pkt_info_t` structures representing the packets to be processed.
    - `batch_cnt`: The number of packets in the batch.
    - `opt_batch_idx`: An optional pointer to a `ulong` where the function can store the number of packets processed.
    - `flush`: An integer flag indicating whether to force a flush of the transmission buffers.
- **Control Flow**:
    - Check if there are packets in the batch (`batch_cnt` is non-zero).
    - Calculate the remaining space in the transmission buffer (`remain`).
    - If the remaining space is less than the batch count, flush the current transmission buffer to make space.
    - Iterate over the packets in the batch, stripping the IP and UDP headers, and copying the payload to the transmission buffer.
    - Update the transmission index (`tx_idx`) after processing the packets.
    - If the transmission buffer is full or a flush is requested, flush the buffer.
    - If `opt_batch_idx` is provided, set it to the number of packets processed.
- **Output**: The function returns 0 to indicate successful processing of the batch.
- **Functions called**:
    - [`quic_tx_aio_send_flush`](#quic_tx_aio_send_flush)



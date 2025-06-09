# Purpose
This C source code file is part of a larger system that manages network communication, specifically focusing on handling UDP sockets for a network tile within a topology. The file defines several static functions and macros that facilitate the creation, configuration, and management of UDP sockets, as well as the sending and receiving of network packets. The code is structured to handle both privileged and unprivileged initialization of network tiles, which are components of a larger network topology. The file includes functions for setting up socket options, binding sockets to specific addresses and ports, and managing socket file descriptors. It also includes logic for handling incoming and outgoing network packets, using functions like `recvmmsg` and `sendmmsg` to batch process network messages efficiently.

The file is not a standalone executable but rather a component intended to be integrated into a larger system, as indicated by its inclusion of other header files and its use of external functions and macros. It defines internal functions and data structures that are likely used by other parts of the system to manage network communication. The code is organized around the concept of a "sock tile," which appears to be a modular unit within a network topology that handles specific network tasks. The file also includes metrics collection for monitoring system calls and network traffic, which suggests it is part of a performance-sensitive application. The presence of configuration macros and the use of system-specific features like `dup3` and `SOCK_CLOEXEC` indicate that the code is designed to be efficient and adaptable to different environments.
# Imports and Dependencies

---
- `fd_sock_tile_private.h`
- `../../topo/fd_topo.h`
- `../../../util/net/fd_eth.h`
- `../../../util/net/fd_ip4.h`
- `../../../util/net/fd_udp.h`
- `assert.h`
- `stdalign.h`
- `errno.h`
- `fcntl.h`
- `unistd.h`
- `netinet/in.h`
- `sys/socket.h`
- `generated/sock_seccomp.h`
- `../../metrics/fd_metrics.h`
- `../../stem/fd_stem.c`


# Global Variables

---
### before\_frag
- **Type**: `function`
- **Description**: The `before_frag` function is a static inline function that is used to perform early filtering of network fragments in a socket tile context. It checks the protocol of the fragment and determines whether to continue processing or not.
- **Use**: This function is used to filter incoming network fragments based on their protocol, allowing only those with the `DST_PROTO_OUTGOING` protocol to continue processing.


---
### fd\_tile\_sock
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_sock` is a global variable of type `fd_topo_run_tile_t`, which is a structure used to define a tile in a topology for a network application. This structure is initialized with various function pointers and parameters that configure the behavior and capabilities of the tile, such as resource limits, security policies, and initialization routines.
- **Use**: This variable is used to configure and manage a network tile within a larger topology, handling tasks such as socket management, security policy enforcement, and initialization procedures.


# Functions

---
### populate\_allowed\_seccomp<!-- {{#callable:populate_allowed_seccomp}} -->
The `populate_allowed_seccomp` function initializes a scratch memory context and populates a seccomp filter policy for socket operations based on the provided topology and tile information.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to a `fd_topo_tile_t` structure representing the tile configuration within the topology.
    - `out_cnt`: An unsigned long integer representing the count of output filters to be populated.
    - `out`: A pointer to a `struct sock_filter` array where the seccomp filter policy will be populated.
- **Control Flow**:
    - Initialize a scratch memory allocator with the local address of the tile object in the topology.
    - Allocate memory for a `fd_sock_tile_t` context within the scratch memory.
    - Call [`populate_sock_filter_policy_sock`](generated/sock_seccomp.h.driver.md#populate_sock_filter_policy_sock) to populate the seccomp filter policy using the provided output count, filter array, log file descriptor, transmit socket, and socket count range.
    - Return the instruction count of the socket filter policy.
- **Output**: Returns an unsigned long integer representing the instruction count of the populated socket filter policy.
- **Functions called**:
    - [`populate_sock_filter_policy_sock`](generated/sock_seccomp.h.driver.md#populate_sock_filter_policy_sock)


---
### populate\_allowed\_fds<!-- {{#callable:populate_allowed_fds}} -->
The `populate_allowed_fds` function populates an array with file descriptors that are allowed for a specific tile in a network topology, including standard error, a log file, a transmit socket, and multiple receive sockets.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the network topology.
    - `tile`: A pointer to a `fd_topo_tile_t` structure representing the specific tile within the topology.
    - `out_fds_cnt`: An unsigned long integer representing the maximum number of file descriptors that can be stored in the `out_fds` array.
    - `out_fds`: A pointer to an integer array where the allowed file descriptors will be stored.
- **Control Flow**:
    - Retrieve a scratch memory address using `fd_topo_obj_laddr` with the given `topo` and `tile->tile_obj_id`.
    - Initialize a scratch allocator with `FD_SCRATCH_ALLOC_INIT`.
    - Allocate memory for a `fd_sock_tile_t` context using `FD_SCRATCH_ALLOC_APPEND`.
    - Retrieve the socket count from the context (`ctx->sock_cnt`).
    - Check if `out_fds_cnt` is less than the required number of file descriptors (`sock_cnt + 3`), and log an error if true.
    - Initialize `out_cnt` to zero to keep track of the number of file descriptors added.
    - Add the standard error file descriptor (2) to `out_fds`.
    - Check if the log file descriptor is valid and add it to `out_fds` if so.
    - Add the transmit socket file descriptor (`ctx->tx_sock`) to `out_fds`.
    - Iterate over each socket in `ctx->pollfd` and add its file descriptor to `out_fds`.
    - Return the total count of file descriptors added to `out_fds`.
- **Output**: Returns the total number of file descriptors added to the `out_fds` array as an unsigned long integer.


---
### tx\_scratch\_footprint<!-- {{#callable:tx_scratch_footprint}} -->
The `tx_scratch_footprint` function calculates the memory footprint required for a transmission scratch buffer based on network MTU and alignment constraints.
- **Inputs**: None
- **Control Flow**:
    - The function calculates the aligned size of the network MTU using `fd_ulong_align_up` with `FD_CHUNK_ALIGN` as the alignment parameter.
    - It multiplies the aligned MTU size by `STEM_BURST` to determine the total memory footprint required for the transmission scratch buffer.
    - The function returns this calculated value.
- **Output**: The function returns an unsigned long integer representing the total memory footprint required for the transmission scratch buffer.


---
### scratch\_align<!-- {{#callable:scratch_align}} -->
The `scratch_align` function returns a constant alignment value of 4096 bytes.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests inlining for performance.
    - The function does not take any parameters.
    - It directly returns the constant value 4096UL, which is an unsigned long integer.
- **Output**: The function outputs an unsigned long integer with the value 4096, representing the alignment size.


---
### scratch\_footprint<!-- {{#callable:scratch_footprint}} -->
The `scratch_footprint` function calculates the memory footprint required for various network-related structures and operations in a socket tile.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, which is not used in the function.
- **Control Flow**:
    - Initialize a variable `l` with `FD_LAYOUT_INIT` to start the layout calculation.
    - Append the size and alignment of `fd_sock_tile_t` to `l` using `FD_LAYOUT_APPEND`.
    - Append the size and alignment of an array of `struct iovec` with `STEM_BURST` elements to `l`.
    - Append the size and alignment of an array of `struct cmsghdr` with `STEM_BURST * FD_SOCK_CMSG_MAX` elements to `l`.
    - Append the size and alignment of an array of `struct sockaddr_in` with `STEM_BURST` elements to `l`.
    - Append the size and alignment of an array of `struct mmsghdr` with `STEM_BURST` elements to `l`.
    - Append the size and alignment of the result from `tx_scratch_footprint()` to `l`.
    - Finalize the layout calculation with `FD_LAYOUT_FINI` using `scratch_align()` and return the result.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the specified structures and operations.
- **Functions called**:
    - [`tx_scratch_footprint`](#tx_scratch_footprint)
    - [`scratch_align`](#scratch_align)


---
### create\_udp\_socket<!-- {{#callable:create_udp_socket}} -->
The `create_udp_socket` function initializes and configures a UDP socket with specific options and binds it to a given address and port, duplicating the socket to a specified file descriptor.
- **Inputs**:
    - `sock_fd`: The file descriptor to which the created UDP socket will be duplicated.
    - `bind_addr`: The IP address to which the socket will be bound, in network byte order.
    - `udp_port`: The UDP port number to which the socket will be bound, in host byte order.
    - `so_rcvbuf`: The size of the receive buffer for the socket.
- **Control Flow**:
    - Check if the file descriptor `sock_fd` is already in use using `fcntl`; log an error if it is.
    - Create a new UDP socket using `socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)`; log an error if socket creation fails.
    - Set the `SO_REUSEPORT` option on the socket to allow multiple sockets to bind to the same address and port; log an error if setting the option fails.
    - Set the `IP_PKTINFO` option to receive packet information; log an error if setting the option fails.
    - Set the socket's receive buffer size using `setsockopt` with `SO_RCVBUF`; log an error if setting the buffer size fails.
    - Initialize a `sockaddr_in` structure with the provided `bind_addr` and `udp_port`, converting the port to network byte order.
    - Bind the socket to the specified address and port using `bind`; log an error if binding fails.
    - Duplicate the original socket to `sock_fd` using `dup3` (or `dup2` if not on Linux) with `O_CLOEXEC` flag; log an error if duplication fails.
    - Close the original socket file descriptor `orig_fd` after duplication; log an error if closing fails.
- **Output**: The function does not return a value; it configures the socket and logs errors if any operation fails.


---
### privileged\_init<!-- {{#callable:privileged_init}} -->
The `privileged_init` function initializes network sockets and related resources for a given tile in a topology, setting up both receive and transmit sockets for network communication.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the network topology.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile within the topology to be initialized.
- **Control Flow**:
    - Allocate scratch memory for various network structures using `FD_SCRATCH_ALLOC_APPEND` for context, batch I/O vectors, control messages, socket addresses, message headers, and transmission scratch space.
    - Initialize the allocated memory to zero using `fd_memset` for context, batch I/O vectors, socket addresses, and message headers.
    - Set up the context structure with pointers to the allocated resources and initialize batch count and transmission pointers.
    - Iterate over a list of UDP port candidates to create receive sockets, checking if each port is valid and associated with a link in the topology.
    - For each valid port, create a UDP socket using [`create_udp_socket`](#create_udp_socket), assign it a file descriptor, and configure it for polling with `POLLIN` events.
    - Create a raw transmit socket for sending data, setting its send buffer size using `setsockopt`.
    - Store the transmit socket file descriptor and bind address in the context structure.
- **Output**: The function does not return a value; it initializes network resources and updates the context structure for the specified tile.
- **Functions called**:
    - [`tx_scratch_footprint`](#tx_scratch_footprint)
    - [`create_udp_socket`](#create_udp_socket)


---
### unprivileged\_init<!-- {{#callable:unprivileged_init}} -->
The `unprivileged_init` function initializes the unprivileged context for a socket tile by setting up receive and transmit link configurations based on the topology and tile information.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the network topology.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile within the topology to be initialized.
- **Control Flow**:
    - Retrieve the local address of the socket tile context using `fd_topo_obj_laddr` with the topology and tile object ID.
    - Check if the number of outgoing links (`tile->out_cnt`) exceeds the maximum allowed (`MAX_NET_OUTS`) and log an error if it does.
    - Iterate over each outgoing link (`tile->out_cnt`) and verify that each link name starts with 'net_'. Log an error if any link does not meet this criterion.
    - For each valid outgoing link, set up the receive link configuration by initializing the base, chunk0, wmark, and chunk fields of the `link_rx` array in the context.
    - Check if the burst size of each outgoing link is below the required `STEM_BURST` and log an error if it is.
    - Iterate over each incoming link (`tile->in_cnt`) and verify that each link name contains '_net'. Log an error if any link does not meet this criterion.
    - For each valid incoming link, set up the transmit link configuration by initializing the base, chunk0, and wmark fields of the `link_tx` array in the context.
- **Output**: The function does not return a value; it initializes the socket tile context in place.


---
### poll\_rx\_socket<!-- {{#callable:poll_rx_socket}} -->
The `poll_rx_socket` function performs a batch receive operation on a specified socket, processes the received packets, and updates the context and metrics accordingly.
- **Inputs**:
    - `ctx`: A pointer to the `fd_sock_tile_t` structure, which contains context information for the socket tile, including batch message buffers and metrics.
    - `stem`: A pointer to the `fd_stem_context_t` structure, which is used for publishing received packets.
    - `sock_idx`: An unsigned integer representing the index of the socket in the context's socket array.
    - `sock_fd`: An integer representing the file descriptor of the socket to be polled.
    - `proto`: A ushort representing the protocol identifier for the socket.
- **Control Flow**:
    - Initialize header size and maximum payload size based on network MTU and header sizes.
    - Retrieve the receive link and port for the specified socket index from the context.
    - Prepare the batch of messages for receiving by setting up the I/O vectors and message headers for each message in the batch.
    - Call `recvmmsg` to receive a batch of messages from the socket, handling errors and updating metrics if necessary.
    - If no messages are received, return 0.
    - For each received message, extract the payload, source address, and control message headers, updating metrics and checking for errors.
    - Construct Ethernet, IP, and UDP headers for each received packet, setting appropriate fields and addresses.
    - Publish each received packet using `fd_stem_publish`, updating the last chunk index.
    - Update the link's chunk index to the next free index and return the number of messages received.
- **Output**: Returns the number of packets successfully received and processed, as an unsigned long integer.


---
### poll\_rx<!-- {{#callable:poll_rx}} -->
The `poll_rx` function polls a set of sockets for incoming data and processes any available packets, returning the total number of packets processed.
- **Inputs**:
    - `ctx`: A pointer to a `fd_sock_tile_t` structure representing the context of the socket tile, which includes socket file descriptors, protocol identifiers, and other state information.
    - `stem`: A pointer to a `fd_stem_context_t` structure used for publishing received packets and managing flow control.
- **Control Flow**:
    - Initialize `pkt_cnt` to zero to count the number of packets processed.
    - Check if `ctx->batch_cnt` is non-zero, indicating an unclean batch, and log an error if so.
    - Reset `ctx->tx_idle_cnt` to zero to restart TX polling.
    - Call `poll` on the file descriptors in `ctx->pollfd` to check for incoming data, logging an error if the call fails.
    - Iterate over each socket in `ctx->pollfd` using a loop indexed by `j`.
    - For each socket, check if there are any events (`POLLIN` or `POLLERR`) in `ctx->pollfd[j].revents`.
    - If events are present, call [`poll_rx_socket`](#poll_rx_socket) to process incoming packets on the socket, adding the number of packets processed to `pkt_cnt`.
    - Reset `ctx->pollfd[j].revents` to zero after processing.
    - Return the total number of packets processed, `pkt_cnt`.
- **Output**: The function returns an `ulong` representing the total number of packets processed from the sockets.
- **Functions called**:
    - [`poll_rx_socket`](#poll_rx_socket)


---
### flush\_tx\_batch<!-- {{#callable:flush_tx_batch}} -->
The `flush_tx_batch` function attempts to send a batch of messages from a socket, updating metrics based on the success or failure of the operation.
- **Inputs**:
    - `ctx`: A pointer to an `fd_sock_tile_t` structure, which contains context information including the batch of messages to be sent, the socket to send them on, and various metrics.
- **Control Flow**:
    - Retrieve the number of messages in the batch from `ctx->batch_cnt`.
    - Iterate over the batch of messages, attempting to send them using `sendmmsg`.
    - If `sendmmsg` sends some or all messages successfully, update the success metrics and adjust the loop index accordingly.
    - If `sendmmsg` fails to send all messages, increment the drop count and handle specific errors by updating corresponding error metrics.
    - If a message fails to send due to an error, log the error and skip the failing message.
    - If all messages are sent successfully, update the packet count metric and exit the loop.
    - Reset the transmission pointer and batch count in the context.
- **Output**: The function does not return a value; it updates the context's metrics and state based on the outcome of the message sending operation.


---
### during\_frag<!-- {{#callable:during_frag}} -->
The `during_frag` function processes a network fragment by validating its size and headers, and prepares it for transmission by copying it into a send buffer.
- **Inputs**:
    - `ctx`: A pointer to the `fd_sock_tile_t` context structure, which contains state and configuration for the socket tile.
    - `in_idx`: An index indicating which input link the fragment is associated with.
    - `seq`: A sequence number for the fragment, marked as unused in this function.
    - `sig`: A signal value used to determine the header size of the fragment.
    - `chunk`: The chunk index of the fragment within the data cache.
    - `sz`: The size of the fragment in bytes.
    - `ctl`: A control value for the fragment, marked as unused in this function.
- **Control Flow**:
    - Check if the chunk index and size are within valid ranges; log an error if not.
    - Calculate the minimum header size and check if the fragment size is smaller; log an error if so.
    - Retrieve the frame and payload pointers using the chunk index and header size.
    - Validate the header size against the total size and minimum header size; log an error if invalid.
    - Extract the IP and UDP headers from the frame and payload, respectively.
    - Verify that the IP version is IPv4 and the protocol is UDP; log an error if not.
    - Calculate the message size as the sum of the UDP header size and payload size.
    - Prepare the message, socket address, I/O vector, and control message headers for transmission.
    - Copy the UDP header and payload into the transmission buffer.
    - Update the total transmitted bytes in the metrics.
- **Output**: The function does not return a value; it prepares the fragment for transmission and updates metrics.


---
### after\_frag<!-- {{#callable:after_frag}} -->
The `after_frag` function finalizes the processing of a packet fragment by updating the transmission context and potentially flushing the transmission batch if a threshold is reached.
- **Inputs**:
    - `ctx`: A pointer to the `fd_sock_tile_t` structure representing the socket tile context.
    - `in_idx`: An unused parameter representing the input index.
    - `seq`: An unused parameter representing the sequence number.
    - `sig`: An unused parameter representing the signal.
    - `sz`: The size of the packet fragment.
    - `tsorig`: An unused parameter representing the original timestamp.
    - `tspub`: An unused parameter representing the publication timestamp.
    - `stem`: An unused pointer to the `fd_stem_context_t` structure.
- **Control Flow**:
    - Reset the transmission idle counter to zero.
    - Increment the batch count in the context.
    - Adjust the transmission pointer by aligning the size `sz` to the chunk alignment and adding it to the current pointer.
    - Check if the batch count has reached the `STEM_BURST` threshold.
    - If the batch count is equal to or exceeds `STEM_BURST`, call [`flush_tx_batch`](#flush_tx_batch) to send the batch of messages.
- **Output**: The function does not return a value; it modifies the state of the `ctx` structure to reflect the processing of a packet fragment.
- **Functions called**:
    - [`flush_tx_batch`](#flush_tx_batch)


---
### after\_credit<!-- {{#callable:after_credit}} -->
The `after_credit` function manages the transmission and reception of packets by flushing the transmission batch and polling for received packets when the transmission idle count exceeds a threshold.
- **Inputs**:
    - `ctx`: A pointer to a `fd_sock_tile_t` structure representing the socket tile context.
    - `stem`: A pointer to a `fd_stem_context_t` structure representing the stem context.
    - `poll_in`: An unused integer pointer, marked with `FD_PARAM_UNUSED`, indicating it is not used in the function.
    - `charge_busy`: A pointer to an integer that will be set to indicate whether the function detected any received packets.
- **Control Flow**:
    - Check if `ctx->tx_idle_cnt` is greater than 512.
    - If `ctx->batch_cnt` is non-zero, call `flush_tx_batch(ctx)` to flush the transmission batch.
    - Call `poll_rx(ctx, stem)` to poll for received packets and store the result in `pkt_cnt`.
    - Set `*charge_busy` to true if `pkt_cnt` is not zero, indicating packets were received.
    - Increment `ctx->tx_idle_cnt`.
- **Output**: The function does not return a value but modifies the `charge_busy` integer to indicate if packets were received.
- **Functions called**:
    - [`flush_tx_batch`](#flush_tx_batch)
    - [`poll_rx`](#poll_rx)


---
### metrics\_write<!-- {{#callable:metrics_write}} -->
The `metrics_write` function updates various socket-related metrics in a given context structure.
- **Inputs**:
    - `ctx`: A pointer to an `fd_sock_tile_t` structure containing the metrics to be updated.
- **Control Flow**:
    - The function uses the macro `FD_MCNT_SET` to set the value of `ctx->metrics.sys_recvmmsg_cnt` to the corresponding metric counter for received messages.
    - It uses the macro `FD_MCNT_ENUM_COPY` to copy the `ctx->metrics.sys_sendmmsg_cnt` array to the corresponding metric counter for sent messages.
    - The function sets the `ctx->metrics.rx_pkt_cnt` to the corresponding metric counter for received packets using `FD_MCNT_SET`.
    - It sets the `ctx->metrics.tx_pkt_cnt` to the corresponding metric counter for transmitted packets using `FD_MCNT_SET`.
    - The function sets the `ctx->metrics.tx_drop_cnt` to the corresponding metric counter for dropped packets using `FD_MCNT_SET`.
    - It sets the `ctx->metrics.tx_bytes_total` to the corresponding metric counter for total transmitted bytes using `FD_MCNT_SET`.
    - Finally, it sets the `ctx->metrics.rx_bytes_total` to the corresponding metric counter for total received bytes using `FD_MCNT_SET`.
- **Output**: The function does not return any value; it updates the metrics in the provided context structure.


---
### rlimit\_file\_cnt<!-- {{#callable:rlimit_file_cnt}} -->
The `rlimit_file_cnt` function calculates the total number of file descriptors required for a given tile in a network topology by adding a constant minimum to the number of sockets in use.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure representing the network topology.
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure representing a specific tile within the topology.
- **Control Flow**:
    - Retrieve the local address of the tile object using `fd_topo_obj_laddr` with the given topology and tile object ID.
    - Access the `sock_cnt` field from the `fd_sock_tile_t` structure pointed to by the retrieved local address.
    - Return the sum of `RX_SOCK_FD_MIN` and the `sock_cnt` value.
- **Output**: The function returns an unsigned long integer representing the total number of file descriptors required for the tile, which is the sum of a predefined minimum and the current socket count.



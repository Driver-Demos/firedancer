# Purpose
This C source code file implements a UDP socket abstraction, providing a structured way to handle UDP communication with additional features like mock Ethernet and IPv4 headers. The primary structure defined is `fd_udpsock`, which encapsulates the necessary components for managing UDP sockets, including file descriptors, mock network addresses, and data structures for handling incoming and outgoing packets. The code includes functions for creating, joining, and managing these UDP socket structures, as well as for sending and receiving packets using asynchronous I/O operations. The file is designed to be part of a larger system, likely a network application, where it can be included and used to facilitate UDP communication with added flexibility and control over packet headers.

The code provides a narrow but essential functionality focused on UDP socket management, with functions like [`fd_udpsock_new`](#fd_udpsock_new), [`fd_udpsock_join`](#fd_udpsock_join), and [`fd_udpsock_service`](#fd_udpsock_service) that handle the lifecycle and operations of the UDP socket. It defines public APIs for setting and retrieving socket properties, such as IP addresses and ports, and for configuring the layer of network headers to use. The file is intended to be integrated into a larger application, as indicated by its inclusion of external headers and its use of shared memory for socket management. The code is structured to support high-performance network applications, with careful attention to memory alignment and efficient packet processing.
# Imports and Dependencies

---
- `errno.h`
- `netinet/in.h`
- `sys/socket.h`
- `sys/stat.h`
- `sys/uio.h`
- `fd_udpsock.h`
- `../../util/net/fd_eth.h`
- `../../util/net/fd_ip4.h`
- `../../util/net/fd_udp.h`


# Data Structures

---
### fd\_udpsock
- **Type**: `struct`
- **Members**:
    - `aio_self`: Asynchronous I/O structure provided by the UDP socket.
    - `aio_rx`: Pointer to an asynchronous I/O structure provided by the receiver.
    - `fd`: File descriptor of the actual socket.
    - `hdr_sz`: Size of the header.
    - `eth_self_addr`: Mock Ethernet address of the local interface.
    - `eth_peer_addr`: Mock Ethernet address of the peer interface.
    - `ip_self_addr`: IPv4 address of the local interface in network byte order.
    - `udp_self_port`: UDP port of the local interface in little endian.
    - `rx_cnt`: Count of received packets.
    - `rx_msg`: Pointer to an array of message headers for received packets.
    - `rx_iov`: Pointer to an array of I/O vectors for received packets.
    - `rx_frame`: Pointer to the frame buffer for received packets.
    - `rx_pkt`: Pointer to an array of packet information structures for received packets.
    - `tx_cnt`: Count of transmitted packets.
    - `tx_msg`: Pointer to an array of message headers for transmitted packets.
    - `tx_iov`: Pointer to an array of I/O vectors for transmitted packets.
    - `tx_frame`: Pointer to the frame buffer for transmitted packets.
- **Description**: The `fd_udpsock` structure is a comprehensive data structure designed to manage UDP socket operations, including both sending and receiving packets. It encapsulates various fields for handling asynchronous I/O operations, mock Ethernet and UDP/IPv4 headers, and pointers to variable-length data structures for managing packet data. The structure is equipped to handle both incoming and outgoing packet data, with fields dedicated to maintaining counts and pointers for message headers, I/O vectors, and frame buffers. This design facilitates efficient network communication by organizing and managing the necessary resources for UDP socket operations.


# Functions

---
### fd\_udpsock\_align<!-- {{#callable:fd_udpsock_align}} -->
The `fd_udpsock_align` function returns the alignment requirement of the `fd_udpsock_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a constant function, meaning it does not modify any global state and always returns the same result.
    - It directly returns the result of the `alignof` operator applied to the `fd_udpsock_t` type, which gives the alignment requirement of this structure.
- **Output**: The function returns an `ulong` representing the alignment requirement of the `fd_udpsock_t` structure.


---
### fd\_udpsock\_footprint<!-- {{#callable:fd_udpsock_footprint}} -->
The `fd_udpsock_footprint` function calculates the memory footprint required for a UDP socket structure based on the given MTU, receive packet count, and transmit packet count.
- **Inputs**:
    - `mtu`: The maximum transmission unit size for the UDP socket.
    - `rx_pkt_cnt`: The number of packets expected to be received.
    - `tx_pkt_cnt`: The number of packets expected to be transmitted.
- **Control Flow**:
    - Check if any of the inputs (mtu, rx_pkt_cnt, tx_pkt_cnt) are zero or if mtu is less than or equal to FD_UDPSOCK_HEADROOM; if so, return 0.
    - Calculate the total packet count as the sum of rx_pkt_cnt and tx_pkt_cnt.
    - Align the mtu to the nearest multiple of FD_UDPSOCK_FRAME_ALIGN using fd_ulong_align_up.
    - Calculate the memory footprint using a series of FD_LAYOUT_APPEND and FD_LAYOUT_FINI calls, which account for the alignment and size of various structures and buffers needed for the UDP socket.
- **Output**: Returns the calculated memory footprint as an unsigned long integer, or 0 if the input conditions are not met.


---
### fd\_udpsock\_new<!-- {{#callable:fd_udpsock_new}} -->
The `fd_udpsock_new` function initializes a new UDP socket structure in shared memory, setting up necessary data structures and default values for packet handling.
- **Inputs**:
    - `shmem`: A pointer to shared memory where the UDP socket structure will be initialized.
    - `mtu`: The maximum transmission unit size for the UDP socket.
    - `rx_pkt_cnt`: The number of receive packets the socket can handle.
    - `tx_pkt_cnt`: The number of transmit packets the socket can handle.
- **Control Flow**:
    - Check if the `shmem` pointer is NULL and return NULL if so, logging a warning.
    - Convert `shmem` to an unsigned long and check if it is aligned according to [`fd_udpsock_align`](#fd_udpsock_align); return NULL if misaligned, logging a warning.
    - Calculate the memory footprint required using [`fd_udpsock_footprint`](#fd_udpsock_footprint) and return NULL if the footprint is invalid, logging a warning.
    - Align the memory address and allocate the main `fd_udpsock_t` structure, initializing its fields to default values.
    - Set default mock network headers for Ethernet and IP addresses.
    - Allocate and align memory for variable-length data structures such as `mmsghdr`, `iovec`, and packet frames.
    - Prepare `iovec` and `msghdr` buffers for receive and transmit operations.
    - Set the default layer for the UDP socket to Ethernet.
    - Return the original `shmem` pointer.
- **Output**: Returns the original `shmem` pointer if successful, or NULL if any error occurs during initialization.
- **Functions called**:
    - [`fd_udpsock_align`](#fd_udpsock_align)
    - [`fd_udpsock_footprint`](#fd_udpsock_footprint)
    - [`fd_udpsock_set_layer`](#fd_udpsock_set_layer)


---
### fd\_udpsock\_join<!-- {{#callable:fd_udpsock_join}} -->
The `fd_udpsock_join` function initializes a UDP socket structure with a given file descriptor and extracts the socket's IPv4 address and port.
- **Inputs**:
    - `shsock`: A pointer to a shared memory region representing the UDP socket structure to be initialized.
    - `fd`: An integer representing the file descriptor of the socket to be joined.
- **Control Flow**:
    - Check if the `shsock` pointer is NULL and log a warning if it is, returning NULL.
    - Cast the `shsock` pointer to a `fd_udpsock_t` pointer and assign the `fd` to the `fd` field of the structure.
    - Declare a `sockaddr` structure and a `socklen_t` variable to hold the address length.
    - Call `getsockname` to retrieve the socket's address and check for errors, logging a warning and returning NULL if it fails.
    - Verify that the socket address family is `AF_INET` (IPv4) and log a warning and return NULL if it is not.
    - Extract the IPv4 address and port from the `sockaddr_in` structure and store them in the `fd_udpsock_t` structure, converting the port to little-endian format.
    - Return the initialized `fd_udpsock_t` structure.
- **Output**: A pointer to the initialized `fd_udpsock_t` structure, or NULL if an error occurs.


---
### fd\_udpsock\_leave<!-- {{#callable:fd_udpsock_leave}} -->
The `fd_udpsock_leave` function sets the file descriptor of a UDP socket to -1 and returns the socket pointer.
- **Inputs**:
    - `sock`: A pointer to an `fd_udpsock_t` structure representing the UDP socket to be left.
- **Control Flow**:
    - Check if the `sock` pointer is NULL using `FD_UNLIKELY`; if it is, log a warning and return NULL.
    - Set the `fd` field of the `sock` structure to -1, indicating the socket is no longer active.
    - Return the `sock` pointer cast to a `void *`.
- **Output**: Returns a `void *` pointer to the `fd_udpsock_t` structure, or NULL if the input `sock` is NULL.


---
### fd\_udpsock\_delete<!-- {{#callable:fd_udpsock_delete}} -->
The `fd_udpsock_delete` function checks if a given shared socket pointer is non-null and returns it, logging a warning if it is null.
- **Inputs**:
    - `shsock`: A pointer to a shared socket object that is intended to be deleted.
- **Control Flow**:
    - Check if the input `shsock` is null using `FD_UNLIKELY` macro.
    - If `shsock` is null, log a warning message 'NULL shsock' and return `NULL`.
    - If `shsock` is not null, return the `shsock` pointer.
- **Output**: Returns the input `shsock` pointer if it is non-null, otherwise returns `NULL`.


---
### fd\_udpsock\_set\_rx<!-- {{#callable:fd_udpsock_set_rx}} -->
The `fd_udpsock_set_rx` function assigns a given asynchronous I/O (AIO) receiver to a UDP socket structure.
- **Inputs**:
    - `sock`: A pointer to an `fd_udpsock_t` structure representing the UDP socket to which the AIO receiver will be assigned.
    - `aio`: A constant pointer to an `fd_aio_t` structure representing the AIO receiver to be set for the UDP socket.
- **Control Flow**:
    - The function takes two parameters: a pointer to a UDP socket structure (`sock`) and a constant pointer to an AIO structure (`aio`).
    - It assigns the `aio` parameter to the `aio_rx` member of the `sock` structure, effectively setting the AIO receiver for the socket.
- **Output**: The function does not return any value.


---
### fd\_udpsock\_get\_tx<!-- {{#callable:fd_udpsock_get_tx}} -->
The `fd_udpsock_get_tx` function retrieves the asynchronous I/O (AIO) transmission interface from a UDP socket structure.
- **Inputs**:
    - `sock`: A pointer to an `fd_udpsock_t` structure representing the UDP socket from which the AIO transmission interface is to be retrieved.
- **Control Flow**:
    - The function takes a single argument, `sock`, which is a pointer to an `fd_udpsock_t` structure.
    - It returns the address of the `aio_self` member of the `fd_udpsock_t` structure, which represents the AIO transmission interface.
- **Output**: A constant pointer to an `fd_aio_t` structure, representing the AIO transmission interface of the given UDP socket.


---
### fd\_udpsock\_service<!-- {{#callable:fd_udpsock_service}} -->
The `fd_udpsock_service` function processes incoming UDP packets by receiving them, constructing mock network headers, and dispatching them to a recipient.
- **Inputs**:
    - `sock`: A pointer to an `fd_udpsock_t` structure representing the UDP socket to be serviced.
- **Control Flow**:
    - The function begins by attempting to receive multiple messages from the socket using `recvmmsg`, storing them in the `rx_msg` array of the `sock` structure.
    - If the `recvmmsg` call fails with an error other than `EAGAIN` or `EWOULDBLOCK`, a warning is logged and the function returns.
    - For each received message, the function constructs a mock Ethernet and IPv4 header, depending on the header size (`hdr_sz`) of the socket.
    - The function sets up the IPv4 header fields, including version, header length, total length, TTL, and protocol, and calculates the checksum.
    - A UDP header is created with source and destination ports, length, and checksum set to zero.
    - The function populates the `rx_pkt` array with packet information, including buffer base and size.
    - Finally, the function dispatches the packets to the recipient using `fd_aio_send`, ignoring any errors.
- **Output**: The function does not return a value; it performs its operations directly on the `sock` structure and sends packets to the recipient.


---
### fd\_udpsock\_send<!-- {{#callable:fd_udpsock_send}} -->
The `fd_udpsock_send` function sends a batch of UDP packets using a specified socket context, handling packet preparation and transmission with optional flushing.
- **Inputs**:
    - `ctx`: A pointer to the socket context (`fd_udpsock_t`) used for sending packets.
    - `batch`: A pointer to an array of `fd_aio_pkt_info_t` structures representing the packets to be sent.
    - `batch_cnt`: The number of packets in the batch to be sent.
    - `opt_batch_idx`: An optional pointer to store the index of the batch that was processed in case of an error.
    - `flush`: An integer flag indicating whether to flush the send buffer (non-zero) or not (zero).
- **Control Flow**:
    - Check if `batch_cnt` is zero; if so, return `FD_AIO_SUCCESS` immediately.
    - Determine the number of packets to send (`send_cnt`) based on the lesser of `batch_cnt` and the socket's transmit capacity (`tx_cnt`).
    - Initialize a dummy batch index if `opt_batch_idx` is not provided.
    - Iterate over each packet in the batch up to `send_cnt`, skipping packets with insufficient buffer size or non-IP packets.
    - For each valid packet, convert IP and UDP headers to host byte order, extract destination address and port, and set up the iovec structure for transmission.
    - Use `sendmmsg` to send the prepared messages, handling errors and updating `opt_batch_idx` if necessary.
    - Return `FD_AIO_SUCCESS` if all packets are sent successfully, or an appropriate error code if not.
- **Output**: Returns an integer status code indicating success (`FD_AIO_SUCCESS`) or an error condition (`FD_AIO_ERR_AGAIN`, `FD_AIO_ERR_INVAL`).


---
### fd\_udpsock\_get\_ip4\_address<!-- {{#callable:fd_udpsock_get_ip4_address}} -->
The function `fd_udpsock_get_ip4_address` retrieves the IPv4 address of the UDP socket in network byte order.
- **Inputs**:
    - `sock`: A pointer to a constant `fd_udpsock_t` structure representing the UDP socket from which the IPv4 address is to be retrieved.
- **Control Flow**:
    - The function accesses the `ip_self_addr` field of the `fd_udpsock_t` structure pointed to by `sock`.
    - It returns the value of `ip_self_addr`, which is the IPv4 address of the socket in network byte order.
- **Output**: The function returns a `uint` representing the IPv4 address of the socket in network byte order.


---
### fd\_udpsock\_get\_listen\_port<!-- {{#callable:fd_udpsock_get_listen_port}} -->
The function `fd_udpsock_get_listen_port` retrieves the UDP listening port number from a given UDP socket structure.
- **Inputs**:
    - `sock`: A pointer to a constant `fd_udpsock_t` structure representing the UDP socket from which the listening port is to be retrieved.
- **Control Flow**:
    - The function accesses the `udp_self_port` field of the `fd_udpsock_t` structure pointed to by `sock`.
    - It returns the value of the `udp_self_port` field.
- **Output**: The function returns an unsigned integer representing the UDP listening port number of the socket.


---
### fd\_udpsock\_set\_layer<!-- {{#callable:fd_udpsock_set_layer}} -->
The `fd_udpsock_set_layer` function sets the header size of a UDP socket based on the specified network layer.
- **Inputs**:
    - `sock`: A pointer to an `fd_udpsock_t` structure representing the UDP socket.
    - `layer`: An unsigned integer specifying the network layer, which can be either `FD_UDPSOCK_LAYER_ETH` or `FD_UDPSOCK_LAYER_IP`.
- **Control Flow**:
    - The function uses a switch statement to determine the action based on the `layer` value.
    - If `layer` is `FD_UDPSOCK_LAYER_ETH`, it sets `sock->hdr_sz` to the combined size of Ethernet, IPv4, and UDP headers.
    - If `layer` is `FD_UDPSOCK_LAYER_IP`, it sets `sock->hdr_sz` to the combined size of IPv4 and UDP headers.
    - If `layer` is neither of the above, it logs a warning about the invalid layer and returns `NULL`.
    - If a valid layer is provided, the function returns the `sock` pointer.
- **Output**: Returns the `fd_udpsock_t` pointer if the layer is valid, otherwise returns `NULL`.


# Function Declarations (Public API)

---
### fd\_udpsock\_send<!-- {{#callable_declaration:fd_udpsock_send}} -->
Sends a batch of UDP packets through a specified socket.
- **Description**: This function is used to send a batch of UDP packets through a socket specified by the context. It should be called when there is a need to transmit multiple packets efficiently. The function handles packet validation and ensures that only valid IP packets are sent. It can operate in a non-blocking mode if the 'flush' parameter is set to zero. The function returns immediately if the batch count is zero. It is important to ensure that the context is properly initialized and that the batch contains valid packet information before calling this function.
- **Inputs**:
    - `ctx`: A pointer to the context, which must be a valid and initialized fd_udpsock_t structure. The caller retains ownership.
    - `batch`: A pointer to an array of fd_aio_pkt_info_t structures containing the packets to be sent. Must not be null.
    - `batch_cnt`: The number of packets in the batch. Must be greater than or equal to zero.
    - `opt_batch_idx`: An optional pointer to a ulong where the function can store the index of the first unsent packet in case of an error. Can be null, in which case a dummy variable is used internally.
    - `flush`: An integer flag indicating whether to block until all packets are sent (non-zero) or to return immediately if the operation would block (zero).
- **Output**: Returns an integer status code: FD_AIO_SUCCESS on success, FD_AIO_ERR_AGAIN if the operation would block, or FD_AIO_ERR_INVAL on other errors. The opt_batch_idx is updated with the index of the first unsent packet in case of an error.
- **See also**: [`fd_udpsock_send`](#fd_udpsock_send)  (Implementation)



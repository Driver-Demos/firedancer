# Purpose
This C header file, `fd_sock_tile_private.h`, is designed to define private structures and constants for managing socket communication within a specific software module, likely part of a larger network or communication library. The file is not intended for public API exposure but rather for internal use within the module, as indicated by the inclusion guards and the use of the `FD_HAS_HOSTED` preprocessor directive, which suggests conditional compilation based on the environment. The primary focus of this file is to manage UDP and raw socket communication, as evidenced by the definitions related to socket handling, such as `FD_SOCK_TILE_MAX_SOCKETS`, `MAX_NET_INS`, and `MAX_NET_OUTS`, which control the number of sockets and network links that can be managed.

The file defines several key structures, including `fd_sock_tile_metrics`, `fd_sock_link_tx`, `fd_sock_link_rx`, and `fd_sock_tile`, which encapsulate the state and metrics of socket operations. These structures manage the details of socket communication, such as tracking the number of packets sent and received, handling socket file descriptors, and managing transmission and reception links. The use of arrays and structures like `pollfd`, `iovec`, and `mmsghdr` indicates a focus on efficient batch processing of network messages. The file also includes provisions for handling metrics, which are periodically updated, suggesting a need for performance monitoring and optimization. Overall, this header file is a critical component for managing low-level socket operations within a networked application, providing the necessary infrastructure for efficient data transmission and reception.
# Imports and Dependencies

---
- `../../../util/fd_util_base.h`
- `../../metrics/generated/fd_metrics_enums.h`
- `poll.h`
- `sys/socket.h`


# Data Structures

---
### fd\_sock\_tile\_metrics
- **Type**: `struct`
- **Members**:
    - `sys_recvmmsg_cnt`: Counts the number of system calls to recvmmsg.
    - `sys_sendmmsg_cnt`: Array counting the number of system calls to sendmmsg, indexed by socket error count.
    - `rx_pkt_cnt`: Counts the number of received packets.
    - `tx_pkt_cnt`: Counts the number of transmitted packets.
    - `tx_drop_cnt`: Counts the number of dropped packets during transmission.
    - `rx_bytes_total`: Total number of bytes received.
    - `tx_bytes_total`: Total number of bytes transmitted.
- **Description**: The `fd_sock_tile_metrics` structure is designed to track various metrics related to socket operations within a network tile. It includes counters for system calls related to message reception and transmission, as well as counts for packets received, transmitted, and dropped. Additionally, it tracks the total number of bytes received and transmitted, providing a comprehensive overview of the socket's performance and activity.


---
### fd\_sock\_tile\_metrics\_t
- **Type**: `struct`
- **Members**:
    - `sys_recvmmsg_cnt`: Counts the number of received messages using the recvmmsg system call.
    - `sys_sendmmsg_cnt`: An array counting the number of sent messages using the sendmmsg system call, indexed by socket error count enums.
    - `rx_pkt_cnt`: Counts the total number of received packets.
    - `tx_pkt_cnt`: Counts the total number of transmitted packets.
    - `tx_drop_cnt`: Counts the number of packets dropped during transmission.
    - `rx_bytes_total`: Tracks the total number of bytes received.
    - `tx_bytes_total`: Tracks the total number of bytes transmitted.
- **Description**: The `fd_sock_tile_metrics_t` structure is designed to collect and store various metrics related to socket operations within a network tile. It includes counters for received and sent messages, both in terms of packet count and byte count, as well as specific metrics for dropped packets and system call usage. This data structure is crucial for monitoring and analyzing the performance and reliability of network communication in a system that utilizes multiple sockets and links for data transmission and reception.


---
### fd\_sock\_link\_tx
- **Type**: `struct`
- **Members**:
    - `base`: A pointer to the base address of the transmission link.
    - `chunk0`: An unsigned long integer representing the initial chunk of data for transmission.
    - `wmark`: An unsigned long integer indicating the watermark level for the transmission link.
- **Description**: The `fd_sock_link_tx` structure is designed to manage transmission links within a socket tile. It contains a base pointer for the link, an initial data chunk, and a watermark level to control or monitor the transmission process. This structure is part of a larger system that handles network communication, specifically for managing outgoing data links.


---
### fd\_sock\_link\_tx\_t
- **Type**: `struct`
- **Members**:
    - `base`: A pointer to the base address of the transmission link.
    - `chunk0`: An unsigned long representing the initial chunk or offset for the transmission.
    - `wmark`: An unsigned long indicating the watermark or threshold for the transmission.
- **Description**: The `fd_sock_link_tx_t` structure is designed to manage transmission links within a socket tile. It contains a base pointer for the link, an initial chunk offset, and a watermark to control or monitor the transmission process. This structure is part of a larger system that handles network communication, specifically for managing multiple transmission links efficiently.


---
### fd\_sock\_link\_rx
- **Type**: `struct`
- **Members**:
    - `base`: A pointer to the base address of the RX link buffer.
    - `chunk0`: An unsigned long representing the initial chunk index or offset.
    - `wmark`: An unsigned long indicating the watermark or threshold for the RX link.
    - `chunk`: An unsigned long representing the current chunk index or offset.
- **Description**: The `fd_sock_link_rx` structure is designed to manage the state and configuration of a receive (RX) link in a network socket tile. It includes a base pointer to the buffer, initial and current chunk indices, and a watermark to control data flow, facilitating efficient data reception and processing in network applications.


---
### fd\_sock\_link\_rx\_t
- **Type**: `struct`
- **Members**:
    - `base`: A pointer to the base address of the RX link buffer.
    - `chunk0`: An unsigned long representing the initial chunk index for the RX link.
    - `wmark`: An unsigned long indicating the watermark level for the RX link.
    - `chunk`: An unsigned long representing the current chunk index for the RX link.
- **Description**: The `fd_sock_link_rx_t` structure is designed to manage the state of a receive (RX) link in a socket-based communication system. It includes pointers and indices to handle data chunks, allowing efficient tracking and management of incoming data packets. This structure is part of a larger system that handles multiple RX and TX links, providing a framework for managing network communication in a high-performance environment.


---
### fd\_sock\_tile
- **Type**: `struct`
- **Members**:
    - `pollfd`: An array of pollfd structures for RX SOCK_DGRAM sockets, with a size defined by FD_SOCK_TILE_MAX_SOCKETS.
    - `sock_cnt`: A count of the number of sockets currently in use.
    - `proto_id`: An array of protocol identifiers for each socket, with a size defined by FD_SOCK_TILE_MAX_SOCKETS.
    - `tx_sock`: An integer representing the TX SOCK_RAW socket.
    - `tx_idle_cnt`: A counter for idle TX operations.
    - `bind_address`: An unsigned integer representing the bind address for the socket.
    - `batch_cnt`: A count of RX/TX batches, constrained to be less than or equal to STEM_BURST.
    - `batch_iov`: A pointer to an array of iovec structures for batch operations.
    - `batch_cmsg`: A pointer to control message data for batch operations.
    - `batch_sa`: A pointer to an array of sockaddr_in structures for batch operations.
    - `batch_msg`: A pointer to an array of mmsghdr structures for batch operations.
    - `rx_sock_port`: An array of port numbers for RX sockets, with a size defined by FD_SOCK_TILE_MAX_SOCKETS.
    - `link_rx_map`: An array mapping RX links, with a size defined by FD_SOCK_TILE_MAX_SOCKETS.
    - `link_rx`: An array of fd_sock_link_rx_t structures for RX links, with a size defined by MAX_NET_OUTS.
    - `link_tx`: An array of fd_sock_link_tx_t structures for TX links, with a size defined by MAX_NET_INS.
    - `tx_scratch0`: A pointer to the start of TX scratch memory.
    - `tx_scratch1`: A pointer to the end of TX scratch memory.
    - `tx_ptr`: A pointer within the range [tx_scratch0, tx_scratch1) for TX operations.
    - `metrics`: A structure containing metrics related to socket operations.
- **Description**: The `fd_sock_tile` structure is designed to manage socket operations for both receiving (RX) and transmitting (TX) data in a networked environment. It supports multiple RX SOCK_DGRAM sockets and a single TX SOCK_RAW socket, with arrays to handle up to a defined maximum number of sockets and links. The structure includes fields for managing socket counts, protocol identifiers, and batch operations, as well as pointers for handling batch data and control messages. Additionally, it maintains metrics for monitoring socket performance and includes scratch memory for TX operations. The design allows for efficient handling of network data, with potential optimizations for cache locality.


---
### fd\_sock\_tile\_t
- **Type**: `struct`
- **Members**:
    - `pollfd`: An array of pollfd structures for RX SOCK_DGRAM sockets, with a maximum size defined by FD_SOCK_TILE_MAX_SOCKETS.
    - `sock_cnt`: A count of the currently active sockets.
    - `proto_id`: An array storing protocol identifiers for each socket, with a size defined by FD_SOCK_TILE_MAX_SOCKETS.
    - `tx_sock`: An integer representing the TX SOCK_RAW socket.
    - `tx_idle_cnt`: A counter for idle TX operations.
    - `bind_address`: An unsigned integer representing the bind address for the TX socket.
    - `batch_cnt`: A count of RX/TX batches, constrained by STEM_BURST.
    - `batch_iov`: A pointer to an array of iovec structures for batch operations.
    - `batch_cmsg`: A pointer to control message data for batch operations.
    - `batch_sa`: A pointer to an array of sockaddr_in structures for batch operations.
    - `batch_msg`: A pointer to an array of mmsghdr structures for batch operations.
    - `rx_sock_port`: An array of port numbers for RX sockets, with a size defined by FD_SOCK_TILE_MAX_SOCKETS.
    - `link_rx_map`: An array mapping RX links, with a size defined by FD_SOCK_TILE_MAX_SOCKETS.
    - `link_rx`: An array of fd_sock_link_rx_t structures for RX links, with a maximum size defined by MAX_NET_OUTS.
    - `link_tx`: An array of fd_sock_link_tx_t structures for TX links, with a maximum size defined by MAX_NET_INS.
    - `tx_scratch0`: A pointer to the start of TX scratch memory.
    - `tx_scratch1`: A pointer to the end of TX scratch memory.
    - `tx_ptr`: A pointer within the range [tx_scratch0, tx_scratch1) for TX operations.
    - `metrics`: A structure of type fd_sock_tile_metrics_t for storing local metrics.
- **Description**: The `fd_sock_tile_t` structure is a complex data structure designed to manage network socket operations, specifically for UDP and raw socket communication. It includes arrays for managing multiple RX and TX sockets, with specific fields for socket counts, protocol identifiers, and batch processing. The structure also incorporates metrics tracking and scratch memory for TX operations, making it suitable for high-performance network applications that require efficient handling of multiple network links and batch processing capabilities.



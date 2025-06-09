# Purpose
This C header file is part of a larger system dealing with QUIC (Quick UDP Internet Connections) protocol tracing, likely for debugging or monitoring purposes. It defines data structures and function prototypes for managing and tracing QUIC connections, including mapping peer connection IDs to connection indices and handling trace contexts. The file includes several external variables and structures, such as `fd_quic_trace_ctx` and `fd_quic_trace_frame_ctx`, which are used to store tracing context and frame-specific information. Additionally, it provides function prototypes for tracing QUIC frames and handling received and logged data from QUIC tiles. The inclusion of a macro for pointer translation suggests that the code deals with memory address translation between different address spaces, which is common in systems that handle network data across different nodes or processes.
# Imports and Dependencies

---
- `../../../shared/fd_config.h`
- `../../../shared/fd_action.h`
- `../../../../disco/quic/fd_quic_tile.h`
- `../../../../waltz/quic/fd_quic_private.h`
- `../../../../util/tmpl/fd_map.c`


# Global Variables

---
### fd\_quic\_trace\_ctx
- **Type**: `fd_quic_ctx_t`
- **Description**: The `fd_quic_trace_ctx` is a global variable of type `fd_quic_ctx_t` that represents the relocated context of a target QUIC tile. It is used to store configuration and state information related to QUIC tracing, such as whether to dump configurations or connections, and network output settings.
- **Use**: This variable is used to manage and access the state and configuration of QUIC tracing operations within the application.


---
### fd\_quic\_trace\_ctx\_remote
- **Type**: `fd_quic_ctx_t const *`
- **Description**: The variable `fd_quic_trace_ctx_remote` is a pointer to a constant `fd_quic_ctx_t` structure. It represents the original QUIC context of a remote QUIC tile, but the pointer itself is located in the local address space.
- **Use**: This variable is used to access the original QUIC context of a remote tile from the local address space.


---
### fd\_quic\_trace\_ctx\_raddr
- **Type**: `ulong`
- **Description**: The `fd_quic_trace_ctx_raddr` is a global variable of type `ulong` that represents the relocated address of the QUIC context in the local address space. It is used to calculate the relative address of pointers within the QUIC context.
- **Use**: This variable is used to translate pointers from the relocated QUIC context to the original context in the local address space.


---
### fd\_quic\_trace\_link\_metrics
- **Type**: `ulong volatile *`
- **Description**: `fd_quic_trace_link_metrics` is a global variable that is a pointer to a volatile unsigned long integer. It is used to store metrics related to QUIC link tracing, which may be updated frequently and asynchronously by different parts of the program.
- **Use**: This variable is used to track and update link metrics for QUIC tracing in a concurrent environment.


---
### fd\_quic\_trace\_log\_base
- **Type**: `void const *`
- **Description**: The `fd_quic_trace_log_base` is a global pointer to a constant void type, indicating it is used to reference a base address for logging purposes in the QUIC tracing context. This variable is likely used to point to a memory location where log data related to QUIC operations is stored or accessed.
- **Use**: This variable is used as a base address for accessing or storing log data in the QUIC tracing system.


---
### \_fd\_quic\_trace\_peer\_map
- **Type**: `peer_conn_id_map_t`
- **Description**: The `_fd_quic_trace_peer_map` is a global array of `peer_conn_id_map_t` structures, with a size determined by the macro `1UL<<PEER_MAP_LG_SLOT_CNT`. This array is used to map peer connection IDs to connection indices, facilitating the management of peer connections in a QUIC protocol context.
- **Use**: This variable is used to store and manage mappings between peer connection IDs and their corresponding connection indices for efficient lookup and management in QUIC tracing operations.


---
### fd\_quic\_trace\_peer\_map
- **Type**: `peer_conn_id_map_t *`
- **Description**: The `fd_quic_trace_peer_map` is a global pointer to a `peer_conn_id_map_t` structure, which is used to map peer connection IDs to connection indices. This map is part of the QUIC tracing functionality and helps in managing and accessing connection information efficiently.
- **Use**: This variable is used to store and access the mapping of peer connection IDs to their respective connection indices in the QUIC tracing context.


---
### fd\_quic\_trace\_target\_fseq
- **Type**: `ulong **`
- **Description**: `fd_quic_trace_target_fseq` is a global variable that is a pointer to a pointer of unsigned long integers. It is used to store the fseq counters that are published by the target QUIC tile.
- **Use**: This variable is used to track and manage the sequence counters for the target QUIC tile, facilitating the tracing and debugging of QUIC connections.


---
### fd\_action\_quic\_trace
- **Type**: `action_t`
- **Description**: The variable `fd_action_quic_trace` is an external global variable of type `action_t`. It is likely used to represent a specific action or operation related to QUIC tracing within the application. The `action_t` type is defined in the included `fd_action.h` header, which suggests it is part of a framework or library for handling actions.
- **Use**: This variable is used to perform or represent a specific action related to QUIC tracing in the application.


# Data Structures

---
### peer\_conn\_id\_map
- **Type**: `struct`
- **Members**:
    - `conn_id`: The connection identifier for the peer, assumed to be at least 8 bytes long and truncated if longer.
    - `hash`: Stores a memoized hash value for the connection identifier.
    - `conn_idx`: Represents the index of the connection.
- **Description**: The `peer_conn_id_map` structure is designed to map a peer's connection identifier to a connection index, facilitating efficient lookup and management of connections. It includes a `conn_id` field for the peer's connection identifier, a `hash` field to store a precomputed hash value for quick access, and a `conn_idx` field to indicate the specific index of the connection. This structure is particularly useful in networking contexts where managing multiple connections efficiently is crucial.


---
### peer\_conn\_id\_map\_t
- **Type**: `struct`
- **Members**:
    - `conn_id`: The peer connection ID, assumed to be at least 8 bytes long, with any excess truncated.
    - `hash`: A memoized hash value for the connection ID.
    - `conn_idx`: The index of the connection associated with the peer connection ID.
- **Description**: The `peer_conn_id_map_t` structure is designed to map a peer connection ID to a connection index, facilitating efficient lookup and management of connections in a QUIC protocol context. It includes a `conn_id` field to store the peer's connection ID, a `hash` field to store a precomputed hash value for quick access, and a `conn_idx` field to store the index of the connection. This structure is part of a larger system for tracing and managing QUIC connections, as indicated by its inclusion in the QUIC trace header file.


---
### fd\_quic\_trace\_ctx
- **Type**: `struct`
- **Members**:
    - `dump`: Indicates if the user requested a dump operation.
    - `dump_config`: Indicates if the user requested a configuration dump.
    - `dump_conns`: Indicates if the user requested a connections dump.
    - `net_out`: Indicates if transmission (net-out) packets should be included.
    - `net_out_base`: Specifies the base address of net-out chunks in the local address space.
- **Description**: The `fd_quic_trace_ctx` structure is used to manage and store context information for tracing operations in a QUIC protocol implementation. It includes flags to determine if specific types of data dumps (general, configuration, or connections) have been requested by the user, as well as whether outgoing network packets should be included in the trace. Additionally, it holds the base address for net-out chunks, which is crucial for managing memory and data flow in the local address space during tracing.


---
### fd\_quic\_trace\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `dump`: Indicates if the user requested a dump operation.
    - `dump_config`: Indicates if the user requested a configuration dump.
    - `dump_conns`: Indicates if the user requested a connections dump.
    - `net_out`: Indicates if transmission (net-out) packets should be included.
    - `net_out_base`: Base address of net-out chunks in the local address space.
- **Description**: The `fd_quic_trace_ctx_t` structure is used to manage tracing context for QUIC operations, specifically for handling user requests related to dumping various aspects of the QUIC state, such as configuration and connections. It also manages the inclusion of network output packets and their base address in the local address space. This structure is part of a larger system for tracing and logging QUIC operations, providing a way to control and configure the tracing behavior.


---
### fd\_quic\_trace\_frame\_ctx
- **Type**: `struct`
- **Members**:
    - `conn_id`: A unique identifier for the connection.
    - `src_ip`: The source IP address of the packet.
    - `src_port`: The source port number of the packet.
    - `pkt_type`: The type of the packet.
    - `pkt_num`: The packet number in the sequence.
- **Description**: The `fd_quic_trace_frame_ctx` structure is used to encapsulate context information for a QUIC frame trace. It includes fields for identifying the connection (`conn_id`), the source IP address (`src_ip`), the source port (`src_port`), the type of packet (`pkt_type`), and the packet number (`pkt_num`). This structure is likely used in the context of tracing or logging network packets in a QUIC protocol implementation, providing essential metadata for each packet processed.


---
### fd\_quic\_trace\_frame\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `conn_id`: A unique identifier for the connection.
    - `src_ip`: The source IP address of the packet.
    - `src_port`: The source port number of the packet.
    - `pkt_type`: The type of the packet, represented as an unsigned character.
    - `pkt_num`: The packet number, used for tracking the sequence of packets.
- **Description**: The `fd_quic_trace_frame_ctx_t` structure is used to represent the context of a QUIC frame trace, containing essential information about the connection and packet details such as connection ID, source IP and port, packet type, and packet number. This structure is likely used in the context of tracing or logging network packets in a QUIC protocol implementation.


# Function Declarations (Public API)

---
### fd\_quic\_trace\_frames<!-- {{#callable_declaration:fd_quic_trace_frames}} -->
Processes QUIC frames from a data buffer.
- **Description**: This function is used to process a series of QUIC frames from a given data buffer, updating the provided context with information about each frame. It should be called when there is a need to parse and trace QUIC frames from a data stream. The function iterates over the data buffer, processing each frame until the entire buffer is consumed or an error is encountered. It is important to ensure that the context is properly initialized before calling this function. The function will stop processing if it encounters a parsing failure or if the returned frame size exceeds the remaining data size.
- **Inputs**:
    - `context`: A pointer to an fd_quic_trace_frame_ctx_t structure that will be updated with information about each processed frame. Must not be null.
    - `data`: A pointer to a buffer containing the data to be processed. The buffer must contain valid QUIC frame data and must not be null.
    - `data_sz`: The size of the data buffer in bytes. Must be greater than zero.
- **Output**: None
- **See also**: [`fd_quic_trace_frames`](fd_quic_trace_frame.c.driver.md#fd_quic_trace_frames)  (Implementation)


---
### fd\_quic\_trace\_rx\_tile<!-- {{#callable_declaration:fd_quic_trace_rx_tile}} -->
Processes received and transmitted QUIC packets for tracing.
- **Description**: This function is used to trace QUIC packets by processing both received and transmitted packet metadata. It should be called when there is a need to analyze or log QUIC packet activity for debugging or monitoring purposes. The function requires a valid tracing context and metadata for both received and transmitted packets. It does not return any value or modify the input parameters, but it may have side effects related to the tracing process, such as logging or updating internal states.
- **Inputs**:
    - `trace_ctx`: A pointer to an fd_quic_trace_ctx_t structure that provides the context for tracing. This must not be null and should be properly initialized before calling the function.
    - `rx_mcache`: A pointer to a constant fd_frag_meta_t structure representing the metadata of received packets. This must not be null and should point to valid metadata.
    - `tx_mcache`: A pointer to a constant fd_frag_meta_t structure representing the metadata of transmitted packets. This must not be null and should point to valid metadata.
- **Output**: None
- **See also**: [`fd_quic_trace_rx_tile`](fd_quic_trace_rx_tile.c.driver.md#fd_quic_trace_rx_tile)  (Implementation)


---
### fd\_quic\_trace\_log\_tile<!-- {{#callable_declaration:fd_quic_trace_log_tile}} -->
Logs QUIC tile activity using the provided metadata cache.
- **Description**: Use this function to log activity related to a QUIC tile by providing a metadata cache. This function is typically called when there is a need to trace or debug the operations of a QUIC tile. It requires a valid metadata cache pointer and does not return any value. Ensure that the metadata cache is properly initialized and valid before calling this function to avoid undefined behavior.
- **Inputs**:
    - `in_mcache`: A pointer to a constant fd_frag_meta_t structure representing the input metadata cache. This parameter must not be null and should point to a valid and initialized metadata cache structure. The caller retains ownership of the memory.
- **Output**: None
- **See also**: [`fd_quic_trace_log_tile`](fd_quic_trace_log_tile.c.driver.md#fd_quic_trace_log_tile)  (Implementation)



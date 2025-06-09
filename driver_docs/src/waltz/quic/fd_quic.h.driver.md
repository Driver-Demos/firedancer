# Purpose
The provided C header file, `fd_quic.h`, defines a partial implementation of the QUIC protocol, which is an encrypted, multiplexing transport layer network protocol. This implementation supports IPv4 over Ethernet and is designed to be non-blocking and single-threaded, with scalability achieved through multiple instances and load balancing based on connection identifiers. The file outlines the memory management, lifecycle, and configuration of QUIC objects, emphasizing pre-allocated memory and position-independent formatting for efficient resource management. It also includes detailed structures and function prototypes for managing QUIC connections, streams, and callbacks, adhering to the specifications of RFC 9000 and RFC 9001.

The header file provides a comprehensive API for initializing, configuring, and managing QUIC connections and streams. It defines several key structures, such as `fd_quic_t`, `fd_quic_limits_t`, and `fd_quic_config_t`, which encapsulate the memory layout, limits, and configuration parameters of a QUIC instance. The file also specifies a set of user-provided callbacks for handling connection and stream events, as well as functions for managing the lifecycle of QUIC objects, including creation, joining, initialization, and deletion. Additionally, it includes metrics for monitoring network, connection, packet, and stream performance, and provides utility functions for setting up network transmission and clock sources. This header is intended to be included in other C files to provide the necessary interfaces and definitions for working with the QUIC protocol in a Firedancer environment.
# Imports and Dependencies

---
- `fd_quic_common.h`
- `fd_quic_enum.h`
- `../aio/fd_aio.h`
- `../tls/fd_tls.h`
- `../../util/hist/fd_histf.h`
- `fd_quic_conn.h`
- `fd_quic_stream.h`


# Global Variables

---
### fd\_quic\_new
- **Type**: `function pointer`
- **Description**: `fd_quic_new` is a function pointer that formats an unused memory region for use as a QUIC client or server. It takes a non-NULL pointer to the memory region and a temporary reference to `fd_quic_limits_t` to determine the required footprint.
- **Use**: This function is used to initialize a memory region for a QUIC object, returning an opaque handle to the formatted region.


---
### fd\_quic\_join
- **Type**: `fd_quic_t *`
- **Description**: The `fd_quic_join` function is a global function that returns a pointer to an `fd_quic_t` structure. This function is used to join a caller to a QUIC object, performing basic coherence checks on the provided memory region.
- **Use**: This function is used to obtain a typed pointer to a QUIC object from a memory region, allowing the caller to interact with the QUIC instance.


---
### fd\_quic\_leave
- **Type**: `function pointer`
- **Description**: `fd_quic_leave` is a function pointer that is part of the QUIC API, designed to handle the process of leaving a current local join of a QUIC instance. It is responsible for freeing all dynamically managed resources associated with the QUIC instance, such as heap allocations and OS handles.
- **Use**: This function is used to properly disconnect from a QUIC instance, ensuring that all resources are released and the instance is left in a clean state.


---
### fd\_quic\_delete
- **Type**: `function pointer`
- **Description**: `fd_quic_delete` is a function pointer that points to a function responsible for unformatting a memory region used as an `fd_quic_t` object. It assumes that no threads are currently joined to the region and returns the given `quic` pointer on success, or NULL if used incorrectly.
- **Use**: This function is used to delete or unformat a `fd_quic_t` object, transferring ownership of the memory region back to the caller.


---
### fd\_quic\_get\_aio\_net\_rx
- **Type**: `fd_aio_t const *`
- **Description**: The `fd_quic_get_aio_net_rx` function returns a constant pointer to an `fd_aio_t` structure, which represents the asynchronous I/O base class for a QUIC instance. This pointer is valid for the lifetime of the QUIC instance and provides access to the network receive operations.
- **Use**: This function is used to obtain the asynchronous I/O base class for network receive operations associated with a QUIC instance.


---
### fd\_quic\_init
- **Type**: `fd_quic_t *`
- **Description**: The `fd_quic_init` function is a global function that initializes a QUIC object, represented by `fd_quic_t`, for use. It prepares the QUIC instance to be ready to serve from the thread that calls this function, ensuring exclusive access to the QUIC object during its operation.
- **Use**: This function is used to initialize a QUIC object, making it ready for network operations and ensuring it is configured correctly before use.


---
### fd\_quic\_fini
- **Type**: `function pointer`
- **Description**: `fd_quic_fini` is a function pointer that takes a pointer to an `fd_quic_t` structure as an argument and returns a pointer to an `fd_quic_t` structure. It is part of the QUIC API, which is a partial implementation of the QUIC protocol, an encrypted, multiplexing transport layer network protocol.
- **Use**: This function is used to release exclusive access over a QUIC instance, zero-initialize references to external objects, and free any heap allocations made during initialization.


# Data Structures

---
### fd\_quic\_conn\_t
- **Type**: `typedef`
- **Members**:
    - `fd_quic_conn_t`: A typedef for the struct fd_quic_conn, representing a QUIC connection.
- **Description**: The `fd_quic_conn_t` is a typedef for a structure representing a QUIC connection within the Firedancer QUIC implementation. This structure is part of a larger system designed to handle encrypted, multiplexing transport layer network protocols, specifically supporting IPv4 over Ethernet. The `fd_quic_conn_t` is used in conjunction with various callbacks and configuration settings to manage the lifecycle and operations of QUIC connections, including connection initiation, handshake completion, and connection termination. The structure is integral to the non-blocking, single-threaded design of the Firedancer QUIC API, which aims to be compliant with RFC 9000 and RFC 9001 standards.


---
### fd\_quic\_stream\_t
- **Type**: `typedef struct fd_quic_stream fd_quic_stream_t;`
- **Description**: The `fd_quic_stream_t` is a forward declaration of a structure used in the QUIC protocol implementation. It represents a stream within a QUIC connection, which is a fundamental component of the QUIC protocol allowing multiplexed data streams over a single connection. The actual structure definition is not provided in the given code, indicating that it is likely defined elsewhere, possibly in a separate file or module. This forward declaration allows the use of pointers to `fd_quic_stream_t` in function prototypes and other structures without needing the complete definition at this point.


---
### fd\_quic\_state\_t
- **Type**: `typedef struct fd_quic_state_private fd_quic_state_t;`
- **Description**: The `fd_quic_state_t` is a typedef for a structure named `fd_quic_state_private`, which is not defined in the provided code. This suggests that `fd_quic_state_t` is intended to be an opaque type, likely used to encapsulate the internal state of a QUIC protocol implementation. The actual structure definition is hidden, indicating that users of this type should interact with it through provided APIs rather than directly accessing its members.


---
### fd\_quic\_limits
- **Type**: `struct`
- **Members**:
    - `conn_cnt`: Maximum number of concurrent connections allowed instance-wide.
    - `handshake_cnt`: Maximum number of concurrent handshakes allowed instance-wide.
    - `log_depth`: Depth of the shared memory log cache instance-wide.
    - `conn_id_cnt`: Maximum number of connection IDs allowed per connection, with a minimum of 4.
    - `stream_id_cnt`: Maximum number of concurrent stream IDs allowed per connection.
    - `inflight_frame_cnt`: Total maximum number of inflight frames allowed instance-wide.
    - `min_inflight_frame_cnt_conn`: Minimum number of inflight frames allowed per connection.
    - `tx_buf_sz`: Size of the transmission buffer in bytes per stream.
    - `stream_pool_cnt`: Number of streams in the stream pool instance-wide.
- **Description**: The `fd_quic_limits` structure defines various limits and constraints for a QUIC instance, ensuring efficient resource management and performance optimization. It specifies the maximum number of concurrent connections, handshakes, and inflight frames allowed across the instance, as well as per-connection limits for connection IDs and stream IDs. Additionally, it sets the size of the transmission buffer for each stream and the total number of streams available in the stream pool. These limits are immutable and remain constant throughout the lifetime of the QUIC instance, providing a framework for memory allocation and operational boundaries.


---
### fd\_quic\_limits\_t
- **Type**: `struct`
- **Members**:
    - `conn_cnt`: Maximum number of concurrent connections allowed instance-wide.
    - `handshake_cnt`: Maximum number of concurrent handshakes allowed instance-wide.
    - `log_depth`: Depth of the shared memory log cache instance-wide.
    - `conn_id_cnt`: Maximum number of connection IDs allowed per connection.
    - `stream_id_cnt`: Maximum number of concurrent stream IDs allowed per connection.
    - `inflight_frame_cnt`: Total maximum number of inflight frames allowed instance-wide.
    - `min_inflight_frame_cnt_conn`: Minimum number of inflight frames allowed per connection.
    - `tx_buf_sz`: Size of the transmission buffer in bytes per stream.
    - `stream_pool_cnt`: Number of streams in the stream pool instance-wide.
- **Description**: The `fd_quic_limits_t` structure defines the memory layout constraints for an `fd_quic_t` object, setting immutable limits that govern the maximum number of connections, handshakes, and streams, as well as buffer sizes and frame counts. These limits are constant throughout the lifetime of an `fd_quic_t` instance, ensuring consistent resource allocation and management for QUIC protocol operations.


---
### fd\_quic\_layout
- **Type**: `struct`
- **Members**:
    - `meta_sz`: Size of the fd_quic_layout structure.
    - `log_off`: Offset to the QUIC log memory region.
    - `conns_off`: Offset to the connection memory region.
    - `conn_footprint`: Size of a single connection footprint.
    - `conn_map_off`: Offset to the connection map memory region.
    - `lg_slot_cnt`: Logarithmic slot count for connection map.
    - `hs_pool_off`: Offset to the handshake pool memory region.
    - `stream_pool_off`: Offset to the stream pool memory region.
    - `pkt_meta_pool_off`: Offset to the packet metadata pool memory region.
- **Description**: The `fd_quic_layout` structure is a layout descriptor for the memory organization of a QUIC object in the Firedancer library. It provides offsets and sizes for various memory regions associated with QUIC operations, such as logging, connections, handshakes, streams, and packet metadata. This structure is derived from `fd_quic_limits_t` and is used to manage the pre-allocated memory layout for efficient QUIC protocol operations.


---
### fd\_quic\_layout\_t
- **Type**: `struct`
- **Members**:
    - `meta_sz`: Size of the fd_quic_layout struct.
    - `log_off`: Offset to the QUIC log.
    - `conns_off`: Offset of the connection memory region.
    - `conn_footprint`: Size of a connection.
    - `conn_map_off`: Offset of the connection map memory region.
    - `lg_slot_cnt`: Logarithm of the slot count for connection map.
    - `hs_pool_off`: Offset of the handshake pool.
    - `stream_pool_off`: Offset of the stream pool.
    - `pkt_meta_pool_off`: Offset of the packet metadata pool.
- **Description**: The `fd_quic_layout_t` structure is an offset table that describes the memory layout of an `fd_quic_t` object, which is a part of a QUIC implementation. It is derived from `fd_quic_limits_t` and provides information about the size and offsets of various components within the QUIC object, such as connection memory regions, stream pools, and packet metadata pools. This layout is crucial for managing the memory efficiently and ensuring that the QUIC object is correctly structured in memory.


---
### fd\_quic\_config
- **Type**: `struct`
- **Members**:
    - `role`: Specifies the role of the QUIC instance, either client or server.
    - `retry`: Indicates if address validation using retry packets is enabled.
    - `tick_per_us`: Represents the number of clock ticks per microsecond.
    - `idle_timeout`: Defines the upper bound on connection idle timeout in nanoseconds.
    - `keep_alive`: Determines if QUIC PING frames are used to keep connections alive.
    - `ack_delay`: Specifies the median delay on outgoing ACKs in nanoseconds.
    - `ack_threshold`: Sets the byte threshold for sending an immediate ACK.
    - `retry_ttl`: Defines the time-to-live for retry tokens in nanoseconds.
    - `tls_hs_ttl`: Specifies the time-to-live for TLS handshake in nanoseconds.
    - `identity_public_key`: Holds the Ed25519 public key of the node identity.
    - `sign`: Pointer to a function for signing TLS 1.3 certificate verify payload.
    - `sign_ctx`: Context pointer for the signing function.
    - `keylog_file`: Path to the file for logging TLS keys.
    - `initial_rx_max_stream_data`: Maximum stream data size in bytes for receiving, set by the user.
    - `net.dscp`: Differentiated services code point for outgoing IPv4 packets.
- **Description**: The `fd_quic_config` structure is a configuration data structure for a QUIC (Quick UDP Internet Connections) instance, which is a transport layer network protocol designed for multiplexing and encryption. This structure contains various configuration parameters that define the behavior and characteristics of a QUIC connection, such as role (client or server), retry mechanisms, timing configurations, and network settings. It also includes fields for TLS configuration, such as public key and signing function, and network-specific settings like DSCP for packet prioritization. The structure is aligned to 16 bytes and is used to configure the QUIC instance before it becomes active.


---
### fd\_quic\_callbacks
- **Type**: `struct`
- **Members**:
    - `quic_ctx`: A user-provided context pointer for instance-wide callbacks.
    - `conn_new`: A non-NULL function pointer for handling new connection events, using quic_ctx.
    - `conn_hs_complete`: A non-NULL function pointer for handling connection handshake completion events, using quic_ctx.
    - `conn_final`: A non-NULL function pointer for handling connection termination notifications, using quic_ctx.
    - `stream_notify`: A non-NULL function pointer for handling notable stream events, using stream_ctx.
    - `stream_rx`: A non-NULL function pointer for handling stream data reception events, using stream_ctx.
    - `tls_keylog`: A nullable function pointer for handling new encryption secret availability, using quic_ctx.
    - `now`: A non-NULL function pointer for the clock source used internally by QUIC.
    - `now_ctx`: A user-provided context pointer for now function calls.
- **Description**: The `fd_quic_callbacks` structure defines a set of user-provided callback functions that are invoked by the QUIC library to handle various events such as new connections, handshake completions, connection terminations, stream notifications, and data receptions. It also includes a clock source function and associated context pointers for both instance-wide and stream-specific callbacks. This structure is essential for integrating user-defined behavior into the QUIC protocol operations, allowing for customized handling of network events and timing.


---
### fd\_quic\_callbacks\_t
- **Type**: `struct`
- **Members**:
    - `quic_ctx`: A user-provided context pointer for instance-wide callbacks.
    - `conn_new`: A callback function pointer for when a server receives a new connection and completes handshakes.
    - `conn_hs_complete`: A callback function pointer for when a client completes a handshake of a connection it created.
    - `conn_final`: A callback function pointer for connection termination notification.
    - `stream_notify`: A callback function pointer that signals a notable stream event.
    - `stream_rx`: A callback function pointer for handling received stream data.
    - `tls_keylog`: A callback function pointer called when a new encryption secret becomes available.
    - `now`: A function pointer to the clock source used internally by QUIC for scheduling events.
    - `now_ctx`: A user-provided context pointer for the clock source function calls.
- **Description**: The `fd_quic_callbacks_t` structure defines a set of user-provided callback functions that are invoked by the QUIC library to notify the user of various events such as new connections, handshake completions, connection terminations, stream events, and encryption key logging. It also includes a clock source function for scheduling events. This structure is essential for integrating user-defined behavior into the QUIC protocol operations, allowing for custom handling of network events and timing.


---
### fd\_quic\_metrics
- **Type**: `union`
- **Members**:
    - `net_rx_pkt_cnt`: Number of IP packets received.
    - `net_rx_byte_cnt`: Total bytes received, including IP, UDP, and QUIC headers.
    - `net_tx_pkt_cnt`: Number of IP packets sent.
    - `net_tx_byte_cnt`: Total bytes sent.
    - `retry_tx_cnt`: Number of Retry packets sent.
    - `conn_active_cnt`: Number of active connections.
    - `conn_created_cnt`: Number of connections created.
    - `conn_closed_cnt`: Number of connections gracefully closed.
    - `conn_aborted_cnt`: Number of connections aborted.
    - `conn_timeout_cnt`: Number of connections that timed out.
    - `conn_retry_cnt`: Number of connections established with retry.
    - `conn_err_no_slots_cnt`: Number of connections that failed to create due to lack of slots.
    - `conn_err_retry_fail_cnt`: Number of connections that failed during retry, e.g., due to invalid token.
    - `pkt_net_hdr_err_cnt`: Number of packets dropped due to unusual IPv4/UDP headers.
    - `pkt_quic_hdr_err_cnt`: Number of packets dropped due to unusual QUIC header.
    - `pkt_undersz_cnt`: Number of QUIC packets dropped for being too small.
    - `pkt_oversz_cnt`: Number of QUIC packets dropped for being too large.
    - `pkt_decrypt_fail_cnt`: Number of packets that failed decryption due to authentication tag issues.
    - `pkt_no_key_cnt`: Number of packets that failed decryption due to missing key.
    - `pkt_no_conn_cnt`: Number of packets with unknown connection ID, excluding Initial packets.
    - `frame_tx_alloc_cnt`: Number of packet metadata allocation successes and failures.
    - `pkt_verneg_cnt`: Number of QUIC version negotiation packets or packets with incorrect version.
    - `pkt_retransmissions_cnt`: Number of packet metadata retries.
    - `frame_rx_cnt`: Number of frames received, indexed by implementation-defined IDs.
    - `frame_rx_err_cnt`: Number of frames that failed.
    - `hs_created_cnt`: Number of handshake flows created.
    - `hs_err_alloc_fail_cnt`: Number of handshakes dropped due to allocation failure.
    - `hs_evicted_cnt`: Number of handshakes evicted.
    - `stream_opened_cnt`: Number of streams opened.
    - `stream_closed_cnt`: Number of streams closed, indexed by notification type.
    - `stream_active_cnt`: Number of active streams.
    - `stream_rx_event_cnt`: Number of stream receive events.
    - `stream_rx_byte_cnt`: Total stream payload bytes received.
    - `ack_tx`: Array of acknowledgment transmission counts.
    - `service_duration`: Time spent in service, measured as a histogram.
    - `receive_duration`: Time spent in receive calls, measured as a histogram.
- **Description**: The `fd_quic_metrics` union is a comprehensive data structure designed to track various metrics related to QUIC protocol operations. It includes network metrics such as packet and byte counts for both received and transmitted data, connection metrics detailing the number of active, created, closed, and failed connections, and packet metrics that track errors and retransmissions. Additionally, it monitors frame and handshake metrics, stream operations, acknowledgment transmissions, and performance metrics like service and receive durations. This union is essential for performance monitoring and debugging in QUIC implementations.


---
### fd\_quic\_metrics\_t
- **Type**: `union`
- **Members**:
    - `net_rx_pkt_cnt`: Number of IP packets received.
    - `net_rx_byte_cnt`: Total bytes received, including IP, UDP, and QUIC headers.
    - `net_tx_pkt_cnt`: Number of IP packets sent.
    - `net_tx_byte_cnt`: Total bytes sent.
    - `retry_tx_cnt`: Number of Retry packets sent.
    - `conn_active_cnt`: Number of active connections.
    - `conn_created_cnt`: Number of connections created.
    - `conn_closed_cnt`: Number of connections gracefully closed.
    - `conn_aborted_cnt`: Number of connections aborted.
    - `conn_timeout_cnt`: Number of connections that timed out.
    - `conn_retry_cnt`: Number of connections established with retry.
    - `conn_err_no_slots_cnt`: Number of connections that failed to create due to lack of slots.
    - `conn_err_retry_fail_cnt`: Number of connections that failed during retry due to invalid token.
    - `pkt_net_hdr_err_cnt`: Number of packets dropped due to unusual IPv4/UDP headers.
    - `pkt_quic_hdr_err_cnt`: Number of packets dropped due to unusual QUIC header.
    - `pkt_undersz_cnt`: Number of QUIC packets dropped for being too small.
    - `pkt_oversz_cnt`: Number of QUIC packets dropped for being too large.
    - `pkt_decrypt_fail_cnt`: Number of packets that failed decryption due to authentication tag.
    - `pkt_no_key_cnt`: Number of packets that failed decryption due to missing key.
    - `pkt_no_conn_cnt`: Number of packets with unknown connection ID, excluding Initial.
    - `frame_tx_alloc_cnt`: Number of packet metadata allocation successes and failures.
    - `pkt_verneg_cnt`: Number of QUIC version negotiation packets or packets with wrong version.
    - `pkt_retransmissions_cnt`: Number of packet metadata retries.
    - `frame_rx_cnt`: Number of frames received, indexed by implementation-defined IDs.
    - `frame_rx_err_cnt`: Number of frames that failed.
    - `hs_created_cnt`: Number of handshake flows created.
    - `hs_err_alloc_fail_cnt`: Number of handshakes dropped due to allocation failure.
    - `hs_evicted_cnt`: Number of handshakes evicted.
    - `stream_opened_cnt`: Number of streams opened.
    - `stream_closed_cnt`: Number of streams closed, indexed by notification type.
    - `stream_active_cnt`: Number of active streams.
    - `stream_rx_event_cnt`: Number of stream RX events.
    - `stream_rx_byte_cnt`: Total stream payload bytes received.
    - `ack_tx`: ACK transmission metrics.
    - `service_duration`: Time spent in service, measured by a histogram.
    - `receive_duration`: Time spent in RX calls, measured by a histogram.
- **Description**: The `fd_quic_metrics_t` is a union that encapsulates a comprehensive set of metrics for monitoring the performance and behavior of a QUIC implementation. It includes network metrics such as packet counts and byte counts for both received and transmitted data, connection metrics detailing the number of active, created, closed, and aborted connections, as well as error counts for various connection failures. Additionally, it tracks packet and frame metrics, including errors related to headers, decryption failures, and retransmissions. Handshake and stream metrics provide insights into the number of handshakes and streams created, closed, and active, along with byte counts and event counts. The structure also includes performance metrics that measure the duration of service and receive operations using histograms. This union is designed to provide a detailed overview of the QUIC protocol's operation, aiding in performance tuning and debugging.


---
### fd\_quic
- **Type**: `struct`
- **Members**:
    - `magic`: A magic number used to identify the structure, expected to be equal to FD_QUIC_MAGIC.
    - `layout`: Defines the memory layout of the fd_quic object, position-independent and read-only.
    - `limits`: Specifies the immutable limits for the fd_quic object, position-independent and read-only.
    - `config`: Holds the mutable configuration settings for the fd_quic object, writable before initialization.
    - `cb`: Contains user-provided callbacks for the QUIC library, reset on join and writable before initialization.
    - `metrics`: Stores various metrics related to network, connection, packet, and performance, position-independent and read-only.
    - `aio_rx`: Represents the local asynchronous I/O for receiving data.
    - `aio_tx`: Represents the remote asynchronous I/O for transmitting data.
- **Description**: The `fd_quic` structure is a core component of a partial implementation of the QUIC protocol, which is an encrypted, multiplexing transport layer network protocol. This structure encapsulates various components necessary for managing QUIC connections, including configuration, callbacks, and metrics. It is designed to be position-independent and persistent, with certain fields being writable only before initialization. The structure also includes asynchronous I/O components for handling network data transmission and reception. The `fd_quic` structure is part of a non-blocking, single-threaded API that supports IPv4 over Ethernet and aims to comply with RFC 9000 and RFC 9001 standards.


# Function Declarations (Public API)

---
### fd\_quic\_align<!-- {{#callable_declaration:fd_quic_align}} -->
Return the required memory alignment for a QUIC object.
- **Description**: Use this function to determine the alignment requirement for memory regions intended to store a QUIC object. This is essential when allocating memory for QUIC objects to ensure proper alignment, which can affect performance and correctness. The function does not require any parameters and always returns the alignment value.
- **Inputs**: None
- **Output**: Returns the alignment requirement as an unsigned long integer.
- **See also**: [`fd_quic_align`](fd_quic.c.driver.md#fd_quic_align)  (Implementation)


---
### fd\_quic\_footprint<!-- {{#callable_declaration:fd_quic_footprint}} -->
Calculate the memory footprint required for a QUIC object.
- **Description**: Use this function to determine the amount of memory needed to allocate a QUIC object based on the specified limits. This is useful for planning memory allocation before creating a QUIC instance. The function requires a valid `fd_quic_limits_t` structure, which defines the constraints and capacities of the QUIC object. If the input is invalid, the function will return 0, indicating an error in calculating the footprint.
- **Inputs**:
    - `limits`: A pointer to a constant `fd_quic_limits_t` structure that specifies the limits for the QUIC object. This parameter must not be null, and it should be properly initialized with valid values. If the input is invalid, the function returns 0.
- **Output**: Returns the memory footprint in bytes required for the QUIC object. If the input is invalid, returns 0.
- **See also**: [`fd_quic_footprint`](fd_quic.c.driver.md#fd_quic_footprint)  (Implementation)


---
### fd\_quic\_new<!-- {{#callable_declaration:fd_quic_new}} -->
Formats a memory region for use as a QUIC client or server.
- **Description**: This function prepares a pre-allocated memory region to be used as a QUIC object, either as a client or server. It requires a valid memory pointer and a set of limits that define the configuration of the QUIC instance. The memory must be properly aligned, and the limits must specify valid values for connection and handshake counts, among other parameters. If any of these preconditions are not met, the function will return NULL, indicating failure. This function is typically called during the setup phase of a QUIC instance, before any operations are performed on it.
- **Inputs**:
    - `mem`: A non-NULL pointer to a pre-allocated memory region with the required alignment and footprint. The caller retains ownership and must ensure the memory is correctly aligned.
    - `limits`: A non-NULL pointer to a fd_quic_limits_t structure that specifies the configuration limits for the QUIC instance. The structure must contain valid values, such as non-zero connection and handshake counts, and must not exceed certain maximums.
- **Output**: Returns a pointer to the initialized fd_quic_t structure on success, or NULL on failure if the input parameters are invalid or the memory is misaligned.
- **See also**: [`fd_quic_new`](fd_quic.c.driver.md#fd_quic_new)  (Implementation)


---
### fd\_quic\_join<!-- {{#callable_declaration:fd_quic_join}} -->
Joins the caller to a QUIC object.
- **Description**: This function is used to join a caller to a QUIC object, allowing interaction with the QUIC instance. It performs basic validation checks on the provided memory region to ensure it is correctly formatted as a QUIC object. This function should be called when a valid, formatted QUIC memory region is available, and the caller intends to interact with the QUIC instance. It is important to ensure that the memory region is correctly aligned and initialized before calling this function. A successful join should be matched with a corresponding leave to properly manage resources.
- **Inputs**:
    - `shquic`: A pointer to the memory region backing the QUIC object in the caller's address space. It must not be null, must be aligned according to FD_QUIC_ALIGN, and must point to a correctly formatted QUIC object. If these conditions are not met, the function returns NULL and logs a warning.
- **Output**: Returns a pointer to the fd_quic_t object on success, or NULL on failure if the input is invalid or the memory region is not correctly formatted.
- **See also**: [`fd_quic_join`](fd_quic.c.driver.md#fd_quic_join)  (Implementation)


---
### fd\_quic\_leave<!-- {{#callable_declaration:fd_quic_leave}} -->
Leaves a current local join of a QUIC object.
- **Description**: This function is used to leave a current local join of a QUIC object, freeing all dynamically managed resources associated with the join. It should be called when a thread no longer needs to interact with a joined fd_quic_t object. The function returns the given quic object on success, allowing for further operations if needed, or NULL on failure, which may occur if the quic parameter is NULL or if there is no active join to leave. It is important to ensure that this function is called to properly manage resources and avoid memory leaks.
- **Inputs**:
    - `quic`: A pointer to an fd_quic_t object representing the current local join. Must not be NULL and should point to an active join. If invalid, the function returns NULL.
- **Output**: Returns the given quic pointer on success, or NULL on failure.
- **See also**: [`fd_quic_leave`](fd_quic.c.driver.md#fd_quic_leave)  (Implementation)


---
### fd\_quic\_delete<!-- {{#callable_declaration:fd_quic_delete}} -->
Unformats a memory region used as an fd_quic_t.
- **Description**: This function is used to unformat a memory region that was previously formatted for use as an fd_quic_t, effectively deleting the QUIC object. It should be called when the QUIC object is no longer needed, and it is assumed that no threads are currently joined to the region. This function transfers ownership of the memory region back to the caller, allowing it to be reused or freed. It is important to ensure that the memory region is correctly aligned and that the fd_quic_t object is valid before calling this function.
- **Inputs**:
    - `quic`: A pointer to the fd_quic_t object to be deleted. It must not be null, must be correctly aligned, and must have a valid magic number. If these conditions are not met, the function logs a warning and returns null.
- **Output**: Returns the given quic pointer on success, or null if the input is invalid.
- **See also**: [`fd_quic_delete`](fd_quic.c.driver.md#fd_quic_delete)  (Implementation)


---
### fd\_quic\_get\_aio\_net\_rx<!-- {{#callable_declaration:fd_quic_get_aio_net_rx}} -->
Retrieve the AIO base class for network reception from a QUIC instance.
- **Description**: This function provides access to the asynchronous I/O (AIO) base class used for receiving network data in a QUIC instance. It should be called when you need to interact with the network reception aspect of a QUIC object. The returned AIO object is valid for the lifetime of the QUIC instance. However, any operations on the AIO must be performed by the thread that has exclusive access to the QUIC instance, ensuring thread safety and proper synchronization.
- **Inputs**:
    - `quic`: A pointer to an fd_quic_t instance. This must not be null and should point to a valid, initialized QUIC object. The caller must ensure exclusive access to the QUIC instance when using the returned AIO object.
- **Output**: Returns a pointer to the fd_aio_t object used for network reception, which is part of the specified QUIC instance.
- **See also**: [`fd_quic_get_aio_net_rx`](fd_quic.c.driver.md#fd_quic_get_aio_net_rx)  (Implementation)


---
### fd\_quic\_set\_aio\_net\_tx<!-- {{#callable_declaration:fd_quic_set_aio_net_tx}} -->
Sets the asynchronous I/O network transmission interface for a QUIC instance.
- **Description**: This function configures the fd_quic_t instance to use a specified fd_aio_t for transmitting data to the network. It should be called when setting up or modifying the network transmission interface for a QUIC instance. If a valid aio_tx is provided, it is used for network transmission; otherwise, the transmission interface is cleared. This function is typically used during the initialization or reconfiguration phase of a QUIC instance.
- **Inputs**:
    - `quic`: A pointer to an fd_quic_t instance. Must not be null, as it represents the QUIC instance being configured.
    - `aio_tx`: A pointer to a constant fd_aio_t structure representing the asynchronous I/O interface for network transmission. If null, the transmission interface is cleared.
- **Output**: None
- **See also**: [`fd_quic_set_aio_net_tx`](fd_quic.c.driver.md#fd_quic_set_aio_net_tx)  (Implementation)


---
### fd\_quic\_set\_clock<!-- {{#callable_declaration:fd_quic_set_clock}} -->
Set the clock source and adjust timing configurations for a QUIC instance.
- **Description**: This function is used to set a new clock source for a QUIC instance and adjust its timing configurations accordingly. It should be called when there is a need to change the clock source or the time scale used by the QUIC instance. The function updates the internal timing parameters to match the new clock ticks per microsecond, ensuring that the QUIC instance operates correctly with the new timing settings. This function must be called before the QUIC instance is initialized or after it has been finalized, as timing configurations are immutable during an active join.
- **Inputs**:
    - `quic`: A pointer to an fd_quic_t instance. Must not be null and should point to a valid QUIC instance that is not currently active.
    - `now_fn`: A function pointer of type fd_quic_now_t that provides the current time. Must not be null.
    - `now_ctx`: A user-provided context pointer that will be passed to the now_fn function. Can be null if no context is needed.
    - `tick_per_us`: A double representing the number of clock ticks per microsecond. Must be a positive value.
- **Output**: None
- **See also**: [`fd_quic_set_clock`](fd_quic.c.driver.md#fd_quic_set_clock)  (Implementation)


---
### fd\_quic\_set\_clock\_tickcount<!-- {{#callable_declaration:fd_quic_set_clock_tickcount}} -->
Sets the clock source for a QUIC instance to use the system tick count.
- **Description**: This function configures the clock source for a given QUIC instance to use the system's tick count as the timing mechanism. It should be called when you want the QUIC instance to rely on the system tick count for scheduling events. This function is typically used during the setup or configuration phase of a QUIC instance, before it is actively used for network operations. Ensure that the QUIC instance is properly initialized and configured before calling this function.
- **Inputs**:
    - `quic`: A pointer to an fd_quic_t instance. This must not be null and should point to a valid, initialized QUIC instance. The function does not handle null pointers and expects the caller to ensure the validity of the input.
- **Output**: None
- **See also**: [`fd_quic_set_clock_tickcount`](fd_quic.c.driver.md#fd_quic_set_clock_tickcount)  (Implementation)


---
### fd\_quic\_init<!-- {{#callable_declaration:fd_quic_init}} -->
Initializes the QUIC object for use.
- **Description**: This function prepares a QUIC object for operation, ensuring it is ready to serve from the calling thread. It must be called after configuring the QUIC object with valid settings and before any service or connection operations. The function checks for necessary configuration parameters and initializes various internal structures. If any required configuration is missing or invalid, the function logs a warning and returns NULL. Successful initialization allows the QUIC object to handle network operations and manage connections.
- **Inputs**:
    - `quic`: A pointer to an fd_quic_t object that has been properly configured. The configuration must include valid role, idle_timeout, ack_delay, retry_ttl, and tick_per_us values, among others. The identity_public_key must be set, and the now callback must not be NULL. The caller retains ownership of the memory.
- **Output**: Returns the initialized fd_quic_t pointer on success, or NULL if initialization fails due to invalid configuration or other errors.
- **See also**: [`fd_quic_init`](fd_quic.c.driver.md#fd_quic_init)  (Implementation)


---
### fd\_quic\_fini<!-- {{#callable_declaration:fd_quic_fini}} -->
Releases resources associated with a QUIC instance.
- **Description**: Use this function to clean up and release resources associated with a QUIC instance when it is no longer needed. It should be called after the QUIC instance has been initialized and used, and when no other threads are accessing it. This function will free any dynamically allocated resources and reset certain internal states, preparing the instance for potential deletion or reinitialization. It is important to ensure that no active connections or operations are ongoing when this function is called.
- **Inputs**:
    - `quic`: A pointer to the fd_quic_t instance to be finalized. Must not be null. If null, the function logs a warning and returns null.
- **Output**: Returns the same pointer passed in if successful, or null if the input was null.
- **See also**: [`fd_quic_fini`](fd_quic.c.driver.md#fd_quic_fini)  (Implementation)


---
### fd\_quic\_conn\_close<!-- {{#callable_declaration:fd_quic_conn_close}} -->
Initiates an asynchronous shutdown of a QUIC connection.
- **Description**: This function is used to begin the process of closing a QUIC connection gracefully. It should be called when the application decides to terminate a connection, providing a reason code that will be communicated to the peer. The function is non-blocking and will not have any effect if the connection is in an invalid, dead, or aborted state. It schedules the connection to be serviced immediately, ensuring that the closure process is handled promptly. This function must be called with a valid connection object.
- **Inputs**:
    - `conn`: A pointer to the fd_quic_conn_t structure representing the connection to be closed. Must not be null. If the connection is in an invalid, dead, or aborted state, the function will return immediately without effect.
    - `app_reason`: An unsigned integer representing the application-specific reason for closing the connection. This reason is sent to the peer as part of the CONNECTION_CLOSE frame.
- **Output**: None
- **See also**: [`fd_quic_conn_close`](fd_quic.c.driver.md#fd_quic_conn_close)  (Implementation)


---
### fd\_quic\_get\_next\_wakeup<!-- {{#callable_declaration:fd_quic_get_next_wakeup}} -->
Returns the next requested service time for a QUIC instance.
- **Description**: This function is intended for use in unit tests to determine the next time a QUIC instance requires servicing. It should be called when testing the scheduling and timing behavior of QUIC connections. The function assumes that the QUIC instance is properly initialized and in a state where it can provide meaningful wakeup times. It does not modify the state of the QUIC instance.
- **Inputs**:
    - `quic`: A pointer to an fd_quic_t instance. It must not be null and should point to a valid, initialized QUIC instance. The caller retains ownership of the memory.
- **Output**: Returns an unsigned long representing the next service time in the form of a wakeup time. If there is an immediate service requirement, it returns 0.
- **See also**: [`fd_quic_get_next_wakeup`](fd_quic.c.driver.md#fd_quic_get_next_wakeup)  (Implementation)


---
### fd\_quic\_service<!-- {{#callable_declaration:fd_quic_service}} -->
Services the next QUIC connection.
- **Description**: This function should be called frequently to handle various QUIC connection tasks such as stream transmission operations, acknowledgment transmission, and timeout management. It is essential for maintaining the active state of QUIC connections and ensuring timely processing of queued operations. The function is non-blocking and should be used in a single-threaded context where the calling thread has exclusive access to the QUIC instance.
- **Inputs**:
    - `quic`: A pointer to an initialized fd_quic_t structure representing the QUIC instance to be serviced. The pointer must not be null, and the caller must have exclusive access to this instance.
- **Output**: Returns an integer indicating whether any work was performed: 1 if the service call did any work, or 0 otherwise.
- **See also**: [`fd_quic_service`](fd_quic.c.driver.md#fd_quic_service)  (Implementation)


---
### fd\_quic\_svc\_validate<!-- {{#callable_declaration:fd_quic_svc_validate}} -->
Validates the service queue and free list invariants of a QUIC instance.
- **Description**: Use this function to check for any violations in the service queue and free list invariants of a QUIC instance, such as cycles in linked lists. It is intended for use in testing scenarios to ensure the integrity of the QUIC instance's internal structures. The function will log warnings or errors and terminate the process if any checks fail. It should be called when you need to verify the correctness of the service queue and free list management in a QUIC instance.
- **Inputs**:
    - `quic`: A pointer to an fd_quic_t instance. This must not be null and should point to a valid, initialized QUIC instance. The function assumes that the QUIC instance is in a state where its service queue and free list can be validated.
- **Output**: None
- **See also**: [`fd_quic_svc_validate`](fd_quic.c.driver.md#fd_quic_svc_validate)  (Implementation)


---
### fd\_quic\_stream\_send<!-- {{#callable_declaration:fd_quic_stream_send}} -->
Sends data over a QUIC stream.
- **Description**: This function is used to send a specified chunk of data over a given QUIC stream. It should be called when you have data ready to be transmitted on an established stream. The function checks if the stream is in a valid state for sending and if the connection is active. It also ensures that the data size does not exceed the allowed limits for the stream and connection. If the `fin` flag is set, it indicates that this is the final data to be sent on the stream, although the flag will not be set if the data cannot be added to the buffer. The function returns an error code if the stream or connection is invalid, or if flow control limits are exceeded.
- **Inputs**:
    - `stream`: A pointer to the `fd_quic_stream_t` representing the stream to send data on. Must not be null and should be in a valid state for sending.
    - `data`: A pointer to the data buffer to be sent. The buffer must contain at least `data_sz` bytes. If `data_sz` is zero, this parameter is ignored.
    - `data_sz`: The size of the data to send, in bytes. Must not exceed the available buffer space or the flow control limits of the stream and connection.
    - `fin`: An integer flag indicating whether this is the final data to be sent on the stream. A non-zero value indicates the final data.
- **Output**: Returns 0 on success, or a negative error code on failure, such as `FD_QUIC_SEND_ERR_INVAL_STREAM`, `FD_QUIC_SEND_ERR_INVAL_CONN`, or `FD_QUIC_SEND_ERR_FLOW`.
- **See also**: [`fd_quic_stream_send`](fd_quic.c.driver.md#fd_quic_stream_send)  (Implementation)


---
### fd\_quic\_stream\_fin<!-- {{#callable_declaration:fd_quic_stream_fin}} -->
Signal the end of data transmission on a QUIC stream.
- **Description**: Use this function to indicate that no more data will be sent from the local endpoint to the peer on the specified QUIC stream. This function should be called when the application has finished sending all intended data on the stream. It is important to ensure that this function is only called once per stream, unless the end of transmission was already indicated through a previous call to a related function. This function does not affect the peer's ability to send data on their side of the stream.
- **Inputs**:
    - `stream`: A pointer to the fd_quic_stream_t representing the stream to be finalized. The stream must be valid and properly initialized. The function will return immediately if the stream has already been marked as finished for transmission.
- **Output**: None
- **See also**: [`fd_quic_stream_fin`](fd_quic.c.driver.md#fd_quic_stream_fin)  (Implementation)


---
### fd\_quic\_process\_packet<!-- {{#callable_declaration:fd_quic_process_packet}} -->
Processes a QUIC packet from the provided data buffer.
- **Description**: This function is used to process a QUIC packet contained within a data buffer. It should be called when a new packet is received and needs to be processed by the QUIC instance. The function handles various checks and parsing of the packet, including IP and UDP header validation, and processes the QUIC payload if valid. It updates internal metrics for error conditions such as oversized packets or header errors. The function assumes that the QUIC instance has been properly initialized and is ready to process incoming packets.
- **Inputs**:
    - `quic`: A pointer to an fd_quic_t instance representing the QUIC object. Must not be null and should be properly initialized before calling this function. The caller retains ownership.
    - `data`: A pointer to a buffer containing the packet data to be processed. Must not be null and should point to a valid memory region containing the packet.
    - `data_sz`: The size of the data buffer in bytes. Must be less than or equal to 0xffff (65535) to avoid being considered oversized. If the size exceeds this limit, the packet is not processed, and an error metric is incremented.
- **Output**: None
- **See also**: [`fd_quic_process_packet`](fd_quic.c.driver.md#fd_quic_process_packet)  (Implementation)


---
### fd\_quic\_tx\_buffered\_raw<!-- {{#callable_declaration:fd_quic_tx_buffered_raw}} -->
Transmit a raw QUIC packet over the network.
- **Description**: This function is used to transmit a raw QUIC packet using the provided buffer and network parameters. It should be called when a QUIC packet is ready to be sent, and the caller must ensure that the buffer contains the payload data to be transmitted. The function handles the construction of the IP and UDP headers and sends the packet using the configured AIO interface. It is important to ensure that the buffer has enough space for the headers and that the QUIC object is properly initialized and configured before calling this function.
- **Inputs**:
    - `quic`: A pointer to an initialized fd_quic_t object representing the QUIC instance. Must not be null.
    - `tx_ptr_ptr`: A pointer to a pointer to the current position in the transmission buffer. The pointer it points to will be reset to tx_buf after transmission.
    - `tx_buf`: A pointer to the start of the transmission buffer containing the payload data. Must not be null and should have enough space for headers.
    - `ipv4_id`: A pointer to a ushort representing the IPv4 ID for the packet. It will be incremented after use.
    - `dst_ipv4_addr`: The destination IPv4 address for the packet, specified as a uint.
    - `dst_udp_port`: The destination UDP port for the packet, specified as a ushort.
    - `src_ipv4_addr`: The source IPv4 address for the packet, specified as a uint.
    - `src_udp_port`: The source UDP port for the packet, specified as a ushort.
- **Output**: Returns a uint indicating success or failure. Returns FD_QUIC_SUCCESS on success, FD_QUIC_FAILED on failure.
- **See also**: [`fd_quic_tx_buffered_raw`](fd_quic.c.driver.md#fd_quic_tx_buffered_raw)  (Implementation)



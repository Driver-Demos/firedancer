# Purpose
The provided C header file, `fd_quic_private.h`, is part of a larger implementation of the QUIC protocol, which is a transport layer network protocol designed for fast and secure internet communication. This file is specifically focused on the internal, private aspects of the QUIC implementation, as indicated by its name and the use of the `#ifndef` and `#define` preprocessor directives to prevent multiple inclusions. It includes various headers that provide functionality for handling QUIC transport parameters, connection mapping, stream management, logging, packet metadata, and TLS (Transport Layer Security) operations, which are essential components of the QUIC protocol.

The file defines several macros, structures, and inline functions that manage the internal state and operations of QUIC connections. Key components include the `fd_quic_state_private` structure, which maintains the state of a QUIC connection, including transport parameters, connection maps, and service queues. The file also provides functions for managing connections, such as creating and freeing connections, scheduling service timers, and handling incoming QUIC packets and frames. Additionally, it includes callback functions for handling TLS handshake events and network data reception. The file is not intended to define public APIs or external interfaces; instead, it serves as a foundational component for the internal workings of a QUIC implementation, providing essential data structures and functions for managing the protocol's complex state and operations.
# Imports and Dependencies

---
- `fd_quic.h`
- `templ/fd_quic_transport_params.h`
- `fd_quic_conn_map.h`
- `fd_quic_stream.h`
- `log/fd_quic_log_tx.h`
- `fd_quic_pkt_meta.h`
- `tls/fd_quic_tls.h`
- `fd_quic_stream_pool.h`
- `fd_quic_pretty_print.h`
- `math.h`
- `../../util/log/fd_dtrace.h`
- `../../util/net/fd_ip4.h`
- `../../util/net/fd_udp.h`
- `../../util/tmpl/fd_pool.c`
- `../../util/tmpl/fd_dlist.c`


# Global Variables

---
### fd\_quic\_conn\_create
- **Type**: `fd_quic_conn_t *`
- **Description**: The `fd_quic_conn_create` function is a global function that creates a new QUIC connection. It takes several parameters including pointers to the QUIC instance, connection IDs, IP addresses, and ports for both the peer and self, as well as a server flag. The function returns a pointer to a newly created `fd_quic_conn_t` structure, which represents the connection.
- **Use**: This function is used to initialize and allocate resources for a new QUIC connection, setting up necessary parameters for communication.


---
### fd\_quic\_gen\_stream\_frames
- **Type**: `function`
- **Description**: The `fd_quic_gen_stream_frames` function is responsible for generating QUIC stream frames for a given connection. It takes a connection object, a pointer to the start and end of the payload buffer, a packet metadata template, and a packet metadata tracker as parameters. The function returns a pointer to the updated position in the payload buffer after the frames have been generated.
- **Use**: This function is used to create and append stream frames to a payload buffer for transmission over a QUIC connection.


# Data Structures

---
### fd\_quic\_svc\_queue
- **Type**: `struct`
- **Members**:
    - `head`: The index of the first element in the queue.
    - `tail`: The index of the last element in the queue.
- **Description**: The `fd_quic_svc_queue` is a simple data structure representing a queue with two primary fields: `head` and `tail`, which are used to track the indices of the first and last elements in the queue, respectively. This structure is likely used to manage a queue of service requests or tasks in the context of QUIC protocol operations, although the exact count of elements is not tracked within this structure as indicated by the commented-out `cnt` field.


---
### fd\_quic\_svc\_queue\_t
- **Type**: `struct`
- **Members**:
    - `head`: Stores the index of the first element in the queue.
    - `tail`: Stores the index of the last element in the queue.
- **Description**: The `fd_quic_svc_queue_t` is a simple doubly linked list structure used within the QUIC implementation to manage service queues. It contains two members, `head` and `tail`, which are unsigned integers representing the indices of the first and last elements in the queue, respectively. This structure is likely used to track and manage the order of service operations or events in the QUIC protocol.


---
### fd\_quic\_state\_private
- **Type**: `struct`
- **Members**:
    - `flags`: Stores various flags related to the QUIC state.
    - `now`: Records the time when the QUIC service or receive callback was entered.
    - `transport_params`: Holds QUIC-TLS transport parameters, including mutable and immutable fields.
    - `max_inflight_frame_cnt_conn`: Maximum number of inflight frames per connection, computed from limits.
    - `log_tx`: Array for logging transmission events.
    - `free_conn_list`: Free list of unused connections.
    - `conn_map`: Maps connection IDs to connection objects.
    - `tls`: Array for managing TLS state.
    - `hs_pool`: Pool for handshake state management.
    - `hs_cache`: Cache for handshake state, implemented as a doubly linked list.
    - `stream_pool`: Pool for managing streams, can be null.
    - `pkt_meta_pool`: Pool for packet metadata management.
    - `_rng`: Random number generator instance.
    - `svc_queue`: Service queues for different service levels.
    - `svc_delay`: Target service delays for different service levels.
    - `conn_base`: Base address of the array of all connections.
    - `conn_sz`: Size of one connection element.
    - `initial_max_data`: Initial maximum data limit from transport parameters.
    - `initial_max_stream_data`: Initial maximum stream data limits for different stream types.
    - `ip_table_upd`: Timestamp of the last ARP/routing table update.
    - `quic_pretty_print`: State for QUIC sampling and pretty printing.
    - `retry_secret`: Secret used for generating RETRY tokens.
    - `retry_iv`: Initialization vector for RETRY token generation.
    - `crypt_scratch`: Scratch space for packet protection operations.
- **Description**: The `fd_quic_state_private` structure is a comprehensive data structure used to manage the internal state of a QUIC (Quick UDP Internet Connections) implementation. It includes various fields for handling flags, timing, transport parameters, connection management, TLS state, stream and packet metadata, random number generation, and service scheduling. The structure is designed to support efficient QUIC operations by maintaining state information necessary for connection management, packet processing, and flow control. It also includes fields for managing cryptographic operations and retry token generation, ensuring secure and reliable communication.


---
### fd\_quic\_pkt
- **Type**: `struct`
- **Members**:
    - `ip4`: An array of one IPv4 header structure, representing the IPv4 header of the packet.
    - `udp`: An array of one UDP header structure, representing the UDP header of the packet.
    - `pkt_number`: The QUIC packet number currently being decoded or parsed.
    - `rcv_time`: The time at which the packet was received.
    - `enc_level`: The encryption level of the packet.
    - `datagram_sz`: The size of the original datagram.
    - `ack_flag`: A flag indicating acknowledgment status, with possible values to not acknowledge, acknowledge, or cancel acknowledgment.
    - `rtt_pkt_number`: The packet number used for round-trip time (RTT) calculations.
    - `rtt_ack_time`: The time at which the acknowledgment for RTT was received.
    - `rtt_ack_delay`: The delay in acknowledgment for RTT calculations.
- **Description**: The `fd_quic_pkt` structure is designed to represent a QUIC packet within a UDP datagram, including its associated metadata for processing. It contains fields for the IPv4 and UDP headers, as well as various attributes related to the QUIC protocol, such as packet number, reception time, encryption level, and acknowledgment flags. Additionally, it includes fields for managing round-trip time (RTT) calculations, which are crucial for network performance analysis and optimization. This structure is used to handle the current packet being processed, although a UDP datagram may contain multiple QUIC packets.


---
### fd\_quic\_frame\_ctx
- **Type**: `struct`
- **Members**:
    - `quic`: A pointer to an fd_quic_t structure, representing the QUIC protocol instance.
    - `conn`: A pointer to an fd_quic_conn_t structure, representing a specific QUIC connection.
    - `pkt`: A pointer to an fd_quic_pkt_t structure, representing a QUIC packet.
- **Description**: The `fd_quic_frame_ctx` structure is a context holder for processing QUIC frames, encapsulating pointers to the QUIC protocol instance, a specific connection, and a packet. This structure is used to maintain the state and context necessary for handling QUIC frames within the protocol's operations, facilitating the interaction between different components of the QUIC implementation.


---
### fd\_quic\_frame\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `quic`: A pointer to an fd_quic_t structure, representing the QUIC instance associated with the frame context.
    - `conn`: A pointer to an fd_quic_conn_t structure, representing the connection associated with the frame context.
    - `pkt`: A pointer to an fd_quic_pkt_t structure, representing the packet associated with the frame context.
- **Description**: The `fd_quic_frame_ctx_t` structure is a context holder for processing QUIC frames, encapsulating pointers to the QUIC instance, the connection, and the packet involved in the frame processing. This structure is used to maintain the state and context necessary for handling QUIC frames within the QUIC protocol implementation.


# Functions

---
### fd\_quic\_get\_state<!-- {{#callable:fd_quic_get_state}} -->
The `fd_quic_get_state` function returns a pointer to the internal state of a QUIC instance from a given `fd_quic_t` pointer.
- **Inputs**:
    - `quic`: A pointer to an `fd_quic_t` structure, representing a QUIC instance.
- **Control Flow**:
    - The function calculates the address of the internal state by adding a predefined offset (`FD_QUIC_STATE_OFF`) to the base address of the `fd_quic_t` structure.
    - It casts the resulting address to a pointer of type `fd_quic_state_t` and returns it.
- **Output**: A pointer to `fd_quic_state_t`, which is the internal state of the given `fd_quic_t` instance.


---
### fd\_quic\_get\_state\_const<!-- {{#callable:fd_quic_get_state_const}} -->
The `fd_quic_get_state_const` function returns a constant pointer to the internal state of a given `fd_quic_t` instance.
- **Inputs**:
    - `quic`: A constant pointer to an `fd_quic_t` instance, representing the QUIC protocol context.
- **Control Flow**:
    - The function calculates the address of the internal state by adding a predefined offset (`FD_QUIC_STATE_OFF`) to the base address of the `quic` instance.
    - It casts the resulting address to a constant pointer of type `fd_quic_state_t` and returns it.
- **Output**: A constant pointer to `fd_quic_state_t`, representing the internal state of the provided `fd_quic_t` instance.


---
### fd\_quic\_conn\_query1<!-- {{#callable:fd_quic_conn_query1}} -->
The `fd_quic_conn_query1` function retrieves a connection map entry based on a connection ID, returning a sentinel if the ID is zero.
- **Inputs**:
    - `map`: A pointer to the connection map (`fd_quic_conn_map_t`) where the connection ID will be queried.
    - `conn_id`: An unsigned long integer representing the connection ID to be queried.
    - `sentinel`: A pointer to a `fd_quic_conn_map_t` structure that acts as a default return value if the connection ID is zero.
- **Control Flow**:
    - Check if `conn_id` is zero; if true, return `sentinel`.
    - If `conn_id` is not zero, call `fd_quic_conn_map_query` with `map`, `conn_id`, and `sentinel` as arguments and return its result.
- **Output**: Returns a pointer to a `fd_quic_conn_map_t` structure, which is either the result of the query or the sentinel if the connection ID is zero.


---
### fd\_quic\_conn\_query<!-- {{#callable:fd_quic_conn_query}} -->
The `fd_quic_conn_query` function retrieves a connection object from a connection map using a given connection ID.
- **Inputs**:
    - `map`: A pointer to the `fd_quic_conn_map_t` structure, which is a map of connection IDs to connection objects.
    - `conn_id`: An unsigned long integer representing the connection ID to be queried in the map.
- **Control Flow**:
    - Initialize a `fd_quic_conn_map_t` structure named `sentinel` with zero values.
    - Check if `conn_id` is zero; if so, return `NULL` as no valid connection ID is provided.
    - Call `fd_quic_conn_map_query` with `map`, `conn_id`, and `sentinel` to retrieve the map entry corresponding to the connection ID.
    - Return the `conn` field from the retrieved map entry, which is a pointer to the `fd_quic_conn_t` structure.
- **Output**: A pointer to an `fd_quic_conn_t` structure representing the connection associated with the given connection ID, or `NULL` if the connection ID is zero or not found.


---
### fd\_quic\_svc\_schedule1<!-- {{#callable:fd_quic_svc_schedule1}} -->
The `fd_quic_svc_schedule1` function schedules a service timer for a QUIC connection using a specified service type.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the QUIC connection for which the service timer is being scheduled.
    - `svc_type`: An unsigned integer specifying the type of service timer to be scheduled, which determines the delay for the timer.
- **Control Flow**:
    - The function retrieves the internal state of the QUIC instance associated with the connection by calling [`fd_quic_get_state`](#fd_quic_get_state) with `conn->quic` as the argument.
    - It then calls `fd_quic_svc_schedule`, passing the retrieved state, the connection, and the service type as arguments to schedule the service timer.
- **Output**: This function does not return any value; it performs an action by scheduling a service timer for the specified connection.
- **Functions called**:
    - [`fd_quic_get_state`](#fd_quic_get_state)


---
### fd\_quic\_now<!-- {{#callable:fd_quic_now}} -->
The `fd_quic_now` function retrieves the current time using a callback function from a QUIC context.
- **Inputs**:
    - `quic`: A pointer to an `fd_quic_t` structure, which contains the callback function and context for retrieving the current time.
- **Control Flow**:
    - The function calls the `now` callback function from the `quic` structure, passing the `now_ctx` as an argument.
    - The result of the callback function is returned as the output of `fd_quic_now`.
- **Output**: The function returns an `ulong` representing the current time as provided by the callback function.


---
### fd\_quic\_cb\_conn\_new<!-- {{#callable:fd_quic_cb_conn_new}} -->
The `fd_quic_cb_conn_new` function initializes a new QUIC connection by invoking a callback if it hasn't been called before.
- **Inputs**:
    - `quic`: A pointer to an `fd_quic_t` structure representing the QUIC instance.
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the connection to be initialized.
- **Control Flow**:
    - Check if the `called_conn_new` flag in the `conn` structure is set; if so, return immediately.
    - Set the `called_conn_new` flag in the `conn` structure to 1 to indicate that the connection has been initialized.
    - Check if the `conn_new` callback in the `quic` structure is not set; if so, return immediately.
    - Invoke the `conn_new` callback with the `conn` and `quic->cb.quic_ctx` as arguments.
- **Output**: This function does not return any value; it performs an action by potentially invoking a callback.


---
### fd\_quic\_cb\_conn\_hs\_complete<!-- {{#callable:fd_quic_cb_conn_hs_complete}} -->
The `fd_quic_cb_conn_hs_complete` function triggers a callback when a QUIC connection handshake is complete, if such a callback is defined.
- **Inputs**:
    - `quic`: A pointer to an `fd_quic_t` structure representing the QUIC instance.
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the specific connection for which the handshake has completed.
- **Control Flow**:
    - Check if the `conn_hs_complete` callback is defined in the `quic` structure.
    - If the callback is defined, invoke `conn_hs_complete` with the `conn` and `quic->cb.quic_ctx` as arguments.
- **Output**: The function does not return any value.


---
### fd\_quic\_cb\_conn\_final<!-- {{#callable:fd_quic_cb_conn_final}} -->
The `fd_quic_cb_conn_final` function triggers the final connection callback if certain conditions are met.
- **Inputs**:
    - `quic`: A pointer to an `fd_quic_t` structure, representing the QUIC instance.
    - `conn`: A pointer to an `fd_quic_conn_t` structure, representing the connection to be finalized.
- **Control Flow**:
    - Check if the `conn_final` callback is set in the `quic` structure and if the `called_conn_new` flag is true in the `conn` structure.
    - If both conditions are met, call the `conn_final` callback with the `conn` and `quic` context as arguments.
- **Output**: The function does not return any value; it performs a callback operation if conditions are met.


---
### fd\_quic\_cb\_stream\_rx<!-- {{#callable:fd_quic_cb_stream_rx}} -->
The `fd_quic_cb_stream_rx` function processes received stream data in a QUIC connection, updating metrics and invoking a callback if defined.
- **Inputs**:
    - `quic`: A pointer to the `fd_quic_t` structure representing the QUIC instance.
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the connection associated with the stream.
    - `stream_id`: An unsigned long integer representing the identifier of the stream receiving data.
    - `offset`: An unsigned long integer indicating the offset in the stream where the data starts.
    - `data`: A pointer to a constant unsigned character array containing the data received on the stream.
    - `data_sz`: An unsigned long integer representing the size of the data received.
    - `fin`: An integer flag indicating if this is the final data for the stream (1 if final, 0 otherwise).
- **Control Flow**:
    - Increment the `stream_rx_event_cnt` metric in the `quic` structure to count the stream receive event.
    - Add the size of the received data (`data_sz`) to the `stream_rx_byte_cnt` metric in the `quic` structure.
    - Check if the `stream_rx` callback is defined in the `quic` structure.
    - If the `stream_rx` callback is not defined, return `FD_QUIC_SUCCESS`.
    - If the `stream_rx` callback is defined, invoke it with the provided connection, stream ID, offset, data, data size, and final flag, and return its result.
- **Output**: The function returns an integer, which is `FD_QUIC_SUCCESS` if no callback is defined, or the result of the `stream_rx` callback if it is defined.


---
### fd\_quic\_cb\_stream\_notify<!-- {{#callable:fd_quic_cb_stream_notify}} -->
The `fd_quic_cb_stream_notify` function updates stream metrics and triggers a callback for stream events if a callback is defined.
- **Inputs**:
    - `quic`: A pointer to an `fd_quic_t` structure representing the QUIC instance.
    - `stream`: A pointer to an `fd_quic_stream_t` structure representing the stream associated with the event.
    - `stream_ctx`: A void pointer to the context associated with the stream, which can be used to pass additional information to the callback.
    - `event`: An integer representing the type of event that occurred on the stream.
- **Control Flow**:
    - Increment the `stream_closed_cnt` metric for the given event in the `quic` structure.
    - Decrement the `stream_active_cnt` metric in the `quic` structure.
    - Check if the `stream_notify` callback is defined in the `quic` structure.
    - If the `stream_notify` callback is defined, call it with the `stream`, `stream_ctx`, and `event` as arguments.
- **Output**: This function does not return a value; it performs operations on the `quic` structure and potentially calls a callback function.


---
### fd\_quic\_conn\_at\_idx<!-- {{#callable:fd_quic_conn_at_idx}} -->
The `fd_quic_conn_at_idx` function calculates and returns a pointer to a specific QUIC connection within an array of connections based on a given index.
- **Inputs**:
    - `quic_state`: A pointer to an `fd_quic_state_t` structure, which contains the state information for QUIC, including the base address and size of each connection.
    - `idx`: An unsigned long integer representing the index of the connection to retrieve from the array of connections.
- **Control Flow**:
    - Retrieve the base address of the connection array from `quic_state->conn_base`.
    - Retrieve the size of each connection from `quic_state->conn_sz`.
    - Calculate the address of the desired connection by adding the product of `idx` and `sz` to `addr`.
    - Cast the calculated address to a pointer of type `fd_quic_conn_t*` and return it.
- **Output**: A pointer to the `fd_quic_conn_t` structure located at the specified index within the connection array.


---
### fd\_quic\_sample\_rtt<!-- {{#callable:fd_quic_sample_rtt}} -->
The `fd_quic_sample_rtt` function updates the round-trip time (RTT) metrics for a QUIC connection based on a new RTT sample and an acknowledgment delay.
- **Inputs**:
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection whose RTT metrics are to be updated.
    - `rtt_ticks`: A long integer representing the round-trip time in ticks for the current sample.
    - `ack_delay`: A long integer representing the acknowledgment delay provided by the peer, in peer units.
- **Control Flow**:
    - Retrieve the RTT metrics structure from the connection object for convenience.
    - Convert the acknowledgment delay from peer units to ticks using the peer's acknowledgment delay scale.
    - Limit the acknowledgment delay to the peer's maximum acknowledgment delay in ticks.
    - Update the minimum RTT with the smaller value between the current minimum RTT and the new RTT sample without adjusting for acknowledgment delay.
    - Calculate the adjusted RTT by subtracting the acknowledgment delay from the RTT sample, ensuring it is not less than the minimum RTT.
    - Set the latest RTT to the adjusted RTT value.
    - If the RTT metrics are not yet valid, initialize the smoothed RTT and RTT variance with the adjusted RTT and mark the RTT as valid.
    - If the RTT metrics are valid, update the smoothed RTT using an exponential moving average and update the RTT variance using the absolute difference between the smoothed RTT and the adjusted RTT.
    - If debugging is enabled, log the RTT metrics and related values for analysis.
- **Output**: The function does not return a value; it updates the RTT metrics within the `fd_quic_conn_t` structure pointed to by `conn`.


---
### fd\_quic\_calc\_expiry<!-- {{#callable:fd_quic_calc_expiry}} -->
The `fd_quic_calc_expiry` function calculates the expiry time for a QUIC packet based on the Packetization Timeout (PTO) specification.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the QUIC connection for which the expiry time is being calculated.
    - `now`: The current timestamp as an unsigned long integer, representing the current time in ticks.
- **Control Flow**:
    - Retrieve the RTT (Round-Trip Time) information from the connection's RTT structure.
    - Calculate the duration using the formula: `smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay`, where `smoothed_rtt`, `var_rtt`, `sched_granularity_ticks`, and `peer_max_ack_delay_ticks` are obtained from the RTT structure.
    - Log the calculated duration using a trace probe for debugging or monitoring purposes.
    - Return the sum of the current time (`now`) and a fixed 500 milliseconds (500e6 ticks) as the expiry time.
- **Output**: The function returns an unsigned long integer representing the calculated expiry time for the QUIC packet, which is the current time plus 500 milliseconds.


# Function Declarations (Public API)

---
### fd\_quic\_conn\_service<!-- {{#callable_declaration:fd_quic_conn_service}} -->
Perform periodic operations and state management for a QUIC connection.
- **Description**: This function is used to manage and perform necessary operations on a QUIC connection at regular intervals. It handles tasks such as sending round-trip time measurement probes, managing connection states, and transmitting data. It should be called periodically to ensure the connection remains active and responsive. The function requires a valid QUIC context and connection, and it uses the current timestamp to determine the timing of operations. It is essential for maintaining the connection's lifecycle and ensuring timely data transmission and state transitions.
- **Inputs**:
    - `quic`: A pointer to the fd_quic_t structure representing the managing QUIC context. Must not be null.
    - `conn`: A pointer to the fd_quic_conn_t structure representing the connection to be serviced. Must not be null.
    - `now`: The current timestamp, used to determine the timing of operations. Should be a valid timestamp in the same time unit as the connection's timing logic.
- **Output**: None
- **See also**: [`fd_quic_conn_service`](fd_quic.c.driver.md#fd_quic_conn_service)  (Implementation)


---
### fd\_quic\_conn\_create<!-- {{#callable_declaration:fd_quic_conn_create}} -->
Creates a new QUIC connection.
- **Description**: This function initializes and returns a new QUIC connection object, associating it with the specified parameters. It should be called when a new connection is needed, either as a server or a client. The function requires a valid QUIC context and connection identifiers, and it handles the allocation of resources for the connection. If the connection cannot be created due to invalid parameters or resource constraints, the function returns NULL.
- **Inputs**:
    - `quic`: A pointer to an fd_quic_t structure representing the QUIC context. Must not be null.
    - `our_conn_id`: An unsigned long representing the connection ID for the local endpoint. Must be non-zero.
    - `peer_conn_id`: A pointer to an fd_quic_conn_id_t structure representing the connection ID for the peer endpoint. Must not be null.
    - `peer_ip_addr`: An unsigned integer representing the IP address of the peer. Must be a valid IPv4 address.
    - `peer_udp_port`: An unsigned short representing the UDP port of the peer. Must be a valid port number.
    - `self_ip_addr`: An unsigned integer representing the IP address of the local endpoint. Can be zero if the connection is outgoing.
    - `self_udp_port`: An unsigned short representing the UDP port of the local endpoint. Must be a valid port number.
    - `server`: An integer indicating whether the connection is for a server (non-zero) or a client (zero).
- **Output**: Returns a pointer to the newly created fd_quic_conn_t structure, or NULL if the connection could not be created.
- **See also**: [`fd_quic_conn_create`](fd_quic.c.driver.md#fd_quic_conn_create)  (Implementation)


---
### fd\_quic\_conn\_free<!-- {{#callable_declaration:fd_quic_conn_free}} -->
Frees resources associated with a QUIC connection.
- **Description**: This function is used to release most resources related to a specified QUIC connection and return it to the connection free list. It should be called when a connection is no longer needed to ensure proper cleanup and resource management. The function handles edge cases such as null connections and double frees by logging warnings and critical errors, respectively. It is important to ensure that the connection is valid and not already freed before calling this function.
- **Inputs**:
    - `quic`: A pointer to an fd_quic_t structure representing the QUIC instance managing the connection. Must not be null.
    - `conn`: A pointer to an fd_quic_conn_t structure representing the connection to be freed. If null, the function logs a warning and returns without performing any action. If the connection is already in an invalid state, indicating a double free, a critical error is logged and the function returns.
- **Output**: None
- **See also**: [`fd_quic_conn_free`](fd_quic.c.driver.md#fd_quic_conn_free)  (Implementation)


---
### fd\_quic\_tx\_stream\_free<!-- {{#callable_declaration:fd_quic_tx_stream_free}} -->
Frees a QUIC stream and returns it to the stream pool.
- **Description**: This function is used to release resources associated with a QUIC stream and return it to the stream pool for reuse. It should be called when a stream is no longer needed, ensuring that the stream is properly removed from the connection's stream map and list. The function also notifies the stream's context of the closure event using the provided code. It is important to ensure that the stream is in use before calling this function, as it will not perform any operations if the stream is already marked as unused.
- **Inputs**:
    - `quic`: A pointer to the QUIC instance managing the stream. Must not be null.
    - `conn`: A pointer to the connection associated with the stream. Must not be null.
    - `stream`: A pointer to the stream to be freed. Must not be null and should be in use.
    - `code`: An integer code used to notify the stream's context of the closure event. The specific meaning of the code is determined by the application.
- **Output**: None
- **See also**: [`fd_quic_tx_stream_free`](fd_quic.c.driver.md#fd_quic_tx_stream_free)  (Implementation)


---
### fd\_quic\_aio\_cb\_receive<!-- {{#callable_declaration:fd_quic_aio_cb_receive}} -->
Processes a batch of received network packets for a QUIC context.
- **Description**: This function is used to handle a batch of network packets received for a QUIC context. It processes each packet individually and updates relevant metrics. The function assumes that each packet in the batch is processed successfully, and any packet that cannot be processed is dropped. It is typically called when new packets are available for processing in a QUIC application. The function updates the number of processed packets and bytes in the QUIC metrics. It is important to ensure that the context provided is valid and properly initialized before calling this function.
- **Inputs**:
    - `context`: A pointer to a valid fd_quic_t structure representing the QUIC context. Must not be null.
    - `batch`: A pointer to an array of fd_aio_pkt_info_t structures, each representing a packet to be processed. Must not be null.
    - `batch_cnt`: The number of packets in the batch array. Must be greater than zero.
    - `opt_batch_idx`: An optional pointer to a ulong where the function will store the number of packets processed. Can be null.
    - `flush`: An integer flag indicating whether to flush the processing. Currently ignored by the function.
- **Output**: Returns FD_AIO_SUCCESS on successful processing of the batch. If opt_batch_idx is provided, it is set to the number of packets processed.
- **See also**: [`fd_quic_aio_cb_receive`](fd_quic.c.driver.md#fd_quic_aio_cb_receive)  (Implementation)


---
### fd\_quic\_tls\_cb\_alert<!-- {{#callable_declaration:fd_quic_tls_cb_alert}} -->
Handles a TLS alert during the QUIC handshake.
- **Description**: This function is a callback used to handle TLS alerts that occur during the QUIC handshake process. It is typically invoked by the TLS layer when an alert is generated, allowing the QUIC layer to respond appropriately. This function should be used in contexts where TLS alerts need to be processed as part of the QUIC protocol's handshake operations. It is expected that the context parameter is a valid pointer to a connection object, and the alert parameter is an integer representing the specific TLS alert code.
- **Inputs**:
    - `hs`: A pointer to a fd_quic_tls_hs_t structure representing the TLS handshake state. The function does not use this parameter, and it can be ignored.
    - `context`: A pointer to a fd_quic_conn_t structure representing the QUIC connection context. This must be a valid pointer, as it is used to determine the connection's role (server or client). The caller retains ownership.
    - `alert`: An integer representing the TLS alert code. This value is used to log the alert and should be a valid TLS alert code.
- **Output**: None
- **See also**: [`fd_quic_tls_cb_alert`](fd_quic.c.driver.md#fd_quic_tls_cb_alert)  (Implementation)


---
### fd\_quic\_tls\_cb\_secret<!-- {{#callable_declaration:fd_quic_tls_cb_secret}} -->
Handles the TLS secret callback for a QUIC connection.
- **Description**: This function is used during the QUIC handshake process to handle the TLS secret callback. It sets the read and write secrets for the specified encryption level of a QUIC connection, generates the necessary cryptographic keys, and optionally logs the keys if a key logging function is provided. This function should be called as part of the TLS handshake process when a new secret is available. It assumes that the context is a valid pointer to a `fd_quic_conn_t` structure and that the `secret` parameter is not null. The function does not return a value but modifies the connection's cryptographic state.
- **Inputs**:
    - `hs`: A pointer to an `fd_quic_tls_hs_t` structure representing the TLS handshake state. Must not be null.
    - `context`: A pointer to a `fd_quic_conn_t` structure representing the QUIC connection. Must not be null and is used to access the connection's cryptographic state.
    - `secret`: A pointer to a constant `fd_quic_tls_secret_t` structure containing the encryption level and the read and write secrets. Must not be null and the `enc_level` must be less than `FD_QUIC_NUM_ENC_LEVELS`.
- **Output**: None
- **See also**: [`fd_quic_tls_cb_secret`](fd_quic.c.driver.md#fd_quic_tls_cb_secret)  (Implementation)


---
### fd\_quic\_tls\_cb\_handshake\_complete<!-- {{#callable_declaration:fd_quic_tls_cb_handshake_complete}} -->
Handles the completion of a QUIC handshake.
- **Description**: This function should be called when a QUIC handshake is completed. It updates the connection state to reflect the handshake completion, provided the connection is in a valid state for this transition. It is important to ensure that the connection is not in an aborted, closed, or dead state before calling this function, as it will have no effect in those cases. Additionally, the function expects that transport parameters have been set before marking the handshake as complete.
- **Inputs**:
    - `hs`: A pointer to a `fd_quic_tls_hs_t` structure representing the handshake state. This parameter is not used in the function and can be ignored.
    - `context`: A pointer to a `fd_quic_conn_t` structure representing the connection context. Must not be null, as it is used to determine the connection state and update it accordingly.
- **Output**: None
- **See also**: [`fd_quic_tls_cb_handshake_complete`](fd_quic.c.driver.md#fd_quic_tls_cb_handshake_complete)  (Implementation)


---
### fd\_quic\_tls\_cb\_peer\_params<!-- {{#callable_declaration:fd_quic_tls_cb_peer_params}} -->
Processes peer transport parameters for a QUIC connection.
- **Description**: This function is used to process and validate the transport parameters received from a peer during a QUIC connection handshake. It should be called with the context of the connection and the encoded transport parameters. The function decodes these parameters and updates the connection's settings accordingly, such as flow control limits and timeout values. It also performs necessary validations, particularly for retry source connection IDs, and sets error states if any validation fails. This function is typically invoked as part of the QUIC handshake process.
- **Inputs**:
    - `context`: A pointer to the connection context, which must be a valid fd_quic_conn_t object. The caller retains ownership and it must not be null.
    - `peer_tp_enc`: A pointer to the encoded transport parameters received from the peer. It must not be null and should point to a valid memory region of size specified by peer_tp_enc_sz.
    - `peer_tp_enc_sz`: The size of the encoded transport parameters in bytes. It must accurately reflect the size of the data pointed to by peer_tp_enc.
- **Output**: None
- **See also**: [`fd_quic_tls_cb_peer_params`](fd_quic.c.driver.md#fd_quic_tls_cb_peer_params)  (Implementation)


---
### fd\_quic\_reconstruct\_pkt\_num<!-- {{#callable_declaration:fd_quic_reconstruct_pkt_num}} -->
Reconstructs the full packet number from a truncated packet number.
- **Description**: This function is used to reconstruct the full packet number from a truncated packet number received in a QUIC packet. It should be called when you have a truncated packet number and need to determine the full packet number within the expected range. The function ensures that the reconstructed packet number is within a valid window around the expected packet number, handling potential overflows and underflows.
- **Inputs**:
    - `pktnum_comp`: The truncated packet number component received in the packet. It is a non-negative integer representing the lower bits of the full packet number.
    - `pktnum_sz`: The size of the packet number in bytes, which determines the number of bits used in the truncated packet number. It must be a positive integer.
    - `exp_pkt_number`: The expected packet number, which is a non-negative integer representing the center of the valid packet number window. This is used to determine the correct full packet number from the truncated component.
- **Output**: Returns the reconstructed full packet number as an unsigned long integer.
- **See also**: [`fd_quic_reconstruct_pkt_num`](fd_quic.c.driver.md#fd_quic_reconstruct_pkt_num)  (Implementation)


---
### fd\_quic\_pkt\_meta\_retry<!-- {{#callable_declaration:fd_quic_pkt_meta_retry}} -->
Retries packet metadata for a QUIC connection.
- **Description**: This function is used to manage the retry of packet metadata for a given QUIC connection. It can be used to force the retry of packets or to handle expired packet metadata based on the current time. The function should be called when there is a need to ensure that packet metadata is retried, either due to expiration or a forced condition. It is important to ensure that the connection and QUIC context are valid before calling this function.
- **Inputs**:
    - `quic`: A pointer to an fd_quic_t structure representing the QUIC context. Must not be null.
    - `conn`: A pointer to an fd_quic_conn_t structure representing the connection for which packet metadata is being retried. Must not be null.
    - `force`: An integer flag indicating whether to force the retry of packet metadata. A non-zero value forces the retry, while zero allows normal expiration handling.
    - `arg_enc_level`: An unsigned integer specifying the encryption level to consider for retrying packet metadata. If set to ~0u, all encryption levels are considered.
- **Output**: None
- **See also**: [`fd_quic_pkt_meta_retry`](fd_quic.c.driver.md#fd_quic_pkt_meta_retry)  (Implementation)


---
### fd\_quic\_reclaim\_pkt\_meta<!-- {{#callable_declaration:fd_quic_reclaim_pkt_meta}} -->
Reclaims resources associated with packet metadata after receiving acknowledgments.
- **Description**: This function is used to reclaim resources associated with packet metadata in a QUIC connection after receiving acknowledgments. It should be called when an acknowledgment for a packet is received, allowing the connection to update its state and free up resources related to the acknowledged packet. The function handles different types of packet metadata, such as PING, handshake data, and stream data, and updates the connection state accordingly. It is important to ensure that the connection and packet metadata are valid and properly initialized before calling this function.
- **Inputs**:
    - `conn`: A pointer to an fd_quic_conn_t structure representing the QUIC connection. Must not be null.
    - `pkt_meta`: A pointer to an fd_quic_pkt_meta_t structure containing the packet metadata to be reclaimed. Must not be null.
    - `enc_level`: An unsigned integer representing the encryption level of the packet. Valid values depend on the QUIC implementation's encryption level definitions.
- **Output**: None
- **See also**: [`fd_quic_reclaim_pkt_meta`](fd_quic.c.driver.md#fd_quic_reclaim_pkt_meta)  (Implementation)


---
### fd\_quic\_process\_quic\_packet\_v1<!-- {{#callable_declaration:fd_quic_process_quic_packet_v1}} -->
Processes a QUIC packet and updates connection state.
- **Description**: This function is used to process a QUIC packet, updating the connection state and handling different packet types such as Initial, Handshake, Retry, and Zero-RTT. It should be called when a new QUIC packet is received, and it requires the packet size to be within a valid range. The function also manages acknowledgment and round-trip time sampling. It is important to ensure that the `fd_quic_t` and `fd_quic_pkt_t` structures are properly initialized before calling this function.
- **Inputs**:
    - `quic`: A pointer to an `fd_quic_t` structure representing the QUIC context. Must not be null.
    - `pkt`: A pointer to an `fd_quic_pkt_t` structure where packet metadata will be stored. Must not be null.
    - `cur_ptr`: A pointer to the current position in the packet data buffer. Must not be null.
    - `cur_sz`: The size of the packet data buffer. Must be between `FD_QUIC_SHORTEST_PKT` and 1500 bytes, inclusive. Invalid sizes will result in a parse failure.
- **Output**: Returns the number of bytes consumed from the packet buffer if successful, or `FD_QUIC_PARSE_FAIL` on failure.
- **See also**: [`fd_quic_process_quic_packet_v1`](fd_quic.c.driver.md#fd_quic_process_quic_packet_v1)  (Implementation)


---
### fd\_quic\_handle\_v1\_initial<!-- {{#callable_declaration:fd_quic_handle_v1_initial}} -->
Handles an incoming QUIC Initial packet.
- **Description**: This function processes an incoming QUIC Initial packet, which is part of the QUIC handshake process. It should be called when a QUIC Initial packet is received, and it handles the packet's parsing, validation, and decryption. The function also manages connection creation if necessary, and updates connection state and metrics. It is important to ensure that the `quic` and `pkt` parameters are properly initialized before calling this function. The function returns the number of bytes consumed from the packet or an error code if the packet is invalid or processing fails.
- **Inputs**:
    - `quic`: A pointer to an initialized `fd_quic_t` structure representing the QUIC context. Must not be null.
    - `p_conn`: A pointer to a pointer to an `fd_quic_conn_t` structure. This may point to an existing connection or be null if a new connection needs to be created. The function may update this pointer to point to a new connection.
    - `pkt`: A pointer to an `fd_quic_pkt_t` structure representing the received packet. Must not be null and should be properly initialized with packet details.
    - `dcid`: A pointer to a constant `fd_quic_conn_id_t` structure representing the destination connection ID. Must not be null.
    - `peer_scid`: A pointer to a constant `fd_quic_conn_id_t` structure representing the source connection ID from the peer. Must not be null.
    - `cur_ptr`: A pointer to the current position in the packet buffer where the Initial packet starts. Must not be null.
    - `cur_sz`: The size of the remaining data in the packet buffer starting from `cur_ptr`. Must be a positive value.
- **Output**: Returns the number of bytes consumed from the packet if successful, or an error code (e.g., `FD_QUIC_PARSE_FAIL`) if the packet is invalid or processing fails.
- **See also**: [`fd_quic_handle_v1_initial`](fd_quic.c.driver.md#fd_quic_handle_v1_initial)  (Implementation)


---
### fd\_quic\_handle\_v1\_handshake<!-- {{#callable_declaration:fd_quic_handle_v1_handshake}} -->
Processes a QUIC handshake packet for a given connection.
- **Description**: This function is used to handle a QUIC handshake packet for a specified connection. It should be called when a handshake packet is received and needs to be processed. The function requires a valid connection object and a packet object, and it expects the current pointer and size to point to the handshake packet data. The function will parse the handshake, decrypt the packet, and handle any frames contained within it. It updates the connection's state and metrics accordingly. If the connection is invalid or the packet cannot be processed, the function returns an error code.
- **Inputs**:
    - `quic`: A pointer to the QUIC context. Must not be null. The caller retains ownership.
    - `conn`: A pointer to the connection object associated with the handshake packet. Must not be null. If the connection is invalid, the function returns an error.
    - `pkt`: A pointer to the packet object representing the handshake packet. Must not be null. The function updates the packet number in this object.
    - `cur_ptr`: A pointer to the current position in the packet data buffer. Must not be null and should point to the start of the handshake packet data.
    - `cur_sz`: The size of the data available at cur_ptr. Must be sufficient to contain the entire handshake packet.
- **Output**: Returns the number of bytes consumed from the packet data if successful, or an error code if the packet cannot be processed.
- **See also**: [`fd_quic_handle_v1_handshake`](fd_quic.c.driver.md#fd_quic_handle_v1_handshake)  (Implementation)


---
### fd\_quic\_handle\_v1\_one\_rtt<!-- {{#callable_declaration:fd_quic_handle_v1_one_rtt}} -->
Processes a QUIC 1-RTT packet for a given connection.
- **Description**: This function is used to handle a QUIC 1-RTT packet associated with a specific connection. It should be called when a 1-RTT packet is received and needs to be processed. The function requires a valid connection and packet, and it assumes that the connection is in a state where 1-RTT keys are available. It performs decryption and processes the packet's frames, updating connection state as necessary. The function returns the total size of the packet if successful, or an error code if processing fails. It is important to ensure that the connection and packet pointers are valid and that the packet size is sufficient before calling this function.
- **Inputs**:
    - `quic`: A pointer to the QUIC context. Must not be null. The caller retains ownership.
    - `conn`: A pointer to the connection associated with the packet. Must not be null. If null, the function increments a no-connection metric and returns an error.
    - `pkt`: A pointer to the packet structure to be filled with packet details. Must not be null. The caller retains ownership.
    - `cur_ptr`: A pointer to the current position in the packet data buffer. Must not be null. The caller retains ownership.
    - `tot_sz`: The total size of the packet data. Must be large enough to contain the minimum required header and packet number fields. If too small, the function returns an error.
- **Output**: Returns the total size of the packet if processing is successful, or an error code if it fails.
- **See also**: [`fd_quic_handle_v1_one_rtt`](fd_quic.c.driver.md#fd_quic_handle_v1_one_rtt)  (Implementation)


---
### fd\_quic\_handle\_v1\_frame<!-- {{#callable_declaration:fd_quic_handle_v1_frame}} -->
Processes a QUIC frame within a given context.
- **Description**: This function is used to handle incoming QUIC frames by processing them within the context of a specified QUIC connection and packet. It should be called when a new frame is received and needs to be interpreted according to the QUIC protocol. The function requires a valid connection that is not in a dead state and a non-empty buffer containing the frame data. It returns a value indicating the success or failure of the frame processing, with specific return values for malformed frames and protocol violations.
- **Inputs**:
    - `quic`: A pointer to an fd_quic_t structure representing the QUIC instance managing the connection. Must not be null.
    - `conn`: A pointer to an fd_quic_conn_t structure representing the connection associated with the frame. Must not be null and must not be in a dead state.
    - `pkt`: A pointer to an fd_quic_pkt_t structure representing the packet containing the frame. Must not be null.
    - `pkt_type`: An unsigned integer representing the type of the packet. Must be a valid packet type as per the QUIC protocol.
    - `frame_ptr`: A pointer to a buffer containing the serialized QUIC frame data. Must not be null and must point to a buffer of at least one byte.
    - `frame_sz`: An unsigned long representing the size of the frame data in the buffer. Must be greater than zero.
- **Output**: Returns a value in (0, frame_sz) if the frame was successfully processed, FD_QUIC_PARSE_FAIL if the frame was malformed, or 0 or a value in [frame_sz, ULONG_MAX) in case of a protocol violation.
- **See also**: [`fd_quic_handle_v1_frame`](fd_quic.c.driver.md#fd_quic_handle_v1_frame)  (Implementation)


---
### fd\_quic\_lazy\_ack\_pkt<!-- {{#callable_declaration:fd_quic_lazy_ack_pkt}} -->
Enqueues a future acknowledgment for a given QUIC packet.
- **Description**: This function is used to schedule an acknowledgment for a specified QUIC packet to be sent at a later time, determined by the configuration settings such as ack_threshold and ack_delay. It should be called when a packet is received and an acknowledgment is required or desired. The function respects the packet's ack_flag, where ACK_FLAG_RQD will schedule an immediate acknowledgment, and ACK_FLAG_CANCEL will suppress the acknowledgment entirely. This function is typically used in the context of managing QUIC connections and ensuring timely acknowledgments of received packets.
- **Inputs**:
    - `quic`: A pointer to an fd_quic_t structure representing the QUIC instance managing the connection. Must not be null.
    - `conn`: A pointer to an fd_quic_conn_t structure representing the connection for which the packet acknowledgment is being managed. Must not be null.
    - `pkt`: A pointer to a constant fd_quic_pkt_t structure representing the packet to be acknowledged. Must not be null and should contain valid packet information including ack_flag.
- **Output**: Returns an integer status code indicating the result of the acknowledgment scheduling. FD_QUIC_ACK_TX_CANCEL is returned if the acknowledgment is canceled due to the ACK_FLAG_CANCEL flag.
- **See also**: [`fd_quic_lazy_ack_pkt`](fd_quic.c.driver.md#fd_quic_lazy_ack_pkt)  (Implementation)


---
### fd\_quic\_gen\_stream\_frames<!-- {{#callable_declaration:fd_quic_gen_stream_frames}} -->
Generates QUIC stream frames for transmission.
- **Description**: This function is used to generate QUIC stream frames from the available data in the connection's streams and append them to the provided payload buffer. It should be called when preparing a packet for transmission to ensure that all available stream data is included. The function iterates over the streams in the connection, checking for data that can be sent, and encodes it into the payload buffer. It handles stream metadata and updates packet metadata for retransmission tracking. The function must be called with a valid connection and sufficient space in the payload buffer to accommodate the stream frames.
- **Inputs**:
    - `conn`: A pointer to an fd_quic_conn_t structure representing the QUIC connection. It must be valid and properly initialized.
    - `payload_ptr`: A pointer to the start of the buffer where the stream frames will be written. It must point to a valid memory region with enough space to hold the frames.
    - `payload_end`: A pointer to the end of the buffer, indicating the maximum writable address. It must be greater than or equal to payload_ptr.
    - `pkt_meta_tmpl`: A pointer to an fd_quic_pkt_meta_t structure used as a template for packet metadata. It must be valid and properly initialized.
    - `tracker`: A pointer to an fd_quic_pkt_meta_tracker_t structure used to track packet metadata. It must be valid and properly initialized.
- **Output**: Returns a pointer to the next position in the payload buffer after the written stream frames.
- **See also**: [`fd_quic_gen_stream_frames`](fd_quic.c.driver.md#fd_quic_gen_stream_frames)  (Implementation)


---
### fd\_quic\_process\_ack\_range<!-- {{#callable_declaration:fd_quic_process_ack_range}} -->
Processes an acknowledgment range for a QUIC connection.
- **Description**: This function is used to process a range of acknowledged packets for a given QUIC connection. It should be called when an acknowledgment frame is received, specifying the largest acknowledged packet and the range of packets acknowledged. The function updates the connection's packet metadata and round-trip time (RTT) information if the largest acknowledged packet is the most recent one. It is important to ensure that the connection and context are valid and properly initialized before calling this function.
- **Inputs**:
    - `conn`: A pointer to the QUIC connection structure. Must not be null and should be a valid connection object.
    - `context`: A pointer to the frame context containing the packet information. Must not be null and should be properly initialized.
    - `enc_level`: The encryption level of the packets being acknowledged. Must be a valid encryption level used in the connection.
    - `largest_ack`: The largest packet number that has been acknowledged. Must be a valid packet number within the range of sent packets.
    - `ack_range`: The range of packet numbers acknowledged, starting from the largest_ack. Must be a non-negative value.
    - `is_largest`: An integer flag indicating if the largest_ack is the most recent packet number. Non-zero if true, zero otherwise.
    - `now`: The current timestamp in ticks. Used for RTT calculations.
    - `ack_delay`: The acknowledgment delay reported by the peer, in peer units. Used for RTT calculations.
- **Output**: None
- **See also**: [`fd_quic_process_ack_range`](fd_quic.c.driver.md#fd_quic_process_ack_range)  (Implementation)



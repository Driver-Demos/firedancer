# Purpose
The provided C header file, `fd_quic_conn.h`, is part of a library that implements the QUIC protocol, which is a transport layer network protocol designed for fast and secure internet communication. This file specifically defines the structures, constants, and function prototypes necessary for managing QUIC connections. It includes definitions for connection states, reason codes for connection termination, and structures for handling connection-specific data such as stream reception, round-trip time (RTT) calculations, and cryptographic keys. The file also provides inline functions for managing connection identifiers and states, as well as functions for initializing and configuring connection objects.

The header file is designed to be included in other C source files that require access to the QUIC connection management functionality. It defines a public API for creating, configuring, and managing QUIC connections, including setting and retrieving user-defined context values associated with a connection. The file includes several other headers that provide additional functionality, such as cryptographic operations and packet metadata management, indicating that it is part of a larger library or framework for QUIC protocol implementation. The file is structured to support both client and server roles, with fields and flags to manage connection state, stream data, and flow control, making it a comprehensive component for handling QUIC connections.
# Imports and Dependencies

---
- `fd_quic.h`
- `fd_quic_ack_tx.h`
- `fd_quic_stream.h`
- `fd_quic_conn_id.h`
- `crypto/fd_quic_crypto_suites.h`
- `fd_quic_pkt_meta.h`


# Global Variables

---
### fd\_quic\_conn\_reason\_name
- **Type**: `function pointer`
- **Description**: `fd_quic_conn_reason_name` is a function that takes a `uint` representing a reason code and returns a `const char *`, which is a string description of the reason. This function is likely used to map QUIC connection reason codes to human-readable descriptions.
- **Use**: This function is used to retrieve the string representation of a QUIC connection reason code for logging or debugging purposes.


---
### fd\_quic\_conn\_new
- **Type**: `fd_quic_conn_t *`
- **Description**: The `fd_quic_conn_new` function is a constructor for creating a new QUIC connection object. It initializes a `fd_quic_conn_t` structure using the provided memory, QUIC instance, and connection limits. This function is essential for setting up a new QUIC connection with the specified parameters.
- **Use**: This variable is used to allocate and initialize a new QUIC connection object, returning a pointer to the initialized `fd_quic_conn_t` structure.


---
### fd\_quic\_conn\_get\_context
- **Type**: `function pointer`
- **Description**: The `fd_quic_conn_get_context` is a function that retrieves the user-defined context associated with a QUIC connection. It takes a pointer to an `fd_quic_conn_t` structure as an argument and returns a void pointer to the context.
- **Use**: This function is used to access the user-defined context data stored within a QUIC connection object.


# Data Structures

---
### fd\_quic\_conn\_stream\_rx
- **Type**: `struct`
- **Members**:
    - `rx_hi_stream_id`: Highest RX stream ID sent by peer plus 4.
    - `rx_sup_stream_id`: Highest allowed RX stream ID plus 4.
    - `rx_max_data`: Limit on the number of bytes the peer is allowed to send.
    - `rx_tot_data`: Total bytes received across all streams, including implied bytes.
    - `rx_max_data_ackd`: Maximum max_data acknowledged by peer.
    - `rx_max_streams_unidir_ackd`: Value of MAX_STREAMS acknowledged for unidirectional streams.
    - `rx_streams_active`: User scratch field, not currently used by fd_quic.
- **Description**: The `fd_quic_conn_stream_rx` structure is designed to manage and track the state of received data streams in a QUIC connection. It maintains information about the highest stream IDs received and allowed, the total data received, and the maximum data acknowledged by the peer. Additionally, it includes a field for the maximum number of unidirectional streams acknowledged. The structure also contains a user scratch field for potential future use, although it is not currently utilized by the fd_quic implementation.


---
### fd\_quic\_conn\_stream\_rx\_t
- **Type**: `struct`
- **Members**:
    - `rx_hi_stream_id`: Highest RX stream ID sent by peer plus 4.
    - `rx_sup_stream_id`: Highest allowed RX stream ID plus 4.
    - `rx_max_data`: Limit on the number of bytes the peer is allowed to send.
    - `rx_tot_data`: Total bytes received across all streams, including implied bytes.
    - `rx_max_data_ackd`: Maximum data acknowledged by peer.
    - `rx_max_streams_unidir_ackd`: Value of MAX_STREAMS acknowledged for unidirectional streams.
    - `rx_streams_active`: User scratch field, not used by fd_quic.
- **Description**: The `fd_quic_conn_stream_rx_t` structure is designed to manage and track the state of received streams in a QUIC connection. It includes fields for tracking the highest stream IDs sent and allowed, the total and maximum data received, and the acknowledgment status of these data limits. Additionally, it contains a user-defined scratch field for custom use, although it is not utilized by the fd_quic library itself. This structure is crucial for maintaining flow control and ensuring that data received from peers adheres to the defined limits.


---
### fd\_quic\_conn\_rtt
- **Type**: `struct`
- **Members**:
    - `is_rtt_valid`: Indicates if at least one valid RTT sample exists.
    - `peer_ack_delay_scale`: Scale factor for converting peer's ack delays into ticks.
    - `sched_granularity_ticks`: Represents the scheduling granularity in ticks.
    - `peer_max_ack_delay_ticks`: Maximum acknowledgment delay from the peer in microseconds.
    - `rtt_period_ticks`: Time bound between RTT measurements in ticks.
    - `smoothed_rtt`: Smoothed round-trip time in ticks.
    - `var_rtt`: Variance of the round-trip time in ticks.
    - `latest_rtt`: Most recent round-trip time measurement in ticks.
    - `min_rtt`: Minimum round-trip time recorded in ticks.
- **Description**: The `fd_quic_conn_rtt` structure is designed to manage and store round-trip time (RTT) related metrics for a QUIC connection. It includes fields to determine the validity of RTT samples, convert peer acknowledgment delays into ticks, and manage scheduling granularity. Additionally, it tracks various RTT metrics such as the smoothed RTT, its variance, the latest RTT measurement, and the minimum RTT observed, all in terms of ticks. This structure is crucial for optimizing and managing the timing aspects of a QUIC connection.


---
### fd\_quic\_conn\_rtt\_t
- **Type**: `struct`
- **Members**:
    - `is_rtt_valid`: Indicates if at least one valid RTT sample exists.
    - `peer_ack_delay_scale`: Scale factor to convert peer's ACK delay units to ticks.
    - `sched_granularity_ticks`: Scheduling granularity in ticks, often accessed with peer_max_ack_delay_ticks.
    - `peer_max_ack_delay_ticks`: Maximum acknowledgment delay from the peer in ticks.
    - `rtt_period_ticks`: Time bound between RTT measurements in ticks.
    - `smoothed_rtt`: Smoothed round-trip time in ticks.
    - `var_rtt`: Variance of the round-trip time in ticks.
    - `latest_rtt`: Most recent round-trip time measurement in ticks.
    - `min_rtt`: Minimum round-trip time observed in ticks.
- **Description**: The `fd_quic_conn_rtt_t` structure is used to manage and store round-trip time (RTT) related metrics for a QUIC connection. It includes fields to determine if RTT samples are valid, convert peer acknowledgment delays to ticks, and store various RTT measurements such as smoothed RTT, variance, latest, and minimum RTT values. This structure is crucial for optimizing the timing and performance of data transmission in QUIC connections by providing accurate RTT metrics.


---
### fd\_quic\_conn
- **Type**: `struct`
- **Members**:
    - `conn_idx`: Connection index used to identify the connection.
    - `conn_gen`: Generation of the connection slot.
    - `quic`: Pointer to the QUIC instance associated with this connection.
    - `context`: User-defined context for the connection.
    - `server`: Indicates the role of the connection: 0 for client, 1 for server.
    - `established`: Indicates if the connection is established for clients.
    - `transport_params_set`: Flag indicating if transport parameters are set.
    - `called_conn_new`: Flag indicating if conn_final needs to be called on teardown.
    - `visited`: Scratch bit with no strict definition.
    - `key_phase`: Indicates the current key phase.
    - `key_update`: Indicates if a key update is needed.
    - `svc_type`: Service type or UINT_MAX for free connections.
    - `svc_prev`: Previous connection in the service queue.
    - `svc_next`: Next connection in the service queue.
    - `svc_time`: Timestamp until which service may be delayed.
    - `our_conn_id`: Connection ID for the local endpoint.
    - `retry_src_conn_id`: Original retry source connection ID for comparison.
    - `host`: Host network endpoint for source address and port.
    - `peer`: Array of peer network endpoints.
    - `peer_cids`: Array of peer connection IDs.
    - `initial_source_conn_id`: Initial source connection ID.
    - `tx_max_datagram_sz`: Maximum datagram size allowed by the peer.
    - `handshake_complete`: Indicates if the handshake is complete.
    - `handshake_done_send`: Indicates if handshake-done needs to be sent to the peer.
    - `handshake_done_ackd`: Indicates if handshake-done was acknowledged.
    - `tls_hs`: Pointer to TLS handshake state.
    - `hs_sent_bytes`: Array tracking handshake data sent.
    - `hs_ackd_bytes`: Array tracking handshake data acknowledged by peer.
    - `secrets`: Master secrets for key derivation.
    - `keys`: Current keys for each encryption level and direction.
    - `new_keys`: Keys for the next key update.
    - `keys_avail`: Bit set of available keys indexed by encryption level.
    - `send_streams`: List of streams needing action.
    - `used_streams`: List of used streams.
    - `tx_next_stream_id`: Next stream ID to be used for transmission.
    - `tx_sup_stream_id`: Highest allowed transmission stream ID plus four.
    - `stream_map`: Map from stream ID to stream.
    - `exp_pkt_number`: Expected packet numbers for different spaces.
    - `pkt_number`: Transmission packet numbers by packet number space.
    - `last_pkt_number`: Last seen packet numbers by packet number space.
    - `ipv4_id`: IPv4 ID field.
    - `tx_buf_conn`: Buffer for the next transmission.
    - `tx_ptr`: Pointer to free space in the transmission buffer.
    - `state`: Current state of the connection.
    - `reason`: Reason for closing the connection.
    - `app_reason`: Application-specific reason for closing the connection.
    - `ack_gen`: Acknowledgment generator state.
    - `unacked_sz`: Size of unacknowledged stream frame payload bytes.
    - `pkt_meta_tracker`: Packet metadata tracker.
    - `tx_max_data`: Maximum data allowed to be sent across all streams.
    - `tx_tot_data`: Total data received across all streams.
    - `flags`: Flags indicating various connection states.
    - `tx_initial_max_stream_data_uni`: Maximum stream data for unidirectional streams.
    - `upd_pkt_number`: Packet number for the last max_data frame.
    - `peer_enc_level`: Highest peer encryption level.
    - `idle_timeout_ticks`: Idle timeout in ticks.
    - `last_activity`: Timestamp of the last activity.
    - `last_ack`: Timestamp of the last acknowledgment.
    - `rtt`: Round trip time related members.
    - `token_len`: Length of the token.
    - `token`: Token used for connection retry.
    - `srx`: Stream receive state.
    - `used_pkt_meta`: Used packet metadata.
- **Description**: The `fd_quic_conn` structure represents a QUIC connection, encapsulating various attributes and states necessary for managing the connection lifecycle, data transmission, and security. It includes fields for connection identification, role determination, service queue management, network endpoints, handshake status, encryption keys, stream management, packet tracking, and flow control. This structure is integral to the operation of a QUIC protocol implementation, providing the necessary data and state management to facilitate reliable and secure communication over the network.


# Functions

---
### fd\_quic\_set\_conn\_state<!-- {{#callable:fd_quic_set_conn_state}} -->
The `fd_quic_set_conn_state` function sets the state of a QUIC connection to a specified value.
- **Inputs**:
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the QUIC connection whose state is to be set.
    - `state`: An unsigned integer representing the new state to be assigned to the connection.
- **Control Flow**:
    - The function takes a pointer to a connection structure and a state value as inputs.
    - It assigns the provided state value to the `state` field of the connection structure.
- **Output**: This function does not return any value; it modifies the state of the connection in place.


---
### fd\_quic\_conn\_uid<!-- {{#callable:fd_quic_conn_uid}} -->
The `fd_quic_conn_uid` function generates a unique identifier for a QUIC connection using its index and generation number.
- **Inputs**:
    - `conn`: A pointer to a constant `fd_quic_conn_t` structure representing the QUIC connection.
- **Control Flow**:
    - The function takes the `conn_idx` from the `fd_quic_conn_t` structure, casts it to an unsigned long, and shifts it left by 32 bits.
    - It then takes the `conn_gen` from the `fd_quic_conn_t` structure, casts it to an unsigned long, and performs a bitwise OR with the shifted `conn_idx`.
- **Output**: The function returns an unsigned long integer that uniquely identifies the connection by combining its index and generation number.


---
### fd\_quic\_conn\_uid\_idx<!-- {{#callable:fd_quic_conn_uid_idx}} -->
The `fd_quic_conn_uid_idx` function extracts the connection index from a 64-bit connection UID by shifting the bits to the right by 32.
- **Inputs**:
    - `conn_uid`: A 64-bit unsigned long integer representing the connection UID, which encodes both the connection index and generation.
- **Control Flow**:
    - The function takes a 64-bit unsigned long integer `conn_uid` as input.
    - It shifts the `conn_uid` 32 bits to the right, effectively discarding the lower 32 bits which represent the connection generation.
    - The result is cast to a 32-bit unsigned integer, which represents the connection index.
- **Output**: The function returns a 32-bit unsigned integer representing the connection index extracted from the `conn_uid`.


---
### fd\_quic\_conn\_uid\_gen<!-- {{#callable:fd_quic_conn_uid_gen}} -->
The `fd_quic_conn_uid_gen` function extracts the lower 32 bits of a 64-bit connection UID to generate a connection generation identifier.
- **Inputs**:
    - `conn_uid`: A 64-bit unsigned long integer representing the connection UID from which the generation identifier is to be extracted.
- **Control Flow**:
    - The function takes a 64-bit unsigned long integer `conn_uid` as input.
    - It performs a bitwise AND operation between `conn_uid` and `0xffffffffUL` to mask out the lower 32 bits.
    - The result of the bitwise operation is cast to a 32-bit unsigned integer and returned.
- **Output**: A 32-bit unsigned integer representing the generation identifier extracted from the connection UID.


# Function Declarations (Public API)

---
### fd\_quic\_conn\_reason\_name<!-- {{#callable_declaration:fd_quic_conn_reason_name}} -->
Retrieve the name of a QUIC connection reason code.
- **Description**: Use this function to obtain a human-readable name for a given QUIC connection reason code. This is useful for logging or debugging purposes when you need to interpret the reason codes defined in the QUIC protocol. The function expects a valid reason code as input and returns a string representing the name of the reason. If the provided reason code is out of the defined range, the function returns "N/A" to indicate an unknown or invalid reason code.
- **Inputs**:
    - `reason`: An unsigned integer representing the QUIC connection reason code. Valid values are those defined by the FD_QUIC_REASON_CODES macro. If the value is outside the defined range, the function returns "N/A".
- **Output**: A constant character pointer to a string representing the name of the reason code. Returns "N/A" if the reason code is invalid or not recognized.
- **See also**: [`fd_quic_conn_reason_name`](fd_quic_conn.c.driver.md#fd_quic_conn_reason_name)  (Implementation)


---
### fd\_quic\_conn\_align<!-- {{#callable_declaration:fd_quic_conn_align}} -->
Returns the alignment requirement of the QUIC connection structure.
- **Description**: Use this function to determine the memory alignment requirement for the `fd_quic_conn_t` structure. This is useful when allocating memory for QUIC connection objects to ensure proper alignment, which is necessary for optimal performance and to avoid undefined behavior. The function does not require any parameters and can be called at any time.
- **Inputs**: None
- **Output**: The function returns an unsigned long representing the alignment requirement in bytes for the `fd_quic_conn_t` structure.
- **See also**: [`fd_quic_conn_align`](fd_quic_conn.c.driver.md#fd_quic_conn_align)  (Implementation)


---
### fd\_quic\_conn\_footprint<!-- {{#callable_declaration:fd_quic_conn_footprint}} -->
Calculate the memory footprint of a QUIC connection.
- **Description**: This function calculates the memory footprint required for a QUIC connection based on the specified limits. It is useful for determining the amount of memory to allocate when setting up a new QUIC connection. The function should be called with a valid `fd_quic_limits_t` structure that defines the constraints and limits for the connection. This function does not modify any input parameters and does not have side effects.
- **Inputs**:
    - `limits`: A pointer to a `fd_quic_limits_t` structure that specifies the limits and constraints for the QUIC connection. This parameter must not be null, and the structure should be properly initialized before calling the function. Invalid or null input will result in undefined behavior.
- **Output**: Returns an unsigned long representing the memory footprint in bytes required for the connection object based on the provided limits.
- **See also**: [`fd_quic_conn_footprint`](fd_quic_conn.c.driver.md#fd_quic_conn_footprint)  (Implementation)


---
### fd\_quic\_conn\_new<!-- {{#callable_declaration:fd_quic_conn_new}} -->
Creates a new QUIC connection object.
- **Description**: This function initializes a new QUIC connection object using the provided memory, QUIC instance, and connection limits. It must be called with a properly aligned memory block, a valid QUIC instance, and valid connection limits. The function returns a pointer to the newly created connection object or NULL if any of the inputs are invalid or if initialization fails. This function is typically used during the setup phase of a QUIC connection to prepare the connection object for further operations.
- **Inputs**:
    - `mem`: A pointer to a memory block where the connection object will be initialized. The memory must be aligned according to the alignment requirements of fd_quic_conn_t. Must not be null.
    - `quic`: A pointer to an existing fd_quic_t instance representing the QUIC context. Must not be null.
    - `limits`: A pointer to a fd_quic_limits_t structure specifying the limits for the connection. Must not be null.
- **Output**: Returns a pointer to the initialized fd_quic_conn_t object, or NULL if initialization fails due to invalid inputs or other errors.
- **See also**: [`fd_quic_conn_new`](fd_quic_conn.c.driver.md#fd_quic_conn_new)  (Implementation)


---
### fd\_quic\_conn\_set\_context<!-- {{#callable_declaration:fd_quic_conn_set_context}} -->
Set the user-defined context value on the connection.
- **Description**: This function associates a user-defined context with a QUIC connection, allowing the caller to store arbitrary data that can be retrieved later. It is typically used to attach application-specific information to a connection. The function should be called whenever there is a need to update or set the context for a connection. The context can be any pointer-sized value, and the caller is responsible for managing the memory and lifecycle of the context data.
- **Inputs**:
    - `conn`: A pointer to an fd_quic_conn_t structure representing the QUIC connection. Must not be null.
    - `context`: A pointer to the user-defined context data to associate with the connection. Can be null if no context is needed.
- **Output**: None
- **See also**: [`fd_quic_conn_set_context`](fd_quic_conn.c.driver.md#fd_quic_conn_set_context)  (Implementation)


---
### fd\_quic\_conn\_get\_context<!-- {{#callable_declaration:fd_quic_conn_get_context}} -->
Retrieve the user-defined context from a QUIC connection.
- **Description**: Use this function to obtain the user-defined context associated with a specific QUIC connection. This is useful when you need to access custom data or state information that was previously set for the connection. Ensure that the connection object is valid and properly initialized before calling this function.
- **Inputs**:
    - `conn`: A pointer to a valid `fd_quic_conn_t` structure representing the QUIC connection. Must not be null. The function does not modify the connection object.
- **Output**: Returns a pointer to the user-defined context associated with the connection, or NULL if no context has been set.
- **See also**: [`fd_quic_conn_get_context`](fd_quic_conn.c.driver.md#fd_quic_conn_get_context)  (Implementation)



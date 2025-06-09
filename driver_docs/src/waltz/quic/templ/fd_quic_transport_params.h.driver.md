# Purpose
This C header file, `fd_quic_transport_params.h`, defines a structured approach to handling QUIC transport parameters. It provides a comprehensive set of macros and structures to manage various transport parameters used in the QUIC protocol, which is a modern transport layer network protocol designed to improve the performance of connection-oriented web applications. The file includes definitions for a variety of transport parameters such as connection IDs, maximum idle timeout, stateless reset tokens, and maximum UDP payload size, among others. Each parameter is associated with a unique identifier, a type, a default value, and a description, which are used to facilitate the encoding and decoding of these parameters in QUIC connections.

The file is primarily intended to be included in other C source files, as it defines a public API for managing QUIC transport parameters. It includes functions for parsing, encoding, and dumping transport parameters, which are essential for the initialization and management of QUIC connections. The use of macros to define parameter types and their associated data structures allows for flexible and efficient handling of these parameters. The file also includes utility functions for parsing variable-length integers, which are commonly used in the QUIC protocol. Overall, this header file provides a robust framework for implementing and managing QUIC transport parameters in a C-based networking application.
# Imports and Dependencies

---
- `../../../util/fd_util_base.h`
- `stdio.h`


# Data Structures

---
### fd\_quic\_transport\_params
- **Type**: `struct`
- **Members**:
    - `original_destination_connection_id`: Stores the original destination connection ID from the first Initial packet sent by the client.
    - `max_idle_timeout_ms`: Specifies the maximum idle timeout in milliseconds for the connection.
    - `stateless_reset_token`: Holds a 16-byte token used for verifying a stateless reset.
    - `max_udp_payload_size`: Defines the maximum UDP payload size the endpoint is willing to receive.
    - `initial_max_data`: Indicates the initial maximum amount of data that can be sent on the connection.
    - `initial_max_stream_data_bidi_local`: Specifies the initial flow control limit for locally initiated bidirectional streams.
    - `initial_max_stream_data_bidi_remote`: Specifies the initial flow control limit for peer-initiated bidirectional streams.
    - `initial_max_stream_data_uni`: Specifies the initial flow control limit for unidirectional streams.
    - `initial_max_streams_bidi`: Indicates the initial maximum number of bidirectional streams the endpoint can initiate.
    - `initial_max_streams_uni`: Indicates the initial maximum number of unidirectional streams the endpoint can initiate.
    - `ack_delay_exponent`: Defines the exponent used to decode the ACK Delay field in the ACK frame.
    - `max_ack_delay`: Specifies the maximum time in milliseconds the endpoint will delay sending acknowledgments.
    - `disable_active_migration`: Indicates if the endpoint does not support active connection migration.
    - `preferred_address`: Contains the server's preferred address for changing server address at the end of the handshake.
    - `active_connection_id_limit`: Specifies the maximum number of connection IDs the endpoint is willing to store.
    - `initial_source_connection_id`: Holds the value included in the Source Connection ID field of the first Initial packet sent.
    - `retry_source_connection_id`: Holds the value included in the Source Connection ID field of a Retry packet.
- **Description**: The `fd_quic_transport_params` structure is a comprehensive data structure used to define various transport parameters for QUIC connections. It includes fields for connection identifiers, timeout settings, flow control limits, and other parameters that dictate the behavior and constraints of a QUIC connection. Each field is associated with a specific type and may have a default value, and the structure is designed to be flexible to accommodate different transport parameter configurations. This structure is crucial for managing the negotiation and enforcement of transport parameters between QUIC endpoints.


---
### fd\_quic\_transport\_params\_t
- **Type**: `struct`
- **Members**:
    - `original_destination_connection_id`: Stores the original destination connection ID from the first Initial packet sent by the client.
    - `max_idle_timeout_ms`: Specifies the maximum idle timeout in milliseconds for the connection.
    - `stateless_reset_token`: Holds a 16-byte token used for verifying a stateless reset.
    - `max_udp_payload_size`: Defines the maximum UDP payload size the endpoint is willing to receive.
    - `initial_max_data`: Indicates the initial maximum amount of data that can be sent on the connection.
    - `initial_max_stream_data_bidi_local`: Specifies the initial flow control limit for locally initiated bidirectional streams.
    - `initial_max_stream_data_bidi_remote`: Specifies the initial flow control limit for peer-initiated bidirectional streams.
    - `initial_max_stream_data_uni`: Specifies the initial flow control limit for unidirectional streams.
    - `initial_max_streams_bidi`: Indicates the initial maximum number of bidirectional streams the endpoint can initiate.
    - `initial_max_streams_uni`: Indicates the initial maximum number of unidirectional streams the endpoint can initiate.
    - `ack_delay_exponent`: Specifies the exponent used to decode the ACK Delay field in the ACK frame.
    - `max_ack_delay`: Indicates the maximum time in milliseconds the endpoint will delay sending acknowledgments.
    - `disable_active_migration`: Indicates if the endpoint does not support active connection migration.
    - `preferred_address`: Contains the server's preferred address for changing server address at the end of the handshake.
    - `active_connection_id_limit`: Specifies the maximum number of connection IDs the endpoint is willing to store.
    - `initial_source_connection_id`: Stores the initial source connection ID sent by the endpoint.
    - `retry_source_connection_id`: Stores the source connection ID included in a Retry packet by the server.
- **Description**: The `fd_quic_transport_params_t` structure is a comprehensive data structure used in the QUIC protocol to define various transport parameters for a connection. These parameters include identifiers for connection IDs, limits on data and stream sizes, timeout settings, and other configuration options that dictate the behavior of the QUIC connection. Each parameter is associated with a specific type and may have a default value or constraints, such as maximum sizes or specific conditions under which they are applicable. This structure is crucial for managing the negotiation and configuration of QUIC connections, ensuring that both endpoints agree on the operational parameters of the connection.


# Functions

---
### fd\_quic\_tp\_parse\_varint<!-- {{#callable:fd_quic_tp_parse_varint}} -->
The `fd_quic_tp_parse_varint` function parses a variable-length integer from a buffer, updates the buffer pointer and size, and returns the parsed integer value.
- **Inputs**:
    - `buf`: A pointer to a pointer to an unsigned char buffer from which the variable-length integer will be parsed.
    - `buf_sz`: A pointer to an unsigned long representing the size of the buffer, which will be updated to reflect the remaining size after parsing.
- **Control Flow**:
    - Check if the buffer size is zero; if so, return the maximum unsigned long value as an error indicator.
    - Determine the width of the variable-length integer by shifting 1 left by the top two bits of the first byte in the buffer.
    - Check if the buffer size is less than the determined width; if so, return the maximum unsigned long value as an error indicator.
    - Initialize the value by masking the first byte with 0x3f to get the lower 6 bits.
    - Iterate over the remaining bytes (if any) according to the width, shifting the current value left by 8 bits and adding the next byte.
    - Advance the buffer pointer by the width of the parsed integer.
    - Decrease the buffer size by the width of the parsed integer.
    - Return the parsed integer value.
- **Output**: The function returns the parsed variable-length integer as an unsigned long, or the maximum unsigned long value if an error occurs (e.g., insufficient buffer size).


# Function Declarations (Public API)

---
### fd\_quic\_dump\_transport\_param\_desc<!-- {{#callable_declaration:fd_quic_dump_transport_param_desc}} -->
Prints descriptions of QUIC transport parameters to a file.
- **Description**: Use this function to output a list of QUIC transport parameter descriptions to a specified file stream. This is useful for logging or debugging purposes when you need to understand the available transport parameters and their descriptions. Ensure that the file stream provided is valid and open for writing before calling this function.
- **Inputs**:
    - `out`: A pointer to a FILE object where the transport parameter descriptions will be written. Must not be null and should be open for writing. If the file stream is invalid, the behavior is undefined.
- **Output**: None
- **See also**: [`fd_quic_dump_transport_param_desc`](fd_quic_transport_params.c.driver.md#fd_quic_dump_transport_param_desc)  (Implementation)


---
### fd\_quic\_decode\_transport\_params<!-- {{#callable_declaration:fd_quic_decode_transport_params}} -->
Decodes QUIC transport parameters from a buffer.
- **Description**: Use this function to parse and decode QUIC transport parameters from a given buffer into a `fd_quic_transport_params_t` structure. It is essential to ensure that the buffer contains valid encoded transport parameters and that the buffer size accurately reflects the data length. The function will adjust the buffer pointer and size as it processes the data. If the buffer contains parameters that exceed its size or if any parameter fails to parse, the function will return an error. This function should be called when you need to interpret transport parameters received over a QUIC connection.
- **Inputs**:
    - `params`: A pointer to an `fd_quic_transport_params_t` structure where the decoded transport parameters will be stored. The caller must ensure this pointer is valid and points to a properly allocated structure.
    - `buf`: A pointer to a buffer containing the encoded transport parameters. The buffer must not be null and should contain valid data to be decoded.
    - `buf_sz`: The size of the buffer in bytes. It must accurately represent the number of bytes available in the buffer for decoding.
- **Output**: Returns 0 on successful decoding of all transport parameters. Returns -1 if a parameter's size exceeds the remaining buffer size or if a parameter fails to parse.
- **See also**: [`fd_quic_decode_transport_params`](fd_quic_transport_params.c.driver.md#fd_quic_decode_transport_params)  (Implementation)


---
### fd\_quic\_dump\_transport\_params<!-- {{#callable_declaration:fd_quic_dump_transport_params}} -->
Prints the QUIC transport parameters to the specified output stream.
- **Description**: Use this function to output a formatted list of QUIC transport parameters to a given file stream, typically for debugging or logging purposes. The function iterates over each transport parameter, checking if it is present, and prints its name, ID, and value to the specified output stream. This function should be called when you need a human-readable representation of the transport parameters. Ensure that the output stream is valid and open for writing before calling this function.
- **Inputs**:
    - `params`: A pointer to a constant `fd_quic_transport_params_t` structure containing the transport parameters to be printed. Must not be null.
    - `out`: A pointer to a `FILE` stream where the transport parameters will be printed. Must be a valid, open file stream for writing.
- **Output**: None
- **See also**: [`fd_quic_dump_transport_params`](fd_quic_transport_params.c.driver.md#fd_quic_dump_transport_params)  (Implementation)


---
### fd\_quic\_encode\_transport\_params<!-- {{#callable_declaration:fd_quic_encode_transport_params}} -->
Encodes QUIC transport parameters into a buffer.
- **Description**: Use this function to encode QUIC transport parameters into a provided buffer, which is useful for preparing data to be sent over a network. The function requires a buffer with sufficient size to hold the encoded parameters and a structure containing the transport parameters to be encoded. It is important to ensure that the buffer is large enough to accommodate the encoded data to avoid buffer overflows. The function returns the number of bytes written to the buffer, allowing the caller to verify the amount of data encoded.
- **Inputs**:
    - `buf`: A pointer to the buffer where the encoded transport parameters will be written. The buffer must be pre-allocated and have enough space to hold the encoded data. The caller retains ownership of the buffer.
    - `buf_sz`: The size of the buffer in bytes. It must be large enough to accommodate the encoded transport parameters. If the buffer is too small, the function may not encode all parameters.
    - `params`: A pointer to a constant fd_quic_transport_params_t structure containing the transport parameters to be encoded. The structure must be properly initialized, and the caller retains ownership.
- **Output**: The function returns the number of bytes written to the buffer, allowing the caller to determine the size of the encoded data.
- **See also**: [`fd_quic_encode_transport_params`](fd_quic_transport_params.c.driver.md#fd_quic_encode_transport_params)  (Implementation)



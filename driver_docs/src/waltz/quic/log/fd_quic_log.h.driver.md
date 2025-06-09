# Purpose
This C header file defines data structures and constants for logging events in a QUIC (Quick UDP Internet Connections) protocol implementation. It includes definitions for two main structures: `fd_quic_log_abi_t`, which holds parameters necessary for consuming log messages from a QUIC log interface, and `fd_quic_log_hdr_t`, which represents the header of a log message containing connection identifiers and packet details. Additionally, the file defines a set of event IDs for various connection and allocation failure events, facilitating the categorization and identification of specific occurrences within the QUIC protocol. The `fd_quic_log_error_t` structure is also defined to encapsulate error information, including protocol-specific error codes and source location details, aiding in debugging and error tracking. Overall, this file serves as a configuration and definition resource for handling and interpreting QUIC logging events.
# Imports and Dependencies

---
- `../../../util/fd_util_base.h`


# Data Structures

---
### fd\_quic\_log\_abi
- **Type**: `struct`
- **Members**:
    - `magic`: A magic number used to verify the integrity or version of the structure, expected to be equal to FD_QUIC_LOG_MAGIC.
    - `mcache_off`: An offset value used in memory caching operations.
    - `chunk0`: An unsigned integer representing the first chunk of data or configuration.
    - `chunk1`: An unsigned integer representing the second chunk of data or configuration.
- **Description**: The `fd_quic_log_abi` structure is designed to encapsulate the necessary parameters for consuming log messages from a QUIC logging interface. It includes a magic number for validation, an offset for memory cache operations, and two unsigned integers that likely represent configuration or data chunks. This structure is part of the ABI (Application Binary Interface) definitions for shared memory logging in QUIC, ensuring that the logging mechanism can correctly interpret and process log data.


---
### fd\_quic\_log\_abi\_t
- **Type**: `struct`
- **Members**:
    - `magic`: A magic number used to identify the structure, expected to be equal to FD_QUIC_LOG_MAGIC.
    - `mcache_off`: An offset value used in the memory cache for log message consumption.
    - `chunk0`: The first chunk identifier for log message processing.
    - `chunk1`: The second chunk identifier for log message processing.
- **Description**: The `fd_quic_log_abi_t` structure is designed to encapsulate all necessary parameters for consuming log messages from a QUIC log interface. It includes a magic number for structure identification, an offset for memory cache operations, and two chunk identifiers that likely assist in managing or processing log data chunks. This structure is part of the ABI definitions for QUIC shared memory logging, facilitating the interaction with the logging system.


---
### fd\_quic\_log\_hdr
- **Type**: `struct`
- **Members**:
    - `conn_id`: A unique identifier for the connection.
    - `pkt_num`: The packet number associated with the log entry.
    - `ip4_saddr`: The source IPv4 address in big endian format.
    - `udp_sport`: The source UDP port in little endian format.
    - `enc_level`: The encryption level of the packet.
    - `flags`: Flags providing additional information about the log entry.
- **Description**: The `fd_quic_log_hdr` structure is used to represent the header of a QUIC log entry, containing essential metadata about a QUIC packet. It includes fields for connection identification, packet sequencing, network addressing, and protocol-specific details such as encryption level and flags. This structure is crucial for logging and debugging QUIC protocol operations, providing a compact representation of packet-related information.


---
### fd\_quic\_log\_hdr\_t
- **Type**: `struct`
- **Members**:
    - `conn_id`: A unique identifier for the connection.
    - `pkt_num`: The packet number associated with the log entry.
    - `ip4_saddr`: The source IPv4 address in big endian format.
    - `udp_sport`: The source UDP port in little endian format.
    - `enc_level`: The encryption level of the packet.
    - `flags`: Flags providing additional information about the log entry.
- **Description**: The `fd_quic_log_hdr_t` structure is used to represent the header information for QUIC log entries, containing essential metadata such as connection ID, packet number, source IP address, source UDP port, encryption level, and additional flags. This structure is crucial for logging and tracking QUIC protocol events, providing a standardized format for capturing and interpreting log data.


---
### fd\_quic\_log\_error
- **Type**: `struct`
- **Members**:
    - `hdr`: A header of type `fd_quic_log_hdr_t` containing connection and packet information.
    - `code`: An array of two unsigned long integers representing protocol-specific error codes.
    - `src_file`: A character array of size 16 indicating the source file where the error occurred.
    - `src_line`: An unsigned integer representing the line number in the source file where the error occurred.
    - `flags`: An unsigned character indicating the origin of the error, with specific bits denoting local or peer origin.
- **Description**: The `fd_quic_log_error` structure is designed to encapsulate error information related to QUIC protocol operations. It includes a header for connection and packet details, an array for protocol-specific error codes, and metadata about the source file and line where the error was generated. The `flags` field provides additional context about the error's origin, distinguishing between local and peer-generated errors.


---
### fd\_quic\_log\_error\_t
- **Type**: `struct`
- **Members**:
    - `hdr`: A header structure containing connection and packet information.
    - `code`: An array of two unsigned long integers representing protocol-specific error codes.
    - `src_file`: A character array of size 16 indicating the source file where the error originated.
    - `src_line`: An unsigned integer representing the line number in the source file where the error occurred.
    - `flags`: An unsigned character indicating the origin of the error, whether local or from a peer.
- **Description**: The `fd_quic_log_error_t` structure is designed to encapsulate error information within the QUIC logging system. It includes a header for connection and packet details, an array for protocol-specific error codes, and metadata about the source of the error, such as the file name and line number. The flags field indicates whether the error was local or received from a peer, providing a comprehensive view of error occurrences in the QUIC protocol.



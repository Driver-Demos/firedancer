# Purpose
This C header file defines structures and functions related to handling QUIC (Quick UDP Internet Connections) connection identifiers (IDs) within the Firedancer project. The primary focus of the file is to manage connection IDs, which are crucial for routing and identifying connections in a QUIC protocol implementation. The file defines a `fd_quic_conn_id_t` structure that encapsulates a QUIC connection ID, which can be up to 20 bytes in size, and includes padding for alignment purposes. The file provides inline functions for creating new connection IDs, including a function to generate random 8-byte connection IDs using a random number generator. Additionally, it defines macros for checking the validity of connection IDs and comparing them for equality.

The file also introduces a `fd_quic_net_endpoint_t` structure to represent a network endpoint using an IP address and UDP port, which is essential for identifying the network location of a QUIC connection. The header file is designed to be included in other parts of the Firedancer project, providing a consistent interface for managing QUIC connection IDs. It does not define a public API for external use but rather serves as an internal utility for the project, focusing on the specific task of connection ID management within the QUIC protocol context.
# Imports and Dependencies

---
- `../../util/fd_util_base.h`
- `../../util/rng/fd_rng.h`
- `string.h`


# Data Structures

---
### fd\_quic\_conn\_id
- **Type**: `struct`
- **Members**:
    - `sz`: Stores the size of the connection ID in bytes, ranging from 0 to 20.
    - `conn_id`: An array of bytes representing the connection ID, with a maximum size defined by FD_QUIC_MAX_CONN_ID_SZ.
    - `pad`: An array used to pad the structure for alignment purposes.
- **Description**: The `fd_quic_conn_id` structure is designed to represent a QUIC connection ID, which is a unique identifier for a connection in the QUIC protocol. It includes a size field `sz` to indicate the length of the connection ID, an array `conn_id` to store the actual connection ID bytes, and a `pad` array to ensure proper memory alignment. The structure is padded explicitly to align with the system's memory requirements, and the unused high bytes of `conn_id` must be zeroed. This structure is used to manage connection IDs in a way that supports efficient routing and identification of packets in a QUIC network.


---
### fd\_quic\_conn\_id\_t
- **Type**: `struct`
- **Members**:
    - `sz`: Stores the size of the connection ID, ranging from 0 to 20 bytes.
    - `conn_id`: An array of bytes representing the connection ID, with a maximum size of 20 bytes.
    - `pad`: An array used to pad the structure for alignment purposes.
- **Description**: The `fd_quic_conn_id_t` structure is designed to represent a QUIC connection ID, which can vary in size from 0 to 20 bytes. The structure includes a size field (`sz`) to indicate the actual length of the connection ID stored in the `conn_id` array. The `pad` array is used to ensure proper alignment of the structure in memory. This structure is used in the context of QUIC protocol implementations to uniquely identify connections, and it includes utility functions for creating new connection IDs and generating random ones.


---
### fd\_quic\_net\_endpoint
- **Type**: `struct`
- **Members**:
    - `ip_addr`: An unsigned integer representing the IP address of the network endpoint.
    - `udp_port`: An unsigned short integer representing the UDP port number of the network endpoint.
- **Description**: The `fd_quic_net_endpoint` structure is used to identify a UDP/IP network endpoint, consisting of an IP address and a UDP port number. This structure is stored in host endian format and may change during the lifetime of a connection, making it suitable for dynamic network configurations.


---
### fd\_quic\_net\_endpoint\_t
- **Type**: `struct`
- **Members**:
    - `ip_addr`: Stores the IP address of the network endpoint as a 32-bit unsigned integer.
    - `udp_port`: Stores the UDP port number of the network endpoint as a 16-bit unsigned short.
- **Description**: The `fd_quic_net_endpoint_t` structure is used to identify a UDP/IP network endpoint, storing the IP address and UDP port in host-endian format. This structure is essential for network communication, as it allows the identification and routing of packets to the correct endpoint. The values within this structure may change during the lifetime of a connection, reflecting the dynamic nature of network communications.


# Functions

---
### fd\_quic\_conn\_id\_new<!-- {{#callable:fd_quic_conn_id_t::fd_quic_conn_id_new}} -->
The `fd_quic_conn_id_new` function creates a new QUIC connection ID structure with a specified size and connection ID data.
- **Inputs**:
    - `conn_id`: A pointer to the connection ID data to be copied into the new connection ID structure.
    - `sz`: The size of the connection ID data, which must be in the range [0,20].
- **Control Flow**:
    - The function begins by initializing a `fd_quic_conn_id_t` structure with the size `sz` cast to an unsigned char.
    - The `fd_memcpy` function is used to copy `sz` bytes from the `conn_id` input into the `conn_id` field of the `fd_quic_conn_id_t` structure.
    - The function returns the newly created `fd_quic_conn_id_t` structure.
- **Output**: The function returns a `fd_quic_conn_id_t` structure containing the specified connection ID data and size.
- **See also**: [`fd_quic_conn_id_t`](#fd_quic_conn_id_t)  (Data Structure)


---
### fd\_quic\_conn\_id\_rand<!-- {{#callable:fd_quic_conn_id_rand}} -->
The `fd_quic_conn_id_rand` function generates a random 8-byte QUIC connection ID and returns it.
- **Inputs**:
    - `conn_id`: A pointer to an `fd_quic_conn_id_t` structure where the generated connection ID will be stored.
    - `rng`: A pointer to an `fd_rng_t` structure used to generate random numbers.
- **Control Flow**:
    - Initialize the `conn_id` structure with a size of 8 bytes, zeroed connection ID, and zeroed padding.
    - Generate a random unsigned long integer using the provided random number generator `rng`.
    - Store the generated random number into the `conn_id`'s `conn_id` field.
    - Return the pointer to the `conn_id` structure.
- **Output**: A pointer to the `fd_quic_conn_id_t` structure containing the newly generated random connection ID.



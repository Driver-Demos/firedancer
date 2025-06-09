# Purpose
This C header file, `fd_udp.h`, provides functionality related to the manipulation and validation of UDP (User Datagram Protocol) headers, specifically within the context of IPv4 networking. The file defines a union `fd_udp_hdr` that represents the structure of a UDP header, including fields for source and destination ports, datagram length, and checksum. The union allows for both structured access to these fields and raw byte-level access, facilitating various operations on UDP headers. The file also includes a function, [`fd_ip4_udp_check`](#fd_ip4_udp_check), which computes and validates the UDP checksum, a critical operation for ensuring data integrity in network communications. This function takes into account the pseudo-header used in checksum calculations, which includes the source and destination IP addresses, and provides a mechanism to verify the correctness of the UDP datagram.

Additionally, the file provides a utility function, [`fd_udp_hdr_bswap`](#fd_udp_hdr_bswap), to reverse the endianness of the fields in a UDP header, which is essential for ensuring correct data interpretation across different systems with varying byte orders. The header file is designed to be included in other C source files, providing a focused set of utilities for handling UDP headers in network programming. It does not define a broad API but rather focuses on specific operations related to UDP header manipulation and validation, making it a specialized component within a larger networking library or application.
# Imports and Dependencies

---
- `fd_ip4.h`


# Data Structures

---
### fd\_udp\_hdr
- **Type**: `union`
- **Members**:
    - `net_sport`: Source port in network byte order.
    - `net_dport`: Destination port in network byte order.
    - `net_len`: Length of the datagram from the first byte of this header to the last byte of the UDP payload.
    - `check`: UDP checksum in invariant order, with 0 indicating no checksum in IPv4.
    - `uc`: An 8-byte array providing raw access to the UDP header data.
- **Description**: The `fd_udp_hdr` is a union representing a UDP header, which can be accessed either as a structured set of fields or as a raw byte array. The structured fields include source and destination ports, the length of the datagram, and a checksum for data integrity. This design allows for both high-level manipulation of UDP header fields and low-level byte manipulation, facilitating operations such as checksum calculations and byte order conversions.


---
### fd\_udp\_hdr\_t
- **Type**: `union`
- **Members**:
    - `net_sport`: Source port in network byte order.
    - `net_dport`: Destination port in network byte order.
    - `net_len`: Length of the datagram from the first byte of this header to the last byte of the UDP payload.
    - `check`: UDP checksum in invariant order, with 0 indicating no checksum in IP4.
    - `uc`: An 8-byte array providing raw access to the UDP header data.
- **Description**: The `fd_udp_hdr_t` is a union representing a UDP header, which is a fundamental component of the User Datagram Protocol used in networking. It contains fields for the source and destination ports, the length of the datagram, and a checksum for error-checking purposes. The union allows access to these fields either individually or as a raw byte array, facilitating both structured and unstructured data manipulation. This structure is crucial for handling UDP packets, especially in scenarios where manual checksum computation or validation is required.


# Functions

---
### fd\_ip4\_udp\_check<!-- {{#callable:fd_ip4_udp_check}} -->
The `fd_ip4_udp_check` function computes or validates the UDP checksum for a given datagram using the IP4 source and destination addresses and the UDP header.
- **Inputs**:
    - `ip4_saddr`: The IP4 source address used for the UDP pseudo header.
    - `ip4_daddr`: The IP4 destination address used for the UDP pseudo header.
    - `udp`: A non-NULL pointer to the UDP header, which contains the source port, destination port, length, and checksum fields.
    - `dgram`: A non-NULL pointer to the datagram data, which is the UDP payload.
- **Control Flow**:
    - Retrieve the network order length from the UDP header and calculate the remaining bytes of the datagram by subtracting the size of the UDP header.
    - Initialize a sum with the pseudo header and UDP header fields, including the protocol, length, source address, destination address, and UDP header fields.
    - Iterate over the datagram data in 4-byte chunks, adding each to the sum, and handle any remaining bytes at the end of the datagram.
    - Reduce the sum to a 16-bit one's complement sum by folding the upper bits into the lower 16 bits.
    - Complement the final sum to produce the checksum result.
- **Output**: Returns a 16-bit checksum value; if the datagram has no checksum, it returns the computed checksum, otherwise it returns 0 for a valid checksum or non-zero for an invalid checksum.


---
### fd\_udp\_hdr\_bswap<!-- {{#callable:fd_udp_hdr_bswap}} -->
The `fd_udp_hdr_bswap` function reverses the byte order of all fields in a UDP header structure to convert between network and host byte order.
- **Inputs**:
    - `hdr`: A pointer to an `fd_udp_hdr_t` structure representing the UDP header whose fields' byte order will be swapped.
- **Control Flow**:
    - The function takes a pointer to a UDP header structure as input.
    - It swaps the byte order of the `net_sport` field using `fd_ushort_bswap`.
    - It swaps the byte order of the `net_dport` field using `fd_ushort_bswap`.
    - It swaps the byte order of the `net_len` field using `fd_ushort_bswap`.
    - It swaps the byte order of the `check` field using `fd_ushort_bswap`.
- **Output**: The function does not return a value; it modifies the input `fd_udp_hdr_t` structure in place.



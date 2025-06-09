# Purpose
This C header file, `fd_igmp.h`, is designed to facilitate the handling and manipulation of Internet Group Management Protocol (IGMP) messages within an IPv4 network context. It defines constants, data structures, and functions that are essential for creating, parsing, and validating IGMP messages. The file includes definitions for different IGMP message types, such as queries and reports, which are used to manage multicast group memberships on a network. The `fd_igmp` union and [`fd_ip4_igmp`](#fd_ip4_igmp) structure encapsulate the IGMP message format, including fields for message type, response time, checksum, and multicast group address, as well as the associated IPv4 header.

The file provides two primary functions: [`fd_igmp_check`](#fd_igmp_check) and [`fd_ip4_igmp`](#fd_ip4_igmp). The [`fd_igmp_check`](#fd_igmp_check) function is used to compute and validate the checksum of an IGMP message, ensuring data integrity. The [`fd_ip4_igmp`](#fd_ip4_igmp) function constructs a well-formed IGMP message, complete with an IPv4 header, given specific parameters such as source and destination addresses, IGMP type, response time, and group address. This header file is intended to be included in other C source files, providing a reusable and efficient way to work with IGMP messages in network applications. It does not define a public API but rather serves as a utility for internal use in network-related software development.
# Imports and Dependencies

---
- `fd_ip4.h`


# Data Structures

---
### fd\_igmp
- **Type**: `union`
- **Members**:
    - `type`: IGMP type.
    - `resp`: For v1, 0 on send and ignored on receive; for v2, 0 on send and required response time in 0.1 s increments on receive.
    - `check`: IGMP checksum in "invariant" order.
    - `group`: IGMP group (IP4 multicast address), technically in network order but used directly by APIs.
    - `u`: Array of two unsigned integers used for checksum calculations.
- **Description**: The `fd_igmp` union is a data structure used to represent an Internet Group Management Protocol (IGMP) message. It contains a struct with fields for the IGMP type, response time, checksum, and group address, as well as an array of two unsigned integers for checksum calculations. This structure facilitates the handling and processing of IGMP messages, which are used for managing multicast group memberships in IP networks.


---
### fd\_igmp\_t
- **Type**: `union`
- **Members**:
    - `type`: Specifies the IGMP message type.
    - `resp`: Indicates the response time or is ignored depending on IGMP version.
    - `check`: Holds the IGMP checksum for message validation.
    - `group`: Represents the multicast group IP address.
    - `u`: An array used for checksum calculations.
- **Description**: The `fd_igmp_t` is a union data structure used to represent an Internet Group Management Protocol (IGMP) message. It encapsulates the essential fields of an IGMP message, including the type of message, response time, checksum, and multicast group address. The union also provides an array for efficient checksum calculations. This structure is crucial for handling IGMP messages in network communication, particularly for managing multicast group memberships.


---
### fd\_ip4\_igmp
- **Type**: `struct`
- **Members**:
    - `ip4`: An array of one IPv4 header structure.
    - `opt`: An array of four unsigned characters for options.
    - `igmp`: An array of one IGMP structure.
- **Description**: The `fd_ip4_igmp` structure is a compound data type that encapsulates an IPv4 header, a set of options, and an IGMP message. It is designed to represent a complete IP packet that includes IGMP (Internet Group Management Protocol) data, which is used for managing multicast group memberships. The structure includes an IPv4 header (`ip4`), a fixed-size options field (`opt`), and an IGMP message (`igmp`), making it suitable for constructing and parsing network packets that involve multicast communication.


---
### fd\_ip4\_igmp\_t
- **Type**: `struct`
- **Members**:
    - `ip4`: An array of one fd_ip4_hdr_t structure representing the IPv4 header.
    - `opt`: A 4-byte array for storing IGMP options.
    - `igmp`: An array of one fd_igmp_t union representing the IGMP message.
- **Description**: The `fd_ip4_igmp_t` structure is a compound data structure that encapsulates an IPv4 header, IGMP options, and an IGMP message. It is designed to facilitate the construction and manipulation of IGMP messages within an IPv4 packet, providing fields for the IPv4 header, IGMP options, and the IGMP message itself. This structure is used in network programming to handle IGMP protocol operations, such as sending and receiving multicast group membership reports and queries.


# Functions

---
### fd\_igmp\_check<!-- {{#callable:fd_igmp_check}} -->
The `fd_igmp_check` function computes and validates the checksum of an IGMP message.
- **Inputs**:
    - `igmp`: A pointer to a `fd_igmp_t` structure representing the IGMP message to be checked.
- **Control Flow**:
    - The function retrieves the two 32-bit words from the IGMP message using the `u` array.
    - It computes the sum of these two words, storing the result in a 64-bit unsigned long `c`.
    - The function then reduces `c` by adding the higher 32 bits to the lower 32 bits, and further reduces it by adding the higher 16 bits to the lower 16 bits.
    - Finally, it adds any remaining carry from the previous step to the lower 16 bits.
    - The function returns the bitwise negation of the final 16-bit result as the checksum.
- **Output**: The function returns a `ushort` which is the computed checksum if the input checksum is zero, or zero if the input checksum is valid, or a non-zero value if the input checksum is invalid.


---
### fd\_ip4\_igmp<!-- {{#callable:fd_ip4_igmp}} -->
The `fd_ip4_igmp` function constructs and returns a well-formed IP4/IGMP message in a provided memory region.
- **Inputs**:
    - `_msg`: A pointer to a memory region where the IP4/IGMP message will be constructed.
    - `ip4_saddr`: The source IP address for the IP4 header, assumed to be a valid unicast address on the subnet.
    - `ip4_daddr`: The destination IP address for the IP4 header, assumed to be a valid multicast address.
    - `igmp_type`: The type of IGMP message to be constructed, such as QUERY, V1_REPORT, V2_REPORT, or V2_LEAVE.
    - `igmp_resp`: The IGMP response time, which is 0 on send and required response time in 0.1 second increments on receive for V2.
    - `igmp_group`: The IGMP group address, typically the same as the destination IP address.
- **Control Flow**:
    - Cast the input `_msg` to a `fd_ip4_igmp_t` pointer named `msg`.
    - Set the IP4 header fields in `msg` including version, header length, type of service, total length, ID, fragment offset, TTL, protocol, and checksum.
    - Copy the source and destination IP addresses into the IP4 header of `msg`.
    - Set the IP4 options in `msg` to include a router alert option.
    - Set the IGMP fields in `msg` including type, response time, checksum, and group address.
    - Compute and set the IP4 header checksum using [`fd_ip4_hdr_check`](fd_ip4.h.driver.md#fd_ip4_hdr_check).
    - Compute and set the IGMP checksum using [`fd_igmp_check`](#fd_igmp_check).
    - Return the pointer `msg`.
- **Output**: A pointer to the constructed `fd_ip4_igmp_t` message.
- **Functions called**:
    - [`fd_ip4_hdr_check`](fd_ip4.h.driver.md#fd_ip4_hdr_check)
    - [`fd_igmp_check`](#fd_igmp_check)



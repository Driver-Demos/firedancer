# Purpose
This C header file, `fd_eth.h`, provides a comprehensive set of definitions and functions for handling Ethernet protocol operations, specifically focusing on Ethernet headers, VLAN tags, and MAC address manipulations. The file includes detailed documentation on Ethernet packet structure, including the preamble, Ethernet header, VLAN tags, payload, and frame check sequence (FCS). It defines constants for Ethernet header types, such as IP, ARP, and VLAN, and provides macros for calculating payload size limits. The file also includes structures for Ethernet headers and VLAN tags, along with utility functions for MAC address operations, such as checking if a MAC address is multicast, locally administered, or broadcast, and functions for computing and appending the FCS of Ethernet frames.

The header file is designed to be included in other C source files, providing a set of utilities for Ethernet packet processing. It defines public APIs for Ethernet-related operations, such as [`fd_eth_fcs`](#fd_eth_fcs) for FCS computation and [`fd_eth_mac_ip4_mcast`](#fd_eth_mac_ip4_mcast) for generating multicast MAC addresses from IPv4 addresses. The file also includes inline functions for efficient MAC address copying and VLAN tag creation. Overall, this header file serves as a foundational component for applications that require low-level Ethernet packet manipulation and analysis, offering both broad functionality for Ethernet protocol handling and specific utilities for MAC address and VLAN tag operations.
# Imports and Dependencies

---
- `../bits/fd_bits.h`


# Global Variables

---
### fd\_cstr\_to\_mac\_addr
- **Type**: `function`
- **Description**: The `fd_cstr_to_mac_addr` function is designed to parse a MAC address from a C-style string that matches a specific format and store the result into a provided memory location. The format expected is defined by `FD_ETH_MAC_FMT`, which is a standard MAC address format (e.g., 'xx:xx:xx:xx:xx:xx').
- **Use**: This function is used to convert a string representation of a MAC address into its byte array form, storing the result in the provided `mac` buffer.


# Data Structures

---
### fd\_eth\_hdr
- **Type**: `struct`
- **Members**:
    - `dst`: An array of 6 unsigned characters representing the destination MAC address.
    - `src`: An array of 6 unsigned characters representing the source MAC address.
    - `net_type`: An unsigned short indicating the type of packet encapsulated, in network byte order.
- **Description**: The `fd_eth_hdr` structure represents an Ethernet header, which is a fundamental component of Ethernet frames used in network communications. It contains fields for the destination and source MAC addresses, each 6 bytes long, which are used to identify the sender and receiver of the packet on a local network. The `net_type` field specifies the type of payload encapsulated within the Ethernet frame, such as an IP or ARP packet, and is stored in network byte order to ensure compatibility across different systems. This structure is crucial for handling Ethernet frames in network applications, allowing for the parsing and construction of Ethernet headers.


---
### fd\_eth\_hdr\_t
- **Type**: `struct`
- **Members**:
    - `dst`: Destination MAC address, represented as an array of 6 unsigned characters.
    - `src`: Source MAC address, represented as an array of 6 unsigned characters.
    - `net_type`: Type of packet encapsulated, stored in network byte order as an unsigned short.
- **Description**: The `fd_eth_hdr_t` structure represents an Ethernet header, which is a fundamental component of Ethernet frames used in network communications. It contains fields for the destination and source MAC addresses, each 6 bytes long, which are used to identify the sender and receiver of the packet on a local network. Additionally, it includes a `net_type` field that specifies the type of payload encapsulated within the Ethernet frame, such as an IP or ARP packet, and is stored in network byte order. This structure is crucial for handling Ethernet frames in network applications, allowing for the parsing and construction of Ethernet headers in data packets.


---
### fd\_vlan\_tag
- **Type**: `struct`
- **Members**:
    - `net_vid`: A 16-bit field containing a 3-bit priority, a 1-bit CFI, and a 12-bit VLAN tag in network byte order.
    - `net_type`: A 16-bit field representing the ethertype in network byte order.
- **Description**: The `fd_vlan_tag` structure is used to represent a VLAN tag in an Ethernet frame. It contains two fields: `net_vid`, which encodes the VLAN ID along with priority and CFI bits, and `net_type`, which specifies the type of protocol encapsulated in the Ethernet frame. This structure is crucial for handling VLAN-tagged Ethernet packets, allowing for the identification and processing of VLAN-specific data within a network.


---
### fd\_vlan\_tag\_t
- **Type**: `struct`
- **Members**:
    - `net_vid`: A 16-bit field containing a 3-bit priority, a 1-bit CFI, and a 12-bit VLAN tag in network byte order.
    - `net_type`: A 16-bit field representing the ethertype in network byte order.
- **Description**: The `fd_vlan_tag_t` structure represents a VLAN tag in an Ethernet frame, which is used to identify and prioritize network traffic. It contains two fields: `net_vid`, which encodes the VLAN ID along with priority and CFI bits, and `net_type`, which specifies the type of protocol encapsulated following the VLAN tag. This structure is crucial for handling VLAN-tagged Ethernet frames, allowing for network segmentation and traffic management.


# Functions

---
### fd\_eth\_mac\_is\_mcast<!-- {{#callable:fd_eth_mac_is_mcast}} -->
The function `fd_eth_mac_is_mcast` checks if a given MAC address is a multicast address.
- **Inputs**:
    - `mac`: A pointer to an array of unsigned characters representing a MAC address.
- **Control Flow**:
    - The function takes a pointer to a MAC address as input.
    - It checks the least significant bit of the first byte of the MAC address using a bitwise AND operation with 1U.
    - The result of the bitwise operation is converted to a boolean value using the double negation operator (!!).
    - The function returns 1 if the MAC address is multicast (i.e., the least significant bit of the first byte is set), otherwise it returns 0.
- **Output**: An integer value indicating whether the MAC address is multicast (1 for true, 0 for false).


---
### fd\_eth\_mac\_is\_local<!-- {{#callable:fd_eth_mac_is_local}} -->
The function `fd_eth_mac_is_local` checks if a given MAC address is locally administered.
- **Inputs**:
    - `mac`: A pointer to an array of unsigned characters representing a MAC address.
- **Control Flow**:
    - The function takes a pointer to a MAC address as input.
    - It checks the second least significant bit of the first byte of the MAC address.
    - The function returns a non-zero value if the bit is set, indicating the MAC address is locally administered, otherwise it returns zero.
- **Output**: An integer indicating whether the MAC address is locally administered (non-zero) or not (zero).


---
### fd\_eth\_mac\_is\_bcast<!-- {{#callable:fd_eth_mac_is_bcast}} -->
The function `fd_eth_mac_is_bcast` checks if a given MAC address is an Ethernet broadcast address.
- **Inputs**:
    - `mac`: A pointer to a 6-byte array representing a MAC address.
- **Control Flow**:
    - The function uses `fd_ulong_load_4_fast` to load the first 4 bytes of the MAC address and `fd_ulong_load_2_fast` to load the last 2 bytes.
    - It adds the results of these two loads together.
    - It compares the sum to the constant value `0xffffffffUL + 0xffffUL`, which represents the broadcast MAC address `FF:FF:FF:FF:FF:FF`.
    - If the sum matches the constant, the function returns 1 (true), indicating the MAC address is a broadcast address; otherwise, it returns 0 (false).
- **Output**: An integer value: 1 if the MAC address is a broadcast address, 0 otherwise.


---
### fd\_eth\_mac\_is\_ip4\_mcast<!-- {{#callable:fd_eth_mac_is_ip4_mcast}} -->
The function `fd_eth_mac_is_ip4_mcast` checks if a given MAC address corresponds to an IPv4 multicast address.
- **Inputs**:
    - `mac`: A pointer to an array of unsigned characters representing a MAC address.
- **Control Flow**:
    - The function uses `fd_ulong_load_3_fast` to load the first three bytes of the MAC address pointed to by `mac`.
    - It compares the loaded value to the constant `0x5e0001UL`.
    - If the loaded value equals `0x5e0001UL`, the function returns 1, indicating the MAC address is an IPv4 multicast address; otherwise, it returns 0.
- **Output**: The function returns an integer: 1 if the MAC address is an IPv4 multicast address, and 0 otherwise.


---
### fd\_eth\_fcs<!-- {{#callable:fd_eth_fcs}} -->
The `fd_eth_fcs` function computes the Frame Check Sequence (FCS) for an Ethernet frame using a given buffer and size.
- **Inputs**:
    - `buf`: A pointer to the buffer containing the Ethernet frame data.
    - `sz`: The size of the buffer in bytes, representing the length of the Ethernet frame data.
- **Control Flow**:
    - The function calls [`fd_eth_fcs_append`](fd_eth.c.driver.md#fd_eth_fcs_append) with a seed value `FD_ETH_FCS_APPEND_SEED`, the buffer `buf`, and the size `sz`.
    - The [`fd_eth_fcs_append`](fd_eth.c.driver.md#fd_eth_fcs_append) function performs the actual computation of the FCS using the provided buffer and size.
- **Output**: The function returns a `uint` representing the computed FCS for the given Ethernet frame data.
- **Functions called**:
    - [`fd_eth_fcs_append`](fd_eth.c.driver.md#fd_eth_fcs_append)


---
### fd\_eth\_mac\_ip4\_mcast<!-- {{#callable:fd_eth_mac_ip4_mcast}} -->
The `fd_eth_mac_ip4_mcast` function generates an Ethernet MAC address for a given IPv4 multicast address and stores it in a specified memory location.
- **Inputs**:
    - `mac`: A pointer to a 6-byte memory region where the resulting MAC address will be stored.
    - `ip4_addr_mcast`: A 32-bit unsigned integer representing the IPv4 multicast address, where the caller ensures the first byte is in the range [224,239].
- **Control Flow**:
    - The function calculates the first 4 bytes of the MAC address by combining a fixed multicast prefix (0x5e0001) with bits 8-14 of the IPv4 address, shifted into the correct position.
    - The function calculates the last 2 bytes of the MAC address by extracting bits 16-31 of the IPv4 address.
    - The calculated MAC address is stored in the memory location pointed to by the `mac` parameter.
    - The function returns the `mac` pointer.
- **Output**: A pointer to the `mac` memory region containing the generated MAC address.


---
### fd\_eth\_mac\_bcast<!-- {{#callable:fd_eth_mac_bcast}} -->
The `fd_eth_mac_bcast` function populates a 6-byte memory region with the Ethernet MAC address for LAN broadcast.
- **Inputs**:
    - `mac`: A pointer to a 6-byte memory region where the broadcast MAC address will be stored.
- **Control Flow**:
    - The function uses the `FD_STORE` macro to store the value `0xffffffffU` into the first 4 bytes of the memory region pointed to by `mac`.
    - It then stores the value `0xffff` into the next 2 bytes of the memory region, completing the 6-byte broadcast MAC address.
    - Finally, the function returns the pointer `mac`.
- **Output**: A pointer to the 6-byte memory region containing the broadcast MAC address.


---
### fd\_eth\_mac\_cpy<!-- {{#callable:fd_eth_mac_cpy}} -->
The `fd_eth_mac_cpy` function copies a 6-byte MAC address from a source to a destination memory location.
- **Inputs**:
    - `mac`: A pointer to the destination memory location where the MAC address will be copied.
    - `_mac`: A pointer to the source memory location containing the MAC address to be copied.
- **Control Flow**:
    - The function uses `FD_LOAD` to read a 4-byte integer from the source MAC address and stores it at the destination using `FD_STORE`.
    - It then reads a 2-byte short from the source MAC address (offset by 4 bytes) and stores it at the destination (offset by 4 bytes) using `FD_STORE`.
    - The function returns the pointer to the destination MAC address.
- **Output**: A pointer to the destination memory location (`mac`) where the MAC address has been copied.


---
### fd\_vlan\_tag<!-- {{#callable:fd_vlan_tag}} -->
The `fd_vlan_tag` function initializes a VLAN tag structure with a given VLAN ID and type, converting them to network byte order.
- **Inputs**:
    - `_tag`: A pointer to a memory region where the VLAN tag will be stored.
    - `vid`: A 12-bit VLAN ID in host byte order, assumed to be in the range [0, 4095].
    - `type`: A 16-bit type indicating what follows this tag, in host byte order.
- **Control Flow**:
    - Cast the input pointer `_tag` to a `fd_vlan_tag_t` pointer named `tag`.
    - Convert the VLAN ID `vid` from host byte order to network byte order using `fd_ushort_bswap` and store it in `tag->net_vid`.
    - Convert the type `type` from host byte order to network byte order using `fd_ushort_bswap` and store it in `tag->net_type`.
    - Return the pointer `tag`.
- **Output**: A pointer to the initialized `fd_vlan_tag_t` structure.


# Function Declarations (Public API)

---
### fd\_eth\_fcs\_append<!-- {{#callable_declaration:fd_eth_fcs_append}} -->
Computes or updates the Frame Check Sequence (FCS) for an Ethernet frame.
- **Description**: Use this function to compute or incrementally update the FCS of an Ethernet frame, which is a CRC32 checksum used to verify data integrity. This function is useful when you need to manually compute or validate an Ethernet FCS, especially in scenarios where hardware does not automatically handle FCS. It can be used to process data in parts, allowing for incremental FCS calculation. Ensure that the buffer provided is valid and that the size accurately reflects the number of bytes to process.
- **Inputs**:
    - `seed`: An initial FCS value to start the calculation. Typically, this is set to FD_ETH_FCS_APPEND_SEED for a new calculation.
    - `buf`: A pointer to the buffer containing the data for which the FCS is to be computed. Must not be null and should point to a valid memory region.
    - `sz`: The size of the buffer in bytes. Must accurately reflect the number of bytes to process.
- **Output**: Returns the computed FCS as an unsigned integer, which can be used to verify the integrity of the Ethernet frame.
- **See also**: [`fd_eth_fcs_append`](fd_eth.c.driver.md#fd_eth_fcs_append)  (Implementation)


---
### fd\_cstr\_to\_mac\_addr<!-- {{#callable_declaration:fd_cstr_to_mac_addr}} -->
Parses a MAC address from a string and stores it in a byte array.
- **Description**: Use this function to convert a MAC address represented as a string in the format "XX:XX:XX:XX:XX:XX" into a 6-byte array. This function is useful when you need to work with MAC addresses in a binary format, such as when configuring network interfaces or processing network packets. The input string must be exactly 17 characters long, with each byte represented by two hexadecimal digits separated by colons. The function returns the byte array on success or NULL if the input string is malformed or if either input parameter is NULL.
- **Inputs**:
    - `s`: A pointer to a null-terminated string representing the MAC address in the format "XX:XX:XX:XX:XX:XX". The string must be exactly 17 characters long, including colons. Must not be null.
    - `mac`: A pointer to a 6-byte array where the parsed MAC address will be stored. Must not be null. The array is left in an undefined state if the function fails.
- **Output**: Returns a pointer to the mac array on success, or NULL if the input string is invalid or if either input parameter is NULL.
- **See also**: [`fd_cstr_to_mac_addr`](fd_eth.c.driver.md#fd_cstr_to_mac_addr)  (Implementation)



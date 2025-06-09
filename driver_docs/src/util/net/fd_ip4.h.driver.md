# Purpose
This C header file, `fd_ip4.h`, provides a comprehensive set of definitions and functions for handling IPv4 (Internet Protocol version 4) headers. It is designed to be included in other C source files to facilitate the manipulation and analysis of IPv4 packet headers. The file defines a union `fd_ip4_hdr` that represents the structure of an IPv4 header, including fields such as version, header length, type of service, total length, identification, fragment offset, time to live, protocol, checksum, and source and destination addresses. The file also includes macros for constructing and formatting IPv4 addresses, as well as for extracting and setting various fields within the IPv4 header.

Additionally, the file provides inline functions for checking the validity of IPv4 addresses, such as whether an address is multicast or broadcast, and for computing and validating the checksum of an IPv4 header. It also includes functions for parsing IPv4 addresses from strings and determining if an address is public or private. The header file is intended to be a utility for network programming, offering a focused set of tools for IPv4 packet manipulation, and does not define a public API or external interface beyond the functions and macros it provides for internal use in network-related applications.
# Imports and Dependencies

---
- `../bits/fd_bits.h`


# Data Structures

---
### fd\_ip4\_hdr
- **Type**: `union`
- **Members**:
    - `verihl`: Contains the IP version and header length in words.
    - `tos`: Specifies the type of service.
    - `net_tot_len`: Total length of the fragment in bytes, including the IP header, in network byte order.
    - `net_id`: Fragment identifier, unique from the sender for a sufficient duration, in network byte order.
    - `net_frag_off`: Fragment offset and status, in network byte order.
    - `ttl`: Time to live for the fragment.
    - `protocol`: Indicates the type of payload.
    - `check`: Header checksum in invariant order.
    - `saddr_c`: Sender's address as a 4-byte array, technically in network order.
    - `saddr`: Sender's address as a 32-bit integer.
    - `daddr_c`: Destination's address as a 4-byte array, technically in network order.
    - `daddr`: Destination's address as a 32-bit integer.
- **Description**: The `fd_ip4_hdr` union represents an IPv4 header structure, encapsulating various fields necessary for IP packet processing. It includes fields for version and header length, type of service, total length, identification, fragment offset, time to live, protocol, and checksum. Additionally, it contains sender and destination addresses, which can be accessed as either 4-byte arrays or 32-bit integers. This structure is designed to handle the essential components of an IPv4 packet header, facilitating network communication and packet management.


---
### fd\_ip4\_hdr\_t
- **Type**: `union`
- **Members**:
    - `verihl`: Contains the IP version and header length in a single byte.
    - `tos`: Specifies the type of service for the packet.
    - `net_tot_len`: Total length of the packet in bytes, including the header, in network byte order.
    - `net_id`: Unique identifier for the packet, in network byte order.
    - `net_frag_off`: Fragment offset and flags, in network byte order.
    - `ttl`: Time to live for the packet, indicating its remaining lifespan.
    - `protocol`: Specifies the protocol of the payload.
    - `check`: Checksum for the header to ensure data integrity.
    - `saddr_c`: Sender's IP address as a 4-byte array, in network byte order.
    - `saddr`: Sender's IP address as a 32-bit integer.
    - `daddr_c`: Destination's IP address as a 4-byte array, in network byte order.
    - `daddr`: Destination's IP address as a 32-bit integer.
- **Description**: The `fd_ip4_hdr_t` is a union representing an IPv4 header, encapsulating various fields necessary for packet routing and delivery in an IP network. It includes fields for version and header length, type of service, total length, identification, fragment offset, time to live, protocol, checksum, and both source and destination addresses. The structure is designed to handle network byte order and provides flexibility for accessing IP addresses either as byte arrays or integers. This union is crucial for managing and manipulating IPv4 packet headers in network programming.


# Functions

---
### fd\_ip4\_addr\_is\_mcast<!-- {{#callable:fd_ip4_addr_is_mcast}} -->
The function `fd_ip4_addr_is_mcast` checks if a given IPv4 address is a multicast address.
- **Inputs**:
    - `addr`: An unsigned integer representing an IPv4 address.
- **Control Flow**:
    - The function casts the input address to an unsigned char and right shifts it by 4 bits.
    - It then compares the result to the hexadecimal value 0xe, which corresponds to the range of multicast addresses (224.0.0.0 to 239.255.255.255).
    - If the comparison is true, the function returns 1, indicating the address is multicast; otherwise, it returns 0.
- **Output**: The function returns 1 if the address is a multicast address, and 0 otherwise.


---
### fd\_ip4\_addr\_is\_bcast<!-- {{#callable:fd_ip4_addr_is_bcast}} -->
The function `fd_ip4_addr_is_bcast` checks if a given IPv4 address is the global broadcast address (255.255.255.255).
- **Inputs**:
    - `addr`: An unsigned integer representing an IPv4 address in network byte order.
- **Control Flow**:
    - The function compares the input address `addr` to the bitwise NOT of 0 (`~0U`), which represents the global broadcast address 255.255.255.255.
    - If the address matches, the function returns 1, indicating it is a broadcast address.
    - If the address does not match, the function returns 0, indicating it is not a broadcast address.
- **Output**: An integer value, 1 if the address is the global broadcast address, otherwise 0.


---
### fd\_ip4\_hdr\_net\_frag\_off\_is\_unfragmented<!-- {{#callable:fd_ip4_hdr_net_frag_off_is_unfragmented}} -->
The function `fd_ip4_hdr_net_frag_off_is_unfragmented` checks if an IPv4 packet is unfragmented based on its fragment offset field.
- **Inputs**:
    - `net_frag_off`: A 16-bit unsigned short integer representing the fragment offset field of an IPv4 header in network byte order.
- **Control Flow**:
    - The function casts the input `net_frag_off` to a 32-bit unsigned integer.
    - It performs a bitwise AND operation with the constant `0xff3fU`, which is a combination of the fragment offset mask and the 'more fragments' flag in network byte order.
    - The result of the bitwise operation is negated and returned as an integer, indicating whether the packet is unfragmented.
- **Output**: Returns an integer value of 1 if the packet is unfragmented (i.e., the fragment offset and 'more fragments' flag are both zero), and 0 otherwise.


---
### fd\_ip4\_hdr\_check<!-- {{#callable:fd_ip4_hdr_check}} -->
The `fd_ip4_hdr_check` function calculates and validates the checksum of an IPv4 header.
- **Inputs**:
    - `vp_hdr`: A pointer to the memory region containing the IPv4 header and any options that might follow it.
- **Control Flow**:
    - The function casts the input pointer `vp_hdr` to a `uchar` pointer `cp`.
    - It extracts the header length `n` from the first byte of the header, which is the lower 4 bits of `verihl`.
    - If `n` is less than 5, the function assumes an unreachable state, as a valid IPv4 header must be at least 5 words long.
    - It initializes a checksum accumulator `c` to zero.
    - The function iterates over each 4-byte word in the header, up to `n` words, copying each word into a temporary variable `u` and adding it to the checksum accumulator `c`.
    - The checksum is then folded by adding the upper 16 bits to the lower 16 bits repeatedly until only 16 bits remain.
    - The function returns the bitwise negation of the final checksum value as a `ushort`.
- **Output**: The function returns a `ushort` representing the calculated checksum for the IPv4 header, or zero if the header's checksum is valid.


---
### fd\_ip4\_hdr\_check\_fast<!-- {{#callable:fd_ip4_hdr_check_fast}} -->
The `fd_ip4_hdr_check_fast` function calculates the checksum of an IPv4 header assuming no options are present (header length is 5 words).
- **Inputs**:
    - `vp_hdr`: A pointer to the IPv4 header to be checked, assumed to be a memory region containing the header and any options.
- **Control Flow**:
    - Cast the input pointer `vp_hdr` to a `uchar` pointer `cp`.
    - Extract the header length `n` from the first byte of the header, specifically the lower 4 bits.
    - Check if `n` is not equal to 5; if so, call [`fd_ip4_hdr_check`](#fd_ip4_hdr_check) for a more general checksum calculation and return its result.
    - Initialize a variable `c` to accumulate the checksum.
    - Iterate over the header words (5 times, since `n` is 5), copying each 4-byte word into a temporary variable `u` and adding it to `c`.
    - Perform a series of bitwise operations and additions to reduce `c` to a 16-bit checksum.
    - Return the bitwise negation of `c` as the checksum.
- **Output**: Returns a 16-bit unsigned short representing the checksum of the IPv4 header.
- **Functions called**:
    - [`fd_ip4_hdr_check`](#fd_ip4_hdr_check)


---
### fd\_ip4\_addr\_is\_public<!-- {{#callable:fd_ip4_addr_is_public}} -->
The `fd_ip4_addr_is_public` function checks if a given IPv4 address is a public address by determining if it falls outside of private and loopback address ranges.
- **Inputs**:
    - `addr`: A 32-bit unsigned integer representing an IPv4 address in network byte order.
- **Control Flow**:
    - Convert the input address from network byte order to host byte order using `fd_uint_bswap`.
    - Check if the converted address falls within any of the predefined private or loopback address ranges by comparing it against the start and end of each range, also converted to host byte order.
    - Return 0 if the address is within any of these ranges, indicating it is not a public address.
    - Return 1 if the address is outside all these ranges, indicating it is a public address.
- **Output**: Returns an integer: 1 if the address is public, 0 if it is private or a loopback address.


---
### fd\_ip4\_hdr\_bswap<!-- {{#callable:fd_ip4_hdr_bswap}} -->
The `fd_ip4_hdr_bswap` function reverses the byte order of specific fields in an IPv4 header structure to convert between network and host byte order.
- **Inputs**:
    - `hdr`: A pointer to an `fd_ip4_hdr_t` structure representing the IPv4 header whose fields need byte order swapping.
- **Control Flow**:
    - The function takes a pointer to an `fd_ip4_hdr_t` structure as input.
    - It swaps the byte order of the `net_tot_len` field using `fd_ushort_bswap`.
    - It swaps the byte order of the `net_id` field using `fd_ushort_bswap`.
    - It swaps the byte order of the `net_frag_off` field using `fd_ushort_bswap`.
    - It swaps the byte order of the `check` field using `fd_ushort_bswap`.
- **Output**: The function does not return a value; it modifies the input `fd_ip4_hdr_t` structure in place.


# Function Declarations (Public API)

---
### fd\_cstr\_to\_ip4\_addr<!-- {{#callable_declaration:fd_cstr_to_ip4_addr}} -->
Parses a string representation of an IPv4 address into a numeric format.
- **Description**: Use this function to convert a string containing an IPv4 address in the format 'x.x.x.x' into a numeric representation suitable for network operations. The function expects the input string to be a valid IPv4 address and will store the result in network byte order. It returns a success indicator, allowing you to verify if the conversion was successful. This function is useful when dealing with user input or configuration files where IP addresses are stored as strings.
- **Inputs**:
    - `s`: A pointer to a null-terminated string representing an IPv4 address in the format 'x.x.x.x'. The string must not exceed 15 characters, including the null terminator. The caller retains ownership and must ensure the string is valid and properly formatted.
    - `out`: A pointer to an unsigned integer where the converted IPv4 address will be stored in network byte order. Must not be null. The function writes to this location only if the conversion is successful.
- **Output**: Returns 1 if the conversion is successful and 0 if it fails due to an invalid format or out-of-range values.
- **See also**: [`fd_cstr_to_ip4_addr`](fd_ip4.c.driver.md#fd_cstr_to_ip4_addr)  (Implementation)



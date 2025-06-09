# Purpose
This C header file, `fd_pcap.h`, provides a set of functions and definitions for handling PCAP (Packet Capture) files, which are commonly used for capturing and analyzing network traffic. The file defines an opaque structure `fd_pcap_iter_t` for iterating over packets in a PCAP file, allowing users to read and process network packets sequentially. The primary functions include `fd_pcap_iter_new` for creating a new iterator, [`fd_pcap_iter_next`](#fd_pcap_iter_next) and [`fd_pcap_iter_next_split`](#fd_pcap_iter_next_split) for extracting packets from the PCAP stream, and [`fd_pcap_iter_delete`](#fd_pcap_iter_delete) for cleaning up the iterator. Additionally, the file provides functions for writing PCAP headers and packets to a file, such as [`fd_pcap_fwrite_hdr`](#fd_pcap_fwrite_hdr) and [`fd_pcap_fwrite_pkt`](#fd_pcap_fwrite_pkt), which facilitate the creation of PCAP files with specified link layer types and packet data.

The header file is designed to be included in other C source files, providing a public API for PCAP file manipulation. It includes constants for different types of PCAP iterators and link layer types, ensuring compatibility with various network protocols. The functions are designed to handle errors gracefully, logging warnings for issues like file corruption or truncated packets. This file is part of a broader utility library, as indicated by its inclusion of other headers like `fd_log.h` and `fd_eth.h`, which suggests its integration with logging and Ethernet-related functionalities. Overall, `fd_pcap.h` offers a focused and efficient interface for developers working with network packet capture and analysis in C.
# Imports and Dependencies

---
- `../log/fd_log.h`
- `fd_eth.h`


# Data Structures

---
### fd\_pcap\_iter\_t
- **Type**: `struct`
- **Description**: The `fd_pcap_iter_t` is an opaque data structure used as a handle for iterating over packets in a pcap file. It is designed to manage the state of the iteration process, allowing functions to read packets sequentially from a pcap file stream. The structure itself is not directly accessible, emphasizing its role as an abstraction layer for pcap file operations, such as reading packet data and managing the underlying file stream.


# Functions

---
### fd\_pcap\_iter\_file<!-- {{#callable:fd_pcap_iter_file}} -->
The `fd_pcap_iter_file` function extracts the file stream from a pcap iterator by masking out the least significant bit of the iterator pointer.
- **Inputs**:
    - `iter`: A pointer to a `fd_pcap_iter_t` structure, representing the pcap iterator from which the file stream is to be extracted.
- **Control Flow**:
    - The function takes the `iter` pointer, casts it to an unsigned long integer, and performs a bitwise AND operation with the complement of 1 (i.e., `~1UL`) to mask out the least significant bit.
    - The result of the bitwise operation is then cast back to a `void *` pointer, effectively returning the file stream associated with the iterator.
- **Output**: The function returns a `void *` pointer to the file stream associated with the pcap iterator, with the least significant bit masked out.


---
### fd\_pcap\_iter\_type<!-- {{#callable:fd_pcap_iter_type}} -->
The `fd_pcap_iter_type` function returns the type of a pcap iterator, indicating whether it is an Ethernet or cooked capture.
- **Inputs**:
    - `iter`: A pointer to an `fd_pcap_iter_t` structure, representing the pcap iterator whose type is to be determined.
- **Control Flow**:
    - The function takes the `iter` pointer, casts it to an unsigned long, and performs a bitwise AND operation with `1UL`.
    - The result of the bitwise operation is returned, which will be either `0UL` or `1UL`.
- **Output**: The function returns an `ulong` value, which is `0UL` for Ethernet type and `1UL` for cooked type, based on the least significant bit of the `iter` pointer.


---
### fd\_pcap\_iter\_delete<!-- {{#callable:fd_pcap_iter_delete}} -->
The `fd_pcap_iter_delete` function destroys a pcap iterator and returns the handle of the underlying file stream.
- **Inputs**:
    - `iter`: A pointer to an `fd_pcap_iter_t` structure representing the pcap iterator to be deleted.
- **Control Flow**:
    - The function calls [`fd_pcap_iter_file`](#fd_pcap_iter_file) with the `iter` argument to retrieve the file stream associated with the iterator.
    - The function returns the file stream obtained from [`fd_pcap_iter_file`](#fd_pcap_iter_file).
- **Output**: The function returns a `void *` which is the handle of the underlying file stream associated with the pcap iterator.
- **Functions called**:
    - [`fd_pcap_iter_file`](#fd_pcap_iter_file)


# Function Declarations (Public API)

---
### fd\_pcap\_iter\_next<!-- {{#callable_declaration:fd_pcap_iter_next}} -->
Extracts the next packet from a pcap stream.
- **Description**: Use this function to retrieve the next packet from a pcap file stream using an iterator. It should be called with a valid iterator that has been initialized with a pcap file. The function reads the packet data into a provided buffer and updates a timestamp variable with the packet's capture time. It returns the size of the packet on success or 0 on failure, which can occur due to end-of-file, read errors, file corruption, or if the packet size exceeds the provided buffer size. The function logs warnings for all failures except normal end-of-file. On success, the packet data is stored in the provided buffer, and the timestamp is updated. On failure, the buffer and timestamp remain unchanged, and the stream may consume an indeterminate number of bytes.
- **Inputs**:
    - `iter`: A pointer to an fd_pcap_iter_t, representing the pcap file iterator. Must be a valid, initialized iterator. The iterator's underlying stream is advanced on success.
    - `pkt`: A pointer to a memory buffer where the packet data will be stored. The buffer must be large enough to hold the packet data, up to pkt_max bytes.
    - `pkt_max`: The maximum number of bytes that can be written to the pkt buffer. If the packet size exceeds this value, the function fails and returns 0.
    - `_pkt_ts`: A pointer to a long where the packet's timestamp will be stored on success. Must not be null.
- **Output**: Returns the size of the packet in bytes on success, or 0 on failure. On success, the packet data is written to the pkt buffer, and the timestamp is updated. On failure, the pkt buffer and timestamp remain unchanged.
- **See also**: [`fd_pcap_iter_next`](fd_pcap.c.driver.md#fd_pcap_iter_next)  (Implementation)


---
### fd\_pcap\_iter\_next\_split<!-- {{#callable_declaration:fd_pcap_iter_next_split}} -->
Extracts the next packet from a pcap stream into separate header and payload buffers.
- **Description**: This function is used to iterate over packets in a pcap file, extracting each packet's headers and payload into separate buffers. It should be called with a valid pcap iterator that has been initialized with a pcap file. The function returns 1 on success and 0 on failure, with failure reasons including end-of-file, read errors, file corruption, or insufficient buffer sizes. On success, the header and payload buffers are populated with the packet's data, and the packet's timestamp is updated. On failure, the buffers may be partially written, and the iterator's stream position may be indeterminate.
- **Inputs**:
    - `iter`: A pointer to a valid fd_pcap_iter_t, representing the current position in the pcap file. Must not be null.
    - `hdr_buf`: A pointer to a writable memory region where the packet headers will be stored. The size of this region is specified by *hdr_sz.
    - `hdr_sz`: A pointer to an ulong that specifies the size of hdr_buf. On success, it is updated with the number of bytes written to hdr_buf.
    - `pld_buf`: A pointer to a writable memory region where the packet payload will be stored. The size of this region is specified by *pld_sz.
    - `pld_sz`: A pointer to an ulong that specifies the size of pld_buf. On success, it is updated with the number of bytes written to pld_buf.
    - `_pkt_ts`: A pointer to a long where the packet's timestamp will be stored on success. Must not be null.
- **Output**: Returns 1 on success, with hdr_buf and pld_buf containing the packet's headers and payload, respectively, and *_pkt_ts updated with the packet's timestamp. Returns 0 on failure, with potential partial writes to hdr_buf and pld_buf.
- **See also**: [`fd_pcap_iter_next_split`](fd_pcap.c.driver.md#fd_pcap_iter_next_split)  (Implementation)


---
### fd\_pcap\_fwrite\_hdr<!-- {{#callable_declaration:fd_pcap_fwrite_hdr}} -->
Write a PCAP file header to a specified file stream.
- **Description**: This function writes a little-endian PCAP file header, version 2.4, to the provided file stream. It should be used when initializing a PCAP file to ensure the file begins with the correct header format. The function requires a valid file stream pointer and a link layer type, which should be one of the predefined FD_PCAP_LINK_LAYER_* values. It returns the number of headers written, which should be 1 on success. If the function fails, it returns 0, indicating that the header was not written.
- **Inputs**:
    - `file`: A pointer to a file stream where the PCAP header will be written. This must be a valid, open file stream, and the caller retains ownership. The function will cast this to a FILE pointer internally.
    - `link_layer_type`: An unsigned integer representing the link layer type for the PCAP file. It should be one of the FD_PCAP_LINK_LAYER_* constants, such as FD_PCAP_LINK_LAYER_ETHERNET or FD_PCAP_LINK_LAYER_USER0. Invalid values may result in undefined behavior.
- **Output**: Returns the number of headers written, which is 1 on success and 0 on failure.
- **See also**: [`fd_pcap_fwrite_hdr`](fd_pcap.c.driver.md#fd_pcap_fwrite_hdr)  (Implementation)


---
### fd\_pcap\_fwrite\_pkt<!-- {{#callable_declaration:fd_pcap_fwrite_pkt}} -->
Writes a pcap Ethernet frame to a file stream.
- **Description**: This function is used to write a pcap Ethernet frame, composed of a header, payload, and frame check sequence (FCS), to a specified file stream. It should be called when you need to log network packets in pcap format with nanosecond timestamp resolution. The function expects the header to start at the first byte of the Ethernet header and the payload to end at the last byte of the Ethernet payload. It returns the number of packets written, which is 1 on success and 0 on failure, with failure details logged. Ensure that the total packet size does not exceed the maximum allowed by the pcap format.
- **Inputs**:
    - `ts`: The timestamp for the packet, in nanoseconds. It is used to record when the packet was captured.
    - `_hdr`: A pointer to the packet header data. Must not be null and should point to the first byte of the Ethernet header.
    - `hdr_sz`: The size of the header in bytes. Must be a valid size that, when combined with payload_sz, does not exceed the maximum packet size allowed by the pcap format.
    - `_payload`: A pointer to the packet payload data. Must not be null and should point to the first byte of the Ethernet payload.
    - `payload_sz`: The size of the payload in bytes. Must be a valid size that, when combined with hdr_sz, does not exceed the maximum packet size allowed by the pcap format.
    - `_fcs`: The frame check sequence (FCS) for the packet. It is appended to the packet data.
    - `file`: A pointer to the file stream where the packet will be written. Must not be null and should be a valid, open file stream.
- **Output**: Returns 1 on successful write of the packet to the file stream, and 0 on failure, with failure details logged.
- **See also**: [`fd_pcap_fwrite_pkt`](fd_pcap.c.driver.md#fd_pcap_fwrite_pkt)  (Implementation)



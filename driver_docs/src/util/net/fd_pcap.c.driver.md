# Purpose
This C source code file provides functionality for reading and writing packet capture (PCAP) files, which are commonly used for network traffic analysis. The code defines structures and functions to handle PCAP file headers and packet headers, allowing for the iteration over packets within a PCAP file. The primary functions include [`fd_pcap_iter_new`](#fd_pcap_iter_new), which initializes a new iterator for reading packets from a PCAP file, [`fd_pcap_iter_next`](#fd_pcap_iter_next), which retrieves the next packet from the file, and [`fd_pcap_iter_next_split`](#fd_pcap_iter_next_split), which separates the packet header and payload for more detailed processing. Additionally, the file includes functions for writing PCAP headers and packets to a file, such as [`fd_pcap_fwrite_hdr`](#fd_pcap_fwrite_hdr) and [`fd_pcap_fwrite_pkt`](#fd_pcap_fwrite_pkt).

The code is structured to handle both Ethernet and Linux cooked capture (SLL) network types, as indicated by the defined constants and conditional logic. It includes error handling and logging to manage issues such as file misalignment, unsupported network types, and truncated packets. The file is intended to be part of a larger library or application, as it includes headers like "fd_pcap.h", "fd_ip4.h", and "fd_udp.h", suggesting integration with other components for network protocol handling. The code is designed to be compiled and run in environments where the `FD_HAS_HOSTED` macro is defined, indicating that it is meant for hosted environments with standard I/O capabilities.
# Imports and Dependencies

---
- `fd_pcap.h`
- `fd_ip4.h`
- `fd_udp.h`
- `stdio.h`
- `errno.h`


# Data Structures

---
### fd\_pcap\_hdr
- **Type**: `struct`
- **Members**:
    - `magic_number`: A unique identifier for the file format, used to detect the endianness of the file.
    - `version_major`: The major version number of the pcap file format.
    - `version_minor`: The minor version number of the pcap file format.
    - `thiszone`: The correction time in seconds between GMT (UTC) and the local timezone of the capture.
    - `sigfigs`: The accuracy of timestamps in the capture file.
    - `snaplen`: The maximum length of captured packets, in bytes.
    - `network`: The data link type of the capture, indicating the type of network.
- **Description**: The `fd_pcap_hdr` structure is used to represent the global header of a pcap file, which is a common format for storing network packet capture data. This header contains metadata about the capture file, including the file format version, timezone information, timestamp accuracy, maximum packet length, and the type of network on which the capture was performed. The `magic_number` field is particularly important as it helps in identifying the file format and determining the byte order of the file. The `network` field specifies the data link type, which is crucial for interpreting the packet data correctly.


---
### fd\_pcap\_hdr\_t
- **Type**: `struct`
- **Members**:
    - `magic_number`: A 32-bit unsigned integer used to identify the file format.
    - `version_major`: A 16-bit unsigned integer representing the major version number of the file format.
    - `version_minor`: A 16-bit unsigned integer representing the minor version number of the file format.
    - `thiszone`: A 32-bit signed integer indicating the correction time in seconds between GMT and the local timezone of the capture.
    - `sigfigs`: A 32-bit unsigned integer for the accuracy of timestamps in the capture.
    - `snaplen`: A 32-bit unsigned integer specifying the maximum length of captured packets.
    - `network`: A 32-bit unsigned integer indicating the data link type of the capture.
- **Description**: The `fd_pcap_hdr_t` structure is used to represent the global header of a PCAP file, which contains metadata about the capture file such as the file format version, timezone information, and the type of network on which the capture was made. This header is crucial for interpreting the rest of the data in the PCAP file, as it provides the necessary context for understanding the captured packets.


---
### fd\_pcap\_pkt\_hdr
- **Type**: `struct`
- **Members**:
    - `sec`: Stores the seconds part of the timestamp in host byte order.
    - `usec`: Stores the microseconds part of the timestamp in host byte order, assuming nanosecond capture.
    - `incl_len`: Indicates the number of bytes of packet data actually captured and stored in host byte order.
    - `orig_len`: Represents the original length of the packet before any truncation, in host byte order.
- **Description**: The `fd_pcap_pkt_hdr` structure is used to represent the header of a packet in a pcap (packet capture) file. It contains timestamp information, with seconds and microseconds fields, to record when the packet was captured. Additionally, it includes fields for the length of the packet data that was captured (`incl_len`) and the original length of the packet (`orig_len`) before any truncation occurred. This structure is crucial for processing and analyzing network traffic data captured in pcap format.


---
### fd\_pcap\_pkt\_hdr\_t
- **Type**: `struct`
- **Members**:
    - `sec`: Stores the seconds part of the timestamp in host order.
    - `usec`: Stores the microseconds part of the timestamp in host order, assuming a nanosecond capture.
    - `incl_len`: Indicates the number of bytes of packet data actually captured and saved in the file, in host order.
    - `orig_len`: Represents the original length of the packet before any truncation, in host order.
- **Description**: The `fd_pcap_pkt_hdr_t` structure is used to represent the header of a packet in a pcap file, capturing essential metadata about the packet such as its timestamp and length. It includes fields for the seconds and microseconds of the packet's timestamp, as well as the length of the packet data that was captured and the original length of the packet. This structure is crucial for reading and writing packet data in pcap files, allowing for accurate reconstruction and analysis of network traffic.


---
### fd\_pcap\_sll\_hdr\_t
- **Type**: `struct`
- **Members**:
    - `dir`: Represents the direction of the packet.
    - `ha_type`: Specifies the hardware address type.
    - `ha_len`: Indicates the length of the hardware address.
    - `ha`: An array of 8 unsigned characters representing the hardware address.
    - `net_type`: Denotes the network type.
- **Description**: The `fd_pcap_sll_hdr_t` structure is used to represent the header of a packet captured in a Linux cooked-mode capture (SLL) format. It contains fields for the direction of the packet, the type and length of the hardware address, the hardware address itself, and the network type. This structure is typically used in packet capture and analysis applications to interpret the metadata associated with packets captured in a cooked-mode format.


# Functions

---
### fd\_pcap\_iter\_new<!-- {{#callable:fd_pcap_iter_new}} -->
The `fd_pcap_iter_new` function initializes a new pcap iterator for reading packets from a pcap file, ensuring the file is valid and supported.
- **Inputs**:
    - `_file`: A pointer to a file object, expected to be a pcap file, which is cast to a `FILE *` type.
- **Control Flow**:
    - Cast the input `_file` to a `FILE *` type.
    - Check if the file pointer is NULL and log a warning if it is, returning NULL.
    - Check if the file pointer is aligned to a 2-byte boundary and log a warning if it is not, returning NULL.
    - Read the pcap file header into a `fd_pcap_hdr_t` structure and log a warning if reading fails, returning NULL.
    - Verify the magic number in the pcap header to ensure it is a supported pcap file format, logging a warning and returning NULL if it is not.
    - Check the network type in the pcap header to ensure it is either Ethernet or Linux cooked socket, logging a warning and returning NULL if it is not.
    - Determine if the file is a cooked socket pcap by checking the network type and set a flag accordingly.
    - Return a pointer to the pcap iterator, encoding the cooked flag in the pointer.
- **Output**: A pointer to an `fd_pcap_iter_t` structure, which is a pcap iterator, or NULL if any validation checks fail.


---
### fd\_pcap\_iter\_next<!-- {{#callable:fd_pcap_iter_next}} -->
The `fd_pcap_iter_next` function reads the next packet from a pcap file, processes it, and stores it in a provided buffer while also returning the packet size and timestamp.
- **Inputs**:
    - `iter`: A pointer to an `fd_pcap_iter_t` structure, which represents the current state of the pcap file iteration.
    - `pkt`: A pointer to a buffer where the packet data will be stored.
    - `pkt_max`: The maximum size of the packet that can be stored in the `pkt` buffer.
    - `_pkt_ts`: A pointer to a long where the timestamp of the packet will be stored.
- **Control Flow**:
    - Retrieve the file pointer and cooked flag from the iterator.
    - Read the packet header from the file; if unsuccessful, log a warning and return 0.
    - Check if the packet size matches the original length; if not, log a warning and return 0.
    - Determine the header size based on whether the packet is cooked or not.
    - Check if the packet size is less than the header size or greater than `pkt_max`; if so, log a warning and return 0.
    - If the packet is cooked, read the SLL header, construct an Ethernet-compatible header, and adjust the packet size.
    - If the packet is not cooked, read the Ethernet header directly.
    - Read the remaining packet payload into the buffer.
    - Calculate the packet timestamp and store it in `_pkt_ts`.
    - Return the size of the packet.
- **Output**: The function returns the size of the packet read, or 0 if an error occurs.
- **Functions called**:
    - [`fd_pcap_iter_file`](fd_pcap.h.driver.md#fd_pcap_iter_file)
    - [`fd_pcap_iter_type`](fd_pcap.h.driver.md#fd_pcap_iter_type)


---
### fd\_pcap\_iter\_next\_split<!-- {{#callable:fd_pcap_iter_next_split}} -->
The `fd_pcap_iter_next_split` function reads the next packet from a pcap file, splits it into header and payload, and stores them in provided buffers while updating their sizes and the packet timestamp.
- **Inputs**:
    - `iter`: A pointer to an `fd_pcap_iter_t` structure representing the current state of the pcap file iteration.
    - `hdr_buf`: A pointer to a buffer where the packet header will be stored.
    - `hdr_sz`: A pointer to an `ulong` that initially contains the size of the `hdr_buf` and will be updated with the actual size of the header read.
    - `pld_buf`: A pointer to a buffer where the packet payload will be stored.
    - `pld_sz`: A pointer to an `ulong` that initially contains the size of the `pld_buf` and will be updated with the actual size of the payload read.
    - `_pkt_ts`: A pointer to a `long` where the timestamp of the packet will be stored.
- **Control Flow**:
    - Retrieve the file and cooked status from the iterator.
    - Read the packet header from the file and check for errors or end-of-file conditions.
    - Verify the packet length and check for truncation or corruption.
    - Determine the size of the pcap header based on whether the file is cooked or not.
    - Check if the packet size exceeds the combined buffer sizes and if the header buffer is large enough for an Ethernet header.
    - If the file is cooked, read the SLL header and construct an Ethernet-compatible header; otherwise, read the Ethernet header directly.
    - Adjust the remaining packet size and header buffer pointer after reading the Ethernet header.
    - Process any VLAN tags by reading them and updating the header buffer and remaining sizes.
    - If the packet is an IP packet, read the IP header and any options, updating the header buffer and remaining sizes.
    - If the packet is a UDP packet, read the UDP header, updating the header buffer and remaining sizes.
    - Check if the payload buffer is large enough for the remaining packet data.
    - Read the payload into the payload buffer and update the payload size.
    - Calculate the packet timestamp from the pcap header and store it in `_pkt_ts`.
    - Return 1 to indicate successful reading and processing of the packet.
- **Output**: Returns 1 on successful reading and processing of the packet, or 0 if an error occurs.
- **Functions called**:
    - [`fd_pcap_iter_file`](fd_pcap.h.driver.md#fd_pcap_iter_file)
    - [`fd_pcap_iter_type`](fd_pcap.h.driver.md#fd_pcap_iter_type)


---
### fd\_pcap\_fwrite\_hdr<!-- {{#callable:fd_pcap_fwrite_hdr}} -->
The `fd_pcap_fwrite_hdr` function writes a PCAP file header to a specified file stream with a given link layer type.
- **Inputs**:
    - `file`: A pointer to a file stream where the PCAP header will be written.
    - `link_layer_type`: An unsigned integer representing the type of link layer for the network data.
- **Control Flow**:
    - Initialize a `fd_pcap_hdr_t` structure with predefined values for magic number, version, timezone, significant figures, and snap length.
    - Set the network field of the header to the provided `link_layer_type`.
    - Use the `fwrite` function to write the initialized header structure to the specified file stream.
- **Output**: Returns the number of elements successfully written, which should be 1 if the header is written successfully.


---
### fd\_pcap\_fwrite\_pkt<!-- {{#callable:fd_pcap_fwrite_pkt}} -->
The `fd_pcap_fwrite_pkt` function writes a packet to a pcap file, including its header, payload, and frame check sequence (FCS).
- **Inputs**:
    - `ts`: A long integer representing the timestamp of the packet in nanoseconds.
    - `_hdr`: A pointer to the packet header data.
    - `hdr_sz`: An unsigned long integer representing the size of the packet header.
    - `_payload`: A pointer to the packet payload data.
    - `payload_sz`: An unsigned long integer representing the size of the packet payload.
    - `_fcs`: An unsigned integer representing the frame check sequence of the packet.
    - `file`: A pointer to a file object where the packet will be written.
- **Control Flow**:
    - Calculate the total packet size by adding the header and payload sizes.
    - Check if the packet size is valid and does not exceed the maximum allowed size for a pcap file; if invalid, log a warning and return 0.
    - Allocate a buffer for the packet data, including space for the pcap packet header and FCS.
    - Set up pointers to the packet header, payload, and FCS within the buffer.
    - Fill in the pcap packet header with the timestamp, included length, and original length of the packet.
    - Copy the header and payload data into the buffer.
    - Set the FCS value in the buffer.
    - Attempt to write the packet buffer to the specified file; if the write fails, log a warning and return 0.
    - Return 1 to indicate success if the packet is written successfully.
- **Output**: Returns an unsigned long integer, 1 if the packet is successfully written to the file, or 0 if an error occurs.



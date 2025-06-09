# Purpose
The provided C code is a specialized library for parsing and pretty-printing QUIC (Quick UDP Internet Connections) protocol packets. It is designed to interpret the structure of QUIC frames and headers, decode them, and output a human-readable JSON representation. The code includes functions to handle different types of QUIC headers, such as initial, handshake, and 1-RTT (one round-trip time) headers, as well as various frame types within the QUIC protocol. The primary function, [`fd_quic_pretty_print_quic_pkt`](#fd_quic_pretty_print_quic_pkt), orchestrates the parsing of a QUIC packet, extracting and formatting its components into a structured JSON format, which is then printed to the console.

The code leverages a series of template-based macros and includes multiple header files to define and handle the various frame types and structures within the QUIC protocol. It uses a combination of decoding functions and pretty-printing functions to convert binary data into a readable format. The code is structured to handle errors gracefully, providing detailed error messages in the JSON output when parsing fails. This library is intended for use in debugging or logging scenarios where understanding the contents of QUIC packets is necessary, and it provides a public API for integrating this functionality into other applications.
# Imports and Dependencies

---
- `templ/fd_quic_pretty_print.h`
- `templ/fd_quic_templ.h`
- `templ/fd_quic_frames_templ.h`
- `templ/fd_quic_undefs.h`
- `fd_quic_private.h`
- `fd_quic_pretty_print.h`
- `templ/fd_quic_dft.h`
- `templ/fd_quic_frame.h`


# Functions

---
### fd\_quic\_pretty\_print\_frame<!-- {{#callable:fd_quic_pretty_print_frame}} -->
The `fd_quic_pretty_print_frame` function parses a QUIC frame from a buffer and formats it into a human-readable JSON string.
- **Inputs**:
    - `out_buf`: A pointer to a character buffer where the formatted JSON string will be written.
    - `out_buf_sz`: A pointer to an unsigned long representing the size of the output buffer.
    - `buf`: A constant pointer to an unsigned character array containing the QUIC frame data to be parsed.
    - `buf_sz`: An unsigned long representing the size of the input buffer containing the QUIC frame data.
- **Control Flow**:
    - Check if the input buffer size is less than 1, returning a parse failure if true.
    - Initialize pointers to the start and end of the input buffer.
    - Check if the frame is a padding or ping frame and count the occurrences, updating the output buffer with this information.
    - Determine the frame ID from the first byte and check if it is valid; if not, return a parse failure.
    - Use a union to store frame-specific data and initialize it to zero.
    - Switch on the frame ID to call the appropriate frame handler function, updating the output buffer with the frame type.
    - If the frame ID is for an ACK frame, handle ACK ranges and ECN counts, updating the output buffer accordingly.
    - For crypto frames, ensure the data size does not exceed the remaining buffer size, and output the data in hexadecimal format.
    - For stream frames, decode optional fields and output stream information, ensuring data size does not exceed the remaining buffer size.
    - For connection close frames, check the reason phrase length and update the buffer pointer accordingly.
- **Output**: Returns the number of bytes consumed from the input buffer, or a parse failure constant if an error occurs.


---
### fd\_quic\_pretty\_print\_quic\_hdr\_initial<!-- {{#callable:fd_quic_pretty_print_quic_hdr_initial}} -->
The function `fd_quic_pretty_print_quic_hdr_initial` decodes and pretty-prints the initial QUIC header from a given buffer into a JSON-like format.
- **Inputs**:
    - `out_buf`: A pointer to a character buffer where the pretty-printed output will be stored.
    - `out_buf_sz`: A pointer to the size of the output buffer, which will be updated as the buffer is filled.
    - `frame_ptr`: A pointer to a location where the function will store the pointer to the start of the frame data within the buffer.
    - `frame_sz`: A pointer to a location where the function will store the size of the frame data.
    - `buf`: A pointer to the input buffer containing the QUIC packet data to be decoded.
    - `buf_sz`: The size of the input buffer.
- **Control Flow**:
    - The function begins by writing the header type 'initial' to the output buffer using `safe_snprintf` and updates the buffer pointers accordingly.
    - It initializes a `fd_quic_initial_t` structure and attempts to decode the initial header from the input buffer using `fd_quic_decode_initial`.
    - If decoding fails, it logs an error, writes an error message to the output buffer, and returns `FD_QUIC_PARSE_FAIL`.
    - If decoding succeeds, it calculates the packet number offset and size, and the payload offset.
    - The packet number is decoded using `fd_quic_pktnum_decode`, and the result is stored in the `initial` structure.
    - The function sets `frame_ptr` to point to the start of the frame data and calculates `frame_sz` as the size of the frame data excluding the packet number and crypto tag size.
    - Finally, it calls `fd_quic_pretty_print_struct_initial` to pretty-print the decoded initial structure into the output buffer.
- **Output**: The function returns the offset to the payload within the buffer, or `FD_QUIC_PARSE_FAIL` if parsing fails.


---
### fd\_quic\_pretty\_print\_quic\_hdr\_handshake<!-- {{#callable:fd_quic_pretty_print_quic_hdr_handshake}} -->
The function `fd_quic_pretty_print_quic_hdr_handshake` decodes and pretty-prints a QUIC handshake header from a given buffer into a JSON-like format.
- **Inputs**:
    - `out_buf`: A pointer to a character buffer where the pretty-printed output will be stored.
    - `out_buf_sz`: A pointer to the size of the output buffer, which will be updated as the buffer is filled.
    - `frame_ptr`: A pointer to a pointer that will be set to the start of the frame data within the buffer.
    - `frame_sz`: A pointer to a variable that will be set to the size of the frame data.
    - `buf`: A constant pointer to the input buffer containing the QUIC handshake header data to be decoded.
    - `buf_sz`: The size of the input buffer.
- **Control Flow**:
    - The function begins by writing the header type 'handshake' to the output buffer using `safe_snprintf` and updates the buffer pointers accordingly.
    - It initializes a `fd_quic_handshake_t` structure and attempts to decode the handshake data from the input buffer using `fd_quic_decode_handshake`.
    - If decoding fails, it logs an error message, writes an error message to the output buffer, and returns `FD_QUIC_PARSE_FAIL`.
    - If decoding succeeds, it calculates the packet number offset and size, and the payload offset.
    - It decodes the packet number from the buffer and updates the handshake structure with this information.
    - The function sets `frame_ptr` to point to the start of the frame data and calculates `frame_sz` as the size of the frame data minus the packet number size and crypto tag size.
    - Finally, it calls `fd_quic_pretty_print_struct_handshake` to pretty-print the handshake structure into the output buffer and returns the payload offset.
- **Output**: The function returns the offset to the payload within the buffer, or `FD_QUIC_PARSE_FAIL` if parsing fails.


---
### fd\_quic\_pretty\_print\_quic\_hdr\_one\_rtt<!-- {{#callable:fd_quic_pretty_print_quic_hdr_one_rtt}} -->
The function `fd_quic_pretty_print_quic_hdr_one_rtt` decodes and pretty-prints a QUIC 1-RTT header from a given buffer into a JSON-like format.
- **Inputs**:
    - `out_buf`: A pointer to a buffer where the pretty-printed output will be written.
    - `out_buf_sz`: A pointer to the size of the output buffer, which will be updated as data is written.
    - `frame_ptr`: A pointer to a location where the function will store the starting address of the frame data within the buffer.
    - `frame_sz`: A pointer to a location where the function will store the size of the frame data.
    - `buf`: A pointer to the input buffer containing the QUIC packet data to be decoded.
    - `buf_sz`: The size of the input buffer.
- **Control Flow**:
    - Initialize the output buffer with a JSON key-value pair indicating the header type as '1-rtt'.
    - Set up a `fd_quic_one_rtt_t` structure and initialize a hidden field required for decoding.
    - Call `fd_quic_decode_one_rtt` to decode the 1-RTT header from the input buffer.
    - If decoding fails, log an error, append an error message to the output buffer, and return a failure code.
    - Calculate the packet number offset and size, and determine the payload offset and size.
    - Decode the packet number from the buffer and store it in the `one_rtt` structure.
    - Set the frame pointer and size to point to the payload data, excluding the crypto tag size.
    - Call `fd_quic_pretty_print_struct_one_rtt` to append the decoded 1-RTT structure to the output buffer.
    - Return the payload offset as the function result.
- **Output**: The function returns the offset to the payload within the buffer, or a failure code if parsing fails.


---
### fd\_quic\_pretty\_print\_quic\_hdr<!-- {{#callable:fd_quic_pretty_print_quic_hdr}} -->
The `fd_quic_pretty_print_quic_hdr` function processes and pretty-prints the header of a QUIC packet, determining its type and delegating to specific functions for detailed processing based on the header type.
- **Inputs**:
    - `out_buf`: A pointer to a buffer where the pretty-printed output will be stored.
    - `out_buf_sz`: A pointer to the size of the output buffer, which will be updated as the buffer is filled.
    - `frame_ptr`: A pointer to a pointer that will be set to the start of the frame data within the buffer.
    - `frame_sz`: A pointer to a variable that will be set to the size of the frame data.
    - `buf`: A pointer to the buffer containing the QUIC packet data to be processed.
    - `buf_sz`: The size of the buffer containing the QUIC packet data.
- **Control Flow**:
    - The function reads the first byte of the buffer to determine if the packet is a long header (by checking the most significant bit).
    - If the packet is not a long header, it calls [`fd_quic_pretty_print_quic_hdr_one_rtt`](#fd_quic_pretty_print_quic_hdr_one_rtt) to process a 1-RTT packet.
    - If the packet is a long header, it extracts the long header type from the first byte.
    - Based on the long header type, it calls the appropriate function: [`fd_quic_pretty_print_quic_hdr_initial`](#fd_quic_pretty_print_quic_hdr_initial) for initial packets, [`fd_quic_pretty_print_quic_hdr_handshake`](#fd_quic_pretty_print_quic_hdr_handshake) for handshake packets, or returns an error for unsupported types (0-RTT and retry).
    - If the long header type is unsupported or unrecognized, it returns a parse failure.
- **Output**: The function returns the number of bytes processed from the buffer if successful, or `FD_QUIC_PARSE_FAIL` if parsing fails.
- **Functions called**:
    - [`fd_quic_pretty_print_quic_hdr_one_rtt`](#fd_quic_pretty_print_quic_hdr_one_rtt)
    - [`fd_quic_pretty_print_quic_hdr_initial`](#fd_quic_pretty_print_quic_hdr_initial)
    - [`fd_quic_pretty_print_quic_hdr_handshake`](#fd_quic_pretty_print_quic_hdr_handshake)


---
### ip4\_to\_str<!-- {{#callable:ip4_to_str}} -->
The `ip4_to_str` function converts a 32-bit IPv4 address into a human-readable string format and stores it in a provided buffer.
- **Inputs**:
    - `buf`: A character buffer of size `IP4_TO_STR_BUF_SZ` where the resulting string representation of the IPv4 address will be stored.
    - `ip4_addr`: A 32-bit unsigned integer representing the IPv4 address to be converted to a string.
- **Control Flow**:
    - The function uses `safe_snprintf` to format the IPv4 address into the provided buffer `buf` using a predefined format `FD_IP4_ADDR_FMT` and arguments `FD_IP4_ADDR_FMT_ARGS(ip4_addr)`.
    - It calculates the size of the formatted string and checks if it exceeds the buffer size `IP4_TO_STR_BUF_SZ`.
    - If the formatted string size is unexpectedly larger than the buffer size, it ensures the buffer is null-terminated by setting the last character of the buffer to '\0'.
- **Output**: The function returns a pointer to the buffer `buf` containing the string representation of the IPv4 address.


---
### fd\_quic\_pretty\_print\_quic\_pkt<!-- {{#callable:fd_quic_pretty_print_quic_pkt}} -->
The `fd_quic_pretty_print_quic_pkt` function formats and prints a QUIC packet in a human-readable JSON format, including its header and frames, and handles parsing errors.
- **Inputs**:
    - `pretty_print`: A pointer to a `fd_quic_pretty_print_t` structure, which is not used in the function.
    - `now`: A timestamp representing the current time, which is not used in the function.
    - `buf`: A pointer to the buffer containing the QUIC packet data to be pretty-printed.
    - `buf_sz`: The size of the buffer containing the QUIC packet data.
    - `flow`: A string representing the flow identifier for the packet.
    - `ip4_saddr`: The source IPv4 address of the packet, in network byte order.
    - `udp_sport`: The source UDP port of the packet, in network byte order.
- **Control Flow**:
    - Check if the `buf` is NULL and return `FD_QUIC_PARSE_FAIL` if true.
    - Initialize a static buffer `pretty_print_buf` to store the JSON output and clear its contents.
    - Format the initial part of the JSON output with packet type, flow, trace time, source IP address, and source UDP port.
    - Call [`fd_quic_pretty_print_quic_hdr`](#fd_quic_pretty_print_quic_hdr) to parse and pretty-print the QUIC header, updating `out_buf` and `out_buf_sz`.
    - If header parsing fails, append an error message to the JSON output and return `FD_QUIC_PARSE_FAIL`.
    - Append the opening of the frames array to the JSON output.
    - Call [`fd_quic_pretty_print_frames`](#fd_quic_pretty_print_frames) to parse and pretty-print the frames, updating `out_buf` and `out_buf_sz`.
    - If frame parsing fails, append an error message to the JSON output, print the buffer, and return `FD_QUIC_PARSE_FAIL`.
    - Append the closing of the frames array and the JSON object to the output.
    - Replace any null characters in `pretty_print_buf` with asterisks.
    - Print the final JSON output to the standard output.
- **Output**: Returns a `ulong` indicating the result of the parsing and printing process, where `FD_QUIC_PARSE_FAIL` indicates a failure.
- **Functions called**:
    - [`ip4_to_str`](#ip4_to_str)
    - [`fd_quic_pretty_print_quic_hdr`](#fd_quic_pretty_print_quic_hdr)
    - [`fd_quic_pretty_print_frames`](#fd_quic_pretty_print_frames)


---
### fd\_quic\_pretty\_print\_frames<!-- {{#callable:fd_quic_pretty_print_frames}} -->
The `fd_quic_pretty_print_frames` function iterates over a buffer of QUIC frames, pretty-printing each frame into a JSON format and appending it to an output buffer.
- **Inputs**:
    - `out_buf`: A pointer to a character buffer where the pretty-printed JSON output will be stored.
    - `out_buf_sz`: A pointer to an unsigned long representing the size of the output buffer.
    - `buf`: A constant pointer to an unsigned character array containing the QUIC frames to be pretty-printed.
    - `buf_sz`: An unsigned long representing the size of the input buffer containing the QUIC frames.
- **Control Flow**:
    - Initialize `orig_buf` to point to the start of `buf` and declare `sz` for storing sizes.
    - Enter a while loop that continues as long as `buf_sz` is greater than 0.
    - Within the loop, use `safe_snprintf` to append a JSON object start string to `out_buf`, updating `out_buf` and `out_buf_sz` accordingly.
    - Call [`fd_quic_pretty_print_frame`](#fd_quic_pretty_print_frame) to process and pretty-print a single frame from `buf`, updating `out_buf` and `out_buf_sz`.
    - If [`fd_quic_pretty_print_frame`](#fd_quic_pretty_print_frame) returns `FD_QUIC_PARSE_FAIL`, append an error message to `out_buf` and break the loop.
    - Append a closing JSON object string to `out_buf`, updating `out_buf` and `out_buf_sz`.
    - If the number of bytes processed (`rc`) is greater than or equal to `buf_sz`, break the loop.
    - Otherwise, increment `buf` by `rc` and decrement `buf_sz` by `rc`.
- **Output**: Returns the number of bytes processed from the input buffer, as an unsigned long.
- **Functions called**:
    - [`fd_quic_pretty_print_frame`](#fd_quic_pretty_print_frame)


# Function Declarations (Public API)

---
### fd\_quic\_pretty\_print\_frames<!-- {{#callable_declaration:fd_quic_pretty_print_frames}} -->
Converts QUIC frames into a JSON-like string representation.
- **Description**: This function is used to convert a buffer of QUIC frames into a JSON-like string representation, appending the result to a provided output buffer. It is useful for logging or debugging purposes where a human-readable format of the frames is required. The function processes each frame in the input buffer, appending its representation to the output buffer, and handles parsing errors by appending an error message to the output. It is important to ensure that the output buffer is sufficiently large to hold the resulting string, and that the input buffer contains valid QUIC frames.
- **Inputs**:
    - `out_buf`: A pointer to a character pointer where the output string will be written. The pointer is updated to point to the end of the written data. Must not be null.
    - `out_buf_sz`: A pointer to an unsigned long representing the size of the output buffer. It is updated to reflect the remaining size after writing. Must not be null.
    - `buf`: A pointer to the input buffer containing QUIC frames to be pretty-printed. Must not be null.
    - `buf_sz`: The size of the input buffer in bytes. Must be greater than zero.
- **Output**: Returns the number of bytes consumed from the input buffer. If a parsing error occurs, the function appends an error message to the output and stops processing further frames.
- **See also**: [`fd_quic_pretty_print_frames`](#fd_quic_pretty_print_frames)  (Implementation)



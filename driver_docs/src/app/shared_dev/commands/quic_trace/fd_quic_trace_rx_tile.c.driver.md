# Purpose
The provided C source code file, `fd_quic_trace_rx_tile.c`, is designed to perform passive decryption and analysis of incoming QUIC packets. It simulates the setup and execution loop of a real QUIC processing tile, specifically focusing on tracing and decrypting QUIC packets for analysis purposes. The file includes several static functions that handle different stages of packet processing, such as [`before_frag`](#before_frag), [`during_frag`](#during_frag), and [`after_frag`](#after_frag), which are used to filter, process, and analyze network fragments. The core functionality revolves around decrypting QUIC packets, including initial, handshake, and 1-RTT packets, using cryptographic keys and then tracing the packet details for further analysis.

The file is not intended to be a standalone executable but rather a component of a larger system, likely part of a network analysis or monitoring tool. It includes several headers and source files from a broader library, indicating its integration into a larger codebase. The functions within the file do not define public APIs or external interfaces; instead, they operate within the context of the QUIC tracing system, using internal data structures and utility functions to perform their tasks. The code is highly specialized, focusing on the specific task of QUIC packet decryption and tracing, and it leverages various utility functions and data structures from the included headers to achieve its purpose.
# Imports and Dependencies

---
- `fd_quic_trace.h`
- `../../../../waltz/quic/fd_quic_private.h`
- `../../../../waltz/quic/templ/fd_quic_parse_util.h`
- `../../../../waltz/quic/fd_quic_proto.c`
- `../../../../util/net/fd_eth.h`
- `../../../../util/net/fd_ip4.h`
- `../../../../util/net/fd_udp.h`
- `../../../../disco/stem/fd_stem.c`


# Functions

---
### before\_frag<!-- {{#callable:before_frag}} -->
The `before_frag` function determines whether a packet should be processed based on its protocol type, specifically filtering for QUIC-related protocols.
- **Inputs**:
    - `_ctx`: A context pointer, marked as unused in this function.
    - `in_idx`: An index value, marked as unused in this function.
    - `seq`: A sequence number, marked as unused in this function.
    - `sig`: A signal value used to determine the protocol type of the packet.
- **Control Flow**:
    - Retrieve the protocol type from the signal using `fd_disco_netmux_sig_proto(sig)`.
    - Check if the protocol is either `DST_PROTO_OUTGOING` or `DST_PROTO_TPU_QUIC`.
    - If the protocol matches one of the specified QUIC-related types, continue processing (return 0).
    - If the protocol does not match, skip processing (return 1).
- **Output**: Returns 0 if the packet is a QUIC-related protocol, otherwise returns 1 to indicate the packet should be skipped.


---
### during\_frag<!-- {{#callable:during_frag}} -->
The `during_frag` function processes a fragment of data based on its protocol type, copying it into a buffer for further processing.
- **Inputs**:
    - `_ctx`: A context pointer, which is unused in this function but typically represents the current state or environment.
    - `in_idx`: An index of the input, marked as unused in this function.
    - `seq`: A sequence number, marked as unused in this function.
    - `sig`: A signal or signature, marked as unused in this function.
    - `chunk`: The chunk of data to be processed.
    - `sz`: The size of the data chunk.
    - `ctl`: Control information related to the data chunk.
- **Control Flow**:
    - Retrieve the protocol type from the signal using `fd_disco_netmux_sig_proto` function.
    - Check if the protocol is `DST_PROTO_TPU_QUIC`.
    - If true, translate the fragment using `fd_net_rx_translate_frag` and copy it to the buffer using `fd_memcpy`.
    - If the protocol is `DST_PROTO_OUTGOING`, calculate the memory address using `trace_ctx->net_out_base` and `chunk`, then copy the data to the buffer using `fd_memcpy`.
- **Output**: The function does not return any value; it performs operations on the context's buffer based on the protocol type.


---
### bounds\_check\_conn<!-- {{#callable:bounds_check_conn}} -->
The `bounds_check_conn` function checks if a given connection object is within the valid bounds of a QUIC instance's connection layout.
- **Inputs**:
    - `quic`: A pointer to an `fd_quic_t` structure representing the QUIC instance.
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the connection to be checked.
- **Control Flow**:
    - Calculate the offset of the connection object from the start of the QUIC instance.
    - Check if this offset is within the range defined by `conns_off` and `conn_map_off` in the QUIC instance's layout.
    - Return true if the offset is within bounds, otherwise return false.
- **Output**: Returns an integer indicating whether the connection is within the valid bounds (non-zero if true, zero if false).


---
### fd\_quic\_trace\_initial<!-- {{#callable:fd_quic_trace_initial}} -->
The `fd_quic_trace_initial` function processes and decrypts incoming QUIC Initial packets, handling connection mapping and key derivation as necessary.
- **Inputs**:
    - `trace_ctx`: A pointer to the QUIC trace context, which contains state and configuration for tracing.
    - `data`: A pointer to the buffer containing the QUIC packet data to be processed.
    - `data_sz`: The size of the data buffer in bytes.
    - `ip4_saddr`: The source IPv4 address from which the packet was received.
    - `udp_sport`: The source UDP port from which the packet was received.
    - `key_idx`: An index indicating whether the packet is ingress (0) or egress (1).
- **Control Flow**:
    - Initialize context and retrieve QUIC state and connection map pointers.
    - Check if the packet size is smaller than the minimum QUIC packet size and return failure if true.
    - Decode the initial packet and check for parsing errors, returning failure if any occur.
    - Validate the packet length and destination connection ID length, logging errors if they are invalid.
    - Attempt to retrieve cryptographic keys for the connection using the destination connection ID.
    - If keys are not found or are empty, derive initial secrets and keys for ingress packets.
    - Decrypt the packet header and check for errors, returning failure if decryption fails.
    - Calculate packet number size and decode the packet number.
    - Verify the total size of the packet and decrypt the packet body, returning failure if decryption fails.
    - If tracing is enabled, pretty print the packet; otherwise, trace the packet frames.
    - Return the total size of the processed packet.
- **Output**: The function returns the total size of the processed packet in bytes, or a failure code if processing fails.
- **Functions called**:
    - [`bounds_check_conn`](#bounds_check_conn)
    - [`fd_quic_trace_frames`](fd_quic_trace_frame.c.driver.md#fd_quic_trace_frames)


---
### fd\_quic\_trace\_handshake<!-- {{#callable:fd_quic_trace_handshake}} -->
The `fd_quic_trace_handshake` function processes and decrypts QUIC handshake packets, verifying their integrity and optionally logging or tracing the packet details.
- **Inputs**:
    - `trace_ctx`: A pointer to the QUIC trace context, which contains state and configuration for tracing.
    - `data`: A pointer to the buffer containing the QUIC packet data to be processed.
    - `data_sz`: The size of the data buffer in bytes.
    - `ip4_saddr`: The source IPv4 address from which the packet was received.
    - `udp_sport`: The source UDP port from which the packet was received.
    - `key_idx`: An index indicating whether the packet is ingress (0) or egress (1).
- **Control Flow**:
    - Initialize context and retrieve QUIC state and connection map.
    - Check if the packet size is smaller than the minimum QUIC packet size; if so, return failure.
    - Decode the handshake packet and check for decoding errors; if any, return failure.
    - Verify the packet length against the data size; if invalid, return failure.
    - Retrieve the appropriate cryptographic keys based on the connection ID and key index.
    - If keys are not found or are invalid, return failure.
    - Decrypt the packet header using the retrieved keys; if decryption fails, return failure.
    - Calculate packet number size and decode the packet number.
    - Verify the total size of the packet against the data size; if invalid, return failure.
    - Decrypt the packet body using the packet number and keys; if decryption fails, return failure.
    - Check if the data size is sufficient for the header and authentication tag; if not, return failure.
    - If tracing is enabled, pretty print the packet details; otherwise, trace the packet frames.
    - Return failure as the function's default behavior.
- **Output**: The function returns `FD_QUIC_PARSE_FAIL` to indicate failure in processing the packet, as it is designed to trace and log rather than return success.
- **Functions called**:
    - [`bounds_check_conn`](#bounds_check_conn)
    - [`fd_quic_trace_frames`](fd_quic_trace_frame.c.driver.md#fd_quic_trace_frames)


---
### fd\_quic\_trace\_1rtt<!-- {{#callable:fd_quic_trace_1rtt}} -->
The `fd_quic_trace_1rtt` function processes and decrypts 1-RTT QUIC packets, handling both ingress and egress flows, and either prints the packet details or traces the frames depending on the context.
- **Inputs**:
    - `trace_ctx`: A pointer to the QUIC trace context, which contains information about the tracing state and configuration.
    - `data`: A pointer to the data buffer containing the QUIC packet to be processed.
    - `data_sz`: The size of the data buffer in bytes.
    - `ip4_saddr`: The source IPv4 address from which the packet was received.
    - `udp_sport`: The source UDP port from which the packet was received.
    - `key_idx`: An index indicating whether the packet is ingress (0) or egress (1).
- **Control Flow**:
    - Check if the packet size is less than the shortest QUIC packet size and return if true.
    - Initialize connection-related variables and determine the connection ID based on the key index (ingress or egress).
    - For ingress, look up the connection using the destination connection ID from the packet data.
    - For egress, use the first 8 bytes of the peer connection ID to look up the connection index in the peer connection ID map.
    - If the connection is not found, log an error message and return.
    - Decrypt the packet header using the appropriate keys for the connection and check for errors.
    - Decode the packet number and reconstruct it using the expected packet number from the connection state.
    - Decrypt the packet payload and check for errors.
    - Calculate header and wrap sizes and ensure the data size is sufficient.
    - If the trace context is set to dump, pretty print the packet details; otherwise, trace the frames if the packet is ingress.
- **Output**: The function does not return a value; it performs operations based on the packet data and context, such as printing or tracing frames.
- **Functions called**:
    - [`bounds_check_conn`](#bounds_check_conn)
    - [`fd_quic_trace_frames`](fd_quic_trace_frame.c.driver.md#fd_quic_trace_frames)


---
### fd\_quic\_trace\_pkt<!-- {{#callable:fd_quic_trace_pkt}} -->
The `fd_quic_trace_pkt` function processes QUIC packets by determining their type and invoking appropriate tracing functions for each packet type.
- **Inputs**:
    - `ctx`: A context pointer used for tracing operations.
    - `data`: A pointer to the data buffer containing the QUIC packet to be processed.
    - `data_sz`: The size of the data buffer in bytes.
    - `ip4_saddr`: The source IPv4 address of the packet.
    - `udp_sport`: The source UDP port of the packet.
    - `key_idx`: An index indicating whether the packet is ingress (0) or egress (1).
- **Control Flow**:
    - Initialize pointers `cur_ptr` and `end_ptr` to iterate over the data buffer.
    - Enter a loop that continues until `cur_ptr` reaches `end_ptr`.
    - Determine if the current packet is a long header packet using `fd_quic_h0_hdr_form`.
    - If the packet is a long header, determine its type using `fd_quic_h0_long_packet_type`.
    - For `FD_QUIC_PKT_TYPE_INITIAL`, call [`fd_quic_trace_initial`](#fd_quic_trace_initial) to process the packet and update `sz` with the processed size.
    - For `FD_QUIC_PKT_TYPE_HANDSHAKE`, call [`fd_quic_trace_handshake`](#fd_quic_trace_handshake) to process the packet and update `sz` with the processed size.
    - If the packet is not a long header, call [`fd_quic_trace_1rtt`](#fd_quic_trace_1rtt) to process a 1-RTT packet and break the loop as 1-RTT packets are last in the datagram.
    - If `sz` is 0 or `FD_QUIC_PARSE_FAIL`, break the loop.
    - Increment `cur_ptr` by `sz` to process the next packet in the buffer.
- **Output**: The function does not return a value; it processes packets and performs tracing operations based on packet type.
- **Functions called**:
    - [`fd_quic_trace_initial`](#fd_quic_trace_initial)
    - [`fd_quic_trace_handshake`](#fd_quic_trace_handshake)
    - [`fd_quic_trace_1rtt`](#fd_quic_trace_1rtt)


---
### after\_frag<!-- {{#callable:after_frag}} -->
The `after_frag` function processes a fragment of a network packet, checking its size and protocol, and then traces the packet if it is a valid QUIC packet.
- **Inputs**:
    - `_ctx`: A context pointer, typically used for passing state or configuration information.
    - `in_idx`: An index of the input fragment, but it is unused in this function.
    - `seq`: A sequence number of the fragment, but it is unused in this function.
    - `sig`: A signature or identifier for the packet, used to determine the protocol.
    - `sz`: The size of the packet fragment.
    - `tsorig`: The original timestamp of the packet, but it is unused in this function.
    - `tspub`: The publication timestamp of the packet, but it is unused in this function.
    - `stem`: A pointer to a stem context, but it is unused in this function.
- **Control Flow**:
    - The function begins by determining the protocol from the `sig` using `fd_disco_netmux_sig_proto` and sets `key_idx` based on whether the protocol is `DST_PROTO_TPU_QUIC`.
    - It checks if the size `sz` is less than `FD_QUIC_SHORTEST_PKT` or greater than the buffer size in `ctx`; if so, it returns early.
    - It initializes pointers `cur` and `end` to the start and end of the buffer, respectively.
    - It reads and advances past the Ethernet header, checking if the end of the buffer is exceeded or if the network type is not IP, returning if either condition is true.
    - It reads the IP header, checks the buffer bounds, and verifies the protocol is UDP, returning if any check fails.
    - It reads the UDP header and checks the buffer bounds again, returning if exceeded.
    - Finally, it extracts the source IP address and UDP source port, and calls [`fd_quic_trace_pkt`](#fd_quic_trace_pkt) to trace the packet.
- **Output**: The function does not return a value; it performs operations based on the packet data and context.
- **Functions called**:
    - [`fd_quic_trace_pkt`](#fd_quic_trace_pkt)


---
### fd\_quic\_trace\_rx\_tile<!-- {{#callable:fd_quic_trace_rx_tile}} -->
The `fd_quic_trace_rx_tile` function sets up and runs a QUIC packet tracing operation using provided receive and transmit metadata caches.
- **Inputs**:
    - `trace_ctx`: A pointer to an `fd_quic_trace_ctx_t` structure, which holds the context for the QUIC tracing operation.
    - `rx_mcache`: A pointer to a constant `fd_frag_meta_t` structure representing the receive metadata cache.
    - `tx_mcache`: A pointer to a constant `fd_frag_meta_t` structure representing the transmit metadata cache.
- **Control Flow**:
    - Allocate memory for two frequency sequence tables (`fseq_tbl`) and initialize them using `fd_fseq_new` and `fd_fseq_join` functions.
    - Initialize a random number generator (`rng`) using `fd_rng_new` and `fd_rng_join`.
    - Prepare a scratch buffer aligned to `FD_STEM_SCRATCH_ALIGN`.
    - Create an array `in_mcache_tbl` containing the receive and transmit metadata caches.
    - Call `stem_run1` with the prepared inputs to execute the tracing operation.
    - After the tracing operation, clean up the frequency sequence tables by calling `fd_fseq_leave` and `fd_fseq_delete` for each table.
- **Output**: The function does not return a value; it performs its operations as a side effect on the provided context and metadata caches.



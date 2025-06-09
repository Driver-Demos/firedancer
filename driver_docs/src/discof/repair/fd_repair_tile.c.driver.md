# Purpose
The provided C source code file is part of a larger system designed to manage the repair protocol for a Firedancer node, which is likely part of a distributed network or blockchain infrastructure. This file implements the "repair tile" functionality, which is responsible for handling data integrity and synchronization across nodes. The code includes various components such as network communication, data handling, and cryptographic operations to ensure the integrity and availability of data within the network. It defines several structures and functions to manage incoming and outgoing network packets, handle repair requests, and maintain the state of the node's data.

The file is structured to integrate with a larger system, as indicated by the numerous includes and the use of external libraries and headers. It defines several key structures, such as `fd_repair_tile_ctx_t`, which encapsulates the context and state for the repair operations. The code also includes functions for sending and receiving network packets, handling different types of repair requests, and managing the node's data state. The use of macros and typedefs suggests that the code is designed for high performance and scalability, likely to handle large volumes of data and network traffic. The file is intended to be part of a larger executable, as it includes initialization functions and a main run loop that integrates with the system's topology and configuration.
# Imports and Dependencies

---
- `fd_fec_chainer.h`
- `../../disco/topo/fd_topo.h`
- `generated/fd_repair_tile_seccomp.h`
- `../../flamenco/repair/fd_repair.h`
- `../../flamenco/runtime/fd_blockstore.h`
- `../../disco/fd_disco.h`
- `../../disco/keyguard/fd_keyload.h`
- `../../disco/keyguard/fd_keyguard_client.h`
- `../../disco/keyguard/fd_keyguard.h`
- `../../disco/net/fd_net_tile.h`
- `../../disco/shred/fd_stake_ci.h`
- `../../util/pod/fd_pod_format.h`
- `../../choreo/fd_choreo_base.h`
- `../../util/net/fd_net_headers.h`
- `../forest/fd_forest.h`
- `fd_fec_repair.h`
- `errno.h`
- `../../util/tmpl/fd_map_dynamic.c`
- `../../disco/stem/fd_stem.c`


# Global Variables

---
### fd\_tile\_repair
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_repair` is a global variable of type `fd_topo_run_tile_t` that represents a configuration for a repair tile in a Firedancer node. It is initialized with specific function pointers and parameters that define its behavior, such as initialization functions, footprint calculations, and the main run function. This structure is crucial for setting up and managing the repair protocol operations within the node.
- **Use**: This variable is used to configure and manage the repair tile's operations, including initialization, security policies, and execution within the Firedancer node.


# Data Structures

---
### fd\_repair\_in\_ctx\_t
- **Type**: `union`
- **Members**:
    - `mem`: Pointer to a memory workspace used for repair operations.
    - `chunk0`: Initial chunk index in the memory workspace.
    - `wmark`: Watermark indicating the upper limit of valid data in the workspace.
    - `mtu`: Maximum transmission unit size for network operations.
    - `net_rx`: Network receive bounds structure for handling network data.
- **Description**: The `fd_repair_in_ctx_t` is a union data structure used in the repair protocol of a Firedancer node. It encapsulates two different contexts: a memory workspace context and a network receive context. The memory workspace context includes a pointer to a memory workspace (`mem`), an initial chunk index (`chunk0`), a watermark (`wmark`), and a maximum transmission unit (`mtu`). The network receive context is represented by `fd_net_rx_bounds_t`, which is used for handling network data reception. This union allows the repair protocol to switch between memory management and network data handling seamlessly.


---
### fd\_repair\_out\_ctx
- **Type**: `struct`
- **Members**:
    - `idx`: An unsigned long integer representing the index of the repair context.
    - `mem`: A pointer to a workspace structure (fd_wksp_t) used for memory management.
    - `chunk0`: An unsigned long integer indicating the starting chunk index in the workspace.
    - `wmark`: An unsigned long integer representing the watermark for the workspace, used to track the highest valid chunk.
    - `chunk`: An unsigned long integer representing the current chunk index being processed.
- **Description**: The `fd_repair_out_ctx` structure is used to manage the output context for a repair operation in a Firedancer node. It contains information about the memory workspace, including the starting chunk, current chunk, and watermark, which are essential for tracking and managing data chunks during the repair process. This structure is crucial for ensuring that the repair protocol can efficiently handle and process data within the allocated memory space.


---
### fd\_repair\_out\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `idx`: An unsigned long integer representing the index of the repair output context.
    - `mem`: A pointer to an fd_wksp_t structure, representing the memory workspace associated with the repair output context.
    - `chunk0`: An unsigned long integer representing the initial chunk of memory in the workspace.
    - `wmark`: An unsigned long integer representing the watermark for the memory usage in the workspace.
    - `chunk`: An unsigned long integer representing the current chunk of memory being used in the workspace.
- **Description**: The `fd_repair_out_ctx_t` structure is used to manage the context for repair output operations in a Firedancer node. It contains information about the memory workspace, including pointers and indices that help track the memory chunks being used for repair operations. This structure is crucial for managing the memory efficiently during the repair process, ensuring that the correct memory segments are accessed and modified as needed.


---
### fd\_fec\_sig
- **Type**: `struct`
- **Members**:
    - `key`: A 64-bit unsigned long used as a map key, with the upper 32 bits representing the slot and the lower 32 bits representing the fec_set_idx.
    - `sig`: An Ed25519 signature identifier for the FEC, represented by the type fd_ed25519_sig_t.
- **Description**: The `fd_fec_sig` structure is designed to represent a signature associated with a Forward Error Correction (FEC) set in a network protocol. It contains a `key` that uniquely identifies the FEC set by combining a slot and an index, and a `sig` which holds the Ed25519 signature for the FEC. This structure is likely used in a mapping context to efficiently retrieve and verify FEC-related data in a network repair protocol.


---
### fd\_fec\_sig\_t
- **Type**: `struct`
- **Members**:
    - `key`: A 64-bit unsigned long used as a map key, with the upper 32 bits representing the slot and the lower 32 bits representing the FEC set index.
    - `sig`: An Ed25519 signature that serves as an identifier for the FEC.
- **Description**: The `fd_fec_sig_t` structure is designed to represent a signature associated with a Forward Error Correction (FEC) set in a Firedancer node. It contains a `key` that uniquely identifies the FEC set by combining a slot number and a FEC set index, and a `sig` which is an Ed25519 signature used to verify the integrity and authenticity of the FEC data. This structure is likely used in a mapping context to efficiently retrieve and manage FEC signatures within the repair protocol of a Firedancer node.


---
### fd\_reasm
- **Type**: `struct`
- **Members**:
    - `slot`: Represents a unique identifier for a slot in the reassembly process.
    - `cnt`: Tracks the count of fragments or elements associated with the slot.
- **Description**: The `fd_reasm` structure is designed to facilitate the reassembly process in a network protocol, specifically within the context of the Firedancer node's repair protocol. It contains a `slot` member, which serves as a unique identifier for a particular slot in the reassembly process, and a `cnt` member, which keeps track of the number of fragments or elements that have been associated with that slot. This structure is likely used to manage and track the progress of reassembling data packets or fragments that are received out of order, ensuring that they can be correctly reconstructed into their original form.


---
### fd\_reasm\_t
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the reassembly process.
    - `cnt`: Indicates the count of elements or fragments associated with the slot.
- **Description**: The `fd_reasm_t` structure is used to manage the reassembly process of data fragments in a network protocol. It contains a `slot` to identify the specific slot or time frame for which the reassembly is being performed, and a `cnt` to keep track of the number of fragments or elements that have been processed or are associated with that slot. This structure is likely part of a larger system for handling data integrity and reconstruction in a distributed network environment.


---
### fd\_repair\_tile\_ctx
- **Type**: `struct`
- **Members**:
    - `tsprint`: Timestamp for printing operations.
    - `tsrepair`: Timestamp for repair operations.
    - `wmark`: Pointer to a watermark value.
    - `prev_wmark`: Previous watermark value.
    - `repair`: Pointer to a repair structure.
    - `repair_config`: Configuration settings for repair operations.
    - `repair_seed`: Seed value for repair operations.
    - `repair_intake_addr`: Address for repair intake operations.
    - `repair_serve_addr`: Address for repair serve operations.
    - `repair_intake_listen_port`: Port for listening to repair intake.
    - `repair_serve_listen_port`: Port for listening to repair serve.
    - `forest`: Pointer to a forest structure for managing data.
    - `fec_sigs`: Pointer to FEC signatures.
    - `reasm`: Pointer to reassembly structure.
    - `fec_chainer`: Pointer to FEC chainer structure.
    - `curr_turbine_slot`: Pointer to the current turbine slot.
    - `identity_private_key`: Private key for identity verification.
    - `identity_public_key`: Public key for identity verification.
    - `wksp`: Pointer to a workspace structure.
    - `in_kind`: Array indicating the kind of input links.
    - `in_links`: Array of input link contexts.
    - `skip_frag`: Flag to skip fragment processing.
    - `net_out_mcache`: Pointer to network output memory cache.
    - `net_out_sync`: Pointer to network output synchronization.
    - `net_out_depth`: Depth of the network output.
    - `net_out_seq`: Sequence number for network output.
    - `net_out_mem`: Pointer to network output memory.
    - `net_out_chunk0`: Initial chunk for network output.
    - `net_out_wmark`: Watermark for network output.
    - `net_out_chunk`: Current chunk for network output.
    - `replay_out_mem`: Pointer to replay output memory.
    - `replay_out_chunk0`: Initial chunk for replay output.
    - `replay_out_wmark`: Watermark for replay output.
    - `replay_out_chunk`: Current chunk for replay output.
    - `shred_tile_cnt`: Count of shred tiles.
    - `shred_out_ctx`: Array of contexts for shred output.
    - `net_id`: Network identifier.
    - `buffer`: Buffer for storing data packets.
    - `intake_hdr`: Header for intake operations.
    - `serve_hdr`: Header for serve operations.
    - `stake_ci`: Pointer to stake context information.
    - `stem`: Pointer to stem context.
    - `blockstore_wksp`: Pointer to blockstore workspace.
    - `blockstore_ljoin`: Local join blockstore structure.
    - `blockstore`: Pointer to blockstore structure.
    - `keyguard_client`: Array of keyguard client structures.
    - `first_turbine_slot`: Pointer to the first turbine slot.
- **Description**: The `fd_repair_tile_ctx` structure is a comprehensive context for managing repair operations in a Firedancer node. It includes timestamps for printing and repair, pointers to various configurations and operational structures, and arrays for managing input and output links. The structure is designed to handle network operations, including intake and serve addresses, and manage data through forest and reassembly structures. It also includes cryptographic keys for identity verification and mechanisms for handling network output and replay operations. The structure is integral to the repair protocol, facilitating communication and data management across the node's network.


---
### fd\_repair\_tile\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `tsprint`: Timestamp for printing operations.
    - `tsrepair`: Timestamp for repair operations.
    - `wmark`: Pointer to a watermark value.
    - `prev_wmark`: Previous watermark value.
    - `repair`: Pointer to a repair object.
    - `repair_config`: Configuration settings for repair operations.
    - `repair_seed`: Seed value for repair operations.
    - `repair_intake_addr`: Address for repair intake operations.
    - `repair_serve_addr`: Address for repair serve operations.
    - `repair_intake_listen_port`: Port for listening to repair intake.
    - `repair_serve_listen_port`: Port for listening to repair serve.
    - `forest`: Pointer to a forest data structure.
    - `fec_sigs`: Pointer to FEC signature data.
    - `reasm`: Pointer to reassembly data.
    - `fec_chainer`: Pointer to FEC chainer data.
    - `curr_turbine_slot`: Pointer to the current turbine slot value.
    - `identity_private_key`: Private key for identity verification.
    - `identity_public_key`: Public key for identity verification.
    - `wksp`: Pointer to a workspace object.
    - `in_kind`: Array indicating the kind of input links.
    - `in_links`: Array of input link contexts.
    - `skip_frag`: Flag to skip fragment processing.
    - `net_out_mcache`: Pointer to the network output memory cache.
    - `net_out_sync`: Pointer to the network output synchronization value.
    - `net_out_depth`: Depth of the network output.
    - `net_out_seq`: Sequence number for network output.
    - `net_out_mem`: Pointer to network output memory.
    - `net_out_chunk0`: Initial chunk value for network output.
    - `net_out_wmark`: Watermark for network output.
    - `net_out_chunk`: Current chunk value for network output.
    - `replay_out_mem`: Pointer to replay output memory.
    - `replay_out_chunk0`: Initial chunk value for replay output.
    - `replay_out_wmark`: Watermark for replay output.
    - `replay_out_chunk`: Current chunk value for replay output.
    - `shred_tile_cnt`: Count of shred tiles.
    - `shred_out_ctx`: Array of contexts for shred output.
    - `net_id`: Network identifier.
    - `buffer`: Buffer for storing data.
    - `intake_hdr`: Header for intake operations.
    - `serve_hdr`: Header for serve operations.
    - `stake_ci`: Pointer to stake consensus information.
    - `stem`: Pointer to stem context.
    - `blockstore_wksp`: Pointer to blockstore workspace.
    - `blockstore_ljoin`: Local join blockstore object.
    - `blockstore`: Pointer to blockstore object.
    - `keyguard_client`: Array of keyguard client objects.
    - `first_turbine_slot`: Pointer to the first turbine slot value.
- **Description**: The `fd_repair_tile_ctx_t` structure is a comprehensive context for managing repair operations in a Firedancer node. It includes timestamps for various operations, configuration settings, and pointers to key components such as repair objects, forest data structures, and FEC (Forward Error Correction) components. The structure also manages network input and output through various ports and addresses, and it maintains state information such as watermarks and sequence numbers. Additionally, it handles cryptographic keys for identity verification and includes buffers and contexts for processing network data and shreds. This structure is central to the repair protocol, facilitating communication and data integrity across the network.


# Functions

---
### scratch\_align<!-- {{#callable:scratch_align}} -->
The `scratch_align` function returns a constant alignment value of 128 bytes.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests the compiler to inline it for performance.
    - The function does not take any parameters.
    - It simply returns a constant value of 128UL, which is an unsigned long integer.
- **Output**: The function outputs a constant unsigned long integer value of 128, representing an alignment size.


---
### loose\_footprint<!-- {{#callable:loose_footprint}} -->
The `loose_footprint` function calculates and returns the memory footprint size for a tile using a gigantic page size.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, which is marked as unused in this function.
- **Control Flow**:
    - The function takes a single argument, `tile`, which is marked as unused with `FD_PARAM_UNUSED`.
    - It returns the product of `1UL` and `FD_SHMEM_GIGANTIC_PAGE_SZ`, which represents the size of a gigantic shared memory page.
- **Output**: The function returns an `ulong` representing the memory footprint size, specifically the size of a gigantic shared memory page.


---
### scratch\_footprint<!-- {{#callable:scratch_footprint}} -->
The `scratch_footprint` function calculates the memory footprint required for various components of a repair tile context in a Firedancer node.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, which is unused in this function.
- **Control Flow**:
    - Initialize a variable `l` with `FD_LAYOUT_INIT` to start the layout calculation.
    - Append the size and alignment of `fd_repair_tile_ctx_t` to `l` using `FD_LAYOUT_APPEND`.
    - Append the size and alignment of `fd_repair` components using `FD_LAYOUT_APPEND` with `fd_repair_align()` and `fd_repair_footprint()`.
    - Append the size and alignment of `fd_forest` components using `FD_LAYOUT_APPEND` with `fd_forest_align()` and `fd_forest_footprint(FD_FOREST_ELE_MAX)`.
    - Append the size and alignment of `fd_fec_sig` components using `FD_LAYOUT_APPEND` with `fd_fec_sig_align()` and `fd_fec_sig_footprint(20)`.
    - Append the size and alignment of `fd_reasm` components using `FD_LAYOUT_APPEND` with `fd_reasm_align()` and `fd_reasm_footprint(20)`.
    - Append the size and alignment of `fd_fec_chainer` components using `FD_LAYOUT_APPEND` with `fd_fec_chainer_align()` and `fd_fec_chainer_footprint(1 << 20)`.
    - Append the size and alignment of `fd_scratch_smem` components using `FD_LAYOUT_APPEND` with `fd_scratch_smem_align()` and `fd_scratch_smem_footprint(FD_REPAIR_SCRATCH_MAX)`.
    - Append the size and alignment of `fd_scratch_fmem` components using `FD_LAYOUT_APPEND` with `fd_scratch_fmem_align()` and `fd_scratch_fmem_footprint(FD_REPAIR_SCRATCH_DEPTH)`.
    - Append the size and alignment of `fd_stake_ci` components using `FD_LAYOUT_APPEND` with `fd_stake_ci_align()` and `fd_stake_ci_footprint()`.
    - Finalize the layout calculation with `FD_LAYOUT_FINI` using `scratch_align()` and return the result.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the specified components.
- **Functions called**:
    - [`fd_fec_chainer_align`](fd_fec_chainer.h.driver.md#fd_fec_chainer_align)
    - [`fd_fec_chainer_footprint`](fd_fec_chainer.h.driver.md#fd_fec_chainer_footprint)
    - [`scratch_align`](#scratch_align)


---
### repair\_signer<!-- {{#callable:repair_signer}} -->
The `repair_signer` function signs a given buffer using a keyguard client within a repair tile context.
- **Inputs**:
    - `signer_ctx`: A pointer to the context of the signer, specifically a `fd_repair_tile_ctx_t` structure.
    - `signature`: An array of 64 unsigned characters where the generated signature will be stored.
    - `buffer`: A constant pointer to the buffer containing the data to be signed.
    - `len`: The length of the buffer to be signed, specified as an unsigned long.
    - `sign_type`: An integer representing the type of signature to be generated.
- **Control Flow**:
    - Cast the `signer_ctx` to a `fd_repair_tile_ctx_t` pointer and store it in `ctx`.
    - Call the `fd_keyguard_client_sign` function with the keyguard client from `ctx`, passing the signature, buffer, length, and sign type as arguments.
- **Output**: The function does not return a value; it outputs the generated signature in the provided `signature` array.


---
### send\_packet<!-- {{#callable:send_packet}} -->
The `send_packet` function constructs and sends a network packet with specified IP and UDP headers, payload, and metadata, updating the context's sequence and chunk information.
- **Inputs**:
    - `ctx`: A pointer to a `fd_repair_tile_ctx_t` structure containing context information for the repair tile, including network output memory and sequence data.
    - `is_intake`: An integer flag indicating whether the packet is for intake (1) or serve (0).
    - `dst_ip_addr`: The destination IP address for the packet.
    - `dst_port`: The destination port for the packet.
    - `src_ip_addr`: The source IP address for the packet.
    - `payload`: A pointer to the payload data to be included in the packet.
    - `payload_sz`: The size of the payload data in bytes.
    - `tsorig`: The original timestamp for the packet, used for metadata.
- **Control Flow**:
    - Allocate memory for the packet using `fd_chunk_to_laddr` with the context's network output memory and chunk.
    - Set the IP and UDP headers in the packet based on whether it is for intake or serve, using the context's headers.
    - Set the source and destination IP addresses and the destination port in the IP and UDP headers, respectively.
    - Calculate and set the total length and checksum for the IP header.
    - Calculate and set the length for the UDP header, and copy the payload into the packet after the headers.
    - Set the UDP checksum to zero.
    - Compute the publication timestamp and signature for the packet using `fd_frag_meta_ts_comp` and `fd_disco_netmux_sig`.
    - Publish the packet metadata using `fd_mcache_publish`, including the sequence, signature, chunk, and timestamps.
    - Increment the context's sequence number and update the chunk using `fd_seq_inc` and `fd_dcache_compact_next`.
- **Output**: The function does not return a value; it sends a packet and updates the context's sequence and chunk information.


---
### handle\_new\_cluster\_contact\_info<!-- {{#callable:handle_new_cluster_contact_info}} -->
The `handle_new_cluster_contact_info` function processes new cluster contact information by adding active peers to the repair context if the number of destinations is within the allowed limit.
- **Inputs**:
    - `ctx`: A pointer to a `fd_repair_tile_ctx_t` structure, which contains the context for the repair tile, including peer tracking and configuration.
    - `buf`: A constant pointer to an unsigned character array containing the buffer with new cluster contact information.
    - `buf_sz`: An unsigned long integer representing the size of the buffer, indicating the number of destinations.
- **Control Flow**:
    - Cast the buffer `buf` to a pointer of type `fd_shred_dest_wire_t` to interpret the data as destination information.
    - Check if the number of destinations (`dest_cnt`) is greater than or equal to `MAX_REPAIR_PEERS`. If so, log a warning and return without processing further.
    - Iterate over each destination in the buffer up to `dest_cnt`.
    - For each destination, check if the current number of peers in the context (`ctx->repair->peer_cnt`) is greater than or equal to `FD_ACTIVE_KEY_MAX`. If so, break the loop to stop adding more peers.
    - For each valid destination, create a `fd_repair_peer_addr_t` structure with the IP address and port from the destination, converting the port to host byte order using `fd_ushort_bswap`.
    - Add the peer to the active peers list in the repair context using `fd_repair_add_active_peer`.
- **Output**: The function does not return a value; it modifies the repair context by adding new active peers based on the provided buffer data.


---
### handle\_new\_stake\_weights<!-- {{#callable:handle_new_stake_weights}} -->
The `handle_new_stake_weights` function updates the stake weights for a repair context, ensuring the count does not exceed a predefined maximum.
- **Inputs**:
    - `ctx`: A pointer to an `fd_repair_tile_ctx_t` structure, which contains the context for the repair tile, including stake information.
- **Control Flow**:
    - Retrieve the count of stake weights from the context's stake information.
    - Check if the count of stake weights exceeds the maximum allowed (`MAX_REPAIR_PEERS`).
    - If the count exceeds the maximum, log an error message and terminate the function.
    - Retrieve the stake weights from the context's stake information.
    - Call `fd_repair_set_stake_weights` to update the repair context with the new stake weights and their count.
- **Output**: The function does not return a value; it updates the stake weights in the repair context or logs an error if the count exceeds the maximum allowed.


---
### fd\_repair\_handle\_ping<!-- {{#callable:fd_repair_handle_ping}} -->
The `fd_repair_handle_ping` function processes a ping message, generates a pong response, signs it, encodes it, and returns the size of the encoded message.
- **Inputs**:
    - `repair_tile_ctx`: A pointer to the repair tile context, which contains various state and configuration information for the repair process.
    - `glob`: A pointer to the global repair context, which includes the public key and other global state information.
    - `ping`: A constant pointer to the incoming ping message that contains a token to be used in the response.
    - `peer_addr`: A constant pointer to the peer address from which the ping was received, marked as unused in this function.
    - `self_ip4_addr`: The IPv4 address of the current node, marked as unused in this function.
    - `msg_buf`: A buffer to store the encoded pong message.
    - `msg_buf_sz`: The size of the message buffer.
- **Control Flow**:
    - Initialize a repair protocol structure and set it to a pong response type.
    - Copy the public key from the global context to the pong message.
    - Create a pre-image by concatenating a fixed string and the token from the ping message.
    - Hash the pre-image using SHA-256 to generate a response token for the pong message.
    - Sign the pre-image using the repair signer function with a specific signature type.
    - Set up a binary encoding context with the message buffer and its size.
    - Encode the protocol structure into the message buffer and check for successful encoding.
    - Calculate the length of the encoded message by subtracting the start of the buffer from the current position in the encoding context.
    - Return the length of the encoded message.
- **Output**: The function returns the length of the encoded pong message as an unsigned long integer.
- **Functions called**:
    - [`repair_signer`](#repair_signer)


---
### fd\_repair\_recv\_clnt\_packet<!-- {{#callable:fd_repair_recv_clnt_packet}} -->
The `fd_repair_recv_clnt_packet` function processes incoming client packets in the repair protocol, handling specific message types and responding accordingly.
- **Inputs**:
    - `repair_tile_ctx`: A pointer to the repair tile context, which contains state and configuration for the repair protocol.
    - `glob`: A pointer to the global repair structure, which holds metrics and other global state.
    - `msg`: A pointer to the message data received from the client.
    - `msglen`: The length of the message data.
    - `src_addr`: A pointer to the source address structure, which contains the address and port of the sender.
    - `dst_ip4_addr`: The destination IPv4 address for the packet.
- **Control Flow**:
    - Increment the received client packet metric in the global structure.
    - Begin a scratch memory scope for temporary allocations.
    - Enter a loop to process the message.
    - Attempt to decode the message using `fd_bincode_decode1_scratch`.
    - If decoding fails or the decoded size does not match the message length, break the loop.
    - Switch on the message discriminant to handle different message types.
    - For a 'ping' message, handle it using [`fd_repair_handle_ping`](#fd_repair_handle_ping), then send a response packet using [`send_packet`](#send_packet).
    - End the scratch memory scope.
    - Return 0 to indicate successful processing.
- **Output**: The function returns an integer, always 0, indicating successful processing of the client packet.
- **Functions called**:
    - [`fd_repair_handle_ping`](#fd_repair_handle_ping)
    - [`send_packet`](#send_packet)


---
### fd\_repair\_sign\_and\_send<!-- {{#callable:fd_repair_sign_and_send}} -->
The `fd_repair_sign_and_send` function encodes, signs, and prepares a repair protocol message for sending.
- **Inputs**:
    - `repair_tile_ctx`: A pointer to the `fd_repair_tile_ctx_t` structure, which contains context information for the repair tile.
    - `protocol`: A pointer to the `fd_repair_protocol_t` structure, which represents the repair protocol message to be encoded and signed.
    - `addr`: A pointer to the `fd_gossip_peer_addr_t` structure, representing the address of the peer (unused in this function).
    - `buf`: A pointer to a buffer where the encoded message will be stored.
    - `buflen`: The length of the buffer, which must be at least 1024 bytes.
- **Control Flow**:
    - The function begins by asserting that the buffer length is at least 1024 bytes.
    - It initializes a `fd_bincode_encode_ctx_t` structure to manage the encoding context.
    - The function attempts to encode the protocol message into the buffer using `fd_repair_protocol_encode`. If encoding fails, it logs a critical error and exits.
    - The function calculates the length of the encoded message and checks if it is at least 68 bytes long, logging a critical error if not.
    - It copies the first 4 bytes of the buffer to the position starting at byte 64, effectively shifting the buffer content.
    - The buffer pointer is adjusted to skip the first 64 bytes, and the buffer length is reduced by 64 bytes.
    - A signature is generated using the [`repair_signer`](#repair_signer) function, which signs the message with the ED25519 algorithm.
    - The buffer pointer and length are restored to their original values, and the signature is inserted into the buffer at position 4.
    - The function returns the final length of the buffer, which includes the signature.
- **Output**: The function returns the length of the buffer after encoding and signing the message.
- **Functions called**:
    - [`repair_signer`](#repair_signer)


---
### fd\_repair\_send\_request<!-- {{#callable:fd_repair_send_request}} -->
The `fd_repair_send_request` function constructs and sends a repair request packet to a specified recipient, updating relevant statistics and metrics.
- **Inputs**:
    - `repair_tile_ctx`: A pointer to the `fd_repair_tile_ctx_t` structure, which contains context information for the repair tile.
    - `glob`: A pointer to the `fd_repair_t` structure, representing the global repair state.
    - `type`: An enumeration value of type `fd_needed_elem_type`, indicating the type of element needed for the repair request.
    - `slot`: An unsigned long integer representing the slot number for which the repair request is being made.
    - `shred_index`: An unsigned integer representing the index of the shred within the slot.
    - `recipient`: A pointer to a `fd_pubkey_t` structure representing the public key of the recipient of the repair request.
    - `now`: A long integer representing the current time, used for timestamping the request.
- **Control Flow**:
    - Initialize a `fd_repair_protocol_t` structure to construct the repair request protocol.
    - Call `fd_repair_construct_request_protocol` to populate the protocol with the necessary information, including the type, slot, shred index, recipient, and current nonce.
    - Increment the `next_nonce` in the global repair state (`glob`).
    - Query the active table to get the active element associated with the recipient's public key.
    - Increment the average requests count for the active element and the send packet count in the global metrics.
    - Prepare a buffer to hold the signed request packet.
    - Call [`fd_repair_sign_and_send`](#fd_repair_sign_and_send) to sign the protocol and prepare it for sending, storing the result in the buffer.
    - Compute the original timestamp using `fd_frag_meta_ts_comp` and the current tick count.
    - Send the packet using [`send_packet`](#send_packet), specifying the recipient's address and port, the source IP address, the buffer, its length, and the original timestamp.
- **Output**: The function does not return a value; it performs its operations as side effects, such as sending a network packet and updating statistics.
- **Functions called**:
    - [`fd_repair_sign_and_send`](#fd_repair_sign_and_send)
    - [`send_packet`](#send_packet)


---
### fd\_repair\_send\_requests<!-- {{#callable:fd_repair_send_requests}} -->
The `fd_repair_send_requests` function sends repair requests to a specified number of peers for a given slot and shred index.
- **Inputs**:
    - `ctx`: A pointer to the `fd_repair_tile_ctx_t` structure, which contains the context for the repair tile.
    - `type`: An enumeration value of type `fd_needed_elem_type` indicating the type of element needed for repair.
    - `slot`: An unsigned long integer representing the slot number for which the repair request is being sent.
    - `shred_index`: An unsigned integer representing the index of the shred for which the repair request is being sent.
    - `now`: A long integer representing the current time, used for timestamping the request.
- **Control Flow**:
    - Retrieve the global repair context from the provided tile context `ctx`.
    - Iterate over a fixed number of peers (`FD_REPAIR_NUM_NEEDED_PEERS`).
    - For each peer, retrieve the peer's public key from the global context and increment the peer index.
    - Call [`fd_repair_send_request`](#fd_repair_send_request) to send a repair request to the current peer using the provided parameters.
    - If the peer index exceeds the total number of peers, reset the peer index to zero to wrap around.
- **Output**: The function does not return a value; it performs its operations by sending requests to peers.
- **Functions called**:
    - [`fd_repair_send_request`](#fd_repair_send_request)


---
### before\_frag<!-- {{#callable:before_frag}} -->
The `before_frag` function checks if a fragment should be processed based on its input kind and signature protocol.
- **Inputs**:
    - `ctx`: A pointer to a `fd_repair_tile_ctx_t` structure, which contains context information for the repair tile.
    - `in_idx`: An unsigned long integer representing the index of the input link being processed.
    - `seq`: An unsigned long integer representing the sequence number, which is unused in this function.
    - `sig`: An unsigned long integer representing the signature of the fragment.
- **Control Flow**:
    - Retrieve the input kind from the context using the provided index `in_idx`.
    - Check if the input kind is `IN_KIND_NET` using a likely branch prediction macro `FD_LIKELY`.
    - If the input kind is `IN_KIND_NET`, call `fd_disco_netmux_sig_proto` with the signature `sig` and compare the result to `DST_PROTO_REPAIR`.
    - Return the result of the comparison as a boolean integer (1 if not equal, 0 if equal).
    - If the input kind is not `IN_KIND_NET`, return 0.
- **Output**: The function returns an integer, 1 if the fragment should be processed (i.e., the signature protocol is not `DST_PROTO_REPAIR` for network input kind), and 0 otherwise.


---
### is\_fec\_completes\_msg<!-- {{#callable:is_fec_completes_msg}} -->
The function `is_fec_completes_msg` checks if a given size matches the sum of predefined constants `FD_SHRED_DATA_HEADER_SZ` and `FD_SHRED_MERKLE_ROOT_SZ`.
- **Inputs**:
    - `sz`: An unsigned long integer representing the size to be checked.
- **Control Flow**:
    - The function takes a single input `sz`.
    - It compares `sz` to the sum of `FD_SHRED_DATA_HEADER_SZ` and `FD_SHRED_MERKLE_ROOT_SZ`.
    - If `sz` equals this sum, the function returns true (non-zero).
    - Otherwise, it returns false (zero).
- **Output**: The function returns an integer: 1 if the size matches the expected sum, otherwise 0.


---
### during\_frag<!-- {{#callable:during_frag}} -->
The `during_frag` function processes a fragment of data based on its type and stores it in a buffer for further handling.
- **Inputs**:
    - `ctx`: A pointer to the `fd_repair_tile_ctx_t` structure, which contains context information for the repair tile.
    - `in_idx`: An unsigned long integer representing the index of the input link from which the fragment is received.
    - `seq`: An unsigned long integer representing the sequence number of the fragment (unused in this function).
    - `sig`: An unsigned long integer representing the signature of the fragment (unused in this function).
    - `chunk`: An unsigned long integer representing the chunk identifier of the fragment.
    - `sz`: An unsigned long integer representing the size of the fragment.
    - `ctl`: An unsigned long integer representing control information for the fragment.
- **Control Flow**:
    - Initialize `ctx->skip_frag` to 0, indicating that the fragment should not be skipped.
    - Determine the kind of input link using `ctx->in_kind[in_idx]` and retrieve the corresponding context `in_ctx`.
    - If the input kind is `IN_KIND_NET`, translate the fragment using `fd_net_rx_translate_frag` and set `dcache_entry_sz` to `sz`.
    - If the input kind is `IN_KIND_CONTACT`, check if the chunk is within the valid range; if not, log an error. Translate the chunk to a local address and set `dcache_entry_sz` to `sz * sizeof(fd_shred_dest_wire_t)`.
    - If the input kind is `IN_KIND_STAKE`, check if the chunk is within the valid range; if not, log an error. Translate the chunk to a local address, initialize a stake message, and return immediately.
    - If the input kind is `IN_KIND_SHRED`, check if the chunk is within the valid range; if not, log an error. Translate the chunk to a local address and set `dcache_entry_sz` to `sz`.
    - If the input kind is unknown, log an error indicating an unknown link kind.
    - Copy the data from `dcache_entry` to `ctx->buffer` using `fd_memcpy`.
- **Output**: The function does not return a value; it modifies the `ctx->buffer` with the processed fragment data.


---
### fd\_repair\_send\_ping<!-- {{#callable:fd_repair_send_ping}} -->
The `fd_repair_send_ping` function constructs and sends a ping message as part of the repair protocol for a Firedancer node.
- **Inputs**:
    - `repair_tile_ctx`: A pointer to the `fd_repair_tile_ctx_t` structure, which contains context information for the repair tile.
    - `glob`: A pointer to the `fd_repair_t` structure, representing the global repair state.
    - `val`: A pointer to the `fd_pinged_elem_t` structure, which contains information about the pinged element, including a token.
    - `buf`: A pointer to a buffer where the encoded ping message will be stored.
    - `buflen`: The length of the buffer `buf`.
- **Control Flow**:
    - Initialize a `fd_repair_response_t` structure `gmsg` and set it to a ping response type.
    - Set the `from` field of the ping message to the public key from `glob`.
    - Create a pre-image by concatenating a fixed string "SOLANA_PING_PONG" and the token from `val`.
    - Compute a SHA-256 hash of the pre-image and store it in the `token` field of the ping message.
    - Sign the pre-image using the [`repair_signer`](#repair_signer) function, storing the signature in the `signature` field of the ping message.
    - Initialize a `fd_bincode_encode_ctx_t` structure `ctx` for encoding the message into the buffer.
    - Check that the buffer length is at least 1024 bytes.
    - Encode the `gmsg` into the buffer using `fd_repair_response_encode`.
    - Return the number of bytes written to the buffer.
- **Output**: The function returns the number of bytes written to the buffer, representing the size of the encoded ping message.
- **Functions called**:
    - [`repair_signer`](#repair_signer)


---
### fd\_repair\_recv\_pong<!-- {{#callable:fd_repair_recv_pong}} -->
The `fd_repair_recv_pong` function processes a 'pong' message in the repair protocol, verifying its authenticity and updating the status of the sender if the verification is successful.
- **Inputs**:
    - `glob`: A pointer to an `fd_repair_t` structure representing the global repair state.
    - `pong`: A constant pointer to an `fd_gossip_ping_t` structure representing the pong message received.
    - `from`: A constant pointer to an `fd_gossip_peer_addr_t` structure representing the address of the sender of the pong message.
- **Control Flow**:
    - Query the `pinged` table in `glob` using `from` to find the corresponding `fd_pinged_elem_t` entry.
    - Check if the entry is `NULL` or if the public key in the entry does not match the public key in `pong`; if so, return immediately.
    - Create a pre-image by concatenating a fixed string 'SOLANA_PING_PONG' and the token from the `fd_pinged_elem_t` entry.
    - Compute the SHA-256 hash of the pre-image to get `pre_image_hash`.
    - Initialize a SHA-256 context, append the fixed string and `pre_image_hash`, and finalize to get the `golden` hash.
    - Verify the signature in `pong` using the `golden` hash and the public key from `pong`; if verification fails, log a warning and return.
    - If verification succeeds, set the `good` field of the `fd_pinged_elem_t` entry to 1.
- **Output**: The function does not return a value; it updates the `good` field of the `fd_pinged_elem_t` entry if the pong message is verified successfully.


---
### repair\_get\_shred<!-- {{#callable:repair_get_shred}} -->
The `repair_get_shred` function retrieves a shred from a blockstore for a given slot and shred index, handling special cases where the shred index is unspecified.
- **Inputs**:
    - `slot`: The slot number from which to retrieve the shred.
    - `shred_idx`: The index of the shred to retrieve; if set to UINT_MAX, the function will determine the appropriate index.
    - `buf`: A buffer where the retrieved shred data will be copied.
    - `buf_max`: The maximum size of the buffer.
    - `arg`: A context argument, expected to be a pointer to `fd_repair_tile_ctx_t`, which contains the blockstore information.
- **Control Flow**:
    - Cast the `arg` parameter to `fd_repair_tile_ctx_t` to access the blockstore.
    - Check if the blockstore is NULL; if so, return -1 indicating an error.
    - If `shred_idx` is UINT_MAX, enter a loop to determine the correct shred index by querying the blockstore's block map.
    - Within the loop, attempt to query the block map for the slot; if the error is `FD_MAP_ERR_KEY`, return -1, if `FD_MAP_ERR_AGAIN`, continue the loop.
    - Once a valid shred index is found, exit the loop and proceed to retrieve the shred data.
    - Call `fd_buf_shred_query_copy_data` to copy the shred data into the provided buffer.
    - Return the size of the copied shred data.
- **Output**: Returns the size of the shred data copied into the buffer, or -1 if an error occurs.


---
### repair\_get\_parent<!-- {{#callable:repair_get_parent}} -->
The `repair_get_parent` function retrieves the parent slot of a given slot from a blockstore, returning a null slot if the blockstore is unavailable.
- **Inputs**:
    - `slot`: The slot number for which the parent slot is to be retrieved.
    - `arg`: A pointer to a context structure (`fd_repair_tile_ctx_t`) that contains the blockstore information.
- **Control Flow**:
    - Cast the `arg` parameter to a `fd_repair_tile_ctx_t` pointer to access the context.
    - Retrieve the blockstore from the context.
    - Check if the blockstore is `NULL`; if so, return `FD_SLOT_NULL`.
    - If the blockstore is not `NULL`, call `fd_blockstore_parent_slot_query` with the blockstore and slot to get the parent slot.
- **Output**: Returns the parent slot of the given slot from the blockstore, or `FD_SLOT_NULL` if the blockstore is `NULL`.


---
### fd\_repair\_recv\_serv\_packet<!-- {{#callable:fd_repair_recv_serv_packet}} -->
The `fd_repair_recv_serv_packet` function processes incoming service packets for a repair protocol, verifying their integrity and responding appropriately based on the packet type.
- **Inputs**:
    - `repair_tile_ctx`: A pointer to the context of the repair tile, which contains state and configuration for the repair process.
    - `glob`: A pointer to the global repair structure that holds metrics and other shared data.
    - `msg`: A pointer to the message buffer containing the incoming packet data.
    - `msglen`: The length of the incoming message in bytes.
    - `peer_addr`: A pointer to the address structure of the peer that sent the packet.
    - `self_ip4_addr`: The IPv4 address of the local node receiving the packet.
- **Control Flow**:
    - Begin a scratch memory scope for temporary allocations.
    - Decode the incoming message using `fd_bincode_decode1_scratch` to obtain a protocol structure.
    - If decoding fails, increment the corrupt packet metric and log a warning, then return 0.
    - Increment the received service packet metric.
    - Check if the decoded size matches the message length; if not, log a warning and return 0.
    - Switch on the protocol's discriminant to handle different packet types (pong, window index, highest window index, orphan, unknown).
    - For each known packet type, update the corresponding metric and handle the packet appropriately.
    - Verify the recipient's public key matches the expected public key; if not, log a warning and return 0.
    - Verify the packet's signature using `fd_ed25519_verify`; if invalid, increment the invalid signature metric, log a warning, and return 0.
    - Query the pinged table to check if the peer is known and good; if not, prepare to ping the client.
    - If the pinged table is full, log a warning, increment the full ping table metric, and return 0.
    - If the peer is not known or not good, insert it into the pinged table and send a ping request.
    - If the peer is known and good, handle the packet based on its type, potentially sending a response packet.
    - End the scratch memory scope.
- **Output**: The function returns an integer, always 0, indicating the completion of packet processing.
- **Functions called**:
    - [`fd_repair_recv_pong`](#fd_repair_recv_pong)
    - [`fd_repair_send_ping`](#fd_repair_send_ping)
    - [`send_packet`](#send_packet)
    - [`repair_get_shred`](#repair_get_shred)
    - [`repair_get_parent`](#repair_get_parent)


---
### after\_frag<!-- {{#callable:after_frag}} -->
The `after_frag` function processes fragments based on their type, updating context and handling specific actions for contact, stake, and shred fragments.
- **Inputs**:
    - `ctx`: A pointer to the `fd_repair_tile_ctx_t` structure, which holds the context for the repair tile.
    - `in_idx`: An unsigned long integer representing the index of the input fragment.
    - `seq`: An unsigned long integer representing the sequence number of the fragment (unused in this function).
    - `sig`: An unsigned long integer representing the signature of the fragment (unused in this function).
    - `sz`: An unsigned long integer representing the size of the fragment.
    - `tsorig`: An unsigned long integer representing the original timestamp of the fragment.
    - `tspub`: An unsigned long integer representing the publication timestamp of the fragment (unused in this function).
    - `stem`: A pointer to the `fd_stem_context_t` structure, which is used for publishing data.
- **Control Flow**:
    - Check if `ctx->skip_frag` is true, and return immediately if so.
    - Set `ctx->stem` to the provided `stem` pointer.
    - Retrieve the kind of input from `ctx->in_kind[in_idx]`.
    - If the input kind is `IN_KIND_CONTACT`, call [`handle_new_cluster_contact_info`](#handle_new_cluster_contact_info) with the context, buffer, and size, then return.
    - If the input kind is `IN_KIND_STAKE`, finalize the stake message and call [`handle_new_stake_weights`](#handle_new_stake_weights), then return.
    - If the input kind is `IN_KIND_SHRED`, perform several operations to initialize and update the forest and FEC chainer, handle FEC completion messages, and insert shreds into the forest.
    - If the input kind is not recognized, process the fragment as a network packet, checking UDP header and size, and call appropriate functions based on the destination port.
- **Output**: The function does not return a value; it performs operations on the context and potentially modifies the state of the system.
- **Functions called**:
    - [`handle_new_cluster_contact_info`](#handle_new_cluster_contact_info)
    - [`handle_new_stake_weights`](#handle_new_stake_weights)
    - [`fd_fec_chainer_init`](fd_fec_chainer.c.driver.md#fd_fec_chainer_init)
    - [`is_fec_completes_msg`](#is_fec_completes_msg)
    - [`fd_fec_chainer_insert`](fd_fec_chainer.c.driver.md#fd_fec_chainer_insert)
    - [`fd_repair_recv_clnt_packet`](#fd_repair_recv_clnt_packet)
    - [`fd_repair_recv_serv_packet`](#fd_repair_recv_serv_packet)


---
### after\_credit<!-- {{#callable:after_credit}} -->
The `after_credit` function manages the repair process by sending requests for missing data in a network of nodes, ensuring that the node is marked as busy if work is done, and updating the network sequence.
- **Inputs**:
    - `ctx`: A pointer to a `fd_repair_tile_ctx_t` structure, which contains the context for the repair tile, including timestamps, repair configuration, and network information.
    - `stem`: A pointer to a `fd_stem_context_t` structure, which is unused in this function.
    - `opt_poll_in`: A pointer to an integer, which is unused in this function.
    - `charge_busy`: A pointer to an integer that indicates whether the tile should be marked as busy.
- **Control Flow**:
    - Set `charge_busy` to 1 to indicate the tile is busy.
    - Get the current wall clock time and check if enough time has passed since the last repair; if not, return early.
    - Update the repair timestamp in the context.
    - Check if the forest root is uninitialized or if there are no peers to send requests to; if so, return early.
    - Initialize variables for the forest, pool, frontier, and orphaned elements.
    - Iterate over the frontier elements to send requests for missing data, breaking if the maximum number of requests per credit is exceeded.
    - Iterate over orphaned elements to send requests for missing data.
    - Update the network output sequence and continue the repair process.
- **Output**: The function does not return a value; it operates by modifying the state of the `ctx` and updating the `charge_busy` flag.
- **Functions called**:
    - [`fd_repair_send_requests`](#fd_repair_send_requests)


---
### during\_housekeeping<!-- {{#callable:during_housekeeping}} -->
The `during_housekeeping` function performs periodic maintenance tasks for a repair tile context, including updating timestamps and printing forest information.
- **Inputs**:
    - `ctx`: A pointer to a `fd_repair_tile_ctx_t` structure, which contains the context for the repair tile, including timestamps, forest, and other relevant data.
- **Control Flow**:
    - Call `fd_repair_settime` to update the repair time with the current wall clock time.
    - Retrieve the current wall clock time and store it in `now`.
    - Check if the time since the last print (`ctx->tsprint`) exceeds one second; if so, print the forest and update `ctx->tsprint` with the current time.
    - Check if `ctx->stem` is NULL; if it is, return immediately without further processing.
- **Output**: The function does not return any value; it performs operations directly on the `ctx` structure.


---
### privileged\_init<!-- {{#callable:privileged_init}} -->
The `privileged_init` function initializes a repair tile context with security-sensitive operations, including loading identity keys and setting up file descriptors for peer cache management.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology of the system.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile (or node) in the topology to be initialized.
- **Control Flow**:
    - Retrieve a scratch memory address using `fd_topo_obj_laddr` with the topology and tile object ID.
    - Initialize a scratch allocator with `FD_SCRATCH_ALLOC_INIT`.
    - Allocate memory for a `fd_repair_tile_ctx_t` context structure using `FD_SCRATCH_ALLOC_APPEND`.
    - Zero out the allocated context structure using `fd_memset`.
    - Load the identity key from the path specified in `tile->repair.identity_key_path` using `fd_keyload_load`.
    - Copy the loaded identity key into the context's private and public key fields.
    - Set the repair configuration's private and public keys in the context.
    - Open the good peer cache file specified in `tile->repair.good_peer_cache_file` with read/write and create permissions.
    - Log a warning if opening the file fails, using `FD_LOG_WARNING`.
    - Assign the file descriptor to the context's repair configuration.
    - Generate a secure random seed for the context's repair seed using `fd_rng_secure`.
- **Output**: This function does not return a value; it performs initialization operations on the provided tile and context.


---
### unprivileged\_init<!-- {{#callable:unprivileged_init}} -->
The `unprivileged_init` function initializes the context and resources for a repair tile in a Firedancer node, setting up input and output links, memory allocations, and various components necessary for the repair protocol.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology of the Firedancer node.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile configuration within the topology.
- **Control Flow**:
    - Allocate scratch memory for the repair tile context and initialize it.
    - Check if the number of input links exceeds the maximum allowed and log an error if so.
    - Iterate over input links to determine their type and initialize corresponding context structures.
    - Check for the presence of a 'sign_repair' input link and log an error if missing.
    - Iterate over output links to configure network, sign, replay, and shred output contexts.
    - Check for the presence of a 'gossip_sign' output link and log an error if missing.
    - Allocate and initialize various components such as blockstore, repair, forest, FEC signatures, reassembly, and FEC chainer.
    - Set up network headers for intake and serve addresses.
    - Initialize the keyguard client for signing operations.
    - Join the blockstore workspace and log an error if it is missing.
    - Join and initialize repair, forest, FEC signatures, reassembly, and FEC chainer components.
    - Set up turbine slot and root slot sequences and update them.
    - Configure the repair component with the necessary addresses and settings.
    - Finalize scratch memory allocation and check for overflow errors.
- **Output**: The function does not return a value; it initializes the repair tile context and its associated resources.
- **Functions called**:
    - [`fd_fec_chainer_align`](fd_fec_chainer.h.driver.md#fd_fec_chainer_align)
    - [`fd_fec_chainer_footprint`](fd_fec_chainer.h.driver.md#fd_fec_chainer_footprint)
    - [`fd_fec_chainer_join`](fd_fec_chainer.c.driver.md#fd_fec_chainer_join)
    - [`fd_fec_chainer_new`](fd_fec_chainer.c.driver.md#fd_fec_chainer_new)
    - [`scratch_footprint`](#scratch_footprint)


---
### populate\_allowed\_seccomp<!-- {{#callable:populate_allowed_seccomp}} -->
The `populate_allowed_seccomp` function configures a seccomp filter policy for a repair tile by populating a given array of socket filters.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, which is unused in this function.
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure, representing the tile configuration.
    - `out_cnt`: An unsigned long integer representing the count of output socket filters.
    - `out`: A pointer to an array of `struct sock_filter` where the seccomp filter policy will be populated.
- **Control Flow**:
    - The function calls [`populate_sock_filter_policy_fd_repair_tile`](generated/fd_repair_tile_seccomp.h.driver.md#populate_sock_filter_policy_fd_repair_tile) with `out_cnt`, `out`, the file descriptor for the log file, and the file descriptor for the good peer cache file from the `tile` structure.
    - The function returns the constant `sock_filter_policy_fd_repair_tile_instr_cnt`.
- **Output**: The function returns an unsigned long integer representing the instruction count for the seccomp filter policy.
- **Functions called**:
    - [`populate_sock_filter_policy_fd_repair_tile`](generated/fd_repair_tile_seccomp.h.driver.md#populate_sock_filter_policy_fd_repair_tile)


---
### populate\_allowed\_fds<!-- {{#callable:populate_allowed_fds}} -->
The `populate_allowed_fds` function populates an array with file descriptors that are allowed for use, specifically including standard error, a log file, and a good peer cache file if they are available.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, which is unused in this function.
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure, which contains information about the tile, including the file descriptor for the good peer cache file.
    - `out_fds_cnt`: An unsigned long integer representing the maximum number of file descriptors that can be stored in the `out_fds` array.
    - `out_fds`: A pointer to an integer array where the allowed file descriptors will be stored.
- **Control Flow**:
    - Check if `out_fds_cnt` is less than 2, and if so, log an error and terminate the program.
    - Initialize `out_cnt` to 0 and set the first element of `out_fds` to 2, which corresponds to the standard error file descriptor.
    - Check if the log file descriptor is valid (not -1) and, if so, add it to `out_fds`.
    - Check if the good peer cache file descriptor from the `tile` is valid (not -1) and, if so, add it to `out_fds`.
    - Return the count of file descriptors added to `out_fds`.
- **Output**: Returns the number of file descriptors added to the `out_fds` array as an unsigned long integer.


---
### fd\_repair\_update\_repair\_metrics<!-- {{#callable:fd_repair_update_repair_metrics}} -->
The `fd_repair_update_repair_metrics` function updates various repair metrics by setting and copying values from a `fd_repair_metrics_t` structure.
- **Inputs**:
    - `metrics`: A pointer to a `fd_repair_metrics_t` structure containing the repair metrics to be updated.
- **Control Flow**:
    - The function begins by setting the `RECV_CLNT_PKT` metric using the `recv_clnt_pkt` value from the `metrics` structure.
    - It sets the `RECV_SERV_PKT` metric using the `recv_serv_pkt` value from the `metrics` structure.
    - The function sets the `RECV_SERV_CORRUPT_PKT` metric using the `recv_serv_corrupt_pkt` value from the `metrics` structure.
    - It sets the `RECV_SERV_INVALID_SIGNATURE` metric using the `recv_serv_invalid_signature` value from the `metrics` structure.
    - The function sets the `RECV_SERV_FULL_PING_TABLE` metric using the `recv_serv_full_ping_table` value from the `metrics` structure.
    - It copies the `RECV_SERV_PKT_TYPES` metrics using the `recv_serv_pkt_types` array from the `metrics` structure.
    - The function sets the `RECV_PKT_CORRUPTED_MSG` metric using the `recv_pkt_corrupted_msg` value from the `metrics` structure.
    - It sets the `SEND_PKT_CNT` metric using the `send_pkt_cnt` value from the `metrics` structure.
    - Finally, it copies the `SENT_PKT_TYPES` metrics using the `sent_pkt_types` array from the `metrics` structure.
- **Output**: The function does not return any value; it updates the repair metrics in place.


---
### metrics\_write<!-- {{#callable:metrics_write}} -->
The `metrics_write` function updates repair-protocol-specific metrics for a given repair tile context.
- **Inputs**:
    - `ctx`: A pointer to an `fd_repair_tile_ctx_t` structure, which contains the context for a repair tile, including repair protocol metrics.
- **Control Flow**:
    - The function calls `fd_repair_get_metrics` with the repair context from `ctx` to retrieve the current repair metrics.
    - It then calls [`fd_repair_update_repair_metrics`](#fd_repair_update_repair_metrics) with the retrieved metrics to update the repair-protocol-specific metrics.
- **Output**: This function does not return any value; it performs an update operation on the metrics.
- **Functions called**:
    - [`fd_repair_update_repair_metrics`](#fd_repair_update_repair_metrics)



# Purpose
The provided C source code file implements a component of a Firedancer node that runs the gossip networking protocol. This file is part of a larger system and is designed to handle the dissemination of information across a network of nodes using the gossip protocol. The code is structured to manage various aspects of the gossip protocol, including sending and receiving packets, handling different types of gossip messages, and maintaining a contact information table for peer nodes. It also includes functionality for signing messages, managing metrics, and interfacing with other components of the system through defined input and output links.

The file is a comprehensive implementation of a gossip tile, which is a modular component within the Firedancer architecture. It integrates with other system components through a series of defined interfaces and utilizes various utility functions and data structures to manage network communication and data integrity. The code defines several key structures, such as `fd_gossip_tile_ctx_t`, which encapsulates the state and configuration of the gossip tile, and functions for processing incoming and outgoing messages. The file also includes setup and initialization routines for configuring the gossip protocol, managing memory and resources, and ensuring secure and efficient operation within the network. This code is intended to be part of a larger system, likely compiled and linked with other components to form a complete executable or library.
# Imports and Dependencies

---
- `../../disco/topo/fd_topo.h`
- `generated/fd_gossip_tile_seccomp.h`
- `../restart/fd_restart.h`
- `../../disco/fd_disco.h`
- `../../disco/keyguard/fd_keyload.h`
- `../../disco/keyguard/fd_keyguard_client.h`
- `../../disco/net/fd_net_tile.h`
- `../../flamenco/gossip/fd_gossip.h`
- `../../flamenco/runtime/fd_system_ids.h`
- `../../flamenco/runtime/fd_runtime.h`
- `../../util/pod/fd_pod.h`
- `../../util/net/fd_ip4.h`
- `../../util/net/fd_udp.h`
- `../../util/net/fd_net_headers.h`
- `../../disco/plugin/fd_plugin.h`
- `unistd.h`
- `arpa/inet.h`
- `linux/unistd.h`
- `sys/random.h`
- `netdb.h`
- `netinet/in.h`
- `sys/socket.h`
- `../../util/tmpl/fd_map_giant.c`
- `../../disco/stem/fd_stem.c`


# Global Variables

---
### fd\_shred\_version
- **Type**: `volatile ulong*`
- **Description**: `fd_shred_version` is a static volatile pointer to an unsigned long integer, indicating that it is a global variable intended to store a shred version number. The use of `volatile` suggests that this variable may be modified by different threads or hardware, and thus, its value should not be cached by the compiler.
- **Use**: This variable is used to store and update the current shred version for the gossip protocol in the Firedancer node.


---
### fd\_tile\_gossip
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_gossip` is a global variable of type `fd_topo_run_tile_t` that represents a configuration for running a gossip tile in the Firedancer node. It is initialized with various function pointers and parameters that define the behavior and setup of the gossip protocol within the node.
- **Use**: This variable is used to configure and manage the execution of the gossip protocol tile, which is responsible for handling networking and communication tasks in the Firedancer node.


# Data Structures

---
### fd\_contact\_info\_elem
- **Type**: `struct`
- **Members**:
    - `key`: A public key of type `fd_pubkey_t` associated with the contact information.
    - `next`: An unsigned long integer used to point to the next element in a linked list or similar structure.
    - `contact_info`: A structure of type `fd_gossip_contact_info_v1_t` containing detailed contact information.
- **Description**: The `fd_contact_info_elem` structure is designed to store contact information for a node in a gossip network. It includes a public key (`key`) to identify the node, a `next` field for linking elements in a data structure, and a `contact_info` field that holds detailed contact information about the node, such as network addresses and other metadata. This structure is used within a contact information table to manage and query node contact details efficiently in a gossip protocol context.


---
### fd\_contact\_info\_elem\_t
- **Type**: `struct`
- **Members**:
    - `key`: Stores the public key associated with the contact information.
    - `next`: Holds the index of the next element in the contact info table, used for chaining in hash tables.
    - `contact_info`: Contains the contact information of a node in the gossip network.
- **Description**: The `fd_contact_info_elem_t` structure is used to represent an element in a contact information table within a gossip network protocol. It includes a public key to identify the node, a 'next' field for linking elements in a hash table, and a `contact_info` field that stores the actual contact information of the node, which is crucial for maintaining and querying the network topology.


---
### fd\_gossip\_tile\_metrics
- **Type**: `struct`
- **Members**:
    - `last_crds_push_contact_info_publish_ts`: Stores the timestamp of the last CRDS push contact info publish.
    - `mismatched_contact_info_shred_version`: Counts the number of mismatched contact info shred versions.
    - `ipv6_contact_info`: Array storing metrics for IPv6 contact info segmented by TVU, Repair, and Send.
    - `zero_ipv4_contact_info`: Array storing metrics for zero IPv4 contact info segmented by TVU, Repair, and Send.
    - `peer_counts`: Array storing peer counts segmented by TVU, Repair, and Send.
    - `shred_version_zero`: Counts the number of times the shred version is zero.
- **Description**: The `fd_gossip_tile_metrics` structure is designed to track various metrics related to the gossip protocol operations within a Firedancer node. It includes timestamps for the last contact info publish, counts of mismatched shred versions, and segmented metrics for IPv6 and zero IPv4 contact info. Additionally, it tracks peer counts and the occurrence of zero shred versions, providing a comprehensive overview of the gossip protocol's performance and potential issues.


---
### fd\_gossip\_tile\_metrics\_t
- **Type**: `struct`
- **Members**:
    - `last_crds_push_contact_info_publish_ts`: Stores the timestamp of the last CRDS push contact info publish.
    - `mismatched_contact_info_shred_version`: Counts the number of mismatched contact info shred versions.
    - `ipv6_contact_info`: Array storing metrics for IPv6 contact info segmented by TVU, Repair, and Send.
    - `zero_ipv4_contact_info`: Array storing metrics for zero IPv4 contact info segmented by TVU, Repair, and Send.
    - `peer_counts`: Array storing the count of peers segmented by TVU, Repair, and Send.
    - `shred_version_zero`: Counts the number of times the shred version is zero.
- **Description**: The `fd_gossip_tile_metrics_t` structure is designed to hold various metrics related to the operation of a gossip tile in a Firedancer node. It includes timestamps for the last contact info publish, counters for mismatched shred versions, and segmented metrics for IPv6 and zero IPv4 contact info. Additionally, it tracks peer counts and the occurrence of zero shred versions, providing a comprehensive overview of the gossip tile's performance and network interactions.


---
### fd\_gossip\_in\_ctx\_t
- **Type**: `union`
- **Members**:
    - `mem`: A pointer to an fd_wksp_t structure, representing a memory workspace.
    - `chunk0`: An unsigned long integer representing the starting chunk index.
    - `wmark`: An unsigned long integer representing the watermark or limit for chunks.
    - `net_rx`: An fd_net_rx_bounds_t structure used for network receive bounds.
- **Description**: The `fd_gossip_in_ctx_t` is a union data structure that serves dual purposes in the context of the Firedancer gossip protocol. It can either represent a memory workspace with associated chunk management through its `mem`, `chunk0`, and `wmark` members, or it can encapsulate network receive bounds using the `net_rx` member. This design allows for flexible handling of input contexts, either for memory management or network operations, within the gossip protocol's tile.


---
### fd\_gossip\_tile\_ctx
- **Type**: `struct`
- **Members**:
    - `gossip`: Pointer to the gossip instance used for networking.
    - `gossip_config`: Configuration settings for the gossip protocol.
    - `last_shred_dest_push_time`: Timestamp of the last shred destination push.
    - `last_plugin_push_time`: Timestamp of the last plugin push.
    - `gossip_seed`: Seed value for gossip operations.
    - `in_kind`: Array indicating the type of input links.
    - `in_links`: Array of input link contexts.
    - `contact_info_table`: Pointer to the contact information table.
    - `shred_contact_out_mcache`: Memory cache for outgoing shred contact information.
    - `shred_contact_out_sync`: Synchronization object for outgoing shred contact information.
    - `shred_contact_out_depth`: Depth of the outgoing shred contact information cache.
    - `shred_contact_out_seq`: Sequence number for outgoing shred contact information.
    - `shred_contact_out_mem`: Memory workspace for outgoing shred contact information.
    - `shred_contact_out_chunk0`: Initial chunk for outgoing shred contact information.
    - `shred_contact_out_wmark`: Watermark for outgoing shred contact information.
    - `shred_contact_out_chunk`: Current chunk for outgoing shred contact information.
    - `repair_contact_out_mcache`: Memory cache for outgoing repair contact information.
    - `repair_contact_out_sync`: Synchronization object for outgoing repair contact information.
    - `repair_contact_out_depth`: Depth of the outgoing repair contact information cache.
    - `repair_contact_out_seq`: Sequence number for outgoing repair contact information.
    - `repair_contact_out_mem`: Memory workspace for outgoing repair contact information.
    - `repair_contact_out_chunk0`: Initial chunk for outgoing repair contact information.
    - `repair_contact_out_wmark`: Watermark for outgoing repair contact information.
    - `repair_contact_out_chunk`: Current chunk for outgoing repair contact information.
    - `send_contact_out_mcache`: Memory cache for outgoing send contact information.
    - `send_contact_out_sync`: Synchronization object for outgoing send contact information.
    - `send_contact_out_depth`: Depth of the outgoing send contact information cache.
    - `send_contact_out_seq`: Sequence number for outgoing send contact information.
    - `send_contact_out_mem`: Memory workspace for outgoing send contact information.
    - `send_contact_out_chunk0`: Initial chunk for outgoing send contact information.
    - `send_contact_out_wmark`: Watermark for outgoing send contact information.
    - `send_contact_out_chunk`: Current chunk for outgoing send contact information.
    - `verify_out_mcache`: Memory cache for outgoing verification information.
    - `verify_out_sync`: Synchronization object for outgoing verification information.
    - `verify_out_depth`: Depth of the outgoing verification information cache.
    - `verify_out_seq`: Sequence number for outgoing verification information.
    - `verify_out_mem`: Memory workspace for outgoing verification information.
    - `verify_out_chunk0`: Initial chunk for outgoing verification information.
    - `verify_out_wmark`: Watermark for outgoing verification information.
    - `verify_out_chunk`: Current chunk for outgoing verification information.
    - `eqvoc_out_mcache`: Memory cache for outgoing EQVOC information.
    - `eqvoc_out_sync`: Synchronization object for outgoing EQVOC information.
    - `eqvoc_out_depth`: Depth of the outgoing EQVOC information cache.
    - `eqvoc_out_seq`: Sequence number for outgoing EQVOC information.
    - `eqvoc_out_mem`: Memory workspace for outgoing EQVOC information.
    - `eqvoc_out_chunk0`: Initial chunk for outgoing EQVOC information.
    - `eqvoc_out_wmark`: Watermark for outgoing EQVOC information.
    - `eqvoc_out_chunk`: Current chunk for outgoing EQVOC information.
    - `restart_out_mcache`: Memory cache for outgoing restart information.
    - `restart_out_sync`: Synchronization object for outgoing restart information.
    - `restart_out_depth`: Depth of the outgoing restart information cache.
    - `restart_out_seq`: Sequence number for outgoing restart information.
    - `restart_out_mem`: Memory workspace for outgoing restart information.
    - `restart_out_chunk0`: Initial chunk for outgoing restart information.
    - `restart_out_wmark`: Watermark for outgoing restart information.
    - `restart_out_chunk`: Current chunk for outgoing restart information.
    - `wksp`: Pointer to the workspace used by the context.
    - `gossip_my_addr`: Address of the gossip node.
    - `tvu_my_addr`: Address of the TVU node.
    - `tpu_my_addr`: Address of the TPU node.
    - `tpu_quic_my_addr`: Address of the TPU QUIC node.
    - `tpu_vote_my_addr`: Address of the TPU vote node.
    - `repair_serve_addr`: Address for repair services.
    - `gossip_listen_port`: Port number for gossip listening.
    - `net_out_mcache`: Memory cache for outgoing network information.
    - `net_out_sync`: Synchronization object for outgoing network information.
    - `net_out_depth`: Depth of the outgoing network information cache.
    - `net_out_seq`: Sequence number for outgoing network information.
    - `net_out_mem`: Memory workspace for outgoing network information.
    - `net_out_chunk0`: Initial chunk for outgoing network information.
    - `net_out_wmark`: Watermark for outgoing network information.
    - `net_out_chunk`: Current chunk for outgoing network information.
    - `gossip_plugin_out_mem`: Memory workspace for outgoing plugin information.
    - `gossip_plugin_out_chunk0`: Initial chunk for outgoing plugin information.
    - `gossip_plugin_out_wmark`: Watermark for outgoing plugin information.
    - `gossip_plugin_out_chunk`: Current chunk for outgoing plugin information.
    - `gossip_plugin_out_idx`: Index for outgoing plugin information.
    - `identity_private_key`: Private key for identity verification.
    - `identity_public_key`: Public key for identity verification.
    - `gossip_buffer`: Buffer for storing gossip messages.
    - `net_id`: Network identifier.
    - `hdr`: Headers for IP and UDP packets.
    - `keyguard_client`: Client for keyguard operations.
    - `stem`: Pointer to the stem context.
    - `replay_vote_txn_sz`: Size of the replay vote transaction.
    - `replay_vote_txn`: Buffer for replay vote transaction data.
    - `restart_last_push_time`: Timestamp of the last restart push.
    - `restart_last_vote_msg_sz`: Size of the last vote message for restart.
    - `restart_heaviest_fork_msg_sz`: Size of the heaviest fork message for restart.
    - `restart_heaviest_fork_msg`: Buffer for the heaviest fork message for restart.
    - `restart_last_vote_msg`: Buffer for the last vote message for restart.
    - `metrics`: Metrics for the gossip tile.
- **Description**: The `fd_gossip_tile_ctx` structure is a comprehensive context for managing the gossip protocol operations within a Firedancer node. It contains various fields for handling input and output links, memory caches, synchronization objects, and network addresses. The structure is designed to facilitate the management of gossip messages, including their reception, processing, and transmission. It also includes fields for storing cryptographic keys, network headers, and metrics to monitor the performance and status of the gossip operations. This context is crucial for ensuring efficient and reliable communication between nodes in a distributed network.


---
### fd\_gossip\_tile\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `gossip`: Pointer to the gossip instance used for networking.
    - `gossip_config`: Configuration settings for the gossip protocol.
    - `last_shred_dest_push_time`: Timestamp of the last shred destination push.
    - `last_plugin_push_time`: Timestamp of the last plugin push.
    - `gossip_seed`: Seed value for gossip operations.
    - `in_kind`: Array indicating the type of each input link.
    - `in_links`: Array of input link contexts.
    - `contact_info_table`: Pointer to the contact information table.
    - `shred_contact_out_mcache`: Memory cache for outgoing shred contact information.
    - `shred_contact_out_sync`: Synchronization variable for outgoing shred contact information.
    - `shred_contact_out_depth`: Depth of the outgoing shred contact information cache.
    - `shred_contact_out_seq`: Sequence number for outgoing shred contact information.
    - `shred_contact_out_mem`: Workspace memory for outgoing shred contact information.
    - `shred_contact_out_chunk0`: Initial chunk for outgoing shred contact information.
    - `shred_contact_out_wmark`: Watermark for outgoing shred contact information.
    - `shred_contact_out_chunk`: Current chunk for outgoing shred contact information.
    - `repair_contact_out_mcache`: Memory cache for outgoing repair contact information.
    - `repair_contact_out_sync`: Synchronization variable for outgoing repair contact information.
    - `repair_contact_out_depth`: Depth of the outgoing repair contact information cache.
    - `repair_contact_out_seq`: Sequence number for outgoing repair contact information.
    - `repair_contact_out_mem`: Workspace memory for outgoing repair contact information.
    - `repair_contact_out_chunk0`: Initial chunk for outgoing repair contact information.
    - `repair_contact_out_wmark`: Watermark for outgoing repair contact information.
    - `repair_contact_out_chunk`: Current chunk for outgoing repair contact information.
    - `send_contact_out_mcache`: Memory cache for outgoing send contact information.
    - `send_contact_out_sync`: Synchronization variable for outgoing send contact information.
    - `send_contact_out_depth`: Depth of the outgoing send contact information cache.
    - `send_contact_out_seq`: Sequence number for outgoing send contact information.
    - `send_contact_out_mem`: Workspace memory for outgoing send contact information.
    - `send_contact_out_chunk0`: Initial chunk for outgoing send contact information.
    - `send_contact_out_wmark`: Watermark for outgoing send contact information.
    - `send_contact_out_chunk`: Current chunk for outgoing send contact information.
    - `verify_out_mcache`: Memory cache for outgoing verification information.
    - `verify_out_sync`: Synchronization variable for outgoing verification information.
    - `verify_out_depth`: Depth of the outgoing verification information cache.
    - `verify_out_seq`: Sequence number for outgoing verification information.
    - `verify_out_mem`: Workspace memory for outgoing verification information.
    - `verify_out_chunk0`: Initial chunk for outgoing verification information.
    - `verify_out_wmark`: Watermark for outgoing verification information.
    - `verify_out_chunk`: Current chunk for outgoing verification information.
    - `eqvoc_out_mcache`: Memory cache for outgoing equivocation information.
    - `eqvoc_out_sync`: Synchronization variable for outgoing equivocation information.
    - `eqvoc_out_depth`: Depth of the outgoing equivocation information cache.
    - `eqvoc_out_seq`: Sequence number for outgoing equivocation information.
    - `eqvoc_out_mem`: Workspace memory for outgoing equivocation information.
    - `eqvoc_out_chunk0`: Initial chunk for outgoing equivocation information.
    - `eqvoc_out_wmark`: Watermark for outgoing equivocation information.
    - `eqvoc_out_chunk`: Current chunk for outgoing equivocation information.
    - `restart_out_mcache`: Memory cache for outgoing restart information.
    - `restart_out_sync`: Synchronization variable for outgoing restart information.
    - `restart_out_depth`: Depth of the outgoing restart information cache.
    - `restart_out_seq`: Sequence number for outgoing restart information.
    - `restart_out_mem`: Workspace memory for outgoing restart information.
    - `restart_out_chunk0`: Initial chunk for outgoing restart information.
    - `restart_out_wmark`: Watermark for outgoing restart information.
    - `restart_out_chunk`: Current chunk for outgoing restart information.
    - `wksp`: Pointer to the workspace used by the context.
    - `gossip_my_addr`: Address of the gossip node.
    - `tvu_my_addr`: Address of the TVU node.
    - `tpu_my_addr`: Address of the TPU node.
    - `tpu_quic_my_addr`: Address of the TPU QUIC node.
    - `tpu_vote_my_addr`: Address of the TPU vote node.
    - `repair_serve_addr`: Address for repair services.
    - `gossip_listen_port`: Port for gossip listening.
    - `net_out_mcache`: Memory cache for outgoing network information.
    - `net_out_sync`: Synchronization variable for outgoing network information.
    - `net_out_depth`: Depth of the outgoing network information cache.
    - `net_out_seq`: Sequence number for outgoing network information.
    - `net_out_mem`: Workspace memory for outgoing network information.
    - `net_out_chunk0`: Initial chunk for outgoing network information.
    - `net_out_wmark`: Watermark for outgoing network information.
    - `net_out_chunk`: Current chunk for outgoing network information.
    - `gossip_plugin_out_mem`: Workspace memory for outgoing gossip plugin information.
    - `gossip_plugin_out_chunk0`: Initial chunk for outgoing gossip plugin information.
    - `gossip_plugin_out_wmark`: Watermark for outgoing gossip plugin information.
    - `gossip_plugin_out_chunk`: Current chunk for outgoing gossip plugin information.
    - `gossip_plugin_out_idx`: Index for outgoing gossip plugin information.
    - `identity_private_key`: Private key for node identity.
    - `identity_public_key`: Public key for node identity.
    - `gossip_buffer`: Buffer for gossip messages.
    - `net_id`: Network identifier.
    - `hdr`: Headers for IP and UDP packets.
    - `keyguard_client`: Client for keyguard operations.
    - `stem`: Pointer to the stem context.
    - `replay_vote_txn_sz`: Size of the replay vote transaction.
    - `replay_vote_txn`: Buffer for replay vote transaction.
    - `restart_last_push_time`: Timestamp of the last restart push.
    - `restart_last_vote_msg_sz`: Size of the last vote message for restart.
    - `restart_heaviest_fork_msg_sz`: Size of the heaviest fork message for restart.
    - `restart_heaviest_fork_msg`: Buffer for the heaviest fork message for restart.
    - `restart_last_vote_msg`: Buffer for the last vote message for restart.
    - `metrics`: Metrics for the gossip tile.
- **Description**: The `fd_gossip_tile_ctx_t` structure is a comprehensive context for managing the gossip protocol in a Firedancer node. It includes configurations, state management, and various buffers and caches for handling network communication, contact information, and protocol-specific data. The structure supports multiple input and output links, each with its own context, and maintains metrics for performance monitoring. It is designed to facilitate the operation of the gossip protocol, including message sending, receiving, and processing, as well as integration with plugins and other system components.


# Functions

---
### fd\_pubkey\_hash<!-- {{#callable:fd_pubkey_hash}} -->
The `fd_pubkey_hash` function computes a hash value for a given public key using a specified seed.
- **Inputs**:
    - `key`: A pointer to a constant `fd_pubkey_t` structure representing the public key to be hashed.
    - `seed`: An unsigned long integer used as the initial seed for the hash computation.
- **Control Flow**:
    - The function calls `fd_hash` with the provided seed, the key data from the `fd_pubkey_t` structure, and the size of the `fd_pubkey_t` structure.
    - The result of the `fd_hash` function call is returned as the output of `fd_pubkey_hash`.
- **Output**: The function returns an unsigned long integer representing the hash value of the public key.


---
### scratch\_align<!-- {{#callable:scratch_align}} -->
The `scratch_align` function returns a constant alignment value of 128 bytes.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use only within the file it is defined in and suggests the compiler to inline it for performance.
    - The function is marked with `FD_FN_CONST`, indicating that it has no side effects and its return value depends only on its parameters (though it has none).
    - The function simply returns the constant value `128UL`.
- **Output**: The function outputs an unsigned long integer value of 128, representing a memory alignment requirement.


---
### loose\_footprint<!-- {{#callable:loose_footprint}} -->
The `loose_footprint` function calculates the memory footprint for a tile using a gigantic page size.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, which is not used in the function.
- **Control Flow**:
    - The function takes a single argument, `tile`, which is marked as unused with `FD_PARAM_UNUSED`.
    - It returns the product of `1UL` and `FD_SHMEM_GIGANTIC_PAGE_SZ`, which represents the size of a gigantic shared memory page.
- **Output**: The function returns an `ulong` representing the memory footprint size, specifically the size of a gigantic shared memory page.


---
### scratch\_footprint<!-- {{#callable:scratch_footprint}} -->
The `scratch_footprint` function calculates the memory footprint required for a gossip tile's scratch space, considering various alignment and size requirements of its components.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, which is not used in the function.
- **Control Flow**:
    - Initialize a variable `l` with `FD_LAYOUT_INIT` to start the layout calculation.
    - Append the alignment and size of `fd_gossip_tile_ctx_t` to `l` using `FD_LAYOUT_APPEND`.
    - Append the alignment and footprint of the gossip component using `fd_gossip_align()` and `fd_gossip_footprint()`.
    - Append the alignment and footprint of the contact info table using `fd_contact_info_table_align()` and `fd_contact_info_table_footprint(FD_PEER_KEY_MAX)`.
    - Finalize the layout calculation with `FD_LAYOUT_FINI` using `scratch_align()` to determine the total footprint.
- **Output**: Returns an `ulong` representing the total memory footprint required for the scratch space.
- **Functions called**:
    - [`scratch_align`](#scratch_align)


---
### send\_packet<!-- {{#callable:send_packet}} -->
The `send_packet` function constructs and sends a UDP packet with a specified payload to a given destination IP address and port, updating network metadata and publishing the packet to a network stem.
- **Inputs**:
    - `ctx`: A pointer to the `fd_gossip_tile_ctx_t` context structure, which contains network and gossip protocol state information.
    - `dst_ip_addr`: The destination IP address to which the packet will be sent, represented as an unsigned integer.
    - `dst_port`: The destination port number for the UDP packet, represented as an unsigned short.
    - `payload`: A pointer to the payload data to be included in the UDP packet.
    - `payload_sz`: The size of the payload data in bytes, represented as an unsigned long.
    - `tsorig`: The original timestamp for the packet, represented as an unsigned long.
- **Control Flow**:
    - Allocate memory for the packet using `fd_chunk_to_laddr` with the context's network output memory and chunk.
    - Copy the IP and UDP headers from the context's header template into the packet.
    - Set the destination IP address and port in the IP and UDP headers, respectively.
    - Calculate and set the total length and checksum for the IP header.
    - Calculate and set the length for the UDP header, and copy the payload data into the packet after the headers.
    - Compute the publication timestamp using `fd_frag_meta_ts_comp` and the current tick count.
    - Generate a signature for the packet using `fd_disco_netmux_sig`.
    - Publish the packet using `fd_stem_publish` with the computed signature, chunk, and size information.
    - Update the context's network output chunk using `fd_dcache_compact_next` to prepare for the next packet.
- **Output**: The function does not return a value; it sends a packet and updates the context's network state.


---
### gossip\_send\_packet<!-- {{#callable:gossip_send_packet}} -->
The `gossip_send_packet` function sends a gossip message packet to a specified peer address using a given context.
- **Inputs**:
    - `msg`: A pointer to the message data to be sent.
    - `msglen`: The length of the message data.
    - `addr`: A pointer to the `fd_gossip_peer_addr_t` structure containing the destination peer's address and port.
    - `arg`: A pointer to a context, typically of type `fd_gossip_tile_ctx_t`, used in the [`send_packet`](#send_packet) function.
- **Control Flow**:
    - Compute the original timestamp `tsorig` using `fd_frag_meta_ts_comp` and `fd_tickcount` to get the current tick count.
    - Call the [`send_packet`](#send_packet) function with the provided context `arg`, destination address and port from `addr`, message `msg`, message length `msglen`, and the computed timestamp `tsorig`.
- **Output**: This function does not return a value; it performs its operation by sending a packet.
- **Functions called**:
    - [`send_packet`](#send_packet)


---
### gossip\_deliver\_fun<!-- {{#callable:gossip_deliver_fun}} -->
The `gossip_deliver_fun` function processes different types of gossip data and updates the context or publishes messages accordingly.
- **Inputs**:
    - `data`: A pointer to `fd_crds_data_t` structure containing the gossip data to be processed.
    - `arg`: A pointer to `fd_gossip_tile_ctx_t` structure, which is the context for the gossip tile.
- **Control Flow**:
    - Cast `arg` to `fd_gossip_tile_ctx_t` pointer `ctx`.
    - Check if `data` is a vote using `fd_crds_data_is_vote`; if true, verify `ctx->verify_out_mcache` is not NULL, then copy the vote transaction to memory and publish it.
    - Check if `data` is contact info v1 using `fd_crds_data_is_contact_info_v1`; if true, log the contact info and update or insert it into the contact info table.
    - Check if `data` is contact info v2 using `fd_crds_data_is_contact_info_v2`; if true, convert it to v1, log, and update or insert it into the contact info table.
    - Check if `data` is a duplicate shred using `fd_crds_data_is_duplicate_shred`; if true, verify `ctx->eqvoc_out_mcache` is not NULL, then copy the duplicate shred to memory and publish it.
    - Check if `data` is restart last voted fork slots using `fd_crds_data_is_restart_last_voted_fork_slots`; if true, verify `ctx->restart_out_mcache` is not NULL, then process the bitmap and publish the message.
    - Check if `data` is restart heaviest fork using `fd_crds_data_is_restart_heaviest_fork`; if true, verify `ctx->restart_out_mcache` is not NULL, then copy the data to memory and publish it.
- **Output**: This function does not return a value; it performs operations based on the type of gossip data received.


---
### gossip\_signer<!-- {{#callable:gossip_signer}} -->
The `gossip_signer` function signs a given buffer using a keyguard client within a gossip tile context.
- **Inputs**:
    - `signer_ctx`: A pointer to the context of the gossip tile, specifically a `fd_gossip_tile_ctx_t` structure.
    - `signature`: An array of 64 unsigned characters where the resulting signature will be stored.
    - `buffer`: A constant pointer to the buffer containing the data to be signed.
    - `len`: The length of the buffer to be signed, specified as an unsigned long.
    - `sign_type`: An integer indicating the type of signature to be performed.
- **Control Flow**:
    - Cast the `signer_ctx` to a `fd_gossip_tile_ctx_t` pointer and store it in `ctx`.
    - Call the `fd_keyguard_client_sign` function with the keyguard client from `ctx`, passing the signature array, buffer, length, and sign type as arguments.
- **Output**: The function does not return a value; it outputs the signature directly into the provided `signature` array.


---
### during\_housekeeping<!-- {{#callable:during_housekeeping}} -->
The `during_housekeeping` function updates the gossip context's time to the current wall clock time.
- **Inputs**:
    - `ctx`: A pointer to an `fd_gossip_tile_ctx_t` structure, which contains the context for the gossip tile, including the gossip object to be updated.
- **Control Flow**:
    - The function calls `fd_log_wallclock()` to get the current wall clock time.
    - It then calls `fd_gossip_settime()` with the gossip object from the context and the current wall clock time to update the gossip's internal time.
- **Output**: This function does not return any value; it performs an update operation on the provided context.


---
### before\_frag<!-- {{#callable:before_frag}} -->
The `before_frag` function determines if a fragment should be processed based on its input kind and signature protocol.
- **Inputs**:
    - `ctx`: A pointer to a `fd_gossip_tile_ctx_t` structure, which contains context information for the gossip tile.
    - `in_idx`: An unsigned long integer representing the index of the input link in the context's `in_kind` array.
    - `seq`: An unsigned long integer representing the sequence number, which is unused in this function.
    - `sig`: An unsigned long integer representing the signature of the fragment.
- **Control Flow**:
    - Retrieve the input kind from the `ctx->in_kind` array using `in_idx` as the index.
    - Check if the input kind is not `IN_KIND_SEND` and not `IN_KIND_RESTART`.
    - Check if the protocol of the signature `sig` is not `DST_PROTO_GOSSIP` using the `fd_disco_netmux_sig_proto` function.
    - Return true (non-zero) if both conditions are met, otherwise return false (zero).
- **Output**: The function returns an integer that is non-zero if the fragment should be processed, and zero if it should not be processed.


---
### during\_frag<!-- {{#callable:during_frag}} -->
The `during_frag` function processes incoming fragments based on their type and updates the context accordingly.
- **Inputs**:
    - `ctx`: A pointer to the `fd_gossip_tile_ctx_t` structure, which holds the context for the gossip tile.
    - `in_idx`: An index indicating which input link is being processed.
    - `seq`: A sequence number, marked as unused in this function.
    - `sig`: A signature, marked as unused in this function.
    - `chunk`: The chunk identifier for the incoming fragment.
    - `sz`: The size of the incoming fragment.
    - `ctl`: Control information for the fragment.
- **Control Flow**:
    - Retrieve the kind of input from `ctx->in_kind[in_idx]` and the input context from `ctx->in_links[in_idx]`.
    - If the input kind is `IN_KIND_RESTART`, check if the chunk and size are within valid ranges; if not, log an error.
    - Load the message from the chunk and determine its type using a discriminant value.
    - If the message is of type `fd_crds_data_enum_restart_last_voted_fork_slots`, ensure it is the first such message, copy it to the context, and update the message size.
    - If the message is of type `fd_crds_data_enum_restart_heaviest_fork`, ensure it is the first such message, copy it to the context, and update the message size.
    - If the input kind is `IN_KIND_SEND`, check if the chunk and size are within valid ranges; if not, log an error.
    - Copy the transaction message to the context and update the transaction size.
    - If the input kind is not `IN_KIND_NET`, return without further processing.
    - Translate the fragment using `fd_net_rx_translate_frag` and copy it to the gossip buffer in the context.
- **Output**: The function does not return a value; it modifies the context `ctx` based on the type and content of the incoming fragment.


---
### after\_frag<!-- {{#callable:after_frag}} -->
The `after_frag` function processes incoming network fragments based on their type and size, handling different actions for restart, send, and network kinds.
- **Inputs**:
    - `ctx`: A pointer to the `fd_gossip_tile_ctx_t` structure, which contains the context for the gossip tile.
    - `in_idx`: An unsigned long integer representing the index of the input link.
    - `seq`: An unsigned long integer representing the sequence number, marked as unused.
    - `sig`: An unsigned long integer representing the signature, marked as unused.
    - `sz`: An unsigned long integer representing the size of the fragment.
    - `tsorig`: An unsigned long integer representing the original timestamp, marked as unused.
    - `tspub`: An unsigned long integer representing the publish timestamp, marked as unused.
    - `stem`: A pointer to the `fd_stem_context_t` structure, which is used to update the context's stem.
- **Control Flow**:
    - Retrieve the kind of input from `ctx->in_kind[in_idx]`.
    - If the input kind is `IN_KIND_RESTART`, return immediately as these are handled elsewhere.
    - If the input kind is `IN_KIND_SEND`, prepare a vote transaction CRDS data structure, parse the transaction, push it to gossip, and log every 50 transactions sent.
    - If the input kind is not `IN_KIND_NET`, return immediately.
    - Check if the size `sz` is less than 42, and return if true.
    - Set `ctx->stem` to the provided `stem` pointer.
    - Parse the Ethernet, IP, and UDP headers from the gossip buffer.
    - Verify the UDP header and data sizes are within bounds, returning if any checks fail.
    - Create a `fd_gossip_peer_addr_t` structure with the source IP and port from the IP and UDP headers.
    - Call `fd_gossip_recv_packet` to process the received packet data.
- **Output**: The function does not return a value; it performs actions based on the input kind and updates the context or logs information as needed.


---
### publish\_peers\_to\_plugin<!-- {{#callable:publish_peers_to_plugin}} -->
The `publish_peers_to_plugin` function iterates over a contact info table to gather peer information and publishes it to a plugin for further processing.
- **Inputs**:
    - `ctx`: A pointer to a `fd_gossip_tile_ctx_t` structure containing the context for the gossip tile, including the contact info table and memory management details.
    - `stem`: A pointer to a `fd_stem_context_t` structure used for publishing the gathered peer information.
- **Control Flow**:
    - Convert the gossip plugin output memory chunk to a local address for writing peer data.
    - Initialize an iterator for the contact info table and loop through each entry until the table is exhausted or a predefined node count limit is reached.
    - For each contact info element, create a gossip update message, zero-initialize it, and populate it with the peer's public key, wallclock, and shred version.
    - Use a macro to copy IP and port information for various socket types from the contact info element to the message, based on the discriminant type.
    - Store the number of processed peers at the beginning of the destination memory.
    - Calculate a timestamp for publication and use `fd_stem_publish` to publish the peer information to the plugin.
    - Update the gossip plugin output chunk to the next available chunk using `fd_dcache_compact_next`.
- **Output**: The function does not return a value; it modifies the memory pointed to by `ctx->gossip_plugin_out_mem` to store peer information and publishes it using the `fd_stem_publish` function.


---
### after\_credit<!-- {{#callable:after_credit}} -->
The `after_credit` function updates the state of a gossip tile context by processing contact information, publishing peer data, and managing gossip messages based on timing and conditions.
- **Inputs**:
    - `ctx`: A pointer to a `fd_gossip_tile_ctx_t` structure representing the context of the gossip tile.
    - `stem`: A pointer to a `fd_stem_context_t` structure used for publishing data.
    - `opt_poll_in`: An optional pointer to an integer, currently unused in the function.
    - `charge_busy`: A pointer to an integer that indicates whether the tile should be marked as busy.
- **Control Flow**:
    - The function begins by setting `charge_busy` to 1, indicating the tile is busy.
    - It updates the `stem` field of the context with the provided `stem` pointer.
    - The function checks if the `shred_contact_out_sync` and `repair_contact_out_sync` are available and updates their sequences if so.
    - It calculates the current time and checks if enough time has passed since the last shred destination push to publish contact information.
    - If conditions are met, it iterates over the contact info table, filtering and counting peers based on IP address validity and shred version.
    - The function updates peer counts in the metrics and logs the number of peers being published.
    - It publishes the peer data to the respective caches if there are peers to publish.
    - The function checks if it's time to publish peers to a plugin and does so if necessary.
    - It checks if it's time to send restart messages and sends them if they are available.
    - Finally, it updates the global shred version and continues the gossip process.
- **Output**: The function does not return a value; it operates by modifying the state of the provided context and potentially publishing data.
- **Functions called**:
    - [`publish_peers_to_plugin`](#publish_peers_to_plugin)


---
### privileged\_init<!-- {{#callable:privileged_init}} -->
The `privileged_init` function initializes a gossip tile context by allocating memory, loading an identity key, and generating a random seed for the gossip protocol.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology of the system.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile within the topology to be initialized.
- **Control Flow**:
    - Obtain a scratch memory address using `fd_topo_obj_laddr` with the provided `topo` and `tile->tile_obj_id`.
    - Initialize a scratch allocator with `FD_SCRATCH_ALLOC_INIT` using the obtained scratch memory.
    - Allocate memory for a `fd_gossip_tile_ctx_t` structure using `FD_SCRATCH_ALLOC_APPEND` and zero-initialize it with `fd_memset`.
    - Load the identity key from the path specified in `tile->gossip.identity_key_path` using `fd_keyload_load`, and copy it into the `identity_public_key` field of the context.
    - Generate a random seed for the gossip protocol using `getrandom` and store it in the `gossip_seed` field of the context.
- **Output**: The function does not return a value; it initializes the context for a gossip tile in place.


---
### unprivileged\_init<!-- {{#callable:unprivileged_init}} -->
The `unprivileged_init` function initializes the unprivileged components of a gossip tile in a Firedancer node, setting up memory, input/output links, and configuring the gossip protocol.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology of the Firedancer node.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile (or node) within the topology to be initialized.
- **Control Flow**:
    - Retrieve the local address of the tile object using `fd_topo_obj_laddr` and store it in `scratch`.
    - Check if the tile has any primary output links; if not, log an error and terminate.
    - Verify that the gossip IP address and listen port are set; if not, log an error and terminate.
    - Initialize scratch memory allocation using `FD_SCRATCH_ALLOC_INIT`.
    - Allocate and initialize a `fd_gossip_tile_ctx_t` context structure in the scratch memory.
    - Join a new contact info table using `fd_contact_info_table_join` and store it in the context.
    - Check if the number of input links exceeds `MAX_IN_LINKS`; if so, log an error and terminate.
    - Iterate over each input link, determine its type, and initialize the corresponding context fields.
    - Ensure there is a 'sign_gossip' input link; if not, log an error and terminate.
    - Iterate over each output link, determine its type, and initialize the corresponding context fields.
    - Ensure there is a 'gossip_sign' output link; if not, log an error and terminate.
    - Set up the workspace and network addresses for the gossip context.
    - Initialize the IP and UDP headers for outgoing packets.
    - Join the keyguard client for signing operations using `fd_keyguard_client_join`.
    - Join and configure the gossip protocol using `fd_gossip_join` and `fd_gossip_set_config`.
    - Update various network addresses in the gossip context.
    - Start the gossip protocol using `fd_gossip_start`.
    - Finalize scratch memory allocation and check for overflow.
    - Retrieve and join the POH shred version object.
    - Initialize metrics in the context to zero.
- **Output**: The function does not return a value; it initializes the gossip tile's context and sets up the necessary configurations for the gossip protocol.
- **Functions called**:
    - [`scratch_footprint`](#scratch_footprint)


---
### populate\_allowed\_seccomp<!-- {{#callable:populate_allowed_seccomp}} -->
The `populate_allowed_seccomp` function populates a seccomp filter policy for a gossip tile and returns the instruction count for the policy.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, representing the topology configuration.
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure, representing the tile configuration.
    - `out_cnt`: An unsigned long integer representing the count of output filters.
    - `out`: A pointer to a `struct sock_filter` array where the seccomp filter policy will be populated.
- **Control Flow**:
    - The function begins by casting the `topo` and `tile` parameters to void to indicate they are unused.
    - It calls [`populate_sock_filter_policy_fd_gossip_tile`](generated/fd_gossip_tile_seccomp.h.driver.md#populate_sock_filter_policy_fd_gossip_tile) with `out_cnt`, `out`, and the file descriptor of the private log file to populate the seccomp filter policy.
    - The function returns the value of `sock_filter_policy_fd_gossip_tile_instr_cnt`, which represents the number of instructions in the seccomp filter policy.
- **Output**: The function returns an unsigned long integer representing the number of instructions in the seccomp filter policy for the gossip tile.
- **Functions called**:
    - [`populate_sock_filter_policy_fd_gossip_tile`](generated/fd_gossip_tile_seccomp.h.driver.md#populate_sock_filter_policy_fd_gossip_tile)


---
### populate\_allowed\_fds<!-- {{#callable:populate_allowed_fds}} -->
The `populate_allowed_fds` function populates an array with file descriptors that are allowed for use, specifically including the standard error and optionally a log file descriptor.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, which is not used in this function.
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure, which is not used in this function.
    - `out_fds_cnt`: An unsigned long integer representing the maximum number of file descriptors that can be stored in the `out_fds` array.
    - `out_fds`: A pointer to an integer array where the allowed file descriptors will be stored.
- **Control Flow**:
    - The function begins by casting the `topo` and `tile` parameters to void to indicate they are unused.
    - It checks if `out_fds_cnt` is less than 2, and if so, logs an error and terminates the program.
    - It initializes `out_cnt` to 0 and assigns the file descriptor for standard error (2) to the first position in `out_fds`, incrementing `out_cnt`.
    - It checks if the log file descriptor is valid (not -1) using `fd_log_private_logfile_fd()`, and if valid, assigns it to the next position in `out_fds`, incrementing `out_cnt`.
    - The function returns the count of file descriptors stored in `out_fds`.
- **Output**: The function returns an unsigned long integer representing the number of file descriptors that have been populated in the `out_fds` array.


---
### fd\_gossip\_update\_gossip\_metrics<!-- {{#callable:fd_gossip_update_gossip_metrics}} -->
The `fd_gossip_update_gossip_metrics` function updates various gossip-related metrics using the provided `fd_gossip_metrics_t` structure.
- **Inputs**:
    - `metrics`: A pointer to an `fd_gossip_metrics_t` structure containing various counters and gauges related to gossip metrics.
- **Control Flow**:
    - The function begins by setting the received packet count and corrupted message count using `FD_MCNT_SET` macros.
    - It then copies enumerated values for received gossip messages, unknown messages, CRDS push and pull messages, duplicate messages, and drop reasons using `FD_MCNT_ENUM_COPY` macros.
    - The function sets and copies metrics related to CRDS push operations, including queue count, using `FD_MCNT_ENUM_COPY` and `FD_MGAUGE_SET` macros.
    - It sets the value meta size and vector size using `FD_MGAUGE_SET` macros.
    - The function updates active push destinations and refresh push states fail count using `FD_MGAUGE_SET` and `FD_MCNT_SET` macros respectively.
    - It copies metrics related to pull request failures and bloom filter results using `FD_MCNT_ENUM_COPY` macros.
    - The function sets metrics for prune operations, including stale entries, high duplicates, and requested origins using `FD_MCNT_SET` and `FD_MGAUGE_SET` macros.
    - It copies metrics for sent gossip messages, packets, ping events, and pong events using `FD_MCNT_ENUM_COPY` macros.
    - Finally, it sets the count of invalid ping signatures and copies peer counts using `FD_MCNT_SET` and `FD_MGAUGE_ENUM_COPY` macros.
- **Output**: The function does not return any value; it updates the metrics in the provided `fd_gossip_metrics_t` structure.


---
### metrics\_write<!-- {{#callable:metrics_write}} -->
The `metrics_write` function updates various metrics related to the gossip protocol and tile-specific metrics in a Firedancer node.
- **Inputs**:
    - `ctx`: A pointer to a `fd_gossip_tile_ctx_t` structure containing the context and metrics for the gossip tile.
- **Control Flow**:
    - The function begins by updating tile-specific metrics using macros like `FD_MGAUGE_SET`, `FD_MCNT_SET`, and `FD_MCNT_ENUM_COPY` to set values for metrics such as the last CRDS push contact info publish timestamp, mismatched contact info shred version, and others.
    - It then calls [`fd_gossip_update_gossip_metrics`](#fd_gossip_update_gossip_metrics) with the current gossip metrics obtained from `fd_gossip_get_metrics(ctx->gossip)` to update gossip-protocol-specific metrics.
- **Output**: The function does not return any value; it updates the metrics in the provided context.
- **Functions called**:
    - [`fd_gossip_update_gossip_metrics`](#fd_gossip_update_gossip_metrics)



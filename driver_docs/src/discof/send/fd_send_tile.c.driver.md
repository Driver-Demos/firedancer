# Purpose
The provided C source code file is part of a larger system designed to handle the sending of transactions to a designated leader in a network, with a primary focus on voting transactions. This file is not a standalone executable but rather a component intended to be integrated into a larger application, likely as part of a distributed system or blockchain infrastructure. The code is structured around the concept of "tiles," which appear to be modular components within the system, each responsible for specific tasks. This particular tile, named "send," is responsible for managing the transmission of transactions, handling network communication, and maintaining metrics related to transaction processing and leader interactions.

Key technical components of this file include the definition of structures for managing input and output links (`fd_send_link_in_t` and `fd_send_link_out_t`), as well as the context for the send tile (`fd_send_tile_ctx_t`). The code handles various types of input data, such as gossip, stake, and replay information, and processes them accordingly. It includes functions for sending packets over the network, determining the current leader for transaction routing, and managing cluster contact information. The file also integrates with other components of the system, such as key management and network utilities, through a series of included headers and external function calls. The code is designed to be efficient and robust, with error handling and logging mechanisms in place to ensure reliable operation within the larger system.
# Imports and Dependencies

---
- `../../disco/metrics/fd_metrics.h`
- `../../disco/topo/fd_topo.h`
- `generated/fd_send_tile_seccomp.h`
- `../../disco/fd_disco.h`
- `../../disco/keyguard/fd_keyload.h`
- `../../disco/keyguard/fd_keyguard_client.h`
- `../../disco/keyguard/fd_keyguard.h`
- `../../disco/pack/fd_microblock.h`
- `../../disco/shred/fd_stake_ci.h`
- `../../flamenco/fd_flamenco.h`
- `../../flamenco/repair/fd_repair.h`
- `../../flamenco/runtime/fd_blockstore.h`
- `../../flamenco/runtime/fd_runtime.h`
- `../../flamenco/leaders/fd_leaders.h`
- `../../flamenco/gossip/fd_gossip.h`
- `../../choreo/fd_choreo.h`
- `../../util/fd_util.h`
- `../../util/net/fd_eth.h`
- `../../util/net/fd_ip4.h`
- `../../util/net/fd_udp.h`
- `../../util/net/fd_net_headers.h`
- `../../disco/stem/fd_stem.c`


# Global Variables

---
### fd\_tile\_send
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_send` is a global variable of type `fd_topo_run_tile_t`, which is a structure that defines the configuration and behavior of a 'send' tile in a distributed system. This structure includes function pointers for initialization, security policy population, and execution, as well as alignment and footprint specifications for memory management.
- **Use**: This variable is used to configure and manage the execution of a tile responsible for sending transactions to a leader in a distributed system.


# Data Structures

---
### fd\_send\_link\_in
- **Type**: `struct`
- **Members**:
    - `mem`: A pointer to a workspace memory structure (fd_wksp_t) used for memory management.
    - `chunk0`: An unsigned long integer representing the starting chunk index in the memory workspace.
    - `wmark`: An unsigned long integer representing the watermark or upper limit for chunk indices.
    - `kind`: An unsigned long integer indicating the type of input link, such as gossip, replay, or stake.
- **Description**: The `fd_send_link_in` structure is designed to manage input links for sending transactions in a distributed system. It holds a pointer to a memory workspace, along with chunk indices and a watermark to manage memory allocation and usage. The `kind` field specifies the type of input link, allowing the system to handle different types of data, such as gossip, replay, or stake updates, appropriately.


---
### fd\_send\_link\_in\_t
- **Type**: `struct`
- **Members**:
    - `mem`: Pointer to a workspace memory structure.
    - `chunk0`: Initial chunk index for data storage.
    - `wmark`: Watermark indicating the upper limit of data storage.
    - `kind`: Type of input link, indicating the kind of data being processed.
- **Description**: The `fd_send_link_in_t` structure is used to define an input link in a data processing pipeline, specifically for handling different types of data such as gossip, stake, or replay. It contains a pointer to a memory workspace, an initial chunk index, a watermark for data storage limits, and a kind field to specify the type of data being processed. This structure is part of a larger system designed to manage and send transactions to a leader in a distributed network.


---
### fd\_send\_link\_out
- **Type**: `struct`
- **Members**:
    - `idx`: An unsigned long integer representing the index of the output link.
    - `mcache`: A pointer to a fragment metadata cache structure.
    - `sync`: A pointer to an unsigned long integer used for synchronization.
    - `depth`: An unsigned long integer representing the depth of the metadata cache.
    - `mem`: A pointer to a workspace structure for memory management.
    - `chunk0`: An unsigned long integer representing the initial chunk index.
    - `wmark`: An unsigned long integer representing the watermark for chunk management.
    - `chunk`: An unsigned long integer representing the current chunk index.
- **Description**: The `fd_send_link_out` structure is used to manage output links in a network communication context. It contains metadata and pointers necessary for handling data chunks, synchronization, and memory management. The structure is designed to facilitate the sending of data packets by maintaining information about the current state of the output link, including its index, memory cache, synchronization status, and chunk management parameters.


---
### fd\_send\_link\_out\_t
- **Type**: `struct`
- **Members**:
    - `idx`: Index of the output link.
    - `mcache`: Pointer to the metadata cache for the output link.
    - `sync`: Pointer to the synchronization variable for the output link.
    - `depth`: Depth of the metadata cache.
    - `mem`: Pointer to the memory workspace associated with the output link.
    - `chunk0`: Initial chunk index for the output link.
    - `wmark`: Watermark for the output link, indicating the maximum chunk index.
    - `chunk`: Current chunk index for the output link.
- **Description**: The `fd_send_link_out_t` structure is used to manage output links in a network communication context. It contains metadata and state information necessary for handling data transmission, including indices, pointers to memory and synchronization structures, and chunk management details. This structure is integral to managing the flow of data packets to their respective destinations in a networked system.


---
### fd\_send\_tile\_ctx
- **Type**: `struct`
- **Members**:
    - `identity_key`: An array of one public key representing the identity key.
    - `vote_acct_addr`: An array of one public key representing the vote account address.
    - `stake_ci`: A pointer to a structure containing stake consensus information.
    - `new_dest_ptr`: A pointer to a structure for new destination information.
    - `new_dest_cnt`: An unsigned long integer representing the count of new destinations.
    - `txn_buf`: A buffer for transaction data, aligned to the size of a transaction pointer.
    - `tpu_serve_addr`: A structure representing the address of the TPU server.
    - `packet_hdr`: An array of one IP4 UDP header structure for packet headers.
    - `net_id`: A 16-bit unsigned integer representing the network ID.
    - `in_links`: An array of input links with a maximum count of 32.
    - `gossip_verify_out`: An array of one output link for gossip verification.
    - `net_out`: An array of one output link for network output.
    - `sign_out_idx`: An unsigned long integer representing the index for signing output.
    - `keyguard_client`: An array of one keyguard client structure.
    - `metrics`: A nested structure containing various transaction and leader metrics.
- **Description**: The `fd_send_tile_ctx` structure is designed to manage the context for sending transactions to a leader in a network. It includes fields for identity and vote account keys, pointers to stake consensus information, and buffers for transaction data. The structure also manages network communication through input and output links, and tracks various metrics related to transaction sending and leader contact. It is primarily used in a system where transactions are signed and sent to a leader, with a focus on voting as a primary use case.


---
### fd\_send\_tile\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `identity_key`: An array of one public key used for identity.
    - `vote_acct_addr`: An array of one public key used for vote account address.
    - `stake_ci`: A pointer to a stake consensus interface.
    - `new_dest_ptr`: A pointer to a new destination weighted shred.
    - `new_dest_cnt`: The count of new destinations.
    - `txn_buf`: A buffer for transactions, aligned to the size of fd_txn_p_t.
    - `tpu_serve_addr`: The address of the TPU server.
    - `packet_hdr`: An array of one IP4 UDP header.
    - `net_id`: A network identifier.
    - `in_links`: An array of input links with a maximum count of 32.
    - `gossip_verify_out`: An output link for gossip verification.
    - `net_out`: An output link for network transmission.
    - `sign_out_idx`: The index for signing output.
    - `keyguard_client`: An array of one keyguard client.
    - `metrics`: A structure containing various transaction and leader metrics.
- **Description**: The `fd_send_tile_ctx_t` structure is designed to manage the context for sending tiles, primarily focusing on transactions that require a single signature, with voting as a primary use case. It includes fields for identity and vote account public keys, pointers to stake consensus interfaces, and buffers for transaction data. The structure also manages input and output links for network communication, including gossip verification and network output. Additionally, it maintains metrics related to transaction and leader interactions, such as the number of transactions sent to the leader and various leader-related errors.


# Functions

---
### scratch\_align<!-- {{#callable:scratch_align}} -->
The `scratch_align` function returns a constant alignment value of 128 bytes.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests the compiler to inline it for performance.
    - It is marked with `FD_FN_CONST`, indicating that it has no side effects and its return value depends only on its parameters, which in this case are none.
    - The function simply returns the constant value `128UL`.
- **Output**: The function outputs an unsigned long integer value of 128, representing a memory alignment requirement.


---
### scratch\_footprint<!-- {{#callable:scratch_footprint}} -->
The `scratch_footprint` function calculates the memory footprint required for a specific tile context and its associated components.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, which is not used in the function.
- **Control Flow**:
    - Initialize a variable `l` with `FD_LAYOUT_INIT`.
    - Append the alignment and size of `fd_send_tile_ctx_t` to `l` using `FD_LAYOUT_APPEND`.
    - Append the alignment and footprint of `fd_stake_ci` to `l` using `FD_LAYOUT_APPEND`.
    - Finalize the layout with `FD_LAYOUT_FINI` using `scratch_align()` and return the result.
- **Output**: The function returns an `ulong` representing the calculated memory footprint.
- **Functions called**:
    - [`scratch_align`](#scratch_align)


---
### send\_packet<!-- {{#callable:send_packet}} -->
The `send_packet` function constructs and sends a UDP packet with a specified payload to a given destination IP address and port, updating network metadata and publishing the packet for further processing.
- **Inputs**:
    - `ctx`: A pointer to a `fd_send_tile_ctx_t` structure containing context information for sending the packet, including network output link and packet header.
    - `stem`: A pointer to a `fd_stem_context_t` structure used for publishing the packet.
    - `dst_ip_addr`: The destination IP address to which the packet will be sent.
    - `dst_port`: The destination port number for the UDP packet.
    - `payload`: A pointer to the payload data to be included in the UDP packet.
    - `payload_sz`: The size of the payload data in bytes.
    - `tsorig`: The original timestamp associated with the packet, used for metadata purposes.
- **Control Flow**:
    - Retrieve the network output link from the context and allocate memory for the packet using the link's memory and chunk information.
    - Copy the pre-defined packet header from the context into the packet memory.
    - Set the destination IP address and update the network ID in the IP header, then calculate and set the total length and checksum for the IP header.
    - Set the destination port and length in the UDP header, then copy the payload data into the packet memory after the headers.
    - Set the UDP checksum to zero, indicating no checksum is used.
    - Calculate the publication timestamp and signature for the packet, then publish the packet using the stem context with the calculated metadata.
    - Update the chunk information in the network output link to prepare for the next packet.
- **Output**: The function does not return a value; it sends a packet and updates network metadata.


---
### get\_current\_leader\_tpu\_vote\_contact<!-- {{#callable:get_current_leader_tpu_vote_contact}} -->
The function `get_current_leader_tpu_vote_contact` retrieves the contact information for the current leader's TPU (Transaction Processing Unit) for a given slot and updates the output destination if found.
- **Inputs**:
    - `ctx`: A pointer to a `fd_send_tile_ctx_t` structure, which contains context information including metrics and stake information.
    - `poh_slot`: An unsigned long integer representing the Proof of History slot for which the leader's contact information is being requested.
    - `out_dest`: A double pointer to a `fd_shred_dest_weighted_t` structure, which will be updated with the leader's contact information if found.
- **Control Flow**:
    - Retrieve the leader schedule for the given slot using `fd_stake_ci_get_lsched_for_slot` and check if it is found; if not, increment the `leader_sched_not_found` metric and return -1.
    - Get the slot leader's public key using `fd_epoch_leaders_get`; if not found, increment the `leader_not_found` metric and return -1.
    - Retrieve the shred destination for the slot using `fd_stake_ci_get_sdest_for_slot` and convert the leader's public key to an index using `fd_shred_dest_pubkey_to_idx`; if no destination is found, increment the `leader_contact_not_found` metric and return -1.
    - Update `out_dest` with the destination information using `fd_shred_dest_idx_to_dest`.
    - Check if the IP address or port in `out_dest` is non-routable (i.e., zero); if so, increment the `leader_contact_nonroutable` metric and return -1.
    - If all checks pass, return 0 indicating success.
- **Output**: Returns 0 on success, indicating that the leader's contact information was successfully retrieved and is routable; returns -1 if any step fails, with the appropriate metric incremented.


---
### handle\_new\_cluster\_contact\_info<!-- {{#callable:handle_new_cluster_contact_info}} -->
The `handle_new_cluster_contact_info` function processes new cluster contact information by updating the destination list in the context with data from a buffer.
- **Inputs**:
    - `ctx`: A pointer to the `fd_send_tile_ctx_t` structure, which holds the context for sending operations, including the destination list to be updated.
    - `buf`: A constant pointer to an unsigned character array containing the buffer with new cluster contact information.
    - `buf_sz`: An unsigned long integer representing the size of the buffer in bytes.
- **Control Flow**:
    - The function casts the buffer to a constant pointer of type `ulong` to interpret the header information.
    - It calculates the number of destinations (`dest_cnt`) by dividing the buffer size by the size of `fd_shred_dest_wire_t`.
    - The function initializes a pointer to the input destinations by casting the header to `fd_shred_dest_wire_t` type.
    - It initializes the destination list in the context by calling `fd_stake_ci_dest_add_init` with the context's stake information.
    - The function updates the context's `new_dest_ptr` and `new_dest_cnt` with the newly initialized destination list and count.
    - A loop iterates over each destination, copying the public key, IP address, and UDP port from the input destinations to the context's destination list.
- **Output**: The function does not return a value; it updates the destination list in the provided context with new cluster contact information.


---
### finalize\_new\_cluster\_contact\_info<!-- {{#callable:finalize_new_cluster_contact_info}} -->
The `finalize_new_cluster_contact_info` function finalizes the addition of new cluster contact information by updating the stake cluster information with the new destination count.
- **Inputs**:
    - `ctx`: A pointer to an `fd_send_tile_ctx_t` structure, which contains context information for sending tiles, including stake cluster information and new destination count.
- **Control Flow**:
    - The function calls `fd_stake_ci_dest_add_fini` with the `stake_ci` and `new_dest_cnt` from the `ctx` structure.
    - There are no conditional statements or loops; the function performs a single operation.
- **Output**: The function does not return any value; it performs an operation to finalize the stake cluster information.


---
### during\_frag<!-- {{#callable:during_frag}} -->
The `during_frag` function processes incoming data fragments based on their type, performing specific actions for stake, gossip, and replay data.
- **Inputs**:
    - `ctx`: A pointer to the `fd_send_tile_ctx_t` structure, which contains context information for the send tile.
    - `in_idx`: An index indicating which input link in the context is being processed.
    - `seq`: A sequence number for the fragment, marked as unused with `FD_PARAM_UNUSED`.
    - `sig`: A signature for the fragment, marked as unused with `FD_PARAM_UNUSED`.
    - `chunk`: The chunk identifier for the data fragment being processed.
    - `sz`: The size of the data fragment.
    - `ctl`: A control parameter for the fragment, marked as unused with `FD_PARAM_UNUSED`.
- **Control Flow**:
    - Retrieve the input link from the context using `in_idx` and check if the `chunk` is within the valid range defined by `chunk0` and `wmark`; log an error if not.
    - Convert the `chunk` to a memory address using `fd_chunk_to_laddr_const` and retrieve the `kind` of the input link.
    - If the `kind` is `IN_KIND_STAKE`, check if the size `sz` is within the expected range for stake updates; log an error if not, and initialize a stake message using `fd_stake_ci_stake_msg_init`.
    - If the `kind` is `IN_KIND_GOSSIP`, check if the size `sz` is within the expected range for gossip updates; log an error if not, and handle new cluster contact information using [`handle_new_cluster_contact_info`](#handle_new_cluster_contact_info).
    - If the `kind` is `IN_KIND_REPLAY`, check if the size `sz` matches the expected transaction size; log an error if not, and copy the data to the transaction buffer `ctx->txn_buf`.
- **Output**: The function does not return a value; it performs actions based on the type of data fragment processed.
- **Functions called**:
    - [`handle_new_cluster_contact_info`](#handle_new_cluster_contact_info)


---
### after\_frag<!-- {{#callable:after_frag}} -->
The `after_frag` function processes different types of incoming data fragments based on their kind, performing specific actions such as finalizing contact information, finalizing stake messages, or signing and sending transactions to a leader.
- **Inputs**:
    - `ctx`: A pointer to the `fd_send_tile_ctx_t` structure, which contains context information for sending tiles.
    - `in_idx`: An unsigned long integer representing the index of the input link in the context's input links array.
    - `seq`: An unsigned long integer representing the sequence number of the fragment (unused in this function).
    - `sig`: An unsigned long integer representing the signature of the fragment, used as the poh_slot for replay kind.
    - `sz`: An unsigned long integer representing the size of the fragment (unused in this function).
    - `tsorig`: An unsigned long integer representing the original timestamp of the fragment (unused in this function).
    - `tspub`: An unsigned long integer representing the publication timestamp of the fragment (unused in this function).
    - `stem`: A pointer to the `fd_stem_context_t` structure, which is used for publishing data (unused in this function).
- **Control Flow**:
    - Retrieve the input link from the context using the provided index `in_idx`.
    - Determine the kind of the input link (GOSSIP, STAKE, or REPLAY).
    - If the kind is GOSSIP, finalize the new cluster contact information and return.
    - If the kind is STAKE, finalize the stake message and return.
    - If the kind is REPLAY, retrieve the transaction from the context's transaction buffer.
    - Sign the transaction using the keyguard client.
    - Retrieve the current leader's contact information using the poh_slot derived from `sig`.
    - If the leader's contact information is found, send the transaction to the leader and increment the transaction sent metric.
    - Send the transaction to the gossip verification output and publish it using the stem context.
- **Output**: The function does not return a value; it performs actions based on the kind of the input link, such as finalizing contact information, finalizing stake messages, or sending transactions.
- **Functions called**:
    - [`finalize_new_cluster_contact_info`](#finalize_new_cluster_contact_info)
    - [`get_current_leader_tpu_vote_contact`](#get_current_leader_tpu_vote_contact)
    - [`send_packet`](#send_packet)


---
### privileged\_init<!-- {{#callable:privileged_init}} -->
The `privileged_init` function initializes a privileged context for a send tile by setting up scratch memory and loading an identity key.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the tile configuration.
- **Control Flow**:
    - Obtain a scratch memory address using `fd_topo_obj_laddr` with the provided `topo` and `tile->tile_obj_id`.
    - Initialize the scratch memory allocator with `FD_SCRATCH_ALLOC_INIT`.
    - Allocate memory for a `fd_send_tile_ctx_t` structure using `FD_SCRATCH_ALLOC_APPEND`.
    - Check if the `identity_key_path` in `tile->send` is an empty string; if so, log an error and terminate.
    - Load the identity key from the specified `identity_key_path` using `fd_keyload_load` and store it in `ctx->identity_key`.
- **Output**: The function does not return a value; it initializes the context and logs an error if the identity key path is not set.


---
### setup\_input\_link<!-- {{#callable:setup_input_link}} -->
The `setup_input_link` function initializes an input link in the context of a send tile by configuring its memory, chunk, watermark, and kind based on the topology and tile information.
- **Inputs**:
    - `ctx`: A pointer to the `fd_send_tile_ctx_t` structure, which holds the context for the send tile, including input and output link descriptors.
    - `topo`: A pointer to the `fd_topo_t` structure, representing the topology of the system, which includes information about links and workspaces.
    - `tile`: A pointer to the `fd_topo_tile_t` structure, representing the specific tile within the topology for which the input link is being set up.
    - `kind`: An unsigned long integer representing the kind of input link, which can be one of the predefined constants like `IN_KIND_GOSSIP`, `IN_KIND_REPLAY`, or `IN_KIND_STAKE`.
    - `name`: A constant character pointer representing the name of the input link to be set up.
- **Control Flow**:
    - Finds the index of the input link in the tile using `fd_topo_find_tile_in_link` with the given name and checks if it is valid.
    - Retrieves the input link from the topology using the found index and the tile's input link ID.
    - Initializes the input link descriptor in the context with the memory workspace, chunk start, watermark, and kind based on the topology's link and workspace information.
- **Output**: The function does not return a value; it modifies the `ctx` structure to set up the input link descriptor.


---
### setup\_output\_link<!-- {{#callable:setup_output_link}} -->
The `setup_output_link` function initializes an output link descriptor for a given topology and tile by setting up various parameters such as index, memory cache, synchronization address, depth, memory workspace, and chunk information.
- **Inputs**:
    - `desc`: A pointer to an `fd_send_link_out_t` structure that will be populated with the output link's configuration.
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology of the system.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile within the topology for which the output link is being set up.
    - `name`: A constant character pointer representing the name of the output link to be set up.
- **Control Flow**:
    - Finds the index of the output link in the topology using `fd_topo_find_tile_out_link` with the provided `topo`, `tile`, and `name` parameters.
    - Asserts that the found index is not `ULONG_MAX`, indicating a valid link was found.
    - Retrieves the `fd_topo_link_t` structure for the output link using the found index.
    - Populates the `desc` structure with the index, memory cache, synchronization address, depth, memory workspace, initial chunk, and watermark of the output link.
- **Output**: The function does not return a value; it modifies the `desc` structure in place to reflect the configuration of the specified output link.


---
### unprivileged\_init<!-- {{#callable:unprivileged_init}} -->
The `unprivileged_init` function initializes the unprivileged context for a send tile, setting up memory, network, and keyguard configurations.
- **Inputs**:
    - `topo`: A pointer to the `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to the `fd_topo_tile_t` structure representing the specific tile configuration.
- **Control Flow**:
    - Retrieve the local address of the tile object using `fd_topo_obj_laddr` and store it in `scratch`.
    - Check if the tile has any primary output links; if not, log an error and terminate.
    - Initialize scratch memory allocation using `FD_SCRATCH_ALLOC_INIT`.
    - Allocate and initialize a `fd_send_tile_ctx_t` context structure in the scratch memory.
    - Join a new stake consensus instance using `fd_stake_ci_join` and store it in the context's `stake_ci` field.
    - Set the network ID to 0 and initialize the TPU serve address and UDP header using `fd_ip4_udp_hdr_init`.
    - Set up input links for gossip, stake, and replay using [`setup_input_link`](#setup_input_link).
    - Set up output links for gossip verification and network using [`setup_output_link`](#setup_output_link).
    - Find and configure the keyguard client for signing transactions using `fd_keyguard_client_join`.
    - Initialize the metrics structure in the context to zero using `fd_memset`.
    - Finalize the scratch memory allocation and check for overflow; log an error if overflow is detected.
- **Output**: The function does not return a value; it initializes the context and configurations for the send tile.
- **Functions called**:
    - [`setup_input_link`](#setup_input_link)
    - [`setup_output_link`](#setup_output_link)
    - [`scratch_align`](#scratch_align)
    - [`scratch_footprint`](#scratch_footprint)


---
### populate\_allowed\_seccomp<!-- {{#callable:populate_allowed_seccomp}} -->
The `populate_allowed_seccomp` function populates a seccomp filter policy for a send tile and returns the instruction count for the policy.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure representing the tile configuration.
    - `out_cnt`: An unsigned long integer representing the count of output filters to be populated.
    - `out`: A pointer to a `struct sock_filter` array where the seccomp filter policy will be populated.
- **Control Flow**:
    - The function begins by explicitly ignoring the `topo` and `tile` parameters, indicating they are not used in the function body.
    - It calls the [`populate_sock_filter_policy_fd_send_tile`](generated/fd_send_tile_seccomp.h.driver.md#populate_sock_filter_policy_fd_send_tile) function with `out_cnt`, `out`, and the file descriptor obtained from `fd_log_private_logfile_fd()`.
    - The function returns the value of `sock_filter_policy_fd_send_tile_instr_cnt`, which presumably represents the number of instructions in the seccomp filter policy.
- **Output**: The function returns an unsigned long integer representing the number of instructions in the seccomp filter policy.
- **Functions called**:
    - [`populate_sock_filter_policy_fd_send_tile`](generated/fd_send_tile_seccomp.h.driver.md#populate_sock_filter_policy_fd_send_tile)


---
### populate\_allowed\_fds<!-- {{#callable:populate_allowed_fds}} -->
The `populate_allowed_fds` function populates an array with file descriptors that are allowed for use, specifically including standard error and a log file descriptor if available.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, representing the topology configuration.
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure, representing the tile configuration.
    - `out_fds_cnt`: An unsigned long integer representing the maximum number of file descriptors that can be stored in the `out_fds` array.
    - `out_fds`: A pointer to an integer array where the allowed file descriptors will be stored.
- **Control Flow**:
    - The function begins by casting the `topo` and `tile` parameters to void to indicate they are unused.
    - It checks if `out_fds_cnt` is less than 2, and if so, logs an error and terminates the program.
    - It initializes `out_cnt` to 0 and assigns the file descriptor for standard error (2) to the first position in `out_fds`, incrementing `out_cnt`.
    - It checks if the log file descriptor is valid (not -1) and, if so, assigns it to the next position in `out_fds`, incrementing `out_cnt`.
    - The function returns the count of file descriptors added to `out_fds`.
- **Output**: The function returns an unsigned long integer representing the number of file descriptors that were successfully populated in the `out_fds` array.


---
### metrics\_write<!-- {{#callable:metrics_write}} -->
The `metrics_write` function updates various transaction and leader metrics in the context of a send tile.
- **Inputs**:
    - `ctx`: A pointer to an `fd_send_tile_ctx_t` structure containing the metrics to be updated.
- **Control Flow**:
    - The function begins by updating the transaction metrics using the `FD_MCNT_SET` macro to set the `TXNS_SENT_TO_LEADER` metric from the context's metrics.
    - It then updates several leader-related metrics using the `FD_MCNT_SET` macro: `LEADER_SCHED_NOT_FOUND`, `LEADER_NOT_FOUND`, `LEADER_CONTACT_NOT_FOUND`, and `LEADER_CONTACT_NONROUTABLE`, all from the context's metrics.
- **Output**: The function does not return any value; it updates metrics in the provided context.



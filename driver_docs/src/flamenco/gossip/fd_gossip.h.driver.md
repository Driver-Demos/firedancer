# Purpose
The provided C header file, `fd_gossip.h`, defines the interface and data structures for a gossip protocol implementation. This file is part of a larger system, likely related to a distributed network or blockchain, where nodes communicate with each other to share information. The header file includes definitions for constants, enumerations, data structures, and function prototypes that facilitate the management and operation of the gossip protocol. It provides a comprehensive set of functionalities, including setting up and managing peer connections, handling incoming and outgoing messages, and maintaining protocol state and metrics.

Key components of this file include the `fd_gossip_t` structure, which represents the global state of the gossip protocol, and the `fd_gossip_config_t` structure, which holds configuration details such as public keys and callback functions for message delivery, packet sending, and signing. The file also defines several functions for initializing, configuring, and managing the gossip protocol, such as [`fd_gossip_new`](#fd_gossip_new), [`fd_gossip_set_config`](#fd_gossip_set_config), and [`fd_gossip_push_value`](#fd_gossip_push_value). Additionally, it includes metrics tracking through the `fd_gossip_metrics_t` structure, which records various statistics about the protocol's operation, such as packet counts and message handling outcomes. This header file is intended to be included in other C source files that implement or utilize the gossip protocol, providing a public API for interacting with the protocol's functionalities.
# Imports and Dependencies

---
- `../types/fd_types.h`
- `../../util/valloc/fd_valloc.h`
- `../../disco/metrics/generated/fd_metrics_gossip.h`
- `../../util/net/fd_net_headers.h`


# Global Variables

---
### fd\_gossip\_new
- **Type**: `function pointer`
- **Description**: `fd_gossip_new` is a function pointer that initializes a new gossip protocol instance in shared memory. It takes a pointer to shared memory (`shmem`) and a seed value (`seed`) as parameters, and returns a pointer to the initialized gossip protocol instance.
- **Use**: This function is used to create a new instance of the gossip protocol, allocating necessary resources in shared memory.


---
### fd\_gossip\_join
- **Type**: `fd_gossip_t *`
- **Description**: The `fd_gossip_join` is a function that returns a pointer to a `fd_gossip_t` structure. This function is used to join a gossip protocol instance using a shared memory map (`shmap`).
- **Use**: This variable is used to initialize and return a pointer to a gossip protocol instance, allowing the caller to interact with the gossip protocol.


---
### fd\_gossip\_leave
- **Type**: `function pointer`
- **Description**: `fd_gossip_leave` is a function pointer that takes a pointer to an `fd_gossip_t` structure as an argument and returns a void pointer. It is part of the global state management functions for the gossip protocol, likely used to handle the process of leaving or disconnecting from a gossip network.
- **Use**: This function is used to manage the disconnection or cleanup process of a gossip protocol instance.


---
### fd\_gossip\_delete
- **Type**: `function pointer`
- **Description**: `fd_gossip_delete` is a function pointer that takes a single argument, `shmap`, which is a pointer to a memory location, and returns a pointer to a memory location. It is part of the global state management functions for the gossip protocol, likely used to delete or clean up resources associated with a shared memory map.
- **Use**: This function is used to delete or clean up resources associated with a shared memory map in the gossip protocol.


---
### fd\_gossip\_addr\_str
- **Type**: `function`
- **Description**: The `fd_gossip_addr_str` function converts a `fd_gossip_peer_addr_t` address into a string representation. It takes a destination buffer `dst`, its length `dstlen`, and a source address `src` as parameters.
- **Use**: This function is used to obtain a human-readable string representation of a gossip peer address for logging or display purposes.


---
### fd\_gossip\_get\_metrics
- **Type**: `fd_gossip_metrics_t *`
- **Description**: The `fd_gossip_get_metrics` is a function that returns a pointer to a `fd_gossip_metrics_t` structure. This structure contains various metrics related to the gossip protocol, such as counts of received and sent packets, message types, and other protocol-specific statistics.
- **Use**: This function is used to retrieve the current metrics of the gossip protocol for monitoring and analysis purposes.


# Data Structures

---
### fd\_gossip\_crds\_route
- **Type**: `enum`
- **Members**:
    - `FD_GOSSIP_CRDS_ROUTE_PULL_RESP`: Represents a route for handling pull responses in the gossip protocol.
    - `FD_GOSSIP_CRDS_ROUTE_PUSH`: Represents a route for handling push messages in the gossip protocol.
    - `FD_GOSSIP_CRDS_ROUTE_INTERNAL`: Represents an internal route used within the gossip protocol.
    - `FD_GOSSIP_CRDS_ROUTE_ENUM_CNT`: Indicates the count of CRDS route enum members.
- **Description**: The `fd_gossip_crds_route` enum defines different routes for handling messages in a gossip protocol, specifically for CRDS (Conflict-free Replicated Data Structures) operations. It includes routes for pull responses, push messages, and internal operations, with an additional member to count the total number of routes defined. This enum is used to categorize and manage the flow of different types of messages within the gossip protocol.


---
### fd\_gossip\_crds\_route\_t
- **Type**: `enum`
- **Members**:
    - `FD_GOSSIP_CRDS_ROUTE_PULL_RESP`: Represents a route for handling pull responses in the CRDS protocol.
    - `FD_GOSSIP_CRDS_ROUTE_PUSH`: Represents a route for handling push messages in the CRDS protocol.
    - `FD_GOSSIP_CRDS_ROUTE_INTERNAL`: Represents an internal route used within the CRDS protocol.
    - `FD_GOSSIP_CRDS_ROUTE_ENUM_CNT`: Indicates the count of CRDS route enum members.
- **Description**: The `fd_gossip_crds_route_t` is an enumeration that defines different routes used in the CRDS (Conflict-free Replicated Data Structures) protocol within the gossip system. It includes routes for handling pull responses, push messages, and internal operations, providing a structured way to manage different types of CRDS message routing. The enumeration also includes a count of its members for easy reference.


---
### fd\_gossip\_t
- **Type**: `struct`
- **Members**:
    - `fd_gossip`: Represents the global state of the gossip protocol.
- **Description**: The `fd_gossip_t` structure is a key component of a gossip protocol implementation, encapsulating the global state necessary for managing peer-to-peer communication. It is used to maintain and update the state of the network, handle incoming and outgoing messages, and manage peer connections. The structure is designed to support various operations such as setting configurations, updating addresses, managing peers, and handling protocol-specific timed events. It is integral to the functioning of the gossip protocol, enabling efficient data dissemination and network management.


---
### fd\_gossip\_peer\_addr\_t
- **Type**: `union`
- **Members**:
    - `fd_ip4_port`: Represents an IP address and port combination, used as a peer address in the gossip protocol.
- **Description**: The `fd_gossip_peer_addr_t` is a union type that is defined as `fd_ip4_port`, which is used to represent a peer's address in the gossip protocol. This data structure is crucial for network communication within the gossip protocol, as it encapsulates the necessary information to identify and communicate with peers using their IP address and port number.


---
### fd\_gossip\_config
- **Type**: `struct`
- **Members**:
    - `public_key`: Pointer to the public key of the node.
    - `node_outset`: Timestamp in milliseconds when the node's public key was set.
    - `my_addr`: Address of the node in the gossip network.
    - `my_version`: Version information of the node in the gossip protocol.
    - `shred_version`: Version of the shred protocol used by the node.
    - `deliver_fun`: Function pointer for handling incoming data delivery.
    - `deliver_arg`: Argument passed to the data delivery function.
    - `send_fun`: Function pointer for sending packets to peers.
    - `send_arg`: Argument passed to the send packet function.
    - `sign_fun`: Function pointer for signing data.
    - `sign_arg`: Argument passed to the sign function.
- **Description**: The `fd_gossip_config` structure is a configuration data structure used in a gossip protocol implementation. It holds essential information about a node, including its public key, address, version, and shred version. Additionally, it contains function pointers for handling data delivery, sending packets, and signing data, along with their respective arguments. This structure is crucial for setting up and managing the behavior of a node within the gossip network, allowing it to communicate and interact with other nodes effectively.


---
### fd\_gossip\_config\_t
- **Type**: `struct`
- **Members**:
    - `public_key`: Pointer to the public key of the node.
    - `node_outset`: Timestamp in milliseconds when the node's public key was set.
    - `my_addr`: Address of the node in the gossip network.
    - `my_version`: Version information of the node.
    - `shred_version`: Version of the shred protocol used by the node.
    - `deliver_fun`: Callback function for delivering received data.
    - `deliver_arg`: Argument passed to the deliver callback function.
    - `send_fun`: Callback function for sending packets.
    - `send_arg`: Argument passed to the send callback function.
    - `sign_fun`: Callback function for signing data.
    - `sign_arg`: Argument passed to the sign callback function.
- **Description**: The `fd_gossip_config_t` structure is a configuration data structure for the gossip protocol, containing essential information and callback functions necessary for the operation of a node within the gossip network. It includes the node's public key, address, version, and shred version, as well as callback functions for data delivery, packet sending, and data signing, each with their respective arguments. This structure is crucial for setting up and managing the node's participation in the gossip protocol, allowing it to communicate and interact with other nodes effectively.


---
### fd\_gossip\_metrics
- **Type**: `struct`
- **Members**:
    - `recv_pkt_cnt`: Counts the number of received packets.
    - `recv_pkt_corrupted_msg`: Counts the number of corrupted messages received in packets.
    - `recv_message`: Array counting received gossip messages by type.
    - `recv_unknown_message`: Counts the number of unknown messages received.
    - `recv_crds`: 2D array counting received CRDS messages by route and value type.
    - `recv_crds_duplicate_message`: 2D array counting duplicate CRDS messages received by route and value type.
    - `recv_crds_drop_reason`: Array counting reasons for dropping received CRDS messages.
    - `push_crds`: Array counting CRDS values pushed by type.
    - `push_crds_duplicate`: Counts duplicate CRDS messages pushed.
    - `push_crds_drop_reason`: Array counting reasons for dropping pushed CRDS messages.
    - `push_crds_queue_cnt`: Counts the number of CRDS values queued for pushing.
    - `value_meta_cnt`: Counts the number of metadata values.
    - `value_vec_cnt`: Counts the number of vector values.
    - `active_push_destinations`: Counts the number of active push destinations.
    - `refresh_push_states_failcnt`: Counts the number of failures in refreshing push states.
    - `handle_pull_req_fails`: Array counting failures in handling pull requests.
    - `handle_pull_req_bloom_filter_result`: Array counting results of bloom filter checks in pull requests.
    - `handle_pull_req_npackets`: Counts the number of packets handled in pull requests.
    - `handle_prune_fails`: Array counting failures in handling prune messages.
    - `make_prune_stale_entry`: Counts stale entries made during prune message creation.
    - `make_prune_high_duplicates`: Counts high duplicate entries made during prune message creation.
    - `make_prune_requested_origins`: Counts requested origins made during prune message creation.
    - `make_prune_sign_data_encode_failed`: Counts failures in encoding sign data during prune message creation.
    - `send_message`: Array counting sent gossip messages by type.
    - `send_packet_cnt`: Counts the number of packets sent.
    - `send_ping_events`: Array counting sent ping events by type.
    - `recv_ping_invalid_signature`: Counts received ping events with invalid signatures.
    - `recv_pong_events`: Array counting received pong events by type.
    - `gossip_peer_cnt`: Array counting the number of known gossip peers by type.
- **Description**: The `fd_gossip_metrics` structure is designed to track various metrics related to the gossip protocol's operation, including packet reception and transmission, message handling, CRDS operations, and peer interactions. It contains numerous counters and arrays that record the frequency and types of events such as received and sent packets, corrupted messages, CRDS message handling, push and pull request outcomes, and ping/pong events. This structure is essential for monitoring the performance and reliability of the gossip protocol, providing detailed insights into its operational metrics.


---
### fd\_gossip\_metrics\_t
- **Type**: `struct`
- **Members**:
    - `recv_pkt_cnt`: Counts the number of received packets.
    - `recv_pkt_corrupted_msg`: Counts the number of corrupted messages received in packets.
    - `recv_message`: Array counting received gossip messages by type.
    - `recv_unknown_message`: Counts the number of unknown messages received.
    - `recv_crds`: 2D array counting received CRDS messages by route and value type.
    - `recv_crds_duplicate_message`: 2D array counting duplicate CRDS messages received by route and value type.
    - `recv_crds_drop_reason`: Counts reasons for dropping received CRDS messages.
    - `push_crds`: Array counting CRDS values pushed by type.
    - `push_crds_duplicate`: Counts duplicate CRDS messages pushed.
    - `push_crds_drop_reason`: Counts reasons for dropping pushed CRDS messages.
    - `push_crds_queue_cnt`: Counts the number of CRDS values queued for pushing.
    - `value_meta_cnt`: Counts the number of metadata values.
    - `value_vec_cnt`: Counts the number of vector values.
    - `active_push_destinations`: Counts the number of active push destinations.
    - `refresh_push_states_failcnt`: Counts failures in refreshing push states.
    - `handle_pull_req_fails`: Array counting failures in handling pull requests.
    - `handle_pull_req_bloom_filter_result`: Array counting results of bloom filter checks in pull requests.
    - `handle_pull_req_npackets`: Counts the number of packets in pull requests.
    - `handle_prune_fails`: Array counting failures in handling prune messages.
    - `make_prune_stale_entry`: Counts stale entries made during prune operations.
    - `make_prune_high_duplicates`: Counts high duplicate entries made during prune operations.
    - `make_prune_requested_origins`: Counts requested origins made during prune operations.
    - `make_prune_sign_data_encode_failed`: Counts failures in encoding sign data during prune operations.
    - `send_message`: Array counting sent gossip messages by type.
    - `send_packet_cnt`: Counts the number of packets sent.
    - `send_ping_events`: Array counting ping events sent.
    - `recv_ping_invalid_signature`: Counts received pings with invalid signatures.
    - `recv_pong_events`: Array counting pong events received.
    - `gossip_peer_cnt`: Array counting the number of gossip peers by type.
- **Description**: The `fd_gossip_metrics_t` structure is designed to track various metrics related to the operation of a gossip protocol. It includes counters for received and sent packets, messages, and CRDS (Conflict-free Replicated Data Structures) operations, as well as metrics for handling pull requests, prune messages, and ping/pong events. The structure provides detailed insights into the performance and behavior of the gossip protocol, allowing for monitoring and debugging of the system's communication processes.


# Function Declarations (Public API)

---
### fd\_gossip\_align<!-- {{#callable_declaration:fd_gossip_align}} -->
Return the required memory alignment for gossip structures.
- **Description**: This function provides the memory alignment requirement for gossip-related data structures. It is essential to use this alignment value when allocating memory for these structures to ensure proper operation and avoid undefined behavior. This function can be called at any time and does not depend on any prior initialization.
- **Inputs**: None
- **Output**: Returns the alignment requirement as an unsigned long integer, which is 128.
- **See also**: [`fd_gossip_align`](fd_gossip.c.driver.md#fd_gossip_align)  (Implementation)


---
### fd\_gossip\_footprint<!-- {{#callable_declaration:fd_gossip_footprint}} -->
Calculate the memory footprint required for a gossip instance.
- **Description**: This function computes the total memory footprint needed to allocate a gossip instance, including all its associated data structures. It should be called to determine the size of memory to allocate before initializing a gossip instance. The function does not require any parameters and returns the size in bytes. It is essential to ensure that the returned size is available in memory before proceeding with gossip instance creation.
- **Inputs**: None
- **Output**: Returns the size in bytes of the memory footprint required for a gossip instance.
- **See also**: [`fd_gossip_footprint`](fd_gossip.c.driver.md#fd_gossip_footprint)  (Implementation)


---
### fd\_gossip\_new<!-- {{#callable_declaration:fd_gossip_new}} -->
Allocate and initialize a new gossip protocol instance in shared memory.
- **Description**: This function sets up a new instance of the gossip protocol by allocating and initializing the necessary data structures in the provided shared memory region. It should be called when a new gossip protocol instance is needed, and the shared memory must have sufficient space as determined by the gossip footprint. The function initializes various components of the gossip protocol, including peer tables, active and inactive lists, value metadata, and more, using the provided seed for any necessary randomization. It is important to ensure that the shared memory region is properly aligned and has enough space to accommodate all allocations; otherwise, an error will be logged.
- **Inputs**:
    - `shmem`: A pointer to the shared memory region where the gossip protocol instance will be allocated. The memory must be properly aligned and have sufficient space as determined by the gossip footprint. The caller retains ownership of this memory.
    - `seed`: An unsigned long integer used to seed any randomization processes within the gossip protocol. It should be a valid seed value for random number generation.
- **Output**: A pointer to the newly created gossip protocol instance, or logs an error if the shared memory is insufficient.
- **See also**: [`fd_gossip_new`](fd_gossip.c.driver.md#fd_gossip_new)  (Implementation)


---
### fd\_gossip\_join<!-- {{#callable_declaration:fd_gossip_join}} -->
Converts a shared memory pointer to a gossip protocol state pointer.
- **Description**: Use this function to obtain a pointer to the global state of the gossip protocol from a shared memory region. This is typically called after the shared memory has been initialized and configured for use with the gossip protocol. The function assumes that the shared memory is correctly set up and does not perform any validation on the input pointer. It is important to ensure that the shared memory is properly aligned and contains a valid gossip protocol state before calling this function.
- **Inputs**:
    - `shmap`: A pointer to the shared memory region that contains the gossip protocol state. The pointer must not be null and should be properly aligned and initialized for use with the gossip protocol. The function does not perform any validation on this pointer.
- **Output**: Returns a pointer to the gossip protocol state (`fd_gossip_t`) located at the provided shared memory address.
- **See also**: [`fd_gossip_join`](fd_gossip.c.driver.md#fd_gossip_join)  (Implementation)


---
### fd\_gossip\_leave<!-- {{#callable_declaration:fd_gossip_leave}} -->
Leaves the gossip protocol.
- **Description**: This function is used to leave the gossip protocol by providing a pointer to the gossip state. It should be called when a node no longer wishes to participate in the gossip network. The function does not perform any operations other than returning the provided pointer, so it is the caller's responsibility to manage any necessary cleanup or deallocation of resources associated with the gossip state.
- **Inputs**:
    - `join`: A pointer to an fd_gossip_t structure representing the gossip state. The pointer must not be null, and the caller retains ownership of the memory. The function does not validate the pointer or perform any operations on it.
- **Output**: Returns the same pointer that was passed in as the parameter, allowing the caller to continue managing the gossip state as needed.
- **See also**: [`fd_gossip_leave`](fd_gossip.c.driver.md#fd_gossip_leave)  (Implementation)


---
### fd\_gossip\_delete<!-- {{#callable_declaration:fd_gossip_delete}} -->
Deletes and cleans up a gossip protocol instance.
- **Description**: Use this function to delete and clean up resources associated with a gossip protocol instance. It should be called when the gossip instance is no longer needed to ensure that all associated resources are properly released. This function expects a valid pointer to a shared memory region representing the gossip instance. It returns the same pointer after performing the cleanup, allowing for potential further operations on the memory if needed. Ensure that the pointer provided is not null and points to a valid, initialized gossip instance.
- **Inputs**:
    - `shmap`: A pointer to the shared memory region representing the gossip instance. Must not be null and should point to a valid, initialized gossip instance. The function will handle invalid pointers by not performing any operations.
- **Output**: Returns the same pointer provided as input, allowing for potential further operations on the memory.
- **See also**: [`fd_gossip_delete`](fd_gossip.c.driver.md#fd_gossip_delete)  (Implementation)


---
### fd\_gossip\_from\_soladdr<!-- {{#callable_declaration:fd_gossip_from_soladdr}} -->
Converts a socket address to a peer address.
- **Description**: Use this function to convert a socket address of type `fd_gossip_socket_addr_t` to a peer address of type `fd_gossip_peer_addr_t`. This function is typically used when you need to translate network socket information into a format suitable for peer-to-peer communication within the gossip protocol. The function expects the source address to be of the IPv4 type; otherwise, it will log an error and return a failure code. Ensure that the destination pointer is valid and that the source address is correctly initialized before calling this function.
- **Inputs**:
    - `dst`: A pointer to an `fd_gossip_peer_addr_t` where the converted address will be stored. Must not be null, and the caller retains ownership.
    - `src`: A pointer to a constant `fd_gossip_socket_addr_t` representing the source socket address. Must not be null and should be properly initialized with a valid IPv4 address.
- **Output**: Returns 0 on successful conversion of an IPv4 address, or -1 if the address family is invalid.
- **See also**: [`fd_gossip_from_soladdr`](fd_gossip.c.driver.md#fd_gossip_from_soladdr)  (Implementation)


---
### fd\_gossip\_to\_soladdr<!-- {{#callable_declaration:fd_gossip_to_soladdr}} -->
Convert a peer address to a socket address.
- **Description**: Use this function to convert a `fd_gossip_peer_addr_t` structure, which represents a peer address, into a `fd_gossip_socket_addr_t` structure, which represents a socket address. This is typically used when you need to translate peer-specific address information into a format suitable for socket operations. Ensure that both input and output pointers are valid and non-null before calling this function.
- **Inputs**:
    - `dst`: A pointer to a `fd_gossip_socket_addr_t` structure where the converted socket address will be stored. Must not be null. The caller is responsible for allocating this structure.
    - `src`: A pointer to a `fd_gossip_peer_addr_t` structure containing the peer address to be converted. Must not be null. The caller retains ownership of this structure.
- **Output**: Returns 0 on successful conversion. The `dst` structure is populated with the converted socket address.
- **See also**: [`fd_gossip_to_soladdr`](fd_gossip.c.driver.md#fd_gossip_to_soladdr)  (Implementation)


---
### fd\_gossip\_contact\_info\_v2\_to\_v1<!-- {{#callable_declaration:fd_gossip_contact_info_v2_to_v1}} -->
Convert contact information from version 2 to version 1 format.
- **Description**: Use this function to transform a contact information structure from version 2 to version 1 format. This is useful when compatibility with older systems or components that only understand the version 1 format is required. The function initializes the version 1 structure to zero before populating it with relevant data from the version 2 structure. It must be called with valid pointers to both version 2 and version 1 structures, and the caller is responsible for ensuring these pointers are not null.
- **Inputs**:
    - `v2`: A pointer to a constant fd_gossip_contact_info_v2_t structure containing the version 2 contact information. Must not be null. The caller retains ownership.
    - `v1`: A pointer to an fd_gossip_contact_info_v1_t structure where the converted version 1 contact information will be stored. Must not be null. The structure is initialized to zero before conversion.
- **Output**: None
- **See also**: [`fd_gossip_contact_info_v2_to_v1`](fd_gossip.c.driver.md#fd_gossip_contact_info_v2_to_v1)  (Implementation)


---
### fd\_gossip\_contact\_info\_v2\_find\_proto\_ident<!-- {{#callable_declaration:fd_gossip_contact_info_v2_find_proto_ident}} -->
Finds the socket address for a given protocol identifier in contact information.
- **Description**: This function searches through the contact information to find a socket entry that matches the specified protocol identifier. If a matching entry is found, it populates the provided output address structure with the corresponding IP address and port. The function returns a success indicator. It should be used when you need to retrieve the network address associated with a specific protocol from a contact information structure. Ensure that the contact information and output address pointers are valid before calling this function.
- **Inputs**:
    - `contact_info`: A pointer to a constant fd_gossip_contact_info_v2_t structure containing the contact information to search. Must not be null.
    - `proto_ident`: An unsigned character representing the protocol identifier to search for. Valid identifiers are defined by the application.
    - `out_addr`: A pointer to an fd_gossip_socket_addr_t structure where the found address will be stored. Must not be null.
- **Output**: Returns 1 if a matching protocol identifier is found and the address is successfully populated; otherwise, returns 0.
- **See also**: [`fd_gossip_contact_info_v2_find_proto_ident`](fd_gossip.c.driver.md#fd_gossip_contact_info_v2_find_proto_ident)  (Implementation)


---
### fd\_gossip\_set\_config<!-- {{#callable_declaration:fd_gossip_set_config}} -->
Configure the gossip protocol with the specified settings.
- **Description**: This function sets up the gossip protocol's configuration using the provided settings. It should be called to initialize the gossip protocol with specific parameters such as public key, node address, version, and callback functions for data delivery, packet sending, and signing. The function must be called after the gossip protocol has been initialized and before it is used for communication. It locks the global state during configuration to ensure thread safety and returns 0 upon successful configuration.
- **Inputs**:
    - `glob`: A pointer to an fd_gossip_t structure representing the global state of the gossip protocol. Must not be null and should be properly initialized before calling this function.
    - `config`: A pointer to an fd_gossip_config_t structure containing the configuration settings for the gossip protocol. Must not be null and should be filled with valid data before calling this function.
- **Output**: Returns 0 on successful configuration.
- **See also**: [`fd_gossip_set_config`](fd_gossip.c.driver.md#fd_gossip_set_config)  (Implementation)


---
### fd\_gossip\_update\_addr<!-- {{#callable_declaration:fd_gossip_update_addr}} -->
Update the gossip protocol's binding address.
- **Description**: This function updates the binding address used by the gossip protocol. It should be called when the address of the node changes and needs to be reflected in the gossip protocol's configuration. The function must be called with a valid gossip protocol state and a valid address. It ensures that the new address is set and refreshes the contact information accordingly. This function is thread-safe and can be called concurrently with other operations on the gossip protocol.
- **Inputs**:
    - `glob`: A pointer to a valid `fd_gossip_t` structure representing the global state of the gossip protocol. Must not be null.
    - `my_addr`: A pointer to a `fd_gossip_peer_addr_t` structure containing the new address to be set. Must not be null.
- **Output**: Returns 0 on success, indicating the address was updated successfully.
- **See also**: [`fd_gossip_update_addr`](fd_gossip.c.driver.md#fd_gossip_update_addr)  (Implementation)


---
### fd\_gossip\_update\_repair\_addr<!-- {{#callable_declaration:fd_gossip_update_repair_addr}} -->
Update the repair service address in the gossip protocol.
- **Description**: This function updates the repair service address for the gossip protocol's global state. It should be called when the repair service address needs to be changed, ensuring that the gossip protocol uses the new address for repair services. The function must be called with a valid `fd_gossip_t` object that represents the global state of the gossip protocol and a valid `fd_gossip_peer_addr_t` object that specifies the new repair service address. The function is thread-safe and locks the global state during the update process to prevent concurrent modifications.
- **Inputs**:
    - `glob`: A pointer to an `fd_gossip_t` object representing the global state of the gossip protocol. Must not be null.
    - `serve`: A pointer to an `fd_gossip_peer_addr_t` object representing the new repair service address. Must not be null.
- **Output**: Returns 0 on successful update of the repair service address.
- **See also**: [`fd_gossip_update_repair_addr`](fd_gossip.c.driver.md#fd_gossip_update_repair_addr)  (Implementation)


---
### fd\_gossip\_update\_tvu\_addr<!-- {{#callable_declaration:fd_gossip_update_tvu_addr}} -->
Update the TVU service address in the gossip protocol.
- **Description**: This function updates the TVU (Transaction Validation Unit) service address for the gossip protocol. It should be called whenever the TVU address needs to be changed, ensuring that the gossip protocol uses the correct address for communication. The function locks the global gossip state, updates the address, refreshes the contact information, and then unlocks the state. It is important to ensure that the `glob` parameter is a valid and initialized gossip state before calling this function.
- **Inputs**:
    - `glob`: A pointer to a `fd_gossip_t` structure representing the global state of the gossip protocol. Must not be null and should be properly initialized before calling this function.
    - `tvu`: A pointer to a `fd_gossip_peer_addr_t` representing the new TVU service address. Must not be null.
- **Output**: Returns 0 on successful update of the TVU address.
- **See also**: [`fd_gossip_update_tvu_addr`](fd_gossip.c.driver.md#fd_gossip_update_tvu_addr)  (Implementation)


---
### fd\_gossip\_update\_tpu\_addr<!-- {{#callable_declaration:fd_gossip_update_tpu_addr}} -->
Update the TPU and TPU_QUIC service addresses in the gossip protocol.
- **Description**: This function updates the TPU and TPU_QUIC service addresses for the gossip protocol's global state. It should be called when there is a need to change the service addresses associated with the TPU and TPU_QUIC roles. The function locks the global state to ensure thread safety during the update process and refreshes the contact information to reflect the new addresses. It is important to ensure that the `glob` parameter is properly initialized before calling this function.
- **Inputs**:
    - `glob`: A pointer to the global state of the gossip protocol. Must not be null and should be properly initialized before use. The caller retains ownership.
    - `tpu`: A pointer to the new TPU service address. Must not be null. The caller retains ownership.
    - `tpu_quic`: A pointer to the new TPU_QUIC service address. Must not be null. The caller retains ownership.
- **Output**: Returns 0 on successful update of the addresses.
- **See also**: [`fd_gossip_update_tpu_addr`](fd_gossip.c.driver.md#fd_gossip_update_tpu_addr)  (Implementation)


---
### fd\_gossip\_update\_tpu\_vote\_addr<!-- {{#callable_declaration:fd_gossip_update_tpu_vote_addr}} -->
Update the TPU vote service address in the gossip protocol.
- **Description**: This function updates the TPU vote service address for the gossip protocol's global state. It should be called when the TPU vote address needs to be changed, ensuring that the gossip protocol uses the new address for TPU vote-related communications. The function must be called with a valid gossip protocol state and a valid TPU vote address. It locks the global state during the update to ensure thread safety and refreshes the contact information sockets to reflect the new address.
- **Inputs**:
    - `glob`: A pointer to the global state of the gossip protocol. Must not be null, and should be properly initialized before calling this function. The caller retains ownership.
    - `tpu_vote`: A pointer to the new TPU vote address to be set. Must not be null, and should point to a valid address structure. The caller retains ownership.
- **Output**: Returns 0 on successful update of the TPU vote address.
- **See also**: [`fd_gossip_update_tpu_vote_addr`](fd_gossip.c.driver.md#fd_gossip_update_tpu_vote_addr)  (Implementation)


---
### fd\_gossip\_set\_shred\_version<!-- {{#callable_declaration:fd_gossip_set_shred_version}} -->
Set the shred version for the gossip protocol.
- **Description**: This function sets the shred version in the global state of the gossip protocol. It should be called after receiving a contact information message that includes the shred version. This function is typically used to update the shred version as part of the protocol's configuration or during runtime when the shred version changes.
- **Inputs**:
    - `glob`: A pointer to the global state of the gossip protocol. Must not be null, and should be properly initialized before calling this function.
    - `shred_version`: The shred version to set. It is an unsigned short integer representing the version number.
- **Output**: None
- **See also**: [`fd_gossip_set_shred_version`](fd_gossip.c.driver.md#fd_gossip_set_shred_version)  (Implementation)


---
### fd\_gossip\_add\_active\_peer<!-- {{#callable_declaration:fd_gossip_add_active_peer}} -->
Add a peer to the active gossip list.
- **Description**: This function is used to add a peer to the active list of peers in the gossip protocol. It should be called when a new peer needs to be actively communicated with. The function requires that the global gossip state has been initialized and is thread-safe, as it locks the global state during the operation. If the active peer list is full, the function will not add the peer and will return an error. This function is useful for managing dynamic peer lists in a networked environment.
- **Inputs**:
    - `glob`: A pointer to the global gossip state structure. It must be initialized and not null. The caller retains ownership.
    - `addr`: A pointer to the address of the peer to be added. It must not be null, and the address should be valid and unique among active peers.
- **Output**: Returns 0 on success, or -1 if the active peer list is full.
- **See also**: [`fd_gossip_add_active_peer`](fd_gossip.c.driver.md#fd_gossip_add_active_peer)  (Implementation)


---
### fd\_gossip\_push\_value<!-- {{#callable_declaration:fd_gossip_push_value}} -->
Publish an outgoing value in the gossip protocol.
- **Description**: This function is used to publish a value within the gossip protocol, setting the source ID and wallclock automatically. It should be called when a new value needs to be disseminated through the gossip network. The function optionally returns the gossip key associated with the value, which can be used for further reference or operations. It is important to ensure that the global gossip state is properly initialized before calling this function to avoid undefined behavior.
- **Inputs**:
    - `glob`: A pointer to the global gossip state. Must not be null and should be properly initialized before use.
    - `data`: A pointer to the CRDS data to be published. Must not be null and should contain valid data to be disseminated.
    - `key_opt`: An optional pointer to a hash structure where the gossip key will be stored. Can be null if the key is not needed by the caller.
- **Output**: Returns an integer status code indicating success or failure of the operation.
- **See also**: [`fd_gossip_push_value`](fd_gossip.c.driver.md#fd_gossip_push_value)  (Implementation)


---
### fd\_gossip\_settime<!-- {{#callable_declaration:fd_gossip_settime}} -->
Set the current protocol time in nanoseconds.
- **Description**: This function updates the current protocol time for the gossip protocol to the specified timestamp in nanoseconds. It is essential to call this function frequently to ensure the protocol operates with the correct time reference. This function should be called before starting or continuing protocol operations to maintain accurate timing.
- **Inputs**:
    - `glob`: A pointer to an fd_gossip_t structure representing the global state of the gossip protocol. Must not be null.
    - `ts`: A long integer representing the timestamp in nanoseconds to set as the current protocol time. There are no explicit constraints on the value, but it should represent a valid time in the context of the protocol.
- **Output**: None
- **See also**: [`fd_gossip_settime`](fd_gossip.c.driver.md#fd_gossip_settime)  (Implementation)


---
### fd\_gossip\_gettime<!-- {{#callable_declaration:fd_gossip_gettime}} -->
Retrieve the current protocol time in nanoseconds.
- **Description**: Use this function to obtain the current protocol time as maintained by the gossip protocol. It is useful for synchronizing operations or logging events relative to the protocol's timeline. Ensure that the gossip structure has been properly initialized and the time has been set using `fd_gossip_settime` before calling this function to get meaningful results.
- **Inputs**:
    - `glob`: A pointer to an `fd_gossip_t` structure representing the global state of the gossip protocol. Must not be null, and should be properly initialized before use.
- **Output**: Returns the current protocol time in nanoseconds as a long integer.
- **See also**: [`fd_gossip_gettime`](fd_gossip.c.driver.md#fd_gossip_gettime)  (Implementation)


---
### fd\_gossip\_start<!-- {{#callable_declaration:fd_gossip_start}} -->
Start timed events and protocol behavior for the gossip system.
- **Description**: This function initiates the timed events and other protocol behaviors necessary for the gossip system to operate. It must be called after the protocol time has been set using `fd_gossip_settime`. This function schedules various internal tasks such as random pulls, pings, logging statistics, refreshing push states, and more, to occur at specific intervals. It is essential to ensure that the global state `glob` is properly initialized and configured before calling this function to avoid undefined behavior.
- **Inputs**:
    - `glob`: A pointer to an `fd_gossip_t` structure representing the global state of the gossip protocol. It must be non-null and properly initialized before calling this function. The caller retains ownership of this pointer.
- **Output**: Returns 0 on successful initiation of the protocol behavior.
- **See also**: [`fd_gossip_start`](fd_gossip.c.driver.md#fd_gossip_start)  (Implementation)


---
### fd\_gossip\_continue<!-- {{#callable_declaration:fd_gossip_continue}} -->
Dispatch timed events and protocol behavior in the main loop.
- **Description**: This function should be called within the main loop of the application to handle timed events and other protocol-related behaviors. It is recommended to call `fd_gossip_settime` before invoking this function to ensure the protocol time is up-to-date. The function processes events that are due based on the current protocol time and executes their associated callbacks. It is essential for maintaining the protocol's operation and should be called regularly to ensure timely event handling.
- **Inputs**:
    - `glob`: A pointer to an `fd_gossip_t` structure representing the global state of the gossip protocol. This pointer must not be null, and the structure should be properly initialized before calling this function.
- **Output**: Returns 0 on successful dispatch of events. The function does not modify the input structure beyond the expected protocol operations.
- **See also**: [`fd_gossip_continue`](fd_gossip.c.driver.md#fd_gossip_continue)  (Implementation)


---
### fd\_gossip\_recv\_packet<!-- {{#callable_declaration:fd_gossip_recv_packet}} -->
Processes a received gossip packet.
- **Description**: This function is used to process a raw gossip packet received from a peer. It should be called whenever a new packet is received to ensure that the packet is decoded and handled appropriately. The function expects the global gossip state to be initialized and the message to be well-formed. If the message is corrupted or cannot be decoded, the function will log a warning and return an error code. This function increments internal metrics counters for received packets and corrupted messages.
- **Inputs**:
    - `glob`: A pointer to the global gossip state. Must not be null and should be properly initialized before calling this function. The caller retains ownership.
    - `msg`: A pointer to the message data to be processed. Must not be null and should point to a valid memory region containing the message.
    - `msglen`: The length of the message data pointed to by `msg`. Must accurately reflect the size of the message data.
    - `from`: A pointer to the address of the sender of the message. Must not be null and should point to a valid `fd_gossip_peer_addr_t` structure.
- **Output**: Returns 0 on success, or -1 if the message is corrupted or cannot be decoded.
- **See also**: [`fd_gossip_recv_packet`](fd_gossip.c.driver.md#fd_gossip_recv_packet)  (Implementation)


---
### fd\_gossip\_get\_shred\_version<!-- {{#callable_declaration:fd_gossip_get_shred_version}} -->
Retrieve the shred version from the gossip global state.
- **Description**: Use this function to obtain the current shred version associated with the gossip protocol's global state. This is typically used to verify or log the shred version that the node is currently operating with. Ensure that the `fd_gossip_t` structure has been properly initialized and configured before calling this function to avoid undefined behavior.
- **Inputs**:
    - `glob`: A pointer to a constant `fd_gossip_t` structure representing the global state of the gossip protocol. This pointer must not be null and should point to a valid, initialized gossip state.
- **Output**: Returns the current shred version as an unsigned short integer.
- **See also**: [`fd_gossip_get_shred_version`](fd_gossip.c.driver.md#fd_gossip_get_shred_version)  (Implementation)


---
### fd\_gossip\_set\_stake\_weights<!-- {{#callable_declaration:fd_gossip_set_stake_weights}} -->
Set the stake weights for the gossip protocol.
- **Description**: This function updates the stake weights in the gossip protocol, which are used to influence the weight of validators in the network. It should be called when the stake weights need to be updated, ensuring that the `gossip` structure is properly initialized and locked. The function requires a valid array of stake weights and a count of these weights, which must not exceed the maximum allowed number. If the input parameters are invalid, the function logs an error and does not proceed with the update.
- **Inputs**:
    - `gossip`: A pointer to an initialized `fd_gossip_t` structure. The caller must ensure this is not null and that the structure is properly initialized before calling this function.
    - `stake_weights`: A pointer to an array of `fd_stake_weight_t` structures representing the stake weights to be set. This must not be null, and each element should have a valid stake value.
    - `stake_weights_cnt`: The number of elements in the `stake_weights` array. This must not exceed the maximum allowed stake weights, otherwise an error is logged.
- **Output**: None
- **See also**: [`fd_gossip_set_stake_weights`](fd_gossip.c.driver.md#fd_gossip_set_stake_weights)  (Implementation)


---
### fd\_gossip\_set\_entrypoints<!-- {{#callable_declaration:fd_gossip_set_entrypoints}} -->
Set initial entrypoints for the gossip protocol.
- **Description**: This function configures the initial set of known validators (entrypoints) for the gossip protocol, which are used to establish initial connections. It should be called once during the startup phase of the application to set up the initial network peers. The function updates the gossip structure with the provided entrypoints, which are expected to be valid IP and port combinations. This setup is crucial for the gossip protocol to begin communication with other nodes.
- **Inputs**:
    - `gossip`: A pointer to an fd_gossip_t structure representing the global state of the gossip protocol. Must not be null.
    - `entrypoints`: A pointer to an array of fd_ip4_port_t structures, each representing an IP address and port of a known validator. The array must contain valid entries and must not be null if entrypoints_cnt is greater than zero.
    - `entrypoints_cnt`: The number of entrypoints in the entrypoints array. Must be a non-negative value and should not exceed the maximum capacity of the gossip structure.
- **Output**: None
- **See also**: [`fd_gossip_set_entrypoints`](fd_gossip.c.driver.md#fd_gossip_set_entrypoints)  (Implementation)


---
### fd\_gossip\_is\_allowed\_entrypoint<!-- {{#callable_declaration:fd_gossip_is_allowed_entrypoint}} -->
Check if a peer address is an allowed entrypoint.
- **Description**: Use this function to determine if a given peer address is recognized as an allowed entrypoint within the gossip protocol. This is typically used to verify if a peer is part of the initial set of known validators that the system can communicate with. The function should be called with a valid gossip state and a peer address to check. It is important to ensure that the gossip structure has been properly initialized and configured with entrypoints before calling this function.
- **Inputs**:
    - `gossip`: A pointer to an fd_gossip_t structure representing the global state of the gossip protocol. It must be initialized and configured with entrypoints before use. Must not be null.
    - `addr`: A pointer to an fd_gossip_peer_addr_t representing the peer address to check. Must not be null.
- **Output**: Returns 1 if the peer address is an allowed entrypoint, otherwise returns 0.
- **See also**: [`fd_gossip_is_allowed_entrypoint`](fd_gossip.c.driver.md#fd_gossip_is_allowed_entrypoint)  (Implementation)


---
### fd\_gossip\_get\_metrics<!-- {{#callable_declaration:fd_gossip_get_metrics}} -->
Retrieve the metrics from a gossip instance.
- **Description**: Use this function to access the metrics associated with a specific gossip instance. This can be useful for monitoring and analyzing the performance and behavior of the gossip protocol. The function must be called with a valid gossip instance that has been properly initialized. It provides a direct reference to the metrics structure, allowing the caller to read the current metrics data.
- **Inputs**:
    - `gossip`: A pointer to an initialized fd_gossip_t instance. Must not be null. The caller retains ownership and responsibility for ensuring the instance is valid.
- **Output**: A pointer to the fd_gossip_metrics_t structure associated with the provided gossip instance.
- **See also**: [`fd_gossip_get_metrics`](fd_gossip.c.driver.md#fd_gossip_get_metrics)  (Implementation)



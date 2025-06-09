# Purpose
The provided C header file, `fd_repair.h`, is part of a larger software system and is designed to facilitate a network repair protocol, likely within a distributed system or blockchain environment. This file defines a set of data structures, constants, and functions that manage the repair process, which involves requesting and receiving data (referred to as "shreds") from other nodes or validators in the network. The file includes definitions for managing active connections with peers, tracking inflight requests, and handling metrics related to the repair operations. It also provides mechanisms for configuring the repair service, updating network addresses, and managing protocol timing and events.

Key components of this file include the `fd_repair` structure, which encapsulates the global state of the repair protocol, and several hash and equality functions for managing peer addresses and inflight requests. The file defines a public API for initializing and managing the repair service, including functions for setting configuration parameters, adding active peers, and handling protocol events. Additionally, it includes metrics tracking to monitor the performance and effectiveness of the repair operations. This header file is intended to be included in other parts of the system, providing a comprehensive interface for managing network repairs in a distributed environment.
# Imports and Dependencies

---
- `../gossip/fd_gossip.h`
- `../../ballet/shred/fd_shred.h`
- `../runtime/context/fd_exec_epoch_ctx.h`
- `../../disco/metrics/generated/fd_metrics_repair.h`
- `../../util/tmpl/fd_map_giant.c`


# Global Variables

---
### fd\_repair\_new
- **Type**: `function pointer`
- **Description**: `fd_repair_new` is a function that initializes a new repair data structure in shared memory and seeds it with a random number generator seed. It returns a pointer to the newly created repair data structure.
- **Use**: This function is used to allocate and initialize a new instance of the `fd_repair_t` structure in shared memory, setting up the necessary state for the repair protocol.


---
### fd\_repair\_join
- **Type**: `fd_repair_t *`
- **Description**: The `fd_repair_join` is a function that returns a pointer to an `fd_repair_t` structure. This function is used to join or attach to a shared memory region that contains the repair service's global state.
- **Use**: This variable is used to access and manipulate the global state of the repair service by joining a shared memory segment.


---
### fd\_repair\_leave
- **Type**: `function pointer`
- **Description**: `fd_repair_leave` is a function pointer that takes a pointer to an `fd_repair_t` structure as an argument and returns a `void` pointer. It is part of the global state management functions for the repair protocol.
- **Use**: This function is used to leave or detach from a joined repair protocol instance, likely performing cleanup or state transition operations.


---
### fd\_repair\_delete
- **Type**: `function pointer`
- **Description**: `fd_repair_delete` is a function pointer that takes a single argument of type `void *` and returns a `void *`. It is likely used to perform cleanup or deallocation operations on a shared memory map (`shmap`).
- **Use**: This function is used to delete or clean up resources associated with a shared memory map in the repair protocol.


---
### fd\_repair\_get\_metrics
- **Type**: `fd_repair_metrics_t *`
- **Description**: The `fd_repair_get_metrics` function returns a pointer to the `fd_repair_metrics_t` structure, which contains various metrics related to the repair service's operation. This structure includes fields for tracking the number of packets received and sent, as well as specific types of packets and any corrupted or invalid packets encountered.
- **Use**: This function is used to access the metrics data of a repair service instance, allowing for monitoring and analysis of its performance.


# Data Structures

---
### fd\_active\_elem
- **Type**: `struct`
- **Members**:
    - `key`: Public identifier and map key.
    - `next`: Used internally by fd_map_giant.
    - `addr`: Address of the repair peer.
    - `avg_reqs`: Moving average of the number of requests.
    - `avg_reps`: Moving average of the number of responses.
    - `avg_lat`: Moving average of response latency.
    - `stake`: Stake associated with the element.
- **Description**: The `fd_active_elem` structure is part of an active table used in a repair protocol to manage validators that are being queried for repairs. It includes a public key as an identifier, an internal index for mapping, and a peer address. Additionally, it tracks moving averages of requests, responses, and latency, which can be useful metrics for evaluating the performance and reliability of the repair process. The stake field represents the stake associated with the validator, which may influence the repair protocol's behavior.


---
### fd\_active\_elem\_t
- **Type**: `struct`
- **Members**:
    - `key`: Public identifier and map key.
    - `next`: Used internally by fd_map_giant.
    - `addr`: Address of the repair peer.
    - `avg_reqs`: Moving average of the number of requests.
    - `avg_reps`: Moving average of the number of responses.
    - `avg_lat`: Moving average of response latency.
    - `stake`: Stake associated with the validator.
- **Description**: The `fd_active_elem_t` structure represents an element in the active table of validators that are being queried for repairs. It includes a public key as an identifier and map key, an address for the repair peer, and several fields for tracking performance metrics such as the moving average of requests, responses, and response latency. Additionally, it contains a stake value representing the validator's stake in the network. The `next` field is used internally for managing the structure within a larger map.


---
### fd\_needed\_elem\_type
- **Type**: `enum`
- **Members**:
    - `fd_needed_window_index`: Represents a needed element type for a window index.
    - `fd_needed_highest_window_index`: Represents a needed element type for the highest window index.
    - `fd_needed_orphan`: Represents a needed element type for an orphan.
- **Description**: The `fd_needed_elem_type` is an enumeration that defines different types of elements that are needed in the context of a repair protocol. It includes three specific types: `fd_needed_window_index`, `fd_needed_highest_window_index`, and `fd_needed_orphan`, each representing a distinct category of elements that may be required during the repair process.


---
### fd\_inflight\_key
- **Type**: `struct`
- **Members**:
    - `type`: An enumeration indicating the type of element needed, defined by `fd_needed_elem_type`.
    - `slot`: An unsigned long integer representing the slot number associated with the inflight key.
    - `shred_index`: An unsigned integer representing the index of the shred within the slot.
- **Description**: The `fd_inflight_key` structure is used to uniquely identify a specific inflight request for a shred in a distributed repair protocol. It consists of a type, slot, and shred index, which together allow the system to track and manage requests for missing data elements efficiently. This structure is crucial for ensuring that the repair protocol can accurately identify and process requests for data that is needed to maintain the integrity and consistency of the distributed system.


---
### fd\_inflight\_key\_t
- **Type**: `struct`
- **Members**:
    - `type`: An enumeration of type `fd_needed_elem_type` indicating the type of inflight element.
    - `slot`: An unsigned long integer representing the slot number associated with the inflight element.
    - `shred_index`: An unsigned integer representing the index of the shred within the slot.
- **Description**: The `fd_inflight_key_t` structure is used to uniquely identify an inflight element in the repair protocol. It consists of a type, slot, and shred index, which together help in tracking and managing the state of repair requests for specific data shreds in a distributed system. This structure is crucial for ensuring that repair requests are efficiently managed and tracked, preventing duplicate requests and optimizing network resource usage.


---
### fd\_inflight\_elem
- **Type**: `struct`
- **Members**:
    - `key`: A key of type `fd_inflight_key_t` that uniquely identifies the inflight element.
    - `last_send_time`: A `long` integer representing the last time a request was sent, in nanoseconds.
    - `req_cnt`: An unsigned integer (`uint`) that counts the number of requests made for this element.
    - `next`: An unsigned long integer (`ulong`) used for linking elements, possibly in a hash table or linked list.
- **Description**: The `fd_inflight_elem` structure is used to represent an element that is currently in-flight, meaning it is part of an ongoing process or transaction. It contains a key to uniquely identify the element, a timestamp of the last send operation, a count of how many requests have been made, and a pointer or index to the next element in a sequence. This structure is likely used in a context where tracking the state and history of network requests or similar operations is necessary, such as in a repair or data recovery protocol.


---
### fd\_inflight\_elem\_t
- **Type**: `struct`
- **Members**:
    - `key`: A key of type `fd_inflight_key_t` that identifies the inflight element.
    - `last_send_time`: A long integer representing the last time a request was sent.
    - `req_cnt`: An unsigned integer counting the number of requests made.
    - `next`: An unsigned long integer used for internal linking or indexing.
- **Description**: The `fd_inflight_elem_t` structure is used to represent an element in the inflight table, which tracks requests that are currently in progress. It contains a key of type `fd_inflight_key_t` to uniquely identify the request, a timestamp for the last time a request was sent, a count of how many requests have been made, and a `next` field for internal management, likely used for chaining or indexing within a data structure.


---
### fd\_pinged\_elem
- **Type**: `struct`
- **Members**:
    - `key`: Holds the address of a repair peer.
    - `next`: Used internally for linking elements in a data structure.
    - `id`: Stores the public key identifier of the peer.
    - `token`: Contains a hash token associated with the peer.
    - `good`: Indicates the status of the peer, typically whether it is considered 'good' or not.
- **Description**: The `fd_pinged_elem` structure is used to represent an element in a table of validator clients that have been pinged. It includes a key for the peer's address, a public key identifier, a hash token, and a status indicator to track whether the peer is considered reliable or 'good'. This structure is part of a larger system for managing and tracking network peers in a repair protocol.


---
### fd\_pinged\_elem\_t
- **Type**: `struct`
- **Members**:
    - `key`: Holds the repair peer address used as the map key.
    - `next`: Used internally by fd_map_giant for linking elements.
    - `id`: Stores the public key identifier of the peer.
    - `token`: Contains a hash token associated with the peer.
    - `good`: Indicates the status of the peer, typically whether it is considered 'good' or not.
- **Description**: The `fd_pinged_elem_t` structure is used to represent an element in a table of validator clients that have been pinged. It includes a key for the repair peer address, a public key identifier, a hash token, and a status indicator for the peer. This structure is part of a larger system for managing and tracking network peers in a repair protocol, and it is used in conjunction with a map to efficiently manage and access these elements.


---
### fd\_peer
- **Type**: `struct`
- **Members**:
    - `key`: A public key of type `fd_pubkey_t` used to uniquely identify the peer.
    - `ip4`: An IPv4 address and port of type `fd_ip4_port_t` representing the network location of the peer.
- **Description**: The `fd_peer` structure is a simple data structure used to represent a network peer in the system. It contains a public key (`key`) for identifying the peer and an IPv4 address with a port (`ip4`) for network communication. This structure is likely used in networking contexts where peers need to be uniquely identified and communicated with over a network.


---
### fd\_peer\_t
- **Type**: `typedef struct fd_peer fd_peer_t;`
- **Members**:
    - `key`: A public key used to identify the peer.
    - `ip4`: An IPv4 address and port number for the peer.
- **Description**: The `fd_peer_t` structure is a simple data structure used to represent a peer in the network. It contains a public key (`key`) for identifying the peer and an IPv4 address with a port (`ip4`) for network communication. This structure is likely used in the context of network operations where peers need to be identified and communicated with using their network addresses.


---
### fd\_repair\_metrics
- **Type**: `struct`
- **Members**:
    - `recv_clnt_pkt`: Counts the number of packets received from clients.
    - `recv_serv_pkt`: Counts the number of packets received from servers.
    - `recv_serv_corrupt_pkt`: Counts the number of corrupted packets received from servers.
    - `recv_serv_invalid_signature`: Counts the number of packets with invalid signatures received from servers.
    - `recv_serv_full_ping_table`: Counts the number of packets received when the server's ping table is full.
    - `recv_serv_pkt_types`: An array counting the types of packets received from servers, indexed by packet type.
    - `recv_pkt_corrupted_msg`: Counts the number of corrupted message packets received.
    - `send_pkt_cnt`: Counts the number of packets sent.
    - `sent_pkt_types`: An array counting the types of packets sent, indexed by request type.
- **Description**: The `fd_repair_metrics` structure is designed to track various metrics related to packet transmission and reception in a repair protocol. It includes counters for packets received from clients and servers, including specific counts for corrupted packets, invalid signatures, and full ping tables. Additionally, it maintains arrays to categorize received and sent packets by type, providing a comprehensive overview of network activity and aiding in performance monitoring and debugging.


---
### fd\_repair\_metrics\_t
- **Type**: `struct`
- **Members**:
    - `recv_clnt_pkt`: Counts the number of packets received from clients.
    - `recv_serv_pkt`: Counts the number of packets received from servers.
    - `recv_serv_corrupt_pkt`: Counts the number of corrupted packets received from servers.
    - `recv_serv_invalid_signature`: Counts the number of packets with invalid signatures received from servers.
    - `recv_serv_full_ping_table`: Counts the number of times the server's ping table is full.
    - `recv_serv_pkt_types`: Array counting the number of each type of packet received from servers.
    - `recv_pkt_corrupted_msg`: Counts the number of corrupted messages received in packets.
    - `send_pkt_cnt`: Counts the number of packets sent.
    - `sent_pkt_types`: Array counting the number of each type of packet sent.
- **Description**: The `fd_repair_metrics_t` structure is designed to track various metrics related to packet transmission and reception in a repair service. It includes counters for packets received from clients and servers, including corrupted packets and those with invalid signatures. Additionally, it tracks the number of packets sent and maintains arrays to count specific types of packets received and sent, providing a comprehensive overview of the network activity and performance of the repair service.


---
### fd\_repair
- **Type**: `struct`
- **Members**:
    - `now`: Current time in nanoseconds.
    - `public_key`: Pointer to the public key used for identification.
    - `private_key`: Pointer to the private key used for secure communication.
    - `service_addr`: Address used for repair services.
    - `intake_addr`: Address used for intake services.
    - `fun_arg`: Function argument used for sending raw packets on the network.
    - `actives`: Pointer to a table of validators actively being pinged, keyed by repair address.
    - `actives_sticky`: Cache of chosen repair peer samples.
    - `actives_sticky_cnt`: Count of active sticky peers.
    - `actives_random_seed`: Random seed for active peers.
    - `peers`: Array of peers with a maximum size defined by FD_ACTIVE_KEY_MAX.
    - `peer_cnt`: Number of peers currently in the peers array.
    - `peer_idx`: Maximum number of peers that can be stored in the peers array.
    - `dupdetect`: Pointer to a table for detecting duplicate requests.
    - `oldest_nonce`: Oldest nonce in the table of needed shreds.
    - `current_nonce`: Current nonce in the table of needed shreds.
    - `next_nonce`: Next nonce in the table of needed shreds.
    - `pinged`: Pointer to a table of validator clients that have been pinged.
    - `last_sends`: Timestamp of the last batch of sends.
    - `last_decay`: Timestamp of the last statistics decay.
    - `last_print`: Timestamp of the last statistics printout.
    - `last_good_peer_cache_file_write`: Timestamp of the last write to the good peer cache file.
    - `rng`: Random number generator instance.
    - `seed`: Seed for the random number generator.
    - `stake_weights_cnt`: Count of stake weights.
    - `stake_weights`: Pointer to an array of stake weights.
    - `good_peer_cache_file_fd`: File descriptor for the cache file of known good repair peers.
    - `metrics`: Metrics related to the repair process.
- **Description**: The `fd_repair` structure is a comprehensive data structure used in a network repair protocol, managing various aspects of communication and data integrity. It includes fields for time management, cryptographic keys, network addresses, and function arguments for packet transmission. The structure maintains tables for active validators, duplicate request detection, and needed shreds, along with metrics for performance monitoring. It also handles peer management, including a cache for sticky peers and a random number generator for operations requiring randomness. Additionally, it supports stake weight management and provides a mechanism for caching known good peers to expedite cold booting.


---
### fd\_repair\_t
- **Type**: `struct`
- **Members**:
    - `now`: Current time in nanoseconds.
    - `public_key`: Pointer to the public key of the repair service.
    - `private_key`: Pointer to the private key of the repair service.
    - `service_addr`: Repair service address.
    - `intake_addr`: Intake address for the repair service.
    - `fun_arg`: Argument for the function used to send raw packets on the network.
    - `actives`: Table of validators actively being pinged, keyed by repair address.
    - `actives_sticky`: Cache of chosen repair peer samples.
    - `actives_sticky_cnt`: Count of active sticky peers.
    - `actives_random_seed`: Random seed for active peers.
    - `peers`: Array of peers.
    - `peer_cnt`: Number of peers in the peers array.
    - `peer_idx`: Maximum number of peers in the peers array.
    - `dupdetect`: Table for duplicate request detection.
    - `oldest_nonce`: Oldest nonce in the table of needed shreds.
    - `current_nonce`: Current nonce in the table of needed shreds.
    - `next_nonce`: Next nonce in the table of needed shreds.
    - `pinged`: Table of validator clients that have been pinged.
    - `last_sends`: Timestamp of the last batch of sends.
    - `last_decay`: Timestamp of the last statistics decay.
    - `last_print`: Timestamp of the last statistics printout.
    - `last_good_peer_cache_file_write`: Timestamp of the last write to the good peer cache file.
    - `rng`: Random number generator.
    - `seed`: Seed for the random number generator.
    - `stake_weights_cnt`: Count of stake weights.
    - `stake_weights`: Pointer to the stake weights.
    - `good_peer_cache_file_fd`: File descriptor for the good peer cache file.
    - `metrics`: Metrics for the repair service.
- **Description**: The `fd_repair_t` structure is a comprehensive data structure used in a repair service protocol, managing various aspects of network repair operations. It includes fields for time management, cryptographic keys, network addresses, and active peer management. The structure also maintains tables for duplicate detection, needed shreds, and pinged validator clients. Additionally, it handles random number generation, stake weights, and metrics collection, providing a robust framework for managing repair operations in a distributed network environment.


---
### fd\_repair\_config
- **Type**: `struct`
- **Members**:
    - `public_key`: A pointer to the public key used for identification and encryption.
    - `private_key`: A pointer to the private key used for secure communication.
    - `service_addr`: The address of the repair service peer.
    - `intake_addr`: The address for receiving repair requests.
    - `good_peer_cache_file_fd`: File descriptor for the cache file storing known good peers.
- **Description**: The `fd_repair_config` structure is used to configure the repair service in a network protocol. It holds cryptographic keys for secure communication, addresses for service and intake operations, and a file descriptor for caching good peer information. This configuration is essential for setting up and managing the repair service's network interactions and maintaining a list of reliable peers.


---
### fd\_repair\_config\_t
- **Type**: `struct`
- **Members**:
    - `public_key`: Pointer to the public key used for repair operations.
    - `private_key`: Pointer to the private key used for repair operations.
    - `service_addr`: Address used for the repair service.
    - `intake_addr`: Address used for receiving repair requests.
    - `good_peer_cache_file_fd`: File descriptor for the cache file of known good repair peers.
- **Description**: The `fd_repair_config_t` structure is used to configure the repair service in a network protocol. It holds essential cryptographic keys and network addresses required for the repair operations, as well as a file descriptor for managing a cache of reliable peers. This configuration is crucial for initializing and managing the repair service's communication and security settings.


# Functions

---
### fd\_hash\_hash<!-- {{#callable:fd_hash_hash}} -->
The `fd_hash_hash` function computes a hash value by XORing the first element of a given hash key with a seed value.
- **Inputs**:
    - `key`: A pointer to an `fd_hash_t` structure, which contains an array of unsigned long integers representing the hash key.
    - `seed`: An unsigned long integer used as a seed value for the hash computation.
- **Control Flow**:
    - The function accesses the first element of the `ul` array within the `fd_hash_t` structure pointed to by `key`.
    - It performs a bitwise XOR operation between this element and the `seed`.
    - The result of the XOR operation is returned as the hash value.
- **Output**: The function returns an unsigned long integer representing the computed hash value.


---
### fd\_repair\_peer\_addr\_eq<!-- {{#callable:fd_repair_peer_addr_eq}} -->
The `fd_repair_peer_addr_eq` function checks if two `fd_repair_peer_addr_t` addresses are equal by comparing their `l` fields.
- **Inputs**:
    - `key1`: A pointer to the first `fd_repair_peer_addr_t` structure to compare.
    - `key2`: A pointer to the second `fd_repair_peer_addr_t` structure to compare.
- **Control Flow**:
    - The function begins by asserting that the size of `fd_repair_peer_addr_t` is equal to the size of `ulong` to ensure type consistency.
    - It then compares the `l` field of the two `fd_repair_peer_addr_t` structures pointed to by `key1` and `key2`.
    - The function returns the result of the comparison, which is `1` if the `l` fields are equal and `0` otherwise.
- **Output**: The function returns an integer, `1` if the two addresses are equal, and `0` if they are not.


---
### fd\_repair\_peer\_addr\_hash<!-- {{#callable:fd_repair_peer_addr_hash}} -->
The `fd_repair_peer_addr_hash` function computes a hash value for a given repair peer address and a seed.
- **Inputs**:
    - `key`: A pointer to an `fd_repair_peer_addr_t` structure representing the repair peer address to be hashed.
    - `seed`: An unsigned long integer used as a seed in the hash computation.
- **Control Flow**:
    - The function begins by asserting that the size of `fd_repair_peer_addr_t` is equal to the size of an unsigned long integer, ensuring type compatibility.
    - It then calculates the hash by adding the `l` field of the `key`, the `seed`, and a large constant (7242237688154252699UL), and then multiplying the result by another large constant (9540121337UL).
- **Output**: The function returns an unsigned long integer representing the computed hash value.


---
### fd\_repair\_peer\_addr\_copy<!-- {{#callable:fd_repair_peer_addr_copy}} -->
The `fd_repair_peer_addr_copy` function copies the address from one `fd_repair_peer_addr_t` structure to another.
- **Inputs**:
    - `keyd`: A pointer to the destination `fd_repair_peer_addr_t` structure where the address will be copied to.
    - `keys`: A pointer to the source `fd_repair_peer_addr_t` structure from which the address will be copied.
- **Control Flow**:
    - The function begins by asserting that the size of `fd_repair_peer_addr_t` is equal to the size of `ulong` to ensure type safety.
    - It then copies the `l` field from the source structure `keys` to the destination structure `keyd`.
- **Output**: The function does not return a value; it performs an in-place copy of the address.


---
### fd\_inflight\_eq<!-- {{#callable:fd_inflight_eq}} -->
The `fd_inflight_eq` function checks if two `fd_inflight_key_t` structures are equal by comparing their `type`, `slot`, and `shred_index` fields.
- **Inputs**:
    - `key1`: A pointer to the first `fd_inflight_key_t` structure to compare.
    - `key2`: A pointer to the second `fd_inflight_key_t` structure to compare.
- **Control Flow**:
    - The function compares the `type` field of `key1` and `key2` for equality.
    - It then compares the `slot` field of `key1` and `key2` for equality.
    - Finally, it compares the `shred_index` field of `key1` and `key2` for equality.
    - The function returns the result of the logical AND operation of these three comparisons.
- **Output**: The function returns an integer value, which is `1` if all fields (`type`, `slot`, and `shred_index`) of the two keys are equal, and `0` otherwise.


---
### fd\_inflight\_hash<!-- {{#callable:fd_inflight_hash}} -->
The `fd_inflight_hash` function computes a hash value for a given `fd_inflight_key_t` structure using a specified seed.
- **Inputs**:
    - `key`: A pointer to an `fd_inflight_key_t` structure containing the `slot` and `shred_index` fields to be used in the hash computation.
    - `seed`: An unsigned long integer used as a seed in the hash computation to ensure variability.
- **Control Flow**:
    - The function takes the `slot` value from the `key` structure and adds it to the `seed`.
    - The result is then multiplied by a large constant `9540121337UL`.
    - The `shred_index` from the `key` structure is multiplied by `131U` and added to the previous result.
    - The final result is returned as the hash value.
- **Output**: The function returns an unsigned long integer representing the computed hash value.


---
### fd\_inflight\_copy<!-- {{#callable:fd_inflight_copy}} -->
The `fd_inflight_copy` function copies the contents of one `fd_inflight_key_t` structure to another.
- **Inputs**:
    - `keyd`: A pointer to the destination `fd_inflight_key_t` structure where the data will be copied to.
    - `keys`: A pointer to the source `fd_inflight_key_t` structure from which the data will be copied.
- **Control Flow**:
    - The function takes two pointers to `fd_inflight_key_t` structures as arguments.
    - It performs a direct assignment of the contents from the source structure pointed to by `keys` to the destination structure pointed to by `keyd`.
- **Output**: The function does not return any value; it modifies the destination structure in place.


---
### fd\_repair\_nonce\_eq<!-- {{#callable:fd_repair_nonce_eq}} -->
The `fd_repair_nonce_eq` function checks if two `fd_repair_nonce_t` values are equal.
- **Inputs**:
    - `key1`: A pointer to the first `fd_repair_nonce_t` value to compare.
    - `key2`: A pointer to the second `fd_repair_nonce_t` value to compare.
- **Control Flow**:
    - The function dereferences both `key1` and `key2` to obtain their values.
    - It then compares these two values using the equality operator `==`.
    - The result of the comparison is returned as the function's output.
- **Output**: An integer value, where 1 indicates the two nonces are equal and 0 indicates they are not.


---
### fd\_repair\_nonce\_hash<!-- {{#callable:fd_repair_nonce_hash}} -->
The `fd_repair_nonce_hash` function computes a hash value from a given nonce and seed using a specific mathematical formula.
- **Inputs**:
    - `key`: A pointer to an `fd_repair_nonce_t` type, representing the nonce to be hashed.
    - `seed`: An `ulong` value used as a seed in the hash computation.
- **Control Flow**:
    - The function takes the value pointed to by `key` and adds it to the `seed` and a large constant `7242237688154252699UL`.
    - The result of the addition is then multiplied by another constant `9540121337UL`.
    - The final result of this multiplication is returned as the hash value.
- **Output**: The function returns an `ulong` representing the computed hash value.


---
### fd\_repair\_nonce\_copy<!-- {{#callable:fd_repair_nonce_copy}} -->
The `fd_repair_nonce_copy` function copies the value of one `fd_repair_nonce_t` variable to another.
- **Inputs**:
    - `keyd`: A pointer to the destination `fd_repair_nonce_t` variable where the value will be copied to.
    - `keys`: A pointer to the source `fd_repair_nonce_t` variable from which the value will be copied.
- **Control Flow**:
    - The function takes two pointers as arguments, `keyd` and `keys`.
    - It dereferences both pointers and assigns the value pointed to by `keys` to the location pointed to by `keyd`.
- **Output**: The function does not return a value; it performs an in-place copy of the nonce value from the source to the destination.


---
### fd\_repair\_align<!-- {{#callable:fd_repair_align}} -->
The `fd_repair_align` function returns a constant alignment value of 128.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, indicating it is intended for use within the same translation unit and suggests potential for optimization by the compiler.
    - The function is marked with `FD_FN_CONST`, indicating it has no side effects and its return value is determined solely by its parameters, which in this case are none.
    - The function simply returns the constant value `128UL`.
- **Output**: The function returns an unsigned long integer with the value 128, representing an alignment size.


---
### fd\_repair\_footprint<!-- {{#callable:fd_repair_footprint}} -->
The `fd_repair_footprint` function calculates the memory footprint required for various components of the repair system, including active, inflight, and pinged tables, as well as stake weights.
- **Inputs**: None
- **Control Flow**:
    - Initialize a variable `l` with `FD_LAYOUT_INIT` to start the layout calculation.
    - Append the size and alignment of `fd_repair_t` to `l` using `FD_LAYOUT_APPEND`.
    - Append the size and alignment of the active table to `l` using `FD_LAYOUT_APPEND`, with parameters from `fd_active_table_align()` and `fd_active_table_footprint(FD_ACTIVE_KEY_MAX)`.
    - Append the size and alignment of the inflight table to `l` using `FD_LAYOUT_APPEND`, with parameters from `fd_inflight_table_align()` and `fd_inflight_table_footprint(FD_NEEDED_KEY_MAX)`.
    - Append the size and alignment of the pinged table to `l` using `FD_LAYOUT_APPEND`, with parameters from `fd_pinged_table_align()` and `fd_pinged_table_footprint(FD_REPAIR_PINGED_MAX)`.
    - Append the size and alignment of the stake weights to `l` using `FD_LAYOUT_APPEND`, with parameters `alignof(fd_stake_weight_t)` and `FD_STAKE_WEIGHTS_MAX * sizeof(fd_stake_weight_t)`.
    - Finalize the layout calculation with `FD_LAYOUT_FINI(l, fd_repair_align())` and return the result.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the repair system's components.
- **Functions called**:
    - [`fd_repair_align`](#fd_repair_align)


# Function Declarations (Public API)

---
### fd\_repair\_align<!-- {{#callable_declaration:fd_repair_align}} -->
Returns the alignment requirement for repair data structures.
- **Description**: This function provides the alignment requirement for data structures used in the repair process. It is useful when allocating memory for these structures to ensure they are properly aligned for optimal performance and compatibility. This function can be called at any time and does not depend on any prior initialization or state.
- **Inputs**: None
- **Output**: Returns the alignment requirement as an unsigned long integer, which is 128.
- **See also**: [`fd_repair_align`](#fd_repair_align)  (Implementation)


---
### fd\_repair\_footprint<!-- {{#callable_declaration:fd_repair_footprint}} -->
Calculate the memory footprint required for the repair data structure.
- **Description**: This function calculates the total memory footprint required to store the repair data structure, including all associated tables and elements. It should be used to determine the amount of memory to allocate when setting up the repair system. The function does not require any parameters and can be called at any time to get the current footprint size. It is essential to ensure that sufficient memory is available based on this footprint before initializing the repair system.
- **Inputs**: None
- **Output**: Returns the total memory footprint in bytes as an unsigned long integer.
- **See also**: [`fd_repair_footprint`](#fd_repair_footprint)  (Implementation)


---
### fd\_repair\_new<!-- {{#callable_declaration:fd_repair_new}} -->
Allocate and initialize a new repair structure in shared memory.
- **Description**: This function sets up a new repair structure within a provided shared memory region, initializing it with a given random seed. It is typically used to prepare the repair service for operation, allocating necessary tables and setting initial states. The function must be called with a valid shared memory pointer that has enough space to accommodate the repair structure and its associated tables. If the allocated space is insufficient, an error is logged. This function is generally called once during the setup phase of the repair service.
- **Inputs**:
    - `shmem`: A pointer to a shared memory region where the repair structure will be allocated. It must be non-null and have sufficient space as determined by `fd_repair_footprint()`.
    - `seed`: An unsigned long integer used to initialize random number generation and other seeded operations within the repair structure. It can be any valid unsigned long value.
- **Output**: Returns a pointer to the newly allocated and initialized repair structure. If the allocation fails due to insufficient space, an error is logged, and the function does not return a valid pointer.
- **See also**: [`fd_repair_new`](fd_repair.c.driver.md#fd_repair_new)  (Implementation)


---
### fd\_repair\_join<!-- {{#callable_declaration:fd_repair_join}} -->
Joins a shared memory region as a repair context.
- **Description**: This function is used to join a shared memory region that is expected to be a repair context, allowing the caller to interact with the repair protocol. It should be called when a repair context is needed from a shared memory segment. The function assumes that the provided shared memory pointer is valid and correctly aligned for a `fd_repair_t` structure. It is the caller's responsibility to ensure that the shared memory region is properly initialized and that the pointer is not null.
- **Inputs**:
    - `shmap`: A pointer to a shared memory region that is expected to be a repair context. The pointer must not be null and should be correctly aligned for a `fd_repair_t` structure. The caller retains ownership of the memory.
- **Output**: Returns a pointer to an `fd_repair_t` structure representing the repair context. The returned pointer is the same as the input pointer, cast to `fd_repair_t *`.
- **See also**: [`fd_repair_join`](fd_repair.c.driver.md#fd_repair_join)  (Implementation)


---
### fd\_repair\_leave<!-- {{#callable_declaration:fd_repair_leave}} -->
Leaves the repair context and returns a pointer to it.
- **Description**: Use this function to leave a repair context that was previously joined. It is typically called when the repair operations are complete, and you want to clean up or transition out of the repair context. This function returns the same pointer that was passed to it, allowing for further operations or cleanup if necessary. Ensure that the pointer provided is valid and was obtained from a successful join operation.
- **Inputs**:
    - `join`: A pointer to an fd_repair_t structure representing the repair context to leave. Must not be null and should be a valid context obtained from a previous join operation.
- **Output**: Returns the same pointer that was passed in, allowing for further use or cleanup.
- **See also**: [`fd_repair_leave`](fd_repair.c.driver.md#fd_repair_leave)  (Implementation)


---
### fd\_repair\_delete<!-- {{#callable_declaration:fd_repair_delete}} -->
Deletes and cleans up a repair data structure.
- **Description**: Use this function to delete and clean up resources associated with a repair data structure that was previously initialized. It should be called when the repair data structure is no longer needed to ensure that all associated resources are properly released. This function must be called with a valid pointer to a shared memory region that was used to create the repair data structure. The function returns the same pointer that was passed to it, allowing for potential reuse or further management of the shared memory.
- **Inputs**:
    - `shmap`: A pointer to the shared memory region containing the repair data structure. Must not be null and should point to a valid repair data structure initialized by fd_repair_new.
- **Output**: Returns the same pointer to the shared memory region that was passed as input.
- **See also**: [`fd_repair_delete`](fd_repair.c.driver.md#fd_repair_delete)  (Implementation)


---
### fd\_repair\_set\_config<!-- {{#callable_declaration:fd_repair_set_config}} -->
Configure the repair service with the specified settings.
- **Description**: This function sets the configuration for a repair service instance using the provided configuration settings. It should be called to initialize or update the repair service's operational parameters, such as public and private keys, service and intake addresses, and the file descriptor for the good peer cache. This function must be called before starting the repair service to ensure it operates with the correct settings.
- **Inputs**:
    - `glob`: A pointer to an `fd_repair_t` structure representing the repair service instance to be configured. Must not be null.
    - `config`: A pointer to an `fd_repair_config_t` structure containing the configuration settings to apply. Must not be null and should be properly initialized with valid data.
- **Output**: Returns 0 on successful configuration.
- **See also**: [`fd_repair_set_config`](fd_repair.c.driver.md#fd_repair_set_config)  (Implementation)


---
### fd\_repair\_update\_addr<!-- {{#callable_declaration:fd_repair_update_addr}} -->
Update the intake and service addresses in the repair structure.
- **Description**: This function updates the intake and service addresses of a given repair structure with new values. It is typically used when the network addresses associated with the repair service need to be changed. The function must be called with valid pointers to the repair structure and the new address values. It does not perform any validation on the addresses themselves, so it is the caller's responsibility to ensure they are correct and valid.
- **Inputs**:
    - `glob`: A pointer to an fd_repair_t structure where the addresses will be updated. Must not be null.
    - `intake_addr`: A pointer to an fd_repair_peer_addr_t structure containing the new intake address. Must not be null.
    - `service_addr`: A pointer to an fd_repair_peer_addr_t structure containing the new service address. Must not be null.
- **Output**: Returns 0 on success. The function updates the intake and service addresses in the provided fd_repair_t structure.
- **See also**: [`fd_repair_update_addr`](fd_repair.c.driver.md#fd_repair_update_addr)  (Implementation)


---
### fd\_repair\_add\_active\_peer<!-- {{#callable_declaration:fd_repair_add_active_peer}} -->
Add a peer to the active repair list.
- **Description**: This function is used to add a peer to the active list of peers that the repair service will communicate with. It should be called when a new peer needs to be actively engaged in the repair process. The function checks if the peer is already active; if not, it adds the peer to the active list and initializes its metrics. This function must be called with a valid repair context and valid peer address and identifier.
- **Inputs**:
    - `glob`: A pointer to an fd_repair_t structure representing the global repair context. Must not be null.
    - `addr`: A pointer to an fd_repair_peer_addr_t structure representing the address of the peer to be added. Must not be null.
    - `id`: A pointer to an fd_pubkey_t structure representing the public key identifier of the peer. Must not be null.
- **Output**: Returns 0 if the peer was successfully added, or 1 if the peer was already active.
- **See also**: [`fd_repair_add_active_peer`](fd_repair.c.driver.md#fd_repair_add_active_peer)  (Implementation)


---
### fd\_repair\_settime<!-- {{#callable_declaration:fd_repair_settime}} -->
Set the current protocol time in nanoseconds.
- **Description**: This function updates the current protocol time within the repair data structure to the specified timestamp. It is essential to call this function frequently to ensure that the protocol operates with the correct time reference. This function should be called before starting timed events or other protocol behaviors to ensure accurate timing.
- **Inputs**:
    - `glob`: A pointer to an fd_repair_t structure representing the global repair data. Must not be null, as the function will attempt to dereference it to set the time.
    - `ts`: A long integer representing the timestamp in nanoseconds to set as the current protocol time. There are no explicit constraints on the value, but it should represent a valid time in the context of the protocol.
- **Output**: None
- **See also**: [`fd_repair_settime`](fd_repair.c.driver.md#fd_repair_settime)  (Implementation)


---
### fd\_repair\_gettime<!-- {{#callable_declaration:fd_repair_gettime}} -->
Retrieve the current protocol time in nanoseconds.
- **Description**: Use this function to obtain the current protocol time maintained within the repair service. This function is useful for synchronizing or logging events relative to the protocol's timeline. It is expected that the repair service has been properly initialized and the time has been set using `fd_repair_settime` before calling this function.
- **Inputs**:
    - `glob`: A pointer to an `fd_repair_t` structure representing the global state of the repair service. This pointer must not be null, and the structure should be properly initialized before use.
- **Output**: Returns the current protocol time in nanoseconds as a long integer.
- **See also**: [`fd_repair_gettime`](fd_repair.c.driver.md#fd_repair_gettime)  (Implementation)


---
### fd\_repair\_start<!-- {{#callable_declaration:fd_repair_start}} -->
Start timed events and other protocol behavior for the repair service.
- **Description**: This function initializes the timing-related fields of the repair service's global state and begins the protocol's timed events. It must be called after setting the current protocol time using `fd_repair_settime`. This function is essential for starting the repair protocol's operations, such as sending requests and managing statistics. It returns an integer status code indicating the success or failure of the operation.
- **Inputs**:
    - `glob`: A pointer to an `fd_repair_t` structure representing the global state of the repair service. This pointer must not be null, and the structure should be properly initialized before calling this function.
- **Output**: Returns an integer status code. A non-negative value indicates success, while a negative value indicates an error occurred during the operation.
- **See also**: [`fd_repair_start`](fd_repair.c.driver.md#fd_repair_start)  (Implementation)


---
### fd\_repair\_continue<!-- {{#callable_declaration:fd_repair_continue}} -->
Dispatches timed events and updates protocol behavior.
- **Description**: This function should be called within the main loop of the application to handle timed events and update the protocol state based on the current time. It is essential to call `fd_repair_settime` before invoking this function to ensure the time is correctly set. The function manages statistics printing, decay, and cache file writing based on elapsed time intervals. It is designed to be called frequently to maintain the protocol's responsiveness and accuracy.
- **Inputs**:
    - `glob`: A pointer to an `fd_repair_t` structure representing the global state of the repair protocol. This parameter must not be null, and the structure should be properly initialized before calling this function.
- **Output**: Returns 0 to indicate successful execution. The function does not modify the input structure in a way that affects its ownership or validity.
- **See also**: [`fd_repair_continue`](fd_repair.c.driver.md#fd_repair_continue)  (Implementation)


---
### fd\_repair\_inflight\_remove<!-- {{#callable_declaration:fd_repair_inflight_remove}} -->
Removes a shred from the inflight table.
- **Description**: Use this function to remove a specific shred from the inflight table within the repair system. This is typically done when a shred is no longer needed to be tracked as inflight, such as when it has been successfully processed or is no longer relevant. The function requires a valid repair context and specific identifiers for the shred to be removed. It is important to ensure that the provided identifiers correctly match an existing entry in the inflight table to avoid unnecessary operations.
- **Inputs**:
    - `glob`: A pointer to an fd_repair_t structure representing the global repair context. Must not be null and should be properly initialized before calling this function.
    - `slot`: An unsigned long representing the slot number of the shred to be removed. It should correspond to a valid slot in the inflight table.
    - `shred_index`: An unsigned integer representing the index of the shred within the specified slot. It should match the index of an existing shred in the inflight table.
- **Output**: Returns 0 after attempting to remove the shred from the inflight table. The function does not indicate whether the removal was successful or if the shred was found.
- **See also**: [`fd_repair_inflight_remove`](fd_repair.c.driver.md#fd_repair_inflight_remove)  (Implementation)


---
### fd\_repair\_need\_window\_index<!-- {{#callable_declaration:fd_repair_need_window_index}} -->
Register a request for a specific shred in a given slot.
- **Description**: This function is used to register a request for a specific shred identified by its index within a given slot in the repair system. It is typically called when there is a need to track or request a particular shred for repair purposes. The function should be called with valid parameters, and it assumes that the repair system has been properly initialized and is in a state ready to handle such requests.
- **Inputs**:
    - `glob`: A pointer to an fd_repair_t structure representing the global state of the repair system. Must not be null, and the repair system should be initialized before calling this function.
    - `slot`: An unsigned long integer representing the slot number for which the shred request is being made. It should be a valid slot number within the context of the repair system.
    - `shred_index`: An unsigned integer representing the index of the shred within the specified slot. It should be a valid shred index for the given slot.
- **Output**: Returns an integer status code indicating the success or failure of the request registration. Specific error codes are not detailed in the header file.
- **See also**: [`fd_repair_need_window_index`](fd_repair.c.driver.md#fd_repair_need_window_index)  (Implementation)


---
### fd\_repair\_need\_highest\_window\_index<!-- {{#callable_declaration:fd_repair_need_highest_window_index}} -->
Register a request for the highest window index shred.
- **Description**: This function is used to register a request for a shred with the highest window index for a given slot. It is typically called when there is a need to ensure that the highest window index shred is available for a specific slot in the repair process. This function should be used in contexts where maintaining the integrity and completeness of data is critical, such as in distributed systems requiring data repair. The function assumes that the global repair state has been properly initialized and that the slot and shred index provided are valid.
- **Inputs**:
    - `glob`: A pointer to an fd_repair_t structure representing the global repair state. Must not be null and should be properly initialized before calling this function.
    - `slot`: An unsigned long integer representing the slot for which the highest window index shred is needed. Must be a valid slot number.
    - `shred_index`: An unsigned integer representing the shred index within the slot. Must be a valid shred index.
- **Output**: Returns an integer status code indicating the success or failure of the request registration. Specific error codes are not detailed in the header.
- **See also**: [`fd_repair_need_highest_window_index`](fd_repair.c.driver.md#fd_repair_need_highest_window_index)  (Implementation)


---
### fd\_repair\_need\_orphan<!-- {{#callable_declaration:fd_repair_need_orphan}} -->
Register a request for an orphan shred.
- **Description**: This function is used to register a request for an orphan shred in the repair protocol. It should be called when there is a need to request a specific orphan shred identified by the slot number. This function is typically used in the context of a repair service that manages and requests missing data pieces (shreds) from peers. The function assumes that the repair service has been properly initialized and is actively managing repair requests.
- **Inputs**:
    - `glob`: A pointer to an fd_repair_t structure representing the global state of the repair service. Must not be null and should be properly initialized before calling this function.
    - `slot`: An unsigned long integer representing the slot number of the orphan shred to be requested. It should be a valid slot number within the context of the repair service.
- **Output**: Returns an integer status code indicating the success or failure of the request registration. A non-zero value typically indicates an error.
- **See also**: [`fd_repair_need_orphan`](fd_repair.c.driver.md#fd_repair_need_orphan)  (Implementation)


---
### fd\_repair\_construct\_request\_protocol<!-- {{#callable_declaration:fd_repair_construct_request_protocol}} -->
Constructs a repair request protocol message.
- **Description**: This function is used to construct a repair request protocol message based on the specified type of needed element, such as window index, highest window index, or orphan. It should be called when a repair request needs to be sent, and it populates the provided protocol structure with the necessary information. The function requires valid input parameters, including a global repair context, a protocol structure to populate, and details about the request such as slot, shred index, recipient, nonce, and current time. The function returns an integer indicating success or failure of the construction.
- **Inputs**:
    - `glob`: A pointer to an fd_repair_t structure representing the global repair context. Must not be null.
    - `protocol`: A pointer to an fd_repair_protocol_t structure where the constructed protocol message will be stored. Must not be null.
    - `type`: An enum value of type fd_needed_elem_type indicating the type of repair request to construct. Valid values are fd_needed_window_index, fd_needed_highest_window_index, and fd_needed_orphan.
    - `slot`: An unsigned long representing the slot number for the repair request. Must be a valid slot number.
    - `shred_index`: An unsigned integer representing the shred index for the repair request. Must be a valid shred index.
    - `recipient`: A pointer to an fd_pubkey_t structure representing the recipient's public key. Must not be null.
    - `nonce`: An unsigned integer representing a unique nonce for the request. Used to prevent replay attacks.
    - `now`: A long integer representing the current time in nanoseconds. Used to timestamp the request.
- **Output**: Returns 1 on successful construction of the protocol message, or 0 if the type is not recognized.
- **See also**: [`fd_repair_construct_request_protocol`](fd_repair.c.driver.md#fd_repair_construct_request_protocol)  (Implementation)


---
### fd\_repair\_add\_sticky<!-- {{#callable_declaration:fd_repair_add_sticky}} -->
Adds a peer to the sticky repair peer list.
- **Description**: Use this function to add a peer's public key to the list of sticky repair peers within the repair service's global state. This function is typically called when a peer is identified as a reliable repair source that should be persistently queried. Ensure that the global repair state has been properly initialized before calling this function. The function does not perform any validation on the input parameters, so it is the caller's responsibility to ensure that the provided public key is valid and that the sticky peer list has not exceeded its maximum capacity.
- **Inputs**:
    - `glob`: A pointer to the global repair state structure (`fd_repair_t`). Must not be null. The caller retains ownership.
    - `id`: A pointer to the public key (`fd_pubkey_t`) of the peer to be added. Must not be null. The caller retains ownership.
- **Output**: None
- **See also**: [`fd_repair_add_sticky`](fd_repair.c.driver.md#fd_repair_add_sticky)  (Implementation)


---
### fd\_repair\_set\_stake\_weights<!-- {{#callable_declaration:fd_repair_set_stake_weights}} -->
Sets the stake weights for a repair instance.
- **Description**: This function updates the stake weights for a given repair instance, which is used to manage validator identities. It should be called when the stake weights need to be initialized or updated. The function requires a valid pointer to a repair instance and a non-null array of stake weights. The number of stake weights must not exceed the defined maximum limit. If these conditions are not met, the function will log an error.
- **Inputs**:
    - `repair`: A pointer to an fd_repair_t structure representing the repair instance. Must not be null.
    - `stake_weights`: A pointer to an array of fd_stake_weight_t representing the stake weights. Must not be null.
    - `stake_weights_cnt`: The number of stake weights in the array. Must be less than or equal to FD_STAKE_WEIGHTS_MAX.
- **Output**: None
- **See also**: [`fd_repair_set_stake_weights`](fd_repair.c.driver.md#fd_repair_set_stake_weights)  (Implementation)


---
### fd\_repair\_get\_metrics<!-- {{#callable_declaration:fd_repair_get_metrics}} -->
Retrieve the repair metrics from a repair context.
- **Description**: Use this function to access the metrics associated with a given repair context. This can be useful for monitoring and analyzing the performance and behavior of the repair process. The function requires a valid repair context and returns a pointer to the metrics structure within that context. Ensure that the repair context is properly initialized before calling this function.
- **Inputs**:
    - `repair`: A pointer to an fd_repair_t structure representing the repair context. Must not be null and should be properly initialized before use.
- **Output**: Returns a pointer to an fd_repair_metrics_t structure containing the metrics of the specified repair context.
- **See also**: [`fd_repair_get_metrics`](fd_repair.c.driver.md#fd_repair_get_metrics)  (Implementation)



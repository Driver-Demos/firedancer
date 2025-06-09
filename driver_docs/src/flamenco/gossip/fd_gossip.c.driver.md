# Purpose
The provided C code is a comprehensive implementation of a gossip protocol, which is a decentralized communication protocol used to disseminate information across a network of nodes. This file is part of a larger system, likely a blockchain or distributed ledger technology, where nodes need to share state information efficiently and reliably. The code is structured to handle various aspects of the gossip protocol, including message encoding and decoding, peer management, and the handling of different types of gossip messages such as pull requests, push messages, pings, and pongs.

Key components of this implementation include the management of peer connections, the use of bloom filters for efficient data dissemination, and the handling of cryptographic signatures for message integrity and authenticity. The code defines several data structures for managing peers, active connections, and the state of the gossip protocol. It also includes mechanisms for scheduling and executing timed events, such as periodic pings to check the liveness of peers and the pruning of inactive connections. The file is designed to be part of a larger system, as indicated by the inclusion of other header files and the use of external functions for tasks like signing messages and sending packets over the network. Overall, this code provides a robust framework for implementing a gossip protocol in a distributed system.
# Imports and Dependencies

---
- `fd_gossip.h`
- `../../ballet/base58/fd_base58.h`
- `../../disco/keyguard/fd_keyguard.h`
- `math.h`
- `../../util/tmpl/fd_map_giant.c`
- `../../util/tmpl/fd_vec.c`
- `../../util/tmpl/fd_prq.c`
- `../../util/tmpl/fd_pool.c`
- `../../util/tmpl/fd_smallset.c`


# Data Structures

---
### fd\_peer\_elem
- **Type**: `struct`
- **Members**:
    - `key`: A unique address identifier for the peer, represented by `fd_gossip_peer_addr_t`.
    - `next`: An index or pointer to the next element in a linked list or similar structure.
    - `id`: A public identifier for the peer, represented by `fd_pubkey_t`.
    - `wallclock`: The last recorded time (in milliseconds) when this peer was heard from.
    - `stake`: The staking value for this validator, currently unimplemented.
- **Description**: The `fd_peer_elem` structure represents an element in a table of all known peers in a gossip network. Each element contains a unique key for identifying the peer, a public identifier, and a timestamp indicating the last time the peer was active. The structure also includes a placeholder for staking information, which is not yet implemented. This structure is used to manage and track the state of peers within the network.


---
### fd\_peer\_elem\_t
- **Type**: `struct`
- **Members**:
    - `key`: Stores the address of the peer as a key.
    - `next`: Index of the next element in the table.
    - `id`: Public identifier of the peer.
    - `wallclock`: Timestamp of the last update for this peer.
    - `stake`: Staking value for the validator, currently unimplemented.
- **Description**: The `fd_peer_elem_t` structure represents an element in the peers table, which contains all known validator addresses or IDs. It is used to store information about each peer, including their address, public identifier, and the last time they were updated. The structure also includes a field for staking information, although this is currently unimplemented. This data structure is part of a larger system for managing peer-to-peer communication and validation in a network.


---
### fd\_active\_elem
- **Type**: `struct`
- **Members**:
    - `key`: Stores the address of the gossip peer.
    - `next`: Holds the index of the next element in the table.
    - `id`: Public identifier of the peer.
    - `pingtime`: Timestamp of the last ping sent.
    - `pingcount`: Number of pings sent before receiving a pong.
    - `pingtoken`: Random data used for ping/pong verification.
    - `pongtime`: Timestamp of the last pong received.
    - `weight`: Selection weight for the peer.
- **Description**: The `fd_active_elem` structure represents an element in the active table, which is used to track validators that are actively pinged for liveness checking. It contains information about the peer's address, a unique identifier, and timestamps for the last ping and pong interactions. Additionally, it maintains a count of pings sent, a token for ping/pong verification, and a weight used for selection purposes.


---
### fd\_active\_elem\_t
- **Type**: `struct`
- **Members**:
    - `key`: Stores the address of the validator being actively pinged.
    - `next`: Used for linking elements in a hash table or list.
    - `id`: Public identifier of the validator.
    - `pingtime`: Timestamp of the last ping sent to the validator.
    - `pingcount`: Number of pings sent to the validator before receiving a pong.
    - `pingtoken`: Random data used in the ping/pong protocol for validation.
    - `pongtime`: Timestamp of the last pong received from the validator.
    - `weight`: Selection weight used for determining the importance or priority of the validator.
- **Description**: The `fd_active_elem_t` structure represents an element in the active table, which tracks validators that are being aggressively pinged for liveness checking. It contains information about the validator's address, public identifier, and timestamps for the last ping and pong interactions. Additionally, it maintains a count of pings sent, a random token for the ping/pong protocol, and a weight for selection purposes. This structure is crucial for managing active connections and ensuring the responsiveness of validators in the network.


---
### fd\_value
- **Type**: `struct`
- **Members**:
    - `key`: Hash of the value data.
    - `wallclock`: Original timestamp of value in milliseconds.
    - `origin`: Public key indicating where this value originated.
    - `data`: Serialized form of the value, including signature, with a fixed size defined by PACKET_DATA_SIZE.
    - `datalen`: Length of the serialized data.
    - `del`: Flag indicating if the value is queued for deletion during cleanup.
- **Description**: The `fd_value` structure represents a full gossip value in the system, encapsulating both the metadata and the serialized data of a CRDS (Cluster Replicated Data Store) value. It includes a hash key for identifying the value, a timestamp for when the value was originally created, the origin of the value in terms of a public key, and the serialized data itself which includes a signature. The structure also contains a length field for the data and a deletion flag used during cleanup operations to mark values that should be removed.


---
### fd\_value\_t
- **Type**: `typedef struct`
- **Members**:
    - `key`: Hash of the value data.
    - `wallclock`: Original timestamp of value in milliseconds.
    - `origin`: Public key indicating where the value originated.
    - `data`: Serialized form of the value, including signature, with a maximum size defined by PACKET_DATA_SIZE.
    - `datalen`: Length of the serialized data.
    - `del`: Flag indicating if the value is queued for deletion during cleanup.
- **Description**: The `fd_value_t` structure represents a full gossip value in the system, encapsulating both the encoded form of a CRDS value and its associated metadata. It includes a hash key for identifying the value, a timestamp for when the value was originally created, and the origin public key to track its source. The data field holds the serialized form of the value, which includes a signature, and is limited by the maximum packet size. The structure also includes a length field for the data and a deletion flag used during cleanup processes to manage memory and data lifecycle efficiently.


---
### fd\_value\_meta
- **Type**: `struct`
- **Members**:
    - `key`: Hash of the value data, also functions as map key.
    - `wallclock`: Timestamp of value in milliseconds.
    - `value`: Pointer to the actual value element, backed by the value vector.
    - `next`: Unused in this context, likely for future or linked list use.
- **Description**: The `fd_value_meta` structure is a minimized form of a full gossip value, primarily used to store metadata about the value. It includes a hash key that serves as both the identifier and map key, a timestamp indicating when the value was created or last updated, and a pointer to the actual value data stored elsewhere. This separation of metadata from the full value allows for efficient memory usage and management, as the metadata can be retained longer than the full value data, which is larger and has a shorter lifespan.


---
### fd\_value\_meta\_t
- **Type**: `struct`
- **Members**:
    - `key`: Hash of the value data, also functions as map key.
    - `wallclock`: Timestamp of value in milliseconds.
    - `value`: Pointer to the actual value element (backed by the value vector).
    - `next`: Pointer to the next element in the map.
- **Description**: The `fd_value_meta_t` structure is a minimized form of a full gossip value that only holds metadata. It is used in a value metadata map to manage the metadata of CRDS values in a gossip protocol. The structure includes a hash key for identifying the value, a timestamp indicating when the value was created or last updated, a pointer to the actual value in a separate value vector, and a pointer to the next element in the map. This separation of metadata from the full value allows for efficient memory usage and management of value lifetimes in the gossip protocol.


---
### fd\_weights\_elem
- **Type**: `struct`
- **Members**:
    - `key`: A public key of type `fd_pubkey_t` associated with the weight entry.
    - `next`: An unsigned long integer used for linking to the next element in a list or table.
    - `weight`: An unsigned long integer representing the weight of the peer, typically determined by stake.
- **Description**: The `fd_weights_elem` structure is part of a weights table that stores the weight for each peer, which is determined by their stake. This structure is used in a mapping to associate a public key with a weight value, facilitating the selection of peers based on their stake weight in a network protocol.


---
### fd\_weights\_elem\_t
- **Type**: `struct`
- **Members**:
    - `key`: A public key used as the identifier for the peer.
    - `next`: A pointer to the next element in the table.
    - `weight`: The weight assigned to the peer, typically determined by stake.
- **Description**: The `fd_weights_elem_t` structure is used to represent an element in the weights table, which stores the weight for each peer in a gossip network. The weight is typically determined by the stake associated with the peer, and it is used to influence the selection of peers for certain operations within the network. The structure includes a public key as the identifier for the peer, a pointer to the next element in the table, and the weight value itself.


---
### fd\_pending\_event\_arg
- **Type**: `union`
- **Members**:
    - `key`: A member of type `fd_gossip_peer_addr_t` used to store a peer address.
    - `ul`: A member of type `ulong` used to store an unsigned long integer value.
- **Description**: The `fd_pending_event_arg` is a union data structure that can store either a peer address (`fd_gossip_peer_addr_t`) or an unsigned long integer (`ulong`). This union is used to represent arguments for pending events in a flexible manner, allowing the event to be associated with either a specific peer address or a generic numeric value, depending on the context of the event.


---
### fd\_pending\_event\_arg\_t
- **Type**: `union`
- **Members**:
    - `key`: Represents a gossip peer address key.
    - `ul`: Represents an unsigned long integer.
- **Description**: The `fd_pending_event_arg_t` is a union data structure used to represent arguments for pending events in a gossip protocol. It can store either a `fd_gossip_peer_addr_t` key, which is used to identify a peer in the network, or an unsigned long integer (`ul`). This flexibility allows the union to be used in different contexts where either a peer address or a numeric value is needed as an argument for event handling.


---
### fd\_pending\_event
- **Type**: `struct`
- **Members**:
    - `timeout`: Specifies the time in milliseconds after which the event should be triggered.
    - `fun`: A function pointer to the event handler function that will be called when the event is triggered.
    - `fun_arg`: An argument of type `fd_pending_event_arg_t` that will be passed to the event handler function.
- **Description**: The `fd_pending_event` structure is used to represent a pending event in a priority queue of timed events. It contains a timeout value indicating when the event should be triggered, a function pointer to the event handler, and an argument to be passed to the handler. This structure is part of a system that manages timed events, allowing for scheduling and execution of functions at specified times.


---
### fd\_pending\_event\_t
- **Type**: `struct`
- **Members**:
    - `timeout`: Specifies the time at which the event is scheduled to occur.
    - `fun`: Pointer to the function to be executed when the event is triggered.
    - `fun_arg`: Argument to be passed to the function when the event is triggered.
- **Description**: The `fd_pending_event_t` structure represents a pending event in a priority queue, used to manage timed events in a system. It contains a timeout indicating when the event should occur, a function pointer to the event handler, and an argument to be passed to the function. This structure is part of a mechanism to handle scheduled tasks efficiently, allowing the system to execute specific functions at designated times.


---
### fd\_push\_state
- **Type**: `struct`
- **Members**:
    - `addr`: Destination address for the push state.
    - `id`: Public identifier associated with the push state.
    - `drop_cnt`: Count of values dropped due to pruning.
    - `prune_keys`: Array of keys used for the bloom filter in pruning.
    - `prune_bits`: Bits table used for the bloom filter in pruning.
    - `packet`: Buffer for a partially assembled packet containing a gossip push message.
    - `packet_end_init`: Pointer to the initial end of the packet when there are zero values.
    - `packet_end`: Pointer to the current end of the packet including values so far.
    - `next`: Next element in the push state list.
- **Description**: The `fd_push_state` structure is used to manage the state of an active push destination in a gossip protocol. It contains information about the destination address, a public identifier, and counters for managing the pruning of values using a bloom filter. The structure also includes a buffer for assembling packets to be sent, with pointers to track the initial and current end of the packet. This structure is crucial for efficiently managing and sending gossip messages to multiple destinations while handling pruning to avoid redundant data transmission.


---
### fd\_push\_state\_t
- **Type**: `struct`
- **Members**:
    - `addr`: Destination address for the push state.
    - `id`: Public identifier for the push state.
    - `drop_cnt`: Number of values dropped due to pruning.
    - `prune_keys`: Keys used for the bloom filter for pruning.
    - `prune_bits`: Bits table used for the bloom filter for pruning.
    - `packet`: Partially assembled packet containing a gossip push message.
    - `packet_end_init`: Initial end of the packet when there are zero values.
    - `packet_end`: Current end of the packet including values so far.
    - `next`: Pointer to the next push state in the list.
- **Description**: The `fd_push_state_t` structure represents an active push destination in a gossip protocol. It contains information about the destination address, public identifier, and mechanisms for pruning using bloom filters. The structure also manages the assembly of packets for pushing messages, tracking the number of values dropped due to pruning, and maintaining the current state of the packet being constructed. This structure is crucial for managing the efficient dissemination of messages in a network by ensuring that only relevant data is pushed to active destinations.


---
### fd\_stats\_elem
- **Type**: `struct`
- **Members**:
    - `key`: Keyed by the sender, represented by `fd_gossip_peer_addr_t`.
    - `next`: An unsigned long integer used for linking or indexing.
    - `last`: Timestamp of the last update, stored as a long integer.
    - `dups`: An array of structures holding duplicate counts by origin, each with an origin and a count.
    - `dups_cnt`: An unsigned long integer representing the count of duplicates.
- **Description**: The `fd_stats_elem` structure is part of a receive statistics table, designed to track and manage statistics related to received messages in a gossip protocol. It includes a key for identifying the sender, a timestamp for the last update, and a mechanism for counting duplicates by origin. This structure is essential for maintaining the integrity and efficiency of message handling by keeping track of duplicate messages and their origins.


---
### fd\_stats\_elem\_t
- **Type**: `struct`
- **Members**:
    - `key`: Keyed by sender, this field holds the address of the peer.
    - `next`: A pointer to the next element in the table.
    - `last`: Timestamp of the last update for this element.
    - `dups`: An array of structures holding duplicate counts by origin.
    - `dups_cnt`: The count of duplicate origins tracked in the dups array.
- **Description**: The `fd_stats_elem_t` structure is a component of the receive statistics table, which is used to track statistics about received messages in a gossip protocol. Each element in the table is keyed by the sender's address and contains information about the last update time and duplicate message counts by origin. This allows the system to monitor and manage duplicate messages, which can be useful for optimizing network traffic and ensuring efficient communication between nodes.


---
### fd\_msg\_stats\_elem
- **Type**: `struct`
- **Members**:
    - `bytes_rx_cnt`: Counts the number of bytes received.
    - `total_cnt`: Tracks the total number of messages received.
    - `dups_cnt`: Records the number of duplicate messages received.
- **Description**: The `fd_msg_stats_elem` structure is used to maintain statistics related to message reception in a network communication context. It keeps track of the total number of bytes received (`bytes_rx_cnt`), the total number of messages received (`total_cnt`), and the number of duplicate messages received (`dups_cnt`). This structure is part of a receive type statistics table, which is likely used to monitor and analyze network traffic patterns and performance.


---
### fd\_msg\_stats\_elem\_t
- **Type**: `typedef struct`
- **Members**:
    - `bytes_rx_cnt`: Counts the number of bytes received.
    - `total_cnt`: Tracks the total number of messages received.
    - `dups_cnt`: Records the number of duplicate messages received.
- **Description**: The `fd_msg_stats_elem_t` structure is used to maintain statistics about received messages, specifically tracking the total number of messages, the number of bytes received, and the count of duplicate messages. This structure is part of a larger system for managing and analyzing network message traffic, providing insights into message reception patterns and potential issues with duplicate messages.


---
### fd\_gossip\_node\_contact\_t
- **Type**: `struct`
- **Members**:
    - `crd`: Stores CRDS data for the node contact.
    - `ci`: Pointer to the gossip contact information version 2.
    - `addrs`: Array of IP addresses associated with the node contact.
    - `sockets`: Array of socket entries associated with the node contact.
- **Description**: The `fd_gossip_node_contact_t` structure is used to represent a node's contact information within a gossip protocol. It includes CRDS data, a pointer to version 2 of the gossip contact information, and arrays for IP addresses and socket entries. This structure is essential for managing and disseminating node contact details in a network, facilitating communication and data exchange between nodes.


---
### fd\_gossip\_node\_addrs\_t
- **Type**: `struct`
- **Members**:
    - `gossip`: Stores the gossip address of the node.
    - `serve_repair`: Stores the serve repair address of the node.
    - `tvu`: Stores the TVU (Transaction Verification Unit) address of the node.
    - `tpu`: Stores the TPU (Transaction Processing Unit) address of the node.
    - `tpu_quic`: Stores the TPU QUIC address of the node.
    - `tpu_vote`: Stores the TPU vote address of the node.
    - `tpu_vote_quic`: Stores the TPU vote QUIC address of the node.
- **Description**: The `fd_gossip_node_addrs_t` structure is a compound data type that encapsulates various network addresses associated with a gossip node in a distributed system. Each member of the structure represents a specific type of address used for different purposes, such as gossip communication, repair services, and transaction processing. This structure is essential for managing and accessing the different network endpoints that a node uses to interact with other nodes in the network.


---
### fd\_gossip
- **Type**: `struct`
- **Members**:
    - `lock`: A volatile unsigned long used as a concurrency lock.
    - `now`: Stores the current time in nanoseconds.
    - `decode_spad`: Pointer to fd_spad_t for holding CRDS decode artifacts.
    - `my_contact`: Stores the node's official contact information in the gossip protocol.
    - `my_node_addrs`: Contains the node's various network addresses.
    - `my_addr`: Pointer to the node's gossip port address in my_node_addrs.
    - `public_key`: Pointer to the node's public key in my_contact.
    - `deliver_fun`: Function pointer for delivering gossip messages to the application.
    - `deliver_arg`: Argument for the deliver_fun function.
    - `send_fun`: Function pointer for sending raw packets on the network.
    - `send_arg`: Argument for the send_fun function.
    - `sign_fun`: Function pointer for sending packets for signing to a remote tile.
    - `sign_arg`: Argument for the sign_fun function.
    - `peers`: Pointer to a table of all known validators, keyed by gossip address.
    - `actives`: Pointer to a table of validators actively pinged, keyed by gossip address.
    - `inactives`: Queue of validators that might be added to actives.
    - `inactives_cnt`: Count of inactive validators.
    - `value_metas`: Pointer to a table of CRDS metadata, keyed by hash of the encoded data.
    - `values`: Vector of full CRDS values.
    - `last_contact_time`: Timestamp of the last time the node's contact info was pushed.
    - `last_contact_info_v2_key`: Hash key of the last contact info version 2.
    - `push_states`: Array of push destinations currently in use.
    - `push_states_cnt`: Count of push states in use.
    - `push_states_pool`: Pool of push states available for use.
    - `need_push_head`: Index into the values vector for the next value to push.
    - `stats`: Pointer to a table of receive statistics.
    - `msg_stats`: Array of message type statistics.
    - `event_heap`: Heap/queue of pending timed events.
    - `rng`: Random number generator instance.
    - `seed`: Seed for the random number generator.
    - `recv_pkt_cnt`: Total number of packets received.
    - `recv_dup_cnt`: Total number of duplicate values received.
    - `recv_nondup_cnt`: Total number of non-duplicate values received.
    - `push_cnt`: Count of values pushed.
    - `not_push_cnt`: Count of values not pushed due to pruning.
    - `weights`: Pointer to a table of stake weights.
    - `entrypoints_cnt`: Count of entrypoints added at startup.
    - `entrypoints`: Array of entrypoints added at startup.
    - `metrics`: Metrics related to the gossip protocol.
- **Description**: The `fd_gossip` structure is a comprehensive data structure used in a gossip protocol implementation. It manages various aspects of the protocol, including node contact information, network addresses, message delivery and sending functions, and tables for known validators and CRDS metadata. It also handles random number generation, packet reception statistics, and push state management. The structure is designed to facilitate efficient communication and data dissemination in a distributed network, with mechanisms for concurrency control, event scheduling, and performance metrics tracking.


# Functions

---
### fd\_gossip\_peer\_addr\_eq<!-- {{#callable:fd_gossip_peer_addr_eq}} -->
Compares two `fd_gossip_peer_addr_t` structures for equality based on their `l` field.
- **Inputs**:
    - `key1`: A pointer to the first `fd_gossip_peer_addr_t` structure to compare.
    - `key2`: A pointer to the second `fd_gossip_peer_addr_t` structure to compare.
- **Control Flow**:
    - The function first asserts that the size of `fd_gossip_peer_addr_t` is equal to the size of an unsigned long using a static assertion.
    - It then compares the `l` field of both `fd_gossip_peer_addr_t` structures and returns the result of this comparison.
- **Output**: Returns 1 if the `l` fields of both structures are equal, otherwise returns 0.


---
### fd\_gossip\_peer\_addr\_hash<!-- {{#callable:fd_gossip_peer_addr_hash}} -->
Calculates a hash value for a given gossip peer address using a seed.
- **Inputs**:
    - `key`: A pointer to a `fd_gossip_peer_addr_t` structure representing the peer address to be hashed.
    - `seed`: An unsigned long integer used as a seed to influence the hash output.
- **Control Flow**:
    - The function first asserts that the size of `fd_gossip_peer_addr_t` is equal to the size of an unsigned long.
    - It then computes the hash by adding the `l` member of the `key`, the `seed`, and a constant value, followed by multiplying the result with another constant.
    - Finally, the computed hash value is returned.
- **Output**: Returns an unsigned long integer representing the computed hash value for the given peer address and seed.


---
### fd\_gossip\_peer\_addr\_copy<!-- {{#callable:fd_gossip_peer_addr_copy}} -->
Copies the address from one `fd_gossip_peer_addr_t` structure to another.
- **Inputs**:
    - `keyd`: A pointer to the destination `fd_gossip_peer_addr_t` structure where the address will be copied.
    - `keys`: A pointer to the source `fd_gossip_peer_addr_t` structure from which the address will be copied.
- **Control Flow**:
    - The function asserts that the size of `fd_gossip_peer_addr_t` is equal to the size of an unsigned long.
    - It then copies the `l` member from the `keys` structure to the `keyd` structure.
- **Output**: This function does not return a value; it modifies the `keyd` structure in place.


---
### fd\_active\_new\_value<!-- {{#callable:fd_active_new_value}} -->
Initializes a new `fd_active_elem_t` structure with default values.
- **Inputs**:
    - `val`: A pointer to an `fd_active_elem_t` structure that will be initialized.
- **Control Flow**:
    - Sets the `pingcount` field of the `val` structure to 1, indicating the first ping attempt.
    - Initializes both `pingtime` and `pongtime` fields to 0, indicating no pings or pongs have occurred yet.
    - Sets the `weight` field to 0, which may be used for prioritization in future operations.
    - Uses `fd_memset` to clear the `id` and `pingtoken` fields, ensuring they start with no residual data.
- **Output**: The function does not return a value; it modifies the `fd_active_elem_t` structure pointed to by `val` directly.


---
### fd\_hash\_hash<!-- {{#callable:fd_hash_hash}} -->
Calculates a hash value by XORing the first element of a hash key with a seed.
- **Inputs**:
    - `key`: A pointer to a `fd_hash_t` structure that contains the hash key.
    - `seed`: An unsigned long integer used as a seed for the hash calculation.
- **Control Flow**:
    - Accesses the first element of the `ul` array in the `fd_hash_t` structure pointed to by `key`.
    - Performs a bitwise XOR operation between this value and the `seed`.
    - Returns the result of the XOR operation.
- **Output**: Returns an unsigned long integer that represents the computed hash value.


---
### fd\_value\_from\_crds<!-- {{#callable:fd_value_from_crds}} -->
The `fd_value_from_crds` function extracts and encodes a value from a CRDS (Controlled Random Distributed System) value structure based on its discriminant type.
- **Inputs**:
    - `val`: A pointer to a `fd_value_t` structure where the extracted value will be stored.
    - `crd`: A constant pointer to a `fd_crds_value_t` structure that contains the data to be extracted.
- **Control Flow**:
    - The function initializes the `del` field of the `val` structure to 0.
    - It uses a switch statement to determine the type of data based on the `discriminant` field of the `crd` structure.
    - For each case corresponding to a specific `discriminant`, it extracts the `origin` and `wallclock` values from the `crd` and assigns them to the `val` structure.
    - If the `discriminant` does not match any known types, it returns an error code indicating an unknown discriminant.
    - After extracting the values, it encodes the `crd` data into the `val` structure using the `fd_crds_value_encode` function.
    - Finally, it computes a SHA-256 hash of the encoded data and stores it in the `key` field of the `val` structure.
- **Output**: The function returns 0 on success, or an error code if the discriminant is unknown or if encoding fails.


---
### fd\_value\_meta\_map\_value\_init<!-- {{#callable:fd_value_meta_map_value_init}} -->
Initializes the metadata for a value in the value metadata map.
- **Inputs**:
    - `meta`: A pointer to a `fd_value_meta_t` structure that holds metadata for a value.
    - `wallclock`: A `ulong` representing the wall clock time (in milliseconds) associated with the value.
    - `value`: A pointer to a `fd_value_t` structure that represents the actual value being initialized.
- **Control Flow**:
    - The function assigns the provided `wallclock` value to the `wallclock` field of the `meta` structure.
    - It sets the `value` field of the `meta` structure to point to the provided `value`.
- **Output**: The function does not return a value; it modifies the `meta` structure in place.


---
### fd\_pending\_event\_arg\_null<!-- {{#callable:fd_pending_event_arg_null}} -->
The `fd_pending_event_arg_null` function returns a null-initialized `fd_pending_event_arg_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns a new `fd_pending_event_arg_t` structure initialized with a member `ul` set to 0.
- **Output**: The output is a `fd_pending_event_arg_t` structure with its `ul` member set to 0, indicating a null or empty state.


---
### fd\_pending\_event\_arg\_peer\_addr<!-- {{#callable:fd_pending_event_arg_peer_addr}} -->
Creates a `fd_pending_event_arg_t` structure initialized with a given `fd_gossip_peer_addr_t` key.
- **Inputs**:
    - `key`: A `fd_gossip_peer_addr_t` structure representing the peer address to be stored in the event argument.
- **Control Flow**:
    - The function directly initializes a `fd_pending_event_arg_t` structure using a designated initializer.
    - It sets the `key` field of the structure to the provided `key` argument.
- **Output**: Returns a `fd_pending_event_arg_t` structure with the `key` field set to the provided `fd_gossip_peer_addr_t`.


---
### fd\_gossip\_init\_node\_contact<!-- {{#callable:fd_gossip_init_node_contact}} -->
Initializes a `fd_gossip_node_contact_t` structure with new contact information.
- **Inputs**:
    - `contact`: A pointer to a `fd_gossip_node_contact_t` structure that will be initialized.
- **Control Flow**:
    - Calls `fd_crds_data_new_disc` to initialize the `crd` field of the `contact` structure with a new discriminant for contact information version 2.
    - Sets the `ci` field of the `contact` structure to point to the inner `contact_info_v2` of the `crd` structure.
    - Assigns the `addrs` and `sockets` fields of the `ci` structure to the corresponding fields in the `contact` structure.
- **Output**: The function does not return a value; it modifies the `contact` structure in place to set up its internal state for handling gossip communication.


---
### fd\_gossip\_get\_metrics<!-- {{#callable:fd_gossip_get_metrics}} -->
Returns a pointer to the `metrics` structure of a given `fd_gossip` instance.
- **Inputs**:
    - `gossip`: A pointer to an `fd_gossip_t` structure, which contains the gossip protocol's state and metrics.
- **Control Flow**:
    - The function directly accesses the `metrics` member of the `gossip` structure.
    - It returns the address of the `metrics` structure.
- **Output**: Returns a pointer to the `fd_gossip_metrics_t` structure that holds various metrics related to the gossip protocol.


---
### fd\_gossip\_align<!-- {{#callable:fd_gossip_align}} -->
The `fd_gossip_align` function returns a constant alignment value of 128.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns a constant value without any conditional logic or loops.
- **Output**: The function outputs a constant unsigned long value of 128.


---
### fd\_gossip\_footprint<!-- {{#callable:fd_gossip_footprint}} -->
Calculates the memory footprint required for the `fd_gossip_t` structure and its associated components.
- **Inputs**: None
- **Control Flow**:
    - Initializes a variable `l` with `FD_LAYOUT_INIT` to start the layout calculation.
    - Appends the size and alignment of various components related to gossip functionality to `l` using `FD_LAYOUT_APPEND`.
    - Each component's footprint is calculated using specific functions like `fd_spad_footprint`, `fd_peer_table_footprint`, etc.
    - Finalizes the layout with `FD_LAYOUT_FINI` and returns the total calculated footprint.
- **Output**: Returns the total memory footprint required for the `fd_gossip_t` structure and its associated components.
- **Functions called**:
    - [`fd_gossip_align`](#fd_gossip_align)


---
### fd\_gossip\_new<!-- {{#callable:fd_gossip_new}} -->
Creates and initializes a new `fd_gossip_t` structure for managing gossip protocol operations.
- **Inputs**:
    - `shmem`: A pointer to shared memory used for scratch allocation.
    - `seed`: A seed value used for random number generation and initialization.
- **Control Flow**:
    - Initializes scratch allocation using `FD_SCRATCH_ALLOC_INIT` with the provided shared memory.
    - Allocates memory for the `fd_gossip_t` structure and initializes it to zero.
    - Sets the `seed` field of the `fd_gossip_t` structure.
    - Allocates and initializes various components such as `decode_spad`, `peers`, `actives`, `value_metas`, `values`, `event_heap`, `stats`, and `weights` using respective allocation functions.
    - Checks if there is enough space allocated for the gossip structure and logs an error if not.
    - Returns a pointer to the initialized `fd_gossip_t` structure.
- **Output**: Returns a pointer to the newly created and initialized `fd_gossip_t` structure.
- **Functions called**:
    - [`fd_gossip_align`](#fd_gossip_align)
    - [`fd_gossip_footprint`](#fd_gossip_footprint)


---
### fd\_gossip\_join<!-- {{#callable:fd_gossip_join}} -->
The `fd_gossip_join` function casts a shared memory pointer to a `fd_gossip_t` structure.
- **Inputs**:
    - `shmap`: A pointer to shared memory that is expected to point to a `fd_gossip_t` structure.
- **Control Flow**:
    - The function directly casts the input pointer `shmap` to a pointer of type `fd_gossip_t`.
    - There are no conditional statements or loops in the function.
- **Output**: Returns a pointer to a `fd_gossip_t` structure, which is the casted version of the input shared memory pointer.


---
### fd\_gossip\_leave<!-- {{#callable:fd_gossip_leave}} -->
The `fd_gossip_leave` function returns the pointer to the `fd_gossip_t` structure passed to it.
- **Inputs**:
    - `join`: A pointer to an `fd_gossip_t` structure that represents the gossip instance to leave.
- **Control Flow**:
    - The function takes a single input parameter, `join`, which is a pointer to an `fd_gossip_t` structure.
    - It directly returns the `join` pointer without any modifications or additional logic.
- **Output**: The output is a pointer to the same `fd_gossip_t` structure that was passed as input.


---
### fd\_gossip\_delete<!-- {{#callable:fd_gossip_delete}} -->
The `fd_gossip_delete` function cleans up and deallocates resources associated with a `fd_gossip_t` structure.
- **Inputs**:
    - `shmap`: A pointer to shared memory that contains the `fd_gossip_t` structure to be deleted.
- **Control Flow**:
    - The function casts the input pointer `shmap` to a pointer of type `fd_gossip_t`.
    - It calls `fd_peer_table_delete` after leaving the peer table associated with the `peers` member of the `fd_gossip_t` structure.
    - It calls `fd_active_table_delete` after leaving the active table associated with the `actives` member.
    - It proceeds to delete various other components of the `fd_gossip_t` structure, including value metadata, value vectors, pending heaps, statistics tables, weights tables, and push states pool.
    - Finally, it returns the pointer to the `fd_gossip_t` structure that was passed in.
- **Output**: Returns a pointer to the `fd_gossip_t` structure that was deleted.


---
### fd\_gossip\_lock<!-- {{#callable:fd_gossip_lock}} -->
The `fd_gossip_lock` function acquires a lock on a `fd_gossip_t` structure to ensure thread-safe access.
- **Inputs**:
    - `gossip`: A pointer to a `fd_gossip_t` structure that contains the state of the gossip protocol, including a lock variable.
- **Control Flow**:
    - If threading is enabled (checked by `FD_HAS_THREADS`), the function enters an infinite loop to attempt to acquire the lock.
    - Within the loop, it uses an atomic compare-and-swap operation (`FD_ATOMIC_CAS`) to try to set the lock from 0 to 1.
    - If the lock is successfully acquired (the CAS operation returns false), the loop breaks.
    - If the lock is not acquired, the function calls `FD_SPIN_PAUSE()` to yield execution, allowing other threads to run.
    - If threading is not enabled, the lock is simply set to 1.
- **Output**: The function does not return a value; it modifies the state of the `gossip` structure by acquiring a lock.


---
### fd\_gossip\_unlock<!-- {{#callable:fd_gossip_unlock}} -->
The `fd_gossip_unlock` function releases a lock on a `fd_gossip_t` structure, allowing other threads to access it.
- **Inputs**:
    - `gossip`: A pointer to a `fd_gossip_t` structure that contains the lock to be released.
- **Control Flow**:
    - The function first ensures memory consistency by calling `FD_COMPILER_MFENCE()`.
    - It then sets the `lock` field of the `gossip` structure to 0, indicating that the lock is released.
- **Output**: The function does not return a value; it modifies the state of the `gossip` structure to indicate that it is no longer locked.


---
### fd\_gossip\_ipaddr\_from\_socketaddr<!-- {{#callable:fd_gossip_ipaddr_from_socketaddr}} -->
Converts a `fd_gossip_socket_addr_t` structure to a corresponding `fd_gossip_ip_addr_t` structure.
- **Inputs**:
    - `addr`: A pointer to a constant `fd_gossip_socket_addr_t` structure that contains the socket address information.
    - `out`: A pointer to a `fd_gossip_ip_addr_t` structure where the converted IP address will be stored.
- **Control Flow**:
    - The function first checks if the `discriminant` of the `addr` indicates an IPv4 address using `FD_LIKELY` for optimization.
    - If it is an IPv4 address, it initializes the `out` structure with the IPv4 discriminant and assigns the IPv4 address from `addr`.
    - If it is not an IPv4 address, it assumes it is an IPv6 address, initializes the `out` structure with the IPv6 discriminant, and assigns the IPv6 address from `addr`.
- **Output**: The function does not return a value; instead, it populates the `out` parameter with the corresponding IP address based on the input socket address type.


---
### fd\_gossip\_port\_from\_socketaddr<!-- {{#callable:fd_gossip_port_from_socketaddr}} -->
Extracts the gossip port from a given socket address.
- **Inputs**:
    - `addr`: A pointer to a `fd_gossip_socket_addr_t` structure that contains the socket address information, including the port number.
- **Control Flow**:
    - Checks if the `discriminant` of the `addr` indicates an IPv4 address.
    - If it is an IPv4 address, returns the port from the `inner.ip4` structure.
    - If it is not an IPv4 address, assumes it is an IPv6 address and returns the port from the `inner.ip6` structure.
- **Output**: Returns the port number as an unsigned short (ushort) from the specified socket address.


---
### fd\_gossip\_contact\_info\_v2\_to\_v1<!-- {{#callable:fd_gossip_contact_info_v2_to_v1}} -->
Converts contact information from version 2 format to version 1 format.
- **Inputs**:
    - `v2`: A pointer to a `fd_gossip_contact_info_v2_t` structure containing the version 2 contact information.
    - `v1`: A pointer to a `fd_gossip_contact_info_v1_t` structure where the converted version 1 contact information will be stored.
- **Control Flow**:
    - The function starts by zeroing out the memory of the `v1` structure using `memset`.
    - It then copies the `from`, `shred_version`, and `wallclock` fields from the `v2` structure to the `v1` structure.
    - Next, it calls [`fd_gossip_contact_info_v2_find_proto_ident`](#fd_gossip_contact_info_v2_find_proto_ident) multiple times to find and set the protocol identifiers for various socket types (gossip, serve repair, TPU, TPU vote, and TVU) from the `v2` structure to the `v1` structure.
- **Output**: The function does not return a value; instead, it populates the `v1` structure with the converted contact information from the `v2` structure.
- **Functions called**:
    - [`fd_gossip_contact_info_v2_find_proto_ident`](#fd_gossip_contact_info_v2_find_proto_ident)


---
### fd\_gossip\_contact\_info\_v2\_find\_proto\_ident<!-- {{#callable:fd_gossip_contact_info_v2_find_proto_ident}} -->
Finds the protocol identifier and corresponding socket address from the contact information.
- **Inputs**:
    - `contact_info`: A pointer to a constant `fd_gossip_contact_info_v2_t` structure containing the contact information including socket entries.
    - `proto_ident`: An unsigned character representing the protocol identifier to search for.
    - `out_addr`: A pointer to a `fd_gossip_socket_addr_t` structure where the found address will be stored.
- **Control Flow**:
    - Initializes a port variable to zero.
    - Iterates over each socket entry in the `contact_info` structure.
    - For each socket entry, updates the port by adding the socket's offset.
    - Checks if the socket entry's key matches the provided `proto_ident`.
    - If a match is found, checks if the index is within the bounds of the addresses length.
    - Depending on the IP address type (IPv4 or IPv6), sets the `out_addr` fields accordingly.
    - Returns 1 if a matching protocol identifier is found, otherwise continues the loop.
    - If no match is found after iterating through all entries, returns 0.
- **Output**: Returns 1 if a matching protocol identifier is found and the corresponding address is set in `out_addr`; otherwise returns 0.


---
### fd\_gossip\_to\_soladdr<!-- {{#callable:fd_gossip_to_soladdr}} -->
Converts a `fd_gossip_peer_addr_t` source address to a `fd_gossip_socket_addr_t` destination address.
- **Inputs**:
    - `dst`: A pointer to a `fd_gossip_socket_addr_t` structure where the converted address will be stored.
    - `src`: A pointer to a constant `fd_gossip_peer_addr_t` structure representing the source address to be converted.
- **Control Flow**:
    - Calls `fd_gossip_socket_addr_new_disc` to initialize the `dst` address with the discriminant set to `fd_gossip_socket_addr_enum_ip4`.
    - Swaps the byte order of the port from the `src` address using `fd_ushort_bswap` and assigns it to the `dst` address.
    - Copies the IP address from the `src` address to the `dst` address.
- **Output**: Returns 0 to indicate successful conversion.


---
### fd\_gossip\_from\_soladdr<!-- {{#callable:fd_gossip_from_soladdr}} -->
Converts a `fd_gossip_socket_addr_t` structure to a `fd_gossip_peer_addr_t` structure.
- **Inputs**:
    - `dst`: A pointer to a `fd_gossip_peer_addr_t` structure where the converted address will be stored.
    - `src`: A pointer to a constant `fd_gossip_socket_addr_t` structure that contains the source address to be converted.
- **Control Flow**:
    - The function starts by asserting that the size of `fd_gossip_peer_addr_t` is equal to the size of an unsigned long.
    - It initializes the `l` field of the destination structure `dst` to 0.
    - It checks if the `discriminant` field of the source structure `src` indicates an IPv4 address.
    - If the address is IPv4, it swaps the byte order of the port and assigns the address and port to the destination structure.
    - If the address is not IPv4, it logs an error message indicating an invalid address family and returns -1.
- **Output**: Returns 0 on successful conversion or -1 if the address family is invalid.


---
### fd\_gossip\_set\_config<!-- {{#callable:fd_gossip_set_config}} -->
Sets the configuration for the gossip protocol.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure representing the global state of the gossip protocol.
    - `config`: A pointer to the `fd_gossip_config_t` structure containing configuration parameters such as public key, addresses, and version information.
- **Control Flow**:
    - Locks the global gossip state to ensure thread safety.
    - Encodes the public key from the configuration into a base58 string for logging.
    - Initializes the node's contact information.
    - Sets the public key and address for the gossip node from the configuration.
    - Updates the contact information with the provided configuration details.
    - Assigns various function pointers for message delivery, sending, and signing from the configuration.
    - Unlocks the global gossip state after configuration is set.
- **Output**: Returns 0 to indicate successful configuration of the gossip protocol.
- **Functions called**:
    - [`fd_gossip_lock`](#fd_gossip_lock)
    - [`fd_gossip_init_node_contact`](#fd_gossip_init_node_contact)
    - [`fd_gossip_peer_addr_copy`](#fd_gossip_peer_addr_copy)
    - [`fd_gossip_refresh_contact_info_v2_sockets`](#fd_gossip_refresh_contact_info_v2_sockets)
    - [`fd_gossip_unlock`](#fd_gossip_unlock)


---
### fd\_gossip\_refresh\_contact\_info\_v2\_sockets<!-- {{#callable:fd_gossip_refresh_contact_info_v2_sockets}} -->
The `fd_gossip_refresh_contact_info_v2_sockets` function updates the contact information for gossip nodes by refreshing the list of sockets and addresses based on the provided node addresses.
- **Inputs**:
    - `addrs`: A pointer to a `fd_gossip_node_addrs_t` structure containing the addresses and ports of various gossip services.
    - `ci_int`: A pointer to a `fd_gossip_node_contact_t` structure that will be updated with the refreshed contact information.
- **Control Flow**:
    - The function begins by initializing local variables to track the last port used, the count of addresses, and the count of sockets.
    - It then converts the ports from network byte order to host byte order for various gossip services.
    - A loop is initiated to find the next available socket based on the minimum port number, iterating through each service's port.
    - If a valid port is found, it checks if the corresponding IP address is already in the contact information; if not, it adds it.
    - The socket information is then updated with the index of the address, the offset from the last port, and a key identifying the service.
    - Special handling is included for the TPU and TPU vote services, which share the same port, to ensure both are represented in the contact information.
    - The loop continues until all valid ports have been processed, at which point the lengths of the addresses and sockets arrays are updated.
- **Output**: The function does not return a value but updates the `ci_int` structure with the new lengths of addresses and sockets, effectively refreshing the contact information for gossip nodes.


---
### fd\_gossip\_update\_addr<!-- {{#callable:fd_gossip_update_addr}} -->
Updates the gossip address and refreshes the contact information.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure representing the global gossip state.
    - `my_addr`: A pointer to the `fd_gossip_peer_addr_t` structure containing the new address to be updated.
- **Control Flow**:
    - Logs the new address being updated using `FD_LOG_NOTICE`.
    - Acquires a lock on the `glob` structure to ensure thread safety.
    - Copies the new address from `my_addr` to the `gossip` field of `glob->my_node_addrs`.
    - Calls [`fd_gossip_refresh_contact_info_v2_sockets`](#fd_gossip_refresh_contact_info_v2_sockets) to refresh the contact information based on the updated address.
    - Releases the lock on the `glob` structure.
    - Returns 0 to indicate success.
- **Output**: Returns 0 to indicate successful completion of the address update.
- **Functions called**:
    - [`fd_gossip_lock`](#fd_gossip_lock)
    - [`fd_gossip_peer_addr_copy`](#fd_gossip_peer_addr_copy)
    - [`fd_gossip_refresh_contact_info_v2_sockets`](#fd_gossip_refresh_contact_info_v2_sockets)
    - [`fd_gossip_unlock`](#fd_gossip_unlock)


---
### fd\_gossip\_update\_repair\_addr<!-- {{#callable:fd_gossip_update_repair_addr}} -->
Updates the repair service address in the gossip protocol.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure representing the global state of the gossip protocol.
    - `serve`: A pointer to the `fd_gossip_peer_addr_t` structure containing the new repair service address.
- **Control Flow**:
    - Logs the new repair service address using `FD_LOG_NOTICE`.
    - Acquires a lock on the `glob` structure to ensure thread safety.
    - Copies the new repair address from `serve` to the `serve_repair` field of `glob->my_node_addrs`.
    - Calls [`fd_gossip_refresh_contact_info_v2_sockets`](#fd_gossip_refresh_contact_info_v2_sockets) to update the contact information with the new address.
    - Releases the lock on the `glob` structure.
    - Returns 0 to indicate success.
- **Output**: Returns 0 to indicate successful update of the repair service address.
- **Functions called**:
    - [`fd_gossip_lock`](#fd_gossip_lock)
    - [`fd_gossip_peer_addr_copy`](#fd_gossip_peer_addr_copy)
    - [`fd_gossip_refresh_contact_info_v2_sockets`](#fd_gossip_refresh_contact_info_v2_sockets)
    - [`fd_gossip_unlock`](#fd_gossip_unlock)


---
### fd\_gossip\_update\_tvu\_addr<!-- {{#callable:fd_gossip_update_tvu_addr}} -->
Updates the TVU (Transaction Validation Unit) service address in the gossip protocol.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure representing the global state of the gossip protocol.
    - `tvu`: A pointer to the `fd_gossip_peer_addr_t` structure containing the new TVU service address.
- **Control Flow**:
    - Logs the update of the TVU service address using `FD_LOG_NOTICE`.
    - Acquires a lock on the `glob` structure to ensure thread safety.
    - Copies the new TVU address into the `glob->my_node_addrs.tvu` field using [`fd_gossip_peer_addr_copy`](#fd_gossip_peer_addr_copy).
    - Calls [`fd_gossip_refresh_contact_info_v2_sockets`](#fd_gossip_refresh_contact_info_v2_sockets) to refresh the contact information based on the updated address.
    - Releases the lock on the `glob` structure.
    - Returns 0 to indicate success.
- **Output**: Returns 0 on success, indicating that the TVU address was updated successfully.
- **Functions called**:
    - [`fd_gossip_lock`](#fd_gossip_lock)
    - [`fd_gossip_peer_addr_copy`](#fd_gossip_peer_addr_copy)
    - [`fd_gossip_refresh_contact_info_v2_sockets`](#fd_gossip_refresh_contact_info_v2_sockets)
    - [`fd_gossip_unlock`](#fd_gossip_unlock)


---
### fd\_gossip\_update\_tpu\_addr<!-- {{#callable:fd_gossip_update_tpu_addr}} -->
Updates the TPU and TPU_QUIC service addresses in the gossip protocol.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure that holds the global state of the gossip protocol.
    - `tpu`: A pointer to a `fd_gossip_peer_addr_t` structure representing the new TPU service address.
    - `tpu_quic`: A pointer to a `fd_gossip_peer_addr_t` structure representing the new TPU_QUIC service address.
- **Control Flow**:
    - Logs the new TPU and TPU_QUIC addresses being updated.
    - Acquires a lock on the global gossip state to ensure thread safety.
    - Copies the new TPU address into the global state.
    - Copies the new TPU_QUIC address into the global state.
    - Refreshes the contact information for the gossip protocol based on the updated addresses.
    - Releases the lock on the global gossip state.
- **Output**: Returns 0 to indicate successful completion of the address update.
- **Functions called**:
    - [`fd_gossip_lock`](#fd_gossip_lock)
    - [`fd_gossip_peer_addr_copy`](#fd_gossip_peer_addr_copy)
    - [`fd_gossip_refresh_contact_info_v2_sockets`](#fd_gossip_refresh_contact_info_v2_sockets)
    - [`fd_gossip_unlock`](#fd_gossip_unlock)


---
### fd\_gossip\_update\_tpu\_vote\_addr<!-- {{#callable:fd_gossip_update_tpu_vote_addr}} -->
Updates the TPU vote service address in the gossip protocol.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure representing the global state of the gossip protocol.
    - `tpu_vote`: A pointer to a `fd_gossip_peer_addr_t` structure containing the new TPU vote service address.
- **Control Flow**:
    - Logs the update of the TPU vote service address using `FD_LOG_NOTICE`.
    - Acquires a lock on the `glob` structure to ensure thread safety.
    - Copies the new TPU vote address from `tpu_vote` to the corresponding field in `glob->my_node_addrs`.
    - Calls [`fd_gossip_refresh_contact_info_v2_sockets`](#fd_gossip_refresh_contact_info_v2_sockets) to refresh the contact information based on the updated address.
    - Releases the lock on the `glob` structure.
    - Returns 0 to indicate success.
- **Output**: Returns 0 to indicate successful completion of the address update.
- **Functions called**:
    - [`fd_gossip_lock`](#fd_gossip_lock)
    - [`fd_gossip_peer_addr_copy`](#fd_gossip_peer_addr_copy)
    - [`fd_gossip_refresh_contact_info_v2_sockets`](#fd_gossip_refresh_contact_info_v2_sockets)
    - [`fd_gossip_unlock`](#fd_gossip_unlock)


---
### fd\_gossip\_set\_shred\_version<!-- {{#callable:fd_gossip_set_shred_version}} -->
Sets the shred version for the gossip protocol.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure representing the global gossip state.
    - `shred_version`: An unsigned short representing the new shred version to be set.
- **Control Flow**:
    - The function directly accesses the `shred_version` field of the `my_contact` member of the `fd_gossip_t` structure.
    - It assigns the provided `shred_version` value to this field.
- **Output**: This function does not return a value; it modifies the state of the `fd_gossip_t` structure.


---
### fd\_gossip\_add\_pending<!-- {{#callable:fd_gossip_add_pending}} -->
Adds a pending event to the gossip event queue if there is space available.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure representing the global gossip state.
    - `fun`: A function pointer of type `fd_pending_event_fun` that will be called when the event is processed.
    - `fun_arg`: An argument of type `fd_pending_event_arg_t` that will be passed to the event function.
    - `timeout`: A long integer representing the timeout duration for the event.
- **Control Flow**:
    - Checks if the current count of pending events in the event heap exceeds the maximum allowed.
    - If the count exceeds the maximum, the function returns 0, indicating failure to add the event.
    - If there is space, it initializes a `fd_pending_event_t` structure with the provided function, argument, and timeout.
    - Inserts the newly created event into the event heap.
    - Returns 1 to indicate successful addition of the event.
- **Output**: Returns 1 if the event was successfully added to the queue, or 0 if the queue is full.


---
### fd\_gossip\_send\_raw<!-- {{#callable:fd_gossip_send_raw}} -->
Sends raw data as a UDP packet to a specified destination address.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure that holds the global state of the gossip protocol.
    - `dest`: A pointer to the `fd_gossip_peer_addr_t` structure representing the destination address to which the data will be sent.
    - `data`: A pointer to the raw data that needs to be sent.
    - `sz`: The size of the data to be sent, in bytes.
- **Control Flow**:
    - Checks if the size of the data to be sent exceeds the maximum allowed packet size defined by `PACKET_DATA_SIZE`.
    - If the size exceeds the limit, logs an error message indicating the oversized packet.
    - Increments the packet send count in the metrics of the `glob` structure.
    - Unlocks the `glob` structure to allow other operations while sending the data.
    - Calls the function pointed to by `glob->send_fun` to send the data to the specified destination.
    - Locks the `glob` structure again after sending the data.
- **Output**: The function does not return a value; it performs the action of sending data over the network.
- **Functions called**:
    - [`fd_gossip_unlock`](#fd_gossip_unlock)
    - [`fd_gossip_lock`](#fd_gossip_lock)


---
### fd\_gossip\_send<!-- {{#callable:fd_gossip_send}} -->
The `fd_gossip_send` function encodes a gossip message and sends it to a specified destination address.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure that holds the global state for the gossip protocol.
    - `dest`: A pointer to the `fd_gossip_peer_addr_t` structure representing the destination address to which the message will be sent.
    - `gmsg`: A pointer to the `fd_gossip_msg_t` structure containing the message to be sent.
- **Control Flow**:
    - The function initializes a buffer `buf` of size `PACKET_DATA_SIZE` to hold the encoded message.
    - It sets up a context `ctx` for encoding the message using `fd_bincode_encode_ctx_t`.
    - The function calls `fd_gossip_msg_encode` to encode the message into the buffer, logging an error if encoding fails.
    - It calculates the size of the encoded message by determining the difference between the end of the encoded data and the start of the buffer.
    - The encoded message is then sent using the [`fd_gossip_send_raw`](#fd_gossip_send_raw) function, which handles the actual sending of the data.
    - Finally, the function updates the metrics to reflect the number of messages sent of the specific type indicated by `gmsg->discriminant`.
- **Output**: The function does not return a value; it performs actions to send a message and update internal metrics.
- **Functions called**:
    - [`fd_gossip_send_raw`](#fd_gossip_send_raw)


---
### fd\_gossip\_make\_ping<!-- {{#callable:fd_gossip_make_ping}} -->
The `fd_gossip_make_ping` function initiates a ping/pong protocol with a specified peer address, managing the state of the ping attempts and sending a ping message.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure that holds the global state of the gossip protocol.
    - `arg`: A pointer to a `fd_pending_event_arg_t` structure containing the peer address to which the ping is to be sent.
- **Control Flow**:
    - The function first queries the active table to check if the peer address is already being tracked.
    - If the peer is not found and the active table is full, it increments a metric and returns.
    - If the peer is not found and there is space, it inserts the peer into the active table and initializes its state.
    - If the peer is found but has already responded to a ping, the function returns.
    - If the ping count exceeds a maximum threshold, it removes the peer from both the active and peer tables and returns.
    - The function updates the ping time and generates a new ping token if this is the first ping attempt.
    - It schedules the next ping attempt after a delay of 200 milliseconds.
    - Finally, it constructs a ping message, signs it, and sends it to the specified peer address.
- **Output**: The function does not return a value but modifies the state of the `fd_gossip_t` structure and sends a ping message to the specified peer.
- **Functions called**:
    - [`fd_active_new_value`](#fd_active_new_value)
    - [`fd_gossip_add_pending`](#fd_gossip_add_pending)
    - [`fd_pending_event_arg_peer_addr`](#fd_pending_event_arg_peer_addr)
    - [`fd_gossip_send`](#fd_gossip_send)


---
### fd\_gossip\_handle\_ping<!-- {{#callable:fd_gossip_handle_ping}} -->
Handles incoming ping messages and responds with a pong message.
- **Inputs**:
    - `glob`: Pointer to the global gossip state structure.
    - `from`: Pointer to the address of the peer that sent the ping.
    - `ping`: Pointer to the ping message structure containing the token and signature.
- **Control Flow**:
    - Verifies the signature of the received ping message using `fd_ed25519_verify`.
    - If the signature is invalid, increments the invalid signature metric and logs a warning, then returns.
    - Creates a new pong message structure and populates it with the sender's public key.
    - Generates a response hash token using the pre-image that includes a constant string and the original ping token.
    - Signs the pong message with the generated token.
    - Sends the pong message back to the sender using [`fd_gossip_send`](#fd_gossip_send).
- **Output**: No return value; the function sends a pong message back to the sender.
- **Functions called**:
    - [`fd_gossip_send`](#fd_gossip_send)


---
### fd\_gossip\_sign\_crds\_value<!-- {{#callable:fd_gossip_sign_crds_value}} -->
The `fd_gossip_sign_crds_value` function signs and timestamps a CRDS value based on its type.
- **Inputs**:
    - `glob`: A pointer to a `fd_gossip_t` structure that contains global state information, including the public key and current time.
    - `crd`: A pointer to a `fd_crds_value_t` structure that holds the CRDS value to be signed and timestamped.
- **Control Flow**:
    - The function begins by determining the type of CRDS value using a switch statement based on the `discriminant` field of the `crd` structure.
    - For each case, it assigns the appropriate public key and wallclock timestamp pointers based on the specific type of CRDS value.
    - If the `discriminant` does not match any known types, the function exits early.
    - The public key is set to the global public key, and the wallclock is updated with the current time converted to milliseconds.
    - The function then encodes the CRDS data into a buffer using `fd_crds_data_encode` and checks for encoding errors.
    - Finally, it calls the signing function provided in the global state to sign the encoded data and store the signature in the `crd` structure.
- **Output**: The function does not return a value but modifies the `crd` structure in place by adding a signature and updating the timestamp.


---
### fd\_gossip\_bloom\_pos<!-- {{#callable:fd_gossip_bloom_pos}} -->
Calculates a bloom filter position based on a hash and a key.
- **Inputs**:
    - `hash`: A pointer to a `fd_hash_t` structure containing the hash data.
    - `key`: An unsigned long integer representing the initial key used for the calculation.
    - `nbits`: An unsigned long integer representing the number of bits in the bloom filter.
- **Control Flow**:
    - A loop iterates 32 times, modifying the `key` using the hash data.
    - In each iteration, the `key` is XORed with a value from the `hash` structure and then multiplied by the FNV prime constant.
    - After the loop, the final `key` is reduced modulo `nbits` to ensure it fits within the bloom filter size.
- **Output**: Returns an unsigned long integer representing the calculated position in the bloom filter.


---
### fd\_gossip\_random\_active<!-- {{#callable:fd_gossip_random_active}} -->
Selects a random active peer from a list of peers with minimal ping counts.
- **Inputs**:
    - `glob`: A pointer to a `fd_gossip_t` structure that contains the state of the gossip protocol, including the active peers.
- **Control Flow**:
    - Initializes an empty list to store active peers and their total weight.
    - Iterates through the active peers using an iterator.
    - Checks if the peer has a valid pong time and if it is allowed as an entry point.
    - If the list is empty, adds the peer to the list and updates the total weight.
    - If the peer has a higher ping count than the current best, it is skipped.
    - If the peer has a lower ping count, it resets the list with this peer.
    - If the peer has the same ping count, it adds the peer to the list and updates the total weight.
    - If no valid peers are found, returns NULL.
    - Generates a random number based on the total weight and selects a peer from the list based on their weights.
- **Output**: Returns a pointer to a randomly selected `fd_active_elem_t` structure representing an active peer, or NULL if no valid peers are found.
- **Functions called**:
    - [`fd_gossip_is_allowed_entrypoint`](#fd_gossip_is_allowed_entrypoint)


---
### fd\_gossip\_random\_pull<!-- {{#callable:fd_gossip_random_pull}} -->
The `fd_gossip_random_pull` function initiates a random pull request for data from a randomly selected active peer.
- **Inputs**: None
- **Control Flow**:
    - The function first schedules itself to be called again after 5 seconds using [`fd_gossip_add_pending`](#fd_gossip_add_pending).
    - It attempts to select a random active peer using [`fd_gossip_random_active`](#fd_gossip_random_active), returning early if no peer is found.
    - It calculates the number of packets needed for a bloom filter based on the number of items in the value metadata map, ensuring a false positive rate of less than 0.1%.
    - Random keys are generated for the bloom filter, and the bits for the bloom filter are initialized.
    - The function samples a subset of bloom filter packets to be included in the pull request.
    - It iterates through the value metadata map to set bits in the bloom filter based on the selected filters and the values that have not expired.
    - Finally, it assembles a pull request message and sends it to the selected peer.
- **Output**: The function does not return a value but sends a pull request message to a randomly selected active peer, containing a bloom filter and the sender's contact information.
- **Functions called**:
    - [`fd_gossip_add_pending`](#fd_gossip_add_pending)
    - [`fd_pending_event_arg_null`](#fd_pending_event_arg_null)
    - [`fd_gossip_random_active`](#fd_gossip_random_active)
    - [`fd_gossip_bloom_pos`](#fd_gossip_bloom_pos)
    - [`fd_gossip_sign_crds_value`](#fd_gossip_sign_crds_value)
    - [`fd_gossip_send`](#fd_gossip_send)


---
### fd\_gossip\_handle\_pong<!-- {{#callable:fd_gossip_handle_pong}} -->
Handles the reception of a pong message in the gossip protocol.
- **Inputs**:
    - `glob`: A pointer to the global gossip state structure (`fd_gossip_t`) that maintains the state of the gossip protocol.
    - `from`: A pointer to the address of the peer that sent the pong message (`fd_gossip_peer_addr_t`).
    - `pong`: A pointer to the pong message structure (`fd_gossip_ping_t`) containing the token and signature.
- **Control Flow**:
    - Queries the active table to find the corresponding entry for the sender's address.
    - If the entry is not found, increments the expired pong event count and logs a debug message before returning.
    - Constructs a pre-image for hash verification using a predefined string and the ping token from the active entry.
    - Calculates the hash of the pre-image and verifies it against the token in the received pong message.
    - If the tokens do not match, increments the wrong token event count and logs a debug message before returning.
    - Verifies the signature of the pong message using the public key of the sender.
    - If the signature is invalid, increments the invalid signature event count and logs a warning before returning.
    - Updates the pong time and ID in the active entry.
    - Queries the peers table to check if the sender is already known.
    - If the sender is new and the peers table is full, increments the table full event count and logs a debug message before returning.
    - Inserts the new peer into the peers table and initializes its stake.
    - Updates the wall clock time and ID for the new peer.
    - Queries the weights table to set the weight for the active entry based on the peer's ID.
- **Output**: The function does not return a value but updates the state of the gossip protocol, including metrics and peer information.


---
### fd\_gossip\_random\_ping<!-- {{#callable:fd_gossip_random_ping}} -->
Initiates a ping/pong protocol with a random active peer to check its liveness.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure that holds the global state of the gossip protocol.
    - `arg`: A pointer to `fd_pending_event_arg_t`, which is not used in this function.
- **Control Flow**:
    - The function schedules itself to be called again in 1 second using [`fd_gossip_add_pending`](#fd_gossip_add_pending).
    - It checks the count of active peers and inactive peers in the `glob` structure.
    - If there are no active or inactive peers, the function returns early.
    - If there are inactive peers and the count of active peers is less than the maximum allowed, it selects a new inactive peer.
    - If there are active peers, it randomly selects one and checks if it has been pinged recently.
    - If the selected peer has been pinged within the last minute, the function returns without sending a ping.
    - If the selected peer is eligible, it prepares a ping message and calls [`fd_gossip_make_ping`](#fd_gossip_make_ping) to send the ping.
- **Output**: The function does not return a value; it initiates a ping to a selected peer.
- **Functions called**:
    - [`fd_gossip_add_pending`](#fd_gossip_add_pending)
    - [`fd_pending_event_arg_null`](#fd_pending_event_arg_null)
    - [`fd_gossip_peer_addr_copy`](#fd_gossip_peer_addr_copy)
    - [`fd_gossip_make_ping`](#fd_gossip_make_ping)


---
### fd\_crds\_dup\_check<!-- {{#callable:fd_crds_dup_check}} -->
Checks for duplicate entries in the CRDS value table and updates statistics accordingly.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure representing the global gossip state.
    - `key`: A pointer to the `fd_hash_t` structure representing the hash key of the value to check for duplicates.
    - `from`: A pointer to the `fd_gossip_peer_addr_t` structure representing the address of the peer that sent the value.
    - `origin`: A pointer to the `fd_pubkey_t` structure representing the public key of the originator of the value.
- **Control Flow**:
    - Queries the value metadata map using the provided `key` to check if the value already exists.
    - If the value exists, it checks if the `from` address is not NULL.
    - If `from` is not NULL, it queries the statistics table for the sender's address.
    - If the sender's entry does not exist in the statistics table, it attempts to insert a new entry.
    - Updates the last received timestamp for the sender's entry.
    - Iterates through the duplicate origins to check if the current `origin` already exists.
    - If the `origin` exists, increments its count.
    - If the `origin` does not exist and the maximum number of origins has not been reached, adds it to the list of duplicates.
    - Returns 1 if a duplicate was found, otherwise returns 0.
- **Output**: Returns 1 if the value is a duplicate (exists in the table), otherwise returns 0.


---
### fd\_crds\_sigverify<!-- {{#callable:fd_crds_sigverify}} -->
The `fd_crds_sigverify` function verifies the signature of a CRDS value using the Ed25519 signature scheme.
- **Inputs**:
    - `crds_encoded_val`: A pointer to the encoded CRDS value which contains the signature followed by the data to be verified.
    - `crds_encoded_len`: The length of the encoded CRDS value.
    - `pubkey`: A pointer to the public key used for signature verification.
- **Control Flow**:
    - The function casts the `crds_encoded_val` to a `fd_signature_t` structure to extract the signature.
    - It calculates the length of the data by subtracting the size of the signature from `crds_encoded_len`.
    - The function then calls `fd_ed25519_verify` with the data, its length, the extracted signature, the public key, and a static SHA-512 context.
- **Output**: Returns an integer indicating the result of the signature verification, where a return value of 0 indicates success and a non-zero value indicates failure.


---
### fd\_gossip\_recv\_crds\_array<!-- {{#callable:fd_gossip_recv_crds_array}} -->
Processes an array of CRDS values, filtering duplicates and invalid signatures before inserting them into the gossip protocol.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure representing the global state of the gossip protocol.
    - `from`: A pointer to the `fd_gossip_peer_addr_t` structure representing the address of the peer sending the CRDS values.
    - `crds`: A pointer to an array of `fd_crds_value_t` structures containing the CRDS values to be processed.
    - `crds_len`: An unsigned long integer representing the number of CRDS values in the array.
    - `route`: An enumeration value of type `fd_gossip_crds_route_t` indicating the route of the CRDS values (e.g., push or pull).
- **Control Flow**:
    - First, the function checks if the number of CRDS values exceeds the maximum allowed, logging an error if it does.
    - Next, it checks if adding the new CRDS values would exceed the current capacity of the values vector, dropping the packet if it does.
    - The function then expands the values vector to accommodate the new CRDS values and initializes a filter pass.
    - During the filter pass, each CRDS value is processed to extract its data, skipping any that are invalid or originate from the local node.
    - If a CRDS value is a duplicate, it is skipped, and metrics are updated accordingly.
    - After filtering, the function contracts the values vector to remove any entries that were not retained.
    - In the insert pass, the retained CRDS values are inserted into the value metadata map, and any contact information is updated.
    - Finally, the function delivers the processed CRDS data upstream using the provided delivery function.
- **Output**: The function does not return a value but modifies the state of the `fd_gossip_t` structure and may invoke the delivery function to send processed data upstream.
- **Functions called**:
    - [`fd_value_from_crds`](#fd_value_from_crds)
    - [`fd_crds_dup_check`](#fd_crds_dup_check)
    - [`fd_crds_sigverify`](#fd_crds_sigverify)
    - [`fd_value_meta_map_value_init`](#fd_value_meta_map_value_init)
    - [`fd_gossip_contact_info_v2_find_proto_ident`](#fd_gossip_contact_info_v2_find_proto_ident)
    - [`fd_gossip_port_from_socketaddr`](#fd_gossip_port_from_socketaddr)
    - [`fd_gossip_from_soladdr`](#fd_gossip_from_soladdr)
    - [`fd_gossip_peer_addr_copy`](#fd_gossip_peer_addr_copy)
    - [`fd_gossip_is_allowed_entrypoint`](#fd_gossip_is_allowed_entrypoint)
    - [`fd_gossip_unlock`](#fd_gossip_unlock)
    - [`fd_gossip_lock`](#fd_gossip_lock)


---
### verify\_signable\_data\_with\_prefix<!-- {{#callable:verify_signable_data_with_prefix}} -->
Verifies the signable data with a specific prefix for a gossip prune message.
- **Inputs**:
    - `glob`: A pointer to the global gossip state structure (`fd_gossip_t`) that holds the current state of the gossip protocol.
    - `msg`: A pointer to a prune message structure (`fd_gossip_prune_msg_t`) that contains the data to be verified, including the public key, prunes, destination, wallclock, and signature.
- **Control Flow**:
    - Initializes a `signdata` structure with a predefined prefix and the relevant data from the `msg` argument.
    - Encodes the `signdata` into a buffer using the `fd_gossip_prune_sign_data_with_prefix_encode` function.
    - If encoding fails, increments a failure metric and logs a warning, then returns an error code.
    - Verifies the signature of the encoded data against the provided public key using the `fd_ed25519_verify` function.
    - Returns the result of the signature verification.
- **Output**: Returns 0 if the signature verification is successful, or a non-zero error code if it fails.


---
### verify\_signable\_data<!-- {{#callable:verify_signable_data}} -->
The `verify_signable_data` function verifies the signature of a prune message by encoding the relevant data and checking it against the provided signature.
- **Inputs**:
    - `glob`: A pointer to a `fd_gossip_t` structure that holds the global state of the gossip protocol.
    - `msg`: A pointer to a `fd_gossip_prune_msg_t` structure containing the prune message data, including the public key, prunes, destination, wallclock, and signature.
- **Control Flow**:
    - The function initializes a `fd_gossip_prune_sign_data_t` structure with the public key, prunes length, prunes, destination, and wallclock from the `msg`.
    - It then prepares a buffer and encoding context for serializing the signable data.
    - If the encoding of the signable data fails, it increments a failure metric and logs a warning, returning 1 to indicate failure.
    - Next, it calls `fd_ed25519_verify` to verify the signature against the encoded data and the public key.
    - The function returns the result of the signature verification.
- **Output**: The function returns 0 if the signature verification is successful, or 1 if it fails.


---
### fd\_gossip\_handle\_prune<!-- {{#callable:fd_gossip_handle_prune}} -->
Handles a prune request in the gossip protocol by verifying the message and updating the bloom filter.
- **Inputs**:
    - `glob`: A pointer to the global gossip state structure (`fd_gossip_t`) that maintains the state of the gossip protocol.
    - `from`: A pointer to the address of the peer that sent the prune message (`fd_gossip_peer_addr_t`).
    - `msg`: A pointer to the prune message structure (`fd_gossip_prune_msg_t`) containing the data to be processed.
- **Control Flow**:
    - The function first checks if the destination of the prune message matches the local public key; if not, it returns immediately.
    - It then attempts to verify the signature of the prune message using two methods: without a prefix and with a predefined prefix.
    - If the signature verification fails, it increments a failure metric and logs a warning before returning.
    - Next, it searches for the active push state that corresponds to the public key specified in the prune message.
    - If no matching push state is found, the function returns.
    - Finally, it updates the bloom filter's prune bits based on the keys specified in the prune message.
- **Output**: The function does not return a value; it modifies the internal state of the gossip protocol by updating the bloom filter.
- **Functions called**:
    - [`verify_signable_data`](#verify_signable_data)
    - [`verify_signable_data_with_prefix`](#verify_signable_data_with_prefix)
    - [`fd_gossip_bloom_pos`](#fd_gossip_bloom_pos)


---
### fd\_gossip\_push\_updated\_contact<!-- {{#callable:fd_gossip_push_updated_contact}} -->
The `fd_gossip_push_updated_contact` function updates and pushes the current contact information of a node in the gossip protocol.
- **Inputs**: None
- **Control Flow**:
    - Checks if the `shred_version` of the node's contact information is zero; if so, it returns early without making any updates.
    - Checks if at least one second has passed since the last contact update; if not, it returns early.
    - If there was a previous contact update, it queries the value metadata map for the last contact info and marks it for deletion.
    - Updates the `last_contact_time` to the current time.
    - Sets the `wallclock` of the current contact information to the current time in milliseconds.
    - Calls [`fd_gossip_push_value_nolock`](#fd_gossip_push_value_nolock) to push the updated contact information.
- **Output**: The function does not return a value; it performs updates and pushes the contact information to other nodes in the gossip network.
- **Functions called**:
    - [`fd_gossip_push_value_nolock`](#fd_gossip_push_value_nolock)


---
### fd\_gossip\_handle\_pull\_req<!-- {{#callable:fd_gossip_handle_pull_req}} -->
Handles a pull request in the gossip protocol by responding with relevant data or pinging unresponsive peers.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure representing the global state of the gossip protocol.
    - `from`: A pointer to the `fd_gossip_peer_addr_t` structure representing the address of the peer that sent the pull request.
    - `msg`: A pointer to the `fd_gossip_pull_req_t` structure containing the details of the pull request.
- **Control Flow**:
    - Queries the active table to check if the peer is currently active.
    - If the peer is not active or unresponsive, it increments the failure metric and may send a ping to the peer.
    - If the peer is active, it prepares a pull response message.
    - Encodes the response message and checks for encoding errors, incrementing the failure metric if necessary.
    - Pushes updated contact information into the values.
    - Applies a bloom filter to determine which values to include in the response based on the request's filter.
    - Sends the response back to the requesting peer, handling packet size limits by flushing data as needed.
    - Records metrics for hits and misses during the filtering process.
- **Output**: The function does not return a value but sends a response back to the requesting peer, containing the relevant data or a ping if the peer is unresponsive.
- **Functions called**:
    - [`fd_gossip_peer_addr_copy`](#fd_gossip_peer_addr_copy)
    - [`fd_gossip_make_ping`](#fd_gossip_make_ping)
    - [`fd_gossip_push_updated_contact`](#fd_gossip_push_updated_contact)
    - [`fd_gossip_bloom_pos`](#fd_gossip_bloom_pos)
    - [`fd_gossip_send_raw`](#fd_gossip_send_raw)


---
### fd\_gossip\_recv<!-- {{#callable:fd_gossip_recv}} -->
The `fd_gossip_recv` function processes incoming gossip messages and dispatches them to the appropriate handler based on the message type.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure that holds the global state of the gossip protocol.
    - `from`: A pointer to the `fd_gossip_peer_addr_t` structure representing the address of the peer that sent the message.
    - `gmsg`: A pointer to the `fd_gossip_msg_t` structure containing the received gossip message.
- **Control Flow**:
    - The function first checks if the `discriminant` of the message is within the expected range and updates the metrics accordingly.
    - It then uses a switch statement to determine the type of the message based on the `discriminant` field.
    - For each case, it calls the appropriate handler function, such as [`fd_gossip_handle_pull_req`](#fd_gossip_handle_pull_req) for pull requests, [`fd_gossip_recv_crds_array`](#fd_gossip_recv_crds_array) for pull responses and push messages, and [`fd_gossip_handle_prune`](#fd_gossip_handle_prune), [`fd_gossip_handle_ping`](#fd_gossip_handle_ping), or [`fd_gossip_handle_pong`](#fd_gossip_handle_pong) for prune, ping, and pong messages respectively.
- **Output**: The function does not return a value; it modifies the state of the `fd_gossip_t` structure and updates metrics based on the processed messages.
- **Functions called**:
    - [`fd_gossip_handle_pull_req`](#fd_gossip_handle_pull_req)
    - [`fd_gossip_recv_crds_array`](#fd_gossip_recv_crds_array)
    - [`fd_gossip_handle_prune`](#fd_gossip_handle_prune)
    - [`fd_gossip_handle_ping`](#fd_gossip_handle_ping)
    - [`fd_gossip_handle_pong`](#fd_gossip_handle_pong)


---
### fd\_gossip\_add\_active\_peer<!-- {{#callable:fd_gossip_add_active_peer}} -->
Adds a peer address to the list of active peers in the gossip protocol.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure representing the global state of the gossip protocol.
    - `addr`: A pointer to the `fd_gossip_peer_addr_t` structure representing the address of the peer to be added.
- **Control Flow**:
    - Locks the gossip state to ensure thread safety.
    - Queries the active peer table to check if the peer address already exists.
    - If the peer is not found, checks if the active peer table is full.
    - If the table is full, logs a warning and returns an error.
    - If there is space, inserts the new peer address into the active peer table.
    - Initializes the new peer's state, including setting the ping count to zero.
    - Unlocks the gossip state before returning.
- **Output**: Returns 0 on success, or -1 if the active peer table is full.
- **Functions called**:
    - [`fd_gossip_lock`](#fd_gossip_lock)
    - [`fd_gossip_unlock`](#fd_gossip_unlock)
    - [`fd_active_new_value`](#fd_active_new_value)


---
### fd\_gossip\_refresh\_push\_states<!-- {{#callable:fd_gossip_refresh_push_states}} -->
The `fd_gossip_refresh_push_states` function updates the list of active push states by removing inactive peers and adding new active peers.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure that holds the global state of the gossip protocol.
    - `arg`: A pointer to a `fd_pending_event_arg_t` structure, which is unused in this function.
- **Control Flow**:
    - The function schedules itself to be called again in 20 seconds using [`fd_gossip_add_pending`](#fd_gossip_add_pending).
    - It iterates through the current push states and removes any that do not have active peers by checking against the active table.
    - If the number of push states reaches the maximum limit, it identifies and removes the push state with the highest drop count.
    - The function attempts to add new active peers as pushers, up to a maximum of 5 attempts, ensuring no duplicates are added.
- **Output**: The function does not return a value but updates the internal state of the `fd_gossip_t` structure, specifically the list of active push states and associated metrics.
- **Functions called**:
    - [`fd_gossip_add_pending`](#fd_gossip_add_pending)
    - [`fd_pending_event_arg_null`](#fd_pending_event_arg_null)
    - [`fd_gossip_random_active`](#fd_gossip_random_active)
    - [`fd_gossip_peer_addr_eq`](#fd_gossip_peer_addr_eq)
    - [`fd_gossip_peer_addr_copy`](#fd_gossip_peer_addr_copy)


---
### fd\_gossip\_push<!-- {{#callable:fd_gossip_push}} -->
The `fd_gossip_push` function manages the process of pushing updated values to active peers in a gossip protocol.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure that holds the global state of the gossip protocol.
    - `arg`: A pointer to `fd_pending_event_arg_t`, which is unused in this function.
- **Control Flow**:
    - The function schedules itself to be called again after 100 milliseconds using [`fd_gossip_add_pending`](#fd_gossip_add_pending).
    - It updates the local contact information by calling [`fd_gossip_push_updated_contact`](#fd_gossip_push_updated_contact).
    - It calculates the number of pending values that need to be pushed and limits this to a maximum defined by `FD_NEED_PUSH_MAX`.
    - It iterates over the recent values, checking if they have expired based on a timeout value.
    - For each valid value, it iterates over the active push states to determine if the value can be sent to each peer.
    - It applies a pruning bloom filter to decide if the value should be sent or dropped.
    - If the packet size exceeds the defined limit, it sends the current packet and resets the packet buffer.
    - Finally, it flushes any remaining data in the packet buffers for each push state.
- **Output**: The function does not return a value but sends updated values to peers and manages the state of outgoing packets.
- **Functions called**:
    - [`fd_gossip_add_pending`](#fd_gossip_add_pending)
    - [`fd_pending_event_arg_null`](#fd_pending_event_arg_null)
    - [`fd_gossip_push_updated_contact`](#fd_gossip_push_updated_contact)
    - [`fd_gossip_bloom_pos`](#fd_gossip_bloom_pos)
    - [`fd_gossip_send_raw`](#fd_gossip_send_raw)


---
### fd\_gossip\_push\_value\_nolock<!-- {{#callable:fd_gossip_push_value_nolock}} -->
The `fd_gossip_push_value_nolock` function pushes a CRDS value into the gossip protocol without acquiring a lock.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure representing the global state of the gossip protocol.
    - `data`: A pointer to the `fd_crds_data_t` structure containing the data to be pushed.
    - `key_opt`: An optional pointer to a `fd_hash_t` where the key of the pushed value will be stored if not NULL.
- **Control Flow**:
    - The function first checks if the `discriminant` of the `data` is valid; if not, it increments a drop metric and returns -1.
    - It wraps the `data` in a `fd_crds_value_t` structure and signs it using [`fd_gossip_sign_crds_value`](#fd_gossip_sign_crds_value).
    - Next, it checks if the metadata map or values vector is full; if so, it increments a drop metric and returns -1.
    - The function expands the values vector to accommodate the new value and attempts to convert the CRDS value into a `fd_value_t` structure.
    - If the conversion fails, it increments a drop metric and returns -1.
    - If `key_opt` is not NULL, it assigns the key of the newly created value to it.
    - The function checks if the value already exists in the metadata map; if it does, it increments a duplicate metric and returns -1.
    - Finally, it inserts the new value into the metadata map, initializes its metadata, and updates the metrics before returning 0.
- **Output**: The function returns 0 on success, or -1 if an error occurs during the process.
- **Functions called**:
    - [`fd_gossip_sign_crds_value`](#fd_gossip_sign_crds_value)
    - [`fd_value_from_crds`](#fd_value_from_crds)
    - [`fd_value_meta_map_value_init`](#fd_value_meta_map_value_init)


---
### fd\_gossip\_push\_value<!-- {{#callable:fd_gossip_push_value}} -->
The `fd_gossip_push_value` function pushes a value into the gossip protocol while ensuring thread safety through locking.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure representing the global state of the gossip protocol.
    - `data`: A pointer to the `fd_crds_data_t` structure containing the data to be pushed into the gossip protocol.
    - `key_opt`: An optional pointer to a `fd_hash_t` structure where the hash of the pushed value can be stored.
- **Control Flow**:
    - The function first acquires a lock on the `glob` object to ensure thread safety.
    - It then calls the [`fd_gossip_push_value_nolock`](#fd_gossip_push_value_nolock) function to perform the actual push operation without the lock.
    - After the push operation, it releases the lock on the `glob` object.
    - Finally, it returns the result code from the [`fd_gossip_push_value_nolock`](#fd_gossip_push_value_nolock) function.
- **Output**: The function returns an integer indicating the success or failure of the push operation, as defined by the [`fd_gossip_push_value_nolock`](#fd_gossip_push_value_nolock) function.
- **Functions called**:
    - [`fd_gossip_lock`](#fd_gossip_lock)
    - [`fd_gossip_push_value_nolock`](#fd_gossip_push_value_nolock)
    - [`fd_gossip_unlock`](#fd_gossip_unlock)


---
### fd\_gossip\_make\_prune<!-- {{#callable:fd_gossip_make_prune}} -->
The `fd_gossip_make_prune` function periodically generates and sends prune requests to peers based on stale entries and high duplicate counts.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure that holds the global state of the gossip protocol.
    - `arg`: A pointer to a `fd_pending_event_arg_t` structure, which is unused in this function.
- **Control Flow**:
    - The function schedules itself to run again in 30 seconds using [`fd_gossip_add_pending`](#fd_gossip_add_pending).
    - It calculates an expiration time based on the current time and a predefined expiration duration.
    - It iterates over the statistics table to check for stale entries and high duplicate counts.
    - For each entry, if it hasn't been updated for a long time, it increments the stale entry metric and removes it from the stats table.
    - If an entry has high duplicate counts, it prepares a prune request message.
    - The function retrieves the peer's ID and constructs a prune message with the relevant data.
    - It signs the prune message and sends it to the corresponding peer.
- **Output**: The function does not return a value; instead, it sends prune requests to peers and updates internal metrics.
- **Functions called**:
    - [`fd_gossip_add_pending`](#fd_gossip_add_pending)
    - [`fd_pending_event_arg_null`](#fd_pending_event_arg_null)
    - [`fd_gossip_send`](#fd_gossip_send)


---
### fd\_gossip\_log\_stats<!-- {{#callable:fd_gossip_log_stats}} -->
The `fd_gossip_log_stats` function logs statistics about received gossip packets and manages peer state.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure that holds the global state of the gossip protocol.
    - `arg`: A pointer to `fd_pending_event_arg_t`, which is unused in this function.
- **Control Flow**:
    - The function schedules itself to run again in 60 seconds using [`fd_gossip_add_pending`](#fd_gossip_add_pending).
    - It checks if any gossip packets have been received; if none, it logs a warning.
    - If packets have been received, it logs the count of received packets.
    - It checks for the presence of peers and whether any CRDS traffic has been received, logging a warning if not.
    - It resets the count of received packets and logs the counts of duplicate and new values received.
    - It logs the number of values pushed and filtered.
    - It iterates over known peers, logging their status and removing any that have not been updated for a specified duration.
    - It updates the metrics for the total, active, and inactive peer counts.
- **Output**: The function does not return a value but logs various statistics and updates the state of the gossip protocol.
- **Functions called**:
    - [`fd_gossip_add_pending`](#fd_gossip_add_pending)
    - [`fd_pending_event_arg_null`](#fd_pending_event_arg_null)
    - [`fd_gossip_peer_addr_copy`](#fd_gossip_peer_addr_copy)


---
### fd\_gossip\_settime<!-- {{#callable:fd_gossip_settime}} -->
Sets the current time in nanoseconds for the `fd_gossip` structure.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure that holds the global state of the gossip protocol.
    - `ts`: A long integer representing the current time in nanoseconds to be set in the `fd_gossip` structure.
- **Control Flow**:
    - The function directly assigns the value of `ts` to the `now` field of the `fd_gossip_t` structure pointed to by `glob`.
- **Output**: This function does not return a value; it modifies the state of the `fd_gossip` structure by updating its `now` field.


---
### fd\_gossip\_gettime<!-- {{#callable:fd_gossip_gettime}} -->
The `fd_gossip_gettime` function retrieves the current time in nanoseconds from the `fd_gossip` structure.
- **Inputs**:
    - `glob`: A pointer to an instance of `fd_gossip_t`, which contains the current state of the gossip protocol including the current time.
- **Control Flow**:
    - The function directly accesses the `now` field of the `fd_gossip_t` structure pointed to by `glob`.
    - It returns the value of `glob->now` without any additional processing or conditions.
- **Output**: Returns a long integer representing the current time in nanoseconds as stored in the `now` field of the `fd_gossip` structure.


---
### fd\_gossip\_compact\_values<!-- {{#callable:fd_gossip_compact_values}} -->
The `fd_gossip_compact_values` function compacts the values in a gossip protocol by removing marked entries and adjusting the push queue.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure that contains the state of the gossip protocol, including the values vector.
- **Control Flow**:
    - Initializes `start` to 0 and retrieves the current count of values in the vector.
    - Finds the first element marked for deletion by iterating through the vector until it finds an entry with `del` set.
    - Uses a while loop to iterate through the values, checking for additional entries marked for deletion.
    - If an entry is found to be marked for deletion, it moves the remaining entries in the vector to fill the gap, preserving order.
    - Updates the `need_push_head` index based on the number of deletions and adjusts the vector size accordingly.
    - Logs the number of values compacted and returns this count.
- **Output**: Returns the number of values that were deleted from the vector during the compaction process.


---
### fd\_gossip\_cleanup\_values<!-- {{#callable:fd_gossip_cleanup_values}} -->
The `fd_gossip_cleanup_values` function cleans up expired values from the gossip protocol's value metadata map and vector.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure that holds the state of the gossip protocol.
    - `arg`: A pointer to a `fd_pending_event_arg_t` structure, which is unused in this function.
- **Control Flow**:
    - The function schedules itself to run again in 15 seconds using [`fd_gossip_add_pending`](#fd_gossip_add_pending).
    - It calculates the expiration time for values by subtracting `FD_GOSSIP_VALUE_EXPIRE` from the current time.
    - It iterates over the value metadata map to check each entry's timestamp against the expiration time.
    - If an entry's timestamp indicates it has expired, it marks the corresponding value for deletion and removes the entry from the metadata map.
    - After processing all entries, it calls [`fd_gossip_compact_values`](#fd_gossip_compact_values) to clean up the values vector and update metrics.
- **Output**: The function does not return a value but updates the state of the gossip protocol by removing expired values and adjusting metrics.
- **Functions called**:
    - [`fd_gossip_add_pending`](#fd_gossip_add_pending)
    - [`fd_pending_event_arg_null`](#fd_pending_event_arg_null)
    - [`fd_gossip_compact_values`](#fd_gossip_compact_values)


---
### fd\_gossip\_start<!-- {{#callable:fd_gossip_start}} -->
The `fd_gossip_start` function initializes and schedules a series of timed events for the gossip protocol.
- **Inputs**:
    - `glob`: A pointer to a `fd_gossip_t` structure that holds the state of the gossip protocol.
- **Control Flow**:
    - Locks the `glob` structure to ensure thread safety.
    - Schedules a series of pending events using [`fd_gossip_add_pending`](#fd_gossip_add_pending) for various functions such as `fd_gossip_random_pull`, `fd_gossip_random_ping`, `fd_gossip_log_stats`, `fd_gossip_refresh_push_states`, `fd_gossip_push`, `fd_gossip_make_prune`, and `fd_gossip_cleanup_values` with specified timeouts.
    - Unlocks the `glob` structure after scheduling the events.
- **Output**: Returns 0 to indicate successful scheduling of the events.
- **Functions called**:
    - [`fd_gossip_lock`](#fd_gossip_lock)
    - [`fd_gossip_add_pending`](#fd_gossip_add_pending)
    - [`fd_pending_event_arg_null`](#fd_pending_event_arg_null)
    - [`fd_gossip_unlock`](#fd_gossip_unlock)


---
### fd\_gossip\_continue<!-- {{#callable:fd_gossip_continue}} -->
The `fd_gossip_continue` function processes pending events in the gossip protocol.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure that holds the state of the gossip protocol.
- **Control Flow**:
    - Locks the `fd_gossip_t` structure to ensure thread safety.
    - Retrieves the event heap from the `glob` structure.
    - Enters a loop that continues as long as there are pending events in the heap.
    - Checks if the timeout of the next event is greater than the current time; if so, breaks the loop.
    - Calls the function associated with the event, passing `glob` and the event's argument.
    - Removes the processed event from the heap.
    - Unlocks the `fd_gossip_t` structure before returning.
- **Output**: Returns 0 to indicate successful processing of events.
- **Functions called**:
    - [`fd_gossip_lock`](#fd_gossip_lock)
    - [`fd_gossip_unlock`](#fd_gossip_unlock)


---
### fd\_gossip\_recv\_packet<!-- {{#callable:fd_gossip_recv_packet}} -->
Receives and processes a gossip packet, decoding it and handling the message accordingly.
- **Inputs**:
    - `glob`: A pointer to the `fd_gossip_t` structure that holds the state of the gossip protocol.
    - `msg`: A pointer to the raw message data received in the gossip packet.
    - `msglen`: The length of the message data.
    - `from`: A pointer to the `fd_gossip_peer_addr_t` structure representing the address of the sender.
- **Control Flow**:
    - Locks the `fd_gossip_t` structure to ensure thread safety.
    - Increments the received packet count and metrics for received packets.
    - Decodes the incoming message using `fd_bincode_decode1_spad`, checking for corruption.
    - If the message is corrupted or the decoded size does not match the expected length, it logs a warning and returns -1.
    - Logs the type of the received message and the sender's address.
    - Calls [`fd_gossip_recv`](#fd_gossip_recv) to handle the decoded message based on its type.
    - Unlocks the `fd_gossip_t` structure before returning.
- **Output**: Returns 0 on successful processing of the packet, or -1 if there was an error in decoding the message.
- **Functions called**:
    - [`fd_gossip_lock`](#fd_gossip_lock)
    - [`fd_gossip_unlock`](#fd_gossip_unlock)
    - [`fd_gossip_recv`](#fd_gossip_recv)


---
### fd\_gossip\_get\_shred\_version<!-- {{#callable:fd_gossip_get_shred_version}} -->
The `fd_gossip_get_shred_version` function retrieves the shred version from the gossip protocol's contact information.
- **Inputs**:
    - `glob`: A constant pointer to a `fd_gossip_t` structure that contains the global state of the gossip protocol.
- **Control Flow**:
    - The function accesses the `my_contact` member of the `fd_gossip_t` structure pointed to by `glob`.
    - It then retrieves the `shred_version` from the `ci` (contact info) structure within `my_contact`.
- **Output**: Returns the `shred_version` as an unsigned short (ushort) value.


---
### fd\_gossip\_set\_stake\_weights<!-- {{#callable:fd_gossip_set_stake_weights}} -->
Sets the stake weights for the gossip protocol.
- **Inputs**:
    - `gossip`: A pointer to the `fd_gossip_t` structure representing the gossip protocol instance.
    - `stake_weights`: A pointer to an array of `fd_stake_weight_t` structures containing the stake weights.
    - `stake_weights_cnt`: The count of stake weights provided, indicating the number of elements in the `stake_weights` array.
- **Control Flow**:
    - Checks if `stake_weights` is NULL and logs an error if it is.
    - Checks if `stake_weights_cnt` exceeds `MAX_STAKE_WEIGHTS` and logs an error if it does.
    - Locks the `gossip` instance to ensure thread safety.
    - Iterates through the existing weights table and removes all entries to clear it for new stake weights.
    - Iterates through the provided `stake_weights` array, inserting each weight into the weights table if the stake is non-zero, and calculates the weight as the square of the logarithm base 2 of the stake.
    - Updates the weights of active elements in the `gossip` instance based on the newly set stake weights.
    - Unlocks the `gossip` instance after updates are complete.
- **Output**: The function does not return a value; it modifies the state of the `gossip` instance by updating the stake weights and the weights of active peers.
- **Functions called**:
    - [`fd_gossip_lock`](#fd_gossip_lock)
    - [`fd_gossip_unlock`](#fd_gossip_unlock)


---
### fd\_gossip\_set\_entrypoints<!-- {{#callable:fd_gossip_set_entrypoints}} -->
Sets the entry points for the gossip protocol and initializes active peers.
- **Inputs**:
    - `gossip`: A pointer to the `fd_gossip_t` structure that holds the state of the gossip protocol.
    - `entrypoints`: A pointer to an array of `fd_ip4_port_t` structures representing the entry points (IP addresses and ports) for the gossip protocol.
    - `entrypoints_cnt`: An unsigned long integer representing the number of entry points provided.
- **Control Flow**:
    - The function first sets the `entrypoints_cnt` field of the `gossip` structure to the provided `entrypoints_cnt` value.
    - It then enters a loop that iterates over each entry point in the `entrypoints` array.
    - For each entry point, it logs a notice with the address and port of the peer being initialized.
    - The function calls [`fd_gossip_add_active_peer`](#fd_gossip_add_active_peer) to add the current entry point as an active peer in the gossip protocol.
    - Finally, it stores the current entry point in the `entrypoints` array of the `gossip` structure.
- **Output**: The function does not return a value; it modifies the state of the `gossip` structure by setting entry points and adding active peers.
- **Functions called**:
    - [`fd_gossip_add_active_peer`](#fd_gossip_add_active_peer)


---
### fd\_gossip\_is\_allowed\_entrypoint<!-- {{#callable:fd_gossip_is_allowed_entrypoint}} -->
Checks if a given peer address is an allowed entry point in the gossip protocol.
- **Inputs**:
    - `gossip`: A pointer to the `fd_gossip_t` structure that contains the state of the gossip protocol.
    - `addr`: A pointer to the `fd_gossip_peer_addr_t` structure representing the peer address to check.
- **Control Flow**:
    - Iterates over the list of entry points stored in the `gossip` structure.
    - For each entry point, it checks if the provided `addr` matches the current entry point using the [`fd_gossip_peer_addr_eq`](#fd_gossip_peer_addr_eq) function.
    - If a match is found, the function returns 1, indicating that the entry point is allowed.
    - If no matches are found after checking all entry points, the function returns 0.
- **Output**: Returns 1 if the provided peer address is an allowed entry point, otherwise returns 0.
- **Functions called**:
    - [`fd_gossip_peer_addr_eq`](#fd_gossip_peer_addr_eq)


# Function Declarations (Public API)

---
### fd\_gossip\_refresh\_contact\_info\_v2\_sockets<!-- {{#callable_declaration:fd_gossip_refresh_contact_info_v2_sockets}} -->
Updates the contact information with new socket addresses.
- **Description**: This function updates the contact information structure with new socket addresses based on the provided node addresses. It should be called whenever the node's address configuration changes to ensure that the contact information reflects the current network setup. The function processes each address and port, ensuring they are stored in the correct order and format. It handles cases where multiple services share the same port and ensures that the contact information does not exceed the maximum allowed sockets.
- **Inputs**:
    - `addrs`: A pointer to a constant `fd_gossip_node_addrs_t` structure containing the node's current addresses. The structure must be properly initialized and must not be null.
    - `ci_int`: A pointer to an `fd_gossip_node_contact_t` structure where the updated contact information will be stored. The structure must be properly initialized and must not be null.
- **Output**: None
- **See also**: [`fd_gossip_refresh_contact_info_v2_sockets`](#fd_gossip_refresh_contact_info_v2_sockets)  (Implementation)


---
### fd\_gossip\_push\_value\_nolock<!-- {{#callable_declaration:fd_gossip_push_value_nolock}} -->
Publishes a CRDS value for gossip propagation.
- **Description**: Use this function to publish a CRDS value into the gossip protocol, which will be signed and stored for later propagation. This function should be called when a new CRDS value needs to be disseminated across the network. It is important to ensure that the `data` parameter has a valid discriminant before calling this function. The function will handle duplicate detection and will not insert the value if it already exists. It is expected that the caller holds the necessary lock on the `glob` structure before invoking this function.
- **Inputs**:
    - `glob`: A pointer to an `fd_gossip_t` structure representing the global state of the gossip protocol. The caller must ensure this is a valid and initialized structure, and must hold the lock on it before calling this function.
    - `data`: A pointer to an `fd_crds_data_t` structure containing the CRDS data to be published. The discriminant must be valid and within the range of known CRDS enum values.
    - `key_opt`: An optional pointer to an `fd_hash_t` structure where the function will store the key of the published value if provided. Can be `NULL` if the key is not needed by the caller.
- **Output**: Returns 0 on success, or -1 if the value could not be published due to an invalid discriminant, table being full, or if the value is a duplicate.
- **See also**: [`fd_gossip_push_value_nolock`](#fd_gossip_push_value_nolock)  (Implementation)



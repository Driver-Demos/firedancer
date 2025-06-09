# Purpose
This C header file defines a set of constants, data structures, and type definitions that are likely used for handling various plugin messages within a distributed system, possibly related to blockchain or distributed ledger technology. The file provides a narrow but essential functionality by defining message types and structures that facilitate communication and data exchange between different components of the system. The constants defined at the beginning of the file represent different message types, such as slot updates, gossip updates, and vote account updates, which are crucial for maintaining the state and synchronization of the distributed system.

The file includes several packed and aligned structures, such as `fd_replay_complete_msg`, `fd_gossip_update_msg`, and `fd_vote_update_msg`, which are designed to efficiently store and transmit data related to slots, gossip updates, and vote updates, respectively. These structures are carefully defined to ensure memory alignment and efficient data handling, which is critical in high-performance distributed systems. The file also includes static assertions to verify the size of these structures, ensuring they meet expected constraints. Overall, this header file serves as a foundational component for defining the message protocol and data structures used in a plugin system, likely intended for integration with other parts of a larger software architecture.
# Data Structures

---
### fd\_plugin\_msg\_slot\_start\_t
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the current slot number in the message.
    - `parent_slot`: Indicates the parent slot number associated with the current slot.
- **Description**: The `fd_plugin_msg_slot_start_t` structure is used to represent the start of a slot in a plugin message system. It contains two members: `slot`, which holds the current slot number, and `parent_slot`, which holds the slot number of the parent slot. This structure is likely used to track and manage slot relationships and transitions within a distributed system or blockchain environment.


---
### fd\_plugin\_msg\_slot\_end\_t
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the message.
    - `cus_used`: Indicates the number of compute units used in the slot.
- **Description**: The `fd_plugin_msg_slot_end_t` structure is used to represent the end of a slot in a plugin message system. It contains information about the slot number and the compute units used, which can be useful for tracking resource usage and slot completion status in a distributed system.


---
### fd\_replay\_complete\_msg
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the replay completion message.
    - `total_txn_count`: Indicates the total number of transactions processed in the slot.
    - `nonvote_txn_count`: Counts the number of non-vote transactions processed in the slot.
    - `failed_txn_count`: Represents the number of transactions that failed during processing.
    - `nonvote_failed_txn_count`: Counts the number of non-vote transactions that failed.
    - `compute_units`: Specifies the total compute units used during the slot.
    - `transaction_fee`: Indicates the total transaction fees collected in the slot.
    - `priority_fee`: Represents the total priority fees collected in the slot.
    - `parent_slot`: Refers to the parent slot number of the current slot.
- **Description**: The `fd_replay_complete_msg` structure is a packed and aligned data structure used to encapsulate information about the completion of a replay process in a distributed system. It contains various fields that provide detailed metrics about the transactions processed in a specific slot, including counts of total, non-vote, and failed transactions, as well as compute units and fees associated with the transactions. This structure is crucial for tracking and analyzing the performance and outcomes of transaction processing in a distributed ledger or blockchain environment.


---
### fd\_replay\_complete\_msg\_t
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the replay completion message.
    - `total_txn_count`: Indicates the total number of transactions processed in the slot.
    - `nonvote_txn_count`: Specifies the number of non-vote transactions processed in the slot.
    - `failed_txn_count`: Denotes the number of transactions that failed during processing in the slot.
    - `nonvote_failed_txn_count`: Represents the number of non-vote transactions that failed during processing in the slot.
    - `compute_units`: Indicates the total compute units consumed during the slot.
    - `transaction_fee`: Specifies the total transaction fees collected during the slot.
    - `priority_fee`: Represents the total priority fees collected during the slot.
    - `parent_slot`: Indicates the parent slot number of the current slot.
- **Description**: The `fd_replay_complete_msg_t` structure is a packed and aligned data structure used to encapsulate information about the completion of a replay process for a specific slot in a distributed system. It includes various fields that provide detailed metrics about the transactions processed, including counts of total, non-vote, and failed transactions, as well as compute units and fees associated with the slot. This structure is crucial for tracking and analyzing the performance and outcomes of replay operations in the system.


---
### fd\_gossip\_update\_msg
- **Type**: `struct`
- **Members**:
    - `pubkey`: A 32-byte array representing the public key.
    - `wallclock`: An unsigned long integer representing the wallclock time.
    - `shred_version`: A 16-bit unsigned integer representing the shred version.
    - `version_type`: An 8-bit unsigned integer representing the version type.
    - `version_major`: A 16-bit unsigned integer representing the major version number.
    - `version_minor`: A 16-bit unsigned integer representing the minor version number.
    - `version_patch`: A 16-bit unsigned integer representing the patch version number.
    - `version_commit_type`: An 8-bit unsigned integer representing the version commit type.
    - `version_commit`: A 32-bit unsigned integer representing the version commit.
    - `version_feature_set`: A 32-bit unsigned integer representing the version feature set.
    - `addrs`: An array of 12 packed structures, each containing an IP address and port number.
- **Description**: The `fd_gossip_update_msg` structure is a packed data structure used to encapsulate information for a gossip update message in a distributed system. It includes a public key, wallclock time, versioning information (type, major, minor, patch, commit type, commit, and feature set), and an array of 12 address structures, each containing an IP address and port number. This structure is designed to be compact and efficient for network transmission, ensuring that all fields are tightly packed without padding.


---
### fd\_gossip\_update\_msg\_t
- **Type**: `struct`
- **Members**:
    - `pubkey`: A 32-byte array representing the public key.
    - `wallclock`: An unsigned long integer representing the wallclock time.
    - `shred_version`: A 16-bit unsigned short representing the shred version.
    - `version_type`: An 8-bit unsigned char representing the version type.
    - `version_major`: A 16-bit unsigned short representing the major version number.
    - `version_minor`: A 16-bit unsigned short representing the minor version number.
    - `version_patch`: A 16-bit unsigned short representing the patch version number.
    - `version_commit_type`: An 8-bit unsigned char representing the version commit type.
    - `version_commit`: A 32-bit unsigned integer representing the version commit.
    - `version_feature_set`: A 32-bit unsigned integer representing the version feature set.
    - `addrs`: An array of 12 structures, each containing an IP address and port.
- **Description**: The `fd_gossip_update_msg_t` structure is a packed data structure used to represent a gossip update message in a network. It includes a public key, wallclock time, shred version, and versioning information (type, major, minor, patch, commit type, commit, and feature set). Additionally, it contains an array of 12 address structures, each with an IP and port, which likely represent network endpoints for various services or protocols. This structure is designed to fit within a specific size constraint defined by `FD_GOSSIP_LINK_MSG_SIZE`.


---
### fd\_vote\_update\_msg
- **Type**: `struct`
- **Members**:
    - `vote_pubkey`: An array of 32 unsigned characters representing the public key of the vote.
    - `node_pubkey`: An array of 32 unsigned characters representing the public key of the node.
    - `activated_stake`: An unsigned long integer representing the activated stake.
    - `last_vote`: An unsigned long integer representing the last vote.
    - `root_slot`: An unsigned long integer representing the root slot.
    - `epoch_credits`: An unsigned long integer representing the epoch credits.
    - `commission`: An unsigned character representing the commission.
    - `is_delinquent`: An unsigned character indicating if the node is delinquent.
- **Description**: The `fd_vote_update_msg` structure is a packed data structure used to encapsulate information related to a vote update in a distributed system. It includes public keys for both the vote and the node, as well as various metrics such as activated stake, last vote, root slot, and epoch credits. Additionally, it contains fields for commission and delinquency status, making it a comprehensive representation of a vote update message.


---
### fd\_vote\_update\_msg\_t
- **Type**: `struct`
- **Members**:
    - `vote_pubkey`: A 32-byte array representing the public key of the vote account.
    - `node_pubkey`: A 32-byte array representing the public key of the node associated with the vote.
    - `activated_stake`: An unsigned long integer indicating the amount of stake activated for voting.
    - `last_vote`: An unsigned long integer representing the slot number of the last vote cast.
    - `root_slot`: An unsigned long integer indicating the root slot number for the vote account.
    - `epoch_credits`: An unsigned long integer representing the credits earned in the current epoch.
    - `commission`: A single byte indicating the commission rate for the vote account.
    - `is_delinquent`: A single byte flag indicating whether the vote account is delinquent.
- **Description**: The `fd_vote_update_msg_t` structure is a packed data structure used to encapsulate information about a vote update in a distributed system. It includes fields for the vote and node public keys, activated stake, last vote slot, root slot, epoch credits, commission rate, and a delinquency flag. This structure is designed to efficiently store and transmit vote-related data, ensuring alignment and packing for optimal performance in network communications.


---
### fd\_plugin\_msg\_block\_engine\_update\_t
- **Type**: `struct`
- **Members**:
    - `name`: A character array of size 16 to store the name of the block engine.
    - `url`: A character array of size 256 to store the URL associated with the block engine.
    - `ip_cstr`: A character array of size 40 to store the IP address in string format, supporting both IPv4 and IPv6.
    - `status`: An integer representing the connection status of the block engine, with predefined status codes.
- **Description**: The `fd_plugin_msg_block_engine_update_t` structure is designed to encapsulate information about a block engine's connection status within a plugin system. It includes fields for storing the block engine's name, URL, and IP address in string format, as well as an integer status code that indicates the current connection state, such as disconnected, connecting, or connected. This structure is likely used to manage and update the state of block engines in a distributed system.



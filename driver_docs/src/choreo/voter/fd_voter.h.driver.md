# Purpose
The provided C header file, `fd_voter.h`, defines structures and functions related to managing and querying the state of a voter within a choreographic system. This file is part of a larger system, as indicated by its inclusion of other headers like `fd_choreo_base.h` and `fd_funk_rec.h`. The primary focus of this file is to define the `fd_voter_t` structure, which encapsulates information about a voter, including their stake and cached votes. It also defines several structures (`fd_voter_vote_old_t`, `fd_voter_vote_t`, `fd_voter_meta_old_t`, `fd_voter_meta_t`, and `fd_voter_state_t`) that represent the serialized layout of a voter's state, supporting zero-copy reads from a vote account. These structures accommodate different versions of voter state serialization, ensuring compatibility with various system versions.

The file provides several inline functions to interact with the voter's state, such as [`fd_voter_state`](#fd_voter_state), [`fd_voter_state_cnt`](#fd_voter_state_cnt), [`fd_voter_state_vote`](#fd_voter_state_vote), and [`fd_voter_state_root`](#fd_voter_state_root). These functions facilitate querying the number of votes, retrieving the most recent vote, and obtaining the root of the voter's tower, respectively. The header also includes compile-time options for additional runtime checks and logging, controlled by the `FD_VOTER_USE_HANDHOLDING` macro. This file is intended to be included in other parts of the system, providing a public API for managing voter states in a choreographic context, and it ensures that the data structures and functions are used consistently across different components of the system.
# Imports and Dependencies

---
- `../fd_choreo_base.h`
- `../../funk/fd_funk_rec.h`


# Global Variables

---
### fd\_voter\_state
- **Type**: `fd_voter_state_t const *`
- **Description**: The `fd_voter_state` function returns a pointer to the start of a voter's state, which is represented by the `fd_voter_state_t` structure. This structure encapsulates the state of a voter, including metadata and a list of votes, and is used to support zero-copy reads of the vote account.
- **Use**: This function is used to query the voter's state from a record in the provided transaction and key, updating the Funk query with the version at the point of querying.


# Data Structures

---
### fd\_voter
- **Type**: `struct`
- **Members**:
    - `key`: A union member representing the vote account address.
    - `rec`: A union member representing the funk record key to query.
    - `hash`: A reserved field for use by fd_map_dynamic.c.
    - `stake`: Represents the voter's stake.
    - `replay_vote`: Cached read of the last tower vote via replay.
    - `gossip_vote`: Cached read of the last tower vote via gossip.
    - `rooted_vote`: Cached read of the last tower root via replay.
- **Description**: The `fd_voter` structure is designed to represent a voter in a flexible context, allowing for different stake values depending on the context, such as slot-level or epoch-level. It includes a union for either a vote account address or a funk record key, a reserved hash field, and several fields for tracking the voter's stake and cached votes. The structure is used in various choreo APIs, including fd_epoch, fd_forks, ghost, and tower, which require tracking and bookkeeping of epoch voters. The fields related to votes are intended to be modified only by specific components like fd_epoch and fd_ghost.


---
### fd\_voter\_t
- **Type**: `struct`
- **Members**:
    - `key`: A union member representing the vote account address as a public key.
    - `rec`: A union member representing the funk record key to query.
    - `hash`: A reserved field for use in dynamic mapping.
    - `stake`: The voter's stake value.
    - `replay_vote`: A cached read of the last tower vote via replay.
    - `gossip_vote`: A cached read of the last tower vote via gossip.
    - `rooted_vote`: A cached read of the last tower root via replay.
- **Description**: The `fd_voter_t` structure represents a voter in a generic context, which can vary depending on the level of the context, such as slot-level or epoch-level. It includes a union for identifying the voter either by a public key or a funk record key, and fields for storing the voter's stake and cached votes from different sources. This structure is used in various choreo APIs to manage and track voters across different contexts and epochs.


---
### fd\_voter\_vote\_old
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the vote.
    - `conf`: Indicates the confidence level of the vote.
- **Description**: The `fd_voter_vote_old` structure is a packed data structure used to represent an old version of a voter's vote in a serialized format. It contains two fields: `slot`, which is an unsigned long integer representing the slot number associated with the vote, and `conf`, which is an unsigned integer indicating the confidence level of the vote. This structure is part of a versioned system for handling voter state data, specifically for the version v0.23.5, and is used to support zero-copy reads of serialized vote account data.


---
### fd\_voter\_vote\_old\_t
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the vote.
    - `conf`: Indicates the confirmation count for the vote.
- **Description**: The `fd_voter_vote_old_t` structure is a compact representation of a voter's vote in a specific slot, primarily used in older versions of the voter's state serialization. It contains two fields: `slot`, which identifies the specific slot number the vote pertains to, and `conf`, which denotes the number of confirmations the vote has received. This structure is part of a larger system that manages and tracks voter states and their associated votes, particularly in the context of blockchain or distributed ledger systems.


---
### fd\_voter\_vote
- **Type**: `struct`
- **Members**:
    - `latency`: Represents the latency of the vote.
    - `slot`: Indicates the slot number associated with the vote.
    - `conf`: Represents the confirmation count of the vote.
- **Description**: The `fd_voter_vote` structure is a packed data structure used to represent a vote in a voting system. It contains three fields: `latency`, which captures the latency of the vote; `slot`, which identifies the specific slot number the vote is associated with; and `conf`, which indicates the confirmation count of the vote. This structure is part of a larger system that manages voting states and is used to support zero-copy reads of vote accounts.


---
### fd\_voter\_vote\_t
- **Type**: `struct`
- **Members**:
    - `latency`: An unsigned character representing the latency of the vote.
    - `slot`: An unsigned long integer representing the slot number of the vote.
    - `conf`: An unsigned integer representing the confirmation status of the vote.
- **Description**: The `fd_voter_vote_t` structure is a packed data structure used to represent a vote in the context of a voter's state. It includes fields for latency, slot, and confirmation status, which are essential for tracking the details of a vote within a voter's tower. This structure is part of a versioned system where different versions of the voter's state may use different vote structures, and it is specifically used in the current version of the voter's state representation.


---
### fd\_voter\_meta\_old
- **Type**: `struct`
- **Members**:
    - `node_pubkey`: The public key of the node associated with the voter.
    - `authorized_voter`: The public key of the voter authorized to vote.
    - `authorized_voter_epoch`: The epoch during which the authorized voter is valid.
    - `prior_voters`: An array storing serialized information about prior voters.
    - `authorized_withdrawer`: The public key of the entity authorized to withdraw funds.
    - `commission`: The commission rate associated with the voter.
    - `cnt`: The count of votes in the voter's tower.
- **Description**: The `fd_voter_meta_old` structure is a packed data structure used to represent metadata about a voter in a serialized format. It includes information about the node's public key, the authorized voter and their epoch, prior voters, the authorized withdrawer, the commission rate, and the count of votes. This structure is part of a versioned system for managing voter state, specifically tailored for older versions of the voter's metadata layout.


---
### fd\_voter\_meta\_old\_t
- **Type**: `struct`
- **Members**:
    - `node_pubkey`: The public key of the node associated with the voter.
    - `authorized_voter`: The public key of the entity authorized to vote on behalf of the node.
    - `authorized_voter_epoch`: The epoch during which the authorized voter is valid.
    - `prior_voters`: Serialized array storing information about prior voters.
    - `authorized_withdrawer`: The public key of the entity authorized to withdraw funds.
    - `commission`: The commission rate for the voter.
    - `cnt`: The count of votes in the voter's tower.
- **Description**: The `fd_voter_meta_old_t` structure is a packed data structure that holds metadata about a voter in a blockchain voting system. It includes fields for the node's public key, the authorized voter's public key and epoch, a serialized array of prior voters, the authorized withdrawer's public key, the commission rate, and the count of votes. This structure is used to represent the serialized layout of a voter's state in older versions of the system, specifically version 0.23.5, and supports zero-copy reads of the vote account.


---
### fd\_voter\_meta
- **Type**: `struct`
- **Members**:
    - `node_pubkey`: The public key of the node associated with the voter.
    - `authorized_withdrawer`: The public key of the entity authorized to withdraw funds.
    - `commission`: The commission rate associated with the voter.
    - `cnt`: The count of votes currently in the voter's tower.
- **Description**: The `fd_voter_meta` structure is a compact representation of metadata associated with a voter in a voting system. It includes the node's public key, the public key of the authorized withdrawer, the commission rate, and the count of votes in the voter's tower. This structure is used to facilitate zero-copy reads of a voter's state from a vote account, allowing efficient access to the voter's metadata without the need for additional data processing.


---
### fd\_voter\_meta\_t
- **Type**: `struct`
- **Members**:
    - `node_pubkey`: The public key of the node associated with the voter.
    - `authorized_withdrawer`: The public key of the entity authorized to withdraw from the vote account.
    - `commission`: The commission rate applied to the voter's rewards.
    - `cnt`: The count of votes in the voter's tower.
- **Description**: The `fd_voter_meta_t` structure is a compact representation of metadata associated with a voter in a voting system. It includes essential information such as the node's public key, the authorized withdrawer's public key, the commission rate, and the count of votes. This structure is used to facilitate zero-copy reads of the vote account, allowing efficient access to the voter's metadata without the need for additional data copying.


---
### fd\_voter\_state
- **Type**: `struct`
- **Members**:
    - `discriminant`: A uint that determines which version of the voter state is being used.
    - `v0_23_5`: A struct containing metadata and an array of old vote structures for version 0.23.5.
    - `v1_14_11`: A struct containing metadata and an array of old vote structures for version 1.14.11.
    - ``: A struct containing metadata and an array of current vote structures.
- **Description**: The `fd_voter_state` structure is a packed data structure that represents the state of a voter, with support for multiple versions of the voter's state. It uses a discriminant to determine which version of the state is active, allowing for different metadata and vote structures to be used depending on the version. The structure includes metadata and an array of votes, with the voter's root following the votes. This design allows for zero-copy reads of the vote account, accommodating different serialized formats for different versions.


---
### fd\_voter\_state\_t
- **Type**: `struct`
- **Members**:
    - `discriminant`: A uint field used to determine the version of the voter's state.
    - `v0_23_5`: A union member containing metadata and votes for version 0.23.5.
    - `v1_14_11`: A union member containing metadata and votes for version 1.14.11.
    - `meta`: A struct containing metadata for the current version of the voter's state.
    - `votes`: An array of vote structures for the current version of the voter's state.
- **Description**: The `fd_voter_state_t` structure represents the state of a voter, encapsulating metadata and vote information in a versioned format. It includes a discriminant to identify the version of the state, and a union that holds different structures for each version, such as `v0_23_5` and `v1_14_11`, each containing metadata and an array of votes. The structure is designed to support zero-copy reads of serialized vote account data, with the layout varying based on the version, and it includes mechanisms to handle the voter's root slot, which is serialized separately due to its variable-length nature.


# Functions

---
### fd\_voter\_state\_cnt<!-- {{#callable:fd_voter_state_cnt}} -->
The `fd_voter_state_cnt` function returns the number of votes in a voter's tower based on the version of the voter's state.
- **Inputs**:
    - `state`: A pointer to a constant `fd_voter_state_t` structure representing the voter's state.
- **Control Flow**:
    - Check if the `discriminant` of the `state` is `FD_VOTER_STATE_V0_23_5`; if true, return the `cnt` from `v0_23_5.meta`.
    - Check if the `discriminant` of the `state` is `FD_VOTER_STATE_V1_14_11`; if true, return the `cnt` from `v1_14_11.meta`.
    - If neither condition is met, return the `cnt` from `meta` of the current state.
- **Output**: The function returns an `ulong` representing the number of votes in the voter's tower.


---
### fd\_voter\_state\_vote<!-- {{#callable:fd_voter_state_vote}} -->
The `fd_voter_state_vote` function retrieves the most recent vote slot from a voter's state, considering different state versions.
- **Inputs**:
    - `state`: A pointer to a `fd_voter_state_t` structure representing the voter's state, which includes metadata and votes.
- **Control Flow**:
    - Call [`fd_voter_state_cnt`](#fd_voter_state_cnt) to get the number of votes in the voter's state.
    - Check if the vote count is zero; if so, return `FD_SLOT_NULL`.
    - Check if the state's discriminant is `FD_VOTER_STATE_V0_23_5`; if true, return the slot of the last vote in `v0_23_5` version.
    - Check if the state's discriminant is `FD_VOTER_STATE_V1_14_11`; if true, return the slot of the last vote in `v1_14_11` version.
    - If none of the above conditions are met, return the slot of the last vote in the current version.
- **Output**: The function returns the slot of the most recent vote as an `ulong`, or `FD_SLOT_NULL` if there are no votes.
- **Functions called**:
    - [`fd_voter_state_cnt`](#fd_voter_state_cnt)


---
### fd\_voter\_state\_root<!-- {{#callable:fd_voter_state_root}} -->
The `fd_voter_state_root` function retrieves the root slot of a voter's tower from a given voter state.
- **Inputs**:
    - `state`: A pointer to a constant `fd_voter_state_t` structure representing the voter's state.
- **Control Flow**:
    - The function begins by calling [`fd_voter_state_cnt`](#fd_voter_state_cnt) to get the number of votes (`cnt`) in the voter's tower.
    - If `cnt` is zero, the function returns `FD_SLOT_NULL`, indicating no root slot is available.
    - Depending on the `discriminant` value of the `state`, the function sets the `root` pointer to the appropriate location in the `votes` array, just after the last vote.
    - If `FD_VOTER_USE_HANDHOLDING` is enabled, the function checks the validity of the `root` pointer using `FD_TEST`.
    - The function checks if the byte at the `root` location is non-zero, indicating the presence of a root slot.
    - If a root slot is present, it returns the `ulong` value located just after the `uchar` at `root`; otherwise, it returns `FD_SLOT_NULL`.
- **Output**: The function returns an `ulong` representing the root slot of the voter's tower, or `FD_SLOT_NULL` if no root slot is present.
- **Functions called**:
    - [`fd_voter_state_cnt`](#fd_voter_state_cnt)



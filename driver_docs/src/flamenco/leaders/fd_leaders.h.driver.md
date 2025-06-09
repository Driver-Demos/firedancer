# Purpose
The provided C header file, `fd_leaders.h`, defines a set of APIs and data structures for managing the leader schedule in the Solana blockchain network. This file is specifically designed to handle the assignment of leaders to slots within an epoch, a fundamental aspect of Solana's consensus mechanism. The leader schedule determines which node (identified by a public key) is responsible for producing a block for each slot. The file includes definitions for managing the leader schedule, such as the `fd_epoch_leaders_t` structure, which encapsulates the schedule for a given epoch, including the public keys of the leaders and the sequence of their assignments.

The header file provides several macros and functions to facilitate the creation, management, and querying of leader schedules. Key functionalities include calculating the memory footprint and alignment requirements for leader schedule objects, initializing new leader schedules, and accessing the leader for a specific slot. The file also addresses potential network attacks by allowing for the exclusion of certain stakes from the leader schedule. This header is intended to be included in other C source files, providing a public API for interacting with Solana's leader schedule, and is compatible with the Solana mainnet as of July 2023.
# Imports and Dependencies

---
- `../fd_flamenco_base.h`
- `../types/fd_types.h`
- `../../ballet/wsample/fd_wsample.h`


# Global Variables

---
### fd\_epoch\_leaders\_new
- **Type**: `function`
- **Description**: The `fd_epoch_leaders_new` function is responsible for formatting a memory region to be used as a leader schedule object for a specific Solana epoch. It initializes the leader schedule for the given epoch, which spans a range of slots, and sets up the necessary data structures to manage the schedule, including a lookup table for node public keys and a schedule of leaders for each slot.
- **Use**: This function is used to initialize and set up a leader schedule object in shared memory for a specified epoch in the Solana network.


---
### fd\_epoch\_leaders\_join
- **Type**: `fd_epoch_leaders_t *`
- **Description**: The `fd_epoch_leaders_join` is a function that returns a pointer to an `fd_epoch_leaders_t` structure. This structure contains the leader schedule for a Solana epoch, including details such as the epoch number, starting slot, number of slots, a lookup table for node public keys, and the leader schedule itself.
- **Use**: This function is used to join the caller to the leader schedule object, allowing access to the leader schedule data for a specific epoch.


---
### fd\_epoch\_leaders\_leave
- **Type**: `function pointer`
- **Description**: `fd_epoch_leaders_leave` is a function that undoes an existing join to a leader schedule object, effectively leaving the leader schedule context. It takes a pointer to an `fd_epoch_leaders_t` structure as its parameter, which represents the leader schedule of a Solana epoch.
- **Use**: This function is used to disassociate or leave a previously joined leader schedule object, cleaning up any resources or state associated with the join.


---
### fd\_epoch\_leaders\_delete
- **Type**: `function pointer`
- **Description**: The `fd_epoch_leaders_delete` is a function that takes a pointer to a memory region (`shleaders`) and unformats it, effectively cleaning up the leader schedule object and returning ownership of the memory back to the caller. This function is part of the API for managing the lifecycle of a leader schedule object in the context of Solana's epoch leader schedule management.
- **Use**: This function is used to delete or unformat a leader schedule object, freeing up the associated memory for reuse or deallocation.


# Data Structures

---
### fd\_epoch\_leaders
- **Type**: `struct`
- **Members**:
    - `epoch`: Represents the epoch number for which the leader schedule is defined.
    - `slot0`: Indicates the starting slot number of the epoch.
    - `slot_cnt`: Specifies the total number of slots in the epoch.
    - `pub`: A pointer to an array of public keys representing node identities.
    - `pub_cnt`: The number of unique public keys in the lookup table.
    - `sched`: A pointer to an array of indexes into the pub array, representing the leader schedule.
    - `sched_cnt`: The number of entries in the sched array, indicating the number of rotations in the schedule.
- **Description**: The `fd_epoch_leaders` structure is designed to manage the leader schedule for a specific epoch in the Solana blockchain. It includes information about the epoch's starting slot and total slot count, as well as a lookup table of node public keys and a schedule that maps slots to leaders using indexes into this table. This structure is crucial for determining which node is responsible for producing a block at any given slot within the epoch, ensuring the orderly progression of the blockchain.


---
### fd\_epoch\_leaders\_t
- **Type**: `struct`
- **Members**:
    - `epoch`: The epoch number for which the leader schedule is defined.
    - `slot0`: The starting slot number of the epoch.
    - `slot_cnt`: The total number of slots in the epoch.
    - `pub`: A pointer to an array of public keys representing node identities.
    - `pub_cnt`: The number of unique public keys in the lookup table.
    - `sched`: An array of indexes into the pub array representing the leader schedule.
    - `sched_cnt`: The number of rotations in the leader schedule.
- **Description**: The `fd_epoch_leaders_t` structure is designed to encapsulate the leader schedule for a Solana epoch, which is a sequence of slots each assigned to a leader identified by a public key. The structure includes information about the epoch, the range of slots it covers, and a lookup table of public keys. The leader schedule is stored as indexes into this lookup table, allowing efficient storage and retrieval of leader information for each slot. This structure is crucial for managing and accessing the leader schedule in a memory-efficient manner, especially given the large number of slots in a Solana epoch.


# Functions

---
### fd\_epoch\_leaders\_get<!-- {{#callable:fd_epoch_leaders_get}} -->
The `fd_epoch_leaders_get` function retrieves the public key of the leader for a specified slot within an epoch's leader schedule.
- **Inputs**:
    - `leaders`: A pointer to an `fd_epoch_leaders_t` structure containing the leader schedule for an epoch.
    - `slot`: An unsigned long integer representing the slot number for which the leader's public key is requested.
- **Control Flow**:
    - Calculate `slot_delta` as the difference between the given `slot` and `leaders->slot0`.
    - Check if the `slot` is less than `leaders->slot0`; if true, return `NULL`.
    - Check if `slot_delta` is greater than or equal to `leaders->slot_cnt`; if true, return `NULL`.
    - Calculate the index in the `sched` array using `slot_delta / FD_EPOCH_SLOTS_PER_ROTATION`.
    - Return the public key from the `pub` array at the index specified by the `sched` array.
- **Output**: A pointer to the `fd_pubkey_t` representing the leader's public key for the specified slot, or `NULL` if the slot is out of range.


# Function Declarations (Public API)

---
### fd\_epoch\_leaders\_align<!-- {{#callable_declaration:fd_epoch_leaders_align}} -->
Return the alignment requirement for a leader schedule object.
- **Description**: Use this function to obtain the alignment requirement for a leader schedule object in the Solana leader schedule API. This is necessary when allocating memory for a leader schedule object to ensure proper alignment. The function is a constant expression and can be used at compile time to determine the alignment requirement.
- **Inputs**: None
- **Output**: The function returns an unsigned long integer representing the alignment requirement in bytes.
- **See also**: [`fd_epoch_leaders_align`](fd_leaders.c.driver.md#fd_epoch_leaders_align)  (Implementation)


---
### fd\_epoch\_leaders\_footprint<!-- {{#callable_declaration:fd_epoch_leaders_footprint}} -->
Calculate the memory footprint required for a leader schedule object.
- **Description**: Use this function to determine the memory footprint needed for a leader schedule object based on the number of unique public keys and the number of slots in an epoch. This is essential for allocating sufficient memory before creating a leader schedule. The function returns zero if either the number of public keys or slots is zero, or if the number of public keys exceeds a certain limit, indicating invalid input.
- **Inputs**:
    - `pub_cnt`: The number of unique public keys in the leader schedule. Must be greater than 0 and less than or equal to UINT_MAX-3. If invalid, the function returns 0.
    - `slot_cnt`: The number of slots in the epoch. Must be greater than 0. If invalid, the function returns 0.
- **Output**: Returns the memory footprint in bytes required for the leader schedule object, or 0 if the input parameters are invalid.
- **See also**: [`fd_epoch_leaders_footprint`](fd_leaders.c.driver.md#fd_epoch_leaders_footprint)  (Implementation)


---
### fd\_epoch\_leaders\_new<!-- {{#callable_declaration:fd_epoch_leaders_new}} -->
Formats a memory region for use as a leader schedule object.
- **Description**: This function initializes a memory region to be used as a leader schedule object for a specified epoch in a Solana network. It requires a memory region with specific alignment and footprint, and it sets up the leader schedule for the given epoch, which spans a range of slots starting from `slot0`. The function requires a list of stake weights, sorted by stake and public key, and an optional excluded stake value for handling cases where not all staked nodes are included. The caller must ensure the memory region is properly aligned and has sufficient size before calling this function. The function does not retain any interest in the `stakes` array after it returns, and the caller is not joined to the object upon return.
- **Inputs**:
    - `shmem`: A pointer to the first byte of a memory region that must be aligned to `FD_EPOCH_LEADERS_ALIGN` and have a footprint of at least `FD_EPOCH_LEADERS_FOOTPRINT(pub_cnt, slot_cnt)`. Must not be null.
    - `epoch`: The epoch number for which the leader schedule is being created.
    - `slot0`: The first slot in the epoch. Must be the starting slot of the epoch.
    - `slot_cnt`: The number of slots in the epoch. Can be less than the full epoch length to derive only a portion of the leader schedule.
    - `pub_cnt`: The number of unique public keys in the schedule. Determines the size of the public key lookup table.
    - `stakes`: A pointer to an array of `fd_stake_weight_t` structures, containing `pub_cnt` entries sorted by (stake, pubkey) in descending order. Must not be null.
    - `excluded_stake`: The sum of the stake weights of nodes not included in the `stakes` array, measured in lamports. Used to handle cases where not all staked nodes are included.
- **Output**: Returns a pointer to the formatted memory region if successful, or NULL if the input memory region is null or misaligned.
- **See also**: [`fd_epoch_leaders_new`](fd_leaders.c.driver.md#fd_epoch_leaders_new)  (Implementation)


---
### fd\_epoch\_leaders\_join<!-- {{#callable_declaration:fd_epoch_leaders_join}} -->
Joins the caller to the leader schedule object.
- **Description**: This function is used to join the caller to an existing leader schedule object, which is represented by the provided shared memory pointer. It is typically called after the leader schedule object has been created and initialized using `fd_epoch_leaders_new`. The function returns a pointer to the `fd_epoch_leaders_t` structure, allowing the caller to interact with the leader schedule. The caller must ensure that the `shleaders` pointer is valid and points to a properly formatted leader schedule object.
- **Inputs**:
    - `shleaders`: A pointer to the shared memory region representing the leader schedule object. It must be a valid pointer to a properly formatted leader schedule object. The caller retains ownership of the memory.
- **Output**: Returns a pointer to the `fd_epoch_leaders_t` structure representing the leader schedule object.
- **See also**: [`fd_epoch_leaders_join`](fd_leaders.c.driver.md#fd_epoch_leaders_join)  (Implementation)


---
### fd\_epoch\_leaders\_leave<!-- {{#callable_declaration:fd_epoch_leaders_leave}} -->
Leaves the leader schedule object.
- **Description**: Use this function to leave a previously joined leader schedule object, effectively undoing the join operation. This function should be called when the caller no longer needs to interact with the leader schedule object, ensuring proper resource management. It is important to ensure that the `leaders` parameter is a valid pointer to a leader schedule object that the caller has joined.
- **Inputs**:
    - `leaders`: A pointer to a `fd_epoch_leaders_t` object that the caller has previously joined. Must not be null. The function will return this pointer cast to a void pointer.
- **Output**: Returns the `leaders` pointer cast to a void pointer.
- **See also**: [`fd_epoch_leaders_leave`](fd_leaders.c.driver.md#fd_epoch_leaders_leave)  (Implementation)


---
### fd\_epoch\_leaders\_delete<!-- {{#callable_declaration:fd_epoch_leaders_delete}} -->
Unformats a memory region and returns ownership back to the caller.
- **Description**: Use this function to release a leader schedule object that was previously formatted with fd_epoch_leaders_new. This function should be called when the leader schedule object is no longer needed, allowing the caller to reclaim the memory for other uses. It is important to ensure that no other operations are performed on the leader schedule object after calling this function, as it effectively invalidates the object.
- **Inputs**:
    - `shleaders`: A pointer to the leader schedule object to be deleted. The pointer must not be null and should point to a valid leader schedule object previously created with fd_epoch_leaders_new. The function will return this pointer back to the caller.
- **Output**: Returns the same pointer passed as input, allowing the caller to reclaim ownership of the memory.
- **See also**: [`fd_epoch_leaders_delete`](fd_leaders.c.driver.md#fd_epoch_leaders_delete)  (Implementation)



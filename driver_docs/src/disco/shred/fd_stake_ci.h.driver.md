# Purpose
The provided C header file, `fd_stake_ci.h`, is designed to manage the complexities associated with leader schedules and shred destinations in a blockchain context, specifically dealing with epoch-specific data. This file is part of a larger system, likely related to a blockchain or distributed ledger technology, where it handles the intricacies of stake delegation changes and their effects on leader schedules and shred destinations across different epochs. The file defines a set of data structures and functions that abstract the complexity of these operations, allowing other parts of the system to interact with leader schedules and shred destinations without needing to manage the underlying details.

Key components of this file include the `fd_stake_ci_t` structure, which encapsulates information about stake weights and shred destinations, and functions like [`fd_stake_ci_new`](#fd_stake_ci_new), [`fd_stake_ci_join`](#fd_stake_ci_join), and [`fd_stake_ci_delete`](#fd_stake_ci_delete), which manage the lifecycle of these structures. The file also provides functions for initializing and finalizing stake messages and destination additions, which are crucial for updating the system with new stake weights and contact information. Additionally, the file includes query functions to retrieve leader schedules and shred destinations for specific slots, ensuring that the correct data is used for each epoch. This header file is integral to maintaining the integrity and efficiency of the system's operation across epoch boundaries, ensuring that changes in stake delegation are accurately reflected in the leader schedules and shred destinations.
# Imports and Dependencies

---
- `fd_shred_dest.h`
- `../../flamenco/leaders/fd_leaders.h`


# Global Variables

---
### fd\_stake\_ci\_new
- **Type**: `function pointer`
- **Description**: The `fd_stake_ci_new` function is a global function pointer that initializes a memory region to be used as a stake contact information store. It takes a memory pointer and a constant pointer to an identity key as parameters.
- **Use**: This function is used to format a given memory region to store stake contact information, associating it with a specific identity key for the local validator.


---
### fd\_stake\_ci\_join
- **Type**: `fd_stake_ci_t *`
- **Description**: The `fd_stake_ci_join` function returns a pointer to an `fd_stake_ci_t` structure, which is used to manage stake contact information in a distributed system. This structure handles the complexities of leader schedules and shred destinations across different epochs, ensuring that changes in stake delegation are correctly applied over time.
- **Use**: This function is used to join a memory region as an `fd_stake_ci_t` structure, allowing the system to manage stake-related data efficiently.


---
### fd\_stake\_ci\_leave
- **Type**: `function pointer`
- **Description**: The `fd_stake_ci_leave` is a function pointer that takes a pointer to an `fd_stake_ci_t` structure as its argument and returns a void pointer. This function is likely used to handle the process of leaving or detaching from a stake contact information context, possibly cleaning up or finalizing any resources associated with the `fd_stake_ci_t` instance.
- **Use**: This function is used to manage the lifecycle of a stake contact information context by detaching or cleaning up resources associated with an `fd_stake_ci_t` instance.


---
### fd\_stake\_ci\_delete
- **Type**: `function pointer`
- **Description**: The `fd_stake_ci_delete` is a function pointer that takes a single argument, a void pointer `mem`, and returns a void pointer. It is part of the `fd_stake_ci` module, which manages stake contact information, including leader schedules and shred destinations, across different epochs.
- **Use**: This function is used to delete or clean up a memory region that was previously formatted as a stake contact information store.


---
### fd\_stake\_ci\_dest\_add\_init
- **Type**: `fd_shred_dest_weighted_t *`
- **Description**: The `fd_stake_ci_dest_add_init` function returns a pointer to the first element of an array of `fd_shred_dest_weighted_t` structures. This array is used to store potential shred destination updates, which are augmented with additional information such as MAC addresses.
- **Use**: This variable is used to initialize and prepare an array for storing updated contact information for potential shred destinations, which is then finalized with `fd_stake_ci_dest_add_fini`.


---
### fd\_stake\_ci\_get\_sdest\_for\_slot
- **Type**: `function`
- **Description**: The `fd_stake_ci_get_sdest_for_slot` function is a global function that returns a pointer to an `fd_shred_dest_t` structure. This structure contains information about the shred destination for a specified slot, if such information is available. The function is part of the `fd_stake_ci` module, which manages leader schedules and shred destinations across epochs.
- **Use**: This function is used to query the shred destination information for a specific slot within the `fd_stake_ci` system.


---
### fd\_stake\_ci\_get\_lsched\_for\_slot
- **Type**: `fd_epoch_leaders_t *`
- **Description**: The `fd_stake_ci_get_lsched_for_slot` is a function that returns a pointer to an `fd_epoch_leaders_t` structure, which contains information about the leader schedule for a specific slot. This function is part of the `fd_stake_ci` module, which manages leader schedules and shred destinations in a blockchain context, specifically handling the complexities around epoch boundaries.
- **Use**: This function is used to query and retrieve the leader schedule for a given slot, providing necessary information for determining the leader node responsible for that slot.


# Data Structures

---
### fd\_per\_epoch\_info\_private
- **Type**: `struct`
- **Members**:
    - `epoch`: Represents the epoch for which the leader schedule and shred destination are valid.
    - `start_slot`: Indicates the starting slot of the time period for which the data is valid.
    - `slot_cnt`: Specifies the number of slots for which the data is valid, starting from start_slot.
    - `excluded_stake`: Represents the stake that is excluded from the calculations.
    - `lsched`: Pointer to the leader schedule data structure for the epoch.
    - `sdest`: Pointer to the shred destination data structure for the epoch.
    - `_lsched`: Memory footprint for the leader schedule, aligned to FD_EPOCH_LEADERS_ALIGN.
    - `_sdest`: Memory footprint for the shred destination, aligned to FD_SHRED_DEST_ALIGN.
- **Description**: The `fd_per_epoch_info_private` structure is designed to manage and store information specific to a particular epoch, including leader schedules and shred destinations. It contains fields to define the epoch, the range of slots it covers, and the stake excluded from calculations. The structure also includes pointers to leader schedule and shred destination data, with memory allocated and aligned for these components. This structure is crucial for handling epoch-specific data, ensuring that the correct leader and shred destination information is available for any given slot within the defined range.


---
### fd\_per\_epoch\_info\_t
- **Type**: `struct`
- **Members**:
    - `epoch`: Represents the epoch number for which the leader schedule and shred destinations are valid.
    - `start_slot`: Indicates the starting slot number of the epoch.
    - `slot_cnt`: Specifies the number of slots in the epoch.
    - `excluded_stake`: Holds the amount of stake that is excluded from the epoch.
    - `lsched`: Pointer to the leader schedule data for the epoch.
    - `sdest`: Pointer to the shred destination data for the epoch.
    - `_lsched`: Memory buffer aligned for leader schedule data storage.
    - `_sdest`: Memory buffer aligned for shred destination data storage.
- **Description**: The `fd_per_epoch_info_t` structure is designed to encapsulate information specific to a particular epoch, including the epoch number, the range of slots it covers, and the associated leader schedule and shred destination data. It includes pointers to the leader schedule (`lsched`) and shred destination (`sdest`) structures, which are used to determine the leader and compute shred destinations for slots within the epoch. The structure also contains aligned memory buffers (`_lsched` and `_sdest`) to store the data for these pointers, ensuring efficient memory usage and access. This structure is crucial for managing epoch-specific data in systems that require precise tracking of leader schedules and shred destinations, such as blockchain or distributed ledger technologies.


---
### fd\_stake\_ci
- **Type**: `struct`
- **Members**:
    - `identity_key`: An array containing a single public key used to identify the local validator.
    - `scratch`: A temporary storage structure used during stake message and destination addition operations.
    - `stake_weight`: An array storing the stake weights for each potential shred destination.
    - `shred_dest`: An array storing the weighted shred destinations.
    - `shred_dest_temp`: A temporary array for storing weighted shred destinations during updates.
    - `epoch_info`: An array storing information about the current and previous epochs.
- **Description**: The `fd_stake_ci` structure is designed to manage leader schedules and shred destinations, which are specific to epochs in a distributed system. It handles the complexities of stake delegation changes and their effects on leader schedules and shred destinations across epoch boundaries. The structure includes fields for storing identity keys, temporary data for stake messages and destination updates, and arrays for stake weights and shred destinations. It also maintains epoch-specific information to facilitate queries about leader schedules and shred destinations for specific slots.


---
### fd\_stake\_ci\_t
- **Type**: `struct`
- **Members**:
    - `identity_key`: An array containing the public key of the identity keypair of the local validator.
    - `scratch`: A temporary storage structure used between stake_msg_init and stake_msg_fini, and between dest_add_init and dest_add_fini.
    - `stake_weight`: An array holding the stake weights for each shred destination.
    - `shred_dest`: An array holding the weighted shred destinations.
    - `shred_dest_temp`: A temporary array for holding weighted shred destinations.
    - `epoch_info`: An array of structures holding information about leader schedules and shred destinations for two epochs.
- **Description**: The `fd_stake_ci_t` structure is designed to manage the complexities of leader schedules and shred destinations in a blockchain environment, specifically around epoch boundaries. It includes fields for storing the identity key of the local validator, temporary storage for stake and destination updates, and arrays for managing stake weights and shred destinations. The structure also maintains information for two epochs to handle transitions and queries efficiently. This data structure is crucial for ensuring that stake delegation changes are correctly applied across epochs without requiring manual adjustments by the caller.


# Functions

---
### fd\_stake\_ci\_footprint<!-- {{#callable:fd_stake_ci_footprint}} -->
The `fd_stake_ci_footprint` function returns the memory footprint size required for an `fd_stake_ci_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests the compiler to replace the function call with the function code itself to reduce function call overhead.
    - The function uses the `sizeof` operator to determine the size of the `fd_stake_ci_t` structure.
    - The function returns this size as an unsigned long integer.
- **Output**: The function returns an unsigned long integer representing the size in bytes of the `fd_stake_ci_t` structure.


---
### fd\_stake\_ci\_align<!-- {{#callable:fd_stake_ci_align}} -->
The `fd_stake_ci_align` function returns the alignment requirement for the `fd_stake_ci_t` data structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests the compiler to embed the function code at the call site for performance.
    - The function uses the `alignof` operator to determine the alignment requirement of the `fd_stake_ci_t` type.
    - The function returns the result of the `alignof` operator, which is the alignment requirement.
- **Output**: The function returns an `ulong` representing the alignment requirement of the `fd_stake_ci_t` type.


# Function Declarations (Public API)

---
### fd\_stake\_ci\_new<!-- {{#callable_declaration:fd_stake_ci_new}} -->
Formats a memory region as a stake contact information store.
- **Description**: This function initializes a given memory region to be used as a stake contact information store, which is essential for managing leader schedules and shred destinations across epochs. It should be called when setting up a new stake contact information structure, using a memory region that meets the required footprint and alignment. The function requires an identity key, which is used to determine the local validator's position in the network. The identity key is not retained after the function returns, so the caller does not need to maintain it beyond the call.
- **Inputs**:
    - `mem`: A pointer to a memory region that will be formatted as a stake contact information store. The memory must be properly aligned and have sufficient size as determined by fd_stake_ci_footprint() and fd_stake_ci_align(). The caller retains ownership of this memory.
    - `identity_key`: A pointer to a constant fd_pubkey_t structure representing the public key of the local validator's identity keypair. This key is used during initialization but is not retained after the function returns. Must not be null.
- **Output**: Returns a pointer to the initialized memory region, now formatted as a stake contact information store.
- **See also**: [`fd_stake_ci_new`](fd_stake_ci.c.driver.md#fd_stake_ci_new)  (Implementation)


---
### fd\_stake\_ci\_join<!-- {{#callable_declaration:fd_stake_ci_join}} -->
Casts a memory region to a stake contact information structure.
- **Description**: Use this function to interpret a pre-allocated memory region as a `fd_stake_ci_t` structure. This is typically done after the memory has been formatted using `fd_stake_ci_new`. The function does not perform any validation on the memory region, so it is the caller's responsibility to ensure that the memory is correctly aligned and sized according to the requirements of `fd_stake_ci_t`. This function is useful when you need to access the stake contact information stored in a specific memory location.
- **Inputs**:
    - `mem`: A pointer to a memory region that should be interpreted as a `fd_stake_ci_t` structure. The memory must be properly aligned and sized for `fd_stake_ci_t`. The caller retains ownership of the memory, and the function does not check for null pointers or validate the memory content.
- **Output**: Returns a pointer to the `fd_stake_ci_t` structure located at the specified memory region.
- **See also**: [`fd_stake_ci_join`](fd_stake_ci.c.driver.md#fd_stake_ci_join)  (Implementation)


---
### fd\_stake\_ci\_leave<!-- {{#callable_declaration:fd_stake_ci_leave}} -->
Releases resources associated with a stake contact information object.
- **Description**: Use this function to release resources associated with a stake contact information object when it is no longer needed. This function should be called after you have finished using the stake contact information object to ensure proper cleanup. It is important to note that this function does not free the memory associated with the object; it merely prepares it for safe deletion or reuse. Ensure that the `info` parameter is a valid pointer to an `fd_stake_ci_t` object before calling this function.
- **Inputs**:
    - `info`: A pointer to an `fd_stake_ci_t` object. This parameter must not be null and should point to a valid stake contact information object. The function does not perform any validation on this pointer, so passing an invalid pointer may result in undefined behavior.
- **Output**: Returns a void pointer to the `info` parameter, allowing for potential chaining or further operations on the same memory location.
- **See also**: [`fd_stake_ci_leave`](fd_stake_ci.c.driver.md#fd_stake_ci_leave)  (Implementation)


---
### fd\_stake\_ci\_delete<!-- {{#callable_declaration:fd_stake_ci_delete}} -->
Deletes a stake contact information store.
- **Description**: Use this function to delete a previously created stake contact information store, effectively marking the memory region as no longer in use. This function should be called when the stake contact information is no longer needed, allowing the memory to be reused or freed. It is important to ensure that the memory passed to this function was previously allocated and formatted as a stake contact information store using `fd_stake_ci_new`. The function does not perform any deallocation or memory management beyond returning the pointer.
- **Inputs**:
    - `mem`: A pointer to the memory region that was previously formatted as a stake contact information store. The memory must have been allocated and initialized using `fd_stake_ci_new`. The caller retains ownership of the memory, and it must not be null.
- **Output**: Returns the same pointer that was passed in, allowing for potential reuse or further memory management by the caller.
- **See also**: [`fd_stake_ci_delete`](fd_stake_ci.c.driver.md#fd_stake_ci_delete)  (Implementation)


---
### fd\_stake\_ci\_stake\_msg\_init<!-- {{#callable_declaration:fd_stake_ci_stake_msg_init}} -->
Initialize stake message data in the stake contact info object.
- **Description**: This function is used to initialize the stake message data within a `fd_stake_ci_t` object using a message containing stake weight updates. It should be called when a new stake message is received, and it prepares the object for processing these updates. The function must be called before any subsequent call to `fd_stake_ci_stake_msg_fini`. The input message must contain valid stake data, and the function will log an error if the number of stakes exceeds the maximum allowed. This function does not alter the state of the object in a way that affects query functions, which will continue to return the same values as before the call.
- **Inputs**:
    - `info`: A pointer to a `fd_stake_ci_t` object where the stake message data will be initialized. The caller must ensure this pointer is valid and points to a properly initialized object.
    - `new_message`: A pointer to a constant unsigned character array containing the new stake message. The message must be at least `FD_STAKE_CI_STAKE_MSG_SZ` bytes long and contain valid stake data. The caller retains ownership of this data, and it must not be null.
- **Output**: None
- **See also**: [`fd_stake_ci_stake_msg_init`](fd_stake_ci.c.driver.md#fd_stake_ci_stake_msg_init)  (Implementation)


---
### fd\_stake\_ci\_stake\_msg\_fini<!-- {{#callable_declaration:fd_stake_ci_stake_msg_fini}} -->
Finalizes the processing of a stake message.
- **Description**: This function should be called after processing a stake message to update the internal state of the stake contact information object. It finalizes the changes made during the stake message processing, ensuring that the leader schedules and shred destinations are updated according to the new stake information. This function must be called after `fd_stake_ci_stake_msg_init` and before any other initialization or finalization functions. It is crucial for maintaining the correct state of the stake contact information across epoch boundaries.
- **Inputs**:
    - `info`: A pointer to an `fd_stake_ci_t` structure that contains the stake contact information. This pointer must not be null, and the structure should be in a stake-msg-pending state, having been initialized by `fd_stake_ci_stake_msg_init`.
- **Output**: None
- **See also**: [`fd_stake_ci_stake_msg_fini`](fd_stake_ci.c.driver.md#fd_stake_ci_stake_msg_fini)  (Implementation)


---
### fd\_stake\_ci\_dest\_add\_init<!-- {{#callable_declaration:fd_stake_ci_dest_add_init}} -->
Initialize the shred destination addition process.
- **Description**: This function prepares the `fd_stake_ci_t` structure for adding new shred destination information. It should be called before populating the shred destination array with additional information, such as MAC addresses, that augments the data received from Rust. The function transitions the stake contact info object into a dest-add-pending mode, allowing subsequent calls to query functions without affecting their return values. It is important to call this function before `fd_stake_ci_dest_add_fini` to ensure proper operation.
- **Inputs**:
    - `info`: A pointer to an `fd_stake_ci_t` structure that must be valid and properly initialized. The caller retains ownership and must ensure it is not null.
- **Output**: Returns a pointer to the first element of an array of `fd_shred_dest_weighted_t` structures, which is used to populate additional shred destination information. The array has a size of `MAX_SHRED_DESTS-1`.
- **See also**: [`fd_stake_ci_dest_add_init`](fd_stake_ci.c.driver.md#fd_stake_ci_dest_add_init)  (Implementation)


---
### fd\_stake\_ci\_dest\_add\_fini<!-- {{#callable_declaration:fd_stake_ci_dest_add_fini}} -->
Finalize the update of shred destinations with additional contact information.
- **Description**: This function is used to finalize the process of updating shred destinations with additional contact information, which is typically received from the Rust side of the application. It should be called after `fd_stake_ci_dest_add_init` has been used to prepare the destination array. The function ensures that the local validator is included in the shred destinations if it was not already present. It must be called with the stake contact info object in a dest-add-pending mode, which is set by a prior call to `fd_stake_ci_dest_add_init`. This function updates the shred destinations for both the current and next epoch, ensuring that the local validator's contact information is correctly included.
- **Inputs**:
    - `info`: A pointer to an `fd_stake_ci_t` structure that holds the stake contact information. This must not be null and should be in a dest-add-pending state.
    - `cnt`: The number of elements in the shred destination array that have been populated. It must be in the range 0 <= cnt < MAX_SHRED_DESTS. If cnt is invalid, the behavior is undefined.
- **Output**: None
- **See also**: [`fd_stake_ci_dest_add_fini`](fd_stake_ci.c.driver.md#fd_stake_ci_dest_add_fini)  (Implementation)


---
### fd\_stake\_ci\_set\_identity<!-- {{#callable_declaration:fd_stake_ci_set_identity}} -->
Updates the identity key of the local validator.
- **Description**: This function is used to change the identity of the locally running validator at runtime. It updates the identity key and adjusts the shred destinations accordingly. This function should be called when there is a need to change the validator's identity key, ensuring that the new identity is properly integrated into the shred destination configuration. The function handles the case where the new identity is not already present in the shred destinations by adding it as a new unstaked validator if necessary.
- **Inputs**:
    - `info`: A pointer to an fd_stake_ci_t structure representing the stake contact information. Must not be null, and the caller retains ownership.
    - `identity_key`: A pointer to a constant fd_pubkey_t structure representing the new identity key. Must not be null, and the caller retains ownership.
- **Output**: None
- **See also**: [`fd_stake_ci_set_identity`](fd_stake_ci.c.driver.md#fd_stake_ci_set_identity)  (Implementation)


---
### fd\_stake\_ci\_get\_sdest\_for\_slot<!-- {{#callable_declaration:fd_stake_ci_get_sdest_for_slot}} -->
Retrieve the shred destination for a specified slot.
- **Description**: Use this function to obtain the shred destination associated with a specific slot, if available. It is particularly useful when you need to determine the destination for shreds during a given slot in the context of epoch-specific leader schedules and shred destinations. The function should be called with a valid stake contact information object, and it will return NULL if the information for the specified slot is not available.
- **Inputs**:
    - `info`: A pointer to a constant fd_stake_ci_t structure containing the stake contact information. This must not be null and should be properly initialized before calling this function.
    - `slot`: An unsigned long integer representing the slot for which the shred destination is requested. There are no specific constraints on the value, but the function will return NULL if the slot information is not available.
- **Output**: A pointer to an fd_shred_dest_t structure containing the shred destination for the specified slot, or NULL if the information is not available.
- **See also**: [`fd_stake_ci_get_sdest_for_slot`](fd_stake_ci.c.driver.md#fd_stake_ci_get_sdest_for_slot)  (Implementation)


---
### fd\_stake\_ci\_get\_lsched\_for\_slot<!-- {{#callable_declaration:fd_stake_ci_get_lsched_for_slot}} -->
Retrieve the leader schedule for a specified slot.
- **Description**: Use this function to obtain the leader schedule associated with a specific slot, which is crucial for determining the leader responsible for that slot. This function should be called when you need to query the leader schedule for a particular slot within the context of epoch-specific leader schedules. It returns a pointer to the leader schedule if available, or NULL if the information for the specified slot is not present. Ensure that the `info` parameter is properly initialized and contains valid epoch information before calling this function.
- **Inputs**:
    - `info`: A pointer to a constant `fd_stake_ci_t` structure containing epoch-specific leader schedule information. Must not be null and should be properly initialized with valid data.
    - `slot`: An unsigned long integer representing the slot number for which the leader schedule is requested. There are no specific constraints on the value, but the function will return NULL if the slot information is unavailable.
- **Output**: Returns a pointer to an `fd_epoch_leaders_t` structure containing the leader schedule for the specified slot, or NULL if the information is not available.
- **See also**: [`fd_stake_ci_get_lsched_for_slot`](fd_stake_ci.c.driver.md#fd_stake_ci_get_lsched_for_slot)  (Implementation)



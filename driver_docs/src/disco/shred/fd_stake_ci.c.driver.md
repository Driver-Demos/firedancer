# Purpose
The provided C source code file is part of a larger system that manages stake and shred destination information for a network of validators, likely in a blockchain or distributed ledger context. The code is designed to handle the initialization, updating, and management of stake-related data structures, specifically focusing on the distribution of shred destinations and leader schedules across different epochs. The file includes functions to create, join, leave, and delete stake contact information structures, as well as to initialize and finalize messages related to stake updates. It also provides mechanisms to update shred destinations based on new stake information and to handle changes in validator identity.

Key technical components of the code include the use of data structures such as `fd_stake_ci_t`, `fd_shred_dest_weighted_t`, and `fd_per_epoch_info_t` to store and manage stake and shred destination information. The code also utilizes sorting and set operations to maintain and update these data structures efficiently. The file defines several functions that serve as an interface for managing stake information, such as [`fd_stake_ci_new`](#fd_stake_ci_new), [`fd_stake_ci_stake_msg_init`](#fd_stake_ci_stake_msg_init), and [`fd_stake_ci_dest_add_fini`](#fd_stake_ci_dest_add_fini). These functions are crucial for ensuring that the system can adapt to changes in stake distribution and validator identities, maintaining the integrity and performance of the network. The code is intended to be part of a larger application, likely a library or module, that interacts with other components to manage network operations in a distributed system.
# Imports and Dependencies

---
- `fd_stake_ci.h`
- `../../util/net/fd_ip4.h`
- `../../util/tmpl/fd_sort.c`
- `../../util/tmpl/fd_set.c`


# Functions

---
### fd\_stake\_ci\_new<!-- {{#callable:fd_stake_ci_new}} -->
The `fd_stake_ci_new` function initializes a `fd_stake_ci_t` structure with dummy stake and shred destination data, setting up initial epoch information and linking it to leader and shred destination schedules.
- **Inputs**:
    - `mem`: A pointer to a memory location where the `fd_stake_ci_t` structure will be initialized.
    - `identity_key`: A constant pointer to an `fd_pubkey_t` structure representing the identity key of the local validator.
- **Control Flow**:
    - Cast the `mem` pointer to an `fd_stake_ci_t` pointer named `info`.
    - Create a dummy stake with a key of zero and a stake of 1, and a dummy shred destination with the provided `identity_key` and a dummy IP address.
    - Initialize the first elements of `info->stake_weight` and `info->shred_dest` with the dummy stake and destination, respectively.
    - Iterate twice to initialize epoch information for two epochs, setting epoch number, start slot, slot count, and excluded stake to zero.
    - For each epoch, create and join new leader and shred destination schedules using the initialized stake weights and identity key.
    - Store the `identity_key` in the `info->identity_key` array.
    - Return the initialized `info` pointer cast to a `void *`.
- **Output**: A pointer to the initialized `fd_stake_ci_t` structure, cast to a `void *`.
- **Functions called**:
    - [`fd_shred_dest_join`](fd_shred_dest.c.driver.md#fd_shred_dest_join)
    - [`fd_shred_dest_new`](fd_shred_dest.c.driver.md#fd_shred_dest_new)


---
### fd\_stake\_ci\_join<!-- {{#callable:fd_stake_ci_join}} -->
The `fd_stake_ci_join` function casts a given memory pointer to a `fd_stake_ci_t` type and returns it.
- **Inputs**:
    - `mem`: A pointer to a memory location that is expected to be of type `fd_stake_ci_t`.
- **Control Flow**:
    - The function takes a single input parameter, `mem`, which is a void pointer.
    - It casts the `mem` pointer to a `fd_stake_ci_t` pointer type.
    - The function returns the casted pointer.
- **Output**: A pointer of type `fd_stake_ci_t` that points to the same memory location as the input `mem`.


---
### fd\_stake\_ci\_leave<!-- {{#callable:fd_stake_ci_leave}} -->
The `fd_stake_ci_leave` function returns a pointer to the `fd_stake_ci_t` structure passed to it.
- **Inputs**:
    - `info`: A pointer to an `fd_stake_ci_t` structure, which contains stake contact information.
- **Control Flow**:
    - The function takes a single argument, `info`, which is a pointer to an `fd_stake_ci_t` structure.
    - It returns the same pointer cast to a `void *`.
- **Output**: A `void *` pointer that is the same as the input `info` pointer.


---
### fd\_stake\_ci\_delete<!-- {{#callable:fd_stake_ci_delete}} -->
The `fd_stake_ci_delete` function returns the memory pointer passed to it without any modification.
- **Inputs**:
    - `mem`: A pointer to a memory block that is intended to be deleted or freed.
- **Control Flow**:
    - The function takes a single argument, a pointer to memory.
    - It immediately returns the same pointer without performing any operations on it.
- **Output**: The function returns the same memory pointer that was passed as an argument.


---
### fd\_stake\_ci\_stake\_msg\_init<!-- {{#callable:fd_stake_ci_stake_msg_init}} -->
The `fd_stake_ci_stake_msg_init` function initializes the stake message information in the `fd_stake_ci_t` structure using data from a new message.
- **Inputs**:
    - `info`: A pointer to an `fd_stake_ci_t` structure where the stake message information will be initialized.
    - `new_message`: A constant pointer to an unsigned character array containing the new message data to be used for initialization.
- **Control Flow**:
    - The function begins by casting the `new_message` to a constant pointer to an unsigned long array using `fd_type_pun_const` to interpret the message data as header information.
    - It extracts the epoch, staked count, start slot, slot count, and excluded stake from the header array.
    - A check is performed to ensure that the staked count does not exceed `MAX_SHRED_DESTS`; if it does, an error is logged and the function terminates.
    - The extracted values are then assigned to the corresponding fields in the `scratch` member of the `info` structure.
    - Finally, the function copies the stake weights from the message header into the `stake_weight` array of the `info` structure, starting from the sixth element of the header.
- **Output**: The function does not return a value; it modifies the `info` structure in place.


---
### log\_summary<!-- {{#callable:log_summary}} -->
The `log_summary` function logs detailed information about stake contact and shred destination details for two epochs, but is currently disabled with a preprocessor directive.
- **Inputs**:
    - `msg`: A constant character pointer representing a message to be logged.
    - `info`: A pointer to an `fd_stake_ci_t` structure containing stake contact information.
- **Control Flow**:
    - The function is wrapped in a preprocessor conditional `#if 0`, which effectively disables its execution.
    - If enabled, it would retrieve epoch information from the `info` structure and log a notice with the provided message.
    - It would iterate over two epochs, logging details about each epoch's shred destination details.
    - For each shred destination, it would log the public key, stake lamports, IP address, and port.
- **Output**: The function does not return any value; it is intended to log information for debugging purposes.
- **Functions called**:
    - [`fd_shred_dest_cnt_all`](fd_shred_dest.h.driver.md#fd_shred_dest_cnt_all)
    - [`fd_shred_dest_idx_to_dest`](fd_shred_dest.h.driver.md#fd_shred_dest_idx_to_dest)


---
### fd\_stake\_ci\_stake\_msg\_fini<!-- {{#callable:fd_stake_ci_stake_msg_fini}} -->
The `fd_stake_ci_stake_msg_fini` function finalizes the update of shred destinations based on new stake information and existing contact data for a given epoch.
- **Inputs**:
    - `info`: A pointer to an `fd_stake_ci_t` structure containing the current stake and contact information, as well as scratch space for temporary data.
- **Control Flow**:
    - Retrieve the current epoch and staked count from the `info->scratch` structure.
    - Initialize a set to track destinations that are not staked in the new epoch.
    - Iterate over the staked nodes, updating the `info->shred_dest` array with existing destination data or new public keys if necessary, and remove these from the unhit set.
    - Check for any destinations that were previously staked but are not in the new list, marking them as unstaked and adding them to the `info->shred_dest` array if they have valid IP addresses.
    - Delete the unhit set after processing all destinations.
    - If any destinations were destaked, sort the unstaked destinations by public key to maintain order.
    - Clear the existing epoch information and create new epoch information using the updated shred destinations and leader schedule.
    - Log a summary of the stake update.
- **Output**: The function does not return a value; it updates the `info` structure in place with new shred destination and epoch information.
- **Functions called**:
    - [`fd_shred_dest_cnt_all`](fd_shred_dest.h.driver.md#fd_shred_dest_cnt_all)
    - [`fd_shred_dest_pubkey_to_idx`](fd_shred_dest.c.driver.md#fd_shred_dest_pubkey_to_idx)
    - [`fd_shred_dest_idx_to_dest`](fd_shred_dest.h.driver.md#fd_shred_dest_idx_to_dest)
    - [`fd_shred_dest_delete`](fd_shred_dest.c.driver.md#fd_shred_dest_delete)
    - [`fd_shred_dest_leave`](fd_shred_dest.c.driver.md#fd_shred_dest_leave)
    - [`fd_shred_dest_join`](fd_shred_dest.c.driver.md#fd_shred_dest_join)
    - [`fd_shred_dest_new`](fd_shred_dest.c.driver.md#fd_shred_dest_new)
    - [`log_summary`](#log_summary)


---
### fd\_stake\_ci\_dest\_add\_init<!-- {{#callable:fd_stake_ci_dest_add_init}} -->
The function `fd_stake_ci_dest_add_init` returns the `shred_dest` array from a given `fd_stake_ci_t` structure.
- **Inputs**:
    - `info`: A pointer to an `fd_stake_ci_t` structure, which contains information about stake and shred destinations.
- **Control Flow**:
    - The function takes a single argument, `info`, which is a pointer to an `fd_stake_ci_t` structure.
    - It directly returns the `shred_dest` member of the `info` structure without any additional processing.
- **Output**: A pointer to the `shred_dest` array within the `fd_stake_ci_t` structure, which is of type `fd_shred_dest_weighted_t *`.


---
### fd\_stake\_ci\_dest\_add\_fini\_impl<!-- {{#callable:fd_stake_ci_dest_add_fini_impl}} -->
The `fd_stake_ci_dest_add_fini_impl` function updates the list of staked and unstaked destinations by reorganizing and sorting them based on their current status and contact information.
- **Inputs**:
    - `info`: A pointer to an `fd_stake_ci_t` structure containing information about the current stake and destination configuration.
    - `cnt`: An unsigned long integer representing the count of destinations to process.
    - `ei`: A pointer to an `fd_per_epoch_info_t` structure containing per-epoch information, including the current list of destinations (`sdest`).
- **Control Flow**:
    - Initialize `found_unstaked_cnt` to 0 and `any_new_unstaked` to 0 to track unstaked destinations.
    - Determine the count of staked destinations using [`fd_shred_dest_cnt_staked`](fd_shred_dest.h.driver.md#fd_shred_dest_cnt_staked) and store it in `staked_cnt`.
    - Iterate over each destination in the range [0, cnt) to update the destination list.
    - For each destination, convert the public key to an index using [`fd_shred_dest_pubkey_to_idx`](fd_shred_dest.c.driver.md#fd_shred_dest_pubkey_to_idx).
    - If the destination is unstaked and there is space, copy it to the unstaked part of the new list and increment `j`.
    - Update the contact information (IP and port) for destinations that are found in the existing list.
    - Track if any new unstaked destinations are found and count the unstaked destinations found.
    - If no new unstaked destinations are found and the count matches the existing unstaked count, return early as no further updates are needed.
    - Otherwise, copy the staked nodes to the beginning of the temporary list and sort the unstaked nodes by public key.
    - Delete the existing destination list and create a new one with the updated list.
    - If the new destination list is NULL, log an error and terminate.
- **Output**: The function does not return a value; it updates the destination list in the `ei` structure in place.
- **Functions called**:
    - [`fd_shred_dest_cnt_staked`](fd_shred_dest.h.driver.md#fd_shred_dest_cnt_staked)
    - [`fd_shred_dest_pubkey_to_idx`](fd_shred_dest.c.driver.md#fd_shred_dest_pubkey_to_idx)
    - [`fd_shred_dest_idx_to_dest`](fd_shred_dest.h.driver.md#fd_shred_dest_idx_to_dest)
    - [`fd_shred_dest_cnt_unstaked`](fd_shred_dest.h.driver.md#fd_shred_dest_cnt_unstaked)
    - [`fd_shred_dest_delete`](fd_shred_dest.c.driver.md#fd_shred_dest_delete)
    - [`fd_shred_dest_leave`](fd_shred_dest.c.driver.md#fd_shred_dest_leave)
    - [`fd_shred_dest_join`](fd_shred_dest.c.driver.md#fd_shred_dest_join)
    - [`fd_shred_dest_new`](fd_shred_dest.c.driver.md#fd_shred_dest_new)


---
### fd\_stake\_ci\_dest\_add\_fini<!-- {{#callable:fd_stake_ci_dest_add_fini}} -->
The `fd_stake_ci_dest_add_fini` function ensures that the local validator is included in the list of shred destinations and updates the destination information for the current and next epoch.
- **Inputs**:
    - `info`: A pointer to an `fd_stake_ci_t` structure containing information about the current stake and shred destinations.
    - `cnt`: An unsigned long integer representing the current count of shred destinations.
- **Control Flow**:
    - Check if the current count of shred destinations is less than the maximum allowed (`MAX_SHRED_DESTS`).
    - Iterate over the existing shred destinations to check if the local validator is already included by comparing public keys.
    - If the local validator is not found, add it to the list of shred destinations with a dummy IP address (`SELF_DUMMY_IP`).
    - If the local validator is found, update its IP address to `SELF_DUMMY_IP`.
    - Call [`fd_stake_ci_dest_add_fini_impl`](#fd_stake_ci_dest_add_fini_impl) to update the shred destinations for both the current and next epoch.
    - Log a summary of the destination update.
- **Output**: The function does not return a value; it modifies the `info` structure in place to ensure the local validator is included in the shred destinations.
- **Functions called**:
    - [`fd_stake_ci_dest_add_fini_impl`](#fd_stake_ci_dest_add_fini_impl)
    - [`log_summary`](#log_summary)


---
### fd\_stake\_ci\_get\_idx\_for\_slot<!-- {{#callable:fd_stake_ci_get_idx_for_slot}} -->
The function `fd_stake_ci_get_idx_for_slot` determines the index of the epoch information for a given slot within a `fd_stake_ci_t` structure.
- **Inputs**:
    - `info`: A pointer to a `fd_stake_ci_t` structure containing epoch information.
    - `slot`: An unsigned long integer representing the slot number for which the index is to be determined.
- **Control Flow**:
    - Initialize `idx` to `ULONG_MAX` to represent an invalid index initially.
    - Iterate over the two elements in the `epoch_info` array within the `info` structure.
    - For each element, check if the `slot` falls within the range defined by `start_slot` and `slot_cnt`.
    - If the condition is met, update `idx` to the current index `i` using the `fd_ulong_if` function.
    - Return the value of `idx`, which will be either a valid index (0 or 1) or `ULONG_MAX` if no valid index is found.
- **Output**: Returns an unsigned long integer representing the index of the epoch information for the given slot, or `ULONG_MAX` if no valid index is found.


---
### fd\_stake\_ci\_set\_identity<!-- {{#callable:fd_stake_ci_set_identity}} -->
The `fd_stake_ci_set_identity` function updates the identity key of a stake configuration and adjusts the shred destination IP addresses accordingly.
- **Inputs**:
    - `info`: A pointer to an `fd_stake_ci_t` structure containing the current stake configuration information.
    - `identity_key`: A pointer to a `fd_pubkey_t` structure representing the new identity key to be set.
- **Control Flow**:
    - Iterate over the two epoch information structures in the `info` object.
    - For each epoch, retrieve the old and new shred destination indices using the current and new identity keys.
    - Check if the old index is valid; if not, log an error.
    - If the new index is valid, update the IP address of the old index to 0 and set the new index's IP address to `SELF_DUMMY_IP`.
    - Update the source of the shred destination with the new index.
    - If the new index is not valid, check if the total number of staked and unstaked destinations has reached the maximum allowed.
    - If not, add the new identity key as an unstaked validator, maintaining lexicographic order.
    - Delete the old shred destination and create a new one with the updated list.
    - Update the identity key in the `info` structure with the new identity key.
- **Output**: The function does not return a value; it modifies the `info` structure in place.
- **Functions called**:
    - [`fd_shred_dest_pubkey_to_idx`](fd_shred_dest.c.driver.md#fd_shred_dest_pubkey_to_idx)
    - [`fd_shred_dest_idx_to_dest`](fd_shred_dest.h.driver.md#fd_shred_dest_idx_to_dest)
    - [`fd_shred_dest_update_source`](fd_shred_dest.h.driver.md#fd_shred_dest_update_source)
    - [`fd_shred_dest_cnt_staked`](fd_shred_dest.h.driver.md#fd_shred_dest_cnt_staked)
    - [`fd_shred_dest_cnt_unstaked`](fd_shred_dest.h.driver.md#fd_shred_dest_cnt_unstaked)
    - [`fd_shred_dest_delete`](fd_shred_dest.c.driver.md#fd_shred_dest_delete)
    - [`fd_shred_dest_leave`](fd_shred_dest.c.driver.md#fd_shred_dest_leave)
    - [`fd_shred_dest_join`](fd_shred_dest.c.driver.md#fd_shred_dest_join)
    - [`fd_shred_dest_new`](fd_shred_dest.c.driver.md#fd_shred_dest_new)


---
### fd\_stake\_ci\_get\_sdest\_for\_slot<!-- {{#callable:fd_stake_ci_get_sdest_for_slot}} -->
The function `fd_stake_ci_get_sdest_for_slot` retrieves the shred destination for a given slot from the stake contact information.
- **Inputs**:
    - `info`: A pointer to a constant `fd_stake_ci_t` structure containing stake contact information.
    - `slot`: An unsigned long integer representing the slot for which the shred destination is requested.
- **Control Flow**:
    - Call [`fd_stake_ci_get_idx_for_slot`](#fd_stake_ci_get_idx_for_slot) with `info` and `slot` to determine the index of the epoch information corresponding to the given slot.
    - Check if the returned index is not equal to `ULONG_MAX`.
    - If the index is valid (not `ULONG_MAX`), return the shred destination (`sdest`) from the epoch information at the determined index.
    - If the index is `ULONG_MAX`, return `NULL`.
- **Output**: Returns a pointer to `fd_shred_dest_t` if the slot is found, otherwise returns `NULL`.
- **Functions called**:
    - [`fd_stake_ci_get_idx_for_slot`](#fd_stake_ci_get_idx_for_slot)


---
### fd\_stake\_ci\_get\_lsched\_for\_slot<!-- {{#callable:fd_stake_ci_get_lsched_for_slot}} -->
The function `fd_stake_ci_get_lsched_for_slot` retrieves the leader schedule for a given slot from the stake configuration information.
- **Inputs**:
    - `info`: A pointer to a constant `fd_stake_ci_t` structure containing stake configuration information.
    - `slot`: An unsigned long integer representing the slot number for which the leader schedule is requested.
- **Control Flow**:
    - Call [`fd_stake_ci_get_idx_for_slot`](#fd_stake_ci_get_idx_for_slot) with `info` and `slot` to determine the index of the epoch information corresponding to the given slot.
    - Check if the returned index is not equal to `ULONG_MAX`.
    - If the index is valid, return the leader schedule (`lsched`) from the epoch information at the determined index.
    - If the index is `ULONG_MAX`, return `NULL`.
- **Output**: A pointer to `fd_epoch_leaders_t` representing the leader schedule for the specified slot, or `NULL` if the slot is not found.
- **Functions called**:
    - [`fd_stake_ci_get_idx_for_slot`](#fd_stake_ci_get_idx_for_slot)



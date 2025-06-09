# Purpose
This C header file, `fd_shred_dest.h`, defines a set of functions and data structures for managing and computing the destinations of shreds in a distributed system, specifically within the context of a blockchain network like Solana. The primary focus of this file is to implement the Turbine tree logic, which is used to determine how shreds (small pieces of data) are propagated through the network. The file includes definitions for handling stake-weighted destinations, which are crucial for ensuring that data is distributed efficiently and securely across validators in the network. The header provides a comprehensive API for creating, managing, and computing shred destinations, including functions for initializing and joining memory regions, computing the first and child destinations in the Turbine tree, and mapping destination indices to actual network addresses.

The file defines several key data structures, such as `fd_shred_dest_weighted_t` for representing a destination with associated stake information, and `fd_shred_dest_t` for managing the state and configuration of shred destinations. It also includes utility functions for aligning and formatting memory, as well as for updating and querying the state of shred destinations. The header is designed to be included in other C source files, providing a modular and reusable interface for handling shred distribution logic. The use of specific data types and constants, such as `fd_shred_dest_idx_t` and `FD_SHRED_DEST_MAX_FANOUT`, ensures that the implementation is both efficient and scalable, capable of handling the high throughput and complex topology of a blockchain network.
# Imports and Dependencies

---
- `../../ballet/shred/fd_shred.h`
- `../../ballet/sha256/fd_sha256.h`
- `../../ballet/wsample/fd_wsample.h`
- `../../flamenco/leaders/fd_leaders.h`


# Global Variables

---
### fd\_shred\_dest\_new
- **Type**: `function`
- **Description**: The `fd_shred_dest_new` function initializes a region of memory to be used as an `fd_shred_dest_t` object, which is responsible for managing the destinations of shreds based on stake weights and leader schedules. It takes in parameters such as a memory pointer, a list of weighted destinations, a count of destinations, a leader schedule, a source public key, and an excluded stake value.
- **Use**: This function is used to set up the necessary data structures and state for determining shred destinations in a Solana network, ensuring that the memory is properly formatted and initialized for subsequent operations.


---
### fd\_shred\_dest\_join
- **Type**: `fd_shred_dest_t *`
- **Description**: The `fd_shred_dest_join` function is a global function that returns a pointer to an `fd_shred_dest_t` structure. This function is used to join a caller to a region of memory that has been formatted as an `fd_shred_dest_t` object, which is used for managing shred destinations in a distributed system.
- **Use**: This function is used to initialize and access a memory region as an `fd_shred_dest_t` object, allowing the caller to interact with shred destination data.


---
### fd\_shred\_dest\_leave
- **Type**: `function pointer`
- **Description**: The `fd_shred_dest_leave` is a function pointer that takes a pointer to an `fd_shred_dest_t` structure as its argument and returns a void pointer. This function is used to perform the opposite operation of `fd_shred_dest_join`, effectively leaving or detaching from a region of memory that was previously formatted as an `fd_shred_dest_t` object.
- **Use**: This function is used to detach from a memory region formatted as an `fd_shred_dest_t` object, reversing the operation of `fd_shred_dest_join`.


---
### fd\_shred\_dest\_delete
- **Type**: `function pointer`
- **Description**: `fd_shred_dest_delete` is a function pointer that takes a single argument, a pointer to a memory region, and returns a pointer. It is used to unformat a region of memory that was previously formatted as an `fd_shred_dest_t` object.
- **Use**: This function is used to clean up or delete a memory region that was used for shred destination computations.


---
### fd\_shred\_dest\_compute\_first
- **Type**: `fd_shred_dest_idx_t *`
- **Description**: The `fd_shred_dest_compute_first` function is a global function that computes the root of the Turbine tree for each of the provided shreds. It is designed to be used for shreds from a slot where the source validator is the leader, as determined by the leader schedule.
- **Use**: This function is used to determine the initial destination index for a set of shreds, storing the results in the provided output array.


---
### fd\_shred\_dest\_compute\_children
- **Type**: `fd_shred_dest_idx_t *`
- **Description**: The `fd_shred_dest_compute_children` function computes the children destinations in the Turbine tree for each provided shred. It is used to determine which validators should receive a shred directly from the source validator, treating the Turbine as a high-radix tree.
- **Use**: This function is used to calculate and store the destination indices for shreds, considering the fanout and destination count, and returns the result in the provided output array.


# Data Structures

---
### fd\_shred\_dest\_weighted
- **Type**: `struct`
- **Members**:
    - `pubkey`: The validator's identity key.
    - `stake_lamports`: Stake, measured in lamports, or 0 for an unstaked validator.
    - `ip4`: The validator's IP address, in network byte order.
    - `port`: The TVU port, in host byte order.
- **Description**: The `fd_shred_dest_weighted` structure represents a destination to which a shred might be sent, typically derived from Gossip. It includes the validator's identity key (`pubkey`), the amount of stake they hold in lamports (`stake_lamports`), their IP address (`ip4`), and the TVU port (`port`). The structure is used in the context of determining shred destinations in a network, with particular attention to the byte order of the IP and port fields.


---
### fd\_shred\_dest\_weighted\_t
- **Type**: `struct`
- **Members**:
    - `pubkey`: The validator's identity key.
    - `stake_lamports`: Stake, measured in lamports, or 0 for an unstaked validator.
    - `ip4`: The validator's IP address, in network byte order.
    - `port`: The TVU port, in host byte order.
- **Description**: The `fd_shred_dest_weighted_t` structure represents a destination to which a shred might be sent, typically derived from Gossip. It includes the validator's identity key (`pubkey`), the stake amount in lamports (`stake_lamports`), the validator's IP address (`ip4`), and the TVU port (`port`). This structure is used to specify the destination information for shreds in a network, with particular attention to the byte order of the IP and port fields.


---
### pubkey\_to\_idx\_t
- **Type**: `struct`
- **Members**:
    - `pubkey_to_idx_map`: A pointer to a mapping from public keys to indices, used to map a validator's public key to its corresponding index in the destination list.
- **Description**: The `pubkey_to_idx_t` is a forward-declared structure used within the `fd_shred_dest_private` structure to map public keys to indices. This mapping is crucial for efficiently determining the index of a validator in the list of destinations, which is used in the Turbine tree logic for distributing shreds in a Solana network. The actual structure definition is not provided in the code, indicating it is likely defined elsewhere or used as an opaque type.


---
### fd\_shred\_dest\_private
- **Type**: `struct`
- **Members**:
    - `_sha256_batch`: An array of bytes used for SHA-256 batch processing, aligned to FD_SHA256_BATCH_ALIGN.
    - `rng`: An array of one fd_chacha20rng_t, used for random number generation.
    - `null_dest`: A placeholder destination initialized to zero, used when a requested destination does not exist.
    - `lsched`: A pointer to a constant fd_epoch_leaders_t, representing the leader schedule for the current epoch.
    - `cnt`: An unsigned long integer representing the count of destinations.
    - `all_destinations`: A pointer to an array of fd_shred_dest_weighted_t, representing all possible destinations.
    - `staked`: A pointer to fd_wsample_t, representing the staked destinations.
    - `unstaked`: A pointer to an array of unsigned long integers, representing unstaked destinations.
    - `unstaked_unremoved_cnt`: An unsigned long integer representing the count of unstaked destinations that have not been removed.
    - `staked_cnt`: An unsigned long integer representing the count of staked destinations.
    - `unstaked_cnt`: An unsigned long integer representing the count of unstaked destinations.
    - `excluded_stake`: An unsigned long integer representing the stake that is excluded from the destination list.
    - `pubkey_to_idx_map`: A pointer to pubkey_to_idx_t, mapping public keys to destination indices.
    - `source_validator_orig_idx`: An unsigned long integer representing the original index of the source validator.
- **Description**: The `fd_shred_dest_private` structure is a complex data structure used in the context of Solana's Turbine protocol to manage and compute destinations for shreds, which are data packets in the network. It includes fields for managing SHA-256 batch processing, random number generation, and destination management, including both staked and unstaked destinations. The structure also maintains mappings from public keys to destination indices and tracks the original index of the source validator. It is aligned to `FD_SHRED_DEST_ALIGN` and is designed to efficiently handle a large number of potential destinations, leveraging both direct and indexed access to destination data.


---
### fd\_shred\_dest\_t
- **Type**: `struct`
- **Members**:
    - `_sha256_batch`: An array aligned to FD_SHA256_BATCH_ALIGN used for SHA256 batch operations.
    - `rng`: An array of fd_chacha20rng_t used for random number generation.
    - `null_dest`: A placeholder destination initialized to zero, used when no valid destination exists.
    - `lsched`: A pointer to a constant fd_epoch_leaders_t structure representing the leader schedule.
    - `cnt`: A count of destinations.
    - `all_destinations`: A pointer to an array of fd_shred_dest_weighted_t representing all possible destinations.
    - `staked`: A pointer to fd_wsample_t used for sampling staked destinations.
    - `unstaked`: A pointer to an array of ulong representing unstaked destinations.
    - `unstaked_unremoved_cnt`: A count of unstaked destinations that have not been removed.
    - `staked_cnt`: A count of staked destinations.
    - `unstaked_cnt`: A count of unstaked destinations.
    - `excluded_stake`: The total stake of excluded validators.
    - `pubkey_to_idx_map`: A pointer to pubkey_to_idx_t mapping public keys to destination indices.
    - `source_validator_orig_idx`: The original index of the source validator in the destination list.
- **Description**: The `fd_shred_dest_t` structure is a complex data structure used in the Solana blockchain to manage and compute the destinations for shreds, which are data packets used in the network. It includes fields for managing SHA256 batch operations, random number generation, and a list of potential destinations, both staked and unstaked. The structure also maintains a mapping from public keys to destination indices and tracks the original index of the source validator. It is aligned to 128 bytes and is designed to efficiently handle a large number of potential destinations, leveraging indices to minimize memory usage. The structure is integral to the Turbine protocol, which is responsible for distributing shreds across the network.


# Functions

---
### fd\_shred\_dest\_align<!-- {{#callable:fd_shred_dest_align}} -->
The `fd_shred_dest_align` function returns the alignment requirement for an `fd_shred_dest_t` object.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as `static inline`, indicating it is a small utility function meant to be inlined for performance.
    - It returns a constant value, `FD_SHRED_DEST_ALIGN`, which is predefined as `128UL`.
- **Output**: The function returns an `ulong` representing the alignment requirement for an `fd_shred_dest_t` object, which is `128UL`.


---
### fd\_shred\_dest\_cnt\_staked<!-- {{#callable:fd_shred_dest_cnt_staked}} -->
The function `fd_shred_dest_cnt_staked` returns the number of staked destinations in a given `fd_shred_dest_t` structure.
- **Inputs**:
    - `sdest`: A pointer to an `fd_shred_dest_t` structure, which contains information about shred destinations.
- **Control Flow**:
    - The function accesses the `staked_cnt` member of the `fd_shred_dest_t` structure pointed to by `sdest`.
    - It returns the value of `staked_cnt`, which represents the number of staked destinations.
- **Output**: The function returns an `ulong` representing the number of staked destinations in the `fd_shred_dest_t` structure.


---
### fd\_shred\_dest\_cnt\_unstaked<!-- {{#callable:fd_shred_dest_cnt_unstaked}} -->
The function `fd_shred_dest_cnt_unstaked` returns the count of unstaked destinations in a given `fd_shred_dest_t` structure.
- **Inputs**:
    - `sdest`: A pointer to an `fd_shred_dest_t` structure, which contains information about shred destinations, including counts of staked and unstaked destinations.
- **Control Flow**:
    - The function accesses the `unstaked_cnt` member of the `fd_shred_dest_t` structure pointed to by `sdest`.
    - It returns the value of `unstaked_cnt`.
- **Output**: The function returns an `ulong` representing the number of unstaked destinations in the `fd_shred_dest_t` structure.


---
### fd\_shred\_dest\_cnt\_all<!-- {{#callable:fd_shred_dest_cnt_all}} -->
The function `fd_shred_dest_cnt_all` calculates the total number of destinations, both staked and unstaked, for a given shred destination object.
- **Inputs**:
    - `sdest`: A pointer to an `fd_shred_dest_t` structure, which contains information about shred destinations, including counts of staked and unstaked destinations.
- **Control Flow**:
    - The function accesses the `staked_cnt` and `unstaked_cnt` fields of the `fd_shred_dest_t` structure pointed to by `sdest`.
    - It adds the values of `staked_cnt` and `unstaked_cnt` together.
- **Output**: The function returns the sum of `staked_cnt` and `unstaked_cnt`, representing the total number of destinations.


---
### fd\_shred\_dest\_idx\_to\_dest<!-- {{#callable:fd_shred_dest_idx_to_dest}} -->
The `fd_shred_dest_idx_to_dest` function maps a destination index to an actual destination structure, returning a null destination if the index is invalid.
- **Inputs**:
    - `sdest`: A pointer to an `fd_shred_dest_t` structure, which contains information about all possible destinations and a null destination.
    - `idx`: An `fd_shred_dest_idx_t` index representing the destination index to be mapped, or `FD_SHRED_DEST_NO_DEST` if no valid destination exists.
- **Control Flow**:
    - The function checks if the provided index `idx` is not equal to `FD_SHRED_DEST_NO_DEST`.
    - If the index is valid, it returns a pointer to the destination at `sdest->all_destinations + idx`.
    - If the index is `FD_SHRED_DEST_NO_DEST`, it returns a pointer to `sdest->null_dest`.
- **Output**: A pointer to an `fd_shred_dest_weighted_t` structure representing the destination, or a null destination if the index is invalid.


---
### fd\_shred\_dest\_update\_source<!-- {{#callable:fd_shred_dest_update_source}} -->
The `fd_shred_dest_update_source` function updates the source validator index for a shred destination object.
- **Inputs**:
    - `sdest`: A pointer to an `fd_shred_dest_t` structure, representing the shred destination object whose source validator index is to be updated.
    - `idx`: An `fd_shred_dest_idx_t` value representing the new index of the source validator, which must be within the valid range of [0, staked_cnt+unstaked_cnt).
- **Control Flow**:
    - The function takes two parameters: a pointer to an `fd_shred_dest_t` structure (`sdest`) and an index (`idx`).
    - It assigns the value of `idx` to the `source_validator_orig_idx` field of the `fd_shred_dest_t` structure pointed to by `sdest`.
- **Output**: This function does not return any value; it modifies the `source_validator_orig_idx` field of the `fd_shred_dest_t` structure in place.


# Function Declarations (Public API)

---
### fd\_shred\_dest\_footprint<!-- {{#callable_declaration:fd_shred_dest_footprint}} -->
Calculate the memory footprint required for an fd_shred_dest_t object.
- **Description**: This function computes the memory footprint needed to store an fd_shred_dest_t object, which is used to manage destinations for shreds based on stake weights. It requires the number of staked and unstaked destinations as input parameters. This function is typically called before allocating memory for an fd_shred_dest_t object to ensure that the allocated region is of sufficient size. The function does not perform any memory allocation itself; it only calculates the required size.
- **Inputs**:
    - `staked_cnt`: The number of destinations with positive stake. Must be a non-negative integer.
    - `unstaked_cnt`: The number of destinations with zero stake. Must be a non-negative integer.
- **Output**: Returns the size in bytes of the memory footprint required for the specified number of staked and unstaked destinations.
- **See also**: [`fd_shred_dest_footprint`](fd_shred_dest.c.driver.md#fd_shred_dest_footprint)  (Implementation)


---
### fd\_shred\_dest\_new<!-- {{#callable_declaration:fd_shred_dest_new}} -->
Formats a memory region for use as an fd_shred_dest_t object.
- **Description**: This function prepares a specified memory region to be used as an fd_shred_dest_t object, which is used to compute shred destinations based on stake weights. It requires a memory region with the correct alignment and footprint, and a sorted list of destination information. The function copies the destination information and retains a read interest in the leader schedule. It must be called with a valid memory region and properly sorted destination information. The function returns the memory region on success or NULL on failure, logging a warning with details if an error occurs.
- **Inputs**:
    - `mem`: A pointer to the memory region to be formatted. Must not be null and must be aligned according to fd_shred_dest_align(). The caller retains ownership.
    - `info`: A pointer to an array of fd_shred_dest_weighted_t structures, representing the destinations. Must be sorted by stake and pubkey, and must include the source validator. The caller retains ownership.
    - `cnt`: The number of destinations in the info array. Must be non-negative.
    - `lsched`: A pointer to an fd_epoch_leaders_t object containing leader information. The function retains a read interest in this object.
    - `source`: A pointer to the public key of the current validator. Must be included in the info array. The caller retains ownership.
    - `excluded_stake`: The total stake of any excluded validators. Must be zero if unstaked validators are present in the info array.
- **Output**: Returns the mem pointer on success, or NULL on failure, with a warning logged.
- **See also**: [`fd_shred_dest_new`](fd_shred_dest.c.driver.md#fd_shred_dest_new)  (Implementation)


---
### fd\_shred\_dest\_join<!-- {{#callable_declaration:fd_shred_dest_join}} -->
Joins a caller to a memory region formatted as an fd_shred_dest_t object.
- **Description**: This function is used to associate a caller with a pre-formatted memory region that represents an fd_shred_dest_t object. It is typically called after the memory has been formatted using fd_shred_dest_new and before any operations that require access to the fd_shred_dest_t structure. The function expects the memory to be correctly aligned and formatted, as per the requirements of fd_shred_dest_t. It is important to ensure that the memory region is valid and properly initialized before calling this function to avoid undefined behavior.
- **Inputs**:
    - `mem`: A pointer to a memory region that has been formatted as an fd_shred_dest_t object. The memory must be properly aligned and initialized. The caller retains ownership of the memory.
- **Output**: Returns a pointer to an fd_shred_dest_t object, allowing the caller to interact with the shred destination data.
- **See also**: [`fd_shred_dest_join`](fd_shred_dest.c.driver.md#fd_shred_dest_join)  (Implementation)


---
### fd\_shred\_dest\_leave<!-- {{#callable_declaration:fd_shred_dest_leave}} -->
Leaves a shred destination context.
- **Description**: Use this function to leave a shred destination context that was previously joined using `fd_shred_dest_join`. It is typically called when the shred destination context is no longer needed, allowing for any necessary cleanup or state management. This function should be called before deleting or unformatting the memory region associated with the shred destination context.
- **Inputs**:
    - `sdest`: A pointer to an `fd_shred_dest_t` structure representing the shred destination context to leave. This pointer must not be null and should point to a valid shred destination context that was previously joined.
- **Output**: Returns a void pointer to the `fd_shred_dest_t` structure that was passed in, allowing for potential further use or cleanup.
- **See also**: [`fd_shred_dest_leave`](fd_shred_dest.c.driver.md#fd_shred_dest_leave)  (Implementation)


---
### fd\_shred\_dest\_delete<!-- {{#callable_declaration:fd_shred_dest_delete}} -->
Unformats a region of memory previously formatted as an fd_shred_dest_t object.
- **Description**: Use this function to clean up and release resources associated with a memory region that was previously formatted as an fd_shred_dest_t object. This function should be called when the fd_shred_dest_t object is no longer needed, ensuring that all associated resources are properly released. It is important to ensure that the memory region was previously formatted using fd_shred_dest_new and that no other operations are performed on the fd_shred_dest_t object after calling this function.
- **Inputs**:
    - `mem`: A pointer to the memory region that was previously formatted as an fd_shred_dest_t object. This pointer must not be null and should point to a valid fd_shred_dest_t object. The function will return this pointer after unformatting the memory.
- **Output**: Returns the input pointer 'mem' after unformatting the memory.
- **See also**: [`fd_shred_dest_delete`](fd_shred_dest.c.driver.md#fd_shred_dest_delete)  (Implementation)


---
### fd\_shred\_dest\_compute\_first<!-- {{#callable_declaration:fd_shred_dest_compute_first}} -->
Computes the root destination for each shred in the Turbine tree.
- **Description**: This function determines the initial destination for each shred in a set, based on the Turbine tree logic. It should be used when the source validator is the leader for the slot from which the shreds originate. The function requires that all shreds are from the same slot and that the leader for this slot is known. It is designed to handle up to 67 shreds at once, and if no valid leader is found or if the computation of seeds fails, it returns NULL. The function modifies the output array to store the destination indices for each shred.
- **Inputs**:
    - `sdest`: A pointer to an fd_shred_dest_t object, which must be properly initialized and joined. It contains the necessary context for computing shred destinations.
    - `input_shreds`: A pointer to an array of pointers to fd_shred_t objects, representing the shreds for which destinations are to be computed. All shreds must be from the same slot. This parameter can be NULL if shred_cnt is 0.
    - `shred_cnt`: The number of shreds in the input_shreds array. Must be between 0 and 67 inclusive. If 0, the function performs no operation and returns the out parameter.
    - `out`: A pointer to an array where the computed destination indices will be stored. The array must have at least shred_cnt elements.
- **Output**: Returns a pointer to the out array on success, or NULL if an error occurs (e.g., no leader found or seed computation failure).
- **See also**: [`fd_shred_dest_compute_first`](fd_shred_dest.c.driver.md#fd_shred_dest_compute_first)  (Implementation)


---
### fd\_shred\_dest\_compute\_children<!-- {{#callable_declaration:fd_shred_dest_compute_children}} -->
Computes the children destinations for each shred in the Turbine tree.
- **Description**: This function determines the child destinations for a source validator in the Turbine tree for each provided shred. It requires all shreds to originate from the same slot, with the leader for that slot known in the leader schedule. The function computes up to `dest_cnt` destinations for each shred, using a tree with a specified `fanout`. If `dest_cnt` exceeds the number of actual destinations, the output is padded with `FD_SHRED_DEST_NO_DEST`. The results are stored in a 2D array format in `out`, with `out_stride` specifying the number of elements per row. If `opt_max_dest_cnt` is provided, it will store the maximum number of real destinations for any shred, which is always less than or equal to `dest_cnt`. The function returns `out` on success or `NULL` on failure.
- **Inputs**:
    - `sdest`: A pointer to an `fd_shred_dest_t` structure representing the source validator's destination information. Must be properly initialized and joined.
    - `input_shreds`: A pointer to an array of pointers to `fd_shred_t` structures, representing the shreds to process. All shreds must be from the same slot. Must not be null if `shred_cnt` is greater than zero.
    - `shred_cnt`: The number of shreds to process. Must be between 0 and 67 inclusive.
    - `out`: A pointer to an array where the destination indices will be stored. Must have sufficient space to hold `dest_cnt` indices for each shred.
    - `out_stride`: The number of elements in each logical row of the output array. Must be at least `shred_cnt`.
    - `fanout`: The fanout of the tree, determining the number of direct children each node has. Must be a valid fanout value.
    - `dest_cnt`: The number of destination indices to compute for each shred. Typically equal to `fanout`.
    - `opt_max_dest_cnt`: An optional pointer to a `ulong` where the maximum number of real destinations for any shred will be stored. Can be null if this information is not needed.
- **Output**: Returns a pointer to the `out` array on success, or `NULL` on failure.
- **See also**: [`fd_shred_dest_compute_children`](fd_shred_dest.c.driver.md#fd_shred_dest_compute_children)  (Implementation)


---
### fd\_shred\_dest\_pubkey\_to\_idx<!-- {{#callable_declaration:fd_shred_dest_pubkey_to_idx}} -->
Maps a public key to a destination index.
- **Description**: Use this function to determine the destination index associated with a given public key within a shred destination context. This is useful when you need to identify the index of a validator's destination based on its public key. The function should be called with a valid shred destination object and a public key. If the public key is not recognized as a destination, the function returns a special value indicating no destination.
- **Inputs**:
    - `sdest`: A pointer to an fd_shred_dest_t object representing the shred destination context. Must not be null and should be properly initialized.
    - `pubkey`: A pointer to an fd_pubkey_t object representing the public key to be mapped. Must not be null. If the public key is all zeros, it is treated as an unknown destination.
- **Output**: Returns the destination index associated with the public key, or FD_SHRED_DEST_NO_DEST if the public key is not known as a destination.
- **See also**: [`fd_shred_dest_pubkey_to_idx`](fd_shred_dest.c.driver.md#fd_shred_dest_pubkey_to_idx)  (Implementation)



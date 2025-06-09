# Purpose
The provided C code is part of a system designed to manage and compute shred destinations, likely within a blockchain or distributed ledger context, such as Solana. The code defines structures and functions to handle the mapping of public keys to indices, compute shred destinations, and perform random sampling of validators. The primary functionality revolves around determining which validators should receive specific data shreds, a process that involves both staked and unstaked validators. The code includes mechanisms for hashing inputs to compute seeds for random number generation, which is crucial for the random sampling of validators.

Key components of the code include the [`fd_shred_dest_new`](#fd_shred_dest_new) function, which initializes a new shred destination structure, and the [`fd_shred_dest_compute_first`](#fd_shred_dest_compute_first) and [`fd_shred_dest_compute_children`](#fd_shred_dest_compute_children) functions, which calculate the first and subsequent destinations for shreds. The code also includes utility functions for managing memory and ensuring proper alignment, as well as functions for handling the mapping of public keys to indices. The use of cryptographic functions like ChaCha20 and SHA-256 indicates a focus on security and randomness in the selection process. Overall, the code provides a specialized and detailed implementation for managing shred destinations in a distributed system, with a focus on efficiency and correctness in handling both staked and unstaked validators.
# Imports and Dependencies

---
- `fd_shred_dest.h`
- `../../util/tmpl/fd_map_dynamic.c`


# Global Variables

---
### null\_pubkey
- **Type**: `fd_pubkey_t`
- **Description**: `null_pubkey` is a static constant variable of type `fd_pubkey_t`, which is a data structure representing a public key. It is initialized with all zero values, effectively serving as a null or invalid public key.
- **Use**: This variable is used as a sentinel value to represent a null or invalid public key in the context of public key operations, such as comparisons or checks for validity.


# Data Structures

---
### pubkey\_to\_idx
- **Type**: `struct`
- **Members**:
    - `key`: A field of type `fd_pubkey_t` representing the public key.
    - `idx`: An unsigned long integer representing the index associated with the public key.
- **Description**: The `pubkey_to_idx` structure is a simple data structure used to map a public key to an index. It contains two members: `key`, which holds the public key, and `idx`, which stores the corresponding index. This structure is typically used in contexts where a quick lookup of an index based on a public key is required, such as in hash maps or associative arrays.


---
### pubkey\_to\_idx\_t
- **Type**: `struct`
- **Members**:
    - `key`: Represents a public key of type `fd_pubkey_t`.
    - `idx`: Stores an index of type `ulong` associated with the public key.
- **Description**: The `pubkey_to_idx_t` structure is a simple mapping data structure that associates a public key (`fd_pubkey_t`) with an index (`ulong`). This structure is used to efficiently map public keys to their corresponding indices, which can be useful in scenarios where quick lookups are needed, such as in hash maps or other associative data structures. The structure is defined as part of a larger system for managing shred destinations, which involves cryptographic operations and data distribution in a networked environment.


---
### shred\_dest\_input
- **Type**: `struct`
- **Members**:
    - `slot`: An unsigned long integer representing the slot number.
    - `type`: An unsigned char indicating the type of shred, with specific bit patterns for data and code.
    - `idx`: An unsigned integer representing the index of the shred.
    - `leader_pubkey`: An array of 32 unsigned chars storing the leader's public key.
- **Description**: The `shred_dest_input` structure is a compact data structure used to store information necessary for computing shred destinations in a distributed ledger system. It includes a slot number, a type identifier for the shred, an index, and a leader's public key. This structure is packed to ensure minimal memory usage and is used as input for hashing operations to determine the seed for cryptographic functions like Chacha20, which are used in the process of determining shred destinations.


---
### shred\_dest\_input\_t
- **Type**: `struct`
- **Members**:
    - `slot`: An unsigned long integer representing the slot number.
    - `type`: An unsigned char indicating the type of shred, either Data or Code.
    - `idx`: An unsigned integer representing the index of the shred.
    - `leader_pubkey`: An array of 32 unsigned characters storing the leader's public key.
- **Description**: The `shred_dest_input_t` structure is a compact, 45-byte data structure used to compute the seed for the Chacha20 algorithm, which in turn determines the destinations for shreds. It contains information about the slot, shred type, index, and the leader's public key, all of which are essential for the hashing process that influences shred distribution.


# Functions

---
### fd\_shred\_dest\_footprint<!-- {{#callable:fd_shred_dest_footprint}} -->
The `fd_shred_dest_footprint` function calculates the memory footprint required for a shred destination structure based on the number of staked and unstaked validators.
- **Inputs**:
    - `staked_cnt`: The number of staked validators.
    - `unstaked_cnt`: The number of unstaked validators.
- **Control Flow**:
    - Calculate the total count of validators by summing `staked_cnt` and `unstaked_cnt`.
    - Determine the largest power of two greater than or equal to twice the maximum of the total count and 1, and find its most significant bit position using `fd_ulong_find_msb`.
    - Use `FD_LAYOUT_APPEND` and `FD_LAYOUT_FINI` to compute the total memory footprint by appending the memory requirements of various components, including alignment and size for `fd_shred_dest_t`, `pubkey_to_idx`, `fd_shred_dest_weighted_t`, `fd_wsample`, and `ulong` for unstaked validators.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the shred destination structure.
- **Functions called**:
    - [`fd_shred_dest_align`](fd_shred_dest.h.driver.md#fd_shred_dest_align)


---
### fd\_shred\_dest\_new<!-- {{#callable:fd_shred_dest_new}} -->
The `fd_shred_dest_new` function initializes a new shred destination structure with given parameters, ensuring proper memory alignment and configuration for staked and unstaked nodes.
- **Inputs**:
    - `mem`: A pointer to the memory location where the shred destination structure will be initialized.
    - `info`: A constant pointer to an array of `fd_shred_dest_weighted_t` structures containing information about the nodes, including their stakes.
    - `cnt`: The number of nodes in the `info` array.
    - `lsched`: A constant pointer to an `fd_epoch_leaders_t` structure representing the leader schedule.
    - `source`: A constant pointer to an `fd_pubkey_t` structure representing the source public key.
    - `excluded_stake`: The amount of stake to be excluded from the staked nodes.
- **Control Flow**:
    - Check if the `mem` pointer is NULL or misaligned, logging a warning and returning NULL if so.
    - Calculate the logarithm of the count of nodes, adjusted for alignment, and initialize memory allocation for the shred destination structure and related data.
    - Copy the `info` array into a new memory location, ensuring that staked nodes do not follow unstaked nodes, logging a warning and returning NULL if the order is incorrect.
    - Count the number of staked and unstaked nodes, and check if there is an excluded stake with unstaked nodes, logging a warning and returning NULL if so.
    - Initialize random number generation and weighted sampling structures for staked nodes, adding their stakes to the sampling structure.
    - Create a mapping from public keys to indices and verify the presence of the source public key, logging a warning and returning NULL if not found.
    - Set up the shred destination structure with the initialized data, including leader schedule, node counts, and mappings.
    - Return a pointer to the initialized shred destination structure.
- **Output**: A pointer to the initialized `fd_shred_dest_t` structure, or NULL if an error occurs during initialization.
- **Functions called**:
    - [`fd_shred_dest_align`](fd_shred_dest.h.driver.md#fd_shred_dest_align)


---
### fd\_shred\_dest\_join<!-- {{#callable:fd_shred_dest_join}} -->
The `fd_shred_dest_join` function casts a memory pointer to a `fd_shred_dest_t` pointer.
- **Inputs**:
    - `mem`: A void pointer to memory that is expected to be aligned and structured as a `fd_shred_dest_t` object.
- **Control Flow**:
    - The function takes a single input, `mem`, which is a void pointer.
    - It casts the `mem` pointer to a `fd_shred_dest_t` pointer.
    - The function returns the casted pointer.
- **Output**: A pointer to `fd_shred_dest_t` that is cast from the input memory pointer.


---
### fd\_shred\_dest\_leave<!-- {{#callable:fd_shred_dest_leave}} -->
The `fd_shred_dest_leave` function casts a pointer to a `fd_shred_dest_t` structure to a `void` pointer and returns it.
- **Inputs**:
    - `sdest`: A pointer to a `fd_shred_dest_t` structure that is to be cast to a `void` pointer.
- **Control Flow**:
    - The function takes a single argument, `sdest`, which is a pointer to a `fd_shred_dest_t` structure.
    - It casts the `sdest` pointer to a `void` pointer.
    - The function returns the casted `void` pointer.
- **Output**: A `void` pointer that is the result of casting the input `fd_shred_dest_t` pointer.


---
### fd\_shred\_dest\_delete<!-- {{#callable:fd_shred_dest_delete}} -->
The `fd_shred_dest_delete` function cleans up and deallocates resources associated with a `fd_shred_dest_t` object.
- **Inputs**:
    - `mem`: A pointer to a memory block that contains a `fd_shred_dest_t` object to be deleted.
- **Control Flow**:
    - Cast the input `mem` to a `fd_shred_dest_t` pointer named `sdest`.
    - Call `fd_chacha20rng_leave` on `sdest->rng` and then `fd_chacha20rng_delete` to clean up the RNG resource.
    - Call `fd_wsample_leave` on `sdest->staked` and then `fd_wsample_delete` to clean up the weighted sample resource.
    - Call `pubkey_to_idx_leave` on `sdest->pubkey_to_idx_map` and then `pubkey_to_idx_delete` to clean up the pubkey-to-index map resource.
    - Return the original `mem` pointer.
- **Output**: The function returns the original `mem` pointer after cleaning up the resources.


---
### sample\_unstaked\_noprepare<!-- {{#callable:sample_unstaked_noprepare}} -->
The `sample_unstaked_noprepare` function performs a single unweighted random sampling from unstaked validators, optionally excluding a specified index, without preparing the unstaked list.
- **Inputs**:
    - `sdest`: A pointer to an `fd_shred_dest_t` structure containing information about staked and unstaked validators.
    - `remove_idx`: An unsigned long integer representing the index of the element to potentially exclude from sampling.
- **Control Flow**:
    - Check if `remove_idx` is within the range of unstaked validators by comparing it to `sdest->staked_cnt` and `sdest->staked_cnt + sdest->unstaked_cnt`.
    - Calculate `unstaked_cnt` by subtracting 1 if `remove_idx` is within the unstaked range, otherwise keep it as `sdest->unstaked_cnt`.
    - If `unstaked_cnt` is zero, return `FD_WSAMPLE_EMPTY` indicating no valid unstaked validators to sample from.
    - Generate a random sample index using `fd_chacha20rng_ulong_roll` with the range of `unstaked_cnt`.
    - Return the sampled index adjusted by `sdest->staked_cnt`, incrementing by 1 if the sample index is greater than or equal to `remove_idx` and `remove_idx` is within the unstaked range.
- **Output**: Returns an unsigned long integer representing the index of the selected unstaked validator, or `FD_WSAMPLE_EMPTY` if no valid unstaked validators are available.


---
### prepare\_unstaked\_sampling<!-- {{#callable:prepare_unstaked_sampling}} -->
The `prepare_unstaked_sampling` function initializes the unstaked validator indices for sampling, excluding a specified index if it falls within the unstaked range.
- **Inputs**:
    - `sdest`: A pointer to an `fd_shred_dest_t` structure, which contains information about staked and unstaked validators.
    - `remove_idx`: An unsigned long integer representing the index of the element to be removed from the unstaked list if it falls within the unstaked range.
- **Control Flow**:
    - Check if `remove_idx` is within the unstaked range by comparing it with `sdest->staked_cnt` and `sdest->staked_cnt + sdest->unstaked_cnt`.
    - Calculate the new count of unstaked validators (`unstaked_cnt`) by subtracting 1 if `remove_idx` is within the unstaked range.
    - Set `sdest->unstaked_unremoved_cnt` to the calculated `unstaked_cnt`.
    - If `unstaked_cnt` is zero, return immediately as there are no unstaked validators to process.
    - Determine the range of indices to directly copy into `sdest->unstaked` based on whether `remove_idx` is within the unstaked range.
    - Iterate over the range, populating `sdest->unstaked` with indices, skipping `remove_idx` if necessary.
- **Output**: The function does not return a value; it modifies the `sdest` structure in place, specifically updating the `unstaked` array and `unstaked_unremoved_cnt` field.


---
### sample\_unstaked<!-- {{#callable:sample_unstaked}} -->
The `sample_unstaked` function performs unweighted random sampling from a list of unstaked validators, removing the selected element from the list for future sampling.
- **Inputs**:
    - `sdest`: A pointer to an `fd_shred_dest_t` structure, which contains the list of unstaked validators and other related data.
- **Control Flow**:
    - Check if `sdest->unstaked_unremoved_cnt` is zero; if so, return `FD_WSAMPLE_EMPTY`.
    - Use `fd_chacha20rng_ulong_roll` to randomly select an index from the `unstaked` array based on `unstaked_unremoved_cnt`.
    - Store the value at the selected index in `to_return`.
    - Replace the selected element in `unstaked` with the last element in the list, effectively removing it from future sampling.
    - Decrement `unstaked_unremoved_cnt` to reflect the removal of an element.
    - Return the value stored in `to_return`.
- **Output**: Returns the index of the selected unstaked validator, or `FD_WSAMPLE_EMPTY` if there are no unstaked validators to sample from.


---
### compute\_seeds<!-- {{#callable:compute_seeds}} -->
The `compute_seeds` function calculates SHA-256 hash seeds for a batch of shreds to determine their destinations based on the leader's public key and the slot number.
- **Inputs**:
    - `sdest`: A pointer to an `fd_shred_dest_t` structure, which contains the SHA-256 batch context and other destination-related data.
    - `input_shreds`: A pointer to an array of pointers to `fd_shred_t` structures, representing the shreds to be processed.
    - `shred_cnt`: The number of shreds in the `input_shreds` array.
    - `leader`: A pointer to an `fd_pubkey_t` structure representing the leader's public key.
    - `slot`: An unsigned long integer representing the slot number for which the seeds are being computed.
    - `dest_hash_output`: A 2D array of unsigned characters where the computed hash outputs will be stored, with dimensions `[FD_SHRED_DEST_MAX_SHRED_CNT][32]`.
- **Control Flow**:
    - Initialize an array `dest_hash_inputs` to store input data for hash computation.
    - Initialize a SHA-256 batch context using `fd_sha256_batch_init`.
    - Iterate over each shred in `input_shreds` up to `shred_cnt`.
    - For each shred, check if its slot matches the given `slot`; if not, return -1 indicating an error.
    - Determine the shred type and populate the `shred_dest_input_t` structure with the slot, type, index, and leader's public key.
    - Add the populated `shred_dest_input_t` to the SHA-256 batch for hashing.
    - Finalize the SHA-256 batch computation with `fd_sha256_batch_fini`.
    - Return 0 to indicate successful computation.
- **Output**: Returns 0 on success, or -1 if any shred's slot does not match the specified slot.


---
### fd\_shred\_dest\_compute\_first<!-- {{#callable:fd_shred_dest_compute_first}} -->
The `fd_shred_dest_compute_first` function determines the initial destination indices for a set of shreds based on the current leader and validator configuration.
- **Inputs**:
    - `sdest`: A pointer to an `fd_shred_dest_t` structure that contains information about the current validator and its configuration.
    - `input_shreds`: A pointer to an array of pointers to `fd_shred_t` structures, representing the shreds to be processed.
    - `shred_cnt`: An unsigned long integer representing the number of shreds in the `input_shreds` array.
    - `out`: A pointer to an array of `fd_shred_dest_idx_t` where the computed destination indices will be stored.
- **Control Flow**:
    - Check if `shred_cnt` is zero; if so, return `out` immediately as there are no shreds to process.
    - Check if the validator count in `sdest` is less than or equal to one; if so, set all output indices to `FD_SHRED_DEST_NO_DEST` and return `out`.
    - Retrieve the slot from the first shred and get the leader's public key for that slot using `fd_epoch_leaders_get`.
    - If the leader is not found, return `NULL`.
    - Call [`compute_seeds`](#compute_seeds) to generate hash outputs for each shred; if it fails, return `NULL`.
    - Determine if the source validator is staked and remove its index from the staked list if it is.
    - For each shred, seed the random number generator with the hash output and determine the destination index based on whether there are any staked candidates.
    - Restore the staked list to its original state after processing all shreds.
    - Return the `out` array with the computed destination indices.
- **Output**: A pointer to the `out` array containing the computed destination indices for each shred, or `NULL` if an error occurs.
- **Functions called**:
    - [`compute_seeds`](#compute_seeds)
    - [`sample_unstaked_noprepare`](#sample_unstaked_noprepare)


---
### fd\_shred\_dest\_compute\_children<!-- {{#callable:fd_shred_dest_compute_children}} -->
The `fd_shred_dest_compute_children` function calculates the destination indices for shreds to be sent to child nodes in a network, considering both staked and unstaked validators.
- **Inputs**:
    - `sdest`: A pointer to an `fd_shred_dest_t` structure representing the source validator's destination configuration.
    - `input_shreds`: A pointer to an array of pointers to `fd_shred_t` structures, representing the shreds to be processed.
    - `shred_cnt`: The number of shreds in the `input_shreds` array.
    - `out`: A pointer to an array where the computed destination indices will be stored.
    - `out_stride`: The stride to be used when writing to the `out` array.
    - `fanout`: The maximum number of child nodes a shred can be sent to.
    - `dest_cnt`: The number of destination indices to compute for each shred.
    - `opt_max_dest_cnt`: An optional pointer to store the maximum number of destinations computed for any shred.
- **Control Flow**:
    - Initialize variables and check if there are no shreds or destinations to process, returning early if so.
    - Retrieve the leader for the current slot and check if the leader is the source validator or if the slot is unknown, returning NULL if true.
    - Determine if the source validator is staked and if it should send shreds based on its position relative to the fanout and the number of staked nodes.
    - Compute hash seeds for the shreds and initialize arrays for storing shuffled indices of staked validators.
    - Iterate over each shred, removing the leader from the staked list if necessary, and determine the source validator's position in the shuffle.
    - If the source validator's index is greater than the fanout, fill the output with `FD_SHRED_DEST_NO_DEST` and continue to the next shred.
    - Calculate the range of destination indices based on the source validator's position and fill the output array with these indices, using both staked and unstaked validators as needed.
    - Update the maximum destination count if necessary and restore the staked list for the next iteration.
- **Output**: Returns a pointer to the `out` array filled with destination indices for each shred, or NULL if an error occurs.
- **Functions called**:
    - [`compute_seeds`](#compute_seeds)
    - [`prepare_unstaked_sampling`](#prepare_unstaked_sampling)
    - [`sample_unstaked`](#sample_unstaked)


---
### fd\_shred\_dest\_pubkey\_to\_idx<!-- {{#callable:fd_shred_dest_pubkey_to_idx}} -->
The function `fd_shred_dest_pubkey_to_idx` maps a given public key to its corresponding index in a shred destination structure.
- **Inputs**:
    - `sdest`: A pointer to an `fd_shred_dest_t` structure, which contains the mapping of public keys to indices.
    - `pubkey`: A constant pointer to an `fd_pubkey_t` structure representing the public key to be mapped to an index.
- **Control Flow**:
    - Check if the provided public key matches the null public key; if so, return `FD_SHRED_DEST_NO_DEST`.
    - Initialize a default result with an index of `FD_SHRED_DEST_NO_DEST`.
    - Query the `pubkey_to_idx_map` in the `sdest` structure using the provided public key and the default result.
    - Return the index from the query result.
- **Output**: The function returns an `fd_shred_dest_idx_t` index corresponding to the provided public key, or `FD_SHRED_DEST_NO_DEST` if the public key is null or not found.



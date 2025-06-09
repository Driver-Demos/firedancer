# Purpose
The provided C header file, `fd_replay.h`, is part of a larger system designed to manage the replay of data blocks in a distributed computing environment. This file defines the structures and functions necessary for orchestrating the replay of blocks as they are received from a cluster. The replay process involves handling data shreds, which are smaller units of data that make up larger blocks. These shreds are grouped into forward-error-correction (FEC) sets to ensure data integrity and are transmitted across the network. The file provides APIs to manage the lifecycle of these FEC sets, including tracking their progress, handling missing shreds through a repair protocol, and ultimately replaying completed data slices.

The file defines several key data structures, such as `fd_replay_fec_t` for tracking in-progress FEC sets and `fd_replay_slice_t` for managing replayable slices of blocks. It also includes functions for creating, joining, and managing replay instances, as well as querying and manipulating FEC sets. The header file is intended to be included in other parts of the system, providing a public API for managing the replay process. It includes mechanisms for ensuring data consistency and order during replay, which is crucial for maintaining the integrity of the distributed system's state. The file is part of a broader framework that includes components for data encoding, transmission, and error correction, as indicated by the included headers and the detailed comments explaining the replay process.
# Imports and Dependencies

---
- `../../ballet/reedsol/fd_reedsol.h`
- `../../disco/fd_disco_base.h`
- `../../flamenco/runtime/fd_blockstore.h`
- `../../tango/fseq/fd_fseq.h`
- `../../util/tmpl/fd_set.c`
- `../../util/tmpl/fd_deque_dynamic.c`
- `../../util/tmpl/fd_map_dynamic.c`


# Global Variables

---
### fd\_replay\_new
- **Type**: `function pointer`
- **Description**: `fd_replay_new` is a function that initializes a memory region for use as a replay structure. It takes a pointer to shared memory and three unsigned long parameters representing the maximum number of FEC sets, slices, and blocks.
- **Use**: This function is used to format a memory region so that it can be used to manage and replay blocks of data in a distributed system.


---
### fd\_replay\_join
- **Type**: `fd_replay_t *`
- **Description**: The `fd_replay_join` is a function that returns a pointer to an `fd_replay_t` structure. This function is used to join the caller to a replay instance, which is a data structure that manages the replay of block slices in a distributed system.
- **Use**: This function is used to obtain a local pointer to a replay instance from a shared memory region, allowing the caller to interact with the replay system.


---
### fd\_replay\_leave
- **Type**: `function`
- **Description**: The `fd_replay_leave` function is a global function that allows a caller to leave a current local join to a replay structure. It takes a constant pointer to an `fd_replay_t` structure as its parameter and returns a pointer to the underlying shared memory region on success, or NULL on failure.
- **Use**: This function is used to safely disconnect from a replay structure, ensuring that resources are properly released and the shared memory region is returned to the caller.


---
### fd\_replay\_delete
- **Type**: `function pointer`
- **Description**: `fd_replay_delete` is a function that unformats a memory region used as a replay. It assumes that no one is joined to the region and returns a pointer to the underlying shared memory region or NULL if used incorrectly.
- **Use**: This function is used to clean up and reclaim the memory region used for replay, transferring ownership of the memory back to the caller.


# Data Structures

---
### fd\_replay\_fec
- **Type**: `struct`
- **Members**:
    - `key`: A map key where the 32 most significant bits represent the slot and the 32 least significant bits represent the fec_set_idx.
    - `prev`: Used internally by a doubly linked list (dlist) for navigation.
    - `hash`: Used internally by a map for hashing purposes.
    - `slot`: The slot of the block that this FEC set is part of.
    - `parent_slot`: The parent slot of the current slot.
    - `fec_set_idx`: The index of the first data shred in the FEC set.
    - `ts`: A timestamp indicating when the first shred was received.
    - `recv_cnt`: The count of shreds received so far, including both data and coding shreds.
    - `data_cnt`: The total count of data shreds in the FEC set.
    - `idxs`: An array used to track which data shred indices need to be requested for repairs.
- **Description**: The `fd_replay_fec` structure is designed to track in-progress Forward Error Correction (FEC) sets within a block replay system. It maintains metadata about the FEC set, such as its slot, parent slot, and the index of the first data shred. It also keeps track of the number of shreds received and the total number of data shreds expected. The structure includes a mechanism to track missing data shred indices that may need to be requested for repairs. This structure is synchronized with the FEC resolver, ensuring that the replay process is aware of the current state of FEC sets, although there may be slight delays due to the downstream nature of the replay tile.


---
### fd\_replay\_fec\_t
- **Type**: `struct`
- **Members**:
    - `key`: A map key where the 32 most significant bits represent the slot and the 32 least significant bits represent the FEC set index.
    - `prev`: Used internally by a doubly linked list (dlist) for navigation.
    - `hash`: Used internally by a map for hashing purposes.
    - `slot`: The slot of the block that this FEC set is part of.
    - `parent_slot`: The parent slot of the current slot.
    - `fec_set_idx`: The index of the first data shred in the FEC set.
    - `ts`: The timestamp when the first shred was received.
    - `recv_cnt`: The count of shreds received so far, including both data and coding shreds.
    - `data_cnt`: The total count of data shreds in the FEC set.
    - `idxs`: A bit vector used to track which data shred indices need to be requested for repairs.
- **Description**: The `fd_replay_fec_t` structure is designed to track in-progress Forward Error Correction (FEC) sets during the replay process of blocks in a distributed system. It synchronizes with the `fd_fec_resolver` to ensure that the FEC sets being tracked are up-to-date, although there might be slight delays due to the downstream nature of the replay tile. The structure includes fields for managing the slot and parent slot information, the index of the first data shred, timestamps, and counts of received and total data shreds. Additionally, it uses a bit vector to manage the indices of data shreds that need to be requested for repairs, ensuring the integrity and completeness of the data being processed.


---
### fd\_replay\_slice
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the replay slice.
    - `deque`: A pointer to a dynamic array (deque) of unsigned long integers, representing a queue of completed entry batches for replay.
- **Description**: The `fd_replay_slice` structure is designed to represent a replayable slice of a block, which consists of one or more completed entry batches. It contains a `slot` to identify the specific block slice and a `deque` to manage the queue of entry batches that are ready for replay. This structure is part of a larger system that orchestrates the replay of blocks as they are received from a cluster, ensuring that the replay process is orderly and efficient.


---
### fd\_replay\_slice\_t
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the replay slice.
    - `deque`: A pointer to a dynamic array (deque) of unsigned long integers, representing the indices of completed entry batches in the slice.
- **Description**: The `fd_replay_slice_t` structure is designed to represent a replayable slice of a block, which consists of one or more completed entry batches. This structure is part of a larger system that orchestrates the replay of blocks as they are received from a cluster. The `slot` member indicates the specific slot of the block that the slice is part of, while the `deque` member is used to store the indices of the completed entry batches within that slice. This allows for efficient management and replay of block slices in the correct order, ensuring that the entire block can be executed properly.


---
### fd\_replay
- **Type**: `struct`
- **Members**:
    - `fec_max`: Maximum number of forward-error-correction (FEC) sets that can be tracked.
    - `slice_max`: Maximum number of block slices that can be replayed.
    - `block_max`: Maximum number of blocks that can be managed.
    - `fec_map`: Pointer to a map tracking in-progress FEC sets for repair.
    - `fec_deque`: Pointer to a FIFO queue of FEC sets.
    - `slice_map`: Pointer to a map tracking block slices to be replayed.
    - `slice_buf`: Buffer to hold the data of a block slice.
    - `magic`: Magic number used to verify the integrity of the replay structure.
- **Description**: The `fd_replay` structure is designed to manage the replay of data blocks in a distributed system, specifically handling forward-error-correction (FEC) sets and block slices. It maintains a cache of outstanding block slices that need replay, using a FIFO order to ensure that slices are replayed in the correct sequence. The structure includes maps and queues to track in-progress FEC sets and block slices, as well as a buffer for holding block slice data. A magic number is included for integrity verification, ensuring that the structure is correctly initialized and used.


---
### fd\_replay\_t
- **Type**: `struct`
- **Members**:
    - `fec_max`: Maximum number of FEC sets that can be tracked.
    - `slice_max`: Maximum number of slices that can be tracked.
    - `block_max`: Maximum number of blocks that can be tracked.
    - `fec_map`: Pointer to a map of in-progress FEC sets.
    - `fec_deque`: Pointer to a deque of in-progress FEC sets, used as a FIFO.
    - `slice_map`: Pointer to a map of block slices to be replayed.
    - `slice_buf`: Buffer to hold the block slice data.
    - `magic`: Magic number used to verify the integrity of the replay structure.
- **Description**: The `fd_replay_t` structure is a top-level data structure designed to manage the replay of block slices in a distributed system. It maintains an LRU cache of outstanding block slices that need to be replayed, ensuring that the replay order is FIFO. The structure tracks in-progress FEC sets to facilitate repairs if they do not complete in a timely manner, and it also manages block slices that are queued for replay. The `fd_replay_t` structure is aligned to 128 bytes and includes a magic number for integrity verification.


# Functions

---
### fd\_replay\_slice\_start\_idx<!-- {{#callable:fd_replay_slice_start_idx}} -->
The function `fd_replay_slice_start_idx` extracts and returns the start index from a 64-bit key by extracting bits 32 to 63.
- **Inputs**:
    - `key`: A 64-bit unsigned long integer from which the start index is to be extracted.
- **Control Flow**:
    - The function calls `fd_ulong_extract` with the `key`, a start bit position of 32, and an end bit position of 63.
    - The result of `fd_ulong_extract` is cast to an unsigned integer and returned.
- **Output**: The function returns an unsigned integer representing the start index extracted from the given key.


---
### fd\_replay\_slice\_end\_idx<!-- {{#callable:fd_replay_slice_end_idx}} -->
The `fd_replay_slice_end_idx` function extracts and returns the lower 31 bits of a given `ulong` key as a `uint`, representing the end index of a replay slice.
- **Inputs**:
    - `key`: A `ulong` value from which the function extracts the lower 31 bits to determine the end index of a replay slice.
- **Control Flow**:
    - The function calls `fd_ulong_extract` with the `key`, starting bit position 0, and bit length 31 to extract the desired bits.
    - The extracted bits are cast to a `uint` and returned as the function's result.
- **Output**: A `uint` representing the end index of a replay slice, derived from the lower 31 bits of the input `key`.


---
### fd\_replay\_slice\_key<!-- {{#callable:fd_replay_slice_key}} -->
The `fd_replay_slice_key` function generates a unique key by combining two 32-bit unsigned integers into a single 64-bit unsigned long integer.
- **Inputs**:
    - `start_idx`: A 32-bit unsigned integer representing the starting index of a slice.
    - `end_idx`: A 32-bit unsigned integer representing the ending index of a slice.
- **Control Flow**:
    - The function takes two 32-bit unsigned integers, `start_idx` and `end_idx`, as input parameters.
    - It casts `start_idx` to a 64-bit unsigned long and shifts it left by 32 bits.
    - It casts `end_idx` to a 64-bit unsigned long and performs a bitwise OR operation with the shifted `start_idx`.
    - The result is a 64-bit unsigned long integer that combines both indices into a single value.
- **Output**: A 64-bit unsigned long integer that uniquely represents the combination of the `start_idx` and `end_idx`.


---
### fd\_replay\_align<!-- {{#callable:fd_replay_align}} -->
The `fd_replay_align` function returns the required memory alignment for a replay structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, indicating it is intended for use within the same translation unit and should be inlined by the compiler.
    - It uses the `alignof` operator to determine the alignment requirement of the `fd_replay_t` structure.
    - The function returns this alignment value as an unsigned long integer.
- **Output**: The function returns an unsigned long integer representing the alignment requirement for the `fd_replay_t` structure.


---
### fd\_replay\_footprint<!-- {{#callable:fd_replay_footprint}} -->
The `fd_replay_footprint` function calculates the memory footprint required for a replay structure based on the maximum number of FEC sets, slices, and blocks.
- **Inputs**:
    - `fec_max`: The maximum number of forward-error-correction (FEC) sets that can be handled.
    - `slice_max`: The maximum number of slices that can be handled.
    - `block_max`: The maximum number of blocks that can be handled.
- **Control Flow**:
    - Calculate the most significant bit positions for the powers of two that are greater than or equal to `fec_max` and `block_max`.
    - Initialize the `footprint` variable using `FD_LAYOUT_INIT` and append the size and alignment of `fd_replay_t`.
    - Append the alignment and footprint of the FEC map, FEC deque, and slice map using the calculated bit positions and maximum values.
    - Iterate over the range of `block_max` to append the alignment and footprint of the slice deque for each block.
    - Finalize the footprint calculation using `FD_LAYOUT_FINI` with the calculated footprint and alignment of `fd_replay_t`.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the replay structure.
- **Functions called**:
    - [`fd_replay_align`](#fd_replay_align)


---
### fd\_replay\_fec\_insert<!-- {{#callable:fd_replay_fec_insert}} -->
The `fd_replay_fec_insert` function inserts a new in-progress FEC set into a map, keyed by slot and FEC set index, and initializes its fields.
- **Inputs**:
    - `replay`: A pointer to an `fd_replay_t` structure, which contains the FEC map where the new FEC set will be inserted.
    - `slot`: An unsigned long integer representing the slot number associated with the FEC set.
    - `fec_set_idx`: An unsigned integer representing the index of the FEC set within the slot.
- **Control Flow**:
    - Check if the FEC map in the `replay` structure is full by comparing the current key count with the maximum allowed keys.
    - If the map is full, return `NULL` to indicate failure to insert.
    - Compute a unique key by combining the `slot` and `fec_set_idx` values.
    - Insert a new FEC set into the map using the computed key, which is guaranteed not to fail.
    - Initialize the fields of the newly inserted FEC set: set `slot` and `fec_set_idx`, record the current wall clock time in `ts`, and set `recv_cnt` and `data_cnt` to zero.
    - Initialize the `idxs` field to track received data shred indices.
- **Output**: A pointer to the newly inserted `fd_replay_fec_t` structure, or `NULL` if the map is full.


---
### fd\_replay\_fec\_remove<!-- {{#callable:fd_replay_fec_remove}} -->
The `fd_replay_fec_remove` function removes an in-progress FEC set from the replay's FEC map using a composite key derived from the slot and FEC set index.
- **Inputs**:
    - `replay`: A pointer to an `fd_replay_t` structure, which contains the FEC map from which the FEC set will be removed.
    - `slot`: An unsigned long integer representing the slot number associated with the FEC set to be removed.
    - `fec_set_idx`: An unsigned integer representing the index of the FEC set within the slot to be removed.
- **Control Flow**:
    - Compute a composite key by shifting the `slot` 32 bits to the left and OR-ing it with `fec_set_idx`.
    - Query the FEC map in the `replay` structure using the computed key to find the corresponding `fd_replay_fec_t` entry.
    - Assert that the FEC entry exists using `FD_TEST`.
    - Remove the FEC entry from the FEC map using `fd_replay_fec_map_remove`.
- **Output**: This function does not return a value; it performs an in-place removal of an FEC set from the map.



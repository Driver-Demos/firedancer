# Purpose
This C source code file is designed to test the functionality of a blockstore system, which is a data structure used to manage and archive blocks of data. The code includes several test functions that simulate the creation, storage, retrieval, and validation of blocks within a blockstore. The primary components of the code include macros for generating block data and creating blockstores, functions for testing block equality and querying blocks, and multiple test functions that validate the blockstore's ability to handle various scenarios, such as archiving large numbers of blocks, managing metadata, and ensuring data integrity during storage and retrieval operations.

The file is structured as a test suite, with a [`main`](#main) function that initializes the testing environment, creates a workspace, and executes a series of tests on the blockstore system. The tests cover different aspects of blockstore functionality, including handling large and small archives, verifying metadata integrity, and ensuring that blocks can be correctly archived and retrieved. The code is intended to be compiled and executed as a standalone program, with dependencies on external libraries and utilities for memory management, logging, and blockstore operations. The presence of conditional compilation directives indicates that the tests require specific capabilities, such as 128-bit integer support, to run.
# Imports and Dependencies

---
- `../../util/fd_util.h`
- `stdlib.h`
- `time.h`
- `unistd.h`
- `fd_blockstore.h`


# Global Variables

---
### shred\_max
- **Type**: `ulong`
- **Description**: `shred_max` is a global variable of type `ulong` that is initialized to the value 128. It is used to define the maximum number of shreds that can be handled by the blockstore in the context of the program.
- **Use**: `shred_max` is used as a parameter in the `fd_blockstore_footprint` function to allocate memory for the blockstore.


---
### block\_max
- **Type**: `ulong`
- **Description**: `block_max` is a global variable of type `ulong` that is initialized to the value 128. It represents the maximum number of blocks that can be handled or stored in a blockstore system.
- **Use**: This variable is used to define the capacity of the blockstore, specifically the maximum number of blocks it can manage.


---
### txn\_max
- **Type**: `ulong`
- **Description**: The `txn_max` variable is a global variable of type `ulong` (unsigned long) initialized to the value 128. It represents the maximum number of transactions that can be handled or processed in a certain context within the program.
- **Use**: `txn_max` is used to define the transaction capacity when creating a blockstore, influencing memory allocation and processing limits.


---
### block\_map\_entry
- **Type**: `fd_block_info_t`
- **Description**: The `block_map_entry` is a variable of type `fd_block_info_t`, which is a structure used to store metadata about a block in the blockstore system. It is initialized with default values and is used to keep track of the block's parent slot, current slot, and timestamp.
- **Use**: This variable is used to store and manage metadata for a block, facilitating operations like querying and archiving blocks in the blockstore.


---
### ser
- **Type**: `fd_blockstore_ser_t`
- **Description**: The `ser` variable is an instance of the `fd_blockstore_ser_t` structure, which is initialized with pointers to a block map entry, a block, and a data array. This structure is used to serialize block data for storage or transmission.
- **Use**: The `ser` variable is used to encapsulate block data, including metadata and the actual data content, for operations such as checkpointing and restoring block data in a blockstore.


# Functions

---
### blocks\_equal<!-- {{#callable:blocks_equal}} -->
The `blocks_equal` function checks if two `fd_block_t` structures have the same data size and collected fees.
- **Inputs**:
    - `block1`: A pointer to the first `fd_block_t` structure to compare.
    - `block2`: A pointer to the second `fd_block_t` structure to compare.
- **Control Flow**:
    - The function compares the `data_sz` field of `block1` and `block2`.
    - It then compares the `collected_fees` field within the `rewards` structure of `block1` and `block2`.
    - The function returns `true` if both comparisons are equal, otherwise it returns `false`.
- **Output**: A boolean value indicating whether the two blocks are equal based on their data size and collected fees.


---
### query\_block<!-- {{#callable:query_block}} -->
The `query_block` function queries a block from a blockstore, checks if the query result matches the expected outcome, and logs the result.
- **Inputs**:
    - `expect`: A boolean indicating whether the query is expected to succeed or not.
    - `blockstore`: A pointer to the blockstore from which the block data is queried.
    - `fd`: An integer file descriptor used for accessing the blockstore.
    - `slotn`: An unsigned long integer representing the slot number of the block to be queried.
- **Control Flow**:
    - Initialize variables for block size, metadata, rewards, parent hash, and block data pointer.
    - Allocate virtual memory for the block data using the blockstore's allocator.
    - Query the block data from the blockstore using `fd_blockstore_block_data_query_volatile`, storing the result in `success`.
    - If block data is retrieved, free the allocated memory for the block data.
    - Check if the success of the query matches the expected outcome (`expect`).
    - Log an error if the query result does not match the expectation, otherwise log a notice indicating a match.
    - Return the metadata of the queried block.
- **Output**: The function returns the metadata of the queried block as an `fd_block_info_t` structure.
- **Functions called**:
    - [`fd_blockstore_alloc`](fd_blockstore.h.driver.md#fd_blockstore_alloc)


---
### test\_archive\_many\_blocks<!-- {{#callable:test_archive_many_blocks}} -->
The function `test_archive_many_blocks` tests the archiving of blocks in a blockstore, ensuring that blocks are correctly archived, evicted, and restored when the blockstore's capacity is exceeded.
- **Inputs**:
    - `wksp`: A pointer to a workspace (`fd_wksp_t`) used for memory allocation.
    - `fd`: A file descriptor (`int`) representing the file to be used for block storage.
    - `fd_size_max`: The maximum size (`ulong`) of the file descriptor for the blockstore.
    - `idx_max`: The maximum index (`ulong`) for the blockstore.
    - `blocks`: The number of blocks (`ulong`) to be archived and tested.
- **Control Flow**:
    - The function begins by clearing the file descriptor using `ftruncate` to ensure it is empty.
    - A blockstore is created and initialized using the provided workspace and file descriptor.
    - Memory is allocated to store block information for comparison later.
    - A loop iterates over the number of blocks specified, generating random block data for each slot.
    - For each block, the data is checkpointed into the blockstore, and then read back to verify correctness.
    - The function checks that the data read back matches the data written, using `memcmp` and a custom [`blocks_equal`](#blocks_equal) function.
    - It verifies that blocks are evicted or remain in the archive as expected, using `fd_blockstore_archiver_lrw_slot` and [`query_block`](#query_block).
    - Periodically, it checks that all blocks in the block index match the blocks in the archive and the stored memory records.
    - Finally, it logs the key count of the block index and frees the allocated memory before closing the blockstore.
- **Output**: The function does not return a value; it performs tests and logs results to verify the correctness of block archiving and eviction.
- **Functions called**:
    - [`fd_blockstore_init`](fd_blockstore.c.driver.md#fd_blockstore_init)
    - [`fd_blockstore_alloc`](fd_blockstore.h.driver.md#fd_blockstore_alloc)
    - [`blocks_equal`](#blocks_equal)
    - [`query_block`](#query_block)


---
### test\_blockstore\_archive\_big<!-- {{#callable:test_blockstore_archive_big}} -->
The function `test_blockstore_archive_big` tests the blockstore's ability to handle large archives by writing and verifying blocks up to specified indices.
- **Inputs**:
    - `wksp`: A pointer to a workspace object used for memory allocation.
    - `fd`: A file descriptor for the blockstore file.
    - `first_idx_max`: The maximum index for the first set of blocks to be archived.
    - `replay_idx_max`: The maximum index for the replay set of blocks to be archived.
- **Control Flow**:
    - The function begins by truncating the file associated with the file descriptor `fd` to ensure it is empty.
    - It initializes a blockstore with a maximum index of `first_idx_max` and checkpoints blocks with random data sizes for each slot from 1 to `first_idx_max`.
    - The function retrieves the least recently written (LRW) slot from the blockstore after checkpointing the blocks.
    - It then reinitializes the blockstore with a new maximum index of `replay_idx_max` and retrieves the LRW slot again.
    - The function verifies that the new LRW slot is greater than or equal to the previous LRW slot.
    - It queries the blockstore to ensure that blocks between the new LRW slot and `first_idx_max` are present and those between the old and new LRW slots are absent.
- **Output**: The function does not return a value; it performs tests and logs results to verify the blockstore's behavior.
- **Functions called**:
    - [`fd_blockstore_init`](fd_blockstore.c.driver.md#fd_blockstore_init)
    - [`query_block`](#query_block)


---
### test\_blockstore\_archive\_small<!-- {{#callable:test_blockstore_archive_small}} -->
The function `test_blockstore_archive_small` tests the blockstore's ability to handle archiving and reading of a specified number of blocks without eviction, and then attempts to insert additional blocks to verify eviction behavior.
- **Inputs**:
    - `wksp`: A pointer to a workspace object used for memory allocation.
    - `fd`: A file descriptor representing the archive file to be used for block storage.
    - `first_idx_max`: The maximum number of blocks that can be stored in the archive file without eviction.
    - `replay_idx_max`: The maximum index for replaying blocks, used to test the blockstore's reading capabilities.
- **Control Flow**:
    - The function begins by truncating the file associated with the file descriptor `fd` to ensure it is empty.
    - It calls [`test_archive_many_blocks`](#test_archive_many_blocks) to store `first_idx_max` blocks in the archive file, ensuring the blockstore can handle this number without eviction.
    - A blockstore is created and initialized from the file descriptor, and the block index is retrieved.
    - If `first_idx_max` is less than `replay_idx_max`, a warning is logged and the function returns early.
    - The function checks that the block index is fully populated and verifies the last read-write (LRW) and most recent write (MRW) slots are correctly set.
    - It attempts to insert an additional block (at `slot = last_archived + 1`) into the blockstore, which should succeed.
    - The function verifies that the LRW slot has been evicted and the MRW slot is updated to the new slot.
    - Finally, it iterates over the slots from the new LRW slot to the MRW slot, checking that each block can be queried successfully from the block index.
- **Output**: The function does not return a value; it performs tests and logs results, using assertions to verify expected behavior.
- **Functions called**:
    - [`test_archive_many_blocks`](#test_archive_many_blocks)
    - [`fd_blockstore_init`](fd_blockstore.c.driver.md#fd_blockstore_init)


---
### test\_blockstore\_metadata\_invalid<!-- {{#callable:test_blockstore_metadata_invalid}} -->
The function `test_blockstore_metadata_invalid` tests the verification of blockstore metadata with different `fd_size_max` values.
- **Inputs**:
    - `fd`: An integer file descriptor representing the file to be truncated and used in the blockstore operations.
- **Control Flow**:
    - The function begins by truncating the file associated with the file descriptor `fd` to size 0 using `ftruncate` and checks the success of this operation with `FD_TEST`.
    - A `fd_blockstore_t` structure named `blockstore` is declared, and its `shmem->archiver.fd_size_max` is set to `0x6000`.
    - A `fd_blockstore_archiver_t` structure named `metadata` is initialized with `fd_size_max` set to `0x6000`, `head` set to `2`, and `tail` set to `3`.
    - The function verifies the metadata against the blockstore using `fd_blockstore_archiver_verify` and checks the result with `FD_TEST`.
    - The `fd_size_max` of `metadata` is then changed to `0x5000`, and the verification process is repeated with the result checked by `FD_TEST`.
- **Output**: The function does not return any value; it performs tests and assertions to verify the correctness of blockstore metadata.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment and logs a warning if the FD_HAS_INT128 capability is not available, then halts the program.
- **Inputs**:
    - `argc`: The count of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - The function begins by calling `fd_boot` to initialize the environment with the command-line arguments.
    - It logs a warning message indicating that the unit test requires FD_HAS_INT128 capability.
    - The function then calls `fd_halt` to terminate the program.
    - Finally, it returns 0, indicating successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution.



# Purpose
The provided C source code file is a comprehensive implementation of a block storage system, which is designed to manage and manipulate blocks of data in a shared memory environment. The code defines several functions that handle the creation, joining, leaving, deletion, and initialization of a block store, as well as operations related to block and transaction management. The primary purpose of this code is to facilitate the storage and retrieval of data blocks, manage their metadata, and ensure data integrity through various checks and balances.

Key technical components include functions for managing shared memory allocations, handling block and transaction maps, and performing operations such as inserting, removing, and querying blocks and shreds. The code also includes mechanisms for logging and error handling to ensure robustness. The block store is designed to be part of a larger system, likely involving distributed data processing or storage, as indicated by the use of shared memory and workspace concepts. The code provides a public API for interacting with the block store, allowing external systems to perform operations such as querying block hashes, updating block heights, and managing transaction data. Overall, this file is a critical component of a larger software system that requires efficient and reliable block storage management.
# Imports and Dependencies

---
- `fd_blockstore.h`
- `fcntl.h`
- `string.h`
- `stdio.h`
- `unistd.h`
- `errno.h`


# Functions

---
### fd\_blockstore\_new<!-- {{#callable:fd_blockstore_new}} -->
The `fd_blockstore_new` function initializes a new blockstore in shared memory, setting up various data structures and ensuring proper alignment and configuration.
- **Inputs**:
    - `shmem`: A pointer to the shared memory region where the blockstore will be initialized.
    - `wksp_tag`: An unsigned long integer representing the workspace tag for the blockstore.
    - `seed`: An unsigned long integer used as a seed for random number generation within the blockstore.
    - `shred_max`: An unsigned long integer specifying the maximum number of shreds the blockstore can handle.
    - `block_max`: An unsigned long integer specifying the maximum number of blocks the blockstore can handle.
    - `idx_max`: An unsigned long integer specifying the maximum index size for the blockstore.
    - `txn_max`: An unsigned long integer specifying the maximum number of transactions the blockstore can handle.
- **Control Flow**:
    - Ensure `block_max` is a power of two and calculate `lock_cnt` as the minimum of `block_max` and `BLOCK_INFO_LOCK_CNT`.
    - Cast `shmem` to `fd_blockstore_shmem_t` and check for null or misalignment, logging warnings and returning NULL if issues are found.
    - Verify `wksp_tag` is non-zero and that `shmem` is part of a workspace, logging warnings and returning NULL if not.
    - Ensure `shred_max` is a power of two, rounding up if necessary and logging a warning.
    - Clear the memory region for the blockstore using `fd_memset`.
    - Initialize various data structures using `FD_SCRATCH_ALLOC_APPEND` for shreds, shred pool, shred map, blocks, block map, block index, slot deque, transaction map, and allocator.
    - Finalize the scratch allocation and verify alignment and footprint size.
    - Initialize shred pool, shred map, and block map with respective functions, and clear the blocks memory.
    - Free map slot parameters for each block to ensure proper state.
    - Set global addresses for block index, slot deque, transaction map, and allocator in the blockstore shared memory structure.
    - Initialize the blockstore's archiver and set initial values for `lps`, `hcs`, and `wmk`.
    - Set `shred_max`, `block_max`, `idx_max`, and `txn_max` in the blockstore shared memory structure.
    - Use memory fences to ensure proper ordering and set the blockstore's magic number.
    - Return the initialized blockstore shared memory pointer.
- **Output**: A pointer to the initialized blockstore in shared memory, or NULL if initialization fails due to alignment or configuration issues.
- **Functions called**:
    - [`fd_blockstore_align`](fd_blockstore.h.driver.md#fd_blockstore_align)
    - [`fd_blockstore_footprint`](fd_blockstore.h.driver.md#fd_blockstore_footprint)


---
### fd\_blockstore\_join<!-- {{#callable:fd_blockstore_join}} -->
The `fd_blockstore_join` function initializes and joins a blockstore structure with shared memory, ensuring proper alignment and configuration before setting up various internal components.
- **Inputs**:
    - `ljoin`: A pointer to a `fd_blockstore_t` structure that will be initialized and joined.
    - `shblockstore`: A pointer to a `fd_blockstore_shmem_t` structure representing the shared memory blockstore to be joined.
- **Control Flow**:
    - Cast `ljoin` to `fd_blockstore_t *` and `shblockstore` to `fd_blockstore_shmem_t *`.
    - Check if `join` is NULL and log a warning if so, returning NULL.
    - Check if `join` is misaligned and log a warning if so, returning NULL.
    - Check if `blockstore` is NULL and log a warning if so, returning NULL.
    - Check if `blockstore` is misaligned and log a warning if so, returning NULL.
    - Check if `blockstore->magic` is not equal to `FD_BLOCKSTORE_MAGIC` and log a warning if so, returning NULL.
    - Initialize scratch allocation with `shblockstore`.
    - Allocate memory for `blockstore`, `shreds`, `shred_pool`, `shred_map`, `blocks`, and `block_map` using `FD_SCRATCH_ALLOC_APPEND`.
    - Finalize scratch allocation with `fd_blockstore_align()`.
    - Assign `blockstore` to `join->shmem`.
    - Join `shred_pool`, `shred_map`, and `block_map` using their respective join functions.
    - Verify the integrity of `shred_pool`, `shred_map`, and `block_map` using their respective verify functions.
    - Return the `join` pointer.
- **Output**: Returns a pointer to the initialized and joined `fd_blockstore_t` structure, or NULL if any errors occur during the process.
- **Functions called**:
    - [`fd_blockstore_align`](fd_blockstore.h.driver.md#fd_blockstore_align)


---
### fd\_blockstore\_leave<!-- {{#callable:fd_blockstore_leave}} -->
The `fd_blockstore_leave` function safely detaches a blockstore from its associated resources and returns a pointer to the blockstore.
- **Inputs**:
    - `blockstore`: A pointer to an `fd_blockstore_t` structure representing the blockstore to be detached.
- **Control Flow**:
    - Check if the `blockstore` pointer is NULL; if so, log a warning and return NULL.
    - Retrieve the workspace containing the blockstore using `fd_wksp_containing`; if not found, log a warning and return NULL.
    - Call `fd_buf_shred_pool_leave` to detach the shred pool associated with the blockstore.
    - Call `fd_buf_shred_map_leave` to detach the shred map associated with the blockstore.
    - Call `fd_block_map_leave` to detach the block map associated with the blockstore.
    - Call `fd_block_idx_leave` to detach the block index associated with the blockstore.
    - Call `fd_slot_deque_leave` to detach the slot deque associated with the blockstore.
    - Call `fd_txn_map_leave` to detach the transaction map associated with the blockstore.
    - Call `fd_alloc_leave` to detach the allocator associated with the blockstore.
    - Return the blockstore pointer cast to a void pointer.
- **Output**: Returns a void pointer to the blockstore if successful, or NULL if an error occurs during detachment.
- **Functions called**:
    - [`fd_blockstore_slot_deque`](fd_blockstore.h.driver.md#fd_blockstore_slot_deque)
    - [`fd_blockstore_alloc`](fd_blockstore.h.driver.md#fd_blockstore_alloc)


---
### fd\_blockstore\_delete<!-- {{#callable:fd_blockstore_delete}} -->
The `fd_blockstore_delete` function deletes a blockstore by validating its alignment and magic number, removing associated structures, and resetting its magic number.
- **Inputs**:
    - `shblockstore`: A pointer to the shared memory blockstore to be deleted.
- **Control Flow**:
    - Cast the input `shblockstore` to a `fd_blockstore_t` pointer.
    - Check if the `blockstore` is NULL and log a warning if so, returning NULL.
    - Verify the alignment of `blockstore` using `fd_ulong_is_aligned` and log a warning if misaligned, returning NULL.
    - Check the magic number of `blockstore->shmem` against `FD_BLOCKSTORE_MAGIC` and log a warning if it doesn't match, returning NULL.
    - Retrieve the workspace containing the blockstore using `fd_wksp_containing` and log a warning if not found, returning NULL.
    - Delete various structures associated with the blockstore, including shred pool, shred map, block map, block index, slot deque, transaction map, and allocator, using respective delete functions.
    - Use memory fences (`FD_COMPILER_MFENCE`) to ensure memory operations are completed before and after setting the magic number to 0.
    - Return the `blockstore` pointer.
- **Output**: Returns a pointer to the deleted `fd_blockstore_t` if successful, or NULL if any validation fails.
- **Functions called**:
    - [`fd_blockstore_align`](fd_blockstore.h.driver.md#fd_blockstore_align)
    - [`fd_blockstore_slot_deque`](fd_blockstore.h.driver.md#fd_blockstore_slot_deque)
    - [`fd_blockstore_alloc`](fd_blockstore.h.driver.md#fd_blockstore_alloc)


---
### fd\_blockstore\_init<!-- {{#callable:fd_blockstore_init}} -->
The `fd_blockstore_init` function initializes a blockstore structure with a given file descriptor, maximum file size, and slot bank information, setting up necessary metadata and preparing the block map for use.
- **Inputs**:
    - `blockstore`: A pointer to an `fd_blockstore_t` structure that will be initialized.
    - `fd`: An integer representing the file descriptor for the archive file.
    - `fd_size_max`: An unsigned long representing the maximum size of the archive file.
    - `slot_bank`: A constant pointer to an `fd_slot_bank_t` structure containing slot bank information used for initialization.
- **Control Flow**:
    - Check if `fd_size_max` is less than `FD_BLOCKSTORE_ARCHIVE_MIN_SIZE`; if so, log an error and return `NULL`.
    - Set `blockstore->shmem->archiver.fd_size_max` to `fd_size_max`.
    - Seek to the end of the file using `lseek(fd, 0, SEEK_END)`.
    - Initialize `smr` with `slot_bank->slot` and set `blockstore->shmem->lps`, `hcs`, and `wmk` to `smr`.
    - Prepare the block map with `fd_block_map_prepare`, using `smr` and `query` as parameters.
    - If preparation fails, log an error and return `NULL`.
    - Initialize the `fd_block_info_t` structure `ele` with values from `slot_bank`, setting various fields such as `slot`, `parent_slot`, `block_height`, `block_hash`, `bank_hash`, `in_poh_hash`, and `flags`.
    - Set several indices and counters in `ele` to zero, and call `fd_block_set_null` on `ele->data_complete_idxs`.
    - Publish the block map with `fd_block_map_publish(query)`.
    - Return the initialized `blockstore` pointer.
- **Output**: Returns a pointer to the initialized `fd_blockstore_t` structure, or `NULL` if initialization fails.


---
### fd\_blockstore\_fini<!-- {{#callable:fd_blockstore_fini}} -->
The `fd_blockstore_fini` function finalizes a blockstore by removing all slots, freeing all associated allocations.
- **Inputs**:
    - `blockstore`: A pointer to an `fd_blockstore_t` structure representing the blockstore to be finalized.
- **Control Flow**:
    - Retrieve the first element of the block map using `fd_block_map_shele` and store it in `ele0`.
    - Determine the maximum number of elements in the block map using `fd_block_map_ele_max` and store it in `block_max`.
    - Iterate over each element index from 0 to `block_max - 1`.
    - For each element, check if the slot is unused (i.e., `ele->slot == 0`), and if so, continue to the next iteration.
    - If the slot is used, call [`fd_blockstore_slot_remove`](#fd_blockstore_slot_remove) to remove the slot from the blockstore.
- **Output**: The function does not return a value; it performs cleanup operations on the blockstore.
- **Functions called**:
    - [`fd_blockstore_slot_remove`](#fd_blockstore_slot_remove)


---
### fd\_txn\_key\_equal<!-- {{#callable:fd_txn_key_equal}} -->
The `fd_txn_key_equal` function compares two transaction keys to determine if they are equal.
- **Inputs**:
    - `k0`: A pointer to the first transaction key of type `fd_txn_key_t` to be compared.
    - `k1`: A pointer to the second transaction key of type `fd_txn_key_t` to be compared.
- **Control Flow**:
    - Iterates over each element of the transaction keys, comparing corresponding elements.
    - If any element in the keys differs, the function returns 0, indicating the keys are not equal.
    - If all elements are equal, the function returns 1, indicating the keys are equal.
- **Output**: Returns an integer: 1 if the transaction keys are equal, 0 otherwise.


---
### fd\_txn\_key\_hash<!-- {{#callable:fd_txn_key_hash}} -->
The `fd_txn_key_hash` function computes a hash value for a transaction key using a seed and XOR operations.
- **Inputs**:
    - `k`: A pointer to a constant `fd_txn_key_t` structure, which contains the transaction key to be hashed.
    - `seed`: An unsigned long integer used as the initial value for the hash computation.
- **Control Flow**:
    - Initialize the hash value `h` with the provided `seed`.
    - Iterate over each `ulong` element in the transaction key `k->v`, which is divided by the size of `ulong` to determine the number of iterations.
    - For each element, update the hash `h` by XORing it with the current element of `k->v`.
    - Return the final computed hash value `h`.
- **Output**: The function returns an unsigned long integer representing the computed hash value of the transaction key.


---
### fd\_blockstore\_slot\_remove<!-- {{#callable:fd_blockstore_slot_remove}} -->
The `fd_blockstore_slot_remove` function removes a specified slot from the blockstore, ensuring it is not replaying and handling its parent and associated shreds.
- **Inputs**:
    - `blockstore`: A pointer to the `fd_blockstore_t` structure representing the blockstore from which the slot will be removed.
    - `slot`: An unsigned long integer representing the slot number to be removed from the blockstore.
- **Control Flow**:
    - Log the function entry with the slot number.
    - Initialize a query structure and set error to `FD_MAP_ERR_AGAIN`.
    - Enter a loop to query the block map for the slot until it is not `FD_MAP_ERR_AGAIN`.
    - If the slot is not found (`FD_MAP_ERR_KEY`), return immediately.
    - Check if the block is replaying; if so, log a warning and return.
    - Retrieve the parent slot and received index from the block info.
    - Remove the slot from the block map with blocking flag.
    - Ensure the block info test for the slot returns false.
    - Prepare the parent slot in the block map and unlink the slot from its parent if it is not published.
    - Remove all shreds associated with the slot using the received index.
- **Output**: The function does not return a value; it performs operations to remove a slot and its associated data from the blockstore.
- **Functions called**:
    - [`fd_blockstore_block_info_test`](#fd_blockstore_block_info_test)
    - [`fd_blockstore_shred_remove`](#fd_blockstore_shred_remove)


---
### fd\_blockstore\_publish<!-- {{#callable:fd_blockstore_publish}} -->
The `fd_blockstore_publish` function updates the watermark of a blockstore and performs a breadth-first search to prune or archive slots, ensuring that the blockstore's state is consistent with the new watermark.
- **Inputs**:
    - `blockstore`: A pointer to an `fd_blockstore_t` structure representing the blockstore to be updated.
    - `fd`: An integer file descriptor, marked as unused in this function.
    - `wmk`: An unsigned long integer representing the new watermark to be set for the blockstore.
- **Control Flow**:
    - Log the current watermark and the new watermark to be set.
    - Check if the current watermark is equal to the new watermark; if so, log a warning and return.
    - Retrieve the slot deque from the blockstore and clear it for reuse.
    - Push the current watermark onto the deque to start the breadth-first search (BFS).
    - While the deque is not empty, pop a slot from the head of the deque.
    - Prepare the block map for the current slot; if preparation fails, log a warning and continue to the next slot.
    - Retrieve the block information for the current slot and add its children to the deque, unless they match the new watermark.
    - Cancel the block map query and remove the slot from the blockstore.
    - After the BFS, remove any orphaned blocks or shreds that are less than the new watermark.
    - Update the blockstore's watermark to the new value.
- **Output**: The function does not return a value; it modifies the state of the blockstore by updating its watermark and potentially removing or archiving slots.
- **Functions called**:
    - [`fd_blockstore_slot_deque`](fd_blockstore.h.driver.md#fd_blockstore_slot_deque)
    - [`fd_blockstore_slot_remove`](#fd_blockstore_slot_remove)


---
### fd\_blockstore\_shred\_remove<!-- {{#callable:fd_blockstore_shred_remove}} -->
The `fd_blockstore_shred_remove` function removes a shred from the blockstore's shred map and releases it back to the shred pool.
- **Inputs**:
    - `blockstore`: A pointer to the `fd_blockstore_t` structure representing the blockstore from which the shred is to be removed.
    - `slot`: An unsigned long integer representing the slot number of the shred to be removed.
    - `idx`: An unsigned integer representing the index of the shred within the specified slot to be removed.
- **Control Flow**:
    - Create a `fd_shred_key_t` key using the provided `slot` and `idx` values.
    - Initialize a `fd_buf_shred_map_query_t` query array with zero values.
    - Call `fd_buf_shred_map_remove` to remove the shred from the shred map using the key, and check for errors.
    - If the map is corrupt, log an error and exit.
    - If the removal is successful, retrieve the shred using `fd_buf_shred_map_query_ele`.
    - Release the shred back to the shred pool using `fd_buf_shred_pool_release` and check for errors.
    - Log errors if the pool is invalid or corrupt, and ensure no errors occurred.
- **Output**: The function does not return a value; it performs operations on the blockstore and logs errors if any issues occur.


---
### fd\_blockstore\_shred\_insert<!-- {{#callable:fd_blockstore_shred_insert}} -->
The `fd_blockstore_shred_insert` function inserts a shred into a blockstore, updating metadata and handling potential conflicts with existing shreds.
- **Inputs**:
    - `blockstore`: A pointer to the `fd_blockstore_t` structure representing the blockstore where the shred will be inserted.
    - `shred`: A constant pointer to the `fd_shred_t` structure representing the shred to be inserted.
- **Control Flow**:
    - Check if the shred is a data shred; if not, log an error and exit.
    - Check if the shred's slot is below the watermark; if so, log a debug message and exit.
    - Create a key from the shred's slot and index.
    - Check if the shred key already exists in the blockstore; if it does, compare payloads and update equivalence vocations if necessary, then exit.
    - Acquire a new shred element from the shred pool; log an error if the pool is empty or corrupt.
    - Copy the shred data into the new element and insert it into the shred map; log an error if insertion fails.
    - Check if the blockstore has metadata for the shred's slot; if not, prepare and initialize a new block info entry.
    - Advance the buffered index watermark and update data complete indices based on the new shred.
    - Update the received index and slot complete index based on the shred's flags.
    - Check and update the parent slot's child slots if necessary, logging warnings if issues arise.
- **Output**: The function does not return a value; it modifies the blockstore and its metadata in place.
- **Functions called**:
    - [`fd_blockstore_shred_test`](#fd_blockstore_shred_test)
    - [`fd_blockstore_block_info_test`](#fd_blockstore_block_info_test)


---
### fd\_blockstore\_shred\_test<!-- {{#callable:fd_blockstore_shred_test}} -->
The `fd_blockstore_shred_test` function checks if a specific shred (identified by slot and index) exists in the blockstore's shred map and handles potential corruption errors.
- **Inputs**:
    - `blockstore`: A pointer to an `fd_blockstore_t` structure representing the blockstore where the shred map is queried.
    - `slot`: An unsigned long integer representing the slot number of the shred to be tested.
    - `idx`: An unsigned integer representing the index of the shred within the specified slot.
- **Control Flow**:
    - Initialize a `fd_shred_key_t` structure with the given slot and index.
    - Declare a `fd_buf_shred_map_query_t` array for querying the shred map.
    - Enter an infinite loop to repeatedly attempt querying the shred map.
    - Call `fd_buf_shred_map_query_try` to attempt querying the shred map with the given key.
    - If the query returns a corruption error (`FD_MAP_ERR_CORRUPT`), log an error message and terminate the program.
    - If the query does not find the key (`FD_MAP_ERR_KEY`), return false (0).
    - If the query is successful, return true (1).
- **Output**: Returns an integer indicating whether the shred exists (1) or not (0), or logs an error and terminates if corruption is detected.


---
### fd\_blockstore\_block\_info\_test<!-- {{#callable:fd_blockstore_block_info_test}} -->
The `fd_blockstore_block_info_test` function checks if a block information entry for a given slot exists in the block map of a blockstore.
- **Inputs**:
    - `blockstore`: A pointer to an `fd_blockstore_t` structure representing the blockstore to be queried.
    - `slot`: An unsigned long integer representing the slot number for which the block information is being queried.
- **Control Flow**:
    - Initialize `err` to `FD_MAP_ERR_AGAIN` to start the loop.
    - Enter a loop that continues while `err` is `FD_MAP_ERR_AGAIN`.
    - Inside the loop, declare a `fd_block_map_query_t` array `query` initialized to zero.
    - Attempt to query the block map using `fd_block_map_query_try` with the given `slot` and store the result in `err`.
    - If `err` is `FD_MAP_ERR_AGAIN`, continue the loop to retry the query.
    - If `err` is `FD_MAP_ERR_KEY`, return 0 indicating the block information does not exist.
    - If the query is successful, test the query with `fd_block_map_query_test`.
    - Exit the loop and return 1 indicating the block information exists.
- **Output**: Returns 1 if the block information for the given slot exists, otherwise returns 0 if it does not exist.


---
### fd\_blockstore\_block\_map\_query<!-- {{#callable:fd_blockstore_block_map_query}} -->
The `fd_blockstore_block_map_query` function retrieves metadata for a specific block slot from a blockstore's block map.
- **Inputs**:
    - `blockstore`: A pointer to an `fd_blockstore_t` structure representing the blockstore from which the block metadata is to be queried.
    - `slot`: An unsigned long integer representing the slot number for which the block metadata is being queried.
- **Control Flow**:
    - Initialize a `fd_block_map_query_t` structure `quer` to zero.
    - Call `fd_block_map_query_try` with the blockstore's block map, the slot, and `quer` to attempt to retrieve the block metadata.
    - Retrieve the block metadata using `fd_block_map_query_ele` and store it in `meta`.
    - If `fd_block_map_query_try` returns an error, return `NULL`.
    - Otherwise, return the retrieved block metadata `meta`.
- **Output**: A pointer to an `fd_block_info_t` structure containing the block metadata for the specified slot, or `NULL` if an error occurs.


---
### fd\_blockstore\_block\_info\_remove<!-- {{#callable:fd_blockstore_block_info_remove}} -->
The `fd_blockstore_block_info_remove` function attempts to remove a block information entry from a blockstore's block map for a given slot.
- **Inputs**:
    - `blockstore`: A pointer to the `fd_blockstore_t` structure representing the blockstore from which the block information is to be removed.
    - `slot`: An unsigned long integer representing the slot number of the block information to be removed.
- **Control Flow**:
    - Initialize `err` to `FD_MAP_ERR_AGAIN` to enter the loop.
    - Enter a loop that continues while `err` is `FD_MAP_ERR_AGAIN`.
    - Call `fd_block_map_remove` to attempt to remove the block information for the given slot from the block map.
    - If `fd_block_map_remove` returns `FD_MAP_ERR_KEY`, indicating the slot is missing, return `FD_BLOCKSTORE_ERR_SLOT_MISSING`.
    - If the removal is successful, exit the loop and return `FD_BLOCKSTORE_SUCCESS`.
- **Output**: Returns `FD_BLOCKSTORE_SUCCESS` if the block information is successfully removed, or `FD_BLOCKSTORE_ERR_SLOT_MISSING` if the slot is not found in the block map.


---
### fd\_buf\_shred\_query\_copy\_data<!-- {{#callable:fd_buf_shred_query_copy_data}} -->
The `fd_buf_shred_query_copy_data` function attempts to copy data from a shred in a blockstore to a provided buffer, returning the size of the copied data or an error code.
- **Inputs**:
    - `blockstore`: A pointer to the `fd_blockstore_t` structure representing the blockstore from which data is queried.
    - `slot`: An unsigned long integer representing the slot number of the shred to be queried.
    - `idx`: An unsigned integer representing the index of the shred within the slot to be queried.
    - `buf`: A pointer to a buffer where the data from the shred will be copied.
    - `buf_sz`: An unsigned long integer representing the size of the buffer `buf`.
- **Control Flow**:
    - Check if `buf_sz` is less than `FD_SHRED_MAX_SZ`; if so, return -1 indicating an error.
    - Initialize a `fd_shred_key_t` structure with the given `slot` and `idx`.
    - Enter a loop that continues while `err` is `FD_MAP_ERR_AGAIN`.
    - Within the loop, attempt to query the shred map using `fd_buf_shred_map_query_try` with the key and check for errors.
    - If the error is `FD_MAP_ERR_KEY`, return -1 indicating the key was not found.
    - If the error is `FD_MAP_ERR_CORRUPT`, log an error and exit.
    - If the error is `FD_MAP_ERR_AGAIN`, continue the loop to retry the query.
    - If no errors occur, retrieve the shred data, calculate its size, and copy it to `buf`.
    - Test the query with `fd_buf_shred_map_query_test` and update `err`.
    - After exiting the loop, assert that `err` is zero using `FD_TEST`.
- **Output**: Returns the size of the copied data as a long integer, or -1 if an error occurs.


---
### fd\_blockstore\_block\_hash\_query<!-- {{#callable:fd_blockstore_block_hash_query}} -->
The `fd_blockstore_block_hash_query` function retrieves the block hash for a given slot from a blockstore.
- **Inputs**:
    - `blockstore`: A pointer to the `fd_blockstore_t` structure representing the blockstore from which the block hash is to be queried.
    - `slot`: An unsigned long integer representing the slot number for which the block hash is to be queried.
    - `hash_out`: A pointer to an `fd_hash_t` structure where the retrieved block hash will be stored.
- **Control Flow**:
    - The function enters an infinite loop to repeatedly attempt querying the block map for the specified slot.
    - It initializes a `fd_block_map_query_t` structure to store the query result.
    - The function calls `fd_block_map_query_try` to attempt querying the block map with the given slot.
    - If the query returns `FD_MAP_ERR_KEY`, the function returns `FD_BLOCKSTORE_ERR_KEY`, indicating the slot is not found.
    - If the query returns `FD_MAP_ERR_AGAIN`, the loop continues to retry the query.
    - Upon a successful query, the block hash is retrieved from the `fd_block_info_t` structure and stored in `hash_out`.
    - The function checks if the query was successful using `fd_block_map_query_test` and returns `FD_BLOCKSTORE_SUCCESS` if so.
- **Output**: The function returns an integer status code: `FD_BLOCKSTORE_SUCCESS` on success, `FD_BLOCKSTORE_ERR_KEY` if the slot is not found, or continues retrying if the query is not yet successful.


---
### fd\_blockstore\_bank\_hash\_query<!-- {{#callable:fd_blockstore_bank_hash_query}} -->
The `fd_blockstore_bank_hash_query` function retrieves the bank hash for a given slot from a blockstore.
- **Inputs**:
    - `blockstore`: A pointer to an `fd_blockstore_t` structure representing the blockstore from which the bank hash is to be queried.
    - `slot`: An unsigned long integer representing the slot number for which the bank hash is to be queried.
    - `hash_out`: A pointer to an `fd_hash_t` structure where the retrieved bank hash will be stored.
- **Control Flow**:
    - The function enters an infinite loop to repeatedly attempt querying the block map for the specified slot.
    - It initializes a `fd_block_map_query_t` structure to store the query result.
    - The function calls `fd_block_map_query_try` to attempt querying the block map for the given slot.
    - If the query returns `FD_MAP_ERR_KEY`, the function returns `FD_BLOCKSTORE_ERR_KEY`, indicating the slot is not found.
    - If the query returns `FD_MAP_ERR_AGAIN`, the loop continues to retry the query.
    - If the query is successful, the bank hash from the queried block information is stored in `hash_out`.
    - The function checks if the query test is successful using `fd_block_map_query_test`.
    - If the query test is successful, the function returns `FD_BLOCKSTORE_SUCCESS`.
- **Output**: The function returns an integer status code: `FD_BLOCKSTORE_SUCCESS` if the bank hash is successfully retrieved, or `FD_BLOCKSTORE_ERR_KEY` if the slot is not found.


---
### fd\_blockstore\_parent\_slot\_query<!-- {{#callable:fd_blockstore_parent_slot_query}} -->
The `fd_blockstore_parent_slot_query` function retrieves the parent slot of a given slot from a blockstore.
- **Inputs**:
    - `blockstore`: A pointer to an `fd_blockstore_t` structure, representing the blockstore from which the parent slot is to be queried.
    - `slot`: An unsigned long integer representing the slot for which the parent slot is to be queried.
- **Control Flow**:
    - Initialize `err` to `FD_MAP_ERR_AGAIN` and `parent_slot` to `FD_SLOT_NULL`.
    - Enter a loop that continues while `err` is `FD_MAP_ERR_AGAIN`.
    - Within the loop, initialize a `fd_block_map_query_t` array `query` with one element set to zero.
    - Call `fd_block_map_query_try` with the blockstore's block map, the slot, and the query to attempt to retrieve the block information.
    - If `err` is `FD_MAP_ERR_KEY`, return `FD_SLOT_NULL` as the slot is not found.
    - If `err` is `FD_MAP_ERR_AGAIN`, continue the loop to retry the query.
    - Retrieve the block information using `fd_block_map_query_ele` and set `parent_slot` to the `parent_slot` field of the block information.
    - Call `fd_block_map_query_test` to finalize the query and update `err`.
    - Exit the loop when `err` is no longer `FD_MAP_ERR_AGAIN`.
    - Return the `parent_slot`.
- **Output**: The function returns an unsigned long integer representing the parent slot of the given slot, or `FD_SLOT_NULL` if the slot is not found.


---
### fd\_blockstore\_slice\_query<!-- {{#callable:fd_blockstore_slice_query}} -->
The `fd_blockstore_slice_query` function retrieves and copies a range of shreds from a blockstore into a buffer, ensuring the buffer size is not exceeded.
- **Inputs**:
    - `blockstore`: A pointer to the `fd_blockstore_t` structure representing the blockstore from which shreds are queried.
    - `slot`: An unsigned long integer representing the slot number for which shreds are being queried.
    - `start_idx`: An unsigned integer representing the starting index of the shreds to be queried.
    - `end_idx`: An unsigned integer representing the ending index (inclusive) of the shreds to be queried.
    - `max`: An unsigned long integer representing the maximum size of the buffer to ensure it is not exceeded.
    - `buf`: A pointer to an unsigned char array where the queried shreds' payloads will be copied.
    - `buf_sz`: A pointer to an unsigned long integer where the total size of the copied payloads will be stored.
- **Control Flow**:
    - Initialize an offset variable `off` to zero to track the current position in the buffer.
    - Iterate over the indices from `start_idx` to `end_idx` inclusive.
    - For each index, perform a speculative copy of the shred data by querying the shred map with the current slot and index.
    - Handle errors such as corrupt map, missing key, or retry if necessary.
    - Retrieve the shred's payload and its size, checking if adding it to the buffer would exceed the `max` size.
    - If the payload size is valid, copy the payload into the buffer at the current offset and update the offset.
    - Continue the loop until all specified shreds are successfully copied.
    - Store the total size of the copied payloads in `buf_sz`.
- **Output**: Returns `FD_BLOCKSTORE_SUCCESS` on successful completion, or an error code if an issue occurs during the query or copy process.


---
### fd\_blockstore\_shreds\_complete<!-- {{#callable:fd_blockstore_shreds_complete}} -->
The `fd_blockstore_shreds_complete` function checks if all shreds for a given slot in a blockstore are complete and returns a boolean indicating the completion status.
- **Inputs**:
    - `blockstore`: A pointer to an `fd_blockstore_t` structure representing the blockstore to query.
    - `slot`: An unsigned long integer representing the slot number to check for shred completion.
- **Control Flow**:
    - Initialize a `fd_block_map_query_t` structure and set `complete` to 0 and `err` to `FD_MAP_ERR_AGAIN`.
    - Enter a loop that continues while `err` is `FD_MAP_ERR_AGAIN`.
    - Attempt to query the block map for the given slot using `fd_block_map_query_try`.
    - Retrieve the block information using `fd_block_map_query_ele`.
    - If the error is `FD_MAP_ERR_KEY`, return 0 indicating the slot is not found.
    - If the error is `FD_MAP_ERR_AGAIN`, continue the loop to retry the query.
    - Check if the `buffered_idx` is not `FD_SHRED_IDX_NULL` and if `slot_complete_idx` equals `buffered_idx` to determine if the shreds are complete.
    - Test the query with `fd_block_map_query_test` and update `err`.
    - Return the value of `complete` indicating whether the shreds are complete.
- **Output**: An integer value, where 1 indicates that all shreds for the specified slot are complete, and 0 indicates they are not.


---
### fd\_blockstore\_block\_map\_query\_volatile<!-- {{#callable:fd_blockstore_block_map_query_volatile}} -->
The function `fd_blockstore_block_map_query_volatile` retrieves block information for a given slot from a blockstore, either from an index or directly from a block map, and handles potential errors in accessing the data.
- **Inputs**:
    - `blockstore`: A pointer to the `fd_blockstore_t` structure representing the blockstore from which block information is to be queried.
    - `fd`: An integer file descriptor used for seeking and reading block information from a file if necessary.
    - `slot`: An unsigned long integer representing the slot number for which block information is being queried.
    - `block_info_out`: A pointer to an `fd_block_info_t` structure where the retrieved block information will be stored.
- **Control Flow**:
    - Initialize a pointer to the block index using `fd_blockstore_block_idx` function.
    - Set an offset variable `off` to `ULONG_MAX` and enter an infinite loop to query the block index for the given slot.
    - If a valid index entry is found, update `off` with the offset from the index entry and break the loop.
    - Check if `off` is less than `ULONG_MAX` to determine if a non-archival query is possible.
    - If so, attempt to seek to the offset in the file using `lseek` and read the block information into `block_info_out` using `fd_io_read`.
    - If the seek or read fails, log a warning and return `FD_BLOCKSTORE_ERR_SLOT_MISSING`.
    - If the offset is not valid, enter a loop to query the block map for the slot using `fd_block_map_query_try`.
    - If the query returns a key error, return `FD_BLOCKSTORE_ERR_SLOT_MISSING`.
    - Copy the queried block information to `block_info_out` and test the query for success.
    - Return `FD_BLOCKSTORE_SUCCESS` if successful.
- **Output**: Returns an integer status code: `FD_BLOCKSTORE_SUCCESS` on success, or `FD_BLOCKSTORE_ERR_SLOT_MISSING` if the slot is missing or an error occurs during the query.


---
### fd\_blockstore\_txn\_query<!-- {{#callable:fd_blockstore_txn_query}} -->
The `fd_blockstore_txn_query` function retrieves a transaction map entry from a blockstore using a given signature.
- **Inputs**:
    - `blockstore`: A pointer to the `fd_blockstore_t` structure representing the blockstore from which the transaction map is queried.
    - `sig`: A constant unsigned character array of size `FD_ED25519_SIG_SZ` representing the signature used to query the transaction map.
- **Control Flow**:
    - A `fd_txn_key_t` key is created and initialized by copying the provided signature into it.
    - The function calls `fd_txn_map_query` with the transaction map obtained from the blockstore and the key to retrieve the transaction map entry.
- **Output**: Returns a pointer to the `fd_txn_map_t` structure representing the transaction map entry corresponding to the given signature, or `NULL` if not found.


---
### fd\_blockstore\_txn\_query\_volatile<!-- {{#callable:fd_blockstore_txn_query_volatile}} -->
The `fd_blockstore_txn_query_volatile` function attempts to query a transaction from a blockstore using a signature and returns transaction data if found, handling both archival and non-archival cases.
- **Inputs**:
    - `blockstore`: A pointer to the blockstore structure from which the transaction is queried.
    - `fd`: A file descriptor used for reading transaction data from a file if necessary.
    - `sig`: A constant array of unsigned characters representing the transaction signature to query.
    - `txn_out`: A pointer to a transaction map structure where the queried transaction data will be stored.
    - `blk_ts`: A pointer to a long where the block timestamp will be stored if found.
    - `blk_flags`: A pointer to an unsigned character where the block flags will be stored if found.
    - `txn_data_out`: An array of unsigned characters where the transaction data will be stored if found.
- **Control Flow**:
    - The function begins by checking if the `BLOCK_ARCHIVING` flag is set; if not, it immediately returns `FD_BLOCKSTORE_ERR_SLOT_MISSING`.
    - If `BLOCK_ARCHIVING` is enabled, it retrieves the workspace and transaction map from the blockstore.
    - It attempts to find the transaction map entry using the provided signature; if not found, it returns `FD_BLOCKSTORE_ERR_TXN_MISSING`.
    - The function then queries the block index for the transaction's slot to determine the offset; if not found, it defaults to `ULONG_MAX`.
    - If the offset is valid (less than `ULONG_MAX`), it seeks to the offset in the file and reads the block information and transaction data, returning `FD_BLOCKSTORE_SUCCESS` if successful.
    - If the offset is not valid, it queries the block map for the transaction's slot, retrieves the block data, and copies the transaction data to `txn_data_out`, returning `FD_BLOCKSTORE_SUCCESS` if successful.
- **Output**: The function returns an integer status code indicating success (`FD_BLOCKSTORE_SUCCESS`) or various error conditions (`FD_BLOCKSTORE_ERR_SLOT_MISSING`, `FD_BLOCKSTORE_ERR_TXN_MISSING`).
- **Functions called**:
    - [`fd_blockstore_wksp`](fd_blockstore.h.driver.md#fd_blockstore_wksp)


---
### fd\_blockstore\_block\_height\_update<!-- {{#callable:fd_blockstore_block_height_update}} -->
The `fd_blockstore_block_height_update` function updates the block height of a specific slot in the blockstore's block map.
- **Inputs**:
    - `blockstore`: A pointer to the `fd_blockstore_t` structure, representing the blockstore where the block height needs to be updated.
    - `slot`: An unsigned long integer representing the slot number for which the block height is to be updated.
    - `height`: An unsigned long integer representing the new block height to be set for the specified slot.
- **Control Flow**:
    - Initialize a `fd_block_map_query_t` query array with zero values.
    - Call `fd_block_map_prepare` to prepare the block map for the specified slot in blocking mode.
    - Retrieve the block information for the specified slot using `fd_block_map_query_ele`.
    - Check if there was an error in preparation or if the slot in the block information does not match the specified slot; if so, cancel the query and return.
    - Update the block height of the block information to the specified height.
    - Publish the updated block information using `fd_block_map_publish`.
- **Output**: The function does not return any value; it updates the block height in the blockstore's block map for the specified slot.


---
### fd\_blockstore\_block\_height\_query<!-- {{#callable:fd_blockstore_block_height_query}} -->
The `fd_blockstore_block_height_query` function retrieves the block height for a given slot from a blockstore.
- **Inputs**:
    - `blockstore`: A pointer to an `fd_blockstore_t` structure representing the blockstore from which the block height is to be queried.
    - `slot`: An unsigned long integer representing the slot number for which the block height is to be queried.
- **Control Flow**:
    - Initialize `block_entry_height` to 0.
    - Enter an infinite loop to repeatedly attempt querying the blockstore.
    - Declare a `fd_block_map_query_t` array `query` initialized to zero.
    - Call `fd_block_map_query_try` to attempt querying the block map with the given slot and store the result in `query`.
    - Retrieve the block information using `fd_block_map_query_ele`.
    - If the error code is `FD_MAP_ERR_KEY`, log an error and exit.
    - If the error code is `FD_MAP_ERR_AGAIN`, continue the loop to retry the query.
    - Set `block_entry_height` to the block height from the retrieved block information.
    - If the query test returns `FD_MAP_SUCCESS`, break the loop.
- **Output**: Returns the block height as an unsigned long integer for the specified slot.


---
### fd\_blockstore\_log\_block\_status<!-- {{#callable:fd_blockstore_log_block_status}} -->
The `fd_blockstore_log_block_status` function logs the status of blocks in a blockstore around a specified slot.
- **Inputs**:
    - `blockstore`: A pointer to an `fd_blockstore_t` structure representing the blockstore to query.
    - `around_slot`: An unsigned long integer representing the slot around which the block status is to be logged.
- **Control Flow**:
    - Initialize a query array and index variables for received, buffered, and slot complete indices.
    - Iterate over slots from `around_slot - 5` to `around_slot + 20`.
    - For each slot, attempt to query the block map until a non-retryable error occurs.
    - If the slot is found, retrieve the received, buffered, and slot complete indices from the slot entry.
    - Log the status of the slot, highlighting the `around_slot` with an asterisk.
- **Output**: The function does not return a value; it logs the block status information to a logging system.


---
### fd\_smart\_size<!-- {{#callable:fd_smart_size}} -->
The `fd_smart_size` function formats a given size in bytes into a human-readable string representation using appropriate units (B, KB, MB, GB).
- **Inputs**:
    - `sz`: An unsigned long integer representing the size in bytes to be formatted.
    - `tmp`: A character array where the formatted size string will be stored.
    - `tmpsz`: The size of the character array `tmp`, indicating the maximum number of characters that can be written to it.
- **Control Flow**:
    - Check if the size `sz` is less than or equal to 128 bytes (1UL<<7); if true, format the size in bytes and store it in `tmp`.
    - If the size `sz` is less than or equal to 131072 bytes (1UL<<17), format the size in kilobytes (KB) with three decimal places and store it in `tmp`.
    - If the size `sz` is less than or equal to 134217728 bytes (1UL<<27), format the size in megabytes (MB) with three decimal places and store it in `tmp`.
    - If none of the above conditions are met, format the size in gigabytes (GB) with three decimal places and store it in `tmp`.
- **Output**: Returns the pointer to the character array `tmp` containing the formatted size string.


---
### fd\_blockstore\_log\_mem\_usage<!-- {{#callable:fd_blockstore_log_mem_usage}} -->
The `fd_blockstore_log_mem_usage` function logs the memory usage statistics of various components within a blockstore.
- **Inputs**:
    - `blockstore`: A pointer to an `fd_blockstore_t` structure representing the blockstore whose memory usage is to be logged.
- **Control Flow**:
    - Initialize a temporary character array `tmp1` for formatting size strings.
    - Log the base footprint of the blockstore using [`fd_smart_size`](#fd_smart_size) to format the size of `fd_blockstore_t`.
    - Retrieve and log the footprint and maximum entries of the shred pool using `fd_buf_shred_pool_ele_max` and `fd_buf_shred_pool_footprint`.
    - Retrieve and log the footprint, chain count, and load of the shred map using `fd_buf_shred_map_chain_cnt` and `fd_buf_shred_map_footprint`.
    - Retrieve and log the footprint, used entries, and maximum entries of the transaction map using `fd_txn_map_key_cnt`, `fd_txn_map_key_max`, and `fd_txn_map_footprint`.
    - Initialize a queue `q` using [`fd_blockstore_slot_deque`](fd_blockstore.h.driver.md#fd_blockstore_slot_deque) and perform a breadth-first search (BFS) starting from the watermark (`wmk`) to count blocks.
    - For each block, query the block map and enqueue its child slots if the block is valid.
    - Log the block count if it is non-zero.
- **Output**: The function does not return a value; it logs memory usage statistics to a logging system.
- **Functions called**:
    - [`fd_smart_size`](#fd_smart_size)
    - [`fd_blockstore_slot_deque`](fd_blockstore.h.driver.md#fd_blockstore_slot_deque)



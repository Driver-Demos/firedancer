# Purpose
This C header file defines structures and functions for interfacing with a RocksDB database in the context of a block storage system, likely used in a blockchain or distributed ledger environment. The file provides a detailed interface for managing blocks of data, including their allocation, iteration, and retrieval from a blockstore. It defines a `fd_block` structure to represent a block of data, with fields for various data types such as shreds, microblocks, and transactions, and provides inline functions to access these data types efficiently. The file also includes a `fd_rocksdb` structure that encapsulates a RocksDB instance, along with functions to initialize, create, destroy, and manipulate the database.

The header file is designed to be included in other C source files, providing a public API for managing block data and interfacing with RocksDB. It includes functions for iterating over database entries, seeking specific slots, and copying data between databases. The file also defines constants for column family indices, which are used to organize data within the RocksDB instance. The presence of conditional compilation directives (`#if FD_HAS_ROCKSDB`) suggests that the RocksDB-related functionality is optional and can be enabled or disabled based on the build configuration. Overall, this file provides a comprehensive interface for managing block data and interacting with a RocksDB database in a high-performance computing environment.
# Imports and Dependencies

---
- `../../ballet/block/fd_microblock.h`
- `fd_blockstore.h`
- `../../ballet/shred/fd_shred.h`
- `rocksdb/c.h`


# Global Variables

---
### fd\_rocksdb\_root\_iter\_new
- **Type**: `function pointer`
- **Description**: `fd_rocksdb_root_iter_new` is a function that creates a new iterator for the root column in a RocksDB database. It takes a single argument, `shiter`, which is a pointer to some shared iterator state or context, and returns a pointer to the newly created iterator.
- **Use**: This function is used to initialize a new iterator for traversing the root column in a RocksDB database, facilitating operations like seeking and iterating over database entries.


---
### fd\_rocksdb\_root\_iter\_join
- **Type**: `fd_rocksdb_root_iter_t *`
- **Description**: The `fd_rocksdb_root_iter_join` is a function that returns a pointer to a `fd_rocksdb_root_iter_t` structure. This structure is used to iterate over the root column of a RocksDB database, which is part of the Solana blockchain's data storage system.
- **Use**: This function is used to join an iterator to the root column of a RocksDB database, allowing traversal of the database's root entries.


---
### fd\_rocksdb\_root\_iter\_leave
- **Type**: `function pointer`
- **Description**: `fd_rocksdb_root_iter_leave` is a function that takes a pointer to an `fd_rocksdb_root_iter_t` structure and returns a void pointer. This function is likely used to perform cleanup or finalization tasks when leaving or ending an iteration over a RocksDB root column family.
- **Use**: This function is used to properly exit or finalize an iteration process over a RocksDB root column family, ensuring any necessary cleanup is performed.


---
### fd\_rocksdb\_init
- **Type**: `function pointer`
- **Description**: `fd_rocksdb_init` is a function that initializes a RocksDB database instance. It takes a pointer to an `fd_rocksdb_t` structure, which represents the database, and a constant character pointer `db_name`, which specifies the name of the database directory.
- **Use**: This function is used to set up a RocksDB instance by providing the necessary database structure and directory name, returning a pointer to an error description if initialization fails.


---
### fd\_rocksdb\_get\_txn\_status\_raw
- **Type**: `function`
- **Description**: The `fd_rocksdb_get_txn_status_raw` function is designed to query transaction status metadata from a RocksDB database. It takes a pointer to a `fd_rocksdb_t` structure, a slot number, a pointer to a transaction signature, and a pointer to a variable where the size of the returned data will be stored. The function returns a pointer to a buffer containing the raw serialized transaction status, or NULL if the record is not found.
- **Use**: This function is used to retrieve raw transaction status data from a RocksDB database, which can then be deserialized using the appropriate API.


# Data Structures

---
### fd\_block
- **Type**: `struct`
- **Members**:
    - `data_gaddr`: Pointer to the beginning of the block's allocated data region.
    - `data_sz`: Size of the block.
    - `shreds_gaddr`: Pointer to the first fd_block_shred_t.
    - `shreds_cnt`: Count of shreds in the block.
    - `batch_gaddr`: Pointer to the list of fd_block_entry_batch_t.
    - `batch_cnt`: Count of entry batches in the block.
    - `micros_gaddr`: Pointer to the list of fd_block_micro_t.
    - `micros_cnt`: Count of microblocks in the block.
    - `txns_gaddr`: Pointer to the list of fd_block_txn_t.
    - `txns_cnt`: Count of transactions in the block.
    - `txns_meta_gaddr`: Pointer to the allocation for transaction metadata.
    - `txns_meta_sz`: Size of the transaction metadata.
- **Description**: The `fd_block` structure is used to manage and iterate over the contents of a block in an offline blockstore memory. It provides pointers and counts for various components of a block, such as shreds, entry batches, microblocks, and transactions, allowing for efficient iteration over these elements. The structure is designed to support indexed iteration by different block components, although random access is not efficient due to the variable-length nature of shreds. This structure is primarily used in offline scenarios to facilitate the processing and analysis of block data.


---
### fd\_block\_t
- **Type**: `struct`
- **Members**:
    - `data_gaddr`: Pointer to the beginning of the block's allocated data region.
    - `data_sz`: Size of the block.
    - `shreds_gaddr`: Pointer to the first fd_block_shred_t.
    - `shreds_cnt`: Count of shreds in the block.
    - `batch_gaddr`: Pointer to the list of fd_block_entry_batch_t.
    - `batch_cnt`: Count of entry batches in the block.
    - `micros_gaddr`: Pointer to the list of fd_block_micro_t.
    - `micros_cnt`: Count of microblocks in the block.
    - `txns_gaddr`: Pointer to the list of fd_block_txn_t.
    - `txns_cnt`: Count of transactions in the block.
    - `txns_meta_gaddr`: Pointer to the allocation for transaction metadata.
    - `txns_meta_sz`: Size of the transaction metadata.
- **Description**: The `fd_block_t` structure is used to manage and iterate over blocks of data stored in a blockstore, specifically for offline-replay purposes. It contains pointers and counts for various components of a block, such as shreds, entry batches, microblocks, and transactions, allowing for efficient iteration and access to these elements. The structure is designed to facilitate the organization and retrieval of block data, supporting operations like iterating by shred, microblock, or transaction, although random access is not optimized due to the variable-length nature of shreds.


---
### fd\_rocksdb
- **Type**: `struct`
- **Members**:
    - `db`: A pointer to the RocksDB database instance.
    - `db_name`: A constant character pointer to the name of the database.
    - `cfgs`: An array of constant character pointers for configuration settings, indexed by column family count.
    - `cf_handles`: An array of pointers to column family handles, indexed by column family count.
    - `opts`: A pointer to the RocksDB options structure.
    - `ro`: A pointer to the RocksDB read options structure.
    - `wo`: A pointer to the RocksDB write options structure.
- **Description**: The `fd_rocksdb` structure is a custom data structure designed to encapsulate the necessary components for interacting with a RocksDB database within the context of the Solana blockchain client. It includes pointers to the database instance, its name, configuration settings, column family handles, and options for reading and writing operations. This structure facilitates the management and manipulation of data stored in a RocksDB instance, allowing for efficient database operations tailored to the needs of the Solana client.


---
### fd\_rocksdb\_t
- **Type**: `struct`
- **Members**:
    - `db`: A pointer to the RocksDB database instance.
    - `db_name`: A constant character pointer to the name of the database.
    - `cfgs`: An array of constant character pointers for configuration settings, with a size of FD_ROCKSDB_CF_CNT.
    - `cf_handles`: An array of pointers to RocksDB column family handles, with a size of FD_ROCKSDB_CF_CNT.
    - `opts`: A pointer to RocksDB options for database configuration.
    - `ro`: A pointer to RocksDB read options for read operations.
    - `wo`: A pointer to RocksDB write options for write operations.
- **Description**: The `fd_rocksdb_t` structure is a representation of a Solana RocksDB client, encapsulating the necessary components to interact with a RocksDB database. It includes pointers to the database instance, its name, configuration settings, column family handles, and options for read and write operations. This structure is designed to facilitate database operations such as initialization, querying, and data manipulation within the context of Solana's blockchain infrastructure.


---
### fd\_rocksdb\_root\_iter
- **Type**: `struct`
- **Members**:
    - `db`: A pointer to an fd_rocksdb_t structure representing the RocksDB database instance.
    - `iter`: A pointer to a rocksdb_iterator_t structure used for iterating over the database entries.
- **Description**: The `fd_rocksdb_root_iter` structure is designed to facilitate iteration over the entries in a RocksDB database, specifically targeting the root column family. It contains a pointer to an `fd_rocksdb_t` structure, which represents the database instance, and a pointer to a `rocksdb_iterator_t`, which is used to traverse the database entries. This structure is essential for operations that require sequential access to the database's root entries, enabling efficient data retrieval and manipulation.


---
### fd\_rocksdb\_root\_iter\_t
- **Type**: `struct`
- **Members**:
    - `db`: A pointer to an fd_rocksdb_t structure representing the RocksDB database instance.
    - `iter`: A pointer to a rocksdb_iterator_t used for iterating over the database entries.
- **Description**: The `fd_rocksdb_root_iter_t` structure is designed to facilitate iteration over the root column family of a RocksDB database. It contains a pointer to the database instance (`db`) and an iterator (`iter`) that allows traversal of the database entries. This structure is part of a larger system that interacts with RocksDB to manage and query data efficiently, particularly in the context of Solana's blockchain data storage.


# Functions

---
### fd\_blockstore\_block\_data\_laddr<!-- {{#callable:fd_blockstore_block_data_laddr}} -->
The function `fd_blockstore_block_data_laddr` returns a local pointer to the data of a specified block within a blockstore.
- **Inputs**:
    - `blockstore`: A pointer to an `fd_blockstore_t` structure, representing the blockstore containing the block.
    - `block`: A pointer to an `fd_block_t` structure, representing the block whose data pointer is to be retrieved.
- **Control Flow**:
    - The function calls [`fd_blockstore_wksp`](fd_blockstore.h.driver.md#fd_blockstore_wksp) with the `blockstore` pointer to obtain the workspace associated with the blockstore.
    - It then calls `fd_wksp_laddr_fast` with the obtained workspace and the `data_gaddr` from the `block` to get the local address of the block's data.
    - The function returns the local address obtained from `fd_wksp_laddr_fast`.
- **Output**: A local pointer to the block's data, valid until the block is removed.
- **Functions called**:
    - [`fd_blockstore_wksp`](fd_blockstore.h.driver.md#fd_blockstore_wksp)


---
### fd\_blockstore\_block\_query<!-- {{#callable:fd_blockstore_block_query}} -->
The `fd_blockstore_block_query` function queries a blockstore for a block at a specified slot and returns a pointer to the block if found, or NULL if not.
- **Inputs**:
    - `blockstore`: A pointer to an `fd_blockstore_t` structure representing the blockstore to be queried.
    - `slot`: An unsigned long integer representing the slot number of the block to be queried.
- **Control Flow**:
    - Initialize `err` to `FD_MAP_ERR_AGAIN` and `query_block_gaddr` to 0.
    - Enter a loop that continues while `err` is `FD_MAP_ERR_AGAIN`.
    - Declare and initialize a `fd_block_map_query_t` array `quer` with one element set to 0.
    - Call `fd_block_map_query_try` with the blockstore's block map, the slot, and `quer`, updating `err`.
    - Retrieve the query element using `fd_block_map_query_ele`.
    - If `err` is `FD_MAP_ERR_KEY`, return NULL as the block is not found.
    - If `err` is `FD_MAP_ERR_AGAIN`, continue the loop to retry the query.
    - If `query->block_gaddr` is 0, return NULL as the block address is invalid.
    - Set `query_block_gaddr` to `query->block_gaddr`.
    - Call `fd_block_map_query_test` with `quer` to update `err`.
    - Once `err` is no longer `FD_MAP_ERR_AGAIN`, return the local address of the block using `fd_wksp_laddr_fast` with the blockstore's workspace and `query_block_gaddr`.
- **Output**: A pointer to an `fd_block_t` structure representing the block at the specified slot, or NULL if the block is not found or the address is invalid.
- **Functions called**:
    - [`fd_blockstore_wksp`](fd_blockstore.h.driver.md#fd_blockstore_wksp)


# Function Declarations (Public API)

---
### fd\_rocksdb\_root\_iter\_new<!-- {{#callable_declaration:fd_rocksdb_root_iter_new}} -->
Initialize a RocksDB root iterator structure.
- **Description**: This function initializes a RocksDB root iterator structure by setting all its fields to zero. It is typically used to prepare a memory region for use as a `fd_rocksdb_root_iter_t` structure. The function must be called with a valid pointer to a memory region that is large enough to hold a `fd_rocksdb_root_iter_t` structure. This function does not allocate memory; it only initializes the memory pointed to by the provided pointer.
- **Inputs**:
    - `ptr`: A pointer to a memory region that will be initialized as a `fd_rocksdb_root_iter_t` structure. The pointer must not be null and must point to a region of memory that is at least the size of `fd_rocksdb_root_iter_t`. The caller retains ownership of the memory.
- **Output**: Returns the same pointer that was passed in, now initialized to zero.
- **See also**: [`fd_rocksdb_root_iter_new`](fd_rocksdb.c.driver.md#fd_rocksdb_root_iter_new)  (Implementation)


---
### fd\_rocksdb\_root\_iter\_join<!-- {{#callable_declaration:fd_rocksdb_root_iter_join}} -->
Converts a generic pointer to a RocksDB root iterator pointer.
- **Description**: Use this function to cast a generic pointer to a `fd_rocksdb_root_iter_t` pointer when you need to work with a RocksDB root iterator. This function is typically used when you have a pointer that you know is a RocksDB root iterator but is currently typed as a void pointer. Ensure that the pointer passed to this function is indeed a valid `fd_rocksdb_root_iter_t` pointer to avoid undefined behavior.
- **Inputs**:
    - `ptr`: A generic pointer that should point to a valid `fd_rocksdb_root_iter_t` object. The caller must ensure that this pointer is not null and is correctly typed to avoid undefined behavior.
- **Output**: Returns a pointer to `fd_rocksdb_root_iter_t` that is equivalent to the input pointer.
- **See also**: [`fd_rocksdb_root_iter_join`](fd_rocksdb.c.driver.md#fd_rocksdb_root_iter_join)  (Implementation)


---
### fd\_rocksdb\_root\_iter\_leave<!-- {{#callable_declaration:fd_rocksdb_root_iter_leave}} -->
Leaves the RocksDB root iterator context.
- **Description**: This function is used to exit the context of a RocksDB root iterator, effectively marking the end of its usage. It should be called when the iterator is no longer needed, allowing for any necessary cleanup or state transition. This function is typically used in conjunction with other iterator functions to manage the lifecycle of a RocksDB root iterator.
- **Inputs**:
    - `iter`: A pointer to an `fd_rocksdb_root_iter_t` structure representing the RocksDB root iterator. The pointer must not be null, and it should point to a valid iterator that was previously initialized or joined.
- **Output**: Returns the same pointer that was passed in, allowing for potential chaining or further operations on the iterator.
- **See also**: [`fd_rocksdb_root_iter_leave`](fd_rocksdb.c.driver.md#fd_rocksdb_root_iter_leave)  (Implementation)


---
### fd\_rocksdb\_root\_iter\_seek<!-- {{#callable_declaration:fd_rocksdb_root_iter_seek}} -->
Seeks to a specified slot in the RocksDB root column family iterator.
- **Description**: This function is used to position a RocksDB root column family iterator at a specific slot, allowing subsequent operations to be performed from that position. It should be called when you need to access or verify data associated with a particular slot in the database. The function requires a valid iterator and database object, and it will attempt to seek to the specified slot. If the seek operation is successful and the slot matches, it retrieves the metadata for that slot. The function returns specific error codes if the seek fails, the slot does not match, or if the slot is empty.
- **Inputs**:
    - `self`: A pointer to an `fd_rocksdb_root_iter_t` structure representing the iterator. Must not be null and should be properly initialized.
    - `db`: A pointer to an `fd_rocksdb_t` structure representing the database. Must not be null and should be properly initialized.
    - `slot`: An unsigned long integer representing the slot number to seek to. Must be a valid slot number within the database.
    - `m`: A pointer to an `fd_slot_meta_t` structure where the metadata for the slot will be stored. Must not be null.
    - `valloc`: An `fd_valloc_t` value used for memory allocation purposes. Must be valid for the context in which it is used.
- **Output**: Returns 0 on success, -1 if the seek operation fails, -2 if the slot does not match the sought slot, and -3 if the slot is empty.
- **See also**: [`fd_rocksdb_root_iter_seek`](fd_rocksdb.c.driver.md#fd_rocksdb_root_iter_seek)  (Implementation)


---
### fd\_rocksdb\_root\_iter\_next<!-- {{#callable_declaration:fd_rocksdb_root_iter_next}} -->
Advances the iterator to the next valid entry and retrieves its metadata.
- **Description**: Use this function to move the iterator to the next entry in the RocksDB root column and retrieve the associated metadata. It should be called after successfully initializing the iterator with a seek operation. The function returns an error if the iterator is not properly initialized, if the current iterator state is invalid, or if advancing the iterator results in an invalid state. Ensure that the iterator is valid before calling this function to avoid errors.
- **Inputs**:
    - `iter`: A pointer to an `fd_rocksdb_root_iter_t` structure representing the current state of the iterator. Must not be null and should be properly initialized with a seek operation.
    - `m`: A pointer to an `fd_slot_meta_t` structure where the metadata of the next entry will be stored. Must not be null.
    - `valloc`: An `fd_valloc_t` value used for memory allocation purposes during metadata retrieval. The specific requirements for this parameter depend on the context of its use.
- **Output**: Returns 0 on success, or a negative error code: -1 if the iterator is not properly initialized, -2 if the starting iterator is invalid, or -3 if advancing the iterator results in an invalid state.
- **See also**: [`fd_rocksdb_root_iter_next`](fd_rocksdb.c.driver.md#fd_rocksdb_root_iter_next)  (Implementation)


---
### fd\_rocksdb\_root\_iter\_slot<!-- {{#callable_declaration:fd_rocksdb_root_iter_slot}} -->
Retrieve the current slot from a RocksDB root iterator.
- **Description**: Use this function to obtain the slot number from the current position of a RocksDB root iterator. It should be called when the iterator is valid and positioned at a key. The function will return an error if the iterator is not properly initialized or if it is not pointing to a valid key. This function is useful for iterating over slots in a RocksDB database, particularly when working with root column families.
- **Inputs**:
    - `self`: A pointer to an `fd_rocksdb_root_iter_t` structure representing the iterator. It must not be null and should be properly initialized with a valid RocksDB instance and iterator.
    - `slot`: A pointer to an `ulong` where the slot number will be stored. It must not be null. The function will write the slot number to this location if successful.
- **Output**: Returns 0 on success, with the slot number written to the location pointed to by `slot`. Returns -1 if the iterator is not properly initialized, or -2 if the iterator is not valid.
- **See also**: [`fd_rocksdb_root_iter_slot`](fd_rocksdb.c.driver.md#fd_rocksdb_root_iter_slot)  (Implementation)


---
### fd\_rocksdb\_root\_iter\_destroy<!-- {{#callable_declaration:fd_rocksdb_root_iter_destroy}} -->
Destroys a RocksDB root iterator.
- **Description**: Use this function to properly clean up and release resources associated with a RocksDB root iterator when it is no longer needed. This function should be called to avoid memory leaks after you are done using the iterator. It ensures that any internal resources held by the iterator are freed, and it resets the iterator's database reference to NULL. This function must be called only on a valid iterator that has been initialized and not on a NULL pointer.
- **Inputs**:
    - `iter`: A pointer to an fd_rocksdb_root_iter_t structure representing the iterator to be destroyed. Must not be NULL. The function will safely handle the case where the internal iterator is already NULL.
- **Output**: None
- **See also**: [`fd_rocksdb_root_iter_destroy`](fd_rocksdb.c.driver.md#fd_rocksdb_root_iter_destroy)  (Implementation)


---
### fd\_rocksdb\_init<!-- {{#callable_declaration:fd_rocksdb_init}} -->
Initializes a RocksDB instance for read-only access.
- **Description**: This function sets up a RocksDB instance for read-only operations using the specified database name. It initializes the provided `fd_rocksdb_t` structure with default column family configurations and options. The function must be called with a valid `fd_rocksdb_t` object and a non-null database name pointing to the actual RocksDB directory. If the initialization fails, it returns a pointer to an error description; otherwise, it returns NULL, indicating success. This function is typically used when you need to access an existing RocksDB database in a read-only mode.
- **Inputs**:
    - `db`: A pointer to an `fd_rocksdb_t` structure that will be initialized. The caller must ensure this is a valid, non-null pointer.
    - `db_name`: A constant character pointer to the name of the database directory. It must not be null and should point to the actual RocksDB directory.
- **Output**: Returns a pointer to a string describing the error if initialization fails, or NULL if successful.
- **See also**: [`fd_rocksdb_init`](fd_rocksdb.c.driver.md#fd_rocksdb_init)  (Implementation)


---
### fd\_rocksdb\_new<!-- {{#callable_declaration:fd_rocksdb_new}} -->
Creates and initializes a new RocksDB instance.
- **Description**: This function initializes a new RocksDB instance at the specified location, setting up necessary options and column families. It should be called when a new database is required, and the provided path must be the full path where the database directory will be created. The function initializes the `fd_rocksdb_t` structure, setting up default options and creating necessary column families. If the database creation fails, an error is logged.
- **Inputs**:
    - `db`: A pointer to an `fd_rocksdb_t` structure that will be initialized. Must not be null, and the caller retains ownership.
    - `db_name`: A string representing the full path where the RocksDB directory will be created. Must not be null, and should point to a valid directory path.
- **Output**: None
- **See also**: [`fd_rocksdb_new`](fd_rocksdb.c.driver.md#fd_rocksdb_new)  (Implementation)


---
### fd\_rocksdb\_destroy<!-- {{#callable_declaration:fd_rocksdb_destroy}} -->
Frees resources associated with a RocksDB instance.
- **Description**: Use this function to release all resources and memory allocations associated with a given RocksDB instance. It should be called when the database is no longer needed to ensure that all internal data structures are properly cleaned up. This function must be called after all operations on the database are complete, and it is not safe to use the database object after this function has been called. Ensure that the `fd_rocksdb_t` object is properly initialized before calling this function.
- **Inputs**:
    - `db`: A pointer to an `fd_rocksdb_t` structure representing the RocksDB instance to be destroyed. Must not be null. The function will safely handle any internal null pointers within the structure.
- **Output**: None
- **See also**: [`fd_rocksdb_destroy`](fd_rocksdb.c.driver.md#fd_rocksdb_destroy)  (Implementation)


---
### fd\_rocksdb\_last\_slot<!-- {{#callable_declaration:fd_rocksdb_last_slot}} -->
Returns the last slot in the RocksDB root column.
- **Description**: This function retrieves the last slot number from the root column of the specified RocksDB instance. It is useful for determining the most recent root entry in the database. The function should be called with a valid `fd_rocksdb_t` object that represents an initialized RocksDB instance. If the root column is empty, the function sets the error message to indicate this and returns 0. The error message is a constant string and does not require deallocation by the caller.
- **Inputs**:
    - `db`: A pointer to an `fd_rocksdb_t` structure representing the RocksDB instance. It must be a valid and initialized database object.
    - `err`: A pointer to a `char*` where an error message will be stored if the function encounters an empty root column. The caller must ensure this pointer is valid. The error message is a constant string and does not need to be freed.
- **Output**: Returns the last slot number as an unsigned long. If the root column is empty, returns 0 and sets the error message.
- **See also**: [`fd_rocksdb_last_slot`](fd_rocksdb.c.driver.md#fd_rocksdb_last_slot)  (Implementation)


---
### fd\_rocksdb\_first\_slot<!-- {{#callable_declaration:fd_rocksdb_first_slot}} -->
Returns the first slot in the RocksDB root column.
- **Description**: Use this function to retrieve the first slot from the root column of a RocksDB database. It is useful when you need to determine the starting point of the data stored in the database. This function should be called when the database is properly initialized and accessible. If the root column is empty, the function sets the error message and returns 0, indicating that there are no slots available.
- **Inputs**:
    - `db`: A pointer to an initialized fd_rocksdb_t structure representing the RocksDB database. Must not be null.
    - `err`: A pointer to a char pointer where an error message will be stored if the root column is empty. Must not be null.
- **Output**: Returns the first slot as an unsigned long integer. If the root column is empty, returns 0 and sets *err to an error message.
- **See also**: [`fd_rocksdb_first_slot`](fd_rocksdb.c.driver.md#fd_rocksdb_first_slot)  (Implementation)


---
### fd\_rocksdb\_find\_last\_slot<!-- {{#callable_declaration:fd_rocksdb_find_last_slot}} -->
Finds the last slot in the RocksDB root column family.
- **Description**: This function retrieves the highest slot number from the root column family of the specified RocksDB instance. It is useful for determining the most recent slot that has been processed or stored in the database. The function should be called when you need to know the last slot in the database. If the root column family is empty, the function sets the error message to indicate this condition and returns 0. The caller must ensure that the `fd_rocksdb_t` instance is properly initialized before calling this function.
- **Inputs**:
    - `db`: A pointer to an initialized `fd_rocksdb_t` structure representing the RocksDB instance. Must not be null.
    - `err`: A pointer to a `char*` where an error message will be stored if the root column family is empty. The caller does not need to free this string. Must not be null.
- **Output**: Returns the highest slot number found in the root column family, or 0 if the column family is empty.
- **See also**: [`fd_rocksdb_find_last_slot`](fd_rocksdb.c.driver.md#fd_rocksdb_find_last_slot)  (Implementation)


---
### fd\_rocksdb\_get\_meta<!-- {{#callable_declaration:fd_rocksdb_get_meta}} -->
Retrieves metadata for a specified slot from the RocksDB database.
- **Description**: Use this function to obtain the metadata associated with a specific slot in a RocksDB database. It is essential to ensure that the database is properly initialized before calling this function. The function will attempt to retrieve the metadata and store it in the provided `fd_slot_meta_t` structure. If an error occurs during the retrieval process, the function will return an error code. This function requires a valid memory allocator to allocate space for the metadata, and the caller is responsible for managing the memory of the error string if an error occurs.
- **Inputs**:
    - `db`: A pointer to an initialized `fd_rocksdb_t` structure representing the database. Must not be null.
    - `slot`: An unsigned long integer representing the slot number for which metadata is to be retrieved.
    - `m`: A pointer to an `fd_slot_meta_t` structure where the retrieved metadata will be stored. Must not be null.
    - `valloc`: A `fd_valloc_t` allocator used for memory allocation during the metadata retrieval process.
- **Output**: Returns 0 on success, -1 if the metadata is not found, and -2 if an error occurs during retrieval. The `fd_slot_meta_t` structure pointed to by `m` is populated with the metadata on success.
- **See also**: [`fd_rocksdb_get_meta`](fd_rocksdb.c.driver.md#fd_rocksdb_get_meta)  (Implementation)


---
### fd\_rocksdb\_get\_txn\_status\_raw<!-- {{#callable_declaration:fd_rocksdb_get_txn_status_raw}} -->
Queries transaction status metadata from RocksDB.
- **Description**: This function retrieves the transaction status metadata for a given transaction signature and slot from a RocksDB database. It is used when you need to access the raw serialized status of a transaction, which is Protobuf-encoded. The function returns a pointer to a malloc-backed buffer containing the status data, and the caller is responsible for freeing this buffer. If the transaction record is not found or an error occurs, the function returns NULL. The size of the returned data is stored in the location pointed to by `psz`. This function should be called with a valid `fd_rocksdb_t` instance and appropriate slot and signature values.
- **Inputs**:
    - `self`: A pointer to an `fd_rocksdb_t` instance representing the RocksDB database. Must not be null.
    - `slot`: The slot number of the block containing the transaction. Must be a valid slot number.
    - `sig`: A pointer to the first signature of the transaction. Must not be null and should point to a valid signature.
    - `psz`: A pointer to an `ulong` where the size of the returned data will be stored. Must not be null.
- **Output**: Returns a pointer to a malloc-backed buffer containing the raw serialized transaction status if successful, or NULL if the record is not found or an error occurs. The caller must free the returned buffer if it is not NULL. The size of the data is stored in the location pointed to by `psz`.
- **See also**: [`fd_rocksdb_get_txn_status_raw`](fd_rocksdb.c.driver.md#fd_rocksdb_get_txn_status_raw)  (Implementation)


---
### fd\_rocksdb\_copy\_over\_slot\_indexed\_range<!-- {{#callable_declaration:fd_rocksdb_copy_over_slot_indexed_range}} -->
Copies entries from one RocksDB instance to another within a specified slot range.
- **Description**: This function is used to copy entries from a source RocksDB instance to a destination RocksDB instance for a specified column family index, within a given range of slot numbers. It is important to note that the column family index must be slot-indexed; otherwise, the function will skip the operation for that index. The function should be called when you need to transfer data between two RocksDB instances while filtering by slot range. It assumes that the keys in the column family are prefixed with the slot number. The function does not perform any operation if the column family index is not slot-indexed, and it returns 0 in such cases.
- **Inputs**:
    - `src`: A pointer to the source fd_rocksdb_t instance from which entries will be copied. Must not be null.
    - `dst`: A pointer to the destination fd_rocksdb_t instance to which entries will be copied. Must not be null.
    - `cf_idx`: The column family index to copy from. Must be a valid index and slot-indexed; otherwise, the function will skip copying for this index.
    - `start_slot`: The starting slot number of the range to copy. Must be less than or equal to end_slot.
    - `end_slot`: The ending slot number of the range to copy. Must be greater than or equal to start_slot.
- **Output**: Returns 0 on success or if the column family index is not slot-indexed.
- **See also**: [`fd_rocksdb_copy_over_slot_indexed_range`](fd_rocksdb.c.driver.md#fd_rocksdb_copy_over_slot_indexed_range)  (Implementation)


---
### fd\_rocksdb\_copy\_over\_txn\_status\_range<!-- {{#callable_declaration:fd_rocksdb_copy_over_txn_status_range}} -->
Copies transaction statuses over a specified block range from one RocksDB instance to another.
- **Description**: This function is used to transfer transaction status data between two RocksDB instances over a specified range of block slots. It is particularly useful when synchronizing or migrating data between databases. The function requires a blockstore object that contains the necessary block information for the specified range. It iterates over each block in the range, checking for completeness, and copies the transaction statuses if the block is complete. This function should be called when both source and destination databases are properly initialized and the blockstore is populated with the relevant block data.
- **Inputs**:
    - `src`: A pointer to the source fd_rocksdb_t instance from which transaction statuses will be copied. Must not be null.
    - `dst`: A pointer to the destination fd_rocksdb_t instance to which transaction statuses will be copied. Must not be null.
    - `blockstore`: A pointer to the fd_blockstore_t instance that contains the block data for the specified range. Must not be null and should be populated with relevant block information.
    - `start_slot`: The starting slot number of the block range to copy. Must be less than or equal to end_slot.
    - `end_slot`: The ending slot number of the block range to copy. Must be greater than or equal to start_slot.
- **Output**: Returns 0 on successful completion of the copy operation.
- **See also**: [`fd_rocksdb_copy_over_txn_status_range`](fd_rocksdb.c.driver.md#fd_rocksdb_copy_over_txn_status_range)  (Implementation)


---
### fd\_rocksdb\_copy\_over\_txn\_status<!-- {{#callable_declaration:fd_rocksdb_copy_over_txn_status}} -->
Copies a transaction status entry from one RocksDB instance to another.
- **Description**: This function is used to copy a specific transaction status entry from a source RocksDB instance to a destination RocksDB instance. It constructs a key using the provided slot number and transaction signature, queries the source database for the transaction status, and inserts the result into the destination database. This function should be used when you need to transfer transaction status data between databases, ensuring that the source and destination databases are properly initialized and accessible. It handles errors by logging a warning and aborting the copy operation if the query fails.
- **Inputs**:
    - `src`: A pointer to the source fd_rocksdb_t instance from which the transaction status will be copied. Must not be null and should be properly initialized.
    - `dst`: A pointer to the destination fd_rocksdb_t instance where the transaction status will be copied to. Must not be null and should be properly initialized.
    - `slot`: An unsigned long representing the slot number associated with the transaction. It is used as part of the key to query the transaction status.
    - `sig`: A pointer to a constant memory location containing the transaction signature. This must point to a valid memory region of at least 64 bytes, as it is used to construct the query key.
- **Output**: None
- **See also**: [`fd_rocksdb_copy_over_txn_status`](fd_rocksdb.c.driver.md#fd_rocksdb_copy_over_txn_status)  (Implementation)


---
### fd\_rocksdb\_insert\_entry<!-- {{#callable_declaration:fd_rocksdb_insert_entry}} -->
Inserts a key-value pair into a specified column family of a RocksDB instance.
- **Description**: Use this function to store a key-value pair in a specific column family of a RocksDB database. It is essential to ensure that the database instance is properly initialized and that the column family index is valid before calling this function. The function will return an error if the insertion fails, which can occur due to issues such as an invalid column family index or database errors. This function is typically used when you need to add or update entries in the database.
- **Inputs**:
    - `db`: A pointer to an initialized fd_rocksdb_t structure representing the RocksDB instance. Must not be null.
    - `cf_idx`: The index of the column family where the key-value pair should be inserted. Must be within the valid range of column family indices for the database.
    - `key`: A pointer to the key data to be inserted. Must not be null and should point to a valid memory region of at least klen bytes.
    - `klen`: The length of the key in bytes. Must accurately reflect the size of the key data.
    - `value`: A pointer to the value data to be inserted. Must not be null and should point to a valid memory region of at least vlen bytes.
    - `vlen`: The length of the value in bytes. Must accurately reflect the size of the value data.
- **Output**: Returns 0 on success, or -1 if an error occurs during the insertion process.
- **See also**: [`fd_rocksdb_insert_entry`](fd_rocksdb.c.driver.md#fd_rocksdb_insert_entry)  (Implementation)


---
### fd\_rocksdb\_import\_block\_blockstore<!-- {{#callable_declaration:fd_rocksdb_import_block_blockstore}} -->
Imports a block from RocksDB into the blockstore.
- **Description**: This function is used to import a block from a RocksDB database into a blockstore, processing shreds and updating block metadata. It should be called when a block needs to be transferred from persistent storage to the blockstore for further processing. The function expects valid metadata and a blockstore to insert the shreds into. It handles missing shreds and logs warnings if any are found. The function also updates block metadata such as timestamps and block heights, and optionally uses a hash override if provided. It must be called with a valid RocksDB instance and blockstore, and the metadata must accurately reflect the block's slot and received shreds.
- **Inputs**:
    - `db`: A pointer to a valid fd_rocksdb_t instance representing the RocksDB database. Must not be null.
    - `m`: A pointer to fd_slot_meta_t containing metadata for the block to be imported. Must not be null and should accurately reflect the block's slot and received shreds.
    - `blockstore`: A pointer to fd_blockstore_t where the block's shreds will be inserted. Must not be null.
    - `txnstatus`: An integer flag indicating whether transaction status should be processed. Non-zero values enable processing.
    - `hash_override`: A pointer to a 32-byte array used to override the block's hash. Can be null, in which case the hash is retrieved from the database.
    - `valloc`: An fd_valloc_t instance used for memory allocation during processing. Must be valid.
- **Output**: Returns 0 on success, or -1 if an error occurs, such as missing shreds or failed database operations.
- **See also**: [`fd_rocksdb_import_block_blockstore`](fd_rocksdb.c.driver.md#fd_rocksdb_import_block_blockstore)  (Implementation)


---
### fd\_rocksdb\_import\_block\_shredcap<!-- {{#callable_declaration:fd_rocksdb_import_block_shredcap}} -->
Imports block data from RocksDB into a shredcap format.
- **Description**: This function is used to import block data from a RocksDB database into a shredcap format, writing the data to specified output streams. It should be called when you need to convert and store block data from a database into a specific format for further processing or storage. The function requires valid metadata and output streams, and it handles errors by returning a negative value if any issues occur during the import process.
- **Inputs**:
    - `db`: A pointer to an initialized fd_rocksdb_t structure representing the RocksDB database. Must not be null.
    - `metadata`: A pointer to an fd_slot_meta_t structure containing metadata about the slot to be imported. Must not be null.
    - `ostream`: A pointer to an fd_io_buffered_ostream_t structure where the shredcap data will be written. Must not be null.
    - `bank_hash_ostream`: A pointer to an fd_io_buffered_ostream_t structure where bank hash information will be written. Must not be null.
    - `valloc`: An fd_valloc_t allocator used for memory allocations during the import process. Must be valid and properly initialized.
- **Output**: Returns 0 on success, or a negative value if an error occurs during the import process.
- **See also**: [`fd_rocksdb_import_block_shredcap`](fd_rocksdb.c.driver.md#fd_rocksdb_import_block_shredcap)  (Implementation)


---
### fd\_blockstore\_block\_allocs\_remove<!-- {{#callable_declaration:fd_blockstore_block_allocs_remove}} -->
Removes all allocations related to a block at a specified slot in the blockstore.
- **Description**: This function is used to remove all allocations associated with a block at a given slot within a blockstore. It should be called when a block is no longer needed and its resources should be freed. The function checks if the block is currently being replayed and will not remove it if a replay is in progress, logging a warning instead. It is important to ensure that the block is not in use before calling this function to avoid potential data corruption or access violations.
- **Inputs**:
    - `blockstore`: A pointer to the fd_blockstore_t structure representing the blockstore from which the block allocations will be removed. Must not be null.
    - `slot`: The slot number of the block whose allocations are to be removed. Must correspond to a valid slot in the blockstore.
- **Output**: None
- **See also**: [`fd_blockstore_block_allocs_remove`](fd_rocksdb.c.driver.md#fd_blockstore_block_allocs_remove)  (Implementation)



# Purpose
This C source code file is designed to manage and store historical data related to remote procedure call (RPC) transactions and blocks, likely in a blockchain or distributed ledger context. The file defines several data structures and functions to handle the storage and retrieval of block and transaction information. The primary structures include `fd_rpc_block`, `fd_rpc_txn`, and `fd_rpc_acct_map_elem`, which are used to represent blocks, transactions, and account mappings, respectively. These structures are organized into maps and pools, which facilitate efficient storage and lookup operations. The code utilizes hash maps and pools to manage these entities, ensuring that operations such as insertion, querying, and iteration over stored data are performed efficiently.

The file provides a comprehensive API for creating and managing an `fd_rpc_history` object, which encapsulates the entire history of blocks and transactions. Key functions include [`fd_rpc_history_create`](#fd_rpc_history_create), which initializes the history object, and [`fd_rpc_history_save`](#fd_rpc_history_save), which saves block and transaction data to a file. The code also includes functions for retrieving specific blocks or transactions by their identifiers, such as [`fd_rpc_history_get_block_info`](#fd_rpc_history_get_block_info) and [`fd_rpc_history_get_txn`](#fd_rpc_history_get_txn). Additionally, the file supports iterating over transactions associated with a particular account, allowing for detailed analysis of account activity. Overall, this code provides a robust framework for maintaining and accessing historical RPC data, which is crucial for applications that require auditing or analysis of past transactions and blocks.
# Imports and Dependencies

---
- `fd_rpc_history.h`
- `unistd.h`
- `../../flamenco/runtime/fd_system_ids.h`
- `../../util/tmpl/fd_map_giant.c`
- `../../util/tmpl/fd_map_chain.c`
- `../../util/tmpl/fd_pool.c`


# Data Structures

---
### fd\_rpc\_block
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the block.
    - `next`: Holds the index or reference to the next block in a sequence.
    - `info`: Contains metadata or notification message related to the block, defined by `fd_replay_notif_msg_t`.
    - `file_offset`: Indicates the offset position of the block data within a file.
    - `file_size`: Specifies the size of the block data in the file.
- **Description**: The `fd_rpc_block` structure is designed to represent a block within an RPC history system, encapsulating essential information such as the slot number, metadata, and file storage details. It is used to manage and access block data efficiently, with fields for tracking the block's position and size within a file, as well as linking to subsequent blocks.


---
### fd\_rpc\_block\_t
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the block.
    - `next`: Holds the index or reference to the next block in a sequence.
    - `info`: Stores notification message information related to the block.
    - `file_offset`: Indicates the offset in the file where the block data starts.
    - `file_size`: Specifies the size of the block data in the file.
- **Description**: The `fd_rpc_block_t` structure is designed to represent a block in a remote procedure call (RPC) history system. It contains information about the block's slot number, a reference to the next block, notification message details, and file-related metadata such as the offset and size of the block data within a file. This structure is used to manage and access block data efficiently in the context of an RPC history.


---
### fd\_rpc\_txn
- **Type**: `struct`
- **Members**:
    - `sig`: A unique transaction signature of type `fd_rpc_txn_key_t`.
    - `next`: An unsigned long integer indicating the next transaction in a sequence.
    - `slot`: An unsigned long integer representing the slot number associated with the transaction.
    - `file_offset`: An unsigned long integer indicating the offset in the file where the transaction data is stored.
    - `file_size`: An unsigned long integer representing the size of the transaction data in the file.
- **Description**: The `fd_rpc_txn` structure is designed to represent a transaction within a remote procedure call (RPC) system. It includes a unique signature (`sig`) to identify the transaction, and fields (`next`, `slot`, `file_offset`, `file_size`) that manage the transaction's position and size within a file, as well as its order in a sequence of transactions. This structure is used to efficiently store and retrieve transaction data from a file, facilitating the management of transaction history in a distributed system.


---
### fd\_rpc\_txn\_t
- **Type**: `struct`
- **Members**:
    - `sig`: Represents the transaction signature key.
    - `next`: Holds the index or pointer to the next transaction in a linked list or map.
    - `slot`: Indicates the slot number associated with the transaction.
    - `file_offset`: Specifies the offset in the file where the transaction data is stored.
    - `file_size`: Denotes the size of the transaction data in the file.
- **Description**: The `fd_rpc_txn_t` structure is designed to represent a transaction within a remote procedure call (RPC) system. It includes a signature key (`sig`) for identifying the transaction, and fields for managing its storage and retrieval, such as `file_offset` and `file_size`, which indicate where the transaction data is located in a file and its size, respectively. The `slot` field associates the transaction with a specific slot, and the `next` field is used for linking transactions, likely in a map or list structure for efficient access and management.


---
### fd\_rpc\_acct\_map\_elem
- **Type**: `struct`
- **Members**:
    - `key`: A public key associated with the account.
    - `next`: An index or pointer to the next element in the map.
    - `slot`: The slot number associated with this account entry.
    - `age`: The age of the account entry, possibly used for eviction or aging policies.
    - `sig`: The transaction signature associated with this account entry.
- **Description**: The `fd_rpc_acct_map_elem` structure is used to represent an element in an account map, which is part of a larger system for tracking account-related data in a blockchain or distributed ledger context. Each element contains a public key (`key`) that identifies the account, a `next` field for linking elements in a map or list, a `slot` indicating the specific ledger slot the account data pertains to, an `age` field that may be used for managing the lifecycle of the entry, and a `sig` field that holds the transaction signature associated with the account. This structure is likely used in conjunction with a map or pool to efficiently manage and query account data.


---
### fd\_rpc\_acct\_map\_elem\_t
- **Type**: `struct`
- **Members**:
    - `key`: A public key associated with the account.
    - `next`: An index or pointer to the next element in the map.
    - `slot`: The slot number associated with the account.
    - `age`: The age of the account in terms of slots.
    - `sig`: The transaction signature associated with the account.
- **Description**: The `fd_rpc_acct_map_elem_t` structure represents an element in an account map, which is part of a larger system for managing and querying account-related data in a blockchain or distributed ledger context. Each element contains a public key (`key`) that uniquely identifies an account, a `next` field for linking elements in a map, a `slot` indicating the specific slot or block number, an `age` field representing the account's age in terms of slots, and a `sig` field that holds the transaction signature associated with the account. This structure is used in conjunction with a map and pool to efficiently manage and access account data.


---
### fd\_rpc\_history
- **Type**: `struct`
- **Members**:
    - `spad`: A pointer to a shared memory allocation descriptor.
    - `block_map`: A pointer to a map of RPC blocks.
    - `block_cnt`: The count of blocks currently stored.
    - `txn_map`: A pointer to a map of RPC transactions.
    - `acct_map`: A pointer to a map of account elements.
    - `acct_pool`: A pointer to a pool of account map elements.
    - `first_slot`: The first slot number recorded in the history.
    - `latest_slot`: The latest slot number recorded in the history.
    - `file_fd`: The file descriptor for the history file.
    - `file_totsz`: The total size of the history file.
- **Description**: The `fd_rpc_history` structure is designed to maintain a history of RPC blocks, transactions, and account activities. It includes pointers to various maps and pools that manage blocks, transactions, and account elements, as well as metadata such as the first and latest slots recorded. The structure also manages a file descriptor and total size for a history file, which is used to persistently store the data. This structure is integral to tracking and retrieving historical data related to RPC operations.


# Functions

---
### fd\_rpc\_txn\_key\_equal<!-- {{#callable:fd_rpc_txn_key_equal}} -->
The `fd_rpc_txn_key_equal` function checks if two transaction keys are equal by comparing their underlying data arrays.
- **Inputs**:
    - `k0`: A pointer to the first transaction key of type `fd_rpc_txn_key_t`.
    - `k1`: A pointer to the second transaction key of type `fd_rpc_txn_key_t`.
- **Control Flow**:
    - Iterates over each element of the transaction key arrays, comparing corresponding elements.
    - If any pair of elements differ, the function returns 0, indicating the keys are not equal.
    - If all elements are equal, the function returns 1, indicating the keys are equal.
- **Output**: Returns an integer: 1 if the transaction keys are equal, 0 otherwise.


---
### fd\_rpc\_txn\_key\_hash<!-- {{#callable:fd_rpc_txn_key_hash}} -->
The `fd_rpc_txn_key_hash` function computes a hash value for a given transaction key using a seed value.
- **Inputs**:
    - `k`: A pointer to a `fd_rpc_txn_key_t` structure, which contains the transaction key to be hashed.
    - `seed`: An unsigned long integer used as the initial seed value for the hash computation.
- **Control Flow**:
    - Initialize the hash value `h` with the provided `seed`.
    - Iterate over each `ulong` element in the transaction key `k->v`, which is divided by the size of `ulong`.
    - For each element, update the hash `h` by performing a bitwise XOR operation with the current element of `k->v`.
    - Return the final computed hash value `h`.
- **Output**: The function returns an unsigned long integer representing the computed hash value of the transaction key.


---
### fd\_rpc\_history\_create<!-- {{#callable:fd_rpc_history_create}} -->
The `fd_rpc_history_create` function initializes and allocates memory for a new RPC history structure, setting up maps for blocks, transactions, and accounts, and opens a file for storing history data.
- **Inputs**:
    - `args`: A pointer to an `fd_rpcserver_args_t` structure containing configuration parameters and resources needed for creating the RPC history, such as memory allocation parameters and file paths.
- **Control Flow**:
    - Allocate memory for the `fd_rpc_history_t` structure using `fd_spad_alloc` and initialize it to zero.
    - Set the `spad` field of the history structure to the provided `spad` from `args`.
    - Initialize `first_slot` to `ULONG_MAX` and `latest_slot` to 0, indicating no slots have been processed yet.
    - Allocate and initialize the block map using `fd_rpc_block_map_new` and `fd_rpc_block_map_join`, with memory allocated based on `block_index_max`.
    - Allocate and initialize the transaction map using `fd_rpc_txn_map_new` and `fd_rpc_txn_map_join`, with memory allocated based on `txn_index_max`.
    - Allocate memory for the account map and pool, initialize them using `fd_rpc_acct_map_new`, `fd_rpc_acct_map_join`, `fd_rpc_acct_map_pool_new`, and `fd_rpc_acct_map_pool_join`, with memory allocated based on `acct_index_max`.
    - Open the history file specified in `args->history_file` with read/write permissions, creating or truncating it as necessary, and store the file descriptor in `file_fd`.
    - If the file cannot be opened, log an error and terminate the program.
    - Initialize `file_totsz` to 0, indicating no data has been written to the file yet.
    - Return the initialized `fd_rpc_history_t` structure.
- **Output**: A pointer to the newly created and initialized `fd_rpc_history_t` structure.


---
### fd\_rpc\_history\_save<!-- {{#callable:fd_rpc_history_save}} -->
The `fd_rpc_history_save` function saves block data from a blockstore into an RPC history structure, updating various maps and writing the data to a file.
- **Inputs**:
    - `hist`: A pointer to an `fd_rpc_history_t` structure that holds the history data and maps.
    - `blockstore`: A pointer to an `fd_blockstore_t` structure from which block data is queried.
    - `info`: A pointer to an `fd_replay_notif_msg_t` structure containing information about the block to be saved.
- **Control Flow**:
    - Begin a frame in the shared memory allocator `spad` associated with `hist`.
    - Check if the block map in `hist` is full; if so, return immediately.
    - Calculate the maximum block size based on the number of shreds and allocate memory for block data.
    - Query the blockstore for block data; if unsuccessful, log a warning and return.
    - Log a notice about saving the block and update the first and latest slot information in `hist`.
    - Insert the block information into the block map; if insertion fails, log an error and return.
    - Write the block data to the history file; if unsuccessful, log an error.
    - Update the block's file offset, size, and increment the total file size and block count in `hist`.
    - Iterate over the block data to process microblocks and transactions.
    - For each transaction, parse it and insert its signature into the transaction map, updating file offsets and sizes.
    - For each account in a transaction, check if it is a vote program; if not, insert it into the account map.
    - Check for any remaining data at the end of the block and log an error if found.
    - End the frame in the shared memory allocator `spad`.
- **Output**: The function does not return a value; it modifies the `fd_rpc_history_t` structure and writes data to a file.


---
### fd\_rpc\_history\_first\_slot<!-- {{#callable:fd_rpc_history_first_slot}} -->
The function `fd_rpc_history_first_slot` retrieves the first slot number recorded in the RPC history.
- **Inputs**:
    - `hist`: A pointer to an `fd_rpc_history_t` structure, which contains the RPC history data.
- **Control Flow**:
    - The function accesses the `first_slot` member of the `fd_rpc_history_t` structure pointed to by `hist`.
    - It returns the value of `first_slot`.
- **Output**: The function returns an `ulong` representing the first slot number in the RPC history.


---
### fd\_rpc\_history\_latest\_slot<!-- {{#callable:fd_rpc_history_latest_slot}} -->
The `fd_rpc_history_latest_slot` function retrieves the latest slot number recorded in the RPC history.
- **Inputs**:
    - `hist`: A pointer to an `fd_rpc_history_t` structure, which contains the RPC history data.
- **Control Flow**:
    - The function accesses the `latest_slot` member of the `fd_rpc_history_t` structure pointed to by `hist`.
    - It returns the value of `latest_slot`.
- **Output**: The function returns an `ulong` representing the latest slot number in the RPC history.


---
### fd\_rpc\_history\_get\_block\_info<!-- {{#callable:fd_rpc_history_get_block_info}} -->
The function `fd_rpc_history_get_block_info` retrieves block information for a given slot from the RPC history.
- **Inputs**:
    - `hist`: A pointer to an `fd_rpc_history_t` structure, which contains the RPC history data.
    - `slot`: An unsigned long integer representing the slot number for which block information is requested.
- **Control Flow**:
    - The function queries the block map within the `fd_rpc_history_t` structure using the provided slot number.
    - If the block corresponding to the slot is not found, the function returns `NULL`.
    - If the block is found, the function returns a pointer to the `info` field of the block, which contains the block information.
- **Output**: A pointer to an `fd_replay_notif_msg_t` structure containing the block information for the specified slot, or `NULL` if the block is not found.


---
### fd\_rpc\_history\_get\_block\_info\_by\_hash<!-- {{#callable:fd_rpc_history_get_block_info_by_hash}} -->
The function `fd_rpc_history_get_block_info_by_hash` retrieves block information from a history structure based on a given block hash.
- **Inputs**:
    - `hist`: A pointer to an `fd_rpc_history_t` structure, which contains the block map and other history-related data.
    - `h`: A pointer to an `fd_hash_t` structure representing the block hash to search for.
- **Control Flow**:
    - Initialize an iterator for the block map within the history structure.
    - Iterate over each element in the block map using the iterator.
    - For each block, check if its block hash matches the provided hash `h` using `fd_hash_eq`.
    - If a match is found, return a pointer to the block's information structure.
    - If no match is found after iterating through all blocks, return `NULL`.
- **Output**: A pointer to an `fd_replay_notif_msg_t` structure containing the block information if a matching block hash is found, otherwise `NULL`.


---
### fd\_rpc\_history\_get\_block<!-- {{#callable:fd_rpc_history_get_block}} -->
The `fd_rpc_history_get_block` function retrieves a block of data from the RPC history based on a given slot and returns its size.
- **Inputs**:
    - `hist`: A pointer to an `fd_rpc_history_t` structure, which contains the RPC history data and metadata.
    - `slot`: An unsigned long integer representing the slot number for which the block data is requested.
    - `blk_sz`: A pointer to an unsigned long integer where the size of the retrieved block will be stored.
- **Control Flow**:
    - Query the block map in the `hist` structure using the provided `slot` to find the corresponding block.
    - If the block is not found, set `*blk_sz` to `ULONG_MAX` and return `NULL`.
    - Allocate memory for the block data using `fd_spad_alloc` with the size of the block found.
    - Read the block data from the file descriptor `hist->file_fd` into the allocated memory using `pread`.
    - If the read operation fails (i.e., the number of bytes read does not match the block size), log an error, set `*blk_sz` to `ULONG_MAX`, and return `NULL`.
    - Set `*blk_sz` to the size of the block and return the pointer to the block data.
- **Output**: Returns a pointer to the block data if successful, or `NULL` if the block is not found or an error occurs during reading.


---
### fd\_rpc\_history\_get\_txn<!-- {{#callable:fd_rpc_history_get_txn}} -->
The `fd_rpc_history_get_txn` function retrieves transaction data from a history file based on a given transaction signature.
- **Inputs**:
    - `hist`: A pointer to an `fd_rpc_history_t` structure, which contains the transaction map and other related data.
    - `sig`: A pointer to an `fd_rpc_txn_key_t` structure representing the transaction signature to query.
    - `txn_sz`: A pointer to an `ulong` where the size of the transaction data will be stored.
    - `slot`: A pointer to an `ulong` where the slot number of the transaction will be stored.
- **Control Flow**:
    - Query the transaction map in `hist` using `sig` to find the corresponding transaction entry.
    - If the transaction is not found, set `txn_sz` to `ULONG_MAX` and return `NULL`.
    - Allocate memory for the transaction data using `fd_spad_alloc` with the size from the transaction entry.
    - Read the transaction data from the history file using `pread` into the allocated memory.
    - If the read operation fails, log an error, set `txn_sz` to `ULONG_MAX`, and return `NULL`.
    - Set `txn_sz` to the size of the transaction and `slot` to the slot number from the transaction entry.
    - Return the pointer to the transaction data.
- **Output**: A pointer to the transaction data if successful, or `NULL` if the transaction is not found or an error occurs.


---
### fd\_rpc\_history\_first\_txn\_for\_acct<!-- {{#callable:fd_rpc_history_first_txn_for_acct}} -->
The function `fd_rpc_history_first_txn_for_acct` retrieves the first transaction associated with a given account from the RPC history.
- **Inputs**:
    - `hist`: A pointer to an `fd_rpc_history_t` structure representing the RPC history.
    - `acct`: A pointer to an `fd_pubkey_t` structure representing the public key of the account to query.
    - `sig`: A pointer to an `fd_rpc_txn_key_t` structure where the transaction signature will be stored.
    - `slot`: A pointer to an `ulong` where the slot number of the transaction will be stored.
- **Control Flow**:
    - Query the account map in the RPC history using the provided account public key to find the corresponding account map element.
    - If the account map element is not found, return NULL.
    - If the account map element is found, store its transaction signature in the provided `sig` pointer.
    - Store the slot number of the transaction in the provided `slot` pointer.
    - Return a pointer to the account map element.
- **Output**: A pointer to the `fd_rpc_acct_map_elem_t` structure representing the first transaction for the account, or NULL if no transaction is found.


---
### fd\_rpc\_history\_next\_txn\_for\_acct<!-- {{#callable:fd_rpc_history_next_txn_for_acct}} -->
The function `fd_rpc_history_next_txn_for_acct` retrieves the next transaction for a given account from the RPC history.
- **Inputs**:
    - `hist`: A pointer to an `fd_rpc_history_t` structure representing the RPC history.
    - `sig`: A pointer to an `fd_rpc_txn_key_t` where the function will store the signature of the next transaction.
    - `slot`: A pointer to an `ulong` where the function will store the slot number of the next transaction.
    - `iter`: A constant void pointer representing the current position in the account map iteration.
- **Control Flow**:
    - Cast the `iter` pointer to a `fd_rpc_acct_map_elem_t` pointer named `ele`.
    - Call `fd_rpc_acct_map_ele_next_const` to get the next element in the account map, updating `ele`.
    - If `ele` is `NULL`, return `NULL` indicating no more transactions are available.
    - Update the `sig` and `slot` with the signature and slot from the current `ele`.
    - Return the updated `ele` pointer.
- **Output**: A constant void pointer to the next transaction element, or `NULL` if there are no more transactions.



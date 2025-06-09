# Purpose
This C header file, `fd_rpc_history.h`, defines the interface for managing and interacting with a history of remote procedure call (RPC) transactions within a server context. It provides a structured way to create, store, and retrieve transaction history data, which is crucial for applications that require tracking and accessing past transactions, such as blockchain or distributed ledger systems. The file includes type definitions and function prototypes that facilitate the creation of an RPC history object, saving transaction data, and retrieving information about transactions and blocks based on various criteria like slot numbers or transaction keys.

The file defines several key components, including the `fd_rpc_history_t` structure, which represents the history object, and the `fd_rpc_txn_key_t` structure, which is used to identify transactions. The functions declared in this header allow for operations such as creating a history object, saving transaction data to a blockstore, and retrieving block or transaction information by slot number or hash. This header file is intended to be included in other C source files that require access to these functionalities, and it serves as a public API for managing RPC transaction history in a server environment.
# Imports and Dependencies

---
- `fd_rpc_service.h`


# Global Variables

---
### fd\_rpc\_history\_create
- **Type**: `function pointer`
- **Description**: The `fd_rpc_history_create` is a function that returns a pointer to an `fd_rpc_history_t` structure. It takes a pointer to an `fd_rpcserver_args_t` structure as an argument, which likely contains configuration or initialization parameters for creating an RPC history instance.
- **Use**: This function is used to initialize and create an instance of an RPC history, which is essential for managing and tracking RPC transactions.


---
### fd\_rpc\_history\_get\_block\_info
- **Type**: `fd_replay_notif_msg_t *`
- **Description**: The variable `fd_rpc_history_get_block_info` is a function that returns a pointer to an `fd_replay_notif_msg_t` structure. It takes two parameters: a pointer to an `fd_rpc_history_t` structure and an unsigned long integer representing a slot.
- **Use**: This function is used to retrieve block information from the RPC history for a specific slot.


---
### fd\_rpc\_history\_get\_block\_info\_by\_hash
- **Type**: `function pointer`
- **Description**: The `fd_rpc_history_get_block_info_by_hash` is a function pointer that returns a pointer to an `fd_replay_notif_msg_t` structure. It takes two parameters: a pointer to an `fd_rpc_history_t` structure and a pointer to an `fd_hash_t` structure. This function is used to retrieve block information based on a given hash.
- **Use**: This function is used to obtain block information from the RPC history using a specific block hash.


---
### fd\_rpc\_history\_get\_block
- **Type**: `function pointer`
- **Description**: The `fd_rpc_history_get_block` is a function that retrieves a block of data from the RPC history given a specific slot. It returns a pointer to an unsigned character array representing the block data and updates the block size through a pointer parameter.
- **Use**: This function is used to access and retrieve block data from the RPC history for a specified slot, providing the block's size as an output parameter.


---
### fd\_rpc\_history\_get\_txn
- **Type**: `function pointer`
- **Description**: The `fd_rpc_history_get_txn` is a function that retrieves a transaction from the RPC history based on a given transaction key. It returns a pointer to an unsigned character array representing the transaction data. The function also outputs the size of the transaction and the slot number where the transaction is located.
- **Use**: This function is used to access specific transaction data from the RPC history using a transaction key.


---
### fd\_rpc\_history\_first\_txn\_for\_acct
- **Type**: `function`
- **Description**: The `fd_rpc_history_first_txn_for_acct` function is a global function that retrieves the first transaction associated with a specific account from the RPC history. It takes a pointer to an `fd_rpc_history_t` structure, a pointer to an account's public key (`fd_pubkey_t`), a pointer to a transaction key (`fd_rpc_txn_key_t`), and a pointer to a slot number (`ulong`).
- **Use**: This function is used to find and return the first transaction for a given account in the RPC history, providing the transaction key and slot number.


---
### fd\_rpc\_history\_next\_txn\_for\_acct
- **Type**: `function`
- **Description**: The `fd_rpc_history_next_txn_for_acct` function is a global function that retrieves the next transaction for a specific account from the RPC history. It takes a history object, a transaction key, a slot pointer, and an iterator as parameters, and returns a pointer to the next transaction.
- **Use**: This function is used to iterate over transactions associated with a specific account in the RPC history.


# Data Structures

---
### fd\_rpc\_history\_t
- **Type**: `typedef struct fd_rpc_history fd_rpc_history_t;`
- **Description**: The `fd_rpc_history_t` is a forward-declared structure used in the context of an RPC server to manage and interact with historical transaction data. It provides a set of functions to create a history instance, save transaction data, and retrieve information about blocks and transactions based on various criteria such as slot number or transaction signature. The structure is designed to interface with other components like blockstores and notification messages, facilitating the retrieval and management of blockchain transaction history.


---
### fd\_rpc\_txn\_key
- **Type**: `struct`
- **Members**:
    - `v`: An array of unsigned long integers with a size determined by the macro FD_ED25519_SIG_SZ divided by the size of an unsigned long.
- **Description**: The `fd_rpc_txn_key` structure is designed to hold a transaction key, represented as an array of unsigned long integers. The size of this array is determined by the macro `FD_ED25519_SIG_SZ`, which is divided by the size of an unsigned long, ensuring that the structure can accommodate a signature of a specific size. This structure is likely used to uniquely identify or verify transactions within the RPC history context.


---
### fd\_rpc\_txn\_key\_t
- **Type**: `struct`
- **Members**:
    - `v`: An array of unsigned long integers with a size determined by the macro FD_ED25519_SIG_SZ divided by the size of an unsigned long.
- **Description**: The `fd_rpc_txn_key_t` structure is designed to hold a transaction key, represented as an array of unsigned long integers. The size of this array is determined by the macro `FD_ED25519_SIG_SZ`, which is divided by the size of an unsigned long, ensuring that the structure can accommodate a signature of a specific size. This structure is likely used to uniquely identify or verify transactions within the RPC history context.


# Function Declarations (Public API)

---
### fd\_rpc\_history\_create<!-- {{#callable_declaration:fd_rpc_history_create}} -->
Creates and initializes an RPC history object.
- **Description**: This function initializes a new RPC history object using the provided server arguments. It allocates necessary resources and sets up internal structures for managing RPC history, including block, transaction, and account maps. The function must be called with valid server arguments, and it returns a pointer to the newly created history object. The caller is responsible for managing the lifecycle of the returned object, including its eventual destruction. This function will log an error and terminate the program if it fails to open the specified history file.
- **Inputs**:
    - `args`: A pointer to an fd_rpcserver_args_t structure containing configuration parameters for the RPC server. This must not be null and should be properly initialized before calling the function. The structure includes parameters for memory allocation and file handling.
- **Output**: Returns a pointer to an initialized fd_rpc_history_t object. If the history file cannot be opened, the function logs an error and terminates the program.
- **See also**: [`fd_rpc_history_create`](fd_rpc_history.c.driver.md#fd_rpc_history_create)  (Implementation)


---
### fd\_rpc\_history\_save<!-- {{#callable_declaration:fd_rpc_history_save}} -->
Saves block and transaction data to the RPC history.
- **Description**: This function is used to save block and transaction data from a blockstore into the RPC history. It should be called when new block data is available and needs to be recorded for future retrieval. The function checks if there is space available in the block map and transaction map before proceeding. It updates the history with the latest slot information and writes the block data to a file. The function handles cases where the block map is full by returning early, and logs warnings or errors if it encounters issues reading from the blockstore or writing to the history file.
- **Inputs**:
    - `hist`: A pointer to an fd_rpc_history_t structure where the block and transaction data will be saved. Must not be null.
    - `blockstore`: A pointer to an fd_blockstore_t structure from which block data is queried. Must not be null.
    - `msg`: A pointer to an fd_replay_notif_msg_t structure containing information about the block to be saved. Must not be null.
- **Output**: None
- **See also**: [`fd_rpc_history_save`](fd_rpc_history.c.driver.md#fd_rpc_history_save)  (Implementation)


---
### fd\_rpc\_history\_first\_slot<!-- {{#callable_declaration:fd_rpc_history_first_slot}} -->
Retrieve the first slot number from the RPC history.
- **Description**: Use this function to obtain the first slot number recorded in the RPC history, which can be useful for understanding the starting point of the stored transaction history. This function should be called with a valid RPC history object, typically after the history has been initialized or populated with data. It is important to ensure that the provided history object is not null to avoid undefined behavior.
- **Inputs**:
    - `hist`: A pointer to an fd_rpc_history_t object representing the RPC history. Must not be null. The caller retains ownership of this object.
- **Output**: Returns the first slot number as an unsigned long integer, representing the earliest slot in the history.
- **See also**: [`fd_rpc_history_first_slot`](fd_rpc_history.c.driver.md#fd_rpc_history_first_slot)  (Implementation)


---
### fd\_rpc\_history\_latest\_slot<!-- {{#callable_declaration:fd_rpc_history_latest_slot}} -->
Retrieve the latest slot number from the RPC history.
- **Description**: Use this function to obtain the most recent slot number recorded in the RPC history. This is useful for determining the latest state or transaction point in the history. The function should be called on a valid `fd_rpc_history_t` object, which must have been properly initialized and populated with data. It is important to ensure that the `hist` parameter is not null before calling this function to avoid undefined behavior.
- **Inputs**:
    - `hist`: A pointer to an `fd_rpc_history_t` object. This parameter must not be null and should point to a valid and initialized RPC history structure. The caller retains ownership of this object.
- **Output**: Returns the latest slot number as an unsigned long integer, representing the most recent entry in the RPC history.
- **See also**: [`fd_rpc_history_latest_slot`](fd_rpc_history.c.driver.md#fd_rpc_history_latest_slot)  (Implementation)


---
### fd\_rpc\_history\_get\_block\_info<!-- {{#callable_declaration:fd_rpc_history_get_block_info}} -->
Retrieve block information for a specified slot.
- **Description**: Use this function to obtain the block information associated with a specific slot from the RPC history. It is useful when you need to access metadata or details about a block that has been previously recorded. The function requires a valid RPC history object and a slot number. If the slot does not exist in the history, the function returns NULL, indicating that no information is available for the given slot.
- **Inputs**:
    - `hist`: A pointer to an fd_rpc_history_t object representing the RPC history. Must not be null, and should be properly initialized before calling this function.
    - `slot`: An unsigned long integer representing the slot number for which block information is requested. The slot should be a valid number within the range of recorded slots in the history.
- **Output**: A pointer to an fd_replay_notif_msg_t structure containing the block information for the specified slot, or NULL if the slot is not found in the history.
- **See also**: [`fd_rpc_history_get_block_info`](fd_rpc_history.c.driver.md#fd_rpc_history_get_block_info)  (Implementation)


---
### fd\_rpc\_history\_get\_block\_info\_by\_hash<!-- {{#callable_declaration:fd_rpc_history_get_block_info_by_hash}} -->
Retrieves block information by its hash from the history.
- **Description**: Use this function to obtain block information associated with a specific hash from the RPC history. It is useful when you need to access block details using a hash rather than a slot number. Ensure that the history object is properly initialized and populated with block data before calling this function. If the hash is not found, the function returns NULL, indicating that no block with the given hash exists in the history.
- **Inputs**:
    - `hist`: A pointer to an initialized `fd_rpc_history_t` object. This object must contain the block history data from which the block information is to be retrieved. The caller retains ownership and must ensure it is not null.
    - `h`: A pointer to an `fd_hash_t` representing the hash of the block to be retrieved. The hash must be valid and the caller retains ownership. If the hash is not found, the function returns NULL.
- **Output**: A pointer to an `fd_replay_notif_msg_t` containing the block information if the hash is found, or NULL if the hash is not present in the history.
- **See also**: [`fd_rpc_history_get_block_info_by_hash`](fd_rpc_history.c.driver.md#fd_rpc_history_get_block_info_by_hash)  (Implementation)


---
### fd\_rpc\_history\_get\_block<!-- {{#callable_declaration:fd_rpc_history_get_block}} -->
Retrieve a block of data from the RPC history for a given slot.
- **Description**: This function retrieves a block of data associated with a specific slot from the RPC history. It should be used when you need to access the data stored for a particular slot. The function allocates memory for the block data, which the caller is responsible for freeing. If the specified slot does not exist in the history, the function returns NULL and sets the block size to ULONG_MAX. This function must be called with a valid history object and a non-null pointer for the block size.
- **Inputs**:
    - `hist`: A pointer to an fd_rpc_history_t object representing the RPC history. Must not be null.
    - `slot`: The slot number for which the block data is requested. Must be a valid slot present in the history.
    - `blk_sz`: A pointer to a ulong where the size of the retrieved block will be stored. Must not be null. If the block is not found, it is set to ULONG_MAX.
- **Output**: Returns a pointer to the block data if successful, or NULL if the block is not found or an error occurs. The caller is responsible for freeing the returned data.
- **See also**: [`fd_rpc_history_get_block`](fd_rpc_history.c.driver.md#fd_rpc_history_get_block)  (Implementation)


---
### fd\_rpc\_history\_get\_txn<!-- {{#callable_declaration:fd_rpc_history_get_txn}} -->
Retrieve a transaction from the RPC history using its signature.
- **Description**: This function retrieves a transaction from the RPC history based on the provided transaction signature. It is used when you need to access the details of a specific transaction that has been previously recorded in the history. The function allocates memory for the transaction data, which the caller is responsible for freeing. If the transaction is not found, the function returns NULL and sets the transaction size to ULONG_MAX. This function should be called only after the RPC history has been properly initialized and populated with transaction data.
- **Inputs**:
    - `hist`: A pointer to an initialized fd_rpc_history_t structure representing the RPC history. Must not be null.
    - `sig`: A pointer to an fd_rpc_txn_key_t structure containing the signature of the transaction to retrieve. Must not be null.
    - `txn_sz`: A pointer to an unsigned long where the size of the transaction will be stored. Must not be null. If the transaction is not found, it is set to ULONG_MAX.
    - `slot`: A pointer to an unsigned long where the slot number of the transaction will be stored. Must not be null.
- **Output**: Returns a pointer to the transaction data if found, or NULL if the transaction is not found or an error occurs. The caller is responsible for freeing the returned data.
- **See also**: [`fd_rpc_history_get_txn`](fd_rpc_history.c.driver.md#fd_rpc_history_get_txn)  (Implementation)


---
### fd\_rpc\_history\_first\_txn\_for\_acct<!-- {{#callable_declaration:fd_rpc_history_first_txn_for_acct}} -->
Retrieve the first transaction for a specified account.
- **Description**: This function is used to obtain the first transaction associated with a given account from the transaction history. It should be called when you need to access the earliest transaction details for a specific account. The function requires a valid history object and account identifier. If the account has no transactions, the function returns NULL. The transaction signature and slot number are output through the provided pointers.
- **Inputs**:
    - `hist`: A pointer to an fd_rpc_history_t object representing the transaction history. Must not be null.
    - `acct`: A pointer to an fd_pubkey_t object representing the account's public key. Must not be null.
    - `sig`: A pointer to an fd_rpc_txn_key_t object where the transaction signature will be stored. Must not be null.
    - `slot`: A pointer to an unsigned long where the slot number of the transaction will be stored. Must not be null.
- **Output**: A pointer to the transaction data if successful, or NULL if the account has no transactions.
- **See also**: [`fd_rpc_history_first_txn_for_acct`](fd_rpc_history.c.driver.md#fd_rpc_history_first_txn_for_acct)  (Implementation)


---
### fd\_rpc\_history\_next\_txn\_for\_acct<!-- {{#callable_declaration:fd_rpc_history_next_txn_for_acct}} -->
Retrieve the next transaction for an account from the history.
- **Description**: Use this function to iterate over transactions associated with a specific account in the history. It should be called after obtaining an initial iterator from `fd_rpc_history_first_txn_for_acct`. The function updates the provided transaction key and slot with the details of the next transaction. If there are no more transactions, it returns `NULL`. Ensure that the `hist` parameter is a valid history object and that `iter` is a valid iterator obtained from a previous call to this function or `fd_rpc_history_first_txn_for_acct`.
- **Inputs**:
    - `hist`: A pointer to a valid `fd_rpc_history_t` object representing the transaction history. Must not be null.
    - `sig`: A pointer to an `fd_rpc_txn_key_t` structure where the function will store the signature of the next transaction. Must not be null.
    - `slot`: A pointer to an `ulong` where the function will store the slot number of the next transaction. Must not be null.
    - `iter`: A pointer to the current iterator position, obtained from a previous call to this function or `fd_rpc_history_first_txn_for_acct`. Must not be null.
- **Output**: Returns a pointer to the next transaction iterator if successful, or `NULL` if there are no more transactions.
- **See also**: [`fd_rpc_history_next_txn_for_acct`](fd_rpc_history.c.driver.md#fd_rpc_history_next_txn_for_acct)  (Implementation)



# Purpose
This C source code file is part of a larger system that implements a JSON-RPC service for interacting with a blockchain, likely Solana, given the references to Solana-specific concepts such as slots, epochs, and accounts. The file defines a comprehensive set of RPC methods that allow clients to query blockchain data, such as account information, block details, transaction statuses, and more. It also supports WebSocket subscriptions for real-time updates on account changes and slot progressions. The code is structured to handle various JSON-RPC requests, parse incoming JSON data, and respond with appropriately formatted JSON responses.

Key components of the code include the definition of data structures for managing WebSocket subscriptions and performance samples, as well as functions for handling specific RPC methods like `getAccountInfo`, `getBalance`, `getBlock`, and many others. The file also includes logic for managing WebSocket connections and subscriptions, allowing clients to receive updates on blockchain events. The code is designed to be integrated into a larger application, as indicated by the inclusion of various headers and the use of external functions and data types. The file serves as a central piece of the RPC service, providing both synchronous and asynchronous interaction capabilities with the blockchain.
# Imports and Dependencies

---
- `fd_rpc_service.h`
- `fd_methods.h`
- `fd_webserver.h`
- `base_enc.h`
- `../../flamenco/types/fd_types.h`
- `../../flamenco/types/fd_solana_block.pb.h`
- `../../flamenco/runtime/fd_runtime.h`
- `../../flamenco/runtime/fd_acc_mgr.h`
- `../../flamenco/runtime/sysvar/fd_sysvar_rent.h`
- `../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h`
- `../../ballet/base58/fd_base58.h`
- `../../ballet/base64/fd_base64.h`
- `fd_rpc_history.h`
- `keywords.h`
- `errno.h`
- `stdlib.h`
- `stdio.h`
- `sys/socket.h`
- `netinet/in.h`
- `stdarg.h`
- `../../app/firedancer/version.h`
- `../../util/tmpl/fd_deque.c`
- `../../util/tmpl/fd_redblack.c`


# Global Variables

---
### PATH\_COMMITMENT
- **Type**: ``uint[4]``
- **Description**: `PATH_COMMITMENT` is a static constant array of unsigned integers with four elements. Each element in the array is a combination of a JSON token type and a keyword or integer, packed into a single 32-bit unsigned integer. This array is used to define a specific path in a JSON structure, likely for parsing or extracting specific data related to JSON-RPC parameters and commitment levels.
- **Use**: This variable is used to specify a path in a JSON structure for extracting or processing JSON-RPC parameters related to commitment levels.


# Data Structures

---
### fd\_ws\_subscription
- **Type**: `struct`
- **Members**:
    - `conn_id`: A unique identifier for the connection associated with the subscription.
    - `meth_id`: An identifier for the method associated with the subscription.
    - `call_id`: A string identifier for the call associated with the subscription, with a maximum length of 64 characters.
    - `subsc_id`: A unique identifier for the subscription itself.
    - `acct_subscribe`: A union member containing details specific to account subscriptions, including account, encoding, offset, and length.
- **Description**: The `fd_ws_subscription` structure is used to manage WebSocket subscriptions in a web server context, specifically for account and slot notifications. It contains identifiers for the connection, method, and call, as well as a unique subscription ID. The structure also includes a union for account-specific subscription details, such as the account public key, encoding type, and optional data slice parameters (offset and length). This allows the server to track and manage active subscriptions efficiently, ensuring that clients receive the correct notifications based on their subscription criteria.


---
### fd\_stats\_snapshot\_t
- **Type**: `typedef`
- **Description**: The `fd_stats_snapshot_t` is a typedef for a structure named `fd_stats_snapshot`. However, the actual definition of the structure is not provided in the given code. This typedef is likely used to create a shorthand for referring to the `fd_stats_snapshot` structure, but without the structure's definition, we cannot describe its members or purpose.


---
### fd\_perf\_sample
- **Type**: `struct`
- **Members**:
    - `num_slots`: Represents the number of slots processed in the sample.
    - `num_transactions`: Indicates the total number of transactions processed in the sample.
    - `num_non_vote_transactions`: Counts the number of non-vote transactions in the sample.
    - `highest_slot`: Records the highest slot number observed in the sample.
- **Description**: The `fd_perf_sample` structure is designed to capture performance metrics over a specific period in a blockchain system. It tracks the number of slots processed, the total number of transactions, the number of non-vote transactions, and the highest slot number observed during the sample period. This data structure is useful for analyzing the performance and throughput of the system over time.


---
### fd\_perf\_sample\_t
- **Type**: `struct`
- **Members**:
    - `num_slots`: Represents the number of slots processed in the performance sample.
    - `num_transactions`: Indicates the total number of transactions processed in the performance sample.
    - `num_non_vote_transactions`: Counts the number of non-vote transactions in the performance sample.
    - `highest_slot`: Records the highest slot number reached in the performance sample.
- **Description**: The `fd_perf_sample_t` structure is designed to capture performance metrics related to slot processing in a blockchain context. It includes fields to track the number of slots processed, the total number of transactions, the number of non-vote transactions, and the highest slot number reached during the sample period. This data structure is likely used to monitor and analyze the performance of the system over time, providing insights into transaction throughput and slot progression.


---
### fd\_rpc\_global\_ctx
- **Type**: `struct`
- **Members**:
    - `spad`: A pointer to an fd_spad_t structure, likely used for memory management or shared data.
    - `ws`: An instance of fd_webserver_t, representing the web server context.
    - `funk`: A pointer to an fd_funk_t structure, possibly related to transaction or account management.
    - `blockstore`: An array of fd_blockstore_t structures, used for storing blockchain data.
    - `blockstore_fd`: An integer file descriptor for the blockstore, used for I/O operations.
    - `sub_list`: An array of fd_ws_subscription structures, managing WebSocket subscriptions.
    - `sub_cnt`: An unsigned long representing the count of active subscriptions.
    - `last_subsc_id`: An unsigned long tracking the last subscription ID assigned.
    - `tpu_socket`: An integer representing a socket for transaction processing unit communication.
    - `tpu_addr`: A sockaddr_in structure holding the address for the TPU socket.
    - `perf_samples`: A pointer to an fd_perf_sample_t structure, used for performance sampling.
    - `perf_sample_snapshot`: An instance of fd_perf_sample_t, capturing a snapshot of performance data.
    - `perf_sample_ts`: A long integer timestamp for the last performance sample.
    - `stake_ci`: A pointer to an fd_stake_ci_t structure, likely related to staking information.
    - `acct_age`: An unsigned long representing the age of an account.
    - `history`: A pointer to an fd_rpc_history_t structure, managing RPC history data.
- **Description**: The `fd_rpc_global_ctx` structure is a comprehensive context for managing a web server and its associated functionalities in a blockchain environment. It includes pointers and instances for managing shared data, web server operations, transaction processing, WebSocket subscriptions, performance sampling, and blockchain history. This structure is central to the operation of the RPC server, handling various aspects of blockchain data management and communication.


---
### fd\_rpc\_global\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `spad`: A pointer to an fd_spad_t structure, likely used for shared memory or data allocation.
    - `ws`: An instance of fd_webserver_t, representing the web server context.
    - `funk`: A pointer to an fd_funk_t structure, possibly related to transaction or account management.
    - `blockstore`: An array of one fd_blockstore_t, used for storing blockchain data.
    - `blockstore_fd`: An integer file descriptor for the blockstore.
    - `sub_list`: An array of fd_ws_subscription structures, managing WebSocket subscriptions.
    - `sub_cnt`: An unsigned long representing the count of active subscriptions.
    - `last_subsc_id`: An unsigned long tracking the last subscription ID used.
    - `tpu_socket`: An integer representing the socket for transaction processing unit communication.
    - `tpu_addr`: A sockaddr_in structure holding the address for the TPU socket.
    - `perf_samples`: A pointer to an fd_perf_sample_t structure, storing performance samples.
    - `perf_sample_snapshot`: An fd_perf_sample_t structure holding a snapshot of performance data.
    - `perf_sample_ts`: A long integer representing the timestamp of the last performance sample.
    - `stake_ci`: A pointer to an fd_stake_ci_t structure, likely related to staking information.
    - `acct_age`: An unsigned long representing the age of an account.
    - `history`: A pointer to an fd_rpc_history_t structure, managing RPC history.
- **Description**: The `fd_rpc_global_ctx_t` structure is a comprehensive context for managing the global state of an RPC server in a blockchain environment. It includes components for web server management, transaction processing, performance sampling, and WebSocket subscriptions. The structure also handles blockchain data storage and retrieval, as well as staking and account management. It is designed to facilitate efficient communication and data handling within the server, supporting various RPC methods and WebSocket interactions.


---
### fd\_rpc\_ctx
- **Type**: `struct`
- **Members**:
    - `call_id`: A character array of size 64 used to store the call identifier for the RPC context.
    - `global`: A pointer to an fd_rpc_global_ctx_t structure, representing the global context associated with the RPC context.
- **Description**: The `fd_rpc_ctx` structure is designed to encapsulate the context for a remote procedure call (RPC) within the Firedancer application. It contains a `call_id` to uniquely identify the RPC call and a pointer to a `fd_rpc_global_ctx_t` structure, which holds the global context and shared resources needed for the RPC operations. This structure is essential for managing and tracking the state and execution of RPC calls within the system.


---
### product\_rb\_node
- **Type**: `struct`
- **Members**:
    - `key`: A public key used as the unique identifier for the node.
    - `nleader`: The number of times this node has been a leader.
    - `nproduced`: The number of blocks produced by this node.
    - `redblack_parent`: Pointer to the parent node in the red-black tree.
    - `redblack_left`: Pointer to the left child node in the red-black tree.
    - `redblack_right`: Pointer to the right child node in the red-black tree.
    - `redblack_color`: Color of the node in the red-black tree, typically red or black.
- **Description**: The `product_rb_node` structure represents a node in a red-black tree, which is a self-balancing binary search tree. Each node contains a public key (`key`) that serves as a unique identifier, and it tracks the number of times the node has been a leader (`nleader`) and the number of blocks it has produced (`nproduced`). The structure also includes pointers to the parent, left, and right child nodes (`redblack_parent`, `redblack_left`, `redblack_right`) and a color attribute (`redblack_color`) to maintain the properties of the red-black tree.


---
### product\_rb\_node\_t
- **Type**: `struct`
- **Members**:
    - `key`: A public key of type `fd_pubkey_t` used as the node's key in the red-black tree.
    - `nleader`: An unsigned integer representing the number of times this node has been a leader.
    - `nproduced`: An unsigned integer representing the number of blocks produced by this node.
    - `redblack_parent`: An unsigned long integer representing the index of the parent node in the red-black tree.
    - `redblack_left`: An unsigned long integer representing the index of the left child node in the red-black tree.
    - `redblack_right`: An unsigned long integer representing the index of the right child node in the red-black tree.
    - `redblack_color`: An integer representing the color of the node in the red-black tree, typically 0 for black and 1 for red.
- **Description**: The `product_rb_node_t` structure represents a node in a red-black tree, which is a self-balancing binary search tree. Each node contains a public key (`key`) used for identification, counters for leadership (`nleader`) and production (`nproduced`), and pointers to its parent, left, and right children in the tree (`redblack_parent`, `redblack_left`, `redblack_right`). The `redblack_color` field indicates the color of the node, which is crucial for maintaining the balance properties of the red-black tree.


---
### leader\_rb\_node
- **Type**: `struct`
- **Members**:
    - `key`: A public key of type `fd_pubkey_t` used as the node's key in the red-black tree.
    - `first`: An unsigned integer representing the first occurrence or index related to the node.
    - `last`: An unsigned integer representing the last occurrence or index related to the node.
    - `redblack_parent`: An unsigned long integer representing the parent node in the red-black tree.
    - `redblack_left`: An unsigned long integer representing the left child node in the red-black tree.
    - `redblack_right`: An unsigned long integer representing the right child node in the red-black tree.
    - `redblack_color`: An integer representing the color of the node in the red-black tree, typically 0 for black and 1 for red.
- **Description**: The `leader_rb_node` structure is a node in a red-black tree, which is a self-balancing binary search tree. It is used to store and manage leader information, with each node containing a public key (`key`), indices (`first` and `last`), and pointers to its parent and children in the tree (`redblack_parent`, `redblack_left`, `redblack_right`). The `redblack_color` field indicates the color of the node, which is crucial for maintaining the balance properties of the red-black tree.


---
### leader\_rb\_node\_t
- **Type**: `struct`
- **Members**:
    - `key`: A public key of type `fd_pubkey_t` used as a unique identifier for the node.
    - `first`: An unsigned integer representing the first occurrence or index of the leader in the schedule.
    - `last`: An unsigned integer representing the last occurrence or index of the leader in the schedule.
    - `redblack_parent`: An unsigned long integer pointing to the parent node in the red-black tree.
    - `redblack_left`: An unsigned long integer pointing to the left child node in the red-black tree.
    - `redblack_right`: An unsigned long integer pointing to the right child node in the red-black tree.
    - `redblack_color`: An integer representing the color of the node in the red-black tree, typically 0 for black and 1 for red.
- **Description**: The `leader_rb_node_t` structure represents a node in a red-black tree, which is used to manage and organize leader schedules in a blockchain context. Each node contains a public key as a unique identifier, indices for the first and last occurrences of the leader in the schedule, and pointers to its parent and children in the red-black tree. The structure also includes a color attribute to maintain the properties of the red-black tree, ensuring balanced and efficient data retrieval and updates.


# Functions

---
### fd\_method\_simple\_error<!-- {{#callable:fd_method_simple_error}} -->
The `fd_method_simple_error` function sends an error response to the web server with a specified error code and message.
- **Inputs**:
    - `ctx`: A pointer to the `fd_rpc_ctx_t` structure that contains the context for the RPC call, including the call ID and global context.
    - `errcode`: An integer representing the error code to be sent in the response.
    - `text`: A string containing the error message to be included in the response.
- **Control Flow**:
    - The function calls [`fd_web_reply_error`](fd_webserver.c.driver.md#fd_web_reply_error), passing the web server context, error code, error message, and the call ID from the context.
    - The [`fd_web_reply_error`](fd_webserver.c.driver.md#fd_web_reply_error) function handles the actual sending of the error response to the client.
- **Output**: The function does not return a value; it directly sends an error response to the web server.
- **Functions called**:
    - [`fd_web_reply_error`](fd_webserver.c.driver.md#fd_web_reply_error)


---
### fd\_method\_error<!-- {{#callable:fd_method_error}} -->
The `fd_method_error` function formats an error message and invokes [`fd_method_simple_error`](#fd_method_simple_error) to handle the error response.
- **Inputs**:
    - `ctx`: A pointer to the `fd_rpc_ctx_t` structure that contains the context for the RPC call.
    - `errcode`: An integer representing the error code to be returned.
    - `format`: A format string for the error message, similar to printf.
    - `ap`: A variable argument list that contains additional arguments for the format string.
- **Control Flow**:
    - The function initializes a character array `text` to hold the formatted error message.
    - It uses `va_start` to initialize the variable argument list `ap` for processing additional arguments.
    - The `vsnprintf` function is called to format the error message into the `text` array using the provided format string and arguments.
    - After formatting, `va_end` is called to clean up the variable argument list.
    - Finally, the function calls [`fd_method_simple_error`](#fd_method_simple_error) with the context, error code, and formatted error message.
- **Output**: The function does not return a value; it sends an error response using [`fd_method_simple_error`](#fd_method_simple_error).
- **Functions called**:
    - [`fd_method_simple_error`](#fd_method_simple_error)


---
### read\_account\_with\_xid<!-- {{#callable:read_account_with_xid}} -->
Retrieves an account record based on a transaction ID.
- **Inputs**:
    - `ctx`: A pointer to the `fd_rpc_ctx_t` structure that contains the context for the RPC call.
    - `recid`: A pointer to the `fd_funk_rec_key_t` structure that represents the record key for the account.
    - `xid`: A pointer to the `fd_funk_txn_xid_t` structure that contains the transaction ID used to query the account.
    - `result_len`: A pointer to an unsigned long variable that will hold the length of the result.
- **Control Flow**:
    - The function retrieves a transaction map from the global context using `fd_funk_txn_map`.
    - It queries the transaction using the provided transaction ID (`xid`) and the transaction map with `fd_funk_txn_query`.
    - Finally, it calls `fd_funk_rec_query_copy` to retrieve a copy of the account record associated with the transaction and the record key, storing the result length.
- **Output**: Returns a pointer to the account record if found, or NULL if not found.


---
### read\_account<!-- {{#callable:read_account}} -->
The `read_account` function retrieves account data from a record based on a given record key.
- **Inputs**:
    - `ctx`: A pointer to the `fd_rpc_ctx_t` structure that contains the global context for the RPC call.
    - `recid`: A pointer to the `fd_funk_rec_key_t` structure that represents the key of the account record to be read.
    - `result_len`: A pointer to an unsigned long variable that will hold the length of the result data.
- **Control Flow**:
    - The function calls `fd_funk_rec_query_copy`, passing the global `funk` context, a NULL transaction pointer, the record ID, the virtual memory space, and the result length pointer.
    - The `fd_funk_rec_query_copy` function is expected to perform the actual retrieval of the account data based on the provided record key.
- **Output**: The function returns a pointer to the account data retrieved, or NULL if the retrieval fails.


---
### get\_slot\_from\_commitment\_level<!-- {{#callable:get_slot_from_commitment_level}} -->
The `get_slot_from_commitment_level` function retrieves the current slot number based on the specified commitment level.
- **Inputs**:
    - `values`: A pointer to a `json_values` structure containing the JSON parameters, including the commitment level.
    - `ctx`: A pointer to a `fd_rpc_ctx_t` structure that holds the context for the RPC call, including access to global state.
- **Control Flow**:
    - The function initializes a variable to hold the size of the commitment string and retrieves the commitment level from the JSON values using [`json_get_value`](fd_methods.c.driver.md#json_get_value).
    - If the commitment string is NULL, it calls [`fd_rpc_history_latest_slot`](fd_rpc_history.c.driver.md#fd_rpc_history_latest_slot) to get the latest slot from the history context.
    - If the commitment string matches 'confirmed', it returns the current highest confirmed slot from the blockstore.
    - If it matches 'processed', it returns the latest processed slot from the blockstore.
    - If it matches 'finalized', it returns the latest finalized slot from the blockstore.
    - If the commitment string does not match any known levels, it logs an error and returns a null slot value.
- **Output**: Returns the slot number corresponding to the specified commitment level, or a null slot value if the commitment level is invalid.
- **Functions called**:
    - [`json_get_value`](fd_methods.c.driver.md#json_get_value)
    - [`fd_rpc_history_latest_slot`](fd_rpc_history.c.driver.md#fd_rpc_history_latest_slot)
    - [`fd_method_error`](#fd_method_error)


---
### read\_epoch\_bank<!-- {{#callable:read_epoch_bank}} -->
The `read_epoch_bank` function retrieves and decodes the epoch bank data from the account.
- **Inputs**:
    - `ctx`: A pointer to the `fd_rpc_ctx_t` structure, which contains the context for the RPC call.
- **Control Flow**:
    - The function starts by obtaining the record key for the epoch bank using `fd_runtime_epoch_bank_key()`.
    - It then calls [`read_account`](#read_account) with the context and the record key to read the account data, storing the result in `val`.
    - If `val` is NULL, a warning is logged and the function returns NULL.
    - The function checks the magic number in the retrieved data to ensure it matches `FD_RUNTIME_ENC_BINCODE`; if not, an error is logged.
    - The function then decodes the epoch bank data using `fd_bincode_decode_spad`, passing the appropriate parameters.
    - If the decoding fails, a warning is logged and the function returns NULL.
    - Finally, if all checks pass, the decoded `fd_epoch_bank_t` pointer is returned.
- **Output**: Returns a pointer to the decoded `fd_epoch_bank_t` structure, or NULL if an error occurs.
- **Functions called**:
    - [`read_account`](#read_account)


---
### read\_slot\_bank<!-- {{#callable:read_slot_bank}} -->
The `read_slot_bank` function retrieves the slot bank data for a specified slot.
- **Inputs**:
    - `ctx`: A pointer to the `fd_rpc_ctx_t` structure that contains the global context for the RPC.
    - `slot`: An unsigned long integer representing the slot number for which the slot bank data is to be read.
- **Control Flow**:
    - The function begins by obtaining the record key for the slot bank using `fd_runtime_slot_bank_key()`.
    - It retrieves block information for the specified slot using `fd_rpc_history_get_block_info()`, and checks if the information is valid.
    - If the block information is not found, a warning is logged and the function returns NULL.
    - Next, it constructs a transaction ID (`xid`) using the slot number and attempts to read the account data using `read_account_with_xid()`.
    - If the account data is not found, it falls back to reading the account data without the transaction ID using `read_account()`.
    - The function checks if the retrieved data is valid by verifying the magic number.
    - If the magic number is invalid, an error is logged.
    - The function then decodes the slot bank data using `fd_bincode_decode_spad()` and checks for successful decoding.
    - If decoding fails, a warning is logged and the function returns NULL.
    - Finally, if all operations are successful, the function returns a pointer to the `fd_slot_bank_t` structure containing the slot bank data.
- **Output**: Returns a pointer to an `fd_slot_bank_t` structure containing the slot bank data for the specified slot, or NULL if an error occurs.
- **Functions called**:
    - [`fd_rpc_history_get_block_info`](fd_rpc_history.c.driver.md#fd_rpc_history_get_block_info)
    - [`read_account_with_xid`](#read_account_with_xid)
    - [`read_account`](#read_account)


---
### method\_getAccountInfo<!-- {{#callable:method_getAccountInfo}} -->
The `method_getAccountInfo` function retrieves account information based on a provided public key and encoding type.
- **Inputs**:
    - `values`: A pointer to a `json_values` structure containing the JSON-RPC parameters.
    - `ctx`: A pointer to a `fd_rpc_ctx_t` structure that holds the context for the RPC call.
- **Control Flow**:
    - The function begins by defining paths to extract parameters from the JSON input.
    - It retrieves the first parameter, which is expected to be a base58-encoded public key, and checks for validity.
    - If the public key is invalid, an error is returned.
    - Next, it retrieves the second parameter for the encoding type, defaulting to base58 if not provided.
    - The function then reads the account data associated with the public key.
    - If no account data is found, a JSON response indicating a null value is sent back.
    - The function checks for optional data slice parameters (length and offset) to limit the response data.
    - Finally, it formats the account data into JSON and sends it back to the client.
- **Output**: The function outputs a JSON-RPC response containing the account information or an error message if any issues occur during processing.
- **Functions called**:
    - [`json_get_value`](fd_methods.c.driver.md#json_get_value)
    - [`fd_method_error`](#fd_method_error)
    - [`read_account`](#read_account)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)
    - [`fd_rpc_history_latest_slot`](fd_rpc_history.c.driver.md#fd_rpc_history_latest_slot)
    - [`fd_account_to_json`](fd_block_to_json.c.driver.md#fd_account_to_json)


---
### method\_getBalance<!-- {{#callable:method_getBalance}} -->
Retrieves the balance of a specified account.
- **Inputs**:
    - `values`: A pointer to a `json_values` structure containing the JSON-RPC parameters.
    - `ctx`: A pointer to a `fd_rpc_ctx_t` structure representing the RPC context.
- **Control Flow**:
    - Begin a SPAD frame to manage memory allocation.
    - Define a static path to extract the account parameter from the JSON input.
    - Retrieve the account string from the JSON input; if not found, return an error.
    - Decode the account string from base58 format into a public key structure; if decoding fails, return an error.
    - Construct a record key for the account and read the account data using this key.
    - If the account data is not found, respond with a JSON indicating a balance of 0.
    - If the account data is found, extract the balance and respond with a JSON containing the balance and the current slot.
- **Output**: Returns a JSON-RPC response containing the account balance and the current slot information.
- **Functions called**:
    - [`json_get_value`](fd_methods.c.driver.md#json_get_value)
    - [`fd_method_error`](#fd_method_error)
    - [`read_account`](#read_account)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)
    - [`fd_rpc_history_latest_slot`](fd_rpc_history.c.driver.md#fd_rpc_history_latest_slot)


---
### method\_getBlock<!-- {{#callable:method_getBlock}} -->
The `method_getBlock` function retrieves block information based on a specified slot number and returns it in a specified encoding format.
- **Inputs**:
    - `values`: A pointer to a `struct json_values` containing the parameters for the method call, including the slot number and optional encoding details.
    - `ctx`: A pointer to a `fd_rpc_ctx_t` structure that holds the context for the RPC call, including the web server context.
- **Control Flow**:
    - The function defines static paths for extracting parameters from the JSON input.
    - It retrieves the slot number from the input and checks if it is provided; if not, it returns an error.
    - It retrieves the encoding type and validates it, defaulting to JSON if not specified.
    - It checks for optional parameters like maximum supported transaction version and transaction details, validating them accordingly.
    - The function fetches block information from the history based on the slot number and checks if the information is available.
    - It retrieves the block data and converts it to the specified JSON format, handling any errors that may occur during this process.
    - Finally, it returns the block information or an error message if any step fails.
- **Output**: The function outputs the block information in the specified encoding format or an error message if any validation or retrieval step fails.
- **Functions called**:
    - [`json_get_value`](fd_methods.c.driver.md#json_get_value)
    - [`fd_method_error`](#fd_method_error)
    - [`fd_rpc_history_get_block_info`](fd_rpc_history.c.driver.md#fd_rpc_history_get_block_info)
    - [`fd_rpc_history_get_block`](fd_rpc_history.c.driver.md#fd_rpc_history_get_block)
    - [`fd_block_to_json`](fd_block_to_json.c.driver.md#fd_block_to_json)


---
### method\_getBlockCommitment<!-- {{#callable:method_getBlockCommitment}} -->
The `method_getBlockCommitment` function logs a warning and returns an error indicating that the block commitment feature is not implemented.
- **Inputs**: None
- **Control Flow**:
    - The function begins by ignoring its input parameters `values` and `ctx`.
    - It logs a warning message stating that the `getBlockCommitment` method is not implemented.
    - It calls the [`fd_method_error`](#fd_method_error) function to report an error with a message indicating the method is not implemented.
    - Finally, it returns 0, indicating the end of the function execution.
- **Output**: The function does not produce a meaningful output; it returns 0 after logging an error and does not perform any operations related to block commitment.
- **Functions called**:
    - [`fd_method_error`](#fd_method_error)


---
### method\_getBlockHeight<!-- {{#callable:method_getBlockHeight}} -->
Retrieves the block height for a given commitment level.
- **Inputs**:
    - `values`: A pointer to a `struct json_values` containing the JSON-RPC parameters.
    - `ctx`: A pointer to a `fd_rpc_ctx_t` structure that holds the context for the RPC call.
- **Control Flow**:
    - Calls [`get_slot_from_commitment_level`](#get_slot_from_commitment_level) to determine the slot number based on the commitment level provided in `values`.
    - Retrieves block information using [`fd_rpc_history_get_block_info`](fd_rpc_history.c.driver.md#fd_rpc_history_get_block_info) for the determined slot.
    - If the block information is not available, it calls [`fd_method_error`](#fd_method_error) to report the error and returns 0.
    - If the block information is available, it formats the response as a JSON string containing the block height and sends it back using [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf).
- **Output**: Returns a JSON-RPC response containing the block height for the specified slot, or an error message if the block information is unavailable.
- **Functions called**:
    - [`get_slot_from_commitment_level`](#get_slot_from_commitment_level)
    - [`fd_rpc_history_get_block_info`](fd_rpc_history.c.driver.md#fd_rpc_history_get_block_info)
    - [`fd_method_error`](#fd_method_error)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)


---
### product\_rb\_compare<!-- {{#callable:product_rb_compare}} -->
Compares two `product_rb_node_t` structures based on their public key values.
- **Inputs**:
    - `left`: A pointer to the first `product_rb_node_t` structure to compare.
    - `right`: A pointer to the second `product_rb_node_t` structure to compare.
- **Control Flow**:
    - Iterates over each element of the public key stored in the `key` field of both `product_rb_node_t` structures.
    - For each element, it compares the corresponding `ulong` values from both nodes.
    - If a difference is found, it returns -1 if the first node's value is less than the second's, or 1 if it is greater.
    - If all elements are equal, it returns 0, indicating that the two nodes are equal.
- **Output**: Returns a negative value if the first node is less than the second, a positive value if it is greater, or 0 if they are equal.


---
### method\_getBlockProduction<!-- {{#callable:method_getBlockProduction}} -->
The `method_getBlockProduction` function retrieves the production statistics of block leaders over a specified range of slots.
- **Inputs**: None
- **Control Flow**:
    - The function begins by initializing the necessary context and retrieving the start and end slots from the blockstore.
    - It calculates the number of slots to process and allocates shared memory for a red-black tree to store production data.
    - The function retrieves the leader schedule for the starting slot and iterates through the slots from start to end.
    - For each slot, it checks if there is a leader and updates the count of blocks produced by that leader.
    - Finally, it formats the results into a JSON response and sends it back to the web server.
- **Output**: The function outputs a JSON object containing the production statistics of each leader, including the number of times they led and the number of blocks they produced, along with the range of slots processed.
- **Functions called**:
    - [`fd_rpc_history_get_block_info`](fd_rpc_history.c.driver.md#fd_rpc_history_get_block_info)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)
    - [`fd_rpc_history_latest_slot`](fd_rpc_history.c.driver.md#fd_rpc_history_latest_slot)


---
### method\_getBlocks<!-- {{#callable:method_getBlocks}} -->
The `method_getBlocks` function retrieves a range of block slot numbers from a JSON-RPC request.
- **Inputs**:
    - `values`: A pointer to a `json_values` structure containing the parsed JSON-RPC request.
    - `ctx`: A pointer to a `fd_rpc_ctx_t` structure that holds the context for the RPC call.
- **Control Flow**:
    - Defines static paths for extracting the start and end slot numbers from the JSON request.
    - Retrieves the start slot number from the request; if not provided, an error is returned.
    - Retrieves the end slot number from the request; if not provided, it defaults to ULONG_MAX.
    - Adjusts the start and end slot numbers to ensure they are within the valid range of historical slots.
    - Begins constructing a JSON response with the result array.
    - Iterates from the start slot to the end slot, retrieving block information for each slot.
    - If block information is found, the slot number is added to the result array.
    - Finalizes the JSON response and sends it back to the client.
- **Output**: Returns a JSON-RPC response containing an array of block slot numbers within the specified range.
- **Functions called**:
    - [`json_get_value`](fd_methods.c.driver.md#json_get_value)
    - [`fd_method_error`](#fd_method_error)
    - [`fd_rpc_history_first_slot`](fd_rpc_history.c.driver.md#fd_rpc_history_first_slot)
    - [`fd_rpc_history_latest_slot`](fd_rpc_history.c.driver.md#fd_rpc_history_latest_slot)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)
    - [`fd_rpc_history_get_block_info`](fd_rpc_history.c.driver.md#fd_rpc_history_get_block_info)


---
### method\_getBlocksWithLimit<!-- {{#callable:method_getBlocksWithLimit}} -->
Retrieves a list of block slots starting from a specified slot number, limited by a specified count.
- **Inputs**:
    - `values`: A pointer to a `json_values` structure containing the parameters for the method.
    - `ctx`: A pointer to a `fd_rpc_ctx_t` structure that holds the context for the RPC call.
- **Control Flow**:
    - Defines static paths for extracting the start slot and limit from the input JSON.
    - Retrieves the start slot number from the input JSON; if not provided, an error is returned.
    - Retrieves the limit from the input JSON; if not provided, an error is returned.
    - Adjusts the start slot to ensure it is not less than the first available slot in history.
    - Limits the maximum number of blocks returned to 500,000.
    - Begins constructing a JSON response with the result array.
    - Iterates from the start slot to the latest slot in history, adding each valid slot to the result array until the limit is reached.
    - Finalizes the JSON response and sends it back to the client.
- **Output**: Returns a JSON object containing the result array of block slots, formatted according to the JSON-RPC 2.0 specification.
- **Functions called**:
    - [`json_get_value`](fd_methods.c.driver.md#json_get_value)
    - [`fd_method_error`](#fd_method_error)
    - [`fd_rpc_history_first_slot`](fd_rpc_history.c.driver.md#fd_rpc_history_first_slot)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)
    - [`fd_rpc_history_latest_slot`](fd_rpc_history.c.driver.md#fd_rpc_history_latest_slot)
    - [`fd_rpc_history_get_block_info`](fd_rpc_history.c.driver.md#fd_rpc_history_get_block_info)


---
### method\_getBlockTime<!-- {{#callable:method_getBlockTime}} -->
Retrieves the execution time of a block given its slot number.
- **Inputs**:
    - `values`: A pointer to a `json_values` structure containing the parameters for the method, specifically the slot number.
    - `ctx`: A pointer to a `fd_rpc_ctx_t` structure that holds the context for the RPC call.
- **Control Flow**:
    - Defines a static path for extracting the slot number from the JSON parameters.
    - Retrieves the slot number from the `values` using the defined path.
    - Checks if the slot number is provided; if not, it sends an error response and returns.
    - Fetches block information using the slot number from the global history context.
    - If the block information is not found, it sends an error response and returns.
    - Formats the block execution time into a JSON response and sends it back to the client.
- **Output**: Returns a JSON response containing the execution time of the block in nanoseconds, along with the request ID.
- **Functions called**:
    - [`json_get_value`](fd_methods.c.driver.md#json_get_value)
    - [`fd_method_error`](#fd_method_error)
    - [`fd_rpc_history_get_block_info`](fd_rpc_history.c.driver.md#fd_rpc_history_get_block_info)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)


---
### method\_getClusterNodes<!-- {{#callable:method_getClusterNodes}} -->
The `method_getClusterNodes` function logs a warning and returns an error indicating that the functionality is not implemented.
- **Inputs**: None
- **Control Flow**:
    - The function begins by ignoring its input parameters `values` and `ctx` using the `(void)` cast.
    - It logs a warning message stating that 'getClusterNodes is not implemented'.
    - It calls the [`fd_method_error`](#fd_method_error) function to report an error with code -1 and a message indicating that the method is not implemented.
    - Finally, it returns 0.
- **Output**: The function returns 0, indicating the completion of the function execution, but it also signals an error due to the unimplemented functionality.
- **Functions called**:
    - [`fd_method_error`](#fd_method_error)


---
### method\_getEpochInfo<!-- {{#callable:method_getEpochInfo}} -->
Retrieves epoch information based on the commitment level.
- **Inputs**:
    - `values`: A pointer to a `json_values` structure containing the JSON-RPC parameters.
    - `ctx`: A pointer to a `fd_rpc_ctx_t` structure that holds the context for the RPC call.
- **Control Flow**:
    - Begins a SPAD frame for memory allocation.
    - Retrieves the slot number based on the commitment level from the `values` input.
    - Fetches block information for the retrieved slot using [`fd_rpc_history_get_block_info`](fd_rpc_history.c.driver.md#fd_rpc_history_get_block_info).
    - If block information is not found, an error is reported and the function returns.
    - Reads the epoch bank using [`read_epoch_bank`](#read_epoch_bank).
    - If the epoch bank cannot be read, an error is reported and the function returns.
    - Calculates the epoch and slot index using `fd_slot_to_epoch`.
    - Formats and sends a JSON response containing the epoch information including absolute slot, block height, epoch number, slot index, number of slots in the epoch, and transaction count.
- **Output**: Returns a JSON-RPC formatted response containing epoch information including absolute slot, block height, epoch number, slot index, number of slots in the epoch, and transaction count.
- **Functions called**:
    - [`get_slot_from_commitment_level`](#get_slot_from_commitment_level)
    - [`fd_rpc_history_get_block_info`](fd_rpc_history.c.driver.md#fd_rpc_history_get_block_info)
    - [`fd_method_error`](#fd_method_error)
    - [`read_epoch_bank`](#read_epoch_bank)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)


---
### method\_getEpochSchedule<!-- {{#callable:method_getEpochSchedule}} -->
The `method_getEpochSchedule` function retrieves the epoch schedule from the epoch bank and formats it into a JSON response.
- **Inputs**: None
- **Control Flow**:
    - The function begins by entering a special memory frame using `FD_SPAD_FRAME_BEGIN`.
    - It attempts to read the epoch bank using the [`read_epoch_bank`](#read_epoch_bank) function.
    - If the epoch bank is not successfully read, it calls [`fd_method_simple_error`](#fd_method_simple_error) to report the error and returns 0.
    - If successful, it formats the epoch schedule data into a JSON response using [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf).
    - Finally, it ends the memory frame with `FD_SPAD_FRAME_END` and returns 0.
- **Output**: The function outputs a JSON object containing the epoch schedule details, including the first normal epoch, first normal slot, leader schedule slot offset, slots per epoch, and whether it is in warmup.
- **Functions called**:
    - [`read_epoch_bank`](#read_epoch_bank)
    - [`fd_method_simple_error`](#fd_method_simple_error)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)


---
### method\_getFeeForMessage<!-- {{#callable:method_getFeeForMessage}} -->
Calculates the fee for a given message based on its size.
- **Inputs**:
    - `values`: A pointer to a `json_values` structure containing the parameters for the method.
    - `ctx`: A pointer to a `fd_rpc_ctx_t` structure that holds the context for the RPC call.
- **Control Flow**:
    - Defines a static path to extract the first parameter from the JSON input, which is expected to be a base64 encoded string.
    - Retrieves the base64 encoded message from the `values` structure and checks if it is NULL; if so, it returns an error.
    - Checks if the decoded size of the base64 message exceeds the maximum transaction size (`FD_TXN_MTU`); if it does, it returns an error.
    - Decodes the base64 message into a buffer and checks if the decoding was successful; if not, it returns an error.
    - Prepares a JSON response with a fixed fee value of 5000 and sends it back to the client.
- **Output**: Returns a JSON response containing the calculated fee for the message, along with the current API version and slot information.
- **Functions called**:
    - [`json_get_value`](fd_methods.c.driver.md#json_get_value)
    - [`fd_method_error`](#fd_method_error)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)
    - [`fd_rpc_history_latest_slot`](fd_rpc_history.c.driver.md#fd_rpc_history_latest_slot)


---
### method\_getFirstAvailableBlock<!-- {{#callable:method_getFirstAvailableBlock}} -->
This function retrieves the first available block slot from the RPC history.
- **Inputs**: None
- **Control Flow**:
    - The function does not process any input arguments as the `values` parameter is unused.
    - It retrieves the web server context from the RPC context.
    - It formats a JSON-RPC response containing the first available block slot and the call ID.
    - The response is sent back to the client using [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf).
- **Output**: The function outputs a JSON-RPC formatted string containing the first available block slot and the request ID.
- **Functions called**:
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)
    - [`fd_rpc_history_first_slot`](fd_rpc_history.c.driver.md#fd_rpc_history_first_slot)


---
### method\_getGenesisHash<!-- {{#callable:method_getGenesisHash}} -->
Retrieves the genesis hash from the epoch bank.
- **Inputs**: None
- **Control Flow**:
    - The function begins by entering a special memory frame for stack allocation.
    - It attempts to read the epoch bank using the [`read_epoch_bank`](#read_epoch_bank) function.
    - If the epoch bank is NULL, it logs an error and returns 0.
    - It prepares a JSON response starting with the JSON-RPC version and result key.
    - The genesis hash is encoded in base58 format and appended to the response.
    - Finally, it completes the JSON response with the call ID and ends the memory frame.
- **Output**: Returns a JSON response containing the genesis hash or an error message if the epoch bank could not be read.
- **Functions called**:
    - [`read_epoch_bank`](#read_epoch_bank)
    - [`fd_method_error`](#fd_method_error)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)
    - [`fd_web_reply_encode_base58`](fd_webserver.c.driver.md#fd_web_reply_encode_base58)


---
### method\_getHealth<!-- {{#callable:method_getHealth}} -->
The `method_getHealth` function responds to health check requests by returning a JSON-RPC formatted message indicating the service is operational.
- **Inputs**: None
- **Control Flow**:
    - The function begins by ignoring the `values` parameter, which is not used.
    - It retrieves the web server context from the `ctx` parameter.
    - The function constructs a JSON response indicating the service is healthy with a result of 'ok'.
    - Finally, it sends the response back to the client and returns 0 to indicate success.
- **Output**: The function outputs a JSON string formatted as: {"jsonrpc":"2.0","result":"ok","id":<call_id>}, where <call_id> is the identifier from the context.
- **Functions called**:
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)


---
### method\_getHighestSnapshotSlot<!-- {{#callable:method_getHighestSnapshotSlot}} -->
The `method_getHighestSnapshotSlot` function logs a warning and returns an error indicating that the method is not implemented.
- **Inputs**: None
- **Control Flow**:
    - The function begins by ignoring its input parameters `values` and `ctx` using `(void)values; (void)ctx;`.
    - It logs a warning message stating that `getHighestSnapshotSlot` is not implemented.
    - It calls the [`fd_method_error`](#fd_method_error) function to report an error with code -1 and a message indicating that the method is not implemented.
    - Finally, it returns 0.
- **Output**: The function returns 0, indicating the completion of the function execution, but it also signals an error due to the method not being implemented.
- **Functions called**:
    - [`fd_method_error`](#fd_method_error)


---
### method\_getIdentity<!-- {{#callable:method_getIdentity}} -->
The `method_getIdentity` function retrieves the identity associated with a specific commitment level and formats it as a JSON response.
- **Inputs**:
    - `values`: A pointer to a `struct json_values` that contains the JSON-RPC parameters.
    - `ctx`: A pointer to a `fd_rpc_ctx_t` structure that holds the context for the RPC call.
- **Control Flow**:
    - The function begins by obtaining a pointer to the web server context from the RPC context.
    - It calls [`get_slot_from_commitment_level`](#get_slot_from_commitment_level) to determine the appropriate slot based on the commitment level specified in the input JSON.
    - Using the determined slot, it retrieves block information via [`fd_rpc_history_get_block_info`](fd_rpc_history.c.driver.md#fd_rpc_history_get_block_info).
    - The function then constructs a JSON response starting with the JSON-RPC version and result key.
    - It encodes the identity associated with the block's execution using [`fd_web_reply_encode_base58`](fd_webserver.c.driver.md#fd_web_reply_encode_base58).
    - Finally, it completes the JSON response and sends it back to the client.
- **Output**: The function outputs a JSON string containing the identity associated with the specified slot, formatted as a JSON-RPC response.
- **Functions called**:
    - [`get_slot_from_commitment_level`](#get_slot_from_commitment_level)
    - [`fd_rpc_history_get_block_info`](fd_rpc_history.c.driver.md#fd_rpc_history_get_block_info)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)
    - [`fd_web_reply_encode_base58`](fd_webserver.c.driver.md#fd_web_reply_encode_base58)


---
### method\_getInflationGovernor<!-- {{#callable:method_getInflationGovernor}} -->
The `method_getInflationGovernor` function logs a warning and returns an error indicating that the inflation governor retrieval is not implemented.
- **Inputs**: None
- **Control Flow**:
    - The function begins by ignoring its input parameters `values` and `ctx` using the `(void)` cast.
    - It logs a warning message indicating that the `getInflationGovernor` method is not implemented.
    - It calls the [`fd_method_error`](#fd_method_error) function to report an error with code -1 and a message stating that the method is not implemented.
    - Finally, it returns 0 to indicate the end of the function execution.
- **Output**: The function does not produce a meaningful output; it returns 0 after logging an error and signaling that the method is not implemented.
- **Functions called**:
    - [`fd_method_error`](#fd_method_error)


---
### method\_getInflationRate<!-- {{#callable:method_getInflationRate}} -->
The `method_getInflationRate` function logs a warning and returns an error indicating that the inflation rate retrieval is not implemented.
- **Inputs**: None
- **Control Flow**:
    - The function begins by ignoring its input parameters `values` and `ctx`.
    - It logs a warning message indicating that the `getInflationRate` method is not implemented.
    - It calls [`fd_method_error`](#fd_method_error) to report an error with a message stating that the method is not implemented.
    - Finally, it returns 0, indicating the end of the function execution.
- **Output**: The function does not produce a meaningful output; it returns 0 after logging an error and does not perform any calculations or data retrieval.
- **Functions called**:
    - [`fd_method_error`](#fd_method_error)


---
### method\_getInflationReward<!-- {{#callable:method_getInflationReward}} -->
The `method_getInflationReward` function logs a warning and returns an error indicating that the inflation reward feature is not implemented.
- **Inputs**: None
- **Control Flow**:
    - The function begins by ignoring its input parameters `values` and `ctx` using `(void)`.
    - It logs a warning message indicating that the `getInflationReward` method is not implemented.
    - It calls the [`fd_method_error`](#fd_method_error) function to report an error with code -1 and a message stating that the method is not implemented.
    - Finally, it returns 0.
- **Output**: The function returns 0, indicating the completion of the function execution, but it also signals an error due to the unimplemented feature.
- **Functions called**:
    - [`fd_method_error`](#fd_method_error)


---
### method\_getLargestAccounts<!-- {{#callable:method_getLargestAccounts}} -->
The `method_getLargestAccounts` function logs a warning and returns an error indicating that the functionality is not implemented.
- **Inputs**: None
- **Control Flow**:
    - The function begins by ignoring its input parameters `values` and `ctx` using `(void)values; (void)ctx;`.
    - It logs a warning message stating that 'getLargestAccounts is not implemented'.
    - It calls the [`fd_method_error`](#fd_method_error) function to report an error with code -1 and a message indicating that the method is not implemented.
    - Finally, it returns 0.
- **Output**: The function returns 0, indicating the end of execution, while also signaling an error through the logging mechanism.
- **Functions called**:
    - [`fd_method_error`](#fd_method_error)


---
### method\_getLatestBlockhash<!-- {{#callable:method_getLatestBlockhash}} -->
Retrieves the latest blockhash and its associated metadata.
- **Inputs**:
    - `values`: A pointer to a `struct json_values` that contains the JSON-RPC parameters.
    - `ctx`: A pointer to the `fd_rpc_ctx_t` context structure that holds the global state.
- **Control Flow**:
    - The function begins by ignoring the `values` parameter.
    - It retrieves the web server context from the `ctx` structure.
    - It calls [`get_slot_from_commitment_level`](#get_slot_from_commitment_level) to determine the appropriate slot based on the commitment level specified in the input.
    - It fetches block information for the determined slot using [`fd_rpc_history_get_block_info`](fd_rpc_history.c.driver.md#fd_rpc_history_get_block_info).
    - The function constructs a JSON response containing the blockhash and the last valid block height.
    - It encodes the blockhash in base58 format and appends it to the response.
    - Finally, it sends the complete JSON response back to the web server.
- **Output**: Returns a JSON-RPC formatted response containing the latest blockhash and its associated metadata, including the slot and last valid block height.
- **Functions called**:
    - [`get_slot_from_commitment_level`](#get_slot_from_commitment_level)
    - [`fd_rpc_history_get_block_info`](fd_rpc_history.c.driver.md#fd_rpc_history_get_block_info)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)
    - [`fd_web_reply_encode_base58`](fd_webserver.c.driver.md#fd_web_reply_encode_base58)


---
### leader\_rb\_compare<!-- {{#callable:leader_rb_compare}} -->
Compares two `leader_rb_node_t` structures based on their public keys.
- **Inputs**:
    - `left`: A pointer to the first `leader_rb_node_t` structure to compare.
    - `right`: A pointer to the second `leader_rb_node_t` structure to compare.
- **Control Flow**:
    - Iterates over each `ulong` element of the `key` field in both `leader_rb_node_t` structures.
    - For each element, compares the corresponding `ulong` values from both nodes after applying byte-swapping.
    - If a difference is found, returns -1 if the first node's value is less than the second's, or 1 if it is greater.
    - If all elements are equal, returns 0 indicating the nodes are equivalent.
- **Output**: Returns a long integer indicating the comparison result: -1 if the first node is less than the second, 1 if greater, and 0 if they are equal.


---
### method\_getLeaderSchedule<!-- {{#callable:method_getLeaderSchedule}} -->
Retrieves the leader schedule for a given slot in the epoch.
- **Inputs**: None
- **Control Flow**:
    - The function begins by allocating a frame in the SPAD memory.
    - It retrieves the current slot based on the commitment level from the input values.
    - The epoch bank is read to obtain the epoch schedule; if it fails, an error is returned.
    - The epoch corresponding to the current slot is determined, and the leader schedule for that epoch is accessed.
    - A red-black tree is initialized to organize the leaders based on their public keys.
    - The function iterates through the scheduled leaders, populating the red-black tree and maintaining an index of the next scheduled slots.
    - The results are formatted into a JSON response, which includes the leader public keys and their corresponding slot indices.
    - Finally, the JSON response is sent back to the web server.
- **Output**: The function outputs a JSON object containing the leader schedule, mapping each leader's public key to their respective scheduled slots.
- **Functions called**:
    - [`get_slot_from_commitment_level`](#get_slot_from_commitment_level)
    - [`read_epoch_bank`](#read_epoch_bank)
    - [`fd_method_error`](#fd_method_error)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)


---
### method\_getMaxRetransmitSlot<!-- {{#callable:method_getMaxRetransmitSlot}} -->
The `method_getMaxRetransmitSlot` function logs a warning and returns an error indicating that the method is not implemented.
- **Inputs**: None
- **Control Flow**:
    - The function begins by ignoring its input parameters `values` and `ctx` using the `(void)` cast.
    - It logs a warning message indicating that the `getMaxRetransmitSlot` method is not implemented.
    - It calls the [`fd_method_error`](#fd_method_error) function to report an error with code -1 and a message stating that the method is not implemented.
    - Finally, it returns 0.
- **Output**: The function returns 0, indicating the completion of the function execution, but it also signals an error due to the method not being implemented.
- **Functions called**:
    - [`fd_method_error`](#fd_method_error)


---
### method\_getMaxShredInsertSlot<!-- {{#callable:method_getMaxShredInsertSlot}} -->
The `method_getMaxShredInsertSlot` function retrieves the maximum shred insert slot from the blockstore and returns it in a JSON-RPC response.
- **Inputs**: None
- **Control Flow**:
    - The function begins by ignoring the `values` parameter, which is not used.
    - It retrieves the `blockstore` from the global context stored in `ctx`.
    - It also retrieves the web server context from `ctx`.
    - The function formats a JSON response containing the maximum shred insert slot (`wmk`) from the blockstore's shared memory and the call ID from the context.
    - Finally, it returns 0 to indicate successful execution.
- **Output**: The function outputs a JSON-RPC formatted string containing the maximum shred insert slot and the call ID.
- **Functions called**:
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)


---
### method\_getMinimumBalanceForRentExemption<!-- {{#callable:method_getMinimumBalanceForRentExemption}} -->
This function calculates the minimum balance required for rent exemption based on the size of the account.
- **Inputs**:
    - `values`: A pointer to a `json_values` structure containing the parameters for the method, specifically the size of the account.
    - `ctx`: A pointer to a `fd_rpc_ctx_t` structure that holds the context for the RPC call.
- **Control Flow**:
    - The function begins by defining a static array `PATH_SIZE` that specifies the JSON path to retrieve the size parameter from the input.
    - It retrieves the size value from the `values` structure using the [`json_get_value`](fd_methods.c.driver.md#json_get_value) function.
    - If the size is not provided, it defaults to 0.
    - The function then attempts to read the epoch bank using the [`read_epoch_bank`](#read_epoch_bank) function.
    - If reading the epoch bank fails, it returns an error message.
    - Next, it calculates the minimum balance for rent exemption using the `fd_rent_exempt_minimum_balance` function, passing the rent information and the size.
    - Finally, it formats the result into a JSON response and sends it back to the client.
- **Output**: The function outputs a JSON response containing the minimum balance required for rent exemption, formatted as a JSON-RPC response.
- **Functions called**:
    - [`json_get_value`](fd_methods.c.driver.md#json_get_value)
    - [`read_epoch_bank`](#read_epoch_bank)
    - [`fd_method_error`](#fd_method_error)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)


---
### method\_getMultipleAccounts<!-- {{#callable:method_getMultipleAccounts}} -->
The `method_getMultipleAccounts` function retrieves multiple account information based on provided account IDs and specified encoding.
- **Inputs**:
    - `values`: A pointer to a `struct json_values` containing the JSON-RPC request parameters, including an array of account IDs and encoding options.
    - `ctx`: A pointer to a `fd_rpc_ctx_t` structure that holds the context for the RPC call, including the web server context.
- **Control Flow**:
    - The function begins by defining a static path to extract the encoding type from the input JSON values.
    - It retrieves the encoding type and checks for valid options (base58, base64, base64+zstd, jsonParsed), returning an error for invalid types.
    - The function initializes a JSON response with the current API version and latest slot number.
    - It enters a loop to iterate over the account IDs provided in the input, constructing a path to retrieve each account ID.
    - For each account ID, it attempts to decode the base58 representation into a public key and retrieves the corresponding account data.
    - If the account data is found, it converts the account information to JSON format based on the specified encoding and appends it to the response.
    - If an account ID is not found, it appends 'null' to the response for that account.
    - Finally, it closes the JSON response and sends it back to the client.
- **Output**: The function outputs a JSON-RPC response containing the context with the API version and latest slot, along with an array of account information or null values for each account ID requested.
- **Functions called**:
    - [`json_get_value`](fd_methods.c.driver.md#json_get_value)
    - [`fd_method_error`](#fd_method_error)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)
    - [`fd_rpc_history_latest_slot`](fd_rpc_history.c.driver.md#fd_rpc_history_latest_slot)
    - [`fd_web_reply_append`](fd_webserver.c.driver.md#fd_web_reply_append)
    - [`read_account`](#read_account)
    - [`fd_account_to_json`](fd_block_to_json.c.driver.md#fd_account_to_json)


---
### method\_getProgramAccounts<!-- {{#callable:method_getProgramAccounts}} -->
The `method_getProgramAccounts` function logs a warning and returns an error indicating that the method is not implemented.
- **Inputs**: None
- **Control Flow**:
    - The function begins by ignoring its input parameters `values` and `ctx`.
    - It logs a warning message stating that the `getProgramAccounts` method is not implemented.
    - It calls the [`fd_method_error`](#fd_method_error) function to report an error with a message indicating that the method is not implemented.
    - Finally, it returns 0, indicating the end of the function execution.
- **Output**: The function does not produce a meaningful output; it returns 0 after logging an error and calling the error handling function.
- **Functions called**:
    - [`fd_method_error`](#fd_method_error)


---
### method\_getRecentPerformanceSamples<!-- {{#callable:method_getRecentPerformanceSamples}} -->
Retrieves recent performance samples based on a specified limit.
- **Inputs**:
    - `values`: A pointer to a `json_values` structure containing the parameters for the method.
    - `ctx`: A pointer to a `fd_rpc_ctx_t` structure representing the RPC context.
- **Control Flow**:
    - The function begins by defining a static array `PATH_LIMIT` to specify the expected JSON path for the input parameter.
    - It retrieves the limit value from the `values` structure using the [`json_get_value`](fd_methods.c.driver.md#json_get_value) function.
    - If the limit is not provided, it calls [`fd_method_error`](#fd_method_error) to return an error message and exits.
    - The function calculates the number of performance samples to return, which is the minimum of the available samples and the specified limit.
    - It constructs a JSON response starting with the result array.
    - A loop iterates over the number of samples to be returned, retrieving each performance sample and formatting it into JSON.
    - If there are more samples to process, it appends a comma to separate the JSON objects.
    - Finally, it closes the JSON array and returns the response.
- **Output**: The function outputs a JSON formatted string containing an array of recent performance samples, each with details such as number of slots, transactions, non-vote transactions, sample period, and the highest slot.
- **Functions called**:
    - [`json_get_value`](fd_methods.c.driver.md#json_get_value)
    - [`fd_method_error`](#fd_method_error)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)


---
### method\_getRecentPrioritizationFees<!-- {{#callable:method_getRecentPrioritizationFees}} -->
The `method_getRecentPrioritizationFees` function logs a warning and returns an error indicating that the method is not implemented.
- **Inputs**: None
- **Control Flow**:
    - The function begins by ignoring its input parameters `values` and `ctx`.
    - It logs a warning message indicating that the method is not implemented.
    - It calls the [`fd_method_error`](#fd_method_error) function to report an error with a message stating that the method is not implemented.
    - Finally, it returns 0.
- **Output**: The function does not produce a meaningful output; it returns 0 after logging an error and indicating that the method is not implemented.
- **Functions called**:
    - [`fd_method_error`](#fd_method_error)


---
### method\_getSignaturesForAddress<!-- {{#callable:method_getSignaturesForAddress}} -->
Retrieves transaction signatures for a specified account address.
- **Inputs**:
    - `values`: A pointer to a `json_values` structure containing the JSON-RPC request parameters.
    - `ctx`: A pointer to a `fd_rpc_ctx_t` structure representing the RPC context.
- **Control Flow**:
    - The function begins by defining a static path to extract the account address from the JSON parameters.
    - It retrieves the account address and checks if it is a valid base58 encoded string.
    - If the account address is invalid, an error is returned to the client.
    - Next, it defines another static path to extract the limit parameter from the JSON request.
    - The limit is set to a default of 1000 if not provided or if it exceeds 1000.
    - The function then prepares to send a JSON-RPC response with the result array.
    - It iterates through the transaction history for the specified account, up to the limit, retrieving transaction details.
    - For each transaction, it formats the transaction details into JSON and appends it to the response.
    - Finally, it sends the complete JSON response back to the client.
- **Output**: Returns a JSON-RPC response containing an array of transaction signatures and their associated details for the specified account.
- **Functions called**:
    - [`json_get_value`](fd_methods.c.driver.md#json_get_value)
    - [`fd_method_error`](#fd_method_error)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)
    - [`fd_rpc_history_first_txn_for_acct`](fd_rpc_history.c.driver.md#fd_rpc_history_first_txn_for_acct)
    - [`fd_rpc_history_get_block_info`](fd_rpc_history.c.driver.md#fd_rpc_history_get_block_info)
    - [`fd_rpc_history_next_txn_for_acct`](fd_rpc_history.c.driver.md#fd_rpc_history_next_txn_for_acct)


---
### method\_getSignatureStatuses<!-- {{#callable:method_getSignatureStatuses}} -->
Retrieves the statuses of multiple transaction signatures.
- **Inputs**:
    - `values`: A pointer to a `json_values` structure containing the JSON-RPC parameters.
    - `ctx`: A pointer to a `fd_rpc_ctx_t` structure that holds the context for the RPC call.
- **Control Flow**:
    - Starts by sending a JSON-RPC response header with the current API version and latest slot number.
    - Enters a loop to iterate over the provided signature IDs until no more signatures are found.
    - For each signature, it attempts to decode it from base58 format into a transaction key.
    - If decoding fails, it appends a null status to the response and continues to the next signature.
    - Retrieves the transaction data associated with the decoded key and checks if it exists.
    - If the transaction data is found, it formats the response with the slot number and a processed status.
    - If the transaction data is not found, it appends a null status to the response.
    - Finally, it closes the JSON response and returns.
- **Output**: Returns a JSON object containing the context with the latest slot and an array of transaction statuses for each signature, including slot number and confirmation status.
- **Functions called**:
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)
    - [`fd_rpc_history_latest_slot`](fd_rpc_history.c.driver.md#fd_rpc_history_latest_slot)
    - [`json_get_value`](fd_methods.c.driver.md#json_get_value)
    - [`fd_web_reply_append`](fd_webserver.c.driver.md#fd_web_reply_append)
    - [`fd_rpc_history_get_txn`](fd_rpc_history.c.driver.md#fd_rpc_history_get_txn)


---
### method\_getSlot<!-- {{#callable:method_getSlot}} -->
The `method_getSlot` function retrieves the current slot number based on the commitment level specified in the input.
- **Inputs**:
    - `values`: A pointer to a `struct json_values` that contains the JSON-RPC request parameters.
    - `ctx`: A pointer to a `fd_rpc_ctx_t` structure that holds the context for the RPC call, including the call ID and global context.
- **Control Flow**:
    - The function first retrieves the web server context from the `ctx` structure.
    - It then calls the [`get_slot_from_commitment_level`](#get_slot_from_commitment_level) function, passing the `values` and `ctx` to determine the current slot based on the commitment level.
    - Finally, it formats a JSON response containing the slot number and the call ID, and sends it back to the web server.
- **Output**: The function returns an integer value of 0, indicating successful execution, and sends a JSON response containing the current slot number and the request ID.
- **Functions called**:
    - [`get_slot_from_commitment_level`](#get_slot_from_commitment_level)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)


---
### method\_getSlotLeader<!-- {{#callable:method_getSlotLeader}} -->
Retrieves the slot leader for a given slot.
- **Inputs**:
    - `values`: A pointer to a `json_values` structure containing the JSON-RPC parameters.
    - `ctx`: A pointer to the `fd_rpc_ctx_t` structure containing the context for the RPC call.
- **Control Flow**:
    - The function starts by obtaining a pointer to the web server context from the `ctx` parameter.
    - It sends the initial part of the JSON-RPC response indicating the version.
    - The function retrieves the current slot based on the commitment level specified in the `values` parameter.
    - It then fetches the leader schedule for the retrieved slot using `fd_stake_ci_get_lsched_for_slot`.
    - The slot leader is obtained from the leader schedule using `fd_epoch_leaders_get`.
    - If a slot leader is found, it is encoded in base58 and included in the response; otherwise, 'null' is emitted.
    - Finally, the function appends the call ID to the response and returns.
- **Output**: Returns a JSON-RPC response containing the slot leader's public key in base58 format or 'null' if no leader is found.
- **Functions called**:
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)
    - [`get_slot_from_commitment_level`](#get_slot_from_commitment_level)


---
### method\_getSlotLeaders<!-- {{#callable:method_getSlotLeaders}} -->
Retrieves the slot leaders for a specified range of slots.
- **Inputs**:
    - `values`: A pointer to a `json_values` structure containing the parameters for the method.
    - `ctx`: A pointer to a `fd_rpc_ctx_t` structure that holds the context for the RPC call.
- **Control Flow**:
    - Defines a static path to extract the start slot from the input JSON.
    - Retrieves the start slot number from the input JSON; if not found, returns an error.
    - Defines a static path to extract the limit from the input JSON.
    - Retrieves the limit from the input JSON; if not found, returns an error.
    - Limits the maximum number of slots to 5000 if the provided limit exceeds this value.
    - Begins constructing a JSON response with the result array.
    - Fetches the leader schedule for the specified start slot.
    - Iterates from the start slot to the start slot plus the limit, retrieving the slot leader for each slot.
    - If a slot leader is found, encodes it in base58 and appends it to the response; otherwise, appends 'null'.
    - Finalizes the JSON response and sends it back to the client.
- **Output**: Returns a JSON object containing an array of slot leaders for the specified range of slots.
- **Functions called**:
    - [`json_get_value`](fd_methods.c.driver.md#json_get_value)
    - [`fd_method_error`](#fd_method_error)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)


---
### method\_getStakeActivation<!-- {{#callable:method_getStakeActivation}} -->
The `method_getStakeActivation` function logs a warning and returns an error indicating that the functionality is not implemented.
- **Inputs**: None
- **Control Flow**:
    - The function begins by ignoring its input parameters `values` and `ctx`.
    - It logs a warning message indicating that the `getStakeActivation` method is not implemented.
    - It calls the [`fd_method_error`](#fd_method_error) function to report an error with a specific error code and message.
    - Finally, it returns 0, indicating the end of the function execution.
- **Output**: The function does not produce a meaningful output; it returns 0 and logs an error message.
- **Functions called**:
    - [`fd_method_error`](#fd_method_error)


---
### method\_getStakeMinimumDelegation<!-- {{#callable:method_getStakeMinimumDelegation}} -->
The `method_getStakeMinimumDelegation` function logs a warning and returns an error indicating that the functionality is not implemented.
- **Inputs**: None
- **Control Flow**:
    - The function begins by ignoring its input parameters `values` and `ctx` using `(void)`.
    - It logs a warning message indicating that the `getStakeMinimumDelegation` method is not implemented.
    - It calls the [`fd_method_error`](#fd_method_error) function to report an error with code -1 and a message stating that the method is not implemented.
    - Finally, it returns 0.
- **Output**: The function returns 0, indicating the end of execution, while also signaling an error through the logging and error reporting mechanism.
- **Functions called**:
    - [`fd_method_error`](#fd_method_error)


---
### method\_getSupply<!-- {{#callable:method_getSupply}} -->
The `method_getSupply` function retrieves the supply information of a specific slot bank.
- **Inputs**:
    - `values`: A pointer to a `struct json_values` containing the JSON-RPC parameters.
    - `ctx`: A pointer to a `fd_rpc_ctx_t` structure that holds the context for the RPC call.
- **Control Flow**:
    - The function begins by entering a SPAD frame context using `FD_SPAD_FRAME_BEGIN`.
    - It retrieves the slot number from the commitment level specified in the `values` parameter using the [`get_slot_from_commitment_level`](#get_slot_from_commitment_level) function.
    - The function then attempts to read the slot bank corresponding to the retrieved slot using [`read_slot_bank`](#read_slot_bank).
    - If the slot bank is not found, it logs an error and returns 0.
    - If the slot bank is found, it prepares a JSON response containing the supply information, including circulating and total supply, and sends it back using [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf).
    - Finally, the function ends the SPAD frame context with `FD_SPAD_FRAME_END` and returns 0.
- **Output**: The function outputs a JSON-RPC formatted response containing the supply information of the specified slot bank, including circulating supply, non-circulating supply, and total supply.
- **Functions called**:
    - [`get_slot_from_commitment_level`](#get_slot_from_commitment_level)
    - [`read_slot_bank`](#read_slot_bank)
    - [`fd_method_error`](#fd_method_error)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)


---
### method\_getTokenAccountBalance<!-- {{#callable:method_getTokenAccountBalance}} -->
The `method_getTokenAccountBalance` function logs a warning and returns an error indicating that the functionality is not implemented.
- **Inputs**: None
- **Control Flow**:
    - The function begins by ignoring its input parameters using (void) to suppress unused variable warnings.
    - It logs a warning message indicating that the `getTokenAccountBalance` method is not implemented.
    - It calls the [`fd_method_error`](#fd_method_error) function to report an error with a specific error code and message.
    - Finally, it returns 0, indicating the end of the function execution.
- **Output**: The function does not produce a meaningful output; it returns 0 after logging an error and indicating that the method is not implemented.
- **Functions called**:
    - [`fd_method_error`](#fd_method_error)


---
### method\_getTokenAccountsByDelegate<!-- {{#callable:method_getTokenAccountsByDelegate}} -->
The `method_getTokenAccountsByDelegate` function logs a warning and returns an error indicating that the method is not implemented.
- **Inputs**: None
- **Control Flow**:
    - The function begins by ignoring its input parameters `values` and `ctx`.
    - It logs a warning message stating that the method is not implemented.
    - It calls [`fd_method_error`](#fd_method_error) to report an error with a message indicating the method is not implemented.
    - Finally, it returns 0.
- **Output**: The function returns 0, indicating the completion of the function execution without performing any operations related to getting token accounts by delegate.
- **Functions called**:
    - [`fd_method_error`](#fd_method_error)


---
### method\_getTokenAccountsByOwner<!-- {{#callable:method_getTokenAccountsByOwner}} -->
The `method_getTokenAccountsByOwner` function logs a warning and returns an error indicating that the method is not implemented.
- **Inputs**: None
- **Control Flow**:
    - The function begins by ignoring its input parameters `values` and `ctx`.
    - It logs a warning message stating that the method is not implemented.
    - It calls the [`fd_method_error`](#fd_method_error) function to report an error with a specific message.
    - Finally, it returns 0 to indicate the end of the function execution.
- **Output**: The function does not produce a meaningful output; it returns 0 after logging an error and warning about the unimplemented method.
- **Functions called**:
    - [`fd_method_error`](#fd_method_error)


---
### method\_getTokenLargestAccounts<!-- {{#callable:method_getTokenLargestAccounts}} -->
The `method_getTokenLargestAccounts` function logs a warning and returns an error indicating that the functionality is not implemented.
- **Inputs**: None
- **Control Flow**:
    - The function begins by ignoring its input parameters `values` and `ctx`.
    - It logs a warning message stating that the `getTokenLargestAccounts` method is not implemented.
    - It calls the [`fd_method_error`](#fd_method_error) function to report an error with a message indicating that the method is not implemented.
    - Finally, it returns 0 to indicate the end of the function execution.
- **Output**: The function does not produce a meaningful output; it returns 0 after logging an error and warning.
- **Functions called**:
    - [`fd_method_error`](#fd_method_error)


---
### method\_getTokenSupply<!-- {{#callable:method_getTokenSupply}} -->
The `method_getTokenSupply` function logs a warning and returns an error indicating that the token supply retrieval is not implemented.
- **Inputs**: None
- **Control Flow**:
    - The function begins by ignoring its input parameters `values` and `ctx` using `(void)values; (void)ctx;`.
    - It logs a warning message stating that 'getTokenSupply is not implemented'.
    - It calls the [`fd_method_error`](#fd_method_error) function to report an error with code -1 and a message indicating that the method is not implemented.
    - Finally, it returns 0.
- **Output**: The function does not produce a meaningful output; it always returns 0 after logging an error and indicating that the method is not implemented.
- **Functions called**:
    - [`fd_method_error`](#fd_method_error)


---
### method\_getTransaction<!-- {{#callable:method_getTransaction}} -->
The `method_getTransaction` function retrieves transaction details based on a provided transaction signature and encoding type.
- **Inputs**:
    - `values`: A pointer to a `json_values` structure containing the parameters for the transaction request.
    - `ctx`: A pointer to an `fd_rpc_ctx_t` structure that holds the context for the RPC call.
- **Control Flow**:
    - The function defines static paths for extracting parameters from the JSON input.
    - It retrieves the transaction signature from the input and checks for its presence, returning an error if not found.
    - It retrieves the encoding type, defaulting to JSON if not specified, and checks for valid encoding types.
    - It checks for a commitment level, defaulting to 'processed' if not specified, and validates it.
    - The function decodes the transaction signature from base58 format into a key structure.
    - It retrieves the raw transaction data from the history using the decoded key.
    - If the transaction data is found, it parses the transaction and prepares the response with transaction details.
    - Finally, it formats the response in JSON and sends it back to the client.
- **Output**: The function outputs a JSON response containing the transaction details, including the block time and slot, or an error message if any validation fails.
- **Functions called**:
    - [`json_get_value`](fd_methods.c.driver.md#json_get_value)
    - [`fd_method_error`](#fd_method_error)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)
    - [`fd_rpc_history_get_txn`](fd_rpc_history.c.driver.md#fd_rpc_history_get_txn)
    - [`fd_rpc_history_get_block_info`](fd_rpc_history.c.driver.md#fd_rpc_history_get_block_info)
    - [`fd_rpc_history_latest_slot`](fd_rpc_history.c.driver.md#fd_rpc_history_latest_slot)
    - [`fd_txn_to_json`](fd_block_to_json.c.driver.md#fd_txn_to_json)


---
### method\_getTransactionCount<!-- {{#callable:method_getTransactionCount}} -->
Retrieves the transaction count for a specific slot.
- **Inputs**:
    - `values`: A pointer to a `json_values` structure containing the JSON-RPC parameters.
    - `ctx`: A pointer to the `fd_rpc_ctx_t` structure containing the context for the RPC call.
- **Control Flow**:
    - Begins a SPAD frame to allocate memory for the operation.
    - Retrieves the slot number based on the commitment level from the `values` parameter.
    - Fetches block information for the retrieved slot using [`fd_rpc_history_get_block_info`](fd_rpc_history.c.driver.md#fd_rpc_history_get_block_info).
    - If the block information is not found, an error is reported using [`fd_method_error`](#fd_method_error).
    - If the block information is found, the transaction count is formatted into a JSON response and sent back to the client.
- **Output**: Returns a JSON-RPC formatted response containing the transaction count for the specified slot.
- **Functions called**:
    - [`get_slot_from_commitment_level`](#get_slot_from_commitment_level)
    - [`fd_rpc_history_get_block_info`](fd_rpc_history.c.driver.md#fd_rpc_history_get_block_info)
    - [`fd_method_error`](#fd_method_error)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)


---
### method\_getVersion<!-- {{#callable:method_getVersion}} -->
The `method_getVersion` function retrieves the version information of the service.
- **Inputs**: None
- **Control Flow**:
    - The function begins by ignoring the `values` parameter.
    - It retrieves the web server context from the `ctx` parameter.
    - The function constructs a JSON response string containing the feature set and the version of the service.
    - Finally, it sends the constructed JSON response back to the client.
- **Output**: The function outputs a JSON formatted string containing the service version and feature set, and returns 0 to indicate success.
- **Functions called**:
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)


---
### method\_getVoteAccounts<!-- {{#callable:method_getVoteAccounts}} -->
The `method_getVoteAccounts` function retrieves and formats the current vote accounts and their associated data for a given slot.
- **Inputs**:
    - `values`: A pointer to a `struct json_values` containing the JSON-RPC parameters.
    - `ctx`: A pointer to the `fd_rpc_ctx_t` context structure containing global state and web server information.
- **Control Flow**:
    - Begins a SPAD frame for memory allocation and context management.
    - Initializes a web server response with a JSON-RPC format.
    - Retrieves the slot number from the commitment level specified in the input parameters.
    - Attempts to read the slot bank for the specified slot; if not found, an error is returned.
    - Iterates through the vote accounts in the slot bank, retrieving timestamps and other relevant data.
    - Formats the retrieved data into a JSON response, including vote public keys, last vote timestamps, and activated stakes.
    - Ends the SPAD frame and returns the response.
- **Output**: Returns a JSON object containing the current vote accounts, their last vote timestamps, and associated stakes, formatted for JSON-RPC response.
- **Functions called**:
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)
    - [`json_get_value`](fd_methods.c.driver.md#json_get_value)
    - [`get_slot_from_commitment_level`](#get_slot_from_commitment_level)
    - [`read_slot_bank`](#read_slot_bank)
    - [`fd_method_error`](#fd_method_error)


---
### method\_isBlockhashValid<!-- {{#callable:method_isBlockhashValid}} -->
Validates if a given blockhash is valid.
- **Inputs**:
    - `values`: A pointer to a `struct json_values` containing the JSON-RPC parameters.
    - `ctx`: A pointer to the `fd_rpc_ctx_t` context structure containing the RPC context.
- **Control Flow**:
    - The function begins by defining a static path to extract the first parameter from the JSON input.
    - It retrieves the blockhash string from the input JSON using [`json_get_value`](fd_methods.c.driver.md#json_get_value).
    - If the blockhash is not provided, it returns an error indicating that a string is required.
    - The blockhash string is then decoded from base58 format into a `fd_hash_t` structure.
    - If the decoding fails, an error is returned indicating invalid base58 encoding.
    - The function retrieves block information associated with the decoded blockhash using [`fd_rpc_history_get_block_info_by_hash`](fd_rpc_history.c.driver.md#fd_rpc_history_get_block_info_by_hash).
    - Finally, it constructs a JSON response indicating whether the blockhash is valid and sends it back to the client.
- **Output**: The function outputs a JSON-RPC response indicating the validity of the blockhash, including the current slot number and a boolean value representing the validity status.
- **Functions called**:
    - [`json_get_value`](fd_methods.c.driver.md#json_get_value)
    - [`fd_method_error`](#fd_method_error)
    - [`fd_rpc_history_get_block_info_by_hash`](fd_rpc_history.c.driver.md#fd_rpc_history_get_block_info_by_hash)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)
    - [`fd_rpc_history_latest_slot`](fd_rpc_history.c.driver.md#fd_rpc_history_latest_slot)


---
### method\_minimumLedgerSlot<!-- {{#callable:method_minimumLedgerSlot}} -->
This function sends a JSON-RPC response containing the minimum ledger slot.
- **Inputs**: None
- **Control Flow**:
    - The function begins by ignoring the `values` parameter.
    - It retrieves the global context from the `ctx` parameter.
    - It accesses the web server instance from the global context.
    - The function formats a JSON response string with the minimum ledger slot value and the call ID.
    - Finally, it returns 0 to indicate successful execution.
- **Output**: The function outputs a JSON string containing the minimum ledger slot and the request ID.
- **Functions called**:
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)


---
### method\_requestAirdrop<!-- {{#callable:method_requestAirdrop}} -->
The `method_requestAirdrop` function logs a warning and returns an error indicating that the airdrop request feature is not implemented.
- **Inputs**: None
- **Control Flow**:
    - The function begins by ignoring its input parameters using `(void)values;` and `(void)ctx;`.
    - It logs a warning message indicating that the `requestAirdrop` method is not implemented.
    - It calls the [`fd_method_error`](#fd_method_error) function to send an error response to the client with an error code of -1 and a message stating that the method is not implemented.
    - Finally, it returns 0 to indicate the end of the function execution.
- **Output**: The function does not produce a meaningful output; it returns 0 after logging an error and sending an error response.
- **Functions called**:
    - [`fd_method_error`](#fd_method_error)


---
### method\_sendTransaction<!-- {{#callable:method_sendTransaction}} -->
The `method_sendTransaction` function processes a transaction by decoding it from a specified encoding format and sending it to a transaction processing unit.
- **Inputs**:
    - `values`: A pointer to a `struct json_values` containing the JSON-RPC parameters, including the transaction data and encoding type.
    - `ctx`: A pointer to a `fd_rpc_ctx_t` structure that holds the context for the RPC call, including the web server context and global state.
- **Control Flow**:
    - Extracts the encoding type from the JSON parameters and determines if it is base58 or base64.
    - Retrieves the transaction data from the JSON parameters and decodes it based on the specified encoding.
    - Parses the decoded transaction data to ensure it is valid.
    - Sends the transaction data to the transaction processing unit (TPU) via a socket.
    - Logs the transaction size and prepares a response with the transaction signature encoded in base58.
- **Output**: The function returns a JSON-RPC response containing the transaction signature if successful, or an error message if any step fails.
- **Functions called**:
    - [`json_get_value`](fd_methods.c.driver.md#json_get_value)
    - [`fd_method_error`](#fd_method_error)
    - [`b58tobin`](base_enc.c.driver.md#b58tobin)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)


---
### method\_simulateTransaction<!-- {{#callable:method_simulateTransaction}} -->
The `method_simulateTransaction` function logs a warning and returns an error indicating that the transaction simulation feature is not implemented.
- **Inputs**: None
- **Control Flow**:
    - The function begins by ignoring its input parameters using `(void)values;` and `(void)ctx;`.
    - It logs a warning message stating that the `simulateTransaction` method is not implemented.
    - It calls the [`fd_method_error`](#fd_method_error) function to report an error with a specific error code and message.
    - Finally, it returns 0, indicating the end of the function execution.
- **Output**: The function does not produce a meaningful output but returns 0 after logging an error and indicating that the feature is not implemented.
- **Functions called**:
    - [`fd_method_error`](#fd_method_error)


---
### fd\_webserver\_method\_generic<!-- {{#callable:fd_webserver_method_generic}} -->
Processes generic web server method requests for a JSON-RPC API.
- **Inputs**:
    - `values`: A pointer to a `json_values` structure containing the parsed JSON-RPC request.
    - `cb_arg`: A pointer to a context structure (`fd_rpc_ctx_t`) that holds the RPC context.
- **Control Flow**:
    - Extracts the `jsonrpc` version from the input JSON and checks if it is '2.0'.
    - Retrieves the `id` from the JSON, which can be either an integer or a string.
    - Fetches the `method` from the JSON to determine which RPC method to invoke.
    - Based on the method ID, it calls the corresponding handler function for the specific RPC method.
    - If the method is not recognized, it returns an error indicating the method is unknown or unimplemented.
- **Output**: The function does not return a value directly; instead, it sends responses back through the web server context based on the method invoked.
- **Functions called**:
    - [`json_get_value`](fd_methods.c.driver.md#json_get_value)
    - [`fd_method_error`](#fd_method_error)
    - [`fd_webserver_json_keyword`](keywords.c.driver.md#fd_webserver_json_keyword)
    - [`method_getAccountInfo`](#method_getAccountInfo)
    - [`method_getBalance`](#method_getBalance)
    - [`method_getBlock`](#method_getBlock)
    - [`method_getBlockCommitment`](#method_getBlockCommitment)
    - [`method_getBlockHeight`](#method_getBlockHeight)
    - [`method_getBlockProduction`](#method_getBlockProduction)
    - [`method_getBlocks`](#method_getBlocks)
    - [`method_getBlocksWithLimit`](#method_getBlocksWithLimit)
    - [`method_getBlockTime`](#method_getBlockTime)
    - [`method_getClusterNodes`](#method_getClusterNodes)
    - [`method_getEpochInfo`](#method_getEpochInfo)
    - [`method_getEpochSchedule`](#method_getEpochSchedule)
    - [`method_getFeeForMessage`](#method_getFeeForMessage)
    - [`method_getFirstAvailableBlock`](#method_getFirstAvailableBlock)
    - [`method_getGenesisHash`](#method_getGenesisHash)
    - [`method_getHealth`](#method_getHealth)
    - [`method_getHighestSnapshotSlot`](#method_getHighestSnapshotSlot)
    - [`method_getIdentity`](#method_getIdentity)
    - [`method_getInflationGovernor`](#method_getInflationGovernor)
    - [`method_getInflationRate`](#method_getInflationRate)
    - [`method_getInflationReward`](#method_getInflationReward)
    - [`method_getLargestAccounts`](#method_getLargestAccounts)
    - [`method_getLatestBlockhash`](#method_getLatestBlockhash)
    - [`method_getLeaderSchedule`](#method_getLeaderSchedule)
    - [`method_getMaxRetransmitSlot`](#method_getMaxRetransmitSlot)
    - [`method_getMaxShredInsertSlot`](#method_getMaxShredInsertSlot)
    - [`method_getMinimumBalanceForRentExemption`](#method_getMinimumBalanceForRentExemption)
    - [`method_getMultipleAccounts`](#method_getMultipleAccounts)
    - [`method_getProgramAccounts`](#method_getProgramAccounts)
    - [`method_getRecentPerformanceSamples`](#method_getRecentPerformanceSamples)
    - [`method_getRecentPrioritizationFees`](#method_getRecentPrioritizationFees)
    - [`method_getSignaturesForAddress`](#method_getSignaturesForAddress)
    - [`method_getSignatureStatuses`](#method_getSignatureStatuses)
    - [`method_getSlot`](#method_getSlot)
    - [`method_getSlotLeader`](#method_getSlotLeader)
    - [`method_getSlotLeaders`](#method_getSlotLeaders)
    - [`method_getStakeActivation`](#method_getStakeActivation)
    - [`method_getStakeMinimumDelegation`](#method_getStakeMinimumDelegation)
    - [`method_getSupply`](#method_getSupply)
    - [`method_getTokenAccountBalance`](#method_getTokenAccountBalance)
    - [`method_getTokenAccountsByDelegate`](#method_getTokenAccountsByDelegate)
    - [`method_getTokenAccountsByOwner`](#method_getTokenAccountsByOwner)
    - [`method_getTokenLargestAccounts`](#method_getTokenLargestAccounts)
    - [`method_getTokenSupply`](#method_getTokenSupply)
    - [`method_getTransaction`](#method_getTransaction)
    - [`method_getTransactionCount`](#method_getTransactionCount)
    - [`method_getVersion`](#method_getVersion)
    - [`method_getVoteAccounts`](#method_getVoteAccounts)
    - [`method_isBlockhashValid`](#method_isBlockhashValid)
    - [`method_minimumLedgerSlot`](#method_minimumLedgerSlot)
    - [`method_requestAirdrop`](#method_requestAirdrop)
    - [`method_sendTransaction`](#method_sendTransaction)
    - [`method_simulateTransaction`](#method_simulateTransaction)


---
### ws\_method\_accountSubscribe<!-- {{#callable:ws_method_accountSubscribe}} -->
The `ws_method_accountSubscribe` function subscribes a client to account updates over a WebSocket connection.
- **Inputs**:
    - `conn_id`: The connection ID of the WebSocket client.
    - `values`: A pointer to a `json_values` structure containing the parameters for the subscription.
    - `ctx`: A pointer to the `fd_rpc_ctx_t` context structure containing global state.
- **Control Flow**:
    - The function begins by defining a static array `PATH` to extract the first parameter from the JSON input, which is expected to be a string representing the account to subscribe to.
    - It retrieves the account string and checks if it is valid; if not, it sends an error response and returns.
    - Next, it decodes the account string from base58 format into a public key structure.
    - The function then defines another static array `PATH2` to extract the encoding type from the JSON input, defaulting to base58 if not provided.
    - It checks the encoding type and validates it, sending an error response for invalid types.
    - The function proceeds to check for optional parameters related to data slicing (length and offset) and validates them against the encoding type.
    - It checks if the maximum number of subscriptions has been reached; if so, it sends an error response and returns.
    - A new subscription is created and populated with the connection ID, method ID, call ID, account details, and encoding type.
    - Finally, it sends a success response back to the client with the subscription ID.
- **Output**: The function returns 1 on successful subscription, and sends a JSON response containing the subscription ID and call ID to the client.
- **Functions called**:
    - [`json_get_value`](fd_methods.c.driver.md#json_get_value)
    - [`fd_method_simple_error`](#fd_method_simple_error)
    - [`fd_method_error`](#fd_method_error)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)


---
### ws\_method\_accountSubscribe\_update<!-- {{#callable:ws_method_accountSubscribe_update}} -->
Updates the account subscription with the latest account information.
- **Inputs**:
    - `ctx`: A pointer to the `fd_rpc_ctx_t` structure containing the context for the RPC call.
    - `msg`: A pointer to the `fd_replay_notif_msg_t` structure containing the notification message with the latest account state.
    - `sub`: A pointer to the `fd_ws_subscription` structure representing the subscription to be updated.
- **Control Flow**:
    - The function begins by initializing a new web server reply using [`fd_web_reply_new`](fd_webserver.c.driver.md#fd_web_reply_new).
    - It retrieves the account record key using `fd_funk_acc_key` based on the account associated with the subscription.
    - It constructs a transaction ID (`xid`) from the slot number in the notification message.
    - The function attempts to read the account data using [`read_account_with_xid`](#read_account_with_xid).
    - If the account data is not found (i.e., `val` is NULL), the function returns 0, indicating no update.
    - If the account data is found, it formats a JSON response with the account notification, including the API version and slot number.
    - The account data is then converted to JSON format using [`fd_account_to_json`](fd_block_to_json.c.driver.md#fd_account_to_json).
    - If there is an error during the conversion, a warning is logged, and the function returns 0.
    - Finally, the formatted JSON response is sent back to the web server.
- **Output**: Returns 1 on successful update of the subscription, or 0 if the account data is not found or an error occurs.
- **Functions called**:
    - [`fd_web_reply_new`](fd_webserver.c.driver.md#fd_web_reply_new)
    - [`read_account_with_xid`](#read_account_with_xid)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)
    - [`fd_account_to_json`](fd_block_to_json.c.driver.md#fd_account_to_json)


---
### ws\_method\_slotSubscribe<!-- {{#callable:ws_method_slotSubscribe}} -->
The `ws_method_slotSubscribe` function handles WebSocket subscription requests for slot notifications.
- **Inputs**:
    - `conn_id`: The connection ID of the WebSocket client subscribing to slot notifications.
    - `values`: A pointer to a `json_values` structure containing the parsed JSON request.
    - `ctx`: A pointer to the `fd_rpc_ctx_t` context structure containing global state.
- **Control Flow**:
    - Check if the current number of subscriptions exceeds the maximum allowed (`FD_WS_MAX_SUBS`).
    - If the limit is exceeded, send an error response indicating too many subscriptions.
    - Create a new subscription entry in the global subscription list.
    - Set the connection ID, method ID, and call ID for the new subscription.
    - Generate a unique subscription ID and store it in the subscription entry.
    - Send a success response back to the client with the subscription ID.
- **Output**: Returns 1 on successful subscription and sends a JSON-RPC response with the subscription ID; otherwise, it returns 0 on failure.
- **Functions called**:
    - [`fd_method_simple_error`](#fd_method_simple_error)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)


---
### ws\_method\_slotSubscribe\_update<!-- {{#callable:ws_method_slotSubscribe_update}} -->
Updates the WebSocket subscription with the latest slot notification.
- **Inputs**:
    - `ctx`: A pointer to the `fd_rpc_ctx_t` structure containing the context for the RPC call.
    - `msg`: A pointer to the `fd_replay_notif_msg_t` structure containing the slot notification message.
    - `sub`: A pointer to the `fd_ws_subscription` structure representing the WebSocket subscription to be updated.
- **Control Flow**:
    - The function retrieves the WebSocket server context from the RPC context.
    - It initializes a new web reply for the WebSocket server.
    - It encodes the bank hash from the slot notification message into a base58 string.
    - It constructs a JSON response containing the slot notification details, including parent, root, slot, and bank hash.
    - Finally, it sends the constructed JSON response to the WebSocket subscription.
- **Output**: The function does not return a value but sends a JSON formatted notification to the WebSocket client.
- **Functions called**:
    - [`fd_web_reply_new`](fd_webserver.c.driver.md#fd_web_reply_new)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)


---
### fd\_webserver\_ws\_subscribe<!-- {{#callable:fd_webserver_ws_subscribe}} -->
The `fd_webserver_ws_subscribe` function handles WebSocket subscription requests for JSON-RPC methods.
- **Inputs**:
    - `values`: A pointer to a `json_values` structure containing the parsed JSON-RPC request.
    - `conn_id`: A unique identifier for the WebSocket connection.
    - `cb_arg`: A pointer to a context structure (`fd_rpc_ctx_t`) used for managing the RPC context.
- **Control Flow**:
    - The function begins by extracting the `jsonrpc` value from the input JSON and checks if it is '2.0'.
    - If the `jsonrpc` value is missing or incorrect, an error response is sent back to the client.
    - Next, it attempts to extract the `id` field from the JSON, either as an integer or a string, and stores it in the context.
    - The function then retrieves the `method` field from the JSON and determines which subscription method to call based on its value.
    - If the method is `KEYW_WS_METHOD_ACCOUNTSUBSCRIBE`, it calls [`ws_method_accountSubscribe`](#ws_method_accountSubscribe) to handle account subscriptions.
    - If the method is `KEYW_WS_METHOD_SLOTSUBSCRIBE`, it calls [`ws_method_slotSubscribe`](#ws_method_slotSubscribe) to handle slot subscriptions.
    - If the method is unknown, an error response is generated indicating the method is unrecognized.
- **Output**: The function does not return a value directly; instead, it sends responses back to the WebSocket client based on the success or failure of the subscription process.
- **Functions called**:
    - [`json_get_value`](fd_methods.c.driver.md#json_get_value)
    - [`fd_web_reply_error`](fd_webserver.c.driver.md#fd_web_reply_error)
    - [`fd_webserver_json_keyword`](keywords.c.driver.md#fd_webserver_json_keyword)
    - [`ws_method_accountSubscribe`](#ws_method_accountSubscribe)
    - [`ws_method_slotSubscribe`](#ws_method_slotSubscribe)


---
### fd\_rpc\_create\_ctx<!-- {{#callable:fd_rpc_create_ctx}} -->
Creates a new RPC context for the server.
- **Inputs**:
    - `args`: Pointer to `fd_rpcserver_args_t` structure containing server arguments.
    - `ctx_p`: Pointer to a pointer where the created `fd_rpc_ctx_t` context will be stored.
- **Control Flow**:
    - Allocates virtual memory for the RPC context and global context using `fd_valloc_malloc`.
    - Initializes the allocated contexts to zero using `fd_memset`.
    - Sets up the global context with the provided arguments, including the SPAD and stake CI.
    - If the server is not in offline mode, creates a UDP socket and binds it to a local address.
    - Allocates memory for performance samples and initializes the performance sample deque.
    - Creates a history object for the RPC context.
    - Starts the web server on the specified port and logs the status.
    - Assigns the created context to the pointer provided in `ctx_p`.
- **Output**: No return value; the created context is stored in the location pointed to by `ctx_p`.
- **Functions called**:
    - [`fd_rpc_history_create`](fd_rpc_history.c.driver.md#fd_rpc_history_create)
    - [`fd_webserver_start`](fd_webserver.c.driver.md#fd_webserver_start)


---
### fd\_rpc\_start\_service<!-- {{#callable:fd_rpc_start_service}} -->
Initializes the RPC service with provided server arguments and context.
- **Inputs**:
    - `args`: A pointer to `fd_rpcserver_args_t` structure containing server configuration and parameters.
    - `ctx`: A pointer to `fd_rpc_ctx_t` structure representing the current RPC context.
- **Control Flow**:
    - The function retrieves the global context from the provided `ctx` pointer.
    - It assigns the function pointer from `args` to the global context.
    - It copies the blockstore data from `args` to the global context's blockstore.
    - It sets the blockstore file descriptor in the global context.
- **Output**: The function does not return a value; it modifies the global context directly.


---
### fd\_rpc\_ws\_poll<!-- {{#callable:fd_rpc_ws_poll}} -->
Polls the web server for incoming requests.
- **Inputs**:
    - `ctx`: A pointer to the `fd_rpc_ctx_t` structure that contains the context for the RPC, including the global state and web server information.
- **Control Flow**:
    - Calls the [`fd_webserver_poll`](fd_webserver.c.driver.md#fd_webserver_poll) function, passing the web server instance from the context.
    - Returns the result of the [`fd_webserver_poll`](fd_webserver.c.driver.md#fd_webserver_poll) function, which indicates the status of the polling operation.
- **Output**: Returns an integer indicating the result of the polling operation, typically the number of events processed or an error code.
- **Functions called**:
    - [`fd_webserver_poll`](fd_webserver.c.driver.md#fd_webserver_poll)


---
### fd\_rpc\_ws\_fd<!-- {{#callable:fd_rpc_ws_fd}} -->
The `fd_rpc_ws_fd` function retrieves the file descriptor for the web server associated with the given RPC context.
- **Inputs**:
    - `ctx`: A pointer to an `fd_rpc_ctx_t` structure that contains the context for the RPC, including a reference to the global web server context.
- **Control Flow**:
    - The function calls [`fd_webserver_fd`](fd_webserver.c.driver.md#fd_webserver_fd) with the web server instance obtained from the global context within the provided `ctx`.
    - The result of the [`fd_webserver_fd`](fd_webserver.c.driver.md#fd_webserver_fd) call is returned directly.
- **Output**: Returns an integer representing the file descriptor for the web server, which can be used for I/O operations.
- **Functions called**:
    - [`fd_webserver_fd`](fd_webserver.c.driver.md#fd_webserver_fd)


---
### fd\_webserver\_ws\_closed<!-- {{#callable:fd_webserver_ws_closed}} -->
The `fd_webserver_ws_closed` function handles the closure of a WebSocket connection by removing the associated subscription.
- **Inputs**:
    - `conn_id`: The unique identifier for the WebSocket connection that is being closed.
    - `cb_arg`: A pointer to the callback argument, which is expected to be a pointer to an `fd_rpc_ctx_t` structure.
- **Control Flow**:
    - The function casts the `cb_arg` to a pointer of type `fd_rpc_ctx_t` to access the global context.
    - It retrieves the global context from the `ctx` structure.
    - It iterates over the list of subscriptions in the global context.
    - For each subscription, it checks if the `conn_id` matches the connection ID being closed.
    - If a match is found, it removes the subscription by replacing it with the last subscription in the list and decrements the subscription count.
- **Output**: The function does not return a value; it modifies the state of the global context by updating the subscription list.


---
### fd\_rpc\_replay\_during\_frag<!-- {{#callable:fd_rpc_replay_during_frag}} -->
The `fd_rpc_replay_during_frag` function copies a replay notification message from a provided buffer into a specified state structure.
- **Inputs**:
    - `ctx`: A pointer to the `fd_rpc_ctx_t` context structure, which is not used in this function.
    - `state`: A pointer to the `fd_replay_notif_msg_t` structure where the message will be copied to.
    - `msg`: A constant pointer to the message buffer containing the replay notification data.
    - `sz`: An integer representing the size of the message buffer.
- **Control Flow**:
    - The function begins by casting the `ctx` parameter to void, indicating it is unused.
    - It then asserts that the size of the message (`sz`) matches the expected size of the `fd_replay_notif_msg_t` structure using `FD_TEST`.
    - Finally, it copies the content of the `msg` buffer into the `state` structure using `fd_memcpy`.
- **Output**: The function does not return a value; it modifies the `state` structure in place with the contents of the `msg` buffer.


---
### fd\_rpc\_replay\_after\_frag<!-- {{#callable:fd_rpc_replay_after_frag}} -->
Processes replay notifications after a fragment is received.
- **Inputs**:
    - `ctx`: A pointer to the `fd_rpc_ctx_t` structure that contains the global context for the RPC.
    - `msg`: A pointer to the `fd_replay_notif_msg_t` structure that contains the replay notification message.
- **Control Flow**:
    - Checks if the message type is `FD_REPLAY_SLOT_TYPE`.
    - Calculates the current timestamp and checks if 60 seconds have passed since the last performance sample.
    - If the performance sample deque is full, it pops the oldest sample.
    - Records a new performance sample if the highest slot in the snapshot is valid.
    - Updates the performance sample snapshot with the current transaction count and highest slot.
    - Saves the history of the current block if the shred count is greater than zero.
    - Iterates through all subscriptions and updates them based on the message type.
- **Output**: The function does not return a value but updates the global context and subscriptions based on the replay notification.
- **Functions called**:
    - [`fd_rpc_history_save`](fd_rpc_history.c.driver.md#fd_rpc_history_save)
    - [`ws_method_slotSubscribe_update`](#ws_method_slotSubscribe_update)
    - [`fd_web_ws_send`](fd_webserver.c.driver.md#fd_web_ws_send)
    - [`ws_method_accountSubscribe_update`](#ws_method_accountSubscribe_update)


---
### fd\_rpc\_stake\_during\_frag<!-- {{#callable:fd_rpc_stake_during_frag}} -->
Initializes the staking message state during a fragment.
- **Inputs**:
    - `ctx`: A pointer to the `fd_rpc_ctx_t` structure representing the RPC context.
    - `state`: A pointer to the `fd_stake_ci_t` structure that holds the staking state.
    - `msg`: A constant pointer to the message data that will be used to initialize the staking state.
    - `sz`: An integer representing the size of the message data.
- **Control Flow**:
    - The function begins by casting the `ctx` and `sz` parameters to void, effectively ignoring them.
    - It then calls the `fd_stake_ci_stake_msg_init` function, passing the `state` and `msg` parameters to initialize the staking message state.
- **Output**: The function does not return a value; it modifies the `state` structure based on the provided `msg`.


---
### fd\_rpc\_stake\_after\_frag<!-- {{#callable:fd_rpc_stake_after_frag}} -->
Finalizes the state of a stake message after a fragment.
- **Inputs**:
    - `ctx`: A pointer to the `fd_rpc_ctx_t` structure, which contains the context for the RPC call.
    - `state`: A pointer to the `fd_stake_ci_t` structure representing the current state of the stake.
- **Control Flow**:
    - The function begins by ignoring the `ctx` parameter using a cast to void.
    - It then calls the `fd_stake_ci_stake_msg_fini` function, passing the `state` parameter to finalize the stake message.
- **Output**: The function does not return a value; it performs an operation to finalize the stake message.


# Function Declarations (Public API)

---
### fd\_method\_error<!-- {{#callable_declaration:fd_method_error}} -->
Reports an error with a formatted message.
- **Description**: Use this function to report an error within an RPC context by providing an error code and a formatted message. It is typically used when an error occurs during the execution of a method, and you want to send a detailed error message back to the client. The function formats the message using a printf-style format string and additional arguments, then sends the error message along with the error code to the client. This function should be called only when an error needs to be reported, and it assumes that the context has been properly initialized.
- **Inputs**:
    - `ctx`: A pointer to an fd_rpc_ctx_t structure representing the RPC context. Must not be null.
    - `errcode`: An integer representing the error code to be reported. It should be a valid error code that the client can interpret.
    - `format`: A printf-style format string used to format the error message. Must not be null.
    - `...`: Additional arguments required by the format string. These should match the format specifiers in the format string.
- **Output**: None
- **See also**: [`fd_method_error`](#fd_method_error)  (Implementation)



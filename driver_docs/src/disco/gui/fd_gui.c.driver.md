# Purpose
The provided C source code file is part of a larger system that manages and monitors a distributed ledger or blockchain network. It is specifically designed to handle the graphical user interface (GUI) components of the system, providing real-time updates and interactions with the network's state. The file includes functions for initializing, updating, and managing the GUI's state, which involves tracking various metrics and statuses related to network slots, transactions, and nodes. It interfaces with other components through a series of function calls and message handling routines, which are used to update the GUI with the latest network information.

Key technical components of this file include functions for creating and joining GUI instances ([`fd_gui_new`](#fd_gui_new), [`fd_gui_join`](#fd_gui_join)), handling WebSocket connections ([`fd_gui_ws_open`](#fd_gui_ws_open), [`fd_gui_ws_message`](#fd_gui_ws_message)), and processing various network events such as slot completions, leader schedule updates, and balance changes. The file also defines several static functions for capturing snapshots of network metrics and transaction waterfalls, which are crucial for providing a comprehensive view of the network's performance and state. Additionally, the file includes message handling functions that respond to different types of plugin messages, ensuring that the GUI remains synchronized with the network's current status. Overall, this file is integral to the system's ability to provide a user-friendly interface for monitoring and interacting with the blockchain network.
# Imports and Dependencies

---
- `fd_gui.h`
- `fd_gui_printf.h`
- `../metrics/fd_metrics.h`
- `../plugin/fd_plugin.h`
- `../../ballet/base58/fd_base58.h`
- `../../ballet/json/cJSON.h`
- `../../disco/genesis/fd_genesis_cluster.h`
- `../../disco/pack/fd_pack.h`
- `../../disco/pack/fd_pack_cost.h`


# Functions

---
### fd\_gui\_align<!-- {{#callable:fd_gui_align}} -->
The `fd_gui_align` function returns a constant alignment value of 128 bytes.
- **Inputs**: None
- **Control Flow**:
    - The function is defined with the `FD_FN_CONST` attribute, indicating it is a constant function.
    - It takes no parameters and directly returns the value `128UL`.
- **Output**: The function outputs an unsigned long integer with the value 128, representing the alignment size.


---
### fd\_gui\_footprint<!-- {{#callable:fd_gui_footprint}} -->
The `fd_gui_footprint` function returns the size of the `fd_gui_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function simply returns the result of the `sizeof` operator applied to `fd_gui_t`.
- **Output**: The function outputs an `ulong` representing the size of the `fd_gui_t` structure in bytes.


---
### fd\_gui\_new<!-- {{#callable:fd_gui_new}} -->
The `fd_gui_new` function initializes a new GUI structure in shared memory, setting up various parameters and configurations for a graphical user interface related to a server and network topology.
- **Inputs**:
    - `shmem`: A pointer to shared memory where the GUI structure will be initialized.
    - `http`: A pointer to an HTTP server structure used for web server interactions.
    - `version`: A string representing the version of the software.
    - `cluster`: A string representing the cluster name or identifier.
    - `identity_key`: A pointer to a 32-byte array representing the identity key.
    - `is_voting`: An integer indicating whether the GUI is in voting mode (non-zero) or not (zero).
    - `topo`: A pointer to a topology structure that contains information about the network topology.
- **Control Flow**:
    - Check if the shared memory pointer `shmem` is NULL and return NULL if true, logging a warning.
    - Check if the shared memory pointer `shmem` is properly aligned using `fd_gui_align()` and return NULL if not, logging a warning.
    - Check if the number of tiles in `topo` exceeds `FD_GUI_TILE_TIMER_TILE_CNT` and return NULL if true, logging a warning.
    - Cast the shared memory pointer `shmem` to a `fd_gui_t` pointer and initialize the GUI structure with the provided parameters.
    - Set various fields in the `gui` structure, including HTTP server, topology, identity key, version, cluster, and initial timestamps.
    - Initialize the `summary` sub-structure with default values, including identity key, version, cluster, startup time, and various counters.
    - Calculate and set the number of tiles for different categories (sock, net, quic, etc.) using `fd_topo_tile_name_cnt`.
    - Initialize arrays and counters in the `summary` sub-structure to zero or default values.
    - Return the initialized `gui` pointer.
- **Output**: A pointer to the initialized `fd_gui_t` structure, or NULL if initialization fails due to invalid inputs.
- **Functions called**:
    - [`fd_gui_align`](#fd_gui_align)


---
### fd\_gui\_join<!-- {{#callable:fd_gui_join}} -->
The `fd_gui_join` function casts a given shared memory pointer to a `fd_gui_t` pointer and returns it.
- **Inputs**:
    - `shmem`: A pointer to shared memory that is expected to be aligned and of sufficient size to hold a `fd_gui_t` structure.
- **Control Flow**:
    - The function takes a single argument, `shmem`, which is a pointer to shared memory.
    - It casts the `shmem` pointer to a `fd_gui_t` pointer.
    - The function returns the casted pointer.
- **Output**: A pointer to `fd_gui_t`, which is the result of casting the input `shmem` pointer.


---
### fd\_gui\_set\_identity<!-- {{#callable:fd_gui_set_identity}} -->
The `fd_gui_set_identity` function updates the identity key and its Base58 encoded representation in the GUI's summary, then broadcasts this information via WebSocket.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI context where the identity key will be set.
    - `identity_pubkey`: A constant pointer to an array of unsigned characters representing the public key to be set as the identity key.
- **Control Flow**:
    - Copy the 32-byte identity public key into the `identity_key` field of the `gui`'s summary.
    - Encode the identity public key into a Base58 string and store it in the `identity_key_base58` field of the `gui`'s summary.
    - Ensure the Base58 encoded string is null-terminated by setting the last character to '\0'.
    - Call [`fd_gui_printf_identity_key`](fd_gui_printf.c.driver.md#fd_gui_printf_identity_key) to print the identity key information to the GUI.
    - Broadcast the updated identity key information to all connected WebSocket clients using `fd_http_server_ws_broadcast`.
- **Output**: This function does not return a value; it performs operations on the `gui` object and communicates updates via WebSocket.
- **Functions called**:
    - [`fd_gui_printf_identity_key`](fd_gui_printf.c.driver.md#fd_gui_printf_identity_key)


---
### fd\_gui\_ws\_open<!-- {{#callable:fd_gui_ws_open}} -->
The `fd_gui_ws_open` function initializes a WebSocket connection by sending various GUI-related data to the client.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI context.
    - `ws_conn_id`: An unsigned long integer representing the WebSocket connection ID.
- **Control Flow**:
    - Define an array of function pointers `printers` that point to various GUI data printing functions.
    - Calculate the length of the `printers` array.
    - Iterate over each function in the `printers` array, call the function with `gui` as an argument, and send the result over the WebSocket connection using `fd_http_server_ws_send`.
    - Check if the block engine is available using `FD_LIKELY`, and if so, print block engine data and send it over the WebSocket connection.
    - Iterate over two possible epochs, and if an epoch is available, print skip rate and epoch data, sending each over the WebSocket connection.
    - Finally, print all peer data and send it over the WebSocket connection.
- **Output**: The function does not return any value; it performs operations to send GUI data over a WebSocket connection.
- **Functions called**:
    - [`fd_gui_printf_block_engine`](fd_gui_printf.c.driver.md#fd_gui_printf_block_engine)
    - [`fd_gui_printf_skip_rate`](fd_gui_printf.c.driver.md#fd_gui_printf_skip_rate)
    - [`fd_gui_printf_epoch`](fd_gui_printf.c.driver.md#fd_gui_printf_epoch)
    - [`fd_gui_printf_peers_all`](fd_gui_printf.c.driver.md#fd_gui_printf_peers_all)


---
### fd\_gui\_tile\_timers\_snap<!-- {{#callable:fd_gui_tile_timers_snap}} -->
The `fd_gui_tile_timers_snap` function captures and updates the current snapshot of tile timers for a GUI object, iterating over each tile to record various metrics.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure, which contains the GUI state and summary information, including tile metrics and topology.
- **Control Flow**:
    - Retrieve the current tile timers snapshot using the index from `gui->summary.tile_timers_snap_idx`.
    - Increment and wrap the `tile_timers_snap_idx` to point to the next snapshot slot.
    - Iterate over each tile in the topology (`gui->topo->tile_cnt`).
    - For each tile, check if the tile's metrics are available; if not, return early.
    - Retrieve the metrics for the current tile using `fd_metrics_tile`.
    - Update the current snapshot with various housekeeping and pre/post-fragmentation tick metrics from the tile's metrics.
- **Output**: The function does not return a value; it updates the `tile_timers_snap` array within the `gui` structure with the latest metrics for each tile.


---
### fd\_gui\_estimated\_tps\_snap<!-- {{#callable:fd_gui_estimated_tps_snap}} -->
The `fd_gui_estimated_tps_snap` function calculates and updates the estimated transactions per second (TPS) history for a GUI by iterating over recent slots and aggregating transaction counts.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure, which contains the GUI's state and data, including slot information and TPS history.
- **Control Flow**:
    - Initialize transaction count variables: `total_txn_cnt`, `vote_txn_cnt`, and `nonvote_failed_txn_cnt` to zero.
    - Iterate over recent slots up to the minimum of `gui->summary.slot_completed + 1` and `FD_GUI_SLOTS_CNT`.
    - For each slot, check if the slot is valid, completed, not too old, and not skipped; if any condition fails, skip or break the loop.
    - Accumulate transaction counts from valid slots into the initialized variables.
    - Update the `gui->summary.estimated_tps_history` with the accumulated transaction counts at the current index.
    - Increment the `gui->summary.estimated_tps_history_idx`, wrapping around if necessary.
- **Output**: The function does not return a value; it updates the `estimated_tps_history` and `estimated_tps_history_idx` fields of the `gui->summary` structure.


---
### fd\_gui\_txn\_waterfall\_snap<!-- {{#callable:fd_gui_txn_waterfall_snap}} -->
The `fd_gui_txn_waterfall_snap` function captures a snapshot of various transaction metrics from different tiles in the system to construct a view of the transaction waterfall.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure, which contains the GUI state and topology information.
    - `cur`: A pointer to an `fd_gui_txn_waterfall_t` structure, which will be populated with the current transaction metrics snapshot.
- **Control Flow**:
    - Initialize the `block_success`, `block_fail`, and `bank_invalid` counters in the `cur->out` structure to zero.
    - Iterate over each bank tile, retrieve its metrics, and update the `block_success`, `block_fail`, and `bank_invalid` counters based on specific metrics indices.
    - Retrieve metrics from the 'pack' tile and update `pack_invalid`, `pack_expired`, `pack_leader_slow`, `pack_wait_full`, and `pack_retained` counters in the `cur->out` structure.
    - Calculate the difference between `inserted_to_extra` and `inserted_from_extra` and update `pack_retained` accordingly.
    - Iterate over each resolv tile, retrieve its metrics, and update `resolv_lut_failed`, `resolv_expired`, `resolv_ancient`, `resolv_no_ledger`, and `resolv_retained` counters.
    - Retrieve metrics from the 'dedup' tile and update the `dedup_duplicate` counter.
    - Iterate over each verify tile, retrieve its metrics, and update `verify_overrun`, `verify_failed`, `verify_parse`, and `verify_duplicate` counters.
    - Iterate over each quic tile, retrieve its metrics, and update `quic_overrun`, `quic_frag_drop`, `quic_abandoned`, `tpu_quic_invalid`, and `tpu_udp_invalid` counters.
    - Iterate over each net tile, retrieve its metrics, and update the `net_overrun` counter.
    - Retrieve metrics from the 'bundle' tile if it exists and update `bundle_txns_received`.
    - Update the `cur->in` structure with metrics from the pack, dedup, and quic tiles, as well as the calculated `bundle_txns_received`.
- **Output**: The function does not return a value; it populates the `cur` structure with the current transaction metrics snapshot.


---
### fd\_gui\_tile\_stats\_snap<!-- {{#callable:fd_gui_tile_stats_snap}} -->
The `fd_gui_tile_stats_snap` function captures and updates various network and transaction statistics for a GUI application based on the current state of network tiles and transaction waterfall data.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI context, which contains information about the network topology and summary statistics.
    - `waterfall`: A constant pointer to an `fd_gui_txn_waterfall_t` structure that holds transaction waterfall data, including counts of various transaction states and errors.
    - `stats`: A pointer to an `fd_gui_tile_stats_t` structure where the function will store the updated statistics.
- **Control Flow**:
    - Initialize the `topo` variable with the network topology from the `gui` structure.
    - Set the `sample_time_nanos` field in `stats` to the current wall clock time.
    - Initialize `net_in_rx_bytes` and `net_out_tx_bytes` in `stats` to zero.
    - Iterate over network tiles and accumulate received and transmitted bytes into `net_in_rx_bytes` and `net_out_tx_bytes`.
    - Iterate over socket tiles and accumulate received and transmitted bytes similarly.
    - Initialize `quic_conn_cnt` in `stats` to zero and iterate over QUIC tiles to accumulate active connections.
    - Calculate `verify_drop_cnt` as the sum of various verification-related drop counts from `waterfall`.
    - Calculate `verify_total_cnt` as the total number of transactions minus various error and drop counts from `waterfall`.
    - Calculate `dedup_drop_cnt` and `dedup_total_cnt` using deduplication-related counts from `waterfall`.
    - Retrieve metrics from the 'pack' tile to set `pack_buffer_cnt` and `pack_buffer_capacity` in `stats`.
    - Calculate `bank_txn_exec_cnt` as the sum of successful and failed block transactions from `waterfall`.
- **Output**: The function updates the `stats` structure with the latest network and transaction statistics, including byte counts, connection counts, and transaction execution counts.


---
### fd\_gui\_poll<!-- {{#callable:fd_gui_poll}} -->
The `fd_gui_poll` function periodically updates and broadcasts GUI metrics and statistics based on the current time and predefined intervals.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure, which contains the GUI state and metrics to be updated and broadcasted.
- **Control Flow**:
    - Retrieve the current wallclock time using `fd_log_wallclock()` and store it in `now`.
    - Initialize `did_work` to 0, which will be used to indicate if any updates were performed.
    - Check if the current time exceeds `gui->next_sample_400millis`; if so, update estimated TPS, print it, broadcast via WebSocket, and update the next sample time by 400 milliseconds.
    - Check if the current time exceeds `gui->next_sample_100millis`; if so, update transaction waterfall and tile stats, print them, broadcast via WebSocket, and update the next sample time by 100 milliseconds.
    - Check if the current time exceeds `gui->next_sample_10millis`; if so, update tile timers, print them, broadcast via WebSocket, and update the next sample time by 10 milliseconds.
    - Return `did_work`, which indicates whether any updates were performed.
- **Output**: An integer indicating whether any updates were performed during the function call (1 if updates were performed, 0 otherwise).
- **Functions called**:
    - [`fd_gui_estimated_tps_snap`](#fd_gui_estimated_tps_snap)
    - [`fd_gui_printf_estimated_tps`](fd_gui_printf.c.driver.md#fd_gui_printf_estimated_tps)
    - [`fd_gui_txn_waterfall_snap`](#fd_gui_txn_waterfall_snap)
    - [`fd_gui_printf_live_txn_waterfall`](fd_gui_printf.c.driver.md#fd_gui_printf_live_txn_waterfall)
    - [`fd_gui_tile_stats_snap`](#fd_gui_tile_stats_snap)
    - [`fd_gui_printf_live_tile_stats`](fd_gui_printf.c.driver.md#fd_gui_printf_live_tile_stats)
    - [`fd_gui_tile_timers_snap`](#fd_gui_tile_timers_snap)
    - [`fd_gui_printf_live_tile_timers`](fd_gui_printf.c.driver.md#fd_gui_printf_live_tile_timers)


---
### fd\_gui\_handle\_gossip\_update<!-- {{#callable:fd_gui_handle_gossip_update}} -->
The `fd_gui_handle_gossip_update` function processes a gossip update message to update the peer list in the GUI, identifying added, updated, and removed peers, and then broadcasts the changes.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI context that holds the current state of peers and other GUI-related data.
    - `msg`: A constant pointer to an unsigned character array containing the gossip update message data.
- **Control Flow**:
    - The function begins by interpreting the first part of the `msg` as a header to extract the number of peers (`peer_cnt`).
    - It initializes counters and arrays to track added, updated, and removed peers.
    - The function iterates over the current list of peers in `gui->gossip.peers` to identify and remove peers that are no longer present in the update message.
    - For each peer in the update message, it checks if the peer already exists in the current list; if not, it adds the peer to the list and updates its details.
    - If a peer already exists, it checks if any details have changed and updates them if necessary, marking the peer as updated.
    - After processing all peers, it calculates the number of added peers and updates the `added` array accordingly.
    - Finally, it calls [`fd_gui_printf_peers_gossip_update`](fd_gui_printf.c.driver.md#fd_gui_printf_peers_gossip_update) to print the update and `fd_http_server_ws_broadcast` to broadcast the changes.
- **Output**: The function does not return a value; it updates the state of the `gui` object and broadcasts changes to the WebSocket server.
- **Functions called**:
    - [`fd_gui_printf_peers_gossip_update`](fd_gui_printf.c.driver.md#fd_gui_printf_peers_gossip_update)


---
### fd\_gui\_handle\_vote\_account\_update<!-- {{#callable:fd_gui_handle_vote_account_update}} -->
The `fd_gui_handle_vote_account_update` function processes a message to update the vote accounts in the GUI, identifying added, updated, and removed accounts, and then broadcasts the changes.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI context that holds the current state of vote accounts.
    - `msg`: A constant pointer to an unsigned character array containing the message data for updating vote accounts.
- **Control Flow**:
    - The function begins by interpreting the message as a header containing the number of peers (`peer_cnt`).
    - It checks if `peer_cnt` is within the allowed limit (<= 40200).
    - Initializes counters and arrays for tracking added, updated, and removed vote accounts.
    - Iterates over the existing vote accounts in the GUI to identify and remove any that are not found in the incoming message data.
    - Iterates over the incoming message data to identify new vote accounts to add and existing accounts to update.
    - For each new account, it copies the relevant data into the GUI's vote account structure and increments the count.
    - For each existing account, it checks if any fields have changed and updates them if necessary, marking the account as updated.
    - Calculates the number of added accounts by comparing the current count with the previous count before processing the message.
    - Calls [`fd_gui_printf_peers_vote_account_update`](fd_gui_printf.c.driver.md#fd_gui_printf_peers_vote_account_update) to print the update details and `fd_http_server_ws_broadcast` to broadcast the changes.
- **Output**: The function does not return a value; it updates the state of the GUI's vote accounts and broadcasts the changes.
- **Functions called**:
    - [`fd_gui_printf_peers_vote_account_update`](fd_gui_printf.c.driver.md#fd_gui_printf_peers_vote_account_update)


---
### fd\_gui\_handle\_validator\_info\_update<!-- {{#callable:fd_gui_handle_validator_info_update}} -->
The function `fd_gui_handle_validator_info_update` processes incoming validator information messages to update or add validator details in the GUI's data structure and broadcasts the changes.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure, which holds the state and data for the GUI, including validator information.
    - `msg`: A constant pointer to an unsigned character array containing the message data with validator information to be processed.
- **Control Flow**:
    - The function begins by casting the `msg` to a `uchar` pointer named `data` for easier access to the message content.
    - It initializes counters and arrays for tracking added and updated validators, but not for removed ones, as removal is not applicable here.
    - The function iterates over the existing validator information in `gui` to check if the incoming validator (identified by its public key) already exists.
    - If the validator is not found, it adds a new entry to the `gui->validator_info` array, copying the public key, name, website, details, and icon URI from the `data`.
    - If the validator is found, it checks if any of the validator's details have changed by comparing the current details with those in `data`.
    - If changes are detected, it updates the existing entry with the new details from `data` and records the index of the updated entry.
    - The function calculates the number of new validators added by comparing the current count with the count before processing the message.
    - It calls [`fd_gui_printf_peers_validator_info_update`](fd_gui_printf.c.driver.md#fd_gui_printf_peers_validator_info_update) to print the update information and `fd_http_server_ws_broadcast` to broadcast the changes over WebSocket.
- **Output**: The function does not return a value; it updates the `gui` structure in place and broadcasts changes.
- **Functions called**:
    - [`fd_gui_printf_peers_validator_info_update`](fd_gui_printf.c.driver.md#fd_gui_printf_peers_validator_info_update)


---
### fd\_gui\_request\_slot<!-- {{#callable:fd_gui_request_slot}} -->
The `fd_gui_request_slot` function processes a request to retrieve information about a specific slot in the GUI system, validating the request and sending the appropriate response over a WebSocket connection.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI context.
    - `ws_conn_id`: An unsigned long integer representing the WebSocket connection ID.
    - `request_id`: An unsigned long integer representing the unique ID of the request.
    - `params`: A constant pointer to a `cJSON` object containing the parameters of the request, specifically the slot number.
- **Control Flow**:
    - Retrieve the 'slot' parameter from the `params` JSON object using `cJSON_GetObjectItemCaseSensitive`.
    - Check if the 'slot' parameter is a valid number using `cJSON_IsNumber`; if not, return `FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST`.
    - Extract the slot number from the 'slot' parameter and calculate the corresponding slot index in the `gui->slots` array.
    - Check if the slot at the calculated index matches the requested slot number and is not `ULONG_MAX`; if not, send a null query response and return 0.
    - If the slot is valid, send a slot request response using [`fd_gui_printf_slot_request`](fd_gui_printf.c.driver.md#fd_gui_printf_slot_request) and return 0.
- **Output**: Returns an integer status code: 0 for success or `FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST` if the request is invalid.
- **Functions called**:
    - [`fd_gui_printf_null_query_response`](fd_gui_printf.c.driver.md#fd_gui_printf_null_query_response)
    - [`fd_gui_printf_slot_request`](fd_gui_printf.c.driver.md#fd_gui_printf_slot_request)


---
### fd\_gui\_request\_slot\_transactions<!-- {{#callable:fd_gui_request_slot_transactions}} -->
The `fd_gui_request_slot_transactions` function processes a request to retrieve transactions for a specific slot in a GUI application.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI context.
    - `ws_conn_id`: An unsigned long representing the WebSocket connection ID.
    - `request_id`: An unsigned long representing the request ID.
    - `params`: A constant pointer to a `cJSON` object containing the parameters for the request, specifically the slot number.
- **Control Flow**:
    - Retrieve the 'slot' parameter from the `params` JSON object using `cJSON_GetObjectItemCaseSensitive`.
    - Check if the 'slot' parameter is a valid number using `cJSON_IsNumber`; if not, return `FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST`.
    - Extract the slot number from the 'slot' parameter and calculate the index in the `slots` array using modulo operation with `FD_GUI_SLOTS_CNT`.
    - Check if the slot at the calculated index matches the requested slot number and is not `ULONG_MAX`; if not, send a null query response and return 0.
    - If the slot is valid, print the slot transactions request using [`fd_gui_printf_slot_transactions_request`](fd_gui_printf.c.driver.md#fd_gui_printf_slot_transactions_request) and send the response over WebSocket.
    - Return 0 to indicate successful processing.
- **Output**: Returns an integer, 0 for successful processing or `FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST` if the slot parameter is invalid.
- **Functions called**:
    - [`fd_gui_printf_null_query_response`](fd_gui_printf.c.driver.md#fd_gui_printf_null_query_response)
    - [`fd_gui_printf_slot_transactions_request`](fd_gui_printf.c.driver.md#fd_gui_printf_slot_transactions_request)


---
### fd\_gui\_request\_slot\_detailed<!-- {{#callable:fd_gui_request_slot_detailed}} -->
The `fd_gui_request_slot_detailed` function processes a detailed slot request by validating the slot parameter and sending a detailed slot request response over a WebSocket connection.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI context.
    - `ws_conn_id`: An unsigned long representing the WebSocket connection ID.
    - `request_id`: An unsigned long representing the unique request ID.
    - `params`: A constant pointer to a `cJSON` object containing the parameters for the request, specifically the slot number.
- **Control Flow**:
    - Retrieve the 'slot' parameter from the `params` JSON object using `cJSON_GetObjectItemCaseSensitive`.
    - Check if the 'slot' parameter is a number using `cJSON_IsNumber`; if not, return `FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST`.
    - Extract the slot number from the 'slot' parameter and calculate the slot index using modulo operation with `FD_GUI_SLOTS_CNT`.
    - Retrieve the slot information from the `gui->slots` array using the calculated index.
    - Check if the slot information is valid by comparing the slot number and ensuring it is not `ULONG_MAX`; if invalid, send a null query response and return 0.
    - If valid, send a detailed slot request response using [`fd_gui_printf_slot_request_detailed`](fd_gui_printf.c.driver.md#fd_gui_printf_slot_request_detailed) and `fd_http_server_ws_send`, then return 0.
- **Output**: Returns an integer status code: 0 for success or `FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST` for invalid input.
- **Functions called**:
    - [`fd_gui_printf_null_query_response`](fd_gui_printf.c.driver.md#fd_gui_printf_null_query_response)
    - [`fd_gui_printf_slot_request_detailed`](fd_gui_printf.c.driver.md#fd_gui_printf_slot_request_detailed)


---
### fd\_gui\_ws\_message<!-- {{#callable:fd_gui_ws_message}} -->
The `fd_gui_ws_message` function processes a WebSocket message by parsing JSON data, validating its structure, and executing specific actions based on the message's topic and key.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI context.
    - `ws_conn_id`: An unsigned long integer representing the WebSocket connection ID.
    - `data`: A pointer to a constant unsigned char array containing the message data to be processed.
    - `data_len`: An unsigned long integer representing the length of the data array.
- **Control Flow**:
    - Parse the JSON data from the input using `cJSON_ParseWithLengthOpts` and check for parsing errors.
    - Retrieve the 'id' field from the JSON object and validate that it is a number.
    - Retrieve the 'topic' and 'key' fields from the JSON object and validate that they are strings.
    - Check if the topic is 'slot' and the key is 'query', 'query_detailed', or 'query_transactions', and if so, retrieve the 'params' field and call the corresponding request function ([`fd_gui_request_slot`](#fd_gui_request_slot), [`fd_gui_request_slot_detailed`](#fd_gui_request_slot_detailed), or [`fd_gui_request_slot_transactions`](#fd_gui_request_slot_transactions)).
    - If the topic is 'summary' and the key is 'ping', call [`fd_gui_printf_summary_ping`](fd_gui_printf.c.driver.md#fd_gui_printf_summary_ping) and send a WebSocket message.
    - If none of the conditions match, return a connection close status indicating an unknown method.
    - Delete the JSON object to free memory before returning.
- **Output**: Returns an integer status code indicating the result of processing the message, such as `FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST` for errors or 0 for successful processing.
- **Functions called**:
    - [`fd_gui_request_slot`](#fd_gui_request_slot)
    - [`fd_gui_request_slot_detailed`](#fd_gui_request_slot_detailed)
    - [`fd_gui_request_slot_transactions`](#fd_gui_request_slot_transactions)
    - [`fd_gui_printf_summary_ping`](fd_gui_printf.c.driver.md#fd_gui_printf_summary_ping)


---
### fd\_gui\_clear\_slot<!-- {{#callable:fd_gui_clear_slot}} -->
The `fd_gui_clear_slot` function initializes and clears a specific slot in the GUI's slot array, setting various parameters to default values and determining if the slot is owned by the current identity.
- **Inputs**:
    - `gui`: A pointer to the `fd_gui_t` structure, which contains the GUI state and slot information.
    - `_slot`: An unsigned long integer representing the slot number to be cleared.
    - `_parent_slot`: An unsigned long integer representing the parent slot number of the slot to be cleared.
- **Control Flow**:
    - Retrieve the slot from the GUI's slot array using the modulo operation with `FD_GUI_SLOTS_CNT` to ensure it wraps around correctly.
    - Initialize `mine` to 0 and `epoch_idx` to 0UL.
    - Iterate over the two possible epochs to determine if the slot falls within a valid epoch range and if the slot leader matches the GUI's identity key.
    - Set various fields of the slot structure to default or maximum values, such as `max_compute_units`, `total_txn_cnt`, `transaction_fee`, etc.
    - If the slot is owned by the current identity (`mine` is true), increment the `my_total_slots` counter for the corresponding epoch.
    - If the slot number is 0, set the slot's level to `FD_GUI_SLOT_LEVEL_ROOTED`.
- **Output**: The function does not return a value; it modifies the slot structure in place.


---
### fd\_gui\_handle\_leader\_schedule<!-- {{#callable:fd_gui_handle_leader_schedule}} -->
The `fd_gui_handle_leader_schedule` function processes a leader schedule message to update the GUI's epoch information and broadcast the changes.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI state.
    - `msg`: A pointer to an array of unsigned long integers containing the leader schedule message data.
- **Control Flow**:
    - Extracts epoch, staked count, start slot, slot count, and excluded stake from the message.
    - Validates that the staked count does not exceed 50,000 and the slot count does not exceed 432,000.
    - Determines the index for the epoch data based on the epoch number modulo 2.
    - Updates the GUI's epoch information with the extracted data, including epoch number, start and end slots, and excluded stake.
    - Resets the total and skipped slots for the current epoch.
    - Deletes the existing leader schedule and creates a new one using the message data.
    - Copies the stakes data from the message into the GUI's epoch stakes array.
    - Sets the start time for the epoch based on the start slot, using the current wall clock time if the start slot is 0, or the completed time of the last non-skipped slot otherwise.
    - Calls [`fd_gui_printf_epoch`](fd_gui_printf.c.driver.md#fd_gui_printf_epoch) to print the epoch information.
    - Broadcasts the updated epoch information over the WebSocket server.
- **Output**: This function does not return a value; it updates the GUI state and broadcasts changes.
- **Functions called**:
    - [`fd_gui_printf_epoch`](fd_gui_printf.c.driver.md#fd_gui_printf_epoch)


---
### fd\_gui\_handle\_slot\_start<!-- {{#callable:fd_gui_handle_slot_start}} -->
The `fd_gui_handle_slot_start` function initializes and updates the state of a slot in the GUI system when a new slot starts.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI system state.
    - `msg`: A pointer to an array of unsigned long integers containing the slot number and parent slot number.
- **Control Flow**:
    - Extract the slot number and parent slot number from the `msg` array.
    - Check if the `debug_in_leader_slot` in `gui` is set to `ULONG_MAX` and set it to the current slot number.
    - Retrieve the slot object from the `gui->slots` array using the slot number modulo `FD_GUI_SLOTS_CNT`.
    - If the slot's current slot number does not match the extracted slot number, call [`fd_gui_clear_slot`](#fd_gui_clear_slot) to reset the slot state.
    - Set the slot's `leader_state` to `FD_GUI_SLOT_LEADER_STARTED`.
    - Call [`fd_gui_tile_timers_snap`](#fd_gui_tile_timers_snap) to snapshot the current tile timers.
    - Update the `tile_timers_snap_idx_slot_start` in `gui->summary` to the previous index in the tile timers snapshot array.
    - Create a `fd_gui_txn_waterfall_t` object and call [`fd_gui_txn_waterfall_snap`](#fd_gui_txn_waterfall_snap) to snapshot the transaction waterfall.
    - Call [`fd_gui_tile_stats_snap`](#fd_gui_tile_stats_snap) to snapshot the tile statistics and store them in the slot's `tile_stats_begin`.
- **Output**: The function does not return a value; it modifies the state of the `gui` and the specified slot.
- **Functions called**:
    - [`fd_gui_clear_slot`](#fd_gui_clear_slot)
    - [`fd_gui_tile_timers_snap`](#fd_gui_tile_timers_snap)
    - [`fd_gui_txn_waterfall_snap`](#fd_gui_txn_waterfall_snap)
    - [`fd_gui_tile_stats_snap`](#fd_gui_tile_stats_snap)


---
### fd\_gui\_handle\_slot\_end<!-- {{#callable:fd_gui_handle_slot_end}} -->
The `fd_gui_handle_slot_end` function processes the end of a slot in the GUI, updating various metrics and states related to the slot's execution.
- **Inputs**:
    - `gui`: A pointer to the `fd_gui_t` structure representing the GUI context.
    - `msg`: A pointer to an array of unsigned long integers containing the slot number and compute units used.
- **Control Flow**:
    - Extract the slot number and compute units used from the `msg` array.
    - Check if the current slot matches the expected slot in `gui->debug_in_leader_slot`; log an error if not.
    - Reset `gui->debug_in_leader_slot` to `ULONG_MAX`.
    - Retrieve the slot structure from the `gui->slots` array using the slot number modulo `FD_GUI_SLOTS_CNT`.
    - Verify that the slot number in the slot structure matches the expected slot number.
    - Update the slot's leader state to `FD_GUI_SLOT_LEADER_ENDED` and set the compute units used.
    - Call [`fd_gui_tile_timers_snap`](#fd_gui_tile_timers_snap) to snapshot the tile timers.
    - Record the slot number in the `gui->summary.tile_timers_leader_history_slot` array to detect overwrites.
    - Set the slot's `tile_timers_history_idx` to the current history index.
    - Calculate the end index for downsampling tile timers and update the sample count.
    - Downsample the tile timers into per-leader-slot storage using a calculated stride.
    - Increment the `gui->summary.tile_timers_history_idx` for the next slot.
    - Snapshot the transaction waterfall state and save it into the slot, then reset reference counters.
    - Call [`fd_gui_tile_stats_snap`](#fd_gui_tile_stats_snap) to snapshot the tile statistics.
- **Output**: The function does not return a value; it updates the state of the `gui` and its associated slot structures.
- **Functions called**:
    - [`fd_gui_tile_timers_snap`](#fd_gui_tile_timers_snap)
    - [`fd_gui_txn_waterfall_snap`](#fd_gui_txn_waterfall_snap)
    - [`fd_gui_tile_stats_snap`](#fd_gui_tile_stats_snap)


---
### fd\_gui\_handle\_reset\_slot<!-- {{#callable:fd_gui_handle_reset_slot}} -->
The `fd_gui_handle_reset_slot` function processes a reset slot message to update the GUI's slot state, vote state, and republish necessary information.
- **Inputs**:
    - `gui`: A pointer to the `fd_gui_t` structure representing the GUI state.
    - `msg`: A pointer to an array of `ulong` values containing the reset slot message data.
- **Control Flow**:
    - Extract the `last_landed_vote`, `parent_cnt`, and `_slot` from the `msg` array.
    - Iterate over each parent slot in the message, clearing slots if necessary using [`fd_gui_clear_slot`](#fd_gui_clear_slot).
    - Update the `vote_distance` and broadcast changes if it differs from the current value.
    - Check and update the `vote_state` based on the `last_landed_vote` and `_slot`, broadcasting changes if necessary.
    - Iterate over slots up to `_slot`, clearing and republishing slots as needed, and updating skip rates.
    - Calculate the `estimated_slot_duration_nanos` if `_slot` differs from the last published slot, and broadcast changes.
    - Update the `slot_completed` value if it differs from `_slot`, and broadcast changes.
    - Republish skip rates for epochs if necessary.
- **Output**: The function does not return a value; it updates the GUI state and broadcasts changes as needed.
- **Functions called**:
    - [`fd_gui_clear_slot`](#fd_gui_clear_slot)
    - [`fd_gui_printf_vote_distance`](fd_gui_printf.c.driver.md#fd_gui_printf_vote_distance)
    - [`fd_gui_printf_vote_state`](fd_gui_printf.c.driver.md#fd_gui_printf_vote_state)
    - [`fd_gui_printf_slot`](fd_gui_printf.c.driver.md#fd_gui_printf_slot)
    - [`fd_gui_printf_estimated_slot_duration_nanos`](fd_gui_printf.c.driver.md#fd_gui_printf_estimated_slot_duration_nanos)
    - [`fd_gui_printf_completed_slot`](fd_gui_printf.c.driver.md#fd_gui_printf_completed_slot)
    - [`fd_gui_printf_skip_rate`](fd_gui_printf.c.driver.md#fd_gui_printf_skip_rate)


---
### fd\_gui\_handle\_completed\_slot<!-- {{#callable:fd_gui_handle_completed_slot}} -->
The `fd_gui_handle_completed_slot` function processes a completed slot message, updating the GUI's slot data and broadcasting relevant updates.
- **Inputs**:
    - `gui`: A pointer to the `fd_gui_t` structure, representing the GUI state and data.
    - `msg`: A pointer to an array of unsigned long integers containing slot completion data, including slot number, transaction counts, fees, and other metrics.
- **Control Flow**:
    - Extracts slot number and various transaction metrics from the `msg` array.
    - Retrieves the slot data from the `gui` structure using the slot number modulo the slot count.
    - Checks if the slot data needs to be cleared and reinitialized if the slot number does not match.
    - Updates the slot's completion time, parent slot, and maximum compute units.
    - Adjusts the slot's level based on its current state and whether it has been optimistically confirmed.
    - Updates transaction counts, fees, and compute units in the slot data.
    - Checks if the slot is the end of an epoch and updates the epoch end time if necessary.
    - Broadcasts the new skip rate if the slot belongs to the current node.
- **Output**: The function does not return a value; it updates the GUI's internal state and may trigger broadcasts to update connected clients.
- **Functions called**:
    - [`fd_gui_clear_slot`](#fd_gui_clear_slot)
    - [`fd_gui_printf_skip_rate`](fd_gui_printf.c.driver.md#fd_gui_printf_skip_rate)


---
### fd\_gui\_handle\_rooted\_slot<!-- {{#callable:fd_gui_handle_rooted_slot}} -->
The `fd_gui_handle_rooted_slot` function processes a rooted slot message, updating the slot's status to rooted and broadcasting the update.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI context.
    - `msg`: A pointer to an array of `ulong` values, where the first element is the slot number that has been rooted.
- **Control Flow**:
    - Extract the slot number `_slot` from the `msg` array.
    - Iterate over slots from `_slot` down to 0 or `FD_GUI_SLOTS_CNT`, whichever is smaller.
    - For each slot, calculate the `parent_slot` and `parent_idx` based on the current index `i`.
    - Retrieve the slot structure from `gui->slots` using `parent_idx`.
    - If the slot's `slot` field is `ULONG_MAX`, break the loop as it indicates an uninitialized slot.
    - If the slot's `slot` field does not match `parent_slot`, log an error and break the loop.
    - If the slot's `level` is already `FD_GUI_SLOT_LEVEL_ROOTED`, break the loop as further processing is unnecessary.
    - Set the slot's `level` to `FD_GUI_SLOT_LEVEL_ROOTED`.
    - Call [`fd_gui_printf_slot`](fd_gui_printf.c.driver.md#fd_gui_printf_slot) to print the slot information and `fd_http_server_ws_broadcast` to broadcast the update.
    - Update `gui->summary.slot_rooted` to `_slot`.
    - Call [`fd_gui_printf_root_slot`](fd_gui_printf.c.driver.md#fd_gui_printf_root_slot) to print the root slot information and `fd_http_server_ws_broadcast` to broadcast the update.
- **Output**: This function does not return a value; it updates the state of the GUI and broadcasts messages.
- **Functions called**:
    - [`fd_gui_printf_slot`](fd_gui_printf.c.driver.md#fd_gui_printf_slot)
    - [`fd_gui_printf_root_slot`](fd_gui_printf.c.driver.md#fd_gui_printf_root_slot)


---
### fd\_gui\_handle\_optimistically\_confirmed\_slot<!-- {{#callable:fd_gui_handle_optimistically_confirmed_slot}} -->
The function `fd_gui_handle_optimistically_confirmed_slot` updates the status of slots in a GUI system to reflect optimistic confirmation and broadcasts these updates.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI system.
    - `msg`: A pointer to an array of unsigned long integers, where the first element represents the slot number that has been optimistically confirmed.
- **Control Flow**:
    - Extract the slot number `_slot` from the `msg` array.
    - Iterate over slots from `_slot` down to the minimum of `_slot` and `FD_GUI_SLOTS_CNT`.
    - For each slot, calculate `parent_slot` and `parent_idx` to access the corresponding slot in the GUI system.
    - Check if the slot is uninitialized or if its slot number is greater than `parent_slot`, and break the loop if so.
    - If the slot number is less than `parent_slot`, continue to the next iteration.
    - If the slot's level is already rooted, break the loop.
    - If the slot's level is less than optimistically confirmed, update its level to optimistically confirmed, print the slot, and broadcast the update.
    - If `_slot` is less than the current optimistically confirmed slot in the summary, iterate backwards from the current optimistically confirmed slot to `_slot`, updating slots to completed if necessary.
    - Update the GUI summary's optimistically confirmed slot to `_slot`, print the update, and broadcast it.
- **Output**: The function does not return a value; it updates the state of the GUI system and broadcasts changes.
- **Functions called**:
    - [`fd_gui_printf_slot`](fd_gui_printf.c.driver.md#fd_gui_printf_slot)
    - [`fd_gui_printf_optimistically_confirmed_slot`](fd_gui_printf.c.driver.md#fd_gui_printf_optimistically_confirmed_slot)


---
### fd\_gui\_handle\_balance\_update<!-- {{#callable:fd_gui_handle_balance_update}} -->
The `fd_gui_handle_balance_update` function updates the balance of either the identity or vote account in the GUI and broadcasts the update via WebSocket.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI context.
    - `msg`: A pointer to an array of unsigned long integers containing the message data, where the first element indicates the account type and the second element is the new balance.
- **Control Flow**:
    - The function begins by switching on the first element of the `msg` array to determine the account type.
    - If the account type is `0UL`, it updates the `identity_account_balance` in the `gui` summary with the second element of `msg`, calls [`fd_gui_printf_identity_balance`](fd_gui_printf.c.driver.md#fd_gui_printf_identity_balance) to print the updated balance, and broadcasts the update using `fd_http_server_ws_broadcast`.
    - If the account type is `1UL`, it updates the `vote_account_balance` in the `gui` summary with the second element of `msg`, calls [`fd_gui_printf_vote_balance`](fd_gui_printf.c.driver.md#fd_gui_printf_vote_balance) to print the updated balance, and broadcasts the update using `fd_http_server_ws_broadcast`.
    - If the account type is neither `0UL` nor `1UL`, it logs an error indicating an unknown account type.
- **Output**: The function does not return a value; it performs updates and broadcasts as side effects.
- **Functions called**:
    - [`fd_gui_printf_identity_balance`](fd_gui_printf.c.driver.md#fd_gui_printf_identity_balance)
    - [`fd_gui_printf_vote_balance`](fd_gui_printf.c.driver.md#fd_gui_printf_vote_balance)


---
### fd\_gui\_handle\_start\_progress<!-- {{#callable:fd_gui_handle_start_progress}} -->
The `fd_gui_handle_start_progress` function updates the GUI's startup progress state based on a message type and logs the progress.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI state.
    - `msg`: A pointer to a constant unsigned character array containing the message data, where the first byte indicates the type of progress update.
- **Control Flow**:
    - Extract the type of progress update from the first byte of the `msg` array.
    - Use a switch statement to handle different progress types based on the extracted type value.
    - For type 0, set the progress to 'initializing' and log the progress.
    - For type 1, determine if a full snapshot has been received and set the progress to searching for either a full or incremental snapshot, then log the progress.
    - For type 2, check if the snapshot is full or incremental, update the corresponding progress state and snapshot details, and log the progress.
    - For type 3, set the flag indicating a full snapshot has been received.
    - For types 4 to 11, update the progress state to the corresponding startup phase and log the progress.
    - For any unknown type, log an error message indicating an unknown progress type.
    - Call [`fd_gui_printf_startup_progress`](fd_gui_printf.c.driver.md#fd_gui_printf_startup_progress) to print the updated startup progress.
    - Broadcast the updated progress state using `fd_http_server_ws_broadcast`.
- **Output**: The function does not return a value; it updates the GUI's startup progress state and logs the progress.
- **Functions called**:
    - [`fd_gui_printf_startup_progress`](fd_gui_printf.c.driver.md#fd_gui_printf_startup_progress)


---
### fd\_gui\_handle\_genesis\_hash<!-- {{#callable:fd_gui_handle_genesis_hash}} -->
The `fd_gui_handle_genesis_hash` function processes a genesis hash message to update the GUI's cluster information if it has changed.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI context.
    - `msg`: A constant pointer to an unsigned character array containing the genesis hash message.
- **Control Flow**:
    - Encode the 32-byte message `msg` into a Base58 string `hash_cstr` using `FD_BASE58_ENCODE_32_BYTES` macro.
    - Identify the cluster using `fd_genesis_cluster_identify` with `hash_cstr` and store the result in `cluster`.
    - Retrieve the cluster name using `fd_genesis_cluster_name` with `cluster` and store it in `cluster_name`.
    - Check if the current cluster name in `gui->summary.cluster` is different from `cluster_name`.
    - If different, update `gui->summary.cluster` with the new `cluster_name`.
    - Call [`fd_gui_printf_cluster`](fd_gui_printf.c.driver.md#fd_gui_printf_cluster) to print the updated cluster information.
    - Broadcast the update using `fd_http_server_ws_broadcast` with `gui->http`.
- **Output**: This function does not return a value; it updates the GUI's cluster information and broadcasts the change if necessary.
- **Functions called**:
    - [`fd_gui_printf_cluster`](fd_gui_printf.c.driver.md#fd_gui_printf_cluster)


---
### fd\_gui\_handle\_block\_engine\_update<!-- {{#callable:fd_gui_handle_block_engine_update}} -->
The function `fd_gui_handle_block_engine_update` updates the GUI's block engine information based on a received message and broadcasts the update.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI context to be updated.
    - `msg`: A constant pointer to an unsigned character array containing the block engine update message.
- **Control Flow**:
    - Cast the `msg` to a `fd_plugin_msg_block_engine_update_t` pointer to access the update data.
    - Set `gui->block_engine.has_block_engine` to 1, indicating the presence of a block engine.
    - Copy the `name`, `url`, and `ip_cstr` from the update message to the corresponding fields in `gui->block_engine`, ensuring not to exceed the buffer size.
    - Set `gui->block_engine.status` to the status from the update message.
    - Call [`fd_gui_printf_block_engine`](fd_gui_printf.c.driver.md#fd_gui_printf_block_engine) to print the block engine information to the GUI.
    - Broadcast the updated block engine information using `fd_http_server_ws_broadcast`.
- **Output**: This function does not return a value; it updates the GUI's block engine information and broadcasts the update.
- **Functions called**:
    - [`fd_gui_printf_block_engine`](fd_gui_printf.c.driver.md#fd_gui_printf_block_engine)


---
### fd\_gui\_plugin\_message<!-- {{#callable:fd_gui_plugin_message}} -->
The `fd_gui_plugin_message` function processes various plugin messages and updates the GUI state accordingly.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI state.
    - `plugin_msg`: An unsigned long integer representing the type of plugin message received.
    - `msg`: A pointer to an unsigned char array containing the message data.
- **Control Flow**:
    - The function uses a switch statement to handle different types of plugin messages based on the `plugin_msg` value.
    - For each case, it calls a specific handler function or performs an action to update the GUI state.
    - If the `plugin_msg` does not match any known case, it logs an error indicating an unhandled plugin message.
- **Output**: The function does not return a value; it updates the GUI state based on the received plugin message.
- **Functions called**:
    - [`fd_gui_handle_rooted_slot`](#fd_gui_handle_rooted_slot)
    - [`fd_gui_handle_optimistically_confirmed_slot`](#fd_gui_handle_optimistically_confirmed_slot)
    - [`fd_gui_handle_completed_slot`](#fd_gui_handle_completed_slot)
    - [`fd_gui_printf_estimated_slot`](fd_gui_printf.c.driver.md#fd_gui_printf_estimated_slot)
    - [`fd_gui_handle_leader_schedule`](#fd_gui_handle_leader_schedule)
    - [`fd_gui_handle_slot_start`](#fd_gui_handle_slot_start)
    - [`fd_gui_handle_slot_end`](#fd_gui_handle_slot_end)
    - [`fd_gui_handle_gossip_update`](#fd_gui_handle_gossip_update)
    - [`fd_gui_handle_vote_account_update`](#fd_gui_handle_vote_account_update)
    - [`fd_gui_handle_validator_info_update`](#fd_gui_handle_validator_info_update)
    - [`fd_gui_handle_reset_slot`](#fd_gui_handle_reset_slot)
    - [`fd_gui_handle_balance_update`](#fd_gui_handle_balance_update)
    - [`fd_gui_handle_start_progress`](#fd_gui_handle_start_progress)
    - [`fd_gui_handle_genesis_hash`](#fd_gui_handle_genesis_hash)
    - [`fd_gui_handle_block_engine_update`](#fd_gui_handle_block_engine_update)


---
### fd\_gui\_init\_slot\_txns<!-- {{#callable:fd_gui_init_slot_txns}} -->
The `fd_gui_init_slot_txns` function initializes transaction-related data for a specific slot in the GUI system, ensuring the slot is cleared if necessary and setting a reference timestamp if it hasn't been set yet.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure, representing the GUI system containing slots and other related data.
    - `tickcount`: A long integer representing the current tick count, used for timestamp calculations.
    - `_slot`: An unsigned long integer representing the slot number to initialize transactions for.
- **Control Flow**:
    - Retrieve the slot from the GUI's slots array using the modulo operation with `FD_GUI_SLOTS_CNT` to ensure it wraps around correctly.
    - Check if the slot's current slot number does not match the provided `_slot`; if so, call [`fd_gui_clear_slot`](#fd_gui_clear_slot) to reset the slot with `ULONG_MAX` as the parent slot.
    - Check if the slot's transaction reference ticks are set to `LONG_MAX`, indicating they haven't been initialized yet.
    - If the reference ticks are uninitialized, set them to the current `tickcount` and calculate the reference nanoseconds using the current wall clock time and the difference in ticks, adjusted by the tick-to-nanosecond conversion rate.
- **Output**: This function does not return a value; it modifies the state of the `fd_gui_t` structure and its associated slot data in place.
- **Functions called**:
    - [`fd_gui_clear_slot`](#fd_gui_clear_slot)


---
### fd\_gui\_became\_leader<!-- {{#callable:fd_gui_became_leader}} -->
The `fd_gui_became_leader` function initializes and updates the transaction slot information when a GUI becomes the leader for a specific slot.
- **Inputs**:
    - `gui`: A pointer to the `fd_gui_t` structure representing the GUI context.
    - `tickcount`: A long integer representing the current tick count, used for timing reference.
    - `_slot`: An unsigned long integer representing the slot number for which the GUI has become the leader.
    - `start_time_nanos`: A long integer representing the start time in nanoseconds for the leader slot.
    - `end_time_nanos`: A long integer representing the end time in nanoseconds for the leader slot.
    - `max_compute_units`: An unsigned long integer representing the maximum compute units allowed for the slot.
    - `max_microblocks`: An unsigned long integer representing the maximum number of microblocks for the slot.
- **Control Flow**:
    - Call [`fd_gui_init_slot_txns`](#fd_gui_init_slot_txns) to initialize the transaction slot for the given slot number.
    - Retrieve the slot structure from the GUI's slots array using the modulo operation with `FD_GUI_SLOTS_CNT`.
    - Set the `max_compute_units` of the slot to the provided `max_compute_units` value, cast to `uint`.
    - Set the `leader_start_time` and `leader_end_time` of the slot's transactions to `start_time_nanos` and `end_time_nanos`, respectively.
    - If the `microblocks_upper_bound` of the slot's transactions is `USHORT_MAX`, set it to `max_microblocks`, cast to `ushort`.
- **Output**: This function does not return a value; it modifies the state of the `fd_gui_t` structure and its associated slot.
- **Functions called**:
    - [`fd_gui_init_slot_txns`](#fd_gui_init_slot_txns)


---
### fd\_gui\_unbecame\_leader<!-- {{#callable:fd_gui_unbecame_leader}} -->
The `fd_gui_unbecame_leader` function updates the microblocks upper bound for a specific slot in the GUI when a node stops being the leader.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI state.
    - `tickcount`: A long integer representing the current tick count.
    - `_slot`: An unsigned long integer representing the slot number.
    - `microblocks_in_slot`: An unsigned long integer representing the number of microblocks in the slot.
- **Control Flow**:
    - Call [`fd_gui_init_slot_txns`](#fd_gui_init_slot_txns) to initialize the slot transactions for the given slot.
    - Retrieve the slot structure from the GUI's slots array using the modulo operation with `FD_GUI_SLOTS_CNT`.
    - Set the `microblocks_upper_bound` of the slot's transactions to the provided `microblocks_in_slot` value, cast to a `ushort`.
- **Output**: This function does not return a value; it modifies the state of the GUI's slot transactions.
- **Functions called**:
    - [`fd_gui_init_slot_txns`](#fd_gui_init_slot_txns)


---
### fd\_gui\_microblock\_execution\_begin<!-- {{#callable:fd_gui_microblock_execution_begin}} -->
The `fd_gui_microblock_execution_begin` function initializes and processes the execution of a set of transactions within a microblock for a given slot in the GUI system.
- **Inputs**:
    - `gui`: A pointer to the `fd_gui_t` structure representing the GUI context.
    - `tickcount`: A long integer representing the current tick count, used for timing calculations.
    - `_slot`: An unsigned long integer representing the slot number for which the microblock execution is being processed.
    - `txns`: A pointer to an array of `fd_txn_p_t` structures representing the transactions to be processed in the microblock.
    - `txn_cnt`: An unsigned long integer representing the number of transactions in the `txns` array.
    - `microblock_idx`: An unsigned integer representing the index of the microblock within the slot.
    - `pack_txn_idx`: An unsigned long integer representing the starting index of the transactions in the transaction history buffer.
- **Control Flow**:
    - Initialize the slot transactions using [`fd_gui_init_slot_txns`](#fd_gui_init_slot_txns) with the provided `gui`, `tickcount`, and `_slot`.
    - Retrieve the slot structure from the GUI's slots array using the modulo operation with `FD_GUI_SLOTS_CNT`.
    - Check if the slot's transaction start offset is uninitialized (ULONG_MAX) and set it to `pack_txn_idx` if so, otherwise update it to the minimum of the current start offset and `pack_txn_idx`.
    - Update the GUI's `pack_txn_idx` to the maximum of its current value and `pack_txn_idx + txn_cnt - 1`.
    - Iterate over each transaction in the `txns` array, compute the cost estimate and other metrics using `fd_pack_compute_cost`, and update the corresponding transaction entry in the GUI's transaction history buffer.
    - Update the slot's `begin_microblocks` count by adding `txn_cnt` to it.
- **Output**: The function does not return a value; it updates the GUI's internal state and transaction history buffer with the processed transaction data.
- **Functions called**:
    - [`fd_gui_init_slot_txns`](#fd_gui_init_slot_txns)


---
### fd\_gui\_microblock\_execution\_end<!-- {{#callable:fd_gui_microblock_execution_end}} -->
The `fd_gui_microblock_execution_end` function finalizes the execution of a microblock transaction in the GUI, updating transaction details and slot information.
- **Inputs**:
    - `gui`: A pointer to the `fd_gui_t` structure representing the GUI state.
    - `tickcount`: A long integer representing the current tick count, used for timing calculations.
    - `bank_idx`: An unsigned long integer representing the index of the bank processing the transaction.
    - `_slot`: An unsigned long integer representing the slot number associated with the transaction.
    - `txn_cnt`: An unsigned long integer representing the number of transactions in the microblock, expected to be 1.
    - `txns`: A pointer to an array of `fd_txn_p_t` structures representing the transactions being processed.
    - `pack_txn_idx`: An unsigned long integer representing the index of the transaction in the transaction history.
    - `txn_start_pct`: An unsigned char representing the percentage of the transaction start.
    - `txn_load_end_pct`: An unsigned char representing the percentage of the transaction load end.
    - `txn_end_pct`: An unsigned char representing the percentage of the transaction end.
    - `tips`: An unsigned long integer representing the tips associated with the transaction.
- **Control Flow**:
    - Check if `txn_cnt` is not equal to 1 and log an error if so, as the function expects exactly one transaction per microblock.
    - Initialize the slot transactions using [`fd_gui_init_slot_txns`](#fd_gui_init_slot_txns) with the given `gui`, `tickcount`, and `_slot`.
    - Retrieve the slot from the GUI's slots array using the modulo operation with `FD_GUI_SLOTS_CNT`.
    - Update the slot's transaction end offset based on `pack_txn_idx` and `txn_cnt`.
    - Update the GUI's `pack_txn_idx` to the maximum of its current value and `pack_txn_idx + txn_cnt - 1`.
    - Iterate over each transaction in `txns`, updating the corresponding transaction entry in the GUI's transaction history with details such as bank index, consumed compute units, error code, timestamps, percentages, tips, and flags.
    - Increment the slot's `end_microblocks` by the transaction count.
- **Output**: The function does not return a value; it updates the GUI's state and transaction history in place.
- **Functions called**:
    - [`fd_gui_init_slot_txns`](#fd_gui_init_slot_txns)



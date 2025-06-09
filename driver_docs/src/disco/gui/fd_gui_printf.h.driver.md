# Purpose
This C header file defines a collection of function prototypes designed to format and output the current state of a graphical user interface (GUI) as JSON messages. These functions are intended to populate a message buffer with formatted data that can be sent to WebSocket clients, either individually or as a broadcast. The functions cover a wide range of GUI state information, including version details, cluster status, identity keys, uptime, voting states, transaction processing statistics, and peer updates. Additionally, the file includes functions for handling specific queries and requests, such as slot information and transaction details. This header file is part of a larger system that likely involves real-time data visualization or monitoring, where the GUI state needs to be communicated efficiently to connected clients.
# Imports and Dependencies

---
- `fd_gui.h`


# Function Declarations (Public API)

---
### fd\_gui\_printf\_version<!-- {{#callable_declaration:fd_gui_printf_version}} -->
Formats the GUI version information as a JSON message.
- **Description**: This function is used to format the current version information of the GUI into a JSON message, which is then placed into the outgoing message buffer. This message can be sent to a specific WebSocket client or broadcast to all clients. It is typically used when there is a need to communicate the current version of the GUI to connected clients. The function must be called with a valid `fd_gui_t` object that has been properly initialized, as it relies on the version information contained within this object.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure that contains the GUI state, including version information. This parameter must not be null and should be properly initialized before calling the function. The caller retains ownership of this object.
- **Output**: None
- **See also**: [`fd_gui_printf_version`](fd_gui_printf.c.driver.md#fd_gui_printf_version)  (Implementation)


---
### fd\_gui\_printf\_cluster<!-- {{#callable_declaration:fd_gui_printf_cluster}} -->
Formats the current cluster state as a JSON message for the GUI.
- **Description**: This function formats the current state of the cluster as a JSON message and places it into the GUI's outgoing message buffer. It is intended to be used when there is a need to communicate the cluster's state to a WebSocket client, either individually or as part of a broadcast to all clients. The function should be called when the cluster state needs to be updated in the GUI. It assumes that the `fd_gui_t` structure is properly initialized and contains valid data for the cluster summary.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI context. It must not be null and should be properly initialized with valid cluster summary data. The caller retains ownership of this pointer.
- **Output**: None
- **See also**: [`fd_gui_printf_cluster`](fd_gui_printf.c.driver.md#fd_gui_printf_cluster)  (Implementation)


---
### fd\_gui\_printf\_commit\_hash<!-- {{#callable_declaration:fd_gui_printf_commit_hash}} -->
Formats the current commit hash as a JSON message in the GUI's outgoing message buffer.
- **Description**: This function is used to format the current commit hash of the application as a JSON message, which is then placed into the outgoing message buffer of the GUI. This message can be sent to a specific WebSocket client or broadcast to all clients connected to the GUI. It is typically called when there is a need to communicate the current commit hash to the clients, such as for debugging or version tracking purposes. The function must be called with a valid `fd_gui_t` object, which represents the state of the GUI.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI state. This parameter must not be null, as it is used to access the outgoing message buffer where the JSON message will be formatted and stored. The caller retains ownership of this object.
- **Output**: None
- **See also**: [`fd_gui_printf_commit_hash`](fd_gui_printf.c.driver.md#fd_gui_printf_commit_hash)  (Implementation)


---
### fd\_gui\_printf\_identity\_key<!-- {{#callable_declaration:fd_gui_printf_identity_key}} -->
Formats the identity key as a JSON message for the GUI.
- **Description**: This function formats the current identity key of the GUI into a JSON message and places it in the outgoing message buffer. It is intended to be used when there is a need to communicate the identity key to a WebSocket client, either individually or as part of a broadcast to all clients. The function must be called with a valid `fd_gui_t` object that has been properly initialized, as it relies on the `identity_key_base58` field within the `summary` structure of the `fd_gui_t` object. The function does not handle null pointers and assumes that the `gui` parameter is valid.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI state. Must not be null and should be properly initialized before calling this function. The function assumes ownership of the pointer for the duration of the call but does not modify the `gui` object.
- **Output**: None
- **See also**: [`fd_gui_printf_identity_key`](fd_gui_printf.c.driver.md#fd_gui_printf_identity_key)  (Implementation)


---
### fd\_gui\_printf\_uptime\_nanos<!-- {{#callable_declaration:fd_gui_printf_uptime_nanos}} -->
Formats and sends the system uptime in nanoseconds as a JSON message.
- **Description**: This function is used to format the current system uptime, measured in nanoseconds since the GUI's startup, into a JSON message. It is intended to be called when there is a need to report the system's uptime to a WebSocket client or broadcast it to all connected clients. The function must be called with a valid `fd_gui_t` object that has been properly initialized and is ready to send messages. It does not handle invalid or null `fd_gui_t` pointers, so the caller must ensure the parameter is valid.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI context. Must not be null and should be properly initialized before calling this function. The caller retains ownership of this pointer.
- **Output**: None
- **See also**: [`fd_gui_printf_uptime_nanos`](fd_gui_printf.c.driver.md#fd_gui_printf_uptime_nanos)  (Implementation)


---
### fd\_gui\_printf\_vote\_state<!-- {{#callable_declaration:fd_gui_printf_vote_state}} -->
Formats the current vote state of the GUI as a JSON message.
- **Description**: This function is used to format the current vote state of the GUI into a JSON message, which is then placed into the GUI's outgoing message buffer. This message can be sent to a specific WebSocket client or broadcast to all clients. The function must be called with a valid `fd_gui_t` object that has been properly initialized. It handles different vote states by converting them into corresponding string representations. If the vote state is unknown, an error is logged.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI context. This parameter must not be null and should be properly initialized before calling the function. The function will log an error if the vote state within this structure is unknown.
- **Output**: None
- **See also**: [`fd_gui_printf_vote_state`](fd_gui_printf.c.driver.md#fd_gui_printf_vote_state)  (Implementation)


---
### fd\_gui\_printf\_vote\_distance<!-- {{#callable_declaration:fd_gui_printf_vote_distance}} -->
Formats the vote distance as a JSON message for the GUI.
- **Description**: This function is used to format the current vote distance state of the GUI into a JSON message, which is then placed into the GUI's outgoing message buffer. This message can be sent to a specific WebSocket client or broadcast to all clients. It is typically called when there is a need to update clients with the current vote distance information. The function assumes that the GUI has been properly initialized and that the `gui` parameter is valid.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI state. Must not be null. The caller retains ownership of the memory.
- **Output**: None
- **See also**: [`fd_gui_printf_vote_distance`](fd_gui_printf.c.driver.md#fd_gui_printf_vote_distance)  (Implementation)


---
### fd\_gui\_printf\_skipped\_history<!-- {{#callable_declaration:fd_gui_printf_skipped_history}} -->
Formats and sends the skipped history data as a JSON message.
- **Description**: This function is used to format the skipped history of slots in the GUI as a JSON message and send it to the outgoing message buffer. It should be called when there is a need to communicate the history of skipped slots to a WebSocket client. The function iterates over the slots, checking for skipped slots that were mined, and includes them in the JSON array. It is important to ensure that the `fd_gui_t` structure is properly initialized and contains valid slot data before calling this function.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI state. Must not be null and should be properly initialized with valid slot data. The caller retains ownership of this pointer.
- **Output**: None
- **See also**: [`fd_gui_printf_skipped_history`](fd_gui_printf.c.driver.md#fd_gui_printf_skipped_history)  (Implementation)


---
### fd\_gui\_printf\_tps\_history<!-- {{#callable_declaration:fd_gui_printf_tps_history}} -->
Formats the transaction per second (TPS) history as a JSON message.
- **Description**: This function is used to format the TPS history data of the GUI into a JSON message, which can then be sent to WebSocket clients. It should be called when there is a need to broadcast or send the TPS history to clients. The function assumes that the `gui` parameter is properly initialized and contains valid TPS history data. It does not handle null pointers, so the caller must ensure that `gui` is not null before calling this function.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure that contains the GUI state, including TPS history data. Must not be null. The caller retains ownership of this pointer.
- **Output**: None
- **See also**: [`fd_gui_printf_tps_history`](fd_gui_printf.c.driver.md#fd_gui_printf_tps_history)  (Implementation)


---
### fd\_gui\_printf\_startup\_progress<!-- {{#callable_declaration:fd_gui_printf_startup_progress}} -->
Formats and sends the current startup progress state as a JSON message.
- **Description**: This function is used to format the current startup progress state of the GUI into a JSON message, which is then placed into the outgoing message buffer for transmission to WebSocket clients. It should be called whenever there is a need to update clients about the current phase of the startup process. The function handles various phases of startup progress and includes additional details about snapshot downloading and ledger processing when applicable. It is expected that the `gui` parameter is properly initialized and contains valid startup progress information.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI state. Must not be null and should be properly initialized with valid startup progress data. The function will log an error if the startup progress phase is unknown.
- **Output**: None
- **See also**: [`fd_gui_printf_startup_progress`](fd_gui_printf.c.driver.md#fd_gui_printf_startup_progress)  (Implementation)


---
### fd\_gui\_printf\_block\_engine<!-- {{#callable_declaration:fd_gui_printf_block_engine}} -->
Formats the block engine state as a JSON message for the GUI.
- **Description**: This function is used to format the current state of the block engine within the GUI as a JSON message. It should be called when there is a need to update the GUI with the block engine's status, such as its name, URL, IP address, and connection status. The function assumes that the `fd_gui_t` structure is properly initialized and contains valid block engine data. It does not handle null pointers and expects the caller to ensure that the `gui` parameter is not null before calling this function.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI context. Must not be null. The caller retains ownership and is responsible for ensuring the structure is properly initialized with valid block engine data.
- **Output**: None
- **See also**: [`fd_gui_printf_block_engine`](fd_gui_printf.c.driver.md#fd_gui_printf_block_engine)  (Implementation)


---
### fd\_gui\_printf\_tiles<!-- {{#callable_declaration:fd_gui_printf_tiles}} -->
Formats the current state of GUI tiles as a JSON message.
- **Description**: This function formats the current state of the GUI tiles into a JSON message and places it in the GUI's outgoing message buffer. It is used to prepare tile information for transmission to WebSocket clients. The function iterates over all tiles in the GUI's topology, excluding those with names starting with 'bench', and includes their kind and kind_id in the JSON message. This function should be called when the tile state needs to be communicated to clients, ensuring that the GUI structure is properly initialized and populated with tile data before invocation.
- **Inputs**:
    - `gui`: A pointer to an fd_gui_t structure representing the GUI context. Must not be null and should be properly initialized with a valid topology containing tile information. The caller retains ownership.
- **Output**: None
- **See also**: [`fd_gui_printf_tiles`](fd_gui_printf.c.driver.md#fd_gui_printf_tiles)  (Implementation)


---
### fd\_gui\_printf\_identity\_balance<!-- {{#callable_declaration:fd_gui_printf_identity_balance}} -->
Formats the identity account balance as a JSON message.
- **Description**: This function is used to format the current identity account balance of the GUI into a JSON message, which is then placed into the GUI's outgoing message buffer. This message can be sent to a specific WebSocket client or broadcast to all clients. It is typically used when there is a need to communicate the current balance state to connected clients. The function must be called with a valid GUI context that has been properly initialized and contains the necessary balance information.
- **Inputs**:
    - `gui`: A pointer to an fd_gui_t structure representing the GUI context. This must not be null and should be properly initialized with the current state, including the identity account balance. If the pointer is null, the behavior is undefined.
- **Output**: None
- **See also**: [`fd_gui_printf_identity_balance`](fd_gui_printf.c.driver.md#fd_gui_printf_identity_balance)  (Implementation)


---
### fd\_gui\_printf\_vote\_balance<!-- {{#callable_declaration:fd_gui_printf_vote_balance}} -->
Formats the vote account balance as a JSON message for the GUI.
- **Description**: This function is used to format the current vote account balance of the GUI into a JSON message, which is then placed into the GUI's outgoing message buffer. This message can be sent to a specific WebSocket client or broadcast to all clients. It is typically called when there is a need to update clients with the latest vote account balance information. The function assumes that the GUI has been properly initialized and that the `fd_gui_t` structure contains valid data.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI state. Must not be null and should be properly initialized before calling this function. The function reads from this structure to obtain the vote account balance.
- **Output**: None
- **See also**: [`fd_gui_printf_vote_balance`](fd_gui_printf.c.driver.md#fd_gui_printf_vote_balance)  (Implementation)


---
### fd\_gui\_printf\_estimated\_slot\_duration\_nanos<!-- {{#callable_declaration:fd_gui_printf_estimated_slot_duration_nanos}} -->
Formats the estimated slot duration in nanoseconds as a JSON message.
- **Description**: This function is used to format the estimated slot duration, measured in nanoseconds, into a JSON message that is added to the GUI's outgoing message buffer. This message can then be sent to a specific WebSocket client or broadcast to all clients. It is typically called when there is a need to communicate the current estimated slot duration to connected clients. The function assumes that the GUI has been properly initialized and that the 'estimated_slot_duration_nanos' field in the GUI's summary structure contains a valid value.
- **Inputs**:
    - `gui`: A pointer to an fd_gui_t structure representing the GUI context. Must not be null. The caller retains ownership and is responsible for ensuring the GUI is properly initialized before calling this function.
- **Output**: None
- **See also**: [`fd_gui_printf_estimated_slot_duration_nanos`](fd_gui_printf.c.driver.md#fd_gui_printf_estimated_slot_duration_nanos)  (Implementation)


---
### fd\_gui\_printf\_root\_slot<!-- {{#callable_declaration:fd_gui_printf_root_slot}} -->
Formats the current root slot state as a JSON message.
- **Description**: This function is used to format the current state of the root slot in the GUI as a JSON message, which is then placed into the GUI's outgoing message buffer. This message can be sent to a specific WebSocket client or broadcast to all clients. It is typically called when there is a need to update clients with the latest root slot information. The function assumes that the GUI has been properly initialized and that the `gui` parameter is valid.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI state. Must not be null. The caller retains ownership of the memory. If the pointer is invalid, the behavior is undefined.
- **Output**: None
- **See also**: [`fd_gui_printf_root_slot`](fd_gui_printf.c.driver.md#fd_gui_printf_root_slot)  (Implementation)


---
### fd\_gui\_printf\_optimistically\_confirmed\_slot<!-- {{#callable_declaration:fd_gui_printf_optimistically_confirmed_slot}} -->
Formats the optimistically confirmed slot information as a JSON message.
- **Description**: This function is used to format the current state of the optimistically confirmed slot in the GUI as a JSON message. It should be called when there is a need to send or broadcast the optimistically confirmed slot information to WebSocket clients. The function encapsulates the slot information within a JSON envelope, making it ready for transmission. It is expected that the GUI object is properly initialized before calling this function.
- **Inputs**:
    - `gui`: A pointer to an fd_gui_t structure representing the GUI state. Must not be null, and the structure should be properly initialized before use. The function will access the 'summary.slot_optimistically_confirmed' field of this structure.
- **Output**: None
- **See also**: [`fd_gui_printf_optimistically_confirmed_slot`](fd_gui_printf.c.driver.md#fd_gui_printf_optimistically_confirmed_slot)  (Implementation)


---
### fd\_gui\_printf\_completed\_slot<!-- {{#callable_declaration:fd_gui_printf_completed_slot}} -->
Formats and sends a JSON message with the completed slot information.
- **Description**: This function is used to format the current state of the GUI related to the completed slot as a JSON message and place it into the outgoing message buffer. It is intended to be called when there is a need to communicate the completed slot information to a WebSocket client, either individually or as part of a broadcast to all clients. The function must be called with a valid `fd_gui_t` object that has been properly initialized and contains the relevant slot completion data.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure that contains the GUI state information. This parameter must not be null and should be properly initialized before calling the function. The function assumes that `gui->summary.slot_completed` contains valid data to be included in the JSON message.
- **Output**: None
- **See also**: [`fd_gui_printf_completed_slot`](fd_gui_printf.c.driver.md#fd_gui_printf_completed_slot)  (Implementation)


---
### fd\_gui\_printf\_estimated\_slot<!-- {{#callable_declaration:fd_gui_printf_estimated_slot}} -->
Formats the estimated slot information as a JSON message.
- **Description**: This function is used to format the estimated slot information from the GUI state into a JSON message, which is then placed into the GUI's outgoing message buffer. This message can be sent to a specific WebSocket client or broadcast to all clients. It is typically called when there is a need to communicate the current estimated slot value to connected clients. The function assumes that the GUI has been properly initialized and that the `gui` parameter is valid.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the current state of the GUI. Must not be null. The caller retains ownership of this pointer, and it is expected to be valid for the duration of the function call.
- **Output**: None
- **See also**: [`fd_gui_printf_estimated_slot`](fd_gui_printf.c.driver.md#fd_gui_printf_estimated_slot)  (Implementation)


---
### fd\_gui\_printf\_estimated\_tps<!-- {{#callable_declaration:fd_gui_printf_estimated_tps}} -->
Formats the estimated transactions per second (TPS) data as a JSON message.
- **Description**: This function is used to format the estimated transactions per second (TPS) data from the GUI's history into a JSON message, which can then be sent to a WebSocket client or broadcast to all clients. It should be called when there is a need to communicate the current estimated TPS metrics, including total, vote, non-vote success, and non-vote failed TPS, to the clients. The function assumes that the GUI structure is properly initialized and contains valid TPS history data.
- **Inputs**:
    - `gui`: A pointer to an fd_gui_t structure representing the GUI context. Must not be null and should be properly initialized with valid TPS history data.
- **Output**: None
- **See also**: [`fd_gui_printf_estimated_tps`](fd_gui_printf.c.driver.md#fd_gui_printf_estimated_tps)  (Implementation)


---
### fd\_gui\_printf\_null\_query\_response<!-- {{#callable_declaration:fd_gui_printf_null_query_response}} -->
Formats a null query response as a JSON message in the GUI's outgoing message buffer.
- **Description**: This function is used to format a null query response for a specific topic and key, associating it with a given identifier. It is intended to be used when a query results in no data, and a null response needs to be communicated to the client. The function must be called with a valid GUI context, and it will format the response as a JSON message, which can then be sent to a WebSocket client. This function does not handle invalid input values explicitly, so it is the caller's responsibility to ensure that the inputs are valid.
- **Inputs**:
    - `gui`: A pointer to an fd_gui_t structure representing the GUI context. Must not be null, and the caller retains ownership.
    - `topic`: A constant character pointer representing the topic of the query. Must not be null, and the caller retains ownership.
    - `key`: A constant character pointer representing the key of the query. Must not be null, and the caller retains ownership.
    - `id`: An unsigned long integer representing the identifier for the query response. It should be a valid identifier within the context of the application.
- **Output**: None
- **See also**: [`fd_gui_printf_null_query_response`](fd_gui_printf.c.driver.md#fd_gui_printf_null_query_response)  (Implementation)


---
### fd\_gui\_printf\_skip\_rate<!-- {{#callable_declaration:fd_gui_printf_skip_rate}} -->
Formats and sends the skip rate for a specific epoch as a JSON message.
- **Description**: This function is used to format the skip rate of a specified epoch into a JSON message and send it through the GUI's outgoing message buffer. It is typically called when there is a need to report the skip rate for a particular epoch to a WebSocket client. The function requires a valid GUI context and an epoch index to identify which epoch's skip rate to report. It handles cases where the total slots for the epoch are zero by reporting a skip rate of 0.0.
- **Inputs**:
    - `gui`: A pointer to an fd_gui_t structure representing the GUI context. Must not be null, as it is used to access the outgoing message buffer and epoch data.
    - `epoch_idx`: An unsigned long integer representing the index of the epoch for which the skip rate is to be reported. It should be within the valid range of epochs available in the GUI context.
- **Output**: None
- **See also**: [`fd_gui_printf_skip_rate`](fd_gui_printf.c.driver.md#fd_gui_printf_skip_rate)  (Implementation)


---
### fd\_gui\_printf\_epoch<!-- {{#callable_declaration:fd_gui_printf_epoch}} -->
Formats and sends epoch data as a JSON message to the GUI's outgoing message buffer.
- **Description**: This function is used to format the details of a specific epoch, identified by its index, into a JSON message and place it in the GUI's outgoing message buffer. This message can then be sent to a WebSocket client or broadcast to all clients. It includes information such as the epoch number, start and end times, start and end slots, excluded stake, and lists of staked public keys, staked lamports, and leader slots. The function should be called when there is a need to update the GUI with the latest epoch data. It assumes that the `gui` object is properly initialized and that `epoch_idx` is a valid index within the bounds of the epoch data stored in `gui`.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI context. Must not be null and should be properly initialized before calling this function. The function assumes ownership of this pointer for the duration of the call.
    - `epoch_idx`: An unsigned long integer representing the index of the epoch to be formatted. It must be a valid index within the bounds of the epoch data available in the `gui` structure. If the index is out of bounds, the behavior is undefined.
- **Output**: None
- **See also**: [`fd_gui_printf_epoch`](fd_gui_printf.c.driver.md#fd_gui_printf_epoch)  (Implementation)


---
### fd\_gui\_printf\_peers\_gossip\_update<!-- {{#callable_declaration:fd_gui_printf_peers_gossip_update}} -->
Formats and sends a JSON message to update the GUI with peer gossip changes.
- **Description**: This function is used to update the GUI with changes in peer gossip information by formatting the changes into a JSON message and sending it to the GUI's outgoing message buffer. It should be called whenever there is a need to reflect updates, additions, or removals of peers in the GUI. The function requires valid input arrays for updated, removed, and added peers, along with their respective counts. It assumes that the GUI has been properly initialized and is ready to handle outgoing messages.
- **Inputs**:
    - `gui`: A pointer to an fd_gui_t structure representing the GUI context. Must not be null, and the GUI should be initialized before calling this function.
    - `updated`: A pointer to an array of ulong values representing the indices of peers that have been updated. The array must be valid and non-null if updated_cnt is greater than zero.
    - `updated_cnt`: The number of peers that have been updated. Must be zero or a positive number.
    - `removed`: A pointer to an array of fd_pubkey_t structures representing the public keys of peers that have been removed. The array must be valid and non-null if removed_cnt is greater than zero.
    - `removed_cnt`: The number of peers that have been removed. Must be zero or a positive number.
    - `added`: A pointer to an array of ulong values representing the indices of peers that have been added. The array must be valid and non-null if added_cnt is greater than zero.
    - `added_cnt`: The number of peers that have been added. Must be zero or a positive number.
- **Output**: None
- **See also**: [`fd_gui_printf_peers_gossip_update`](fd_gui_printf.c.driver.md#fd_gui_printf_peers_gossip_update)  (Implementation)


---
### fd\_gui\_printf\_peers\_vote\_account\_update<!-- {{#callable_declaration:fd_gui_printf_peers_vote_account_update}} -->
Formats and updates the GUI with changes to vote account peers.
- **Description**: This function is used to update the GUI with the current state of vote account peers by formatting the changes into JSON messages. It should be called whenever there are updates, additions, or removals of vote account peers to ensure the GUI reflects the latest state. The function requires a valid GUI context and lists of updated, removed, and added peers. It handles the formatting of these changes into the outgoing message buffer, which can then be sent to clients. The function assumes that the provided lists accurately represent the changes to be made.
- **Inputs**:
    - `gui`: A pointer to an fd_gui_t structure representing the GUI context. Must not be null.
    - `updated`: A pointer to an array of ulong indices representing peers that have been updated. The array must have at least updated_cnt elements.
    - `updated_cnt`: The number of elements in the updated array. Must be non-negative.
    - `removed`: A pointer to an array of fd_pubkey_t structures representing peers that have been removed. The array must have at least removed_cnt elements.
    - `removed_cnt`: The number of elements in the removed array. Must be non-negative.
    - `added`: A pointer to an array of ulong indices representing peers that have been added. The array must have at least added_cnt elements.
    - `added_cnt`: The number of elements in the added array. Must be non-negative.
- **Output**: None
- **See also**: [`fd_gui_printf_peers_vote_account_update`](fd_gui_printf.c.driver.md#fd_gui_printf_peers_vote_account_update)  (Implementation)


---
### fd\_gui\_printf\_peers\_validator\_info\_update<!-- {{#callable_declaration:fd_gui_printf_peers_validator_info_update}} -->
Updates the GUI with changes to validator peer information.
- **Description**: This function is used to update the GUI with information about changes to validator peers, including additions, updates, and removals. It should be called whenever there is a change in the validator peer set that needs to be reflected in the GUI. The function formats these changes into JSON messages and places them in the outgoing message buffer for transmission to WebSocket clients. It is important to ensure that the `gui` parameter is properly initialized before calling this function.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI context. Must not be null, and must be properly initialized before use. The caller retains ownership.
    - `updated`: A pointer to an array of `ulong` indices representing the validators that have been updated. The array must have at least `updated_cnt` elements. The caller retains ownership.
    - `updated_cnt`: The number of elements in the `updated` array. Must be non-negative.
    - `removed`: A pointer to an array of `fd_pubkey_t` structures representing the validators that have been removed. The array must have at least `removed_cnt` elements. The caller retains ownership.
    - `removed_cnt`: The number of elements in the `removed` array. Must be non-negative.
    - `added`: A pointer to an array of `ulong` indices representing the validators that have been added. The array must have at least `added_cnt` elements. The caller retains ownership.
    - `added_cnt`: The number of elements in the `added` array. Must be non-negative.
- **Output**: None
- **See also**: [`fd_gui_printf_peers_validator_info_update`](fd_gui_printf.c.driver.md#fd_gui_printf_peers_validator_info_update)  (Implementation)


---
### fd\_gui\_printf\_peers\_all<!-- {{#callable_declaration:fd_gui_printf_peers_all}} -->
Formats and sends a JSON message containing all peer information to the GUI's outgoing message buffer.
- **Description**: This function is used to format the current state of all peers in the GUI as a JSON message and place it into the outgoing message buffer. It should be called when there is a need to broadcast the complete list of peers, including gossip peers, vote accounts, and validator information, to all connected clients. The function assumes that the `fd_gui_t` structure is properly initialized and contains valid peer data. It does not handle invalid or null `fd_gui_t` pointers, so the caller must ensure the input is valid.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure containing the GUI state, including peer information. Must not be null, and the structure should be properly initialized with valid data.
- **Output**: None
- **See also**: [`fd_gui_printf_peers_all`](fd_gui_printf.c.driver.md#fd_gui_printf_peers_all)  (Implementation)


---
### fd\_gui\_printf\_slot<!-- {{#callable_declaration:fd_gui_printf_slot}} -->
Formats and sends a JSON message with the current state of a specified slot.
- **Description**: This function is used to format the current state of a specified slot in the GUI as a JSON message and send it to the outgoing message buffer. It is typically called when there is a need to update clients with the latest information about a particular slot. The function handles various slot attributes, such as completion status, transaction counts, and fees, and includes them in the JSON message. It is important to ensure that the `gui` parameter is properly initialized and that the `_slot` index is within the valid range of slots managed by the GUI.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI context. Must not be null, and the GUI must be properly initialized before calling this function. The caller retains ownership.
    - `_slot`: An unsigned long integer representing the index of the slot to be formatted and sent. The index should be within the valid range of slots managed by the GUI. If the index is out of range, it will be wrapped using modulo operation with `FD_GUI_SLOTS_CNT`.
- **Output**: None
- **See also**: [`fd_gui_printf_slot`](fd_gui_printf.c.driver.md#fd_gui_printf_slot)  (Implementation)


---
### fd\_gui\_printf\_summary\_ping<!-- {{#callable_declaration:fd_gui_printf_summary_ping}} -->
Formats a summary ping message as a JSON object in the GUI's outgoing message buffer.
- **Description**: This function is used to create a JSON-formatted summary ping message that is added to the GUI's outgoing message buffer. It is typically used to communicate a ping event to WebSocket clients connected to the GUI. The function must be called with a valid GUI context, and it formats the message with the specified identifier. This function does not handle invalid GUI contexts or identifiers, so it is the caller's responsibility to ensure that the inputs are valid before calling this function.
- **Inputs**:
    - `gui`: A pointer to an fd_gui_t structure representing the GUI context. Must not be null, and the caller retains ownership.
    - `id`: An unsigned long integer representing the identifier for the ping message. There are no specific constraints on the value, but it should be meaningful within the context of the application.
- **Output**: None
- **See also**: [`fd_gui_printf_summary_ping`](fd_gui_printf.c.driver.md#fd_gui_printf_summary_ping)  (Implementation)


---
### fd\_gui\_printf\_slot\_request<!-- {{#callable_declaration:fd_gui_printf_slot_request}} -->
Formats and sends a JSON message about a specific slot to the GUI's outgoing message buffer.
- **Description**: This function is used to format the current state of a specific slot in the GUI as a JSON message, which is then placed into the GUI's outgoing message buffer. This message can be sent to a specific WebSocket client or broadcast to all clients. It should be called when there is a need to query and communicate the status of a slot, including its level, completion time, transaction counts, and other relevant metrics. The function handles edge cases such as invalid slot indices by using modulo arithmetic to ensure valid access within the slot array.
- **Inputs**:
    - `gui`: A pointer to an fd_gui_t structure representing the GUI context. Must not be null, and the caller retains ownership.
    - `slot`: An unsigned long representing the index of the slot to query. The value is wrapped using modulo arithmetic to ensure it is within the valid range of slots.
    - `id`: An unsigned long representing the identifier for the query. This is used to track the request and must be a valid identifier.
- **Output**: None
- **See also**: [`fd_gui_printf_slot_request`](fd_gui_printf.c.driver.md#fd_gui_printf_slot_request)  (Implementation)


---
### fd\_gui\_printf\_slot\_request\_detailed<!-- {{#callable_declaration:fd_gui_printf_slot_request_detailed}} -->
Formats detailed slot information as a JSON message for the GUI.
- **Description**: This function is used to format detailed information about a specific slot into a JSON message, which is then placed into the GUI's outgoing message buffer. This message can be sent to a specific WebSocket client or broadcast to all clients. It should be called when detailed slot information is required, such as during a slot query. The function assumes that the GUI has been properly initialized and that the slot index is valid within the context of the GUI's slot array.
- **Inputs**:
    - `gui`: A pointer to an fd_gui_t structure representing the GUI context. Must not be null, and the GUI must be properly initialized before calling this function. The caller retains ownership.
    - `slot`: An unsigned long integer representing the slot index for which detailed information is requested. It should be within the valid range of slots managed by the GUI.
    - `id`: An unsigned long integer representing the unique identifier for the request. This is used to correlate responses with requests.
- **Output**: None
- **See also**: [`fd_gui_printf_slot_request_detailed`](fd_gui_printf.c.driver.md#fd_gui_printf_slot_request_detailed)  (Implementation)


---
### fd\_gui\_printf\_slot\_transactions\_request<!-- {{#callable_declaration:fd_gui_printf_slot_transactions_request}} -->
Formats and sends a JSON message with transaction details for a specified slot.
- **Description**: This function is used to format and send a JSON message containing detailed transaction information for a specified slot in the GUI. It should be called when transaction details for a particular slot need to be queried and communicated to clients. The function assumes that the GUI has been properly initialized and that the slot index is valid. It handles edge cases by providing null values for transaction details that are unavailable or exceed certain limits. The function does not modify the input parameters but writes the formatted JSON message to the GUI's outgoing message buffer.
- **Inputs**:
    - `gui`: A pointer to an fd_gui_t structure representing the GUI context. Must not be null, and the GUI should be properly initialized before calling this function. The caller retains ownership.
    - `_slot`: An unsigned long integer representing the slot index for which transaction details are requested. The value is used modulo the number of slots in the GUI, so it should be within the valid range of slot indices.
    - `id`: An unsigned long integer representing the unique identifier for the request. This ID is included in the JSON message to correlate responses with requests.
- **Output**: None
- **See also**: [`fd_gui_printf_slot_transactions_request`](fd_gui_printf.c.driver.md#fd_gui_printf_slot_transactions_request)  (Implementation)


---
### fd\_gui\_printf\_live\_tile\_timers<!-- {{#callable_declaration:fd_gui_printf_live_tile_timers}} -->
Formats and sends the current live tile timers as a JSON message.
- **Description**: This function is used to format the current state of live tile timers in the GUI as a JSON message, which is then placed into the outgoing message buffer. This message can be sent to a specific WebSocket client or broadcast to all clients. It should be called when there is a need to update clients with the latest live tile timer information. The function assumes that the GUI has been properly initialized and that the `fd_gui_t` structure is correctly populated with the necessary tile timer snapshots.
- **Inputs**:
    - `gui`: A pointer to an `fd_gui_t` structure representing the GUI state. Must not be null and should be properly initialized with valid tile timer snapshot data.
- **Output**: None
- **See also**: [`fd_gui_printf_live_tile_timers`](fd_gui_printf.c.driver.md#fd_gui_printf_live_tile_timers)  (Implementation)


---
### fd\_gui\_printf\_live\_txn\_waterfall<!-- {{#callable_declaration:fd_gui_printf_live_txn_waterfall}} -->
Formats and sends a live transaction waterfall summary as a JSON message.
- **Description**: This function is used to format the current and previous transaction waterfall states into a JSON message and send it to the GUI's outgoing message buffer. It is typically called when there is a need to update the GUI with the latest transaction waterfall data, including the next leader slot information. The function must be called with valid pointers to the GUI context and transaction waterfall states. It is important to ensure that the GUI has been properly initialized before calling this function to avoid undefined behavior.
- **Inputs**:
    - `gui`: A pointer to an fd_gui_t structure representing the GUI context. Must not be null, and the GUI must be initialized before use. The caller retains ownership.
    - `prev`: A pointer to a constant fd_gui_txn_waterfall_t structure representing the previous transaction waterfall state. Must not be null. The caller retains ownership.
    - `cur`: A pointer to a constant fd_gui_txn_waterfall_t structure representing the current transaction waterfall state. Must not be null. The caller retains ownership.
    - `next_leader_slot`: An unsigned long integer representing the next leader slot. It should be a valid slot number.
- **Output**: None
- **See also**: [`fd_gui_printf_live_txn_waterfall`](fd_gui_printf.c.driver.md#fd_gui_printf_live_txn_waterfall)  (Implementation)


---
### fd\_gui\_printf\_live\_tile\_stats<!-- {{#callable_declaration:fd_gui_printf_live_tile_stats}} -->
Formats and sends live tile statistics as a JSON message.
- **Description**: This function is used to format the current and previous live tile statistics into a JSON message and send it to the GUI's outgoing message buffer. It is typically called when there is a need to update the GUI with the latest tile statistics, ensuring that the display reflects the most recent data. The function requires valid pointers to the GUI context and the tile statistics structures. It assumes that the GUI has been properly initialized and is ready to send messages. The function does not handle null pointers, so the caller must ensure that all inputs are valid.
- **Inputs**:
    - `gui`: A pointer to an fd_gui_t structure representing the GUI context. Must not be null. The caller retains ownership.
    - `prev`: A pointer to a constant fd_gui_tile_stats_t structure representing the previous tile statistics. Must not be null. The caller retains ownership.
    - `cur`: A pointer to a constant fd_gui_tile_stats_t structure representing the current tile statistics. Must not be null. The caller retains ownership.
- **Output**: None
- **See also**: [`fd_gui_printf_live_tile_stats`](fd_gui_printf.c.driver.md#fd_gui_printf_live_tile_stats)  (Implementation)



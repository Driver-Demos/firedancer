# Purpose
The provided C source code file is part of a larger system that manages a restart process in a distributed environment, likely related to a blockchain or consensus mechanism. The file defines several functions that handle the initialization, management, and verification of a "restart" process, which involves determining the heaviest fork in a blockchain-like structure. This is achieved by processing gossip messages, calculating stakes, and verifying fork slots. The code is structured to handle various stages of the restart process, including initializing memory, receiving and processing gossip messages, finding the heaviest fork, and verifying the fork's integrity.

Key components of the code include functions for initializing restart structures ([`fd_restart_new`](#fd_restart_new), [`fd_restart_init`](#fd_restart_init)), processing gossip messages ([`fd_restart_recv_gossip_msg`](#fd_restart_recv_gossip_msg)), and verifying the heaviest fork ([`fd_restart_verify_heaviest_fork`](#fd_restart_verify_heaviest_fork)). The code also includes utility functions for converting between different data formats, such as run-length encoding and raw bitmaps. The file imports several headers, indicating its reliance on external modules for functionality related to stakes, snapshots, and system variables. The code is designed to be integrated into a larger system, as it does not define a `main` function and instead provides functionality that can be called by other parts of the system.
# Imports and Dependencies

---
- `fd_restart.h`
- `../../flamenco/stakes/fd_stakes.h`
- `../../flamenco/snapshot/fd_snapshot_create.h`
- `../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h`
- `sys/types.h`
- `unistd.h`


# Functions

---
### fd\_restart\_new<!-- {{#callable:fd_restart_new}} -->
The `fd_restart_new` function initializes a memory region for a restart operation by zeroing it out, ensuring it is non-null and properly aligned.
- **Inputs**:
    - `mem`: A pointer to the memory region to be initialized for the restart operation.
- **Control Flow**:
    - Check if the `mem` pointer is NULL; if so, log a warning and return NULL.
    - Check if the `mem` pointer is aligned according to [`fd_restart_align`](fd_restart.h.driver.md#fd_restart_align); if not, log a warning and return NULL.
    - Use `fd_memset` to zero out the memory region with a size defined by [`fd_restart_footprint`](fd_restart.h.driver.md#fd_restart_footprint).
    - Return the `mem` pointer.
- **Output**: Returns the initialized memory pointer if successful, or NULL if the input was NULL or misaligned.
- **Functions called**:
    - [`fd_restart_align`](fd_restart.h.driver.md#fd_restart_align)
    - [`fd_restart_footprint`](fd_restart.h.driver.md#fd_restart_footprint)


---
### fd\_restart\_join<!-- {{#callable:fd_restart_join}} -->
The `fd_restart_join` function validates the alignment of a memory address and returns it as a `fd_restart_t` pointer if valid.
- **Inputs**:
    - `restart`: A pointer to a memory location that is expected to be aligned and represent a `fd_restart_t` structure.
- **Control Flow**:
    - Check if the `restart` pointer is NULL; if so, log a warning and return NULL.
    - Check if the `restart` pointer is aligned according to [`fd_restart_align`](fd_restart.h.driver.md#fd_restart_align); if not, log a warning and return NULL.
    - Cast the `restart` pointer to a `fd_restart_t` pointer and return it.
- **Output**: A pointer to `fd_restart_t` if the input is valid and aligned, otherwise NULL.
- **Functions called**:
    - [`fd_restart_align`](fd_restart.h.driver.md#fd_restart_align)


---
### fd\_restart\_recv\_enough\_stake<!-- {{#callable:fd_restart_recv_enough_stake}} -->
The function `fd_restart_recv_enough_stake` checks if the received and voted stake percentages meet the required thresholds for a restart process.
- **Inputs**:
    - `restart`: A pointer to an `fd_restart_t` structure containing information about the current restart process, including total stake and received stake data for different epochs.
- **Control Flow**:
    - Initialize arrays `received` and `voted` to store the percentage of stake received and voted for each epoch, calculated as a percentage of the total stake.
    - Iterate over each epoch, logging the percentage of stake received and voted for each epoch.
    - Set `min_active_stake` to the percentage of stake received in the first epoch.
    - Check if the voted percentage in the second epoch is greater than or equal to a predefined threshold (`FD_RESTART_WAIT_FOR_NEXT_EPOCH_THRESHOLD_PERCENT`).
    - If the condition is met, update `min_active_stake` to the minimum of its current value and the percentage of stake received in the second epoch.
    - Return whether `min_active_stake` is greater than or equal to another predefined threshold (`FD_RESTART_WAIT_FOR_SUPERMAJORITY_THRESHOLD_PERCENT`).
- **Output**: Returns an integer indicating whether the minimum active stake percentage is sufficient to meet the supermajority threshold, which is used to determine if the restart process can proceed.


---
### fd\_restart\_recv\_last\_voted\_fork\_slots<!-- {{#callable:fd_restart_recv_last_voted_fork_slots}} -->
The function `fd_restart_recv_last_voted_fork_slots` processes a message containing the last voted fork slots from a validator, updating the restart state to find the heaviest fork slot if enough stake is received.
- **Inputs**:
    - `restart`: A pointer to an `fd_restart_t` structure representing the current restart state.
    - `msg`: A pointer to an `fd_gossip_restart_last_voted_fork_slots_t` structure containing the message with the last voted fork slots from a validator.
    - `out_heaviest_fork_found`: A pointer to an `ulong` that will be set to 1 if the heaviest fork slot is found.
- **Control Flow**:
    - Check if the current stage is `FD_RESTART_STAGE_FIND_HEAVIEST_FORK_SLOT_NUM`; if not, return immediately.
    - Convert the last voted slot to an epoch and check if it is within the valid range of the root epoch; if not, log a warning and return.
    - Check if the last voted slot is within the valid range of the funk root; if not, log a warning and return.
    - Iterate over the stake weights to find the message sender and update the stake received for the epochs.
    - If no stake is received, log a warning and return.
    - Decode the bitmap in the message and aggregate the validator's stake into `slot_to_stake` for each slot indicated by the bitmap.
    - Check if enough stake has been received using [`fd_restart_recv_enough_stake`](#fd_restart_recv_enough_stake); if so, calculate the stake threshold and find the heaviest fork slot.
    - If the heaviest fork slot is found, update the `out_heaviest_fork_found` to 1 and change the stage to `FD_RESTART_STAGE_FIND_HEAVIEST_FORK_BANK_HASH`.
- **Output**: The function does not return a value but updates the `out_heaviest_fork_found` to 1 if the heaviest fork slot is found.
- **Functions called**:
    - [`fd_restart_recv_enough_stake`](#fd_restart_recv_enough_stake)


---
### fd\_restart\_recv\_heaviest\_fork<!-- {{#callable:fd_restart_recv_heaviest_fork}} -->
The function `fd_restart_recv_heaviest_fork` processes a 'restart_heaviest_fork' message to update the heaviest fork information if the message is from the coordinator.
- **Inputs**:
    - `restart`: A pointer to an `fd_restart_t` structure that holds the state of the restart process.
    - `msg`: A pointer to an `fd_gossip_restart_heaviest_fork_t` structure containing the message data, including the sender's public key, the last slot, and the last slot hash.
- **Control Flow**:
    - The function checks if the message is from the coordinator by comparing the public key in the message with the coordinator's public key stored in the `restart` structure.
    - If the message is from the coordinator, it logs a warning message with the slot and hash information, updates the `restart` structure with the last slot and hash from the message, and sets the `coordinator_heaviest_fork_ready` flag to 1.
    - If the message is not from the coordinator, it logs a warning message indicating that the message was ignored.
- **Output**: The function does not return a value; it updates the `restart` structure in place.


---
### fd\_restart\_recv\_gossip\_msg<!-- {{#callable:fd_restart_recv_gossip_msg}} -->
The `fd_restart_recv_gossip_msg` function processes incoming gossip messages to update the restart state based on the type of message received.
- **Inputs**:
    - `restart`: A pointer to an `fd_restart_t` structure representing the current restart state.
    - `gossip_msg`: A pointer to the incoming gossip message data.
    - `out_heaviest_fork_found`: A pointer to an `ulong` where the function will store whether the heaviest fork was found (1 if found, 0 otherwise).
- **Control Flow**:
    - The function begins by casting the `gossip_msg` to a `uchar` pointer and loading a `uint` discriminant from it to determine the type of message.
    - If the discriminant matches `fd_crds_data_enum_restart_heaviest_fork`, it processes the message as a heaviest fork message by calling [`fd_restart_recv_heaviest_fork`](#fd_restart_recv_heaviest_fork).
    - If the discriminant matches `fd_crds_data_enum_restart_last_voted_fork_slots`, it processes the message as a last voted fork slots message by adjusting the message's bitmap pointer and calling [`fd_restart_recv_last_voted_fork_slots`](#fd_restart_recv_last_voted_fork_slots).
- **Output**: The function does not return a value but updates the `restart` state and sets `out_heaviest_fork_found` to indicate if the heaviest fork was found.
- **Functions called**:
    - [`fd_restart_recv_heaviest_fork`](#fd_restart_recv_heaviest_fork)
    - [`fd_restart_recv_last_voted_fork_slots`](#fd_restart_recv_last_voted_fork_slots)


---
### fd\_restart\_find\_heaviest\_fork\_bank\_hash<!-- {{#callable:fd_restart_find_heaviest_fork_bank_hash}} -->
The function `fd_restart_find_heaviest_fork_bank_hash` determines the heaviest fork bank hash and whether a repair is needed based on the current state of the restart and funk structures.
- **Inputs**:
    - `restart`: A pointer to an `fd_restart_t` structure, which contains information about the current restart state, including the heaviest fork slot and root bank hash.
    - `funk`: A pointer to an `fd_funk_t` structure, which is used to manage transactions and their states.
    - `out_need_repair`: A pointer to an unsigned long where the function will store whether a repair is needed (1) or not (0).
- **Control Flow**:
    - Check if `restart->heaviest_fork_slot` is less than `restart->funk_root`; if true, log an error and halt the process.
    - If `restart->heaviest_fork_slot` equals `restart->funk_root`, log a notice, set `restart->heaviest_fork_bank_hash` to `restart->root_bank_hash`, mark the heaviest fork as ready, and set `*out_need_repair` to 0.
    - If neither of the above conditions is met, start a write transaction on `funk`, cancel all in-preparation transactions, end the write transaction, and set `*out_need_repair` to 1.
- **Output**: The function does not return a value but modifies the `out_need_repair` to indicate if a repair is needed and updates the `restart` structure's state.


---
### fd\_restart\_verify\_heaviest\_fork<!-- {{#callable:fd_restart_verify_heaviest_fork}} -->
The `fd_restart_verify_heaviest_fork` function verifies the heaviest fork in a restart process and prepares a message for gossip if conditions are met.
- **Inputs**:
    - `restart`: A pointer to an `fd_restart_t` structure representing the current restart state.
    - `is_constipated`: A pointer to an `ulong` that indicates whether the system is constipated.
    - `hard_forks`: A pointer to an array of `fd_slot_pair_t` representing hard fork slots.
    - `hard_forks_len`: The length of the `hard_forks` array.
    - `genesis_hash`: A pointer to an `fd_hash_t` representing the genesis hash.
    - `out_buf`: A pointer to an `uchar` buffer where the output message will be stored.
    - `out_send`: A pointer to an `ulong` that will be set to 1 if a message should be sent, otherwise 0.
- **Control Flow**:
    - Initialize `out_send` to 0.
    - Check if the current stage of the restart is `FD_RESTART_STAGE_FIND_HEAVIEST_FORK_BANK_HASH`; if not, return immediately.
    - If the heaviest fork is ready, check if the current node is the coordinator or if the coordinator's message has been received.
    - If the current node is the coordinator, set `out_send` to 1.
    - If the coordinator's message has been received, verify that the heaviest fork slot and bank hash match those of the coordinator; if they do, set `out_send` to 1.
    - If `out_send` is set, prepare a gossip message with the heaviest fork information, update the restart stage to `FD_RESTART_STAGE_GENERATE_SNAPSHOT`, and update the sequence number.
    - Calculate a new shred version by hashing the genesis hash and hard fork slots, then log a warning with the new shred version.
    - Set the restart stage to `FD_RESTART_STAGE_DONE`.
- **Output**: The function outputs a message in `out_buf` if `out_send` is set to 1, indicating that a gossip message should be sent.


---
### fd\_restart\_convert\_runlength\_to\_raw\_bitmap<!-- {{#callable:fd_restart_convert_runlength_to_raw_bitmap}} -->
The function `fd_restart_convert_runlength_to_raw_bitmap` converts a run-length encoded bitmap from a message into a raw bitmap format and updates the message metadata accordingly.
- **Inputs**:
    - `msg`: A pointer to a `fd_gossip_restart_last_voted_fork_slots_t` structure containing the run-length encoded bitmap data.
    - `out_bitmap`: A pointer to an `uchar` array where the raw bitmap will be stored.
    - `out_bitmap_len`: A pointer to an `ulong` where the length of the raw bitmap will be stored.
- **Control Flow**:
    - Initialize `bit_cnt` to 0 and set `*out_bitmap_len` to 0.
    - Clear the `out_bitmap` array using `fd_memset` to ensure it starts empty.
    - Iterate over the run-length encoded offsets in `msg` using a loop with index `i`.
    - For each offset, retrieve the count of bits (`cnt`) and check if the current bit (`bit`) is set.
    - If `bit` is set, iterate over the positions from `bit_cnt` to `bit_cnt + cnt` and set the corresponding bits in `out_bitmap`.
    - Check for potential buffer overflow by ensuring the position does not exceed `FD_RESTART_RAW_BITMAP_BYTES_MAX`. If it does, set `*out_bitmap_len` to `FD_RESTART_RAW_BITMAP_BYTES_MAX + 1` and return.
    - Toggle the `bit` value for the next iteration and update `bit_cnt` by adding `cnt`.
    - Update `*out_bitmap_len` to reflect the current length of the bitmap.
    - Update the `msg` structure to indicate that the offsets are now in raw format, setting the appropriate fields in `msg->offsets`.
- **Output**: The function outputs a raw bitmap in `out_bitmap` and its length in `out_bitmap_len`, and updates the `msg` structure to reflect the conversion from run-length encoding to raw bitmap.


---
### fd\_restart\_convert\_raw\_bitmap\_to\_runlength<!-- {{#callable:fd_restart_convert_raw_bitmap_to_runlength}} -->
The function `fd_restart_convert_raw_bitmap_to_runlength` converts a raw bitmap representation of fork slots into a run-length encoding format.
- **Inputs**:
    - `msg`: A pointer to a `fd_gossip_restart_last_voted_fork_slots_t` structure containing the raw bitmap data to be converted.
    - `out_encoding`: A pointer to an array of `fd_restart_run_length_encoding_inner_t` structures where the run-length encoded data will be stored.
- **Control Flow**:
    - Initialize `cnt` to 0, `last_bit` to 1, and `offsets_len` to 0.
    - Iterate over each bit in the raw bitmap using `raw_bitmap_iter`.
    - For each bit, calculate its index `idx` and offset `off` within the byte.
    - Extract the bit value using `fd_uchar_extract_bit`.
    - If the current bit is the same as `last_bit`, increment `cnt`.
    - If the current bit differs from `last_bit`, store `cnt` in `out_encoding` at `offsets_len`, reset `cnt` to 1, and update `last_bit` to the current bit.
    - After the loop, store the final `cnt` in `out_encoding` at `offsets_len`.
    - Update the `msg` structure to indicate that the offsets are now in run-length encoding format.
- **Output**: The function does not return a value, but it modifies the `out_encoding` array to contain the run-length encoded data and updates the `msg` structure to reflect the new encoding format.


---
### fd\_restart\_init<!-- {{#callable:fd_restart_init}} -->
The `fd_restart_init` function initializes a `fd_restart_t` structure with various parameters and prepares it for processing restart logic in a distributed system.
- **Inputs**:
    - `restart`: A pointer to a `fd_restart_t` structure that will be initialized.
    - `funk_root`: An unsigned long integer representing the root slot number for the restart process.
    - `root_bank_hash`: A pointer to an `fd_hash_t` structure containing the hash of the root bank.
    - `epoch_stakes`: A pointer to an array of pointers to `fd_vote_accounts_t` structures representing the vote accounts for each epoch.
    - `epoch_schedule`: A pointer to an `fd_epoch_schedule_t` structure that defines the epoch schedule.
    - `tower_checkpt_fileno`: An integer file descriptor for the tower checkpoint file.
    - `slot_history`: A pointer to a `fd_slot_history_t` structure containing the slot history.
    - `my_pubkey`: A pointer to an `fd_pubkey_t` structure representing the public key of the current node.
    - `coordinator_pubkey`: A pointer to an `fd_pubkey_t` structure representing the public key of the coordinator node.
    - `out_buf`: A pointer to an unsigned char buffer where the output message will be stored.
    - `out_buf_len`: A pointer to an unsigned long integer where the length of the output buffer will be stored.
    - `runtime_spad`: A pointer to an `fd_spad_t` structure used for runtime operations.
- **Control Flow**:
    - Initialize the `restart` structure with the provided `funk_root`, `epoch_schedule`, and other parameters.
    - Set the initial stage of the restart process to `FD_RESTART_STAGE_FIND_HEAVIEST_FORK_SLOT_NUM`.
    - Copy the `root_bank_hash`, `my_pubkey`, and `coordinator_pubkey` into the `restart` structure.
    - Clear the `slot_to_stake` and `last_voted_fork_slots_received` arrays in the `restart` structure.
    - Log the initialization details including funk root, root epoch, and public keys.
    - Iterate over the epochs to populate vote account information and calculate total stakes for each epoch.
    - Read the last voted slot and its bank hash from the tower checkpoint file.
    - Prepare a gossip message with the last voted slot and its hash, and calculate a bitmap for the last voted fork slots.
    - Encode slots from the tower checkpoint and slot history into the bitmap.
    - Send the prepared message to the [`fd_restart_recv_last_voted_fork_slots`](#fd_restart_recv_last_voted_fork_slots) function to process the last voted fork slots.
    - Log a warning if a single validator has more than 80% stake.
- **Output**: The function does not return a value but initializes the `fd_restart_t` structure and prepares an output buffer with a gossip message.
- **Functions called**:
    - [`fd_restart_recv_last_voted_fork_slots`](#fd_restart_recv_last_voted_fork_slots)


---
### fd\_restart\_tower\_checkpt<!-- {{#callable:fd_restart_tower_checkpt}} -->
The `fd_restart_tower_checkpt` function creates a checkpoint of the current state of a voting tower and its associated ghost node history to a file.
- **Inputs**:
    - `vote_bank_hash`: A pointer to a constant `fd_hash_t` structure representing the hash of the vote bank.
    - `tower`: A pointer to an `fd_tower_t` structure representing the voting tower whose state is being checkpointed.
    - `ghost`: A pointer to an `fd_ghost_t` structure representing the ghost node history associated with the tower.
    - `root`: An unsigned long integer representing the root slot of the tower.
    - `tower_checkpt_fileno`: An integer file descriptor for the checkpoint file where the tower state will be written.
- **Control Flow**:
    - The function begins by seeking to the start of the checkpoint file using `lseek`.
    - It initializes several variables to track the total written size and the length of the checkpoint history.
    - The function writes the `vote_bank_hash`, `tower_height`, and `root` to the checkpoint file, updating `total_wsz` with each write.
    - It iterates over the votes in the tower, writing each vote's slot to the checkpoint file and updating `total_wsz`.
    - The function retrieves the last voted slot and uses it to query the ghost node map for the corresponding node.
    - It iterates through the ghost node history from the last voted slot to the ghost root, writing each node's slot to the checkpoint file and updating `total_wsz` and `checkpt_history_len`.
    - The ghost root slot is written to the checkpoint file, followed by a marker indicating the end of the slot history.
    - The checkpoint file is truncated to the total written size and flushed to disk using `fsync`.
    - If the total written size does not match the expected size, a warning is logged.
- **Output**: The function does not return a value but writes the state of the tower and its ghost node history to the specified checkpoint file.



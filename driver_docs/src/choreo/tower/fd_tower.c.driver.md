# Purpose
The provided C source code file is part of a system that manages a data structure referred to as a "tower," which is used to handle voting and consensus mechanisms, likely in a distributed system or blockchain context. The code defines a set of functions that operate on this tower structure, including creating, joining, leaving, and deleting towers, as well as performing various checks and operations related to voting. The primary focus of the code is to manage votes, simulate voting scenarios, and ensure that votes adhere to certain rules and thresholds, such as lockout and switch checks, which are critical for maintaining consensus and preventing double voting or other inconsistencies.

Key technical components include functions for managing the lifecycle of a tower ([`fd_tower_new`](#fd_tower_new), [`fd_tower_join`](#fd_tower_join), [`fd_tower_leave`](#fd_tower_leave), [`fd_tower_delete`](#fd_tower_delete)), as well as functions for simulating votes and checking conditions like lockout and switch thresholds ([`fd_tower_lockout_check`](#fd_tower_lockout_check), [`fd_tower_switch_check`](#fd_tower_switch_check), [`fd_tower_threshold_check`](#fd_tower_threshold_check)). The code also includes mechanisms for converting between different representations of votes and for verifying the integrity of the tower structure. The file appears to be part of a larger system, as it relies on external functions and data structures (e.g., `fd_ghost_t`, `fd_epoch_t`, `fd_funk_t`) and includes logging and error handling to ensure robustness. The code is designed to be integrated into a larger application, likely as a library or module, providing specific functionality related to voting and consensus management.
# Imports and Dependencies

---
- `fd_tower.h`
- `stdio.h`


# Functions

---
### fd\_tower\_new<!-- {{#callable:fd_tower_new}} -->
The `fd_tower_new` function initializes a new tower structure in shared memory, ensuring the memory is non-null and properly aligned before delegating to `fd_tower_votes_new`.
- **Inputs**:
    - `shmem`: A pointer to the shared memory location where the tower structure is to be initialized.
- **Control Flow**:
    - Check if the `shmem` pointer is NULL; if so, log a warning and return NULL.
    - Check if the `shmem` pointer is aligned according to [`fd_tower_align`](fd_tower.h.driver.md#fd_tower_align); if not, log a warning and return NULL.
    - Call `fd_tower_votes_new` with `shmem` and return its result.
- **Output**: Returns a pointer to the newly initialized tower structure, or NULL if the input memory is invalid.
- **Functions called**:
    - [`fd_tower_align`](fd_tower.h.driver.md#fd_tower_align)


---
### fd\_tower\_join<!-- {{#callable:fd_tower_join}} -->
The `fd_tower_join` function validates the alignment of a shared memory tower and joins it to the voting system if valid.
- **Inputs**:
    - `shtower`: A pointer to the shared memory tower that needs to be joined.
- **Control Flow**:
    - Check if the `shtower` pointer is NULL; if so, log a warning and return NULL.
    - Check if the `shtower` pointer is aligned according to [`fd_tower_align`](fd_tower.h.driver.md#fd_tower_align); if not, log a warning and return NULL.
    - If both checks pass, call `fd_tower_votes_join` with `shtower` and return its result.
- **Output**: Returns a pointer to the joined `fd_tower_t` structure if successful, or NULL if the input is invalid.
- **Functions called**:
    - [`fd_tower_align`](fd_tower.h.driver.md#fd_tower_align)


---
### fd\_tower\_leave<!-- {{#callable:fd_tower_leave}} -->
The `fd_tower_leave` function safely exits a tower by checking for a NULL pointer and then calling `fd_tower_votes_leave` to handle the leave operation.
- **Inputs**:
    - `tower`: A pointer to an `fd_tower_t` structure representing the tower to leave.
- **Control Flow**:
    - Check if the `tower` pointer is NULL using `FD_UNLIKELY`; if it is, log a warning and return NULL.
    - If the `tower` is not NULL, call `fd_tower_votes_leave` with the `tower` as an argument and return its result.
- **Output**: Returns a pointer to the result of `fd_tower_votes_leave`, or NULL if the `tower` is NULL.


---
### fd\_tower\_delete<!-- {{#callable:fd_tower_delete}} -->
The `fd_tower_delete` function deletes a tower object after verifying its validity and alignment.
- **Inputs**:
    - `tower`: A pointer to the tower object that needs to be deleted.
- **Control Flow**:
    - Check if the `tower` pointer is NULL; if so, log a warning and return NULL.
    - Check if the `tower` pointer is aligned according to [`fd_tower_align`](fd_tower.h.driver.md#fd_tower_align); if not, log a warning and return NULL.
    - Call `fd_tower_votes_delete` to delete the tower and return its result.
- **Output**: Returns a pointer to the result of `fd_tower_votes_delete`, or NULL if the input was invalid.
- **Functions called**:
    - [`fd_tower_align`](fd_tower.h.driver.md#fd_tower_align)


---
### expiration<!-- {{#callable:expiration}} -->
The `expiration` function calculates the expiration slot for a vote based on its configuration.
- **Inputs**:
    - `vote`: A pointer to a constant `fd_tower_vote_t` structure representing a vote, which contains the fields `slot` and `conf`.
- **Control Flow**:
    - Calculate `lockout` by left-shifting 1 by the value of `vote->conf`.
    - Return the sum of `vote->slot` and `lockout`.
- **Output**: The function returns an unsigned long integer representing the expiration slot of the vote.


---
### simulate\_vote<!-- {{#callable:simulate_vote}} -->
The `simulate_vote` function simulates the process of removing expired votes from the top of a voting tower until a non-expired vote is found or all votes are expired.
- **Inputs**:
    - `tower`: A pointer to a constant `fd_tower_t` structure representing the voting tower.
    - `slot`: An unsigned long integer representing the current slot against which votes are checked for expiration.
- **Control Flow**:
    - Initialize `cnt` with the number of votes in the tower using `fd_tower_votes_cnt` function.
    - Enter a while loop that continues as long as `cnt` is non-zero.
    - Within the loop, check if the expiration of the top vote (using `fd_tower_votes_peek_index_const` and [`expiration`](#expiration) functions) is greater than or equal to the current slot.
    - If the expiration condition is met, break out of the loop, indicating a non-expired vote is found.
    - If the expiration condition is not met, decrement `cnt` to simulate removing the expired vote.
    - Return the final count of non-expired votes.
- **Output**: The function returns an unsigned long integer representing the count of non-expired votes remaining in the tower after simulating the removal of expired votes.
- **Functions called**:
    - [`expiration`](#expiration)


---
### fd\_tower\_lockout\_check<!-- {{#callable:fd_tower_lockout_check}} -->
The `fd_tower_lockout_check` function checks if the last vote in a tower is on the same fork as a given slot, using ghost data to determine ancestry.
- **Inputs**:
    - `tower`: A pointer to a constant `fd_tower_t` structure representing the tower of votes.
    - `ghost`: A pointer to a constant `fd_ghost_t` structure used to determine ancestry information.
    - `slot`: An unsigned long integer representing the slot for which the lockout check is being performed.
- **Control Flow**:
    - If `FD_TOWER_USE_HANDHOLDING` is defined, the function checks that the tower is not empty using `FD_TEST`.
    - The function calls [`simulate_vote`](#simulate_vote) to remove expired votes from the top of the tower and get the count of remaining votes.
    - It retrieves the last vote in the tower using `fd_tower_votes_peek_index_const` with the index `cnt - 1`.
    - It retrieves the root node from the ghost using `fd_ghost_root`.
    - The function checks if the last vote's slot is less than the root's slot or if the last vote's slot is an ancestor of the given slot using `fd_ghost_is_ancestor`.
    - A log notice is generated with the result of the lockout check and details of the top vote and the switch slot.
    - The function returns the result of the lockout check as an integer.
- **Output**: An integer indicating whether the last vote in the tower is on the same fork as the given slot (1 for true, 0 for false).
- **Functions called**:
    - [`simulate_vote`](#simulate_vote)


---
### fd\_tower\_switch\_check<!-- {{#callable:fd_tower_switch_check}} -->
The `fd_tower_switch_check` function determines if a switch to a different fork is permissible based on the current vote's slot, the ghost's root, and the stake percentage of the new fork.
- **Inputs**:
    - `tower`: A pointer to a `fd_tower_t` structure representing the current voting tower.
    - `epoch`: A pointer to a `fd_epoch_t` structure containing epoch-related data, including total stake.
    - `ghost`: A pointer to a `fd_ghost_t` structure representing the ghost data structure used for ancestry checks.
    - `slot`: An unsigned long integer representing the slot for which the switch is being considered.
- **Control Flow**:
    - Check if the last vote's slot is less than the ghost's root slot; if so, return 1 to allow the switch.
    - Ensure that the latest vote's slot and the target slot are on different forks by checking ancestry paths.
    - Retrieve the ghost's common ancestor (GCA) for the latest vote's slot and the target slot.
    - Identify the child node of the GCA that corresponds to the latest vote's slot and exclude it from stake calculations.
    - Calculate the total stake of all other child nodes of the GCA.
    - Compute the switch percentage by dividing the calculated switch stake by the total stake from the epoch.
    - Log the switch decision and return whether the switch percentage exceeds a predefined threshold (`SWITCH_PCT`).
- **Output**: Returns an integer indicating whether a switch to a different fork is permissible (1 if permissible, 0 otherwise).


---
### fd\_tower\_threshold\_check<!-- {{#callable:fd_tower_threshold_check}} -->
The `fd_tower_threshold_check` function evaluates whether the voting tower has sufficient depth and stake to meet a predefined threshold for voting in a given slot.
- **Inputs**:
    - `tower`: A constant pointer to an `fd_tower_t` structure representing the current voting tower.
    - `epoch`: A constant pointer to an `fd_epoch_t` structure representing the current epoch data.
    - `funk`: A pointer to an `fd_funk_t` structure used for accessing vote account data.
    - `txn`: A constant pointer to an `fd_funk_txn_t` structure representing the current transaction context.
    - `slot`: An unsigned long integer representing the current slot for which the vote is being considered.
    - `runtime_spad`: A pointer to an `fd_spad_t` structure used for temporary memory allocation during the function execution.
- **Control Flow**:
    - Simulate a vote on the current tower to determine how many votes would remain after expiring those that would be expired by voting for the current slot.
    - Check if the remaining votes in the tower are fewer than `THRESHOLD_DEPTH`; if so, return 1 to indicate failure to meet the threshold.
    - Determine the slot of the vote at the `THRESHOLD_DEPTH` index from the end of the tower's votes.
    - Initialize a counter for the total stake of votes that have a slot greater than or equal to the threshold slot.
    - Iterate over all vote accounts in the epoch, skipping invalid keys and empty slots.
    - For each valid voter, allocate memory for a new tower, convert the voter's landed votes into the tower's format, and simulate a vote.
    - If the voter's tower is empty after simulation, continue to the next voter.
    - Check the voter's latest vote; if its slot is greater than or equal to the threshold slot, add the voter's stake to the threshold stake counter.
    - Calculate the percentage of total stake that meets the threshold and log the result.
    - Return whether the threshold percentage exceeds `THRESHOLD_PCT`.
- **Output**: The function returns an integer indicating whether the threshold percentage of stake is met (greater than `THRESHOLD_PCT`), returning 1 for failure and 0 for success.
- **Functions called**:
    - [`simulate_vote`](#simulate_vote)
    - [`fd_tower_align`](fd_tower.h.driver.md#fd_tower_align)
    - [`fd_tower_footprint`](fd_tower.h.driver.md#fd_tower_footprint)
    - [`fd_tower_join`](#fd_tower_join)
    - [`fd_tower_new`](#fd_tower_new)
    - [`fd_tower_from_vote_acc`](#fd_tower_from_vote_acc)


---
### FD\_SPAD\_FRAME\_BEGIN<!-- {{#callable:fd_tower_to_vote_txn::FD_SPAD_FRAME_BEGIN}} -->
The `FD_SPAD_FRAME_BEGIN` function initializes a voting transaction by updating the vote state, preparing transaction accounts, and encoding the vote instruction for a Solana validator.
- **Inputs**:
    - `runtime_spad`: A pointer to a shared memory space used for temporary allocations during the function execution.
- **Control Flow**:
    - Initialize a `fd_compact_vote_state_update_t` structure `tower_sync` and set its root, timestamp, and lockouts length.
    - Allocate memory for lockouts using `fd_spad_alloc` and iterate over tower votes to populate lockouts with offsets and confirmation counts.
    - Check if the validator identity matches the vote authority to determine the number of signatures and account setup for the transaction.
    - Generate the transaction base using `fd_txn_base_generate` with the appropriate account setup based on the identity check.
    - Create a vote instruction, encode it, and add it to the transaction payload using `fd_txn_add_instr`.
- **Output**: The function does not return a value but modifies the `vote_txn` structure to include the prepared transaction payload and metadata.


---
### fd\_tower\_reset\_slot<!-- {{#callable:fd_tower_reset_slot}} -->
The `fd_tower_reset_slot` function determines the appropriate slot to reset to based on the current state of the tower and ghost structures, ensuring consistency and correctness in the voting process.
- **Inputs**:
    - `tower`: A pointer to a constant `fd_tower_t` structure representing the current state of the voting tower.
    - `epoch`: A pointer to a constant `fd_epoch_t` structure representing the current epoch information.
    - `ghost`: A pointer to a constant `fd_ghost_t` structure representing the ghost state used for determining ancestry and head nodes.
- **Control Flow**:
    - Retrieve the last vote from the tower using `fd_tower_votes_peek_tail_const` and the root and head nodes from the ghost using `fd_ghost_root` and `fd_ghost_head` respectively.
    - Check if the last vote is null, or if its slot is less than the ghost root's slot, or if the ghost root is not an ancestor of the last vote's slot using `fd_ghost_is_ancestor`.
    - If any of the above conditions are true, return the slot of the ghost head node.
    - Otherwise, query the ghost for the node corresponding to the last vote's slot using `fd_ghost_query`.
    - If `FD_TOWER_USE_HANDHOLDING` is enabled, verify that the node was found and log an error if not.
    - Return the slot of the head node found by traversing from the node corresponding to the last vote's slot using `fd_ghost_head`.
- **Output**: The function returns an `ulong` representing the slot to reset to, which is either the slot of the ghost head or the slot of the head node found by traversing from the last vote's node.


---
### fd\_tower\_vote\_slot<!-- {{#callable:fd_tower_vote_slot}} -->
The `fd_tower_vote_slot` function determines the appropriate slot to vote for based on the current state of the tower and ghost structures, ensuring compliance with voting rules and thresholds.
- **Inputs**:
    - `tower`: A pointer to the `fd_tower_t` structure representing the current voting tower state.
    - `epoch`: A constant pointer to the `fd_epoch_t` structure representing the current epoch information.
    - `funk`: A pointer to the `fd_funk_t` structure used for managing state and transactions.
    - `txn`: A constant pointer to the `fd_funk_txn_t` structure representing the current transaction context.
    - `ghost`: A constant pointer to the `fd_ghost_t` structure representing the ghost state used for determining ancestry and fork information.
    - `runtime_spad`: A pointer to the `fd_spad_t` structure used for runtime scratchpad memory allocation.
- **Control Flow**:
    - Retrieve the last vote from the tower and the root and head nodes from the ghost structure.
    - Check if a vote should be made for the ghost head based on conditions such as not having voted, the last vote being less than the ghost root, or the ghost root not being an ancestor of the last vote.
    - If the ghost head is on the same fork as the last vote slot, check if the threshold condition is met to vote for it.
    - If the ghost head is on a different fork, check if lockout and switch conditions are met to switch the vote to the ghost head.
    - Log the success or failure of the voting decision and return the appropriate slot or `FD_SLOT_NULL` if voting is not possible.
- **Output**: Returns the slot number to vote for if conditions are met, or `FD_SLOT_NULL` if voting is not possible.
- **Functions called**:
    - [`fd_tower_threshold_check`](#fd_tower_threshold_check)
    - [`fd_tower_lockout_check`](#fd_tower_lockout_check)
    - [`fd_tower_switch_check`](#fd_tower_switch_check)


---
### fd\_tower\_vote<!-- {{#callable:fd_tower_vote}} -->
The `fd_tower_vote` function manages the voting process for a given slot in a tower, handling expired votes, updating confirmations, and adding new votes.
- **Inputs**:
    - `tower`: A pointer to an `fd_tower_t` structure representing the voting tower.
    - `slot`: An unsigned long integer representing the slot number for which the vote is being cast.
- **Control Flow**:
    - Log the voting action for the given slot.
    - If handholding is enabled, check if the slot is less than the last vote's slot and log an error if so.
    - Use [`simulate_vote`](#simulate_vote) to determine how many expired votes should be removed from the tower.
    - Remove expired votes from the tower until the count matches the simulated count.
    - Check if the tower is full; if so, pop the head vote and set it as the new root.
    - Iterate through the votes in reverse order to increment confirmations for consecutive confirmations in prior votes.
    - Add the new vote with the given slot and a confirmation count of 1 to the tower.
- **Output**: Returns the new root slot if the tower was full and a vote was popped, otherwise returns `FD_SLOT_NULL`.
- **Functions called**:
    - [`simulate_vote`](#simulate_vote)


---
### fd\_tower\_simulate\_vote<!-- {{#callable:fd_tower_simulate_vote}} -->
The `fd_tower_simulate_vote` function simulates the voting process for a given slot in a tower structure and returns the count of valid votes.
- **Inputs**:
    - `tower`: A pointer to a constant `fd_tower_t` structure representing the tower of votes.
    - `slot`: An unsigned long integer representing the slot for which the vote simulation is to be performed.
- **Control Flow**:
    - If `FD_TOWER_USE_HANDHOLDING` is defined, the function checks if the tower is not empty using `FD_TEST` to prevent caller errors.
    - The function calls [`simulate_vote`](#simulate_vote) with the provided `tower` and `slot` to perform the vote simulation.
    - The result from [`simulate_vote`](#simulate_vote), which is the count of valid votes, is returned.
- **Output**: The function returns an unsigned long integer representing the count of valid votes after simulating the vote for the given slot.
- **Functions called**:
    - [`simulate_vote`](#simulate_vote)


---
### fd\_tower\_from\_vote\_acc<!-- {{#callable:fd_tower_from_vote_acc}} -->
The `fd_tower_from_vote_acc` function populates a voting tower with votes retrieved from a specified vote account using the Funk database.
- **Inputs**:
    - `tower`: A pointer to an `fd_tower_t` structure where the votes will be stored.
    - `funk`: A pointer to an `fd_funk_t` structure representing the Funk database context.
    - `txn`: A constant pointer to an `fd_funk_txn_t` structure representing the transaction context.
    - `vote_acc`: A constant pointer to an `fd_funk_rec_key_t` structure representing the key of the vote account to query.
- **Control Flow**:
    - Check if the tower is empty; if not, log an error and exit (only if handholding is enabled).
    - Initialize a vote count and an array to store up to 32 votes.
    - Enter an infinite loop to query the vote state from the Funk database using the provided transaction and vote account key.
    - If the state is NULL, return immediately as there is no valid vote state.
    - Retrieve the number of votes from the state and clear the votes array.
    - Iterate over each vote in the state, copying it into the votes array based on the version of the vote state.
    - If an unknown state discriminant is encountered, log an error and exit.
    - If the speculative query is successful, break out of the loop.
    - Push each vote from the votes array into the tower.
- **Output**: The function does not return a value; it modifies the `tower` in place by adding votes retrieved from the specified vote account.


---
### fd\_tower\_to\_vote\_txn<!-- {{#callable:fd_tower_to_vote_txn}} -->
The `fd_tower_to_vote_txn` function constructs a vote transaction from a given tower state, root, and other parameters, and encodes it into a transaction payload.
- **Inputs**:
    - `tower`: A pointer to the `fd_tower_t` structure representing the current state of the voting tower.
    - `root`: An unsigned long integer representing the root slot of the tower.
    - `bank_hash`: A pointer to the `fd_hash_t` structure representing the hash of the bank.
    - `recent_blockhash`: A pointer to the `fd_hash_t` structure representing the recent block hash.
    - `validator_identity`: A pointer to the `fd_pubkey_t` structure representing the public key of the validator identity.
    - `vote_authority`: A pointer to the `fd_pubkey_t` structure representing the public key of the vote authority.
    - `vote_acc`: A pointer to the `fd_pubkey_t` structure representing the public key of the vote account.
    - `vote_txn`: A pointer to the `fd_txn_p_t` structure where the constructed vote transaction will be stored.
    - `runtime_spad`: A pointer to the `fd_spad_t` structure used for runtime scratchpad memory allocation.
- **Control Flow**:
    - Begin a frame for the runtime scratchpad memory allocation.
    - Initialize a `fd_compact_vote_state_update_t` structure to store the compact vote state update information.
    - Set the root, timestamp, and lockouts length in the `tower_sync` structure.
    - Allocate memory for lockouts using the runtime scratchpad and populate it with offsets and confirmation counts from the tower votes.
    - Determine if the validator identity and vote authority are the same and set up transaction accounts accordingly.
    - Generate the base transaction metadata using `fd_txn_base_generate` based on the account setup.
    - Create a vote instruction with the compact update vote state and encode it into a buffer.
    - Add the vote instruction to the transaction payload using `fd_txn_add_instr`.
    - End the frame for the runtime scratchpad memory allocation.
- **Output**: The function outputs a constructed vote transaction stored in the `vote_txn` structure, with its payload and metadata populated based on the input parameters and tower state.


---
### fd\_tower\_verify<!-- {{#callable:fd_tower_verify}} -->
The `fd_tower_verify` function checks the integrity of a sequence of votes in a tower by ensuring that each vote's slot and confirmation count are greater than or equal to the previous vote's.
- **Inputs**:
    - `tower`: A pointer to a constant `fd_tower_t` structure representing the tower of votes to be verified.
- **Control Flow**:
    - Initialize a pointer `prev` to `NULL` to keep track of the previous vote in the iteration.
    - Iterate over the votes in the tower using an iterator initialized with `fd_tower_votes_iter_init`.
    - For each vote, retrieve the current vote using `fd_tower_votes_iter_ele_const`.
    - Check if `prev` is not `NULL` and if the current vote's slot and confirmation count are not both less than the previous vote's slot and confirmation count.
    - If the condition is violated, log a warning message and return `-1` to indicate an invariant violation.
    - Update `prev` to point to the current vote.
    - Continue the iteration until all votes are checked.
    - Return `0` if all votes satisfy the invariant condition.
- **Output**: Returns `0` if the votes in the tower maintain the required invariant, otherwise returns `-1` if an invariant violation is detected.


---
### fd\_tower\_print<!-- {{#callable:fd_tower_print}} -->
The `fd_tower_print` function prints a formatted table of vote slots and their confirmation counts from a given tower structure, ending with the root slot.
- **Inputs**:
    - `tower`: A pointer to a constant `fd_tower_t` structure representing the tower of votes to be printed.
    - `root`: An unsigned long integer representing the root slot to be printed at the end of the table.
- **Control Flow**:
    - Log a notice indicating the start of the tower print.
    - Initialize `max_slot` to zero to track the maximum slot value.
    - Iterate over the votes in the tower in reverse order to find the maximum slot value.
    - Calculate the number of digits in the maximum slot value for formatting purposes.
    - Print the table header with appropriate spacing based on the digit count.
    - Print a divider line under the header.
    - Iterate over the votes in the tower again in reverse order to print each vote's slot and confirmation count, formatted according to the digit count.
    - Print the root slot at the end of the table.
- **Output**: The function does not return a value; it outputs the formatted table to the standard output.



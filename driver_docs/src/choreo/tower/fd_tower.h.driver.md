# Purpose
The provided C header file, `fd_tower.h`, defines an API for implementing Solana's TowerBFT consensus algorithm. This algorithm is crucial for achieving consensus in a distributed network of validators by ensuring that a supermajority of stake converges on the same blockchain fork. The file outlines the structure and operations of a "vote tower," which is a data structure used by validators to manage their voting history and decisions. The vote tower is essentially a stack where each entry represents a vote for a specific blockchain slot, along with a confirmation count that indicates how many consecutive votes have been cast on the same fork. This structure helps manage the lockout periods and switching rules that prevent validators from frequently changing forks, thereby promoting stability and convergence in the network.

The file provides a comprehensive set of functions for managing the vote tower, including creating, joining, and deleting a tower, as well as performing various checks and operations related to voting. These include lockout checks, switch checks, and threshold checks, which ensure that validators adhere to the rules of the TowerBFT algorithm. The file also includes functions for simulating votes, determining the appropriate slots for voting and resetting, and converting the tower state into a format suitable for transmission in a vote transaction. The header file is designed to be included in other C source files, providing a robust interface for integrating TowerBFT functionality into a Solana validator's software stack.
# Imports and Dependencies

---
- `../fd_choreo_base.h`
- `../epoch/fd_epoch.h`
- `../ghost/fd_ghost.h`
- `../voter/fd_voter.h`
- `../../disco/pack/fd_microblock.h`
- `../../flamenco/runtime/fd_blockstore.h`
- `../../flamenco/runtime/fd_system_ids.h`
- `../../flamenco/txn/fd_txn_generate.h`
- `../../funk/fd_funk.h`
- `../../util/tmpl/fd_deque.c`


# Global Variables

---
### fd\_tower\_new
- **Type**: `function pointer`
- **Description**: `fd_tower_new` is a function that formats an unused memory region for use as a tower in the context of Solana's TowerBFT algorithm. It takes a non-NULL pointer to a memory region with the required footprint and alignment as its parameter.
- **Use**: This function is used to initialize a memory region so that it can be used to store a validator's vote tower.


---
### fd\_tower\_join
- **Type**: `fd_tower_t *`
- **Description**: The `fd_tower_join` function is a global function that returns a pointer to an `fd_tower_t` structure. This function is used to join a caller to a tower, which is a representation of a validator's 'vote tower' in the context of Solana's TowerBFT algorithm.
- **Use**: This function is used to obtain a local pointer to the tower's memory region, allowing the caller to interact with the tower's data structure.


---
### fd\_tower\_leave
- **Type**: `function pointer`
- **Description**: `fd_tower_leave` is a function that allows a process to leave a current local join to a tower, which is a data structure representing a validator's vote tower in the context of Solana's TowerBFT algorithm. The function returns a pointer to the underlying shared memory region on success, or NULL on failure, logging details of the failure.
- **Use**: This function is used to safely disconnect a process from a shared memory region used as a tower, ensuring proper resource management and cleanup.


---
### fd\_tower\_delete
- **Type**: `function pointer`
- **Description**: `fd_tower_delete` is a function that unformats a memory region used as a tower, assuming only the local process is joined to the region. It returns a pointer to the underlying shared memory region or NULL if used incorrectly, such as when the provided pointer is not a valid tower.
- **Use**: This function is used to clean up and release the memory resources associated with a tower, transferring ownership of the memory region back to the caller.


# Data Structures

---
### fd\_tower\_vote
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number for which the vote is cast.
    - `conf`: Indicates the confirmation count for the vote, representing how many consecutive votes have been cast on the same fork.
- **Description**: The `fd_tower_vote` structure is a fundamental component of the TowerBFT algorithm used in Solana's consensus mechanism. It encapsulates a single vote within a validator's vote tower, storing the slot number and the confirmation count. The slot number identifies the specific block or slot the vote pertains to, while the confirmation count tracks how many consecutive votes have been made on the same fork, which is crucial for determining lockout periods and ensuring consensus stability. This structure is used to manage and track the state of votes in the consensus process, facilitating decisions on fork selection and ensuring the integrity of the blockchain.


---
### fd\_tower\_vote\_t
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the vote slot for which the validator has voted.
    - `conf`: Indicates the confirmation count, representing how many consecutive votes have been cast on the same fork.
- **Description**: The `fd_tower_vote_t` structure is a fundamental component of the TowerBFT algorithm used in Solana's consensus mechanism. It encapsulates a single vote within a validator's "vote tower," which is a stack-like structure that tracks the slots a validator has voted for and the confirmation count for each vote. The confirmation count is crucial for determining the lockout period, which prevents a validator from switching forks too frequently, thereby promoting consensus stability. This structure is used to manage and verify the voting process, ensuring that validators adhere to the rules of the TowerBFT algorithm.


# Functions

---
### fd\_tower\_align<!-- {{#callable:fd_tower_align}} -->
The `fd_tower_align` function returns the alignment requirement for a memory region suitable for use as a tower in the TowerBFT algorithm.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests performance optimization by the compiler.
    - The function simply returns a constant value, `FD_TOWER_ALIGN`, which is predefined elsewhere in the code.
- **Output**: The function returns an unsigned long integer representing the alignment requirement for a tower.


---
### fd\_tower\_footprint<!-- {{#callable:fd_tower_footprint}} -->
The `fd_tower_footprint` function returns the memory footprint size required for a tower data structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests a small, frequently used function.
    - The function simply returns a constant value, `FD_TOWER_FOOTPRINT`, which is predefined elsewhere in the code.
- **Output**: The function outputs an unsigned long integer representing the size of memory required for the tower data structure.


# Function Declarations (Public API)

---
### fd\_tower\_new<!-- {{#callable_declaration:fd_tower_new}} -->
Formats a memory region for use as a TowerBFT vote tower.
- **Description**: This function initializes a memory region to be used as a vote tower for Solana's TowerBFT algorithm. It should be called with a valid memory pointer that meets the required alignment and footprint specifications. The function checks if the provided memory is non-null and properly aligned; if not, it logs a warning and returns null. This function is typically used during the setup phase of a TowerBFT system to prepare memory for storing vote data.
- **Inputs**:
    - `shmem`: A pointer to the memory region to be formatted as a tower. It must not be null and must be aligned according to fd_tower_align(). If these conditions are not met, the function logs a warning and returns null. The caller retains ownership of the memory.
- **Output**: Returns a pointer to the initialized tower structure on success, or null if the input is invalid.
- **See also**: [`fd_tower_new`](fd_tower.c.driver.md#fd_tower_new)  (Implementation)


---
### fd\_tower\_join<!-- {{#callable_declaration:fd_tower_join}} -->
Joins the caller to a shared tower memory region.
- **Description**: This function is used to join a caller to a shared memory region that represents a tower, which is part of the TowerBFT algorithm for consensus in a validator cluster. It should be called when a process needs to interact with the tower structure. The function requires that the memory region is properly aligned and not null. If these conditions are not met, the function will log a warning and return null. This function is typically used after the memory region has been initialized with `fd_tower_new`.
- **Inputs**:
    - `shtower`: A pointer to the shared memory region representing the tower. It must not be null and must be aligned according to `fd_tower_align()`. If these conditions are not met, the function logs a warning and returns null. The caller retains ownership of the memory.
- **Output**: Returns a pointer to the local address space representation of the tower on success, or null if the input is invalid.
- **See also**: [`fd_tower_join`](fd_tower.c.driver.md#fd_tower_join)  (Implementation)


---
### fd\_tower\_leave<!-- {{#callable_declaration:fd_tower_leave}} -->
Leaves a current local join of a tower.
- **Description**: This function is used to leave a current local join of a tower, which is part of the TowerBFT algorithm for consensus in a validator cluster. It should be called when a process no longer needs to interact with the tower, allowing for cleanup or transition to another state. The function must be called with a valid tower pointer that was previously joined. If the provided tower pointer is null, the function logs a warning and returns null, indicating failure to leave the join.
- **Inputs**:
    - `tower`: A pointer to the fd_tower_t structure representing the tower to leave. Must not be null. If null, the function logs a warning and returns null.
- **Output**: Returns a pointer to the underlying shared memory region on success, or null if the input is invalid (e.g., null pointer).
- **See also**: [`fd_tower_leave`](fd_tower.c.driver.md#fd_tower_leave)  (Implementation)


---
### fd\_tower\_delete<!-- {{#callable_declaration:fd_tower_delete}} -->
Unformats a memory region used as a tower.
- **Description**: Use this function to release a memory region previously formatted as a tower, effectively unformatting it. This function should be called when the tower is no longer needed, and it assumes that only the local process is joined to the region. It returns a pointer to the underlying shared memory region, transferring ownership back to the caller. If the provided pointer is null or misaligned, the function logs a warning and returns null.
- **Inputs**:
    - `tower`: A pointer to the memory region used as a tower. It must be non-null and properly aligned according to the tower's alignment requirements. If the pointer is null or misaligned, the function logs a warning and returns null.
- **Output**: Returns a pointer to the underlying shared memory region if successful, or null if the input is invalid.
- **See also**: [`fd_tower_delete`](fd_tower.c.driver.md#fd_tower_delete)  (Implementation)


---
### fd\_tower\_lockout\_check<!-- {{#callable_declaration:fd_tower_lockout_check}} -->
Checks if voting for a specified slot violates lockout rules.
- **Description**: This function determines whether a validator can vote for a given slot without violating the lockout rules of the TowerBFT algorithm. It should be used to ensure that a vote does not occur on a different fork before the expiration of a previous vote's lockout period. The function assumes that the tower is non-empty and uses the ghost structure to verify if the slot is on the same fork as previous votes. It returns a boolean indicating whether voting is permissible.
- **Inputs**:
    - `tower`: A pointer to a non-empty fd_tower_t structure representing the validator's vote tower. The caller retains ownership and must ensure it is not null.
    - `ghost`: A pointer to an fd_ghost_t structure used to determine fork ancestry. The caller retains ownership and must ensure it is not null.
    - `slot`: An unsigned long integer representing the slot to check for lockout. It must be a valid slot number.
- **Output**: Returns 1 if voting for the specified slot is allowed without violating lockout, otherwise returns 0.
- **See also**: [`fd_tower_lockout_check`](fd_tower.c.driver.md#fd_tower_lockout_check)  (Implementation)


---
### fd\_tower\_switch\_check<!-- {{#callable_declaration:fd_tower_switch_check}} -->
Checks if switching to a new fork is permissible based on stake weight.
- **Description**: This function determines whether it is permissible to switch to a new fork identified by `slot` in the context of Solana's TowerBFT consensus algorithm. It should be called when a validator is considering switching its vote to a different fork. The function checks if a sufficient percentage of stake has voted for a different descendant of the greatest common ancestor (GCA) of the current vote fork and the target switch fork. The function assumes that the tower is non-empty and that the caller has already ensured the necessary preconditions for a switch check.
- **Inputs**:
    - `tower`: A pointer to a non-empty `fd_tower_t` structure representing the current vote tower. The caller retains ownership and must ensure it is valid.
    - `epoch`: A pointer to a `fd_epoch_t` structure representing the current epoch. The caller retains ownership and must ensure it is valid.
    - `ghost`: A pointer to a `fd_ghost_t` structure used to determine ancestry relationships between slots. The caller retains ownership and must ensure it is valid.
    - `slot`: An unsigned long integer representing the slot of the fork to which the switch is being considered. It must be a valid slot number.
- **Output**: Returns 1 if switching to the fork of `slot` is permissible, otherwise returns 0.
- **See also**: [`fd_tower_switch_check`](fd_tower.c.driver.md#fd_tower_switch_check)  (Implementation)


---
### fd\_tower\_threshold\_check<!-- {{#callable_declaration:fd_tower_threshold_check}} -->
Checks if the tower passes the threshold required to vote for a given slot.
- **Description**: This function determines whether the voting tower meets the necessary threshold to vote for a specified slot. It should be used when a validator needs to ensure that at least a supermajority of stake has voted for the same fork as the vote at a certain depth in the tower. This is relevant after voting for and confirming the same fork, ensuring the tower is deep enough to proceed with voting. The function simulates a vote to expire stale votes and calculates the stake percentage that meets the threshold. It returns a boolean indicating whether the threshold is met.
- **Inputs**:
    - `tower`: A pointer to a constant fd_tower_t structure representing the validator's vote tower. Must not be null.
    - `epoch`: A pointer to a constant fd_epoch_t structure representing the current epoch's state. Must not be null.
    - `funk`: A pointer to an fd_funk_t structure used for accessing the accounts database. Must not be null.
    - `txn`: A pointer to a constant fd_funk_txn_t structure representing the current transaction context. Must not be null.
    - `slot`: An unsigned long integer representing the slot for which the threshold check is being performed.
    - `runtime_spad`: A pointer to an fd_spad_t structure used for temporary memory allocation during the function's execution. Must not be null.
- **Output**: Returns 1 if the threshold check is passed, otherwise returns 0.
- **See also**: [`fd_tower_threshold_check`](fd_tower.c.driver.md#fd_tower_threshold_check)  (Implementation)


---
### fd\_tower\_reset\_slot<!-- {{#callable_declaration:fd_tower_reset_slot}} -->
Determines the slot to reset PoH to for building the next leader block.
- **Description**: This function is used to determine the appropriate slot to reset the Proof of History (PoH) to when preparing to build the next leader block. It should be called when a validator needs to decide which fork to build upon. The function assumes that the provided tower and ghost are valid and synchronized, meaning every vote slot in the tower corresponds to a node in the ghost. The function returns the slot of the ghost head if no votes have been cast, if the last vote slot is older than the ghost root, or if the last vote slot is on a minority fork not chaining back to the ghost root. This ensures that the validator builds on the most appropriate fork, avoiding minority forks that are not supported by the majority of the cluster.
- **Inputs**:
    - `tower`: A pointer to a constant fd_tower_t structure representing the validator's vote tower. It must be a valid local join and synchronized with the ghost.
    - `epoch`: A pointer to a constant fd_epoch_t structure representing the current epoch. It is used for context but not directly manipulated by the function.
    - `ghost`: A pointer to a constant fd_ghost_t structure representing the ghost tree. It must be a valid local join and synchronized with the tower.
- **Output**: Returns the slot to reset PoH to, or FD_SLOT_NULL if the tower and ghost are not synchronized.
- **See also**: [`fd_tower_reset_slot`](fd_tower.c.driver.md#fd_tower_reset_slot)  (Implementation)


---
### fd\_tower\_vote\_slot<!-- {{#callable_declaration:fd_tower_vote_slot}} -->
Determines the appropriate vote slot based on the current ghost tree and voting rules.
- **Description**: This function is used to determine the correct slot to vote for in the context of Solana's TowerBFT consensus algorithm. It should be called when a validator needs to decide on a vote slot based on the current state of the ghost tree and the validator's vote tower. The function considers whether the ghost head is on the same fork as the last vote slot and checks if the threshold, lockout, and switch conditions are met. It returns a valid vote slot if conditions are satisfied or FD_SLOT_NULL if voting is not possible due to lockout, threshold, or switch constraints.
- **Inputs**:
    - `tower`: A pointer to an fd_tower_t structure representing the validator's vote tower. Must not be null and should be properly initialized.
    - `epoch`: A pointer to an fd_epoch_t structure representing the current epoch. Must not be null.
    - `funk`: A pointer to an fd_funk_t structure used for accessing the accounts database. Must not be null.
    - `txn`: A pointer to an fd_funk_txn_t structure representing the current transaction context. Must not be null.
    - `ghost`: A pointer to an fd_ghost_t structure representing the ghost tree used for fork selection. Must not be null.
    - `runtime_spad`: A pointer to an fd_spad_t structure used for runtime scratchpad operations. Must not be null.
- **Output**: Returns the slot number to vote for if conditions are met, or FD_SLOT_NULL if voting is not possible.
- **See also**: [`fd_tower_vote_slot`](fd_tower.c.driver.md#fd_tower_vote_slot)  (Implementation)


---
### fd\_tower\_simulate\_vote<!-- {{#callable_declaration:fd_tower_simulate_vote}} -->
Simulates a vote on the vote tower for a given slot.
- **Description**: This function is used to simulate the effect of voting for a specific slot on a validator's vote tower, without actually committing the vote. It is useful for determining the potential changes in the vote tower, such as which votes would be popped due to expiration. This function should be called when you need to understand the impact of a vote on the tower's structure before making an actual vote. It assumes that the vote tower is not empty.
- **Inputs**:
    - `tower`: A pointer to a constant fd_tower_t structure representing the vote tower. It must not be null and should be non-empty.
    - `slot`: An unsigned long integer representing the slot for which the vote is being simulated. There are no specific constraints on the value, but it should be a valid slot number in the context of the tower.
- **Output**: Returns an unsigned long integer representing the new height (count) for all the votes that would have been popped from the tower as a result of the simulated vote.
- **See also**: [`fd_tower_simulate_vote`](fd_tower.c.driver.md#fd_tower_simulate_vote)  (Implementation)


---
### fd\_tower\_from\_vote\_acc<!-- {{#callable_declaration:fd_tower_from_vote_acc}} -->
Writes the saved tower state from a vote account to a provided tower.
- **Description**: This function initializes a provided `fd_tower_t` structure with the vote state retrieved from a specified vote account. It should be used when you need to populate a tower with the current voting state from a vote account, typically during initialization or synchronization processes. The function assumes that the `tower` is a valid and currently empty join of an `fd_tower`. It will not proceed if the tower is not empty, ensuring that no existing data is overwritten. The function will attempt to query the vote state repeatedly until successful, handling any transient errors internally.
- **Inputs**:
    - `tower`: A pointer to an `fd_tower_t` structure that will be populated with the vote state. Must be a valid, empty join of an `fd_tower`. The caller retains ownership.
    - `funk`: A pointer to an `fd_funk_t` structure representing the Funk database context. Must not be null. The caller retains ownership.
    - `txn`: A pointer to a constant `fd_funk_txn_t` structure representing the transaction context. Must not be null. The caller retains ownership.
    - `vote_acc`: A pointer to a constant `fd_funk_rec_key_t` structure representing the key of the vote account to query. Must not be null. The caller retains ownership.
- **Output**: None
- **See also**: [`fd_tower_from_vote_acc`](fd_tower.c.driver.md#fd_tower_from_vote_acc)  (Implementation)


---
### fd\_tower\_to\_vote\_txn<!-- {{#callable_declaration:fd_tower_to_vote_txn}} -->
Converts a vote tower into a transaction for the Solana vote program.
- **Description**: This function is used to create a transaction that represents the current state of a validator's vote tower, which is then sent to the Solana network as part of the voting process. It should be called when a validator needs to update its vote state on the blockchain. The function requires a valid vote tower and other necessary parameters such as the root slot, bank hash, recent blockhash, and public keys for the validator identity, vote authority, and vote account. The function prepares the transaction by encoding the vote state and adding the necessary instructions. It assumes that the provided pointers are valid and that the runtime scratchpad is properly initialized.
- **Inputs**:
    - `tower`: A pointer to a constant fd_tower_t representing the validator's current vote tower. Must not be null.
    - `root`: An unsigned long representing the root slot of the vote tower.
    - `bank_hash`: A pointer to a constant fd_hash_t representing the hash of the bank. Must not be null.
    - `recent_blockhash`: A pointer to a constant fd_hash_t representing the recent blockhash. Must not be null.
    - `validator_identity`: A pointer to a constant fd_pubkey_t representing the validator's identity public key. Must not be null.
    - `vote_authority`: A pointer to a constant fd_pubkey_t representing the vote authority public key. Must not be null.
    - `vote_acc`: A pointer to a constant fd_pubkey_t representing the vote account public key. Must not be null.
    - `vote_txn`: A pointer to an fd_txn_p_t where the generated transaction will be stored. Must not be null.
    - `runtime_spad`: A pointer to an fd_spad_t used as a scratchpad for runtime operations. Must be properly initialized and must not be null.
- **Output**: None
- **See also**: [`fd_tower_to_vote_txn`](fd_tower.c.driver.md#fd_tower_to_vote_txn)  (Implementation)


---
### fd\_tower\_verify<!-- {{#callable_declaration:fd_tower_verify}} -->
Checks if the tower is in a valid state.
- **Description**: Use this function to verify the integrity of a vote tower, ensuring that the vote slots and confirmation counts are in a valid, monotonically increasing order. This function should be called to validate the tower's state before performing operations that depend on its correctness. It returns an error if the tower's state violates expected invariants, such as having vote slots or confirmation counts that are not in the correct order.
- **Inputs**:
    - `tower`: A pointer to a constant fd_tower_t structure representing the vote tower to be verified. The pointer must not be null, and the tower should be properly initialized and joined before calling this function.
- **Output**: Returns 0 if the tower is valid, or -1 if the tower is in an invalid state, such as having non-monotonic vote slots or confirmation counts.
- **See also**: [`fd_tower_verify`](fd_tower.c.driver.md#fd_tower_verify)  (Implementation)


---
### fd\_tower\_print<!-- {{#callable_declaration:fd_tower_print}} -->
Pretty-prints the vote tower as a formatted table.
- **Description**: Use this function to display the current state of a vote tower in a human-readable table format. It is useful for debugging or monitoring the status of the tower. The function outputs the slot numbers and their corresponding confirmation counts, followed by the root slot. Ensure that the `tower` parameter is a valid pointer to a `fd_tower_t` structure before calling this function.
- **Inputs**:
    - `tower`: A pointer to a `fd_tower_t` structure representing the vote tower. Must not be null and should point to a valid, initialized tower.
    - `root`: An unsigned long integer representing the root slot to be printed at the end of the table. It is used to indicate the current root of the tower.
- **Output**: None
- **See also**: [`fd_tower_print`](fd_tower.c.driver.md#fd_tower_print)  (Implementation)



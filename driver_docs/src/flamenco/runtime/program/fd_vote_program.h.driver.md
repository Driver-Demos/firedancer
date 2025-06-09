# Purpose
This C header file defines the interface for a vote program used in a blockchain consensus mechanism, specifically for the Solana blockchain. The vote program is a critical component that allows node operators to register their nodes and participate in the consensus process by implementing Tower BFT logic, which includes voting and managing lockouts. The file provides a set of custom error codes that are used to handle various error conditions related to voting operations, such as mismatches in slots or timestamps, lockout conflicts, and issues with vote account states. These error codes facilitate robust error handling and debugging within the vote program.

The file also declares several functions that form the public API of the vote program. These functions include [`fd_vote_program_execute`](#fd_vote_program_execute), which serves as the entry point for processing vote instructions, and other utility functions for managing vote states, querying stake amounts, and handling commission splits. The header file includes references to external resources, such as GitHub links, which provide additional context for some of the functions. Overall, this file is designed to be included in other parts of the software to provide the necessary functionality for managing and executing voting operations within the Solana blockchain's consensus framework.
# Imports and Dependencies

---
- `../context/fd_exec_instr_ctx.h`


# Data Structures

---
### fd\_commission\_split
- **Type**: `struct`
- **Members**:
    - `voter_portion`: Represents the portion of the commission allocated to the voter, expressed as an unsigned long integer.
    - `staker_portion`: Represents the portion of the commission allocated to the staker, expressed as an unsigned long integer.
    - `is_split`: Indicates whether the commission is split between voter and staker, expressed as an unsigned integer.
- **Description**: The `fd_commission_split` structure is used to define the distribution of commission between a voter and a staker in a voting program. It contains fields to specify the portions of the commission allocated to each party and a flag to indicate if the commission is split. This structure is essential for managing and calculating the distribution of rewards in a consensus algorithm, ensuring that both voters and stakers receive their respective shares.


---
### fd\_commission\_split\_t
- **Type**: `struct`
- **Members**:
    - `voter_portion`: Represents the portion of the commission allocated to the voter.
    - `staker_portion`: Represents the portion of the commission allocated to the staker.
    - `is_split`: Indicates whether the commission is split between voter and staker.
- **Description**: The `fd_commission_split_t` structure is used to define the distribution of commission between a voter and a staker in a voting program. It contains fields to specify the portions of the commission allocated to each party and a flag to indicate if the commission is split. This structure is essential for managing and calculating the distribution of rewards in a consensus mechanism.


# Function Declarations (Public API)

---
### fd\_vote\_program\_execute<!-- {{#callable_declaration:fd_vote_program_execute}} -->
Processes a vote program instruction.
- **Description**: This function serves as the entry point for executing instructions within the vote program, which is integral to Solana's consensus mechanism. It processes various vote-related instructions, updating the transaction context to reflect any changes to vote accounts. This function should be called with a valid execution instruction context, and it assumes that the context has been properly initialized. The function handles different instruction types, ensuring that the necessary preconditions are met and returning specific error codes if any issues arise during execution.
- **Inputs**:
    - `ctx`: A pointer to an fd_exec_instr_ctx_t structure representing the execution instruction context. This parameter must not be null and should be properly initialized before calling the function. The function updates this context to reflect any changes to vote accounts.
- **Output**: Returns an integer status code indicating the result of the instruction execution. A return value of FD_EXECUTOR_INSTR_SUCCESS indicates success, while other values represent specific error conditions encountered during execution.
- **See also**: [`fd_vote_program_execute`](fd_vote_program.c.driver.md#fd_vote_program_execute)  (Implementation)


---
### fd\_vote\_state\_versions\_is\_correct\_and\_initialized<!-- {{#callable_declaration:fd_vote_state_versions_is_correct_and_initialized}} -->
Checks if a vote account is correctly initialized and has the correct version.
- **Description**: Use this function to verify that a given vote account is both correctly initialized and matches one of the expected version sizes. This function is essential for ensuring that the vote account is in a valid state before performing operations that depend on its correctness. It checks the data length and specific data patterns to determine the validity of the account. This function should be called whenever there is a need to validate the state of a vote account, especially before processing transactions or updates related to voting.
- **Inputs**:
    - `vote_account`: A pointer to an fd_txn_account_t structure representing the vote account to be checked. Must not be null. The function expects this account to have methods for retrieving data length and data content. Invalid or null pointers may lead to undefined behavior.
- **Output**: Returns a non-zero value if the vote account is correctly initialized and matches one of the expected version sizes; otherwise, returns zero.
- **See also**: [`fd_vote_state_versions_is_correct_and_initialized`](fd_vote_program.c.driver.md#fd_vote_state_versions_is_correct_and_initialized)  (Implementation)


---
### fd\_query\_pubkey\_stake<!-- {{#callable_declaration:fd_query_pubkey_stake}} -->
Queries the delegated stake amount for a given vote account public key.
- **Description**: Use this function to retrieve the amount of delegated stake associated with a specific vote account public key from a given set of vote accounts. This function is useful when you need to determine the stake amount for consensus or voting purposes. It requires a valid public key and a vote accounts structure that contains the necessary mapping information. If the public key does not exist in the vote accounts map, or if the vote accounts structure is not properly initialized, the function will return 0, indicating no stake is associated with the given public key.
- **Inputs**:
    - `pubkey`: A pointer to an fd_pubkey_t structure representing the public key of the vote account. Must not be null, and the caller retains ownership.
    - `vote_accounts`: A pointer to an fd_vote_accounts_t structure containing the vote accounts map. Must not be null, and the caller retains ownership. The structure should be properly initialized with either a vote accounts pool or root; otherwise, the function will return 0.
- **Output**: Returns the amount of delegated stake as an unsigned long integer. Returns 0 if the public key does not exist in the vote accounts map or if the vote accounts structure is not initialized.
- **See also**: [`fd_query_pubkey_stake`](fd_vote_program.c.driver.md#fd_query_pubkey_stake)  (Implementation)


---
### fd\_vote\_get\_state<!-- {{#callable_declaration:fd_vote_get_state}} -->
Retrieve the current state of a vote account.
- **Description**: This function is used to obtain the current state of a specified vote account. It should be called when you need to access the state information of a vote account for processing or validation purposes. The function requires a valid vote account and a scratchpad for temporary data storage. It outputs the state in a versioned format through a pointer. Ensure that the provided pointers are valid and that the output pointer is ready to receive the state data.
- **Inputs**:
    - `self`: A pointer to a constant `fd_txn_account_t` representing the vote account whose state is to be retrieved. Must not be null.
    - `spad`: A pointer to an `fd_spad_t` used as a scratchpad for temporary data storage during the operation. Must not be null.
    - `versioned`: A pointer to a pointer of `fd_vote_state_versioned_t` where the retrieved state will be stored. Must not be null and should be ready to receive the state data.
- **Output**: Returns an integer error code indicating the success or failure of the operation. A return value of 0 indicates success, while non-zero values indicate specific errors.
- **See also**: [`fd_vote_get_state`](fd_vote_program.c.driver.md#fd_vote_get_state)  (Implementation)


---
### fd\_vote\_convert\_to\_current<!-- {{#callable_declaration:fd_vote_convert_to_current}} -->
Converts a versioned vote state to the current format.
- **Description**: Use this function to update a versioned vote state to the current format, ensuring compatibility with the latest vote program requirements. This function should be called when you need to work with the most recent vote state format, particularly after loading or receiving a vote state that may be in an older format. It is essential to ensure that both input parameters are valid and properly initialized before calling this function.
- **Inputs**:
    - `self`: A pointer to a `fd_vote_state_versioned_t` structure representing the versioned vote state to be converted. Must not be null and should be properly initialized.
    - `spad`: A pointer to an `fd_spad_t` structure used during the conversion process. Must not be null and should be properly initialized.
- **Output**: None
- **See also**: [`fd_vote_convert_to_current`](fd_vote_program.c.driver.md#fd_vote_convert_to_current)  (Implementation)


---
### fd\_vote\_record\_timestamp\_vote\_with\_slot<!-- {{#callable_declaration:fd_vote_record_timestamp_vote_with_slot}} -->
Records a timestamp vote for a specific slot.
- **Description**: This function is used to record a timestamp vote associated with a specific slot in the voting context. It should be called when a node operator wants to register a timestamp vote for a given slot and vote account. The function requires a valid execution slot context and a vote account public key. It ensures thread safety by acquiring a write lock on the vote stake lock during the operation. The function handles cases where the vote account pool is not allocated by logging an error. It updates the existing vote if found or inserts a new vote into the map if not.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. Must not be null. The caller retains ownership.
    - `vote_acc`: A pointer to a constant fd_pubkey_t representing the public key of the vote account. Must not be null. The caller retains ownership.
    - `timestamp`: A long integer representing the timestamp to be recorded. There are no specific constraints on the value.
    - `slot`: An unsigned long integer representing the slot number for which the vote is being recorded. There are no specific constraints on the value.
- **Output**: None
- **See also**: [`fd_vote_record_timestamp_vote_with_slot`](fd_vote_program.c.driver.md#fd_vote_record_timestamp_vote_with_slot)  (Implementation)


---
### fd\_vote\_commission\_split<!-- {{#callable_declaration:fd_vote_commission_split}} -->
Calculates the commission split for a vote state.
- **Description**: Use this function to determine the distribution of a commission between a voter and a staker based on the current vote state version. It calculates the portions of a given amount that should be allocated to the voter and the staker, considering the commission rate specified in the vote state. This function should be called when you need to compute the financial distribution for a vote state, ensuring that the vote state is correctly initialized and the result structure is provided for output.
- **Inputs**:
    - `vote_state_versioned`: A pointer to a `fd_vote_state_versioned_t` structure representing the current vote state. The structure must be properly initialized and must not be null. The function uses the commission rate from this structure to calculate the split.
    - `on`: An `ulong` representing the total amount to be split between the voter and the staker. This value is used to calculate the portions based on the commission rate.
    - `result`: A pointer to an `fd_commission_split_t` structure where the function will store the calculated voter and staker portions, as well as a flag indicating if the split is non-trivial. This structure must be allocated by the caller and must not be null.
- **Output**: The function populates the `result` structure with the calculated voter and staker portions and a flag indicating if the split is non-trivial. It does not return a value.
- **See also**: [`fd_vote_commission_split`](fd_vote_program.c.driver.md#fd_vote_commission_split)  (Implementation)


---
### fd\_vote\_store\_account<!-- {{#callable_declaration:fd_vote_store_account}} -->
Stores or removes a vote account based on its lamport balance.
- **Description**: This function is used to manage vote accounts within the context of a Solana node's execution slot. It should be called when there is a need to update the state of a vote account, either by storing it or removing it, depending on its lamport balance. The function requires that the vote account is owned by the Solana vote program, and it operates under a write lock to ensure thread safety. It is important to ensure that the vote account is valid and properly initialized before calling this function.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution context of the current slot. This must not be null and the caller retains ownership.
    - `vote_account`: A pointer to an fd_txn_account_t structure representing the vote account to be stored or removed. This must not be null, and the vote account must be owned by the Solana vote program. The caller retains ownership.
- **Output**: None
- **See also**: [`fd_vote_store_account`](fd_vote_program.c.driver.md#fd_vote_store_account)  (Implementation)



# Purpose
This C header file, `fd_exec.h`, is part of a larger software system, likely related to a blockchain or distributed ledger technology, given the terminology used such as "epoch," "stake," and "slot." The file provides a set of inline functions and data structures that facilitate the generation and management of various execution-related messages and contexts within a replay or execution environment. The primary focus of the file is on handling stake weights, epoch and slot messages, and execution tracking, which are crucial for maintaining the integrity and efficiency of the system's operation.

The file defines several key structures and functions. The `fd_stake_weight_msg_t` structure is used to encapsulate information about stake weights for a given epoch, including the number of staked nodes and slots. Functions like [`generate_stake_weight_msg`](#generate_stake_weight_msg), [`generate_replay_exec_epoch_msg`](#generate_replay_exec_epoch_msg), and [`generate_replay_exec_slot_msg`](#generate_replay_exec_slot_msg) are responsible for formatting memory regions to represent specific message types, which are essential for communication and data consistency across different components of the system. Additionally, the `fd_slice_exec` structure and its associated functions manage the execution state of transactions and microblocks, providing mechanisms to parse, reset, and track execution progress. This file is integral to the system's execution layer, ensuring that messages are correctly formatted and execution states are accurately maintained.
# Imports and Dependencies

---
- `../../flamenco/fd_flamenco_base.h`
- `../../flamenco/runtime/context/fd_exec_epoch_ctx.h`
- `../../flamenco/runtime/context/fd_exec_slot_ctx.h`
- `../../flamenco/runtime/fd_runtime_public.h`
- `../../flamenco/stakes/fd_stakes.h`
- `../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h`


# Global Variables

---
### fd\_slice\_exec\_join
- **Type**: `fd_slice_exec_t *`
- **Description**: The `fd_slice_exec_join` is a function that returns a pointer to an `fd_slice_exec_t` structure. This structure is used to manage the execution of slices, which are segments of memory that contain transactions or microblocks to be processed. The function takes a single argument, `slmem`, which is a pointer to a memory region that is presumably used to initialize or join the execution context.
- **Use**: This function is used to obtain a pointer to an `fd_slice_exec_t` structure, which is essential for managing and executing slices of transactions or microblocks in a memory batch.


# Data Structures

---
### fd\_stake\_weight\_msg\_t
- **Type**: `struct`
- **Members**:
    - `epoch`: Epoch for which the stake weights are valid.
    - `staked_cnt`: Number of staked nodes.
    - `start_slot`: Start slot of the epoch.
    - `slot_cnt`: Number of slots in the epoch.
    - `excluded_stake`: Total stake that is excluded from leader selection.
- **Description**: The `fd_stake_weight_msg_t` structure is used to represent a message containing information about stake weights for a specific epoch in a distributed system. It includes details such as the epoch number, the count of staked nodes, the starting slot of the epoch, the total number of slots in the epoch, and the total stake that is excluded from leader selection. This structure is crucial for managing and communicating stake-related data within the system, ensuring that the correct stake weights are applied during the epoch.


---
### fd\_slice\_exec
- **Type**: `struct`
- **Members**:
    - `mbatch`: Pointer to the memory region sized for max size of a block.
    - `wmark`: Offset into slice where previous bytes have been executed, and following bytes have not.
    - `sz`: Total bytes this slice occupies in mbatch memory.
    - `mblks_rem`: Number of microblocks remaining in the current batch iteration.
    - `txns_rem`: Number of transactions remaining in current microblock iteration.
    - `last_mblk_off`: Stored offset to the last microblock header seen.
    - `last_batch`: Signifies last batch execution.
- **Description**: The `fd_slice_exec` structure is designed to manage and track the execution state of a memory slice within a batch processing context. It holds a pointer to a memory region (`mbatch`) and tracks the execution progress through a watermark (`wmark`). The structure also maintains the size of the slice (`sz`), and counts of remaining microblocks (`mblks_rem`) and transactions (`txns_rem`) to be processed. Additionally, it records the offset of the last microblock header (`last_mblk_off`) and indicates whether the current batch is the last one (`last_batch`). This structure is crucial for efficiently managing the execution flow of transactions and microblocks in a batch processing system.


---
### fd\_slice\_exec\_t
- **Type**: `struct`
- **Members**:
    - `mbatch`: Pointer to the memory region sized for the maximum size of a block.
    - `wmark`: Offset into the slice where previous bytes have been executed, and following bytes have not.
    - `sz`: Total bytes this slice occupies in mbatch memory.
    - `mblks_rem`: Number of microblocks remaining in the current batch iteration.
    - `txns_rem`: Number of transactions remaining in the current microblock iteration.
    - `last_mblk_off`: Stored offset to the last microblock header seen.
    - `last_batch`: Signifies last batch execution.
- **Description**: The `fd_slice_exec_t` structure is designed to manage the execution of slices within a memory batch, specifically for handling microblocks and transactions. It maintains pointers and offsets to track the execution progress, including the number of remaining microblocks and transactions, and the offset of the last microblock header. This structure is crucial for efficiently managing and executing batches of transactions, ensuring that execution can be resumed or continued from the correct point in the memory batch.


# Functions

---
### generate\_stake\_weight\_msg<!-- {{#callable:generate_stake_weight_msg}} -->
The `generate_stake_weight_msg` function formats a stake weight message for a given epoch and outputs it to a specified memory location.
- **Inputs**:
    - `slot_ctx`: A pointer to `fd_exec_slot_ctx_t`, which contains context information for the current execution slot.
    - `runtime_spad`: A pointer to `fd_spad_t`, used for runtime scratchpad memory allocation.
    - `epoch`: An unsigned long integer representing the epoch for which the stake weights are being generated.
    - `stake_weight_msg_out`: A pointer to an unsigned long array where the formatted stake weight message will be output.
- **Control Flow**:
    - Retrieve the epoch bank from the slot context's epoch context.
    - Cast the output memory location to a `fd_stake_weight_msg_t` structure for message formatting.
    - Calculate the stake weights by calling `fd_stake_weights_by_node` with the slot's epoch stakes, the stake weights array, and the runtime scratchpad.
    - Set the `epoch`, `staked_cnt`, `start_slot`, `slot_cnt`, and `excluded_stake` fields of the stake weight message.
    - Return the size of the formatted message, which includes the base size and the size of the stake weights.
- **Output**: The function returns the total size in bytes of the formatted stake weight message, which includes the base message size and the size of the stake weights.


---
### generate\_replay\_exec\_epoch\_msg<!-- {{#callable:generate_replay_exec_epoch_msg}} -->
The `generate_replay_exec_epoch_msg` function formats and populates a `fd_runtime_public_epoch_msg_t` structure with epoch-related data from the provided execution context and runtime resources.
- **Inputs**:
    - `slot_ctx`: A pointer to an `fd_exec_slot_ctx_t` structure containing the execution context for the current slot, including epoch-related data.
    - `runtime_spad`: A pointer to an `fd_spad_t` structure used for memory allocation during the function's execution.
    - `runtime_public_wksp`: A pointer to an `fd_wksp_t` structure representing the workspace for public runtime data.
    - `bank_hash_cmp`: A pointer to an `fd_bank_hash_cmp_t` structure used to obtain a global address for bank hash comparison.
    - `epoch_msg_out`: A pointer to an `fd_runtime_public_epoch_msg_t` structure where the formatted epoch message will be stored.
- **Control Flow**:
    - Copy features, total epoch stake, epoch schedule, rent, and slots per year from `slot_ctx->epoch_ctx` to `epoch_msg_out`.
    - Calculate the global address for bank hash comparison using `fd_wksp_gaddr_fast` and store it in `epoch_msg_out->bank_hash_cmp_gaddr`.
    - Log an error if the global address for bank hash comparison is not obtained successfully.
    - Calculate the size needed to encode stakes and allocate memory for it using `fd_spad_alloc`.
    - Initialize an encoding context with the allocated memory and encode the stakes using `fd_stakes_encode`.
    - Log an error if encoding the stakes fails.
    - Calculate the global address for the encoded stakes and store it in `epoch_msg_out->stakes_encoded_gaddr`.
    - Store the size of the encoded stakes in `epoch_msg_out->stakes_encoded_sz`.
- **Output**: The function outputs a well-formatted `fd_runtime_public_epoch_msg_t` structure with epoch-related data populated from the input execution context and runtime resources.


---
### generate\_replay\_exec\_slot\_msg<!-- {{#callable:generate_replay_exec_slot_msg}} -->
The `generate_replay_exec_slot_msg` function formats a `fd_runtime_public_slot_msg_t` structure with slot execution details and encodes the block hash queue for a given execution slot context.
- **Inputs**:
    - `slot_ctx`: A pointer to an `fd_exec_slot_ctx_t` structure containing the execution slot context, including slot bank and execution recording details.
    - `runtime_spad`: A pointer to an `fd_spad_t` structure used for memory allocation during encoding.
    - `runtime_public_wksp`: A pointer to an `fd_wksp_t` structure representing the workspace for public runtime data.
    - `slot_msg_out`: A pointer to an `fd_runtime_public_slot_msg_t` structure where the formatted slot message will be stored.
- **Control Flow**:
    - Assigns the slot, previous lamports per signature, fee rate governor, and execution recording flag from `slot_ctx` to `slot_msg_out`.
    - Calculates the size needed to encode the block hash queue and allocates memory for it using `fd_spad_alloc`.
    - Initializes an `fd_bincode_encode_ctx_t` structure for encoding the block hash queue.
    - Encodes the block hash queue using `fd_block_hash_queue_encode` and checks for errors.
    - Stores the global address and size of the encoded block hash queue in `slot_msg_out`.
- **Output**: The function outputs a well-formatted `fd_runtime_public_slot_msg_t` structure with execution slot details and encoded block hash queue information.


---
### generate\_hash\_bank\_msg<!-- {{#callable:generate_hash_bank_msg}} -->
The `generate_hash_bank_msg` function initializes a `fd_runtime_public_hash_bank_msg_t` structure with provided address and index values.
- **Inputs**:
    - `task_infos_gaddr`: A `ulong` representing the global address of task information.
    - `lt_hash_gaddr`: A `ulong` representing the global address of the hash.
    - `start_idx`: A `ulong` representing the starting index for the hash bank message.
    - `end_idx`: A `ulong` representing the ending index for the hash bank message.
    - `hash_msg_out`: A pointer to a `fd_runtime_public_hash_bank_msg_t` structure where the message will be stored.
- **Control Flow**:
    - Assigns the value of `task_infos_gaddr` to `hash_msg_out->task_infos_gaddr`.
    - Assigns the value of `lt_hash_gaddr` to `hash_msg_out->lthash_gaddr`.
    - Assigns the value of `start_idx` to `hash_msg_out->start_idx`.
    - Assigns the value of `end_idx` to `hash_msg_out->end_idx`.
- **Output**: The function does not return a value; it modifies the `hash_msg_out` structure in place.


---
### generate\_bpf\_scan\_msg<!-- {{#callable:generate_bpf_scan_msg}} -->
The `generate_bpf_scan_msg` function initializes a `fd_runtime_public_bpf_scan_msg_t` structure with provided index and address values.
- **Inputs**:
    - `start_idx`: The starting index for the BPF scan message.
    - `end_idx`: The ending index for the BPF scan message.
    - `recs_gaddr`: The global address for the records associated with the BPF scan.
    - `is_bpf_gaddr`: The global address indicating whether the scan is a BPF scan.
    - `scan_msg_out`: A pointer to a `fd_runtime_public_bpf_scan_msg_t` structure that will be populated with the provided values.
- **Control Flow**:
    - Assigns the value of `start_idx` to `scan_msg_out->start_idx`.
    - Assigns the value of `end_idx` to `scan_msg_out->end_idx`.
    - Assigns the value of `recs_gaddr` to `scan_msg_out->recs_gaddr`.
    - Assigns the value of `is_bpf_gaddr` to `scan_msg_out->is_bpf_gaddr`.
- **Output**: The function does not return a value; it modifies the `scan_msg_out` structure in place.


---
### fd\_slice\_exec\_txn\_ready<!-- {{#callable:fd_slice_exec_txn_ready}} -->
The `fd_slice_exec_txn_ready` function checks if there are any transactions remaining to be executed in the current microblock iteration.
- **Inputs**:
    - `slice_exec_ctx`: A pointer to an `fd_slice_exec_t` structure, which contains the execution context for a slice, including the number of transactions remaining (`txns_rem`).
- **Control Flow**:
    - The function accesses the `txns_rem` field of the `fd_slice_exec_t` structure pointed to by `slice_exec_ctx`.
    - It evaluates whether `txns_rem` is greater than 0, indicating that there are transactions left to process.
- **Output**: The function returns an integer value: 1 if there are transactions remaining (`txns_rem > 0`), otherwise 0.


---
### fd\_slice\_exec\_microblock\_ready<!-- {{#callable:fd_slice_exec_microblock_ready}} -->
The function `fd_slice_exec_microblock_ready` checks if the current execution context is ready to process a new microblock by ensuring there are no remaining transactions and there are remaining microblocks.
- **Inputs**:
    - `slice_exec_ctx`: A pointer to an `fd_slice_exec_t` structure representing the current execution context, which contains information about the number of remaining transactions and microblocks.
- **Control Flow**:
    - The function checks if `txns_rem` is equal to 0, indicating there are no remaining transactions to process.
    - It also checks if `mblks_rem` is greater than 0, indicating there are remaining microblocks to process.
    - The function returns the result of the logical AND operation between these two conditions.
- **Output**: The function returns an integer value, which is 1 (true) if there are no remaining transactions and there are remaining microblocks, otherwise it returns 0 (false).


---
### fd\_slice\_exec\_slice\_ready<!-- {{#callable:fd_slice_exec_slice_ready}} -->
The `fd_slice_exec_slice_ready` function checks if both transactions and microblocks are completely processed in the given execution context.
- **Inputs**:
    - `slice_exec_ctx`: A pointer to an `fd_slice_exec_t` structure representing the execution context, which contains information about the remaining transactions and microblocks.
- **Control Flow**:
    - The function accesses the `txns_rem` and `mblks_rem` fields of the `fd_slice_exec_t` structure pointed to by `slice_exec_ctx`.
    - It evaluates whether both `txns_rem` is equal to 0 and `mblks_rem` is equal to 0UL.
    - The function returns the result of the logical AND operation between these two conditions.
- **Output**: The function returns an integer value, which is 1 if both transactions and microblocks are fully processed (i.e., `txns_rem` and `mblks_rem` are both 0), and 0 otherwise.


---
### fd\_slice\_exec\_slot\_complete<!-- {{#callable:fd_slice_exec_slot_complete}} -->
The function `fd_slice_exec_slot_complete` checks if the execution of a slot is complete by verifying that it is the last batch and there are no remaining microblocks or transactions.
- **Inputs**:
    - `slice_exec_ctx`: A pointer to an `fd_slice_exec_t` structure that contains the execution context of the current slice, including information about the batch, microblocks, and transactions.
- **Control Flow**:
    - The function accesses the `last_batch` member of the `fd_slice_exec_t` structure to check if the current batch is the last one.
    - It checks if `mblks_rem` (remaining microblocks) is equal to 0, indicating no more microblocks are left to process.
    - It checks if `txns_rem` (remaining transactions) is equal to 0, indicating no more transactions are left to process.
    - The function returns the result of the logical AND operation of the above three conditions.
- **Output**: The function returns an integer value, which is non-zero (true) if the slot execution is complete (i.e., it is the last batch and there are no remaining microblocks or transactions), and zero (false) otherwise.


# Function Declarations (Public API)

---
### fd\_slice\_exec\_join<!-- {{#callable_declaration:fd_slice_exec_join}} -->
Initializes a slice execution context from shared memory.
- **Description**: This function is used to initialize a slice execution context from a given shared memory region. It should be called when a new execution context is needed, and the memory region is expected to be properly allocated and aligned for a `fd_slice_exec_t` structure. The function will reset the context to a default state, preparing it for use in execution tracking. It is important to ensure that the memory region is valid and not null before calling this function.
- **Inputs**:
    - `slmem`: A pointer to a memory region that will be used to initialize the slice execution context. This memory must be allocated and aligned appropriately for a `fd_slice_exec_t` structure. The pointer must not be null, and the caller retains ownership of the memory.
- **Output**: Returns a pointer to the initialized `fd_slice_exec_t` structure, which is the same as the input memory region.
- **See also**: [`fd_slice_exec_join`](fd_exec.c.driver.md#fd_slice_exec_join)  (Implementation)


---
### fd\_slice\_exec\_txn\_parse<!-- {{#callable_declaration:fd_slice_exec_txn_parse}} -->
Parses a transaction from the current execution context.
- **Description**: This function is used to parse a transaction from the provided execution context, extracting the transaction payload and updating the context's watermark and transaction count. It should be called when a transaction needs to be processed from the current slice execution context. The function assumes that the execution context is properly initialized and contains valid data. It updates the output transaction structure with the parsed payload and its size. The function logs an error if parsing fails or if the transaction size exceeds the maximum allowed size.
- **Inputs**:
    - `slice_exec_ctx`: A pointer to an fd_slice_exec_t structure representing the current execution context. It must be properly initialized and not null. The function updates its watermark and transaction count.
    - `txn_p_out`: A pointer to an fd_txn_p_t structure where the parsed transaction payload and size will be stored. It must be a valid pointer and not null.
- **Output**: None
- **See also**: [`fd_slice_exec_txn_parse`](fd_exec.c.driver.md#fd_slice_exec_txn_parse)  (Implementation)


---
### fd\_slice\_exec\_microblock\_parse<!-- {{#callable_declaration:fd_slice_exec_microblock_parse}} -->
Parses the next microblock header in the execution context.
- **Description**: Use this function to parse the header of the next microblock in the execution context, updating the context's state to reflect the parsed microblock. This function should be called when the execution context is ready to process a new microblock, as indicated by the `fd_slice_exec_microblock_ready` function. It updates the watermark and the number of remaining microblocks and transactions in the context. Ensure that the execution context is properly initialized and contains valid data before calling this function.
- **Inputs**:
    - `slice_exec_ctx`: A pointer to an `fd_slice_exec_t` structure representing the execution context. This parameter must not be null and should point to a valid, initialized execution context. The function updates this context with information from the parsed microblock header.
- **Output**: None
- **See also**: [`fd_slice_exec_microblock_parse`](fd_exec.c.driver.md#fd_slice_exec_microblock_parse)  (Implementation)


---
### fd\_slice\_exec\_reset<!-- {{#callable_declaration:fd_slice_exec_reset}} -->
Resets the execution context for a slice.
- **Description**: Use this function to reset the state of a slice execution context to its initial state. This is typically done before starting a new execution cycle or when reinitializing the context for reuse. It clears all counters and markers related to batch and microblock processing, ensuring that the context is ready for a fresh execution sequence. This function should be called when the context is not actively being used for execution.
- **Inputs**:
    - `slice_exec_ctx`: A pointer to an fd_slice_exec_t structure representing the execution context to be reset. Must not be null. The caller retains ownership of the context.
- **Output**: None
- **See also**: [`fd_slice_exec_reset`](fd_exec.c.driver.md#fd_slice_exec_reset)  (Implementation)


---
### fd\_slice\_exec\_begin<!-- {{#callable_declaration:fd_slice_exec_begin}} -->
Initialize a slice execution context for a new execution batch.
- **Description**: This function prepares a slice execution context for processing a new batch of data. It sets the size of the slice, marks whether this is the last batch, and initializes internal counters and markers to their starting states. This function should be called before beginning the execution of a new batch to ensure the context is correctly set up. It is important to ensure that the `slice_exec_ctx` is a valid pointer to an initialized `fd_slice_exec_t` structure before calling this function.
- **Inputs**:
    - `slice_exec_ctx`: A pointer to an `fd_slice_exec_t` structure that will be initialized for the new execution batch. Must not be null.
    - `slice_sz`: The size of the slice in bytes. This value is used to set the size of the execution context.
    - `last_batch`: An integer flag indicating whether this is the last batch to be executed. Non-zero values signify the last batch.
- **Output**: None
- **See also**: [`fd_slice_exec_begin`](fd_exec.c.driver.md#fd_slice_exec_begin)  (Implementation)



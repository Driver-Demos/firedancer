# Purpose
This C source code file is part of a larger system that appears to be involved in executing and managing transactions within a distributed or parallel computing environment. The file defines and implements the functionality for an "execution tile," which is a component responsible for processing transactions, managing state transitions (such as epochs and slots), and interacting with other components like replay and writer tiles. The code is structured around a central context (`fd_exec_tile_ctx_t`) that maintains the state and configuration necessary for the execution tile to perform its tasks. This includes managing memory workspaces, transaction contexts, and various runtime parameters.

The file includes several functions that handle different aspects of transaction processing, such as preparing for new epochs and slots, executing transactions, hashing accounts, and scanning for BPF (Berkeley Packet Filter) programs. It also manages the lifecycle of transactions and slots using a stack-like structure (`exec_spad`) to ensure proper allocation and deallocation of resources. The code is designed to be integrated into a larger system, as indicated by its use of external headers and its reliance on specific data structures and conventions (e.g., `fd_spad`, `fd_funk`, `fd_runtime`). The file also includes setup and initialization routines for the execution tile, ensuring that it is correctly configured within the system's topology and can communicate with other components via defined interfaces and message-passing mechanisms.
# Imports and Dependencies

---
- `stdlib.h`
- `../../disco/tiles.h`
- `generated/fd_exec_tile_seccomp.h`
- `../../util/pod/fd_pod_format.h`
- `../../flamenco/runtime/fd_runtime.h`
- `../../flamenco/runtime/fd_runtime_public.h`
- `../../flamenco/runtime/fd_executor.h`
- `../../flamenco/runtime/fd_hashes.h`
- `../../flamenco/runtime/program/fd_bpf_program_util.h`
- `../../funk/fd_funk.h`
- `../../funk/fd_funk_filemap.h`
- `../../disco/stem/fd_stem.c`


# Global Variables

---
### privileged\_init
- **Type**: `function`
- **Description**: The `privileged_init` function is a static function defined at the top level of the file. It takes two parameters, `fd_topo_t *topo` and `fd_topo_tile_t *tile`, both marked as unused with `FD_PARAM_UNUSED`. The function body is currently empty, indicating that it is either a placeholder for future implementation or its functionality is not required in the current context.
- **Use**: This function is intended to perform initialization tasks that require elevated privileges, but it is currently not implemented.


---
### fd\_tile\_execor
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_execor` is a global variable of type `fd_topo_run_tile_t`, which is a structure used to define the execution parameters and functions for a tile in a topology. This structure includes fields for the tile's name, memory footprint, security policies, initialization functions, and the main execution function.
- **Use**: This variable is used to configure and manage the execution of a tile within a distributed system, specifying its initialization, security, and runtime behavior.


# Data Structures

---
### fd\_exec\_tile\_out\_ctx
- **Type**: `struct`
- **Members**:
    - `idx`: An unsigned long integer representing the index of the context.
    - `mem`: A pointer to an fd_wksp_t structure, representing a memory workspace.
    - `chunk`: An unsigned long integer representing the current chunk in use.
    - `chunk0`: An unsigned long integer representing the initial chunk.
    - `wmark`: An unsigned long integer representing the watermark for the chunks.
- **Description**: The `fd_exec_tile_out_ctx` structure is designed to manage the output context for execution tiles in a distributed system. It holds information about the current state of memory allocation and chunk management, including the index, memory workspace, and chunk details. This structure is crucial for managing the execution flow and ensuring that data is processed and stored correctly within the system's memory constraints.


---
### fd\_exec\_tile\_out\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `idx`: An unsigned long integer representing the index of the execution tile.
    - `mem`: A pointer to an fd_wksp_t structure, representing the memory workspace associated with the execution tile.
    - `chunk`: An unsigned long integer representing the current chunk in the memory workspace.
    - `chunk0`: An unsigned long integer representing the initial chunk in the memory workspace.
    - `wmark`: An unsigned long integer representing the watermark for the memory workspace.
- **Description**: The `fd_exec_tile_out_ctx_t` structure is used to manage the output context of an execution tile in a distributed computing environment. It contains information about the memory workspace, including the current and initial chunks, as well as a watermark to track memory usage. This structure is essential for managing the execution flow and memory allocation within the execution tile, ensuring that data is processed efficiently and correctly.


---
### fd\_exec\_tile\_ctx
- **Type**: `struct`
- **Members**:
    - `replay_exec_in_idx`: Index for replay execution input.
    - `tile_cnt`: Count of tiles.
    - `tile_idx`: Index of the current tile.
    - `replay_in_mem`: Pointer to replay input memory workspace.
    - `replay_in_chunk0`: Initial chunk for replay input.
    - `replay_in_wmark`: Watermark for replay input.
    - `exec_writer_out`: Output context for execution writer.
    - `boot_msg_sent`: Flag indicating if the boot message has been sent.
    - `runtime_public_wksp`: Pointer to runtime public workspace.
    - `runtime_public`: Pointer to runtime public data.
    - `runtime_spad`: Pointer to runtime scratchpad.
    - `exec_spad`: Pointer to execution scratchpad.
    - `exec_spad_wksp`: Pointer to execution scratchpad workspace.
    - `pending_txn_pop`: Flag for pending transaction pop.
    - `pending_slot_pop`: Flag for pending slot pop.
    - `pending_epoch_pop`: Flag for pending epoch pop.
    - `funk`: Funk-specific data structure.
    - `funk_wksp`: Pointer to funk workspace.
    - `txn`: Transaction data structure.
    - `txn_ctx`: Pointer to transaction context.
    - `exec_res`: Execution result status.
    - `txn_id`: Transaction identifier.
    - `bpf_id`: BPF cache update identifier.
    - `exec_fseq`: Pointer to execution sequence.
    - `pairs_len`: Length of account pairs to hash.
- **Description**: The `fd_exec_tile_ctx` structure is a comprehensive data structure used to manage the execution context of a tile in a distributed system. It includes various fields for handling replay execution inputs, managing runtime and execution scratchpads, and maintaining transaction contexts. The structure is designed to facilitate the execution of transactions, manage frame lifetimes for transactions, slots, and epochs, and handle specific functionalities related to the 'funk' system. It also includes mechanisms for managing sequence numbers to prevent race conditions and ensure proper execution flow.


---
### fd\_exec\_tile\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `replay_exec_in_idx`: Index of the replay execution input link.
    - `tile_cnt`: Count of tiles in the topology.
    - `tile_idx`: Index of the current tile.
    - `replay_in_mem`: Pointer to the workspace memory for replay input.
    - `replay_in_chunk0`: Initial chunk index for replay input.
    - `replay_in_wmark`: Watermark for replay input chunks.
    - `exec_writer_out`: Output context for the execution writer.
    - `boot_msg_sent`: Flag indicating if the boot message has been sent.
    - `runtime_public_wksp`: Pointer to the runtime public workspace.
    - `runtime_public`: Pointer to the runtime public structure.
    - `runtime_spad`: Pointer to the runtime scratchpad.
    - `exec_spad`: Pointer to the execution scratchpad.
    - `exec_spad_wksp`: Pointer to the workspace containing the execution scratchpad.
    - `pending_txn_pop`: Flag indicating if a transaction frame needs to be popped.
    - `pending_slot_pop`: Flag indicating if a slot frame needs to be popped.
    - `pending_epoch_pop`: Flag indicating if an epoch frame needs to be popped.
    - `funk`: Funk-specific data structure for transaction management.
    - `funk_wksp`: Pointer to the workspace containing funk data.
    - `txn`: Transaction data structure refreshed with each transaction.
    - `txn_ctx`: Pointer to the execution transaction context.
    - `exec_res`: Result of the last transaction execution.
    - `txn_id`: Monotonically increasing transaction identifier.
    - `bpf_id`: Identifier for updates to the BPF cache.
    - `exec_fseq`: Pointer to the execution sequence number.
    - `pairs_len`: Number of accounts to hash.
- **Description**: The `fd_exec_tile_ctx_t` structure is a complex data structure used in a tile-based execution environment, managing various aspects of transaction execution, memory management, and communication between different components of the system. It includes fields for managing input and output links, runtime and execution contexts, transaction management, and synchronization mechanisms. The structure is designed to handle the lifecycle of transactions, slots, and epochs, ensuring proper allocation and deallocation of resources, and maintaining the state of execution through various flags and identifiers.


# Functions

---
### scratch\_align<!-- {{#callable:scratch_align}} -->
The `scratch_align` function returns a constant alignment value of 128 bytes.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests the compiler to inline it for performance.
    - It returns a constant value of 128UL, which is an unsigned long integer representing the alignment size.
- **Output**: The function outputs a constant unsigned long integer value of 128, representing the alignment size.


---
### scratch\_footprint<!-- {{#callable:scratch_footprint}} -->
The `scratch_footprint` function calculates the memory footprint required for a `fd_exec_tile_ctx_t` structure, aligned to the value returned by [`scratch_align`](#scratch_align).
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, which is marked as unused in this function.
- **Control Flow**:
    - Initialize a variable `l` with `FD_LAYOUT_INIT`.
    - Append the size and alignment of `fd_exec_tile_ctx_t` to `l` using `FD_LAYOUT_APPEND`.
    - Finalize the layout with `FD_LAYOUT_FINI`, using the alignment value from `scratch_align()`, and return the result.
- **Output**: The function returns an `ulong` representing the calculated memory footprint for the `fd_exec_tile_ctx_t` structure, aligned as specified.
- **Functions called**:
    - [`scratch_align`](#scratch_align)


---
### prepare\_new\_epoch\_execution<!-- {{#callable:prepare_new_epoch_execution}} -->
The `prepare_new_epoch_execution` function initializes and updates the execution context for a new epoch by managing memory frames, updating transaction context with epoch data, and decoding necessary information from the workspace.
- **Inputs**:
    - `ctx`: A pointer to `fd_exec_tile_ctx_t`, which is the execution context containing various runtime and transaction-related data structures.
    - `epoch_msg`: A pointer to `fd_runtime_public_epoch_msg_t`, which contains the epoch-specific data needed to update the execution context.
- **Control Flow**:
    - Check if transaction-level, slot-level, or epoch-level frames need to be popped from the execution stack and do so if necessary.
    - Push a new frame onto the execution stack to prepare for the new epoch.
    - Update the transaction context (`txn_ctx`) with features, total epoch stake, schedule, rent, and slots per year from the `epoch_msg`.
    - Retrieve the encoded stakes from the workspace using the address provided in `epoch_msg` and decode it into the execution context's stakes.
    - Retrieve and join the bank hash comparison object from the workspace using the address provided in `epoch_msg` and update the transaction context with it.
- **Output**: The function does not return a value; it updates the execution context (`ctx`) in place with new epoch data.


---
### prepare\_new\_slot\_execution<!-- {{#callable:prepare_new_slot_execution}} -->
The `prepare_new_slot_execution` function initializes and prepares the execution context for a new slot by managing stack frames, querying transaction maps, and decoding block hash queues.
- **Inputs**:
    - `ctx`: A pointer to the `fd_exec_tile_ctx_t` structure, which holds the execution context for the tile.
    - `slot_msg`: A pointer to the `fd_runtime_public_slot_msg_t` structure, which contains information about the new slot, such as slot number, previous lamports per signature, fee rate governor, and block hash queue details.
- **Control Flow**:
    - Check if transaction-level information needs to be refreshed by popping the transaction frame if `ctx->pending_txn_pop` is true, and reset `ctx->pending_txn_pop` to 0.
    - Check if slot-level information needs to be refreshed by popping the slot frame if `ctx->pending_slot_pop` is true, and reset `ctx->pending_slot_pop` to 0.
    - Push a new frame onto the execution stack (`exec_spad`) and set `ctx->pending_slot_pop` to 1 to indicate that the slot frame needs to be popped at the start of the next slot.
    - Retrieve the transaction map using `fd_funk_txn_map` and check if it is valid; log an error if not.
    - Create a transaction ID (`xid`) using the slot number from `slot_msg` and query the transaction using `fd_funk_txn_query`; log an error if the transaction is not found.
    - Assign the found transaction to `ctx->txn_ctx->funk_txn`.
    - Update the transaction context (`ctx->txn_ctx`) with slot information from `slot_msg`, including slot number, previous lamports per signature, fee rate governor, and execution recording flag.
    - Decode the block hash queue from the encoded data in `slot_msg` using `fd_bincode_decode_spad` and log an error if decoding fails.
    - Assign the decoded block hash queue to `ctx->txn_ctx->block_hash_queue`.
- **Output**: The function does not return a value; it modifies the execution context (`ctx`) in place to prepare for the new slot.


---
### execute\_txn<!-- {{#callable:execute_txn}} -->
The `execute_txn` function manages the execution of a transaction by setting up the necessary context, verifying the transaction, executing it, and handling the results.
- **Inputs**:
    - `ctx`: A pointer to an `fd_exec_tile_ctx_t` structure, which contains the context and state information necessary for executing a transaction.
- **Control Flow**:
    - Check if there is a pending transaction frame to pop from the execution stack and pop it if necessary.
    - Push a new frame onto the execution stack for the current transaction.
    - Initialize a `fd_execute_txn_task_info_t` structure with the transaction context, execution result, and transaction details.
    - Retrieve the transaction descriptor and prepare a raw transaction structure with the payload and size.
    - Set the transaction flags to indicate successful sanitization.
    - Set up the transaction context using the transaction descriptor and raw transaction.
    - Attempt to set up accessed accounts for the transaction; if this fails, clear the transaction flags and set the execution result to the error code, then return.
    - Verify the transaction; if verification fails, log a warning, clear the transaction flags, set the execution result to a signature failure error code, and return.
    - Perform a pre-execution check; if the transaction flags do not indicate successful sanitization, return.
    - Execute the transaction and update the transaction flags to indicate successful execution.
    - If the execution result indicates success, reclaim the accounts associated with the transaction.
- **Output**: The function does not return a value but updates the transaction context and execution result within the `fd_exec_tile_ctx_t` structure.


---
### hash\_accounts<!-- {{#callable:hash_accounts}} -->
The `hash_accounts` function hashes a range of accounts using task information and updates a hash value in a specified workspace.
- **Inputs**:
    - `ctx`: A pointer to the `fd_exec_tile_ctx_t` structure, which contains context information for the execution tile, including transaction context and workspace pointers.
    - `msg`: A pointer to the `fd_runtime_public_hash_bank_msg_t` structure, which contains message data including the start and end indices for the accounts to be hashed, and global addresses for task information and hash values.
- **Control Flow**:
    - Retrieve the start and end indices from the `msg` structure.
    - Fetch the task information array using the global address from `msg` and the workspace in `ctx`.
    - Check if the task information array is successfully retrieved; log an error if not.
    - Check if the `lthash_gaddr` in `msg` is non-zero; log an error if it is zero.
    - Fetch the hash value using the global address from `msg` and the workspace in `ctx`.
    - Check if the hash value is successfully retrieved; log an error if not.
    - Initialize the hash value to zero using `fd_lthash_zero`.
    - Iterate over the range from `start_idx` to `end_idx`, inclusive.
    - For each index, call `fd_account_hash` to hash the account and update the hash value.
- **Output**: The function does not return a value; it updates the hash value in the workspace specified by `lthash_gaddr`.


---
### bpf\_scan\_accounts<!-- {{#callable:bpf_scan_accounts}} -->
The `bpf_scan_accounts` function scans a range of account records to determine if they are BPF programs and updates a corresponding array with the results.
- **Inputs**:
    - `ctx`: A pointer to an `fd_exec_tile_ctx_t` structure, which contains context information for the execution tile, including workspace pointers and transaction context.
    - `msg`: A pointer to an `fd_runtime_public_bpf_scan_msg_t` structure, which contains the message data for the BPF scan, including the start and end indices of the accounts to scan and global addresses for the records and BPF status arrays.
- **Control Flow**:
    - Retrieve the start and end indices from the `msg` structure.
    - Use `fd_wksp_laddr_fast` to convert the global address of the records array (`recs_gaddr`) to a local address and check for errors.
    - Use `fd_wksp_laddr_fast` to convert the global address of the BPF status array (`is_bpf_gaddr`) to a local address and check for errors.
    - Retrieve the workspace associated with the transaction context's funk using `fd_funk_wksp`.
    - Iterate over the range from `start_idx` to `end_idx`, inclusive.
    - For each index, retrieve the corresponding record from the `recs` array.
    - Call `fd_bpf_is_bpf_program` to determine if the record is a BPF program and store the result in the `is_bpf` array at the same index.
- **Output**: The function does not return a value; it updates the `is_bpf` array in place to indicate which accounts are BPF programs.


---
### snap\_hash\_count<!-- {{#callable:snap_hash_count}} -->
The `snap_hash_count` function calculates the number of account pairs to hash for a given execution tile context.
- **Inputs**:
    - `ctx`: A pointer to an `fd_exec_tile_ctx_t` structure, which contains the execution context for a tile, including information about the current tile index and count.
- **Control Flow**:
    - The function calls `fd_accounts_sorted_subrange_count` with the `funk` member of `ctx`, and the `tile_idx` and `tile_cnt` members cast to `uint`.
    - The result of this call is assigned to the `pairs_len` member of `ctx`.
- **Output**: The function does not return a value; it modifies the `pairs_len` member of the `ctx` structure to store the count of account pairs.


---
### snap\_hash\_gather<!-- {{#callable:snap_hash_gather}} -->
The `snap_hash_gather` function retrieves and processes account hash data from a workspace, ensuring the necessary data structures are joined and then invoking a subrange gather operation.
- **Inputs**:
    - `ctx`: A pointer to a `fd_exec_tile_ctx_t` structure, which contains context information for the execution tile, including workspace pointers and execution state.
    - `msg`: A pointer to a `fd_runtime_public_snap_hash_msg_t` structure, which contains message data including global addresses for output pairs, pairs, and hash values.
- **Control Flow**:
    - Retrieve the number of pairs from the workspace using the global address provided in `msg->num_pairs_out_gaddr` and check for successful joining.
    - Retrieve the pairs from the workspace using the global address provided in `msg->pairs_gaddr` and check for successful joining.
    - Retrieve the hash values from the workspace using the global address provided in `msg->lt_hash_value_out_gaddr` and check for successful joining.
    - Call `fd_accounts_sorted_subrange_gather` with the context's funk, tile index, tile count, and the retrieved data to perform the gather operation.
- **Output**: The function does not return a value; it performs operations on the data structures pointed to by the input arguments.


---
### during\_frag<!-- {{#callable:during_frag}} -->
The `during_frag` function processes incoming messages based on their signature and performs corresponding actions such as executing transactions, preparing new slot or epoch executions, hashing accounts, scanning BPF programs, or handling snapshot hash operations.
- **Inputs**:
    - `ctx`: A pointer to the `fd_exec_tile_ctx_t` structure, which contains the execution context and state information for the tile.
    - `in_idx`: An unsigned long integer representing the index of the incoming message.
    - `seq`: An unsigned long integer representing the sequence number of the message (unused in this function).
    - `sig`: An unsigned long integer representing the signature of the message, which determines the type of action to be taken.
    - `chunk`: An unsigned long integer representing the memory chunk where the message is located.
    - `sz`: An unsigned long integer representing the size of the message.
    - `ctl`: An unsigned long integer representing control information (unused in this function).
- **Control Flow**:
    - Check if `in_idx` matches `ctx->replay_exec_in_idx` to ensure the message is from the expected source.
    - Verify that `chunk` is within the valid range defined by `ctx->replay_in_chunk0` and `ctx->replay_in_wmark`; log an error if not.
    - Based on the `sig` value, determine the type of message and execute the corresponding action:
    - If `sig` is `EXEC_NEW_TXN_SIG`, retrieve the transaction message, update the context, and execute the transaction.
    - If `sig` is `EXEC_NEW_SLOT_SIG`, retrieve the slot message, log the event, and prepare for new slot execution.
    - If `sig` is `EXEC_NEW_EPOCH_SIG`, retrieve the epoch message, log the event, and prepare for new epoch execution.
    - If `sig` is `EXEC_HASH_ACCS_SIG`, retrieve the hash bank message, log the event, and hash the accounts.
    - If `sig` is `EXEC_BPF_SCAN_SIG`, retrieve the BPF scan message, log the event, and perform a BPF scan on accounts.
    - If `sig` is `EXEC_SNAP_HASH_ACCS_CNT_SIG`, log the event and perform a snapshot hash count.
    - If `sig` is `EXEC_SNAP_HASH_ACCS_GATHER_SIG`, retrieve the snapshot hash message, log the event, and gather snapshot hashes.
    - Log an error if the `sig` does not match any known signature.
- **Output**: The function does not return a value; it performs actions based on the message signature and updates the execution context accordingly.
- **Functions called**:
    - [`execute_txn`](#execute_txn)
    - [`prepare_new_slot_execution`](#prepare_new_slot_execution)
    - [`prepare_new_epoch_execution`](#prepare_new_epoch_execution)
    - [`hash_accounts`](#hash_accounts)
    - [`bpf_scan_accounts`](#bpf_scan_accounts)
    - [`snap_hash_count`](#snap_hash_count)
    - [`snap_hash_gather`](#snap_hash_gather)


---
### after\_frag<!-- {{#callable:after_frag}} -->
The `after_frag` function processes different message signatures to update execution states and send acknowledgments in a distributed execution context.
- **Inputs**:
    - `ctx`: A pointer to the `fd_exec_tile_ctx_t` structure, which holds the execution context and state information for the tile.
    - `in_idx`: An unsigned long integer representing the input index, marked as unused in this function.
    - `seq`: An unsigned long integer representing the sequence number, marked as unused in this function.
    - `sig`: An unsigned long integer representing the message signature that determines the type of message being processed.
    - `sz`: An unsigned long integer representing the size of the message, marked as unused in this function.
    - `tsorig`: An unsigned long integer representing the original timestamp of the message.
    - `tspub`: An unsigned long integer representing the publication timestamp of the message.
    - `stem`: A pointer to the `fd_stem_context_t` structure, which is used for publishing messages.
- **Control Flow**:
    - Check if the `sig` matches `EXEC_NEW_SLOT_SIG`, log a debug message, and update the execution sequence to indicate the slot is done.
    - Check if the `sig` matches `EXEC_NEW_EPOCH_SIG`, log a debug message, and update the execution sequence to indicate the epoch is done.
    - Check if the `sig` matches `EXEC_NEW_TXN_SIG`, log a debug message, update the transaction context with execution results, prepare a message for the writer tile, publish the message, and update the chunk for the next message.
    - Check if the `sig` matches `EXEC_HASH_ACCS_SIG`, log a debug message, and update the execution sequence to indicate the hash accounts process is done.
    - Check if the `sig` matches `EXEC_BPF_SCAN_SIG`, log a debug message with the BPF ID, update the execution sequence to indicate the BPF scan is done, and increment the BPF ID, resetting it if it reaches the sentinel value.
    - Check if the `sig` matches `EXEC_SNAP_HASH_ACCS_CNT_SIG`, log a notice message with the pairs length, and update the execution sequence to indicate the snap hash count process is done.
    - Check if the `sig` matches `EXEC_SNAP_HASH_ACCS_GATHER_SIG`, log a notice message, and update the execution sequence to indicate the snap hash gather process is done.
    - If none of the known signatures match, log an error message indicating an unknown message signature.
- **Output**: The function does not return a value; it performs actions based on the message signature to update execution states and send acknowledgments.


---
### unprivileged\_init<!-- {{#callable:unprivileged_init}} -->
The `unprivileged_init` function initializes an execution tile in a distributed system by setting up memory allocations, validating links, joining runtime and execution contexts, and preparing for transaction processing.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology of the distributed system.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile (or node) in the topology to be initialized.
- **Control Flow**:
    - Allocate scratch memory for the execution context using `fd_topo_obj_laddr` and `FD_SCRATCH_ALLOC_*` macros.
    - Validate the allocated memory size against the expected footprint using [`scratch_footprint`](#scratch_footprint).
    - Determine the number of tiles and the index of the current tile using `fd_topo_tile_name_cnt` and `tile->kind_id`.
    - Find and validate the in-link from the replay tile to the execution tile using `fd_topo_find_tile_in_link` and set up memory pointers for incoming data.
    - Find and validate the out-link to the exec writer using `fd_topo_find_tile_out_link` and set up memory pointers for outgoing data.
    - Join the runtime public workspace and validate its existence using `fd_runtime_public_join` and `fd_runtime_public_spad`.
    - Join the execution spad and validate its existence using `fd_spad_join` and `fd_wksp_containing`.
    - Initialize funk-specific settings by joining the funk file and workspace using `fd_funk_open_file` and `fd_funk_wksp`.
    - Allocate and join the transaction context using `fd_spad_alloc_check`, `fd_exec_txn_ctx_new`, and `fd_exec_txn_ctx_join`.
    - Join the execution sequence using `fd_fseq_join` and update its state to `FD_EXEC_STATE_NOT_BOOTED`.
    - Initialize transaction and BPF IDs to zero.
- **Output**: The function does not return a value; it initializes the execution context and sets up the necessary links and memory for processing transactions.
- **Functions called**:
    - [`scratch_align`](#scratch_align)
    - [`scratch_footprint`](#scratch_footprint)


---
### after\_credit<!-- {{#callable:after_credit}} -->
The `after_credit` function initializes and sends a boot message to writer and replay tiles if it hasn't been sent yet.
- **Inputs**:
    - `ctx`: A pointer to an `fd_exec_tile_ctx_t` structure, which contains the execution context for the tile.
    - `stem`: A pointer to an `fd_stem_context_t` structure, which is used for publishing messages.
    - `opt_poll_in`: An optional pointer to an integer, not used in this function.
    - `charge_busy`: An optional pointer to an integer, not used in this function.
- **Control Flow**:
    - Check if the boot message has already been sent using `ctx->boot_msg_sent`.
    - If not sent, set `ctx->boot_msg_sent` to 1 to indicate the boot message will be sent.
    - Calculate the global address (`gaddr`) for `txn_ctx` and `exec_spad` using `fd_wksp_gaddr`.
    - Log a critical error if either `txn_ctx_gaddr` or `exec_spad_gaddr` is zero.
    - Calculate the offset of `txn_ctx` from `exec_spad` and log a critical error if the offset is greater than `UINT_MAX`.
    - Prepare a boot message with the calculated `txn_ctx_offset`.
    - Publish the boot message to writer tiles using `fd_stem_publish`.
    - Update the execution sequence (`exec_fseq`) to indicate the boot message has been sent using `fd_fseq_update`.
- **Output**: The function does not return a value; it performs actions to send a boot message and update the execution context.


---
### populate\_allowed\_seccomp<!-- {{#callable:populate_allowed_seccomp}} -->
The `populate_allowed_seccomp` function populates a seccomp filter policy for an execution tile and returns the instruction count for the policy.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, representing the topology configuration.
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure, representing the tile configuration.
    - `out_cnt`: An unsigned long integer representing the count of output filters to be populated.
    - `out`: A pointer to a `struct sock_filter` array where the seccomp filter policy will be populated.
- **Control Flow**:
    - The function begins by casting the `topo` and `tile` parameters to void to indicate they are unused.
    - It calls the [`populate_sock_filter_policy_fd_exec_tile`](generated/fd_exec_tile_seccomp.h.driver.md#populate_sock_filter_policy_fd_exec_tile) function with `out_cnt`, `out`, and the file descriptor obtained from `fd_log_private_logfile_fd()`.
    - The function returns the value of `sock_filter_policy_fd_exec_tile_instr_cnt`, which represents the number of instructions in the seccomp filter policy.
- **Output**: The function returns an unsigned long integer representing the number of instructions in the seccomp filter policy.
- **Functions called**:
    - [`populate_sock_filter_policy_fd_exec_tile`](generated/fd_exec_tile_seccomp.h.driver.md#populate_sock_filter_policy_fd_exec_tile)


---
### populate\_allowed\_fds<!-- {{#callable:populate_allowed_fds}} -->
The `populate_allowed_fds` function populates an array with file descriptors that are allowed for use, specifically including standard error and optionally a log file descriptor.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, which represents the topology configuration; however, it is not used in this function.
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure, which represents a tile configuration; however, it is not used in this function.
    - `out_fds_cnt`: An unsigned long integer representing the maximum number of file descriptors that can be stored in the `out_fds` array.
    - `out_fds`: A pointer to an integer array where the allowed file descriptors will be stored.
- **Control Flow**:
    - The function begins by casting `topo` and `tile` to void to indicate they are unused.
    - It checks if `out_fds_cnt` is less than 2, and if so, logs an error and terminates the program.
    - It initializes `out_cnt` to 0 and assigns the file descriptor for standard error (2) to the first position in `out_fds`, incrementing `out_cnt`.
    - It checks if the log file descriptor is valid (not -1) using `fd_log_private_logfile_fd()`, and if valid, assigns it to the next position in `out_fds`, incrementing `out_cnt`.
    - The function returns the count of file descriptors added to `out_fds`.
- **Output**: The function returns an unsigned long integer representing the number of file descriptors that were successfully populated in the `out_fds` array.



# Purpose
The provided C header file defines a public interface for a runtime system, likely part of a larger software framework, possibly related to distributed computing or blockchain technology given the terminology used (e.g., "epoch," "slot," "txn"). The file includes definitions for various constants, data structures, and function prototypes that facilitate the management of execution states and transactions within this runtime environment. It provides a set of APIs for parallel execution, state management, and message handling, which are essential for coordinating tasks across multiple execution units or threads.

Key components of this file include the definition of execution and writer states, callback functions for parallel execution, and several message structures that encapsulate different types of runtime messages (e.g., epoch, slot, transaction, hash bank, BPF scan, and snapshot hash messages). The file also outlines functions for managing execution sequences and writer sequences, which are crucial for tracking the progress and state of various operations within the runtime. Additionally, the file defines a structure for the public runtime interface, which includes features and shared memory management. This header file is intended to be included in other parts of the software, providing a standardized interface for interacting with the runtime system.
# Imports and Dependencies

---
- `../features/fd_features.h`
- `../types/fd_types.h`
- `../../disco/pack/fd_microblock.h`
- `../../disco/fd_disco_base.h`


# Global Variables

---
### fd\_runtime\_public\_new
- **Type**: `function`
- **Description**: The `fd_runtime_public_new` function is responsible for initializing a new instance of a runtime public structure in shared memory. It takes a pointer to shared memory (`shmem`) and a maximum size for the scratchpad memory (`spad_mem_max`) as parameters.
- **Use**: This function is used to allocate and set up a new runtime public structure in shared memory, preparing it for use in the application.


---
### fd\_runtime\_public\_join
- **Type**: `fd_runtime_public_t *`
- **Description**: The `fd_runtime_public_join` is a function that returns a pointer to a `fd_runtime_public_t` structure. This function is used to join a shared memory segment, represented by the `shmem` parameter, to a local `fd_runtime_public_t` instance.
- **Use**: This function is used to access and manipulate the public runtime state stored in shared memory.


---
### fd\_runtime\_public\_spad
- **Type**: `function pointer`
- **Description**: The `fd_runtime_public_spad` is a function that returns a pointer to an `fd_spad_t` structure. It takes a constant pointer to an `fd_runtime_public_t` structure as its argument.
- **Use**: This function is used to obtain a local join of the runtime scratchpad (spad) associated with the given runtime public structure.


# Data Structures

---
### fd\_exec\_para\_cb\_ctx
- **Type**: `struct`
- **Members**:
    - `num_args`: Specifies the number of arguments that the callback function will use.
    - `func`: A function pointer to the callback function that will be executed.
    - `para_arg_1`: A pointer to the first argument used for multithreaded execution.
    - `para_arg_2`: A pointer to the second argument used for multithreaded execution.
    - `fn_arg_1`: A pointer to the first argument used by the core business logic of the function.
    - `fn_arg_2`: A pointer to the second argument used by the core business logic of the function.
    - `fn_arg_3`: A pointer to the third argument used by the core business logic of the function.
    - `fn_arg_4`: A pointer to the fourth argument used by the core business logic of the function.
- **Description**: The `fd_exec_para_cb_ctx` structure is designed to facilitate parallel execution by encapsulating the context required for a callback function. It includes a function pointer `func` that points to the callback function, and several argument pointers (`para_arg_1`, `para_arg_2`, `fn_arg_1`, `fn_arg_2`, `fn_arg_3`, `fn_arg_4`) that are used to pass data to the function. The `para_arg` pointers are specifically for multithreaded execution, while the `fn_arg` pointers are for the core business logic. The `num_args` member indicates how many arguments the function will use, allowing for flexible execution schemes.


---
### fd\_exec\_para\_cb\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `num_args`: Specifies the number of arguments that the callback function will use.
    - `func`: A function pointer to the callback function that will be executed.
    - `para_arg_1`: A pointer to the first parameter used for multithreaded execution.
    - `para_arg_2`: A pointer to the second parameter used for multithreaded execution.
    - `fn_arg_1`: A pointer to the first argument used by the core business logic of the function.
    - `fn_arg_2`: A pointer to the second argument used by the core business logic of the function.
    - `fn_arg_3`: A pointer to the third argument used by the core business logic of the function.
    - `fn_arg_4`: A pointer to the fourth argument used by the core business logic of the function.
- **Description**: The `fd_exec_para_cb_ctx_t` structure is designed to facilitate parallel execution by encapsulating the context required for executing a callback function. It includes a function pointer `func` to the callback function, a `num_args` field indicating the number of arguments, and several pointers (`para_arg_1`, `para_arg_2`, `fn_arg_1`, `fn_arg_2`, `fn_arg_3`, `fn_arg_4`) that provide the necessary arguments for both multithreaded execution and core business logic. This structure is used to manage and execute different execution schemes, such as thread pools or execution tiles, by passing the appropriate arguments to the callback function.


---
### fd\_runtime\_public\_epoch\_msg
- **Type**: `struct`
- **Members**:
    - `features`: Represents the features available in the current runtime context.
    - `total_epoch_stake`: Stores the total stake for the current epoch.
    - `epoch_schedule`: Defines the schedule for epochs in the runtime.
    - `rent`: Holds the rent configuration for the runtime.
    - `slots_per_year`: Indicates the number of slots that occur in a year.
    - `stakes_encoded_gaddr`: Stores the global address for encoded stakes.
    - `stakes_encoded_sz`: Represents the size of the encoded stakes.
    - `bank_hash_cmp_gaddr`: Holds the global address for the bank hash comparison.
- **Description**: The `fd_runtime_public_epoch_msg` structure is designed to encapsulate information related to the epoch in a runtime environment. It includes various fields that define the features, total stake, epoch schedule, and rent configuration, as well as details about the number of slots per year and encoded stake information. This structure is crucial for managing and accessing epoch-related data efficiently within the runtime system.


---
### fd\_runtime\_public\_epoch\_msg\_t
- **Type**: `struct`
- **Members**:
    - `features`: Represents the features enabled in the runtime environment.
    - `total_epoch_stake`: Stores the total stake for the current epoch.
    - `epoch_schedule`: Defines the schedule for epochs in the runtime.
    - `rent`: Holds the rent configuration for the runtime.
    - `slots_per_year`: Indicates the number of slots expected per year.
    - `stakes_encoded_gaddr`: Global address for encoded stakes data.
    - `stakes_encoded_sz`: Size of the encoded stakes data.
    - `bank_hash_cmp_gaddr`: Global address for the bank hash comparison data.
- **Description**: The `fd_runtime_public_epoch_msg_t` structure is designed to encapsulate information related to the epoch in a runtime environment. It includes details about the features enabled, the total stake for the epoch, the schedule of epochs, and rent configurations. Additionally, it provides information about the number of slots per year and contains global addresses and sizes for encoded stakes and bank hash comparison data, which are crucial for managing and verifying the state of the runtime during an epoch.


---
### fd\_runtime\_public\_slot\_msg
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the current slot number in the runtime.
    - `prev_lamports_per_signature`: Stores the previous lamports per signature value.
    - `fee_rate_governor`: Holds the fee rate governor configuration.
    - `block_hash_queue_encoded_gaddr`: Contains the encoded global address of the block hash queue.
    - `block_hash_queue_encoded_sz`: Specifies the size of the encoded block hash queue.
    - `enable_exec_recording`: Indicates whether execution recording is enabled.
- **Description**: The `fd_runtime_public_slot_msg` structure is designed to encapsulate information related to a specific slot in a runtime environment. It includes details such as the slot number, previous lamports per signature, and fee rate governor settings. Additionally, it manages the encoded global address and size of the block hash queue, and a flag to enable or disable execution recording. This structure is crucial for managing and tracking slot-specific data within the runtime.


---
### fd\_runtime\_public\_slot\_msg\_t
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the current slot number in the blockchain.
    - `prev_lamports_per_signature`: Stores the previous lamports per signature value.
    - `fee_rate_governor`: Holds the fee rate governor settings for the slot.
    - `block_hash_queue_encoded_gaddr`: Contains the encoded global address of the block hash queue.
    - `block_hash_queue_encoded_sz`: Specifies the size of the encoded block hash queue.
    - `enable_exec_recording`: Indicates whether execution recording is enabled for the slot.
- **Description**: The `fd_runtime_public_slot_msg_t` structure is designed to encapsulate information related to a specific slot in a blockchain runtime environment. It includes details such as the slot number, previous lamports per signature, and fee rate governor settings. Additionally, it manages the encoded global address and size of the block hash queue, and a flag to enable or disable execution recording for the slot. This structure is crucial for managing and tracking the state and configuration of individual slots within the blockchain's execution framework.


---
### fd\_runtime\_public\_txn\_msg
- **Type**: `struct`
- **Members**:
    - `txn`: A pointer to a transaction structure, represented by `fd_txn_p_t`.
- **Description**: The `fd_runtime_public_txn_msg` structure is a simple data structure designed to encapsulate a transaction message within the runtime public context. It contains a single member, `txn`, which is a pointer to a transaction, allowing for the handling and manipulation of transaction data within the system. This structure is part of a larger framework for managing runtime operations and transactions in a distributed or parallel execution environment.


---
### fd\_runtime\_public\_txn\_msg\_t
- **Type**: `struct`
- **Members**:
    - `txn`: A pointer to a transaction structure, `fd_txn_p_t`, representing the transaction data.
- **Description**: The `fd_runtime_public_txn_msg_t` structure is a simple data structure designed to encapsulate a transaction message within the runtime public interface. It contains a single member, `txn`, which is a pointer to a transaction structure. This structure is likely used to pass transaction data between different components of the system, facilitating operations such as transaction processing or logging within a distributed or parallel execution environment.


---
### fd\_runtime\_public\_hash\_bank\_msg
- **Type**: `struct`
- **Members**:
    - `task_infos_gaddr`: A global address for task information.
    - `lthash_gaddr`: A global address for the ledger transaction hash.
    - `start_idx`: The starting index for processing.
    - `end_idx`: The ending index for processing.
- **Description**: The `fd_runtime_public_hash_bank_msg` structure is designed to encapsulate information related to hash banking operations within a runtime environment. It includes global addresses for task information and ledger transaction hashes, as well as indices that define the range of operations to be processed. This structure is likely used in contexts where hash banking tasks are distributed or managed across different parts of a system, requiring precise control over the data and operations involved.


---
### fd\_runtime\_public\_hash\_bank\_msg\_t
- **Type**: `struct`
- **Members**:
    - `task_infos_gaddr`: Stores the global address of task information.
    - `lthash_gaddr`: Stores the global address of the ledger transaction hash.
    - `start_idx`: Indicates the starting index for processing.
    - `end_idx`: Indicates the ending index for processing.
- **Description**: The `fd_runtime_public_hash_bank_msg_t` structure is designed to encapsulate information related to hash bank messages within a runtime environment. It includes fields for storing global addresses of task information and ledger transaction hashes, as well as indices that define the range of tasks or transactions to be processed. This structure is likely used in the context of managing or processing a batch of tasks or transactions in a distributed or parallel computing environment.


---
### fd\_runtime\_public\_bpf\_scan\_msg
- **Type**: `struct`
- **Members**:
    - `recs_gaddr`: Stores the global address of the records.
    - `is_bpf_gaddr`: Stores the global address indicating if BPF is present.
    - `cache_txn_gaddr`: Stores the global address of the cached transaction.
    - `start_idx`: Indicates the starting index for the scan.
    - `end_idx`: Indicates the ending index for the scan.
- **Description**: The `fd_runtime_public_bpf_scan_msg` structure is designed to facilitate the scanning of BPF (Berkeley Packet Filter) related data within a runtime environment. It contains global addresses for records, BPF presence, and cached transactions, as well as indices that define the range of the scan. This structure is likely used in contexts where BPF data needs to be accessed or manipulated efficiently, providing a compact representation of the necessary parameters for such operations.


---
### fd\_runtime\_public\_bpf\_scan\_msg\_t
- **Type**: `struct`
- **Members**:
    - `recs_gaddr`: Stores the global address of the records.
    - `is_bpf_gaddr`: Stores the global address indicating if the record is a BPF.
    - `cache_txn_gaddr`: Stores the global address of the cached transaction.
    - `start_idx`: Indicates the starting index for the scan.
    - `end_idx`: Indicates the ending index for the scan.
- **Description**: The `fd_runtime_public_bpf_scan_msg_t` structure is designed to facilitate the scanning of BPF (Berkeley Packet Filter) related data within a runtime environment. It contains fields that store global addresses for records, BPF indicators, and cached transactions, as well as indices that define the range of the scan. This structure is likely used in contexts where BPF data needs to be processed or analyzed, providing a way to manage and access relevant data efficiently.


---
### fd\_runtime\_public\_snap\_hash\_msg
- **Type**: `struct`
- **Members**:
    - `num_pairs_out_gaddr`: Stores the global address for the number of pairs output.
    - `lt_hash_value_out_gaddr`: Stores the global address for the output hash value.
    - `pairs_gaddr`: Stores the global address for the pairs.
- **Description**: The `fd_runtime_public_snap_hash_msg` structure is designed to manage and store global addresses related to snapshot hash operations in a runtime environment. It contains fields for the number of pairs, the hash value, and the pairs themselves, all represented as global addresses (gaddr). This structure is likely used in a distributed or parallel processing context where these addresses are needed to access or store data across different nodes or processes.


---
### fd\_runtime\_public\_snap\_hash\_msg\_t
- **Type**: `struct`
- **Members**:
    - `num_pairs_out_gaddr`: Stores the global address for the number of pairs output.
    - `lt_hash_value_out_gaddr`: Stores the global address for the output hash value.
    - `pairs_gaddr`: Stores the global address for the pairs.
- **Description**: The `fd_runtime_public_snap_hash_msg_t` structure is designed to manage and store information related to snapshot hash messages in a runtime environment. It contains addresses for the number of pairs, the hash value, and the pairs themselves, which are likely used in the context of hashing operations or data integrity checks within the system.


---
### fd\_runtime\_public\_exec\_writer\_boot\_msg
- **Type**: `struct`
- **Members**:
    - `txn_ctx_offset`: This member represents the offset of the transaction context.
- **Description**: The `fd_runtime_public_exec_writer_boot_msg` structure is a simple data structure used to encapsulate information related to the boot message of an execution writer in a runtime environment. It contains a single member, `txn_ctx_offset`, which indicates the offset of the transaction context, likely used to manage or reference transaction-related data within a larger system or process.


---
### fd\_runtime\_public\_exec\_writer\_boot\_msg\_t
- **Type**: `struct`
- **Members**:
    - `txn_ctx_offset`: This member represents the offset for the transaction context.
- **Description**: The `fd_runtime_public_exec_writer_boot_msg_t` structure is a simple data structure used within the runtime public execution writer context. It contains a single member, `txn_ctx_offset`, which is an unsigned integer representing the offset for the transaction context. This structure is likely used to initialize or manage the booting process of an execution writer, ensuring that the transaction context is correctly aligned or referenced within the system's memory constraints.


---
### fd\_runtime\_public\_exec\_writer\_txn\_msg
- **Type**: `struct`
- **Members**:
    - `txn_id`: A 32-bit unsigned integer representing the transaction ID.
    - `exec_tile_id`: An 8-bit unsigned character representing the execution tile ID.
- **Description**: The `fd_runtime_public_exec_writer_txn_msg` structure is designed to encapsulate information related to a transaction message within an execution writer context. It contains a transaction ID and an execution tile ID, which are used to uniquely identify and manage transactions across different execution tiles in a distributed or parallel processing environment. This structure is part of a larger system that handles transaction processing and execution state management.


---
### fd\_runtime\_public\_exec\_writer\_txn\_msg\_t
- **Type**: `struct`
- **Members**:
    - `txn_id`: A 32-bit unsigned integer representing the transaction ID.
    - `exec_tile_id`: An 8-bit unsigned character representing the execution tile ID.
- **Description**: The `fd_runtime_public_exec_writer_txn_msg_t` structure is designed to encapsulate information related to a transaction message within the execution writer context. It contains a transaction ID and an execution tile ID, which are used to identify and manage transactions across different execution tiles. This structure is constrained to fit within a predefined maximum transmission unit (MTU) size, ensuring efficient communication and processing within the system.


---
### fd\_runtime\_public\_replay\_writer\_slot\_msg
- **Type**: `struct`
- **Members**:
    - `slot_ctx_gaddr`: A field of type 'ulong' that stores the global address of the slot context.
- **Description**: The `fd_runtime_public_replay_writer_slot_msg` structure is a simple data structure that contains a single member, `slot_ctx_gaddr`, which is used to store the global address of a slot context. This structure is likely used in the context of replaying or writing slot-related data in a distributed or parallel processing environment. The structure is defined to ensure that the size of the message does not exceed a predefined maximum transmission unit (MTU) for replay writer messages.


---
### fd\_runtime\_public\_replay\_writer\_slot\_msg\_t
- **Type**: `struct`
- **Members**:
    - `slot_ctx_gaddr`: Represents the global address of the slot context.
- **Description**: The `fd_runtime_public_replay_writer_slot_msg_t` structure is a simple data structure that contains a single member, `slot_ctx_gaddr`, which holds the global address of the slot context. This structure is used in the context of replay writer operations, where it likely serves as a message or a data packet that carries information about the slot context within a larger system or application. The size of this structure is constrained to be within the maximum transmission unit (MTU) for replay writer messages, ensuring it fits within the expected data limits for communication or storage.


---
### fd\_runtime\_public
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the structure, likely used for validation or versioning.
    - `features`: A copy of the currently active features, represented by the fd_features_t type.
    - `runtime_spad_gaddr`: A global address for the runtime scratchpad, possibly used for shared memory or communication.
- **Description**: The `fd_runtime_public` structure is designed to hold public and readable runtime information, including a unique magic number for identification, a non-fork-aware copy of active features, and a global address for the runtime scratchpad. This structure is part of a larger system that manages execution states and contexts, and it is intended to be used until the epoch and slot contexts are made fork-aware, at which point the features map can be removed. The structure is likely used in a multi-threaded or distributed environment where shared access to runtime state is necessary.


---
### fd\_runtime\_public\_t
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the structure, used to verify its integrity.
    - `features`: A copy of the currently active features, not fork-aware.
    - `runtime_spad_gaddr`: The global address of the runtime scratchpad, part of the runtime.
- **Description**: The `fd_runtime_public_t` structure is designed to represent a public and readable workspace within the runtime environment. It contains a magic number for integrity verification, a non-fork-aware copy of the active features, and a global address for the runtime scratchpad. This structure is part of a larger system that manages execution states and transactions in a parallel execution environment, and it is intended to be used in conjunction with other components to facilitate efficient runtime operations.


# Functions

---
### fd\_exec\_para\_call\_func<!-- {{#callable:FD_FN_UNUSED::fd_exec_para_call_func}} -->
The `fd_exec_para_call_func` function executes a callback function with a set of arguments provided in a context structure.
- **Inputs**:
    - `ctx`: A pointer to a `fd_exec_para_cb_ctx_t` structure containing the callback function and its arguments.
- **Control Flow**:
    - The function retrieves the callback function from the `ctx` structure.
    - It then calls this function with six arguments: two parallel execution arguments (`para_arg_1` and `para_arg_2`) and four function-specific arguments (`fn_arg_1`, `fn_arg_2`, `fn_arg_3`, `fn_arg_4`).
- **Output**: This function does not return any value; it executes the callback function specified in the context.


---
### fd\_exec\_para\_cb\_is\_single\_threaded<!-- {{#callable:FD_FN_UNUSED::fd_exec_para_cb_is_single_threaded}} -->
The function `fd_exec_para_cb_is_single_threaded` checks if a given execution context is configured for single-threaded execution by verifying that its parallel execution arguments are null.
- **Inputs**:
    - `ctx`: A pointer to an `fd_exec_para_cb_ctx_t` structure, which contains context information for parallel execution, including function pointers and arguments.
- **Control Flow**:
    - The function checks if both `para_arg_1` and `para_arg_2` in the `ctx` structure are `NULL`.
    - If both are `NULL`, it indicates that the context is set for single-threaded execution.
- **Output**: The function returns an integer value: `1` if the context is single-threaded (both `para_arg_1` and `para_arg_2` are `NULL`), otherwise `0`.


---
### fd\_exec\_fseq\_get\_state<!-- {{#callable:FD_FN_UNUSED::fd_exec_fseq_get_state}} -->
The function `fd_exec_fseq_get_state` extracts the lower 32 bits of a 64-bit unsigned integer, representing the state of an execution sequence.
- **Inputs**:
    - `fseq`: A 64-bit unsigned integer representing an execution sequence.
- **Control Flow**:
    - The function takes a 64-bit unsigned integer `fseq` as input.
    - It performs a bitwise AND operation between `fseq` and `0xFFFFFFFFU`, effectively extracting the lower 32 bits of `fseq`.
    - The result of the bitwise operation is cast to a 32-bit unsigned integer and returned.
- **Output**: A 32-bit unsigned integer representing the state extracted from the lower 32 bits of the input `fseq`.


---
### fd\_exec\_fseq\_set\_slot\_done<!-- {{#callable:FD_FN_UNUSED::fd_exec_fseq_set_slot_done}} -->
The function `fd_exec_fseq_set_slot_done` returns a constant value representing the state of a slot being done in the execution sequence.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as static and unused, indicating it is intended for internal use and may not be currently utilized.
    - It directly returns the constant `FD_EXEC_STATE_SLOT_DONE` cast to an unsigned long integer.
- **Output**: The function returns an unsigned long integer representing the state of a slot being done, specifically the constant `FD_EXEC_STATE_SLOT_DONE`.


---
### fd\_exec\_fseq\_set\_booted<!-- {{#callable:FD_FN_UNUSED::fd_exec_fseq_set_booted}} -->
The function `fd_exec_fseq_set_booted` sets the booted state of an execution sequence with a given offset.
- **Inputs**:
    - `offset`: An unsigned integer representing the offset to be set in the execution sequence state.
- **Control Flow**:
    - The function takes an input `offset` and casts it to an unsigned long, shifting it left by 32 bits to form the higher part of the state.
    - It then uses a bitwise OR operation to combine this shifted offset with the constant `FD_EXEC_STATE_BOOTED`, which represents the booted state.
    - The resulting value, which encodes both the offset and the booted state, is returned.
- **Output**: The function returns an unsigned long integer representing the combined state of the execution sequence, including the booted state and the provided offset.


---
### fd\_exec\_fseq\_get\_booted\_offset<!-- {{#callable:FD_FN_UNUSED::fd_exec_fseq_get_booted_offset}} -->
The function `fd_exec_fseq_get_booted_offset` extracts the booted offset from a 64-bit sequence number by shifting it right by 32 bits and casting it to a 32-bit unsigned integer.
- **Inputs**:
    - `fseq`: A 64-bit unsigned long integer representing a sequence number from which the booted offset is to be extracted.
- **Control Flow**:
    - The function takes a 64-bit unsigned long integer `fseq` as input.
    - It shifts `fseq` right by 32 bits to isolate the upper 32 bits.
    - The result of the shift operation is cast to a 32-bit unsigned integer.
    - The function returns this 32-bit unsigned integer as the booted offset.
- **Output**: A 32-bit unsigned integer representing the booted offset extracted from the input sequence number.


---
### fd\_exec\_fseq\_set\_epoch\_done<!-- {{#callable:FD_FN_UNUSED::fd_exec_fseq_set_epoch_done}} -->
The function `fd_exec_fseq_set_epoch_done` returns a constant value representing the state of an execution sequence as 'epoch done'.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as static and unused, indicating it is intended for internal use within the file and may not be currently utilized.
    - The function takes no input parameters.
    - It directly returns the constant `FD_EXEC_STATE_EPOCH_DONE`, which is defined as a bit-shifted value representing the 'epoch done' state.
- **Output**: The function returns an `ulong` value that signifies the 'epoch done' state of an execution sequence.


---
### fd\_exec\_fseq\_set\_hash\_done<!-- {{#callable:FD_FN_UNUSED::fd_exec_fseq_set_hash_done}} -->
The function `fd_exec_fseq_set_hash_done` returns a constant value representing the state of a hash operation being completed in the execution sequence.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as static and unused, indicating it is intended for internal use within the file and may not be currently utilized.
    - It directly returns the constant `FD_EXEC_STATE_HASH_DONE`, which is defined as a bitwise shift operation resulting in a specific unsigned long value.
- **Output**: The function returns an unsigned long integer representing the state of a hash operation being completed, specifically the constant `FD_EXEC_STATE_HASH_DONE`.


---
### fd\_exec\_fseq\_set\_bpf\_scan\_done<!-- {{#callable:FD_FN_UNUSED::fd_exec_fseq_set_bpf_scan_done}} -->
The function `fd_exec_fseq_set_bpf_scan_done` sets the BPF scan done state for a given execution ID by encoding it into a 64-bit unsigned long integer.
- **Inputs**:
    - `id`: A 64-bit unsigned long integer representing the execution ID to be encoded with the BPF scan done state.
- **Control Flow**:
    - Shift the input `id` 32 bits to the left to position it in the higher 32 bits of the resulting state.
    - Perform a bitwise OR operation with the constant `FD_EXEC_STATE_BPF_SCAN_DONE` to set the BPF scan done state in the lower 32 bits.
    - Return the combined 64-bit state value.
- **Output**: A 64-bit unsigned long integer representing the state with the BPF scan done flag set for the given execution ID.


---
### fd\_exec\_fseq\_get\_bpf\_id<!-- {{#callable:FD_FN_UNUSED::fd_exec_fseq_get_bpf_id}} -->
The function `fd_exec_fseq_get_bpf_id` extracts the BPF ID from a given execution sequence number by shifting the bits.
- **Inputs**:
    - `fseq`: An unsigned long integer representing the execution sequence number from which the BPF ID is to be extracted.
- **Control Flow**:
    - The function takes a single input parameter `fseq` of type `ulong`.
    - It performs a bitwise right shift operation on `fseq` by 32 bits.
    - The result of the shift operation is cast to an unsigned integer type `uint`.
    - The function returns this casted value as the BPF ID.
- **Output**: The function returns a `uint` representing the BPF ID extracted from the higher 32 bits of the input `fseq`.


---
### fd\_exec\_fseq\_set\_snap\_hash\_cnt\_done<!-- {{#callable:FD_FN_UNUSED::fd_exec_fseq_set_snap_hash_cnt_done}} -->
The function `fd_exec_fseq_set_snap_hash_cnt_done` sets the state to indicate that the snapshot hash count operation is done, incorporating a given length of pairs into the state.
- **Inputs**:
    - `pairs_len`: An unsigned integer representing the length of pairs to be incorporated into the state.
- **Control Flow**:
    - The function takes an input `pairs_len` and casts it to an unsigned long integer.
    - It shifts `pairs_len` left by 32 bits to position it in the upper half of a 64-bit state variable.
    - The function then performs a bitwise OR operation with the constant `FD_EXEC_STATE_SNAP_CNT_DONE` to set the appropriate state flag.
    - Finally, the function returns the computed state as an unsigned long integer.
- **Output**: The function returns an unsigned long integer representing the state with the snapshot hash count done flag set and the `pairs_len` incorporated.


---
### fd\_exec\_fseq\_get\_pairs\_len<!-- {{#callable:FD_FN_UNUSED::fd_exec_fseq_get_pairs_len}} -->
The function `fd_exec_fseq_get_pairs_len` extracts and returns the upper 32 bits of a 64-bit unsigned long integer, representing the length of pairs.
- **Inputs**:
    - `fseq`: A 64-bit unsigned long integer from which the upper 32 bits are extracted.
- **Control Flow**:
    - The function takes a single input parameter, `fseq`, which is a 64-bit unsigned long integer.
    - It performs a right bitwise shift operation on `fseq` by 32 bits, effectively moving the upper 32 bits to the lower 32-bit position.
    - The result of the shift operation is cast to a 32-bit unsigned integer (`uint`) and returned as the output.
- **Output**: A 32-bit unsigned integer representing the upper 32 bits of the input `fseq`.


---
### fd\_exec\_fseq\_set\_snap\_hash\_gather\_done<!-- {{#callable:FD_FN_UNUSED::fd_exec_fseq_set_snap_hash_gather_done}} -->
The function `fd_exec_fseq_set_snap_hash_gather_done` returns a constant value representing the state of 'snapshot hash gather done' in the execution sequence.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as static and unused, indicating it is intended for internal use and may not be currently utilized.
    - It directly returns the constant `FD_EXEC_STATE_SNAP_GATHER_DONE`, which is defined as a bit-shifted value representing a specific execution state.
- **Output**: The function returns an unsigned long integer (`ulong`) representing the state `FD_EXEC_STATE_SNAP_GATHER_DONE`.


---
### fd\_exec\_fseq\_is\_not\_joined<!-- {{#callable:fd_exec_fseq_is_not_joined}} -->
The function `fd_exec_fseq_is_not_joined` checks if a given execution sequence identifier is not joined by comparing it to `ULONG_MAX`.
- **Inputs**:
    - `fseq`: An unsigned long integer representing the execution sequence identifier to be checked.
- **Control Flow**:
    - The function takes a single input parameter `fseq`.
    - It compares `fseq` to `ULONG_MAX`.
    - If `fseq` is equal to `ULONG_MAX`, the function returns true (non-zero).
    - Otherwise, it returns false (zero).
- **Output**: The function returns an integer value: 1 if `fseq` is equal to `ULONG_MAX`, indicating the sequence is not joined, and 0 otherwise.


---
### fd\_writer\_fseq\_get\_state<!-- {{#callable:fd_writer_fseq_get_state}} -->
The function `fd_writer_fseq_get_state` extracts the state information from a given `fseq` value by masking and returning the lower 24 bits.
- **Inputs**:
    - `fseq`: A 64-bit unsigned long integer representing a sequence value from which the state needs to be extracted.
- **Control Flow**:
    - The function takes a 64-bit unsigned long integer `fseq` as input.
    - It applies a bitwise AND operation between `fseq` and the hexadecimal mask `0x00FFFFFFU`, which isolates the lower 24 bits of `fseq`.
    - The result of the bitwise operation is cast to a 32-bit unsigned integer and returned as the state.
- **Output**: A 32-bit unsigned integer representing the state extracted from the lower 24 bits of the input `fseq`.


---
### fd\_writer\_fseq\_set\_txn\_done<!-- {{#callable:fd_writer_fseq_set_txn_done}} -->
The function `fd_writer_fseq_set_txn_done` constructs a state value representing a completed transaction by combining a transaction ID, an execution tile ID, and a predefined state flag.
- **Inputs**:
    - `txn_id`: A 32-bit unsigned integer representing the transaction ID.
    - `exec_tile_id`: An 8-bit unsigned character representing the execution tile ID.
- **Control Flow**:
    - Initialize a 64-bit unsigned integer `state` by shifting the `txn_id` 32 bits to the left.
    - Shift the `exec_tile_id` 24 bits to the left and combine it with `state` using a bitwise OR operation.
    - Combine the `state` with the constant `FD_WRITER_STATE_TXN_DONE` using a bitwise OR operation.
    - Return the resulting `state` value.
- **Output**: A 64-bit unsigned integer representing the combined state of the transaction ID, execution tile ID, and the transaction done state flag.


---
### fd\_writer\_fseq\_get\_txn\_id<!-- {{#callable:fd_writer_fseq_get_txn_id}} -->
The function `fd_writer_fseq_get_txn_id` extracts the transaction ID from a given 64-bit sequence number by shifting the bits to the right by 32 positions.
- **Inputs**:
    - `fseq`: A 64-bit unsigned long integer representing a sequence number that encodes various pieces of information, including the transaction ID.
- **Control Flow**:
    - The function takes a 64-bit unsigned long integer `fseq` as input.
    - It performs a bitwise right shift operation on `fseq` by 32 bits.
    - The result of the shift operation is cast to a 32-bit unsigned integer, effectively extracting the transaction ID from the higher 32 bits of `fseq`.
- **Output**: The function returns a 32-bit unsigned integer representing the transaction ID extracted from the input sequence number.


---
### fd\_writer\_fseq\_get\_exec\_tile\_id<!-- {{#callable:fd_writer_fseq_get_exec_tile_id}} -->
The function `fd_writer_fseq_get_exec_tile_id` extracts the execution tile ID from a given sequence number.
- **Inputs**:
    - `fseq`: A 64-bit unsigned long integer representing a sequence number containing various encoded information, including the execution tile ID.
- **Control Flow**:
    - The function takes a 64-bit unsigned long integer `fseq` as input.
    - It performs a right bitwise shift of 24 positions on `fseq` to move the execution tile ID into the least significant byte position.
    - It applies a bitwise AND operation with `0xFFUL` to isolate the 8 bits representing the execution tile ID.
    - The result is cast to an unsigned char and returned.
- **Output**: The function returns an unsigned char representing the execution tile ID extracted from the input sequence number.


---
### fd\_writer\_fseq\_is\_not\_joined<!-- {{#callable:fd_writer_fseq_is_not_joined}} -->
The function `fd_writer_fseq_is_not_joined` checks if a given sequence number is equal to `ULONG_MAX`, indicating it is not joined.
- **Inputs**:
    - `fseq`: An unsigned long integer representing a sequence number.
- **Control Flow**:
    - The function compares the input `fseq` with `ULONG_MAX`.
    - If `fseq` is equal to `ULONG_MAX`, the function returns true (non-zero).
    - If `fseq` is not equal to `ULONG_MAX`, the function returns false (zero).
- **Output**: An integer that is non-zero if `fseq` is `ULONG_MAX`, otherwise zero.


# Function Declarations (Public API)

---
### fd\_runtime\_public\_align<!-- {{#callable_declaration:fd_runtime_public_align}} -->
Determine the alignment requirement for the public runtime structure.
- **Description**: Use this function to obtain the alignment requirement for the `fd_runtime_public_t` structure, which is necessary when allocating memory for instances of this structure. This function ensures that the alignment is compatible with both the `fd_runtime_public_t` structure and any special alignment requirements of the system's scratchpad memory. It is typically used in conjunction with memory allocation functions to ensure proper alignment.
- **Inputs**: None
- **Output**: Returns the alignment requirement as an unsigned long integer, representing the maximum alignment needed between `fd_runtime_public_t` and the system's scratchpad alignment.
- **See also**: [`fd_runtime_public_align`](fd_runtime_public.c.driver.md#fd_runtime_public_align)  (Implementation)


---
### fd\_runtime\_public\_footprint<!-- {{#callable_declaration:fd_runtime_public_footprint}} -->
Calculates the memory footprint required for a public runtime workspace.
- **Description**: Use this function to determine the amount of memory needed to allocate a public runtime workspace, which includes space for both the runtime structure and any associated scratchpad memory. This function is useful when planning memory allocation for runtime operations, ensuring that sufficient space is reserved. It should be called before allocating memory for the runtime to avoid memory overflows or under-allocations.
- **Inputs**:
    - `spad_mem_max`: Specifies the maximum size of the scratchpad memory in bytes. It must be a positive integer, and the function will calculate the total footprint based on this value. Invalid values, such as zero or negative numbers, may lead to undefined behavior.
- **Output**: Returns the total memory footprint in bytes required for the public runtime workspace, including the specified scratchpad memory.
- **See also**: [`fd_runtime_public_footprint`](fd_runtime_public.c.driver.md#fd_runtime_public_footprint)  (Implementation)


---
### fd\_runtime\_public\_new<!-- {{#callable_declaration:fd_runtime_public_new}} -->
Allocate and initialize a new runtime public structure in shared memory.
- **Description**: This function is used to allocate and initialize a new runtime public structure within a specified shared memory region. It should be called when a new runtime public instance is needed, and the shared memory region must be part of a valid workspace. The function also initializes a scratchpad memory area with a specified maximum size. If the shared memory is not part of a workspace or if the scratchpad memory cannot be created, the function will return NULL, indicating failure.
- **Inputs**:
    - `shmem`: A pointer to the shared memory region where the runtime public structure will be allocated. Must be part of a valid workspace. If not, the function returns NULL.
    - `spad_mem_max`: The maximum size of the scratchpad memory to be allocated. This value determines the footprint of the scratchpad memory area.
- **Output**: Returns a pointer to the shared memory region if successful, or NULL if the shared memory is not part of a workspace or if the scratchpad memory cannot be created.
- **See also**: [`fd_runtime_public_new`](fd_runtime_public.c.driver.md#fd_runtime_public_new)  (Implementation)


---
### fd\_runtime\_public\_join<!-- {{#callable_declaration:fd_runtime_public_join}} -->
Joins a shared memory region as a runtime public structure.
- **Description**: This function is used to join a shared memory region as a `fd_runtime_public_t` structure, allowing access to its contents. It should be called with a valid shared memory pointer that has been previously initialized with the correct magic number and runtime spad allocation. If the shared memory does not meet these conditions, the function will return `NULL` and log a warning. This function is typically used in environments where shared memory is utilized for inter-process communication or resource sharing.
- **Inputs**:
    - `shmem`: A pointer to the shared memory region to be joined. It must not be null and should point to a memory region initialized with the correct magic number (`FD_RUNTIME_PUBLIC_MAGIC`) and a non-zero runtime spad allocation. The caller retains ownership of the memory.
- **Output**: Returns a pointer to the `fd_runtime_public_t` structure if successful, or `NULL` if the shared memory is invalid or not properly initialized.
- **See also**: [`fd_runtime_public_join`](fd_runtime_public.c.driver.md#fd_runtime_public_join)  (Implementation)


---
### fd\_runtime\_public\_spad<!-- {{#callable_declaration:fd_runtime_public_spad}} -->
Returns a local join of the runtime scratchpad.
- **Description**: This function provides access to the runtime scratchpad associated with a given runtime public structure. It should be called when a local join of the scratchpad is needed for operations that require direct access to the scratchpad's data. The function expects a valid pointer to a `fd_runtime_public_t` structure, which must be part of a workspace. If the input is null or not part of a workspace, the function will return null and log a warning.
- **Inputs**:
    - `runtime_public`: A pointer to a `fd_runtime_public_t` structure representing the runtime public data. It must not be null and should be part of a valid workspace. If null or not part of a workspace, the function returns null and logs a warning.
- **Output**: A pointer to an `fd_spad_t` structure representing the local join of the runtime scratchpad, or null if the input is invalid.
- **See also**: [`fd_runtime_public_spad`](fd_runtime_public.c.driver.md#fd_runtime_public_spad)  (Implementation)



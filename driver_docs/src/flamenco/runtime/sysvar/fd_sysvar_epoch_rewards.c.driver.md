# Purpose
This C source code file is focused on managing and manipulating epoch rewards within a system, likely part of a larger financial or blockchain-related application. The code provides a set of functions to initialize, read, distribute, and deactivate epoch rewards, which are stored as system variables (sysvars). The primary technical components include functions for encoding and decoding these sysvars, ensuring that the rewards data is correctly serialized and deserialized for storage and retrieval. The code interacts with various system components, such as execution contexts and transaction management, to maintain the integrity and consistency of the rewards data across different execution slots.

The file is not a standalone executable but rather a part of a larger system, likely intended to be included and used by other components within the application. It defines internal functions for managing epoch rewards, which are crucial for maintaining the state and distribution of rewards over time. The functions ensure that the rewards are correctly updated and synchronized, especially in environments where multiple updates can occur within a single slot. The code also includes error handling to manage potential issues such as overflow or inactive rewards, ensuring robust operation within the system.
# Imports and Dependencies

---
- `fd_sysvar_epoch_rewards.h`
- `fd_sysvar.h`
- `../fd_acc_mgr.h`
- `../fd_runtime.h`
- `../fd_borrowed_account.h`
- `../fd_system_ids.h`
- `../context/fd_exec_epoch_ctx.h`


# Functions

---
### write\_epoch\_rewards<!-- {{#callable:write_epoch_rewards}} -->
The `write_epoch_rewards` function encodes epoch rewards data and updates the sysvar with the encoded data in the given execution slot context.
- **Inputs**:
    - `slot_ctx`: A pointer to an `fd_exec_slot_ctx_t` structure representing the execution slot context where the sysvar will be updated.
    - `epoch_rewards`: A pointer to an `fd_sysvar_epoch_rewards_t` structure containing the epoch rewards data to be encoded and written.
- **Control Flow**:
    - Calculate the size of the encoded epoch rewards data using `fd_sysvar_epoch_rewards_size` function.
    - Allocate a buffer `enc` of the calculated size and initialize it to zero using `fd_memset`.
    - Initialize a `fd_bincode_encode_ctx_t` structure `ctx` with the buffer `enc` and its end address.
    - Encode the `epoch_rewards` data into the buffer using `fd_sysvar_epoch_rewards_encode`; log an error if encoding fails.
    - Update the sysvar in the given slot context using [`fd_sysvar_set`](fd_sysvar.c.driver.md#fd_sysvar_set) with the encoded data.
- **Output**: The function does not return a value; it updates the sysvar with the encoded epoch rewards data in the specified execution slot context.
- **Functions called**:
    - [`fd_sysvar_set`](fd_sysvar.c.driver.md#fd_sysvar_set)


---
### fd\_sysvar\_epoch\_rewards\_read<!-- {{#callable:fd_sysvar_epoch_rewards_read}} -->
The `fd_sysvar_epoch_rewards_read` function reads and decodes the sysvar epoch rewards from a specified account in a read-only transaction context.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure representing the current state of the system.
    - `funk_txn`: A pointer to an `fd_funk_txn_t` structure representing the transaction context in which the read operation is performed.
    - `spad`: A pointer to an `fd_spad_t` structure used for decoding the sysvar epoch rewards data.
- **Control Flow**:
    - Declare a transaction account using `FD_TXN_ACCOUNT_DECL` macro.
    - Initialize the account in a read-only mode using `fd_txn_account_init_from_funk_readonly` with the sysvar epoch rewards ID.
    - Check if the initialization was successful; if not, return `NULL`.
    - Check if the account has zero lamports, indicating non-existence in a fuzzer context, and return `NULL` if true.
    - Decode the sysvar epoch rewards data using `fd_bincode_decode_spad` and return the decoded data.
- **Output**: A pointer to an `fd_sysvar_epoch_rewards_t` structure containing the decoded sysvar epoch rewards data, or `NULL` if an error occurs or the account is deemed non-existent.


---
### fd\_sysvar\_epoch\_rewards\_distribute<!-- {{#callable:fd_sysvar_epoch_rewards_distribute}} -->
The function `fd_sysvar_epoch_rewards_distribute` updates the distributed rewards for epoch rewards and writes the updated state back to the system.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context (`fd_exec_slot_ctx_t`), which contains information about the current execution slot.
    - `distributed`: An unsigned long integer representing the amount of rewards to be distributed.
    - `runtime_spad`: A pointer to the runtime scratchpad (`fd_spad_t`), used for temporary storage during execution.
- **Control Flow**:
    - Read the current epoch rewards using [`fd_sysvar_epoch_rewards_read`](#fd_sysvar_epoch_rewards_read) with the provided `slot_ctx` and `runtime_spad`.
    - Check if the `epoch_rewards` is NULL, and log an error if it is.
    - Verify that the `epoch_rewards` is active, logging an error if it is not.
    - Check if adding the `distributed` amount to `epoch_rewards->distributed_rewards` would exceed `epoch_rewards->total_rewards`, logging an error if it would.
    - Add the `distributed` amount to `epoch_rewards->distributed_rewards`.
    - Call [`write_epoch_rewards`](#write_epoch_rewards) to update the epoch rewards in the system with the new distributed rewards.
- **Output**: The function does not return a value; it updates the state of the epoch rewards in the system.
- **Functions called**:
    - [`fd_sysvar_epoch_rewards_read`](#fd_sysvar_epoch_rewards_read)
    - [`write_epoch_rewards`](#write_epoch_rewards)


---
### fd\_sysvar\_epoch\_rewards\_set\_inactive<!-- {{#callable:fd_sysvar_epoch_rewards_set_inactive}} -->
The function `fd_sysvar_epoch_rewards_set_inactive` sets the 'active' status of epoch rewards to inactive and ensures the integrity of reward distribution before updating the system variable.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context, which contains information about the current execution slot and its associated data.
    - `runtime_spad`: A pointer to the runtime scratchpad, used for temporary storage and operations during execution.
- **Control Flow**:
    - Read the current epoch rewards using [`fd_sysvar_epoch_rewards_read`](#fd_sysvar_epoch_rewards_read) with the provided `slot_ctx` and `runtime_spad`.
    - Check if the epoch rewards could not be read and log an error if so.
    - Determine if the 'partitioned_epoch_rewards_superfeature' is active using `FD_FEATURE_ACTIVE`.
    - If the feature is active, check if `total_rewards` is less than `distributed_rewards` and log an error if true.
    - If the feature is not active, check if `total_rewards` is not equal to `distributed_rewards` and log an error if true.
    - Set the `active` field of `epoch_rewards` to 0, marking it as inactive.
    - Write the updated epoch rewards back using [`write_epoch_rewards`](#write_epoch_rewards).
- **Output**: The function does not return a value; it performs operations to update the state of epoch rewards in the system.
- **Functions called**:
    - [`fd_sysvar_epoch_rewards_read`](#fd_sysvar_epoch_rewards_read)
    - [`write_epoch_rewards`](#write_epoch_rewards)


---
### fd\_sysvar\_epoch\_rewards\_init<!-- {{#callable:fd_sysvar_epoch_rewards_init}} -->
The `fd_sysvar_epoch_rewards_init` function initializes the epoch rewards system variable with specified parameters and writes it to the execution slot context.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context (`fd_exec_slot_ctx_t`) where the epoch rewards will be initialized.
    - `total_rewards`: The total amount of rewards available for distribution in the epoch.
    - `distributed_rewards`: The amount of rewards that have already been distributed.
    - `distribution_starting_block_height`: The block height at which the distribution of rewards starts.
    - `num_partitions`: The number of partitions for the reward distribution.
    - `point_value`: A structure (`fd_point_value_t`) containing point values and possibly reward values used for calculations.
    - `last_blockhash`: A constant pointer to the last block hash (`fd_hash_t`) used to set the parent block hash in the epoch rewards.
- **Control Flow**:
    - Initialize an `fd_sysvar_epoch_rewards_t` structure with the provided parameters and set it as active.
    - Check if the `partitioned_epoch_rewards_superfeature` is active in the current slot context; if so, use `point_value.rewards` for `total_rewards`.
    - Verify that `total_rewards` is not less than `distributed_rewards` to prevent overflow, logging an error if this condition is violated.
    - Copy the `last_blockhash` into the `parent_blockhash` field of the `epoch_rewards` structure.
    - Call [`write_epoch_rewards`](#write_epoch_rewards) to encode and store the initialized `epoch_rewards` in the slot context.
- **Output**: The function does not return a value; it initializes and writes the epoch rewards to the provided slot context.
- **Functions called**:
    - [`write_epoch_rewards`](#write_epoch_rewards)



# Purpose
This C header file, `fd_hashes.h`, is part of a larger software system and provides a collection of data structures and function prototypes related to hashing operations within a runtime environment. The primary focus of this file is on managing and computing hashes for accounts, which are likely part of a distributed ledger or blockchain system. The file defines several key data structures, such as `fd_pubkey_hash_pair`, `fd_pubkey_hash_pair_list`, `fd_subrange_task_info`, and `fd_accounts_hash_task_info`, which are used to organize and manage the data necessary for hashing operations. These structures facilitate the handling of public keys, hash values, and task-related information, which are essential for the efficient computation and management of account hashes.

The file also declares a variety of functions that perform specific tasks related to account hashing, such as gathering account data, updating hash banks, and computing both incremental and non-incremental hashes of the account database. Functions like [`fd_hash_account`](#fd_hash_account), [`fd_accounts_hash`](#fd_accounts_hash), and [`fd_snapshot_service_hash`](#fd_snapshot_service_hash) are central to the file's purpose, providing the mechanisms to compute and verify hashes based on different criteria and states. The inclusion of feature flags and conditional logic suggests that the file supports multiple hashing strategies, which can be toggled based on the system's configuration or state. Overall, this header file is a critical component of a system that requires robust and flexible account hashing capabilities, likely for purposes such as data integrity, verification, and synchronization in a distributed environment.
# Imports and Dependencies

---
- `../fd_flamenco_base.h`
- `../types/fd_types.h`
- `../../funk/fd_funk.h`
- `../../ballet/lthash/fd_lthash.h`
- `fd_runtime_public.h`


# Global Variables

---
### fd\_hash\_account
- **Type**: `function`
- **Description**: The `fd_hash_account` function is responsible for computing the hash of an account. It takes several parameters including a hash buffer, a long-term hash value, account metadata, a public key, account data, a flag indicating if hashing is needed, and feature flags. The function writes the resulting hash to the provided hash buffer and returns a pointer to it.
- **Use**: This function is used to generate a hash for an account, incorporating various account attributes such as lamports, rent_epoch, data, executable status, owner, and public key.


---
### fd\_hash\_account\_current
- **Type**: `function`
- **Description**: The `fd_hash_account_current` function is a global function that determines the appropriate account hash function to use based on the current feature activation state. It takes several parameters including a hash buffer, a pointer to a long-term hash value, account metadata, a public key, data, a flag indicating if hashing is needed, and feature flags.
- **Use**: This function is used to compute the current account hash by selecting the appropriate hashing method based on the active features.


# Data Structures

---
### fd\_pubkey\_hash\_pair
- **Type**: `struct`
- **Members**:
    - `rec`: A pointer to a constant fd_funk_rec_t structure, representing a record.
    - `hash`: A pointer to a constant fd_hash_t structure, representing a hash value.
- **Description**: The `fd_pubkey_hash_pair` structure is designed to hold a pair of pointers, one pointing to a record (`fd_funk_rec_t`) and the other to a hash (`fd_hash_t`). This structure is aligned to a 16-byte boundary as specified by `FD_PUBKEY_HASH_PAIR_ALIGN`, ensuring efficient memory access and alignment. It is typically used in contexts where a public key is associated with its corresponding hash, facilitating operations that require both the record and its hash to be accessed together.


---
### fd\_pubkey\_hash\_pair\_t
- **Type**: `struct`
- **Members**:
    - `rec`: A pointer to a constant fd_funk_rec_t structure, representing a record.
    - `hash`: A pointer to a constant fd_hash_t structure, representing a hash.
- **Description**: The `fd_pubkey_hash_pair_t` structure is designed to hold a pair of pointers, one pointing to a record and the other to a hash. This structure is aligned to 16 bytes, ensuring efficient memory access and usage. It is typically used in contexts where a public key is associated with a hash, facilitating operations that require both elements to be processed together, such as in cryptographic or data integrity applications.


---
### fd\_pubkey\_hash\_pair\_list
- **Type**: `struct`
- **Members**:
    - `pairs`: A pointer to an array of fd_pubkey_hash_pair_t structures.
    - `pairs_len`: An unsigned long integer representing the number of elements in the pairs array.
- **Description**: The `fd_pubkey_hash_pair_list` structure is designed to manage a list of public key and hash pairs, encapsulated in `fd_pubkey_hash_pair_t` structures. It contains a pointer to an array of these pairs and a length field to track the number of pairs in the list. This structure is useful for handling collections of public key-hash associations, which are common in cryptographic and blockchain applications.


---
### fd\_pubkey\_hash\_pair\_list\_t
- **Type**: `struct`
- **Members**:
    - `pairs`: A pointer to an array of fd_pubkey_hash_pair_t structures.
    - `pairs_len`: An unsigned long integer representing the number of elements in the pairs array.
- **Description**: The `fd_pubkey_hash_pair_list_t` structure is designed to manage a list of public key and hash pairs. It contains a pointer to an array of `fd_pubkey_hash_pair_t` structures, which hold individual public key and hash pairings, and a length field that indicates the number of such pairs in the list. This structure is useful for handling collections of public key-hash associations, likely in contexts where such pairings need to be processed or iterated over as a group.


---
### fd\_subrange\_task\_info
- **Type**: `struct`
- **Members**:
    - `features`: A pointer to a union of features, likely used to store various feature flags or settings.
    - `funk`: A pointer to a fd_funk_t structure, which is likely used for managing or interacting with a database or data store.
    - `num_lists`: An unsigned long integer representing the number of lists contained in the structure.
    - `lists`: A pointer to an array of fd_pubkey_hash_pair_list_t structures, which likely store lists of public key and hash pairs.
    - `lthash_values`: A pointer to an array of fd_lthash_value_t structures, which likely store hash values for some purpose.
- **Description**: The `fd_subrange_task_info` structure is designed to encapsulate information related to a specific task involving subranges, likely in the context of hashing or data processing. It includes pointers to features and a funk structure, which may be used for configuration and data management, respectively. The structure also maintains a count of lists and pointers to these lists, which store public key and hash pairings, as well as hash values, indicating its role in managing and processing cryptographic or data integrity tasks.


---
### fd\_subrange\_task\_info\_t
- **Type**: `struct`
- **Members**:
    - `features`: A pointer to a union of features, likely used to store various feature flags or settings.
    - `funk`: A pointer to a fd_funk_t structure, which is likely used for managing or interacting with a database or data store.
    - `num_lists`: An unsigned long integer representing the number of lists in the structure.
    - `lists`: A pointer to an array of fd_pubkey_hash_pair_list_t structures, which likely store lists of public key and hash pairs.
    - `lthash_values`: A pointer to an array of fd_lthash_value_t structures, which are likely used to store hash values for some purpose.
- **Description**: The `fd_subrange_task_info_t` structure is designed to encapsulate information related to a subrange task, likely in the context of hashing or data processing. It includes pointers to features, a funk structure for database interactions, a count of lists, and arrays of public key-hash pair lists and hash values. This structure is likely used to manage and execute tasks that involve processing or hashing subsets of data, possibly in a parallel or distributed computing environment.


---
### fd\_accounts\_hash\_task\_info
- **Type**: `struct`
- **Members**:
    - `slot_ctx`: A pointer to an execution slot context.
    - `acc_pubkey`: An array containing a single public key associated with the account.
    - `acc_hash`: An array containing a single hash value associated with the account.
    - `should_erase`: A flag indicating whether the account should be erased.
    - `hash_changed`: A flag indicating whether the account's hash has changed.
- **Description**: The `fd_accounts_hash_task_info` structure is designed to hold information related to the hashing task of an account in a specific execution slot context. It includes a pointer to the execution slot context, a single public key, and a hash associated with the account. Additionally, it contains flags to indicate whether the account should be erased and whether its hash has changed, which are crucial for managing account state and ensuring data integrity during hash operations.


---
### fd\_accounts\_hash\_task\_info\_t
- **Type**: `struct`
- **Members**:
    - `slot_ctx`: A pointer to an execution slot context.
    - `acc_pubkey`: An array containing a single public key for the account.
    - `acc_hash`: An array containing a single hash for the account.
    - `should_erase`: A flag indicating whether the account should be erased.
    - `hash_changed`: A flag indicating whether the account hash has changed.
- **Description**: The `fd_accounts_hash_task_info_t` structure is designed to hold information related to the hashing task of an account in a distributed system. It includes pointers to the execution context, the public key, and the hash of the account, as well as flags to indicate if the account should be erased or if its hash has changed. This structure is likely used in the process of updating or verifying account hashes within a larger system, ensuring data integrity and consistency.


---
### fd\_accounts\_hash\_task\_data
- **Type**: `struct`
- **Members**:
    - `info`: A pointer to a `fd_accounts_hash_task_info_t` structure, which contains information about the account hash task.
    - `info_sz`: An unsigned long integer representing the size of the `info` array.
    - `lthash_values`: A pointer to an array of `fd_lthash_value_t` values, which are used in the hash computation.
    - `num_recs`: An unsigned long integer indicating the number of records associated with the task.
- **Description**: The `fd_accounts_hash_task_data` structure is designed to encapsulate data necessary for executing account hash tasks. It includes a pointer to task-specific information (`info`), the size of this information (`info_sz`), a pointer to hash values (`lthash_values`) used in the computation, and the number of records (`num_recs`) involved in the task. This structure is essential for managing and processing account hash operations efficiently within the system.


---
### fd\_accounts\_hash\_task\_data\_t
- **Type**: `struct`
- **Members**:
    - `info`: A pointer to an `fd_accounts_hash_task_info_t` structure containing task-specific information.
    - `info_sz`: An unsigned long integer representing the size of the `info` array.
    - `lthash_values`: A pointer to an array of `fd_lthash_value_t` structures used for hash calculations.
    - `num_recs`: An unsigned long integer indicating the number of records to process.
- **Description**: The `fd_accounts_hash_task_data_t` structure is designed to encapsulate data necessary for processing account hash tasks. It includes a pointer to task-specific information (`info`), the size of this information (`info_sz`), a pointer to hash values (`lthash_values`), and the number of records to be processed (`num_recs`). This structure is used in the context of hashing operations on accounts, facilitating the organization and management of data required for these tasks.


---
### fd\_features\_t
- **Type**: `union`
- **Description**: The `fd_features_t` is a union type defined as `fd_features`, but the actual members of this union are not provided in the given code. It is used in various functions related to account hashing and feature activation, suggesting it encapsulates different feature states or configurations that influence the behavior of these functions.


# Function Declarations (Public API)

---
### fd\_accounts\_sorted\_subrange\_count<!-- {{#callable_declaration:fd_accounts_sorted_subrange_count}} -->
Counts the number of non-empty, executable accounts within a specified subrange.
- **Description**: Use this function to determine the number of non-empty, executable accounts within a specified subrange of account keys in a given `fd_funk_t` context. This function is useful when you need to process or analyze accounts in specific segments of the key space. It is important to ensure that the `funk` parameter is properly initialized before calling this function. The function will return zero if the specified subrange is invalid or if no accounts meet the criteria within the range.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure representing the context in which the accounts are managed. Must not be null.
    - `range_idx`: An unsigned integer specifying the index of the subrange to be counted. It should be less than `range_cnt`.
    - `range_cnt`: An unsigned integer specifying the total number of subranges. Must be greater than zero.
- **Output**: Returns the number of non-empty, executable accounts within the specified subrange as an unsigned long integer.
- **See also**: [`fd_accounts_sorted_subrange_count`](fd_hashes.c.driver.md#fd_accounts_sorted_subrange_count)  (Implementation)


---
### fd\_accounts\_sorted\_subrange\_gather<!-- {{#callable_declaration:fd_accounts_sorted_subrange_gather}} -->
Gathers and sorts account records within a specified subrange.
- **Description**: This function is used to collect and sort account records from a specified subrange of the account database. It is typically called when there is a need to process or analyze a subset of accounts, such as during hashing operations. The function requires a valid `fd_funk_t` context and expects the subrange to be defined by `range_idx` and `range_cnt`. The results, including the number of valid account pairs and their associated hash values, are output through the provided pointers. The function assumes that the `pairs` array is large enough to hold all the gathered records and that `features` is properly initialized. It is important to ensure that the `range_idx` and `range_cnt` parameters define a valid subrange to avoid undefined behavior.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure representing the account database context. Must not be null.
    - `range_idx`: An unsigned integer specifying the index of the subrange to process. Must be less than `range_cnt`.
    - `range_cnt`: An unsigned integer specifying the total number of subranges. Must be greater than zero.
    - `num_pairs_out`: A pointer to an `ulong` where the function will store the number of valid account pairs found. Must not be null.
    - `lthash_value_out`: A pointer to an `fd_lthash_value_t` where the function will store the accumulated hash value. Can be null if the hash value is not needed.
    - `pairs`: A pointer to an array of `fd_pubkey_hash_pair_t` where the function will store the gathered account pairs. Must be large enough to hold all pairs.
    - `features`: A pointer to an `fd_features_t` structure specifying feature flags for the operation. Must be properly initialized.
- **Output**: The function outputs the number of valid account pairs to `num_pairs_out` and optionally updates `lthash_value_out` with the accumulated hash value. The `pairs` array is populated with the gathered account pairs.
- **See also**: [`fd_accounts_sorted_subrange_gather`](fd_hashes.c.driver.md#fd_accounts_sorted_subrange_gather)  (Implementation)


---
### fd\_accounts\_hash\_counter\_and\_gather\_tpool\_cb<!-- {{#callable_declaration:fd_accounts_hash_counter_and_gather_tpool_cb}} -->
Coordinates tasks for hashing and gathering account data using a thread pool.
- **Description**: This function is used to manage and execute tasks related to hashing and gathering account data across multiple threads using a thread pool. It initializes necessary data structures, executes tasks to count and gather records, and waits for all tasks to complete. This function should be called when there is a need to process account data in parallel, leveraging multiple worker threads for efficiency. It assumes that the thread pool and task information structures are properly initialized before invocation.
- **Inputs**:
    - `para_arg_1`: A pointer to a `fd_tpool_t` structure representing the thread pool to be used for task execution. Must not be null.
    - `para_arg_2`: Unused parameter, can be null or any value.
    - `fn_arg_1`: A pointer to a `fd_subrange_task_info_t` structure that will be populated with task information, including lists and hash values. Must not be null.
    - `fn_arg_2`: A pointer to a `fd_spad_t` structure used for runtime memory allocation. Must not be null.
    - `fn_arg_3`: Unused parameter, can be null or any value.
    - `fn_arg_4`: Unused parameter, can be null or any value.
- **Output**: None
- **See also**: [`fd_accounts_hash_counter_and_gather_tpool_cb`](fd_hashes.c.driver.md#fd_accounts_hash_counter_and_gather_tpool_cb)  (Implementation)


---
### fd\_update\_hash\_bank\_exec\_hash<!-- {{#callable_declaration:fd_update_hash_bank_exec_hash}} -->
Updates the hash bank with execution hash data.
- **Description**: This function is used to update the hash bank with execution hash data based on the provided task data and hash values. It should be called when there is a need to apply changes to the bank's hash, typically during transaction processing. The function requires a valid execution slot context and expects the task data and hash values to be correctly initialized. It handles the application of hash changes and manages the capture context if provided. The function assumes that the runtime scratchpad is available for temporary allocations.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. Must not be null.
    - `hash`: A pointer to an fd_hash_t structure where the resulting hash will be stored. Must not be null.
    - `capture_ctx`: A pointer to an fd_capture_ctx_t structure for capturing context, or null if capturing is not needed.
    - `task_datas`: A pointer to an array of fd_accounts_hash_task_data_t structures containing task data for hash updates. Must not be null.
    - `task_datas_cnt`: The number of elements in the task_datas array. Must be greater than zero.
    - `lt_hashes`: A pointer to an array of fd_lthash_value_t structures representing hash values to be applied. Must not be null.
    - `lt_hashes_cnt`: The number of elements in the lt_hashes array. Must be greater than zero.
    - `signature_cnt`: The number of signatures to be processed. Must be a valid unsigned long value.
    - `runtime_spad`: A pointer to an fd_spad_t structure used for temporary allocations. Must not be null.
- **Output**: Returns an integer status code, typically FD_EXECUTOR_INSTR_SUCCESS on success.
- **See also**: [`fd_update_hash_bank_exec_hash`](fd_hashes.c.driver.md#fd_update_hash_bank_exec_hash)  (Implementation)


---
### fd\_collect\_modified\_accounts<!-- {{#callable_declaration:fd_collect_modified_accounts}} -->
Collects modified accounts from a transaction context.
- **Description**: This function is used to gather all accounts that have been modified in the current transaction context and store relevant information in the provided task data structure. It should be called when you need to process or analyze accounts that have been changed during a transaction. The function allocates memory for storing account information, so ensure that the runtime scratchpad is properly initialized and has sufficient space. It is important to handle any warnings or errors logged by the function, especially those related to unexpected null public keys.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the current execution slot context. Must not be null.
    - `task_data`: A pointer to an fd_accounts_hash_task_data_t structure where the modified account information will be stored. Must not be null.
    - `runtime_spad`: A pointer to an fd_spad_t structure used for runtime memory allocation. Must not be null and should be properly initialized.
- **Output**: None
- **See also**: [`fd_collect_modified_accounts`](fd_hashes.c.driver.md#fd_collect_modified_accounts)  (Implementation)


---
### fd\_account\_hash<!-- {{#callable_declaration:fd_account_hash}} -->
Updates the account hash and ledger hash for a given account.
- **Description**: This function is used to update the hash of an account and its associated ledger hash based on the current transaction context. It should be called when an account's state needs to be reflected in the ledger hash, typically during transaction processing. The function checks the account's metadata and updates the hash if necessary, marking the account for erasure if it has no lamports. It also handles changes in the account's hash and updates the ledger hash accordingly. This function must be called with valid transaction and account metadata, and it assumes that the account metadata is accessible and correctly initialized.
- **Inputs**:
    - `funk`: A pointer to an fd_funk_t structure representing the current state of the account database. Must not be null.
    - `funk_txn`: A pointer to an fd_funk_txn_t structure representing the current transaction context. Must not be null.
    - `task_info`: A pointer to an fd_accounts_hash_task_info_t structure containing information about the account to be hashed, including its public key and current hash. Must not be null.
    - `lt_hash`: A pointer to an fd_lthash_value_t structure where the ledger hash will be updated. Must not be null.
    - `slot`: An unsigned long representing the current slot number. Used to determine if the account's hash should be marked as changed.
    - `features`: A pointer to an fd_features_t structure representing the current feature set. Must not be null.
- **Output**: None
- **See also**: [`fd_account_hash`](fd_hashes.c.driver.md#fd_account_hash)  (Implementation)


---
### fd\_update\_hash\_bank\_tpool<!-- {{#callable_declaration:fd_update_hash_bank_tpool}} -->
Updates the hash bank using a thread pool for parallel processing.
- **Description**: This function updates the hash bank by processing modified accounts and computing their hashes, potentially using a thread pool for parallel execution. It is designed to handle both single-threaded and multi-threaded scenarios, depending on whether a thread pool is provided. The function should be called when there is a need to update the hash bank with new or modified account data, and it requires a valid execution slot context, capture context, and runtime scratchpad memory. The function returns an integer status code indicating success or failure of the operation.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. Must not be null.
    - `capture_ctx`: A pointer to an fd_capture_ctx_t structure used for capturing context during execution. Must not be null.
    - `hash`: A pointer to an fd_hash_t structure where the updated hash will be stored. Must not be null.
    - `signature_cnt`: An unsigned long integer representing the number of signatures to process. Must be a valid count of signatures.
    - `tpool`: A pointer to an fd_tpool_t structure representing the thread pool to use for parallel processing. Can be null, in which case the function will execute in a single-threaded manner.
    - `runtime_spad`: A pointer to an fd_spad_t structure representing the runtime scratchpad memory used for temporary allocations. Must not be null.
- **Output**: Returns an integer status code indicating the success or failure of the hash bank update operation.
- **See also**: [`fd_update_hash_bank_tpool`](fd_hashes.c.driver.md#fd_update_hash_bank_tpool)  (Implementation)


---
### fd\_hash\_account<!-- {{#callable_declaration:fd_hash_account}} -->
Compute the hash of an account based on specified parameters.
- **Description**: This function computes a hash for an account using various account attributes such as lamports, rent epoch, data, executable status, owner, and public key. It can compute either the account hash, the lthash, or both, depending on the `hash_needed` parameter. The function writes the resulting hash to the provided `hash` buffer and returns a pointer to it. This function should be used when a hash of an account is required for verification or storage purposes. Ensure that the `hash` buffer is properly allocated and that the `account`, `pubkey`, and `data` pointers are valid before calling this function.
- **Inputs**:
    - `hash`: A buffer of at least 32 bytes where the resulting hash will be stored. Must not be null.
    - `lthash`: A pointer to an `fd_lthash_value_t` structure where the lthash will be stored if needed. Must not be null if `hash_needed` includes `FD_HASH_JUST_LTHASH`.
    - `account`: A pointer to a constant `fd_account_meta_t` structure containing account metadata. Must not be null.
    - `pubkey`: A pointer to a constant `fd_pubkey_t` structure representing the account's public key. Must not be null.
    - `data`: A pointer to a constant byte array containing additional data to be included in the hash. Must not be null.
    - `hash_needed`: An integer flag indicating which hashes to compute. Can be `FD_HASH_JUST_ACCOUNT_HASH`, `FD_HASH_JUST_LTHASH`, or `FD_HASH_BOTH_HASHES`.
    - `features`: A pointer to an `fd_features_t` structure, which is currently unused. Can be null.
- **Output**: Returns a pointer to the `hash` buffer containing the computed hash.
- **See also**: [`fd_hash_account`](fd_hashes.c.driver.md#fd_hash_account)  (Implementation)


---
### fd\_hash\_account\_current<!-- {{#callable_declaration:fd_hash_account_current}} -->
Selects the appropriate account hash function based on feature activation state.
- **Description**: This function is used to compute the hash of an account by selecting the appropriate hashing method depending on the current feature activation state. It should be called when you need to generate a hash for an account, taking into account various account attributes and the current feature set. The function writes the resulting hash to the provided buffer and returns a pointer to the hash. It is important to ensure that the `hash` buffer is properly allocated and that all pointers provided are valid and non-null, except where specified otherwise.
- **Inputs**:
    - `hash`: A buffer of at least 32 bytes where the resulting hash will be stored. Must not be null.
    - `lthash`: A pointer to an `fd_lthash_value_t` structure. This parameter is used in the hashing process and must not be null.
    - `account`: A pointer to a constant `fd_account_meta_t` structure containing metadata about the account. Must not be null.
    - `pubkey`: A pointer to a constant `fd_pubkey_t` structure representing the public key of the account. Must not be null.
    - `data`: A pointer to a constant byte array containing additional data for the account. This can be null if no additional data is needed.
    - `hash_needed`: An integer flag indicating which hash operations are needed. Valid values are defined by constants such as `FD_HASH_JUST_ACCOUNT_HASH`, `FD_HASH_JUST_LTHASH`, and `FD_HASH_BOTH_HASHES`.
    - `features`: A pointer to an `fd_features_t` structure representing the current feature set. This parameter is used to determine the hashing method and must not be null.
- **Output**: Returns a pointer to the resulting hash stored in the `hash` buffer.
- **See also**: [`fd_hash_account_current`](fd_hashes.c.driver.md#fd_hash_account_current)  (Implementation)


---
### fd\_accounts\_hash<!-- {{#callable_declaration:fd_accounts_hash}} -->
Generate a complete hash of the entire account database.
- **Description**: This function computes a comprehensive hash of all accounts in the database, which can be used for integrity verification or other purposes. It should be called when a complete and up-to-date hash of the account database is required. The function supports both single-threaded and multi-threaded execution contexts, adapting its behavior accordingly. It also conditionally includes additional hash data if certain features are active. The function must be called with valid pointers for all parameters, and it assumes that the account data is not being modified concurrently.
- **Inputs**:
    - `funk`: A pointer to an fd_funk_t structure representing the account database. Must not be null.
    - `slot_bank`: A pointer to an fd_slot_bank_t structure representing the slot bank. Must not be null.
    - `accounts_hash`: A pointer to an fd_hash_t structure where the resulting account hash will be stored. Must not be null.
    - `runtime_spad`: A pointer to an fd_spad_t structure used for runtime scratchpad memory. Must not be null.
    - `features`: A pointer to an fd_features_t structure indicating which features are active. Must not be null.
    - `exec_para_ctx`: A pointer to an fd_exec_para_cb_ctx_t structure that provides context for parallel execution. Must not be null.
    - `lt_hash`: A pointer to an fd_lthash_value_t structure for storing additional hash data if certain features are active. Can be null if not needed.
- **Output**: Returns 0 on successful hash computation. The resulting hash is stored in the accounts_hash parameter, and optionally in lt_hash if provided and applicable.
- **See also**: [`fd_accounts_hash`](fd_hashes.c.driver.md#fd_accounts_hash)  (Implementation)


---
### fd\_snapshot\_service\_hash<!-- {{#callable_declaration:fd_snapshot_service_hash}} -->
Generates a snapshot hash for the account database.
- **Description**: This function computes a snapshot hash of the entire account database, optionally including the epoch account hash based on the state of the epoch bank. It is intended for use by the snapshot service, which does not have access to a slot context handle. The function must be called with valid pointers to the account hash, snapshot hash, slot bank, epoch bank, funk, thread pool, runtime scratchpad, and features. It is important to ensure that the epoch bank's slots are correctly set to determine whether the epoch account hash should be included in the snapshot hash.
- **Inputs**:
    - `accounts_hash`: A pointer to an fd_hash_t structure where the computed accounts hash will be stored. Must not be null.
    - `snapshot_hash`: A pointer to an fd_hash_t structure where the computed snapshot hash will be stored. Must not be null.
    - `slot_bank`: A pointer to an fd_slot_bank_t structure representing the slot bank. Must not be null.
    - `epoch_bank`: A pointer to an fd_epoch_bank_t structure representing the epoch bank. Must not be null. The function checks the eah_stop_slot and eah_start_slot to decide on including the epoch account hash.
    - `funk`: A pointer to an fd_funk_t structure representing the funk. Must not be null.
    - `tpool`: A pointer to an fd_tpool_t structure representing the thread pool. Must not be null.
    - `runtime_spad`: A pointer to an fd_spad_t structure used as a runtime scratchpad. Must not be null.
    - `features`: A pointer to an fd_features_t structure representing the features. Must not be null.
- **Output**: Returns 0 on successful computation of the snapshot hash.
- **See also**: [`fd_snapshot_service_hash`](fd_hashes.c.driver.md#fd_snapshot_service_hash)  (Implementation)


---
### fd\_snapshot\_service\_inc\_hash<!-- {{#callable_declaration:fd_snapshot_service_inc_hash}} -->
Generate an incremental snapshot hash for the account database.
- **Description**: This function is used to generate an incremental snapshot hash of the account database, which includes conditionally incorporating the epoch account hash based on the state of the epoch bank. It should be called when an updated snapshot hash is needed, particularly in contexts where the snapshot service is used. The function requires valid pointers to various structures representing the account and epoch banks, as well as a list of public keys. It is important to ensure that the epoch bank's state is correctly set to determine whether the epoch account hash should be included.
- **Inputs**:
    - `accounts_hash`: A pointer to an fd_hash_t structure where the current accounts hash is stored. Must not be null.
    - `snapshot_hash`: A pointer to an fd_hash_t structure where the resulting snapshot hash will be stored. Must not be null.
    - `slot_bank`: A pointer to an fd_slot_bank_t structure representing the slot bank. Must not be null.
    - `epoch_bank`: A pointer to an fd_epoch_bank_t structure representing the epoch bank. Must not be null.
    - `funk`: A pointer to an fd_funk_t structure representing the funk context. Must not be null.
    - `pubkeys`: A pointer to an array of fd_funk_rec_key_t pointers representing the public keys to be included in the hash. Must not be null.
    - `pubkeys_len`: The number of public keys in the pubkeys array. Must be non-negative.
    - `spad`: A pointer to an fd_spad_t structure used for temporary storage during hash computation. Must not be null.
    - `features`: A pointer to an fd_features_t structure representing feature flags. Must not be null.
- **Output**: Returns 0 on successful hash computation. The snapshot_hash is updated with the new hash value.
- **See also**: [`fd_snapshot_service_inc_hash`](fd_hashes.c.driver.md#fd_snapshot_service_inc_hash)  (Implementation)


---
### fd\_accounts\_check\_lthash<!-- {{#callable_declaration:fd_accounts_check_lthash}} -->
Verifies the long-term hash of account transactions.
- **Description**: This function is used to verify the integrity of account transactions by comparing the calculated long-term hash (lthash) against the expected value stored in the slot bank. It should be called when there is a need to ensure that the account transactions have not been tampered with. The function requires a valid transaction context and a slot bank to perform the verification. It logs a notice if the hashes match and an error if they do not, indicating a potential data integrity issue. The function must be called with valid pointers to the required structures, and it assumes that the transaction context is properly initialized and that the runtime scratchpad has sufficient memory for temporary allocations.
- **Inputs**:
    - `funk`: A pointer to an fd_funk_t structure representing the transaction context. Must not be null.
    - `funk_txn`: A pointer to an fd_funk_txn_t structure representing the current transaction. Must not be null.
    - `slot_bank`: A pointer to an fd_slot_bank_t structure where the expected lthash is stored. Must not be null.
    - `runtime_spad`: A pointer to an fd_spad_t structure used for temporary memory allocations. Must not be null and should have sufficient space for the function's needs.
    - `features`: A pointer to an fd_features_t structure representing feature flags. Must not be null.
- **Output**: None
- **See also**: [`fd_accounts_check_lthash`](fd_hashes.c.driver.md#fd_accounts_check_lthash)  (Implementation)


---
### fd\_calculate\_epoch\_accounts\_hash\_values<!-- {{#callable_declaration:fd_calculate_epoch_accounts_hash_values}} -->
Calculate epoch account hash values based on the current slot context.
- **Description**: This function determines the start, stop, and interval slots for calculating epoch account hash values within the given execution slot context. It should be called when you need to update or verify the hash values for accounts in a specific epoch. The function checks if certain features are active and adjusts the calculation parameters accordingly. It sets the start, stop, and interval slots to maximum values if the calculation interval is insufficient or if specific features are active, effectively disabling the calculation for those conditions.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the current execution slot context. This parameter must not be null, and the structure should be properly initialized before calling the function. The function uses this context to determine the current slot and epoch information.
- **Output**: None
- **See also**: [`fd_calculate_epoch_accounts_hash_values`](fd_hashes.c.driver.md#fd_calculate_epoch_accounts_hash_values)  (Implementation)


---
### fd\_accounts\_hash\_inc\_only<!-- {{#callable_declaration:fd_accounts_hash_inc_only}} -->
Generates an incremental hash for account records in a transaction.
- **Description**: This function computes an incremental hash for account records associated with a given transaction. It is used when you need to update the hash of accounts affected by a transaction without recalculating the entire database hash. The function should be called with a valid execution slot context and transaction. It optionally verifies existing hashes if the verification flag is set. Ensure that the scratchpad memory is properly initialized before calling this function.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution context. Must not be null.
    - `accounts_hash`: A pointer to an fd_hash_t structure where the resulting hash will be stored. Must not be null.
    - `child_txn`: A pointer to an fd_funk_txn_t structure representing the transaction whose account records are to be hashed. Must not be null.
    - `do_hash_verify`: An unsigned long flag indicating whether to verify existing hashes (non-zero) or not (zero).
    - `spad`: A pointer to an fd_spad_t structure used for temporary storage during hash computation. Must be properly initialized and not null.
- **Output**: Returns 0 on successful hash computation. The accounts_hash parameter is updated with the new hash value.
- **See also**: [`fd_accounts_hash_inc_only`](fd_hashes.c.driver.md#fd_accounts_hash_inc_only)  (Implementation)


---
### fd\_account\_hash\_task<!-- {{#callable_declaration:fd_account_hash_task}} -->
Processes a range of account hash tasks using a thread pool.
- **Description**: This function is used to process a range of account hash tasks, specified by the indices `t0` and `t1`, using a thread pool. It is typically called as part of a larger parallel processing framework where multiple tasks are distributed across threads. The function requires a valid task pool and arguments that include the hash values to be processed. It is important to ensure that the indices `t0` and `t1` are within the bounds of the task data provided in the thread pool. The function does not utilize the `reduce`, `stride`, `l0`, `l1`, `m0`, `m1`, `n0`, and `n1` parameters, which are marked as unused.
- **Inputs**:
    - `tpool`: A pointer to the thread pool containing task data. Must not be null and should point to a valid `fd_accounts_hash_task_data_t` structure.
    - `t0`: The starting index of the task range to process. Must be less than or equal to `t1` and within the bounds of the task data.
    - `t1`: The ending index of the task range to process. Must be greater than or equal to `t0` and within the bounds of the task data.
    - `args`: A pointer to the hash values to be processed. Must not be null and should point to a valid `fd_lthash_value_t` structure.
    - `reduce`: Unused parameter. Can be set to any value.
    - `stride`: Unused parameter. Can be set to any value.
    - `l0`: Unused parameter. Can be set to any value.
    - `l1`: Unused parameter. Can be set to any value.
    - `m0`: Unused parameter. Can be set to any value.
    - `m1`: Unused parameter. Can be set to any value.
    - `n0`: Unused parameter. Can be set to any value.
    - `n1`: Unused parameter. Can be set to any value.
- **Output**: None
- **See also**: [`fd_account_hash_task`](fd_hashes.c.driver.md#fd_account_hash_task)  (Implementation)



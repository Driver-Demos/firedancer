# Purpose
The provided C header file, `fd_snapshot.h`, is designed to facilitate high-level operations related to Solana blockchain snapshots. It offers a collection of blocking APIs that manage the loading and processing of snapshot data, which is crucial for initializing and maintaining the state of a Solana node. The file includes several function prototypes that handle different stages of snapshot loading, such as initializing the context, loading the manifest and status cache, and finalizing the snapshot load. These functions are structured to allow for efficient loading, enabling other operations to commence while the snapshot is being processed. This is particularly important for optimizing the time taken to load large snapshot files, which can be dominated by the loading of append vectors.

The header file defines several constants and structures, such as `fd_snapshot_load_ctx_t`, which are used to manage the snapshot loading context. It also includes functions for generating both non-incremental and incremental hashes of the account database, which are essential for verifying the integrity of the snapshot data. The file is intended to be included in other C source files, as indicated by the inclusion guards and the use of `FD_PROTOTYPES_BEGIN` and `FD_PROTOTYPES_END` macros, which suggest a modular design. The header file is part of a larger system, as evidenced by its dependencies on other headers like `fd_snapshot_base.h` and `fd_runtime_public.h`, and it is designed to be used in environments where the Zstandard (ZSTD) compression library is available, as indicated by the `FD_HAS_ZSTD` preprocessor directive.
# Imports and Dependencies

---
- `fd_snapshot_base.h`
- `../runtime/fd_runtime_public.h`
- `../../funk/fd_funk_txn.h`
- `../../ballet/lthash/fd_lthash.h`


# Global Variables

---
### fd\_snapshot\_load\_new
- **Type**: `fd_snapshot_load_ctx_t *`
- **Description**: The `fd_snapshot_load_new` function is responsible for setting up a new snapshot load context, which is used in the process of loading a snapshot in a Solana blockchain environment. It initializes the context with various parameters such as memory location, snapshot source, type, directory, and other execution-related contexts. This function is a part of a series of functions that manage the loading and initialization of snapshot data, allowing for efficient and organized snapshot management.
- **Use**: This variable is used to create and initialize a new context for loading a snapshot, which is then used by other functions to manage the snapshot loading process.


# Data Structures

---
### fd\_snapshot\_load\_ctx\_t
- **Type**: `struct`
- **Description**: The `fd_snapshot_load_ctx_t` is a forward-declared structure used as a context for loading snapshots in the Solana blockchain environment. It is utilized in various functions to manage the state and process of loading snapshots, including initialization, manifest and status cache loading, account loading, and finalization. The structure is essential for handling the complex operations involved in snapshot management, allowing for efficient and organized loading processes.


# Function Declarations (Public API)

---
### fd\_snapshot\_load\_ctx\_align<!-- {{#callable_declaration:fd_snapshot_load_ctx_align}} -->
Return the alignment requirement of the snapshot load context structure.
- **Description**: Use this function to determine the memory alignment requirement for the `fd_snapshot_load_ctx_t` structure. This is useful when allocating memory for instances of this structure to ensure proper alignment, which is necessary for correct and efficient access on most architectures. This function should be called before allocating memory for `fd_snapshot_load_ctx_t` to ensure that the memory is aligned correctly.
- **Inputs**: None
- **Output**: Returns the alignment requirement in bytes for the `fd_snapshot_load_ctx_t` structure.
- **See also**: [`fd_snapshot_load_ctx_align`](fd_snapshot.c.driver.md#fd_snapshot_load_ctx_align)  (Implementation)


---
### fd\_snapshot\_load\_ctx\_footprint<!-- {{#callable_declaration:fd_snapshot_load_ctx_footprint}} -->
Return the size of the snapshot load context structure.
- **Description**: Use this function to determine the memory footprint required for a `fd_snapshot_load_ctx_t` structure. This is useful when allocating memory for snapshot loading operations, ensuring that sufficient space is reserved for the context structure. It is typically called before initializing or creating a new snapshot load context.
- **Inputs**: None
- **Output**: The function returns an `ulong` representing the size in bytes of the `fd_snapshot_load_ctx_t` structure.
- **See also**: [`fd_snapshot_load_ctx_footprint`](fd_snapshot.c.driver.md#fd_snapshot_load_ctx_footprint)  (Implementation)


---
### fd\_snapshot\_load\_new<!-- {{#callable_declaration:fd_snapshot_load_new}} -->
Initialize a snapshot load context with specified parameters.
- **Description**: This function sets up a new snapshot load context, which is essential for managing the state and parameters required for loading a snapshot in a Solana environment. It should be called before any other snapshot load operations to ensure that the context is properly initialized. The function requires a pre-allocated memory buffer to store the context and various parameters that define the source and type of the snapshot, as well as options for hash verification and execution contexts. The caller must ensure that the provided memory buffer is appropriately aligned and sized to accommodate the context structure.
- **Inputs**:
    - `mem`: A pointer to a pre-allocated memory buffer where the context will be initialized. The buffer must be properly aligned and large enough to hold the context structure.
    - `snapshot_src`: A string representing the source of the snapshot, such as a file path. Must not be null.
    - `snapshot_src_type`: An integer indicating the type of the snapshot source. Valid values are context-specific and should be defined elsewhere.
    - `snapshot_dir`: A string representing the directory where the snapshot is located. Must not be null.
    - `slot_ctx`: A pointer to an initialized slot context. The caller retains ownership and must ensure it remains valid for the duration of the snapshot load process.
    - `verify_hash`: A non-zero value indicates that the snapshot hash should be calculated for verification purposes.
    - `check_hash`: A non-zero value indicates that the snapshot hash should be checked against the file name to ensure integrity.
    - `snapshot_type`: An integer specifying the type of snapshot. Valid values are defined by FD_SNAPSHOT_TYPE_{...} constants.
    - `exec_spads`: A pointer to an array of execution scratchpads. This parameter is currently unused in the function.
    - `exec_spad_cnt`: The number of execution scratchpads provided. This parameter is currently unused in the function.
    - `runtime_spad`: A pointer to a runtime scratchpad used during the snapshot load process. Must be valid and properly initialized.
    - `exec_para_ctx`: A pointer to an execution parameter callback context. The caller retains ownership and must ensure it remains valid for the duration of the snapshot load process.
- **Output**: Returns a pointer to the initialized snapshot load context.
- **See also**: [`fd_snapshot_load_new`](fd_snapshot.c.driver.md#fd_snapshot_load_new)  (Implementation)


---
### fd\_snapshot\_load\_init<!-- {{#callable_declaration:fd_snapshot_load_init}} -->
Initialize the snapshot loading context for a snapshot load operation.
- **Description**: This function prepares the snapshot loading context for the process of loading a snapshot, setting up necessary transactions and logging the operation's initiation. It should be called after creating a new snapshot load context with `fd_snapshot_load_new` and before loading the manifest and status cache. The function handles different snapshot types, logging errors for unspecified types and notices for full or incremental types. It also manages transaction setup based on the context's configuration, particularly when hash verification is enabled.
- **Inputs**:
    - `ctx`: A pointer to an `fd_snapshot_load_ctx_t` structure that represents the snapshot loading context. This context must be initialized with `fd_snapshot_load_new` before calling this function. The function expects a valid pointer and will log an error if the snapshot type is unspecified.
- **Output**: None
- **See also**: [`fd_snapshot_load_init`](fd_snapshot.c.driver.md#fd_snapshot_load_init)  (Implementation)


---
### fd\_snapshot\_load\_manifest\_and\_status\_cache<!-- {{#callable_declaration:fd_snapshot_load_manifest_and_status_cache}} -->
Loads the manifest and status cache from a snapshot.
- **Description**: This function is used to load the manifest and optionally the status cache from a snapshot source into the provided context. It should be called after initializing the snapshot load context with `fd_snapshot_load_new` and `fd_snapshot_load_init`. The function allows for an optional base slot override and uses flags to determine whether to initialize the manifest and status cache objects. It is designed to quickly load the manifest to enable other operations to start while the rest of the snapshot is being processed.
- **Inputs**:
    - `ctx`: A pointer to an initialized `fd_snapshot_load_ctx_t` structure. This context must be set up using `fd_snapshot_load_new` and `fd_snapshot_load_init` before calling this function. The caller retains ownership.
    - `base_slot_override`: An optional pointer to an `ulong` that specifies a base slot to override the default. If null, the function uses the slot from the context's slot bank. The caller retains ownership.
    - `restore_manifest_flags`: An integer flag that controls whether the manifest and status cache objects are initialized. Valid values are `FD_SNAPSHOT_RESTORE_NONE`, `FD_SNAPSHOT_RESTORE_MANIFEST`, and `FD_SNAPSHOT_RESTORE_STATUS_CACHE`. Invalid values may lead to undefined behavior.
- **Output**: None
- **See also**: [`fd_snapshot_load_manifest_and_status_cache`](fd_snapshot.c.driver.md#fd_snapshot_load_manifest_and_status_cache)  (Implementation)


---
### fd\_snapshot\_load\_accounts<!-- {{#callable_declaration:fd_snapshot_load_accounts}} -->
Loads the remaining accounts from a snapshot file.
- **Description**: This function is used to load the remaining accounts from a snapshot file after the manifest has been processed. It should be called as part of the snapshot loading sequence, specifically after the manifest and status cache have been loaded. This function is blocking and will continue to load accounts until the snapshot is fully processed. It is important to ensure that the context provided is properly initialized and that the manifest has been successfully loaded before calling this function. The function logs errors if it encounters issues during the loading process.
- **Inputs**:
    - `ctx`: A pointer to an initialized fd_snapshot_load_ctx_t structure. This context must have been set up by previous steps in the snapshot loading process. The pointer must not be null, and it is the caller's responsibility to ensure the context is valid and correctly initialized.
- **Output**: None
- **See also**: [`fd_snapshot_load_accounts`](fd_snapshot.c.driver.md#fd_snapshot_load_accounts)  (Implementation)


---
### fd\_snapshot\_load\_fini<!-- {{#callable_declaration:fd_snapshot_load_fini}} -->
Finalizes the snapshot loading process using the provided context.
- **Description**: This function is used to complete the snapshot loading process by utilizing the slot context and funk transactions that have been populated during the earlier stages of loading. It should be called after the snapshot has been fully loaded and the runtime is ready to be set up. The function verifies the snapshot type and hash if required, and ensures that the necessary features are active. It also handles the publication of transactions if there are any child transactions different from the parent transaction. This function must be called after all other snapshot loading functions have been executed to ensure the snapshot is correctly finalized.
- **Inputs**:
    - `ctx`: A pointer to an fd_snapshot_load_ctx_t structure that contains the context for the snapshot loading process. This parameter must not be null and should be properly initialized by previous snapshot loading functions. The function will log errors if the snapshot type is incorrect or if hash verification fails.
- **Output**: None
- **See also**: [`fd_snapshot_load_fini`](fd_snapshot.c.driver.md#fd_snapshot_load_fini)  (Implementation)


---
### fd\_snapshot\_load\_all<!-- {{#callable_declaration:fd_snapshot_load_all}} -->
Performs a blocking load of a Solana snapshot.
- **Description**: This function is used to load a Solana snapshot in a blocking manner, setting up the necessary context and initializing the runtime environment. It should be called when a complete snapshot load is required, including manifest and status cache initialization, and when the runtime needs to be prepared for execution. The function requires a valid slot context and sufficient space in the runtime scratchpad to buffer the snapshot's manifest. It also provides options to verify and check the snapshot hash, which can be useful for ensuring data integrity. The function is designed to handle different snapshot types and source types, and it supports parallel execution through a thread pool.
- **Inputs**:
    - `source_cstr`: A string representing the source of the snapshot, typically a local file system path. Must not be null.
    - `source_type`: An integer indicating the type of the source. Valid values depend on the implementation and are not specified in the header.
    - `snapshot_dir`: A string representing the directory where the snapshot is located. Must not be null.
    - `slot_ctx`: A pointer to a valid and initialized fd_exec_slot_ctx_t structure. Must not be null.
    - `base_slot_override`: A pointer to an unsigned long where the base slot override will be stored. Can be null if no override is needed.
    - `tpool`: A pointer to a fd_tpool_t structure representing the thread pool for parallel execution. Must not be null.
    - `verify_hash`: An unsigned integer flag indicating whether to calculate the snapshot hash. Non-zero to enable.
    - `check_hash`: An unsigned integer flag indicating whether to check that the snapshot hash matches the file name. Non-zero to enable.
    - `snapshot_type`: An integer representing the type of snapshot. Must be one of the defined FD_SNAPSHOT_TYPE_{...} constants.
    - `exec_spads`: A pointer to an array of fd_spad_t pointers for execution scratchpads. Must not be null if exec_spad_cnt is non-zero.
    - `exec_spad_cnt`: An unsigned long indicating the number of execution scratchpads. Must be non-zero if exec_spads is not null.
    - `runtime_spad`: A pointer to a fd_spad_t structure for the runtime scratchpad. Must not be null and should have enough space to buffer the snapshot's manifest.
- **Output**: None
- **See also**: [`fd_snapshot_load_all`](fd_snapshot.c.driver.md#fd_snapshot_load_all)  (Implementation)


---
### fd\_snapshot\_load\_prefetch\_manifest<!-- {{#callable_declaration:fd_snapshot_load_prefetch_manifest}} -->
Prefetches the manifest for a snapshot load context.
- **Description**: Use this function to prefetch the manifest of a snapshot into the provided load context. This is typically done to prepare the context for further snapshot loading operations, ensuring that the manifest is available for quick access. The function must be called with a valid and initialized `fd_snapshot_load_ctx_t` structure. It is important to ensure that the context's memory allocations and initializations are properly set up before calling this function to avoid errors.
- **Inputs**:
    - `ctx`: A pointer to a `fd_snapshot_load_ctx_t` structure that represents the snapshot load context. This must be a valid, non-null pointer, and the context should be properly initialized before calling this function. The function will use this context to manage the prefetching of the snapshot manifest.
- **Output**: None
- **See also**: [`fd_snapshot_load_prefetch_manifest`](fd_snapshot.c.driver.md#fd_snapshot_load_prefetch_manifest)  (Implementation)


---
### fd\_snapshot\_get\_slot<!-- {{#callable_declaration:fd_snapshot_get_slot}} -->
Retrieve the slot number from the snapshot load context.
- **Description**: Use this function to obtain the slot number associated with a given snapshot load context. This is typically used after initializing or loading a snapshot to determine the specific slot that the snapshot corresponds to. Ensure that the context provided is valid and has been properly initialized or loaded with snapshot data before calling this function.
- **Inputs**:
    - `ctx`: A pointer to a `fd_snapshot_load_ctx_t` structure representing the snapshot load context. This must be a valid, non-null pointer to a context that has been initialized or loaded with snapshot data. If the context is invalid or uninitialized, the behavior is undefined.
- **Output**: Returns an unsigned long integer representing the slot number associated with the provided snapshot load context.
- **See also**: [`fd_snapshot_get_slot`](fd_snapshot.c.driver.md#fd_snapshot_get_slot)  (Implementation)


---
### fd\_snapshot\_hash<!-- {{#callable_declaration:fd_snapshot_hash}} -->
Generate a non-incremental hash of the entire account database.
- **Description**: This function computes a non-incremental hash of the entire account database, optionally including the epoch account hash. It is typically used to verify the integrity of the account data by generating a hash that can be compared against expected values. The function must be called with a valid slot context and other necessary parameters. It does not modify the input parameters except for the accounts_hash, which will contain the resulting hash. The check_hash parameter is ignored in this function.
- **Inputs**:
    - `slot_ctx`: A pointer to a valid fd_exec_slot_ctx_t structure representing the execution slot context. Must not be null.
    - `accounts_hash`: A pointer to an fd_hash_t structure where the resulting hash will be stored. Must not be null.
    - `check_hash`: An unsigned integer that is ignored by this function.
    - `runtime_spad`: A pointer to an fd_spad_t structure used for runtime operations. Must not be null.
    - `exec_para_ctx`: A pointer to an fd_exec_para_cb_ctx_t structure for execution parameters. Must not be null.
    - `lt_hash`: A pointer to an fd_lthash_value_t structure used in the hashing process. Must not be null.
- **Output**: Returns 0 on success, indicating the hash was successfully generated and stored in accounts_hash.
- **See also**: [`fd_snapshot_hash`](fd_snapshot.c.driver.md#fd_snapshot_hash)  (Implementation)


---
### fd\_snapshot\_inc\_hash<!-- {{#callable_declaration:fd_snapshot_inc_hash}} -->
Generate an incremental hash of the account database.
- **Description**: This function computes an incremental hash of the entire account database, optionally including the epoch account hash, based on the provided slot context. It should be used when an incremental update to the account hash is needed, such as during transaction processing. The function requires a valid slot context and may verify the hash if specified. It returns an integer status code indicating success or failure.
- **Inputs**:
    - `slot_ctx`: A pointer to a valid and initialized fd_exec_slot_ctx_t structure representing the execution slot context. Must not be null.
    - `accounts_hash`: A pointer to an fd_hash_t structure where the resulting hash will be stored. Must not be null.
    - `child_txn`: A pointer to an fd_funk_txn_t structure representing the child transaction to be included in the hash computation. Must not be null.
    - `check_hash`: An unsigned integer flag indicating whether to verify the hash. Non-zero values enable hash verification.
    - `spad`: A pointer to an fd_spad_t structure used for temporary storage during hash computation. Must not be null.
    - `lt_hash`: A pointer to an fd_lthash_value_t structure, which is not used in this function. Can be null.
- **Output**: Returns an integer status code: 0 on success, or a non-zero value on failure.
- **See also**: [`fd_snapshot_inc_hash`](fd_snapshot.c.driver.md#fd_snapshot_inc_hash)  (Implementation)



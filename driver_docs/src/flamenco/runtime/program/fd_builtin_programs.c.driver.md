# Purpose
This C source file is part of a larger system that manages and initializes built-in programs within a blockchain runtime environment, specifically for the Solana blockchain. The file defines and initializes various built-in programs, stateless programs, and precompiled programs, which are essential components of the blockchain's execution environment. These programs include system-level functionalities such as the system program, vote program, stake program, and various loader programs, among others. The file also handles the migration of certain built-in programs to a core BPF (Berkeley Packet Filter) environment, which is a part of the blockchain's feature upgrade mechanism.

The file includes several macros and data structures to define and manage these programs, such as `BUILTIN_PROGRAM`, `STATELESS_BUILTIN`, and `PRECOMPILE`. It also provides functions to initialize these programs within a given execution context ([`fd_builtin_programs_init`](#fd_builtin_programs_init)) and to check the migration status of programs ([`fd_is_migrating_builtin_program`](#fd_is_migrating_builtin_program)). Additionally, the file includes mechanisms to write "bogus" executable accounts, which are necessary for the built-in programs to function correctly within the blockchain's execution model. Overall, this file is crucial for setting up and managing the built-in programs that form the backbone of the Solana blockchain's runtime environment.
# Imports and Dependencies

---
- `fd_builtin_programs.h`
- `fd_precompiles.h`
- `../fd_runtime.h`
- `../fd_acc_mgr.h`
- `../fd_system_ids.h`
- `../fd_system_ids_pp.h`
- `../../../util/tmpl/fd_map_perfect.c`


# Global Variables

---
### stateless\_programs\_builtins
- **Type**: ``fd_stateless_builtin_program_t[]``
- **Description**: The `stateless_programs_builtins` is a static constant array of type `fd_stateless_builtin_program_t`, which is used to store stateless built-in programs. It is initialized with the macro `FEATURE_PROGRAM_BUILTIN`, which represents a specific stateless built-in program configuration.
- **Use**: This variable is used to define and store the configurations of stateless built-in programs for the system.


---
### precompiles
- **Type**: `fd_precompile_program_t[]`
- **Description**: The `precompiles` variable is a static constant array of type `fd_precompile_program_t`, which holds precompiled program configurations. It includes entries for SECP256R1, KECCAK SECP, and ED25519 signature verification programs. These precompiled programs are used to optimize certain cryptographic operations within the system.
- **Use**: This variable is used to store and manage precompiled program configurations for efficient execution of specific cryptographic operations.


---
### builtin\_programs
- **Type**: `fd_builtin_program_t const[]`
- **Description**: The `builtin_programs` variable is a static array of `fd_builtin_program_t` structures, each representing a built-in program in the system. These programs include various Solana programs such as the system program, vote program, stake program, and others, each defined with specific identifiers and configurations.
- **Use**: This variable is used to store and manage the list of built-in programs available in the system, facilitating their initialization and execution.


---
### migrating\_builtins
- **Type**: `fd_core_bpf_migration_config_t const *`
- **Description**: The `migrating_builtins` variable is an array of pointers to `fd_core_bpf_migration_config_t` structures. Each element in the array represents a configuration for migrating a specific built-in program to the Core BPF (Berkeley Packet Filter) system. The array is statically defined and contains configurations for the stake program, config program, and address lookup table program.
- **Use**: This variable is used to store and access the migration configurations for specific built-in programs that are transitioning to the Core BPF system.


# Functions

---
### fd\_write\_builtin\_account<!-- {{#callable:fd_write_builtin_account}} -->
The `fd_write_builtin_account` function initializes and updates a built-in account with specific properties in a transaction context.
- **Inputs**:
    - `slot_ctx`: A pointer to the execution slot context (`fd_exec_slot_ctx_t`), which contains the transaction and funk context.
    - `pubkey`: A constant public key (`fd_pubkey_t`) representing the account to be written.
    - `data`: A constant character pointer to the data to be set in the account.
    - `sz`: An unsigned long representing the size of the data to be set in the account.
- **Control Flow**:
    - Retrieve the funk and transaction context from the `slot_ctx`.
    - Declare a transaction account record `rec`.
    - Initialize the account record `rec` from the funk context with the given public key, allowing it to be mutable, and check for errors.
    - Set the account's data, lamports, rent epoch, executable flag, and owner using the `rec`'s virtual table functions.
    - Finalize the mutable account record `rec` in the funk context.
    - Increment the capitalization of the slot bank in the `slot_ctx`.
    - Check for errors in committing the account manager, though this part is commented out.
- **Output**: The function does not return a value; it operates by side effects on the `slot_ctx` and the account record `rec`.


---
### write\_inline\_spl\_native\_mint\_program\_account<!-- {{#callable:write_inline_spl_native_mint_program_account}} -->
The function `write_inline_spl_native_mint_program_account` initializes and configures a Solana SPL native mint program account with specific parameters if the cluster type is 3.
- **Inputs**:
    - `slot_ctx`: A pointer to an `fd_exec_slot_ctx_t` structure, which contains context information for the execution slot, including epoch context and transaction details.
- **Control Flow**:
    - Retrieve the epoch bank from the slot context's epoch context.
    - Check if the cluster type of the epoch bank is 3; if not, return immediately.
    - Retrieve the `funk` and `txn` from the slot context.
    - Define a public key `key` pointing to the SPL native mint ID.
    - Declare a transaction account record `rec`.
    - Initialize the transaction account from the `funk` with the public key, setting it as mutable and specifying the size of the data array.
    - Check for errors in the initialization using `FD_TEST`.
    - Set the lamports, rent epoch, executable flag, owner, and data for the account using the `rec`'s virtual table functions.
    - Finalize the mutable transaction account.
    - Check for errors again using `FD_TEST`.
- **Output**: The function does not return a value; it modifies the state of the transaction account within the provided execution slot context.


---
### fd\_builtin\_programs\_init<!-- {{#callable:fd_builtin_programs_init}} -->
The `fd_builtin_programs_init` function initializes built-in programs by writing their accounts based on feature activation and migration configurations.
- **Inputs**:
    - `slot_ctx`: A pointer to an `fd_exec_slot_ctx_t` structure, which contains context information about the execution slot, including the slot bank and epoch context.
- **Control Flow**:
    - Retrieve the list of built-in programs using `fd_builtins()` and iterate over them.
    - For each built-in program, check if it has a core BPF migration configuration and if the corresponding feature is active; if so, skip writing the account.
    - If the program has an enable feature offset and the feature is not active, skip writing the account.
    - Otherwise, write the built-in account using [`fd_write_builtin_account`](#fd_write_builtin_account) with the program's public key and data.
    - Check if specific features like `zk_token_sdk_enabled` and `zk_elgamal_proof_program_enabled` are active, and write their accounts if they are.
    - Depending on the cluster version, write precompile accounts with either empty or non-empty data.
    - Call [`write_inline_spl_native_mint_program_account`](#write_inline_spl_native_mint_program_account) to write the inline SPL token mint program account.
- **Output**: The function does not return a value; it performs operations to initialize built-in program accounts in the provided execution slot context.
- **Functions called**:
    - [`fd_builtins`](#fd_builtins)
    - [`fd_num_builtins`](#fd_num_builtins)
    - [`fd_write_builtin_account`](#fd_write_builtin_account)
    - [`write_inline_spl_native_mint_program_account`](#write_inline_spl_native_mint_program_account)


---
### fd\_builtins<!-- {{#callable:fd_builtins}} -->
The `fd_builtins` function returns a pointer to an array of built-in program configurations.
- **Inputs**: None
- **Control Flow**:
    - The function is defined to return a pointer to a constant `fd_builtin_program_t` type.
    - It directly returns the `builtin_programs` array, which is a static constant array of built-in program configurations.
- **Output**: A pointer to the `builtin_programs` array, which contains configurations for various built-in programs.


---
### fd\_num\_builtins<!-- {{#callable:fd_num_builtins}} -->
The `fd_num_builtins` function returns the total number of built-in programs defined in the system.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of the macro `BUILTIN_PROGRAMS_COUNT`.
- **Output**: The function outputs an unsigned long integer representing the count of built-in programs.


---
### fd\_stateless\_builtins<!-- {{#callable:fd_stateless_builtins}} -->
The `fd_stateless_builtins` function returns a pointer to an array of stateless built-in programs.
- **Inputs**: None
- **Control Flow**:
    - The function simply returns the `stateless_programs_builtins` array, which is a static constant array of `fd_stateless_builtin_program_t` structures.
    - There are no conditional statements, loops, or complex logic in this function.
- **Output**: A pointer to a constant array of `fd_stateless_builtin_program_t` structures, representing stateless built-in programs.


---
### fd\_num\_stateless\_builtins<!-- {{#callable:fd_num_stateless_builtins}} -->
The function `fd_num_stateless_builtins` returns the count of stateless built-in programs.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of the macro `STATELESS_BUILTINS_COUNT`.
- **Output**: The function outputs an unsigned long integer representing the number of stateless built-in programs.


---
### fd\_precompiles<!-- {{#callable:fd_precompiles}} -->
The `fd_precompiles` function returns a pointer to an array of precompiled program configurations.
- **Inputs**: None
- **Control Flow**:
    - The function simply returns the `precompiles` array, which is a static constant array of `fd_precompile_program_t` structures.
    - There are no conditional statements or loops; the function is straightforward and returns the pre-defined array.
- **Output**: A pointer to a constant array of `fd_precompile_program_t` structures, representing precompiled program configurations.


---
### fd\_num\_precompiles<!-- {{#callable:fd_num_precompiles}} -->
The `fd_num_precompiles` function returns the total number of precompiled programs defined in the system.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of the macro `PRECOMPILE_PROGRAMS_COUNT`.
- **Output**: The function outputs an unsigned long integer representing the count of precompiled programs.


---
### fd\_is\_migrating\_builtin\_program<!-- {{#callable:fd_is_migrating_builtin_program}} -->
The function `fd_is_migrating_builtin_program` checks if a given built-in program identified by a public key is in the process of migrating to BPF (Berkeley Packet Filter) and updates a flag indicating if the migration has occurred.
- **Inputs**:
    - `txn_ctx`: A pointer to a constant `fd_exec_txn_ctx_t` structure representing the transaction context, which includes the current slot and feature set.
    - `pubkey`: A pointer to a constant `fd_pubkey_t` structure representing the public key of the program to check for migration.
    - `migrated_yet`: A pointer to an `uchar` that will be set to 1 if the program has been migrated to BPF, otherwise it remains 0.
- **Control Flow**:
    - Initialize `migrated_yet` to 0, indicating no migration by default.
    - Iterate over each configuration in `migrating_builtins` array, which contains migration configurations for built-in programs.
    - For each configuration, compare the public key of the program with the `builtin_program_id` in the configuration using `memcmp`.
    - If a match is found, check if the `enable_feature_offset` is not `NO_ENABLE_FEATURE_ID` and if the feature is active using `FD_FEATURE_ACTIVE_OFFSET`.
    - If the feature is active, set `migrated_yet` to 1, indicating the program has been migrated to BPF.
    - Return 1 if a matching configuration is found, otherwise return 0 after the loop.
- **Output**: Returns 1 if the program is found in the migration list and possibly migrated, otherwise returns 0.


---
### fd\_is\_non\_migrating\_builtin\_program<!-- {{#callable:fd_is_non_migrating_builtin_program}} -->
The function `fd_is_non_migrating_builtin_program` checks if a given public key corresponds to a non-migrating built-in program.
- **Inputs**:
    - `pubkey`: A pointer to a `fd_pubkey_t` structure representing the public key to be checked.
- **Control Flow**:
    - The function calls `fd_non_migrating_builtins_tbl_contains` with the provided `pubkey` to check if it is in the non-migrating built-ins table.
    - The result of the table check is converted to a boolean value using the double negation operator `!!` and returned.
- **Output**: The function returns an `uchar` (unsigned char) that is non-zero if the public key is a non-migrating built-in program, and zero otherwise.



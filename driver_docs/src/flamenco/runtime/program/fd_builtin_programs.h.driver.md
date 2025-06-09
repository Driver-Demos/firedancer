# Purpose
This C header file, `fd_buildin_programs.h`, is part of a larger software system and provides definitions and declarations related to the management and configuration of built-in programs within a runtime environment. The file defines several data structures, such as `fd_core_bpf_migration_config`, `fd_builtin_program`, `fd_stateless_builtin_program`, and `fd_precompile_program`, which are used to represent different types of built-in programs and their configurations, particularly in the context of migration to Core BPF (Berkeley Packet Filter) and feature activation at epoch boundaries. These structures encapsulate information such as public keys, data, feature offsets, and migration configurations, which are essential for managing the lifecycle and transitions of these programs.

Additionally, the file declares a set of functions that provide an interface for initializing built-in program accounts, writing to these accounts, and querying information about the built-in programs. Functions like [`fd_builtin_programs_init`](#fd_builtin_programs_init), [`fd_write_builtin_account`](#fd_write_builtin_account), and [`fd_is_migrating_builtin_program`](#fd_is_migrating_builtin_program) are crucial for interacting with the built-in programs, determining their migration status, and managing their execution context. This header file is intended to be included in other parts of the software system, providing a public API for handling built-in programs, which are likely a core component of the system's runtime functionality.
# Imports and Dependencies

---
- `../../fd_flamenco_base.h`
- `../../runtime/fd_system_ids.h`
- `../../features/fd_features.h`
- `../context/fd_exec_epoch_ctx.h`
- `../context/fd_exec_slot_ctx.h`
- `../fd_system_ids.h`
- `../fd_system_ids_pp.h`


# Global Variables

---
### fd\_builtins
- **Type**: `fd_builtin_program_t const *`
- **Description**: The `fd_builtins` variable is a pointer to a constant `fd_builtin_program_t` structure. This structure represents built-in programs that transition at epoch boundaries when features are activated, containing information such as a public key, data, and a configuration for core BPF migration.
- **Use**: This variable is used to access the built-in programs that are part of the system, allowing for their initialization and management.


---
### fd\_stateless\_builtins
- **Type**: `fd_stateless_builtin_program_t const *`
- **Description**: The `fd_stateless_builtins` is a function that returns a pointer to a constant `fd_stateless_builtin_program_t` structure. This structure represents stateless built-in programs that transition at epoch boundaries when features are activated.
- **Use**: This variable is used to access the stateless built-in programs within the system, allowing for their management and transition during feature activation.


---
### fd\_precompiles
- **Type**: `fd_precompile_program_t const *`
- **Description**: The `fd_precompiles` is a function that returns a pointer to a constant `fd_precompile_program_t` structure. This structure represents a precompiled program with associated metadata such as a public key, feature offset, and a verification function.
- **Use**: This variable is used to access the list of precompiled programs available in the system.


# Data Structures

---
### fd\_core\_bpf\_migration\_config
- **Type**: `struct`
- **Members**:
    - `source_buffer_address`: A pointer to a constant fd_pubkey_t representing the source buffer address.
    - `upgrade_authority_address`: A pointer to an fd_pubkey_t representing the upgrade authority address.
    - `enable_feature_offset`: An unsigned long integer indicating the offset for enabling a feature.
    - `builtin_program_id`: A pointer to a constant fd_pubkey_t representing the built-in program ID.
- **Description**: The `fd_core_bpf_migration_config` structure is designed to configure the migration of a built-in program to Core BPF. It includes pointers to public key structures for the source buffer and upgrade authority, an offset for enabling features, and a built-in program ID. This configuration is crucial for managing the transition of programs within the system, ensuring that the correct authorities and identifiers are used during the migration process.


---
### fd\_core\_bpf\_migration\_config\_t
- **Type**: `struct`
- **Members**:
    - `source_buffer_address`: A pointer to a constant fd_pubkey_t representing the source buffer address.
    - `upgrade_authority_address`: A pointer to an fd_pubkey_t representing the upgrade authority address.
    - `enable_feature_offset`: An unsigned long integer indicating the offset for enabling a feature.
    - `builtin_program_id`: A pointer to a constant fd_pubkey_t representing the built-in program ID.
- **Description**: The `fd_core_bpf_migration_config_t` structure is designed to hold configuration details necessary for migrating a built-in program to Core BPF. It includes pointers to public key structures for the source buffer and upgrade authority, an offset for enabling features, and the ID of the built-in program. This configuration is crucial for managing the transition of programs within the system, ensuring that the correct authorities and identifiers are used during the migration process.


---
### fd\_builtin\_program
- **Type**: `struct`
- **Members**:
    - `pubkey`: A constant pointer to a public key associated with the built-in program.
    - `data`: A constant pointer to a character array containing data related to the built-in program.
    - `enable_feature_offset`: An unsigned long integer representing the offset for enabling a feature.
    - `core_bpf_migration_config`: A constant pointer to a configuration structure for Core BPF migration.
- **Description**: The `fd_builtin_program` structure is designed to represent a built-in program within a system, encapsulating essential information such as its public key, associated data, and configuration details for migration to Core BPF. This structure is used to manage transitions of built-in programs at epoch boundaries when features are activated, providing a framework for handling program upgrades and migrations efficiently.


---
### fd\_builtin\_program\_t
- **Type**: `struct`
- **Members**:
    - `pubkey`: A constant pointer to a public key associated with the built-in program.
    - `data`: A constant pointer to character data related to the built-in program.
    - `enable_feature_offset`: An unsigned long integer indicating the offset for enabling a feature.
    - `core_bpf_migration_config`: A constant pointer to a configuration structure for Core BPF migration.
- **Description**: The `fd_builtin_program_t` structure represents a built-in program within the system, encapsulating essential information such as its public key, associated data, and configuration details for migration to Core BPF. This structure is used to manage transitions of built-in programs at epoch boundaries when features are activated, providing a framework for handling program upgrades and feature enablement.


---
### fd\_stateless\_builtin\_program
- **Type**: `struct`
- **Members**:
    - `pubkey`: A pointer to a constant `fd_pubkey_t` representing the public key associated with the stateless built-in program.
    - `core_bpf_migration_config`: A pointer to a constant `fd_core_bpf_migration_config_t` that holds configuration details for migrating the built-in program to Core BPF.
- **Description**: The `fd_stateless_builtin_program` structure is designed to represent stateless built-in programs within a system, particularly in the context of transitions at epoch boundaries when features are activated. It contains a public key to identify the program and a configuration structure for handling migrations to Core BPF, which is a part of the system's feature management and upgrade process.


---
### fd\_stateless\_builtin\_program\_t
- **Type**: `struct`
- **Members**:
    - `pubkey`: A pointer to a constant fd_pubkey_t representing the public key of the stateless built-in program.
    - `core_bpf_migration_config`: A pointer to a constant fd_core_bpf_migration_config_t containing configuration details for migrating the program to Core BPF.
- **Description**: The `fd_stateless_builtin_program_t` structure represents a stateless built-in program in the system, which is used to manage transitions at epoch boundaries when features are activated. It contains a public key to identify the program and a configuration for migrating the program to Core BPF, ensuring that the program can be updated or modified without maintaining state across epochs.


---
### fd\_precompile\_program
- **Type**: `struct`
- **Members**:
    - `pubkey`: A pointer to a constant public key associated with the precompiled program.
    - `feature_offset`: An unsigned long integer representing the offset for a specific feature.
    - `verify_fn`: A pointer to a function that takes a context and returns an integer, used for verification purposes.
- **Description**: The `fd_precompile_program` structure is designed to represent a precompiled program within a system, containing a public key, a feature offset, and a verification function. This structure is likely used in contexts where precompiled programs need to be identified, associated with specific features, and verified for correctness or authenticity. The `pubkey` serves as a unique identifier, the `feature_offset` indicates the position or activation point of a feature, and the `verify_fn` provides a mechanism to validate the program's execution context.


---
### fd\_precompile\_program\_t
- **Type**: `struct`
- **Members**:
    - `pubkey`: A pointer to a constant `fd_pubkey_t` representing the public key associated with the precompile program.
    - `feature_offset`: An unsigned long integer indicating the offset for the feature associated with the precompile program.
    - `verify_fn`: A pointer to a function that takes a `fd_exec_instr_ctx_t*` and returns an integer, used to verify the precompile program.
- **Description**: The `fd_precompile_program_t` structure represents a precompiled program in the system, identified by a public key and associated with a specific feature offset. It includes a verification function pointer that is used to validate the execution context of the program. This structure is part of a larger system for managing built-in and precompiled programs, particularly in the context of feature activation and migration within a runtime environment.


# Function Declarations (Public API)

---
### fd\_builtin\_programs\_init<!-- {{#callable_declaration:fd_builtin_programs_init}} -->
Initialize the builtin program accounts.
- **Description**: This function sets up the builtin program accounts for the given execution slot context. It should be called to ensure that all necessary builtin programs are initialized and available for use within the specified slot context. The function checks for feature activations and configures the accounts accordingly, including handling special cases for precompiles and inline SPL token mint programs. It is important to call this function after the slot context has been properly initialized and before any operations that depend on these builtin programs are performed.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. This parameter must not be null, and the context should be fully initialized before calling this function. The function will use this context to determine which features are active and configure the builtin program accounts accordingly.
- **Output**: None
- **See also**: [`fd_builtin_programs_init`](fd_builtin_programs.c.driver.md#fd_builtin_programs_init)  (Implementation)


---
### fd\_write\_builtin\_account<!-- {{#callable_declaration:fd_write_builtin_account}} -->
Writes data to a built-in account in the execution slot context.
- **Description**: This function is used to write data to a built-in account identified by a public key within a given execution slot context. It should be called when there is a need to update the account data, lamports, rent epoch, executable status, and owner for a built-in program. The function assumes that the slot context and the public key are valid and that the data size is appropriate for the account. It modifies the account's properties and increments the slot bank's capitalization. The function must be used in a context where the slot context and transaction are properly initialized.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. Must not be null and should be properly initialized before calling this function.
    - `pubkey`: A constant fd_pubkey_t representing the public key of the account to be written to. Must be a valid public key.
    - `data`: A constant character pointer to the data to be written to the account. Must not be null and should point to a valid memory location with at least 'sz' bytes.
    - `sz`: An unsigned long representing the size of the data to be written. Must be a valid size that the account can accommodate.
- **Output**: None
- **See also**: [`fd_write_builtin_account`](fd_builtin_programs.c.driver.md#fd_write_builtin_account)  (Implementation)


---
### fd\_builtins<!-- {{#callable_declaration:fd_builtins}} -->
Retrieve the list of built-in programs.
- **Description**: Use this function to obtain a pointer to the array of built-in programs available in the system. This function is typically called when there is a need to access or iterate over the built-in programs for operations such as initialization, configuration, or querying. It is expected to be called in contexts where the built-in programs have been initialized and are ready for use. The function does not modify any state and is safe to call multiple times.
- **Inputs**: None
- **Output**: Returns a pointer to a constant array of `fd_builtin_program_t` structures representing the built-in programs.
- **See also**: [`fd_builtins`](fd_builtin_programs.c.driver.md#fd_builtins)  (Implementation)


---
### fd\_num\_builtins<!-- {{#callable_declaration:fd_num_builtins}} -->
Return the number of built-in programs available.
- **Description**: Use this function to retrieve the total count of built-in programs currently available in the system. This function is useful when you need to iterate over all built-in programs or when you need to verify the number of built-in programs for configuration or validation purposes. It does not require any parameters and can be called at any time to get the current count of built-in programs.
- **Inputs**: None
- **Output**: Returns an unsigned long integer representing the number of built-in programs.
- **See also**: [`fd_num_builtins`](fd_builtin_programs.c.driver.md#fd_num_builtins)  (Implementation)


---
### fd\_stateless\_builtins<!-- {{#callable_declaration:fd_stateless_builtins}} -->
Retrieve the list of stateless built-in programs.
- **Description**: Use this function to obtain a constant pointer to the array of stateless built-in programs. This function is useful when you need to access or iterate over the stateless built-in programs configured in the system. It is expected to be called when the list of stateless built-in programs is needed, and it does not modify any state or require any prior initialization.
- **Inputs**: None
- **Output**: A constant pointer to an array of `fd_stateless_builtin_program_t` structures representing the stateless built-in programs.
- **See also**: [`fd_stateless_builtins`](fd_builtin_programs.c.driver.md#fd_stateless_builtins)  (Implementation)


---
### fd\_num\_stateless\_builtins<!-- {{#callable_declaration:fd_num_stateless_builtins}} -->
Returns the number of stateless built-in programs.
- **Description**: Use this function to retrieve the total count of stateless built-in programs available in the system. This function is useful when you need to iterate over or manage these programs, ensuring you have the correct number for allocation or processing purposes. It can be called at any time and does not require any prior initialization or setup.
- **Inputs**: None
- **Output**: The function returns an unsigned long integer representing the number of stateless built-in programs.
- **See also**: [`fd_num_stateless_builtins`](fd_builtin_programs.c.driver.md#fd_num_stateless_builtins)  (Implementation)


---
### fd\_is\_migrating\_builtin\_program<!-- {{#callable_declaration:fd_is_migrating_builtin_program}} -->
Check if a program is a migrating built-in and determine its migration status.
- **Description**: This function checks whether a given program, identified by its public key, is a migrating built-in program and determines if it has been migrated to BPF. It should be used when you need to verify the migration status of a built-in program within a transaction context. The function requires a valid transaction context and public key, and it outputs the migration status through the `migrated_yet` parameter. The function returns 1 if the program is a migrating built-in, with `migrated_yet` indicating whether it has been migrated, and 0 if the program is not a migrating built-in.
- **Inputs**:
    - `txn_ctx`: A pointer to a `fd_exec_txn_ctx_t` structure representing the transaction context. Must not be null.
    - `pubkey`: A pointer to a `fd_pubkey_t` structure representing the public key of the program to check. Must not be null.
    - `migrated_yet`: A pointer to an `uchar` where the migration status will be stored. Must not be null. The value will be set to 1 if the program has been migrated to BPF, otherwise it will be set to 0.
- **Output**: Returns 1 if the program is a migrating built-in program, with `migrated_yet` indicating migration status; returns 0 if the program is not a migrating built-in.
- **See also**: [`fd_is_migrating_builtin_program`](fd_builtin_programs.c.driver.md#fd_is_migrating_builtin_program)  (Implementation)


---
### fd\_is\_non\_migrating\_builtin\_program<!-- {{#callable_declaration:fd_is_non_migrating_builtin_program}} -->
Checks if a program is a non-migrating built-in program.
- **Description**: Use this function to determine if a given program, identified by its public key, is a non-migrating built-in program. This is useful in contexts where you need to differentiate between migrating and non-migrating built-in programs. The function expects a valid public key and will return a non-zero value if the program is non-migrating, or zero otherwise. Ensure that the public key provided is not null to avoid undefined behavior.
- **Inputs**:
    - `pubkey`: A pointer to a constant fd_pubkey_t representing the public key of the program to check. Must not be null. The caller retains ownership of the memory.
- **Output**: Returns a non-zero value if the program is a non-migrating built-in program, or zero if it is not.
- **See also**: [`fd_is_non_migrating_builtin_program`](fd_builtin_programs.c.driver.md#fd_is_non_migrating_builtin_program)  (Implementation)


---
### fd\_precompiles<!-- {{#callable_declaration:fd_precompiles}} -->
Retrieve the list of precompiled programs.
- **Description**: Use this function to obtain a pointer to the array of precompiled programs available in the system. This function is typically called when there is a need to access or iterate over the precompiled programs for operations such as verification or feature management. The returned pointer provides read-only access to the precompiled program data, and the caller should not attempt to modify the contents of the array.
- **Inputs**: None
- **Output**: A pointer to a constant array of `fd_precompile_program_t` structures representing the precompiled programs.
- **See also**: [`fd_precompiles`](fd_builtin_programs.c.driver.md#fd_precompiles)  (Implementation)


---
### fd\_num\_precompiles<!-- {{#callable_declaration:fd_num_precompiles}} -->
Return the number of precompiled programs available.
- **Description**: Use this function to retrieve the total count of precompiled programs that are available in the system. This can be useful for iterating over all precompiled programs or for validation purposes. The function does not require any initialization or setup before being called and can be used at any point where the count of precompiled programs is needed.
- **Inputs**: None
- **Output**: Returns an unsigned long integer representing the number of precompiled programs.
- **See also**: [`fd_num_precompiles`](fd_builtin_programs.c.driver.md#fd_num_precompiles)  (Implementation)



# Purpose
This C header file defines a structure and associated functions for managing a fuzz testing runner within a runtime environment, specifically for the Flamenco project. The `fd_runtime_fuzz_runner_t` structure encapsulates a "funk" instance and a shared memory space (spad), which are essential components for executing fuzz tests. The file provides function prototypes for creating and deleting these runner instances, as well as utility functions for setting up the testing context, such as loading account states and activating runtime features. The header ensures that memory management and context setup are handled efficiently, with functions to align memory, calculate memory footprint, and manage workspace allocations. Overall, this file serves as a foundational component for setting up and managing fuzz testing environments in the Flamenco runtime.
# Imports and Dependencies

---
- `assert.h`
- `../../fd_runtime.h`
- `generated/context.pb.h`


# Global Variables

---
### fd\_runtime\_fuzz\_runner\_new
- **Type**: `fd_runtime_fuzz_runner_t *`
- **Description**: The `fd_runtime_fuzz_runner_new` function is a constructor that initializes a new `fd_runtime_fuzz_runner_t` instance. It formats two memory regions, one for a fuzzing context object and another for an spad, using the provided memory pointers and workspace tag.
- **Use**: This function is used to create and initialize a new fuzz runner instance, allocating necessary resources and returning a pointer to the newly created runner.


---
### fd\_runtime\_fuzz\_runner\_delete
- **Type**: `function pointer`
- **Description**: The `fd_runtime_fuzz_runner_delete` is a function that takes a pointer to an `fd_runtime_fuzz_runner_t` structure and is responsible for freeing workspace allocations managed by the runner. It also returns the memory region backing the runner itself back to the caller.
- **Use**: This function is used to clean up and deallocate resources associated with a fuzz runner instance.


# Data Structures

---
### fd\_runtime\_fuzz\_runner
- **Type**: `struct`
- **Members**:
    - `funk`: An array of one fd_funk_t instance, used for managing a funk context.
    - `wksp`: A pointer to an fd_wksp_t, representing a workspace for memory management.
    - `spad`: A pointer to an fd_spad_t, representing a scratchpad for temporary data storage.
- **Description**: The `fd_runtime_fuzz_runner` structure is designed to facilitate fuzz testing by providing a context that includes a funk instance, a workspace, and a scratchpad. It is used in runtime tests to manage memory and state for fuzzing operations, allowing for the creation and deletion of fuzzing contexts and the management of associated resources.


---
### fd\_runtime\_fuzz\_runner\_t
- **Type**: `struct`
- **Members**:
    - `funk`: An array of one fd_funk_t instance, representing a funk instance.
    - `wksp`: A pointer to an fd_wksp_t, representing a workspace.
    - `spad`: A pointer to an fd_spad_t, representing a scratchpad.
- **Description**: The `fd_runtime_fuzz_runner_t` structure is designed to encapsulate a fuzzing runner environment, providing a funk instance and a scratchpad (spad) for use in various harnesses. It includes a single-element array of `fd_funk_t` to manage the funk instance, a pointer to `fd_wksp_t` for workspace management, and a pointer to `fd_spad_t` for scratchpad operations. This structure is integral to setting up and managing the memory and context required for fuzz testing within the runtime environment.


# Function Declarations (Public API)

---
### fd\_runtime\_fuzz\_runner\_align<!-- {{#callable_declaration:fd_runtime_fuzz_runner_align}} -->
Return the alignment requirement of the fd_runtime_fuzz_runner_t type.
- **Description**: Use this function to determine the alignment requirement for the fd_runtime_fuzz_runner_t type, which is necessary when allocating memory for instances of this type. This function is useful when you need to ensure that memory allocations meet the alignment constraints of the fd_runtime_fuzz_runner_t structure, especially in low-level memory management scenarios.
- **Inputs**: None
- **Output**: Returns the alignment requirement as an unsigned long integer, representing the number of bytes.
- **See also**: [`fd_runtime_fuzz_runner_align`](fd_harness_common.c.driver.md#fd_runtime_fuzz_runner_align)  (Implementation)


---
### fd\_runtime\_fuzz\_runner\_footprint<!-- {{#callable_declaration:fd_runtime_fuzz_runner_footprint}} -->
Calculate the memory footprint required for a fuzz runner.
- **Description**: Use this function to determine the amount of memory needed to allocate for a fuzz runner, which includes the memory for a funk instance but excludes spad memory. This function is useful when setting up memory allocations for fuzzing contexts, ensuring that sufficient space is reserved for the runner's operations. It should be called before allocating memory for a fuzz runner to ensure that the allocation is appropriately sized.
- **Inputs**: None
- **Output**: Returns the size in bytes of the memory footprint required for a fuzz runner.
- **See also**: [`fd_runtime_fuzz_runner_footprint`](fd_harness_common.c.driver.md#fd_runtime_fuzz_runner_footprint)  (Implementation)


---
### fd\_runtime\_fuzz\_runner\_new<!-- {{#callable_declaration:fd_runtime_fuzz_runner_new}} -->
Formats memory regions for a fuzzing context and spad, returning a new runner instance.
- **Description**: This function initializes a new `fd_runtime_fuzz_runner_t` instance by formatting the provided memory regions for use as a fuzzing context and a scratchpad (spad). It requires two memory regions: `mem`, which must be part of an `fd_wksp` and is used for both the runner and a funk instance, and `spad_mem`, which is used for the spad. The `wksp_tag` parameter is used for workspace allocations managed by the runner. The function returns a pointer to the newly created runner on success. If the initialization fails, it returns `NULL` and logs the reason for the error. This function should be used when setting up a fuzzing environment that requires a dedicated runner and associated resources.
- **Inputs**:
    - `mem`: A pointer to a memory region that is part of an `fd_wksp` and must have enough space to hold both the runner and a funk instance. The caller retains ownership.
    - `spad_mem`: A pointer to a memory region used for the spad. The caller retains ownership.
    - `wksp_tag`: An unsigned long integer used as a tag for workspace allocations managed by the runner. It must be a valid tag for the workspace.
- **Output**: Returns a pointer to the newly created `fd_runtime_fuzz_runner_t` instance on success, or `NULL` on failure.
- **See also**: [`fd_runtime_fuzz_runner_new`](fd_harness_common.c.driver.md#fd_runtime_fuzz_runner_new)  (Implementation)


---
### fd\_runtime\_fuzz\_runner\_delete<!-- {{#callable_declaration:fd_runtime_fuzz_runner_delete}} -->
Frees resources associated with a fuzz runner and returns its memory region.
- **Description**: Use this function to clean up and deallocate resources associated with a `fd_runtime_fuzz_runner_t` instance when it is no longer needed. This function should be called to ensure that all workspace allocations managed by the runner are properly freed, and the memory region backing the runner is returned to the caller. It is important to ensure that the `runner` is not null before calling this function, as passing a null pointer will result in a no-op and return null. Additionally, the function performs internal verifications and logs errors if any inconsistencies are detected in the shared padding (spad) usage.
- **Inputs**:
    - `runner`: A pointer to the `fd_runtime_fuzz_runner_t` instance to be deleted. Must not be null. If null, the function returns null without performing any operations.
- **Output**: Returns a pointer to the memory region that backed the runner, or null if the input `runner` was null.
- **See also**: [`fd_runtime_fuzz_runner_delete`](fd_harness_common.c.driver.md#fd_runtime_fuzz_runner_delete)  (Implementation)


---
### fd\_runtime\_fuzz\_load\_account<!-- {{#callable_declaration:fd_runtime_fuzz_load_account}} -->
Creates or overwrites an account in a funk transaction based on the provided account state.
- **Description**: This function is used to create or overwrite an account in a funk transaction using the provided account state. It initializes the account with the specified parameters, such as lamports, data, executable status, rent epoch, and owner. The function can optionally reject accounts with zero lamports if specified. It must be called with a valid account state and a funk transaction context. The account must not already exist in the funk transaction, and the function will return success or failure based on these conditions.
- **Inputs**:
    - `acc`: A pointer to an fd_txn_account_t structure where the account will be loaded. The caller must ensure this is a valid, non-null pointer.
    - `funk`: A pointer to an fd_funk_t structure representing the funk context. Must be valid and non-null.
    - `funk_txn`: A pointer to an fd_funk_txn_t structure representing the funk transaction context. Must be valid and non-null.
    - `state`: A pointer to a constant fd_exec_test_acct_state_t structure containing the account state to be loaded. Must be valid and non-null.
    - `reject_zero_lamports`: A uchar flag indicating whether to reject accounts with zero lamports. If non-zero, accounts with zero lamports will not be loaded.
- **Output**: Returns 1 on success if the account is created or overwritten, or 0 if the account already exists or is rejected due to zero lamports.
- **See also**: [`fd_runtime_fuzz_load_account`](fd_harness_common.c.driver.md#fd_runtime_fuzz_load_account)  (Implementation)


---
### fd\_runtime\_fuzz\_restore\_features<!-- {{#callable_declaration:fd_runtime_fuzz_restore_features}} -->
Activates features in the runtime based on a given feature set.
- **Description**: This function is used to activate specific features in the runtime environment by enabling them in the provided epoch context. It should be called when there is a need to restore or set features according to a predefined feature set. The function will disable all existing features in the epoch context before enabling the specified ones. It is important to ensure that the feature set contains only supported features, as the function will return an error if any unsupported feature is encountered.
- **Inputs**:
    - `epoch_ctx`: A pointer to an `fd_exec_epoch_ctx_t` structure where the features will be activated. This must not be null, and the caller retains ownership.
    - `feature_set`: A pointer to a constant `fd_exec_test_feature_set_t` structure that specifies the features to be activated. This must not be null, and the caller retains ownership. The feature set should contain only supported features to avoid errors.
- **Output**: Returns 1 on success if all features are supported and activated, or 0 if any unsupported feature is encountered.
- **See also**: [`fd_runtime_fuzz_restore_features`](fd_harness_common.c.driver.md#fd_runtime_fuzz_restore_features)  (Implementation)



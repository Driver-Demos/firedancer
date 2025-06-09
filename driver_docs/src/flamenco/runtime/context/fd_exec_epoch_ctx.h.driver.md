# Purpose
This C header file defines the structure and functions for managing an execution context that remains constant throughout an entire epoch in a distributed system, likely related to blockchain or consensus mechanisms. The primary structure, `fd_exec_epoch_ctx_t`, encapsulates various components such as features, an epoch bank, and pointers to other structures like `fd_bank_hash_cmp_t` and `fd_runtime_public_t`. The context is designed to handle voting accounts, stake delegations, and epoch leaders, which are crucial for maintaining the state and operations within an epoch. The file provides a set of functions to create, join, leave, and delete these contexts, as well as to manage the memory associated with bank data structures, ensuring that the context is correctly initialized and maintained throughout its lifecycle.

The header file also defines several inline functions that provide access to specific components of the epoch context, such as the epoch bank and various stake-related data structures. These functions facilitate efficient access and manipulation of the context's internal data, which is essential for the performance of the system. The use of macros like `FD_EXEC_EPOCH_CTX_ALIGN` and `FD_EXEC_EPOCH_CTX_MAGIC` ensures proper alignment and integrity of the context structure. Overall, this file serves as a critical component in managing the state and operations of an epoch, providing a well-defined interface for interacting with the epoch context in a consistent and efficient manner.
# Imports and Dependencies

---
- `../../features/fd_features.h`
- `../../leaders/fd_leaders.h`
- `../fd_bank_hash_cmp.h`
- `../fd_rent_lists.h`


# Global Variables

---
### fd\_exec\_epoch\_ctx\_new
- **Type**: `function pointer`
- **Description**: `fd_exec_epoch_ctx_new` is a function that initializes a new execution epoch context. It takes a memory pointer and a maximum vote account value as parameters, and returns a pointer to the newly created context.
- **Use**: This function is used to allocate and set up a new execution epoch context with specified parameters.


---
### fd\_exec\_epoch\_ctx\_join
- **Type**: `fd_exec_epoch_ctx_t *`
- **Description**: The `fd_exec_epoch_ctx_join` function returns a pointer to an `fd_exec_epoch_ctx_t` structure, which represents the context that remains constant throughout an entire epoch. This context includes various configuration and state information necessary for managing epoch-related operations.
- **Use**: This function is used to join or access an existing epoch context from a given memory location.


---
### fd\_exec\_epoch\_ctx\_leave
- **Type**: `function pointer`
- **Description**: The `fd_exec_epoch_ctx_leave` is a function that takes a pointer to an `fd_exec_epoch_ctx_t` structure as its parameter and returns a void pointer. This function is likely used to perform cleanup or finalization tasks when leaving or exiting the context of an epoch in the execution environment.
- **Use**: This function is used to handle the exit or cleanup process for an epoch context, ensuring that resources are properly released or reset.


---
### fd\_exec\_epoch\_ctx\_delete
- **Type**: `function pointer`
- **Description**: The `fd_exec_epoch_ctx_delete` is a function pointer that takes a single argument of type `void *` and returns a `void *`. It is used to delete or deallocate memory associated with an epoch context in the Flamenco runtime system.
- **Use**: This function is used to clean up and free resources associated with an epoch context when it is no longer needed.


---
### fd\_exec\_epoch\_ctx\_bank\_mem\_setup
- **Type**: `function`
- **Description**: The `fd_exec_epoch_ctx_bank_mem_setup` function is responsible for initializing the bank data structures within an epoch context. It sets up the necessary structures for votes, delegations, stake history, and next epoch stakes to ensure they have the correct pool initialization and layout.
- **Use**: This function is used to prepare the bank data structures in an epoch context for use, ensuring they are correctly initialized and laid out.


# Data Structures

---
### fd\_exec\_epoch\_ctx\_layout
- **Type**: `struct`
- **Members**:
    - `vote_acc_max`: Specifies the maximum number of vote accounts.
    - `footprint`: Represents the memory footprint of the context.
    - `stake_votes_off`: Offset for accessing stake votes data.
    - `stake_delegations_off`: Offset for accessing stake delegations data.
    - `next_epoch_stakes_off`: Offset for accessing next epoch stakes data.
    - `leaders_off`: Offset for accessing leaders data for the current epoch.
- **Description**: The `fd_exec_epoch_ctx_layout` structure defines the layout of various offsets and limits used in the execution context of an epoch. It includes fields for managing the maximum number of vote accounts, the memory footprint, and offsets for accessing different types of data such as stake votes, stake delegations, next epoch stakes, and leaders specific to the current epoch. This layout is crucial for organizing and accessing the data efficiently during the execution of an epoch.


---
### fd\_exec\_epoch\_ctx\_layout\_t
- **Type**: `struct`
- **Members**:
    - `vote_acc_max`: Specifies the maximum number of vote accounts.
    - `footprint`: Represents the memory footprint of the context layout.
    - `stake_votes_off`: Offset for the stake votes within the memory layout.
    - `stake_delegations_off`: Offset for the stake delegations within the memory layout.
    - `next_epoch_stakes_off`: Offset for the next epoch stakes within the memory layout.
    - `leaders_off`: Offset for the leaders of the current epoch within the memory layout.
- **Description**: The `fd_exec_epoch_ctx_layout_t` structure defines the layout of various offsets and maximums used in the execution context of an epoch. It includes fields for managing the memory layout of vote accounts, stake votes, stake delegations, next epoch stakes, and leaders, ensuring that these components are correctly aligned and accessible within the context of an epoch's execution.


---
### fd\_runtime\_public\_t
- **Type**: `typedef struct fd_runtime_public fd_runtime_public_t;`
- **Description**: The `fd_runtime_public_t` is a forward declaration of a structure in C, indicating that it is a custom data type whose details are not defined in the provided code. This type is used as a pointer within the `fd_exec_epoch_ctx` structure, suggesting it holds or references runtime public data relevant to the execution context of an epoch, but its specific fields and purpose are not detailed in the given file.


---
### fd\_exec\_epoch\_ctx
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the structure, expected to be equal to FD_EXEC_EPOCH_CTX_MAGIC.
    - `layout`: An instance of fd_exec_epoch_ctx_layout_t that defines the memory layout for various epoch-related data.
    - `features`: An instance of fd_features_t that holds feature flags or settings.
    - `epoch_bank`: An instance of fd_epoch_bank_t that manages the bank data for the epoch.
    - `bank_hash_cmp`: A pointer to a function or structure for comparing bank hashes.
    - `runtime_public`: A pointer to an fd_runtime_public_t structure, likely containing public runtime data.
    - `constipate_root`: An integer used for managing offline replay constipation.
    - `total_epoch_stake`: A ulong representing the total stake for the epoch.
- **Description**: The fd_exec_epoch_ctx structure is designed to maintain a constant context throughout an entire epoch in a distributed system. It includes various fields that manage the layout of epoch-related data, feature settings, and bank data. The structure is aligned to 64 bytes for performance reasons and includes a magic number for validation. It also contains pointers to functions or structures for hash comparison and runtime data, as well as fields for managing offline replay and tracking the total stake in the epoch.


# Functions

---
### fd\_exec\_epoch\_ctx\_epoch\_bank\_const<!-- {{#callable:fd_exec_epoch_ctx_epoch_bank_const}} -->
The function `fd_exec_epoch_ctx_epoch_bank_const` returns a constant pointer to the `epoch_bank` member of a given `fd_exec_epoch_ctx_t` context structure.
- **Inputs**:
    - `ctx`: A constant pointer to an `fd_exec_epoch_ctx_t` structure, representing the execution context for an epoch.
- **Control Flow**:
    - The function takes a single input, `ctx`, which is a pointer to a constant `fd_exec_epoch_ctx_t` structure.
    - It accesses the `epoch_bank` member of the `ctx` structure.
    - The function returns a constant pointer to the `epoch_bank` member.
- **Output**: A constant pointer to the `epoch_bank` member of the provided `fd_exec_epoch_ctx_t` structure.


# Function Declarations (Public API)

---
### fd\_exec\_epoch\_ctx\_new<!-- {{#callable_declaration:fd_exec_epoch_ctx_new}} -->
Create a new execution epoch context.
- **Description**: This function initializes a new execution epoch context using the provided memory region. It should be called when a new epoch context is needed, ensuring that the memory is properly aligned and non-null. The function sets up the context with default values and configurations, preparing it for use in managing epoch-related data. It is important to ensure that the memory provided is aligned according to `FD_EXEC_EPOCH_CTX_ALIGN` and that `vote_acc_max` is valid, as invalid inputs will result in a null return.
- **Inputs**:
    - `mem`: A pointer to a memory region where the context will be initialized. Must not be null and must be aligned to `FD_EXEC_EPOCH_CTX_ALIGN`. The caller retains ownership.
    - `vote_acc_max`: The maximum number of vote accounts. Must be a valid value as determined by the context's requirements. Invalid values will result in a null return.
- **Output**: Returns a pointer to the initialized context on success, or null if the input parameters are invalid.
- **See also**: [`fd_exec_epoch_ctx_new`](fd_exec_epoch_ctx.c.driver.md#fd_exec_epoch_ctx_new)  (Implementation)


---
### fd\_exec\_epoch\_ctx\_join<!-- {{#callable_declaration:fd_exec_epoch_ctx_join}} -->
Returns a pointer to a valid epoch context from a memory block.
- **Description**: Use this function to obtain a pointer to an `fd_exec_epoch_ctx_t` structure from a given memory block. This function should be called when you have a memory block that is expected to contain a valid epoch context. It checks if the memory block is non-null and if it contains the correct magic number to ensure it is a valid context. If these conditions are not met, the function returns `NULL`, indicating an invalid or uninitialized context.
- **Inputs**:
    - `mem`: A pointer to a memory block that is expected to contain an `fd_exec_epoch_ctx_t` structure. Must not be null. The memory block should have been previously initialized with the correct magic number. If `mem` is null or the magic number is incorrect, the function returns `NULL`.
- **Output**: Returns a pointer to an `fd_exec_epoch_ctx_t` if the memory block is valid; otherwise, returns `NULL`.
- **See also**: [`fd_exec_epoch_ctx_join`](fd_exec_epoch_ctx.c.driver.md#fd_exec_epoch_ctx_join)  (Implementation)


---
### fd\_exec\_epoch\_ctx\_leave<!-- {{#callable_declaration:fd_exec_epoch_ctx_leave}} -->
Leaves the current epoch context.
- **Description**: Use this function to leave an epoch context that was previously joined. It should be called when the operations requiring the context are complete, allowing for proper cleanup and resource management. The function checks for a valid context by verifying that the provided pointer is not null and that it has the correct magic number. If these conditions are not met, it logs a warning and returns null. This function is typically used in conjunction with `fd_exec_epoch_ctx_join` to manage the lifecycle of an epoch context.
- **Inputs**:
    - `ctx`: A pointer to an `fd_exec_epoch_ctx_t` structure representing the epoch context to leave. Must not be null and must have a valid magic number. If invalid, the function logs a warning and returns null.
- **Output**: Returns a pointer to the context if successful, or null if the context is invalid.
- **See also**: [`fd_exec_epoch_ctx_leave`](fd_exec_epoch_ctx.c.driver.md#fd_exec_epoch_ctx_leave)  (Implementation)


---
### fd\_exec\_epoch\_ctx\_delete<!-- {{#callable_declaration:fd_exec_epoch_ctx_delete}} -->
Deletes an execution epoch context and returns the memory to the caller.
- **Description**: Use this function to safely delete an execution epoch context that was previously created, ensuring that all associated resources are properly released. This function should be called when the context is no longer needed, and it is important to ensure that the memory passed to this function is valid, aligned, and was previously initialized with the correct magic number. The function will log warnings and return NULL if the memory is NULL, misaligned, or has an incorrect magic number, indicating that the context was not properly initialized or has already been deleted.
- **Inputs**:
    - `mem`: A pointer to the memory block representing the execution epoch context. It must not be NULL, must be aligned to FD_EXEC_EPOCH_CTX_ALIGN, and must have been initialized with the correct magic number (FD_EXEC_EPOCH_CTX_MAGIC). The caller retains ownership of the memory.
- **Output**: Returns the original memory pointer if the deletion is successful, or NULL if the input is invalid or the context was not properly initialized.
- **See also**: [`fd_exec_epoch_ctx_delete`](fd_exec_epoch_ctx.c.driver.md#fd_exec_epoch_ctx_delete)  (Implementation)


---
### fd\_exec\_epoch\_ctx\_epoch\_bank\_delete<!-- {{#callable_declaration:fd_exec_epoch_ctx_epoch_bank_delete}} -->
Deletes the epoch bank from the execution epoch context.
- **Description**: Use this function to delete the epoch bank associated with a given execution epoch context. This is typically done when the epoch bank is no longer needed, such as at the end of an epoch or before reinitializing the bank. The function ensures that the memory associated with the epoch bank is properly cleared and reset. It is important to ensure that the `epoch_ctx` is valid and properly initialized before calling this function.
- **Inputs**:
    - `epoch_ctx`: A pointer to an `fd_exec_epoch_ctx_t` structure representing the execution epoch context. Must not be null. The caller retains ownership and is responsible for ensuring the context is valid and initialized.
- **Output**: None
- **See also**: [`fd_exec_epoch_ctx_epoch_bank_delete`](fd_exec_epoch_ctx.c.driver.md#fd_exec_epoch_ctx_epoch_bank_delete)  (Implementation)


---
### fd\_exec\_epoch\_ctx\_align<!-- {{#callable_declaration:fd_exec_epoch_ctx_align}} -->
Returns the alignment requirement for the epoch context structure.
- **Description**: Use this function to obtain the alignment requirement for the `fd_exec_epoch_ctx_t` structure, which is necessary when allocating memory for instances of this structure. This function is useful when setting up memory layouts that need to adhere to specific alignment constraints to ensure proper access and performance.
- **Inputs**: None
- **Output**: The function returns an `ulong` representing the alignment requirement for the `fd_exec_epoch_ctx_t` structure.
- **See also**: [`fd_exec_epoch_ctx_align`](fd_exec_epoch_ctx.c.driver.md#fd_exec_epoch_ctx_align)  (Implementation)


---
### fd\_exec\_epoch\_ctx\_footprint<!-- {{#callable_declaration:fd_exec_epoch_ctx_footprint}} -->
Calculates the memory footprint required for an epoch context.
- **Description**: This function is used to determine the amount of memory needed to store an epoch context, given a specified maximum number of vote accounts. It is useful for allocating memory before initializing an epoch context. The function should be called with a valid maximum vote account number to ensure accurate memory allocation.
- **Inputs**:
    - `vote_acc_max`: Specifies the maximum number of vote accounts that the epoch context will support. It must be a positive integer, and providing an invalid value may result in undefined behavior.
- **Output**: Returns the size in bytes of the memory footprint required for the epoch context.
- **See also**: [`fd_exec_epoch_ctx_footprint`](fd_exec_epoch_ctx.c.driver.md#fd_exec_epoch_ctx_footprint)  (Implementation)


---
### fd\_exec\_epoch\_ctx\_bank\_mem\_clear<!-- {{#callable_declaration:fd_exec_epoch_ctx_bank_mem_clear}} -->
Clears the bank data structures in the epoch context.
- **Description**: Use this function to empty the existing bank data structures, including votes, delegations, stake history, and next epoch stakes, within the provided epoch context. This is particularly useful before decoding a bank from a different source to ensure that no residual data interferes with the new data being loaded. It is important to ensure that the `epoch_ctx` is valid and properly initialized before calling this function.
- **Inputs**:
    - `epoch_ctx`: A pointer to an `fd_exec_epoch_ctx_t` structure representing the epoch context. This must not be null and should be a valid, initialized context. The function will clear specific data structures within this context.
- **Output**: None
- **See also**: [`fd_exec_epoch_ctx_bank_mem_clear`](fd_exec_epoch_ctx.c.driver.md#fd_exec_epoch_ctx_bank_mem_clear)  (Implementation)


---
### fd\_exec\_epoch\_ctx\_bank\_mem\_setup<!-- {{#callable_declaration:fd_exec_epoch_ctx_bank_mem_setup}} -->
Initializes the bank data structures for an epoch context.
- **Description**: This function sets up the bank data structures within a given epoch context, preparing them for use by initializing the pools for votes, delegations, and next epoch stakes. It should be called to ensure that the epoch context's bank is correctly initialized before any operations that depend on these structures are performed. The function assumes that the provided epoch context is valid and properly aligned, and it returns a pointer to the initialized epoch bank.
- **Inputs**:
    - `epoch_ctx`: A pointer to an fd_exec_epoch_ctx_t structure representing the epoch context. This must not be null and should be properly initialized and aligned according to FD_EXEC_EPOCH_CTX_ALIGN. The caller retains ownership of this structure.
- **Output**: Returns a pointer to the initialized fd_epoch_bank_t structure within the provided epoch context.
- **See also**: [`fd_exec_epoch_ctx_bank_mem_setup`](fd_exec_epoch_ctx.c.driver.md#fd_exec_epoch_ctx_bank_mem_setup)  (Implementation)


---
### fd\_exec\_epoch\_ctx\_from\_prev<!-- {{#callable_declaration:fd_exec_epoch_ctx_from_prev}} -->
Initialize an epoch context from a previous context.
- **Description**: This function sets up a new epoch context by copying relevant data from a previous epoch context. It is used to transition from one epoch to the next while maintaining continuity of certain features and settings. The function must be called with valid pointers to both the current and previous epoch contexts, as well as a runtime scratchpad for temporary data storage. It is important to ensure that the previous context is fully initialized and that the runtime scratchpad is properly configured before calling this function.
- **Inputs**:
    - `self`: A pointer to the current epoch context to be initialized. Must not be null and should point to a valid memory location where the new context will be set up.
    - `prev`: A pointer to the previous epoch context from which data will be copied. Must not be null and should point to a fully initialized epoch context.
    - `runtime_spad`: A pointer to a runtime scratchpad used for temporary data storage during the initialization process. Must not be null and should be properly configured for use.
- **Output**: None
- **See also**: [`fd_exec_epoch_ctx_from_prev`](fd_exec_epoch_ctx.c.driver.md#fd_exec_epoch_ctx_from_prev)  (Implementation)



# Purpose
The provided C source code file is designed to manage the lifecycle and memory layout of an execution epoch context, specifically for a system that appears to handle voting and delegation processes, likely in a distributed or blockchain environment. The code defines functions to create, initialize, join, leave, and delete an `fd_exec_epoch_ctx_t` structure, which encapsulates the state and configuration for an epoch, including vote accounts, stake delegations, and epoch leaders. The file includes functions to calculate memory footprints, align memory, and manage memory allocation for various components of the epoch context, ensuring that the memory is correctly aligned and initialized.

The code is structured around a central theme of managing epoch-related data structures, with a focus on memory management and data integrity. It provides a narrow but critical functionality, encapsulating the operations needed to handle epoch contexts within a larger system. The file does not define a public API or external interfaces directly but rather implements internal functions that are likely used by other parts of the system to manage epoch contexts. Key technical components include memory alignment and allocation functions, as well as functions to handle the setup and teardown of complex data structures related to voting and delegation. The use of macros and static functions suggests that this code is intended to be part of a larger library or system, where these epoch contexts are a fundamental part of the system's operation.
# Imports and Dependencies

---
- `fd_exec_epoch_ctx.h`
- `assert.h`
- `../sysvar/fd_sysvar_stake_history.h`
- `../fd_runtime_public.h`


# Functions

---
### fd\_exec\_epoch\_ctx\_align<!-- {{#callable:fd_exec_epoch_ctx_align}} -->
The function `fd_exec_epoch_ctx_align` returns the alignment requirement for an epoch context structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined to return a constant value, `FD_EXEC_EPOCH_CTX_ALIGN`, which represents the alignment requirement for the epoch context structure.
    - There are no conditional statements or loops; the function simply returns the constant value.
- **Output**: The function returns an unsigned long integer representing the alignment requirement for an epoch context structure.


---
### fd\_exec\_epoch\_ctx\_footprint\_ext<!-- {{#callable:fd_exec_epoch_ctx_footprint_ext}} -->
The `fd_exec_epoch_ctx_footprint_ext` function calculates and sets up the memory footprint for an epoch context layout based on the maximum number of vote accounts.
- **Inputs**:
    - `layout`: A pointer to an `fd_exec_epoch_ctx_layout_t` structure that will be initialized and populated with offsets and sizes for various components of the epoch context.
    - `vote_acc_max`: An unsigned long integer representing the maximum number of vote accounts, which determines the size of various components in the epoch context.
- **Control Flow**:
    - Check if `vote_acc_max` is zero; if so, return 0 as no memory is needed.
    - Initialize the `layout` structure to zero and set its `vote_acc_max` field.
    - Calculate the size of the stake votes map using `fd_vote_accounts_pair_t_map_footprint` and return 0 if the size is zero.
    - Calculate the size of the stake delegations map using `fd_delegation_pair_t_map_footprint` and return 0 if the size is zero.
    - Calculate the size of the next epoch stakes map using `fd_vote_accounts_pair_t_map_footprint` and return 0 if the size is zero.
    - Calculate the size of the leaders map using `fd_epoch_leaders_footprint` and log a critical error if the size is zero.
    - Initialize a scratch allocation context `l` and append memory allocations for the epoch context and its components, storing offsets in the `layout`.
    - Finalize the scratch allocation and set the `footprint` field of the `layout` to the total allocated size, which is then returned.
- **Output**: The function returns the total memory footprint size as an unsigned long integer, which is stored in the `footprint` field of the `layout`.
- **Functions called**:
    - [`fd_exec_epoch_ctx_align`](#fd_exec_epoch_ctx_align)


---
### fd\_exec\_epoch\_ctx\_footprint<!-- {{#callable:fd_exec_epoch_ctx_footprint}} -->
The `fd_exec_epoch_ctx_footprint` function calculates the memory footprint required for an epoch context based on the maximum number of vote accounts.
- **Inputs**:
    - `vote_acc_max`: The maximum number of vote accounts to consider when calculating the memory footprint.
- **Control Flow**:
    - Declare a local variable `layout` of type `fd_exec_epoch_ctx_layout_t`.
    - Call the function [`fd_exec_epoch_ctx_footprint_ext`](#fd_exec_epoch_ctx_footprint_ext) with `layout` and `vote_acc_max` as arguments.
    - Return the result of the [`fd_exec_epoch_ctx_footprint_ext`](#fd_exec_epoch_ctx_footprint_ext) function call.
- **Output**: The function returns an unsigned long integer representing the calculated memory footprint for the epoch context.
- **Functions called**:
    - [`fd_exec_epoch_ctx_footprint_ext`](#fd_exec_epoch_ctx_footprint_ext)


---
### fd\_exec\_epoch\_ctx\_new<!-- {{#callable:fd_exec_epoch_ctx_new}} -->
The `fd_exec_epoch_ctx_new` function initializes a new execution epoch context in a given memory block, setting up its layout and features based on the provided maximum vote account count.
- **Inputs**:
    - `mem`: A pointer to a memory block where the execution epoch context will be initialized.
    - `vote_acc_max`: An unsigned long integer specifying the maximum number of vote accounts to be supported by the context.
- **Control Flow**:
    - Check if the provided memory pointer `mem` is NULL and log a warning if so, returning NULL.
    - Verify if the memory pointer `mem` is aligned according to `FD_EXEC_EPOCH_CTX_ALIGN` and log a warning if not, returning NULL.
    - Cast the memory pointer to `fd_exec_epoch_ctx_t` and zero out the memory for the context structure.
    - Call [`fd_exec_epoch_ctx_footprint_ext`](#fd_exec_epoch_ctx_footprint_ext) to set up the layout of the context based on `vote_acc_max`, logging a warning and returning NULL if it fails.
    - Set up the memory for the epoch bank using [`fd_exec_epoch_ctx_bank_mem_setup`](#fd_exec_epoch_ctx_bank_mem_setup).
    - Disable all features in the context and set the cluster version to default values.
    - Enable cleaned-up features based on the cluster version.
    - Use memory fences to ensure memory operations are completed before setting the magic number.
    - Set the magic number of the context to `FD_EXEC_EPOCH_CTX_MAGIC` using memory fences.
    - Return the original memory pointer `mem`.
- **Output**: Returns the original memory pointer `mem` if successful, or NULL if any checks or initializations fail.
- **Functions called**:
    - [`fd_exec_epoch_ctx_footprint_ext`](#fd_exec_epoch_ctx_footprint_ext)
    - [`fd_exec_epoch_ctx_bank_mem_setup`](#fd_exec_epoch_ctx_bank_mem_setup)


---
### fd\_exec\_epoch\_ctx\_join<!-- {{#callable:fd_exec_epoch_ctx_join}} -->
The `fd_exec_epoch_ctx_join` function validates and returns a pointer to an `fd_exec_epoch_ctx_t` structure from a given memory block if it is correctly initialized.
- **Inputs**:
    - `mem`: A pointer to a memory block that is expected to contain an `fd_exec_epoch_ctx_t` structure.
- **Control Flow**:
    - Check if the `mem` pointer is NULL; if so, log a warning and return NULL.
    - Cast the `mem` pointer to an `fd_exec_epoch_ctx_t` pointer named `ctx`.
    - Check if the `magic` field of `ctx` matches `FD_EXEC_EPOCH_CTX_MAGIC`; if not, log a warning and return NULL.
    - Return the `ctx` pointer.
- **Output**: A pointer to an `fd_exec_epoch_ctx_t` structure if the input memory block is valid, otherwise NULL.


---
### epoch\_ctx\_bank\_mem\_leave<!-- {{#callable:epoch_ctx_bank_mem_leave}} -->
The `epoch_ctx_bank_mem_leave` function releases resources associated with stake votes and stake delegations in an epoch context.
- **Inputs**:
    - `epoch_ctx`: A pointer to an `fd_exec_epoch_ctx_t` structure representing the epoch context from which resources are to be released.
- **Control Flow**:
    - Retrieve the memory address of the epoch context and its layout.
    - Calculate the memory addresses for stake votes and stake delegations using offsets from the layout.
    - Call `fd_vote_accounts_pair_t_map_leave` to release resources associated with stake votes.
    - Call `fd_delegation_pair_t_map_leave` to release resources associated with stake delegations.
- **Output**: This function does not return any value; it performs operations to release resources.


---
### fd\_exec\_epoch\_ctx\_leave<!-- {{#callable:fd_exec_epoch_ctx_leave}} -->
The `fd_exec_epoch_ctx_leave` function checks the validity of an epoch context and then performs cleanup operations before returning the context.
- **Inputs**:
    - `ctx`: A pointer to an `fd_exec_epoch_ctx_t` structure representing the epoch context to be left.
- **Control Flow**:
    - Check if the `ctx` pointer is NULL; if so, log a warning and return NULL.
    - Verify that the `magic` field of the context matches `FD_EXEC_EPOCH_CTX_MAGIC`; if not, log a warning and return NULL.
    - Call [`epoch_ctx_bank_mem_leave`](#epoch_ctx_bank_mem_leave) to perform cleanup operations on the context's memory.
    - Return the context cast to a `void *`.
- **Output**: Returns a `void *` pointer to the context if successful, or NULL if the context is invalid.
- **Functions called**:
    - [`epoch_ctx_bank_mem_leave`](#epoch_ctx_bank_mem_leave)


---
### fd\_exec\_epoch\_ctx\_delete<!-- {{#callable:fd_exec_epoch_ctx_delete}} -->
The `fd_exec_epoch_ctx_delete` function deletes an execution epoch context by validating the input memory, cleaning up associated resources, and resetting the context's magic number.
- **Inputs**:
    - `mem`: A pointer to the memory block representing the execution epoch context to be deleted.
- **Control Flow**:
    - Check if the input memory pointer `mem` is NULL and log a warning if it is, returning NULL.
    - Verify if the memory is aligned according to `FD_EXEC_EPOCH_CTX_ALIGN` and log a warning if it is not, returning NULL.
    - Cast the memory to a `fd_exec_epoch_ctx_t` structure and check if the magic number matches `FD_EXEC_EPOCH_CTX_MAGIC`; log a warning and return NULL if it does not match.
    - Retrieve the layout from the context header and calculate the memory addresses for `next_epoch_stakes_mem` and `leaders_mem` using offsets from the layout.
    - Call `fd_vote_accounts_pair_t_map_delete` and `fd_epoch_leaders_delete` to clean up resources associated with `next_epoch_stakes_mem` and `leaders_mem`.
    - Call [`fd_exec_epoch_ctx_epoch_bank_delete`](#fd_exec_epoch_ctx_epoch_bank_delete) to delete the epoch bank associated with the context.
    - Use memory fences to ensure memory operations are completed and set the context's magic number to 0.
    - Return the original memory pointer `mem`.
- **Output**: Returns the original memory pointer `mem` if the deletion is successful, or NULL if any validation checks fail.
- **Functions called**:
    - [`fd_exec_epoch_ctx_epoch_bank_delete`](#fd_exec_epoch_ctx_epoch_bank_delete)


---
### epoch\_ctx\_bank\_mem\_delete<!-- {{#callable:epoch_ctx_bank_mem_delete}} -->
The `epoch_ctx_bank_mem_delete` function deletes memory associated with stake votes and stake delegations within an epoch context.
- **Inputs**:
    - `epoch_ctx`: A pointer to an `fd_exec_epoch_ctx_t` structure representing the epoch context whose memory is to be deleted.
- **Control Flow**:
    - Retrieve the memory address of the epoch context and its layout.
    - Calculate the memory addresses for stake votes and stake delegations using offsets from the layout.
    - Call `fd_vote_accounts_pair_t_map_delete` to delete the stake votes memory.
    - Call `fd_delegation_pair_t_map_delete` to delete the stake delegations memory.
- **Output**: This function does not return any value; it performs memory deletion operations on the provided epoch context.


---
### fd\_exec\_epoch\_ctx\_epoch\_bank\_delete<!-- {{#callable:fd_exec_epoch_ctx_epoch_bank_delete}} -->
The function `fd_exec_epoch_ctx_epoch_bank_delete` deletes the memory associated with the epoch bank in the given execution epoch context and resets its state.
- **Inputs**:
    - `epoch_ctx`: A pointer to an `fd_exec_epoch_ctx_t` structure representing the execution epoch context whose epoch bank is to be deleted.
- **Control Flow**:
    - Call the helper function [`epoch_ctx_bank_mem_delete`](#epoch_ctx_bank_mem_delete) to delete the memory associated with the epoch bank in the given execution epoch context.
    - Use `memset` to reset the `epoch_bank` field of the `epoch_ctx` structure to zero, effectively clearing its state.
- **Output**: This function does not return any value; it performs its operations directly on the provided `epoch_ctx` structure.
- **Functions called**:
    - [`epoch_ctx_bank_mem_delete`](#epoch_ctx_bank_mem_delete)


---
### fd\_exec\_epoch\_ctx\_bank\_mem\_clear<!-- {{#callable:fd_exec_epoch_ctx_bank_mem_clear}} -->
The `fd_exec_epoch_ctx_bank_mem_clear` function clears the memory associated with vote accounts and stake delegations in the epoch bank of a given execution epoch context.
- **Inputs**:
    - `epoch_ctx`: A pointer to an `fd_exec_epoch_ctx_t` structure representing the execution epoch context whose bank memory is to be cleared.
- **Control Flow**:
    - Retrieve the `epoch_bank` from the provided `epoch_ctx`.
    - For the current epoch's vote accounts, release the memory associated with the vote accounts tree and set the root to NULL.
    - For the current epoch's stake delegations, release the memory associated with the stake delegations tree and set the root to NULL.
    - For the next epoch's vote accounts, release the memory associated with the vote accounts tree and set the root to NULL.
- **Output**: This function does not return a value; it operates directly on the provided `epoch_ctx` to clear its bank memory.


---
### fd\_exec\_epoch\_ctx\_bank\_mem\_setup<!-- {{#callable:fd_exec_epoch_ctx_bank_mem_setup}} -->
The `fd_exec_epoch_ctx_bank_mem_setup` function initializes and sets up memory pools for vote accounts, stake delegations, and next epoch stakes within an epoch bank context.
- **Inputs**:
    - `self`: A pointer to an `fd_exec_epoch_ctx_t` structure, which contains the layout and epoch bank to be initialized.
- **Control Flow**:
    - Retrieve the layout from the `self` structure.
    - Calculate memory addresses for stake votes, stake delegations, and next epoch stakes using offsets from the layout.
    - Initialize a new epoch bank using `fd_epoch_bank_new`.
    - Set up the vote accounts pool by creating and joining a new map for stake votes memory.
    - Set up the stake delegations pool by creating and joining a new map for stake delegations memory.
    - Set up the next epoch stakes pool by creating and joining a new map for next epoch stakes memory.
    - Return the initialized `epoch_bank`.
- **Output**: A pointer to the initialized `fd_epoch_bank_t` structure within the `self` context.


---
### fd\_exec\_epoch\_ctx\_from\_prev<!-- {{#callable:fd_exec_epoch_ctx_from_prev}} -->
The `fd_exec_epoch_ctx_from_prev` function initializes a new execution epoch context by copying relevant data from a previous context and encoding the epoch bank into a runtime scratchpad.
- **Inputs**:
    - `self`: A pointer to the `fd_exec_epoch_ctx_t` structure that will be initialized with data from the previous context.
    - `prev`: A pointer to the `fd_exec_epoch_ctx_t` structure representing the previous execution epoch context from which data will be copied.
    - `runtime_spad`: A pointer to the `fd_spad_t` structure used as a scratchpad for temporary data storage during the function execution.
- **Control Flow**:
    - Copy the `features` from `prev` to `self` using a large memory copy operation.
    - Copy the `bank_hash_cmp` and `runtime_public` pointers from `prev` to `self`.
    - Set `self->total_epoch_stake` to zero.
    - Copy the `features` from `prev` to `self->runtime_public->features` using a large memory copy operation.
    - Retrieve the epoch bank from the `prev` context using `fd_exec_epoch_ctx_epoch_bank`.
    - Begin a scratchpad frame using `FD_SPAD_FRAME_BEGIN` with `runtime_spad`.
    - Calculate the size of the old epoch bank and allocate a buffer in the scratchpad with the required alignment and size.
    - Encode the old epoch bank into the allocated buffer using `fd_epoch_bank_encode`.
    - Calculate the aligned size for the epoch leaders and copy them from `prev` to `self` using `fd_memcpy`.
    - End the scratchpad frame using `FD_SPAD_FRAME_END`.
- **Output**: The function does not return a value; it modifies the `self` context in place.


---
### FD\_SPAD\_FRAME\_BEGIN<!-- {{#callable:fd_exec_epoch_ctx_from_prev::FD_SPAD_FRAME_BEGIN}} -->
The `FD_SPAD_FRAME_BEGIN` function allocates memory for encoding an epoch bank and copies epoch leader data from a previous context to the current context.
- **Inputs**:
    - `runtime_spad`: A pointer to a `fd_spad_t` structure used for memory allocation during the function's execution.
- **Control Flow**:
    - Calculate the size of the old epoch bank using `fd_epoch_bank_size` and store it in `sz`.
    - Allocate memory in `runtime_spad` with alignment using `fd_spad_alloc` and store the pointer in `buf`.
    - Initialize an encoding context `encode` with `buf` and its end address.
    - Encode the old epoch bank into the allocated buffer using `fd_epoch_bank_encode`.
    - Calculate the aligned size for epoch leaders using `fd_ulong_align_up` and store it in `sz`.
    - Copy the epoch leaders from the previous context to the current context using `fd_memcpy`.
- **Output**: The function does not return a value; it performs memory allocation and data copying operations.



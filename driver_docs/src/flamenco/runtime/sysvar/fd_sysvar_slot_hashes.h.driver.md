# Purpose
This C header file defines the interface for managing a system variable (sysvar) related to "slot hashes" within a larger software system, likely related to blockchain or distributed ledger technology. The file includes function prototypes for creating, joining, leaving, deleting, writing, initializing, updating, and reading the slot hashes sysvar, which stores the most recent hashes of a slot's parent bank hashes. It sets a maximum capacity for the slot hashes entries and aligns them according to a predefined global alignment. The header file also includes necessary dependencies from other parts of the project, indicating its integration with a broader system. The functions provided facilitate memory management and data manipulation for the slot hashes, ensuring they are correctly updated and accessed within the system's execution context.
# Imports and Dependencies

---
- `../../../funk/fd_funk.h`
- `../../../funk/fd_funk_txn.h`
- `../../fd_flamenco_base.h`
- `../../types/fd_types.h`


# Global Variables

---
### fd\_sysvar\_slot\_hashes\_new
- **Type**: `function pointer`
- **Description**: The `fd_sysvar_slot_hashes_new` function is a global function that initializes a new slot hashes sysvar structure in the provided memory space. It takes a pointer to a memory location and a capacity for slot hashes as parameters.
- **Use**: This function is used to allocate and initialize memory for storing the most recent hashes of a slot's parent bank hashes.


---
### fd\_sysvar\_slot\_hashes\_join
- **Type**: `fd_slot_hashes_global_t *`
- **Description**: The `fd_sysvar_slot_hashes_join` function returns a pointer to a `fd_slot_hashes_global_t` structure. This structure is likely used to manage or access the global state of slot hashes within a shared memory context. The function takes a pointer to shared memory and a pointer to a pointer of `fd_slot_hash_t`, indicating it may initialize or link the slot hash data to the shared memory.
- **Use**: This function is used to join or link the slot hashes data structure to a shared memory segment, facilitating access to the slot hashes' global state.


---
### fd\_sysvar\_slot\_hashes\_leave
- **Type**: `function pointer`
- **Description**: The `fd_sysvar_slot_hashes_leave` is a function pointer that is used to leave or detach from a slot hashes global context. It takes two parameters: a pointer to `fd_slot_hashes_global_t`, which represents the global context of slot hashes, and a pointer to `fd_slot_hash_t`, which represents a specific slot hash.
- **Use**: This function is used to properly leave or detach from the slot hashes global context, ensuring that any necessary cleanup or state updates are performed.


---
### fd\_sysvar\_slot\_hashes\_delete
- **Type**: `function pointer`
- **Description**: The `fd_sysvar_slot_hashes_delete` is a function that takes a pointer to memory as its argument and returns a pointer. It is likely used to delete or deallocate resources associated with the 'slot hashes' sysvar, which contains the most recent hashes of the slot's parent bank hashes.
- **Use**: This function is used to manage memory by deleting or cleaning up resources related to the 'slot hashes' sysvar.


---
### fd\_sysvar\_slot\_hashes\_read
- **Type**: `fd_slot_hashes_global_t *`
- **Description**: The `fd_sysvar_slot_hashes_read` function returns a pointer to a `fd_slot_hashes_global_t` structure, which represents the slot hashes sysvar. This sysvar contains the most recent hashes of the slot's parent bank hashes, crucial for maintaining the integrity and consistency of the slot data in the system.
- **Use**: This function is used to read the slot hashes sysvar from the funk data structure, returning NULL if the account does not exist or has zero lamports.


# Function Declarations (Public API)

---
### fd\_sysvar\_slot\_hashes\_footprint<!-- {{#callable_declaration:fd_sysvar_slot_hashes_footprint}} -->
Calculate the memory footprint required for slot hashes.
- **Description**: This function calculates the total memory footprint required to store the slot hashes sysvar, given a specified capacity for slot hashes. It is useful for determining the amount of memory to allocate when initializing or managing slot hashes. The function should be called whenever you need to know the memory requirements for a given number of slot hashes, ensuring that the capacity does not exceed the defined maximum, FD_SYSVAR_SLOT_HASHES_CAP.
- **Inputs**:
    - `slot_hashes_cap`: The capacity of slot hashes for which the memory footprint is to be calculated. It should be a non-negative value and ideally should not exceed FD_SYSVAR_SLOT_HASHES_CAP to ensure proper memory allocation.
- **Output**: Returns the total memory footprint in bytes required for the specified slot hashes capacity.
- **See also**: [`fd_sysvar_slot_hashes_footprint`](fd_sysvar_slot_hashes.c.driver.md#fd_sysvar_slot_hashes_footprint)  (Implementation)


---
### fd\_sysvar\_slot\_hashes\_new<!-- {{#callable_declaration:fd_sysvar_slot_hashes_new}} -->
Allocate and initialize a new slot hashes sysvar structure.
- **Description**: This function allocates and initializes a new slot hashes sysvar structure in the provided memory region. It should be called when a new slot hashes sysvar is needed, and the caller must ensure that the memory region is properly aligned and large enough to accommodate the structure. The function requires a non-null memory pointer and a capacity for the slot hashes. If the memory is not aligned or is null, the function will log an error and terminate. This function is typically used in systems managing slot hashes for parent bank hashes.
- **Inputs**:
    - `mem`: A pointer to the memory region where the slot hashes sysvar will be allocated. Must not be null and must be aligned to FD_SYSVAR_SLOT_HASHES_ALIGN. The caller retains ownership of the memory.
    - `slot_hashes_cap`: The capacity for the slot hashes, indicating the maximum number of entries the sysvar can hold. It should be a positive number, typically not exceeding FD_SYSVAR_SLOT_HASHES_CAP.
- **Output**: Returns a pointer to the initialized slot hashes sysvar structure. If the input memory is null or not aligned, the function logs an error and does not return.
- **See also**: [`fd_sysvar_slot_hashes_new`](fd_sysvar_slot_hashes.c.driver.md#fd_sysvar_slot_hashes_new)  (Implementation)


---
### fd\_sysvar\_slot\_hashes\_join<!-- {{#callable_declaration:fd_sysvar_slot_hashes_join}} -->
Join a shared memory region to access slot hash data.
- **Description**: This function is used to join a shared memory region that contains slot hash data, allowing access to the most recent hashes of the slot's parent bank hashes. It should be called when you need to access or manipulate the slot hash data stored in shared memory. The function returns a pointer to the global slot hashes structure and also sets a pointer to the slot hash data. Ensure that the shared memory region is properly initialized and aligned before calling this function.
- **Inputs**:
    - `shmem`: A pointer to the shared memory region containing the slot hash data. It must be properly initialized and aligned according to FD_SYSVAR_SLOT_HASHES_ALIGN. The caller retains ownership.
    - `slot_hash`: A pointer to a pointer that will be set to the slot hash data within the shared memory. Must not be null.
- **Output**: Returns a pointer to the fd_slot_hashes_global_t structure representing the global slot hashes data.
- **See also**: [`fd_sysvar_slot_hashes_join`](fd_sysvar_slot_hashes.c.driver.md#fd_sysvar_slot_hashes_join)  (Implementation)


---
### fd\_sysvar\_slot\_hashes\_leave<!-- {{#callable_declaration:fd_sysvar_slot_hashes_leave}} -->
Leaves the slot hashes global context.
- **Description**: This function is used to leave or detach from the slot hashes global context, which is part of the slot hashes sysvar. It should be called when the operations on the slot hashes are complete and the context is no longer needed. This function ensures that any necessary cleanup or detachment operations are performed. It is important to ensure that the `slot_hash` parameter is valid and properly initialized before calling this function.
- **Inputs**:
    - `slot_hashes_global`: A pointer to the `fd_slot_hashes_global_t` structure representing the global context of slot hashes. The caller retains ownership and must ensure it is valid.
    - `slot_hash`: A pointer to the `fd_slot_hash_t` structure that is part of the slot hashes context. It must be valid and properly initialized before calling this function.
- **Output**: Returns the `slot_hashes_global` pointer, allowing for potential chaining of operations.
- **See also**: [`fd_sysvar_slot_hashes_leave`](fd_sysvar_slot_hashes.c.driver.md#fd_sysvar_slot_hashes_leave)  (Implementation)


---
### fd\_sysvar\_slot\_hashes\_delete<!-- {{#callable_declaration:fd_sysvar_slot_hashes_delete}} -->
Deletes the slot hashes sysvar from the provided memory.
- **Description**: Use this function to remove the slot hashes sysvar from a previously allocated memory region. It should be called when the slot hashes sysvar is no longer needed, to clean up resources. The function expects a valid memory pointer that was used to create the slot hashes sysvar. It returns the original memory pointer, allowing for potential reuse or deallocation by the caller. Ensure that the memory provided is correctly aligned and was previously initialized for slot hashes sysvar usage.
- **Inputs**:
    - `mem`: A pointer to the memory region containing the slot hashes sysvar. This memory must have been previously allocated and initialized for slot hashes sysvar operations. The pointer must not be null, and it should be correctly aligned as per the sysvar's requirements.
- **Output**: Returns the original memory pointer provided as input, allowing for further use or deallocation.
- **See also**: [`fd_sysvar_slot_hashes_delete`](fd_sysvar_slot_hashes.c.driver.md#fd_sysvar_slot_hashes_delete)  (Implementation)


---
### fd\_sysvar\_slot\_hashes\_write<!-- {{#callable_declaration:fd_sysvar_slot_hashes_write}} -->
Write a funk entry for the slot hashes sysvar account.
- **Description**: This function is used to write a funk entry for the slot hashes sysvar account, primarily for testing purposes. It encodes the global slot hashes data and updates the sysvar account with this encoded information. This function should be used when there is a need to manually update the slot hashes sysvar account, typically in a testing context. It is important to ensure that the provided slot context and global slot hashes are valid and properly initialized before calling this function.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. This must be a valid, non-null pointer, and the caller retains ownership.
    - `slot_hashes_global`: A pointer to an fd_slot_hashes_global_t structure containing the global slot hashes data to be written. This must be a valid, non-null pointer, and the caller retains ownership.
- **Output**: None
- **See also**: [`fd_sysvar_slot_hashes_write`](fd_sysvar_slot_hashes.c.driver.md#fd_sysvar_slot_hashes_write)  (Implementation)


---
### fd\_sysvar\_slot\_hashes\_init<!-- {{#callable_declaration:fd_sysvar_slot_hashes_init}} -->
Initialize the slot hashes sysvar for a given execution slot context.
- **Description**: This function sets up the slot hashes sysvar for the specified execution slot context by allocating necessary memory within the provided runtime scratchpad. It should be called to initialize the slot hashes before any operations that depend on this sysvar are performed. The function ensures that the slot hashes are properly initialized and written to the execution context, preparing it for subsequent operations. It is important to ensure that the runtime scratchpad is properly initialized and has sufficient space for the allocation.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. Must not be null, as it is used to write the initialized slot hashes.
    - `runtime_spad`: A pointer to an fd_spad_t structure representing the runtime scratchpad memory. Must not be null and should be properly initialized to allow memory allocation for the slot hashes.
- **Output**: None
- **See also**: [`fd_sysvar_slot_hashes_init`](fd_sysvar_slot_hashes.c.driver.md#fd_sysvar_slot_hashes_init)  (Implementation)


---
### fd\_sysvar\_slot\_hashes\_update<!-- {{#callable_declaration:fd_sysvar_slot_hashes_update}} -->
Update the slot hashes sysvar account with the latest slot information.
- **Description**: This function updates the slot hashes sysvar account with the most recent hashes of the slot's parent bank hashes. It should be called at the end of every slot, before execution commences, to ensure that the sysvar account reflects the latest state. The function handles the creation of a new slot hashes entry if it does not already exist and updates the existing entry if it does. It is important to ensure that the `slot_ctx` and `runtime_spad` are properly initialized and valid before calling this function.
- **Inputs**:
    - `slot_ctx`: A pointer to an `fd_exec_slot_ctx_t` structure representing the execution context of the current slot. Must be valid and properly initialized.
    - `runtime_spad`: A pointer to an `fd_spad_t` structure used for runtime memory allocation. Must be valid and properly initialized.
- **Output**: None
- **See also**: [`fd_sysvar_slot_hashes_update`](fd_sysvar_slot_hashes.c.driver.md#fd_sysvar_slot_hashes_update)  (Implementation)


---
### fd\_sysvar\_slot\_hashes\_read<!-- {{#callable_declaration:fd_sysvar_slot_hashes_read}} -->
Reads the slot hashes sysvar from a funk transaction.
- **Description**: This function retrieves the slot hashes sysvar from the specified funk transaction. It should be used when you need to access the most recent hashes of the slot's parent bank hashes. The function requires a valid funk and funk transaction to operate. If the sysvar account does not exist in the funk or has zero lamports, the function will return NULL, indicating that the account is not present. Ensure that the spad parameter is properly initialized to allocate memory for the slot hashes.
- **Inputs**:
    - `funk`: A pointer to an fd_funk_t structure representing the funk from which to read the slot hashes. Must not be null.
    - `funk_txn`: A pointer to an fd_funk_txn_t structure representing the transaction context within the funk. Must not be null.
    - `spad`: A pointer to an fd_spad_t structure used for memory allocation. Must be properly initialized and not null.
- **Output**: Returns a pointer to an fd_slot_hashes_global_t structure containing the slot hashes if successful, or NULL if the account does not exist or has zero lamports.
- **See also**: [`fd_sysvar_slot_hashes_read`](fd_sysvar_slot_hashes.c.driver.md#fd_sysvar_slot_hashes_read)  (Implementation)



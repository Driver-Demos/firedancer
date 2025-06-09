# Purpose
This C header file defines a data structure and associated functions for managing epoch forks in a distributed system. The primary purpose of the code is to handle the transition of context across epoch boundaries in a system where operations are organized into epochs. The file introduces a mechanism to manage forks that occur when an epoch boundary is crossed, ensuring that the correct context is maintained for each unique subtree of forks. This is achieved by maintaining a map of epoch fork entries, which are updated and pruned as the system progresses through different epochs.

The file defines a `fd_epoch_forks` structure, which includes an array of `fd_epoch_fork_elem` structures to store information about each fork, such as the parent slot and the associated epoch context. The API provided by this header file includes functions to initialize the epoch forks ([`fd_epoch_forks_new`](#fd_epoch_forks_new)), publish and prune fork entries when a new epoch is rooted ([`fd_epoch_forks_publish`](#fd_epoch_forks_publish)), prepare a new fork entry or retrieve an existing one ([`fd_epoch_forks_prepare`](#fd_epoch_forks_prepare)), and obtain the correct epoch context for a given slot ([`fd_epoch_forks_get_epoch_ctx`](#fd_epoch_forks_get_epoch_ctx)). This code is intended to be included in other C files and provides a focused functionality for managing epoch transitions in a distributed system, without defining a public API for external interfaces.
# Imports and Dependencies

---
- `../../disco/fd_disco_base.h`
- `../../choreo/ghost/fd_ghost.h`


# Data Structures

---
### fd\_epoch\_fork\_elem
- **Type**: `struct`
- **Members**:
    - `parent_slot`: Stores the slot number of the parent in the fork tree.
    - `epoch`: Represents the epoch number associated with the fork.
    - `epoch_ctx`: Pointer to the execution context for the epoch.
- **Description**: The `fd_epoch_fork_elem` structure is designed to represent an element in a fork tree that spans across an epoch boundary. It contains information about the parent slot, the epoch number, and a pointer to the execution context for the epoch. This structure is used to manage and track the state of forks as they transition between epochs, ensuring that the correct execution context is maintained for each unique subtree of forks.


---
### fd\_epoch\_fork\_elem\_t
- **Type**: `struct`
- **Members**:
    - `parent_slot`: Stores the parent slot number associated with the fork.
    - `epoch`: Represents the epoch number for the fork.
    - `epoch_ctx`: Points to the execution context associated with the epoch.
- **Description**: The `fd_epoch_fork_elem_t` structure is designed to manage individual fork elements within an epoch boundary in a distributed system. Each element contains information about the parent slot, the epoch number, and a pointer to the execution context (`epoch_ctx`) associated with that epoch. This structure is part of a larger mechanism to handle forks across epoch boundaries, ensuring that the correct execution context is maintained and updated as the system progresses through different epochs.


---
### fd\_epoch\_forks
- **Type**: `struct`
- **Members**:
    - `forks`: An array of fd_epoch_fork_elem_t structures, each representing a fork in the epoch.
    - `curr_epoch_idx`: An unsigned long integer indicating the current epoch index.
    - `epoch_ctx_base`: A pointer to a base memory location for epoch context objects.
- **Description**: The `fd_epoch_forks` structure is designed to manage forks across epoch boundaries in a system that requires a new epoch context for each unique subtree of forks. It maintains an array of fork elements, each representing a potential fork in the epoch, and provides mechanisms to prepare, publish, and retrieve the correct epoch context for a given slot. The structure is initialized with a base pointer to a pre-allocated memory region for epoch context objects, and it supports operations to manage and prune fork entries as the system progresses through epochs.


---
### fd\_epoch\_forks\_t
- **Type**: `struct`
- **Members**:
    - `forks`: An array of fd_epoch_fork_elem_t structures, each representing a fork entry with a maximum size defined by MAX_EPOCH_FORKS.
    - `curr_epoch_idx`: An unsigned long integer representing the current index of the epoch in the forks array.
    - `epoch_ctx_base`: A pointer to an unsigned char, serving as the base address for pre-allocated memory for epoch context objects.
- **Description**: The `fd_epoch_forks_t` structure is designed to manage forks across epoch boundaries in a distributed system. It maintains an array of fork elements, each containing information about a parent slot, epoch, and associated epoch context. The structure supports operations to initialize fork elements, publish and prune fork entries when a new epoch is rooted, and prepare or retrieve the correct epoch context for a given slot. This allows for efficient management of epoch contexts across forks, ensuring that the correct context is used and unnecessary entries are pruned when no longer needed.


# Function Declarations (Public API)

---
### fd\_epoch\_forks\_new<!-- {{#callable_declaration:fd_epoch_forks_new}} -->
Initialize epoch fork elements and set the base pointer for epoch context allocations.
- **Description**: This function initializes all elements of the provided `fd_epoch_forks_t` structure, setting each fork's parent slot and epoch to a default maximum value and clearing any existing epoch context pointers. It also sets the base pointer for epoch context allocations, which is used in managing epoch contexts across fork boundaries. This function should be called before any other operations on the `fd_epoch_forks_t` structure to ensure it is in a known state. The caller must ensure that `epoch_forks` points to a valid, writable `fd_epoch_forks_t` structure and that `epoch_ctx_base` points to a pre-allocated memory region suitable for epoch context objects.
- **Inputs**:
    - `epoch_forks`: A pointer to an `fd_epoch_forks_t` structure that will be initialized. Must not be null and must point to a valid, writable memory location.
    - `epoch_ctx_base`: A pointer to a pre-allocated memory region for epoch context objects. The caller retains ownership and must ensure it is valid for the duration of the `fd_epoch_forks_t` usage.
- **Output**: None
- **See also**: [`fd_epoch_forks_new`](fd_epoch_forks.c.driver.md#fd_epoch_forks_new)  (Implementation)


---
### fd\_epoch\_forks\_publish<!-- {{#callable_declaration:fd_epoch_forks_publish}} -->
Publish the current epoch fork and prune unnecessary entries.
- **Description**: Use this function to update the current epoch fork context when a new root is established. It checks if the current epoch index matches the expected index for the given root. If not, it updates the current epoch index and prunes any epoch fork entries that are no longer needed. This function should be called whenever a new root is established to ensure that the epoch context is correctly maintained and unnecessary entries are cleared.
- **Inputs**:
    - `epoch_forks`: A pointer to an `fd_epoch_forks_t` structure that manages the epoch fork entries. Must not be null.
    - `ghost`: A pointer to an `fd_ghost_t` structure used to determine the correct epoch context. Must not be null.
    - `root`: An unsigned long representing the root slot for which the epoch context is being published. It should be a valid slot number.
- **Output**: None
- **See also**: [`fd_epoch_forks_publish`](fd_epoch_forks.c.driver.md#fd_epoch_forks_publish)  (Implementation)


---
### fd\_epoch\_forks\_prepare<!-- {{#callable_declaration:fd_epoch_forks_prepare}} -->
Creates or retrieves an epoch fork entry for a given parent slot and epoch.
- **Description**: This function is used to manage forks that cross an epoch boundary by either creating a new fork entry or retrieving an existing one. It should be called when a new epoch is encountered, and a fork needs to be tracked. The function requires a pre-initialized `fd_epoch_forks_t` structure and a base pointer for epoch context memory. It will crash with a critical error if the maximum number of forks is exceeded, so it is important to ensure that the number of forks does not surpass the defined limit.
- **Inputs**:
    - `epoch_forks`: A pointer to an `fd_epoch_forks_t` structure that manages the epoch forks. Must not be null and should be properly initialized before calling this function.
    - `parent_slot`: An unsigned long representing the parent slot of the fork. It identifies the slot at which the fork occurs.
    - `new_epoch`: An unsigned long representing the new epoch number. It specifies the epoch that the fork is crossing into.
    - `out_fork`: A pointer to a pointer of `fd_epoch_fork_elem_t` where the function will store the address of the created or retrieved fork entry. Must not be null.
    - `vote_accounts_max`: An unsigned long indicating the maximum number of vote accounts. It is used to determine the size of the epoch context memory allocation.
- **Output**: Returns 1 if an existing fork entry is found and returned, otherwise returns 0 after creating a new entry. Crashes with a critical error if the maximum number of forks is exceeded.
- **See also**: [`fd_epoch_forks_prepare`](fd_epoch_forks.c.driver.md#fd_epoch_forks_prepare)  (Implementation)


---
### fd\_epoch\_forks\_get\_epoch\_ctx<!-- {{#callable_declaration:fd_epoch_forks_get_epoch_ctx}} -->
Returns the index of the correct epoch context for the current slot.
- **Description**: This function is used to determine the appropriate epoch context index for a given slot, taking into account any forks that may have occurred across epoch boundaries. It should be called when you need to retrieve the epoch context for processing a specific slot, especially when dealing with forks. The function handles cases where the current slot is part of a new epoch fork and returns the index of the relevant fork entry. It is important to ensure that the `epoch_forks` and `ghost` structures are properly initialized before calling this function.
- **Inputs**:
    - `epoch_forks`: A pointer to an `fd_epoch_forks_t` structure that manages epoch fork entries. Must not be null.
    - `ghost`: A pointer to an `fd_ghost_t` structure used to determine ancestry relationships. Must not be null.
    - `curr_slot`: The current slot for which the epoch context is being queried. Must be a valid slot number.
    - `opt_prev_slot`: An optional pointer to a previous slot number, used to refine the search for the correct epoch context. Can be null.
- **Output**: Returns the index of the epoch context entry that corresponds to the current slot or the relevant fork.
- **See also**: [`fd_epoch_forks_get_epoch_ctx`](fd_epoch_forks.c.driver.md#fd_epoch_forks_get_epoch_ctx)  (Implementation)



# Purpose
The provided C header file, `fd_epoch.h`, is part of a larger software system and is designed to manage and manipulate "epochs" within a choreographic framework. An epoch, in this context, appears to be a period or phase in a distributed system where certain operations or transactions are grouped and managed. The file defines a data structure, `fd_epoch_t`, which encapsulates information about an epoch, including its unique identifier (`magic`), memory address (`epoch_gaddr`), total stake, and the range of slots it covers. Additionally, it maintains a reference to a dynamic map of voters, which are likely entities participating in the epoch, identified by their public keys.

The file provides a set of functions to handle the lifecycle of an epoch, including initialization ([`fd_epoch_init`](#fd_epoch_init)), finalization ([`fd_epoch_fini`](#fd_epoch_fini)), and memory management operations such as creating ([`fd_epoch_new`](#fd_epoch_new)), joining ([`fd_epoch_join`](#fd_epoch_join)), leaving ([`fd_epoch_leave`](#fd_epoch_leave)), and deleting ([`fd_epoch_delete`](#fd_epoch_delete)) an epoch. These functions ensure that the memory regions used for epochs are properly formatted, accessed, and released. The header also includes macros and inline functions to facilitate the alignment and footprint calculations necessary for efficient memory usage. The inclusion of `fd_map_dynamic.c` suggests that the file leverages dynamic mapping utilities to manage the voters associated with each epoch. Overall, this header file provides a focused API for managing epochs in a distributed system, emphasizing memory management and participant tracking.
# Imports and Dependencies

---
- `../fd_choreo_base.h`
- `../voter/fd_voter.h`
- `../../util/tmpl/fd_map_dynamic.c`


# Global Variables

---
### fd\_epoch\_new
- **Type**: `function pointer`
- **Description**: The `fd_epoch_new` function is a global function that initializes a memory region for use as an epoch. It takes a pointer to a memory region (`mem`) and a maximum number of voters (`voter_max`) as parameters.
- **Use**: This function is used to format a memory region so that it can be used to manage epoch data, including voter information, in a distributed system.


---
### fd\_epoch\_join
- **Type**: `fd_epoch_t *`
- **Description**: The `fd_epoch_join` function is a global function that returns a pointer to an `fd_epoch_t` structure. This function is used to join the caller to an epoch by providing a pointer to the memory region backing the epoch in the caller's address space.
- **Use**: This function is used to establish a local join to an epoch, allowing the caller to interact with the epoch's data.


---
### fd\_epoch\_leave
- **Type**: `function pointer`
- **Description**: `fd_epoch_leave` is a function that allows a caller to leave a current local join of an epoch. It takes a constant pointer to an `fd_epoch_t` structure as its parameter and returns a pointer to the underlying shared memory region on success, or NULL on failure.
- **Use**: This function is used to safely disconnect from an epoch, ensuring that resources are properly released and any necessary cleanup is performed.


---
### fd\_epoch\_delete
- **Type**: `function pointer`
- **Description**: `fd_epoch_delete` is a function that unformats a memory region used as an epoch, assuming only the local process is joined to the region. It returns a pointer to the underlying shared memory region or NULL if there is an obvious error, such as the provided epoch not being a valid epoch.
- **Use**: This function is used to delete an epoch by transferring the ownership of the memory region back to the caller.


# Data Structures

---
### fd\_epoch
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the epoch, expected to be equal to FD_EPOCH_MAGIC.
    - `epoch_gaddr`: The global address of this epoch in the backing workspace, must be non-zero.
    - `total_stake`: The total amount of stake in the epoch.
    - `first_slot`: The first slot number in the epoch.
    - `last_slot`: The last slot number in the epoch.
    - `voters_gaddr`: The global address of a dynamic map containing all voters in the current epoch, keyed by public key.
- **Description**: The `fd_epoch` structure is designed to represent an epoch in a distributed system, encapsulating essential information such as a unique identifier (`magic`), global address (`epoch_gaddr`), total stake, and slot range (`first_slot` and `last_slot`). It also includes a reference to a dynamic map of voters (`voters_gaddr`), which is crucial for managing and accessing voter information during the epoch. The structure is aligned to 128 bytes to optimize memory access and reduce false sharing in concurrent environments.


---
### fd\_epoch\_t
- **Type**: `struct`
- **Members**:
    - `magic`: A constant value used to verify the integrity and version of the epoch structure.
    - `epoch_gaddr`: The global address of the epoch in the backing workspace, ensuring it is non-zero.
    - `total_stake`: The total amount of stake present in the epoch.
    - `first_slot`: The first slot number in the epoch.
    - `last_slot`: The last slot number in the epoch.
    - `voters_gaddr`: The global address of a dynamic map containing all voters in the current epoch, keyed by their public key.
- **Description**: The `fd_epoch_t` structure represents an epoch in a distributed system, encapsulating metadata such as the epoch's global address, total stake, and slot range. It also includes a reference to a dynamic map of voters, allowing for efficient access and management of voter information within the epoch. The structure is aligned to 128 bytes to optimize memory access and reduce false sharing in concurrent environments.


# Functions

---
### fd\_epoch\_align<!-- {{#callable:fd_epoch_align}} -->
The `fd_epoch_align` function returns the memory alignment requirement for the `fd_epoch_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests that the compiler should attempt to embed the function's code directly at the call site to reduce function call overhead.
    - The function uses the `alignof` operator to determine the alignment requirement of the `fd_epoch_t` structure, which is a custom data structure defined in the same file.
    - The function returns the result of the `alignof` operator, which is an unsigned long integer representing the alignment requirement.
- **Output**: The function returns an unsigned long integer representing the alignment requirement of the `fd_epoch_t` structure.


---
### fd\_epoch\_footprint<!-- {{#callable:fd_epoch_footprint}} -->
The `fd_epoch_footprint` function calculates the memory footprint required for an epoch structure, including its voters, based on the maximum number of voters.
- **Inputs**:
    - `voter_max`: The maximum number of voters that the epoch is expected to handle.
- **Control Flow**:
    - Calculate the smallest power of two greater than or equal to `voter_max` using `fd_ulong_pow2_up` and find its most significant bit position with `fd_ulong_find_msb`, then add 2 to ensure a fill ratio of 0.25 or less.
    - Initialize the layout with `FD_LAYOUT_INIT`.
    - Append the alignment and size of `fd_epoch_t` to the layout using `FD_LAYOUT_APPEND`.
    - Append the alignment and footprint of the voters map, calculated with `fd_epoch_voters_align` and `fd_epoch_voters_footprint`, to the layout.
    - Finalize the layout with the alignment of `fd_epoch_t` using `FD_LAYOUT_FINI`.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the epoch structure, including its voters.
- **Functions called**:
    - [`fd_epoch_align`](#fd_epoch_align)


---
### fd\_epoch\_wksp<!-- {{#callable:fd_epoch_wksp}} -->
The `fd_epoch_wksp` function returns a pointer to the workspace backing the given epoch by adjusting the epoch's address with its global address offset.
- **Inputs**:
    - `epoch`: A constant pointer to an `fd_epoch_t` structure representing the epoch whose backing workspace is to be retrieved.
- **Control Flow**:
    - The function takes the input `epoch`, which is a pointer to an `fd_epoch_t` structure.
    - It calculates the local address of the workspace by subtracting the `epoch_gaddr` (global address of the epoch) from the address of the `epoch` itself.
    - The result is cast to a pointer of type `fd_wksp_t` and returned.
- **Output**: A pointer to `fd_wksp_t`, representing the local join to the workspace backing the epoch.


---
### fd\_epoch\_voters<!-- {{#callable:fd_epoch_voters}} -->
The `fd_epoch_voters` function retrieves a pointer to the voters map within a given epoch's workspace.
- **Inputs**:
    - `epoch`: A pointer to an `fd_epoch_t` structure representing the epoch from which to retrieve the voters map.
- **Control Flow**:
    - The function calls [`fd_epoch_wksp`](#fd_epoch_wksp) with the `epoch` pointer to get the workspace associated with the epoch.
    - It then calls `fd_wksp_laddr_fast` with the workspace and the `voters_gaddr` from the epoch to get the local address of the voters map.
    - Finally, it returns the pointer to the voters map.
- **Output**: A pointer to the `fd_voter_t` structure representing the voters map in the local address space.
- **Functions called**:
    - [`fd_epoch_wksp`](#fd_epoch_wksp)


---
### fd\_epoch\_voters\_const<!-- {{#callable:fd_epoch_voters_const}} -->
The `fd_epoch_voters_const` function retrieves a constant pointer to the voters map associated with a given epoch.
- **Inputs**:
    - `epoch`: A constant pointer to an `fd_epoch_t` structure representing the epoch whose voters map is to be accessed.
- **Control Flow**:
    - The function calls [`fd_epoch_wksp`](#fd_epoch_wksp) with the `epoch` argument to obtain the workspace associated with the epoch.
    - It then calls `fd_wksp_laddr_fast` with the workspace and the `voters_gaddr` from the `epoch` to get the local address of the voters map.
    - The function returns the result of `fd_wksp_laddr_fast`, which is a constant pointer to the voters map.
- **Output**: A constant pointer to `fd_voter_t`, representing the voters map for the specified epoch.
- **Functions called**:
    - [`fd_epoch_wksp`](#fd_epoch_wksp)


# Function Declarations (Public API)

---
### fd\_epoch\_new<!-- {{#callable_declaration:fd_epoch_new}} -->
Formats a memory region for use as an epoch.
- **Description**: This function prepares a specified memory region to be used as an epoch, which is a data structure for managing voting processes. It should be called with a valid memory pointer and a maximum number of voters, ensuring the memory is properly aligned and part of a workspace. The function initializes the memory region, setting up necessary structures for managing voters and epoch data. It returns a pointer to the formatted memory region or NULL if any preconditions are not met, such as a NULL memory pointer, misalignment, or invalid workspace association.
- **Inputs**:
    - `shmem`: A non-NULL pointer to the memory region to be formatted as an epoch. The memory must be aligned according to fd_epoch_align() and must be part of a workspace. If these conditions are not met, the function returns NULL.
    - `voter_max`: The maximum number of voters that the epoch should support. This value determines the size of the memory footprint required. If the calculated footprint is zero, the function returns NULL.
- **Output**: Returns a pointer to the formatted memory region on success, or NULL if any preconditions are violated.
- **See also**: [`fd_epoch_new`](fd_epoch.c.driver.md#fd_epoch_new)  (Implementation)


---
### fd\_epoch\_join<!-- {{#callable_declaration:fd_epoch_join}} -->
Joins the caller to the specified epoch.
- **Description**: This function is used to join the caller to an epoch, allowing access to the epoch's data and operations. It should be called with a pointer to the memory region backing the epoch, which must be properly aligned and part of a workspace. The epoch must also have a valid magic number indicating it is correctly initialized. If any of these conditions are not met, the function will return NULL and log a warning. This function is typically called after the epoch has been created and before any operations are performed on it.
- **Inputs**:
    - `shepoch`: A pointer to the memory region backing the epoch. It must not be NULL, must be aligned according to fd_epoch_align(), and must be part of a workspace. The epoch must have a valid magic number (FD_EPOCH_MAGIC). If these conditions are not met, the function returns NULL.
- **Output**: Returns a pointer to the epoch in the local address space on success, or NULL if the input is invalid or the epoch is not properly initialized.
- **See also**: [`fd_epoch_join`](fd_epoch.c.driver.md#fd_epoch_join)  (Implementation)


---
### fd\_epoch\_leave<!-- {{#callable_declaration:fd_epoch_leave}} -->
Leaves the current local join of an epoch.
- **Description**: This function is used to leave a current local join of an epoch, effectively ending the caller's participation in the epoch. It should be called when the caller no longer needs to interact with the epoch. The function requires a valid pointer to an `fd_epoch_t` structure representing the epoch. If the provided pointer is null, the function logs a warning and returns null, indicating failure. This function is typically used in conjunction with `fd_epoch_join` to manage the lifecycle of an epoch join.
- **Inputs**:
    - `epoch`: A pointer to a constant `fd_epoch_t` structure representing the epoch to leave. Must not be null. If null, the function logs a warning and returns null.
- **Output**: Returns a pointer to the underlying shared memory region on success, or null if the input is invalid.
- **See also**: [`fd_epoch_leave`](fd_epoch.c.driver.md#fd_epoch_leave)  (Implementation)


---
### fd\_epoch\_delete<!-- {{#callable_declaration:fd_epoch_delete}} -->
Unformats a memory region used as an epoch.
- **Description**: Use this function to unformat a memory region that was previously formatted for use as an epoch. It should be called when the epoch is no longer needed and only the local process is joined to the region. This function transfers ownership of the memory region back to the caller. It returns a pointer to the underlying shared memory region or NULL if the input is invalid, such as when the epoch is NULL or misaligned. Logging is performed in case of errors.
- **Inputs**:
    - `epoch`: A pointer to the memory region used as an epoch. It must not be NULL and must be properly aligned according to fd_epoch_align(). If the pointer is NULL or misaligned, the function logs a warning and returns NULL.
- **Output**: Returns a pointer to the underlying shared memory region if successful, or NULL if the input is invalid.
- **See also**: [`fd_epoch_delete`](fd_epoch.c.driver.md#fd_epoch_delete)  (Implementation)


---
### fd\_epoch\_init<!-- {{#callable_declaration:fd_epoch_init}} -->
Initialize an epoch with data from an epoch bank.
- **Description**: This function sets up an `fd_epoch_t` structure using information from a provided `fd_epoch_bank_t`. It should be called once at the beginning of an epoch, after the epoch has been joined locally and before any other operations are performed on it. The function populates the epoch's slot range and initializes voter information based on the stake data from the epoch bank. It assumes that the epoch has not been previously initialized and that the provided pointers are valid.
- **Inputs**:
    - `epoch`: A pointer to an `fd_epoch_t` structure that must be a valid local join and not previously initialized. The caller retains ownership.
    - `epoch_bank`: A pointer to a constant `fd_epoch_bank_t` structure containing the data to initialize the epoch. The caller retains ownership and it must not be null.
- **Output**: None
- **See also**: [`fd_epoch_init`](fd_epoch.c.driver.md#fd_epoch_init)  (Implementation)


---
### fd\_epoch\_fini<!-- {{#callable_declaration:fd_epoch_fini}} -->
Finalize an epoch by clearing its voters and resetting its total stake.
- **Description**: Use this function to properly finalize an epoch that has been previously initialized and is currently joined. It should be called once at the end of an epoch's lifecycle to clear all associated voters and reset the total stake to zero. This function assumes that the epoch is a valid local join and has already been initialized. It is important to ensure that the epoch is in a valid state before calling this function to avoid undefined behavior.
- **Inputs**:
    - `epoch`: A pointer to a valid fd_epoch_t structure representing the epoch to be finalized. The epoch must be a valid local join and must have been initialized prior to calling this function. The pointer must not be null.
- **Output**: None
- **See also**: [`fd_epoch_fini`](fd_epoch.c.driver.md#fd_epoch_fini)  (Implementation)



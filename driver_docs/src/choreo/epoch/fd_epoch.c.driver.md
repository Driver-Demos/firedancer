# Purpose
This C source code file provides functionality for managing and manipulating "epochs" within a shared memory context, specifically focusing on the initialization, joining, leaving, and deletion of epoch structures. The code is designed to work with a shared memory segment, ensuring that the memory is properly aligned and part of a workspace. The primary functions include [`fd_epoch_new`](#fd_epoch_new), which initializes a new epoch in shared memory, [`fd_epoch_join`](#fd_epoch_join), which allows a process to join an existing epoch, [`fd_epoch_leave`](#fd_epoch_leave), which handles leaving an epoch, and [`fd_epoch_delete`](#fd_epoch_delete), which manages the deletion of an epoch. Additionally, the file includes [`fd_epoch_init`](#fd_epoch_init) and [`fd_epoch_fini`](#fd_epoch_fini) for setting up and finalizing epoch data, respectively. These functions ensure that the epoch's voter data is correctly initialized and cleared.

The code is structured to handle memory alignment and workspace validation, using macros and utility functions to manage these aspects. It also includes mechanisms for logging warnings when operations encounter issues, such as null pointers or misaligned memory. The file appears to be part of a larger system that deals with voting or consensus mechanisms, as indicated by the use of voter-related structures and functions. The code is not a standalone executable but rather a component intended to be integrated into a larger application, likely providing a backend for managing epochs in a distributed or parallel processing environment.
# Imports and Dependencies

---
- `fd_epoch.h`


# Functions

---
### fd\_epoch\_new<!-- {{#callable:fd_epoch_new}} -->
The `fd_epoch_new` function initializes a new epoch structure in shared memory, setting up necessary data structures for managing voters.
- **Inputs**:
    - `shmem`: A pointer to the shared memory where the epoch structure will be initialized.
    - `voter_max`: The maximum number of voters that the epoch can accommodate.
- **Control Flow**:
    - Check if the `shmem` pointer is NULL and log a warning if it is, returning NULL.
    - Verify if `shmem` is properly aligned according to `fd_epoch_align()` and log a warning if not, returning NULL.
    - Calculate the memory footprint required for the epoch using `fd_epoch_footprint(voter_max)` and log a warning if it is zero, returning NULL.
    - Clear the memory at `shmem` with zeros for the calculated footprint size.
    - Determine the workspace containing `shmem` using `fd_wksp_containing()` and log a warning if it is not part of a workspace, returning NULL.
    - Calculate the number of slots needed for voters using `fd_ulong_find_msb(fd_ulong_pow2_up(voter_max)) + 2`.
    - Initialize scratch allocation with `FD_SCRATCH_ALLOC_INIT` and allocate memory for the epoch structure and voters using `FD_SCRATCH_ALLOC_APPEND`.
    - Finalize the scratch allocation and ensure the allocated memory matches the expected footprint.
    - Set up the epoch's global addresses for voters and the epoch itself using `fd_wksp_gaddr_fast`.
    - Initialize the epoch's total stake and slot values to zero or null.
    - Use memory fences to ensure memory operations are completed before setting the epoch's magic number.
    - Set the epoch's magic number to `FD_EPOCH_MAGIC` to indicate successful initialization.
    - Return the `shmem` pointer.
- **Output**: Returns the `shmem` pointer if the epoch is successfully initialized, otherwise returns NULL if any checks fail.
- **Functions called**:
    - [`fd_epoch_align`](fd_epoch.h.driver.md#fd_epoch_align)
    - [`fd_epoch_footprint`](fd_epoch.h.driver.md#fd_epoch_footprint)


---
### fd\_epoch\_join<!-- {{#callable:fd_epoch_join}} -->
The `fd_epoch_join` function validates and returns a pointer to an `fd_epoch_t` structure if it is correctly aligned, part of a workspace, and has the correct magic number.
- **Inputs**:
    - `shepoch`: A void pointer to the epoch structure that needs to be validated and joined.
- **Control Flow**:
    - Cast the input `shepoch` to an `fd_epoch_t` pointer named `epoch`.
    - Check if `epoch` is NULL; if so, log a warning and return NULL.
    - Check if `epoch` is aligned according to [`fd_epoch_align`](fd_epoch.h.driver.md#fd_epoch_align); if not, log a warning and return NULL.
    - Retrieve the workspace containing `epoch` using `fd_wksp_containing`; if it is not part of a workspace, log a warning and return NULL.
    - Check if the `magic` field of `epoch` matches `FD_EPOCH_MAGIC`; if not, log a warning and return NULL.
    - If all checks pass, return the `epoch` pointer.
- **Output**: Returns a pointer to the `fd_epoch_t` structure if all validation checks pass, otherwise returns NULL.
- **Functions called**:
    - [`fd_epoch_align`](fd_epoch.h.driver.md#fd_epoch_align)


---
### fd\_epoch\_leave<!-- {{#callable:fd_epoch_leave}} -->
The `fd_epoch_leave` function checks if the given epoch pointer is non-null and returns it as a void pointer.
- **Inputs**:
    - `epoch`: A constant pointer to an `fd_epoch_t` structure, representing the epoch to be left.
- **Control Flow**:
    - Check if the `epoch` pointer is NULL using `FD_UNLIKELY`; if it is, log a warning and return NULL.
    - If the `epoch` pointer is not NULL, cast it to a void pointer and return it.
- **Output**: A void pointer to the `epoch` if it is non-null, otherwise NULL.


---
### fd\_epoch\_delete<!-- {{#callable:fd_epoch_delete}} -->
The `fd_epoch_delete` function checks if a given epoch pointer is valid and aligned, and returns the pointer if it is.
- **Inputs**:
    - `epoch`: A pointer to the epoch object that is to be deleted.
- **Control Flow**:
    - Check if the `epoch` pointer is NULL; if so, log a warning and return NULL.
    - Check if the `epoch` pointer is aligned according to [`fd_epoch_align`](fd_epoch.h.driver.md#fd_epoch_align); if not, log a warning and return NULL.
    - Return the `epoch` pointer.
- **Output**: Returns the `epoch` pointer if it is valid and aligned, otherwise returns NULL.
- **Functions called**:
    - [`fd_epoch_align`](fd_epoch.h.driver.md#fd_epoch_align)


---
### fd\_epoch\_init<!-- {{#callable:fd_epoch_init}} -->
The `fd_epoch_init` function initializes an epoch structure with slot information and voter data from a given epoch bank.
- **Inputs**:
    - `epoch`: A pointer to an `fd_epoch_t` structure that will be initialized.
    - `epoch_bank`: A constant pointer to an `fd_epoch_bank_t` structure containing the epoch bank data used for initialization.
- **Control Flow**:
    - Set the `first_slot` and `last_slot` of the `epoch` from the `epoch_bank`'s start and stop slots.
    - Retrieve the epoch voters from the `epoch` and the vote accounts from the `epoch_bank`.
    - Iterate over each vote account in the vote accounts pool starting from the minimum node.
    - For each vote account with a positive stake, perform handholding checks if enabled, insert the voter into the epoch voters, and set the voter's stake and vote slots to null.
    - Accumulate the total stake from all vote accounts into the `epoch`'s total stake.
- **Output**: The function does not return a value; it initializes the provided `epoch` structure in place.
- **Functions called**:
    - [`fd_epoch_voters`](fd_epoch.h.driver.md#fd_epoch_voters)


---
### fd\_epoch\_fini<!-- {{#callable:fd_epoch_fini}} -->
The `fd_epoch_fini` function finalizes an epoch by clearing its voters and resetting the total stake to zero.
- **Inputs**:
    - `epoch`: A pointer to an `fd_epoch_t` structure representing the epoch to be finalized.
- **Control Flow**:
    - Call [`fd_epoch_voters`](fd_epoch.h.driver.md#fd_epoch_voters) with the `epoch` to retrieve the voters associated with the epoch.
    - Call `fd_epoch_voters_clear` to clear the voters retrieved in the previous step.
    - Set the `total_stake` field of the `epoch` to 0UL, effectively resetting the total stake.
- **Output**: This function does not return any value; it modifies the `epoch` structure in place.
- **Functions called**:
    - [`fd_epoch_voters`](fd_epoch.h.driver.md#fd_epoch_voters)



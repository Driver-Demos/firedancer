# Purpose
The provided C source code file is designed to manage Forward Error Correction (FEC) repair operations, specifically focusing on the creation, joining, leaving, and deletion of FEC repair structures. The code defines a set of functions that operate on a data structure, `fd_fec_repair_t`, which is used to handle FEC repair processes. The primary functions include [`fd_fec_repair_new`](#fd_fec_repair_new), which initializes a new FEC repair structure in shared memory, and [`fd_fec_repair_join`](#fd_fec_repair_join), which allows a process to join an existing FEC repair structure. Additionally, the file includes functions for leaving ([`fd_fec_repair_leave`](#fd_fec_repair_leave)) and deleting ([`fd_fec_repair_delete`](#fd_fec_repair_delete)) the FEC repair structure, ensuring proper memory management and alignment checks.

The code also includes functions to check the completion status of FEC sets, such as [`check_blind_fec_completed`](#check_blind_fec_completed) and [`check_set_blind_fec_completed`](#check_set_blind_fec_completed). These functions assess whether a particular FEC set has been fully processed, using a combination of intra-pool and intra-map queries to determine the status of data shreds. The file is part of a larger system that likely deals with data integrity and recovery, using FEC techniques to ensure data can be reconstructed in the event of loss or corruption. The code is modular and provides a specific set of functionalities related to FEC repair, making it a specialized component within a broader application or library.
# Imports and Dependencies

---
- `fd_fec_repair.h`


# Functions

---
### fd\_fec\_repair\_new<!-- {{#callable:fd_fec_repair_new}} -->
The `fd_fec_repair_new` function initializes and allocates memory for a new Forward Error Correction (FEC) repair structure using shared memory.
- **Inputs**:
    - `shmem`: A pointer to the shared memory region where the FEC repair structure will be allocated.
    - `fec_max`: The maximum number of FECs that can be handled.
    - `shred_tile_cnt`: The number of shred tiles to be managed.
    - `seed`: A seed value used for initializing the intra map.
- **Control Flow**:
    - Calculate `total_fecs_pow2` as the smallest power of two greater than or equal to `fec_max * shred_tile_cnt`.
    - Initialize scratch memory allocation with `FD_SCRATCH_ALLOC_INIT`.
    - Allocate memory for the `fd_fec_repair_t` structure and its components using `FD_SCRATCH_ALLOC_APPEND`.
    - Initialize `intra_pool` and `intra_map` using `fd_fec_intra_pool_new` and `fd_fec_intra_map_new` respectively.
    - Allocate and initialize `order_pool_lst` and `order_dlist_lst` for each shred tile using a loop.
    - Verify the final memory allocation with `FD_SCRATCH_ALLOC_FINI`.
    - Set `fec_max` and `shred_tile_cnt` in the `repair` structure.
- **Output**: Returns a pointer to the newly created `fd_fec_repair_t` structure.
- **Functions called**:
    - [`fd_fec_repair_align`](fd_fec_repair.h.driver.md#fd_fec_repair_align)
    - [`fd_fec_repair_footprint`](fd_fec_repair.h.driver.md#fd_fec_repair_footprint)


---
### fd\_fec\_repair\_join<!-- {{#callable:fd_fec_repair_join}} -->
The `fd_fec_repair_join` function initializes and joins various components of a Forward Error Correction (FEC) repair structure from shared memory.
- **Inputs**:
    - `shfec_repair`: A pointer to shared memory that contains the FEC repair structure to be joined.
- **Control Flow**:
    - Cast the input `shfec_repair` to a `fd_fec_repair_t` pointer named `fec_repair`.
    - Join the `intra_pool` component of `fec_repair` using `fd_fec_intra_pool_join`.
    - Join the `intra_map` component of `fec_repair` using `fd_fec_intra_map_join`.
    - Iterate over each shred tile (from 0 to `fec_repair->shred_tile_cnt - 1`).
    - For each shred tile, join the `order_pool_lst` and `order_dlist_lst` components using `fd_fec_order_pool_join` and `fd_fec_order_dlist_join`, respectively.
    - Return the updated `fec_repair` pointer.
- **Output**: A pointer to the joined `fd_fec_repair_t` structure.


---
### fd\_fec\_repair\_leave<!-- {{#callable:fd_fec_repair_leave}} -->
The `fd_fec_repair_leave` function checks if a given FEC repair object is non-null and returns it as a void pointer.
- **Inputs**:
    - `fec_repair`: A constant pointer to an `fd_fec_repair_t` structure, representing the FEC repair object to be checked and returned.
- **Control Flow**:
    - Check if the `fec_repair` pointer is NULL using `FD_UNLIKELY`; if it is NULL, log a warning message and return NULL.
    - If `fec_repair` is not NULL, cast it to a void pointer and return it.
- **Output**: Returns a void pointer to the `fd_fec_repair_t` object if it is non-null, otherwise returns NULL.


---
### fd\_fec\_repair\_delete<!-- {{#callable:fd_fec_repair_delete}} -->
The `fd_fec_repair_delete` function checks the validity and alignment of a given memory pointer and returns it if valid.
- **Inputs**:
    - `shmem`: A pointer to the shared memory region that is expected to be a `fd_fec_repair_t` structure.
- **Control Flow**:
    - Cast the input `shmem` to a `fd_fec_repair_t` pointer named `fec_repair`.
    - Check if `fec_repair` is NULL using `FD_UNLIKELY`; if so, log a warning and return NULL.
    - Check if `fec_repair` is aligned according to `fd_fec_repair_align()` using `FD_UNLIKELY`; if not, log a warning and return NULL.
    - If both checks pass, return the `fec_repair` pointer.
- **Output**: Returns the `fd_fec_repair_t` pointer if it is non-NULL and properly aligned; otherwise, returns NULL.
- **Functions called**:
    - [`fd_fec_repair_align`](fd_fec_repair.h.driver.md#fd_fec_repair_align)


---
### check\_blind\_fec\_completed<!-- {{#callable:check_blind_fec_completed}} -->
The function `check_blind_fec_completed` checks if a Forward Error Correction (FEC) set is complete based on certain conditions in the FEC repair and chainer structures.
- **Inputs**:
    - `fec_repair`: A constant pointer to an `fd_fec_repair_t` structure, which contains information about the FEC repair process.
    - `fec_chainer`: A pointer to an `fd_fec_chainer_t` structure, which is used to query the next FEC set.
    - `slot`: An unsigned long integer representing the slot number, used to generate the FEC key.
    - `fec_set_idx`: An unsigned integer representing the index of the FEC set within the slot.
- **Control Flow**:
    - Compute the FEC key by combining the slot and fec_set_idx.
    - Query the FEC intra map using the computed FEC key to get the `fec_intra` structure.
    - If `fec_intra` is NULL, return 0 indicating no FEC set is present.
    - If `fec_intra->data_cnt` is not zero, return 0 indicating a coding shred is present and completion should not be forced.
    - If `fec_intra->buffered_idx` is UINT_MAX, return 0 indicating no buffered index is available.
    - If `fec_intra->buffered_idx` equals `fec_intra->completes_idx`, return 1 indicating the FEC set is complete.
    - Compute the next FEC key by incrementing the current FEC set index by `fec_intra->buffered_idx + 1`.
    - Query the FEC intra map using the next FEC key to get the `next_fec` structure.
    - If `next_fec` is NULL, query the FEC chainer for the next FEC set.
    - If the next FEC set is not found in the chainer, return 0 indicating no next FEC set is present.
    - Return 1 indicating the FEC set is complete.
- **Output**: The function returns an integer: 1 if the FEC set is complete, and 0 otherwise.


---
### check\_set\_blind\_fec\_completed<!-- {{#callable:check_set_blind_fec_completed}} -->
The function `check_set_blind_fec_completed` checks if a Forward Error Correction (FEC) set is complete and updates its status if necessary.
- **Inputs**:
    - `fec_repair`: A pointer to an `fd_fec_repair_t` structure, which contains the intra_map and intra_pool used for querying FEC intra elements.
    - `fec_chainer`: A pointer to an `fd_fec_chainer_t` structure, used to query the next FEC element if needed.
    - `slot`: An unsigned long integer representing the slot number, used to generate the FEC key.
    - `fec_set_idx`: An unsigned integer representing the index of the FEC set within the slot.
- **Control Flow**:
    - Compute `fec_key` using `slot` and `fec_set_idx` to query the current FEC intra element from `fec_repair->intra_map`.
    - Compute `next_fec_key` using `slot` and the next FEC set index based on `fec_intra->buffered_idx`.
    - Check if `fec_intra->data_cnt` is non-zero; if so, return 0 as the FEC set is not complete.
    - Check if `fec_intra->buffered_idx` is `UINT_MAX`; if so, return 0 as there is no buffered index.
    - Check if `fec_intra->buffered_idx` equals `fec_intra->completes_idx`; if so, return 1 as the FEC set is complete.
    - Query the next FEC intra element using `next_fec_key`; if it doesn't exist, query the next FEC element using `fec_chainer`.
    - If no next FEC element is found, return 0 as there is no next FEC set.
    - If `fec_intra->completes_idx` is `UINT_MAX`, set it to `fec_intra->buffered_idx`.
    - Return whether `fec_intra->buffered_idx` is not `UINT_MAX` and equals `fec_intra->completes_idx`.
- **Output**: Returns an integer: 1 if the FEC set is complete, 0 otherwise.



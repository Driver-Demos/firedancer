# Purpose
This C source code file provides functionality for managing a runtime public structure, specifically focusing on memory alignment, footprint calculation, and shared memory operations. The code defines several functions that operate on a data structure `fd_runtime_public_t`, which appears to be a part of a larger system involving shared memory and workspaces. The functions include [`fd_runtime_public_align`](#fd_runtime_public_align), which calculates the alignment requirements for the structure, and [`fd_runtime_public_footprint`](#fd_runtime_public_footprint), which computes the memory footprint needed for the structure and its associated components. The [`fd_runtime_public_join`](#fd_runtime_public_join) function is responsible for validating and joining a shared memory segment to the runtime public structure, ensuring that the memory is correctly initialized and part of a valid workspace.

Additionally, the file includes functions for creating and managing the runtime public structure within a shared memory context. The [`fd_runtime_public_new`](#fd_runtime_public_new) function initializes a new instance of the structure in shared memory, setting up necessary components like a scratchpad memory (`spad`). The [`fd_runtime_public_spad`](#fd_runtime_public_spad) function retrieves the scratchpad memory associated with a given runtime public structure. Throughout the code, there are checks and logging for error conditions, such as invalid magic numbers or missing workspace associations, ensuring robustness in memory management operations. This file is likely part of a larger library or system that deals with shared memory and runtime environments, providing essential utilities for memory alignment and management.
# Imports and Dependencies

---
- `fd_runtime_public.h`


# Functions

---
### fd\_runtime\_public\_align<!-- {{#callable:fd_runtime_public_align}} -->
The `fd_runtime_public_align` function returns the maximum alignment requirement between `fd_runtime_public_t` and the alignment required by the scratchpad memory.
- **Inputs**: None
- **Control Flow**:
    - The function calls `fd_ulong_max` with two arguments: `alignof(fd_runtime_public_t)` and `fd_spad_align()`.
    - It returns the result of `fd_ulong_max`, which is the greater of the two alignment values.
- **Output**: The function returns an `ulong` representing the maximum alignment requirement.


---
### fd\_runtime\_public\_footprint<!-- {{#callable:fd_runtime_public_footprint}} -->
The `fd_runtime_public_footprint` function calculates the memory footprint required for a public runtime structure and its associated scratchpad memory.
- **Inputs**:
    - `spad_mem_max`: The maximum memory size for the scratchpad (spad) in bytes.
- **Control Flow**:
    - The function begins by initializing a layout using `FD_LAYOUT_INIT`.
    - It appends the alignment and size of `fd_runtime_public_t` to the layout using `FD_LAYOUT_APPEND`.
    - It further appends the alignment and footprint of the scratchpad memory, calculated using `fd_spad_align()` and `fd_spad_footprint(spad_mem_max)`, to the layout.
    - Finally, it appends the alignment of the public runtime structure using `fd_runtime_public_align()` and finalizes the layout with `FD_LAYOUT_FINI`.
- **Output**: The function returns an unsigned long integer representing the total memory footprint required for the public runtime structure and its scratchpad.
- **Functions called**:
    - [`fd_runtime_public_align`](#fd_runtime_public_align)


---
### fd\_runtime\_public\_join<!-- {{#callable:fd_runtime_public_join}} -->
The `fd_runtime_public_join` function validates and returns a pointer to a `fd_runtime_public_t` structure from shared memory if it meets certain conditions.
- **Inputs**:
    - `shmem`: A pointer to shared memory that is expected to contain a `fd_runtime_public_t` structure.
- **Control Flow**:
    - Cast the `shmem` pointer to a `fd_runtime_public_t` pointer named `pub`.
    - Check if the `magic` field of `pub` is equal to `FD_RUNTIME_PUBLIC_MAGIC`; if not, log a warning and return `NULL`.
    - Check if the `runtime_spad_gaddr` field of `pub` is zero; if so, log a warning and return `NULL`.
    - Call `fd_wksp_containing` with `shmem` to get the workspace containing the shared memory; if it returns `NULL`, log a warning and return `NULL`.
    - If all checks pass, return the `pub` pointer.
- **Output**: A pointer to a `fd_runtime_public_t` structure if all checks pass, otherwise `NULL`.


---
### fd\_runtime\_public\_new<!-- {{#callable:fd_runtime_public_new}} -->
The `fd_runtime_public_new` function initializes a new runtime public structure in shared memory and sets up a scratchpad memory within it.
- **Inputs**:
    - `shmem`: A pointer to the shared memory where the runtime public structure will be initialized.
    - `spad_mem_max`: The maximum size of the scratchpad memory to be allocated within the runtime public structure.
- **Control Flow**:
    - Check if the provided shared memory is part of a workspace using `fd_wksp_containing`; if not, log a warning and return NULL.
    - Initialize a scratch allocation context with `FD_SCRATCH_ALLOC_INIT`.
    - Allocate memory for the `fd_runtime_public_t` structure and the scratchpad memory using `FD_SCRATCH_ALLOC_APPEND`.
    - Finalize the scratch allocation with `FD_SCRATCH_ALLOC_FINI`.
    - Zero out the allocated `fd_runtime_public_t` structure using `fd_memset`.
    - Attempt to create a new scratchpad with `fd_spad_new`; if unsuccessful, log a warning and return NULL.
    - Retrieve the global address of the scratchpad memory using `fd_wksp_gaddr`; if unsuccessful, log a critical error (unreachable code).
    - Set the magic number for the runtime public structure to `FD_RUNTIME_PUBLIC_MAGIC` with memory fences to ensure proper ordering.
    - Return the original shared memory pointer.
- **Output**: Returns the original shared memory pointer if successful, or NULL if any step fails.
- **Functions called**:
    - [`fd_runtime_public_align`](#fd_runtime_public_align)


---
### fd\_runtime\_public\_spad<!-- {{#callable:fd_runtime_public_spad}} -->
The function `fd_runtime_public_spad` retrieves and joins a shared private address (spad) from a given runtime public structure.
- **Inputs**:
    - `runtime_public`: A pointer to a constant `fd_runtime_public_t` structure, which contains information about the runtime public context, including the global address of the spad.
- **Control Flow**:
    - Check if `runtime_public` is NULL; if so, log a warning and return NULL.
    - Retrieve the workspace (`wksp`) containing `runtime_public`; if not found, log a warning and return NULL.
    - Get the local address (`spad_laddr`) of the spad using the workspace and the global address from `runtime_public`; if retrieval fails, log a critical error and return NULL.
    - Join the spad using its local address and return the result.
- **Output**: A pointer to an `fd_spad_t` structure if successful, or NULL if any error occurs during the process.



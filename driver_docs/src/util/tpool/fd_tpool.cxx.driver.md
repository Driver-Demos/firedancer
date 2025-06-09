# Purpose
This C++ source code file is part of a thread pool implementation, designed to manage and execute tasks concurrently across multiple threads. The code provides a comprehensive set of functionalities for initializing, managing, and executing tasks within a thread pool. It includes functions for initializing ([`fd_tpool_init`](#fd_tpool_init)) and finalizing ([`fd_tpool_fini`](#fd_tpool_fini)) the thread pool, as well as adding ([`fd_tpool_worker_push`](#fd_tpool_worker_push)) and removing ([`fd_tpool_worker_pop`](#fd_tpool_worker_pop)) worker threads. The code is structured to handle both single-threaded and multi-threaded environments, as indicated by the conditional compilation directives checking for `FD_HAS_THREADS`.

The core functionality revolves around managing worker threads that execute tasks in parallel, with synchronization mechanisms such as mutexes and condition variables used to manage thread states and transitions. The file defines several task execution strategies, such as round-robin, block, task queue, batch, and raw execution, which are implemented through macros and functions. These strategies allow for flexible task distribution and execution within the thread pool. The code is intended to be part of a larger system, likely a library, that can be imported and used to facilitate parallel processing in applications. It provides a public API for managing the lifecycle of the thread pool and executing tasks, making it a critical component for applications requiring efficient multi-threading capabilities.
# Imports and Dependencies

---
- `fd_tpool.h`
- `pthread.h`


# Global Variables

---
### m\_stride
- **Type**: `ulong`
- **Description**: The variable `m_stride` is a global variable of type `ulong` that represents the difference between two time points, `t1` and `t0`. It is used to calculate the stride or step size for iterating over a range of tasks in a thread pool execution context.
- **Use**: `m_stride` is used to determine the step size for task execution in a round-robin scheduling strategy within a thread pool.


---
### m
- **Type**: `ulong`
- **Description**: The variable `m` is an unsigned long integer that is initialized to a value calculated by adding `l0` to the minimum of `node_t0-t0` and `ULONG_MAX-l0`. This calculation is designed to be robust against overflow.
- **Use**: `m` is used as a loop counter in a while loop to iterate over a range from `l0` to `l1`, ensuring that the loop continues as long as `m` is less than `l1`.


---
### FD\_TPOOL\_EXEC\_ALL\_IMPL\_HDR
- **Type**: `Macro`
- **Description**: `FD_TPOOL_EXEC_ALL_IMPL_HDR` is a macro that defines a function template for executing tasks across a thread pool in different styles, such as round-robin, block, task queue, and batch. It is used to set up the function header and initial logic for task execution in a thread pool environment.
- **Use**: This macro is used to define the header and initial setup for task execution functions in a thread pool, allowing for different execution styles.


---
### m0
- **Type**: `ulong`
- **Description**: The variable `m0` is a global variable of type `ulong` (unsigned long integer). It is used in the context of a task execution framework, likely related to partitioning work across multiple threads or nodes.
- **Use**: `m0` is used as a parameter in task execution functions to define a range or partition of work to be processed.


---
### m1
- **Type**: `ulong`
- **Description**: The variable `m1` is a global variable of type `ulong` (unsigned long integer) used in the context of a task execution framework. It is defined alongside `m0` and is used in the `FD_TPOOL_PARTITION` macro to determine a partition of work for a task.
- **Use**: `m1` is used to specify the upper bound of a partition of work in a task execution framework, facilitating parallel processing.


---
### tpool
- **Type**: `void*`
- **Description**: The `tpool` variable is a global pointer of type `void*` that is initialized to point to the second element of the `l_next` array. It is used within a loop in the `taskq` implementation of the thread pool execution model.
- **Use**: This variable is used to store a reference to a thread pool or related data structure, facilitating task execution in a multi-threaded environment.


# Data Structures

---
### fd\_tpool\_private\_worker\_cfg<!-- {{#data_structure:fd_tpool_private_worker_cfg}} -->
- **Type**: `struct`
- **Members**:
    - `tpool`: A pointer to an fd_tpool_t structure, representing the thread pool associated with the worker.
    - `tile_idx`: An unsigned long integer representing the index of the tile (or worker) within the thread pool.
- **Description**: The `fd_tpool_private_worker_cfg` structure is used to configure a private worker within a thread pool. It contains a pointer to the thread pool (`tpool`) and an index (`tile_idx`) that identifies the specific worker or tile within that pool. This configuration is essential for managing and executing tasks across multiple threads in a parallel computing environment.


---
### fd\_tpool\_private\_worker\_cfg\_t<!-- {{#data_structure:fd_tpool_private_worker_cfg_t}} -->
- **Type**: `struct`
- **Members**:
    - `tpool`: A pointer to an fd_tpool_t structure, representing the thread pool associated with the worker.
    - `tile_idx`: An unsigned long integer representing the index of the tile (or thread) within the thread pool.
- **Description**: The `fd_tpool_private_worker_cfg_t` structure is used to configure a worker within a thread pool. It contains a pointer to the thread pool (`tpool`) and an index (`tile_idx`) that identifies the specific tile or thread within that pool. This configuration is essential for managing and executing tasks across multiple threads in a parallel computing environment.


# Functions

---
### fd\_tpool\_private\_worker<!-- {{#callable:fd_tpool_private_worker}} -->
The [`fd_tpool_private_worker`](fd_tpool.h.driver.md#fd_tpool_private_worker) function initializes and manages a worker thread in a thread pool, executing tasks and handling synchronization.
- **Inputs**:
    - `argc`: An integer representing the index of the worker in the thread pool.
    - `argv`: A pointer to an array of character pointers, which is cast to a `fd_tpool_private_worker_cfg_t` structure containing configuration for the worker.
- **Control Flow**:
    - The function begins by casting `argc` to `worker_idx` and `argv` to a configuration structure `cfg` to extract the thread pool and tile index.
    - A `fd_tpool_private_worker_t` structure is initialized to zero and configured with the tile index.
    - If threading is enabled, it checks if the worker should sleep based on the thread pool options and initializes mutex and condition variables if necessary.
    - The worker is registered in the thread pool's worker array at the index `worker_idx`.
    - The function enters an infinite loop where it waits for tasks to execute, checking if the worker is idle or should halt.
    - If a task is available, it executes the task using either `fd_tpool_task_t` or `fd_tpool_task_v2_t` based on the argument count.
    - After task execution, it updates the worker's sequence number to indicate task completion.
    - If the worker is set to halt, it breaks the loop and proceeds to clean up resources.
    - If threading is enabled, it destroys the mutex and condition variables before returning.
- **Output**: The function returns an integer, always 0, indicating successful execution.
- **Functions called**:
    - [`fd_tpool_private_worker`](fd_tpool.h.driver.md#fd_tpool_private_worker)


---
### fd\_tpool\_private\_wake<!-- {{#callable:fd_tpool_private_wake}} -->
The `fd_tpool_private_wake` function signals a condition variable to wake up a worker thread in a thread pool.
- **Inputs**:
    - `worker`: A pointer to an `fd_tpool_private_worker_t` structure representing the worker to be woken up.
- **Control Flow**:
    - Retrieve the mutex lock and condition variable from the worker structure.
    - Attempt to lock the mutex using `pthread_mutex_lock`; log a warning if it fails.
    - Signal the condition variable using `pthread_cond_signal`; log a warning if it fails.
    - Unlock the mutex using `pthread_mutex_unlock`; log a warning if it fails.
- **Output**: This function does not return any value.


---
### fd\_tpool\_align<!-- {{#callable:fd_tpool_align}} -->
The `fd_tpool_align` function returns the alignment requirement for a thread pool.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of the macro `FD_TPOOL_ALIGN`.
- **Output**: The function returns an `ulong` representing the alignment requirement for a thread pool.


---
### fd\_tpool\_footprint<!-- {{#callable:fd_tpool_footprint}} -->
The `fd_tpool_footprint` function calculates the memory footprint required for a thread pool with a specified maximum number of workers, ensuring alignment.
- **Inputs**:
    - `worker_max`: The maximum number of workers that the thread pool can accommodate, represented as an unsigned long integer.
- **Control Flow**:
    - Check if `worker_max` is within the valid range (1 to `FD_TILE_MAX`); if not, return 0.
    - Calculate the total memory size required for the thread pool, including the size of the `fd_tpool_private_worker_t` structure, the `fd_tpool_t` structure, and an array of pointers to `fd_tpool_private_worker_t` structures, all aligned to `FD_TPOOL_ALIGN`.
    - Return the aligned memory size.
- **Output**: The function returns the aligned memory size required for the thread pool as an unsigned long integer, or 0 if the input is invalid.


---
### fd\_tpool\_init<!-- {{#callable:fd_tpool_init}} -->
The `fd_tpool_init` function initializes a thread pool structure in a given memory region, setting up the initial worker and configuration parameters.
- **Inputs**:
    - `mem`: A pointer to the memory region where the thread pool will be initialized.
    - `worker_max`: The maximum number of workers that the thread pool can support.
    - `opt`: Options for configuring the thread pool, such as whether workers should sleep when idle.
- **Control Flow**:
    - The function begins by ensuring memory ordering with `FD_COMPILER_MFENCE()`.
    - It checks if the `mem` pointer is NULL and logs a warning if so, returning NULL.
    - It verifies that the `mem` pointer is properly aligned using `fd_ulong_is_aligned` and logs a warning if not, returning NULL.
    - It calculates the memory footprint required for the thread pool using [`fd_tpool_footprint`](#fd_tpool_footprint) and logs a warning if the footprint is zero, returning NULL.
    - The memory region is zeroed out using `fd_memset`.
    - A worker structure is initialized at the start of the memory region, setting `seq0` to 1 and `seq1` to 0.
    - The thread pool structure is initialized immediately after the worker structure, setting `opt`, `worker_max`, and `worker_cnt`.
    - Memory ordering is ensured again with `FD_COMPILER_MFENCE()`, and the initial worker is assigned to the thread pool.
    - The function returns a pointer to the initialized thread pool.
- **Output**: A pointer to the initialized `fd_tpool_t` structure, or NULL if initialization fails due to invalid inputs or alignment issues.
- **Functions called**:
    - [`fd_tpool_align`](#fd_tpool_align)
    - [`fd_tpool_footprint`](#fd_tpool_footprint)
    - [`fd_tpool_private_worker`](#fd_tpool_private_worker)


---
### fd\_tpool\_fini<!-- {{#callable:fd_tpool_fini}} -->
The `fd_tpool_fini` function finalizes a thread pool by ensuring all but one worker are removed and returns a pointer to the first worker.
- **Inputs**:
    - `tpool`: A pointer to the thread pool (`fd_tpool_t`) to be finalized.
- **Control Flow**:
    - The function begins by enforcing a memory fence with `FD_COMPILER_MFENCE()` to ensure memory operations are completed in order.
    - It checks if the `tpool` is NULL using `FD_UNLIKELY`, logs a warning if true, and returns NULL.
    - A loop runs while the worker count in the pool is greater than one, attempting to pop workers using [`fd_tpool_worker_pop`](#fd_tpool_worker_pop).
    - If [`fd_tpool_worker_pop`](#fd_tpool_worker_pop) fails, a warning is logged and the function returns NULL.
    - Finally, the function returns a pointer to the first worker in the pool using `fd_tpool_private_worker0`.
- **Output**: A pointer to the first worker in the thread pool, or NULL if an error occurs.
- **Functions called**:
    - [`fd_tpool_worker_cnt`](fd_tpool.h.driver.md#fd_tpool_worker_cnt)
    - [`fd_tpool_worker_pop`](#fd_tpool_worker_pop)


---
### fd\_tpool\_worker\_push<!-- {{#callable:fd_tpool_worker_push}} -->
The `fd_tpool_worker_push` function adds a new worker to a thread pool, ensuring the worker is valid and not already present, and initializes it for execution.
- **Inputs**:
    - `tpool`: A pointer to the thread pool (`fd_tpool_t`) to which a new worker is to be added.
    - `tile_idx`: An unsigned long integer representing the index of the tile (worker) to be added to the thread pool.
- **Control Flow**:
    - The function begins by ensuring memory ordering with `FD_COMPILER_MFENCE()`.
    - It checks if `tpool` is NULL and logs a warning if so, returning NULL.
    - It checks if `tile_idx` is zero, logs a warning, and returns NULL if true.
    - It checks if `tile_idx` is the same as the current tile index, logs a warning, and returns NULL if true.
    - It checks if `tile_idx` is greater than or equal to the total tile count, logs a warning, and returns NULL if true.
    - It retrieves the current worker list and count from the thread pool.
    - It checks if the current worker count exceeds the maximum allowed, logs a warning, and returns NULL if true.
    - It iterates over existing workers to check if `tile_idx` is already present, logs a warning, and returns NULL if true.
    - It prepares a configuration for the new worker and sets up arguments for execution.
    - It sets the new worker slot to NULL and ensures memory ordering with `FD_COMPILER_MFENCE()`.
    - It attempts to create a new execution context for the worker with `fd_tile_exec_new`, logs a warning, and returns NULL if it fails.
    - It waits in a loop until the new worker is initialized, using `FD_SPIN_PAUSE()` for efficient waiting.
    - Finally, it increments the worker count in the thread pool and returns the updated thread pool.
- **Output**: Returns a pointer to the updated thread pool (`fd_tpool_t *`) if successful, or NULL if any error occurs during the process.
- **Functions called**:
    - [`fd_tpool_private_worker`](#fd_tpool_private_worker)


---
### fd\_tpool\_worker\_pop<!-- {{#callable:fd_tpool_worker_pop}} -->
The `fd_tpool_worker_pop` function removes the last worker from a thread pool if it is idle and properly shuts it down.
- **Inputs**:
    - `tpool`: A pointer to the thread pool (`fd_tpool_t`) from which a worker is to be removed.
- **Control Flow**:
    - The function begins by ensuring memory ordering with `FD_COMPILER_MFENCE()`.
    - It checks if the `tpool` is NULL and logs a warning if so, returning NULL.
    - It retrieves the current worker count from the `tpool` and checks if there is more than one worker; if not, it logs a warning and returns NULL.
    - It checks if the last worker is idle using [`fd_tpool_worker_idle`](fd_tpool.h.driver.md#fd_tpool_worker_idle); if not, it logs a warning and returns NULL.
    - The function sends a HALT signal to the worker by setting its task to 0 and updating its sequence number, ensuring memory ordering with `FD_COMPILER_MFENCE()`.
    - If the thread pool is configured to sleep, it wakes the worker using [`fd_tpool_private_wake`](#fd_tpool_private_wake).
    - It waits for the worker to shut down by calling `fd_tile_exec_delete` and logs any errors or unexpected return values.
    - Finally, it decrements the worker count in the `tpool` and returns the updated `tpool`.
- **Output**: A pointer to the updated thread pool (`fd_tpool_t`) with one less worker, or NULL if an error occurred.
- **Functions called**:
    - [`fd_tpool_worker_idle`](fd_tpool.h.driver.md#fd_tpool_worker_idle)
    - [`fd_tpool_private_worker`](#fd_tpool_private_worker)
    - [`fd_tpool_private_wake`](#fd_tpool_private_wake)



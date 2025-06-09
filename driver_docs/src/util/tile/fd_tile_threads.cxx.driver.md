# Purpose
This C++ source code file is designed to manage and optimize the execution of threads, referred to as "tiles," on a multi-core system. It provides a comprehensive set of functionalities for configuring CPU priorities, managing thread stacks, and handling thread execution and synchronization. The code includes mechanisms to set high scheduler priorities for threads, create and manage optimized stacks using huge pages for better NUMA and TLB performance, and handle thread affinity to specific CPUs. It also includes error handling and logging to ensure that any issues during these operations are reported and can be addressed.

The file defines several key components, including structures and functions for configuring CPU settings, creating and deleting stacks, and managing the lifecycle of threads. It provides APIs for both the tile side (e.g., [`fd_tile_id`](#fd_tile_id), [`fd_tile_idx`](#fd_tile_idx)) and the dispatch side (e.g., [`fd_tile_exec_new`](#fd_tile_exec_new), [`fd_tile_exec_delete`](#fd_tile_exec_delete)) to facilitate the execution of tasks on different tiles. The code also includes boot and halt functions to initialize and clean up the thread group, ensuring that all threads are properly managed and resources are released when no longer needed. This file is intended to be part of a larger system where it can be included and used to manage thread execution efficiently, particularly in high-performance computing environments.
# Imports and Dependencies

---
- `ctype.h`
- `errno.h`
- `pthread.h`
- `unistd.h`
- `sched.h`
- `syscall.h`
- `sys/resource.h`
- `sys/mman.h`
- `sys/prctl.h`
- `../sanitize/fd_sanitize.h`
- `fd_tile_private.h`


# Global Variables

---
### fd\_tile\_private\_id0
- **Type**: `ulong`
- **Description**: The variable `fd_tile_private_id0` is a static global variable of type `ulong` that is zeroed at application start and initialized by the boot manager. It is used to store an identifier related to the tile system in the application.
- **Use**: This variable is used to store the starting identifier for a range of tile identifiers managed by the boot manager.


---
### fd\_tile\_private\_id1
- **Type**: `ulong`
- **Description**: `fd_tile_private_id1` is a static global variable of type `ulong` that is used to store an identifier related to the tile system. It is initialized to zero at the start of the application and is set by the boot manager.
- **Use**: This variable is used to track the upper bound of tile identifiers in the system, helping to manage and identify different tiles within the application.


---
### fd\_tile\_private\_cnt
- **Type**: `ulong`
- **Description**: The `fd_tile_private_cnt` is a static global variable of type `ulong` that is used to store the count of tiles in the system. It is initialized by the boot manager and is zeroed at the application start.
- **Use**: This variable is used to keep track of the number of tiles available in the system, which is crucial for managing and dispatching tasks to different tiles.


---
### fd\_tile\_private\_id
- **Type**: `ulong`
- **Description**: The `fd_tile_private_id` is a global variable of type `ulong` that is zeroed at the start of an application or thread and is initialized by the boot or tile manager. It is used to store a unique identifier for a tile within a thread group.
- **Use**: This variable is used to track and manage the identity of a tile in a multi-threaded environment, allowing for proper initialization and management by the tile manager.


---
### fd\_tile\_private\_idx
- **Type**: `ulong`
- **Description**: The `fd_tile_private_idx` is a static thread-local variable of type `ulong` that is zeroed at application or thread start and initialized by the boot or tile manager. It is used to store the index of the current tile in a multi-threaded environment.
- **Use**: This variable is used to track the index of the current tile within the tile management system, allowing for identification and management of individual tiles.


---
### fd\_tile\_private\_stack0
- **Type**: `ulong`
- **Description**: `fd_tile_private_stack0` is a global variable of type `ulong` that is used to store the starting address of a stack for a tile in a multi-threaded environment. It is initialized by the boot or tile manager at the start of the application or thread.
- **Use**: This variable is used to keep track of the lower boundary of the stack memory allocated for a tile, which is crucial for stack management and diagnostics.


---
### fd\_tile\_private\_stack1
- **Type**: `FD_TL ulong`
- **Description**: The `fd_tile_private_stack1` is a global variable of type `ulong` that is declared with the `FD_TL` macro, which likely indicates a thread-local storage specifier. It is used to store the upper boundary address of a stack for a tile in a multi-threaded environment.
- **Use**: This variable is used to keep track of the upper boundary of a stack allocated for a tile, which is part of the thread management and execution system.


---
### fd\_tile\_private\_cpu\_id
- **Type**: `ushort`
- **Description**: The `fd_tile_private_cpu_id` is a static array of unsigned short integers with a size defined by `FD_TILE_MAX`. It is initialized to zero at the start of the application and is later set up by the boot process.
- **Use**: This array is used to map each tile to a specific CPU ID, allowing the system to manage CPU affinity for different tiles.


---
### fd\_tile\_private
- **Type**: `struct`
- **Description**: The `fd_tile_private` is a static array of structures, each aligned to 128 bytes to minimize false sharing in parallel dispatch. Each structure contains a lock pointer, a tile pointer, and a pthread_t variable. The lock pointer is non-NULL if the tile index is available for dispatch, and equals the tile pointer otherwise.
- **Use**: This variable is used to manage and coordinate the dispatch of tasks to different tiles in a parallel processing environment.


---
### fd\_tile\_private\_cpu\_config\_save
- **Type**: `fd_tile_private_cpu_config_t[1]`
- **Description**: The variable `fd_tile_private_cpu_config_save` is a static array of one element of type `fd_tile_private_cpu_config_t`. This type is a structure that contains a single integer field named `prio`, which is used to store the priority of a CPU configuration.
- **Use**: This variable is used to save the CPU configuration state, specifically the scheduler priority, for later restoration.


# Data Structures

---
### fd\_tile\_private\_cpu\_config<!-- {{#data_structure:fd_tile_private_cpu_config}} -->
- **Type**: `struct`
- **Members**:
    - `prio`: An integer representing the priority of the CPU configuration.
- **Description**: The `fd_tile_private_cpu_config` structure is a simple data structure used to store the priority level of a CPU configuration. It contains a single integer member, `prio`, which is used to hold the priority value. This structure is likely used in the context of configuring CPU scheduling priorities for threads or processes in a system, as indicated by its usage in functions that adjust or restore CPU priorities.


---
### fd\_tile\_private\_cpu\_config\_t<!-- {{#data_structure:fd_tile_private_cpu_config_t}} -->
- **Type**: `struct`
- **Members**:
    - `prio`: An integer representing the priority of the CPU configuration.
- **Description**: The `fd_tile_private_cpu_config_t` structure is used to store the CPU configuration settings for a tile, specifically the scheduler priority. It contains a single member, `prio`, which holds the priority level of the CPU configuration. This structure is utilized in functions that configure and restore CPU settings for optimal performance of tile-based computations.


---
### fd\_tile\_private<!-- {{#data_structure:fd_tile_private}} -->
- **Type**: `struct`
- **Members**:
    - `id`: A unique identifier for the tile.
    - `idx`: The index of the tile.
    - `state`: The current state of the tile, represented by FD_TILE_PRIVATE_STATE_* constants.
    - `argc`: The argument count for the task to be executed by the tile.
    - `argv`: The argument vector for the task to be executed by the tile.
    - `task`: A function pointer to the task that the tile is supposed to execute.
    - `fail`: A pointer to a string indicating failure reason if the task fails.
    - `ret`: The return value of the task executed by the tile.
- **Description**: The `fd_tile_private` struct is a data structure used to manage the state and execution context of a tile in a multi-threaded environment. It is aligned to 128 bytes to avoid false sharing in cache lines. Each tile has a unique identifier (`id`), an index (`idx`), and maintains its current state (`state`) which can be one of several predefined states. The struct also holds the arguments (`argc` and `argv`) and the task (`task`) that the tile is supposed to execute. Additionally, it records the outcome of the task execution through `fail` and `ret` fields, which indicate if the task failed and its return value, respectively.


---
### fd\_tile\_private\_t<!-- {{#data_structure:fd_tile_private_t}} -->
- **Type**: `struct`
- **Members**:
    - `id`: A unique identifier for the tile.
    - `idx`: The index of the tile within a group.
    - `state`: The current state of the tile, represented by predefined constants.
    - `argc`: The argument count for the task to be executed by the tile.
    - `argv`: The argument vector for the task to be executed by the tile.
    - `task`: A function pointer to the task that the tile will execute.
    - `fail`: A string indicating the reason for task failure, if any.
    - `ret`: The return value of the executed task.
- **Description**: The `fd_tile_private_t` structure is designed to manage the state and execution context of a tile in a multi-threaded environment. It includes fields for identifying the tile (`id` and `idx`), managing its execution state (`state`), and handling task execution (`argc`, `argv`, `task`, `fail`, and `ret`). The structure is aligned to avoid cache line sharing issues, ensuring efficient access and modification in concurrent scenarios.


---
### fd\_tile\_private\_manager\_args<!-- {{#data_structure:fd_tile_private_manager_args}} -->
- **Type**: `struct`
- **Members**:
    - `id`: A unique identifier for the tile manager.
    - `idx`: The index of the tile manager.
    - `cpu_idx`: The CPU index where the tile manager is running.
    - `stack`: A pointer to the stack, NULL if created by pthread, non-NULL if user-created.
    - `stack_sz`: The size of the stack in bytes.
    - `tile`: A pointer to the fd_tile_private structure associated with this manager.
- **Description**: The `fd_tile_private_manager_args` struct is used to encapsulate the arguments required to manage a tile in a multi-threaded environment. It includes identifiers and indices for the tile and CPU, a pointer to the stack used by the tile, and a reference to the tile's private data structure. This struct is essential for setting up and managing the execution context of a tile, allowing for efficient task scheduling and resource management in a parallel processing system.


---
### fd\_tile\_private\_manager\_args\_t<!-- {{#data_structure:fd_tile_private_manager_args_t}} -->
- **Type**: `struct`
- **Members**:
    - `id`: A unique identifier for the tile manager.
    - `idx`: The index of the tile within the tile group.
    - `cpu_idx`: The index of the CPU on which the tile is running.
    - `stack`: A pointer to the stack memory, NULL if created by pthread, non-NULL if user-created.
    - `stack_sz`: The size of the stack memory.
    - `tile`: A pointer to the fd_tile_private structure associated with this tile manager.
- **Description**: The `fd_tile_private_manager_args_t` structure is used to pass arguments to the tile manager function in a multi-threaded environment. It contains information about the tile's unique identifier, its index within the tile group, the CPU index it is running on, and details about the stack memory being used. This structure facilitates the management and configuration of individual tiles within a larger tile-based processing system, allowing for efficient task execution and resource allocation.


# Functions

---
### fd\_tile\_private\_cpu\_config<!-- {{#callable:fd_tile_private_cpu_config}} -->
The `fd_tile_private_cpu_config` function configures the CPU scheduler priority for a tile based on the provided CPU index.
- **Inputs**:
    - `save`: A pointer to an `fd_tile_private_cpu_config_t` structure where the current priority configuration will be saved.
    - `cpu_idx`: An unsigned long integer representing the CPU index for which the configuration is being set.
- **Control Flow**:
    - Check if the `cpu_idx` is 65535UL, indicating a floating tile, and set the priority to `INT_MIN` without changing the scheduler priority.
    - If not a floating tile, attempt to get the current process priority using `getpriority`.
    - If `getpriority` fails, log a warning and set the priority to `INT_MIN`.
    - If the current priority is not -19, attempt to set it to -19 using `setpriority`.
    - If `setpriority` fails, log a warning and set the priority to `INT_MIN`.
    - If successful, save the current priority in the `save` structure.
- **Output**: The function does not return a value but modifies the `save` structure to store the current or intended priority configuration.


---
### fd\_tile\_private\_cpu\_restore<!-- {{#callable:fd_tile_private_cpu_restore}} -->
The `fd_tile_private_cpu_restore` function restores the CPU priority to a previously saved state.
- **Inputs**:
    - `save`: A pointer to an `fd_tile_private_cpu_config_t` structure containing the saved CPU priority to be restored.
- **Control Flow**:
    - Retrieve the saved priority from the `save` structure.
    - Check if the saved priority is not `INT_MIN` and not `-19`.
    - If the priority needs to be restored and `setpriority` fails, log a warning message.
- **Output**: The function does not return a value; it performs an action to restore CPU priority and logs a warning if it fails.


---
### fd\_tile\_private\_stack\_new<!-- {{#callable:fd_tile_private_stack_new}} -->
The `fd_tile_private_stack_new` function creates a new stack for a tile, optimized for NUMA and TLB if requested, and sets up guard regions for memory protection.
- **Inputs**:
    - `optimize`: An integer flag indicating whether to create a NUMA and TLB optimized stack.
    - `cpu_idx`: The index of the CPU on which the tile is running, used for optimization if requested.
- **Control Flow**:
    - Initialize the stack pointer to NULL.
    - If optimization is requested, attempt to acquire a NUMA and TLB optimized stack using `fd_shmem_acquire` with huge pages.
    - If the acquisition is successful, release the first and last huge pages to create guard regions and adjust the stack pointer.
    - If the acquisition fails, log a warning about insufficient huge pages and fall back to a normal page-backed stack.
    - If no stack is acquired (either due to no optimization or failed optimization), use `mmap` to allocate a normal stack with guard regions.
    - If `mmap` fails, log a warning and return NULL.
    - Create guard regions at the beginning and end of the stack using `mmap` with `PROT_NONE` to prevent access.
    - Return the pointer to the newly created stack.
- **Output**: A pointer to the newly created stack, or NULL if stack creation fails.


---
### fd\_tile\_private\_stack\_delete<!-- {{#callable:fd_tile_private_stack_delete}} -->
The `fd_tile_private_stack_delete` function deallocates a memory stack and its associated guard regions using the `munmap` system call.
- **Inputs**:
    - `_stack`: A pointer to the memory stack to be deallocated.
- **Control Flow**:
    - Check if the `_stack` pointer is null and return immediately if it is.
    - Cast the `_stack` pointer to an `uchar` pointer and calculate the addresses for the lower and upper guard regions.
    - Attempt to unmap the upper guard region using `munmap` and log a warning if it fails.
    - Attempt to unmap the lower guard region using `munmap` and log a warning if it fails.
    - Attempt to unmap the main stack region using `munmap` and log a warning if it fails.
- **Output**: The function does not return any value.


---
### fd\_tile\_id0<!-- {{#callable:fd_tile_id0}} -->
The function `fd_tile_id0` returns the value of the static variable `fd_tile_private_id0`.
- **Inputs**: None
- **Control Flow**:
    - The function is a simple getter function that directly returns the value of the static variable `fd_tile_private_id0`.
- **Output**: The function returns an unsigned long integer (`ulong`) which is the value of `fd_tile_private_id0`.


---
### fd\_tile\_id1<!-- {{#callable:fd_tile_id1}} -->
The function `fd_tile_id1` returns the value of the private variable `fd_tile_private_id1`.
- **Inputs**: None
- **Control Flow**:
    - The function is defined to return an unsigned long integer (`ulong`).
    - It directly returns the value of the variable `fd_tile_private_id1`.
- **Output**: The function returns an unsigned long integer representing the value of `fd_tile_private_id1`.


---
### fd\_tile\_cnt<!-- {{#callable:fd_tile_cnt}} -->
The `fd_tile_cnt` function returns the current count of tiles initialized in the system.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of the global variable `fd_tile_private_cnt`.
- **Output**: The function outputs an unsigned long integer representing the number of tiles.


---
### fd\_tile\_id<!-- {{#callable:fd_tile_id}} -->
The `fd_tile_id` function returns the current thread's tile identifier.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of the global variable `fd_tile_private_id`.
- **Output**: The function outputs an unsigned long integer representing the tile ID of the current thread.


---
### fd\_tile\_idx<!-- {{#callable:fd_tile_idx}} -->
The `fd_tile_idx` function returns the current tile index from a thread-local variable.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of the thread-local variable `fd_tile_private_idx`.
- **Output**: The function outputs an unsigned long integer representing the current tile index.


---
### fd\_tile\_cpu\_id<!-- {{#callable:fd_tile_cpu_id}} -->
The `fd_tile_cpu_id` function retrieves the CPU ID associated with a given tile index, ensuring it is within valid bounds and returning a special value if not.
- **Inputs**:
    - `tile_idx`: An unsigned long integer representing the index of the tile for which the CPU ID is requested.
- **Control Flow**:
    - Check if the provided `tile_idx` is greater than or equal to `fd_tile_private_cnt`; if so, return `ULONG_MAX` to indicate an invalid index.
    - Retrieve the CPU ID from the `fd_tile_private_cpu_id` array using the `tile_idx`.
    - Use the `fd_ulong_if` function to return the CPU ID if it is less than 65535, otherwise return `ULONG_MAX-1` to indicate a special case.
- **Output**: Returns an unsigned long integer representing the CPU ID associated with the given tile index, or a special value if the index is invalid or the CPU ID is out of bounds.


---
### fd\_tile\_private\_manager<!-- {{#callable:fd_tile_private_manager}} -->
The `fd_tile_private_manager` function manages a tile's lifecycle, including setting CPU affinity, configuring the stack, and executing tasks in a loop until halted.
- **Inputs**:
    - `_args`: A pointer to `fd_tile_private_manager_args_t` structure containing the tile's ID, index, CPU index, stack information, and a pointer to the tile structure.
- **Control Flow**:
    - Cast `_args` to `fd_tile_private_manager_args_t` pointer to access tile parameters.
    - If not using GLIBC and CPU index is valid, set CPU affinity for the thread to the specified CPU index.
    - Set the thread name using `prctl` to identify the tile by its index.
    - Validate thread identifiers to ensure they match expected values, logging an error if not.
    - Initialize a `fd_tile_private_t` structure to represent the tile's state and configuration.
    - Set the tile's state to `BOOT`, configure the stack, and transition to `IDLE` state.
    - If a user-provided stack is available, set it up and prevent it from being affected by `fork()` using `madvise`.
    - If no user-provided stack, discover stack extents using `fd_log_private_stack_discover`.
    - Configure CPU settings for the tile using [`fd_tile_private_cpu_config`](#fd_tile_private_cpu_config).
    - Log the successful boot of the tile and set its state to `IDLE`.
    - Enter an infinite loop to manage the tile's task execution lifecycle.
    - Check the tile's state; if `EXEC`, execute the assigned task and handle exceptions, then transition back to `IDLE`.
    - If the state is not `EXEC` or `IDLE`, break the loop, indicating a halt.
    - Log the halting of the tile and reset its state to `BOOT`.
- **Output**: Returns the stack pointer, which may be user-provided or discovered, after the tile has been halted and reset.
- **Functions called**:
    - [`fd_cpuset_setaffinity`](fd_tile.c.driver.md#fd_cpuset_setaffinity)
    - [`fd_tile_private_cpu_config`](#fd_tile_private_cpu_config)


---
### fd\_tile\_private\_trylock<!-- {{#callable:fd_tile_private_trylock}} -->
The `fd_tile_private_trylock` function attempts to acquire a lock on a tile at a given index and returns the tile if successful, or NULL if not.
- **Inputs**:
    - `tile_idx`: An unsigned long integer representing the index of the tile to attempt to lock.
- **Control Flow**:
    - A volatile pointer to the lock of the tile at the specified index is obtained.
    - The current tile at the lock is retrieved.
    - A check is performed to see if the tile is non-NULL and if an atomic compare-and-swap operation can set the lock to NULL, indicating a successful lock acquisition.
    - If both conditions are met, the tile is returned.
    - If the conditions are not met, NULL is returned.
- **Output**: Returns a pointer to the `fd_tile_private_t` structure if the lock is successfully acquired, otherwise returns NULL.


---
### fd\_tile\_private\_lock<!-- {{#callable:fd_tile_private_lock}} -->
The `fd_tile_private_lock` function attempts to acquire a lock on a tile by atomically setting its lock pointer to NULL, effectively locking it for exclusive access.
- **Inputs**:
    - `tile_idx`: An unsigned long integer representing the index of the tile to be locked.
- **Control Flow**:
    - Declare a volatile pointer `vtile` to the lock of the tile at the given index.
    - Enter an infinite loop to repeatedly attempt to lock the tile.
    - Retrieve the current value of the tile pointer `tile` from `vtile`.
    - Check if `tile` is non-null and if an atomic compare-and-swap operation on `vtile` successfully sets it to NULL.
    - If both conditions are met, break out of the loop, indicating the tile is successfully locked.
    - If not, pause briefly using `FD_SPIN_PAUSE()` to reduce CPU usage before retrying.
- **Output**: Returns a pointer to the `fd_tile_private_t` structure representing the locked tile.


---
### fd\_tile\_private\_unlock<!-- {{#callable:fd_tile_private_unlock}} -->
The `fd_tile_private_unlock` function releases a lock on a tile by setting the lock to the provided tile pointer.
- **Inputs**:
    - `tile_idx`: An unsigned long integer representing the index of the tile to unlock.
    - `tile`: A pointer to an `fd_tile_private_t` structure representing the tile to be set as the lock.
- **Control Flow**:
    - The function directly sets the lock of the tile at the specified index in the `fd_tile_private` array to the provided tile pointer.
    - It uses the `FD_VOLATILE` macro to ensure the operation is performed with volatile semantics, which is important for multi-threaded environments.
- **Output**: The function does not return any value.


---
### fd\_tile\_exec\_new<!-- {{#callable:fd_tile_exec_new}} -->
The `fd_tile_exec_new` function attempts to dispatch a task to a specified tile, setting up the task's arguments and state if the tile is available and valid.
- **Inputs**:
    - `idx`: The index of the tile to which the task should be dispatched.
    - `task`: A function pointer representing the task to be executed on the tile.
    - `argc`: The number of arguments to be passed to the task.
    - `argv`: An array of argument strings to be passed to the task.
- **Control Flow**:
    - Check if the tile index is invalid (either the current tile or tile 0) and return NULL if so.
    - Attempt to lock the specified tile using [`fd_tile_private_trylock`](#fd_tile_private_trylock); return NULL if the tile is unavailable.
    - Set the tile's `argc`, `argv`, and `task` fields to the provided values, ensuring memory visibility with `FD_COMPILER_MFENCE`.
    - Change the tile's state to `FD_TILE_PRIVATE_STATE_EXEC` to indicate it is ready to execute the task.
    - Return a pointer to the tile cast as `fd_tile_exec_t *`.
- **Output**: A pointer to `fd_tile_exec_t` representing the tile if successful, or NULL if the tile is unavailable or invalid.
- **Functions called**:
    - [`fd_tile_private_trylock`](#fd_tile_private_trylock)


---
### fd\_tile\_exec\_delete<!-- {{#callable:fd_tile_exec_delete}} -->
The `fd_tile_exec_delete` function waits for a tile to become idle, retrieves the execution result if requested, and releases the lock on the tile.
- **Inputs**:
    - `exec`: A pointer to an `fd_tile_exec_t` structure representing the tile execution context to be deleted.
    - `opt_ret`: An optional pointer to an integer where the function will store the return value of the tile's last executed task, if available.
- **Control Flow**:
    - Cast the `exec` pointer to a `fd_tile_private_t` pointer to access the tile's private data.
    - Retrieve the tile index from the tile's private data.
    - Enter a loop to wait until the tile's state becomes `FD_TILE_PRIVATE_STATE_IDLE`.
    - Once the tile is idle, retrieve the failure message from the tile's private data.
    - If there is no failure message and `opt_ret` is not null, store the tile's return value in `opt_ret`.
    - Unlock the tile using its index and private data.
- **Output**: Returns a constant character pointer to a failure message if the tile execution failed, or `NULL` if it succeeded.
- **Functions called**:
    - [`fd_tile_private_unlock`](#fd_tile_private_unlock)


---
### fd\_tile\_exec<!-- {{#callable:fd_tile_exec}} -->
The `fd_tile_exec` function retrieves a pointer to the tile execution structure for a given tile index.
- **Inputs**:
    - `tile_idx`: An unsigned long integer representing the index of the tile whose execution structure is to be retrieved.
- **Control Flow**:
    - The function accesses the global array `fd_tile_private` using the provided `tile_idx` to retrieve the `tile` member.
    - It casts the `tile` member to a `fd_tile_exec_t *` type and returns it.
- **Output**: A pointer to the `fd_tile_exec_t` structure associated with the specified tile index.


---
### fd\_tile\_exec\_id<!-- {{#callable:fd_tile_exec_id}} -->
The `fd_tile_exec_id` function retrieves the unique identifier of a tile execution context from a given `fd_tile_exec_t` pointer.
- **Inputs**:
    - `exec`: A pointer to a `fd_tile_exec_t` structure representing the tile execution context.
- **Control Flow**:
    - The function casts the input `exec` pointer to a `fd_tile_private_t` pointer.
    - It accesses the `id` field of the `fd_tile_private_t` structure.
    - The function returns the value of the `id` field.
- **Output**: The function returns an `ulong` representing the unique identifier of the tile execution context.


---
### fd\_tile\_exec\_idx<!-- {{#callable:fd_tile_exec_idx}} -->
The `fd_tile_exec_idx` function retrieves the index of a tile execution from a given `fd_tile_exec_t` pointer.
- **Inputs**:
    - `exec`: A pointer to a `fd_tile_exec_t` structure, which represents a tile execution.
- **Control Flow**:
    - The function casts the `exec` pointer to a `fd_tile_private_t` pointer.
    - It accesses the `idx` member of the `fd_tile_private_t` structure.
    - The function returns the value of the `idx` member.
- **Output**: The function returns an `ulong` representing the index of the tile execution.


---
### fd\_tile\_exec\_task<!-- {{#callable:fd_tile_exec_task}} -->
The `fd_tile_exec_task` function retrieves the task associated with a given tile execution context.
- **Inputs**:
    - `exec`: A pointer to a `fd_tile_exec_t` structure representing the tile execution context.
- **Control Flow**:
    - The function casts the `exec` pointer to a `fd_tile_private_t` pointer.
    - It accesses the `task` member of the `fd_tile_private_t` structure.
    - The function returns the value of the `task` member.
- **Output**: The function returns a `fd_tile_task_t`, which is the task associated with the given tile execution context.


---
### fd\_tile\_exec\_argc<!-- {{#callable:fd_tile_exec_argc}} -->
The `fd_tile_exec_argc` function retrieves the argument count (`argc`) from a given `fd_tile_exec_t` execution context.
- **Inputs**:
    - `exec`: A pointer to a constant `fd_tile_exec_t` structure representing the execution context from which the argument count is to be retrieved.
- **Control Flow**:
    - The function casts the `exec` pointer to a `fd_tile_private_t` pointer.
    - It accesses the `argc` member of the `fd_tile_private_t` structure.
    - The function returns the value of the `argc` member.
- **Output**: The function returns an integer representing the number of arguments (`argc`) associated with the given execution context.


---
### fd\_tile\_exec\_argv<!-- {{#callable:fd_tile_exec_argv}} -->
The `fd_tile_exec_argv` function retrieves the argument vector (`argv`) from a given `fd_tile_exec_t` execution context.
- **Inputs**:
    - `exec`: A pointer to a constant `fd_tile_exec_t` structure representing the execution context from which to retrieve the argument vector.
- **Control Flow**:
    - The function casts the `exec` pointer to a `fd_tile_private_t` constant pointer.
    - It then accesses the `argv` member of the `fd_tile_private_t` structure and returns it.
- **Output**: A pointer to a character array (`char **`) representing the argument vector (`argv`) associated with the given execution context.


---
### fd\_tile\_exec\_done<!-- {{#callable:fd_tile_exec_done}} -->
The `fd_tile_exec_done` function checks if a tile execution is complete by verifying if the tile's state is idle.
- **Inputs**:
    - `exec`: A pointer to a `fd_tile_exec_t` structure representing the tile execution context to be checked.
- **Control Flow**:
    - Cast the `exec` pointer to a `fd_tile_private_t` pointer named `tile`.
    - Return the result of comparing the volatile state of `tile` to `FD_TILE_PRIVATE_STATE_IDLE`.
- **Output**: An integer value indicating whether the tile's state is idle (1 if idle, 0 otherwise).


---
### fd\_tile\_private\_cpus\_parse<!-- {{#callable:fd_tile_private_cpus_parse}} -->
The `fd_tile_private_cpus_parse` function parses a string representing CPU tile assignments and populates an array with the corresponding CPU indices for each tile.
- **Inputs**:
    - `cstr`: A constant character pointer representing the input string that specifies CPU tile assignments.
    - `tile_to_cpu`: A pointer to an array of unsigned short integers where the parsed CPU indices for each tile will be stored.
- **Control Flow**:
    - Check if the input string `cstr` is null and return 0 if it is.
    - Initialize a counter `cnt` to 0 and declare a CPU set `assigned_set` to track assigned CPUs.
    - Iterate over the input string, skipping whitespace and processing each segment of the string.
    - If a segment starts with 'f', parse it as a request for floating tiles and update `tile_to_cpu` with 65535 for each floating tile.
    - If a segment starts with a digit, parse it as a CPU range or single CPU, handling optional stride values, and update `tile_to_cpu` with the parsed CPU indices.
    - Check for errors such as malformed input, invalid ranges, or repeated CPUs, and log errors if any are found.
    - Continue parsing until the end of the string is reached or an error is encountered.
- **Output**: Returns the number of CPU indices successfully parsed and stored in the `tile_to_cpu` array.


---
### fd\_tile\_private\_map\_boot<!-- {{#callable:fd_tile_private_map_boot}} -->
The `fd_tile_private_map_boot` function initializes and boots a group of threads (tiles) on specified CPUs, setting up their execution environment and managing their resources.
- **Inputs**:
    - `tile_to_cpu`: A pointer to an array of unsigned short integers mapping each tile to a specific CPU index.
    - `tile_cnt`: An unsigned long integer representing the number of tiles to be booted.
- **Control Flow**:
    - Initialize global variables `fd_tile_private_id0`, `fd_tile_private_id1`, and `fd_tile_private_cnt` with the current thread ID and tile count.
    - Log the start of the booting process for the thread group.
    - Iterate over tiles from index 1 to `tile_cnt-1` to set up each tile's execution environment.
    - For each tile, determine if it is fixed to a specific CPU or floating, and log the booting process.
    - Initialize thread attributes and set CPU affinity if the tile is fixed to a specific CPU (GNU-specific).
    - Create an optimized stack for the tile if possible, otherwise fall back to a default stack, and log any issues.
    - Initialize and set up the tile's manager arguments, then create a new thread for the tile using `pthread_create`.
    - Wait for the tile to be ready to execute by polling its state.
    - Destroy the thread attributes after the tile is ready.
    - Boot tile 0 separately, checking and setting its CPU affinity, and log any issues.
    - Set up the execution environment for tile 0, including stack discovery and CPU configuration.
    - Log the successful booting of all tiles and copy the CPU mapping to a global array.
- **Output**: The function does not return a value; it sets up the execution environment for a group of threads (tiles) and logs the booting process.
- **Functions called**:
    - [`fd_tile_private_stack_new`](#fd_tile_private_stack_new)
    - [`fd_tile_private_stack_delete`](#fd_tile_private_stack_delete)
    - [`fd_cpuset_getaffinity`](fd_tile.c.driver.md#fd_cpuset_getaffinity)
    - [`fd_cpuset_setaffinity`](fd_tile.c.driver.md#fd_cpuset_setaffinity)
    - [`fd_tile_private_cpu_config`](#fd_tile_private_cpu_config)


---
### fd\_tile\_private\_boot\_str<!-- {{#callable:fd_tile_private_boot_str}} -->
The `fd_tile_private_boot_str` function initializes the tile-to-CPU mapping and boots the tile system based on the provided CPU configuration string.
- **Inputs**:
    - `cpus`: A constant character pointer representing a string that specifies the CPU configuration for the tiles.
- **Control Flow**:
    - Declare an array `tile_to_cpu` to store the mapping of tiles to CPUs.
    - Call [`fd_tile_private_cpus_parse`](#fd_tile_private_cpus_parse) with `cpus` to fill `tile_to_cpu` and get the count of tiles `tile_cnt`.
    - Check if `tile_cnt` is zero, indicating no CPUs were specified; if so, log a message and set `tile_to_cpu[0]` to 65535 and `tile_cnt` to 1.
    - Call [`fd_tile_private_map_boot`](#fd_tile_private_map_boot) with `tile_to_cpu` and `tile_cnt` to boot the tile system.
- **Output**: This function does not return a value; it performs initialization and configuration of the tile system.
- **Functions called**:
    - [`fd_tile_private_cpus_parse`](#fd_tile_private_cpus_parse)
    - [`fd_tile_private_map_boot`](#fd_tile_private_map_boot)


---
### fd\_tile\_private\_boot<!-- {{#callable:fd_tile_private_boot}} -->
The `fd_tile_private_boot` function initializes the tile configuration by extracting CPU settings from command line arguments and booting the tile system accordingly.
- **Inputs**:
    - `pargc`: A pointer to an integer representing the number of command line arguments.
    - `pargv`: A pointer to an array of strings representing the command line arguments.
- **Control Flow**:
    - The function calls `fd_env_strip_cmdline_cstr` to extract the `--tile-cpus` configuration from the command line arguments or environment variables.
    - If the `--tile-cpus` configuration is not specified, it logs an informational message indicating this.
    - If the `--tile-cpus` configuration is specified, it logs the configuration value.
    - The function then calls [`fd_tile_private_boot_str`](#fd_tile_private_boot_str) with the extracted CPU configuration string to initialize the tile system.
- **Output**: This function does not return any value; it performs initialization and logging operations.
- **Functions called**:
    - [`fd_tile_private_boot_str`](#fd_tile_private_boot_str)


---
### fd\_tile\_private\_halt<!-- {{#callable:fd_tile_private_halt}} -->
The `fd_tile_private_halt` function halts all tiles in a multi-threaded environment, ensuring all tasks are completed and resources are cleaned up.
- **Inputs**: None
- **Control Flow**:
    - Log the start of the halt process.
    - Clear the CPU ID array for all tiles.
    - Determine the number of tiles to halt.
    - Lock each tile (except tile 0) to prevent further dispatches.
    - Wait for all tasks on each tile to complete by checking their state until they are idle.
    - Signal all tiles to transition to the halt state.
    - Wait for each tile to halt by joining their threads and cleaning up their stacks.
    - Restore the CPU configuration to its previous state.
    - Log the successful halt of tile 0.
    - Unlock all tiles and reset various internal state variables to zero.
    - Log the successful completion of the halt process.
- **Output**: The function does not return any value.
- **Functions called**:
    - [`fd_tile_private_lock`](#fd_tile_private_lock)
    - [`fd_tile_private_stack_delete`](#fd_tile_private_stack_delete)
    - [`fd_tile_private_cpu_restore`](#fd_tile_private_cpu_restore)
    - [`fd_tile_private_unlock`](#fd_tile_private_unlock)



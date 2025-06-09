# Purpose
This C header file, `fd_tile.h`, is part of a module designed to facilitate the fast dispatching and execution of tasks within a thread group, referred to as "tiles." It provides a set of APIs for managing and executing tasks on these tiles, which are essentially threads within a group. The file defines several key components, including a maximum number of tiles (`FD_TILE_MAX`), a function pointer type for tasks (`fd_tile_task_t`), and an opaque handle for tile execution (`fd_tile_exec_t`). The header also includes functions to retrieve information about the tiles, such as their IDs and CPU bindings, and to manage the execution of tasks on these tiles.

The file is structured to support parallel execution by allowing tasks to be dispatched to specific tiles, with functions to start ([`fd_tile_exec_new`](#fd_tile_exec_new)), monitor ([`fd_tile_exec_done`](#fd_tile_exec_done)), and terminate ([`fd_tile_exec_delete`](#fd_tile_exec_delete)) these tasks. It also includes diagnostic functions for stack management, which are useful for debugging and optimizing stack usage. The header is intended to be included in other C source files, providing a public API for managing thread-based task execution. The functions are designed to be used in a multi-threaded environment, with considerations for stack size and CPU affinity, making it a specialized utility for high-performance computing scenarios where task dispatching and execution efficiency are critical.
# Imports and Dependencies

---
- `../shmem/fd_shmem.h`


# Global Variables

---
### fd\_tile\_private\_stack0
- **Type**: `ulong`
- **Description**: `fd_tile_private_stack0` is a global variable of type `ulong` that represents the starting address of the stack for tile 0 in a thread group. It is used in conjunction with `fd_tile_private_stack1` to define the stack boundaries for tile 0.
- **Use**: This variable is used to determine the lower boundary of the stack memory region for tile 0, aiding in stack diagnostics and management.


---
### fd\_tile\_private\_stack1
- **Type**: `FD_TL ulong`
- **Description**: `fd_tile_private_stack1` is a global variable representing the upper boundary of the stack memory region for a tile in a thread group. It is used to determine the size and boundaries of the stack allocated for tile execution.
- **Use**: This variable is used to calculate the stack size and to provide diagnostics for stack usage in tile-based parallel execution.


---
### fd\_tile\_exec\_new
- **Type**: `fd_tile_exec_t *`
- **Description**: The `fd_tile_exec_new` function is a global function that initiates the parallel execution of a task on a specified tile within a thread group. It returns a handle of type `fd_tile_exec_t *`, which is an opaque handle representing the execution context of the task on the tile.
- **Use**: This function is used to start a task on a specific tile, returning a handle to manage the execution.


---
### fd\_tile\_exec\_delete
- **Type**: `function`
- **Description**: The `fd_tile_exec_delete` function is responsible for deleting a given tile execution (`exec`) and blocking the caller if necessary until the execution is complete. It returns a constant character pointer which is NULL if the execution terminated normally, or an infinite lifetime C string if the execution terminated abnormally.
- **Use**: This function is used to clean up and finalize a tile execution, ensuring that resources are properly released and any return values are captured if the execution completed successfully.


---
### fd\_tile\_exec\_argv
- **Type**: `char **`
- **Description**: The `fd_tile_exec_argv` function returns a pointer to an array of character strings (char **), which represents the argument vector (argv) for a tile execution context. This is part of the tile execution management system, where each tile can execute tasks with specific command-line-like arguments.
- **Use**: This variable is used to access the argument vector of a tile execution, allowing retrieval of command-line arguments passed to a task running on a tile.


# Data Structures

---
### fd\_tile\_exec\_t
- **Type**: `typedef struct fd_tile_exec_private fd_tile_exec_t;`
- **Members**:
    - `fd_tile_exec_private`: An opaque structure representing the private details of a tile execution.
- **Description**: The `fd_tile_exec_t` is an opaque data structure used as a handle for managing the execution of tasks on a tile within a thread group. It abstracts the details of task execution, allowing users to start, manage, and terminate tasks dispatched to specific tiles. The structure is defined as a typedef of `struct fd_tile_exec_private`, indicating that its internal implementation details are hidden from the user, promoting encapsulation and modularity in task management.


# Functions

---
### fd\_tile\_stack0<!-- {{#callable:fd_tile_stack0}} -->
The `fd_tile_stack0` function returns a pointer to the start of the stack for tile 0 in the caller's local address space.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as an inline function, which suggests it is intended to be expanded in place where it is called, rather than being invoked as a normal function call.
    - The function simply returns a casted pointer to `fd_tile_private_stack0`, which is presumably a global variable representing the start of the stack for tile 0.
- **Output**: A `void const *` pointer to the start of the stack for tile 0.


---
### fd\_tile\_stack1<!-- {{#callable:fd_tile_stack1}} -->
The `fd_tile_stack1` function returns a pointer to the end of the stack for the current tile.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as an inline function, which suggests it is intended to be small and frequently used.
    - It returns a casted pointer to `fd_tile_private_stack1`, which represents the end of the stack for the current tile.
- **Output**: A `void const *` pointer to the end of the stack for the current tile.


---
### fd\_tile\_stack\_sz<!-- {{#callable:fd_tile_stack_sz}} -->
The `fd_tile_stack_sz` function calculates the size of the stack for a tile by subtracting the starting address from the ending address of the stack.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as an inline function, which suggests it is intended to be small and frequently used.
    - It returns the difference between `fd_tile_private_stack1` and `fd_tile_private_stack0`, which represent the end and start addresses of the stack, respectively.
- **Output**: The function returns an `ulong` representing the size of the stack in bytes.


---
### fd\_tile\_stack\_est\_used<!-- {{#callable:fd_tile_stack_est_used}} -->
The `fd_tile_stack_est_used` function estimates the number of bytes currently used in the stack of the calling tile.
- **Inputs**: None
- **Control Flow**:
    - Declare a local array `stack_mem` of size 1 to ensure it is allocated on the stack.
    - Assign the value 1 to `stack_mem[0]` using the `FD_VOLATILE` macro to ensure the memory is actually used and not optimized away.
    - Return the result of `fd_ulong_if`, which checks if `fd_tile_private_stack1` is non-zero and calculates the difference between `fd_tile_private_stack1` and the address of `stack_mem` if true, otherwise returns 0.
- **Output**: The function returns an `ulong` representing the estimated number of bytes used in the stack.


---
### fd\_tile\_stack\_est\_free<!-- {{#callable:fd_tile_stack_est_free}} -->
The `fd_tile_stack_est_free` function estimates the amount of free stack memory available for the current tile by calculating the difference between the current stack pointer and the start of the stack.
- **Inputs**: None
- **Control Flow**:
    - Declare a local array `stack_mem` of size 1 to ensure a stack allocation.
    - Assign a volatile value to `stack_mem[0]` to ensure it is backed by memory and resides on the stack.
    - Use `fd_ulong_if` to check if `fd_tile_private_stack0` is non-zero.
    - If `fd_tile_private_stack0` is zero, return 0 as the free stack space cannot be determined.
    - If `fd_tile_private_stack0` is non-zero, calculate the difference between the address of `stack_mem` and `fd_tile_private_stack0` to estimate the free stack space.
- **Output**: The function returns an `ulong` representing the estimated number of free bytes in the stack for the current tile.


---
### fd\_tile\_exec\_by\_id\_new<!-- {{#callable:fd_tile_exec_by_id_new}} -->
The `fd_tile_exec_by_id_new` function initiates the execution of a task on a specified tile by its application thread index.
- **Inputs**:
    - `id`: An unsigned long representing the application thread index, which should be within the range [fd_tile_id0(), fd_tile_id1()).
    - `task`: A non-NULL function pointer of type `fd_tile_task_t` representing the task to be executed.
    - `argc`: An integer representing the number of arguments passed to the task.
    - `argv`: An array of character pointers representing the arguments to be passed to the task.
- **Control Flow**:
    - The function calculates the tile index by subtracting `fd_tile_id0()` from the provided `id`.
    - It then calls `fd_tile_exec_new` with the calculated tile index, the task, argc, and argv to start the task execution on the specified tile.
- **Output**: Returns a pointer to `fd_tile_exec_t`, which is a handle for the execution of the task on the specified tile, or NULL if the execution could not be initiated.


---
### fd\_tile\_exec\_by\_id<!-- {{#callable:fd_tile_exec_by_id}} -->
The `fd_tile_exec_by_id` function retrieves the execution handle for a tile specified by its application thread index.
- **Inputs**:
    - `tile_id`: The application thread index of the tile for which the execution handle is to be retrieved.
- **Control Flow**:
    - The function calculates the tile index by subtracting the base tile ID (`fd_tile_id0()`) from the given `tile_id`.
    - It then calls `fd_tile_exec` with the calculated tile index to retrieve the execution handle.
- **Output**: A pointer to `fd_tile_exec_t`, which is the execution handle for the specified tile.


# Function Declarations (Public API)

---
### fd\_tile\_exec\_id<!-- {{#callable_declaration:fd_tile_exec_id}} -->
Retrieve the unique identifier of a tile execution.
- **Description**: Use this function to obtain the unique identifier associated with a specific tile execution. This identifier is constant and valid for the duration of the execution. It is essential to ensure that the `exec` parameter points to a valid and current execution context before calling this function. This function is typically used in scenarios where you need to track or manage specific executions within a thread group.
- **Inputs**:
    - `exec`: A pointer to a `fd_tile_exec_t` structure representing the tile execution. This must not be null and should point to a valid, current execution context. Passing an invalid or null pointer results in undefined behavior.
- **Output**: Returns an unsigned long representing the unique identifier of the specified tile execution.
- **See also**: [`fd_tile_exec_id`](fd_tile_threads.cxx.driver.md#fd_tile_exec_id)  (Implementation)


---
### fd\_tile\_private\_map\_boot<!-- {{#callable_declaration:fd_tile_private_map_boot}} -->
Boots a thread group with specified CPU mappings.
- **Description**: This function initializes and boots a group of threads, referred to as tiles, within a thread group, mapping each tile to a specific CPU as specified by the caller. It should be called when setting up a thread group to ensure that each tile is correctly associated with a CPU, which can enhance performance by optimizing CPU affinity and stack usage. The function logs the booting process and handles errors related to thread creation and CPU affinity settings. It is important to ensure that the system is properly configured to allow the specified CPU mappings and that the function is called in an environment where the fd library is already booted.
- **Inputs**:
    - `tile_to_cpu`: An array of unsigned short integers where each element specifies the CPU index to which the corresponding tile should be mapped. The array must have at least 'tile_cnt' elements, and the values should be valid CPU indices or a special value indicating a floating tile. The caller retains ownership of this array.
    - `tile_cnt`: The number of tiles to boot, specified as an unsigned long integer. It must be greater than zero and should not exceed the maximum number of tiles supported by the system (FD_TILE_MAX).
- **Output**: None
- **See also**: [`fd_tile_private_map_boot`](fd_tile_threads.cxx.driver.md#fd_tile_private_map_boot)  (Implementation)



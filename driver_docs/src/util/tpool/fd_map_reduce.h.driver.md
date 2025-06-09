# Purpose
The provided C code is a sophisticated implementation of a parallel processing framework designed to facilitate high-performance, deterministic parallel computations using a thread pool. The code defines a set of macros and inline functions that enable the creation and execution of map-reduce operations, which are commonly used in parallel computing to process large datasets efficiently. The framework is designed to mimic the behavior of CUDA-like kernels but operates entirely on the CPU, avoiding the overhead of data transfer between CPU and GPU. It achieves this by leveraging a thread pool to distribute work across multiple threads, optimizing for cache locality and scalability.

The core components of this framework include the `FD_MAP_REDUCE` and `FD_FOR_ALL` macros, which provide the structure for defining and executing parallel operations. The `FD_MAP_REDUCE` macro is used for operations that require both mapping and reduction phases, while `FD_FOR_ALL` is a special case for operations that only require mapping. The code also includes a series of private inline functions (`fd_map_reduce_private_*`) that handle the dispatch of tasks to the thread pool with varying numbers of arguments. The framework is designed to be included indirectly through a header file (`fd_tpool.h`), ensuring that it integrates seamlessly with other components of a larger software system. This code is intended for developers who need to implement high-performance parallel algorithms in C, providing a flexible and efficient way to manage concurrent execution.
# Functions

---
### fd\_map\_reduce\_private\_0<!-- {{#callable:fd_map_reduce_private_0}} -->
The function `fd_map_reduce_private_0` executes a task with a thread pool and a set of arguments, specifically passing three arguments to the task.
- **Inputs**:
    - `task`: A function pointer of type `fd_tpool_task_v2_t` that represents the task to be executed.
    - `tpool`: A pointer to `fd_tpool_t`, representing the thread pool to be used for executing the task.
    - `t0`: An unsigned long integer representing the starting index or thread ID for the task execution.
    - `t1`: An unsigned long integer representing the ending index or thread ID for the task execution.
    - `i0`: A long integer representing the starting index of a range to be processed by the task.
    - `i1`: A long integer representing the ending index of a range to be processed by the task.
- **Control Flow**:
    - Initialize an array `arg` of three unsigned long integers.
    - Assign `t1` to `arg[0]`, cast `i0` to `ulong` and assign to `arg[1]`, and cast `i1` to `ulong` and assign to `arg[2]`.
    - Invoke the `task` function with `tpool`, `t0`, the number of arguments (3UL), and the `arg` array.
- **Output**: The function does not return a value; it executes the provided task with the specified arguments.


---
### fd\_map\_reduce\_private\_1<!-- {{#callable:fd_map_reduce_private_1}} -->
The function `fd_map_reduce_private_1` prepares and executes a task with a thread pool by passing a set of arguments including a range and an additional parameter.
- **Inputs**:
    - `task`: A function pointer of type `fd_tpool_task_v2_t` that represents the task to be executed.
    - `tpool`: A pointer to a thread pool of type `fd_tpool_t` used to manage threads for executing the task.
    - `t0`: An unsigned long integer representing the starting index of the thread pool range.
    - `t1`: An unsigned long integer representing the ending index of the thread pool range.
    - `i0`: A long integer representing the starting index of the data range to be processed.
    - `i1`: A long integer representing the ending index of the data range to be processed.
    - `a0`: An unsigned long integer representing an additional argument to be passed to the task.
- **Control Flow**:
    - Initialize an array `arg` of size 4 to store arguments for the task.
    - Assign `t1` to `arg[0]`, cast `i0` to `ulong` and assign to `arg[1]`, cast `i1` to `ulong` and assign to `arg[2]`, and assign `a0` to `arg[3]`.
    - Invoke the `task` function with `tpool`, `t0`, the number of arguments (4UL), and the `arg` array.
- **Output**: The function does not return a value; it executes a task using the provided thread pool and arguments.


---
### fd\_map\_reduce\_private\_2<!-- {{#callable:fd_map_reduce_private_2}} -->
The `fd_map_reduce_private_2` function prepares and executes a task with a thread pool, passing specific arguments for processing.
- **Inputs**:
    - `task`: A function pointer of type `fd_tpool_task_v2_t` that represents the task to be executed.
    - `tpool`: A pointer to `fd_tpool_t`, representing the thread pool to be used for executing the task.
    - `t0`: An unsigned long integer representing the starting index or thread ID for the task.
    - `t1`: An unsigned long integer representing the ending index or thread ID for the task.
    - `i0`: A long integer representing the starting index of a range to be processed.
    - `i1`: A long integer representing the ending index of a range to be processed.
    - `a0`: An unsigned long integer representing the first additional argument to be passed to the task.
    - `a1`: An unsigned long integer representing the second additional argument to be passed to the task.
- **Control Flow**:
    - Initialize an array `arg` of 5 unsigned long integers.
    - Assign `t1` to `arg[0]`, cast `i0` to unsigned long and assign to `arg[1]`, cast `i1` to unsigned long and assign to `arg[2]`, assign `a0` to `arg[3]`, and assign `a1` to `arg[4]`.
    - Call the `task` function with `tpool`, `t0`, the number of arguments (5UL), and the `arg` array.
- **Output**: The function does not return a value; it executes a task with the provided arguments.


---
### fd\_map\_reduce\_private\_3<!-- {{#callable:fd_map_reduce_private_3}} -->
The `fd_map_reduce_private_3` function prepares and invokes a task with a thread pool and a set of arguments for parallel processing.
- **Inputs**:
    - `task`: A function pointer of type `fd_tpool_task_v2_t` representing the task to be executed.
    - `tpool`: A pointer to `fd_tpool_t`, representing the thread pool to be used for executing the task.
    - `t0`: An unsigned long integer representing the starting index of the thread pool range.
    - `t1`: An unsigned long integer representing the ending index of the thread pool range.
    - `i0`: A long integer representing the starting index of the data range to be processed.
    - `i1`: A long integer representing the ending index of the data range to be processed.
    - `a0`: An unsigned long integer representing the first additional argument to be passed to the task.
    - `a1`: An unsigned long integer representing the second additional argument to be passed to the task.
    - `a2`: An unsigned long integer representing the third additional argument to be passed to the task.
- **Control Flow**:
    - An array `arg` of 6 unsigned long integers is created to hold the arguments for the task.
    - The elements of `arg` are populated with `t1`, `i0`, `i1`, `a0`, `a1`, and `a2`, with `i0` and `i1` being cast to unsigned long integers.
    - The `task` function is called with `tpool`, `t0`, the number of arguments (6UL), and the `arg` array.
- **Output**: The function does not return a value; it executes the provided task with the specified arguments.


---
### fd\_map\_reduce\_private\_4<!-- {{#callable:fd_map_reduce_private_4}} -->
The function `fd_map_reduce_private_4` prepares an array of arguments and invokes a task function with these arguments and a thread pool.
- **Inputs**:
    - `task`: A function pointer of type `fd_tpool_task_v2_t` that represents the task to be executed.
    - `tpool`: A pointer to a thread pool of type `fd_tpool_t` used for task execution.
    - `t0`: An unsigned long integer representing the starting index of the thread pool range.
    - `t1`: An unsigned long integer representing the ending index of the thread pool range.
    - `i0`: A long integer representing the starting index of the data range to be processed.
    - `i1`: A long integer representing the ending index of the data range to be processed.
    - `a0`: An unsigned long integer representing the first additional argument to be passed to the task.
    - `a1`: An unsigned long integer representing the second additional argument to be passed to the task.
    - `a2`: An unsigned long integer representing the third additional argument to be passed to the task.
    - `a3`: An unsigned long integer representing the fourth additional argument to be passed to the task.
- **Control Flow**:
    - Initialize an array `arg` of size 7 to store the arguments for the task.
    - Assign `t1` to `arg[0]`, cast `i0` and `i1` to `ulong` and assign them to `arg[1]` and `arg[2]` respectively.
    - Assign `a0`, `a1`, `a2`, and `a3` to `arg[3]`, `arg[4]`, `arg[5]`, and `arg[6]` respectively.
    - Invoke the `task` function with `tpool`, `t0`, the number of arguments (7UL), and the `arg` array.
- **Output**: The function does not return a value; it executes a task using the provided thread pool and arguments.


---
### fd\_map\_reduce\_private\_5<!-- {{#callable:fd_map_reduce_private_5}} -->
The function `fd_map_reduce_private_5` prepares an array of arguments and invokes a task function with these arguments and a thread pool.
- **Inputs**:
    - `task`: A function pointer of type `fd_tpool_task_v2_t` that represents the task to be executed.
    - `tpool`: A pointer to a thread pool of type `fd_tpool_t`.
    - `t0`: An unsigned long integer representing the starting thread index.
    - `t1`: An unsigned long integer representing the ending thread index.
    - `i0`: A long integer representing the starting index for a range of elements.
    - `i1`: A long integer representing the ending index for a range of elements.
    - `a0`: An unsigned long integer representing the first additional argument to be passed to the task.
    - `a1`: An unsigned long integer representing the second additional argument to be passed to the task.
    - `a2`: An unsigned long integer representing the third additional argument to be passed to the task.
    - `a3`: An unsigned long integer representing the fourth additional argument to be passed to the task.
    - `a4`: An unsigned long integer representing the fifth additional argument to be passed to the task.
- **Control Flow**:
    - Initialize an array `arg` of 8 unsigned long integers.
    - Assign `t1` to `arg[0]`, cast `i0` and `i1` to unsigned long and assign them to `arg[1]` and `arg[2]` respectively.
    - Assign `a0`, `a1`, `a2`, `a3`, and `a4` to `arg[3]` through `arg[7]`.
    - Invoke the `task` function with `tpool`, `t0`, the number 8, and the `arg` array as arguments.
- **Output**: The function does not return any value; it executes a task with the provided arguments.


---
### fd\_map\_reduce\_private\_6<!-- {{#callable:fd_map_reduce_private_6}} -->
The function `fd_map_reduce_private_6` prepares an array of arguments and invokes a task function with these arguments and a thread pool.
- **Inputs**:
    - `task`: A function pointer of type `fd_tpool_task_v2_t` that represents the task to be executed.
    - `tpool`: A pointer to a thread pool of type `fd_tpool_t` used for task execution.
    - `t0`: An unsigned long integer representing the starting index of the thread pool range.
    - `t1`: An unsigned long integer representing the ending index of the thread pool range.
    - `i0`: A long integer representing the starting index of the data range to be processed.
    - `i1`: A long integer representing the ending index of the data range to be processed.
    - `a0`: An unsigned long integer representing the first additional argument to be passed to the task.
    - `a1`: An unsigned long integer representing the second additional argument to be passed to the task.
    - `a2`: An unsigned long integer representing the third additional argument to be passed to the task.
    - `a3`: An unsigned long integer representing the fourth additional argument to be passed to the task.
    - `a4`: An unsigned long integer representing the fifth additional argument to be passed to the task.
    - `a5`: An unsigned long integer representing the sixth additional argument to be passed to the task.
- **Control Flow**:
    - Initialize an array `arg` of 9 unsigned long integers.
    - Assign `t1` to `arg[0]`, cast `i0` and `i1` to unsigned long and assign them to `arg[1]` and `arg[2]` respectively.
    - Assign `a0` to `arg[3]`, `a1` to `arg[4]`, `a2` to `arg[5]`, `a3` to `arg[6]`, `a4` to `arg[7]`, and `a5` to `arg[8]`.
    - Invoke the `task` function with `tpool`, `t0`, the number of arguments (9UL), and the `arg` array.
- **Output**: The function does not return a value; it executes the provided task function with the specified arguments.


---
### fd\_map\_reduce\_private\_7<!-- {{#callable:fd_map_reduce_private_7}} -->
The function `fd_map_reduce_private_7` prepares and executes a task with a thread pool, passing a set of arguments including thread and index ranges, and additional parameters.
- **Inputs**:
    - `task`: A function pointer of type `fd_tpool_task_v2_t` representing the task to be executed.
    - `tpool`: A pointer to `fd_tpool_t`, representing the thread pool to be used for executing the task.
    - `t0`: An unsigned long representing the starting index of the thread range.
    - `t1`: An unsigned long representing the ending index of the thread range.
    - `i0`: A long integer representing the starting index of the data range.
    - `i1`: A long integer representing the ending index of the data range.
    - `a0`: An unsigned long representing the first additional argument to be passed to the task.
    - `a1`: An unsigned long representing the second additional argument to be passed to the task.
    - `a2`: An unsigned long representing the third additional argument to be passed to the task.
    - `a3`: An unsigned long representing the fourth additional argument to be passed to the task.
    - `a4`: An unsigned long representing the fifth additional argument to be passed to the task.
    - `a5`: An unsigned long representing the sixth additional argument to be passed to the task.
    - `a6`: An unsigned long representing the seventh additional argument to be passed to the task.
- **Control Flow**:
    - Initialize an array `arg` of 10 unsigned long elements.
    - Assign `t1` to `arg[0]`, cast `i0` and `i1` to unsigned long and assign to `arg[1]` and `arg[2]` respectively.
    - Assign `a0` to `arg[3]`, `a1` to `arg[4]`, `a2` to `arg[5]`, `a3` to `arg[6]`, `a4` to `arg[7]`, `a5` to `arg[8]`, and `a6` to `arg[9]`.
    - Call the `task` function with `tpool`, `t0`, the number of arguments (10UL), and the `arg` array.
- **Output**: The function does not return a value; it executes the provided task with the specified arguments.


---
### fd\_map\_reduce\_private\_8<!-- {{#callable:fd_map_reduce_private_8}} -->
The function `fd_map_reduce_private_8` prepares an array of arguments and invokes a task function with these arguments for parallel processing.
- **Inputs**:
    - `task`: A function pointer of type `fd_tpool_task_v2_t` that represents the task to be executed.
    - `tpool`: A pointer to a thread pool (`fd_tpool_t`) used for managing threads.
    - `t0`: An unsigned long integer representing the starting index of the thread pool range.
    - `t1`: An unsigned long integer representing the ending index of the thread pool range.
    - `i0`: A long integer representing the starting index of the data range to be processed.
    - `i1`: A long integer representing the ending index of the data range to be processed.
    - `a0`: An unsigned long integer representing the first additional argument to be passed to the task.
    - `a1`: An unsigned long integer representing the second additional argument to be passed to the task.
    - `a2`: An unsigned long integer representing the third additional argument to be passed to the task.
    - `a3`: An unsigned long integer representing the fourth additional argument to be passed to the task.
    - `a4`: An unsigned long integer representing the fifth additional argument to be passed to the task.
    - `a5`: An unsigned long integer representing the sixth additional argument to be passed to the task.
    - `a6`: An unsigned long integer representing the seventh additional argument to be passed to the task.
    - `a7`: An unsigned long integer representing the eighth additional argument to be passed to the task.
- **Control Flow**:
    - An array `arg` of 11 unsigned long integers is created.
    - The elements of `arg` are initialized with `t1`, `i0`, `i1`, and the additional arguments `a0` to `a7`.
    - The `task` function is called with `tpool`, `t0`, the number of arguments (11), and the `arg` array.
- **Output**: The function does not return a value; it executes the task function with the provided arguments.


---
### fd\_map\_reduce\_private\_9<!-- {{#callable:fd_map_reduce_private_9}} -->
The `fd_map_reduce_private_9` function prepares an array of arguments and invokes a task function with these arguments and a thread pool.
- **Inputs**:
    - `task`: A function pointer of type `fd_tpool_task_v2_t` that represents the task to be executed.
    - `tpool`: A pointer to a thread pool (`fd_tpool_t`) that manages the threads for executing the task.
    - `t0`: An unsigned long integer representing the starting index of the thread pool range.
    - `t1`: An unsigned long integer representing the ending index of the thread pool range.
    - `i0`: A long integer representing the starting index of the data range to be processed.
    - `i1`: A long integer representing the ending index of the data range to be processed.
    - `a0`: An unsigned long integer representing the first additional argument to be passed to the task.
    - `a1`: An unsigned long integer representing the second additional argument to be passed to the task.
    - `a2`: An unsigned long integer representing the third additional argument to be passed to the task.
    - `a3`: An unsigned long integer representing the fourth additional argument to be passed to the task.
    - `a4`: An unsigned long integer representing the fifth additional argument to be passed to the task.
    - `a5`: An unsigned long integer representing the sixth additional argument to be passed to the task.
    - `a6`: An unsigned long integer representing the seventh additional argument to be passed to the task.
    - `a7`: An unsigned long integer representing the eighth additional argument to be passed to the task.
    - `a8`: An unsigned long integer representing the ninth additional argument to be passed to the task.
- **Control Flow**:
    - Initialize an array `arg` of 12 unsigned long integers.
    - Assign `t1` to `arg[0]`, cast `i0` and `i1` to unsigned long and assign to `arg[1]` and `arg[2]` respectively.
    - Assign `a0` to `arg[3]`, `a1` to `arg[4]`, `a2` to `arg[5]`, `a3` to `arg[6]`, `a4` to `arg[7]`, `a5` to `arg[8]`, `a6` to `arg[9]`, `a7` to `arg[10]`, and `a8` to `arg[11]`.
    - Invoke the `task` function with `tpool`, `t0`, the number 12UL, and the `arg` array as arguments.
- **Output**: The function does not return a value; it executes a task using the provided thread pool and arguments.


---
### fd\_map\_reduce\_private\_10<!-- {{#callable:fd_map_reduce_private_10}} -->
The function `fd_map_reduce_private_10` prepares an array of arguments and invokes a task function with these arguments and a thread pool.
- **Inputs**:
    - `task`: A function pointer of type `fd_tpool_task_v2_t` that represents the task to be executed.
    - `tpool`: A pointer to a thread pool of type `fd_tpool_t` used for task execution.
    - `t0`: An unsigned long integer representing the starting index or thread ID for the task.
    - `t1`: An unsigned long integer representing the ending index or thread ID for the task.
    - `i0`: A long integer representing the starting index of a range to be processed.
    - `i1`: A long integer representing the ending index of a range to be processed.
    - `a0`: An unsigned long integer representing the first additional argument to be passed to the task.
    - `a1`: An unsigned long integer representing the second additional argument to be passed to the task.
    - `a2`: An unsigned long integer representing the third additional argument to be passed to the task.
    - `a3`: An unsigned long integer representing the fourth additional argument to be passed to the task.
    - `a4`: An unsigned long integer representing the fifth additional argument to be passed to the task.
    - `a5`: An unsigned long integer representing the sixth additional argument to be passed to the task.
    - `a6`: An unsigned long integer representing the seventh additional argument to be passed to the task.
    - `a7`: An unsigned long integer representing the eighth additional argument to be passed to the task.
    - `a8`: An unsigned long integer representing the ninth additional argument to be passed to the task.
    - `a9`: An unsigned long integer representing the tenth additional argument to be passed to the task.
- **Control Flow**:
    - Initialize an array `arg` of 13 unsigned long integers.
    - Assign `t1` to `arg[0]`, cast `i0` and `i1` to unsigned long and assign them to `arg[1]` and `arg[2]` respectively.
    - Assign the additional arguments `a0` to `a9` to `arg[3]` through `arg[12]`.
    - Invoke the `task` function with `tpool`, `t0`, the number of arguments (13UL), and the `arg` array.
- **Output**: The function does not return a value; it executes a task using the provided thread pool and arguments.


---
### fd\_map\_reduce\_private\_11<!-- {{#callable:fd_map_reduce_private_11}} -->
The `fd_map_reduce_private_11` function prepares an array of arguments and invokes a task function with these arguments and a thread pool.
- **Inputs**:
    - `task`: A function pointer of type `fd_tpool_task_v2_t` that represents the task to be executed.
    - `tpool`: A pointer to a thread pool of type `fd_tpool_t` used for task execution.
    - `t0`: An unsigned long integer representing the starting index of the thread pool range.
    - `t1`: An unsigned long integer representing the ending index of the thread pool range.
    - `i0`: A long integer representing the starting index of the data range to be processed.
    - `i1`: A long integer representing the ending index of the data range to be processed.
    - `a0`: An unsigned long integer representing the first additional argument to be passed to the task.
    - `a1`: An unsigned long integer representing the second additional argument to be passed to the task.
    - `a2`: An unsigned long integer representing the third additional argument to be passed to the task.
    - `a3`: An unsigned long integer representing the fourth additional argument to be passed to the task.
    - `a4`: An unsigned long integer representing the fifth additional argument to be passed to the task.
    - `a5`: An unsigned long integer representing the sixth additional argument to be passed to the task.
    - `a6`: An unsigned long integer representing the seventh additional argument to be passed to the task.
    - `a7`: An unsigned long integer representing the eighth additional argument to be passed to the task.
    - `a8`: An unsigned long integer representing the ninth additional argument to be passed to the task.
    - `a9`: An unsigned long integer representing the tenth additional argument to be passed to the task.
    - `a10`: An unsigned long integer representing the eleventh additional argument to be passed to the task.
- **Control Flow**:
    - Initialize an array `arg` of 14 unsigned long integers.
    - Assign `t1` to `arg[0]`, cast `i0` and `i1` to unsigned long and assign to `arg[1]` and `arg[2]` respectively.
    - Assign `a0` to `a10` to `arg[3]` to `arg[13]`.
    - Invoke the `task` function with `tpool`, `t0`, the number of arguments (14UL), and the `arg` array.
- **Output**: The function does not return a value; it executes a task with the provided arguments.


---
### fd\_map\_reduce\_private\_12<!-- {{#callable:fd_map_reduce_private_12}} -->
The function `fd_map_reduce_private_12` prepares an array of arguments and invokes a task function with these arguments and a thread pool.
- **Inputs**:
    - `task`: A function pointer of type `fd_tpool_task_v2_t` that represents the task to be executed.
    - `tpool`: A pointer to a thread pool of type `fd_tpool_t` used for task execution.
    - `t0`: An unsigned long integer representing the starting index of the thread pool range.
    - `t1`: An unsigned long integer representing the ending index of the thread pool range.
    - `i0`: A long integer representing the starting index of the data range to be processed.
    - `i1`: A long integer representing the ending index of the data range to be processed.
    - `a0`: An unsigned long integer representing the first additional argument to be passed to the task.
    - `a1`: An unsigned long integer representing the second additional argument to be passed to the task.
    - `a2`: An unsigned long integer representing the third additional argument to be passed to the task.
    - `a3`: An unsigned long integer representing the fourth additional argument to be passed to the task.
    - `a4`: An unsigned long integer representing the fifth additional argument to be passed to the task.
    - `a5`: An unsigned long integer representing the sixth additional argument to be passed to the task.
    - `a6`: An unsigned long integer representing the seventh additional argument to be passed to the task.
    - `a7`: An unsigned long integer representing the eighth additional argument to be passed to the task.
    - `a8`: An unsigned long integer representing the ninth additional argument to be passed to the task.
    - `a9`: An unsigned long integer representing the tenth additional argument to be passed to the task.
    - `a10`: An unsigned long integer representing the eleventh additional argument to be passed to the task.
    - `a11`: An unsigned long integer representing the twelfth additional argument to be passed to the task.
- **Control Flow**:
    - Initialize an array `arg` of 15 unsigned long integers.
    - Assign `t1` to `arg[0]`, cast `i0` and `i1` to unsigned long and assign to `arg[1]` and `arg[2]` respectively.
    - Assign `a0` to `a11` to `arg[3]` to `arg[14]`.
    - Invoke the `task` function with `tpool`, `t0`, the number of arguments (15UL), and the `arg` array.
- **Output**: The function does not return a value; it executes a task using the provided thread pool and arguments.


---
### fd\_map\_reduce\_private\_13<!-- {{#callable:fd_map_reduce_private_13}} -->
The `fd_map_reduce_private_13` function prepares an array of arguments and invokes a task function with these arguments and a thread pool.
- **Inputs**:
    - `task`: A function pointer of type `fd_tpool_task_v2_t` that represents the task to be executed.
    - `tpool`: A pointer to a thread pool of type `fd_tpool_t` used for task execution.
    - `t0`: An unsigned long integer representing the starting index of the thread pool range.
    - `t1`: An unsigned long integer representing the ending index of the thread pool range.
    - `i0`: A long integer representing the starting index of the range to be processed.
    - `i1`: A long integer representing the ending index of the range to be processed.
    - `a0`: An unsigned long integer representing the first additional argument to be passed to the task.
    - `a1`: An unsigned long integer representing the second additional argument to be passed to the task.
    - `a2`: An unsigned long integer representing the third additional argument to be passed to the task.
    - `a3`: An unsigned long integer representing the fourth additional argument to be passed to the task.
    - `a4`: An unsigned long integer representing the fifth additional argument to be passed to the task.
    - `a5`: An unsigned long integer representing the sixth additional argument to be passed to the task.
    - `a6`: An unsigned long integer representing the seventh additional argument to be passed to the task.
    - `a7`: An unsigned long integer representing the eighth additional argument to be passed to the task.
    - `a8`: An unsigned long integer representing the ninth additional argument to be passed to the task.
    - `a9`: An unsigned long integer representing the tenth additional argument to be passed to the task.
    - `a10`: An unsigned long integer representing the eleventh additional argument to be passed to the task.
    - `a11`: An unsigned long integer representing the twelfth additional argument to be passed to the task.
    - `a12`: An unsigned long integer representing the thirteenth additional argument to be passed to the task.
- **Control Flow**:
    - Initialize an array `arg` of 16 unsigned long integers.
    - Assign `t1` to `arg[0]`, cast `i0` and `i1` to unsigned long and assign them to `arg[1]` and `arg[2]` respectively.
    - Assign the additional arguments `a0` to `a12` to `arg[3]` through `arg[15]`.
    - Invoke the `task` function with `tpool`, `t0`, the number of arguments (16UL), and the `arg` array.
- **Output**: The function does not return a value; it executes a task using the provided thread pool and arguments.


---
### fd\_map\_reduce\_private\_14<!-- {{#callable:fd_map_reduce_private_14}} -->
The `fd_map_reduce_private_14` function prepares and executes a task with a thread pool, passing 14 additional arguments along with thread and index range information.
- **Inputs**:
    - `task`: A function pointer of type `fd_tpool_task_v2_t` representing the task to be executed.
    - `tpool`: A pointer to `fd_tpool_t`, representing the thread pool to be used for executing the task.
    - `t0`: An unsigned long representing the starting index of the thread pool range.
    - `t1`: An unsigned long representing the ending index of the thread pool range.
    - `i0`: A long integer representing the starting index of the data range to be processed.
    - `i1`: A long integer representing the ending index of the data range to be processed.
    - `a0`: An unsigned long representing the first additional argument to be passed to the task.
    - `a1`: An unsigned long representing the second additional argument to be passed to the task.
    - `a2`: An unsigned long representing the third additional argument to be passed to the task.
    - `a3`: An unsigned long representing the fourth additional argument to be passed to the task.
    - `a4`: An unsigned long representing the fifth additional argument to be passed to the task.
    - `a5`: An unsigned long representing the sixth additional argument to be passed to the task.
    - `a6`: An unsigned long representing the seventh additional argument to be passed to the task.
    - `a7`: An unsigned long representing the eighth additional argument to be passed to the task.
    - `a8`: An unsigned long representing the ninth additional argument to be passed to the task.
    - `a9`: An unsigned long representing the tenth additional argument to be passed to the task.
    - `a10`: An unsigned long representing the eleventh additional argument to be passed to the task.
    - `a11`: An unsigned long representing the twelfth additional argument to be passed to the task.
    - `a12`: An unsigned long representing the thirteenth additional argument to be passed to the task.
    - `a13`: An unsigned long representing the fourteenth additional argument to be passed to the task.
- **Control Flow**:
    - Initialize an array `arg` of 17 unsigned long elements.
    - Assign `t1` to `arg[0]`, cast `i0` and `i1` to unsigned long and assign to `arg[1]` and `arg[2]` respectively.
    - Assign the additional arguments `a0` to `a13` to `arg[3]` through `arg[16]`.
    - Invoke the `task` function with `tpool`, `t0`, the number of arguments (17UL), and the `arg` array.
- **Output**: The function does not return a value; it executes a task with the provided arguments.


---
### fd\_map\_reduce\_private\_15<!-- {{#callable:fd_map_reduce_private_15}} -->
The `fd_map_reduce_private_15` function prepares an array of arguments and invokes a task function with these arguments and a thread pool.
- **Inputs**:
    - `task`: A function pointer of type `fd_tpool_task_v2_t` that represents the task to be executed.
    - `tpool`: A pointer to a thread pool of type `fd_tpool_t` used for task execution.
    - `t0`: An unsigned long integer representing the starting index of the thread pool range.
    - `t1`: An unsigned long integer representing the ending index of the thread pool range.
    - `i0`: A long integer representing the starting index of the range to be processed.
    - `i1`: A long integer representing the ending index of the range to be processed.
    - `a0`: An unsigned long integer representing the first additional argument to be passed to the task.
    - `a1`: An unsigned long integer representing the second additional argument to be passed to the task.
    - `a2`: An unsigned long integer representing the third additional argument to be passed to the task.
    - `a3`: An unsigned long integer representing the fourth additional argument to be passed to the task.
    - `a4`: An unsigned long integer representing the fifth additional argument to be passed to the task.
    - `a5`: An unsigned long integer representing the sixth additional argument to be passed to the task.
    - `a6`: An unsigned long integer representing the seventh additional argument to be passed to the task.
    - `a7`: An unsigned long integer representing the eighth additional argument to be passed to the task.
    - `a8`: An unsigned long integer representing the ninth additional argument to be passed to the task.
    - `a9`: An unsigned long integer representing the tenth additional argument to be passed to the task.
    - `a10`: An unsigned long integer representing the eleventh additional argument to be passed to the task.
    - `a11`: An unsigned long integer representing the twelfth additional argument to be passed to the task.
    - `a12`: An unsigned long integer representing the thirteenth additional argument to be passed to the task.
    - `a13`: An unsigned long integer representing the fourteenth additional argument to be passed to the task.
    - `a14`: An unsigned long integer representing the fifteenth additional argument to be passed to the task.
- **Control Flow**:
    - Initialize an array `arg` of 18 unsigned long integers.
    - Assign `t1` to `arg[0]`, cast `i0` and `i1` to unsigned long and assign them to `arg[1]` and `arg[2]` respectively.
    - Assign the additional arguments `a0` to `a14` to `arg[3]` through `arg[17]`.
    - Invoke the `task` function with `tpool`, `t0`, the number of arguments (18UL), and the `arg` array.
- **Output**: The function does not return any value; it executes the provided task function with the specified arguments.


---
### fd\_map\_reduce\_private\_16<!-- {{#callable:fd_map_reduce_private_16}} -->
The `fd_map_reduce_private_16` function prepares and executes a task with a thread pool, passing 19 arguments to the task.
- **Inputs**:
    - `task`: A function pointer of type `fd_tpool_task_v2_t` that represents the task to be executed.
    - `tpool`: A pointer to `fd_tpool_t`, representing the thread pool to be used for executing the task.
    - `t0`: An unsigned long integer representing the starting index of the thread pool range.
    - `t1`: An unsigned long integer representing the ending index of the thread pool range.
    - `i0`: A long integer representing the starting index of the range to be processed.
    - `i1`: A long integer representing the ending index of the range to be processed.
    - `a0`: An unsigned long integer representing the first additional argument to be passed to the task.
    - `a1`: An unsigned long integer representing the second additional argument to be passed to the task.
    - `a2`: An unsigned long integer representing the third additional argument to be passed to the task.
    - `a3`: An unsigned long integer representing the fourth additional argument to be passed to the task.
    - `a4`: An unsigned long integer representing the fifth additional argument to be passed to the task.
    - `a5`: An unsigned long integer representing the sixth additional argument to be passed to the task.
    - `a6`: An unsigned long integer representing the seventh additional argument to be passed to the task.
    - `a7`: An unsigned long integer representing the eighth additional argument to be passed to the task.
    - `a8`: An unsigned long integer representing the ninth additional argument to be passed to the task.
    - `a9`: An unsigned long integer representing the tenth additional argument to be passed to the task.
    - `a10`: An unsigned long integer representing the eleventh additional argument to be passed to the task.
    - `a11`: An unsigned long integer representing the twelfth additional argument to be passed to the task.
    - `a12`: An unsigned long integer representing the thirteenth additional argument to be passed to the task.
    - `a13`: An unsigned long integer representing the fourteenth additional argument to be passed to the task.
    - `a14`: An unsigned long integer representing the fifteenth additional argument to be passed to the task.
    - `a15`: An unsigned long integer representing the sixteenth additional argument to be passed to the task.
- **Control Flow**:
    - Initialize an array `arg` of 19 unsigned long integers.
    - Assign `t1` to `arg[0]`, cast `i0` and `i1` to unsigned long and assign to `arg[1]` and `arg[2]` respectively.
    - Assign the additional arguments `a0` to `a15` to `arg[3]` through `arg[18]`.
    - Invoke the `task` function with `tpool`, `t0`, the number of arguments (19UL), and the `arg` array.
- **Output**: The function does not return a value; it executes a task with the provided arguments.


---
### fd\_map\_reduce\_private\_17<!-- {{#callable:fd_map_reduce_private_17}} -->
The function `fd_map_reduce_private_17` prepares and executes a task with a thread pool, passing 20 arguments to the task.
- **Inputs**:
    - `task`: A function pointer of type `fd_tpool_task_v2_t` representing the task to be executed.
    - `tpool`: A pointer to `fd_tpool_t`, representing the thread pool to be used for executing the task.
    - `t0`: An unsigned long integer representing the starting index of the thread pool range.
    - `t1`: An unsigned long integer representing the ending index of the thread pool range.
    - `i0`: A long integer representing the starting index of the range to be processed.
    - `i1`: A long integer representing the ending index of the range to be processed.
    - `a0`: An unsigned long integer representing the first additional argument to be passed to the task.
    - `a1`: An unsigned long integer representing the second additional argument to be passed to the task.
    - `a2`: An unsigned long integer representing the third additional argument to be passed to the task.
    - `a3`: An unsigned long integer representing the fourth additional argument to be passed to the task.
    - `a4`: An unsigned long integer representing the fifth additional argument to be passed to the task.
    - `a5`: An unsigned long integer representing the sixth additional argument to be passed to the task.
    - `a6`: An unsigned long integer representing the seventh additional argument to be passed to the task.
    - `a7`: An unsigned long integer representing the eighth additional argument to be passed to the task.
    - `a8`: An unsigned long integer representing the ninth additional argument to be passed to the task.
    - `a9`: An unsigned long integer representing the tenth additional argument to be passed to the task.
    - `a10`: An unsigned long integer representing the eleventh additional argument to be passed to the task.
    - `a11`: An unsigned long integer representing the twelfth additional argument to be passed to the task.
    - `a12`: An unsigned long integer representing the thirteenth additional argument to be passed to the task.
    - `a13`: An unsigned long integer representing the fourteenth additional argument to be passed to the task.
    - `a14`: An unsigned long integer representing the fifteenth additional argument to be passed to the task.
    - `a15`: An unsigned long integer representing the sixteenth additional argument to be passed to the task.
    - `a16`: An unsigned long integer representing the seventeenth additional argument to be passed to the task.
- **Control Flow**:
    - Initialize an array `arg` of 20 unsigned long integers.
    - Assign `t1` to `arg[0]`, cast `i0` and `i1` to unsigned long and assign to `arg[1]` and `arg[2]` respectively.
    - Assign the additional arguments `a0` to `a16` to `arg[3]` to `arg[19]`.
    - Invoke the `task` function with `tpool`, `t0`, the number of arguments (20), and the `arg` array.
- **Output**: The function does not return a value; it executes a task with the provided arguments.


---
### fd\_map\_reduce\_private\_18<!-- {{#callable:fd_map_reduce_private_18}} -->
The `fd_map_reduce_private_18` function prepares an array of 21 arguments and invokes a task function with these arguments and additional parameters for parallel processing.
- **Inputs**:
    - `task`: A function pointer of type `fd_tpool_task_v2_t` that represents the task to be executed.
    - `tpool`: A pointer to a thread pool (`fd_tpool_t`) used for managing threads.
    - `t0`: An unsigned long integer representing the starting index of the thread pool range.
    - `t1`: An unsigned long integer representing the ending index of the thread pool range.
    - `i0`: A long integer representing the starting index of the data range to be processed.
    - `i1`: A long integer representing the ending index of the data range to be processed.
    - `a0`: An unsigned long integer representing the first additional argument to be passed to the task.
    - `a1`: An unsigned long integer representing the second additional argument to be passed to the task.
    - `a2`: An unsigned long integer representing the third additional argument to be passed to the task.
    - `a3`: An unsigned long integer representing the fourth additional argument to be passed to the task.
    - `a4`: An unsigned long integer representing the fifth additional argument to be passed to the task.
    - `a5`: An unsigned long integer representing the sixth additional argument to be passed to the task.
    - `a6`: An unsigned long integer representing the seventh additional argument to be passed to the task.
    - `a7`: An unsigned long integer representing the eighth additional argument to be passed to the task.
    - `a8`: An unsigned long integer representing the ninth additional argument to be passed to the task.
    - `a9`: An unsigned long integer representing the tenth additional argument to be passed to the task.
    - `a10`: An unsigned long integer representing the eleventh additional argument to be passed to the task.
    - `a11`: An unsigned long integer representing the twelfth additional argument to be passed to the task.
    - `a12`: An unsigned long integer representing the thirteenth additional argument to be passed to the task.
    - `a13`: An unsigned long integer representing the fourteenth additional argument to be passed to the task.
    - `a14`: An unsigned long integer representing the fifteenth additional argument to be passed to the task.
    - `a15`: An unsigned long integer representing the sixteenth additional argument to be passed to the task.
    - `a16`: An unsigned long integer representing the seventeenth additional argument to be passed to the task.
    - `a17`: An unsigned long integer representing the eighteenth additional argument to be passed to the task.
- **Control Flow**:
    - Initialize an array `arg` of 21 unsigned long integers.
    - Assign `t1` to `arg[0]`, cast `i0` and `i1` to unsigned long and assign to `arg[1]` and `arg[2]` respectively.
    - Assign the additional arguments `a0` to `a17` to `arg[3]` through `arg[20]`.
    - Invoke the `task` function with `tpool`, `t0`, the number of arguments (21UL), and the `arg` array.
- **Output**: The function does not return a value; it executes a task with the provided arguments.


---
### fd\_map\_reduce\_private\_19<!-- {{#callable:fd_map_reduce_private_19}} -->
The function `fd_map_reduce_private_19` prepares and executes a task with a thread pool, passing a set of 22 arguments to the task.
- **Inputs**:
    - `task`: A function pointer of type `fd_tpool_task_v2_t` that represents the task to be executed.
    - `tpool`: A pointer to a thread pool (`fd_tpool_t`) that manages the threads executing the task.
    - `t0`: An unsigned long integer representing the starting index of the thread pool range.
    - `t1`: An unsigned long integer representing the ending index of the thread pool range.
    - `i0`: A long integer representing the starting index of the data range to be processed.
    - `i1`: A long integer representing the ending index of the data range to be processed.
    - `a0`: An unsigned long integer representing the first additional argument to be passed to the task.
    - `a1`: An unsigned long integer representing the second additional argument to be passed to the task.
    - `a2`: An unsigned long integer representing the third additional argument to be passed to the task.
    - `a3`: An unsigned long integer representing the fourth additional argument to be passed to the task.
    - `a4`: An unsigned long integer representing the fifth additional argument to be passed to the task.
    - `a5`: An unsigned long integer representing the sixth additional argument to be passed to the task.
    - `a6`: An unsigned long integer representing the seventh additional argument to be passed to the task.
    - `a7`: An unsigned long integer representing the eighth additional argument to be passed to the task.
    - `a8`: An unsigned long integer representing the ninth additional argument to be passed to the task.
    - `a9`: An unsigned long integer representing the tenth additional argument to be passed to the task.
    - `a10`: An unsigned long integer representing the eleventh additional argument to be passed to the task.
    - `a11`: An unsigned long integer representing the twelfth additional argument to be passed to the task.
    - `a12`: An unsigned long integer representing the thirteenth additional argument to be passed to the task.
    - `a13`: An unsigned long integer representing the fourteenth additional argument to be passed to the task.
    - `a14`: An unsigned long integer representing the fifteenth additional argument to be passed to the task.
    - `a15`: An unsigned long integer representing the sixteenth additional argument to be passed to the task.
    - `a16`: An unsigned long integer representing the seventeenth additional argument to be passed to the task.
    - `a17`: An unsigned long integer representing the eighteenth additional argument to be passed to the task.
    - `a18`: An unsigned long integer representing the nineteenth additional argument to be passed to the task.
- **Control Flow**:
    - Initialize an array `arg` of 22 unsigned long integers.
    - Assign `t1` to `arg[0]`, cast `i0` and `i1` to unsigned long and assign to `arg[1]` and `arg[2]` respectively.
    - Assign the additional arguments `a0` to `a18` to `arg[3]` to `arg[21]`.
    - Invoke the `task` function with `tpool`, `t0`, the number of arguments (22), and the `arg` array.
- **Output**: The function does not return a value; it executes a task with the provided arguments.


---
### fd\_map\_reduce\_private\_20<!-- {{#callable:fd_map_reduce_private_20}} -->
The `fd_map_reduce_private_20` function prepares and executes a task with a thread pool, passing a set of 23 arguments to the task.
- **Inputs**:
    - `task`: A function pointer of type `fd_tpool_task_v2_t` representing the task to be executed.
    - `tpool`: A pointer to `fd_tpool_t`, representing the thread pool to be used for executing the task.
    - `t0`: An unsigned long integer representing the starting index of the thread pool range.
    - `t1`: An unsigned long integer representing the ending index of the thread pool range.
    - `i0`: A long integer representing the starting index of the data range to be processed.
    - `i1`: A long integer representing the ending index of the data range to be processed.
    - `a0`: An unsigned long integer representing the first additional argument to be passed to the task.
    - `a1`: An unsigned long integer representing the second additional argument to be passed to the task.
    - `a2`: An unsigned long integer representing the third additional argument to be passed to the task.
    - `a3`: An unsigned long integer representing the fourth additional argument to be passed to the task.
    - `a4`: An unsigned long integer representing the fifth additional argument to be passed to the task.
    - `a5`: An unsigned long integer representing the sixth additional argument to be passed to the task.
    - `a6`: An unsigned long integer representing the seventh additional argument to be passed to the task.
    - `a7`: An unsigned long integer representing the eighth additional argument to be passed to the task.
    - `a8`: An unsigned long integer representing the ninth additional argument to be passed to the task.
    - `a9`: An unsigned long integer representing the tenth additional argument to be passed to the task.
    - `a10`: An unsigned long integer representing the eleventh additional argument to be passed to the task.
    - `a11`: An unsigned long integer representing the twelfth additional argument to be passed to the task.
    - `a12`: An unsigned long integer representing the thirteenth additional argument to be passed to the task.
    - `a13`: An unsigned long integer representing the fourteenth additional argument to be passed to the task.
    - `a14`: An unsigned long integer representing the fifteenth additional argument to be passed to the task.
    - `a15`: An unsigned long integer representing the sixteenth additional argument to be passed to the task.
    - `a16`: An unsigned long integer representing the seventeenth additional argument to be passed to the task.
    - `a17`: An unsigned long integer representing the eighteenth additional argument to be passed to the task.
    - `a18`: An unsigned long integer representing the nineteenth additional argument to be passed to the task.
    - `a19`: An unsigned long integer representing the twentieth additional argument to be passed to the task.
- **Control Flow**:
    - Initialize an array `arg` of 23 unsigned long integers.
    - Assign `t1` to `arg[0]`, cast `i0` and `i1` to unsigned long and assign to `arg[1]` and `arg[2]` respectively.
    - Assign the additional arguments `a0` to `a19` to `arg[3]` through `arg[22]`.
    - Invoke the `task` function with `tpool`, `t0`, the number of arguments (23), and the `arg` array.
- **Output**: The function does not return a value; it executes a task with the provided arguments.


---
### fd\_map\_reduce\_private\_21<!-- {{#callable:fd_map_reduce_private_21}} -->
The function `fd_map_reduce_private_21` prepares and executes a task with a thread pool, passing 24 arguments to the task.
- **Inputs**:
    - `task`: A function pointer of type `fd_tpool_task_v2_t` representing the task to be executed.
    - `tpool`: A pointer to `fd_tpool_t`, representing the thread pool to be used for executing the task.
    - `t0`: An unsigned long integer representing the starting index of the thread pool range.
    - `t1`: An unsigned long integer representing the ending index of the thread pool range.
    - `i0`: A long integer representing the starting index of the range to be processed.
    - `i1`: A long integer representing the ending index of the range to be processed.
    - `a0`: An unsigned long integer representing the first additional argument to be passed to the task.
    - `a1`: An unsigned long integer representing the second additional argument to be passed to the task.
    - `a2`: An unsigned long integer representing the third additional argument to be passed to the task.
    - `a3`: An unsigned long integer representing the fourth additional argument to be passed to the task.
    - `a4`: An unsigned long integer representing the fifth additional argument to be passed to the task.
    - `a5`: An unsigned long integer representing the sixth additional argument to be passed to the task.
    - `a6`: An unsigned long integer representing the seventh additional argument to be passed to the task.
    - `a7`: An unsigned long integer representing the eighth additional argument to be passed to the task.
    - `a8`: An unsigned long integer representing the ninth additional argument to be passed to the task.
    - `a9`: An unsigned long integer representing the tenth additional argument to be passed to the task.
    - `a10`: An unsigned long integer representing the eleventh additional argument to be passed to the task.
    - `a11`: An unsigned long integer representing the twelfth additional argument to be passed to the task.
    - `a12`: An unsigned long integer representing the thirteenth additional argument to be passed to the task.
    - `a13`: An unsigned long integer representing the fourteenth additional argument to be passed to the task.
    - `a14`: An unsigned long integer representing the fifteenth additional argument to be passed to the task.
    - `a15`: An unsigned long integer representing the sixteenth additional argument to be passed to the task.
    - `a16`: An unsigned long integer representing the seventeenth additional argument to be passed to the task.
    - `a17`: An unsigned long integer representing the eighteenth additional argument to be passed to the task.
    - `a18`: An unsigned long integer representing the nineteenth additional argument to be passed to the task.
    - `a19`: An unsigned long integer representing the twentieth additional argument to be passed to the task.
    - `a20`: An unsigned long integer representing the twenty-first additional argument to be passed to the task.
- **Control Flow**:
    - Initialize an array `arg` of 24 unsigned long integers.
    - Assign `t1` to `arg[0]`, cast `i0` and `i1` to unsigned long and assign to `arg[1]` and `arg[2]` respectively.
    - Assign the additional arguments `a0` to `a20` to `arg[3]` to `arg[23]`.
    - Invoke the `task` function with `tpool`, `t0`, the number 24, and the `arg` array as arguments.
- **Output**: The function does not return any value; it executes a task with the provided arguments.


---
### fd\_map\_reduce\_private\_22<!-- {{#callable:fd_map_reduce_private_22}} -->
The function `fd_map_reduce_private_22` prepares an array of 25 arguments and invokes a task function with these arguments and additional parameters for parallel processing.
- **Inputs**:
    - `task`: A function pointer of type `fd_tpool_task_v2_t` that represents the task to be executed.
    - `tpool`: A pointer to a thread pool of type `fd_tpool_t` used for managing threads.
    - `t0`: An unsigned long integer representing the starting index of the thread pool range.
    - `t1`: An unsigned long integer representing the ending index of the thread pool range.
    - `i0`: A long integer representing the starting index of the data range to be processed.
    - `i1`: A long integer representing the ending index of the data range to be processed.
    - `a0`: An unsigned long integer representing the first additional argument to be passed to the task.
    - `a1`: An unsigned long integer representing the second additional argument to be passed to the task.
    - `a2`: An unsigned long integer representing the third additional argument to be passed to the task.
    - `a3`: An unsigned long integer representing the fourth additional argument to be passed to the task.
    - `a4`: An unsigned long integer representing the fifth additional argument to be passed to the task.
    - `a5`: An unsigned long integer representing the sixth additional argument to be passed to the task.
    - `a6`: An unsigned long integer representing the seventh additional argument to be passed to the task.
    - `a7`: An unsigned long integer representing the eighth additional argument to be passed to the task.
    - `a8`: An unsigned long integer representing the ninth additional argument to be passed to the task.
    - `a9`: An unsigned long integer representing the tenth additional argument to be passed to the task.
    - `a10`: An unsigned long integer representing the eleventh additional argument to be passed to the task.
    - `a11`: An unsigned long integer representing the twelfth additional argument to be passed to the task.
    - `a12`: An unsigned long integer representing the thirteenth additional argument to be passed to the task.
    - `a13`: An unsigned long integer representing the fourteenth additional argument to be passed to the task.
    - `a14`: An unsigned long integer representing the fifteenth additional argument to be passed to the task.
    - `a15`: An unsigned long integer representing the sixteenth additional argument to be passed to the task.
    - `a16`: An unsigned long integer representing the seventeenth additional argument to be passed to the task.
    - `a17`: An unsigned long integer representing the eighteenth additional argument to be passed to the task.
    - `a18`: An unsigned long integer representing the nineteenth additional argument to be passed to the task.
    - `a19`: An unsigned long integer representing the twentieth additional argument to be passed to the task.
    - `a20`: An unsigned long integer representing the twenty-first additional argument to be passed to the task.
    - `a21`: An unsigned long integer representing the twenty-second additional argument to be passed to the task.
- **Control Flow**:
    - Initialize an array `arg` of 25 unsigned long integers.
    - Assign `t1` to `arg[0]`, cast `i0` and `i1` to unsigned long and assign to `arg[1]` and `arg[2]` respectively.
    - Assign the additional arguments `a0` to `a21` to `arg[3]` through `arg[24]`.
    - Invoke the `task` function with `tpool`, `t0`, the number of arguments (25UL), and the `arg` array.
- **Output**: The function does not return a value; it executes a task with the provided arguments.


---
### fd\_map\_reduce\_private\_23<!-- {{#callable:fd_map_reduce_private_23}} -->
The function `fd_map_reduce_private_23` prepares an array of 26 arguments and invokes a task function with these arguments and a thread pool.
- **Inputs**:
    - `task`: A function pointer of type `fd_tpool_task_v2_t` that represents the task to be executed.
    - `tpool`: A pointer to a thread pool of type `fd_tpool_t`.
    - `t0`: An unsigned long integer representing the starting thread index.
    - `t1`: An unsigned long integer representing the ending thread index.
    - `i0`: A long integer representing the starting index for a range of elements.
    - `i1`: A long integer representing the ending index for a range of elements.
    - `a0`: An unsigned long integer representing the first additional argument.
    - `a1`: An unsigned long integer representing the second additional argument.
    - `a2`: An unsigned long integer representing the third additional argument.
    - `a3`: An unsigned long integer representing the fourth additional argument.
    - `a4`: An unsigned long integer representing the fifth additional argument.
    - `a5`: An unsigned long integer representing the sixth additional argument.
    - `a6`: An unsigned long integer representing the seventh additional argument.
    - `a7`: An unsigned long integer representing the eighth additional argument.
    - `a8`: An unsigned long integer representing the ninth additional argument.
    - `a9`: An unsigned long integer representing the tenth additional argument.
    - `a10`: An unsigned long integer representing the eleventh additional argument.
    - `a11`: An unsigned long integer representing the twelfth additional argument.
    - `a12`: An unsigned long integer representing the thirteenth additional argument.
    - `a13`: An unsigned long integer representing the fourteenth additional argument.
    - `a14`: An unsigned long integer representing the fifteenth additional argument.
    - `a15`: An unsigned long integer representing the sixteenth additional argument.
    - `a16`: An unsigned long integer representing the seventeenth additional argument.
    - `a17`: An unsigned long integer representing the eighteenth additional argument.
    - `a18`: An unsigned long integer representing the nineteenth additional argument.
    - `a19`: An unsigned long integer representing the twentieth additional argument.
    - `a20`: An unsigned long integer representing the twenty-first additional argument.
    - `a21`: An unsigned long integer representing the twenty-second additional argument.
    - `a22`: An unsigned long integer representing the twenty-third additional argument.
- **Control Flow**:
    - Initialize an array `arg` of 26 unsigned long integers.
    - Assign `t1` to `arg[0]`, cast `i0` and `i1` to unsigned long and assign to `arg[1]` and `arg[2]` respectively.
    - Assign the additional arguments `a0` to `a22` to `arg[3]` through `arg[25]`.
    - Invoke the `task` function with `tpool`, `t0`, the number of arguments (26), and the `arg` array.
- **Output**: The function does not return a value; it executes a task with the provided arguments.


---
### fd\_map\_reduce\_private\_24<!-- {{#callable:fd_map_reduce_private_24}} -->
The function `fd_map_reduce_private_24` prepares and passes an array of 27 arguments to a task function for execution within a thread pool.
- **Inputs**:
    - `task`: A function pointer of type `fd_tpool_task_v2_t` that represents the task to be executed.
    - `tpool`: A pointer to `fd_tpool_t`, representing the thread pool in which the task will be executed.
    - `t0`: An unsigned long integer representing the starting index of the thread pool range.
    - `t1`: An unsigned long integer representing the ending index of the thread pool range.
    - `i0`: A long integer representing the starting index of the range to be processed.
    - `i1`: A long integer representing the ending index of the range to be processed.
    - `a0`: An unsigned long integer representing the first additional argument to be passed to the task.
    - `a1`: An unsigned long integer representing the second additional argument to be passed to the task.
    - `a2`: An unsigned long integer representing the third additional argument to be passed to the task.
    - `a3`: An unsigned long integer representing the fourth additional argument to be passed to the task.
    - `a4`: An unsigned long integer representing the fifth additional argument to be passed to the task.
    - `a5`: An unsigned long integer representing the sixth additional argument to be passed to the task.
    - `a6`: An unsigned long integer representing the seventh additional argument to be passed to the task.
    - `a7`: An unsigned long integer representing the eighth additional argument to be passed to the task.
    - `a8`: An unsigned long integer representing the ninth additional argument to be passed to the task.
    - `a9`: An unsigned long integer representing the tenth additional argument to be passed to the task.
    - `a10`: An unsigned long integer representing the eleventh additional argument to be passed to the task.
    - `a11`: An unsigned long integer representing the twelfth additional argument to be passed to the task.
    - `a12`: An unsigned long integer representing the thirteenth additional argument to be passed to the task.
    - `a13`: An unsigned long integer representing the fourteenth additional argument to be passed to the task.
    - `a14`: An unsigned long integer representing the fifteenth additional argument to be passed to the task.
    - `a15`: An unsigned long integer representing the sixteenth additional argument to be passed to the task.
    - `a16`: An unsigned long integer representing the seventeenth additional argument to be passed to the task.
    - `a17`: An unsigned long integer representing the eighteenth additional argument to be passed to the task.
    - `a18`: An unsigned long integer representing the nineteenth additional argument to be passed to the task.
    - `a19`: An unsigned long integer representing the twentieth additional argument to be passed to the task.
    - `a20`: An unsigned long integer representing the twenty-first additional argument to be passed to the task.
    - `a21`: An unsigned long integer representing the twenty-second additional argument to be passed to the task.
    - `a22`: An unsigned long integer representing the twenty-third additional argument to be passed to the task.
    - `a23`: An unsigned long integer representing the twenty-fourth additional argument to be passed to the task.
- **Control Flow**:
    - Initialize an array `arg` of 27 unsigned long integers.
    - Assign `t1` to `arg[0]`, cast `i0` and `i1` to unsigned long and assign to `arg[1]` and `arg[2]` respectively.
    - Assign the additional arguments `a0` to `a23` to `arg[3]` through `arg[26]`.
    - Invoke the `task` function with `tpool`, `t0`, the size of the `arg` array (27UL), and the `arg` array itself as parameters.
- **Output**: The function does not return a value; it executes the provided task function with the specified arguments.


---
### fd\_map\_reduce\_private\_25<!-- {{#callable:fd_map_reduce_private_25}} -->
The function `fd_map_reduce_private_25` prepares and executes a task with a thread pool, passing a set of 28 arguments to the task.
- **Inputs**:
    - `task`: A function pointer of type `fd_tpool_task_v2_t` representing the task to be executed.
    - `tpool`: A pointer to `fd_tpool_t`, representing the thread pool to be used for executing the task.
    - `t0`: An unsigned long integer representing the starting index of the thread pool range.
    - `t1`: An unsigned long integer representing the ending index of the thread pool range.
    - `i0`: A long integer representing the starting index of the range to be processed.
    - `i1`: A long integer representing the ending index of the range to be processed.
    - `a0`: An unsigned long integer representing the first additional argument to be passed to the task.
    - `a1`: An unsigned long integer representing the second additional argument to be passed to the task.
    - `a2`: An unsigned long integer representing the third additional argument to be passed to the task.
    - `a3`: An unsigned long integer representing the fourth additional argument to be passed to the task.
    - `a4`: An unsigned long integer representing the fifth additional argument to be passed to the task.
    - `a5`: An unsigned long integer representing the sixth additional argument to be passed to the task.
    - `a6`: An unsigned long integer representing the seventh additional argument to be passed to the task.
    - `a7`: An unsigned long integer representing the eighth additional argument to be passed to the task.
    - `a8`: An unsigned long integer representing the ninth additional argument to be passed to the task.
    - `a9`: An unsigned long integer representing the tenth additional argument to be passed to the task.
    - `a10`: An unsigned long integer representing the eleventh additional argument to be passed to the task.
    - `a11`: An unsigned long integer representing the twelfth additional argument to be passed to the task.
    - `a12`: An unsigned long integer representing the thirteenth additional argument to be passed to the task.
    - `a13`: An unsigned long integer representing the fourteenth additional argument to be passed to the task.
    - `a14`: An unsigned long integer representing the fifteenth additional argument to be passed to the task.
    - `a15`: An unsigned long integer representing the sixteenth additional argument to be passed to the task.
    - `a16`: An unsigned long integer representing the seventeenth additional argument to be passed to the task.
    - `a17`: An unsigned long integer representing the eighteenth additional argument to be passed to the task.
    - `a18`: An unsigned long integer representing the nineteenth additional argument to be passed to the task.
    - `a19`: An unsigned long integer representing the twentieth additional argument to be passed to the task.
    - `a20`: An unsigned long integer representing the twenty-first additional argument to be passed to the task.
    - `a21`: An unsigned long integer representing the twenty-second additional argument to be passed to the task.
    - `a22`: An unsigned long integer representing the twenty-third additional argument to be passed to the task.
    - `a23`: An unsigned long integer representing the twenty-fourth additional argument to be passed to the task.
    - `a24`: An unsigned long integer representing the twenty-fifth additional argument to be passed to the task.
- **Control Flow**:
    - Initialize an array `arg` of 28 unsigned long integers.
    - Assign `t1` to `arg[0]`, cast `i0` and `i1` to unsigned long and assign to `arg[1]` and `arg[2]` respectively.
    - Assign the additional arguments `a0` to `a24` to `arg[3]` to `arg[27]`.
    - Invoke the `task` function with `tpool`, `t0`, the number of arguments (28UL), and the `arg` array.
- **Output**: The function does not return a value; it executes a task with the provided arguments.


---
### fd\_map\_reduce\_private\_26<!-- {{#callable:fd_map_reduce_private_26}} -->
The function `fd_map_reduce_private_26` prepares an array of 29 arguments and invokes a task function with these arguments and a thread pool.
- **Inputs**:
    - `task`: A function pointer of type `fd_tpool_task_v2_t` that represents the task to be executed.
    - `tpool`: A pointer to a thread pool of type `fd_tpool_t` used for task execution.
    - `t0`: An unsigned long integer representing the starting index of the thread pool range.
    - `t1`: An unsigned long integer representing the ending index of the thread pool range.
    - `i0`: A long integer representing the starting index of the range to be processed.
    - `i1`: A long integer representing the ending index of the range to be processed.
    - `a0`: An unsigned long integer representing the first additional argument to be passed to the task.
    - `a1`: An unsigned long integer representing the second additional argument to be passed to the task.
    - `a2`: An unsigned long integer representing the third additional argument to be passed to the task.
    - `a3`: An unsigned long integer representing the fourth additional argument to be passed to the task.
    - `a4`: An unsigned long integer representing the fifth additional argument to be passed to the task.
    - `a5`: An unsigned long integer representing the sixth additional argument to be passed to the task.
    - `a6`: An unsigned long integer representing the seventh additional argument to be passed to the task.
    - `a7`: An unsigned long integer representing the eighth additional argument to be passed to the task.
    - `a8`: An unsigned long integer representing the ninth additional argument to be passed to the task.
    - `a9`: An unsigned long integer representing the tenth additional argument to be passed to the task.
    - `a10`: An unsigned long integer representing the eleventh additional argument to be passed to the task.
    - `a11`: An unsigned long integer representing the twelfth additional argument to be passed to the task.
    - `a12`: An unsigned long integer representing the thirteenth additional argument to be passed to the task.
    - `a13`: An unsigned long integer representing the fourteenth additional argument to be passed to the task.
    - `a14`: An unsigned long integer representing the fifteenth additional argument to be passed to the task.
    - `a15`: An unsigned long integer representing the sixteenth additional argument to be passed to the task.
    - `a16`: An unsigned long integer representing the seventeenth additional argument to be passed to the task.
    - `a17`: An unsigned long integer representing the eighteenth additional argument to be passed to the task.
    - `a18`: An unsigned long integer representing the nineteenth additional argument to be passed to the task.
    - `a19`: An unsigned long integer representing the twentieth additional argument to be passed to the task.
    - `a20`: An unsigned long integer representing the twenty-first additional argument to be passed to the task.
    - `a21`: An unsigned long integer representing the twenty-second additional argument to be passed to the task.
    - `a22`: An unsigned long integer representing the twenty-third additional argument to be passed to the task.
    - `a23`: An unsigned long integer representing the twenty-fourth additional argument to be passed to the task.
    - `a24`: An unsigned long integer representing the twenty-fifth additional argument to be passed to the task.
    - `a25`: An unsigned long integer representing the twenty-sixth additional argument to be passed to the task.
- **Control Flow**:
    - Initialize an array `arg` of 29 unsigned long integers.
    - Assign `t1` to `arg[0]`, cast `i0` and `i1` to unsigned long and assign to `arg[1]` and `arg[2]` respectively.
    - Assign the additional arguments `a0` to `a25` to `arg[3]` through `arg[28]`.
    - Invoke the `task` function with `tpool`, `t0`, the number of arguments (29UL), and the `arg` array.
- **Output**: The function does not return a value; it executes a task using the provided thread pool and arguments.



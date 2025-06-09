# Purpose
The provided C header file defines a thread pool API designed for high-performance, scalable execution of parallel tasks. The primary purpose of this file is to offer a robust and efficient mechanism for managing and executing tasks across multiple threads, addressing common inefficiencies found in traditional thread pool implementations. The file includes detailed explanations and mathematical insights into optimizing thread parallelism, emphasizing the importance of minimizing overheads associated with task partitioning and thread dispatching.

Key components of this header file include the definition of data structures and function prototypes for managing thread pools (`fd_tpool_t`), executing tasks ([`fd_tpool_exec`](#fd_tpool_exec)), and partitioning tasks among threads (`FD_TPOOL_PARTITION`). The file also introduces advanced techniques for parallelizing task dispatch and execution, such as recursive task division and optimized thread wake-up strategies. Additionally, it provides macros and inline functions to facilitate the creation, management, and execution of tasks within a thread pool, ensuring minimal overhead and maximum scalability. This header is intended to be included in other C source files, providing a public API for developers to leverage in their applications requiring efficient parallel task execution.
# Imports and Dependencies

---
- `../scratch/fd_scratch.h`
- `fd_map_reduce.h`


# Global Variables

---
### \_ftp\_block\_rem
- **Type**: `ulong`
- **Description**: The `_ftp_block_rem` variable is a global variable of type `ulong` that represents the number of leftover tasks after dividing the total number of tasks (`_ftp_task_cnt`) by the number of lanes (`_ftp_lane_cnt`).
- **Use**: It is used to determine the number of tasks that do not fit into complete SIMD blocks, typically requiring special handling such as no-operation or fast masking.


---
### \_ftp\_worker\_block\_min
- **Type**: `ulong`
- **Description**: The variable `_ftp_worker_block_min` is a global variable of type `ulong` that represents the minimum number of complete SIMD (Single Instruction, Multiple Data) blocks that can be assigned to a worker thread. It is calculated by dividing the total number of complete SIMD blocks (`_ftp_block_cnt`) by the total number of worker threads (`_ftp_worker_cnt`).
- **Use**: This variable is used to determine the baseline number of SIMD blocks each worker thread should handle in a parallel task distribution.


---
### \_ftp\_worker\_extra\_cnt
- **Type**: `ulong`
- **Description**: The variable `_ftp_worker_extra_cnt` is a global variable of type `ulong` that calculates the number of worker threads that need to handle an extra complete SIMD block when tasks are partitioned among workers. This is determined by taking the remainder of the division of the total number of complete SIMD blocks (`_ftp_block_cnt`) by the number of worker threads (`_ftp_worker_cnt`).
- **Use**: This variable is used to ensure that any remaining tasks, after evenly distributing complete SIMD blocks among workers, are assigned to some workers to maintain load balance.


---
### \_ftp\_worker\_task0
- **Type**: `ulong`
- **Description**: The variable `_ftp_worker_task0` is a global variable of type `ulong` that is used to calculate the starting index of tasks assigned to a specific worker in a thread pool. It is part of a macro `FD_TPOOL_PARTITION` that partitions tasks among multiple worker threads in a way that balances the workload as evenly as possible.
- **Use**: This variable is used to determine the starting task index for a worker thread in a parallel task execution environment.


---
### \_ftp\_worker\_task1
- **Type**: `ulong`
- **Description**: The variable `_ftp_worker_task1` is a global variable of type `ulong` that represents the end index of a range of tasks assigned to a specific worker in a thread pool. It is calculated based on the starting index `_ftp_worker_task0`, the number of lanes `_ftp_lane_cnt`, the minimum number of complete SIMD blocks per worker `_ftp_worker_block_min`, and additional conditions related to the worker index and remaining blocks.
- **Use**: This variable is used to determine the range of tasks a specific worker thread will execute in a parallelized task distribution.


---
### FD\_STATIC\_ASSERT
- **Type**: `macro`
- **Description**: `FD_STATIC_ASSERT` is a macro used to perform compile-time assertions in C. It checks a condition at compile time and, if the condition is false, it generates a compilation error with a specified message. In this case, it checks if `FD_TILE_MAX` is less than 2048UL and, if not, it triggers a compilation error with the message `update_implementation`. This is a safeguard to ensure that certain conditions are met before the code is compiled.
- **Use**: This macro is used to enforce constraints on compile-time constants, ensuring that the code adheres to specific requirements before compilation proceeds.


---
### fd\_tpool\_init
- **Type**: `fd_tpool_t *`
- **Description**: The `fd_tpool_init` function initializes a memory region as a thread pool capable of supporting up to a specified number of worker threads. It returns a handle to the thread pool on success, or NULL on failure. The function ensures that worker 0 is already created and ready for use.
- **Use**: This variable is used to create and initialize a thread pool for efficient parallel task execution.


---
### fd\_tpool\_fini
- **Type**: `function pointer`
- **Description**: `fd_tpool_fini` is a function that finalizes a thread pool (`fd_tpool_t`) by popping all worker threads and unformatting the underlying memory region. It should be called by a thread that was not pushed into the thread pool, typically a 'worker 0' thread, and no other operations on the thread pool should be in progress when this is called.
- **Use**: This function is used to clean up and release resources associated with a thread pool once it is no longer needed.


---
### fd\_tpool\_worker\_push
- **Type**: ``fd_tpool_t *``
- **Description**: The `fd_tpool_worker_push` function is a global function that adds a worker thread, identified by `tile_idx`, to a thread pool represented by `tpool`. It ensures that the specified tile is idle and not already part of the pool before adding it.
- **Use**: This function is used to dynamically add worker threads to a thread pool for parallel task execution.


---
### fd\_tpool\_worker\_pop
- **Type**: `fd_tpool_t *`
- **Description**: The `fd_tpool_worker_pop` function is a global function that removes the most recently added worker thread from a thread pool (`tpool`). It returns a pointer to the thread pool (`fd_tpool_t *`) on success, indicating that the worker thread has been successfully removed and is now idle, or NULL on failure.
- **Use**: This function is used to manage the lifecycle of worker threads in a thread pool by removing the most recently added worker, making it available for other tasks.


# Data Structures

---
### fd\_tpool\_t
- **Type**: `typedef struct fd_tpool_private fd_tpool_t;`
- **Members**:
    - `fd_tpool_private`: An opaque structure representing the private details of a thread pool.
- **Description**: The `fd_tpool_t` is an opaque handle for a thread pool, designed to facilitate ultra-low overhead and high scalability in launching thread-parallel jobs. It abstracts the complexities of thread management, allowing users to efficiently partition and dispatch tasks across multiple threads. The underlying implementation focuses on minimizing overheads associated with thread creation and task dispatch, enabling effective parallelization even for small tasks. This is achieved through pre-allocated threads, optimized task partitioning, and efficient wake-up mechanisms, making it suitable for high-performance computing scenarios.


---
### fd\_tpool\_private\_worker
- **Type**: `struct`
- **Members**:
    - `seq0`: A sequence number used for dispatch read/write operations, ideally write-only for dispatch and read-only for workers.
    - `arg_cnt`: Indicates the number of arguments for a task, with UINT_MAX for a v1 task or a count for a v2 task.
    - `task`: Holds the task identifier, which is 0 to halt the worker, or a task type depending on arg_cnt.
    - `arg`: An array of task arguments, indexed from 0 to arg_cnt.
    - `seq1`: A sequence number used for dispatch read-only and worker write-only operations, ensuring separation from seq0.
    - `tile_idx`: The index of the tile, read-only after initialization.
    - `lock`: Used by sleeping workers to manage locking.
    - `wake`: Used by sleeping workers to manage waking up.
- **Description**: The `fd_tpool_private_worker` structure is a data structure designed to manage worker threads in a thread pool, providing fields for task management, argument handling, and synchronization. It includes sequence numbers for managing read/write operations, a task identifier to control worker actions, and an array for task arguments. Additionally, it has fields for managing worker states such as locking and waking, which are particularly useful for workers that may enter a sleep state. The structure is aligned to 128 bytes to optimize cache usage and minimize false sharing in multi-threaded environments.


---
### fd\_tpool\_private\_worker\_t
- **Type**: `struct`
- **Members**:
    - `seq0`: A dispatch read/write field, ideally write-only, and read-only for the worker.
    - `arg_cnt`: Indicates the argument count for a v2 task or UINT_MAX for a v1 task.
    - `task`: Holds the task function pointer or 0 to halt the worker.
    - `arg`: An array of task arguments, indexed from 0 to arg_cnt.
    - `seq1`: A dispatch read-only field, worker write-only, located in a different cache line pair than seq0.
    - `tile_idx`: Read-only after initialization, indicating the tile index.
    - `lock`: Used by sleeping workers for synchronization.
    - `wake`: Used by sleeping workers to manage wake-up signals.
- **Description**: The `fd_tpool_private_worker_t` structure is a private data structure used within a thread pool implementation to manage individual worker threads. It contains fields for managing task dispatching, including sequence numbers for synchronization (`seq0` and `seq1`), a task function pointer (`task`), and an array of arguments (`arg`). The structure also includes fields for managing worker state and synchronization, such as `tile_idx`, `lock`, and `wake`. This structure is aligned to 128 bytes to optimize cache usage and minimize false sharing between threads.


---
### fd\_tpool\_private
- **Type**: `struct`
- **Members**:
    - `opt`: A bitwise OR of FD_TPOOL_OPTs, representing options for the thread pool.
    - `worker_max`: The maximum number of worker threads allowed, must be positive.
    - `worker_cnt`: The current count of worker threads, ranging from 1 to worker_max.
- **Description**: The `fd_tpool_private` structure is a private data structure used to manage a thread pool in a high-performance computing context. It contains configuration options (`opt`), the maximum number of worker threads (`worker_max`), and the current number of active worker threads (`worker_cnt`). The structure is designed to facilitate efficient thread management and task distribution, avoiding the overheads associated with naive thread pool implementations. It is aligned to 128 bytes and is used in conjunction with an array of `fd_tpool_private_worker_t` pointers to manage individual worker threads.


# Functions

---
### fd\_tpool\_private\_split<!-- {{#callable:fd_tpool_private_split}} -->
The `fd_tpool_private_split` function calculates a NUMA-aware split of a given number of elements, ensuring the left side is greater than or equal to the right side, and one of the splits is the largest power of two smaller than the input.
- **Inputs**:
    - `n`: An unsigned long integer representing the number of elements to be split, assumed to be greater than 1.
- **Control Flow**:
    - The function first calculates the most significant bit (MSB) of the input `n` using `fd_ulong_find_msb(n)`, which determines the largest power of two less than or equal to `n`.
    - It then calculates `m` as `1UL << (b-1)`, which is the largest power of two smaller than `n`.
    - The function uses `fd_ulong_if` to decide the return value: if `n & m` is false (meaning `n` is exactly a power of two), it returns `n-m`; otherwise, it returns `m<<1`.
- **Output**: The function returns an unsigned long integer representing the number of elements assigned to the left side of the split.


---
### fd\_tpool\_private\_wake<!-- {{#callable:fd_tpool_private_wake}} -->
The `fd_tpool_private_wake` function is intended to wake a worker thread in a thread pool that is currently idle and sleeping.
- **Inputs**:
    - `worker`: A pointer to a `fd_tpool_private_worker_t` structure representing the worker thread to be woken up.
- **Control Flow**:
    - The function takes a single argument, `worker`, which is a pointer to a worker thread structure.
    - The function body currently does nothing with the `worker` argument, as it is cast to void to suppress unused variable warnings.
    - The function is defined as `static inline`, suggesting it is intended for use within the same translation unit and optimized for performance.
    - The function is conditionally compiled based on the presence of threading support (`FD_HAS_THREADS`).
- **Output**: The function does not produce any output or return a value.


---
### fd\_tpool\_opt<!-- {{#callable:fd_tpool_opt}} -->
The `fd_tpool_opt` function retrieves the options bitmask from a given thread pool structure.
- **Inputs**:
    - `tpool`: A pointer to a constant `fd_tpool_t` structure representing the thread pool from which the options are to be retrieved.
- **Control Flow**:
    - The function takes a single argument, `tpool`, which is a pointer to a constant `fd_tpool_t` structure.
    - It directly accesses the `opt` member of the `fd_tpool_t` structure pointed to by `tpool`.
    - The function returns the value of the `opt` member.
- **Output**: The function returns an `ulong` representing the options bitmask of the thread pool.


---
### fd\_tpool\_worker\_cnt<!-- {{#callable:fd_tpool_worker_cnt}} -->
The `fd_tpool_worker_cnt` function returns the current number of worker threads in a thread pool.
- **Inputs**:
    - `tpool`: A pointer to a `fd_tpool_t` structure representing the thread pool whose worker count is to be retrieved.
- **Control Flow**:
    - The function takes a single argument, `tpool`, which is a pointer to a `fd_tpool_t` structure.
    - It accesses the `worker_cnt` field of the `fd_tpool_t` structure pointed to by `tpool`.
    - The value of `worker_cnt` is cast to an `ulong` and returned.
- **Output**: The function returns an `ulong` representing the number of worker threads currently in the thread pool.


---
### fd\_tpool\_worker\_max<!-- {{#callable:fd_tpool_worker_max}} -->
The `fd_tpool_worker_max` function retrieves the maximum number of worker threads that a thread pool (`fd_tpool_t`) can support.
- **Inputs**:
    - `tpool`: A pointer to a constant `fd_tpool_t` structure representing the thread pool from which the maximum number of worker threads is to be retrieved.
- **Control Flow**:
    - The function takes a single argument, `tpool`, which is a pointer to a constant `fd_tpool_t` structure.
    - It accesses the `worker_max` field of the `fd_tpool_t` structure pointed to by `tpool`.
    - The value of `worker_max` is cast to an `ulong` type and returned.
- **Output**: The function returns an `ulong` representing the maximum number of worker threads that the thread pool can support.


---
### fd\_tpool\_worker\_tile\_idx<!-- {{#callable:fd_tpool_worker_tile_idx}} -->
The `fd_tpool_worker_tile_idx` function retrieves the tile index of a specified worker in a thread pool.
- **Inputs**:
    - `tpool`: A pointer to a constant `fd_tpool_t` structure representing the thread pool.
    - `worker_idx`: An unsigned long integer representing the index of the worker within the thread pool.
- **Control Flow**:
    - The function calls [`fd_tpool_private_worker`](#fd_tpool_private_worker) with `tpool` to get the array of worker pointers.
    - It accesses the worker at the specified `worker_idx` in the array.
    - It retrieves the `tile_idx` from the worker structure and casts it to `ulong`.
- **Output**: The function returns the tile index of the specified worker as an unsigned long integer.
- **Functions called**:
    - [`fd_tpool_private_worker`](#fd_tpool_private_worker)


---
### fd\_tpool\_worker\_idle<!-- {{#callable:fd_tpool_worker_idle}} -->
The `fd_tpool_worker_idle` function checks if a specific worker in a thread pool is idle by comparing sequence numbers to ensure no tasks were scheduled during the check.
- **Inputs**:
    - `tpool`: A pointer to a constant `fd_tpool_t` structure representing the thread pool.
    - `worker_idx`: An unsigned long integer representing the index of the worker within the thread pool to be checked for idleness.
- **Control Flow**:
    - Retrieve the worker from the thread pool using the provided worker index.
    - Initialize pointers to the worker's `seq0` and `seq1` sequence numbers.
    - Enter a loop to repeatedly check the worker's state.
    - Use memory fences to ensure memory operations are completed in order.
    - Read the initial sequence number `seq0` from the worker's `seq0`.
    - In a loop, read the sequence number `seq1` from the worker's `seq1` and then re-read `seq0` to get `seq2`.
    - If `seq2` equals the initial `seq0`, break the loop, indicating no task was scheduled during the check.
    - If `seq2` does not equal `seq0`, pause briefly and retry the check by updating `seq0` to `seq2`.
- **Output**: Returns an integer, 1 if the worker was idle (i.e., `seq0` equals `seq1`), or 0 if it was not idle.
- **Functions called**:
    - [`fd_tpool_private_worker`](#fd_tpool_private_worker)


---
### fd\_tpool\_exec<!-- {{#callable:fd_tpool_exec}} -->
The `fd_tpool_exec` function schedules a task to be executed by a specific worker thread in a thread pool, passing various task parameters and ensuring proper synchronization.
- **Inputs**:
    - `tpool`: A pointer to the thread pool (`fd_tpool_t`) where the task will be executed.
    - `worker_idx`: The index of the worker thread within the thread pool that will execute the task.
    - `task`: A function pointer (`fd_tpool_task_t`) representing the task to be executed.
    - `task_tpool`: A pointer to the task-specific thread pool context.
    - `task_t0`: The starting index for the task's range of execution.
    - `task_t1`: The ending index for the task's range of execution.
    - `task_args`: A pointer to the arguments specific to the task.
    - `task_reduce`: A pointer to the reduction context for the task.
    - `task_stride`: The stride value for the task's execution.
    - `task_l0`: The starting index for the task's l-dimension range.
    - `task_l1`: The ending index for the task's l-dimension range.
    - `task_m0`: The starting index for the task's m-dimension range.
    - `task_m1`: The ending index for the task's m-dimension range.
    - `task_n0`: The starting index for the task's n-dimension range.
    - `task_n1`: The ending index for the task's n-dimension range.
- **Control Flow**:
    - Retrieve the worker thread from the thread pool using the provided worker index.
    - Increment the worker's sequence number (`seq0`) to signal a new task dispatch.
    - Set the worker's argument count to `UINT_MAX` to indicate a task dispatch.
    - Assign the task and its parameters to the worker's task and argument fields.
    - Use memory fences (`FD_COMPILER_MFENCE`) to ensure proper memory ordering and visibility of changes.
    - Update the worker's sequence number (`seq0`) again to finalize the task dispatch.
    - If the thread pool is configured with the `FD_TPOOL_OPT_SLEEP` option, wake the worker thread using [`fd_tpool_private_wake`](#fd_tpool_private_wake).
- **Output**: The function does not return a value; it schedules a task for execution by a worker thread in the thread pool.
- **Functions called**:
    - [`fd_tpool_private_worker`](#fd_tpool_private_worker)
    - [`fd_tpool_private_wake`](#fd_tpool_private_wake)


---
### fd\_tpool\_wait<!-- {{#callable:fd_tpool_wait}} -->
The `fd_tpool_wait` function waits for a specific worker thread in a thread pool to complete its task and exit the EXEC state.
- **Inputs**:
    - `tpool`: A constant pointer to the thread pool (`fd_tpool_t`) containing the worker thread to be waited on.
    - `worker_idx`: An unsigned long integer representing the index of the worker thread within the thread pool to wait for.
- **Control Flow**:
    - Retrieve the worker thread from the thread pool using the provided `worker_idx`.
    - Enter an infinite loop to repeatedly check the status of the worker thread.
    - Use memory fences (`FD_COMPILER_MFENCE`) to ensure memory operations are completed in order.
    - Read the `seq1` value from the worker's `seq1` field.
    - If `seq0` equals `seq1`, break out of the loop, indicating the worker is no longer in the EXEC state.
    - If `seq0` does not equal `seq1`, pause briefly using `FD_SPIN_PAUSE` and continue checking.
- **Output**: The function does not return a value; it ensures that the specified worker thread is no longer in the EXEC state before returning control to the caller.
- **Functions called**:
    - [`fd_tpool_private_worker`](#fd_tpool_private_worker)


---
### fd\_tpool\_exec\_all\_taskq<!-- {{#callable:fd_tpool_exec_all_taskq}} -->
The `fd_tpool_exec_all_taskq` function executes a task across a range of worker threads in a thread pool using a task queue approach.
- **Inputs**:
    - `tpool`: A pointer to the thread pool (`fd_tpool_t`) where the tasks will be executed.
    - `t0`: The starting index of the worker threads in the thread pool to be used for task execution.
    - `t1`: The ending index (exclusive) of the worker threads in the thread pool to be used for task execution.
    - `task`: A function pointer to the task (`fd_tpool_task_t`) to be executed by the worker threads.
    - `task_tpool`: A pointer to the task-specific thread pool context.
    - `task_args`: A pointer to the arguments to be passed to the task function.
    - `task_reduce`: A pointer to the reduction context or data structure used by the task.
    - `task_stride`: The stride or step size for the task execution.
    - `task_l0`: The starting index of the task range to be executed.
    - `task_l1`: The ending index (exclusive) of the task range to be executed.
- **Control Flow**:
    - Initialize an array `l_next` with alignment to 128 bytes, setting its first element to `task_l0` and the second to the casted `task_tpool` pointer.
    - Invoke a memory fence to ensure memory operations are completed before proceeding.
    - Call the `fd_tpool_private_exec_all_taskq_node` function with the provided parameters and the initialized `l_next` array to execute the task across the specified range of worker threads.
- **Output**: The function does not return a value; it performs its operations directly on the provided thread pool and task parameters.


# Function Declarations (Public API)

---
### fd\_tpool\_align<!-- {{#callable_declaration:fd_tpool_align}} -->
Return the alignment requirement for a thread pool.
- **Description**: This function provides the alignment requirement for a memory region to be used as a thread pool. It is useful when setting up memory for a thread pool to ensure that the memory is correctly aligned for optimal performance. This function can be called at any time and does not depend on any prior initialization of the thread pool.
- **Inputs**: None
- **Output**: Returns the alignment requirement as an unsigned long integer.
- **See also**: [`fd_tpool_align`](fd_tpool.cxx.driver.md#fd_tpool_align)  (Implementation)


---
### fd\_tpool\_footprint<!-- {{#callable_declaration:fd_tpool_footprint}} -->
Calculate the memory footprint required for a thread pool with a specified maximum number of workers.
- **Description**: This function computes the memory footprint needed to create a thread pool that can support up to a specified maximum number of worker threads. It should be used when planning memory allocation for a thread pool. The function returns zero if the specified number of workers is outside the valid range, which is between 1 and FD_TILE_MAX inclusive. This indicates that the input is invalid and no memory footprint can be calculated.
- **Inputs**:
    - `worker_max`: The maximum number of worker threads the thread pool should support. It must be within the range [1, FD_TILE_MAX]. If the value is outside this range, the function returns 0, indicating an invalid input.
- **Output**: The function returns the size in bytes of the memory footprint required for the thread pool if the input is valid. If the input is invalid, it returns 0.
- **See also**: [`fd_tpool_footprint`](fd_tpool.cxx.driver.md#fd_tpool_footprint)  (Implementation)


---
### fd\_tpool\_init<!-- {{#callable_declaration:fd_tpool_init}} -->
Initializes a thread pool with specified memory and worker constraints.
- **Description**: This function sets up a memory region as a thread pool capable of managing up to a specified number of worker threads. It should be called with a properly aligned memory region and a valid worker count. The function returns a handle to the initialized thread pool, with worker 0 already set up for use. This function is essential for preparing the thread pool before any parallel task execution and acts as a memory fence to ensure proper ordering of operations.
- **Inputs**:
    - `mem`: A pointer to a memory region that will be formatted as a thread pool. This memory must be aligned according to the requirements of fd_tpool_align() and must not be null. The caller retains ownership of this memory.
    - `worker_max`: The maximum number of worker threads the thread pool can support. It must be a positive number within the range [1, FD_TILE_MAX]. If this value is invalid, the function will return NULL.
    - `opt`: A bitwise OR of options that specify additional behaviors for the thread pool. These options are defined by FD_TPOOL_OPT constants.
- **Output**: Returns a pointer to the initialized thread pool on success, or NULL if initialization fails due to invalid input or alignment issues.
- **See also**: [`fd_tpool_init`](fd_tpool.cxx.driver.md#fd_tpool_init)  (Implementation)


---
### fd\_tpool\_fini<!-- {{#callable_declaration:fd_tpool_fini}} -->
Finalizes a thread pool and releases its resources.
- **Description**: This function should be called to properly finalize a thread pool, ensuring that all worker threads are popped and the underlying memory is unformatted. It must be called by a thread that was not part of the thread pool (e.g., a 'worker 0' thread) and no other operations on the thread pool should be in progress or initiated after this call. This function acts as a compiler memory fence, ensuring memory operations are completed before the pool is finalized.
- **Inputs**:
    - `tpool`: A pointer to the thread pool to be finalized. It must not be null, and the caller must ensure that no other operations are in progress on this thread pool. If null, the function logs a warning and returns null.
- **Output**: Returns a pointer to the memory region used by the thread pool on success, or null on failure.
- **See also**: [`fd_tpool_fini`](fd_tpool.cxx.driver.md#fd_tpool_fini)  (Implementation)


---
### fd\_tpool\_worker\_push<!-- {{#callable_declaration:fd_tpool_worker_push}} -->
Adds a worker tile to the thread pool.
- **Description**: Use this function to add a worker tile to an existing thread pool, allowing it to participate in parallel task execution. The function should be called only when no other operations are being performed on the thread pool. The tile to be added must be idle, not the calling tile, and not already part of the pool. The function returns the updated thread pool on success or NULL on failure, logging the reason for failure.
- **Inputs**:
    - `tpool`: A pointer to the thread pool to which the tile will be added. Must not be NULL.
    - `tile_idx`: The index of the tile to be added. Must be non-zero, not the calling tile, and within the valid range of tile indices.
- **Output**: Returns the updated thread pool on success, or NULL on failure.
- **See also**: [`fd_tpool_worker_push`](fd_tpool.cxx.driver.md#fd_tpool_worker_push)  (Implementation)


---
### fd\_tpool\_worker\_pop<!-- {{#callable_declaration:fd_tpool_worker_pop}} -->
Removes the most recently added worker thread from the thread pool.
- **Description**: Use this function to remove the most recently added worker thread from a thread pool when it is no longer needed. This function should be called only when no other operations on the thread pool are in progress or will start during its execution. The function requires that the thread pool is not null and that there is more than one worker in the pool. It also checks that the worker to be removed is idle before proceeding. If these conditions are not met, the function will log a warning and return null. This function acts as a compiler memory fence.
- **Inputs**:
    - `tpool`: A pointer to the thread pool from which the worker is to be removed. Must not be null. The function will return null if this condition is not met.
- **Output**: Returns the thread pool pointer on success, or null if the operation fails due to invalid input or if the worker to be removed is not idle.
- **See also**: [`fd_tpool_worker_pop`](fd_tpool.cxx.driver.md#fd_tpool_worker_pop)  (Implementation)



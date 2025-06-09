# Purpose
The provided C header file, `fd_fibre.h`, defines a lightweight cooperative multitasking framework using fibers. Fibers are user-space threads that allow for non-preemptive multitasking, where the programmer explicitly yields control between fibers. This file provides the necessary data structures and function prototypes to create, manage, and schedule fibers within a program. The core components include the `fd_fibre` structure, which encapsulates the context and state of a fiber, and the `fd_fibre_pipe` structure, which facilitates communication between fibers through a pipe mechanism. The file also defines several functions for initializing, starting, switching, and managing the lifecycle of fibers, as well as scheduling and synchronization utilities.

The header file is designed to be included in other C source files, providing a public API for fiber management. It includes function prototypes for initializing the main fiber, starting new fibers, freeing resources, and switching execution between fibers. Additionally, it offers scheduling functions to manage fiber execution order and timing, as well as pipe functions for inter-fiber communication. The file ensures proper memory alignment and footprint requirements for fiber operations, and it includes a mechanism for handling fatal errors through the `fd_fibre_abort` macro. Overall, this header file provides a comprehensive interface for implementing cooperative multitasking in C applications.
# Imports and Dependencies

---
- `ucontext.h`
- `../fd_util.h`


# Global Variables

---
### fd\_fibre\_current
- **Type**: `fd_fibre_t *`
- **Description**: The `fd_fibre_current` is a global pointer to an `fd_fibre_t` structure, which represents the currently executing fibre in the system. This structure includes context information, stack details, and scheduling parameters for a fibre, allowing for cooperative multitasking within the application.
- **Use**: This variable is used to keep track of the currently active fibre, updating its state during context switches and fibre management operations.


---
### fd\_fibre\_init
- **Type**: `fd_fibre_t *`
- **Description**: The `fd_fibre_init` function is a global function that initializes a new fibre from the current thread and returns a pointer to the `fd_fibre_t` structure representing this fibre. It is essential to call this function before making any other fibre-related calls to ensure proper setup and management of fibres.
- **Use**: This function is used to create and initialize a new fibre from the current thread, setting up the necessary context and stack for fibre execution.


---
### fd\_fibre\_start
- **Type**: `function pointer`
- **Description**: `fd_fibre_start` is a function that initializes and starts a new fibre, which is a lightweight thread of execution. It takes a memory pointer `mem`, a stack size `stack_sz`, a function pointer `fn` to be executed by the fibre, and an argument `arg` to be passed to the function. The function returns a pointer to the newly created `fd_fibre_t` structure representing the fibre.
- **Use**: This function is used to create and prepare a new fibre for execution, allowing for concurrent operations within the application.


---
### fd\_fibre\_pipe\_new
- **Type**: `fd_fibre_pipe_t *`
- **Description**: The `fd_fibre_pipe_new` function is responsible for creating a new instance of a fibre pipe, which is a data structure used to facilitate communication between fibres. It initializes a pipe with a specified number of entries, allowing fibres to send and receive data through it.
- **Use**: This function is used to allocate and initialize a new fibre pipe, setting up the necessary memory and structure for inter-fibre communication.


# Data Structures

---
### fd\_fibre
- **Type**: `struct`
- **Members**:
    - `ctx`: Stores the execution context of the fibre.
    - `stack`: Pointer to the memory allocated for the fibre's stack.
    - `stack_sz`: Size of the stack allocated for the fibre.
    - `fn`: Function pointer to the entry point of the fibre.
    - `arg`: Pointer to the argument passed to the fibre's function.
    - `done`: Indicates whether the fibre has completed execution.
    - `sched_time`: Time at which the fibre is scheduled to run.
    - `next`: Pointer to the next fibre in the scheduling queue.
    - `sentinel`: Used as a marker or flag within the fibre structure.
- **Description**: The `fd_fibre` structure represents a lightweight cooperative thread, or fibre, in a concurrent programming environment. It encapsulates the necessary context and state for managing the execution of a fibre, including its stack, function to execute, and scheduling information. The structure allows for the creation, management, and scheduling of fibres, enabling efficient context switching and execution control in a multi-threaded application. The `fd_fibre` is designed to be used with functions that manage fibre lifecycle, scheduling, and inter-fibre communication.


---
### fd\_fibre\_t
- **Type**: `struct`
- **Members**:
    - `ctx`: Stores the execution context of the fibre.
    - `stack`: Pointer to the memory allocated for the fibre's stack.
    - `stack_sz`: Size of the stack allocated for the fibre.
    - `fn`: Function pointer to the entry function of the fibre.
    - `arg`: Argument to be passed to the fibre's entry function.
    - `done`: Flag indicating whether the fibre has completed execution.
    - `sched_time`: Time at which the fibre is scheduled to run.
    - `next`: Pointer to the next fibre in the scheduling queue.
    - `sentinel`: Used as a marker or flag within the fibre structure.
- **Description**: The `fd_fibre_t` structure represents a lightweight thread of execution, or fibre, in a cooperative multitasking environment. It encapsulates the execution context, stack information, and scheduling details necessary for managing the fibre's lifecycle. The structure includes a function pointer for the fibre's entry point and an argument to be passed to it, as well as scheduling parameters to manage execution order and timing. The `done` flag indicates whether the fibre has finished executing, and the `next` pointer is used to link fibres in a scheduling queue.


---
### fd\_fibre\_pipe
- **Type**: `struct`
- **Members**:
    - `cap`: The capacity of the pipe, indicating the maximum number of entries it can hold.
    - `head`: The index of the next entry to be read from the pipe.
    - `tail`: The index of the next entry to be written to the pipe.
    - `writer`: A pointer to the fibre currently waiting to write to the pipe, if any.
    - `reader`: A pointer to the fibre currently waiting to read from the pipe, if any.
    - `entries`: An array of unsigned long integers representing the data entries in the pipe.
- **Description**: The `fd_fibre_pipe` structure is a data structure used to facilitate communication between fibres by acting as a bounded buffer or queue. It maintains a circular buffer with a specified capacity (`cap`) and uses `head` and `tail` indices to manage the reading and writing of data entries. The structure also keeps track of fibres that are waiting to perform read or write operations through the `writer` and `reader` pointers. This allows for synchronization between fibres, ensuring that data is correctly passed from one fibre to another, with the potential for blocking operations if the pipe is full or empty.


---
### fd\_fibre\_pipe\_t
- **Type**: `struct`
- **Members**:
    - `cap`: Represents the capacity of the pipe.
    - `head`: Indicates the current head index in the pipe.
    - `tail`: Indicates the current tail index in the pipe.
    - `writer`: Points to the fibre currently waiting to write, if any.
    - `reader`: Points to the fibre currently waiting to read, if any.
    - `entries`: Holds the entries in the pipe as an array of unsigned long integers.
- **Description**: The `fd_fibre_pipe_t` structure is a data structure used to facilitate communication between fibres by acting as a pipe. It maintains a circular buffer with a specified capacity, indicated by `cap`, and uses `head` and `tail` indices to manage the buffer's state. The structure also keeps track of fibres waiting to perform read or write operations through the `writer` and `reader` pointers. The `entries` array stores the actual data being passed through the pipe.


# Function Declarations (Public API)

---
### fd\_fibre\_init\_footprint<!-- {{#callable_declaration:fd_fibre_init_footprint}} -->
Returns the memory footprint required for fiber initialization.
- **Description**: Use this function to determine the size of memory needed to initialize a fiber. It calculates the memory footprint based on the size of the fiber structure, ensuring it is aligned to the required boundary. This function should be called before allocating memory for fiber initialization to ensure the memory block is appropriately sized and aligned.
- **Inputs**: None
- **Output**: The function returns an unsigned long representing the memory footprint required for initializing a fiber, aligned to the specified boundary.
- **See also**: [`fd_fibre_init_footprint`](fd_fibre.c.driver.md#fd_fibre_init_footprint)  (Implementation)


---
### fd\_fibre\_init\_align<!-- {{#callable_declaration:fd_fibre_init_align}} -->
Returns the alignment requirement for fiber initialization.
- **Description**: Use this function to obtain the alignment requirement for memory when initializing a fiber using `fd_fibre_init`. This function should be called to ensure that the memory provided for fiber initialization meets the necessary alignment constraints, which is crucial for correct operation. It is typically used in conjunction with `fd_fibre_init_footprint` to allocate memory with the correct size and alignment.
- **Inputs**: None
- **Output**: Returns the alignment requirement as an unsigned long integer, which is the value of `FD_FIBRE_ALIGN`.
- **See also**: [`fd_fibre_init_align`](fd_fibre.c.driver.md#fd_fibre_init_align)  (Implementation)


---
### fd\_fibre\_init<!-- {{#callable_declaration:fd_fibre_init}} -->
Initialize a new fibre from the current thread.
- **Description**: This function initializes a new fibre using the provided memory block and should be called before any other fibre operations. It sets up the fibre's context and prepares it for scheduling. The memory provided must meet the size and alignment requirements specified by `fd_fibre_init_footprint` and `fd_fibre_init_align`. This function should not be called more than once on the same thread, as it is intended to create a fibre from the current thread's context.
- **Inputs**:
    - `mem`: A pointer to a memory block allocated for the fibre. The memory must be properly aligned and sized according to `fd_fibre_init_align` and `fd_fibre_init_footprint`. The caller retains ownership of this memory.
- **Output**: Returns a pointer to the initialized `fd_fibre_t` structure representing the new fibre.
- **See also**: [`fd_fibre_init`](fd_fibre.c.driver.md#fd_fibre_init)  (Implementation)


---
### fd\_fibre\_start\_footprint<!-- {{#callable_declaration:fd_fibre_start_footprint}} -->
Calculate the memory footprint required to start a new fibre.
- **Description**: Use this function to determine the amount of memory needed to start a new fibre with a specified stack size. This is essential for allocating the correct amount of memory before initializing a fibre. The function computes the total memory requirement by aligning the size of the fibre structure and the stack size to the defined alignment boundary. This function should be called before allocating memory for a new fibre to ensure that the memory block is appropriately sized and aligned.
- **Inputs**:
    - `stack_size`: The size of the stack required for the new fibre, specified in bytes. It must be a non-negative value. The function aligns this size to the defined alignment boundary, so the actual memory footprint may be larger than the specified stack size.
- **Output**: Returns the total memory footprint in bytes required to start a new fibre with the specified stack size, including alignment adjustments.
- **See also**: [`fd_fibre_start_footprint`](fd_fibre.c.driver.md#fd_fibre_start_footprint)  (Implementation)


---
### fd\_fibre\_start\_align<!-- {{#callable_declaration:fd_fibre_start_align}} -->
Returns the alignment requirement for starting a fibre.
- **Description**: Use this function to obtain the alignment requirement for memory used in fibre initialization. This is necessary to ensure that the memory allocated for a fibre is correctly aligned, which is a prerequisite for successful fibre operations. Call this function before allocating memory for a fibre to determine the correct alignment.
- **Inputs**: None
- **Output**: Returns an unsigned long representing the alignment requirement for starting a fibre.
- **See also**: [`fd_fibre_start_align`](fd_fibre.c.driver.md#fd_fibre_start_align)  (Implementation)


---
### fd\_fibre\_start<!-- {{#callable_declaration:fd_fibre_start}} -->
Start a new fibre with a specified function and argument.
- **Description**: This function is used to create and start a new fibre, which is a lightweight thread of execution. It must be called after `fd_fibre_init` has been successfully invoked to initialize the fibre system. The function sets up the execution context for the new fibre, including its stack and the function to execute. The current fibre remains active, while the new fibre is prepared to run when scheduled. This function is useful for concurrent programming where multiple tasks need to be managed within the same process.
- **Inputs**:
    - `mem`: A pointer to the memory allocated for the new fibre. The memory must be properly aligned and sized according to `fd_fibre_start_align` and `fd_fibre_start_footprint`.
    - `stack_sz`: The size of the stack for the new fibre. It should be large enough to accommodate the function's execution requirements.
    - `fn`: A function pointer to the entry point of the new fibre. This function will be executed when the fibre is scheduled to run.
    - `arg`: A pointer to the argument that will be passed to the function `fn` when the fibre starts executing.
- **Output**: Returns a pointer to the newly created `fd_fibre_t` structure representing the fibre.
- **See also**: [`fd_fibre_start`](fd_fibre.c.driver.md#fd_fibre_start)  (Implementation)


---
### fd\_fibre\_free<!-- {{#callable_declaration:fd_fibre_free}} -->
Frees the resources of a fibre.
- **Description**: Use this function to release the resources associated with a fibre when it is no longer needed. It is important to ensure that the fibre is not currently running when calling this function. The caller is responsible for managing the memory of the fibre, as this function does not deallocate the memory itself.
- **Inputs**:
    - `fibre`: A pointer to the fd_fibre_t structure representing the fibre to be freed. The fibre must not be currently running, and the caller retains ownership of the memory.
- **Output**: None
- **See also**: [`fd_fibre_free`](fd_fibre.c.driver.md#fd_fibre_free)  (Implementation)


---
### fd\_fibre\_swap<!-- {{#callable_declaration:fd_fibre_swap}} -->
Switches execution to a specified fibre.
- **Description**: Use this function to switch the execution context to the fibre specified by the parameter. This function should be called when you want to pause the current fibre and resume execution in another fibre. It is important to ensure that the fibre you are switching to is not marked as done, as the function will return immediately in such cases. Additionally, if the specified fibre is the same as the current fibre, the function will also return immediately without making any changes. This function updates the global variable `fd_fibre_current` to reflect the currently running fibre before performing the switch.
- **Inputs**:
    - `swap_to`: A pointer to the `fd_fibre_t` structure representing the fibre to switch to. The fibre must not be null and should not be marked as done. The caller retains ownership of the fibre.
- **Output**: None
- **See also**: [`fd_fibre_swap`](fd_fibre.c.driver.md#fd_fibre_swap)  (Implementation)


---
### fd\_fibre\_set\_clock<!-- {{#callable_declaration:fd_fibre_set_clock}} -->
Set a custom clock function for the fibre scheduler.
- **Description**: Use this function to specify a custom clock function that the fibre scheduler will use to obtain the current time. This is useful when you need to integrate the fibre system with a specific timing source or when testing with a mock clock. The function should be called before any scheduling operations that depend on the clock. The provided clock function must return a long integer representing the current time. If no clock function is set, the default behavior of the scheduler is undefined.
- **Inputs**:
    - `clock`: A pointer to a function that returns a long integer representing the current time. The function must not be null, and the caller retains ownership of the function pointer. If an invalid function is provided, the behavior of the scheduler is undefined.
- **Output**: None
- **See also**: [`fd_fibre_set_clock`](fd_fibre.c.driver.md#fd_fibre_set_clock)  (Implementation)


---
### fd\_fibre\_yield<!-- {{#callable_declaration:fd_fibre_yield}} -->
Yield execution of the current fibre to allow other fibres to run.
- **Description**: This function is used to yield the execution of the currently running fibre, allowing other fibres in the system to execute. It is typically called when a fibre has completed its current task and is willing to let other fibres run, or when it needs to wait for some condition to be met. This function should be used in a cooperative multitasking environment where fibres voluntarily yield control to ensure fair scheduling. It must be called from within a fibre context, and it assumes that the fibre system has been properly initialized.
- **Inputs**: None
- **Output**: None
- **See also**: [`fd_fibre_yield`](fd_fibre.c.driver.md#fd_fibre_yield)  (Implementation)


---
### fd\_fibre\_wait<!-- {{#callable_declaration:fd_fibre_wait}} -->
Stops the current fibre from running for a specified duration.
- **Description**: Use this function to pause the execution of the currently running fibre for a specified number of nanoseconds. This function should be called when you want to yield control and allow other fibres to execute, effectively implementing a delay in the current fibre's execution. It is important to ensure that a fibre scheduler is initialized and running before calling this function, as it relies on the scheduler to manage the fibre's execution state. If the specified wait time is less than one nanosecond, the function will default to a minimum wait time of one nanosecond. This function does not perform any action if no scheduler is present.
- **Inputs**:
    - `wait_ns`: The number of nanoseconds to wait. If less than 1, the function defaults to a wait time of 1 nanosecond. The caller retains ownership of this value.
- **Output**: None
- **See also**: [`fd_fibre_wait`](fd_fibre.c.driver.md#fd_fibre_wait)  (Implementation)


---
### fd\_fibre\_wait\_until<!-- {{#callable_declaration:fd_fibre_wait_until}} -->
Stops the current fibre until a specified time.
- **Description**: Use this function to pause the execution of the currently running fibre until the specified resume time in nanoseconds. This function should be called when you want to ensure that the current fibre does not resume execution until a certain point in time. It is important to note that this function requires a scheduler to be set; otherwise, it will return immediately without any effect. The function ensures that the fibre will not resume before the specified time, and if the specified time is in the past, it will adjust to resume as soon as possible. This function should be used in a context where fibre scheduling is properly initialized and managed.
- **Inputs**:
    - `resume_time_ns`: The time in nanoseconds at which the current fibre should resume execution. If this time is in the past, it will be adjusted to the current time plus one nanosecond to ensure the fibre resumes as soon as possible. The caller retains ownership of this value.
- **Output**: None
- **See also**: [`fd_fibre_wait_until`](fd_fibre.c.driver.md#fd_fibre_wait_until)  (Implementation)


---
### fd\_fibre\_wake<!-- {{#callable_declaration:fd_fibre_wake}} -->
Wakes a specified fibre for scheduling.
- **Description**: Use this function to wake a fibre that is not currently executing, allowing it to be scheduled for execution. This function should be called when you want to resume a fibre that has been previously suspended or is waiting. It updates the scheduling time of the specified fibre and adds it to the schedule, unless the fibre is the currently executing one, in which case it does nothing. Ensure that the fibre passed is valid and initialized before calling this function.
- **Inputs**:
    - `fibre`: A pointer to the fd_fibre_t structure representing the fibre to be woken. Must not be null and should point to a valid fibre that is not the currently executing one. If the fibre is the current one, the function will return immediately without making any changes.
- **Output**: None
- **See also**: [`fd_fibre_wake`](fd_fibre.c.driver.md#fd_fibre_wake)  (Implementation)


---
### fd\_fibre\_schedule<!-- {{#callable_declaration:fd_fibre_schedule}} -->
Adds a fibre to the scheduling queue based on its wake time.
- **Description**: Use this function to add a fibre to the scheduling queue, ensuring it is placed in the correct position according to its scheduled wake time. This function should be called when a fibre needs to be scheduled for execution at a specific time. It is important to ensure that the fibre is properly initialized and not currently running before calling this function. The function assumes that a valid clock has been set using `fd_fibre_set_clock`. If the clock is not set, the function will abort execution.
- **Inputs**:
    - `fibre`: A pointer to the `fd_fibre_t` structure representing the fibre to be scheduled. The `fibre` must be properly initialized and not null. The function will handle the fibre's insertion into the schedule based on its `sched_time` attribute.
- **Output**: None
- **See also**: [`fd_fibre_schedule`](fd_fibre.c.driver.md#fd_fibre_schedule)  (Implementation)


---
### fd\_fibre\_schedule\_run<!-- {{#callable_declaration:fd_fibre_schedule_run}} -->
Runs the current fibre schedule and returns the time of the next ready fibre.
- **Description**: This function executes the current fibre schedule, selecting and running fibres based on their scheduled times. It should be called when you want to process the fibre queue and execute any fibres that are ready to run. The function will return immediately if there are no fibres ready to execute, providing the time when the next fibre will be ready. If the schedule is empty, it returns -1. Ensure that the fibre system is properly initialized and that fibres have been scheduled before calling this function.
- **Inputs**: None
- **Output**: Returns the time of the next ready fibre, or -1 if there are no fibres in the schedule.
- **See also**: [`fd_fibre_schedule_run`](fd_fibre.c.driver.md#fd_fibre_schedule_run)  (Implementation)


---
### fd\_fibre\_pipe\_align<!-- {{#callable_declaration:fd_fibre_pipe_align}} -->
Return the alignment requirement for a fibre pipe.
- **Description**: Use this function to determine the alignment requirement for memory allocations intended for fibre pipes. This is essential when allocating memory for a fibre pipe to ensure proper alignment, which can affect performance and correctness. The function does not require any parameters and can be called at any time to retrieve the alignment value.
- **Inputs**: None
- **Output**: Returns the alignment requirement as an unsigned long integer.
- **See also**: [`fd_fibre_pipe_align`](fd_fibre.c.driver.md#fd_fibre_pipe_align)  (Implementation)


---
### fd\_fibre\_pipe\_footprint<!-- {{#callable_declaration:fd_fibre_pipe_footprint}} -->
Calculate the memory footprint required for a fibre pipe with a specified number of entries.
- **Description**: Use this function to determine the amount of memory needed to allocate a fibre pipe that can hold a specified number of entries. This is useful when planning memory allocation for fibre communication, ensuring that enough space is reserved for the pipe structure and its entries. The function should be called before creating a new fibre pipe to ensure that the memory allocation is sufficient.
- **Inputs**:
    - `entries`: The number of entries the fibre pipe should be able to hold. It must be a non-negative integer, as negative values would not make sense for a count of entries.
- **Output**: Returns the total size in bytes required to store the fibre pipe structure and its entries.
- **See also**: [`fd_fibre_pipe_footprint`](fd_fibre.c.driver.md#fd_fibre_pipe_footprint)  (Implementation)


---
### fd\_fibre\_pipe\_new<!-- {{#callable_declaration:fd_fibre_pipe_new}} -->
Create a new fibre pipe in the provided memory.
- **Description**: This function initializes a new fibre pipe structure in the provided memory block, setting up the necessary internal state for managing a pipe with the specified number of entries. It is essential to ensure that the memory block is properly aligned and large enough to accommodate the pipe structure and its entries. The function should be called when a new communication channel between fibres is needed, and the memory must remain valid for the lifetime of the pipe.
- **Inputs**:
    - `mem`: A pointer to a memory block where the pipe will be initialized. The memory must be aligned according to FD_FIBRE_ALIGN and large enough to hold the pipe structure and its entries. The caller retains ownership and must ensure the memory remains valid for the pipe's lifetime.
    - `entries`: The number of entries the pipe can hold. It must be a positive integer, and the function will configure the pipe to manage this many entries.
- **Output**: Returns a pointer to the initialized fd_fibre_pipe_t structure within the provided memory block.
- **See also**: [`fd_fibre_pipe_new`](fd_fibre.c.driver.md#fd_fibre_pipe_new)  (Implementation)


---
### fd\_fibre\_pipe\_write<!-- {{#callable_declaration:fd_fibre_pipe_write}} -->
Write a value into a fibre pipe with optional timeout.
- **Description**: This function attempts to write a specified value into a fibre pipe, potentially blocking if the pipe is full. It is useful for inter-fibre communication where data needs to be passed from one fibre to another. The function will block until space becomes available in the pipe or until the specified timeout period elapses. It should be called when the pipe is expected to have space or when the caller is willing to wait for space to become available. The function returns immediately if there is space available, otherwise, it waits for the specified timeout duration. If the timeout is reached without space becoming available, the function returns with a timeout indication.
- **Inputs**:
    - `pipe`: A pointer to the fd_fibre_pipe_t structure representing the pipe to write to. Must not be null, and the pipe should be properly initialized before calling this function.
    - `value`: The ulong value to be written into the pipe. There are no restrictions on the value itself.
    - `timeout`: The maximum time in nanoseconds to wait for space to become available in the pipe. If set to a negative value, the function will wait indefinitely until space is available.
- **Output**: Returns 0 if the value was successfully written to the pipe. Returns 1 if the operation timed out before space became available.
- **See also**: [`fd_fibre_pipe_write`](fd_fibre.c.driver.md#fd_fibre_pipe_write)  (Implementation)


---
### fd\_fibre\_pipe\_read<!-- {{#callable_declaration:fd_fibre_pipe_read}} -->
Read a value from a fibre pipe with an optional timeout.
- **Description**: This function attempts to read a value from the specified fibre pipe. If the pipe is empty, the function will block until data becomes available or the specified timeout period elapses. It is useful in scenarios where inter-fibre communication is required, and the reader can afford to wait for data up to a certain time limit. The function must be called with a valid pipe and a non-null pointer for storing the read value. If the timeout is reached without reading any data, the function returns a timeout indication.
- **Inputs**:
    - `pipe`: A pointer to the fd_fibre_pipe_t structure from which to read. Must not be null and should be properly initialized.
    - `value`: A pointer to an unsigned long where the read value will be stored. Must not be null.
    - `timeout`: The maximum time in nanoseconds to wait for data to become available. If set to a negative value, the function may wait indefinitely.
- **Output**: Returns 0 if a value was successfully read, or 1 if the operation timed out without reading any data.
- **See also**: [`fd_fibre_pipe_read`](fd_fibre.c.driver.md#fd_fibre_pipe_read)  (Implementation)



# Purpose
The provided C source code implements a cooperative threading library, often referred to as "fibers" or "fibres," which allows multiple execution contexts to be managed within a single operating system thread. This library provides the necessary functions to initialize, start, switch between, and manage the lifecycle of fibers. Key components include functions for initializing a fiber ([`fd_fibre_init`](#fd_fibre_init)), starting a new fiber ([`fd_fibre_start`](#fd_fibre_start)), switching execution to a different fiber ([`fd_fibre_swap`](#fd_fibre_swap)), and managing fiber scheduling ([`fd_fibre_schedule`](#fd_fibre_schedule), [`fd_fibre_schedule_run`](#fd_fibre_schedule_run)). The code also includes mechanisms for yielding execution ([`fd_fibre_yield`](#fd_fibre_yield)), waiting for a specific time ([`fd_fibre_wait`](#fd_fibre_wait), [`fd_fibre_wait_until`](#fd_fibre_wait_until)), and waking fibers ([`fd_fibre_wake`](#fd_fibre_wake)).

Additionally, the code provides a simple inter-fiber communication mechanism through a pipe-like structure (`fd_fibre_pipe_t`), which allows fibers to write to and read from a shared buffer with functions like [`fd_fibre_pipe_write`](#fd_fibre_pipe_write) and [`fd_fibre_pipe_read`](#fd_fibre_pipe_read). This pipe mechanism includes timeout capabilities, allowing fibers to wait for data to become available or space to write data. The library is designed to be used as part of a larger application, providing a lightweight alternative to traditional threading by allowing multiple fibers to be managed within a single thread, thus reducing context-switching overhead and improving performance in certain scenarios.
# Imports and Dependencies

---
- `fd_fibre.h`
- `stdio.h`
- `stdlib.h`
- `string.h`
- `errno.h`


# Global Variables

---
### fd\_fibre\_current
- **Type**: `fd_fibre_t*`
- **Description**: The `fd_fibre_current` is a global pointer variable of type `fd_fibre_t*` that is initialized to `NULL`. It is used to keep track of the currently executing fibre in a cooperative threading environment.
- **Use**: This variable is used to store the reference to the fibre that is currently active, allowing the system to manage context switching between fibres.


---
### fd\_fibre\_scheduler
- **Type**: `fd_fibre_t*`
- **Description**: The `fd_fibre_scheduler` is a global pointer variable of type `fd_fibre_t*`, which is used to reference the fibre that acts as the scheduler in a cooperative threading environment. It is initialized to `NULL` and is set to point to the current fibre when the scheduling process is initiated.
- **Use**: This variable is used to switch execution to the fibre scheduler during fibre management operations such as yielding or waiting.


---
### fd\_fibre\_schedule\_queue
- **Type**: `fd_fibre_t[1]`
- **Description**: The `fd_fibre_schedule_queue` is a global array of `fd_fibre_t` structures, initialized with a single element. This element acts as a sentinel node in a circular linked list, with its `next` pointer pointing to itself, indicating the end of the list.
- **Use**: This variable is used as the head of the scheduling queue for fibers, managing the order in which fibers are scheduled to run.


# Functions

---
### fd\_fibre\_run\_fn<!-- {{#callable:fd_fibre_run_fn}} -->
The `fd_fibre_run_fn` function executes a user-defined function associated with a fibre and marks the fibre as done.
- **Inputs**:
    - `vp`: A pointer to a `fd_fibre_t` structure, which contains the user function and its argument to be executed.
- **Control Flow**:
    - Cast the input pointer `vp` to a `fd_fibre_t` pointer named `fibre`.
    - Invoke the user-defined function `fibre->fn` with the argument `fibre->arg`.
    - Set the `done` flag of the fibre to 1, indicating the fibre has completed its execution.
- **Output**: The function does not return any value; it modifies the state of the fibre by setting its `done` flag.


---
### fd\_fibre\_init\_footprint<!-- {{#callable:fd_fibre_init_footprint}} -->
The `fd_fibre_init_footprint` function calculates the memory footprint required for initializing a fibre, ensuring it is aligned to a specified boundary.
- **Inputs**: None
- **Control Flow**:
    - The function calls `fd_ulong_align_up` with the size of `fd_fibre_t` and `FD_FIBRE_ALIGN` as arguments.
    - It returns the result of the alignment calculation.
- **Output**: The function returns an unsigned long integer representing the aligned size of the `fd_fibre_t` structure.


---
### fd\_fibre\_init\_align<!-- {{#callable:fd_fibre_init_align}} -->
The `fd_fibre_init_align` function returns the alignment requirement for initializing a fibre.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of `FD_FIBRE_ALIGN`.
- **Output**: The function outputs an `ulong` representing the alignment requirement for fibre initialization.


---
### fd\_fibre\_init<!-- {{#callable:fd_fibre_init}} -->
The `fd_fibre_init` function initializes a fibre structure in the provided memory and sets up its execution context.
- **Inputs**:
    - `mem`: A pointer to a memory block where the fibre structure will be initialized.
- **Control Flow**:
    - Cast the provided memory pointer to a `fd_fibre_t` pointer and assign it to `fibre`.
    - Clear the memory of the `fibre` structure using `memset` to initialize all fields to zero.
    - Set the `stack` and `stack_sz` fields of the `fibre` to `NULL` and `0`, respectively.
    - Obtain the address of the `ctx` field of the `fibre` and store it in `ctx`.
    - Call `getcontext` to initialize the `ctx` with the current context; if it fails, print an error message and abort the program.
    - Set the global `fd_fibre_current` to point to the newly initialized `fibre`.
    - Return the pointer to the initialized `fibre`.
- **Output**: A pointer to the initialized `fd_fibre_t` structure.


---
### fd\_fibre\_start\_footprint<!-- {{#callable:fd_fibre_start_footprint}} -->
The `fd_fibre_start_footprint` function calculates the memory footprint required to start a fibre, including the fibre structure and its stack, aligned to a specific boundary.
- **Inputs**:
    - `stack_size`: The size of the stack required for the fibre, specified in bytes.
- **Control Flow**:
    - The function first calculates the aligned size of the `fd_fibre_t` structure using `fd_ulong_align_up` with `FD_FIBRE_ALIGN`.
    - It then calculates the aligned size of the provided `stack_size` using the same alignment function and constant.
    - The function returns the sum of these two aligned sizes, representing the total memory footprint required.
- **Output**: The function returns an unsigned long integer representing the total aligned memory footprint required to start a fibre, including both the fibre structure and its stack.


---
### fd\_fibre\_start\_align<!-- {{#callable:fd_fibre_start_align}} -->
The `fd_fibre_start_align` function returns the alignment requirement for starting a fibre.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of the macro `FD_FIBRE_ALIGN`.
- **Output**: The function returns an `ulong` representing the alignment requirement for starting a fibre.


---
### fd\_fibre\_start<!-- {{#callable:fd_fibre_start}} -->
The `fd_fibre_start` function initializes and prepares a new fibre for execution, setting up its stack, context, and function to be executed.
- **Inputs**:
    - `mem`: A pointer to the memory location where the fibre structure and its stack will be allocated.
    - `stack_sz`: The size of the stack to be allocated for the new fibre.
    - `fn`: A function pointer to the function that the fibre will execute.
    - `arg`: A pointer to the argument that will be passed to the function `fn` when the fibre is executed.
- **Control Flow**:
    - Check if `fd_fibre_current` is NULL, indicating that `fd_fibre_init` has not been called, and abort if true.
    - Calculate the aligned memory address for the stack within the provided memory block.
    - Initialize a new `fd_fibre_t` structure at the beginning of the memory block and zero out its contents.
    - Set the stack size and stack pointer in the fibre structure.
    - Assign the function pointer `fn` and its argument `arg` to the fibre structure.
    - Copy the current fibre's context to the new fibre's context to initialize it.
    - Set the `uc_link` of the new fibre's context to point to the current fibre's context, establishing a successor context.
    - Configure the stack for the new fibre's context with the specified stack pointer and size.
    - Create a new execution context for the fibre using `makecontext`, specifying `fd_fibre_run_fn` as the function to execute.
- **Output**: Returns a pointer to the newly initialized `fd_fibre_t` structure, representing the new fibre.


---
### fd\_fibre\_free<!-- {{#callable:fd_fibre_free}} -->
The `fd_fibre_free` function is a placeholder for freeing a fibre, but it does not perform any operations as the caller is responsible for managing the memory.
- **Inputs**:
    - `fibre`: A pointer to an `fd_fibre_t` structure representing the fibre to be freed.
- **Control Flow**:
    - The function takes a pointer to an `fd_fibre_t` structure as an argument.
    - It does not perform any operations on the fibre, as indicated by the comment that the caller owns the memory.
    - The fibre pointer is cast to void to suppress unused variable warnings.
- **Output**: The function does not return any value or perform any operations.


---
### fd\_fibre\_swap<!-- {{#callable:fd_fibre_swap}} -->
The `fd_fibre_swap` function switches the execution context to a specified fibre, provided it is not already the current fibre and is not marked as done.
- **Inputs**:
    - `swap_to`: A pointer to the `fd_fibre_t` structure representing the fibre to which execution should be switched.
- **Control Flow**:
    - Check if the `swap_to` fibre is the current fibre; if so, return immediately.
    - Check if the `swap_to` fibre is marked as done; if so, return immediately.
    - Set the `uc_link` of the `swap_to` fibre's context to point to the current fibre's context, establishing a return path.
    - Store the current fibre in a temporary variable `fibre_pop` for later restoration.
    - Update `fd_fibre_current` to point to the `swap_to` fibre, making it the new current fibre.
    - Attempt to switch the execution context from `fibre_pop` to `swap_to` using `swapcontext`; if it fails, log an error and abort the program.
    - After returning from the context switch, restore `fd_fibre_current` to the original fibre stored in `fibre_pop`.
- **Output**: The function does not return a value; it modifies the global state by changing the current execution context to the specified fibre.


---
### fd\_fibre\_set\_clock<!-- {{#callable:fd_fibre_set_clock}} -->
The `fd_fibre_set_clock` function sets the global clock function pointer for the fibre scheduler.
- **Inputs**:
    - `clock`: A function pointer to a clock function that returns a long integer, representing the current time.
- **Control Flow**:
    - Assigns the provided clock function pointer to the global variable `fd_fibre_clock`.
- **Output**: This function does not return any value.


---
### fd\_fibre\_yield<!-- {{#callable:fd_fibre_yield}} -->
The `fd_fibre_yield` function allows the currently executing fibre to yield control, enabling other fibres to run.
- **Inputs**: None
- **Control Flow**:
    - The function calls [`fd_fibre_wait`](#fd_fibre_wait) with an argument of `0`, indicating that the current fibre should yield immediately without waiting.
    - The [`fd_fibre_wait`](#fd_fibre_wait) function checks if a scheduler is available; if not, it returns immediately.
    - If a scheduler is present, it calculates the wake time for the current fibre, schedules it, and then swaps execution to the scheduler fibre.
- **Output**: The function does not return any value.
- **Functions called**:
    - [`fd_fibre_wait`](#fd_fibre_wait)


---
### fd\_fibre\_wait<!-- {{#callable:fd_fibre_wait}} -->
The `fd_fibre_wait` function pauses the execution of the current fibre for a specified duration by scheduling it to resume at a calculated future time and then switching control to the fibre scheduler.
- **Inputs**:
    - `wait_ns`: The number of nanoseconds to wait before the current fibre is scheduled to resume execution.
- **Control Flow**:
    - Check if the fibre scheduler is available; if not, return immediately.
    - Calculate the wake time by adding the current time from `fd_fibre_clock()` to `wait_ns`, ensuring a minimum wait of 1 nanosecond.
    - Set the current fibre's `sched_time` to the calculated wake time.
    - Schedule the current fibre using [`fd_fibre_schedule`](#fd_fibre_schedule).
    - Switch execution to the fibre scheduler using [`fd_fibre_swap`](#fd_fibre_swap).
- **Output**: The function does not return a value; it modifies the scheduling state of the current fibre and switches execution to the scheduler.
- **Functions called**:
    - [`fd_fibre_schedule`](#fd_fibre_schedule)
    - [`fd_fibre_swap`](#fd_fibre_swap)


---
### fd\_fibre\_wait\_until<!-- {{#callable:fd_fibre_wait_until}} -->
The `fd_fibre_wait_until` function suspends the execution of the current fibre until a specified resume time, allowing other fibres to run in the meantime.
- **Inputs**:
    - `resume_time_ns`: The time in nanoseconds at which the current fibre should resume execution.
- **Control Flow**:
    - Retrieve the current time using `fd_fibre_clock()` and store it in `now`.
    - Check if `resume_time_ns` is less than or equal to `now`; if so, set `resume_time_ns` to `now + 1` to ensure the fibre waits at least a minimal time.
    - If `fd_fibre_scheduler` is `NULL`, return immediately as no scheduling can occur without a scheduler.
    - Set the `sched_time` of the current fibre (`fd_fibre_current`) to `resume_time_ns`.
    - Schedule the current fibre by calling `fd_fibre_schedule(fd_fibre_current)`.
    - Switch execution to the fibre scheduler by calling `fd_fibre_swap(fd_fibre_scheduler)`.
- **Output**: The function does not return a value; it modifies the state of the current fibre and the scheduler to manage execution timing.
- **Functions called**:
    - [`fd_fibre_schedule`](#fd_fibre_schedule)
    - [`fd_fibre_swap`](#fd_fibre_swap)


---
### fd\_fibre\_wake<!-- {{#callable:fd_fibre_wake}} -->
The `fd_fibre_wake` function updates the scheduling time of a specified fibre and adds it to the scheduling queue if it is not the currently executing fibre.
- **Inputs**:
    - `fibre`: A pointer to an `fd_fibre_t` structure representing the fibre to be woken up and scheduled.
- **Control Flow**:
    - Check if the specified fibre is the currently executing fibre; if so, return immediately without making any changes.
    - Set the `sched_time` of the specified fibre to the current time obtained from `fd_fibre_clock()`.
    - Call [`fd_fibre_schedule`](#fd_fibre_schedule) to add the specified fibre to the scheduling queue.
- **Output**: This function does not return a value; it modifies the state of the specified fibre and the scheduling queue.
- **Functions called**:
    - [`fd_fibre_schedule`](#fd_fibre_schedule)


---
### fd\_fibre\_schedule<!-- {{#callable:fd_fibre_schedule}} -->
The `fd_fibre_schedule` function manages the scheduling of a fibre by removing it from the current schedule and reinserting it at the appropriate position based on its wake time.
- **Inputs**:
    - `fibre`: A pointer to the `fd_fibre_t` structure representing the fibre to be scheduled.
- **Control Flow**:
    - Check if the global clock function `fd_fibre_clock` is set; if not, abort the operation.
    - Initialize `cur_fibre` to the head of the schedule queue.
    - Iterate through the schedule queue to remove the specified `fibre` by updating the `next` pointer of the preceding fibre.
    - Iterate through the schedule queue again to find the correct position to insert the `fibre` based on its `sched_time`.
    - Insert the `fibre` into the schedule by updating the `next` pointers of the preceding and current fibres.
- **Output**: The function does not return a value; it modifies the scheduling queue in place.


---
### fd\_fibre\_schedule\_run<!-- {{#callable:fd_fibre_schedule_run}} -->
The `fd_fibre_schedule_run` function manages the execution of scheduled fibres, returning the time of the next ready fibre or -1 if no fibres are scheduled.
- **Inputs**: None
- **Control Flow**:
    - Set the currently running fibre as the scheduler by assigning `fd_fibre_current` to `fd_fibre_scheduler`.
    - Enter an infinite loop to process the fibre schedule queue.
    - Retrieve the next fibre from the schedule queue using `fd_fibre_schedule_queue->next`.
    - Check if the current fibre is a sentinel; if so, return -1 indicating no fibres are scheduled.
    - Get the current time using `fd_fibre_clock()` and compare it with the scheduled time of the current fibre.
    - If the current fibre's scheduled time is greater than the current time, return the scheduled time of the current fibre, indicating when it will be ready to run.
    - Remove the current fibre from the schedule queue by updating `fd_fibre_schedule_queue->next`.
    - Check if the current fibre is not done; if not, swap execution to the current fibre using `fd_fibre_swap(cur_fibre)`.
- **Output**: Returns the time of the next ready fibre or -1 if there are no fibres in the schedule.
- **Functions called**:
    - [`fd_fibre_swap`](#fd_fibre_swap)


---
### fd\_fibre\_pipe\_align<!-- {{#callable:fd_fibre_pipe_align}} -->
The `fd_fibre_pipe_align` function returns the alignment requirement of the `fd_fibre_pipe_t` type.
- **Inputs**: None
- **Control Flow**:
    - The function calls the `alignof` operator on the `fd_fibre_pipe_t` type to determine its alignment requirement.
    - The result of the `alignof` operation is returned as the function's output.
- **Output**: The function returns an `ulong` value representing the alignment requirement of the `fd_fibre_pipe_t` type.


---
### fd\_fibre\_pipe\_footprint<!-- {{#callable:fd_fibre_pipe_footprint}} -->
The `fd_fibre_pipe_footprint` function calculates the memory footprint required for a fibre pipe with a specified number of entries.
- **Inputs**:
    - `entries`: The number of entries that the fibre pipe will hold.
- **Control Flow**:
    - Calculate the size of the fibre pipe structure using `sizeof(fd_fibre_pipe_t)`.
    - Multiply the number of entries by the size of an `ulong` to determine the additional memory required for the entries.
    - Add the size of the fibre pipe structure to the calculated memory for entries to get the total footprint.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the fibre pipe with the specified number of entries.


---
### fd\_fibre\_pipe\_new<!-- {{#callable:fd_fibre_pipe_new}} -->
The `fd_fibre_pipe_new` function initializes a new fibre pipe structure in the provided memory with a specified number of entries.
- **Inputs**:
    - `mem`: A pointer to the memory location where the fibre pipe structure will be initialized.
    - `entries`: The number of entries the fibre pipe can hold, representing its capacity.
- **Control Flow**:
    - Cast the provided memory pointer to a `fd_fibre_pipe_t` pointer to initialize the pipe structure.
    - Calculate the address for the entries array by offsetting from the pipe structure.
    - Set the pipe's capacity (`cap`) to the specified number of entries.
    - Initialize the `head` and `tail` indices to 0, indicating an empty pipe.
    - Set the `reader` and `writer` pointers to NULL, indicating no current reader or writer.
    - Assign the calculated entries array address to the `entries` field of the pipe.
    - Return the initialized pipe structure.
- **Output**: A pointer to the newly initialized `fd_fibre_pipe_t` structure.


---
### fd\_fibre\_pipe\_write<!-- {{#callable:fd_fibre_pipe_write}} -->
The `fd_fibre_pipe_write` function attempts to write a value to a fibre pipe, waiting for space to become available or timing out if necessary.
- **Inputs**:
    - `pipe`: A pointer to the `fd_fibre_pipe_t` structure representing the pipe to which the value will be written.
    - `value`: The `ulong` value to be written into the pipe.
    - `timeout`: A `long` representing the maximum time to wait for space to become available in the pipe before timing out.
- **Control Flow**:
    - Initialize `prev_writer` to the current writer of the pipe and calculate the timeout timestamp.
    - Enter a loop that continues until there is space in the pipe or the operation times out.
    - Calculate the used and free space in the pipe.
    - If there is free space, break out of the loop to write the value.
    - If no free space is available, set the current fibre as the writer and check if the timeout has been reached.
    - If the timeout is reached, restore the previous writer and return a timeout indication (1).
    - If not timed out, schedule the current fibre to wake up at the timeout timestamp and switch to the scheduler.
    - Once space is available, write the value to the pipe, increment the head, and wake up any waiting reader.
    - Restore the previous writer and return a success indication (0).
- **Output**: Returns 0 on successful write, or 1 if the operation times out.
- **Functions called**:
    - [`fd_fibre_schedule`](#fd_fibre_schedule)
    - [`fd_fibre_swap`](#fd_fibre_swap)


---
### fd\_fibre\_pipe\_read<!-- {{#callable:fd_fibre_pipe_read}} -->
The `fd_fibre_pipe_read` function attempts to read a value from a fibre pipe, waiting until data is available or a timeout occurs.
- **Inputs**:
    - `pipe`: A pointer to the `fd_fibre_pipe_t` structure representing the fibre pipe from which to read.
    - `value`: A pointer to an `ulong` where the read value will be stored if successful.
    - `timeout`: A `long` representing the maximum time to wait for data to become available, in the same units as the fibre clock.
- **Control Flow**:
    - Store the current reader of the pipe in `prev_reader`.
    - Calculate the timeout timestamp by adding the current time from `fd_fibre_clock()` to the `timeout` value.
    - Enter a loop that continues until data is available or the timeout is reached.
    - Calculate the number of used slots in the pipe by subtracting `tail` from `head`.
    - If data is available (`used` is non-zero), break out of the loop.
    - If no data is available, update the pipe's reader to the current fibre and check if the timeout has been reached.
    - If the timeout is reached, restore the previous reader and return a timeout indication (1).
    - If not timed out, set the current fibre's schedule time to the timeout timestamp, schedule it, and switch to the scheduler.
    - Once data is available, retrieve the value from the pipe's entries using the current `tail` index, store it in `value`, and increment the `tail`.
    - If there is a waiting writer, schedule the current fibre and switch to the writer.
    - Restore the previous reader and return success (0).
- **Output**: Returns 0 on successful read, or 1 if a timeout occurs before data becomes available.
- **Functions called**:
    - [`fd_fibre_schedule`](#fd_fibre_schedule)
    - [`fd_fibre_swap`](#fd_fibre_swap)



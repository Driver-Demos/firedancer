# Purpose
This C source code file is designed to test and demonstrate the functionality of a fiber-based concurrency library, likely named `fd_fibre`. The code includes a variety of functions that simulate concurrent execution using fibers, which are lightweight threads of execution. The file contains several test functions ([`fn1`](#fn1), [`fn2`](#fn2), [`fn3`](#fn3), [`test1`](#test1), [`test2`](#test2), [`test_pipe_producer`](#test_pipe_producer), [`test_pipe_consumer`](#test_pipe_consumer), [`pipe_producer_main`](#pipe_producer_main), [`pipe_filter_main`](#pipe_filter_main), and [`pipe_consumer_main`](#pipe_consumer_main)) that are executed within fibers to demonstrate scheduling, waiting, and message-passing capabilities. The tests involve creating fibers, scheduling them, and using synthetic timing to simulate real-time execution. The [`run_pipe_test`](#run_pipe_test) and [`run_test_pipe_filter`](#run_test_pipe_filter) functions specifically test the message-passing capabilities between fibers using a pipe mechanism, where messages are sent and received between producer and consumer fibers.

The code is structured to initialize and manage fibers, allocate necessary memory, and execute a series of tests that highlight the library's ability to handle concurrent tasks. The [`main`](#main) function orchestrates the execution of these tests, setting up the environment, running the tests, and cleaning up resources. The use of a synthetic clock ([`my_clock`](#my_clock)) and the manipulation of a global time variable (`now`) allow the tests to simulate time-dependent behavior without relying on real-time delays. This file serves as both a demonstration and a validation tool for the `fd_fibre` library, showcasing its capabilities in handling concurrent execution and inter-fiber communication.
# Imports and Dependencies

---
- `stdio.h`
- `stdlib.h`
- `fd_fibre.h`


# Global Variables

---
### now
- **Type**: `long`
- **Description**: The variable `now` is a global variable of type `long` that represents a synthetic clock time in the program. It is used to simulate the passage of time for testing purposes, particularly in the context of fiber scheduling and message passing between fibers.
- **Use**: `now` is used to track and update the current time in the synthetic clock, allowing the program to simulate time-based events and scheduling.


---
### done
- **Type**: `int`
- **Description**: The `done` variable is a global integer flag initialized to 0. It is used to control the execution flow of certain functions, particularly in the context of fiber scheduling and testing.
- **Use**: The `done` variable is used as a flag to signal when certain tests or operations should terminate, such as in the `test1` and `test2` functions.


# Data Structures

---
### pipe\_producer\_args
- **Type**: `struct`
- **Members**:
    - `output`: A pointer to an fd_fibre_pipe_t structure, representing the output pipe for the producer.
    - `expire`: A long integer representing the expiration time for the producer's operation.
    - `period`: A long integer representing the period between successive operations of the producer.
- **Description**: The `pipe_producer_args` structure is used to encapsulate the arguments required by a pipe producer function in a fibre-based system. It includes a pointer to an output pipe, an expiration time to determine how long the producer should run, and a period to specify the interval between each message production. This structure facilitates the configuration and control of message production in a concurrent environment.


---
### pipe\_producer\_args\_t
- **Type**: `struct`
- **Members**:
    - `output`: A pointer to an fd_fibre_pipe_t structure, representing the output pipe for the producer.
    - `expire`: A long integer representing the expiration time for the producer's operation.
    - `period`: A long integer representing the period between message transmissions.
- **Description**: The `pipe_producer_args_t` structure is used to encapsulate the arguments required by a pipe producer function in a fibre-based system. It includes a pointer to an output pipe, an expiration time to determine how long the producer should run, and a period to specify the interval between sending messages. This structure facilitates the configuration and control of message production in a concurrent environment using fibres.


---
### pipe\_filter\_args
- **Type**: `struct`
- **Members**:
    - `input`: A pointer to an fd_fibre_pipe_t structure representing the input pipe.
    - `out1`: A pointer to an fd_fibre_pipe_t structure representing the first output pipe.
    - `out2`: A pointer to an fd_fibre_pipe_t structure representing the second output pipe.
    - `period`: A long integer representing the period for processing messages.
- **Description**: The `pipe_filter_args` structure is designed to hold the arguments necessary for a pipe filter operation in a fibre-based system. It contains pointers to an input pipe and two output pipes, allowing messages to be received from the input and distributed to the outputs based on certain conditions. The `period` member specifies the time interval for processing messages, which is used to manage the timing of operations within the fibre system.


---
### pipe\_filter\_args\_t
- **Type**: `struct`
- **Members**:
    - `input`: A pointer to an input pipe for receiving messages.
    - `out1`: A pointer to the first output pipe for distributing messages.
    - `out2`: A pointer to the second output pipe for distributing messages.
    - `period`: A long integer representing the period for message processing.
- **Description**: The `pipe_filter_args_t` structure is used to define the arguments for a pipe filter function, which receives messages from an input pipe and distributes them to two output pipes based on certain conditions. The structure contains pointers to the input and output pipes, as well as a period value that dictates the timing for message processing. This setup is typically used in a fiber-based concurrent programming environment to manage message flow between different components.


---
### pipe\_consumer\_args
- **Type**: `struct`
- **Members**:
    - `name`: A constant character pointer representing the name of the consumer.
    - `input`: A pointer to an fd_fibre_pipe_t structure, representing the input pipe for the consumer.
    - `expire`: A long integer indicating the expiration time for the consumer's operation.
- **Description**: The `pipe_consumer_args` structure is designed to encapsulate the arguments required for a pipe consumer in a fibre-based system. It includes a name for identification, an input pipe from which the consumer will read messages, and an expiration time that dictates how long the consumer should continue its operation. This structure is used to pass necessary parameters to the consumer function, ensuring that it has all the information needed to process messages from the input pipe within a specified timeframe.


---
### pipe\_consumer\_args\_t
- **Type**: `struct`
- **Members**:
    - `name`: A constant character pointer representing the name of the consumer.
    - `input`: A pointer to an fd_fibre_pipe_t structure, representing the input pipe from which messages are consumed.
    - `expire`: A long integer representing the expiration time for the consumer to stop reading messages.
- **Description**: The `pipe_consumer_args_t` structure is used to encapsulate the arguments required by a pipe consumer function in a fibre-based system. It includes a name for identification, an input pipe for receiving messages, and an expiration time to determine how long the consumer should continue processing messages. This structure is essential for managing the lifecycle and behavior of a consumer fibre in a message-passing system.


# Functions

---
### fn1<!-- {{#callable:fn1}} -->
The function `fn1` prints a message to the standard output indicating it is running.
- **Inputs**:
    - `vp`: A void pointer that is not used within the function.
- **Control Flow**:
    - The function casts the input parameter `vp` to void to explicitly ignore it.
    - It prints the message "running fn1\n" to the standard output using `printf`.
    - It flushes the output buffer to ensure the message is immediately displayed using `fflush(stdout)`.
- **Output**: The function does not return any value.


---
### fn2<!-- {{#callable:fn2}} -->
The function `fn2` prints a message to the standard output indicating it is running and flushes the output buffer.
- **Inputs**:
    - `vp`: A void pointer that is not used within the function.
- **Control Flow**:
    - The function casts the input parameter `vp` to void to explicitly indicate it is unused.
    - It prints the message "running fn2\n" to the standard output using `printf`.
    - The function then calls `fflush(stdout)` to ensure the output buffer is flushed immediately, making the message appear on the console without delay.
- **Output**: The function does not return any value as its return type is `void`.


---
### fn3<!-- {{#callable:fn3}} -->
The function `fn3` prints a message to the standard output indicating it is running and flushes the output buffer.
- **Inputs**:
    - `vp`: A void pointer that is not used within the function.
- **Control Flow**:
    - The function takes a single argument, a void pointer `vp`, which is explicitly cast to void to indicate it is unused.
    - A message "running fn3\n" is printed to the standard output using `printf`.
    - The output buffer is flushed immediately using `fflush(stdout)` to ensure the message is displayed promptly.
- **Output**: The function does not return any value.


---
### my\_clock<!-- {{#callable:my_clock}} -->
The `my_clock` function returns the current value of the global variable `now`, which represents a synthetic clock time.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of the global variable `now`.
- **Output**: The function outputs a `long` integer representing the current synthetic clock time stored in the global variable `now`.


---
### test1<!-- {{#callable:test1}} -->
The `test1` function repeatedly prints the current time and a specified period, then waits for the specified period until a global `done` flag is set.
- **Inputs**:
    - `vp`: A pointer to a `long` array where the first element represents the period in some time unit.
- **Control Flow**:
    - Cast the input `vp` to a `long` pointer and store it in `arg`.
    - Extract the period from `arg[0]`.
    - Enter a loop that continues until the global `done` flag is set to a non-zero value.
    - Inside the loop, print the current period and the global `now` time variable.
    - Flush the standard output buffer to ensure the message is printed immediately.
    - Call [`fd_fibre_wait`](fd_fibre.c.driver.md#fd_fibre_wait) with the period to pause execution for the specified duration.
- **Output**: The function does not return any value; it operates in a loop until the `done` flag is set.
- **Functions called**:
    - [`fd_fibre_wait`](fd_fibre.c.driver.md#fd_fibre_wait)


---
### test2<!-- {{#callable:test2}} -->
The `test2` function waits until a specified time and then sets a global flag to indicate completion.
- **Inputs**:
    - `vp`: A pointer to a long integer, which represents the 'done' time until which the function waits.
- **Control Flow**:
    - Cast the input pointer `vp` to a `long*` and store it in `arg`.
    - Extract the 'done' time from `arg[0]` and store it in `done_time`.
    - Print a message indicating the start of the waiting period and flush the output buffer.
    - Call `fd_fibre_wait_until(done_time)` to wait until the specified 'done' time.
    - Print a message indicating the end of the waiting period and flush the output buffer.
    - Set the global variable `done` to 1 to indicate that the waiting period has completed.
- **Output**: The function does not return a value, but it sets the global variable `done` to 1 after waiting until the specified time.
- **Functions called**:
    - [`fd_fibre_wait_until`](fd_fibre.c.driver.md#fd_fibre_wait_until)


---
### test\_pipe\_producer<!-- {{#callable:test_pipe_producer}} -->
The `test_pipe_producer` function sends messages through a pipe at a fixed rate for a specified duration.
- **Inputs**:
    - `vp`: A pointer to a `fd_fibre_pipe_t` structure, which represents the pipe through which messages will be sent.
- **Control Flow**:
    - The function begins by casting the input `vp` to a `fd_fibre_pipe_t` pointer named `pipe`.
    - It prints a starting message and flushes the output buffer.
    - It initializes timing variables: `run_period` for the message interval, `run_duration` for the total run time, `send_time` for the next message send time, and `run_end` for the end time of the function.
    - A message counter `msg` is initialized to zero.
    - The function enters a loop that continues until the current time `now` is less than `run_end`.
    - Inside the loop, it waits until `send_time` using [`fd_fibre_wait_until`](fd_fibre.c.driver.md#fd_fibre_wait_until).
    - It attempts to write the current message `msg` to the pipe using [`fd_fibre_pipe_write`](fd_fibre.c.driver.md#fd_fibre_pipe_write).
    - If the write fails, it prints an error message and exits the program.
    - The `send_time` is incremented by `run_period` for the next iteration.
    - The message counter `msg` is incremented.
    - After the loop, it prints a finished message.
- **Output**: The function does not return a value; it performs its operations as a side effect by sending messages through the pipe.
- **Functions called**:
    - [`fd_fibre_wait_until`](fd_fibre.c.driver.md#fd_fibre_wait_until)
    - [`fd_fibre_pipe_write`](fd_fibre.c.driver.md#fd_fibre_pipe_write)


---
### test\_pipe\_consumer<!-- {{#callable:test_pipe_consumer}} -->
The `test_pipe_consumer` function reads messages from a pipe for a specified duration and prints each received message.
- **Inputs**:
    - `vp`: A pointer to a `fd_fibre_pipe_t` object, which represents the pipe from which messages are read.
- **Control Flow**:
    - The function starts by casting the input `vp` to a `fd_fibre_pipe_t` pointer named `pipe`.
    - It initializes `run_period` to 1,000,000 (1 millisecond) and `run_duration` to 1,000,000,000 (1 second), calculating `run_end` as the current time plus `run_duration`.
    - A loop runs while the current time (`now`) is less than `run_end`.
    - Within the loop, it attempts to read a message from the pipe with a timeout of `run_period`.
    - If the read operation fails (indicated by a non-zero return value), it prints an error message and exits the program.
    - If a message is successfully read, it prints the message and the current time.
- **Output**: The function does not return a value; it outputs messages to the standard output and may terminate the program on read failure.
- **Functions called**:
    - [`fd_fibre_pipe_read`](fd_fibre.c.driver.md#fd_fibre_pipe_read)


---
### run\_pipe\_test<!-- {{#callable:run_pipe_test}} -->
The `run_pipe_test` function initializes and runs a test of a producer-consumer model using fibers and a communication pipe, scheduling and executing the fibers until completion.
- **Inputs**: None
- **Control Flow**:
    - Prints 'pipe test starting' to indicate the beginning of the test.
    - Sets the global variable `now` to zero for consistent output timing.
    - Allocates memory for a communication pipe and initializes it with a specified number of entries.
    - Allocates memory for two fibers, one for the producer and one for the consumer, and initializes them with the respective functions and the pipe as an argument.
    - Schedules the producer and consumer fibers for execution.
    - Enters a loop to run the scheduled fibers until no more fibers are scheduled, updating the `now` variable to the next scheduled event time.
    - Frees the memory allocated for the fibers and the pipe after the test is complete.
    - Prints 'pipe test complete' to indicate the end of the test.
- **Output**: The function does not return any value; it performs its operations and outputs status messages to the console.
- **Functions called**:
    - [`fd_fibre_start_align`](fd_fibre.c.driver.md#fd_fibre_start_align)
    - [`fd_fibre_start_footprint`](fd_fibre.c.driver.md#fd_fibre_start_footprint)
    - [`fd_fibre_pipe_new`](fd_fibre.c.driver.md#fd_fibre_pipe_new)
    - [`fd_fibre_start`](fd_fibre.c.driver.md#fd_fibre_start)
    - [`fd_fibre_schedule`](fd_fibre.c.driver.md#fd_fibre_schedule)
    - [`fd_fibre_schedule_run`](fd_fibre.c.driver.md#fd_fibre_schedule_run)
    - [`fd_fibre_free`](fd_fibre.c.driver.md#fd_fibre_free)


---
### pipe\_producer\_main<!-- {{#callable:pipe_producer_main}} -->
The `pipe_producer_main` function sends messages periodically through a pipe until a specified expiration time is reached.
- **Inputs**:
    - `vp_args`: A pointer to a `pipe_producer_args_t` structure containing the output pipe, expiration time, and period for sending messages.
- **Control Flow**:
    - Cast the `vp_args` to a `pipe_producer_args_t` pointer to access the arguments.
    - Initialize the output pipe, expiration time, and period from the arguments.
    - Calculate the initial send time and expiration time based on the current time (`now`).
    - Initialize a message counter starting at 1.
    - Enter a loop that continues until the current time is less than the expiration time.
    - Within the loop, wait until the next scheduled send time using [`fd_fibre_wait_until`](fd_fibre.c.driver.md#fd_fibre_wait_until).
    - Attempt to write the current message to the output pipe with a timeout equal to the period.
    - If the write operation fails, print an error message and exit the program.
    - Increment the send time by the period for the next iteration.
    - Increment the message counter.
    - Print a completion message after exiting the loop.
- **Output**: The function does not return a value; it sends messages to a pipe and exits when the expiration time is reached or an error occurs.
- **Functions called**:
    - [`fd_fibre_wait_until`](fd_fibre.c.driver.md#fd_fibre_wait_until)
    - [`fd_fibre_pipe_write`](fd_fibre.c.driver.md#fd_fibre_pipe_write)


---
### pipe\_filter\_main<!-- {{#callable:pipe_filter_main}} -->
The `pipe_filter_main` function reads messages from an input pipe and distributes them to two output pipes based on divisibility conditions.
- **Inputs**:
    - `vp_args`: A pointer to a `pipe_filter_args_t` structure containing the input pipe, two output pipes, and a period for timeout.
- **Control Flow**:
    - Cast the `vp_args` to a `pipe_filter_args_t` pointer to access the input and output pipes and the period.
    - Initialize the timeout with the period value.
    - Enter an infinite loop to continuously read messages from the input pipe.
    - Attempt to read a message from the input pipe with a timeout; break the loop if reading fails.
    - Check if the message is divisible by 2; if true, write it to the first output pipe and exit on failure.
    - Check if the message is divisible by 3; if true, write it to the second output pipe and exit on failure.
    - Print a completion message after exiting the loop.
- **Output**: The function does not return a value; it performs its operations through side effects on the pipes and prints messages to the console.
- **Functions called**:
    - [`fd_fibre_pipe_read`](fd_fibre.c.driver.md#fd_fibre_pipe_read)
    - [`fd_fibre_pipe_write`](fd_fibre.c.driver.md#fd_fibre_pipe_write)


---
### pipe\_consumer\_main<!-- {{#callable:pipe_consumer_main}} -->
The `pipe_consumer_main` function reads messages from a pipe until a specified expiration time and prints each received message.
- **Inputs**:
    - `vp_args`: A pointer to a `pipe_consumer_args_t` structure containing the input pipe, expiration time, and consumer name.
- **Control Flow**:
    - Cast the `vp_args` to a `pipe_consumer_args_t` pointer to access the input arguments.
    - Calculate the expiration time by adding the current time (`now`) to the `expire` value from the arguments.
    - Enter a loop that continues until the current time exceeds the expiration time.
    - Within the loop, attempt to read a message from the input pipe with a timeout equal to the remaining time until expiration.
    - If the read operation is successful, print the received message along with the consumer's name.
    - If the read operation fails, break out of the loop.
    - After exiting the loop, print a message indicating that the consumer has finished.
- **Output**: The function does not return a value; it outputs messages to the standard output.
- **Functions called**:
    - [`fd_fibre_pipe_read`](fd_fibre.c.driver.md#fd_fibre_pipe_read)


---
### run\_test\_pipe\_filter<!-- {{#callable:run_test_pipe_filter}} -->
The `run_test_pipe_filter` function sets up and executes a test scenario involving a producer, a filter, and two consumer fibers using pipes for inter-fiber communication.
- **Inputs**: None
- **Control Flow**:
    - Initialize variables for pipe entries and stack size.
    - Allocate memory and create three pipes for communication between fibers.
    - Set the period to 1 ms and expiration time to 20 ms for the fibers.
    - Initialize arguments for the producer, filter, and two consumer fibers, specifying their input/output pipes and timing parameters.
    - Allocate memory and start fibers for the producer, filter, and two consumers using the specified arguments.
    - Schedule the fibers to be run by the fiber scheduler.
    - Enter a loop to run the scheduled fibers until no more fibers are scheduled (indicated by a timeout of -1).
    - Free the memory allocated for the fibers and pipes after execution is complete.
- **Output**: The function does not return any value; it performs its operations as a side effect by running the test scenario.
- **Functions called**:
    - [`fd_fibre_start_align`](fd_fibre.c.driver.md#fd_fibre_start_align)
    - [`fd_fibre_start_footprint`](fd_fibre.c.driver.md#fd_fibre_start_footprint)
    - [`fd_fibre_pipe_new`](fd_fibre.c.driver.md#fd_fibre_pipe_new)
    - [`fd_fibre_start`](fd_fibre.c.driver.md#fd_fibre_start)
    - [`fd_fibre_schedule`](fd_fibre.c.driver.md#fd_fibre_schedule)
    - [`fd_fibre_schedule_run`](fd_fibre.c.driver.md#fd_fibre_schedule_run)
    - [`fd_fibre_free`](fd_fibre.c.driver.md#fd_fibre_free)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes and manages the execution of multiple fibres, including scheduling and running tests for fibre synchronization and communication.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - The function begins by initializing the main fibre using [`fd_fibre_init`](fd_fibre.c.driver.md#fd_fibre_init) and allocating memory for it.
    - Three additional fibres are created for functions `fn1`, `fn2`, and `fn3`, each with a specified stack size, and are started using [`fd_fibre_start`](fd_fibre.c.driver.md#fd_fibre_start).
    - Each of these fibres is swapped in and out of execution using [`fd_fibre_swap`](fd_fibre.c.driver.md#fd_fibre_swap), allowing them to complete their tasks.
    - The memory allocated for these fibres is freed after their execution is complete.
    - The function sets a custom clock using [`fd_fibre_set_clock`](fd_fibre.c.driver.md#fd_fibre_set_clock) to facilitate fibre scheduling based on time.
    - Four test fibres are created with different periods and a done time, and are scheduled using [`fd_fibre_schedule`](fd_fibre.c.driver.md#fd_fibre_schedule).
    - A loop runs the fibre schedule using [`fd_fibre_schedule_run`](fd_fibre.c.driver.md#fd_fibre_schedule_run) until no more fibres are scheduled, updating the current time with the returned timeout value.
    - The memory for the test fibres is freed after execution.
    - The function calls [`run_pipe_test`](#run_pipe_test) and [`run_test_pipe_filter`](#run_test_pipe_filter) to execute additional tests involving fibre communication through pipes.
    - Finally, the main fibre is freed, and its allocated memory is released before the function returns 0.
- **Output**: The function returns an integer value of 0, indicating successful execution.
- **Functions called**:
    - [`fd_fibre_init_align`](fd_fibre.c.driver.md#fd_fibre_init_align)
    - [`fd_fibre_init_footprint`](fd_fibre.c.driver.md#fd_fibre_init_footprint)
    - [`fd_fibre_init`](fd_fibre.c.driver.md#fd_fibre_init)
    - [`fd_fibre_start_align`](fd_fibre.c.driver.md#fd_fibre_start_align)
    - [`fd_fibre_start_footprint`](fd_fibre.c.driver.md#fd_fibre_start_footprint)
    - [`fd_fibre_start`](fd_fibre.c.driver.md#fd_fibre_start)
    - [`fd_fibre_swap`](fd_fibre.c.driver.md#fd_fibre_swap)
    - [`fd_fibre_free`](fd_fibre.c.driver.md#fd_fibre_free)
    - [`fd_fibre_set_clock`](fd_fibre.c.driver.md#fd_fibre_set_clock)
    - [`fd_fibre_schedule`](fd_fibre.c.driver.md#fd_fibre_schedule)
    - [`fd_fibre_schedule_run`](fd_fibre.c.driver.md#fd_fibre_schedule_run)
    - [`run_pipe_test`](#run_pipe_test)
    - [`run_test_pipe_filter`](#run_test_pipe_filter)



# Purpose
This C++ source code file is designed to test the functionality of a transactional system using a multi-threaded approach. The code primarily revolves around the [`TestState`](#TestStateTestState) class, which manages the state of the test, including a pointer to a `fd_funk_t` object representing the transactional system and a workspace pointer. The [`TestState`](#TestStateTestState) class also includes methods for selecting transactions and counting them. The code utilizes POSIX threads to create a multi-threaded environment where each thread performs operations on the transactional system, such as preparing, publishing, and querying records. The [`work_thread`](#work_thread) function is the core of the threaded operations, where each thread continuously performs transactions and record manipulations based on the current run state.

The main function initializes the environment, sets up the transactional system, and manages the lifecycle of the test, including starting, pausing, and stopping the threads. It uses a loop to simulate transaction preparation and publishing, and it controls the execution flow using a shared `runstate` variable. The code also includes mechanisms for verifying the integrity of the transactional system and cleaning up resources at the end of the test. This file is an executable test harness that leverages the `fd_funk` library to validate the behavior of transactions under concurrent conditions, making it a critical component for ensuring the robustness of the transactional system.
# Imports and Dependencies

---
- `test_funk_common.hpp`
- `cstdio`
- `pthread.h`


# Global Variables

---
### runstate
- **Type**: `int`
- **Description**: The `runstate` variable is a global static volatile integer that represents the current state of the program's execution. It is initialized to the `STARTUP` state, which is part of an enumeration that includes `STARTUP`, `PAUSE`, `RUN`, and `DONE` states.
- **Use**: This variable is used to control the flow of execution in the `work_thread` function, determining when threads should start, pause, run, or terminate.


---
### runcnt
- **Type**: `volatile uint`
- **Description**: The `runcnt` variable is a global, static, and volatile unsigned integer that is used to keep track of the number of active operations or threads currently running in the system. It is incremented and decremented by worker threads to reflect their active status.
- **Use**: `runcnt` is used to monitor the number of active threads during the execution of the program, ensuring synchronization and proper management of thread states.


---
### insertcnt
- **Type**: `volatile uint`
- **Description**: The `insertcnt` variable is a global, volatile unsigned integer that is used to keep track of the number of insert operations performed by the threads in the program. It is initialized to zero and is incremented atomically within the `work_thread` function whenever a record is successfully inserted.
- **Use**: This variable is used to count and report the total number of insert operations completed by all threads during the execution of the program.


# Data Structures

---
### TestState<!-- {{#data_structure:TestState}} -->
- **Type**: `class`
- **Members**:
    - `_funk`: A pointer to an fd_funk_t object, representing the main functional unit or context.
    - `_wksp`: A pointer to an fd_wksp_t object, representing the workspace associated with the funk.
    - `_pairs`: An array of ThreadPair structures, each containing a reference to the TestState and a record offset.
- **Description**: The TestState class is designed to manage and coordinate the state of a test involving multiple threads and transactions. It holds pointers to a functional unit (_funk) and its associated workspace (_wksp), and maintains an array of ThreadPair structures to manage thread-specific state. The class provides methods to pick transactions and count them, facilitating the execution and management of concurrent operations in a multi-threaded environment.
- **Member Functions**:
    - [`TestState::TestState`](#TestStateTestState)
    - [`TestState::pick_txn`](#TestStatepick_txn)
    - [`TestState::count_txns`](#TestStatecount_txns)

**Methods**

---
#### TestState::TestState<!-- {{#callable:TestState::TestState}} -->
The `TestState` constructor initializes a `TestState` object by setting up its internal state and creating a set of `ThreadPair` objects for managing thread-specific data.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` object, which represents the main data structure that the `TestState` will operate on.
- **Control Flow**:
    - The constructor initializes the `_funk` member with the provided `funk` pointer.
    - It initializes the `_wksp` member by calling `fd_funk_wksp(funk)` to obtain the workspace associated with the `funk`.
    - A loop iterates over a range defined by `NUM_THREADS`, creating a `ThreadPair` for each thread, associating it with the current `TestState` instance and a unique record offset.
- **Output**: The constructor does not return a value; it initializes the `TestState` object in place.
- **Functions called**:
    - [`fd_funk_wksp`](fd_funk.h.driver.md#fd_funk_wksp)
- **See also**: [`TestState`](#TestState)  (Data Structure)


---
#### TestState::pick\_txn<!-- {{#callable:TestState::pick_txn}} -->
The `pick_txn` function selects a random transaction from a list of transactions that are either unfrozen or not frozen, based on the input parameter.
- **Inputs**:
    - `unfrozen`: A boolean flag indicating whether to include only unfrozen transactions in the selection.
- **Control Flow**:
    - Initialize an array `txns` to store pointers to transactions and a counter `txns_cnt` to track the number of transactions added.
    - If `unfrozen` is false or the last published transaction is not frozen, add a NULL pointer to the `txns` array and increment `txns_cnt`.
    - Initialize an iterator `txn_iter` to iterate over all transactions using [`fd_funk_txn_all_iter_new`](fd_funk_txn.c.driver.md#fd_funk_txn_all_iter_new).
    - Iterate over all transactions using a for loop with [`fd_funk_txn_all_iter_done`](fd_funk_txn.c.driver.md#fd_funk_txn_all_iter_done) and [`fd_funk_txn_all_iter_next`](fd_funk_txn.c.driver.md#fd_funk_txn_all_iter_next).
    - For each transaction, check if `unfrozen` is false or the transaction is not frozen using [`fd_funk_txn_is_frozen`](fd_funk_txn.h.driver.md#fd_funk_txn_is_frozen).
    - If the transaction meets the criteria, assert that `txns_cnt` is less than `MAX_TXN_CNT`, add the transaction to the `txns` array, and increment `txns_cnt`.
    - Select a random transaction from the `txns` array using `lrand48()%txns_cnt` and return it.
- **Output**: A pointer to a randomly selected transaction from the list of eligible transactions.
- **Functions called**:
    - [`fd_funk_last_publish_is_frozen`](fd_funk.h.driver.md#fd_funk_last_publish_is_frozen)
    - [`fd_funk_txn_all_iter_new`](fd_funk_txn.c.driver.md#fd_funk_txn_all_iter_new)
    - [`fd_funk_txn_all_iter_done`](fd_funk_txn.c.driver.md#fd_funk_txn_all_iter_done)
    - [`fd_funk_txn_all_iter_next`](fd_funk_txn.c.driver.md#fd_funk_txn_all_iter_next)
    - [`fd_funk_txn_all_iter_ele`](fd_funk_txn.c.driver.md#fd_funk_txn_all_iter_ele)
    - [`fd_funk_txn_is_frozen`](fd_funk_txn.h.driver.md#fd_funk_txn_is_frozen)
- **See also**: [`TestState`](#TestState)  (Data Structure)


---
#### TestState::count\_txns<!-- {{#callable:TestState::count_txns}} -->
The `count_txns` function counts the number of transactions in the `_funk` data structure using an iterator.
- **Inputs**: None
- **Control Flow**:
    - Initialize a transaction iterator `txn_iter` for iterating over all transactions in `_funk`.
    - Set a counter `cnt` to zero to keep track of the number of transactions.
    - Use a for-loop to iterate over all transactions using [`fd_funk_txn_all_iter_new`](fd_funk_txn.c.driver.md#fd_funk_txn_all_iter_new), [`fd_funk_txn_all_iter_done`](fd_funk_txn.c.driver.md#fd_funk_txn_all_iter_done), and [`fd_funk_txn_all_iter_next`](fd_funk_txn.c.driver.md#fd_funk_txn_all_iter_next) functions.
    - Increment the counter `cnt` for each transaction encountered in the loop.
    - Return the counter `cnt` as the total number of transactions.
- **Output**: The function returns an unsigned integer representing the total count of transactions in the `_funk` data structure.
- **Functions called**:
    - [`fd_funk_txn_all_iter_new`](fd_funk_txn.c.driver.md#fd_funk_txn_all_iter_new)
    - [`fd_funk_txn_all_iter_done`](fd_funk_txn.c.driver.md#fd_funk_txn_all_iter_done)
    - [`fd_funk_txn_all_iter_next`](fd_funk_txn.c.driver.md#fd_funk_txn_all_iter_next)
- **See also**: [`TestState`](#TestState)  (Data Structure)



---
### ThreadPair<!-- {{#data_structure:TestState::ThreadPair}} -->
- **Type**: `struct`
- **Members**:
    - `_state`: A pointer to a TestState object, representing the state associated with the thread.
    - `_rec_offset`: An unsigned long integer representing the record offset for the thread.
- **Description**: The `ThreadPair` struct is a simple data structure used to associate a `TestState` object with a specific record offset, represented by an unsigned long integer. It is used within the `TestState` class to manage and organize thread-specific data, particularly in a multi-threaded environment where each thread operates on a distinct record offset. The struct is part of an array `_pairs` that holds such associations for a predefined number of threads (`NUM_THREADS`).


# Functions

---
### work\_thread<!-- {{#callable:work_thread}} -->
The `work_thread` function is a worker thread routine that performs transactional operations on a shared data structure, managing records and ensuring data consistency through a series of atomic operations and state checks.
- **Inputs**:
    - `arg`: A pointer to a `TestState::ThreadPair` structure, which contains a reference to the `TestState` object and a record offset.
- **Control Flow**:
    - The function begins by extracting the `ThreadPair` from the `arg` and initializes a key with the record offset.
    - It waits for the `runstate` to change from `STARTUP` to begin processing and continues until `runstate` is `DONE`.
    - When `runstate` is `PAUSE`, the thread waits without processing.
    - When `runstate` is `RUN`, it increments the `runcnt` counter atomically to indicate active processing.
    - Within the `RUN` state, it repeatedly picks a transaction, prepares a record, allocates and writes a value, and publishes the record.
    - After publishing, it increments the `insertcnt` counter atomically.
    - It then enters a loop to query and verify the record's value, ensuring data consistency, and breaks out once verified.
    - The key is incremented by `NUM_THREADS` to prepare for the next iteration.
    - When exiting the `RUN` state, it decrements the `runcnt` counter atomically.
- **Output**: The function returns `NULL` upon completion, indicating the end of the thread's execution.
- **Functions called**:
    - [`fd_funk_rec_prepare`](fd_funk_rec.c.driver.md#fd_funk_rec_prepare)
    - [`fd_funk_val_truncate`](fd_funk_val.c.driver.md#fd_funk_val_truncate)
    - [`fd_funk_alloc`](fd_funk.h.driver.md#fd_funk_alloc)
    - [`fd_funk_rec_publish`](fd_funk_rec.c.driver.md#fd_funk_rec_publish)
    - [`fd_funk_rec_query_try_global`](fd_funk_rec.c.driver.md#fd_funk_rec_query_try_global)
    - [`fd_funk_val_sz`](fd_funk_val.h.driver.md#fd_funk_val_sz)
    - [`fd_funk_val`](fd_funk_val.h.driver.md#fd_funk_val)
    - [`fd_funk_rec_query_test`](fd_funk_rec.c.driver.md#fd_funk_rec_query_test)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes a shared memory workspace, creates and manages multiple threads to perform transactions on a data structure, and coordinates the execution and verification of these transactions.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of character pointers listing all the arguments.
- **Control Flow**:
    - Initialize the random number generator with a fixed seed for reproducibility.
    - Call `fd_boot` to perform any necessary setup with the command-line arguments.
    - Determine the maximum number of transactions and records, and obtain the NUMA index for shared memory allocation.
    - Create a new anonymous workspace with gigantic page size and allocate memory for the `fd_funk` data structure.
    - Initialize the `fd_funk` data structure and join it to the allocated memory.
    - Create a `TestState` object to manage the state of the transactions and threads.
    - Spawn `NUM_THREADS` threads, each executing the `work_thread` function with a specific `ThreadPair` from `TestState`.
    - Set the `runstate` to `PAUSE` to initially pause the execution of threads.
    - Initialize a transaction ID structure `xid` to zero.
    - Enter a loop to perform 10 iterations of transaction operations.
    - In each iteration, publish two transactions and prepare 20 new transactions with incremented transaction IDs.
    - Set the `runstate` to `RUN` to allow threads to execute transactions, log the number of transactions, and sleep for 2 seconds.
    - Pause the execution by setting `runstate` to `PAUSE` and wait for all threads to finish their current operations.
    - Optionally verify the integrity of the `fd_funk` data structure if `FD_FUNK_HANDHOLDING` is defined.
    - After the loop, set `runstate` to `DONE` to signal threads to terminate.
    - Join all threads to ensure they have completed execution.
    - Leave and delete the `fd_funk` data structure, freeing the allocated memory.
    - Print a success message and return 0 to indicate successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution of the program.
- **Functions called**:
    - [`fd_funk_align`](fd_funk.c.driver.md#fd_funk_align)
    - [`fd_funk_footprint`](fd_funk.c.driver.md#fd_funk_footprint)
    - [`fd_funk_join`](fd_funk.c.driver.md#fd_funk_join)
    - [`fd_funk_new`](fd_funk.c.driver.md#fd_funk_new)
    - [`fd_funk_txn_publish`](fd_funk_txn.c.driver.md#fd_funk_txn_publish)
    - [`fd_funk_txn_prepare`](fd_funk_txn.c.driver.md#fd_funk_txn_prepare)
    - [`fd_funk_verify`](fd_funk.c.driver.md#fd_funk_verify)
    - [`fd_funk_leave`](fd_funk.c.driver.md#fd_funk_leave)
    - [`fd_funk_delete`](fd_funk.c.driver.md#fd_funk_delete)



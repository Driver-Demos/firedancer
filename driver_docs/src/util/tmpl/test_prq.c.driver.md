# Purpose
This C source code file is designed to test the functionality of priority queues implemented using a heap data structure. It defines a structure `event_t` to represent events with timeouts and values, and then uses this structure to create three different types of priority queues: `eventq`, `maxq`, and `implq`. Each queue type is defined by including the `fd_prq.c` file with specific macros that customize the behavior of the priority queue, such as sorting order and timeout handling. The code includes functions to test the integrity of these heaps, ensuring that they maintain the correct order properties for both minimum and maximum heaps, as well as a custom implicit heap that uses a cross-multiplication technique for ordering.

The main function orchestrates a series of tests to validate the construction, insertion, removal, and destruction of these priority queues. It uses a random number generator to simulate event scheduling and cancellation, ensuring that the queues handle these operations correctly. The code also includes conditional compilation for additional testing features when hosted environments are available. This file is primarily a test suite for verifying the correctness and robustness of the priority queue implementations, rather than a library or application intended for direct use in other software.
# Imports and Dependencies

---
- `../fd_util.h`
- `sys/types.h`
- `sys/wait.h`
- `unistd.h`
- `fd_prq.c`


# Data Structures

---
### event
- **Type**: `struct`
- **Members**:
    - `timeout`: Represents the primary timeout value for the event.
    - `timeout2`: A secondary timeout value used for testing, which must be strictly positive.
    - `val`: An array of three long integers used to store additional values related to the event.
- **Description**: The `event` structure is designed to represent an event with timing characteristics, primarily used in priority queue implementations. It contains two timeout values, `timeout` and `timeout2`, where `timeout2` is specifically used for testing purposes and must be positive. Additionally, the structure includes an array `val` of three long integers, which can store supplementary data associated with the event. This structure is utilized in various queue implementations, such as event queues, max queues, and implicit queues, to manage and sort events based on their timeout values.


---
### event\_t
- **Type**: `struct`
- **Members**:
    - `timeout`: A long integer representing the primary timeout value for the event.
    - `timeout2`: A long integer used for implementation-specific purposes, strictly positive.
    - `val`: An array of three long integers used to store additional values associated with the event.
- **Description**: The `event_t` structure is designed to represent an event with timing characteristics, primarily used in priority queue implementations. It contains two timeout values, `timeout` and `timeout2`, which are used to determine the order of events in different queue configurations. The `val` array holds three additional long integer values that can be used for various purposes related to the event. This structure is integral to the functioning of the event queues (`eventq`, `maxq`, and `implq`) defined in the accompanying code, which manage events based on their timeout values.


# Functions

---
### test\_heap<!-- {{#callable:test_heap}} -->
The `test_heap` function verifies that a given heap of events maintains the properties of a min-heap, ensuring the heap's count, maximum capacity, and parent-child timeout order are correct.
- **Inputs**:
    - `heap`: A pointer to an array of `event_t` structures representing the heap.
    - `cnt`: An unsigned long integer representing the current number of elements in the heap.
    - `max`: An unsigned long integer representing the maximum capacity of the heap.
- **Control Flow**:
    - Check if the current count of elements in the heap matches the provided `cnt` using `FD_TEST` macro.
    - Check if the maximum capacity of the heap matches the provided `max` using `FD_TEST` macro.
    - Ensure that the current count `cnt` does not exceed the maximum capacity `max` using `FD_TEST` macro.
    - Iterate over each child node in the heap starting from index 1 to `cnt-1`.
    - For each child node, calculate its parent index using `(child-1UL) >> 1`.
    - Verify that the timeout of the parent node is less than or equal to the timeout of the child node using `FD_TEST` macro.
- **Output**: The function returns 0, indicating successful validation of the heap properties.


---
### test\_max\_heap<!-- {{#callable:test_max_heap}} -->
The `test_max_heap` function verifies that a given heap of events satisfies the properties of a max-heap data structure.
- **Inputs**:
    - `heap`: A pointer to an array of `event_t` structures representing the heap.
    - `cnt`: The number of elements currently in the heap.
    - `max`: The maximum capacity of the heap.
- **Control Flow**:
    - Check if the current count of elements in the heap matches the provided `cnt` using `maxq_cnt` function.
    - Check if the maximum capacity of the heap matches the provided `max` using `maxq_max` function.
    - Ensure that the current count `cnt` is less than or equal to the maximum capacity `max`.
    - Iterate over each child node in the heap starting from index 1 to `cnt-1`.
    - For each child node, calculate its parent node index using `(child-1UL) >> 1`.
    - Verify that the parent's `timeout` value is greater than or equal to the child's `timeout` value, ensuring max-heap property.
- **Output**: The function returns 0 to indicate successful verification of the max-heap properties.


---
### test\_implicit\_heap<!-- {{#callable:test_implicit_heap}} -->
The `test_implicit_heap` function verifies that a heap of events maintains the correct implicit heap properties based on a custom timeout ratio.
- **Inputs**:
    - `heap`: A pointer to an array of `event_t` structures representing the heap.
    - `cnt`: The current number of elements in the heap.
    - `max`: The maximum capacity of the heap.
- **Control Flow**:
    - Check if the current count of elements in the heap matches `cnt` using `implq_cnt` function.
    - Verify if the maximum capacity of the heap matches `max` using `implq_max` function.
    - Ensure that the current count `cnt` does not exceed the maximum capacity `max`.
    - Iterate over each child node in the heap starting from index 1 to `cnt-1`.
    - For each child, calculate its parent index using `(child-1) >> 1`.
    - Compute the timeout ratio for both the parent and child nodes as `timeout / timeout2`.
    - Check if the parent's timeout ratio is greater than or equal to the child's timeout ratio to ensure heap property is maintained.
- **Output**: The function returns 0, indicating successful verification of the heap properties.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes and tests various priority queue implementations by inserting, removing, and validating events in different configurations.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the program with `fd_boot` and set up a random number generator `rng`.
    - Define a maximum number of events `max` to be used in the tests, currently hardcoded to 1024.
    - Calculate memory alignment and footprint for the event queue and ensure they are valid.
    - Allocate memory for the event queue and check if it fits within the allocated space.
    - Create and join an event queue, then test its initial state for correct count and maximum capacity.
    - Insert events into the queue in a quasi-random order, ensuring they are inserted correctly and the heap property is maintained.
    - Remove events from the queue in order of their timeout values, checking the order and heap property after each removal.
    - Repeat the insertion and removal process for different queue types: max queue and implicit queue, each with specific properties and tests.
    - Test the destruction of the queues and ensure memory is correctly released.
    - If hosted and handholding is enabled, test for critical log conditions by simulating errors.
    - Finally, clean up the random number generator and halt the program.
- **Output**: The function returns 0 upon successful completion of all tests, indicating that all queue operations were performed correctly.
- **Functions called**:
    - [`test_heap`](#test_heap)
    - [`test_max_heap`](#test_max_heap)
    - [`test_implicit_heap`](#test_implicit_heap)



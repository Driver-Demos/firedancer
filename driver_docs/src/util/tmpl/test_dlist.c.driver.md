# Purpose
This C source code file is designed to implement and test a doubly linked list (dlist) and a pool of elements, providing both reference and test implementations. The code includes functions for initializing, manipulating, and verifying the integrity of a doubly linked list and a pool of elements. The reference implementation uses static arrays and indices to manage a fixed-size pool and dlist, while the test implementation uses macros to generate similar functionality with a more flexible design. The code is structured to allow for operations such as pushing and popping elements from the head or tail of the list, inserting elements before or after a given element, and replacing or removing elements. It also includes a main function that performs extensive testing of these operations to ensure correctness and robustness.

The file is a comprehensive test suite for the doubly linked list and pool functionalities, with a focus on verifying the correctness of operations through a series of randomized tests. It includes boundary condition checks and diagnostic logging to facilitate debugging and validation. The code is intended to be compiled and executed as a standalone program, as indicated by the presence of a [`main`](#main) function. It does not define public APIs or external interfaces, but rather serves as an internal testing tool to validate the behavior of the linked list and pool implementations. The inclusion of headers like `fd_pool.c` and `fd_dlist.c` suggests that these components are modular and can be reused or adapted for other applications requiring similar data structures.
# Imports and Dependencies

---
- `../fd_util.h`
- `sys/types.h`
- `sys/wait.h`
- `unistd.h`
- `fd_pool.c`
- `fd_dlist.c`


# Global Variables

---
### ref\_ele
- **Type**: `array of struct`
- **Description**: `ref_ele` is a static array of structures, where each structure contains three unsigned long integers: `prev`, `next`, and `val`. This array is used to manage a pool of elements and a doubly linked list, with each element in the array representing a node in the list.
- **Use**: `ref_ele` is used to store and manage the state of each element in a pool and doubly linked list, facilitating operations like insertion, removal, and traversal.


---
### ref\_pool
- **Type**: `ulong`
- **Description**: `ref_pool` is a static global variable of type `ulong` initialized to `ELE_IDX_NULL`. It represents the head of a pool of elements that are available for use in a linked list structure.
- **Use**: `ref_pool` is used to track the first available element in the pool, allowing for efficient acquisition and release of elements as they are needed or returned.


---
### ref\_dlist\_head
- **Type**: `ulong`
- **Description**: `ref_dlist_head` is a global variable of type `ulong` that is initialized to `ELE_IDX_NULL`, which is defined as the bitwise negation of 0 (`~0UL`). This variable represents the index of the head element in a doubly linked list structure used within the code.
- **Use**: It is used to track the starting point of the doubly linked list, allowing operations such as insertion, deletion, and traversal to be performed from the head of the list.


---
### ref\_dlist\_tail
- **Type**: `ulong`
- **Description**: `ref_dlist_tail` is a static global variable of type `ulong` that is initialized to `ELE_IDX_NULL`, which is defined as the bitwise negation of 0 (`~0UL`). This effectively sets `ref_dlist_tail` to the maximum possible value for an unsigned long, often used as a sentinel value to indicate a null or uninitialized state.
- **Use**: It is used to track the index of the last element in a doubly linked list, allowing operations to efficiently access or modify the tail of the list.


# Data Structures

---
### tst\_ele
- **Type**: `struct`
- **Members**:
    - `prev_cidx`: A field of type CIDX_T representing the index of the previous element in a list.
    - `next_cidx`: A field of type CIDX_T representing the index of the next element in a list.
    - `val`: A field of type ulong representing the value stored in the element.
- **Description**: The `tst_ele` structure is a node used in a doubly linked list, where each node contains an index to the previous and next elements, as well as a value. This structure is designed to facilitate operations on a doubly linked list, such as insertion, deletion, and traversal, by maintaining references to adjacent nodes through the `prev_cidx` and `next_cidx` fields. The `val` field stores the actual data associated with the node.


---
### tst\_ele\_t
- **Type**: `struct`
- **Members**:
    - `prev_cidx`: Stores the index of the previous element in the list.
    - `next_cidx`: Stores the index of the next element in the list.
    - `val`: Holds the value associated with the element.
- **Description**: The `tst_ele_t` structure is a node used in a doubly linked list, where each node contains a value and indices to the previous and next nodes in the list. The `prev_cidx` and `next_cidx` fields are used to navigate through the list, while the `val` field stores the data associated with the node. This structure is part of a pool and doubly linked list implementation, allowing for efficient element management and traversal.


# Functions

---
### ref\_pool\_init<!-- {{#callable:ref_pool_init}} -->
The `ref_pool_init` function initializes a pool of elements by setting up a linked list structure for a specified number of elements.
- **Inputs**:
    - `ele_cnt`: The number of elements to initialize in the pool, which should be in the range [0, ELE_MAX].
- **Control Flow**:
    - Check if `ele_cnt` is zero; if so, set `ref_pool` to `ELE_IDX_NULL` and return.
    - Set `ref_pool` to 0, indicating the start of the pool.
    - Iterate over the range from 1 to `ele_cnt - 1`, setting up each element's `prev`, `next`, and `val` fields to create a linked list structure.
    - Set the last element's `prev`, `next`, and `val` fields to finalize the linked list.
- **Output**: The function does not return a value; it initializes the global `ref_pool` and `ref_ele` array to represent a pool of elements.


---
### ref\_pool\_is\_empty<!-- {{#callable:ref_pool_is_empty}} -->
The `ref_pool_is_empty` function checks if the reference pool is empty by comparing the `ref_pool` variable to `ELE_IDX_NULL`.
- **Inputs**: None
- **Control Flow**:
    - The function checks if the global variable `ref_pool` is equal to `ELE_IDX_NULL`.
    - If `ref_pool` is equal to `ELE_IDX_NULL`, the function returns 1, indicating the pool is empty.
    - If `ref_pool` is not equal to `ELE_IDX_NULL`, the function returns 0, indicating the pool is not empty.
- **Output**: The function returns an integer: 1 if the pool is empty, 0 otherwise.


---
### ref\_pool\_idx\_acquire<!-- {{#callable:ref_pool_idx_acquire}} -->
The `ref_pool_idx_acquire` function retrieves and removes the first element index from a pool, assuming the pool is not empty.
- **Inputs**: None
- **Control Flow**:
    - The function initializes a local variable `ele_idx` with the current head of the pool, `ref_pool`.
    - It updates `ref_pool` to point to the next element in the pool using `ref_ele[ele_idx].next`.
    - Finally, it returns the index `ele_idx` of the acquired element.
- **Output**: The function returns an `ulong` representing the index of the element that was acquired from the pool.


---
### ref\_pool\_idx\_release<!-- {{#callable:ref_pool_idx_release}} -->
The `ref_pool_idx_release` function releases an element index back to the pool by updating the pool's head to point to this index.
- **Inputs**:
    - `ele_idx`: The index of the element to be released back into the pool; it is assumed that this element is not currently in the pool or in the doubly linked list.
- **Control Flow**:
    - The function sets the `next` field of the element at `ele_idx` to the current head of the pool, `ref_pool`.
    - The function updates `ref_pool` to point to `ele_idx`, effectively making it the new head of the pool.
- **Output**: The function does not return a value; it modifies the global state of the pool by updating the `ref_pool` and the `next` field of the element at `ele_idx`.


---
### ref\_dlist\_is\_empty<!-- {{#callable:ref_dlist_is_empty}} -->
The function `ref_dlist_is_empty` checks if the doubly linked list is empty by comparing the head index to a null value.
- **Inputs**: None
- **Control Flow**:
    - The function checks if `ref_dlist_head` is equal to `ELE_IDX_NULL`.
    - If `ref_dlist_head` is `ELE_IDX_NULL`, it returns 1, indicating the list is empty.
    - Otherwise, it returns 0, indicating the list is not empty.
- **Output**: The function returns an integer: 1 if the doubly linked list is empty, and 0 otherwise.


---
### ref\_dlist\_idx\_peek\_head<!-- {{#callable:ref_dlist_idx_peek_head}} -->
The function `ref_dlist_idx_peek_head` returns the index of the head element in a doubly linked list, assuming the list is not empty.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of the global variable `ref_dlist_head`, which holds the index of the head element of the doubly linked list.
- **Output**: The function returns an `ulong` representing the index of the head element in the doubly linked list.


---
### ref\_dlist\_idx\_peek\_tail<!-- {{#callable:ref_dlist_idx_peek_tail}} -->
The function `ref_dlist_idx_peek_tail` returns the index of the last element in a doubly linked list, assuming the list is not empty.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of the global variable `ref_dlist_tail`, which holds the index of the last element in the doubly linked list.
    - The function assumes that the list is not empty, so it does not perform any checks or modifications.
- **Output**: The function returns an `ulong` representing the index of the last element in the doubly linked list.


---
### ref\_dlist\_idx\_push\_head<!-- {{#callable:ref_dlist_idx_push_head}} -->
The `ref_dlist_idx_push_head` function inserts an element at the head of a doubly linked list, updating the list's head and tail pointers as necessary.
- **Inputs**:
    - `ele_idx`: The index of the element to be inserted at the head of the doubly linked list; it is assumed that this element is not currently in the list or pool.
- **Control Flow**:
    - Retrieve the current head index of the doubly linked list and store it in `next_idx`.
    - Set the `prev` pointer of the element at `ele_idx` to `ELE_IDX_NULL`, indicating it will be the new head.
    - Set the `next` pointer of the element at `ele_idx` to `next_idx`, linking it to the current head.
    - If `next_idx` is `ELE_IDX_NULL`, indicating the list was empty, set the list's tail to `ele_idx`.
    - Otherwise, update the `prev` pointer of the current head element to point to `ele_idx`.
    - Finally, update the list's head to `ele_idx`, completing the insertion.
- **Output**: The function does not return a value; it modifies the global state of the doubly linked list by updating the head and possibly the tail.


---
### ref\_dlist\_idx\_push\_tail<!-- {{#callable:ref_dlist_idx_push_tail}} -->
The `ref_dlist_idx_push_tail` function appends an element, identified by its index, to the tail of a doubly linked list, updating the list's head and tail pointers as necessary.
- **Inputs**:
    - `ele_idx`: The index of the element to be added to the tail of the doubly linked list; it is assumed that this element is not already in the list or the pool.
- **Control Flow**:
    - Retrieve the current tail index of the doubly linked list and store it in `prev_idx`.
    - Set the `prev` pointer of the element at `ele_idx` to `prev_idx`, and its `next` pointer to `ELE_IDX_NULL`, indicating it will be the new tail.
    - If `prev_idx` is `ELE_IDX_NULL`, indicating the list was empty, set the list's head to `ele_idx`.
    - Otherwise, set the `next` pointer of the current tail element to `ele_idx`, linking the new element to the end of the list.
    - Update the list's tail to `ele_idx`, making it the new tail of the list.
- **Output**: The function does not return a value; it modifies the global state of the doubly linked list by adding a new element to its tail.


---
### ref\_dlist\_idx\_pop\_head<!-- {{#callable:ref_dlist_idx_pop_head}} -->
The `ref_dlist_idx_pop_head` function removes and returns the index of the head element from a doubly linked list, updating the list's head and tail pointers accordingly.
- **Inputs**: None
- **Control Flow**:
    - Retrieve the index of the current head element from `ref_dlist_head`.
    - Get the index of the next element in the list from `ref_ele[ele_idx].next`.
    - Update `ref_dlist_head` to point to the next element's index.
    - If the next element's index is `ELE_IDX_NULL`, set `ref_dlist_tail` to `ELE_IDX_NULL`, indicating the list is now empty.
    - Otherwise, set the `prev` pointer of the new head element to `ELE_IDX_NULL`.
    - Return the index of the removed head element.
- **Output**: The function returns the index of the element that was removed from the head of the doubly linked list.


---
### ref\_dlist\_idx\_pop\_tail<!-- {{#callable:ref_dlist_idx_pop_tail}} -->
The `ref_dlist_idx_pop_tail` function removes and returns the index of the last element from a doubly linked list, updating the list's tail and potentially its head if the list becomes empty.
- **Inputs**: None
- **Control Flow**:
    - Retrieve the index of the current tail element from `ref_dlist_tail`.
    - Get the previous element's index from the `prev` field of the current tail element.
    - Update `ref_dlist_tail` to the previous element's index.
    - If the previous index is `ELE_IDX_NULL`, set `ref_dlist_head` to `ELE_IDX_NULL`, indicating the list is now empty.
    - Otherwise, set the `next` field of the new tail element to `ELE_IDX_NULL`.
    - Return the index of the removed tail element.
- **Output**: The function returns the index of the element that was removed from the tail of the doubly linked list.


---
### ref\_dlist\_idx\_insert\_before<!-- {{#callable:ref_dlist_idx_insert_before}} -->
The `ref_dlist_idx_insert_before` function inserts an element into a doubly linked list before a specified element.
- **Inputs**:
    - `ele_idx`: The index of the element to be inserted, which is assumed to not be in the doubly linked list or pool.
    - `dlist_idx`: The index of the element in the doubly linked list before which the new element will be inserted, and is assumed to be in the list.
- **Control Flow**:
    - Retrieve the index of the previous element to `dlist_idx` from the doubly linked list.
    - Set the `prev` pointer of the element at `ele_idx` to the retrieved previous index.
    - Set the `next` pointer of the element at `ele_idx` to `dlist_idx`.
    - Update the `prev` pointer of the element at `dlist_idx` to `ele_idx`.
    - If the previous index is `ELE_IDX_NULL`, update the head of the doubly linked list to `ele_idx`.
    - Otherwise, update the `next` pointer of the previous element to `ele_idx`.
- **Output**: The function does not return a value; it modifies the doubly linked list structure in place.


---
### ref\_dlist\_idx\_insert\_after<!-- {{#callable:ref_dlist_idx_insert_after}} -->
The `ref_dlist_idx_insert_after` function inserts an element into a doubly linked list immediately after a specified element.
- **Inputs**:
    - `ele_idx`: The index of the element to be inserted into the doubly linked list, which is assumed to be not currently in the list or pool.
    - `dlist_idx`: The index of the element in the doubly linked list after which the new element will be inserted, which is assumed to be currently in the list.
- **Control Flow**:
    - Retrieve the index of the element following `dlist_idx` in the list and store it in `next_idx`.
    - Set the `next` pointer of the element at `ele_idx` to `next_idx` and the `prev` pointer to `dlist_idx`.
    - Update the `next` pointer of the element at `dlist_idx` to point to `ele_idx`.
    - If `next_idx` is `ELE_IDX_NULL`, update the list's tail to `ele_idx`; otherwise, update the `prev` pointer of the element at `next_idx` to `ele_idx`.
- **Output**: The function does not return a value; it modifies the linked list structure in place.


---
### ref\_dlist\_idx\_remove<!-- {{#callable:ref_dlist_idx_remove}} -->
The `ref_dlist_idx_remove` function removes an element from a doubly linked list by updating the previous and next pointers of the surrounding elements.
- **Inputs**:
    - `ele_idx`: The index of the element to be removed from the doubly linked list, which is assumed to be currently in the list.
- **Control Flow**:
    - Retrieve the previous and next indices of the element at `ele_idx` from the `ref_ele` array.
    - If `prev_idx` is `ELE_IDX_NULL`, update `ref_dlist_head` to `next_idx`, otherwise set the `next` pointer of the element at `prev_idx` to `next_idx`.
    - If `next_idx` is `ELE_IDX_NULL`, update `ref_dlist_tail` to `prev_idx`, otherwise set the `prev` pointer of the element at `next_idx` to `prev_idx`.
- **Output**: The function does not return a value; it modifies the global state of the doubly linked list by removing the specified element.


---
### ref\_dlist\_idx\_replace<!-- {{#callable:ref_dlist_idx_replace}} -->
The `ref_dlist_idx_replace` function replaces an element in a doubly linked list with another element, updating the list's head and tail pointers as necessary.
- **Inputs**:
    - `ele_idx`: The index of the new element to be inserted into the doubly linked list, which is assumed to be not currently in the list or pool.
    - `old_idx`: The index of the existing element in the doubly linked list that is to be replaced.
- **Control Flow**:
    - Retrieve the previous and next indices of the element at `old_idx` from the `ref_ele` array.
    - Set the `prev` and `next` pointers of the element at `ele_idx` to the retrieved previous and next indices, respectively.
    - If the previous index is `ELE_IDX_NULL`, update the `ref_dlist_head` to `ele_idx`; otherwise, set the `next` pointer of the element at the previous index to `ele_idx`.
    - If the next index is `ELE_IDX_NULL`, update the `ref_dlist_tail` to `ele_idx`; otherwise, set the `prev` pointer of the element at the next index to `ele_idx`.
- **Output**: The function does not return a value; it modifies the doubly linked list in place, replacing the element at `old_idx` with the element at `ele_idx`.


---
### ref\_dlist\_remove\_all<!-- {{#callable:ref_dlist_remove_all}} -->
The `ref_dlist_remove_all` function clears all elements from the doubly linked list by setting the head and tail indices to null.
- **Inputs**: None
- **Control Flow**:
    - The function sets `ref_dlist_head` to `ELE_IDX_NULL`, indicating the list is empty.
    - The function sets `ref_dlist_tail` to `ELE_IDX_NULL`, further indicating the list is empty.
- **Output**: The function does not return any value; it modifies the global state of the doubly linked list to be empty.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes and tests a doubly linked list (dlist) implementation with various operations, including insertion, deletion, and verification, while logging the process and handling errors.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the environment and parse command-line arguments to determine the maximum number of elements (`ele_max`).
    - Log the start of testing with the specified `ele_max`.
    - Initialize a random number generator (`rng`) and a scratch memory buffer with specific alignment and footprint.
    - Check for configuration errors related to `ele_max`, alignment, and footprint, logging errors if any are found.
    - Initialize a reference pool and join a test pool with the specified `ele_max`.
    - Log the start of construction testing and perform various tests on the dlist's alignment, footprint, and creation.
    - Join the dlist and perform a series of operations to test its functionality, including checking if the list is empty, pushing elements to the head and tail, popping elements from the head and tail, inserting elements before and after others, removing elements, and replacing elements.
    - Iterate through a large number of operations (1 billion) to test the dlist's robustness, logging progress at intervals.
    - If hosted and handholding is enabled, test boundary conditions and log critical errors for invalid operations.
    - Log the start of destruction testing, leave and delete the dlist, and verify the operations.
    - Clean up by deleting the test pool and random number generator, then log the successful completion of tests and halt the program.
- **Output**: The function returns an integer, 0, indicating successful execution.
- **Functions called**:
    - [`ref_pool_init`](#ref_pool_init)
    - [`ref_dlist_is_empty`](#ref_dlist_is_empty)
    - [`ref_dlist_idx_peek_head`](#ref_dlist_idx_peek_head)
    - [`ref_dlist_idx_peek_tail`](#ref_dlist_idx_peek_tail)
    - [`ref_pool_is_empty`](#ref_pool_is_empty)
    - [`ref_pool_idx_acquire`](#ref_pool_idx_acquire)
    - [`ref_dlist_idx_push_head`](#ref_dlist_idx_push_head)
    - [`ref_dlist_idx_push_tail`](#ref_dlist_idx_push_tail)
    - [`ref_dlist_idx_pop_head`](#ref_dlist_idx_pop_head)
    - [`ref_pool_idx_release`](#ref_pool_idx_release)
    - [`ref_dlist_idx_pop_tail`](#ref_dlist_idx_pop_tail)
    - [`ref_dlist_idx_insert_before`](#ref_dlist_idx_insert_before)
    - [`ref_dlist_idx_insert_after`](#ref_dlist_idx_insert_after)
    - [`ref_dlist_idx_remove`](#ref_dlist_idx_remove)
    - [`ref_dlist_idx_replace`](#ref_dlist_idx_replace)



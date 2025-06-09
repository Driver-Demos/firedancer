# Purpose
This C source code file is designed to test and demonstrate the functionality of a data structure known as a "treap," which is a combination of a binary search tree and a heap. The file includes the implementation of a treap and a variant called "lreap," which optimizes iteration. The code is structured to test various operations on these data structures, such as insertion, deletion, querying, and merging, ensuring their integrity and correctness through extensive testing. The file also includes a pool allocator for managing memory efficiently, which is crucial for handling the dynamic nature of treap operations.

The code is organized into several key components: the definition of the `ele` structure, which represents the elements stored in the treap; macros for configuring the treap and pool operations; and a series of test functions that validate the behavior of the treap under different scenarios. The main function orchestrates these tests, setting up the environment and executing a series of operations to verify the treap's functionality. The file is intended to be compiled and executed as a standalone program, providing a comprehensive test suite for the treap data structure. It does not define public APIs or external interfaces, as its primary purpose is internal testing and validation.
# Imports and Dependencies

---
- `../fd_util.h`
- `sys/types.h`
- `sys/wait.h`
- `unistd.h`
- `fd_pool.c`
- `fd_treap.c`
- `stdio.h`


# Global Variables

---
### scratch
- **Type**: `uchar[]`
- **Description**: The `scratch` variable is a static array of unsigned characters with a size defined by `SCRATCH_FOOTPRINT`, which is 2048 bytes. It is aligned in memory according to `SCRATCH_ALIGN`, which is 128 bytes, to ensure optimal access and performance.
- **Use**: This variable is used as a memory pool for operations involving data structures like pools and treaps, providing a contiguous block of memory for efficient allocation and deallocation.


---
### ele\_max
- **Type**: `ulong`
- **Description**: `ele_max` is a global variable of type `ulong` initialized to the value 254UL. It represents the maximum number of elements that can be handled in certain data structures, such as pools and treaps, within the program.
- **Use**: This variable is used to define the upper limit of elements in data structures like pools and treaps, ensuring operations do not exceed this limit.


---
### pool
- **Type**: `ele_t *`
- **Description**: The `pool` variable is a pointer to an array of `ele_t` structures, which are used to manage a pool of elements for operations involving treaps and lreaps. The `ele_t` structure contains fields for managing tree-like data structures, such as parent, left, right, priority, previous, and next indices, as well as a value field.
- **Use**: The `pool` variable is used to allocate and manage a pool of elements for treap and lreap operations, providing storage and access to the elements' data.


---
### a
- **Type**: `lreap_t *`
- **Description**: The variable `a` is a pointer to an `lreap_t` structure, which represents a leftist treap data structure. It is initialized by joining a newly created leftist treap with a maximum element count specified by `ele_max`. This structure is used to manage a collection of elements in a way that supports efficient insertion, deletion, and merging operations.
- **Use**: `a` is used to perform operations on a leftist treap, such as insertion, deletion, and merging with another treap.


---
### b
- **Type**: `lreap_t*`
- **Description**: The variable `b` is a pointer to an `lreap_t` structure, which represents a left-leaning treap data structure. It is initialized by joining a newly created left-leaning treap with a maximum element count specified by `ele_max`. The `lreap_join` function is used to associate the treap with its memory and configuration.
- **Use**: This variable is used to manage and manipulate a left-leaning treap data structure, allowing for operations such as insertion, deletion, and iteration over elements.


# Data Structures

---
### ele
- **Type**: `struct`
- **Members**:
    - `parent_cidx`: Stores the index of the parent element in a tree structure.
    - `left_cidx`: Stores the index of the left child element in a tree structure.
    - `right_cidx`: Stores the index of the right child element in a tree structure.
    - `prio_cidx`: Stores the index used for priority in a treap data structure.
    - `prev_cidx`: Stores the index of the previous element in a linked list or similar structure.
    - `next_cidx`: Stores the index of the next element in a linked list or similar structure.
    - `val`: Holds the value of the element, represented as a signed character.
- **Description**: The `ele` structure is a compound data type used to represent a node in a tree or linked list structure, particularly in the context of a treap, which is a combination of a binary search tree and a heap. Each `ele` instance contains indices to its parent, left and right children, and priority, facilitating its use in hierarchical data structures. Additionally, it includes indices for previous and next elements, supporting its use in linked list-like structures. The `val` field stores the actual value of the element, allowing for comparisons and operations within the data structure.


---
### ele\_t
- **Type**: `struct`
- **Members**:
    - `parent_cidx`: Stores the index of the parent node in a tree structure.
    - `left_cidx`: Stores the index of the left child node in a tree structure.
    - `right_cidx`: Stores the index of the right child node in a tree structure.
    - `prio_cidx`: Stores the priority index used for ordering in a treap.
    - `prev_cidx`: Stores the index of the previous element in a linked list or similar structure.
    - `next_cidx`: Stores the index of the next element in a linked list or similar structure.
    - `val`: Holds the value of the element, represented as a signed character.
- **Description**: The `ele_t` structure is a compound data type used to represent an element in a tree or linked list structure, particularly in the context of a treap, which is a combination of a binary search tree and a heap. It contains indices for parent, left, and right child nodes, as well as priority and linked list navigation indices, allowing it to be used in various data structures that require hierarchical and sequential ordering. The `val` field holds the actual value of the element, facilitating comparisons and operations within these structures.


# Functions

---
### dump\_treap<!-- {{#callable:dump_treap}} -->
The `dump_treap` function recursively prints the structure and values of a treap data structure in a human-readable format, with indentation to represent tree depth.
- **Inputs**:
    - `i`: The index of the current node in the treap to be printed.
    - `ele`: A constant pointer to an array of `ele_t` structures representing the elements of the treap.
    - `indent`: The current level of indentation for printing, representing the depth of the node in the treap.
- **Control Flow**:
    - Check if the current index `i` is null using `treap_idx_is_null(i)`.
    - If `i` is null, print spaces equal to the current `indent` level followed by a dash ('-') to indicate a null node and return.
    - Recursively call `dump_treap` for the right child of the current node, increasing the `indent` by 4.
    - Print spaces equal to the current `indent` level, then print the value, priority, and index of the current node.
    - Recursively call `dump_treap` for the left child of the current node, increasing the `indent` by 4.
- **Output**: The function does not return a value; it outputs the structure of the treap to the standard output (stdout).


---
### test\_iteration<!-- {{#callable:test_iteration}} -->
The `test_iteration` function tests the forward and reverse iteration over two data structures, `treap` and `lreap`, while performing insertions, deletions, and validations using a provided deletion function.
- **Inputs**:
    - `del`: A function pointer of type `delfn_t` that determines which index to delete based on the current element value, or returns -1 to indicate no deletion.
- **Control Flow**:
    - Initialize two treap structures (`treap` and `lreap`) and two pools (`pool1` and `pool2`) with 64 elements each.
    - In the forward iteration block, insert elements into both treap and lreap, setting their values and priorities, and iterate over them using forward iterators.
    - During each iteration, check for element consistency between treap and lreap, update a bitflag `seen`, and determine if an element should be deleted using the `del` function.
    - If an element is deleted, remove it from both treap and lreap, and update the `seen` bitflag accordingly.
    - Verify the integrity of the treap and lreap structures after each iteration and ensure all elements have been seen by the end of the iteration.
    - In the reverse iteration block, repeat similar steps as the forward iteration but iterate in reverse order, checking for the smallest element instead of the largest.
    - After both iterations, clean up by deleting the treap, lreap, and pools.
- **Output**: The function does not return any value; it performs tests and assertions to validate the behavior of the data structures and the deletion function.


---
### del\_fn\_self\_0<!-- {{#callable:del_fn_self_0}} -->
The function `del_fn_self_0` always returns -1, indicating that no deletion should occur.
- **Inputs**:
    - `i`: An integer input that is ignored in the function.
- **Control Flow**:
    - The function takes an integer input `i` but does not use it in any computation.
    - The function explicitly casts `i` to void to indicate that it is unused.
    - The function returns a constant value of -1.
- **Output**: The function returns an integer value of -1, which typically indicates that no deletion should occur.


---
### del\_fn\_self\_1<!-- {{#callable:del_fn_self_1}} -->
The function `del_fn_self_1` returns the input integer if it is odd, otherwise it returns -1.
- **Inputs**:
    - `i`: An integer input to be evaluated for deletion.
- **Control Flow**:
    - The function checks if the least significant bit of the integer `i` is set (i.e., `i` is odd) using the bitwise AND operation `i & 1`.
    - If `i` is odd, the function returns `i`.
    - If `i` is not odd (i.e., even), the function returns -1.
- **Output**: The function returns the integer `i` if it is odd, otherwise it returns -1.


---
### del\_fn\_self\_2<!-- {{#callable:del_fn_self_2}} -->
The function `del_fn_self_2` determines whether to return the input integer or -1 based on whether the integer is even.
- **Inputs**:
    - `i`: An integer input to the function.
- **Control Flow**:
    - The function checks if the bitwise NOT of the integer `i` AND 1 is true, which is equivalent to checking if `i` is even.
    - If `i` is even, the function returns `i`.
    - If `i` is odd, the function returns -1.
- **Output**: The function returns the integer `i` if it is even, otherwise it returns -1.


---
### del\_fn\_self\_3<!-- {{#callable:del_fn_self_3}} -->
The function `del_fn_self_3` determines whether to return the input integer `i` or -1 based on specific conditions involving bitwise operations and a comparison.
- **Inputs**:
    - `i`: An integer input that the function evaluates to decide whether to return it or -1.
- **Control Flow**:
    - The function checks if the least significant bit of `i` is set (i.e., `i` is odd) using the expression `i & 1`.
    - It also checks if `i` is less than 32 using the expression `i < 32`.
    - Both conditions are combined using a bitwise AND operation `&`.
    - If both conditions are true, the function returns `i`; otherwise, it returns -1.
- **Output**: The function returns the integer `i` if it is odd and less than 32; otherwise, it returns -1.


---
### del\_fn\_self\_4<!-- {{#callable:del_fn_self_4}} -->
The function `del_fn_self_4` determines whether to return the input integer `i` or -1 based on specific bitwise and comparison conditions.
- **Inputs**:
    - `i`: An integer input that the function evaluates to decide whether to return it or -1.
- **Control Flow**:
    - The function uses bitwise NOT and AND operations to check if `i` is even (`~i & 1`).
    - It also checks if `i` is less than 32 (`i < 32`).
    - If both conditions are true, the function returns `i`; otherwise, it returns -1.
- **Output**: The function returns the integer `i` if it is even and less than 32; otherwise, it returns -1.


---
### del\_fn\_self\_5<!-- {{#callable:del_fn_self_5}} -->
The function `del_fn_self_5` determines whether to return the input integer `i` or -1 based on specific bitwise and comparison conditions.
- **Inputs**:
    - `i`: An integer input that the function evaluates to decide whether to return it or -1.
- **Control Flow**:
    - The function checks if the least significant bit of `i` is set (i.e., `i` is odd) using the expression `(i & 1)`.
    - It also checks if `i` is greater than 31 using the expression `(i > 31)`.
    - Both conditions are combined using a bitwise AND operation `((i & 1) & (i > 31))`.
    - If the combined condition evaluates to true (non-zero), the function returns `i`.
    - If the combined condition evaluates to false (zero), the function returns -1.
- **Output**: The function returns the integer `i` if it is odd and greater than 31; otherwise, it returns -1.


---
### del\_fn\_self\_6<!-- {{#callable:del_fn_self_6}} -->
The function `del_fn_self_6` determines whether to return the input index or -1 based on specific bitwise and comparison conditions.
- **Inputs**:
    - `i`: An integer index to be evaluated for deletion.
- **Control Flow**:
    - The function checks if the bitwise negation of `i` AND 1 is true, which means `i` is even.
    - It also checks if `i` is greater than 31.
    - If both conditions are true, it returns `i`; otherwise, it returns -1.
- **Output**: The function returns the input index `i` if it is even and greater than 31, otherwise it returns -1.


---
### del\_fn\_self\_7<!-- {{#callable:del_fn_self_7}} -->
The function `del_fn_self_7` returns the input integer `i` without any modification.
- **Inputs**:
    - `i`: An integer input that the function will return as is.
- **Control Flow**:
    - The function takes an integer `i` as input.
    - It directly returns the integer `i` without any processing or condition checks.
- **Output**: The output is the same integer `i` that was passed as input.


---
### del\_fn\_next<!-- {{#callable:del_fn_next}} -->
The `del_fn_next` function returns the next index to delete, incrementing the input index by 1 if it is less than 63, otherwise returning -1.
- **Inputs**:
    - `i`: An integer representing the current index.
- **Control Flow**:
    - The function checks if the input index `i` is less than 63.
    - If `i` is less than 63, it returns `i + 1`.
    - If `i` is 63 or greater, it returns -1.
- **Output**: An integer representing the next index to delete, or -1 if no deletion should occur.


---
### del\_fn\_prev<!-- {{#callable:del_fn_prev}} -->
The `del_fn_prev` function returns the previous index if the current index is greater than zero, otherwise it returns -1.
- **Inputs**:
    - `i`: An integer representing the current index.
- **Control Flow**:
    - Check if the input index `i` is greater than 0.
    - If true, return `i - 1`.
    - If false, return -1.
- **Output**: An integer representing the previous index if `i` is greater than 0, otherwise -1.


---
### del\_fn\_3<!-- {{#callable:del_fn_3}} -->
The `del_fn_3` function calculates a new index by multiplying the input index by 3 and taking the result modulo 64.
- **Inputs**:
    - `i`: An integer representing the current index.
- **Control Flow**:
    - The function takes an integer input `i`.
    - It multiplies `i` by 3.
    - The result is then taken modulo 64.
    - The function returns the computed value.
- **Output**: An integer representing the new index calculated as `(i*3)%64`.


---
### del\_fn\_5<!-- {{#callable:del_fn_5}} -->
The `del_fn_5` function calculates a deletion index by multiplying the input integer by 5 and taking the result modulo 64.
- **Inputs**:
    - `i`: An integer input representing the current index or value to be processed for deletion.
- **Control Flow**:
    - The function takes an integer input `i`.
    - It multiplies `i` by 5.
    - The result of the multiplication is then taken modulo 64.
    - The function returns the computed value.
- **Output**: An integer representing the calculated index for deletion, which is the result of `(i*5)%64`.


---
### test\_iteration\_all<!-- {{#callable:test_iteration_all}} -->
The `test_iteration_all` function executes a series of tests on a data structure by iterating over it with various deletion functions.
- **Inputs**: None
- **Control Flow**:
    - The function calls [`test_iteration`](#test_iteration) with a series of deletion functions: `del_fn_self_0`, `del_fn_self_1`, `del_fn_self_2`, `del_fn_self_3`, `del_fn_self_4`, `del_fn_self_5`, `del_fn_self_6`, `del_fn_self_7`, `del_fn_next`, `del_fn_prev`, `del_fn_3`, and `del_fn_5`.
    - Each call to [`test_iteration`](#test_iteration) tests the data structure's iteration and deletion logic using the provided deletion function.
- **Output**: The function does not return any value; it performs tests and likely logs results or assertions internally.
- **Functions called**:
    - [`test_iteration`](#test_iteration)


---
### lreap\_to\_treap<!-- {{#callable:lreap_to_treap}} -->
The `lreap_to_treap` function converts an `lreap_t` structure into a `treap_t` structure by copying relevant fields.
- **Inputs**:
    - `in`: A pointer to an `lreap_t` structure that is to be converted into a `treap_t` structure.
    - `out`: A pointer to a `treap_t` structure where the converted data from the `lreap_t` structure will be stored.
- **Control Flow**:
    - The function begins by copying the `ele_max` field from the `in` (lreap) structure to the `out` (treap) structure.
    - Next, it copies the `ele_cnt` field from the `in` structure to the `out` structure.
    - Then, it copies the `root` field from the `in` structure to the `out` structure.
    - Finally, the function returns the `out` pointer, which now contains the converted treap data.
- **Output**: A pointer to the `treap_t` structure (`out`) that now contains the data from the `lreap_t` structure (`in`).


---
### test\_merge<!-- {{#callable:test_merge}} -->
The `test_merge` function tests the merging of two lreap or treap data structures, verifying their integrity and clearing them after each test iteration.
- **Inputs**:
    - `rng`: A pointer to a random number generator state used for random operations.
    - `optimize_iteration`: An integer flag indicating whether to optimize the iteration using lreap (1) or to use treap (0).
- **Control Flow**:
    - Define a macro `MERGE_VERIFY_AND_CLEAR` to verify and clear the merged data structures.
    - Initialize two lreap structures `a` and `b` and a pool of elements.
    - Iterate over a range to distribute elements between `a` and `b`, then merge and verify them using the macro.
    - Perform random distribution of elements between `a` and `b`, merge, and verify them using the macro.
    - Test a degenerate case by filling the internal stack and merging, then verify using the macro.
    - Unpoison memory and clean up by deleting the lreap structures and the pool.
- **Output**: The function does not return a value; it performs tests and assertions to verify the correctness of merging operations.


---
### test\_duplicate<!-- {{#callable:test_duplicate}} -->
The `test_duplicate` function tests the insertion, verification, and removal of elements in a treap data structure, focusing on handling duplicate values.
- **Inputs**:
    - `rng`: A pointer to a random number generator (`fd_rng_t`) used for generating random numbers during the test.
- **Control Flow**:
    - Initialize a maximum element count (`ele_max`) to 254.
    - Create and join a pool and a treap with the specified maximum element count.
    - Set all element values in the pool to zero to ensure uniformity.
    - Run a loop 100 times to test treap operations with unique values:
    -   - Initialize arrays for tracking insertion order and free indices.
    -   - Seed the treap with a hash of the current iteration index.
    -   - Randomly select indices from the free list, insert them into the treap, and update the insertion order.
    -   - Verify the treap structure and check that the forward iteration order matches the insertion order.
    -   - Remove all elements from the treap.
    - Delete the treap after the loop completes.
    - Create and join two new treaps (`a` and `b`) for testing with duplicate values.
    - Set element values in the pool to random values between -15 and 14 to introduce duplicates.
    - Run another loop 100 times to test treap operations with duplicate values:
    -   - Randomly insert elements into either treap `a` or `b`.
    -   - Merge the two treaps and verify the merged structure.
    -   - Remove all elements from treap `a`.
    - Delete both treaps `a` and `b` after the loop completes.
- **Output**: The function does not return any value; it performs tests and assertions to verify the correctness of treap operations with duplicate values.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes and tests a treap data structure with various operations, including insertion, removal, and iteration, while ensuring data integrity and handling command-line arguments for configuration.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the environment and parse command-line arguments for `--max` and `--seed` values.
    - Check if `ele_max` exceeds 64 and log an error if it does.
    - Log the testing parameters `--max` and `--seed`.
    - Initialize a random number generator `rng`.
    - Calculate alignment and footprint for the pool and log an error if they exceed predefined limits.
    - Join a new pool with the specified `ele_max`.
    - Test special values and address conversion for the treap.
    - Seed the treap with the specified seed and verify priorities.
    - Test alignment and footprint of the treap.
    - Create and join a new treap, performing various operations like query, insert, remove, and iteration in a loop for 10 million iterations.
    - Perform additional tests for merge, duplicate, and iteration operations.
    - Log a notice of successful test completion and halt the program.
- **Output**: The function returns an integer, 0, indicating successful execution.
- **Functions called**:
    - [`test_merge`](#test_merge)
    - [`test_duplicate`](#test_duplicate)
    - [`test_iteration_all`](#test_iteration_all)



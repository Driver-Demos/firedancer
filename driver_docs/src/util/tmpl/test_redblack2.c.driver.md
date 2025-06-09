# Purpose
This C source code file is designed to implement and test a red-black tree data structure. The file includes the necessary headers and defines a structure `rbnode` to represent nodes in the red-black tree, with fields for key, parent, left and right children, and color. The code provides a set of static functions for creating, destroying, finding, inserting, and deleting nodes in the tree, as well as checking the tree's integrity. The file also includes a series of unit tests to verify the correctness of these operations, such as insertion, deletion, and finding the minimum node. These tests are executed in the [`all_tests`](#all_tests) function, which logs the results and reports any failures.

The code is structured to be part of a larger project, as indicated by the inclusion of an external file `fd_redblack.c` and the use of utility functions like `fd_boot` and `fd_halt`. The main function initializes the environment, sets up a memory pool for the red-black tree, and runs the unit tests. The file is not intended to be a standalone executable but rather a component of a larger system, likely providing a robust implementation of a red-black tree for use in other parts of the project. The use of macros and typedefs helps in abstracting the red-black tree operations, making the code modular and reusable.
# Imports and Dependencies

---
- `stdio.h`
- `string.h`
- `stdlib.h`
- `time.h`
- `limits.h`
- `assert.h`
- `../fd_util.h`
- `fd_redblack.c`


# Global Variables

---
### mu\_tests
- **Type**: `int`
- **Description**: The `mu_tests` variable is a global integer that keeps track of the total number of unit tests executed in the program. It is initialized to zero and incremented each time a test is run.
- **Use**: `mu_tests` is used to count the number of unit tests executed, providing a total count for reporting purposes.


---
### mu\_fails
- **Type**: `int`
- **Description**: The `mu_fails` variable is a global integer that tracks the number of failed unit tests in the program. It is initialized to zero and incremented each time a test fails.
- **Use**: `mu_fails` is used to count and report the number of failed tests during the execution of the `all_tests` function.


---
### permutation\_error
- **Type**: `int`
- **Description**: The `permutation_error` is a global integer variable initialized to zero. It is used to track the number of errors encountered during permutation operations, specifically in the context of inserting and deleting elements in a red-black tree.
- **Use**: This variable is incremented whenever an error occurs during permutation-based insertion or deletion operations in the red-black tree.


---
### pool
- **Type**: `rbnode*`
- **Description**: The `pool` variable is a static global pointer to an `rbnode` structure, initialized to `NULL`. It serves as a memory pool for managing red-black tree nodes.
- **Use**: `pool` is used to allocate, manage, and release memory for red-black tree nodes throughout the program.


---
### tree\_create
- **Type**: `function pointer`
- **Description**: `tree_create` is a static function that returns a pointer to an `rbtree` structure. It is used to initialize and create a new red-black tree, which is a type of self-balancing binary search tree.
- **Use**: This function is used to create and initialize a new red-black tree instance, returning a pointer to the newly created tree.


---
### tree\_find
- **Type**: `function pointer`
- **Description**: `tree_find` is a static function pointer that is used to locate a node within a red-black tree (`rbtree`) based on a given key. It is defined to take a pointer to a red-black tree and an integer key as parameters, and it returns a pointer to the `rbnode` that matches the key.
- **Use**: This function is used to search for a specific node in a red-black tree by its key.


---
### tree\_insert
- **Type**: `function pointer`
- **Description**: `tree_insert` is a static function pointer that represents a function for inserting a node with a specified key into a red-black tree. It is defined to take a double pointer to a red-black tree (`rbtree **rbt`) and an integer key (`int key`) as parameters, and it returns a pointer to an `rbnode`.
- **Use**: This function is used to insert a new node with a given key into a red-black tree, ensuring the tree maintains its properties.


---
### make\_black\_tree
- **Type**: `rbtree *`
- **Description**: The `make_black_tree` function is a static function that returns a pointer to an `rbtree`, which is a type alias for `rbnode`. This function is responsible for creating a red-black tree, inserting a predefined set of characters, deleting some of them, and ensuring the remaining nodes are black.
- **Use**: This function is used to create and manipulate a red-black tree, ensuring certain nodes are black, and is likely used for testing or initializing a specific tree state.


# Data Structures

---
### rbnode\_struct
- **Type**: `struct`
- **Members**:
    - `key`: An integer key used for node identification and comparison.
    - `u`: A union that can either store red-black tree node information or a next-free index.
    - `u.rb.parent`: An unsigned integer representing the index of the parent node in the red-black tree.
    - `u.rb.left`: An unsigned integer representing the index of the left child node in the red-black tree.
    - `u.rb.right`: An unsigned integer representing the index of the right child node in the red-black tree.
    - `u.rb.color`: An integer representing the color of the node, typically used in red-black trees to maintain balance.
    - `u.nf`: An unsigned long used to store the next-free index when the node is not part of the tree.
- **Description**: The `rbnode_struct` is a data structure used to represent a node in a red-black tree, a type of self-balancing binary search tree. Each node contains a key for identification and comparison, and a union that can either store red-black tree specific information (parent, left and right children, and color) or a next-free index for memory management purposes. This structure is essential for maintaining the properties of the red-black tree, ensuring that the tree remains balanced after insertions and deletions.


---
### rbnode
- **Type**: `struct`
- **Members**:
    - `key`: An integer key used for node identification and comparison.
    - `u`: A union containing either red-black tree node pointers or a next-free pointer.
- **Description**: The `rbnode` structure represents a node in a red-black tree, a self-balancing binary search tree. Each node contains an integer key for sorting and identification purposes. The union `u` allows the node to either store pointers to its parent, left, and right children along with its color in the red-black tree, or a next-free pointer for memory management. This design supports efficient insertion, deletion, and lookup operations while maintaining tree balance.


# Functions

---
### rb\_compare<!-- {{#callable:rb_compare}} -->
The `rb_compare` function compares the keys of two red-black tree nodes and returns the difference as a long integer.
- **Inputs**:
    - `left`: A pointer to the first `rbnode` structure, representing a node in a red-black tree.
    - `right`: A pointer to the second `rbnode` structure, representing another node in a red-black tree.
- **Control Flow**:
    - The function takes two `rbnode` pointers as input parameters.
    - It accesses the `key` field of each `rbnode` structure.
    - It calculates the difference between the `key` of the `left` node and the `key` of the `right` node.
    - The result of the subtraction is cast to a `long` type and returned.
- **Output**: A `long` integer representing the difference between the keys of the two nodes, which can be used to determine their relative ordering.


---
### all\_tests<!-- {{#callable:all_tests}} -->
The `all_tests` function executes a series of unit tests for various tree operations and logs the results.
- **Inputs**: None
- **Control Flow**:
    - Initialize `correct_free` with the current free memory in the pool using `rb_free(pool)`.
    - Execute each unit test function using the `mu_test` macro, which logs the test name and result, and checks for memory leaks by comparing `correct_free` with the current free memory after each test.
    - Update `correct_free` after each test to the current free memory in the pool.
- **Output**: The function does not return any value; it performs logging and updates global test counters.
- **Functions called**:
    - [`unit_test_create`](#unit_test_create)
    - [`unit_test_find`](#unit_test_find)
    - [`unit_test_successor`](#unit_test_successor)
    - [`unit_test_atomic_insertion`](#unit_test_atomic_insertion)
    - [`unit_test_chain_insertion`](#unit_test_chain_insertion)
    - [`unit_test_atomic_deletion`](#unit_test_atomic_deletion)
    - [`unit_test_chain_deletion`](#unit_test_chain_deletion)
    - [`unit_test_permutation_insertion`](#unit_test_permutation_insertion)
    - [`unit_test_permutation_deletion`](#unit_test_permutation_deletion)
    - [`unit_test_random_insertion_deletion`](#unit_test_random_insertion_deletion)
    - [`unit_test_min`](#unit_test_min)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, sets up a memory pool for red-black tree operations, runs a series of unit tests, and reports the results.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Call `fd_boot` to initialize the environment with command-line arguments.
    - Define constants `SCRATCH_ALIGN` and `SCRATCH_FOOTPRINT` for memory alignment and size.
    - Allocate a scratch memory buffer aligned to `SCRATCH_ALIGN` and sized to `SCRATCH_FOOTPRINT`.
    - Calculate the maximum number of nodes that can fit in the scratch memory using `rb_max_for_footprint`.
    - Check if the calculated footprint exceeds the scratch memory size and log an error if it does.
    - Create and join a red-black tree memory pool using the scratch memory and calculated maximum nodes.
    - Verify the maximum nodes in the pool match the calculated maximum and log an error if they don't.
    - Call [`all_tests`](#all_tests) to execute a series of unit tests on the red-black tree operations.
    - Delete and leave the red-black tree memory pool.
    - Check if any tests failed and log an error with the number of failed tests if any.
    - Log a success message and return 0 if all tests passed.
    - Call `fd_halt` to terminate the program if there are test failures.
- **Output**: The function returns 0 if all tests pass, otherwise it logs an error and halts the program.
- **Functions called**:
    - [`all_tests`](#all_tests)


---
### tree\_create<!-- {{#callable:tree_create}} -->
The `tree_create` function initializes and returns a new red-black tree, but currently returns `NULL` as a placeholder.
- **Inputs**: None
- **Control Flow**:
    - The function is defined to return a pointer to an `rbtree` type.
    - It immediately returns `NULL`, indicating that the tree creation logic is not yet implemented.
- **Output**: The function returns `NULL`, indicating that no tree is created.


---
### tree\_destroy<!-- {{#callable:tree_destroy}} -->
The `tree_destroy` function releases the resources associated with a red-black tree.
- **Inputs**:
    - `rbt`: A pointer to the red-black tree (`rbtree`) that needs to be destroyed.
- **Control Flow**:
    - The function calls `rb_release_tree` with the global `pool` and the provided `rbt` to release the resources associated with the red-black tree.
- **Output**: The function does not return any value.


---
### tree\_find<!-- {{#callable:tree_find}} -->
The `tree_find` function searches for a node with a specified key in a red-black tree and returns a pointer to the node if found.
- **Inputs**:
    - `rbt`: A pointer to the red-black tree (rbtree) in which to search for the node.
    - `key`: An integer representing the key of the node to be searched for in the tree.
- **Control Flow**:
    - A temporary `rbnode` structure named `query` is created and its `key` field is set to the input `key`.
    - The function `rb_find` is called with the global `pool`, the input `rbt`, and the address of `query` to search for the node with the specified key in the tree.
    - The result of `rb_find`, which is a pointer to the found node or NULL if not found, is returned.
- **Output**: A pointer to the `rbnode` with the specified key if found, or NULL if no such node exists in the tree.


---
### tree\_check<!-- {{#callable:tree_check}} -->
The `tree_check` function verifies the integrity of a red-black tree structure and returns a success indicator.
- **Inputs**:
    - `rbt`: A pointer to the red-black tree (rbtree) that needs to be verified.
- **Control Flow**:
    - The function calls `rb_verify` with the global `pool` and the provided `rbt` to check the tree's integrity.
    - The `assert` statement ensures that the result of `rb_verify` is false, indicating the tree is valid.
    - If the assertion passes, the function returns 1, indicating success.
- **Output**: The function returns an integer value of 1, indicating that the tree check was successful.


---
### tree\_insert<!-- {{#callable:tree_insert}} -->
The `tree_insert` function inserts a new node with a specified key into a red-black tree, ensuring the key is within valid bounds and handling memory allocation and insertion failures.
- **Inputs**:
    - `rbt`: A double pointer to the red-black tree (`rbtree **`) where the new node will be inserted.
    - `key`: An integer representing the key of the new node to be inserted into the tree.
- **Control Flow**:
    - Check if the key is within the valid range defined by `MIN` and `MAX`; if not, log a warning and return `NULL`.
    - Acquire a new node from the memory pool and assign the key to this node.
    - Attempt to insert the node into the red-black tree using `rb_insert`; if insertion fails, log a warning, free the allocated node, and return `NULL`.
    - If insertion is successful, return the pointer to the newly inserted node.
- **Output**: Returns a pointer to the newly inserted node (`rbnode *`) if successful, or `NULL` if the key is invalid or insertion fails.


---
### tree\_delete<!-- {{#callable:tree_delete}} -->
The `tree_delete` function removes a node with a specified key from a red-black tree and verifies the deletion.
- **Inputs**:
    - `rbt`: A double pointer to the red-black tree from which a node is to be deleted.
    - `key`: An integer key representing the node to be deleted from the tree.
- **Control Flow**:
    - Create a temporary `rbnode` structure `key2` and set its key to the input `key`.
    - Use `rb_find` to search for the node with the specified key in the tree; if not found, log a warning and return 0.
    - If the node is found, call `rb_remove` to remove the node from the tree.
    - Release the node's resources using `rb_release`.
    - Verify the node is no longer in the tree using `rb_find`; if it still exists, log a warning and return 0.
    - If the node was successfully deleted, return 1.
- **Output**: Returns 1 if the node was successfully deleted, otherwise returns 0 if the node was not found or deletion failed.


---
### swap<!-- {{#callable:swap}} -->
The `swap` function exchanges the values of two characters pointed to by the input pointers.
- **Inputs**:
    - `x`: A pointer to a character whose value is to be swapped with the character pointed to by `y`.
    - `y`: A pointer to a character whose value is to be swapped with the character pointed to by `x`.
- **Control Flow**:
    - Declare a temporary character variable `temp`.
    - Assign the value pointed to by `x` to `temp`.
    - Assign the value pointed to by `y` to the location pointed to by `x`.
    - Assign the value stored in `temp` to the location pointed to by `y`.
- **Output**: The function does not return a value; it modifies the values at the memory locations pointed to by `x` and `y`.


---
### permute<!-- {{#callable:permute}} -->
The [`permute`](#permute) function generates all permutations of a given string and applies a specified function to each permutation.
- **Inputs**:
    - `a`: A pointer to a character array (string) that is to be permuted.
    - `start`: The starting index from which permutations should begin.
    - `end`: The ending index at which permutations should end.
    - `func`: A function pointer to a function that takes a character array as an argument and is called for each permutation.
- **Control Flow**:
    - Check if the start index is equal to the end index; if so, call the function `func` with the current permutation and return.
    - Iterate over the range from the start index to the end index.
    - For each iteration, swap the character at the start index with the character at the current index.
    - Recursively call [`permute`](#permute) with the start index incremented by one.
    - Swap back the characters at the start index and the current index to restore the original order.
- **Output**: The function does not return a value; it applies the provided function to each permutation of the input string.
- **Functions called**:
    - [`swap`](#swap)
    - [`permute`](#permute)


---
### permutation\_insert<!-- {{#callable:permutation_insert}} -->
The `permutation_insert` function inserts each character of a given string into a red-black tree, checking for successful insertion and tree integrity after each operation.
- **Inputs**:
    - `a`: A pointer to a null-terminated string of characters to be inserted into the red-black tree.
- **Control Flow**:
    - Initialize a red-black tree using [`tree_create`](#tree_create).
    - Iterate over each character in the input string `a`.
    - For each character, attempt to insert it into the red-black tree using [`tree_insert`](#tree_insert).
    - Check if the insertion was successful, if the node can be found in the tree, and if the tree maintains its integrity using [`tree_check`](#tree_check).
    - If any of these checks fail, log a warning, increment the `permutation_error` counter, and exit the function early.
    - After all characters are processed, destroy the red-black tree using [`tree_destroy`](#tree_destroy).
- **Output**: The function does not return a value but modifies the global `permutation_error` variable if an insertion fails.
- **Functions called**:
    - [`tree_create`](#tree_create)
    - [`tree_insert`](#tree_insert)
    - [`tree_find`](#tree_find)
    - [`tree_check`](#tree_check)
    - [`tree_destroy`](#tree_destroy)


---
### permutation\_delete<!-- {{#callable:permutation_delete}} -->
The `permutation_delete` function deletes characters from a red-black tree that were previously inserted, ensuring the tree remains valid after each deletion.
- **Inputs**:
    - `a`: A string of characters to be deleted from the red-black tree.
- **Control Flow**:
    - Initialize a red-black tree `rbt` using [`tree_create`](#tree_create).
    - Define a character array `b` with the value of `CHARS` ("ABCDEFGHIJ").
    - Iterate over each character in `b`, inserting it into the red-black tree `rbt` using [`tree_insert`](#tree_insert).
    - For each insertion, verify the node was inserted correctly, the node can be found, and the tree is valid using [`tree_find`](#tree_find) and [`tree_check`](#tree_check).
    - If any insertion fails, log a warning, increment `permutation_error`, and exit the function.
    - Iterate over each character in the input string `a`, deleting it from the red-black tree `rbt` using [`tree_delete`](#tree_delete).
    - For each deletion, verify the node was deleted correctly and the tree is valid using [`tree_check`](#tree_check).
    - If any deletion fails, log a warning, increment `permutation_error`, and exit the function.
    - Destroy the red-black tree `rbt` using [`tree_destroy`](#tree_destroy).
- **Output**: The function does not return a value, but it modifies the global variable `permutation_error` to indicate if any errors occurred during the deletion process.
- **Functions called**:
    - [`tree_create`](#tree_create)
    - [`tree_insert`](#tree_insert)
    - [`tree_find`](#tree_find)
    - [`tree_check`](#tree_check)
    - [`tree_delete`](#tree_delete)
    - [`tree_destroy`](#tree_destroy)


---
### make\_black\_tree<!-- {{#callable:make_black_tree}} -->
The `make_black_tree` function creates a red-black tree, performs a series of insertions and deletions, and verifies the tree's structure and node colors, returning the tree if successful or NULL if any operation fails.
- **Inputs**: None
- **Control Flow**:
    - Initialize a red-black tree using [`tree_create`](#tree_create).
    - Insert characters from string `a` into the tree, checking after each insertion that the tree is valid using [`tree_check`](#tree_check).
    - Delete characters from string `b` from the tree, checking after each deletion that the tree is valid using [`tree_check`](#tree_check).
    - Verify that nodes corresponding to characters in string `c` exist in the tree and are colored black.
    - Check specific node relationships to ensure the tree structure is correct.
    - If any operation fails, destroy the tree and return NULL.
- **Output**: Returns a pointer to a valid red-black tree if all operations succeed, or NULL if any operation fails.
- **Functions called**:
    - [`tree_create`](#tree_create)
    - [`tree_insert`](#tree_insert)
    - [`tree_check`](#tree_check)
    - [`tree_delete`](#tree_delete)
    - [`tree_find`](#tree_find)
    - [`tree_destroy`](#tree_destroy)


---
### unit\_test\_create<!-- {{#callable:unit_test_create}} -->
The `unit_test_create` function tests the creation and destruction of a red-black tree.
- **Inputs**: None
- **Control Flow**:
    - Declare a pointer `rbt` of type `rbtree`.
    - Call `tree_create()` to initialize a new red-black tree and assign it to `rbt`.
    - Call `tree_destroy(rbt)` to destroy the created tree.
    - Return 1 to indicate the test passed successfully.
- **Output**: The function returns an integer value `1`, indicating the test was successful.
- **Functions called**:
    - [`tree_create`](#tree_create)
    - [`tree_destroy`](#tree_destroy)


---
### unit\_test\_find<!-- {{#callable:unit_test_find}} -->
The `unit_test_find` function tests the insertion and retrieval of nodes in a red-black tree to ensure that the [`tree_find`](#tree_find) function correctly locates nodes by their keys.
- **Inputs**: None
- **Control Flow**:
    - Create a red-black tree using [`tree_create`](#tree_create).
    - Insert nodes with keys 'R', 'E', 'D', 'S', 'O', 'X', 'C', 'U', 'B', 'T' into the tree using [`tree_insert`](#tree_insert).
    - Check if the tree is valid using [`tree_check`](#tree_check); if any insertion fails or the tree is invalid, log a warning and go to the error handling section.
    - For each inserted node, use [`tree_find`](#tree_find) to verify that the node can be found by its key; if any node cannot be found, log a warning and go to the error handling section.
    - If all nodes are found correctly, destroy the tree and return 1 indicating success.
    - In the error handling section, destroy the tree and return 0 indicating failure.
- **Output**: The function returns 1 if all nodes are inserted and found successfully, otherwise it returns 0 if any operation fails.
- **Functions called**:
    - [`tree_create`](#tree_create)
    - [`tree_insert`](#tree_insert)
    - [`tree_check`](#tree_check)
    - [`tree_find`](#tree_find)
    - [`tree_destroy`](#tree_destroy)


---
### unit\_test\_successor<!-- {{#callable:unit_test_successor}} -->
The `unit_test_successor` function tests the functionality of finding the successor of nodes in a red-black tree after performing a series of insertions and deletions.
- **Inputs**: None
- **Control Flow**:
    - Create a red-black tree using [`tree_create`](#tree_create).
    - Insert nodes with keys 'R', 'E', 'D', 'S', 'O', 'X', 'C', 'U', 'B', 'T' into the tree using [`tree_insert`](#tree_insert).
    - Delete the node with key 'O' using [`tree_delete`](#tree_delete).
    - Check the integrity of the tree using [`tree_check`](#tree_check).
    - Verify the successor of each node using `rb_successor` to ensure it matches the expected order: B -> C, C -> D, D -> E, E -> R, R -> S, S -> T, T -> U, U -> X, X -> NULL.
    - If any step fails, log a warning and go to the error handling section.
    - Destroy the tree using [`tree_destroy`](#tree_destroy) and return 1 if all tests pass.
    - In the error handling section, destroy the tree and return 0.
- **Output**: Returns 1 if all successor tests pass, otherwise returns 0 if any test fails.
- **Functions called**:
    - [`tree_create`](#tree_create)
    - [`tree_insert`](#tree_insert)
    - [`tree_delete`](#tree_delete)
    - [`tree_check`](#tree_check)
    - [`tree_destroy`](#tree_destroy)


---
### unit\_test\_atomic\_insertion<!-- {{#callable:unit_test_atomic_insertion}} -->
The `unit_test_atomic_insertion` function tests the atomic insertion operations on a red-black tree by inserting predefined character sequences and verifying the tree's integrity after each insertion.
- **Inputs**: None
- **Control Flow**:
    - Initialize a 2D array `cs` with predefined character sequences representing different tree states and a corresponding `name` array for descriptive test names.
    - Iterate over each sequence in `cs`, creating a new red-black tree for each sequence.
    - For each character in the current sequence, attempt to insert it into the tree and check the tree's integrity using [`tree_check`](#tree_check).
    - If an insertion fails or the tree check fails, log a warning message with the test name and character, then jump to the error handling section.
    - If all insertions succeed for a sequence, destroy the tree and proceed to the next sequence.
    - If any test fails, destroy the tree and return 0; otherwise, return 1 after all tests pass.
- **Output**: The function returns 1 if all atomic insertion tests pass successfully, otherwise it returns 0 if any test fails.
- **Functions called**:
    - [`tree_create`](#tree_create)
    - [`tree_insert`](#tree_insert)
    - [`tree_check`](#tree_check)
    - [`tree_destroy`](#tree_destroy)


---
### unit\_test\_chain\_insertion<!-- {{#callable:unit_test_chain_insertion}} -->
The `unit_test_chain_insertion` function tests the insertion of a sequence of integers into a red-black tree and verifies the tree's integrity after each insertion.
- **Inputs**: None
- **Control Flow**:
    - Initialize two integer arrays, `a1` and `a2`, with predefined values.
    - Iterate over each element in `a1`, creating a new red-black tree for each element.
    - For each tree, iterate over all elements in `a2`, inserting each into the tree and checking the tree's integrity after each insertion.
    - Insert the current element from `a1` into the tree and check the tree's integrity.
    - If any insertion or integrity check fails, log a warning and jump to the error handling section.
    - Destroy the tree after all insertions are complete.
    - Return 1 if all insertions and checks are successful, otherwise return 0 after handling errors.
- **Output**: The function returns 1 if all insertions and tree integrity checks are successful, otherwise it returns 0 if any insertion or check fails.
- **Functions called**:
    - [`tree_create`](#tree_create)
    - [`tree_insert`](#tree_insert)
    - [`tree_check`](#tree_check)
    - [`tree_destroy`](#tree_destroy)


---
### unit\_test\_atomic\_deletion<!-- {{#callable:unit_test_atomic_deletion}} -->
The `unit_test_atomic_deletion` function tests the atomic deletion operations on a red-black tree by inserting and then deleting specific sequences of nodes, ensuring the tree remains balanced and valid after each operation.
- **Inputs**:
    - `void`: This function does not take any input parameters.
- **Control Flow**:
    - Initialize a red-black tree pointer `rbt` and loop through a predefined set of test cases `cs` and their descriptions `name`.
    - For each test case, create a new red-black tree using `tree_create()`.
    - Insert nodes into the tree as specified by the current test case's first array, checking after each insertion that the tree remains valid using `tree_check()`.
    - If any insertion fails, log a warning message and jump to the error handling section.
    - Delete nodes from the tree as specified by the current test case's second array, again checking after each deletion that the tree remains valid.
    - If any deletion fails, log a warning message and jump to the error handling section.
    - Destroy the tree using `tree_destroy()` after processing each test case.
    - Return 1 if all test cases pass without errors, otherwise return 0 after handling errors.
- **Output**: The function returns an integer: 1 if all atomic deletion tests pass successfully, or 0 if any test fails.
- **Functions called**:
    - [`tree_create`](#tree_create)
    - [`tree_insert`](#tree_insert)
    - [`tree_check`](#tree_check)
    - [`tree_delete`](#tree_delete)
    - [`tree_destroy`](#tree_destroy)


---
### unit\_test\_chain\_deletion<!-- {{#callable:unit_test_chain_deletion}} -->
The `unit_test_chain_deletion` function tests the deletion of specific nodes from a red-black tree and verifies the tree's integrity after each deletion.
- **Inputs**: None
- **Control Flow**:
    - Initialize a character array `a` with the string "BEGI" and determine its length `n`.
    - Iterate over each character in `a`, creating a new red-black tree `rbt` using [`make_black_tree`](#make_black_tree) for each character.
    - If [`make_black_tree`](#make_black_tree) returns `NULL`, log a warning and jump to the error handling section.
    - Attempt to delete the current character from the tree using [`tree_delete`](#tree_delete) and check the tree's integrity with [`tree_check`](#tree_check).
    - If deletion or integrity check fails, log a warning and jump to the error handling section.
    - Destroy the tree `rbt` after processing each character.
    - Return 1 if all deletions and checks are successful.
    - In the error handling section, destroy the tree if it exists and return 0.
- **Output**: The function returns 1 if all deletions and integrity checks are successful, otherwise it returns 0.
- **Functions called**:
    - [`make_black_tree`](#make_black_tree)
    - [`tree_delete`](#tree_delete)
    - [`tree_check`](#tree_check)
    - [`tree_destroy`](#tree_destroy)


---
### unit\_test\_permutation\_insertion<!-- {{#callable:unit_test_permutation_insertion}} -->
The `unit_test_permutation_insertion` function tests the insertion of all permutations of a predefined set of characters into a red-black tree and checks for errors during the process.
- **Inputs**:
    - `void`: This function does not take any input parameters.
- **Control Flow**:
    - Initialize a character array `a` with the value of `CHARS`, which is "ABCDEFGHIJ".
    - Set the global variable `permutation_error` to 0 to track any errors during permutation insertions.
    - Call the [`permute`](#permute) function with `a`, starting index 0, ending index `strlen(a) - 1`, and the `permutation_insert` function as arguments.
    - The [`permute`](#permute) function generates all permutations of the array `a` and applies the `permutation_insert` function to each permutation.
    - Return 1 if `permutation_error` remains 0, indicating no errors occurred during the insertions; otherwise, return 0.
- **Output**: The function returns an integer value: 1 if all permutations were inserted without errors, or 0 if any errors occurred during the insertion process.
- **Functions called**:
    - [`permute`](#permute)


---
### unit\_test\_permutation\_deletion<!-- {{#callable:unit_test_permutation_deletion}} -->
The `unit_test_permutation_deletion` function tests the deletion of all permutations of a predefined set of characters from a red-black tree.
- **Inputs**: None
- **Control Flow**:
    - Initialize a character array `a` with the value of `CHARS`.
    - Set `permutation_error` to 0 to track any errors during permutation deletions.
    - Call the [`permute`](#permute) function with `a`, starting index 0, ending index `strlen(a) - 1`, and the `permutation_delete` function as arguments.
    - Return 1 if `permutation_error` is 0, indicating success, otherwise return 0.
- **Output**: The function returns an integer, 1 if all permutations were successfully deleted without errors, otherwise 0.
- **Functions called**:
    - [`permute`](#permute)


---
### unit\_test\_random\_insertion\_deletion<!-- {{#callable:unit_test_random_insertion_deletion}} -->
The function `unit_test_random_insertion_deletion` tests the random insertion and deletion of keys in a red-black tree, ensuring the tree maintains its properties throughout the operations.
- **Inputs**: None
- **Control Flow**:
    - Initialize a red-black tree `rbt` using [`tree_create`](#tree_create).
    - Set `ninsert` and `ndelete` counters to zero and `max` to 9999.
    - Seed the random number generator with the current time.
    - Perform 1999 iterations where a random key is generated and inserted into the tree if it is not already present, incrementing `ninsert` for each successful insertion.
    - Check the tree's integrity after each insertion using [`tree_check`](#tree_check); log a warning and exit on failure.
    - Perform up to 9998 iterations where a random key is generated and deleted from the tree if it is present, incrementing `ndelete` for each successful deletion.
    - Check the tree's integrity after each deletion using [`tree_check`](#tree_check); log a warning and exit on failure.
    - Log the number of successful insertions and deletions.
    - Destroy the tree using [`tree_destroy`](#tree_destroy) and return 1 on success.
    - On any error during insertion or deletion, destroy the tree and return 0.
- **Output**: The function returns 1 if all insertions and deletions are successful and the tree maintains its properties; otherwise, it returns 0.
- **Functions called**:
    - [`tree_create`](#tree_create)
    - [`tree_find`](#tree_find)
    - [`tree_insert`](#tree_insert)
    - [`tree_check`](#tree_check)
    - [`tree_delete`](#tree_delete)
    - [`tree_destroy`](#tree_destroy)


---
### unit\_test\_min<!-- {{#callable:unit_test_min}} -->
The `unit_test_min` function tests the functionality of finding the minimum element in a red-black tree after a series of insertions and deletions.
- **Inputs**: None
- **Control Flow**:
    - Create a new red-black tree using [`tree_create`](#tree_create).
    - Define a macro `RB_MINIMAL` to find the minimum node in the tree using `rb_minimum`.
    - Check if the minimum of an empty tree is `NULL`.
    - Insert 'B' into the tree and check if it becomes the minimum.
    - Insert 'A' into the tree and check if it becomes the new minimum.
    - Insert 'C' into the tree and verify that 'A' remains the minimum.
    - Delete 'B' and verify that 'A' is still the minimum.
    - Delete 'A' and check if 'C' becomes the new minimum.
    - Delete 'C' and verify that the tree is empty, hence the minimum is `NULL`.
    - If any of the checks fail, log a warning and go to the error handling section.
    - Destroy the tree and return 1 if all checks pass.
    - In the error handling section, destroy the tree and return 0.
- **Output**: The function returns 1 if all tests pass, indicating the minimum functionality works correctly, or 0 if any test fails.
- **Functions called**:
    - [`tree_create`](#tree_create)
    - [`tree_insert`](#tree_insert)
    - [`tree_find`](#tree_find)
    - [`tree_delete`](#tree_delete)
    - [`tree_destroy`](#tree_destroy)


# Function Declarations (Public API)

---
### tree\_create<!-- {{#callable_declaration:tree_create}} -->
Creates a new red-black tree.
- **Description**: Use this function to initialize a new red-black tree structure. This function is typically called before performing any operations on the tree, such as insertion or deletion. It is important to note that the function currently returns NULL, indicating that the tree is not actually created or initialized. This behavior suggests that the function may be a placeholder or requires further implementation to return a valid tree structure.
- **Inputs**: None
- **Output**: Returns a pointer to a newly created red-black tree, or NULL if the tree is not created.
- **See also**: [`tree_create`](#tree_create)  (Implementation)


---
### tree\_destroy<!-- {{#callable_declaration:tree_destroy}} -->
Destroys a red-black tree and releases its resources.
- **Description**: Use this function to properly dispose of a red-black tree when it is no longer needed. It ensures that all resources associated with the tree are released. This function should be called to prevent memory leaks after the tree is no longer in use. The tree must have been previously created and initialized before calling this function.
- **Inputs**:
    - `rbt`: A pointer to the red-black tree to be destroyed. The tree must have been previously created and must not be null. Passing a null pointer results in undefined behavior.
- **Output**: None
- **See also**: [`tree_destroy`](#tree_destroy)  (Implementation)


---
### tree\_find<!-- {{#callable_declaration:tree_find}} -->
Searches for a node with the specified key in the red-black tree.
- **Description**: Use this function to locate a node within a red-black tree by its key. It is essential that the red-black tree has been properly initialized and populated with nodes before calling this function. The function will return a pointer to the node if it exists, or NULL if no node with the specified key is found. This function does not modify the tree or its nodes.
- **Inputs**:
    - `rbt`: A pointer to the red-black tree in which to search. Must not be null and should point to a valid, initialized red-black tree structure.
    - `key`: An integer representing the key of the node to search for. There are no specific constraints on the key value, but it should be within the range of keys used in the tree.
- **Output**: Returns a pointer to the rbnode with the specified key if found, or NULL if no such node exists in the tree.
- **See also**: [`tree_find`](#tree_find)  (Implementation)


---
### tree\_check<!-- {{#callable_declaration:tree_check}} -->
Checks the validity of a red-black tree.
- **Description**: Use this function to verify the structural integrity and properties of a red-black tree. It should be called whenever you need to ensure that the tree maintains its red-black properties, such as after insertions or deletions. The function assumes that the tree has been properly initialized and that the provided pointer is valid. It is important to note that this function will terminate the program if the tree is invalid, as it uses an assertion to perform the check.
- **Inputs**:
    - `rbt`: A pointer to the red-black tree to be checked. Must not be null and should point to a valid red-black tree structure.
- **Output**: Returns 1 if the tree is valid. The function will assert and terminate the program if the tree is invalid.
- **See also**: [`tree_check`](#tree_check)  (Implementation)


---
### tree\_insert<!-- {{#callable_declaration:tree_insert}} -->
Inserts a key into a red-black tree.
- **Description**: Use this function to insert a new key into a red-black tree, which is a self-balancing binary search tree. The function should be called with a pointer to the tree and the key to be inserted. It returns a pointer to the newly inserted node if successful, or NULL if the insertion fails or if the key is outside the valid range. Ensure that the tree has been properly initialized before calling this function.
- **Inputs**:
    - `rbt`: A pointer to a pointer to the red-black tree where the key will be inserted. The tree must be initialized before calling this function. The caller retains ownership.
    - `key`: An integer representing the key to be inserted into the tree. The key must be within the range defined by MIN and MAX. If the key is outside this range, the function will return NULL.
- **Output**: Returns a pointer to the newly inserted node if the insertion is successful. Returns NULL if the key is invalid or if the insertion fails.
- **See also**: [`tree_insert`](#tree_insert)  (Implementation)


---
### tree\_delete<!-- {{#callable_declaration:tree_delete}} -->
Deletes a node with the specified key from a red-black tree.
- **Description**: Use this function to remove a node with a given key from a red-black tree. It should be called when you need to delete an element from the tree. The function requires a valid pointer to the red-black tree and a key to identify the node to be deleted. If the key is not found in the tree, the function logs a warning and returns 0. After deletion, it verifies that the node is no longer in the tree, logging a warning if the deletion was unsuccessful. The function returns 1 on successful deletion and 0 if the node was not found or the deletion failed.
- **Inputs**:
    - `rbt`: A pointer to a pointer to the red-black tree from which the node should be deleted. The tree must be initialized and must not be null. The caller retains ownership.
    - `key`: An integer key identifying the node to be deleted. The key must be within the valid range of keys used in the tree.
- **Output**: Returns 1 if the node with the specified key was successfully deleted, or 0 if the node was not found or the deletion failed.
- **See also**: [`tree_delete`](#tree_delete)  (Implementation)


---
### make\_black\_tree<!-- {{#callable_declaration:make_black_tree}} -->
Creates a red-black tree with specific nodes and properties.
- **Description**: This function initializes a red-black tree, inserts a predefined set of nodes, deletes certain nodes, and verifies the properties of the remaining nodes to ensure they are black. It is useful for setting up a red-black tree with a known structure and properties, particularly for testing or demonstration purposes. The function returns a pointer to the created tree if successful, or NULL if any operation fails, ensuring the tree maintains its red-black properties throughout the process.
- **Inputs**: None
- **Output**: Returns a pointer to the created red-black tree, or NULL if an error occurs during tree operations.
- **See also**: [`make_black_tree`](#make_black_tree)  (Implementation)


---
### swap<!-- {{#callable_declaration:swap}} -->
Swaps the values of two characters.
- **Description**: Use this function to exchange the values of two characters pointed to by the given pointers. This is useful in algorithms that require swapping elements, such as sorting or permutation generation. Ensure that the pointers provided are valid and point to allocated memory locations, as the function directly dereferences them. The function does not perform any checks on the validity of the pointers, so passing null or invalid pointers will result in undefined behavior.
- **Inputs**:
    - `x`: A pointer to a character whose value will be swapped with the character pointed to by 'y'. Must not be null.
    - `y`: A pointer to a character whose value will be swapped with the character pointed to by 'x'. Must not be null.
- **Output**: None
- **See also**: [`swap`](#swap)  (Implementation)


---
### permute<!-- {{#callable_declaration:permute}} -->
Generates all permutations of a string and applies a function to each permutation.
- **Description**: Use this function to generate all possible permutations of a given string and apply a specified function to each permutation. This function is useful when you need to perform operations on every permutation of a set of characters. The function must be called with a valid string, and the start and end indices must define a valid range within the string. The provided function will be called with each permutation of the string, allowing for custom operations on each permutation. Ensure that the function pointer is not null to avoid undefined behavior.
- **Inputs**:
    - `a`: A pointer to a character array (string) that will be permuted. The string must be null-terminated, and the caller retains ownership. The function assumes the string is valid and does not perform null checks.
    - `start`: The starting index for the permutation range within the string. Must be less than or equal to 'end' and within the bounds of the string.
    - `end`: The ending index for the permutation range within the string. Must be greater than or equal to 'start' and within the bounds of the string.
    - `func`: A pointer to a function that takes a character pointer as an argument. This function will be called with each permutation of the string. The function pointer must not be null.
- **Output**: None
- **See also**: [`permute`](#permute)  (Implementation)


---
### permutation\_insert<!-- {{#callable_declaration:permutation_insert}} -->
Inserts characters from a string into a red-black tree.
- **Description**: This function takes a string and inserts each character into a red-black tree, ensuring that the tree maintains its properties after each insertion. It is useful for applications that require dynamic set operations with balanced tree properties. The function logs a warning and increments a global error counter if any insertion fails or if the tree properties are violated. It should be called with a valid, null-terminated string and assumes that the red-black tree can handle the character values provided.
- **Inputs**:
    - `a`: A pointer to a null-terminated string of characters to be inserted into the tree. The string must not be null, and each character should be within the valid range for insertion into the tree. Invalid characters or a null pointer will result in a logged warning and an increment of the global error counter.
- **Output**: None
- **See also**: [`permutation_insert`](#permutation_insert)  (Implementation)


---
### permutation\_delete<!-- {{#callable_declaration:permutation_delete}} -->
Deletes specified characters from a red-black tree initialized with a predefined set of characters.
- **Description**: This function is used to remove characters from a red-black tree that is initially populated with a predefined set of characters ('A' to 'J'). It is useful when you need to ensure that specific characters are no longer present in the tree. The function expects a string of characters to be deleted from the tree. It logs a warning and increments an error counter if any deletion fails or if the tree's integrity is compromised after an operation. The function should be called when you need to perform a batch deletion of characters from the tree.
- **Inputs**:
    - `a`: A null-terminated string containing characters to be deleted from the tree. Each character in the string should be within the set of predefined characters ('A' to 'J'). The caller retains ownership of the string, and it must not be null.
- **Output**: None
- **See also**: [`permutation_delete`](#permutation_delete)  (Implementation)


---
### unit\_test\_create<!-- {{#callable_declaration:unit_test_create}} -->
Runs a basic unit test for creating and destroying a red-black tree.
- **Description**: This function is used to perform a simple unit test that involves creating a red-black tree and then immediately destroying it. It is intended to verify that the creation and destruction processes do not result in errors or resource leaks. This function is typically used in a testing context to ensure the basic functionality of tree creation and destruction is working as expected.
- **Inputs**: None
- **Output**: Returns 1 to indicate the test was executed, but does not provide information on success or failure of the operations.
- **See also**: [`unit_test_create`](#unit_test_create)  (Implementation)


---
### unit\_test\_find<!-- {{#callable_declaration:unit_test_find}} -->
Tests the find operation in a red-black tree.
- **Description**: This function is used to verify the correctness of the find operation in a red-black tree by inserting a series of nodes and then checking if each node can be correctly found. It should be called as part of a suite of unit tests to ensure the integrity of tree operations. The function assumes that the tree creation and insertion functions are working correctly and that the tree is properly initialized before the find operations are tested. It returns a success or failure status based on whether all nodes were found correctly.
- **Inputs**: None
- **Output**: Returns 1 if all nodes are found correctly, otherwise returns 0.
- **See also**: [`unit_test_find`](#unit_test_find)  (Implementation)


---
### unit\_test\_successor<!-- {{#callable_declaration:unit_test_successor}} -->
Performs a unit test for the rb_successor function in a red-black tree.
- **Description**: This function is used to verify the correctness of the rb_successor function, which finds the successor of a given node in a red-black tree. It sets up a red-black tree with specific nodes, deletes a node, and then checks if the successor function returns the expected results for each node. This function should be called as part of a suite of unit tests to ensure the integrity of red-black tree operations. It returns 1 if the test passes and 0 if it fails, logging warnings in case of failure.
- **Inputs**: None
- **Output**: Returns 1 if the test passes successfully, otherwise returns 0 if any part of the test fails.
- **See also**: [`unit_test_successor`](#unit_test_successor)  (Implementation)


---
### unit\_test\_atomic\_insertion<!-- {{#callable_declaration:unit_test_atomic_insertion}} -->
Performs unit tests for atomic insertion operations on a red-black tree.
- **Description**: This function is used to verify the correctness of atomic insertion operations in a red-black tree data structure. It tests various scenarios of node insertions, including transitions from empty nodes to 2-children nodes, 2-children nodes to 3-children nodes, and so on, up to the splitting of 4-children nodes. The function should be called as part of a suite of unit tests to ensure the red-black tree maintains its properties after each insertion. It returns a success or failure status based on whether all test cases pass without errors.
- **Inputs**: None
- **Output**: Returns 1 if all atomic insertion tests pass successfully, otherwise returns 0 if any test fails.
- **See also**: [`unit_test_atomic_insertion`](#unit_test_atomic_insertion)  (Implementation)


---
### unit\_test\_chain\_insertion<!-- {{#callable_declaration:unit_test_chain_insertion}} -->
Tests the insertion of a sequence of integers into a red-black tree.
- **Description**: This function is used to verify the correct insertion of a predefined sequence of integers into a red-black tree, ensuring that the tree maintains its properties after each insertion. It is typically used in a testing context to validate the integrity of the tree operations. The function iterates over two arrays of integers, inserting elements from the second array into a newly created tree, followed by an element from the first array. If any insertion fails or the tree properties are violated, the function logs a warning and returns 0, indicating failure. Otherwise, it returns 1, indicating success.
- **Inputs**: None
- **Output**: Returns 1 if all insertions are successful and the tree properties are maintained; returns 0 if any insertion fails or the tree properties are violated.
- **See also**: [`unit_test_chain_insertion`](#unit_test_chain_insertion)  (Implementation)


---
### unit\_test\_atomic\_deletion<!-- {{#callable_declaration:unit_test_atomic_deletion}} -->
Performs unit tests for atomic deletion operations on a red-black tree.
- **Description**: This function is used to verify the correctness of atomic deletion operations in a red-black tree data structure. It tests various scenarios where nodes are deleted from the tree, ensuring that the tree maintains its properties after each deletion. The function should be called as part of a test suite to validate the integrity of deletion operations. It returns a success or failure status based on whether all test cases pass. The function assumes that the red-black tree implementation and related functions are correctly defined and available.
- **Inputs**: None
- **Output**: Returns 1 if all deletion tests pass, otherwise returns 0 if any test fails.
- **See also**: [`unit_test_atomic_deletion`](#unit_test_atomic_deletion)  (Implementation)


---
### unit\_test\_chain\_deletion<!-- {{#callable_declaration:unit_test_chain_deletion}} -->
Tests the deletion of a sequence of nodes from a red-black tree.
- **Description**: This function is used to verify the correct deletion of a sequence of nodes from a red-black tree. It is typically called as part of a suite of unit tests to ensure the integrity and correctness of tree operations. The function attempts to delete a predefined sequence of characters from a tree and checks the tree's validity after each deletion. It returns a success or failure status based on whether all deletions were successful and the tree remained valid. This function should be used in a controlled test environment and assumes that the tree creation and deletion functions are correctly implemented.
- **Inputs**: None
- **Output**: Returns 1 if all deletions are successful and the tree remains valid; otherwise, returns 0.
- **See also**: [`unit_test_chain_deletion`](#unit_test_chain_deletion)  (Implementation)


---
### unit\_test\_permutation\_insertion<!-- {{#callable_declaration:unit_test_permutation_insertion}} -->
Tests the insertion of all permutations of a predefined character set into a red-black tree.
- **Description**: This function is used to verify the correctness of the red-black tree insertion logic by attempting to insert all permutations of a predefined set of characters into the tree. It should be called as part of a suite of unit tests to ensure that the tree maintains its properties across all possible insertion orders. The function assumes that the red-black tree and related functions are correctly initialized and available. It returns a boolean indicating whether all permutations were inserted without error.
- **Inputs**: None
- **Output**: Returns 1 if all permutations are inserted without error, otherwise returns 0.
- **See also**: [`unit_test_permutation_insertion`](#unit_test_permutation_insertion)  (Implementation)


---
### unit\_test\_permutation\_deletion<!-- {{#callable_declaration:unit_test_permutation_deletion}} -->
Tests the deletion of permutations in a red-black tree.
- **Description**: This function is used to test the deletion of all permutations of a predefined set of characters from a red-black tree. It should be called to verify that the tree can handle the deletion of any permutation of the characters without errors. The function initializes a permutation error counter, generates all permutations of the characters, and attempts to delete each permutation from the tree. It returns a success indicator based on whether any errors were encountered during the process.
- **Inputs**: None
- **Output**: Returns 1 if all permutations were deleted successfully without errors, otherwise returns 0.
- **See also**: [`unit_test_permutation_deletion`](#unit_test_permutation_deletion)  (Implementation)


---
### unit\_test\_random\_insertion\_deletion<!-- {{#callable_declaration:unit_test_random_insertion_deletion}} -->
Performs a unit test for random insertion and deletion in a red-black tree.
- **Description**: This function is used to test the robustness and correctness of random insertions and deletions in a red-black tree data structure. It creates a red-black tree, performs a series of random insertions followed by random deletions, and checks the integrity of the tree after each operation. The function logs warnings if any insertion or deletion fails, and it returns a success or failure status based on the outcome of these operations. This function is typically used in a testing environment to validate the implementation of red-black tree operations.
- **Inputs**: None
- **Output**: Returns 1 if all operations succeed and the tree remains valid, otherwise returns 0.
- **See also**: [`unit_test_random_insertion_deletion`](#unit_test_random_insertion_deletion)  (Implementation)


---
### unit\_test\_min<!-- {{#callable_declaration:unit_test_min}} -->
Tests the minimum value retrieval in a red-black tree.
- **Description**: This function is a unit test designed to verify the correct behavior of retrieving the minimum value from a red-black tree. It creates a new tree, performs a series of insertions and deletions, and checks if the minimum value is correctly updated after each operation. The function should be called as part of a test suite to ensure the red-black tree implementation handles minimum value retrieval correctly. It returns a success or failure status based on the test results.
- **Inputs**: None
- **Output**: Returns 1 if the test passes, or 0 if it fails.
- **See also**: [`unit_test_min`](#unit_test_min)  (Implementation)



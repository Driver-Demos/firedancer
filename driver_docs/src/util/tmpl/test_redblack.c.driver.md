# Purpose
This C source code file is an executable program that tests the functionality of a red-black tree implementation. The code defines a structure `my_rb_node` to represent nodes in the red-black tree, including fields for the key, value, parent, left and right children, and color. The program includes a main function that initializes a random number generator and sets up a memory pool for managing red-black tree nodes. It performs various operations on the red-black tree, such as insertion, searching, and deletion, to verify the correctness of the tree's behavior under different scenarios.

The code is structured to test the red-black tree's properties, such as maintaining balance and ensuring correct node ordering. It includes multiple test cases with different insertion and deletion orders to ensure robustness. The program uses assertions and error logging to detect and report any inconsistencies or errors in the tree's operations. Additionally, the code demonstrates memory management by allocating and releasing nodes from a memory pool and copying the pool's contents to a different memory location to test the tree's integrity. Overall, this file serves as a comprehensive test suite for validating the implementation of a red-black tree data structure.
# Imports and Dependencies

---
- `../fd_util.h`
- `stdlib.h`
- `assert.h`
- `fd_redblack.c`


# Global Variables

---
### scratch
- **Type**: `uchar array`
- **Description**: The `scratch` variable is a global array of unsigned characters with a size defined by `SCRATCH_FOOTPRINT`, which is set to 65536 bytes (1 << 16). It is aligned in memory according to `SCRATCH_ALIGN`, which is 128 bytes. This alignment ensures that the array starts at a memory address that is a multiple of 128, which can be beneficial for performance on certain hardware architectures.
- **Use**: The `scratch` array is used as a memory pool for red-black tree operations, providing a contiguous block of memory for node allocation and manipulation.


---
### scratch2
- **Type**: `uchar array`
- **Description**: The `scratch2` variable is a global array of unsigned characters with a size defined by `SCRATCH_FOOTPRINT`, which is set to 65536 bytes (1 << 16). It is aligned in memory according to `SCRATCH_ALIGN`, which is 128 bytes.
- **Use**: `scratch2` is used as a memory buffer to store a copy of the data from the `scratch` array, allowing for operations on a separate memory pool.


# Data Structures

---
### my\_rb\_node
- **Type**: `struct`
- **Members**:
    - `key`: Stores the key value for the node, used for ordering in the red-black tree.
    - `val`: Holds the value associated with the key in the node.
    - `redblack_parent`: Stores the index or reference to the parent node in the red-black tree.
    - `redblack_left`: Stores the index or reference to the left child node in the red-black tree.
    - `redblack_right`: Stores the index or reference to the right child node in the red-black tree.
    - `redblack_color`: Indicates the color of the node, typically used to maintain balance in the red-black tree.
- **Description**: The `my_rb_node` structure represents a node in a red-black tree, a self-balancing binary search tree. Each node contains a key and a value, along with references to its parent and children nodes, which are used to maintain the tree structure. The `redblack_color` field is crucial for maintaining the balance of the tree, as it helps enforce the properties of a red-black tree, ensuring that the tree remains approximately balanced, which allows for efficient search, insertion, and deletion operations.


---
### my\_rb\_node\_t
- **Type**: `struct`
- **Members**:
    - `key`: Stores the key value for the node, used for ordering in the red-black tree.
    - `val`: Holds the value associated with the key in the node.
    - `redblack_parent`: Stores the index or reference to the parent node in the red-black tree.
    - `redblack_left`: Stores the index or reference to the left child node in the red-black tree.
    - `redblack_right`: Stores the index or reference to the right child node in the red-black tree.
    - `redblack_color`: Indicates the color of the node, either red or black, for maintaining red-black tree properties.
- **Description**: The `my_rb_node_t` structure represents a node in a red-black tree, a self-balancing binary search tree. Each node contains a key and a value, along with references to its parent and children nodes, which are used to maintain the tree structure. The `redblack_color` field is crucial for ensuring the tree remains balanced by following red-black tree properties, which help in maintaining efficient search, insertion, and deletion operations.


# Functions

---
### my\_rb\_compare<!-- {{#callable:my_rb_compare}} -->
The `my_rb_compare` function compares two red-black tree nodes based on their keys and returns the difference as a long integer.
- **Inputs**:
    - `left`: A pointer to the first red-black tree node to be compared.
    - `right`: A pointer to the second red-black tree node to be compared.
- **Control Flow**:
    - The function takes two pointers to `my_rb_node_t` structures as input.
    - It calculates the difference between the `key` fields of the two nodes.
    - The result of the subtraction is cast to a `long` and returned.
- **Output**: A `long` integer representing the difference between the keys of the two nodes, which indicates their relative order.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes a red-black tree, performs various insertion, search, and deletion operations to test its functionality, and verifies the integrity of the tree throughout these operations.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the program environment with `fd_boot` and set up a random number generator `rng`.
    - Calculate the maximum number of nodes `max` that can fit in the scratch memory and verify the footprint size.
    - Create and join a red-black tree pool using the scratch memory and verify its maximum capacity.
    - Perform three test cases where nodes are inserted into the tree with different key patterns (ascending, descending, and pseudo-random).
    - For each test case, insert nodes into the tree, verify their presence, and check the tree's integrity.
    - Allocate a list for random insertion and deletion orderings, and perform 1000 iterations of random insertions and deletions, verifying the tree's integrity after each operation.
    - Perform additional tests with half the maximum nodes, move the pool to a different memory location, and verify the tree's integrity again.
    - Release all resources, delete the random number generator, and log a success message before halting the program.
- **Output**: The function returns an integer status code, `0`, indicating successful execution.
- **Functions called**:
    - [`my_rb_node`](#my_rb_node)



# Purpose
This C source code file is an executable program designed to test and validate the functionality of a workspace management system, likely part of a larger software library. The code includes a [`main`](#main) function, which is the entry point of the program, and it performs a series of tests on workspace operations such as allocation, deallocation, tagging, and memory setting. The program uses a random number generator to simulate various scenarios and edge cases, ensuring the robustness of the workspace management functions. The workspace operations are tested for correctness by verifying memory alignment, tag management, and memory usage statistics.

The file includes several key components: it initializes a random number generator, parses command-line arguments to configure test parameters, and performs extensive testing of workspace functions like `fd_wksp_alloc`, `fd_wksp_free`, `fd_wksp_tag`, and `fd_wksp_memset`. The code also includes conditional compilation sections for debugging purposes, such as dumping the used and free trees of the workspace, which are currently commented out. The program logs its progress and results, providing detailed feedback on the success or failure of each test case. This file is a comprehensive test suite for ensuring the integrity and performance of the workspace management system, and it is intended to be executed as a standalone application.
# Imports and Dependencies

---
- `../fd_util.h`
- `fd_wksp_private.h`
- `stdio.h`


# Global Variables

---
### scratch
- **Type**: `uchar array`
- **Description**: The `scratch` variable is a global array of unsigned characters with a maximum size defined by `SCRATCH_MAX`, which is 16384 bytes. It is aligned according to the `FD_WKSP_ALIGN` attribute, ensuring that the memory address of the array meets specific alignment requirements for efficient access.
- **Use**: This variable is used as a workspace buffer for various operations in the program, providing temporary storage that is aligned for optimal performance.


# Functions

---
### dump\_used\_tree<!-- {{#callable:dump_used_tree}} -->
The `dump_used_tree` function recursively prints a representation of a binary tree structure, showing the range of addresses and indices of nodes in a workspace's used partition.
- **Inputs**:
    - `i`: The index of the current node in the workspace's private information array.
    - `pinfo`: A pointer to an array of `fd_wksp_private_pinfo_t` structures containing information about the workspace partitions.
    - `indent`: The current indentation level for formatting the output, used to visually represent the tree structure.
- **Control Flow**:
    - Check if the current index `i` is `FD_WKSP_PRIVATE_PINFO_IDX_NULL`; if so, print a placeholder for a null node and return.
    - Recursively call `dump_used_tree` for the left child of the current node, increasing the indentation level by 4.
    - Print the current node's address range and index, then iterate through any nodes with the same index, printing their indices as well.
    - Recursively call `dump_used_tree` for the right child of the current node, again increasing the indentation level by 4.
- **Output**: The function outputs a formatted representation of the used tree structure to the standard output, showing address ranges and indices of nodes.
- **Functions called**:
    - [`fd_wksp_private_pinfo_idx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx)


---
### dump\_free\_tree<!-- {{#callable:dump_free_tree}} -->
The `dump_free_tree` function recursively prints a representation of a free memory tree structure, showing the size and indices of free memory blocks.
- **Inputs**:
    - `i`: An unsigned long integer representing the current index in the memory tree to be processed.
    - `pinfo`: A pointer to a constant array of `fd_wksp_private_pinfo_t` structures, which contains information about the memory blocks.
    - `indent`: An unsigned long integer representing the current indentation level for printing the tree structure.
- **Control Flow**:
    - Check if the current index `i` is equal to `FD_WKSP_PRIVATE_PINFO_IDX_NULL`; if so, print a placeholder for an empty node and return.
    - Recursively call `dump_free_tree` for the left child of the current node, increasing the indentation level by 4.
    - Print spaces according to the current indentation level, followed by the size of the memory block at index `i`.
    - Iterate through the linked list of nodes with the same size, printing their indices until reaching `FD_WKSP_PRIVATE_PINFO_IDX_NULL`.
    - Recursively call `dump_free_tree` for the right child of the current node, increasing the indentation level by 4.
- **Output**: The function outputs a formatted representation of the free memory tree to the standard output, showing the size and indices of free memory blocks.
- **Functions called**:
    - [`fd_wksp_private_pinfo_idx`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo_idx)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes a workspace and random number generator, processes command-line arguments, configures workspace parameters, performs various tests on workspace functions, and executes a loop to simulate workspace operations and verify their correctness.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the environment and random number generator.
    - Parse command-line arguments to set workspace parameters such as scratch size, name, seed, part max, and data max.
    - Validate and adjust workspace parameters based on constraints.
    - Log the configuration details for testing.
    - Calculate the workspace footprint and validate it against the scratch size.
    - Create and join a new workspace with the specified parameters.
    - Perform a series of tests on workspace functions like address conversion, allocation, tagging, and memory operations.
    - Enter a loop to simulate workspace operations, including allocation, freeing, resetting, and rebuilding, while periodically logging usage statistics and verifying workspace integrity.
    - After the loop, verify the workspace, clean up resources, and log a success message before halting the program.
- **Output**: The function returns an integer value of 0, indicating successful execution.
- **Functions called**:
    - [`fd_wksp_part_max_est`](fd_wksp_admin.c.driver.md#fd_wksp_part_max_est)
    - [`fd_wksp_data_max_est`](fd_wksp_admin.c.driver.md#fd_wksp_data_max_est)
    - [`fd_wksp_footprint`](fd_wksp_admin.c.driver.md#fd_wksp_footprint)
    - [`fd_wksp_join`](fd_wksp_admin.c.driver.md#fd_wksp_join)
    - [`fd_wksp_new`](fd_wksp_admin.c.driver.md#fd_wksp_new)
    - [`fd_wksp_laddr`](fd_wksp_user.c.driver.md#fd_wksp_laddr)
    - [`fd_wksp_gaddr`](fd_wksp_user.c.driver.md#fd_wksp_gaddr)
    - [`fd_wksp_laddr_fast`](fd_wksp.h.driver.md#fd_wksp_laddr_fast)
    - [`fd_wksp_gaddr_fast`](fd_wksp.h.driver.md#fd_wksp_gaddr_fast)
    - [`fd_wksp_alloc`](fd_wksp.h.driver.md#fd_wksp_alloc)
    - [`fd_wksp_tag`](fd_wksp_user.c.driver.md#fd_wksp_tag)
    - [`fd_wksp_memset`](fd_wksp_user.c.driver.md#fd_wksp_memset)
    - [`fd_wksp_free`](fd_wksp_user.c.driver.md#fd_wksp_free)
    - [`fd_wksp_tag_query`](fd_wksp_user.c.driver.md#fd_wksp_tag_query)
    - [`fd_wksp_tag_free`](fd_wksp_user.c.driver.md#fd_wksp_tag_free)
    - [`fd_wksp_reset`](fd_wksp_user.c.driver.md#fd_wksp_reset)
    - [`fd_wksp_usage`](fd_wksp.h.driver.md#fd_wksp_usage)
    - [`fd_wksp_verify`](fd_wksp_admin.c.driver.md#fd_wksp_verify)
    - [`fd_wksp_rebuild`](fd_wksp_admin.c.driver.md#fd_wksp_rebuild)
    - [`fd_wksp_alloc_at_least`](fd_wksp_user.c.driver.md#fd_wksp_alloc_at_least)
    - [`fd_wksp_delete`](fd_wksp_admin.c.driver.md#fd_wksp_delete)
    - [`fd_wksp_leave`](fd_wksp_admin.c.driver.md#fd_wksp_leave)



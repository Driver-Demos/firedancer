# Purpose
This C source code file is designed to perform a "torture test" on memory allocation and deallocation within a shared workspace, specifically focusing on same-thread allocation. The code is structured as an executable program, with a [`main`](#main) function that initializes the environment and sets up the parameters for the test, and a [`test_main`](#test_main) function that executes the core logic of the test. The primary functionality of this code is to rigorously test the allocation and deallocation of memory blocks with varying sizes and alignments, ensuring that the memory management system can handle a large number of allocations and deallocations efficiently and correctly. The test involves random allocation and deallocation of memory blocks, checking for correct alignment, size, and tag management, and verifying that the memory content remains consistent throughout the process.

The code utilizes several key components, including a workspace (`fd_wksp_t`) for memory management, a random number generator (`fd_rng_t`) for simulating random allocation patterns, and various utility functions for workspace operations. The test is designed to run on multiple tiles (or threads), with synchronization mechanisms in place to coordinate the start and end of the test across these tiles. The program also includes command-line argument parsing to customize the test parameters, such as the number of allocations, maximum alignment, and maximum size. The use of macros and conditional compilation directives (e.g., `FD_HAS_DEEPASAN`) indicates that the code is designed to be flexible and adaptable to different testing environments and configurations. Overall, this file serves as a robust testing tool for evaluating the performance and correctness of memory allocation systems in a multi-threaded context.
# Imports and Dependencies

---
- `../fd_util.h`


# Global Variables

---
### go
- **Type**: `int`
- **Description**: The `go` variable is a static integer initialized to 0, indicating that it is a global variable with file scope and internal linkage. It is used as a flag to control the execution flow of the program, particularly to signal when certain operations should commence.
- **Use**: The `go` variable is used to signal the start of the test operations by being set to 1, allowing the while loop in `test_main` to proceed.


---
### \_wksp
- **Type**: `fd_wksp_t *`
- **Description**: The `_wksp` variable is a static pointer to an `fd_wksp_t` structure, which represents a workspace used for memory allocation and management in the program. It is initialized either by attaching to an existing workspace or by creating a new anonymous workspace, depending on the command-line arguments provided.
- **Use**: This variable is used to manage memory allocations and deallocations within the program, facilitating the testing of same-thread allocation operations.


---
### \_alloc\_cnt
- **Type**: `ulong`
- **Description**: The `_alloc_cnt` variable is a static global variable of type `ulong` that represents the number of allocations to be performed during the execution of the program. It is initialized with a default value of 1048576UL, which can be overridden by a command-line argument.
- **Use**: This variable is used to control the number of memory allocations in the torture test for same-thread allocation.


---
### \_align\_max
- **Type**: `ulong`
- **Description**: The `_align_max` variable is a static global variable of type `ulong` that represents the maximum alignment constraint for memory allocations in the program. It is initialized with a default value of 4096UL, which is a power of two, ensuring that memory allocations adhere to this alignment requirement.
- **Use**: This variable is used to determine the alignment of memory allocations within the workspace, ensuring they meet the specified alignment constraints.


---
### \_sz\_max
- **Type**: `ulong`
- **Description**: The `_sz_max` variable is a static global variable of type `ulong` that represents the maximum size for memory allocations in the test program. It is initialized with a default value of 262144UL, which can be overridden by a command-line argument `--sz-max`. This variable is used to determine the upper limit for the size of memory blocks that can be allocated during the test.
- **Use**: It is used to set the maximum size for memory allocations in the test program.


# Functions

---
### test\_main<!-- {{#callable:test_main}} -->
The `test_main` function performs a stress test on memory allocation and deallocation within a workspace, ensuring correct usage and alignment while validating memory integrity.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize variables and constants, including workspace and random number generator setup.
    - Check initial workspace usage and validate its state with assertions.
    - Wait for a volatile flag `go` to be set before proceeding with the main loop.
    - Iterate over a loop twice the number of `alloc_cnt`, deciding randomly whether to allocate or free memory based on current state and constraints.
    - For allocation, determine size and alignment, allocate memory, and fill it with a unique pattern for later validation.
    - For deallocation, select a random outstanding allocation, validate its integrity, and free it.
    - After the loop, clean up by deleting the random number generator and return 0.
- **Output**: The function returns an integer, 0, indicating successful execution.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes and configures a workspace for memory allocation testing across multiple tiles, executing a test function on each tile and managing workspace resources.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the environment using `fd_boot` with command-line arguments.
    - Parse command-line arguments to configure workspace parameters such as `--wksp`, `--page-sz`, `--page-cnt`, `--near-cpu`, `--seed`, `--part-max`, `--alloc-cnt`, `--align-max`, and `--sz-max`.
    - Validate parsed parameters, ensuring they meet specific criteria (e.g., positive values, power of two).
    - Determine the number of tiles available using `fd_tile_cnt`.
    - If a workspace name is provided, attach to it using `fd_wksp_attach`; otherwise, create an anonymous workspace using `fd_wksp_new_anon`.
    - Log the configuration details for the test.
    - Check if the workspace alignment is valid; log an error if not.
    - Initialize remote tiles for execution using `fd_tile_exec_new` for each tile except the first one.
    - Pause for a short duration using `fd_log_sleep`.
    - Set a volatile flag `go` to 1 to signal the start of the test.
    - Execute the [`test_main`](#test_main) function on the main tile.
    - Wait for remote tiles to complete their execution using `fd_tile_exec_delete`.
    - Detach or delete the workspace based on whether it was attached or created anonymously.
    - Log a success message and halt the program using `fd_halt`.
- **Output**: The function returns an integer value `0`, indicating successful execution.
- **Functions called**:
    - [`test_main`](#test_main)



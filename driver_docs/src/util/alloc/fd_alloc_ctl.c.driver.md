# Purpose
This C source code file implements a command-line utility for managing memory allocation within a workspace environment. The program is designed to handle various commands related to memory allocation, such as creating new allocations, deleting them, allocating and freeing memory, compacting memory, and querying the state of allocations. The code is structured to parse command-line arguments and execute corresponding operations, providing feedback and logging for each command processed. The utility is built to work in a hosted environment, as indicated by the `FD_HAS_HOSTED` preprocessor directive, and it includes error handling to ensure robust operation.

The main technical components of this code include functions for attaching to and detaching from workspaces, allocating and freeing memory, and querying allocation properties. The code leverages a set of utility functions and macros, such as `fd_wksp_attach`, `fd_alloc_new`, and [`fd_alloc_fprintf`](#fd_alloc_fprintf), to perform these operations. The program defines a public API through its command-line interface, allowing users to interact with the memory allocation system by issuing commands like "new", "delete", "malloc", "free", "compact", and "query". Each command is associated with specific parameters and expected behaviors, which are validated and executed within the main function. The code also includes a help command to guide users on how to use the utility effectively.
# Imports and Dependencies

---
- `../fd_util.h`
- `../wksp/fd_wksp_private.h`
- `stdio.h`


# Functions

---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, checks for valid command-line arguments, and logs an error if the arguments are not supported on the current platform.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Call `fd_boot` to initialize the environment with the command-line arguments.
    - Check if `argc` is less than 1, and log an error if true.
    - Check if `argc` is greater than 1, and log an error if true, indicating that `fd_alloc_ctl` is not supported on this platform.
    - Log a notice indicating that 0 commands were processed.
    - Call `fd_halt` to clean up and terminate the program.
    - Return 0 to indicate successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution.


# Function Declarations (Public API)

---
### fd\_alloc\_fprintf<!-- {{#callable_declaration:fd_alloc_fprintf}} -->
Prints diagnostic information about a memory allocator to a specified stream.
- **Description**: Use this function to output detailed diagnostic information about a memory allocator associated with a given join object to a specified output stream. This function is useful for debugging and monitoring the state of memory allocations. It must be called with a valid join object and a non-null output stream. If the stream is null, the function will return immediately without printing anything. The function provides a summary of allocation statistics and details about each size class and large allocations.
- **Inputs**:
    - `join`: A pointer to an fd_alloc_t object representing the memory allocator to be diagnosed. The caller retains ownership and must ensure it is a valid join object.
    - `stream`: A pointer to a FILE object where the diagnostic information will be printed. Must not be null. If null, the function returns 0 without performing any operations.
- **Output**: Returns an integer indicating the number of diagnostic entries printed. If the stream is null, returns 0.
- **See also**: [`fd_alloc_fprintf`](fd_alloc.c.driver.md#fd_alloc_fprintf)  (Implementation)



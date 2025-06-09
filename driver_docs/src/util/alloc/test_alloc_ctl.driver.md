# Purpose
This Bash script is a test suite designed to validate the functionality of two command-line utilities, `fd_wksp_ctl` and `fd_alloc_ctl`, which are likely part of a larger software system dealing with workspace and memory allocation management. The script provides narrow functionality, focusing specifically on testing various operations such as creating, querying, allocating, freeing, compacting, and deleting memory allocations within a specified workspace. It sets up a test environment by defining configuration variables, cleans up any previous test artifacts, and executes a series of tests to ensure that the utilities behave as expected under different scenarios. The script is not an executable for end-users but rather a utility for developers to verify the correctness and robustness of the memory management tools in their software.
# Global Variables

---
### UNIT\_TEST
- **Type**: `string`
- **Description**: The `UNIT_TEST` variable is a string that holds the directory path of the script's source file. It is determined using the `dirname` command on the `$BASH_SOURCE` variable, which contains the path of the script being executed.
- **Use**: This variable is used to determine the location of the binaries relative to the script's location.


---
### BUILD
- **Type**: `string`
- **Description**: The `BUILD` variable is a string that holds the directory path of the build location for the binaries used in the script. It is determined by taking the directory name of the `UNIT_TEST` variable, which itself is derived from the script's source path.
- **Use**: This variable is used to construct the path to the `bin` directory, which contains the executable binaries needed for the script's operations.


---
### BIN
- **Type**: `string`
- **Description**: The `BIN` variable is a string that holds the path to the directory where the binary executables are located. It is constructed by appending '/bin' to the `BUILD` directory path, which is derived from the directory of the unit test script.
- **Use**: This variable is used to specify the location of the binary executables for various commands executed in the script.


---
### WKSP
- **Type**: `string`
- **Description**: The `WKSP` variable is a global string variable that holds the name of the workspace file used in the script. It is set to the value `test_fd_alloc_ctl.wksp`. This variable is used throughout the script to reference the workspace in various commands.
- **Use**: `WKSP` is used to specify the workspace file name for operations such as creation, deletion, and allocation control in the script.


---
### PAGE\_CNT
- **Type**: `integer`
- **Description**: The variable `PAGE_CNT` is a global integer variable set to 1. It represents the number of pages to be used when creating a workspace (`wksp`) in the script.
- **Use**: This variable is used as an argument in the command to create a new workspace, specifying the number of pages to allocate.


---
### PAGE\_SZ
- **Type**: `string`
- **Description**: The variable `PAGE_SZ` is a global string variable set to the value 'gigantic'. It is used to specify the size of a page in the context of workspace allocation and management.
- **Use**: `PAGE_SZ` is used as an argument when creating a new workspace with the `fd_wksp_ctl` command.


---
### CPU\_IDX
- **Type**: `integer`
- **Description**: The `CPU_IDX` variable is a global integer variable set to 0. It is used to specify the CPU index for operations related to workspace management in the script.
- **Use**: This variable is used as a parameter when creating a new workspace with the `fd_wksp_ctl` command, indicating which CPU index to associate with the workspace.


---
### MODE
- **Type**: `integer`
- **Description**: The `MODE` variable is a global variable defined in the script with a value of `0600`. It represents the file permission mode used when creating a new workspace (`wksp`) in the script. The mode `0600` indicates that the file is readable and writable by the owner, but not accessible by others.
- **Use**: This variable is used as an argument when creating a new workspace to set its file permission mode.


---
### TAG\_META
- **Type**: `integer`
- **Description**: `TAG_META` is a global variable defined as an integer with a value of 1234. It is used as a tag identifier in the script, likely to differentiate or categorize certain operations or data allocations.
- **Use**: This variable is used as a tag identifier when invoking the `fd_alloc_ctl` command to manage allocations.


---
### TAG\_ALLOC
- **Type**: `integer`
- **Description**: `TAG_ALLOC` is a global integer variable set to the value 2345. It is used as a tag identifier for allocation operations within the script.
- **Use**: This variable is used as a tag to identify and manage allocation operations in the `fd_alloc_ctl` command.


---
### FD\_LOG\_PATH
- **Type**: `string`
- **Description**: The `FD_LOG_PATH` variable is a global string variable that is used to specify the path for logging. In this script, it is set to an empty string, effectively disabling any permanent logging functionality.
- **Use**: This variable is used to control the logging behavior of the script, and by setting it to an empty string, it ensures that no logs are written to a file.


---
### ALLOC
- **Type**: `string`
- **Description**: The `ALLOC` variable is a string that stores the result of a command execution, specifically the output of the `fd_alloc_ctl` command when creating a new allocation with a specified tag in a workspace. This variable is used to reference the allocation for subsequent operations such as querying, allocating, freeing, compacting, and deleting memory allocations.
- **Use**: `ALLOC` is used to store and reference the identifier of a memory allocation created in a workspace for further memory management operations.


---
### GADDR0
- **Type**: `string`
- **Description**: `GADDR0` is a global variable that stores the result of a memory allocation command executed by the `fd_alloc_ctl` tool. It captures the address or identifier of the allocated memory block within the workspace specified by the `ALLOC` variable.
- **Use**: `GADDR0` is used to store the address of a memory allocation for later operations such as freeing the allocated memory.


---
### GADDR1
- **Type**: `string`
- **Description**: GADDR1 is a global variable that stores the result of a memory allocation operation performed by the fd_alloc_ctl command. It is assigned the output of the command, which is expected to be a memory address or identifier for the allocated memory block.
- **Use**: GADDR1 is used to store and reference a specific memory allocation for further operations such as freeing the memory.


---
### GADDR2
- **Type**: `string`
- **Description**: `GADDR2` is a global variable that stores the result of a memory allocation operation performed by the `fd_alloc_ctl` command. It is assigned the output of the command that allocates memory with specific parameters (6, 2, 10) for the allocation identified by `ALLOC`. This variable is used to keep track of the address or identifier of the allocated memory block.
- **Use**: `GADDR2` is used to store the address or identifier of a memory block allocated by the `fd_alloc_ctl` command for later operations such as freeing the memory.


---
### GADDR3
- **Type**: `string`
- **Description**: GADDR3 is a global variable that stores the result of a memory allocation operation performed by the fd_alloc_ctl command. It is assigned the output of the command, which is expected to be a memory address or identifier for the allocated memory block.
- **Use**: GADDR3 is used to store and reference the memory address or identifier of a specific allocated memory block for further operations such as freeing the memory.


# Functions

---
### fail
The `fail` function logs an error message, attempts to clean up a workspace, and exits the script with a failure status.
- **Inputs**:
    - `$1`: A string representing the context or name of the operation that failed.
    - `$2`: An integer representing the unexpected exit code of the failed operation.
- **Control Flow**:
    - Prints an error message to the standard output, indicating the failure context and the unexpected exit code.
    - Attempts to delete a workspace using the `fd_wksp_ctl delete` command, suppressing any output or errors.
    - Prints a message indicating that the log is not available.
    - Exits the script with a status code of 1, indicating failure.
- **Output**: The function does not return any value; it exits the script with a status code of 1.



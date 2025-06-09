# Purpose
This Bash script is a test suite designed to validate the functionality of a command-line tool named `fd_wksp_ctl`, which appears to manage workspace operations. The script provides narrow functionality, focusing specifically on testing various commands and scenarios related to workspace management, such as creating, deleting, allocating, tagging, and querying workspaces. It is not an executable or a library file but rather a test script that automates the execution of `fd_wksp_ctl` commands to ensure they behave as expected under different conditions. The script includes error handling to clean up checkpoints and log failures, ensuring that any unexpected behavior is reported and that the environment is reset for subsequent tests.
# Global Variables

---
### UNIT\_TEST
- **Type**: `string`
- **Description**: The `UNIT_TEST` variable is a global variable that stores the directory path of the script's source file. It is determined using the `dirname` command on the `$BASH_SOURCE` variable, which contains the path of the script being executed.
- **Use**: This variable is used to determine the base directory for locating other related directories or files, such as the `BUILD` and `BIN` directories.


---
### BUILD
- **Type**: `string`
- **Description**: The `BUILD` variable is a global string variable that holds the directory path of the build location for the binaries. It is determined by taking the directory of the `UNIT_TEST` variable, which itself is derived from the directory of the script's source file.
- **Use**: This variable is used to construct the path to the `bin` directory, which is then used to execute various commands in the script.


---
### BIN
- **Type**: `string`
- **Description**: The `BIN` variable is a string that holds the path to the 'bin' directory within the build directory. It is constructed by appending '/bin' to the `BUILD` variable, which itself is derived from the directory of the unit test script.
- **Use**: This variable is used to specify the location of the binary files that are executed throughout the script.


---
### WKSP
- **Type**: `string`
- **Description**: The variable `WKSP` is a string that holds the name of a workspace file, specifically 'test_fd_wksp_ctl.wksp'. This file is used in various operations throughout the script, such as creating, deleting, and managing workspace allocations.
- **Use**: `WKSP` is used as an argument in commands to specify the workspace file being operated on.


---
### PAGE\_CNT
- **Type**: `integer`
- **Description**: `PAGE_CNT` is a global variable that specifies the number of pages to be used in the workspace operations. It is set to a default value of 1, indicating that the operations will be performed on a single page by default.
- **Use**: `PAGE_CNT` is used as an argument in various commands to define the number of pages for workspace operations.


---
### PAGE\_SZ
- **Type**: `string`
- **Description**: The variable `PAGE_SZ` is a global variable defined as a string with the value 'gigantic'. It is used in the context of a script that appears to manage workspace control operations, likely related to memory or storage allocation.
- **Use**: `PAGE_SZ` is used as a parameter in various commands to specify the size of a page when creating or managing workspaces.


---
### CPU\_IDX
- **Type**: `integer`
- **Description**: `CPU_IDX` is a global variable that is initialized to the integer value 0. It is used to specify the CPU index for operations that require CPU-specific parameters.
- **Use**: This variable is used as a parameter in the `fd_wksp_ctl` command to specify the CPU index when creating a new workspace.


---
### MODE
- **Type**: `integer`
- **Description**: The variable `MODE` is a global variable defined with the value `0600`. This value represents file permissions in octal notation, commonly used in Unix-like operating systems to specify read and write permissions for the owner, and no permissions for group and others.
- **Use**: `MODE` is used as a parameter in various commands to set file permissions when creating or manipulating files and directories.


---
### CHECKPT
- **Type**: `string`
- **Description**: The `CHECKPT` variable is a global string variable that holds the name of a checkpoint file, specifically 'test_fd_wksp_ctl.checkpt'. This file is used in various test operations to store and restore workspace states during the execution of the script.
- **Use**: `CHECKPT` is used as a filename for checkpoint operations, such as creating, querying, and restoring workspace states in the script.


---
### INFO
- **Type**: `string`
- **Description**: The variable `INFO` is a global string variable initialized with the value 'The quick brown fox jumps over the lazy dog'. This is a well-known pangram, a sentence that contains every letter of the alphabet at least once.
- **Use**: `INFO` is used as a parameter in the `fd_wksp_ctl` command to provide additional information during the execution of certain operations, such as checkpointing.


---
### FD\_LOG\_PATH
- **Type**: `string`
- **Description**: The `FD_LOG_PATH` variable is a global string variable that is used to specify the path for logging in the script. In this script, it is set to an empty string, effectively disabling any permanent logging functionality.
- **Use**: `FD_LOG_PATH` is used to control the logging path, and setting it to an empty string disables logging.


---
### GADDR
- **Type**: `string`
- **Description**: The `GADDR` variable is a global variable that stores the result of an allocation command executed by the `fd_wksp_ctl` binary. This command attempts to allocate a workspace with specific parameters and, if successful, assigns the resulting address to `GADDR`. The variable is used to hold the address of the allocated memory block for further operations in the script.
- **Use**: `GADDR` is used to store the address of a successfully allocated memory block for subsequent operations in the script.


---
### GADDR1
- **Type**: `string`
- **Description**: GADDR1 is a global variable that stores the result of a command execution. Specifically, it captures the output of the command `$BIN/fd_wksp_ctl tag 1234 alloc "$WKSP" 4096 4096`, which is expected to allocate a workspace with a specific tag and size.
- **Use**: GADDR1 is used to store the address or identifier of a newly allocated workspace segment, which can be referenced later in the script for further operations.


---
### GADDR2
- **Type**: `string`
- **Description**: GADDR2 is a global variable that stores the result of a command execution, specifically the output of the 'fd_wksp_ctl' command with the 'tag' and 'alloc' options. It is used to allocate a workspace with a specific tag and size.
- **Use**: GADDR2 is used to store the address or identifier of a newly allocated workspace segment, which can be referenced in subsequent operations.


---
### GADDR3
- **Type**: `string`
- **Description**: GADDR3 is a global variable that stores the result of an allocation command executed by the fd_wksp_ctl tool. It is specifically associated with a tagged allocation using the tag 2345, within a specified workspace, with a size of 4096 bytes and an alignment of 4096 bytes.
- **Use**: GADDR3 is used to store the address returned by the allocation command, which can be referenced later in the script for operations like tag-query or tag-free.


---
### SUPPORTED\_STYLES
- **Type**: `string`
- **Description**: `SUPPORTED_STYLES` is a global variable that stores the output of the command `$BIN/fd_wksp_ctl supported-styles`. This command is expected to return a list of supported styles for the `fd_wksp_ctl` tool, which are then iterated over in the script to perform various tests with each style.
- **Use**: This variable is used to iterate over each supported style and execute a series of tests for each style in the script.


# Functions

---
### fail
The `fail` function handles unexpected exit codes by removing a checkpoint file, logging an error message, and terminating the script with an exit status of 1.
- **Inputs**:
    - `$1`: A string representing the context or name of the operation that failed.
    - `$2`: An integer representing the unexpected exit code of the operation.
- **Control Flow**:
    - Remove the file specified by the variable `CHECKPT` using `rm -fv` to forcefully and verbosely delete it.
    - Print an error message to standard output indicating the failure context and the unexpected exit code.
    - Print a message indicating that the log is not available.
    - Terminate the script with an exit status of 1 using `exit 1`.
- **Output**: The function does not return any value; it terminates the script with an exit status of 1.



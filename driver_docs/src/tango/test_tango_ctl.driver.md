# Purpose
This Bash script is a test suite designed to validate the functionality of a command-line tool, `fd_tango_ctl`, which appears to manage various resources such as workspaces, caches, sequences, and control nodes. The script provides narrow functionality, focusing specifically on testing the creation, querying, and deletion of these resources, as well as handling error cases and ensuring that the tool behaves as expected under various conditions. It is not an executable meant for general use but rather a utility for developers to verify the correctness of the `fd_tango_ctl` tool. The script sets up a testing environment, executes a series of commands to test different functionalities, and uses a helper function `fail()` to report unexpected outcomes, ensuring that any failures are logged and the script exits appropriately.
# Global Variables

---
### UNIT\_TEST
- **Type**: `string`
- **Description**: The `UNIT_TEST` variable is a string that holds the directory path of the script's source file. It is determined using the `dirname` command on the `$BASH_SOURCE` variable, which contains the path of the script being executed.
- **Use**: This variable is used to determine the location of binaries relative to the script's directory.


---
### BUILD
- **Type**: `string`
- **Description**: The `BUILD` variable is a global string variable that holds the directory path of the build location. It is determined by taking the directory of the `UNIT_TEST` variable, which itself is derived from the script's source directory.
- **Use**: This variable is used to construct the path to the `bin` directory, which is stored in the `BIN` variable, and is subsequently used to execute various commands in the script.


---
### BIN
- **Type**: `string`
- **Description**: The `BIN` variable is a string that holds the path to the directory where the binary files are located. It is constructed by appending '/bin' to the `BUILD` directory path, which is derived from the script's source directory.
- **Use**: This variable is used to specify the location of executable binaries for various commands executed in the script.


---
### WKSP
- **Type**: `string`
- **Description**: The `WKSP` variable is a string that specifies the name of the workspace file used in the script. It is set to `test_fd_tango_ctl.wksp`, which is likely a test workspace for the script's operations.
- **Use**: This variable is used to reference the workspace file in various commands throughout the script, such as creating, querying, and deleting caches and other resources.


---
### PAGE\_CNT
- **Type**: `integer`
- **Description**: The variable `PAGE_CNT` is a global integer variable initialized to 1. It represents the number of pages to be used when creating a new workspace in the script.
- **Use**: `PAGE_CNT` is used as an argument in the command to create a new workspace, specifying the number of pages to allocate.


---
### PAGE\_SZ
- **Type**: `string`
- **Description**: The variable `PAGE_SZ` is a global variable defined as a string with the value 'gigantic'. It is used in the context of specifying the size of a page for workspace operations in the script.
- **Use**: `PAGE_SZ` is used as an argument in commands that create or manipulate workspaces, indicating the size of the page to be used.


---
### CPU\_IDX
- **Type**: `integer`
- **Description**: `CPU_IDX` is a global variable set to the integer value 0. It is used to specify the CPU index for operations related to workspace management in the script.
- **Use**: This variable is used as a parameter when creating a new workspace with the `fd_wksp_ctl` command, indicating the CPU index to be used.


---
### MODE
- **Type**: `string`
- **Description**: The `MODE` variable is a global variable defined in the script with a value of `0600`. This value represents file permissions in octal notation, where the owner has read and write permissions, and no permissions are granted to the group or others.
- **Use**: This variable is used as an argument when creating a new workspace with the `fd_wksp_ctl` command, specifying the permissions for the workspace.


---
### FD\_LOG\_PATH
- **Type**: `string`
- **Description**: The `FD_LOG_PATH` is a global variable that is initialized as an empty string. It is intended to specify the path for logging, but in this script, it is set to an empty value, effectively disabling logging. The variable is exported to make it available to any subprocesses spawned by the script.
- **Use**: `FD_LOG_PATH` is used to control the logging behavior of the script, but it is set to an empty string to disable logging.


---
### MCACHE
- **Type**: `string`
- **Description**: The `MCACHE` variable is a global variable that stores the result of executing the `fd_tango_ctl new-mcache` command with specific parameters. This command is used to create a new memory cache (mcache) in the specified workspace with given size and configuration parameters.
- **Use**: `MCACHE` is used to store the identifier or reference to the newly created memory cache, which can then be queried, modified, or deleted in subsequent operations.


---
### DCACHE0
- **Type**: `string`
- **Description**: DCACHE0 is a global variable that stores the result of executing the command to create a new dcache using the fd_tango_ctl tool. It is initialized with the output of the command that specifies the workspace, size, and other parameters for the dcache.
- **Use**: DCACHE0 is used to store the identifier or reference to a newly created dcache, which can be queried or deleted later in the script.


---
### DCACHE1
- **Type**: `string`
- **Description**: The variable `DCACHE1` is a global variable that stores the result of executing the `fd_tango_ctl new-dcache` command with specific parameters. This command creates a new data cache in the specified workspace with given parameters such as size, block size, and compactness.
- **Use**: `DCACHE1` is used to store the identifier of a newly created data cache, which can be queried or deleted later in the script.


---
### DCACHE2
- **Type**: `string`
- **Description**: The variable `DCACHE2` is a string that stores the result of executing the `fd_tango_ctl new-dcache-raw` command with specific parameters. This command is used to create a new raw data cache in the specified workspace with a size of 2097152 and a block size of 4096.
- **Use**: `DCACHE2` is used to store the identifier or reference to the newly created raw data cache, which can be queried or deleted later in the script.


---
### FSEQ
- **Type**: `string`
- **Description**: The `FSEQ` variable is a string that stores the result of executing the `fd_tango_ctl new-fseq` command with the specified workspace (`WKSP`) and sequence number (2345). This command is used to create a new sequence in the specified workspace.
- **Use**: `FSEQ` is used to store the identifier of the newly created sequence, which can then be queried or deleted using subsequent commands.


---
### CNC
- **Type**: `string`
- **Description**: The `CNC` variable is a string that stores the result of executing the `fd_tango_ctl new-cnc` command with specific parameters. This command is used to create a new CNC (presumably a control or configuration entity) within the specified workspace (`WKSP`) with given parameters for type, now, and size.
- **Use**: This variable is used to store the identifier or reference to the newly created CNC, which can then be queried, signaled, or deleted in subsequent operations.


---
### TCACHE
- **Type**: `string`
- **Description**: The `TCACHE` variable is a global string variable that stores the result of creating a new transaction cache using the `fd_tango_ctl new-tcache` command. It is initialized with the output of this command, which is expected to be a unique identifier or path for the newly created transaction cache.
- **Use**: `TCACHE` is used to reference the transaction cache in subsequent operations such as querying, resetting, and deleting the cache.


# Functions

---
### fail
The `fail` function outputs an error message with a specified context and exit code, then terminates the script with an exit status of 1.
- **Inputs**:
    - `$1`: A string representing the context or description of the failure.
    - `$2`: An integer representing the unexpected exit code that triggered the failure.
- **Control Flow**:
    - The function prints a message to standard output indicating a failure, including the context and unexpected exit code.
    - It prints 'Log N/A' to indicate that no log is available.
    - The function then exits the script with a status code of 1, indicating an error.
- **Output**: The function does not return any value; it terminates the script with an exit status of 1.



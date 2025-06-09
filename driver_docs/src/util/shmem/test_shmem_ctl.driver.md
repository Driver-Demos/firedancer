# Purpose
This Bash script is a test suite designed to validate the functionality of a command-line utility named `fd_shmem_ctl`, which appears to manage shared memory operations. The script provides narrow functionality, focusing specifically on testing various commands and scenarios related to shared memory control, such as creating, querying, and unlinking shared memory segments. It is not an executable or a library file but rather a test script intended to be run in a shell environment to ensure that the `fd_shmem_ctl` utility behaves as expected under different conditions. The script includes a series of test cases that check for correct handling of both valid and invalid inputs, and it uses a helper function `fail()` to report unexpected exit codes, thereby facilitating debugging and verification of the utility's robustness.
# Global Variables

---
### UNIT\_TEST
- **Type**: `string`
- **Description**: The `UNIT_TEST` variable is a string that holds the directory path of the script's source file. It is determined using the `dirname` command on the `$BASH_SOURCE` variable, which contains the path of the currently executing script.
- **Use**: This variable is used to determine the location of binaries relative to the script's directory.


---
### BUILD
- **Type**: `string`
- **Description**: The `BUILD` variable is a string that holds the directory path of the build location for the binaries. It is determined by taking the directory of the `UNIT_TEST` variable, which itself is derived from the script's source directory. This variable is used to construct the path to the `bin` directory where the compiled binaries are expected to be located.
- **Use**: `BUILD` is used to define the path to the `bin` directory, which is then used to execute various commands in the script.


---
### BIN
- **Type**: `string`
- **Description**: The `BIN` variable is a string that holds the path to the directory where the binary files are located. It is constructed by appending '/bin' to the `BUILD` directory path, which is derived from the directory of the `UNIT_TEST` script.
- **Use**: This variable is used to specify the location of the `fd_shmem_ctl` binary, which is executed multiple times throughout the script to perform various shared memory control operations.


---
### SHMEM
- **Type**: `string`
- **Description**: The variable `SHMEM` is a global string variable that holds the name of the shared memory segment used in the script. It is set to the value 'test_fd_shmem_ctl'. This name is used in various commands to create, query, and unlink shared memory segments.
- **Use**: `SHMEM` is used as an identifier for shared memory operations in the script.


---
### PAGE\_CNT
- **Type**: `integer`
- **Description**: The variable `PAGE_CNT` is a global integer variable set to the value 3. It represents the number of pages to be used in shared memory operations.
- **Use**: `PAGE_CNT` is used as an argument in the `fd_shmem_ctl create` command to specify the number of pages to allocate for shared memory.


---
### PAGE\_SZ
- **Type**: `string`
- **Description**: The variable `PAGE_SZ` is a global variable defined as a string with the value 'normal'. It is used in the script to specify the page size for shared memory operations.
- **Use**: `PAGE_SZ` is used as an argument in various `fd_shmem_ctl` commands to define the page size for shared memory operations.


---
### CPU\_IDX
- **Type**: `integer`
- **Description**: The `CPU_IDX` variable is a global integer variable set to 0. It represents the index of the CPU to be used in the context of shared memory control operations.
- **Use**: This variable is used as a parameter in the `fd_shmem_ctl` command to specify the CPU index for operations such as creating shared memory.


---
### MODE
- **Type**: `integer`
- **Description**: The `MODE` variable is a global integer variable set to `0600`, which represents file permissions in octal notation. This permission setting allows the owner to read and write the file, while others have no permissions.
- **Use**: `MODE` is used as a parameter in the `fd_shmem_ctl create` command to specify the permissions for the shared memory segment being created.


---
### FD\_LOG\_PATH
- **Type**: `string`
- **Description**: The `FD_LOG_PATH` variable is a global string variable that is used to specify the path for logging. In this script, it is set to an empty string, effectively disabling any permanent logging functionality. This means that no logs will be written to a file or directory, as the path is not defined.
- **Use**: `FD_LOG_PATH` is used to control the logging behavior of the script by setting it to an empty string to disable logging.


# Functions

---
### fail
The `fail` function outputs an error message with a specified reason and exit code, then terminates the script with an exit status of 1.
- **Inputs**:
    - `$1`: A string representing the reason or context for the failure.
    - `$2`: An integer representing the unexpected exit code that triggered the failure.
- **Control Flow**:
    - The function prints a failure message to the standard output, including the reason and unexpected exit code.
    - It prints a placeholder message indicating that a log is not available.
    - The function then exits the script with a status code of 1, indicating an error.
- **Output**: The function does not return any value; it terminates the script with an exit status of 1.



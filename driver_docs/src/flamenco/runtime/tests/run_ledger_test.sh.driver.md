# Purpose
This Bash script is designed to automate the process of downloading, preparing, and executing a ledger replay operation, likely for a blockchain or distributed ledger system. It provides a relatively narrow functionality focused on handling ledger data, including downloading ledger archives from a cloud storage service, setting up the environment, and executing a replay command using a specific binary (`fd_ledger`). The script includes options for configuring various parameters such as the dump directory, ledger, snapshot, restore archive, and other operational settings, which are parsed from command-line arguments. It also manages authentication for accessing cloud resources and handles error logging and reporting. This script is not an executable in the traditional sense but rather a utility script intended to be run in a command-line environment to facilitate ledger data processing tasks.
# Global Variables

---
### POSITION\_ARGS
- **Type**: `array`
- **Description**: The `POSITION_ARGS` variable is a global array that is initialized as an empty array. It is used to store positional arguments that are not recognized as options or flags by the script. These arguments are collected during the command-line argument parsing process.
- **Use**: This variable is used to accumulate and store any non-option command-line arguments passed to the script for later use.


---
### OBJDIR
- **Type**: `string`
- **Description**: The `OBJDIR` variable is a global string variable that specifies the directory path where build artifacts are stored. It defaults to 'build/native/gcc' if not set externally.
- **Use**: This variable is used to define the directory path for storing coverage data and executing the `fd_ledger` binary.


---
### LEDGER
- **Type**: `string`
- **Description**: The `LEDGER` variable is a global string variable initialized as an empty string. It is used to store the path or identifier of a ledger, which is a data structure or file that records transactions or other data.
- **Use**: This variable is used to specify the ledger path or identifier for various operations, such as downloading, processing, and replaying ledger data.


---
### SNAPSHOT
- **Type**: `string`
- **Description**: The `SNAPSHOT` variable is a global string variable that is initially set to an empty string. It is later assigned a value based on command-line arguments, specifically the `--snapshot` option, which appends the provided argument to the `LEDGER` path. This variable is used to specify the path to a snapshot file within the script.
- **Use**: The `SNAPSHOT` variable is used to construct a command-line argument for the `fd_ledger` command, indicating the snapshot file to be used during the ledger replay process.


---
### RESTORE\_ARCHIVE
- **Type**: `string`
- **Description**: The `RESTORE_ARCHIVE` variable is a global string variable that is initially set to an empty string. It is used to store the path to a restore archive file, which is constructed by appending a given argument to the `LEDGER` directory path. This variable is used to specify the restore archive option for the `fd_ledger` command.
- **Use**: This variable is used to pass the restore archive path as a command-line argument to the `fd_ledger` executable for ledger replay operations.


---
### END\_SLOT
- **Type**: `string`
- **Description**: The `END_SLOT` variable is a global string variable that represents a command-line argument for specifying the end slot number in a ledger processing script. It is initialized with the default value of `--end-slot 1010`, which indicates the slot number at which the ledger processing should stop unless overridden by a command-line argument.
- **Use**: This variable is used to pass the end slot number to the `fd_ledger` command during ledger replay operations.


---
### PAGES
- **Type**: `string`
- **Description**: The `PAGES` variable is a global string variable that holds the command-line argument for specifying the number of pages to be processed. It is initialized with the default value `--page-cnt 30`, indicating that 30 pages should be processed by default.
- **Use**: This variable is used to pass the page count argument to the `fd_ledger` command during its execution.


---
### FUNK\_PAGES
- **Type**: `string`
- **Description**: The `FUNK_PAGES` variable is a global string variable that represents a command-line argument for specifying the number of 'funk' pages to be used in a process. It is initialized with the value `--funk-page-cnt 16`, indicating a default count of 16 funk pages. This variable can be overridden by a command-line argument using the `-y` or `--funk-pages` option.
- **Use**: This variable is used to pass the `--funk-page-cnt` argument with a specified count to the `fd_ledger` command during execution.


---
### INDEX\_MAX
- **Type**: `string`
- **Description**: The `INDEX_MAX` variable is a global string variable that represents a command-line argument for setting the maximum index value in a script. It is initialized with the value `--index-max 5000000`, indicating a default maximum index of 5,000,000.
- **Use**: This variable is used to specify the maximum index value when executing the `fd_ledger` command within the script.


---
### TRASH\_HASH
- **Type**: `string`
- **Description**: The `TRASH_HASH` variable is a global string variable that is initially set to an empty string. It is used to store a command-line option for specifying a trash hash value, which is passed to the `fd_ledger` command during execution.
- **Use**: This variable is used to append the `--trash-hash` option with a specified value to the command line arguments for the `fd_ledger` command.


---
### LOG
- **Type**: `string`
- **Description**: The `LOG` variable is a global string variable that holds the path to a temporary file used for logging the output of the `fd_ledger` command. The path is constructed using the `/tmp/ledger_log` prefix followed by the process ID (`$$`), ensuring a unique log file for each execution of the script.
- **Use**: This variable is used to redirect the standard output and error of the `fd_ledger` command to a temporary log file for later inspection.


---
### TILE\_CPUS
- **Type**: `string`
- **Description**: The `TILE_CPUS` variable is a string that specifies a range of CPU cores to be used for tiling operations. It is defined with the value `--tile-cpus 5-15`, indicating that CPU cores 5 through 15 are designated for this purpose.
- **Use**: This variable is used to pass the specified CPU core range as an argument to the `fd_ledger` command for processing.


---
### THREAD\_MEM\_BOUND
- **Type**: `string`
- **Description**: The `THREAD_MEM_BOUND` variable is a global string variable that specifies a command-line argument for setting the memory bound for threads. It is initialized with the value `"--thread-mem-bound 0"`, indicating that the default memory bound is set to 0.
- **Use**: This variable is used as a command-line argument when executing the `fd_ledger` binary to control the memory allocation for threads.


---
### CLUSTER\_VERSION
- **Type**: `string`
- **Description**: The `CLUSTER_VERSION` variable is a global string variable that is initially set to an empty string. It is used to store the cluster version information, which can be specified via command-line arguments using the `-c` or `--cluster-version` option.
- **Use**: This variable is used to pass the cluster version as a command-line argument to the `fd_ledger` command during the execution of the script.


---
### DUMP\_DIR
- **Type**: `string`
- **Description**: The `DUMP_DIR` variable is a global string variable that specifies the directory path where dump files are stored. It is initialized with a default value of './dump', but can be overridden by a command-line argument using the `-d` or `--dump-dir` option. This variable is used to determine the location for storing and accessing dump files during the script's execution.
- **Use**: `DUMP_DIR` is used to set the directory path for storing dump files, which can be customized via command-line arguments.


---
### ONE\_OFFS
- **Type**: `string`
- **Description**: The `ONE_OFFS` variable is a global string variable that is used to store command-line options related to one-off features. It is initially set to an empty string and can be modified by the `-o` or `--one-offs` command-line argument, which appends the specified one-off features to the variable.
- **Use**: This variable is used to pass one-off feature options to the `fd_ledger` command during its execution.


---
### ZST
- **Type**: `integer`
- **Description**: The `ZST` variable is a global integer flag used to determine the compression format of a file to be downloaded. It is set to 1 when the `--zst` command-line option is provided, indicating that the file should be downloaded in the Zstandard (.zst) format.
- **Use**: This variable is used to conditionally execute commands for downloading and extracting files in the Zstandard format.


---
### DUMP
- **Type**: `string`
- **Description**: The `DUMP` variable is a global string variable that stores the absolute path to the directory where dump files are stored. It is initialized using the `realpath` command to ensure it contains the full path to the directory specified by `DUMP_DIR`, which defaults to './dump' if not set by the user.
- **Use**: This variable is used to define the location where ledger and snapshot files are downloaded and extracted for processing.


---
### status
- **Type**: `integer`
- **Description**: The `status` variable is a global integer variable that captures the exit status of the `fd_ledger` command execution. It is set to the exit code returned by the command, which indicates whether the command was successful or if an error occurred.
- **Use**: This variable is used to determine the success or failure of the `fd_ledger` command execution and to control the subsequent flow of the script based on this outcome.


---
### fd\_log\_file
- **Type**: `string`
- **Description**: The `fd_log_file` variable is a string that captures the output of a `grep` command searching for the phrase 'Log at' within the log file specified by the `LOG` variable. This variable is used to store the specific log file path or message that indicates where the log for the ledger is located.
- **Use**: This variable is used to output the location of the log file for the ledger after the replay command is executed.


# Functions

---
### echo\_notice
The `echo_notice` function prints a message in blue text to the console.
- **Inputs**:
    - `$1`: The message string to be printed in blue text.
- **Control Flow**:
    - The function uses the `echo` command with the `-e` flag to enable interpretation of backslash escapes.
    - It applies ANSI escape codes to change the text color to blue (`\033[34m`) and reset it back to default (`\033[0m`) after the message.
- **Output**: The function outputs the provided message to the console in blue text.


---
### echo\_error
The `echo_error` function prints an error message in red text to the console.
- **Inputs**:
    - `$1`: The first part of the error message to be printed.
    - `$2`: The second part of the error message to be printed, appended to the first part.
- **Control Flow**:
    - The function uses the `echo` command with the `-e` flag to enable interpretation of backslash escapes.
    - It prints the concatenated string of `$1` and `$2` in red color using ANSI escape codes (`\033[31m` for red and `\033[0m` to reset color).
- **Output**: The function outputs a red-colored error message to the standard output.



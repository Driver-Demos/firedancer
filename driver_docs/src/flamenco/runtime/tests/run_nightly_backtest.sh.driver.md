# Purpose
This Bash script is designed to automate the process of configuring and running a backtest for a ledger using the Firedancer development tools. It provides a narrow functionality focused on setting up the environment, configuring shared memory pages, and executing a backtest while sending notifications to a Slack channel. The script parses command-line arguments to customize the backtest parameters, such as ledger, snapshot, and end slot, and generates a configuration file in TOML format. It then uses this configuration to initialize and run the backtest, logging the results and checking for mismatches. The script sends Slack messages to notify the start and completion status of the backtest, including any errors encountered, making it a useful tool for monitoring and automating ledger testing processes.
# Global Variables

---
### LOG
- **Type**: `string`
- **Description**: The `LOG` variable is a global string variable that holds the path to a temporary log file. The file path is constructed using the `/tmp/ledger_log` prefix followed by the process ID (`$$`), ensuring a unique log file for each script execution.
- **Use**: This variable is used to store log output from the script's execution, which is later checked for specific messages to determine the success or failure of the ledger processing.


---
### TRASH\_HASH
- **Type**: `string`
- **Description**: The `TRASH_HASH` variable is a global string variable that is initially set to an empty string. It is used to store a command-line option for specifying a trash hash value, which is appended to the `TRASH_HASH` variable when the `-t` or `--trash` option is provided.
- **Use**: This variable is used to construct a command-line argument for a script, allowing the user to specify a trash hash value.


---
### THREAD\_MEM\_BOUND
- **Type**: `string`
- **Description**: The `THREAD_MEM_BOUND` variable is a global string variable that is initialized with the value `"--thread-mem-bound 0"`. This variable appears to be a command-line option or flag that might be used to set a memory boundary for threads in a subsequent command or script execution.
- **Use**: This variable is used to define a memory boundary option for threads, likely to be passed as a parameter in a command-line execution.


---
### LEDGER
- **Type**: `string`
- **Description**: The `LEDGER` variable is a global string variable that holds the name or identifier of a ledger being processed by the script. It is set via command-line arguments using the `-l` or `--ledger` option and is used throughout the script to construct file paths and messages related to the ledger's processing.
- **Use**: This variable is used to specify the ledger being processed, affecting file paths and Slack messages.


---
### SNAPSHOT
- **Type**: `string`
- **Description**: The `SNAPSHOT` variable is a global string variable that is set based on command-line arguments passed to the script. It is constructed using the `--snapshot` or `-s` option, and its value is a path that combines a directory named 'dump', the value of the `LEDGER` variable, and a user-specified subdirectory or file name.
- **Use**: This variable is used to specify the path to a snapshot file or directory, which is then utilized in the configuration of the replay tile in the generated TOML configuration file.


---
### END\_SLOT
- **Type**: `string`
- **Description**: The `END_SLOT` variable is a global string variable that stores the value of the end slot for a process or operation. It is set via command-line arguments using the `-e` or `--end_slot` option.
- **Use**: `END_SLOT` is used in the configuration file to specify the end slot for the archiver tile in the backtest process.


---
### FUNK\_PAGES
- **Type**: `string`
- **Description**: The `FUNK_PAGES` variable is a global string variable that stores a value passed as an argument to the script using the `-y` or `--funk-pages` option. It represents the size of the 'funk' in gigabytes, which is used in the configuration of the replay tile in the TOML configuration file.
- **Use**: This variable is used to set the `funk_sz_gb` parameter in the TOML configuration file for the replay tile.


---
### INDEX\_MAX
- **Type**: `string`
- **Description**: The `INDEX_MAX` variable is a global string variable that is set via command-line arguments using the `-m` or `--indexmax` option. It represents the maximum number of records for the 'funk' component in the configuration file.
- **Use**: This variable is used to set the `funk_rec_max` parameter in the configuration file for the backtest process.


---
### CLUSTER\_VERSION
- **Type**: `string`
- **Description**: The `CLUSTER_VERSION` variable is a global string variable that stores the version of the cluster being used in the script. It is set via a command-line argument `-c` or `--cluster-version` and is used to configure the cluster version in the generated TOML configuration file for the backtest process.
- **Use**: This variable is used to specify the cluster version in the configuration file for the backtest process.


---
### POSITION\_ARGS
- **Type**: `array`
- **Description**: `POSITION_ARGS` is a global array variable that stores command-line arguments that do not match any predefined options in the script. It is used to collect all positional arguments passed to the script after all options have been processed.
- **Use**: This variable is used to store and access any additional command-line arguments that are not associated with specific flags or options.


---
### CHECKPT\_PATH
- **Type**: `string`
- **Description**: The `CHECKPT_PATH` variable is a string that defines the file path for storing mismatch data related to a specific ledger. It is constructed using a base directory `/data/nightly-mismatches/` and appends the ledger name followed by `_mismatch`. This path is used to store or reference data related to mismatches encountered during the processing of the ledger.
- **Use**: This variable is used to specify the location where mismatch data for a given ledger is stored or accessed.


---
### allocated\_pages
- **Type**: `string`
- **Description**: The `allocated_pages` variable is a string that stores the output of a command executed to query the shared memory configuration using the `fd_shmem_cfg` tool. This command is part of a script that manages memory allocation for a system, specifically querying the number of gigantic and huge pages allocated.
- **Use**: This variable is used to capture and store the output of the `fd_shmem_cfg query` command, which is then parsed to determine the number of gigantic and huge pages currently allocated.


---
### gigantic\_pages
- **Type**: `integer`
- **Description**: The `gigantic_pages` variable holds the number of gigantic pages currently allocated in the system. It is extracted from the output of a command that queries shared memory configuration, specifically looking for the line containing 'gigantic pages' and parsing the total number from it.
- **Use**: This variable is used to determine if any gigantic pages are currently allocated, and if not, it triggers a configuration command to allocate a specified number of gigantic and huge pages.


---
### huge\_pages
- **Type**: `integer`
- **Description**: The `huge_pages` variable is an integer that stores the number of huge pages currently allocated in the system. It is extracted from the output of a command that queries shared memory configuration.
- **Use**: This variable is used to determine if any huge pages are currently allocated, and if not, it triggers a configuration command to allocate a specified number of huge pages.


---
### START\_SLACK\_MESSAGE
- **Type**: `string`
- **Description**: The `START_SLACK_MESSAGE` variable is a string that contains a formatted message intended to be sent to a Slack channel. It includes placeholders for the ledger name, commit hash, and branch name, which are dynamically inserted into the message.
- **Use**: This variable is used to notify a Slack channel that a run for a specific ledger is starting, by sending the message through the `send_slack_message` function.


---
### status
- **Type**: `integer`
- **Description**: The `status` variable is a global integer variable used to indicate the success or failure of a process. It is set to 0 if the process completes successfully, and 1 if there is a failure, such as a bank hash mismatch during the ledger processing.
- **Use**: This variable is used to determine the outcome of the ledger processing and to construct appropriate Slack messages based on the success or failure of the process.


---
### START\_SLOT
- **Type**: `string`
- **Description**: The `START_SLOT` variable is a string that is derived from the `SNAPSHOT` variable. It extracts a specific part of the `SNAPSHOT` string, which is expected to be in a format where the second field, separated by a hyphen, represents the starting slot number.
- **Use**: This variable is used to identify the starting slot number for a ledger operation, which is later referenced in the Slack message to indicate where the ledger processing began.


---
### END\_SLACK\_MESSAGE
- **Type**: `string`
- **Description**: The `END_SLACK_MESSAGE` variable is a string that holds the message to be sent to a Slack channel at the end of a process. It contains information about the completion status of a ledger processing task, including the ledger name, commit, branch, and any mismatch details if the process failed.
- **Use**: This variable is used to construct and send a final status message to a Slack channel, indicating whether the ledger processing was successful or if it encountered errors.


---
### MISMATCH\_LOG
- **Type**: `string`
- **Description**: The `MISMATCH_LOG` variable is a string that captures the last occurrence of a mismatch error message from the log file specified by the `LOG` variable. It is used to determine if there was a bank hash mismatch during the execution of the script.
- **Use**: This variable is used to extract and store the last mismatch error message from the log file for further processing and notification.


---
### MISMATCH\_SLOT
- **Type**: `string`
- **Description**: The `MISMATCH_SLOT` variable is a string that stores the slot number where a mismatch occurred during the ledger processing. It is extracted from the log file when a mismatch is detected.
- **Use**: This variable is used to report the specific slot number in the Slack message when a ledger mismatch is detected.


# Functions

---
### send\_slack\_message
The `send_slack_message` function sends a message to a Slack channel using a predefined webhook URL.
- **Inputs**:
    - `MESSAGE`: A string containing the message text to be sent to the Slack channel.
- **Control Flow**:
    - The function takes a single argument, MESSAGE, which is the text to be sent to Slack.
    - It constructs a JSON payload with the message text and a link_names parameter set to 1, which allows Slack to parse and link any names mentioned in the message.
    - The function uses the `curl` command to send a POST request to the Slack webhook URL, with the JSON payload as the data.
- **Output**: The function does not return any value; it performs a side effect by sending a message to a Slack channel.



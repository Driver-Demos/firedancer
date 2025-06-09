# Purpose
This Bash script is designed to automate the process of running a ledger replay operation, likely for a blockchain or distributed ledger system, and to report the results via Slack notifications. It provides a narrow functionality focused on configuring memory pages, executing a ledger replay command with various parameters, and handling the results. The script parses command-line arguments to set up the environment and parameters for the ledger replay, such as ledger path, snapshot, end slot, and other configurations. It checks and configures memory pages if necessary, executes the replay command, and logs the output. Upon completion, it sends a notification to a Slack channel with the results, indicating whether the operation was successful or if there were any mismatches or failures. This script is not an executable or a library but rather a utility script intended to be run in a specific operational context.
# Global Variables

---
### LOG
- **Type**: `string`
- **Description**: The `LOG` variable is a string that represents the file path where the output of the script's execution is logged. It is constructed using a temporary directory path `/tmp/ledger_log` concatenated with the process ID (`$$`) of the running script, ensuring a unique log file for each execution.
- **Use**: This variable is used to redirect the standard output and error of the `fd_ledger` command to a log file for later analysis.


---
### TRASH\_HASH
- **Type**: `string`
- **Description**: The `TRASH_HASH` variable is a global string variable that is used to store a command-line argument for the `--trash-hash` option. It is initially set to an empty string and can be updated based on user input when the script is executed with the `-t` or `--trash` flag.
- **Use**: This variable is used to pass the `--trash-hash` option and its value to the `fd_ledger` command within the script.


---
### THREAD\_MEM\_BOUND
- **Type**: `string`
- **Description**: The `THREAD_MEM_BOUND` variable is a global string variable that is initialized with the value `--thread-mem-bound 0`. This variable is used as a command-line argument for the `fd_ledger` command, which is executed later in the script.
- **Use**: This variable is used to specify the memory bound for threads when running the `fd_ledger` command.


---
### LEDGER
- **Type**: `string`
- **Description**: The `LEDGER` variable is a global string variable that holds the name or identifier of the ledger being processed. It is set via command-line arguments when the script is executed, specifically using the `-l` or `--ledger` option. The value of `LEDGER` is used in various parts of the script to construct file paths and messages related to the ledger processing.
- **Use**: This variable is used to specify and reference the ledger being processed throughout the script, including in file paths and Slack messages.


---
### SNAPSHOT
- **Type**: `string`
- **Description**: The `SNAPSHOT` variable is a global string variable that is set when the `-s` or `--snapshot` command-line option is provided. It constructs a string that specifies the path to a snapshot directory, formatted as `--snapshot dump/$LEDGER/$2`, where `$LEDGER` and `$2` are dynamically replaced with the ledger name and snapshot identifier, respectively.
- **Use**: This variable is used as a command-line argument for the `fd_ledger` command to specify the snapshot path for ledger replay operations.


---
### END\_SLOT
- **Type**: `string`
- **Description**: The `END_SLOT` variable is a string that stores the command-line argument for specifying the end slot in a ledger processing operation. It is constructed by concatenating the string `--end-slot` with the value provided by the user as a command-line argument.
- **Use**: This variable is used to pass the end slot parameter to the `fd_ledger` command, which is responsible for processing the ledger up to the specified slot.


---
### PAGES
- **Type**: `string`
- **Description**: The `PAGES` variable is a global string variable that stores a command-line argument for specifying the number of pages to be processed. It is initialized when the script is executed with the `-p` or `--pages` option, followed by a numerical value.
- **Use**: This variable is used to pass the `--page-cnt` option with its corresponding value to the `fd_ledger` command within the script.


---
### FUNK\_PAGES
- **Type**: `string`
- **Description**: The `FUNK_PAGES` variable is a global string variable that stores a command-line argument for specifying the number of 'funk pages' to be used in a process. It is set when the `-y` or `--funk-pages` option is provided in the script's command-line arguments, and it appends the `--funk-page-cnt` flag followed by the specified number to the command executed later in the script.
- **Use**: This variable is used to pass the number of funk pages as a parameter to the `fd_ledger` command.


---
### INDEX\_MAX
- **Type**: `string`
- **Description**: The `INDEX_MAX` variable is a global string variable that stores a command-line option for setting the maximum index value in a script. It is assigned a value when the `-m` or `--indexmax` option is provided in the command-line arguments, and it is used to pass the `--index-max` option followed by a specified value to the `fd_ledger` command.
- **Use**: This variable is used to configure the maximum index value for the `fd_ledger` command by appending the `--index-max` option with a user-specified value.


---
### CLUSTER\_VERSION
- **Type**: `string`
- **Description**: The `CLUSTER_VERSION` variable is a global string variable that stores the cluster version information passed as a command-line argument. It is used to specify the version of the cluster that the script should operate on.
- **Use**: This variable is used as a command-line argument in the execution of the `fd_ledger` command to set the cluster version.


---
### POSITION\_ARGS
- **Type**: `array`
- **Description**: `POSITION_ARGS` is a global array variable that stores any command-line arguments that do not match the predefined options in the script. These are arguments that are not associated with any specific flag or option and are collected for further processing or use within the script.
- **Use**: This variable is used to capture and store positional arguments passed to the script that do not match any of the specified options.


---
### CHECKPT\_PATH
- **Type**: `string`
- **Description**: The `CHECKPT_PATH` variable is a string that defines the file path where checkpoint mismatch data is stored. It is constructed using a base directory `/data/nightly-mismatches/` and appends the ledger name followed by `_mismatch`. This path is used to store or reference data related to mismatches found during the ledger processing.
- **Use**: This variable is used to specify the directory path for storing checkpoint mismatch data during ledger processing.


---
### allocated\_pages
- **Type**: `string`
- **Description**: The `allocated_pages` variable is a string that stores the output of a command executed to query the shared memory configuration using the `fd_shmem_cfg` tool. This output contains information about the number of gigantic and huge pages currently allocated in the system.
- **Use**: This variable is used to determine the current allocation of gigantic and huge pages, which is then parsed to decide whether additional pages need to be configured.


---
### gigantic\_pages
- **Type**: `integer`
- **Description**: The `gigantic_pages` variable holds the number of gigantic pages currently allocated in the system. It is extracted from the output of a command that queries shared memory configuration, specifically looking for the line containing 'gigantic pages' and capturing the total number of such pages.
- **Use**: This variable is used to determine if any gigantic pages are currently allocated, and if not, it triggers a configuration command to allocate a specified number of gigantic and huge pages.


---
### huge\_pages
- **Type**: `integer`
- **Description**: The `huge_pages` variable is an integer that stores the number of huge pages currently allocated in the system. It is extracted from the output of a command that queries shared memory configuration, specifically looking for the line containing 'huge pages' and parsing the total number from it.
- **Use**: This variable is used to determine if any huge pages are currently configured, and if not, it triggers a configuration command to allocate a specified number of huge pages.


---
### START\_SLACK\_MESSAGE
- **Type**: `string`
- **Description**: The `START_SLACK_MESSAGE` variable is a string that contains a formatted message intended to be sent as a notification to a Slack channel. It includes placeholders for the ledger name, commit ID, and branch name, which are dynamically inserted into the message.
- **Use**: This variable is used to construct the initial notification message that is sent to a Slack channel to alert users that a ledger processing run is starting.


---
### start\_json\_payload
- **Type**: `string`
- **Description**: The `start_json_payload` variable is a JSON-formatted string that contains a message intended for Slack notifications. It is constructed using a Bash here-document and includes a text field with a message about the start of a ledger processing run.
- **Use**: This variable is used to send a notification to a Slack channel via a webhook, indicating the start of a ledger processing operation.


---
### status
- **Type**: `integer`
- **Description**: The `status` variable captures the exit status of the `fd_ledger` command execution. It is assigned the value of `$?`, which is a special variable in bash that holds the exit status of the last executed command.
- **Use**: This variable is used to determine the success or failure of the `fd_ledger` command, influencing the content of the subsequent Slack notification message.


---
### END\_SLACK\_MESSAGE
- **Type**: `string`
- **Description**: The `END_SLACK_MESSAGE` is a global string variable that holds the message to be sent to a Slack channel at the end of the script execution. It is constructed based on the success or failure of the ledger processing operation, and includes details such as the ledger name, commit, branch, and any mismatches or completion information.
- **Use**: This variable is used to construct the final message payload for a Slack notification, indicating the result of the ledger processing operation.


---
### START\_SLOT
- **Type**: `string`
- **Description**: The `START_SLOT` variable is a string that is derived from the `SNAPSHOT` variable. It extracts a specific part of the snapshot file name, which is expected to be in a format where the slot number is the second component when split by a hyphen ('-').
- **Use**: This variable is used to identify the starting slot number for the ledger replay process, which is then included in the Slack notification messages to provide context about the ledger operation.


---
### MISMATCHED
- **Type**: `string`
- **Description**: The `MISMATCHED` variable is a string that captures the last occurrence of the phrase 'Bank hash mismatch!' from the log file specified by the `LOG` variable. It is used to determine if there was a mismatch during the ledger replay process.
- **Use**: This variable is used to check for mismatches in the ledger replay process and to construct a message indicating the slot at which the mismatch occurred.


---
### REPLAY\_COMPLETED
- **Type**: `string`
- **Description**: The variable `REPLAY_COMPLETED` is a string that captures the last line from the log file that contains the phrase 'replay completed'. This indicates that the replay process has finished successfully.
- **Use**: This variable is used to determine if the replay process completed successfully by checking if it contains any content, which then influences the construction of a Slack message.


---
### REPLAY\_COMPLETED\_LINE
- **Type**: `string`
- **Description**: `REPLAY_COMPLETED_LINE` is a string variable that stores the last line from the log file containing the phrase 'replay completed'. This line is extracted using the `grep` command and is used to determine if the replay process has completed successfully.
- **Use**: This variable is used to extract and store information about the successful completion of a replay process from the log file.


---
### REPLAY\_INFO
- **Type**: `string`
- **Description**: The `REPLAY_INFO` variable is a string that captures the details of a successful replay operation from the log file. It is extracted from the line in the log that indicates the replay has completed successfully.
- **Use**: This variable is used to append information about the successful completion of a ledger replay to the end Slack message.


---
### MISMATCH\_SLOT
- **Type**: `string`
- **Description**: `MISMATCH_SLOT` is a string variable that stores the slot number where a bank hash mismatch occurred during the ledger replay process. It is extracted from the log file by searching for the last occurrence of the phrase 'Bank hash mismatch!' and parsing the slot number from that line.
- **Use**: This variable is used to append information about the mismatch slot to the Slack message, indicating where the ledger replay encountered a mismatch.


---
### json\_payload
- **Type**: `string`
- **Description**: The `json_payload` variable is a string that contains a JSON-formatted message intended for sending to a Slack webhook. It is constructed using a here-document (heredoc) syntax to embed the JSON structure directly in the script.
- **Use**: This variable is used to send a notification message to a Slack channel via a webhook, indicating the completion status of a ledger processing task.



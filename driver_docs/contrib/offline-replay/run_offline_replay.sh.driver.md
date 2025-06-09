# Purpose
This Bash script is designed to automate the process of replaying a ledger for a specified network, utilizing resources from Google Cloud Storage and integrating with Slack for notifications. The script is structured to continuously monitor a cloud storage bucket for new data, download necessary files, and execute a series of operations to replay the ledger. It uses several environment variables and configuration files to determine the network parameters, Slack webhook URLs, and other operational settings. The script is intended to run indefinitely, checking for updates every hour, and it includes mechanisms to handle errors and mismatches during the replay process.

Key technical components of the script include functions for sending messages to Slack, which are used extensively throughout the script to provide real-time updates on the script's progress and any issues encountered. The script also interacts with Google Cloud Storage to download ledger data and snapshots, and it uses various command-line tools to manage and replay the ledger data. The script is designed to handle both "gigantic" and "huge" memory pages, configuring them as needed, and it includes logic to manage snapshots and minimize mismatches during the replay process.

Overall, this script provides a comprehensive solution for automating the ledger replay process, with a focus on error handling and notification. It is a specialized tool intended for use in environments where ledger data needs to be processed and verified regularly, and it is designed to be robust and adaptable to changes in the data or network configuration.
# Global Variables

---
### OBJDIR
- **Type**: `string`
- **Description**: The `OBJDIR` variable is a global string variable that specifies the directory path where the build artifacts are located. It is initialized with a default value of `build/native/gcc` if not already set in the environment.
- **Use**: `OBJDIR` is used to construct paths for executing binaries and scripts related to the build process, such as `fd_shmem_cfg` and `fd_ledger`, within the specified directory.


---
### CURRENT\_MISMATCH\_COUNT
- **Type**: `integer`
- **Description**: The `CURRENT_MISMATCH_COUNT` variable is a global integer variable initialized to zero. It is used to track the number of mismatches that occur during the execution of a script that processes ledger data.
- **Use**: This variable is incremented each time a mismatch is detected, and if it exceeds a threshold, the script exits to prevent further processing.


---
### CURRENT\_FAILURE\_COUNT
- **Type**: `integer`
- **Description**: `CURRENT_FAILURE_COUNT` is a global integer variable initialized to 0. It is used to keep track of the number of failures that occur during the execution of a script that processes ledger data.
- **Use**: This variable is incremented each time a failure occurs, and if it exceeds a threshold, the script exits to prevent further processing.


# Functions

---
### send\_slack\_message
The `send_slack_message` function sends a message to a specified Slack channel using a webhook URL.
- **Inputs**:
    - `MESSAGE`: A string containing the message to be sent to the Slack channel.
- **Control Flow**:
    - The function takes a single argument, MESSAGE, which is the text to be sent to Slack.
    - A JSON payload is constructed with the MESSAGE and a 'link_names' attribute set to 1, which allows Slack to parse and link channel names and usernames.
    - The `curl` command is used to send a POST request to the Slack webhook URL with the JSON payload as the data.
- **Output**: The function does not return any value; it performs a side effect by sending a message to a Slack channel.


---
### send\_slack\_debug\_message
The `send_slack_debug_message` function sends a debug message to a specified Slack webhook URL using a JSON payload.
- **Inputs**:
    - `MESSAGE`: A string containing the message to be sent to the Slack debug channel.
- **Control Flow**:
    - The function takes a single argument, MESSAGE, which is the content of the message to be sent.
    - A JSON payload is constructed with the MESSAGE and a link_names attribute set to 1.
    - The payload is sent to the SLACK_DEBUG_WEBHOOK_URL using a POST request via curl with the appropriate headers.
- **Output**: The function does not return any output; it performs a side effect by sending a message to a Slack channel.



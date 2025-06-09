# Purpose
This Bash script is designed to automate the process of replaying and verifying ledger data from a specified network, using Google Cloud Storage as the source for ledger data and snapshots. The script is structured to continuously monitor a cloud storage bucket for new ledger data, download the necessary files, and perform a replay of the ledger using a tool called `firedancer-dev`. It also integrates with Slack to send notifications about the progress and results of the replay process, including any mismatches or failures encountered during the replay.

The script begins by setting up environment variables and sourcing network parameters. It defines several functions to send messages to different Slack channels, which are used throughout the script to provide real-time updates. The main loop of the script checks for the latest ledger data in a specified Google Cloud Storage bucket, downloads the necessary files, and builds the required software components using Git and Cargo. It then performs a replay of the ledger data, checking for mismatches or failures. If a mismatch or failure is detected, the script attempts to minimize the issue by creating new snapshots and adjusting the replay parameters. The script is designed to run indefinitely, checking for new data every hour.

The script is a comprehensive automation tool that combines cloud storage operations, software building, and ledger replay functionality. It is intended for use in environments where ledger data needs to be continuously verified and validated, such as in blockchain or distributed ledger systems. The integration with Slack provides a convenient way to monitor the process and receive alerts about any issues that arise, making it a valuable tool for maintaining the integrity of ledger data.
# Global Variables

---
### OBJDIR
- **Type**: `string`
- **Description**: The `OBJDIR` variable is a global string variable that specifies the directory path where the build output is stored. It defaults to `build/native/gcc` if not already set in the environment.
- **Use**: This variable is used to define the path for the build output directory, which is utilized in various commands to execute binaries and scripts from the specified build location.


---
### CURRENT\_MISMATCH\_COUNT
- **Type**: `integer`
- **Description**: The `CURRENT_MISMATCH_COUNT` variable is a global integer variable initialized to zero. It is used to keep track of the number of mismatches encountered during the execution of a script that processes ledger data.
- **Use**: This variable is incremented each time a mismatch is detected in the ledger replay process, and it is checked to determine if the script should terminate due to excessive mismatches.


---
### CURRENT\_FAILURE\_COUNT
- **Type**: `integer`
- **Description**: `CURRENT_FAILURE_COUNT` is a global integer variable initialized to zero. It is used to keep track of the number of failures that occur during the execution of a script that processes network data and replays ledgers.
- **Use**: This variable is incremented each time a failure is detected during the ledger replay process, and if it exceeds a threshold, the script exits to prevent further processing.


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
- **Output**: The function does not return any value; it sends a message to a Slack channel as a side effect.


---
### send\_mismatch\_slack\_message
The `send_mismatch_slack_message` function sends a message to a specific Slack webhook URL designated for mismatch notifications.
- **Inputs**:
    - `MESSAGE`: A string containing the message to be sent to the Slack channel.
- **Control Flow**:
    - The function takes a single argument, MESSAGE, which is the content of the message to be sent.
    - A JSON payload is constructed with the MESSAGE and a link_names flag set to 1.
    - The payload is sent to the SLACK_MISMATCH_WEBHOOK_URL using a POST request via curl with the appropriate headers.
- **Output**: The function does not return any value; it sends a message to a Slack channel.


---
### send\_slack\_debug\_message
The `send_slack_debug_message` function sends a debug message to a specified Slack webhook URL using a JSON payload.
- **Inputs**:
    - `MESSAGE`: A string containing the message to be sent to the Slack channel.
- **Control Flow**:
    - The function takes a single argument, MESSAGE, which is the content of the message to be sent.
    - A JSON payload is constructed with the MESSAGE and a link_names attribute set to 1.
    - The curl command is used to send a POST request with the JSON payload to the SLACK_DEBUG_WEBHOOK_URL.
- **Output**: The function does not return any value; it sends a message to a Slack channel.



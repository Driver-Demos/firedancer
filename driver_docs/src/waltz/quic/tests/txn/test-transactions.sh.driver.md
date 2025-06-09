# Purpose
This Bash script is designed to process and transmit a specified number of transactions from a given file, logging the results for analysis. It operates in a narrow scope, focusing specifically on reading transaction data, executing a network namespace command (`nsenter`) to transmit each transaction, and logging the outcomes. The script employs Bash strict mode to ensure robust error handling and uses command-line arguments to determine the number of transactions to process and the source file. It is not a standalone executable but rather a utility script intended to be run in a specific network environment, as indicated by the use of `nsenter` with a network namespace. The script concludes by summarizing the success rate of the transactions, providing a simple report of the transmission results.
# Global Variables

---
### SCRIPT\_DIR
- **Type**: `string`
- **Description**: `SCRIPT_DIR` is a string variable that stores the absolute path of the directory where the script is located. It is determined by using the `dirname` command on the script's source path and converting it to an absolute path with `pwd`. This ensures that any subsequent commands that rely on the script's location can use this variable to operate relative to the script's directory.
- **Use**: This variable is used to change the current working directory to the script's directory, ensuring that all file operations are performed relative to the script's location.


---
### NUM\_TRANSACTIONS
- **Type**: `integer`
- **Description**: `NUM_TRANSACTIONS` is a global variable that holds the number of transactions to be processed. It is initialized with a default value of 1000, but can be overridden by a command-line argument.
- **Use**: This variable is used to determine how many lines from the transaction file (`TX_FILE`) should be read and processed.


---
### TX\_FILE
- **Type**: `string`
- **Description**: `TX_FILE` is a global variable that holds the name of the file containing transaction data. It is initialized with a default value of 'tx', but can be overridden by a second command-line argument when the script is executed.
- **Use**: This variable is used to specify the source file from which a specified number of transaction lines are read and processed.



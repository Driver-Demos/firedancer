# Purpose
This Bash script is designed to execute a batch processing task, specifically handling network transactions in parallel. It is an executable script that utilizes GNU Parallel to manage the concurrent execution of a specified number of transactions, which are read from a transaction file. The script is configured to run a default of 8,102 transactions from a file named `all.txns`, using up to 64 parallel jobs, unless overridden by command-line arguments. It employs strict error handling to ensure robustness and uses `nsenter` to execute commands within a specific network namespace, indicating its use in a network testing or simulation environment. The script concludes by reporting the number of successful transactions, providing a summary of the operation's effectiveness.
# Global Variables

---
### SCRIPT\_DIR
- **Type**: `string`
- **Description**: `SCRIPT_DIR` is a string variable that stores the absolute path of the directory where the script is located. It is determined by using the `dirname` command on the script's source path (`BASH_SOURCE[0]`) and converting it to an absolute path with `pwd`. This ensures that the script can reliably reference its own directory regardless of the current working directory when the script is executed.
- **Use**: `SCRIPT_DIR` is used to change the current working directory to the script's directory, ensuring that subsequent commands are executed in the correct context.


---
### NUM\_TRANSACTIONS
- **Type**: `integer`
- **Description**: NUM_TRANSACTIONS is a global variable that holds the number of transactions to be processed. It is initialized with a default value of 8102, but can be overridden by a command-line argument.
- **Use**: This variable is used to determine how many lines from the transaction file (TX_FILE) should be processed in parallel.


---
### TX\_FILE
- **Type**: `string`
- **Description**: `TX_FILE` is a global variable that holds the name of the file containing transaction data. It is initialized with a default value of 'all.txns', but can be overridden by a second command-line argument when the script is executed.
- **Use**: This variable is used to specify the source file from which a specified number of transactions are read and processed in parallel.


---
### NUM\_JOBS
- **Type**: `integer`
- **Description**: `NUM_JOBS` is a global variable that specifies the number of parallel jobs to run when executing the `parallel` command in the script. It is set to a default value of 64, but can be overridden by providing a third argument when running the script.
- **Use**: This variable is used to control the concurrency level of the `parallel` command, determining how many jobs are executed simultaneously.



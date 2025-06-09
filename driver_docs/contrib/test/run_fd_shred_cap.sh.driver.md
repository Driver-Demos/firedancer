# Purpose
This Bash script is designed to automate the setup, execution, and cleanup of a simulation environment for a software component named "firedancer-dev," which appears to be related to a blockchain or distributed ledger system. The script performs several tasks: it checks for sufficient disk space, manages configuration files, generates key pairs, and downloads necessary resources from a cloud storage service. It also sets up a trap to ensure cleanup operations are executed upon script termination, whether due to completion or interruption. The script configures and initiates the "firedancer-dev" application using a TOML configuration file, which it dynamically generates based on the current environment and downloaded resources. This script provides narrow functionality, specifically tailored to managing the lifecycle of a simulation run for the "firedancer-dev" application, and is not intended to be a reusable library or a general-purpose executable.
# Global Variables

---
### DUMP\_DIR
- **Type**: `string`
- **Description**: The `DUMP_DIR` variable is a global string variable that specifies the directory path where dump files are stored. It is initialized with a default value of './dump' if not already set in the environment. This variable is used to determine the location for storing downloaded and extracted ledger files.
- **Use**: `DUMP_DIR` is used to set the directory path for storing dump files, which are downloaded and extracted during the script execution.


---
### LOG
- **Type**: `string`
- **Description**: The `LOG` variable is a string that represents the file path to a temporary log file used by the script. It is defined as `/tmp/ledger_log$$`, where `$$` is a placeholder for the process ID of the script, ensuring a unique log file for each execution.
- **Use**: This variable is used to store log output from the script's execution, allowing for tracking and debugging of the script's operations.


---
### DATA\_DIR
- **Type**: `string`
- **Description**: The `DATA_DIR` variable is a global string variable that specifies the directory path where service data for the Firedancer application is stored. It is initialized with a default value of `/data/svc_firedancer` if not already set in the environment. This directory is used to store various files related to the Firedancer service, such as blockstore and funk files.
- **Use**: `DATA_DIR` is used to define the location for storing and managing service-related data files for the Firedancer application.


---
### TOML
- **Type**: `string`
- **Description**: The `TOML` variable is a string that holds the file path to the configuration file `fd_shredcap.toml` located in the `DATA_DIR` directory. This file is used to store configuration settings for the Firedancer application.
- **Use**: The `TOML` variable is used to specify the path to the configuration file for the Firedancer application, which is referenced during the application's configuration and execution processes.


---
### SCRIPT\_DIR
- **Type**: `string`
- **Description**: `SCRIPT_DIR` is a string variable that stores the absolute path of the directory where the current script is located. It is determined by using the `dirname` command on the script's source path (`${BASH_SOURCE[0]}`) and converting it to an absolute path using `pwd`. This ensures that the script can reliably reference its own directory regardless of the current working directory from which it is executed.
- **Use**: `SCRIPT_DIR` is used to construct paths relative to the script's location, such as `FD_DIR`, which is used in various commands throughout the script.


---
### FD\_DIR
- **Type**: `string`
- **Description**: `FD_DIR` is a global variable that stores the path to the root directory of the Firedancer project. It is constructed by navigating two directories up from the directory containing the script (`SCRIPT_DIR`).
- **Use**: This variable is used to construct paths to various Firedancer binaries and configuration files for execution and setup.


---
### OBJDIR
- **Type**: `string`
- **Description**: The `OBJDIR` variable is a global string variable that specifies the directory path where the build artifacts are located. It is defined using a default value of `build/native/${CC}`, where `${CC}` is expected to be a compiler identifier, unless overridden by an environment variable.
- **Use**: This variable is used to construct paths to executable binaries within the script, specifically for the `firedancer-dev` commands.


---
### AGAVE\_PATH
- **Type**: `string`
- **Description**: `AGAVE_PATH` is a global variable that specifies the directory path where the Agave project's release binaries are located. It defaults to './agave/target/release' if not set externally.
- **Use**: This variable is used to locate and execute the `solana-keygen` binary for generating key pairs.


---
### DUMP
- **Type**: `string`
- **Description**: The `DUMP` variable is a global string variable that stores the absolute path to the directory specified by `DUMP_DIR`. It is initialized using the `realpath` command to ensure it contains the full path, regardless of the input format.
- **Use**: This variable is used to define the location where certain files, such as downloaded resources and extracted data, are stored and accessed during the script's execution.


---
### LEDGER
- **Type**: `string`
- **Description**: The `LEDGER` variable is a string that represents the name of a specific testnet ledger, 'testnet-317018409-shred-cap'. This ledger is used in the context of the script to identify and manage the data related to a specific testnet environment for the Firedancer project.
- **Use**: The `LEDGER` variable is used to construct paths for downloading and accessing testnet data from a Google Cloud Storage bucket.


---
### SNAPSHOT
- **Type**: `string`
- **Description**: The `SNAPSHOT` variable is a string that holds the path to the first snapshot file found in the directory `$DUMP/$LEDGER`. This path is determined by listing files with the pattern `snapshot*.tar.zst` and selecting the first one using `head -n1`. The snapshot file is likely a compressed archive used for initializing or restoring a state in the application.
- **Use**: The `SNAPSHOT` variable is used in the configuration file to specify the snapshot file path for the replay tile in the application.


---
### INCREMENTAL
- **Type**: `string`
- **Description**: The `INCREMENTAL` variable is a string that stores the path to the first file matching the pattern `incremental*` within the directory specified by `$DUMP/$LEDGER`. This path is determined by listing the files in the directory and selecting the first match.
- **Use**: This variable is used in the configuration file to specify the path to the incremental snapshot for the replay tile in the Firedancer application.


---
### SHREDCAP
- **Type**: `string`
- **Description**: The `SHREDCAP` variable is a string that holds the path to the first file in the directory `$DUMP/$LEDGER` that matches the pattern `*shredcap`. This path is used in the configuration file to specify the `shred_cap_replay` parameter for the `tiles.store_int` section.
- **Use**: `SHREDCAP` is used to set the `shred_cap_replay` parameter in the TOML configuration file for the Firedancer application.


---
### status
- **Type**: `integer`
- **Description**: The `status` variable is a global integer variable that stores the exit status of the `firedancer-dev` command executed with a timeout. It is used to determine the success or failure of the command execution.
- **Use**: This variable is used to exit the script with the appropriate status code, indicating whether the simulation completed successfully or failed.


---
### simulation\_finished
- **Type**: `string`
- **Description**: The `simulation_finished` variable is a string that captures the output of a grep command searching for the phrase 'Finished simulation' in the log file specified by the `LOG` variable. This variable is used to determine if the simulation process has completed successfully by checking if the log contains a specific completion message.
- **Use**: This variable is used to check the log file for a specific message indicating the successful completion of a simulation.


# Functions

---
### cleanup
The `cleanup` function terminates all running instances of the `firedancer-dev` process and finalizes the configuration using a specified TOML file.
- **Inputs**: None
- **Control Flow**:
    - The function attempts to kill all running instances of the `firedancer-dev` process using `sudo killall firedancer-dev`, ignoring any errors.
    - It then runs the `firedancer-dev configure fini all` command with the configuration file specified by the resolved path of `TOML`, again ignoring any errors.
    - Finally, the function exits with the status code stored in the `status` variable.
- **Output**: The function does not return a value; it exits the script with a status code.



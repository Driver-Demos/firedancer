# Purpose
This script is a shell script designed to configure and execute a specific mode of a software application called "FD" (likely short for Firedancer) in "wen-restart" mode. It provides narrow functionality, focusing on setting up the environment and configuration necessary for this specific execution mode. The script sets up various configuration parameters, such as file paths for memory-mapped files, checkpoint logs, and identity keys, and it writes these configurations into a TOML file named `wen_restart.toml`. It also compiles the `firedancer-dev` application and cleans up memory before running the application with the specified configuration. The script is intended to be executed in a Unix-like environment and is likely used for development or testing purposes, given the presence of hardcoded paths and the use of `gdb` for debugging.
# Global Variables

---
### FUNK\_FILE
- **Type**: `string`
- **Description**: The `FUNK_FILE` variable is a global string variable that holds the file path to a memory-mapped binary file named `funk_file.bin`. This file is likely used for storing or accessing data in a specific format required by the script or application.
- **Use**: The `FUNK_FILE` variable is used in the configuration section of the script to specify the location of the funk file for the `firedancer-dev` application.


---
### TOWER\_CHECKPT\_FILE
- **Type**: `string`
- **Description**: The `TOWER_CHECKPT_FILE` is a global variable that holds the name of the file used for storing the tower checkpoint logs. This file is crucial for the wen-restart mode of the script, as it helps in maintaining the state of the tower checkpoints during the restart process.
- **Use**: This variable is used in the configuration file `wen_restart.toml` to specify the location of the tower checkpoint file for the `firedancer-dev` application.


---
### RESTART\_LOG\_FILE
- **Type**: `string`
- **Description**: The `RESTART_LOG_FILE` is a global variable that specifies the file path for logging restart operations in the script. It is initially set to 'wenrestart.log', and the script ensures that this file is created and then removed at the start of the script execution.
- **Use**: This variable is used to define the log file path for restart operations, which is referenced in the configuration file for logging purposes.


---
### GENESIS\_HASH
- **Type**: `string`
- **Description**: The `GENESIS_HASH` is a global variable that holds a string representing the hash of the genesis block in a blockchain system. This hash is crucial for identifying the initial state of the blockchain and is used in various configurations and operations within the system.
- **Use**: This variable is used to configure the `wen_restart.toml` file, ensuring the system recognizes the correct genesis block during the restart process.


---
### RESTART\_COORDINATOR
- **Type**: `string`
- **Description**: The `RESTART_COORDINATOR` variable is a string that holds the public key of the coordinator used during the wen-restart mode of the FD script. This key is essential for identifying the coordinator responsible for managing the restart process.
- **Use**: This variable is used in the configuration file `wen_restart.toml` to specify the coordinator's public key for the restart process.


---
### SHRED\_VER
- **Type**: `integer`
- **Description**: `SHRED_VER` is a global variable that holds the integer value 16013, representing the expected shred version for the consensus configuration in the script. Shred versions are used in distributed systems to ensure compatibility and consistency across different nodes or components.
- **Use**: This variable is used in the consensus section of the `wen_restart.toml` configuration file to specify the expected shred version for the system.


---
### SNAPSHOT\_OUT\_DIR
- **Type**: `string`
- **Description**: The `SNAPSHOT_OUT_DIR` variable is a global string variable that specifies the directory path where snapshot output files will be stored. In this script, it is set to the current directory, denoted by './'. This variable is used in the configuration file to define the output directory for batch processing.
- **Use**: This variable is used to specify the output directory for snapshot files in the configuration settings of the script.


---
### PRIMARY\_IP
- **Type**: `string`
- **Description**: The `PRIMARY_IP` variable is a global string variable that holds the IP address '147.75.87.225'. This IP address is used as an entry point for the gossip protocol in the configuration of the Firedancer application.
- **Use**: This variable is used to specify the IP address for the gossip entry point in the `wen_restart.toml` configuration file.


---
### IDENTITY
- **Type**: `string`
- **Description**: The `IDENTITY` variable is a global string variable that holds the file path to the identity keypair JSON file, specifically named `fd-identity-keypair.json`. This file is likely used to authenticate or identify the process or application being run by the script.
- **Use**: The `IDENTITY` variable is used to specify the path to the identity keypair file in the configuration for the `firedancer-dev` application.


---
### BLOCK\_FILE
- **Type**: `string`
- **Description**: The `BLOCK_FILE` variable is a global string variable that specifies the file path to the blockstore file used in the script. It is set to `/data/yunzhang/blockstore_file.bin`. This file is intended to store block data for the application.
- **Use**: The `BLOCK_FILE` variable is used to specify the path of the blockstore file, which is then removed at the start of the script to avoid potentially inconsistent data.


---
### CLUSTER\_VERSION
- **Type**: `string`
- **Description**: The `CLUSTER_VERSION` variable is a global string variable that specifies the version of the cluster being used in the script. It is set to "2.0.3" and is used to ensure compatibility with the software components that require a specific cluster version.
- **Use**: This variable is used in the configuration file `wen_restart.toml` to set the `cluster_version` parameter for the `tiles.replay` section.



# Purpose
This Bash script is designed to automate the setup and execution of a development environment for a software component named "firedancer-dev." It provides narrow functionality, specifically tailored to configure and run this particular application. The script includes steps to set up environment variables, manage process cleanup, and configure network settings. It also dynamically generates a configuration file (`firedancer-dev.toml`) with various settings related to network interfaces, logging, and consensus parameters. The script ensures that the necessary binaries are available in the system path and uses commands like `wget` and `jq` to interact with network resources and parse JSON data. Overall, this script is intended for developers or system administrators who need to initialize and manage the "firedancer-dev" application in a controlled testing environment.
# Global Variables

---
### SCRIPT\_DIR
- **Type**: `string`
- **Description**: `SCRIPT_DIR` is a string variable that stores the absolute path of the directory where the script is located. It is determined by using the `dirname` command on the script's source path (`${BASH_SOURCE[0]}`) and converting it to an absolute path with `pwd`. This ensures that the script can reliably reference its own directory regardless of the current working directory from which it is executed.
- **Use**: `SCRIPT_DIR` is used to construct paths relative to the script's location, such as `FD_DIR`, ensuring that file and directory references are accurate and consistent.


---
### FD\_DIR
- **Type**: `string`
- **Description**: The `FD_DIR` variable is a global string variable that holds the path to the root directory of the Firedancer project. It is constructed by navigating two directories up from the current script's directory, which is determined by the `SCRIPT_DIR` variable.
- **Use**: This variable is used to construct paths for executing Firedancer-related commands and accessing its configuration files.


---
### OBJDIR
- **Type**: `string`
- **Description**: The `OBJDIR` variable is a global string variable that specifies the directory path where the build artifacts are located. It is defined using a default value of `build/native/${CC}`, where `${CC}` is expected to be an environment variable representing the compiler being used. If `OBJDIR` is already set in the environment, its value will be used instead of the default.
- **Use**: `OBJDIR` is used to construct paths to the `firedancer-dev` binary and other related files within the build directory.


---
### AGAVE\_PATH
- **Type**: `string`
- **Description**: The `AGAVE_PATH` variable is a global string variable that specifies the file path to the Agave project's release target directory. It is initialized with a default value of './agave/target/release' if not already set in the environment.
- **Use**: This variable is used to construct the command path for executing the Solana binary within the Agave project.


---
### \_PRIMARY\_INTERFACE
- **Type**: `string`
- **Description**: The `_PRIMARY_INTERFACE` variable is a string that holds the name of the primary network interface used for the default route on the system. It is determined by parsing the output of the `ip route show default` command and extracting the interface name using `awk`. This variable is crucial for network-related operations in the script, as it helps identify the interface through which network traffic is routed by default.
- **Use**: This variable is used to determine the primary network interface for network operations, such as obtaining the primary IP address.


---
### PRIMARY\_IP
- **Type**: `string`
- **Description**: The `PRIMARY_IP` variable is a string that holds the IP address of the primary network interface on the system. It is determined by first identifying the default network interface using the `ip route show default` command, and then extracting the IP address associated with that interface using `ip addr show`. The IP address is further processed to remove the subnet mask, leaving only the base IP address.
- **Use**: This variable is used to dynamically configure network-related settings in the script, such as setting entry points for gossip protocols and downloading snapshots from a specific IP address.


---
### FULL\_SNAPSHOT
- **Type**: `string`
- **Description**: The `FULL_SNAPSHOT` variable is a string that stores the location of a snapshot file downloaded from a server. It is obtained by executing a `wget` command to download the snapshot file from a URL constructed using the `PRIMARY_IP` and port 8899, and then parsing the output to extract the location header.
- **Use**: This variable is used to specify the snapshot file location in the configuration file for the `firedancer-dev` application.


---
### SHRED\_VERS
- **Type**: `string`
- **Description**: The `SHRED_VERS` variable is a string that captures the shred version number from the `validator.log` file. It is extracted using a `grep` command that searches for the pattern 'shred_version:' and then uses `sed` to isolate the numeric value following this pattern.
- **Use**: This variable is used to set the `expected_shred_version` in the `firedancer-dev.toml` configuration file, ensuring that the system operates with the correct shred version.



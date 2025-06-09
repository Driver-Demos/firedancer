# Purpose
This Bash script is designed to facilitate inter-process communication (IPC) testing by orchestrating the execution of receiver and transmitter processes on specific CPU cores, taking into account NUMA (Non-Uniform Memory Access) configurations. It provides a narrow functionality focused on setting up and managing the execution environment for these processes, ensuring they run on appropriate cores to optimize performance. The script checks for necessary configuration files and environment setup, such as `test_ipc.conf`, and uses `taskset` to bind processes to specific CPU cores. It also constructs and executes halt commands to gracefully stop the processes after a set duration. This script is not a standalone executable but rather a utility script that relies on external binaries and configuration files to perform its tasks.
# Global Variables

---
### FD\_LOG\_PATH
- **Type**: `string`
- **Description**: The `FD_LOG_PATH` variable is a global string variable initialized to an empty string. It is intended to store the path to a log file or directory, although it is not used within the provided script.
- **Use**: `FD_LOG_PATH` is exported as an environment variable, potentially for use by other scripts or processes that require a log path.


---
### rx\_cnt
- **Type**: `integer`
- **Description**: The `rx_cnt` variable is a global integer variable that represents the number of receiver instances to be started. It is initialized with the first command-line argument passed to the script.
- **Use**: This variable is used to control the number of iterations in loops that start receiver processes and configure their settings.


---
### CORE\_FIRST
- **Type**: `integer`
- **Description**: `CORE_FIRST` is a global variable that is initialized with the value of `NUMA_IDX`. It represents the starting core index for CPU affinity settings in a multi-core, NUMA (Non-Uniform Memory Access) environment.
- **Use**: `CORE_FIRST` is used to determine the initial CPU core for task assignment, ensuring that processes are bound to the appropriate cores for optimal performance in a NUMA system.


---
### NUMA\_STRIDE
- **Type**: `integer`
- **Description**: NUMA_STRIDE is a global variable that determines the increment step for CPU core allocation across NUMA nodes. It is used to configure how CPU cores are assigned to processes, either in a block or striped manner, depending on the system's NUMA configuration.
- **Use**: NUMA_STRIDE is used to calculate the next CPU core to assign to a process by adding it to the current core index, facilitating efficient CPU core allocation across NUMA nodes.


---
### HALT\_ALL
- **Type**: `string`
- **Description**: The `HALT_ALL` variable is a string that accumulates commands to send halt signals to various components in the script. It is initially set to an empty string and is appended with commands to halt both the transmitter and receiver components based on the configuration provided in the script.
- **Use**: This variable is used to construct a command string that is executed at the end of the script to stop all running processes by sending halt signals.


---
### CORE\_NEXT
- **Type**: `integer`
- **Description**: `CORE_NEXT` is a global integer variable that represents the next CPU core index to be used for task assignment. It is initially set to the value of `CORE_FIRST`, which is derived from the NUMA node index.
- **Use**: `CORE_NEXT` is used to assign CPU cores to receiver and transmitter tasks in a round-robin fashion, incrementing by `NUMA_STRIDE` after each assignment.



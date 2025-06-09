# Purpose
This Bash script is designed to facilitate inter-process communication (IPC) testing by orchestrating the execution of receiver and transmitter processes on a system with specific CPU and NUMA configurations. It provides a narrow functionality focused on setting up and managing the execution environment for these processes, ensuring they run on designated CPU cores and NUMA nodes. The script checks for necessary prerequisites, such as the existence of a configuration file (`tmp/test_ipc.conf`) and the initialization of shared memory objects, before proceeding. It dynamically constructs and executes commands to start receiver and transmitter processes using `taskset` to bind them to specific CPU cores, and it manages their execution lifecycle by sending halt signals after a predefined duration. This script is not an executable in the traditional sense but rather a utility script intended to be run in a testing environment to validate IPC mechanisms.
# Global Variables

---
### FD\_LOG\_PATH
- **Type**: `string`
- **Description**: The `FD_LOG_PATH` variable is a global string variable initialized to an empty string. It is intended to store the path to a log file or directory for logging purposes.
- **Use**: This variable is used to define and export the log path for the script, although it is not actively used within the provided code.


---
### rx\_cnt
- **Type**: `integer`
- **Description**: The variable `rx_cnt` is a global integer variable that represents the number of receiver instances to be started. It is initialized with the first command-line argument passed to the script.
- **Use**: `rx_cnt` is used to control the number of iterations in loops that start receiver processes and configure their settings.


---
### CORE\_FIRST
- **Type**: `integer`
- **Description**: CORE_FIRST is a global variable that is initialized with the value of NUMA_IDX. It represents the starting core index for CPU affinity settings in a NUMA (Non-Uniform Memory Access) architecture.
- **Use**: CORE_FIRST is used to determine the initial CPU core for task assignment, ensuring processes are run on the appropriate cores for optimal performance in a NUMA environment.


---
### NUMA\_STRIDE
- **Type**: `integer`
- **Description**: NUMA_STRIDE is a global variable that determines the increment step for CPU core allocation across NUMA nodes. It is set to the value of NUMA_CNT, which likely represents the number of NUMA nodes or a related configuration parameter. This variable is used to adjust the core allocation strategy based on the system's NUMA architecture, either assigning cores in blocks or striping them across nodes.
- **Use**: NUMA_STRIDE is used to calculate the next CPU core to allocate for tasks, ensuring they are distributed according to the NUMA configuration.


---
### HALT\_ALL
- **Type**: `string`
- **Description**: The `HALT_ALL` variable is a string that accumulates commands to send halt signals to various components in the script. It is initially an empty string and is appended with 'signal-cnc' commands for both the transmitter and each receiver based on the number of receivers specified by `rx_cnt`. This variable is used to construct a command that will be executed to stop all running processes at the end of the script.
- **Use**: `HALT_ALL` is used to store and execute halt commands for the transmitter and receivers in the script.


---
### CORE\_NEXT
- **Type**: `integer`
- **Description**: CORE_NEXT is a global integer variable that is initialized to the value of CORE_FIRST. It is used to keep track of the next CPU core to be assigned for running tasks in a multi-core environment.
- **Use**: CORE_NEXT is incremented by NUMA_STRIDE after each task assignment to ensure tasks are distributed across CPU cores.



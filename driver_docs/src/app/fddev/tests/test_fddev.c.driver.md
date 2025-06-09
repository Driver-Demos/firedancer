# Purpose
This C source code file is designed to manage and execute a series of processes related to a development environment, likely for testing or configuring a software system. The file includes several key functions that handle different stages of a development workflow, such as configuration ([`fddev_configure`](#fddev_configure)), workspace initialization ([`fddev_wksp`](#fddev_wksp)), readiness checks ([`fddev_ready`](#fddev_ready)), and development operations ([`fddev_dev`](#fddev_dev)). These functions are executed as child processes, managed through the [`fork_child`](#fork_child) and [`wait_children`](#wait_children) functions, which handle process creation and synchronization, respectively. The code also includes mechanisms for logging and error handling, ensuring that each stage of the process is executed with the necessary permissions and resources.

The file is structured to be part of a larger system, as indicated by the inclusion of multiple headers and the use of shared commands and utilities. It defines a main function ([`main`](#main)) that serves as the entry point for executing the test run, which involves initializing configurations, setting up logging, and orchestrating the execution of the various stages through the [`fddev_test_run`](#fddev_test_run) function. This function checks command-line arguments to determine the mode of execution and uses process isolation techniques like `unshare` to create a new process namespace. The code is modular, with each function focusing on a specific aspect of the development process, and it leverages system calls and utilities to manage inter-process communication and synchronization effectively.
# Imports and Dependencies

---
- `../main.h`
- `../../platform/fd_sys_util.h`
- `../../shared/commands/ready.h`
- `../../shared_dev/commands/wksp.h`
- `../../shared_dev/commands/dev.h`
- `errno.h`
- `unistd.h`
- `poll.h`
- `fcntl.h`
- `sched.h`
- `sys/wait.h`
- `sys/mman.h`


# Data Structures

---
### child\_info
- **Type**: `struct`
- **Members**:
    - `name`: A pointer to a constant character string representing the name of the child process.
    - `pipefd`: An integer representing the file descriptor for the pipe used for inter-process communication.
    - `pid`: An integer representing the process ID of the child process.
- **Description**: The `child_info` structure is used to store information about a child process, including its name, the file descriptor for a pipe used for communication, and its process ID. This structure is useful for managing and tracking child processes spawned by a parent process, allowing for operations such as waiting for a child process to exit or communicating with it through a pipe.


# Functions

---
### fddev\_configure<!-- {{#callable:fddev_configure}} -->
The `fddev_configure` function initializes and configures stages for a device configuration process, excluding any 'kill' stages, and ensures proper permissions before executing the configuration commands.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure that holds configuration settings for the device.
    - `pipefd`: An integer representing a file descriptor for a pipe, which is not used in this function.
- **Control Flow**:
    - The function begins by setting the log thread name to 'configure'.
    - An `args_t` structure is initialized with a command for configuration and an empty stages array.
    - A loop iterates over the `STAGES` array, skipping any stage named 'kill', and populates the `args.configure.stages` array with the remaining stages.
    - A capability check object `chk` is created and joined using `fd_cap_chk_join` and `fd_cap_chk_new`.
    - The function `configure_cmd_perm` is called to check permissions for the configuration command using `args`, `chk`, and `config`.
    - An assertion checks that there are no errors in the capability check using `FD_TEST`.
    - The function `configure_cmd_fn` is called to execute the configuration command with `args` and `config`.
    - The function returns 0, indicating successful execution.
- **Output**: The function returns an integer value of 0, indicating successful configuration.


---
### fddev\_wksp<!-- {{#callable:fddev_wksp}} -->
The `fddev_wksp` function sets up a workspace by checking permissions and executing workspace commands based on the provided configuration.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure that contains configuration settings for the workspace.
    - `pipefd`: An integer representing a file descriptor for a pipe, which is not used in this function.
- **Control Flow**:
    - The function begins by setting the log thread name to 'wksp'.
    - An `args_t` structure is initialized to zero.
    - A capability check object `chk` is created and joined using `fd_cap_chk_join` and `fd_cap_chk_new`.
    - The function `wksp_cmd_perm` is called to check permissions for workspace commands using `args`, `chk`, and `config`.
    - The number of errors in the capability check is retrieved using `fd_cap_chk_err_cnt`.
    - If there are any errors, a warning is logged for each error, and an error is logged indicating insufficient permissions to create workspaces, which terminates the function.
    - If no errors are found, `wksp_cmd_fn` is called to execute the workspace commands with `args` and `config`.
    - The function returns 0, indicating successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution.


---
### fddev\_ready<!-- {{#callable:fddev_ready}} -->
The `fddev_ready` function sets the logging context to 'ready' and executes the `ready_cmd_fn` function with initialized arguments and configuration.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure that holds configuration data.
    - `pipefd`: An integer representing a file descriptor for a pipe, which is not used in this function.
- **Control Flow**:
    - The function begins by casting `pipefd` to void to indicate it is unused.
    - It sets the logging context to 'ready' using `fd_log_thread_set`.
    - An `args_t` structure is initialized to zero.
    - The `ready_cmd_fn` function is called with the initialized `args` and the provided `config`.
    - The function returns 0, indicating successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution.


---
### fddev\_dev<!-- {{#callable:fddev_dev}} -->
The `fddev_dev` function sets up and executes a development command with specific configurations and permissions, ensuring no errors occur during the process.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing configuration settings for the function.
    - `pipefd`: An integer representing a file descriptor for inter-process communication.
- **Control Flow**:
    - Set the logging thread name to 'dev'.
    - Initialize an `args_t` structure with specific development command settings, including disabling configuration and workspace initialization.
    - Set the `debug_tile` field of `args` to an empty string.
    - Allocate and join a capability check structure `chk` using `fd_cap_chk_join` and `fd_cap_chk_new`.
    - Call `dev_cmd_perm` to check permissions for the development command using `args`, `chk`, and `config`.
    - Assert that there are no errors in `chk` using `FD_TEST`.
    - Log a warning message with the current process ID using `FD_LOG_WARNING`.
    - Execute the development command function `dev_cmd_fn` with `args`, `config`, and `spawn_agave`.
    - Return 0 to indicate successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution without errors.


---
### fork\_child<!-- {{#callable:fork_child}} -->
The `fork_child` function creates a new process using `fork`, sets up a pipe for inter-process communication, and executes a specified child function in the child process.
- **Inputs**:
    - `name`: A constant character pointer representing the name of the child process.
    - `config`: A pointer to a `config_t` structure containing configuration data for the child process.
    - `child`: A function pointer to the child function that will be executed in the child process, taking a `config_t` pointer and an integer pipe file descriptor as arguments.
- **Control Flow**:
    - Initialize a pipe for inter-process communication and check for errors.
    - Call `fork` to create a new process and check for errors.
    - In the child process (when `pid` is 0), close the read end of the pipe, execute the `child` function with `config` and the write end of the pipe, and exit the process with the result of the `child` function.
    - In the parent process, close the write end of the pipe.
    - Return a `child_info` structure containing the name, read end of the pipe, and process ID of the child.
- **Output**: A `struct child_info` containing the name of the child process, the file descriptor for the read end of the pipe, and the process ID of the child process.


---
### wait\_children<!-- {{#callable:wait_children}} -->
The `wait_children` function monitors a set of child processes for termination within a specified timeout period and returns the index of the first child that exits.
- **Inputs**:
    - `children`: An array of `struct child_info` representing the child processes to monitor, each containing a name, a pipe file descriptor, and a process ID.
    - `children_cnt`: The number of child processes in the `children` array.
    - `timeout_seconds`: The maximum time in seconds to wait for any child process to exit.
- **Control Flow**:
    - Initialize an array of `struct pollfd` to monitor the pipe file descriptors of the child processes.
    - Use the `poll` function to wait for any of the child processes to exit, with a timeout specified by `timeout_seconds`.
    - If `poll` returns an error or times out, log an error and terminate the program.
    - Identify the first child process that has exited by checking the `POLLHUP` event in the `revents` field of the `pollfd` array.
    - Use `waitpid` to retrieve the exit status of the identified child process.
    - Log an error and terminate the program if `waitpid` fails, the child did not exit, or exited with an error status.
    - Close the pipe file descriptor of the exited child process.
    - Return the index of the exited child process.
- **Output**: The function returns the index of the first child process that exits.


---
### init\_log\_memfd<!-- {{#callable:init_log_memfd}} -->
The `init_log_memfd` function creates a memory file descriptor and sets its size to 4096 bytes for logging purposes.
- **Inputs**: None
- **Control Flow**:
    - Call `memfd_create` with the name 'fd_log_lock_page' and flags set to 0 to create a memory file descriptor.
    - Check if `memfd_create` returns -1, indicating an error, and log an error message if so.
    - Call `ftruncate` on the created memory file descriptor to set its size to 4096 bytes.
    - Check if `ftruncate` returns -1, indicating an error, and log an error message if so.
    - Return the memory file descriptor.
- **Output**: The function returns an integer representing the memory file descriptor created.


---
### fddev\_test\_run<!-- {{#callable:fddev_test_run}} -->
The `fddev_test_run` function executes a test run by either initializing a new process namespace and running a configuration or by invoking a development main function based on the command-line arguments.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
    - `run`: A function pointer to a function that takes a `config_t` pointer and returns an integer, used to execute the main logic of the test run.
- **Control Flow**:
    - Check if the run is a base run by evaluating the command-line arguments.
    - If it is a base run, attempt to unshare the process namespace with `CLONE_NEWPID`.
    - Fork the process; if fork fails, log an error.
    - In the child process, initialize the system, set the log thread, load the configuration, initialize the topology, and execute the `run` function with the configuration.
    - In the parent process, wait for the child process to exit and handle any errors or signals appropriately.
    - If it is not a base run, call `fd_dev_main` with the provided arguments and configuration.
- **Output**: Returns 0 on successful execution, or an error code if any part of the process fails, including errors from the `run` function or `fd_dev_main`.
- **Functions called**:
    - [`init_log_memfd`](#init_log_memfd)


---
### test\_fddev<!-- {{#callable:test_fddev}} -->
The `test_fddev` function orchestrates the execution of several child processes to configure, initialize workspaces, and prepare the development environment, ensuring they complete successfully within specified timeouts.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure that contains configuration settings for the child processes.
- **Control Flow**:
    - Forks a child process to run `fddev_configure` with the name 'fddev configure' and waits for it to complete within 15 seconds.
    - Forks a child process to run `fddev_wksp` with the name 'fddev wksp' and waits for it to complete within 60 seconds.
    - Forks two child processes to run `fddev_dev` and `fddev_ready` with the names 'fddev dev' and 'fddev ready', respectively.
    - Waits for both 'fddev dev' and 'fddev ready' processes to complete within 30 seconds.
    - Checks if any of the child processes exited unexpectedly and logs an error if so.
    - Returns 0 upon successful completion of all child processes.
- **Output**: Returns 0 to indicate successful execution of all child processes without unexpected exits.
- **Functions called**:
    - [`fork_child`](#fork_child)
    - [`wait_children`](#wait_children)


---
### main<!-- {{#callable:main}} -->
The `main` function serves as the entry point of the program, invoking the [`fddev_test_run`](#fddev_test_run) function with command-line arguments and a test function to execute a series of device tests.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - The function calls [`fddev_test_run`](#fddev_test_run) with `argc`, `argv`, and `test_fddev` as arguments.
    - The [`fddev_test_run`](#fddev_test_run) function is responsible for determining the execution path based on the command-line arguments and running the appropriate test or main function.
- **Output**: The function returns the result of the [`fddev_test_run`](#fddev_test_run) function, which is an integer status code indicating the success or failure of the test execution.
- **Functions called**:
    - [`fddev_test_run`](#fddev_test_run)


# Function Declarations (Public API)

---
### spawn\_agave<!-- {{#callable_declaration:spawn_agave}} -->
Creates and names a new thread to run the agave_main1 function.
- **Description**: This function is used to spawn a new thread that executes the agave_main1 function, using the provided configuration. It is typically called when a new execution context is needed for agave_main1, and the thread is named 'fdSolMain' for identification purposes. The function expects a valid configuration object and will log an error if thread creation or naming fails.
- **Inputs**:
    - `config`: A pointer to a constant config_t structure containing configuration data for the thread. Must not be null, and the caller retains ownership of the memory.
- **Output**: None
- **See also**: [`spawn_agave`](../commands/dev.c.driver.md#spawn_agave)  (Implementation)



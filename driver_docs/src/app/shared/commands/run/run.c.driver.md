# Purpose
This C source code file is part of a larger system designed to manage and execute processes within a controlled environment, likely for a high-performance computing application. The file defines several functions and structures that facilitate the setup and execution of processes in a sandboxed environment, utilizing Linux-specific features such as namespaces, capabilities, and seccomp filters for security and resource management. The primary functionality revolves around setting up a process tree where a main process spawns a namespace-isolated child process, which in turn manages other child processes (referred to as "tiles" and "agave") that perform specific tasks. This setup ensures that if any process in the tree fails, all related processes are terminated, maintaining system integrity.

Key components of the code include functions for configuring process permissions ([`run_cmd_perm`](#run_cmd_perm)), setting up signal handlers ([`install_parent_signals`](#install_parent_signals)), creating isolated process stacks ([`create_clone_stack`](#create_clone_stack)), and executing child processes ([`execve_agave`](#execve_agave), [`execve_tile`](#execve_tile)). The code also includes mechanisms for managing shared resources like memory and network namespaces, and it uses seccomp filters to restrict system calls for enhanced security. The file is structured to be part of a larger application, likely a daemon or service, that requires elevated permissions to perform initial setup tasks but drops these permissions once the environment is configured. This approach is common in systems that need to balance performance, security, and resource management in a multi-process environment.
# Imports and Dependencies

---
- `run.h`
- `sys/wait.h`
- `generated/main_seccomp.h`
- `generated/pidns_arm64_seccomp.h`
- `generated/pidns_seccomp.h`
- `../../../platform/fd_sys_util.h`
- `../../../platform/fd_file_util.h`
- `../../../platform/fd_net_util.h`
- `../configure/configure.h`
- `dirent.h`
- `sched.h`
- `stdio.h`
- `stdlib.h`
- `poll.h`
- `unistd.h`
- `errno.h`
- `fcntl.h`
- `sys/prctl.h`
- `sys/resource.h`
- `sys/mman.h`
- `sys/stat.h`
- `linux/capability.h`
- `linux/unistd.h`
- `../../../../util/tile/fd_tile_private.h`


# Global Variables

---
### CALLBACKS
- **Type**: `fd_topo_obj_callbacks_t *`
- **Description**: CALLBACKS is an external array of pointers to fd_topo_obj_callbacks_t structures. This array is likely used to store callback functions or handlers related to topology objects in the system.
- **Use**: CALLBACKS is used to manage and access callback functions for topology objects, facilitating dynamic behavior in the system.


---
### fd\_log\_private\_path
- **Type**: `char[1024]`
- **Description**: The `fd_log_private_path` is a global character array with a fixed size of 1024 bytes, initialized as an empty string at the start. It is used to store the file path of the log file.
- **Use**: This variable is used to store and access the path to the log file throughout the program, particularly for logging purposes.


---
### pid\_namespace
- **Type**: `pid_t`
- **Description**: The `pid_namespace` is a static global variable of type `pid_t`, which is typically used to store process identifiers (PIDs) in Unix-like operating systems. In this context, it is used to store the PID of a process that is part of a PID namespace, which is a feature that allows for the isolation of process IDs between different sets of processes.
- **Use**: This variable is used to store the PID of the process that acts as the init process for a PID namespace, allowing for process isolation and management within that namespace.


---
### fd\_log\_private\_shared\_lock
- **Type**: `int*`
- **Description**: The `fd_log_private_shared_lock` is a pointer to an integer that is used as a lock mechanism for logging operations. It is intended to be shared among processes to coordinate access to logging resources.
- **Use**: This variable is used to manage access to logging resources, ensuring that log messages are printed without interference from other processes.


---
### fd\_cfg\_stage\_hugetlbfs
- **Type**: `configure_stage_t`
- **Description**: The variable `fd_cfg_stage_hugetlbfs` is a global variable of type `configure_stage_t`. It is declared as an external variable, indicating that its definition is likely located in another file. This variable is part of a configuration system for managing huge pages in a Linux environment.
- **Use**: This variable is used to check and ensure that huge pages are configured correctly in the system, as part of the Firedancer setup process.


---
### fd\_cfg\_stage\_ethtool\_channels
- **Type**: `configure_stage_t`
- **Description**: The variable `fd_cfg_stage_ethtool_channels` is a global variable of type `configure_stage_t`. It is declared as an external variable, indicating that its definition is located in another translation unit. This variable is likely part of a configuration system for managing network settings, specifically related to ethtool channels.
- **Use**: This variable is used to manage and configure the ethtool channels settings as part of the network configuration process.


---
### fd\_cfg\_stage\_ethtool\_gro
- **Type**: `configure_stage_t`
- **Description**: The variable `fd_cfg_stage_ethtool_gro` is a global variable of type `configure_stage_t`. It is declared as an external variable, indicating that its definition is located in another file. This variable is likely used to manage or represent a specific configuration stage related to the ethtool's Generic Receive Offload (GRO) settings.
- **Use**: This variable is used to check and possibly initialize the ethtool GRO settings as part of the Firedancer configuration process.


---
### fd\_cfg\_stage\_ethtool\_loopback
- **Type**: `configure_stage_t`
- **Description**: The variable `fd_cfg_stage_ethtool_loopback` is a global variable of type `configure_stage_t`. It is declared as an external variable, indicating that its definition is likely located in another file. This variable is part of a set of configuration stages related to network settings, specifically for managing ethtool loopback configurations.
- **Use**: This variable is used to check and initialize the ethtool loopback configuration as part of the Firedancer setup process.


---
### fd\_cfg\_stage\_sysctl
- **Type**: `configure_stage_t`
- **Description**: The variable `fd_cfg_stage_sysctl` is a global variable of type `configure_stage_t`. It is declared as an external variable, indicating that it is defined elsewhere in the program or in a linked module. This variable is likely used to represent a specific stage in a configuration process related to system control parameters.
- **Use**: This variable is used to check and possibly initialize system control parameters during the configuration process.


---
### fd\_cfg\_stage\_hyperthreads
- **Type**: `configure_stage_t`
- **Description**: The variable `fd_cfg_stage_hyperthreads` is a global variable of type `configure_stage_t`. It is declared as an external variable, indicating that its definition is located in another file. This variable is likely part of a configuration system for managing hyperthreading settings.
- **Use**: This variable is used to check and configure hyperthreading settings as part of the system's configuration stages.


---
### run\_cmd\_fn
- **Type**: `function`
- **Description**: The `run_cmd_fn` is a function that is responsible for executing the main command to start up a Firedancer validator. It checks the configuration for necessary entrypoints and conditions before proceeding to run the Firedancer process.
- **Use**: This function is used to initiate the Firedancer validator process, ensuring that the configuration is valid and the necessary conditions are met before starting.


---
### fd\_action\_run1
- **Type**: `action_t`
- **Description**: The `fd_action_run1` variable is a global instance of the `action_t` structure, which is used to define an action or command within the Firedancer application. It contains fields such as `name`, `args`, `fn`, `perm`, and `description`, which specify the action's name, arguments, function to execute, permissions, and a description of the action, respectively.
- **Use**: This variable is used to define and register the 'run1' action, which starts up a single Firedancer tile.


---
### fd\_action\_run
- **Type**: `action_t`
- **Description**: The `fd_action_run` variable is a global instance of the `action_t` structure, which is used to define an action named "run". This action is responsible for starting up a Firedancer validator, a component of a system that likely involves network operations and requires specific permissions to execute.
- **Use**: This variable is used to encapsulate the details and permissions required to execute the "run" command for starting a Firedancer validator.


# Data Structures

---
### pidns\_clone\_args
- **Type**: `struct`
- **Members**:
    - `config`: A pointer to a constant configuration structure.
    - `pipefd`: A pointer to an integer representing a file descriptor for a pipe.
    - `closefd`: An integer representing a file descriptor that should be closed.
- **Description**: The `pidns_clone_args` structure is used to encapsulate arguments required for cloning a process into a new PID namespace. It includes a pointer to a configuration object, a pipe file descriptor for inter-process communication, and a file descriptor that should be closed during the process setup. This structure is essential for managing process isolation and communication in a sandboxed environment.


# Functions

---
### run\_cmd\_perm<!-- {{#callable:run_cmd_perm}} -->
The `run_cmd_perm` function configures system resource limits and capabilities required for running a Firedancer validator by checking and raising necessary permissions.
- **Inputs**:
    - `args`: A pointer to an `args_t` structure, which is not used in this function.
    - `chk`: A pointer to an `fd_cap_chk_t` structure used for checking and raising resource limits and capabilities.
    - `config`: A constant pointer to a `config_t` structure containing configuration details such as user IDs, group IDs, and network settings.
- **Control Flow**:
    - The function begins by ignoring the `args` parameter as it is not used.
    - It calculates the maximum memory lock limit using `fd_topo_mlock_max_tile` based on the topology in the configuration.
    - It raises the `RLIMIT_MEMLOCK` limit to allow all memory to be locked using `mlock(2)`.
    - It raises the `RLIMIT_NICE` limit to increase thread priorities.
    - It raises the `RLIMIT_NOFILE` limit to allow more open files for Agave.
    - It checks and raises the `CAP_NET_RAW` capability to bind to a raw socket for XDP usage.
    - It checks and raises the `CAP_SYS_ADMIN` capability for initializing XDP with `bpf(2)` and for sandboxing the process if required.
    - If the current user ID does not match the configured user ID, it raises the `CAP_SETUID` capability to switch to the sandbox user.
    - If the current group ID does not match the configured group ID, it raises the `CAP_SETGID` capability to switch to the sandbox group.
    - If network namespace is enabled in development settings, it raises the `CAP_SYS_ADMIN` capability to enter a network namespace.
    - If the Prometheus listen port is less than 1024, it raises the `CAP_NET_BIND_SERVICE` capability to bind to a privileged port for serving metrics.
    - If the GUI listen port is less than 1024, it raises the `CAP_NET_BIND_SERVICE` capability to bind to a privileged port for serving the GUI.
- **Output**: The function does not return a value; it performs actions to configure system permissions and capabilities.


---
### parent\_signal<!-- {{#callable:parent_signal}} -->
The `parent_signal` function handles signals received by the parent process, ensuring proper logging and termination of child processes.
- **Inputs**:
    - `sig`: An integer representing the signal number received by the process.
- **Control Flow**:
    - If `pid_namespace` is set, send a SIGKILL to terminate the process with that PID.
    - Set a local lock variable to zero and assign it to `fd_log_private_shared_lock` to avoid deadlocks in logging.
    - Check if the log file descriptor is valid; if so, log the received signal and the log file path, otherwise just log the signal.
    - If the signal is SIGINT, call `fd_sys_util_exit_group` with an exit code of 128 plus SIGINT; otherwise, call it with an exit code of 0.
- **Output**: The function does not return a value; it performs actions based on the received signal.


---
### install\_parent\_signals<!-- {{#callable:install_parent_signals}} -->
The `install_parent_signals` function sets up signal handlers for the parent process to handle termination and ignore certain user signals.
- **Inputs**: None
- **Control Flow**:
    - Initialize a `sigaction` structure `sa` with `parent_signal` as the handler and no flags.
    - Set the signal handler for `SIGTERM` and `SIGINT` to `parent_signal` using `sigaction`, logging an error if it fails.
    - Change the signal handler in `sa` to `SIG_IGN` to ignore signals.
    - Set the signal handler for `SIGUSR1` and `SIGUSR2` to `SIG_IGN` using `sigaction`, logging an error if it fails.
- **Output**: The function does not return any value.


---
### create\_clone\_stack<!-- {{#callable:create_clone_stack}} -->
The `create_clone_stack` function allocates a memory region for a stack with guard pages using `mmap` and `munmap` to ensure safe stack usage in a cloned process.
- **Inputs**: None
- **Control Flow**:
    - Calculate the total size needed for the stack and guard pages.
    - Use `mmap` to allocate a memory region with read and write permissions.
    - Check if `mmap` failed and log an error if it did.
    - Use `munmap` to unmap the lower and upper guard pages from the allocated region.
    - Adjust the stack pointer to account for the lower guard page.
    - Use `mmap` with `MAP_FIXED` to create non-accessible guard pages at the lower and upper ends of the stack.
    - Check if `mmap` for guard pages failed and log an error if it did.
    - Return the pointer to the usable stack area.
- **Output**: A pointer to the allocated stack area, excluding the guard pages.


---
### execve\_agave<!-- {{#callable:execve_agave}} -->
The `execve_agave` function forks a new process to execute the current executable with specific arguments and environment variables, handling file descriptor settings and error logging.
- **Inputs**:
    - `config_memfd`: An integer representing a file descriptor for the configuration memory.
    - `pipefd`: An integer representing a file descriptor for a pipe used for inter-process communication.
- **Control Flow**:
    - Check if setting the file descriptor flags for `pipefd` to 0 fails, and log an error if it does.
    - Fork a new process and log an error if the fork fails.
    - In the child process (if fork is successful), retrieve the current executable path and prepare arguments for `execve`.
    - Check for the presence of the `GOOGLE_APPLICATION_CREDENTIALS` environment variable and include it in the environment if it exists.
    - Attempt to execute the current executable with the prepared arguments and environment, logging an error if `execve` fails.
    - In the parent process, set the file descriptor flags for `pipefd` to `FD_CLOEXEC` and return the child's process ID.
- **Output**: Returns the process ID of the child process if successful, or logs an error and exits if any operation fails.


---
### execve\_tile<!-- {{#callable:execve_tile}} -->
The `execve_tile` function sets up and executes a new process for a given tile with specific CPU affinity and priority settings, using a provided configuration and communication pipe.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure representing the tile to be executed, containing information such as CPU index and kind ID.
    - `floating_cpu_set`: A pointer to a `fd_cpuset_t` structure representing the set of CPUs to use if the tile's CPU index is not specified.
    - `floating_priority`: An integer representing the priority to set if the tile's CPU index is not specified.
    - `config_memfd`: An integer file descriptor for the configuration memory file to be passed to the new process.
    - `pipefd`: An integer file descriptor for a pipe used for communication with the new process.
- **Control Flow**:
    - Declare a CPU set and check if the tile's CPU index is specified.
    - If specified, set the CPU affinity to the tile's CPU index and set the process priority to -19.
    - If not specified, copy the floating CPU set and set the process priority to the floating priority.
    - Set the thread affinity to the determined CPU set, logging an error if it fails.
    - Clear the CLOEXEC flag on the pipe file descriptor to pass it to the new process.
    - Fork a new process and check for errors.
    - In the child process, construct the executable path and arguments, then execute the new process using `execve`.
    - In the parent process, set the CLOEXEC flag back on the pipe file descriptor and return the child's PID.
- **Output**: Returns the PID of the newly created child process, or logs an error if any step fails.


---
### main\_pid\_namespace<!-- {{#callable:main_pid_namespace}} -->
The `main_pid_namespace` function initializes and manages a PID namespace, handling process creation, configuration, and monitoring for a set of child processes.
- **Inputs**:
    - `_args`: A pointer to a `pidns_clone_args` structure containing configuration data, pipe file descriptors, and a file descriptor to close.
- **Control Flow**:
    - Close the read end of the pipe specified in `args->pipefd` and optionally close `args->closefd` if it is not -1.
    - Retrieve the configuration from `args` and set up logging for the PID namespace.
    - If sandboxing is not enabled, set the process as a child subreaper using `prctl`.
    - Save the current CPU affinity to restore it later and initialize arrays for child process management.
    - Convert the configuration to a memory file descriptor and handle errors if conversion fails.
    - If debugging is enabled, modify the shared log lock.
    - Create a child process for 'agave' if certain conditions are met, using [`execve_agave`](#execve_agave).
    - Enter a network namespace if enabled in the configuration.
    - Save the current process priority and handle errors if retrieval fails.
    - Install XDP if required by the network provider and handle file descriptor settings for XDP.
    - Iterate over the tiles in the configuration, creating child processes for each non-agave tile using [`execve_tile`](#execve_tile).
    - Restore the original process priority and CPU affinity.
    - Close various file descriptors, including those related to configuration and logging.
    - Set up a seccomp filter and enter a sandbox environment if enabled, or switch user and group IDs otherwise.
    - Reap child processes to ensure they do not appear in process listings, handling errors and exit statuses appropriately.
    - Set up polling on the main pipe and child pipes to monitor for process termination.
    - Enter a loop to poll for events on the pipes, handling process termination and cleanup if any child or the parent process dies.
- **Output**: The function returns an integer, typically 0, indicating successful execution and management of the PID namespace and its child processes.
- **Functions called**:
    - [`execve_agave`](#execve_agave)
    - [`execve_tile`](#execve_tile)
    - [`populate_sock_filter_policy_pidns_arm64`](generated/pidns_arm64_seccomp.h.driver.md#populate_sock_filter_policy_pidns_arm64)
    - [`populate_sock_filter_policy_pidns`](generated/pidns_seccomp.h.driver.md#populate_sock_filter_policy_pidns)


---
### clone\_firedancer<!-- {{#callable:clone_firedancer}} -->
The `clone_firedancer` function creates a new process in a PID namespace and sets up a communication pipe between the parent and child processes.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing configuration settings, including whether to use a sandbox environment.
    - `close_fd`: An integer representing a file descriptor that should be closed in the child process.
    - `out_pipe`: A pointer to an integer where the read end of the pipe will be stored for the parent process to detect when the child process has terminated.
- **Control Flow**:
    - Create a pipe with `pipe2` to allow the child process to detect when the parent process has died.
    - Determine the clone flags based on the sandbox setting in the configuration, using `CLONE_NEWPID` if sandboxing is enabled.
    - Prepare the `pidns_clone_args` structure with the configuration, file descriptor to close, and pipe file descriptors.
    - Allocate a stack for the new process using [`create_clone_stack`](#create_clone_stack).
    - Call `clone` to create a new process in a PID namespace, passing the `main_pid_namespace` function and the prepared arguments.
    - If `clone` fails, log an error and terminate the process.
    - Close the write end of the pipe in the parent process to ensure the child can detect when the parent has died.
    - Store the read end of the pipe in `out_pipe` for the parent process to monitor the child process.
- **Output**: Returns the process ID of the newly created namespace process, or logs an error if the clone operation fails.
- **Functions called**:
    - [`create_clone_stack`](#create_clone_stack)


---
### workspace\_path<!-- {{#callable:workspace_path}} -->
The `workspace_path` function constructs a file path for a workspace based on the configuration and workspace details, and stores it in the provided output buffer.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing configuration details, including mount paths for huge and gigantic pages.
    - `wksp`: A pointer to a `fd_topo_wksp_t` structure representing the workspace, which includes the page size and workspace name.
    - `out`: A character array with a size of `PATH_MAX` where the constructed workspace path will be stored.
- **Control Flow**:
    - Determine the mount path based on the page size of the workspace (`wksp->page_sz`).
    - If the page size is `FD_SHMEM_HUGE_PAGE_SZ`, set `mount_path` to `config->hugetlbfs.huge_page_mount_path`.
    - If the page size is `FD_SHMEM_GIGANTIC_PAGE_SZ`, set `mount_path` to `config->hugetlbfs.gigantic_page_mount_path`.
    - If the page size is neither, log an error indicating an invalid page size.
    - Use `fd_cstr_printf_check` to format the workspace path as `<mount_path>/<config->name>_<wksp->name>.wksp` and store it in the `out` buffer.
- **Output**: The function does not return a value but populates the `out` buffer with the constructed workspace path.


---
### warn\_unknown\_files<!-- {{#callable:warn_unknown_files}} -->
The `warn_unknown_files` function checks for and logs any unknown files in a specified mount path based on the given mount type.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing configuration details, including paths for huge and gigantic page mount points and workspace information.
    - `mount_type`: An unsigned long integer indicating the type of mount (0 for huge pages, 1 for gigantic pages).
- **Control Flow**:
    - Determine the mount path based on the `mount_type` (0 for huge pages, 1 for gigantic pages).
    - Open the directory at the determined mount path; if it fails to open and the error is not 'no such file or directory', log an error and return.
    - Iterate over each entry in the directory, skipping '.' and '..'.
    - For each entry, construct its full path and check if it matches any known workspace paths or, if `mount_type` is 0, any known stack paths.
    - If an entry does not match any known paths, log a warning indicating an unknown file was found.
    - Close the directory and log an error if closing fails.
- **Output**: The function does not return a value; it logs warnings for unknown files and errors for invalid operations.
- **Functions called**:
    - [`workspace_path`](#workspace_path)


---
### initialize\_workspaces<!-- {{#callable:initialize_workspaces}} -->
The `initialize_workspaces` function sets up and initializes workspaces based on the provided configuration, handling permissions and existing workspace files.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing configuration details, including user and group IDs, workspace count, and workspace details.
- **Control Flow**:
    - Retrieve the current user and group IDs using `getuid()` and `getgid()`.
    - If the current group ID differs from the one in the config, attempt to change the effective group ID using `setegid()`. Log an error if it fails.
    - If the current user ID differs from the one in the config, attempt to change the effective user ID using `seteuid()`. Log an error if it fails.
    - Iterate over each workspace in the configuration's topology.
    - For each workspace, generate its path using `workspace_path()`.
    - Check if the workspace path exists using `stat()`.
    - If the path exists and the configuration is for a live cluster, attempt to delete the existing workspace file using `unlink()`.
    - Determine whether to update an existing workspace or create a new one based on the result of `stat()` and the configuration settings.
    - Attempt to create or update the workspace using `fd_topo_create_workspace()`. Log an error if it fails due to memory issues, and warn about unknown files if necessary.
    - Join the workspace in read-write mode using `fd_topo_join_workspace()`.
    - Initialize the workspace with `fd_topo_wksp_new()` using predefined callbacks.
    - Leave the workspace using `fd_topo_leave_workspace()`.
    - Restore the original user and group IDs using `seteuid()` and `setegid()`, logging errors if these operations fail.
- **Output**: The function does not return a value; it performs operations to initialize workspaces and logs errors if any issues occur.
- **Functions called**:
    - [`workspace_path`](#workspace_path)
    - [`warn_unknown_files`](#warn_unknown_files)


---
### initialize\_stacks<!-- {{#callable:initialize_stacks}} -->
The `initialize_stacks` function sets up shared memory stacks for each tile in the configuration, ensuring proper permissions and handling potential errors.
- **Inputs**:
    - `config`: A pointer to a constant `config_t` structure containing configuration details, including user and group IDs, topology information, and paths for huge page mounts.
- **Control Flow**:
    - Check if the `FD_HAS_MSAN` macro is defined; if so, return immediately as MSan is incompatible with the stack setup.
    - Retrieve the current user and group IDs using `getgid()` and `getuid()`.
    - If the current group ID differs from the one in the configuration, attempt to change the effective group ID using `setegid()`. Log an error if this fails.
    - If the current user ID differs from the one in the configuration, attempt to change the effective user ID using `seteuid()`. Log an error if this fails.
    - Iterate over each tile in the configuration's topology.
    - For each tile, construct a path for the stack file using `fd_cstr_printf_check()` and attempt to unlink it, logging an error if the unlink fails for reasons other than the file not existing.
    - Determine the CPU index for the stack, defaulting to 0 if the tile's CPU index is not less than 65535.
    - Construct a name for the stack using `fd_cstr_printf_check()`.
    - Attempt to create a shared memory stack using `fd_shmem_create_multi()`, logging an error if it fails due to memory issues or other reasons.
    - Restore the original user and group IDs using `seteuid()` and `setegid()`, logging errors if these operations fail.
- **Output**: The function does not return a value; it performs its operations for side effects, such as setting up stacks and logging errors.
- **Functions called**:
    - [`warn_unknown_files`](#warn_unknown_files)


---
### fdctl\_check\_configure<!-- {{#callable:fdctl_check_configure}} -->
The `fdctl_check_configure` function verifies the system configuration for Firedancer, ensuring that huge pages, network settings, kernel parameters, and hyperthreading are correctly set up.
- **Inputs**:
    - `config`: A pointer to a constant `config_t` structure containing the configuration settings to be checked.
- **Control Flow**:
    - Call `fd_cfg_stage_hugetlbfs.check` to verify huge pages configuration.
    - If huge pages are not configured correctly, log an error and suggest running `fdctl configure init hugetlbfs`.
    - Check if network namespace is not enabled and network provider is 'xdp'.
    - If conditions are met, check network configurations using `fd_cfg_stage_ethtool_channels`, `fd_cfg_stage_ethtool_gro`, and `fd_cfg_stage_ethtool_loopback`.
    - For each network configuration check, if not configured correctly, log an error and suggest the appropriate `fdctl configure init` command.
    - Call `fd_cfg_stage_sysctl.check` to verify kernel parameters configuration.
    - If kernel parameters are not configured correctly, log an error and suggest running `fdctl configure init sysctl`.
    - Call `fd_cfg_stage_hyperthreads.check` to verify hyperthreading configuration.
    - If hyperthreading is not configured correctly, log an error and suggest running `fdctl configure init hyperthreads`.
- **Output**: The function does not return a value; it logs errors if any configuration checks fail.


---
### run\_firedancer\_init<!-- {{#callable:run_firedancer_init}} -->
The `run_firedancer_init` function initializes the Firedancer environment by verifying key paths, checking configuration, and optionally initializing workspaces and stacks.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing configuration details for the Firedancer environment.
    - `init_workspaces`: An integer flag indicating whether to initialize workspaces (non-zero value) or not (zero value).
- **Control Flow**:
    - The function begins by declaring a `struct stat` variable `st` and attempts to `stat` the identity key path specified in the `config` structure.
    - If the `stat` call fails because the file does not exist (`ENOENT`), it logs an error message indicating the missing identity key.
    - If the `stat` call fails for any other reason, it logs a different error message with the specific error details.
    - If the `config` indicates that the environment is not a Firedancer (`!config->is_firedancer`), it iterates over the `authorized_voter_paths` and performs similar `stat` checks, logging errors if any path is missing or inaccessible.
    - The function then calls [`fdctl_check_configure`](#fdctl_check_configure) to verify the configuration settings.
    - If `init_workspaces` is true, it calls [`initialize_workspaces`](#initialize_workspaces) to set up the necessary workspaces.
    - Finally, it calls [`initialize_stacks`](#initialize_stacks) to set up the stack environment.
- **Output**: The function does not return a value; it performs initialization tasks and logs errors if any issues are encountered.
- **Functions called**:
    - [`fdctl_check_configure`](#fdctl_check_configure)
    - [`initialize_workspaces`](#initialize_workspaces)
    - [`initialize_stacks`](#initialize_stacks)


---
### fdctl\_setup\_netns<!-- {{#callable:fdctl_setup_netns}} -->
The `fdctl_setup_netns` function configures the network namespace for a given configuration, optionally restoring the original namespace after setup.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure that contains configuration settings, including network namespace and provider information.
    - `stay`: An integer flag indicating whether to stay in the new network namespace (non-zero) or to restore the original namespace (zero).
- **Control Flow**:
    - Check if network namespace is enabled in the configuration; if not, return immediately.
    - Determine whether to save the original network namespace based on the `stay` flag.
    - Attempt to enter the specified network namespace using `fd_net_util_netns_enter`; log an error and exit if it fails.
    - If the network provider is 'xdp', initialize ethtool settings using `fd_cfg_stage_ethtool_channels`, `fd_cfg_stage_ethtool_gro`, and `fd_cfg_stage_ethtool_loopback`.
    - If the original network namespace was saved, attempt to restore it using `fd_net_util_netns_restore`; log an error and exit if it fails.
- **Output**: The function does not return a value; it performs network namespace setup and logs errors if operations fail.


---
### run\_firedancer<!-- {{#callable:run_firedancer}} -->
The `run_firedancer` function initializes and runs the Firedancer process, setting up necessary security and sandboxing measures, and managing process control and logging.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing configuration settings for the Firedancer process.
    - `parent_pipefd`: An integer representing the file descriptor for the parent process's pipe, used for inter-process communication.
    - `init_workspaces`: An integer flag indicating whether to initialize workspaces (non-zero to initialize).
- **Control Flow**:
    - Log the topology configuration using `fd_topo_print_log`.
    - Initialize the Firedancer process with [`run_firedancer_init`](#run_firedancer_init), passing the configuration and workspace initialization flag.
    - Attempt to create a Landlock ruleset using a syscall, logging a warning if not supported by the kernel.
    - Close standard input (file descriptor 0) and conditionally close standard output (file descriptor 1) if not used for logging.
    - Clone the Firedancer process into a new PID namespace using [`clone_firedancer`](#clone_firedancer), obtaining a pipe file descriptor for communication.
    - Install signal handlers for SIGINT and SIGTERM to manage process termination and logging.
    - Close the log lock file descriptor from the configuration.
    - Populate a seccomp filter policy for the main process using [`populate_sock_filter_policy_main`](generated/main_seccomp.h.driver.md#populate_sock_filter_policy_main).
    - Prepare an array of allowed file descriptors for the sandbox environment, including stderr, the log file, and pipe ends.
    - Enter a sandbox environment using `fd_sandbox_enter` if sandboxing is enabled, otherwise switch user and group IDs with `fd_sandbox_switch_uid_gid`.
    - Set up a shared log lock to prevent deadlocks if a child process dies while holding the lock.
    - Wait for the PID namespace process to terminate using `wait4`, logging an error if it fails.
    - Exit the process group with the appropriate exit status based on the termination signal or exit code of the PID namespace process.
- **Output**: The function does not return a value; it manages process control and exits the process group based on the status of the PID namespace process.
- **Functions called**:
    - [`run_firedancer_init`](#run_firedancer_init)
    - [`clone_firedancer`](#clone_firedancer)
    - [`install_parent_signals`](#install_parent_signals)
    - [`populate_sock_filter_policy_main`](generated/main_seccomp.h.driver.md#populate_sock_filter_policy_main)



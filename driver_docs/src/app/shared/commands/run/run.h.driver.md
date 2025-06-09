# Purpose
This C header file defines the interface for a set of functions and actions related to running and managing a software component called "Firedancer." It includes function prototypes for initializing and configuring workspaces, setting up network namespaces, and executing commands with specific permissions. The file also declares two external action variables, `fd_action_run1` and `fd_action_run`, which likely represent specific operations or tasks within the Firedancer application. The inclusion of configuration and argument structures (`config_t` and `args_t`) suggests that these functions are designed to be flexible and adaptable to different runtime configurations. Overall, this header file serves as a blueprint for implementing the operational logic of the Firedancer application, focusing on initialization, configuration, and execution processes.
# Imports and Dependencies

---
- `../../fd_config.h`
- `../../fd_action.h`


# Global Variables

---
### create\_clone\_stack
- **Type**: `function pointer`
- **Description**: The `create_clone_stack` is a function pointer that returns a void pointer. It is declared within the `FD_PROTOTYPES_BEGIN` and `FD_PROTOTYPES_END` block, indicating it is part of a set of function prototypes for the application.
- **Use**: This function is used to create a stack for a clone operation, returning a pointer to the created stack.


---
### fd\_action\_run1
- **Type**: `action_t`
- **Description**: The variable `fd_action_run1` is a global variable of type `action_t`, which is likely a structure or typedef defined elsewhere in the codebase. It is declared as an external variable, indicating that it is defined in another source file and is accessible from this header file.
- **Use**: This variable is used to represent a specific action or command that can be executed, likely related to the 'run1' command functionality in the application.


---
### fd\_action\_run
- **Type**: `action_t`
- **Description**: The `fd_action_run` is a global variable of type `action_t`, which is likely a custom data type defined elsewhere in the codebase. It is declared as an external variable, indicating that its definition is located in another source file.
- **Use**: This variable is used to represent a specific action or command that can be executed within the application, possibly related to running or managing processes.


# Function Declarations (Public API)

---
### create\_clone\_stack<!-- {{#callable_declaration:create_clone_stack}} -->
Allocates and returns a pointer to a new stack with guard pages for a clone.
- **Description**: This function is used to allocate a memory region suitable for use as a stack for a new thread or process clone. It sets up guard pages at both ends of the stack to help detect stack overflows and underflows. The function should be called when a new stack is needed for a clone operation, ensuring that the system has sufficient resources to allocate the required memory. The caller is responsible for managing the lifecycle of the returned stack, including deallocating it when no longer needed.
- **Inputs**: None
- **Output**: Returns a pointer to the start of the allocated stack memory, or logs an error and terminates if allocation fails.
- **See also**: [`create_clone_stack`](run.c.driver.md#create_clone_stack)  (Implementation)


---
### clone\_firedancer<!-- {{#callable_declaration:clone_firedancer}} -->
Creates a new process in a PID namespace and sets up a communication pipe.
- **Description**: This function is used to create a new process within a PID namespace, optionally using a sandbox environment based on the configuration provided. It sets up a pipe to allow the child process to detect when the parent process has terminated. This function should be called when a new isolated process is needed, and it requires a valid configuration object. The function will return a process ID for the new namespace or an error code if the operation fails. The caller must ensure that the `out_pipe` pointer is valid and that the `close_fd` is a valid file descriptor if it is to be closed in the child process.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing configuration settings. This must not be null and should be properly initialized before calling the function.
    - `close_fd`: An integer representing a file descriptor that should be closed in the child process. It should be a valid file descriptor or -1 if no file descriptor needs to be closed.
    - `out_pipe`: A pointer to an integer where the function will store the read end of the pipe. This must not be null, and the caller is responsible for managing the lifecycle of the pipe.
- **Output**: Returns the process ID of the new namespace on success, or a negative error code on failure.
- **See also**: [`clone_firedancer`](run.c.driver.md#clone_firedancer)  (Implementation)


---
### fdctl\_check\_configure<!-- {{#callable_declaration:fdctl_check_configure}} -->
Verify and ensure the system configuration is correct for Firedancer.
- **Description**: This function checks the system configuration to ensure it is correctly set up for running Firedancer. It verifies several aspects of the configuration, including huge pages, network settings, kernel parameters, and hyperthreading. If any configuration is incorrect, it logs an error message with guidance on how to fix the issue. This function should be called before starting Firedancer to ensure all necessary system configurations are in place. It is particularly important to run this after a system restart, as some configurations may need to be reapplied.
- **Inputs**:
    - `config`: A pointer to a constant `config_t` structure containing the configuration settings to be checked. The caller retains ownership of this pointer, and it must not be null. The function assumes the configuration is valid and correctly populated.
- **Output**: None
- **See also**: [`fdctl_check_configure`](run.c.driver.md#fdctl_check_configure)  (Implementation)


---
### initialize\_workspaces<!-- {{#callable_declaration:initialize_workspaces}} -->
Initializes and configures workspaces based on the provided configuration.
- **Description**: This function sets up workspaces as specified in the provided configuration object. It should be called when the system needs to prepare workspaces for operation, typically during initialization. The function temporarily switches to a non-root user and group ID to perform workspace creation, ensuring proper permissions. It handles existing workspaces by either updating them or creating new ones if they do not exist. The function must be called with a valid configuration object that specifies the necessary workspace details. It is important to ensure that the configuration is correctly set up before calling this function to avoid errors.
- **Inputs**:
    - `config`: A pointer to a config_t structure that contains the configuration details for the workspaces. This includes user and group IDs, workspace count, and other necessary parameters. The pointer must not be null, and the configuration must be properly initialized before calling this function.
- **Output**: None
- **See also**: [`initialize_workspaces`](run.c.driver.md#initialize_workspaces)  (Implementation)


---
### initialize\_stacks<!-- {{#callable_declaration:initialize_stacks}} -->
Initializes memory stacks for each tile in the configuration.
- **Description**: This function sets up memory stacks for each tile specified in the provided configuration. It should be called after the configuration is fully defined and before any operations that require these stacks. The function temporarily changes the effective user and group IDs to those specified in the configuration to ensure proper permissions for creating shared memory stacks. It handles potential errors such as memory allocation failures and logs them appropriately. This function is essential for preparing the environment for subsequent operations that depend on these stacks.
- **Inputs**:
    - `config`: A pointer to a constant `config_t` structure containing configuration details for stack initialization. This includes user and group IDs, tile information, and paths for huge page mounts. The pointer must not be null, and the structure should be fully populated with valid data before calling this function.
- **Output**: None
- **See also**: [`initialize_stacks`](run.c.driver.md#initialize_stacks)  (Implementation)


---
### run\_firedancer\_init<!-- {{#callable_declaration:run_firedancer_init}} -->
Initializes the Firedancer environment based on the provided configuration.
- **Description**: This function sets up the Firedancer environment by verifying the existence of necessary identity and voter keys as specified in the configuration. It should be called with a valid configuration object before running any Firedancer operations. If the `init_workspaces` parameter is non-zero, it will also initialize workspaces. The function checks for the presence of identity and voter keys, logging errors if they are missing or inaccessible. It then configures the environment and initializes necessary components.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing configuration details for the Firedancer environment. Must not be null and should be properly initialized with valid paths and settings.
    - `init_workspaces`: An integer flag indicating whether to initialize workspaces. A non-zero value triggers workspace initialization.
- **Output**: None
- **See also**: [`run_firedancer_init`](run.c.driver.md#run_firedancer_init)  (Implementation)


---
### fdctl\_setup\_netns<!-- {{#callable_declaration:fdctl_setup_netns}} -->
Configures the network namespace for the application.
- **Description**: This function sets up the network namespace based on the provided configuration. It should be called when the application needs to operate within a specific network namespace, as defined in the configuration. The function checks if the network namespace feature is enabled in the configuration and attempts to enter the specified network namespace. If the 'stay' parameter is false, it will also attempt to restore the original network namespace after configuration. This function is typically used in environments where network isolation is required, such as containerized applications. It is important to ensure that the configuration is correctly set up before calling this function to avoid errors.
- **Inputs**:
    - `config`: A pointer to a config_t structure containing the network configuration. The structure must be properly initialized and must not be null. The function expects the 'development.netns.enabled' field to be set to true to proceed with namespace setup.
    - `stay`: An integer flag indicating whether to remain in the new network namespace. If non-zero, the function will not attempt to restore the original namespace. If zero, the function will restore the original namespace after setup.
- **Output**: None
- **See also**: [`fdctl_setup_netns`](run.c.driver.md#fdctl_setup_netns)  (Implementation)


---
### run\_firedancer<!-- {{#callable_declaration:run_firedancer}} -->
Executes the Firedancer application with specified configuration and initialization options.
- **Description**: This function is used to start the Firedancer application, taking into account the provided configuration and initialization settings. It should be called when you need to run Firedancer with specific parameters, such as a configuration structure and initialization flags. The function handles setting up the environment, including security features like Landlock and seccomp, and manages process namespaces and signal handling. It is important to ensure that the configuration is properly set up before calling this function, as it relies on the configuration details to initialize and run the application correctly. The function also manages file descriptors and process termination, ensuring that resources are properly cleaned up.
- **Inputs**:
    - `config`: A pointer to a config_t structure containing the configuration settings for Firedancer. This must be properly initialized before calling the function. The caller retains ownership and must ensure it is not null.
    - `parent_pipefd`: An integer representing the file descriptor for the parent pipe. It can be -1 if not used. The function will handle closing this file descriptor if necessary.
    - `init_workspaces`: An integer flag indicating whether to initialize workspaces. A non-zero value will trigger workspace initialization.
- **Output**: None
- **See also**: [`run_firedancer`](run.c.driver.md#run_firedancer)  (Implementation)


---
### run\_cmd\_perm<!-- {{#callable_declaration:run_cmd_perm}} -->
Adjusts system resource limits and capabilities for a command.
- **Description**: This function is used to ensure that the necessary system resource limits and capabilities are set for executing a command with specific permissions. It should be called when preparing to run a command that requires elevated privileges or specific resource limits, such as locking memory, increasing the number of open files, or binding to privileged ports. The function checks and raises resource limits and capabilities as needed, based on the provided configuration. It is important to ensure that the `chk` and `config` parameters are properly initialized before calling this function.
- **Inputs**:
    - `args`: A pointer to an `args_t` structure. This parameter is not used in the function and can be ignored.
    - `chk`: A pointer to an `fd_cap_chk_t` structure. This parameter must be initialized before calling the function, as it is used to check and raise system capabilities and resource limits.
    - `config`: A pointer to a constant `config_t` structure. This parameter must be initialized and contains configuration settings that determine which capabilities and resource limits need to be adjusted.
- **Output**: None
- **See also**: [`run_cmd_perm`](run.c.driver.md#run_cmd_perm)  (Implementation)


---
### run1\_cmd\_args<!-- {{#callable_declaration:run1_cmd_args}} -->
Parse command-line arguments for the run1 command.
- **Description**: This function processes command-line arguments intended for the 'run1' command, extracting and validating necessary parameters. It expects at least two arguments: a tile name and a kind ID. The function modifies the argument count and vector to reflect the consumed arguments. It also populates the provided 'args' structure with the parsed values. If the arguments are insufficient or invalid, the function logs an error and terminates the program. This function should be called early in the program's execution to ensure that the required parameters are available for subsequent operations.
- **Inputs**:
    - `pargc`: A pointer to the argument count, which must be greater than or equal to 2. The function decrements this count as arguments are consumed. Must not be null.
    - `pargv`: A pointer to the argument vector, which must contain at least two valid arguments. The function advances this pointer as arguments are consumed. Must not be null.
    - `args`: A pointer to an 'args_t' structure where the parsed command-line arguments will be stored. The structure is modified to include the parsed 'pipe_fd', 'tile_name', and 'kind_id'. Must not be null.
- **Output**: None
- **See also**: [`run1_cmd_args`](run1.c.driver.md#run1_cmd_args)  (Implementation)


---
### run1\_cmd\_fn<!-- {{#callable_declaration:run1_cmd_fn}} -->
Executes a command in a new process with specific configuration and arguments.
- **Description**: This function is used to execute a command within a new process context, utilizing the provided configuration and arguments. It is typically called when a specific command needs to be run with a particular setup defined by the configuration. The function sets up the necessary environment, including process affinity and logging, before executing the command. It is important to ensure that the configuration and arguments are properly initialized and valid before calling this function. The function handles errors internally and logs them if any issues occur during execution.
- **Inputs**:
    - `args`: A pointer to an `args_t` structure containing the arguments for the command. This must be properly initialized and must not be null. The function expects valid data within this structure to determine the command execution parameters.
    - `config`: A pointer to a `config_t` structure that holds the configuration settings for the command execution. This must be properly initialized and must not be null. The configuration is used to set up the environment and determine execution parameters.
- **Output**: None
- **See also**: [`run1_cmd_fn`](run1.c.driver.md#run1_cmd_fn)  (Implementation)



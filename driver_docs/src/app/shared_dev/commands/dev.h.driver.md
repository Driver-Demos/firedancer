# Purpose
This code is a C header file that defines function prototypes for device command operations within a software application. It includes necessary dependencies from other shared components, specifically configuration and action headers, indicating that it interacts with broader application settings and actions. The file declares three functions: [`dev_cmd_args`](#dev_cmd_args), [`dev_cmd_perm`](#dev_cmd_perm), and [`dev_cmd_fn`](#dev_cmd_fn), each designed to handle different aspects of device command processing, such as argument parsing, permission checking, and executing a main function with a given configuration. The use of `FD_PROTOTYPES_BEGIN` and `FD_PROTOTYPES_END` suggests a macro-based approach to managing function prototypes, likely for ensuring compatibility or specific compilation settings. Overall, this header file serves as an interface for managing device-related commands in a modular and organized manner.
# Imports and Dependencies

---
- `../../shared/fd_config.h`
- `../../shared/fd_action.h`


# Function Declarations (Public API)

---
### dev\_cmd\_args<!-- {{#callable_declaration:dev_cmd_args}} -->
Parse and modify command-line arguments for device configuration.
- **Description**: This function processes command-line arguments to configure device-related settings in the provided `args_t` structure. It modifies the argument count and vector to remove recognized options, such as `--monitor`, `--no-configure`, `--no-init-workspaces`, and `--no-agave` or `--no-solana`. It also extracts the value for `--debug-tile` if present. This function should be called before using the `args` structure for further device configuration, ensuring that the command-line options are correctly parsed and applied.
- **Inputs**:
    - `pargc`: A pointer to the argument count, which will be modified to reflect the removal of recognized options. Must not be null.
    - `pargv`: A pointer to the argument vector, which will be modified to remove recognized options. Must not be null.
    - `args`: A pointer to an `args_t` structure where the parsed command-line options will be stored. Must not be null and should be properly initialized before calling this function.
- **Output**: None
- **See also**: [`dev_cmd_args`](dev.c.driver.md#dev_cmd_args)  (Implementation)


---
### dev\_cmd\_perm<!-- {{#callable_declaration:dev_cmd_perm}} -->
Execute device command permissions based on provided arguments and configuration.
- **Description**: This function is used to execute device command permissions, taking into account the provided arguments and configuration. It should be called when you need to apply permission checks and potentially configure device stages as specified in the arguments. The function expects valid pointers to the arguments, permission check structure, and configuration. It is important to ensure that the 'args' parameter is properly initialized and that the 'chk' and 'config' parameters are valid and consistent with the intended operation. The function does not return a value, and its behavior is contingent on the state of the 'args' structure, particularly the 'no_configure' flag.
- **Inputs**:
    - `args`: A pointer to an 'args_t' structure containing command arguments. The 'dev.no_configure' flag within this structure determines whether configuration commands are executed. Must not be null.
    - `chk`: A pointer to an 'fd_cap_chk_t' structure used for permission checking. Must be a valid pointer and not null.
    - `config`: A pointer to a constant 'config_t' structure containing configuration data. Must be a valid pointer and not null.
- **Output**: None
- **See also**: [`dev_cmd_perm`](dev.c.driver.md#dev_cmd_perm)  (Implementation)


---
### dev\_cmd\_fn<!-- {{#callable_declaration:dev_cmd_fn}} -->
Executes a development command based on provided arguments and configuration.
- **Description**: This function is used to execute a development command by utilizing the provided arguments and configuration. It is typically called when a specific development task needs to be performed, such as configuring, updating, or running a development environment. The function may modify the configuration based on the arguments and can execute different paths depending on the presence of certain flags in the arguments. It is important to ensure that the `args` and `config` parameters are properly initialized before calling this function. The function may also invoke a user-provided callback function `agave_main` if certain conditions are met.
- **Inputs**:
    - `args`: A pointer to an `args_t` structure containing the command-line arguments and flags for the development command. Must not be null and should be properly initialized before calling the function.
    - `config`: A pointer to a `config_t` structure that holds the configuration settings for the development environment. The function may modify this configuration based on the provided arguments. Must not be null and should be properly initialized.
    - `agave_main`: A pointer to a function that takes a constant `config_t` pointer as an argument. This callback function may be invoked if certain conditions in the arguments are met. Can be null if not needed.
- **Output**: None
- **See also**: [`dev_cmd_fn`](dev.c.driver.md#dev_cmd_fn)  (Implementation)



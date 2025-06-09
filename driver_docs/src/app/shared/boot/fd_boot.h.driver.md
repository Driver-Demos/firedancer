# Purpose
This code is a C header file that provides function prototypes for initializing and running a main application, likely within a larger software framework. The file defines two functions: [`fd_main`](#fd_main) and [`fd_main_init`](#fd_main_init), which are designed to handle application startup processes, including configuration management and initialization routines. The functions take parameters related to command-line arguments, configuration settings, and initialization callbacks, indicating their role in setting up the application environment, possibly for a system called "Firedancer." The inclusion guards prevent multiple inclusions of this header file, and the file also includes other headers for configuration and utility functions, suggesting its integration into a broader codebase.
# Imports and Dependencies

---
- `../fd_config.h`
- `../../../util/fd_util.h`


# Function Declarations (Public API)

---
### fd\_main<!-- {{#callable_declaration:fd_main}} -->
Executes a specified subcommand with configuration and permission checks.
- **Description**: This function processes command-line arguments to execute a specified subcommand, performing necessary configuration and permission checks. It is typically used in applications that require command-line interface (CLI) operations, where different subcommands trigger different functionalities. The function expects a set of command-line arguments, a default configuration, and a topology initialization function. It handles help and version commands immediately without requiring full configuration loading, which is useful in environments like CI/CD. The function must be called with valid command-line arguments and a non-null topology initialization function.
- **Inputs**:
    - `argc`: The number of command-line arguments. Must be greater than zero to specify a subcommand.
    - `_argv`: An array of command-line argument strings. The first argument should be the subcommand to execute. Must not be null.
    - `is_firedancer`: An integer flag indicating whether the application is running in 'firedancer' mode. Non-zero values enable this mode.
    - `default_config`: A pointer to a string containing the default configuration data. Must not be null.
    - `default_config_sz`: The size of the default configuration data in bytes. Must be a valid size corresponding to the data pointed by 'default_config'.
    - `topo_init`: A pointer to a function that initializes the topology configuration. Must not be null.
- **Output**: Returns 0 on successful execution of the subcommand, or 1 if no subcommand is specified. Logs errors and warnings for unknown subcommands or arguments.
- **See also**: [`fd_main`](fd_boot.c.driver.md#fd_main)  (Implementation)


---
### fd\_main\_init<!-- {{#callable_declaration:fd_main_init}} -->
Initialize the main application environment and configuration.
- **Description**: This function sets up the initial environment and configuration for the main application, preparing it for execution. It should be called at the start of the application to configure logging, memory, and other essential settings based on command-line arguments and configuration files. The function handles both default and user-provided configurations, and it requires a topology initialization function to be provided. It is crucial to ensure that the pointers to command-line arguments and configuration structures are valid and that the topology initialization function is correctly implemented.
- **Inputs**:
    - `pargc`: Pointer to the argument count, which may be modified to reflect processed arguments. Must not be null.
    - `pargv`: Pointer to the argument vector, which may be modified to reflect processed arguments. Must not be null.
    - `config`: Pointer to a config_t structure that will be initialized with configuration settings. Must not be null.
    - `is_firedancer`: Integer flag indicating if the application is running in Firedancer mode. Non-zero for true, zero for false.
    - `is_local_cluster`: Integer flag indicating if the application is running in a local cluster environment. Non-zero for true, zero for false.
    - `log_path`: Optional path to a log file. Can be null, in which case default logging behavior is used.
    - `default_config`: Pointer to a default configuration string. Must not be null.
    - `default_config_sz`: Size of the default configuration string in bytes. Must be a valid size for the provided default configuration.
    - `topo_init`: Function pointer to a topology initialization function that takes a config_t pointer. Must not be null and should correctly initialize the topology based on the configuration.
- **Output**: None
- **See also**: [`fd_main_init`](fd_boot.c.driver.md#fd_main_init)  (Implementation)



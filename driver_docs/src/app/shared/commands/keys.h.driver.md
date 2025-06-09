# Purpose
This code is a C header file that defines the interface for handling command-related operations in an application. It includes function prototypes for [`keys_cmd_args`](#keys_cmd_args) and [`keys_cmd_fn`](#keys_cmd_fn), which are likely responsible for processing command-line arguments and executing command functions, respectively. The file also declares an external variable `fd_action_keys` of type `action_t`, which suggests it is used to represent a specific action or command within the application. The inclusion of `fd_config.h` indicates that the file relies on configuration settings defined elsewhere. Overall, this header file is part of a modular system, providing declarations necessary for managing command actions in a shared application context.
# Imports and Dependencies

---
- `../fd_config.h`


# Global Variables

---
### fd\_action\_keys
- **Type**: `action_t`
- **Description**: The `fd_action_keys` is a global variable of type `action_t`, which is likely a custom data type defined elsewhere in the codebase. It is declared as an external variable, indicating that it is defined in another source file and is accessible from this header file.
- **Use**: This variable is used to represent or store an action related to keys, and it is accessible across different source files that include this header.


# Function Declarations (Public API)

---
### keys\_cmd\_args<!-- {{#callable_declaration:keys_cmd_args}} -->
Parses command-line arguments for key-related operations.
- **Description**: This function processes command-line arguments to determine the specific key-related operation to perform, such as creating a new key or retrieving a public key. It expects the arguments to include a subcommand ('new' or 'pubkey') followed by a file path. The function updates the provided `args` structure with the parsed command and file path. It must be called with at least two arguments, and the first argument should be a valid subcommand. If the arguments are invalid or the subcommand is unrecognized, an error is logged, and the function does not modify the `args` structure.
- **Inputs**:
    - `pargc`: A pointer to an integer representing the count of command-line arguments. Must be at least 2. The value is decremented as arguments are processed.
    - `pargv`: A pointer to an array of strings representing the command-line arguments. The array is modified to point to the next unprocessed argument.
    - `args`: A pointer to an `args_t` structure where the parsed command and file path will be stored. Must not be null.
- **Output**: None
- **See also**: [`keys_cmd_args`](keys.c.driver.md#keys_cmd_args)  (Implementation)


---
### keys\_cmd\_fn<!-- {{#callable_declaration:keys_cmd_fn}} -->
Execute a key-related command based on the provided arguments.
- **Description**: This function processes a key-related command specified in the `args` parameter and performs the corresponding action. It must be called with valid `args` and `config` structures. The function supports generating a new key pair or retrieving a public key, depending on the command specified. If an unrecognized command is provided, the function logs an error. Ensure that the `args` structure is properly initialized with a valid command before calling this function.
- **Inputs**:
    - `args`: A pointer to an `args_t` structure containing the command and associated data. The `keys.cmd` field must be set to a valid command, such as `CMD_NEW_KEY` or `CMD_PUBKEY`. The structure must be properly initialized before use.
    - `config`: A pointer to a `config_t` structure containing configuration data such as user and group IDs. This structure must be properly initialized before use.
- **Output**: None
- **See also**: [`keys_cmd_fn`](keys.c.driver.md#keys_cmd_fn)  (Implementation)



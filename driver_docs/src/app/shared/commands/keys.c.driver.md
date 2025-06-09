# Purpose
This C source code file is designed to handle cryptographic key management, specifically focusing on generating new key pairs and retrieving public keys from existing key files. The file defines a command-line interface for these operations, allowing users to execute commands such as "new" to generate a new key pair and "pubkey" to retrieve and display a public key. The code is structured around a command handler ([`keys_cmd_args`](#keys_cmd_args)) that parses command-line arguments to determine the desired operation, and a function ([`keys_cmd_fn`](#keys_cmd_fn)) that executes the appropriate action based on the parsed command. The [`generate_keypair`](#FD_FN_SENSITIVEgenerate_keypair) function is responsible for creating a new key pair, using system calls to generate random data and manage file permissions, while [`keys_pubkey`](#keys_pubkey) loads and encodes a public key for display.

The file is part of a larger system, as indicated by the inclusion of various headers from different directories, suggesting it is a component of a modular software architecture. It defines an `action_t` structure, `fd_action_keys`, which encapsulates the command's name, argument parsing function, execution function, and a description, making it suitable for integration into a broader command processing framework. This structure implies that the file is intended to be part of a library or application that supports multiple actions or commands, with this particular file focusing on key management functionalities. The code does not define a public API or external interface directly but rather contributes to the internal logic of a larger application.
# Imports and Dependencies

---
- `../fd_config.h`
- `../fd_action.h`
- `../../platform/fd_file_util.h`
- `../../../disco/keyguard/fd_keyload.h`
- `errno.h`
- `fcntl.h`
- `unistd.h`
- `sys/stat.h`
- `sys/random.h`


# Global Variables

---
### fd\_action\_keys
- **Type**: `action_t`
- **Description**: The `fd_action_keys` is a global variable of type `action_t` that represents an action related to key management. It is initialized with a name, argument processing function, execution function, permissions, and a description.
- **Use**: This variable is used to define and manage actions for generating new keypairs or printing public keys within the application.


# Data Structures

---
### cmd\_type\_t
- **Type**: `enum`
- **Members**:
    - `CMD_NEW_KEY`: Represents a command to create a new key.
    - `CMD_PUBKEY`: Represents a command to retrieve a public key.
- **Description**: The `cmd_type_t` is an enumeration that defines two command types: `CMD_NEW_KEY` and `CMD_PUBKEY`. These commands are used to specify actions related to key management, such as generating a new keypair or retrieving a public key, within the context of the provided code. The enumeration allows for clear and concise representation of these command types, facilitating command handling in the associated functions.


# Functions

---
### keys\_cmd\_args<!-- {{#callable:keys_cmd_args}} -->
The `keys_cmd_args` function parses command-line arguments to determine the subcommand ('new' or 'pubkey') and the associated file path for key operations.
- **Inputs**:
    - `pargc`: A pointer to an integer representing the count of command-line arguments.
    - `pargv`: A pointer to an array of strings representing the command-line arguments.
    - `args`: A pointer to an `args_t` structure where parsed command information will be stored.
- **Control Flow**:
    - Check if the number of arguments is less than 2; if so, log an error and exit.
    - Check if the first argument is 'new'; if so, decrement the argument count, advance the argument pointer, and set the command to `CMD_NEW_KEY` with the next argument as the file path.
    - Check if the first argument is 'pubkey'; if so, decrement the argument count, advance the argument pointer, and set the command to `CMD_PUBKEY` with the next argument as the file path.
    - If neither 'new' nor 'pubkey' is matched, log an error and exit.
    - Decrement the argument count and advance the argument pointer to finalize parsing.
- **Output**: The function modifies the `args` structure to store the parsed command type and file path, and adjusts the argument count and pointer to reflect the consumed arguments.


---
### generate\_keypair<!-- {{#callable:FD_FN_SENSITIVE::generate_keypair}} -->
The `generate_keypair` function generates a 64-byte Ed25519 keypair, writes it to a specified file, and manages file permissions using specified user and group IDs.
- **Inputs**:
    - `keyfile`: A constant character pointer representing the path to the file where the keypair will be saved.
    - `target_uid`: An unsigned integer representing the user ID to be used for file creation.
    - `target_gid`: An unsigned integer representing the group ID to be used for file creation.
    - `use_grnd_random`: An integer flag indicating whether to use the GRND_RANDOM flag with the getrandom() function for generating random bytes.
- **Control Flow**:
    - Initialize flags based on the `use_grnd_random` input to determine randomness source.
    - Generate 32 random bytes using `getrandom()` and store them in the first half of the `keypair` array.
    - Create a SHA-512 context and derive the public key from the private key using `fd_ed25519_public_from_private()`.
    - Temporarily switch to the specified non-root user and group IDs for file operations.
    - Create necessary directories for the keyfile path if they do not exist.
    - Open the keyfile for writing, ensuring it does not already exist, and handle errors appropriately.
    - Write the keypair as a JSON array of bytes to the file, handling errors for each write operation.
    - Close the file and log a success message.
    - Revert to the original user and group IDs.
    - Explicitly clear the keypair from memory for security reasons.
- **Output**: The function does not return a value but writes the generated keypair to the specified file and logs success or error messages.


---
### keys\_pubkey<!-- {{#callable:keys_pubkey}} -->
The `keys_pubkey` function loads a public key from a specified file and prints it in Base58 encoded format.
- **Inputs**:
    - `file_path`: A constant character pointer representing the path to the file from which the public key is to be loaded.
- **Control Flow**:
    - Call `fd_keyload_load` with `file_path` and `1` to load the public key from the specified file.
    - Declare a character array `pubkey_str` to hold the Base58 encoded public key.
    - Call `fd_base58_encode_32` to encode the loaded public key into Base58 format and store it in `pubkey_str`.
    - Log the Base58 encoded public key to standard output using `FD_LOG_STDOUT`.
- **Output**: The function does not return a value; it outputs the Base58 encoded public key to standard output.


---
### keys\_cmd\_fn<!-- {{#callable:keys_cmd_fn}} -->
The `keys_cmd_fn` function executes a command to either generate a new keypair or print a public key based on the command type specified in the arguments.
- **Inputs**:
    - `args`: A pointer to an `args_t` structure containing command type and file path information for key operations.
    - `config`: A pointer to a `config_t` structure containing user and group ID information for file operations.
- **Control Flow**:
    - Check if the command type in `args` is `CMD_NEW_KEY` using `FD_LIKELY` macro.
    - If true, call [`generate_keypair`](#FD_FN_SENSITIVEgenerate_keypair) with the file path from `args`, and user and group IDs from `config`.
    - If the command type is `CMD_PUBKEY`, call [`keys_pubkey`](#keys_pubkey) with the file path from `args`.
    - If the command type is neither `CMD_NEW_KEY` nor `CMD_PUBKEY`, log an error indicating an unknown key type.
- **Output**: The function does not return a value; it performs actions based on the command type, such as generating a keypair or printing a public key, and logs errors if the command type is unknown.
- **Functions called**:
    - [`FD_FN_SENSITIVE::generate_keypair`](#FD_FN_SENSITIVEgenerate_keypair)
    - [`keys_pubkey`](#keys_pubkey)



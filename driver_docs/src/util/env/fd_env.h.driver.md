# Purpose
This C header file, `fd_env.h`, provides a set of APIs designed to facilitate the extraction and manipulation of environment variables and command-line arguments within a program. The primary functionality revolves around searching for key-value pairs in both the environment and command-line arguments, converting the values to various data types, and returning the last found value. If no such value is found, a default value is returned. The file defines a macro, `FD_ENV_STRIP_CMDLINE_DECL`, which is used to declare functions for different data types, such as `char`, `int`, `ulong`, and `float`, among others. These functions are designed to modularize command-line parsing, allowing independently developed code units to handle command-line arguments without conflict.

Additionally, the file includes a function, [`fd_env_strip_cmdline_contains`](#fd_env_strip_cmdline_contains), which checks for the presence of a specific key in the command-line arguments and removes it if found. This functionality is crucial for managing command-line arguments in a modular and conflict-free manner. The header file is intended to be included in other C source files, providing a consistent interface for environment and command-line argument handling. It does not define a public API for external use but rather serves as an internal utility for programs that require robust environment and command-line parsing capabilities. The file also includes conditional compilation directives to handle environments that may not support POSIX-like features, ensuring broader compatibility.
# Imports and Dependencies

---
- `../cstr/fd_cstr.h`


# Function Declarations (Public API)

---
### fd\_env\_strip\_cmdline\_contains<!-- {{#callable_declaration:fd_env_strip_cmdline_contains}} -->
Removes a specified key from command line arguments if present.
- **Description**: Use this function to check for the presence of a specific key in the command line arguments and remove it if found. This is useful for modular command line parsing, allowing different parts of a program to handle specific arguments independently. The function should be called with valid pointers to the argument count and argument vector, as well as a non-null key to search for. If any of these pointers are null, the function will not perform any operations.
- **Inputs**:
    - `pargc`: A pointer to an integer representing the number of command line arguments. Must not be null. The value is updated to reflect the new argument count after any removals.
    - `pargv`: A pointer to an array of strings representing the command line arguments. Must not be null. The array is modified in place to remove the specified key, and is null-terminated after modification.
    - `key`: A constant string representing the key to search for in the command line arguments. Must not be null. If the key is found, it is removed from the arguments.
- **Output**: Returns 1 if the key was found and removed from the command line arguments, otherwise returns 0.
- **See also**: [`fd_env_strip_cmdline_contains`](fd_env.c.driver.md#fd_env_strip_cmdline_contains)  (Implementation)



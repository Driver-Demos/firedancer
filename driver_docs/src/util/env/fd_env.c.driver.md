# Purpose
This C source code file provides functionality for processing command-line arguments and environment variables in a POSIX-compliant environment. It defines a macro-based implementation to strip specific command-line arguments and retrieve their values, which can be specified by a key. The code is structured to handle different data types, such as strings, integers, and floating-point numbers, by using a macro `FD_ENV_STRIP_CMDLINE_IMPL` that generates functions for each type. This allows for flexible and type-safe retrieval of command-line argument values or environment variable values, converting them to the appropriate type using helper functions like `fd_cstr_to_##what`.

The file is designed to be included in other C programs, as indicated by the use of include guards and conditional compilation directives. It checks for a specific environment style (`FD_ENV_STYLE`) and defaults to a POSIX style if the host is a hosted environment. The code also includes a function [`fd_env_strip_cmdline_contains`](#fd_env_strip_cmdline_contains) to check for the presence of a specific command-line argument and remove it from the argument list. This file does not define a public API or external interfaces directly but provides utility functions that can be used internally within a larger application to manage command-line and environment configurations efficiently.
# Imports and Dependencies

---
- `fd_env.h`
- `stdlib.h`


# Functions

---
### fd\_env\_strip\_cmdline\_contains<!-- {{#callable:fd_env_strip_cmdline_contains}} -->
The function `fd_env_strip_cmdline_contains` removes occurrences of a specified key from the command-line arguments and returns whether the key was found.
- **Inputs**:
    - `pargc`: A pointer to an integer representing the number of command-line arguments.
    - `pargv`: A pointer to an array of strings representing the command-line arguments.
    - `key`: A constant string representing the key to be removed from the command-line arguments.
- **Control Flow**:
    - Initialize `new_argc` to 0 and `found` to 0.
    - Check if `key`, `pargc`, and `pargv` are not NULL.
    - Iterate over each argument in `*pargv` using a for loop.
    - If the current argument does not match `key`, copy it to the new position in `*pargv` and increment `new_argc`.
    - If the current argument matches `key`, set `found` to 1.
    - After the loop, update `*pargc` to `new_argc` and set `(*pargv)[new_argc]` to NULL to terminate the array.
    - Return the value of `found` indicating if the key was found.
- **Output**: An integer indicating whether the key was found in the command-line arguments (1 if found, 0 otherwise).



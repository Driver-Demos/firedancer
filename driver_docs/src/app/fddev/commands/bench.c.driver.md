# Purpose
This C source code file defines a function [`fddev_bench_cmd_fn`](#fddev_bench_cmd_fn) that is responsible for executing a benchmark command within a multi-threaded environment. It includes necessary headers for threading and command functionalities, and it utilizes the `pthread` library to create a new thread that runs the [`agave_thread_main`](#agave_thread_main) function. This function, in turn, calls [`agave_boot`](#agave_boot), which is expected to run indefinitely, as indicated by the comment stating that Agave will never exit. The main thread is put to sleep indefinitely, allowing the program to be terminated via an external interrupt like Ctrl+C. Additionally, the file defines an `action_t` structure `fd_action_bench`, which encapsulates metadata and function pointers related to the benchmark command, including its name, arguments, and permissions, indicating its role in testing validator transactions per second (TPS) benchmarks.
# Imports and Dependencies

---
- `../../shared_dev/commands/bench/bench.h`
- `../../shared_dev/commands/dev.h`
- `unistd.h`
- `pthread.h`


# Global Variables

---
### fd\_action\_bench
- **Type**: `action_t`
- **Description**: The `fd_action_bench` is a global variable of type `action_t` that represents a specific action configuration for a command named 'bench'. It includes various fields such as the name of the action, arguments, function pointer, permissions, a flag indicating if it is for a local cluster, and a description of the action.
- **Use**: This variable is used to define and configure the 'bench' command action, which is likely part of a command-line interface or a similar system for testing validator TPS benchmarks.


# Functions

---
### agave\_thread\_main<!-- {{#callable:agave_thread_main}} -->
The `agave_thread_main` function initializes a thread by calling [`agave_boot`](../../fdctl/commands/run_agave.c.driver.md#agave_boot) with a configuration and logs an error if [`agave_boot`](../../fdctl/commands/run_agave.c.driver.md#agave_boot) exits.
- **Inputs**:
    - `_args`: A pointer to a `config_t` structure that contains configuration data for the [`agave_boot`](../../fdctl/commands/run_agave.c.driver.md#agave_boot) function.
- **Control Flow**:
    - The function casts the `_args` parameter to a `config_t` pointer named `config`.
    - It calls the [`agave_boot`](../../fdctl/commands/run_agave.c.driver.md#agave_boot) function with the `config` pointer.
    - If [`agave_boot`](../../fdctl/commands/run_agave.c.driver.md#agave_boot) exits, it logs an error message using `FD_LOG_ERR`.
    - The function returns `NULL` after logging the error.
- **Output**: The function returns `NULL` after logging an error message if [`agave_boot`](../../fdctl/commands/run_agave.c.driver.md#agave_boot) exits.
- **Functions called**:
    - [`agave_boot`](../../fdctl/commands/run_agave.c.driver.md#agave_boot)


---
### fddev\_bench\_cmd\_fn<!-- {{#callable:fddev_bench_cmd_fn}} -->
The `fddev_bench_cmd_fn` function initiates a benchmark command and starts a separate thread to run the `agave_thread_main` function, then puts the main thread to sleep indefinitely.
- **Inputs**:
    - `args`: A pointer to an `args_t` structure containing command-line arguments for the benchmark command.
    - `config`: A pointer to a `config_t` structure containing configuration settings for the benchmark and agave thread.
- **Control Flow**:
    - Call the `bench_cmd_fn` function with `args` and `config` to execute the benchmark command.
    - Create a new thread named `agave` that runs the `agave_thread_main` function, passing `config` as an argument.
    - Enter an infinite loop where the main thread pauses indefinitely, effectively sleeping until interrupted by a signal such as Ctrl+C.
- **Output**: This function does not return any value as it is a `void` function.


# Function Declarations (Public API)

---
### agave\_boot<!-- {{#callable_declaration:agave_boot}} -->
Boots the Agave validator with the specified configuration.
- **Description**: This function initializes and starts the Agave validator using the provided configuration settings. It constructs command-line arguments based on the configuration and sets environment variables as needed. The function must be called with a valid configuration structure, and it assumes that the configuration is fully populated with all necessary parameters. It does not return, as it ultimately calls a function that exits the process on failure. This function should be used when you need to start the Agave validator with specific settings defined in a configuration object.
- **Inputs**:
    - `config`: A pointer to a constant `config_t` structure containing the configuration settings for the Agave validator. The structure must be fully populated with valid data, as the function does not perform deep validation of the configuration contents. The caller retains ownership of the configuration object, and it must not be null.
- **Output**: None
- **See also**: [`agave_boot`](../../fdctl/commands/run_agave.c.driver.md#agave_boot)  (Implementation)



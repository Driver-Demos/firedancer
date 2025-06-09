# Purpose
This C source code file defines a command function for a benchmarking tool within a development environment. It includes headers for shared development commands and the standard `unistd.h` for POSIX API access. The function [`firedancer_dev_bench_cmd_fn`](#firedancer_dev_bench_cmd_fn) is designed to execute a benchmark command using `bench_cmd_fn` and then enters an infinite loop to keep the parent thread active, allowing termination via an external interrupt like Ctrl+C. Additionally, the file defines an `action_t` structure, `fd_action_bench`, which encapsulates metadata and function pointers for the "bench" command, including its name, arguments, permissions, and a description indicating its purpose to test validator transactions per second (TPS) benchmarks.
# Imports and Dependencies

---
- `../../shared_dev/commands/bench/bench.h`
- `../../shared_dev/commands/dev.h`
- `unistd.h`


# Global Variables

---
### fd\_action\_bench
- **Type**: `action_t`
- **Description**: The `fd_action_bench` is a global variable of type `action_t` that represents a specific action configuration for a command named 'bench'. It includes various fields such as the name of the action, arguments, a function pointer to execute the action, permissions, a flag indicating if it is for a local cluster, and a description of the action.
- **Use**: This variable is used to define and configure the 'bench' command action, which is likely part of a command-line interface or application framework.


# Functions

---
### firedancer\_dev\_bench\_cmd\_fn<!-- {{#callable:firedancer_dev_bench_cmd_fn}} -->
The `firedancer_dev_bench_cmd_fn` function executes a benchmark command and then puts the parent thread to sleep indefinitely until interrupted.
- **Inputs**:
    - `args`: A pointer to an `args_t` structure containing command-line arguments for the benchmark command.
    - `config`: A pointer to a `config_t` structure containing configuration settings for the benchmark command.
- **Control Flow**:
    - Call the `bench_cmd_fn` function with `args` and `config` to execute the benchmark command.
    - Enter an infinite loop where the `pause()` function is called to put the parent thread to sleep indefinitely.
- **Output**: This function does not return any value; it runs indefinitely until interrupted by an external signal such as Ctrl+C.



# Purpose
This C header file defines the interface for a benchmarking module within a larger application, likely related to network or distributed system performance testing. It includes function prototypes for [`bench_cmd_fn`](#bench_cmd_fn) and [`bench_cmd_args`](#bench_cmd_args), which are presumably used to execute a benchmark command and handle its arguments, respectively. Additionally, the [`add_bench_topo`](#add_bench_topo) function is declared, which appears to configure a benchmarking topology with various parameters such as tile counts, transaction modes, and network settings. The file includes other headers for configuration and action handling, indicating its integration into a broader system. The use of include guards ensures that the header is only included once, preventing redefinition errors during compilation.
# Imports and Dependencies

---
- `../../../shared/fd_config.h`
- `../../../shared/fd_action.h`


# Function Declarations (Public API)

---
### bench\_cmd\_fn<!-- {{#callable_declaration:bench_cmd_fn}} -->
Configures and initializes the benchmarking environment.
- **Description**: This function sets up the necessary configuration and initializes the environment for running benchmarks. It should be called with valid configuration and argument structures to ensure proper setup. The function adjusts network settings, CPU affinity, and other parameters based on the provided configuration. It also performs necessary checks to ensure consistency in CPU affinity settings across different components. This function must be called before executing any benchmarking tasks to ensure the environment is correctly configured.
- **Inputs**:
    - `args`: A pointer to an `args_t` structure containing command-line arguments and options. The structure must be properly initialized and must not be null. The function uses this to determine specific configuration options, such as whether QUIC is disabled.
    - `config`: A pointer to a `config_t` structure containing the configuration settings for the benchmarking environment. This structure must be fully initialized and must not be null. The function modifies this configuration to set up the environment, including network and CPU affinity settings.
- **Output**: None
- **See also**: [`bench_cmd_fn`](bench.c.driver.md#bench_cmd_fn)  (Implementation)


---
### bench\_cmd\_args<!-- {{#callable_declaration:bench_cmd_args}} -->
Parses command-line arguments to configure benchmark settings.
- **Description**: This function processes command-line arguments to adjust the benchmark configuration, specifically checking for the presence of the '--no-quic' flag. It should be called during the initialization phase of a benchmark application to modify the behavior of the benchmark based on user-specified command-line options. The function updates the 'args' structure to reflect the presence of the '--no-quic' flag, which disables QUIC protocol usage in the benchmark. It is important to ensure that 'pargc' and 'pargv' are correctly initialized with the command-line argument count and values, respectively, before calling this function.
- **Inputs**:
    - `pargc`: A pointer to an integer representing the count of command-line arguments. It must not be null and should be initialized with the number of arguments passed to the program.
    - `pargv`: A pointer to an array of strings representing the command-line arguments. It must not be null and should be initialized with the argument values passed to the program.
    - `args`: A pointer to an 'args_t' structure where the parsed command-line options will be stored. The caller retains ownership and it must be a valid pointer.
- **Output**: None
- **See also**: [`bench_cmd_args`](bench.c.driver.md#bench_cmd_args)  (Implementation)



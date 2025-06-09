## Folders
- **[generated](run/generated.driver.md)**: The `generated` folder in the `firedancer` codebase contains header files that define generated seccomp filter policies for restricting system calls based on architecture and specific conditions.

## Files
- **[main.seccomppolicy](run/main.seccomppolicy.driver.md)**: The `main.seccomppolicy` file defines the security policy for the boot process of Firedancer, which involves creating a PID namespace, supervising the child process, and handling logging and process termination.
- **[pidns.seccomppolicy](run/pidns.seccomppolicy.driver.md)**: The `pidns.seccomppolicy` file defines the security policy for the child process in a PID namespace responsible for launching and managing Firedancer tiles, including logging and process supervision.
- **[pidns_arm64.seccomppolicy](run/pidns_arm64.seccomppolicy.driver.md)**: The `pidns_arm64.seccomppolicy` file defines a seccomp policy for the child process in a PID namespace on arm64 architecture, ensuring proper logging and process termination behavior for the Firedancer application.
- **[run.c](run/run.c.driver.md)**: The `run.c` file in the `firedancer` codebase implements the functionality to start and manage a Firedancer validator, including setting up process namespaces, handling permissions, configuring network settings, and managing child processes for different components of the validator.
- **[run.h](run/run.h.driver.md)**: The `run.h` file in the `firedancer` codebase declares functions and actions related to configuring, initializing, and running the Firedancer application, including handling command arguments and network namespace setup.
- **[run1.c](run/run1.c.driver.md)**: The `run1.c` file in the `firedancer` codebase implements a command for running a specified tile with a given kind ID, handling command-line arguments, setting up the environment, and managing process creation and execution.

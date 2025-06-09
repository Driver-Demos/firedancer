# Purpose
This C header file, `fd_util.h`, serves as a central utility interface for a larger software system, providing essential services and configurations for logging, memory allocation, and thread management. It includes a variety of other headers, some of which are commented out, indicating modularity and potential for customization or deprecation. The file defines two primary functions, [`fd_boot`](#fd_boot) and [`fd_halt`](#fd_halt), which are responsible for initializing and shutting down the utility services, respectively. These functions are designed to be called at the start and end of a thread group's lifecycle, ensuring that all necessary resources and configurations are properly managed.

The file also outlines a comprehensive set of command-line and environment options for configuring logging behavior, such as log paths, deduplication, backtracing, and various identifiers for applications, threads, hosts, and users. These options allow for detailed customization of the logging process, including the ability to specify log levels and colorization. Additionally, the file provides options for shared memory paths and CPU allocation for thread groups, which are crucial for optimizing performance in multi-threaded applications. Overall, `fd_util.h` acts as a foundational component, facilitating the integration and management of various utility services within the software system.
# Imports and Dependencies

---
- `rng/fd_rng.h`
- `spad/fd_spad.h`
- `alloc/fd_alloc.h`
- `sandbox/fd_sandbox.h`
- `bits/fd_sat.h`


# Function Declarations (Public API)

---
### fd\_boot<!-- {{#callable_declaration:fd_boot}} -->
Boots all fd_util services for the application.
- **Description**: This function should be called once immediately after the main thread in a thread group starts to initialize all fd_util services. It prepares the environment for the application by processing command line and environment options related to logging, shared memory, and thread management. This function must be called before any other fd_util services are used to ensure proper setup. It modifies the command line arguments to remove any options it processes.
- **Inputs**:
    - `pargc`: A pointer to the argument count, typically passed from the main function. It must not be null, and the value it points to will be modified to reflect any changes in the argument list.
    - `pargv`: A pointer to the argument vector, typically passed from the main function. It must not be null, and the array it points to will be modified to remove any processed options.
- **Output**: None
- **See also**: [`fd_boot`](fd_util.c.driver.md#fd_boot)  (Implementation)


---
### fd\_halt<!-- {{#callable_declaration:fd_halt}} -->
Halts all fd_util services before program termination.
- **Description**: This function should be called explicitly once immediately before the normal shutdown of a thread group to halt all fd_util services. It is intended to be used in conjunction with fd_boot, which initializes these services. This function ensures that all resources and services are properly terminated, preventing potential resource leaks or undefined behavior during program termination. It must be called after fd_boot has been successfully executed.
- **Inputs**: None
- **Output**: None
- **See also**: [`fd_halt`](fd_util.c.driver.md#fd_halt)  (Implementation)



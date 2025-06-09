# Purpose
This C source code file provides functionality for managing CPU affinity for processes, specifically targeting systems running the Linux operating system. The file defines two primary functions: [`fd_cpuset_getaffinity`](#fd_cpuset_getaffinity) and [`fd_cpuset_setaffinity`](#fd_cpuset_setaffinity). These functions are designed to retrieve and set the CPU affinity of a process, respectively. CPU affinity determines which CPU cores a process is allowed to execute on, which can be crucial for optimizing performance and resource management in multi-core systems. The code uses conditional compilation to ensure that these functions are only operational on Linux systems, as indicated by the `#if defined(__linux__)` preprocessor directive. If the code is compiled on a non-Linux system, the functions will return an error, setting `errno` to `ENOTSUP` to indicate that the operation is not supported.

The technical components of the code include the use of the `sched_getaffinity` and `sched_setaffinity` system calls, which are part of the GNU C Library and provide the underlying functionality for CPU affinity management. The code also includes a custom type, `fd_cpuset_t`, which is presumably defined in the included header file "fd_tile_private.h". This type is used to represent the CPU set mask, and the code employs type punning to convert between this custom type and the standard `cpu_set_t` type used by the system calls. The file is likely part of a larger library or application that deals with process management or system resource allocation, and it provides a narrow, specialized functionality focused on CPU affinity.
# Imports and Dependencies

---
- `errno.h`
- `sched.h`
- `fd_tile_private.h`


# Functions

---
### fd\_cpuset\_getaffinity<!-- {{#callable:fd_cpuset_getaffinity}} -->
The `fd_cpuset_getaffinity` function retrieves the CPU affinity mask for a given process ID on Linux systems.
- **Inputs**:
    - `pid`: The process ID (PID) for which the CPU affinity mask is to be retrieved.
    - `mask`: A pointer to an `fd_cpuset_t` structure where the CPU affinity mask will be stored.
- **Control Flow**:
    - Check if the code is being compiled on a Linux system using the `__linux__` preprocessor directive.
    - If on Linux, call `sched_getaffinity` with the given PID, size of the CPU set, and a type-punned pointer to the mask to retrieve the CPU affinity.
    - If not on Linux, set the `errno` to `ENOTSUP` to indicate the operation is not supported and return -1.
- **Output**: On Linux, it returns the result of `sched_getaffinity`, which is 0 on success and -1 on failure; on non-Linux systems, it returns -1 and sets `errno` to `ENOTSUP`.


---
### fd\_cpuset\_setaffinity<!-- {{#callable:fd_cpuset_setaffinity}} -->
The `fd_cpuset_setaffinity` function sets the CPU affinity mask for a given process ID on Linux systems.
- **Inputs**:
    - `pid`: The process ID (PID) of the process for which the CPU affinity is to be set.
    - `mask`: A pointer to a `fd_cpuset_t` structure that represents the CPU affinity mask to be applied.
- **Control Flow**:
    - The function checks if the code is being compiled on a Linux system using the `__linux__` preprocessor directive.
    - If on Linux, it calls `sched_setaffinity` with the given PID, the size of the CPU set, and the CPU set mask, after casting the mask to a `cpu_set_t` type using `fd_type_pun_const`.
    - If not on Linux, it sets the `errno` to `ENOTSUP` to indicate that the operation is not supported and returns -1.
- **Output**: On Linux, it returns the result of `sched_setaffinity`, which is 0 on success and -1 on failure; on non-Linux systems, it returns -1 and sets `errno` to `ENOTSUP`.



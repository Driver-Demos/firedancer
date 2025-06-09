# Purpose
This C header file, `fd_tile_private.h`, is designed for internal use within the `fd_tile` module, providing a custom implementation of CPU set management to address limitations and issues with the standard `cpu_set_t` API, particularly in environments using musl libc. The file defines `fd_cpuset_t`, a replacement for `cpu_set_t`, and includes macros and functions to manage CPU affinity in a more stable and reliable manner. The primary functionality revolves around defining and manipulating CPU sets, with macros like `FD_CPUSET_DECL` for declaring CPU sets and functions such as [`fd_cpuset_getaffinity`](#fd_cpuset_getaffinity) and [`fd_cpuset_setaffinity`](#fd_cpuset_setaffinity) for wrapping the standard `sched_getaffinity` and `sched_setaffinity` functions. These functions are intended to handle type-punning issues and ensure compatibility with the internal workings of `fd_tile`.

The file also includes internal utility functions like [`fd_tile_private_stack_new`](#fd_tile_private_stack_new) and [`fd_tile_private_cpus_parse`](#fd_tile_private_cpus_parse), which are used for managing stack allocation and parsing CPU configurations, respectively. The header is not intended for public API exposure but rather serves as a private utility to enhance the robustness and performance of CPU affinity management within the `fd_tile` module. The inclusion of `fd_set.c` through a template mechanism suggests a modular approach to handling sets, allowing for flexibility and reuse of set-related operations. Overall, this file provides specialized, low-level functionality crucial for optimizing CPU resource management in the context of the `fd_tile` system.
# Imports and Dependencies

---
- `fd_tile.h`
- `../tmpl/fd_set.c`


# Global Variables

---
### fd\_tile\_private\_stack\_new
- **Type**: `function pointer`
- **Description**: `fd_tile_private_stack_new` is a function that returns a pointer to a newly allocated stack for a tile, which is a component of the fd_tile system. It takes two parameters: an integer `optimize` and an unsigned long `cpu_idx`, which likely influence the stack's configuration or allocation based on optimization needs and CPU index.
- **Use**: This function is used internally within the fd_tile system to allocate a new stack for a tile, potentially optimizing for specific CPU indices.


# Function Declarations (Public API)

---
### fd\_cpuset\_getaffinity<!-- {{#callable_declaration:fd_cpuset_getaffinity}} -->
Retrieve the CPU affinity mask for a specified thread.
- **Description**: This function retrieves the CPU affinity mask for the thread specified by `tid` and stores it in the provided `mask`. It is intended for internal use within the fd_tile module to address type-punning issues with the standard CPU affinity APIs. The function should be called when you need to determine the CPU affinity of a thread, particularly when working within the fd_tile context. Note that if the number of host CPUs exceeds FD_TILE_MAX, the CPU set will be silently truncated. This function is not supported on non-Linux platforms, where it will return an error.
- **Inputs**:
    - `tid`: The thread ID for which to get the CPU affinity. A value of 0 implies the current thread. Must be a valid thread ID.
    - `mask`: A pointer to an fd_cpuset_t where the CPU affinity mask will be stored. Must not be null, and the caller is responsible for ensuring it is properly declared using FD_CPUSET_DECL.
- **Output**: Returns 0 on success. On non-Linux platforms, or if an error occurs, returns -1 and sets errno to indicate the error.
- **See also**: [`fd_cpuset_getaffinity`](fd_tile.c.driver.md#fd_cpuset_getaffinity)  (Implementation)


---
### fd\_cpuset\_setaffinity<!-- {{#callable_declaration:fd_cpuset_setaffinity}} -->
Set the CPU affinity for a specified thread.
- **Description**: This function sets the CPU affinity for a thread identified by the given thread ID, allowing the thread to run on a specified set of CPUs. It is intended for internal use within the fd_tile module and should be used to address type-punning issues with the standard CPU affinity APIs. The function should be called with a valid thread ID and a properly initialized CPU set mask. On non-Linux systems, the function will return an error indicating that the operation is not supported.
- **Inputs**:
    - `tid`: The thread ID for which the CPU affinity is to be set. A value of 0 implies the current thread. Must be a valid thread ID.
    - `mask`: A pointer to an fd_cpuset_t structure that specifies the CPUs on which the thread is allowed to run. Must not be null and should be properly initialized using FD_CPUSET_DECL.
- **Output**: Returns 0 on success. On failure, returns -1 and sets errno to indicate the error. On non-Linux systems, returns -1 and sets errno to ENOTSUP.
- **See also**: [`fd_cpuset_setaffinity`](fd_tile.c.driver.md#fd_cpuset_setaffinity)  (Implementation)


---
### fd\_tile\_private\_stack\_new<!-- {{#callable_declaration:fd_tile_private_stack_new}} -->
Creates a new stack optimized for NUMA and TLB if requested.
- **Description**: This function allocates a new stack, optionally optimized for NUMA and TLB, for a tile running on a specified CPU. It should be used when a stack with specific memory locality and performance characteristics is needed. The function attempts to allocate a huge page-backed stack if optimization is requested, falling back to a normal page-backed stack if huge page allocation fails. If optimization is not requested, a normal page-backed stack is allocated directly. The function also sets up guard regions to protect against stack overflows. It is important to note that this function is intended for internal use within the fd_tile module.
- **Inputs**:
    - `optimize`: An integer flag indicating whether to optimize the stack for NUMA and TLB. A non-zero value requests optimization, while zero skips it.
    - `cpu_idx`: An unsigned long specifying the CPU index for which the stack is being created. This is used to determine the NUMA node for optimization purposes if requested.
- **Output**: Returns a pointer to the newly allocated stack, or NULL if the allocation fails.
- **See also**: [`fd_tile_private_stack_new`](fd_tile_threads.cxx.driver.md#fd_tile_private_stack_new)  (Implementation)


---
### fd\_tile\_private\_cpus\_parse<!-- {{#callable_declaration:fd_tile_private_cpus_parse}} -->
Parses a CPU configuration string into a tile-to-CPU mapping.
- **Description**: This function is used to parse a string that specifies CPU configurations for tiles and populate an array with the corresponding CPU indices. It is designed to handle configurations where tiles are either assigned specific CPUs or are set to float on the original core set. The function processes the input string, which may include ranges and strides, and fills the provided array with the parsed CPU indices. It returns the number of CPUs parsed. The function expects a valid, non-null string and an adequately sized array to store the results. It will return zero if the input string is null. The function is intended for internal use within the fd_tile module and assumes that the caller handles any potential errors or malformed input strings.
- **Inputs**:
    - `cstr`: A constant character pointer to the input string specifying the CPU configuration. It must not be null, as a null input will result in a return value of zero.
    - `tile_to_cpu`: A pointer to an array of unsigned short integers where the parsed CPU indices will be stored. The array should be large enough to hold all the parsed indices, up to a maximum defined by FD_TILE_MAX.
- **Output**: Returns the number of CPUs successfully parsed from the input string. If the input string is null, it returns zero.
- **See also**: [`fd_tile_private_cpus_parse`](fd_tile_threads.cxx.driver.md#fd_tile_private_cpus_parse)  (Implementation)



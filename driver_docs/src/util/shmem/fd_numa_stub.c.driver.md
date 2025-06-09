# Purpose
This C source code file provides a set of functions related to Non-Uniform Memory Access (NUMA) operations, but it is specifically designed for a build target that does not support NUMA. Each function in the file is a placeholder that logs a warning message indicating the lack of NUMA support and returns a default error value. The functions include operations for counting NUMA nodes and CPUs, locking and unlocking memory, getting and setting memory policies, binding memory, and moving pages. These functions are intended to be part of a broader system that would normally handle NUMA-related tasks, but in this context, they serve as stubs to ensure that the code can compile and run without NUMA support.

The file includes a private header, "fd_shmem_private.h," suggesting that it is part of a larger library or application dealing with shared memory or similar low-level operations. The functions return standard error codes and set the `errno` variable to `EINVAL` (Invalid Argument) to indicate that the operations are not supported. This approach allows the rest of the application to handle these functions gracefully, even when NUMA is not available. The file does not define public APIs or external interfaces but rather provides internal functionality that can be conditionally compiled based on the target environment's capabilities.
# Imports and Dependencies

---
- `fd_shmem_private.h`
- `errno.h`


# Functions

---
### fd\_numa\_node\_cnt<!-- {{#callable:fd_numa_node_cnt}} -->
The `fd_numa_node_cnt` function logs a warning about the lack of NUMA support and returns zero.
- **Inputs**: None
- **Control Flow**:
    - Logs a warning message indicating that there is no NUMA support for the current build target.
    - Returns the value 0UL, indicating that no NUMA nodes are available.
- **Output**: The function returns an unsigned long integer value of 0, representing the count of NUMA nodes, which is zero due to lack of support.


---
### fd\_numa\_cpu\_cnt<!-- {{#callable:fd_numa_cpu_cnt}} -->
The `fd_numa_cpu_cnt` function logs a warning about the lack of NUMA support and returns zero.
- **Inputs**: None
- **Control Flow**:
    - Logs a warning message indicating that there is no NUMA support for the current build target.
    - Returns the value 0UL, indicating that no CPUs are counted due to the lack of NUMA support.
- **Output**: The function returns an unsigned long integer value of 0, representing the count of CPUs, which is zero due to the absence of NUMA support.


---
### fd\_numa\_node\_idx<!-- {{#callable:fd_numa_node_idx}} -->
The `fd_numa_node_idx` function logs a warning about the lack of NUMA support and returns the maximum unsigned long value.
- **Inputs**:
    - `cpu_idx`: An unsigned long integer representing the CPU index, which is not used in the function.
- **Control Flow**:
    - The function takes an input parameter `cpu_idx` but does not use it, as indicated by the cast to void.
    - A warning message is logged stating that there is no NUMA support for the current build target.
    - The function returns `ULONG_MAX`, which is the maximum value for an unsigned long integer, indicating an error or unsupported operation.
- **Output**: The function returns `ULONG_MAX`, which is typically used to indicate an error or unsupported operation in this context.


---
### fd\_numa\_mlock<!-- {{#callable:fd_numa_mlock}} -->
The `fd_numa_mlock` function attempts to lock a memory range in RAM but logs a warning and returns an error due to lack of NUMA support.
- **Inputs**:
    - `addr`: A pointer to the starting address of the memory range to be locked.
    - `len`: The length in bytes of the memory range to be locked.
- **Control Flow**:
    - The function begins by casting the input parameters `addr` and `len` to void to indicate they are unused.
    - A warning message is logged stating that there is no NUMA support for the build target.
    - The global variable `errno` is set to `EINVAL` to indicate an invalid argument error.
    - The function returns -1 to signal failure.
- **Output**: The function returns -1 to indicate failure, and sets `errno` to `EINVAL`.


---
### fd\_numa\_munlock<!-- {{#callable:fd_numa_munlock}} -->
The `fd_numa_munlock` function attempts to unlock a memory region from NUMA policy but always fails due to lack of NUMA support in the build target.
- **Inputs**:
    - `addr`: A pointer to the starting address of the memory region to be unlocked.
    - `len`: The length of the memory region to be unlocked, in bytes.
- **Control Flow**:
    - The function takes two parameters, `addr` and `len`, but does not use them due to lack of NUMA support.
    - A warning message is logged indicating that NUMA support is not available for the build target.
    - The global variable `errno` is set to `EINVAL` to indicate an invalid argument error.
    - The function returns `-1` to signal failure.
- **Output**: The function returns `-1` to indicate failure and sets `errno` to `EINVAL`.


---
### fd\_numa\_get\_mempolicy<!-- {{#callable:fd_numa_get_mempolicy}} -->
The `fd_numa_get_mempolicy` function is a placeholder that logs a warning about the lack of NUMA support and returns an error.
- **Inputs**:
    - `mode`: A pointer to an integer where the memory policy mode would be stored.
    - `nodemask`: A pointer to an unsigned long where the node mask would be stored.
    - `maxnode`: An unsigned long representing the maximum number of nodes.
    - `addr`: A pointer to a memory address, typically used to determine the policy for a specific address.
    - `flags`: An unsigned integer representing flags that modify the behavior of the function.
- **Control Flow**:
    - All input parameters are cast to void to indicate they are unused.
    - A warning is logged stating that there is no NUMA support for the build target.
    - The global variable `errno` is set to `EINVAL` to indicate an invalid argument error.
    - The function returns -1L to signal an error.
- **Output**: The function returns -1L to indicate an error due to lack of NUMA support.


---
### fd\_numa\_set\_mempolicy<!-- {{#callable:fd_numa_set_mempolicy}} -->
The `fd_numa_set_mempolicy` function attempts to set the NUMA memory policy but always fails due to lack of NUMA support in the build target.
- **Inputs**:
    - `mode`: An integer representing the desired NUMA memory policy mode.
    - `nodemask`: A pointer to an array of unsigned long integers representing the nodes to which the policy applies.
    - `maxnode`: An unsigned long integer indicating the maximum node number plus one.
- **Control Flow**:
    - The function begins by explicitly ignoring the input parameters using the `(void)` cast to suppress unused variable warnings.
    - A warning message is logged indicating that there is no NUMA support for the current build target.
    - The `errno` is set to `EINVAL` to indicate an invalid argument error.
    - The function returns `-1L` to signal failure.
- **Output**: The function returns a long integer value of `-1L` to indicate failure, and sets `errno` to `EINVAL`.


---
### fd\_numa\_mbind<!-- {{#callable:fd_numa_mbind}} -->
The `fd_numa_mbind` function is a placeholder for NUMA memory binding that logs a warning and returns an error due to lack of NUMA support.
- **Inputs**:
    - `addr`: A pointer to the starting address of the memory range to bind.
    - `len`: The length of the memory range to bind.
    - `mode`: The memory binding mode to apply.
    - `nodemask`: A pointer to a nodemask specifying the NUMA nodes to bind the memory to.
    - `maxnode`: The maximum node number plus one in the nodemask.
    - `flags`: Flags to modify the behavior of the memory binding.
- **Control Flow**:
    - All input parameters are cast to void to indicate they are unused.
    - A warning message is logged indicating no NUMA support for the build target.
    - The global variable `errno` is set to `EINVAL` to indicate an invalid argument error.
    - The function returns -1L to signal failure.
- **Output**: The function returns -1L to indicate failure due to lack of NUMA support.


---
### fd\_numa\_move\_pages<!-- {{#callable:fd_numa_move_pages}} -->
The `fd_numa_move_pages` function is a placeholder that logs a warning about the lack of NUMA support and returns an error.
- **Inputs**:
    - `pid`: The process ID for which the pages are to be moved.
    - `count`: The number of pages to be moved.
    - `pages`: An array of pointers to the pages to be moved.
    - `nodes`: An array of node IDs where the pages should be moved.
    - `status`: An array to store the status of each page after the move attempt.
    - `flags`: Flags to modify the behavior of the page move operation.
- **Control Flow**:
    - All input parameters are cast to void to indicate they are unused.
    - A warning is logged stating that there is no NUMA support for the build target.
    - The global variable `errno` is set to `EINVAL` to indicate an invalid argument error.
    - The function returns -1L to signal failure.
- **Output**: The function returns -1L to indicate failure due to lack of NUMA support.



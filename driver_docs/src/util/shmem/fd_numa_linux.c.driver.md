# Purpose
This C source code file provides a set of functions for interacting with the Non-Uniform Memory Access (NUMA) configuration of a Linux system. The code is designed to parse and manage NUMA node indices, count the number of NUMA nodes and CPUs, and perform memory locking and policy operations using system calls. The file includes functions such as [`fd_numa_node_cnt`](#fd_numa_node_cnt), [`fd_numa_cpu_cnt`](#fd_numa_cpu_cnt), and [`fd_numa_node_idx`](#fd_numa_node_idx) to retrieve the number of NUMA nodes, the number of CPUs, and the NUMA node index for a given CPU, respectively. These functions utilize the sysfs interface to access system configuration details, ensuring compatibility with Linux systems that support NUMA.

Additionally, the file provides low-level interfaces to memory management functions using direct system calls, such as [`fd_numa_mlock`](#fd_numa_mlock), [`fd_numa_munlock`](#fd_numa_munlock), [`fd_numa_get_mempolicy`](#fd_numa_get_mempolicy), [`fd_numa_set_mempolicy`](#fd_numa_set_mempolicy), [`fd_numa_mbind`](#fd_numa_mbind), and [`fd_numa_move_pages`](#fd_numa_move_pages). These functions bypass the standard library's AddressSanitizer (ASan) interceptors to ensure that memory operations are performed directly, which is crucial for applications that require precise control over memory allocation and locking. The code is structured to handle potential errors gracefully, logging warnings when operations fail, and it includes considerations for future improvements, such as handling ASan compatibility and enhancing the parsing logic for sysfs paths.
# Imports and Dependencies

---
- `fd_shmem_private.h`
- `../sanitize/fd_msan.h`
- `errno.h`
- `dirent.h`
- `sys/sysinfo.h`
- `unistd.h`
- `sys/syscall.h`


# Functions

---
### fd\_numa\_private\_parse\_node\_idx<!-- {{#callable:fd_numa_private_parse_node_idx}} -->
The `fd_numa_private_parse_node_idx` function parses a string of the form 'node[0-9]+' to extract a non-negative integer index, returning -1 if parsing fails.
- **Inputs**:
    - `s`: A constant character pointer to a string that is expected to start with 'node' followed by a numeric index.
- **Control Flow**:
    - Check if the input string `s` is NULL; if so, return -1.
    - Check if the string starts with 'node'; if not, return -1.
    - Advance the pointer `s` past the 'node' prefix.
    - Initialize a long integer `val` to 0 to accumulate the numeric index.
    - Iterate over the characters in the string starting from `s` to parse the numeric index.
    - If a non-digit character is encountered, return -1.
    - Accumulate the numeric value by converting each character to its numeric value and adding it to `val`, multiplied by 10.
    - Check for overflow; if `val` exceeds `INT_MAX`, return -1.
    - If no digits were found after 'node', return -1.
    - Return the parsed integer value as an int.
- **Output**: Returns an integer representing the parsed node index, or -1 if the input is invalid or parsing fails.


---
### fd\_numa\_node\_cnt<!-- {{#callable:fd_numa_node_cnt}} -->
The `fd_numa_node_cnt` function counts the number of NUMA nodes available on the system by reading the directory entries in the sysfs path `/sys/devices/system/node`.
- **Inputs**: None
- **Control Flow**:
    - Open the directory at the path `/sys/devices/system/node` using `opendir`; if it fails, log a warning and return 0.
    - Initialize `node_idx_max` to `INT_MIN` to track the highest node index found.
    - Iterate over each directory entry using `readdir`; for each entry, parse the node index using [`fd_numa_private_parse_node_idx`](#fd_numa_private_parse_node_idx) and update `node_idx_max` with the maximum value found.
    - Close the directory using `closedir`; if it fails, log a warning but continue execution.
    - If no valid node index was found (`node_idx_max < 0`), log a warning and return 0.
    - Return the count of NUMA nodes as `node_idx_max + 1`.
- **Output**: The function returns an `ulong` representing the count of NUMA nodes found, or 0 if none are found or an error occurs.
- **Functions called**:
    - [`fd_numa_private_parse_node_idx`](#fd_numa_private_parse_node_idx)


---
### fd\_numa\_cpu\_cnt<!-- {{#callable:fd_numa_cpu_cnt}} -->
The `fd_numa_cpu_cnt` function returns the number of processors available on the system.
- **Inputs**: None
- **Control Flow**:
    - The function calls `get_nprocs()` to retrieve the number of processors configured by the operating system.
    - It checks if the returned value is less than or equal to zero, which is considered an unexpected result.
    - If the result is unexpected, it logs a warning message and returns 0.
    - If the result is valid, it casts the integer count to an unsigned long and returns it.
- **Output**: The function returns the number of processors as an unsigned long integer, or 0 if an error occurs.


---
### fd\_numa\_node\_idx<!-- {{#callable:fd_numa_node_idx}} -->
The `fd_numa_node_idx` function retrieves the NUMA node index associated with a given CPU index by examining the system's sysfs directory structure.
- **Inputs**:
    - `cpu_idx`: An unsigned long integer representing the index of the CPU for which the NUMA node index is to be determined.
- **Control Flow**:
    - Constructs a path to the sysfs directory for the specified CPU using `fd_cstr_printf`.
    - Attempts to open the directory at the constructed path using `opendir`; logs a warning and returns `ULONG_MAX` if it fails.
    - Iterates over the directory entries using `readdir`, searching for a symlink that indicates the NUMA node configuration.
    - Uses [`fd_numa_private_parse_node_idx`](#fd_numa_private_parse_node_idx) to parse the directory entry names to find a valid NUMA node index; breaks the loop if a valid index is found.
    - Closes the directory using `closedir`, logging a warning if it fails.
    - Checks if a valid NUMA node index was found; logs a warning and returns `ULONG_MAX` if not.
    - Returns the found NUMA node index as an unsigned long integer.
- **Output**: Returns the NUMA node index as an unsigned long integer associated with the specified CPU index, or `ULONG_MAX` if the index cannot be determined.
- **Functions called**:
    - [`fd_numa_private_parse_node_idx`](#fd_numa_private_parse_node_idx)


---
### fd\_numa\_mlock<!-- {{#callable:fd_numa_mlock}} -->
The `fd_numa_mlock` function locks a specified range of memory pages, preventing them from being swapped out to disk.
- **Inputs**:
    - `addr`: A pointer to the starting address of the memory region to be locked.
    - `len`: The length in bytes of the memory region to be locked.
- **Control Flow**:
    - The function directly calls the `syscall` function with `SYS_mlock`, passing the `addr` and `len` parameters.
    - The result of the `syscall` is cast to an `int` and returned.
- **Output**: The function returns an integer which is the result of the `mlock` system call, typically 0 on success or -1 on failure with `errno` set appropriately.


---
### fd\_numa\_munlock<!-- {{#callable:fd_numa_munlock}} -->
The `fd_numa_munlock` function attempts to unlock a specified range of memory pages, making them pageable again, using a system call.
- **Inputs**:
    - `addr`: A pointer to the starting address of the memory region to be unlocked.
    - `len`: The length in bytes of the memory region to be unlocked.
- **Control Flow**:
    - The function directly calls the `syscall` function with `SYS_mlock`, `addr`, and `len` as arguments.
    - The result of the `syscall` is cast to an `int` and returned.
- **Output**: The function returns an `int` which is the result of the `syscall`, indicating success or failure of the memory unlock operation.


---
### fd\_numa\_get\_mempolicy<!-- {{#callable:fd_numa_get_mempolicy}} -->
The `fd_numa_get_mempolicy` function retrieves the NUMA memory policy for a process or memory address and unpoisons the memory if successful.
- **Inputs**:
    - `mode`: A pointer to an integer where the current memory policy mode will be stored.
    - `nodemask`: A pointer to a bitmask representing the set of NUMA nodes, which will be filled with the current policy's nodemask.
    - `maxnode`: The maximum number of nodes that the nodemask can represent.
    - `addr`: A pointer to a memory address for which the policy is queried, or NULL to query the process's policy.
    - `flags`: Flags that modify the behavior of the syscall, such as MPOL_F_NODE or MPOL_F_ADDR.
- **Control Flow**:
    - Invoke the `syscall` function with `SYS_get_mempolicy` and the provided arguments to retrieve the memory policy.
    - Check if the syscall was successful (i.e., `rc == 0`).
    - If successful and `mode` is not NULL, call `fd_msan_unpoison` to unpoison the memory at `mode`.
    - If successful and `nodemask` is not NULL, call `fd_msan_unpoison` to unpoison the memory at `nodemask` with a size calculated based on `maxnode`.
    - Return the result of the syscall.
- **Output**: Returns a long integer which is the result of the `syscall` function, indicating success (0) or an error code.


---
### fd\_numa\_set\_mempolicy<!-- {{#callable:fd_numa_set_mempolicy}} -->
The `fd_numa_set_mempolicy` function sets the NUMA memory policy for the calling process using a system call.
- **Inputs**:
    - `mode`: An integer specifying the memory policy mode to be set.
    - `nodemask`: A pointer to an array of unsigned long integers representing the nodemask, which specifies the NUMA nodes to be used.
    - `maxnode`: An unsigned long integer indicating the maximum node number plus one that can be set in the nodemask.
- **Control Flow**:
    - The function directly calls the `syscall` function with `SYS_set_mempolicy` and the provided arguments `mode`, `nodemask`, and `maxnode`.
- **Output**: The function returns a long integer which is the result of the `syscall` function, indicating success or failure of setting the memory policy.


---
### fd\_numa\_mbind<!-- {{#callable:fd_numa_mbind}} -->
The `fd_numa_mbind` function binds a range of memory to a specific NUMA node or set of nodes using the `mbind` system call.
- **Inputs**:
    - `addr`: A pointer to the starting address of the memory range to be bound.
    - `len`: The length of the memory range to be bound, in bytes.
    - `mode`: An integer specifying the memory binding policy.
    - `nodemask`: A pointer to a bitmask specifying the NUMA nodes to which the memory should be bound.
    - `maxnode`: The maximum node number plus one, indicating the size of the nodemask.
    - `flags`: Flags that modify the behavior of the `mbind` system call.
- **Control Flow**:
    - The function directly calls the `syscall` function with `SYS_mbind` and the provided arguments to perform the memory binding operation.
- **Output**: The function returns a `long` value which is the result of the `mbind` system call, typically 0 on success or -1 on failure with `errno` set appropriately.


---
### fd\_numa\_move\_pages<!-- {{#callable:fd_numa_move_pages}} -->
The `fd_numa_move_pages` function moves memory pages of a process to specified NUMA nodes and updates the status of each page.
- **Inputs**:
    - `pid`: The process ID of the process whose pages are to be moved.
    - `count`: The number of pages to be moved.
    - `pages`: An array of pointers to the pages that need to be moved.
    - `nodes`: An array of integers specifying the target NUMA node for each page.
    - `status`: An array where the status of each page after the move will be stored.
    - `flags`: Flags that modify the behavior of the `move_pages` syscall.
- **Control Flow**:
    - Invoke the `move_pages` syscall with the provided arguments to move the pages to the specified NUMA nodes.
    - Check if the syscall returns 0, indicating success.
    - If successful, call `fd_msan_unpoison` to unpoison the `status` array, marking it as initialized for memory sanitization tools.
- **Output**: Returns a long integer which is the result of the `move_pages` syscall, indicating success or failure of the operation.



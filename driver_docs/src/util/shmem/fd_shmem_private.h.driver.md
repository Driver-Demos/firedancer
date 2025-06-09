# Purpose
This C header file, `fd_shmem_private.h`, is part of a shared memory management system, specifically focusing on NUMA (Non-Uniform Memory Access) configurations and operations. It provides a set of private APIs and utilities for handling shared memory in a NUMA-aware manner, which is crucial for optimizing memory access patterns in systems with multiple memory nodes. The file includes functions for determining the number of NUMA nodes and CPUs, identifying the closest NUMA node to a given CPU, and managing memory policies and locking mechanisms. These functions wrap around Linux system calls like `mlock`, `munlock`, `get_mempolicy`, `set_mempolicy`, `mbind`, and `move_pages`, providing a higher-level interface for NUMA operations.

The file also defines several macros and constants related to path and buffer size management, ensuring that shared memory paths are constructed correctly and efficiently. It includes conditional compilation directives to handle thread safety, using mutex locks when threads are enabled. The header is designed to be included in other C source files, providing essential utilities for shared memory initialization and management, particularly in environments where NUMA considerations are critical. The functions and macros defined here are intended for internal use within the shared memory management system, as indicated by the "private" designation in the file name and the use of static inline functions and external variables for internal state management.
# Imports and Dependencies

---
- `fd_shmem.h`
- `pthread.h`


# Global Variables

---
### fd\_shmem\_private\_lock
- **Type**: `pthread_mutex_t`
- **Description**: `fd_shmem_private_lock` is a global array of `pthread_mutex_t` used for thread synchronization in environments where threading is supported. It is defined as an array with a single element, indicating that it is intended to be used as a single mutex lock.
- **Use**: This mutex is used to protect shared memory operations, ensuring that only one thread can access the shared memory at a time when threading is enabled.


---
### fd\_shmem\_private\_base
- **Type**: `char array`
- **Description**: `fd_shmem_private_base` is a global character array with a maximum size defined by `FD_SHMEM_PRIVATE_BASE_MAX`. It is initialized to an empty string at the start of a thread group and is set up during the boot process.
- **Use**: This variable is used as a base path for constructing shared memory paths in the system.


---
### fd\_shmem\_private\_base\_len
- **Type**: `ulong`
- **Description**: The `fd_shmem_private_base_len` is a global variable of type `ulong` that represents the length of the shared memory private base path. It is initialized to 0UL at boot time, indicating that initially, the length of the base path is zero.
- **Use**: This variable is used to store and track the length of the shared memory private base path, which is crucial for constructing file paths in shared memory operations.


---
### fd\_shmem\_private\_map\_rand
- **Type**: `function`
- **Description**: The `fd_shmem_private_map_rand` function is designed to map private and anonymous pages of memory at a random virtual address. It takes two parameters: `size`, which specifies the minimum number of bytes to map, and `align`, which specifies the minimum alignment of the first byte to map. The function returns a virtual address on success or `MAP_FAILED` on failure.
- **Use**: This function is used to allocate memory with specific alignment and size requirements at a random virtual address.


# Functions

---
### fd\_shmem\_private\_path<!-- {{#callable:fd_shmem_private_path}} -->
The `fd_shmem_private_path` function constructs a private shared memory path string based on a given name and page size, storing the result in a provided buffer.
- **Inputs**:
    - `name`: A valid string representing the name to be included in the path.
    - `page_sz`: An unsigned long integer representing the page size, which can be normal, huge, or gigantic.
    - `buf`: A non-NULL character buffer with at least `FD_SHMEM_PRIVATE_PATH_BUF_MAX` bytes to store the resulting path string.
- **Control Flow**:
    - The function calls `fd_cstr_printf` to format a string into the provided buffer `buf`.
    - The format string used is `"%s/.%s/%s"`, which combines the base path, page size string, and name into a single path.
    - The function uses `fd_shmem_private_base` as the base path and converts `page_sz` to a string using [`fd_shmem_page_sz_to_cstr`](fd_shmem_admin.c.driver.md#fd_shmem_page_sz_to_cstr).
    - The formatted string is stored in `buf`, and the function returns `buf`.
- **Output**: The function returns the `buf` pointer, which contains the formatted path string.
- **Functions called**:
    - [`fd_shmem_page_sz_to_cstr`](fd_shmem_admin.c.driver.md#fd_shmem_page_sz_to_cstr)


# Function Declarations (Public API)

---
### fd\_shmem\_private\_map\_rand<!-- {{#callable_declaration:fd_shmem_private_map_rand}} -->
Maps a private anonymous memory region at a random virtual address.
- **Description**: This function maps a private and anonymous memory region of at least the specified size at a random virtual address, with the starting address aligned to the specified alignment. It is useful for allocating memory in a way that minimizes address predictability, which can be beneficial for security or testing purposes. The function attempts to find a suitable address up to 1000 times before failing. It should be used when a non-deterministic memory layout is desired, and the caller must handle the possibility of failure.
- **Inputs**:
    - `size`: The minimum number of bytes to map. Must be a positive value.
    - `align`: The minimum alignment for the starting address of the mapped region. Must be a power of two.
- **Output**: Returns a pointer to the mapped memory region on success, or MAP_FAILED on failure.
- **See also**: [`fd_shmem_private_map_rand`](fd_shmem_user.c.driver.md#fd_shmem_private_map_rand)  (Implementation)



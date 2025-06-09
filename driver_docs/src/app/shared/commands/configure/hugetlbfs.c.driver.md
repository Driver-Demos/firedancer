# Purpose
This C source code file is designed to manage the configuration and lifecycle of hugetlbfs, a filesystem in Linux that supports the use of large memory pages, which can improve performance for certain applications by reducing the overhead of page table management. The file is part of a larger system, likely a configuration management tool, as indicated by the `configure_stage_t` structure at the end, which defines a stage named "hugetlbfs". This stage includes functions for initializing and finalizing permissions ([`init_perm`](#init_perm) and [`fini_perm`](#fini_perm)), setting up and tearing down the hugetlbfs mounts ([`init`](#init) and [`fini`](#fini)), and checking the current configuration status ([`check`](#check)).

The code is structured to handle various tasks related to hugetlbfs, such as mounting the filesystem with specific page sizes, ensuring the required number of huge pages are available, and managing permissions. It interacts with the Linux filesystem and process management interfaces, using system calls and file operations to read and write configuration data. The code also includes error handling and logging to provide feedback on the operations performed, such as mounting and unmounting filesystems, and adjusting system settings. The use of static functions and the inclusion of platform-specific utilities suggest that this file is part of a modular system, where each component is responsible for a specific aspect of the configuration process.
# Imports and Dependencies

---
- `configure.h`
- `../../../platform/fd_file_util.h`
- `../../../platform/fd_sys_util.h`
- `unistd.h`
- `errno.h`
- `stdio.h`
- `stdlib.h`
- `dirent.h`
- `sys/stat.h`
- `sys/mount.h`
- `linux/capability.h`


# Global Variables

---
### TOTAL\_HUGE\_PAGE\_PATH
- **Type**: ``char const *[2]``
- **Description**: The `TOTAL_HUGE_PAGE_PATH` is a static array of two constant character pointers, each pointing to a string that represents a file path in the Linux sysfs. These paths are used to access the total number of huge pages available on a specific NUMA node, with the paths differing based on the size of the huge pages (2MB and 1GB).
- **Use**: This variable is used to construct file paths for reading and writing the total number of huge pages on a NUMA node.


---
### FREE\_HUGE\_PAGE\_PATH
- **Type**: ``char const *[2]``
- **Description**: The `FREE_HUGE_PAGE_PATH` is a static array of two constant character pointers, each pointing to a string that represents a file path in the Linux sysfs. These paths are used to access the number of free huge pages available on a specific NUMA node for two different page sizes: 2048kB and 1048576kB.
- **Use**: This variable is used to format and access the file paths that provide information about the number of free huge pages on a NUMA node.


---
### PAGE\_SIZE
- **Type**: `array of unsigned long integers`
- **Description**: `PAGE_SIZE` is a static array of unsigned long integers that defines the sizes of two types of huge pages used in the system. The first element represents a huge page size of 2 MiB (2097152 bytes), and the second element represents a gigantic page size of 1 GiB (1073741824 bytes).
- **Use**: This variable is used to specify the page sizes for huge and gigantic pages in memory management operations, particularly when configuring and managing hugetlbfs mounts.


---
### PAGE\_NAMES
- **Type**: ``static char const *` array`
- **Description**: `PAGE_NAMES` is a static array of constant character pointers, each pointing to a string that represents the name of a page size. The array contains two elements: "huge" and "gigantic".
- **Use**: This array is used to label different page sizes in the context of managing huge pages in the system.


---
### fd\_cfg\_stage\_hugetlbfs
- **Type**: `configure_stage_t`
- **Description**: The `fd_cfg_stage_hugetlbfs` is a global variable of type `configure_stage_t` that represents a configuration stage for managing hugetlbfs, a filesystem for huge pages in Linux. It contains function pointers for initializing and finalizing permissions, as well as for initializing, finalizing, and checking the configuration of hugetlbfs. The variable is initialized with specific functions to handle these operations.
- **Use**: This variable is used to manage the lifecycle and configuration checks of the hugetlbfs stage in the system.


# Functions

---
### init\_perm<!-- {{#callable:init_perm}} -->
The `init_perm` function checks and sets the necessary permissions for using hugetlbfs by verifying root and CAP_SYS_ADMIN capabilities.
- **Inputs**:
    - `chk`: A pointer to an `fd_cap_chk_t` structure used for checking capabilities.
    - `config`: A constant pointer to a `config_t` structure, which is not used in this function (indicated by `FD_PARAM_UNUSED`).
- **Control Flow**:
    - Call `fd_cap_chk_root` to check if the process has root permissions for increasing `/proc/sys/vm/nr_hugepages`.
    - Call `fd_cap_chk_cap` to check if the process has the `CAP_SYS_ADMIN` capability for mounting hugetlbfs filesystems.
- **Output**: The function does not return a value; it performs checks and sets permissions as side effects.


---
### fini\_perm<!-- {{#callable:fini_perm}} -->
The `fini_perm` function checks and removes permissions related to hugetlbfs by ensuring root access and the capability to unmount hugetlbfs filesystems.
- **Inputs**:
    - `chk`: A pointer to an `fd_cap_chk_t` structure used for capability checking.
    - `config`: A constant pointer to a `config_t` structure, which is not used in this function.
- **Control Flow**:
    - Calls `fd_cap_chk_root` to check for root permissions related to removing directories from `/mnt` associated with hugetlbfs.
    - Calls `fd_cap_chk_cap` to check for the `CAP_SYS_ADMIN` capability required to unmount hugetlbfs filesystems.
- **Output**: This function does not return any value; it performs permission checks as side effects.


---
### init<!-- {{#callable:init}} -->
The `init` function configures and mounts hugetlbfs filesystems for huge and gigantic pages on each NUMA node based on the provided configuration.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing configuration details for hugetlbfs, including mount paths and topology information.
- **Control Flow**:
    - Initialize mount paths for huge and gigantic pages from the configuration.
    - Determine the number of NUMA nodes using `fd_shmem_numa_cnt()`.
    - For each NUMA node, calculate the required number of huge and gigantic pages using `fd_topo_huge_page_cnt()` and `fd_topo_gigantic_page_cnt()`.
    - For each page type (huge and gigantic), check the number of free pages available on the system.
    - If the available pages are less than required, attempt to increase the total number of pages by writing to the system's huge page configuration files.
    - If increasing the pages fails due to memory fragmentation, attempt to compact memory and drop caches, then retry.
    - Calculate the minimum size required for each page type across all NUMA nodes.
    - Create and mount the hugetlbfs directories with the calculated options, setting appropriate permissions.
- **Output**: The function does not return a value but logs errors and notices, and may terminate the program if critical errors occur.


---
### cmdline<!-- {{#callable:cmdline}} -->
The `cmdline` function reads the command line arguments of the current process from `/proc/self/cmdline` into a provided buffer and null-terminates the string.
- **Inputs**:
    - `buf`: A character buffer where the command line arguments will be stored.
    - `buf_sz`: The size of the buffer `buf` in bytes.
- **Control Flow**:
    - Open the file `/proc/self/cmdline` for reading.
    - Check if the file was opened successfully; if not, log an error and exit.
    - Read up to `buf_sz - 1` bytes from the file into the buffer `buf`.
    - Check for read errors; if any, log an error and exit.
    - Close the file and check for errors during closing; if any, log an error and exit.
    - Null-terminate the buffer at the position after the last read byte.
- **Output**: The function does not return a value; it modifies the buffer `buf` in place to contain the command line arguments of the current process.


---
### warn\_mount\_users<!-- {{#callable:warn_mount_users}} -->
The `warn_mount_users` function checks for processes that have open file descriptors in a specified mount path and logs a warning for each such process.
- **Inputs**:
    - `mount_path`: A constant character pointer representing the path of the mount to check for open file descriptors.
- **Control Flow**:
    - Open the `/proc` directory to read process information.
    - Iterate over each entry in the `/proc` directory, skipping `.` and `..` entries.
    - Convert each directory name to a process ID (PID) and skip non-numeric entries.
    - Construct the path to the process's memory maps file (`/proc/<pid>/maps`).
    - Open the maps file and read the command line of the current process.
    - Read each line of the maps file to check if it contains the specified mount path.
    - If a line contains the mount path, log a warning with the PID and command line of the process.
    - Handle errors in reading or closing files with appropriate logging.
    - Close the `/proc` directory.
- **Output**: The function does not return a value; it logs warnings for processes with open file descriptors in the specified mount path.
- **Functions called**:
    - [`cmdline`](#cmdline)


---
### fini<!-- {{#callable:fini}} -->
The `fini` function unmounts and removes directories related to hugetlbfs mounts specified in the configuration.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing paths for hugetlbfs mounts.
    - `pre_init`: An integer flag that is not used in this function.
- **Control Flow**:
    - The function begins by casting `pre_init` to void, indicating it is unused.
    - A normal page mount path is constructed using the `hugetlbfs.mount_path` from the `config`.
    - An array `mount_path` is initialized with paths for huge, gigantic, and normal page mounts.
    - A loop iterates over the `mount_path` array to process each mount path.
    - For each mount path, the function opens `/proc/self/mounts` to read current mounts.
    - It reads each line from the file and checks if the line contains the current mount path.
    - If a mount path is found, it attempts to unmount it using `umount`.
    - If unmounting fails due to the mount being busy, it calls [`warn_mount_users`](#warn_mount_users) and logs an error.
    - If unmounting fails for other reasons, it logs an error with the failure details.
    - After processing the mounts, it attempts to remove the directory using `rmdir`.
    - If removing the directory fails for reasons other than it not existing, it logs an error.
    - Finally, it attempts to remove the main `hugetlbfs.mount_path` directory.
- **Output**: The function does not return a value; it performs operations and logs errors if they occur.
- **Functions called**:
    - [`warn_mount_users`](#warn_mount_users)


---
### check<!-- {{#callable:check}} -->
The `check` function verifies the configuration and existence of hugetlbfs mount points and their properties based on the provided configuration.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing configuration details for hugetlbfs, including mount paths, user ID, and group ID.
- **Control Flow**:
    - Initialize mount paths and expected page sizes for huge and gigantic pages.
    - Calculate the required minimum size for each page type across all NUMA nodes.
    - Check the existence of the mount paths using `stat` and handle errors or non-existence cases.
    - Verify directory permissions and existence using [`check_dir`](configure.c.driver.md#check_dir).
    - Open `/proc/self/mounts` to read and verify mount configurations for each path.
    - For each mount path, parse the mount options and verify device, path, type, and options like `rw`, `relatime`, and `pagesize`.
    - Check if the `min_size` option meets the required minimum size.
    - Handle errors and log messages for any discrepancies found during checks.
    - If all checks pass, call `CONFIGURE_OK()` to indicate successful configuration.
- **Output**: The function returns a `configure_result_t` indicating the configuration status, which could be fully configured, partially configured, or not configured based on the checks performed.
- **Functions called**:
    - [`check_dir`](configure.c.driver.md#check_dir)



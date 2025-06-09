# Purpose
This Bash script is designed to manage shared memory using hugetlbfs, a filesystem that supports huge pages in Linux. The script provides a set of commands to initialize, finalize, allocate, free, query, and reset shared memory regions. It uses environment variables and system paths to determine where to mount the shared memory, defaulting to "/mnt/.fd" if no specific path is provided. The script supports different types of memory pages, including "normal," "huge," and "gigantic," and it interacts with the system's NUMA (Non-Uniform Memory Access) nodes to manage memory allocation.

The script includes several functions that encapsulate specific tasks. For instance, `init` sets up the necessary directories and mounts for shared memory, while `fini` cleans up these resources. The `alloc` function reserves a specified number of huge pages on a given NUMA node, and `query` provides information about the current state of shared memory usage. The script also includes error handling to ensure that operations are performed with the necessary permissions and that the system is in a compatible state.

Overall, this script is a utility for managing shared memory in a Linux environment, particularly for applications that require large memory pages for performance reasons. It is intended to be run with superuser privileges due to the nature of the operations it performs, such as mounting filesystems and modifying system memory settings. The script provides a command-line interface for users to interact with the shared memory system, offering flexibility and control over memory management tasks.
# Global Variables

---
### SHMEM\_PATH
- **Type**: `string`
- **Description**: `SHMEM_PATH` is a global variable that holds the path to the shared memory file system mount point. It is initialized using the environment variable `FD_SHMEM_PATH` if it is set, otherwise it defaults to the path "/mnt/.fd". This variable is crucial for determining where shared memory resources are mounted and managed within the script.
- **Use**: `SHMEM_PATH` is used throughout the script to create, manage, and clean up shared memory resources at the specified mount point.


---
### ALL\_TYPES
- **Type**: `string`
- **Description**: The `ALL_TYPES` variable is a string that contains a space-separated list of page types: "gigantic", "huge", and "normal". These page types represent different sizes of memory pages that can be used in the script for memory management operations.
- **Use**: `ALL_TYPES` is used to iterate over the different page types when performing operations such as initialization, querying, and resetting shared memory regions.


---
### BIN
- **Type**: `string`
- **Description**: The `BIN` variable is a string that holds the directory path of the script being executed. It is determined by using the `dirname` command on the `$BASH_SOURCE` variable, which contains the path to the script file.
- **Use**: This variable is used to construct paths for executing other scripts or commands relative to the script's location.


---
### NUMA\_CNT
- **Type**: `string`
- **Description**: `NUMA_CNT` is a global variable that stores the output of a command executed by the script, specifically the number of NUMA nodes available on the system. It is determined by running the `fd_shmem_ctl numa-cnt` command, which is expected to return the count of NUMA nodes, and this output is captured into the `NUMA_CNT` variable.
- **Use**: This variable is used to iterate over the available NUMA nodes when querying or allocating huge pages in the system.


# Functions

---
### get\_page\_size
The `get_page_size` function returns the size in bytes of a memory page based on the specified page type.
- **Inputs**:
    - `$1`: A string representing the type of page, which can be 'normal', 'huge', or 'gigantic'.
- **Control Flow**:
    - Check if the input page type is 'normal'; if so, return 4096 bytes.
    - Check if the input page type is 'huge'; if so, return 2097152 bytes.
    - Check if the input page type is 'gigantic'; if so, return 1073741824 bytes.
    - If the input page type is not recognized, print an error message and exit with status 1.
- **Output**: The function outputs the size of the specified page type in bytes or an error message if the page type is unsupported.


---
### get\_page\_path
The `get_page_path` function returns the system path for hugepages based on the specified page type and NUMA node.
- **Inputs**:
    - `$1`: The type of page, which can be either 'huge' or 'gigantic'.
    - `$2`: The NUMA node number for which the path is being requested.
- **Control Flow**:
    - Check if the page type ($1) is 'huge'.
    - If 'huge', return the path for 2048kB hugepages for the specified NUMA node ($2).
    - Check if the page type ($1) is 'gigantic'.
    - If 'gigantic', return the path for 1048576kB hugepages for the specified NUMA node ($2).
    - If the page type is neither 'huge' nor 'gigantic', print an error message and exit with a failure status.
- **Output**: A string representing the system path for the specified hugepage type and NUMA node, or an error message if the page type is unsupported.


---
### get\_page\_total
The `get_page_total` function retrieves the total number of huge pages of a specified type available on a specified NUMA node.
- **Inputs**:
    - `$1`: The type of huge page, which can be either 'huge' or 'gigantic'.
    - `$2`: The NUMA node number for which the total number of huge pages is to be retrieved.
- **Control Flow**:
    - The function calls `get_page_path` with the provided page type and NUMA node to determine the path to the hugepages information.
    - It uses the `cat` command to read the `nr_hugepages` file at the determined path, which contains the total number of huge pages.
    - If the `cat` command fails (returns a non-zero status), the function prints an error message and exits with a status of 1.
- **Output**: The function outputs the total number of huge pages of the specified type on the specified NUMA node, or an error message if the operation fails.


---
### get\_page\_free
The `get_page_free` function retrieves the number of free huge pages of a specified type and NUMA node from the system.
- **Inputs**:
    - `$1`: The type of huge page, which can be 'huge' or 'gigantic'.
    - `$2`: The NUMA node number for which the free huge pages are to be retrieved.
- **Control Flow**:
    - The function constructs the path to the 'free_hugepages' file for the specified page type and NUMA node using the `get_page_path` function.
    - It uses the `cat` command to read the number of free huge pages from the constructed path.
    - If the `cat` command fails (indicated by a non-zero exit status), the function prints an error message and exits with a status of 1.
- **Output**: The function outputs the number of free huge pages for the specified type and NUMA node to the standard output.


---
### try\_defrag\_memory
The `try_defrag_memory` function attempts to defragment system memory by writing to a specific system file and optionally waits for a short period if successful.
- **Inputs**: None
- **Control Flow**:
    - The function writes the value '1' to the file '/proc/sys/vm/compact_memory' to trigger a memory compaction attempt by the operating system.
    - It checks the exit status of the write operation to determine if it was successful.
    - If the write operation is successful (exit status is 0), the function pauses execution for 0.25 seconds to allow the operating system to perform background memory compaction.
- **Output**: The function does not return any value or output.


---
### init
The `init` function initializes a shared memory IPC domain by creating necessary directories and mounting them with specified permissions, user, and group.
- **Inputs**:
    - `SHMEM_PERM`: The permissions to set on the shared memory path, in the format used by `chmod`.
    - `SHMEM_USER`: The user to own the shared memory path, in the format used by `chown`.
    - `SHMEM_GROUP`: The group to own the shared memory path, in the format used by `chown`.
- **Control Flow**:
    - Check if the shared memory path already exists; if so, print an error and exit.
    - Create the shared memory path directory and check for errors; if any, print an error and exit.
    - Iterate over all page types (gigantic, huge, normal) to create and mount directories for each type.
    - For each page type, check if the mount path already exists; if so, print an error and exit.
    - Create the mount path directory and check for errors; if any, print an error and exit.
    - Check if the mount path is already mounted; if so, print an error and exit.
    - Attempt to defragment memory before mounting.
    - Mount the directory with appropriate settings based on the page type (tmpfs for normal, hugetlbfs for others) and check for errors; if any, print an error and exit.
    - Attempt to defragment memory again after mounting.
    - Change ownership of the shared memory path to the specified user and group, checking for errors.
    - Set permissions on the shared memory path, checking for errors.
    - Print a success message if all operations complete without errors.
- **Output**: The function outputs success or failure messages to the console, indicating the result of the initialization process.


---
### fini
The `fini` function unmounts and removes the shared memory directory specified by `SHMEM_PATH` and attempts to defragment memory.
- **Inputs**: None
- **Control Flow**:
    - Check if the directory specified by `SHMEM_PATH` exists.
    - If it exists, call `try_defrag_memory` to attempt memory defragmentation.
    - Iterate over each type in `ALL_TYPES` and attempt to unmount the corresponding directory under `SHMEM_PATH`.
    - If unmounting fails, print an error message but continue the process.
    - Remove the directory specified by `SHMEM_PATH` recursively and forcefully.
    - If removal fails, print an error message and exit with a failure status.
    - Call `try_defrag_memory` again to attempt memory defragmentation.
    - Print a success message if all operations complete without error.
    - If the directory does not exist, print an error message indicating the path is not accessible and exit with a failure status.
- **Output**: The function outputs success or failure messages to the console, indicating the result of the unmount and removal operations.


---
### query
The `query` function displays the current shared memory utilization and details of named shared memory regions for different page types and NUMA nodes.
- **Inputs**: None
- **Control Flow**:
    - Prints an empty line for formatting.
    - Iterates over all page types defined in `ALL_TYPES`, excluding 'normal'.
    - For each page type, prints the type and iterates over NUMA nodes, printing the total and free pages for each node using `get_page_total` and `get_page_free`.
    - Checks if the shared memory path (`SHMEM_PATH`) exists; if so, prints the path and iterates over all page types, listing shared memory regions and their details.
    - If the shared memory path does not exist, prints an error message and exits with failure.
- **Output**: The function outputs the shared memory utilization and details of shared memory regions to the console, or an error message if the shared memory path is not accessible.


---
### alloc
The `alloc` function reserves a specified number of huge pages of a given type on a specified NUMA node, ensuring that all pages are free before allocation.
- **Inputs**:
    - `CNT`: The number of pages to allocate.
    - `TYPE`: The type of pages to allocate, which can be 'huge' or 'gigantic'.
    - `NUMA`: The NUMA node on which to allocate the pages.
- **Control Flow**:
    - Check if the page type is 'normal'; if so, print an error message and exit.
    - Retrieve the total and free number of pages of the specified type and NUMA node.
    - If the total number of pages is not equal to the free number, print an error message and exit.
    - Attempt to defragment memory.
    - Set the number of huge pages to the specified count by writing to the appropriate system file.
    - Check if the operation was successful by comparing the total and free pages again.
    - If the expected number of pages is not allocated or some pages are in use, print an error message and exit.
    - Print a success message if all checks pass.
- **Output**: The function outputs success or failure messages to the console, indicating whether the allocation was successful or not.


---
### reset
The `reset` function removes all named shared memory regions within a specified shared memory path.
- **Inputs**: None
- **Control Flow**:
    - Check if the directory specified by `SHMEM_PATH` exists.
    - If the directory exists, attempt to defragment memory using `try_defrag_memory`.
    - Iterate over each type in `ALL_TYPES` and remove all files in the corresponding subdirectory under `SHMEM_PATH`.
    - If any removal operation fails, print an error message and exit with a failure status.
    - Attempt to defragment memory again after the removal operations.
    - If the directory does not exist, print an error message indicating the path is not accessible and exit with a failure status.
- **Output**: The function outputs a success message if all operations are successful, or an error message and exits with a failure status if any operation fails.



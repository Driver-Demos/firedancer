# Purpose
This C source code file is designed to manage and provide information about the CPU topology of a system. It includes functions to read and interpret CPU-related data from the Linux filesystem, specifically from the `/sys/devices/system/cpu/` directory, which contains details about CPU presence, online status, and hyperthreading relationships. The file defines several static and public functions that facilitate the retrieval of CPU count, the identification of sibling CPUs in hyperthreaded systems, and the determination of whether a CPU is online. The [`fd_topo_cpus_init`](#fd_topo_cpus_init) function initializes a data structure representing the CPU topology, populating it with information about each CPU's index, online status, NUMA node, and sibling CPU if applicable. The [`fd_topo_cpus_printf`](#fd_topo_cpus_printf) function is used to log the CPU topology information, providing a formatted output of each CPU's status and relationships.

The code is structured to be part of a larger system, likely a library or utility that deals with CPU topology and NUMA configurations. It includes error handling mechanisms that log errors and terminate the process if critical operations fail, ensuring robustness in environments where accurate CPU topology information is crucial. The file does not define a main function, indicating that it is not an executable but rather a component intended to be integrated into other software. The inclusion of headers like `fd_cpu_topo.h` and `fd_shmem_private.h` suggests that it is part of a modular system, possibly dealing with shared memory and CPU topology management. The functions provided are essential for applications that need to optimize performance based on CPU and NUMA configurations, such as high-performance computing or real-time systems.
# Imports and Dependencies

---
- `fd_cpu_topo.h`
- `../../util/shmem/fd_shmem_private.h`
- `errno.h`
- `unistd.h`
- `fcntl.h`
- `stdio.h`
- `stdlib.h`


# Functions

---
### read\_uint\_file<!-- {{#callable:read_uint_file}} -->
The `read_uint_file` function reads an unsigned integer from a file specified by a given path and logs an error if any file operation fails.
- **Inputs**:
    - `path`: A constant character pointer representing the file path from which the unsigned integer is to be read.
    - `errmsg_enoent`: A constant character pointer representing the error message to be logged if the file does not exist (errno is ENOENT).
- **Control Flow**:
    - Open the file at the specified path in read mode using `fopen`.
    - Check if the file pointer is NULL, indicating that the file could not be opened.
    - If the file could not be opened and the error is ENOENT, log an error with the provided error message; otherwise, log a generic fopen error.
    - Initialize an unsigned integer variable `value` to 0.
    - Attempt to read an unsigned integer from the file using `fscanf`.
    - If reading fails (i.e., `fscanf` does not return 1), log an error indicating the failure to read the unsigned integer.
    - Close the file using `fclose` and log an error if closing the file fails.
    - Return the read unsigned integer value.
- **Output**: Returns the unsigned integer read from the specified file.


---
### fd\_topo\_cpu\_cnt<!-- {{#callable:fd_topo_cpu_cnt}} -->
The `fd_topo_cpu_cnt` function reads the CPU range from the system file "/sys/devices/system/cpu/present" and returns the total number of CPUs available.
- **Inputs**: None
- **Control Flow**:
    - Declare a character array `path` to store the file path and use `fd_cstr_printf_check` to format the path to "/sys/devices/system/cpu/present".
    - Declare a character array `line` to store the file content and open the file at `path` in read-only mode using `open`.
    - Check if the file descriptor `fd` is valid; if not, log an error and exit.
    - Read the content of the file into `line` using `read` and check for errors or buffer overflow; log an error and exit if any issues are found.
    - Close the file descriptor `fd` and check for errors; log an error and exit if any issues are found.
    - Null-terminate the `line` string at the position of `bytes_read`.
    - Use `strtok_r` to tokenize the `line` string, splitting by the '-' character to find the end of the CPU range.
    - Convert the token representing the end of the CPU range to an unsigned long using `fd_cstr_to_ulong`.
    - Return the end value incremented by one to represent the total number of CPUs.
- **Output**: The function returns an `ulong` representing the total number of CPUs available on the system.


---
### fd\_topob\_sibling\_idx<!-- {{#callable:fd_topob_sibling_idx}} -->
The `fd_topob_sibling_idx` function retrieves the sibling CPU index for a given CPU index, which is part of a hyperthreaded pair, or returns `ULONG_MAX` if no sibling is found.
- **Inputs**:
    - `cpu_idx`: The index of the CPU for which the sibling index is to be determined.
- **Control Flow**:
    - Constructs a file path to the CPU's topology thread siblings list using the provided `cpu_idx`.
    - Attempts to open the file at the constructed path for reading; logs an error and exits if the file cannot be opened.
    - Reads the contents of the file into a buffer; logs an error and exits if the read fails or if the buffer is too small.
    - Closes the file descriptor; logs an error and exits if closing fails.
    - Searches for a comma in the read line to separate sibling indices; returns `ULONG_MAX` if no comma is found.
    - Parses the first sibling index from the line; logs an error and exits if parsing fails.
    - Parses the second sibling index from the line; logs an error and exits if parsing fails.
    - Checks if the first parsed index matches `cpu_idx` and returns the second index if true; otherwise, checks if the second parsed index matches `cpu_idx` and returns the first index if true.
    - Logs an error and exits if neither parsed index matches `cpu_idx`.
- **Output**: Returns the index of the sibling CPU if found, or `ULONG_MAX` if no sibling is found.


---
### fd\_topo\_cpus\_online<!-- {{#callable:fd_topo_cpus_online}} -->
The `fd_topo_cpus_online` function checks if a specified CPU is online by reading its status from the system file.
- **Inputs**:
    - `cpu_idx`: The index of the CPU whose online status is to be checked.
- **Control Flow**:
    - Check if the `cpu_idx` is 0, and if so, return 1 since CPU 0 cannot be set offline.
    - Construct the file path to the CPU's online status file using `fd_cstr_printf_check`.
    - Call [`read_uint_file`](#read_uint_file) with the constructed path to read the online status of the CPU.
    - Return the result of [`read_uint_file`](#read_uint_file) as an integer.
- **Output**: An integer indicating the online status of the specified CPU, where 1 typically means online and 0 means offline.
- **Functions called**:
    - [`read_uint_file`](#read_uint_file)


---
### fd\_topo\_cpus\_init<!-- {{#callable:fd_topo_cpus_init}} -->
The `fd_topo_cpus_init` function initializes the CPU topology structure by populating it with information about each CPU's index, online status, NUMA node, and sibling CPU.
- **Inputs**:
    - `cpus`: A pointer to an `fd_topo_cpus_t` structure that will be initialized with CPU topology information.
- **Control Flow**:
    - Retrieve the number of NUMA nodes and store it in `cpus->numa_node_cnt`.
    - Retrieve the total number of CPUs and store it in `cpus->cpu_cnt`.
    - Iterate over each CPU index from 0 to `cpus->cpu_cnt - 1`.
    - For each CPU, set its index in the `cpus->cpu` array.
    - Determine if the CPU is online and store the result in `cpus->cpu[i].online`.
    - Retrieve the NUMA node index for the CPU and store it in `cpus->cpu[i].numa_node`.
    - If the CPU is online, retrieve its sibling CPU index and store it in `cpus->cpu[i].sibling`; otherwise, set `cpus->cpu[i].sibling` to `ULONG_MAX`.
- **Output**: The function does not return a value; it initializes the provided `fd_topo_cpus_t` structure with CPU topology data.
- **Functions called**:
    - [`fd_topo_cpu_cnt`](#fd_topo_cpu_cnt)
    - [`fd_topo_cpus_online`](#fd_topo_cpus_online)
    - [`fd_topob_sibling_idx`](#fd_topob_sibling_idx)


---
### fd\_topo\_cpus\_printf<!-- {{#callable:fd_topo_cpus_printf}} -->
The `fd_topo_cpus_printf` function logs the status of each CPU in the `fd_topo_cpus_t` structure, including its online status, sibling CPU, and NUMA node.
- **Inputs**:
    - `cpus`: A pointer to an `fd_topo_cpus_t` structure containing information about the CPUs, including their count and properties such as online status, sibling, and NUMA node.
- **Control Flow**:
    - Iterates over each CPU in the `cpus` structure using a for loop, from index 0 to `cpus->cpu_cnt - 1`.
    - For each CPU, logs a message with its index, online status, sibling index, and NUMA node using the `FD_LOG_NOTICE` macro.
- **Output**: The function does not return a value; it outputs log messages for each CPU's status.



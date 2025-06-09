# Purpose
This C header file defines data structures and function prototypes for managing CPU topology information. It includes two main structures: `fd_topo_cpu`, which represents individual CPU details such as index, online status, NUMA node, and sibling relationships, and `fd_topo_cpus`, which aggregates multiple `fd_topo_cpu` instances and tracks the total number of CPUs and NUMA nodes. The file provides function prototypes for initializing the CPU topology ([`fd_topo_cpus_init`](#fd_topo_cpus_init)) by reading system information and for printing this topology information ([`fd_topo_cpus_printf`](#fd_topo_cpus_printf)). This header is part of a larger system, likely dealing with hardware resource management, and ensures that CPU topology data is correctly initialized and accessible for further processing or diagnostics.
# Imports and Dependencies

---
- `../fd_disco_base.h`


# Data Structures

---
### fd\_topo\_cpu
- **Type**: `struct`
- **Members**:
    - `idx`: An unsigned long integer representing the index of the CPU.
    - `online`: An integer indicating whether the CPU is online (1) or offline (0).
    - `numa_node`: An unsigned long integer representing the NUMA node to which the CPU belongs.
    - `sibling`: An unsigned long integer representing the sibling CPU in a multi-core processor.
- **Description**: The `fd_topo_cpu` structure is designed to encapsulate information about a single CPU in a system, including its index, online status, NUMA node association, and sibling relationship in a multi-core setup. This structure is part of a larger CPU topology framework, which helps in understanding and managing the CPU layout and configuration in a system.


---
### fd\_topo\_cpu\_t
- **Type**: `struct`
- **Members**:
    - `idx`: An unsigned long integer representing the index of the CPU.
    - `online`: An integer indicating whether the CPU is online (1) or offline (0).
    - `numa_node`: An unsigned long integer representing the NUMA node to which the CPU belongs.
    - `sibling`: An unsigned long integer representing the sibling CPU in a multi-core processor.
- **Description**: The `fd_topo_cpu_t` structure is designed to encapsulate information about a single CPU in a system, including its index, online status, NUMA node association, and sibling relationship. This structure is part of a larger CPU topology framework that helps in managing and understanding the CPU layout and configuration in a multi-core, multi-node environment.


---
### fd\_topo\_cpus
- **Type**: `struct`
- **Members**:
    - `numa_node_cnt`: Represents the count of NUMA nodes in the system.
    - `cpu_cnt`: Indicates the total number of CPUs available.
    - `cpu`: An array of `fd_topo_cpu_t` structures, each representing a CPU, with a maximum size of 1024.
- **Description**: The `fd_topo_cpus` structure is designed to encapsulate information about the CPU topology of a system, including the number of NUMA nodes and CPUs. It contains an array of `fd_topo_cpu_t` structures, each detailing individual CPU attributes, allowing for a comprehensive representation of the system's CPU configuration.


---
### fd\_topo\_cpus\_t
- **Type**: `struct`
- **Members**:
    - `numa_node_cnt`: Stores the count of NUMA nodes in the system.
    - `cpu_cnt`: Holds the number of CPUs in the system.
    - `cpu`: An array of fd_topo_cpu_t structures, with a maximum size of 1024, representing individual CPU details.
- **Description**: The `fd_topo_cpus_t` structure is designed to represent the topology of CPUs in a system, including the number of NUMA nodes and CPUs. It contains an array of `fd_topo_cpu_t` structures, each detailing individual CPU attributes such as index, online status, NUMA node association, and sibling relationships. This structure is used to manage and access CPU topology information efficiently, typically initialized by reading from the operating system.


# Function Declarations (Public API)

---
### fd\_topo\_cpus\_init<!-- {{#callable_declaration:fd_topo_cpus_init}} -->
Initialize the CPU topology structure with system information.
- **Description**: This function initializes a `fd_topo_cpus_t` structure by populating it with CPU topology information obtained from the operating system. It must be called before using the `fd_topo_cpus_t` structure for any operations that depend on CPU topology data. The function will log an error and terminate the process if it fails to determine the CPU topology, ensuring that the structure is only used when valid data is available.
- **Inputs**:
    - `cpus`: A pointer to a `fd_topo_cpus_t` structure that will be initialized. The caller must ensure this pointer is valid and points to a properly allocated `fd_topo_cpus_t` structure. The function assumes ownership of the structure's contents during initialization.
- **Output**: None
- **See also**: [`fd_topo_cpus_init`](fd_cpu_topo.c.driver.md#fd_topo_cpus_init)  (Implementation)


---
### fd\_topo\_cpus\_printf<!-- {{#callable_declaration:fd_topo_cpus_printf}} -->
Prints the status of each CPU in the topology.
- **Description**: Use this function to output the status of each CPU in a given topology structure. It should be called after the CPU topology has been initialized using `fd_topo_cpus_init`. The function iterates over all CPUs in the provided `fd_topo_cpus_t` structure and logs their online status, sibling index, and NUMA node association. This is useful for debugging or monitoring purposes to understand the current configuration and status of the CPUs in the system.
- **Inputs**:
    - `cpus`: A pointer to an `fd_topo_cpus_t` structure containing the CPU topology information. This must not be null and should be properly initialized using `fd_topo_cpus_init` before calling this function. The function assumes that the `cpu_cnt` field accurately reflects the number of CPUs described in the `cpu` array.
- **Output**: None
- **See also**: [`fd_topo_cpus_printf`](fd_cpu_topo.c.driver.md#fd_topo_cpus_printf)  (Implementation)



# Purpose
This C header file is designed for managing IPv4 neighbor discovery using the Address Resolution Protocol (ARP). It defines a data structure, `fd_neigh4_entry`, which holds information about an IPv4 address, its corresponding MAC address, the state of the entry, and a timestamp for probe suppression. The file includes macros to define the states of the neighbor entries, such as `INCOMPLETE` and `ACTIVE`. Additionally, it provides a function prototype for [`fd_neigh4_hmap_fprintf`](#fd_neigh4_hmap_fprintf), which is used to print the routing table to a specified file, ensuring the output is stable and formatted in ASCII with line feeds. The file also includes necessary headers and configurations for logging and map slot parameterization, indicating its integration with a larger system for network management.
# Imports and Dependencies

---
- `../../util/log/fd_log.h`
- `fd_neigh4_map_defines.h`
- `../../util/tmpl/fd_map_slot_para.c`


# Data Structures

---
### fd\_neigh4\_entry
- **Type**: `struct`
- **Members**:
    - `ip4_addr`: Stores the IPv4 address associated with the neighbor entry.
    - `mac_addr`: Holds the MAC address corresponding to the IPv4 address.
    - `state`: Indicates the state of the neighbor entry, such as incomplete or active.
    - `_pad`: Padding to align the structure to 16 bytes.
    - `probe_suppress_until`: Specifies the time until which probe suppression is active.
- **Description**: The `fd_neigh4_entry` structure is designed for managing IPv4 neighbor discovery using ARP, aligning to 16 bytes for performance optimization. It contains fields for storing an IPv4 address, its corresponding MAC address, the state of the neighbor entry, and a timestamp for probe suppression. This structure is part of a larger system for handling network routing tables and neighbor discovery processes.


---
### fd\_neigh4\_entry\_t
- **Type**: `struct`
- **Members**:
    - `ip4_addr`: Stores the IPv4 address associated with the neighbor entry.
    - `mac_addr`: Holds the MAC address corresponding to the IPv4 address.
    - `state`: Indicates the state of the neighbor entry, such as INCOMPLETE or ACTIVE.
    - `_pad`: Padding to align the structure to 16 bytes.
    - `probe_suppress_until`: Specifies the time until which ARP probes are suppressed for this entry.
- **Description**: The `fd_neigh4_entry_t` structure is used for managing IPv4 neighbor discovery entries, specifically for ARP (Address Resolution Protocol) operations. It contains fields for storing an IPv4 address, its corresponding MAC address, the state of the entry, and a timestamp to control ARP probe suppression. The structure is aligned to 16 bytes for performance reasons.


# Function Declarations (Public API)

---
### fd\_neigh4\_hmap\_fprintf<!-- {{#callable_declaration:fd_neigh4_hmap_fprintf}} -->
Prints the IPv4 neighbor routing table to a specified file.
- **Description**: This function outputs the contents of an IPv4 neighbor routing table to a specified file in ASCII format with LF newlines. It should be used when there is a need to log or display the current state of the routing table. The order of the routes in the output is not defined but remains consistent across multiple calls. The function only operates on tables that are in the ACTIVE state. It returns 0 on success and an errno value if an error occurs during the printing process.
- **Inputs**:
    - `map`: A pointer to a constant fd_neigh4_hmap_t structure representing the IPv4 neighbor routing table. The table must be in the ACTIVE state for the function to operate correctly. The caller retains ownership and must ensure the pointer is valid.
    - `file`: A pointer to a FILE or equivalent where the routing table will be printed. The caller is responsible for ensuring this pointer is valid and open for writing. If the file operation fails, the function returns an errno value.
- **Output**: Returns 0 on success. If an error occurs during file operations, it returns the corresponding errno value.
- **See also**: [`fd_neigh4_hmap_fprintf`](fd_neigh4_map.c.driver.md#fd_neigh4_hmap_fprintf)  (Implementation)



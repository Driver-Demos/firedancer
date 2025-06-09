# Purpose
The provided C header file, `fd_netdev_tbl.h`, defines a network interface table API, which is primarily used for managing and interacting with network device configurations and their operational statuses. The file includes definitions for various operational states of network interfaces, as specified by RFC 2863, and structures to represent network devices (`fd_netdev_t`) and bonded network devices (`fd_netdev_bond_t`). The core component of this API is the `fd_netdev_tbl_t`, which is a table optimized for frequent reads and infrequent writes, designed to store and manage network device information efficiently. The API provides functions for creating, joining, leaving, deleting, and resetting these network device tables, ensuring that modifications are safely synchronized across threads by copying the entire table when necessary.

This header file is intended to be included in other C source files, providing a structured way to handle network device configurations and their states. It defines several constants, types, and function prototypes that form the public API for interacting with network device tables. The API includes functions for memory alignment and footprint calculation, table creation and deletion, and printing the table's contents. The file also includes a utility function to convert operational status codes to human-readable strings. Overall, this header file offers a comprehensive interface for managing network devices, focusing on efficient data handling and thread safety.
# Imports and Dependencies

---
- `../../util/fd_util_base.h`


# Global Variables

---
### fd\_netdev\_tbl\_new
- **Type**: `function pointer`
- **Description**: The `fd_netdev_tbl_new` is a function that initializes a memory region to be used as an empty network device table (`netdev_tbl`). It takes a pointer to shared memory (`shmem`), and two unsigned long integers (`dev_max` and `bond_max`) which specify the maximum number of devices and bond masters, respectively, that the table can accommodate.
- **Use**: This function is used to set up a network device table in a specified memory region, returning the memory pointer on success or NULL on failure.


---
### fd\_netdev\_tbl\_join
- **Type**: `fd_netdev_tbl_join_t *`
- **Description**: The `fd_netdev_tbl_join` is a function that returns a pointer to a `fd_netdev_tbl_join_t` structure. This structure is used to join a network device table, providing access to the table's header, device table, and bond table.
- **Use**: This function is used to join a network device table, writing object information to the provided `fd_netdev_tbl_join_t` structure.


---
### fd\_netdev\_tbl\_leave
- **Type**: `function pointer`
- **Description**: The `fd_netdev_tbl_leave` is a function that undoes a previous join operation on a network device table. It takes a pointer to a `fd_netdev_tbl_join_t` structure as an argument and returns a pointer to the memory region that was backing the join.
- **Use**: This function is used to leave a network device table, effectively reversing the join operation and returning control of the memory region to the caller.


---
### fd\_netdev\_tbl\_delete
- **Type**: `function pointer`
- **Description**: The `fd_netdev_tbl_delete` is a function that takes a pointer to a memory region (`shtbl`) and unformats the memory region backing a network device table (`netdev_tbl`). It returns ownership of the memory region back to the caller.
- **Use**: This function is used to delete a network device table by unformatting its memory region and returning the memory ownership to the caller.


---
### fd\_oper\_status\_cstr
- **Type**: `function`
- **Description**: The `fd_oper_status_cstr` function is a global function that takes an unsigned integer `oper_status` as an argument and returns a constant character pointer. This function is likely used to convert the operational status code of a network interface into a human-readable string representation.
- **Use**: This function is used to map operational status codes to their corresponding string descriptions, facilitating easier interpretation and debugging of network interface states.


# Data Structures

---
### fd\_netdev
- **Type**: `struct`
- **Members**:
    - `mtu`: Largest layer-3 payload that fits in a packet.
    - `mac_addr`: MAC address of the network device.
    - `if_idx`: Interface index of the network device.
    - `slave_tbl_idx`: Index to bond slave table, -1 if not a bond master.
    - `master_idx`: Index of bond master, -1 if not a bond slave.
    - `name`: C-string interface name with a maximum length of 15 characters.
    - `oper_status`: Operational status of the network device, represented by FD_OPER_STATUS_* constants.
    - `pad`: Padding to align the structure to 32 bytes.
- **Description**: The `fd_netdev` structure holds the basic configuration of a network device, including its maximum transmission unit (MTU), MAC address, interface index, and operational status. It also contains indices for bond master and slave relationships, allowing it to represent both standalone and bonded network interfaces. The structure is padded to ensure it aligns to 32 bytes, which can be important for performance and memory alignment on certain architectures.


---
### fd\_netdev\_t
- **Type**: `struct`
- **Members**:
    - `mtu`: Largest layer-3 payload that fits in a packet.
    - `mac_addr`: MAC address of the network device.
    - `if_idx`: Interface index of the network device.
    - `slave_tbl_idx`: Index to bond slave table, -1 if not a bond master.
    - `master_idx`: Index of bond master, -1 if not a bond slave.
    - `name`: C-string interface name with a maximum length of 15 characters.
    - `oper_status`: Operational status of the network device, represented by one of FD_OPER_STATUS_* constants.
    - `pad`: Padding to ensure the structure is 32 bytes in size.
- **Description**: The `fd_netdev_t` structure holds the basic configuration of a network device, including its maximum transmission unit (MTU), MAC address, interface index, and operational status. It also contains indices for bond master and slave relationships, if applicable, and a name for the interface. The structure is padded to ensure it is 32 bytes in size, which may be important for alignment or memory layout considerations.


---
### fd\_netdev\_bond
- **Type**: `struct`
- **Members**:
    - `slave_cnt`: Stores the count of active slave devices in the bond.
    - `slave_idx`: An array holding the indices of the active slave devices, with a maximum size defined by FD_NETDEV_BOND_SLAVE_MAX.
- **Description**: The `fd_netdev_bond` structure is used to represent a bonded network device, specifically listing its active slave devices. It contains a count of the active slaves and an array of indices pointing to these slaves, allowing for efficient management and reference of bonded network interfaces. This structure is part of a larger network device management system, facilitating the organization and operation of network bonds.


---
### fd\_netdev\_bond\_t
- **Type**: `struct`
- **Members**:
    - `slave_cnt`: The number of active slave devices in the bond.
    - `slave_idx`: An array of indices representing the active slave devices, with a maximum size defined by FD_NETDEV_BOND_SLAVE_MAX.
- **Description**: The `fd_netdev_bond_t` structure is used to represent a bonded network device, specifically listing the active slave devices associated with the bond. It contains a count of the active slaves and an array of indices that point to these slave devices, allowing for efficient management and access to the bonded network configuration.


---
### fd\_netdev\_tbl\_t
- **Type**: `struct`
- **Members**:
    - `dev_max`: Maximum number of network devices supported by the table.
    - `bond_max`: Maximum number of bond masters supported by the table.
    - `dev_cnt`: Current count of network devices in the table.
    - `bond_cnt`: Current count of bond masters in the table.
- **Description**: The `fd_netdev_tbl_t` is a data structure that represents a network interface table, optimized for frequent reads and rare writes. It is not thread-safe for in-place modifications, requiring a full copy for synchronization across threads. The table is designed to manage network devices and bond masters, with a header that tracks the maximum and current counts of these entities. The structure is part of a larger API that provides functions for creating, joining, leaving, deleting, and resetting the table, as well as printing its contents.


---
### fd\_netdev\_tbl\_hdr
- **Type**: `struct`
- **Members**:
    - `dev_max`: Maximum number of network devices supported.
    - `bond_max`: Maximum number of bond devices supported.
    - `dev_cnt`: Current count of network devices.
    - `bond_cnt`: Current count of bond devices.
- **Description**: The `fd_netdev_tbl_hdr` structure serves as a header for a network device table, providing metadata about the maximum and current number of network and bond devices managed by the table. It is used to track the capacity and utilization of the network device table, ensuring that operations on the table respect its limits.


---
### fd\_netdev\_tbl\_hdr\_t
- **Type**: `struct`
- **Members**:
    - `dev_max`: Maximum number of network devices supported by the table.
    - `bond_max`: Maximum number of bond devices supported by the table.
    - `dev_cnt`: Current count of network devices in the table.
    - `bond_cnt`: Current count of bond devices in the table.
- **Description**: The `fd_netdev_tbl_hdr_t` structure serves as a header for a network device table, providing metadata about the table's capacity and current usage. It includes fields to track the maximum and current number of network devices and bond devices, facilitating efficient management and access to network interface data within the table.


---
### fd\_netdev\_tbl\_join
- **Type**: `struct`
- **Members**:
    - `hdr`: A pointer to a header structure containing metadata about the network device and bond tables.
    - `dev_tbl`: A pointer to an array of network device structures.
    - `bond_tbl`: A pointer to an array of bond structures, each listing active slaves of a bond device.
- **Description**: The `fd_netdev_tbl_join` structure is designed to facilitate the joining of a network device table, providing pointers to the header, device table, and bond table. It acts as a composite structure that aggregates the essential components of a network interface table, allowing for efficient access and manipulation of network device and bond information. This structure is particularly useful in scenarios where frequent reads and rare writes are expected, as it provides a consolidated view of the network device and bond configurations.


---
### fd\_netdev\_tbl\_join\_t
- **Type**: `struct`
- **Members**:
    - `hdr`: Pointer to a header structure containing metadata about the network device table.
    - `dev_tbl`: Pointer to an array of network device configurations.
    - `bond_tbl`: Pointer to an array of bond device configurations.
- **Description**: The `fd_netdev_tbl_join_t` structure is used to represent a joined view of a network device table, which includes metadata, device configurations, and bond configurations. It is part of a system designed to manage network interfaces, providing a way to access and manipulate the network device and bond tables. This structure is typically used in conjunction with functions that manage the lifecycle of the network device table, such as joining, leaving, and resetting the table.


# Function Declarations (Public API)

---
### fd\_netdev\_tbl\_align<!-- {{#callable_declaration:fd_netdev_tbl_align}} -->
Returns the alignment requirement for a network device table.
- **Description**: Use this function to obtain the alignment requirement for memory regions intended to back a network device table. This is necessary when allocating memory for such tables to ensure proper alignment, which is crucial for performance and correctness on many systems. The function does not require any parameters and can be called at any time to retrieve the alignment value.
- **Inputs**: None
- **Output**: The function returns an unsigned long integer representing the alignment requirement, which is a constant value.
- **See also**: [`fd_netdev_tbl_align`](fd_netdev_tbl.c.driver.md#fd_netdev_tbl_align)  (Implementation)


---
### fd\_netdev\_tbl\_footprint<!-- {{#callable_declaration:fd_netdev_tbl_footprint}} -->
Calculate the memory footprint required for a network device table.
- **Description**: Use this function to determine the amount of memory needed to store a network device table with a specified maximum number of devices and bond masters. This is useful for allocating memory before initializing a network device table. The function requires valid input values for both `dev_max` and `bond_max`, which must be greater than zero and not exceed `USHORT_MAX`. If these conditions are not met, the function returns zero, indicating an invalid configuration.
- **Inputs**:
    - `dev_max`: The maximum number of network devices the table can hold. Must be greater than zero and not exceed USHORT_MAX. If invalid, the function returns zero.
    - `bond_max`: The maximum number of bond masters the table can hold. Must be greater than zero and not exceed USHORT_MAX. If invalid, the function returns zero.
- **Output**: Returns the size in bytes of the memory footprint required for the specified configuration, or zero if the input values are invalid.
- **See also**: [`fd_netdev_tbl_footprint`](fd_netdev_tbl.c.driver.md#fd_netdev_tbl_footprint)  (Implementation)


---
### fd\_netdev\_tbl\_new<!-- {{#callable_declaration:fd_netdev_tbl_new}} -->
Formats a memory region as an empty network device table.
- **Description**: This function initializes a memory region to serve as an empty network device table, which can manage up to `dev_max` network devices and `bond_max` bond masters. It should be called with a properly aligned memory region, as specified by `fd_netdev_tbl_align()`, and valid maximum counts for devices and bonds. The function returns a pointer to the initialized table on success, or NULL if any preconditions are not met, such as a NULL or misaligned memory region, or invalid maximum counts. This function is typically used during the setup phase of a network management application to prepare a data structure for tracking network interfaces.
- **Inputs**:
    - `shmem`: A pointer to a shared memory region where the table will be initialized. Must not be null and must be aligned according to `FD_NETDEV_TBL_ALIGN`.
    - `dev_max`: The maximum number of network devices the table can manage. Must be greater than 0 and less than or equal to `USHORT_MAX`.
    - `bond_max`: The maximum number of bond masters the table can manage. Must be greater than 0 and less than or equal to `USHORT_MAX`.
- **Output**: Returns a pointer to the initialized network device table on success, or NULL if initialization fails due to invalid input parameters.
- **See also**: [`fd_netdev_tbl_new`](fd_netdev_tbl.c.driver.md#fd_netdev_tbl_new)  (Implementation)


---
### fd\_netdev\_tbl\_leave<!-- {{#callable_declaration:fd_netdev_tbl_leave}} -->
Releases a network device table join.
- **Description**: Use this function to release a previously joined network device table, effectively undoing the join operation. This function should be called when the network device table is no longer needed, allowing the caller to regain ownership of the memory region backing the join. It is important to note that this function returns the join pointer, not the original shared table pointer.
- **Inputs**:
    - `join`: A pointer to a `fd_netdev_tbl_join_t` structure representing the joined network device table. Must not be null, as the function assumes a valid join structure is provided.
- **Output**: Returns the `join` pointer, indicating the caller regains ownership of the memory region backing the join.
- **See also**: [`fd_netdev_tbl_leave`](fd_netdev_tbl.c.driver.md#fd_netdev_tbl_leave)  (Implementation)


---
### fd\_netdev\_tbl\_delete<!-- {{#callable_declaration:fd_netdev_tbl_delete}} -->
Unformats a network device table and returns ownership of the memory region.
- **Description**: Use this function to unformat a previously formatted network device table, effectively marking it as no longer in use. This function should be called when the table is no longer needed, allowing the caller to reclaim the memory region for other purposes. It is important to ensure that the table is not in use by any other operations or threads before calling this function. The function will log a warning and return NULL if the provided table pointer is NULL.
- **Inputs**:
    - `shtbl`: A pointer to the memory region backing the network device table. Must not be NULL. If NULL, the function logs a warning and returns NULL. The caller retains ownership of the memory.
- **Output**: Returns the original pointer to the memory region on success, or NULL if the input was NULL.
- **See also**: [`fd_netdev_tbl_delete`](fd_netdev_tbl.c.driver.md#fd_netdev_tbl_delete)  (Implementation)


---
### fd\_netdev\_tbl\_reset<!-- {{#callable_declaration:fd_netdev_tbl_reset}} -->
Resets the network device table to an empty state.
- **Description**: Use this function to clear all entries in a network device table, effectively resetting it to its initial empty state. This is useful when you need to reinitialize the table without deallocating and reallocating memory. The function sets the device and bond counts to zero and clears all entries in the device and bond tables. It should be called when the table is not being accessed by other threads, as the operation is not thread-safe.
- **Inputs**:
    - `tbl`: A pointer to a `fd_netdev_tbl_join_t` structure representing the network device table to reset. The pointer must not be null, and the table should be properly initialized before calling this function. The caller retains ownership of the memory.
- **Output**: None
- **See also**: [`fd_netdev_tbl_reset`](fd_netdev_tbl.c.driver.md#fd_netdev_tbl_reset)  (Implementation)


---
### fd\_netdev\_tbl\_fprintf<!-- {{#callable_declaration:fd_netdev_tbl_fprintf}} -->
Prints the network interface table to a specified file.
- **Description**: Use this function to output the current state of a network interface table to a specified file or file-like object. It is useful for logging or debugging purposes when you need a human-readable representation of the network interfaces and their statuses. The function iterates over the network devices in the table and prints details such as the device name, MTU, operational status, and MAC address. If a device is part of a bond, it also prints information about the bond and its slaves. The function expects a valid network interface table and a writable file pointer. It returns 0 on success and an error code on failure.
- **Inputs**:
    - `tbl`: A pointer to a `fd_netdev_tbl_join_t` structure representing the network interface table to be printed. Must not be null and should be properly initialized before calling this function.
    - `file`: A pointer to a `FILE` or equivalent writable file-like object where the output will be written. Must not be null and should be open for writing.
- **Output**: Returns 0 on success. On failure, it returns an error code indicating the type of error encountered.
- **See also**: [`fd_netdev_tbl_fprintf`](fd_netdev_tbl.c.driver.md#fd_netdev_tbl_fprintf)  (Implementation)


---
### fd\_oper\_status\_cstr<!-- {{#callable_declaration:fd_oper_status_cstr}} -->
Convert an operational status code to a human-readable string.
- **Description**: Use this function to obtain a human-readable string that describes the operational status of a network interface, based on a given status code. This is useful for logging, debugging, or displaying status information to users. The function maps predefined status codes to their corresponding string representations. If the provided status code does not match any known status, the function returns "unknown". This function is read-only and does not modify any input data.
- **Inputs**:
    - `oper_status`: An unsigned integer representing the operational status code of a network interface. Valid values are defined as FD_OPER_STATUS_* constants, such as FD_OPER_STATUS_UP, FD_OPER_STATUS_DOWN, etc. If the value does not match any of these constants, the function will return "unknown".
- **Output**: A constant character pointer to a string representing the human-readable form of the operational status. Possible return values include "up", "down", "testing", "dormant", "not present", "lower layer down", and "unknown".
- **See also**: [`fd_oper_status_cstr`](fd_netdev_tbl.c.driver.md#fd_oper_status_cstr)  (Implementation)



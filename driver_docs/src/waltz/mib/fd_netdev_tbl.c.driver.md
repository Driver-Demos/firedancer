# Purpose
This C source code file is designed to manage a network device table, providing functionality for creating, joining, resetting, and deleting network device tables. The code defines a private structure `fd_netdev_tbl_private` to encapsulate the metadata and offsets for device and bond tables. It includes functions such as [`fd_netdev_tbl_new`](#fd_netdev_tbl_new) for initializing a new network device table in shared memory, [`fd_netdev_tbl_join`](#fd_netdev_tbl_join) for accessing the table, and [`fd_netdev_tbl_reset`](#fd_netdev_tbl_reset) for resetting the table's device and bond counts. The code also includes a function [`fd_netdev_tbl_fprintf`](#fd_netdev_tbl_fprintf) for printing the status of network devices to a file, which is conditionally compiled if the `FD_HAS_HOSTED` macro is defined. This suggests that the code is intended to be used in both hosted and non-hosted environments.

The file is part of a larger system, as indicated by the inclusion of headers like "fd_netdev_tbl.h" and "../../util/fd_util.h". It provides a narrow but essential functionality focused on managing network device tables, which are likely used in a broader network management or monitoring application. The code ensures memory alignment and checks for valid input parameters, emphasizing robustness and error handling. The presence of macros like `FD_UNLIKELY` and `FD_LOG_WARNING` suggests performance optimization and logging capabilities. The file does not define a public API but rather implements internal functions that are likely used by other components of the system to manage network device configurations and states.
# Imports and Dependencies

---
- `fd_netdev_tbl.h`
- `../../util/fd_util.h`
- `errno.h`
- `stdio.h`
- `../../util/net/fd_eth.h`


# Data Structures

---
### fd\_netdev\_tbl\_private
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier used to verify the integrity of the structure.
    - `dev_off`: Offset from the start of the structure to the device table.
    - `bond_off`: Offset from the start of the structure to the bond table.
    - `hdr`: Header containing metadata about the device and bond tables.
- **Description**: The `fd_netdev_tbl_private` structure is a private data structure used to manage network device tables. It contains a magic number for integrity verification, offsets to locate device and bond tables within a shared memory segment, and a header that holds metadata such as the maximum number of devices and bonds, as well as their current counts. This structure is integral to the management and manipulation of network devices and their bonding configurations in a shared memory context.


# Functions

---
### fd\_netdev\_tbl\_align<!-- {{#callable:fd_netdev_tbl_align}} -->
The `fd_netdev_tbl_align` function returns the alignment requirement for a network device table.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of the macro `FD_NETDEV_TBL_ALIGN`.
- **Output**: The function outputs an `ulong` representing the alignment requirement for a network device table.


---
### fd\_netdev\_tbl\_footprint<!-- {{#callable:fd_netdev_tbl_footprint}} -->
The `fd_netdev_tbl_footprint` function calculates the memory footprint required for a network device table based on the maximum number of devices and bonds.
- **Inputs**:
    - `dev_max`: The maximum number of network devices that the table can accommodate.
    - `bond_max`: The maximum number of network device bonds that the table can accommodate.
- **Control Flow**:
    - Check if `dev_max` is zero or exceeds `USHORT_MAX`; if so, return 0.
    - Check if `bond_max` is zero or exceeds `USHORT_MAX`; if so, return 0.
    - Calculate the memory footprint using a series of layout append operations, starting with `FD_LAYOUT_INIT` and appending the sizes and alignments of `fd_netdev_tbl_t`, `fd_netdev_t` multiplied by `dev_max`, and `fd_netdev_bond_t` multiplied by `bond_max`, then finalize with `FD_LAYOUT_FINI`.
- **Output**: Returns the calculated memory footprint as an unsigned long integer, or 0 if the input constraints are not met.


---
### fd\_netdev\_tbl\_new<!-- {{#callable:fd_netdev_tbl_new}} -->
The `fd_netdev_tbl_new` function initializes a new network device table in shared memory, ensuring proper alignment and valid input parameters.
- **Inputs**:
    - `shmem`: A pointer to the shared memory where the network device table will be allocated.
    - `dev_max`: The maximum number of network devices that the table can accommodate, must be greater than 0 and less than or equal to USHORT_MAX.
    - `bond_max`: The maximum number of network device bonds that the table can accommodate, must be greater than 0 and less than or equal to USHORT_MAX.
- **Control Flow**:
    - Check if `shmem` is NULL and log a warning if it is, returning NULL.
    - Verify that `shmem` is properly aligned to `FD_NETDEV_TBL_ALIGN` and log a warning if it is not, returning NULL.
    - Ensure `dev_max` is within valid range (greater than 0 and less than or equal to USHORT_MAX) and log a warning if it is not, returning NULL.
    - Ensure `bond_max` is within valid range (greater than 0 and less than or equal to USHORT_MAX) and log a warning if it is not, returning NULL.
    - Initialize scratch memory allocation with `FD_SCRATCH_ALLOC_INIT`.
    - Allocate memory for the network device table, devices, and bonds using `FD_SCRATCH_ALLOC_APPEND`.
    - Finalize the scratch memory allocation with `FD_SCRATCH_ALLOC_FINI`.
    - Initialize the network device table structure with magic number, offsets, and header information.
    - Join the network device table, reset it, and then leave it using [`fd_netdev_tbl_join`](#fd_netdev_tbl_join), [`fd_netdev_tbl_reset`](#fd_netdev_tbl_reset), and [`fd_netdev_tbl_leave`](#fd_netdev_tbl_leave).
    - Return the pointer to the initialized network device table.
- **Output**: A pointer to the newly created and initialized network device table, or NULL if any validation checks fail.
- **Functions called**:
    - [`fd_netdev_tbl_join`](#fd_netdev_tbl_join)
    - [`fd_netdev_tbl_reset`](#fd_netdev_tbl_reset)
    - [`fd_netdev_tbl_leave`](#fd_netdev_tbl_leave)


---
### fd\_netdev\_tbl\_join<!-- {{#callable:fd_netdev_tbl_join}} -->
The `fd_netdev_tbl_join` function initializes a `fd_netdev_tbl_join_t` structure by linking it to an existing shared network device table, ensuring the table's validity through a magic number check.
- **Inputs**:
    - `ljoin`: A pointer to a `fd_netdev_tbl_join_t` structure that will be initialized and returned.
    - `shtbl`: A pointer to a shared network device table (`fd_netdev_tbl_t`) that the join structure will be linked to.
- **Control Flow**:
    - Check if `shtbl` is NULL; if so, log a warning and return NULL.
    - Cast `ljoin` to a `fd_netdev_tbl_join_t` pointer and `shtbl` to a `fd_netdev_tbl_t` pointer.
    - Verify the magic number of the table; if it does not match `FD_NETDEV_TBL_MAGIC`, log a warning and return NULL.
    - Initialize the `fd_netdev_tbl_join_t` structure with pointers to the header, device table, and bond table of the shared table.
    - Return the initialized `fd_netdev_tbl_join_t` pointer.
- **Output**: Returns a pointer to the initialized `fd_netdev_tbl_join_t` structure, or NULL if the input table is invalid.


---
### fd\_netdev\_tbl\_leave<!-- {{#callable:fd_netdev_tbl_leave}} -->
The `fd_netdev_tbl_leave` function returns the pointer to the `fd_netdev_tbl_join_t` structure passed to it.
- **Inputs**:
    - `join`: A pointer to an `fd_netdev_tbl_join_t` structure, which represents a joined network device table.
- **Control Flow**:
    - The function takes a single argument, `join`, which is a pointer to an `fd_netdev_tbl_join_t` structure.
    - It simply returns the `join` pointer without performing any operations on it.
- **Output**: The function returns the same pointer to `fd_netdev_tbl_join_t` that was passed as an argument.


---
### fd\_netdev\_tbl\_delete<!-- {{#callable:fd_netdev_tbl_delete}} -->
The `fd_netdev_tbl_delete` function invalidates a network device table by setting its magic number to zero and returns the table pointer.
- **Inputs**:
    - `shtbl`: A pointer to the shared memory table (`fd_netdev_tbl_t`) to be deleted.
- **Control Flow**:
    - Check if the input `shtbl` is NULL; if so, log a warning and return NULL.
    - Cast the input `shtbl` to a `fd_netdev_tbl_t` pointer.
    - Set the `magic` field of the table to 0, effectively invalidating it.
    - Return the pointer to the table.
- **Output**: Returns the pointer to the invalidated network device table, or NULL if the input was NULL.


---
### fd\_netdev\_tbl\_reset<!-- {{#callable:fd_netdev_tbl_reset}} -->
The `fd_netdev_tbl_reset` function resets a network device table by clearing device and bond counts and initializing device and bond entries to default values.
- **Inputs**:
    - `tbl`: A pointer to an `fd_netdev_tbl_join_t` structure representing the network device table to be reset.
- **Control Flow**:
    - Set the device count (`dev_cnt`) in the table header to 0.
    - Set the bond count (`bond_cnt`) in the table header to 0.
    - Iterate over each device entry up to the maximum number of devices (`dev_max`) and set each device's `master_idx` and `slave_tbl_idx` to -1, indicating uninitialized or default state.
    - Use `fd_memset` to zero out the bond table, effectively resetting all bond entries to their default state.
- **Output**: The function does not return a value; it modifies the input `fd_netdev_tbl_join_t` structure in place.


---
### fd\_netdev\_tbl\_fprintf<!-- {{#callable:fd_netdev_tbl_fprintf}} -->
The `fd_netdev_tbl_fprintf` function prints the details of network devices from a network device table to a specified file stream.
- **Inputs**:
    - `tbl`: A pointer to a `fd_netdev_tbl_join_t` structure representing the network device table to be printed.
    - `file_`: A pointer to a `FILE` stream where the network device information will be printed.
- **Control Flow**:
    - Initialize a `FILE` pointer from the `file_` argument.
    - Iterate over each network device in the `tbl` using a loop from 0 to `tbl->hdr->dev_cnt`.
    - For each device, check if the `oper_status` is non-zero; if zero, skip to the next device.
    - Print the device index, name, MTU, operational status, and its string representation using `WRAP_PRINTF`.
    - If the device is a slave (indicated by `slave_tbl_idx >= 0`), print 'master' using `WRAP_PRINT`.
    - Print the device's MAC address using `WRAP_PRINTF`.
    - If the device is a slave and has associated slaves in the bond table, print the number of slaves and their indices and names using nested loops and `WRAP_PRINTF`.
    - Return 0 to indicate successful completion.
- **Output**: Returns 0 on successful printing of all network device information to the specified file stream.
- **Functions called**:
    - [`fd_oper_status_cstr`](#fd_oper_status_cstr)


---
### fd\_oper\_status\_cstr<!-- {{#callable:fd_oper_status_cstr}} -->
The `fd_oper_status_cstr` function converts an operational status code into a human-readable string representation.
- **Inputs**:
    - `oper_status`: An unsigned integer representing the operational status code of a network device.
- **Control Flow**:
    - The function uses a switch statement to match the input `oper_status` with predefined status codes.
    - If `oper_status` matches `FD_OPER_STATUS_UP`, the function returns the string "up".
    - If `oper_status` matches `FD_OPER_STATUS_DOWN`, the function returns the string "down".
    - If `oper_status` matches `FD_OPER_STATUS_TESTING`, the function returns the string "testing".
    - If `oper_status` matches `FD_OPER_STATUS_DORMANT`, the function returns the string "dormant".
    - If `oper_status` matches `FD_OPER_STATUS_NOT_PRESENT`, the function returns the string "not present".
    - If `oper_status` matches `FD_OPER_STATUS_LOWER_LAYER_DOWN`, the function returns the string "lower layer down".
    - If `oper_status` matches `FD_OPER_STATUS_UNKNOWN` or any other value, the function returns the string "unknown".
- **Output**: A constant character pointer to a string that describes the operational status.



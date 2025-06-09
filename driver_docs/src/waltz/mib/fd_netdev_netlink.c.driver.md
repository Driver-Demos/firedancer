# Purpose
The provided C source code file is designed to interact with the Linux kernel's networking subsystem using the Netlink protocol. It primarily focuses on retrieving and processing network device information, such as interface names, MAC addresses, operational states, and MTU sizes. The code is structured to work specifically on Linux systems, as indicated by the preprocessor directive that checks for a Linux environment. The main function, [`fd_netdev_netlink_load_table`](#fd_netdev_netlink_load_table), sends a Netlink request to obtain a list of network interfaces and iterates over the responses to populate a network device table (`fd_netdev_tbl_join_t`). This table is used to store detailed information about each network interface, including its operational status and any associated bonding configurations.

The file includes several key components, such as the initialization of network device structures and the translation of Linux-specific operational states to a more generic format. It also handles error checking and logging to ensure robust communication with the Netlink interface. The code is part of a larger system, likely a network management or monitoring tool, and is intended to be compiled and executed on Linux systems. It does not define public APIs or external interfaces but rather serves as an internal component for managing network device information within the application.
# Imports and Dependencies

---
- `fd_netdev_netlink.h`
- `../../util/fd_util.h`
- `fd_netdev_tbl.h`
- `errno.h`
- `linux/if.h`
- `linux/if_arp.h`
- `linux/rtnetlink.h`


# Functions

---
### fd\_netdev\_init<!-- {{#callable:fd_netdev_init}} -->
The `fd_netdev_init` function initializes a `fd_netdev_t` structure with default values.
- **Inputs**:
    - `netdev`: A pointer to a `fd_netdev_t` structure that will be initialized.
- **Control Flow**:
    - The function assigns default values to the fields of the `fd_netdev_t` structure pointed to by `netdev`.
    - The fields are set as follows: `mtu` to 1500, `if_idx` to 0, `slave_tbl_idx` to -1, `master_idx` to -1, and `oper_status` to `FD_OPER_STATUS_INVALID`.
    - The function then returns the pointer to the initialized `fd_netdev_t` structure.
- **Output**: A pointer to the initialized `fd_netdev_t` structure.


---
### ifoper\_to\_oper\_status<!-- {{#callable:ifoper_to_oper_status}} -->
The function `ifoper_to_oper_status` maps Linux interface operational status codes to their corresponding RFC 2863 operational status codes.
- **Inputs**:
    - `if_oper`: An unsigned integer representing the Linux interface operational status code.
- **Control Flow**:
    - The function uses a switch statement to match the input `if_oper` against predefined Linux operational status codes.
    - For each case, it returns the corresponding RFC 2863 operational status code.
    - If the input does not match any predefined case, it defaults to returning `FD_OPER_STATUS_INVALID`.
- **Output**: The function returns an unsigned character representing the RFC 2863 operational status code corresponding to the input Linux operational status code.


---
### fd\_netdev\_netlink\_load\_table<!-- {{#callable:fd_netdev_netlink_load_table}} -->
The function `fd_netdev_netlink_load_table` populates a network device table by sending a netlink request to retrieve network interface information and processing the response.
- **Inputs**:
    - `tbl`: A pointer to an `fd_netdev_tbl_join_t` structure, which represents the network device table to be populated.
    - `netlink`: A pointer to an `fd_netlink_t` structure, which contains the file descriptor and sequence number for the netlink communication.
- **Control Flow**:
    - Reset the network device table using [`fd_netdev_tbl_reset`](fd_netdev_tbl.c.driver.md#fd_netdev_tbl_reset).
    - Increment the sequence number in the `netlink` structure.
    - Prepare a netlink request message to get link information using `RTM_GETLINK`.
    - Send the request using `sendto` and check for errors in sending.
    - Initialize a buffer and an iterator for processing netlink messages.
    - Iterate over the received netlink messages using `fd_netlink_iter_init`, `fd_netlink_iter_done`, and `fd_netlink_iter_next`.
    - For each message, check for errors and process only `RTM_NEWLINK` messages.
    - For each valid message, extract interface information and attributes, and populate a `fd_netdev_t` structure.
    - Check and handle various attributes like interface name, MAC address, operational state, MTU, and master index.
    - Update the network device table with the populated `fd_netdev_t` structure.
    - After processing all messages, iterate over the device table to establish bond master-slave relationships.
    - Return 0 on success or an error code on failure.
- **Output**: Returns 0 on success, or an error code if an error occurs during the netlink communication or processing.
- **Functions called**:
    - [`fd_netdev_tbl_reset`](fd_netdev_tbl.c.driver.md#fd_netdev_tbl_reset)
    - [`fd_netdev_init`](#fd_netdev_init)
    - [`ifoper_to_oper_status`](#ifoper_to_oper_status)



# Purpose
This C header file, `fd_fib4_netlink.h`, provides an interface for importing routing information from the Linux netlink system into a Forwarding Information Base (FIB) for IPv4. It is specifically designed for use on Linux systems, as indicated by the conditional compilation directive `#if defined(__linux__)`. The file defines several error codes (`FD_FIB_NETLINK_*`) to handle various outcomes of the netlink import operations, such as success, internal errors, I/O errors, interruptions, and insufficient space in the FIB. The primary function, [`fd_fib4_netlink_load_table`](#fd_fib4_netlink_load_table), is responsible for mirroring a specified route table from netlink into a FIB object, with the ability to handle common routing tables like `RT_TABLE_LOCAL` and `RT_TABLE_MAIN`. Additionally, the file provides a function, [`fd_fib4_netlink_strerror`](#fd_fib4_netlink_strerror), to convert error codes into human-readable strings, aiding in debugging and error handling.
# Imports and Dependencies

---
- `fd_fib4.h`
- `fd_netlink1.h`


# Global Variables

---
### fd\_fib4\_netlink\_strerror
- **Type**: `function pointer`
- **Description**: `fd_fib4_netlink_strerror` is a function that returns a constant character pointer, which is typically used to provide a human-readable string description of an error code related to netlink operations. This function is marked with `FD_FN_CONST`, indicating that it does not modify any global state and its return value depends only on its parameters.
- **Use**: This function is used to convert error codes from netlink operations into descriptive error messages.


# Function Declarations (Public API)

---
### fd\_fib4\_netlink\_load\_table<!-- {{#callable_declaration:fd_fib4_netlink_load_table}} -->
Mirrors a route table from netlink to a fib4 object.
- **Description**: This function is used to import and mirror a specified IPv4 route table from the Linux netlink interface into a fib4 object. It should be called when you need to synchronize the fib4 object with the current state of a netlink route table, typically identified by table_id values like RT_TABLE_LOCAL or RT_TABLE_MAIN. The function requires a valid, writable join to a fib4 object and a netlink object with a usable rtnetlink socket. It logs diagnostic information at the debug level and errors at the warning level. On success, the fib4 object will reflect the route table, although unsupported routes may be converted to blackhole routes. On failure, the fib4 object will be left in a state that blackholes all packets, and specific error codes will indicate the nature of the failure.
- **Inputs**:
    - `fib`: A pointer to a fd_fib4_t object that is writable and joined. The caller retains ownership and must ensure it is valid and properly initialized.
    - `netlink`: A pointer to a fd_netlink_t object with a usable rtnetlink socket. The caller retains ownership and must ensure it is valid and properly initialized.
    - `table_id`: An unsigned integer representing the ID of the route table to be mirrored. Valid values are in the range [0, 2^31), typically RT_TABLE_LOCAL (255) or RT_TABLE_MAIN (254).
- **Output**: Returns FD_FIB_NETLINK_SUCCESS on success, with the fib object reflecting the route table. On failure, returns an error code such as FD_FIB_NETLINK_ERR_OOPS, FD_FIB_NETLINK_ERR_IO, FD_FIB_NETLINK_ERR_INTR, or FD_FIB_NETLINK_ERR_SPACE, indicating the type of error encountered.
- **See also**: [`fd_fib4_netlink_load_table`](fd_fib4_netlink.c.driver.md#fd_fib4_netlink_load_table)  (Implementation)


---
### fd\_fib4\_netlink\_strerror<!-- {{#callable_declaration:fd_fib4_netlink_strerror}} -->
Returns a human-readable string describing a netlink error code.
- **Description**: Use this function to obtain a descriptive string for a given netlink error code, which can be useful for logging or debugging purposes. It translates known error codes into human-readable messages, such as 'success' or 'io', and returns 'unknown' for any unrecognized error codes. This function is particularly useful when handling the results of netlink operations, allowing developers to understand and communicate the nature of errors more effectively.
- **Inputs**:
    - `err`: An integer representing the netlink error code. Valid values are FD_FIB_NETLINK_SUCCESS, FD_FIB_NETLINK_ERR_OOPS, FD_FIB_NETLINK_ERR_IO, FD_FIB_NETLINK_ERR_INTR, and FD_FIB_NETLINK_ERR_SPACE. If an unrecognized error code is provided, the function returns 'unknown'.
- **Output**: A constant string describing the error code, such as 'success', 'oops', 'io', 'interrupt', 'out of space', or 'unknown' for unrecognized codes.
- **See also**: [`fd_fib4_netlink_strerror`](fd_fib4_netlink.c.driver.md#fd_fib4_netlink_strerror)  (Implementation)



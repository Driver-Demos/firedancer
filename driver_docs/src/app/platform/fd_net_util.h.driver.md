# Purpose
This C header file, `fd_net_util.h`, provides utility functions for network interface and namespace management. It includes functions to determine the network interface index (`ifindex`) that routes to a specific public IP address (8.8.8.8), enter a specified network namespace, restore the original network namespace, and retrieve the IP address of a given network interface. Each function returns zero on success and -1 on failure, with `errno` set to indicate the error. The file is designed to facilitate network configuration and management tasks, particularly in environments where network namespaces are used to isolate network resources.
# Imports and Dependencies

---
- `../../util/fd_util.h`


# Function Declarations (Public API)

---
### fd\_net\_util\_internet\_ifindex<!-- {{#callable_declaration:fd_net_util_internet_ifindex}} -->
Retrieve the interface index for routing to the public internet.
- **Description**: This function is used to determine the network interface index (ifindex) that routes to the public internet, specifically to the IP address 8.8.8.8. It is useful for applications that need to identify the primary network interface used for internet connectivity. The function should be called when the caller needs to know which interface is used for routing to the internet. It returns zero on success, writing the ifindex to the provided pointer. If no suitable interface is found, or if an error occurs, it returns -1 and sets errno to indicate the error, such as ENODEV if no interface is found.
- **Inputs**:
    - `ifindex`: A pointer to an unsigned integer where the function will store the interface index. Must not be null. On success, the ifindex is written to this location. On failure, the value is undefined.
- **Output**: Returns 0 on success with the ifindex written to the provided pointer. Returns -1 on failure, with errno set to indicate the error.
- **See also**: [`fd_net_util_internet_ifindex`](fd_net_util.c.driver.md#fd_net_util_internet_ifindex)  (Implementation)


---
### fd\_net\_util\_netns\_enter<!-- {{#callable_declaration:fd_net_util_netns_enter}} -->
Attempts to enter the specified network namespace.
- **Description**: This function is used to change the network namespace of the calling process to the one specified by the given name. It should be used when a process needs to operate within a different network namespace. If the `original_netns` parameter is provided, the function attempts to store the file descriptor of the current network namespace, allowing the caller to restore it later. The caller is responsible for closing this file descriptor when it is no longer needed. On failure, the function returns -1 and sets `errno` appropriately, but the process might still have entered the new network namespace, so the caller should not assume any valid state and may need to abort.
- **Inputs**:
    - `name`: A string representing the name of the network namespace to enter. It must not be null and should correspond to a valid network namespace path under '/var/run/netns/'. If the name is too long, the function returns -1 and sets `errno` to `ENAMETOOLONG`.
    - `original_netns`: A pointer to an integer where the file descriptor of the original network namespace will be stored if not null. The caller retains ownership and must close this file descriptor when it is no longer needed. If null, the original network namespace is not saved.
- **Output**: Returns 0 on success, indicating the process is now in the specified network namespace. Returns -1 on failure, with `errno` set appropriately. The original network namespace file descriptor may be set even if the function fails.
- **See also**: [`fd_net_util_netns_enter`](fd_net_util.c.driver.md#fd_net_util_netns_enter)  (Implementation)


---
### fd\_net\_util\_netns\_restore<!-- {{#callable_declaration:fd_net_util_netns_restore}} -->
Attempts to restore the calling process to the original network namespace.
- **Description**: This function is used to revert the calling process back to its original network namespace using a file descriptor obtained from a previous call to `fd_net_util_netns_enter()`. It should be called when the process needs to exit a temporary network namespace and return to its original state. The function closes the provided file descriptor upon successful execution, so the caller does not need to manage its closure. If the function fails, it returns -1 and sets errno, but the process might still have entered the original network namespace, leaving the caller in an uncertain state. Therefore, on failure, the caller should not assume any valid state and may need to abort.
- **Inputs**:
    - `original_fd`: The file descriptor to the original network namespace, obtained from `fd_net_util_netns_enter()`. It must be a valid file descriptor. The function will close this descriptor on success, so the caller should not attempt to close it afterwards.
- **Output**: Returns 0 on success, indicating the process is now in the original network namespace. Returns -1 on failure, with errno set appropriately. The original file descriptor is closed on success.
- **See also**: [`fd_net_util_netns_restore`](fd_net_util.c.driver.md#fd_net_util_netns_restore)  (Implementation)


---
### fd\_net\_util\_if\_addr<!-- {{#callable_declaration:fd_net_util_if_addr}} -->
Attempts to get the IP address of the provided interface.
- **Description**: Use this function to retrieve the IP address associated with a specific network interface. It is useful when you need to programmatically determine the IP address assigned to a network interface on the system. The function must be called with a valid network interface name. On success, the IP address is stored in the provided pointer. If the function fails, it returns -1 and sets errno to indicate the error, leaving the value pointed to by addr undefined.
- **Inputs**:
    - `interface`: A string representing the name of the network interface whose IP address is to be retrieved. It must be a valid interface name and must not be null. The function does not modify the string.
    - `addr`: A pointer to an unsigned integer where the IP address of the interface will be stored on success. The pointer must not be null. On failure, the value pointed to by addr is undefined.
- **Output**: Returns 0 on success, with the IP address written to the location pointed to by addr. Returns -1 on failure, with errno set to indicate the error.
- **See also**: [`fd_net_util_if_addr`](fd_net_util.c.driver.md#fd_net_util_if_addr)  (Implementation)



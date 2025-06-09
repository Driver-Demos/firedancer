# Purpose
This C source code file provides a set of utility functions for network namespace management and network interface operations. The primary functionality includes entering and restoring network namespaces, retrieving the index of the default internet interface, and obtaining the IP address of a specified network interface. The file is designed to be part of a larger system, likely a network management or configuration tool, and is intended to be included and used by other C programs rather than being an executable itself.

The key technical components of this file include system calls and network-related operations. The [`fd_net_util_netns_enter`](#fd_net_util_netns_enter) and [`fd_net_util_netns_restore`](#fd_net_util_netns_restore) functions manage network namespaces, allowing the program to switch between different network environments. The [`fd_net_util_internet_ifindex`](#fd_net_util_internet_ifindex) function uses netlink sockets to query the system for the default internet interface index, while [`fd_net_util_if_addr`](#fd_net_util_if_addr) retrieves the IP address of a specified network interface using ioctl system calls. These functions interact with low-level network interfaces and system resources, making them crucial for applications that require precise control over network configurations.
# Imports and Dependencies

---
- `fd_net_util.h`
- `fcntl.h`
- `errno.h`
- `sched.h`
- `unistd.h`
- `net/if.h`
- `sys/ioctl.h`
- `sys/socket.h`
- `linux/netlink.h`
- `linux/rtnetlink.h`
- `netinet/in.h`


# Functions

---
### fd\_net\_util\_netns\_enter<!-- {{#callable:fd_net_util_netns_enter}} -->
The `fd_net_util_netns_enter` function switches the current process to a specified network namespace and optionally saves the original namespace for later restoration.
- **Inputs**:
    - `name`: A constant character pointer representing the name of the network namespace to enter.
    - `original_netns`: An integer pointer where the file descriptor of the original network namespace will be stored if not NULL.
- **Control Flow**:
    - Constructs the path to the network namespace using the provided name and checks if it fits within the buffer size.
    - If `original_netns` is not NULL, opens the current network namespace and stores its file descriptor in `_original_netns`.
    - Opens the target network namespace specified by the constructed path.
    - Attempts to switch to the target network namespace using `setns`.
    - If `original_netns` is not NULL, stores the file descriptor of the original namespace in `original_netns`.
    - Closes the file descriptor for the target network namespace.
    - Creates a dummy socket to bring the loopback interface up using `ioctl`.
    - Returns 0 on success or -1 on failure, setting `errno` appropriately.
- **Output**: Returns 0 on success, or -1 on failure with `errno` set to indicate the error.


---
### fd\_net\_util\_netns\_restore<!-- {{#callable:fd_net_util_netns_restore}} -->
The `fd_net_util_netns_restore` function restores the network namespace to its original state using a file descriptor and then closes the file descriptor.
- **Inputs**:
    - `original_fd`: An integer representing the file descriptor of the original network namespace to be restored.
- **Control Flow**:
    - Check if setting the network namespace using `setns` with `original_fd` and `CLONE_NEWNET` fails; if so, return -1.
    - Attempt to close the file descriptor `original_fd`; if this fails, return -1.
    - If both operations succeed, return 0.
- **Output**: Returns 0 on success, or -1 if an error occurs during setting the network namespace or closing the file descriptor.


---
### fd\_net\_util\_internet\_ifindex<!-- {{#callable:fd_net_util_internet_ifindex}} -->
The function `fd_net_util_internet_ifindex` retrieves the interface index of the default internet route using netlink sockets.
- **Inputs**:
    - `ifindex`: A pointer to an unsigned integer where the function will store the interface index of the default internet route.
- **Control Flow**:
    - Create a netlink socket for route communication.
    - Initialize a netlink request message to get the route for the IP address 8.8.8.8.
    - Send the netlink request message through the socket.
    - Receive the response from the netlink socket into a buffer.
    - Parse the response to find the route attribute of type RTA_OIF, which contains the interface index.
    - Close the netlink socket.
    - If a valid interface index is found, store it in the provided `ifindex` pointer and return 0; otherwise, set `errno` to ENODEV and return -1.
- **Output**: Returns 0 on success with the interface index stored in `ifindex`, or -1 on failure with `errno` set appropriately.


---
### fd\_net\_util\_if\_addr<!-- {{#callable:fd_net_util_if_addr}} -->
The `fd_net_util_if_addr` function retrieves the IPv4 address of a specified network interface and stores it in the provided address variable.
- **Inputs**:
    - `interface`: A constant character pointer representing the name of the network interface whose IP address is to be retrieved.
    - `addr`: A pointer to an unsigned integer where the retrieved IP address will be stored.
- **Control Flow**:
    - Create a socket using the `AF_INET` domain and `SOCK_DGRAM` type.
    - Check if the socket creation was successful; if not, return -1.
    - Initialize a `struct ifreq` and set its address family to `AF_INET`.
    - Copy the interface name into the `ifr_name` field of the `struct ifreq`, ensuring it is null-terminated.
    - Use the `ioctl` function with `SIOCGIFADDR` to retrieve the IP address of the specified interface.
    - Check if the `ioctl` call was successful; if not, return -1.
    - Close the socket and check if the close operation was successful; if not, return -1.
    - Extract the IP address from the `ifr_addr` field of the `struct ifreq` and store it in the provided `addr` variable.
    - Return 0 to indicate success.
- **Output**: Returns 0 on success, with the IP address stored in the `addr` variable; returns -1 on failure.



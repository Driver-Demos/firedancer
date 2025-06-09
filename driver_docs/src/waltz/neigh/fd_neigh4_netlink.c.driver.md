# Purpose
The provided C code is part of a network management system that interacts with the Linux kernel's Netlink interface to manage IPv4 neighbor entries. It is specifically designed to handle neighbor table updates, which are crucial for maintaining the mapping between IP addresses and their corresponding MAC addresses in a network. The code includes two primary functions: [`fd_neigh4_netlink_request_dump`](#fd_neigh4_netlink_request_dump) and [`fd_neigh4_netlink_ingest_message`](#fd_neigh4_netlink_ingest_message). The first function, [`fd_neigh4_netlink_request_dump`](#fd_neigh4_netlink_request_dump), sends a Netlink request to the kernel to dump the current state of the neighbor table for a specified network interface. This is achieved by constructing and sending a Netlink message with the appropriate headers and flags.

The second function, [`fd_neigh4_netlink_ingest_message`](#fd_neigh4_netlink_ingest_message), processes incoming Netlink messages that contain updates to the neighbor table. It parses the message to extract the IP and MAC addresses and determines whether to add, update, or remove an entry in the neighbor table based on the message type and neighbor state. The code utilizes structures and constants from Linux headers to interact with the Netlink protocol and employs a hash map (`fd_neigh4_hmap_t`) to store and manage the neighbor entries. This code is part of a broader system that likely includes other components for comprehensive network management, and it is intended to be integrated into a larger application rather than functioning as a standalone executable.
# Imports and Dependencies

---
- `fd_neigh4_netlink.h`
- `errno.h`
- `sys/socket.h`
- `linux/netlink.h`
- `linux/rtnetlink.h`
- `linux/neighbour.h`
- `../ip/fd_netlink1.h`
- `fd_neigh4_map.h`


# Functions

---
### fd\_neigh4\_netlink\_request\_dump<!-- {{#callable:fd_neigh4_netlink_request_dump}} -->
The function `fd_neigh4_netlink_request_dump` sends a netlink request to dump IPv4 neighbor information for a specified network interface.
- **Inputs**:
    - `netlink`: A pointer to an `fd_netlink_t` structure, which contains information about the netlink socket, including the file descriptor and sequence number.
    - `if_idx`: An unsigned integer representing the index of the network interface for which the neighbor information is requested.
- **Control Flow**:
    - Initialize a sequence number by incrementing the `seq` field of the `netlink` structure.
    - Create a `request` structure containing a netlink message header (`nlmsghdr`) and a neighbor message (`ndmsg`).
    - Set the `nlmsg_type` to `RTM_GETNEIGH`, `nlmsg_flags` to `NLM_F_REQUEST | NLM_F_DUMP`, `nlmsg_len` to the size of the request, and `nlmsg_seq` to the incremented sequence number.
    - Set the `ndm_family` to `AF_INET` and `ndm_ifindex` to the provided `if_idx`.
    - Send the `request` structure over the netlink socket using the `send` function.
    - Check if the `send` function returns a negative value, indicating an error, and log a warning message with the error details.
    - Check if the number of bytes sent is not equal to the size of the request, indicating a short write, and log a warning message.
    - Return `errno` if there was an error in sending, `EPIPE` if there was a short write, or `0` if the request was sent successfully.
- **Output**: Returns `0` on success, `errno` if there was an error in sending the request, or `EPIPE` if there was a short write.


---
### fd\_neigh4\_netlink\_ingest\_message<!-- {{#callable:fd_neigh4_netlink_ingest_message}} -->
The function `fd_neigh4_netlink_ingest_message` processes a netlink message to update or remove an entry in an IPv4 neighbor hash map based on the message type and content.
- **Inputs**:
    - `map`: A pointer to the `fd_neigh4_hmap_t` structure representing the IPv4 neighbor hash map to be updated.
    - `msg_hdr`: A constant pointer to a `struct nlmsghdr` representing the netlink message header containing the neighbor information.
    - `if_idx`: An unsigned integer representing the interface index to which the message pertains.
- **Control Flow**:
    - Check if the message type is either `RTM_NEWNEIGH` or `RTM_DELNEIGH`; log a warning and return if not.
    - Extract the `ndmsg` structure and the associated attributes from the message header.
    - Verify that the message pertains to the IPv4 family and the specified interface index; return if not.
    - Initialize variables for the destination IPv4 address and MAC address.
    - Iterate over the attributes in the message to extract the IPv4 destination address and MAC address, logging warnings and returning if unexpected sizes are encountered.
    - If either the MAC address or IPv4 address is missing, log a debug message and return.
    - Determine whether to remove or update the entry based on the neighbor state and message type.
    - If removing, call `fd_neigh4_hmap_remove` to remove the entry from the map.
    - If updating, prepare the map for update, log a warning and return if preparation fails, then update the entry with the new state, IP address, and MAC address, and publish the changes.
- **Output**: The function does not return a value; it updates the neighbor hash map in place based on the netlink message content.



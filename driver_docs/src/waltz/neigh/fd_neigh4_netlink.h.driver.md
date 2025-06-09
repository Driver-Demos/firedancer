# Purpose
This C header file, `fd_neigh4_netlink.h`, provides an interface for managing IPv4 neighbor information using Linux netlink sockets. It is designed to work specifically on Linux systems, as indicated by the conditional compilation directive `#if defined(__linux__)`. The file includes function prototypes for requesting a dump of the IPv4 neighbor table ([`fd_neigh4_netlink_request_dump`](#fd_neigh4_netlink_request_dump)) and for processing netlink messages related to neighbor entries ([`fd_neigh4_netlink_ingest_message`](#fd_neigh4_netlink_ingest_message)). The functions handle operations such as inserting, updating, or removing entries in a neighbor table, focusing exclusively on IPv4 entries and ignoring IPv6 entries. The header assumes that link-layer addresses are 6 bytes long, typical for Ethernet, and includes error handling for netlink operations.
# Imports and Dependencies

---
- `fd_neigh4_map.h`
- `../ip/fd_netlink1.h`


# Function Declarations (Public API)

---
### fd\_neigh4\_netlink\_request\_dump<!-- {{#callable_declaration:fd_neigh4_netlink_request_dump}} -->
Request a dump of the IPv4 neighbor table for a specified interface index.
- **Description**: This function is used to request a dump of the IPv4 neighbor table from the Linux kernel for a specified network interface. It should be called when you need to retrieve the current state of the IPv4 neighbor table for a given interface. The function sends a netlink request to the kernel, which typically responds with multi-part messages containing the neighbor table entries. The function returns 0 on success, indicating that the request was sent successfully, or an error code if the request fails. It is important to ensure that the `netlink` parameter is properly initialized and that the `if_idx` corresponds to a valid network interface index.
- **Inputs**:
    - `netlink`: A pointer to an `fd_netlink_t` structure that must be properly initialized before calling this function. The caller retains ownership and is responsible for ensuring it is valid.
    - `if_idx`: An unsigned integer representing the interface index for which the IPv4 neighbor table dump is requested. It should correspond to a valid network interface index.
- **Output**: Returns 0 on success, or an error code (errno) on failure.
- **See also**: [`fd_neigh4_netlink_request_dump`](fd_neigh4_netlink.c.driver.md#fd_neigh4_netlink_request_dump)  (Implementation)


---
### fd\_neigh4\_netlink\_ingest\_message<!-- {{#callable_declaration:fd_neigh4_netlink_ingest_message}} -->
Imports an RTM_NEWNEIGH or RTM_DELNEIGH message into the neighbor table.
- **Description**: This function processes a netlink message to update an IPv4 neighbor table, either inserting, updating, or removing an entry based on the message type and state. It should be used when handling netlink messages related to IPv4 neighbors, specifically for Ethernet interfaces. The function logs warnings for unexpected message types or invalid link-layer address sizes and ignores messages not matching the specified interface index or those related to IPv6. It is essential to ensure that the interface index corresponds to an Ethernet interface before calling this function.
- **Inputs**:
    - `map`: A pointer to the fd_neigh4_hmap_t structure representing the neighbor table to be updated. The caller retains ownership and must ensure it is valid.
    - `msg`: A pointer to a constant nlmsghdr structure containing the netlink message to be processed. Must not be null and should represent either an RTM_NEWNEIGH or RTM_DELNEIGH message.
    - `if_idx`: An unsigned integer representing the interface index. The function will only process messages matching this index, assuming it corresponds to an Ethernet interface.
- **Output**: None
- **See also**: [`fd_neigh4_netlink_ingest_message`](fd_neigh4_netlink.c.driver.md#fd_neigh4_netlink_ingest_message)  (Implementation)



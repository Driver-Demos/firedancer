# Purpose
This C header file defines a private structure and associated constants for managing network link contexts within a software system. The `fd_netlink_tile_ctx` structure encapsulates various components necessary for handling network link updates, including netlink monitors, request handlers, and tables for network devices, routes, and neighbors. It includes mechanisms for rate-limiting updates and tracking metrics related to network synchronization and solicitations. The file also defines a unique magic number (`FD_NETLINK_TILE_CTX_MAGIC`) to identify instances of the `fd_netlink_tile_ctx_t` structure, ensuring integrity and version control. This header is likely part of a larger system dealing with network configuration and monitoring, providing a foundational data structure for managing network state and updates efficiently.
# Imports and Dependencies

---
- `../../waltz/ip/fd_netlink1.h`
- `../metrics/generated/fd_metrics_netlnk.h`
- `../../waltz/ip/fd_fib4.h`
- `../../waltz/mib/fd_dbl_buf.h`
- `../../waltz/mib/fd_netdev_tbl.h`
- `../../waltz/neigh/fd_neigh4_map.h`
- `../../waltz/neigh/fd_neigh4_probe.h`


# Data Structures

---
### fd\_netlink\_tile\_ctx
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the fd_netlink_tile_ctx structure, set to FD_NETLINK_TILE_CTX_MAGIC.
    - `nl_monitor`: An array of fd_netlink_t structures used for monitoring netlink events.
    - `nl_req`: An array of fd_netlink_t structures used for sending netlink requests.
    - `action`: A bitmask representing pending actions such as route, link, or neighbor updates.
    - `update_backoff`: A rate limit for link and route table changes, measured in ticks.
    - `route4_update_ts`: Timestamp for the last route4 update.
    - `link_update_ts`: Timestamp for the last link update.
    - `netdev_local`: A pointer to a local mutable link table.
    - `netdev_sz`: The size of the netdev table.
    - `netdev_tbl`: An array representing a join to the local mutable link table.
    - `netdev_buf`: A pointer to a global immutable copy of the link table.
    - `fib4_local`: A pointer to a local route table.
    - `fib4_main`: A pointer to the main route table.
    - `neigh4`: An array representing a neighbor table.
    - `neigh4_ifidx`: An index for the neighbor table interface.
    - `idle_cnt`: A counter for idle state in the neighbor table.
    - `prober`: An array representing a neighbor table prober.
    - `metrics`: A structure containing various metrics such as full syncs and solicits sent or failed.
- **Description**: The `fd_netlink_tile_ctx` structure is a comprehensive data structure used for managing and monitoring network link and route updates in a system. It includes fields for handling netlink events, managing link and route tables, and probing neighbor tables. The structure also maintains metrics for tracking synchronization and solicitations, and it uses a unique magic number for identification. This structure is designed to facilitate efficient network management by providing mechanisms for rate limiting updates and maintaining both local and global copies of network tables.


---
### fd\_netlink\_tile\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the fd_netlink_tile_ctx_t structure, set to FD_NETLINK_TILE_CTX_MAGIC.
    - `nl_monitor`: An array of fd_netlink_t used for monitoring netlink events.
    - `nl_req`: An array of fd_netlink_t used for sending netlink requests.
    - `action`: A bitmask representing pending actions such as route, link, or neighbor updates.
    - `update_backoff`: A rate limit for link and route table changes, measured in ticks.
    - `route4_update_ts`: Timestamp for the last route4 update.
    - `link_update_ts`: Timestamp for the last link update.
    - `netdev_local`: A pointer to a local mutable network device table.
    - `netdev_sz`: The size of the network device table.
    - `netdev_tbl`: A join to the local mutable network device table.
    - `netdev_buf`: A pointer to a global immutable copy of the network device table.
    - `fib4_local`: A pointer to a local FIB4 (Forwarding Information Base) table.
    - `fib4_main`: A pointer to the main FIB4 table.
    - `neigh4`: An array of fd_neigh4_hmap_t representing the neighbor table.
    - `neigh4_ifidx`: The interface index for the neighbor table.
    - `idle_cnt`: A counter for idle operations.
    - `prober`: An array of fd_neigh4_prober_t used for probing neighbors.
    - `metrics`: A struct containing various metrics related to link and route synchronizations and neighbor solicitations.
- **Description**: The `fd_netlink_tile_ctx_t` structure is a comprehensive data structure used for managing and monitoring network link and route updates in a system. It includes fields for handling netlink events, managing network device and route tables, and probing neighbor tables. The structure also contains mechanisms for rate limiting updates and maintaining metrics on synchronization and solicitation activities. This structure is essential for ensuring efficient and synchronized network operations, providing both mutable and immutable views of network data, and facilitating communication with network devices and routes.



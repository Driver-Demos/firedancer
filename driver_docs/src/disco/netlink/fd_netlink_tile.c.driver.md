# Purpose
This C source code file is designed to manage and interact with network topology using Netlink, a communication protocol between the Linux kernel and user-space processes. The file provides functionality to create and join network topology tiles, which are components of a larger network topology structure. It includes functions to initialize and manage network devices, routing tables, and neighbor tables using Netlink messages. The code is structured to handle both privileged and unprivileged initialization of network components, ensuring that the necessary resources and configurations are set up for network communication and monitoring.

The file is part of a larger system, as indicated by the inclusion of multiple headers from different directories, suggesting it is a component of a network management library or application. It defines several key functions and structures, such as [`fd_netlink_topo_create`](#fd_netlink_topo_create) and [`fd_netlink_topo_join`](#fd_netlink_topo_join), which are responsible for setting up and integrating network topology components. The code also includes mechanisms for handling Netlink messages, updating network state, and managing metrics related to network operations. The use of shared memory and synchronization primitives indicates that this code is designed for high-performance network operations, likely in a multi-threaded or distributed environment. The file does not define a public API but rather serves as an internal component of a larger system, focusing on network topology management and monitoring.
# Imports and Dependencies

---
- `fd_netlink_tile_private.h`
- `../topo/fd_topo.h`
- `../topo/fd_topob.h`
- `../metrics/fd_metrics.h`
- `../../waltz/ip/fd_fib4_netlink.h`
- `../../waltz/mib/fd_netdev_netlink.h`
- `../../waltz/neigh/fd_neigh4_netlink.h`
- `../../util/pod/fd_pod_format.h`
- `../../util/log/fd_dtrace.h`
- `errno.h`
- `net/if.h`
- `netinet/in.h`
- `sys/socket.h`
- `sys/random.h`
- `sys/time.h`
- `linux/rtnetlink.h`
- `generated/netlink_seccomp.h`
- `../stem/fd_stem.c`


# Global Variables

---
### fd\_tile\_netlnk
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_netlnk` is a global variable of type `fd_topo_run_tile_t`, which is a structure that encapsulates various function pointers and properties related to the operation of a network link tile. This structure includes fields for the tile's name, functions for populating allowed seccomp and file descriptors, alignment and footprint calculations, and initialization routines for both privileged and unprivileged contexts. Additionally, it includes a function pointer for the main execution routine of the tile.
- **Use**: This variable is used to define and manage the behavior and lifecycle of a network link tile within the system, including its initialization, resource allocation, and execution.


# Functions

---
### fd\_netlink\_topo\_create<!-- {{#callable:fd_netlink_topo_create}} -->
The `fd_netlink_topo_create` function initializes and configures network topology objects for a netlink tile, setting up shared memory usage and properties for network devices, routes, and neighbors.
- **Inputs**:
    - `netlink_tile`: A pointer to an `fd_topo_tile_t` structure representing the netlink tile to be configured.
    - `topo`: A pointer to an `fd_topo_t` structure representing the network topology.
    - `netlnk_max_routes`: An unsigned long integer specifying the maximum number of routes for the netlink configuration.
    - `netlnk_max_neighbors`: An unsigned long integer specifying the maximum number of neighbors for the netlink configuration.
    - `bind_interface`: A constant character pointer to the name of the network interface to bind to.
- **Control Flow**:
    - Retrieve topology objects for double buffer, main and local FIB4, and neighbor hashmap using `fd_topob_obj` function.
    - Set up shared memory usage for the netlink tile with these objects using `fd_topob_tile_uses` in read-write mode.
    - Calculate the MTU for the netdev double buffer and insert it into the topology properties using `fd_pod_insertf_ulong`.
    - Configure the route table by inserting the maximum number of routes into the topology properties for both main and local FIB4 objects.
    - Calculate parameters for the neighbor hashmap, including maximum elements, alignment, and footprint, and insert these into the topology properties.
    - Generate a random seed using `getrandom` and insert it into the topology properties for the neighbor object.
    - Assign object IDs and bind interface name to the `netlink_tile` structure fields.
- **Output**: The function does not return a value; it modifies the `netlink_tile` and `topo` structures to configure the network topology.


---
### fd\_netlink\_topo\_join<!-- {{#callable:fd_netlink_topo_join}} -->
The `fd_netlink_topo_join` function configures a join tile to use specific network-related objects in a topology in read-only mode.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the network topology.
    - `netlink_tile`: A pointer to an `fd_topo_tile_t` structure representing the netlink tile within the topology.
    - `join_tile`: A pointer to an `fd_topo_tile_t` structure representing the tile that will join the network topology.
- **Control Flow**:
    - The function calls `fd_topob_tile_uses` four times, each time passing the `topo`, `join_tile`, and a specific object from the `topo->objs` array, indexed by IDs stored in `netlink_tile->netlink` structure, along with the `FD_SHMEM_JOIN_MODE_READ_ONLY` mode.
    - The objects used are `neigh4_obj_id`, `neigh4_ele_obj_id`, `fib4_main_obj_id`, and `fib4_local_obj_id`, which are part of the netlink tile's configuration.
- **Output**: The function does not return any value; it modifies the state of the `join_tile` to use certain objects in the topology in a read-only manner.


---
### scratch\_align<!-- {{#callable:scratch_align}} -->
The `scratch_align` function returns the maximum alignment requirement between `fd_netlink_tile_ctx_t` and `FD_NETDEV_TBL_ALIGN`.
- **Inputs**: None
- **Control Flow**:
    - The function calls `fd_ulong_max` with two arguments: `alignof(fd_netlink_tile_ctx_t)` and `FD_NETDEV_TBL_ALIGN`.
    - It returns the result of `fd_ulong_max`, which is the maximum of the two alignment values.
- **Output**: The function returns an `ulong` representing the maximum alignment requirement between `fd_netlink_tile_ctx_t` and `FD_NETDEV_TBL_ALIGN`.


---
### scratch\_footprint<!-- {{#callable:scratch_footprint}} -->
The `scratch_footprint` function calculates the memory footprint required for a network link tile context and associated network device table.
- **Inputs**:
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure, which is not used in the function.
- **Control Flow**:
    - Initialize a variable `l` with `FD_LAYOUT_INIT` to start the layout calculation.
    - Append the alignment and size of `fd_netlink_tile_ctx_t` to `l` using `FD_LAYOUT_APPEND`.
    - Append the alignment and footprint of the network device table, calculated with `fd_netdev_tbl_align()` and `fd_netdev_tbl_footprint(NETDEV_MAX, BOND_MASTER_MAX)`, to `l`.
    - Finalize the layout with `FD_LAYOUT_FINI`, using the alignment from `scratch_align()`, and return the result.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the specified layout.
- **Functions called**:
    - [`scratch_align`](#scratch_align)


---
### populate\_allowed\_seccomp<!-- {{#callable:populate_allowed_seccomp}} -->
The `populate_allowed_seccomp` function populates a seccomp filter policy for a netlink tile based on the provided topology and tile context.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the network topology.
    - `tile`: A pointer to a `fd_topo_tile_t` structure representing the specific tile within the topology.
    - `out_cnt`: An unsigned long integer representing the count of output seccomp filter instructions.
    - `out`: A pointer to a `struct sock_filter` array where the seccomp filter instructions will be populated.
- **Control Flow**:
    - Retrieve the netlink tile context using `fd_topo_obj_laddr` with the topology and tile object ID.
    - Verify that the retrieved context's magic number matches `FD_NETLINK_TILE_CTX_MAGIC` to ensure it is valid.
    - Call [`populate_sock_filter_policy_netlink`](generated/netlink_seccomp.h.driver.md#populate_sock_filter_policy_netlink) to populate the seccomp filter policy using the provided output count, filter array, and file descriptors from the context.
    - Return the count of seccomp filter instructions, `sock_filter_policy_netlink_instr_cnt`.
- **Output**: Returns the number of seccomp filter instructions populated, as an unsigned long integer.
- **Functions called**:
    - [`populate_sock_filter_policy_netlink`](generated/netlink_seccomp.h.driver.md#populate_sock_filter_policy_netlink)


---
### populate\_allowed\_fds<!-- {{#callable:populate_allowed_fds}} -->
The `populate_allowed_fds` function populates an array with file descriptors that are allowed for a specific network tile context.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology.
    - `tile`: A pointer to a `fd_topo_tile_t` structure representing the tile within the topology.
    - `out_fds_cnt`: An unsigned long integer representing the maximum number of file descriptors that can be stored in the `out_fds` array.
    - `out_fds`: A pointer to an integer array where the allowed file descriptors will be stored.
- **Control Flow**:
    - Retrieve the network tile context using `fd_topo_obj_laddr` with the given `topo` and `tile->tile_obj_id`.
    - Check if the `magic` field of the context matches `FD_NETLINK_TILE_CTX_MAGIC` to ensure the context is valid.
    - If `out_fds_cnt` is less than 5, log an error and terminate the function.
    - Initialize `out_cnt` to 0 and set `out_fds[out_cnt++]` to 2, representing the standard error file descriptor.
    - If the log file descriptor is valid (not -1), add it to `out_fds` and increment `out_cnt`.
    - Add the file descriptors from the context's `nl_monitor`, `nl_req`, and `prober` to `out_fds`, incrementing `out_cnt` for each.
    - Return the total count of file descriptors added to `out_fds`.
- **Output**: The function returns an unsigned long integer representing the number of file descriptors added to the `out_fds` array.


---
### privileged\_init<!-- {{#callable:privileged_init}} -->
The `privileged_init` function initializes a network topology tile for privileged operations, setting up necessary network interfaces and configurations for netlink communication.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the network topology.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile within the topology to be initialized.
- **Control Flow**:
    - Check if the tile's kind_id is not zero, logging an error if it is not, as only one netlink tile is allowed.
    - Retrieve the network interface index for the tile's netlink neighbor interface using `if_nametoindex` and log an error if it fails.
    - Obtain a pointer to the tile's context object using `fd_topo_obj_laddr` and initialize it with zeroes, setting its magic number and neighbor interface index.
    - Initialize two netlink sockets (`nl_monitor` and `nl_req`) with specific buffer sizes, logging an error if initialization fails.
    - Set up a sockaddr_nl structure for binding the netlink monitor socket to specific netlink groups and bind the socket, logging an error if binding fails.
    - Initialize a neighbor prober with specific parameters for probe rate and delay.
    - Set a socket option on the netlink monitor socket to specify a 2ms timeout for receive operations, logging an error if setting the option fails.
- **Output**: The function does not return a value; it performs initialization and configuration tasks, logging errors if any step fails.


---
### unprivileged\_init<!-- {{#callable:unprivileged_init}} -->
The `unprivileged_init` function initializes network-related resources and context for a tile in a topology without requiring elevated privileges.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the network topology.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile within the topology to be initialized.
- **Control Flow**:
    - Initialize a scratch allocation region using the tile's object address.
    - Allocate and initialize a `fd_netlink_tile_ctx_t` context structure within the scratch region.
    - Verify the context's magic number to ensure it is correctly initialized.
    - Calculate and allocate memory for the network device table within the context.
    - Check the presence of required object IDs in the tile's netlink structure.
    - Create and join a new network device table using the allocated memory.
    - Join a double buffer for network devices using the tile's netlink object ID.
    - Join a neighbor hashmap and two FIB4 tables using their respective object IDs from the tile's netlink structure.
    - Iterate over incoming links of the tile to ensure they have an MTU of zero, logging an error if not.
    - Set action flags in the context to indicate updates are needed for links, routes, and neighbors.
    - Set the update backoff time to 10 milliseconds.
- **Output**: The function does not return a value; it initializes the context and resources for the tile.


---
### metrics\_write<!-- {{#callable:metrics_write}} -->
The `metrics_write` function updates various network-related metrics in a given context.
- **Inputs**:
    - `ctx`: A pointer to a `fd_netlink_tile_ctx_t` structure, which contains network-related metrics and context information.
- **Control Flow**:
    - The function uses several macros (`FD_MCNT_SET`, `FD_MCNT_ENUM_COPY`, `FD_MGAUGE_SET`) to update metrics related to network link and route synchronization, interface and route counts, and neighbor probe statistics.
    - It updates the count of dropped events using `fd_netlink_enobufs_cnt`.
    - It updates the count of full link and route synchronizations using values from `ctx->metrics`.
    - It copies update counts from `ctx->metrics.update_cnt` using `FD_MCNT_ENUM_COPY`.
    - It sets the interface count using the device count from `ctx->netdev_tbl->hdr->dev_cnt`.
    - It sets the local and main route counts using the results of `fd_fib4_cnt` on `ctx->fib4_local` and `ctx->fib4_main`, respectively.
    - It updates the count of neighbor probes sent and failed using values from `ctx->metrics`.
    - It updates the rate limit counts for host and global neighbor probes using values from `ctx->prober`.
- **Output**: The function does not return a value; it updates metrics in the provided context.


---
### netlink\_monitor\_read<!-- {{#callable:netlink_monitor_read}} -->
The `netlink_monitor_read` function reads and processes netlink messages from a socket, updating context actions and metrics based on the message type.
- **Inputs**:
    - `ctx`: A pointer to a `fd_netlink_tile_ctx_t` structure, which holds the context for the netlink tile, including file descriptors and metrics.
    - `flags`: An integer representing flags to modify the behavior of the `recvfrom` system call, such as `MSG_DONTWAIT` for non-blocking operation.
- **Control Flow**:
    - Allocate a buffer `msg` of 16384 bytes to store the incoming message.
    - Call `recvfrom` to read a message from the netlink socket into `msg`, using the file descriptor from `ctx->nl_monitor->fd` and the specified `flags`.
    - Check if `msg_sz` (the size of the received message) is less than or equal to 0; if so, handle errors based on `errno` and return 0 for recoverable errors or log an error for others.
    - Cast the message buffer `msg` to a `struct nlmsghdr` pointer `nlh`.
    - Log a trace probe with details from the netlink message header.
    - Use a switch statement to handle different `nlmsg_type` values, updating `ctx->action` and `ctx->metrics.update_cnt` based on the message type (e.g., `RTM_NEWLINK`, `RTM_DELLINK`, `RTM_NEWROUTE`, `RTM_DELROUTE`, `RTM_NEWNEIGH`, `RTM_DELNEIGH`).
    - For `RTM_NEWNEIGH` and `RTM_DELNEIGH`, call `fd_neigh4_netlink_ingest_message` to process the neighbor message.
    - Log an informational message for unexpected netlink message types.
    - Return 1 to indicate a message was successfully read and processed.
- **Output**: Returns 1 if a message was read and processed, or 0 if no message was read due to recoverable errors.


---
### during\_housekeeping<!-- {{#callable:during_housekeeping}} -->
The `during_housekeeping` function performs periodic updates and synchronization of network link, route, and neighbor information based on the current context and pending actions.
- **Inputs**:
    - `ctx`: A pointer to a `fd_netlink_tile_ctx_t` structure that holds the context and state for network link, route, and neighbor updates.
- **Control Flow**:
    - Retrieve the current time using `fd_tickcount()` and store it in `now`.
    - Check if the `FD_NET_TILE_ACTION_LINK_UPDATE` action is set in `ctx->action`.
    - If the current time `now` is less than `ctx->link_update_ts`, return immediately.
    - Clear the `FD_NET_TILE_ACTION_LINK_UPDATE` flag from `ctx->action`.
    - Load the network device table using `fd_netdev_netlink_load_table` and insert it into the double buffer using `fd_dbl_buf_insert`.
    - Update `ctx->link_update_ts` to the current time plus `ctx->update_backoff` and increment `ctx->metrics.link_full_syncs`.
    - Check if the `FD_NET_TILE_ACTION_ROUTE4_UPDATE` action is set in `ctx->action`.
    - If the current time `now` is less than `ctx->route4_update_ts`, return immediately.
    - Clear the `FD_NET_TILE_ACTION_ROUTE4_UPDATE` flag from `ctx->action`.
    - Load the IPv4 route tables for local and main using `fd_fib4_netlink_load_table`.
    - Update `ctx->route4_update_ts` to the current time plus `ctx->update_backoff` and increment `ctx->metrics.route_full_syncs`.
    - Check if the `FD_NET_TILE_ACTION_NEIGH_UPDATE` action is set in `ctx->action`.
    - Clear the `FD_NET_TILE_ACTION_NEIGH_UPDATE` flag from `ctx->action`.
    - Request a dump of the neighbor table using `fd_neigh4_netlink_request_dump`.
    - Initialize a netlink iterator and iterate over the messages, ingesting each message into the neighbor table using `fd_neigh4_netlink_ingest_message`.
- **Output**: The function does not return a value; it updates the state and metrics within the `ctx` structure.


---
### before\_credit<!-- {{#callable:before_credit}} -->
The `before_credit` function manages the reading of netlink messages and adjusts the busy state of the system based on socket activity.
- **Inputs**:
    - `ctx`: A pointer to a `fd_netlink_tile_ctx_t` structure, which holds the context for netlink operations.
    - `stem`: A pointer to a `fd_stem_context_t` structure, which is unused in this function.
    - `charge_busy`: A pointer to an integer that indicates whether the system should be considered busy.
- **Control Flow**:
    - Enter an infinite loop to clear the socket buffer by calling [`netlink_monitor_read`](#netlink_monitor_read) with `MSG_DONTWAIT` flag.
    - If [`netlink_monitor_read`](#netlink_monitor_read) returns false, break the loop, otherwise set `*charge_busy` to 1.
    - Increment the `idle_cnt` in the context structure.
    - If `idle_cnt` reaches or exceeds 128, set `*charge_busy` to 0 and perform a blocking read by calling [`netlink_monitor_read`](#netlink_monitor_read) without flags.
- **Output**: The function does not return a value; it modifies the `charge_busy` integer and the `idle_cnt` in the context structure.
- **Functions called**:
    - [`netlink_monitor_read`](#netlink_monitor_read)


---
### after\_poll\_overrun<!-- {{#callable:after_poll_overrun}} -->
The `after_poll_overrun` function resets the idle count of a network link context to indicate a poll overrun event.
- **Inputs**:
    - `ctx`: A pointer to a `fd_netlink_tile_ctx_t` structure, representing the context of a network link tile.
- **Control Flow**:
    - The function takes a single argument, `ctx`, which is a pointer to a `fd_netlink_tile_ctx_t` structure.
    - It sets the `idle_cnt` field of the `ctx` structure to -1L, indicating a reset of the idle count due to a poll overrun.
- **Output**: This function does not return any value; it modifies the `idle_cnt` field of the provided context structure.


---
### after\_frag<!-- {{#callable:after_frag}} -->
The `after_frag` function processes a neighbor solicit request by validating the request, checking if the kernel is already handling it, and if not, inserting a placeholder and triggering a neighbor solicit via netlink.
- **Inputs**:
    - `ctx`: A pointer to the `fd_netlink_tile_ctx_t` structure, which contains context information for the netlink tile.
    - `in_idx`: An unsigned long integer representing the input index, which is not used in the function.
    - `seq`: An unsigned long integer representing the sequence number, which is not used in the function.
    - `sig`: An unsigned long integer containing the request data, including the interface index and IPv4 address.
    - `sz`: An unsigned long integer representing the size of the request, expected to be zero.
    - `tsorig`: An unsigned long integer representing the original timestamp, which is not used in the function.
    - `tspub`: An unsigned long integer representing the publication timestamp, which is not used in the function.
    - `stem`: A pointer to the `fd_stem_context_t` structure, which is not used in the function.
- **Control Flow**:
    - The function starts by recording the current time and resetting the idle count in the context.
    - It checks if the size (`sz`) of the request is non-zero and logs a warning if so.
    - It extracts the interface index and IPv4 address from the `sig` field and checks if the interface index matches the expected value in the context.
    - If the interface index is invalid, it increments the failure metric and logs an error, then returns.
    - The function checks if the kernel is already handling the request by querying the neighbor hashmap; if so, it increments the failure metric and returns.
    - If the request is not being handled, it prepares to insert a placeholder in the neighbor hashmap.
    - If the preparation fails, it increments the failure metric and returns.
    - It sets the state of the neighbor entry to incomplete, clears the MAC address, and publishes the entry.
    - Finally, it triggers a neighbor solicit via netlink and updates the metrics based on the result of the probe.
- **Output**: The function does not return a value; it updates the context and metrics based on the processing of the neighbor solicit request.



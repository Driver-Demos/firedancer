# Purpose
This C source code file is an executable program designed to interact with the Linux kernel's networking stack using the Netlink protocol. Its primary purpose is to retrieve and display the neighbor tables for all Ethernet interfaces on a system. The code achieves this by sending Netlink requests to the kernel to list all network interfaces and then iterating over these interfaces to request and process their neighbor tables. The neighbor tables are stored in a hash map structure (`fd_neigh4_hmap_t`), which is initialized, populated, and then reinitialized for each interface. The program logs the output to standard error, providing a detailed view of the neighbor tables for diagnostic or monitoring purposes.

The code is structured around several key components: the [`main`](#main) function, which sets up the environment and initializes resources; the [`dump_neighbor_table`](#dump_neighbor_table) function, which handles the retrieval and processing of neighbor table data for a specific interface; and the [`dump_all_neighbor_tables`](#dump_all_neighbor_tables) function, which orchestrates the process for all interfaces. The program uses a combination of custom data structures and functions (e.g., `fd_neigh4_hmap_t`, `fd_netlink_t`) and standard Linux networking headers to perform its tasks. It does not define public APIs or external interfaces, as it is intended to be run as a standalone utility rather than a library to be imported elsewhere.
# Imports and Dependencies

---
- `fd_neigh4_netlink.h`
- `errno.h`
- `stdio.h`
- `sys/socket.h`
- `net/if.h`
- `linux/if_arp.h`
- `linux/netlink.h`
- `linux/rtnetlink.h`
- `../../util/fd_util.h`


# Functions

---
### dump\_neighbor\_table<!-- {{#callable:dump_neighbor_table}} -->
The `dump_neighbor_table` function retrieves and logs the neighbor table for a specified network interface, then reinitializes the neighbor hash map.
- **Inputs**:
    - `map`: A pointer to an `fd_neigh4_hmap_t` structure representing the neighbor hash map to be updated and reinitialized.
    - `netlink1`: A pointer to an `fd_netlink_t` structure used for sending and receiving netlink messages.
    - `if_idx`: An integer representing the index of the network interface for which the neighbor table is to be dumped.
- **Control Flow**:
    - Call [`fd_neigh4_netlink_request_dump`](fd_neigh4_netlink.c.driver.md#fd_neigh4_netlink_request_dump) to request a dump of the neighbor table for the specified interface index using `netlink1`.
    - Initialize a buffer and an iterator for processing netlink messages.
    - Iterate over the netlink messages using `fd_netlink_iter_init`, `fd_netlink_iter_done`, and `fd_netlink_iter_next`.
    - For each message, call [`fd_neigh4_netlink_ingest_message`](fd_neigh4_netlink.c.driver.md#fd_neigh4_netlink_ingest_message) to update the neighbor hash map with the message data.
    - Retrieve and print the interface name using `if_indextoname` and log the current neighbor table using [`fd_neigh4_hmap_fprintf`](fd_neigh4_map.c.driver.md#fd_neigh4_hmap_fprintf).
    - Flush the log buffer to ensure all messages are output.
    - Retrieve parameters of the current hash map such as `ele_max`, `lock_cnt`, `probe_max`, `seed`, `shmap`, `shele`, and `ljoin`.
    - Delete the current hash map using `fd_neigh4_hmap_delete`.
    - Clear the hash map entries using `fd_memset`.
    - Recreate the hash map with `fd_neigh4_hmap_new` and rejoin it with `fd_neigh4_hmap_join`.
- **Output**: The function does not return a value; it operates by side effects on the provided neighbor hash map and logs output to `stderr`.
- **Functions called**:
    - [`fd_neigh4_netlink_request_dump`](fd_neigh4_netlink.c.driver.md#fd_neigh4_netlink_request_dump)
    - [`fd_neigh4_netlink_ingest_message`](fd_neigh4_netlink.c.driver.md#fd_neigh4_netlink_ingest_message)
    - [`fd_neigh4_hmap_fprintf`](fd_neigh4_map.c.driver.md#fd_neigh4_hmap_fprintf)


---
### dump\_all\_neighbor\_tables<!-- {{#callable:dump_all_neighbor_tables}} -->
The `dump_all_neighbor_tables` function retrieves and processes the neighbor tables for all Ethernet interfaces using netlink sockets.
- **Inputs**:
    - `map`: A pointer to a `fd_neigh4_hmap_t` structure, which is used to store and manage the neighbor table entries.
    - `netlink0`: A pointer to a `fd_netlink_t` structure, used for sending and receiving netlink messages to list network interfaces.
    - `netlink1`: A pointer to a `fd_netlink_t` structure, used for processing individual neighbor tables for each interface.
- **Control Flow**:
    - Initialize a netlink message request to list all network interfaces with Ethernet type using `netlink0`.
    - Send the request using the `send` function and check for errors in sending the message.
    - Log a notice indicating the start of dumping neighbor tables for all Ethernet interfaces.
    - Initialize a buffer and an iterator for processing netlink messages received in response to the request.
    - Iterate over the received netlink messages using `fd_netlink_iter_t` to process each message.
    - Check for errors in the netlink messages and log errors if any are found.
    - For each valid `RTM_NEWLINK` message, extract the interface index and call [`dump_neighbor_table`](#dump_neighbor_table) to process the neighbor table for that interface.
- **Output**: The function does not return a value; it performs operations to dump neighbor tables and logs the results.
- **Functions called**:
    - [`dump_neighbor_table`](#dump_neighbor_table)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, sets up shared memory and network link structures, processes command-line arguments, creates a hash map for network neighbors, dumps neighbor tables for all Ethernet interfaces, and then cleans up resources before exiting.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the environment using `fd_boot` with command-line arguments.
    - Determine the CPU index and adjust if it exceeds the shared memory CPU count.
    - Parse command-line arguments for page size, page count, and NUMA index, with defaults if not provided.
    - Convert the page size string to an actual size and log an error if unsupported.
    - Create an anonymous workspace with the specified page size, count, and NUMA index.
    - Initialize two netlink structures with different sequence numbers and verify their creation.
    - Allocate memory for a hash map and its elements in the workspace and verify allocations.
    - Create a new hash map for network neighbors and join it to the allocated memory.
    - Dump all neighbor tables for Ethernet interfaces using the initialized netlink structures.
    - Finalize the netlink structures and clean up the hash map and workspace allocations.
    - Log a success message and halt the program.
- **Output**: The function returns an integer, specifically 0, indicating successful execution.
- **Functions called**:
    - [`dump_all_neighbor_tables`](#dump_all_neighbor_tables)



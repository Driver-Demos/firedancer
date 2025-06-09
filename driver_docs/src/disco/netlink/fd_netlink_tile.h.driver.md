# Purpose
This C header file, `fd_netlink_tile.h`, defines interfaces and structures for interacting with a "netlink tile" within a network topology framework. It includes declarations for managing network link configurations and operations, such as creating and joining network topologies and handling neighbor solicitation requests, which are akin to ARP requests for IPv4 addresses. The file introduces a structure, `fd_netlink_neigh4_solicit_link_t`, to encapsulate the necessary metadata for sending these requests efficiently, ensuring deduplication and high-rate safety. Additionally, it provides a static inline function, [`fd_netlink_neigh4_solicit`](#fd_netlink_neigh4_solicit), to facilitate the solicitation process by publishing requests to a message cache. The file is part of a larger system, as indicated by references to external documentation and related components like `fd_topo.h`.
# Imports and Dependencies

---
- `../topo/fd_topo.h`


# Global Variables

---
### fd\_tile\_netlnk
- **Type**: `fd_topo_run_tile_t`
- **Description**: The variable `fd_tile_netlnk` is an external global variable of type `fd_topo_run_tile_t`. It represents the netlink tile, which is a component used for network communication within the system.
- **Use**: This variable is used to provide access to the netlink tile functionalities, allowing for operations such as neighbor solicitation and network topology management.


# Data Structures

---
### fd\_netlink\_neigh4\_solicit\_link
- **Type**: `struct`
- **Members**:
    - `mcache`: A pointer to a memory cache structure used for storing metadata.
    - `depth`: An unsigned long integer representing the depth of the cache.
    - `seq`: An unsigned long integer used to track the sequence number for operations.
- **Description**: The `fd_netlink_neigh4_solicit_link` structure is designed to hold the necessary information for sending neighbor solicitation requests, specifically for IPv4 addresses, to the netlink tile. It includes a pointer to a metadata cache (`mcache`), a `depth` value indicating the cache's depth, and a `seq` value for maintaining the sequence of operations. This structure is integral to the process of deduplicating and managing high-rate ARP requests efficiently.


---
### fd\_netlink\_neigh4\_solicit\_link\_t
- **Type**: `struct`
- **Members**:
    - `mcache`: A pointer to fd_frag_meta_t, used for managing metadata cache.
    - `depth`: An unsigned long integer representing the depth of the cache.
    - `seq`: An unsigned long integer used to track the sequence number for requests.
- **Description**: The `fd_netlink_neigh4_solicit_link_t` structure is designed to facilitate the sending of neighbor solicitation requests, such as ARP requests, to the netlink tile. It contains a pointer to a metadata cache (`mcache`), a `depth` field indicating the cache depth, and a `seq` field for maintaining the sequence number of requests. This structure is integral to the process of deduplicating and managing high-rate solicitation requests efficiently.


# Functions

---
### fd\_netlink\_neigh4\_solicit<!-- {{#callable:fd_netlink_neigh4_solicit}} -->
The `fd_netlink_neigh4_solicit` function sends a neighbor solicitation request for an IPv4 address using a netlink tile, updating the sequence number after publishing the request.
- **Inputs**:
    - `link`: A pointer to a `fd_netlink_neigh4_solicit_link_t` structure containing metadata required for the solicitation request.
    - `ip4_addr`: An unsigned integer representing the IPv4 address in big endian format for which the neighbor solicitation is requested.
    - `if_idx`: An unsigned integer representing the interface index associated with the IPv4 address.
    - `tspub_comp`: An unsigned long integer representing a timestamp or a component used in the publication process.
- **Control Flow**:
    - Retrieve the current sequence number from the `link` structure.
    - Compute a signature by combining the `ip4_addr` and `if_idx` into a single unsigned long integer.
    - Call `fd_mcache_publish` to publish the solicitation request with the computed signature and other parameters.
    - Increment the sequence number in the `link` structure using `fd_seq_inc`.
- **Output**: The function does not return a value; it operates by side effects, updating the sequence number in the `link` structure and publishing a solicitation request.


# Function Declarations (Public API)

---
### fd\_netlink\_topo\_create<!-- {{#callable_declaration:fd_netlink_topo_create}} -->
Configures a netlink tile with specified topology and network parameters.
- **Description**: This function sets up a netlink tile within a given topology, configuring it with specified maximum routes and neighbors, and binding it to a network interface. It should be called when initializing network topology components that require netlink tile configuration. The function expects valid pointers to a netlink tile and a topology structure, and a non-null string for the network interface. It modifies the netlink tile to reflect the configuration parameters provided.
- **Inputs**:
    - `netlink_tile`: A pointer to an fd_topo_tile_t structure representing the netlink tile to be configured. Must not be null.
    - `topo`: A pointer to an fd_topo_t structure representing the network topology. Must not be null.
    - `netlnk_max_routes`: An unsigned long specifying the maximum number of routes the netlink tile can handle. Must be a positive value.
    - `netlnk_max_neighbors`: An unsigned long specifying the maximum number of neighbors the netlink tile can handle. Must be a positive value.
    - `bind_interface`: A constant character pointer to the name of the network interface to bind. Must not be null and should be a valid interface name.
- **Output**: None
- **See also**: [`fd_netlink_topo_create`](fd_netlink_tile.c.driver.md#fd_netlink_topo_create)  (Implementation)


---
### fd\_netlink\_topo\_join<!-- {{#callable_declaration:fd_netlink_topo_join}} -->
Joins a tile to a netlink topology in read-only mode.
- **Description**: This function is used to associate a tile with a netlink topology, allowing the tile to access specific network-related objects in a read-only manner. It should be called when a tile needs to join an existing netlink topology to perform operations that require read access to network objects. The function assumes that the topology and tiles have been properly initialized and configured before calling. It is important to ensure that the provided pointers are valid and that the topology and tiles are in a consistent state to avoid undefined behavior.
- **Inputs**:
    - `topo`: A pointer to an fd_topo_t structure representing the network topology. Must not be null and should be properly initialized before calling.
    - `netlink_tile`: A pointer to an fd_topo_tile_t structure representing the netlink tile. Must not be null and should be properly initialized with valid object IDs.
    - `join_tile`: A pointer to an fd_topo_tile_t structure representing the tile to be joined to the topology. Must not be null and should be properly initialized.
- **Output**: None
- **See also**: [`fd_netlink_topo_join`](fd_netlink_tile.c.driver.md#fd_netlink_topo_join)  (Implementation)



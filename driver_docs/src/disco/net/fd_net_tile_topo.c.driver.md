# Purpose
The provided C source code file is designed to manage and configure network topology for a system that utilizes network tiles, specifically focusing on the setup and management of XDP (eXpress Data Path) and socket-based network tiles. The code is part of a larger system that appears to be modular, with components for different network configurations and operations. The primary functionality of this file is to define and initialize network tiles, set up their configurations, and manage the interconnections between these tiles using a topology object (`fd_topo_t`). The code includes functions to set up XDP and socket tiles, create network links, and finalize network tile configurations, indicating its role in the broader network management framework.

Key technical components include functions like [`setup_xdp_tile`](#setup_xdp_tile) and [`setup_sock_tile`](#setup_sock_tile), which configure network tiles based on the specified provider (either "xdp" or "socket"). The code also defines functions for creating and managing network links ([`fd_topos_net_rx_link`](#fd_topos_net_rx_link) and [`add_xdp_rx_link`](#add_xdp_rx_link)) and finalizing network tile configurations ([`fd_topos_net_tile_finish`](#fd_topos_net_tile_finish)). The file imports several headers, suggesting dependencies on other parts of the system, such as topology management (`fd_topob.h`), network link management (`fd_netlink_tile.h`), and configuration settings (`fd_config.h`). The code is structured to be part of a library or module that can be integrated into a larger application, providing specific network topology management capabilities without defining a public API or external interface directly.
# Imports and Dependencies

---
- `fd_net_tile.h`
- `../topo/fd_topob.h`
- `../netlink/fd_netlink_tile.h`
- `../../app/shared/fd_config.h`
- `../../util/pod/fd_pod_format.h`
- `net/if.h`


# Functions

---
### setup\_xdp\_tile<!-- {{#callable:setup_xdp_tile}} -->
The `setup_xdp_tile` function configures a network tile for XDP (eXpress Data Path) operations within a given topology.
- **Inputs**:
    - `topo`: A pointer to the `fd_topo_t` structure representing the network topology.
    - `i`: An unsigned long integer representing the index of the tile being configured.
    - `netlink_tile`: A pointer to the `fd_topo_tile_t` structure representing the netlink tile.
    - `tile_to_cpu`: A constant pointer to an array of unsigned long integers mapping tiles to CPU indices.
    - `net_cfg`: A constant pointer to the `fd_config_net_t` structure containing network configuration parameters.
- **Control Flow**:
    - Retrieve a tile object for the network tile using `fd_topob_tile` with specific parameters.
    - Establish a link between the network and netlink tiles using `fd_topob_link`.
    - Configure the input and output connections for the tile using `fd_topob_tile_in` and `fd_topob_tile_out`.
    - Join the netlink topology with the current tile using `fd_netlink_topo_join`.
    - Retrieve a UMEM object and associate it with the tile using `fd_topob_obj` and `fd_topob_tile_uses`.
    - Insert the UMEM object ID into the topology properties using `fd_pod_insertf_ulong`.
    - Initialize and set the network interface name in the tile's configuration using `fd_cstr_init`, `fd_cstr_append_cstr_safe`, and `fd_cstr_fini`.
    - Set various network parameters in the tile's configuration, including bind address, flush timeout, queue sizes, and zero-copy mode.
    - Copy the XDP mode string from the configuration to the tile's configuration using `fd_memset` and `fd_memcpy`.
    - Assign various object IDs from the netlink tile to the current tile's configuration.
    - Determine the free ring depth based on the XDP TX queue size and adjust it for loopback if the tile index is zero.
- **Output**: The function does not return a value; it modifies the network tile's configuration within the topology.


---
### setup\_sock\_tile<!-- {{#callable:setup_sock_tile}} -->
The `setup_sock_tile` function configures a socket tile in a network topology by setting its bind address and socket buffer sizes based on the provided network configuration.
- **Inputs**:
    - `topo`: A pointer to the network topology structure (`fd_topo_t`) that the socket tile is part of.
    - `tile_to_cpu`: A pointer to an array of unsigned long integers mapping tile indices to CPU indices.
    - `net_cfg`: A pointer to a constant network configuration structure (`fd_config_net_t`) containing network settings, including bind address and socket buffer sizes.
- **Control Flow**:
    - Retrieve a tile from the topology using `fd_topob_tile` with the type 'sock' and the CPU index from `tile_to_cpu` corresponding to the current tile count in `topo`.
    - Set the `bind_address` of the tile's network configuration to the parsed bind address from `net_cfg`.
    - Check if the `receive_buffer_size` in `net_cfg` exceeds `INT_MAX`; if so, log an error and terminate.
    - Check if the `send_buffer_size` in `net_cfg` exceeds `INT_MAX`; if so, log an error and terminate.
    - Set the tile's network receive buffer size (`so_rcvbuf`) to the `receive_buffer_size` from `net_cfg`, cast to an integer.
    - Set the tile's network send buffer size (`so_sndbuf`) to the `send_buffer_size` from `net_cfg`, cast to an integer.
- **Output**: The function does not return a value; it modifies the network topology structure in place.


---
### fd\_topos\_net\_tiles<!-- {{#callable:fd_topos_net_tiles}} -->
The `fd_topos_net_tiles` function initializes network tiles in a topology based on the specified network configuration provider, either 'xdp' or 'socket', and sets up the necessary workspaces and configurations for each tile.
- **Inputs**:
    - `topo`: A pointer to the `fd_topo_t` structure representing the network topology.
    - `net_tile_cnt`: The number of network tiles to be configured.
    - `net_cfg`: A constant pointer to the `fd_config_net_t` structure containing network configuration details.
    - `netlnk_max_routes`: The maximum number of routes for the netlink tile.
    - `netlnk_max_neighbors`: The maximum number of neighbors for the netlink tile.
    - `tile_to_cpu`: An array mapping tile indices to CPU indices, with a maximum size of `FD_TILE_MAX`.
- **Control Flow**:
    - Initialize the packet buffer workspace by calling `fd_topob_wksp` with 'net_umem'.
    - Check if the network provider specified in `net_cfg` is 'xdp'.
    - If 'xdp', initialize workspaces for 'net', 'netlnk', 'netbase', and 'net_netlnk'.
    - Create a netlink tile using `fd_topob_tile` and configure it with `fd_netlink_topo_create`.
    - Iterate over the number of network tiles (`net_tile_cnt`) and call [`setup_xdp_tile`](#setup_xdp_tile) for each tile to configure it.
    - If the network provider is 'socket', initialize the 'sock' workspace.
    - Iterate over the number of network tiles (`net_tile_cnt`) and call [`setup_sock_tile`](#setup_sock_tile) for each tile to configure it.
    - If the network provider is neither 'xdp' nor 'socket', log an error indicating an invalid provider.
- **Output**: The function does not return a value; it performs setup operations on the provided topology structure.
- **Functions called**:
    - [`setup_xdp_tile`](#setup_xdp_tile)
    - [`setup_sock_tile`](#setup_sock_tile)


---
### topo\_is\_xdp<!-- {{#callable:topo_is_xdp}} -->
The `topo_is_xdp` function checks if any tile in the given topology is named 'net', indicating the presence of an XDP (eXpress Data Path) configuration.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology to be checked.
- **Control Flow**:
    - Iterate over each tile in the `topo` structure using a for loop.
    - For each tile, compare its name to the string "net" using `strcmp`.
    - If a match is found, return 1 to indicate the presence of a 'net' tile.
    - If no match is found after checking all tiles, return 0.
- **Output**: Returns 1 if a tile named 'net' is found, otherwise returns 0.


---
### add\_xdp\_rx\_link<!-- {{#callable:add_xdp_rx_link}} -->
The `add_xdp_rx_link` function adds a new XDP RX link to the topology, ensuring the link name is unique and within limits, and associates it with the appropriate memory cache and depth properties.
- **Inputs**:
    - `topo`: A pointer to the `fd_topo_t` structure representing the network topology.
    - `link_name`: A constant character pointer representing the name of the link to be added.
    - `net_kind_id`: An unsigned long integer representing the network kind identifier.
    - `depth`: An unsigned long integer representing the depth of the link.
- **Control Flow**:
    - Check if `topo` or `link_name` is NULL and log an error if so.
    - Check if the length of `link_name` exceeds the maximum allowed size and log an error if so.
    - Check if the number of links has reached the maximum allowed and log an error if so.
    - Initialize `kind_id` to 0 and iterate over existing links to count occurrences of `link_name`, incrementing `kind_id` for each match.
    - Create a new link in the topology's links array at the current link count index.
    - Copy `link_name` into the new link's name field, set its ID to the current link count, and assign `kind_id`, `depth`, and default values for `mtu` and `burst`.
    - Retrieve the memory cache object ID and assign it to the new link's `mcache_obj_id`.
    - Insert the depth property into the topology's properties using the memory cache object ID.
    - Query for the data cache object ID using `net_kind_id` and assign it to the new link's `dcache_obj_id`, logging an error if not found.
    - Increment the topology's link count.
- **Output**: The function does not return a value; it modifies the `topo` structure by adding a new link.


---
### fd\_topos\_net\_rx\_link<!-- {{#callable:fd_topos_net_rx_link}} -->
The `fd_topos_net_rx_link` function configures a network receive link in a topology, either using XDP or socket-based methods, depending on the topology configuration.
- **Inputs**:
    - `topo`: A pointer to the `fd_topo_t` structure representing the network topology.
    - `link_name`: A constant character pointer representing the name of the link to be configured.
    - `net_kind_id`: An unsigned long integer representing the network kind identifier.
    - `depth`: An unsigned long integer representing the depth of the link.
- **Control Flow**:
    - Check if the topology is configured for XDP using [`topo_is_xdp`](#topo_is_xdp) function.
    - If XDP is configured, call [`add_xdp_rx_link`](#add_xdp_rx_link) to add the XDP receive link and then call `fd_topob_tile_out` to configure the tile output for the 'net' kind.
    - If XDP is not configured, call `fd_topob_link` to add a link with 'net_umem' and then call `fd_topob_tile_out` to configure the tile output for the 'sock' kind.
- **Output**: The function does not return a value; it modifies the topology structure to add a network receive link.
- **Functions called**:
    - [`topo_is_xdp`](#topo_is_xdp)
    - [`add_xdp_rx_link`](#add_xdp_rx_link)


---
### fd\_topos\_tile\_in\_net<!-- {{#callable:fd_topos_tile_in_net}} -->
The `fd_topos_tile_in_net` function configures input links for network or socket tiles in a topology.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology configuration.
    - `fseq_wksp`: A constant character pointer to the name of the workspace for the flow sequence.
    - `link_name`: A constant character pointer to the name of the link to be configured.
    - `link_kind_id`: An unsigned long integer representing the kind ID of the link.
    - `reliable`: An integer indicating whether the link is reliable (non-zero) or not (zero).
    - `polled`: An integer indicating whether the link is polled (non-zero) or not (zero).
- **Control Flow**:
    - Iterates over all tiles in the topology using a for loop.
    - Checks if the tile's name is either 'net' or 'sock'.
    - If the tile's name matches, calls `fd_topob_tile_in` to configure the input link for the tile with the provided parameters.
- **Output**: The function does not return a value; it performs configuration actions on the topology structure.


---
### fd\_topos\_net\_tile\_finish<!-- {{#callable:fd_topos_net_tile_finish}} -->
The `fd_topos_net_tile_finish` function finalizes the configuration of a network tile in a topology by adjusting queue sizes and setting up memory caches based on the network kind identifier.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the network topology.
    - `net_kind_id`: An unsigned long integer representing the network kind identifier for which the tile configuration is being finalized.
- **Control Flow**:
    - Check if the topology is using XDP; if not, return immediately.
    - Find the network tile associated with the given `net_kind_id`.
    - Calculate the receive (RX) and transmit (TX) queue depths, increasing each by 50%.
    - If `net_kind_id` is 0, double the RX and TX depths for loopback XSK.
    - Initialize `cum_frame_cnt` with the sum of RX and TX depths.
    - Iterate over all outgoing links of the network tile to accumulate the depth of all RX mcaches into `cum_frame_cnt`.
    - Retrieve the UMEM object ID associated with the network kind ID and ensure it is valid.
    - Ensure the network tile's UMEM dcache object ID is greater than 0.
    - Insert the cumulative frame count, burst size, and MTU into the topology properties for the UMEM object.
- **Output**: The function does not return a value; it modifies the topology properties in place.
- **Functions called**:
    - [`topo_is_xdp`](#topo_is_xdp)



# Purpose
This C header file, `fd_net_tile.h`, is part of a networking module designed to facilitate XDP (eXpress Data Path) networking within a Firedancer topology using a 'net' tile. It includes APIs for managing and interacting with network tiles, specifically focusing on receiving (RX) packet handling and topology configuration. The file defines structures and functions to initialize and translate packet bounds, ensuring that packet payloads are correctly located and accessed within memory constraints. Additionally, it provides functions to append network tiles to a topology, establish packet RX links, and register network transmission links, which are crucial for setting up efficient and reliable network communication paths in a high-performance computing environment. The file also includes error handling to ensure robustness in packet processing and topology management.
# Imports and Dependencies

---
- `../fd_disco_base.h`
- `../../tango/dcache/fd_dcache.h`


# Global Variables

---
### FD\_PROTOTYPES\_BEGIN
- **Type**: `Macro`
- **Description**: `FD_PROTOTYPES_BEGIN` is a macro used to mark the beginning of a section in the code where function prototypes are declared. It is typically used in conjunction with `FD_PROTOTYPES_END` to encapsulate function declarations, ensuring that they are properly organized and easily identifiable within the codebase.
- **Use**: This macro is used to delineate sections of function prototypes in the code, aiding in code organization and readability.


# Data Structures

---
### fd\_topo\_t
- **Type**: `typedef`
- **Members**:
    - `fd_topo_t`: An alias for the struct fd_topo, representing a Firedancer topology.
- **Description**: The `fd_topo_t` is a typedef for the `struct fd_topo`, which is used within the Firedancer framework to represent a network topology. This data structure is central to managing and configuring network tiles, which are components that facilitate fast XDP networking. The `fd_topo_t` is utilized in various functions to append network tiles, link network tiles to applications, and finalize network tile configurations, indicating its role in orchestrating the network layout and communication pathways within the Firedancer system.


---
### fd\_net\_rx\_bounds
- **Type**: `struct`
- **Members**:
    - `base`: Base address of the workspace containing the dcache.
    - `pkt_lo`: Lowest permitted pointer to packet payload.
    - `pkt_wmark`: Highest permitted pointer to packet payload.
- **Description**: The `fd_net_rx_bounds` structure is used to define the bounds for receiving packets in a network tile setup. It contains three members: `base`, which holds the base address of the workspace containing the dcache; `pkt_lo`, which specifies the lowest permissible pointer to a packet payload; and `pkt_wmark`, which indicates the highest permissible pointer to a packet payload. This structure is crucial for ensuring that packet payloads are accessed within valid memory bounds, preventing out-of-bounds errors during network operations.


---
### fd\_net\_rx\_bounds\_t
- **Type**: `struct`
- **Members**:
    - `base`: Base address of the workspace containing the dcache.
    - `pkt_lo`: Lowest permitted pointer to packet payload.
    - `pkt_wmark`: Highest permitted pointer to packet payload.
- **Description**: The `fd_net_rx_bounds_t` structure is used to define the bounds for receiving packets in a network tile within the Firedancer topology. It contains three members: `base`, which holds the base address of the workspace containing the dcache; `pkt_lo`, which is the lowest permitted pointer to a packet payload; and `pkt_wmark`, which is the highest permitted pointer to a packet payload. This structure is crucial for ensuring that packet payloads are accessed within valid memory bounds, preventing out-of-bounds errors during network operations.


---
### fd\_config\_net\_t
- **Type**: `typedef struct fd_config_net fd_config_net_t;`
- **Description**: The `fd_config_net_t` is a typedef for a structure named `fd_config_net`, which is used in the context of configuring network tiles within a Firedancer topology. The specific details of the structure's members are not provided in the given code, indicating that it is likely defined elsewhere. This structure is used as a parameter in functions related to appending network tiles to a topology, suggesting its role in network configuration and management within the Firedancer system.


# Functions

---
### fd\_net\_rx\_bounds\_init<!-- {{#callable:fd_net_rx_bounds_init}} -->
The `fd_net_rx_bounds_init` function initializes a bounds checker for RX packets by setting up the base address and permissible packet payload range within a data cache.
- **Inputs**:
    - `bounds`: A pointer to an `fd_net_rx_bounds_t` structure that will be initialized to define the bounds for RX packets.
    - `dcache`: A pointer to a data cache (dcache) that contains packet payloads, used to determine the bounds for RX packets.
- **Control Flow**:
    - The function calculates the base address of the workspace containing the dcache using `fd_wksp_containing` and assigns it to `bounds->base`.
    - It sets `bounds->pkt_lo` to the address of the dcache, marking the lowest permissible pointer to packet payloads.
    - It calculates `bounds->pkt_wmark` as the sum of `bounds->pkt_lo` and the size of the data cache minus the maximum transmission unit (MTU), marking the highest permissible pointer to packet payloads.
    - The function checks if `bounds->base` is zero, which would indicate a failure to find the workspace containing the dcache, and logs an error if this unlikely event occurs.
- **Output**: The function does not return a value; it initializes the `fd_net_rx_bounds_t` structure pointed to by `bounds` with the calculated bounds for RX packets.


---
### fd\_net\_rx\_translate\_frag<!-- {{#callable:fd_net_rx_translate_frag}} -->
The `fd_net_rx_translate_frag` function calculates a pointer to the start of a packet payload in memory and checks if it is within valid bounds, logging an error and terminating the application if it is not.
- **Inputs**:
    - `bounds`: A pointer to an `fd_net_rx_bounds_t` structure containing the base address and valid packet payload bounds.
    - `chunk`: An unsigned long integer representing the chunk index used to calculate the packet's memory address.
    - `ctl`: An unsigned long integer used as an offset in the memory address calculation.
    - `sz`: An unsigned long integer representing the size of the packet fragment.
- **Control Flow**:
    - Calculate the memory address `p` using the base address from `bounds`, the `chunk` shifted by `FD_CHUNK_LG_SZ`, and the `ctl` offset.
    - Check if `p` is within the bounds specified by `pkt_lo` and `pkt_wmark` in `bounds`, and if `sz` is less than or equal to `FD_NET_MTU`.
    - If the calculated address `p` is out of bounds or `sz` exceeds `FD_NET_MTU`, log an error message and terminate the application.
    - Return the calculated address `p` as a constant void pointer.
- **Output**: A constant void pointer to the calculated memory address of the packet payload.


# Function Declarations (Public API)

---
### fd\_topos\_net\_tiles<!-- {{#callable_declaration:fd_topos_net_tiles}} -->
Append net and netlnk tiles to the topology for XDP networking.
- **Description**: This function is used to enhance a Firedancer topology by appending network tiles that provide fast XDP networking capabilities. It should be called when setting up a topology that requires network communication, specifically using XDP or socket-based providers. The function configures the necessary workspaces and network links based on the provided configuration. It is important to ensure that the `topo` structure is properly initialized before calling this function, and that the `net_cfg` specifies a valid provider. The function handles different network providers by setting up the appropriate tiles and workspaces, and it logs an error if an invalid provider is specified.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology to which the net and netlnk tiles will be appended. Must not be null.
    - `net_tile_cnt`: The number of network tiles to append. Must be a non-negative integer.
    - `net_config`: A pointer to a constant `fd_config_net_t` structure containing the network configuration. Must not be null and must specify a valid provider ('xdp' or 'socket').
    - `netlnk_max_routes`: The maximum number of routes for the netlnk tile. Must be a non-negative integer.
    - `netlnk_max_neighbors`: The maximum number of neighbors for the netlnk tile. Must be a non-negative integer.
    - `tile_to_cpu`: An array mapping tile indices to CPU indices. The array must have at least `FD_TILE_MAX` elements.
- **Output**: None
- **See also**: [`fd_topos_net_tiles`](fd_net_tile_topo.c.driver.md#fd_topos_net_tiles)  (Implementation)


---
### fd\_topos\_net\_rx\_link<!-- {{#callable_declaration:fd_topos_net_rx_link}} -->
Establish a packet reception link between a network and application tile in a topology.
- **Description**: This function is used to create a link for receiving packets from a network tile to an application tile within a Firedancer topology. It should be called when setting up the network topology, specifically for configuring packet reception paths. The function adapts its behavior based on whether the topology uses XDP (eXpress Data Path) or not, ensuring the appropriate link type is established. It is important to ensure that the topology (`topo`) is properly initialized before calling this function.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology. Must not be null and should be properly initialized before use.
    - `link_name`: A constant character pointer representing the name of the link. Must not be null and should be a valid, unique identifier for the link within the topology.
    - `net_kind_id`: An unsigned long integer representing the network kind identifier. It should correspond to a valid network kind within the topology.
    - `depth`: An unsigned long integer specifying the depth of the link. It should be a positive value indicating the buffer depth for the link.
- **Output**: None
- **See also**: [`fd_topos_net_rx_link`](fd_net_tile_topo.c.driver.md#fd_topos_net_rx_link)  (Implementation)


---
### fd\_topos\_tile\_in\_net<!-- {{#callable_declaration:fd_topos_tile_in_net}} -->
Registers a net TX link with all net tiles.
- **Description**: This function is used to register a network transmission link with all network tiles in a given topology. It should be called after all application-to-network tile links have been established. This function is typically invoked once per network tile to ensure proper link registration. It is important to ensure that the topology and other parameters are correctly set up before calling this function to avoid unexpected behavior.
- **Inputs**:
    - `topo`: A pointer to an fd_topo_t structure representing the topology. Must not be null.
    - `fseq_wksp`: A constant character pointer representing the workspace for the sequence. Must not be null.
    - `link_name`: A constant character pointer representing the name of the link. Must not be null.
    - `link_kind_id`: An unsigned long representing the kind ID of the link. Should be a valid kind ID.
    - `reliable`: An integer indicating whether the link is reliable. Non-zero for reliable, zero otherwise.
    - `polled`: An integer indicating whether the link is polled. Non-zero for polled, zero otherwise.
- **Output**: None
- **See also**: [`fd_topos_tile_in_net`](fd_net_tile_topo.c.driver.md#fd_topos_tile_in_net)  (Implementation)


---
### fd\_topos\_net\_tile\_finish<!-- {{#callable_declaration:fd_topos_net_tile_finish}} -->
Finalize the configuration of a network tile in the topology.
- **Description**: This function should be called after all application-to-network tile links have been established and is used to finalize the setup of a specific network tile within a Firedancer topology. It adjusts internal parameters related to the network tile's queue sizes and ensures that necessary properties are set for the tile's operation. This function must be called once for each network tile to ensure proper configuration.
- **Inputs**:
    - `topo`: A pointer to an fd_topo_t structure representing the topology. Must not be null and should be properly initialized before calling this function.
    - `net_kind_id`: An unsigned long integer identifying the kind of network tile to finalize. It should correspond to a valid network tile within the topology.
- **Output**: None
- **See also**: [`fd_topos_net_tile_finish`](fd_net_tile_topo.c.driver.md#fd_topos_net_tile_finish)  (Implementation)



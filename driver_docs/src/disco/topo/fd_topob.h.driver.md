# Purpose
The provided C header file, `fd_topob.h`, is a builder interface for constructing and managing a topology using the `fd_topo` framework. It offers a collection of functions designed to facilitate the creation and manipulation of a network topology, which includes elements such as tiles, objects, links, and workspaces. The file defines several macros and functions that allow users to initialize a new topology, add components like workspaces and objects, establish relationships between tiles and objects, and manage links with specific properties such as reliability and polling status. The header file is intended to be included in other C source files, providing a public API for developers to build and configure complex topologies programmatically.

Key components of this file include functions for adding and configuring tiles, links, and objects within a topology, as well as managing their interconnections and memory mappings. The file defines constants for link polling and reliability, ensuring that users can specify the behavior of links in the topology. The functions provided allow for detailed customization, such as setting up input and output links for tiles, automatically laying out tiles onto CPUs, and finalizing the topology configuration. This header file is part of a broader system, likely used in environments where efficient data flow and resource management are critical, such as in high-performance computing or distributed systems.
# Imports and Dependencies

---
- `../../disco/topo/fd_topo.h`


# Global Variables

---
### fd\_topob\_new
- **Type**: `function pointer`
- **Description**: The `fd_topob_new` is a function that initializes a new `fd_topo_t` structure at a specified memory address and associates it with a given application name. This function returns a pointer to the newly created topology, which initially contains no tiles, objects, or links.
- **Use**: This function is used to create and initialize an empty topology structure for further configuration and use in the application.


---
### fd\_topob\_obj
- **Type**: `fd_topo_obj_t *`
- **Description**: The `fd_topob_obj` function is a global function that returns a pointer to an `fd_topo_obj_t` structure. It is used to add an object with a specified name to a topology, associating it with a given workspace name. This function ensures that the object occupies space in memory within the specified workspace, although it does not automatically map the object into any tiles.
- **Use**: This function is used to create and manage objects within a topology, associating them with specific workspaces.


---
### fd\_topob\_link
- **Type**: `fd_topo_link_t *`
- **Description**: The `fd_topob_link` function returns a pointer to a `fd_topo_link_t` structure, which represents a link in a topology. This link is characterized by its name, associated workspace, depth, maximum transmission unit (MTU), and burst size. The link is initially created without any producer or consumer, and these need to be added separately.
- **Use**: This function is used to add a new link to a topology, which can later be configured with producers and consumers.


---
### fd\_topob\_tile
- **Type**: `fd_topo_tile_t *`
- **Description**: The `fd_topob_tile` is a function that returns a pointer to an `fd_topo_tile_t` structure. It is used to add a tile to the topology, which involves creating various objects needed for a standard tile, such as tile scratch memory and metrics memory. These objects are linked to the respective workspaces provided, and the tile is specified to map those workspaces when it is attached.
- **Use**: This function is used to add and configure a tile within a topology, linking it to specific workspaces and setting its properties such as CPU index and whether it uses keyswitch or is an agave tile.


# Function Declarations (Public API)

---
### fd\_topob\_new<!-- {{#callable_declaration:fd_topob_new}} -->
Initialize a new fd_topo_t with the given app name at the specified memory address.
- **Description**: This function initializes a new fd_topo_t structure at the provided memory address and assigns it the specified application name. It should be used to create an empty topology with no tiles, objects, or links. The memory address must be properly aligned for fd_topo_t, and the application name must fit within the allocated space. If the memory is null or misaligned, or if the application name is too long, the function will return null and log a warning or error.
- **Inputs**:
    - `mem`: A pointer to the memory location where the fd_topo_t structure will be initialized. Must not be null and must be aligned to the requirements of fd_topo_t.
    - `app_name`: A string representing the application name to be assigned to the topology. The length of the string must be less than the maximum allowed size for the app_name field in fd_topo_t.
- **Output**: Returns a pointer to the initialized fd_topo_t structure, or null if initialization fails due to null or misaligned memory, or an overly long application name.
- **See also**: [`fd_topob_new`](fd_topob.c.driver.md#fd_topob_new)  (Implementation)


---
### fd\_topob\_wksp<!-- {{#callable_declaration:fd_topob_wksp}} -->
Add a workspace with a unique name to the topology.
- **Description**: This function is used to add a new workspace to an existing topology, identified by a unique name. It is essential to ensure that the workspace name is unique within the topology, as duplicate names will result in an error. The function should be called when you need to expand the topology with additional workspaces, and it is important to ensure that the total number of workspaces does not exceed the maximum allowed limit. This function must be called with valid parameters, as it does not handle null pointers or empty names gracefully.
- **Inputs**:
    - `topo`: A pointer to an fd_topo_t structure representing the topology to which the workspace will be added. Must not be null.
    - `name`: A constant character pointer representing the name of the workspace to be added. The name must be unique, non-null, and non-empty, and its length must be less than the maximum allowed size for workspace names.
- **Output**: None
- **See also**: [`fd_topob_wksp`](fd_topob.c.driver.md#fd_topob_wksp)  (Implementation)


---
### fd\_topob\_obj<!-- {{#callable_declaration:fd_topob_obj}} -->
Add an object with a specified name to a topology.
- **Description**: Use this function to add an object to a topology, associating it with a specified workspace. The workspace must already exist in the topology. This function is useful for allocating space for an object in memory, although it does not map the object into any tiles. Ensure that the topology, object name, and workspace name are valid and non-null before calling this function. The object name must not exceed the maximum allowed length, and the total number of objects must not exceed the predefined limit. If these conditions are not met, the function will log an error and terminate.
- **Inputs**:
    - `topo`: A pointer to an fd_topo_t structure representing the topology. Must not be null.
    - `obj_name`: A string representing the name of the object to add. Must not be null and must be shorter than the maximum allowed length for object names.
    - `wksp_name`: A string representing the name of the workspace to associate with the object. Must not be null and the workspace must already exist in the topology.
- **Output**: Returns a pointer to the newly added fd_topo_obj_t structure representing the object.
- **See also**: [`fd_topob_obj`](fd_topob.c.driver.md#fd_topob_obj)  (Implementation)


---
### fd\_topob\_tile\_uses<!-- {{#callable_declaration:fd_topob_tile_uses}} -->
Add a relationship indicating a tile uses a specific object in a given mode.
- **Description**: This function establishes a relationship between a tile and an object within a topology, specifying that the tile uses the object in a particular mode. It should be used when you want to map an object into a tile's memory space, allowing the tile to access the object either in read-only or read-write mode. Ensure that the tile has not exceeded its maximum number of objects before calling this function, as exceeding this limit will result in an error. This function is typically used after creating both the tile and the object within the topology.
- **Inputs**:
    - `topo`: A pointer to the topology structure. The function does not use this parameter, but it is required for consistency with other API functions. The caller retains ownership.
    - `tile`: A pointer to the tile structure that will use the object. Must not be null. The tile should have been previously added to the topology.
    - `obj`: A pointer to the object structure that the tile will use. Must not be null. The object should have been previously added to the topology.
    - `mode`: An integer specifying the mode in which the tile will use the object. It should be either FD_SHMEM_JOIN_MODE_READ_ONLY or FD_SHMEM_JOIN_MODE_READ_WRITE.
- **Output**: None
- **See also**: [`fd_topob_tile_uses`](fd_topob.c.driver.md#fd_topob_tile_uses)  (Implementation)


---
### fd\_topob\_link<!-- {{#callable_declaration:fd_topob_link}} -->
Add a link to the topology with specified parameters.
- **Description**: This function is used to add a new link to an existing topology. It requires a valid topology object and unique link and workspace names. The function sets up the link with specified depth, MTU, and burst values. It is important to ensure that the link name is not too long and that the topology has not exceeded its maximum number of links. The function will log an error if any of these conditions are not met. This function should be called when you need to establish a new communication link within the topology, and it assumes that the workspace associated with the link already exists.
- **Inputs**:
    - `topo`: A pointer to an fd_topo_t structure representing the topology. Must not be null.
    - `link_name`: A string representing the name of the link. Must not be null and should be unique within the topology.
    - `wksp_name`: A string representing the name of the workspace associated with the link. Must not be null and should correspond to an existing workspace.
    - `depth`: An unsigned long specifying the depth of the link. Represents the buffer depth for the link.
    - `mtu`: An unsigned long specifying the maximum transmission unit for the link. Determines the maximum size of data packets.
    - `burst`: An unsigned long specifying the burst size for the link. Represents the maximum number of packets that can be sent in a burst.
- **Output**: Returns a pointer to the newly created fd_topo_link_t structure representing the link.
- **See also**: [`fd_topob_link`](fd_topob.c.driver.md#fd_topob_link)  (Implementation)


---
### fd\_topob\_tile<!-- {{#callable_declaration:fd_topob_tile}} -->
Add a tile to the topology with specified properties and workspaces.
- **Description**: This function is used to add a new tile to an existing topology, associating it with specific workspaces for tile operations and metrics. It should be called when you need to expand the topology with a new tile that has defined characteristics such as CPU index and whether it uses a keyswitch. The function requires valid workspace names and a non-null topology structure. It ensures that the tile name is unique and not too long, and that the topology has not exceeded its maximum tile capacity. The function also handles the creation of necessary objects and their associations with the tile.
- **Inputs**:
    - `topo`: A pointer to an fd_topo_t structure representing the topology. Must not be null.
    - `tile_name`: A string representing the name of the tile. Must not be null and should be unique within the topology. The length must be less than the maximum allowed for tile names.
    - `tile_wksp`: A string representing the name of the workspace for the tile. Must not be null and should correspond to an existing workspace in the topology.
    - `metrics_wksp`: A string representing the name of the workspace for metrics. Must not be null and should correspond to an existing workspace in the topology.
    - `cpu_idx`: An unsigned long representing the CPU index to which the tile is assigned.
    - `is_agave`: An integer indicating whether the tile is an Agave tile (non-zero) or not (zero).
    - `uses_keyswitch`: An integer indicating whether the tile uses a keyswitch (non-zero) or not (zero).
- **Output**: Returns a pointer to the newly added fd_topo_tile_t structure representing the tile in the topology.
- **See also**: [`fd_topob_tile`](fd_topob.c.driver.md#fd_topob_tile)  (Implementation)


---
### fd\_topob\_tile\_in<!-- {{#callable_declaration:fd_topob_tile_in}} -->
Add an input link to a tile in the topology.
- **Description**: This function is used to associate an input link with a specified tile in the topology, allowing the tile to receive data from the link. It should be called after the tile and link have been added to the topology. The function requires the tile and link names, their respective kind identifiers, and the workspace name for the flow sequence (fseq). The link can be marked as reliable or unreliable, and as polled or unpolled, affecting how data is read and flow control is managed. The function will log an error if any of the input parameters are null, if the tile or link cannot be found, or if the tile has reached its maximum number of input links.
- **Inputs**:
    - `topo`: A pointer to the fd_topo_t structure representing the topology. Must not be null.
    - `tile_name`: A string representing the name of the tile to which the input link is being added. Must not be null.
    - `tile_kind_id`: An unsigned long representing the kind identifier for the tile.
    - `fseq_wksp`: A string representing the name of the workspace for the flow sequence. Must not be null.
    - `link_name`: A string representing the name of the link to be added as an input to the tile. Must not be null.
    - `link_kind_id`: An unsigned long representing the kind identifier for the link.
    - `reliable`: An integer indicating whether the link is reliable (1) or unreliable (0).
    - `polled`: An integer indicating whether the link is polled (1) or unpolled (0).
- **Output**: None
- **See also**: [`fd_topob_tile_in`](fd_topob.c.driver.md#fd_topob_tile_in)  (Implementation)


---
### fd\_topob\_tile\_out<!-- {{#callable_declaration:fd_topob_tile_out}} -->
Add an output link to a tile in the topology.
- **Description**: This function associates an output link with a specified tile in the topology, allowing the tile to write to the link. It should be used when you want to enable a tile to send data through a specific link. The function requires that both the tile and the link are already defined in the topology. It is important to ensure that the number of output links for a tile does not exceed the maximum allowed. This function must be called after the tile and link have been added to the topology using the appropriate functions.
- **Inputs**:
    - `topo`: A pointer to the topology structure where the tile and link are defined. Must not be null.
    - `tile_name`: The name of the tile to which the output link will be added. Must correspond to an existing tile in the topology.
    - `tile_kind_id`: The kind identifier for the tile, used to uniquely identify the tile within its kind. Must correspond to an existing tile kind in the topology.
    - `link_name`: The name of the link to be added as an output link for the tile. Must correspond to an existing link in the topology.
    - `link_kind_id`: The kind identifier for the link, used to uniquely identify the link within its kind. Must correspond to an existing link kind in the topology.
- **Output**: None
- **See also**: [`fd_topob_tile_out`](fd_topob.c.driver.md#fd_topob_tile_out)  (Implementation)


---
### fd\_topob\_auto\_layout<!-- {{#callable_declaration:fd_topob_auto_layout}} -->
Automatically layout tiles onto CPUs in the topology.
- **Description**: This function assigns CPU cores to tiles in the given topology, attempting to optimize for NUMA locality and critical tile performance. It should be called after all tiles have been added to the topology but before finalizing it. The function will leave certain tiles floating if they are not recognized as part of the ordered or critical sets. If `reserve_agave_cores` is non-zero, it will reserve additional CPU cores for agave affinity, if available. The function logs warnings for any unrecognized tiles that are left floating.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology. Must not be null and should be properly initialized with tiles added.
    - `reserve_agave_cores`: An integer flag indicating whether to reserve additional CPU cores for agave affinity. Non-zero values enable this reservation.
- **Output**: None
- **See also**: [`fd_topob_auto_layout`](fd_topob.c.driver.md#fd_topob_auto_layout)  (Implementation)


---
### fd\_topob\_finish<!-- {{#callable_declaration:fd_topob_finish}} -->
Finalize the topology creation by laying out objects and validating the topology.
- **Description**: This function completes the setup of a topology by arranging all objects within their respective workspaces and ensuring that all components are correctly sized and aligned. It also performs a validation check on the topology to ensure its correctness. This function must be called after all components of the topology have been added and configured, as it finalizes the topology's structure and prepares it for use. It is essential to provide valid callbacks for each object in the topology to handle specific operations like alignment and footprint calculation.
- **Inputs**:
    - `topo`: A pointer to an fd_topo_t structure representing the topology to be finalized. This must be a valid and fully configured topology object.
    - `callbacks`: An array of pointers to fd_topo_obj_callbacks_t structures, each providing callback functions for specific object operations. The array must be null-terminated, and each object in the topology must have a corresponding callback entry. If a callback for an object is missing, the function will log an error and terminate.
- **Output**: None
- **See also**: [`fd_topob_finish`](fd_topob.c.driver.md#fd_topob_finish)  (Implementation)



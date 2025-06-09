# Purpose
The provided C source code file is part of a larger system that manages and configures a topology of computational resources, likely for a distributed or parallel computing environment. The file defines several functions that operate on a data structure, `fd_topo_t`, which represents the topology. This structure includes components such as workspaces, objects, links, and tiles, each with specific attributes and relationships. The functions in this file are responsible for creating and configuring these components, ensuring they are correctly aligned and named, and managing their interconnections. The code also includes validation functions to ensure the integrity of the topology configuration, such as checking for unique workspace names and ensuring each link has the correct number of producers and consumers.

The file provides a broad range of functionality related to topology management, including the creation of new topology components ([`fd_topob_new`](#fd_topob_new)), adding workspaces ([`fd_topob_wksp`](#fd_topob_wksp)), objects ([`fd_topob_obj`](#fd_topob_obj)), links ([`fd_topob_link`](#fd_topob_link)), and tiles ([`fd_topob_tile`](#fd_topob_tile)). It also includes functions for setting up input and output links for tiles, validating the topology configuration, and automatically assigning resources like CPU cores to tiles ([`fd_topob_auto_layout`](#fd_topob_auto_layout)). The code is designed to be part of a library that can be imported and used by other parts of the system, as it defines a set of public APIs for managing the topology. The file also includes mechanisms for logging errors and warnings, which helps in debugging and ensuring the robustness of the topology configuration.
# Imports and Dependencies

---
- `fd_topob.h`
- `../../util/pod/fd_pod_format.h`
- `fd_cpu_topo.h`


# Functions

---
### fd\_topob\_new<!-- {{#callable:fd_topob_new}} -->
The `fd_topob_new` function initializes a new `fd_topo_t` structure with specified memory and application name, ensuring proper alignment and setting default properties.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_topo_t` structure will be initialized.
    - `app_name`: A constant character pointer representing the application name to be stored in the `fd_topo_t` structure.
- **Control Flow**:
    - Cast the `mem` pointer to a `fd_topo_t` pointer named `topo`.
    - Check if `topo` is NULL and log a warning if true, then return NULL.
    - Check if `topo` is properly aligned to `fd_topo_t` alignment requirements and log a warning if not, then return NULL.
    - Initialize the memory of `topo` to zero using `fd_memset`.
    - Create a new property object using `fd_pod_new` for `topo->props`.
    - Check if `app_name` length exceeds the maximum allowed size for `topo->app_name` and log an error if true.
    - Copy `app_name` into `topo->app_name` using `strncpy`.
    - Set `topo->max_page_size` to `FD_SHMEM_GIGANTIC_PAGE_SZ`.
    - Set `topo->gigantic_page_threshold` to four times `FD_SHMEM_HUGE_PAGE_SZ`.
    - Return the initialized `topo` pointer.
- **Output**: Returns a pointer to the initialized `fd_topo_t` structure, or NULL if initialization fails due to alignment or memory issues.


---
### fd\_topob\_wksp<!-- {{#callable:fd_topob_wksp}} -->
The `fd_topob_wksp` function adds a new workspace to a topology structure, ensuring the workspace name is valid and unique, and increments the workspace count.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology to which the workspace will be added.
    - `name`: A constant character pointer representing the name of the workspace to be added.
- **Control Flow**:
    - Check if `topo` or `name` is NULL or if `name` is an empty string; if so, log an error and terminate.
    - Check if the length of `name` exceeds the maximum allowed size for a workspace name; if so, log an error and terminate.
    - Check if the current workspace count has reached the maximum allowed workspaces; if so, log an error and terminate.
    - Retrieve a pointer to the next available workspace slot in the `workspaces` array of the `topo` structure.
    - Copy the `name` into the `name` field of the workspace, ensuring it fits within the allocated space.
    - Set the `id` of the workspace to the current workspace count.
    - Increment the workspace count in the `topo` structure.
- **Output**: This function does not return a value; it modifies the `topo` structure in place by adding a new workspace.


---
### fd\_topob\_obj<!-- {{#callable:fd_topob_obj}} -->
The `fd_topob_obj` function creates and initializes a new topology object within a given topology structure, associating it with a specified workspace.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology where the object will be added.
    - `obj_name`: A constant character pointer representing the name of the object to be created.
    - `wksp_name`: A constant character pointer representing the name of the workspace to associate with the object.
- **Control Flow**:
    - Check if any of the input arguments (`topo`, `obj_name`, `wksp_name`) are NULL and log an error if so.
    - Check if the length of `obj_name` exceeds the maximum allowed size for object names in the topology and log an error if it does.
    - Check if the current object count in the topology has reached the maximum allowed number of objects and log an error if it has.
    - Find the workspace ID associated with `wksp_name` using `fd_topo_find_wksp` and log an error if the workspace is not found.
    - Create a new object in the topology's object array at the current object count index.
    - Copy `obj_name` into the new object's name field, set its ID to the current object count, and set its workspace ID to the found workspace ID.
    - Increment the topology's object count.
    - Return a pointer to the newly created object.
- **Output**: A pointer to the newly created `fd_topo_obj_t` object within the topology.


---
### fd\_topob\_link<!-- {{#callable:fd_topob_link}} -->
The `fd_topob_link` function creates and initializes a new link in a topology structure, associating it with specified workspace objects and properties.
- **Inputs**:
    - `topo`: A pointer to the topology structure (`fd_topo_t`) where the link will be added.
    - `link_name`: A constant character pointer representing the name of the link to be created.
    - `wksp_name`: A constant character pointer representing the name of the workspace associated with the link.
    - `depth`: An unsigned long integer specifying the depth property of the link.
    - `mtu`: An unsigned long integer specifying the maximum transmission unit (MTU) property of the link.
    - `burst`: An unsigned long integer specifying the burst property of the link.
- **Control Flow**:
    - Check if any of the input pointers (`topo`, `link_name`, `wksp_name`) are NULL and log an error if so.
    - Check if the length of `link_name` exceeds the maximum allowed size and log an error if so.
    - Check if the current number of links in the topology exceeds the maximum allowed and log an error if so.
    - Initialize `kind_id` to 0 and iterate over existing links to count how many have the same name as `link_name`, incrementing `kind_id` for each match.
    - Create a new link in the topology's links array at the current link count index and initialize its properties (`name`, `id`, `kind_id`, `depth`, `mtu`, `burst`).
    - Retrieve the mcache object associated with `wksp_name` and set the link's `mcache_obj_id` to this object's ID.
    - Insert the `depth` property into the topology's properties using the mcache object's ID.
    - If `mtu` is non-zero, retrieve the dcache object associated with `wksp_name`, set the link's `dcache_obj_id`, and insert `depth`, `burst`, and `mtu` properties into the topology's properties using the dcache object's ID.
    - Increment the topology's link count.
    - Return a pointer to the newly created link.
- **Output**: A pointer to the newly created and initialized `fd_topo_link_t` structure within the topology.
- **Functions called**:
    - [`fd_topob_obj`](#fd_topob_obj)


---
### fd\_topob\_tile\_uses<!-- {{#callable:fd_topob_tile_uses}} -->
The `fd_topob_tile_uses` function associates a given object with a tile in a topology, recording the object's ID and usage mode, while ensuring the tile does not exceed its maximum object usage capacity.
- **Inputs**:
    - `topo`: A pointer to the `fd_topo_t` structure representing the topology; however, it is not used in this function.
    - `tile`: A pointer to the `fd_topo_tile_t` structure representing the tile that will use the object.
    - `obj`: A pointer to the `fd_topo_obj_t` structure representing the object to be used by the tile.
    - `mode`: An integer representing the mode in which the tile will use the object.
- **Control Flow**:
    - The function begins by casting the `topo` parameter to void, indicating it is unused.
    - It checks if the current count of objects used by the tile (`tile->uses_obj_cnt`) has reached the maximum allowed (`FD_TOPO_MAX_TILE_OBJS`).
    - If the maximum is exceeded, it logs an error and terminates the program using `FD_LOG_ERR`.
    - If not exceeded, it assigns the object's ID (`obj->id`) to the next available position in the tile's `uses_obj_id` array.
    - It assigns the usage mode to the corresponding position in the tile's `uses_obj_mode` array.
    - Finally, it increments the `uses_obj_cnt` to reflect the addition of the new object.
- **Output**: The function does not return a value; it modifies the `tile` structure in place.


---
### fd\_topob\_tile<!-- {{#callable:fd_topob_tile}} -->
The `fd_topob_tile` function initializes and adds a new tile to the topology structure, setting its properties and associating it with specified workspaces and objects.
- **Inputs**:
    - `topo`: A pointer to the `fd_topo_t` structure representing the topology to which the tile will be added.
    - `tile_name`: A string representing the name of the tile to be added.
    - `tile_wksp`: A string representing the workspace name associated with the tile.
    - `metrics_wksp`: A string representing the workspace name associated with the metrics for the tile.
    - `cpu_idx`: An unsigned long representing the CPU index to which the tile is assigned.
    - `is_agave`: An integer flag indicating whether the tile is an 'agave' type.
    - `uses_keyswitch`: An integer flag indicating whether the tile uses a keyswitch object.
- **Control Flow**:
    - Check for NULL arguments and log an error if any are found.
    - Check if the tile name is too long or if the maximum number of tiles has been reached, logging an error if so.
    - Initialize `kind_id` by counting existing tiles with the same name.
    - Create a new tile in the topology's tile array and set its properties, including name, id, kind_id, is_agave, and cpu_idx.
    - Retrieve the tile object using [`fd_topob_obj`](#fd_topob_obj) and associate it with the tile using [`fd_topob_tile_uses`](#fd_topob_tile_uses).
    - Retrieve the metrics object using [`fd_topob_obj`](#fd_topob_obj) and associate it with the tile using [`fd_topob_tile_uses`](#fd_topob_tile_uses).
    - If `uses_keyswitch` is true, retrieve the keyswitch object and associate it with the tile; otherwise, set `keyswitch_obj_id` to `ULONG_MAX`.
    - Increment the tile count in the topology and return a pointer to the newly created tile.
- **Output**: A pointer to the newly created `fd_topo_tile_t` structure representing the added tile.
- **Functions called**:
    - [`fd_topob_obj`](#fd_topob_obj)
    - [`fd_topob_tile_uses`](#fd_topob_tile_uses)


---
### fd\_topob\_tile\_in<!-- {{#callable:fd_topob_tile_in}} -->
The `fd_topob_tile_in` function adds an incoming link to a specified tile in a topology, ensuring the link and tile exist and updating the tile's input link properties.
- **Inputs**:
    - `topo`: A pointer to the topology structure (`fd_topo_t`) where the tile and link are defined.
    - `tile_name`: A string representing the name of the tile to which the incoming link will be added.
    - `tile_kind_id`: An unsigned long integer representing the kind ID of the tile.
    - `fseq_wksp`: A string representing the name of the workspace associated with the fseq object.
    - `link_name`: A string representing the name of the link to be added as an incoming link to the tile.
    - `link_kind_id`: An unsigned long integer representing the kind ID of the link.
    - `reliable`: An integer indicating whether the link is reliable (non-zero) or not (zero).
    - `polled`: An integer indicating whether the link is polled (non-zero) or not (zero).
- **Control Flow**:
    - Check if any of the input pointers (`topo`, `tile_name`, `fseq_wksp`, `link_name`) are NULL and log an error if so.
    - Find the tile ID using `fd_topo_find_tile` with the given `tile_name` and `tile_kind_id`; log an error if the tile is not found.
    - Retrieve the tile structure from the topology using the found tile ID.
    - Find the link ID using `fd_topo_find_link` with the given `link_name` and `link_kind_id`; log an error if the link is not found.
    - Retrieve the link structure from the topology using the found link ID.
    - Check if the tile's current input link count exceeds the maximum allowed (`FD_TOPO_MAX_TILE_IN_LINKS`) and log an error if so.
    - Add the link ID to the tile's input link array and set the reliability and polling properties for this link.
    - Create or retrieve an fseq object using [`fd_topob_obj`](#fd_topob_obj) and associate it with the tile using [`fd_topob_tile_uses`](#fd_topob_tile_uses) in read-write mode.
    - Store the fseq object ID in the tile's input link fseq object ID array and increment the tile's input link count.
    - Associate the tile with the link's mcache object using [`fd_topob_tile_uses`](#fd_topob_tile_uses) in read-only mode.
    - If the link has a non-zero MTU, associate the tile with the link's dcache object using [`fd_topob_tile_uses`](#fd_topob_tile_uses) in read-only mode.
- **Output**: The function does not return a value; it modifies the topology structure by adding an incoming link to a specified tile.
- **Functions called**:
    - [`fd_topob_obj`](#fd_topob_obj)
    - [`fd_topob_tile_uses`](#fd_topob_tile_uses)


---
### fd\_topob\_tile\_out<!-- {{#callable:fd_topob_tile_out}} -->
The `fd_topob_tile_out` function associates an outgoing link with a specified tile in a topology, updating the tile's outgoing link count and ensuring the tile uses the appropriate shared memory objects.
- **Inputs**:
    - `topo`: A pointer to the `fd_topo_t` structure representing the topology.
    - `tile_name`: A constant character pointer representing the name of the tile.
    - `tile_kind_id`: An unsigned long representing the kind ID of the tile.
    - `link_name`: A constant character pointer representing the name of the link.
    - `link_kind_id`: An unsigned long representing the kind ID of the link.
- **Control Flow**:
    - Finds the tile ID using `fd_topo_find_tile` with the given `tile_name` and `tile_kind_id`.
    - Logs an error and exits if the tile is not found (tile ID is `ULONG_MAX`).
    - Finds the link ID using `fd_topo_find_link` with the given `link_name` and `link_kind_id`.
    - Logs an error and exits if the link is not found (link ID is `ULONG_MAX`).
    - Checks if the tile's outgoing link count has reached the maximum allowed (`FD_TOPO_MAX_TILE_OUT_LINKS`), logging an error and exiting if so.
    - Adds the link ID to the tile's outgoing link list and increments the outgoing link count.
    - Calls [`fd_topob_tile_uses`](#fd_topob_tile_uses) to associate the tile with the link's memory cache object in read-write mode.
    - If the link's MTU is non-zero, calls [`fd_topob_tile_uses`](#fd_topob_tile_uses) to associate the tile with the link's data cache object in read-write mode.
- **Output**: This function does not return a value; it modifies the topology structure in place.
- **Functions called**:
    - [`fd_topob_tile_uses`](#fd_topob_tile_uses)


---
### validate<!-- {{#callable:validate}} -->
The `validate` function checks the integrity and consistency of a topology structure by verifying various constraints on objects, tiles, links, and workspaces.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure representing the topology to be validated.
- **Control Flow**:
    - Iterates over all objects to ensure their workspace IDs are valid.
    - Checks each tile's input links to ensure they are valid and not duplicated.
    - Verifies that each tile's output links are valid, not duplicated, and different from input links, with exceptions for certain link names.
    - Ensures non-polling input links are not marked as reliable.
    - Confirms that workspace names are unique and each workspace is correctly identified by its ID.
    - Validates that each link has exactly one producer and at least one consumer, unless exceptions are permitted.
- **Output**: The function does not return a value but logs errors and terminates execution if any validation checks fail.


---
### fd\_topob\_auto\_layout<!-- {{#callable:fd_topob_auto_layout}} -->
The `fd_topob_auto_layout` function automatically assigns CPU cores to tiles in a topology, ensuring certain tiles are floating and others are assigned based on criticality and NUMA node order, with an option to reserve additional cores for Agave.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology of tiles and their configurations.
    - `reserve_agave_cores`: An integer flag indicating whether to reserve additional CPU cores for Agave.
- **Control Flow**:
    - Initialize all tile CPU indices to `ULONG_MAX` to mark them as unassigned.
    - Initialize CPU topology and prepare arrays for CPU ordering and assignment tracking.
    - Iterate over NUMA nodes and CPUs to create a sequential CPU ordering, considering hyper-threading pairs.
    - Assign CPUs to tiles based on the predefined `ORDERED` list, ensuring critical tiles avoid hyper-threading pairs.
    - Check that unassigned tiles are in the `FLOATING` list, logging a warning if not.
    - If `reserve_agave_cores` is set, reserve remaining online CPUs for Agave affinity.
- **Output**: The function modifies the `topo` structure by setting the `cpu_idx` for each tile and potentially updating the `agave_affinity_cpu_idx` array if `reserve_agave_cores` is true.
- **Functions called**:
    - [`fd_topo_cpus_init`](fd_cpu_topo.c.driver.md#fd_topo_cpus_init)


---
### initialize\_numa\_assignments<!-- {{#callable:initialize_numa_assignments}} -->
The `initialize_numa_assignments` function assigns NUMA nodes to workspaces based on the largest object they contain and the tiles that map these objects.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology of the system, including workspaces, objects, and tiles.
- **Control Flow**:
    - Iterate over each workspace in the topology.
    - For each workspace, find the object with the largest footprint that belongs to it.
    - If no object is found for a workspace, log an error and exit.
    - For the largest object, search for a tile that maps this object and has a valid CPU index.
    - If such a tile is found, assign the NUMA node of the tile's CPU to the workspace and mark the assignment as strict and lazy.
    - If no strict assignment is found, search for any tile that uses the object and has a valid CPU index.
    - If such a tile is found, assign the NUMA node of the tile's CPU to the workspace and mark the assignment as lazy.
    - If no lazy assignment is found, log an error indicating no tile uses the object for the workspace.
- **Output**: The function does not return a value; it modifies the `numa_idx` field of each workspace in the `topo` structure to reflect the assigned NUMA node.


---
### fd\_topob\_finish<!-- {{#callable:fd_topob_finish}} -->
The `fd_topob_finish` function finalizes the setup of a topology by calculating and updating metrics for tiles and workspaces, aligning and assigning memory offsets, and validating the topology configuration.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology to be finalized.
    - `callbacks`: An array of pointers to `fd_topo_obj_callbacks_t` structures, providing callback functions for topology objects.
- **Control Flow**:
    - Iterate over each tile in the topology to count the number of polled input links and reliable consumer links, updating the topology properties with these counts.
    - For each workspace, calculate the total loose size by iterating over objects in the workspace and using the `loose` callback if available.
    - Determine the maximum partition size and align the offset for each object in the workspace, using the `align` and `footprint` callbacks to set object offsets and footprints.
    - Calculate the total footprint for the workspace, adjusting for alignment and page size, and update the workspace properties accordingly.
    - Call [`initialize_numa_assignments`](#initialize_numa_assignments) to assign NUMA nodes to workspaces based on tile usage.
    - Call [`validate`](#validate) to ensure the topology configuration is correct and consistent.
- **Output**: The function does not return a value; it modifies the `topo` structure in place.
- **Functions called**:
    - [`initialize_numa_assignments`](#initialize_numa_assignments)
    - [`validate`](#validate)



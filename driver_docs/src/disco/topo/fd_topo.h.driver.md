# Purpose
The provided C header file, `fd_topo.h`, is part of the Firedancer project and defines the data structures and functions necessary for managing and interacting with a topology of computational resources. This file is integral to the Firedancer system, which appears to be a high-performance, distributed computing framework. The header file defines several key structures, such as `fd_topo_t`, `fd_topo_wksp_t`, `fd_topo_link_t`, and `fd_topo_tile_t`, which represent the overall topology, workspaces, links, and tiles (processes) within the system, respectively. These structures are used to configure and manage the relationships and resources among different components in a Firedancer deployment, including memory management, process execution, and inter-process communication.

The file also provides a comprehensive set of functions for manipulating these structures, such as creating and joining workspaces, finding specific tiles or links, and running tiles either in a single process or across multiple processes. The functions facilitate the setup and execution of the Firedancer topology, ensuring that resources are correctly allocated and processes are properly sandboxed for security. Additionally, the file includes configuration options for various network and processing components, allowing for detailed customization of the system's behavior. This header file is crucial for developers working with Firedancer, as it provides the necessary interfaces and definitions to build and manage complex distributed systems efficiently.
# Imports and Dependencies

---
- `../stem/fd_stem.h`
- `../../tango/fd_tango.h`
- `../../waltz/xdp/fd_xdp1.h`
- `../../ballet/base58/fd_base58.h`
- `../../util/net/fd_net_headers.h`


# Global Variables

---
### fd\_topo\_tile\_stack\_join
- **Type**: `function pointer`
- **Description**: `fd_topo_tile_stack_join` is a function pointer that represents a function used to join a huge page optimized stack for a specific tile in the Firedancer topology. This function is responsible for mapping the stack into the process, assuming the stack already exists at a known path in the hugetlbfs mount.
- **Use**: This function is used to integrate a tile's stack into the process's memory space, facilitating the tile's execution within the Firedancer framework.


# Data Structures

---
### fd\_topo\_wksp\_t
- **Type**: `struct`
- **Members**:
    - `id`: The ID of this workspace, indexed from [0, wksp_cnt) and must match its index in the workspaces list when placed in a topology.
    - `name`: The name of this workspace, which must be unique within a topology.
    - `numa_idx`: The index of the NUMA node from which this workspace should be allocated.
    - `page_sz`: The size of the pages backing this workspace, chosen from predefined page sizes.
    - `page_cnt`: The number of pages required to map this workspace for data storage.
    - `part_max`: The maximum number of partitions allowed in this workspace, limiting concurrent allocations.
    - `wksp`: A pointer to the workspace memory in the local process.
    - `known_footprint`: The total size in bytes of all data in Firedancer stored in this workspace at startup.
    - `total_footprint`: The total potential size in bytes of all data that could be stored in this workspace, including known and loose data.
- **Description**: The `fd_topo_wksp_t` structure represents a workspace in the Firedancer topology, which is a memory management unit that operates over memory-mapped huge pages. It includes fields for identifying the workspace (`id` and `name`), specifying its NUMA node allocation (`numa_idx`), and several computed fields that describe the memory characteristics of the workspace, such as page size (`page_sz`), page count (`page_cnt`), and partition limits (`part_max`). Additionally, it maintains pointers to the workspace memory (`wksp`) and tracks the memory footprint of data stored within it (`known_footprint` and `total_footprint`). This structure is crucial for managing memory resources efficiently in a Firedancer topology.


---
### fd\_topo\_link\_t
- **Type**: `struct`
- **Members**:
    - `id`: The ID of this link, used as an index in the links list.
    - `name`: The name of this link, allowing multiple links with the same name in a topology.
    - `kind_id`: The ID of this link within its name, uniquely identifying the link along with the name.
    - `depth`: The depth of the mcache representing the link.
    - `mtu`: The MTU of data fragments in the mcache, with 0 indicating no dcache.
    - `burst`: The maximum number of MTU-sized data fragments that can be bursted to the dcache.
    - `mcache_obj_id`: The object ID for the mcache associated with this link.
    - `dcache_obj_id`: The object ID for the dcache associated with this link.
    - `mcache`: A pointer to the mcache of this link.
    - `dcache`: A pointer to the dcache of this link, if it exists.
    - `permit_no_consumers`: A flag indicating if the link can exist without consumers.
    - `permit_no_producers`: A flag indicating if the link can exist without producers.
- **Description**: The `fd_topo_link_t` structure represents a link in a Firedancer topology, which is essentially an mcache in a workspace with one producer and potentially multiple consumers. It includes identifiers for the link and its kind, as well as configuration parameters like depth, MTU, and burst size. The structure also contains computed fields for the mcache and dcache pointers, and flags to permit topologies where the link has no consumers or producers. This structure is crucial for managing data flow in a Firedancer topology, ensuring that links are uniquely identifiable and properly configured.


---
### fd\_topo\_tile\_t
- **Type**: `struct`
- **Members**:
    - `id`: The ID of this tile, indexed from [0, tile_cnt), and must match its index in the tiles list when placed in a topology.
    - `name`: The name of this tile, allowing multiple tiles with the same name in a topology.
    - `kind_id`: The ID of this tile within its name, uniquely identifying a tile along with its name.
    - `is_agave`: Indicates if the tile needs to run in the Agave (Anza) address space.
    - `cpu_idx`: The CPU index to pin the tile on, with ULONG_MAX or more indicating the tile should not be pinned to a core.
    - `in_cnt`: The number of links that this tile reads from.
    - `in_link_id`: The link_id of each link that this tile reads from, indexed in [0, in_cnt).
    - `in_link_reliable`: Indicates if each link that this tile reads from is a reliable or unreliable consumer, indexed in [0, in_cnt).
    - `in_link_poll`: Indicates if each link that this tile reads from should be polled by the tile infrastructure, indexed in [0, in_cnt).
    - `out_cnt`: The number of links that this tile writes to.
    - `out_link_id`: The link_id of each link that this tile writes to, indexed in [0, link_cnt).
    - `tile_obj_id`: An identifier for the tile object.
    - `metrics_obj_id`: An identifier for the metrics object associated with the tile.
    - `keyswitch_obj_id`: An identifier for the keyswitch object associated with the tile.
    - `in_link_fseq_obj_id`: An array of identifiers for the fseq objects of each link that this tile reads from.
    - `uses_obj_cnt`: The count of objects that this tile uses.
    - `uses_obj_id`: An array of identifiers for the objects that this tile uses.
    - `uses_obj_mode`: An array indicating the mode of each object that this tile uses.
    - `metrics`: Shared memory for metrics that this tile should write, consumed by monitoring and metrics writing tiles.
    - `in_link_fseq`: An array of fseqs for each link that this tile reads from, uniquely identified by link and tile identifiers.
    - `net`: Configuration for network-related options, including provider, interface, and various network-specific settings.
    - `netlink`: Configuration for netlink-related options, including object identifiers and interface name.
    - `quic`: Configuration for QUIC-related options, including ports and connection settings.
    - `verify`: Configuration for verification-related options, including tcache depth.
    - `dedup`: Configuration for deduplication-related options, including tcache depth.
    - `bundle`: Configuration for bundle-related options, including URLs, paths, and buffer sizes.
    - `pack`: Configuration for packing-related options, including transaction limits and strategy settings.
    - `poh`: Configuration for proof-of-history-related options, including bank count and identity paths.
    - `shred`: Configuration for shredding-related options, including ports and expected shred version.
    - `store`: Configuration for storage-related options, including blockstore settings.
    - `sign`: Configuration for signing-related options, including identity key path.
    - `gui`: Configuration for GUI-related options, including listen address and port.
    - `metric`: Configuration for metric-related options, including Prometheus listen address and port.
    - `replay`: Configuration for replay-related options, including feature enablement and paths.
    - `restart`: Configuration for restart-related options, including file paths and memory limits.
    - `exec`: Configuration for execution-related options, including file paths.
    - `writer`: Configuration for writer-related options, including file paths.
    - `benchs`: Configuration for benchmarking-related options, including connection counts and QUIC settings.
    - `bencho`: Configuration for benchmarking-related options, including RPC ports and IP addresses.
    - `benchg`: Configuration for benchmarking-related options, including account counts and mode.
    - `gossip`: Configuration for gossip-related options, including ports and entrypoints.
    - `repair`: Configuration for repair-related options, including ports and cache files.
    - `store_int`: Configuration for internal storage-related options, including paths and expected shred version.
    - `send`: Configuration for sending-related options, including ports and IP addresses.
    - `eqvoc`: Configuration for EQVOC-related options, including identity key path.
    - `rpcserv`: Configuration for RPC service-related options, including ports and IP addresses.
    - `batch`: Configuration for batch-related options, including intervals and directory paths.
    - `pktgen`: Configuration for packet generation-related options, including fake destination IP.
    - `archiver`: Configuration for archiver-related options, including paths and end slots.
- **Description**: The `fd_topo_tile_t` structure represents a tile in the Firedancer topology, which is a unique process spawned to represent one thread of execution. It includes identifiers and configuration for the tile's operation, such as its ID, name, CPU pinning, and the links it reads from and writes to. The structure also contains computed fields for metrics and link sequences, as well as a union of various configuration options for different operational modes like network, QUIC, and storage. This allows the tile to be flexibly configured and managed within the Firedancer system, supporting a wide range of functionalities and integrations.


---
### fd\_topo\_obj\_t
- **Type**: `struct`
- **Members**:
    - `id`: A unique identifier for the topology object.
    - `name`: A character array storing the name of the topology object, with a maximum length of 12 characters plus a null terminator.
    - `wksp_id`: The identifier of the workspace to which this object belongs.
    - `offset`: The offset within the workspace where this object is located.
    - `footprint`: The memory footprint of the object in bytes.
- **Description**: The `fd_topo_obj_t` structure represents an object within a Firedancer topology, encapsulating essential metadata such as its unique identifier, name, associated workspace ID, memory offset within the workspace, and its memory footprint. This structure is used to manage and reference objects within the larger topology configuration, facilitating memory management and object identification within the Firedancer system.


---
### fd\_topo
- **Type**: `struct`
- **Members**:
    - `app_name`: A character array storing the application name, with a maximum length of 256 characters.
    - `props`: An array of unsigned characters with a size of 16384, used for storing properties.
    - `wksp_cnt`: An unsigned long integer representing the count of workspaces in the topology.
    - `link_cnt`: An unsigned long integer representing the count of links in the topology.
    - `tile_cnt`: An unsigned long integer representing the count of tiles in the topology.
    - `obj_cnt`: An unsigned long integer representing the count of objects in the topology.
    - `workspaces`: An array of fd_topo_wksp_t structures, with a maximum size defined by FD_TOPO_MAX_WKSPS, representing the workspaces in the topology.
    - `links`: An array of fd_topo_link_t structures, with a maximum size defined by FD_TOPO_MAX_LINKS, representing the links in the topology.
    - `tiles`: An array of fd_topo_tile_t structures, with a maximum size defined by FD_TOPO_MAX_TILES, representing the tiles in the topology.
    - `objs`: An array of fd_topo_obj_t structures, with a maximum size defined by FD_TOPO_MAX_OBJS, representing the objects in the topology.
    - `agave_affinity_cnt`: An unsigned long integer representing the count of Agave affinities.
    - `agave_affinity_cpu_idx`: An array of unsigned long integers, with a size defined by FD_TILE_MAX, representing CPU indices for Agave affinity.
    - `max_page_size`: An unsigned long integer indicating the maximum page size, either 2^21 or 2^30.
    - `gigantic_page_threshold`: An unsigned long integer representing the threshold for gigantic pages, related to hugetlbfs.
- **Description**: The `fd_topo` structure is a comprehensive representation of a Firedancer configuration, encapsulating the entire topology of workspaces, links, tiles, and objects. It includes arrays for storing detailed information about each component, such as workspaces, links, tiles, and objects, with specific counts for each. The structure also manages properties and configurations related to memory management, such as page sizes and thresholds for gigantic pages. Additionally, it handles CPU affinity settings for Agave processes, ensuring efficient resource allocation and process management within the Firedancer system.


---
### fd\_topo\_t
- **Type**: `struct`
- **Members**:
    - `app_name`: A character array storing the application name associated with the topology.
    - `props`: A byte array storing properties or configuration data for the topology.
    - `wksp_cnt`: The count of workspaces in the topology.
    - `link_cnt`: The count of links in the topology.
    - `tile_cnt`: The count of tiles in the topology.
    - `obj_cnt`: The count of objects in the topology.
    - `workspaces`: An array of workspace structures, each representing a memory management unit in the topology.
    - `links`: An array of link structures, each representing a communication channel between tiles.
    - `tiles`: An array of tile structures, each representing a process or thread of execution in the topology.
    - `objs`: An array of object structures, each representing a specific object in the topology.
    - `agave_affinity_cnt`: The count of CPU affinities for Agave tiles.
    - `agave_affinity_cpu_idx`: An array of CPU indices for Agave tile affinities.
    - `max_page_size`: The maximum page size used in the topology, either 2^21 or 2^30.
    - `gigantic_page_threshold`: The threshold for using gigantic pages, related to hugetlbfs configuration.
- **Description**: The `fd_topo_t` structure represents the overall configuration of a Firedancer topology, encapsulating the relationships and configurations of workspaces, links, tiles, and objects. It includes arrays for each of these components, along with metadata such as counts and properties. The structure is designed to manage and describe the complex interconnections and resource allocations necessary for Firedancer's execution environment, including memory management, process execution, and communication channels. It also includes specific configurations for handling large memory pages and CPU affinities, particularly for Agave tiles.


---
### fd\_topo\_run\_tile\_t
- **Type**: `struct`
- **Members**:
    - `name`: A constant character pointer to the name of the tile.
    - `keep_host_networking`: An integer flag indicating whether to keep host networking.
    - `allow_connect`: An integer flag indicating whether connections are allowed.
    - `rlimit_file_cnt`: An unsigned long representing the file count resource limit.
    - `rlimit_address_space`: An unsigned long representing the address space resource limit.
    - `rlimit_data`: An unsigned long representing the data resource limit.
    - `for_tpool`: An integer flag indicating if the tile is for a thread pool.
    - `populate_allowed_seccomp`: A function pointer to populate allowed seccomp filters.
    - `populate_allowed_fds`: A function pointer to populate allowed file descriptors.
    - `scratch_align`: A function pointer to get the alignment of scratch memory.
    - `scratch_footprint`: A function pointer to get the footprint of scratch memory.
    - `loose_footprint`: A function pointer to get the loose footprint of the tile.
    - `privileged_init`: A function pointer for privileged initialization of the tile.
    - `unprivileged_init`: A function pointer for unprivileged initialization of the tile.
    - `run`: A function pointer to run the tile.
    - `rlimit_file_cnt_fn`: A function pointer to get the file count resource limit.
- **Description**: The `fd_topo_run_tile_t` structure is designed to encapsulate the configuration and operational parameters for a Firedancer tile, which is a unique process representing a thread of execution. This structure includes various resource limits, flags for networking and connection permissions, and function pointers for initialization, execution, and resource management. It is integral to managing the lifecycle and resource constraints of a tile within the Firedancer topology, ensuring that each tile operates within its defined limits and can be initialized and run with the appropriate permissions and configurations.


---
### fd\_topo\_obj\_callbacks
- **Type**: `struct`
- **Members**:
    - `name`: A constant character pointer representing the name of the callback.
    - `footprint`: A function pointer that calculates the memory footprint of a topology object.
    - `align`: A function pointer that determines the alignment requirements of a topology object.
    - `loose`: A function pointer that calculates the loose memory requirements of a topology object.
    - `new`: A function pointer that initializes a new topology object.
- **Description**: The `fd_topo_obj_callbacks` structure is designed to provide a set of callback functions for handling topology objects within the Firedancer framework. It includes function pointers for calculating memory footprint, alignment, and loose memory requirements, as well as initializing new objects. This structure allows for flexible and dynamic management of topology objects by providing customizable operations through its function pointers.


---
### fd\_topo\_obj\_callbacks\_t
- **Type**: `struct`
- **Members**:
    - `name`: A constant character pointer representing the name of the object callback.
    - `footprint`: A function pointer that calculates the memory footprint of a topology object.
    - `align`: A function pointer that determines the alignment requirements of a topology object.
    - `loose`: A function pointer that calculates the loose memory requirements of a topology object.
    - `new`: A function pointer that initializes a new topology object.
- **Description**: The `fd_topo_obj_callbacks_t` structure defines a set of callback functions for managing topology objects within the Firedancer framework. It includes function pointers for calculating memory footprint, alignment, and loose memory requirements, as well as for initializing new objects. This structure allows for flexible and dynamic management of topology objects by providing customizable operations that can be tailored to specific needs within the topology.


# Functions

---
### fd\_topo\_workspace\_align<!-- {{#callable:fd_topo_workspace_align}} -->
The `fd_topo_workspace_align` function returns a fixed alignment value for workspace memory management.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests inlining for performance.
    - The function does not take any parameters and directly returns a constant value.
    - The return value is a hardcoded unsigned long integer, 4096UL, which represents the alignment size.
- **Output**: The function returns an unsigned long integer representing the alignment size, specifically 4096UL.


---
### fd\_topo\_obj\_laddr<!-- {{#callable:fd_topo_obj_laddr}} -->
The `fd_topo_obj_laddr` function calculates the local address of an object within a topology's workspace.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure representing the topology containing the workspaces and objects.
    - `obj_id`: An unsigned long integer representing the ID of the object within the topology whose local address is to be calculated.
- **Control Flow**:
    - Retrieve the object from the topology's object array using the provided `obj_id`.
    - Access the workspace associated with the object using the object's `wksp_id`.
    - Calculate the local address by adding the object's offset to the base address of the workspace.
- **Output**: Returns a void pointer to the calculated local address of the specified object within its workspace.


---
### fd\_topo\_tile\_name\_cnt<!-- {{#callable:fd_topo_tile_name_cnt}} -->
The `fd_topo_tile_name_cnt` function counts the number of tiles in a topology that have a specific name.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology, which contains information about tiles, workspaces, and links.
    - `name`: A constant character pointer representing the name of the tile to be counted within the topology.
- **Control Flow**:
    - Initialize a counter `cnt` to zero.
    - Iterate over each tile in the topology using a loop that runs from 0 to `topo->tile_cnt`.
    - For each tile, compare its name with the provided `name` using `strcmp`.
    - If the names match, increment the counter `cnt`.
    - After the loop, return the counter `cnt`.
- **Output**: The function returns an `ulong` representing the count of tiles with the specified name in the topology.


---
### fd\_topo\_find\_wksp<!-- {{#callable:fd_topo_find_wksp}} -->
The `fd_topo_find_wksp` function searches for a workspace by name within a topology and returns its index or `ULONG_MAX` if not found.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology containing the workspaces.
    - `name`: A constant character pointer representing the name of the workspace to find.
- **Control Flow**:
    - Iterates over each workspace in the topology using a for loop, with the loop index `i` ranging from 0 to `topo->wksp_cnt`.
    - For each workspace, it compares the workspace's name with the provided `name` using `strcmp`.
    - If a match is found (i.e., `strcmp` returns 0), the function returns the current index `i`.
    - If no match is found after checking all workspaces, the function returns `ULONG_MAX`.
- **Output**: The function returns the index of the workspace with the specified name if found, or `ULONG_MAX` if no such workspace exists.


---
### fd\_topo\_find\_tile<!-- {{#callable:fd_topo_find_tile}} -->
The `fd_topo_find_tile` function searches for a tile in a topology by its name and kind_id, returning its index or ULONG_MAX if not found.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology to search within.
    - `name`: A constant character pointer representing the name of the tile to search for.
    - `kind_id`: An unsigned long integer representing the kind_id of the tile to search for.
- **Control Flow**:
    - Iterates over each tile in the topology using a for loop, with the loop index `i` ranging from 0 to `topo->tile_cnt`.
    - For each tile, checks if the tile's name matches the provided `name` and if the tile's `kind_id` matches the provided `kind_id`.
    - If both conditions are met, returns the current index `i` as the result.
    - If no matching tile is found after checking all tiles, returns `ULONG_MAX`.
- **Output**: Returns the index of the tile in the topology if found, otherwise returns `ULONG_MAX`.


---
### fd\_topo\_find\_link<!-- {{#callable:fd_topo_find_link}} -->
The `fd_topo_find_link` function searches for a link in a topology by its name and kind_id, returning its index or ULONG_MAX if not found.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology containing the links.
    - `name`: A constant character pointer representing the name of the link to be found.
    - `kind_id`: An unsigned long integer representing the kind ID of the link to be found.
- **Control Flow**:
    - Iterates over each link in the topology using a for loop, with the loop index `i` ranging from 0 to `topo->link_cnt`.
    - For each link, checks if the link's name matches the provided `name` and if the link's `kind_id` matches the provided `kind_id`.
    - If both conditions are met, returns the current index `i` as the position of the link in the topology.
    - If no matching link is found after checking all links, returns `ULONG_MAX` to indicate the link was not found.
- **Output**: Returns the index of the link in the topology if found, or `ULONG_MAX` if no matching link is found.


---
### fd\_topo\_find\_tile\_in\_link<!-- {{#callable:fd_topo_find_tile_in_link}} -->
The `fd_topo_find_tile_in_link` function searches for a specific input link by name and kind_id within a given tile's input links and returns its index if found, or ULONG_MAX if not.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology, which contains information about all links, tiles, and workspaces.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the tile whose input links are to be searched.
    - `name`: A constant character pointer representing the name of the link to be searched for.
    - `kind_id`: An unsigned long integer representing the kind ID of the link to be searched for.
- **Control Flow**:
    - Iterate over each input link of the given tile using a loop that runs from 0 to `tile->in_cnt`.
    - For each input link, check if the link's name matches the provided `name` and if the link's kind ID matches the provided `kind_id`.
    - If both conditions are met, return the current index `i` of the input link.
    - If no matching link is found after checking all input links, return `ULONG_MAX`.
- **Output**: The function returns the index of the input link within the tile's input links if a match is found, otherwise it returns `ULONG_MAX`.


---
### fd\_topo\_find\_tile\_out\_link<!-- {{#callable:fd_topo_find_tile_out_link}} -->
The function `fd_topo_find_tile_out_link` searches for an outgoing link from a tile in a topology that matches a given name and kind ID, returning its index or `ULONG_MAX` if not found.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology containing links and tiles.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the tile whose outgoing links are to be searched.
    - `name`: A constant character pointer representing the name of the link to be found.
    - `kind_id`: An unsigned long integer representing the kind ID of the link to be found.
- **Control Flow**:
    - Iterate over each outgoing link of the given tile using a loop that runs from 0 to `tile->out_cnt`.
    - For each outgoing link, check if the link's name matches the given `name` and its kind ID matches the given `kind_id`.
    - If a match is found, return the index `i` of the matching outgoing link.
    - If no matching link is found after checking all outgoing links, return `ULONG_MAX`.
- **Output**: The function returns the index of the matching outgoing link if found, or `ULONG_MAX` if no such link exists.


---
### fd\_topo\_find\_link\_producer<!-- {{#callable:fd_topo_find_link_producer}} -->
The `fd_topo_find_link_producer` function identifies the tile that produces a specified link within a topology.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology, which contains information about tiles and links.
    - `link`: A pointer to an `fd_topo_link_t` structure representing the link for which the producer tile is to be found.
- **Control Flow**:
    - Iterate over each tile in the topology using a loop that runs from 0 to `topo->tile_cnt`.
    - For each tile, iterate over its output links using a loop that runs from 0 to `tile->out_cnt`.
    - Check if the current output link's ID matches the ID of the specified link using `FD_UNLIKELY` for potential optimization.
    - If a match is found, return the index of the tile as the producer of the link.
    - If no producer is found after checking all tiles, return `ULONG_MAX` to indicate no producer exists.
- **Output**: The function returns the index of the tile that produces the specified link, or `ULONG_MAX` if no such tile exists.


---
### fd\_topo\_link\_consumer\_cnt<!-- {{#callable:fd_topo_link_consumer_cnt}} -->
The function `fd_topo_link_consumer_cnt` counts the number of tiles in a topology that consume a specific link.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology, which contains information about all tiles and links.
    - `link`: A pointer to an `fd_topo_link_t` structure representing the specific link for which the consumer count is to be determined.
- **Control Flow**:
    - Initialize a counter `cnt` to zero to keep track of the number of consumers.
    - Iterate over each tile in the topology using a loop that runs from 0 to `topo->tile_cnt`.
    - For each tile, iterate over its input links using a loop that runs from 0 to `tile->in_cnt`.
    - Check if the current input link ID of the tile matches the ID of the specified link using `FD_UNLIKELY`.
    - If a match is found, increment the consumer count `cnt`.
    - After iterating through all tiles and their input links, return the final count of consumers.
- **Output**: The function returns an `ulong` representing the number of tiles that consume the specified link.


---
### fd\_topo\_link\_reliable\_consumer\_cnt<!-- {{#callable:fd_topo_link_reliable_consumer_cnt}} -->
The function `fd_topo_link_reliable_consumer_cnt` counts the number of reliable consumers for a given link in a topology.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology, which contains information about all tiles and links.
    - `link`: A pointer to an `fd_topo_link_t` structure representing the specific link for which the reliable consumer count is to be determined.
- **Control Flow**:
    - Initialize a counter `cnt` to zero to keep track of the number of reliable consumers.
    - Iterate over each tile in the topology using a loop that runs from 0 to `topo->tile_cnt`.
    - For each tile, iterate over its input links using a loop that runs from 0 to `tile->in_cnt`.
    - Check if the current input link's ID matches the given link's ID and if it is marked as reliable (`tile->in_link_reliable[j]`).
    - If both conditions are true, increment the `cnt` counter.
    - After iterating through all tiles and their input links, return the value of `cnt`.
- **Output**: The function returns an `ulong` representing the number of reliable consumers for the specified link in the topology.


# Function Declarations (Public API)

---
### fd\_topo\_join\_tile\_workspaces<!-- {{#callable_declaration:fd_topo_join_tile_workspaces}} -->
Join all necessary workspaces for a specific tile in the topology.
- **Description**: This function is used to map all shared memory workspaces required by a specific tile into the process's address space. It should be called before the tile begins execution to ensure that all necessary memory is accessible, especially in environments where memory mapping is restricted after process sandboxing. The function iterates over all workspaces in the topology and joins those that the tile needs, based on its configuration.
- **Inputs**:
    - `topo`: A pointer to an fd_topo_t structure representing the topology. It must not be null and should be properly initialized with the topology's configuration.
    - `tile`: A pointer to an fd_topo_tile_t structure representing the tile for which workspaces need to be joined. It must not be null and should be part of the provided topology.
- **Output**: None
- **See also**: [`fd_topo_join_tile_workspaces`](fd_topo.c.driver.md#fd_topo_join_tile_workspaces)  (Implementation)


---
### fd\_topo\_join\_workspace<!-- {{#callable_declaration:fd_topo_join_workspace}} -->
Join a workspace into the process's address space.
- **Description**: This function maps the shared memory associated with a specified workspace into the process's address space, allowing the process to access and manipulate the workspace's memory. It should be called when a workspace needs to be accessed by the process, typically after the workspace has been created and before any operations that require access to its memory. The function requires a valid topology and workspace structure, and the mode parameter determines the access permissions for the memory mapping. If the join operation fails, an error is logged, and the program may terminate.
- **Inputs**:
    - `topo`: A pointer to an fd_topo_t structure representing the topology. Must not be null.
    - `wksp`: A pointer to an fd_topo_wksp_t structure representing the workspace to be joined. Must not be null.
    - `mode`: An integer specifying the access mode for the memory mapping. Valid values are FD_SHMEM_JOIN_MODE_READ_WRITE or FD_SHMEM_JOIN_MODE_READ_ONLY.
- **Output**: None
- **See also**: [`fd_topo_join_workspace`](fd_topo.c.driver.md#fd_topo_join_workspace)  (Implementation)


---
### fd\_topo\_join\_workspaces<!-- {{#callable_declaration:fd_topo_join_workspaces}} -->
Join all workspaces in the topology with specified access mode.
- **Description**: This function maps all the shared memory associated with each workspace in the given topology into the process's address space. It should be used when you need to access all workspaces in a topology, either for reading or writing, depending on the specified mode. This is particularly useful in environments where memory needs to be accessed in a controlled manner, such as in sandboxed processes. Ensure that the topology structure is properly initialized before calling this function.
- **Inputs**:
    - `topo`: A pointer to an fd_topo_t structure representing the topology. Must not be null and should be properly initialized with the workspaces to be joined.
    - `mode`: An integer specifying the access mode for the workspaces. It should be either FD_SHMEM_JOIN_MODE_READ_WRITE or FD_SHMEM_JOIN_MODE_READ_ONLY, determining whether the workspaces are mapped with write or read permissions.
- **Output**: None
- **See also**: [`fd_topo_join_workspaces`](fd_topo.c.driver.md#fd_topo_join_workspaces)  (Implementation)


---
### fd\_topo\_leave\_workspaces<!-- {{#callable_declaration:fd_topo_leave_workspaces}} -->
Unmaps all previously mapped workspaces in the topology.
- **Description**: Use this function to unmap all shared memory workspaces that were previously mapped in the given topology. It should be called when the workspaces are no longer needed or before the topology is destroyed to ensure proper cleanup of resources. The function assumes that the `topo` parameter is non-NULL and will only unmap workspaces that have been previously joined, making it safe to call even if some workspaces were not mapped.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology. It must not be NULL, and the function will operate on the workspaces within this topology.
- **Output**: None
- **See also**: [`fd_topo_leave_workspaces`](fd_topo.c.driver.md#fd_topo_leave_workspaces)  (Implementation)


---
### fd\_topo\_create\_workspace<!-- {{#callable_declaration:fd_topo_create_workspace}} -->
Create or update a workspace in the topology.
- **Description**: This function is used to create a new workspace or update an existing one within a given topology. It is essential to ensure that the workspace is correctly formatted and ready for use. The function should be called when a workspace needs to be initialized or resized. If `update_existing` is set to 1, the function will attempt to update an existing workspace, which is useful in development environments to avoid the overhead of zeroing memory. However, this should be used cautiously in production as it may leave residual data from previous runs.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology. Must not be null.
    - `wksp`: A pointer to an `fd_topo_wksp_t` structure representing the workspace to be created or updated. Must not be null.
    - `update_existing`: An integer flag indicating whether to update an existing workspace (1) or create a new one (0).
- **Output**: Returns 0 on success. Returns -1 on failure if there is insufficient memory (errno set to ENOMEM). Other errors will cause the program to exit.
- **See also**: [`fd_topo_create_workspace`](fd_topo.c.driver.md#fd_topo_create_workspace)  (Implementation)


---
### fd\_topo\_fill\_tile<!-- {{#callable_declaration:fd_topo_fill_tile}} -->
Fills a tile's workspaces in the topology.
- **Description**: Use this function to populate the workspaces associated with a specific tile in the topology. It should be called when a tile's workspaces need to be initialized or updated within the topology. This function iterates over the workspaces in the topology and fills those required by the specified tile. Ensure that the topology and tile structures are properly initialized before calling this function.
- **Inputs**:
    - `topo`: A pointer to an fd_topo_t structure representing the topology. Must not be null and should be properly initialized.
    - `tile`: A pointer to an fd_topo_tile_t structure representing the tile whose workspaces need to be filled. Must not be null and should be properly initialized.
- **Output**: None
- **See also**: [`fd_topo_fill_tile`](fd_topo.c.driver.md#fd_topo_fill_tile)  (Implementation)


---
### fd\_topo\_workspace\_fill<!-- {{#callable_declaration:fd_topo_workspace_fill}} -->
Fills a topology's workspace with necessary shared memory mappings.
- **Description**: This function is used to map the necessary shared memory for all objects within a specified workspace in a given topology. It should be called when the workspace needs to be prepared for use, ensuring that all relevant memory regions are accessible. The function assumes that the workspace and topology structures are properly initialized and valid. It is important to ensure that the workspace ID matches the expected ID in the topology to avoid incorrect memory mappings.
- **Inputs**:
    - `topo`: A pointer to an fd_topo_t structure representing the topology. It must be non-null and properly initialized.
    - `wksp`: A pointer to an fd_topo_wksp_t structure representing the workspace to be filled. It must be non-null and its ID should match the expected ID in the topology.
- **Output**: None
- **See also**: [`fd_topo_workspace_fill`](fd_topo.c.driver.md#fd_topo_workspace_fill)  (Implementation)


---
### fd\_topo\_wksp\_new<!-- {{#callable_declaration:fd_topo_wksp_new}} -->
Apply a new function to each object in a specified workspace.
- **Description**: This function iterates over all objects in a given workspace within a topology and applies a specified 'new' function from a set of callbacks to each object that matches the workspace ID and object name. It is typically used to initialize or configure objects in a workspace after the topology has been set up. The function requires a valid topology and workspace, and a non-null array of callback structures. Each callback structure should contain a 'new' function pointer that will be invoked for matching objects.
- **Inputs**:
    - `topo`: A pointer to a constant fd_topo_t structure representing the topology. It must not be null and should be properly initialized before calling this function.
    - `wksp`: A pointer to a constant fd_topo_wksp_t structure representing the workspace. It must not be null and should correspond to a valid workspace within the topology.
    - `callbacks`: An array of pointers to fd_topo_obj_callbacks_t structures. Each structure should contain a 'new' function pointer and a name. The array must be null-terminated, and the function will apply the 'new' function to objects with matching names in the specified workspace.
- **Output**: None
- **See also**: [`fd_topo_wksp_new`](fd_topo.c.driver.md#fd_topo_wksp_new)  (Implementation)


---
### fd\_topo\_fill<!-- {{#callable_declaration:fd_topo_fill}} -->
Fills all workspaces in the topology with necessary data.
- **Description**: This function iterates over all workspaces in the given topology and fills each one with the necessary data. It should be called when the topology's workspaces need to be initialized or updated with current data. The function assumes that the topology structure is properly initialized and that the workspace count accurately reflects the number of workspaces present.
- **Inputs**:
    - `topo`: A pointer to an fd_topo_t structure representing the topology. It must be non-null and properly initialized with a valid workspace count.
- **Output**: None
- **See also**: [`fd_topo_fill`](fd_topo.c.driver.md#fd_topo_fill)  (Implementation)


---
### fd\_topo\_tile\_stack\_join<!-- {{#callable_declaration:fd_topo_tile_stack_join}} -->
Joins a huge page optimized stack for a specified tile.
- **Description**: This function is used to join a huge page optimized stack for a tile identified by the given application name, tile name, and tile kind ID. It is typically called when setting up the memory environment for a tile in a Firedancer topology. The function assumes that the stack already exists at a known path in the hugetlbfs mount. It is important to ensure that the application and tile names, along with the tile kind ID, correctly identify the stack to be joined. This function should be used in environments where memory optimization through huge pages is desired.
- **Inputs**:
    - `app_name`: A string representing the application name. It must not be null and should correctly identify the application associated with the stack.
    - `tile_name`: A string representing the tile name. It must not be null and should correctly identify the tile associated with the stack.
    - `tile_kind_id`: An unsigned long integer representing the kind ID of the tile. It should uniquely identify the tile kind within the application and tile name context.
- **Output**: Returns a pointer to the joined stack memory. If the operation fails, the function logs an error and may terminate the application.
- **See also**: [`fd_topo_tile_stack_join`](fd_topo_run.c.driver.md#fd_topo_tile_stack_join)  (Implementation)


---
### fd\_topo\_install\_xdp<!-- {{#callable_declaration:fd_topo_install_xdp}} -->
Installs an XDP program on a network interface for a specified topology.
- **Description**: This function installs an XDP (eXpress Data Path) program on the network interface specified in the given topology. It is used to set up packet processing on the network interface associated with the first 'net' tile in the topology. The function requires a valid topology structure and an optional IPv4 address for filtering. It returns a structure containing file descriptors for the XDP socket map and program link. This function should be called when setting up network packet processing in a Firedancer topology.
- **Inputs**:
    - `topo`: A pointer to a constant fd_topo_t structure representing the network topology. It must not be null and should be properly initialized with at least one 'net' tile.
    - `bind_addr`: An unsigned integer representing an optional IPv4 address for filtering by destination IP. It can be zero if no filtering is required.
- **Output**: Returns an fd_xdp_fds_t structure containing file descriptors for the XDP socket map and program link.
- **See also**: [`fd_topo_install_xdp`](fd_topo_run.c.driver.md#fd_topo_install_xdp)  (Implementation)


---
### fd\_topo\_run\_single\_process<!-- {{#callable_declaration:fd_topo_run_single_process}} -->
Runs all tiles in a single process, switching to specified UID and GID.
- **Description**: This function is used to run all tiles within a single process, which is the calling process. It spawns a thread for each tile, switches the thread to the specified user ID (UID) and group ID (GID), and then executes the tile. The function is useful for debugging and tooling, as it allows running tiles in a shared address space without sandboxing, except for the UID and GID switch. It is not intended for production use, where each tile would typically run in its own process with full security sandboxing. The function returns after spawning all threads, and an error is logged if any tile exits unexpectedly. The `agave` parameter controls which tiles are started based on their Agave status.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology configuration. Must not be null.
    - `agave`: An integer that determines which tiles to start: 0 for non-Agave tiles, 1 for Agave tiles, and any other value for all tiles.
    - `uid`: An unsigned integer representing the user ID to switch to for each thread. Must be a valid UID.
    - `gid`: An unsigned integer representing the group ID to switch to for each thread. Must be a valid GID.
    - `tile_run`: A function pointer to a callback that determines how each tile should be run. Must not be null.
    - `done_futex`: A pointer to an integer used as a futex for synchronization. Can be null if not used.
- **Output**: None
- **See also**: [`fd_topo_run_single_process`](fd_topo_run.c.driver.md#fd_topo_run_single_process)  (Implementation)


---
### fd\_topo\_run\_tile<!-- {{#callable_declaration:fd_topo_run_tile}} -->
Runs a specified tile within the current process, potentially sandboxing it.
- **Description**: This function is used to execute a specific tile within the current process, with options for sandboxing and debugging. It is typically called when a tile needs to be run in isolation, with the ability to control its environment and security settings. The function will not return, as tiles are expected to run indefinitely. It allows for setting user and group IDs, controlling terminal detachment, and configuring file descriptor allowances. Debugging support is provided through wait and debugger parameters, which can pause execution until certain conditions are met.
- **Inputs**:
    - `topo`: A pointer to an fd_topo_t structure representing the topology. Must not be null.
    - `tile`: A pointer to an fd_topo_tile_t structure representing the tile to run. Must not be null.
    - `sandbox`: An integer indicating whether to sandbox the process (non-zero) or not (zero).
    - `keep_controlling_terminal`: An integer indicating whether to keep the controlling terminal (non-zero) or detach it (zero) if sandboxing is enabled.
    - `dumpable`: An integer indicating whether the process should be made dumpable (non-zero) or not (zero).
    - `uid`: A uint specifying the user ID to switch to before running the tile.
    - `gid`: A uint specifying the group ID to switch to before running the tile.
    - `allow_fd`: An integer specifying a file descriptor to allow if sandboxing is enabled. If -1, no additional file descriptors are allowed.
    - `wait`: A volatile int pointer used for debugging. If non-null, the function waits until the pointed value is non-zero before proceeding.
    - `debugger`: A volatile int pointer used for debugging. If non-null, the function waits for a debugger to attach before setting the pointed value to non-zero.
    - `tile_run`: A pointer to an fd_topo_run_tile_t structure containing function pointers and settings for running the tile. Must not be null.
- **Output**: None
- **See also**: [`fd_topo_run_tile`](fd_topo_run.c.driver.md#fd_topo_run_tile)  (Implementation)


---
### fd\_topo\_mlock\_max\_tile<!-- {{#callable_declaration:fd_topo_mlock_max_tile}} -->
Determine the maximum memory lock requirement for any tile in the topology.
- **Description**: Use this function to find out the maximum amount of memory that any single tile in the topology will lock using mlock(). This is useful for setting the RLIMIT_MLOCK value appropriately to ensure that all tile processes can successfully lock the required memory. The function should be called after the topology has been fully configured and before any tiles are run, to ensure accurate memory requirements are captured.
- **Inputs**:
    - `topo`: A pointer to a constant fd_topo_t structure representing the topology. This must not be null and should be fully initialized with all tiles and their configurations.
- **Output**: Returns the maximum amount of memory, in bytes, that will be locked by any single tile in the topology.
- **See also**: [`fd_topo_mlock_max_tile`](fd_topo.c.driver.md#fd_topo_mlock_max_tile)  (Implementation)


---
### fd\_topo\_mlock<!-- {{#callable_declaration:fd_topo_mlock}} -->
Calculates the total memory size of all workspaces in a topology.
- **Description**: Use this function to determine the total memory size, in bytes, required by all workspaces in a given topology. This is useful for understanding the memory footprint of the topology's workspaces. The function should be called with a valid topology structure that has been properly initialized. It does not modify the input topology or any of its components.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure representing the topology. This must not be null and should be properly initialized with valid workspace data.
- **Output**: Returns the total memory size in bytes of all workspaces in the topology.
- **See also**: [`fd_topo_mlock`](fd_topo.c.driver.md#fd_topo_mlock)  (Implementation)


---
### fd\_topo\_gigantic\_page\_cnt<!-- {{#callable_declaration:fd_topo_gigantic_page_cnt}} -->
Returns the number of gigantic pages needed by the topology on a specified NUMA node.
- **Description**: Use this function to determine the number of gigantic pages required by the topology on a specific NUMA node. This is useful for memory allocation and planning in systems where memory is divided into NUMA nodes. The function should be called with a valid topology structure and a valid NUMA node index. It assumes that the topology has been properly initialized and populated with workspace information.
- **Inputs**:
    - `topo`: A pointer to a constant fd_topo_t structure representing the topology. It must not be null and should be properly initialized with workspace data.
    - `numa_idx`: An unsigned long representing the index of the NUMA node. It should be within the range of available NUMA nodes in the system. If the index is invalid, the function will return 0.
- **Output**: The function returns an unsigned long representing the total number of gigantic pages required by the topology on the specified NUMA node.
- **See also**: [`fd_topo_gigantic_page_cnt`](fd_topo.c.driver.md#fd_topo_gigantic_page_cnt)  (Implementation)


---
### fd\_topo\_huge\_page\_cnt<!-- {{#callable_declaration:fd_topo_huge_page_cnt}} -->
Returns the number of huge pages needed by the topology on a specified NUMA node.
- **Description**: Use this function to determine the number of huge pages required by the topology on a specific NUMA node. This count includes pages needed for workspaces and process stacks that are placed in the hugetlbfs. The function can also account for anonymous huge pages if specified. It is important to ensure that the `topo` parameter is a valid pointer to a properly initialized `fd_topo_t` structure before calling this function.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology. Must not be null and should be properly initialized.
    - `numa_idx`: An unsigned long representing the index of the NUMA node for which the huge page count is needed. Should be a valid NUMA node index within the system.
    - `include_anonymous`: An integer flag indicating whether to include anonymous huge pages in the count. Non-zero values include anonymous pages, while zero excludes them.
- **Output**: Returns the total number of huge pages as an unsigned long.
- **See also**: [`fd_topo_huge_page_cnt`](fd_topo.c.driver.md#fd_topo_huge_page_cnt)  (Implementation)


---
### fd\_topo\_print\_log<!-- {{#callable_declaration:fd_topo_print_log}} -->
Prints a message describing the topology to an output stream.
- **Description**: This function generates a detailed summary of the topology described by the `fd_topo_t` structure and outputs it either to the standard output or as a NOTICE log message, depending on the value of the `stdout` parameter. It provides information about the total number of tiles, memory usage, required pages, and details about workspaces, objects, links, and tiles within the topology. This function should be called when a comprehensive overview of the topology is needed for debugging or monitoring purposes. The `topo` parameter must be a valid, non-null pointer to an initialized `fd_topo_t` structure.
- **Inputs**:
    - `stdout`: An integer flag indicating the output destination. If non-zero, the message is printed to standard output; otherwise, it is logged as a NOTICE message.
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology to be described. Must not be null and should be properly initialized before calling this function.
- **Output**: None
- **See also**: [`fd_topo_print_log`](fd_topo.c.driver.md#fd_topo_print_log)  (Implementation)



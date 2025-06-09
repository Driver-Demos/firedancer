# Purpose
The provided C source code file is designed to simulate a smaller topology for a specific application, likely related to a distributed system or network simulation. The primary purpose of this code is to set up and manage a series of interconnected components, referred to as "tiles," which include playback, storei, replay, and exec tiles. These components are organized in a topology that facilitates the reading of an archive file to reproduce fragments into a storei tile and to simulate the behavior of a replay tile, including the management of forks. The code is structured to define and configure these tiles, establish communication links between them, and manage shared resources such as transaction caches and block stores.

The code is not a standalone executable but rather a part of a larger system, as indicated by its inclusion of multiple headers and its reliance on external configurations and shared memory. It defines a public API through the `fd_action_sim` structure, which provides a command interface for the simulation. The code is modular, with functions dedicated to setting up different components of the topology, such as transaction caches, runtime environments, and block stores. It also includes mechanisms for initializing and running the topology in a single process, suggesting its use in a controlled simulation environment. The detailed setup of communication links and shared objects indicates a focus on simulating complex interactions within a distributed system.
# Imports and Dependencies

---
- `../../shared/commands/run/run.h`
- `../../shared/fd_config.h`
- `../../../disco/topo/fd_cpu_topo.h`
- `../../../disco/topo/fd_topob.h`
- `../../../util/pod/fd_pod_format.h`
- `../../../flamenco/runtime/fd_runtime.h`
- `../../../flamenco/runtime/fd_txncache.h`
- `unistd.h`
- `sys/random.h`
- `../../../flamenco/runtime/fd_blockstore.h`


# Global Variables

---
### CALLBACKS
- **Type**: `fd_topo_obj_callbacks_t *`
- **Description**: CALLBACKS is an array of pointers to fd_topo_obj_callbacks_t structures, which are likely used to handle callbacks for topology objects in the Firedancer system. This array is declared as an external variable, indicating that its definition is located in another file.
- **Use**: CALLBACKS is used to store and manage callback functions for various topology objects within the Firedancer system.


---
### sim\_cmd\_fn
- **Type**: `function`
- **Description**: `sim_cmd_fn` is a static function that initializes and configures a simulation topology based on the provided configuration. It sets up various components and workspaces necessary for the simulation to run, and then executes the topology in a single process.
- **Use**: This function is used to set up and execute a simulation topology for testing or development purposes.


---
### sim\_cmd\_perm
- **Type**: `function`
- **Description**: The `sim_cmd_perm` function is a static function defined to handle permission checks for the 'sim' command. It takes three parameters: `args` of type `args_t*`, `chk` of type `fd_cap_chk_t*`, and `config` of type `config_t const*`, all of which are marked as unused with the `FD_PARAM_UNUSED` macro.
- **Use**: This function is used to define permission handling logic for the 'sim' command, although currently it does not implement any specific logic.


---
### fd\_action\_sim
- **Type**: `action_t`
- **Description**: The `fd_action_sim` is a global variable of type `action_t` that represents a command action for a simulation. It is initialized with specific function pointers and arguments related to the simulation command, such as `sim_cmd_args`, `sim_cmd_fn`, and `sim_cmd_perm`. This structure is used to define the behavior and permissions of the 'sim' command within the application.
- **Use**: This variable is used to encapsulate the details and execution logic of the 'sim' command, allowing it to be invoked with the specified arguments and permissions.


# Functions

---
### setup\_topo\_txncache<!-- {{#callable:setup_topo_txncache}} -->
The `setup_topo_txncache` function initializes a transaction cache object within a topology and sets its properties based on provided parameters.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology in which the transaction cache object will be set up.
    - `wksp_name`: A constant character pointer representing the name of the workspace associated with the transaction cache object.
    - `max_rooted_slots`: An unsigned long integer specifying the maximum number of rooted slots for the transaction cache.
    - `max_live_slots`: An unsigned long integer specifying the maximum number of live slots for the transaction cache.
    - `max_txn_per_slot`: An unsigned long integer specifying the maximum number of transactions per slot for the transaction cache.
    - `max_constipated_slots`: An unsigned long integer specifying the maximum number of constipated slots for the transaction cache.
- **Control Flow**:
    - Create a new topology object `obj` using `fd_topob_obj` with the type 'txncache' and the provided workspace name `wksp_name`.
    - Insert the `max_rooted_slots` value into the topology's properties using `fd_pod_insertf_ulong`, associating it with the key formatted as 'obj.<id>.max_rooted_slots'.
    - Insert the `max_live_slots` value into the topology's properties using `fd_pod_insertf_ulong`, associating it with the key formatted as 'obj.<id>.max_live_slots'.
    - Insert the `max_txn_per_slot` value into the topology's properties using `fd_pod_insertf_ulong`, associating it with the key formatted as 'obj.<id>.max_txn_per_slot'.
    - Insert the `max_constipated_slots` value into the topology's properties using `fd_pod_insertf_ulong`, associating it with the key formatted as 'obj.<id>.max_constipated_slots'.
    - Return the created topology object `obj`.
- **Output**: Returns a pointer to the newly created `fd_topo_obj_t` object representing the transaction cache within the topology.


---
### setup\_topo\_runtime\_pub<!-- {{#callable:setup_topo_runtime_pub}} -->
The `setup_topo_runtime_pub` function initializes a topology object for a 'runtime_pub' workspace and sets its properties in the topology's property list.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology in which the object is being set up.
    - `wksp_name`: A constant character pointer representing the name of the workspace associated with the 'runtime_pub' object.
    - `mem_max`: An unsigned long integer specifying the maximum memory allocation for the 'runtime_pub' object.
- **Control Flow**:
    - Call `fd_topob_obj` to create or retrieve a topology object with the name 'runtime_pub' and the specified workspace name.
    - Use `FD_TEST` to insert the `mem_max` value into the topology's properties, formatted with the object's ID.
    - Use `FD_TEST` to insert a constant value `12UL` as the workspace tag into the topology's properties, formatted with the object's ID.
    - Return the created or retrieved topology object.
- **Output**: Returns a pointer to an `fd_topo_obj_t` object representing the 'runtime_pub' object in the topology.


---
### setup\_topo\_blockstore<!-- {{#callable:setup_topo_blockstore}} -->
The `setup_topo_blockstore` function initializes a blockstore object within a topology, setting various properties and calculating its memory footprint.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology in which the blockstore object will be set up.
    - `wksp_name`: A constant character pointer representing the name of the workspace associated with the blockstore object.
    - `shred_max`: An unsigned long integer specifying the maximum number of shreds the blockstore can handle.
    - `block_max`: An unsigned long integer specifying the maximum number of blocks the blockstore can handle.
    - `idx_max`: An unsigned long integer specifying the maximum index size for the blockstore.
    - `txn_max`: An unsigned long integer specifying the maximum number of transactions the blockstore can handle.
    - `alloc_max`: An unsigned long integer specifying the maximum additional allocation size for the blockstore.
- **Control Flow**:
    - Create a blockstore object using `fd_topob_obj` with the given topology and workspace name.
    - Generate a random seed using `getrandom` and verify its size with `FD_TEST`.
    - Insert various properties into the topology's properties using `fd_pod_insertf_ulong`, including workspace tag, seed, shred_max, block_max, idx_max, txn_max, and alloc_max.
    - Calculate the blockstore's memory footprint using `fd_blockstore_footprint` and add `alloc_max` to it.
    - Insert the calculated footprint into the topology's properties under the 'loose' key.
    - Return the created blockstore object.
- **Output**: Returns a pointer to the initialized `fd_topo_obj_t` blockstore object.


---
### sim\_topo<!-- {{#callable:sim_topo}} -->
The `sim_topo` function initializes and configures a topology for a simulation environment, setting up various tiles and links based on the provided configuration.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing configuration details for setting up the topology, including tile settings, paths, and network parameters.
- **Control Flow**:
    - Initialize CPU topology using `fd_topo_cpus_init`.
    - Create a new topology using `fd_topob_new` and set the maximum page size.
    - Define CPU indices for different tiles (metric, playback, storei, replay, and static_end).
    - Add and configure the metric tile, including setting the Prometheus listen address and port.
    - Add and configure the playback tile, including setting the archiver path and checking its validity.
    - Add and configure the storei tile, including setting various paths and parameters related to blockstore and shred capabilities.
    - Add and configure the replay tile, including setting parameters for blockstore, transaction metadata, and various replay settings.
    - Add executor tiles based on the configuration's execution tile count.
    - Set up links between playback, storei, and replay tiles, defining their properties such as depth, MTU, and burst settings.
    - Configure shared objects used by storei, replay, and exec tiles, including blockstore, runtime publication, and transaction cache.
    - Finish the topology setup and print the topology information.
- **Output**: The function does not return a value; it modifies the `config` structure to set up the topology.
- **Functions called**:
    - [`setup_topo_blockstore`](#setup_topo_blockstore)
    - [`setup_topo_runtime_pub`](#setup_topo_runtime_pub)
    - [`setup_topo_txncache`](#setup_topo_txncache)


---
### sim\_cmd\_args<!-- {{#callable:sim_cmd_args}} -->
The `sim_cmd_args` function is a placeholder function that does not perform any operations on its input arguments.
- **Inputs**:
    - `pargc`: A pointer to an integer representing the argument count, marked as unused.
    - `pargv`: A pointer to a pointer to a character array representing the argument vector, marked as unused.
    - `args`: A pointer to an `args_t` structure, marked as unused.
- **Control Flow**:
    - The function is defined as static, meaning it is limited to the file scope.
    - The function takes three parameters, all marked with `FD_PARAM_UNUSED`, indicating they are not used within the function body.
    - The function body is empty, indicating no operations or logic are performed.
- **Output**: The function does not return any value or output.


# Function Declarations (Public API)

---
### fdctl\_tile\_run<!-- {{#callable_declaration:fdctl_tile_run}} -->
Retrieves a tile from the topology by its name.
- **Description**: Use this function to find and retrieve a tile from the topology based on its name. It is essential to ensure that the tile name provided exists within the topology; otherwise, an error will be logged, and a default-initialized tile will be returned. This function is typically used in scenarios where specific tile configurations or operations need to be executed based on the tile's presence in the topology.
- **Inputs**:
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure representing the tile to be retrieved. The `name` field of this structure is used to search for the tile in the topology. The pointer must not be null, and the `name` field must be a valid string.
- **Output**: Returns an `fd_topo_run_tile_t` structure corresponding to the tile with the matching name. If no matching tile is found, logs an error and returns a default-initialized `fd_topo_run_tile_t`.
- **See also**: [`fdctl_tile_run`](../../shared/boot/fd_boot.c.driver.md#fdctl_tile_run)  (Implementation)



# Purpose
The provided C code is part of a larger software system designed to perform a "backtest" operation, which involves replaying data from a database (such as RocksDB) to simulate and reproduce the behavior of a specific component called a "replay tile." This code is structured to set up a smaller topology for this purpose, involving various components like repair, replay, execution, and writing processes. The main technical components include functions for setting up different parts of the topology, such as runtime, transaction cache, blockstore, and snapshots, which are crucial for managing the data flow and processing within the backtest operation. The code also defines the interconnections between these components, ensuring that data is correctly routed and processed through the system.

This file is a C source file that is likely part of a larger application, possibly a simulation or testing framework, given its focus on replaying and testing data flows. It does not define a standalone executable but rather provides functionality that is integrated into a larger system. The code includes several static functions for configuring and initializing various components of the topology, and it defines a public API through the `fd_action_backtest` structure, which specifies the name, arguments, function, and permissions for the backtest action. This structure is likely used by other parts of the system to trigger the backtest operation, making it a critical part of the system's external interface.
# Imports and Dependencies

---
- `../../shared/commands/configure/configure.h`
- `../../shared/commands/run/run.h`
- `../../shared/fd_config.h`
- `../../../disco/tiles.h`
- `../../../disco/topo/fd_cpu_topo.h`
- `../../../disco/topo/fd_topob.h`
- `../../../util/pod/fd_pod_format.h`
- `../../../discof/replay/fd_replay_notif.h`
- `../../../flamenco/runtime/fd_runtime.h`
- `../../../flamenco/runtime/fd_txncache.h`
- `../../../flamenco/snapshot/fd_snapshot_base.h`
- `unistd.h`
- `sys/random.h`
- `../../../flamenco/runtime/fd_blockstore.h`


# Global Variables

---
### CALLBACKS
- **Type**: `fd_topo_obj_callbacks_t *`
- **Description**: CALLBACKS is a global variable that is an array of pointers to fd_topo_obj_callbacks_t structures. These structures are likely used to define callback functions or handlers for various events or operations within the topology management system.
- **Use**: CALLBACKS is used to store and manage callback functions for topology operations, facilitating event-driven programming within the system.


---
### backtest\_cmd\_fn
- **Type**: `function pointer`
- **Description**: `backtest_cmd_fn` is a static function that is used as a command function for the 'backtest' action. It is responsible for setting up and executing a backtest topology using the provided configuration.
- **Use**: This function is used to initialize and run a backtest topology, which involves setting up various components and executing them in a single process.


---
### backtest\_cmd\_perm
- **Type**: `function`
- **Description**: The `backtest_cmd_perm` is a static function defined to handle permission checks for the backtest command. It takes three parameters: `args` of type `args_t*`, `chk` of type `fd_cap_chk_t*`, and `config` of type `config_t const*`, all marked as unused with `FD_PARAM_UNUSED`. The function currently does not perform any operations.
- **Use**: This function is used as a placeholder for permission checks related to the backtest command, although it currently does not implement any logic.


---
### fd\_action\_backtest
- **Type**: `action_t`
- **Description**: The `fd_action_backtest` is a global variable of type `action_t` that represents a command action for a backtest operation. It is initialized with specific function pointers and arguments related to the backtest command, such as `backtest_cmd_args`, `backtest_cmd_fn`, and `backtest_cmd_perm`. This setup allows the backtest command to be executed with the defined behavior and permissions.
- **Use**: This variable is used to define and execute the backtest command within the software, providing the necessary functions and permissions for its operation.


# Functions

---
### setup\_topo\_runtime\_pub<!-- {{#callable:setup_topo_runtime_pub}} -->
The `setup_topo_runtime_pub` function initializes a topology object for a runtime publication workspace and sets specific properties related to memory and workspace tagging.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology configuration.
    - `wksp_name`: A constant character pointer representing the name of the workspace to be used.
    - `mem_max`: An unsigned long integer specifying the maximum memory allocation for the object.
- **Control Flow**:
    - Call `fd_topob_obj` to create or retrieve a topology object with the name 'runtime_pub' and the specified workspace name.
    - Insert the `mem_max` value into the topology's properties using `fd_pod_insertf_ulong`, associating it with the object's ID and the key format 'obj.%lu.mem_max'.
    - Insert a fixed value of 12UL into the topology's properties using `fd_pod_insertf_ulong`, associating it with the object's ID and the key format 'obj.%lu.wksp_tag'.
    - Return the created or retrieved topology object.
- **Output**: Returns a pointer to an `fd_topo_obj_t` object representing the initialized topology object for the runtime publication workspace.


---
### setup\_topo\_txncache<!-- {{#callable:setup_topo_txncache}} -->
The `setup_topo_txncache` function initializes a transaction cache object within a topology and sets its properties based on provided parameters.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology in which the transaction cache object is to be set up.
    - `wksp_name`: A constant character pointer representing the name of the workspace associated with the transaction cache object.
    - `max_rooted_slots`: An unsigned long integer specifying the maximum number of rooted slots for the transaction cache.
    - `max_live_slots`: An unsigned long integer specifying the maximum number of live slots for the transaction cache.
    - `max_txn_per_slot`: An unsigned long integer specifying the maximum number of transactions per slot for the transaction cache.
    - `max_constipated_slots`: An unsigned long integer specifying the maximum number of constipated slots for the transaction cache.
- **Control Flow**:
    - Create a new topology object `obj` using `fd_topob_obj` with the type 'txncache' and the provided workspace name `wksp_name`.
    - Insert the `max_rooted_slots` value into the topology's properties using `fd_pod_insertf_ulong`, associating it with the object's ID and the key 'max_rooted_slots'.
    - Insert the `max_live_slots` value into the topology's properties using `fd_pod_insertf_ulong`, associating it with the object's ID and the key 'max_live_slots'.
    - Insert the `max_txn_per_slot` value into the topology's properties using `fd_pod_insertf_ulong`, associating it with the object's ID and the key 'max_txn_per_slot'.
    - Insert the `max_constipated_slots` value into the topology's properties using `fd_pod_insertf_ulong`, associating it with the object's ID and the key 'max_constipated_slots'.
    - Return the created topology object `obj`.
- **Output**: A pointer to the newly created `fd_topo_obj_t` object representing the transaction cache within the topology.


---
### setup\_topo\_blockstore<!-- {{#callable:setup_topo_blockstore}} -->
The `setup_topo_blockstore` function initializes a blockstore object within a topology, setting various properties and calculating its memory footprint.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology in which the blockstore object is to be set up.
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
    - Calculate the blockstore's memory footprint using `fd_blockstore_footprint` and add alloc_max to it.
    - Insert the calculated blockstore footprint into the topology's properties under the 'loose' key.
    - Return the created blockstore object.
- **Output**: Returns a pointer to the newly created `fd_topo_obj_t` blockstore object.


---
### setup\_snapshots<!-- {{#callable:setup_snapshots}} -->
The `setup_snapshots` function configures the source type and path for incremental and full snapshots in a tile based on the provided configuration.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing configuration data, including paths for incremental and full snapshots.
    - `tile`: A pointer to an `fd_topo_tile_t` structure where the snapshot source type and path will be set.
- **Control Flow**:
    - Initialize flags `incremental_is_file` and `incremental_is_url` based on whether the respective paths in `config` are non-empty.
    - Check if both `incremental_is_file` and `incremental_is_url` are set, and log an error if so, as only one should be set.
    - Set `tile->replay.incremental_src_type` to `INT_MAX` initially.
    - If `incremental_is_url` is true, copy the URL from `config` to `tile` and set the source type to `FD_SNAPSHOT_SRC_HTTP`.
    - If `incremental_is_file` is true, copy the file path from `config` to `tile` and set the source type to `FD_SNAPSHOT_SRC_FILE`.
    - Repeat the above steps for `snapshot_is_file` and `snapshot_is_url` to configure full snapshot paths and types.
- **Output**: The function does not return a value; it modifies the `tile` structure in place to set the snapshot source type and path.


---
### backtest\_topo<!-- {{#callable:backtest_topo}} -->
The `backtest_topo` function sets up a topology for replaying shreds from a source like RocksDB, configuring various tiles and links within the topology based on the provided configuration.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing configuration details for setting up the topology, including layout, network, and tile-specific settings.
- **Control Flow**:
    - Initialize execution and writer tile counts from the configuration.
    - Create a new topology object and set its maximum page size and gigantic page threshold.
    - Add a metric tile to the topology and configure its Prometheus listen address and port.
    - Add a backtest tile to the topology, setting its archiver end slot and path, and log if the path is not found.
    - Add a replay tile to the topology, configuring various replay settings such as blockstore file paths, transaction metadata storage, and snapshot settings.
    - Call [`setup_snapshots`](#setup_snapshots) to configure snapshot sources for the replay tile.
    - Add executor and writer tiles to the topology based on the counts from the configuration.
    - Set up various links between tiles, including repair to replay, pack/batch to replay, replay to stake/send/poh, replay to backtest, replay to exec, exec to writer, and replay to writer links.
    - Configure shared objects used by replay, exec, and writer tiles, such as blockstore, turb_slot, runtime_pub, exec_spad, exec_fseq, writer_fseq, root_slot, txncache, busy, poh_slot, and constipated objects.
    - Finish the topology setup and print the topology information.
- **Output**: The function does not return a value; it sets up the topology and logs the configuration details.
- **Functions called**:
    - [`setup_snapshots`](#setup_snapshots)
    - [`setup_topo_blockstore`](#setup_topo_blockstore)
    - [`setup_topo_runtime_pub`](#setup_topo_runtime_pub)
    - [`setup_topo_txncache`](#setup_topo_txncache)


---
### backtest\_cmd\_args<!-- {{#callable:backtest_cmd_args}} -->
The `backtest_cmd_args` function is a placeholder function for handling command-line arguments related to the backtest command, but it currently does nothing as indicated by the empty function body and the use of `FD_PARAM_UNUSED`.
- **Inputs**:
    - `pargc`: A pointer to an integer representing the number of command-line arguments.
    - `pargv`: A pointer to an array of strings representing the command-line arguments.
    - `args`: A pointer to an `args_t` structure, which is presumably used to store parsed command-line arguments.
- **Control Flow**:
    - The function is defined as static, meaning it is limited to the file scope.
    - The function takes three parameters, all marked with `FD_PARAM_UNUSED`, indicating they are not used within the function body.
    - The function body is empty, meaning no operations are performed on the inputs.
- **Output**: The function does not return any value or produce any output.


# Function Declarations (Public API)

---
### fdctl\_tile\_run<!-- {{#callable_declaration:fdctl_tile_run}} -->
Retrieves a tile from the topology by its name.
- **Description**: Use this function to find and retrieve a tile from a predefined set of tiles based on its name. It is essential to ensure that the tile name provided exists within the set of tiles; otherwise, an error is logged, and a default-initialized tile is returned. This function is typically used in scenarios where tiles are dynamically managed and need to be accessed by name.
- **Inputs**:
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure representing the tile to be retrieved. The `name` field of this structure is used to search for the tile. The pointer must not be null, and the `name` field must be a valid string.
- **Output**: Returns an `fd_topo_run_tile_t` structure corresponding to the tile with the matching name. If no matching tile is found, logs an error and returns a default-initialized `fd_topo_run_tile_t`.
- **See also**: [`fdctl_tile_run`](../../shared/boot/fd_boot.c.driver.md#fdctl_tile_run)  (Implementation)



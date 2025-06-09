# Purpose
This C source code file is part of the Firedancer project and serves as the main entry point for a specific executable, likely related to development or testing, as indicated by the binary name "firedancer-dev". The file includes several header files from the Firedancer and shared development libraries, suggesting it relies on a broader framework or system architecture. The primary purpose of this file is to initialize and run a Firedancer application by setting up various components, stages, tiles, and actions that are essential for the application's operation.

The code defines arrays of callback functions, configuration stages, tiles, and actions, which are integral to the Firedancer's topology and configuration management. These arrays are populated with external references to various components, indicating that this file orchestrates the integration of these components into a cohesive application. The [`main`](#main) function calls `fd_dev_main`, passing command-line arguments and configuration details, which suggests that this file is responsible for bootstrapping the application, initializing the topology, and executing the main logic of the Firedancer system. The presence of numerous callbacks and actions indicates that the application is modular and extensible, allowing for a wide range of functionalities to be configured and executed within the Firedancer framework.
# Imports and Dependencies

---
- `../firedancer/topology.h`
- `../firedancer/config.h`
- `../shared_dev/boot/fd_dev_boot.h`
- `../shared/fd_action.h`
- `../shared/commands/configure/configure.h`


# Global Variables

---
### FD\_APP\_NAME
- **Type**: `string`
- **Description**: `FD_APP_NAME` is a global constant pointer to a string that holds the name of the application, which is "Firedancer". This variable is defined as a `char const *`, indicating that it points to a constant character string that should not be modified.
- **Use**: It is used to provide the application name in various contexts throughout the program.


---
### FD\_BINARY\_NAME
- **Type**: `string`
- **Description**: `FD_BINARY_NAME` is a global constant pointer to a string that holds the name of the binary executable for the Firedancer application. It is defined as a constant character pointer initialized to the value "firedancer-dev", indicating the development version of the software.
- **Use**: This variable is used to identify the specific binary version of the Firedancer application during execution.


---
### fd\_obj\_cb\_mcache
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_mcache` is a global variable of type `fd_topo_obj_callbacks_t`, which is likely a structure that holds callback functions related to topology object management in the Firedancer application. This variable is used to manage and respond to events or actions associated with a memory cache in the topology.
- **Use**: This variable is used as part of an array of callback pointers to facilitate the handling of topology-related operations.


---
### fd\_obj\_cb\_dcache
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_dcache` is a global variable that holds a callback structure of type `fd_topo_obj_callbacks_t`. This structure is likely used to define various callback functions related to the data cache operations in the Firedancer application.
- **Use**: This variable is used to register and manage callbacks for operations involving the data cache in the topology management system.


---
### fd\_obj\_cb\_cnc
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_cnc` is a global variable of type `fd_topo_obj_callbacks_t`, which is likely a structure that holds callback functions related to a specific topology object in the Firedancer application. This variable is used to manage and execute callbacks for the CNC (Control and Network Configuration) topology object.
- **Use**: This variable is used as part of an array of callback pointers to facilitate the handling of various topology-related events.


---
### fd\_obj\_cb\_fseq
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_fseq` is a global variable of type `fd_topo_obj_callbacks_t`, which is likely a structure that holds callback functions related to a specific topology object in the Firedancer application. This variable is used to define the behavior of the system when interacting with the 'fseq' topology object, allowing for modular and flexible handling of events or actions associated with that object.
- **Use**: This variable is used to register and manage callbacks for the 'fseq' topology object within the Firedancer framework.


---
### fd\_obj\_cb\_metrics
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_metrics` is a global variable of type `fd_topo_obj_callbacks_t`, which is likely a structure that holds callback functions related to topology object metrics in the Firedancer application. This variable is used to manage and execute specific actions or responses associated with metrics in the system's topology.
- **Use**: This variable is used as part of an array of callback pointers to facilitate the handling of topology object events.


---
### fd\_obj\_cb\_opaque
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_opaque` is a global variable of type `fd_topo_obj_callbacks_t`, which is likely a structure that holds callback functions related to topology object operations in the Firedancer application. This variable is part of a set of callback handlers that facilitate various operations within the topology management system.
- **Use**: This variable is used to reference a specific set of callbacks for handling opaque topology objects in the Firedancer framework.


---
### fd\_obj\_cb\_dbl\_buf
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_dbl_buf` is a global variable that holds a callback structure of type `fd_topo_obj_callbacks_t`. This structure is likely used to define various callback functions related to the topology object, specifically for double buffering operations.
- **Use**: This variable is used to register or reference callback functions for managing double buffer operations in the topology.


---
### fd\_obj\_cb\_neigh4\_hmap
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_neigh4_hmap` is a global variable of type `fd_topo_obj_callbacks_t`, which is likely a structure that holds callback functions related to network topology objects. This variable is part of a larger set of callback handlers that manage various aspects of the system's topology, specifically for neighbor handling in a hash map context.
- **Use**: This variable is used to register and manage callbacks for neighbor-related operations in the topology management system.


---
### fd\_obj\_cb\_fib4
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_fib4` is a global variable of type `fd_topo_obj_callbacks_t`, which is likely a structure that holds callback functions related to a specific topology object in the Firedancer application. This variable is part of a larger set of callback objects that manage various aspects of the system's topology.
- **Use**: This variable is used to provide callback functionality for the `fib4` topology object within the Firedancer framework.


---
### fd\_obj\_cb\_keyswitch
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_keyswitch` is a global variable of type `fd_topo_obj_callbacks_t`, which is likely a structure that holds callback functions related to a specific topology object, in this case, a keyswitch. This variable is part of a larger set of callback definitions that facilitate the handling of various topology-related events or actions within the Firedancer application.
- **Use**: This variable is used to register or reference the keyswitch callbacks in the topology management system.


---
### fd\_obj\_cb\_tile
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_tile` is a global variable of type `fd_topo_obj_callbacks_t`, which is likely a structure that holds callback functions related to a specific topology object in the Firedancer application. This variable is used to define the behavior of the tile object within the topology, allowing for modular and flexible handling of events or actions associated with that object.
- **Use**: This variable is used to register and manage callbacks for the tile topology object in the Firedancer application.


---
### fd\_obj\_cb\_runtime\_pub
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_runtime_pub` is a global variable of type `fd_topo_obj_callbacks_t`, which is likely a structure that holds callback functions related to topology object operations in the Firedancer application. This variable is used to manage runtime publication callbacks, enabling dynamic interactions with the topology system.
- **Use**: This variable is used to register and invoke callbacks for runtime publication events within the topology management framework.


---
### fd\_obj\_cb\_blockstore
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_blockstore` is a global variable that holds a callback structure of type `fd_topo_obj_callbacks_t`. This structure is likely used to define various callback functions related to the blockstore component of the Firedancer application, facilitating interaction with the topology of the system.
- **Use**: This variable is used as part of an array of callback pointers to manage different topology object callbacks.


---
### fd\_obj\_cb\_fec\_sets
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_fec_sets` is a global variable of type `fd_topo_obj_callbacks_t`, which is likely a structure that holds callback functions related to Forward Error Correction (FEC) settings in a topology management context. This variable is declared as `extern`, indicating that it is defined in another source file, allowing it to be accessed across multiple files in the project.
- **Use**: This variable is used to reference a set of callbacks specifically for handling FEC-related operations within the topology management system.


---
### fd\_obj\_cb\_txncache
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_txncache` is a global variable of type `fd_topo_obj_callbacks_t`, which is likely a structure that holds callback functions related to topology object management in the Firedancer application. This variable is used to manage and handle transactions within the topology, providing a mechanism for executing specific actions when certain events occur.
- **Use**: This variable is used as part of an array of callback pointers to facilitate transaction caching operations in the topology.


---
### fd\_obj\_cb\_exec\_spad
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: The `fd_obj_cb_exec_spad` variable is an external declaration of type `fd_topo_obj_callbacks_t`, which is likely a structure that holds callback functions related to a specific execution context in the Firedancer topology. This variable is part of a larger set of callback objects that facilitate various operations within the system's topology management.
- **Use**: It is used as an entry in the `CALLBACKS` array, which organizes multiple callback objects for easy access during execution.


---
### CALLBACKS
- **Type**: `array of pointers to `fd_topo_obj_callbacks_t``
- **Description**: `CALLBACKS` is a global array that holds pointers to various callback functions related to topology object management in the Firedancer application. Each element in the array points to a specific callback function that can be invoked during the execution of the program, facilitating modular and flexible handling of different topology events.
- **Use**: This variable is used to store and manage a collection of callback functions that can be called in response to specific topology-related events.


---
### fd\_cfg\_stage\_kill
- **Type**: `configure_stage_t`
- **Description**: `fd_cfg_stage_kill` is a global variable of type `configure_stage_t`, which likely represents a specific configuration stage in the Firedancer application. This variable is used to manage or define the behavior of the application during the 'kill' stage of its operation.
- **Use**: This variable is used as part of an array of configuration stages to facilitate the application's state management.


---
### fd\_cfg\_stage\_netns
- **Type**: `configure_stage_t`
- **Description**: The variable `fd_cfg_stage_netns` is an external declaration of type `configure_stage_t`, which likely represents a configuration stage related to network namespaces. This variable is part of a larger configuration management system, allowing for modular and organized handling of different stages in the application lifecycle.
- **Use**: It is used as an element in the `STAGES` array to manage various configuration stages.


---
### fd\_cfg\_stage\_genesis
- **Type**: `configure_stage_t`
- **Description**: The variable `fd_cfg_stage_genesis` is an external declaration of type `configure_stage_t`, which likely represents a configuration stage in the Firedancer application. This variable is part of a series of configuration stages that the application can utilize during its initialization or operational phases.
- **Use**: It is used as an element in the `STAGES` array, which holds pointers to various configuration stages for the application.


---
### fd\_cfg\_stage\_keys
- **Type**: `configure_stage_t`
- **Description**: The `fd_cfg_stage_keys` variable is an external declaration of type `configure_stage_t`, which likely represents a configuration stage in the Firedancer application. This variable is part of a series of configuration stages that the application can transition through, indicating a specific phase in the configuration process.
- **Use**: It is used as an element in the `STAGES` array, which holds pointers to various configuration stages for the application.


---
### STAGES
- **Type**: `array of pointers to `configure_stage_t``
- **Description**: `STAGES` is a global array that holds pointers to various configuration stages represented by the `configure_stage_t` type. Each element in the array corresponds to a specific stage in the configuration process, allowing for organized management and execution of these stages.
- **Use**: This variable is used to reference and iterate through different configuration stages during the setup of the application.


---
### fd\_tile\_net
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_net` is a global variable of type `fd_topo_run_tile_t`, which likely represents a network tile in the Firedancer topology. This variable is used to manage and interact with network-related functionalities within the Firedancer application.
- **Use**: This variable is utilized as part of an array of tiles that facilitate various network operations in the application.


---
### fd\_tile\_netlnk
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_netlnk` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific tile in a network topology used within the Firedancer application. This variable is declared as `extern`, indicating that it is defined in another source file, allowing it to be accessed across multiple files in the project.
- **Use**: This variable is used to reference a network link tile in the context of the Firedancer topology.


---
### fd\_tile\_sock
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_sock` is a global variable of type `fd_topo_run_tile_t`, which is likely a structure used to represent a specific tile in the Firedancer topology. This variable is part of a larger set of tiles that facilitate various functionalities within the Firedancer application.
- **Use**: It is used to reference a specific tile related to socket operations in the Firedancer topology.


---
### fd\_tile\_quic
- **Type**: `fd_topo_run_tile_t`
- **Description**: The variable `fd_tile_quic` is an external declaration of type `fd_topo_run_tile_t`, which likely represents a specific configuration or state related to a QUIC (Quick UDP Internet Connections) tile in the Firedancer application. This variable is part of a larger set of tiles that manage different aspects of the application's topology and functionality.
- **Use**: `fd_tile_quic` is used to reference the QUIC tile configuration within the Firedancer application.


---
### fd\_tile\_verify
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_verify` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific tile in a topology run within the Firedancer application. This variable is used to manage or verify the state of a particular component or process in the system's topology.
- **Use**: This variable is used as part of the `TILES` array to facilitate operations related to the verification tile in the topology.


---
### fd\_tile\_dedup
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_dedup` is a global variable of type `fd_topo_run_tile_t`, which is likely a structure used to represent a specific tile in the Firedancer topology. This variable is part of a collection of tiles that facilitate various functionalities within the system, specifically related to deduplication processes.
- **Use**: This variable is used to reference the deduplication tile within the Firedancer architecture, allowing for operations related to data deduplication.


---
### fd\_tile\_pack
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_pack` variable is an external declaration of type `fd_topo_run_tile_t`, which likely represents a specific configuration or state related to a tile in the Firedancer topology. This variable is part of a larger set of tile instances that are used to manage various aspects of the system's operation.
- **Use**: It is used as a reference in the `TILES` array, which aggregates multiple tile instances for processing within the Firedancer application.


---
### fd\_tile\_resolv
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_resolv` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific tile in a topology run context. This variable is part of a larger set of tiles that are used to manage different aspects of the system's operation, particularly in relation to network or data processing tasks.
- **Use**: This variable is used to reference a specific tile configuration during the execution of the program.


---
### fd\_tile\_shred
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_shred` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific tile in a topology run within the Firedancer application. This variable is part of a larger set of tiles that are used to manage various aspects of the application's functionality.
- **Use**: It is used as an element in the `TILES` array, which aggregates multiple tile instances for processing in the application.


---
### fd\_tile\_sign
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_sign` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific tile in a topology run within the Firedancer application. This variable is part of a larger set of tiles that are used to manage various aspects of the application's operation.
- **Use**: It is used to reference a specific tile configuration during the execution of the Firedancer application.


---
### fd\_tile\_metric
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_metric` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific tile in the Firedancer topology run. This variable is used to store metrics related to the performance or behavior of a particular tile during execution.
- **Use**: This variable is used to reference and manage the metrics associated with a specific tile in the Firedancer system.


---
### fd\_tile\_cswtch
- **Type**: `fd_topo_run_tile_t`
- **Description**: The variable `fd_tile_cswtch` is an external declaration of type `fd_topo_run_tile_t`, which likely represents a specific tile in a topology run configuration. This variable is part of a larger set of tiles that are used to manage different aspects of the system's operation.
- **Use**: It is used as an element in the `TILES` array, which holds pointers to various topology run tiles for processing.


---
### fd\_tile\_gui
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_gui` variable is an external declaration of type `fd_topo_run_tile_t`, which likely represents a specific tile in a topology run for the Firedancer application. This variable is part of a larger set of tiles that are used to manage different aspects of the application's functionality.
- **Use**: It is used to reference the GUI tile within the Firedancer topology, allowing for interaction with the graphical user interface components.


---
### fd\_tile\_plugin
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_plugin` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific configuration or state related to a plugin in the Firedancer topology system. This variable is part of a larger set of tile instances that manage various functionalities within the application.
- **Use**: It is used to reference the plugin tile within the Firedancer topology framework.


---
### fd\_tile\_bencho
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_bencho` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific configuration or state related to a tile in the Firedancer topology. This variable is part of a larger set of tile instances that are used to manage different aspects of the system's operation.
- **Use**: This variable is used to reference a specific tile configuration within the Firedancer system, allowing for organized management of various operational tiles.


---
### fd\_tile\_benchg
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_benchg` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific tile in the Firedancer topology. This variable is used to manage or reference a particular aspect of the system's operation related to benchmarking.
- **Use**: It is used within the context of the Firedancer application to facilitate operations related to benchmarking tiles.


---
### fd\_tile\_benchs
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_benchs` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific configuration or state related to a tile in the Firedancer topology. This variable is part of a larger set of tile instances that are used to manage different aspects of the system's operation.
- **Use**: This variable is used to reference a specific tile configuration within the Firedancer system.


---
### fd\_tile\_bundle
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_bundle` variable is an external declaration of type `fd_topo_run_tile_t`, which likely represents a specific configuration or state related to a tile in the Firedancer topology. This variable is part of a larger set of tile instances that are used to manage various functionalities within the Firedancer application.
- **Use**: It is used as an element in the `TILES` array, which aggregates multiple tile instances for processing within the application.


---
### fd\_tile\_gossip
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_gossip` is a global variable of type `fd_topo_run_tile_t`, which is likely used to represent a specific tile in the Firedancer topology related to gossip protocols. This variable is declared as an external reference, indicating that its definition exists in another translation unit, allowing it to be shared across different parts of the program.
- **Use**: This variable is used to manage and facilitate gossip communication within the Firedancer network topology.


---
### fd\_tile\_repair
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_repair` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific tile in the Firedancer topology related to repair operations. This variable is part of a larger set of tiles that manage various functionalities within the system.
- **Use**: It is used to reference the repair tile within the Firedancer topology, allowing for operations related to tile repair.


---
### fd\_tile\_replay
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_replay` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific configuration or state related to a tile in the Firedancer topology. This variable is part of a larger set of tiles that are used to manage various aspects of the system's operation.
- **Use**: It is used to reference the replay tile within the Firedancer topology, allowing for operations related to replay functionality.


---
### fd\_tile\_execor
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_execor` is a global variable of type `fd_topo_run_tile_t`, which is likely a structure used to represent a specific execution tile in the Firedancer topology. This variable is part of a larger system that manages various execution tiles, each responsible for different aspects of the application's functionality.
- **Use**: This variable is used to reference the execution tile responsible for executing specific tasks within the Firedancer framework.


---
### fd\_tile\_writer
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_writer` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific tile in the Firedancer topology system. This variable is used to manage or interact with a particular aspect of the system's operation, possibly related to writing data or processing tasks.
- **Use**: This variable is used within the Firedancer application to facilitate operations related to the writing tile in the topology.


---
### fd\_tile\_batch
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_batch` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific configuration or state related to a batch processing tile in the Firedancer application. This variable is part of a larger set of tile instances that manage various functionalities within the system.
- **Use**: This variable is used to reference the batch processing tile within the Firedancer architecture.


---
### fd\_tile\_poh
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_poh` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific tile in the Firedancer topology. This variable is used to manage or represent a particular aspect of the system's operation related to the Proof of History (PoH) functionality.
- **Use**: This variable is used within the context of the Firedancer application to facilitate operations related to the PoH tile.


---
### fd\_tile\_send
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_send` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific tile in the Firedancer topology system. This variable is used to manage or represent the state and behavior of a communication or processing tile within the system's architecture.
- **Use**: This variable is used as part of an array of tiles to facilitate operations related to the Firedancer topology.


---
### fd\_tile\_eqvoc
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_eqvoc` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific tile in the Firedancer topology. This variable is used to manage or represent a particular aspect of the system's operation related to the 'equivalence voc' functionality.
- **Use**: This variable is used as part of the global array `TILES`, which holds references to various topology run tiles.


---
### fd\_tile\_rpcserv
- **Type**: `fd_topo_run_tile_t`
- **Description**: The variable `fd_tile_rpcserv` is an external declaration of type `fd_topo_run_tile_t`, which likely represents a specific tile in the Firedancer topology related to RPC (Remote Procedure Call) services. This variable is part of a larger set of tiles that facilitate various functionalities within the Firedancer application.
- **Use**: It is used to reference the RPC service tile within the Firedancer topology.


---
### fd\_tile\_backtest
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_backtest` is a global variable of type `fd_topo_run_tile_t`, which is likely a structure used to represent a specific tile in the Firedancer topology related to backtesting functionality. This variable is part of a larger set of tiles that facilitate various operations within the Firedancer application.
- **Use**: This variable is used to reference the backtest tile within the Firedancer topology, allowing for specific operations related to backtesting.


---
### fd\_tile\_restart
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_restart` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific tile in the Firedancer topology run. This variable is used to manage or control the state of the restart tile within the system's architecture.
- **Use**: This variable is used to reference the restart tile in the Firedancer topology, allowing for operations related to restarting processes or components.


---
### fd\_tile\_archiver\_feeder
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_archiver_feeder` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific component or functionality within a topology management system. This variable is used to manage or facilitate the feeding of data to an archiving process, indicating its role in the overall architecture of the application.
- **Use**: This variable is used to reference the archiver feeder tile in the topology management system.


---
### fd\_tile\_archiver\_writer
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_archiver_writer` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific component or functionality within a topology management system. This variable is used to manage or facilitate the writing operations of an archiver tile in the Firedancer application.
- **Use**: It is used as part of the overall tile management system to handle archiving tasks.


---
### fd\_tile\_archiver\_playback
- **Type**: `string`
- **Description**: `fd_tile_archiver_playback` is an external variable of type `fd_topo_run_tile_t`, which is likely used to manage or represent a specific tile in the Firedancer architecture related to archiving playback functionality. This variable is part of a larger system that handles various tiles, each serving different roles in the topology.
- **Use**: This variable is used to reference the playback tile in the Firedancer system's architecture.


---
### TILES
- **Type**: `array of pointers to `fd_topo_run_tile_t``
- **Description**: `TILES` is a global array that holds pointers to various `fd_topo_run_tile_t` instances, which represent different operational tiles in the Firedancer topology. This array serves as a centralized reference for managing and accessing the different tiles used in the system.
- **Use**: `TILES` is used to facilitate the organization and retrieval of tile instances during the execution of the Firedancer application.


---
### fd\_action\_run
- **Type**: `action_t`
- **Description**: `fd_action_run` is a global variable of type `action_t`, which likely represents a specific action or command within the Firedancer application. This variable is part of a larger set of actions that the application can perform, indicating its role in managing or executing a particular task.
- **Use**: This variable is used to reference the action associated with running the Firedancer application.


---
### fd\_action\_run1
- **Type**: `action_t`
- **Description**: `fd_action_run1` is a global variable of type `action_t`, which is likely a structure or typedef representing an action within the Firedancer application. This variable is part of a collection of actions that the application can perform, indicating its role in the execution flow.
- **Use**: This variable is used to reference a specific action in the `ACTIONS` array, allowing the application to execute or manage that action during runtime.


---
### fd\_action\_configure
- **Type**: `action_t`
- **Description**: `fd_action_configure` is a global variable of type `action_t`, which likely represents a specific action or command within the Firedancer application. This variable is part of a larger set of actions that the application can perform, indicating its role in configuring the system.
- **Use**: This variable is used to reference the configuration action in the context of the application's action handling.


---
### fd\_action\_monitor
- **Type**: `action_t`
- **Description**: `fd_action_monitor` is a global variable of type `action_t`, which likely represents a specific action or state within the Firedancer application. This variable is part of a larger set of action variables that define various operational commands or states that the application can execute or respond to.
- **Use**: It is used within the application to monitor specific actions or events related to the Firedancer's operation.


---
### fd\_action\_keys
- **Type**: `action_t`
- **Description**: `fd_action_keys` is a global variable of type `action_t`, which likely represents a specific action or command within the Firedancer application. This variable is part of a larger set of action variables that define various operational commands for the system.
- **Use**: It is used to reference a specific action related to key management in the Firedancer application.


---
### fd\_action\_ready
- **Type**: `action_t`
- **Description**: `fd_action_ready` is a global variable of type `action_t`, which likely represents a specific action or state within the Firedancer application. This variable is part of a collection of action variables that define various operational commands or states that the application can execute or respond to.
- **Use**: It is used as part of the `ACTIONS` array, which holds pointers to different action types that the application can perform.


---
### fd\_action\_mem
- **Type**: `action_t`
- **Description**: `fd_action_mem` is a global variable of type `action_t`, which likely represents a specific action or state within the Firedancer application. This variable is part of a larger set of action variables that define various operational commands or states that the application can execute.
- **Use**: This variable is used to reference a specific action related to memory management within the application.


---
### fd\_action\_netconf
- **Type**: `action_t`
- **Description**: `fd_action_netconf` is a global variable of type `action_t`, which likely represents a specific action or command related to network configuration within the Firedancer application. This variable is part of a larger set of actions that the application can perform, indicating its role in managing network-related functionalities.
- **Use**: This variable is used to reference the network configuration action in the context of the application's action handling system.


---
### fd\_action\_set\_identity
- **Type**: `action_t`
- **Description**: `fd_action_set_identity` is a global variable of type `action_t`, which is likely a structure or typedef representing an action within the Firedancer application. This variable is used to define a specific action related to setting an identity, which may involve configuration or state management in the context of the application.
- **Use**: This variable is used as part of an array of actions that the application can perform, allowing it to be referenced and executed as needed.


---
### fd\_action\_version
- **Type**: `action_t`
- **Description**: `fd_action_version` is a global variable of type `action_t`, which likely represents a specific action or state within the Firedancer application. This variable is part of a larger set of action variables that define various operational commands for the application.
- **Use**: It is used to reference the version action in the context of the application's action handling system.


---
### fd\_action\_bench
- **Type**: `action_t`
- **Description**: `fd_action_bench` is a global variable of type `action_t`, which likely represents a specific action or command within the Firedancer application. This variable is part of a larger set of action variables that define various operational commands for the application.
- **Use**: It is used as an entry in the `ACTIONS` array, which holds pointers to different action commands that the application can execute.


---
### fd\_action\_bundle\_client
- **Type**: `action_t`
- **Description**: `fd_action_bundle_client` is a global variable of type `action_t`, which likely represents a specific action or command within the Firedancer application. This variable is part of a larger set of action variables that define various operational commands for the system.
- **Use**: It is used as an entry in the `ACTIONS` array, which holds pointers to different action commands that the application can execute.


---
### fd\_action\_dev
- **Type**: `action_t`
- **Description**: `fd_action_dev` is a global variable of type `action_t`, which likely represents a specific action or command within the Firedancer application. This variable is part of a larger set of action variables that define various operational commands for the application.
- **Use**: It is used as an entry in the `ACTIONS` array, which holds pointers to different action commands that the application can execute.


---
### fd\_action\_dump
- **Type**: `action_t`
- **Description**: `fd_action_dump` is a global variable of type `action_t`, which is likely a structure or typedef representing an action within the Firedancer application. This variable is part of a collection of actions that the application can perform, indicating that it may be used to handle specific operational tasks or commands.
- **Use**: This variable is used to reference a specific action in the context of the Firedancer application, allowing it to be included in action management arrays.


---
### fd\_action\_flame
- **Type**: `action_t`
- **Description**: `fd_action_flame` is a global variable of type `action_t`, which likely represents a specific action or command within the Firedancer application. This variable is part of a larger set of action variables that define various operational commands for the application.
- **Use**: It is used as an entry in the `ACTIONS` array, which holds pointers to different action commands that the application can execute.


---
### fd\_action\_help
- **Type**: `action_t`
- **Description**: `fd_action_help` is a global variable of type `action_t`, which is likely a structure or typedef representing an action within the Firedancer application. This variable is used to define a specific action that can be triggered or referenced during the application's execution, particularly in the context of user commands or operational tasks.
- **Use**: This variable is used as part of an array of actions that the application can perform, allowing it to be invoked when the corresponding help action is requested.


---
### fd\_action\_load
- **Type**: `action_t`
- **Description**: `fd_action_load` is a global variable of type `action_t`, which likely represents a specific action or command within the Firedancer application. This variable is part of a larger set of action variables that define various operational commands for the system.
- **Use**: It is used as an entry in the `ACTIONS` array, which holds pointers to different action commands that the application can execute.


---
### fd\_action\_pktgen
- **Type**: `action_t`
- **Description**: `fd_action_pktgen` is a global variable of type `action_t`, which is likely a structure or typedef representing an action in the Firedancer application. This variable is used to define a specific action related to packet generation within the system.
- **Use**: This variable is utilized in the context of action management, specifically for packet generation tasks.


---
### fd\_action\_quic\_trace
- **Type**: `action_t`
- **Description**: `fd_action_quic_trace` is a global variable of type `action_t`, which is likely used to define a specific action related to QUIC trace functionality within the Firedancer application. This variable is part of a larger set of action variables that represent different operational commands or states in the system.
- **Use**: This variable is used to reference the QUIC trace action within the application's action handling mechanism.


---
### fd\_action\_txn
- **Type**: `action_t`
- **Description**: `fd_action_txn` is a global variable of type `action_t`, which likely represents a specific action or command within the Firedancer application. This variable is part of a larger set of action variables that define various operational commands for the system.
- **Use**: It is used to reference a specific action related to transactions in the Firedancer application.


---
### fd\_action\_wksp
- **Type**: `action_t`
- **Description**: `fd_action_wksp` is a global variable of type `action_t`, which likely represents a specific action or command within the Firedancer application. This variable is part of a larger set of actions that the application can perform, indicating its role in managing or executing specific tasks.
- **Use**: This variable is used to reference a specific action in the `ACTIONS` array, allowing the application to invoke the corresponding functionality.


---
### fd\_action\_gossip
- **Type**: `action_t`
- **Description**: `fd_action_gossip` is a global variable of type `action_t`, which is likely used to represent a specific action or command within the Firedancer application. This variable is part of a larger set of action variables that define various operational commands for the system.
- **Use**: This variable is used to reference the 'gossip' action within the application's action handling mechanism.


---
### fd\_action\_sim
- **Type**: `action_t`
- **Description**: `fd_action_sim` is a global variable of type `action_t`, which likely represents a specific action or command within the Firedancer application. This variable is part of a larger set of actions that the application can perform, indicating its role in simulating certain behaviors or processes.
- **Use**: This variable is used as part of the `ACTIONS` array, allowing it to be referenced and executed as a specific action within the application.


---
### fd\_action\_backtest
- **Type**: `action_t`
- **Description**: `fd_action_backtest` is a global variable of type `action_t`, which likely represents a specific action or command within the Firedancer application. This variable is part of a larger set of actions that the application can perform, indicating its role in the system's operational capabilities.
- **Use**: This variable is used to reference the backtest action in the context of the Firedancer application, allowing it to be included in action arrays for execution.


---
### ACTIONS
- **Type**: `array of pointers to action_t`
- **Description**: The `ACTIONS` variable is an array of pointers to `action_t` structures, which represent various actions that can be performed within the application. Each element in the array points to a specific action, allowing for dynamic action handling and execution based on the application's requirements.
- **Use**: This variable is used to store and manage a collection of action pointers that can be invoked during the application's runtime.


# Functions

---
### main<!-- {{#callable:main}} -->
The `main` function serves as the entry point of the program, invoking `fd_dev_main` with command-line arguments and default configuration settings.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments passed to the program.
- **Control Flow**:
    - The function calls `fd_dev_main`, passing `argc`, `argv`, a hardcoded integer `1`, a pointer to `firedancer_default_config`, the size of `firedancer_default_config_sz`, and `fd_topo_initialize` as arguments.
    - The function returns the result of the `fd_dev_main` call.
- **Output**: The function returns an integer which is the result of the `fd_dev_main` function call, typically used as the program's exit status.



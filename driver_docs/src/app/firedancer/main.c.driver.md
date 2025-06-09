# Purpose
This C source code file is part of a larger software system named "Firedancer." It serves as an entry point for the application, as indicated by the presence of the [`main`](#main) function. The file is structured to initialize and configure various components of the Firedancer system, which appears to be a complex application with multiple functionalities. The code includes several external references to callback objects, configuration stages, and execution tiles, which are organized into arrays. These arrays (`CALLBACKS`, `STAGES`, `TILES`, and `ACTIONS`) suggest a modular architecture where different components can be dynamically managed and executed.

The file imports several headers, indicating dependencies on other parts of the system, such as topology management and configuration handling. The [`main`](#main) function calls `fd_main`, passing command-line arguments and configuration details, which suggests that this file is responsible for initializing the application with default settings and starting the execution flow. Additionally, the file includes a function [`add_bench_topo`](#add_bench_topo), which appears to be a utility for adding benchmarking topology configurations, although it is currently a placeholder with unused parameters. This function hints at the system's capability to handle performance testing or monitoring scenarios, further emphasizing the file's role in managing and orchestrating various operational aspects of the Firedancer application.
# Imports and Dependencies

---
- `topology.h`
- `config.h`
- `../shared/boot/fd_boot.h`
- `../shared/commands/configure/configure.h`


# Global Variables

---
### FD\_APP\_NAME
- **Type**: `char const *`
- **Description**: `FD_APP_NAME` is a global constant pointer to a string that holds the name of the application, which is "Firedancer". This variable is defined as a constant character pointer, ensuring that the string it points to cannot be modified. It serves as a way to reference the application name throughout the codebase.
- **Use**: This variable is used to provide a consistent application name for logging, display, or configuration purposes.


---
### FD\_BINARY\_NAME
- **Type**: `string`
- **Description**: `FD_BINARY_NAME` is a global constant pointer to a string that holds the name of the binary executable for the Firedancer application. It is defined as a constant character pointer, ensuring that the string it points to cannot be modified. This variable is typically used for logging, display, or identification purposes within the application.
- **Use**: `FD_BINARY_NAME` is used to reference the name of the binary throughout the application, providing a consistent identifier.


---
### fd\_obj\_cb\_mcache
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_mcache` is a global variable of type `fd_topo_obj_callbacks_t`, which is likely a structure that holds callback functions related to topology object management in the Firedancer application. This variable is used to manage and execute specific operations or events associated with memory caching in the topology.
- **Use**: This variable is used as part of an array of callback pointers to facilitate the handling of various topology-related operations.


---
### fd\_obj\_cb\_dcache
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_dcache` is a global variable of type `fd_topo_obj_callbacks_t`, which is likely a structure that holds callback functions related to topology object management in the Firedancer application. This variable is used to define specific behaviors or actions that should be executed in response to certain events or states within the topology management system.
- **Use**: This variable is used as part of an array of callback pointers to facilitate dynamic handling of topology-related events.


---
### fd\_obj\_cb\_cnc
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_cnc` is a global variable that holds a callback structure of type `fd_topo_obj_callbacks_t`. This structure is likely used to define various callback functions related to a specific object in the topology management system.
- **Use**: This variable is used to register or reference callback functions for handling events or actions associated with the CNC (Control Node Communication) in the topology.


---
### fd\_obj\_cb\_fseq
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_fseq` is a global variable of type `fd_topo_obj_callbacks_t`, which is likely a structure that holds function pointers or callback functions related to topology object management in the Firedancer application. This variable is part of a set of callbacks that facilitate interactions with various components of the system, specifically for handling the 'fseq' (possibly referring to a sequence or flow) aspect of the topology.
- **Use**: This variable is used to register or reference callback functions that are invoked during topology operations related to the 'fseq' component.


---
### fd\_obj\_cb\_metrics
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_metrics` is a global variable of type `fd_topo_obj_callbacks_t`, which is likely a structure that holds callback functions related to topology object metrics. This variable is used to manage and execute specific operations or actions associated with metrics in the topology system.
- **Use**: This variable is used as part of an array of callback pointers to facilitate the handling of topology object events.


---
### fd\_obj\_cb\_opaque
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_opaque` is a global variable of type `fd_topo_obj_callbacks_t`, which is likely a structure that holds function pointers or callback functions related to topology object operations. This variable is part of a set of callback structures that facilitate the handling of various topology-related events or actions in the system.
- **Use**: This variable is used to reference specific callback functions for managing topology objects in the application.


---
### fd\_obj\_cb\_dbl\_buf
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_dbl_buf` is a global variable of type `fd_topo_obj_callbacks_t`, which is likely a structure that holds function pointers or callback functions related to topology object management in the Firedancer application. This variable is used to manage double buffering operations for topology objects, facilitating efficient data handling and processing.
- **Use**: This variable is used as part of a collection of callbacks for managing various topology objects in the application.


---
### fd\_obj\_cb\_neigh4\_hmap
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_neigh4_hmap` is a global variable of type `fd_topo_obj_callbacks_t`, which is likely a structure that holds callback functions related to network neighbor management in a topology context. This variable is part of a larger set of callback functions that facilitate various operations within the system's topology management.
- **Use**: This variable is used as part of an array of callback pointers to manage network neighbor operations in the topology.


---
### fd\_obj\_cb\_fib4
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_fib4` is a global variable of type `fd_topo_obj_callbacks_t`, which is likely a structure that holds callback functions related to a specific topology object in the Firedancer application. This variable is part of a larger set of callback objects that manage various aspects of the system's topology.
- **Use**: This variable is used to reference the callback functions associated with the 'fib4' topology object within the application.


---
### fd\_obj\_cb\_keyswitch
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_keyswitch` is a global variable of type `fd_topo_obj_callbacks_t`, which is likely a structure that holds callback functions related to a specific topology object, in this case, a keyswitch. This variable is used to define the behavior of the keyswitch object within the system's topology management.
- **Use**: This variable is used to register and manage callbacks for the keyswitch topology object.


---
### fd\_obj\_cb\_tile
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_tile` is a global variable of type `fd_topo_obj_callbacks_t`, which is likely a structure that holds callback functions related to a specific tile in the topology. This variable is part of a larger set of callback objects that manage various aspects of the system's topology.
- **Use**: This variable is used to reference the callback functions associated with the tile in the topology management system.


---
### fd\_obj\_cb\_runtime\_pub
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_runtime_pub` is a global variable of type `fd_topo_obj_callbacks_t`, which is likely a structure that holds callback functions related to topology object management in the Firedancer application. This variable is used to define specific behaviors or actions that should occur during runtime for the published topology objects.
- **Use**: This variable is used to register or reference runtime callback functions for topology object operations.


---
### fd\_obj\_cb\_blockstore
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_blockstore` is a global variable that holds a reference to a structure of type `fd_topo_obj_callbacks_t`, which is likely used to define callback functions for handling operations related to a blockstore in the topology management system. This variable is part of a larger set of callback references that facilitate modular and flexible handling of various topology objects.
- **Use**: This variable is used to register and manage callback functions specific to blockstore operations within the topology framework.


---
### fd\_obj\_cb\_fec\_sets
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_fec_sets` is a global variable of type `fd_topo_obj_callbacks_t`, which is likely a structure that holds callback functions related to Forward Error Correction (FEC) settings in a topology management context. This variable is part of a larger set of callback structures that facilitate various operations within the system's topology.
- **Use**: This variable is used to register and manage FEC-related callback functions in the topology management system.


---
### fd\_obj\_cb\_txncache
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: `fd_obj_cb_txncache` is a global variable of type `fd_topo_obj_callbacks_t`, which is likely a structure that holds callback functions related to topology object management for transaction caching. This variable is used to define specific behaviors or actions that should be taken when certain events occur in the transaction cache context.
- **Use**: This variable is used to register callback functions for handling events related to transaction caching in the topology management system.


---
### fd\_obj\_cb\_exec\_spad
- **Type**: `fd_topo_obj_callbacks_t`
- **Description**: The `fd_obj_cb_exec_spad` variable is an external declaration of type `fd_topo_obj_callbacks_t`, which is likely a structure that holds callback functions related to a specific execution context in a topology management system. This variable is part of a larger set of callback objects that facilitate various operations within the system's topology.
- **Use**: It is used as a callback reference in the `CALLBACKS` array to manage execution-related operations in the topology.


---
### CALLBACKS
- **Type**: `array of pointers to `fd_topo_obj_callbacks_t``
- **Description**: `CALLBACKS` is a global array that holds pointers to various callback functions related to topology object management. Each element in the array points to a specific callback function, allowing for dynamic handling of different operations within the topology framework.
- **Use**: This variable is used to facilitate the registration and invocation of topology-related callbacks in the application.


---
### STAGES
- **Type**: `array of pointers to `configure_stage_t``
- **Description**: `STAGES` is a global array that holds pointers to various configuration stages, specifically of type `configure_stage_t`. Each element in the array points to a specific configuration stage, which is likely used during the initialization or configuration process of the application.
- **Use**: This variable is used to manage and access different configuration stages in the application.


---
### fd\_tile\_net
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_net` is a global variable of type `fd_topo_run_tile_t`, which likely represents a network tile in a topology management system. This variable is used to manage and configure network-related operations within the application.
- **Use**: It is utilized as part of an array of tiles that are referenced for various network operations.


---
### fd\_tile\_netlnk
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_netlnk` variable is an external declaration of type `fd_topo_run_tile_t`, which likely represents a specific tile in a network topology. This variable is part of a larger set of tiles that are used to manage different aspects of the network's operation.
- **Use**: It is used to reference a network link tile within the system's topology management.


---
### fd\_tile\_sock
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_sock` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific tile in a topology run related to socket operations. This variable is part of a larger set of tiles that manage various aspects of the system's functionality.
- **Use**: It is used to reference the socket tile within the topology management system.


---
### fd\_tile\_quic
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_quic` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific configuration or state related to a QUIC (Quick UDP Internet Connections) tile in the system's topology. This variable is part of a larger set of tile variables that manage different aspects of the system's operation.
- **Use**: This variable is used to reference the QUIC tile configuration within the system's topology management.


---
### fd\_tile\_verify
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_verify` variable is an external declaration of type `fd_topo_run_tile_t`, which likely represents a specific tile in a topology run configuration. This variable is part of a larger set of tiles that are used to manage various aspects of the system's operation, particularly in relation to verification processes.
- **Use**: This variable is used to reference a specific tile for verification within the system's topology management.


---
### fd\_tile\_dedup
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_dedup` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific tile configuration or state in a topology management system. This variable is part of a larger set of tiles that are used to manage different aspects of the system's operation.
- **Use**: It is used to reference the deduplication tile within the topology management framework.


---
### fd\_tile\_pack
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_pack` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific configuration or state related to a tile in a topology run. This variable is part of a larger set of tile variables that manage different aspects of the system's topology.
- **Use**: It is used to reference a specific tile configuration within the broader context of tile management in the application.


---
### fd\_tile\_resolv
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_resolv` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific tile in a topology run context. This variable is part of a collection of tiles that are used to manage different aspects of the system's operation, particularly in relation to network or data processing tasks.
- **Use**: This variable is used to reference a specific tile configuration within the broader system of tiles defined for the application.


---
### fd\_tile\_shred
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_shred` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific tile in a topology run configuration. This variable is part of a larger set of tiles that are used to manage different aspects of the system's operation.
- **Use**: This variable is used to reference a specific tile configuration within the system's topology management.


---
### fd\_tile\_sign
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_sign` variable is a global instance of the `fd_topo_run_tile_t` structure, which is likely used to represent a specific tile in a topology run. This variable is part of a larger set of tiles that are utilized in the system's topology management.
- **Use**: It is used to reference a specific tile configuration related to signing operations within the topology.


---
### fd\_tile\_metric
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_metric` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific tile in a topology run, encapsulating metrics related to that tile. This variable is part of a larger set of tiles used in the system, indicating its role in managing or monitoring performance metrics.
- **Use**: This variable is used to reference and manage the metrics associated with a specific tile during the execution of the topology.


---
### fd\_tile\_cswtch
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_cswtch` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific tile in a topology run configuration. This variable is part of a larger set of tiles that are used to manage different aspects of the system's operation.
- **Use**: This variable is used to reference a specific tile configuration within the system's topology management.


---
### fd\_tile\_gui
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_gui` variable is an external declaration of type `fd_topo_run_tile_t`, which likely represents a specific tile in a topology management system. This variable is part of a collection of tiles that are used to manage different aspects of the system's operation, particularly in a graphical user interface context.
- **Use**: It is used to reference the GUI tile within the broader system of tiles for managing various functionalities.


---
### fd\_tile\_plugin
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_plugin` variable is a global instance of the `fd_topo_run_tile_t` structure, which is likely used to represent a specific tile in a topology run. This variable is part of a collection of tiles that facilitate various functionalities within the Firedancer application.
- **Use**: It is used to reference a specific tile plugin in the context of the application's topology management.


---
### fd\_tile\_bundle
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_bundle` is a global variable of type `fd_topo_run_tile_t`, which likely represents a collection or configuration of tiles used in the Firedancer application. This variable is declared as `extern`, indicating that it is defined in another source file, allowing it to be accessed across multiple files within the project.
- **Use**: It is used to reference a specific tile configuration within the Firedancer application.


---
### fd\_tile\_gossip
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_gossip` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific tile in a topology management system. This variable is used to manage or represent the state and behavior of a gossip protocol within the system, facilitating communication between nodes.
- **Use**: This variable is used to reference the gossip tile in various operations related to topology management.


---
### fd\_tile\_repair
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_repair` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific tile in a topology management system. This variable is used to manage or represent the state and behavior of a repair operation within the system's topology.
- **Use**: This variable is used to reference the repair tile in various operations related to topology management.


---
### fd\_tile\_replay
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_replay` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific configuration or state related to a tile in a topology run. This variable is part of a larger set of tiles that are used in the context of the Firedancer application, indicating its role in managing or executing specific tasks within the system.
- **Use**: This variable is used to reference a specific tile configuration during the execution of the Firedancer application.


---
### fd\_tile\_execor
- **Type**: `fd_topo_run_tile_t`
- **Description**: The variable `fd_tile_execor` is an external declaration of type `fd_topo_run_tile_t`, which likely represents a specific tile in a topology run context. This variable is part of a larger set of tiles that are used to manage various operations within the Firedancer application.
- **Use**: It is used to reference a specific execution tile in the topology management system.


---
### fd\_tile\_writer
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_writer` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific tile in a topology run context. This variable is used to manage or represent the state and behavior of a tile responsible for writing operations within the system.
- **Use**: This variable is utilized in the context of managing tiles in a topology, specifically for writing operations.


---
### fd\_tile\_batch
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_batch` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific configuration or state related to a batch processing tile in the Firedancer topology. This variable is part of a larger set of tile instances that are used to manage different aspects of the system's operation.
- **Use**: It is used to reference the batch processing tile within the Firedancer system's topology.


---
### fd\_tile\_poh
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_poh` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific tile in a topology run context. This variable is part of a larger set of tiles that are used to manage different aspects of the system's operation.
- **Use**: It is used to reference a specific tile configuration or state within the topology management system.


---
### fd\_tile\_send
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_send` variable is an external declaration of type `fd_topo_run_tile_t`, which likely represents a specific tile in a topology run context. This variable is part of a larger set of tiles that are used to manage various operations within the Firedancer application.
- **Use**: It is used to reference a specific tile for sending data in the topology management system.


---
### fd\_tile\_eqvoc
- **Type**: `fd_topo_run_tile_t`
- **Description**: `fd_tile_eqvoc` is a global variable of type `fd_topo_run_tile_t`, which likely represents a specific tile in a topology management system. This variable is used to manage or represent a particular aspect of the system's topology, possibly related to event handling or communication.
- **Use**: This variable is used as part of an array of tiles that are referenced in the system's topology.


---
### fd\_tile\_rpcserv
- **Type**: `fd_topo_run_tile_t`
- **Description**: The variable `fd_tile_rpcserv` is an external declaration of type `fd_topo_run_tile_t`, which likely represents a specific tile in a topology management system. This tile is presumably responsible for handling RPC (Remote Procedure Call) services within the application.
- **Use**: It is used as part of an array of tiles that are managed within the system, specifically for RPC service functionalities.


---
### fd\_tile\_restart
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_restart` variable is an external reference to an instance of the `fd_topo_run_tile_t` structure, which is likely used to manage or represent a specific tile in the Firedancer topology. This variable is part of a larger set of tile instances that facilitate various operations within the system.
- **Use**: It is used as part of the `TILES` array to manage and access different tile functionalities in the Firedancer application.


---
### TILES
- **Type**: `array of pointers to `fd_topo_run_tile_t``
- **Description**: `TILES` is a global array that holds pointers to various `fd_topo_run_tile_t` instances, which represent different tiles in the Firedancer topology. Each tile is a component that can perform specific functions within the system, and the array allows for easy access and management of these tiles.
- **Use**: This variable is used to reference and manage the different tiles that are part of the Firedancer topology.


---
### fd\_action\_run
- **Type**: `action_t`
- **Description**: `fd_action_run` is a global variable of type `action_t`, which likely represents a specific action or command within the application. This variable is part of a larger set of actions that the application can perform, indicating its role in the system's operational flow.
- **Use**: This variable is used to reference a specific action in the `ACTIONS` array, allowing the application to execute or manage that action during runtime.


---
### fd\_action\_run1
- **Type**: `action_t`
- **Description**: `fd_action_run1` is a global variable of type `action_t`, which likely represents a specific action or state in the Firedancer application. This variable is part of a collection of actions that the application can perform, indicating its role in managing different operational modes or commands.
- **Use**: This variable is used to define and manage a specific action within the application's action handling system.


---
### fd\_action\_configure
- **Type**: `action_t`
- **Description**: `fd_action_configure` is a global variable of type `action_t`, which likely represents a specific action or command within the Firedancer application. This variable is used to configure the behavior of the application during its runtime, allowing for dynamic adjustments based on user input or system state.
- **Use**: This variable is used as part of an array of actions that the application can perform, enabling the configuration of various operational parameters.


---
### fd\_action\_monitor
- **Type**: `action_t`
- **Description**: `fd_action_monitor` is a global variable of type `action_t`, which likely represents a specific action or state within the application. This variable is part of a set of actions that the application can perform, indicating its role in monitoring functionality.
- **Use**: This variable is used to reference the monitoring action within the application's action management system.


---
### fd\_action\_keys
- **Type**: `action_t`
- **Description**: `fd_action_keys` is a global variable of type `action_t`, which likely represents a specific action or command within the application. This variable is part of a set of actions that the application can perform, indicating its role in managing or responding to specific events or commands.
- **Use**: This variable is used as part of an array of actions, allowing the application to reference and execute the associated action when needed.


---
### fd\_action\_ready
- **Type**: `action_t`
- **Description**: `fd_action_ready` is a global variable of type `action_t`, which likely represents a specific action state or command within the application. This variable is part of a set of actions that the application can perform, indicating that the system is ready to execute a particular task.
- **Use**: This variable is used to signal the readiness of the system to perform actions defined in the `ACTIONS` array.


---
### fd\_action\_mem
- **Type**: `action_t`
- **Description**: `fd_action_mem` is a global variable of type `action_t`, which likely represents a specific action or state within the application. This variable is part of a collection of actions that the application can perform, indicating its role in managing or executing memory-related operations.
- **Use**: This variable is used as part of an array of actions, allowing the application to reference and execute the memory action when needed.


---
### fd\_action\_netconf
- **Type**: `action_t`
- **Description**: `fd_action_netconf` is a global variable of type `action_t`, which likely represents a specific action or command related to network configuration within the application. This variable is part of a larger set of actions that the application can perform, indicating its role in managing network-related functionalities.
- **Use**: This variable is used as part of an array of actions that can be executed, allowing the application to handle network configuration tasks.


---
### fd\_action\_set\_identity
- **Type**: `action_t`
- **Description**: `fd_action_set_identity` is a global variable of type `action_t`, which likely represents a specific action or command within the Firedancer application. This variable is part of a collection of actions that the application can perform, indicating its role in managing or executing specific functionalities.
- **Use**: This variable is used to define and reference a specific action related to setting an identity in the application.


---
### fd\_action\_help
- **Type**: `action_t`
- **Description**: `fd_action_help` is a global variable of type `action_t`, which likely represents a specific action or command within the application. It is used to provide help information to users, detailing the available commands and their usage.
- **Use**: This variable is utilized in the context of action handling, specifically to display help information when requested.


---
### fd\_action\_version
- **Type**: `action_t`
- **Description**: `fd_action_version` is a global variable of type `action_t`, which likely represents a specific version of an action within the Firedancer application. This variable is used to manage or identify the versioning of actions that the application can perform.
- **Use**: This variable is used to reference the version of an action in the context of action management.


---
### ACTIONS
- **Type**: `array of pointers to action_t`
- **Description**: `ACTIONS` is a global array that holds pointers to various `action_t` instances, which represent different actions that can be performed within the application. This array serves as a centralized reference for managing and executing these actions, allowing for dynamic action handling.
- **Use**: `ACTIONS` is used to access and invoke specific actions defined in the application.


# Functions

---
### main<!-- {{#callable:main}} -->
The `main` function serves as the entry point of the program, invoking `fd_main` with specific configuration parameters to initialize the Firedancer application.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments passed to the program.
- **Control Flow**:
    - The function calls `fd_main` with the following arguments: `argc`, `argv`, the integer `1`, a constant character pointer `firedancer_default_config`, the size of the default configuration `firedancer_default_config_sz`, and the function pointer `fd_topo_initialize`.
    - The function returns the result of the `fd_main` function call.
- **Output**: The function returns an integer value which is the result of the `fd_main` function call, typically used as the program's exit status.


---
### add\_bench\_topo<!-- {{#callable:add_bench_topo}} -->
The `add_bench_topo` function is a placeholder that takes multiple parameters related to benchmarking topology but does not perform any operations with them.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure, presumably representing the topology to be modified or used.
    - `affinity`: A constant character pointer, likely representing CPU affinity settings.
    - `benchg_tile_cnt`: An unsigned long integer representing the count of benchmark generation tiles.
    - `benchs_tile_cnt`: An unsigned long integer representing the count of benchmark server tiles.
    - `accounts_cnt`: An unsigned long integer representing the number of accounts involved in the benchmark.
    - `transaction_mode`: An integer representing the mode of transactions, possibly indicating different transaction types or settings.
    - `contending_fraction`: A float representing the fraction of contending transactions.
    - `cu_price_spread`: A float representing the price spread for computational units.
    - `conn_cnt`: An unsigned long integer representing the number of connections.
    - `send_to_port`: A ushort representing the port number to send data to.
    - `send_to_ip_addr`: A uint representing the IP address to send data to.
    - `rpc_port`: A ushort representing the port number for RPC communication.
    - `rpc_ip_addr`: A uint representing the IP address for RPC communication.
    - `no_quic`: An integer flag indicating whether QUIC protocol should be disabled.
    - `reserve_agave_cores`: An integer flag indicating whether to reserve Agave cores.
- **Control Flow**:
    - The function takes multiple parameters but does not perform any operations with them.
    - Each parameter is cast to void to suppress unused variable warnings, indicating that the function is a placeholder or stub.
- **Output**: The function does not produce any output or return any value.



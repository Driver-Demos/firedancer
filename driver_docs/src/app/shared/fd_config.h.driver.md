# Purpose
The provided C header file defines a comprehensive configuration structure for a software system, likely related to a distributed or networked application, given the inclusion of networking and consensus components. The file includes several structures, such as `fd_configh_t`, `fd_configf_t`, and `fd_config_net_t`, which encapsulate various configuration parameters related to paths, reporting, ledger management, gossip protocols, RPC settings, snapshots, and network configurations. These structures are organized to support different aspects of the system's operation, such as consensus mechanisms, runtime limits, and network interfaces, indicating a broad functionality aimed at configuring a complex application environment.

The file also defines a primary configuration structure, `fd_config_t`, which aggregates these components and includes additional settings for logging, development, and system layout. This structure is designed to be loaded and manipulated through the [`fd_config_load`](#fd_config_load) function, which reads configuration data from files, validates it, and prepares it for use. The file also provides a function, [`fd_config_to_memfd`](#fd_config_to_memfd), to facilitate sharing configuration data with child processes via memory file descriptors. This header file is intended to be included in other C source files, providing a public API for configuration management within the application.
# Imports and Dependencies

---
- `../../disco/topo/fd_topo.h`
- `../../ballet/base58/fd_base58.h`
- `../../util/net/fd_net_headers.h`
- `net/if.h`


# Data Structures

---
### fd\_configh
- **Type**: `struct`
- **Members**:
    - `dynamic_port_range`: A character array of size 32 to store the dynamic port range.
    - `paths`: A nested struct containing paths related to accounts and authorized voters.
    - `reporting`: A nested struct for storing Solana metrics configuration.
    - `ledger`: A nested struct for ledger configuration including account indexes and paths.
    - `gossip`: A nested struct for gossip protocol configuration including port check and host.
    - `consensus`: A nested struct for consensus configuration including snapshot and genesis fetch settings.
    - `rpc`: A nested struct for RPC configuration including API settings and transaction history.
    - `snapshots`: A nested struct for snapshot configuration including paths and retention settings.
    - `layout`: A nested struct for layout configuration including affinity and scheduler threads.
- **Description**: The `fd_configh` structure is a comprehensive configuration data structure used in a software system, likely related to a blockchain or distributed ledger technology. It encapsulates various configuration settings across multiple domains such as network ports, file paths, ledger settings, gossip protocol, consensus mechanisms, RPC settings, snapshot management, and system layout. Each domain is represented by a nested struct, allowing for organized and modular configuration management. This structure is designed to handle complex configurations with multiple parameters, including arrays and nested structures, to support a robust and flexible configuration system.


---
### fd\_configh\_t
- **Type**: `struct`
- **Members**:
    - `dynamic_port_range`: A character array of size 32 to store the dynamic port range.
    - `paths`: A nested structure containing paths related to accounts and authorized voter paths.
    - `reporting`: A nested structure for storing Solana metrics configuration.
    - `ledger`: A nested structure for ledger configuration including account indexes and paths.
    - `gossip`: A nested structure for gossip configuration including port check and host.
    - `consensus`: A nested structure for consensus configuration including snapshot and genesis fetch settings.
    - `rpc`: A nested structure for RPC configuration including API settings and transaction history.
    - `snapshots`: A nested structure for snapshot configuration including paths and intervals.
    - `layout`: A nested structure for layout configuration including affinity and scheduler handler threads.
- **Description**: The `fd_configh_t` structure is a comprehensive configuration data structure used to manage various settings for a system, likely related to a distributed ledger or blockchain environment. It includes multiple nested structures to handle specific configuration areas such as paths, reporting, ledger, gossip, consensus, RPC, snapshots, and layout. Each nested structure contains fields pertinent to its domain, such as paths for file locations, metrics configurations, ledger settings, network gossip parameters, consensus rules, RPC settings, snapshot management, and system layout. This structure is designed to encapsulate a wide range of configuration options necessary for the operation and management of a complex system.


---
### fd\_configf
- **Type**: `struct`
- **Members**:
    - `consensus`: Contains a single integer field 'vote' for consensus-related configuration.
    - `blockstore`: Holds configuration parameters for block storage, including maximum sizes and file paths.
    - `runtime`: Defines runtime configuration with heap size and various limits for slots and transactions.
    - `layout`: Specifies the execution and writer tile counts for layout configuration.
- **Description**: The `fd_configf` structure is designed to encapsulate configuration settings for a system, focusing on consensus, block storage, runtime, and layout aspects. It includes nested structures to organize related parameters, such as voting settings in 'consensus', storage limits and file paths in 'blockstore', memory and transaction limits in 'runtime', and tile counts in 'layout'. This structure is likely used to configure and manage system resources and behaviors in a modular and organized manner.


---
### fd\_configf\_t
- **Type**: `struct`
- **Members**:
    - `consensus`: Contains a single integer field 'vote' related to consensus configuration.
    - `blockstore`: Holds configuration parameters for block storage, including maximum sizes and file paths.
    - `runtime`: Defines runtime limits such as heap size and transaction limits.
    - `layout`: Specifies the execution and writer tile counts for layout configuration.
- **Description**: The `fd_configf_t` structure is a configuration data structure used to define various parameters for a system, likely related to a blockchain or distributed ledger technology. It includes sections for consensus settings, block storage configurations, runtime limits, and layout specifications. Each section contains fields that specify limits, sizes, and paths necessary for the system's operation, allowing for detailed customization and optimization of the system's performance and resource allocation.


---
### fd\_config\_net
- **Type**: `struct`
- **Members**:
    - `provider`: Specifies the network provider, either 'xdp' or 'socket'.
    - `interface`: Holds the name of the network interface.
    - `bind_address`: Stores the bind address as a string.
    - `bind_address_parsed`: Contains the parsed bind address as an unsigned integer.
    - `ip_addr`: Holds the IP address as an unsigned integer.
    - `ingress_buffer_size`: Specifies the size of the ingress buffer.
    - `xdp`: Contains XDP-specific configuration details such as mode, zero-copy, and queue sizes.
    - `socket`: Holds socket-specific configuration details like receive and send buffer sizes.
- **Description**: The `fd_config_net` structure is designed to encapsulate network configuration settings for a system, supporting both XDP and socket-based networking. It includes fields for specifying the network provider, interface, and bind address, along with parsed and raw IP addresses. The structure also contains nested structures for XDP and socket configurations, allowing for detailed specification of buffer sizes, queue sizes, and operational modes, making it versatile for different networking scenarios.


---
### fd\_config\_net\_t
- **Type**: `struct`
- **Members**:
    - `provider`: Specifies the network provider, either 'xdp' or 'socket'.
    - `interface`: Holds the name of the network interface.
    - `bind_address`: Stores the bind address for the network.
    - `bind_address_parsed`: Indicates if the bind address has been parsed.
    - `ip_addr`: Stores the IP address.
    - `ingress_buffer_size`: Specifies the size of the ingress buffer.
    - `xdp`: Contains XDP-specific configuration settings.
    - `socket`: Contains socket-specific configuration settings.
- **Description**: The `fd_config_net_t` structure is designed to encapsulate network configuration settings for a system, supporting both XDP and socket-based networking. It includes fields for specifying the network provider, interface, and bind address, as well as parsed address and IP address information. The structure also defines buffer sizes for network data handling and contains nested structures for XDP and socket-specific configurations, allowing for detailed customization of network behavior.


---
### fd\_config
- **Type**: `struct`
- **Members**:
    - `name`: A character array to store the name of the configuration.
    - `user`: A character array to store the user associated with the configuration.
    - `hostname`: A character array to store the hostname.
    - `tick_per_ns_mu`: A double representing the mean ticks per nanosecond.
    - `tick_per_ns_sigma`: A double representing the standard deviation of ticks per nanosecond.
    - `topo`: An instance of fd_topo_t representing the topology configuration.
    - `cluster`: A character array to store the cluster name.
    - `is_live_cluster`: An integer flag indicating if the cluster is live.
    - `uid`: An unsigned integer representing the user ID.
    - `gid`: An unsigned integer representing the group ID.
    - `is_firedancer`: An integer flag indicating if the configuration is for a firedancer.
    - `frankendancer`: A union member of type fd_configh_t for frankendancer configuration.
    - `firedancer`: A union member of type fd_configf_t for firedancer configuration.
    - `paths`: A nested structure containing paths for base, ledger, identity key, and vote account.
    - `log`: A nested structure for logging configuration including file descriptors and log levels.
    - `consensus`: A nested structure containing consensus-related configurations.
    - `gossip`: A nested structure for gossip protocol configuration including entrypoints and ports.
    - `rpc`: A nested structure for RPC configuration including ports and metadata storage.
    - `layout`: A nested structure for layout configuration including tile counts and affinity.
    - `hugetlbfs`: A nested structure for huge page filesystem configuration.
    - `net`: An instance of fd_config_net_t for network configuration.
    - `development`: A nested structure for development settings including sandbox and network namespaces.
    - `tiles`: A nested structure for tile configurations including network, quic, verify, and more.
- **Description**: The `fd_config` structure is a comprehensive configuration data structure used to manage various settings and parameters for a system, potentially a distributed or networked application. It includes fields for basic identification like name, user, and hostname, as well as detailed configurations for network settings, logging, consensus protocols, and more. The structure supports both 'frankendancer' and 'firedancer' configurations through a union, allowing for flexible use cases. It also contains nested structures for paths, logging, gossip, RPC, layout, and development settings, making it a versatile and complex configuration tool for managing system behavior and performance.


---
### fd\_config\_t
- **Type**: `struct`
- **Members**:
    - `name`: A character array to store the name of the configuration.
    - `user`: A character array to store the user associated with the configuration.
    - `hostname`: A character array to store the hostname, with a maximum size defined by FD_LOG_NAME_MAX.
    - `tick_per_ns_mu`: A double representing the mean ticks per nanosecond.
    - `tick_per_ns_sigma`: A double representing the standard deviation of ticks per nanosecond.
    - `topo`: An instance of fd_topo_t representing the topology configuration.
    - `cluster`: A character array to store the cluster name.
    - `is_live_cluster`: An integer flag indicating if the cluster is live.
    - `uid`: An unsigned integer representing the user ID.
    - `gid`: An unsigned integer representing the group ID.
    - `is_firedancer`: An integer flag indicating if the configuration is for a Firedancer.
    - `frankendancer`: A union member of type fd_configh_t for Frankendancer-specific configurations.
    - `firedancer`: A union member of type fd_configf_t for Firedancer-specific configurations.
    - `paths`: A nested structure containing paths for base, ledger, identity key, and vote account.
    - `log`: A nested structure for logging configurations, including file descriptors and log levels.
    - `consensus`: A nested structure for consensus configurations, including expected shred version.
    - `gossip`: A nested structure for gossip configurations, including entrypoints and ports.
    - `rpc`: A nested structure for RPC configurations, including ports and storage options.
    - `layout`: A nested structure for layout configurations, including tile counts and affinity.
    - `hugetlbfs`: A nested structure for huge page configurations, including mount paths and page sizes.
    - `net`: An instance of fd_config_net_t for network configurations.
    - `development`: A nested structure for development configurations, including sandbox and network namespace settings.
    - `tiles`: A nested structure for tile configurations, including network, quic, and verification settings.
- **Description**: The `fd_config_t` structure is a comprehensive configuration data structure used to manage various settings and parameters for a system, potentially a distributed or networked application. It includes fields for general information such as name, user, and hostname, as well as specific configurations for network, logging, consensus, gossip, RPC, and development settings. The structure also supports different modes of operation through union members for Frankendancer and Firedancer configurations. Additionally, it contains nested structures for paths, logging, and various operational parameters, making it a versatile and detailed configuration tool for complex systems.


---
### config\_t
- **Type**: `struct`
- **Members**:
    - `name`: A character array to store the name of the configuration.
    - `user`: A character array to store the user associated with the configuration.
    - `hostname`: A character array to store the hostname, with a maximum size defined by FD_LOG_NAME_MAX.
    - `tick_per_ns_mu`: A double representing the mean ticks per nanosecond.
    - `tick_per_ns_sigma`: A double representing the standard deviation of ticks per nanosecond.
    - `topo`: An instance of fd_topo_t representing the topology configuration.
    - `cluster`: A character array to store the cluster name.
    - `is_live_cluster`: An integer flag indicating if the cluster is live.
    - `uid`: An unsigned integer representing the user ID.
    - `gid`: An unsigned integer representing the group ID.
    - `is_firedancer`: An integer flag indicating if the configuration is for a Firedancer.
    - `frankendancer`: A union member of type fd_configh_t for Frankendancer-specific configurations.
    - `firedancer`: A union member of type fd_configf_t for Firedancer-specific configurations.
    - `paths`: A nested structure containing paths for base, ledger, identity key, and vote account.
    - `log`: A nested structure for logging configurations, including file descriptors and log levels.
    - `consensus`: A nested structure for consensus-related configurations, including expected shred version.
    - `gossip`: A nested structure for gossip protocol configurations, including entrypoints and ports.
    - `rpc`: A nested structure for RPC configurations, including ports and transaction metadata storage.
    - `layout`: A nested structure for layout configurations, including tile counts and affinity.
    - `hugetlbfs`: A nested structure for huge page configurations, including mount paths and page sizes.
    - `net`: An instance of fd_config_net_t for network configurations.
    - `development`: A nested structure for development configurations, including sandbox and network namespace settings.
    - `tiles`: A nested structure for tile configurations, including network, quic, and verification settings.
- **Description**: The `config_t` structure is a comprehensive configuration data structure used to manage various settings and parameters for a system, potentially a distributed or networked application. It includes fields for general information such as name, user, and hostname, as well as specific configurations for network, logging, consensus, gossip, RPC, and development settings. The structure supports both Frankendancer and Firedancer configurations through a union, allowing for flexible use in different contexts. It also includes nested structures for detailed configuration of paths, logging, network, and other subsystems, making it a central component for managing the application's operational parameters.


# Function Declarations (Public API)

---
### fd\_config\_load<!-- {{#callable_declaration:fd_config_load}} -->
Loads and validates a configuration object from default and user configuration data.
- **Description**: This function initializes a configuration object by loading data from a default configuration and optionally overlaying it with user-specific configuration data. It should be used when setting up a configuration for a system that requires both default and user-specific settings. The function performs validation and fills in additional data necessary for the configuration to be complete and ready for use. It is important to note that this function will terminate the process with an error message if any issues are encountered during loading or validation, so it should be used in contexts where such behavior is acceptable.
- **Inputs**:
    - `is_firedancer`: Indicates whether the configuration is for a Firedancer setup. Accepts integer values, typically 0 or 1.
    - `netns`: Specifies the network namespace to be used. Accepts integer values.
    - `is_local_cluster`: Indicates if the configuration is for a local cluster. Accepts integer values, typically 0 or 1.
    - `default_config`: Pointer to the default configuration data. Must not be null.
    - `default_config_sz`: Size of the default configuration data in bytes. Must be a valid size corresponding to the data pointed to by default_config.
    - `user_config`: Pointer to the user configuration data. Can be null if no user-specific configuration is provided.
    - `user_config_sz`: Size of the user configuration data in bytes. Must be a valid size if user_config is not null.
    - `user_config_path`: Path to the user configuration file. Used for logging or error messages. Must not be null if user_config is provided.
    - `config`: Pointer to the configuration object to be initialized. Must not be null and should point to a valid fd_config_t structure.
- **Output**: None
- **See also**: [`fd_config_load`](fd_config.c.driver.md#fd_config_load)  (Implementation)


---
### fd\_config\_to\_memfd<!-- {{#callable_declaration:fd_config_to_memfd}} -->
Create a memfd and write the raw bytes of a config struct into it.
- **Description**: This function is used to create a memory file descriptor (memfd) and write the raw bytes of the provided configuration structure into it. It is useful for sharing configuration data with child processes that are spawned using `execve(2)`, as these processes cannot share memory with the parent process. The function returns a file descriptor for the memfd on success, which can be used to access the configuration data. If the function fails, it returns -1 and sets `errno` to indicate the error. This function should be called when there is a need to pass configuration data to a child process in a way that is independent of the file system.
- **Inputs**:
    - `config`: A pointer to a `fd_config_t` structure containing the configuration data to be written to the memfd. The pointer must not be null, and the structure should be fully initialized before calling this function.
- **Output**: Returns a file descriptor for the created memfd on success, or -1 on failure with `errno` set to indicate the error.
- **See also**: [`fd_config_to_memfd`](fd_config.c.driver.md#fd_config_to_memfd)  (Implementation)



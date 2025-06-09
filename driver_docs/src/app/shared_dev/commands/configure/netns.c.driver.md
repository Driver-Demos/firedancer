# Purpose
This C source code file is designed to manage network namespaces, providing functionality to create, configure, and delete network namespaces on a system. The code is structured around a configuration-driven approach, where the network namespace settings are derived from a `config_t` structure. The primary operations include initializing network namespaces with specific interfaces, setting up virtual Ethernet (veth) pairs, configuring network interface parameters, and disabling certain network features that are incompatible with network namespaces. The code also includes functions to check the existence and configuration of these namespaces, ensuring they are correctly set up or reporting errors if they are not.

The file defines a `configure_stage_t` structure named `fd_cfg_stage_netns`, which encapsulates the lifecycle management of network namespaces, including enabling, initializing, finalizing, and checking the configuration. The `RUN` macro is a critical component, executing shell commands to manipulate network namespaces and interfaces, and ensuring that any failures are logged and handled appropriately. This code is intended to be part of a larger system, likely a network management or simulation tool, where it can be imported and used to manage network namespaces as part of a broader configuration process.
# Imports and Dependencies

---
- `../../../shared/commands/configure/configure.h`
- `errno.h`
- `sys/stat.h`


# Global Variables

---
### fd\_cfg\_stage\_netns
- **Type**: `configure_stage_t`
- **Description**: The `fd_cfg_stage_netns` is a global variable of type `configure_stage_t` that represents a configuration stage for managing network namespaces. It includes function pointers for enabling, initializing, finalizing, and checking the configuration of network namespaces, as well as permissions for initialization and finalization. This structure is used to encapsulate the operations and checks necessary for setting up and tearing down network namespaces in a controlled manner.
- **Use**: This variable is used to manage the lifecycle of network namespaces, including their creation, configuration, and deletion, as part of a larger configuration management system.


# Functions

---
### enabled<!-- {{#callable:enabled}} -->
The `enabled` function checks if the network namespace feature is enabled in the given configuration.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing configuration settings, specifically for the development network namespace.
- **Control Flow**:
    - Access the `development.netns.enabled` field from the `config` structure.
    - Return the value of the `enabled` field, which indicates whether the network namespace feature is enabled.
- **Output**: An integer value representing the enabled status of the network namespace feature (typically 0 for disabled, non-zero for enabled).


---
### init\_perm<!-- {{#callable:init_perm}} -->
The `init_perm` function initializes permissions by checking if the current process has root capabilities to create and enter network namespaces.
- **Inputs**:
    - `chk`: A pointer to an `fd_cap_chk_t` structure used to check capabilities.
    - `config`: A constant pointer to a `config_t` structure, which is not used in this function.
- **Control Flow**:
    - The function calls `fd_cap_chk_root` with the `chk` pointer, a constant string `NAME`, and a description string to verify root capabilities for network namespace operations.
- **Output**: This function does not return any value; it performs a capability check as a side effect.


---
### fini\_perm<!-- {{#callable:fini_perm}} -->
The `fini_perm` function is responsible for finalizing permissions by removing network namespaces.
- **Inputs**:
    - `chk`: A pointer to an `fd_cap_chk_t` structure, used for capability checking.
    - `config`: A constant pointer to a `config_t` structure, which is not used in this function.
- **Control Flow**:
    - The function calls `fd_cap_chk_root` with the `chk` pointer, a constant string `NAME`, and a description string "remove network namespaces".
    - There are no conditional statements or loops; the function performs a single operation.
- **Output**: The function does not return any value; it is a `void` function.


---
### init<!-- {{#callable:init}} -->
The `init` function sets up network namespaces and virtual Ethernet interfaces based on the provided configuration.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing network namespace and interface configuration details.
- **Control Flow**:
    - Retrieve the number of tiles and interface names from the configuration.
    - Create two network namespaces using the `ip netns add` command for each interface.
    - Create a virtual Ethernet (veth) link between the two namespaces with specified RX and TX queue numbers.
    - Set the MAC addresses for each interface within their respective namespaces using `ip link set`.
    - Assign IP addresses to each interface within their respective namespaces using `ip address add`.
    - Bring up each interface within their respective namespaces using `ip link set dev up`.
    - Configure the number of RX and TX channels for each interface using `ethtool --set-channels`.
    - Disable UDP segmentation offload for each interface using `ethtool -K tx-udp-segmentation off`.
    - Disable generic segmentation offload and TX GRE segmentation for each interface using `ethtool -K`.
- **Output**: The function does not return a value; it performs network namespace and interface setup as a side effect.


---
### fini<!-- {{#callable:fini}} -->
The `fini` function deletes network interfaces and namespaces specified in the configuration.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing network namespace configuration details, specifically the names of the interfaces to be deleted.
    - `pre_init`: An integer parameter that is not used in the function, marked with `FD_PARAM_UNUSED`.
- **Control Flow**:
    - Retrieve the names of the network interfaces `interface0` and `interface1` from the `config` structure.
    - Construct a command string to delete `interface0` using `ip link del dev` and execute it using the `system` function.
    - Log a debug message if the deletion of `interface0` fails.
    - Construct and execute a command to delete the network namespace for `interface0` using `ip netns delete`.
    - Construct and execute a command to delete the network namespace for `interface1` using `ip netns delete`.
    - Log an error and terminate if both namespace deletions fail, indicating that neither namespace was present.
- **Output**: The function does not return a value; it performs cleanup operations and logs errors if deletions fail.


---
### check<!-- {{#callable:check}} -->
The `check` function verifies the existence and readability of two network namespace interfaces specified in the configuration.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing network namespace configuration details, specifically the names of two interfaces to check.
- **Control Flow**:
    - Retrieve the names of the two network interfaces (`interface0` and `interface1`) from the `config` structure.
    - Construct a file path for `interface0` in the `/var/run/netns/` directory and check if it exists and is readable using the `stat` function.
    - If `stat` fails for `interface0` and the error is not `ENOENT`, call `PARTIALLY_CONFIGURED` to indicate a partial configuration error.
    - Repeat the path construction and `stat` check for `interface1`.
    - If both `interface0` and `interface1` do not exist, call `NOT_CONFIGURED` to indicate neither interface is configured.
    - If only `interface0` does not exist, call `NOT_CONFIGURED` for `interface0`.
    - If only `interface1` does not exist, call `NOT_CONFIGURED` for `interface1`.
    - If both interfaces exist and are readable, call `CONFIGURE_OK` to indicate successful configuration.
- **Output**: The function returns a `configure_result_t` indicating the configuration status of the network namespaces, which could be `CONFIGURE_OK`, `PARTIALLY_CONFIGURED`, or `NOT_CONFIGURED` based on the checks performed.



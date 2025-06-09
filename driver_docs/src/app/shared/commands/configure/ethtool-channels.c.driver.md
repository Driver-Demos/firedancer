# Purpose
This C source code file is designed to configure network device channels using the `ethtool` utility, specifically focusing on setting the number of channels for network interfaces. The code is part of a larger configuration system, as indicated by its integration with a `configure.h` header and the definition of a `configure_stage_t` structure. The primary functionality revolves around checking and setting the number of channels on network devices, which is crucial for optimizing network performance, particularly in environments using the eXpress Data Path (XDP) for high-performance packet processing. The code includes functions to determine if a device is bonded, read slave devices for bonded interfaces, and configure the number of channels on both bonded and non-bonded devices. It also includes error handling to ensure robust operation, logging errors when operations such as opening files or performing ioctl calls fail.

The file defines a specific configuration stage named `fd_cfg_stage_ethtool_channels`, which includes methods for enabling the stage, initializing permissions, initializing the device configuration, and checking the current configuration against expected values. The code is structured to handle both bonded and non-bonded network devices, adjusting the number of channels based on the configuration provided. This is particularly important for systems that require a specific number of channels per network tile, as indicated by the `config->layout.net_tile_count` parameter. The code is not intended to be a standalone executable but rather a component of a larger system, likely a network configuration or management tool, that uses this functionality to ensure network devices are optimally configured for performance.
# Imports and Dependencies

---
- `configure.h`
- `errno.h`
- `stdio.h`
- `unistd.h`
- `sys/ioctl.h`
- `sys/stat.h`
- `linux/if.h`
- `linux/ethtool.h`
- `linux/sockios.h`


# Global Variables

---
### fd\_cfg\_stage\_ethtool\_channels
- **Type**: `configure_stage_t`
- **Description**: The `fd_cfg_stage_ethtool_channels` is a global variable of type `configure_stage_t` that represents a configuration stage for setting network device channels using ethtool. It is initialized with specific function pointers and parameters to manage the configuration process, including enabling, initializing, and checking the configuration of network device channels.
- **Use**: This variable is used to define and manage the configuration stage for adjusting network device channels with ethtool, ensuring the correct setup and validation of network interfaces.


# Functions

---
### enabled<!-- {{#callable:enabled}} -->
The `enabled` function determines whether the ethtool configuration should be enabled based on the network namespace and network stack provider settings.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing configuration settings, including network namespace and network provider information.
- **Control Flow**:
    - Check if the network namespace is enabled in the configuration; if so, return 0 to indicate ethtool should not be enabled.
    - Check if the network provider is 'xdp'; if not, return 0 to indicate ethtool should not be enabled.
    - If neither of the above conditions are met, return 1 to indicate ethtool should be enabled.
- **Output**: Returns an integer: 0 if ethtool should not be enabled, and 1 if it should be enabled.


---
### init\_perm<!-- {{#callable:init_perm}} -->
The `init_perm` function initializes permissions by invoking a root check for increasing network device channels using `ethtool --set-channels`.
- **Inputs**:
    - `chk`: A pointer to an `fd_cap_chk_t` structure, which is used to perform capability checks.
    - `config`: A constant pointer to a `config_t` structure, which is not used in this function (indicated by `FD_PARAM_UNUSED`).
- **Control Flow**:
    - The function calls `fd_cap_chk_root` with the `chk` pointer, a predefined name `NAME`, and a description string to check root capabilities for increasing network device channels.
- **Output**: This function does not return any value; it performs a side-effect operation by calling `fd_cap_chk_root`.


---
### device\_is\_bonded<!-- {{#callable:device_is_bonded}} -->
The `device_is_bonded` function checks if a given network device is part of a bonded interface by verifying the existence of a specific directory in the filesystem.
- **Inputs**:
    - `device`: A constant character pointer representing the name of the network device to check for bonding.
- **Control Flow**:
    - Constructs a file path string pointing to the bonding directory of the specified network device using `fd_cstr_printf_check`.
    - Performs a `stat` system call on the constructed path to check if the directory exists.
    - If the `stat` call fails for reasons other than the directory not existing (`ENOENT`), logs an error message and exits.
    - Returns `1` (true) if the directory exists, indicating the device is bonded, otherwise returns `0` (false).
- **Output**: Returns an integer value: `1` if the device is bonded (directory exists), or `0` if it is not bonded (directory does not exist).


---
### device\_read\_slaves<!-- {{#callable:device_read_slaves}} -->
The `device_read_slaves` function reads the list of slave network interfaces for a bonded network device and stores it in the provided output buffer.
- **Inputs**:
    - `device`: A constant character pointer representing the name of the network device whose slave interfaces are to be read.
    - `output`: A character array of size 4096 where the list of slave interfaces will be stored.
- **Control Flow**:
    - Constructs the file path to the bonding slaves file for the given network device.
    - Attempts to open the file at the constructed path for reading.
    - If the file cannot be opened, logs an error and exits.
    - Reads a line from the file into the output buffer, checking for errors such as end-of-file or read errors.
    - If the line is too long or empty, logs an error and exits.
    - Closes the file, logging an error if the close operation fails.
    - Removes the newline character from the end of the output string.
- **Output**: The function outputs the list of slave network interfaces as a null-terminated string in the provided output buffer.


---
### init\_device<!-- {{#callable:init_device}} -->
The `init_device` function configures the network device's channel settings using the ethtool interface.
- **Inputs**:
    - `device`: A string representing the name of the network device to be configured.
    - `combined_channel_count`: An unsigned integer specifying the number of combined channels to set for the device.
- **Control Flow**:
    - Check if the device name is too long or empty, logging an error if so.
    - Create a socket for network communication using `AF_INET` and `SOCK_DGRAM`, logging an error if socket creation fails.
    - Initialize an `ethtool_channels` structure and set its command to `ETHTOOL_GCHANNELS`.
    - Prepare an `ifreq` structure with the device name and associate it with the `ethtool_channels` structure.
    - Use `ioctl` to get the current channel settings of the device, logging an error if the operation fails.
    - Set the command in `ethtool_channels` to `ETHTOOL_SCHANNELS` and configure the channel counts based on the `max_combined` field.
    - Log a notice with the command to set the channels using `ethtool`.
    - Use `ioctl` to apply the new channel settings, handling specific errors related to the Intel ice driver and logging other errors.
    - Close the socket, logging an error if the close operation fails.
- **Output**: The function does not return a value; it logs errors and notices as part of its operation.


---
### init<!-- {{#callable:init}} -->
The `init` function configures network device channels for a given interface, handling both bonded and non-bonded devices.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing network configuration details, including the network interface and the number of network tiles.
- **Control Flow**:
    - Check if the network device specified in `config->net.interface` is bonded using [`device_is_bonded`](#device_is_bonded).
    - If the device is bonded, read the list of slave devices using [`device_read_slaves`](#device_read_slaves).
    - For each slave device, call [`init_device`](#init_device) to configure the number of channels based on `config->layout.net_tile_count`.
    - If the device is not bonded, directly call [`init_device`](#init_device) for the specified interface with the number of channels from `config->layout.net_tile_count`.
- **Output**: The function does not return a value; it performs configuration actions on network devices.
- **Functions called**:
    - [`device_is_bonded`](#device_is_bonded)
    - [`device_read_slaves`](#device_read_slaves)
    - [`init_device`](#init_device)


---
### check\_device<!-- {{#callable:check_device}} -->
The `check_device` function verifies if a network device has the expected number of channels and logs errors if the configuration is incorrect.
- **Inputs**:
    - `device`: A string representing the name of the network device to be checked.
    - `expected_channel_count`: An unsigned integer representing the expected number of channels for the network device.
- **Control Flow**:
    - Check if the device name length is valid and log an error if it is too long or empty.
    - Create a socket for communication and log an error if socket creation fails.
    - Initialize an `ethtool_channels` structure to query the device's channel configuration.
    - Set up an `ifreq` structure with the device name and associate it with the `ethtool_channels` structure.
    - Use `ioctl` to retrieve the current channel configuration of the device, handling errors if the device does not support channel configuration or if the `ioctl` call fails.
    - Close the socket and log an error if closing fails.
    - Determine the current number of channels based on the `ethtool_channels` structure's fields.
    - Compare the current number of channels with the expected count and log errors or configuration issues if they do not match.
- **Output**: The function does not return a value but logs errors or configuration issues if the device's channel configuration does not meet expectations.


---
### check<!-- {{#callable:check}} -->
The `check` function verifies if the network device or its bonded slaves have the correct number of channels configured as per the given configuration.
- **Inputs**:
    - `config`: A pointer to a `config_t` structure containing network configuration details, including the network interface and the expected number of channels.
- **Control Flow**:
    - Check if the network device specified in `config->net.interface` is bonded using [`device_is_bonded`](#device_is_bonded).
    - If the device is bonded, read the list of slave devices into a buffer using [`device_read_slaves`](#device_read_slaves).
    - Tokenize the buffer to extract each slave device name and call [`check_device`](#check_device) for each slave with the expected channel count from `config->layout.net_tile_count`.
    - If the device is not bonded, directly call [`check_device`](#check_device) with the network interface and expected channel count.
    - If all checks pass, call `CONFIGURE_OK()` to indicate successful configuration.
- **Output**: The function returns a `configure_result_t` indicating the success or failure of the configuration check.
- **Functions called**:
    - [`device_is_bonded`](#device_is_bonded)
    - [`device_read_slaves`](#device_read_slaves)
    - [`check_device`](#check_device)



# Purpose
This C header file defines the interface for managing XSK (AF_XDP socket) file descriptors within an XDP (eXpress Data Path) redirect program. It includes function prototypes for [`fd_xsk_activate`](#fd_xsk_activate) and [`fd_xsk_deactivate`](#fd_xsk_deactivate), which are responsible for installing and uninstalling XSK file descriptors into the XDP program's XSKMAP, respectively. The [`fd_xsk_activate`](#fd_xsk_activate) function binds an XSK to a network device, allowing packets to be redirected to and from the XSK's RX and TX queues, while [`fd_xsk_deactivate`](#fd_xsk_deactivate) removes this binding, stopping the traffic flow. The file also includes necessary headers for utility functions and data structures, ensuring proper integration with the broader system. This header is crucial for applications that require efficient packet processing and redirection at the kernel level using XDP and AF_XDP sockets.
# Imports and Dependencies

---
- `fd_xsk.h`
- `../../util/fd_util.h`


# Global Variables

---
### fd\_xsk\_activate
- **Type**: `function pointer`
- **Description**: The `fd_xsk_activate` is a function that installs an XSK file descriptor into the XDP redirect program's XSKMAP for a specified network device. It ensures that packets arriving on the netdev RX queue are redirected to the XSK RX queue and packets written to the XSK's TX ring are sent to the netdev TX queue. The function returns the XSK on success or logs an error and returns NULL on failure.
- **Use**: This function is used to activate an XSK by associating it with a network device, enabling packet redirection through the XDP program.


---
### fd\_xsk\_deactivate
- **Type**: `function pointer`
- **Description**: The `fd_xsk_deactivate` is a function pointer that represents a function used to uninstall an XSK file descriptor from the XDP redirect program's XSKMAP. This function ensures that the XSK will no longer receive network traffic by removing it from the map. It returns the XSK on success or if no installation was found, and logs an error to the warning log if it fails.
- **Use**: This function is used to deactivate an XSK by removing it from the XDP redirect program's XSKMAP, stopping it from receiving traffic.


# Function Declarations (Public API)

---
### fd\_xsk\_activate<!-- {{#callable_declaration:fd_xsk_activate}} -->
Installs an XSK file descriptor into the XDP redirect program's XSKMAP.
- **Description**: This function is used to bind an XSK file descriptor to a specific network device and queue by installing it into the XDP redirect program's XSKMAP. It should be called when you want to enable packet redirection for a network device using the XDP program. The function requires a valid local join to an fd_xsk_t structure and an open file descriptor for the XSKMAP. If another XSK is already installed at the specified key, it will be replaced without notification. On success, the function returns the provided xsk pointer, allowing packets arriving on the associated RX queue to be redirected to the XSK RX queue, and packets written to the XSK's TX ring to be sent to the corresponding TX queue. If an error occurs, the function logs a warning and returns NULL.
- **Inputs**:
    - `xsk`: A pointer to an fd_xsk_t structure representing the XSK to be activated. It must be a valid local join and must not be null.
    - `xsk_map_fd`: An integer representing the file descriptor for the XSKMAP where the XSK will be installed. It must be a valid, open file descriptor.
- **Output**: Returns the xsk pointer on success, or NULL on error.
- **See also**: [`fd_xsk_activate`](fd_xdp_redirect_user.c.driver.md#fd_xsk_activate)  (Implementation)


---
### fd\_xsk\_deactivate<!-- {{#callable_declaration:fd_xsk_deactivate}} -->
Uninstalls an XSK file descriptor from the XDP redirect program's XSKMAP.
- **Description**: Use this function to stop an XSK from receiving traffic by removing it from the XDP redirect program's XSKMAP. This function should be called when you want to deactivate the XSK and cease its traffic handling capabilities. It returns the XSK on successful deactivation or if no installation was found, ensuring that the XSK is no longer active in the network stack. In case of an error during the uninstallation process, the function logs a warning and returns NULL.
- **Inputs**:
    - `xsk`: A pointer to an fd_xsk_t structure representing the XSK to be deactivated. Must be a valid local join to fd_xsk_t and not null.
    - `xsk_map_fd`: An integer representing the file descriptor of the XSKMAP from which the XSK should be removed. Must be a valid file descriptor.
- **Output**: Returns the xsk on success or if no redirect program installation was found. Returns NULL on error, with a warning logged.
- **See also**: [`fd_xsk_deactivate`](fd_xdp_redirect_user.c.driver.md#fd_xsk_deactivate)  (Implementation)



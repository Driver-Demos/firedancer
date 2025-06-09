# Purpose
This C source code file provides functionality for managing flow control configurations, specifically for a system that handles multiple receivers. The code defines three primary functions: [`fd_fctl_new`](#fd_fctl_new), [`fd_fctl_cfg_rx_add`](#fd_fctl_cfg_rx_add), and [`fd_fctl_cfg_done`](#fd_fctl_cfg_done). The [`fd_fctl_new`](#fd_fctl_new) function initializes a flow control structure in shared memory, ensuring that the memory is properly aligned and that the maximum number of receivers (`rx_max`) does not exceed a predefined limit. The [`fd_fctl_cfg_rx_add`](#fd_fctl_cfg_rx_add) function adds a new receiver configuration to the flow control structure, validating parameters such as the maximum credit (`cr_max`) and ensuring that the number of receivers does not exceed the initialized maximum. The [`fd_fctl_cfg_done`](#fd_fctl_cfg_done) function finalizes the configuration by setting burst, maximum, resume, and refill credits, ensuring they are within valid ranges based on the receiver configurations.

The code is designed to be part of a larger system, likely a library, that manages flow control for data reception. It includes error checking and logging to handle invalid inputs and configurations. The functions operate on a custom data structure (`fd_fctl_t`), which is likely defined in the included header file "fd_fctl.h". This file does not define a public API or external interfaces directly but provides internal mechanisms for setting up and managing flow control parameters, which can be used by other parts of the system to ensure efficient and controlled data handling.
# Imports and Dependencies

---
- `fd_fctl.h`


# Functions

---
### fd\_fctl\_new<!-- {{#callable:fd_fctl_new}} -->
The `fd_fctl_new` function initializes a flow control structure in shared memory with specified parameters, ensuring alignment and size constraints are met.
- **Inputs**:
    - `shmem`: A pointer to the shared memory location where the flow control structure will be initialized.
    - `rx_max`: The maximum number of receive operations allowed, specified as an unsigned long integer.
- **Control Flow**:
    - Check if the `shmem` pointer is NULL; if so, log a warning and return NULL.
    - Verify if `shmem` is properly aligned using `fd_ulong_is_aligned`; if not, log a warning and return NULL.
    - Ensure `rx_max` does not exceed `FD_FCTL_RX_MAX_MAX`; if it does, log a warning and return NULL.
    - Cast `shmem` to a `fd_fctl_t` pointer and initialize its fields: `rx_max` is set to `rx_max`, `rx_cnt` to 0, and other control parameters (`in_refill`, `cr_burst`, `cr_max`, `cr_resume`, `cr_refill`) to 0.
    - Return the `shmem` pointer, now initialized as a flow control structure.
- **Output**: Returns the `shmem` pointer if initialization is successful, otherwise returns NULL if any checks fail.


---
### fd\_fctl\_cfg\_rx\_add<!-- {{#callable:fd_fctl_cfg_rx_add}} -->
The `fd_fctl_cfg_rx_add` function adds a new receiver configuration to a flow control structure, ensuring the provided parameters are valid and updating the structure accordingly.
- **Inputs**:
    - `fctl`: A pointer to the flow control structure (`fd_fctl_t`) to which a new receiver configuration will be added.
    - `cr_max`: The maximum credit value for the new receiver, which must be a positive value not exceeding `LONG_MAX`.
    - `seq_laddr`: A pointer to a sequence address, which can be NULL to indicate the receiver is disabled temporarily.
    - `slow_laddr`: A pointer to a slow address, which must not be NULL.
- **Control Flow**:
    - Check if `fctl` is NULL and log a warning if so, returning NULL.
    - Check if `cr_max` is zero or exceeds `LONG_MAX`, logging a warning and returning NULL if either condition is true.
    - Allow `seq_laddr` to be NULL, indicating the receiver is disabled for the time being.
    - Check if `slow_laddr` is NULL, log a warning, and return NULL if true.
    - Calculate the current receiver index (`rx_idx`) from `fctl->rx_cnt` and check if it exceeds `fctl->rx_max`, logging a warning and returning NULL if true.
    - Retrieve the private receiver array from `fctl` and set the `cr_max`, `seq_laddr`, and `slow_laddr` for the receiver at `rx_idx`.
    - Increment the receiver count (`rx_cnt`) in `fctl` and return the updated `fctl` structure.
- **Output**: Returns the updated `fd_fctl_t` structure with the new receiver configuration added, or NULL if any validation checks fail.
- **Functions called**:
    - [`fd_fctl_private_rx`](fd_fctl.h.driver.md#fd_fctl_private_rx)


---
### fd\_fctl\_cfg\_done<!-- {{#callable:fd_fctl_cfg_done}} -->
The `fd_fctl_cfg_done` function finalizes the configuration of a flow control structure by setting burst, max, resume, and refill credit values, ensuring they are within valid ranges.
- **Inputs**:
    - `fctl`: A pointer to an `fd_fctl_t` structure that is being configured.
    - `cr_burst`: An unsigned long representing the burst credit value to be set.
    - `cr_max`: An unsigned long representing the maximum credit value to be set.
    - `cr_resume`: An unsigned long representing the resume credit value to be set.
    - `cr_refill`: An unsigned long representing the refill credit value to be set.
- **Control Flow**:
    - Check if the `fctl` pointer is NULL and log a warning if so, returning NULL.
    - Retrieve the private receiver configuration and count from the `fctl` structure.
    - Calculate `cr_burst_max` as the minimum of `LONG_MAX` and the maximum credit values of all receivers.
    - Validate that `cr_burst` is within the range [1, `cr_burst_max`], logging a warning and returning NULL if not.
    - If `cr_max` is zero, set it to the maximum of `cr_burst_max` and the maximum credit values of all receivers.
    - Validate that `cr_max` is within the range [`cr_burst`, `LONG_MAX`], logging a warning and returning NULL if not.
    - If `cr_resume` is zero, calculate it as `cr_burst` plus two-thirds of the difference between `cr_max` and `cr_burst`.
    - Validate that `cr_resume` is within the range [`cr_burst`, `cr_max`], logging a warning and returning NULL if not.
    - If `cr_refill` is zero, calculate it as `cr_burst` plus half of the difference between `cr_resume` and `cr_burst`.
    - Validate that `cr_refill` is within the range [`cr_burst`, `cr_resume`], logging a warning and returning NULL if not.
    - Set the `cr_burst`, `cr_max`, `cr_resume`, and `cr_refill` values in the `fctl` structure.
    - Return the configured `fctl` structure.
- **Output**: Returns a pointer to the configured `fd_fctl_t` structure, or NULL if any validation fails.
- **Functions called**:
    - [`fd_fctl_private_rx`](fd_fctl.h.driver.md#fd_fctl_private_rx)



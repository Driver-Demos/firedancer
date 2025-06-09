# Purpose
The provided C header file, `fd_fctl.h`, defines a set of APIs for implementing credit-based flow control in distributed systems. This file is part of a larger system, likely a library, that aims to manage the flow of data between transmitters and receivers with minimal overhead. The primary focus of this code is to provide mechanisms for controlling data flow in scenarios where backpressure is undesirable, such as in large-scale distributed systems. The file includes definitions for managing flow control objects (`fd_fctl_t`), which handle the allocation and management of credits that dictate how much data a transmitter can send to its receivers.

The header file defines both public and private APIs. The public APIs include functions for creating, configuring, and managing flow control objects, such as [`fd_fctl_new`](#fd_fctl_new), [`fd_fctl_cfg_rx_add`](#fd_fctl_cfg_rx_add), and [`fd_fctl_cfg_done`](#fd_fctl_cfg_done). These functions allow users to set up flow control parameters, add receivers, and finalize configurations. The file also provides accessor functions to retrieve configuration details and manage credits dynamically during runtime. The private APIs, which are not intended for direct use by applications, facilitate inlining of flow control operations for performance-critical loops. The file emphasizes the importance of minimizing the use of flow control to avoid backpressure, suggesting that the system should be designed to operate efficiently with minimal reliance on these mechanisms. Overall, this header file is a crucial component for developers looking to implement efficient flow control in distributed systems, providing a structured approach to managing data flow with low overhead.
# Imports and Dependencies

---
- `../fd_tango_base.h`


# Global Variables

---
### fd\_fctl\_new
- **Type**: `function pointer`
- **Description**: The `fd_fctl_new` function is a constructor API that initializes a memory region as a flow control (fctl) object. It takes a pointer to a shared memory region (`shmem`) and a maximum number of receivers (`rx_max`) as parameters. The function returns a pointer to the initialized memory region on success or NULL on failure.
- **Use**: This function is used to set up a flow control object in a specified memory region, preparing it for managing flow control for a specified number of receivers.


---
### fd\_fctl\_cfg\_rx\_add
- **Type**: `fd_fctl_t *`
- **Description**: The `fd_fctl_cfg_rx_add` function is a global function that adds flow control details for a receiver to a given flow control object (`fctl`). It is part of a credit-based flow control system designed to manage the flow of data between a transmitter and multiple receivers, ensuring that the transmitter does not overwhelm the receivers with data.
- **Use**: This function is used to configure a flow control object by adding a receiver's flow control parameters, such as the maximum credits (`cr_max`), sequence address (`seq_laddr`), and slow address (`slow_laddr`).


---
### fd\_fctl\_cfg\_done
- **Type**: `function pointer`
- **Description**: `fd_fctl_cfg_done` is a function that finalizes the configuration of a flow control object (`fd_fctl_t`). It takes parameters to set the credit burst size, maximum credits, resume threshold, and refill threshold for the flow control mechanism.
- **Use**: This function is used to complete the setup of a flow control object by specifying its credit management parameters, ensuring it is ready for use in managing data transmission.


# Data Structures

---
### fd\_fctl\_t
- **Type**: ``typedef struct fd_fctl_private fd_fctl_t;``
- **Members**:
    - `rx_max`: Maximum number of receivers for this flow control, ranging from 0 to FD_FCTL_RX_MAX_MAX.
    - `rx_cnt`: Current number of receivers for this flow control, ranging from 0 to rx_max.
    - `in_refill`: Indicates if the flow control is currently in a refilling state, with values 0 or 1.
    - `cr_burst`: Maximum number of credits a transmitter will use in a burst, ranging from 1 to LONG_MAX.
    - `cr_max`: Upper bound of the number of credits a transmitter can have, ranging from cr_burst to LONG_MAX.
    - `cr_resume`: Credit threshold for the flow control to stop trying to refill credits, ranging from cr_burst to cr_max.
    - `cr_refill`: Credit threshold for the flow control to start trying to refill its credits, ranging from 1 to cr_resume.
- **Description**: The `fd_fctl_t` is an opaque handle to a flow control object designed to manage flow control for a transmitter with zero or more reliable receivers, allowing backpressure. It is part of a system that provides ultra-flexible, low-overhead credit-based flow control, ideally used sparingly in large-scale distributed systems to avoid backpressure. The structure is defined as a typedef of `fd_fctl_private`, which contains fields for managing the maximum and current number of receivers, the state of credit refilling, and various credit thresholds for managing flow control operations. The design allows for dynamic and efficient management of flow control, ensuring that transmitters and receivers can operate smoothly without unnecessary backpressure.


---
### fd\_fctl\_private\_rx
- **Type**: `struct`
- **Members**:
    - `cr_max`: Specifies the maximum number of credits for a receiver, should be positive.
    - `seq_laddr`: Pointer to the sequence location in the local address space, NULL indicates an inactive receiver.
    - `slow_laddr`: Pointer to the location where statistics for the slowest receiver are accumulated.
- **Description**: The `fd_fctl_private_rx` structure is part of a flow control system designed to manage credit-based flow control for receivers in a distributed system. It contains fields to manage the maximum credits a receiver can handle (`cr_max`), a pointer to the sequence address (`seq_laddr`) which indicates the receiver's current position in the sequence space, and a pointer to a location (`slow_laddr`) where the system accumulates statistics about the slowest receiver. This structure is used internally to facilitate efficient flow control operations, ensuring that the system can handle backpressure and maintain performance by tracking and managing receiver states.


---
### fd\_fctl\_private\_rx\_t
- **Type**: `struct`
- **Members**:
    - `cr_max`: Maximum number of credits safe for the transmitter to burst to the receiver when fully caught up.
    - `seq_laddr`: Pointer to the location in the user's local address space for querying the receiver's current position in the sequence space.
    - `slow_laddr`: Pointer to the location in the user's local address space for accumulating statistics on the slowest receiver.
- **Description**: The `fd_fctl_private_rx_t` structure is a private data structure used within the flow control system to manage individual receiver details. It holds information about the maximum credits a receiver can handle (`cr_max`), a pointer to the sequence address (`seq_laddr`) which indicates the receiver's current position in the sequence space, and a pointer to the slow address (`slow_laddr`) used for tracking which receiver is the slowest. This structure is part of a larger flow control mechanism designed to manage backpressure in distributed systems.


---
### fd\_fctl\_private
- **Type**: `struct`
- **Members**:
    - `rx_max`: Maximum number of receivers for this flow control, ranging from 0 to FD_FCTL_RX_MAX_MAX.
    - `rx_cnt`: Current number of receivers for this flow control, ranging from 0 to rx_max.
    - `in_refill`: Indicates if the flow control is currently in a refilling state, with values 0 or 1.
    - `cr_burst`: Maximum number of credits a transmitter will use in a burst, ranging from 1 to LONG_MAX.
    - `cr_max`: Upper bound of the number of credits a transmitter can have, ranging from cr_burst to LONG_MAX.
    - `cr_resume`: Credit threshold for the flow control to stop refilling credits, ranging from cr_burst to cr_max.
    - `cr_refill`: Credit threshold for the flow control to start refilling credits, ranging from 1 to cr_resume.
- **Description**: The `fd_fctl_private` structure is a part of a credit-based flow control system designed to manage the flow of data between a transmitter and multiple receivers. It maintains the state of the flow control, including the maximum and current number of receivers, and various credit thresholds that dictate when the system should refill or resume credits. The structure is designed to handle backpressure in distributed systems, ensuring that the transmitter does not overwhelm the receivers by sending more data than they can handle. The structure also includes an array of `fd_fctl_private_rx_t` elements, which represent individual receivers and are used to track their state and performance.


# Functions

---
### fd\_fctl\_private\_rx<!-- {{#callable:fd_fctl_private_rx}} -->
The `fd_fctl_private_rx` function returns a pointer to the first element of the receiver array associated with a given flow control object.
- **Inputs**:
    - `fctl`: A pointer to an `fd_fctl_t` structure, representing a flow control object.
- **Control Flow**:
    - The function takes a pointer to an `fd_fctl_t` structure as input.
    - It calculates the address of the first element of the receiver array by incrementing the `fctl` pointer by one unit of `fd_fctl_t`.
    - The function casts this calculated address to a pointer of type `fd_fctl_private_rx_t` and returns it.
- **Output**: A pointer to the first element of the `fd_fctl_private_rx_t` array associated with the given `fd_fctl_t` object.


---
### fd\_fctl\_private\_rx\_const<!-- {{#callable:fd_fctl_private_rx_const}} -->
The `fd_fctl_private_rx_const` function returns a constant pointer to the first element of the receiver array associated with a given flow control object.
- **Inputs**:
    - `fctl`: A constant pointer to an `fd_fctl_t` structure, representing the flow control object.
- **Control Flow**:
    - The function takes a constant pointer to an `fd_fctl_t` structure as input.
    - It calculates the address of the first element of the receiver array by incrementing the `fctl` pointer by one unit of `fd_fctl_t`.
    - The function casts the resulting address to a constant pointer of type `fd_fctl_private_rx_t` and returns it.
- **Output**: A constant pointer to the first element of the `fd_fctl_private_rx_t` array associated with the given `fd_fctl_t` object.


---
### fd\_fctl\_footprint<!-- {{#callable:fd_fctl_footprint}} -->
The `fd_fctl_footprint` function calculates the memory footprint required for a flow control object based on the maximum number of receivers, returning zero if the input exceeds the maximum allowable receivers.
- **Inputs**:
    - `rx_max`: The maximum number of receivers for which the flow control object is to be configured, expected to be within the range [0, FD_FCTL_RX_MAX_MAX].
- **Control Flow**:
    - Check if `rx_max` is greater than `FD_FCTL_RX_MAX_MAX` using `FD_UNLIKELY`; if true, return 0UL.
    - If `rx_max` is within the valid range, calculate and return the footprint using the macro `FD_FCTL_FOOTPRINT(rx_max)`.
- **Output**: The function returns an unsigned long integer representing the memory footprint required for the flow control object, or 0 if `rx_max` is invalid.


---
### fd\_fctl\_join<!-- {{#callable:fd_fctl_join}} -->
The `fd_fctl_join` function casts a given memory address to a pointer of type `fd_fctl_t` and returns it.
- **Inputs**:
    - `shfctl`: A pointer to a memory region that holds the state of a flow control object (`fctl`).
- **Control Flow**:
    - The function takes a single input parameter `shfctl`, which is a pointer to a memory region.
    - It casts this pointer to a `fd_fctl_t` type pointer.
    - The function then returns the casted pointer.
- **Output**: A pointer of type `fd_fctl_t` that represents the flow control object in the local address space.


---
### fd\_fctl\_leave<!-- {{#callable:fd_fctl_leave}} -->
The `fd_fctl_leave` function returns a pointer to the memory region holding the state of a flow control object, effectively leaving the current flow control join.
- **Inputs**:
    - `fctl`: A pointer to an `fd_fctl_t` structure representing the flow control object to leave.
- **Control Flow**:
    - The function takes a pointer to an `fd_fctl_t` structure as input.
    - It casts the input pointer to a `void *` type.
    - The function returns the casted pointer, which points to the memory region holding the state of the flow control object.
- **Output**: A `void *` pointer to the memory region holding the state of the flow control object.


---
### fd\_fctl\_delete<!-- {{#callable:fd_fctl_delete}} -->
The `fd_fctl_delete` function returns the memory region used for flow control to the caller by simply returning the input pointer.
- **Inputs**:
    - `shfctl`: A pointer to the memory region currently used to hold the state of a flow control object.
- **Control Flow**:
    - The function takes a single input parameter, `shfctl`, which is a pointer to a memory region.
    - It returns the same pointer `shfctl` without any modification or additional operations.
- **Output**: A pointer to the memory region that was used for flow control, which is the same as the input `shfctl`.


---
### fd\_fctl\_rx\_max<!-- {{#callable:fd_fctl_rx_max}} -->
The `fd_fctl_rx_max` function retrieves the maximum number of receivers that a flow control object (`fd_fctl_t`) can accommodate.
- **Inputs**:
    - `fctl`: A pointer to a constant `fd_fctl_t` structure, representing the flow control object from which the maximum number of receivers is to be retrieved.
- **Control Flow**:
    - The function is defined as a static inline function, which suggests it is intended for use within the same translation unit and optimized for performance.
    - The function is marked with `FD_FN_PURE`, indicating it has no side effects and its return value depends only on its parameters.
    - The function accesses the `rx_max` field of the `fd_fctl_t` structure pointed to by `fctl`.
    - It casts the `rx_max` value to an `ulong` type and returns it.
- **Output**: The function returns an `ulong` representing the maximum number of receivers (`rx_max`) that the flow control object can handle.


---
### fd\_fctl\_rx\_cnt<!-- {{#callable:fd_fctl_rx_cnt}} -->
The `fd_fctl_rx_cnt` function retrieves the current number of receivers for a given flow control object.
- **Inputs**:
    - `fctl`: A pointer to a constant `fd_fctl_t` structure representing the flow control object.
- **Control Flow**:
    - The function is defined as a static inline function, which suggests it is intended for use within the same translation unit and optimized for performance.
    - It directly accesses the `rx_cnt` member of the `fd_fctl_t` structure pointed to by `fctl`.
    - The function casts the `rx_cnt` value to an `ulong` type before returning it.
- **Output**: The function returns the current number of receivers (`rx_cnt`) as an unsigned long integer (`ulong`).


---
### fd\_fctl\_cr\_burst<!-- {{#callable:fd_fctl_cr_burst}} -->
The `fd_fctl_cr_burst` function retrieves the `cr_burst` value from a given flow control object.
- **Inputs**:
    - `fctl`: A pointer to a constant `fd_fctl_t` structure representing the flow control object from which the `cr_burst` value is to be retrieved.
- **Control Flow**:
    - The function is defined as a static inline function, which suggests it is intended for use within the same translation unit and allows for potential inlining by the compiler.
    - The function directly accesses the `cr_burst` member of the `fd_fctl_t` structure pointed to by `fctl`.
    - It returns the value of `cr_burst` without any additional computation or checks.
- **Output**: The function returns an `ulong` representing the `cr_burst` value of the specified flow control object.


---
### fd\_fctl\_cr\_max<!-- {{#callable:fd_fctl_cr_max}} -->
The `fd_fctl_cr_max` function retrieves the maximum number of credits a transmitter can have from a flow control object.
- **Inputs**:
    - `fctl`: A pointer to a constant `fd_fctl_t` structure, representing the flow control object from which the maximum credit value is to be retrieved.
- **Control Flow**:
    - The function is defined as a static inline function, which suggests it is intended for use within the same translation unit and optimized for performance.
    - It directly accesses the `cr_max` field of the `fd_fctl_t` structure pointed to by `fctl` and returns its value.
- **Output**: The function returns an `ulong` value representing the maximum number of credits (`cr_max`) configured for the flow control object.


---
### fd\_fctl\_cr\_resume<!-- {{#callable:fd_fctl_cr_resume}} -->
The `fd_fctl_cr_resume` function retrieves the credit resume threshold from a flow control object.
- **Inputs**:
    - `fctl`: A pointer to a constant `fd_fctl_t` structure representing the flow control object.
- **Control Flow**:
    - The function is defined as a static inline function, which suggests it is intended for frequent use and should be inlined by the compiler for performance reasons.
    - It directly accesses the `cr_resume` member of the `fd_fctl_t` structure pointed to by `fctl`.
    - The function returns the value of `cr_resume` without any additional computation or logic.
- **Output**: The function returns an `ulong` representing the credit resume threshold of the flow control object.


---
### fd\_fctl\_cr\_refill<!-- {{#callable:fd_fctl_cr_refill}} -->
The `fd_fctl_cr_refill` function retrieves the credit refill threshold from a flow control object.
- **Inputs**:
    - `fctl`: A pointer to a constant `fd_fctl_t` structure, representing the flow control object from which the credit refill threshold is to be retrieved.
- **Control Flow**:
    - The function accesses the `cr_refill` member of the `fd_fctl_t` structure pointed to by `fctl`.
    - It returns the value of `cr_refill`.
- **Output**: The function returns an `ulong` representing the credit refill threshold of the flow control object.


---
### fd\_fctl\_rx\_cr\_max<!-- {{#callable:fd_fctl_rx_cr_max}} -->
The `fd_fctl_rx_cr_max` function retrieves the maximum credit value for a specific receiver in a flow control system.
- **Inputs**:
    - `fctl`: A pointer to a constant `fd_fctl_t` structure representing the flow control object.
    - `rx_idx`: An unsigned long integer representing the index of the receiver for which the maximum credit is being queried.
- **Control Flow**:
    - The function calls [`fd_fctl_private_rx_const`](#fd_fctl_private_rx_const) with the `fctl` pointer to get a constant pointer to the array of `fd_fctl_private_rx_t` structures.
    - It accesses the `cr_max` field of the `fd_fctl_private_rx_t` structure at the specified `rx_idx` in the array.
    - The value of `cr_max` is cast to an unsigned long and returned.
- **Output**: The function returns an unsigned long integer representing the maximum credit value (`cr_max`) for the specified receiver index.
- **Functions called**:
    - [`fd_fctl_private_rx_const`](#fd_fctl_private_rx_const)


---
### fd\_fctl\_rx\_seq\_laddr<!-- {{#callable:fd_fctl_rx_seq_laddr}} -->
The `fd_fctl_rx_seq_laddr` function retrieves the sequence address pointer for a specific receiver index from a flow control object.
- **Inputs**:
    - `fctl`: A constant pointer to an `fd_fctl_t` structure, representing the flow control object.
    - `rx_idx`: An unsigned long integer representing the index of the receiver for which the sequence address is being retrieved.
- **Control Flow**:
    - The function calls [`fd_fctl_private_rx_const`](#fd_fctl_private_rx_const) with the `fctl` argument to get a constant pointer to the array of `fd_fctl_private_rx_t` structures.
    - It accesses the `seq_laddr` field of the `fd_fctl_private_rx_t` structure at the specified `rx_idx` in the array.
    - The function returns the value of the `seq_laddr` field, which is a pointer to an unsigned long integer.
- **Output**: A constant pointer to an unsigned long integer, representing the sequence address of the specified receiver.
- **Functions called**:
    - [`fd_fctl_private_rx_const`](#fd_fctl_private_rx_const)


---
### fd\_fctl\_rx\_slow\_laddr<!-- {{#callable:fd_fctl_rx_slow_laddr}} -->
The `fd_fctl_rx_slow_laddr` function retrieves the address of the slowest receiver's statistics for a given receiver index from a flow control object.
- **Inputs**:
    - `fctl`: A pointer to an `fd_fctl_t` structure, which represents the flow control object.
    - `rx_idx`: An unsigned long integer representing the index of the receiver for which the slow address is being queried.
- **Control Flow**:
    - The function calls [`fd_fctl_private_rx`](#fd_fctl_private_rx) with the `fctl` pointer to obtain the array of private receiver structures.
    - It accesses the `slow_laddr` field of the receiver at the specified `rx_idx` in the array.
    - The function returns the `slow_laddr` pointer for the specified receiver index.
- **Output**: A pointer to an unsigned long integer, representing the address where statistics for the slowest receiver are accumulated.
- **Functions called**:
    - [`fd_fctl_private_rx`](#fd_fctl_private_rx)


---
### fd\_fctl\_rx\_slow\_laddr\_const<!-- {{#callable:fd_fctl_rx_slow_laddr_const}} -->
The `fd_fctl_rx_slow_laddr_const` function retrieves a constant pointer to the slow address of a specified receiver in a flow control structure.
- **Inputs**:
    - `fctl`: A constant pointer to an `fd_fctl_t` structure, representing the flow control object.
    - `rx_idx`: An unsigned long integer representing the index of the receiver whose slow address is to be retrieved.
- **Control Flow**:
    - The function calls [`fd_fctl_private_rx_const`](#fd_fctl_private_rx_const) with the `fctl` argument to get a constant pointer to the array of private receiver structures.
    - It accesses the `slow_laddr` field of the receiver at the specified `rx_idx` in the array and returns it.
- **Output**: A constant pointer to an unsigned long integer, representing the slow address of the specified receiver.
- **Functions called**:
    - [`fd_fctl_private_rx_const`](#fd_fctl_private_rx_const)


---
### fd\_fctl\_rx\_cr\_return<!-- {{#callable:fd_fctl_rx_cr_return}} -->
The `fd_fctl_rx_cr_return` function updates the receiver's sequence position in a flow control system, ensuring memory consistency with compiler memory fences.
- **Inputs**:
    - `_rx_seq`: A pointer to an unsigned long integer representing the receiver's sequence position in the flow control system.
    - `rx_seq`: An unsigned long integer representing the new sequence position of the receiver.
- **Control Flow**:
    - A compiler memory fence is executed to ensure memory operations are completed before proceeding.
    - The value pointed to by `_rx_seq` is updated to `rx_seq` using a volatile store to prevent compiler optimizations that could reorder operations.
    - Another compiler memory fence is executed to ensure the update is visible to other threads immediately.
- **Output**: This function does not return a value; it updates the sequence position in memory and ensures memory consistency.


---
### fd\_fctl\_cr\_query<!-- {{#callable:fd_fctl_cr_query}} -->
The `fd_fctl_cr_query` function calculates the minimum number of credits available to a transmitter without overrunning any receiver and identifies the slowest receiver that constrains this credit availability.
- **Inputs**:
    - `fctl`: A constant pointer to an `fd_fctl_t` structure representing the flow control object.
    - `tx_seq`: An unsigned long integer representing the current sequence number of the transmitter.
    - `_rx_idx_slow`: A pointer to an unsigned long where the index of the slowest receiver will be stored.
- **Control Flow**:
    - Initialize `rx` to point to the array of receivers and `rx_cnt` to the number of receivers.
    - Set `cr_query` to the maximum credits available (`cr_max`) and `rx_idx_slow` to `ULONG_MAX`.
    - Iterate over each receiver index from 0 to `rx_cnt-1`.
    - For each receiver, check if the receiver is active by verifying if `seq_laddr` is not NULL.
    - Calculate `rx_seq` as the current sequence number of the receiver using `FD_VOLATILE_CONST`.
    - Compute `rx_cr_query` as the maximum of zero and the difference between the receiver's `cr_max` and the difference between `tx_seq` and `rx_seq`.
    - Update `rx_idx_slow` to the current index if `rx_cr_query` is less than `cr_query`.
    - Update `cr_query` to the minimum of `rx_cr_query` and the current `cr_query`.
    - Store the slowest receiver index in `_rx_idx_slow`.
- **Output**: Returns the minimum number of credits available (`cr_query`) as an unsigned long integer.
- **Functions called**:
    - [`fd_fctl_private_rx_const`](#fd_fctl_private_rx_const)


---
### fd\_fctl\_tx\_cr\_update<!-- {{#callable:fd_fctl_tx_cr_update}} -->
The `fd_fctl_tx_cr_update` function updates the number of credits available to a transmitter based on its current credit availability and sequence position, managing the transition between normal and refilling states.
- **Inputs**:
    - `fctl`: A pointer to an `fd_fctl_t` structure representing the flow control object managing the transmitter's credits.
    - `cr_avail`: The current number of credits available to the transmitter.
    - `tx_seq`: The current sequence number position of the transmitter.
- **Control Flow**:
    - Check if the current credits available (`cr_avail`) are below the refill threshold (`fctl->cr_refill`) or if the transmitter is already in the refilling state (`fctl->in_refill`).
    - If either condition is true, query the receivers for available credits using [`fd_fctl_cr_query`](#fd_fctl_cr_query), which returns the number of credits that might be available and the index of the slowest receiver.
    - If the queried credits (`cr_query`) are greater than or equal to the resume threshold (`fctl->cr_resume`), update `cr_avail` to `cr_query` and set `fctl->in_refill` to 0, indicating the transmitter can resume normal operation.
    - If `cr_query` is less than `fctl->cr_resume` and the transmitter is not already in the refilling state, increment the slow counter for the slowest receiver (`rx_idx_slow`) and set `fctl->in_refill` to 1, indicating the transmitter is entering the refilling state.
    - If `cr_query` is less than `fctl->cr_resume` and the transmitter is already in the refilling state, do nothing.
- **Output**: The function returns the updated number of credits available (`cr_avail`) to the transmitter.
- **Functions called**:
    - [`fd_fctl_cr_query`](#fd_fctl_cr_query)
    - [`fd_fctl_private_rx`](#fd_fctl_private_rx)


# Function Declarations (Public API)

---
### fd\_fctl\_new<!-- {{#callable_declaration:fd_fctl_new}} -->
Initializes a memory region for flow control management.
- **Description**: This function initializes a given memory region to be used as a flow control object, which can manage flow control for a specified number of reliable consumers. It should be called when setting up flow control for a transmitter, ensuring that the memory region is properly aligned and has the necessary footprint. The function returns the initialized memory region on success, or NULL if the memory region is invalid or the number of receivers exceeds the maximum allowed. It is important to ensure that the memory region is non-NULL, correctly aligned, and that the number of receivers is within the valid range before calling this function.
- **Inputs**:
    - `shmem`: A pointer to the memory region to be initialized. Must not be NULL and must be aligned according to fd_fctl_align(). The caller retains ownership of this memory.
    - `rx_max`: The maximum number of receivers the flow control object can manage. Must be in the range [0, FD_FCTL_RX_MAX_MAX]. If this value is too large, the function will return NULL.
- **Output**: Returns a pointer to the initialized memory region on success, or NULL on failure.
- **See also**: [`fd_fctl_new`](fd_fctl.c.driver.md#fd_fctl_new)  (Implementation)


---
### fd\_fctl\_cfg\_rx\_add<!-- {{#callable_declaration:fd_fctl_cfg_rx_add}} -->
Adds a receiver's flow control configuration to a flow control object.
- **Description**: Use this function to add flow control details for a new receiver to an existing flow control object. This function should be called before the flow control configuration is completed. Each receiver is assigned an index sequentially as they are added, which can be used for diagnostics. The function requires valid parameters and will return NULL if any preconditions are not met, such as a NULL flow control object, a NULL slow_laddr, an invalid cr_max, or if the maximum number of receivers has been exceeded.
- **Inputs**:
    - `fctl`: A pointer to a flow control object. Must not be NULL. The caller retains ownership.
    - `cr_max`: The maximum number of credits safe for the transmitter to burst to the receiver. Must be in the range [1, LONG_MAX]. If outside this range, the function returns NULL.
    - `seq_laddr`: A pointer to the location in the user's address space where the receiver's sequence position can be queried. Can be NULL, indicating the receiver is inactive.
    - `slow_laddr`: A pointer to the location where statistics about the slowest receiver are accumulated. Must not be NULL. The caller retains ownership.
- **Output**: Returns a pointer to the flow control object on success, or NULL on failure.
- **See also**: [`fd_fctl_cfg_rx_add`](fd_fctl.c.driver.md#fd_fctl_cfg_rx_add)  (Implementation)


---
### fd\_fctl\_cfg\_done<!-- {{#callable_declaration:fd_fctl_cfg_done}} -->
Completes the configuration of a flow control object.
- **Description**: Use this function to finalize the configuration of a flow control object after adding all necessary receiver configurations. It sets the credit parameters for the flow control, ensuring they are within valid ranges. This function should be called only once all receivers have been added and before the flow control object is used for managing credits. If any parameter is set to zero, a reasonable default will be chosen. The function returns the configured flow control object on success or NULL if any parameter is invalid or if the flow control object is NULL.
- **Inputs**:
    - `fctl`: A pointer to the flow control object to be configured. Must not be NULL. The caller retains ownership.
    - `cr_burst`: The maximum number of credits a transmitter will use in a burst. Must be in the range [1, cr_burst_max], where cr_burst_max is the minimum of the maximum credits of all receivers.
    - `cr_max`: An upper bound on the number of credits a transmitter can have. Must be in the range [cr_burst, LONG_MAX]. If set to 0, a default value will be chosen.
    - `cr_resume`: The credit threshold for stopping credit refills. Must be in the range [cr_burst, cr_max]. If set to 0, a default value will be chosen.
    - `cr_refill`: The credit threshold for starting credit refills. Must be in the range [cr_burst, cr_resume]. If set to 0, a default value will be chosen.
- **Output**: Returns the configured flow control object on success, or NULL if any parameter is invalid or if the flow control object is NULL.
- **See also**: [`fd_fctl_cfg_done`](fd_fctl.c.driver.md#fd_fctl_cfg_done)  (Implementation)



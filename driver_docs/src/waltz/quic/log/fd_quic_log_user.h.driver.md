# Purpose
The provided C header file, `fd_quic_log_user.h`, defines an Application Binary Interface (ABI) for extracting high-frequency logs from an `fd_quic` instance. This file is part of a logging system designed to facilitate the consumption of log data by providing structures and functions that allow a consumer to join and interact with a `quic_log` interface. The header file does not include APIs for writing logs, which are instead found in a separate internal header file, `fd_quic_log_internal.h`. The primary focus of this file is to define the necessary components and functions for reading and managing log data, such as joining a log as a consumer, accessing log data, and ensuring safe reads.

Key technical components include the `fd_quic_log_rx` structure, which holds parameters for a consumer-side join to a `quic_log` interface, and several macros and functions that manage the alignment, memory layout, and data access within the logging system. The file defines constants like `FD_QUIC_LOG_ALIGN` and `FD_QUIC_LOG_MAGIC` to ensure proper memory alignment and to signal the layout of the shared memory region. Functions such as `fd_quic_log_rx_join`, [`fd_quic_log_rx_leave`](#fd_quic_log_rx_leave), and [`fd_quic_log_rx_data_const`](#fd_quic_log_rx_data_const) provide mechanisms for joining a log, leaving a log, and accessing log data, respectively. The file also includes inline functions for checking the safety of log reads and extracting event IDs from log metadata. Overall, this header file is a crucial component for consumers of the `fd_quic` logging system, providing the necessary interface to access and manage log data efficiently.
# Imports and Dependencies

---
- `fd_quic_log.h`
- `../../../tango/mcache/fd_mcache.h`


# Global Variables

---
### fd\_quic\_log\_rx\_leave
- **Type**: `function pointer`
- **Description**: The `fd_quic_log_rx_leave` is a function that facilitates the disconnection of a consumer from a QUIC log interface. It takes a pointer to an `fd_quic_log_rx_t` structure, which contains the parameters of the consumer-side join to the QUIC log, and returns a void pointer.
- **Use**: This function is used to leave or disconnect from a local consumer-side join to a QUIC log.


# Data Structures

---
### fd\_quic\_log\_rx
- **Type**: `struct`
- **Members**:
    - `mcache`: A pointer to a constant fd_frag_meta_t structure, representing the metadata cache.
    - `mcache_seq`: A pointer to a constant unsigned long, representing the sequence number of the metadata cache.
    - `base`: A void pointer to the base address of the data buffer.
    - `data_lo_laddr`: An unsigned long representing the lower bound of the data's local address range.
    - `data_hi_laddr`: An unsigned long representing the upper bound of the data's local address range.
    - `seq`: An unsigned long representing the current sequence number.
    - `depth`: An unsigned long representing the depth of the metadata cache.
- **Description**: The `fd_quic_log_rx` structure is designed to facilitate the consumer-side interaction with a QUIC log interface, providing necessary parameters for accessing and managing log data. It includes pointers to metadata and sequence information, as well as address range boundaries and sequence tracking, enabling efficient log data retrieval and management in a high-frequency logging environment.


---
### fd\_quic\_log\_rx\_t
- **Type**: `struct`
- **Members**:
    - `mcache`: A pointer to a constant fd_frag_meta_t structure, representing the metadata cache.
    - `mcache_seq`: A pointer to a constant unsigned long, representing the sequence number of the metadata cache.
    - `base`: A pointer to a void type, representing the base address for data access.
    - `data_lo_laddr`: An unsigned long representing the lower bound of the data address range.
    - `data_hi_laddr`: An unsigned long representing the upper bound of the data address range.
    - `seq`: An unsigned long representing the current sequence number.
    - `depth`: An unsigned long representing the depth of the metadata cache.
- **Description**: The `fd_quic_log_rx_t` structure is designed to manage the parameters necessary for a consumer-side join to a QUIC log interface. It includes pointers to metadata and sequence information, as well as address boundaries and sequence tracking for efficient log data retrieval. This structure is crucial for handling high-frequency log extraction from an fd_quic instance, ensuring that the consumer can accurately and safely access log data within defined memory boundaries.


# Functions

---
### fd\_quic\_log\_rx\_data\_const<!-- {{#callable:fd_quic_log_rx_data_const}} -->
The `fd_quic_log_rx_data_const` function returns a constant pointer to a data record in a QUIC log based on a given chunk index.
- **Inputs**:
    - `rx`: A constant pointer to an `fd_quic_log_rx_t` structure, which contains parameters for a consumer-side join to a QUIC log interface.
    - `chunk`: An unsigned long integer representing the index of the data chunk to be accessed.
- **Control Flow**:
    - The function calls `fd_chunk_to_laddr_const` with `rx->base` and `chunk` as arguments.
    - It returns the result of the `fd_chunk_to_laddr_const` function call, which is a constant pointer to the data record.
- **Output**: A constant pointer to the data record corresponding to the specified chunk index.


---
### fd\_quic\_log\_rx\_is\_safe<!-- {{#callable:fd_quic_log_rx_is_safe}} -->
The `fd_quic_log_rx_is_safe` function checks if a log message read is within the bounds of a specified memory range.
- **Inputs**:
    - `rx`: A pointer to a `fd_quic_log_rx_t` structure containing parameters of a consumer-side join to a quic_log interface.
    - `chunk`: An unsigned long integer representing the chunk value, which is used to calculate the starting address of the log message.
    - `sz`: An unsigned long integer representing the size of the log message to be checked.
- **Control Flow**:
    - Calculate the starting address of the log message (`msg_lo`) using `fd_chunk_to_laddr_const` with `rx->base` and `chunk`.
    - Calculate the ending address of the log message (`msg_hi`) by adding `sz` to `msg_lo`.
    - Retrieve the minimum (`msg_min`) and maximum (`msg_max`) valid addresses from `rx->data_lo_laddr` and `rx->data_hi_laddr`, respectively.
    - Check if `msg_lo` is greater than or equal to `msg_min`, `msg_hi` is less than or equal to `msg_max`, and `msg_lo` is less than or equal to `msg_hi`.
    - Return 1 if all conditions are met, indicating the log message is within bounds; otherwise, return 0.
- **Output**: Returns an integer: 1 if the log message is within the specified bounds, otherwise 0.


---
### fd\_quic\_log\_sig\_event<!-- {{#callable:fd_quic_log_sig_event}} -->
The `fd_quic_log_sig_event` function extracts the lower 16 bits of a given signal value, returning it as an unsigned integer.
- **Inputs**:
    - `sig`: An unsigned long integer representing a signal from which the event ID is to be extracted.
- **Control Flow**:
    - The function takes a single input parameter, `sig`, which is an unsigned long integer.
    - It performs a bitwise AND operation between `sig` and `USHORT_MAX` (which is a constant representing the maximum value of an unsigned short, typically 65535).
    - The result of the bitwise operation is cast to an unsigned integer and returned.
- **Output**: The function returns an unsigned integer representing the lower 16 bits of the input signal `sig`.


---
### fd\_quic\_log\_rx\_tail<!-- {{#callable:fd_quic_log_rx_tail}} -->
The `fd_quic_log_rx_tail` function retrieves a pointer to the metadata of a specific log record from the end of a sequence in a QUIC log.
- **Inputs**:
    - `rx`: A pointer to a `fd_quic_log_rx_t` structure, which contains parameters for accessing the QUIC log metadata.
    - `idx`: An unsigned long integer representing the index from the end of the sequence to retrieve the log record.
- **Control Flow**:
    - Calculate the sequence number by querying the current sequence from `rx->mcache_seq`, subtracting 1, and then subtracting `idx`.
    - Compute the line index using `fd_mcache_line_idx` with the calculated sequence number and the depth of the cache.
    - Return a pointer to the metadata at the computed line index in the `rx->mcache`.
- **Output**: A pointer to a `fd_frag_meta_t` structure representing the metadata of the specified log record.


# Function Declarations (Public API)

---
### fd\_quic\_log\_rx\_leave<!-- {{#callable_declaration:fd_quic_log_rx_leave}} -->
Leaves a local consumer-side join to a quic_log.
- **Description**: This function is used to leave a consumer-side join to a quic_log, effectively resetting the log structure. It should be called when the consumer no longer needs to access the quic_log, ensuring that the log structure is cleared and ready for reuse or deallocation. The function must be called with a valid pointer to an fd_quic_log_rx_t structure that represents an active join. If the provided pointer is NULL, the function logs a warning and returns NULL.
- **Inputs**:
    - `log`: A pointer to an fd_quic_log_rx_t structure representing the consumer-side join to a quic_log. Must not be NULL. If NULL, the function logs a warning and returns NULL.
- **Output**: Returns the pointer to the fd_quic_log_rx_t structure if successful, or NULL if the input was NULL.
- **See also**: [`fd_quic_log_rx_leave`](fd_quic_log.c.driver.md#fd_quic_log_rx_leave)  (Implementation)



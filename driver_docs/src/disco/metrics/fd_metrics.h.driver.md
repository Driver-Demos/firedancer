# Purpose
The provided C header file, `fd_metrics.h`, is designed to facilitate the management and manipulation of performance metrics in a shared memory environment. It primarily focuses on defining a layout for metrics that allows both producers and consumers to efficiently read and write data with minimal overhead. The file includes macros and inline functions that enable the registration, updating, and retrieval of various types of metrics, such as counters, gauges, and histograms, all stored as `ulong` values. The metrics are organized in a way that minimizes cache traffic and allows for quick snapshots, which is crucial for performance monitoring in high-frequency environments.

The header file defines a set of macros for setting and getting metric values, as well as for copying histogram data. It also provides functions for converting time measurements between seconds and ticks, which are essential for maintaining consistent time-based metrics across different components. The file includes mechanisms for initializing and formatting memory regions to be used as metrics storage, ensuring that all metrics are zero-initialized and properly aligned. By abstracting the complexity of shared memory management and providing a straightforward API for metric operations, this file serves as a critical component for applications that require precise and efficient performance monitoring.
# Imports and Dependencies

---
- `fd_metrics_base.h`
- `generated/fd_metrics_all.h`
- `../../tango/tempo/fd_tempo.h`
- `../../util/hist/fd_histf.h`


# Global Variables

---
### fd\_metrics\_base\_tl
- **Type**: `FD_TL ulong *`
- **Description**: `fd_metrics_base_tl` is a thread-local pointer to an unsigned long integer, representing the base address of the metrics region in shared memory. This pointer is used to access the start of the layout for tile-specific metrics, which are defined as offsets from this base pointer.
- **Use**: This variable is used to set the base address for metrics in shared memory, allowing macros to compute offsets for specific metrics efficiently.


---
### fd\_metrics\_tl
- **Type**: `FD_TL volatile ulong *`
- **Description**: `fd_metrics_tl` is a thread-local pointer to a volatile unsigned long integer, representing the start of the tile-specific metrics area in shared memory. This pointer is used to access and update metrics specific to a tile, which are laid out sequentially in memory.
- **Use**: This variable is used by macros to perform operations on tile-specific metrics, such as setting, getting, and incrementing metric values.


# Functions

---
### fd\_metrics\_tile<!-- {{#callable:fd_metrics_tile}} -->
The `fd_metrics_tile` function calculates and returns a pointer to the start of the tile-specific metrics area within a given metrics object.
- **Inputs**:
    - `metrics`: A pointer to an array of unsigned long integers representing the metrics object, where the first two elements specify the number of in-links and out-links, respectively.
- **Control Flow**:
    - The function calculates the offset to the tile-specific metrics area by adding 2 to the base pointer, which skips the first two elements that store the in-link and out-link counts.
    - It then adds the product of `FD_METRICS_ALL_LINK_IN_TOTAL` and the first element of the metrics array (in-link count) to account for the in-link metrics.
    - Finally, it adds the product of `FD_METRICS_ALL_LINK_OUT_TOTAL` and the second element of the metrics array (out-link count) to account for the out-link metrics.
    - The resulting pointer is returned, pointing to the start of the tile-specific metrics area.
- **Output**: A pointer to the start of the tile-specific metrics area within the metrics object, represented as a volatile unsigned long integer pointer.


---
### fd\_metrics\_link\_in<!-- {{#callable:fd_metrics_link_in}} -->
The `fd_metrics_link_in` function returns a pointer to the in-link metrics area for a specified in-link index within a metrics object.
- **Inputs**:
    - `metrics`: A pointer to an array of unsigned long integers representing the metrics object.
    - `in_idx`: An unsigned long integer representing the index of the in-link for which the metrics area is being accessed.
- **Control Flow**:
    - The function calculates the offset by adding 2 to the base metrics pointer and then adding the product of `FD_METRICS_ALL_LINK_IN_TOTAL` and `in_idx`.
    - It returns a pointer to the calculated offset within the metrics array.
- **Output**: A pointer to the in-link metrics area for the specified in-link index.


---
### fd\_metrics\_link\_out<!-- {{#callable:fd_metrics_link_out}} -->
The `fd_metrics_link_out` function calculates and returns a pointer to the out-link metrics area for a given out-link index within a metrics object.
- **Inputs**:
    - `metrics`: A pointer to an array of unsigned long integers representing the metrics object.
    - `out_idx`: An unsigned long integer representing the index of the out-link for which the metrics pointer is needed.
- **Control Flow**:
    - The function calculates the offset by adding 2 to the base metrics pointer, which skips the first two elements that store the in-link and out-link counts.
    - It then adds the product of `FD_METRICS_ALL_LINK_IN_TOTAL` and the first element of the metrics array (in-link count) to account for the in-link metrics.
    - Finally, it adds the product of `FD_METRICS_ALL_LINK_OUT_TOTAL` and `out_idx` to reach the specific out-link metrics area.
- **Output**: A pointer to the specific out-link metrics area within the metrics object, represented as a volatile unsigned long integer pointer.


---
### fd\_metrics\_new<!-- {{#callable:fd_metrics_new}} -->
The `fd_metrics_new` function initializes a shared memory region for metrics storage, setting up the in-link and out-link consumer counts.
- **Inputs**:
    - `shmem`: A pointer to the shared memory region to be initialized for metrics storage.
    - `in_link_cnt`: The number of input links to be recorded in the metrics.
    - `out_link_consumer_cnt`: The number of output link consumers to be recorded in the metrics.
- **Control Flow**:
    - The function begins by zeroing out the memory region pointed to by `shmem` using `fd_memset`, with the size determined by `FD_METRICS_FOOTPRINT` based on `in_link_cnt` and `out_link_consumer_cnt`.
    - A pointer `metrics` is assigned to the `shmem` address.
    - The first element of `metrics` is set to `in_link_cnt`, and the second element is set to `out_link_consumer_cnt`.
    - The function returns the `shmem` pointer, now initialized for metrics storage.
- **Output**: The function returns the `shmem` pointer, which now points to an initialized metrics storage region.


---
### fd\_metrics\_register<!-- {{#callable:fd_metrics_register}} -->
The `fd_metrics_register` function sets thread-local pointers to a given metrics object for use in metrics operations.
- **Inputs**:
    - `metrics`: A pointer to an array of unsigned long integers representing the metrics object to be registered.
- **Control Flow**:
    - Check if the `metrics` pointer is NULL using `FD_UNLIKELY`; if it is, log an error and terminate the program using `FD_LOG_ERR`.
    - Assign the `metrics` pointer to the thread-local variable `fd_metrics_base_tl`.
    - Calculate the tile-specific metrics pointer using `fd_metrics_tile(metrics)` and assign it to the thread-local variable `fd_metrics_tl`.
    - Return the `metrics` pointer.
- **Output**: Returns the same `metrics` pointer that was passed as an argument.
- **Functions called**:
    - [`fd_metrics_tile`](#fd_metrics_tile)


---
### fd\_metrics\_convert\_seconds\_to\_ticks<!-- {{#callable:fd_metrics_convert_seconds_to_ticks}} -->
The function `fd_metrics_convert_seconds_to_ticks` converts a time duration from seconds to ticks using a predefined tick rate per nanosecond.
- **Inputs**:
    - `seconds`: A double representing the time duration in seconds to be converted to ticks.
- **Control Flow**:
    - Retrieve the tick rate per nanosecond by calling `fd_tempo_tick_per_ns(NULL)`.
    - Multiply the input `seconds` by the tick rate and by 1e9 to convert seconds to ticks.
    - Cast the result to an unsigned long integer and return it.
- **Output**: The function returns an unsigned long integer representing the equivalent number of ticks for the given time duration in seconds.


---
### fd\_metrics\_convert\_ticks\_to\_seconds<!-- {{#callable:fd_metrics_convert_ticks_to_seconds}} -->
The function `fd_metrics_convert_ticks_to_seconds` converts a given number of ticks into seconds using a conversion factor derived from the system's tick rate per nanosecond.
- **Inputs**:
    - `ticks`: An unsigned long integer representing the number of ticks to be converted into seconds.
- **Control Flow**:
    - Retrieve the tick rate per nanosecond by calling `fd_tempo_tick_per_ns` with a NULL argument.
    - Calculate the number of seconds by dividing the input `ticks` by the product of the tick rate per nanosecond and 1e9 (to convert nanoseconds to seconds).
    - Return the calculated seconds as a double.
- **Output**: A double representing the equivalent time in seconds for the given number of ticks.


---
### fd\_metrics\_convert\_ticks\_to\_nanoseconds<!-- {{#callable:fd_metrics_convert_ticks_to_nanoseconds}} -->
The function `fd_metrics_convert_ticks_to_nanoseconds` converts a given number of ticks into nanoseconds using a conversion factor obtained from `fd_tempo_tick_per_ns`.
- **Inputs**:
    - `ticks`: The number of ticks to be converted into nanoseconds.
- **Control Flow**:
    - Retrieve the conversion factor from ticks to nanoseconds by calling `fd_tempo_tick_per_ns` with a NULL argument.
    - Convert the input `ticks` to a double and divide it by the conversion factor to get the equivalent time in nanoseconds.
    - Cast the result back to an unsigned long integer and return it.
- **Output**: The function returns the equivalent time in nanoseconds as an unsigned long integer.


---
### fd\_metrics\_join<!-- {{#callable:fd_metrics_join}} -->
The `fd_metrics_join` function casts a given memory pointer to a `ulong` pointer and returns it.
- **Inputs**:
    - `mem`: A pointer to a memory region that is expected to be formatted for metrics.
- **Control Flow**:
    - The function takes a single input parameter, `mem`, which is a pointer to a memory region.
    - It directly returns the input `mem` cast to a `ulong` pointer without any additional processing.
- **Output**: A `ulong` pointer that points to the same memory location as the input `mem`.


---
### fd\_metrics\_leave<!-- {{#callable:fd_metrics_leave}} -->
The `fd_metrics_leave` function returns the input memory pointer without modification.
- **Inputs**:
    - `mem`: A pointer to a memory region that is intended to be left or unjoined from the metrics system.
- **Control Flow**:
    - The function takes a single input parameter, `mem`, which is a pointer to a memory region.
    - It returns the same pointer `mem` without any modification or additional processing.
- **Output**: The function returns the same pointer that was passed as input, effectively performing a no-op on the memory region.


---
### fd\_metrics\_delete<!-- {{#callable:fd_metrics_delete}} -->
The `fd_metrics_delete` function returns the input memory pointer without modification.
- **Inputs**:
    - `mem`: A pointer to a memory region that is intended to be deleted or deallocated.
- **Control Flow**:
    - The function takes a single input parameter, `mem`, which is a pointer to a memory region.
    - It returns the same pointer `mem` without performing any operations on it.
- **Output**: The function returns the same pointer that was passed as input, effectively performing no operation on the memory.



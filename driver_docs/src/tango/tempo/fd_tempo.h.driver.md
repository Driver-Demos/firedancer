# Purpose
This C header file, `fd_tempo.h`, provides a collection of APIs for time measurement and interval management, specifically designed for high-performance computing environments. It includes functions to model and estimate the performance characteristics of wallclock and tickcount operations, such as [`fd_tempo_wallclock_model`](#fd_tempo_wallclock_model) and [`fd_tempo_tickcount_model`](#fd_tempo_tickcount_model), which help in understanding the cost and jitter associated with these operations. The file also offers utilities for synchronizing tick rates across processes ([`fd_tempo_set_tick_per_ns`](#fd_tempo_set_tick_per_ns)) and for observing synchronized time and tickcount pairs ([`fd_tempo_observe_pair`](#fd_tempo_observe_pair)). Additionally, it provides mechanisms for managing intervals between housekeeping events, such as [`fd_tempo_lazy_default`](#fd_tempo_lazy_default) for determining default laziness intervals and [`fd_tempo_async_min`](#fd_tempo_async_min) for calculating minimum intervals between asynchronous events. These functions are crucial for optimizing timing and synchronization in distributed systems, ensuring efficient and consistent performance across different threads and processes.
# Imports and Dependencies

---
- `../fd_tango_base.h`


# Functions

---
### fd\_tempo\_lazy\_default<!-- {{#callable:fd_tempo_lazy_default}} -->
The `fd_tempo_lazy_default` function calculates a default target interval in nanoseconds for housekeeping events based on the maximum credits available.
- **Inputs**:
    - `cr_max`: The maximum number of credits available, represented as an unsigned long integer.
- **Control Flow**:
    - The function checks if `cr_max` is greater than 954,437,176.
    - If `cr_max` is greater, it returns `INT_MAX` cast to a long integer.
    - If `cr_max` is not greater, it calculates the interval as `1 + ((9 * cr_max) >> 2)` and returns it as a long integer.
- **Output**: The function returns a long integer representing the target interval in nanoseconds for housekeeping events, constrained to be within [1, 2^31].


---
### fd\_tempo\_async\_reload<!-- {{#callable:fd_tempo_async_reload}} -->
The `fd_tempo_async_reload` function generates a random number within a specified range to randomize timing intervals for background tasks.
- **Inputs**:
    - `rng`: A pointer to an `fd_rng_t` structure, which is used to generate random numbers.
    - `async_min`: An unsigned long integer representing the minimum interval, which must be a power of two within the range [1, 2^31].
- **Control Flow**:
    - The function calls `fd_rng_uint` with the `rng` pointer to generate a random unsigned integer.
    - It performs a bitwise AND operation between the generated random number and `async_min-1UL` to ensure the result is within the range [0, async_min).
    - The function adds `async_min` to the result of the bitwise operation to shift the range to [async_min, 2*async_min).
    - The final result is returned as the output of the function.
- **Output**: The function returns an unsigned long integer that is a random number within the range [async_min, 2*async_min).


# Function Declarations (Public API)

---
### fd\_tempo\_wallclock\_model<!-- {{#callable_declaration:fd_tempo_wallclock_model}} -->
Returns an estimate of the minimum cost of fd_log_wallclock() in ticks.
- **Description**: This function provides an estimate of the minimum time cost, in ticks, for calling fd_log_wallclock(). It is useful for understanding the overhead and jitter associated with this function call. The first invocation in a thread group may be slow as it performs the necessary measurements, but subsequent calls will be fast and return the same parameters. The function ensures that the returned minimum cost is finite and positive, and if the optional parameter is provided, it also estimates the typical jitter. In cases where the function cannot be parameterized correctly on the first call, it logs a warning and uses a fallback parameterization.
- **Inputs**:
    - `opt_tau`: A pointer to a double where the function will store the estimated typical jitter of fd_log_wallclock() if it is not NULL. The caller retains ownership and must ensure it is a valid pointer if provided.
- **Output**: Returns a double representing the estimated minimum cost of fd_log_wallclock() in ticks, which is guaranteed to be finite and positive.
- **See also**: [`fd_tempo_wallclock_model`](fd_tempo.c.driver.md#fd_tempo_wallclock_model)  (Implementation)


---
### fd\_tempo\_tickcount\_model<!-- {{#callable_declaration:fd_tempo_tickcount_model}} -->
Estimates the minimum cost and typical jitter of fd_tickcount() in ticks.
- **Description**: This function provides an estimate of the minimum cost (t0) and typical jitter (tau) associated with the fd_tickcount() function, modeling it as a shifted exponential distribution. It should be called when you need to understand the performance characteristics of fd_tickcount() in terms of ticks. The first invocation in a thread group may be slow as it performs the necessary calculations, but subsequent calls will be fast and return the same parameters. If the function cannot determine a sane parameterization on the first call, it logs a warning and uses a fallback parameterization. The estimated t0 will always be finite and positive, while tau will be finite and non-negative.
- **Inputs**:
    - `opt_tau`: A pointer to a double where the function will store the estimated typical jitter (tau) if it is non-NULL. The caller retains ownership of this pointer, and it must be valid if provided. If NULL, the function will not provide the jitter estimate.
- **Output**: Returns the estimated minimum cost (t0) of fd_tickcount() in ticks, which is a finite and positive double.
- **See also**: [`fd_tempo_tickcount_model`](fd_tempo.c.driver.md#fd_tempo_tickcount_model)  (Implementation)


---
### fd\_tempo\_set\_tick\_per\_ns<!-- {{#callable_declaration:fd_tempo_set_tick_per_ns}} -->
Sets the tick per nanosecond values for synchronization.
- **Description**: Use this function to explicitly set the tick per nanosecond values, which will affect the return values of subsequent calls to `fd_tempo_tick_per_ns`. This function is primarily intended for synchronizing the tick_per_ns value across different processes. It should not be used arbitrarily, as it overrides the default behavior of `fd_tempo_tick_per_ns`.
- **Inputs**:
    - `_mu`: The mean tick per nanosecond value to be set. The caller is responsible for ensuring this value is appropriate for synchronization purposes.
    - `_sigma`: The standard deviation of the tick per nanosecond value to be set. The caller is responsible for ensuring this value is appropriate for synchronization purposes.
- **Output**: None
- **See also**: [`fd_tempo_set_tick_per_ns`](fd_tempo.c.driver.md#fd_tempo_set_tick_per_ns)  (Implementation)


---
### fd\_tempo\_observe\_pair<!-- {{#callable_declaration:fd_tempo_observe_pair}} -->
Observes wallclock and tickcount simultaneously and estimates jitter.
- **Description**: This function is used to obtain simultaneous observations of the wallclock and tickcount, estimating the tickcount at the time the wallclock was observed. It is useful for precision timing calibrations, providing a measure of the jitter in ticks. The function returns a non-negative jitter value, indicating the accuracy of the tickcount relative to the wallclock observation. If any anomalies are detected during the measurement, a warning is logged, and a best-effort result is returned. This function should be used when precise timing synchronization between wallclock and tickcount is required.
- **Inputs**:
    - `opt_now`: A pointer to a long where the observed wallclock value will be stored. Can be NULL if the wallclock observation is not needed. Caller retains ownership.
    - `opt_tic`: A pointer to a long where the estimated tickcount value will be stored. Can be NULL if the tickcount estimation is not needed. Caller retains ownership.
- **Output**: Returns a non-negative long representing the jitter in ticks. If opt_now is non-NULL, it stores the wallclock observation; if opt_tic is non-NULL, it stores the estimated tickcount.
- **See also**: [`fd_tempo_observe_pair`](fd_tempo.c.driver.md#fd_tempo_observe_pair)  (Implementation)


---
### fd\_tempo\_async\_min<!-- {{#callable_declaration:fd_tempo_async_min}} -->
Calculates a reasonable minimum interval in ticks between housekeeping events.
- **Description**: This function determines a suitable minimum interval, in ticks, for scheduling housekeeping events in a system. It should be used when you need to ensure that a cycle of events completes within a specified time frame, given in nanoseconds. The function returns a power of two that represents this interval, ensuring that events are spaced appropriately to avoid synchronization issues. It is important to provide valid input values within specified ranges to avoid failure, which results in a return value of zero.
- **Inputs**:
    - `lazy`: The target interval in nanoseconds for completing a cycle of housekeeping events. Must be a positive long integer within the range [1, 2^31). If outside this range, the function logs a warning and returns zero.
    - `event_cnt`: The number of housekeeping events to be scheduled in a cycle. Must be a positive unsigned long integer within the range [1, 2^31). If outside this range, the function logs a warning and returns zero.
    - `tick_per_ns`: The conversion ratio from nanoseconds to ticks, representing the tick rate of the scheduling counter. Must be a positive float within the range (0, ~1.5e29). If outside this range, the function logs a warning and returns zero.
- **Output**: Returns a positive integer power of two in the range [1, 2^31] representing the minimum interval in ticks. Returns zero if any input validation fails or if the calculated interval is unreasonable.
- **See also**: [`fd_tempo_async_min`](fd_tempo.c.driver.md#fd_tempo_async_min)  (Implementation)



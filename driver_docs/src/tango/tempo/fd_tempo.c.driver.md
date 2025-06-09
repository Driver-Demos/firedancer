# Purpose
This C source code file provides functionality for modeling and measuring the performance of time-related operations, specifically focusing on wallclock and tickcount measurements. The file includes functions to model the overhead and jitter of these operations using robust statistical methods, such as fitting a shifted exponential distribution to the time differences observed between consecutive calls. The primary functions, [`fd_tempo_wallclock_model`](#fd_tempo_wallclock_model) and [`fd_tempo_tickcount_model`](#fd_tempo_tickcount_model), estimate the minimal overhead and jitter for wallclock and tickcount operations, respectively. Additionally, the file includes functions to set and retrieve the number of ticks per nanosecond, which is crucial for converting between different time units in performance-sensitive applications.

The code is structured to ensure that these measurements are robust against noise and outliers, using techniques like trimming and robust fitting. It also includes a function, [`fd_tempo_observe_pair`](#fd_tempo_observe_pair), to accurately pair wallclock and tickcount observations, minimizing the error in joint reads. The file is designed to be part of a larger system, as indicated by the inclusion of headers from other directories, and it provides a narrow but essential functionality related to time measurement and performance modeling. The use of static variables and the `FD_ONCE_BEGIN` macro suggests that some computations are intended to be performed only once, optimizing performance by avoiding redundant calculations.
# Imports and Dependencies

---
- `../fd_tango.h`
- `../../util/math/fd_stat.h`


# Global Variables

---
### mu
- **Type**: `double`
- **Description**: The variable `mu` is a static global variable of type double, used to store the mean value of the tick per nanosecond measurement. It is initialized and updated within the `fd_tempo_set_tick_per_ns` and `fd_tempo_tick_per_ns` functions.
- **Use**: `mu` is used to hold the mean tick per nanosecond value, which is either set explicitly or calculated through robust statistical estimation.


---
### sigma
- **Type**: `double`
- **Description**: The `sigma` variable is a static global variable of type double, used to store the standard deviation of the tick per nanosecond measurement. It is part of the robust estimation process for determining the tick rate of the system clock.
- **Use**: `sigma` is used to store the standard deviation of the tick per nanosecond measurement, which is calculated during the initialization of the tick rate model.


---
### explicit\_set
- **Type**: `int`
- **Description**: The `explicit_set` variable is a static integer that acts as a flag to indicate whether certain values have been explicitly set by the user. It is initialized to 0, meaning that by default, the values are not explicitly set.
- **Use**: This variable is used to determine if the `fd_tempo_set_tick_per_ns` function has been called to set specific values for `mu` and `sigma`, bypassing the need for further sampling.


---
### fd\_tempo\_tick\_per\_ns
- **Type**: `function`
- **Description**: The `fd_tempo_tick_per_ns` function calculates the number of ticks per nanosecond by measuring the change in tick count and wall clock over a constant time interval. It uses robust statistical methods to estimate the average and root mean square (RMS) values, assuming a normal distribution of noise.
- **Use**: This function is used to determine the tick rate of the system's clock, which can be used for precise timing and synchronization tasks.


# Functions

---
### fd\_tempo\_wallclock\_model<!-- {{#callable:fd_tempo_wallclock_model}} -->
The `fd_tempo_wallclock_model` function estimates the minimal overhead and jitter of the `fd_log_wallclock` function by modeling it as a shifted exponential random variable and returns the estimated minimum time required for a call.
- **Inputs**:
    - `opt_tau`: A pointer to a double where the function will store the estimated jitter parameter (tau) if it is not NULL.
- **Control Flow**:
    - The function uses static variables `t0` and `tau` to store the estimated minimum time and jitter, respectively.
    - The `FD_ONCE_BEGIN` macro ensures the initialization block is executed only once.
    - A loop is used to repeatedly measure the time taken by `fd_log_wallclock` calls, storing the differences in an array `trial`.
    - The array is trimmed to remove outliers, and a robust exponential fit is applied to estimate `t0` and `tau`.
    - If the fit is successful and `t0` is positive, the loop breaks; otherwise, it retries up to three times.
    - If unsuccessful after three attempts, a warning is logged, and default values for `t0` and `tau` are used.
    - If `opt_tau` is not NULL, the estimated `tau` is stored in the location pointed to by `opt_tau`.
- **Output**: The function returns the estimated minimum time `t0` as a double, representing the minimal overhead of the `fd_log_wallclock` function.


---
### fd\_tempo\_tickcount\_model<!-- {{#callable:fd_tempo_tickcount_model}} -->
The `fd_tempo_tickcount_model` function models the performance of the `fd_tickcount()` function by estimating its minimal overhead and jitter using a robust statistical method.
- **Inputs**:
    - `opt_tau`: A pointer to a double where the estimated jitter (tau) will be stored if not NULL.
- **Control Flow**:
    - Initialize static variables `t0` and `tau` to store the model parameters.
    - Begin a loop that will attempt to model the `fd_tickcount()` performance up to three times.
    - In each iteration, perform 512 trials where the difference between two consecutive `fd_tickcount()` calls is measured and stored in an array.
    - Trim the first and last 64 samples from the array to remove outliers, leaving 384 samples for analysis.
    - Use a robust exponential fitting function `fd_stat_robust_exp_fit_double` to estimate the parameters `t0` and `tau` from the trimmed sample data.
    - If the fitting function returns a value greater than half the sample count and `t0` is positive, break the loop, indicating a successful model.
    - If the loop iterates three times without success, log a warning and set `t0` and `tau` to fallback values of 24 and 4, respectively.
    - End the once-only initialization block.
    - If `opt_tau` is not NULL, store the estimated `tau` in the provided location.
- **Output**: Returns the estimated minimal overhead `t0` of the `fd_tickcount()` function.


---
### fd\_tempo\_set\_tick\_per\_ns<!-- {{#callable:fd_tempo_set_tick_per_ns}} -->
The `fd_tempo_set_tick_per_ns` function sets the global variables `mu` and `sigma` to the provided values and marks them as explicitly set.
- **Inputs**:
    - `_mu`: A double representing the mean value to be set for the global variable `mu`.
    - `_sigma`: A double representing the standard deviation value to be set for the global variable `sigma`.
- **Control Flow**:
    - Set the global variable `explicit_set` to 1, indicating that the values have been explicitly set.
    - Assign the value of `_mu` to the global variable `mu`.
    - Assign the value of `_sigma` to the global variable `sigma`.
- **Output**: This function does not return any value.


---
### fd\_tempo\_observe\_pair<!-- {{#callable:fd_tempo_observe_pair}} -->
The `fd_tempo_observe_pair` function performs a series of alternating tickcount and wallclock observations to determine the wallclock observation with the smallest elapsed ticks, providing a precise joint read of time and tickcount.
- **Inputs**:
    - `opt_now`: A pointer to a long where the best wallclock observation will be stored, if not NULL.
    - `opt_tic`: A pointer to a long where the best tickcount observation will be stored, adjusted to the midpoint of the tickcount bounds, if not NULL.
- **Control Flow**:
    - Initialize variables for best wallclock, tickcount, and joint tickcount difference.
    - Perform a series of alternating tickcount and wallclock observations, storing results in arrays.
    - Determine the best wallclock observation by finding the one with the smallest elapsed ticks between adjacent tickcount observations.
    - If the best joint tickcount difference is negative, log a warning and set it to zero.
    - Store the best wallclock and adjusted tickcount in the provided pointers, if they are not NULL.
- **Output**: Returns the smallest elapsed number of ticks between adjacent tickcount observations, which is the best joint tickcount difference.


---
### fd\_tempo\_async\_min<!-- {{#callable:fd_tempo_async_min}} -->
The `fd_tempo_async_min` function calculates a minimum asynchronous interval based on input parameters, ensuring the result is a power of two within a specified range.
- **Inputs**:
    - `lazy`: A long integer representing a laziness factor, which must be in the range [1, 2^31).
    - `event_cnt`: An unsigned long integer representing the number of events, which must be in the range [1, 2^31).
    - `tick_per_ns`: A float representing the number of ticks per nanosecond, which must be greater than 0 and less than or equal to approximately 1.5e29.
- **Control Flow**:
    - Check if 'lazy' is within the valid range [1, 2^31); if not, log a warning and return 0.
    - Check if 'event_cnt' is within the valid range [1, 2^31); if not, log a warning and return 0.
    - Calculate the maximum valid 'tick_per_ns' and check if 'tick_per_ns' is within the valid range (0, ~1.5e29); if not, log a warning and return 0.
    - Convert 'lazy' and 'event_cnt' to floats and calculate '_async_target' as (tick_per_ns * _lazy) / _event_cnt.
    - Check if '_async_target' is within the valid range [1, 2^32); if not, log a warning and return 0.
    - Convert '_async_target' to an unsigned long 'async_target'.
    - Return 1 shifted left by the most significant bit position of 'async_target', ensuring the result is a power of two within [1, 2^31].
- **Output**: An unsigned long integer representing the minimum asynchronous interval, which is a power of two within the range [1, 2^31], or 0 if any input validation fails.



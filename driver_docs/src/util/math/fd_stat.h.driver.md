# Purpose
The provided C header file, `fd_stat.h`, is a utility library focused on statistical computations and operations on various data types, including both integer and floating-point types. It offers a range of functions for computing averages, filtering data, and determining medians, with a particular emphasis on robustness and efficiency. The file includes inline functions for calculating the average of two numbers without risking overflow, and it provides macros to declare functions for filtering and finding medians across different data types. Additionally, it includes functions for robust statistical fitting, such as estimating the mean and root mean square (RMS) of a dataset, while being resilient to outliers and data corruption.

The file also includes sorting functionality for ascending and descending order across various primitive types, utilizing a template-based approach to generate the necessary sorting functions. This header file is designed to be included in other C source files, providing a broad set of statistical tools that can be used in a variety of applications. It defines public APIs for statistical operations, ensuring that the functions are accessible for external use. The file is structured to handle different data types, including support for 128-bit integers and double precision floating-point numbers, contingent on the availability of these types in the compilation environment.
# Imports and Dependencies

---
- `../bits/fd_bits.h`
- `../tmpl/fd_sort.c`


# Functions

---
### fd\_stat\_avg2\_schar<!-- {{#callable:fd_stat_avg2_schar}} -->
The function `fd_stat_avg2_schar` calculates the average of two signed char values without risk of intermediate overflow by converting them to long integers, summing them, and then right-shifting the result by one bit.
- **Inputs**:
    - `x`: A signed char value representing the first number to be averaged.
    - `y`: A signed char value representing the second number to be averaged.
- **Control Flow**:
    - Convert both input signed char values `x` and `y` to long integers.
    - Sum the converted long integer values.
    - Right-shift the sum by one bit to divide by two, effectively calculating the average.
    - Cast the result back to a signed char before returning.
- **Output**: The function returns the average of the two input signed char values as a signed char, computed in a round toward negative infinity sense.


---
### fd\_stat\_avg2\_short<!-- {{#callable:fd_stat_avg2_short}} -->
The `fd_stat_avg2_short` function calculates the average of two short integers without risk of intermediate overflow by using long integer arithmetic.
- **Inputs**:
    - `x`: A short integer representing the first value to be averaged.
    - `y`: A short integer representing the second value to be averaged.
- **Control Flow**:
    - Casts both input short integers `x` and `y` to long integers to prevent overflow during addition.
    - Adds the two long integers together.
    - Performs a right bitwise shift by 1 on the sum to divide it by 2, effectively calculating the average.
    - Casts the result back to a short integer before returning.
- **Output**: Returns the average of the two input short integers as a short integer, rounded towards negative infinity.


---
### fd\_stat\_avg2\_int<!-- {{#callable:fd_stat_avg2_int}} -->
The `fd_stat_avg2_int` function calculates the average of two integers without risk of intermediate overflow by using a long integer for intermediate calculations and then right-shifting the result.
- **Inputs**:
    - `x`: An integer value representing the first number to be averaged.
    - `y`: An integer value representing the second number to be averaged.
- **Control Flow**:
    - The function casts both input integers `x` and `y` to long integers to prevent overflow during addition.
    - It adds the two long integers together.
    - The sum is then right-shifted by one bit to divide by two, effectively calculating the average.
    - The result is cast back to an integer type before being returned.
- **Output**: The function returns an integer that is the average of the two input integers, rounded towards negative infinity.


---
### fd\_stat\_avg2\_uchar<!-- {{#callable:fd_stat_avg2_uchar}} -->
The `fd_stat_avg2_uchar` function calculates the average of two unsigned char values without risk of overflow by using bitwise operations.
- **Inputs**:
    - `x`: An unsigned char value representing the first operand.
    - `y`: An unsigned char value representing the second operand.
- **Control Flow**:
    - The function casts both input unsigned char values, `x` and `y`, to unsigned long to prevent overflow during addition.
    - It adds the two unsigned long values together.
    - The sum is then right-shifted by one bit to divide by two, effectively calculating the average.
    - The result is cast back to an unsigned char before being returned.
- **Output**: The function returns the average of the two input unsigned char values as an unsigned char.


---
### fd\_stat\_avg2\_ushort<!-- {{#callable:fd_stat_avg2_ushort}} -->
The `fd_stat_avg2_ushort` function calculates the average of two unsigned short integers without risk of intermediate overflow.
- **Inputs**:
    - `x`: An unsigned short integer representing the first value to be averaged.
    - `y`: An unsigned short integer representing the second value to be averaged.
- **Control Flow**:
    - Casts both input values `x` and `y` to `ulong` to prevent overflow during addition.
    - Adds the two `ulong` values together.
    - Performs a right bitwise shift by 1 on the sum to divide it by 2, effectively calculating the average.
    - Casts the result back to `ushort` before returning.
- **Output**: Returns the average of the two input unsigned short integers as an unsigned short integer.


---
### fd\_stat\_avg2\_uint<!-- {{#callable:fd_stat_avg2_uint}} -->
The `fd_stat_avg2_uint` function calculates the average of two unsigned integers without risk of overflow by using a wider integer type for intermediate calculations.
- **Inputs**:
    - `x`: An unsigned integer representing the first value to be averaged.
    - `y`: An unsigned integer representing the second value to be averaged.
- **Control Flow**:
    - Casts both input unsigned integers `x` and `y` to a wider integer type `ulong` to prevent overflow during addition.
    - Adds the two `ulong` values together.
    - Shifts the result right by one bit to divide by two, effectively calculating the average.
    - Casts the result back to an unsigned integer `uint` before returning.
- **Output**: The function returns the average of the two input unsigned integers as a `uint`, rounded towards negative infinity.


---
### fd\_stat\_avg2\_long<!-- {{#callable:fd_stat_avg2_long}} -->
The `fd_stat_avg2_long` function calculates the average of two long integers without risk of intermediate overflow, rounding towards negative infinity.
- **Inputs**:
    - `x`: A long integer representing the first number to be averaged.
    - `y`: A long integer representing the second number to be averaged.
- **Control Flow**:
    - The function shifts both input numbers `x` and `y` right by one bit, effectively dividing them by two.
    - It adds the results of the right shifts together.
    - It checks if both `x` and `y` are odd by performing a bitwise AND with `1L`, and adds `1` to the result if both are odd.
- **Output**: The function returns a long integer representing the average of `x` and `y`, rounded towards negative infinity.


---
### fd\_stat\_avg2\_ulong<!-- {{#callable:fd_stat_avg2_ulong}} -->
The `fd_stat_avg2_ulong` function calculates the average of two unsigned long integers without risk of intermediate overflow, rounding towards negative infinity.
- **Inputs**:
    - `x`: An unsigned long integer representing the first number to average.
    - `y`: An unsigned long integer representing the second number to average.
- **Control Flow**:
    - The function shifts both input values `x` and `y` right by one bit, effectively dividing them by two.
    - It adds the results of these shifts together.
    - It checks if both `x` and `y` have their least significant bit set (i.e., both are odd) by performing a bitwise AND with `1UL`, and adds this result to the sum.
- **Output**: The function returns the average of the two input unsigned long integers, rounded towards negative infinity.


---
### fd\_stat\_avg2\_int128<!-- {{#callable:fd_stat_avg2_int128}} -->
The `fd_stat_avg2_int128` function calculates the average of two 128-bit integers without risk of intermediate overflow, rounding towards negative infinity.
- **Inputs**:
    - `x`: The first 128-bit integer input.
    - `y`: The second 128-bit integer input.
- **Control Flow**:
    - The function shifts both input integers `x` and `y` to the right by one bit, effectively dividing them by two.
    - It adds the results of the right shifts together.
    - It calculates the bitwise AND of `x`, `y`, and the integer `1`, and adds this to the sum of the right shifts to account for rounding towards negative infinity.
- **Output**: The function returns the average of the two input 128-bit integers as an `int128` type, rounded towards negative infinity.


---
### fd\_stat\_avg2\_uint128<!-- {{#callable:fd_stat_avg2_uint128}} -->
The function `fd_stat_avg2_uint128` calculates the average of two `uint128` numbers without risk of intermediate overflow.
- **Inputs**:
    - `x`: The first `uint128` number to be averaged.
    - `y`: The second `uint128` number to be averaged.
- **Control Flow**:
    - The function shifts both `x` and `y` right by one bit, effectively dividing them by 2.
    - It adds the results of the right shifts together.
    - It calculates the bitwise AND of `x`, `y`, and the constant `1` to determine if both numbers are odd, adding this result to the sum to account for rounding.
- **Output**: The function returns the average of `x` and `y` as a `uint128` value, rounded towards negative infinity.


---
### fd\_stat\_avg2\_float<!-- {{#callable:fd_stat_avg2_float}} -->
The `fd_stat_avg2_float` function calculates the average of two floating-point numbers.
- **Inputs**:
    - `x`: A floating-point number representing the first value to be averaged.
    - `y`: A floating-point number representing the second value to be averaged.
- **Control Flow**:
    - The function takes two float arguments, `x` and `y`.
    - It calculates the average by multiplying each input by 0.5 and summing the results.
    - The function returns the computed average as a float.
- **Output**: A float representing the average of the two input numbers.


---
### fd\_stat\_avg2\_double<!-- {{#callable:fd_stat_avg2_double}} -->
The `fd_stat_avg2_double` function calculates the average of two double-precision floating-point numbers.
- **Inputs**:
    - `x`: A double-precision floating-point number representing the first value to be averaged.
    - `y`: A double-precision floating-point number representing the second value to be averaged.
- **Control Flow**:
    - The function takes two double-precision floating-point numbers as input.
    - It calculates the average by multiplying each input by 0.5 and summing the results.
    - The function returns the computed average as a double-precision floating-point number.
- **Output**: A double-precision floating-point number representing the average of the two input values.


# Function Declarations (Public API)

---
### fd\_stat\_robust\_norm\_fit\_float<!-- {{#callable_declaration:fd_stat_robust_norm_fit_float}} -->
Estimates the mean and RMS of a dataset with robust handling of outliers.
- **Description**: This function is used to estimate the mean and root mean square (RMS) of a dataset, assuming most data points are independent and identically distributed (IID) samples from a normal distribution, with some potentially corrupted outliers. It filters out extreme values and NaNs, using only samples with magnitudes less than FLT_MAX/5 for the estimation. The function is robust against data corruption, making it suitable for datasets with outliers. It returns the number of valid samples used in the estimation. If no valid samples are found, the mean and RMS are set to zero. The function requires a scratch space for temporary data storage, which can be the same as the input data if in-place operation is acceptable.
- **Inputs**:
    - `opt_mu`: A pointer to a float where the estimated mean will be stored. Can be NULL if the mean is not needed. If provided, the caller must ensure it is a valid pointer.
    - `opt_sigma`: A pointer to a float where the estimated RMS will be stored. Can be NULL if the RMS is not needed. If provided, the caller must ensure it is a valid pointer.
    - `x`: A pointer to an array of floats representing the dataset. The array must contain at least 'cnt' elements. The caller retains ownership and must ensure the data is valid and non-NULL.
    - `cnt`: The number of elements in the dataset array 'x'. Must be non-negative. If zero, the function will return zero and set mean and RMS to zero if requested.
    - `scratch`: A pointer to a memory region with space for at least 'cnt' floats, used for temporary storage during computation. The memory will be overwritten. Can be the same as 'x' if in-place operation is acceptable.
- **Output**: Returns the number of valid samples used in the estimation, which is a non-negative integer.
- **See also**: [`fd_stat_robust_norm_fit_float`](fd_stat.c.driver.md#fd_stat_robust_norm_fit_float)  (Implementation)


---
### fd\_stat\_robust\_exp\_fit\_float<!-- {{#callable_declaration:fd_stat_robust_exp_fit_float}} -->
Estimates the parameters of a shifted exponential distribution from a dataset.
- **Description**: This function is used to estimate the minimum (x0) and decay length (tau) of a shifted exponential distribution from a given dataset of floating-point numbers. It is designed to be robust against outliers by filtering out extreme values before performing the estimation. The function should be called when you have a dataset that you suspect follows a shifted exponential distribution and you need robust parameter estimates. It requires a scratch space for intermediate calculations, which will be overwritten. The function returns the number of data points used in the estimation, which can be fewer than the original count if some data points are filtered out.
- **Inputs**:
    - `opt_x0`: A pointer to a float where the estimated minimum of the distribution will be stored. Can be NULL if the estimate is not needed. If provided, the caller must ensure it is a valid pointer.
    - `opt_tau`: A pointer to a float where the estimated decay length of the distribution will be stored. Can be NULL if the estimate is not needed. If provided, the caller must ensure it is a valid pointer.
    - `x`: A pointer to an array of floats representing the dataset. The array must contain at least 'cnt' elements. The caller retains ownership and must ensure the data is valid and non-NULL.
    - `cnt`: The number of elements in the dataset array 'x'. Must be a non-negative integer.
    - `scratch`: A pointer to a memory region that can hold at least 'cnt' floats. This space is used for intermediate calculations and will be modified. The caller must ensure it is properly allocated and aligned.
- **Output**: Returns the number of data points used in the estimation after filtering.
- **See also**: [`fd_stat_robust_exp_fit_float`](fd_stat.c.driver.md#fd_stat_robust_exp_fit_float)  (Implementation)


---
### fd\_stat\_robust\_norm\_fit\_double<!-- {{#callable_declaration:fd_stat_robust_norm_fit_double}} -->
Estimates the mean and standard deviation of a dataset with robust filtering.
- **Description**: This function estimates the mean and standard deviation of a dataset, assuming most data points are independent and identically distributed (IID) samples from a normal distribution, with some potentially corrupted outliers. It filters out extreme values with magnitudes greater than DBL_MAX/5 and computes robust estimates using the median. The function is useful for datasets with outliers, providing robust statistical estimates. It returns the number of data points used in the estimation. The function requires a scratch space for temporary data storage, which will be modified during execution.
- **Inputs**:
    - `opt_mu`: A pointer to a double where the estimated mean will be stored. Can be NULL if the mean is not needed. If provided, the caller must ensure it is a valid pointer.
    - `opt_sigma`: A pointer to a double where the estimated standard deviation will be stored. Can be NULL if the standard deviation is not needed. If provided, the caller must ensure it is a valid pointer.
    - `x`: A pointer to an array of doubles representing the dataset. The array must contain at least 'cnt' elements. The caller retains ownership and must ensure the data is valid and non-NULL.
    - `cnt`: The number of elements in the dataset array 'x'. Must be a non-negative integer.
    - `scratch`: A pointer to a memory region used for temporary storage during computation. Must be large enough to hold 'cnt' doubles. The caller retains ownership and must ensure it is valid and non-NULL.
- **Output**: Returns the number of data points used in the estimation, which is the count of values in 'x' with magnitude less than DBL_MAX/5.
- **See also**: [`fd_stat_robust_norm_fit_double`](fd_stat.c.driver.md#fd_stat_robust_norm_fit_double)  (Implementation)


---
### fd\_stat\_robust\_exp\_fit\_double<!-- {{#callable_declaration:fd_stat_robust_exp_fit_double}} -->
Estimates the parameters of a robust exponential fit for double precision data.
- **Description**: This function estimates the minimum (x0) and decay length (tau) of a shifted exponential distribution from a given set of double precision samples. It is designed to be robust against outliers, assuming most samples are independent and identically distributed (IID) from the target distribution. The function filters out samples with magnitudes greater than DBL_MAX/5 and computes the estimates based on the remaining data. It should be called when a robust estimation of exponential distribution parameters is needed, especially in the presence of potential data corruption. The function returns the number of valid samples used in the estimation.
- **Inputs**:
    - `opt_x0`: A pointer to a double where the estimated minimum of the distribution will be stored. Can be NULL if the estimate is not needed. If provided, the caller must ensure it is a valid pointer.
    - `opt_tau`: A pointer to a double where the estimated decay length of the distribution will be stored. Can be NULL if the estimate is not needed. If provided, the caller must ensure it is a valid pointer.
    - `x`: A pointer to an array of double precision samples. The array must contain at least 'cnt' elements. The caller retains ownership and must ensure the array is valid and non-null.
    - `cnt`: The number of samples in the array 'x'. Must be a non-negative value.
    - `scratch`: A pointer to a memory region that can hold at least 'cnt' doubles. This region will be used as temporary storage and will be modified by the function. The caller retains ownership and must ensure it is valid and properly aligned.
- **Output**: Returns the number of valid samples used in the estimation, which is a non-negative ulong value.
- **See also**: [`fd_stat_robust_exp_fit_double`](fd_stat.c.driver.md#fd_stat_robust_exp_fit_double)  (Implementation)



# Purpose
This C source code file provides a collection of statistical and sorting functions designed to handle various data types, including both integer and floating-point types. The primary functionality revolves around filtering data, computing medians, and performing robust statistical fits for normal and exponential distributions. The code defines a macro `FD_STAT_IMPL` to generate type-specific implementations of filtering and median calculation functions for different data types, such as `schar`, `short`, `int`, `long`, `float`, and `double`. These functions are used to filter out data points based on a threshold and compute the median, which is a robust estimator of the central tendency in the presence of outliers.

Additionally, the file includes sorting functionality for ascending and descending order using a template-based approach. It imports a sorting implementation from an external file (`fd_sort.c`) and applies it to various data types by defining macros that specify the sort name, key type, and sorting style. The sorting functions are crucial for the median calculation and other statistical operations that require ordered data. The file also includes robust fitting functions for normal and exponential distributions, which estimate parameters like mean (`mu`), standard deviation (`sigma`), initial value (`x0`), and time constant (`tau`) using median and median absolute deviation. This code is intended to be part of a larger library, providing essential statistical and sorting utilities that can be reused across different applications.
# Imports and Dependencies

---
- `fd_stat.h`
- `../tmpl/fd_sort.c`


# Global Variables

---
### j
- **Type**: `ulong`
- **Description**: The variable `j` is a local variable of type `ulong` initialized to zero within the `fd_stat_filter_##T` function. It is used to keep track of the number of elements in the array `y` that meet a certain condition based on the threshold value.
- **Use**: `j` is incremented each time an element in the input array `x` satisfies the condition, effectively counting the number of elements that pass the filter.


# Functions

---
### fd\_stat\_robust\_norm\_fit\_float<!-- {{#callable:fd_stat_robust_norm_fit_float}} -->
The function `fd_stat_robust_norm_fit_float` computes robust estimates of the mean and standard deviation of a dataset, filtering out extreme values to prevent overflow.
- **Inputs**:
    - `opt_mu`: A pointer to a float where the computed robust mean (mu) will be stored, if not NULL.
    - `opt_sigma`: A pointer to a float where the computed robust standard deviation (sigma) will be stored, if not NULL.
    - `x`: A pointer to an array of floats representing the input data.
    - `cnt`: An unsigned long integer representing the number of elements in the input data array.
    - `scratch`: A pointer to a memory area used for temporary storage during computation.
- **Control Flow**:
    - The function begins by casting the scratch pointer to a float pointer for temporary storage.
    - It filters the input data array `x` to remove extreme values using `fd_stat_filter_float`, storing the result in `y` and updating `cnt` to the number of valid elements.
    - If either `opt_mu` or `opt_sigma` is not NULL, it proceeds to compute the median of the filtered data using `fd_stat_median_float`.
    - If `opt_mu` is not NULL, it stores the computed median in `*opt_mu`.
    - If `opt_sigma` is not NULL, it calculates the absolute deviations from the median, updates `y`, and computes the median of these deviations, scaling it by a constant to estimate the standard deviation, storing the result in `*opt_sigma`.
    - The function returns the count of valid elements after filtering.
- **Output**: The function returns an unsigned long integer representing the number of elements remaining after filtering the input data.


---
### fd\_stat\_robust\_exp\_fit\_float<!-- {{#callable:fd_stat_robust_exp_fit_float}} -->
The function `fd_stat_robust_exp_fit_float` estimates the parameters of an exponential distribution robustly from a given dataset of floats by filtering out extreme values and calculating the median and median absolute deviation.
- **Inputs**:
    - `opt_x0`: A pointer to a float where the estimated x0 parameter will be stored, or NULL if not needed.
    - `opt_tau`: A pointer to a float where the estimated tau parameter will be stored, or NULL if not needed.
    - `x`: A pointer to an array of floats representing the input data.
    - `cnt`: The number of elements in the input data array.
    - `scratch`: A pointer to a memory area used for temporary storage during computation.
- **Control Flow**:
    - Allocate a float pointer `y` to use the provided `scratch` memory for temporary storage.
    - Filter the input data `x` to remove extreme values using `fd_stat_filter_float`, updating `cnt` to the number of valid data points.
    - Check if either `opt_x0` or `opt_tau` is non-NULL to determine if parameter estimation is needed.
    - Compute the median of the filtered data stored in `y`.
    - Calculate the median absolute deviation (MAD) from the median for the data in `y`.
    - If `opt_x0` is non-NULL, estimate `x0` using the formula `med - mad*1.44042009041256f`.
    - If `opt_tau` is non-NULL, estimate `tau` using the formula `mad*2.07808692123503f`.
    - Return the count of valid data points after filtering.
- **Output**: The function returns the number of valid data points after filtering the input data.


---
### fd\_stat\_robust\_norm\_fit\_double<!-- {{#callable:fd_stat_robust_norm_fit_double}} -->
The function `fd_stat_robust_norm_fit_double` calculates robust estimates of the mean and standard deviation of a dataset using the median and median absolute deviation.
- **Inputs**:
    - `opt_mu`: A pointer to a double where the estimated mean will be stored, or NULL if the mean is not needed.
    - `opt_sigma`: A pointer to a double where the estimated standard deviation will be stored, or NULL if the standard deviation is not needed.
    - `x`: A pointer to an array of doubles representing the input data.
    - `cnt`: The number of elements in the input data array.
    - `scratch`: A pointer to a memory area used for temporary storage during computation.
- **Control Flow**:
    - The function begins by casting the `scratch` pointer to a double pointer `y`.
    - It filters the input data `x` using `fd_stat_filter_double`, storing the result in `y` and updating `cnt` to the number of valid data points.
    - If either `opt_mu` or `opt_sigma` is non-NULL, it proceeds to calculate the median of the filtered data `y`.
    - If `opt_mu` is non-NULL, it stores the median in `*opt_mu`.
    - If `opt_sigma` is non-NULL, it calculates the absolute deviations from the median, updates `y` with these deviations, and computes the median of these deviations.
    - It then scales this median absolute deviation by a constant factor (1.48260221850560) to estimate the standard deviation, storing the result in `*opt_sigma`.
- **Output**: The function returns the number of valid data points after filtering, which is stored in `cnt`.


---
### fd\_stat\_robust\_exp\_fit\_double<!-- {{#callable:fd_stat_robust_exp_fit_double}} -->
The `fd_stat_robust_exp_fit_double` function estimates the parameters of a robust exponential fit for a given dataset of doubles, filtering out extreme values and calculating the median and median absolute deviation to determine the fit parameters.
- **Inputs**:
    - `opt_x0`: A pointer to a double where the estimated x0 parameter will be stored, or NULL if not needed.
    - `opt_tau`: A pointer to a double where the estimated tau parameter will be stored, or NULL if not needed.
    - `x`: A pointer to an array of doubles representing the input data.
    - `cnt`: The number of elements in the input data array.
    - `scratch`: A pointer to a memory area used for temporary storage during computation.
- **Control Flow**:
    - The function begins by casting the scratch pointer to a double pointer and storing it in `y`.
    - It calls `fd_stat_filter_double` to filter the input data `x`, storing the filtered data in `y` and updating `cnt` to the number of valid data points.
    - If either `opt_x0` or `opt_tau` is not NULL, the function proceeds to calculate the median of the filtered data `y`.
    - The function then computes the absolute deviation of each element in `y` from the median and updates `y` with these deviations.
    - It calculates the median of these absolute deviations (MAD).
    - If `opt_x0` is not NULL, it calculates `*opt_x0` as the median minus MAD multiplied by a constant factor.
    - If `opt_tau` is not NULL, it calculates `*opt_tau` as MAD multiplied by another constant factor.
    - Finally, the function returns the count of valid data points after filtering.
- **Output**: The function returns the number of valid data points after filtering, which is an unsigned long integer.



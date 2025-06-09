# Purpose
This C header file defines a data structure and associated functions for estimating the sliding-window mean and variance of tagged data. The primary purpose of this code is to provide a mechanism for efficiently calculating statistical estimates for data that is categorized by tags, which are opaque identifiers. The data structure, `fd_est_tbl_t`, uses an exponential moving average (EMA) approach to maintain these estimates, allowing for quick updates and queries. The structure is designed to handle real-valued inputs and is optimized for performance by using a fixed-size array of bins, where each bin accumulates statistics for tags that map to it. This design choice introduces some approximation due to potential tag aliasing, but it also ensures that the system can handle a large number of tags without excessive memory usage.

The file includes several key components: macros for alignment and footprint calculations, the definition of the main data structure (`fd_est_tbl_t`), and a set of inline functions for managing the lifecycle of the estimation table. These functions include creating a new table ([`fd_est_tbl_new`](#fd_est_tbl_new)), joining and leaving a table ([`fd_est_tbl_join`](#fd_est_tbl_join) and [`fd_est_tbl_leave`](#fd_est_tbl_leave)), and deleting a table ([`fd_est_tbl_delete`](#fd_est_tbl_delete)). Additionally, the file provides functions for updating the table with new data ([`fd_est_tbl_update`](#fd_est_tbl_update)) and estimating the mean and variance for a given tag ([`fd_est_tbl_estimate`](#fd_est_tbl_estimate)). The code is designed to be used in environments where double precision is available, as indicated by the `FD_HAS_DOUBLE` preprocessor directive. This header file is intended to be included in other C source files, providing a reusable component for statistical analysis of tagged data streams.
# Imports and Dependencies

---
- `../../ballet/fd_ballet_base.h`


# Data Structures

---
### fd\_private\_est\_tbl\_bin
- **Type**: `struct`
- **Members**:
    - `x`: The numerator of the EMA of the values that have mapped to this bin.
    - `x2`: The numerator of the EMA of the square of values that have mapped to this bin.
    - `d`: The denominator for EMA(x), paired with the numerator from above.
    - `d2`: An additional denominator used in EMA calculations.
- **Description**: The `fd_private_est_tbl_bin` structure is used to accumulate statistics for a specific bin in an estimation table, which is part of a system designed to estimate the sliding-window mean and variance of tagged data. Each bin holds the numerators and denominators for exponential moving averages (EMA) of values and their squares, allowing for efficient computation of statistical estimates over time. This structure is integral to handling the approximation of mean and variance for data associated with specific tags, which are mapped to these bins.


---
### fd\_est\_tbl\_bin\_t
- **Type**: `struct`
- **Members**:
    - `x`: The numerator of the EMA of the values that have mapped to this bin.
    - `x2`: The numerator of the EMA of the square of values that have mapped to this bin.
    - `d`: The denominator for EMA(x), paired with the numerator from above.
    - `d2`: An additional denominator used in variance calculations.
- **Description**: The `fd_est_tbl_bin_t` structure is used internally within an estimation table to accumulate statistics about data values that map to a specific bin index. It maintains exponential moving averages (EMA) for both the values and their squares, which are used to estimate the mean and variance of the data. The structure is designed to be compact, allowing for efficient updates and queries, and is aligned to facilitate atomic operations on some platforms.


---
### fd\_private\_est\_tbl
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier set to FD_EST_TBL_MAGIC to verify the integrity of the structure.
    - `bin_cnt_mask`: A mask used to determine the number of bins in the table, which is a power of two.
    - `ema_coeff`: The decay coefficient used in Exponential Moving Average (EMA) computations, typically close to 1.0.
    - `default_val`: The default mean value returned when a query maps to a bin with insufficient data.
    - `bins`: An array of bins used to store statistical data, with the array size conventionally set to 1.
- **Description**: The `fd_private_est_tbl` structure is designed to estimate the sliding-window mean and variance of tagged data. It uses an array of bins to map tags to statistical data, allowing for approximate answers to queries about the mean and variance of recent data associated with a specific tag. The structure is aligned to 32 bytes and includes fields for managing the number of bins, the decay coefficient for EMA calculations, and a default value for queries with insufficient data. The `magic` field ensures the structure's integrity, while the `bins` array holds the actual statistical data, with its size determined by the `bin_cnt_mask`.


---
### fd\_est\_tbl\_t
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier set to FD_EST_TBL_MAGIC to verify the integrity of the structure.
    - `bin_cnt_mask`: A mask used to determine the number of bins in the table, which is a power of two.
    - `ema_coeff`: The decay coefficient used in Exponential Moving Average (EMA) computations, typically near 1.0.
    - `default_val`: The default mean value returned when a query maps to a bin with very few values.
    - `bins`: An array of bins used to accumulate statistics about tags, with the array size conventionally set to 1.
- **Description**: The `fd_est_tbl_t` structure is designed to estimate the sliding-window mean and variance of tagged data. It uses an array of bins to map tags to statistics, allowing for approximate answers to queries about the mean and variance of recent data with a specific tag. The structure is aligned to 32 bytes and includes a magic number for integrity checks, a mask to determine the number of bins, a decay coefficient for EMA calculations, and a default value for queries with insufficient data. The bins array holds the actual statistical data, with each bin containing numerators and denominators for EMA calculations of values and their squares.


# Functions

---
### fd\_est\_tbl\_align<!-- {{#callable:fd_est_tbl_align}} -->
The `fd_est_tbl_align` function returns the required memory alignment for an estimation table's state.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, indicating it is intended for use within the same translation unit and optimized for performance.
    - It returns a constant value `FD_EST_TBL_ALIGN`, which is predefined as 32UL, representing the alignment requirement for the estimation table.
- **Output**: The function returns an unsigned long integer representing the alignment requirement for the estimation table.


---
### fd\_est\_tbl\_footprint<!-- {{#callable:fd_est_tbl_footprint}} -->
The `fd_est_tbl_footprint` function calculates the memory footprint required for an estimation table with a specified number of bins.
- **Inputs**:
    - `bin_cnt`: The number of bins for which the memory footprint is to be calculated; it must be a power of two and greater than zero.
- **Control Flow**:
    - Check if `bin_cnt` is zero or not a power of two using `fd_ulong_is_pow2`; if true, return 0UL.
    - Check if `bin_cnt` exceeds the maximum allowable number of bins based on `ULONG_MAX`; if true, return 0UL.
    - Calculate and return the memory footprint as the size of `fd_est_tbl_t` plus the size of `bin_cnt-1` `fd_est_tbl_bin_t` structures.
- **Output**: Returns the calculated memory footprint in bytes as an unsigned long integer, or 0UL if the input is invalid.


---
### fd\_est\_tbl\_new<!-- {{#callable:fd_est_tbl_new}} -->
The `fd_est_tbl_new` function initializes a memory region as an estimation table for calculating sliding-window mean and variance of tagged data.
- **Inputs**:
    - `mem`: A pointer to a memory region that will be formatted as an estimation table.
    - `bin_cnt`: The number of bins in the table, which must be a power of two and greater than zero.
    - `history`: The window size for the exponential moving average (EMA) calculations, must be positive.
    - `default_val`: The default value to return as the mean when a query maps to a bin with very few values.
- **Control Flow**:
    - Check if `bin_cnt` is zero or not a power of two, returning NULL if true.
    - Check if `bin_cnt` exceeds the maximum allowable size, returning NULL if true.
    - Check if `history` is zero, returning NULL if true.
    - Cast the memory region `mem` to a `fd_est_tbl_t` pointer and initialize its fields.
    - Set `bin_cnt_mask` to `bin_cnt - 1`.
    - Calculate and set `ema_coeff` as `1.0 - 1.0/(double)history`.
    - Set `default_val` to the provided `default_val`.
    - Initialize all bins in the table to zero using `fd_memset`.
    - Set the `magic` field to `FD_EST_TBL_MAGIC` to mark the table as initialized.
    - Return the pointer to the initialized table.
- **Output**: Returns a pointer to the initialized estimation table on success, or NULL on failure due to invalid inputs.


---
### fd\_est\_tbl\_join<!-- {{#callable:fd_est_tbl_join}} -->
The `fd_est_tbl_join` function verifies the magic number of a given estimation table and returns a pointer to it if valid, otherwise returns NULL.
- **Inputs**:
    - `_tbl`: A pointer to a memory region that is expected to hold the state of an `fd_est_tbl_t` structure.
- **Control Flow**:
    - Cast the input pointer `_tbl` to a `fd_est_tbl_t` pointer named `tbl`.
    - Check if the `magic` field of `tbl` is equal to `FD_EST_TBL_MAGIC`.
    - If the `magic` field does not match, return `NULL`.
    - If the `magic` field matches, return the `tbl` pointer.
- **Output**: Returns a pointer to the `fd_est_tbl_t` structure if the magic number is valid, otherwise returns `NULL`.


---
### fd\_est\_tbl\_leave<!-- {{#callable:fd_est_tbl_leave}} -->
The `fd_est_tbl_leave` function returns a pointer to the memory region holding the state of a `fd_est_tbl_t` table, effectively leaving the current join.
- **Inputs**:
    - `tbl`: A pointer to an `fd_est_tbl_t` structure representing the estimation table whose join is to be left.
- **Control Flow**:
    - The function takes a pointer to an `fd_est_tbl_t` structure as input.
    - It casts the input pointer to a `void *` type.
    - The function returns the casted pointer, effectively leaving the join.
- **Output**: A `void *` pointer to the memory region holding the table state, which is the same as the input pointer cast to `void *`.


---
### fd\_est\_tbl\_delete<!-- {{#callable:fd_est_tbl_delete}} -->
The `fd_est_tbl_delete` function unformats a memory region used for an estimation table and returns ownership of the memory to the caller.
- **Inputs**:
    - `tbl`: A pointer to an `fd_est_tbl_t` structure representing the estimation table to be deleted.
- **Control Flow**:
    - Check if the `magic` field of the table is not equal to `FD_EST_TBL_MAGIC`, and if so, log a warning about invalid magic.
    - Use a memory fence to ensure memory operations are completed before proceeding.
    - Set the `magic` field of the table to 0, effectively marking it as unformatted.
    - Use another memory fence to ensure the `magic` field update is completed.
    - Return the pointer to the table, indicating the memory region is now unformatted and returned to the caller.
- **Output**: A pointer to the `fd_est_tbl_t` structure, indicating the memory region is now unformatted and returned to the caller.


---
### fd\_est\_tbl\_estimate<!-- {{#callable:fd_est_tbl_estimate}} -->
The `fd_est_tbl_estimate` function estimates the mean and variance of data associated with a specific tag from a sliding-window estimation table.
- **Inputs**:
    - `tbl`: A pointer to a constant `fd_est_tbl_t` structure representing the estimation table.
    - `tag`: An unsigned long integer representing the tag for which the mean and variance are to be estimated.
    - `variance_out`: A pointer to a double where the variance will be stored if it is not NULL.
- **Control Flow**:
    - Calculate the bin index by applying a mask to the tag and retrieve the corresponding bin from the table.
    - Check if the bin's denominator `d` is greater than 0.0 to determine if there is data associated with the tag.
    - If no data is associated (i.e., `d <= 0.0`), set the mean to the table's default value and variance to 0.0.
    - If data is associated, calculate the mean as `x/d` and the variance using the formula `(d * x2 - (x*x)) / (d * d - d2)`.
    - Ensure the variance is non-negative by using `fd_double_if` to set it to 0.0 if it is negative.
    - If `variance_out` is not NULL, store the calculated variance in the location pointed to by `variance_out`.
    - Return the calculated mean.
- **Output**: The function returns a double representing the estimated mean of the data associated with the given tag.


---
### fd\_est\_tbl\_update<!-- {{#callable:fd_est_tbl_update}} -->
The `fd_est_tbl_update` function updates the statistics of a specific bin in an estimation table with a new tagged value, adjusting the exponential moving averages (EMA) of the value and its square.
- **Inputs**:
    - `tbl`: A pointer to the `fd_est_tbl_t` structure representing the estimation table.
    - `tag`: An unsigned long integer used to identify the bin within the table to update.
    - `value`: An unsigned integer representing the new value to be inserted into the table.
- **Control Flow**:
    - Calculate the bin index by applying a mask to the tag and retrieve the corresponding bin from the table.
    - If `FD_EST_TBL_ADAPTIVE` is defined, estimate the mean and variance for the tag, compute the normalized squared deviation, and calculate an adaptive coefficient `C` based on this deviation.
    - If `FD_EST_TBL_ADAPTIVE` is not defined, use the table's `ema_coeff` as the coefficient `C`.
    - Update the bin's `x` (EMA of values) by adding the new value and adjusting the existing EMA with coefficient `C`.
    - Update the bin's `x2` (EMA of squared values) similarly, using the square of the new value.
    - Update the bin's `d` (denominator for EMA of values) by incrementing it and adjusting with `C`.
    - Update the bin's `d2` (denominator for EMA of squared values) by incrementing it and adjusting with `C*C`.
- **Output**: The function does not return a value; it updates the state of the specified bin in the estimation table.
- **Functions called**:
    - [`fd_est_tbl_estimate`](#fd_est_tbl_estimate)



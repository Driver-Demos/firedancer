# Purpose
This C header file defines a fixed-size exponential histogram data structure and associated functions for managing and utilizing it. The primary purpose of this code is to provide a mechanism for efficiently categorizing and counting numerical data into exponentially spaced buckets, which is useful for analyzing data distributions with a wide range of values. The histogram is designed to handle values up to a specified maximum, with an overflow bucket for values exceeding this limit. The code includes functions for creating a new histogram, adding samples, and retrieving bucket counts and boundaries, as well as the total sum of all samples, which can be used to compute the mean.

The file defines a private structure `fd_histf_private` that holds the histogram's data, including the counts for each bucket and the precomputed left edges of the buckets. The histogram is aligned for performance reasons, particularly when using SIMD (Single Instruction, Multiple Data) operations, which are conditionally included if AVX (Advanced Vector Extensions) is available. The code provides a clear API for interacting with the histogram, including functions to initialize, join, leave, and delete histograms, as well as to sample values and retrieve statistical information. This header file is intended to be included in other C source files, providing a reusable and efficient tool for data analysis tasks that require histogram-based data aggregation.
# Imports and Dependencies

---
- `math.h`
- `../log/fd_log.h`
- `../simd/fd_avx.h`


# Data Structures

---
### fd\_histf\_private
- **Type**: `struct`
- **Members**:
    - `counts`: An array storing the count of samples in each histogram bucket.
    - `left_edge`: An array defining the left edges of the histogram buckets, pre-subtracted by 2^63 for comparison purposes.
    - `sum`: The total sum of all samples added to the histogram, used for calculating the mean.
- **Description**: The `fd_histf_private` structure is designed to implement a fixed-size exponential histogram with a specific alignment requirement. It contains an array `counts` to keep track of the number of samples in each of the histogram's buckets, and an array `left_edge` that defines the boundaries of these buckets, adjusted for efficient comparison using AVX2 instructions. The `sum` field accumulates the total of all samples, facilitating the computation of the mean value of the samples. This structure is part of a system that allows for efficient histogramming of data with exponential bucket spacing, including handling of overflow and underflow values.


---
### fd\_histf\_t
- **Type**: `struct`
- **Members**:
    - `counts`: An array of unsigned long integers representing the count of samples in each histogram bucket.
    - `left_edge`: An array of long integers representing the left edge of each histogram bucket, pre-subtracted by 2^63 for comparison purposes.
    - `sum`: An unsigned long integer representing the sum of all samples added to the histogram.
- **Description**: The `fd_histf_t` structure is designed to implement a simple, fast, fixed-size exponential histogram. It uses a fixed number of buckets (16) to categorize values exponentially up to a maximum value, with an additional overflow bucket for values exceeding this maximum. The structure maintains an array of counts for each bucket, an array of left edges for bucket boundaries (adjusted for efficient comparison), and a sum of all samples for calculating the mean. This design allows for efficient categorization and statistical analysis of a stream of data values.


# Functions

---
### fd\_histf\_align<!-- {{#callable:fd_histf_align}} -->
The `fd_histf_align` function returns the alignment requirement for the fixed-size exponential histogram data structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests that the function call overhead is minimized by inlining.
    - The function simply returns a constant value, `FD_HISTF_ALIGN`, which is defined as 32UL, indicating the alignment requirement for the histogram structure.
- **Output**: The function returns an unsigned long integer representing the alignment requirement for the histogram data structure.


---
### fd\_histf\_footprint<!-- {{#callable:fd_histf_footprint}} -->
The `fd_histf_footprint` function returns the memory footprint size required for a fixed-size exponential histogram.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests that the function body will be inserted at each call site to reduce function call overhead.
    - The function returns a constant value, `FD_HISTF_FOOTPRINT`, which is a pre-calculated size based on the number of histogram buckets and their alignment requirements.
- **Output**: The function returns an unsigned long integer representing the memory footprint size required for the histogram.


---
### fd\_histf\_new<!-- {{#callable:fd_histf_new}} -->
The `fd_histf_new` function initializes a memory region as a fixed-size exponential histogram with buckets spaced between specified minimum and maximum values.
- **Inputs**:
    - `mem`: A pointer to a memory region that will be formatted as a histogram; it must be non-NULL and properly aligned.
    - `min_value`: The minimum value for the histogram's range, must be greater than 0.
    - `max_value`: The maximum value for the histogram's range, must be greater than or equal to min_value.
- **Control Flow**:
    - Check if max_value is less than or equal to min_value; if so, return NULL.
    - Ensure min_value is at least 1 and adjust max_value to ensure there are enough buckets.
    - Cast the memory region to a histogram structure and initialize the counts to zero and sum to zero.
    - Calculate the left edges of the histogram buckets using exponential spacing, ensuring no bucket is empty.
    - Adjust the left edges by subtracting 2^63 to facilitate signed comparisons.
    - Set the last left edge to LONG_MAX to handle overflow.
    - Return the pointer to the initialized histogram.
- **Output**: A pointer to the initialized histogram structure, or NULL if the input values are invalid.


---
### fd\_histf\_join<!-- {{#callable:fd_histf_join}} -->
The `fd_histf_join` function casts a generic pointer to a specific histogram type pointer.
- **Inputs**:
    - `_hist`: A generic pointer to a memory region that is expected to be formatted as a `fd_histf_t` histogram.
- **Control Flow**:
    - The function takes a single input parameter, `_hist`, which is a void pointer.
    - It casts the input pointer `_hist` to a `fd_histf_t` pointer type.
    - The function returns the casted pointer.
- **Output**: A pointer of type `fd_histf_t *`, which is the input pointer cast to this specific type.


---
### fd\_histf\_leave<!-- {{#callable:fd_histf_leave}} -->
The `fd_histf_leave` function casts a pointer to a `fd_histf_t` histogram structure back to a generic `void` pointer.
- **Inputs**:
    - `_hist`: A pointer to a `fd_histf_t` structure representing a histogram.
- **Control Flow**:
    - The function takes a single argument, `_hist`, which is a pointer to a `fd_histf_t` structure.
    - It returns the same pointer cast to a `void` pointer.
- **Output**: A `void` pointer that is the same as the input pointer, `_hist`, but cast to a generic type.


---
### fd\_histf\_delete<!-- {{#callable:fd_histf_delete}} -->
The `fd_histf_delete` function returns the pointer to the histogram object passed to it, effectively serving as a placeholder for a deletion operation.
- **Inputs**:
    - `_hist`: A pointer to the histogram object that is intended to be deleted or released.
- **Control Flow**:
    - The function takes a single argument, `_hist`, which is a pointer to a histogram object.
    - It returns the same pointer `_hist` without performing any additional operations.
- **Output**: The function returns the same pointer that was passed to it, `_hist`, without any modifications.


---
### fd\_histf\_bucket\_cnt<!-- {{#callable:fd_histf_bucket_cnt}} -->
The `fd_histf_bucket_cnt` function returns the total number of buckets in a fixed-size exponential histogram, including the overflow bucket.
- **Inputs**:
    - `hist`: A pointer to an `fd_histf_t` structure representing the histogram, though it is not used in the function.
- **Control Flow**:
    - The function takes a single argument, `hist`, which is a pointer to an `fd_histf_t` structure, but it is not utilized in the function body.
    - The function returns the constant `FD_HISTF_BUCKET_CNT`, which is defined as 16UL, representing the number of buckets in the histogram.
- **Output**: The function returns an `ulong` value representing the number of buckets in the histogram, which is 16.


---
### fd\_histf\_sample<!-- {{#callable:fd_histf_sample}} -->
The `fd_histf_sample` function adds a sample value to a fixed-size exponential histogram, updating the appropriate bucket count and the total sum of values.
- **Inputs**:
    - `hist`: A pointer to an `fd_histf_t` structure representing the histogram where the sample will be added.
    - `value`: An unsigned long integer representing the sample value to be added to the histogram.
- **Control Flow**:
    - The function begins by adding the input value to the histogram's total sum.
    - The input value is shifted by subtracting 2^63 to facilitate signed comparisons.
    - If AVX is available, the function uses SIMD operations to efficiently determine which histogram bucket the shifted value falls into by comparing it against pre-shifted left edges of the buckets.
    - For each set of four buckets, a selection mask is created to identify the correct bucket, and the corresponding count is incremented by subtracting the mask from the current count.
    - If AVX is not available, a loop iterates over all buckets, incrementing the count of the appropriate bucket based on the shifted value's position relative to the bucket edges.
- **Output**: The function does not return a value; it modifies the histogram in place by updating the sum and the appropriate bucket count.


---
### fd\_histf\_cnt<!-- {{#callable:fd_histf_cnt}} -->
The `fd_histf_cnt` function retrieves the count of samples in a specified bucket of a fixed-size exponential histogram.
- **Inputs**:
    - `hist`: A pointer to a constant `fd_histf_t` structure representing the histogram.
    - `b`: An unsigned long integer representing the index of the bucket for which the sample count is requested.
- **Control Flow**:
    - The function accesses the `counts` array within the `fd_histf_t` structure using the bucket index `b`.
    - It returns the value stored at the specified index `b` in the `counts` array.
- **Output**: The function returns an unsigned long integer representing the number of samples in the specified bucket `b` of the histogram.


---
### fd\_histf\_left<!-- {{#callable:fd_histf_left}} -->
The `fd_histf_left` function returns the left boundary of a specified histogram bucket, adjusted by adding 2^63 to handle unsigned comparisons.
- **Inputs**:
    - `hist`: A pointer to a constant `fd_histf_t` structure representing the histogram.
    - `b`: An unsigned long integer representing the index of the bucket for which the left boundary is requested.
- **Control Flow**:
    - Access the `left_edge` array of the `fd_histf_t` structure using the bucket index `b`.
    - Retrieve the value at `left_edge[b]` and cast it to an unsigned long integer.
    - Add 2^63 to the retrieved value to adjust for the pre-subtraction of 2^63 in the histogram's `left_edge` values.
    - Return the adjusted value as the left boundary of the specified bucket.
- **Output**: The function returns an unsigned long integer representing the left boundary of the specified histogram bucket, adjusted by adding 2^63.


---
### fd\_histf\_right<!-- {{#callable:fd_histf_right}} -->
The `fd_histf_right` function returns the right edge of a specified histogram bucket, adjusted by adding 2^63 to the pre-subtracted value.
- **Inputs**:
    - `hist`: A pointer to a constant `fd_histf_t` structure representing the histogram.
    - `b`: An unsigned long integer representing the index of the bucket for which the right edge is to be retrieved.
- **Control Flow**:
    - Access the `left_edge` array of the `fd_histf_t` structure at index `b+1` to get the pre-subtracted right edge value of the bucket.
    - Convert this value to an unsigned long integer and add 2^63 to adjust for the pre-subtraction done during histogram initialization.
    - Return the adjusted right edge value.
- **Output**: The function returns an unsigned long integer representing the right edge of the specified histogram bucket, adjusted by adding 2^63.


---
### fd\_histf\_sum<!-- {{#callable:fd_histf_sum}} -->
The `fd_histf_sum` function returns the sum of all samples added to a fixed-size exponential histogram.
- **Inputs**:
    - `hist`: A pointer to a constant `fd_histf_t` structure representing the histogram from which the sum of samples is to be retrieved.
- **Control Flow**:
    - The function directly accesses the `sum` field of the `fd_histf_t` structure pointed to by `hist`.
    - It returns the value of the `sum` field, which represents the total sum of all samples added to the histogram.
- **Output**: The function returns an `ulong` representing the sum of all samples added to the histogram.



# Purpose
This C header file, `fd_metrics_base.h`, is designed to define and manage metadata for various types of metrics, specifically gauges, counters, and histograms. It provides a structured way to declare and handle metrics by defining macros and a data structure that encapsulates the properties of each metric type. The file includes definitions for metric types and converters, and it uses macros to facilitate the declaration of metrics with specific attributes such as name, type, description, offset, and conversion method. The macros also support the declaration of histogram metrics with specific range attributes, either in raw form or converted to seconds.

The file defines a `fd_metrics_meta_t` structure, which holds metadata for a metric, including its name, type, description, offset, and conversion method. It also includes a union for histogram-specific data, allowing for different configurations based on the metric's nature. Additionally, the file provides a utility function, [`fd_metrics_meta_type_str`](#fd_metrics_meta_type_str), which returns a string representation of the metric type, enhancing readability and debugging. This header file is intended to be included in other C source files, providing a consistent interface for metric management across a software project.
# Imports and Dependencies

---
- `../../util/fd_util.h`


# Data Structures

---
### fd\_metrics\_meta\_t
- **Type**: `struct`
- **Members**:
    - `name`: A pointer to a constant character string representing the name of the metric.
    - `enum_name`: A pointer to a constant character string representing the name of the enumeration associated with the metric.
    - `enum_variant`: A pointer to a constant character string representing the variant of the enumeration associated with the metric.
    - `type`: An integer representing the type of the metric, such as gauge, counter, or histogram.
    - `desc`: A pointer to a constant character string providing a description of the metric.
    - `offset`: An unsigned long integer representing the offset of the metric.
    - `converter`: An integer indicating the type of conversion applied to the metric, such as none, seconds, or nanoseconds.
    - `histogram`: A union containing histogram-specific data, which can be either 'none' or 'seconds' with respective min and max values.
- **Description**: The `fd_metrics_meta_t` structure is designed to encapsulate metadata about a metric, including its name, type, description, and conversion details. It supports different metric types such as gauge, counter, and histogram, with specific fields for handling enumerations and histogram data. The structure allows for flexible representation of metrics, including the ability to specify conversion types and histogram ranges, making it suitable for a variety of metric tracking and reporting applications.


# Functions

---
### fd\_metrics\_meta\_type\_str<!-- {{#callable:fd_metrics_meta_type_str}} -->
The function `fd_metrics_meta_type_str` returns a string representation of the metric type from a given `fd_metrics_meta_t` structure.
- **Inputs**:
    - `metric`: A pointer to a constant `fd_metrics_meta_t` structure, which contains metadata about a metric, including its type.
- **Control Flow**:
    - The function uses a switch statement to check the `type` field of the `metric` structure.
    - If the `type` is `FD_METRICS_TYPE_GAUGE`, it returns the string "gauge".
    - If the `type` is `FD_METRICS_TYPE_COUNTER`, it returns the string "counter".
    - If the `type` is `FD_METRICS_TYPE_HISTOGRAM`, it returns the string "histogram".
    - For any other `type` value, it returns the string "unknown".
- **Output**: A string representing the type of the metric, which can be "gauge", "counter", "histogram", or "unknown".



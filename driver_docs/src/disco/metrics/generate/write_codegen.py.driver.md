# Purpose
This Python script is designed to automate the generation of C header and source files that define and describe various metrics used in a software system. The script processes metric definitions, which are likely structured as Python objects, and outputs C preprocessor directives and declarations that can be used in a C-based application. The primary functionality of the script is to convert metric information into a format that can be easily integrated into C code, ensuring that metrics are consistently defined and accessible across different parts of the system.

The script includes several key functions that handle different aspects of the code generation process. The [`_write_metric`](#_write_metric) function is responsible for writing individual metric definitions to a file, converting metric names from camel case to snake case, and handling different metric types such as histograms and enumerations. The [`_write_common`](#_write_common), [`_write_tile`](#_write_tile), and [`_write_enums`](#_write_enums) functions organize the generated code into different files based on the type of metrics and their associations with system components, such as tiles or enums. The [`write_codegen`](#write_codegen) function orchestrates the overall process, ensuring that the necessary directories are created and that all metrics are processed and written to the appropriate files. This script is a crucial part of a build system that ensures metrics are accurately and efficiently integrated into the software's C codebase.
# Imports and Dependencies

---
- `.types.*`
- `pathlib.Path`
- `typing.TextIO`
- `os`
- `re`


# Functions

---
### camel2snake<!-- {{#callable:firedancer/src/disco/metrics/generate/write_codegen.camel2snake}} -->
The `camel2snake` function converts a camel case string to a snake case string and returns it in uppercase.
- **Inputs**:
    - `str`: A string in camel case format that needs to be converted to snake case.
- **Control Flow**:
    - Uses a regular expression to identify positions in the string where a lowercase letter is followed by an uppercase letter.
    - Inserts an underscore ('_') at these positions to convert the camel case to snake case.
    - Converts the entire resulting string to uppercase.
- **Output**: Returns the converted string in snake case format, fully in uppercase.


---
### \_write\_metric<!-- {{#callable:firedancer/src/disco/metrics/generate/write_codegen._write_metric}} -->
The `_write_metric` function generates and writes C preprocessor macro definitions for a given metric to a file, based on the metric's type and properties.
- **Inputs**:
    - `f`: A file-like object (TextIO) where the macro definitions will be written.
    - `metric`: An instance of the `Metric` class, representing the metric for which macros are being generated.
    - `prefix`: A string prefix to be used in the macro names, typically indicating the context or category of the metric.
- **Control Flow**:
    - Convert the metric's name from camel case to snake case using the [`camel2snake`](#camel2snake) function.
    - Strip and join the metric's description lines into a single string.
    - Initialize the converter variable to 'NONE'.
    - Check if the metric is an instance of `HistogramMetric` and update the converter variable accordingly.
    - Write several macro definitions to the file, including offset, name, type, description, and converter macros.
    - If the metric is a `GaugeEnumMetric` or `CounterEnumMetric`, write additional macros for each enum value, including count and offset macros.
    - If the metric is a `HistogramMetric`, determine the min and max values based on the converter type and write corresponding macros.
    - Write a newline to the file to separate this metric's macros from others.
- **Output**: The function writes C preprocessor macro definitions to the provided file, defining various properties of the metric such as offset, name, type, description, converter, and additional properties for enum and histogram metrics.
- **Functions called**:
    - [`firedancer/src/disco/metrics/generate/write_codegen.camel2snake`](#camel2snake)


---
### \_write\_metric\_descriptor<!-- {{#callable:firedancer/src/disco/metrics/generate/write_codegen._write_metric_descriptor}} -->
The `_write_metric_descriptor` function writes metric descriptor declarations to a file based on the type of metric provided.
- **Inputs**:
    - `f`: A file-like object where the metric descriptor declarations will be written.
    - `full_name`: A string representing the full name of the metric.
    - `metric`: An instance of the `Metric` class or its subclasses, representing the metric to be described.
- **Control Flow**:
    - Check if the metric is an instance of `CounterMetric` and write a counter metric declaration to the file.
    - Check if the metric is an instance of `GaugeMetric` and write a gauge metric declaration to the file.
    - Check if the metric is an instance of `CounterEnumMetric`, iterate over its enum values, and write counter enum metric declarations to the file for each value.
    - Check if the metric is an instance of `GaugeEnumMetric`, iterate over its enum values, and write gauge enum metric declarations to the file for each value.
    - Check if the metric is an instance of `HistogramMetric` and determine the type of histogram converter to write the appropriate histogram metric declaration to the file.
    - Raise an exception if the histogram converter is unknown.
    - Raise a `ValueError` if the metric type is unknown.
- **Output**: The function does not return any value; it writes metric descriptor declarations to the provided file-like object.
- **Functions called**:
    - [`firedancer/src/disco/metrics/generate/write_codegen.camel2snake`](#camel2snake)


---
### \_write\_common<!-- {{#callable:firedancer/src/disco/metrics/generate/write_codegen._write_common}} -->
The `_write_common` function generates C header and source files for metrics by writing metric definitions and descriptors based on the provided `Metrics` object.
- **Inputs**:
    - `metrics`: An instance of the `Metrics` class containing metric data, including tiles, link_in, link_out, and common metrics.
- **Control Flow**:
    - Open a file `fd_metrics_all.h` for writing in the `../generated` directory.
    - Write a header comment and include a base header file.
    - Iterate over each tile in `metrics.tiles` and include corresponding header files.
    - Write sections for LINK OUT, LINK IN, and TILE metrics, calling [`_write_metric`](#_write_metric) for each metric in these categories.
    - Calculate the total offset for common metrics and write it as a macro definition.
    - Define macros for the total number of LINK IN and LINK OUT metrics and declare external arrays for them.
    - Calculate the maximum offset for tile metrics and define a macro for the total size of metrics.
    - Define macros and declare external arrays for tile kind names, sizes, and metrics.
    - Open a file `fd_metrics_all.c` for writing in the `../generated` directory.
    - Write a header comment and include the generated header file.
    - Write the definition of the `FD_METRICS_ALL` array by iterating over common metrics and calling [`_write_metric_descriptor`](#_write_metric_descriptor).
    - Write the definitions of `FD_METRICS_ALL_LINK_IN` and `FD_METRICS_ALL_LINK_OUT` arrays similarly.
    - Write the definitions of tile kind names, sizes, and metrics arrays by iterating over tiles.
- **Output**: The function outputs two files, `fd_metrics_all.h` and `fd_metrics_all.c`, containing C code with metric definitions and descriptors.
- **Functions called**:
    - [`firedancer/src/disco/metrics/generate/write_codegen._write_metric`](#_write_metric)
    - [`firedancer/src/disco/metrics/generate/types.Metric.footprint`](types.py.driver.md#Metricfootprint)
    - [`firedancer/src/disco/metrics/generate/write_codegen.camel2snake`](#camel2snake)
    - [`firedancer/src/disco/metrics/generate/write_codegen._write_metric_descriptor`](#_write_metric_descriptor)


---
### \_write\_tile<!-- {{#callable:firedancer/src/disco/metrics/generate/write_codegen._write_tile}} -->
The `_write_tile` function generates C header and source files for a specific tile's metrics, defining constants and declarations based on the provided metrics.
- **Inputs**:
    - `tile`: An instance of the `Tile` class representing the tile for which metrics are being generated.
    - `metrics`: A list of `Metric` objects representing the metrics to be written for the specified tile.
- **Control Flow**:
    - Open a header file for writing in the generated directory, named based on the tile's name in lowercase.
    - Write a comment indicating the file is auto-generated and include necessary header files.
    - Iterate over each metric in the `metrics` list and call [`_write_metric`](#_write_metric) to write metric-specific definitions to the header file.
    - Calculate the total count of all metrics and write a `#define` statement for the total metrics count and an `extern` declaration for the metrics array.
    - Open a source file for writing in the generated directory, named based on the tile's name in lowercase.
    - Write a comment indicating the file is auto-generated and include the corresponding header file.
    - Write the definition of the metrics array, iterating over each metric to call [`_write_metric_descriptor`](#_write_metric_descriptor) to write metric-specific descriptors.
    - Close both the header and source files after writing.
- **Output**: The function outputs two files: a header file (`fd_metrics_<tile_name>.h`) and a source file (`fd_metrics_<tile_name>.c`) containing metric definitions and declarations for the specified tile.
- **Functions called**:
    - [`firedancer/src/disco/metrics/generate/write_codegen._write_metric`](#_write_metric)
    - [`firedancer/src/disco/metrics/generate/types.Metric.count`](types.py.driver.md#Metriccount)
    - [`firedancer/src/disco/metrics/generate/write_codegen.camel2snake`](#camel2snake)
    - [`firedancer/src/disco/metrics/generate/write_codegen._write_metric_descriptor`](#_write_metric_descriptor)


---
### \_write\_enums<!-- {{#callable:firedancer/src/disco/metrics/generate/write_codegen._write_enums}} -->
The `_write_enums` function generates a C header file defining macros for metric enumerations based on a list of `MetricEnum` objects.
- **Inputs**:
    - `enums`: A list of `MetricEnum` objects, each representing a set of enumerated values for metrics.
- **Control Flow**:
    - Open a file named 'fd_metrics_enums.h' in the '../generated' directory for writing.
    - Write a comment at the top of the file indicating it is auto-generated and should not be manually edited.
    - Iterate over each `MetricEnum` object in the `enums` list.
    - For each `MetricEnum`, write a macro defining the enum's name in snake case and its count of values.
    - Iterate over each value in the `MetricEnum`'s values list.
    - For each value, write macros defining the index and name of the value in snake case.
    - Write a newline after processing each `MetricEnum`.
- **Output**: The function outputs a C header file containing macro definitions for each metric enumeration and its values.
- **Functions called**:
    - [`firedancer/src/disco/metrics/generate/write_codegen.camel2snake`](#camel2snake)


---
### write\_codegen<!-- {{#callable:firedancer/src/disco/metrics/generate/write_codegen.write_codegen}} -->
The `write_codegen` function generates code files for metrics by creating necessary directories and invoking helper functions to write common metrics, tile-specific metrics, and enums.
- **Inputs**:
    - `metrics`: An instance of the `Metrics` class containing information about various metrics, tiles, and enums to be processed and written to code files.
- **Control Flow**:
    - Create a directory named 'generated' relative to the current file's directory if it does not already exist.
    - Call the [`_write_common`](#_write_common) function to write common metrics data to a file.
    - Iterate over each tile and its associated metrics in `metrics.tiles`, calling [`_write_tile`](#_write_tile) for each to generate tile-specific code files.
    - Call the [`_write_enums`](#_write_enums) function to write enum definitions to a file.
    - Print a summary message indicating the number of metrics and tiles processed.
- **Output**: The function does not return any value; it performs file operations to generate code files and prints a summary message to the console.
- **Functions called**:
    - [`firedancer/src/disco/metrics/generate/write_codegen._write_common`](#_write_common)
    - [`firedancer/src/disco/metrics/generate/write_codegen._write_tile`](#_write_tile)
    - [`firedancer/src/disco/metrics/generate/write_codegen._write_enums`](#_write_enums)
    - [`firedancer/src/disco/metrics/generate/types.Metrics.count`](types.py.driver.md#Metricscount)



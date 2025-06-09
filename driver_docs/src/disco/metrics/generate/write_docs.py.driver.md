# Purpose
This Python code is designed to generate documentation for a set of metrics, outputting the results to a Markdown file. The primary function, [`write_docs`](#write_docs), takes a `Metrics` object as input and writes formatted documentation to a file located at `../../../book/api/metrics-generated.md`. The code processes different categories of metrics, such as `link_out`, `link_in`, and `common`, as well as metrics associated with specific tiles. It uses helper functions like [`_write_metric`](#_write_metric) to format each metric's name, type, and description into a Markdown table format, ensuring that the output is both human-readable and structured for easy inclusion in documentation.

The code leverages regular expressions to convert metric names from camelCase to snake_case, enhancing readability and consistency in the documentation. It also includes HTML elements to style the metric names and tags, which are embedded within the Markdown content. This script is not a standalone application but rather a utility intended to be part of a larger documentation generation process, likely integrated into a build or deployment pipeline. The use of specific imports and the structure of the code suggest that it is part of a broader system for managing and documenting metrics, with a focus on clarity and organization in the generated documentation.
# Imports and Dependencies

---
- `.types.*`
- `typing.TextIO`
- `re`


# Functions

---
### camel2snake<!-- {{#callable:firedancer/src/disco/metrics/generate/write_docs.camel2snake}} -->
The `camel2snake` function converts a camelCase string to a snake_case string.
- **Inputs**:
    - `str`: A string in camelCase format that needs to be converted to snake_case.
- **Control Flow**:
    - Uses a regular expression to identify positions in the string where a lowercase letter is followed by an uppercase letter.
    - Inserts an underscore ('_') before each identified uppercase letter, except if it is the first character of the string.
    - Converts the entire string to lowercase.
- **Output**: A string converted from camelCase to snake_case format.


---
### \_write\_metric<!-- {{#callable:firedancer/src/disco/metrics/generate/write_docs._write_metric}} -->
The `_write_metric` function formats and writes metric information to a file in a specific markdown table format, handling both enum and non-enum metrics.
- **Inputs**:
    - `f`: A file-like object (TextIO) where the metric information will be written.
    - `metric`: An instance of the Metric class, which contains information about the metric to be written.
    - `prefix`: A string prefix to be prepended to the metric name for formatting purposes.
- **Control Flow**:
    - Check if the metric is an instance of CounterEnumMetric or GaugeEnumMetric.
    - If it is an enum metric, iterate over each value in the metric's enum values.
    - For each enum value, convert the metric name and value name from camel case to snake case.
    - Format the metric name and value name with HTML span tags for styling.
    - Construct a full tag string with the formatted value name and replace underscores with a zero-width space for better display.
    - Write a formatted line to the file with the metric name, type, description, and value label.
    - If the metric is not an enum metric, convert the metric name from camel case to snake case.
    - Format the metric name with an HTML span tag for styling.
    - Write a formatted line to the file with the metric name, type, and description.
- **Output**: The function writes formatted metric information to the provided file-like object, with different formats for enum and non-enum metrics.
- **Functions called**:
    - [`firedancer/src/disco/metrics/generate/write_docs.camel2snake`](#camel2snake)


---
### write\_docs<!-- {{#callable:firedancer/src/disco/metrics/generate/write_docs.write_docs}} -->
The `write_docs` function generates a markdown file documenting various metrics by writing formatted metric data into a specified file.
- **Inputs**:
    - `metrics`: An instance of the `Metrics` class containing collections of metrics to be documented, including `link_out`, `link_in`, `common`, and `tiles`.
- **Control Flow**:
    - Open a file located at '../../../book/api/metrics-generated.md' in write mode.
    - Write a section header and preamble for 'All Links' metrics.
    - Iterate over `metrics.link_out` and `metrics.link_in`, writing each metric using the [`_write_metric`](#_write_metric) helper function with the prefix 'link'.
    - Write a closing div tag for the 'All Links' section.
    - Write a section header and preamble for 'All Tiles' metrics.
    - Iterate over `metrics.common`, writing each metric using the [`_write_metric`](#_write_metric) helper function with the prefix 'tile'.
    - Write a closing div tag for the 'All Tiles' section.
    - Iterate over each `Tile` enumeration value, checking if it exists in `metrics.tiles`.
    - For each existing tile, write a section header for the tile, iterate over its metrics, and write each using the [`_write_metric`](#_write_metric) helper function with the tile's name as the prefix.
    - Write a closing div tag for each tile section.
    - Print a message indicating the number of metrics written to the file.
- **Output**: The function outputs a markdown file at the specified path, containing formatted documentation of the metrics, and prints a message to the console indicating the number of metrics written.
- **Functions called**:
    - [`firedancer/src/disco/metrics/generate/write_docs._write_metric`](#_write_metric)
    - [`firedancer/src/disco/metrics/generate/types.Metrics.count`](types.py.driver.md#Metricscount)



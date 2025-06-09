# Purpose
This file is a generated C source file that defines an array of metric metadata, specifically for use with a metrics storage system. It includes a header file, `fd_metrics_storei.h`, which likely contains necessary declarations and definitions for the metrics system. The array `FD_METRICS_STOREI` is initialized with metric entries using the `DECLARE_METRIC` macro, which suggests a standardized way to define metrics, each associated with a type, in this case, `GAUGE`. The file is not meant to be manually edited, as indicated by the comment, and is likely part of a larger system where metrics are programmatically generated and managed.
# Imports and Dependencies

---
- `fd_metrics_storei.h`


# Global Variables

---
### FD\_METRICS\_STOREI
- **Type**: `const fd_metrics_meta_t[]`
- **Description**: FD_METRICS_STOREI is a global constant array of type fd_metrics_meta_t, which is used to store metadata for metrics. The array is initialized with metric declarations for turbine slots, specifically STOREI_FIRST_TURBINE_SLOT and STOREI_CURRENT_TURBINE_SLOT, both of which are of type GAUGE.
- **Use**: This variable is used to define and store metadata for specific metrics related to turbine slots, allowing for consistent access and management of these metrics throughout the program.



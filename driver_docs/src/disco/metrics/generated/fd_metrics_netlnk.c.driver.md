# Purpose
This C source code file is an auto-generated configuration file that defines a collection of network-related metrics for monitoring purposes. It includes an array of `fd_metrics_meta_t` structures, each initialized with specific metrics using macros like `DECLARE_METRIC` and `DECLARE_METRIC_ENUM`. These metrics are categorized as either counters or gauges, and they track various network link statistics such as drop events, full syncs, updates, interface counts, and neighbor probe activities. The file is not meant to be manually edited, as indicated by the comment at the top, and it relies on the inclusion of the "fd_metrics_netlnk.h" header file for necessary type definitions and macro declarations. This setup is typically used in systems that require detailed network performance monitoring and analysis.
# Imports and Dependencies

---
- `fd_metrics_netlnk.h`


# Global Variables

---
### FD\_METRICS\_NETLNK
- **Type**: `const fd_metrics_meta_t[]`
- **Description**: FD_METRICS_NETLNK is a constant array of type fd_metrics_meta_t, which holds metadata for various network link metrics. Each element in the array is initialized using macros like DECLARE_METRIC and DECLARE_METRIC_ENUM, which define different types of metrics such as counters and gauges for network link events and states. The array is used to track and manage metrics related to network link operations, such as drop events, full syncs, updates, and probe activities.
- **Use**: This variable is used to store and manage metadata for network link metrics, facilitating the tracking and analysis of network link performance and events.



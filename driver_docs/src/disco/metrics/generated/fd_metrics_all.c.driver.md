# Purpose
This C source file is a generated code file that defines a comprehensive set of metrics for a system, likely related to performance monitoring or diagnostics. The file includes arrays of `fd_metrics_meta_t` structures, which are used to declare various metrics associated with different components or activities within the system. These metrics are categorized into several groups, such as general tile metrics, link input metrics, and link output metrics. Each metric is defined using macros like `DECLARE_METRIC` and `DECLARE_METRIC_ENUM`, which likely expand to initialize the metric metadata with specific attributes such as type (e.g., GAUGE, COUNTER) and context (e.g., TILE_REGIME).

Additionally, the file defines arrays for tile kind names and their corresponding sizes, which suggest that the system is composed of various functional units or "tiles" such as "net", "quic", "bundle", and others. Each tile kind has an associated set of metrics and a total size, indicating the number of metrics or the scope of monitoring for that tile. This file is not intended to be edited manually, as indicated by the comment at the top, and is likely part of a larger system where it serves as a central repository for metric definitions that can be used by other components for monitoring and analysis purposes.
# Imports and Dependencies

---
- `fd_metrics_all.h`


# Global Variables

---
### FD\_METRICS\_ALL
- **Type**: `const fd_metrics_meta_t[]`
- **Description**: FD_METRICS_ALL is a global constant array of type fd_metrics_meta_t, which holds metadata for various metrics related to system tiles. Each element in the array is defined using macros like DECLARE_METRIC and DECLARE_METRIC_ENUM, specifying the metric type (e.g., GAUGE or COUNTER) and its associated properties. This array is used to track and manage performance metrics for different operational regimes and states of system tiles.
- **Use**: FD_METRICS_ALL is used to store and provide access to a comprehensive set of metrics for monitoring and analyzing the performance of system tiles.


---
### FD\_METRICS\_ALL\_LINK\_IN
- **Type**: `const fd_metrics_meta_t[]`
- **Description**: FD_METRICS_ALL_LINK_IN is a global constant array of type fd_metrics_meta_t, which holds metadata for various link-related metrics. Each element in the array is defined using the DECLARE_METRIC macro, specifying the metric name and its type, such as COUNTER. This array is used to track metrics related to link consumption, filtering, and overruns.
- **Use**: This variable is used to store and organize metadata for link-related metrics, facilitating the monitoring and analysis of link performance.


---
### FD\_METRICS\_ALL\_LINK\_OUT
- **Type**: `const fd_metrics_meta_t[]`
- **Description**: FD_METRICS_ALL_LINK_OUT is a global constant array of type fd_metrics_meta_t, which is used to store metadata for metrics related to outgoing links. It is initialized with a single metric, LINK_SLOW_COUNT, which is categorized as a COUNTER.
- **Use**: This variable is used to define and store metadata for tracking the count of slow outgoing link events.


---
### FD\_METRICS\_TILE\_KIND\_NAMES
- **Type**: `const char *`
- **Description**: `FD_METRICS_TILE_KIND_NAMES` is a global constant array of strings, where each string represents the name of a specific tile kind used in the metrics system. The array is indexed by `FD_METRICS_TILE_KIND_CNT`, which presumably defines the total number of tile kinds available.
- **Use**: This variable is used to provide human-readable names for different tile kinds in the metrics system.


---
### FD\_METRICS\_TILE\_KIND\_SIZES
- **Type**: `const ulong[]`
- **Description**: `FD_METRICS_TILE_KIND_SIZES` is a constant array of unsigned long integers that holds the total size of metrics for each tile kind. The array is indexed by tile kind and each element corresponds to a specific metric total, such as `FD_METRICS_NET_TOTAL`, `FD_METRICS_QUIC_TOTAL`, etc.
- **Use**: This array is used to store and provide quick access to the total size of metrics associated with each tile kind in the system.


---
### FD\_METRICS\_TILE\_KIND\_METRICS
- **Type**: `const fd_metrics_meta_t *`
- **Description**: `FD_METRICS_TILE_KIND_METRICS` is a global array of pointers to `fd_metrics_meta_t` structures, each representing a set of metrics for different tile kinds. The array is indexed by tile kind and contains metrics for various components such as networking, verification, and storage.
- **Use**: This variable is used to access the specific metrics associated with each tile kind in the system.



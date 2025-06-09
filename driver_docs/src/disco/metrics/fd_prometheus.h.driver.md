# Purpose
This C header file defines the interface for rendering metrics in the Prometheus text-based exposition format, specifically for use with an HTTP server. It includes necessary headers for metrics handling, HTTP server operations, and topology management. The file declares two functions: [`fd_prometheus_render_all`](#fd_prometheus_render_all), which formats all metrics for a given topology into the Prometheus format and writes them to an HTTP server's outgoing buffer, and [`fd_prometheus_render_tile`](#fd_prometheus_render_tile), which performs a similar operation for individual tiles within the topology. This header is part of a larger system that likely involves monitoring and exporting metrics for distributed systems, leveraging Prometheus for metrics exposition.
# Imports and Dependencies

---
- `fd_metrics_base.h`
- `../../waltz/http/fd_http_server.h`
- `../topo/fd_topo.h`


# Function Declarations (Public API)

---
### fd\_prometheus\_render\_all<!-- {{#callable_declaration:fd_prometheus_render_all}} -->
Format all metrics for a topology into Prometheus exposition format.
- **Description**: This function formats all metrics associated with a given topology into the Prometheus text-based exposition format and writes them to the outgoing ring buffer of the specified HTTP server. It is intended to be used when you need to expose metrics for monitoring purposes in a format that Prometheus can scrape. The function should be called when the topology is fully initialized and ready to have its metrics exposed. Ensure that the HTTP server is properly set up to handle the outgoing data.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure representing the topology whose metrics are to be formatted. The pointer must not be null, and the topology should be fully initialized.
    - `http`: A pointer to an `fd_http_server_t` structure representing the HTTP server where the formatted metrics will be written. The pointer must not be null, and the server should be ready to handle outgoing data.
- **Output**: None
- **See also**: [`fd_prometheus_render_all`](fd_prometheus.c.driver.md#fd_prometheus_render_all)  (Implementation)


---
### fd\_prometheus\_render\_tile<!-- {{#callable_declaration:fd_prometheus_render_tile}} -->
Format metrics for a specific topology tile into Prometheus exposition format.
- **Description**: This function formats a set of metrics associated with a specific topology tile into the Prometheus text-based exposition format and writes the result into the HTTP server's outgoing ring buffer. It is intended to be used when you need to expose metrics for a particular tile in a topology to a Prometheus server. The function should be called with a valid HTTP server instance and a non-null tile and metrics array. The number of metrics to be formatted is specified by the metrics_cnt parameter. Ensure that the HTTP server is properly initialized before calling this function.
- **Inputs**:
    - `http`: A pointer to an fd_http_server_t instance where the formatted metrics will be written. Must not be null. The caller retains ownership.
    - `tile`: A pointer to an fd_topo_tile_t instance representing the topology tile for which metrics are being formatted. Must not be null. The caller retains ownership.
    - `metrics`: A pointer to an array of fd_metrics_meta_t instances representing the metrics to be formatted. Must not be null. The caller retains ownership.
    - `metrics_cnt`: The number of metrics in the metrics array to be formatted. Must be a non-negative integer.
- **Output**: None
- **See also**: [`fd_prometheus_render_tile`](fd_prometheus.c.driver.md#fd_prometheus_render_tile)  (Implementation)



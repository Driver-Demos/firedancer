# Purpose
This C source code file is designed to facilitate the rendering of metrics in a format compatible with Prometheus, a popular open-source monitoring and alerting toolkit. The code is structured around the `fd_prom_render_t` structure, which is used to manage the state of the rendering process, including the HTTP server connection and the last processed metric name hash. The primary functionality of this file is to convert various types of metrics, such as counters, histograms, and links, into a textual format that Prometheus can scrape and interpret. This is achieved through a series of static functions that handle different metric types and their specific rendering requirements, such as [`render_counter`](#render_counter), [`render_histogram`](#render_histogram), and [`render_link`](#render_link).

The file includes functions like [`fd_prometheus_render_tile`](#fd_prometheus_render_tile) and [`fd_prometheus_render_all`](#fd_prometheus_render_all), which serve as public interfaces for rendering metrics for individual tiles or the entire topology, respectively. These functions utilize the static rendering functions to output the metrics data to an HTTP server, which Prometheus can then access. The code relies on several external components, such as `fd_http_server_t` for HTTP communication and `fd_metrics_meta_t` for metric metadata, indicating that it is part of a larger system. The inclusion of headers like `fd_metrics.h` and `fd_http_server.h` suggests that this file is intended to be part of a broader library or application, providing specialized functionality for metrics rendering within a networked environment.
# Imports and Dependencies

---
- `fd_prometheus.h`
- `fd_metrics.h`
- `../topo/fd_topo.h`
- `../../waltz/http/fd_http_server.h`


# Data Structures

---
### fd\_prom\_render
- **Type**: `struct`
- **Members**:
    - `http`: A pointer to an fd_http_server_t structure, representing the HTTP server used for rendering.
    - `last_name_hash`: An unsigned long integer storing the hash of the last metric name rendered, used to avoid redundant header rendering.
- **Description**: The `fd_prom_render` structure is designed to facilitate the rendering of Prometheus metrics over HTTP. It contains a pointer to an HTTP server, which is used to output the metrics, and a hash of the last metric name rendered, which helps in optimizing the rendering process by preventing duplicate headers for the same metric name. This structure is central to the rendering functions that output various types of metrics, such as counters, histograms, and links, ensuring that the metrics are formatted correctly for Prometheus consumption.


---
### fd\_prom\_render\_t
- **Type**: `struct`
- **Members**:
    - `http`: A pointer to an fd_http_server_t structure, representing the HTTP server used for rendering.
    - `last_name_hash`: An unsigned long integer storing the hash of the last metric name rendered.
- **Description**: The `fd_prom_render_t` structure is designed to facilitate the rendering of Prometheus metrics over HTTP. It contains a pointer to an HTTP server, which is used to output the rendered metrics, and a hash of the last metric name, which helps in optimizing the rendering process by avoiding redundant header outputs for the same metric name. This structure is central to the functions that render different types of metrics, such as counters, histograms, and links, ensuring that the metrics are formatted correctly for Prometheus consumption.


# Functions

---
### fd\_prom\_render\_create<!-- {{#callable:fd_prom_render_create}} -->
The `fd_prom_render_create` function initializes and returns a `fd_prom_render_t` structure with a given HTTP server pointer and a default last name hash value.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` structure, representing the HTTP server to be associated with the `fd_prom_render_t` instance.
- **Control Flow**:
    - The function takes a single argument, `http`, which is a pointer to an `fd_http_server_t` structure.
    - It returns a `fd_prom_render_t` structure initialized with the `http` pointer and a `last_name_hash` set to 0UL.
- **Output**: A `fd_prom_render_t` structure initialized with the provided HTTP server pointer and a `last_name_hash` of 0UL.


---
### render\_header<!-- {{#callable:render_header}} -->
The `render_header` function outputs a header for a metric to an HTTP server, ensuring it is only rendered once per unique metric name.
- **Inputs**:
    - `r`: A pointer to an `fd_prom_render_t` structure, which contains the HTTP server context and the last rendered metric name hash.
    - `metric`: A pointer to a constant `fd_metrics_meta_t` structure, which contains metadata about the metric, including its name and description.
- **Control Flow**:
    - Calculate the hash of the metric's name using `fd_cstr_hash`.
    - Check if the current metric's name hash is different from the last rendered name hash stored in `r->last_name_hash`.
    - If the hashes differ, check if `r->last_name_hash` is non-zero, indicating a previous metric was rendered, and print a newline to the HTTP server.
    - Print the metric's HELP and TYPE information to the HTTP server using `fd_http_server_printf`.
    - Update `r->last_name_hash` with the current metric's name hash.
- **Output**: The function does not return a value; it outputs formatted metric header information to the HTTP server.
- **Functions called**:
    - [`fd_metrics_meta_type_str`](fd_metrics_base.h.driver.md#fd_metrics_meta_type_str)


---
### render\_link<!-- {{#callable:render_link}} -->
The `render_link` function formats and sends a metric value related to a network link to an HTTP server, converting the value if necessary based on the metric's converter type.
- **Inputs**:
    - `r`: A pointer to an `fd_prom_render_t` structure, which contains the HTTP server context for rendering.
    - `metric`: A constant pointer to an `fd_metrics_meta_t` structure, which holds metadata about the metric being rendered, including its name, description, and converter type.
    - `tile`: A constant pointer to an `fd_topo_tile_t` structure, representing the tile (or node) in the topology associated with the metric.
    - `link`: A constant pointer to an `fd_topo_link_t` structure, representing the link in the topology associated with the metric.
    - `value`: An unsigned long integer representing the metric value to be rendered, which may be converted based on the metric's converter type.
- **Control Flow**:
    - Call [`render_header`](#render_header) to ensure the metric header is rendered if it hasn't been already.
    - Check the `converter` field of the `metric` to determine if the `value` needs conversion.
    - If the converter is `FD_METRICS_CONVERTER_NANOSECONDS`, convert `value` from ticks to nanoseconds using [`fd_metrics_convert_ticks_to_nanoseconds`](fd_metrics.h.driver.md#fd_metrics_convert_ticks_to_nanoseconds).
    - If the converter is `FD_METRICS_CONVERTER_NONE`, do nothing to `value`.
    - If the converter is unknown, log an error using `FD_LOG_ERR`.
    - Format and send the metric data to the HTTP server using `fd_http_server_printf`, including the metric name, tile and link identifiers, and the (possibly converted) value.
- **Output**: The function does not return a value; it outputs formatted metric data to the HTTP server specified in the `fd_prom_render_t` structure.
- **Functions called**:
    - [`render_header`](#render_header)
    - [`fd_metrics_convert_ticks_to_nanoseconds`](fd_metrics.h.driver.md#fd_metrics_convert_ticks_to_nanoseconds)


---
### render\_histogram<!-- {{#callable:render_histogram}} -->
The `render_histogram` function generates and sends a formatted histogram representation of metric data to an HTTP server for a specific tile.
- **Inputs**:
    - `r`: A pointer to an `fd_prom_render_t` structure, which contains the HTTP server context for rendering.
    - `metric`: A constant pointer to an `fd_metrics_meta_t` structure, which holds metadata about the metric to be rendered.
    - `tile`: A constant pointer to an `fd_topo_tile_t` structure, representing the tile for which the histogram is being rendered.
- **Control Flow**:
    - Call [`render_header`](#render_header) to output the header for the metric if it hasn't been rendered yet.
    - Initialize a histogram object `hist` based on the metric's converter type, either converting seconds to ticks or using raw values.
    - Iterate over each bucket in the histogram, accumulating values from the tile's metrics and formatting the bucket's upper edge value.
    - For each bucket, format and send the bucket's data to the HTTP server using `fd_http_server_printf`.
    - Calculate and format the sum of all values in the histogram, then send this data to the HTTP server.
    - Send the total count of values in the histogram to the HTTP server.
- **Output**: The function outputs formatted histogram data, including bucket values, sum, and count, to the specified HTTP server.
- **Functions called**:
    - [`render_header`](#render_header)
    - [`fd_metrics_convert_seconds_to_ticks`](fd_metrics.h.driver.md#fd_metrics_convert_seconds_to_ticks)
    - [`fd_metrics_tile`](fd_metrics.h.driver.md#fd_metrics_tile)
    - [`fd_metrics_convert_ticks_to_seconds`](fd_metrics.h.driver.md#fd_metrics_convert_ticks_to_seconds)


---
### render\_counter<!-- {{#callable:render_counter}} -->
The `render_counter` function formats and sends a counter metric's data to an HTTP server for Prometheus monitoring.
- **Inputs**:
    - `r`: A pointer to an `fd_prom_render_t` structure, which contains the HTTP server context for rendering.
    - `metric`: A constant pointer to an `fd_metrics_meta_t` structure, which holds metadata about the metric being rendered.
    - `tile`: A constant pointer to an `fd_topo_tile_t` structure, which represents the tile associated with the metric.
- **Control Flow**:
    - Call [`render_header`](#render_header) to ensure the metric's header is rendered if it hasn't been already.
    - Retrieve the metric's value from the tile's metrics using the metric's offset.
    - Format and send the metric's name, kind, and kind_id to the HTTP server using `fd_http_server_printf`.
    - If the metric has an `enum_name`, append it and its variant to the output.
    - Finally, append the metric's value to the output and send it to the HTTP server.
- **Output**: The function does not return a value; it outputs formatted metric data to the HTTP server specified in the `fd_prom_render_t` structure.
- **Functions called**:
    - [`render_header`](#render_header)
    - [`fd_metrics_tile`](fd_metrics.h.driver.md#fd_metrics_tile)


---
### render\_links\_in<!-- {{#callable:render_links_in}} -->
The `render_links_in` function iterates over metrics and topology tiles to render incoming link metrics using a specified rendering context.
- **Inputs**:
    - `r`: A pointer to an `fd_prom_render_t` structure, which contains the rendering context for HTTP output.
    - `topo`: A pointer to a constant `fd_topo_t` structure, representing the topology of tiles and links.
    - `metrics_cnt`: An unsigned long integer representing the number of metrics to process.
    - `metrics`: A pointer to an array of constant `fd_metrics_meta_t` structures, each describing a metric to be rendered.
- **Control Flow**:
    - Iterate over each metric in the `metrics` array using a loop indexed by `i`.
    - For each metric, iterate over each tile in the topology using a loop indexed by `j`.
    - Initialize `polled_in_idx` to zero for tracking polled incoming links.
    - For each tile, iterate over its incoming links using a loop indexed by `k`.
    - Check if the incoming link is polled using `tile->in_link_poll[k]`; if not, continue to the next link.
    - Retrieve the link information from the topology using `tile->in_link_id[k]`.
    - Calculate the metric value for the link using [`fd_metrics_link_in`](fd_metrics.h.driver.md#fd_metrics_link_in) and the metric's offset.
    - Call [`render_link`](#render_link) to render the metric for the current link, tile, and metric value.
    - Increment `polled_in_idx` after processing a polled link.
- **Output**: The function does not return a value; it performs rendering operations as a side effect.
- **Functions called**:
    - [`fd_metrics_link_in`](fd_metrics.h.driver.md#fd_metrics_link_in)
    - [`render_link`](#render_link)


---
### render\_links\_out<!-- {{#callable:render_links_out}} -->
The `render_links_out` function iterates over metrics and topology tiles to render outgoing link metrics for reliable connections using a Prometheus renderer.
- **Inputs**:
    - `r`: A pointer to an `fd_prom_render_t` structure used for rendering metrics.
    - `topo`: A constant pointer to an `fd_topo_t` structure representing the topology of tiles and links.
    - `metrics_cnt`: An unsigned long integer representing the number of metrics to process.
    - `metrics`: A constant pointer to an array of `fd_metrics_meta_t` structures containing metadata for each metric.
- **Control Flow**:
    - Iterate over each metric in the `metrics` array using a loop indexed by `i`.
    - For each metric, iterate over each tile in the topology using a loop indexed by `j`.
    - Initialize `reliable_conns_idx` to zero for tracking reliable connections.
    - For each tile, iterate over each consumer tile in the topology using a loop indexed by `k`.
    - For each consumer tile, iterate over its input links using a loop indexed by `l`.
    - For each input link, iterate over the current tile's output links using a loop indexed by `m`.
    - Check if the consumer tile's input link ID matches the current tile's output link ID and if the input link is reliable.
    - If the condition is met, retrieve the link from the topology and calculate the metric value using [`fd_metrics_link_out`](fd_metrics.h.driver.md#fd_metrics_link_out).
    - Call [`render_link`](#render_link) to render the metric for the reliable connection and increment `reliable_conns_idx`.
- **Output**: The function does not return a value; it performs rendering operations as a side effect.
- **Functions called**:
    - [`fd_metrics_link_out`](fd_metrics.h.driver.md#fd_metrics_link_out)
    - [`render_link`](#render_link)


---
### render\_tile\_metric<!-- {{#callable:render_tile_metric}} -->
The `render_tile_metric` function renders a metric for a given tile based on its type, either as a counter or histogram.
- **Inputs**:
    - `r`: A pointer to an `fd_prom_render_t` structure, which contains rendering context information.
    - `tile`: A pointer to a `fd_topo_tile_t` structure representing the tile for which the metric is being rendered.
    - `metric`: A pointer to a `fd_metrics_meta_t` structure representing the metric to be rendered.
- **Control Flow**:
    - Check if the metric type is either `FD_METRICS_TYPE_COUNTER` or `FD_METRICS_TYPE_GAUGE` using `FD_LIKELY` macro.
    - If true, call [`render_counter`](#render_counter) to render the metric as a counter.
    - Otherwise, check if the metric type is `FD_METRICS_TYPE_HISTOGRAM` using `FD_LIKELY` macro.
    - If true, call [`render_histogram`](#render_histogram) to render the metric as a histogram.
- **Output**: The function does not return a value; it performs rendering operations based on the metric type.
- **Functions called**:
    - [`render_counter`](#render_counter)
    - [`render_histogram`](#render_histogram)


---
### render\_tile<!-- {{#callable:render_tile}} -->
The `render_tile` function iterates over a set of metrics and tiles, rendering metrics for a specific tile if its name matches the provided `tile_name`.
- **Inputs**:
    - `r`: A pointer to an `fd_prom_render_t` structure used for rendering metrics.
    - `topo`: A constant pointer to an `fd_topo_t` structure representing the topology of tiles.
    - `tile_name`: A constant character pointer representing the name of the tile to render metrics for; if NULL, metrics for all tiles are rendered.
    - `metrics_cnt`: An unsigned long integer representing the number of metrics to process.
    - `metrics`: A constant pointer to an array of `fd_metrics_meta_t` structures containing metadata for each metric.
- **Control Flow**:
    - The function iterates over each metric in the `metrics` array using a loop indexed by `i`.
    - For each metric, it iterates over each tile in the `topo->tiles` array using a loop indexed by `j`.
    - Within the inner loop, it checks if `tile_name` is not NULL and if the current tile's name does not match `tile_name`; if so, it continues to the next tile.
    - If the tile name matches or `tile_name` is NULL, it calls [`render_tile_metric`](#render_tile_metric) to render the metric for the current tile.
- **Output**: The function does not return a value; it performs rendering operations as a side effect.
- **Functions called**:
    - [`render_tile_metric`](#render_tile_metric)


---
### fd\_prometheus\_render\_tile<!-- {{#callable:fd_prometheus_render_tile}} -->
The `fd_prometheus_render_tile` function renders Prometheus metrics for a specific tile using a given HTTP server.
- **Inputs**:
    - `http`: A pointer to an `fd_http_server_t` structure, representing the HTTP server to which the metrics will be rendered.
    - `tile`: A constant pointer to an `fd_topo_tile_t` structure, representing the tile for which metrics are to be rendered.
    - `metrics`: A constant pointer to an array of `fd_metrics_meta_t` structures, representing the metadata of the metrics to be rendered.
    - `metrics_cnt`: An unsigned long integer representing the number of metrics in the `metrics` array.
- **Control Flow**:
    - Create a `fd_prom_render_t` object `r` using [`fd_prom_render_create`](#fd_prom_render_create) with the provided `http` server.
    - Iterate over each metric in the `metrics` array, up to `metrics_cnt`.
    - For each metric, call [`render_tile_metric`](#render_tile_metric) with the `fd_prom_render_t` object `r`, the `tile`, and the current metric.
- **Output**: The function does not return a value; it performs rendering operations directly on the provided HTTP server.
- **Functions called**:
    - [`fd_prom_render_create`](#fd_prom_render_create)
    - [`render_tile_metric`](#render_tile_metric)


---
### fd\_prometheus\_render\_all<!-- {{#callable:fd_prometheus_render_all}} -->
The `fd_prometheus_render_all` function renders all metrics for a given topology to an HTTP server in Prometheus format.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure representing the topology for which metrics are to be rendered.
    - `http`: A pointer to an `fd_http_server_t` structure representing the HTTP server where the metrics will be rendered.
- **Control Flow**:
    - Create a `fd_prom_render_t` object using the provided HTTP server.
    - Call [`render_tile`](#render_tile) to render all metrics for the entire topology.
    - Call [`render_links_in`](#render_links_in) to render metrics for incoming links in the topology.
    - Call [`render_links_out`](#render_links_out) to render metrics for outgoing links in the topology.
    - Iterate over each tile kind and call [`render_tile`](#render_tile) to render metrics specific to each tile kind.
- **Output**: The function does not return a value; it outputs metrics data to the specified HTTP server.
- **Functions called**:
    - [`fd_prom_render_create`](#fd_prom_render_create)
    - [`render_tile`](#render_tile)
    - [`render_links_in`](#render_links_in)
    - [`render_links_out`](#render_links_out)



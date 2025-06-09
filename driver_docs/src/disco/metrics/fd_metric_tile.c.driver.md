# Purpose
This C source code file is designed to set up and manage an HTTP server that serves Prometheus metrics. The primary functionality revolves around initializing and configuring an HTTP server to handle requests specifically for metrics collection, which is a common requirement in monitoring and observability systems. The code includes the setup of server parameters, such as maximum connections and buffer sizes, and defines the behavior for handling HTTP GET requests to the "/metrics" endpoint. The server is configured to respond with metrics data in a format compatible with Prometheus, a popular open-source monitoring and alerting toolkit.

The file integrates several components, including network and HTTP server utilities, and uses conditional compilation to include architecture-specific security policies. It defines a context structure (`fd_metric_ctx_t`) to maintain server state and uses a scratch memory allocation pattern for efficient resource management. The code also includes functions for initializing the server in both privileged and unprivileged modes, setting up security policies with seccomp filters, and managing file descriptors. The inclusion of a stem callback mechanism suggests that this code is part of a larger framework or application, where it acts as a module responsible for metrics collection and exposure. The file does not define a public API but rather serves as an internal component within a broader system architecture.
# Imports and Dependencies

---
- `fd_prometheus.h`
- `../../waltz/http/fd_http_server.h`
- `../../util/net/fd_ip4.h`
- `sys/types.h`
- `sys/socket.h`
- `unistd.h`
- `string.h`
- `generated/fd_metric_tile_arm64_seccomp.h`
- `generated/fd_metric_tile_seccomp.h`
- `../stem/fd_stem.c`


# Global Variables

---
### METRICS\_PARAMS
- **Type**: `fd_http_server_params_t`
- **Description**: `METRICS_PARAMS` is a constant global variable of type `fd_http_server_params_t` that defines the configuration parameters for an HTTP server dedicated to handling metrics. It specifies limits on the number of connections, request lengths, and buffer sizes for outgoing data.
- **Use**: This variable is used to configure the HTTP server that serves metrics, ensuring it operates within defined resource constraints.


---
### fd\_tile\_metric
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_metric` is a global variable of type `fd_topo_run_tile_t` that is configured to manage the execution of a metrics tile in a topology. It includes settings for resource limits, security policies, and initialization routines for both privileged and unprivileged contexts.
- **Use**: This variable is used to define and control the behavior of a metrics tile, including its resource limits, security configurations, and initialization processes.


# Data Structures

---
### fd\_metric\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `topo`: A pointer to an fd_topo_t structure, representing the topology context.
    - `metrics_server`: A pointer to an fd_http_server_t structure, representing the HTTP server for metrics.
- **Description**: The `fd_metric_ctx_t` structure is designed to encapsulate the context required for managing metrics in a system. It includes a pointer to a topology context (`fd_topo_t`) and a pointer to an HTTP server (`fd_http_server_t`) that serves metrics. This structure is used to facilitate the integration of Prometheus metrics by providing the necessary context for rendering and serving metrics over HTTP.


# Functions

---
### scratch\_align<!-- {{#callable:scratch_align}} -->
The `scratch_align` function returns a constant alignment value of 128 bytes.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests the compiler to inline it for performance.
    - The function is marked with `FD_FN_CONST`, indicating that it has no side effects and its return value depends only on its parameters (though it takes no parameters in this case).
    - The function simply returns the constant value `128UL`.
- **Output**: The function returns an unsigned long integer with the value 128, representing an alignment size.


---
### scratch\_footprint<!-- {{#callable:scratch_footprint}} -->
The `scratch_footprint` function calculates the memory footprint required for a scratch space used by a metrics server and its context.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, which is not used in the function but is part of the function signature.
- **Control Flow**:
    - Initialize a variable `l` with `FD_LAYOUT_INIT` to start the layout calculation.
    - Append the alignment and size of `fd_metric_ctx_t` to `l` using `FD_LAYOUT_APPEND`.
    - Append the alignment and footprint of an HTTP server, configured with `METRICS_PARAMS`, to `l` using `FD_LAYOUT_APPEND`.
    - Finalize the layout calculation with `FD_LAYOUT_FINI`, using the alignment from `scratch_align()`, and return the result.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the scratch space.
- **Functions called**:
    - [`scratch_align`](#scratch_align)


---
### before\_credit<!-- {{#callable:before_credit}} -->
The `before_credit` function updates the `charge_busy` variable with the result of polling the HTTP server for incoming connections or requests.
- **Inputs**:
    - `ctx`: A pointer to an `fd_metric_ctx_t` structure, which contains the context for the metrics server.
    - `stem`: A pointer to an `fd_stem_context_t` structure, which is not used in this function.
    - `charge_busy`: A pointer to an integer where the result of the HTTP server poll will be stored.
- **Control Flow**:
    - The function begins by explicitly ignoring the `stem` parameter using a cast to void, indicating it is not used.
    - The function calls `fd_http_server_poll` with the metrics server from the `ctx` and a timeout of 1 millisecond.
    - The result of the poll is stored in the integer pointed to by `charge_busy`.
- **Output**: The function does not return a value, but it modifies the integer pointed to by `charge_busy` to reflect the result of the server poll.


---
### metrics\_http\_request<!-- {{#callable:metrics_http_request}} -->
The `metrics_http_request` function processes HTTP GET requests to the '/metrics' endpoint, rendering Prometheus metrics and returning appropriate HTTP responses based on the request method and path.
- **Inputs**:
    - `request`: A pointer to a `fd_http_server_request_t` structure representing the incoming HTTP request, containing information such as the request method, path, and context.
- **Control Flow**:
    - Retrieve the context from the request's context field and cast it to `fd_metric_ctx_t`.
    - Check if the request method is not GET; if so, return a 400 Bad Request response.
    - Check if the request path is '/metrics'; if so, proceed to render Prometheus metrics using [`fd_prometheus_render_all`](fd_prometheus.c.driver.md#fd_prometheus_render_all).
    - Prepare a 200 OK response with content type 'text/plain; version=0.0.4'.
    - Attempt to stage the response body using `fd_http_server_stage_body`; if it fails, log a warning and return a 500 Internal Server Error response.
    - If the request path is not '/metrics', return a 404 Not Found response.
- **Output**: The function returns an `fd_http_server_response_t` structure representing the HTTP response, with status codes 200, 400, 404, or 500 depending on the request's validity and processing outcome.
- **Functions called**:
    - [`fd_prometheus_render_all`](fd_prometheus.c.driver.md#fd_prometheus_render_all)


---
### privileged\_init<!-- {{#callable:privileged_init}} -->
The `privileged_init` function initializes a metrics server for a given topology and tile, setting up necessary memory allocations and server configurations.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile configuration, including metrics listening address and port.
- **Control Flow**:
    - Retrieve a scratch memory address using `fd_topo_obj_laddr` with the topology and tile object ID.
    - Initialize the scratch allocator with `FD_SCRATCH_ALLOC_INIT`.
    - Allocate memory for a `fd_metric_ctx_t` structure using `FD_SCRATCH_ALLOC_APPEND`.
    - Allocate memory for an HTTP server using `FD_SCRATCH_ALLOC_APPEND` with alignment and footprint parameters.
    - Define HTTP server callbacks, specifically setting the request callback to `metrics_http_request`.
    - Create a new HTTP server instance with `fd_http_server_new`, passing the allocated server memory, parameters, callbacks, and context.
    - Join the HTTP server to the context using `fd_http_server_join`.
    - Set the server to listen on the specified address and port from the tile's metrics configuration using `fd_http_server_listen`.
- **Output**: The function does not return a value; it sets up the metrics server within the provided context.


---
### unprivileged\_init<!-- {{#callable:unprivileged_init}} -->
The `unprivileged_init` function initializes a metric context for a given topology and tile, ensuring memory allocation does not exceed the available scratch space, and logs the Prometheus metrics endpoint address.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile configuration, including its object ID and metrics settings.
- **Control Flow**:
    - Retrieve the local address of the tile object using `fd_topo_obj_laddr` and store it in `scratch`.
    - Initialize the scratch memory allocator with `FD_SCRATCH_ALLOC_INIT`.
    - Allocate memory for an `fd_metric_ctx_t` structure within the scratch space using `FD_SCRATCH_ALLOC_APPEND`.
    - Assign the `topo` pointer to the `topo` field of the allocated `fd_metric_ctx_t` structure.
    - Finalize the scratch allocation with `FD_SCRATCH_ALLOC_FINI` and check if the allocated memory exceeds the available scratch space using [`scratch_footprint`](#scratch_footprint).
    - If a scratch overflow is detected, log an error message with `FD_LOG_ERR`.
    - Log a warning message indicating the Prometheus metrics endpoint address and port using `FD_LOG_WARNING`.
- **Output**: The function does not return a value; it performs initialization and logging as side effects.
- **Functions called**:
    - [`scratch_footprint`](#scratch_footprint)


---
### populate\_allowed\_seccomp<!-- {{#callable:populate_allowed_seccomp}} -->
The `populate_allowed_seccomp` function initializes a scratch memory area, sets up a metrics context, and populates a seccomp filter policy for a given tile.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to a `fd_topo_tile_t` structure representing the specific tile configuration.
    - `out_cnt`: An unsigned long integer representing the count of output seccomp filter entries.
    - `out`: A pointer to an array of `struct sock_filter` where the seccomp filter policy will be populated.
- **Control Flow**:
    - Retrieve a scratch memory address using `fd_topo_obj_laddr` with the given topology and tile object ID.
    - Initialize the scratch memory allocation using `FD_SCRATCH_ALLOC_INIT`.
    - Allocate memory for a `fd_metric_ctx_t` structure within the scratch space using `FD_SCRATCH_ALLOC_APPEND`.
    - Call [`populate_sock_filter_policy_fd_metric_tile`](generated/fd_metric_tile_seccomp.h.driver.md#populate_sock_filter_policy_fd_metric_tile) to populate the seccomp filter policy using the provided output count, filter array, and file descriptors for logging and metrics server.
    - Return the instruction count from `sock_filter_policy_fd_metric_tile_instr_cnt`.
- **Output**: The function returns an unsigned long integer representing the number of instructions in the populated seccomp filter policy.
- **Functions called**:
    - [`populate_sock_filter_policy_fd_metric_tile`](generated/fd_metric_tile_seccomp.h.driver.md#populate_sock_filter_policy_fd_metric_tile)


---
### populate\_allowed\_fds<!-- {{#callable:populate_allowed_fds}} -->
The `populate_allowed_fds` function populates an array with file descriptors that are allowed for use, including standard error, a log file, and a metrics server socket.
- **Inputs**:
    - `topo`: A pointer to a `fd_topo_t` structure representing the topology.
    - `tile`: A pointer to a `fd_topo_tile_t` structure representing the tile configuration.
    - `out_fds_cnt`: An unsigned long integer representing the maximum number of file descriptors that can be stored in the `out_fds` array.
    - `out_fds`: A pointer to an integer array where the allowed file descriptors will be stored.
- **Control Flow**:
    - Allocate scratch memory using `fd_topo_obj_laddr` and initialize it with `FD_SCRATCH_ALLOC_INIT`.
    - Append a `fd_metric_ctx_t` structure to the scratch memory using `FD_SCRATCH_ALLOC_APPEND`.
    - Check if `out_fds_cnt` is less than 3, and log an error if true.
    - Initialize `out_cnt` to 0 and set `out_fds[0]` to 2, which corresponds to the standard error file descriptor.
    - Check if the log file descriptor is valid (not -1) and, if so, add it to `out_fds` and increment `out_cnt`.
    - Add the metrics server file descriptor to `out_fds` and increment `out_cnt`.
    - Return the count of file descriptors added to `out_fds`.
- **Output**: The function returns an unsigned long integer representing the number of file descriptors added to the `out_fds` array.



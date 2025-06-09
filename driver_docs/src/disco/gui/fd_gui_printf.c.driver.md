# Purpose
The provided C source code file is designed to facilitate the generation and formatting of JSON data for a graphical user interface (GUI) in a networked application. The file includes a series of functions that construct JSON objects and arrays, which are then used to represent various data points and states within the application. These functions are primarily used to format data related to network peers, transaction statistics, slot information, and other metrics into JSON format, which can be easily consumed by a GUI for display purposes. The code is structured to handle different data types, such as strings, integers, and floating-point numbers, and includes mechanisms for handling special cases, such as null values and data sanitization.

The file is not a standalone executable but rather a component of a larger system, likely intended to be included in a larger application that manages network communications and data visualization. It defines a set of static and non-static functions that serve as an internal API for formatting and outputting JSON data. The functions are organized around specific tasks, such as opening and closing JSON objects and arrays, and formatting specific data types like unsigned long integers, doubles, and strings. The code also includes conditional compilation directives to manage dependencies and versioning information, ensuring compatibility with different build environments. Overall, this file plays a crucial role in the data presentation layer of the application, enabling the conversion of complex data structures into a standardized JSON format for GUI consumption.
# Imports and Dependencies

---
- `ctype.h`
- `stdio.h`
- `fd_gui_printf.h`
- `../../waltz/http/fd_http_server_private.h`
- `../../ballet/utf8/fd_utf8.h`
- `../../app/fdctl/version.h`


# Functions

---
### jsonp\_open\_object<!-- {{#callable:jsonp_open_object}} -->
This function opens a JSON object in a JSONP response format, optionally including a key.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the state and context for the GUI and HTTP server.
    - `key`: A constant character pointer representing the key to be included in the JSON object; if NULL, no key is included.
- **Control Flow**:
    - The function first checks if the `key` is likely to be non-null using the `FD_LIKELY` macro.
    - If the `key` is valid, it formats and sends a JSON string with the key followed by an opening brace '{'.
    - If the `key` is NULL, it sends just an opening brace '{' without a key.
- **Output**: The function does not return a value; instead, it outputs a formatted string to the HTTP server's response stream.


---
### jsonp\_close\_object<!-- {{#callable:jsonp_close_object}} -->
Closes a JSONP object by stripping any trailing comma and printing a closing brace.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the state and context for the JSONP response.
- **Control Flow**:
    - Calls [`jsonp_strip_trailing_comma`](#jsonp_strip_trailing_comma) to remove any trailing comma from the JSONP output if present.
    - Uses `fd_http_server_printf` to print the closing brace '}' for the JSONP object.
- **Output**: This function does not return a value; it modifies the output stream directly by printing to it.
- **Functions called**:
    - [`jsonp_strip_trailing_comma`](#jsonp_strip_trailing_comma)


---
### jsonp\_open\_array<!-- {{#callable:jsonp_open_array}} -->
The `jsonp_open_array` function formats and outputs the opening of a JSON array, optionally including a key.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the context for the HTTP server.
    - `key`: A constant character pointer representing the key to be included in the JSON output; if NULL, no key is included.
- **Control Flow**:
    - The function checks if the `key` is likely to be non-null using the `FD_LIKELY` macro.
    - If `key` is non-null, it prints the key followed by a colon and an opening bracket for the array.
    - If `key` is null, it simply prints an opening bracket for the array.
- **Output**: The function outputs a formatted string to the HTTP server, representing the start of a JSON array, either with or without a key.


---
### jsonp\_close\_array<!-- {{#callable:jsonp_close_array}} -->
Closes a JSONP array by stripping any trailing comma and appending a closing bracket.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the state and context for the JSONP response.
- **Control Flow**:
    - Calls [`jsonp_strip_trailing_comma`](#jsonp_strip_trailing_comma) to remove any trailing comma from the current JSONP output.
    - Uses `fd_http_server_printf` to print the closing bracket for the JSONP array.
- **Output**: This function does not return a value; it modifies the output stream to close a JSONP array.
- **Functions called**:
    - [`jsonp_strip_trailing_comma`](#jsonp_strip_trailing_comma)


---
### jsonp\_ulong<!-- {{#callable:jsonp_ulong}} -->
Formats and prints a JSON representation of an unsigned long value, optionally associated with a key.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the HTTP server context for output.
    - `key`: A constant character pointer representing the key to associate with the value in the JSON output; can be NULL.
    - `value`: An unsigned long integer value to be printed in the JSON format.
- **Control Flow**:
    - Checks if the `key` is likely to be valid using the `FD_LIKELY` macro.
    - If `key` is valid, it prints the key-value pair in the format "key":value, using `fd_http_server_printf`.
    - If `key` is NULL, it prints just the value followed by a comma.
- **Output**: The function does not return a value; it directly prints the formatted JSON output to the HTTP server context.


---
### jsonp\_long<!-- {{#callable:jsonp_long}} -->
Formats and sends a JSONP response containing a long integer value.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the HTTP server context.
    - `key`: A string representing the key to be used in the JSONP response.
    - `value`: A long integer value to be included in the JSONP response.
- **Control Flow**:
    - Checks if the `key` is likely to be valid using `FD_LIKELY` macro.
    - If `key` is valid, it formats the output as a JSON key-value pair with the provided `key` and `value`.
    - If `key` is not valid, it simply outputs the `value` without a key.
- **Output**: The function outputs a formatted string to the HTTP server, either as a key-value pair or just the value, followed by a comma.


---
### jsonp\_double<!-- {{#callable:jsonp_double}} -->
Formats and sends a JSONP response containing a double value.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the HTTP server context.
    - `key`: A string representing the key to be associated with the double value in the JSONP response.
    - `value`: A double value to be formatted and sent in the JSONP response.
- **Control Flow**:
    - Checks if the `key` is likely to be valid using the `FD_LIKELY` macro.
    - If `key` is valid, it formats the output as a JSON key-value pair with the specified `key` and `value`.
    - If `key` is not valid, it sends the double value without a key.
- **Output**: The function does not return a value; it directly sends formatted output to the HTTP server.


---
### jsonp\_ulong\_as\_str<!-- {{#callable:jsonp_ulong_as_str}} -->
Formats an unsigned long value as a JSON string, optionally including a key.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the HTTP server context for output.
    - `key`: A constant character pointer representing the key to be used in the JSON output; if NULL, the key is omitted.
    - `value`: An unsigned long integer value to be formatted as a string in the JSON output.
- **Control Flow**:
    - The function first checks if the `key` is likely to be non-null using the `FD_LIKELY` macro.
    - If `key` is non-null, it formats the output as a JSON key-value pair with the value as a string.
    - If `key` is null, it formats the output as a JSON string without a key.
- **Output**: The function outputs a formatted JSON string representation of the unsigned long value, either as a key-value pair or as a standalone string.


---
### jsonp\_long\_as\_str<!-- {{#callable:jsonp_long_as_str}} -->
Formats a long integer as a JSON string value, optionally including a key.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the HTTP server context for output.
    - `key`: A constant character pointer representing the key to be used in the JSON output; if NULL, the key is omitted.
    - `value`: A long integer value to be formatted as a string in the JSON output.
- **Control Flow**:
    - Checks if the `key` is likely to be non-null using the `FD_LIKELY` macro.
    - If `key` is valid, it prints the key and the long value formatted as a string in JSON format.
    - If `key` is NULL, it prints only the long value formatted as a string in JSON format.
- **Output**: The function outputs a JSON formatted string representation of the long integer, either with or without a key, to the HTTP server.


---
### jsonp\_sanitize\_str<!-- {{#callable:jsonp_sanitize_str}} -->
Sanitizes a JSONP string by replacing certain characters with spaces.
- **Inputs**:
    - `http`: A pointer to a `fd_http_server_t` structure that contains the data to be sanitized.
    - `start_len`: The starting index in the data buffer from which to begin sanitization.
- **Control Flow**:
    - The function retrieves the data buffer from the `http` structure.
    - It iterates over the data buffer starting from `start_len` to the length of the data.
    - For each character, it checks if it is a control character (U+0000 to U+001F), a double quote ('"'), or a backslash ('\').
    - If any of these characters are found, they are replaced with a space.
- **Output**: The function does not return a value; it modifies the data in place.


---
### jsonp\_string<!-- {{#callable:jsonp_string}} -->
The `jsonp_string` function formats a JSONP string representation of a key-value pair, ensuring proper UTF-8 encoding and escaping.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the HTTP server context for output.
    - `key`: A constant character pointer representing the key in the JSON object.
    - `value`: A constant character pointer representing the value to be associated with the key.
- **Control Flow**:
    - The function first checks if the `value` is non-null and verifies its UTF-8 encoding using `fd_utf8_verify`.
    - If the value is not valid UTF-8, it sets `val` to NULL.
    - If the `key` is valid, it prints the key in JSON format using `fd_http_server_printf`.
    - If the `val` is valid, it prints the value enclosed in quotes, sanitizes it using [`jsonp_sanitize_str`](#jsonp_sanitize_str), and appends a comma.
    - If the `val` is NULL, it prints 'null' followed by a comma.
- **Output**: The function does not return a value; instead, it outputs a formatted JSONP string directly to the HTTP server context.
- **Functions called**:
    - [`jsonp_sanitize_str`](#jsonp_sanitize_str)


---
### jsonp\_bool<!-- {{#callable:jsonp_bool}} -->
The `jsonp_bool` function formats a boolean value as a JSON key-value pair.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the HTTP server context.
    - `key`: A string representing the key for the JSON object; if NULL, the key is omitted.
    - `value`: An integer representing the boolean value to be formatted, where non-zero is true and zero is false.
- **Control Flow**:
    - The function first checks if the `key` is likely to be valid using the `FD_LIKELY` macro.
    - If the `key` is valid, it prints the key and the corresponding boolean value ('true' or 'false') to the HTTP server output.
    - If the `key` is NULL, it only prints the boolean value without a key.
- **Output**: The function outputs a formatted string to the HTTP server, representing the boolean value in JSON format, either as a key-value pair or just the value.


---
### jsonp\_null<!-- {{#callable:jsonp_null}} -->
Outputs a JSON representation of a null value, optionally associated with a key.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the HTTP server context for output.
    - `key`: A constant character pointer representing the key to associate with the null value in the JSON output.
- **Control Flow**:
    - Checks if the `key` is likely to be valid using the `FD_LIKELY` macro.
    - If `key` is valid, it formats and sends a JSON string with the key and a null value to the HTTP server using `fd_http_server_printf`.
    - If `key` is not valid, it sends a JSON string with just the null value.
- **Output**: The function outputs a JSON formatted string representing a null value, either as '"key": null,' if a valid key is provided, or simply 'null,' if no key is provided.


---
### jsonp\_open\_envelope<!-- {{#callable:jsonp_open_envelope}} -->
The `jsonp_open_envelope` function initializes a JSONP envelope by opening a JSON object and adding topic and key strings.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the state and context for the JSONP output.
    - `topic`: A constant character pointer representing the topic to be included in the JSONP envelope.
    - `key`: A constant character pointer representing the key to be included in the JSONP envelope.
- **Control Flow**:
    - Calls [`jsonp_open_object`](#jsonp_open_object) to start a new JSON object, passing the `gui` pointer and a NULL key.
    - Calls [`jsonp_string`](#jsonp_string) to add the `topic` as a key-value pair in the JSON object.
    - Calls [`jsonp_string`](#jsonp_string) again to add the `key` as another key-value pair in the JSON object.
- **Output**: The function does not return a value; it modifies the JSON output directly through the `fd_gui_t` structure.
- **Functions called**:
    - [`jsonp_open_object`](#jsonp_open_object)
    - [`jsonp_string`](#jsonp_string)


---
### jsonp\_close\_envelope<!-- {{#callable:jsonp_close_envelope}} -->
Closes a JSONP envelope by closing the current JSON object and stripping any trailing comma.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the state and context for the JSONP response.
- **Control Flow**:
    - Calls the [`jsonp_close_object`](#jsonp_close_object) function to close the current JSON object.
    - Calls the [`jsonp_strip_trailing_comma`](#jsonp_strip_trailing_comma) function to remove any trailing comma from the JSON output.
- **Output**: This function does not return a value; it modifies the state of the `fd_gui_t` structure to finalize the JSONP response.
- **Functions called**:
    - [`jsonp_close_object`](#jsonp_close_object)
    - [`jsonp_strip_trailing_comma`](#jsonp_strip_trailing_comma)


---
### fd\_gui\_printf\_open\_query\_response\_envelope<!-- {{#callable:fd_gui_printf_open_query_response_envelope}} -->
This function opens a JSON response envelope for a query, including a topic, key, and ID.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that holds the GUI state and context.
    - `topic`: A constant character pointer representing the topic of the query.
    - `key`: A constant character pointer representing the key associated with the query.
    - `id`: An unsigned long integer representing the ID of the query.
- **Control Flow**:
    - The function begins by calling [`jsonp_open_object`](#jsonp_open_object) to start a new JSON object.
    - It then calls [`jsonp_string`](#jsonp_string) to add the `topic` to the JSON object.
    - Next, it calls [`jsonp_string`](#jsonp_string) again to add the `key` to the JSON object.
    - Finally, it calls [`jsonp_ulong`](#jsonp_ulong) to add the `id` to the JSON object.
- **Output**: The function does not return a value; instead, it outputs a JSON object to the GUI context that includes the topic, key, and ID.
- **Functions called**:
    - [`jsonp_open_object`](#jsonp_open_object)
    - [`jsonp_string`](#jsonp_string)
    - [`jsonp_ulong`](#jsonp_ulong)


---
### fd\_gui\_printf\_close\_query\_response\_envelope<!-- {{#callable:fd_gui_printf_close_query_response_envelope}} -->
Closes a JSONP response envelope and removes any trailing commas.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the state and context for the GUI.
- **Control Flow**:
    - Calls the [`jsonp_close_object`](#jsonp_close_object) function to close the current JSON object in the response.
    - Calls the [`jsonp_strip_trailing_comma`](#jsonp_strip_trailing_comma) function to remove any trailing comma from the JSON response.
- **Output**: This function does not return a value; it modifies the state of the JSON response being constructed.
- **Functions called**:
    - [`jsonp_close_object`](#jsonp_close_object)
    - [`jsonp_strip_trailing_comma`](#jsonp_strip_trailing_comma)


---
### fd\_gui\_printf\_null\_query\_response<!-- {{#callable:fd_gui_printf_null_query_response}} -->
Formats and sends a JSON response indicating a null query result.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the GUI context for the response.
    - `topic`: A string representing the topic of the query.
    - `key`: A string representing the key associated with the query.
    - `id`: An unsigned long integer representing the identifier for the query.
- **Control Flow**:
    - Calls [`fd_gui_printf_open_query_response_envelope`](#fd_gui_printf_open_query_response_envelope) to start the JSON response with the provided `topic`, `key`, and `id`.
    - Calls [`jsonp_null`](#jsonp_null) to add a null value for the 'value' key in the JSON response.
    - Calls [`fd_gui_printf_close_query_response_envelope`](#fd_gui_printf_close_query_response_envelope) to finalize the JSON response.
- **Output**: The function outputs a JSON formatted response indicating that the query resulted in a null value, structured according to the provided `topic`, `key`, and `id`.
- **Functions called**:
    - [`fd_gui_printf_open_query_response_envelope`](#fd_gui_printf_open_query_response_envelope)
    - [`jsonp_null`](#jsonp_null)
    - [`fd_gui_printf_close_query_response_envelope`](#fd_gui_printf_close_query_response_envelope)


---
### fd\_gui\_printf\_version<!-- {{#callable:fd_gui_printf_version}} -->
This function sends the version information of the GUI in a JSONP format.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the GUI state and data.
- **Control Flow**:
    - The function begins by calling [`jsonp_open_envelope`](#jsonp_open_envelope) to start a JSONP envelope with the topic 'summary' and key 'version'.
    - It then calls [`jsonp_string`](#jsonp_string) to add the version information from `gui->summary.version` to the JSONP response.
    - Finally, it calls [`jsonp_close_envelope`](#jsonp_close_envelope) to close the JSONP envelope.
- **Output**: The function outputs a JSONP formatted string containing the version information of the GUI.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_string`](#jsonp_string)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_cluster<!-- {{#callable:fd_gui_printf_cluster}} -->
Formats and sends a JSONP response containing the cluster summary information.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the GUI state and data to be formatted.
- **Control Flow**:
    - Calls [`jsonp_open_envelope`](#jsonp_open_envelope) to start a JSONP envelope with the topic 'summary' and key 'cluster'.
    - Uses [`jsonp_string`](#jsonp_string) to add the cluster summary value from `gui->summary.cluster` to the JSONP response.
    - Calls [`jsonp_close_envelope`](#jsonp_close_envelope) to close the JSONP envelope.
- **Output**: The function outputs a JSONP formatted string that includes the cluster summary value, structured within an envelope.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_string`](#jsonp_string)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_commit\_hash<!-- {{#callable:fd_gui_printf_commit_hash}} -->
This function sends a JSONP response containing the commit hash of the application.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the GUI state and context for the JSONP response.
- **Control Flow**:
    - Calls [`jsonp_open_envelope`](#jsonp_open_envelope) to start a new JSONP object with the topic 'summary' and key 'commit_hash'.
    - Calls [`jsonp_string`](#jsonp_string) to add the commit hash value defined by `FDCTL_COMMIT_REF_CSTR` to the JSONP response.
    - Calls [`jsonp_close_envelope`](#jsonp_close_envelope) to close the JSONP object.
- **Output**: The function outputs a JSONP formatted string that includes the commit hash under the specified topic and key.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_string`](#jsonp_string)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_identity\_key<!-- {{#callable:fd_gui_printf_identity_key}} -->
This function formats and sends the identity key of a GUI object in a JSONP response.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the GUI state and data.
- **Control Flow**:
    - Calls [`jsonp_open_envelope`](#jsonp_open_envelope) to start a JSONP envelope with the topic 'summary' and key 'identity_key'.
    - Calls [`jsonp_string`](#jsonp_string) to add the identity key value from `gui->summary.identity_key_base58` to the JSONP response.
    - Calls [`jsonp_close_envelope`](#jsonp_close_envelope) to close the JSONP envelope.
- **Output**: The function outputs a JSONP formatted string containing the identity key under the specified envelope.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_string`](#jsonp_string)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_uptime\_nanos<!-- {{#callable:fd_gui_printf_uptime_nanos}} -->
This function sends the uptime in nanoseconds since the startup of the GUI.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the GUI state and context.
- **Control Flow**:
    - Calls [`jsonp_open_envelope`](#jsonp_open_envelope) to start a JSON envelope with the topic 'summary' and key 'uptime_nanos'.
    - Calculates the uptime in nanoseconds by subtracting the `startup_time_nanos` from the current wall clock time obtained from `fd_log_wallclock()`.
    - Calls [`jsonp_ulong_as_str`](#jsonp_ulong_as_str) to format and send the uptime value as a string in the JSON response.
    - Calls [`jsonp_close_envelope`](#jsonp_close_envelope) to close the JSON envelope.
- **Output**: The function outputs a JSON object containing the uptime in nanoseconds as a string under the key 'value'.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_ulong_as_str`](#jsonp_ulong_as_str)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_vote\_distance<!-- {{#callable:fd_gui_printf_vote_distance}} -->
This function formats and sends a JSON response containing the vote distance value from the GUI summary.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the GUI state and summary data.
- **Control Flow**:
    - Calls [`jsonp_open_envelope`](#jsonp_open_envelope) to start a JSON object with the topic 'summary' and key 'vote_distance'.
    - Uses [`jsonp_ulong`](#jsonp_ulong) to add the vote distance value from `gui->summary.vote_distance` to the JSON object.
    - Calls [`jsonp_close_envelope`](#jsonp_close_envelope) to close the JSON object.
- **Output**: The function outputs a JSON object that includes the vote distance value under the specified topic and key.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_ulong`](#jsonp_ulong)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_vote\_state<!-- {{#callable:fd_gui_printf_vote_state}} -->
This function formats and outputs the current voting state of a GUI in JSON format.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the GUI state and summary information.
- **Control Flow**:
    - The function begins by calling [`jsonp_open_envelope`](#jsonp_open_envelope) to start a JSON object for the 'vote_state'.
    - It then checks the `vote_state` field of the `gui->summary` structure using a switch statement.
    - Depending on the value of `vote_state`, it calls [`jsonp_string`](#jsonp_string) to set the corresponding string value ('non-voting', 'voting', or 'delinquent').
    - If the `vote_state` does not match any known case, it logs an error message indicating an unknown vote state.
    - Finally, it calls [`jsonp_close_envelope`](#jsonp_close_envelope) to close the JSON object.
- **Output**: The function outputs a JSON object that includes the topic 'summary' and the key 'vote_state', with a value indicating the current voting state.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_string`](#jsonp_string)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_skipped\_history<!-- {{#callable:fd_gui_printf_skipped_history}} -->
This function generates a JSONP response containing the history of skipped slots for a given GUI.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the GUI state and data.
- **Control Flow**:
    - The function begins by opening a JSONP envelope with the topic 'slot' and key 'skipped_history'.
    - It then opens a JSON array to hold the values of skipped slots.
    - A loop iterates from 0 to the minimum of `gui->summary.slot_completed + 1` and `FD_GUI_SLOTS_CNT`.
    - Within the loop, it calculates the current slot index and retrieves the corresponding `fd_gui_slot_t` structure.
    - If the slot's index does not match the expected value, the loop breaks.
    - If the slot is marked as 'mine' and 'skipped', the slot index is added to the JSON array.
    - After the loop, the JSON array is closed, followed by closing the JSONP envelope.
- **Output**: The function outputs a JSONP formatted response that includes an array of skipped slot indices.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_open_array`](#jsonp_open_array)
    - [`jsonp_ulong`](#jsonp_ulong)
    - [`jsonp_close_array`](#jsonp_close_array)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_tps\_history<!-- {{#callable:fd_gui_printf_tps_history}} -->
The `fd_gui_printf_tps_history` function formats and outputs the historical transaction per second (TPS) data in a JSON-like structure.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the GUI state and data to be formatted.
- **Control Flow**:
    - The function begins by opening a JSON envelope with the topic 'summary' and key 'tps_history'.
    - It then opens a JSON array named 'value' to hold the TPS history data.
    - A loop iterates over a predefined count of TPS samples (`FD_GUI_TPS_HISTORY_SAMPLE_CNT`).
    - Within the loop, it calculates the index for accessing the estimated TPS history using a circular buffer approach.
    - For each sample, it opens a nested JSON array and populates it with four double values representing different TPS metrics, each divided by the window duration.
    - After populating the nested array, it closes it.
    - Once all samples are processed, the outer array is closed, followed by closing the JSON envelope.
- **Output**: The function outputs a structured JSON-like representation of the TPS history, including multiple arrays of calculated TPS metrics for each sample.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_open_array`](#jsonp_open_array)
    - [`jsonp_double`](#jsonp_double)
    - [`jsonp_close_array`](#jsonp_close_array)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_startup\_progress<!-- {{#callable:fd_gui_printf_startup_progress}} -->
The `fd_gui_printf_startup_progress` function reports the current startup progress of the GUI in a structured JSON format.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the current state and progress of the GUI.
- **Control Flow**:
    - The function begins by determining the current phase of startup progress based on the `startup_progress` field of the `gui` structure.
    - A switch statement is used to map the `startup_progress` value to a corresponding phase string.
    - If the phase is unknown, an error is logged.
    - The function then opens a JSON envelope and object to structure the output.
    - It includes the current phase and additional details based on the current progress level, such as downloading snapshots and processing ledgers.
    - For each relevant progress stage, it retrieves and formats additional data (like peer addresses and elapsed time) and adds them to the JSON output.
    - Finally, the JSON object and envelope are closed.
- **Output**: The function outputs a JSON object containing the current phase of startup progress and various metrics related to the startup process, such as peer addresses, elapsed time, and snapshot details.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_open_object`](#jsonp_open_object)
    - [`jsonp_string`](#jsonp_string)
    - [`jsonp_ulong`](#jsonp_ulong)
    - [`jsonp_double`](#jsonp_double)
    - [`jsonp_null`](#jsonp_null)
    - [`jsonp_close_object`](#jsonp_close_object)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_block\_engine<!-- {{#callable:fd_gui_printf_block_engine}} -->
This function formats and sends a JSON response containing the status and details of a block engine.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the state and data for the GUI.
- **Control Flow**:
    - The function begins by calling [`jsonp_open_envelope`](#jsonp_open_envelope) to start a JSON envelope with the topic 'block_engine' and key 'update'.
    - It then opens a JSON object with [`jsonp_open_object`](#jsonp_open_object) for the 'value' field.
    - The function retrieves and sends the block engine's name, URL, and IP address using [`jsonp_string`](#jsonp_string).
    - It checks the status of the block engine and sends the corresponding status string ('connecting', 'connected', or 'disconnected') based on the value of `gui->block_engine.status`.
    - Finally, it closes the JSON object and envelope using [`jsonp_close_object`](#jsonp_close_object) and [`jsonp_close_envelope`](#jsonp_close_envelope).
- **Output**: The function outputs a JSON formatted string that includes the block engine's name, URL, IP address, and status, structured within a JSON envelope.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_open_object`](#jsonp_open_object)
    - [`jsonp_string`](#jsonp_string)
    - [`jsonp_close_object`](#jsonp_close_object)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_tiles<!-- {{#callable:fd_gui_printf_tiles}} -->
The `fd_gui_printf_tiles` function generates a JSON representation of tile information for a graphical user interface.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the graphical user interface context and data.
- **Control Flow**:
    - The function begins by opening a JSON envelope with the topic 'summary' and key 'tiles'.
    - It then opens a JSON array to hold the tile values.
    - A loop iterates over each tile in the `gui->topo->tiles` array, checking the count of tiles (`tile_cnt`).
    - For each tile, it checks if the tile's name starts with 'bench'; if so, it skips that tile.
    - If the tile is not a 'bench', it opens a JSON object for that tile and adds its name and kind ID to the JSON output.
    - After processing all tiles, the JSON array and envelope are closed.
- **Output**: The function outputs a JSON structure containing an array of tile objects, each with 'kind' and 'kind_id' attributes, while excluding any tiles that are categorized as 'bench'. The overall structure is wrapped in a summary envelope.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_open_array`](#jsonp_open_array)
    - [`jsonp_open_object`](#jsonp_open_object)
    - [`jsonp_string`](#jsonp_string)
    - [`jsonp_ulong`](#jsonp_ulong)
    - [`jsonp_close_object`](#jsonp_close_object)
    - [`jsonp_close_array`](#jsonp_close_array)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_identity\_balance<!-- {{#callable:fd_gui_printf_identity_balance}} -->
This function formats and outputs the identity account balance in a JSONP envelope.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the GUI state and data.
- **Control Flow**:
    - Calls [`jsonp_open_envelope`](#jsonp_open_envelope) to start a JSONP envelope with the topic 'summary' and key 'identity_balance'.
    - Calls [`jsonp_ulong_as_str`](#jsonp_ulong_as_str) to format the identity account balance as a string and include it in the JSONP output.
    - Calls [`jsonp_close_envelope`](#jsonp_close_envelope) to close the JSONP envelope.
- **Output**: The function outputs a JSONP formatted string containing the identity account balance under the specified envelope.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_ulong_as_str`](#jsonp_ulong_as_str)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_vote\_balance<!-- {{#callable:fd_gui_printf_vote_balance}} -->
This function formats and sends the vote account balance as a JSON response.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the GUI state and data.
- **Control Flow**:
    - Calls [`jsonp_open_envelope`](#jsonp_open_envelope) to start a JSON envelope with the topic 'summary' and key 'vote_balance'.
    - Calls [`jsonp_ulong_as_str`](#jsonp_ulong_as_str) to format the vote account balance as a string and include it in the JSON response.
    - Calls [`jsonp_close_envelope`](#jsonp_close_envelope) to close the JSON envelope.
- **Output**: The function outputs a JSON object containing the vote account balance under the specified keys.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_ulong_as_str`](#jsonp_ulong_as_str)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_estimated\_slot\_duration\_nanos<!-- {{#callable:fd_gui_printf_estimated_slot_duration_nanos}} -->
This function sends a JSON response containing the estimated slot duration in nanoseconds.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that holds the GUI state and data.
- **Control Flow**:
    - Calls [`jsonp_open_envelope`](#jsonp_open_envelope) to start a JSON envelope with the topic 'summary' and key 'estimated_slot_duration_nanos'.
    - Calls [`jsonp_ulong`](#jsonp_ulong) to add the estimated slot duration in nanoseconds from `gui->summary.estimated_slot_duration_nanos` to the JSON response.
    - Calls [`jsonp_close_envelope`](#jsonp_close_envelope) to close the JSON envelope.
- **Output**: The function outputs a JSON object that includes the estimated slot duration in nanoseconds under the specified keys.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_ulong`](#jsonp_ulong)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_root\_slot<!-- {{#callable:fd_gui_printf_root_slot}} -->
This function sends a JSONP formatted response containing the value of the root slot.
- **Inputs**: None
- **Control Flow**:
    - The function begins by calling [`jsonp_open_envelope`](#jsonp_open_envelope) to start a new JSONP envelope with the topic 'summary' and key 'root_slot'.
    - It then calls [`jsonp_ulong`](#jsonp_ulong) to include the value of `gui->summary.slot_rooted` in the JSONP response.
    - Finally, it calls [`jsonp_close_envelope`](#jsonp_close_envelope) to close the JSONP envelope.
- **Output**: The function outputs a JSONP response that includes the root slot value under the specified envelope structure.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_ulong`](#jsonp_ulong)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_optimistically\_confirmed\_slot<!-- {{#callable:fd_gui_printf_optimistically_confirmed_slot}} -->
This function sends a JSON response containing the value of the optimistically confirmed slot.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that holds the GUI state and data.
- **Control Flow**:
    - Calls [`jsonp_open_envelope`](#jsonp_open_envelope) to start a JSON envelope with the topic 'summary' and key 'optimistically_confirmed_slot'.
    - Uses [`jsonp_ulong`](#jsonp_ulong) to add the value of `gui->summary.slot_optimistically_confirmed` to the JSON response.
    - Calls [`jsonp_close_envelope`](#jsonp_close_envelope) to close the JSON envelope.
- **Output**: The function outputs a JSON object that includes the optimistically confirmed slot value under the specified envelope.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_ulong`](#jsonp_ulong)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_completed\_slot<!-- {{#callable:fd_gui_printf_completed_slot}} -->
This function sends a JSON response containing the number of completed slots in a specific format.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that holds the GUI state and data.
- **Control Flow**:
    - Calls [`jsonp_open_envelope`](#jsonp_open_envelope) to start a JSON object with the topic 'summary' and key 'completed_slot'.
    - Uses [`jsonp_ulong`](#jsonp_ulong) to add the value of `gui->summary.slot_completed` to the JSON object.
    - Calls [`jsonp_close_envelope`](#jsonp_close_envelope) to close the JSON object.
- **Output**: The function outputs a JSON object that includes the topic 'summary', the key 'completed_slot', and the value representing the number of completed slots.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_ulong`](#jsonp_ulong)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_estimated\_slot<!-- {{#callable:fd_gui_printf_estimated_slot}} -->
The `fd_gui_printf_estimated_slot` function formats and sends a JSON response containing the estimated slot value.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the GUI state and data to be formatted.
- **Control Flow**:
    - Calls [`jsonp_open_envelope`](#jsonp_open_envelope) to start a JSON object with the topic 'summary' and key 'estimated_slot'.
    - Calls [`jsonp_ulong`](#jsonp_ulong) to add the estimated slot value from `gui->summary.slot_estimated` to the JSON object.
    - Calls [`jsonp_close_envelope`](#jsonp_close_envelope) to close the JSON object.
- **Output**: The function outputs a JSON object that includes the estimated slot value under the specified topic and key.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_ulong`](#jsonp_ulong)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_skip\_rate<!-- {{#callable:fd_gui_printf_skip_rate}} -->
Generates and sends a JSON response containing the skip rate for a specified epoch.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that holds the GUI state and context.
    - `epoch_idx`: An unsigned long integer representing the index of the epoch for which the skip rate is to be calculated.
- **Control Flow**:
    - Opens a JSON envelope with the topic 'summary' and key 'skip_rate'.
    - Opens a JSON object to hold the value.
    - Writes the epoch number from the specified epoch index into the JSON object.
    - Checks if the total slots for the specified epoch are zero; if so, sets the skip rate to 0.0.
    - If total slots are not zero, calculates the skip rate as the ratio of skipped slots to total slots and writes it to the JSON object.
    - Closes the JSON object and the envelope.
- **Output**: The function outputs a JSON structure containing the epoch number and the calculated skip rate, which is sent to the GUI context.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_open_object`](#jsonp_open_object)
    - [`jsonp_ulong`](#jsonp_ulong)
    - [`jsonp_double`](#jsonp_double)
    - [`jsonp_close_object`](#jsonp_close_object)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_epoch<!-- {{#callable:fd_gui_printf_epoch}} -->
Formats and sends epoch-related data to a GUI in JSON format.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the GUI context and state.
    - `epoch_idx`: An unsigned long integer representing the index of the epoch to be formatted.
- **Control Flow**:
    - Opens a JSON envelope for the epoch data.
    - Creates a JSON object to hold the epoch's values.
    - Retrieves and formats the epoch number.
    - Checks if the start time is valid; if so, formats it as a string, otherwise adds a null value.
    - Checks if the end time is valid; if so, formats it as a string, otherwise adds a null value.
    - Formats the start and end slots of the epoch.
    - Formats the excluded stake in lamports as a string.
    - Opens a JSON array for staked public keys and iterates through them, encoding each public key in Base58 format.
    - Opens a JSON array for staked lamports and formats each stake as a string.
    - Opens a JSON array for leader slots and formats each leader slot.
    - Closes the JSON object and envelope.
- **Output**: The function outputs a structured JSON representation of the specified epoch's data, including epoch number, start and end times, slots, staked public keys, staked lamports, and leader slots.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_open_object`](#jsonp_open_object)
    - [`jsonp_ulong`](#jsonp_ulong)
    - [`jsonp_ulong_as_str`](#jsonp_ulong_as_str)
    - [`jsonp_null`](#jsonp_null)
    - [`jsonp_open_array`](#jsonp_open_array)
    - [`jsonp_string`](#jsonp_string)
    - [`jsonp_close_array`](#jsonp_close_array)
    - [`jsonp_close_object`](#jsonp_close_object)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_waterfall<!-- {{#callable:fd_gui_printf_waterfall}} -->
Generates a JSON representation of the differences in transaction waterfall metrics between two states.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that holds the GUI context for output.
    - `prev`: A pointer to a `fd_gui_txn_waterfall_t` structure representing the previous state of the transaction waterfall.
    - `cur`: A pointer to a `fd_gui_txn_waterfall_t` structure representing the current state of the transaction waterfall.
- **Control Flow**:
    - The function begins by opening a JSON object labeled 'waterfall'.
    - It then opens a nested object labeled 'in' to report input metrics.
    - For each input metric, it calculates the difference between the current and previous values and outputs them using [`jsonp_ulong`](#jsonp_ulong).
    - After reporting all input metrics, it closes the 'in' object.
    - Next, it opens another nested object labeled 'out' to report output metrics.
    - Similar to the input metrics, it calculates the differences for each output metric and outputs them.
    - Finally, it closes the 'out' object and the main 'waterfall' object.
- **Output**: The function does not return a value but outputs a JSON representation of the transaction waterfall metrics to the provided `fd_gui_t` context.
- **Functions called**:
    - [`jsonp_open_object`](#jsonp_open_object)
    - [`jsonp_ulong`](#jsonp_ulong)
    - [`jsonp_close_object`](#jsonp_close_object)


---
### fd\_gui\_printf\_live\_txn\_waterfall<!-- {{#callable:fd_gui_printf_live_txn_waterfall}} -->
This function formats and sends a JSON response containing the current and previous transaction waterfall statistics along with the next leader slot.
- **Inputs**:
    - `gui`: A pointer to the `fd_gui_t` structure that holds the GUI state and context.
    - `prev`: A pointer to the previous `fd_gui_txn_waterfall_t` structure containing the previous transaction statistics.
    - `cur`: A pointer to the current `fd_gui_txn_waterfall_t` structure containing the current transaction statistics.
    - `next_leader_slot`: An unsigned long integer representing the next leader slot.
- **Control Flow**:
    - The function begins by opening a JSON envelope with the topic 'summary' and key 'live_txn_waterfall'.
    - It then opens a JSON object to hold the value data.
    - The next leader slot is added to the JSON object using the [`jsonp_ulong`](#jsonp_ulong) function.
    - The function [`fd_gui_printf_waterfall`](#fd_gui_printf_waterfall) is called to add the transaction waterfall statistics, which includes both current and previous statistics.
    - Finally, the JSON object and envelope are closed.
- **Output**: The function outputs a JSON formatted string that includes the next leader slot and the transaction waterfall statistics, structured under the 'summary' and 'live_txn_waterfall' keys.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_open_object`](#jsonp_open_object)
    - [`jsonp_ulong`](#jsonp_ulong)
    - [`fd_gui_printf_waterfall`](#fd_gui_printf_waterfall)
    - [`jsonp_close_object`](#jsonp_close_object)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_tile\_stats<!-- {{#callable:fd_gui_printf_tile_stats}} -->
The `fd_gui_printf_tile_stats` function formats and outputs tile statistics in JSON format.
- **Inputs**:
    - `gui`: A pointer to the `fd_gui_t` structure that contains the GUI context for output.
    - `prev`: A pointer to the previous tile statistics of type `fd_gui_tile_stats_t`.
    - `cur`: A pointer to the current tile statistics of type `fd_gui_tile_stats_t`.
- **Control Flow**:
    - The function begins by opening a JSON object for 'tile_primary_metric'.
    - It outputs the current QUIC connection count.
    - If the current sample time is greater than the previous sample time, it calculates and outputs the net input and output rates based on the difference in bytes and sample times.
    - If the current verification count is greater than the previous, it calculates and outputs the verification drop rate.
    - If the current deduplication count is greater than the previous, it calculates and outputs the deduplication drop rate.
    - It outputs the difference in bank transaction execution counts.
    - It calculates and outputs the pack buffer utilization ratio.
    - Finally, it outputs zero for several metrics that are not calculated and closes the JSON object.
- **Output**: The function outputs a JSON object containing various statistics related to tile performance, including connection counts, network input/output rates, verification and deduplication drop rates, and other metrics.
- **Functions called**:
    - [`jsonp_open_object`](#jsonp_open_object)
    - [`jsonp_ulong`](#jsonp_ulong)
    - [`jsonp_double`](#jsonp_double)
    - [`jsonp_close_object`](#jsonp_close_object)


---
### fd\_gui\_printf\_live\_tile\_stats<!-- {{#callable:fd_gui_printf_live_tile_stats}} -->
This function formats and outputs live tile statistics in a JSON-like structure.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the GUI context for output.
    - `prev`: A pointer to a `fd_gui_tile_stats_t` structure representing the previous tile statistics.
    - `cur`: A pointer to a `fd_gui_tile_stats_t` structure representing the current tile statistics.
- **Control Flow**:
    - The function begins by calling [`jsonp_open_envelope`](#jsonp_open_envelope) to start a new JSON envelope with the topic 'summary' and key 'live_tile_primary_metric'.
    - Next, it opens a JSON object using [`jsonp_open_object`](#jsonp_open_object) with the key 'value'.
    - It then sets a static value for 'next_leader_slot' to 0 using [`jsonp_ulong`](#jsonp_ulong).
    - The function proceeds to call [`fd_gui_printf_tile_stats`](#fd_gui_printf_tile_stats), passing the GUI context and the previous and current tile statistics to format and output the tile statistics.
    - Finally, it closes the JSON object and the envelope using [`jsonp_close_object`](#jsonp_close_object) and [`jsonp_close_envelope`](#jsonp_close_envelope) respectively.
- **Output**: The function outputs a structured JSON representation of live tile statistics, including a static 'next_leader_slot' value and the formatted statistics derived from the previous and current tile statistics.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_open_object`](#jsonp_open_object)
    - [`jsonp_ulong`](#jsonp_ulong)
    - [`fd_gui_printf_tile_stats`](#fd_gui_printf_tile_stats)
    - [`jsonp_close_object`](#jsonp_close_object)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_tile\_timers<!-- {{#callable:fd_gui_printf_tile_timers}} -->
The `fd_gui_printf_tile_timers` function calculates and reports the idle time of tile timers based on current and previous timer states.
- **Inputs**:
    - `gui`: A pointer to the `fd_gui_t` structure that contains GUI-related data.
    - `prev`: A pointer to an array of `fd_gui_tile_timers_t` structures representing the previous state of tile timers.
    - `cur`: A pointer to an array of `fd_gui_tile_timers_t` structures representing the current state of tile timers.
- **Control Flow**:
    - Iterates over each tile in the GUI's topology using a for loop.
    - Checks if the tile name starts with 'bench'; if so, it skips reporting for that tile.
    - Calculates the total timer values for both current and previous states by summing various timer metrics.
    - Determines the idle time based on the difference in caught-up post-fragmentation ticks between current and previous states.
    - If the total timer values are equal, it sets idle time to -1 to indicate no sampling since the last report.
    - Calls [`jsonp_double`](#jsonp_double) to report the calculated idle time for each tile.
- **Output**: The function outputs the idle time for each tile as a JSON double value, with a special case for tiles that have not reported any timer data.
- **Functions called**:
    - [`jsonp_double`](#jsonp_double)


---
### fd\_gui\_printf\_live\_tile\_timers<!-- {{#callable:fd_gui_printf_live_tile_timers}} -->
This function formats and outputs live tile timer statistics in a JSON-like structure.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the GUI state and data.
- **Control Flow**:
    - The function begins by opening a JSON envelope for the 'live_tile_timers' summary.
    - It then opens a JSON array to hold the timer values.
    - The current and previous tile timer snapshots are retrieved from the `gui` structure using the current snapshot index.
    - The [`fd_gui_printf_tile_timers`](#fd_gui_printf_tile_timers) function is called to format and output the timer data for both the current and previous snapshots.
    - Finally, the JSON array and envelope are closed.
- **Output**: The function outputs a JSON structure containing the live tile timer statistics, including the current and previous timer values for each tile.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_open_array`](#jsonp_open_array)
    - [`fd_gui_printf_tile_timers`](#fd_gui_printf_tile_timers)
    - [`jsonp_close_array`](#jsonp_close_array)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_estimated\_tps<!-- {{#callable:fd_gui_printf_estimated_tps}} -->
This function formats and outputs the estimated transactions per second (TPS) data in JSON format.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the GUI state and data.
- **Control Flow**:
    - Calculates the index for the estimated TPS history using the current index and the total sample count.
    - Opens a JSON envelope for the 'summary' and 'estimated_tps'.
    - Opens a JSON object to hold the values.
    - Calculates and outputs the total TPS, vote TPS, non-vote success TPS, and non-vote failed TPS by dividing the respective values by the window duration.
    - Closes the JSON object and the envelope.
- **Output**: The function outputs a JSON object containing the estimated TPS values, including total TPS, vote TPS, non-vote success TPS, and non-vote failed TPS.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_open_object`](#jsonp_open_object)
    - [`jsonp_double`](#jsonp_double)
    - [`jsonp_close_object`](#jsonp_close_object)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_gossip\_contains<!-- {{#callable:fd_gui_gossip_contains}} -->
The `fd_gui_gossip_contains` function checks if a given public key is present in the gossip peer list.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the state of the GUI, including the gossip peer list.
    - `pubkey`: A pointer to a `uchar` array representing the public key to search for in the gossip peers.
- **Control Flow**:
    - The function iterates over each peer in the `gui->gossip.peer_cnt` array.
    - For each peer, it compares the provided `pubkey` with the public key of the current peer using `memcmp`.
    - If a match is found, the function returns 1 immediately.
    - If no matches are found after checking all peers, the function returns 0.
- **Output**: The function returns 1 if the public key is found in the gossip peers, otherwise it returns 0.


---
### fd\_gui\_vote\_acct\_contains<!-- {{#callable:fd_gui_vote_acct_contains}} -->
Checks if a given public key exists in the list of vote accounts.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the GUI state, including the list of vote accounts.
    - `pubkey`: A pointer to a `uchar` array representing the public key to be checked against the vote accounts.
- **Control Flow**:
    - Iterates over each vote account in the `gui->vote_account.vote_accounts` array.
    - For each account, it compares the provided `pubkey` with the public key of the current vote account using `memcmp`.
    - If a match is found, the function returns 1, indicating that the public key exists in the list.
    - If no matches are found after checking all accounts, the function returns 0.
- **Output**: Returns 1 if the public key is found in the list of vote accounts, otherwise returns 0.


---
### fd\_gui\_printf\_peer<!-- {{#callable:fd_gui_printf_peer}} -->
The `fd_gui_printf_peer` function formats and outputs JSON data related to a specific peer's identity, including its gossip information, vote accounts, and validator info.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the GUI state and data.
    - `identity_pubkey`: A pointer to a constant unsigned char array representing the public key of the peer.
- **Control Flow**:
    - The function initializes indices for gossip, info, and vote accounts to `ULONG_MAX`.
    - It iterates through the peers in the `gossip` structure to find the index of the peer matching the provided `identity_pubkey`.
    - It similarly searches for the index in the `validator_info` structure.
    - It collects indices of vote accounts that match the `identity_pubkey`.
    - The function opens a JSON object and encodes the `identity_pubkey` in Base58 format.
    - If the gossip index is not found, it outputs a null value for gossip; otherwise, it outputs the gossip details including version, feature set, wallclock, and socket information.
    - It outputs an array of vote accounts associated with the peer, including their activated stake and other details.
    - If the info index is not found, it outputs a null value for info; otherwise, it outputs the name, details, website, and icon URL of the validator.
- **Output**: The function outputs a JSON object containing the peer's identity, gossip information (if available), associated vote accounts, and validator information (if available).
- **Functions called**:
    - [`jsonp_open_object`](#jsonp_open_object)
    - [`jsonp_string`](#jsonp_string)
    - [`jsonp_ulong`](#jsonp_ulong)
    - [`jsonp_close_object`](#jsonp_close_object)
    - [`jsonp_open_array`](#jsonp_open_array)
    - [`jsonp_ulong_as_str`](#jsonp_ulong_as_str)
    - [`jsonp_bool`](#jsonp_bool)
    - [`jsonp_close_array`](#jsonp_close_array)


---
### fd\_gui\_printf\_peers\_gossip\_update<!-- {{#callable:fd_gui_printf_peers_gossip_update}} -->
Updates the GUI with the current state of peers in the gossip network.
- **Inputs**:
    - `gui`: A pointer to the `fd_gui_t` structure representing the GUI context.
    - `updated`: An array of `ulong` indices representing peers that have been updated.
    - `updated_cnt`: The count of updated peers.
    - `removed`: An array of `fd_pubkey_t` structures representing peers that have been removed.
    - `removed_cnt`: The count of removed peers.
    - `added`: An array of `ulong` indices representing peers that have been added.
    - `added_cnt`: The count of added peers.
- **Control Flow**:
    - Open a JSON envelope for the peers update.
    - Open a JSON object to hold the value of the update.
    - Create an array for added peers and iterate over the `added` array.
    - For each added peer, check if it is not already in the vote accounts or validator info; if not, print the peer's information.
    - Close the added peers array.
    - Create an array for updated peers and iterate over the `added` array again.
    - For each added peer, check if it is in the vote accounts or validator info; if so, print the peer's information.
    - Iterate over the `updated` array and print each updated peer's information.
    - Close the updated peers array.
    - Create an array for removed peers and iterate over the `removed` array.
    - For each removed peer, check if it is not in the vote accounts or validator info; if not, print the peer's public key.
    - Close the removed peers array.
    - Close the JSON object and the envelope.
- **Output**: The function outputs a structured JSON representation of the peers that have been added, updated, or removed from the gossip network.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_open_object`](#jsonp_open_object)
    - [`jsonp_open_array`](#jsonp_open_array)
    - [`fd_gui_vote_acct_contains`](#fd_gui_vote_acct_contains)
    - [`fd_gui_validator_info_contains`](#fd_gui_validator_info_contains)
    - [`fd_gui_printf_peer`](#fd_gui_printf_peer)
    - [`jsonp_close_array`](#jsonp_close_array)
    - [`jsonp_string`](#jsonp_string)
    - [`jsonp_close_object`](#jsonp_close_object)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_peers\_vote\_account\_update<!-- {{#callable:fd_gui_printf_peers_vote_account_update}} -->
Updates the GUI with the status of peers' vote accounts.
- **Inputs**:
    - `gui`: A pointer to the `fd_gui_t` structure that holds the GUI state.
    - `updated`: An array of `ulong` representing the indices of vote accounts that have been updated.
    - `updated_cnt`: The count of updated vote accounts.
    - `removed`: An array of `fd_pubkey_t` representing the public keys of vote accounts that have been removed.
    - `removed_cnt`: The count of removed vote accounts.
    - `added`: An array of `ulong` representing the indices of vote accounts that have been added.
    - `added_cnt`: The count of added vote accounts.
- **Control Flow**:
    - Open a JSON envelope for the peers update.
    - Open a JSON object to hold the value of the update.
    - Create an array for added vote accounts and iterate through the `added` array.
    - For each added account, check if it is not already in gossip or validator info; if not, print the peer's information.
    - Close the added array.
    - Create an array for updated vote accounts and iterate through the `added` array again.
    - For each added account, check if it is already in gossip or validator info; if so, print the peer's information.
    - Iterate through the `updated` array and print each updated peer's information.
    - Close the updated array.
    - Create an array for removed vote accounts and iterate through the `removed` array.
    - For each removed account, check if it is not in gossip or validator info; if not, print its public key.
    - Close the removed array and the value object.
    - Close the JSON envelope.
- **Output**: The function outputs a structured JSON response that reflects the current state of peers' vote accounts, including added, updated, and removed accounts.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_open_object`](#jsonp_open_object)
    - [`jsonp_open_array`](#jsonp_open_array)
    - [`fd_gui_gossip_contains`](#fd_gui_gossip_contains)
    - [`fd_gui_validator_info_contains`](#fd_gui_validator_info_contains)
    - [`fd_gui_printf_peer`](#fd_gui_printf_peer)
    - [`jsonp_close_array`](#jsonp_close_array)
    - [`jsonp_string`](#jsonp_string)
    - [`jsonp_close_object`](#jsonp_close_object)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_peers\_validator\_info\_update<!-- {{#callable:fd_gui_printf_peers_validator_info_update}} -->
Updates the GUI with information about peers' validator status.
- **Inputs**:
    - `gui`: A pointer to the `fd_gui_t` structure representing the GUI context.
    - `updated`: An array of `ulong` representing the indices of updated validators.
    - `updated_cnt`: The count of updated validators.
    - `removed`: An array of `fd_pubkey_t` representing the public keys of removed validators.
    - `removed_cnt`: The count of removed validators.
    - `added`: An array of `ulong` representing the indices of added validators.
    - `added_cnt`: The count of added validators.
- **Control Flow**:
    - Open a JSON envelope for the peers update.
    - Open a JSON object to hold the value of the update.
    - Create an array for added validators and iterate through the `added` array.
    - For each added validator, check if it is already in gossip or vote accounts; if not, print its information.
    - Close the added array.
    - Create an array for updated validators and iterate through the `added` array again.
    - For each added validator, check if it is in gossip or vote accounts; if it is, print its information.
    - Iterate through the `updated` array and print information for each updated validator.
    - Close the updated array.
    - Create an array for removed validators and iterate through the `removed` array.
    - For each removed validator, check if it is in gossip or vote accounts; if it is, print its public key.
    - Close the removed array and the value object.
    - Close the JSON envelope.
- **Output**: No direct output; updates the GUI with the current state of peers' validator information in JSON format.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_open_object`](#jsonp_open_object)
    - [`jsonp_open_array`](#jsonp_open_array)
    - [`fd_gui_gossip_contains`](#fd_gui_gossip_contains)
    - [`fd_gui_vote_acct_contains`](#fd_gui_vote_acct_contains)
    - [`fd_gui_printf_peer`](#fd_gui_printf_peer)
    - [`jsonp_close_array`](#jsonp_close_array)
    - [`jsonp_string`](#jsonp_string)
    - [`jsonp_close_object`](#jsonp_close_object)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_peers\_all<!-- {{#callable:fd_gui_printf_peers_all}} -->
The `fd_gui_printf_peers_all` function generates a JSON representation of all peers, including gossip peers, vote accounts, and validator information.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that contains the state and data necessary for generating the JSON output.
- **Control Flow**:
    - Open a JSON envelope for the 'peers' update.
    - Open a JSON object to contain the value.
    - Open a JSON array for adding peers.
    - Iterate over all gossip peers and print each peer's information using [`fd_gui_printf_peer`](#fd_gui_printf_peer).
    - Iterate over all vote accounts and check if they are not already in gossip; if not, print their information.
    - Iterate over all validator information and check if they are not in gossip or vote accounts; if not, print their information.
    - Close the array, object, and envelope.
- **Output**: The function outputs a JSON structure that lists all peers, including their details, formatted for a GUI update.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_open_object`](#jsonp_open_object)
    - [`jsonp_open_array`](#jsonp_open_array)
    - [`fd_gui_printf_peer`](#fd_gui_printf_peer)
    - [`fd_gui_gossip_contains`](#fd_gui_gossip_contains)
    - [`fd_gui_vote_acct_contains`](#fd_gui_vote_acct_contains)
    - [`jsonp_close_array`](#jsonp_close_array)
    - [`jsonp_close_object`](#jsonp_close_object)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_ts\_tile\_timers<!-- {{#callable:fd_gui_printf_ts_tile_timers}} -->
Formats and outputs tile timer statistics in JSON format.
- **Inputs**:
    - `gui`: A pointer to the `fd_gui_t` structure that contains the GUI context.
    - `prev`: A pointer to the previous state of tile timers, represented as `fd_gui_tile_timers_t`.
    - `cur`: A pointer to the current state of tile timers, represented as `fd_gui_tile_timers_t`.
- **Control Flow**:
    - Opens a JSON object to encapsulate the tile timer data.
    - Writes a timestamp in nanoseconds to the JSON object.
    - Opens a JSON array to hold the tile timer data.
    - Calls [`fd_gui_printf_tile_timers`](#fd_gui_printf_tile_timers) to format and output the timer data for each tile.
    - Closes the JSON array and the JSON object.
- **Output**: Outputs a JSON object containing a timestamp and an array of tile timer statistics.
- **Functions called**:
    - [`jsonp_open_object`](#jsonp_open_object)
    - [`jsonp_ulong_as_str`](#jsonp_ulong_as_str)
    - [`jsonp_open_array`](#jsonp_open_array)
    - [`fd_gui_printf_tile_timers`](#fd_gui_printf_tile_timers)
    - [`jsonp_close_array`](#jsonp_close_array)
    - [`jsonp_close_object`](#jsonp_close_object)


---
### fd\_gui\_printf\_slot<!-- {{#callable:fd_gui_printf_slot}} -->
The `fd_gui_printf_slot` function formats and sends a JSON representation of a specified slot's state in a graphical user interface.
- **Inputs**:
    - `gui`: A pointer to the `fd_gui_t` structure that contains the GUI state and data.
    - `_slot`: An unsigned long integer representing the index of the slot to be formatted.
- **Control Flow**:
    - Retrieve the slot information from the `gui` structure using the provided `_slot` index, ensuring it wraps around using modulo operation.
    - Determine the string representation of the slot's level using a switch statement based on the `slot->level` value.
    - Check if the parent slot exists and is valid; if not, set it to NULL.
    - Calculate the duration in nanoseconds between the current slot's completion time and its parent's completion time, defaulting to LONG_MAX if not applicable.
    - Open a JSON envelope for the slot update and create a nested JSON object for the slot's details.
    - Populate the JSON object with various attributes of the slot, including its index, state flags, duration, completion time, transaction counts, and fees, handling potential null values appropriately.
    - Close the JSON objects and the envelope.
- **Output**: The function outputs a JSON structure representing the state of the specified slot, including its level, completion status, transaction counts, and other relevant metrics.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_open_object`](#jsonp_open_object)
    - [`jsonp_ulong`](#jsonp_ulong)
    - [`jsonp_bool`](#jsonp_bool)
    - [`jsonp_null`](#jsonp_null)
    - [`jsonp_long`](#jsonp_long)
    - [`jsonp_long_as_str`](#jsonp_long_as_str)
    - [`jsonp_string`](#jsonp_string)
    - [`jsonp_ulong_as_str`](#jsonp_ulong_as_str)
    - [`jsonp_close_object`](#jsonp_close_object)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_summary\_ping<!-- {{#callable:fd_gui_printf_summary_ping}} -->
This function sends a JSONP formatted summary ping response containing an ID and a null value.
- **Inputs**:
    - `gui`: A pointer to a `fd_gui_t` structure that holds the GUI context.
    - `id`: An unsigned long integer representing the ID to be included in the response.
- **Control Flow**:
    - The function begins by calling [`jsonp_open_envelope`](#jsonp_open_envelope) to start a new JSONP object with the topic 'summary' and key 'ping'.
    - It then calls [`jsonp_ulong`](#jsonp_ulong) to add the ID to the JSONP response.
    - Next, it calls [`jsonp_null`](#jsonp_null) to add a null value associated with the key 'value'.
    - Finally, it calls [`jsonp_close_envelope`](#jsonp_close_envelope) to close the JSONP object.
- **Output**: The function outputs a JSONP formatted string that includes the ID and a null value within a structured envelope.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_ulong`](#jsonp_ulong)
    - [`jsonp_null`](#jsonp_null)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_slot\_request<!-- {{#callable:fd_gui_printf_slot_request}} -->
Formats and sends a JSON response containing details about a specific slot request.
- **Inputs**:
    - `gui`: A pointer to the `fd_gui_t` structure that holds the GUI state.
    - `_slot`: An unsigned long integer representing the index of the slot being queried.
    - `id`: An unsigned long integer representing the unique identifier for the request.
- **Control Flow**:
    - Retrieve the slot information from the `gui` structure using the provided `_slot` index.
    - Determine the level of the slot (e.g., incomplete, completed) using a switch statement.
    - Check if the slot has a valid parent slot and calculate the duration since the parent slot was completed.
    - Open a JSON envelope for the slot query response.
    - Add the slot details, including its ID, level, and various transaction counts, to the JSON response.
    - Handle cases where certain values are not available by adding null entries in the JSON response.
- **Output**: The function outputs a JSON formatted string containing details about the specified slot, including its level, transaction counts, and timing information.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_ulong`](#jsonp_ulong)
    - [`jsonp_open_object`](#jsonp_open_object)
    - [`jsonp_bool`](#jsonp_bool)
    - [`jsonp_string`](#jsonp_string)
    - [`jsonp_null`](#jsonp_null)
    - [`jsonp_long`](#jsonp_long)
    - [`jsonp_close_object`](#jsonp_close_object)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_slot\_transactions\_request<!-- {{#callable:fd_gui_printf_slot_transactions_request}} -->
This function formats and sends a JSON response containing details about a specific slot's transactions.
- **Inputs**:
    - `gui`: A pointer to the `fd_gui_t` structure that holds the GUI state.
    - `_slot`: An unsigned long integer representing the index of the slot to query.
    - `id`: An unsigned long integer representing the unique identifier for the request.
- **Control Flow**:
    - The function retrieves the slot information from the `gui` structure using the provided `_slot` index.
    - It determines the level of the slot (e.g., incomplete, completed) using a switch statement.
    - It checks for the parent slot and calculates the duration between the current slot's completion time and its parent's completion time.
    - The function opens a JSON envelope and populates it with the slot's details, including its level, transaction counts, and other relevant metrics.
    - If the slot's transactions are not overwritten and all microblocks are processed, it includes detailed transaction information in the response.
- **Output**: The function outputs a JSON object containing the slot's details, including its level, transaction counts, and timestamps, formatted for a GUI response.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_ulong`](#jsonp_ulong)
    - [`jsonp_open_object`](#jsonp_open_object)
    - [`jsonp_bool`](#jsonp_bool)
    - [`jsonp_string`](#jsonp_string)
    - [`jsonp_null`](#jsonp_null)
    - [`jsonp_long`](#jsonp_long)
    - [`jsonp_close_object`](#jsonp_close_object)
    - [`jsonp_long_as_str`](#jsonp_long_as_str)
    - [`jsonp_open_array`](#jsonp_open_array)
    - [`jsonp_close_array`](#jsonp_close_array)
    - [`jsonp_ulong_as_str`](#jsonp_ulong_as_str)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)


---
### fd\_gui\_printf\_slot\_request\_detailed<!-- {{#callable:fd_gui_printf_slot_request_detailed}} -->
This function generates a detailed JSON response for a specific slot request in a GUI.
- **Inputs**:
    - `gui`: A pointer to the `fd_gui_t` structure that contains the GUI state and data.
    - `_slot`: An unsigned long integer representing the index of the slot being queried.
    - `id`: An unsigned long integer representing the unique identifier for the request.
- **Control Flow**:
    - The function retrieves the slot information from the `gui` structure using the provided `_slot` index.
    - It determines the level of the slot (e.g., incomplete, completed) using a switch statement.
    - It checks for the parent slot and calculates the duration in nanoseconds between the current slot's completion time and its parent's completion time.
    - The function opens a JSON envelope and populates it with various slot details, including its level, transaction counts, and fees.
    - If the slot's leader state indicates it has ended, it retrieves and includes additional statistics such as waterfall data and tile timers.
    - Finally, it closes the JSON envelope.
- **Output**: The function outputs a JSON object containing detailed information about the specified slot, including its state, transaction counts, and additional statistics if applicable.
- **Functions called**:
    - [`jsonp_open_envelope`](#jsonp_open_envelope)
    - [`jsonp_ulong`](#jsonp_ulong)
    - [`jsonp_open_object`](#jsonp_open_object)
    - [`jsonp_bool`](#jsonp_bool)
    - [`jsonp_string`](#jsonp_string)
    - [`jsonp_null`](#jsonp_null)
    - [`jsonp_long`](#jsonp_long)
    - [`jsonp_close_object`](#jsonp_close_object)
    - [`fd_gui_printf_waterfall`](#fd_gui_printf_waterfall)
    - [`jsonp_open_array`](#jsonp_open_array)
    - [`fd_gui_printf_ts_tile_timers`](#fd_gui_printf_ts_tile_timers)
    - [`jsonp_close_array`](#jsonp_close_array)
    - [`fd_gui_printf_tile_stats`](#fd_gui_printf_tile_stats)
    - [`jsonp_close_envelope`](#jsonp_close_envelope)



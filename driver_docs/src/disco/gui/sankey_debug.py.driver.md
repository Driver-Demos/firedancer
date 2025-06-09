# Purpose
This Python script is designed to fetch, parse, and analyze Prometheus metrics data from a given URL or file, and then print a detailed breakdown of various transaction metrics in a formatted output. The script is structured as a command-line utility, where the user provides a URL or file path as an argument. The [`scrape_url`](#scrape_url) function retrieves the content from the specified URL, while the [`parse_prometheus_text`](#parse_prometheus_text) function processes the text to extract and aggregate metric data using regular expressions. The parsed data is then used by the [`print_sankey`](#print_sankey) function to compute and display a comprehensive summary of transaction metrics, including categories such as "verify", "dedup", "resolv", "pack", and "bank", among others.

The script is primarily intended for debugging and analysis purposes, providing insights into the flow and status of transactions within a system that uses Prometheus for monitoring. It does not define a public API or external interfaces, as its functionality is encapsulated within the script itself. The main technical components include HTTP requests for data retrieval, regular expression parsing for data extraction, and formatted output for data presentation. The script's output is structured to highlight the total input and output of transactions, along with any discrepancies, making it a valuable tool for developers and system administrators monitoring transaction processing systems.
# Imports and Dependencies

---
- `re`
- `sys`
- `requests`
- `typing.Dict`
- `typing.Tuple`
- `typing.Optional`
- `pprint`


# Functions

---
### scrape\_url<!-- {{#callable:firedancer/src/disco/gui/sankey_debug.scrape_url}} -->
The `scrape_url` function retrieves the HTML content of a given URL as a string.
- **Inputs**:
    - `url`: A string representing the URL from which to fetch the HTML content.
- **Control Flow**:
    - The function uses the `requests.get` method to send an HTTP GET request to the specified URL.
    - It checks if the request was successful by calling `response.raise_for_status()`, which raises an HTTPError for bad responses.
    - The response encoding is set to 'utf-8' to ensure the text is properly decoded.
    - Finally, the function returns the text content of the response.
- **Output**: A string containing the HTML content of the specified URL.


---
### parse\_prometheus\_text<!-- {{#callable:firedancer/src/disco/gui/sankey_debug.parse_prometheus_text}} -->
The `parse_prometheus_text` function parses Prometheus-formatted text to extract and aggregate metric values based on specific patterns.
- **Inputs**:
    - `text`: A string containing Prometheus-formatted metrics data to be parsed.
- **Control Flow**:
    - Compile a regular expression pattern to match Prometheus metrics with specific attributes and values.
    - Initialize an empty dictionary `result` to store aggregated metric values.
    - Iterate over each line in the input `text` by splitting it into lines.
    - For each line, attempt to match it against the compiled regular expression pattern.
    - If a match is found, extract the metric name, variant, and value from the matched groups.
    - If a `link_kind_id` is present, use it as the variant instead of the initially extracted variant.
    - Check if the metric name and variant tuple is already in the `result` dictionary; if not, initialize it with a value of 0.
    - Add the extracted value to the corresponding entry in the `result` dictionary, converting the value to an integer.
    - Return the `result` dictionary containing aggregated metric values.
- **Output**: A dictionary where keys are tuples of metric names and optional variants, and values are the aggregated integer values of the metrics.


---
### print\_sankey<!-- {{#callable:firedancer/src/disco/gui/sankey_debug.print_sankey}} -->
The `print_sankey` function calculates and prints a detailed breakdown of transaction metrics from a given dictionary of summed data.
- **Inputs**:
    - `summed`: A dictionary where keys are tuples of metric names and optional variants, and values are integers representing the summed counts of those metrics.
- **Control Flow**:
    - Initialize variables for different input sources such as 'block_engine', 'gossip', 'udp', and 'quic' using the provided dictionary.
    - Calculate various verification metrics like 'verify_overrun', 'verify_failed', 'verify_parse', and 'verify_dedup' by summing relevant entries from the dictionary.
    - Compute deduplication metrics such as 'dedup_dedup' using the dictionary values.
    - Calculate resolution metrics including 'resolv_failed' and 'resolv_retained' by summing and subtracting relevant dictionary entries.
    - Determine packing metrics like 'pack_cranked', 'pack_retained', 'pack_leader_slot', 'pack_expired', and 'pack_invalid' using the dictionary.
    - Compute bank-related metrics such as 'bank_invalid', 'block_fail', and 'block_success'.
    - Calculate reconciliation metrics for verify, dedup, resolv, and pack stages using the dictionary values.
    - Print a formatted report of all calculated metrics, including totals and unaccounted values.
- **Output**: The function outputs a formatted string to the console, detailing the calculated metrics and their totals.


---
### main<!-- {{#callable:firedancer/src/disco/gui/sankey_debug.main}} -->
The `main` function processes a URL or file path from command line arguments, retrieves and parses its content, and then prints a detailed Sankey diagram of the parsed data.
- **Inputs**: None
- **Control Flow**:
    - Check if the number of command line arguments is not equal to 2; if so, print usage instructions and exit.
    - Retrieve the URL or file path from the command line arguments.
    - Determine if the input is a URL by checking if it starts with 'http'; if true, use [`scrape_url`](#scrape_url) to fetch content, otherwise read content from a file.
    - Parse the retrieved content using [`parse_prometheus_text`](#parse_prometheus_text).
    - Pretty print the parsed data using `pprint.pprint`.
    - Pass the parsed data to [`print_sankey`](#print_sankey) to print a detailed Sankey diagram.
- **Output**: The function does not return any value; it outputs information to the console.
- **Functions called**:
    - [`firedancer/src/disco/gui/sankey_debug.scrape_url`](#scrape_url)
    - [`firedancer/src/disco/gui/sankey_debug.parse_prometheus_text`](#parse_prometheus_text)
    - [`firedancer/src/disco/gui/sankey_debug.print_sankey`](#print_sankey)



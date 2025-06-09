# Purpose
This Python script is designed to monitor and report on transaction and computational unit statistics from a blockchain network, likely Solana, given the context of the JSON-RPC methods used. The script provides a command-line interface for users to specify an RPC endpoint and a metrics URL, along with various options to display specific statistics such as elapsed time, transaction count, transactions per second (TPS), computational units per second, and the current slot number. The script continuously polls the specified endpoints at user-defined intervals to gather and compute these metrics, which are then printed to the console in a formatted manner.

The script is structured with several key components: it uses the `argparse` module to handle command-line arguments, the `requests` library to perform HTTP requests to the specified endpoints, and the `time` module to manage polling intervals and calculate elapsed time. The [`get_txn_cnt`](#get_txn_cnt) function retrieves the transaction count and slot number from the RPC endpoint, while [`get_cus_requested`](#get_cus_requested) fetches computational unit statistics from the metrics URL. The [`tps`](#tps) function orchestrates the polling and calculation of metrics, and the [`main`](#main) function serves as the entry point, parsing arguments and initiating the monitoring process. This script is intended to be executed as a standalone program rather than imported as a module, as indicated by the `if __name__ == "__main__":` block.
# Imports and Dependencies

---
- `requests`
- `argparse`
- `time`


# Functions

---
### get\_txn\_cnt<!-- {{#callable:firedancer/contrib/test/tps.get_txn_cnt}} -->
The `get_txn_cnt` function retrieves the transaction count and current slot from a specified RPC endpoint using JSON-RPC requests.
- **Inputs**:
    - `rpc`: A string representing the RPC endpoint URL to which the JSON-RPC requests will be sent.
- **Control Flow**:
    - Constructs a JSON-RPC request payload to get the transaction count with a commitment level of 'processed'.
    - Sends a POST request to the specified RPC endpoint with the constructed payload and a JSON content type header.
    - Parses the JSON response to extract the transaction count from the 'result' field.
    - Constructs another JSON-RPC request payload to get the current slot with a commitment level of 'processed'.
    - Sends a POST request to the specified RPC endpoint with the new payload and a JSON content type header.
    - Parses the JSON response to extract the current slot from the 'result' field.
    - Returns a tuple containing the transaction count and the current slot.
- **Output**: A tuple containing two elements: the transaction count and the current slot, both retrieved from the RPC endpoint.


---
### get\_cus\_requested<!-- {{#callable:firedancer/contrib/test/tps.get_cus_requested}} -->
The `get_cus_requested` function retrieves and returns the integer value associated with the 'pack_cus_net_sum' metric from a given metrics URL.
- **Inputs**:
    - `metrics`: A string representing the URL from which to fetch the metrics data.
- **Control Flow**:
    - Send a GET request to the provided metrics URL using the `requests` library.
    - Split the response text into individual lines.
    - Iterate over each line in the response text.
    - Check if a line starts with the string 'pack_cus_net_sum'.
    - If such a line is found, split the line by spaces and return the second element as an integer.
- **Output**: The function returns an integer value extracted from the line starting with 'pack_cus_net_sum' in the metrics data.


---
### parse\_args<!-- {{#callable:firedancer/contrib/test/tps.parse_args}} -->
The `parse_args` function parses command-line arguments for an application that monitors transaction and slot metrics.
- **Inputs**: None
- **Control Flow**:
    - An `ArgumentParser` object is created to handle command-line argument parsing.
    - Several arguments are added to the parser, each with specific flags, types, and requirements.
    - The `-r` or `--rpc` argument is required and expects a string value.
    - The `-m` or `--metrics` argument is required and expects a string value.
    - The `-t` or `--time` argument is required and expects an integer value.
    - The `-e` or `--show-elapsed` argument is a boolean flag that, if present, indicates elapsed time should be shown.
    - The `-x` or `--show-txns` argument is a boolean flag that, if present, indicates transaction count should be shown.
    - The `-p` or `--show-tps` argument is a boolean flag that, if present, indicates transactions per second should be shown.
    - The `-u` or `--show-cus` argument is a boolean flag that, if present, indicates custom units per second should be shown.
    - The `-s` or `--show-slot` argument is a boolean flag that, if present, indicates the slot number should be shown.
    - The parsed arguments are stored in the `args` variable and returned.
- **Output**: The function returns an `argparse.Namespace` object containing the parsed command-line arguments.


---
### tps<!-- {{#callable:firedancer/contrib/test/tps.tps}} -->
The `tps` function continuously monitors and prints transaction and custom metric statistics from a specified RPC and metrics endpoint at regular intervals.
- **Inputs**:
    - `rpc`: A string representing the RPC endpoint URL to fetch transaction count and slot information.
    - `metrics`: A string representing the metrics endpoint URL to fetch custom metrics data.
    - `poll`: An integer representing the polling interval in seconds between each data fetch and calculation.
    - `show_elapsed`: A boolean flag indicating whether to display the elapsed time in the output.
    - `show_txns`: A boolean flag indicating whether to display the transaction count difference in the output.
    - `show_tps`: A boolean flag indicating whether to display the transactions per second (TPS) in the output.
    - `show_cus`: A boolean flag indicating whether to display the custom metrics per second in the output.
    - `show_slot`: A boolean flag indicating whether to display the slot number in the output.
- **Control Flow**:
    - Enter an infinite loop to continuously monitor metrics.
    - Fetch the initial transaction count and slot number using [`get_txn_cnt`](#get_txn_cnt) with the provided RPC endpoint.
    - Fetch the initial custom metrics using [`get_cus_requested`](#get_cus_requested) with the provided metrics endpoint.
    - Record the current time as `before_time`.
    - Pause execution for the duration specified by `poll`.
    - Record the current time as `after_time`.
    - Fetch the updated transaction count and slot number using [`get_txn_cnt`](#get_txn_cnt) again.
    - Fetch the updated custom metrics using [`get_cus_requested`](#get_cus_requested) again.
    - Calculate the difference in transaction count and custom metrics between the two fetches.
    - Calculate the time difference between `before_time` and `after_time`.
    - Compute transactions per second (TPS) and custom metrics per second based on the differences and time elapsed.
    - Print the results based on the flags `show_slot`, `show_elapsed`, `show_txns`, `show_tps`, and `show_cus`.
- **Output**: The function outputs formatted statistics to the console, including slot number, elapsed time, transaction count difference, TPS, and custom metrics per second, based on the specified flags.
- **Functions called**:
    - [`firedancer/contrib/test/tps.get_txn_cnt`](#get_txn_cnt)
    - [`firedancer/contrib/test/tps.get_cus_requested`](#get_cus_requested)


---
### main<!-- {{#callable:firedancer/contrib/test/tps.main}} -->
The `main` function parses command-line arguments and initiates the transaction per second (TPS) monitoring process using the provided arguments.
- **Inputs**: None
- **Control Flow**:
    - The function calls `parse_args()` to parse command-line arguments and store them in the `args` variable.
    - It then calls the [`tps`](#tps) function, passing the parsed arguments as parameters to monitor and display transaction statistics.
- **Output**: The function does not return any value; it initiates the TPS monitoring process.
- **Functions called**:
    - [`firedancer/contrib/test/tps.parse_args`](#parse_args)
    - [`firedancer/contrib/test/tps.tps`](#tps)



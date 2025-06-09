# Purpose
This Python script is designed as a unit test and fuzzer for an RPC server, specifically targeting JSON-RPC 2.0 methods. It is structured to test both valid and invalid JSON-RPC requests against a server endpoint, which is specified via command-line arguments. The script uses the `argparse` module to handle command-line arguments, allowing users to specify the server URL and whether to enable fuzz testing. The core functionality is divided into two main methods: [`good_method`](#good_method) and [`bad_method`](#bad_method). The [`good_method`](#good_method) function sends valid JSON-RPC requests and checks for expected responses, while the [`bad_method`](#bad_method) function sends intentionally malformed requests to ensure the server handles errors correctly. The script also includes an asynchronous function [`hello`](#hello) that uses WebSockets to subscribe to account and slot updates, demonstrating the server's real-time capabilities.

Additionally, the script includes a fuzz testing mechanism that, when enabled, manipulates the request data to test the server's robustness against unexpected input. This is achieved through the [`fuzz_test`](#fuzz_test) function, which iterates over the collected request data and introduces various mutations. The script is comprehensive in its testing approach, covering a wide range of JSON-RPC methods such as `getSlot`, `getBlock`, `getTransaction`, and more, ensuring that the server's API is thoroughly validated. The script is intended to be executed as a standalone test suite, providing a detailed examination of the server's response to both standard and edge-case scenarios.
# Imports and Dependencies

---
- `asyncio`
- `websockets`
- `requests`
- `json`
- `argparse`
- `random`


# Global Variables

---
### parser
- **Type**: `argparse.ArgumentParser`
- **Description**: The `parser` variable is an instance of `argparse.ArgumentParser` used to handle command-line arguments for the script. It is configured with a program name 'test_rpc_server' and a description 'Unit test/fuzzer for rpcserver'. The parser is set up to accept a URL argument with a default value of 'http://localhost:8123/' and a boolean flag for fuzzing.
- **Use**: This variable is used to parse command-line arguments to configure the behavior of the script, such as setting the server URL and enabling fuzzing.


---
### args
- **Type**: `argparse.Namespace`
- **Description**: The `args` variable is an instance of `argparse.Namespace` that holds the parsed command-line arguments for the script. It is created by calling `parser.parse_args()`, which processes the command-line arguments according to the configuration defined in the `argparse.ArgumentParser` instance `parser`. The `args` object contains attributes corresponding to the command-line options, such as `url` and `fuzz`, which are used throughout the script.
- **Use**: This variable is used to access command-line arguments, specifically the URL and fuzzing options, which influence the behavior of the script.


---
### url
- **Type**: `str`
- **Description**: The `url` variable is a string that holds the URL endpoint for the RPC server, which is used for making HTTP requests. It is initialized with a default value of 'http://localhost:8123/' but can be overridden by a command-line argument.
- **Use**: This variable is used to specify the target URL for HTTP requests made by the `requests.post` method in the `good_method`, `bad_method`, and `fuzz_test` functions, as well as for establishing WebSocket connections in the `hello` function.


---
### fuzz
- **Type**: `bool`
- **Description**: The `fuzz` variable is a boolean flag that is set based on the command-line argument `--fuzz`. It defaults to `False` and is set to `True` if the `--fuzz` option is provided when running the script.
- **Use**: This variable is used to determine whether to perform fuzz testing on the data being sent in the `good_method` and `bad_method` functions.


---
### fixtures
- **Type**: `list`
- **Description**: The `fixtures` variable is a global list that is initially empty. It is used to store JSON-encoded data when the `fuzz` flag is set to true.
- **Use**: This variable is used to collect data for fuzz testing when the `fuzz` option is enabled.


---
### res
- **Type**: `dict`
- **Description**: The variable `res` is a dictionary that stores the JSON response from a JSON-RPC request made to a server. It is obtained by calling the `good_method` function, which sends a POST request to a specified URL with a JSON-RPC payload and parses the response content into a dictionary.
- **Use**: This variable is used to store and access the results of JSON-RPC method calls, allowing the program to verify and utilize the data returned from the server.


---
### slot
- **Type**: `any`
- **Description**: The `slot` variable is assigned the value of the 'result' key from the response of a JSON-RPC call made by the `good_method` function with the 'getSlot' method. This value represents a specific slot number obtained from the server response.
- **Use**: The `slot` variable is used as a parameter in subsequent JSON-RPC calls to retrieve or manipulate data related to that specific slot.


---
### sig
- **Type**: `str`
- **Description**: The variable `sig` is a string that represents the first signature from a specific transaction within a block of transactions. It is extracted from the 'signatures' list of the 'transaction' dictionary in the `trans` object.
- **Use**: This variable is used to identify and retrieve specific transaction details by its signature in subsequent API calls.


---
### accts
- **Type**: `list`
- **Description**: The variable `accts` is a list that contains account keys extracted from a specific transaction's message. It is derived from the `accountKeys` field within the `message` of a transaction object, which is part of a larger JSON response from a blockchain-related API call.
- **Use**: This variable is used to iterate over account keys to perform operations such as fetching account information and balances.


---
### hash
- **Type**: `string`
- **Description**: The `hash` variable is a string that stores the block hash value obtained from the response of a JSON-RPC call to the method `getLatestBlockhash`. This value is extracted from the nested dictionary structure of the response, specifically from `res['result']['value']['blockhash']`. The block hash is a unique identifier for a block in the blockchain.
- **Use**: The `hash` variable is used as a parameter in a subsequent JSON-RPC call to the method `isBlockhashValid` to verify the validity of the block hash.


---
### votekeys
- **Type**: `list`
- **Description**: The `votekeys` variable is a list of dictionaries, each containing a single key-value pair where the key is 'votePubkey'. This list is constructed by iterating over the 'current' list within the 'result' dictionary of the `res` object, which is the response from a JSON-RPC call to the 'getVoteAccounts' method.
- **Use**: This variable is used to store the public keys of vote accounts, which can be used in subsequent RPC calls to interact with or query specific vote accounts.


# Functions

---
### good\_method<!-- {{#callable:firedancer/src/app/rpcserver/test_rpc_server.good_method}} -->
The `good_method` function sends a JSON-RPC request to a specified URL, processes the response, and verifies the response ID matches the request ID.
- **Inputs**:
    - `arg`: A dictionary representing a JSON-RPC request, which must include an 'id' key.
- **Control Flow**:
    - The function prints the JSON representation of the input argument.
    - The input argument is serialized to a JSON string and encoded to UTF-8 bytes.
    - If the global variable `fuzz` is True, the encoded data is appended to the `fixtures` list.
    - A POST request is made to the URL specified by the global variable `url`, with the encoded data as the request body and 'application/json' as the content type.
    - The response content is written to a file named 'response'.
    - The response content is deserialized from JSON to a Python dictionary.
    - The deserialized response is printed.
    - An assertion checks that the 'id' in the input argument matches the 'id' in the response.
    - The deserialized response is returned.
- **Output**: A dictionary representing the JSON-RPC response from the server.


---
### bad\_method<!-- {{#callable:firedancer/src/app/rpcserver/test_rpc_server.bad_method}} -->
The `bad_method` function sends a JSON-RPC request to a specified URL and asserts that the response contains an error.
- **Inputs**:
    - `arg`: A dictionary representing the JSON-RPC request payload to be sent.
- **Control Flow**:
    - Prints the string 'BAD: ' followed by the JSON string representation of the input argument.
    - Encodes the JSON string representation of the input argument to UTF-8 bytes.
    - If the global variable `fuzz` is True, appends the encoded data to the global `fixtures` list.
    - Sends a POST request to the URL specified by the global variable `url` with the encoded data as the request body and 'application/json' as the content type.
    - Writes the content of the response to a file named 'response' in binary write mode.
    - Parses the response content as JSON and stores it in the variable `res`.
    - Prints the parsed JSON response.
    - Asserts that the 'error' key in the response JSON is not None, indicating an error is expected in the response.
- **Output**: The function does not return any value, but it asserts that the response contains an error, which will raise an AssertionError if the condition is not met.


---
### hello<!-- {{#callable:firedancer/src/app/rpcserver/test_rpc_server.hello}} -->
The `hello` function establishes a WebSocket connection to a specified URL, subscribes to account and slot updates, and processes incoming messages for a set number of iterations.
- **Decorators**: `@asyncio.coroutine`
- **Inputs**: None
- **Control Flow**:
    - Establishes an asynchronous WebSocket connection to a URL derived from the global `url` variable, replacing 'http:' with 'ws:'.
    - Iterates over the global `accts` list, creating a JSON-RPC request to subscribe to each account with specific parameters, and sends it over the WebSocket connection.
    - After subscribing to accounts, sends a JSON-RPC request to subscribe to slot updates.
    - Enters a loop to receive and print messages from the WebSocket for a maximum of 50 iterations, incrementing a counter each time a message is received.
    - Closes the WebSocket connection after the loop completes.
- **Output**: The function does not return any value; it performs actions such as sending and receiving WebSocket messages and printing them to the console.


---
### fuzz\_test<!-- {{#callable:firedancer/src/app/rpcserver/test_rpc_server.fuzz_test}} -->
The `fuzz_test` function performs fuzz testing on a given byte sequence by sending various modified versions of it to a specified URL via HTTP POST requests.
- **Inputs**:
    - `f`: A byte sequence that will be fuzz tested by sending modified versions of it to a server.
- **Control Flow**:
    - Define an inner function `try_bytes` that sends a POST request with the given data and returns the response content.
    - Print a newline and the original byte sequence `f`.
    - Send the original byte sequence `f` using `try_bytes` and print the response.
    - Iterate over each byte in `f`, modifying it by inserting different byte sequences (e.g., `b'\x00'`, `b'\x01'`, `b'x'`, `b'000'`, `b' '`) at each position and sending these modified sequences using `try_bytes`.
    - If the current index `i` is greater than 0, also send a version of `f` with the byte at `i-1` removed.
    - Initialize `i` to 0 and enter a while loop to find pairs of double quotes (ASCII 34) in `f`.
    - For each pair of double quotes found, send modified versions of `f` with the content between the quotes removed or replaced with different byte sequences (e.g., `b'xxx'`, `b'0123'`, `b'cat'`).
    - Increment `i` to continue searching for the next pair of double quotes.
- **Output**: The function does not return any value; it performs side effects by sending HTTP requests and printing responses.



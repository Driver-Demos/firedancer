# Purpose
This C source code file is designed to handle the conversion of various blockchain-related data structures into JSON format, specifically for use in a web server context. The file includes functions that serialize transaction data, error messages, and other blockchain components into JSON, which can then be transmitted over HTTP to clients. The code is part of a larger system that appears to be dealing with blockchain transactions, possibly related to the Solana blockchain, as indicated by the use of terms like "solblock" and "fd_solana".

The file includes several functions that convert different types of data into JSON, such as [`fd_tokenbalance_to_json`](#fd_tokenbalance_to_json), [`fd_error_to_json`](#fd_error_to_json), and [`fd_txn_to_json_full`](#fd_txn_to_json_full). These functions utilize a web server object (`fd_webserver_t`) to append JSON-formatted strings to a response. The code also handles various encoding formats, including base58 and base64, and supports different levels of detail for the JSON output, such as full transaction details or just account information. Additionally, the file includes error handling and logging capabilities, ensuring that any issues during the conversion process are appropriately managed. Overall, this file provides a focused set of functionalities for JSON serialization of blockchain data, which is crucial for enabling web-based interactions with blockchain systems.
# Imports and Dependencies

---
- `stdio.h`
- `unistd.h`
- `../../ballet/nanopb/pb_decode.h`
- `fd_webserver.h`
- `../../ballet/txn/fd_txn.h`
- `../../ballet/block/fd_microblock.h`
- `../../ballet/base58/fd_base58.h`
- `../../ballet/zstd/fd_zstd.h`
- `../../flamenco/types/fd_types.h`
- `../../flamenco/types/fd_solana_block.pb.h`
- `../../flamenco/runtime/fd_blockstore.h`
- `../../flamenco/runtime/fd_executor_err.h`
- `../../flamenco/runtime/fd_system_ids.h`
- `fd_block_to_json.h`
- `fd_stub_to_json.h`
- `zstd.h`


# Data Structures

---
### decode\_return\_data\_buf
- **Type**: `struct`
- **Members**:
    - `data`: An array of 256 unsigned characters (uchar) used to store data.
    - `sz`: An unsigned long integer (ulong) representing the size of the data stored in the buffer.
- **Description**: The `decode_return_data_buf` structure is designed to hold a buffer of data and its corresponding size. It contains a fixed-size array of 256 unsigned characters to store the data and an unsigned long integer to keep track of the actual size of the data stored in the buffer. This structure is useful for handling data that needs to be decoded or processed, where the size of the data may vary but does not exceed 256 bytes.


# Functions

---
### fd\_tokenbalance\_to\_json<!-- {{#callable:fd_tokenbalance_to_json}} -->
The `fd_tokenbalance_to_json` function converts a token balance structure into a JSON format and sends it to a web server.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure, representing the web server to which the JSON data will be sent.
    - `b`: A pointer to a `_fd_solblock_TokenBalance` structure, containing the token balance information to be converted to JSON.
- **Control Flow**:
    - The function begins by sending a JSON formatted string to the web server with the account index, mint, owner, and program ID from the token balance structure.
    - It then sends the amount from the `ui_token_amount` field of the token balance structure.
    - The function checks if the `ui_token_amount` has decimals; if so, it sends the decimals value and sets the `dec` variable to the decimals value, otherwise sets `dec` to 0.
    - If the `ui_token_amount` has a UI amount, it sends the UI amount formatted to the number of decimals specified by `dec`.
    - Finally, it sends the `uiAmountString` from the `ui_token_amount` field and closes the JSON object.
- **Output**: The function does not return a value; it outputs the JSON representation of the token balance directly to the web server.
- **Functions called**:
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)


---
### instr\_strerror<!-- {{#callable:instr_strerror}} -->
The `instr_strerror` function returns a string description of an error code related to instruction execution errors.
- **Inputs**:
    - `err`: An integer representing the error code for which a string description is needed.
- **Control Flow**:
    - The function uses a switch statement to match the input error code against predefined error constants.
    - For each case, it returns a corresponding string that describes the error.
    - If the error code does not match any predefined case, the function returns an empty string.
- **Output**: A constant character pointer to a string that describes the error associated with the input error code.


---
### fd\_error\_to\_json<!-- {{#callable:fd_error_to_json}} -->
The `fd_error_to_json` function converts error data into a JSON format for web server responses, handling specific instruction errors or defaulting to a hex dump.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure, representing the web server context for sending responses.
    - `bytes`: A pointer to a byte array containing the error data to be processed.
    - `size`: An unsigned long integer representing the size of the `bytes` array.
- **Control Flow**:
    - Store the original `bytes` and `size` for potential hex dump use.
    - Check if `size` is less than the size of a `uint`; if so, jump to hex dump.
    - Extract a `uint` from `bytes` to determine the error `kind`, then adjust `bytes` and `size`.
    - If `kind` is 8 (indicating an instruction error), proceed to extract further details.
    - Check if `size` is less than 1; if so, jump to hex dump.
    - Extract an instruction `index` from `bytes`, then adjust `bytes` and `size`.
    - Check if `size` is less than the size of a `uint`; if so, jump to hex dump.
    - Extract an error code `cnum` from `bytes`, then adjust `bytes` and `size`.
    - If `cnum` is `FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR`, extract a custom error code and format a JSON response with it.
    - Otherwise, format a JSON response using the error string from `instr_strerror(cnum)`.
    - If any size checks fail, encode the original `bytes` as a hex string and send it as a JSON response.
- **Output**: The function does not return a value; it sends a JSON-formatted response to the web server context `ws`.
- **Functions called**:
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)
    - [`instr_strerror`](#instr_strerror)
    - [`fd_web_reply_encode_hex`](fd_webserver.c.driver.md#fd_web_reply_encode_hex)


---
### fd\_inner\_instructions\_to\_json<!-- {{#callable:fd_inner_instructions_to_json}} -->
The `fd_inner_instructions_to_json` function converts inner instructions of a Solana block into a JSON format and sends it to a web server.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure, representing the web server to which the JSON data will be sent.
    - `insts`: A pointer to a `_fd_solblock_InnerInstructions` structure, which contains the inner instructions to be converted to JSON.
- **Control Flow**:
    - The function begins by sending a JSON formatted string with the index of the inner instructions to the web server using [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf).
    - It then iterates over each instruction in the `insts` structure using a for loop.
    - For each instruction, it sends a JSON formatted string with the instruction's data encoded in base58 and its program ID index to the web server.
    - The function uses [`fd_web_reply_encode_base58`](fd_webserver.c.driver.md#fd_web_reply_encode_base58) to encode the instruction data in base58 format.
    - After processing all instructions, it appends a closing bracket to the JSON array using the `EMIT_SIMPLE` macro.
- **Output**: The function does not return a value; it outputs JSON formatted data directly to the web server specified by the `ws` parameter.
- **Functions called**:
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)
    - [`fd_web_reply_encode_base58`](fd_webserver.c.driver.md#fd_web_reply_encode_base58)


---
### decode\_return\_data<!-- {{#callable:decode_return_data}} -->
The `decode_return_data` function reads data from a protobuf input stream into a buffer, ensuring the data size does not exceed the buffer's capacity.
- **Inputs**:
    - `stream`: A pointer to a `pb_istream_t` structure representing the input stream from which data is read.
    - `field`: A pointer to a `pb_field_t` structure, which is not used in this function.
    - `arg`: A pointer to a pointer to a `void`, which is expected to point to a `decode_return_data_buf` structure where the data will be stored.
- **Control Flow**:
    - The function begins by casting the `arg` parameter to a `decode_return_data_buf` structure pointer.
    - It calculates the minimum of the buffer's size and the remaining bytes in the stream to determine how much data to read.
    - The `pb_read` function is called to read the determined amount of data from the stream into the buffer's data array.
    - The function returns `true` (1) to indicate successful execution.
- **Output**: The function returns a boolean value `true` (1) indicating successful data decoding.


---
### fd\_txn\_meta\_to\_json<!-- {{#callable:fd_txn_meta_to_json}} -->
The `fd_txn_meta_to_json` function converts transaction metadata into a JSON format and appends it to a web server response.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure, representing the web server to which the JSON response will be appended.
    - `meta_raw`: A pointer to the raw transaction metadata that needs to be converted to JSON.
    - `meta_raw_sz`: The size of the raw transaction metadata in bytes.
- **Control Flow**:
    - Check if `meta_raw` is NULL or `meta_raw_sz` is zero; if so, append '"meta":null,' to the response and return NULL.
    - Initialize a `fd_solblock_TransactionStatusMeta` structure and a `decode_return_data_buf` structure for decoding return data.
    - Set up a `pb_callback_t` for decoding return data and assign it to `txn_status.return_data.data`.
    - Create a `pb_istream_t` from `meta_raw` and `meta_raw_sz` and attempt to decode it into `txn_status` using `pb_decode`.
    - If decoding fails, log an error and return.
    - Append the beginning of the JSON object '"meta":{' to the response.
    - Check and append various fields from `txn_status` to the JSON response, such as `computeUnitsConsumed`, `err`, `fee`, `innerInstructions`, `loadedAddresses`, `logMessages`, `postBalances`, `postTokenBalances`, `preBalances`, `preTokenBalances`, and `returnData`.
    - Release resources associated with `txn_status` using `pb_release`.
    - Return NULL after appending the complete JSON object to the response.
- **Output**: The function returns NULL after appending the JSON representation of the transaction metadata to the web server response.
- **Functions called**:
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)
    - [`fd_error_to_json`](#fd_error_to_json)
    - [`fd_inner_instructions_to_json`](#fd_inner_instructions_to_json)
    - [`fd_web_reply_encode_json_string`](fd_webserver.c.driver.md#fd_web_reply_encode_json_string)
    - [`fd_tokenbalance_to_json`](#fd_tokenbalance_to_json)
    - [`fd_web_reply_encode_base64`](fd_webserver.c.driver.md#fd_web_reply_encode_base64)


---
### generic\_program\_to\_json<!-- {{#callable:generic_program_to_json}} -->
The `generic_program_to_json` function converts a generic program instruction from a transaction into a JSON format for web server responses.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure, which represents the web server context for appending JSON responses.
    - `txn`: A pointer to an `fd_txn_t` structure, representing the transaction containing the instruction.
    - `instr`: A pointer to an `fd_txn_instr_t` structure, representing the specific instruction within the transaction to be converted to JSON.
    - `raw`: A pointer to a byte array containing the raw transaction data.
    - `need_comma`: A pointer to an integer that indicates whether a comma is needed before appending new JSON data.
    - `spad`: A pointer to an `fd_spad_t` structure, used for managing stack-allocated memory during the JSON conversion process.
- **Control Flow**:
    - Begin a stack frame using `FD_SPAD_FRAME_BEGIN` with `spad` to manage memory allocation.
    - Check if a comma is needed before appending new JSON data and append a comma if necessary.
    - Append the beginning of a JSON object with an `accounts` array to the web server response.
    - Calculate the starting position of account indices in the raw data using `instr->acct_off`.
    - Iterate over each account index specified in the instruction, encode the account's public key in Base58, and append it to the JSON response.
    - Append the `data` field to the JSON response and encode the instruction's data in Base58.
    - Encode the program ID in Base58 and append it to the JSON response with a placeholder `program` field set to `unknown`.
    - Set `*need_comma` to 1 to indicate that subsequent JSON data should be prefixed with a comma.
    - End the stack frame using `FD_SPAD_FRAME_END`.
- **Output**: The function returns `NULL`, indicating successful execution without errors.
- **Functions called**:
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)
    - [`fd_web_reply_encode_base58`](fd_webserver.c.driver.md#fd_web_reply_encode_base58)


---
### FD\_SPAD\_FRAME\_BEGIN<!-- {{#callable:FD_SPAD_FRAME_BEGIN}} -->
The `FD_SPAD_FRAME_BEGIN` function processes a compute budget program instruction, decodes it, and formats it into a JSON response for a web server.
- **Inputs**:
    - `spad`: A pointer to a shared program address data structure used for memory allocation and alignment.
- **Control Flow**:
    - Check if a comma is needed in the output and emit it if necessary.
    - Decode the compute budget program instruction from the provided data using `fd_bincode_decode_spad`.
    - Check if the decoding was successful; if not, emit 'null' and return `NULL`.
    - Initialize a JSON object using [`fd_rpc_json_init`](fd_stub_to_json.c.driver.md#fd_rpc_json_init) and [`fd_rpc_json_new`](fd_stub_to_json.c.driver.md#fd_rpc_json_new).
    - Walk through the decoded instruction and convert it to JSON format using `fd_compute_budget_program_instruction_walk`.
    - Emit the JSON formatted instruction with additional program metadata.
    - Set the `need_comma` flag to 1 to indicate that a comma is needed before the next JSON object.
- **Output**: The function returns `NULL` after processing the instruction and emitting the JSON response.
- **Functions called**:
    - [`fd_rpc_json_init`](fd_stub_to_json.c.driver.md#fd_rpc_json_init)
    - [`fd_rpc_json_new`](fd_stub_to_json.c.driver.md#fd_rpc_json_new)
    - [`fd_rpc_json_align`](fd_stub_to_json.c.driver.md#fd_rpc_json_align)
    - [`fd_rpc_json_footprint`](fd_stub_to_json.c.driver.md#fd_rpc_json_footprint)


---
### vote\_program\_to\_json<!-- {{#callable:vote_program_to_json}} -->
The `vote_program_to_json` function converts a vote program instruction into a JSON format for web server response.
- **Inputs**:
    - `ws`: A pointer to the `fd_webserver_t` structure, representing the web server context for appending JSON data.
    - `txn`: A pointer to the `fd_txn_t` structure, representing the transaction context (unused in this function).
    - `instr`: A pointer to the `fd_txn_instr_t` structure, representing the instruction within the transaction.
    - `raw`: A pointer to the raw byte data of the transaction.
    - `need_comma`: A pointer to an integer flag indicating whether a comma is needed before appending new JSON data.
    - `spad`: A pointer to the `fd_spad_t` structure, used for temporary storage and memory allocation during JSON conversion.
- **Control Flow**:
    - The function begins by checking if a comma is needed and appends it to the web server response if necessary.
    - It decodes the vote instruction from the raw data using `fd_bincode_decode_spad` and checks for successful decoding.
    - If decoding fails, it appends 'null' to the response and returns NULL.
    - If decoding succeeds, it initializes a JSON object and walks through the vote instruction to convert it into JSON format.
    - It appends the JSON representation of the vote instruction, along with program details, to the web server response.
    - The function sets the `need_comma` flag to 1, indicating that subsequent JSON data should be prefixed with a comma.
- **Output**: The function returns NULL, indicating the end of JSON conversion for the vote program instruction.
- **Functions called**:
    - [`fd_rpc_json_init`](fd_stub_to_json.c.driver.md#fd_rpc_json_init)
    - [`fd_rpc_json_new`](fd_stub_to_json.c.driver.md#fd_rpc_json_new)
    - [`fd_rpc_json_align`](fd_stub_to_json.c.driver.md#fd_rpc_json_align)
    - [`fd_rpc_json_footprint`](fd_stub_to_json.c.driver.md#fd_rpc_json_footprint)


---
### system\_program\_to\_json<!-- {{#callable:system_program_to_json}} -->
The `system_program_to_json` function converts a system program instruction into a JSON format for web server response.
- **Inputs**:
    - `ws`: A pointer to the web server context (`fd_webserver_t`) used for appending JSON data to the response.
    - `txn`: A pointer to the transaction (`fd_txn_t`) associated with the instruction, though it is not used in this function.
    - `instr`: A pointer to the transaction instruction (`fd_txn_instr_t`) containing metadata about the instruction to be converted.
    - `raw`: A pointer to the raw byte data of the transaction from which the instruction data is extracted.
    - `need_comma`: A pointer to an integer flag indicating whether a comma is needed before appending new JSON data.
    - `spad`: A pointer to a scratchpad memory (`fd_spad_t`) used for temporary allocations during JSON conversion.
- **Control Flow**:
    - Begin a scratchpad frame using `FD_SPAD_FRAME_BEGIN` macro to manage temporary memory allocations.
    - Check if a comma is needed before appending new JSON data and append a comma if necessary.
    - Decode the system program instruction from the raw data using `fd_bincode_decode_spad` and check for successful decoding.
    - If decoding fails, append `null` to the JSON response and return `NULL`.
    - Initialize a JSON object using [`fd_rpc_json_init`](fd_stub_to_json.c.driver.md#fd_rpc_json_init) and [`fd_rpc_json_new`](fd_stub_to_json.c.driver.md#fd_rpc_json_new) for the decoded instruction.
    - Walk through the decoded instruction to convert it into JSON format using `fd_system_program_instruction_walk`.
    - Append additional JSON fields for the program name, program ID, and stack height.
    - Set the `need_comma` flag to 1 to indicate that subsequent JSON data should be prefixed with a comma.
    - End the scratchpad frame using `FD_SPAD_FRAME_END` macro.
- **Output**: The function returns `NULL` after appending the JSON representation of the system program instruction to the web server response.
- **Functions called**:
    - [`fd_rpc_json_init`](fd_stub_to_json.c.driver.md#fd_rpc_json_init)
    - [`fd_rpc_json_new`](fd_stub_to_json.c.driver.md#fd_rpc_json_new)
    - [`fd_rpc_json_align`](fd_stub_to_json.c.driver.md#fd_rpc_json_align)
    - [`fd_rpc_json_footprint`](fd_stub_to_json.c.driver.md#fd_rpc_json_footprint)


---
### config\_program\_to\_json<!-- {{#callable:config_program_to_json}} -->
The `config_program_to_json` function logs a warning indicating it is not implemented and then calls [`generic_program_to_json`](#generic_program_to_json) with the same parameters.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure, representing the web server context.
    - `txn`: A pointer to an `fd_txn_t` structure, representing the transaction data.
    - `instr`: A pointer to an `fd_txn_instr_t` structure, representing the transaction instruction data.
    - `raw`: A pointer to an unsigned character array, representing raw transaction data.
    - `need_comma`: A pointer to an integer that indicates whether a comma is needed in the JSON output.
    - `spad`: A pointer to an `fd_spad_t` structure, representing a scratchpad memory area for temporary data storage.
- **Control Flow**:
    - Logs a warning message indicating that the function is not implemented.
    - Calls the [`generic_program_to_json`](#generic_program_to_json) function with the provided parameters.
- **Output**: Returns `NULL`, indicating no specific output is generated by this function.
- **Functions called**:
    - [`generic_program_to_json`](#generic_program_to_json)


---
### stake\_program\_to\_json<!-- {{#callable:stake_program_to_json}} -->
The `stake_program_to_json` function logs a warning indicating it is not implemented and then calls [`generic_program_to_json`](#generic_program_to_json) to handle JSON conversion for a stake program instruction.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure, representing the web server context for appending JSON data.
    - `txn`: A pointer to an `fd_txn_t` structure, representing the transaction data.
    - `instr`: A pointer to an `fd_txn_instr_t` structure, representing the instruction data within the transaction.
    - `raw`: A pointer to a `uchar` array containing raw transaction data.
    - `need_comma`: A pointer to an integer that indicates whether a comma is needed before appending new JSON data.
    - `spad`: A pointer to an `fd_spad_t` structure, used for temporary storage and memory management during JSON conversion.
- **Control Flow**:
    - Logs a warning message indicating that the function is not implemented.
    - Calls the [`generic_program_to_json`](#generic_program_to_json) function with the same parameters to handle the JSON conversion.
- **Output**: Returns `NULL`, indicating no specific output or result is produced by this function.
- **Functions called**:
    - [`generic_program_to_json`](#generic_program_to_json)


---
### compute\_budget\_program\_to\_json<!-- {{#callable:compute_budget_program_to_json}} -->
The `compute_budget_program_to_json` function converts a compute budget program instruction into a JSON format and appends it to a web server response.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure, representing the web server to which the JSON response will be appended.
    - `txn`: A pointer to an `fd_txn_t` structure, representing the transaction associated with the instruction (unused in this function).
    - `instr`: A pointer to an `fd_txn_instr_t` structure, representing the instruction to be converted to JSON.
    - `raw`: A pointer to a byte array containing the raw data of the transaction.
    - `need_comma`: A pointer to an integer that indicates whether a comma is needed before appending the JSON (used for formatting purposes).
    - `spad`: A pointer to an `fd_spad_t` structure, used for temporary storage and memory allocation during the function's execution.
- **Control Flow**:
    - The function begins by checking if a comma is needed and appends it to the web server response if necessary.
    - It decodes the compute budget program instruction from the raw data using `fd_bincode_decode_spad`.
    - If the decoding fails, it appends 'null' to the response and returns `NULL`.
    - If decoding is successful, it initializes a JSON object using [`fd_rpc_json_init`](fd_stub_to_json.c.driver.md#fd_rpc_json_init) and [`fd_rpc_json_new`](fd_stub_to_json.c.driver.md#fd_rpc_json_new).
    - The function then walks through the decoded instruction to convert it into JSON format using `fd_compute_budget_program_instruction_walk`.
    - It appends the JSON representation of the instruction, along with program metadata, to the web server response.
    - Finally, it sets `*need_comma` to 1 to indicate that a comma is needed before the next JSON object and returns `NULL`.
- **Output**: The function returns `NULL` after appending the JSON representation of the compute budget program instruction to the web server response.
- **Functions called**:
    - [`fd_rpc_json_init`](fd_stub_to_json.c.driver.md#fd_rpc_json_init)
    - [`fd_rpc_json_new`](fd_stub_to_json.c.driver.md#fd_rpc_json_new)
    - [`fd_rpc_json_align`](fd_stub_to_json.c.driver.md#fd_rpc_json_align)
    - [`fd_rpc_json_footprint`](fd_stub_to_json.c.driver.md#fd_rpc_json_footprint)


---
### address\_lookup\_table\_program\_to\_json<!-- {{#callable:address_lookup_table_program_to_json}} -->
The `address_lookup_table_program_to_json` function logs a warning indicating it is not implemented and then calls the [`generic_program_to_json`](#generic_program_to_json) function with the same parameters.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure, representing the web server context.
    - `txn`: A pointer to an `fd_txn_t` structure, representing the transaction data.
    - `instr`: A pointer to an `fd_txn_instr_t` structure, representing the transaction instruction data.
    - `raw`: A pointer to an unsigned character array, representing raw transaction data.
    - `need_comma`: A pointer to an integer, indicating whether a comma is needed in the JSON output.
    - `spad`: A pointer to an `fd_spad_t` structure, representing a scratchpad memory area for temporary data storage.
- **Control Flow**:
    - Logs a warning message indicating that the function is not implemented.
    - Calls the [`generic_program_to_json`](#generic_program_to_json) function with the provided parameters.
- **Output**: Returns `NULL`.
- **Functions called**:
    - [`generic_program_to_json`](#generic_program_to_json)


---
### executor\_zk\_elgamal\_proof\_program\_to\_json<!-- {{#callable:executor_zk_elgamal_proof_program_to_json}} -->
The function `executor_zk_elgamal_proof_program_to_json` logs a warning indicating it is not implemented and then calls [`generic_program_to_json`](#generic_program_to_json) with the same parameters.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure, representing the web server context.
    - `txn`: A pointer to an `fd_txn_t` structure, representing the transaction data.
    - `instr`: A pointer to an `fd_txn_instr_t` structure, representing the transaction instruction data.
    - `raw`: A pointer to a constant unsigned character array, representing raw data associated with the transaction.
    - `need_comma`: A pointer to an integer that indicates whether a comma is needed in the JSON output.
    - `spad`: A pointer to an `fd_spad_t` structure, representing a scratchpad memory area for temporary data storage.
- **Control Flow**:
    - Logs a warning message indicating that the function is not implemented.
    - Calls the [`generic_program_to_json`](#generic_program_to_json) function with the provided parameters.
- **Output**: Returns `NULL`, indicating no specific output is generated by this function.
- **Functions called**:
    - [`generic_program_to_json`](#generic_program_to_json)


---
### bpf\_loader\_program\_to\_json<!-- {{#callable:bpf_loader_program_to_json}} -->
The `bpf_loader_program_to_json` function logs a warning indicating it is not implemented and then calls [`generic_program_to_json`](#generic_program_to_json) with the same parameters.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure, representing the web server context.
    - `txn`: A pointer to an `fd_txn_t` structure, representing the transaction data.
    - `instr`: A pointer to an `fd_txn_instr_t` structure, representing the transaction instruction data.
    - `raw`: A pointer to a constant unsigned character array, representing raw transaction data.
    - `need_comma`: A pointer to an integer that indicates whether a comma is needed in the JSON output.
    - `spad`: A pointer to an `fd_spad_t` structure, representing a scratchpad memory area for temporary data storage.
- **Control Flow**:
    - Logs a warning message indicating that the function is not implemented.
    - Calls the [`generic_program_to_json`](#generic_program_to_json) function with the provided parameters.
- **Output**: Returns `NULL`, indicating no specific output is generated by this function.
- **Functions called**:
    - [`generic_program_to_json`](#generic_program_to_json)


---
### fd\_instr\_to\_json<!-- {{#callable:fd_instr_to_json}} -->
The `fd_instr_to_json` function converts a transaction instruction into a JSON format based on the specified encoding type.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure, used for appending JSON data to the web server response.
    - `txn`: A pointer to an `fd_txn_t` structure representing the transaction containing the instruction.
    - `instr`: A pointer to an `fd_txn_instr_t` structure representing the instruction to be converted to JSON.
    - `raw`: A pointer to a byte array containing the raw transaction data.
    - `encoding`: An `fd_rpc_encoding_t` value indicating the encoding type for the JSON output (e.g., `FD_ENC_JSON` or `FD_ENC_JSON_PARSED`).
    - `need_comma`: A pointer to an integer that indicates whether a comma is needed before appending the next JSON object.
    - `spad`: A pointer to an `fd_spad_t` structure used for temporary storage during JSON conversion.
- **Control Flow**:
    - Check if the encoding is `FD_ENC_JSON` and format the instruction as a simple JSON object with account indices and base58-encoded data.
    - If the encoding is `FD_ENC_JSON_PARSED`, retrieve the account count and program ID from the transaction, and check if the program ID is valid.
    - Compare the program ID with known program IDs to determine the specific program type (e.g., vote, system, config) and call the corresponding function to convert the instruction to JSON.
    - If the program ID does not match any known types, call [`generic_program_to_json`](#generic_program_to_json) to handle the conversion.
    - Return `NULL` if the program ID is invalid or if the conversion is successful.
- **Output**: Returns `NULL` if the conversion is successful or if the program ID is invalid.
- **Functions called**:
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)
    - [`fd_web_reply_encode_base58`](fd_webserver.c.driver.md#fd_web_reply_encode_base58)
    - [`vote_program_to_json`](#vote_program_to_json)
    - [`system_program_to_json`](#system_program_to_json)
    - [`config_program_to_json`](#config_program_to_json)
    - [`stake_program_to_json`](#stake_program_to_json)
    - [`compute_budget_program_to_json`](#compute_budget_program_to_json)
    - [`address_lookup_table_program_to_json`](#address_lookup_table_program_to_json)
    - [`executor_zk_elgamal_proof_program_to_json`](#executor_zk_elgamal_proof_program_to_json)
    - [`bpf_loader_program_to_json`](#bpf_loader_program_to_json)
    - [`generic_program_to_json`](#generic_program_to_json)


---
### fd\_txn\_to\_json\_full<!-- {{#callable:fd_txn_to_json_full}} -->
The `fd_txn_to_json_full` function converts a transaction and its associated data into a JSON format, supporting various encoding types.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure, which is used to append the JSON output.
    - `txn`: A pointer to an `fd_txn_t` structure representing the transaction to be converted to JSON.
    - `raw`: A pointer to a raw byte array containing the transaction data.
    - `raw_sz`: The size of the raw transaction data in bytes.
    - `encoding`: An `fd_rpc_encoding_t` value indicating the desired encoding format for the JSON output (e.g., base64, base58, JSON, JSON_PARSED).
    - `maxvers`: A long integer representing the maximum version, which is not used in this function.
    - `spad`: A pointer to an `fd_spad_t` structure used for temporary storage during JSON conversion.
- **Control Flow**:
    - Check if the encoding is `FD_ENC_BASE64` or `FD_ENC_BASE58`, and if so, encode the transaction data accordingly and return.
    - Call [`fd_txn_meta_to_json`](#fd_txn_meta_to_json) to append transaction metadata to the JSON output.
    - Iterate over account keys in the transaction, encoding them in base58 and appending them to the JSON output.
    - If the transaction version is `FD_TXN_V0`, process address table lookups and append them to the JSON output.
    - Append transaction header information, including the number of readonly signed and unsigned accounts and required signatures.
    - Iterate over transaction instructions, converting each to JSON using [`fd_instr_to_json`](#fd_instr_to_json) and appending them to the JSON output.
    - Encode the recent blockhash in base58 and append it to the JSON output.
    - Iterate over transaction signatures, encoding each in base58 and appending them to the JSON output.
    - Determine the transaction version and append it to the JSON output.
- **Output**: Returns `NULL` on success, or a string describing an error if encoding or JSON conversion fails.
- **Functions called**:
    - [`fd_web_reply_encode_base64`](fd_webserver.c.driver.md#fd_web_reply_encode_base64)
    - [`fd_web_reply_encode_base58`](fd_webserver.c.driver.md#fd_web_reply_encode_base58)
    - [`fd_txn_meta_to_json`](#fd_txn_meta_to_json)
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)
    - [`fd_instr_to_json`](#fd_instr_to_json)


---
### fd\_txn\_to\_json\_accts<!-- {{#callable:fd_txn_to_json_accts}} -->
The `fd_txn_to_json_accts` function converts transaction account keys and signatures into a JSON format for web server responses.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure, representing the web server context for appending JSON data.
    - `txn`: A pointer to an `fd_txn_t` structure, representing the transaction whose account keys and signatures are to be converted to JSON.
    - `raw`: A pointer to a byte array containing raw transaction data, used to extract account keys and signatures.
    - `encoding`: An `fd_rpc_encoding_t` value, indicating the encoding type, though it is not used in this function.
    - `maxvers`: A long integer representing the maximum version, though it is not used in this function.
- **Control Flow**:
    - The function begins by emitting the start of a JSON object for transaction account keys.
    - It retrieves the number of account keys from the transaction structure and a pointer to the account keys from the raw data.
    - A loop iterates over each account key, encoding it in Base58 and determining if it is a signer or writable, then appends this information to the JSON response.
    - After processing all account keys, the function emits the start of a JSON array for signatures.
    - Another loop iterates over each signature, encoding it in Base58 and appending it to the JSON response.
    - The function concludes by emitting the end of the JSON object.
- **Output**: The function returns `NULL`, indicating successful completion without errors.
- **Functions called**:
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)


---
### fd\_txn\_to\_json<!-- {{#callable:fd_txn_to_json}} -->
The `fd_txn_to_json` function converts a transaction into a JSON format based on the specified detail level.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure, which is used to append the JSON output.
    - `txn`: A pointer to an `fd_txn_t` structure representing the transaction to be converted to JSON.
    - `raw`: A pointer to the raw transaction data in a byte array.
    - `raw_sz`: The size of the raw transaction data in bytes.
    - `encoding`: An `fd_rpc_encoding_t` value specifying the encoding format for the JSON output.
    - `maxvers`: A long integer specifying the maximum version of the transaction to be processed.
    - `detail`: An `enum fd_block_detail` value indicating the level of detail to include in the JSON output.
    - `spad`: A pointer to an `fd_spad_t` structure used for temporary storage during processing.
- **Control Flow**:
    - Check if the `detail` parameter is `FD_BLOCK_DETAIL_FULL` and call [`fd_txn_to_json_full`](#fd_txn_to_json_full) if true.
    - Check if the `detail` parameter is `FD_BLOCK_DETAIL_ACCTS` and call [`fd_txn_to_json_accts`](#fd_txn_to_json_accts) if true.
    - Return the string "unsupported detail parameter" if neither condition is met.
- **Output**: A pointer to a constant character string, which is either the result of the JSON conversion or an error message if the detail parameter is unsupported.
- **Functions called**:
    - [`fd_txn_to_json_full`](#fd_txn_to_json_full)
    - [`fd_txn_to_json_accts`](#fd_txn_to_json_accts)


---
### fd\_block\_to\_json<!-- {{#callable:fd_block_to_json}} -->
The `fd_block_to_json` function converts block data into a JSON format for web server responses, including block metadata, rewards, and transaction details based on the specified detail level.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure used for appending JSON data to the web server response.
    - `call_id`: A string representing the call identifier for the JSON-RPC response.
    - `blk_data`: A pointer to the block data in a byte array format.
    - `blk_sz`: The size of the block data in bytes.
    - `info`: A pointer to an `fd_replay_notif_msg_t` structure containing information about the current block.
    - `parent_info`: A pointer to an `fd_replay_notif_msg_t` structure containing information about the parent block, or NULL if not available.
    - `encoding`: An `fd_rpc_encoding_t` value specifying the encoding format for transactions.
    - `maxvers`: A long integer specifying the maximum version for transaction encoding.
    - `detail`: An `enum fd_block_detail` value indicating the level of detail to include in the JSON output.
    - `rewards`: A pointer to an `fd_block_rewards_t` structure containing block reward information, or NULL if not available.
    - `spad`: A pointer to an `fd_spad_t` structure used for temporary storage during JSON conversion.
- **Control Flow**:
    - Begin JSON output with basic block metadata including block height, time, parent slot, and hashes.
    - If rewards are provided, encode the leader's public key and append reward details to the JSON.
    - If the detail level is `FD_BLOCK_DETAIL_NONE`, finalize the JSON with the call ID and return.
    - For `FD_BLOCK_DETAIL_SIGS`, iterate over microblocks and transactions to extract and encode signatures, appending them to the JSON.
    - For other detail levels, iterate over microblocks and transactions, parsing each transaction and converting it to JSON using [`fd_txn_to_json`](#fd_txn_to_json), appending the results to the JSON.
    - Check for any remaining data in the block that wasn't processed and log an error if found.
    - Finalize the JSON output with the call ID and return.
- **Output**: Returns a pointer to a string indicating an error if one occurs, or NULL on success.
- **Functions called**:
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)
    - [`fd_txn_to_json`](#fd_txn_to_json)


---
### fd\_account\_to\_json<!-- {{#callable:fd_account_to_json}} -->
The `fd_account_to_json` function converts account data into a JSON format, encoding the data based on the specified encoding type and including metadata such as owner, address, and lamports.
- **Inputs**:
    - `ws`: A pointer to an `fd_webserver_t` structure used for web server communication.
    - `acct`: An `fd_pubkey_t` structure representing the account's public key.
    - `enc`: An `fd_rpc_encoding_t` value specifying the encoding type for the account data.
    - `val`: A pointer to the account data to be converted to JSON.
    - `val_sz`: The size of the account data in bytes.
    - `off`: A long integer specifying the offset for slicing the data.
    - `len`: A long integer specifying the length for slicing the data.
    - `spad`: A pointer to an `fd_spad_t` structure used for memory allocation, particularly for ZSTD compression.
- **Control Flow**:
    - The function begins by initializing a JSON response with the data field.
    - It checks if the account data size is sufficient to include metadata and adjusts the data pointer and size accordingly.
    - If slicing is requested (i.e., `len` and `off` are not `FD_LONG_UNSET`), it adjusts the data pointer and size based on the offset and length, ensuring they are within bounds.
    - The function then encodes the data based on the specified encoding type (`FD_ENC_BASE58`, `FD_ENC_BASE64`, or `FD_ENC_BASE64_ZSTD`) and handles errors if encoding fails.
    - It constructs the JSON response with metadata fields such as executable status, lamports, owner, address, rent epoch, and space.
    - Finally, it returns `NULL` to indicate successful completion.
- **Output**: Returns `NULL` on success, or a string describing the error if an error occurs during processing.
- **Functions called**:
    - [`fd_web_reply_sprintf`](fd_webserver.c.driver.md#fd_web_reply_sprintf)
    - [`fd_web_reply_encode_base58`](fd_webserver.c.driver.md#fd_web_reply_encode_base58)
    - [`fd_web_reply_encode_base64`](fd_webserver.c.driver.md#fd_web_reply_encode_base64)



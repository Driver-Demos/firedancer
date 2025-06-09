# Purpose
This C header file defines a set of functions and types for converting various blockchain-related data structures into JSON format, which is likely used for web server communication or API responses. It includes function prototypes for converting transaction metadata, transactions, blocks, and account information into JSON, with support for different encoding types such as Base58, Base64, and JSON itself. The file also defines an enumeration for specifying the level of detail to include in the JSON output, such as full details, account details, signature details, or none. Additionally, it includes necessary type definitions and constants, such as `FD_LONG_UNSET`, which likely serves as a special value indicator. This header is part of a larger system, as indicated by the inclusion of other headers from different modules, suggesting its role in a modular blockchain or distributed ledger application.
# Imports and Dependencies

---
- `../../util/fd_util.h`
- `../../ballet/txn/fd_txn.h`
- `../../flamenco/runtime/fd_blockstore.h`
- `../../discof/replay/fd_replay_notif.h`


# Global Variables

---
### fd\_txn\_meta\_to\_json
- **Type**: `function pointer`
- **Description**: The `fd_txn_meta_to_json` is a function that converts transaction metadata into a JSON string. It takes a web server context, a pointer to raw metadata, and the size of the metadata as parameters.
- **Use**: This function is used to serialize transaction metadata into a JSON format for web server responses.


---
### fd\_txn\_to\_json
- **Type**: `function`
- **Description**: The `fd_txn_to_json` function is a global function that converts a transaction (`fd_txn_t`) into a JSON string representation. It takes several parameters including a web server context, the transaction data, raw data, encoding type, versioning information, block detail level, and a shared padding structure. The function returns a constant character pointer to the JSON string.
- **Use**: This function is used to serialize transaction data into a JSON format for web server responses or logging purposes.


---
### fd\_block\_to\_json
- **Type**: `function pointer`
- **Description**: The `fd_block_to_json` is a function that converts block data into a JSON string representation. It takes various parameters including a web server context, block data, encoding type, and additional metadata to format the block data appropriately. This function is part of a larger system that likely deals with blockchain or distributed ledger technology, given the context of block data and transaction metadata.
- **Use**: This function is used to serialize block data into a JSON format for web server responses or further processing.


---
### fd\_account\_to\_json
- **Type**: `function`
- **Description**: The `fd_account_to_json` function is a global function that converts account data into a JSON string representation. It takes several parameters including a web server context, an account public key, an encoding type, a value pointer with its size, and offset and length parameters for data extraction, as well as a shared padding structure. The function returns a constant character pointer to the resulting JSON string.
- **Use**: This function is used to serialize account data into a JSON format for web server responses or other JSON-based data exchanges.


# Data Structures

---
### fd\_webserver\_t
- **Type**: `typedef struct`
- **Description**: The `fd_webserver_t` is a forward-declared structure type in C, which means that its definition is not provided in the given code. It is likely used as a handle or context for web server operations, as suggested by its usage in various function prototypes that convert different data types to JSON format. The actual structure definition would typically include members relevant to managing web server state or configuration, but these details are not available in the provided code.


---
### fd\_rpc\_encoding\_t
- **Type**: `enum`
- **Members**:
    - `FD_ENC_BASE58`: Represents Base58 encoding.
    - `FD_ENC_BASE64`: Represents Base64 encoding.
    - `FD_ENC_BASE64_ZSTD`: Represents Base64 encoding with Zstandard compression.
    - `FD_ENC_JSON`: Represents JSON encoding.
    - `FD_ENC_JSON_PARSED`: Represents parsed JSON encoding.
- **Description**: The `fd_rpc_encoding_t` is an enumeration that defines various encoding types used for data serialization in RPC (Remote Procedure Call) operations. It includes options for Base58, Base64, Base64 with Zstandard compression, JSON, and parsed JSON encodings, allowing flexibility in how data is encoded and transmitted in the system.


---
### fd\_block\_detail
- **Type**: `enum`
- **Members**:
    - `FD_BLOCK_DETAIL_FULL`: Represents a block detail level that includes all information.
    - `FD_BLOCK_DETAIL_ACCTS`: Represents a block detail level that includes account information.
    - `FD_BLOCK_DETAIL_SIGS`: Represents a block detail level that includes signature information.
    - `FD_BLOCK_DETAIL_NONE`: Represents a block detail level with no additional information.
- **Description**: The `fd_block_detail` enumeration defines different levels of detail that can be included when processing or representing a block in the system. It provides options to include full details, only account-related details, only signature-related details, or no additional details at all. This allows for flexible handling of block data depending on the requirements of the operation being performed.


# Function Declarations (Public API)

---
### fd\_txn\_meta\_to\_json<!-- {{#callable_declaration:fd_txn_meta_to_json}} -->
Converts transaction metadata to a JSON format and appends it to a web server response.
- **Description**: This function is used to convert raw transaction metadata into a JSON format and append it to the response of a web server. It should be called when you need to include transaction metadata in a web server's JSON response. The function handles cases where the metadata is null or empty by appending a null JSON object. It is important to ensure that the web server object is properly initialized before calling this function. The function does not return any value, and the JSON data is directly appended to the web server's response.
- **Inputs**:
    - `ws`: A pointer to an initialized fd_webserver_t object where the JSON data will be appended. Must not be null.
    - `meta_raw`: A pointer to the raw transaction metadata to be converted. Can be null, in which case a null JSON object is appended.
    - `meta_raw_sz`: The size of the raw transaction metadata in bytes. If zero, a null JSON object is appended.
- **Output**: None
- **See also**: [`fd_txn_meta_to_json`](fd_block_to_json.c.driver.md#fd_txn_meta_to_json)  (Implementation)


---
### fd\_txn\_to\_json<!-- {{#callable_declaration:fd_txn_to_json}} -->
Converts a transaction to a JSON representation.
- **Description**: This function is used to convert a transaction into a JSON format, which can be useful for web server responses or logging. It requires a web server context, a transaction object, and raw transaction data. The function supports different encoding formats and detail levels, allowing for flexibility in the output. The detail parameter determines the level of detail included in the JSON output, with only 'FD_BLOCK_DETAIL_FULL' and 'FD_BLOCK_DETAIL_ACCTS' being supported. If an unsupported detail level is provided, the function returns an error message. This function should be used when a JSON representation of a transaction is needed, and the caller must ensure that the provided parameters are valid and appropriate for the desired output.
- **Inputs**:
    - `ws`: A pointer to an fd_webserver_t structure representing the web server context. Must not be null.
    - `txn`: A pointer to an fd_txn_t structure representing the transaction to be converted. Must not be null.
    - `raw`: A pointer to the raw transaction data. Must not be null.
    - `raw_sz`: The size of the raw transaction data. Must be a valid size for the data pointed to by 'raw'.
    - `encoding`: An fd_rpc_encoding_t value specifying the encoding format for the JSON output. Must be a valid encoding type.
    - `maxvers`: A long integer specifying the maximum version of the JSON format to use. Can be set to FD_LONG_UNSET if no specific version is required.
    - `detail`: An enum fd_block_detail value specifying the level of detail for the JSON output. Only 'FD_BLOCK_DETAIL_FULL' and 'FD_BLOCK_DETAIL_ACCTS' are supported.
    - `spad`: A pointer to an fd_spad_t structure for additional data storage. Can be null if not used.
- **Output**: Returns a pointer to a string containing the JSON representation of the transaction, or an error message if an unsupported detail level is provided.
- **See also**: [`fd_txn_to_json`](fd_block_to_json.c.driver.md#fd_txn_to_json)  (Implementation)


---
### fd\_block\_to\_json<!-- {{#callable_declaration:fd_block_to_json}} -->
Converts block data to a JSON representation and sends it to a web server.
- **Description**: This function is used to convert block data into a JSON format and send it to a specified web server. It requires information about the block, such as its size, encoding, and detail level, as well as optional information about the parent block and rewards. The function must be called with valid block data and a properly initialized web server context. It handles different levels of block detail, including full transactions or just signatures, and formats the output accordingly. The function returns a string indicating an error if parsing fails, or NULL on success.
- **Inputs**:
    - `ws`: A pointer to an fd_webserver_t structure representing the web server context. Must not be null.
    - `call_id`: A string representing the call identifier for the JSON-RPC response. Must not be null.
    - `blk_data`: A pointer to the block data to be converted. Must not be null and should point to a valid block data buffer.
    - `blk_sz`: The size of the block data in bytes. Must be a valid size corresponding to the data pointed to by blk_data.
    - `info`: A pointer to an fd_replay_notif_msg_t structure containing information about the block. Must not be null.
    - `parent_info`: A pointer to an fd_replay_notif_msg_t structure containing information about the parent block. Can be null if no parent information is available.
    - `encoding`: An fd_rpc_encoding_t value specifying the encoding format for the transactions.
    - `maxvers`: A long integer specifying the maximum version of the transactions to be included. Can be FD_LONG_UNSET to indicate no version limit.
    - `detail`: An enum fd_block_detail value specifying the level of detail to include in the JSON output.
    - `rewards`: A pointer to an fd_block_rewards_t structure containing rewards information. Can be null if no rewards information is available.
    - `spad`: A pointer to an fd_spad_t structure used for temporary storage during processing. Must not be null.
- **Output**: Returns a const char* indicating an error message if parsing fails, or NULL on success.
- **See also**: [`fd_block_to_json`](fd_block_to_json.c.driver.md#fd_block_to_json)  (Implementation)


---
### fd\_account\_to\_json<!-- {{#callable_declaration:fd_account_to_json}} -->
Converts account data to a JSON representation.
- **Description**: This function is used to convert account data into a JSON format suitable for web server responses. It requires a web server context, account public key, encoding type, and the account data to be converted. The function supports various encoding formats, including base58, base64, and optionally base64 with ZSTD compression. It handles slicing of the data if offset and length are specified, but does not support JSON encoding with slicing. The function returns a JSON string representation of the account data or an error message if the conversion fails.
- **Inputs**:
    - `ws`: A pointer to an fd_webserver_t structure representing the web server context. Must not be null.
    - `acct`: An fd_pubkey_t representing the public key of the account. Used to encode the account's address.
    - `enc`: An fd_rpc_encoding_t value specifying the encoding format for the account data. Supported values are FD_ENC_BASE58, FD_ENC_BASE64, FD_ENC_BASE64_ZSTD, and FD_ENC_JSON. FD_ENC_JSON_PARSED is not supported with slicing.
    - `val`: A pointer to the account data to be converted. Must not be null and should point to a valid memory region of at least val_sz bytes.
    - `val_sz`: The size in bytes of the account data pointed to by val. Must be greater than or equal to the size of fd_account_meta_t and metadata->hlen.
    - `off`: A long integer specifying the offset from which to start slicing the data. If set to FD_LONG_UNSET, no offset is applied.
    - `len`: A long integer specifying the length of the data slice. If set to FD_LONG_UNSET, the entire data from the offset is used.
    - `spad`: A pointer to an fd_spad_t structure used for temporary storage during encoding. Can be null if FD_ENC_BASE64_ZSTD is not used.
- **Output**: Returns a pointer to a string containing the JSON representation of the account data, or an error message if the conversion fails.
- **See also**: [`fd_account_to_json`](fd_block_to_json.c.driver.md#fd_account_to_json)  (Implementation)



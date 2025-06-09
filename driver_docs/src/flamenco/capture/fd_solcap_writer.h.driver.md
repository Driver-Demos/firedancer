# Purpose
This C header file defines the interface for a capture writer object, `fd_solcap_writer_t`, which is used to write SOLCAP_V1_BANK files. The file provides a set of function prototypes for managing the lifecycle of the writer object, including functions to create, initialize, and delete the writer, as well as to manage memory alignment and footprint requirements. It also includes functions for writing various components of a capture file, such as account data, bank preimages, and transactions, ensuring that these operations are performed in a specific order to maintain data integrity. The header file includes necessary dependencies and uses opaque pointers to encapsulate the implementation details, promoting modularity and abstraction.
# Imports and Dependencies

---
- `fd_solcap_proto.h`
- `fd_solcap.pb.h`
- `../types/fd_types.h`


# Global Variables

---
### fd\_solcap\_writer\_new
- **Type**: `fd_solcap_writer_t *`
- **Description**: The `fd_solcap_writer_new` function is responsible for creating a new instance of the `fd_solcap_writer_t` object using a specified memory region. This function ensures that the memory region provided is properly aligned and has the necessary footprint to support the writer object.
- **Use**: This function is used to initialize a new capture writer object, which is essential for writing SOLCAP_V1_BANK files.


---
### fd\_solcap\_writer\_delete
- **Type**: `function pointer`
- **Description**: The `fd_solcap_writer_delete` is a function that takes a pointer to an `fd_solcap_writer_t` object and destroys it, transferring ownership of the backing memory region to the caller. If the input pointer is NULL, the function behaves as a no-operation and returns NULL.
- **Use**: This function is used to properly deallocate and clean up resources associated with an `fd_solcap_writer_t` object.


---
### fd\_solcap\_writer\_init
- **Type**: `function pointer`
- **Description**: The `fd_solcap_writer_init` is a function that initializes a `fd_solcap_writer_t` object to write to a new stream. It takes a pointer to a `fd_solcap_writer_t` object and a stream (such as a `FILE *`) as parameters. The function sets up the writer to begin writing a capture file, starting with the capture file header.
- **Use**: This function is used to initialize a capture writer object to start writing data to a specified stream, preparing it for subsequent operations.


---
### fd\_solcap\_writer\_flush
- **Type**: `function pointer`
- **Description**: The `fd_solcap_writer_flush` is a function that takes a pointer to an `fd_solcap_writer_t` object and completes any outstanding writes to the associated stream, returning ownership of the stream handle back to the caller. It always returns the writer object for convenience, and logs any errors that occur during the process.
- **Use**: This function is used to ensure that all data is written to the stream and to return control of the stream to the caller after writing operations are complete.


# Data Structures

---
### fd\_solcap\_writer\_t
- **Type**: `struct`
- **Members**:
    - `fd_solcap_writer_t`: An opaque handle to a capture writer object for writing SOLCAP_V1_BANK files.
- **Description**: The `fd_solcap_writer_t` is a data structure that serves as an opaque handle for managing the lifecycle and operations of a capture writer object, specifically designed for writing SOLCAP_V1_BANK files. It provides a set of functions to create, initialize, and manage the writing process to a stream, ensuring proper alignment and memory footprint. The structure supports operations such as setting slots, writing account data, and managing bank preimages, all crucial for maintaining the integrity and order of the capture data. The design encapsulates the complexity of file writing and stream management, offering a streamlined API for users to interact with the capture writer.


# Function Declarations (Public API)

---
### fd\_solcap\_writer\_set\_slot<!-- {{#callable_declaration:fd_solcap_writer_set_slot}} -->
Start a new slot record for the capture writer.
- **Description**: Use this function to begin a new slot record in the capture writer, ensuring that any previous slot record is completed. This function should be called before writing any account or bank data for a new slot. Slot numbers must be provided in a monotonically increasing order to maintain the correct sequence of records.
- **Inputs**:
    - `writer`: A pointer to an fd_solcap_writer_t object. Must not be null. If null, the function returns immediately without making any changes.
    - `slot`: An unsigned long integer representing the slot number. Slot numbers must be provided in a monotonically increasing order.
- **Output**: None
- **See also**: [`fd_solcap_writer_set_slot`](fd_solcap_writer.c.driver.md#fd_solcap_writer_set_slot)  (Implementation)


---
### fd\_solcap\_write\_account<!-- {{#callable_declaration:fd_solcap_write_account}} -->
Appends an account record to the current slot's account delta hash in the stream.
- **Description**: This function is used to append a copy of an account, represented by a key, metadata, and data, to the stream associated with the current slot's account delta hash. It should be called only for accounts that are part of the current slot's account delta hash. The function requires that the writer object has been successfully initialized and is currently set to a slot. The order of accounts is arbitrary, and the function will return 0 if the writer is not valid, indicating no operation was performed.
- **Inputs**:
    - `writer`: A pointer to an initialized fd_solcap_writer_t object. Must not be null, as it represents the stream to which the account data will be written.
    - `key`: A pointer to a 32-byte array representing the account's key. The caller retains ownership, and it must not be null.
    - `meta`: A pointer to a fd_solana_account_meta_t structure containing metadata about the account, such as lamports, rent epoch, and executable status. Must not be null.
    - `data`: A pointer to the account's data to be written. The caller retains ownership, and it must not be null.
    - `data_sz`: The size of the data in bytes. Must be a valid size corresponding to the data pointer.
    - `hash`: A pointer to a 32-byte array representing the account's hash. The caller retains ownership, and it must not be null.
- **Output**: Returns an integer status code from the underlying write operation, or 0 if the writer is null.
- **See also**: [`fd_solcap_write_account`](fd_solcap_writer.c.driver.md#fd_solcap_write_account)  (Implementation)


---
### fd\_solcap\_write\_account2<!-- {{#callable_declaration:fd_solcap_write_account2}} -->
Appends account data and metadata to the capture stream.
- **Description**: This function appends a copy of the specified account data and its associated metadata to the capture stream managed by the writer. It should be called only after the writer has been properly initialized and is currently set to a valid slot. The function is intended for use with accounts that are part of the current slot's account delta hash. It handles the serialization of account metadata and ensures that the data is aligned and written correctly to the stream. The function does not perform any operation if the writer is null.
- **Inputs**:
    - `writer`: A pointer to an initialized fd_solcap_writer_t object. Must not be null. The function returns immediately if this parameter is null.
    - `tbl`: A pointer to a constant fd_solcap_account_tbl_t structure containing account table information. The caller retains ownership.
    - `meta_pb`: A pointer to an fd_solcap_AccountMeta structure where metadata will be serialized. The caller retains ownership.
    - `data`: A pointer to the account data to be written. The caller retains ownership and the data must be valid for the duration of the call.
    - `data_sz`: The size in bytes of the account data to be written. Must be a valid size for the data provided.
- **Output**: Returns 0 on success. The function writes to the stream managed by the writer and updates the writer's internal state.
- **See also**: [`fd_solcap_write_account2`](fd_solcap_writer.c.driver.md#fd_solcap_write_account2)  (Implementation)


---
### fd\_solcap\_write\_bank\_preimage<!-- {{#callable_declaration:fd_solcap_write_bank_preimage}} -->
Sets fields for the current slot's bank hash preimage.
- **Description**: This function is used to set additional fields that are part of the current slot's bank hash preimage in a capture writer object. It should be called after initializing the writer and setting the slot, and after writing all relevant accounts for the current slot. The function requires valid hash values for the current bank, previous bank, and PoH, and optionally for the account delta and accounts lt hash checksum. If the optional hashes are not provided, they will be set to zero. The signature count is also set as part of the preimage. The function returns an integer indicating success or failure.
- **Inputs**:
    - `writer`: A pointer to an initialized fd_solcap_writer_t object. Must not be null. The writer should be properly initialized and set to the correct slot before calling this function.
    - `bank_hash`: A pointer to a 32-byte hash representing the current bank. Must not be null.
    - `prev_bank_hash`: A pointer to a 32-byte hash representing the previous bank. Must not be null.
    - `account_delta_hash`: A pointer to a 32-byte hash representing the Merkle root of changed accounts. Can be null, in which case it will be set to zero.
    - `accounts_lt_hash_checksum`: A pointer to a 32-byte hash representing the accounts lt hash checksum. Can be null, in which case it will be set to zero.
    - `poh_hash`: A pointer to a 32-byte hash representing the PoH of the current block. Must not be null.
    - `signature_cnt`: An unsigned long integer representing the number of signatures. There are no specific constraints mentioned, but it should be a valid count.
- **Output**: Returns an integer indicating success (non-zero) or failure (zero).
- **See also**: [`fd_solcap_write_bank_preimage`](fd_solcap_writer.c.driver.md#fd_solcap_write_bank_preimage)  (Implementation)


---
### fd\_solcap\_write\_bank\_preimage2<!-- {{#callable_declaration:fd_solcap_write_bank_preimage2}} -->
Writes a bank preimage to the capture stream.
- **Description**: This function is used to write a bank preimage to the capture stream associated with the given writer. It should be called after setting the slot and writing all relevant accounts for that slot. The function updates the preimage with the current slot and account table information from the writer before serializing it to the stream. It is important to ensure that the writer is properly initialized and that the preimage is correctly populated before calling this function. The function handles any necessary alignment and serialization details internally.
- **Inputs**:
    - `writer`: A pointer to an initialized fd_solcap_writer_t object. Must not be null. The function will return 0 if this parameter is null.
    - `preimage_pb`: A pointer to an fd_solcap_BankPreimage structure that will be updated with the current slot and account table information before being serialized. Must not be null.
- **Output**: Returns 0 on success or an error code if an error occurs during the writing process.
- **See also**: [`fd_solcap_write_bank_preimage2`](fd_solcap_writer.c.driver.md#fd_solcap_write_bank_preimage2)  (Implementation)


---
### fd\_solcap\_write\_transaction2<!-- {{#callable_declaration:fd_solcap_write_transaction2}} -->
Writes a transaction to the capture stream.
- **Description**: This function appends a transaction to the current capture stream managed by the writer. It should be called only for transactions that are part of the current slot's transaction hash. The writer must be properly initialized before calling this function. If the writer is null, the function returns immediately without performing any operations. This function is part of the process of recording transaction data in a structured format for later retrieval or analysis.
- **Inputs**:
    - `writer`: A pointer to an initialized fd_solcap_writer_t object. Must not be null. The function will return immediately if this parameter is null.
    - `txn`: A pointer to a fd_solcap_Transaction object representing the transaction to be written. The caller retains ownership of this object, and it must be valid for the duration of the function call.
- **Output**: Returns 0 on success or if the writer is null, indicating no operation was performed.
- **See also**: [`fd_solcap_write_transaction2`](fd_solcap_writer.c.driver.md#fd_solcap_write_transaction2)  (Implementation)



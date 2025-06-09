# Purpose
This C header file, `fd_bank_abi.h`, defines the application binary interface (ABI) for handling transactions within a banking system, specifically focusing on the concept of a `SanitizedTransaction`. The file provides a structured way to manage transaction data and its associated metadata, which includes various vectors of data types such as `uchar`, `CompiledInstruction`, `MessageAddressTableLookup`, and `Pubkey`. These vectors are stored in a sidecar buffer, which is a separate memory area that holds additional data required by the transaction. The file defines constants for transaction alignment and footprint, as well as macros to calculate the footprint of the sidecar data based on the number of accounts, instructions, and address table lookups involved in a transaction.

The file also declares a set of functions and error codes related to transaction initialization and address lookup table resolution. The [`fd_bank_abi_txn_init`](#fd_bank_abi_txn_init) function is responsible for constructing a transaction in memory, while [`fd_bank_abi_resolve_address_lookup_tables`](#fd_bank_abi_resolve_address_lookup_tables) resolves address lookup tables for a given transaction. The header file ensures ABI compatibility with a Rust representation of transactions, although it notes the complexity and potential instability of this approach. The functions and structures defined in this file are intended to be used in conjunction with a Rust environment, where the C-constructed transactions are passed as references to Rust code. The file is part of a larger system, as indicated by its inclusion of other headers and its role in managing transaction data efficiently and safely across language boundaries.
# Imports and Dependencies

---
- `../../disco/pack/fd_pack.h`
- `../../ballet/blake3/fd_blake3.h`


# Global Variables

---
### fd\_bank\_abi\_get\_lookup\_addresses
- **Type**: `function`
- **Description**: The `fd_bank_abi_get_lookup_addresses` function is a global function that returns a pointer to the expanded address lookup tables for a given transaction. It is used to access the accounts loaded from an address lookup table, with writable accounts listed first. If the transaction does not involve any address lookup tables, the return value is undefined and may be NULL.
- **Use**: This function is used to retrieve the address lookup tables associated with a transaction, providing access to the accounts involved.


# Data Structures

---
### fd\_bank\_abi\_txn\_t
- **Type**: `struct`
- **Members**:
    - `fd_bank_abi_txn_private`: A private structure used to define the fd_bank_abi_txn_t type.
- **Description**: The `fd_bank_abi_txn_t` is a typedef for a private structure `fd_bank_abi_txn_private`, which is designed to be ABI compatible with a Rust `RuntimeTransaction<SanitizedTransaction>`. This structure is used to handle transactions in a way that avoids unnecessary data copying by utilizing a sidecar buffer for storing vector data. The structure is intended to be used in conjunction with specific functions to initialize and manage transaction data, ensuring that the transaction and its sidecar buffer have the same lifetime. It is crucial for performance optimization and is not safe for direct manipulation in Rust due to its unconventional memory management.


# Function Declarations (Public API)

---
### fd\_bank\_abi\_txn\_init<!-- {{#callable_declaration:fd_bank_abi_txn_init}} -->
Initialize a sanitized transaction with sidecar data for a given bank and slot.
- **Description**: This function initializes a sanitized transaction structure, `fd_bank_abi_txn_t`, using the provided transaction data and associated metadata. It should be called when you need to prepare a transaction for processing within a specific bank and slot context. The function requires pre-allocated memory for both the transaction and its sidecar data, which must be of sufficient size as defined by `FD_BANK_ABI_TXN_FOOTPRINT` and `FD_BANK_ABI_TXN_FOOTPRINT_SIDECAR`. The function handles both legacy and versioned transactions, setting up necessary fields and computing hashes as needed. It returns a success or error code based on the initialization outcome.
- **Inputs**:
    - `out_txn`: Pointer to a pre-allocated buffer where the initialized transaction will be stored. Must be at least `FD_BANK_ABI_TXN_FOOTPRINT` bytes.
    - `out_sidecar`: Pointer to a pre-allocated buffer for storing sidecar data. Must be large enough to accommodate the sidecar data as determined by the transaction's requirements.
    - `bank`: Pointer to a constant bank object representing the context in which the transaction is being initialized.
    - `slot`: The slot number for which the transaction is being initialized, affecting address lookup table resolution.
    - `blake3`: Pointer to a Blake3 hashing context used to compute the transaction's message hash.
    - `payload`: Pointer to the raw transaction payload data, which must be valid and correctly formatted.
    - `payload_sz`: Size of the transaction payload in bytes, indicating the length of the data pointed to by `payload`.
    - `txn`: Pointer to a parsed transaction structure containing metadata and instructions for the transaction.
    - `is_simple_vote`: Integer flag indicating whether the transaction is a simple vote (non-zero) or not (zero).
- **Output**: Returns `FD_BANK_ABI_TXN_INIT_SUCCESS` on successful initialization or an error code such as `FD_BANK_ABI_TXN_INIT_ERR_*` on failure.
- **See also**: [`fd_bank_abi_txn_init`](fd_bank_abi.c.driver.md#fd_bank_abi_txn_init)  (Implementation)


---
### fd\_bank\_abi\_get\_lookup\_addresses<!-- {{#callable_declaration:fd_bank_abi_get_lookup_addresses}} -->
Retrieve the expanded address lookup tables for a transaction.
- **Description**: Use this function to obtain a pointer to the expanded address lookup tables associated with a given transaction. This is useful when you need to access the accounts loaded from address lookup tables, with writable accounts listed first. The function should be called on a transaction that has been properly initialized using `fd_bank_abi_txn_init`. If the transaction does not involve any address lookup tables, the return value is undefined and may be NULL. The returned pointer is valid as long as the sidecar memory region associated with the transaction remains valid.
- **Inputs**:
    - `txn`: A pointer to a `fd_bank_abi_txn_t` structure, which must have been initialized using `fd_bank_abi_txn_init`. The transaction should be one that potentially involves address lookup tables. The pointer must not be null.
- **Output**: A pointer to the expanded address lookup tables within the sidecar region of the transaction, or NULL if the transaction does not load any accounts from an address lookup table. The pointer's validity is tied to the lifetime of the sidecar memory region.
- **See also**: [`fd_bank_abi_get_lookup_addresses`](fd_bank_abi.c.driver.md#fd_bank_abi_get_lookup_addresses)  (Implementation)



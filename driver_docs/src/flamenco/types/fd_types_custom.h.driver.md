# Purpose
This C header file, `fd_types_custom.h`, is part of a larger software system and provides a collection of type definitions and utility functions related to cryptographic operations, transaction handling, and network addressing. The file defines several data structures and associated operations, such as `fd_hash_t` and `fd_pubkey_t`, which are used for handling cryptographic hashes and public keys. These structures are designed to be interchangeable, as indicated by their shared footprint and alignment. The file also includes definitions for handling digital signatures (`fd_signature_t`) and transaction metadata (`fd_txnstatusidx_t`), which are crucial for maintaining the integrity and status of transactions within the system.

Additionally, the file provides structures and functions for encoding and decoding operations, particularly for Solana vote accounts and transactions, as seen in the [`fd_solana_vote_account_decode`](#fd_solana_vote_account_decode) and `fd_flamenco_txn` functions. These functions facilitate the serialization and deserialization of data, which is essential for network communication and data storage. The inclusion of network-related types, such as `fd_gossip_ip4_addr_t` and `fd_gossip_ip6_addr_t`, suggests that the file also supports network communication functionalities. Overall, this header file serves as a foundational component for cryptographic and transaction-related operations within the broader software system, providing essential types and functions that are likely used across multiple modules.
# Imports and Dependencies

---
- `fd_types_meta.h`
- `fd_bincode.h`
- `../../ballet/ed25519/fd_ed25519.h`
- `../../ballet/txn/fd_txn.h`
- `../../util/net/fd_ip4.h`


# Global Variables

---
### fd\_solana\_vote\_account\_decode
- **Type**: `function pointer`
- **Description**: `fd_solana_vote_account_decode` is a function that decodes a Solana vote account from a binary format into a memory structure. It takes a pointer to a memory location and a decoding context as parameters.
- **Use**: This function is used to convert encoded binary data of a Solana vote account into a usable in-memory structure for further processing.


---
### fd\_flamenco\_txn\_new
- **Type**: `function`
- **Description**: The `fd_flamenco_txn_new` function is a static inline function that initializes a `fd_flamenco_txn_t` structure. It is defined as an empty function, indicating that it currently does not perform any operations on the `fd_flamenco_txn_t` instance passed to it.
- **Use**: This function is used to initialize a `fd_flamenco_txn_t` structure, although it currently does not modify the structure.


---
### fd\_flamenco\_txn\_decode\_global
- **Type**: `function pointer`
- **Description**: `fd_flamenco_txn_decode_global` is a function pointer that points to a function responsible for decoding a global transaction in the Flamenco system. It takes a memory pointer and a decoding context as parameters, and returns a pointer to the decoded transaction data.
- **Use**: This function is used to decode transaction data from a global context, facilitating the processing of transactions in the Flamenco system.


---
### fd\_flamenco\_txn\_decode
- **Type**: `function pointer`
- **Description**: `fd_flamenco_txn_decode` is a function that decodes a transaction from a memory buffer using a specified binary decoding context. It is part of the transaction handling utilities in the Flamenco runtime, which deals with encoding and decoding operations for transactions.
- **Use**: This function is used to decode a transaction from a memory buffer, utilizing a binary decoding context to interpret the data.


# Data Structures

---
### fd\_hash
- **Type**: `union`
- **Members**:
    - `hash`: An array of unsigned characters with a size defined by FD_HASH_FOOTPRINT, used to store hash values.
    - `key`: An array of unsigned characters with a size defined by FD_HASH_FOOTPRINT, interchangeable with fd_pubkey.
    - `ul`: An array of unsigned long integers, providing access to the data as ulong types.
    - `ui`: An array of unsigned integers, providing access to the data as uint types.
    - `uc`: An array of unsigned characters, providing access to the data as uchar types.
- **Description**: The `fd_hash` union is a packed data structure designed to store hash values and public keys interchangeably, with multiple type-specific accessors for different data types. It allows the same memory footprint to be accessed as an array of unsigned characters, unsigned integers, or unsigned long integers, providing flexibility in how the data is manipulated and interpreted. The use of packed attribute ensures that there is no padding between the members, which is crucial for certain applications where memory layout consistency is required.


---
### fd\_hash\_t
- **Type**: `union`
- **Members**:
    - `hash`: An array of unsigned characters representing the hash, with a footprint of 32 bytes.
    - `key`: An array of unsigned characters representing the key, also with a footprint of 32 bytes, making fd_hash and fd_pubkey interchangeable.
    - `ul`: An array of unsigned long integers for type-specific access, with a size based on the hash footprint divided by the size of ulong.
    - `ui`: An array of unsigned integers for type-specific access, with a size based on the hash footprint divided by the size of uint.
    - `uc`: An array of unsigned characters, identical to the hash array, for type-specific access.
- **Description**: The `fd_hash_t` is a union data structure designed to store a hash or public key in a flexible manner, allowing interchangeable use between hash and public key representations. It provides multiple type-specific accessors, including arrays of unsigned characters, unsigned long integers, and unsigned integers, all aligned to a 32-byte footprint. This design facilitates efficient memory usage and interoperability within the system, particularly in cryptographic and network-related operations.


---
### fd\_pubkey\_t
- **Type**: `union`
- **Members**:
    - `hash`: An array of unsigned characters representing a hash with a fixed footprint size.
    - `key`: An array of unsigned characters, identical to 'hash', allowing interchangeability between fd_hash and fd_pubkey.
    - `ul`: An array of unsigned long integers for accessing the hash as long integers.
    - `ui`: An array of unsigned integers for accessing the hash as integers.
    - `uc`: An array of unsigned characters for accessing the hash as characters.
- **Description**: The `fd_pubkey_t` is a union type that is defined as an alias for `fd_hash`, allowing it to represent a public key in a flexible manner. It provides multiple ways to access the underlying data, including as a byte array, long integers, or integers, making it versatile for various cryptographic operations. The union is packed to ensure no padding is added, maintaining a consistent footprint and alignment, which is crucial for cryptographic data structures.


---
### fd\_signature
- **Type**: `union`
- **Members**:
    - `uc`: An array of 64 unsigned characters.
    - `ul`: An array of 8 unsigned long integers.
- **Description**: The `fd_signature` union is a data structure that provides two different views of a 512-bit signature: as an array of 64 bytes (`uchar`) or as an array of 8 unsigned long integers (`ulong`). This allows for flexible manipulation and interpretation of the signature data, depending on the context in which it is used.


---
### fd\_signature\_t
- **Type**: `union`
- **Members**:
    - `uc`: An array of 64 unsigned characters representing the signature in byte form.
    - `ul`: An array of 8 unsigned long integers representing the signature in a different format.
- **Description**: The `fd_signature_t` is a union data structure that provides two different representations of a digital signature. It can be accessed as an array of 64 bytes (`uchar`) or as an array of 8 unsigned long integers (`ulong`). This flexibility allows for different types of operations or interpretations on the signature data, depending on the context in which it is used.


---
### fd\_option\_slot
- **Type**: `struct`
- **Members**:
    - `is_some`: A uchar indicating whether the slot value is valid or not.
    - `slot`: A ulong representing the slot value.
- **Description**: The `fd_option_slot` structure is a simple data structure that represents an optional slot value. It contains a flag `is_some` to indicate the presence of a valid slot value, and a `slot` field to store the actual slot value if it is present. This structure is aligned to 8 bytes, ensuring efficient memory access and usage.


---
### fd\_option\_slot\_t
- **Type**: `struct`
- **Members**:
    - `is_some`: A flag indicating whether the option contains a value (1) or is empty (0).
    - `slot`: An unsigned long integer representing the slot value when the option is not empty.
- **Description**: The `fd_option_slot_t` structure is a simple data structure used to represent an optional slot value. It contains a flag `is_some` to indicate the presence of a valid slot value, and a `slot` field to store the actual slot value when present. This structure is useful for scenarios where a slot value may or may not be available, allowing for efficient handling of optional data.


---
### fd\_txnstatusidx
- **Type**: `struct`
- **Members**:
    - `sig`: An Ed25519 signature associated with the transaction status index.
    - `offset`: An unsigned long integer representing the offset in the transaction status metadata block.
    - `status_sz`: An unsigned long integer indicating the size of the status in the transaction status metadata block.
- **Description**: The `fd_txnstatusidx` structure is designed to index transaction status metadata blocks, providing a way to associate an Ed25519 signature with specific metadata through an offset and size. This structure is useful in systems where transaction metadata needs to be efficiently accessed and managed, particularly in blockchain or distributed ledger environments where transaction integrity and status tracking are critical.


---
### fd\_txnstatusidx\_t
- **Type**: `struct`
- **Members**:
    - `sig`: Holds the signature of the transaction using the Ed25519 signature scheme.
    - `offset`: Represents the offset position of the transaction status in a data block.
    - `status_sz`: Indicates the size of the transaction status metadata.
- **Description**: The `fd_txnstatusidx_t` structure is designed to index transaction status metadata blocks. It contains a signature field `sig` for verifying the transaction using Ed25519, an `offset` field to locate the transaction status within a data block, and a `status_sz` field to specify the size of the transaction status metadata. This structure is essential for managing and accessing transaction status information efficiently in a system that handles numerous transactions.


---
### fd\_gossip\_ip6\_addr
- **Type**: `union`
- **Members**:
    - `uc`: An array of 16 unsigned characters representing the IPv6 address in byte format.
    - `us`: An array of 8 unsigned short integers representing the IPv6 address in 16-bit segments.
    - `ul`: An array of 4 unsigned integers representing the IPv6 address in 32-bit segments.
- **Description**: The `fd_gossip_ip6_addr` is a union data structure designed to represent an IPv6 address in multiple formats. It provides three different views of the same 128-bit address: as an array of 16 bytes (`uchar`), as an array of 8 16-bit unsigned shorts (`ushort`), and as an array of 4 32-bit unsigned integers (`uint`). This flexibility allows for easy manipulation and access to the IPv6 address in different contexts, depending on the required granularity or format.


---
### fd\_gossip\_ip6\_addr\_t
- **Type**: `union`
- **Members**:
    - `uc`: An array of 16 unsigned characters representing the IPv6 address.
    - `us`: An array of 8 unsigned short integers representing the IPv6 address.
    - `ul`: An array of 4 unsigned integers representing the IPv6 address.
- **Description**: The `fd_gossip_ip6_addr_t` is a union data structure designed to represent an IPv6 address in multiple formats. It provides three different views of the same 128-bit address: as an array of 16 bytes (`uchar`), as an array of 8 16-bit unsigned shorts (`ushort`), and as an array of 4 32-bit unsigned integers (`uint`). This flexibility allows for efficient manipulation and access to the IPv6 address data in various contexts, depending on the specific requirements of the application.


---
### fd\_flamenco\_txn
- **Type**: `struct`
- **Members**:
    - `txn_buf`: A buffer of unsigned characters with a maximum size defined by FD_TXN_MAX_SZ, used to store transaction data.
    - `txn`: An extension of fd_txn_t, representing a transaction, defined as an array of zero elements.
    - `raw`: An array of unsigned characters with a size defined by FD_TXN_MTU, used to store raw transaction data.
    - `raw_sz`: An unsigned long integer representing the size of the raw transaction data.
- **Description**: The `fd_flamenco_txn` structure is a wrapper around transaction data, providing a flexible buffer for storing transaction information and its raw representation. It includes a union that allows access to the transaction data either as a buffer of unsigned characters or as an extended transaction type (`fd_txn_t`). The structure also maintains the size of the raw transaction data, facilitating encoding and decoding operations. This structure is part of a larger system for handling transactions, likely in a blockchain or distributed ledger context, and is designed to be replaced by a more efficient implementation in the future.


---
### fd\_flamenco\_txn\_t
- **Type**: `struct`
- **Members**:
    - `txn_buf`: A buffer to hold the transaction data with a maximum size defined by FD_TXN_MAX_SZ.
    - `txn`: An extension to access the transaction as an fd_txn_t type.
    - `raw`: A buffer to hold the raw transaction data with a maximum transmission unit size defined by FD_TXN_MTU.
    - `raw_sz`: The size of the raw transaction data stored in the raw buffer.
- **Description**: The `fd_flamenco_txn_t` structure is a wrapper around the `fd_txn_t` type, designed to manage transaction data within a buffer. It includes a buffer `txn_buf` for storing transaction data, a `raw` buffer for raw transaction data, and a `raw_sz` field to track the size of the data in the `raw` buffer. This structure facilitates encoding and decoding of transaction data, and is intended to be replaced by a more efficient stubs generator in the future.


# Functions

---
### fd\_hash\_eq<!-- {{#callable:fd_hash_eq}} -->
The `fd_hash_eq` function compares two `fd_hash_t` structures for equality by checking if their memory contents are identical.
- **Inputs**:
    - `a`: A pointer to the first `fd_hash_t` structure to be compared.
    - `b`: A pointer to the second `fd_hash_t` structure to be compared.
- **Control Flow**:
    - The function uses `memcmp` to compare the memory contents of the two `fd_hash_t` structures pointed to by `a` and `b`.
    - It checks if the result of `memcmp` is zero, which indicates that the memory contents are identical.
- **Output**: The function returns an integer value: `1` if the two `fd_hash_t` structures are equal, and `0` otherwise.


---
### fd\_flamenco\_txn\_destroy<!-- {{#callable:fd_flamenco_txn_destroy}} -->
The `fd_flamenco_txn_destroy` function is a placeholder for destroying a `fd_flamenco_txn_t` transaction object, but currently does nothing.
- **Inputs**:
    - `self`: A pointer to a constant `fd_flamenco_txn_t` object that is intended to be destroyed.
- **Control Flow**:
    - The function is defined as `static inline`, indicating it is intended for use within the same translation unit and suggests it should be inlined by the compiler.
    - The function takes a single argument, `self`, which is a pointer to a constant `fd_flamenco_txn_t` object.
    - The function body is empty, meaning it performs no operations on the input argument.
- **Output**: The function does not produce any output or perform any operations.


---
### fd\_flamenco\_txn\_size<!-- {{#callable:fd_flamenco_txn_size}} -->
The `fd_flamenco_txn_size` function returns the size of the raw transaction data in a `fd_flamenco_txn_t` structure.
- **Inputs**:
    - `self`: A pointer to a constant `fd_flamenco_txn_t` structure, representing the transaction whose raw size is to be retrieved.
- **Control Flow**:
    - The function accesses the `raw_sz` member of the `fd_flamenco_txn_t` structure pointed to by `self`.
    - It returns the value of `raw_sz`, which represents the size of the raw transaction data.
- **Output**: The function returns an `ulong` representing the size of the raw transaction data in the `fd_flamenco_txn_t` structure.


---
### fd\_flamenco\_txn\_encode<!-- {{#callable:fd_flamenco_txn_encode}} -->
The `fd_flamenco_txn_encode` function encodes a transaction's raw data into a binary encoding context.
- **Inputs**:
    - `self`: A pointer to a `fd_flamenco_txn_t` structure containing the transaction data to be encoded.
    - `ctx`: A pointer to a `fd_bincode_encode_ctx_t` structure that represents the binary encoding context where the transaction data will be encoded.
- **Control Flow**:
    - The function calls [`fd_bincode_bytes_encode`](fd_bincode.h.driver.md#fd_bincode_bytes_encode) with the transaction's raw data (`self->raw`), its size (`self->raw_sz`), and the encoding context (`ctx`).
    - The result of the [`fd_bincode_bytes_encode`](fd_bincode.h.driver.md#fd_bincode_bytes_encode) function call is returned as the output of `fd_flamenco_txn_encode`.
- **Output**: The function returns an integer which is the result of the [`fd_bincode_bytes_encode`](fd_bincode.h.driver.md#fd_bincode_bytes_encode) function, indicating the success or failure of the encoding process.
- **Functions called**:
    - [`fd_bincode_bytes_encode`](fd_bincode.h.driver.md#fd_bincode_bytes_encode)


---
### fd\_flamenco\_txn\_walk<!-- {{#callable:fd_flamenco_txn_walk}} -->
The `fd_flamenco_txn_walk` function processes a transaction by retrieving its first signature and passing it to a callback function for further handling.
- **Inputs**:
    - `w`: A pointer to a context or state that is passed to the callback function `fun`.
    - `self`: A pointer to a `fd_flamenco_txn_t` structure representing the transaction to be processed.
    - `fun`: A function pointer of type `fd_types_walk_fn_t` that is called with the transaction's signature and other parameters.
    - `name`: A constant character pointer representing the name associated with the transaction, passed to the callback function.
    - `level`: An unsigned integer representing the level or depth of the transaction, passed to the callback function.
- **Control Flow**:
    - Initialize a static array `zero` with 64 zero bytes to use as a default signature.
    - Retrieve the transaction from the `self` parameter and assign it to `txn`.
    - Initialize `sig0` to point to `zero` as a default signature.
    - Check if the transaction has any signatures using `FD_LIKELY` macro for likely branch prediction.
    - If the transaction has signatures, retrieve the first signature using `fd_txn_get_signatures` and assign it to `sig0`.
    - Call the function `fun` with the context `w`, the signature `sig0`, the name, a constant `FD_FLAMENCO_TYPE_SIG512`, a string "txn", and the level.
- **Output**: The function does not return a value; it performs an operation by calling the provided callback function `fun` with the transaction's signature and other parameters.


---
### fd\_flamenco\_txn\_align<!-- {{#callable:fd_flamenco_txn_align}} -->
The `fd_flamenco_txn_align` function returns the alignment requirement of the `fd_flamenco_txn_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as `static inline`, indicating it is intended for use within the same translation unit and suggests performance optimization by inlining.
    - The function returns the result of the `alignof` operator applied to `fd_flamenco_txn_t`, which determines the alignment requirement of this type.
- **Output**: The function returns an `ulong` representing the alignment requirement of the `fd_flamenco_txn_t` structure.


---
### fd\_flamenco\_txn\_footprint<!-- {{#callable:fd_flamenco_txn_footprint}} -->
The `fd_flamenco_txn_footprint` function returns the size in bytes of the `fd_flamenco_txn_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as `static inline`, indicating it is intended for use within the same translation unit and suggests inlining for performance.
    - The function body consists of a single return statement that returns the result of the `sizeof` operator applied to `fd_flamenco_txn_t`.
- **Output**: The function returns an `ulong` representing the size in bytes of the `fd_flamenco_txn_t` structure.


# Function Declarations (Public API)

---
### fd\_flamenco\_txn\_encode\_global<!-- {{#callable_declaration:FD_FN_UNUSED::fd_flamenco_txn_encode_global}} -->
Encode a Flamenco transaction using a global context.
- **Description**: This function is intended for encoding a Flamenco transaction using a provided encoding context. It is primarily designed for testing purposes and should not be used in production code. The function requires a valid Flamenco transaction and an encoding context as inputs. It is expected to be called in scenarios where testing of transaction encoding is necessary. The function does not perform any actual encoding and will log an error if invoked.
- **Inputs**:
    - `self`: A pointer to a constant `fd_flamenco_txn_t` structure representing the transaction to be encoded. The pointer must not be null.
    - `ctx`: A pointer to an `fd_bincode_encode_ctx_t` structure representing the encoding context. The pointer must not be null.
- **Output**: An integer error code is returned, indicating the function is not intended for use and will log an error.
- **See also**: [`FD_FN_UNUSED::fd_flamenco_txn_encode_global`](fd_types_custom.c.driver.md#FD_FN_UNUSEDfd_flamenco_txn_encode_global)  (Implementation)


---
### fd\_flamenco\_txn\_decode\_global<!-- {{#callable_declaration:FD_FN_UNUSED::fd_flamenco_txn_decode_global}} -->
Decode a global transaction for testing purposes.
- **Description**: This function is intended solely for testing and does not perform any actual decoding of a transaction. It logs an error message indicating its purpose as a test-only function. This function should not be used in production code as it does not provide any functional behavior beyond error logging.
- **Inputs**:
    - `mem`: A pointer to memory intended for transaction data. This parameter is not used in the function.
    - `ctx`: A pointer to a decoding context of type `fd_bincode_decode_ctx_t`. This parameter is not used in the function.
- **Output**: None
- **See also**: [`FD_FN_UNUSED::fd_flamenco_txn_decode_global`](fd_types_custom.c.driver.md#FD_FN_UNUSEDfd_flamenco_txn_decode_global)  (Implementation)


---
### fd\_flamenco\_txn\_decode\_footprint<!-- {{#callable_declaration:fd_flamenco_txn_decode_footprint}} -->
Calculates the footprint size for decoding a Flamenco transaction.
- **Description**: Use this function to determine the memory footprint required for decoding a Flamenco transaction. It should be called with a valid decoding context and a pointer to a size accumulator. The function updates the total size by adding the size of a Flamenco transaction and then attempts to decode the footprint using an internal function. The decoding context's data pointer is restored to its original state after the operation, ensuring no side effects on the context's data position.
- **Inputs**:
    - `ctx`: A pointer to a valid `fd_bincode_decode_ctx_t` structure representing the decoding context. Must not be null.
    - `total_sz`: A pointer to an `ulong` that accumulates the total size required for decoding. Must not be null. The function adds the size of a Flamenco transaction to this value.
- **Output**: Returns an integer error code indicating the success or failure of the footprint decoding operation.
- **See also**: [`fd_flamenco_txn_decode_footprint`](fd_types_custom.c.driver.md#fd_flamenco_txn_decode_footprint)  (Implementation)


---
### fd\_flamenco\_txn\_decode\_footprint\_inner<!-- {{#callable_declaration:fd_flamenco_txn_decode_footprint_inner}} -->
Decodes a transaction footprint from a binary context.
- **Description**: This function is used to decode a transaction footprint from a binary context, updating the context's data pointer and the total size of the decoded data. It should be called when you need to parse transaction data from a binary stream. The function expects the context to have sufficient data available; otherwise, it returns an overflow error. It also updates the total size with the size of the decoded transaction data.
- **Inputs**:
    - `ctx`: A pointer to an fd_bincode_decode_ctx_t structure representing the binary decoding context. The data pointer within this context must not exceed the dataend pointer, as this would result in an overflow error.
    - `total_sz`: A pointer to an unsigned long where the function will add the size of the decoded transaction data. The caller must ensure this pointer is valid and initialized before calling the function.
- **Output**: Returns 0 on success, or a negative error code if an overflow or parsing error occurs.
- **See also**: [`fd_flamenco_txn_decode_footprint_inner`](fd_types_custom.c.driver.md#fd_flamenco_txn_decode_footprint_inner)  (Implementation)


---
### fd\_flamenco\_txn\_decode<!-- {{#callable_declaration:fd_flamenco_txn_decode}} -->
Decodes a transaction from a binary context into memory.
- **Description**: Use this function to decode a transaction from a binary format into a pre-allocated memory region. It initializes the transaction structure and decodes the transaction data using the provided decoding context. Ensure that the memory region is large enough to hold the transaction structure and any additional data. This function must be called with a valid decoding context and a properly allocated memory region to avoid undefined behavior.
- **Inputs**:
    - `mem`: A pointer to a pre-allocated memory region where the decoded transaction will be stored. Must not be null and should be large enough to accommodate the transaction structure.
    - `ctx`: A pointer to a decoding context used to interpret the binary data. Must not be null and should be properly initialized before calling this function.
- **Output**: Returns a pointer to the decoded transaction structure within the provided memory region.
- **See also**: [`fd_flamenco_txn_decode`](fd_types_custom.c.driver.md#fd_flamenco_txn_decode)  (Implementation)


---
### fd\_flamenco\_txn\_decode\_inner<!-- {{#callable_declaration:fd_flamenco_txn_decode_inner}} -->
Decodes a transaction from a binary context into a transaction structure.
- **Description**: Use this function to decode a transaction from a binary format into a `fd_flamenco_txn_t` structure. It is essential to ensure that `struct_mem` points to a valid `fd_flamenco_txn_t` structure and `ctx` is properly initialized with the binary data to decode. The function updates the transaction structure with the decoded data and advances the context's data pointer by the size of the decoded transaction. If decoding fails, an error is logged, and the function returns without modifying the transaction structure.
- **Inputs**:
    - `struct_mem`: A pointer to a `fd_flamenco_txn_t` structure where the decoded transaction will be stored. Must not be null.
    - `alloc_mem`: A pointer to a memory allocation pointer, which is not used in this function. Can be null.
    - `ctx`: A pointer to a `fd_bincode_decode_ctx_t` structure containing the binary data to decode. Must not be null and should be properly initialized with data to decode.
- **Output**: None
- **See also**: [`fd_flamenco_txn_decode_inner`](fd_types_custom.c.driver.md#fd_flamenco_txn_decode_inner)  (Implementation)



# Purpose
This C header file defines the structures and constants necessary for representing and manipulating Solana transactions within a software system. The primary structure defined is `fd_txn_t`, which encapsulates the details of a Solana transaction, including its version, signatures, account addresses, instructions, and optional address lookup tables. The file also defines `fd_txn_instr_t` for representing individual instructions within a transaction, and `fd_txn_acct_addr_lut_t` for handling address lookup tables. These structures are crucial for managing the atomicity and execution of transactions on the Solana blockchain, ensuring that transactions are processed correctly and efficiently.

The header file provides a comprehensive set of macros and inline functions to facilitate the parsing, validation, and manipulation of transaction data. It includes constants for transaction formats, signature sizes, and account address limits, which are essential for maintaining compatibility with Solana's specifications. The file also defines utility functions for accessing transaction components, such as signatures and account addresses, and for iterating over accounts with specific properties. Additionally, it includes mechanisms for tracking parsing success and failure, which are useful for debugging and performance monitoring. Overall, this header file serves as a foundational component for any system that needs to interact with Solana transactions, providing both the data structures and the operational logic required for effective transaction management.
# Imports and Dependencies

---
- `../fd_ballet_base.h`
- `../ed25519/fd_ed25519.h`


# Data Structures

---
### fd\_txn\_instr
- **Type**: `struct`
- **Members**:
    - `program_id`: The index of the program's account address in the transaction's list of account addresses.
    - `_padding_reserved_1`: Explicit padding to align the structure as the compiler would.
    - `acct_cnt`: The number of accounts this instruction references.
    - `data_sz`: The size in bytes of the data passed to this instruction.
    - `acct_off`: The byte offset where the account address index array starts.
    - `data_off`: The byte offset where the instruction data array starts.
- **Description**: The `fd_txn_instr` structure represents a single instruction within a Solana transaction, detailing the invocation of a smart contract with specific data and accounts. It includes fields for identifying the program to invoke, the number of accounts involved, the size and location of the data, and offsets for accessing account indices and instruction data within the transaction payload. This structure is crucial for defining the operations to be executed as part of a transaction, allowing for the specification of both the program logic and the resources it requires.


---
### fd\_txn\_instr\_t
- **Type**: `struct`
- **Members**:
    - `program_id`: The index of the program's account address in the transaction's list of account addresses.
    - `_padding_reserved_1`: Explicit padding to align the structure.
    - `acct_cnt`: The number of accounts this instruction references.
    - `data_sz`: The size in bytes of the data passed to this instruction.
    - `acct_off`: The byte offset where the account address index array starts.
    - `data_off`: The byte offset where the instruction data array starts.
- **Description**: The `fd_txn_instr_t` structure represents a single instruction within a Solana transaction, which is essentially a command to execute a smart contract with specified data and accounts. Each instruction specifies the program to invoke, the number of accounts it references, and the size and location of the data and account indices within the transaction payload. This structure is crucial for defining the steps a transaction will execute on the Solana blockchain.


---
### fd\_txn
- **Type**: `struct`
- **Members**:
    - `transaction_version`: The version number of this transaction, must be one of { FD_TXN_VLEGACY, FD_TXN_V0 }.
    - `signature_cnt`: The number of signatures in this transaction, ranging from 1 to FD_TXN_SIG_MAX.
    - `signature_off`: The byte offset where the signatures start, relative to the start of the transaction.
    - `message_off`: The byte offset where the 'message' starts, relative to the start of the transaction.
    - `readonly_signed_cnt`: The number of signatures that are read-only, ranging from 0 to signature_cnt.
    - `readonly_unsigned_cnt`: The number of read-only account addresses without accompanying signatures.
    - `acct_addr_cnt`: The number of account addresses in this transaction, excluding address table lookups.
    - `acct_addr_off`: The byte offset where the account addresses start, relative to the start of the transaction.
    - `recent_blockhash_off`: The byte offset where the recent blockhash starts, relative to the start of the transaction.
    - `addr_table_lookup_cnt`: The number of address lookup tables in this transaction, must be 0 if transaction_version is FD_TXN_VLEGACY.
    - `addr_table_adtl_writable_cnt`: The total number of writable account addresses across all address table lookups.
    - `addr_table_adtl_cnt`: The total number of account addresses across all address lookup tables.
    - `_padding_reserved_1`: Explicit padding that the compiler would have inserted.
    - `instr_cnt`: The number of instructions in this transaction, ranging from 0 to FD_TXN_INSTR_MAX.
    - `instr`: A flexible array member of instructions in this transaction, indexed from 0 to instr_cnt.
- **Description**: The `fd_txn` structure represents a Solana transaction, encapsulating various components such as versioning, signatures, account addresses, and instructions. It includes fields for managing offsets and counts of signatures, account addresses, and instructions, as well as handling address lookup tables for transactions. The structure is designed to support both legacy and versioned transactions, with specific fields dedicated to managing read-only and writable accounts, ensuring the transaction's integrity and execution within the Solana blockchain environment.


---
### fd\_txn\_t
- **Type**: `struct`
- **Members**:
    - `transaction_version`: The version number of this transaction, indicating the format used.
    - `signature_cnt`: The number of signatures included in this transaction.
    - `signature_off`: The byte offset where the signatures start in the transaction data.
    - `message_off`: The byte offset where the message starts, which is covered by the signatures.
    - `readonly_signed_cnt`: The count of signatures that are read-only.
    - `readonly_unsigned_cnt`: The count of account addresses without signatures that are read-only.
    - `acct_addr_cnt`: The total number of account addresses in the transaction.
    - `acct_addr_off`: The byte offset where the account addresses start in the transaction data.
    - `recent_blockhash_off`: The byte offset where the recent blockhash starts in the transaction data.
    - `addr_table_lookup_cnt`: The number of address lookup tables included in the transaction.
    - `addr_table_adtl_writable_cnt`: The count of writable account addresses from address table lookups.
    - `addr_table_adtl_cnt`: The total count of account addresses from address table lookups.
    - `_padding_reserved_1`: Explicit padding for alignment purposes.
    - `instr_cnt`: The number of instructions included in this transaction.
    - `instr`: A flexible array of instructions that are part of the transaction.
- **Description**: The `fd_txn_t` structure represents a Solana transaction, which is a fundamental unit of execution in the Solana blockchain. It encapsulates a list of instructions, account addresses, and other metadata necessary for executing a transaction. The structure includes fields for managing transaction versions, signatures, account addresses, and instructions, as well as offsets for accessing various components within the serialized transaction data. This design allows for efficient parsing and execution of transactions, supporting features like address lookup tables and handling of read-only and writable accounts.


---
### fd\_txn\_acct\_addr\_lut
- **Type**: `struct`
- **Members**:
    - `addr_off`: The offset in bytes from the start of the transaction to where the account address is stored.
    - `writable_cnt`: The number of account addresses selected as writable from the on-chain list.
    - `readonly_cnt`: The number of account addresses selected as read-only from the on-chain list.
    - `writable_off`: The offset in bytes from the start of the transaction to where writable account indices begin.
    - `readonly_off`: The offset in bytes from the start of the transaction to where read-only account indices begin.
- **Description**: The `fd_txn_acct_addr_lut` structure is an on-chain address lookup table used in Solana transactions to specify which account addresses from an on-chain list should be included in the transaction's list of account addresses. It includes offsets for locating account addresses and indices within the transaction data, as well as counts for writable and read-only accounts, allowing for efficient management and access of account permissions within a transaction.


---
### fd\_txn\_acct\_addr\_lut\_t
- **Type**: `struct`
- **Members**:
    - `addr_off`: The offset in bytes where the address of the account containing the list to load is stored.
    - `writable_cnt`: The number of account addresses selected as writable from the on-chain list.
    - `readonly_cnt`: The number of account addresses selected as read-only from the on-chain list.
    - `writable_off`: The offset in bytes where the writable account indices begin.
    - `readonly_off`: The offset in bytes where the read-only account indices begin.
- **Description**: The `fd_txn_acct_addr_lut_t` structure represents an on-chain address lookup table in Solana's transaction system. It is used to specify which account addresses from an on-chain list should be included in the list of account addresses available to instructions in a transaction. This structure allows transactions to reference more accounts by selecting specific addresses as writable or read-only, using offsets to locate these indices within the transaction data.


---
### fd\_txn\_parse\_counters
- **Type**: `struct`
- **Members**:
    - `success_cnt`: The number of times a transaction parsed successfully.
    - `failure_cnt`: The number of times a transaction was ill-formed and failed to parse for any reason.
    - `failure_ring`: An array storing information about the causes of recent transaction parsing failures, specifically the line of code which detected the failure.
- **Description**: The `fd_txn_parse_counters` structure is designed to keep track of the outcomes of transaction parsing attempts. It maintains a count of successful and failed parsing attempts through `success_cnt` and `failure_cnt` respectively. Additionally, it provides a `failure_ring` array to store information about recent parsing failures, which helps in diagnosing issues by recording the line of code where each failure was detected. This structure is useful for monitoring and debugging transaction parsing processes.


---
### fd\_txn\_parse\_counters\_t
- **Type**: `struct`
- **Members**:
    - `success_cnt`: The number of times a transaction parsed successfully.
    - `failure_cnt`: The number of times a transaction was ill-formed and failed to parse.
    - `failure_ring`: An array storing information about the causes of recent transaction parsing failures.
- **Description**: The `fd_txn_parse_counters_t` structure is designed to collect metrics about the outcomes of parsing transactions. It keeps track of the number of successful and failed transaction parses, and maintains a ring buffer to store information about the causes of recent parsing failures. This data structure is useful for monitoring and debugging the transaction parsing process, providing insights into the frequency and nature of parsing errors.


---
### fd\_acct\_addr
- **Type**: `union`
- **Members**:
    - `b`: An array of unsigned characters with a size defined by FD_TXN_ACCT_ADDR_SZ.
- **Description**: The `fd_acct_addr` is a union data structure that encapsulates a Solana account address, which can be an Ed25519 public key, a SHA256 hash, or a hardcoded sysvar. It is defined as a union with a single member, an array of unsigned characters (`uchar`) of size `FD_TXN_ACCT_ADDR_SZ`, which ensures that all types of account addresses have a consistent size. This union is used to represent account addresses in a Solana transaction, providing a flexible way to handle different types of addresses while maintaining a uniform interface.


---
### fd\_acct\_addr\_t
- **Type**: `union`
- **Members**:
    - `b`: An array of bytes representing a Solana account address, with a fixed size of 32 bytes.
- **Description**: The `fd_acct_addr_t` is a union that encapsulates a Solana account address, which can be an Ed25519 public key, a SHA256 hash from a program-derived address, or a hardcoded sysvar. This union provides a flexible way to handle different types of account addresses in a uniform manner, ensuring they all conform to the same size requirement of 32 bytes. The use of a union here allows for different interpretations of the address data without implying any specific alignment.


# Functions

---
### fd\_txn\_get\_address\_tables\_const<!-- {{#callable:fd_txn_get_address_tables_const}} -->
The function `fd_txn_get_address_tables_const` retrieves a constant pointer to the address tables associated with a given Solana transaction.
- **Inputs**:
    - `txn`: A constant pointer to an `fd_txn_t` structure representing a Solana transaction.
- **Control Flow**:
    - The function takes a constant pointer to an `fd_txn_t` structure as input.
    - It calculates the address of the address tables by adding the number of instructions (`instr_cnt`) to the base address of the instructions array (`instr`).
    - The function returns a constant pointer to the calculated address, cast to a `fd_txn_acct_addr_lut_t const *`.
- **Output**: A constant pointer to the address tables (`fd_txn_acct_addr_lut_t const *`) associated with the transaction.


---
### fd\_txn\_get\_signatures<!-- {{#callable:fd_txn_get_signatures}} -->
The `fd_txn_get_signatures` function retrieves the array of Ed25519 signatures from a serialized Solana transaction payload based on the transaction's signature offset.
- **Inputs**:
    - `txn`: A pointer to a constant `fd_txn_t` structure representing a Solana transaction, which contains metadata about the transaction including the signature offset.
    - `payload`: A pointer to a constant void type representing the serialized transaction data from which the signatures are to be extracted.
- **Control Flow**:
    - The function casts the `payload` pointer to an unsigned long integer for arithmetic operations.
    - It adds the `signature_off` value from the `txn` structure to the `payload` pointer, effectively calculating the starting address of the signatures within the payload.
    - The result is cast back to a pointer of type `fd_ed25519_sig_t const *`, which points to the beginning of the signatures array.
- **Output**: A pointer to a constant array of `fd_ed25519_sig_t` structures, representing the signatures in the transaction payload.


---
### fd\_txn\_get\_acct\_addrs<!-- {{#callable:fd_txn_get_acct_addrs}} -->
The `fd_txn_get_acct_addrs` function retrieves the array of account addresses from a serialized Solana transaction payload based on the transaction's account address offset.
- **Inputs**:
    - `txn`: A pointer to a constant `fd_txn_t` structure representing a Solana transaction, which contains metadata about the transaction including the offset to the account addresses.
    - `payload`: A pointer to a constant void type representing the serialized transaction data from which the account addresses are to be extracted.
- **Control Flow**:
    - The function calculates the starting address of the account addresses by adding the `acct_addr_off` offset from the `txn` structure to the base address of the `payload`.
    - It casts the resulting address to a pointer of type `fd_acct_addr_t const *`, which represents an array of account addresses.
- **Output**: A pointer to a constant array of `fd_acct_addr_t`, which are the account addresses extracted from the transaction payload.


---
### fd\_txn\_get\_recent\_blockhash<!-- {{#callable:fd_txn_get_recent_blockhash}} -->
The `fd_txn_get_recent_blockhash` function retrieves the recent blockhash from a Solana transaction payload using an offset specified in the transaction structure.
- **Inputs**:
    - `txn`: A pointer to a `fd_txn_t` structure representing a Solana transaction, which contains metadata including the offset to the recent blockhash.
    - `payload`: A pointer to the serialized transaction data from which the recent blockhash is to be extracted.
- **Control Flow**:
    - The function calculates the address of the recent blockhash by adding the `recent_blockhash_off` offset from the `txn` structure to the base address of the `payload`.
    - It casts the calculated address to a `uchar const *` type and returns it.
- **Output**: A pointer to the recent blockhash within the transaction payload, cast to a `uchar const *` type.


---
### fd\_txn\_get\_instr\_accts<!-- {{#callable:fd_txn_get_instr_accts}} -->
The `fd_txn_get_instr_accts` function retrieves the account indices array for a given instruction within a Solana transaction payload.
- **Inputs**:
    - `instr`: A pointer to a `fd_txn_instr_t` structure representing a specific instruction within a Solana transaction.
    - `payload`: A pointer to the transaction data, which is the serialized form of the transaction.
- **Control Flow**:
    - The function calculates the address of the account indices array by adding the `acct_off` offset from the `instr` structure to the base address of the `payload`.
    - It casts the resulting address to a `uchar const *` type and returns it.
- **Output**: A pointer to the start of the account indices array for the specified instruction within the transaction payload.


---
### fd\_txn\_get\_instr\_data<!-- {{#callable:fd_txn_get_instr_data}} -->
The `fd_txn_get_instr_data` function retrieves the binary data associated with a specific instruction in a Solana transaction.
- **Inputs**:
    - `instr`: A pointer to a `fd_txn_instr_t` structure representing a specific instruction within a Solana transaction.
    - `payload`: A pointer to the start of the transaction data, which contains the serialized transaction information.
- **Control Flow**:
    - The function calculates the address of the instruction data by adding the `data_off` offset from the `instr` structure to the base `payload` pointer.
    - It casts the resulting address to a `uchar const *` type and returns it.
- **Output**: A pointer to the binary data associated with the specified instruction, cast to a `uchar const *` type.


---
### fd\_txn\_is\_simple\_vote\_transaction<!-- {{#callable:fd_txn_is_simple_vote_transaction}} -->
The function `fd_txn_is_simple_vote_transaction` checks if a given Solana transaction is a simple vote transaction by verifying specific criteria.
- **Inputs**:
    - `txn`: A pointer to a `fd_txn_t` structure representing a Solana transaction.
    - `payload`: A pointer to the serialized data of the transaction, which is coupled with `txn`.
- **Control Flow**:
    - Retrieve the base address of account addresses using [`fd_txn_get_acct_addrs`](#fd_txn_get_acct_addrs) with `txn` and `payload`.
    - Check if the transaction has exactly one instruction; if not, return 0.
    - Verify that the transaction is a legacy transaction; if not, return 0.
    - Ensure the transaction has no more than two signatures; if not, return 0.
    - Retrieve the program ID index from the first instruction of the transaction.
    - Calculate the program ID address using the base address and the program ID index.
    - Compare the program ID with the predefined vote program ID using `fd_memeq`; return the result of this comparison.
- **Output**: Returns 1 if the transaction is a simple vote transaction, otherwise returns 0.
- **Functions called**:
    - [`fd_txn_get_acct_addrs`](#fd_txn_get_acct_addrs)


---
### fd\_txn\_align<!-- {{#callable:fd_txn_align}} -->
The `fd_txn_align` function returns the alignment requirement in bytes for a memory region to be used as a `fd_txn_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function calls `alignof(fd_txn_t)` to determine the alignment requirement of the `fd_txn_t` structure.
    - It returns the result of `alignof(fd_txn_t)` as the alignment requirement.
- **Output**: The function returns an `ulong` representing the alignment requirement in bytes for a `fd_txn_t` structure.


---
### fd\_txn\_footprint<!-- {{#callable:fd_txn_footprint}} -->
The `fd_txn_footprint` function calculates the total memory footprint of a Solana transaction, including its instructions and address tables.
- **Inputs**:
    - `instr_cnt`: The number of instructions in the transaction.
    - `addr_table_lookup_cnt`: The number of address table lookups in the transaction.
- **Control Flow**:
    - Calculate the size of the transaction structure `fd_txn_t`.
    - Calculate the total size of the instructions by multiplying `instr_cnt` by the size of `fd_txn_instr_t`.
    - Calculate the total size of the address table lookups by multiplying `addr_table_lookup_cnt` by the size of `fd_txn_acct_addr_lut_t`.
    - Sum the sizes calculated in the previous steps to get the total footprint.
- **Output**: The function returns an unsigned long integer representing the total size in bytes of the transaction, including its instructions and address tables.


---
### fd\_txn\_account\_cnt<!-- {{#callable:fd_txn_account_cnt}} -->
The `fd_txn_account_cnt` function calculates the number of accounts in a Solana transaction that match specified properties based on the `include_cat` parameter.
- **Inputs**:
    - `txn`: A pointer to a `fd_txn_t` structure representing a Solana transaction, which contains details about the transaction's accounts, signatures, and other metadata.
    - `include_cat`: An integer representing a bitmask of account categories to include in the count, using predefined constants like `FD_TXN_ACCT_CAT_WRITABLE_SIGNER`, `FD_TXN_ACCT_CAT_READONLY_SIGNER`, etc.
- **Control Flow**:
    - Initialize a counter `cnt` to zero.
    - Check if `include_cat` includes `FD_TXN_ACCT_CAT_WRITABLE_SIGNER` and add the count of writable signer accounts to `cnt`.
    - Check if `include_cat` includes `FD_TXN_ACCT_CAT_READONLY_SIGNER` and add the count of readonly signer accounts to `cnt`.
    - Check if `include_cat` includes `FD_TXN_ACCT_CAT_READONLY_NONSIGNER_IMM` and add the count of readonly non-signer immediate accounts to `cnt`.
    - Check if `include_cat` includes `FD_TXN_ACCT_CAT_WRITABLE_ALT` and add the count of writable accounts from address lookup tables to `cnt`.
    - Check if `include_cat` includes `FD_TXN_ACCT_CAT_WRITABLE_NONSIGNER_IMM` and add the count of writable non-signer immediate accounts to `cnt`.
    - Check if `include_cat` includes `FD_TXN_ACCT_CAT_READONLY_ALT` and add the count of readonly accounts from address lookup tables to `cnt`.
    - Return the total count `cnt`.
- **Output**: The function returns an `ulong` representing the total number of accounts in the transaction that match the specified categories in `include_cat`.


---
### fd\_txn\_acct\_iter\_init<!-- {{#callable:fd_txn_acct_iter_init}} -->
The `fd_txn_acct_iter_init` function initializes an iterator for iterating over account addresses in a Solana transaction that match specified categories.
- **Inputs**:
    - `txn`: A pointer to a `fd_txn_t` structure representing a Solana transaction.
    - `include_cat`: An integer representing a bitwise combination of account categories to include in the iteration, defined by `FD_TXN_ACCT_CAT_*` constants.
- **Control Flow**:
    - Initialize an array `control` with three elements set to zero to store (start, count) pairs for account categories.
    - Initialize a variable `i` to -1 to track the index in the `control` array.
    - Extract various counts from the `txn` structure for convenience, such as signature count, readonly signed count, etc.
    - Use a macro `INCLUDE_RANGE` to populate the `control` array with (start, count) pairs for each account category specified in `include_cat`.
    - For each category, check if it is included in `include_cat` and update the `control` array accordingly, incrementing `i` and setting the start and count values.
    - After populating the `control` array, remove any empty intervals by checking if the count is zero and adjusting the `control` values to skip empty intervals.
    - Return a single `ulong` value combining the non-empty (start, count) pairs from the `control` array.
- **Output**: A `ulong` value representing the iterator state, encoding up to three (start, count) pairs for the specified account categories.


---
### fd\_txn\_acct\_iter\_next<!-- {{#callable:FD_FN_CONST::fd_txn_acct_iter_next}} -->
The `fd_txn_acct_iter_next` function advances an iterator over account addresses in a transaction, moving to the next interval if the current one is exhausted.
- **Inputs**:
    - `cur`: The current iterator state, represented as a `fd_txn_acct_iter_t` type, which is an opaque handle for iterating over account addresses.
- **Control Flow**:
    - The function increments the low byte of `cur` and decrements the count byte by subtracting 0x0100UL.
    - It checks if the count byte is non-zero using a bitwise AND operation with 0xFF00UL.
    - If the count byte is zero, indicating the end of the current interval, it shifts `cur` right by 16 bits to move to the next interval.
    - The function returns the updated iterator state, either the current interval or the next one, based on the count byte check.
- **Output**: The function returns the updated iterator state as a `fd_txn_acct_iter_t`, which is either the current interval or the next one if the current interval is exhausted.


---
### fd\_txn\_acct\_iter\_end<!-- {{#callable:FD_FN_CONST::fd_txn_acct_iter_end}} -->
The `fd_txn_acct_iter_end` function returns a constant value indicating the end of an account iterator in a transaction.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as an inline function, which suggests it is intended to be expanded in place where it is called, rather than being invoked as a separate function call.
    - The function does not take any parameters.
    - It simply returns the constant value `0UL`, which is an unsigned long integer with a value of zero.
- **Output**: The function returns an unsigned long integer with a value of zero, representing the end of an account iterator.


---
### fd\_txn\_acct\_iter\_idx<!-- {{#callable:FD_FN_CONST::fd_txn_acct_iter_idx}} -->
The `fd_txn_acct_iter_idx` function extracts the index of the current account from an iterator used for iterating over transaction accounts.
- **Inputs**:
    - `cur`: A `fd_txn_acct_iter_t` type representing the current state of the account iterator.
- **Control Flow**:
    - The function takes a single argument `cur`, which is an iterator state.
    - It performs a bitwise AND operation between `cur` and `0xFFUL` to extract the lower 8 bits of `cur`.
    - The result of this operation is returned as the index of the current account.
- **Output**: The function returns an `ulong` representing the index of the current account in the iteration.


---
### fd\_txn\_parse<!-- {{#callable:fd_txn_parse}} -->
The `fd_txn_parse` function is a wrapper that calls [`fd_txn_parse_core`](fd_txn_parse.c.driver.md#fd_txn_parse_core) to parse a Solana transaction from a given payload.
- **Inputs**:
    - `payload`: A pointer to the first byte of the encoded transaction data.
    - `payload_sz`: The size in bytes of the payload data.
    - `out_buf`: A buffer where the parsed transaction will be stored.
    - `counters_opt`: An optional pointer to a structure for collecting metrics about the parsing process.
- **Control Flow**:
    - The function directly calls [`fd_txn_parse_core`](fd_txn_parse.c.driver.md#fd_txn_parse_core) with the provided arguments and a NULL for the optional `payload_sz_opt` parameter.
    - It returns the result of the [`fd_txn_parse_core`](fd_txn_parse.c.driver.md#fd_txn_parse_core) function call.
- **Output**: The function returns the total size of the resulting `fd_txn` struct on success, or 0 on failure.
- **Functions called**:
    - [`fd_txn_parse_core`](fd_txn_parse.c.driver.md#fd_txn_parse_core)


---
### fd\_txn\_is\_writable<!-- {{#callable:fd_txn_is_writable}} -->
The `fd_txn_is_writable` function determines if an account at a given index in a Solana transaction is writable.
- **Inputs**:
    - `txn`: A pointer to a `fd_txn_t` structure representing a Solana transaction.
    - `idx`: An unsigned short integer representing the index of the account to check for writability.
- **Control Flow**:
    - Check if the transaction version is FD_TXN_V0 and if the index is greater than or equal to the account address count.
    - If true, check if the index is less than the sum of account address count and additional writable count from address tables; return 1 if true, otherwise return 0.
    - If the index is less than the difference between signature count and readonly signed count, return 1.
    - If the index is greater than or equal to the signature count and less than the difference between account address count and readonly unsigned count, return 1.
    - Return 0 if none of the conditions for writability are met.
- **Output**: Returns 1 if the account at the specified index is writable, otherwise returns 0.


---
### fd\_txn\_is\_signer<!-- {{#callable:fd_txn_is_signer}} -->
The `fd_txn_is_signer` function checks if the account at a given index in a Solana transaction is a signer.
- **Inputs**:
    - `txn`: A pointer to a constant `fd_txn_t` structure representing a Solana transaction.
    - `idx`: An integer representing the index of the account to check within the transaction.
- **Control Flow**:
    - The function compares the provided index `idx` with the `signature_cnt` field of the `fd_txn_t` structure.
    - If `idx` is less than `signature_cnt`, the function returns 1, indicating the account is a signer.
    - If `idx` is not less than `signature_cnt`, the function returns 0, indicating the account is not a signer.
- **Output**: The function returns an integer: 1 if the account at the specified index is a signer, and 0 otherwise.


# Function Declarations (Public API)

---
### fd\_txn\_parse\_core<!-- {{#callable_declaration:fd_txn_parse_core}} -->
Parses a Solana transaction from its canonical encoding.
- **Description**: This function is used to parse a Solana transaction from its canonical encoding format, typically used on the wire. It reads the transaction data from the provided payload and stores the parsed transaction in the specified output buffer. The function ensures that the transaction is well-formed and adheres to expected constraints, returning the size of the parsed transaction structure on success. It is important to ensure that the payload size does not exceed the maximum transmission unit (MTU) and that the output buffer has sufficient space to store the parsed transaction. Optionally, it can update counters for successful and failed parsing attempts, and provide the size of the parsed payload if requested.
- **Inputs**:
    - `payload`: A pointer to the first byte of the encoded transaction data. It must not be null and should point to a valid memory region of at least payload_sz bytes.
    - `payload_sz`: The size of the payload in bytes. It must be less than or equal to FD_TXN_MTU.
    - `out_buf`: A pointer to the memory where the parsed transaction will be stored. It must have space for at least FD_TXN_MAX_SZ bytes.
    - `counters_opt`: An optional pointer to a fd_txn_parse_counters_t structure for collecting parsing metrics. If null, no metrics will be collected.
    - `payload_sz_opt`: An optional pointer to a ulong where the function will store the total bytes used by the transaction. If null, the function will return an error if the payload size does not match exactly.
- **Output**: Returns the size of the parsed fd_txn structure on success, or 0 on failure. On failure, the contents of out_buf are undefined.
- **See also**: [`fd_txn_parse_core`](fd_txn_parse.c.driver.md#fd_txn_parse_core)  (Implementation)



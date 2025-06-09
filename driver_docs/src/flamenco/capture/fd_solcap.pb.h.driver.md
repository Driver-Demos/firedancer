# Purpose
This C header file is an automatically generated nanopb header, which defines data structures and associated metadata for serializing and deserializing protocol buffer messages related to Solana blockchain data capture. The file includes several struct definitions, each representing different components of blockchain data, such as `fd_solcap_FileMeta`, `fd_solcap_BankPreimage`, `fd_solcap_AccountTableMeta`, `fd_solcap_AccountMeta`, and `fd_solcap_Transaction`. These structures encapsulate various attributes of blockchain data, including metadata about file captures, bank preimages, account tables, account metadata, and transaction details. Each struct is equipped with fields that store specific data points, such as slot numbers, hashes, transaction signatures, and error codes, which are crucial for capturing and processing blockchain state and transactions.

The file also provides initializer macros for these structs, allowing for easy instantiation with default or zero values. Additionally, it defines field tags and encoding specifications for use with nanopb, a small code-size Protocol Buffers implementation in C. This header is intended to be included in other C source files that require access to these data structures for processing Solana blockchain data. The file ensures compatibility with a specific version of the nanopb generator, as indicated by the version check, and it includes provisions for C++ compatibility through the use of `extern "C"`. Overall, this header file serves as a critical component for applications that need to handle serialized blockchain data efficiently using nanopb.
# Imports and Dependencies

---
- `../../ballet/nanopb/pb_firedancer.h`


# Data Structures

---
### fd\_solcap\_FileMeta
- **Type**: `struct`
- **Members**:
    - `first_slot`: Represents the number of the first slot in the capture file.
    - `slot_cnt`: Indicates the total number of slots in the capture file.
    - `main_block_magic`: Stores the magic number of the main block type.
- **Description**: The `fd_solcap_FileMeta` structure is used to store metadata related to a capture file in a Solana blockchain context. It includes information about the first slot number, the total count of slots, and a magic number that identifies the main block type, which is essential for interpreting the file's contents correctly.


---
### fd\_solcap\_BankPreimage
- **Type**: `struct`
- **Members**:
    - `slot`: The slot number associated with this bank preimage.
    - `bank_hash`: A 32-byte array representing the hash of the current bank.
    - `prev_bank_hash`: A 32-byte array representing the hash of the previous bank block.
    - `account_delta_hash`: A 32-byte array representing the hash of the changed accounts.
    - `poh_hash`: A 32-byte array representing the Proof-of-History hash of the current block.
    - `signature_cnt`: The number of transactions in the current block.
    - `account_cnt`: The number of accounts changed in the current block, also the number of leaves in the account delta Merkle tree.
    - `account_table_coff`: The offset from the first byte of the current chunk to the first byte of the account table chunk.
    - `accounts_lt_hash_checksum`: A 32-byte array representing the hash of all the accounts.
- **Description**: The `fd_solcap_BankPreimage` structure is designed to encapsulate the pre-image of a bank hash for a specific slot in a blockchain context, specifically for slots that were not skipped. It includes various hashes such as the bank hash, previous bank hash, account delta hash, and Proof-of-History hash, which are crucial for verifying the integrity and changes within a block. Additionally, it tracks the number of transactions and accounts affected in the block, providing a comprehensive snapshot of the block's state and changes.


---
### fd\_solcap\_AccountTableMeta
- **Type**: `struct`
- **Members**:
    - `slot`: The slot number that this accounts table refers to.
    - `account_table_coff`: The chunk offset to the first entry of the accounts table.
    - `account_table_cnt`: The number of records in the accounts table, equal to BankPreimage.account_cnt.
- **Description**: The `fd_solcap_AccountTableMeta` structure is used to store metadata about an accounts table in a Solana capture file. It includes the slot number that the accounts table is associated with, the offset to the first entry in the accounts table, and the count of records within the table. This structure is crucial for navigating and interpreting the accounts data within a capture file, providing essential information for locating and understanding the accounts data in relation to the blockchain slot it pertains to.


---
### fd\_solcap\_AccountMeta
- **Type**: `struct`
- **Members**:
    - `lamports`: Represents the amount of lamports (smallest unit of currency) in the account.
    - `slot`: Indicates the slot number associated with the account.
    - `rent_epoch`: Specifies the rent epoch for the account, which is used for rent collection.
    - `owner`: A 32-byte array representing the public key of the account's owner.
    - `executable`: A boolean indicating whether the account contains executable code.
    - `data_coff`: An integer representing the chunk offset to the account data.
    - `data_sz`: Specifies the size of the account data in bytes.
- **Description**: The `fd_solcap_AccountMeta` structure is used to encapsulate metadata about a Solana account, including its balance in lamports, the slot number, rent epoch, and ownership details. It also includes information about whether the account is executable and provides offsets and sizes for accessing the account's data. This structure is essential for managing and interacting with accounts in the Solana blockchain environment.


---
### fd\_solcap\_Transaction
- **Type**: `struct`
- **Members**:
    - `txn_sig`: A 64-byte array representing the transaction signature.
    - `slot`: A 64-bit unsigned integer indicating the slot number associated with the transaction.
    - `fd_txn_err`: A 32-bit signed integer representing the Firedancer transaction error code.
    - `fd_custom_err`: A 32-bit unsigned integer for custom error codes specific to Firedancer.
    - `solana_txn_err`: A 64-bit unsigned integer for Solana transaction error codes.
    - `fd_cus_used`: A 64-bit unsigned integer indicating the number of Firedancer compute units used.
    - `solana_cus_used`: A 64-bit unsigned integer indicating the number of Solana compute units used.
    - `failed_instr_path_count`: A size type indicating the number of elements in the failed instruction path array.
    - `failed_instr_path`: An array of 4 unsigned 32-bit integers representing the path to the failed instruction.
    - `instr_err`: A 32-bit unsigned integer representing the instruction processing error code.
    - `instr_err_idx`: A 32-bit signed integer indicating the index of the instruction error.
- **Description**: The `fd_solcap_Transaction` structure is designed to encapsulate detailed information about a transaction within the Solana blockchain, specifically for use with the Firedancer system. It includes fields for transaction signature, slot number, various error codes, and compute unit usage metrics. Additionally, it tracks the path and index of any failed instructions, providing a comprehensive view of transaction processing and error handling.



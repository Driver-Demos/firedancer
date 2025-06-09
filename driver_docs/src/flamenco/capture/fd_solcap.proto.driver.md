# Purpose
This file is a Protocol Buffers (proto3) definition file that specifies the structure of data related to capturing and storing information about Solana blockchain slots and transactions. The file defines several message types, each representing a different aspect of the data capture process. These message types include `FileMeta`, `BankPreimage`, `AccountTableMeta`, `AccountMeta`, and `Transaction`, each of which encapsulates specific metadata or data related to blockchain slots, accounts, and transactions. The use of Protocol Buffers allows for efficient serialization and deserialization of structured data, making it suitable for network communication and storage.

The `FileMeta` message provides metadata about the capture file, such as the first slot number and the total number of slots. The `BankPreimage` message contains detailed information about the pre-image of the bank hash for a given slot, including hashes related to accounts and transactions, as well as counts of signatures and accounts. The `AccountTableMeta` and `AccountMeta` messages describe metadata and details about accounts within a specific slot, including lamports, slot numbers, and ownership information. The `Transaction` message captures details about individual transactions, including transaction signatures, error codes, and resource usage metrics.

Overall, this file serves as a schema definition for capturing and organizing data related to Solana blockchain operations. It provides a structured way to represent complex data relationships and dependencies, facilitating the storage, retrieval, and analysis of blockchain data. The use of nanopb options indicates that this file is intended to be used with the nanopb library, which is a small code-size Protocol Buffers implementation in C, suitable for embedded systems.
# Imports and Dependencies

---
- `nanopb.proto`


# Data Structures

---
### FileMeta
- **Type**: `message`
- **Members**:
    - `first_slot`: Number of the first slot in this capture file.
    - `slot_cnt`: Total number of slots in this capture file.
    - `main_block_magic`: Magic number of main block type.
- **Description**: The `FileMeta` message is a data structure that represents the metadata associated with a file header in the Solana capture package. It contains three fields: `first_slot`, which indicates the number of the first slot in the capture file; `slot_cnt`, which specifies the total number of slots in the capture file; and `main_block_magic`, a fixed 64-bit integer that serves as a magic number for identifying the main block type. This metadata is crucial for understanding the structure and content of the capture file.


---
### BankPreimage
- **Type**: `message`
- **Members**:
    - `slot`: The slot number associated with this bank preimage.
    - `bank_hash`: The hash representing the bank state for the current slot.
    - `prev_bank_hash`: The hash of the bank state from the previous slot.
    - `account_delta_hash`: The hash of the accounts that have changed in the current slot.
    - `poh_hash`: The Proof-of-History hash for the current block.
    - `signature_cnt`: The number of transactions in the current block.
    - `account_cnt`: The number of accounts changed in the current block.
    - `account_table_coff`: The offset to the first byte of the account table chunk.
    - `accounts_lt_hash_checksum`: The hash of all the accounts in the current block.
- **Description**: The `BankPreimage` message is a data structure that encapsulates the pre-image of a bank hash for a specific slot in a blockchain context, specifically for the Solana network. It includes various fields such as the slot number, hashes for the current and previous bank states, and other metadata like the number of transactions and accounts affected in the current block. This structure is crucial for maintaining the integrity and traceability of the blockchain's state changes over time.


---
### AccountTableMeta
- **Type**: `message`
- **Members**:
    - `slot`: The slot number that this accounts table refers to.
    - `account_table_coff`: The chunk offset to the first entry of the accounts table.
    - `account_table_cnt`: The number of records in the accounts table, equal to BankPreimage.account_cnt.
- **Description**: The `AccountTableMeta` is a message structure that encapsulates metadata about an accounts table in the context of a specific slot within a Solana capture file. It includes the slot number (`slot`) that the accounts table pertains to, the offset (`account_table_coff`) to the first entry of the accounts table within the data chunk, and the count (`account_table_cnt`) of records in the accounts table, which corresponds to the number of accounts changed in the associated bank preimage.


---
### AccountMeta
- **Type**: `message`
- **Members**:
    - `lamports`: The number of lamports (smallest unit of SOL) associated with the account.
    - `slot`: The slot number at which the account data is relevant.
    - `rent_epoch`: The epoch at which the account will next owe rent.
    - `owner`: The public key of the account's owner, with a fixed size of 32 bytes.
    - `executable`: A boolean indicating whether the account contains executable code.
    - `data_coff`: The offset to the account data within the chunk.
    - `data_sz`: The size of the account data.
- **Description**: The `AccountMeta` message is a data structure used to represent metadata about a Solana account within a specific slot. It includes information such as the number of lamports in the account, the slot number, the rent epoch, and the account's owner. Additionally, it indicates whether the account is executable and provides details about the account data's offset and size. This structure is crucial for managing account states and interactions within the Solana blockchain.


---
### Transaction
- **Type**: `message`
- **Members**:
    - `txn_sig`: A fixed-length byte array representing the transaction signature.
    - `slot`: An unsigned 64-bit integer indicating the slot number associated with the transaction.
    - `fd_txn_err`: A 32-bit integer representing the transaction error code specific to the file descriptor.
    - `fd_custom_err`: A 32-bit unsigned integer for custom error codes related to the file descriptor.
    - `solana_txn_err`: A 64-bit unsigned integer indicating the Solana transaction error code.
    - `fd_cus_used`: A 64-bit unsigned integer representing the file descriptor's custom units used.
    - `solana_cus_used`: A 64-bit unsigned integer indicating the Solana custom units used.
    - `failed_instr_path`: A repeated field of up to 4 unsigned 32-bit integers representing the path to the failed instruction, with zero length indicating success.
    - `instr_err`: A 32-bit unsigned integer representing the instruction processing error code.
    - `instr_err_idx`: A 32-bit integer indicating the index of the instruction error.
- **Description**: The `Transaction` message is a data structure that encapsulates details about a transaction within the Solana blockchain capture file. It includes fields for the transaction signature, slot number, various error codes, and custom units used. Additionally, it provides information about the path to any failed instructions and the index of any instruction errors, allowing for detailed error tracking and analysis of transaction processing.



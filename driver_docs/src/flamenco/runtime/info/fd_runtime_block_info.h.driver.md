# Purpose
This C header file defines a data structure, `fd_runtime_block_info`, which is used to encapsulate information about a runtime block in a system, likely related to blockchain or distributed ledger technology. The structure includes several fields that track counts of various components, such as microblock batches, microblocks, signatures, transactions, and accounts, indicating its role in managing or analyzing block data. Additionally, it includes a pointer to an array of `fd_microblock_batch_info_t` structures, suggesting that it handles detailed batch information, and a pointer to a raw block with its size, which implies it can store or reference raw block data. The file includes necessary dependencies from other parts of the project, ensuring that the structure is integrated with existing utilities and data types. Overall, this header file is a part of a larger system, providing a blueprint for managing block-related runtime information.
# Imports and Dependencies

---
- `../../../util/fd_util_base.h`
- `../../../ballet/block/fd_microblock.h`
- `../../../ballet/txn/fd_txn.h`
- `fd_microblock_batch_info.h`


# Data Structures

---
### fd\_runtime\_block\_info
- **Type**: `struct`
- **Members**:
    - `microblock_batch_cnt`: Stores the count of microblock batches.
    - `microblock_cnt`: Stores the count of microblocks.
    - `signature_cnt`: Stores the count of signatures.
    - `txn_cnt`: Stores the count of transactions.
    - `account_cnt`: Stores the count of accounts.
    - `microblock_batch_infos`: Pointer to an array of microblock batch information structures.
    - `raw_block`: Pointer to the raw block data.
    - `raw_block_sz`: Stores the size of the raw block data.
- **Description**: The `fd_runtime_block_info` structure is designed to encapsulate information about a runtime block in a blockchain context. It includes various counters for microblock batches, microblocks, signatures, transactions, and accounts, providing a comprehensive overview of the block's composition. Additionally, it holds a pointer to an array of `fd_microblock_batch_info_t` structures, which contain detailed information about each microblock batch. The structure also includes a pointer to the raw block data and its size, allowing for direct access and manipulation of the block's binary data.


---
### fd\_runtime\_block\_info\_t
- **Type**: `struct`
- **Members**:
    - `microblock_batch_cnt`: Stores the count of microblock batches.
    - `microblock_cnt`: Stores the count of microblocks.
    - `signature_cnt`: Stores the count of signatures.
    - `txn_cnt`: Stores the count of transactions.
    - `account_cnt`: Stores the count of accounts.
    - `microblock_batch_infos`: Pointer to an array of microblock batch information structures.
    - `raw_block`: Pointer to the raw block data.
    - `raw_block_sz`: Stores the size of the raw block data.
- **Description**: The `fd_runtime_block_info_t` structure is designed to encapsulate information about a runtime block in a blockchain context. It includes various counters for microblocks, signatures, transactions, and accounts, as well as pointers to detailed microblock batch information and raw block data. This structure is essential for managing and accessing block-related data efficiently in a blockchain system.



# Purpose
This C header file defines structures and functions for managing and summarizing rebate information related to transaction processing in a system that handles microblocks. The primary purpose of this code is to facilitate the efficient scheduling of transactions by accounting for the computational units (CUs) that transactions actually consume, which may be less than initially requested. This allows the system to optimize resource allocation by potentially scheduling additional transactions based on the available rebate information. The file introduces two main structures: `fd_pack_rebate_sum_t` and `fd_pack_rebate_t`. The former is used to digest microblocks and produce rebate summaries, while the latter encapsulates the rebate details in a format that can be processed by the system.

The file provides several functions to manage the lifecycle and operations of these structures, including creating new rebate summaries, adding transaction rebate information, generating rebate reports, and clearing pending rebates. The functions are designed to be used in a local context, as indicated by the requirement for a valid local join. The code is intended to be part of a larger system, likely a library, given its focus on defining data structures and functions without a `main` function or direct execution logic. The header file also includes static assertions to ensure that certain size constraints are met, which is crucial for maintaining the integrity and performance of the rebate processing system.
# Imports and Dependencies

---
- `../fd_disco_base.h`
- `fd_microblock.h`


# Global Variables

---
### fd\_pack\_rebate\_sum\_new
- **Type**: `function pointer`
- **Description**: The `fd_pack_rebate_sum_new` is a function pointer that takes a single argument, a pointer to memory (`void * mem`), and returns a pointer to memory (`void *`).
- **Use**: This function is used to initialize a new instance of the `fd_pack_rebate_sum_t` structure in the provided memory space.


# Data Structures

---
### fd\_pack\_rebate\_entry\_t
- **Type**: `struct`
- **Members**:
    - `key`: This is an account address of type `fd_acct_addr_t`.
    - `rebate_cus`: This is an unsigned long integer representing the rebate compute units.
- **Description**: The `fd_pack_rebate_entry_t` structure is designed to represent an entry in a rebate system, where each entry consists of an account address and the number of compute units (CUs) that can be rebated. This structure is used within larger data structures to manage and track rebate information for transactions, allowing for efficient scheduling and processing of additional transactions based on available rebates.


---
### fd\_pack\_rebate\_sum\_private
- **Type**: `struct`
- **Members**:
    - `total_cost_rebate`: Stores the total cost rebate as an unsigned long integer.
    - `vote_cost_rebate`: Stores the vote cost rebate as an unsigned long integer.
    - `data_bytes_rebate`: Stores the data bytes rebate as an unsigned long integer.
    - `microblock_cnt_rebate`: Stores the microblock count rebate as an unsigned long integer.
    - `ib_result`: Indicates the result of an internal block operation with -1 for failure, 0 for not an internal block, and 1 for success.
    - `writer_cnt`: Stores the count of writers as an unsigned integer.
    - `map`: An array of fd_pack_rebate_entry_t structures with a fixed size of 8192.
    - `inserted`: An array of pointers to fd_pack_rebate_entry_t structures with a capacity defined by FD_PACK_REBATE_SUM_CAPACITY.
- **Description**: The `fd_pack_rebate_sum_private` structure is designed to manage and summarize rebate information related to transaction processing in a system that handles microblocks. It maintains various rebate metrics such as total cost, vote cost, data bytes, and microblock count rebates, and tracks the result of internal block operations. The structure also includes a map for storing rebate entries and an array for tracking inserted entries, facilitating efficient rebate management and reporting.


---
### fd\_pack\_rebate\_sum\_t
- **Type**: `struct`
- **Members**:
    - `total_cost_rebate`: Stores the total cost rebate value.
    - `vote_cost_rebate`: Stores the vote cost rebate value.
    - `data_bytes_rebate`: Stores the data bytes rebate value.
    - `microblock_cnt_rebate`: Stores the microblock count rebate value.
    - `ib_result`: Indicates the result of an internal block operation with values -1, 0, or 1.
    - `writer_cnt`: Counts the number of writers involved.
    - `map`: An array of fd_pack_rebate_entry_t structures, each containing account address and rebate CUs.
    - `inserted`: An array of pointers to fd_pack_rebate_entry_t structures, with a capacity defined by FD_PACK_REBATE_SUM_CAPACITY.
- **Description**: The `fd_pack_rebate_sum_t` structure is designed to manage and summarize rebate information for transactions within a microblock. It maintains various rebate metrics such as total cost, vote cost, data bytes, and microblock count rebates. The structure also tracks the result of internal block operations and the number of writers. It includes a map of rebate entries, each associated with an account address and rebate CUs, and an array of pointers to these entries, allowing for efficient management and retrieval of rebate data.


---
### fd\_pack\_rebate
- **Type**: `struct`
- **Members**:
    - `total_cost_rebate`: Represents the total cost rebate in unsigned long format.
    - `vote_cost_rebate`: Represents the vote cost rebate in unsigned long format.
    - `data_bytes_rebate`: Represents the data bytes rebate in unsigned long format.
    - `microblock_cnt_rebate`: Represents the microblock count rebate in unsigned long format.
    - `ib_result`: Indicates the result of an internal block operation with -1 for failure, 0 for not an internal block, and 1 for success.
    - `writer_cnt`: Stores the count of writers as an unsigned integer.
    - `writer_rebates`: An array of fd_pack_rebate_entry_t structures, with a size determined by writer_cnt, up to 1637.
- **Description**: The `fd_pack_rebate` structure is designed to encapsulate rebate information related to transaction processing in a system that handles microblocks. It includes fields for various types of rebates such as total cost, vote cost, data bytes, and microblock count rebates, all stored as unsigned long integers. The `ib_result` field provides a status indicator for internal block operations, while `writer_cnt` specifies the number of writers involved. The `writer_rebates` array holds detailed rebate entries for each writer, with its size dynamically determined by the `writer_cnt` field, allowing for up to 1637 entries. This structure is used to summarize rebate information that can be utilized by other components in the system to optimize transaction scheduling and processing.


---
### fd\_pack\_rebate\_t
- **Type**: `struct`
- **Members**:
    - `total_cost_rebate`: Represents the total cost rebate in the structure.
    - `vote_cost_rebate`: Represents the vote cost rebate in the structure.
    - `data_bytes_rebate`: Represents the data bytes rebate in the structure.
    - `microblock_cnt_rebate`: Represents the microblock count rebate in the structure.
    - `ib_result`: Indicates the result of an internal block operation, with values -1 for failure, 0 for not an internal block, and 1 for success.
    - `writer_cnt`: Indicates the number of writer rebates, up to 1637.
    - `writer_rebates`: An array of fd_pack_rebate_entry_t structures representing individual writer rebates.
- **Description**: The `fd_pack_rebate_t` structure is used to summarize rebate information for transactions, specifically detailing various types of cost rebates such as total cost, vote cost, data bytes, and microblock count rebates. It also includes a result indicator for internal block operations and maintains an array of writer rebates, which can vary in size up to a specified limit. This structure is integral to managing and reporting rebate information in transaction processing systems.


# Functions

---
### fd\_pack\_rebate\_sum\_align<!-- {{#callable:fd_pack_rebate_sum_align}} -->
The `fd_pack_rebate_sum_align` function returns the alignment requirement of the `fd_pack_rebate_sum_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, which suggests it is intended for use within the same translation unit and optimized for performance.
    - It uses the `alignof` operator to determine the alignment requirement of the `fd_pack_rebate_sum_t` type.
    - The function returns the result of the `alignof` operator, which is the alignment requirement in bytes.
- **Output**: The function returns an `ulong` representing the alignment requirement of the `fd_pack_rebate_sum_t` structure.


---
### fd\_pack\_rebate\_sum\_footprint<!-- {{#callable:fd_pack_rebate_sum_footprint}} -->
The `fd_pack_rebate_sum_footprint` function returns the size in bytes of the `fd_pack_rebate_sum_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended to be used within the same translation unit and suggests the compiler to replace the function call with the function code itself to reduce overhead.
    - The function is marked with `FD_FN_PURE`, indicating it has no side effects and its return value depends only on its parameters or global variables.
    - The function simply returns the result of the `sizeof` operator applied to the `fd_pack_rebate_sum_t` type, which calculates the size of this structure in bytes.
- **Output**: The function outputs an `ulong` representing the size of the `fd_pack_rebate_sum_t` structure in bytes.


# Function Declarations (Public API)

---
### fd\_pack\_rebate\_sum\_new<!-- {{#callable_declaration:fd_pack_rebate_sum_new}} -->
Initializes a new rebate summary structure.
- **Description**: This function initializes a memory region to be used as a rebate summary structure, setting all internal counters and state to their initial values. It should be called before using the memory region for any rebate summary operations. The memory provided must be large enough to hold a `fd_pack_rebate_sum_t` structure and must be properly aligned. This function does not allocate memory; it only initializes the provided memory region.
- **Inputs**:
    - `mem`: A pointer to a memory region that will be used to store the rebate summary structure. The memory must be aligned according to `fd_pack_rebate_sum_align()` and have a size of at least `fd_pack_rebate_sum_footprint()`. The caller retains ownership of this memory, and it must not be null.
- **Output**: Returns the same pointer passed in `mem`, now initialized for use as a rebate summary structure.
- **See also**: [`fd_pack_rebate_sum_new`](fd_pack_rebate_sum.c.driver.md#fd_pack_rebate_sum_new)  (Implementation)


---
### fd\_pack\_rebate\_sum\_add\_txn<!-- {{#callable_declaration:fd_pack_rebate_sum_add_txn}} -->
Add rebate information from transactions to the pending summary.
- **Description**: This function processes a set of transactions, updating the rebate summary with information about consumed and rebated compute units (CUs). It should be called with a valid rebate summary structure and a list of transactions, each of which must have certain fields populated, such as the EXECUTE_SUCCESS flag and the bank_cu field. If transactions involve writable accounts from address lookup tables, additional writable account addresses must be provided. The function can handle a transaction count of zero, which results in a no-op. It does not retain any references to the transaction data after execution. The function returns the number of times a report must be generated before processing more transactions.
- **Inputs**:
    - `s`: A pointer to a valid fd_pack_rebate_sum_t structure, which must be a valid local join.
    - `txns`: A pointer to an array of fd_txn_p_t structures representing the transactions to process. Must not be null if txn_cnt is greater than zero.
    - `adtl_writable`: A pointer to an array of pointers to fd_acct_addr_t, representing additional writable account addresses for each transaction. Can be null if txn_cnt is zero or if transactions do not load writable accounts from address lookup tables.
    - `txn_cnt`: The number of transactions to process, which must be in the range [0, MAX_TXN_PER_MICROBLOCK]. A value of zero results in a no-op.
- **Output**: Returns the number of times fd_pack_rebate_sum_report must be called before the next call to this function with a non-zero txn_cnt.
- **See also**: [`fd_pack_rebate_sum_add_txn`](fd_pack_rebate_sum.c.driver.md#fd_pack_rebate_sum_add_txn)  (Implementation)


---
### fd\_pack\_rebate\_sum\_report<!-- {{#callable_declaration:fd_pack_rebate_sum_report}} -->
Generates a rebate report from the current rebate information.
- **Description**: This function is used to generate a rebate report based on the current state of rebate information stored in the provided `fd_pack_rebate_sum_t` structure. It should be called when a summary of rebates is needed, typically after transactions have been processed and rebate information has been accumulated. The function requires that `s` points to a valid local join and that `out` points to a memory region with sufficient capacity to store the report. The function updates the state of `s` to reflect that the current rebate information has been reported, allowing for new information to be accumulated in subsequent operations.
- **Inputs**:
    - `s`: A pointer to an `fd_pack_rebate_sum_t` structure containing the current rebate information. Must point to a valid local join. The function will update this structure to reflect that the rebate information has been reported.
    - `out`: A pointer to an `fd_pack_rebate_t` structure where the rebate report will be written. Must point to a memory region with at least `USHORT_MAX` bytes of capacity. The function will populate this structure with the rebate report.
- **Output**: Returns the number of bytes written to `out`, which will be in the range [0, USHORT_MAX].
- **See also**: [`fd_pack_rebate_sum_report`](fd_pack_rebate_sum.c.driver.md#fd_pack_rebate_sum_report)  (Implementation)


---
### fd\_pack\_rebate\_sum\_clear<!-- {{#callable_declaration:fd_pack_rebate_sum_clear}} -->
Clears the state of any pending rebates.
- **Description**: Use this function to reset the state of a `fd_pack_rebate_sum_t` structure, effectively clearing any pending rebate information. This function should be called when you need to discard the current rebate data and start fresh. It is a faster alternative to leaving, deleting, creating anew, and rejoining the structure. Ensure that the structure `s` is a valid local join before calling this function.
- **Inputs**:
    - `s`: A pointer to a `fd_pack_rebate_sum_t` structure. It must be a valid local join. The function will reset its state, clearing any pending rebate information.
- **Output**: None
- **See also**: [`fd_pack_rebate_sum_clear`](fd_pack_rebate_sum.c.driver.md#fd_pack_rebate_sum_clear)  (Implementation)



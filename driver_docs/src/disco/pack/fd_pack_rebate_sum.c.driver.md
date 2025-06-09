# Purpose
This C source code file is designed to manage and compute rebate summaries for transactions, specifically in a context where transactions are processed in microblocks. The file defines functions to initialize, update, report, and clear rebate summaries, which are encapsulated in a structure `fd_pack_rebate_sum_t`. The code utilizes a hash map (referred to as `rmap`) to track rebate entries associated with account addresses, allowing for efficient querying and updating of rebate information. The file includes conditional compilation for AVX (Advanced Vector Extensions) support, which optimizes certain operations if the hardware supports it.

The primary functions in this file include [`fd_pack_rebate_sum_new`](#fd_pack_rebate_sum_new), which initializes a rebate summary structure; [`fd_pack_rebate_sum_add_txn`](#fd_pack_rebate_sum_add_txn), which processes a batch of transactions to update the rebate summary; [`fd_pack_rebate_sum_report`](#fd_pack_rebate_sum_report), which generates a report of the current rebate summary and resets the internal counters; and [`fd_pack_rebate_sum_clear`](#fd_pack_rebate_sum_clear), which clears the rebate summary data. The code is structured to handle various transaction flags and conditions, such as initializer bundles and execution success, to accurately compute rebates. The use of macros and conditional logic ensures that the code is both flexible and efficient, catering to different transaction scenarios and system capabilities.
# Imports and Dependencies

---
- `fd_pack_rebate_sum.h`
- `fd_pack.h`
- `../../util/simd/fd_avx.h`
- `../../util/tmpl/fd_map.c`


# Global Variables

---
### null\_addr
- **Type**: `fd_acct_addr_t`
- **Description**: The `null_addr` is a static constant of type `fd_acct_addr_t` initialized to zero. It serves as a sentinel value representing a null or invalid account address in the context of the program.
- **Use**: This variable is used as a null key in the map implementation to identify invalid or uninitialized account addresses.


# Functions

---
### fd\_pack\_rebate\_sum\_new<!-- {{#callable:fd_pack_rebate_sum_new}} -->
The `fd_pack_rebate_sum_new` function initializes a `fd_pack_rebate_sum_t` structure with default values and sets up a new rebate map.
- **Inputs**:
    - `mem`: A pointer to a memory block where the `fd_pack_rebate_sum_t` structure will be initialized.
- **Control Flow**:
    - Cast the input memory pointer to a `fd_pack_rebate_sum_t` pointer.
    - Initialize all fields of the `fd_pack_rebate_sum_t` structure to zero or default values.
    - Call `rmap_new` to initialize the rebate map within the structure.
    - Perform a test to ensure the footprint of the map matches the expected size, which is intended to be optimized out by the compiler.
    - Return the original memory pointer.
- **Output**: Returns the original memory pointer `mem`, now initialized as a `fd_pack_rebate_sum_t` structure.


---
### fd\_pack\_rebate\_sum\_add\_txn<!-- {{#callable:fd_pack_rebate_sum_add_txn}} -->
The `fd_pack_rebate_sum_add_txn` function processes a batch of transactions to update rebate summaries and manage account entries in a rebate map.
- **Inputs**:
    - `s`: A pointer to an `fd_pack_rebate_sum_t` structure that holds the rebate summary data.
    - `txns`: A pointer to an array of `fd_txn_p_t` structures representing the transactions to be processed.
    - `adtl_writable`: A pointer to an array of pointers to `fd_acct_addr_t` structures, representing additional writable account addresses for each transaction.
    - `txn_cnt`: An unsigned long integer representing the number of transactions in the `txns` array.
- **Control Flow**:
    - Check if `txn_cnt` is zero; if so, return a calculated value based on `writer_cnt` and `HEADROOM`.
    - Initialize flags `is_initializer_bundle`, `ib_success`, and `any_in_block` to track transaction properties.
    - Iterate over each transaction in `txns` to update rebate summaries and account entries.
    - For each transaction, update `total_cost_rebate`, `vote_cost_rebate`, and `data_bytes_rebate` based on transaction flags and execution success.
    - If `rebated_cus` is zero, skip further processing for the current transaction.
    - Retrieve account addresses from the transaction and update or insert them into the rebate map, adjusting `rebate_cus` as needed.
    - Process additional writable account addresses if the transaction is marked as sanitized successfully.
    - Ensure `writer_cnt` does not exceed `FD_PACK_REBATE_SUM_CAPACITY`.
    - Calculate and update `microblock_cnt_rebate` and `data_bytes_rebate` based on transaction block status and bundle flags.
    - Update `ib_result` if the transaction is an initializer bundle and `ib_result` is not -1.
    - Return a calculated value to ensure sufficient capacity for future account address insertions.
- **Output**: Returns an unsigned long integer representing the number of times a report should be called to ensure sufficient capacity for account address insertions.


---
### fd\_pack\_rebate\_sum\_report<!-- {{#callable:fd_pack_rebate_sum_report}} -->
The `fd_pack_rebate_sum_report` function transfers rebate summary data from a source structure to an output structure, resets the source, and returns the size of the output data.
- **Inputs**:
    - `s`: A pointer to an `fd_pack_rebate_sum_t` structure containing the rebate summary data to be reported.
    - `out`: A pointer to an `fd_pack_rebate_t` structure where the rebate summary data will be stored.
- **Control Flow**:
    - Check if `s->ib_result`, `s->total_cost_rebate`, and `s->writer_cnt` are all zero; if so, return 0UL immediately.
    - Transfer and reset the `total_cost_rebate`, `vote_cost_rebate`, `data_bytes_rebate`, `microblock_cnt_rebate`, and `ib_result` fields from `s` to `out`.
    - Initialize `out->writer_cnt` to 0U.
    - Determine the minimum of `s->writer_cnt` and 1637UL, and iterate over this range.
    - For each iteration, decrement `s->writer_cnt`, transfer the corresponding entry from `s->inserted` to `out->writer_rebates`, and remove the entry from `s->map`.
    - Return the size of the `out` structure minus the size of one `fd_pack_rebate_entry_t`, plus the size of `out->writer_cnt` times `fd_pack_rebate_entry_t`.
- **Output**: The function returns an `ulong` representing the size of the `out` structure, adjusted for the number of writer rebates included.


---
### fd\_pack\_rebate\_sum\_clear<!-- {{#callable:fd_pack_rebate_sum_clear}} -->
The `fd_pack_rebate_sum_clear` function resets all rebate-related counters and removes all entries from the rebate map in a `fd_pack_rebate_sum_t` structure.
- **Inputs**:
    - `s`: A pointer to a `fd_pack_rebate_sum_t` structure whose rebate counters and map entries are to be cleared.
- **Control Flow**:
    - Set `total_cost_rebate`, `vote_cost_rebate`, `data_bytes_rebate`, `microblock_cnt_rebate`, and `ib_result` fields of `s` to 0.
    - Retrieve the current `writer_cnt` from `s`.
    - Iterate over each entry in `s->inserted` using a loop that decrements `writer_cnt` each time.
    - For each entry, remove it from the map `s->map` using `rmap_remove`.
- **Output**: This function does not return a value; it modifies the `fd_pack_rebate_sum_t` structure in place.



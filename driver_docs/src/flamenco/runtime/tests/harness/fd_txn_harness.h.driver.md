# Purpose
This C header file is part of a testing harness for transaction serialization and execution within a runtime environment, likely related to blockchain or distributed ledger technology. It includes a series of header files that provide necessary dependencies, such as executor functions, built-in programs, and system variables, indicating its integration with a larger system. The file defines macros for safely appending data to a transaction buffer, ensuring that the serialized transaction does not exceed a predefined maximum size (FD_TXN_MTU). It declares two primary functions: [`fd_runtime_fuzz_serialize_txn`](#fd_runtime_fuzz_serialize_txn), which serializes a transaction into a raw format while checking size constraints, and [`fd_runtime_fuzz_txn_run`](#fd_runtime_fuzz_txn_run), which executes a transaction using a given context. These functions are designed to facilitate testing and validation of transaction processing within the system.
# Imports and Dependencies

---
- `assert.h`
- `../../fd_executor.h`
- `../../program/fd_builtin_programs.h`
- `../../program/fd_bpf_program_util.h`
- `../../sysvar/fd_sysvar_last_restart_slot.h`
- `../../sysvar/fd_sysvar_slot_hashes.h`
- `../../sysvar/fd_sysvar_recent_hashes.h`
- `../../sysvar/fd_sysvar_stake_history.h`
- `../../sysvar/fd_sysvar_epoch_rewards.h`
- `../../sysvar/fd_sysvar_clock.h`
- `../../sysvar/fd_sysvar_epoch_schedule.h`
- `../../sysvar/fd_sysvar_rent.h`
- `../../../fd_flamenco.h`
- `../../../../disco/pack/fd_pack.h`
- `fd_harness_common.h`
- `generated/txn.pb.h`


# Function Declarations (Public API)

---
### fd\_runtime\_fuzz\_serialize\_txn<!-- {{#callable_declaration:fd_runtime_fuzz_serialize_txn}} -->
Serializes a Protobuf SanitizedTransaction into a transaction descriptor.
- **Description**: This function serializes a given Protobuf SanitizedTransaction into a transaction descriptor format and writes it to a pre-allocated buffer. It is used to prepare transaction data for further processing or transmission. The function must be called with a buffer of at least 1232 bytes to ensure there is enough space for the serialized transaction. It returns the number of bytes consumed in the buffer, or ULONG_MAX if the serialization exceeds the buffer size limit. The function also outputs the count of instructions and address table lookups in the transaction.
- **Inputs**:
    - `txn_raw_begin`: A pointer to a pre-allocated buffer of at least 1232 bytes where the serialized transaction will be written. The caller retains ownership and must ensure the buffer is valid.
    - `tx`: A pointer to a constant fd_exec_test_sanitized_transaction_t structure representing the transaction to be serialized. Must not be null.
    - `out_instr_cnt`: A pointer to a ushort where the function will store the count of instructions in the transaction. Must not be null.
    - `out_addr_table_cnt`: A pointer to a ushort where the function will store the count of address table lookups in the transaction. Must not be null.
- **Output**: Returns the number of bytes consumed in the buffer, or ULONG_MAX if the serialization exceeds the buffer size limit.
- **See also**: [`fd_runtime_fuzz_serialize_txn`](fd_txn_harness.c.driver.md#fd_runtime_fuzz_serialize_txn)  (Implementation)


---
### fd\_runtime\_fuzz\_txn\_run<!-- {{#callable_declaration:fd_runtime_fuzz_txn_run}} -->
Executes a transaction using the provided context and captures the results.
- **Description**: This function executes a transaction based on the given transaction context and stores the results in a specified output buffer. It is used to test transaction execution within a runtime environment. The function requires a valid runner and input context, and it writes the execution results to the provided output buffer. The caller must ensure that the output buffer is sufficiently large to hold the results. The function returns the number of bytes written to the output buffer, or zero if the transaction context creation fails.
- **Inputs**:
    - `runner`: A pointer to an fd_runtime_fuzz_runner_t structure that manages the execution environment. Must not be null.
    - `input_`: A pointer to a constant transaction context input. The input must be valid and properly initialized.
    - `output_`: A pointer to a location where the function will store a pointer to the transaction result. Must not be null.
    - `output_buf`: A pointer to a buffer where the transaction execution results will be stored. Must be pre-allocated and large enough to hold the results.
    - `output_bufsz`: The size of the output buffer in bytes. Must be large enough to accommodate the transaction results.
- **Output**: Returns the number of bytes written to the output buffer, or zero if the transaction context creation fails.
- **See also**: [`fd_runtime_fuzz_txn_run`](fd_txn_harness.c.driver.md#fd_runtime_fuzz_txn_run)  (Implementation)



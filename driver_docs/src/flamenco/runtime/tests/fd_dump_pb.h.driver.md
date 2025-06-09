# Purpose
The `fd_dump_pb.h` file is a C header file that provides a set of APIs for serializing and dumping various components of a ledger system into Protobuf messages. This functionality is crucial for debugging, testing, and data collection purposes within a ledger environment. The file defines functions to serialize instructions, transactions, and blocks into Protobuf format, which can then be used for replaying and analyzing ledger transactions. The header file is part of a larger system that includes components for handling instructions, runtime blocks, and virtual machine states, as indicated by the included headers such as `fd_instr_info.h`, `fd_runtime_block_info.h`, and `fd_vm.h`.

The primary technical components of this file include functions like [`fd_dump_instr_to_protobuf`](#fd_dump_instr_to_protobuf), [`fd_dump_txn_to_protobuf`](#fd_dump_txn_to_protobuf), and [`fd_dump_block_to_protobuf`](#fd_dump_block_to_protobuf), which handle the serialization of instructions, transactions, and blocks, respectively. Additionally, the file provides mechanisms for capturing the state of a virtual machine, which is essential for debugging and testing complex ledger operations. The header file also outlines command-line arguments that can be used to filter and direct the output of these dumps, allowing for targeted data collection. This file is part of a broader testing and conformance framework, as evidenced by references to the `solana-conformance` project, which facilitates the comparison of execution results across different ledger implementations.
# Imports and Dependencies

---
- `../info/fd_instr_info.h`
- `../info/fd_runtime_block_info.h`
- `../../vm/fd_vm.h`
- `harness/generated/block.pb.h`


# Function Declarations (Public API)

---
### fd\_dump\_instr\_to\_protobuf<!-- {{#callable_declaration:fd_dump_instr_to_protobuf}} -->
Dumps a specific instruction to a Protobuf file.
- **Description**: This function is used to serialize and dump a specific instruction from a transaction context into a Protobuf message, which is then written to a file. It is useful for debugging and testing by allowing the replay of specific instructions. The function should be called when you need to capture the state of an instruction for later analysis. It requires a valid transaction context and instruction information. The function respects a signature filter, if set, and will only dump instructions matching the specified signature. The output file is named using the base58-encoded transaction signature and the instruction index.
- **Inputs**:
    - `txn_ctx`: A pointer to a fd_exec_txn_ctx_t structure representing the transaction context. Must not be null.
    - `instr`: A pointer to a fd_instr_info_t structure containing information about the instruction to be dumped. Must not be null.
    - `instruction_idx`: An unsigned short representing the index of the instruction within the transaction. It is used in the output file name.
- **Output**: None
- **See also**: [`fd_dump_instr_to_protobuf`](fd_dump_pb.c.driver.md#fd_dump_instr_to_protobuf)  (Implementation)


---
### fd\_dump\_txn\_to\_protobuf<!-- {{#callable_declaration:fd_dump_txn_to_protobuf}} -->
Dumps a transaction to a Protobuf message file.
- **Description**: This function is used to serialize a transaction context into a Protobuf message and write it to a file in a specified output directory. It is particularly useful for debugging, collecting test data, and replaying ledger transactions. The function should be called when a transaction needs to be captured in a Protobuf format, and it respects a signature filter if specified, meaning only transactions with matching signatures will be dumped. Ensure that the transaction context and scratchpad memory are properly initialized before calling this function.
- **Inputs**:
    - `txn_ctx`: A pointer to a transaction context structure (fd_exec_txn_ctx_t) that contains the transaction data to be dumped. Must not be null.
    - `spad`: A pointer to a scratchpad memory structure (fd_spad_t) used for temporary storage during the operation. Must not be null.
- **Output**: None
- **See also**: [`fd_dump_txn_to_protobuf`](fd_dump_pb.c.driver.md#fd_dump_txn_to_protobuf)  (Implementation)


---
### fd\_dump\_block\_to\_protobuf<!-- {{#callable_declaration:fd_dump_block_to_protobuf}} -->
Creates a Protobuf message representing a block context.
- **Description**: This function is used to create an initial Protobuf message that captures the state of a block context, including fields from the slot and epoch context, as well as any current builtins and sysvar accounts. It is typically called when there is a need to serialize block information for debugging or testing purposes. The function must be called with a valid capture context, as a null capture context will result in a warning and no operation. The function does not handle spad frames internally, so any necessary memory management must be handled by the caller.
- **Inputs**:
    - `slot_ctx`: A pointer to a constant fd_exec_slot_ctx_t structure representing the slot context. The caller retains ownership and it must not be null.
    - `capture_ctx`: A pointer to a constant fd_capture_ctx_t structure representing the capture context. It must not be null, as a null value will trigger a warning and the function will return without performing any operation.
    - `spad`: A pointer to an fd_spad_t structure used for temporary storage during the operation. The caller retains ownership and it must not be null.
    - `block_context_msg`: A pointer to an fd_exec_test_block_context_t structure where the resulting Protobuf message will be stored. The caller is responsible for ensuring this is a valid, writable location.
- **Output**: None
- **See also**: [`fd_dump_block_to_protobuf`](fd_dump_pb.c.driver.md#fd_dump_block_to_protobuf)  (Implementation)


---
### fd\_dump\_block\_to\_protobuf\_tx\_only<!-- {{#callable_declaration:fd_dump_block_to_protobuf_tx_only}} -->
Dumps transactions from a runtime block into a Protobuf message.
- **Description**: This function is used to serialize and dump transactions from a given runtime block into a Protobuf message format, which is useful for debugging and testing purposes. It requires valid block information and capture context to function correctly. The function must be called with non-null pointers for `block_info` and `capture_ctx`, as it will log a warning and return immediately if these are null. The function also allocates memory for the output buffer and writes the serialized data to a file in the specified output directory. It is important to ensure that the `spad` frame is properly managed to avoid potential issues during execution.
- **Inputs**:
    - `block_info`: A pointer to a constant `fd_runtime_block_info_t` structure containing information about the runtime block. Must not be null.
    - `slot_ctx`: A pointer to a constant `fd_exec_slot_ctx_t` structure providing context about the execution slot. The caller retains ownership.
    - `capture_ctx`: A pointer to a constant `fd_capture_ctx_t` structure specifying the capture context, including the output directory for the Protobuf message. Must not be null.
    - `spad`: A pointer to an `fd_spad_t` structure used for memory allocation during the function's execution. The caller retains ownership.
    - `block_context_msg`: A pointer to an `fd_exec_test_block_context_t` structure where the Protobuf message will be stored. The caller retains ownership and is responsible for managing the memory.
- **Output**: None
- **See also**: [`fd_dump_block_to_protobuf_tx_only`](fd_dump_pb.c.driver.md#fd_dump_block_to_protobuf_tx_only)  (Implementation)


---
### fd\_dump\_vm\_cpi\_state<!-- {{#callable_declaration:fd_dump_vm_cpi_state}} -->
Captures and dumps the VM state and instruction context to a file.
- **Description**: This function is used to capture the current state of a virtual machine (VM) and its instruction context, and then serialize this information into a Protobuf message stored in a file. It is intended to be called at the start of a VM_SYSCALL_CPI_ENTRYPOINT to facilitate debugging and analysis of the VM's state at that point. The function assumes the existence of a 'vm_cpi_state' directory in the current working directory and generates a unique file based on the tile ID, caller public key, and instruction size. If a file with the same name already exists, the function will not overwrite it and will return immediately.
- **Inputs**:
    - `vm`: A pointer to an fd_vm_t structure representing the virtual machine whose state is to be captured. Must not be null.
    - `fn_name`: A constant character pointer to the name of the function being invoked. The string is copied and should not be null.
    - `instruction_va`: An unsigned long representing the virtual address of the instruction. Must be a valid address within the VM's address space.
    - `acct_infos_va`: An unsigned long representing the virtual address of account information. Must be a valid address within the VM's address space.
    - `acct_info_cnt`: An unsigned long indicating the number of account information entries. Should be a non-negative value.
    - `signers_seeds_va`: An unsigned long representing the virtual address of the signers' seeds. Must be a valid address within the VM's address space.
    - `signers_seeds_cnt`: An unsigned long indicating the number of signers' seeds. Should be a non-negative value.
- **Output**: None
- **See also**: [`fd_dump_vm_cpi_state`](fd_dump_pb.c.driver.md#fd_dump_vm_cpi_state)  (Implementation)



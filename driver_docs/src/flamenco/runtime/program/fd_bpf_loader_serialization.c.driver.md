# Purpose
This C source code file is responsible for handling the serialization and deserialization of input data for a BPF (Berkeley Packet Filter) virtual machine. The primary focus of the code is to manage the input region of the BPF VM, which includes instruction information, account metadata, and account data. The file provides functions to serialize this data into a contiguous memory buffer when direct mapping is not enabled, and to handle more sophisticated memory translation when direct mapping is active. The serialization process involves copying account data and metadata into a buffer, while deserialization involves extracting this data back into the appropriate structures after execution. The code also addresses the challenges of memory alignment and the potential overhead of copying large data regions, offering solutions like direct mapping to optimize performance.

The file defines several static functions that are not intended to be used outside of this compilation unit, indicating that it is part of a larger system where these functions are called internally. The functions [`fd_bpf_loader_input_serialize_parameters`](#fd_bpf_loader_input_serialize_parameters) and [`fd_bpf_loader_input_deserialize_parameters`](#fd_bpf_loader_input_deserialize_parameters) serve as the main entry points for serialization and deserialization, respectively, and handle both aligned and unaligned data formats. The code is designed to be efficient and robust, with error handling and optimizations for different scenarios, such as when accounts are read-only or when data resizing is required. The use of direct mapping allows for more efficient memory usage by avoiding unnecessary data copying, which is particularly beneficial when dealing with large data sets or nested calls.
# Imports and Dependencies

---
- `fd_bpf_loader_serialization.h`
- `../fd_borrowed_account.h`
- `../fd_runtime.h`


# Functions

---
### new\_input\_mem\_region<!-- {{#callable:new_input_mem_region}} -->
The `new_input_mem_region` function adds a new memory region to an array of input memory regions, updating its properties based on the provided parameters and the previous region's details.
- **Inputs**:
    - `input_mem_regions`: A pointer to an array of `fd_vm_input_region_t` structures representing the input memory regions.
    - `input_mem_regions_cnt`: A pointer to a `uint` that holds the current count of input memory regions.
    - `buffer`: A pointer to a `uchar` buffer that represents the host address of the new memory region.
    - `region_sz`: An `ulong` representing the size of the new memory region.
    - `is_writable`: A `uchar` indicating whether the new memory region is writable (non-zero) or not (zero).
    - `is_acct_data`: A `uchar` indicating whether the new memory region corresponds to account data (non-zero) or not (zero).
- **Control Flow**:
    - Calculate the virtual address offset for the new region based on the count of existing regions and their sizes.
    - Set the properties of the new memory region in the `input_mem_regions` array, including writability, host address, size, virtual address offset, and account data flag.
    - Increment the count of input memory regions.
- **Output**: The function does not return a value; it modifies the `input_mem_regions` array and increments the `input_mem_regions_cnt` to reflect the addition of the new memory region.


---
### write\_account<!-- {{#callable:write_account}} -->
The `write_account` function serializes account data and metadata into a buffer or maps it directly into memory regions for a BPF virtual machine, depending on the configuration.
- **Inputs**:
    - `account`: A pointer to an `fd_borrowed_account_t` structure representing the account to be serialized or mapped.
    - `instr_acc_idx`: An unsigned char representing the index of the account in the instruction.
    - `serialized_params`: A double pointer to an unsigned char, pointing to the current position in the serialized parameters buffer.
    - `serialized_params_start`: A double pointer to an unsigned char, pointing to the start of the serialized parameters buffer.
    - `input_mem_regions`: A pointer to an array of `fd_vm_input_region_t` structures representing the input memory regions.
    - `input_mem_regions_cnt`: A pointer to an unsigned integer representing the count of input memory regions.
    - `acc_region_metas`: A pointer to an array of `fd_vm_acc_region_meta_t` structures representing metadata for account regions.
    - `is_aligned`: An integer indicating whether the data should be aligned.
    - `copy_account_data`: An integer indicating whether the account data should be copied into the buffer or directly mapped.
- **Control Flow**:
    - Retrieve account data and its length if the account is not NULL.
    - If `copy_account_data` is true, copy the account data into the serialized parameters buffer and adjust for alignment if necessary.
    - If `copy_account_data` is false, map the account data directly into memory regions, updating metadata and handling alignment and resizing regions.
    - Update the serialized parameters start pointer to the current position in the buffer.
- **Output**: The function does not return a value but modifies the serialized parameters buffer and updates the input memory regions and account region metadata.
- **Functions called**:
    - [`new_input_mem_region`](#new_input_mem_region)


---
### fd\_bpf\_loader\_input\_serialize\_aligned<!-- {{#callable:fd_bpf_loader_input_serialize_aligned}} -->
The function `fd_bpf_loader_input_serialize_aligned` serializes account and instruction data into a 16-byte aligned buffer for a BPF virtual machine, considering account duplication and alignment requirements.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which contains transaction and instruction details.
    - `sz`: A pointer to an unsigned long where the function will store the size of the serialized data.
    - `pre_lens`: A pointer to an array of unsigned longs to store the pre-serialization lengths of account data.
    - `input_mem_regions`: A pointer to an array of `fd_vm_input_region_t` structures representing input memory regions.
    - `input_mem_regions_cnt`: A pointer to an unsigned integer representing the count of input memory regions.
    - `acc_region_metas`: A pointer to an array of `fd_vm_acc_region_meta_t` structures for storing metadata about account regions.
    - `copy_account_data`: An integer flag indicating whether to copy account data into the serialized buffer.
    - `mask_out_rent_epoch_in_vm_serialization`: An integer flag indicating whether to mask out the rent epoch in the serialized data.
- **Control Flow**:
    - Initialize arrays to track seen account indices and duplicate account indices.
    - Calculate the total size needed for serialization by iterating over each account and considering duplication and alignment.
    - Allocate a 16-byte aligned buffer for the serialized data.
    - Store the number of accounts in the buffer and iterate over each account to serialize its data.
    - For duplicate accounts, store a marker and the index of the original account to maintain alignment.
    - For unique accounts, serialize metadata including signer status, writability, executable status, key, owner, lamports, data length, and rent epoch.
    - If `copy_account_data` is true, copy the account data into the buffer, aligning it as necessary.
    - Store the instruction data and program ID in the buffer.
    - Check for serialization errors by ensuring the buffer size matches the calculated size.
    - Add the serialized data as a new input memory region and update the size pointer.
- **Output**: Returns a pointer to the start of the serialized parameters buffer.
- **Functions called**:
    - [`write_account`](#write_account)
    - [`new_input_mem_region`](#new_input_mem_region)


---
### fd\_bpf\_loader\_input\_deserialize\_aligned<!-- {{#callable:fd_bpf_loader_input_deserialize_aligned}} -->
The function `fd_bpf_loader_input_deserialize_aligned` deserializes account data from a buffer into a context structure, handling both direct mapping and copying of account data.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which contains information about the instruction and accounts involved.
    - `pre_lens`: A constant pointer to an array of unsigned long integers representing the pre-serialization lengths of account data.
    - `buffer`: A pointer to an unsigned character array that contains the serialized account data to be deserialized.
    - `buffer_sz`: An unsigned long integer representing the size of the buffer, though it is marked as unused in this function.
    - `copy_account_data`: An integer flag indicating whether account data should be copied (non-zero) or directly mapped (zero).
- **Control Flow**:
    - Initialize a starting position `start` to zero and an array `acc_idx_seen` to track seen account indices.
    - Increment `start` by the size of an unsigned long to skip the number of accounts.
    - Iterate over each account in the context's instruction account list.
    - For each account, increment `start` to account for the position byte.
    - Borrow the account using `FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK`.
    - Check if the account index has been seen before; if so, increment `start` by 7 to skip duplicate data.
    - If the account index is new, mark it as seen and increment `start` by the sizes of various metadata fields (is_signer, is_writable, executable, original_data_len, key).
    - Load the owner from the buffer and increment `start` by the size of `fd_pubkey_t`.
    - Load lamports from the buffer, compare with the account's lamports, and update if necessary, incrementing `start` by the size of an unsigned long.
    - Load the post-serialization data length from the buffer and increment `start`.
    - Calculate alignment offset and set `post_data` to the current buffer position.
    - Check if the post-serialization length is valid against metadata constraints.
    - If `copy_account_data` is true, check if the account data can be resized and changed, then set the data from the buffer slice; otherwise, verify data consistency.
    - If direct mapping is enabled, adjust `start` for alignment, resize the account data if possible, and copy reallocated bytes directly into the account data buffer.
    - Increment `start` by the maximum permitted data increase, alignment offset, and the size of an unsigned long for the rent epoch.
    - Compare the account's owner with the loaded owner and update if necessary.
- **Output**: Returns an integer status code, `FD_EXECUTOR_INSTR_SUCCESS` on success or an error code if any operation fails.


---
### fd\_bpf\_loader\_input\_serialize\_unaligned<!-- {{#callable:fd_bpf_loader_input_serialize_unaligned}} -->
The function `fd_bpf_loader_input_serialize_unaligned` serializes account and instruction data into a contiguous buffer for a BPF virtual machine, handling duplicate accounts and optional data copying.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context, which contains transaction and instruction details.
    - `sz`: A pointer to a ulong where the function will store the size of the serialized data.
    - `pre_lens`: An array of ulongs to store the lengths of account data before serialization.
    - `input_mem_regions`: An array of memory regions representing the input region of the VM.
    - `input_mem_regions_cnt`: A pointer to a uint representing the count of input memory regions.
    - `acc_region_metas`: An array of metadata for account regions, used for tracking serialized data offsets.
    - `copy_account_data`: An integer flag indicating whether to copy account data into the serialized buffer.
    - `mask_out_rent_epoch_in_vm_serialization`: An integer flag indicating whether to mask out the rent epoch in the serialized data.
- **Control Flow**:
    - Initialize variables for serialized size and account tracking arrays.
    - Iterate over each account in the instruction context to calculate the serialized size, accounting for duplicates and optional data copying.
    - Allocate a 16-byte aligned buffer for the serialized data.
    - Iterate over each account again to serialize account metadata and data into the buffer, handling duplicates and storing metadata offsets.
    - Serialize instruction data and program ID into the buffer.
    - Verify the serialized size matches the expected size and update the input memory regions with the new serialized data region.
- **Output**: Returns a pointer to the start of the serialized parameters buffer.
- **Functions called**:
    - [`write_account`](#write_account)
    - [`new_input_mem_region`](#new_input_mem_region)


---
### fd\_bpf\_loader\_input\_deserialize\_unaligned<!-- {{#callable:fd_bpf_loader_input_deserialize_unaligned}} -->
The function `fd_bpf_loader_input_deserialize_unaligned` deserializes input data for a BPF loader, updating account metadata and data as necessary, without assuming alignment.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`), which contains information about the current instruction and accounts.
    - `pre_lens`: A constant pointer to an array of unsigned long integers representing the pre-serialized lengths of account data.
    - `input`: A pointer to an unsigned character array containing the serialized input data to be deserialized.
    - `input_sz`: An unsigned long integer representing the size of the input data buffer.
    - `copy_account_data`: An integer flag indicating whether account data should be copied during deserialization.
- **Control Flow**:
    - Initialize `input_cursor` to point to the start of the input buffer and a `acc_idx_seen` array to track processed account indices.
    - Skip the first `ulong` in the input buffer, which represents the number of accounts.
    - Iterate over each account in the instruction context (`ctx->instr->acct_cnt`).
    - For each account, check if it has been processed using `acc_idx_seen`; if not, mark it as seen and proceed.
    - Advance `input_cursor` past metadata fields: `is_signer`, `is_writable`, and `key`.
    - Borrow the account using `FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK` and update its lamports if they differ from the serialized value.
    - Advance `input_cursor` past the `lamports` and `data length` fields.
    - If `copy_account_data` is true, copy the account data from the input buffer to the account, checking for errors and data consistency.
    - Advance `input_cursor` past the account data, `owner`, `executable`, and `rent_epoch` fields.
    - Check if `input_cursor` exceeds the input buffer size (`input_sz`) and return an error if it does.
- **Output**: Returns 0 on success, or an error code if deserialization fails or if there is an inconsistency in the input data.


---
### fd\_bpf\_loader\_input\_serialize\_parameters<!-- {{#callable:fd_bpf_loader_input_serialize_parameters}} -->
The `fd_bpf_loader_input_serialize_parameters` function serializes input parameters for a BPF loader, choosing between aligned and unaligned serialization based on the `is_deprecated` flag.
- **Inputs**:
    - `instr_ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`) containing instruction and transaction details.
    - `sz`: A pointer to an unsigned long where the size of the serialized data will be stored.
    - `pre_lens`: A pointer to an array of unsigned longs to store pre-serialization lengths of account data.
    - `input_mem_regions`: A pointer to an array of `fd_vm_input_region_t` structures representing input memory regions.
    - `input_mem_regions_cnt`: A pointer to an unsigned integer representing the count of input memory regions.
    - `acc_region_metas`: A pointer to an array of `fd_vm_acc_region_meta_t` structures for account region metadata.
    - `direct_mapping`: An integer flag indicating whether direct mapping is enabled (non-zero) or not (zero).
    - `mask_out_rent_epoch_in_vm_serialization`: An integer flag indicating whether to mask out the rent epoch during serialization.
    - `is_deprecated`: An unsigned char flag indicating whether to use the deprecated serialization method.
    - `out`: A double pointer to an unsigned char where the serialized output will be stored.
- **Control Flow**:
    - Retrieve the number of instruction accounts from `instr_ctx` and check if it exceeds the maximum allowed (`FD_INSTR_ACCT_MAX`).
    - If the number of accounts exceeds the maximum, return an error code `FD_EXECUTOR_INSTR_ERR_MAX_ACCS_EXCEEDED`.
    - Check the `is_deprecated` flag to determine the serialization method.
    - If `is_deprecated` is true, call [`fd_bpf_loader_input_serialize_unaligned`](#fd_bpf_loader_input_serialize_unaligned) to perform unaligned serialization and store the result in `out`.
    - If `is_deprecated` is false, call [`fd_bpf_loader_input_serialize_aligned`](#fd_bpf_loader_input_serialize_aligned) to perform aligned serialization and store the result in `out`.
    - Return `FD_EXECUTOR_INSTR_SUCCESS` to indicate successful serialization.
- **Output**: Returns an integer status code indicating success (`FD_EXECUTOR_INSTR_SUCCESS`) or an error (`FD_EXECUTOR_INSTR_ERR_MAX_ACCS_EXCEEDED`).
- **Functions called**:
    - [`fd_bpf_loader_input_serialize_unaligned`](#fd_bpf_loader_input_serialize_unaligned)
    - [`fd_bpf_loader_input_serialize_aligned`](#fd_bpf_loader_input_serialize_aligned)


---
### fd\_bpf\_loader\_input\_deserialize\_parameters<!-- {{#callable:fd_bpf_loader_input_deserialize_parameters}} -->
The function `fd_bpf_loader_input_deserialize_parameters` deserializes input parameters for a BPF loader, choosing between aligned and unaligned deserialization based on whether the input is deprecated.
- **Inputs**:
    - `ctx`: A pointer to the execution instruction context (`fd_exec_instr_ctx_t`) which contains the context for the current instruction execution.
    - `pre_lens`: A constant pointer to an array of unsigned long integers representing the pre-serialized lengths of account data.
    - `input`: A pointer to an unsigned character array that contains the serialized input data to be deserialized.
    - `input_sz`: An unsigned long integer representing the size of the input data buffer.
    - `direct_mapping`: An integer flag indicating whether direct mapping is enabled (non-zero) or not (zero).
    - `is_deprecated`: An unsigned character flag indicating whether the deserialization should use the deprecated method (non-zero) or not (zero).
- **Control Flow**:
    - Check if the `is_deprecated` flag is set.
    - If `is_deprecated` is true, call [`fd_bpf_loader_input_deserialize_unaligned`](#fd_bpf_loader_input_deserialize_unaligned) with the provided parameters, negating the `direct_mapping` flag.
    - If `is_deprecated` is false, call [`fd_bpf_loader_input_deserialize_aligned`](#fd_bpf_loader_input_deserialize_aligned) with the provided parameters, negating the `direct_mapping` flag.
    - Return the result of the called deserialization function.
- **Output**: The function returns an integer status code indicating the success or failure of the deserialization process.
- **Functions called**:
    - [`fd_bpf_loader_input_deserialize_unaligned`](#fd_bpf_loader_input_deserialize_unaligned)
    - [`fd_bpf_loader_input_deserialize_aligned`](#fd_bpf_loader_input_deserialize_aligned)



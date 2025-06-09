# Purpose
This C header file, `fd_bpf_program_util.h`, is part of a larger software system and provides utility functions and data structures for managing and interacting with eBPF (extended Berkeley Packet Filter) programs within the context of the Flamenco runtime environment. The file defines a key data structure, `fd_sbpf_validated_program_t`, which encapsulates information about a validated eBPF program, including metadata such as the program's entry point, size, and version. This structure is crucial for managing the lifecycle and execution of eBPF programs, ensuring they are correctly validated and stored in memory.

The file also declares several functions that facilitate the creation, alignment, and footprint calculation of validated eBPF programs, as well as functions for managing program cache entries and loading them into memory. These functions are essential for the efficient execution and management of eBPF programs within the runtime, providing mechanisms to validate, cache, and retrieve program data. The header file includes other related headers, indicating its integration with broader system components such as execution contexts and system calls. Overall, this file serves as a specialized utility for handling eBPF programs, focusing on validation, memory management, and runtime execution within the Flamenco system.
# Imports and Dependencies

---
- `../../fd_flamenco_base.h`
- `../fd_runtime_public.h`
- `../fd_acc_mgr.h`
- `../context/fd_exec_slot_ctx.h`
- `../../vm/syscall/fd_vm_syscall.h`


# Global Variables

---
### fd\_sbpf\_validated\_program\_new
- **Type**: `fd_sbpf_validated_program_t *`
- **Description**: The `fd_sbpf_validated_program_new` is a function that returns a pointer to a newly created `fd_sbpf_validated_program_t` structure. This structure is used to represent a validated SBPF (Solana Berkeley Packet Filter) program, which includes metadata such as magic number, entry point, and memory layout details.
- **Use**: This function is used to initialize and allocate a new validated SBPF program structure using provided memory and ELF information.


# Data Structures

---
### fd\_sbpf\_validated\_program
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the structure, used for validation.
    - `last_updated_slot`: The slot number when the program was last updated.
    - `entry_pc`: The entry point program counter for the validated program.
    - `text_cnt`: The count of text sections in the program.
    - `text_off`: The offset of the text section in the program.
    - `text_sz`: The size of the text section in the program.
    - `rodata_sz`: The size of the read-only data section.
    - `calldests_shmem`: Pointer to the shared memory for call destinations.
    - `calldests`: Pointer to the call destinations data structure.
    - `rodata`: Pointer to the read-only data section.
    - `sbpf_version`: The version of the SBPF (Solana Berkeley Packet Filter) being used.
- **Description**: The `fd_sbpf_validated_program` structure is designed to encapsulate the details of a validated SBPF program, including metadata such as the magic number for validation, the last updated slot, and the entry point program counter. It also manages memory pointers for text and read-only data sections, as well as call destinations, facilitating efficient copying and management of these components. The structure supports versioning with an SBPF version field, ensuring compatibility and tracking of the program's evolution.


---
### fd\_sbpf\_validated\_program\_t
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the validated program structure.
    - `last_updated_slot`: The slot number when the program was last updated.
    - `entry_pc`: The entry point program counter for the validated program.
    - `text_cnt`: The count of text sections in the program.
    - `text_off`: The offset of the text section in the program.
    - `text_sz`: The size of the text section in the program.
    - `rodata_sz`: The size of the read-only data section.
    - `calldests_shmem`: A pointer to the shared memory for call destinations.
    - `calldests`: A pointer to the call destinations structure.
    - `rodata`: A pointer to the read-only data section.
    - `sbpf_version`: The version of the SBPF (Solana Berkeley Packet Filter) used.
- **Description**: The `fd_sbpf_validated_program_t` structure represents a validated SBPF program, containing metadata and pointers necessary for execution and management. It includes fields for tracking the program's unique identifier, version, entry point, and memory layout, such as text and read-only data sections. Additionally, it maintains pointers to shared memory and call destinations, facilitating efficient copying and execution of the program. This structure is crucial for managing SBPF programs within the Flamenco runtime environment, ensuring they are correctly validated and executed.


# Function Declarations (Public API)

---
### bpf\_tpool\_wrapper<!-- {{#callable_declaration:bpf_tpool_wrapper}} -->
Wraps a thread pool task for BPF program scanning and cache entry creation.
- **Description**: This function is used to wrap a task that scans BPF programs and creates cache entries within a thread pool context. It should be called when there is a need to perform these operations concurrently using a thread pool. The function expects specific arguments related to the thread pool, BPF records, and execution context. It is important to ensure that the parameters are correctly initialized and valid before calling this function, as it does not perform any validation on its own.
- **Inputs**:
    - `para_arg_1`: A pointer to a thread pool object (fd_tpool_t). Must not be null and should be a valid thread pool instance.
    - `para_arg_2`: Unused parameter. Can be set to any value, but typically ignored.
    - `fn_arg_1`: A pointer to an array of BPF records (fd_funk_rec_t const **). Must not be null and should point to valid BPF records.
    - `fn_arg_2`: A pointer to a uchar that indicates if the program is a BPF program. Must not be null.
    - `fn_arg_3`: An unsigned long representing the count of records. Must be a valid count corresponding to the records pointed by fn_arg_1.
    - `fn_arg_4`: A pointer to an execution slot context (fd_exec_slot_ctx_t). Must not be null and should be a valid execution context.
- **Output**: None
- **See also**: [`bpf_tpool_wrapper`](fd_bpf_program_util.c.driver.md#bpf_tpool_wrapper)  (Implementation)


---
### fd\_sbpf\_validated\_program\_new<!-- {{#callable_declaration:fd_sbpf_validated_program_new}} -->
Creates a new validated SBPF program structure in the provided memory.
- **Description**: This function initializes a new `fd_sbpf_validated_program_t` structure in the memory provided by the caller. It sets up the necessary fields based on the information from the `elf_info` parameter, including the SBPF version and memory layout for call destinations and read-only data. The function must be called with a valid memory region that is properly aligned and large enough to accommodate the structure and its associated data. The caller is responsible for managing the memory's lifecycle.
- **Inputs**:
    - `mem`: A pointer to a memory region where the validated program structure will be created. This memory must be properly aligned and large enough to hold the structure and its associated data. The caller retains ownership and is responsible for ensuring the memory's validity.
    - `elf_info`: A pointer to a constant `fd_sbpf_elf_info_t` structure containing information about the ELF file, such as the SBPF version and read-only data size. This parameter must not be null, and the data it points to must remain valid for the duration of the function call.
- **Output**: Returns a pointer to the newly created `fd_sbpf_validated_program_t` structure located at the provided memory address.
- **See also**: [`fd_sbpf_validated_program_new`](fd_bpf_program_util.c.driver.md#fd_sbpf_validated_program_new)  (Implementation)


---
### fd\_sbpf\_validated\_program\_align<!-- {{#callable_declaration:fd_sbpf_validated_program_align}} -->
Return the alignment requirement of the fd_sbpf_validated_program_t structure.
- **Description**: Use this function to determine the memory alignment requirement for instances of the fd_sbpf_validated_program_t structure. This is useful when allocating memory for such structures to ensure proper alignment, which can be critical for performance and correctness on some architectures. The function does not require any parameters and can be called at any time.
- **Inputs**: None
- **Output**: Returns the alignment requirement as an unsigned long integer, representing the number of bytes.
- **See also**: [`fd_sbpf_validated_program_align`](fd_bpf_program_util.c.driver.md#fd_sbpf_validated_program_align)  (Implementation)


---
### fd\_sbpf\_validated\_program\_footprint<!-- {{#callable_declaration:fd_sbpf_validated_program_footprint}} -->
Calculate the memory footprint required for a validated SBPF program.
- **Description**: This function computes the total memory footprint needed to store a validated SBPF program based on the provided ELF information. It is useful for determining the amount of memory to allocate when creating or managing SBPF programs. The function should be called with valid ELF information, which includes details about the read-only data size. The calculated footprint accounts for alignment and additional structures required by the program.
- **Inputs**:
    - `elf_info`: A pointer to a constant fd_sbpf_elf_info_t structure containing ELF information. This must not be null and should contain valid data about the read-only data size and footprint. Invalid or null input will lead to undefined behavior.
- **Output**: Returns the total memory footprint in bytes as an unsigned long, which represents the space required to store the validated SBPF program.
- **See also**: [`fd_sbpf_validated_program_footprint`](fd_bpf_program_util.c.driver.md#fd_sbpf_validated_program_footprint)  (Implementation)


---
### fd\_bpf\_scan\_and\_create\_bpf\_program\_cache\_entry<!-- {{#callable_declaration:fd_bpf_scan_and_create_bpf_program_cache_entry}} -->
Scans and creates BPF program cache entries.
- **Description**: This function is used to scan through records in a transaction and create cache entries for BPF programs. It should be called when there is a need to update or initialize the BPF program cache based on the current transaction context. The function requires a valid execution slot context and a runtime scratchpad for its operation. It handles concurrency by using a unique transaction identifier and ensures that the cache is updated correctly. The function returns an error code if it fails to prepare or publish the transaction.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. Must not be null and should be properly initialized before calling this function.
    - `runtime_spad`: A pointer to an fd_spad_t structure used as a runtime scratchpad. Must not be null and should be allocated and initialized appropriately before use.
- **Output**: Returns 0 on success, indicating that the BPF program cache entries were created successfully. Returns -1 on failure, indicating an error occurred during transaction preparation or publishing.
- **See also**: [`fd_bpf_scan_and_create_bpf_program_cache_entry`](fd_bpf_program_util.c.driver.md#fd_bpf_scan_and_create_bpf_program_cache_entry)  (Implementation)


---
### fd\_bpf\_is\_bpf\_program<!-- {{#callable_declaration:fd_bpf_is_bpf_program}} -->
Determines if a record represents a BPF program.
- **Description**: Use this function to check if a given record corresponds to a BPF program by examining its metadata. This function should be called with a valid record and workspace, and it will set the output parameter to indicate whether the record is a BPF program. The function expects the record to have a valid key and will safely handle cases where the metadata is not present or does not match known BPF program identifiers.
- **Inputs**:
    - `rec`: A pointer to a constant `fd_funk_rec_t` structure representing the record to be checked. Must not be null.
    - `funk_wksp`: A pointer to an `fd_wksp_t` workspace used to access the record's value. Must not be null.
    - `is_bpf_program`: A pointer to an `uchar` where the result will be stored. Must not be null. The value will be set to 1 if the record is a BPF program, or 0 otherwise.
- **Output**: None
- **See also**: [`fd_bpf_is_bpf_program`](fd_bpf_program_util.c.driver.md#fd_bpf_is_bpf_program)  (Implementation)


---
### fd\_bpf\_scan\_and\_create\_bpf\_program\_cache\_entry\_para<!-- {{#callable_declaration:fd_bpf_scan_and_create_bpf_program_cache_entry_para}} -->
Scans and creates BPF program cache entries in parallel.
- **Description**: This function is used to scan through records and create BPF program cache entries in a parallelized manner. It should be called when there is a need to efficiently process and cache BPF programs from a set of records. The function requires a valid execution slot context, a runtime scratchpad for temporary allocations, and a parallel execution context for handling the parallel processing. It is important to ensure that the provided contexts are properly initialized and that the runtime scratchpad has sufficient space for allocations. The function returns an integer indicating success or failure of the operation.
- **Inputs**:
    - `slot_ctx`: A pointer to an fd_exec_slot_ctx_t structure representing the execution slot context. Must be valid and properly initialized. The caller retains ownership.
    - `runtime_spad`: A pointer to an fd_spad_t structure used as a runtime scratchpad for temporary allocations. Must be valid and have sufficient space for allocations. The caller retains ownership.
    - `exec_para_ctx`: A pointer to an fd_exec_para_cb_ctx_t structure representing the parallel execution context. Must be valid and properly initialized. The caller retains ownership.
- **Output**: Returns 0 on success, or -1 if an error occurs during the operation.
- **See also**: [`fd_bpf_scan_and_create_bpf_program_cache_entry_para`](fd_bpf_program_util.c.driver.md#fd_bpf_scan_and_create_bpf_program_cache_entry_para)  (Implementation)


---
### fd\_bpf\_load\_cache\_entry<!-- {{#callable_declaration:fd_bpf_load_cache_entry}} -->
Loads a validated BPF program from the cache.
- **Description**: This function attempts to load a validated BPF program associated with a given public key from the cache. It should be called when you need to retrieve a BPF program that has been previously validated and stored. The function will repeatedly attempt to access the cache until it successfully retrieves a valid program or determines that the program is not available. It is important to ensure that the `funk` and `funk_txn` contexts are properly initialized before calling this function. The function will return an error if the program cannot be found or if the retrieved program is invalid.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure representing the context in which the cache is managed. Must not be null.
    - `funk_txn`: A pointer to an `fd_funk_txn_t` structure representing the transaction context. Must not be null.
    - `program_pubkey`: A pointer to an `fd_pubkey_t` structure representing the public key of the program to be loaded. Must not be null.
    - `valid_prog`: A pointer to a pointer of `fd_sbpf_validated_program_t` where the address of the loaded validated program will be stored. Must not be null.
- **Output**: Returns 0 on success, with `valid_prog` pointing to the loaded program. Returns -1 if the program cannot be found or is invalid.
- **See also**: [`fd_bpf_load_cache_entry`](fd_bpf_program_util.c.driver.md#fd_bpf_load_cache_entry)  (Implementation)


---
### fd\_bpf\_get\_sbpf\_versions<!-- {{#callable_declaration:fd_bpf_get_sbpf_versions}} -->
Retrieve the minimum and maximum supported sBPF versions for a given slot and feature set.
- **Description**: This function determines the range of sBPF versions that are supported based on the provided execution slot and feature set. It is useful for understanding which sBPF versions can be executed or deployed in a given context. The function must be called with valid pointers for the minimum and maximum version outputs, and a valid feature set. It does not perform any validation on the input pointers, so they must not be null.
- **Inputs**:
    - `sbpf_min_version`: A pointer to an unsigned integer where the minimum supported sBPF version will be stored. Must not be null.
    - `sbpf_max_version`: A pointer to an unsigned integer where the maximum supported sBPF version will be stored. Must not be null.
    - `slot`: An unsigned long representing the execution slot for which the sBPF versions are being queried. It is used to determine active features.
    - `features`: A pointer to a constant fd_features_t structure that contains the feature set used to determine the supported sBPF versions. Must not be null.
- **Output**: The function writes the minimum and maximum supported sBPF versions to the provided pointers.
- **See also**: [`fd_bpf_get_sbpf_versions`](fd_bpf_program_util.c.driver.md#fd_bpf_get_sbpf_versions)  (Implementation)



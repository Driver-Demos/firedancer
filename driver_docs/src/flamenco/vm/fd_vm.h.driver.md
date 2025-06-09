# Purpose
The provided C header file defines the structure and functionality for a virtual machine (VM) capable of executing sBPF (Solana Berkeley Packet Filter) programs. This file is part of a larger system, likely related to the Solana blockchain, as indicated by references to Solana-specific components and practices. The primary structure defined is `fd_vm_t`, which encapsulates the state and configuration of the VM, including memory regions, execution state, and syscall mappings. The file also defines several auxiliary structures, such as `fd_vm_shadow_t`, `fd_vm_input_region_t`, and `fd_vm_acc_region_meta_t`, which manage stack frames, input memory regions, and account metadata, respectively. These structures are crucial for handling the VM's memory management and execution context.

The header file provides a set of function prototypes for managing the lifecycle of the VM, including creation ([`fd_vm_new`](#fd_vm_new)), initialization ([`fd_vm_init`](#fd_vm_init)), execution ([`fd_vm_exec`](#fd_vm_exec)), and deletion ([`fd_vm_delete`](#fd_vm_delete)). It also includes functions for joining and leaving a VM instance, as well as validating sBPF programs. The VM is designed to handle various execution states and errors, such as invalid instructions, memory access violations, and compute unit limits, with detailed error codes and diagnostics. The file emphasizes alignment and memory footprint considerations, ensuring that the VM operates efficiently within its allocated resources. Overall, this header file is a critical component of a system that executes sBPF programs, providing both the structural definitions and the API for interacting with the VM.
# Imports and Dependencies

---
- `fd_vm_base.h`


# Global Variables

---
### fd\_vm\_new
- **Type**: `void *`
- **Description**: The `fd_vm_new` function is a global function that returns a pointer to a memory region formatted to hold a `fd_vm_t` structure. It takes a single argument, `shmem`, which is a pointer to the start of the memory region to be formatted.
- **Use**: This function is used to initialize a memory region with the necessary alignment and footprint to store a `fd_vm_t` instance, returning the pointer to the memory region on success.


---
### fd\_vm\_join
- **Type**: `fd_vm_t *`
- **Description**: The `fd_vm_join` function returns a pointer to an `fd_vm_t` structure, which represents a virtual machine capable of executing sBPF programs. This function is used to join a caller to a virtual machine by providing a handle to the memory region where the virtual machine is stored.
- **Use**: This variable is used to obtain a local handle to a virtual machine instance, allowing the caller to interact with and execute programs on the virtual machine.


---
### fd\_vm\_init
- **Type**: `fd_vm_t *`
- **Description**: The `fd_vm_init` function initializes an instance of the `fd_vm_t` structure, which represents a virtual machine capable of executing sBPF programs. It sets up various parameters and configurations necessary for the VM's operation, such as memory regions, syscall mappings, and execution contexts.
- **Use**: This function is used to prepare a `fd_vm_t` instance for execution by configuring its memory, instruction context, and other necessary components.


---
### fd\_vm\_leave
- **Type**: `function pointer`
- **Description**: `fd_vm_leave` is a function that allows a caller to leave their current local join to a virtual machine (VM) represented by `fd_vm_t`. It returns a pointer to the memory region holding the VM on success, or NULL on failure.
- **Use**: This function is used to safely exit a VM session, ensuring that the caller is no longer joined to the VM upon successful return.


---
### fd\_vm\_delete
- **Type**: `function pointer`
- **Description**: `fd_vm_delete` is a function that takes a pointer to a memory region (`void * shmem`) and unformats it, assuming it holds a virtual machine (VM) state. It returns a pointer to the memory region on success, indicating that the caller has regained ownership of the memory.
- **Use**: This function is used to clean up and release the memory region previously formatted to hold a VM, ensuring that no one is joined to the VM at the time of deletion.


# Data Structures

---
### fd\_vm\_t
- **Type**: `struct`
- **Members**:
    - `instr_ctx`: Pointer to the instruction context used by the VM.
    - `heap_max`: Maximum amount of heap memory in bytes.
    - `entry_cu`: Initial compute units for the program.
    - `rodata`: Pointer to the read-only data of the program.
    - `rodata_sz`: Size of the read-only data in bytes.
    - `text`: Pointer to the program's sBPF instructions.
    - `text_cnt`: Count of sBPF instructions.
    - `text_off`: Offset for relocation of indirect calls.
    - `text_sz`: Size of the sBPF program in bytes.
    - `entry_pc`: Initial program counter value.
    - `calldests`: Bit vector of callable local functions.
    - `syscalls`: Map of syscalls available to the VM.
    - `trace`: Pointer to the trace location for execution traces.
    - `pc`: Current instruction pointer.
    - `ic`: Number of executed instructions.
    - `cu`: Remaining compute units for the transaction.
    - `frame_cnt`: Current number of stack frames pushed.
    - `heap_sz`: Current heap size in bytes.
    - `region_haddr`: Array of host addresses for memory regions.
    - `region_ld_sz`: Array of load sizes for memory regions.
    - `region_st_sz`: Array of store sizes for memory regions.
    - `input_mem_regions`: Array of input memory regions.
    - `input_mem_regions_cnt`: Count of input memory regions.
    - `acc_region_metas`: Array mapping instruction account indices to memory regions.
    - `is_deprecated`: Flag indicating if the VM instance is deprecated.
    - `reg`: Array of registers used by the VM.
    - `shadow`: Shadow stack for stack frame information.
    - `stack`: Memory for the stack.
    - `heap`: Memory for the heap.
    - `sha`: Pointer to a SHA instance for hashing.
    - `magic`: Magic number for validation.
    - `direct_mapping`: Flag indicating if direct memory mapping is enabled.
    - `stack_frame_size`: Size of a stack frame.
    - `segv_store_vaddr`: Virtual address causing a segmentation fault on store.
    - `sbpf_version`: Version of the SBPF being used.
- **Description**: The `fd_vm_t` structure represents a virtual machine capable of executing sBPF programs. It includes configuration settings such as maximum heap size, initial compute units, and program-specific data like read-only data and instruction text. The structure also maintains execution state, including the program counter, instruction count, and compute units, as well as memory management details like region addresses and sizes. Additionally, it supports features like syscall mapping, execution tracing, and direct memory mapping, with fields for managing stack, heap, and register states. The structure is designed to be aligned and footprinted for efficient memory usage and includes a magic number for validation.


---
### fd\_vm\_shadow
- **Type**: `struct`
- **Members**:
    - `r6`: Represents a general-purpose register used in the shadow stack.
    - `r7`: Represents a general-purpose register used in the shadow stack.
    - `r8`: Represents a general-purpose register used in the shadow stack.
    - `r9`: Represents a general-purpose register used in the shadow stack.
    - `r10`: Represents a general-purpose register used in the shadow stack.
    - `pc`: Holds the program counter value for the shadow stack.
- **Description**: The `fd_vm_shadow` structure is designed to store stack frame information that is not accessible from within a program. It contains a set of general-purpose registers (r6 to r10) and a program counter (pc), which are used to maintain the state of a virtual machine's execution context. This structure is particularly useful for managing the shadow stack, which is a mechanism to track function calls and returns in a virtual machine environment, ensuring that the execution state can be accurately restored or inspected as needed.


---
### fd\_vm\_shadow\_t
- **Type**: `struct`
- **Members**:
    - `r6`: Represents a general-purpose register used in the stack frame.
    - `r7`: Represents a general-purpose register used in the stack frame.
    - `r8`: Represents a general-purpose register used in the stack frame.
    - `r9`: Represents a general-purpose register used in the stack frame.
    - `r10`: Represents a general-purpose register used in the stack frame.
    - `pc`: Holds the program counter value for the stack frame.
- **Description**: The `fd_vm_shadow_t` structure is designed to store stack frame information that is not accessible from within a program. It contains a set of general-purpose registers (r6 to r10) and a program counter (pc), which are used to maintain the state of a stack frame in a virtual machine environment. This structure is crucial for managing the execution context of a program, especially in scenarios where stack frames need to be manipulated or inspected outside the program's direct control.


---
### fd\_vm\_input\_region
- **Type**: `struct`
- **Members**:
    - `vaddr_offset`: Represents offset from the start of the input region.
    - `haddr`: Host address corresponding to the start of the mem region.
    - `region_sz`: Size of the memory region.
    - `is_writable`: If the region can be written to or is read-only.
    - `is_acct_data`: Set if this is an account data region (either orig data or resize buffer).
- **Description**: The `fd_vm_input_region` structure is designed to manage fragmented memory regions within a larger input region for a virtual machine. It includes fields to specify the virtual address offset, host address, size of the memory region, and flags to indicate if the region is writable or if it contains account data. This structure is crucial for handling memory management in environments where memory regions are not contiguous and need to be accessed or modified based on specific permissions and characteristics.


---
### fd\_vm\_input\_region\_t
- **Type**: `struct`
- **Members**:
    - `vaddr_offset`: Represents offset from the start of the input region.
    - `haddr`: Host address corresponding to the start of the mem region.
    - `region_sz`: Size of the memory region.
    - `is_writable`: If the region can be written to or is read-only.
    - `is_acct_data`: Set if this is an account data region (either orig data or resize buffer).
- **Description**: The `fd_vm_input_region_t` structure is designed to manage fragmented memory regions within a larger input region, specifically for use in a virtual machine context. It includes fields to track the virtual address offset, host address, size, and properties of each memory region, such as whether it is writable or associated with account data. This structure is crucial for handling non-contiguous memory regions, allowing for efficient memory management and access control in virtualized environments.


---
### fd\_vm\_acc\_region\_meta
- **Type**: `struct`
- **Members**:
    - `region_idx`: An unsigned integer representing the index of the region.
    - `has_data_region`: An unsigned character indicating if the region has a data region.
    - `has_resizing_region`: An unsigned character indicating if the region has a resizing region.
    - `metadata_region_offset`: An unsigned long representing the offset of the accounts metadata region, relative to the start of the input region.
- **Description**: The `fd_vm_acc_region_meta` structure is designed to hold metadata about a specific account within a virtual machine's memory management system. It includes information about the region index, whether the region has associated data or resizing capabilities, and the offset of the metadata region relative to the input region. This structure is aligned to 8 bytes and is used to map an instruction account index to its corresponding input memory region location, excluding any duplicate account markers at the beginning of the full metadata region.


---
### fd\_vm\_acc\_region\_meta\_t
- **Type**: `struct`
- **Members**:
    - `region_idx`: Index of the memory region associated with the account.
    - `has_data_region`: Indicates if the account has an associated data region.
    - `has_resizing_region`: Indicates if the account has an associated resizing region.
    - `metadata_region_offset`: Offset of the account's metadata region relative to the start of the input region.
- **Description**: The `fd_vm_acc_region_meta_t` structure is designed to hold metadata about a specific account within a virtual machine's memory management system. It maps an instruction account index to its corresponding input memory region location, providing details such as the index of the region, whether the account has data or resizing regions, and the offset of the metadata region. This structure is crucial for managing and accessing account data efficiently within the virtual machine's input space.


---
### fd\_vm
- **Type**: `struct`
- **Members**:
    - `instr_ctx`: Pointer to the instruction context used by the VM.
    - `heap_max`: Maximum amount of heap memory in bytes.
    - `entry_cu`: Initial number of compute units for the program.
    - `rodata`: Pointer to the program's read-only data.
    - `rodata_sz`: Size of the read-only data in bytes.
    - `text`: Pointer to the program's sBPF instructions.
    - `text_cnt`: Number of sBPF instructions.
    - `text_off`: Relocation offset for indirect calls in bytes.
    - `text_sz`: Size of the sBPF program in bytes.
    - `entry_pc`: Initial program counter value.
    - `calldests`: Bit vector of callable local functions.
    - `syscalls`: Pointer to the map of syscalls.
    - `trace`: Pointer to the trace location for streaming execution traces.
    - `pc`: Current instruction pointer.
    - `ic`: Number of executed instructions.
    - `cu`: Remaining compute units for the transaction.
    - `frame_cnt`: Current number of stack frames pushed.
    - `heap_sz`: Current heap size in bytes.
    - `region_haddr`: Array of host addresses for VM memory regions.
    - `region_ld_sz`: Array of load sizes for VM memory regions.
    - `region_st_sz`: Array of store sizes for VM memory regions.
    - `input_mem_regions`: Pointer to an array of input memory regions.
    - `input_mem_regions_cnt`: Count of input memory regions.
    - `acc_region_metas`: Pointer to account region metadata.
    - `is_deprecated`: Flag indicating if the VM instance is deprecated.
    - `reg`: Array of VM registers.
    - `shadow`: Shadow stack for stack frame information.
    - `stack`: VM stack memory.
    - `heap`: VM heap memory.
    - `sha`: Pointer to a SHA instance for hashing.
    - `magic`: Magic number for VM validation.
    - `direct_mapping`: Flag indicating if direct memory mapping is enabled.
    - `stack_frame_size`: Size of a stack frame.
    - `segv_store_vaddr`: Virtual address causing a segmentation fault on store.
    - `sbpf_version`: Version of the sBPF being used.
- **Description**: The `fd_vm` structure represents a virtual machine capable of executing sBPF programs, providing a comprehensive configuration and state management for program execution. It includes fields for managing VM configuration, execution state, memory regions, and syscall handling. The structure is designed to handle complex memory mappings and execution diagnostics, supporting features like direct memory mapping and tracing. It also includes safety checks and alignment requirements to ensure proper execution and memory access, making it suitable for executing programs in a controlled and efficient manner.


# Functions

---
### fd\_vm\_is\_check\_align\_enabled<!-- {{#callable:fd_vm_is_check_align_enabled}} -->
The function `fd_vm_is_check_align_enabled` determines if alignment checks should be performed during memory translation for a given virtual machine instance.
- **Inputs**:
    - `vm`: A pointer to a constant `fd_vm_t` structure representing the virtual machine instance.
- **Control Flow**:
    - The function checks the `is_deprecated` field of the `fd_vm_t` structure pointed to by `vm`.
    - It returns the negation of the `is_deprecated` field, effectively returning 1 if `is_deprecated` is false and 0 if it is true.
- **Output**: An integer value, 1 if alignment checks are enabled (i.e., the VM is not deprecated), and 0 otherwise.


---
### fd\_vm\_is\_check\_size\_enabled<!-- {{#callable:fd_vm_is_check_size_enabled}} -->
The function `fd_vm_is_check_size_enabled` determines if size checks should be enabled for memory translation in a virtual machine.
- **Inputs**:
    - `vm`: A pointer to a constant `fd_vm_t` structure representing the virtual machine instance.
- **Control Flow**:
    - The function checks the `is_deprecated` field of the `fd_vm_t` structure pointed to by `vm`.
    - It returns the negation of the `is_deprecated` field, effectively returning 1 if `is_deprecated` is false and 0 if true.
- **Output**: An integer value, 1 if size checks should be enabled (i.e., the VM is not deprecated), and 0 otherwise.


---
### fd\_vm\_exec<!-- {{#callable:fd_vm_exec}} -->
The `fd_vm_exec` function executes a virtual machine (VM) either with or without tracing based on the VM's trace configuration.
- **Inputs**:
    - `vm`: A pointer to an `fd_vm_t` structure representing the virtual machine to be executed.
- **Control Flow**:
    - Check if the `trace` field of the `vm` structure is set (non-zero).
    - If `trace` is set, call `fd_vm_exec_trace(vm)` to execute the VM with tracing enabled.
    - If `trace` is not set, call `fd_vm_exec_notrace(vm)` to execute the VM without tracing.
- **Output**: Returns an integer status code indicating success (0) or an error code (negative) if execution fails.
- **Functions called**:
    - [`fd_vm_exec_trace`](fd_vm_interp.c.driver.md#fd_vm_exec_trace)
    - [`fd_vm_exec_notrace`](fd_vm_interp.c.driver.md#fd_vm_exec_notrace)


# Function Declarations (Public API)

---
### fd\_vm\_align<!-- {{#callable_declaration:fd_vm_align}} -->
Returns the alignment requirement for a virtual machine memory region.
- **Description**: Use this function to obtain the alignment requirement for a memory region that will hold a `fd_vm_t` structure. This is useful when allocating memory for a virtual machine to ensure that the memory is properly aligned according to the system's requirements. The alignment value is a constant and is a power of two, which facilitates compatibility with various memory allocation functions that require specific alignment.
- **Inputs**: None
- **Output**: The function returns an unsigned long integer representing the alignment requirement in bytes.
- **See also**: [`fd_vm_align`](fd_vm.c.driver.md#fd_vm_align)  (Implementation)


---
### fd\_vm\_footprint<!-- {{#callable_declaration:fd_vm_footprint}} -->
Returns the memory footprint required for a virtual machine instance.
- **Description**: Use this function to determine the amount of memory required to allocate for a virtual machine instance. This is useful for ensuring that memory allocations are appropriately sized before initializing or creating a virtual machine. The function does not require any parameters and can be called at any time to retrieve the constant footprint size.
- **Inputs**: None
- **Output**: Returns an unsigned long integer representing the memory footprint size in bytes.
- **See also**: [`fd_vm_footprint`](fd_vm.c.driver.md#fd_vm_footprint)  (Implementation)


---
### fd\_vm\_new<!-- {{#callable_declaration:fd_vm_new}} -->
Formats a memory region for a virtual machine.
- **Description**: This function prepares a memory region to hold a `fd_vm_t` structure, which represents a virtual machine capable of executing sBPF programs. It should be called with a pointer to a memory region that the caller owns and that meets the alignment and footprint requirements specified by `fd_vm_align()` and `fd_vm_footprint()`. The function returns the same pointer on success, indicating that the memory region is now formatted for use as a virtual machine. If the provided memory region is null or misaligned, the function logs a warning and returns null, indicating failure. The caller is not joined to the virtual machine upon return.
- **Inputs**:
    - `shmem`: A pointer to the first byte of the memory region to be formatted. The memory region must be aligned according to `fd_vm_align()` and have a size of at least `fd_vm_footprint()`. The caller retains ownership of the memory region. If null or misaligned, the function logs a warning and returns null.
- **Output**: Returns the input pointer `shmem` on success, or null on failure if the input is null or misaligned.
- **See also**: [`fd_vm_new`](fd_vm.c.driver.md#fd_vm_new)  (Implementation)


---
### fd\_vm\_join<!-- {{#callable_declaration:fd_vm_join}} -->
Joins a caller to a virtual machine using shared memory.
- **Description**: This function is used to join a caller to a virtual machine (VM) by providing a pointer to a shared memory region that holds the VM. It is essential to ensure that the shared memory is correctly aligned and initialized with the expected magic value before calling this function. If the shared memory is null, misaligned, or does not contain the correct magic value, the function will return null and log a warning. This function is typically called after the VM has been created and initialized, and it allows the caller to interact with the VM through a local handle.
- **Inputs**:
    - `shmem`: A pointer to the shared memory region that holds the VM. It must not be null, must be aligned according to the VM's alignment requirements, and must contain a VM with the correct magic value. If these conditions are not met, the function returns null and logs a warning.
- **Output**: Returns a local handle to the VM on success, or null on failure if the input conditions are not met.
- **See also**: [`fd_vm_join`](fd_vm.c.driver.md#fd_vm_join)  (Implementation)


---
### fd\_vm\_init<!-- {{#callable_declaration:fd_vm_init}} -->
Initializes a virtual machine for executing sBPF programs.
- **Description**: This function sets up a virtual machine (VM) for executing sBPF programs by initializing the provided `fd_vm_t` structure with the necessary configuration and state. It must be called with a valid `fd_vm_t` object that has been properly allocated and has the correct magic value. The function checks for valid input parameters and returns the initialized VM object on success or `NULL` on failure. It is essential to ensure that the VM and instruction context are not `NULL`, and that the heap size does not exceed the maximum allowed limit. This function prepares the VM for execution, but does not start the execution itself.
- **Inputs**:
    - `vm`: A pointer to an `fd_vm_t` structure that will be initialized. Must not be `NULL` and must have the correct magic value.
    - `instr_ctx`: A pointer to an `fd_exec_instr_ctx_t` structure representing the instruction context. Must not be `NULL`.
    - `heap_max`: The maximum heap size in bytes. Must not exceed `FD_VM_HEAP_MAX`.
    - `entry_cu`: The initial number of compute units for the program. Must be within valid limits.
    - `rodata`: A pointer to the read-only data for the program. Can be `NULL` if `rodata_sz` is zero.
    - `rodata_sz`: The size of the read-only data in bytes. Should match the size of the data pointed to by `rodata`.
    - `text`: A pointer to the program's sBPF instructions. Can be `NULL` if `text_cnt` is zero.
    - `text_cnt`: The number of sBPF instructions. Should match the number of instructions pointed to by `text`.
    - `text_off`: The relocation offset in bytes for indirect calls. Must be calculated correctly based on `text` and `rodata`.
    - `text_sz`: The size of the program's sBPF instructions in bytes. Should be `text_cnt * 8`.
    - `entry_pc`: The initial program counter. Must be within the range of valid instruction indices.
    - `calldests`: A pointer to a bit vector indicating callable local functions. Can be `NULL` if not used.
    - `sbpf_version`: The version of the sBPF to be used. Must be a valid version number.
    - `syscalls`: A pointer to an `fd_sbpf_syscalls_t` structure representing the syscall map. Can be `NULL` if no syscalls are used.
    - `trace`: A pointer to an `fd_vm_trace_t` structure for execution tracing. Can be `NULL` if tracing is not required.
    - `sha`: A pointer to an `fd_sha256_t` structure for SHA operations. Can be `NULL` if SHA operations are not required.
    - `mem_regions`: A pointer to an array of `fd_vm_input_region_t` structures representing input memory regions. Can be `NULL` if `mem_regions_cnt` is zero.
    - `mem_regions_cnt`: The number of input memory regions. Should match the number of regions pointed to by `mem_regions`.
    - `acc_region_metas`: A pointer to an array of `fd_vm_acc_region_meta_t` structures for account region metadata. Can be `NULL` if not used.
    - `is_deprecated`: A flag indicating if the VM is initialized by a deprecated program. Non-zero if deprecated.
    - `direct_mapping`: An integer flag indicating if direct mapping is enabled. Non-zero if enabled.
- **Output**: Returns a pointer to the initialized `fd_vm_t` structure on success, or `NULL` on failure.
- **See also**: [`fd_vm_init`](fd_vm.c.driver.md#fd_vm_init)  (Implementation)


---
### fd\_vm\_leave<!-- {{#callable_declaration:fd_vm_leave}} -->
Leaves the caller's current local join to a virtual machine.
- **Description**: This function is used to leave a previously joined virtual machine, represented by the `fd_vm_t` handle. It should be called when the caller no longer needs to interact with the virtual machine, effectively ending the session. The function returns a pointer to the memory region holding the virtual machine on success, allowing the caller to manage or deallocate the memory if needed. If the provided `vm` parameter is null, the function logs a warning and returns null, indicating failure. This function does not modify the virtual machine state or the memory region itself.
- **Inputs**:
    - `vm`: A pointer to an `fd_vm_t` structure representing the virtual machine to leave. Must not be null. If null, the function logs a warning and returns null.
- **Output**: Returns a pointer to the memory region holding the virtual machine on success, or null if the `vm` parameter is null.
- **See also**: [`fd_vm_leave`](fd_vm.c.driver.md#fd_vm_leave)  (Implementation)


---
### fd\_vm\_delete<!-- {{#callable_declaration:fd_vm_delete}} -->
Unformats a memory region holding a virtual machine.
- **Description**: Use this function to unformat a memory region that was previously formatted to hold a virtual machine (VM) instance. It should be called when the VM is no longer needed, and the memory region is to be reclaimed by the caller. The function requires that the memory region is not currently joined by any process. It checks for null pointers, proper alignment, and a valid magic number to ensure the memory region is a valid VM instance. If any of these checks fail, the function logs a warning and returns NULL.
- **Inputs**:
    - `shmem`: A pointer to the first byte of the memory region holding the VM. It must not be null, must be properly aligned according to fd_vm_align(), and must contain a valid VM instance with the correct magic number. The caller retains ownership of the memory region.
- **Output**: Returns a pointer to the memory region on success, allowing the caller to reclaim it. Returns NULL if the input is invalid or checks fail, with details logged as warnings.
- **See also**: [`fd_vm_delete`](fd_vm.c.driver.md#fd_vm_delete)  (Implementation)


---
### fd\_vm\_validate<!-- {{#callable_declaration:fd_vm_validate}} -->
Validates the sBPF program in the given virtual machine.
- **Description**: Use this function to validate the sBPF program associated with a virtual machine before execution. It checks the program's instructions for validity based on the sBPF version and other configuration parameters of the virtual machine. This function must be called before executing the program to ensure that all instructions are valid and that the program will not cause errors during execution. It returns an error code if any validation checks fail, indicating the type of validation error encountered.
- **Inputs**:
    - `vm`: A pointer to a constant fd_vm_t structure representing the virtual machine to validate. The structure must be properly initialized and must not be null. The function will return an error code if the validation fails.
- **Output**: Returns an integer indicating success or an error code if validation fails. The error code specifies the type of validation error encountered.
- **See also**: [`fd_vm_validate`](fd_vm.c.driver.md#fd_vm_validate)  (Implementation)


---
### fd\_vm\_setup\_state\_for\_execution<!-- {{#callable_declaration:fd_vm_setup_state_for_execution}} -->
Prepares a virtual machine for execution.
- **Description**: This function sets up the state of a virtual machine (VM) for execution by initializing its registers and setting its execution state. It should be called before executing any program on the VM to ensure that the VM is in a clean and ready state. The function requires a valid VM object and will return an error if the VM is null. It does not reset logs, so any previous log data will remain intact.
- **Inputs**:
    - `vm`: A pointer to an fd_vm_t structure representing the virtual machine. Must not be null. The caller retains ownership of the VM object. If null, the function logs a warning and returns an error code.
- **Output**: Returns FD_VM_SUCCESS (0) on successful setup, or FD_VM_ERR_INVAL if the VM pointer is null.
- **See also**: [`fd_vm_setup_state_for_execution`](fd_vm.c.driver.md#fd_vm_setup_state_for_execution)  (Implementation)


---
### fd\_vm\_exec\_trace<!-- {{#callable_declaration:fd_vm_exec_trace}} -->
Executes an sBPF program with execution and memory tracing enabled.
- **Description**: This function runs an sBPF program on the provided virtual machine instance with both execution and memory tracing enabled. It should be called when detailed tracing of the program's execution is required, which can be useful for debugging or performance analysis. The virtual machine must be properly initialized and configured before calling this function. If the virtual machine pointer is null, the function returns an error code indicating invalid input. The function returns a success code if the program executes without errors, or an appropriate error code if a fault occurs during execution.
- **Inputs**:
    - `vm`: A pointer to an initialized fd_vm_t structure representing the virtual machine. Must not be null. The function will return an error if this parameter is null.
- **Output**: Returns an integer status code: FD_VM_SUCCESS (0) on success, or a negative FD_VM_ERR code on failure, indicating the type of fault encountered during execution.
- **See also**: [`fd_vm_exec_trace`](fd_vm_interp.c.driver.md#fd_vm_exec_trace)  (Implementation)


---
### fd\_vm\_exec\_notrace<!-- {{#callable_declaration:fd_vm_exec_notrace}} -->
Executes an sBPF program on a virtual machine without tracing.
- **Description**: This function runs an sBPF program on the provided virtual machine instance without generating an execution trace, even if the virtual machine is configured to support tracing. It should be called when tracing is not required or desired. The function requires a valid, initialized `fd_vm_t` instance and will return an error code if the instance is null. The function returns a success code if the program executes without errors, or an appropriate error code if execution fails due to invalid instructions, memory access violations, or other runtime errors.
- **Inputs**:
    - `vm`: A pointer to an `fd_vm_t` instance representing the virtual machine. Must not be null. The virtual machine should be properly initialized before calling this function. If null, the function returns an error code.
- **Output**: Returns an integer status code: `FD_VM_SUCCESS` (0) on successful execution, or a negative error code indicating the type of failure encountered during execution.
- **See also**: [`fd_vm_exec_notrace`](fd_vm_interp.c.driver.md#fd_vm_exec_notrace)  (Implementation)



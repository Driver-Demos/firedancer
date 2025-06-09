# Purpose
The provided C header file, `fd_vm_base.h`, is part of a larger software system, likely related to a virtual machine (VM) implementation within the Firedancer project. This file primarily defines a comprehensive set of error codes, constants, and function prototypes that are essential for the operation and management of a virtual machine environment. The error codes are categorized into various types, including standard VM errors, execution errors, syscall errors, and specific errors related to sBPF (Solana's Berkeley Packet Filter) validation and execution. These codes facilitate error handling and debugging by providing standardized responses to different failure scenarios within the VM.

Additionally, the file outlines several constants related to the VM's operational limits, such as register counts, stack and heap sizes, and compute budgets. These constants are crucial for defining the resource constraints and operational parameters of the VM. The file also includes function prototypes for error string conversion, disassembly of instructions and programs, and tracing of VM events, which are vital for debugging and performance analysis. The inclusion of syscall registration functions suggests that the VM supports extensibility through custom syscalls, allowing for tailored functionality depending on the deployment context. Overall, this header file serves as a foundational component for managing VM operations, error handling, and resource constraints within the Firedancer project.
# Imports and Dependencies

---
- `../fd_flamenco_base.h`
- `../../ballet/sbpf/fd_sbpf_loader.h`
- `../features/fd_features.h`


# Global Variables

---
### fd\_vm\_strerror
- **Type**: ``char const *``
- **Description**: The `fd_vm_strerror` function is a constant function that takes an integer error code as input and returns a constant character pointer to a human-readable string describing the error. The error codes are defined as macros, such as `FD_VM_SUCCESS` and various `FD_VM_ERR_*` codes, which represent different success and error states in the Firedancer virtual machine.
- **Use**: This function is used to convert error codes into descriptive strings for easier debugging and logging.


---
### fd\_vm\_trace\_new
- **Type**: `function pointer`
- **Description**: `fd_vm_trace_new` is a function that initializes a new virtual machine trace object in shared memory. It takes three parameters: a pointer to shared memory (`shmem`), the maximum number of bytes for event storage (`event_max`), and the maximum number of bytes to capture per data event (`event_data_max`).
- **Use**: This function is used to allocate and set up a new trace object for capturing and storing virtual machine events.


---
### fd\_vm\_trace\_join
- **Type**: `fd_vm_trace_t *`
- **Description**: The `fd_vm_trace_join` function is a global function that returns a pointer to an `fd_vm_trace_t` structure. This function is used to join a trace object, which is likely stored in shared memory, allowing the caller to interact with the trace data.
- **Use**: This function is used to obtain a pointer to an `fd_vm_trace_t` structure, enabling the caller to access and manipulate trace events.


---
### fd\_vm\_trace\_leave
- **Type**: `function pointer`
- **Description**: `fd_vm_trace_leave` is a function that takes a pointer to an `fd_vm_trace_t` structure and returns a void pointer. This function is likely used to handle the process of leaving or detaching from a trace session in a virtual machine context.
- **Use**: This function is used to manage the lifecycle of a trace session by detaching from the current trace, potentially cleaning up resources or finalizing the trace data.


---
### fd\_vm\_trace\_delete
- **Type**: `function pointer`
- **Description**: `fd_vm_trace_delete` is a function pointer that takes a single argument, a void pointer `_trace`, and returns a void pointer. This function is likely used to delete or clean up a trace object in a virtual machine context.
- **Use**: This function is used to delete a trace object, freeing any associated resources.


# Data Structures

---
### fd\_vm\_trace\_event\_exe
- **Type**: `struct`
- **Members**:
    - `info`: Event info bit field.
    - `pc`: Program counter.
    - `ic`: Instruction counter.
    - `cu`: Compute units.
    - `ic_correction`: Instruction counter correction.
    - `frame_cnt`: Frame count.
    - `reg`: Array of registers with size FD_VM_REG_CNT.
    - `text`: Array of two ulong elements, used for text storage if the event has valid clear.
- **Description**: The `fd_vm_trace_event_exe` structure is designed to capture and store detailed information about a virtual machine execution event. It includes fields for tracking the program counter, instruction counter, compute units, and frame count, as well as an array for register values and a text array for additional event-specific data. This structure is aligned to 8 bytes for efficient memory access and is used within a tracing system to log execution events in a virtual machine environment.


---
### fd\_vm\_trace\_event\_exe\_t
- **Type**: `struct`
- **Members**:
    - `info`: Event info bit field.
    - `pc`: Program counter.
    - `ic`: Instruction count.
    - `cu`: Compute units.
    - `ic_correction`: Instruction count correction.
    - `frame_cnt`: Frame count.
    - `reg`: Array of registers with size FD_VM_REG_CNT.
    - `text`: Array of two ulong values representing instruction text.
- **Description**: The `fd_vm_trace_event_exe_t` structure is used to record execution trace events in a virtual machine environment. It captures detailed information about the state of the VM at a specific point in time, including the program counter, instruction count, compute units, and register states. This structure is essential for debugging and performance analysis, as it provides a snapshot of the VM's execution context, allowing developers to trace and understand the behavior of their programs.


---
### fd\_vm\_trace\_event\_mem
- **Type**: `struct`
- **Members**:
    - `info`: Event info bit field.
    - `vaddr`: VM address range associated with event.
    - `sz`: Size of the memory range associated with the event.
- **Description**: The `fd_vm_trace_event_mem` structure is used to represent a memory-related event in a virtual machine trace. It contains information about the event, such as the event type and validity (stored in the `info` field), the virtual memory address range associated with the event (`vaddr`), and the size of the memory range (`sz`). This structure is aligned to 8 bytes, and if the event has valid data, it may include user data bytes up to a maximum size, with padding to maintain alignment.


---
### fd\_vm\_trace\_event\_mem\_t
- **Type**: `struct`
- **Members**:
    - `info`: Event info bit field.
    - `vaddr`: VM address range associated with the event.
    - `sz`: Size of the memory range involved in the event.
- **Description**: The `fd_vm_trace_event_mem_t` structure is used to represent memory-related trace events in a virtual machine environment. It contains fields to store information about the event, such as the type and validity of the event (`info`), the virtual memory address range involved (`vaddr`), and the size of the memory range (`sz`). This structure is part of a tracing mechanism that records memory access attempts, either reads or writes, within the virtual machine, and can capture user data associated with these events if available.


---
### fd\_vm\_trace
- **Type**: `struct`
- **Members**:
    - `magic`: A magic number used to identify the structure, set to FD_VM_TRACE_MAGIC.
    - `event_max`: The maximum number of bytes allocated for event storage.
    - `event_data_max`: The maximum number of bytes that can be captured per data event.
    - `event_sz`: The number of bytes currently used in the event storage.
- **Description**: The `fd_vm_trace` structure is designed to manage and store trace events for a virtual machine. It includes fields to define the maximum storage capacity for events (`event_max`) and the maximum data size for individual events (`event_data_max`). The `magic` field is used to verify the integrity and version of the structure, while `event_sz` keeps track of the current usage of the event storage. This structure is crucial for capturing and analyzing the execution and memory access events within the virtual machine, facilitating debugging and performance analysis.


---
### fd\_vm\_trace\_t
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the trace structure, set to FD_VM_TRACE_MAGIC.
    - `event_max`: The maximum number of bytes allocated for event storage.
    - `event_data_max`: The maximum number of bytes that can be captured per data event.
    - `event_sz`: The number of bytes currently used in the event storage.
- **Description**: The `fd_vm_trace_t` structure is used to manage and store trace events for a virtual machine. It includes fields to define the maximum storage capacity for events (`event_max`) and the maximum data size per event (`event_data_max`). The `magic` field is used to verify the integrity and version of the trace structure, while `event_sz` keeps track of the current usage of the event storage. This structure is essential for capturing and analyzing execution and memory access events within the virtual machine.


# Functions

---
### fd\_vm\_trace\_event<!-- {{#callable:fd_vm_trace_event}} -->
The `fd_vm_trace_event` function returns a pointer to the memory location where trace events are stored for a given trace object.
- **Inputs**:
    - `trace`: A pointer to a constant `fd_vm_trace_t` structure, representing the trace object from which the event storage location is to be retrieved.
- **Control Flow**:
    - The function takes a single input parameter, `trace`, which is a pointer to a `fd_vm_trace_t` structure.
    - It calculates the memory location immediately following the `fd_vm_trace_t` structure by incrementing the pointer `trace` by one.
    - The function returns this calculated memory location as a `void` pointer.
- **Output**: A `void` pointer to the memory location where trace events are stored, which is immediately after the `fd_vm_trace_t` structure in memory.


---
### fd\_vm\_trace\_event\_sz<!-- {{#callable:fd_vm_trace_event_sz}} -->
The `fd_vm_trace_event_sz` function returns the number of bytes currently used for trace events in a given `fd_vm_trace_t` structure.
- **Inputs**:
    - `trace`: A pointer to a constant `fd_vm_trace_t` structure, which contains information about the trace events.
- **Control Flow**:
    - The function is a simple inline function that directly accesses the `event_sz` member of the `fd_vm_trace_t` structure pointed to by `trace`.
- **Output**: The function returns an `ulong` representing the number of bytes of trace events currently stored.


---
### fd\_vm\_trace\_event\_max<!-- {{#callable:fd_vm_trace_event_max}} -->
The `fd_vm_trace_event_max` function retrieves the maximum number of bytes allocated for event storage in a given trace object.
- **Inputs**:
    - `trace`: A pointer to a constant `fd_vm_trace_t` structure representing the trace object from which the maximum event storage size is to be retrieved.
- **Control Flow**:
    - The function is defined as a static inline function, which suggests it is intended for use within the same translation unit and optimized for performance.
    - It directly accesses the `event_max` member of the `fd_vm_trace_t` structure pointed to by the `trace` argument.
    - The function returns the value of `trace->event_max` without any additional computation or error checking.
- **Output**: The function returns an `ulong` representing the maximum number of bytes allocated for event storage in the trace object.


---
### fd\_vm\_trace\_event\_data\_max<!-- {{#callable:fd_vm_trace_event_data_max}} -->
The `fd_vm_trace_event_data_max` function retrieves the maximum number of bytes that can be captured per data event from a given trace object.
- **Inputs**:
    - `trace`: A pointer to a constant `fd_vm_trace_t` structure, which contains information about the trace, including event data limits.
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests a performance optimization by the compiler.
    - It directly accesses the `event_data_max` field of the `fd_vm_trace_t` structure pointed to by the `trace` argument.
    - The function returns the value of `event_data_max`, which indicates the maximum bytes of data that can be captured per event.
- **Output**: The function returns an `ulong` representing the maximum number of bytes that can be captured per data event in the trace.


---
### fd\_vm\_trace\_event\_info<!-- {{#callable:fd_vm_trace_event_info}} -->
The `fd_vm_trace_event_info` function encodes event type and validity into a single unsigned long integer.
- **Inputs**:
    - `type`: An integer representing the event type, expected to be one of the FD_VM_TRACE_EVENT_TYPE_* constants.
    - `valid`: An integer indicating the validity of the event, expected to be either 0 or 1.
- **Control Flow**:
    - The function shifts the 'valid' integer left by 2 bits.
    - It performs a bitwise OR operation between the shifted 'valid' value and the 'type' value.
    - The result is cast to an unsigned long integer and returned.
- **Output**: An unsigned long integer that encodes the event type and validity information.


---
### fd\_vm\_trace\_event\_info\_type<!-- {{#callable:fd_vm_trace_event_info_type}} -->
The `fd_vm_trace_event_info_type` function extracts the event type from a given event info bit field.
- **Inputs**:
    - `info`: An unsigned long integer representing the event info bit field from which the event type is to be extracted.
- **Control Flow**:
    - The function takes a single input parameter `info` of type `ulong`.
    - It performs a bitwise AND operation between `info` and `3UL` to isolate the two least significant bits.
    - The result of the bitwise operation is cast to an `int` and returned as the event type.
- **Output**: The function returns an integer representing the event type, which is derived from the two least significant bits of the `info` parameter.


---
### fd\_vm\_trace\_event\_info\_valid<!-- {{#callable:fd_vm_trace_event_info_valid}} -->
The `fd_vm_trace_event_info_valid` function extracts the validity bit from a trace event's info field by right-shifting the input value by two bits.
- **Inputs**:
    - `info`: An unsigned long integer representing the event info bit field from which the validity bit is to be extracted.
- **Control Flow**:
    - The function takes an unsigned long integer `info` as input.
    - It performs a right bitwise shift operation on `info` by 2 bits.
    - The result of the shift operation is cast to an integer and returned.
- **Output**: The function returns an integer representing the validity bit extracted from the input `info`, which is either 0 or 1.


---
### fd\_vm\_trace\_reset<!-- {{#callable:fd_vm_trace_reset}} -->
The `fd_vm_trace_reset` function resets the event size of a virtual machine trace to zero, effectively clearing all recorded events.
- **Inputs**:
    - `trace`: A pointer to an `fd_vm_trace_t` structure, which represents the trace object to be reset.
- **Control Flow**:
    - Check if the `trace` pointer is NULL using the `FD_UNLIKELY` macro.
    - If `trace` is NULL, return the error code `FD_VM_ERR_INVAL`.
    - If `trace` is not NULL, set the `event_sz` field of the `trace` structure to 0, indicating that no events are currently recorded.
    - Return `FD_VM_SUCCESS` to indicate the operation was successful.
- **Output**: Returns `FD_VM_SUCCESS` (0) on success, or `FD_VM_ERR_INVAL` (-1) if the `trace` pointer is NULL.


---
### fd\_vm\_syscall\_register\_all<!-- {{#callable:fd_vm_syscall_register_all}} -->
The `fd_vm_syscall_register_all` function registers all available syscalls for a given deployment context.
- **Inputs**:
    - `syscalls`: A pointer to an `fd_sbpf_syscalls_t` structure where the syscalls will be registered.
    - `is_deploy`: An unsigned char indicating whether the syscalls are being registered for deployment (1) or execution (0).
- **Control Flow**:
    - The function calls [`fd_vm_syscall_register_slot`](syscall/fd_vm_syscall.c.driver.md#fd_vm_syscall_register_slot) with the provided `syscalls`, a slot value of `0UL`, `NULL` for features, and the `is_deploy` flag.
    - The function returns the result of the [`fd_vm_syscall_register_slot`](syscall/fd_vm_syscall.c.driver.md#fd_vm_syscall_register_slot) call.
- **Output**: The function returns an integer status code, where `FD_VM_SUCCESS` (0) indicates success and negative values indicate various error conditions.
- **Functions called**:
    - [`fd_vm_syscall_register_slot`](syscall/fd_vm_syscall.c.driver.md#fd_vm_syscall_register_slot)


# Function Declarations (Public API)

---
### fd\_vm\_strerror<!-- {{#callable_declaration:fd_vm_strerror}} -->
Convert an error code to a human-readable string.
- **Description**: Use this function to obtain a descriptive string for a given error code related to Firedancer VM operations. It is useful for logging or displaying error messages to users. The function accepts both standard Firedancer error codes and VM-specific error codes, returning a constant string that describes the error. If the error code is not recognized, it returns a generic "UNKNOWN" message. The returned string is always non-null and has an infinite lifetime.
- **Inputs**:
    - `err`: An integer representing the error code. It can be any of the defined Firedancer error codes or VM-specific error codes. If the code is not recognized, the function returns a generic "UNKNOWN" message.
- **Output**: A constant string describing the error associated with the provided error code.
- **See also**: [`fd_vm_strerror`](fd_vm.c.driver.md#fd_vm_strerror)  (Implementation)


---
### fd\_vm\_disasm\_instr<!-- {{#callable_declaration:fd_vm_disasm_instr}} -->
Disassembles a single sBPF instruction into a human-readable format.
- **Description**: Use this function to convert a single sBPF instruction into a human-readable string format, which is appended to the provided output buffer. This function is useful for debugging or analyzing sBPF programs. Ensure that the output buffer has enough space to accommodate the disassembled instruction, and that the initial length of the buffer is correctly set in `_out_len`. The function requires valid input parameters and will return an error code if any parameter is invalid or if the output buffer is insufficiently sized.
- **Inputs**:
    - `text`: A pointer to the array of instruction words to be disassembled. Must not be null and should have at least `text_cnt` elements.
    - `text_cnt`: The number of instruction words available in `text`. Must be greater than zero.
    - `pc`: The program counter corresponding to the first instruction in `text`. Used for disassembly context.
    - `syscalls`: A pointer to a syscall mapping structure. Can be null if syscall annotation is not needed.
    - `out`: A pointer to the output buffer where the disassembled instruction will be appended. Must not be null and should have a size of at least `out_max`.
    - `out_max`: The maximum number of bytes that can be written to the `out` buffer. Must be greater than zero.
    - `_out_len`: A pointer to the current length of the string in `out`. Must not be null and should be less than `out_max` on entry.
- **Output**: Returns `FD_VM_SUCCESS` on successful disassembly, updating the `out` buffer and `_out_len`. Returns `FD_VM_ERR_INVAL` for invalid inputs or if `_out_len` is not less than `out_max` on entry.
- **See also**: [`fd_vm_disasm_instr`](fd_vm_disasm.c.driver.md#fd_vm_disasm_instr)  (Implementation)


---
### fd\_vm\_disasm\_program<!-- {{#callable_declaration:fd_vm_disasm_program}} -->
Disassembles an sBPF program into a human-readable format.
- **Description**: This function is used to convert a sequence of sBPF instructions into a human-readable format, appending the disassembled output to a provided buffer. It is useful for debugging or analyzing sBPF programs. The function requires a valid instruction sequence and a sufficiently large output buffer. It handles various edge cases, such as truncated instructions and unsupported numbers of functions or labels, by returning specific error codes. The function must be called with valid parameters, and the output buffer must have enough space to accommodate the disassembled text.
- **Inputs**:
    - `text`: A pointer to an array of ulong representing the sBPF instructions to disassemble. Must not be null if text_cnt is non-zero.
    - `text_cnt`: The number of instructions in the text array. Must be non-zero if text is not null.
    - `syscalls`: A pointer to a syscall mapping structure used to annotate syscalls in the disassembly. Can be null if no annotation is needed.
    - `out`: A pointer to a character buffer where the disassembled output will be written. Must not be null.
    - `out_max`: The maximum number of bytes that can be written to the out buffer. Must be greater than zero.
    - `_out_len`: A pointer to a ulong that holds the current length of the string in the out buffer. Must not be null and should be less than out_max.
- **Output**: Returns FD_VM_SUCCESS on success, or a negative error code on failure, such as FD_VM_ERR_INVAL for invalid input or FD_VM_ERR_UNSUP for unsupported features.
- **See also**: [`fd_vm_disasm_program`](fd_vm_disasm.c.driver.md#fd_vm_disasm_program)  (Implementation)


---
### fd\_vm\_trace\_align<!-- {{#callable_declaration:fd_vm_trace_align}} -->
Returns the alignment requirement for trace events.
- **Description**: This function provides the alignment requirement for trace events, which is essential for ensuring that memory operations related to trace events are performed correctly and efficiently. It is typically used when setting up or managing memory for trace events in a virtual machine environment. This function does not require any prior initialization and can be called at any time to retrieve the alignment value.
- **Inputs**: None
- **Output**: Returns an unsigned long integer representing the alignment requirement, which is 8.
- **See also**: [`fd_vm_trace_align`](fd_vm_trace.c.driver.md#fd_vm_trace_align)  (Implementation)


---
### fd\_vm\_trace\_footprint<!-- {{#callable_declaration:fd_vm_trace_footprint}} -->
Calculate the memory footprint required for a trace object.
- **Description**: This function calculates the memory footprint needed to store a trace object, given the maximum number of events and the maximum data size per event. It is useful for determining the amount of memory to allocate for tracing virtual machine events. The function should be called with valid parameters before allocating memory for a trace object. If either parameter exceeds 1 EiB, the function returns 0, indicating an invalid request.
- **Inputs**:
    - `event_max`: The maximum number of bytes for event storage. Must be less than or equal to 1 EiB. If greater, the function returns 0.
    - `event_data_max`: The maximum number of bytes that can be captured per event. Must be less than or equal to 1 EiB. If greater, the function returns 0.
- **Output**: Returns the aligned size in bytes required for the trace object, or 0 if the input parameters are invalid.
- **See also**: [`fd_vm_trace_footprint`](fd_vm_trace.c.driver.md#fd_vm_trace_footprint)  (Implementation)


---
### fd\_vm\_trace\_new<!-- {{#callable_declaration:fd_vm_trace_new}} -->
Creates a new trace object in shared memory.
- **Description**: This function initializes a trace object in the provided shared memory region, setting it up to record a specified maximum number of events and event data. It should be called with a properly aligned shared memory pointer and valid event limits. The function will return a pointer to the initialized trace object or NULL if any preconditions are not met, such as a NULL or misaligned shared memory pointer, or invalid event limits.
- **Inputs**:
    - `shmem`: A pointer to the shared memory region where the trace object will be created. Must not be NULL and must be aligned according to fd_vm_trace_align(). The caller retains ownership.
    - `event_max`: The maximum number of bytes allocated for event storage. Must be a valid value that allows fd_vm_trace_footprint() to return a non-zero footprint.
    - `event_data_max`: The maximum number of bytes that can be captured per event. Must be a valid value that allows fd_vm_trace_footprint() to return a non-zero footprint.
- **Output**: Returns a pointer to the initialized trace object on success, or NULL if the input parameters are invalid or the shared memory is misaligned.
- **See also**: [`fd_vm_trace_new`](fd_vm_trace.c.driver.md#fd_vm_trace_new)  (Implementation)


---
### fd\_vm\_trace\_join<!-- {{#callable_declaration:fd_vm_trace_join}} -->
Validates and joins a trace object.
- **Description**: This function is used to validate and join a trace object represented by a pointer. It should be called when you have a trace object that you want to work with, ensuring that the object is valid and properly aligned. The function checks for null pointers, alignment, and a magic number to confirm the trace object's integrity. If any of these checks fail, it returns NULL, indicating an invalid trace object. This function is typically used in environments where trace objects are shared or passed around, and validation is necessary before use.
- **Inputs**:
    - `_trace`: A pointer to a trace object. It must not be null, must be aligned according to fd_vm_trace_align(), and must have a valid magic number. If these conditions are not met, the function returns NULL.
- **Output**: Returns a pointer to the validated trace object if successful, or NULL if the validation fails.
- **See also**: [`fd_vm_trace_join`](fd_vm_trace.c.driver.md#fd_vm_trace_join)  (Implementation)


---
### fd\_vm\_trace\_leave<!-- {{#callable_declaration:fd_vm_trace_leave}} -->
Leaves a trace session and returns a pointer to the trace object.
- **Description**: Use this function to leave a trace session that was previously joined. It should be called when tracing is no longer needed, allowing for any necessary cleanup or finalization of the trace session. This function must be called with a valid trace object that was previously joined. If the trace parameter is null, the function logs a warning and returns null, indicating that no action was taken.
- **Inputs**:
    - `trace`: A pointer to a fd_vm_trace_t object representing the trace session to leave. Must not be null. If null, a warning is logged and null is returned.
- **Output**: Returns a pointer to the trace object if successful, or null if the trace parameter is null.
- **See also**: [`fd_vm_trace_leave`](fd_vm_trace.c.driver.md#fd_vm_trace_leave)  (Implementation)


---
### fd\_vm\_trace\_delete<!-- {{#callable_declaration:fd_vm_trace_delete}} -->
Deletes a trace object if it is valid and properly aligned.
- **Description**: Use this function to safely delete a trace object that was previously created and is no longer needed. The function checks if the provided trace object is non-null, properly aligned, and has a valid magic number before deleting it. If any of these conditions are not met, the function logs a warning and returns null. This function should be called when you are sure that the trace object is no longer in use and you want to free its resources.
- **Inputs**:
    - `_trace`: A pointer to the trace object to be deleted. It must not be null, must be aligned according to fd_vm_trace_align(), and must have a valid magic number. If these conditions are not met, the function logs a warning and returns null.
- **Output**: Returns a pointer to the deleted trace object if successful, or null if the trace object was invalid or misaligned.
- **See also**: [`fd_vm_trace_delete`](fd_vm_trace.c.driver.md#fd_vm_trace_delete)  (Implementation)


---
### fd\_vm\_trace\_printf<!-- {{#callable_declaration:fd_vm_trace_printf}} -->
Pretty prints the current trace to stdout.
- **Description**: Use this function to output a human-readable representation of the current trace events to the standard output. It is useful for debugging or logging purposes to understand the sequence of events captured in the trace. The function requires a valid trace object and optionally a syscalls mapping to annotate syscall names in the disassembly. It returns a success code if the operation completes successfully, or an error code if the trace is null or if there is an input-output error due to corrupted trace events.
- **Inputs**:
    - `trace`: A pointer to a constant fd_vm_trace_t object representing the trace to be printed. Must not be null. If null, the function returns FD_VM_ERR_INVAL.
    - `syscalls`: A pointer to a constant fd_sbpf_syscalls_t object representing the syscall mapping for annotating syscalls in the disassembly. Can be null, in which case no syscall annotations will be made.
- **Output**: Returns FD_VM_SUCCESS on success, or an error code such as FD_VM_ERR_INVAL if the trace is null, or FD_VM_ERR_IO if there is a corruption detected in the trace events.
- **See also**: [`fd_vm_trace_printf`](fd_vm_trace.c.driver.md#fd_vm_trace_printf)  (Implementation)


---
### fd\_vm\_syscall\_register<!-- {{#callable_declaration:fd_vm_syscall_register}} -->
Registers a syscall with a given name and function.
- **Description**: Use this function to add a new syscall to the provided syscall map, associating it with a specified name and function. This function should be called when you need to extend the syscall capabilities of a virtual machine. Ensure that the `syscalls` and `name` parameters are not null before calling this function. The function will return an error if the name or its hash is already present in the map, or if the inputs are invalid. On success, the syscall map retains a read-only reference to the name, so it should have an infinite lifetime.
- **Inputs**:
    - `syscalls`: A pointer to the syscall map where the new syscall will be registered. Must not be null. The caller retains ownership.
    - `name`: A constant character string representing the name of the syscall. Must not be null and should have an infinite lifetime as the syscall map retains a read-only reference.
    - `func`: A function pointer to the syscall implementation. Can be null, but the virtual machine may not accept it as valid.
- **Output**: Returns FD_VM_SUCCESS (0) on success, or FD_VM_ERR_INVAL (-1) if the inputs are invalid or the name is already in the map.
- **See also**: [`fd_vm_syscall_register`](syscall/fd_vm_syscall.c.driver.md#fd_vm_syscall_register)  (Implementation)


---
### fd\_vm\_syscall\_register\_slot<!-- {{#callable_declaration:fd_vm_syscall_register_slot}} -->
Registers syscalls for a specified slot and feature set.
- **Description**: This function registers a set of syscalls for a given slot and feature set, clearing any previously registered syscalls. It should be used when configuring the syscall environment for a specific execution context, such as deploying or executing programs. The function requires a valid syscalls object and can handle different configurations based on the slot and feature set provided. If the slot is zero, all syscalls are enabled. The function returns an error code if the syscalls object is null or if the syscall map is full.
- **Inputs**:
    - `syscalls`: A pointer to an fd_sbpf_syscalls_t object where the syscalls will be registered. Must not be null.
    - `slot`: An unsigned long representing the slot for which syscalls are being registered. If zero, all syscalls are enabled.
    - `features`: A pointer to an fd_features_t object that specifies which features are active for the given slot. Can be null if slot is zero.
    - `is_deploy`: An unsigned char indicating whether the syscalls are being registered for deployment (1) or execution (0).
- **Output**: Returns FD_VM_SUCCESS (0) on success, or a negative error code on failure, such as FD_VM_ERR_INVAL for invalid input or FD_VM_ERR_FULL if the syscall map is full.
- **See also**: [`fd_vm_syscall_register_slot`](syscall/fd_vm_syscall.c.driver.md#fd_vm_syscall_register_slot)  (Implementation)



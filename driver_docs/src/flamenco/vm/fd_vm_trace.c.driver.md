# Purpose
This C source code file is designed to manage and manipulate a virtual machine (VM) trace system, which is used to record and analyze events occurring during the execution of a virtual machine. The file provides a set of functions that handle the creation, joining, leaving, and deletion of trace objects, as well as recording execution and memory events. The primary data structure used is `fd_vm_trace_t`, which stores information about the maximum number of events and data size, and tracks the current size of recorded events. The code ensures memory alignment and integrity through checks and uses a magic number to validate trace objects.

The file includes functions for recording execution ([`fd_vm_trace_event_exe`](#fd_vm_trace_event_exe)) and memory events ([`fd_vm_trace_event_mem`](#fd_vm_trace_event_mem)), which capture details such as program counter, instruction count, and register states for execution events, and virtual address, size, and data for memory events. Additionally, the [`fd_vm_trace_printf`](#fd_vm_trace_printf) function provides a mechanism to print the recorded events in a human-readable format, facilitating debugging and analysis. The code is structured to handle potential errors and misalignments gracefully, logging warnings and returning error codes when issues are detected. This file is likely part of a larger system, providing a focused API for VM trace management and event logging.
# Imports and Dependencies

---
- `fd_vm_private.h`
- `stdio.h`


# Functions

---
### fd\_vm\_trace\_align<!-- {{#callable:fd_vm_trace_align}} -->
The `fd_vm_trace_align` function returns the alignment requirement for a virtual machine trace, which is 8 bytes.
- **Inputs**: None
- **Control Flow**:
    - The function is defined to return an unsigned long integer.
    - It directly returns the constant value 8UL, indicating an 8-byte alignment requirement.
- **Output**: The function returns an unsigned long integer representing the alignment requirement, which is 8 bytes.


---
### fd\_vm\_trace\_footprint<!-- {{#callable:fd_vm_trace_footprint}} -->
The `fd_vm_trace_footprint` function calculates the memory footprint required for a trace structure based on the maximum number of events and event data.
- **Inputs**:
    - `event_max`: The maximum number of events that the trace can store.
    - `event_data_max`: The maximum size of event data that the trace can handle.
- **Control Flow**:
    - Check if either `event_max` or `event_data_max` exceeds the limit of `1UL<<60`; if so, return 0UL as an error condition.
    - Calculate the footprint by aligning the sum of the size of `fd_vm_trace_t` and `event_max` to an 8-byte boundary using `fd_ulong_align_up`.
    - Return the calculated aligned footprint.
- **Output**: The function returns the aligned memory footprint required for the trace structure, or 0UL if the input values exceed the specified limits.


---
### fd\_vm\_trace\_new<!-- {{#callable:fd_vm_trace_new}} -->
The `fd_vm_trace_new` function initializes a new virtual machine trace structure in shared memory, setting up its parameters and ensuring proper alignment and size.
- **Inputs**:
    - `shmem`: A pointer to the shared memory where the trace structure will be initialized.
    - `event_max`: The maximum number of events that the trace can store.
    - `event_data_max`: The maximum size of event data that can be stored in the trace.
- **Control Flow**:
    - Cast the `shmem` pointer to a `fd_vm_trace_t` pointer named `trace`.
    - Check if `trace` is NULL and log a warning if so, returning NULL.
    - Verify that `shmem` is aligned according to `fd_vm_trace_align()` and log a warning if not, returning NULL.
    - Calculate the memory footprint required using `fd_vm_trace_footprint()` and log a warning if the footprint is zero, returning NULL.
    - Initialize the memory pointed to by `trace` to zero using `memset`.
    - Set `trace->event_max` to `event_max`, `trace->event_data_max` to `event_data_max`, and `trace->event_sz` to 0.
    - Use memory fences (`FD_COMPILER_MFENCE`) to ensure memory operations are completed before setting `trace->magic` to `FD_VM_TRACE_MAGIC`.
    - Return the initialized `trace` pointer.
- **Output**: A pointer to the initialized `fd_vm_trace_t` structure, or NULL if initialization fails due to invalid input or alignment issues.
- **Functions called**:
    - [`fd_vm_trace_align`](#fd_vm_trace_align)
    - [`fd_vm_trace_footprint`](#fd_vm_trace_footprint)


---
### fd\_vm\_trace\_join<!-- {{#callable:fd_vm_trace_join}} -->
The `fd_vm_trace_join` function validates and returns a pointer to a `fd_vm_trace_t` structure if it is correctly aligned and has the correct magic number.
- **Inputs**:
    - `_trace`: A void pointer to a `fd_vm_trace_t` structure that needs to be validated and joined.
- **Control Flow**:
    - Cast the input `_trace` to a `fd_vm_trace_t` pointer named `trace`.
    - Check if `trace` is NULL; if so, log a warning and return NULL.
    - Check if `trace` is not aligned according to [`fd_vm_trace_align`](#fd_vm_trace_align); if misaligned, log a warning and return NULL.
    - Check if `trace->magic` does not equal `FD_VM_TRACE_MAGIC`; if not, log a warning and return NULL.
    - If all checks pass, return the `trace` pointer.
- **Output**: Returns a pointer to the `fd_vm_trace_t` structure if all validations pass, otherwise returns NULL.
- **Functions called**:
    - [`fd_vm_trace_align`](#fd_vm_trace_align)


---
### fd\_vm\_trace\_leave<!-- {{#callable:fd_vm_trace_leave}} -->
The `fd_vm_trace_leave` function checks if a given trace pointer is valid and returns it as a void pointer if it is, or logs a warning and returns NULL if it is not.
- **Inputs**:
    - `trace`: A pointer to an `fd_vm_trace_t` structure, which represents a trace object to be validated and returned.
- **Control Flow**:
    - Check if the `trace` pointer is NULL using `FD_UNLIKELY`; if it is, log a warning message 'NULL trace' and return NULL.
    - If the `trace` pointer is not NULL, cast it to a void pointer and return it.
- **Output**: Returns the input `trace` pointer cast to a void pointer if it is not NULL; otherwise, returns NULL.


---
### fd\_vm\_trace\_delete<!-- {{#callable:fd_vm_trace_delete}} -->
The `fd_vm_trace_delete` function validates and deletes a virtual machine trace by resetting its magic number to zero.
- **Inputs**:
    - `_trace`: A pointer to the trace object to be deleted, expected to be of type `fd_vm_trace_t`.
- **Control Flow**:
    - Cast the input `_trace` to a `fd_vm_trace_t` pointer named `trace`.
    - Check if `trace` is NULL; if so, log a warning and return NULL.
    - Check if `trace` is not aligned according to [`fd_vm_trace_align`](#fd_vm_trace_align); if misaligned, log a warning and return NULL.
    - Check if `trace->magic` does not match `FD_VM_TRACE_MAGIC`; if not, log a warning and return NULL.
    - Use memory fence operations to ensure memory ordering and set `trace->magic` to 0, effectively marking it as deleted.
    - Return the `trace` pointer cast back to `void *`.
- **Output**: Returns a pointer to the deleted trace object if successful, or NULL if any validation checks fail.
- **Functions called**:
    - [`fd_vm_trace_align`](#fd_vm_trace_align)


---
### fd\_vm\_trace\_event\_exe<!-- {{#callable:fd_vm_trace_event_exe}} -->
The `fd_vm_trace_event_exe` function records an execution event in a virtual machine trace, storing details about the program counter, instruction count, computational units, registers, and instruction text.
- **Inputs**:
    - `trace`: A pointer to an `fd_vm_trace_t` structure where the event will be recorded.
    - `pc`: The program counter value at the time of the event.
    - `ic`: The instruction count at the time of the event.
    - `cu`: The computational unit count at the time of the event.
    - `reg`: An array of registers (`ulong` type) representing the state of the registers at the time of the event.
    - `text`: A pointer to an array of `ulong` representing the instruction text.
    - `text_cnt`: The number of words in the instruction text.
    - `ic_correction`: A correction value for the instruction count.
    - `frame_cnt`: The frame count at the time of the event.
- **Control Flow**:
    - Check if any of the pointers `trace`, `reg`, or `text` are NULL or if `text_cnt` is zero; if so, return `FD_VM_ERR_INVAL`.
    - Extract the first word of the instruction text and determine if the instruction is multiword based on its opcode class.
    - Calculate the footprint of the event, adjusting for multiword instructions.
    - Check if there is enough space in the trace to store the event; if not, return `FD_VM_ERR_FULL`.
    - Calculate the address where the event should be stored in the trace and update the trace's event size.
    - Populate the event structure with the provided data, including program counter, instruction count, computational units, registers, and instruction text.
    - If the instruction is multiword, store the second word of the instruction text.
    - Return `FD_VM_SUCCESS` to indicate successful recording of the event.
- **Output**: Returns an integer status code: `FD_VM_SUCCESS` on success, `FD_VM_ERR_INVAL` if inputs are invalid, or `FD_VM_ERR_FULL` if there is insufficient space to record the event.
- **Functions called**:
    - [`fd_vm_trace_event_info`](fd_vm_base.h.driver.md#fd_vm_trace_event_info)


---
### fd\_vm\_trace\_event\_mem<!-- {{#callable:fd_vm_trace_event_mem}} -->
The `fd_vm_trace_event_mem` function records a memory event in a trace, handling both read and write operations, and stores associated data if provided.
- **Inputs**:
    - `trace`: A pointer to an `fd_vm_trace_t` structure, which holds the trace information and storage.
    - `write`: An integer indicating whether the event is a write (non-zero) or read (zero) operation.
    - `vaddr`: An unsigned long representing the virtual address involved in the memory event.
    - `sz`: An unsigned long specifying the size of the data involved in the memory event.
    - `data`: A pointer to the data to be recorded with the event, if any.
- **Control Flow**:
    - Check if the `trace` pointer is NULL and return `FD_VM_ERR_INVAL` if it is.
    - Determine if the event is valid by checking if `data` and `sz` are non-zero.
    - Calculate the size of the data to be recorded, ensuring it does not exceed `trace->event_data_max`.
    - Calculate the total footprint of the event, aligning it to 8 bytes.
    - Check if there is enough space in the trace to store the event; return `FD_VM_ERR_FULL` if not.
    - Calculate the location in memory to store the event and update the trace's event size.
    - Record the event type and validity in the event structure.
    - Store the virtual address and size in the event structure.
    - If the event is valid, copy the data into the event structure.
    - Return `FD_VM_SUCCESS` to indicate successful recording of the event.
- **Output**: Returns an integer status code: `FD_VM_SUCCESS` on success, `FD_VM_ERR_INVAL` if the trace is NULL, or `FD_VM_ERR_FULL` if there is insufficient space to record the event.
- **Functions called**:
    - [`fd_vm_trace_event_info`](fd_vm_base.h.driver.md#fd_vm_trace_event_info)


---
### fd\_vm\_trace\_printf<!-- {{#callable:fd_vm_trace_printf}} -->
The `fd_vm_trace_printf` function processes and prints detailed information about virtual machine trace events, including execution and memory access events, from a given trace object.
- **Inputs**:
    - `trace`: A pointer to a `fd_vm_trace_t` structure containing the trace events to be processed and printed.
    - `syscalls`: A pointer to a `fd_sbpf_syscalls_t` structure used for disassembling instructions during execution event processing.
- **Control Flow**:
    - Check if the `trace` input is NULL and log a warning if so, returning an invalid argument error code.
    - Retrieve the maximum data size for events from the trace and initialize pointers to the event data and remaining size.
    - Enter a loop to process each event in the trace while there is remaining data.
    - For each event, check if there is enough data to read the event info; if not, log a warning and return an I/O error code.
    - Determine the event type from the event info and handle it based on its type (execution or memory access).
    - For execution events, calculate the event footprint, check for truncation, and print the architectural state and disassembled instruction.
    - For memory access events, calculate the event footprint, check for truncation, and print the memory access details including data in a formatted manner.
    - If an unexpected event type is encountered, log a warning and return an I/O error code.
    - Update the pointer and remaining size to move to the next event in the trace.
    - Return success if all events are processed without errors.
- **Output**: Returns an integer status code, `FD_VM_SUCCESS` on success, or an error code such as `FD_VM_ERR_INVAL` or `FD_VM_ERR_IO` on failure.
- **Functions called**:
    - [`fd_vm_trace_event_data_max`](fd_vm_base.h.driver.md#fd_vm_trace_event_data_max)
    - [`fd_vm_trace_event`](fd_vm_base.h.driver.md#fd_vm_trace_event)
    - [`fd_vm_trace_event_sz`](fd_vm_base.h.driver.md#fd_vm_trace_event_sz)
    - [`fd_vm_trace_event_info_type`](fd_vm_base.h.driver.md#fd_vm_trace_event_info_type)
    - [`fd_vm_trace_event_info_valid`](fd_vm_base.h.driver.md#fd_vm_trace_event_info_valid)
    - [`fd_vm_disasm_instr`](fd_vm_disasm.c.driver.md#fd_vm_disasm_instr)
    - [`fd_vm_strerror`](fd_vm.c.driver.md#fd_vm_strerror)



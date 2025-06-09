# Purpose
The provided C header file, `fd_vm_private.h`, is part of a virtual machine (VM) implementation, specifically designed to handle memory management and instruction processing for a system that appears to be related to the Solana blockchain's eBPF (Extended Berkeley Packet Filter) execution environment. This file is not intended to be a standalone executable but rather a private component of a larger system, likely included in other source files to provide specific functionalities related to memory alignment, instruction encoding/decoding, and memory access within the VM.

Key components of this file include definitions for memory alignment constants that ensure compatibility with Rust types, which are crucial for interoperability between C and Rust in this context. It also defines structures and functions for handling vectors and memory regions, including translating virtual addresses to host addresses and managing memory access permissions. The file includes macros and inline functions for encoding and decoding eBPF instructions, which are essential for executing programs within the VM. Additionally, it provides mechanisms for error logging and handling, ensuring that execution errors are properly tracked and reported. Overall, this header file is a critical part of the VM's internal workings, focusing on efficient memory management and instruction processing to support the execution of eBPF programs.
# Imports and Dependencies

---
- `fd_vm.h`
- `../../ballet/sbpf/fd_sbpf_instr.h`
- `../../ballet/sbpf/fd_sbpf_opcodes.h`
- `../../ballet/murmur3/fd_murmur3.h`
- `../runtime/context/fd_exec_txn_ctx.h`
- `../features/fd_features.h`
- `fd_vm_base.h`


# Data Structures

---
### fd\_vm\_vec
- **Type**: `struct`
- **Members**:
    - `addr`: Represents the starting virtual address of the vector.
    - `len`: Indicates the length or size of the vector.
- **Description**: The `fd_vm_vec` structure is a packed data structure that serves as a descriptor for a vector in memory, similar in layout to a Rust slice header. It contains two members: `addr`, which is the starting virtual address of the vector, and `len`, which specifies the length or size of the vector. This structure is used to represent vector-like data in the C version of the syscall API, ensuring compatibility with Rust's memory alignment and layout conventions.


---
### fd\_vm\_vec\_t
- **Type**: `struct`
- **Members**:
    - `addr`: Represents the virtual address of the vector.
    - `len`: Indicates the length or size of the vector.
- **Description**: The `fd_vm_vec_t` structure is a packed data structure that serves as an in-memory representation of a vector descriptor, similar in layout to a Rust slice header or various vector types in the C version of the syscall API. It contains two members: `addr`, which holds the virtual address of the vector, and `len`, which specifies the length or size of the vector. This structure is aligned according to the Rust slice reference alignment and is used within the virtual machine context to manage memory efficiently.


# Functions

---
### fd\_vm\_instr<!-- {{#callable:fd_vm_instr}} -->
The `fd_vm_instr` function constructs a SBPF instruction word by combining various fields such as opcode, destination register, source register, offset, and immediate value into a single 64-bit unsigned long integer.
- **Inputs**:
    - `opcode`: An unsigned long integer representing the operation code, assumed to be valid.
    - `dst`: An unsigned long integer representing the destination register, assumed to be within the range [0, FD_VM_REG_CNT).
    - `src`: An unsigned long integer representing the source register, assumed to be within the range [0, FD_VM_REG_CNT).
    - `offset`: A short integer representing the offset value.
    - `imm`: An unsigned integer representing the immediate value.
- **Control Flow**:
    - The function takes five parameters: opcode, dst, src, offset, and imm.
    - It shifts the destination register value left by 8 bits and the source register value left by 12 bits.
    - The offset is cast to an unsigned short, then to an unsigned long, and shifted left by 16 bits.
    - The immediate value is cast to an unsigned long and shifted left by 32 bits.
    - All these shifted values are combined using bitwise OR operations with the opcode to form a single 64-bit instruction word.
- **Output**: The function returns a 64-bit unsigned long integer representing the constructed SBPF instruction word.


---
### fd\_vm\_instr\_opcode<!-- {{#callable:fd_vm_instr_opcode}} -->
The `fd_vm_instr_opcode` function extracts the opcode from a given SBPF instruction word by masking the least significant 8 bits.
- **Inputs**:
    - `instr`: An unsigned long integer representing the SBPF instruction word from which the opcode is to be extracted.
- **Control Flow**:
    - The function takes a single input parameter, `instr`, which is an unsigned long integer.
    - It applies a bitwise AND operation between `instr` and `255UL` (which is equivalent to `0xFF` in hexadecimal) to isolate the least significant 8 bits of the instruction.
    - The result of this operation is returned as the opcode.
- **Output**: The function returns an unsigned long integer representing the opcode, which is the value of the least significant 8 bits of the input instruction.


---
### fd\_vm\_instr\_dst<!-- {{#callable:fd_vm_instr_dst}} -->
The `fd_vm_instr_dst` function extracts the destination register field from a given SBPF instruction word.
- **Inputs**:
    - `instr`: An unsigned long integer representing the SBPF instruction word from which the destination register field is to be extracted.
- **Control Flow**:
    - The function shifts the input instruction word 8 bits to the right.
    - It then applies a bitwise AND operation with the value 15UL to isolate the 4-bit destination register field.
- **Output**: The function returns an unsigned long integer representing the destination register field, which is a value in the range [0, 16).


---
### fd\_vm\_instr\_src<!-- {{#callable:fd_vm_instr_src}} -->
The `fd_vm_instr_src` function extracts the source register field from a given SBPF instruction word.
- **Inputs**:
    - `instr`: An unsigned long integer representing the SBPF instruction word from which the source register field is to be extracted.
- **Control Flow**:
    - The function shifts the input instruction word 12 bits to the right.
    - It then applies a bitwise AND operation with the value 15UL to isolate the 4-bit source register field.
    - The result is returned as the source register field, which is in the range [0, 16).
- **Output**: The function returns an unsigned long integer representing the source register field extracted from the instruction word.


---
### fd\_vm\_instr\_offset<!-- {{#callable:fd_vm_instr_offset}} -->
The `fd_vm_instr_offset` function extracts and returns the offset field from a given SBPF instruction word.
- **Inputs**:
    - `instr`: An unsigned long integer representing the SBPF instruction word from which the offset field is to be extracted.
- **Control Flow**:
    - The function shifts the input instruction word 16 bits to the right to isolate the offset field.
    - It then casts the result to an unsigned short, then to a signed short, and finally to a signed long, ensuring the correct sign extension.
    - The final result is cast to an unsigned long before being returned.
- **Output**: The function returns an unsigned long integer representing the offset field extracted from the instruction word.


---
### fd\_vm\_instr\_imm<!-- {{#callable:fd_vm_instr_imm}} -->
The `fd_vm_instr_imm` function extracts the immediate value from a 64-bit SBPF instruction word by shifting it right by 32 bits and casting it to a 32-bit unsigned integer.
- **Inputs**:
    - `instr`: A 64-bit unsigned long integer representing an SBPF instruction word from which the immediate value is to be extracted.
- **Control Flow**:
    - The function takes a single input parameter, `instr`, which is a 64-bit unsigned long integer.
    - It shifts the `instr` value right by 32 bits to isolate the immediate value portion of the instruction.
    - The result of the shift operation is then cast to a 32-bit unsigned integer.
    - The function returns this 32-bit unsigned integer as the immediate value.
- **Output**: A 32-bit unsigned integer representing the immediate value extracted from the input instruction word.


---
### fd\_vm\_instr\_opclass<!-- {{#callable:fd_vm_instr_opclass}} -->
The `fd_vm_instr_opclass` function extracts the operation class from a given SBPF instruction word.
- **Inputs**:
    - `instr`: An unsigned long integer representing the SBPF instruction word from which the operation class is to be extracted.
- **Control Flow**:
    - The function takes the input `instr` and performs a bitwise AND operation with the constant `7UL`.
    - This operation isolates the least significant 3 bits of the `instr`, which represent the operation class.
- **Output**: The function returns an unsigned long integer representing the operation class of the instruction, which is a value in the range [0, 8).


---
### fd\_vm\_instr\_normal\_opsrc<!-- {{#callable:fd_vm_instr_normal_opsrc}} -->
The `fd_vm_instr_normal_opsrc` function extracts the 'opsrc' field from a given SBPF instruction word by right-shifting the instruction by 3 bits and masking with 1UL.
- **Inputs**:
    - `instr`: An unsigned long integer representing the SBPF instruction word from which the 'opsrc' field is to be extracted.
- **Control Flow**:
    - The function takes a single input, `instr`, which is an unsigned long integer representing an SBPF instruction.
    - It performs a right bitwise shift on `instr` by 3 positions.
    - The result of the shift is then bitwise ANDed with 1UL to isolate the 'opsrc' field.
    - The function returns the isolated 'opsrc' field as an unsigned long integer.
- **Output**: The function returns an unsigned long integer representing the 'opsrc' field of the SBPF instruction, which is a value in the range [0, 2).


---
### fd\_vm\_instr\_normal\_opmode<!-- {{#callable:fd_vm_instr_normal_opmode}} -->
The `fd_vm_instr_normal_opmode` function extracts the normal operation mode from a given SBPF instruction word.
- **Inputs**:
    - `instr`: An unsigned long integer representing the SBPF instruction word from which the normal operation mode is to be extracted.
- **Control Flow**:
    - The function shifts the input instruction word 4 bits to the right.
    - It then applies a bitwise AND operation with the value 15UL to isolate the 4 bits representing the normal operation mode.
- **Output**: The function returns an unsigned long integer representing the normal operation mode, which is a value in the range [0, 16).


---
### fd\_vm\_instr\_mem\_opsize<!-- {{#callable:fd_vm_instr_mem_opsize}} -->
The `fd_vm_instr_mem_opsize` function extracts the memory operation size from a given SBPF instruction word.
- **Inputs**:
    - `instr`: An unsigned long integer representing the SBPF instruction word from which the memory operation size is to be extracted.
- **Control Flow**:
    - The function shifts the input instruction word 3 bits to the right.
    - It then applies a bitwise AND operation with the value 3UL to isolate the relevant bits representing the memory operation size.
- **Output**: The function returns an unsigned long integer representing the memory operation size, which is a value in the range [0, 4).


---
### fd\_vm\_instr\_mem\_opaddrmode<!-- {{#callable:fd_vm_instr_mem_opaddrmode}} -->
The function `fd_vm_instr_mem_opaddrmode` extracts the memory operation address mode from a given SBPF instruction word.
- **Inputs**:
    - `instr`: An unsigned long integer representing the SBPF instruction word from which the memory operation address mode is to be extracted.
- **Control Flow**:
    - The function shifts the input instruction word 5 bits to the right.
    - It then applies a bitwise AND operation with the value 7UL to isolate the relevant bits representing the memory operation address mode.
- **Output**: The function returns an unsigned long integer representing the memory operation address mode, which is a value in the range [0, 8).


---
### fd\_vm\_mem\_cfg<!-- {{#callable:fd_vm_mem_cfg}} -->
The `fd_vm_mem_cfg` function configures the memory regions of a virtual machine (VM) by setting up host addresses and load/store sizes for various memory regions, including program, stack, heap, and input regions.
- **Inputs**:
    - `vm`: A pointer to an `fd_vm_t` structure representing the virtual machine whose memory regions are to be configured.
- **Control Flow**:
    - Initialize the host address, load size, and store size for region 0 to zero.
    - Set the host address, load size, and store size for the program region using the VM's read-only data and its size.
    - Configure the stack region with its host address and maximum load/store sizes.
    - Set the heap region's host address and maximum load/store sizes.
    - Initialize the host address, load size, and store size for region 5 to zero.
    - Check if direct mapping is enabled or if there are no input memory regions; if true, set the input region's host address, load size, and store size to zero.
    - If direct mapping is not enabled and there are input memory regions, set the input region's host address, load size, and store size using the first input memory region's address and size.
    - Return the configured VM pointer.
- **Output**: Returns the pointer to the configured `fd_vm_t` structure.


---
### fd\_vm\_get\_input\_mem\_region\_idx<!-- {{#callable:fd_vm_get_input_mem_region_idx}} -->
The `fd_vm_get_input_mem_region_idx` function performs a binary search to find the index of the input memory region in a virtual machine that contains a given offset.
- **Inputs**:
    - `vm`: A pointer to a constant `fd_vm_t` structure representing the virtual machine, which contains information about input memory regions.
    - `offset`: An unsigned long integer representing the offset within the input memory regions to locate.
- **Control Flow**:
    - Initialize `left` to 0 and `right` to the count of input memory regions minus one.
    - Enter a while loop that continues as long as `left` is less than `right`.
    - Calculate `mid` as the average of `left` and `right`.
    - Check if the `offset` is greater than or equal to the sum of the virtual address offset and region size of the middle region.
    - If true, set `left` to `mid + 1`; otherwise, set `right` to `mid`.
    - Exit the loop when `left` is no longer less than `right`.
    - Return `left` as the index of the input memory region containing the offset.
- **Output**: The function returns an unsigned long integer representing the index of the input memory region that contains the specified offset.


---
### fd\_vm\_find\_input\_mem\_region<!-- {{#callable:fd_vm_find_input_mem_region}} -->
The `fd_vm_find_input_mem_region` function locates the host address corresponding to a given offset in the input memory region, ensuring the access is valid and does not span non-writable regions.
- **Inputs**:
    - `vm`: A pointer to the `fd_vm_t` structure representing the virtual machine context, which contains information about input memory regions.
    - `offset`: An unsigned long integer representing the offset within the input memory region to be accessed.
    - `sz`: An unsigned long integer representing the size of the memory access.
    - `write`: An unsigned char indicating whether the access is a write operation (non-zero) or a read operation (zero).
    - `sentinel`: An unsigned long integer used as a return value to indicate an invalid access.
    - `is_multi_region`: A pointer to an unsigned char that will be set to 1 if the access spans multiple memory regions, otherwise 0.
- **Control Flow**:
    - Check if there are no input memory regions; if so, return the sentinel value indicating the access is too large.
    - Use a binary search to find the index of the memory region that contains the given offset.
    - Calculate the number of bytes left to access and the number of bytes available in the current region.
    - Check if the access is a write and the current region is not writable; if so, return the sentinel value indicating an illegal write.
    - Initialize the starting region index and set `is_multi_region` to 0.
    - Enter a loop to handle cases where the access spans multiple regions, updating `is_multi_region` to 1 if necessary.
    - In the loop, subtract the bytes available in the current region from the bytes left to access, and move to the next region if needed.
    - Check if the region index exceeds the number of regions, indicating the access is too large, and return the sentinel value.
    - Calculate the adjusted host address based on the starting region index, offset, and virtual address offset, and return it.
- **Output**: The function returns an unsigned long integer representing the host address corresponding to the given offset, or the sentinel value if the access is invalid.
- **Functions called**:
    - [`fd_vm_get_input_mem_region_idx`](#fd_vm_get_input_mem_region_idx)


---
### fd\_vm\_mem\_haddr<!-- {{#callable:fd_vm_mem_haddr}} -->
The `fd_vm_mem_haddr` function translates a virtual memory address range to a host memory address range, ensuring the range is valid and handling special cases for stack regions and input regions.
- **Inputs**:
    - `vm`: A pointer to the `fd_vm_t` structure representing the virtual machine context.
    - `vaddr`: The starting virtual address to be translated.
    - `sz`: The size of the memory range to be translated.
    - `vm_region_haddr`: An array of host addresses corresponding to each virtual memory region.
    - `vm_region_sz`: An array of sizes for each virtual memory region.
    - `write`: A flag indicating if the access is a write (1) or a read (0).
    - `sentinel`: A value to return if the translation fails.
    - `is_multi_region`: A pointer to a uchar that will be set to 1 if the access spans multiple regions, otherwise 0.
- **Control Flow**:
    - Determine the region and offset from the virtual address using `FD_VADDR_TO_REGION` and a mask.
    - Check if the region is a stack region with unmapped gaps and adjust the offset if necessary.
    - Calculate the maximum size that can be accessed within the region.
    - If the region is the input region, call [`fd_vm_find_input_mem_region`](#fd_vm_find_input_mem_region) to handle the translation.
    - If memory tracing is enabled and the size is within bounds, log the memory access event.
    - Return the translated host address if the size is within bounds, otherwise return the sentinel value.
- **Output**: Returns the translated host address if the virtual address range is valid, otherwise returns the sentinel value.
- **Functions called**:
    - [`fd_vm_find_input_mem_region`](#fd_vm_find_input_mem_region)
    - [`fd_vm_trace_event_mem`](fd_vm_base.h.driver.md#fd_vm_trace_event_mem)


---
### fd\_vm\_mem\_haddr\_fast<!-- {{#callable:fd_vm_mem_haddr_fast}} -->
The `fd_vm_mem_haddr_fast` function quickly translates a virtual address to a host address using pre-configured region mappings, assuming the virtual address is already known to be valid.
- **Inputs**:
    - `vm`: A pointer to a constant `fd_vm_t` structure representing the virtual machine context.
    - `vaddr`: An unsigned long integer representing the virtual address to be translated.
    - `vm_region_haddr`: A pointer to an array of unsigned long integers representing the base host addresses for each virtual memory region, indexed from 0 to 5.
- **Control Flow**:
    - Initialize a variable `is_multi` to 0, which is used to track if the access spans multiple regions.
    - Determine the memory region of the virtual address `vaddr` by calling `FD_VADDR_TO_REGION(vaddr)`.
    - Calculate the offset within the region by applying the mask `FD_VM_OFFSET_MASK` to `vaddr`.
    - Check if the determined region is the input region (`FD_VM_INPUT_REGION`).
    - If the region is the input region, call [`fd_vm_find_input_mem_region`](#fd_vm_find_input_mem_region) to find the corresponding host address, passing the virtual machine context, offset, size of 1, write flag as 0, sentinel value as 0, and a pointer to `is_multi`.
    - If the region is not the input region, return the sum of the base host address for the region from `vm_region_haddr` and the calculated offset.
- **Output**: Returns an unsigned long integer representing the translated host address corresponding to the given virtual address.
- **Functions called**:
    - [`fd_vm_find_input_mem_region`](#fd_vm_find_input_mem_region)


---
### fd\_vm\_mem\_ld\_multi<!-- {{#callable:fd_vm_mem_ld_multi}} -->
The `fd_vm_mem_ld_multi` function loads a specified number of bytes from a virtual memory address to a destination buffer, handling cases where the load spans multiple memory regions.
- **Inputs**:
    - `vm`: A pointer to a constant `fd_vm_t` structure representing the virtual machine context.
    - `sz`: An unsigned integer representing the number of bytes to load.
    - `vaddr`: An unsigned long representing the virtual address from which to start loading.
    - `haddr`: An unsigned long representing the host address corresponding to the virtual address.
    - `dst`: A pointer to an unsigned char buffer where the loaded bytes will be stored.
- **Control Flow**:
    - Calculate the offset within the virtual address using a mask.
    - Determine the initial memory region index using the offset.
    - Calculate the number of bytes available in the current memory region.
    - Enter a loop that continues until all requested bytes are loaded (decrementing `sz` each iteration).
    - If the current region has no more bytes available, move to the next region and update the host address and bytes available.
    - Load a byte from the current host address to the destination buffer, increment the host address, and decrement the bytes available in the current region.
- **Output**: The function does not return a value; it modifies the destination buffer `dst` by loading bytes from the specified virtual memory address.
- **Functions called**:
    - [`fd_vm_get_input_mem_region_idx`](#fd_vm_get_input_mem_region_idx)


---
### fd\_vm\_mem\_ld\_1<!-- {{#callable:fd_vm_mem_ld_1}} -->
The `fd_vm_mem_ld_1` function loads a single byte from a given host address and returns it as an unsigned long.
- **Inputs**:
    - `haddr`: An unsigned long representing the host address from which a byte is to be loaded.
- **Control Flow**:
    - The function casts the host address to a pointer to a constant unsigned char.
    - It dereferences this pointer to obtain the byte stored at the given address.
    - The byte is then cast to an unsigned long and returned.
- **Output**: An unsigned long containing the zero-extended value of the byte loaded from the specified host address.


---
### fd\_vm\_mem\_ld\_2<!-- {{#callable:fd_vm_mem_ld_2}} -->
The `fd_vm_mem_ld_2` function loads a 2-byte value from a host address, handling both single and multi-region memory scenarios, and returns it as an unsigned long.
- **Inputs**:
    - `vm`: A pointer to a constant `fd_vm_t` structure representing the virtual machine context.
    - `vaddr`: An unsigned long representing the virtual address from which to load the data.
    - `haddr`: An unsigned long representing the host address from which to load the data.
    - `is_multi_region`: A uint indicating whether the memory access spans multiple regions (non-zero) or not (zero).
- **Control Flow**:
    - Declare a variable `t` of type `ushort` to store the loaded data.
    - Check if `is_multi_region` is false (likely case).
    - If `is_multi_region` is false, use `memcpy` to copy 2 bytes from `haddr` to `t`.
    - If `is_multi_region` is true, call [`fd_vm_mem_ld_multi`](#fd_vm_mem_ld_multi) to handle loading across multiple regions.
    - Return the value of `t` cast to `ulong`.
- **Output**: The function returns the loaded 2-byte value as an unsigned long.
- **Functions called**:
    - [`fd_vm_mem_ld_multi`](#fd_vm_mem_ld_multi)


---
### fd\_vm\_mem\_ld\_4<!-- {{#callable:fd_vm_mem_ld_4}} -->
The `fd_vm_mem_ld_4` function loads a 4-byte unsigned integer from a specified host address, handling both single and multi-region memory scenarios.
- **Inputs**:
    - `vm`: A pointer to a constant `fd_vm_t` structure, representing the virtual machine context.
    - `vaddr`: An unsigned long integer representing the virtual address from which to load the data.
    - `haddr`: An unsigned long integer representing the host address from which to load the data.
    - `is_multi_region`: An unsigned integer flag indicating whether the memory access spans multiple regions (non-zero) or not (zero).
- **Control Flow**:
    - Declare a variable `t` of type `uint` to store the loaded data.
    - Check if `is_multi_region` is false (likely case).
    - If `is_multi_region` is false, use `memcpy` to copy 4 bytes from `haddr` to `t`.
    - If `is_multi_region` is true, call [`fd_vm_mem_ld_multi`](#fd_vm_mem_ld_multi) to handle loading across multiple memory regions.
    - Return the value of `t` cast to `ulong`.
- **Output**: Returns an `ulong` representing the 4-byte unsigned integer loaded from the specified host address.
- **Functions called**:
    - [`fd_vm_mem_ld_multi`](#fd_vm_mem_ld_multi)


---
### fd\_vm\_mem\_ld\_8<!-- {{#callable:fd_vm_mem_ld_8}} -->
The `fd_vm_mem_ld_8` function loads an 8-byte unsigned long value from a specified host address, handling both single and multi-region memory scenarios.
- **Inputs**:
    - `vm`: A pointer to a constant `fd_vm_t` structure representing the virtual machine context.
    - `vaddr`: An unsigned long representing the virtual address from which to load the data.
    - `haddr`: An unsigned long representing the host address from which to load the data.
    - `is_multi_region`: An unsigned integer indicating whether the memory access spans multiple regions (non-zero if true).
- **Control Flow**:
    - Declare a variable `t` of type `ulong` to store the loaded value.
    - Check if `is_multi_region` is false using `FD_LIKELY`.
    - If `is_multi_region` is false, use `memcpy` to copy 8 bytes from `haddr` to `t`.
    - If `is_multi_region` is true, call [`fd_vm_mem_ld_multi`](#fd_vm_mem_ld_multi) to handle loading across multiple regions.
    - Return the value stored in `t`.
- **Output**: Returns an unsigned long value representing the 8-byte data loaded from the specified host address.
- **Functions called**:
    - [`fd_vm_mem_ld_multi`](#fd_vm_mem_ld_multi)


---
### fd\_vm\_mem\_st\_multi<!-- {{#callable:fd_vm_mem_st_multi}} -->
The `fd_vm_mem_st_multi` function writes a specified number of bytes from a source buffer to a virtual memory address, handling cases where the write operation spans multiple memory regions.
- **Inputs**:
    - `vm`: A pointer to a constant `fd_vm_t` structure representing the virtual machine context, which contains information about memory regions.
    - `sz`: An unsigned integer representing the number of bytes to be written from the source buffer to the destination.
    - `vaddr`: An unsigned long integer representing the virtual address where the data should be written.
    - `haddr`: An unsigned long integer representing the host address corresponding to the starting point of the write operation.
    - `src`: A pointer to an unsigned char array containing the source data to be written to the virtual memory.
- **Control Flow**:
    - Calculate the offset within the virtual memory using the virtual address and a mask.
    - Determine the index of the memory region corresponding to the offset using [`fd_vm_get_input_mem_region_idx`](#fd_vm_get_input_mem_region_idx).
    - Calculate the number of bytes available in the current memory region.
    - Initialize a destination pointer to the host address.
    - Enter a loop that continues until all bytes specified by `sz` are written.
    - Within the loop, check if the current region has no more bytes available; if so, move to the next region and update the destination pointer and bytes available.
    - Write a byte from the source to the destination, increment both pointers, and decrement the available bytes in the current region.
- **Output**: The function does not return a value; it performs the side effect of writing data to the specified virtual memory address.
- **Functions called**:
    - [`fd_vm_get_input_mem_region_idx`](#fd_vm_get_input_mem_region_idx)


---
### fd\_vm\_mem\_st\_1<!-- {{#callable:fd_vm_mem_st_1}} -->
The `fd_vm_mem_st_1` function stores a single byte value at a specified host memory address.
- **Inputs**:
    - `haddr`: The host memory address where the byte value will be stored.
    - `val`: The byte value to be stored at the specified host memory address.
- **Control Flow**:
    - The function takes a host memory address and a byte value as inputs.
    - It casts the host memory address to a pointer to an unsigned char (byte).
    - The function then assigns the byte value to the memory location pointed to by the casted address.
- **Output**: The function does not return any value; it performs an in-place memory operation.


---
### fd\_vm\_mem\_st\_2<!-- {{#callable:fd_vm_mem_st_2}} -->
The `fd_vm_mem_st_2` function stores a 2-byte value at a specified host address, handling both single and multi-region memory scenarios.
- **Inputs**:
    - `vm`: A pointer to a constant `fd_vm_t` structure representing the virtual machine context.
    - `vaddr`: An unsigned long integer representing the virtual address where the value should be stored.
    - `haddr`: An unsigned long integer representing the host address where the value should be stored.
    - `val`: A 2-byte unsigned short integer value to be stored at the specified address.
    - `is_multi_region`: An unsigned integer flag indicating whether the memory operation spans multiple regions (non-zero) or not (zero).
- **Control Flow**:
    - Check if the memory operation does not span multiple regions using `FD_LIKELY` macro.
    - If the operation is within a single region, use `memcpy` to copy the 2-byte value to the host address.
    - If the operation spans multiple regions, call [`fd_vm_mem_st_multi`](#fd_vm_mem_st_multi) to handle the multi-region store operation.
- **Output**: The function does not return a value; it performs a memory store operation.
- **Functions called**:
    - [`fd_vm_mem_st_multi`](#fd_vm_mem_st_multi)


---
### fd\_vm\_mem\_st\_4<!-- {{#callable:fd_vm_mem_st_4}} -->
The `fd_vm_mem_st_4` function stores a 4-byte unsigned integer value to a specified host address, handling both single and multi-region memory scenarios.
- **Inputs**:
    - `vm`: A pointer to a constant `fd_vm_t` structure representing the virtual machine context.
    - `vaddr`: An unsigned long integer representing the virtual address where the value should be stored.
    - `haddr`: An unsigned long integer representing the host address where the value should be stored.
    - `val`: A 4-byte unsigned integer value to be stored at the specified address.
    - `is_multi_region`: An unsigned integer flag indicating whether the memory operation spans multiple regions (non-zero) or not (zero).
- **Control Flow**:
    - Check if the `is_multi_region` flag is false (likely case).
    - If false, use `memcpy` to copy the 4-byte value directly to the host address `haddr`.
    - If true, call [`fd_vm_mem_st_multi`](#fd_vm_mem_st_multi) to handle storing the value across multiple memory regions.
- **Output**: The function does not return a value; it performs a memory store operation.
- **Functions called**:
    - [`fd_vm_mem_st_multi`](#fd_vm_mem_st_multi)


---
### fd\_vm\_mem\_st\_8<!-- {{#callable:fd_vm_mem_st_8}} -->
The `fd_vm_mem_st_8` function stores an 8-byte value to a specified host address, handling both single and multi-region memory scenarios.
- **Inputs**:
    - `vm`: A pointer to a constant `fd_vm_t` structure, representing the virtual machine context.
    - `vaddr`: An unsigned long integer representing the virtual address where the value should be stored.
    - `haddr`: An unsigned long integer representing the host address where the value should be stored.
    - `val`: An unsigned long integer representing the 8-byte value to be stored.
    - `is_multi_region`: An unsigned integer flag indicating whether the memory operation spans multiple regions (non-zero) or not (zero).
- **Control Flow**:
    - Check if the `is_multi_region` flag is not set (likely case).
    - If not set, use `memcpy` to copy the 8-byte value directly to the host address `haddr`.
    - If set, call [`fd_vm_mem_st_multi`](#fd_vm_mem_st_multi) to handle storing the value across multiple memory regions.
- **Output**: The function does not return a value; it performs a memory store operation.
- **Functions called**:
    - [`fd_vm_mem_st_multi`](#fd_vm_mem_st_multi)


---
### fd\_vm\_mem\_st\_try<!-- {{#callable:fd_vm_mem_st_try}} -->
The `fd_vm_mem_st_try` function attempts to store a sequence of bytes from a source array into a virtual memory space, stopping if any address translation fails.
- **Inputs**:
    - `vm`: A pointer to a constant `fd_vm_t` structure representing the virtual machine context.
    - `vaddr`: An unsigned long integer representing the starting virtual address where the data should be stored.
    - `sz`: An unsigned long integer representing the size of the data to be stored, in bytes.
    - `val`: A pointer to an array of unsigned characters containing the data to be stored.
- **Control Flow**:
    - Initialize a variable `is_multi_region` to 0 to track if the memory spans multiple regions.
    - Iterate over each byte in the data to be stored, from 0 to `sz-1`.
    - For each byte, calculate the host address (`haddr`) corresponding to the current virtual address using [`fd_vm_mem_haddr`](#fd_vm_mem_haddr).
    - If `haddr` is zero (indicating a failed address translation), exit the function early.
    - If `haddr` is valid, store the current byte from `val` into the calculated host address.
- **Output**: The function does not return a value; it performs memory operations directly on the virtual machine's memory space.
- **Functions called**:
    - [`fd_vm_mem_haddr`](#fd_vm_mem_haddr)



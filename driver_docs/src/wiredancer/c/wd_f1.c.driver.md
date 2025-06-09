# Purpose
This C source code file is designed to manage and interact with PCIe (Peripheral Component Interconnect Express) devices, specifically in the context of FPGA (Field-Programmable Gate Array) management on AWS F1 instances. The file provides a set of functions to initialize, configure, and communicate with PCIe slots, handling tasks such as attaching to FPGA interfaces, reading and writing data, and managing data streams. The code includes both private and public functions, with private functions prefixed by an underscore to indicate their intended internal use. The primary public functions include [`wd_init_pci`](#wd_init_pci), which initializes PCIe slots, and [`wd_ed25519_verify_req`](#wd_ed25519_verify_req), which appears to handle requests for Ed25519 signature verification, a cryptographic operation.

The file is structured to support high-performance data streaming and processing, leveraging AVX (Advanced Vector Extensions) for efficient data handling. It includes mechanisms for managing memory-mapped I/O, setting up DMA (Direct Memory Access) operations, and handling backpressure in data streams. The code also provides utility functions for resetting and reading counters, managing virtual DIP switches, and converting virtual addresses to physical addresses. The presence of functions like [`wd_ed25519_verify_init_req`](#wd_ed25519_verify_init_req) and [`wd_ed25519_verify_req`](#wd_ed25519_verify_req) suggests that the code is part of a larger system that performs cryptographic operations, possibly for secure data processing or verification tasks. Overall, this file is a specialized component of a broader system, focusing on efficient PCIe communication and FPGA management.
# Imports and Dependencies

---
- `wd_f1.h`


# Functions

---
### wd\_init\_pci<!-- {{#callable:wd_init_pci}} -->
The `wd_init_pci` function initializes PCI slots for a given workspace by mapping memory, setting up PCI bars, and configuring streams for each active slot.
- **Inputs**:
    - `wd`: A pointer to a `wd_wksp_t` structure representing the workspace to be initialized.
    - `slots`: A 64-bit unsigned integer representing the bitmask of PCI slots to be initialized.
- **Control Flow**:
    - Set the `pci_slots` field of the `wd` structure to the provided `slots` bitmask.
    - Map a 32-byte memory region for `stream_buf` using `mmap` with read/write permissions and specific flags.
    - Set the `initialized` flag of `fpga_mgmt_state` to true, indicating that FPGA management is initialized.
    - Iterate over each possible PCI slot (up to `WD_N_PCI_SLOTS`).
    - For each slot, initialize the `bar0`, `bar4`, and `bar4_addr` fields of the `pci` structure to default values.
    - Check if the current slot is active by testing the corresponding bit in `pci_slots`. If not active, continue to the next slot.
    - Attempt to attach to the AFI on the current slot for both BAR0 and BAR4 using `fpga_pci_attach`. If either attachment fails, log an error and return -1.
    - Retrieve the address for BAR4 using `fpga_pci_get_address`.
    - Initialize the stream configuration for each stream in the current PCI slot by setting specific fields (`a`, `b`, `m`).
    - Return 0 to indicate successful initialization.
- **Output**: Returns 0 on successful initialization of the PCI slots, or -1 if an error occurs during attachment to the AFI.


---
### wd\_free\_pci<!-- {{#callable:wd_free_pci}} -->
The `wd_free_pci` function is a placeholder function that takes a workspace pointer as input and returns 0 without performing any operations.
- **Inputs**:
    - `wd`: A pointer to a `wd_wksp_t` structure, representing the workspace for PCI operations.
- **Control Flow**:
    - The function takes a single argument, `wd`, which is a pointer to a `wd_wksp_t` structure.
    - The function explicitly ignores the `wd` argument using `(void)wd;`, indicating that it is not used.
    - The function returns the integer value 0.
- **Output**: The function returns an integer value of 0, indicating successful completion without performing any operations.


---
### \_wd\_read\_32<!-- {{#callable:_wd_read_32}} -->
The function `_wd_read_32` reads a 32-bit value from a specified address on a PCI device's BAR0 memory space.
- **Inputs**:
    - `pci`: A pointer to a `wd_pci_t` structure representing the PCI device from which to read.
    - `addr`: A 32-bit unsigned integer representing the address offset within the PCI device's BAR0 memory space to read from.
- **Control Flow**:
    - Declare an integer `rc` and a 32-bit unsigned integer `value` to store the return code and the read value, respectively.
    - Call `fpga_pci_peek` with `pci->bar0`, `addr`, and `&value` to attempt to read a 32-bit value from the specified address in the PCI device's BAR0 memory space.
    - Check if `rc` (the return code from `fpga_pci_peek`) is non-zero, indicating an error occurred during the read operation.
    - If an error occurred, log an error message using `FD_LOG_ERR`.
    - Return the read `value`.
- **Output**: Returns a 32-bit unsigned integer representing the value read from the specified address in the PCI device's BAR0 memory space.


---
### \_wd\_write\_32<!-- {{#callable:_wd_write_32}} -->
The function `_wd_write_32` writes a 32-bit value to a specified address on a PCI device's BAR0 memory space.
- **Inputs**:
    - `pci`: A pointer to a `wd_pci_t` structure representing the PCI device.
    - `addr`: A 32-bit unsigned integer representing the address offset within the PCI device's BAR0 memory space.
    - `v`: A 32-bit unsigned integer value to be written to the specified address.
- **Control Flow**:
    - The function calls `fpga_pci_poke` with the PCI device's BAR0 handle, the specified address, and the value to be written.
- **Output**: The function does not return any value.


---
### \_wd\_write\_256<!-- {{#callable:_wd_write_256}} -->
The function `_wd_write_256` writes a 256-bit block of data from a buffer to a specified offset in a PCI device's memory space using AVX instructions for efficient data transfer.
- **Inputs**:
    - `pci`: A pointer to a `wd_pci_t` structure representing the PCI device to which data will be written.
    - `off`: A 64-bit unsigned integer representing the offset in the PCI device's memory space where the data will be written.
    - `buf`: A constant pointer to the buffer containing the data to be written, expected to be at least 256 bits (32 bytes) in size.
- **Control Flow**:
    - Cast the `buf` pointer to a `uint32_t` pointer to access the data as 32-bit integers.
    - Calculate the target address in the PCI device's memory by adding the offset (divided by 4) to the base address `bar4_addr` from the `pci` structure.
    - Use an `if` statement with a condition that is always false (0) to provide an alternative method of writing data, which is not executed.
    - In the `else` block, load the 256-bit data from the buffer into an AVX register using `_mm256_load_si256`.
    - Stream the 256-bit data from the AVX register to the calculated address in the PCI device's memory using `_mm256_stream_si256`.
- **Output**: The function does not return a value; it performs a side effect by writing data to the PCI device's memory.


---
### \_wd\_stream\_256<!-- {{#callable:_wd_stream_256}} -->
The `_wd_stream_256` function writes a 256-bit data block to a specified PCI slot and manages the stream buffer's state, flushing it when necessary.
- **Inputs**:
    - `wd`: A pointer to a `wd_wksp_t` structure, which represents the workspace containing PCI slot information.
    - `slot`: A `uint32_t` representing the index of the PCI slot to which the data will be written.
    - `buf`: A constant pointer to the data buffer containing the 256-bit data to be written.
- **Control Flow**:
    - Retrieve the stream state for the specified PCI slot from the workspace.
    - Call [`_wd_write_256`](#_wd_write_256) to write the 256-bit data from `buf` to the PCI slot, using the current offset and stream identifier.
    - Increment the stream's offset `a` by 32.
    - Check if the offset `a` has reached the maximum value `m`; if so, flush the stream and reset `a` to 0.
    - If the lower 6 bits of `a` are all set (i.e., `a & 0xFC0 == 0xFC0`), flush the stream.
- **Output**: The function does not return a value; it performs operations on the PCI stream buffer and may flush the buffer as a side effect.
- **Functions called**:
    - [`_wd_write_256`](#_wd_write_256)
    - [`_wd_stream_flush`](#_wd_stream_flush)


---
### \_wd\_stream\_flush<!-- {{#callable:_wd_stream_flush}} -->
The `_wd_stream_flush` function ensures memory ordering by executing a store fence operation.
- **Inputs**:
    - `wd`: A pointer to a `wd_wksp_t` structure, which represents the workspace context.
    - `slot`: A `uint32_t` representing the slot number, which is part of the workspace context.
- **Control Flow**:
    - The function takes two parameters, `wd` and `slot`, but does not use them in its logic.
    - It calls the `_mm_sfence()` intrinsic function to issue a store fence, ensuring that all previous store operations are completed before any subsequent store operations.
- **Output**: The function does not return any value.


---
### wd\_rst\_cntrs<!-- {{#callable:wd_rst_cntrs}} -->
The `wd_rst_cntrs` function resets the counters for a specified PCI slot if it is enabled.
- **Inputs**:
    - `wd`: A pointer to a `wd_wksp_t` structure, which contains information about the PCI workspace, including the slots and their configurations.
    - `slot`: A 32-bit unsigned integer representing the specific PCI slot to reset the counters for.
- **Control Flow**:
    - Check if the specified slot is enabled by verifying if the corresponding bit in `wd->pci_slots` is set.
    - If the slot is not enabled, return immediately without performing any action.
    - If the slot is enabled, call the [`_wd_write_32`](#_wd_write_32) function to write the value `1` to the address `0x20<<2` of the specified slot's PCI configuration.
- **Output**: The function does not return any value; it performs an action to reset the counters for the specified PCI slot.
- **Functions called**:
    - [`_wd_write_32`](#_wd_write_32)


---
### wd\_snp\_cntrs<!-- {{#callable:wd_snp_cntrs}} -->
The `wd_snp_cntrs` function writes a specific value to a PCI slot register to snapshot the counters if the slot is enabled.
- **Inputs**:
    - `wd`: A pointer to a `wd_wksp_t` structure representing the workspace containing PCI slot information.
    - `slot`: A 32-bit unsigned integer representing the specific PCI slot to operate on.
- **Control Flow**:
    - Check if the specified slot is enabled by verifying if the corresponding bit in `wd->pci_slots` is set.
    - If the slot is not enabled, the function returns immediately without performing any operation.
    - If the slot is enabled, call [`_wd_write_32`](#_wd_write_32) to write the value `2` to the address `0x20<<2` of the specified PCI slot's register.
- **Output**: The function does not return any value.
- **Functions called**:
    - [`_wd_write_32`](#_wd_write_32)


---
### wd\_rd\_cntr<!-- {{#callable:wd_rd_cntr}} -->
The `wd_rd_cntr` function reads a counter value from a specified PCI slot and counter index in a workspace structure.
- **Inputs**:
    - `wd`: A pointer to a `wd_wksp_t` structure representing the workspace containing PCI slot information.
    - `slot`: A `uint32_t` representing the specific PCI slot to access.
    - `ci`: A `uint32_t` representing the counter index to be read from the specified slot.
- **Control Flow**:
    - Check if the specified slot is enabled in the `pci_slots` bitmask of the workspace; if not, return 0.
    - Write the counter index `ci` to the address `0x10<<2` of the specified slot using [`_wd_write_32`](#_wd_write_32).
    - Read and return the counter value from the address `0x20<<2` of the specified slot using [`_wd_read_32`](#_wd_read_32).
- **Output**: Returns a `uint32_t` representing the counter value read from the specified PCI slot and counter index, or 0 if the slot is not enabled.
- **Functions called**:
    - [`_wd_write_32`](#_wd_write_32)
    - [`_wd_read_32`](#_wd_read_32)


---
### wd\_rd\_ts<!-- {{#callable:wd_rd_ts}} -->
The `wd_rd_ts` function reads a 64-bit timestamp from a specified PCI slot if it is enabled.
- **Inputs**:
    - `wd`: A pointer to a `wd_wksp_t` structure representing the workspace containing PCI slot information.
    - `slot`: A 32-bit unsigned integer representing the PCI slot number from which to read the timestamp.
- **Control Flow**:
    - Check if the specified slot is enabled by verifying if the corresponding bit in `wd->pci_slots` is set.
    - If the slot is not enabled, return 0 immediately.
    - Read a 32-bit value from the PCI slot at address `(0x12+0)<<2` and store it in the higher 32 bits of the `ts` variable.
    - Shift the `ts` variable left by 32 bits to make room for the lower 32 bits.
    - Read another 32-bit value from the PCI slot at address `(0x11+0)<<2` and store it in the lower 32 bits of the `ts` variable.
    - Return the combined 64-bit timestamp `ts`.
- **Output**: A 64-bit unsigned integer representing the timestamp read from the specified PCI slot, or 0 if the slot is not enabled.
- **Functions called**:
    - [`_wd_read_32`](#_wd_read_32)


---
### wd\_zprintf<!-- {{#callable:wd_zprintf}} -->
The `wd_zprintf` function formats a string with variable arguments, replaces all '0' characters with underscores, and prints the result.
- **Inputs**:
    - `format`: A C-style string that contains the text to be written, optionally including embedded format specifiers that are replaced by the values specified in subsequent additional arguments.
    - `...`: A variable number of arguments that are formatted according to the format specifiers in the format string.
- **Control Flow**:
    - Initialize a character array `s` of size 512 to store the formatted string.
    - Start processing the variable arguments using `va_start` with the format string.
    - Use `vsnprintf` to format the string with the provided arguments and store it in `s`.
    - Iterate over each character in the string `s`.
    - If a character is '0', replace it with '_'.
    - Print the modified string `s` using `printf`.
    - End processing of the variable arguments using `va_end`.
- **Output**: The function does not return a value; it outputs the formatted and modified string directly to the standard output.


---
### \_wd\_next\_slot<!-- {{#callable:_wd_next_slot}} -->
The function `_wd_next_slot` finds the next available PCI slot in a circular manner from a given starting slot.
- **Inputs**:
    - `wd`: A pointer to a `wd_wksp_t` structure, which contains information about the PCI slots.
    - `slot`: A `uint32_t` representing the current slot index from which to start searching for the next available slot.
- **Control Flow**:
    - The function iterates over a fixed number of PCI slots, defined by `WD_N_PCI_SLOTS`.
    - In each iteration, it increments the `slot` index by one.
    - If the incremented `slot` index exceeds or equals `WD_N_PCI_SLOTS`, it wraps around to 0.
    - It checks if the slot is available by performing a bitwise AND operation between `wd->pci_slots` and a bitmask with a single bit set at the `slot` position.
    - If an available slot is found, the loop breaks and the function returns the current `slot` index.
- **Output**: The function returns a `uint32_t` representing the index of the next available PCI slot.


---
### \_wd\_set\_vdip\_64<!-- {{#callable:_wd_set_vdip_64}} -->
The function `_wd_set_vdip_64` sets privileged bytes for a specified slot by iteratively configuring and sending 8-byte values to the FPGA management interface.
- **Inputs**:
    - `wd`: A pointer to a `wd_wksp_t` structure, which is not used in the function.
    - `slot`: A `uint32_t` representing the slot ID where the vDIP is to be set.
    - `vi`: A `uint32_t` representing the virtual interface index used in calculating the vDIP value.
    - `v`: A `uint64_t` value that is split into bytes and used to set the vDIP.
- **Control Flow**:
    - The function begins by casting the `wd` parameter to void, indicating it is unused.
    - A loop iterates 8 times, corresponding to the 8 bytes of the 64-bit value `v`.
    - In each iteration, a `vdip` value is initialized to 0xf.
    - The `vdip` is modified by shifting and adding the current byte of `v` and the calculated index based on `vi`.
    - The least significant byte of `v` is extracted and shifted into the `vdip`, and `v` is right-shifted by 8 bits to prepare for the next iteration.
    - The function `fpga_mgmt_set_vDIP` is called with the current `slot` and `vdip` value.
    - If `fpga_mgmt_set_vDIP` returns a non-zero value, an error is logged, and the function returns -1.
    - If all iterations complete without error, the function returns 0.
- **Output**: The function returns 0 on success, or -1 if an error occurs while setting the vDIP.


---
### \_wd\_get\_phys<!-- {{#callable:_wd_get_phys}} -->
The function `_wd_get_phys` retrieves the physical address corresponding to a given virtual address in memory.
- **Inputs**:
    - `p`: A pointer to the virtual address whose physical address is to be retrieved.
- **Control Flow**:
    - Retrieve the system's page size using `sysconf` with `_SC_PAGESIZE`.
    - Open the `/proc/self/pagemap` file in read-only mode to access the process's page table entries.
    - Check if the file descriptor `pagemap_fd` is valid; if not, log an error and return 0.
    - Calculate the virtual page number (`vpn`) by dividing the virtual address by the page size.
    - Read the page frame number (`pfn`) from the pagemap file using `pread`, handling partial reads in a loop.
    - Mask the `pfn` to extract the relevant bits for the physical address.
    - Calculate the physical address by multiplying the `pfn` by the page size and adding the offset within the page.
    - Close the pagemap file descriptor.
    - Return the calculated physical address.
- **Output**: The function returns a `uint64_t` representing the physical address corresponding to the input virtual address, or 0 if an error occurs.


---
### wd\_ed25519\_verify\_init\_req<!-- {{#callable:wd_ed25519_verify_init_req}} -->
The `wd_ed25519_verify_init_req` function initializes a request for ED25519 verification by setting up PCI slots and configuring DMA and threshold levels.
- **Inputs**:
    - `wd`: A pointer to a `wd_wksp_t` structure representing the workspace context.
    - `send_fails`: A `uint8_t` value indicating the number of send failures to be configured.
    - `mcache_depth`: A `uint64_t` value representing the depth of the memory cache.
    - `mcache_addr`: A pointer to the memory cache address.
- **Control Flow**:
    - The function begins by setting the request slot and depth in the workspace structure using [`_wd_next_slot`](#_wd_next_slot) and the provided `mcache_depth`.
    - It calculates the physical address of the memory cache using [`_wd_get_phys`](#_wd_get_phys).
    - The function iterates over all possible PCI slots, checking if each slot is enabled in `wd->pci_slots`.
    - For each enabled slot, it sets up threshold levels for a pipe-chain by writing specific values to the PCI configuration space using [`_wd_write_32`](#_wd_write_32).
    - It configures SHA padding thresholds and writes the `send_fails` value to the PCI configuration space.
    - The function sets up virtual DIP (vDIP) configurations for DMA using [`_wd_set_vdip_64`](#_wd_set_vdip_64) with the calculated physical address and request depth.
- **Output**: The function does not return a value; it modifies the `wd` structure and configures the PCI slots.
- **Functions called**:
    - [`_wd_next_slot`](#_wd_next_slot)
    - [`_wd_get_phys`](#_wd_get_phys)
    - [`_wd_write_32`](#_wd_write_32)
    - [`_wd_set_vdip_64`](#_wd_set_vdip_64)


---
### wd\_ed25519\_verify\_init\_resp<!-- {{#callable:wd_ed25519_verify_init_resp}} -->
The function `wd_ed25519_verify_init_resp` is a placeholder function that takes a workspace pointer as an argument but performs no operations.
- **Inputs**:
    - `wd`: A pointer to a `wd_wksp_t` structure, representing the workspace context for the operation.
- **Control Flow**:
    - The function takes a single argument, `wd`, which is a pointer to a `wd_wksp_t` structure.
    - The function explicitly casts the `wd` argument to void to indicate that it is unused.
    - No operations or logic are performed within the function body.
- **Output**: The function does not return any value or produce any output.


---
### wd\_ed25519\_verify\_req<!-- {{#callable:wd_ed25519_verify_req}} -->
The `wd_ed25519_verify_req` function sends a request to verify an Ed25519 signature using a PCIe interface, handling backpressure and data streaming to the FPGA.
- **Inputs**:
    - `wd`: A pointer to a `wd_wksp_t` structure representing the workspace, which includes PCIe slot information and stream buffers.
    - `msg`: A pointer to the message data that needs to be verified.
    - `sz`: The size of the message in bytes.
    - `sig`: A pointer to the signature data to be verified.
    - `public_key`: A pointer to the public key used for verification.
    - `m_seq`: A 64-bit sequence number used for managing request order and backpressure checks.
    - `m_chunk`: A 32-bit chunk identifier for the message.
    - `m_ctrl`: A 16-bit control parameter for the request.
    - `m_sz`: A 16-bit size parameter for the request.
- **Control Flow**:
    - Initialize the PCIe slot and source variables from the workspace structure.
    - Check for backpressure every 16 requests by examining PCIe buffer levels and pending transactions.
    - If backpressure is detected, cycle through available PCIe slots to find one that is not backpressured.
    - If no suitable slot is found within the try limit, return -1 indicating a timeout.
    - Calculate the DMA address using the sequence number and request depth.
    - Prepare the stream buffer with magic numbers, size, control, DMA address, sequence number, and chunk information.
    - Stream the prepared buffer to the PCIe slot using [`_wd_stream_256`](#_wd_stream_256).
    - Copy the signature and public key into the stream buffer and send them to the PCIe slot.
    - Iterate over the message in 32-byte chunks, copying each chunk into the stream buffer and sending it to the PCIe slot.
    - If the number of chunks is odd, send an additional empty buffer to pad the stream for 512-bit alignment.
    - Flush the write-combining buffers to ensure all data is sent.
    - Update the request slot in the workspace structure.
- **Output**: Returns 0 on success, or -1 if a timeout occurs due to backpressure.
- **Functions called**:
    - [`_wd_next_slot`](#_wd_next_slot)
    - [`_wd_read_32`](#_wd_read_32)
    - [`_wd_stream_256`](#_wd_stream_256)
    - [`_wd_stream_flush`](#_wd_stream_flush)


# Function Declarations (Public API)

---
### \_wd\_read\_32<!-- {{#callable_declaration:_wd_read_32}} -->
Reads a 32-bit value from a specified address on a PCI device.
- **Description**: This function retrieves a 32-bit value from a given address on a PCI device specified by the `pci` parameter. It is typically used when direct access to the PCI device's memory-mapped registers is required. The function assumes that the PCI device has been properly initialized and is ready for read operations. If the read operation fails, an error is logged, but the function still returns the value read from the address, which may be undefined in case of an error.
- **Inputs**:
    - `pci`: A pointer to a `wd_pci_t` structure representing the PCI device. Must not be null, and the device should be properly initialized before calling this function.
    - `addr`: A 32-bit unsigned integer representing the address to read from within the PCI device's memory space. The address should be valid and within the accessible range of the device.
- **Output**: Returns the 32-bit value read from the specified address. If the read operation fails, the returned value may be undefined.
- **See also**: [`_wd_read_32`](#_wd_read_32)  (Implementation)


---
### \_wd\_write\_32<!-- {{#callable_declaration:_wd_write_32}} -->
Writes a 32-bit value to a specified address on a PCI device.
- **Description**: Use this function to write a 32-bit value to a specific address on a PCI device represented by the `wd_pci_t` structure. This function is typically used in environments where direct interaction with PCI devices is required, such as in FPGA or other hardware interfacing applications. Ensure that the `wd_pci_t` structure is properly initialized and that the address is valid for the intended operation. This function does not perform any error checking on the address or the value being written.
- **Inputs**:
    - `pci`: A pointer to a `wd_pci_t` structure representing the PCI device. Must not be null and should be properly initialized before calling this function.
    - `addr`: A 32-bit unsigned integer representing the address on the PCI device where the value will be written. The address should be valid and within the range supported by the device.
    - `v`: A 32-bit unsigned integer representing the value to be written to the specified address on the PCI device.
- **Output**: None
- **See also**: [`_wd_write_32`](#_wd_write_32)  (Implementation)


---
### \_wd\_write\_256<!-- {{#callable_declaration:_wd_write_256}} -->
Writes 256 bytes of data to a specified offset in PCI memory.
- **Description**: This function is used to write a block of 256 bytes from a buffer to a specified offset in the PCI memory space associated with a given PCI device. It is typically used in scenarios where large data transfers to PCI devices are required, such as in high-performance computing or FPGA applications. The function assumes that the buffer contains at least 256 bytes of data and that the PCI device has been properly initialized and configured. The offset is specified in bytes and must be aligned to a 256-byte boundary for correct operation. The function does not perform any error checking on the input parameters, so it is the caller's responsibility to ensure that the inputs are valid.
- **Inputs**:
    - `pci`: A pointer to a wd_pci_t structure representing the PCI device. Must not be null and should be properly initialized before calling this function.
    - `off`: A 64-bit unsigned integer specifying the offset in the PCI memory space where the data should be written. Must be aligned to a 256-byte boundary.
    - `buf`: A pointer to a buffer containing at least 256 bytes of data to be written. Must not be null.
- **Output**: None
- **See also**: [`_wd_write_256`](#_wd_write_256)  (Implementation)


---
### \_wd\_stream\_256<!-- {{#callable_declaration:_wd_stream_256}} -->
Writes a 256-byte data block to a specified PCI slot stream.
- **Description**: This function is used to write a 256-byte block of data to a specific stream within a PCI slot in the workspace. It should be called when there is a need to transfer data to a PCI slot, ensuring that the workspace and slot are properly initialized and valid. The function handles the increment of the stream's address and automatically flushes the stream if certain conditions are met, such as reaching the maximum address or specific address boundaries. This ensures data integrity and proper stream management.
- **Inputs**:
    - `wd`: A pointer to a `wd_wksp_t` structure representing the workspace. It must be a valid, non-null pointer initialized with the PCI slots.
    - `slot`: An unsigned 32-bit integer representing the PCI slot index. It must be within the valid range of slots initialized in the workspace.
    - `buf`: A constant pointer to the data buffer containing the 256 bytes to be written. The buffer must not be null and should contain at least 256 bytes of data.
- **Output**: None
- **See also**: [`_wd_stream_256`](#_wd_stream_256)  (Implementation)


---
### \_wd\_stream\_flush<!-- {{#callable_declaration:_wd_stream_flush}} -->
Flushes the write-combining buffers for a specified PCIe slot.
- **Description**: This function is used to ensure that all previous writes to a PCIe slot are completed and visible to other components. It should be called when it is necessary to guarantee that all data has been written out from the write-combining buffers, typically after a series of write operations to a PCIe slot. This function does not perform any operations on the provided parameters and is safe to call with any values.
- **Inputs**:
    - `wd`: A pointer to a `wd_wksp_t` structure. The function does not use this parameter, so it can be any value, including null.
    - `slot`: A `uint32_t` representing the PCIe slot number. The function does not use this parameter, so it can be any value.
- **Output**: None
- **See also**: [`_wd_stream_flush`](#_wd_stream_flush)  (Implementation)


---
### \_wd\_next\_slot<!-- {{#callable_declaration:_wd_next_slot}} -->
Finds the next available PCI slot.
- **Description**: This function is used to find the next available PCI slot in a workspace, starting from a given slot index. It is useful when iterating over PCI slots to perform operations only on those that are available. The function will wrap around if it reaches the end of the slot list, ensuring that all slots are checked. It should be called when a valid workspace is initialized and the current slot index is known.
- **Inputs**:
    - `wd`: A pointer to a `wd_wksp_t` structure representing the workspace. Must not be null, and should be properly initialized before calling this function.
    - `slot`: A `uint32_t` representing the current slot index. It should be within the range of available slots, but the function will handle wrapping around if it exceeds the maximum slot index.
- **Output**: Returns a `uint32_t` representing the index of the next available PCI slot.
- **See also**: [`_wd_next_slot`](#_wd_next_slot)  (Implementation)



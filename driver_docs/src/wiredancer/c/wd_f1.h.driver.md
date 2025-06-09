# Purpose
This C header file, `wd_f1.h`, is part of a larger software system that interfaces with FPGA (Field-Programmable Gate Array) hardware, specifically for managing PCI (Peripheral Component Interconnect) resources and performing cryptographic operations using the ED25519 standard. The file defines data structures and function prototypes that facilitate the initialization, management, and utilization of PCI slots and streams, as well as the verification of digital signatures. The header includes several external libraries and headers, such as `fpga_pci.h` and `fpga_mgmt.h`, indicating its reliance on FPGA management and PCI handling functionalities. The file also defines constants and data structures like `wd_pci_t` and `wd_wksp_t` to manage PCI resources and workspace configurations.

The primary functionality provided by this header revolves around initializing and freeing PCI resources, resetting and sampling counters, reading counters and timestamps, and performing ED25519 signature verification. The functions [`wd_ed25519_verify_init_req`](#wd_ed25519_verify_init_req), [`wd_ed25519_verify_init_resp`](#wd_ed25519_verify_init_resp), and [`wd_ed25519_verify_req`](#wd_ed25519_verify_req) are particularly focused on setting up and executing the signature verification process, which is crucial for ensuring data integrity and authenticity in secure communications. This header file is intended to be included in other C source files, providing a public API for interacting with FPGA-based PCI resources and cryptographic verification processes.
# Imports and Dependencies

---
- `fcntl.h`
- `unistd.h`
- `stdio.h`
- `stdarg.h`
- `sys/mman.h`
- `immintrin.h`
- `fpga_pci.h`
- `fpga_mgmt.h`
- `utils/lcd.h`
- `fpga_mgmt_internal.h`
- `../../tango/mcache/fd_mcache.h`


# Data Structures

---
### wd\_pci\_st\_t
- **Type**: `struct`
- **Members**:
    - `a`: Represents the address in the PCI structure.
    - `b`: Represents the base in the PCI structure.
    - `m`: Represents the mask in the PCI structure.
- **Description**: The `wd_pci_st_t` structure is a simple data structure used to represent a PCI configuration with three 64-bit unsigned integer fields: `a`, `b`, and `m`. These fields are used to store the address, base, and mask values respectively, which are essential for configuring and managing PCI devices in a system. This structure is likely used in conjunction with other structures and functions to facilitate PCI operations in the context of the larger software system.


---
### wd\_pci\_t
- **Type**: `struct`
- **Members**:
    - `bar0`: A handle to the first PCI Base Address Register (BAR).
    - `bar4`: A handle to the fourth PCI Base Address Register (BAR).
    - `bar4_addr`: A pointer to the memory-mapped address of the fourth PCI BAR.
    - `stream`: An array of wd_pci_st_t structures representing PCI streams, with a size defined by WD_N_PCI_STREAMS.
- **Description**: The `wd_pci_t` structure is designed to manage and interact with PCI (Peripheral Component Interconnect) resources in a system. It includes handles to specific PCI Base Address Registers (BARs), which are used for memory-mapped I/O operations, and a pointer to the memory-mapped address of one of these BARs. Additionally, it contains an array of `wd_pci_st_t` structures, each representing a PCI stream, allowing for the management of multiple data streams through the PCI interface. This structure is likely used in conjunction with FPGA (Field-Programmable Gate Array) management, as suggested by the included headers and context.


---
### wd\_ed25519\_verify\_t
- **Type**: `struct`
- **Members**:
    - `req_slot`: A 32-bit unsigned integer representing the request slot.
    - `req_depth`: A 64-bit unsigned integer representing the request depth.
- **Description**: The `wd_ed25519_verify_t` structure is used to encapsulate information related to an ED25519 verification request in a hardware-accelerated environment. It contains two members: `req_slot`, which identifies the specific slot for the request, and `req_depth`, which indicates the depth or level of the request. This structure is likely used in conjunction with other components to manage and track the state of cryptographic verification operations.


---
### wd\_wksp\_t
- **Type**: `struct`
- **Members**:
    - `initialized`: Indicates whether the workspace has been initialized.
    - `pci_slots`: Stores the number of PCI slots available.
    - `stream_buf`: Pointer to a buffer for stream data.
    - `pci`: Array of wd_pci_t structures representing PCI configurations.
    - `sv`: Structure for ED25519 verification state.
- **Description**: The `wd_wksp_t` structure is a compound data type used to manage the state and configuration of a wiredancer workspace, particularly in relation to PCI and ED25519 verification operations. It includes an initialization flag, a count of PCI slots, a pointer to a stream buffer, an array of PCI configurations, and a structure for managing ED25519 verification requests. This structure is central to the operation of the wiredancer system, facilitating communication and data processing between the software and hardware components.


# Function Declarations (Public API)

---
### wd\_init\_pci<!-- {{#callable_declaration:wd_init_pci}} -->
Initialize PCI slots for a wiredancer workspace.
- **Description**: This function sets up the PCI slots for a given wiredancer workspace, configuring the necessary resources for each slot specified by the `slots` bitmask. It should be called to prepare the workspace for subsequent operations that require PCI access. The function maps a stream buffer and initializes the PCI bars and streams for each active slot. It returns an error if it fails to attach to any specified slot. Ensure that the workspace is properly allocated and that the `slots` parameter correctly represents the desired configuration before calling this function.
- **Inputs**:
    - `wd`: A pointer to a `wd_wksp_t` structure representing the wiredancer workspace. Must not be null, and the structure should be properly allocated and initialized before calling this function.
    - `slots`: A 64-bit integer bitmask indicating which PCI slots to initialize. Each bit corresponds to a slot, with a set bit indicating that the slot should be initialized. Only slots within the range of available slots (0 to 7) are valid.
- **Output**: Returns 0 on success, or -1 if an error occurs during the attachment of any specified PCI slot.
- **See also**: [`wd_init_pci`](wd_f1.c.driver.md#wd_init_pci)  (Implementation)


---
### wd\_free\_pci<!-- {{#callable_declaration:wd_free_pci}} -->
Releases resources associated with PCI in the workspace.
- **Description**: Use this function to release any resources or perform cleanup related to PCI that were previously initialized in the workspace. It should be called when the PCI resources are no longer needed, typically after operations requiring PCI access are complete. This function assumes that the workspace has been properly initialized and used, and it does not perform any validation or error checking on the input parameter.
- **Inputs**:
    - `wd`: A pointer to a `wd_wksp_t` structure representing the workspace. The workspace should have been previously initialized and used for PCI operations. The pointer must not be null, and the caller retains ownership of the memory.
- **Output**: Returns 0, indicating successful execution. No resources are actually freed in this implementation.
- **See also**: [`wd_free_pci`](wd_f1.c.driver.md#wd_free_pci)  (Implementation)


---
### wd\_rst\_cntrs<!-- {{#callable_declaration:wd_rst_cntrs}} -->
Reset the counters for a specified PCI slot.
- **Description**: This function is used to reset the counters associated with a specific PCI slot in the given workspace. It should be called when you need to clear the counter values for a particular slot, typically as part of a maintenance or initialization routine. The function checks if the specified slot is valid and active before attempting to reset the counters, ensuring that no operation is performed on inactive slots. This function does not perform any action if the slot is not active, making it safe to call without additional checks.
- **Inputs**:
    - `wd`: A pointer to a `wd_wksp_t` structure representing the workspace. This must not be null and should be properly initialized before calling this function.
    - `slot`: An unsigned 32-bit integer representing the PCI slot number. It should be within the range of available slots, and the function will only reset counters if the slot is active in the workspace.
- **Output**: None
- **See also**: [`wd_rst_cntrs`](wd_f1.c.driver.md#wd_rst_cntrs)  (Implementation)


---
### wd\_snp\_cntrs<!-- {{#callable_declaration:wd_snp_cntrs}} -->
Snapshots the counters for a specified PCI slot.
- **Description**: Use this function to snapshot the counters for a specific PCI slot within the workspace. It should be called when you need to capture the current state of the counters for a given slot. The function checks if the specified slot is active by verifying its presence in the `pci_slots` bitmask. If the slot is not active, the function returns immediately without making any changes. This function must be called with a valid `wd_wksp_t` structure that has been properly initialized and configured with active PCI slots.
- **Inputs**:
    - `wd`: A pointer to a `wd_wksp_t` structure representing the workspace. This must not be null and should be properly initialized with active PCI slots.
    - `slot`: An unsigned 32-bit integer representing the PCI slot to snapshot. The slot must be within the range of available slots and must be active in the `pci_slots` bitmask of the workspace.
- **Output**: None
- **See also**: [`wd_snp_cntrs`](wd_f1.c.driver.md#wd_snp_cntrs)  (Implementation)


---
### wd\_rd\_cntr<!-- {{#callable_declaration:wd_rd_cntr}} -->
Read a counter value from a specified PCI slot.
- **Description**: This function retrieves a counter value from a specified slot in the PCI configuration of a wiredancer workspace. It should be used when you need to access the counter value associated with a particular slot and counter index. The function checks if the specified slot is valid and enabled in the workspace's PCI slots before attempting to read the counter. If the slot is not enabled, the function returns 0. This function assumes that the workspace has been properly initialized and configured with valid PCI slots.
- **Inputs**:
    - `wd`: A pointer to a wd_wksp_t structure representing the wiredancer workspace. Must not be null and should be properly initialized.
    - `slot`: An unsigned 32-bit integer representing the PCI slot index to read from. Must be within the range of available slots and correspond to an enabled slot in the workspace.
    - `ci`: An unsigned 32-bit integer representing the counter index to read. The specific range or valid values for this parameter are not detailed in the header.
- **Output**: Returns the counter value as a 32-bit unsigned integer if the slot is enabled; otherwise, returns 0.
- **See also**: [`wd_rd_cntr`](wd_f1.c.driver.md#wd_rd_cntr)  (Implementation)


---
### wd\_rd\_ts<!-- {{#callable_declaration:wd_rd_ts}} -->
Reads a timestamp from a specified PCI slot.
- **Description**: This function retrieves a 64-bit timestamp from a specified PCI slot within the given workspace. It should be used when a timestamp is needed from a particular slot that is currently active. The function checks if the specified slot is valid and active by examining the `pci_slots` bitmask in the `wd_wksp_t` structure. If the slot is not active, the function returns 0. This function is typically called after the PCI slots have been initialized and configured.
- **Inputs**:
    - `wd`: A pointer to a `wd_wksp_t` structure representing the workspace. This must not be null and should be properly initialized before calling this function.
    - `slot`: A 32-bit unsigned integer representing the PCI slot number from which to read the timestamp. The slot number should correspond to an active slot as indicated by the `pci_slots` bitmask in the `wd_wksp_t` structure. If the slot is not active, the function returns 0.
- **Output**: Returns a 64-bit unsigned integer representing the timestamp read from the specified PCI slot, or 0 if the slot is not active.
- **See also**: [`wd_rd_ts`](wd_f1.c.driver.md#wd_rd_ts)  (Implementation)


---
### wd\_zprintf<!-- {{#callable_declaration:wd_zprintf}} -->
Formats and prints a string with zeroes replaced by underscores.
- **Description**: This function is used to format a string according to a specified format and variable arguments, replacing all occurrences of the character '0' with '_', and then printing the result to the standard output. It is useful when you need to ensure that zeroes in the formatted output are visually distinct or replaced for readability or other purposes. The function handles up to 511 characters of formatted output, as it uses a fixed-size buffer, and any additional characters are truncated. It should be used when the formatted string is expected to fit within this limit.
- **Inputs**:
    - `format`: A C string that contains the text to be written, optionally containing embedded format specifiers that are replaced by the values specified in subsequent additional arguments. Must not be null.
    - `...`: A variable number of arguments, each containing data to be formatted and inserted in the resulting string according to the format specifiers in the format string. The number and types of these arguments must match the format specifiers.
- **Output**: None
- **See also**: [`wd_zprintf`](wd_f1.c.driver.md#wd_zprintf)  (Implementation)


---
### wd\_ed25519\_verify\_init\_req<!-- {{#callable_declaration:wd_ed25519_verify_init_req}} -->
Initialize the internal state for ED25519 verification request processing.
- **Description**: This function sets up the internal state necessary for processing ED25519 verification requests. It should be called before any verification requests are made to ensure that the workspace is properly configured. The function configures the request slot and depth, and sets up the necessary PCI slots for communication. It is important to ensure that the workspace pointer is valid and that the memory cache address is correctly mapped to physical memory. The function does not perform any input validation, so care must be taken to provide valid parameters.
- **Inputs**:
    - `wd`: A pointer to a wd_wksp_t structure representing the workspace. Must not be null. The caller retains ownership.
    - `send_fails`: A uint8_t value indicating the number of send failures to be configured. Valid range is 0 to 255.
    - `mcache_depth`: A uint64_t value representing the depth of the memory cache. Must be a valid non-zero value.
    - `mcache_addr`: A pointer to the memory cache address. Must be a valid address that can be mapped to physical memory. The caller retains ownership.
- **Output**: None
- **See also**: [`wd_ed25519_verify_init_req`](wd_f1.c.driver.md#wd_ed25519_verify_init_req)  (Implementation)


---
### wd\_ed25519\_verify\_init\_resp<!-- {{#callable_declaration:wd_ed25519_verify_init_resp}} -->
Initialize the internal state of the response path for ED25519 verification.
- **Description**: This function is used to set up the internal state necessary for handling responses in the ED25519 verification process. It should be called after the workspace has been properly initialized and before any response handling operations are performed. This function does not perform any operations on the workspace other than initialization, and it does not return any value or modify any input parameters.
- **Inputs**:
    - `wd`: A pointer to a `wd_wksp_t` structure representing the workspace. The workspace must be initialized before calling this function. The pointer must not be null, and the caller retains ownership of the workspace.
- **Output**: None
- **See also**: [`wd_ed25519_verify_init_resp`](wd_f1.c.driver.md#wd_ed25519_verify_init_resp)  (Implementation)


---
### wd\_ed25519\_verify\_req<!-- {{#callable_declaration:wd_ed25519_verify_req}} -->
Sends a verification request to hardware to verify a message using the ED25519 standard.
- **Description**: This function is used to send a request to the underlying hardware to verify a message's signature using the ED25519 cryptographic standard. It should be called when you need to verify a message's authenticity and integrity against a given signature and public key. The function blocks until the request can be sent, and it assumes that the message, signature, and public key are correctly formatted and aligned in memory. The function does not perform input validation, so it is the caller's responsibility to ensure that the inputs are valid. The function returns zero on success, indicating that the request was successfully sent to the hardware.
- **Inputs**:
    - `wd`: A pointer to a wd_wksp_t structure representing the workspace. The workspace must be properly initialized before calling this function.
    - `msg`: A pointer to the message data to be verified. It must point to a memory region of at least 'sz' bytes. If 'sz' is zero, 'msg' can be NULL.
    - `sz`: The size of the message in bytes. It can be zero, in which case 'msg' can be NULL.
    - `sig`: A pointer to a 64-byte memory region containing the signature of the message. Must not be NULL.
    - `public_key`: A pointer to a 32-byte memory region containing the public key used for verification. Must not be NULL.
    - `m_seq`: A 64-bit sequence number used for managing request ordering. It is used internally and should be unique for each request.
    - `m_chunk`: A 32-bit value representing the chunk of the message being processed. It is used internally for managing data chunks.
    - `m_ctrl`: A 16-bit control value indicating the start and end of packet boundaries. The lower bit indicates the start of packet, and the next bit indicates the end of packet.
    - `m_sz`: A 16-bit value representing the size of the message chunk. It is used internally for managing data sizes.
- **Output**: Returns zero on success, indicating the request was successfully sent to the hardware. Returns -1 if the request could not be sent due to backpressure or other issues.
- **See also**: [`wd_ed25519_verify_req`](wd_f1.c.driver.md#wd_ed25519_verify_req)  (Implementation)



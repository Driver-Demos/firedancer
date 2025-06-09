# Purpose
The provided C header file, `fd_pcapng.h`, defines an interface for working with the PCAP Next Generation (pcapng) file format, which is used for storing packet capture data. This file is part of a library that facilitates reading from and writing to pcapng files, offering functionality to handle packet data, metadata, and decryption secrets. The library is designed to be robust against malicious inputs but is not optimized for high-performance packet capture, making it unsuitable for capturing packets at line rate. The file includes definitions for structures and functions that manage pcapng iterators, frames, and options for section header blocks (SHB) and interface description blocks (IDB).

Key components of this header file include the `fd_pcapng_iter_t` structure, which represents an iterator for reading pcapng files, and the `fd_pcapng_frame_t` structure, which encapsulates a generalized frame read from a pcapng file. The file provides a set of functions for creating and managing iterators, reading frames, and writing various blocks to pcapng files, such as SHB, IDB, and Enhanced Packet Blocks (EPB). It also includes macros for defining frame types and link types, as well as functions for handling default options based on the system environment. The API is designed to be used in a hosted environment, with certain functions conditionally compiled based on the availability of hosted features.
# Imports and Dependencies

---
- `../fd_util_base.h`


# Global Variables

---
### fd\_pcapng\_iter\_new
- **Type**: `fd_pcapng_iter_t *`
- **Description**: The `fd_pcapng_iter_new` is a function that returns a pointer to a `fd_pcapng_iter_t`, which is an opaque handle for iterating over a pcapng file. This function initializes a new iterator using a provided memory region and a file stream that is positioned at the start of a pcapng section header block.
- **Use**: This function is used to create an iterator for reading pcapng files, allowing sequential access to frames within the file.


---
### fd\_pcapng\_iter\_delete
- **Type**: `function pointer`
- **Description**: `fd_pcapng_iter_delete` is a function that takes a pointer to an `fd_pcapng_iter_t` structure and returns a void pointer. This function is responsible for destroying an `fd_pcapng_iter_t` iterator, effectively cleaning up resources associated with the iterator and returning the underlying memory region to the caller.
- **Use**: This function is used to properly dispose of an `fd_pcapng_iter_t` iterator, allowing the caller to regain ownership of the memory and stream handle.


---
### fd\_pcapng\_iter\_next
- **Type**: `fd_pcapng_frame_t *`
- **Description**: The `fd_pcapng_iter_next` function is a global function that returns a pointer to a `fd_pcapng_frame_t` structure. This structure represents a generalized frame read from a pcapng file, which can be a packet or metadata. The function is used to extract the next frame from a pcapng stream, returning NULL on failure or end of the file.
- **Use**: This function is used to iterate over frames in a pcapng file, providing access to each frame's data and metadata sequentially.


# Data Structures

---
### fd\_pcapng\_iter\_t
- **Type**: `struct`
- **Members**:
    - `fd_pcapng_iter_t`: An opaque handle for iterating over pcapng files.
- **Description**: The `fd_pcapng_iter_t` is an opaque data structure used to iterate over pcapng files, which are packet capture files with additional features like embedded encryption secrets. This iterator is designed to read pcapng files, providing a mechanism to extract frames, which can be packets or metadata, from the file stream. The structure is part of a library that supports little-endian pcapng files and is not optimized for high-performance packet capture, focusing instead on robustness against malicious inputs.


---
### fd\_pcapng\_frame
- **Type**: `struct`
- **Members**:
    - `ts`: Time in nanoseconds, matching fd_log_wallclock.
    - `type`: Packet type identifier.
    - `data_sz`: Size of the data array.
    - `orig_sz`: Original packet size, which is greater than or equal to data_sz.
    - `if_idx`: Index of the network interface.
    - `data`: Array holding the frame data, with a maximum size defined by FD_PCAPNG_FRAME_SZ.
- **Description**: The `fd_pcapng_frame` structure is used to represent a generalized frame read from a pcapng file, which is typically a packet but can also include metadata. It includes a timestamp (`ts`) for when the frame was captured, a `type` to specify the kind of packet, and size fields (`data_sz` and `orig_sz`) to describe the data's size and the original packet size, respectively. The `if_idx` field indicates the interface index, and the `data` array holds the actual frame data, with a maximum size of 16384 bytes. This structure is part of a library for handling pcapng files, which are used for packet captures and support additional features like embedded encryption secrets.


---
### fd\_pcapng\_frame\_t
- **Type**: `struct`
- **Members**:
    - `ts`: Time in nanoseconds, matching fd_log_wallclock.
    - `type`: Packet type identifier.
    - `data_sz`: Size of the data array.
    - `orig_sz`: Original packet size, which is greater than or equal to data_sz.
    - `if_idx`: Index of the interface from which the packet was captured.
    - `data`: Array containing the frame data, with a maximum size defined by FD_PCAPNG_FRAME_SZ.
- **Description**: The `fd_pcapng_frame_t` structure represents a generalized frame read from a pcapng file, which is typically a packet but can also include metadata. It includes a timestamp, packet type, data size, original packet size, interface index, and an array to hold the frame data. This structure is used to encapsulate the details of a packet or metadata extracted from a pcapng stream, facilitating the processing and analysis of network captures.


---
### fd\_pcapng\_shb\_opts
- **Type**: `struct`
- **Members**:
    - `hardware`: Generic name of the machine performing capture, e.g., 'x86_64 Server'.
    - `os`: Operating system or distribution name.
    - `userappl`: Name of the program performing the capture, e.g., 'Firedancer'.
- **Description**: The `fd_pcapng_shb_opts` structure is used to store optional metadata for a Section Header Block (SHB) in the pcapng file format, which is a format for packet captures. This structure includes fields for specifying the hardware, operating system, and application name associated with the capture process. These fields are optional and provide context about the environment in which the packet capture was performed, enhancing the interpretability of the capture data.


---
### fd\_pcapng\_shb\_opts\_t
- **Type**: `struct`
- **Members**:
    - `hardware`: Generic name of the machine performing the capture, such as 'x86_64 Server'.
    - `os`: Name of the operating system or distribution.
    - `userappl`: Name of the program performing the capture, e.g., 'Firedancer'.
- **Description**: The `fd_pcapng_shb_opts_t` structure is used to store optional metadata for a Section Header Block (SHB) in the pcapng file format, which is used for packet captures. This structure includes fields for specifying the hardware, operating system, and application name associated with the capture, providing context and additional information about the environment in which the capture was performed. These fields are optional and their absence is implied by zero.


---
### fd\_pcapng\_idb\_opts
- **Type**: `struct`
- **Members**:
    - `name`: Name of the network interface in the operating system, stored as a character array of length 16.
    - `ip4_addr`: IPv4 address in big endian order, stored as an unsigned character array of length 4.
    - `mac_addr`: MAC address, stored as an unsigned character array of length 6.
    - `tsresol`: Timestamp resolution, represented as an unsigned character.
    - `hardware`: Name of the network interface hardware, stored as a character array of length 64.
- **Description**: The `fd_pcapng_idb_opts` structure is used to define options for an Interface Description Block (IDB) in the pcapng file format, which is used for packet captures. It includes fields for storing the name of the network interface, its IPv4 and MAC addresses, the timestamp resolution, and the hardware name. This structure is part of a library that supports reading and writing pcapng files, which are used to capture network traffic with additional features like embedded encryption secrets.


---
### fd\_pcapng\_idb\_opts\_t
- **Type**: `struct`
- **Members**:
    - `name`: Name of network interface in OS.
    - `ip4_addr`: IPv4 address in big endian order.
    - `mac_addr`: MAC address of the network interface.
    - `tsresol`: Timestamp resolution setting.
    - `hardware`: Name of network interface hardware.
- **Description**: The `fd_pcapng_idb_opts_t` structure is used to define options for the Interface Description Block (IDB) in the pcapng file format. It includes fields for specifying the network interface's name, IPv4 address, MAC address, timestamp resolution, and hardware name. These options provide metadata about the network interface used during packet capture, which can be embedded in pcapng files to describe the capture environment.


# Functions

---
### fd\_pcapng\_is\_pkt<!-- {{#callable:fd_pcapng_is_pkt}} -->
The function `fd_pcapng_is_pkt` checks if a given frame is a regular captured packet by evaluating its type.
- **Inputs**:
    - `frame`: A pointer to a constant `fd_pcapng_frame_t` structure representing a frame read from a pcapng file.
- **Control Flow**:
    - Retrieve the `type` field from the `frame` structure.
    - Check if the `type` is equal to `FD_PCAPNG_FRAME_SIMPLE` or `FD_PCAPNG_FRAME_ENHANCED`.
    - Return 1 if the type matches either of these values, indicating the frame is a regular packet; otherwise, return 0.
- **Output**: An integer value, 1 if the frame is a regular packet (either simple or enhanced), and 0 if it is not.


# Function Declarations (Public API)

---
### fd\_pcapng\_iter\_align<!-- {{#callable_declaration:fd_pcapng_iter_align}} -->
Return the alignment requirement for a pcapng iterator.
- **Description**: This function provides the alignment requirement for a memory region that will be used to create a pcapng iterator. It is useful when allocating memory for a pcapng iterator to ensure that the memory is correctly aligned, which is necessary for the iterator to function properly. This function should be called before allocating memory for a pcapng iterator to determine the correct alignment.
- **Inputs**: None
- **Output**: Returns the alignment requirement as an unsigned long integer.
- **See also**: [`fd_pcapng_iter_align`](fd_pcapng.c.driver.md#fd_pcapng_iter_align)  (Implementation)


---
### fd\_pcapng\_iter\_footprint<!-- {{#callable_declaration:fd_pcapng_iter_footprint}} -->
Return the memory footprint of a pcapng iterator.
- **Description**: Use this function to determine the size of memory required to store an instance of a pcapng iterator. This is useful when allocating memory for creating a new iterator with fd_pcapng_iter_new. The function does not require any parameters and can be called at any time to retrieve the constant size of the iterator structure.
- **Inputs**: None
- **Output**: The function returns an unsigned long representing the size in bytes of the fd_pcapng_iter_t structure.
- **See also**: [`fd_pcapng_iter_footprint`](fd_pcapng.c.driver.md#fd_pcapng_iter_footprint)  (Implementation)


---
### fd\_pcapng\_iter\_new<!-- {{#callable_declaration:fd_pcapng_iter_new}} -->
Create a new pcapng iterator for reading a pcapng file.
- **Description**: This function initializes a pcapng iterator using a provided memory region and a file stream. The memory region must be non-null, properly aligned, and meet the footprint requirements for an fd_pcapng_iter_t. The file stream should be non-null and positioned at the start of a pcapng section header block. The function returns a pointer to the initialized iterator on success, or NULL if any preconditions are not met or if the file does not start with a valid section header block. It is important to ensure that the file is in the correct format and version, as unsupported versions will result in a failure.
- **Inputs**:
    - `mem`: A non-null pointer to a memory region that must be aligned according to fd_pcapng_iter_t's alignment requirements. The caller retains ownership of this memory.
    - `file`: A non-null pointer to a file stream that should be positioned at the start of a pcapng section header block. The caller retains ownership of the file stream.
- **Output**: Returns a pointer to an fd_pcapng_iter_t on success, or NULL on failure.
- **See also**: [`fd_pcapng_iter_new`](fd_pcapng.c.driver.md#fd_pcapng_iter_new)  (Implementation)


---
### fd\_pcapng\_iter\_delete<!-- {{#callable_declaration:fd_pcapng_iter_delete}} -->
Destroys a pcapng iterator and returns the underlying memory region.
- **Description**: Use this function to properly dispose of a pcapng iterator when it is no longer needed. This function should be called to clean up resources associated with the iterator, ensuring that the memory allocated for it is returned to the caller. It is important to call this function to avoid memory leaks. The caller regains ownership of the memory region after the function is called.
- **Inputs**:
    - `iter`: A pointer to the fd_pcapng_iter_t iterator to be destroyed. Must not be null. The function will zero out the memory occupied by the iterator.
- **Output**: Returns a pointer to the underlying memory region that was used by the iterator, allowing the caller to reuse or free it as needed.
- **See also**: [`fd_pcapng_iter_delete`](fd_pcapng.c.driver.md#fd_pcapng_iter_delete)  (Implementation)


---
### fd\_pcapng\_iter\_next<!-- {{#callable_declaration:fd_pcapng_iter_next}} -->
Extracts the next frame from a pcapng stream.
- **Description**: Use this function to retrieve the next frame from a pcapng file stream using an iterator. It should be called repeatedly to iterate over all frames in the stream. The function returns a pointer to a frame descriptor on success, or NULL if the end of the section or file is reached, or if an error occurs. Errors are logged with warnings, and the last error code can be retrieved using fd_pcapng_iter_err. The returned frame and its data are stored in a thread-local memory region, which remains valid until the next call to this function or until the iterator is deleted.
- **Inputs**:
    - `iter`: A pointer to an fd_pcapng_iter_t structure, which must be initialized and associated with a valid pcapng file stream. The iterator must not be NULL, and it retains ownership of the stream.
- **Output**: Returns a pointer to an fd_pcapng_frame_t structure containing the frame data on success, or NULL on failure or end of file.
- **See also**: [`fd_pcapng_iter_next`](fd_pcapng.c.driver.md#fd_pcapng_iter_next)  (Implementation)


---
### fd\_pcapng\_iter\_err<!-- {{#callable_declaration:fd_pcapng_iter_err}} -->
Retrieve the last error encountered by the pcapng iterator.
- **Description**: Use this function to obtain the last error code encountered by a pcapng iterator during operations such as reading frames. This is useful for diagnosing issues when iterating over a pcapng file, especially after a failure in functions like `fd_pcapng_iter_next`. The function should be called with a valid iterator that has been previously initialized. It does not modify the iterator or any other state.
- **Inputs**:
    - `iter`: A pointer to a constant `fd_pcapng_iter_t` structure representing the pcapng iterator. This must not be null and should be a valid iterator that has been initialized and possibly used in previous operations.
- **Output**: Returns an integer representing the last error code encountered by the iterator. The error codes are based on `fd_io` error codes.
- **See also**: [`fd_pcapng_iter_err`](fd_pcapng.c.driver.md#fd_pcapng_iter_err)  (Implementation)


---
### fd\_pcapng\_shb\_defaults<!-- {{#callable_declaration:fd_pcapng_shb_defaults}} -->
Sets default options for a Section Header Block based on the system environment.
- **Description**: This function initializes the fields of a `fd_pcapng_shb_opts_t` structure with default values that are determined by the current system environment. It should be called with a pre-initialized `fd_pcapng_shb_opts_t` structure to populate its fields with default hardware, operating system, and application name information. This is useful for setting up a pcapng Section Header Block with system-specific defaults before writing it to a file.
- **Inputs**:
    - `opt`: A pointer to a `fd_pcapng_shb_opts_t` structure that must be initialized before calling this function. The function will populate this structure with default values. The pointer must not be null.
- **Output**: None
- **See also**: [`fd_pcapng_shb_defaults`](fd_pcapng.c.driver.md#fd_pcapng_shb_defaults)  (Implementation)


---
### fd\_pcapng\_fwrite\_shb<!-- {{#callable_declaration:fd_pcapng_fwrite_shb}} -->
Writes a Section Header Block (SHB) to a pcapng file stream.
- **Description**: This function writes a little-endian pcapng Section Header Block (SHB) version 1.0 to the specified file stream. It is typically used at the beginning of a pcapng file to define a new section, and multiple SHBs can be included in a single file. The function accepts optional metadata about the hardware, operating system, and application, which can be embedded in the SHB. The caller must ensure that the file stream is aligned to a 4-byte boundary, as the function writes data in multiples of 4 bytes. The function returns the number of SHBs written, which should be 1 on success and 0 on failure.
- **Inputs**:
    - `opt`: A pointer to a `fd_pcapng_shb_opts_t` structure containing optional metadata for the SHB. This parameter can be NULL, in which case no additional metadata is included.
    - `file`: A pointer to a file stream where the SHB will be written. This must be a valid, open file stream, and the caller is responsible for ensuring 4-byte alignment of the stream pointer.
- **Output**: Returns the number of SHBs written, which is 1 on success and 0 on failure.
- **See also**: [`fd_pcapng_fwrite_shb`](fd_pcapng.c.driver.md#fd_pcapng_fwrite_shb)  (Implementation)


---
### fd\_pcapng\_idb\_defaults<!-- {{#callable_declaration:fd_pcapng_idb_defaults}} -->
Stores default options for an IDB based on the system environment.
- **Description**: This function initializes the provided `fd_pcapng_idb_opts_t` structure with default values for an Interface Description Block (IDB) using the system environment. It requires a valid network interface index, `if_idx`, which is specific to the operating system and unrelated to the PCAPNG interface index. The function should be called when you need to populate an IDB with system-specific defaults before writing it to a pcapng file. It returns 0 on success and -1 on failure, with failure reasons logged. On failure, the `opt` structure may be partially written.
- **Inputs**:
    - `opt`: A pointer to an `fd_pcapng_idb_opts_t` structure where default options will be stored. Must not be null. The structure is partially written on failure.
    - `if_idx`: An unsigned integer representing the operating system's network interface index. Must be a valid index for the function to succeed.
- **Output**: Returns 0 on success and -1 on failure. On failure, the `opt` structure may be partially written, and reasons for failure are logged.
- **See also**: [`fd_pcapng_idb_defaults`](fd_pcapng.c.driver.md#fd_pcapng_idb_defaults)  (Implementation)


---
### fd\_pcapng\_fwrite\_idb<!-- {{#callable_declaration:fd_pcapng_fwrite_idb}} -->
Writes an Interface Description Block (IDB) to a pcapng file stream.
- **Description**: This function is used to write an Interface Description Block (IDB) to a pcapng file stream, typically following a Section Header Block (SHB). It is essential for defining the characteristics of the network interface used in the capture. The function requires a valid link type and a file stream pointer. Optional interface description options can be provided, but the timestamp resolution option is ignored as the function always writes a resolution of nanoseconds. The function returns the number of blocks written, which should be 1 on success.
- **Inputs**:
    - `link_type`: Specifies the type of link layer for the interface. Must be one of the predefined FD_PCAPNG_LINKTYPE_* constants, such as FD_PCAPNG_LINKTYPE_ETHERNET.
    - `opt`: Pointer to a fd_pcapng_idb_opts_t structure containing optional interface description options. Can be NULL, in which case no additional options are written.
    - `file`: Pointer to a file stream where the IDB will be written. Must not be NULL and should be properly aligned to 4-byte boundaries.
- **Output**: Returns the number of IDBs written to the file, which should be 1 on success and 0 on failure.
- **See also**: [`fd_pcapng_fwrite_idb`](fd_pcapng.c.driver.md#fd_pcapng_fwrite_idb)  (Implementation)


---
### fd\_pcapng\_fwrite\_pkt<!-- {{#callable_declaration:fd_pcapng_fwrite_pkt}} -->
Writes an Enhanced Packet Block (EPB) to a pcapng file.
- **Description**: This function is used to write an Enhanced Packet Block (EPB) to a pcapng file, which is a format for storing packet capture data. It should be called when you want to log an Ethernet frame with a specific timestamp into a pcapng file. The function requires the file stream to be aligned to a 4-byte boundary before calling. It returns the number of packets written, which should be 1 on success, and 0 on failure. The function handles alignment and padding of the payload to ensure proper formatting in the pcapng file.
- **Inputs**:
    - `ts`: The timestamp in nanoseconds when the packet was captured. It should be a valid long integer representing the time.
    - `payload`: A pointer to the payload data of the packet. This must not be null and should point to a valid memory region containing the packet data.
    - `payload_sz`: The size of the payload in bytes. It should be a non-negative ulong value representing the length of the data pointed to by payload.
    - `file`: A pointer to a FILE object representing the open pcapng file stream. The stream must be aligned to a 4-byte boundary, and the caller retains ownership of the file pointer.
- **Output**: Returns 1 on successful writing of the packet, or 0 if an error occurs during the write process.
- **See also**: [`fd_pcapng_fwrite_pkt`](fd_pcapng.c.driver.md#fd_pcapng_fwrite_pkt)  (Implementation)


---
### fd\_pcapng\_fwrite\_tls\_key\_log<!-- {{#callable_declaration:fd_pcapng_fwrite_tls_key_log}} -->
Writes TLS key log information to a PCAPNG file.
- **Description**: This function writes TLS key log information to a PCAPNG file using a Decryption Secrets Block (DSB). It should be used when you need to embed TLS decryption secrets into a PCAPNG file for later analysis. The function requires the file stream to be aligned to a 4-byte boundary before calling. It returns 1 on success and 0 on failure, where failure can occur due to issues with writing to the file stream. The function assumes the log data is in ASCII format and handles necessary padding to maintain alignment.
- **Inputs**:
    - `log`: Pointer to the first byte of the NSS key log in ASCII format. The caller retains ownership and it must not be null.
    - `log_sz`: The size in bytes of the log data. It must accurately reflect the size of the data pointed to by log.
    - `file`: A pointer to a file stream (e.g., a FILE* from fopen) where the TLS key log will be written. The stream must be aligned to a 4-byte boundary before calling this function.
- **Output**: Returns 1 on success and 0 on failure, indicating whether the TLS key log was successfully written to the file.
- **See also**: [`fd_pcapng_fwrite_tls_key_log`](fd_pcapng.c.driver.md#fd_pcapng_fwrite_tls_key_log)  (Implementation)



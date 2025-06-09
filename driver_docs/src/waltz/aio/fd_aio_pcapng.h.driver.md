# Purpose
This C header file defines the interface for a module that implements a Man-in-the-Middle (MitM) asynchronous I/O (aio) component, specifically designed to capture network packets and log them to a PCAPNG file. The `fd_aio_pcapng` structure acts as a transparent intermediary between a sender and receiver, capturing packets unidirectionally and allowing multiple writers to join the same PCAPNG stream on a single thread. The file provides function prototypes for starting a new PCAPNG section, joining and leaving the MitM object, and retrieving the base aio class for packet forwarding and logging. The design supports capturing traffic in a single direction, with the option to create a pair for duplex communication, and emphasizes thread safety by recommending local buffering and atomic writes for multi-threaded environments.
# Imports and Dependencies

---
- `fd_aio.h`


# Global Variables

---
### fd\_aio\_pcapng\_join
- **Type**: `fd_aio_pcapng_t *`
- **Description**: The `fd_aio_pcapng_join` function returns a pointer to an `fd_aio_pcapng_t` structure, which is used to configure a memory region for capturing and forwarding network traffic. This structure acts as a Man-in-the-Middle (MitM) that logs traffic to a PCAPNG stream while forwarding it to a specified destination.
- **Use**: This variable is used to initialize and return a configured `fd_aio_pcapng_t` structure for capturing and logging network traffic to a PCAPNG file.


---
### fd\_aio\_pcapng\_leave
- **Type**: `function pointer`
- **Description**: The `fd_aio_pcapng_leave` is a function that is used to leave or disconnect from the current join to a `fd_aio_pcapng_t` object. It is responsible for cleaning up or finalizing the connection to the 'man-in-the-middle' (MitM) object that was previously joined.
- **Use**: This function is used to properly disconnect and clean up resources associated with a `fd_aio_pcapng_t` object after its use.


---
### fd\_aio\_pcapng\_get\_aio
- **Type**: `FD_FN_CONST fd_aio_t const *`
- **Description**: The `fd_aio_pcapng_get_aio` function returns a pointer to the `fd_aio_t` base class of a `fd_aio_pcapng_t` instance. This function is used to access the base class functionality of the `fd_aio_pcapng_t` object, which is responsible for capturing and forwarding packets in a packet capture (PCAPNG) stream.
- **Use**: This function is used to retrieve the base class pointer from a `fd_aio_pcapng_t` instance, allowing for packet forwarding and logging in a PCAPNG stream.


# Data Structures

---
### fd\_aio\_pcapng
- **Type**: `struct`
- **Members**:
    - `local`: An abstract base class of type fd_aio_t.
    - `dst`: A constant pointer to an fd_aio_t, representing the destination in local address space.
    - `pcapng`: A pointer to a stream object, typically a FILE, used for packet capture.
- **Description**: The `fd_aio_pcapng` structure is designed to facilitate a man-in-the-middle (MitM) asynchronous I/O operation that captures network packets and writes them to a file in the PCAPNG format. It acts as an intermediary between a sender and receiver, allowing for the transparent capture of packets. The structure includes a local abstract base class, a destination pointer for local address space operations, and a stream object for handling the PCAPNG file output. This setup supports multiple writers on the same thread but does not support sharing across threads without additional buffering and synchronization.


---
### fd\_aio\_pcapng\_t
- **Type**: `struct`
- **Members**:
    - `local`: An abstract base class of type fd_aio_t.
    - `dst`: A pointer to an fd_aio_t object in the local address space.
    - `pcapng`: A pointer to a stream object, typically a FILE, for capturing packets.
- **Description**: The `fd_aio_pcapng_t` structure is designed to facilitate a Man-in-the-Middle (MitM) asynchronous I/O operation that transparently captures packets between a sender and receiver, logging them to a file in the PCAPNG format. It supports multiple writers on the same thread but does not support sharing across threads without additional buffering and atomic operations. The structure includes a local abstract base class, a destination pointer for forwarding traffic, and a stream object for logging the captured packets.


# Function Declarations (Public API)

---
### fd\_aio\_pcapng\_start<!-- {{#callable_declaration:fd_aio_pcapng_start}} -->
Start a new PCAPNG section and define an interface on the given stream.
- **Description**: This function initializes a new PCAPNG section by writing a Section Header Block (SHB) and an Interface Description Block (IDB) to the provided stream handle, which is typically a FILE. It is used when starting a new capture session on a PCAPNG stream. The function should be called before any packet data is written to ensure the stream is properly initialized. If the SHB and IDB have already been created by the caller, this function is optional. The function returns 1 on success, indicating that the section and interface were successfully written. On failure, it returns 0 and sets errno, leaving the stream state undefined.
- **Inputs**:
    - `pcapng`: A pointer to the stream handle where the PCAPNG section and interface will be written. This is typically a FILE. The caller retains ownership of the stream handle, and it must be valid and writable. Invalid or null pointers will result in a failure, returning 0.
- **Output**: Returns 1 on success, indicating successful initialization of the PCAPNG section and interface. Returns 0 on failure, with errno set to indicate the error.
- **See also**: [`fd_aio_pcapng_start`](fd_aio_pcapng.c.driver.md#fd_aio_pcapng_start)  (Implementation)


---
### fd\_aio\_pcapng\_start\_l3<!-- {{#callable_declaration:fd_aio_pcapng_start_l3}} -->
Starts a new PCAPNG section with a single interface for L3 traffic.
- **Description**: This function initializes a new PCAPNG section by writing a Section Header Block (SHB) and an Interface Description Block (IDB) to the provided PCAPNG stream handle, which is typically a FILE. It is used to set up the necessary headers for capturing network traffic in a PCAPNG format, specifically for Layer 3 (L3) traffic. This function should be called before any packet data is written to the stream. It returns a success indicator, and in case of failure, the stream state becomes undefined.
- **Inputs**:
    - `pcapng`: A pointer to the PCAPNG stream handle, typically a FILE. The caller retains ownership and must ensure it is a valid, writable stream. Invalid or null pointers will result in a failure return value.
- **Output**: Returns 1 on success, indicating that the SHB and IDB were successfully written. Returns 0 on failure, leaving the stream state undefined.
- **See also**: [`fd_aio_pcapng_start_l3`](fd_aio_pcapng.c.driver.md#fd_aio_pcapng_start_l3)  (Implementation)


---
### fd\_aio\_pcapng\_join<!-- {{#callable_declaration:fd_aio_pcapng_join}} -->
Formats a memory region for use as a packet capture and forwarding intermediary.
- **Description**: This function configures a memory region to act as a middleman (MitM) for capturing and forwarding network traffic. It should be used when you need to transparently capture packets between a sender and receiver while logging them to a specified stream. The function requires that the pcapng stream already has valid Section Header Block (SHB) and Interface Description Block (IDB) headers, which can be created using `fd_aio_pcapng_start`. This function is typically used in scenarios where packet capture is needed for analysis or logging purposes. It is important to ensure that the memory region provided meets the alignment and size requirements of `fd_aio_pcapng_t`.
- **Inputs**:
    - `mitm`: A pointer to a memory region that will be formatted as an `fd_aio_pcapng_t`. This region must meet the alignment and size requirements of `fd_aio_pcapng_t`. The caller retains ownership.
    - `dst`: A pointer to an `fd_aio_t` object representing the destination for forwarded traffic. Must not be null.
    - `pcapng`: A pointer to a stream object (typically a FILE) where captured packets will be logged. Must have valid SHB and IDB headers at the time of the call.
- **Output**: Returns a pointer to the configured `fd_aio_pcapng_t` object, which is ready to forward and log traffic.
- **See also**: [`fd_aio_pcapng_join`](fd_aio_pcapng.c.driver.md#fd_aio_pcapng_join)  (Implementation)


---
### fd\_aio\_pcapng\_leave<!-- {{#callable_declaration:fd_aio_pcapng_leave}} -->
Leaves the current join to the MitM object.
- **Description**: Use this function to properly disconnect from a previously joined fd_aio_pcapng_t object. It should be called when you no longer need to capture packets or forward traffic through the MitM object. Before calling this function, ensure that all other objects configured to send to the aio provided by this MitM are disconnected. This function will reset the destination and pcapng stream handle to NULL, effectively leaving the MitM object in a clean state for potential reuse or deallocation.
- **Inputs**:
    - `mitm`: A pointer to an fd_aio_pcapng_t object that was previously joined. This parameter must not be null and should be a valid MitM object that is currently in use. The function will handle the object by resetting its internal pointers, so ensure no other operations are performed on it after this call until it is properly reinitialized.
- **Output**: Returns a pointer to the fd_aio_pcapng_t object that was passed in, now with its internal state reset.
- **See also**: [`fd_aio_pcapng_leave`](fd_aio_pcapng.c.driver.md#fd_aio_pcapng_leave)  (Implementation)


---
### fd\_aio\_pcapng\_get\_aio<!-- {{#callable_declaration:fd_aio_pcapng_get_aio}} -->
Retrieve the base fd_aio interface from a MitM aio object.
- **Description**: Use this function to obtain the base fd_aio interface from a MitM aio object that is part of a packet capture setup. This is useful when you need to interact with the aio interface directly, such as sending packets through it. The returned interface is valid for the duration of the join, and packets sent through this interface will be logged to the associated pcapng stream. The function ensures that even if pcapng writes fail, packet forwarding will continue, and warnings will be logged.
- **Inputs**:
    - `mitm`: A pointer to a constant fd_aio_pcapng_t object. This object must have been properly initialized and joined using fd_aio_pcapng_join. The pointer must not be null.
- **Output**: A pointer to a constant fd_aio_t, representing the base aio interface of the given MitM aio object.
- **See also**: [`fd_aio_pcapng_get_aio`](fd_aio_pcapng.c.driver.md#fd_aio_pcapng_get_aio)  (Implementation)



# Purpose
This C header file, `fd_h2_rbuf_sock.h`, provides functionality for handling socket-based communication using a ring buffer structure, specifically `fd_h2_rbuf_t`. The file is designed to be included in other C source files and is conditionally compiled based on the presence of the `FD_H2_HAS_SOCKETS` macro, indicating that socket operations are supported. The primary purpose of this file is to facilitate efficient data transfer over sockets by preparing and committing data for sending and receiving operations using the `recvmsg` and `sendmsg` system calls. It defines several static inline functions that manage the preparation and commitment of data in the ring buffer, ensuring that data is correctly segmented and transferred between the buffer and the socket.

The key technical components of this file include functions like [`fd_h2_rbuf_prepare_recvmsg`](#fd_h2_rbuf_prepare_recvmsg), [`fd_h2_rbuf_commit_recvmsg`](#fd_h2_rbuf_commit_recvmsg), [`fd_h2_rbuf_recvmsg`](#fd_h2_rbuf_recvmsg), [`fd_h2_rbuf_prepare_sendmsg`](#fd_h2_rbuf_prepare_sendmsg), [`fd_h2_rbuf_commit_sendmsg`](#fd_h2_rbuf_commit_sendmsg), and [`fd_h2_rbuf_sendmsg`](#fd_h2_rbuf_sendmsg). These functions work together to handle the complexities of managing a circular buffer for socket communication, such as calculating available space, managing buffer wrap-around, and updating buffer pointers after data transfer. The use of `struct iovec` allows for efficient handling of non-contiguous memory segments, which is crucial for the ring buffer's operation. This header file does not define a public API or external interfaces directly but provides inline functions that can be used by other components of a larger system to implement socket communication using a ring buffer.
# Imports and Dependencies

---
- `fd_h2_rbuf.h`
- `errno.h`
- `sys/socket.h`


# Functions

---
### fd\_h2\_rbuf\_prepare\_recvmsg<!-- {{#callable:fd_h2_rbuf_prepare_recvmsg}} -->
The `fd_h2_rbuf_prepare_recvmsg` function prepares a receive message operation by setting up an iovec structure for a ring buffer, indicating where data can be received.
- **Inputs**:
    - `rbuf`: A pointer to an `fd_h2_rbuf_t` structure representing the ring buffer to be used for receiving data.
    - `iov`: An array of two `struct iovec` elements that will be populated with pointers and lengths indicating where data can be received in the ring buffer.
- **Control Flow**:
    - Retrieve pointers to the buffer start (`buf0`), buffer end (`buf1`), current low (`lo`), and high (`hi`) positions from the ring buffer structure.
    - Calculate the free size available in the ring buffer using [`fd_h2_rbuf_free_sz`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_free_sz) function.
    - If there is no free space (`free_sz` is zero), return 0 to indicate no iovec setup is possible.
    - If `lo` is less than or equal to `hi`, set up the first iovec to point from `hi` to the end of the buffer (`buf1`) with a length limited by the free size, and the second iovec to point from the start of the buffer (`buf0`) to `lo` with a length limited by the remaining free size.
    - If `lo` is greater than `hi`, set up the first iovec to point from `hi` with a length equal to the free size, and set the second iovec to have a base of `NULL` and length of 0.
    - Return 2 if both iovecs are used, or 1 if only the first iovec is used.
- **Output**: The function returns an `ulong` indicating the number of iovec structures that have been set up (either 1 or 2), or 0 if no space is available for receiving data.
- **Functions called**:
    - [`fd_h2_rbuf_free_sz`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_free_sz)


---
### fd\_h2\_rbuf\_commit\_recvmsg<!-- {{#callable:fd_h2_rbuf_commit_recvmsg}} -->
The function `fd_h2_rbuf_commit_recvmsg` updates the read buffer's high watermark and position after receiving a message into a ring buffer.
- **Inputs**:
    - `rbuf`: A pointer to an `fd_h2_rbuf_t` structure representing the ring buffer.
    - `iovec`: An array of two `struct iovec` elements representing the memory regions where data was received.
    - `sz`: The size in bytes of the data received.
- **Control Flow**:
    - Retrieve pointers to the start and end of the buffer from `rbuf`.
    - Extract the first and second `iovec` structures from the `iovec` array.
    - Increment the `hi_off` field of `rbuf` by `sz` to update the high watermark offset.
    - Check if `sz` is greater than the length of the first `iovec` (`iov0`).
    - If `sz` is greater than `iov0.iov_len`, set `rbuf->hi` to the base of the second `iovec` plus the remaining size after `iov0` is filled.
    - Otherwise, set `rbuf->hi` to the base of the first `iovec` plus `sz`.
    - If `rbuf->hi` equals `buf1`, wrap around and set `rbuf->hi` to `buf0`.
- **Output**: The function does not return a value; it modifies the `rbuf` structure in place.


---
### fd\_h2\_rbuf\_recvmsg<!-- {{#callable:fd_h2_rbuf_recvmsg}} -->
The `fd_h2_rbuf_recvmsg` function receives a message from a socket into a ring buffer, handling partial reads and updating the buffer state accordingly.
- **Inputs**:
    - `rbuf`: A pointer to an `fd_h2_rbuf_t` structure representing the ring buffer where the received data will be stored.
    - `sock`: An integer representing the socket file descriptor from which the message will be received.
    - `flags`: An integer representing the flags to be used with the `recvmsg` system call.
- **Control Flow**:
    - Prepare the iovec structures for receiving data by calling [`fd_h2_rbuf_prepare_recvmsg`](#fd_h2_rbuf_prepare_recvmsg) with the ring buffer and iovec array.
    - Check if the iovec count is zero, indicating no space is available in the buffer, and return 0 if true.
    - Initialize a `msghdr` structure with the prepared iovec array and its count.
    - Call `recvmsg` to receive data from the socket into the buffer using the `msghdr` structure.
    - If `recvmsg` returns a negative value, check if the error is `EAGAIN` and return 0 if true, otherwise return the error number.
    - If `recvmsg` returns zero, indicating the connection is closed, return `EPIPE`.
    - Commit the received data to the ring buffer by calling [`fd_h2_rbuf_commit_recvmsg`](#fd_h2_rbuf_commit_recvmsg) with the buffer, iovec array, and size of received data.
    - Return 0 to indicate successful reception and buffer update.
- **Output**: Returns 0 on successful reception and buffer update, 0 if no data is received due to `EAGAIN`, `EPIPE` if the connection is closed, or an error number if `recvmsg` fails with a different error.
- **Functions called**:
    - [`fd_h2_rbuf_prepare_recvmsg`](#fd_h2_rbuf_prepare_recvmsg)
    - [`fd_h2_rbuf_commit_recvmsg`](#fd_h2_rbuf_commit_recvmsg)


---
### fd\_h2\_rbuf\_prepare\_sendmsg<!-- {{#callable:fd_h2_rbuf_prepare_sendmsg}} -->
The function `fd_h2_rbuf_prepare_sendmsg` prepares a ring buffer for sending data by setting up an array of `iovec` structures to describe the data to be sent.
- **Inputs**:
    - `rbuf`: A pointer to an `fd_h2_rbuf_t` structure representing the ring buffer from which data is to be sent.
    - `iov`: An array of two `iovec` structures that will be populated to describe the data segments to be sent.
- **Control Flow**:
    - Retrieve pointers to the buffer start (`buf0`), buffer end (`buf1`), current low position (`lo`), and high position (`hi`) from the ring buffer structure.
    - Calculate the size of the data currently used in the buffer using [`fd_h2_rbuf_used_sz`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_used_sz) function.
    - If the used size is zero, return 0 indicating no data to send.
    - Check if the high position is less than or equal to the low position, indicating a wrap-around condition in the buffer.
    - If wrap-around is detected, set the first `iovec` to point from `lo` to the end of the buffer (`buf1`) and the second `iovec` from the start of the buffer (`buf0`) to `hi`, adjusting lengths accordingly.
    - If no wrap-around, set the first `iovec` to point from `lo` to `hi` and set the second `iovec` to zero length.
    - Return the number of `iovec` structures used (either 1 or 2).
- **Output**: The function returns an `ulong` indicating the number of `iovec` structures populated (either 1 or 2), or 0 if there is no data to send.
- **Functions called**:
    - [`fd_h2_rbuf_used_sz`](fd_h2_rbuf.h.driver.md#fd_h2_rbuf_used_sz)


---
### fd\_h2\_rbuf\_commit\_sendmsg<!-- {{#callable:fd_h2_rbuf_commit_sendmsg}} -->
The function `fd_h2_rbuf_commit_sendmsg` updates the read buffer's low offset and pointer after sending a message using a scatter-gather I/O vector.
- **Inputs**:
    - `rbuf`: A pointer to an `fd_h2_rbuf_t` structure representing the read buffer.
    - `iovec`: An array of two `struct iovec` elements representing the scatter-gather I/O vector used for sending data.
    - `sz`: An unsigned long integer representing the size of the data that was sent.
- **Control Flow**:
    - Retrieve the buffer pointers `buf0` and `buf1` from the `rbuf` structure.
    - Extract the first and second `iovec` elements into `iov0` and `iov1`.
    - Increment the `lo_off` field of `rbuf` by `sz`.
    - Check if `sz` is greater than the length of `iov0`.
    - If true, update `rbuf->lo` to point to the base of `iov1` plus the excess size over `iov0`'s length.
    - If false, update `rbuf->lo` to point to the base of `iov0` plus `sz`.
    - If `rbuf->lo` equals `buf1`, reset `rbuf->lo` to `buf0` to handle buffer wrapping.
- **Output**: The function does not return a value; it modifies the `rbuf` structure in place.


---
### fd\_h2\_rbuf\_sendmsg<!-- {{#callable:fd_h2_rbuf_sendmsg}} -->
The `fd_h2_rbuf_sendmsg` function sends data from a ring buffer to a socket using the `sendmsg` system call and updates the buffer state accordingly.
- **Inputs**:
    - `rbuf`: A pointer to an `fd_h2_rbuf_t` structure representing the ring buffer from which data is to be sent.
    - `sock`: An integer representing the socket file descriptor to which the data is to be sent.
    - `flags`: An integer representing flags that modify the behavior of the `sendmsg` system call.
- **Control Flow**:
    - Initialize an array of `iovec` structures to hold buffer segments for sending.
    - Call [`fd_h2_rbuf_prepare_sendmsg`](#fd_h2_rbuf_prepare_sendmsg) to prepare the `iovec` array with data from the ring buffer and get the count of segments to send.
    - If no segments are prepared (i.e., `iov_cnt` is zero), return 0 indicating no data to send.
    - Create a `msghdr` structure and set its `msg_iov` and `msg_iovlen` fields to the `iovec` array and its count, respectively.
    - Call `sendmsg` with the socket, message header, and flags to send the data.
    - If `sendmsg` returns a negative value, return the error number from `errno`.
    - Call [`fd_h2_rbuf_commit_sendmsg`](#fd_h2_rbuf_commit_sendmsg) to update the ring buffer state based on the number of bytes successfully sent.
    - Return 0 to indicate successful completion.
- **Output**: Returns 0 on success, or an error number if the `sendmsg` call fails.
- **Functions called**:
    - [`fd_h2_rbuf_prepare_sendmsg`](#fd_h2_rbuf_prepare_sendmsg)
    - [`fd_h2_rbuf_commit_sendmsg`](#fd_h2_rbuf_commit_sendmsg)



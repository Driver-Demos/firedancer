# Purpose
This C source code file is designed to test the functionality of writing and reading pcapng (Packet Capture Next Generation) files, which are used for storing network packet data. The file includes several static functions that test the writing of different types of pcapng blocks, such as Section Header Blocks (SHB), Interface Description Blocks (IDB), Enhanced Packet Blocks (EPB), and Decryption Secrets Blocks (DSB). These tests are performed using the `fmemopen` function to simulate file operations in memory, allowing for the verification of the correct writing of data structures to the pcapng format. The code also includes a "dogfood" test, which writes a series of pcapng blocks and then reads them back to ensure the integrity and correctness of the data handling.

The file is structured as an executable C program, with a [`main`](#main) function that initializes the environment, runs the various test functions, and then concludes with a log message indicating success. The code makes use of static assertions to ensure the correct layout of data structures, which is critical for maintaining compatibility with the pcapng format. The inclusion of header files such as "fd_pcapng.h" and "fd_pcapng_private.h" suggests that this file is part of a larger library or application focused on network packet analysis or capture. The file does not define public APIs or external interfaces directly but rather serves as a test suite to validate the functionality of the pcapng handling capabilities provided by the included headers.
# Imports and Dependencies

---
- `fd_pcapng.h`
- `fd_pcapng_private.h`
- `../fd_util.h`
- `stddef.h`
- `stdio.h`


# Functions

---
### test\_pcapng\_fwrite\_shb<!-- {{#callable:test_pcapng_fwrite_shb}} -->
The function `test_pcapng_fwrite_shb` tests the writing of a Section Header Block (SHB) to a memory buffer using the [`fd_pcapng_fwrite_shb`](fd_pcapng.c.driver.md#fd_pcapng_fwrite_shb) function.
- **Inputs**: None
- **Control Flow**:
    - Initialize a buffer `buf` of 512 bytes to zero and open it as a file stream `pcap` in write mode using `fmemopen`.
    - Check if the file stream `pcap` is successfully opened using `FD_TEST`.
    - Log the start of the Section Header Block test using `FD_LOG_INFO`.
    - Initialize `fd_pcapng_shb_opts_t` structure `opts` with hardware, OS, and user application information.
    - Call [`fd_pcapng_fwrite_shb`](fd_pcapng.c.driver.md#fd_pcapng_fwrite_shb) with `opts` and `pcap`, and verify it returns 1 using `FD_TEST`.
    - Get the current position in the file stream `pcap` using `ftell` and verify it is non-negative using `FD_TEST`.
    - Close the file stream `pcap` and verify it closes successfully using `FD_TEST`.
    - Log a hex dump of the buffer `buf` up to the position `pos` using `FD_LOG_HEXDUMP_INFO`.
- **Output**: The function does not return any value; it performs tests and logs results to verify the correct writing of a Section Header Block to a buffer.
- **Functions called**:
    - [`fd_pcapng_fwrite_shb`](fd_pcapng.c.driver.md#fd_pcapng_fwrite_shb)


---
### test\_pcapng\_fwrite\_idb<!-- {{#callable:test_pcapng_fwrite_idb}} -->
The function `test_pcapng_fwrite_idb` tests the writing of an Interface Description Block (IDB) to a memory buffer using the [`fd_pcapng_fwrite_idb`](fd_pcapng.c.driver.md#fd_pcapng_fwrite_idb) function.
- **Inputs**: None
- **Control Flow**:
    - Initialize a buffer `buf` of 512 bytes to zero and open it as a writable memory stream `pcap`.
    - Check if the `pcap` file stream is successfully opened using `FD_TEST`.
    - Log the start of the Interface Description Block test using `FD_LOG_INFO`.
    - Define and initialize an `fd_pcapng_idb_opts_t` structure `opts` with interface details such as name, IP address, MAC address, and hardware description.
    - Call [`fd_pcapng_fwrite_idb`](fd_pcapng.c.driver.md#fd_pcapng_fwrite_idb) with Ethernet link type and `opts`, and verify it returns 1 using `FD_TEST`.
    - Get the current position in the `pcap` stream using `ftell` and verify it is non-negative using `FD_TEST`.
    - Close the `pcap` stream and verify it closes successfully using `FD_TEST`.
    - Log a hex dump of the buffer `buf` up to the position `pos` using `FD_LOG_HEXDUMP_INFO`.
- **Output**: The function does not return any value; it performs tests and logs results to verify the correct writing of an IDB to a memory buffer.
- **Functions called**:
    - [`fd_pcapng_fwrite_idb`](fd_pcapng.c.driver.md#fd_pcapng_fwrite_idb)


---
### test\_pcapng\_fwrite\_pkt<!-- {{#callable:test_pcapng_fwrite_pkt}} -->
The function `test_pcapng_fwrite_pkt` tests the writing of a packet to a pcapng file using a memory buffer and verifies the operation's success.
- **Inputs**: None
- **Control Flow**:
    - Initialize a buffer `buf` of 512 bytes to zero and open it as a writable memory stream `pcap`.
    - Check if the `pcap` file stream is successfully opened using `FD_TEST`.
    - Log the start of the packet test with `FD_LOG_INFO`.
    - Define a timestamp `ts` and a packet `pkt` with specific byte values.
    - Call [`fd_pcapng_fwrite_pkt`](fd_pcapng.c.driver.md#fd_pcapng_fwrite_pkt) to write the packet to the `pcap` stream and verify the return value is 1 using `FD_TEST`.
    - Get the current position in the `pcap` stream using `ftell` and verify it is non-negative with `FD_TEST`.
    - Close the `pcap` stream and verify successful closure with `FD_TEST`.
    - Log a hex dump of the written data in the buffer using `FD_LOG_HEXDUMP_INFO`.
- **Output**: The function does not return any value; it performs tests and logs results to verify the packet writing process.
- **Functions called**:
    - [`fd_pcapng_fwrite_pkt`](fd_pcapng.c.driver.md#fd_pcapng_fwrite_pkt)


---
### test\_pcapng\_fwrite\_tls\_key\_log<!-- {{#callable:test_pcapng_fwrite_tls_key_log}} -->
The function `test_pcapng_fwrite_tls_key_log` tests the writing of a TLS key log entry to a pcapng file using a memory buffer.
- **Inputs**: None
- **Control Flow**:
    - Initialize a buffer `buf` of 512 bytes to zero.
    - Open a memory stream `pcap` using `fmemopen` with the buffer `buf` for writing in binary mode.
    - Check if the file stream `pcap` is successfully opened using `FD_TEST`.
    - Log the start of the TLS key log test using `FD_LOG_INFO`.
    - Define a constant character array `log` containing a TLS key log entry.
    - Call [`fd_pcapng_fwrite_tls_key_log`](fd_pcapng.c.driver.md#fd_pcapng_fwrite_tls_key_log) to write the TLS key log entry to the `pcap` stream and verify the return value is 1 using `FD_TEST`.
    - Get the current position in the `pcap` stream using `ftell` and verify it is non-negative using `FD_TEST`.
    - Close the `pcap` stream using `fclose` and verify it returns 0 using `FD_TEST`.
    - Log a hex dump of the buffer `buf` up to the position `pos` using `FD_LOG_HEXDUMP_INFO`.
- **Output**: The function does not return any value; it performs tests and logs information to verify the correct writing of a TLS key log entry to a pcapng file.
- **Functions called**:
    - [`fd_pcapng_fwrite_tls_key_log`](fd_pcapng.c.driver.md#fd_pcapng_fwrite_tls_key_log)


---
### test\_pcapng\_dogfood<!-- {{#callable:test_pcapng_dogfood}} -->
The function `test_pcapng_dogfood` writes a pcapng file to a memory buffer, reads it back to verify the contents, and logs the process.
- **Inputs**: None
- **Control Flow**:
    - Initialize a static buffer and open it as a file stream for writing and reading.
    - Log the start of the test with 'TEST: dogfood'.
    - Write a Section Header Block (SHB) with specified options to the pcapng file and log the position.
    - Write an Interface Description Block (IDB) with specified options to the pcapng file and log the position.
    - Write three Enhanced Packet Blocks (EPBs) with different packet data and log the positions after each write.
    - Write a Decryption Secrets Block (DSB) with a TLS key log and log the position.
    - Flush the file stream, log a hexdump of the buffer, and rewind the file stream for reading.
    - Initialize an iterator for reading the pcapng file and verify its alignment and size.
    - Iterate over the frames in the pcapng file, verifying the type and content of each frame against expected values.
    - Check for the end of the iteration and verify no errors occurred.
    - Write another SHB to the pcapng file to conclude the test.
- **Output**: The function does not return any value; it performs tests and logs results to verify the correctness of pcapng file writing and reading.
- **Functions called**:
    - [`fd_pcapng_fwrite_shb`](fd_pcapng.c.driver.md#fd_pcapng_fwrite_shb)
    - [`fd_pcapng_fwrite_idb`](fd_pcapng.c.driver.md#fd_pcapng_fwrite_idb)
    - [`fd_pcapng_fwrite_pkt`](fd_pcapng.c.driver.md#fd_pcapng_fwrite_pkt)
    - [`fd_pcapng_fwrite_tls_key_log`](fd_pcapng.c.driver.md#fd_pcapng_fwrite_tls_key_log)
    - [`fd_pcapng_iter_align`](fd_pcapng.c.driver.md#fd_pcapng_iter_align)
    - [`fd_pcapng_iter_footprint`](fd_pcapng.c.driver.md#fd_pcapng_iter_footprint)
    - [`fd_pcapng_iter_new`](fd_pcapng.c.driver.md#fd_pcapng_iter_new)
    - [`fd_pcapng_iter_next`](fd_pcapng.c.driver.md#fd_pcapng_iter_next)
    - [`fd_pcapng_is_pkt`](fd_pcapng.h.driver.md#fd_pcapng_is_pkt)
    - [`fd_pcapng_iter_err`](fd_pcapng.c.driver.md#fd_pcapng_iter_err)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, runs a series of tests on pcapng writing functions, logs a success message, and then halts the program.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments passed to the program.
- **Control Flow**:
    - Call `fd_boot` to initialize the environment with command-line arguments.
    - Execute [`test_pcapng_fwrite_shb`](#test_pcapng_fwrite_shb) to test writing a Section Header Block to a pcapng file.
    - Execute [`test_pcapng_fwrite_idb`](#test_pcapng_fwrite_idb) to test writing an Interface Description Block to a pcapng file.
    - Execute [`test_pcapng_fwrite_pkt`](#test_pcapng_fwrite_pkt) to test writing a packet to a pcapng file.
    - Execute [`test_pcapng_fwrite_tls_key_log`](#test_pcapng_fwrite_tls_key_log) to test writing a TLS key log to a pcapng file.
    - Execute [`test_pcapng_dogfood`](#test_pcapng_dogfood) to test writing and reading back a pcapng file.
    - Log a notice message indicating the tests passed.
    - Call `fd_halt` to clean up and terminate the program.
    - Return 0 to indicate successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution.
- **Functions called**:
    - [`test_pcapng_fwrite_shb`](#test_pcapng_fwrite_shb)
    - [`test_pcapng_fwrite_idb`](#test_pcapng_fwrite_idb)
    - [`test_pcapng_fwrite_pkt`](#test_pcapng_fwrite_pkt)
    - [`test_pcapng_fwrite_tls_key_log`](#test_pcapng_fwrite_tls_key_log)
    - [`test_pcapng_dogfood`](#test_pcapng_dogfood)



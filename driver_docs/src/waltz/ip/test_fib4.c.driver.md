# Purpose
This C source code file is an executable program designed to test and demonstrate the functionality of a Forwarding Information Base (FIB) for IPv4 routing, specifically using a library that provides FIB operations. The code includes the setup and manipulation of two FIB instances, `fib_local` and `fib_main`, which are used to simulate routing tables. The program initializes memory for these FIBs, populates them with routing entries, and performs lookup operations to verify the correct routing behavior. The code also includes a test function, [`test_fib_print`](#test_fib_print), which is used to validate the output of the FIB against expected results, ensuring that the FIB operations are functioning as intended.

The file includes both setup and teardown procedures for the FIB instances, ensuring that resources are properly allocated and freed. It uses a series of test cases to simulate real-world routing scenarios, such as local, broadcast, and unicast routes, and verifies the expected routing outcomes using assertions. The code is structured to run in a hosted environment, with conditional compilation to include necessary headers and functions for testing. This file serves as a comprehensive test suite for the FIB library, ensuring its reliability and correctness in handling IPv4 routing scenarios.
# Imports and Dependencies

---
- `fd_fib4.h`
- `../../util/fd_util.h`
- `../../util/net/fd_ip4.h`
- `stdio.h`


# Global Variables

---
### fib1\_mem
- **Type**: `uchar array`
- **Description**: The `fib1_mem` variable is a statically allocated array of unsigned characters (uchar) with a size of 4096 bytes. It is aligned according to the `FD_FIB4_ALIGN` specification, which is likely a macro defining the required memory alignment for the data structure it supports.
- **Use**: This variable is used as a memory buffer to store data for a Forwarding Information Base (FIB) structure, specifically for IPv4 routing information.


---
### fib2\_mem
- **Type**: `uchar array`
- **Description**: The `fib2_mem` variable is a static array of unsigned characters with a size of 4096 bytes, aligned according to the `FD_FIB4_ALIGN` macro. It is used to store memory for a Forwarding Information Base (FIB) structure, specifically for IPv4 routing information.
- **Use**: This variable is used to allocate and align memory for the `fd_fib4_t` structure, which is joined and manipulated in the main function to manage routing information.


# Functions

---
### test\_fib\_print<!-- {{#callable:test_fib_print}} -->
The `test_fib_print` function compares the string representation of a FIB (Forwarding Information Base) to an expected string and logs an error if they do not match.
- **Inputs**:
    - `fib`: A pointer to a constant `fd_fib4_t` structure representing the Forwarding Information Base to be printed.
    - `actual`: A constant character pointer to the expected string representation of the FIB.
- **Control Flow**:
    - A static buffer `dump_buf` of size 8192 is declared to hold the FIB's string representation.
    - A file stream `dump` is opened using `fmemopen` to write into `dump_buf`.
    - The function [`fd_fib4_fprintf`](fd_fib4.c.driver.md#fd_fib4_fprintf) is called to print the FIB into the `dump` stream, and its success is asserted using `FD_TEST`.
    - The size of the written data is determined using `ftell`, and the `dump` stream is closed.
    - The function checks if the content of `dump_buf` matches the `actual` string up to the size `sz` using `strncmp`.
    - If the strings do not match, the content of `dump_buf` is written to `stderr`, and an error is logged using `FD_LOG_ERR`.
- **Output**: The function does not return a value; it performs a side effect of logging an error if the FIB's string representation does not match the expected string.
- **Functions called**:
    - [`fd_fib4_fprintf`](fd_fib4.c.driver.md#fd_fib4_fprintf)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes and tests a Forwarding Information Base (FIB) for IPv4 routing, simulating a simple production routing scenario and verifying the routing logic through various test cases.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the program environment with `fd_boot` using `argc` and `argv`.
    - Verify memory alignment and size for FIB structures using `FD_TEST`.
    - Create and join two FIB structures, `fib_local` and `fib_main`, using [`fd_fib4_new`](fd_fib4.c.driver.md#fd_fib4_new) and [`fd_fib4_join`](fd_fib4.c.driver.md#fd_fib4_join).
    - Check that an empty FIB returns a THROW result using [`fd_fib4_lookup`](fd_fib4.c.driver.md#fd_fib4_lookup).
    - Clear `fib_local` and populate it with several routing entries using [`fd_fib4_append`](fd_fib4.c.driver.md#fd_fib4_append).
    - Print the contents of `fib_local` using [`test_fib_print`](#test_fib_print) to verify the entries.
    - Clear `fib_main` and populate it with routing entries for default and specific routes using [`fd_fib4_append`](fd_fib4.c.driver.md#fd_fib4_append).
    - Print the contents of `fib_main` using [`test_fib_print`](#test_fib_print) to verify the entries.
    - Define a macro `QUERY` to perform route lookups in both FIBs and combine results using `fd_fib4_hop_or`.
    - Perform route lookups for specific IP addresses and verify the results using `FD_TEST`.
    - Clear `fib_main` again and verify that `fib_local` returns a THROW result for a specific lookup.
    - Delete the FIB structures using [`fd_fib4_delete`](fd_fib4.c.driver.md#fd_fib4_delete) and [`fd_fib4_leave`](fd_fib4.c.driver.md#fd_fib4_leave).
    - Log a success message and halt the program with `fd_halt`.
- **Output**: The function returns an integer value `0`, indicating successful execution.
- **Functions called**:
    - [`fd_fib4_align`](fd_fib4.c.driver.md#fd_fib4_align)
    - [`fd_fib4_footprint`](fd_fib4.c.driver.md#fd_fib4_footprint)
    - [`fd_fib4_join`](fd_fib4.c.driver.md#fd_fib4_join)
    - [`fd_fib4_new`](fd_fib4.c.driver.md#fd_fib4_new)
    - [`fd_fib4_lookup`](fd_fib4.c.driver.md#fd_fib4_lookup)
    - [`fd_fib4_clear`](fd_fib4.c.driver.md#fd_fib4_clear)
    - [`fd_fib4_free_cnt`](fd_fib4.c.driver.md#fd_fib4_free_cnt)
    - [`fd_fib4_append`](fd_fib4.c.driver.md#fd_fib4_append)
    - [`test_fib_print`](#test_fib_print)
    - [`fd_fib4_delete`](fd_fib4.c.driver.md#fd_fib4_delete)
    - [`fd_fib4_leave`](fd_fib4.c.driver.md#fd_fib4_leave)



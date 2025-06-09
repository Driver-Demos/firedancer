# Purpose
The provided C source code file is a test suite designed to exercise and validate the functionality of an eBPF (extended Berkeley Packet Filter) program specifically for XDP (eXpress Data Path) on Linux systems. The code is structured to run unit tests on the `ebpf_xdp_flow` using the `bpf(2)` syscall in `BPF_PROG_TEST_RUN` mode, which allows for testing BPF programs without attaching them to a live network interface. The file includes various components such as the setup of BPF maps and AF_XDP sockets, loading of eBPF programs, and execution of test cases that simulate network packet processing to verify the expected behavior of the eBPF program.

The code is comprehensive in its approach, covering multiple test scenarios including different packet types (e.g., TCP, ARP, ICMP, DNS) and network conditions (e.g., different destination ports, IP protocols, and Ethernet types). It uses a combination of predefined binary packet fixtures and dynamically generated test packets to ensure the eBPF program correctly handles and redirects network traffic as intended. The file is intended to be executed as a standalone program, as indicated by the presence of a [`main`](#main) function, and it includes error handling and logging to provide feedback on test outcomes. The code is tightly coupled with the Linux operating system and requires specific permissions to load and test BPF programs, reflecting its specialized nature for network performance testing and validation in environments that support XDP.
# Imports and Dependencies

---
- `errno.h`
- `stdio.h`
- `stdlib.h`
- `unistd.h`
- `sys/socket.h`
- `../../util/fd_util.h`
- `../../util/net/fd_eth.h`
- `../../util/net/fd_ip4.h`
- `../../util/net/fd_udp.h`
- `../ebpf/fd_linux_bpf.h`
- `fd_xdp1.h`


# Global Variables

---
### prog\_fd
- **Type**: `int`
- **Description**: The `prog_fd` variable is a global integer that is initialized to -1. It is used to store the file descriptor of a loaded BPF (Berkeley Packet Filter) program.
- **Use**: `prog_fd` is used to hold the file descriptor returned by the `bpf` system call when loading a BPF program, allowing the program to be referenced and tested later in the code.


---
### xsks\_fd
- **Type**: `int`
- **Description**: The `xsks_fd` is a global integer variable initialized to -1, representing a file descriptor for a BPF map of type XSKMAP. This map is used to associate AF_XDP sockets with specific queues for packet processing in the eBPF program.
- **Use**: It is used to store the file descriptor of the XSKMAP created for managing queue-to-XSK associations in the eBPF test program.


---
### xsk\_fd
- **Type**: `int`
- **Description**: The `xsk_fd` variable is a global integer that represents a file descriptor for an AF_XDP socket. It is initialized to -1, indicating that the socket is not yet created or opened.
- **Use**: This variable is used to store the file descriptor of an AF_XDP socket, which is created and utilized in the test harness to facilitate packet processing and testing of eBPF programs.


# Functions

---
### fd\_bpf\_map\_clear<!-- {{#callable:fd_bpf_map_clear}} -->
The `fd_bpf_map_clear` function iteratively deletes all elements from a BPF map specified by the file descriptor `map_fd`.
- **Inputs**:
    - `map_fd`: An integer representing the file descriptor of the BPF map to be cleared.
- **Control Flow**:
    - Initialize a variable `key` to 0UL to start iterating over the map keys.
    - Enter an infinite loop to iterate over the map keys.
    - Use `fd_bpf_map_get_next_key` to retrieve the next key in the map, storing it in `next_key`.
    - If `fd_bpf_map_get_next_key` returns a non-zero value, check if `errno` is `ENOENT` (indicating no more keys), and break the loop if true.
    - If `errno` is not `ENOENT`, log an error message and exit the loop.
    - Use `fd_bpf_map_delete_elem` to delete the element associated with `next_key` from the map.
    - Log an error message if `fd_bpf_map_delete_elem` fails.
    - Update `key` to `next_key` to continue iterating over the map.
- **Output**: Returns 0 upon successful completion of clearing the map.


---
### load\_prog<!-- {{#callable:load_prog}} -->
The `load_prog` function loads an eBPF program into the kernel using the BPF_PROG_LOAD command and handles potential errors during the loading process.
- **Inputs**:
    - `code_buf`: A pointer to an array of unsigned long integers representing the eBPF program instructions to be loaded.
    - `code_cnt`: An unsigned long integer representing the number of instructions in the eBPF program.
- **Control Flow**:
    - Initialize a static character array `ebpf_kern_log` to store the eBPF verifier log.
    - Set the first character of `ebpf_kern_log` to 0 to clear any previous log data.
    - Define a `bpf_attr` union with attributes for loading an eBPF program, including program type, instruction count, instruction buffer, license, program name, log level, log size, and log buffer.
    - Call the `bpf` function with the `BPF_PROG_LOAD` command, passing the `bpf_attr` structure and its size, and store the result in `prog_fd`.
    - Check if `prog_fd` is negative, indicating an error during program loading.
    - If the error is due to insufficient permissions (`errno == EPERM`), log a warning, halt the program, and exit.
    - If any other error occurs, log the eBPF verifier log and the error message, then log an error and exit.
    - Return the file descriptor `prog_fd` of the loaded eBPF program.
- **Output**: The function returns an integer representing the file descriptor of the loaded eBPF program, or a negative value if an error occurred during loading.


---
### prog\_test<!-- {{#callable:prog_test}} -->
The `prog_test` function tests an eBPF program by running it with a given packet and verifying the output against an expected action.
- **Inputs**:
    - `pkt`: A pointer to the packet data to be tested.
    - `pkt_sz`: The size of the packet data in bytes.
    - `name`: A string representing the name of the test, used for logging purposes.
    - `expected_action`: The expected action (e.g., XDP_PASS, XDP_REDIRECT) that the eBPF program should return when run with the given packet.
- **Control Flow**:
    - Clear the XSK map by calling `fd_bpf_map_clear(xsks_fd)` to ensure no previous state affects the test.
    - Define a macro `FD_XDP_TEST` to log an error and exit if a condition is not met.
    - Set up the XSK map by associating the RX queue with the XSK file descriptor using `fd_bpf_map_update_elem`.
    - Initialize a `bpf_attr` structure with the program file descriptor, input packet data, and packet size.
    - Run the eBPF program using the `bpf` syscall with `BPF_PROG_TEST_RUN` and the initialized `bpf_attr`.
    - Log the return value of the eBPF program test using `FD_LOG_INFO`.
    - Verify that the return value of the eBPF program matches the expected action using the `FD_XDP_TEST` macro.
- **Output**: The function does not return a value; it logs information and errors, and may terminate the program if a test fails.
- **Functions called**:
    - [`fd_bpf_map_clear`](#fd_bpf_map_clear)


---
### run\_tests<!-- {{#callable:run_tests}} -->
The `run_tests` function performs a series of network packet tests using different configurations to verify the behavior of an eBPF XDP program.
- **Inputs**:
    - `dst_ip`: The destination IP address used in the test packets.
- **Control Flow**:
    - Initialize a packet structure with Ethernet, IPv4, and UDP headers, setting the destination IP to `dst_ip`.
    - Iterate over all possible UDP destination ports (0 to 65535), setting the expected action to `XDP_REDIRECT` for specific ports (`PORT0` and `PORT1`) and `XDP_PASS` for others, then test each configuration using [`prog_test`](#prog_test).
    - Test the IPv4 protocol field by setting it to UDP, ICMP, and TCP, expecting `XDP_REDIRECT` for UDP and `XDP_PASS` for others.
    - Test the IPv4 destination IP by incrementing it and setting it to zero, expecting `XDP_PASS` or `XDP_REDIRECT` based on the `dst_ip` value.
    - Iterate over all possible Ethertype values, expecting `XDP_REDIRECT` for IP and `XDP_PASS` for others, and test each configuration.
    - Test the Internet Header Length (IHL) by setting it to 6 and expecting `XDP_REDIRECT`.
    - Run additional tests using predefined binary fixtures, expecting `XDP_PASS` for most and `XDP_REDIRECT` for `quic_initial`.
- **Output**: The function does not return a value; it performs tests and logs results, verifying that the eBPF XDP program behaves as expected under various conditions.
- **Functions called**:
    - [`prog_test`](#prog_test)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes and tests an eBPF XDP program by creating necessary maps and sockets, loading the program, running tests, and cleaning up resources.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Call `fd_boot` to initialize the environment with command-line arguments.
    - Define a `bpf_attr` structure to specify attributes for creating a BPF map of type `XSKMAP`.
    - Create the BPF map using the `bpf` syscall with `BPF_MAP_CREATE` and check for errors.
    - Create an AF_XDP socket using the `socket` function and verify its creation.
    - Define an array of ports and a buffer for the eBPF program code.
    - Generate the eBPF program code using [`fd_xdp_gen_program`](fd_xdp1.c.driver.md#fd_xdp_gen_program) with a specific IP address and ports.
    - Load the generated eBPF program using [`load_prog`](#load_prog) and store the program file descriptor.
    - Run tests on the loaded program using [`run_tests`](#run_tests) with the specified IP address.
    - Close the program file descriptor after tests are completed.
    - Generate and load another eBPF program with a different IP address (0.0.0.0) and run tests again.
    - Close the program file descriptor after the second set of tests.
    - Close the AF_XDP socket to clean up resources.
    - Log a notice indicating the tests passed and call `fd_halt` to terminate the program.
- **Output**: The function returns an integer status code, `0` for successful execution or `-1` if an error occurs during map creation.
- **Functions called**:
    - [`fd_xdp_gen_program`](fd_xdp1.c.driver.md#fd_xdp_gen_program)
    - [`load_prog`](#load_prog)
    - [`run_tests`](#run_tests)



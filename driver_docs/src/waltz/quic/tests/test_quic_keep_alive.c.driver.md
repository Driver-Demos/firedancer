# Purpose
This C source code file is designed to test the functionality of a QUIC (Quick UDP Internet Connections) protocol implementation. It primarily focuses on establishing and validating connections between a client and a server using the QUIC protocol, with specific emphasis on testing the "keep-alive" feature. The code includes functions to simulate new connections and handshake completions, and it uses a global clock to manage timing for the tests. The [`test_quic_keep_alive`](#test_quic_keep_alive) function is central to the file, as it tests whether the client connection remains active or becomes inactive based on the keep-alive configuration.

The file is structured as an executable program, with a [`main`](#main) function that initializes the testing environment, sets up the necessary resources, and executes the tests. It uses various helper functions and structures from included headers to manage memory, random number generation, and QUIC-specific configurations. The code defines a set of limits for the QUIC connections and uses anonymous workspace allocations to manage resources. The testing process involves creating virtual pairs of client and server QUIC instances, running services to simulate network activity, and validating the outcomes based on the keep-alive settings. The file concludes by cleaning up resources and logging the test results.
# Imports and Dependencies

---
- `../fd_quic.h`
- `fd_quic_test_helpers.h`


# Global Variables

---
### server\_complete
- **Type**: `int`
- **Description**: The `server_complete` variable is a global integer initialized to 0, used to indicate whether the server-side connection has been successfully established in a QUIC protocol test.
- **Use**: This variable is set to 1 in the `my_connection_new` function to signal that the server connection is complete.


---
### client\_complete
- **Type**: `int`
- **Description**: The `client_complete` variable is a global integer initialized to 0, used to indicate the completion status of a client-side handshake in a QUIC (Quick UDP Internet Connections) protocol test.
- **Use**: This variable is set to 1 when the client-side handshake is complete, allowing the test to verify that both client and server handshakes have been successfully completed.


---
### my\_connection\_new
- **Type**: ``void``
- **Description**: The `my_connection_new` function is a callback function that is triggered when a new connection is established in the QUIC protocol. It takes two parameters: a pointer to a `fd_quic_conn_t` structure representing the connection and a void pointer for context, both of which are marked as unused in this implementation. The function sets the global variable `server_complete` to 1, indicating that the server-side connection setup is complete.
- **Use**: This function is used as a callback to signal the completion of a new server connection in a QUIC communication setup.


---
### my\_handshake\_complete
- **Type**: `function`
- **Description**: The `my_handshake_complete` function is a callback function that is invoked when a client's handshake process is completed in a QUIC connection. It sets the global variable `client_complete` to 1, indicating that the client's handshake has been successfully completed.
- **Use**: This function is used as a callback to update the handshake completion status of a client in a QUIC connection.


---
### now
- **Type**: `ulong`
- **Description**: The `now` variable is a global variable of type `ulong` initialized to the value 145. It acts as a simulated clock or time counter within the program.
- **Use**: The `now` variable is used to simulate the passage of time in the `test_quic_keep_alive` function by incrementing its value in a loop.


# Functions

---
### test\_clock<!-- {{#callable:test_clock}} -->
The `test_clock` function returns the current value of a global variable `now`, which simulates a clock.
- **Inputs**:
    - `ctx`: A void pointer to context data, which is unused in this function.
- **Control Flow**:
    - The function explicitly casts the input `ctx` to void to indicate it is unused.
    - The function returns the value of the global variable `now`.
- **Output**: The function returns an unsigned long integer representing the current simulated time from the global variable `now`.


---
### test\_quic\_keep\_alive<!-- {{#callable:test_quic_keep_alive}} -->
The `test_quic_keep_alive` function tests the behavior of QUIC connections with and without the keep-alive feature enabled.
- **Inputs**:
    - `client_quic`: A pointer to the client QUIC configuration and state structure.
    - `server_quic`: A pointer to the server QUIC configuration and state structure.
    - `keep_alive`: An integer flag indicating whether the keep-alive feature should be enabled (non-zero) or disabled (zero).
- **Control Flow**:
    - Initialize the `server_complete` and `client_complete` flags to 0.
    - Set the `keep_alive` configuration of the client QUIC to the provided `keep_alive` value.
    - Initialize both the server and client QUIC instances using `fd_quic_init` and validate them with `fd_quic_svc_validate`.
    - Establish a connection from the client to the server using `fd_quic_connect` and verify the connection is successful.
    - Run a loop up to 20 times, logging service runs and calling `fd_quic_service` for both client and server, breaking early if both handshakes are complete.
    - Verify that the idle timeouts for client and server are equal and calculate a timestep as one-eighth of the idle timeout.
    - Run another loop 10 times, incrementing the global `now` by the timestep and calling `fd_quic_service` for both client and server.
    - Check the state of the client connection: if `keep_alive` is enabled, ensure the connection is active; otherwise, ensure it is either dead or invalid.
- **Output**: The function does not return a value but performs assertions to verify the expected behavior of the QUIC connection based on the keep-alive setting.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes and tests a QUIC server-client pair using a virtual connection, verifying keep-alive functionality and cleaning up resources afterwards.
- **Inputs**:
    - `argc`: The count of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the environment and QUIC test environment with `fd_boot` and [`fd_quic_test_boot`](fd_quic_test_helpers.c.driver.md#fd_quic_test_boot).
    - Create a random number generator `rng` using `fd_rng_new` and `fd_rng_join`.
    - Determine the CPU index and adjust if it exceeds the shared memory CPU count.
    - Parse command-line arguments for page size, page count, and NUMA index using `fd_env_strip_cmdline_cstr` and `fd_env_strip_cmdline_ulong`.
    - Convert the page size string to an actual size using `fd_cstr_to_shmem_page_sz` and log an error if unsupported.
    - Create an anonymous workspace `wksp` with the specified page size and count.
    - Define QUIC limits in a `fd_quic_limits_t` structure and calculate the QUIC footprint, logging an error if invalid.
    - Create anonymous QUIC server and client instances with [`fd_quic_new_anonymous`](fd_quic_test_helpers.c.driver.md#fd_quic_new_anonymous), using the workspace and random number generator.
    - Set callback functions for the server and client QUIC instances, including `test_clock`, `my_connection_new`, and `my_handshake_complete`.
    - Configure initial receive maximum stream data for both server and client QUIC instances.
    - Initialize a virtual QUIC pair with [`fd_quic_virtual_pair_init`](fd_quic_test_helpers.c.driver.md#fd_quic_virtual_pair_init).
    - Test the QUIC keep-alive functionality twice with [`test_quic_keep_alive`](#test_quic_keep_alive), once with keep-alive disabled and once enabled.
    - Finalize the virtual QUIC pair with [`fd_quic_virtual_pair_fini`](fd_quic_test_helpers.c.driver.md#fd_quic_virtual_pair_fini).
    - Clean up resources by deleting and freeing the QUIC instances, workspace, and random number generator.
    - Log a notice indicating the test passed and halt the QUIC test environment and program.
- **Output**: The function returns an integer value of 0, indicating successful execution.
- **Functions called**:
    - [`fd_quic_test_boot`](fd_quic_test_helpers.c.driver.md#fd_quic_test_boot)
    - [`fd_quic_new_anonymous`](fd_quic_test_helpers.c.driver.md#fd_quic_new_anonymous)
    - [`fd_quic_virtual_pair_init`](fd_quic_test_helpers.c.driver.md#fd_quic_virtual_pair_init)
    - [`test_quic_keep_alive`](#test_quic_keep_alive)
    - [`fd_quic_virtual_pair_fini`](fd_quic_test_helpers.c.driver.md#fd_quic_virtual_pair_fini)
    - [`fd_quic_test_halt`](fd_quic_test_helpers.c.driver.md#fd_quic_test_halt)



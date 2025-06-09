# Purpose
The provided C code is a comprehensive unit test for a system called "Wiredancer," designed to be executed on AWS-F1 instances. The primary purpose of this code is to validate the performance and correctness of the Wiredancer system against an x86-based verification process. The test involves several components, including a "replay" tile that feeds network packets to a "parser" tile, which then parses transactions and sends signature verification requests downstream. These requests can be processed by either an x86-based "verify" tile or the Wiredancer system itself. The "checker" tile compares the outputs from the x86 and Wiredancer systems to ensure consistency by matching sequence numbers.

The code is structured into multiple components, each with a specific role in the testing process. It includes functions for replaying network packets, parsing transactions, verifying signatures using both x86 and Wiredancer, and checking the results. The code also includes configuration settings for various parameters such as the number of FPGA slots, test duration, and random transaction corruption. Additionally, it provides mechanisms for signal handling and logging to facilitate monitoring and debugging during the test execution. The test is designed to be flexible, allowing it to run with either Wiredancer or x86 independently, or both for comparative analysis.
# Imports and Dependencies

---
- `fd_replay_loop.h`
- `../../util/net/fd_eth.h`
- `../../util/net/fd_ip4.h`
- `../../util/net/fd_udp.h`
- `../../ballet/txn/fd_txn.h`
- `../../ballet/ed25519/fd_ed25519_private.h`
- `../../ballet/ed25519/fd_ed25519.h`
- `../../ballet/sha512/fd_sha512.h`
- `../c/wd_f1.h`
- `wd_f1_mon.h`
- `pthread.h`
- `stdio.h`
- `signal.h`


# Global Variables

---
### test\_halt
- **Type**: `ulong`
- **Description**: The `test_halt` variable is a global variable of type `ulong` initialized to 0UL. It is used to signal the main function to halt execution when a specific condition is met, such as receiving a POSIX signal.
- **Use**: This variable is used as a flag to indicate when the main function should stop running, typically in response to an external signal.


# Data Structures

---
### parsed\_txn\_compressed\_meta
- **Type**: `union`
- **Members**:
    - `all`: A single unsigned long integer representing the entire union.
    - `msg_sz`: A 16-bit unsigned short representing the message size.
    - `msg_off`: A 16-bit unsigned short representing the message offset from the start of the packet.
    - `signature_off`: A 16-bit unsigned short representing the signature offset from the start of the packet.
    - `public_key_off`: A 16-bit unsigned short representing the public key offset from the start of the packet.
- **Description**: The `parsed_txn_compressed_meta` is a union data structure designed to store metadata about a parsed transaction in a compressed format. It can be accessed as a single `ulong` for quick operations or as a structured set of fields for detailed information. The structured fields include offsets and sizes for the message, signature, and public key within a packet, allowing for efficient parsing and processing of transaction data.


---
### parsed\_txn\_compressed\_meta\_t
- **Type**: `union`
- **Members**:
    - `all`: A single unsigned long integer representing the entire union.
    - `value`: A struct containing four unsigned short integers representing various offsets and sizes within a packet.
- **Description**: The `parsed_txn_compressed_meta_t` is a union designed to store metadata about a parsed transaction in a compact form. It can be accessed as a single `ulong` for efficient storage and comparison, or as a struct with four `ushort` fields that provide specific offsets and sizes related to the transaction's message, signature, and public key within a packet. This structure is used to facilitate the processing and verification of transactions in a network packet, ensuring that the necessary data can be quickly accessed and manipulated.


---
### test\_cfg
- **Type**: `struct`
- **Members**:
    - `wksp`: Pointer to a workspace object used for memory management.
    - `replay_cnc`: Pointer to a command and control structure for the replay tile.
    - `replay_pcap`: Constant character pointer to the path of the pcap file to be replayed.
    - `replay_mtu`: Maximum transmission unit size for the replay.
    - `replay_orig`: Original sequence number for the replay.
    - `replay_mcache`: Pointer to a metadata cache for the replay.
    - `replay_dcache`: Pointer to a data cache for the replay.
    - `replay_cr_max`: Maximum credit for replay flow control.
    - `replay_lazy`: Laziness parameter for replay processing.
    - `replay_seed`: Seed for the random number generator used in replay.
    - `replay_fseq`: Pointer to an array of flow sequence numbers for replay.
    - `replay_fseq_cnt`: Count of flow sequences for replay.
    - `parser_cnc`: Pointer to a command and control structure for the parser tile.
    - `parser_mcache`: Pointer to a metadata cache for the parser.
    - `parser_lazy`: Laziness parameter for parser processing.
    - `parser_seed`: Seed for the random number generator used in parser.
    - `parser_enabled`: Flag indicating if the parser is enabled.
    - `parser_replay_fseq`: Pointer to the replay flow sequence used by the parser.
    - `parser_rand_txn_corrupt`: Flag indicating if random transaction corruption is enabled in the parser.
    - `v_x86_cnc`: Pointer to a command and control structure for the x86 verification tile.
    - `v_x86_mcache`: Pointer to a metadata cache for the x86 verification.
    - `v_x86_lazy`: Laziness parameter for x86 verification processing.
    - `v_x86_seed`: Seed for the random number generator used in x86 verification.
    - `v_x86_enabled`: Flag indicating if the x86 verification is enabled.
    - `v__wd_enabled`: Flag indicating if the Wiredancer verification is enabled.
    - `v__wd_mcache`: Pointer to a metadata cache for the Wiredancer verification.
    - `vcheck_cnc`: Pointer to a command and control structure for the verification checker tile.
    - `vcheck_seed`: Seed for the random number generator used in verification checking.
    - `vcheck_lazy`: Laziness parameter for verification checking processing.
    - `test_version`: Version of the test being executed.
    - `wd_slots`: Number of FPGA slots used in the Wiredancer test.
    - `wd_split`: Flag indicating if the Wiredancer workload is split.
- **Description**: The `test_cfg` structure is a configuration data structure used in a unit test for the Wiredancer system, which is designed to test the performance and correctness of packet processing across different components, including replay, parsing, and verification on both x86 and FPGA-based systems. It contains pointers to various command and control structures, metadata caches, and data caches, as well as configuration parameters such as seeds for random number generation, laziness parameters for processing, and flags to enable or disable certain components. The structure is used to manage the flow of data and control signals between different tiles in the test setup, ensuring that the test runs according to the specified configuration.


---
### test\_cfg\_t
- **Type**: `typedef struct test_cfg test_cfg_t;`
- **Members**:
    - `wksp`: Pointer to a workspace structure used for memory management.
    - `replay_cnc`: Pointer to a command and control structure for the replay tile.
    - `replay_pcap`: Constant character pointer to the path of the pcap file to be replayed.
    - `replay_mtu`: Maximum transmission unit size for replay packets.
    - `replay_orig`: Original sequence number for replay packets.
    - `replay_mcache`: Pointer to a metadata cache for replay packets.
    - `replay_dcache`: Pointer to a data cache for replay packets.
    - `replay_cr_max`: Maximum credit for replay flow control.
    - `replay_lazy`: Lazy parameter for replay tile processing.
    - `replay_seed`: Seed for random number generation in replay tile.
    - `replay_fseq`: Array of pointers to flow sequence numbers for replay consumers.
    - `replay_fseq_cnt`: Count of replay flow sequence consumers.
    - `parser_cnc`: Pointer to a command and control structure for the parser tile.
    - `parser_mcache`: Pointer to a metadata cache for parser output.
    - `parser_lazy`: Lazy parameter for parser tile processing.
    - `parser_seed`: Seed for random number generation in parser tile.
    - `parser_enabled`: Flag indicating if the parser tile is enabled.
    - `parser_replay_fseq`: Pointer to the replay flow sequence used by the parser.
    - `parser_rand_txn_corrupt`: Flag indicating if random transaction corruption is enabled in the parser.
    - `v_x86_cnc`: Pointer to a command and control structure for the x86 verification tile.
    - `v_x86_mcache`: Pointer to a metadata cache for x86 verification output.
    - `v_x86_lazy`: Lazy parameter for x86 verification tile processing.
    - `v_x86_seed`: Seed for random number generation in x86 verification tile.
    - `v_x86_enabled`: Flag indicating if the x86 verification tile is enabled.
    - `v__wd_enabled`: Flag indicating if the Wiredancer verification tile is enabled.
    - `v__wd_mcache`: Pointer to a metadata cache for Wiredancer verification output.
    - `vcheck_cnc`: Pointer to a command and control structure for the verification checker tile.
    - `vcheck_seed`: Seed for random number generation in verification checker tile.
    - `vcheck_lazy`: Lazy parameter for verification checker tile processing.
    - `test_version`: Version of the test to be executed.
    - `wd_slots`: Bitmask indicating the FPGA slots used by Wiredancer.
    - `wd_split`: Flag indicating if Wiredancer should split its workload.
- **Description**: The `test_cfg_t` structure is a configuration data structure used in a unit test for the Wiredancer system, which is designed to test the system's performance and correctness against an x86-based verification system. It contains various configuration parameters and pointers to resources such as workspaces, caches, and command and control structures for different tiles (replay, parser, x86 verification, and Wiredancer verification). The structure also includes flags and seeds for enabling features and controlling random number generation, as well as parameters for managing flow control and processing laziness. This configuration is crucial for setting up and managing the test environment and ensuring that the test runs with the desired settings and conditions.


# Functions

---
### sha512\_modq\_lsB<!-- {{#callable:sha512_modq_lsB}} -->
The `sha512_modq_lsB` function computes a SHA-512 hash of a signature, public key, and message, reduces it modulo a large prime, and returns the least significant byte of the result.
- **Inputs**:
    - `msg`: A pointer to the message data to be hashed.
    - `sz`: The size of the message data in bytes.
    - `sig`: A pointer to the signature data, which is expected to be 32 bytes long.
    - `public_key`: A pointer to the public key data, which is expected to be 32 bytes long.
    - `sha`: A pointer to an `fd_sha512_t` structure used for SHA-512 hashing operations.
- **Control Flow**:
    - Cast the `sig` input to a `uchar` pointer and assign it to `r`.
    - Initialize a 64-byte array `h` to store the hash result.
    - Initialize the SHA-512 context using `fd_sha512_init` with the provided `sha` pointer.
    - Append the first 32 bytes of the signature (`r`) to the SHA-512 context.
    - Append the 32-byte public key to the SHA-512 context.
    - Append the message data of size `sz` to the SHA-512 context.
    - Finalize the SHA-512 hash computation and store the result in `h`.
    - Reduce the hash `h` modulo a large prime using `fd_ed25519_sc_reduce`.
    - Return the least significant byte of the reduced hash as an integer.
- **Output**: The function returns an integer representing the least significant byte of the reduced hash.


---
### replay\_tile\_main<!-- {{#callable:replay_tile_main}} -->
The `replay_tile_main` function initializes and runs a replay tile loop for packet processing in a network test environment.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments.
    - `argv`: An array of strings representing the command-line arguments, which is cast to a `test_cfg_t` configuration structure for the function.
- **Control Flow**:
    - The function begins by casting `argv` to a `test_cfg_t` pointer to access configuration settings.
    - It logs a notice indicating the activation of the replay tile.
    - A random number generator (`fd_rng_t`) is initialized using a seed from the configuration.
    - A scratch space is allocated with specific alignment and footprint requirements for the replay tile.
    - The function calls [`fd_replay_tile_loop`](fd_replay_loop.c.driver.md#fd_replay_tile_loop) with various configuration parameters, including control and data caches, sequence numbers, and the random number generator, to execute the main loop of the replay tile.
    - The function checks the result of [`fd_replay_tile_loop`](fd_replay_loop.c.driver.md#fd_replay_tile_loop) to ensure it completes successfully.
    - Finally, the random number generator is cleaned up, and the function returns 0 to indicate successful execution.
- **Output**: The function returns an integer, specifically 0, indicating successful execution.
- **Functions called**:
    - [`fd_replay_tile_loop`](fd_replay_loop.c.driver.md#fd_replay_tile_loop)


---
### parser\_tile\_main<!-- {{#callable:parser_tile_main}} -->
The `parser_tile_main` function processes network packets, parses transactions, and sends signature verification requests to either an x86-based or Wiredancer-based verification system.
- **Inputs**:
    - `argc`: An integer representing the number of arguments passed to the function, used here to derive the parser index.
    - `argv`: An array of character pointers representing the arguments passed to the function, used here to access the configuration structure `test_cfg_t`.
- **Control Flow**:
    - Initialize various components such as workspace, command and control (CNC), and memory caches based on the configuration provided in `argv`.
    - Log the activation of the parser tile.
    - Set up connections to various caches and control structures, including replay and output caches, and initialize diagnostic counters.
    - Initialize random number generator and configure transaction corruption settings.
    - Initialize Wiredancer if enabled, and set up for signature verification requests.
    - Enter the main processing loop, signaling the CNC to run.
    - In each loop iteration, wait for a fragment sequence and perform housekeeping tasks if necessary.
    - Process each received network packet, extracting and verifying headers (Ethernet, IPv4, UDP) and parsing transactions.
    - For each transaction, potentially corrupt the message, and send signature verification requests to either x86 or Wiredancer systems based on configuration.
    - Update diagnostic counters and publish results to the output cache.
    - Check for overruns and increment sequence numbers for the next iteration.
    - Upon loop exit, clean up resources, signal CNC to boot, and return 0.
- **Output**: The function returns an integer, 0, indicating successful execution.


---
### v\_x86\_tile\_main<!-- {{#callable:v_x86_tile_main}} -->
The `v_x86_tile_main` function processes transaction fragments, verifies signatures using either Ed25519 or SHA512MODQ, and publishes results to an output cache.
- **Inputs**:
    - `argc`: The number of command-line arguments, used to initialize the `v_x86_idx` variable.
    - `argv`: An array of command-line arguments, cast to a `test_cfg_t` structure pointer to access configuration settings.
- **Control Flow**:
    - Initialize local variables and log the function activation.
    - Retrieve configuration settings from the `test_cfg_t` structure, including workspace, CNC, and mcache pointers.
    - Set initial diagnostic values for transaction and signature counts in the CNC diagnostics array.
    - Enter the main processing loop, signaling the CNC to run and waiting for the parser CNC to advance beyond the current sequence number.
    - In the loop, perform housekeeping tasks such as sending heartbeats and checking for halt signals.
    - Implement auto-throttling by adjusting the sequence number based on the difference between parser and current sequences.
    - Wait for a fragment to be available in the parser mcache, checking for overruns.
    - Process the received fragment by extracting message, signature, and public key data from the fragment's metadata.
    - Verify the signature using the specified test version (Ed25519 or SHA512MODQ) and publish the verification result to the output mcache.
    - Check for overruns during processing and increment sequence numbers for the next iteration.
    - Update CNC diagnostics with the number of processed transactions and signatures.
    - Exit the loop if a halt signal is received or an error occurs.
    - Clean up resources by deleting the random number generator and signaling the CNC to boot.
- **Output**: The function returns an integer status code, typically 0 for successful execution.
- **Functions called**:
    - [`sha512_modq_lsB`](#sha512_modq_lsB)


---
### vcheck\_tile\_main<!-- {{#callable:vcheck_tile_main}} -->
The `vcheck_tile_main` function verifies the signature verification results from x86 and Wiredancer, comparing them and updating diagnostic counters accordingly.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the function.
    - `argv`: An array of command-line arguments, where the first argument is a pointer to a `test_cfg_t` structure containing configuration data for the test.
- **Control Flow**:
    - Initialize variables and log the start of the function.
    - Set up command and control diagnostics by initializing diagnostic counters to zero.
    - Check if x86 and Wiredancer producers are enabled and set up their respective caches and sequences.
    - Initialize a random number generator using the seed from the configuration.
    - Initialize Wiredancer PCI and verification response.
    - Enter the main loop, signaling the CNC to run.
    - Poll the x86 mcache if x86 is enabled, waiting for fragments and handling signals.
    - Poll the Wiredancer mcache if Wiredancer is enabled, synchronizing with x86 sequence and handling signals.
    - Process x86 fragments, checking for overruns and incrementing sequence.
    - Process Wiredancer fragments, checking for overruns, incrementing sequence, and updating pass/fail counters.
    - Compare x86 and Wiredancer results if both are enabled, logging discrepancies and updating validation counters.
    - Increment the expected signature for the next iteration.
    - Free Wiredancer PCI resources and clean up the random number generator.
    - Signal the CNC to boot and return 0.
- **Output**: The function returns an integer, specifically 0, indicating successful execution.


---
### test\_sigaction<!-- {{#callable:test_sigaction}} -->
The `test_sigaction` function handles a POSIX signal by logging the signal number and setting a halt flag.
- **Inputs**:
    - `sig`: The signal number that was received.
    - `info`: A pointer to a `siginfo_t` structure containing additional information about the signal (unused in this function).
    - `context`: A pointer to a context structure (unused in this function).
- **Control Flow**:
    - The function begins by casting the `info` and `context` pointers to void to indicate they are unused.
    - A log message is generated to indicate that a POSIX signal was received, including the signal number.
    - The global variable `test_halt` is set to 1UL to signal that the main process should halt.
- **Output**: This function does not return any value.


---
### test\_signal\_trap<!-- {{#callable:test_signal_trap}} -->
The `test_signal_trap` function sets up a signal handler for a specified signal to handle it using a custom action.
- **Inputs**:
    - `sig`: An integer representing the signal number for which the handler is being set.
- **Control Flow**:
    - Declare a `sigaction` structure `act` to hold the signal action configuration.
    - Assign the `test_sigaction` function to `act->sa_sigaction` to handle the signal.
    - Call `sigemptyset` to initialize the signal mask set in `act->sa_mask` to empty, logging an error if it fails.
    - Set `act->sa_flags` to `SA_SIGINFO | SA_RESETHAND` to specify that the handler should receive additional information and reset to default after handling.
    - Call `sigaction` to set the action for the specified signal `sig`, logging an error if it fails.
- **Output**: The function does not return any value; it sets up a signal handler for the specified signal.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, checks for necessary capabilities, logs a warning if they are not present, and then halts the program.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments passed to the program.
- **Control Flow**:
    - The function begins by calling `fd_boot` to initialize the environment with the command-line arguments.
    - It logs a warning message indicating that the unit test requires certain capabilities (FD_HAS_HOSTED, FD_HAS_X86, and FD_HAS_WIREDANCER) which are not present.
    - The function then calls `fd_halt` to terminate the program.
    - Finally, it returns 0, indicating successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution.



# Purpose
This C source code file is a comprehensive test suite designed to evaluate the functionality and performance of a deduplication system using multiple tiles for transmission (TX), deduplication, and reception (RX) of data packets. The code is structured to run in a hosted environment with AVX (Advanced Vector Extensions) support, and it includes various components such as command-and-control (CNC) interfaces, memory caches (mcaches), data caches (dcaches), flow control (fctl), and random number generators (RNGs). The main function orchestrates the setup, execution, and teardown of the test environment, configuring parameters like packet size, burst characteristics, and duplication thresholds. It initializes the necessary resources, launches the TX, deduplication, and RX tiles, and manages their lifecycle through CNC signals.

The file defines a `test_cfg` structure to hold configuration parameters and memory pointers for the test setup. The TX tile injects synthetic traffic into the deduplication tile, which processes the data and forwards it to the RX tiles. The deduplication tile uses a tcache to track and eliminate duplicate packets, ensuring only unique data is processed by the RX tiles. The RX tiles validate the integrity of received data and check for duplicates. The code includes diagnostic logging to monitor performance metrics such as packet throughput. The test is designed to run for a specified duration, after which it halts all tiles, cleans up resources, and exits. The file is intended to be compiled and executed as a standalone program, with the main function serving as the entry point.
# Imports and Dependencies

---
- `../fd_disco.h`
- `math.h`


# Data Structures

---
### test\_cfg
- **Type**: `struct`
- **Members**:
    - `wksp`: Pointer to a workspace of type `fd_wksp_t`.
    - `tx_cnt`: Number of transmitters.
    - `tx_lazy`: Lazy parameter for transmitters.
    - `tx_cnc_mem`: Pointer to memory for transmit command-and-control.
    - `tx_cnc_footprint`: Footprint size of the transmit command-and-control memory.
    - `tx_rng_mem`: Pointer to memory for transmit random number generator.
    - `tx_rng_footprint`: Footprint size of the transmit random number generator memory.
    - `tx_fseq_mem`: Pointer to memory for transmit flow sequence.
    - `tx_fseq_footprint`: Footprint size of the transmit flow sequence memory.
    - `tx_mcache_mem`: Pointer to memory for transmit metadata cache.
    - `tx_mcache_footprint`: Footprint size of the transmit metadata cache memory.
    - `tx_dcache_mem`: Pointer to memory for transmit data cache.
    - `tx_dcache_footprint`: Footprint size of the transmit data cache memory.
    - `tx_fctl_mem`: Pointer to memory for transmit flow control.
    - `tx_fctl_footprint`: Footprint size of the transmit flow control memory.
    - `dedup_cnc_mem`: Pointer to memory for deduplication command-and-control.
    - `dedup_tcache_mem`: Pointer to memory for deduplication transaction cache.
    - `dedup_mcache_mem`: Pointer to memory for deduplication metadata cache.
    - `dedup_scratch_mem`: Pointer to memory for deduplication scratch space.
    - `dedup_cr_max`: Maximum credit for deduplication.
    - `dedup_lazy`: Lazy parameter for deduplication.
    - `dedup_seed`: Seed for deduplication random number generator.
    - `rx_cnt`: Number of receivers.
    - `rx_lazy`: Lazy parameter for receivers.
    - `rx_cnc_mem`: Pointer to memory for receive command-and-control.
    - `rx_cnc_footprint`: Footprint size of the receive command-and-control memory.
    - `rx_rng_mem`: Pointer to memory for receive random number generator.
    - `rx_rng_footprint`: Footprint size of the receive random number generator memory.
    - `rx_fseq_mem`: Pointer to memory for receive flow sequence.
    - `rx_fseq_footprint`: Footprint size of the receive flow sequence memory.
    - `rx_tcache_mem`: Pointer to memory for receive transaction cache.
    - `rx_tcache_footprint`: Footprint size of the receive transaction cache memory.
    - `pkt_framing`: Packet framing size.
    - `pkt_payload_max`: Maximum packet payload size.
    - `burst_tau`: Average time between bursts.
    - `burst_avg`: Average burst size.
    - `dup_thresh`: Threshold for duplicate detection.
    - `dup_avg_age`: Average age of duplicates.
- **Description**: The `test_cfg` structure is a configuration data structure used to manage and configure various parameters and memory allocations for a test involving transmission, deduplication, and reception of data packets. It includes pointers to memory for command-and-control, random number generators, flow sequences, metadata caches, data caches, and flow control for both transmission and reception. It also contains parameters for deduplication, such as maximum credits, lazy parameters, and a random seed. Additionally, it holds configuration details for packet framing, payload size, burst characteristics, and duplicate detection thresholds.


---
### test\_cfg\_t
- **Type**: `struct`
- **Members**:
    - `wksp`: Pointer to a workspace object used for memory management.
    - `tx_cnt`: Number of transmission (TX) tiles.
    - `tx_lazy`: Lazy parameter for TX operations, affecting timing and performance.
    - `tx_cnc_mem`: Pointer to memory for TX command-and-control (CNC) operations.
    - `tx_cnc_footprint`: Size of the memory footprint for TX CNC operations.
    - `tx_rng_mem`: Pointer to memory for TX random number generator (RNG) operations.
    - `tx_rng_footprint`: Size of the memory footprint for TX RNG operations.
    - `tx_fseq_mem`: Pointer to memory for TX flow sequence operations.
    - `tx_fseq_footprint`: Size of the memory footprint for TX flow sequence operations.
    - `tx_mcache_mem`: Pointer to memory for TX metadata cache operations.
    - `tx_mcache_footprint`: Size of the memory footprint for TX metadata cache operations.
    - `tx_dcache_mem`: Pointer to memory for TX data cache operations.
    - `tx_dcache_footprint`: Size of the memory footprint for TX data cache operations.
    - `tx_fctl_mem`: Pointer to memory for TX flow control operations.
    - `tx_fctl_footprint`: Size of the memory footprint for TX flow control operations.
    - `dedup_cnc_mem`: Pointer to memory for deduplication CNC operations.
    - `dedup_tcache_mem`: Pointer to memory for deduplication transaction cache operations.
    - `dedup_mcache_mem`: Pointer to memory for deduplication metadata cache operations.
    - `dedup_scratch_mem`: Pointer to scratch memory for deduplication operations.
    - `dedup_cr_max`: Maximum credit for deduplication operations.
    - `dedup_lazy`: Lazy parameter for deduplication operations, affecting timing and performance.
    - `dedup_seed`: Seed value for deduplication RNG operations.
    - `rx_cnt`: Number of reception (RX) tiles.
    - `rx_lazy`: Lazy parameter for RX operations, affecting timing and performance.
    - `rx_cnc_mem`: Pointer to memory for RX CNC operations.
    - `rx_cnc_footprint`: Size of the memory footprint for RX CNC operations.
    - `rx_rng_mem`: Pointer to memory for RX RNG operations.
    - `rx_rng_footprint`: Size of the memory footprint for RX RNG operations.
    - `rx_fseq_mem`: Pointer to memory for RX flow sequence operations.
    - `rx_fseq_footprint`: Size of the memory footprint for RX flow sequence operations.
    - `rx_tcache_mem`: Pointer to memory for RX transaction cache operations.
    - `rx_tcache_footprint`: Size of the memory footprint for RX transaction cache operations.
    - `pkt_framing`: Size of the packet framing overhead.
    - `pkt_payload_max`: Maximum size of the packet payload.
    - `burst_tau`: Average time between bursts in ticks.
    - `burst_avg`: Average size of a burst in bytes.
    - `dup_thresh`: Threshold for determining duplicate packets.
    - `dup_avg_age`: Average age of duplicate packets.
- **Description**: The `test_cfg_t` structure is a configuration data structure used in a network testing environment. It encapsulates various parameters and memory pointers required for managing transmission (TX), reception (RX), and deduplication operations across multiple tiles. The structure includes fields for workspace management, command-and-control memory, random number generation, flow control, and caching operations. It also contains parameters for packet handling, such as framing, payload size, and burst characteristics, as well as deduplication settings like credit limits and lazy parameters. This structure is essential for configuring and executing network tests that involve complex data flow and deduplication processes.


# Functions

---
### tx\_tile\_main<!-- {{#callable:tx_tile_main}} -->
The `tx_tile_main` function simulates the transmission of synthetic network traffic by managing command-and-control signals, flow control, and data caching, while generating and publishing synthetic data fragments in a loop.
- **Inputs**:
    - `argc`: An integer representing the index of the transmission (tx) tile, used to calculate the tile's unique memory offsets.
    - `argv`: A pointer to an array of character pointers, which is cast to a `test_cfg_t` structure containing configuration parameters for the transmission tile.
- **Control Flow**:
    - Initialize various pointers and variables for command-and-control, memory caches, flow control, and random number generation based on the tile index and configuration.
    - Set up initial diagnostic and housekeeping configurations, including timing and synthetic load model parameters.
    - Enter an infinite loop to simulate the transmission process, performing housekeeping tasks at a low rate in the background.
    - Check for command-and-control signals and flow control credits, adjusting the backpressure state accordingly.
    - If backpressure is detected, pause and update the current time, then continue the loop.
    - If not backpressured, check if the next burst of data is ready to start, and if so, record the timestamp and prepare the synthetic data fragment.
    - Generate and fill the data region with a test pattern using AVX instructions, then publish the fragment to consumers.
    - Update the chunk and sequence for the next iteration, adjusting the burst parameters if the end of a burst is reached.
    - Continue the loop until a halt signal is received, at which point the function signals a boot state and returns.
- **Output**: The function returns an integer, specifically 0, indicating successful execution.


---
### dedup\_tile\_main<!-- {{#callable:dedup_tile_main}} -->
The `dedup_tile_main` function initializes and manages resources for a deduplication tile, processes deduplication tasks, and cleans up resources upon completion.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments, which is not used in this function.
    - `argv`: An array of character pointers representing the command-line arguments, which is cast to a `test_cfg_t` structure pointer for configuration data.
- **Control Flow**:
    - The function begins by casting `argv` to a `test_cfg_t` pointer to access configuration data.
    - It checks if `tx_cnt` or `rx_cnt` exceed 128, logging an error if they do.
    - It joins the deduplication command-and-control (CNC) memory using `fd_cnc_join`.
    - It initializes arrays for transaction metadata caches (`tx_mcache`) and flow sequence numbers (`tx_fseq`) by joining each respective memory segment.
    - It joins the deduplication transaction cache and metadata cache using `fd_tcache_join` and `fd_mcache_join`.
    - It initializes an array for receive flow sequence numbers (`rx_fseq`) by joining each respective memory segment.
    - A random number generator is initialized using `fd_rng_new` and `fd_rng_join`.
    - The function calls `fd_dedup_tile` to perform the deduplication task, logging an error if it fails.
    - It deletes the random number generator and leaves all joined resources in reverse order of their initialization.
    - Finally, the function returns 0 to indicate successful completion.
- **Output**: The function returns an integer, 0, indicating successful execution.


---
### rx\_tile\_main<!-- {{#callable:rx_tile_main}} -->
The `rx_tile_main` function processes incoming data fragments from a deduplication tile, performing housekeeping tasks and validating data integrity.
- **Inputs**:
    - `argc`: An integer representing the index of the receiver (rx) tile.
    - `argv`: An array of character pointers, which is cast to a `test_cfg_t` structure containing configuration data for the test.
- **Control Flow**:
    - Initialize various components such as CNC, mcache, fseq, RNG, and tcache using the configuration data.
    - Enter an infinite loop to process incoming data fragments.
    - Wait for a fragment sequence while performing housekeeping tasks in the background.
    - If housekeeping is needed, update synchronization info, send flow control credits, send diagnostic info, and check for command-and-control signals.
    - If an overrun is detected while polling, log an error and exit.
    - Process the received fragment, checking for duplicates and validating the payload integrity.
    - If a duplicate or corrupt payload is detected, log an error and exit.
    - Increment the sequence number and iteration counter for the next loop iteration.
    - Upon exiting the loop, signal the CNC to boot and return 0.
- **Output**: Returns an integer, 0, indicating successful execution.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment and logs a warning if the required capabilities are not present, then halts the program.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Call `fd_boot` to initialize the environment with command-line arguments.
    - Log a warning message indicating that the unit test requires specific capabilities (FD_HAS_HOSTED and FD_HAS_AVX).
    - Call `fd_halt` to terminate the program.
    - Return 0 to indicate successful execution.
- **Output**: The function returns an integer 0, indicating successful execution.



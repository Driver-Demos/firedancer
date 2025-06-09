# Purpose
The provided C header file, `fd_replay.h`, defines the interface for a module that replays data from a pcap file into a tango fragment stream. This module is part of a larger system, likely involving network data processing or simulation, where replaying packet data is necessary for testing or analysis. The file includes definitions for constants, macros, and function prototypes that facilitate the replay of packet data, ensuring that it can be integrated into a broader system with multiple consumers. The replay functionality is designed to handle both reliable and unreliable consumers, with specific mechanisms for flow control and diagnostics.

Key components of this header file include the definition of control signals and diagnostic counters used by the replay tile, which are crucial for managing the state and performance of the replay process. The file specifies the alignment and memory footprint requirements for the replay tile's scratch memory, ensuring efficient memory usage and minimizing cache coherence issues. The function prototypes, such as [`fd_replay_tile`](#fd_replay_tile) and [`fd_replay_tile_loop`](#fd_replay_tile_loop), provide the necessary interfaces for initializing and running the replay process, handling command-and-control operations, and managing the flow of packet data to consumers. This header file is intended to be included in other C source files, providing a clear API for integrating the replay functionality into larger applications.
# Imports and Dependencies

---
- `../../disco/fd_disco_base.h`


# Function Declarations (Public API)

---
### fd\_replay\_tile\_scratch\_align<!-- {{#callable_declaration:fd_replay_tile_scratch_align}} -->
Return the required alignment for a replay tile scratch region.
- **Description**: This function provides the alignment requirement for a replay tile scratch region, which is necessary for setting up the memory correctly before running a replay tile. It should be called when preparing the scratch memory to ensure it meets the alignment constraints, which helps in mitigating false sharing and optimizing performance. The alignment value is a constant and is an integer power of 2, ensuring compatibility with typical memory alignment requirements.
- **Inputs**: None
- **Output**: Returns the alignment requirement as an unsigned long integer, which is a constant value defined by FD_REPLAY_TILE_SCRATCH_ALIGN.
- **See also**: [`fd_replay_tile_scratch_align`](fd_replay_loop.c.driver.md#fd_replay_tile_scratch_align)  (Implementation)


---
### fd\_replay\_tile\_scratch\_footprint<!-- {{#callable_declaration:fd_replay_tile_scratch_footprint}} -->
Calculate the memory footprint required for a replay tile scratch region.
- **Description**: This function computes the memory footprint needed for a replay tile scratch region that can support a specified number of outputs. It should be used when setting up the memory requirements for a replay tile. The function returns zero if the specified number of outputs exceeds the maximum allowed, enabling the caller to detect and handle configuration issues. It is important to ensure that the number of outputs does not exceed the defined maximum before calling this function.
- **Inputs**:
    - `out_cnt`: The number of reliable consumers the replay tile will support. It must be a non-negative value and should not exceed FD_REPLAY_TILE_OUT_MAX. If out_cnt is greater than this maximum, the function returns zero, indicating an invalid configuration.
- **Output**: The function returns the calculated memory footprint in bytes if the input is valid, or zero if the number of outputs exceeds the maximum allowed.
- **See also**: [`fd_replay_tile_scratch_footprint`](fd_replay_loop.c.driver.md#fd_replay_tile_scratch_footprint)  (Implementation)


---
### fd\_replay\_tile<!-- {{#callable_declaration:fd_replay_tile}} -->
Replays packets from a pcap file into a fragment stream.
- **Description**: This function replays packets from a specified pcap file into a fragment stream, managing flow control and diagnostics through a command-and-control interface. It should be called when the command-and-control interface is in the BOOT state. The function handles multiple reliable consumers and uses a specified origin for the fragment stream. It requires properly aligned and sized scratch memory and expects the caller to manage the lifetime of all resources used. The function returns 0 on successful execution, transitioning the command-and-control interface through various states, or a non-zero error code if it fails to boot.
- **Inputs**:
    - `cnc`: A pointer to the command-and-control interface for the replay, which must be in the BOOT state before calling. Must not be null.
    - `pcap_path`: A pointer to a null-terminated string specifying the path to the pcap file. Must not be null.
    - `pkt_max`: The maximum size of a packet in the pcap file. Must be greater than zero.
    - `orig`: The origin for the fragment stream, which must be in the range [0, FD_FRAG_META_ORIG_MAX).
    - `mcache`: A pointer to the memory cache for the fragment stream output. Must not be null.
    - `dcache`: A pointer to the data cache for the fragment stream output. Must not be null.
    - `out_cnt`: The number of reliable consumers, which must be less than or equal to FD_REPLAY_TILE_OUT_MAX.
    - `out_fseq`: An array of pointers to sequence numbers for each reliable consumer. Must not be null if out_cnt is greater than zero.
    - `cr_max`: The maximum number of flow control credits. If zero, a default value based on mcache depth is used.
    - `lazy`: The interval in nanoseconds for receiving credits from consumers. If less than or equal to zero, a default value is used.
    - `rng`: A pointer to a random number generator used by the replay. Must not be null.
    - `scratch`: A pointer to scratch memory for the tile, which must be properly aligned and sized. Must not be null.
- **Output**: Returns 0 on successful execution, or a non-zero error code if the tile fails to boot.
- **See also**: [`fd_replay_tile`](fd_replay_loop.c.driver.md#fd_replay_tile)  (Implementation)


---
### fd\_replay\_tile\_loop<!-- {{#callable_declaration:fd_replay_tile_loop}} -->
Replays packets from a pcap file into a fragment stream.
- **Description**: This function replays packets from a specified pcap file into a fragment stream, managing flow control and diagnostics through a command-and-control interface. It is designed to handle multiple reliable consumers and requires the command-and-control interface to be in the BOOT state before invocation. The function transitions the state to RUN upon successful boot and back to BOOT upon halting. It returns 0 on successful execution and a non-zero error code if it fails to boot. The function requires exclusive access to the provided resources during its execution.
- **Inputs**:
    - `cnc`: Local join to the replay's command-and-control interface. Must not be null and should be in the BOOT state before calling.
    - `pcap_path`: Pointer to a string containing the path to the pcap file. Must not be null.
    - `pkt_max`: Maximum size of a packet in the pcap file. Must be a positive value.
    - `orig`: Origin for the pcap fragment stream, must be in the range [0, FD_FRAG_META_ORIG_MAX).
    - `mcache`: Local join to the replay's fragment stream output mcache. Must not be null.
    - `dcache`: Local join to the replay's fragment stream output dcache. Must not be null.
    - `out_cnt`: Number of reliable consumers, indexed from 0 to out_cnt-1. Must not exceed FD_REPLAY_TILE_OUT_MAX.
    - `out_fseq`: Array of pointers to the local join of each reliable consumer's fseq. Must not be null if out_cnt is greater than 0.
    - `cr_max`: Maximum number of flow control credits. If set to 0, a default value based on mcache depth is used.
    - `lazy`: Interval in nanoseconds for receiving credits from consumers. A value <=0 indicates a default should be used.
    - `rng`: Local join to the random number generator for the replay. Must not be null and should be uniquely seeded.
    - `scratch`: Pointer to tile scratch memory. Must be aligned according to fd_replay_tile_scratch_align and have sufficient footprint as per fd_replay_tile_scratch_footprint.
- **Output**: Returns 0 on successful execution, non-zero on failure to boot.
- **See also**: [`fd_replay_tile_loop`](fd_replay_loop.c.driver.md#fd_replay_tile_loop)  (Implementation)



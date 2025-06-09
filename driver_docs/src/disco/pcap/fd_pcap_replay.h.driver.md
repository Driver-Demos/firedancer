# Purpose
This C header file, `fd_pcap_replay.h`, defines the interface for a module that replays packet capture (pcap) data into a "tango fragment stream." The primary functionality of this module is to read packets from a pcap file and publish them to a specified output stream, which can be consumed by multiple reliable and unreliable consumers. The file outlines several constants and macros that define the behavior and configuration of the replay process, such as signal handling for command and control (CNC) operations, diagnostic counters for monitoring the replay process, and parameters for managing output streams and flow control.

The header file provides a detailed API for the [`fd_pcap_replay_tile`](#fd_pcap_replay_tile) function, which is responsible for executing the replay operation. This function requires various parameters, including paths to the pcap file, memory caches for output, and configuration settings for flow control and consumer management. The file also specifies alignment and footprint requirements for scratch memory used during the replay process. The design of this module emphasizes robust operation, allowing for diagnostics and flow control to ensure efficient and reliable packet replay. The header file is intended to be included in other C source files that need to utilize the pcap replay functionality, providing a clear and structured interface for developers.
# Imports and Dependencies

---
- `../fd_disco_base.h`


# Function Declarations (Public API)

---
### fd\_pcap\_replay\_tile\_scratch\_align<!-- {{#callable_declaration:fd_pcap_replay_tile_scratch_align}} -->
Return the required alignment for a pcap_replay tile scratch region.
- **Description**: This function provides the alignment requirement for a scratch memory region used by a pcap_replay tile. It is essential to ensure that the scratch memory is aligned according to this value to avoid issues related to memory access and performance. This function is typically used when setting up the memory layout for a pcap_replay tile, ensuring that the scratch region is correctly aligned to meet the system's requirements.
- **Inputs**: None
- **Output**: Returns the alignment requirement as an unsigned long integer, which is a power of 2 and at least double the cache line size.
- **See also**: [`fd_pcap_replay_tile_scratch_align`](fd_pcap_replay.c.driver.md#fd_pcap_replay_tile_scratch_align)  (Implementation)


---
### fd\_pcap\_replay\_tile\_scratch\_footprint<!-- {{#callable_declaration:fd_pcap_replay_tile_scratch_footprint}} -->
Calculate the memory footprint required for a pcap replay tile scratch region.
- **Description**: This function computes the memory footprint needed for a scratch region that supports a specified number of outputs in a pcap replay tile. It should be used when setting up the scratch memory for a pcap replay tile to ensure that the memory allocation is sufficient. The function expects a valid number of outputs, which must not exceed the defined maximum. If the provided output count is invalid, the function returns zero, allowing the caller to detect and handle configuration errors.
- **Inputs**:
    - `out_cnt`: The number of reliable consumers the pcap replay tile will support. It must be a non-negative value not exceeding FD_PCAP_REPLAY_TILE_OUT_MAX. If out_cnt is greater than this maximum, the function returns zero.
- **Output**: The function returns the calculated memory footprint in bytes if the input is valid. If the input is invalid, it returns zero.
- **See also**: [`fd_pcap_replay_tile_scratch_footprint`](fd_pcap_replay.c.driver.md#fd_pcap_replay_tile_scratch_footprint)  (Implementation)


---
### fd\_pcap\_replay\_tile<!-- {{#callable_declaration:fd_pcap_replay_tile}} -->
Replays packets from a pcap file into a fragment stream.
- **Description**: This function is used to replay packets from a specified pcap file into a fragment stream, managing flow control and diagnostics through a command-and-control interface. It should be called when the command-and-control (cnc) is in the BOOT state. The function handles the transition of the cnc from BOOT to RUN, processes the pcap file, and transitions back to BOOT upon completion or halt. It supports multiple reliable consumers and uses a scratch memory region for temporary data. Proper alignment and footprint of the scratch memory are required, and the function returns 0 on successful execution or a non-zero error code if it fails to boot.
- **Inputs**:
    - `cnc`: Local join to the command-and-control interface for the pcap replay. Must not be null and should be in the BOOT state before calling.
    - `pcap_path`: Pointer to a string containing the path to the pcap file. Must not be null.
    - `pkt_max`: Maximum size of a packet in the pcap file. Must be a positive value.
    - `orig`: Origin for the pcap fragment stream, should be in the range [0, FD_FRAG_META_ORIG_MAX).
    - `mcache`: Local join to the fragment stream output mcache. Must not be null.
    - `dcache`: Local join to the fragment stream output dcache. Must not be null.
    - `out_cnt`: Number of reliable consumers, indexed from 0 to out_cnt-1. Must not exceed FD_PCAP_REPLAY_TILE_OUT_MAX.
    - `out_fseq`: Array of pointers to the local join of each reliable consumer's fseq. Must not be null if out_cnt is greater than 0.
    - `cr_max`: Maximum number of flow control credits. If set to 0, a default value based on mcache depth is used.
    - `lazy`: Interval in nanoseconds for receiving credits from consumers. If less than or equal to 0, a default value is used.
    - `rng`: Local join to the random number generator used by the pcap replay. Must not be used by other tiles while this tile is running.
    - `scratch`: Pointer to the scratch memory region used by the tile. Must be properly aligned and have sufficient footprint as specified by fd_pcap_replay_tile_scratch_align and fd_pcap_replay_tile_scratch_footprint.
- **Output**: Returns 0 on successful execution, or a non-zero error code if the tile fails to boot.
- **See also**: [`fd_pcap_replay_tile`](fd_pcap_replay.c.driver.md#fd_pcap_replay_tile)  (Implementation)



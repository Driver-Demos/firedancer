# Purpose
This C source code file is a comprehensive test suite for verifying the functionality and performance of a SHA-256 hashing implementation. The code is structured around a main function that initializes the environment, sets up random number generation, and performs a series of tests to ensure the correctness and efficiency of the SHA-256 functions. It includes static assertions to validate the alignment and footprint of the SHA-256 structures, ensuring they meet expected specifications. The code tests various aspects of the SHA-256 implementation, including single-shot hashing, incremental hashing, and batch processing, using predefined test vectors to verify the accuracy of the hash outputs.

The file also includes performance benchmarking for different hashing scenarios, such as Poh-style hashing, incremental hashing, streamlined hashing, and batched hashing, providing insights into the throughput and efficiency of the implementation. The benchmarks simulate real-world data processing scenarios, such as hashing UDP payloads, to measure the hashing speed in terms of gigabits per second. Additionally, the code tests the handling of large input sizes, ensuring the implementation can process data sizes beyond typical limits. Overall, this file serves as a robust validation and benchmarking tool for the SHA-256 hashing functions, ensuring they meet both functional and performance requirements.
# Imports and Dependencies

---
- `../fd_ballet.h`
- `fd_sha256_test_vector.c`


# Functions

---
### main<!-- {{#callable:main}} -->
The `main` function initializes and tests SHA-256 hashing operations, including single-shot, incremental, and batched hashing, and performs benchmarking on these operations.
- **Inputs**:
    - `argc`: The number of command-line arguments.
    - `argv`: An array of command-line argument strings.
- **Control Flow**:
    - Initialize the environment and random number generator.
    - Verify SHA-256 alignment and footprint constants.
    - Test SHA-256 object creation and joining with various memory alignments.
    - Iterate over test vectors to validate single-shot, incremental, and streamlined SHA-256 hashing.
    - Test SHA-256 batching with random data and validate results against reference hashes.
    - Benchmark SHA-256 hashing in different modes (PoH-style, incremental, streamlined, and batched) for performance metrics.
    - Test hashing of a large input size to verify correctness against a known hash value.
    - Clean up resources and exit.
- **Output**: The function returns an integer status code, 0 for successful execution.



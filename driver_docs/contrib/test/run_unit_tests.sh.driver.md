# Purpose
The provided file is a Bash script designed to schedule and execute unit tests in a NUMA (Non-Uniform Memory Access) aware manner. It configures the execution environment by setting default values for job parameters such as the number of jobs, NUMA node index, page size, and memory allocation per job. The script parses command-line arguments to customize these settings and uses a greedy scheduling approach to distribute test execution across available NUMA nodes and CPUs. The script's functionality is narrow, focusing specifically on optimizing test execution by leveraging system resources efficiently. It is relevant to a codebase as it automates the testing process, ensuring that tests are run in parallel while considering system memory and CPU constraints, which is crucial for maintaining code quality and performance.
# Content Summary
The `run_unit_tests.sh` script is a Bash script designed to execute unit tests in a NUMA (Non-Uniform Memory Access) aware manner, optimizing the distribution of test jobs across available NUMA nodes and CPUs. This script is particularly useful in environments where memory and CPU resources are distributed across multiple NUMA nodes, allowing for efficient resource utilization during test execution.

### Key Functional Details:

1. **Script Initialization and Defaults:**
   - The script begins by setting strict error handling options (`set -euo pipefail`) to ensure robust execution.
   - Default values are defined for several parameters, including `JOBS` (number of concurrent jobs), `NUMA_IDX` (NUMA node index), `PAGE_SZ` (page size, defaulting to "gigantic"), `JOB_MEM` (memory per job, defaulting to 2GiB), `PAGE_CNT` (page count), `TESTS` (test files), and `VERBOSE` (verbosity level).

2. **Command-Line Argument Parsing:**
   - The script processes command-line arguments to customize its behavior. Flags include `--tests` for specifying test files, `-j` for setting the number of jobs, `--numa-idx` for NUMA node indices, `--page-sz` for page size, `--page-cnt` for page count, `--job-mem` for job memory, and `-v` for verbosity.

3. **NUMA and CPU Configuration:**
   - The script determines the NUMA nodes to use by parsing the `NUMA_IDX` argument.
   - It calculates the required page count based on the specified page size and job memory.
   - The script maps available CPUs per NUMA node and calculates job parallelism, either using all available CPUs or distributing jobs evenly across NUMA nodes.

4. **Test Scheduling and Execution:**
   - The script reads a list of tests to be executed, filtering out comments.
   - It schedules tests to run on available CPUs, ensuring that each CPU is utilized efficiently.
   - The `dispatch` function is responsible for starting test jobs, logging their output, and associating them with specific NUMA nodes and CPUs.

5. **Job Management:**
   - The script tracks running jobs using process IDs (PIDs) and manages job slots per NUMA node.
   - It includes mechanisms to handle job completion, logging results, and adjusting job counts based on available resources.

6. **Resource Checks and Adjustments:**
   - Before executing jobs, the script checks the availability of memory pages on each NUMA node and adjusts the number of concurrent jobs if necessary to prevent resource exhaustion.

7. **Result Reporting:**
   - The script provides feedback on test execution, indicating success or failure for each test. It outputs results in a color-coded format for easy identification of pass/fail status.
   - Upon completion, it summarizes the overall test results, exiting with a status code that reflects the success or failure of the test suite.

This script is a practical tool for developers working in environments with complex memory and CPU configurations, allowing them to efficiently run unit tests while maximizing resource utilization.

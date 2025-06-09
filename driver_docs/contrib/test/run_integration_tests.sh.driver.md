# Purpose
The provided script, `run_integration_tests.sh`, is a Bash executable designed to manage and execute integration tests for a software project. It offers narrow functionality focused on running integration tests sequentially, ensuring that only one test runs at a time to avoid potential conflicts or system configuration changes. The script processes command-line arguments to specify test files and verbosity, and it uses a Makefile to determine the appropriate build environment if no tests are directly specified. It manages test execution by dispatching and monitoring test processes, capturing their output, and logging results. The script also handles cleanup and reports the success or failure of the tests, making it a crucial tool for developers to verify the integration of different software components in a controlled manner.
# Global Variables

---
### TESTS
- **Type**: `string`
- **Description**: The `TESTS` variable is a global string variable that is initially set to an empty value. It is intended to hold the path to a file containing a list of integration tests to be executed. The variable is populated based on the command-line argument `--tests` provided when the script is run.
- **Use**: This variable is used to determine which integration tests should be scheduled and executed by the script.


---
### VERBOSE
- **Type**: `integer`
- **Description**: The `VERBOSE` variable is a global integer variable used to control the verbosity level of the script's output. It is initialized to 0, indicating that verbose output is disabled by default.
- **Use**: The `VERBOSE` variable is set to 1 when the `-v` flag is passed as a command-line argument, enabling verbose output for debugging or informational purposes.


---
### AVAILABLE\_JOBS
- **Type**: `integer`
- **Description**: The `AVAILABLE_JOBS` variable is a global integer variable that is initialized to 1. It is used to control the number of concurrent jobs that can be scheduled and run at any given time in the script. By setting it to 1, the script ensures that only one integration test job is executed at a time, preventing concurrent execution.
- **Use**: This variable is used to limit the number of concurrent jobs to one, ensuring sequential execution of integration tests.


---
### FAIL\_CNT
- **Type**: `integer`
- **Description**: `FAIL_CNT` is a global integer variable initialized to zero. It is used to keep track of the number of integration tests that have failed during the execution of the script.
- **Use**: `FAIL_CNT` is incremented each time a test fails, and its final value determines the script's exit status, indicating the number of failed tests.


# Functions

---
### rc\_path
The `rc_path` function generates a file path for storing the return code and elapsed time of a process based on its process ID.
- **Inputs**:
    - `$1`: The process ID (PID) for which the return code file path is being generated.
- **Control Flow**:
    - The function takes a single argument, which is the process ID.
    - It constructs a file path string using the format `/tmp/.pid-<PID>.rc`.
    - The constructed file path is then printed to the standard output.
- **Output**: A string representing the file path `/tmp/.pid-<PID>.rc` where `<PID>` is the provided process ID.


---
### runner
The `runner` function executes a given program with specific logging and coverage settings, capturing its execution time and exit status.
- **Inputs**:
    - `prog`: The path to the program to be executed.
    - `log`: The path to the log file where the program's stderr output will be redirected.
    - `...`: Additional arguments to be passed to the program being executed.
- **Control Flow**:
    - The function starts by setting the local variable `pid` to the current process ID (`BASHPID`).
    - It extracts the program path (`prog`) and log file path (`log`) from the arguments, and constructs a full log file path (`logfull`).
    - A coverage directory (`covdir`) is created based on the program's directory structure, and a coverage file path (`LLVM_PROFILE_FILE`) is set up.
    - The function then executes the program using `sudo`, redirecting its stderr to the log file and suppressing stdout, while also setting the log path and log level.
    - The execution time is measured using the `time` command, and the exit status is captured.
    - The exit status and elapsed time are written to a file at a path determined by the `rc_path` function, using the process ID.
- **Output**: The function does not return a value, but it writes the program's exit status and elapsed time to a file specified by the `rc_path` function.


---
### dispatch
The `dispatch` function forks a task to run a specified program with logging and tracks its process ID for later management.
- **Inputs**:
    - `prog`: The path to the program to be executed.
    - `...`: Additional command-line arguments to be passed to the program.
- **Control Flow**:
    - Extracts the program name from the provided path.
    - Creates a directory for logs based on the program's path and name.
    - Generates a log file name with a timestamp.
    - If verbose mode is enabled, prints a message indicating the program being dispatched.
    - Calls the `runner` function in the background to execute the program with logging, capturing its process ID.
    - Stores the process ID in the `PIDS` associative array and maps it to the program name and log file in `PID2UNIT` and `PID2LOG` arrays respectively.
- **Output**: The function does not return a value but manages the execution of a program in the background and tracks its process ID for further management.


---
### sow
The 'sow' function schedules tasks from a list of tests until the maximum concurrency limit is reached.
- **Inputs**:
    - `None`: The function does not take any direct input arguments, but it operates on the global TEST_LIST and AVAILABLE_JOBS variables.
- **Control Flow**:
    - Check if TEST_LIST is empty or AVAILABLE_JOBS is zero; if either is true, return immediately.
    - Retrieve the first test from TEST_LIST and remove it from the list.
    - Decrement AVAILABLE_JOBS by one to account for the new task being scheduled.
    - Call the 'dispatch' function with the test to schedule it for execution.
- **Output**: The function does not return any value; it modifies the global state by scheduling a test for execution and updating the AVAILABLE_JOBS count.


---
### reap
The 'reap' function waits for any child process to finish and handles the cleanup and logging of the process results.
- **Inputs**: None
- **Control Flow**:
    - The function waits for any child process in the PIDS array to finish using 'wait -n'.
    - It iterates over the PIDS array to check if any process has completed by verifying the absence of its directory in '/proc/'.
    - For each completed process, it reads the return code and elapsed time from the corresponding rc file.
    - It retrieves the unit name and log file path associated with the process ID from the PID2UNIT and PID2LOG arrays.
    - The function increments the AVAILABLE_JOBS counter to allow scheduling of new jobs.
    - If the process exited with a non-zero return code, it increments the FAIL_CNT counter and logs the failure details.
    - If the process exited successfully, it logs a success message.
- **Output**: The function does not return a value but updates global state variables such as AVAILABLE_JOBS and FAIL_CNT, and logs the results of completed processes.



# Purpose
This Python script is designed to execute a series of shell commands in parallel using multiple CPU cores. It achieves this by dividing the available CPU cores into batches and assigning each batch to a separate worker process. The script reads commands from a specified file, and each command is executed with a specific set of CPU cores as parameters. The script uses the `multiprocessing` module to manage parallel execution and inter-process communication, employing queues to distribute commands and parameters to worker processes. It also includes error handling to detect and respond to any command execution failures, ensuring that all processes are terminated if an error occurs.

The script is structured as a standalone executable, intended to be run from the command line with a file path argument specifying the file containing the commands to be executed. The main components include functions for grouping CPUs into batches, a worker function that executes commands, and a main function that orchestrates the overall process. The script is particularly useful for scenarios where tasks can be parallelized across multiple CPU cores, such as batch processing or distributed computing tasks. It does not define a public API or external interfaces, as its primary purpose is to execute a predefined set of commands in a parallelized manner.
# Imports and Dependencies

---
- `subprocess`
- `multiprocessing`
- `multiprocessing.Queue`
- `multiprocessing.Value`
- `multiprocessing.Event`
- `os`
- `sys`


# Functions

---
### group\_cpus\_by\_batch\_size<!-- {{#callable:firedancer/src/flamenco/runtime/tests/run_ledger_tests_all.group_cpus_by_batch_size}} -->
The function `group_cpus_by_batch_size` organizes available CPU indices into batches of a specified size, starting from the third CPU.
- **Inputs**:
    - `batch_size`: An integer specifying the number of CPUs to include in each batch, defaulting to 8.
- **Control Flow**:
    - Import the `os` module to access system-level information.
    - Retrieve the total number of CPUs available using `os.cpu_count()`.
    - Limit the number of CPUs to 128 if more are available.
    - Print the total number of CPUs available.
    - Create a list of batches, each containing a range of CPU indices starting from the third CPU, with each batch having a size defined by `batch_size`.
    - Return the list of CPU batches.
- **Output**: A list of lists, where each inner list contains indices of CPUs grouped into batches of the specified size.


---
### group\_cpus\_by\_num\_batches<!-- {{#callable:firedancer/src/flamenco/runtime/tests/run_ledger_tests_all.group_cpus_by_num_batches}} -->
The function `group_cpus_by_num_batches` divides available CPUs into a specified number of batches.
- **Inputs**:
    - `num_batches`: An integer specifying the number of batches to divide the CPUs into, with a default value of 4.
- **Control Flow**:
    - Import the `os` module to access system-level information.
    - Retrieve the total number of available CPUs using `os.cpu_count()`.
    - Calculate the batch size by dividing the total number of CPUs by the number of batches.
    - Create a list of CPU batches, where each batch is a list of CPU indices, starting from index 2, and ensure the number of batches does not exceed `num_batches`.
    - Return the list of CPU batches.
- **Output**: A list of lists, where each inner list contains indices of CPUs grouped into a batch.


---
### worker<!-- {{#callable:firedancer/src/flamenco/runtime/tests/run_ledger_tests_all.worker}} -->
The `worker` function processes commands from a queue using available parameters, handling errors and signaling termination if any command fails.
- **Inputs**:
    - `command_queue`: A queue from which commands are retrieved for execution.
    - `available_params`: A queue containing parameters that can be used with commands.
    - `error_occurred`: A shared integer value used to indicate if an error has occurred during command execution.
    - `error_event`: An event object used to signal if an error has occurred, prompting the worker to stop processing.
- **Control Flow**:
    - The function enters a loop that continues until the `error_event` is set.
    - It retrieves a command from the `command_queue`.
    - If the command is `None`, the loop breaks, signaling the worker to quit.
    - A parameter is acquired from the `available_params` queue.
    - The command is executed with the parameter using `subprocess.run`.
    - If the command execution is successful, a completion message is printed.
    - If a `subprocess.CalledProcessError` is raised, an error message is printed, `error_occurred` is set to 1, `error_event` is set, and the loop breaks.
    - The parameter is returned to the `available_params` queue in a `finally` block, ensuring it is always released.
- **Output**: The function does not return a value; it performs command execution and error handling, affecting shared state through `error_occurred` and `error_event`.


---
### main<!-- {{#callable:firedancer/src/flamenco/runtime/tests/run_ledger_tests_all.main}} -->
The `main` function orchestrates the execution of commands from a file using multiprocessing, distributing tasks across CPU batches and handling errors.
- **Inputs**:
    - `file_path`: A string representing the path to a file containing commands to be executed.
- **Control Flow**:
    - The function starts by grouping CPUs into batches of size 10 and selects the first 5 batches.
    - It constructs parameter ranges for each CPU batch to be used in command execution.
    - Commands are read from the specified file and stored in a queue for processing.
    - A multiprocessing manager is used to create shared queues for available parameters and commands, and a shared value for error tracking.
    - Worker processes are created, each executing the `worker` function with the command queue, available parameters, and error tracking variables.
    - Each worker process retrieves commands and parameters, executes them, and handles any errors by setting an error flag and event.
    - After all commands are processed, workers are signaled to stop by placing `None` in the command queue.
    - The function waits for all worker processes to complete and checks for any errors, terminating the script if an error occurred.
- **Output**: The function does not return a value; it prints output to the console and may terminate the script if an error occurs during command execution.
- **Functions called**:
    - [`firedancer/src/flamenco/runtime/tests/run_ledger_tests_all.group_cpus_by_batch_size`](#group_cpus_by_batch_size)



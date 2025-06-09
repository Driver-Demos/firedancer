# Purpose
This Bash script is designed to complement automatic unit tests by executing a series of test binaries and logging their outputs. It provides narrow functionality, specifically tailored for running and managing unit tests within a development environment where `OBJDIR` and `MACHINE` environment variables are set. The script systematically executes various test cases, capturing their outputs into designated log files within a specified log path. It includes tests for shared memory control, workspace control, allocation control, and inter-process communication, among others. Additionally, the script contains commented-out sections and placeholders for future enhancements or fixes, indicating areas where the testing process may be expanded or improved. Overall, this script is a utility for developers to automate and verify the correctness of different components in a software project.
# Global Variables

---
### BIN
- **Type**: `string`
- **Description**: The `BIN` variable is a global string variable that constructs a path to a 'bin' directory within the object directory specified by the `OBJDIR` environment variable. It uses the syntax `${OBJDIR:?}/bin` to ensure that `OBJDIR` is set and non-empty, otherwise the script will terminate with an error.
- **Use**: `BIN` is used to specify the directory path where binary executables are located, although it is not actively used in the provided script.


---
### UNIT\_TEST
- **Type**: `string`
- **Description**: The `UNIT_TEST` variable is a global string variable that holds the path to the unit test directory within the object directory specified by `OBJDIR`. It is constructed by appending '/unit-test' to the `OBJDIR` path, which is expected to be set in the environment before the script is executed.
- **Use**: This variable is used to specify the location of unit test executables that are run throughout the script to perform various tests, with their outputs being redirected to log files.


---
### FD\_LOG\_PATH
- **Type**: `string`
- **Description**: The `FD_LOG_PATH` variable is a global environment variable set to the string "-". It is exported for use by other processes or scripts that are executed within the same environment.
- **Use**: `FD_LOG_PATH` is used to define a log path or logging behavior for the script, although its specific role is not detailed in the provided code.



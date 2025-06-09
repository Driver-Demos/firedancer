# Purpose
This Bash script, `run_conformance_tests.sh`, is designed to automate the execution of conformance tests for the Solana blockchain using a specified set of test inputs. It provides a narrow functionality focused on setting up the necessary environment and dependencies, such as cloning and preparing specific branches of the Firedancer, Solfuzz-Agave, and Solana-Conformance repositories. The script is an executable file that manages the configuration and execution of tests by accepting various command-line arguments to customize the test environment, such as specifying directories, repositories, and branches. It ensures that all required dependencies are correctly set up and then runs the tests, storing the results in a designated output directory. This script is essential for developers or testers who need to validate the conformance of Solana implementations efficiently.
# Global Variables

---
### RUN\_DIRECTORY
- **Type**: `string`
- **Description**: The `RUN_DIRECTORY` variable is a global string variable that specifies the default directory path where the conformance tests will be executed. It is initialized with the default value "/data/conformance_tests". This directory is used as the working directory for running the tests and storing related files.
- **Use**: This variable is used to determine the directory where the conformance tests are run and where related repositories and results are stored.


---
### FIREDANCER\_BRANCH
- **Type**: `string`
- **Description**: The `FIREDANCER_BRANCH` variable is a global string variable that specifies the branch of the Firedancer repository to be used during the setup and execution of the conformance tests. It is initialized with a default value of 'main', which can be overridden by a command-line argument.
- **Use**: This variable is used to determine which branch of the Firedancer repository is checked out and built during the script execution.


---
### AGAVE\_BRANCH
- **Type**: `string`
- **Description**: `AGAVE_BRANCH` is a global variable that specifies the branch of the solfuzz-agave repository to be used in the script. It is initialized with a default value of 'agave-v2.0', which can be overridden by a command-line argument.
- **Use**: This variable is used to determine which branch of the solfuzz-agave repository to checkout during the setup process.


---
### SOLANA\_CONFORMANCE\_BRANCH
- **Type**: `string`
- **Description**: The `SOLANA_CONFORMANCE_BRANCH` variable is a global string variable that specifies the branch of the solana-conformance repository to be used during the execution of the conformance tests. By default, it is set to 'main', but it can be overridden by a command-line argument.
- **Use**: This variable is used to determine which branch of the solana-conformance repository is checked out and used for running the conformance tests.


---
### FIREDANCER\_REPO
- **Type**: `string`
- **Description**: The `FIREDANCER_REPO` variable is a global string variable that holds the path to the Firedancer repository. It is used to specify the location where the Firedancer codebase is stored or cloned to, which is necessary for setting up and running the conformance tests.
- **Use**: This variable is used to determine the directory path for the Firedancer repository, which is essential for cloning the repository if it does not exist and for navigating to the directory to perform setup and build operations.


---
### AGAVE\_REPO
- **Type**: `string`
- **Description**: `AGAVE_REPO` is a global variable that stores the path to the solfuzz-agave repository. It is used to specify the location of the repository, which can be set via a command-line argument or defaults to a directory within the run directory if not provided.
- **Use**: This variable is used to navigate to the solfuzz-agave repository directory for setup and build operations.


---
### SOLANA\_CONFORMANCE\_REPO
- **Type**: `string`
- **Description**: The `SOLANA_CONFORMANCE_REPO` variable is a global string variable that holds the path to the solana-conformance repository. It is used to specify the location of the repository needed for running conformance tests.
- **Use**: This variable is used to determine the directory path where the solana-conformance repository is located or cloned to, which is necessary for setting up and executing the conformance tests.


---
### TEST\_INPUTS
- **Type**: `string`
- **Description**: `TEST_INPUTS` is a global variable that stores the directory path containing the test inputs for the conformance tests. It is a required argument for the script, and the script will exit with an error if it is not provided.
- **Use**: This variable is used to specify the location of test inputs when running the conformance tests.


---
### OUTPUT\_DIR
- **Type**: `string`
- **Description**: The `OUTPUT_DIR` variable is a global string variable that specifies the directory path where the test results will be stored after running the conformance tests. It can be set via the command-line argument `-o` or `--output-dir`, and defaults to a subdirectory `test_results` within the `RUN_DIRECTORY` if not explicitly provided.
- **Use**: This variable is used to determine the location for saving the output of the test results generated by the conformance test suite.



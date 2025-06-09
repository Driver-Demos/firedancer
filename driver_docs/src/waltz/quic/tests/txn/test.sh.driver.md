# Purpose
This Bash script, `test.sh`, serves as a wrapper to facilitate the execution of unit tests through the `make` build automation tool. Its primary purpose is to ensure that the tests are executed in the correct build environment by leveraging Make's ability to select the appropriate build directory based on environment variables such as `$CC` (compiler) and `$MACHINE` (machine architecture). The script indirectly calls another script, `config/test.sh`, via the `make run-unit-test` command, passing any additional options provided to `test.sh` through the `TEST_OPTS` variable. Additionally, it sets a shared memory path variable, `SHMEM_PATH`, with a default value of `/mnt/.fd`, which can be overridden by the `FD_SHMEM_PATH` environment variable. This script provides narrow functionality focused on test execution within a specific build context.
# Global Variables

---
### SHMEM\_PATH
- **Type**: `string`
- **Description**: `SHMEM_PATH` is a global string variable that holds the path to a shared memory directory. It is initialized with the value of the environment variable `FD_SHMEM_PATH` if it is set; otherwise, it defaults to `/mnt/.fd`. This allows for flexibility in specifying the shared memory path based on the environment or using a default location.
- **Use**: This variable is used to define the location of the shared memory directory for the script's operations.



# Purpose
This Bash script is a build and installation script for the Firedancer project, providing a broad range of functionality to manage dependencies and system requirements across different operating systems. It is designed to automate the process of fetching, building, and installing various third-party libraries and dependencies required by the project. The script supports multiple commands such as `fetch`, `check`, `install`, and `nuke`, each serving a specific purpose like downloading dependencies, checking system packages, installing libraries, and cleaning up installations, respectively. It includes logic to handle different operating systems (Linux, macOS) and distributions (Fedora, Debian, Alpine) by checking for required packages and installing them if necessary. Additionally, it provides options for development mode and memory sanitizer builds, making it a versatile tool for setting up the development environment for Firedancer.
# Imports and Dependencies

---
- `git`
- `curl`
- `tar`
- `make`
- `cmake`
- `gcc`
- `g++`
- `perl`
- `awk`
- `dpkg`
- `rpm`
- `apk`
- `brew`


# Global Variables

---
### OS
- **Type**: `string`
- **Description**: The `OS` variable is a global string variable that stores the name of the operating system on which the script is running. It is initialized using the `uname -s` command, which returns the operating system name, such as 'Darwin' for macOS or 'Linux' for Linux systems. The script uses this variable to determine the appropriate actions or configurations based on the operating system.
- **Use**: The `OS` variable is used to conditionally execute code blocks specific to the detected operating system, such as setting the `MAKE` command or handling unsupported OS cases.


---
### MAKE
- **Type**: `array`
- **Description**: The `MAKE` variable is a global array variable that is used to store the command for invoking the `make` utility with parallel execution enabled. It is set based on the operating system detected, specifically for Darwin (macOS) and Linux, to use `make -j`, which allows for parallel job execution during the build process.
- **Use**: This variable is used to execute the `make` command with parallel jobs in various functions that build and install software components.


---
### ID
- **Type**: `string`
- **Description**: The `ID` variable is a global string variable that is used to identify the operating system type. It is set to 'macos' if the script is running on a Darwin-based system (macOS).
- **Use**: This variable is used to determine the operating system type for conditional logic in the script, particularly for package management and installation processes.


---
### SUDO
- **Type**: `string`
- **Description**: The `SUDO` variable is a global string variable that is used to determine whether the script needs to use `sudo` to escalate privileges when executing certain commands. It is initialized as an empty string and is set to "sudo" if the current user is not the root user (i.e., the user ID is not 0).
- **Use**: This variable is used to prepend the `sudo` command to package installation commands if the script is not run as the root user.


---
### PREFIX
- **Type**: `string`
- **Description**: The `PREFIX` variable is a global string variable that holds the path to the directory where the software dependencies and components will be installed. It is initialized to the current working directory appended with '/opt', which means that by default, the installation will occur in an 'opt' directory within the current directory from which the script is executed.
- **Use**: This variable is used throughout the script to specify the installation directory for various software components and dependencies.


---
### DEVMODE
- **Type**: `integer`
- **Description**: `DEVMODE` is a global integer variable initialized to 0. It acts as a flag to determine whether the script should operate in development mode.
- **Use**: This variable is used to conditionally execute certain code blocks, such as fetching additional repositories or installing extra packages, when set to 1.


---
### MSAN
- **Type**: `integer`
- **Description**: The `MSAN` variable is a global integer flag used to determine whether MemorySanitizer (MSAN) should be enabled during the build process. It is initialized to 0, indicating that MSAN is disabled by default.
- **Use**: This variable is used to conditionally execute code related to enabling MSAN, such as setting compiler flags and installing specific dependencies like LLVM when its value is set to 1.


---
### \_CC
- **Type**: `string`
- **Description**: The `_CC` variable is a global string variable that holds the name of the C compiler to be used for building the project. It defaults to `gcc` if the `CC` environment variable is not set.
- **Use**: This variable is used to determine the C compiler command that will be executed during the build process.


---
### \_CXX
- **Type**: `string`
- **Description**: The `_CXX` variable is a global string variable that is used to specify the C++ compiler to be used in the build process. It defaults to the value of the `CXX` environment variable, or `g++` if `CXX` is not set.
- **Use**: This variable is used to determine the C++ compiler command for building the software.


---
### EXTRA\_CFLAGS
- **Type**: `string`
- **Description**: `EXTRA_CFLAGS` is a global variable defined as an empty string. It is intended to store additional flags that can be passed to the C compiler during the build process. These flags can be used to modify the behavior of the compiler, such as enabling specific optimizations or warnings.
- **Use**: `EXTRA_CFLAGS` is used to append additional compiler flags when building various dependencies, allowing for customization of the build process.


---
### EXTRA\_CXXFLAGS
- **Type**: `string`
- **Description**: `EXTRA_CXXFLAGS` is a global variable defined as an empty string. It is intended to store additional flags for the C++ compiler, which can be used to modify the behavior of the compiler during the build process.
- **Use**: This variable is used to append extra C++ compiler flags, particularly when building projects with specific configurations such as memory sanitization.


---
### EXTRA\_LDFLAGS
- **Type**: `string`
- **Description**: `EXTRA_LDFLAGS` is a global variable defined as an empty string. It is intended to store additional linker flags that can be used during the build process of various software components. This variable is particularly useful for specifying custom linker options that are not included by default.
- **Use**: `EXTRA_LDFLAGS` is used to append additional linker flags when building software components, allowing for customization of the linking process.


---
### ACTION
- **Type**: `integer`
- **Description**: The `ACTION` variable is a global integer variable initialized to 0. It is used to track whether any of the main script actions (such as `nuke`, `fetch`, `check`, or `install`) have been executed.
- **Use**: `ACTION` is used to determine if the script should proceed with the default action sequence of `fetch`, `check`, and `install` when no specific command is provided.


# Functions

---
### help
The `help` function displays usage instructions and available commands for the script.
- **Inputs**: None
- **Control Flow**:
    - The function uses a `cat` command to output a block of text that describes how to use the script, including the default command and available commands.
    - The function then exits the script with a status code of 0, indicating successful execution.
- **Output**: The function outputs a help message to the console and exits the script.


---
### nuke
The `nuke` function removes all third-party dependency files and checkouts by deleting the specified installation prefix directory.
- **Inputs**: None
- **Control Flow**:
    - The function uses the `rm -rf` command to forcefully and recursively remove the directory specified by the `PREFIX` variable.
    - It prints a message indicating that the directory has been 'nuked'.
    - The function then exits with a status code of 0, indicating successful completion.
- **Output**: The function does not return any value, but it deletes the directory specified by the `PREFIX` variable and prints a confirmation message.


---
### checkout\_repo
The `checkout_repo` function clones a specified Git repository into a designated directory, optionally checking out a specific branch or tag.
- **Inputs**:
    - `$1`: The name of the repository to be cloned, used as the directory name under the prefix path.
    - `$2`: The URL of the Git repository to be cloned.
    - `$3`: The branch or tag to be checked out after cloning; if empty, a specific commit hash is used instead.
    - `$4`: The specific commit hash to reset to if no branch or tag is specified.
- **Control Flow**:
    - Check if the directory for the repository already exists under the prefix path.
    - If the directory exists, print a message indicating that the fetch is being skipped.
    - If the directory does not exist and no branch is specified, clone the repository and reset to the specified commit hash.
    - If the directory does not exist and a branch is specified, clone the repository with the specified branch and depth of 1.
    - If a branch is specified, check if the current tag matches the specified branch.
    - If the tag does not match, fetch the branch and tags, then checkout the specified branch.
- **Output**: The function does not return a value but performs side effects by cloning repositories and checking out branches or commits.


---
### checkout\_llvm
The `checkout_llvm` function downloads and extracts the LLVM source code into a specified directory if it does not already exist.
- **Inputs**: None
- **Control Flow**:
    - Check if the directory `$PREFIX/git/llvm` exists; if it does, print a message and return.
    - If the directory does not exist, print a message indicating the start of the download process.
    - Change the current directory to `$PREFIX/git`.
    - Use `curl` to download the LLVM source tarball from a specified URL and extract it using `tar`.
    - Rename the extracted directory to `llvm`.
    - Return to the previous directory.
- **Output**: The function does not return any value; it performs file system operations to download and extract LLVM source code.


---
### fetch
The `fetch` function initializes git submodules and clones specified repositories into a designated directory, optionally including additional repositories based on development mode settings.
- **Inputs**:
    - `None`: The function does not take any direct input arguments.
- **Control Flow**:
    - The function starts by updating and initializing git submodules using `git submodule update --init`.
    - It creates a directory for storing git repositories at `$PREFIX/git` if it doesn't already exist.
    - If the `MSAN` flag is set to 1, it calls `checkout_llvm` to download LLVM.
    - It calls `checkout_repo` for each specified repository, passing the repository name, URL, and version or commit hash to clone the repository into the `$PREFIX/git` directory.
    - If `DEVMODE` is set to 1, additional repositories are cloned using `checkout_repo`.
- **Output**: The function does not return any value; it performs actions to clone repositories into a specified directory.


---
### check\_fedora\_pkgs
The `check_fedora_pkgs` function checks for the presence of required RPM packages on a Fedora system and prepares a command to install any missing packages.
- **Inputs**: None
- **Control Flow**:
    - Define a list of required RPM packages in the `REQUIRED_RPMS` array, including packages for both general and development mode.
    - Print a message indicating the start of the RPM package check.
    - Initialize an empty array `MISSING_RPMS` to store any missing packages.
    - Iterate over each package in `REQUIRED_RPMS` and check if it is installed using `rpm -q`. If not installed, add it to `MISSING_RPMS`.
    - Check if `MISSING_RPMS` is empty; if so, print a success message and return 0.
    - If there are missing packages, determine the appropriate package installation command based on whether `SUDO` is set, and prepare the command to install the missing packages using `dnf`.
- **Output**: The function does not return a value but prints messages indicating the status of required packages and prepares a command to install missing packages if any are found.


---
### check\_debian\_pkgs
The `check_debian_pkgs` function checks for the presence of required Debian packages and prepares a command to install any missing ones.
- **Inputs**: None
- **Control Flow**:
    - Define a list `REQUIRED_DEBS` containing the names of necessary Debian packages.
    - If `DEVMODE` is set to 1, append additional development packages to `REQUIRED_DEBS`.
    - Print a message indicating the start of the package check.
    - Initialize an empty list `MISSING_DEBS` to store any missing packages.
    - Iterate over each package in `REQUIRED_DEBS` and check if it is installed using `dpkg -s`.
    - If a package is not installed, add it to `MISSING_DEBS`.
    - If `MISSING_DEBS` is empty, print a success message and return 0.
    - If there are missing packages, construct an `apt-get` command to install them, using `sudo` if necessary.
- **Output**: The function does not return a value but prints messages indicating the status of package checks and prepares a command to install missing packages if any are found.


---
### check\_alpine\_pkgs
The `check_alpine_pkgs` function checks for the presence of required APK packages on an Alpine Linux system and prepares a command to install any missing packages.
- **Inputs**: None
- **Control Flow**:
    - Define a list of required APK packages, including build-base, curl, linux-headers, libucontext-dev, and patch.
    - If DEVMODE is enabled, additional packages like autoconf, automake, bison, flex, gettext, perl, and protobuf-dev are added to the list.
    - Print a message indicating the start of the check for required APK packages.
    - Initialize an empty list to store missing packages.
    - Iterate over each package in the REQUIRED_APKS list and check if it is installed using `apk info -e`.
    - If a package is not installed, add it to the MISSING_APKS list.
    - If no packages are missing, print a success message and return 0.
    - If there are missing packages, prepare a command to install them using `apk add`, optionally prefixed with `sudo` if the user is not root.
- **Output**: The function does not return a value but prints messages indicating the status of required packages and prepares a command to install any missing packages.


---
### check\_macos\_pkgs
The `check_macos_pkgs` function checks for the presence of required Homebrew formulae on macOS and prepares a command to install any missing ones.
- **Inputs**:
    - `None`: This function does not take any input arguments.
- **Control Flow**:
    - Define a list of required Homebrew formulae: perl, autoconf, gettext, automake, flex, bison, and protobuf.
    - Print a message indicating the start of the check for required brew formulae.
    - Initialize an empty list to store any missing formulae.
    - Iterate over each formula in the required list and check if it is installed by verifying the existence of its directory in '/usr/local/Cellar/'.
    - If a formula is not found, add it to the list of missing formulae.
    - If no formulae are missing, print a message indicating all required formulae are installed and return 0.
    - If there are missing formulae, prepare a command to install them using Homebrew.
- **Output**: The function outputs a command to install missing Homebrew formulae if any are found, otherwise it returns 0 indicating all required formulae are installed.


---
### check
The `check` function verifies the presence of required system packages for building and installing dependencies based on the detected operating system and distribution.
- **Inputs**: None
- **Control Flow**:
    - Determine the distribution type using the `DISTRO` variable, which is derived from `ID_LIKE` or `ID`.
    - Iterate over each word in the `DISTRO` variable to identify the distribution type (e.g., fedora, debian, alpine, macos).
    - For each recognized distribution type, call the corresponding function to check for required packages (e.g., `check_fedora_pkgs`, `check_debian_pkgs`).
    - If any required packages are missing, construct a command to install them using the appropriate package manager (e.g., `dnf`, `apt-get`, `apk`, `brew`).
    - Prompt the user to install missing packages, or automatically install them if `FD_AUTO_INSTALL_PACKAGES` is set to 1.
    - Check if the `cargo` command is available in the PATH, and if not, attempt to source the cargo environment or prompt the user to install `rustup`.
    - If `rustup` is not installed, prompt the user to install it and update the rust toolchain if necessary.
- **Output**: The function does not return a value but exits with code 0 on success, indicating that all required packages are present.


---
### install\_libcxx
The `install_libcxx` function configures, builds, and installs the libcxx and libcxxabi libraries from the LLVM project into a specified directory.
- **Inputs**: None
- **Control Flow**:
    - Change directory to the LLVM source directory located at `$PREFIX/git/llvm`.
    - Remove any existing `build` directory and create a new one.
    - Change into the newly created `build` directory.
    - Run `cmake` to configure the build system for libcxx and libcxxabi with specific options such as install prefix, build type, and runtime options.
    - Execute the `make` command to build the libcxx and libcxxabi libraries.
    - Run `make install` to install the built libraries into the specified prefix directory.
- **Output**: The function does not return any value; it performs the installation of libcxx and libcxxabi libraries as a side effect.


---
### install\_zstd
The `install_zstd` function installs the Zstandard (zstd) library to a specified prefix directory using make.
- **Inputs**:
    - `None`: This function does not take any direct input arguments.
- **Control Flow**:
    - Change directory to the Zstandard library source directory located at `$PREFIX/git/zstd/lib`.
    - Print a message indicating the start of the Zstandard installation process.
    - Execute the `make` command with specified flags to install the Zstandard library to the `$PREFIX` directory.
    - Print a message indicating the successful installation of Zstandard.
- **Output**: The function does not return any value; it performs the installation of the Zstandard library as a side effect.


---
### install\_lz4
The `install_lz4` function installs the LZ4 compression library to a specified prefix directory.
- **Inputs**:
    - `None`: This function does not take any direct input arguments.
- **Control Flow**:
    - Change directory to the LZ4 library source directory located at `$PREFIX/git/lz4/lib`.
    - Print a message indicating the start of the LZ4 installation process.
    - Execute the `make` command with specified options to install LZ4 to the `$PREFIX` directory, ensuring no shared libraries are built and using position-independent code.
    - Print a message indicating the successful installation of LZ4.
- **Output**: The function does not return any value; it performs the installation of the LZ4 library as a side effect.


---
### install\_s2n
The `install_s2n` function installs the s2n-bignum library by building it from source and copying the necessary files to a specified prefix directory.
- **Inputs**:
    - `None`: This function does not take any direct input arguments.
- **Control Flow**:
    - Change directory to the s2n source directory located at `$PREFIX/git/s2n`.
    - Print a message indicating the start of the s2n-bignum installation process.
    - Execute the `make` command in the `x86` directory to build the s2n-bignum library.
    - Copy the built static library `libs2nbignum.a` to the `lib` directory under the specified prefix.
    - Copy all header files from the `include` directory to the `include` directory under the specified prefix.
    - Print a message indicating the successful installation of s2n-bignum.
- **Output**: The function does not return any value; it performs installation tasks and outputs status messages to the console.


---
### install\_blst
The `install_blst` function installs the BLST cryptographic library into a specified directory.
- **Inputs**:
    - `None`: This function does not take any direct input arguments.
- **Control Flow**:
    - Change directory to the BLST source directory located at `$PREFIX/git/blst`.
    - Print a message indicating the start of the BLST installation process.
    - Set the `CFLAGS` variable with default flags and append any extra flags specified by `EXTRA_CFLAGS`.
    - Run the `build.sh` script with the configured `CFLAGS` to build the BLST library.
    - Copy the static library `libblst.a` to the `lib` directory under the specified `PREFIX`.
    - Copy the header files from the `bindings` directory to the `include` directory under the specified `PREFIX`.
    - Print a message indicating the successful installation of BLST.
- **Output**: The function does not return any value; it performs installation tasks and outputs status messages to the console.


---
### install\_secp256k1
The `install_secp256k1` function configures, builds, and installs the secp256k1 library from its source code into a specified directory.
- **Inputs**:
    - `None`: This function does not take any direct input arguments; it uses environment variables and predefined paths.
- **Control Flow**:
    - Change directory to the secp256k1 source directory located at `$PREFIX/git/secp256k1`.
    - Remove any existing build directory and create a new one for a clean build environment.
    - Run the `cmake` command to configure the build system with specific options for secp256k1, such as disabling shared libraries and enabling the recovery module.
    - Use the `make` command to compile the secp256k1 library.
    - Install the compiled secp256k1 library into the specified prefix directory using `make install`.
- **Output**: The function outputs log messages indicating the progress of configuration, building, and installation steps, and it installs the secp256k1 library into the specified directory.


---
### install\_openssl
The `install_openssl` function configures, builds, and installs the OpenSSL library to a specified prefix directory.
- **Inputs**:
    - `None`: This function does not take any direct input arguments; it relies on environment variables and the current directory context.
- **Control Flow**:
    - Change directory to the OpenSSL source directory located at `$PREFIX/git/openssl`.
    - Run the OpenSSL configuration script with specific flags to customize the build, such as disabling certain features and enabling TLS 1.3.
    - Build the OpenSSL libraries using the `make` command with the `build_libs` target.
    - Install the built OpenSSL libraries to the specified prefix directory using the `make install_dev` command.
- **Output**: The function outputs log messages indicating the progress of configuring, building, and installing OpenSSL, and it installs the OpenSSL library files to the specified prefix directory.


---
### install\_rocksdb
The `install_rocksdb` function compiles and installs the RocksDB library from source into a specified directory.
- **Inputs**:
    - `None`: This function does not take any direct input arguments; it relies on environment variables and the current directory structure.
- **Control Flow**:
    - Change directory to the RocksDB source directory located at `$PREFIX/git/rocksdb`.
    - Determine the number of jobs for parallel make execution based on the number of available processors, defaulting to at least one job.
    - Clean any previous build artifacts using `make clean`.
    - Set environment variables to disable certain RocksDB features (NUMA, ZLIB, BZIP, GFLAGS) and configure compiler flags for building.
    - Compile the RocksDB static library using `make` with the specified number of jobs and options for a lite build.
    - Install the compiled static library into the specified prefix directory using `make install-static`.
- **Output**: The function does not return any value; it performs installation tasks and outputs status messages to the console.


---
### install\_snappy
The `install_snappy` function configures, builds, and installs the Snappy compression library into a specified directory.
- **Inputs**:
    - `None`: This function does not take any direct input arguments; it relies on environment variables and the current directory structure.
- **Control Flow**:
    - Change directory to the Snappy source directory located at `$PREFIX/git/snappy`.
    - Create a `build` directory within the Snappy source directory and change into it.
    - Run `cmake` to configure the Snappy build with specific options such as disabling shared libraries and tests, and setting the installation directory to an empty string (indicating the use of `DESTDIR` for installation).
    - Build Snappy using `make` with parallel jobs.
    - Install Snappy to the specified `PREFIX` directory using `make install` with `DESTDIR` set to `$PREFIX`.
- **Output**: The function outputs log messages indicating the progress of configuring, building, and installing Snappy, and it installs the Snappy library into the specified `PREFIX` directory.


---
### install
The `install` function builds and installs various project dependencies into a specified prefix directory.
- **Inputs**:
    - `None`: The function does not take any direct input arguments, but it relies on several environment variables and the current state of the system.
- **Control Flow**:
    - Set the C and C++ compilers using the environment variables `CC` and `CXX`, defaulting to `gcc` and `g++` if not set.
    - Create necessary directories for include and lib files under the specified prefix directory.
    - If the `MSAN` flag is set, install the `libcxx` library with memory sanitizer options.
    - Install the `zstd` and `lz4` libraries unconditionally.
    - If the system architecture is `x86_64`, install the `s2n` library.
    - Install the `openssl` and `secp256k1` libraries unconditionally.
    - If the `DEVMODE` flag is set, install additional libraries: `blst`, `snappy`, and `rocksdb`.
    - Merge `lib64` directory into `lib` if it exists, then remove `lib64`.
    - Remove `cmake` and `pkgconfig` files from the `lib` directory to prevent accidental dependencies.
    - Print a completion message indicating the installation process is done.
- **Output**: The function does not return any value; it performs installation tasks and outputs status messages to the console.



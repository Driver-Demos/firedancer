# Purpose
The provided file is a GitHub Actions workflow configuration file, written in YAML, which automates the build process for a software project across different compilers, architectures, and targets. This file defines a workflow named "Builds" that can be triggered either by a workflow call or manually via workflow dispatch. It includes inputs for specifying versions of GCC and Clang compilers, target machines, exception groups, and build options such as dry-run, verbosity, and error handling. The file contains three main jobs: `build_gcc`, `build_clang`, and `build_arm`, each responsible for executing builds with specific configurations and conditions. The workflow is designed to run concurrently, with a mechanism to cancel in-progress builds if a new one is triggered. This configuration is crucial for ensuring consistent and automated builds in a continuous integration/continuous deployment (CI/CD) pipeline, enhancing the reliability and efficiency of the software development process.
# Content Summary
This configuration file is a GitHub Actions workflow designed to automate the build process for a software project across different compilers, architectures, and targets. The workflow is named "Builds" and is triggered by two events: `workflow_call` and `workflow_dispatch`. It supports a variety of input parameters that allow developers to customize the build process.

Key inputs include:
- `gcc` and `clang`: Specify the versions of GCC and Clang compilers to use, with options for specific versions, "none", or "all".
- `machine`: Defines the target machines for the build, with options for specific machines or "all".
- `gcc_exceptions` and `clang_exceptions`: Allow specifying exception groups for GCC and Clang, respectively, using a semi-colon delimited format.
- `build_arm`: A boolean flag to enable ARM architecture builds.
- `dry_run`, `verbose`, and `exit_on_err`: Boolean flags to control the build process, such as performing a dry run, enabling verbose output, and exiting on the first error.

The workflow includes three main jobs: `build_gcc`, `build_clang`, and `build_arm`. Each job runs on a specified runner and includes steps to check out the code, set up the environment, and execute the build process with the specified arguments.

- **`build_gcc`**: Executes builds using GCC, running on a `ci4` runner. It constructs command-line arguments based on the input parameters and runs a build script with these arguments, excluding Rust and Clang components.
  
- **`build_clang`**: Similar to `build_gcc`, but for Clang builds, running on a `ci16` runner. It also constructs command-line arguments and runs a build script, excluding Rust and GCC components.

- **`build_arm`**: Specifically targets ARM architecture builds, running on an `ARM64` runner. It uses a matrix strategy to specify GCC version 12 and includes steps to set up the environment and execute the build using `make`.

The workflow ensures concurrency control by grouping builds based on the workflow and pull request number or reference, with the option to cancel in-progress builds if a new one is triggered. This setup provides a flexible and comprehensive build automation solution for projects requiring multi-compiler and multi-architecture support.

# Purpose
The provided file is a GitHub Actions workflow configuration file written in YAML. It is designed to automate the process of setting up and testing a local network environment for a project named "Firedancer." The workflow is triggered either by a direct call or manually via the GitHub interface. It defines a job named "firedancer-localnet" that runs on a self-hosted runner with specific environment variables and dependencies. The job includes multiple steps, such as checking out the code, setting up dependencies, building the project, and managing a local cluster of nodes. The workflow ensures that all validators in the cluster have been leaders and performs cleanup tasks to remove any artifacts or processes that were started during the execution. This file is crucial for continuous integration and testing within the codebase, ensuring that the local network setup and validation processes are automated and repeatable.
# Content Summary
The provided file is a GitHub Actions workflow configuration for a project named "Firedancer." This workflow is designed to automate the setup, execution, and cleanup of a local network test environment for the Firedancer project. The workflow is triggered either by a direct call (`workflow_call`) or manually (`workflow_dispatch`).

Key components of the workflow include:

1. **Inputs and Environment Setup**: The workflow accepts an input parameter `machine`, defaulting to `linux_gcc_zen2`, which is used to configure the environment variable `MACHINE`. The environment is further configured with `CC` set to `gcc` and `AGAVE_VERSION` set to `v2.0.3`.

2. **Job Configuration**: The main job, `firedancer-localnet`, is configured to run on a self-hosted runner with 512GB of memory and has a timeout of 30 minutes. The job consists of several steps:

   - **Checkout and Dependencies**: The workflow checks out the repository and its submodules, and installs additional dependencies with the `+dev` flag.
   
   - **System Configuration**: It configures the system to use a specified number of huge pages, which are necessary for the operation of the Firedancer environment.

   - **Build Process**: The project is built using the `make` command with the target `firedancer-dev`.

   - **Agave Repository Setup**: The workflow clones and checks out a specific version of the Agave repository, builds it, and sets the `AGAVE_PATH` environment variable.

   - **Cluster and Node Management**: The workflow includes steps to stop any existing processes related to the Firedancer and Agave validators, remove any existing ledger and cluster artifacts, and start a new Agave cluster and Firedancer node. It uses `prlimit` to set resource limits for file descriptors and memory locking.

   - **Validation Check**: A script checks if all validators have been leaders by querying the local RPC server for leader schedules and epoch information. It ensures that each validator has taken the leader role at least once.

   - **Cleanup**: The workflow ensures that all processes are terminated, and any artifacts or logs generated during the test are removed, regardless of the test outcome.

This configuration is crucial for developers working with the Firedancer project as it automates the setup and teardown of a complex testing environment, ensuring consistency and reducing manual intervention.

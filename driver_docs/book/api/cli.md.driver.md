# Purpose
The provided content is a documentation excerpt for the `fdctl` command-line interface, which is part of the Firedancer software suite. This file serves as a comprehensive guide for users to understand and utilize various subcommands of `fdctl`, which is used to manage and configure a Firedancer validator. The document outlines several commands such as `run`, `monitor`, `configure`, `version`, `set-identity`, `keys`, and `mem`, each with specific functionalities related to running, monitoring, configuring, and managing the validator's identity and resources. The file is structured to provide detailed descriptions of each command, including their arguments, capabilities, and operational details, ensuring users can effectively execute tasks such as running the validator, monitoring its performance, configuring the operating system environment, and managing cryptographic keys. This documentation is crucial for developers and system administrators who need to deploy and maintain Firedancer validators, as it provides essential information on command usage, system requirements, and configuration options.
# Content Summary
The provided document is a comprehensive guide to the `fdctl` Command Line Interface (CLI) for the Firedancer software, detailing its various subcommands and their functionalities. The `fdctl` CLI is designed to manage and configure the Firedancer validator, a component likely involved in blockchain or distributed ledger technology.

### Key Subcommands and Their Functionalities:

1. **`run`**: This command initiates the validator process. It requires a configuration TOML file specified by the `--config <path>` argument. The command runs continuously until the validator stops, and any errors encountered will affect the process's exit code. It logs output to `stderr` and requires certain system capabilities, such as `CAP_NET_RAW` and `CAP_SYS_ADMIN`, to perform network and system-level operations.

2. **`monitor`**: This command is used to monitor the performance of a locally running validator. It provides real-time updates on throughput and other performance metrics, refreshing the terminal display multiple times per second. Like `run`, it requires a configuration file and certain capabilities for sandboxing and resource management.

3. **`configure`**: This command prepares the operating system to run Firedancer by setting up huge pages, kernel parameters, and network device configurations. It includes subcommands like `init`, `check`, and `fini` to initialize, verify, and finalize the system configuration, respectively. Each stage of configuration requires root privileges or specific capabilities to modify system settings.

4. **`version`**: This command outputs the current version of the validator software, providing a simple way to verify the installed version.

5. **`set-identity`**: This command changes the identity key of a running validator, which is crucial for maintaining the validator's unique identity in the network. It requires a keypair file and the same configuration file used to start the validator. The command includes options like `--require-tower` and `--force` to handle specific scenarios related to identity changes.

6. **`keys`**: This section includes subcommands for managing cryptographic keys. `keys pubkey` prints the public key from a specified key file, while `keys new` generates a new keypair and writes it to a specified path. These operations are essential for identity management and security within the Firedancer ecosystem.

7. **`mem`**: This command provides detailed information about the memory requirements and configuration of the validator. It outputs data on total memory usage, required page sizes, and the layout of memory tiles, which is critical for ensuring the validator has sufficient resources to operate efficiently.

Overall, the `fdctl` CLI is a powerful tool for managing the Firedancer validator, offering commands for running, monitoring, configuring, and managing the identity and resources of the validator. Each command is designed with specific arguments and capabilities to ensure secure and efficient operation within a system environment.

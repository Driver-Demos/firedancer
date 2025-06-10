Firedancer CLI
==============

Overview of Firedancer and fdctl
================================

Firedancer is a high-performance validator client for the Solana blockchain. It is engineered for speed, security, and operational independence with dedicated modules for core blockchain operations, cryptographic processes, and network management. By leveraging advanced security techniques such as restrictive sandboxing and CPU core management, Firedancer ensures stable and efficient validator performance. Its flexible design also supports simulation, benchmarking, and diagnostic tools to help operators fine-tune deployment configurations while maintaining strong version control.

Complementing the validator client is the fdctl command-line tool. fdctl provides a command-driven interface for managing every aspect of a validator’s operations—from launching processes and monitoring performance to adjusting configuration settings and handling keys. Operators benefit from uniform flags, dynamic command registration, and built-in configuration management, which together simplify tasks such as process control, resource allocation, performance diagnostics, and system updates.

Common operator tasks include:

* Starting and managing validator processes
    
* Updating or overriding default configurations
    
* Monitoring performance metrics and system resources
    
* Running diagnostic and troubleshooting commands
    

Installation and Setup
======================

This section details the steps required to obtain, build, and configure the Firedancer CLI (fdctl) from source. The guide covers verifying system prerequisites, cloning the repository, installing dependencies, building the project, and configuring the deployment.

Follow these steps to ensure a proper setup:

1.  Verify your system meets the prerequisites:
    
    * A Unix-like operating system (Linux or macOS)
        
    * A supported C/C++ compiler (GCC 8.5+ or Clang)
        
    * Essential build tools (make, tar, standard Unix utilities)
        
    * Git for cloning the repository
        
    * For Linux builds, a recent kernel (e.g., v4.18 or later)
        
    * Additional dependencies such as Rust (via rustup), Python 3.8/3.9, OpenSSL, RocksDB, Snappy, Zstandard, etc.
        
    * On macOS M1 systems, install LLVM tools (e.g., using Homebrew: `brew install llvm`)
        
    * For module-based environments, an activation script (provided in the repository) loads necessary modules
        
2.  Clone the Firedancer repository with submodules:
    
    * Run from your terminal:
        
            git clone --recurse-submodules https://github.com/firedancer-io/firedancer.git
            cd firedancer
        
3.  Install external dependencies:
    
    * Execute the dependency installation script:
        
            ./deps.sh
        
    * For development mode:
        
            ./deps.sh +dev
        
    * For memory sanitizer builds:
        
            ./deps.sh +msan install
        
    * Optionally, bundle static libraries and include files:
        
            ./firedancer/contrib/deps-bundle.sh
        
4.  Activate your module-based environment (if applicable):
    
    * From the contrib folder, run:
        
            cd firedancer/contrib
            source activate
        
5.  Build fdctl from source:
    
    * From the repository root (after installing dependencies), run:
        
            make
        
    * For faster builds, run:
        
            make -j
        
6.  Configure custom machine settings (optional):
    
    * Set the MACHINE environment variable if targeting a non-native configuration:
        
            MACHINE=my_machine make -j
        
    * Use custom machine configuration files located in `config/machine/`
        
7.  Enable additional build features (optional):
    
    * For example, to enable debugging:
        
            make -j EXTRAS="debug"
        
8.  Use Rust-specific build automation (if applicable):
    
    * Ensure your Rust toolchain (via rustup) is up-to-date and then run:
        
            ./build.sh -t fdctl
        
        (Use `./build.sh --help` for additional options)
        
9.  Configure fdctl deployment:
    
    * fdctl loads configuration from embedded and external TOML files. Activate a configuration file using:
        
        * An environment variable:
            
                export FIREDANCER_CONFIG_TOML=/path/to/your/config.toml
            
        * Or a command-line option:
            
                fdctl --config /path/to/your/config.toml <command>
            
10. Apply runtime host-level configurations (if required):
    
    * For example, memory and filesystem settings:
        
            fdctl configure init hugetlbfs
        
    * For kernel and network optimizations:
        
            sudo fdctl configure init sysctl
            sudo fdctl configure init ethtool-channels
            sudo fdctl configure init ethtool-gro
            sudo fdctl configure init ethtool-loopback
        
    * Verify configurations using:
        
            fdctl configure check all
        
11. (Optional) Refine the build process with advanced options:
    
    * Adjust build configurations by reviewing files in `firedancer/config/extra`.
        
12. Troubleshoot any issues:
    
    * Confirm that all prerequisites and environment variables are correctly set.
        
    * Re-run dependency setup if necessary.
        
    * Check Makefile outputs for compiler flags and messages.
        
    * Use fdctl’s configuration “check” commands for diagnostics.
        

Following these steps will equip you with a properly built and configured fdctl for the Firedancer validator client.

Building fdctl from Source
--------------------------

Below is a consolidated series of shell commands—with numbered annotations—to help you build the fdctl command-line tool from source. Choose the build route that best fits your environment:

1.  Clone the Firedancer repository and initialize submodules.
    
        git clone --recurse-submodules https://github.com/<organization>/firedancer.git  # Replace <organization> accordingly.
        cd firedancer
    
2.  Option A – Build from the fd_tango Directory:
    
        cd src/tango
        make
    
    * (Optional) Install the binary:
        
            sudo make install  # OR, copy fd_tango_ctl to your PATH:
            # sudo cp fd_tango_ctl /usr/local/bin/fdctl
        
3.  Option B – Build from the fdctl Application Directory:
    
        cd ../app/fdctl
        make
    
    * (Optional) Install the binary:
        
            sudo make install  # OR, manually copy the generated binary
        
4.  Option C – Build Using the Contributed Build Script:
    
        cd ../../
        ./contrib/build.sh --targets fdctl
    
    * For a Clang-only verbose build:
        
            # ./contrib/build.sh --no-gcc --targets fdctl --verbose
        
5.  Option D – Machine-Specific Configurations:
    
        make -f config/machine/linux_clang_noarch64.mk
    
    * For Linux GCC with 128-bit support:
        
            make -f config/machine/linux_gcc_noarch128.mk
        
    * For a Minimal Build with Clang:
        
            make -f config/machine/linux_clang_minimal.mk
        
6.  Update Build Information (if needed):
    
        git fetch --tags
        git checkout __FD_LATEST_VERSION__  # Replace with your target version tag.
        git submodule update --init --recursive
        make -j fdctl
    
7.  Final Installation (if not done via "make install"):
    
        sudo cp path/to/fdctl /usr/local/bin/fdctl
    

* Verification: Check version
    
        fdctl --version
    

Installing Dependencies with deps.sh
------------------------------------

The deps.sh script automates the setup of both system-level and third-party dependencies. It ensures that your environment is properly configured for building Firedancer. Key dependency tasks performed by deps.sh include:

* Fetching & Building External Dependencies
    
    * Downloads and builds third-party libraries and repositories such as zstd, lz4, OpenSSL, secp256k1, and, in development mode, crates like blst, rocksdb, and snappy.
        
* Checking & Installing System-Level Packages
    
    * Verifies that required packages (e.g., curl, build-essential, cmake) are installed and runs package manager commands when needed.
        
* Environment Cleanup & Configuration
    
    * Provides a “nuke” command to clean previous installations, sets up a dependency prefix (typically ./opt), and configures specialized builds (e.g., with MemorySanitizer via +msan).
        
* Bundling Dependencies for Distribution
    
    * Packages libraries and headers using GNU tar and Zstandard to form a redistributable bundle.
        
* Integration with Automation & CI/CD
    
    * Supports continuous integration workflows by enabling dependency caching, updates, and conditional installs.
        
* Specialized Build Modes
    
    * Use +dev for extended dependency cloning and +msan for MemorySanitizer builds.
        

Below are example commands to invoke deps.sh:

    FD_AUTO_INSTALL_PACKAGES=1 ./deps.sh +dev check fetch
    ./deps.sh nuke
    CC=<compiler> ./deps.sh +dev fetch install
    ./deps.sh +msan

Configuration File Basics
-------------------------

The Firedancer configuration uses a TOML file format. Below is a minimal example demonstrating dynamic placeholders and key sections. Use inline comments to adjust paths and ports as needed.

    # Firedancer Minimal Configuration File
    
    # Instance identification
    name = "fd1"                  # Unique instance name
    user = "firedancer"           # Non-root OS user
    
    [scratch]
    # Directory for temporary files; placeholders are dynamically replaced.
    scratch_directory = "/home/{user}/.firedancer/{name}"
    
    [paths]
    # Base directories for ledger, identity, and logs.
    base = "/home/{user}/.firedancer/{name}"
    identity_key = "/home/{user}/.firedancer/{name}/identity.json"  
    vote_account = "/home/{user}/.firedancer/{name}/vote.json"        
    
    [ledger]
    directory = "/home/{user}/.firedancer/{name}/ledger"
    
    [log]
    # Log file storage path.
    path = "/home/{user}/.firedancer/{name}/logs/fd.log"
    
    [gossip]
    port = 8001                   # P2P gossip port
    entrypoints = ["127.0.0.1:8001"]
    
    [rpc]
    port = 8899                   # JSON RPC port
    full_api = true               # Enables full RPC functionality
    private = false               # Restrict RPC access if set to true
    
    # Dynamic network port range for additional listeners.
    dynamic_port_range = "8900-9000"
    
    [tiles]
    [tile.metric]
    prometheus_listen_port = 7999   # Metrics port for monitoring

Dynamic placeholders such as {user} and {name} allow quick adjustments for different environments. This configuration file can be compiled into the binary or supplied at runtime to override defaults.

CLI Structure and Invocation
============================

The global syntax is as follows:

    fdctl [global options] <command> [command-specific options]

Global flags such as --config, --help, or --version are processed first, ensuring consistent behavior across subcommands. Below is a table summarizing the primary global flags:

|     |     |     |
| --- | --- | --- |
| Flag | Shorthand | Description |
| \--config | N/A | Specifies the configuration TOML file for launching or monitoring the validator. |
| \--help | \-h | Displays detailed usage instructions and subcommand list. |
| \--version | \-v | Outputs the current software version and build commit reference. |
| \--log-path | N/A | Sets the file path for log output. |
| \--log-level-stderr | N/A | Configures verbosity of logging to standard error. |

Core Subcommands and Their Functions
====================================

The fdctl CLI is organized around a dynamic “action” framework with subcommands that enforce permissions, parse arguments, and execute operations. The following sections detail key subcommands:

Run Subcommand
--------------

The run subcommand starts the Firedancer validator client by initializing the process tree, setting environment variables, loading configurations, and spawning child processes for networking, block production, and verification.

Implementation details:

* Multiple source files (e.g., run.c, run1.c) support this command.
    
* Registers several actions (e.g., fd_action_run, fd_action_run_agave).
    
* Applies techniques like process cloning, CPU affinity, and namespace isolation.
    

Required permissions:

* Elevated privileges (root or sudo) are required for namespace creation and system configuration changes.
    

Typical output:

* Startup logs, configuration confirmation, error messages if misconfigured, and runtime diagnostics.
    

Flag Summary:

|     |     |     |
| --- | --- | --- |
| Flag | Description | Example |
| \--config | Specifies the configuration file to load. | \--config config.yaml |
| \--agave | Activates a specialized Agave mode for PID namespace isolation. | \--agave |
| \--dev | Runs the validator in development mode with added logging. | \--dev |

Configure Subcommand
--------------------

The configure subcommand optimizes the host system for blockchain operations. It adjusts kernel parameters, mounts hugetlbfs filesystems, configures sysctl settings, disables hyperthreads on critical cores, and tunes network settings via ethtool.

Stages include:

* hugetlbfs – Reserve large memory pages.
    
* sysctl – Update kernel parameters such as max_map_count.
    
* Hyperthread and network tuning – Disabling or adjusting features via ethtool.
    
* Additional helper functions validate the configuration setup.
    

Required permissions:

* Root privileges are needed as the command alters system-level settings.
    

Flag Summary:

|     |     |     |
| --- | --- | --- |
| Flag | Description | Example |
| init | Initializes system configuration. | configure init |
| check | Validates applied configuration with diagnostics. | configure check |

Monitor Subcommand
------------------

The monitor command displays real-time performance metrics such as CPU utilization, network throughput, and diagnostic information through periodic terminal updates.

Implementation:

* Uses helper functions to format and color metrics.
    
* Sets signal handlers and file descriptors for live updates.
    
* May use additional flags (e.g., --bench, --sankey).
    

Required permissions:

* Generally requires no elevated privileges, though some detailed metrics might need extra rights.
    

Flag Summary:

|     |     |     |
| --- | --- | --- |
| Flag | Description | Example |
| \--bench | Show additional benchmark metrics. | fdctl monitor --bench |
| \--sankey | Visualizes network and processing flows. | fdctl monitor --sankey |

Additional Management Commands
------------------------------

Additional subcommands manage keys, node identity, workspace allocation, and more:

### Keys

Manage cryptographic keypairs for validator operations.

* Commands:
    
    * new: Generate a new keypair.
        
    * pubkey: Output a Base58-encoded public key from an existing file.
        

Flag Summary:

|     |     |     |
| --- | --- | --- |
| Flag | Description | Example |
| new | Generates a new cryptographic keypair. | fdctl keys new |
| pubkey | Prints the public key from a key file. | fdctl keys pubkey mykey.json |

### Ready and Set Identity

* Ready: Checks that all validator tiles are in a ready state.
    
* Set Identity: Updates the node’s identity with a new key.
    

Flag Summary:

|     |     |     |
| --- | --- | --- |
| Flag | Description | Example |
| ready | Checks and reports if all tiles/processing nodes are ready. | fdctl ready |
| set-identity | Updates the node's identity using the specified key file. | fdctl set-identity mykey.json |

### Help and Version

Display usage and version information.

Flag Summary:

|     |     |     |
| --- | --- | --- |
| Flag | Description | Example |
| \--help | Displays help and usage information. | fdctl --help |
| \--version | Outputs current software version. | fdctl --version |

### Supplementary Commands

Additional commands include memory diagnostics (mem), network configuration listing (netconf), and development utilities (fddev):

|     |     |     |     |
| --- | --- | --- | --- |
| Command | Flags/Options | Description | Example |
| mem | N/A | Displays memory usage and tile configuration. | fdctl mem |
| netconf | N/A | Lists network interfaces and routes. | fdctl netconf |
| fddev | dev1, gossip | Launches development tile or configures gossip protocol. | fdctl fddev dev1 / gossip |

Workspace and Resource Management
---------------------------------

Commands related to workspaces encompass creating, deleting, allocating, freeing, querying, and checkpoint management. For example:

* wksp new – Create a new workspace.
    
* wksp alloc – Allocate a memory block.
    
* wksp free – Free memory.
    
* tag-query – Query allocation tags.
    

A quick table for workspace operations:

|     |     |     |     |
| --- | --- | --- | --- |
| Command | Option | Description | Example |
| wksp | new | Create a new workspace with required parameters. | fdctl wksp new --name mywksp --pages 100 |
| wksp | delete | Delete an existing workspace by name. | fdctl wksp delete mywksp |
| wksp | alloc | Allocate a memory block. | fdctl wksp alloc --size 1024 |
| wksp | free | Free a previously allocated memory block. | fdctl wksp free --addr 0xABCDEF |

Command Usage Examples
======================

Below are practical scenarios illustrating common operations. Each description is followed by the exact CLI command(s).

* * *

Scenario: Run continuous integration tests (build, run tests, and export coverage data).

    sh ci_tests.sh

Scenario: Execute integration tests with verbose output for a specific test.

    sh run_integration_tests.sh -v --test <test-name>

(Replace `<test-name>` with the desired identifier.)

Scenario: Run unit tests with NUMA-aware scheduling.

    bash run_unit_tests.sh

Scenario: Automate fetching and execution of test vectors concurrently.

    sh run_test_vectors.sh --log-path /path/to/output.log

Scenario: Set up a local Firedancer test cluster and stakes.

    sh setup_fd_cluster.sh
    sh setup_fd_cluster_stakes.sh

Scenario: Monitor transaction processing statistics (TPS).

    python firedancer/contrib/test/tps.py -r "http://localhost:8899" -m "http://localhost:8080/metrics" -t 5

Scenario: Retrieve detailed transaction metrics (elapsed time, TPS, compute units, slot info).

    python firedancer/contrib/test/tps.py -r "http://localhost:8899" -m "http://localhost:8080/metrics" -t 3 -e -x -p -u -s

* * *

Scenario: Start a single validator tile in development mode with configuration skipped.

    fdctl dev1 agave
    fdctl dev1 tileA --no-configure

Scenario: Run a TPS benchmark test on the validator for 30 seconds using one tile.

    fdctl benchmark --tiles 1 --duration 30

Scenario: Spawn additional validator threads (e.g., 4 extra threads).

    fdctl start-threads --count 4

Scenario: Run integration tests via the build system.

    make integration-test

* * *

Scenario: Display CLI help information.

    fdctl help

Scenario: Generate a new keypair for the validator.

    fdctl keys new

Scenario: Print the public key from an existing key file.

    fdctl keys print <key_file_path>

(Replace `<key_file_path>` with the actual file path.)

Scenario: Query current memory usage statistics.

    fdctl mem

Scenario: Display network configuration details.

    fdctl netconf

Scenario: Check readiness of validator tiles (with or without a custom configuration file).

    fdctl ready
    fdctl ready --config /path/to/config.yaml

Scenario: Change validator identity with a new key (optionally forcing the update).

    fdctl set_identity --key <new_identity_key_file>
    fdctl set_identity --force --key <new_identity_key_file>

Scenario: Display the current fdctl version.

    fdctl version

* * *

Scenario: Initialize all host configuration stages (requires root).

    sudo fdctl configure init all

Scenario: Configure hugetlbfs on the host system.

    sudo fdctl configure init hugetlbfs

Scenario: Adjust kernel parameters via sysctl.

    sudo fdctl configure init sysctl

Scenario: Disable hyperthreads for performance.

    sudo fdctl configure init hyperthreads

Scenario: Tune network device channels with ethtool.

    sudo fdctl configure init ethtool-channels

Scenario: Disable network GRO.

    sudo fdctl configure init ethtool-gro

Scenario: Disable loopback offload features.

    sudo fdctl configure init ethtool-loopback

Scenario: Verify all configuration stages.

    fdctl configure check all

Scenario: Finalize the hugetlbfs configuration stage.

    sudo fdctl configure fini hugetlbfs

* * *

Additional examples (covering transaction sending, program deployment, shared memory management, etc.) can be found in the detailed sample commands above.

Best Practices
==============

* Run with the Minimum Privileges
    
    * Operate under the principle of least privilege using dedicated non-root user accounts. Only use elevated privileges for strictly controlled tasks such as initial configuration.
        
* Isolate and Drop Elevated Privileges Quickly
    
    * Separate tasks that require root (e.g., binding file descriptors or configuring shared memory) from the main runtime. Immediately drop privileges once the task completes.
        
* Use Privileged Operations Selectively and Audit Them
    
    * Leverage sudo only for the minimal, marked tasks. In automated environments, ensure these operations are audited and used only once during setup.
        
* Enforce Strict File and Resource Access Controls
    
    * Set up identity keys, ledger directories, and configuration files with stringent permissions. Use dedicated functions to enforce correct ownership and prevent inadvertent access.
        
* Adhere Rigorously to Documented Security Protocols
    
    * Regularly consult security documentation (e.g., SECURITY.md) and follow recommendations for secure logging and data handling.
        
* Implement Robust Syscall Filtering and Sandboxing
    
    * Use BPF-based seccomp filters to whitelist system calls and isolate sensitive operations using containerization, network namespaces, or Landlock restrictions.
        
* Maintain Diligent System Upkeep and Regular Updates
    
    * Keep both the operating system (Linux kernel v4.18 or later) and the Firedancer codebase current with the latest patches. Reapply system configurations upon each reboot.
        
* Continuously Monitor, Audit, and Clean Up
    
    * Utilize logging and automated monitoring tools to capture system anomalies. Schedule regular security audits and cleanup stale ledger data, temporary files, and orphaned processes.
        

Troubleshooting and Support
===========================

Below is a FAQ-style guide to diagnose and resolve common issues with Firedancer:

* Q: How do I interpret error messages from Firedancer?
    
    * Use helper functions (e.g., fd_funk_strerror, fd_toml_strerror, fd_vm_strerror) to convert error codes.
        
    * Identify the source (CLI configuration, dependency setup, runtime transactions, snapshot issues, etc.).
        
    * For advanced subsystems (e.g., Groove), check specialized error functions (e.g., fd_groove_strerror).
        
* Q: Where can I locate logs and diagnostic information?
    
    * Many components output errors to STDOUT/STDERR; redirect these to a file when needed.
        
    * Set a log file destination using the --log-path option or FD_LOG_PATH environment variable.
        
    * For high-frequency logs, check temporary files under /tmp (e.g., fd_ledger_log\[PID\]).
        
    * Use diagnostic tools (like fd_backtrace_print) and hexdump utilities for detailed analysis.
        
* Q: What troubleshooting steps should I follow?
    
    * Record the complete error message and inspect command-line arguments, workspace settings, and configuration file formats.
        
    * Review log files and re-run unit or integration tests to reproduce the issue.
        
    * Verify that all required system resources, permissions, and environment variables are correctly set.
        
    * Narrow down issues to specific modules by testing CLI commands, runtime operations, or shared memory management independently.
        
* Q: How do I handle module-specific errors?
    
    * For CLI and configuration errors, use the internal help (fdctl help) to verify command syntax.
        
    * For runtime and snapshot issues, consult source modules (e.g., fd_exec_txn_ctx.c or fd_snapshot_main.c) and error code definitions.
        
    * For network-related issues, check protocol tests and conversion functions within fd_openssl.c.
        
* Q: Where can I find additional help and documentation?
    
    * Review the documentation in the doc and book folders of the repository (README.md, SECURITY.md, etc.).
        
    * Verify build configuration files (e.g., Local.mk, fd_shredcap.toml) for required feature flags.
        
    * Engage with the community via the GitHub issue tracker or through channels like the Solana Tech Discord (#firedancer-operators).
        
    * Enable verbose or debug modes (using --verbose or --debug flags) for more in-depth diagnostic information.
        

Additional Resources:

* [Firedancer Documentation](https://github.com/Firedancer-io/firedancer/tree/main/doc)
    
* [Firedancer GitHub Repository](https://github.com/Firedancer-io/firedancer)
    
* [Firedancer Community Support](https://discord.gg/solana)
    
* [Firedancer Build and Configuration Files](https://github.com/Firedancer-io/firedancer/blob/main/README.md)
    

Reference
=========

Below is a summary of key fdctl subcommands, flags, and their descriptions. Use this table as a quick-reference guide.

|     |     |     |     |
| --- | --- | --- | --- |
| Command / Utility | Flags / Options | Description | Module / Location |
| **fdctl – Validator Operations** |     |     |     |
| run‑agave | • --log  <br>• --bind-address  <br>• --dynamic-port-range  <br>• --firedancer-tpu-port  <br>• --firedancer-tvu-port  <br>• --identity  <br>• --vote-account  <br>• --no-snapshot-fetch  <br>• --expected-genesis-hash  <br>• --ledger  <br>• --limit-ledger-size  <br>• --accounts  <br>• --entrypoint  <br>• --gossip-host  <br>• --gossip-port  <br>• --rpc-port  <br>• --full-rpc-api  <br>• --private-rpc  <br>• --full-snapshot-interval-slots  <br>• --snapshot-interval-slots  <br>• --unified-scheduler-handler-threads  <br>• --require-tower | Launches the Agave portion of the validator with dynamic networking, ledger, consensus, snapshot, and scheduler settings. | firedancer/src/app/fdctl/commands/run_agave.c (and associated header) |
| monitor | –   | Displays real‑time performance metrics and system status. | fdctl module |
| version | –   | Outputs software version details. | fdctl and shared modules |
| set‑identity | –   | Safely updates the node’s identity cryptographic key. | Shared (fdctl/shared) |
| keys | –   | Creates or retrieves cryptographic keypairs for node operations. | Shared (fdctl/shared) |
| mem | –   | Displays workspace memory allocations and tile topology information. | Shared (fdctl/shared/commands/mem.c) |
| **fddev – Development Validator** |     |     |     |
| dev1 | –   | Sets up a development validator by running a single tile instance. | firedancer/src/app/fddev/dev1.c |
| **Shared Development & Testing Commands** |     |     |     |
| flame | \[all, tile, tile:idx, agave\] | Captures performance flamegraphs using /usr/bin/perf, targeting all tiles, a specific tile, or the Agave process. (Requires root privileges.) | firedancer/src/app/shared_dev/commands/flame.c |
| txn | • --payload-base64-encoded  <br>• --count (1–128)  <br>• --dst-ip  <br>• --dst-port | Sends transactions over QUIC with an optional base64‑encoded payload. | firedancer/src/app/shared_dev/commands/txn.c |
| dump | • --out-file (default: "dump.pcap")  <br>• --link | Dumps network packet data as a PCAP file for offline analysis. | firedancer/src/app/shared_dev/commands/dump.c |
| load | • --tpu-ip  <br>• --rpc-ip  <br>• --tpu-port  <br>• --rpc-port  <br>• --affinity  <br>• --num-benchg  <br>• --num-benchs  <br>• --num-accounts  <br>• --connections  <br>• --transaction-mode  <br>• --contending-fraction  <br>• --cu-price-spread  <br>• --no-quic | Simulates network conditions and transaction workloads for load testing and benchmarking. | firedancer/src/app/shared_dev/commands/load.c |
| **shredcap (Blockstore & Ingestion)** |     |     |     |
| ingest (shredcap) | • --wksp  <br>• --pages  <br>• --reset  <br>• --maxfilesz  <br>• --slothistory  <br>• --doverify | Reads blockchain data from a RocksDB store into a capture format; optionally verifies (--doverify). | firedancer/src/app/shredcap/main.c |
| verify / populate (shredcap) | –   | Performs integrity checks (verify) or populates blockstores from captured data (populate). | firedancer/src/app/shredcap/main.c |
| **tango – Shared Memory & Cache Controls** |     |     |     |
| fd_tango_ctl (group) | Subcommands: tag, mcache, dcache, fseq, cnc, tcache (with parameters like workspace names, depths, sizes, etc.) | Manages shared memory caches and control variables, including tag, metadata cache, data cache, flow counters, control nodes, and transaction caches. | firedancer/src/tango (see fd_tango_ctl_help for additional details) |
| **Snapshot and Data Dump Tools** |     |     |     |
| fd_blockstore_tool | • --rocksdb-path {path}  <br>• --out {out.csv}  <br>• Start/end slot parameters | Processes block data from RocksDB and exports aggregated CSV reports. | firedancer/src/flamenco/runtime/fd_blockstore_tool.c |
| fd_vm_tool | • --cmd  <br>• --program-file (mandatory)  <br>• --input-file (if applicable) | Disassembles, validates, traces, or executes VM programs. | firedancer/src/flamenco/vm/fd_vm_tool.c |
| fd_snapshot_main | • --page-sz, --page-cnt  <br>• --near-cpu  <br>• --snapshot  <br>• --manifest, etc. | Processes snapshot manifests and account records, generating CSV/YAML outputs. | firedancer/src/flamenco/snapshot/fd_snapshot_main.c |
| fd_solcap_yaml | • --page-sz, --page-cnt  <br>• --scratch-mb  <br>• -v  <br>• --start-slot  <br>• --end-slot | Converts runtime capture (solcap) files into YAML format. | firedancer/src/flamenco/capture/fd_solcap_yaml.c |
| fd_solcap_dump | • --file {FILE}  <br>• --type (with workspace options) | Decodes binary account data from capture files, outputting a YAML representation. | firedancer/src/flamenco/capture/fd_solcap_dump.c |
| fd_stakes_from_snapshot | Modes: epochs, nodes, leaders; • --page-sz, --page-cnt  <br>• --epoch (required for nodes/leaders) | Extracts epoch keys, node stakes, and leader schedules from snapshot manifests. | firedancer/src/flamenco/stakes/fd_stakes_from_snapshot.c |
| **Memory, Workspace & Pod Utilities** |     |     |     |
| fd_shmem_ctl | Subcommands: help, cpu-cnt, numa-cnt, cpu-idx, create, query, unlink | Manages shared memory segments (creation, querying, removal). | firedancer/src/util/shmem/fd_shmem_ctl.c |
| fd_alloc_ctl | Subcommands: help, tag, new, delete, malloc, free, compact, query | Controls dynamic memory allocation operations, including allocation and compaction. | firedancer/src/util/alloc/fd_alloc_ctl.c |
| fd_wksp_ctl | Subcommands: help, tag, new, delete, alloc, info, free, tag-query, tag-free, memset, check, verify, rebuild, reset, usage, query, checkpt, checkpt-query, restore | Manages workspaces (allocation, checkpointing, usage queries, etc.). | firedancer/src/util/wksp/fd_wksp_ctl.c |
| fd_pod_ctl | Subcommands: help, tag, new, delete, reset, list, insert, insert‑file, remove, update, set, compact, query‑root, query | Manages pod resources (creation, deletion, update, querying). | firedancer/src/util/pod/fd_pod_ctl.c |
| **Dependencies Script (deps.sh)** |     |     |     |
| deps.sh help | –   | Displays usage information for dependency commands. | Root-level script (deps.sh) |
| deps.sh nuke | –   | Removes the dependency installation directory ($PREFIX). | Root-level script (deps.sh) |
| deps.sh fetch | –   | Clones required dependencies into $PREFIX/git and initializes submodules. | Root-level script (deps.sh) |
| deps.sh check | –   | Verifies that system packages (e.g., curl, make, compiler tools) are installed. | Root-level script (deps.sh) |
| deps.sh install | –   | Builds and installs all project dependencies. | Root-level script (deps.sh) |
| deps.sh +msan (flag) | –   | Activates MemorySanitizer mode with custom prefix (./opt‑msan) and clang flags (-fsanitize=memory, -fno-omit-frame-pointer). | Root-level script (deps.sh) |
| deps.sh +dev (flag) | –   | Enables development mode, fetching extra repositories and supplemental OS package requirements. | Root-level script (deps.sh) |

For additional details on command usage, configuration options, and troubleshooting steps, refer to the repository’s documentation in the doc and book folders.

Happy validating!

Made with ❤️ by [Driver](https://www.driver.ai/) in 19 minutes
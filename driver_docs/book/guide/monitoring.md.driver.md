# Purpose
This document is a configuration and monitoring guide for a software system involving the Agave CLI and Firedancer, which are used in conjunction with the Solana blockchain validator. It provides detailed instructions on how to build and use command-line tools to monitor the performance and status of a Solana validator, including checking gossip participation, catch-up status, voting activity, and block production. The document also describes how to access Prometheus-compatible metrics exposed by Firedancer, which can be configured via a TOML file, and how to use the `fdctl` tool for live monitoring of system performance. The content is highly focused on monitoring and performance evaluation, providing both command-line and GUI options for users to track the operational status of their validator nodes. This file is crucial for developers and operators within the codebase to ensure the health and efficiency of their blockchain infrastructure.
# Content Summary
This document provides detailed instructions and information on monitoring the Frankendancer validator using various command-line tools and metrics. It is structured into sections that cover the use of the Agave CLI, metrics exposure, and live monitoring tools.

### Agave CLI Monitoring
The document begins by explaining how to monitor the Frankendancer validator using the Agave command-line interface (CLI). It instructs users to first build the `solana` CLI binary using the `make solana` command, which places the compiled binary in the `./build/native/gcc/bin` directory. The document highlights several key commands for monitoring the validator:

- **gossip:** This command checks if the validator has joined the gossip network, providing details such as IP address, identity, gossip port, TPU port, RPC address, version, and feature set.
- **catchup:** This command verifies if the validator is synchronized with the network by showing how many slots it is behind.
- **validators:** This command ensures the validator is actively voting, displaying information about the identity, vote account, commission, last vote, root slot, skip rate, credits, version, and active stake.
- **block-production:** This command checks if the validator is producing blocks, showing the number of leader slots, blocks produced, skipped slots, and skip rate.

The document notes that many commands require RPC to be enabled on the validator and refers users to a configuration guide for more information.

### Metrics
The document describes how Firedancer exposes a set of Prometheus-compatible metrics at an HTTP endpoint, defaulting to port `7999`, which can be configured in a TOML file. It provides an example of retrieving metrics using a `curl` command and mentions that more information is available in the metrics API documentation.

### Live Monitoring
Firedancer includes a monitoring tool, `fdctl`, which can be run on the same host as the validator to view performance information. The document provides an example command to run `fdctl` with a configuration file and explains the output, which includes various performance metrics for different tiles (e.g., net, quic, verify). Additionally, it mentions the availability of a Firedancer GUI for browser-based monitoring, with instructions to enable it in the configuration section.

Overall, this document serves as a comprehensive guide for developers to monitor and assess the performance and status of the Frankendancer validator using command-line tools and metrics.


## Files
- **[backtest.c](commands/backtest.c.driver.md)**: The `backtest.c` file in the `firedancer` codebase implements a command to set up and execute a smaller topology for replaying shreds from sources like RocksDB, simulating the behavior of a replay tile in a distributed system.
- **[bench.c](commands/bench.c.driver.md)**: The `bench.c` file in the `firedancer` codebase defines a command for testing validator TPS benchmarks, including a function that executes the benchmark and a structure describing the command's properties.
- **[dev.c](commands/dev.c.driver.md)**: The `dev.c` file defines a command function for starting a development validator in the Firedancer application, utilizing shared development command functionality.
- **[gossip.c](commands/gossip.c.driver.md)**: The `gossip.c` file in the `firedancer` codebase defines the setup and execution of a gossip protocol within a network topology, including configuration, initialization, and permission handling for the gossip command.
- **[sim.c](commands/sim.c.driver.md)**: The `sim.c` file in the `firedancer` codebase implements a command to simulate a smaller topology for reading archive files and reproducing fragments, as well as mimicking the behavior of a replay tile within a specified network topology.

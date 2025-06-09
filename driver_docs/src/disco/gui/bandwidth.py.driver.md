# Purpose
This Python script is designed to measure and report the bandwidth of incoming data over a WebSocket connection. It connects to a specified WebSocket server and continuously receives data frames. Each frame is expected to be a JSON object containing at least a "topic" and a "key," which are used to categorize the data into groups. The script calculates the total number of bytes received for each group and the overall total, then computes the bandwidth in megabits per second (Mbps) for each group and overall. This information is printed to the console every second, providing a real-time view of the data transmission rates.

The script leverages the `asyncio` and `websockets` libraries to handle asynchronous communication, allowing it to efficiently manage the WebSocket connection and data processing. The use of `defaultdict` from the `collections` module simplifies the accumulation of byte counts for each group. This code is structured as a standalone script, as indicated by the direct call to `asyncio.get_event_loop().run_until_complete()`, which initiates the bandwidth measurement process. The script does not define any public APIs or external interfaces, focusing solely on its internal functionality to monitor and report bandwidth usage.
# Imports and Dependencies

---
- `asyncio`
- `websockets`
- `time`
- `json`
- `collections.defaultdict`


# Functions

---
### measure\_bandwidth<!-- {{#callable:firedancer/src/disco/gui/bandwidth.measure_bandwidth}} -->
The `measure_bandwidth` function asynchronously measures and prints the incoming bandwidth of data received over a WebSocket connection, grouped by topic and key, every second.
- **Decorators**: `@async`
- **Inputs**:
    - `uri`: The URI of the WebSocket server to connect to.
- **Control Flow**:
    - Establishes an asynchronous WebSocket connection to the specified URI with a maximum frame size of 1,000,000,000 bytes.
    - Initializes a start time and dictionaries to track total bytes received by group and overall.
    - Enters an infinite loop to continuously receive frames from the WebSocket.
    - Parses each received frame as JSON to extract 'topic' and 'key', forming a group identifier.
    - Accumulates the byte length of each frame into the total bytes for its group and overall total bytes.
    - Calculates the elapsed time since the last bandwidth measurement.
    - If the elapsed time is greater than or equal to one second, calculates the bandwidth in Mbps for each group and overall.
    - Sorts the group bandwidths in descending order and prints them if they exceed 0.001 Mbps.
    - Prints the overall bandwidth and resets the start time and byte counters for the next measurement period.
- **Output**: The function does not return a value; it prints the bandwidth measurements to the console.



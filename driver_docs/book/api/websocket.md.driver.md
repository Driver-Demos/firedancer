# Purpose
The provided content is a detailed documentation of the Firedancer WebSocket API, which is an optional HTTP WebSockets API designed for consumers to subscribe to validator information. This API is primarily used to support the Firedancer GUI, offering real-time streaming of various topics related to the state and performance of a Solana validator. The documentation outlines how to connect to the API, the structure of data messages, and the different types of information that can be queried or received, such as validator summaries, slot updates, epoch information, and peer data. The API is not stable or versioned, and users are cautioned about its potential instability. The content is highly relevant to a codebase as it provides a comprehensive guide for developers to interact with the Firedancer WebSocket API, enabling them to integrate real-time validator data into their applications or monitoring tools.
# Content Summary
The provided document is a comprehensive guide to the Firedancer WebSocket API, which is designed to allow consumers to subscribe to validator information. This API is primarily used to support the Firedancer GUI and is not stable or versioned, meaning it can change or be removed without notice. Developers should exercise caution when using it.

### Key Functional Details:

1. **Connection and Configuration**: 
   - The API is accessed via a WebSocket client, typically connecting to `ws://localhost:80/websocket`. The port is specified in a TOML configuration file.
   - The API streams data to connected clients across various topics, and clients must keep up with the data stream to avoid disconnection.

2. **Data Streaming and Frequency**:
   - Data is streamed in real-time, with different frequencies such as `Once`, `Live`, `Request`, and periodic intervals like `1s`.
   - JSON is used for data encoding, with a structured envelope containing `topic`, `key`, and `value`.

3. **Query Mechanism**:
   - Clients can issue queries using WebSocket frames to request specific data, marked with a frequency of `Request`.
   - Queries must be well-formed to avoid disconnection, and responses may return `null` if data is unavailable.

4. **Handling Forks**:
   - The API provides information based on the current fork choice of the validator, which may not always be the newest or heaviest fork.
   - Information is updated when the validator switches fork choice.

5. **Topics and Data Points**:
   - **Summary**: Provides high-level information about the validator, including version, cluster, identity key, vote state, uptime, and startup progress.
   - **Block Engine**: Details about additional transaction providers configured by the operator.
   - **Epoch**: Information about epochs, including start and end times, staked pubkeys, and leader slots.
   - **Peers**: Information about validator peers, sourced from gossip and on-chain data.
   - **Slot**: Details about slots, including their state, transactions, and performance metrics.

6. **Slot and Transaction Details**:
   - Slots can be in various states such as `incomplete`, `completed`, `optimistically_confirmed`, `rooted`, and `finalized`.
   - Detailed transaction metrics are available, including compute units, fees, and error codes.

7. **Error Codes**:
   - A comprehensive list of error codes is provided, explaining potential issues that can occur during transaction processing.

This document serves as a detailed reference for developers working with the Firedancer WebSocket API, providing essential information on how to connect, query, and interpret the data streams related to validator operations.

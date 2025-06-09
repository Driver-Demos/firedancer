# Purpose
This file is a JSON configuration for a Grafana dashboard, which is used to visualize and monitor metrics related to QUIC (Quick UDP Internet Connections) and network performance. The file provides a detailed setup for various panels within the dashboard, each configured to display specific metrics such as packet rates, bandwidth, connection counts, and transaction rates, using data sourced from Prometheus. The configuration includes settings for visual elements like color schemes, grid positions, and data queries, ensuring that the dashboard is both informative and visually coherent. The file's content is crucial for the codebase as it defines how real-time data is presented to users, enabling them to monitor and analyze network performance effectively. The dashboard is titled "Firedancer Networking," indicating its focus on network-related metrics, and it is designed to be editable, allowing for customization and updates as needed.
# Content Summary
This JSON configuration file is a Grafana dashboard setup for monitoring networking metrics related to QUIC (Quick UDP Internet Connections) and other network activities. The dashboard is titled "Firedancer Networking" and is designed to provide insights into various aspects of network performance and health.

Key components of the configuration include:

1. **Annotations and Alerts**: The dashboard includes a built-in annotation feature for "Annotations & Alerts" with a specific icon color and is linked to the Grafana datasource.

2. **Panels**: The dashboard is composed of multiple panels, each configured to display specific metrics. These panels are primarily of the "timeseries" and "stat" types, and they visualize data such as packet rates, bandwidth, transaction counts, connection events, and latency. Each panel is associated with a Prometheus datasource, and the data is queried using PromQL expressions.

3. **Panel Details**:
   - **QUIC Packets and Bandwidth**: Panels display the rate of UDP packets handled by QUIC, both incoming (RX) and outgoing (TX), as well as the bandwidth usage.
   - **Transaction Metrics**: Panels track the number of transactions received, failed, and the stream completion rate.
   - **Connection Metrics**: Panels monitor active connections, connections created, aborted, gracefully closed, and rejected due to various reasons.
   - **Latency and Drops**: Panels provide insights into QUIC receive latency and packet drop rates.

4. **Field Configuration**: Each panel has detailed field configurations, including color modes, thresholds, and unit settings, to enhance data visualization. Thresholds are set to indicate performance levels, with colors like green and red to signify normal and critical states, respectively.

5. **Templating**: The dashboard uses templating to allow dynamic selection of data sources and instances. It includes variables for the datasource and instance, enabling users to filter and view data for specific instances.

6. **Time Settings**: The dashboard is set to display data from the last 30 minutes, with the timezone configured to UTC.

7. **Versioning and Metadata**: The dashboard has a unique identifier (UID), version number, and schema version, which are essential for managing and updating the dashboard configuration.

Overall, this configuration file is designed to provide a comprehensive view of network performance, focusing on QUIC protocol metrics, and is highly customizable through its templating and panel configurations.

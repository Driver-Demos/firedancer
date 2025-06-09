# Purpose
This Python code defines a framework for parsing and managing metrics from XML data, specifically focusing on different types of metrics such as counters, gauges, and histograms. The code is structured around several classes that represent different metric types and their properties, including `Metric`, `CounterMetric`, `GaugeMetric`, `HistogramMetric`, and their enum-based counterparts. The `Tile` and `MetricType` enums categorize metrics into different functional areas and types, respectively. The `Metrics` class aggregates these metrics, organizing them into common metrics, tile-specific metrics, and link-specific metrics, and provides methods to calculate their count and layout.

The code also includes functions for parsing XML data to instantiate these metric objects. The [`parse_metric`](#parse_metric) function interprets XML elements to create specific metric instances, while [`parse_metrics`](#parse_metrics) processes an entire XML document to build a comprehensive `Metrics` object. This setup suggests that the code is designed to be part of a larger system where metrics are defined in XML format and need to be programmatically accessed and manipulated. The code is likely intended to be used as a library, providing a structured way to handle metrics data, rather than as a standalone script.
# Imports and Dependencies

---
- `enum.Enum`
- `typing.Dict`
- `typing.List`
- `typing.Optional`
- `xml.etree.ElementTree`


# Classes

---
### Tile<!-- {{#class:firedancer/src/disco/metrics/generate/types.Tile}} -->
- **Members**:
    - `NET`: Represents the network tile with an integer value of 0.
    - `QUIC`: Represents the QUIC protocol tile with an integer value of 1.
    - `BUNDLE`: Represents the bundle tile with an integer value of 2.
    - `VERIFY`: Represents the verify tile with an integer value of 3.
    - `DEDUP`: Represents the deduplication tile with an integer value of 4.
    - `RESOLV`: Represents the resolve tile with an integer value of 5.
    - `PACK`: Represents the pack tile with an integer value of 6.
    - `BANK`: Represents the bank tile with an integer value of 7.
    - `POH`: Represents the proof of history tile with an integer value of 8.
    - `SHRED`: Represents the shred tile with an integer value of 9.
    - `STORE`: Represents the store tile with an integer value of 10.
    - `SIGN`: Represents the sign tile with an integer value of 11.
    - `METRIC`: Represents the metric tile with an integer value of 12.
    - `CSWTCH`: Represents the context switch tile with an integer value of 13.
    - `EVENT`: Represents the event tile with an integer value of 14.
    - `PLUGIN`: Represents the plugin tile with an integer value of 15.
    - `GUI`: Represents the graphical user interface tile with an integer value of 16.
    - `REPLAY`: Represents the replay tile with an integer value of 17.
    - `STOREI`: Represents the store interface tile with an integer value of 18.
    - `GOSSIP`: Represents the gossip protocol tile with an integer value of 19.
    - `NETLNK`: Represents the network link tile with an integer value of 20.
    - `SOCK`: Represents the socket tile with an integer value of 21.
    - `REPAIR`: Represents the repair tile with an integer value of 22.
    - `SEND`: Represents the send tile with an integer value of 23.
- **Description**: The Tile class is an enumeration that defines a set of constants representing different types of tiles, each associated with a unique integer value. These tiles are likely used to categorize or identify different components or functionalities within a system, such as network operations, protocol handling, data storage, and user interface elements. Each tile is represented by a name and an integer, facilitating easy reference and comparison within the code.
- **Inherits From**:
    - `Enum`


---
### MetricType<!-- {{#class:firedancer/src/disco/metrics/generate/types.MetricType}} -->
- **Decorators**: `@Enum`
- **Members**:
    - `COUNTER`: Represents a counter metric type with a value of 0.
    - `GAUGE`: Represents a gauge metric type with a value of 1.
    - `HISTOGRAM`: Represents a histogram metric type with a value of 2.
- **Description**: The MetricType class is an enumeration that defines three distinct types of metrics: COUNTER, GAUGE, and HISTOGRAM, each associated with a unique integer value. This class is used to categorize metrics based on their behavior and characteristics, facilitating the management and processing of different metric types within the system.
- **Inherits From**:
    - `Enum`


---
### HistogramConverter<!-- {{#class:firedancer/src/disco/metrics/generate/types.HistogramConverter}} -->
- **Members**:
    - `NONE`: Represents no conversion with a value of 0.
    - `SECONDS`: Represents conversion to seconds with a value of 1.
- **Description**: The HistogramConverter class is an enumeration that defines two possible conversion types for histograms: NONE, which indicates no conversion, and SECONDS, which indicates conversion to seconds. This class is used to specify how histogram data should be interpreted or converted in the context of metrics.
- **Inherits From**:
    - `Enum`


---
### EnumValue<!-- {{#class:firedancer/src/disco/metrics/generate/types.EnumValue}} -->
- **Members**:
    - `value`: An integer representing the value of the enum.
    - `name`: A string representing the name of the enum.
    - `label`: A string representing the label of the enum.
- **Description**: The EnumValue class is a simple data structure used to represent an enumeration value with its associated integer value, name, and label. It is typically used within a collection of enum values to provide a structured representation of enumerated data, allowing for easy access and manipulation of these attributes.
- **Methods**:
    - [`firedancer/src/disco/metrics/generate/types.EnumValue.__init__`](#EnumValue__init__)

**Methods**

---
#### EnumValue\.\_\_init\_\_<!-- {{#callable:firedancer/src/disco/metrics/generate/types.EnumValue.__init__}} -->
The `__init__` method initializes an instance of the `EnumValue` class with specified integer value, name, and label attributes.
- **Inputs**:
    - `value`: An integer representing the value of the enum.
    - `name`: A string representing the name of the enum.
    - `label`: A string representing the label of the enum.
- **Control Flow**:
    - Assigns the input integer `value` to the instance's `value` attribute.
    - Assigns the input string `name` to the instance's `name` attribute.
    - Assigns the input string `label` to the instance's `label` attribute.
- **Output**: This method does not return any value; it initializes the instance attributes.
- **See also**: [`firedancer/src/disco/metrics/generate/types.EnumValue`](#EnumValue)  (Base Class)



---
### MetricEnum<!-- {{#class:firedancer/src/disco/metrics/generate/types.MetricEnum}} -->
- **Members**:
    - `name`: The name of the metric enumeration.
    - `values`: A list of EnumValue objects representing the possible values of the metric enumeration.
- **Description**: The MetricEnum class is designed to represent a metric enumeration, which includes a name and a list of possible values encapsulated as EnumValue objects. This class is used to define enumerations for metrics, allowing for structured representation and easy access to the enumeration's name and its associated values.
- **Methods**:
    - [`firedancer/src/disco/metrics/generate/types.MetricEnum.__init__`](#MetricEnum__init__)

**Methods**

---
#### MetricEnum\.\_\_init\_\_<!-- {{#callable:firedancer/src/disco/metrics/generate/types.MetricEnum.__init__}} -->
The `__init__` method initializes a `MetricEnum` object with a name and a list of `EnumValue` objects.
- **Inputs**:
    - `name`: A string representing the name of the metric enumeration.
    - `values`: A list of `EnumValue` objects representing the possible values for the metric enumeration.
- **Control Flow**:
    - Assigns the `name` parameter to the `name` attribute of the `MetricEnum` instance.
    - Assigns the `values` parameter to the `values` attribute of the `MetricEnum` instance.
- **Output**: This method does not return any value; it initializes the attributes of the `MetricEnum` instance.
- **See also**: [`firedancer/src/disco/metrics/generate/types.MetricEnum`](#MetricEnum)  (Base Class)



---
### Metric<!-- {{#class:firedancer/src/disco/metrics/generate/types.Metric}} -->
- **Members**:
    - `type`: Specifies the type of the metric, such as counter, gauge, or histogram.
    - `name`: The name of the metric.
    - `tile`: An optional tile associated with the metric, indicating its category or group.
    - `description`: A textual description of the metric.
    - `clickhouse_exclude`: A boolean indicating whether the metric should be excluded from ClickHouse.
    - `offset`: An integer representing the offset of the metric, initialized to 0.
- **Description**: The Metric class represents a generic metric with attributes defining its type, name, associated tile, description, and whether it should be excluded from ClickHouse. It provides a basic structure for metrics, including a default offset and methods to calculate its footprint and count.
- **Methods**:
    - [`firedancer/src/disco/metrics/generate/types.Metric.__init__`](#Metric__init__)
    - [`firedancer/src/disco/metrics/generate/types.Metric.footprint`](#Metricfootprint)
    - [`firedancer/src/disco/metrics/generate/types.Metric.count`](#Metriccount)

**Methods**

---
#### Metric\.\_\_init\_\_<!-- {{#callable:firedancer/src/disco/metrics/generate/types.Metric.__init__}} -->
The `__init__` method initializes a `Metric` object with specified attributes such as type, name, tile, description, and clickhouse exclusion flag, and sets an initial offset value.
- **Inputs**:
    - `type`: The type of the metric, specified as a `MetricType` enum value.
    - `name`: A string representing the name of the metric.
    - `tile`: An optional `Tile` enum value indicating the tile associated with the metric.
    - `description`: A string providing a description of the metric.
    - `clickhouse_exclude`: A boolean flag indicating whether the metric should be excluded from ClickHouse.
- **Control Flow**:
    - Assigns the `type` parameter to the `self.type` attribute.
    - Assigns the `name` parameter to the `self.name` attribute.
    - Assigns the `tile` parameter to the `self.tile` attribute.
    - Assigns the `description` parameter to the `self.description` attribute.
    - Assigns the `clickhouse_exclude` parameter to the `self.clickhouse_exclude` attribute.
    - Initializes the `self.offset` attribute to 0.
- **Output**: This method does not return any value; it initializes the attributes of a `Metric` instance.
- **See also**: [`firedancer/src/disco/metrics/generate/types.Metric`](#Metric)  (Base Class)


---
#### Metric\.footprint<!-- {{#callable:firedancer/src/disco/metrics/generate/types.Metric.footprint}} -->
The `footprint` method in the `Metric` class returns a fixed integer value representing the memory footprint of the metric.
- **Inputs**: None
- **Control Flow**:
    - The method directly returns the integer value 8 without any computation or condition checks.
- **Output**: The method returns an integer value of 8.
- **See also**: [`firedancer/src/disco/metrics/generate/types.Metric`](#Metric)  (Base Class)


---
#### Metric\.count<!-- {{#callable:firedancer/src/disco/metrics/generate/types.Metric.count}} -->
The `count` method in the `Metric` class returns a constant integer value of 1.
- **Inputs**: None
- **Control Flow**:
    - The method directly returns the integer value 1 without any conditions or calculations.
- **Output**: An integer value of 1.
- **See also**: [`firedancer/src/disco/metrics/generate/types.Metric`](#Metric)  (Base Class)



---
### CounterMetric<!-- {{#class:firedancer/src/disco/metrics/generate/types.CounterMetric}} -->
- **Description**: The `CounterMetric` class is a specialized type of `Metric` that represents a counter metric, which is used to track the count of occurrences of a particular event or condition. It inherits from the `Metric` class and is initialized with a metric type of `COUNTER`, along with a name, an optional tile, a description, and a flag indicating whether it should be excluded from ClickHouse. This class does not introduce any additional properties beyond those inherited from `Metric`.
- **Methods**:
    - [`firedancer/src/disco/metrics/generate/types.CounterMetric.__init__`](#CounterMetric__init__)
- **Inherits From**:
    - [`firedancer/src/disco/metrics/generate/types.Metric`](#Metric)

**Methods**

---
#### CounterMetric\.\_\_init\_\_<!-- {{#callable:firedancer/src/disco/metrics/generate/types.CounterMetric.__init__}} -->
The [`__init__`](#EnumValue__init__) method initializes a `CounterMetric` object by setting its attributes using the provided parameters and calling the parent class constructor with a specific metric type.
- **Inputs**:
    - `name`: A string representing the name of the metric.
    - `tile`: An optional `Tile` enum value indicating the tile associated with the metric.
    - `description`: A string providing a description of the metric.
    - `clickhouse_exclude`: A boolean indicating whether the metric should be excluded from ClickHouse.
- **Control Flow**:
    - The method begins by calling the [`__init__`](#EnumValue__init__) method of the parent class `Metric` using `super()`.
    - It passes `MetricType.COUNTER` along with the provided parameters `name`, `tile`, `description`, and `clickhouse_exclude` to the parent class constructor.
- **Output**: The method does not return any value; it initializes the `CounterMetric` instance.
- **Functions called**:
    - [`firedancer/src/disco/metrics/generate/types.EnumValue.__init__`](#EnumValue__init__)
- **See also**: [`firedancer/src/disco/metrics/generate/types.CounterMetric`](#CounterMetric)  (Base Class)



---
### GaugeMetric<!-- {{#class:firedancer/src/disco/metrics/generate/types.GaugeMetric}} -->
- **Description**: The `GaugeMetric` class is a specialized type of `Metric` that represents a gauge metric, which is used to measure values that can go up and down, such as temperature or speed. It inherits from the `Metric` class and is initialized with a specific metric type of `GAUGE`, along with a name, an optional tile, a description, and a flag indicating whether to exclude it from ClickHouse. This class does not introduce any new members beyond those inherited from `Metric`.
- **Methods**:
    - [`firedancer/src/disco/metrics/generate/types.GaugeMetric.__init__`](#GaugeMetric__init__)
- **Inherits From**:
    - [`firedancer/src/disco/metrics/generate/types.Metric`](#Metric)

**Methods**

---
#### GaugeMetric\.\_\_init\_\_<!-- {{#callable:firedancer/src/disco/metrics/generate/types.GaugeMetric.__init__}} -->
The [`__init__`](#Metric__init__) method initializes a `GaugeMetric` object by setting its type to `GAUGE` and passing other parameters to the parent `Metric` class.
- **Inputs**:
    - `name`: A string representing the name of the metric.
    - `tile`: An optional `Tile` enum value indicating the tile associated with the metric.
    - `description`: A string providing a description of the metric.
    - `clickhouse_exclude`: A boolean indicating whether the metric should be excluded from ClickHouse.
- **Control Flow**:
    - The method calls the parent class `Metric`'s [`__init__`](#Metric__init__) method using `super()`, passing `MetricType.GAUGE` as the type along with the other parameters: `name`, `tile`, `description`, and `clickhouse_exclude`.
- **Output**: There is no return value as this is a constructor method for initializing an object.
- **Functions called**:
    - [`firedancer/src/disco/metrics/generate/types.Metric.__init__`](#Metric__init__)
- **See also**: [`firedancer/src/disco/metrics/generate/types.GaugeMetric`](#GaugeMetric)  (Base Class)



---
### HistogramMetric<!-- {{#class:firedancer/src/disco/metrics/generate/types.HistogramMetric}} -->
- **Members**:
    - `converter`: Specifies the converter type for the histogram data.
    - `min`: Defines the minimum value for the histogram range.
    - `max`: Defines the maximum value for the histogram range.
- **Description**: The HistogramMetric class is a specialized type of Metric that represents histogram data, inheriting from the Metric class. It includes additional attributes specific to histograms, such as a converter to handle data conversion and minimum and maximum values to define the range of the histogram. This class is used to encapsulate histogram metrics with specific configurations and provides a method to calculate its memory footprint.
- **Methods**:
    - [`firedancer/src/disco/metrics/generate/types.HistogramMetric.__init__`](#HistogramMetric__init__)
    - [`firedancer/src/disco/metrics/generate/types.HistogramMetric.footprint`](#HistogramMetricfootprint)
- **Inherits From**:
    - [`firedancer/src/disco/metrics/generate/types.Metric`](#Metric)

**Methods**

---
#### HistogramMetric\.\_\_init\_\_<!-- {{#callable:firedancer/src/disco/metrics/generate/types.HistogramMetric.__init__}} -->
The [`__init__`](#EnumValue__init__) method initializes a `HistogramMetric` object with specific attributes including a converter, minimum, and maximum values.
- **Inputs**:
    - `name`: A string representing the name of the histogram metric.
    - `tile`: An optional `Tile` enum value indicating the tile associated with the metric.
    - `description`: A string providing a description of the histogram metric.
    - `clickhouse_exclude`: A boolean indicating whether to exclude this metric from ClickHouse.
    - `converter`: A `HistogramConverter` enum value specifying the conversion type for the histogram.
    - `min`: A string representing the minimum value for the histogram.
    - `max`: A string representing the maximum value for the histogram.
- **Control Flow**:
    - Calls the parent class `Metric`'s [`__init__`](#EnumValue__init__) method with `MetricType.HISTOGRAM` and other provided parameters.
    - Assigns the `converter` parameter to the `self.converter` attribute.
    - Assigns the `min` parameter to the `self.min` attribute.
    - Assigns the `max` parameter to the `self.max` attribute.
- **Output**: This method does not return any value; it initializes the object's state.
- **Functions called**:
    - [`firedancer/src/disco/metrics/generate/types.EnumValue.__init__`](#EnumValue__init__)
- **See also**: [`firedancer/src/disco/metrics/generate/types.HistogramMetric`](#HistogramMetric)  (Base Class)


---
#### HistogramMetric\.footprint<!-- {{#callable:firedancer/src/disco/metrics/generate/types.HistogramMetric.footprint}} -->
The `footprint` method in the `HistogramMetric` class returns a fixed integer value representing the memory footprint of the metric.
- **Inputs**: None
- **Control Flow**:
    - The method directly returns the integer value 136 without any computation or condition checks.
- **Output**: The method outputs an integer value, specifically 136, which represents the memory footprint of the `HistogramMetric` instance.
- **See also**: [`firedancer/src/disco/metrics/generate/types.HistogramMetric`](#HistogramMetric)  (Base Class)



---
### CounterEnumMetric<!-- {{#class:firedancer/src/disco/metrics/generate/types.CounterEnumMetric}} -->
- **Members**:
    - `enum`: Holds the MetricEnum instance associated with the CounterEnumMetric.
- **Description**: The CounterEnumMetric class is a specialized type of Metric that represents a counter metric associated with an enumeration. It extends the base Metric class by incorporating a MetricEnum, which defines a set of enumerated values that the counter can take. This class provides methods to calculate the memory footprint and count of the enumerated values, making it suitable for scenarios where metrics need to be categorized or differentiated based on enumerated types.
- **Methods**:
    - [`firedancer/src/disco/metrics/generate/types.CounterEnumMetric.__init__`](#CounterEnumMetric__init__)
    - [`firedancer/src/disco/metrics/generate/types.CounterEnumMetric.footprint`](#CounterEnumMetricfootprint)
    - [`firedancer/src/disco/metrics/generate/types.CounterEnumMetric.count`](#CounterEnumMetriccount)
- **Inherits From**:
    - [`firedancer/src/disco/metrics/generate/types.Metric`](#Metric)

**Methods**

---
#### CounterEnumMetric\.\_\_init\_\_<!-- {{#callable:firedancer/src/disco/metrics/generate/types.CounterEnumMetric.__init__}} -->
The [`__init__`](#CounterMetric__init__) method initializes a `CounterEnumMetric` object with specified attributes and sets its metric type to `COUNTER`.
- **Inputs**:
    - `name`: A string representing the name of the metric.
    - `tile`: An optional `Tile` enum value indicating the tile associated with the metric.
    - `description`: A string providing a description of the metric.
    - `clickhouse_exclude`: A boolean indicating whether the metric should be excluded from ClickHouse.
    - `enum`: A `MetricEnum` object representing the enumeration associated with the metric.
- **Control Flow**:
    - The method calls the parent class `Metric`'s [`__init__`](#CounterMetric__init__) method with `MetricType.COUNTER`, `name`, `tile`, `description`, and `clickhouse_exclude` as arguments to initialize the base attributes.
    - The `enum` attribute of the `CounterEnumMetric` instance is set to the provided `enum` argument.
- **Output**: The method does not return any value; it initializes the instance of `CounterEnumMetric`.
- **Functions called**:
    - [`firedancer/src/disco/metrics/generate/types.CounterMetric.__init__`](#CounterMetric__init__)
- **See also**: [`firedancer/src/disco/metrics/generate/types.CounterEnumMetric`](#CounterEnumMetric)  (Base Class)


---
#### CounterEnumMetric\.footprint<!-- {{#callable:firedancer/src/disco/metrics/generate/types.CounterEnumMetric.footprint}} -->
The `footprint` method calculates the memory footprint of a `CounterEnumMetric` instance based on the number of enum values it contains.
- **Inputs**: None
- **Control Flow**:
    - The method accesses the `enum` attribute of the `CounterEnumMetric` instance, which is expected to be a `MetricEnum` object.
    - It retrieves the `values` attribute from the `enum`, which is a list of `EnumValue` objects.
    - The method calculates the length of the `values` list to determine the number of enum values.
    - It multiplies the length of the `values` list by 8 to compute the total memory footprint.
- **Output**: The method returns an integer representing the memory footprint, calculated as 8 times the number of enum values in the `enum` attribute.
- **See also**: [`firedancer/src/disco/metrics/generate/types.CounterEnumMetric`](#CounterEnumMetric)  (Base Class)


---
#### CounterEnumMetric\.count<!-- {{#callable:firedancer/src/disco/metrics/generate/types.CounterEnumMetric.count}} -->
The `count` method in the `CounterEnumMetric` class returns the number of values in the associated `MetricEnum`.
- **Inputs**: None
- **Control Flow**:
    - The method accesses the `enum` attribute of the `CounterEnumMetric` instance, which is an instance of `MetricEnum`.
    - It retrieves the `values` attribute from the `enum`, which is a list of `EnumValue` objects.
    - The method calculates the length of this list using the `len()` function.
    - The length, representing the count of enum values, is returned as the output.
- **Output**: The method returns an integer representing the number of values in the `MetricEnum` associated with the `CounterEnumMetric` instance.
- **See also**: [`firedancer/src/disco/metrics/generate/types.CounterEnumMetric`](#CounterEnumMetric)  (Base Class)



---
### GaugeEnumMetric<!-- {{#class:firedancer/src/disco/metrics/generate/types.GaugeEnumMetric}} -->
- **Members**:
    - `enum`: Holds the MetricEnum instance associated with the gauge metric.
- **Description**: The GaugeEnumMetric class is a specialized type of Metric that represents a gauge metric associated with an enumeration of values. It extends the base Metric class by incorporating a MetricEnum, which allows it to handle multiple enumerated values. This class provides methods to calculate the memory footprint and count of the enumerated values, making it suitable for scenarios where metrics need to be categorized and quantified based on predefined enumerations.
- **Methods**:
    - [`firedancer/src/disco/metrics/generate/types.GaugeEnumMetric.__init__`](#GaugeEnumMetric__init__)
    - [`firedancer/src/disco/metrics/generate/types.GaugeEnumMetric.footprint`](#GaugeEnumMetricfootprint)
    - [`firedancer/src/disco/metrics/generate/types.GaugeEnumMetric.count`](#GaugeEnumMetriccount)
- **Inherits From**:
    - [`firedancer/src/disco/metrics/generate/types.Metric`](#Metric)

**Methods**

---
#### GaugeEnumMetric\.\_\_init\_\_<!-- {{#callable:firedancer/src/disco/metrics/generate/types.GaugeEnumMetric.__init__}} -->
The [`__init__`](#EnumValue__init__) method initializes a `GaugeEnumMetric` object with specified attributes and sets its type to `GAUGE`.
- **Inputs**:
    - `name`: A string representing the name of the metric.
    - `tile`: An optional `Tile` enum value indicating the tile associated with the metric.
    - `description`: A string providing a description of the metric.
    - `clickhouse_exclude`: A boolean indicating whether the metric should be excluded from ClickHouse.
    - `enum`: A `MetricEnum` object representing the enumeration associated with the metric.
- **Control Flow**:
    - Calls the parent class `Metric`'s [`__init__`](#EnumValue__init__) method with `MetricType.GAUGE`, `name`, `tile`, `description`, and `clickhouse_exclude` as arguments.
    - Assigns the `enum` parameter to the `enum` attribute of the `GaugeEnumMetric` instance.
- **Output**: The method does not return any value; it initializes the object.
- **Functions called**:
    - [`firedancer/src/disco/metrics/generate/types.EnumValue.__init__`](#EnumValue__init__)
- **See also**: [`firedancer/src/disco/metrics/generate/types.GaugeEnumMetric`](#GaugeEnumMetric)  (Base Class)


---
#### GaugeEnumMetric\.footprint<!-- {{#callable:firedancer/src/disco/metrics/generate/types.GaugeEnumMetric.footprint}} -->
The `footprint` method calculates the memory footprint of a `GaugeEnumMetric` instance based on the number of enum values it contains.
- **Inputs**: None
- **Control Flow**:
    - The method accesses the `enum` attribute of the `GaugeEnumMetric` instance, which is expected to be a `MetricEnum` object.
    - It retrieves the `values` attribute from the `enum`, which is a list of `EnumValue` objects.
    - The method calculates the length of the `values` list to determine the number of enum values.
    - It multiplies the length of the `values` list by 8 to compute the total memory footprint.
- **Output**: The method returns an integer representing the memory footprint, calculated as 8 times the number of enum values in the `enum` attribute.
- **See also**: [`firedancer/src/disco/metrics/generate/types.GaugeEnumMetric`](#GaugeEnumMetric)  (Base Class)


---
#### GaugeEnumMetric\.count<!-- {{#callable:firedancer/src/disco/metrics/generate/types.GaugeEnumMetric.count}} -->
The `count` method in the `GaugeEnumMetric` class returns the number of values in the associated `MetricEnum`.
- **Inputs**: None
- **Control Flow**:
    - The method accesses the `enum` attribute of the `GaugeEnumMetric` instance, which is an instance of `MetricEnum`.
    - It retrieves the `values` attribute from the `enum`, which is a list of `EnumValue` objects.
    - The method calculates the length of this list using the `len()` function.
    - The length of the list, representing the count of enum values, is returned as an integer.
- **Output**: The method returns an integer representing the number of values in the `MetricEnum` associated with the `GaugeEnumMetric` instance.
- **See also**: [`firedancer/src/disco/metrics/generate/types.GaugeEnumMetric`](#GaugeEnumMetric)  (Base Class)



---
### Metrics<!-- {{#class:firedancer/src/disco/metrics/generate/types.Metrics}} -->
- **Members**:
    - `common`: A list of common metrics shared across different components.
    - `tiles`: A dictionary mapping Tile enums to lists of metrics specific to each tile.
    - `link_in`: A list of metrics related to incoming links.
    - `link_out`: A list of metrics related to outgoing links.
    - `enums`: A list of MetricEnum objects representing enumerated metric types.
- **Description**: The Metrics class is designed to manage and organize a collection of metrics, categorized into common metrics, tile-specific metrics, and link-related metrics. It provides functionality to count the total number of metrics and to layout the metrics by calculating their offsets based on their footprint. This class is essential for handling metrics in a structured manner, allowing for efficient metric management and retrieval.
- **Methods**:
    - [`firedancer/src/disco/metrics/generate/types.Metrics.__init__`](#Metrics__init__)
    - [`firedancer/src/disco/metrics/generate/types.Metrics.count`](#Metricscount)
    - [`firedancer/src/disco/metrics/generate/types.Metrics.layout`](#Metricslayout)

**Methods**

---
#### Metrics\.\_\_init\_\_<!-- {{#callable:firedancer/src/disco/metrics/generate/types.Metrics.__init__}} -->
The `__init__` method initializes a `Metrics` object with lists of common metrics, tile-specific metrics, link-in metrics, link-out metrics, and metric enumerations.
- **Inputs**:
    - `common`: A list of `Metric` objects representing common metrics.
    - `tiles`: A dictionary mapping `Tile` enum values to lists of `Metric` objects, representing metrics specific to each tile.
    - `link_in`: A list of `Metric` objects representing link-in metrics.
    - `link_out`: A list of `Metric` objects representing link-out metrics.
    - `enums`: A list of `MetricEnum` objects representing metric enumerations.
- **Control Flow**:
    - Assigns the `common` parameter to the instance variable `self.common`.
    - Assigns the `tiles` parameter to the instance variable `self.tiles`.
    - Assigns the `link_in` parameter to the instance variable `self.link_in`.
    - Assigns the `link_out` parameter to the instance variable `self.link_out`.
    - Assigns the `enums` parameter to the instance variable `self.enums`.
- **Output**: This method does not return any value; it initializes the instance variables of the `Metrics` class.
- **See also**: [`firedancer/src/disco/metrics/generate/types.Metrics`](#Metrics)  (Base Class)


---
#### Metrics\.count<!-- {{#callable:firedancer/src/disco/metrics/generate/types.Metrics.count}} -->
The [`count`](#Metriccount) method calculates the total count of all metrics across different categories in the `Metrics` class.
- **Inputs**: None
- **Control Flow**:
    - The method starts by calculating the sum of counts for all metrics in the `common` list using a list comprehension and the [`count`](#Metriccount) method of each `Metric` object.
    - It then adds the sum of counts for each list of metrics in the `tiles` dictionary, iterating over each list of metrics associated with a tile and summing their counts.
    - Next, it adds the sum of counts for all metrics in the `link_in` list, again using a list comprehension to call the [`count`](#Metriccount) method on each `Metric`.
    - Finally, it adds the sum of counts for all metrics in the `link_out` list, using a similar list comprehension to call the [`count`](#Metriccount) method on each `Metric`.
- **Output**: The method returns an integer representing the total count of all metrics across the `common`, `tiles`, `link_in`, and `link_out` categories.
- **Functions called**:
    - [`firedancer/src/disco/metrics/generate/types.Metric.count`](#Metriccount)
- **See also**: [`firedancer/src/disco/metrics/generate/types.Metrics`](#Metrics)  (Base Class)


---
#### Metrics\.layout<!-- {{#callable:firedancer/src/disco/metrics/generate/types.Metrics.layout}} -->
The `layout` method calculates and assigns offset values to metrics in different categories based on their footprint size.
- **Inputs**: None
- **Control Flow**:
    - Initialize an integer variable `offset` to 0.
    - Iterate over each metric in `self.link_in`, set its `offset` to the current `offset` value, and increment `offset` by the metric's footprint divided by 8.
    - Reinitialize `offset` to 0 and repeat the above step for `self.link_out`.
    - Reinitialize `offset` to 0 and repeat the above step for `self.common`.
    - Iterate over each list of metrics in `self.tiles.values()`, initialize `tile_offset` to the current `offset`, set each metric's `offset` to `tile_offset`, and increment `tile_offset` by the metric's footprint divided by 8.
- **Output**: The method does not return any value; it modifies the `offset` attribute of each `Metric` object in place.
- **Functions called**:
    - [`firedancer/src/disco/metrics/generate/types.Metric.footprint`](#Metricfootprint)
- **See also**: [`firedancer/src/disco/metrics/generate/types.Metrics`](#Metrics)  (Base Class)



# Functions

---
### parse\_metric<!-- {{#callable:firedancer/src/disco/metrics/generate/types.parse_metric}} -->
The `parse_metric` function parses an XML element representing a metric and returns an appropriate Metric object based on the metric's type and attributes.
- **Inputs**:
    - `tile`: An optional Tile enum value that represents the tile associated with the metric.
    - `metric`: An XML element (ET.Element) that contains the attributes and sub-elements defining the metric.
    - `enums`: A dictionary mapping enum names to MetricEnum objects, used for metrics that reference enumerations.
- **Control Flow**:
    - Extract the 'name' attribute from the metric XML element.
    - Initialize the 'description' variable to an empty string.
    - Check for a 'summary' sub-element or attribute in the metric to set the 'description'.
    - Determine if the metric should be excluded from ClickHouse by checking the 'clickhouse_exclude' attribute.
    - Check the tag of the metric to determine its type: 'counter', 'gauge', or 'histogram'.
    - For 'counter' and 'gauge' types, check for an 'enum' attribute to decide between EnumMetric and regular Metric classes.
    - For 'histogram' type, determine the converter type from the 'converter' attribute and extract 'min' and 'max' attributes.
    - Raise an exception if the metric type is unknown.
- **Output**: Returns an instance of a subclass of Metric (CounterMetric, GaugeMetric, HistogramMetric, CounterEnumMetric, or GaugeEnumMetric) based on the metric's type and attributes.
- **Functions called**:
    - [`firedancer/src/disco/metrics/generate/types.CounterEnumMetric`](#CounterEnumMetric)
    - [`firedancer/src/disco/metrics/generate/types.CounterMetric`](#CounterMetric)
    - [`firedancer/src/disco/metrics/generate/types.GaugeEnumMetric`](#GaugeEnumMetric)
    - [`firedancer/src/disco/metrics/generate/types.GaugeMetric`](#GaugeMetric)
    - [`firedancer/src/disco/metrics/generate/types.HistogramMetric`](#HistogramMetric)


---
### parse\_metrics<!-- {{#callable:firedancer/src/disco/metrics/generate/types.parse_metrics}} -->
The `parse_metrics` function parses XML data to construct and return a [`Metrics`](#Metrics) object containing metric definitions and enumerations.
- **Inputs**:
    - `xml_data`: A string containing XML data that defines metrics and enumerations.
- **Control Flow**:
    - Parse the XML data into an ElementTree structure using `ET.fromstring`.
    - Extract and construct a dictionary of [`MetricEnum`](#MetricEnum) objects from the XML elements named 'enum'.
    - Find the 'common' XML element, assert its existence, and parse its child elements into a list of `Metric` objects using [`parse_metric`](#parse_metric).
    - Find all 'tile' XML elements, parse each tile's metrics into a dictionary mapping `Tile` enums to lists of `Metric` objects.
    - Find the 'linkin' XML element, assert its existence, and parse its child elements into a list of `Metric` objects using [`parse_metric`](#parse_metric).
    - Find the 'linkout' XML element, assert its existence, and parse its child elements into a list of `Metric` objects using [`parse_metric`](#parse_metric).
    - Return a [`Metrics`](#Metrics) object initialized with the parsed common metrics, tile metrics, link-in metrics, link-out metrics, and enumerations.
- **Output**: A [`Metrics`](#Metrics) object containing parsed metric definitions and enumerations from the XML data.
- **Functions called**:
    - [`firedancer/src/disco/metrics/generate/types.MetricEnum`](#MetricEnum)
    - [`firedancer/src/disco/metrics/generate/types.EnumValue`](#EnumValue)
    - [`firedancer/src/disco/metrics/generate/types.parse_metric`](#parse_metric)
    - [`firedancer/src/disco/metrics/generate/types.Metrics`](#Metrics)



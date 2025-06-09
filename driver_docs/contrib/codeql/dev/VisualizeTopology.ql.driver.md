# Purpose
This source code file is designed to facilitate the visualization of a network topology by defining classes and methods that represent various components of the topology, such as tiles and links. The code is structured around several classes, including `Tile`, `InLink`, `OutLink`, and `Link`, each extending from a base class or type and providing specific functionality to identify and represent these components. The `Tile` class, for instance, identifies function calls related to network tiles and provides methods to generate JSON and Mermaid representations of these tiles. Similarly, the `InLink` and `OutLink` classes capture input and output link information, respectively, and the `Link` class combines these to represent complete links between tiles.

The file provides both JSON and Mermaid representations of the network topology, which are useful for different visualization purposes. JSON is a widely-used format for data interchange, while Mermaid is a tool for creating diagrams and visualizations from text definitions. The methods `getJson` and `getMermaid` compile the representations of all tiles and links into these formats, allowing for easy integration with visualization tools or further processing.

Overall, this code serves as a utility for extracting and representing network topology information from specific source files, as indicated by the `inTopology` predicate. It is not an executable file but rather a library or module intended to be used within a larger system that requires visualization of network topologies. The focus on specific file paths and function names suggests it is tailored to a particular application or set of applications, providing a narrow but essential functionality within that context.
# Imports and Dependencies

---
- `cpp`


# Data Structures

---
### Tile
- **Type**: `class`
- **Members**:
    - `name`: A string representing the name of the tile.
- **Description**: The `Tile` class is a specialized data structure that extends the `FunctionCall` class, representing a tile in a network topology. It includes a constructor that initializes the tile by checking specific conditions such as the target name and location within the topology. The class provides methods to get JSON and Mermaid representations of the tile, determining if it is a multi-tile and its shape in a diagram. The `Tile` class is integral to visualizing and managing network topologies, particularly in distinguishing between single and multi-tile configurations.


---
### InLink
- **Type**: `class`
- **Members**:
    - `name`: Stores the name of the InLink.
    - `in_tile`: Stores the name of the tile associated with the InLink.
- **Description**: The InLink class is a specialized data structure that extends the FunctionCall class, representing an incoming link in a network topology. It captures the name of the link and the associated tile, either from a specific function call or a network context, ensuring it is part of a defined topology. The class provides methods to retrieve the name and the tile of the link, facilitating the representation and manipulation of network connections.


---
### OutLink
- **Type**: `class`
- **Members**:
    - `name`: Stores the name of the OutLink.
    - `out_tile`: Stores the name of the output tile associated with the OutLink.
- **Description**: The OutLink class is a specialized data structure that extends the FunctionCall class, designed to represent an outgoing link in a network topology. It captures the name of the link and the associated output tile, ensuring that the link is part of a specified topology. The class provides methods to retrieve the name and output tile, facilitating the representation and manipulation of network links within the system.


---
### Link
- **Type**: `class`
- **Members**:
    - `name`: The name of the link.
    - `out_tile`: The name of the output tile.
    - `in_tile`: The name of the input tile.
- **Description**: The `Link` class represents a connection between two tiles, identified by a name, an output tile, and an input tile. It is constructed by matching an `OutLink` and an `InLink` with the same name, and it provides methods to generate JSON and Mermaid representations of the link.


# Functions

---
### inTopology
The `inTopology` function checks if a given location is part of a specific topology by verifying its file path.
- **Inputs**:
    - `loc`: A `Location` object representing the location to be checked.
- **Control Flow**:
    - Retrieve the file path of the location using `loc.getFile().getRelativePath()`.
    - Check if the file path is equal to either 'src/app/firedancer/topology.c' or 'src/disco/net/fd_net_tile_topo.c'.
    - Return true if the file path matches either of the specified paths, indicating the location is part of the topology.
- **Output**: A boolean value indicating whether the location is part of the specified topology.


---
### Tile
The `Tile` class represents a function call that checks for specific conditions related to topology and provides JSON and Mermaid representations of the tile.
- **Inputs**: None
- **Control Flow**:
    - The constructor `Tile()` checks if the target function name is `fd_topob_tile`, retrieves the second argument as `name`, and verifies the location is within the specified topology files, excluding the name 'sock'.
    - The method `getJsonRepr()` constructs a JSON representation of the tile with its name and whether it is multi-tile.
    - The method `isMultiTile()` checks if there is a `ForStmt` child of the current instance, returning 'true' if it exists, otherwise 'false'.
    - The method `getMermaidShape()` returns 'processes' if the tile is multi-tile, otherwise 'rect'.
    - The method `getMermaidRepr()` constructs a Mermaid diagram representation of the tile with its name and shape.
- **Output**: The `Tile` class does not directly produce an output but provides methods to generate JSON and Mermaid representations of the tile.


---
### getJsonRepr
The `getJsonRepr` function generates a JSON representation of a `Tile` object, including its name and whether it is a multi-tile.
- **Inputs**: None
- **Control Flow**:
    - The function constructs a JSON string by concatenating the `name` of the `Tile` object and the result of the `isMultiTile` method.
    - The `isMultiTile` method checks if there exists a `ForStmt` that is a child of the current `Tile` object, returning 'true' if it exists and 'false' otherwise.
    - The JSON string is formatted as '{"name": "<name>", "isMultiTile": <isMultiTile>}' and assigned to `result`.
- **Output**: A JSON string representing the `Tile` object, including its name and multi-tile status.


---
### isMultiTile
The `isMultiTile` function determines if a `Tile` object is associated with a multi-tile structure by checking for the existence of a `ForStmt` that has the `Tile` as a child.
- **Inputs**: None
- **Control Flow**:
    - The function checks if there exists a `ForStmt` (a type of loop statement) where the `Tile` object is a child node.
    - If such a `ForStmt` exists, the function returns the string "true".
    - If no such `ForStmt` exists, the function returns the string "false".
- **Output**: The function returns a string, either "true" or "false", indicating whether the `Tile` is part of a multi-tile structure.


---
### getMermaidShape
The `getMermaidShape` function determines the shape type for a tile in a Mermaid diagram based on whether it is a multi-tile.
- **Inputs**: None
- **Control Flow**:
    - The function checks if the tile is a multi-tile by calling `this.isMultiTile()`.
    - If `this.isMultiTile()` returns "true", the function sets the result to "processes".
    - If `this.isMultiTile()` returns "false", the function sets the result to "rect".
- **Output**: The function returns a string, either "processes" or "rect", representing the shape type for a tile in a Mermaid diagram.


---
### getMermaidRepr
The `getMermaidRepr` function generates a Mermaid diagram representation of a tile or link in a network topology.
- **Inputs**: None
- **Control Flow**:
    - The function checks if the current object is a multi-tile using `isMultiTile`.
    - Based on the result of `isMultiTile`, it determines the shape of the tile as either 'processes' or 'rect'.
    - It constructs a string representation in the Mermaid format using the tile's name and shape.
- **Output**: A string representing the Mermaid diagram format for the tile or link.


---
### InLink
The `InLink` class constructor initializes an instance representing an incoming link in a network topology, based on specific function call patterns and location constraints.
- **Inputs**: None
- **Control Flow**:
    - The constructor checks if the function call target has the name 'fd_topob_tile_in' and retrieves the name and in_tile from specific arguments if true, ensuring the location is part of the topology using `inTopology`.
    - Alternatively, it checks if the function call target has the name 'fd_topos_tile_in_net', retrieves the name from a different argument, sets in_tile to 'net', and ensures the location is part of the topology using `inTopology`.
    - The constructor uses logical OR to allow either of the above conditions to initialize the `InLink` instance.
- **Output**: An instance of the `InLink` class with initialized `name` and `in_tile` attributes based on the function call and location constraints.


---
### getName
The `getName` function retrieves the name of an `InLink` or `OutLink` object.
- **Inputs**: None
- **Control Flow**:
    - The function is defined within the `InLink` and `OutLink` classes.
    - For `InLink`, it returns the `name` attribute of the `InLink` object.
    - For `OutLink`, it returns the `name` attribute of the `OutLink` object.
- **Output**: The function returns a string representing the name of the link.


---
### getInTile
The `getInTile` function retrieves the name of the input tile associated with an `InLink` object.
- **Inputs**:
    - `None`: The function does not take any input arguments.
- **Control Flow**:
    - The function accesses the `in_tile` attribute of the `InLink` class instance.
    - It assigns the value of `in_tile` to the variable `result`.
- **Output**: The function returns a string representing the name of the input tile.


---
### OutLink
The `OutLink` class constructor initializes an instance representing an outgoing link in a network topology, based on specific function call targets and arguments.
- **Inputs**: None
- **Control Flow**:
    - The constructor checks if the function call target has the name 'fd_topob_tile_out' and retrieves the name and out_tile from specific arguments if true, ensuring the location is part of the topology.
    - Alternatively, it checks if the function call target has the name 'fd_topos_net_rx_link', retrieves the name from a specific argument, sets out_tile to 'net', and ensures the location is part of the topology.
- **Output**: An instance of the `OutLink` class with initialized `name` and `out_tile` attributes.


---
### getOutTile
The `getOutTile` function retrieves the output tile name associated with an `OutLink` object.
- **Inputs**:
    - `None`: The function does not take any explicit input arguments.
- **Control Flow**:
    - The function is a method of the `OutLink` class.
    - It accesses the `out_tile` attribute of the `OutLink` instance.
    - The function returns the value of the `out_tile` attribute.
- **Output**: The function returns a string representing the name of the output tile associated with the `OutLink` instance.


---
### Link
The `Link` class constructor initializes a `Link` object by matching `OutLink` and `InLink` objects with the same name and setting the `name`, `out_tile`, and `in_tile` properties.
- **Inputs**: None
- **Control Flow**:
    - The constructor checks for the existence of an `OutLink` object `ol` where the `name` and `out_tile` are set from `ol`'s `getName()` and `getOutTile()` methods, respectively.
    - It then checks for the existence of an `InLink` object `il` where the `name` matches `ol`'s name and sets `in_tile` from `il`'s `getInTile()` method.
    - If both `OutLink` and `InLink` objects are found with matching names, the `Link` object is initialized with a string representation combining `name`, `out_tile`, and `in_tile`.
- **Output**: A `Link` object with properties `name`, `out_tile`, and `in_tile` initialized based on matching `OutLink` and `InLink` objects.


---
### truncate
The `truncate` function removes the last two characters from a given string.
- **Inputs**:
    - `str`: A string from which the last two characters will be removed.
- **Control Flow**:
    - The function calculates the length of the input string `str`.
    - It creates a substring of `str` from the beginning up to two characters before the end.
    - The resulting substring is returned as the output.
- **Output**: A string that is the input string `str` with its last two characters removed.


---
### allTiles
The `allTiles` function generates a JSON representation of all `Tile` objects in the system.
- **Inputs**: None
- **Control Flow**:
    - The function uses a `concat` operation to iterate over all `Tile` objects.
    - For each `Tile` object, it calls the `getJsonRepr` method to get its JSON representation.
    - The JSON representations are concatenated into a single string, separated by commas, and ordered in descending order.
    - The resulting string is assigned to `result`.
- **Output**: A string containing the JSON representation of all `Tile` objects, concatenated and ordered.


---
### allLinks
The `allLinks` function generates a JSON representation of all unique links in the topology.
- **Inputs**: None
- **Control Flow**:
    - The function uses a `concat` operation to iterate over all `Link` objects.
    - For each `Link`, it retrieves its JSON representation using `l.getJsonRepr()`.
    - The function ensures uniqueness by using a `unique` operation on the JSON strings.
    - Each unique JSON string is concatenated with a comma and space.
    - The result is a single string containing all unique link JSON representations, separated by commas.
- **Output**: A string containing the JSON representation of all unique links, each formatted as a JSON object and separated by commas.


---
### getJson
The `getJson` function generates a JSON representation of the topology, including tiles and links, by aggregating their individual JSON representations.
- **Inputs**: None
- **Control Flow**:
    - The function calls `allTiles()` to get a concatenated string of JSON representations of all `Tile` objects, each followed by a comma and space.
    - It calls `truncate()` on the result of `allTiles()` to remove the trailing comma and space.
    - The function calls `allLinks()` to get a concatenated string of JSON representations of all `Link` objects, each followed by a comma and space.
    - It calls `truncate()` on the result of `allLinks()` to remove the trailing comma and space.
    - The function constructs a JSON string with two arrays: `tiles` and `links`, using the truncated results from `allTiles()` and `allLinks()`.
- **Output**: A JSON string representing the topology, containing arrays of tiles and links.


---
### allTilesMermaid
The `allTilesMermaid` function generates a Mermaid diagram representation of all tiles in the topology.
- **Inputs**: None
- **Control Flow**:
    - The function uses a `concat` operation to iterate over all `Tile` objects.
    - For each `Tile` object, it calls the `getMermaidRepr` method to get its Mermaid representation.
    - The results are concatenated into a single string, with each tile's representation followed by a newline character.
    - The concatenated string is ordered by the Mermaid representation of each tile in descending order.
- **Output**: A string containing the Mermaid diagram representation of all tiles, with each tile's representation on a new line.


---
### allLinksMermaid
The `allLinksMermaid` function generates a Mermaid diagram representation of all unique links in the topology.
- **Inputs**: None
- **Control Flow**:
    - The function uses the `concat` operation to iterate over all `Link` objects.
    - For each `Link`, it calls `getMermaidRepr()` to get the Mermaid representation of the link.
    - The function ensures uniqueness by using the `unique` operation on the Mermaid representations.
    - It concatenates all unique Mermaid representations of links, each followed by a newline character.
- **Output**: A string containing the Mermaid diagram representation of all unique links, each on a new line.


---
### getMermaid
The `getMermaid` function generates a Mermaid.js flowchart representation of a network topology based on defined tiles and links.
- **Inputs**: None
- **Control Flow**:
    - The function begins by calling `allTilesMermaid()` to get the Mermaid representation of all tiles.
    - It then calls `allLinksMermaid()` to get the Mermaid representation of all links.
    - The function concatenates the string 'flowchart LR\n' with the results from `allTilesMermaid()` and `allLinksMermaid()`.
    - The concatenated string is assigned to the variable `result`.
- **Output**: A string representing the Mermaid.js flowchart of the network topology.



# Purpose
The provided Python script is a code generator that reads a JSON configuration file (`fd_types.json`) and generates C header and source files for data serialization and deserialization. The script is designed to handle complex data structures, including structs, enums, and various container types like vectors, maps, and options. It supports both fixed-size and dynamic-size types, and it can generate code for both local and global data representations.

The script defines several classes to represent different types of data structures, such as `OpaqueType`, `StructType`, and `EnumType`. Each class is responsible for generating the necessary C code to define the data structure, as well as functions for encoding, decoding, and walking through the data. The script also handles special cases like compact encoding and zero-copy deserialization. The generated code includes functions for creating new instances, encoding data to a binary format, decoding data from a binary format, and walking through the data structure for inspection or debugging purposes. The script ensures that all types are properly aligned and that memory footprints are calculated accurately for dynamic types.
# Imports and Dependencies

---
- `json`
- `sys`


# Global Variables

---
### header
- **Type**: `file object`
- **Description**: The `header` variable is a global file object that is opened for writing. It is initialized using the `open` function with the first command-line argument (`sys.argv[1]`) as the file name and "w" as the mode, indicating that the file is opened for writing.
- **Use**: This variable is used to write header information to a file specified by the first command-line argument.


---
### body
- **Type**: `file object`
- **Description**: The `body` variable is a global file object that is opened for writing. It is created by opening a file specified by the second command-line argument (`sys.argv[2]`).
- **Use**: This variable is used to write content to a file, including auto-generated comments and include directives.


---
### reflect
- **Type**: `<class 'io.TextIOWrapper'>`
- **Description**: The `reflect` variable is a global variable that is an instance of `io.TextIOWrapper`, which is a file object in Python. It is opened in write mode ('w') using the third command-line argument (`sys.argv[3]`) as the file path.
- **Use**: This variable is used to write output to a file specified by the third command-line argument.


---
### namespace
- **Type**: `str`
- **Description**: The `namespace` variable is a string extracted from the JSON object loaded from the file `fd_types.json`. It represents a specific key within this JSON structure.
- **Use**: This variable is used to store the value associated with the 'namespace' key from the JSON data, which is likely used throughout the code to prefix or identify certain elements or types.


---
### entries
- **Type**: `list`
- **Description**: The `entries` variable is a list extracted from a JSON object loaded from a file named 'fd_types.json'. It contains the data under the key 'entries' from this JSON object.
- **Use**: This variable is used to store and access the list of entries defined in the 'fd_types.json' file for further processing in the script.


---
### preambletypes
- **Type**: `set`
- **Description**: The `preambletypes` variable is a global set initialized as an empty set. It is intended to store unique elements, likely related to types or identifiers used in the preamble of generated code.
- **Use**: This variable is used to keep track of types or identifiers that have been processed or included in the preamble section of the generated code, ensuring they are only added once.


---
### postambletypes
- **Type**: `set`
- **Description**: The `postambletypes` variable is a global set initialized as an empty set. It is intended to store unique elements, likely related to types or categories that are processed or generated in the code.
- **Use**: This variable is used to keep track of types that have been processed or need to be processed in the postamble section of the code.


---
### simpletypes
- **Type**: `dict`
- **Description**: The `simpletypes` variable is a dictionary that maps primitive type names to their corresponding bincode function names. It is initialized with a series of key-value pairs where the key is a primitive type (e.g., 'char', 'uchar') and the value is the corresponding bincode function name (e.g., 'int8', 'uint8').
- **Use**: This variable is used to map primitive types to their bincode function names for encoding and decoding operations.


---
### fixedsizetypes
- **Type**: `dict`
- **Description**: The `fixedsizetypes` variable is a dictionary that maps type names to their corresponding encoded sizes. It includes various primitive types and custom types, each associated with a specific size in bytes.
- **Use**: This variable is used to determine the encoded size of different types for serialization and deserialization processes.


---
### flattypes
- **Type**: `set`
- **Description**: The `flattypes` variable is a set containing various data types, including primitive types like `bool`, `int`, `double`, and custom types like `flamenco_txn`. It also includes array types such as `uchar[32]` and `uchar[2048]`. This set is used to identify types that do not contain nested local pointers, making them suitable for certain operations that require flat data structures.
- **Use**: This variable is used to categorize types that are flat, meaning they do not contain nested pointers, which is useful for serialization and memory management tasks.


---
### fuzzytypes
- **Type**: `set`
- **Description**: The `fuzzytypes` variable is a set containing a collection of type names, primarily representing various primitive and custom data types such as integers, unsigned integers, and custom types like `pubkey` and `signature`. These types are considered 'fuzzy', meaning they are fixed size and valid for all possible bit patterns.
- **Use**: This variable is used to identify types that are fixed size and can be safely used in operations that require such properties.


---
### memberTypeMap
- **Type**: `dict`
- **Description**: The `memberTypeMap` is a dictionary that maps string keys representing different data structure types to their corresponding class implementations. Each key in the dictionary corresponds to a specific type of member, such as 'static_vector', 'vector', 'string', etc., and the value is a class that handles the operations for that type.
- **Use**: This variable is used to dynamically select and instantiate the appropriate class for a given member type based on its string identifier.


---
### type\_map
- **Type**: `dict`
- **Description**: The `type_map` variable is a global dictionary initialized as an empty dictionary. It is intended to store mappings from type names to their corresponding type information or objects.
- **Use**: This variable is used to store and retrieve type information based on type names, facilitating type management and lookup in the program.


# Classes

---
### TypeNode<!-- {{#class:firedancer/src/flamenco/types/gen_stubs.TypeNode}} -->
- **Members**:
    - `produce_global`: Indicates whether the type should be produced globally.
    - `name`: Stores the name of the type node.
    - `encoders`: Holds encoder information, initially set to None.
- **Description**: The `TypeNode` class is a foundational structure used to represent a type node in a type system, initialized with JSON data or keyword arguments. It manages the name and global production status of the type, and provides methods to determine characteristics like fixed size, fuzziness, and flatness. The class also includes methods for handling subtypes and members, and for emitting offsets and joining types.
- **Methods**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.__init__`](#TypeNode__init__)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.isFixedSize`](#TypeNodeisFixedSize)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.fixedSize`](#TypeNodefixedSize)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.isFuzzy`](#TypeNodeisFuzzy)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.isFlat`](#TypeNodeisFlat)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.emitOffsetJoin`](#TypeNodeemitOffsetJoin)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.subTypes`](#TypeNodesubTypes)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.subMembers`](#TypeNodesubMembers)

**Methods**

---
#### TypeNode\.\_\_init\_\_<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.TypeNode.__init__}} -->
The `__init__` method initializes a `TypeNode` object with attributes based on a JSON input or keyword arguments.
- **Inputs**:
    - `json`: A dictionary containing initialization data, specifically a 'name' key and optionally a 'global' key.
    - `kwargs`: Additional keyword arguments that can include a 'name' key if 'json' is None.
- **Control Flow**:
    - Initialize 'produce_global' to False.
    - Check if 'json' is not None; if true, set 'name' from 'json' and 'produce_global' from 'json' if 'global' key exists.
    - If 'json' is None, check if 'name' is in 'kwargs'; if true, set 'name' from 'kwargs'.
    - If neither 'json' nor 'name' in 'kwargs' is provided, raise a ValueError.
    - Initialize 'encoders' to None.
- **Output**: The method does not return a value; it initializes the object's attributes.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.TypeNode`](#TypeNode)  (Base Class)


---
#### TypeNode\.isFixedSize<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.TypeNode.isFixedSize}} -->
The `isFixedSize` method in the `TypeNode` class always returns `False`, indicating that instances of `TypeNode` are not of fixed size.
- **Inputs**: None
- **Control Flow**:
    - The method contains a single return statement.
    - The method returns the boolean value `False`.
- **Output**: The method returns a boolean value `False`, indicating that the object is not of fixed size.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.TypeNode`](#TypeNode)  (Base Class)


---
#### TypeNode\.fixedSize<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.TypeNode.fixedSize}} -->
The `fixedSize` method in the `TypeNode` class is a placeholder method that does not perform any operations or return any value.
- **Inputs**: None
- **Control Flow**:
    - The method is defined but contains no implementation, meaning it does not execute any code or logic.
- **Output**: The method does not return any value or output.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.TypeNode`](#TypeNode)  (Base Class)


---
#### TypeNode\.isFuzzy<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.TypeNode.isFuzzy}} -->
The `isFuzzy` method in the `TypeNode` class always returns `False`, indicating that the type is not considered 'fuzzy'.
- **Inputs**: None
- **Control Flow**:
    - The method simply returns the boolean value `False`.
- **Output**: The method outputs a boolean value `False`, indicating the type is not fuzzy.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.TypeNode`](#TypeNode)  (Base Class)


---
#### TypeNode\.isFlat<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.TypeNode.isFlat}} -->
The `isFlat` method in the `TypeNode` class always returns `False`, indicating that the type is not flat.
- **Inputs**: None
- **Control Flow**:
    - The method contains a single return statement that returns `False`.
- **Output**: The method returns a boolean value `False`.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.TypeNode`](#TypeNode)  (Base Class)


---
#### TypeNode\.emitOffsetJoin<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.TypeNode.emitOffsetJoin}} -->
The `emitOffsetJoin` method is a placeholder method in the `TypeNode` class intended to handle offset joining for a given type name.
- **Inputs**:
    - `type_name`: A string representing the name of the type for which offset joining is to be handled.
- **Control Flow**:
    - The method is defined but not implemented, indicating it is likely intended to be overridden or implemented in a subclass or later in the development process.
- **Output**: The method does not return any value as it is currently not implemented.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.TypeNode`](#TypeNode)  (Base Class)


---
#### TypeNode\.subTypes<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.TypeNode.subTypes}} -->
The `subTypes` method returns an empty iterator, indicating that the current `TypeNode` instance has no subtypes.
- **Inputs**: None
- **Control Flow**:
    - The method directly returns an iterator over an empty tuple, which is equivalent to an empty iterator.
- **Output**: An iterator over an empty tuple, effectively an empty iterator.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.TypeNode`](#TypeNode)  (Base Class)


---
#### TypeNode\.subMembers<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.TypeNode.subMembers}} -->
The `subMembers` method returns an iterator over an empty tuple, indicating no sub-members for the `PrimitiveMember` class.
- **Inputs**: None
- **Control Flow**:
    - The method directly returns an iterator created from an empty tuple.
- **Output**: An iterator over an empty tuple, effectively representing no sub-members.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.TypeNode`](#TypeNode)  (Base Class)



---
### PrimitiveMember<!-- {{#class:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember}} -->
- **Members**:
    - `type`: Stores the type of the primitive member as specified in the JSON.
    - `varint`: Indicates if the member uses a varint modifier based on the JSON.
    - `decode`: Determines if the member should be decoded, defaulting to true if not specified in the JSON.
    - `encode`: Determines if the member should be encoded, defaulting to true if not specified in the JSON.
    - `walk`: Determines if the member should be walked, defaulting to true if not specified in the JSON.
    - `emitMemberMap`: A class variable mapping types to their corresponding C code emission functions.
    - `emitDecodeFootprintMap`: A class variable mapping types to their corresponding decode footprint functions.
    - `emitDecodeMap`: A class variable mapping types to their corresponding decode functions.
    - `emitEncodeMap`: A class variable mapping types to their corresponding encode functions.
    - `emitSizeMap`: A class variable mapping types to their corresponding size calculation functions.
    - `emitWalkMap`: A class variable mapping types to their corresponding walk functions.
- **Description**: The PrimitiveMember class is a specialized type of TypeNode that represents a primitive member within a data structure, initialized with a container and JSON data. It manages various attributes such as type, varint, decode, encode, and walk, which are determined based on the provided JSON. The class includes several class variables that map different types to their respective functions for emitting C code, decoding, encoding, calculating size, and walking through the data structure. These mappings facilitate the generation of C code for handling different primitive types in a structured manner.
- **Methods**:
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.__init__`](#PrimitiveMember__init__)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitPreamble`](#PrimitiveMemberemitPreamble)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitPostamble`](#PrimitiveMemberemitPostamble)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitNew`](#PrimitiveMemberemitNew)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.isFlat`](#PrimitiveMemberisFlat)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitMember`](#PrimitiveMemberemitMember)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitMemberGlobal`](#PrimitiveMemberemitMemberGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.isFixedSize`](#PrimitiveMemberisFixedSize)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.fixedSize`](#PrimitiveMemberfixedSize)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.isFuzzy`](#PrimitiveMemberisFuzzy)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.string_decode_footprint`](#PrimitiveMemberstring_decode_footprint)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.ushort_decode_footprint`](#PrimitiveMemberushort_decode_footprint)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.ulong_decode_footprint`](#PrimitiveMemberulong_decode_footprint)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.string_decode_footprint`](#PrimitiveMemberstring_decode_footprint)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitDecodeFootprint`](#PrimitiveMemberemitDecodeFootprint)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.string_decode_unsafe`](#PrimitiveMemberstring_decode_unsafe)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.ushort_decode_unsafe`](#PrimitiveMemberushort_decode_unsafe)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.ulong_decode_unsafe`](#PrimitiveMemberulong_decode_unsafe)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitDecodeInner`](#PrimitiveMemberemitDecodeInner)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitDecodeInnerGlobal`](#PrimitiveMemberemitDecodeInnerGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.string_encode`](#PrimitiveMemberstring_encode)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.ushort_encode`](#PrimitiveMemberushort_encode)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.ulong_encode`](#PrimitiveMemberulong_encode)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitEncode`](#PrimitiveMemberemitEncode)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitEncodeGlobal`](#PrimitiveMemberemitEncodeGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitSize`](#PrimitiveMemberemitSize)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitWalk`](#PrimitiveMemberemitWalk)
- **Inherits From**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode`](#TypeNode)

**Methods**

---
#### PrimitiveMember\.\_\_init\_\_<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.__init__}} -->
The [`__init__`](#TypeNode__init__) method initializes an instance of the `PrimitiveMember` class by setting its attributes based on a provided JSON configuration.
- **Inputs**:
    - `container`: An object or structure that contains or is associated with this `PrimitiveMember` instance.
    - `json`: A dictionary containing configuration data for initializing the `PrimitiveMember` instance, including keys like 'type', 'modifier', 'decode', 'encode', and 'walk'.
- **Control Flow**:
    - The method begins by calling the superclass's [`__init__`](#TypeNode__init__) method with the `json` argument to initialize inherited attributes.
    - It sets the `type` attribute of the instance to the value associated with the 'type' key in the `json` dictionary.
    - The `varint` attribute is set to `True` if the 'modifier' key in `json` is present and its value is 'varint'; otherwise, it is set to `False`.
    - The `decode` attribute is set to `True` if the 'decode' key is not present in `json` or if it is present and its value is `True`; otherwise, it is set to `False`.
    - The `encode` attribute is set similarly to `decode`, based on the presence and value of the 'encode' key in `json`.
    - The `walk` attribute is set similarly to `decode`, based on the presence and value of the 'walk' key in `json`.
- **Output**: The method does not return any value; it initializes the instance attributes.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.__init__`](#TypeNode__init__)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember`](#PrimitiveMember)  (Base Class)


---
#### PrimitiveMember\.emitPreamble<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitPreamble}} -->
The `emitPreamble` method is a placeholder method in the `PrimitiveMember` class that currently does nothing.
- **Inputs**: None
- **Control Flow**:
    - The method is defined but contains no implementation, indicated by the `pass` statement.
- **Output**: There is no output as the method does nothing.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember`](#PrimitiveMember)  (Base Class)


---
#### PrimitiveMember\.emitPostamble<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitPostamble}} -->
The `emitPostamble` method is a placeholder method in the `PrimitiveMember` class that currently does nothing.
- **Inputs**: None
- **Control Flow**:
    - The method is defined but contains no implementation, indicated by the `pass` statement.
- **Output**: There is no output as the method does nothing.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember`](#PrimitiveMember)  (Base Class)


---
#### PrimitiveMember\.emitNew<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitNew}} -->
The `emitNew` method is a placeholder method in the `PrimitiveMember` class intended for emitting new instances of a member with a specified indentation.
- **Inputs**:
    - `indent`: A string representing the indentation to be used when emitting new instances, defaulting to an empty string.
- **Control Flow**:
    - The method is defined but not implemented, indicating it is a placeholder for future functionality.
- **Output**: The method does not return any value or output as it is currently a placeholder.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember`](#PrimitiveMember)  (Base Class)


---
#### PrimitiveMember\.isFlat<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.isFlat}} -->
The `isFlat` method checks if the type of a `PrimitiveMember` instance is not a C-style string pointer (`char*`).
- **Inputs**: None
- **Control Flow**:
    - The method accesses the `type` attribute of the `PrimitiveMember` instance.
    - It compares the `type` attribute to the string `char*`.
    - The method returns `True` if the `type` is not `char*`, otherwise it returns `False`.
- **Output**: A boolean value indicating whether the type is not `char*`.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember`](#PrimitiveMember)  (Base Class)


---
#### PrimitiveMember\.emitMember<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitMember}} -->
The `emitMember` method generates C code to declare a member variable of a specific type in a header file based on the `type` and `name` attributes of the `PrimitiveMember` instance.
- **Inputs**: None
- **Control Flow**:
    - The method accesses the `emitMemberMap` dictionary using the `type` attribute of the `PrimitiveMember` instance to retrieve a lambda function.
    - The lambda function is called with the `name` attribute of the `PrimitiveMember` instance as an argument.
    - The lambda function prints a C declaration for the member variable to the `header` file.
- **Output**: The method does not return any value; it outputs C code to a file.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember`](#PrimitiveMember)  (Base Class)


---
#### PrimitiveMember\.emitMemberGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitMemberGlobal}} -->
The `emitMemberGlobal` method generates code to declare a global member variable based on the type of the `PrimitiveMember` instance.
- **Inputs**:
    - `self`: An instance of the `PrimitiveMember` class, which contains attributes like `type` and `name` that define the member's characteristics.
- **Control Flow**:
    - The method accesses the `emitMemberMap` dictionary using the `type` attribute of the `PrimitiveMember` instance.
    - It retrieves a lambda function from the dictionary that corresponds to the member's type.
    - The lambda function is called with the `name` attribute of the `PrimitiveMember` instance, which generates the appropriate code for declaring the member variable in a global context.
- **Output**: The method outputs code to declare a global member variable, which is written to the `header` file.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember`](#PrimitiveMember)  (Base Class)


---
#### PrimitiveMember\.isFixedSize<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.isFixedSize}} -->
The `isFixedSize` method determines if a `PrimitiveMember` instance has a fixed size based on its attributes.
- **Inputs**: None
- **Control Flow**:
    - Check if the `varint` attribute is `True`; if so, return `False`.
    - Check if the `encode` and `decode` attributes are not equal; if so, return `False`.
    - Check if the `type` attribute is in the `fixedsizetypes` dictionary; if so, return `True`.
    - If none of the above conditions are met, return `False`.
- **Output**: A boolean value indicating whether the `PrimitiveMember` instance is of fixed size.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember`](#PrimitiveMember)  (Base Class)


---
#### PrimitiveMember\.fixedSize<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.fixedSize}} -->
The `fixedSize` method returns the fixed size of a primitive member type if encoding is enabled, otherwise it returns 0.
- **Inputs**:
    - `self`: An instance of the PrimitiveMember class, which contains attributes like type, encode, and others.
- **Control Flow**:
    - Check if the 'encode' attribute of the instance is False.
    - If 'encode' is False, return 0.
    - If 'encode' is True, return the fixed size of the type from the 'fixedsizetypes' dictionary using the instance's 'type' attribute.
- **Output**: An integer representing the fixed size of the type if encoding is enabled, or 0 if encoding is not enabled.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember`](#PrimitiveMember)  (Base Class)


---
#### PrimitiveMember\.isFuzzy<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.isFuzzy}} -->
The `isFuzzy` method determines if a `PrimitiveMember` instance is considered 'fuzzy' based on its type and modifier.
- **Inputs**:
    - `self`: An instance of the `PrimitiveMember` class, which contains attributes like `type` and `varint`.
- **Control Flow**:
    - Check if the `varint` attribute of the instance is `True`.
    - If `varint` is `True`, return `False`.
    - If `varint` is `False`, check if the `type` attribute is in the `fuzzytypes` set.
    - Return `True` if the `type` is in `fuzzytypes`, otherwise return `False`.
- **Output**: A boolean value indicating whether the instance is 'fuzzy' or not.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember`](#PrimitiveMember)  (Base Class)


---
#### PrimitiveMember\.string\_decode\_footprint<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.string_decode_footprint}} -->
The `string_decode_footprint` method generates C code to decode a string's footprint, handling potential errors during the decoding process.
- **Inputs**:
    - `n`: An identifier or name for the string being decoded.
    - `varint`: A boolean indicating whether the string length is encoded as a variable-length integer.
    - `indent`: A string used for indentation in the generated C code.
- **Control Flow**:
    - Prints a declaration for a `ulong` variable `slen` to the output file `body` with the specified indentation.
    - Prints a line of C code to decode a `uint64` value into `slen` using `fd_bincode_uint64_decode`, checking for errors.
    - If an error occurs during the `uint64` decoding, it returns the error code.
    - Prints a line of C code to decode the footprint of a byte array of length `slen` using `fd_bincode_bytes_decode_footprint`, checking for errors.
    - If an error occurs during the byte array footprint decoding, it returns the error code.
    - Prints a line to add `slen + 1` to `*total_sz` to account for the null termination of the string.
- **Output**: The function does not return a value; it writes C code to the `body` file to handle string footprint decoding.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember`](#PrimitiveMember)  (Base Class)


---
#### PrimitiveMember\.ushort\_decode\_footprint<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.ushort_decode_footprint}} -->
The `ushort_decode_footprint` function generates C code to decode a 16-bit unsigned integer, either in a compact or standard format, and checks for decoding errors.
- **Inputs**:
    - `n`: An identifier for the variable being decoded, though not directly used in the function.
    - `varint`: A boolean indicating whether the decoding should use a compact varint format.
    - `indent`: A string used to indent the generated C code for readability.
- **Control Flow**:
    - Check if `varint` is true to determine the decoding method.
    - If `varint` is true, generate code to decode using `fd_bincode_compact_u16_decode` in a do-while loop.
    - If `varint` is false, generate code to decode using `fd_bincode_uint16_decode_footprint`.
    - Generate code to check if the decoding was successful and return an error if not.
- **Output**: The function outputs C code to the `body` file stream, which includes the decoding logic and error checking.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember`](#PrimitiveMember)  (Base Class)


---
#### PrimitiveMember\.ulong\_decode\_footprint<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.ulong_decode_footprint}} -->
The `ulong_decode_footprint` method generates code to decode a footprint for a ulong type, handling both varint and non-varint cases.
- **Inputs**:
    - `n`: An identifier or name used in the generated code, though not directly used in the function body.
    - `varint`: A boolean indicating whether the decoding should use varint decoding or not.
    - `indent`: A string representing the indentation level for the generated code.
- **Control Flow**:
    - Check if `varint` is True.
    - If `varint` is True, generate code to decode a varint footprint using `fd_bincode_varint_decode_footprint` and print it with the specified indentation.
    - If `varint` is False, generate code to decode a uint64 footprint using `fd_bincode_uint64_decode_footprint` and print it with the specified indentation.
    - Generate code to check if the decoding was successful and return an error if not, printing it with the specified indentation.
- **Output**: The function outputs generated code lines to a file or stream, specifically to the `body` file object, which is assumed to be defined in the surrounding context.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember`](#PrimitiveMember)  (Base Class)


---
#### PrimitiveMember\.string\_decode\_footprint<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.string_decode_footprint}} -->
The `string_decode_footprint` method decodes a string's length and footprint from a binary context, updating the total size with the string length plus an extra byte for null termination.
- **Inputs**:
    - `n`: An identifier or name for the string being decoded.
    - `varint`: A boolean indicating whether the string length is encoded as a variable-length integer.
    - `indent`: A string used for indentation in the generated code output.
- **Control Flow**:
    - Declare a variable `slen` of type `ulong` to store the string length.
    - Decode the string length using `fd_bincode_uint64_decode` and store the result in `slen`.
    - Check if the decoding was successful; if not, return the error code.
    - Decode the footprint of the string using `fd_bincode_bytes_decode_footprint` with the decoded length `slen`.
    - Check if the footprint decoding was successful; if not, return the error code.
    - Update the total size by adding `slen + 1` to account for the string length and an extra byte for null termination.
- **Output**: The function outputs C code to a file, updating the total size variable with the string's length and an extra byte for null termination.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember`](#PrimitiveMember)  (Base Class)


---
#### PrimitiveMember\.emitDecodeFootprint<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitDecodeFootprint}} -->
The `emitDecodeFootprint` method generates code to calculate the memory footprint required for decoding a specific primitive type if decoding is enabled.
- **Inputs**:
    - `indent`: A string representing the indentation to be used in the generated code, defaulting to an empty string.
- **Control Flow**:
    - Check if the `decode` attribute of the instance is `True`.
    - If `decode` is `True`, use the `emitDecodeFootprintMap` dictionary to call the appropriate function for the instance's type, passing `self.name`, `self.varint`, and `indent` as arguments.
- **Output**: The method does not return any value; it outputs code to a file or stream specified in the context.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember`](#PrimitiveMember)  (Base Class)


---
#### PrimitiveMember\.string\_decode\_unsafe<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.string_decode_unsafe}} -->
The `string_decode_unsafe` function decodes a string from a binary format without safety checks, updating memory allocation pointers accordingly.
- **Inputs**:
    - `n`: The name of the string variable to decode.
    - `varint`: A boolean indicating if the decoding should consider variable-length integers.
    - `indent`: A string used for indentation in the generated code.
- **Control Flow**:
    - Declare a variable `slen` of type `ulong` to hold the string length.
    - Call `fd_bincode_uint64_decode_unsafe` to decode the length of the string into `slen`.
    - Assign the current memory allocation pointer to `self->{n}`.
    - Call `fd_bincode_bytes_decode_unsafe` to decode the string bytes into `self->{n}` using the decoded length `slen`.
    - Set the character at `self->{n}[slen]` to '\0' to null-terminate the string.
    - Update the memory allocation pointer `*alloc_mem` to account for the decoded string and its null terminator.
- **Output**: The function does not return a value; it modifies the memory allocation pointer and the string variable in place.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember`](#PrimitiveMember)  (Base Class)


---
#### PrimitiveMember\.ushort\_decode\_unsafe<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.ushort_decode_unsafe}} -->
The `ushort_decode_unsafe` method generates C code to decode a 16-bit unsigned short integer from a binary context, using either a compact or standard decoding function based on the `varint` flag.
- **Inputs**:
    - `n`: The name of the variable to be decoded, used in the generated C code.
    - `varint`: A boolean flag indicating whether to use compact varint decoding or standard decoding.
    - `indent`: A string representing the indentation level for the generated C code.
- **Control Flow**:
    - Check if `varint` is true.
    - If `varint` is true, generate C code using `fd_bincode_compact_u16_decode_unsafe` for compact decoding.
    - If `varint` is false, generate C code using `fd_bincode_uint16_decode_unsafe` for standard decoding.
    - Print the generated C code to the `body` file with the specified indentation.
- **Output**: The function outputs C code to the `body` file, which decodes a 16-bit unsigned short integer from a binary context.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember`](#PrimitiveMember)  (Base Class)


---
#### PrimitiveMember\.ulong\_decode\_unsafe<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.ulong_decode_unsafe}} -->
The `ulong_decode_unsafe` function generates C code to decode a ulong value from a context, using either a varint or a fixed uint64 decoding method, and writes it to a specified output stream.
- **Inputs**:
    - `n`: The name of the variable to be decoded, used in the generated C code.
    - `varint`: A boolean indicating whether to use varint decoding (if true) or fixed uint64 decoding (if false).
    - `indent`: A string representing the indentation level for the generated C code.
- **Control Flow**:
    - Check if `varint` is true.
    - If true, generate C code for varint decoding using `fd_bincode_varint_decode_unsafe` and write it to the output stream `body`.
    - If false, generate C code for fixed uint64 decoding using `fd_bincode_uint64_decode_unsafe` and write it to the output stream `body`.
- **Output**: The function does not return a value; it writes generated C code to the output stream `body`.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember`](#PrimitiveMember)  (Base Class)


---
#### PrimitiveMember\.emitDecodeInner<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitDecodeInner}} -->
The `emitDecodeInner` method decodes a specific type of data for a `PrimitiveMember` object if decoding is enabled.
- **Inputs**:
    - `indent`: A string used for indentation in the generated code, defaulting to an empty string.
- **Control Flow**:
    - Check if the `decode` attribute of the `PrimitiveMember` instance is `True`.
    - If `decode` is `True`, use the `emitDecodeMap` dictionary to find the appropriate decoding function for the member's type.
    - Call the decoding function with the member's name, `varint` status, and the provided `indent` string.
- **Output**: The method does not return any value; it performs an action by printing the decoding logic to a file.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember`](#PrimitiveMember)  (Base Class)


---
#### PrimitiveMember\.emitDecodeInnerGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitDecodeInnerGlobal}} -->
The `emitDecodeInnerGlobal` method decodes a member variable of a `PrimitiveMember` object using a type-specific decoding function if decoding is enabled.
- **Inputs**:
    - `indent`: A string representing the indentation to be used in the generated code, defaulting to an empty string.
- **Control Flow**:
    - Check if the `decode` attribute of the `PrimitiveMember` instance is `True`.
    - If `decode` is `True`, use the `emitDecodeMap` dictionary to find the appropriate decoding function for the member's type.
    - Call the decoding function with the member's name, `varint` status, and the provided `indent` string.
- **Output**: The method does not return any value; it performs an action by invoking a decoding function.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember`](#PrimitiveMember)  (Base Class)


---
#### PrimitiveMember\.string\_encode<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.string_encode}} -->
The `string_encode` function encodes a string by first determining its length and then encoding both the length and the string's bytes into a given context.
- **Inputs**:
    - `n`: The name of the string member in the object to be encoded.
    - `varint`: A boolean indicating whether the encoding should use variable-length integers (not used in this function).
    - `indent`: A string used for indentation in the generated code output.
- **Control Flow**:
    - Calculate the length of the string `self->{n}` and store it in `slen`.
    - Encode the length `slen` using `fd_bincode_uint64_encode` and store the result in `err`.
    - Check if `err` indicates an error; if so, return `err`.
    - Encode the string bytes using `fd_bincode_bytes_encode` and store the result in `err`.
    - Check if `err` indicates an error; if so, return `err`.
- **Output**: The function outputs C code to a file, which encodes the length and bytes of a string into a context, and returns an error code if any encoding step fails.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember`](#PrimitiveMember)  (Base Class)


---
#### PrimitiveMember\.ushort\_encode<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.ushort_encode}} -->
The `ushort_encode` function encodes a 16-bit unsigned short integer using either a compact or standard encoding method based on the `varint` flag.
- **Inputs**:
    - `n`: The name of the variable to be encoded, which is a member of the `self` object.
    - `varint`: A boolean flag indicating whether to use compact encoding (`True`) or standard encoding (`False`).
    - `indent`: A string used for indentation in the generated code output.
- **Control Flow**:
    - Check if `varint` is `True` to determine the encoding method.
    - If `varint` is `True`, use `fd_bincode_compact_u16_encode` for compact encoding.
    - If `varint` is `False`, use `fd_bincode_uint16_encode` for standard encoding.
    - Print the encoding operation to the `body` file with the specified `indent`.
    - Check for errors using `FD_UNLIKELY` macro and return the error if any.
- **Output**: The function outputs C code lines to a file, which encode a 16-bit unsigned short integer and handle potential errors.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember`](#PrimitiveMember)  (Base Class)


---
#### PrimitiveMember\.ulong\_encode<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.ulong_encode}} -->
The `ulong_encode` function encodes a ulong value using either a varint or a uint64 encoding method based on the `varint` flag and checks for errors during the encoding process.
- **Inputs**:
    - `n`: The name of the ulong variable to be encoded.
    - `varint`: A boolean flag indicating whether to use varint encoding (True) or uint64 encoding (False).
    - `indent`: A string used for indentation in the generated code output.
- **Control Flow**:
    - Check if `varint` is True; if so, encode the ulong variable using `fd_bincode_varint_encode` and print the corresponding code line with indentation.
    - If `varint` is False, encode the ulong variable using `fd_bincode_uint64_encode` and print the corresponding code line with indentation.
    - Print a line of code that checks if the encoding resulted in an error using `FD_UNLIKELY` and returns the error if it occurred.
- **Output**: The function outputs lines of code to the `body` file, which include the encoding operation and error checking logic.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember`](#PrimitiveMember)  (Base Class)


---
#### PrimitiveMember\.emitEncode<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitEncode}} -->
The `emitEncode` method generates encoding logic for a primitive member based on its type and encoding settings.
- **Inputs**:
    - `indent`: A string representing the indentation to be used in the generated code, defaulting to an empty string.
- **Control Flow**:
    - Check if the `encode` attribute of the instance is True.
    - If True, use the `emitEncodeMap` dictionary to find the appropriate encoding function for the member's type.
    - Call the encoding function with the member's name, varint status, and the provided indent.
- **Output**: The method does not return a value; it outputs encoding logic to a file or stream.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember`](#PrimitiveMember)  (Base Class)


---
#### PrimitiveMember\.emitEncodeGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitEncodeGlobal}} -->
The `emitEncodeGlobal` method encodes a global representation of a primitive member if encoding is enabled.
- **Inputs**:
    - `indent`: A string representing the indentation to be used in the generated code, defaulting to an empty string.
- **Control Flow**:
    - Check if the `encode` attribute of the instance is `True`.
    - If `encode` is `True`, call the encoding function from `PrimitiveMember.emitEncodeMap` using the instance's `type`, `name`, `varint`, and `indent` as arguments.
- **Output**: The method does not return any value; it outputs encoded data to a file or stream specified in the encoding function.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember`](#PrimitiveMember)  (Base Class)


---
#### PrimitiveMember\.emitSize<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitSize}} -->
The `emitSize` method calculates and outputs the size of a primitive member based on its type and encoding settings.
- **Inputs**:
    - `inner`: A string representing the inner structure or prefix to be used in the size calculation.
    - `indent`: A string used for indentation in the output, defaulting to an empty string.
- **Control Flow**:
    - Check if the `encode` attribute of the instance is True.
    - If True, use the `emitSizeMap` dictionary to find the appropriate lambda function for the member's type.
    - Invoke the lambda function with the member's name, `varint` status, `inner`, and `indent` as arguments.
- **Output**: The method does not return a value; it outputs the size calculation to a file or stream specified in the lambda function.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember`](#PrimitiveMember)  (Base Class)


---
#### PrimitiveMember\.emitWalk<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitWalk}} -->
The `emitWalk` method triggers a specific walk function for a member based on its type if the `walk` attribute is enabled.
- **Inputs**:
    - `inner`: A string representing the inner context or prefix to be used in the walk function.
    - `indent`: An optional string for indentation, defaulting to an empty string, used for formatting purposes.
- **Control Flow**:
    - Check if the `walk` attribute of the instance is True.
    - If True, call the appropriate function from `emitWalkMap` using the instance's `type` as the key, passing `name` and `inner` as arguments.
- **Output**: The method does not return any value; it performs an action based on the instance's type and walk attribute.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember`](#PrimitiveMember)  (Base Class)



---
### StructMember<!-- {{#class:firedancer/src/flamenco/types/gen_stubs.StructMember}} -->
- **Members**:
    - `type`: Holds the type of the struct member as specified in the JSON input.
    - `ignore_underflow`: Indicates whether underflow should be ignored, defaulting to False if not specified in the JSON input.
- **Description**: The `StructMember` class represents a member of a struct, inheriting from `TypeNode`. It is initialized with a container and a JSON object, extracting the type and an optional flag to ignore underflow. The class provides methods to emit various code segments for handling the struct member, such as preamble, postamble, member declaration, and encoding/decoding operations. It also includes checks for whether the member is flat, fixed size, or fuzzy, based on predefined type sets.
- **Methods**:
    - [`firedancer/src/flamenco/types/gen_stubs.StructMember.__init__`](#StructMember__init__)
    - [`firedancer/src/flamenco/types/gen_stubs.StructMember.isFlat`](#StructMemberisFlat)
    - [`firedancer/src/flamenco/types/gen_stubs.StructMember.emitPreamble`](#StructMemberemitPreamble)
    - [`firedancer/src/flamenco/types/gen_stubs.StructMember.emitPostamble`](#StructMemberemitPostamble)
    - [`firedancer/src/flamenco/types/gen_stubs.StructMember.emitMember`](#StructMemberemitMember)
    - [`firedancer/src/flamenco/types/gen_stubs.StructMember.emitMemberGlobal`](#StructMemberemitMemberGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.StructMember.isFixedSize`](#StructMemberisFixedSize)
    - [`firedancer/src/flamenco/types/gen_stubs.StructMember.fixedSize`](#StructMemberfixedSize)
    - [`firedancer/src/flamenco/types/gen_stubs.StructMember.isFuzzy`](#StructMemberisFuzzy)
    - [`firedancer/src/flamenco/types/gen_stubs.StructMember.emitNew`](#StructMemberemitNew)
    - [`firedancer/src/flamenco/types/gen_stubs.StructMember.emitDecodeFootprint`](#StructMemberemitDecodeFootprint)
    - [`firedancer/src/flamenco/types/gen_stubs.StructMember.emitDecodeInner`](#StructMemberemitDecodeInner)
    - [`firedancer/src/flamenco/types/gen_stubs.StructMember.emitDecodeInnerGlobal`](#StructMemberemitDecodeInnerGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.StructMember.emitEncode`](#StructMemberemitEncode)
    - [`firedancer/src/flamenco/types/gen_stubs.StructMember.emitEncodeGlobal`](#StructMemberemitEncodeGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.StructMember.emitSize`](#StructMemberemitSize)
    - [`firedancer/src/flamenco/types/gen_stubs.StructMember.emitWalk`](#StructMemberemitWalk)
- **Inherits From**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode`](#TypeNode)

**Methods**

---
#### StructMember\.\_\_init\_\_<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructMember.__init__}} -->
The [`__init__`](#TypeNode__init__) method initializes a `StructMember` instance with a container and JSON data, setting its type and ignore_underflow attributes.
- **Inputs**:
    - `container`: The container in which the `StructMember` is being initialized.
    - `json`: A dictionary containing initialization data, including the type and optionally the ignore_underflow flag.
- **Control Flow**:
    - Call the parent class's [`__init__`](#TypeNode__init__) method with the JSON data.
    - Set the `type` attribute of the instance to the value associated with the 'type' key in the JSON data.
    - Set the `ignore_underflow` attribute to the boolean value of the 'ignore_underflow' key in the JSON data if it exists, otherwise set it to False.
- **Output**: There is no return value; the method initializes the instance attributes.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.__init__`](#TypeNode__init__)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructMember`](#StructMember)  (Base Class)


---
#### StructMember\.isFlat<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructMember.isFlat}} -->
The `isFlat` method checks if the `type` attribute of a `StructMember` instance is in the predefined set of `flattypes`.
- **Inputs**: None
- **Control Flow**:
    - The method accesses the `type` attribute of the instance.
    - It checks if this `type` is present in the `flattypes` set.
    - The method returns `True` if the `type` is in `flattypes`, otherwise it returns `False`.
- **Output**: A boolean value indicating whether the `type` of the `StructMember` is considered flat (i.e., it does not contain nested local pointers).
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructMember`](#StructMember)  (Base Class)


---
#### StructMember\.emitPreamble<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructMember.emitPreamble}} -->
The `emitPreamble` method is a placeholder method in the `StructMember` class that currently does nothing.
- **Inputs**: None
- **Control Flow**:
    - The method is defined but contains no implementation, indicated by the `pass` statement.
- **Output**: There is no output as the method does nothing.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructMember`](#StructMember)  (Base Class)


---
#### StructMember\.emitPostamble<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructMember.emitPostamble}} -->
The `emitPostamble` method is a placeholder method in the `StructMember` class that currently does nothing.
- **Inputs**: None
- **Control Flow**:
    - The method is defined but contains no implementation, indicated by the `pass` statement.
- **Output**: There is no output as the method does nothing.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructMember`](#StructMember)  (Base Class)


---
#### StructMember\.emitMember<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructMember.emitMember}} -->
The `emitMember` method generates and writes a C-style struct member declaration to a header file.
- **Inputs**:
    - `indent`: A string used to specify the indentation level for the generated code, defaulting to an empty string.
- **Control Flow**:
    - The method constructs a formatted string representing a C-style struct member declaration using the `namespace`, `type`, and `name` attributes of the instance.
    - The formatted string is printed to the `header` file, with the specified `indent` applied.
- **Output**: The method does not return any value; it writes output directly to a file.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructMember`](#StructMember)  (Base Class)


---
#### StructMember\.emitMemberGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructMember.emitMemberGlobal}} -->
The `emitMemberGlobal` method generates C code to declare a global member variable for a struct, using a different type suffix based on whether the member type is in a predefined set of flat types.
- **Inputs**:
    - `indent`: A string used to specify the indentation level for the generated code, defaulting to an empty string.
- **Control Flow**:
    - Check if the member's type is in the `flattypes` set.
    - If the type is in `flattypes`, print a line declaring a member variable with a type suffix `_t`.
    - If the type is not in `flattypes`, print a line declaring a member variable with a type suffix `_global_t`.
- **Output**: The method outputs C code to a file, specifically to the `header` file object, declaring a global member variable for a struct.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructMember`](#StructMember)  (Base Class)


---
#### StructMember\.isFixedSize<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructMember.isFixedSize}} -->
The `isFixedSize` method checks if the type of a `StructMember` instance is among the predefined fixed-size types.
- **Inputs**:
    - `self`: An instance of the `StructMember` class, which contains a `type` attribute representing the type of the struct member.
- **Control Flow**:
    - The method accesses the `type` attribute of the `self` instance.
    - It checks if this `type` is present in the `fixedsizetypes` dictionary, which maps type names to their fixed sizes.
    - The method returns `True` if the `type` is found in `fixedsizetypes`, otherwise it returns `False`.
- **Output**: A boolean value indicating whether the `type` of the `StructMember` is a fixed-size type.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructMember`](#StructMember)  (Base Class)


---
#### StructMember\.fixedSize<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructMember.fixedSize}} -->
The `fixedSize` method returns the fixed size of a struct member based on its type.
- **Inputs**: None
- **Control Flow**:
    - The method accesses the `fixedsizetypes` dictionary using the `type` attribute of the instance.
    - It returns the value associated with the instance's type in the `fixedsizetypes` dictionary.
- **Output**: The output is an integer representing the fixed size of the struct member's type.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructMember`](#StructMember)  (Base Class)


---
#### StructMember\.isFuzzy<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructMember.isFuzzy}} -->
The `isFuzzy` method checks if the `type` attribute of a `StructMember` instance is in the predefined set of `fuzzytypes`.
- **Inputs**:
    - `self`: An instance of the `StructMember` class, which contains the `type` attribute to be checked.
- **Control Flow**:
    - The method accesses the `type` attribute of the `self` instance.
    - It checks if this `type` is present in the `fuzzytypes` set.
    - The method returns the result of this membership test.
- **Output**: A boolean value indicating whether the `type` of the `StructMember` instance is in the `fuzzytypes` set.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructMember`](#StructMember)  (Base Class)


---
#### StructMember\.emitNew<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructMember.emitNew}} -->
The `emitNew` method generates and writes a C function call to initialize a new instance of a struct member based on its type and name.
- **Inputs**:
    - `indent`: A string representing the indentation to be used in the generated code, defaulting to an empty string.
- **Control Flow**:
    - The method constructs a formatted string using the provided `indent`, the `namespace`, the `type`, and the `name` of the struct member.
    - It writes this formatted string to the `body` file, which is presumably a file object for writing C code.
- **Output**: The method does not return any value; it writes a line of code to a file.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructMember`](#StructMember)  (Base Class)


---
#### StructMember\.emitDecodeFootprint<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructMember.emitDecodeFootprint}} -->
The `emitDecodeFootprint` method generates C code to decode the footprint of a specific type and checks for errors during the decoding process.
- **Inputs**:
    - `indent`: A string used to specify the indentation level for the generated C code, defaulting to an empty string.
- **Control Flow**:
    - Prints a line of C code to decode the footprint of a type using a specific function, incorporating the provided indentation.
    - Prints a line of C code to check if an error occurred during the decoding process and returns the error if one is found.
- **Output**: The method does not return any value; it outputs C code to a file specified by the `body` variable.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructMember`](#StructMember)  (Base Class)


---
#### StructMember\.emitDecodeInner<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructMember.emitDecodeInner}} -->
The `emitDecodeInner` method generates code to decode a specific struct member using a predefined decoding function.
- **Inputs**:
    - `indent`: A string representing the indentation to be used in the generated code, defaulting to an empty string.
- **Control Flow**:
    - The method prints a line of code to the `body` file, which calls a decoding function specific to the member's type and namespace.
    - The decoding function is called with the member's name, a memory allocation pointer (`alloc_mem`), and a context (`ctx`).
- **Output**: The method does not return any value; it outputs a line of code to a file.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructMember`](#StructMember)  (Base Class)


---
#### StructMember\.emitDecodeInnerGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructMember.emitDecodeInnerGlobal}} -->
The `emitDecodeInnerGlobal` method generates code to decode a struct member using either a local or global decoding function based on the member's type.
- **Inputs**:
    - `indent`: A string representing the indentation to be used in the generated code, defaulting to an empty string.
- **Control Flow**:
    - Check if the member's type is in the `flattypes` set.
    - If the type is in `flattypes`, print a line of code to decode the member using the local decoding function.
    - If the type is not in `flattypes`, print a line of code to decode the member using the global decoding function.
- **Output**: The method outputs C code to the `body` file stream, which is used for decoding a struct member.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructMember`](#StructMember)  (Base Class)


---
#### StructMember\.emitEncode<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructMember.emitEncode}} -->
The `emitEncode` method generates C code to encode a struct member and handle potential errors during encoding.
- **Inputs**:
    - `indent`: A string used to specify the indentation level for the generated code, defaulting to an empty string.
- **Control Flow**:
    - Prints a line of C code to encode the struct member using a specific encoding function, with the result stored in an error variable `err`.
    - Prints a conditional statement to check if the error variable `err` indicates an error, and if so, returns the error.
- **Output**: The method does not return any value; it outputs C code to a file specified by the `body` file object.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructMember`](#StructMember)  (Base Class)


---
#### StructMember\.emitEncodeGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructMember.emitEncodeGlobal}} -->
The `emitEncodeGlobal` method generates C code to encode a struct member globally, handling both flat and non-flat types.
- **Inputs**:
    - `indent`: A string used for indentation in the generated C code, defaulting to an empty string.
- **Control Flow**:
    - Check if the member's type is in the set of flat types.
    - If the type is flat, generate code to encode the member using a local encoding function.
    - If the type is not flat, generate code to encode the member using a global encoding function.
    - In both cases, generate code to check for encoding errors and return the error if one occurs.
- **Output**: The method outputs C code to a file, which encodes a struct member globally, handling error checking.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructMember`](#StructMember)  (Base Class)


---
#### StructMember\.emitSize<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructMember.emitSize}} -->
The `emitSize` method calculates and prints the size of a specific struct member by invoking a size function based on the member's type.
- **Inputs**:
    - `inner`: A string representing the inner structure or prefix to access the member within the struct.
    - `indent`: An optional string used to specify the indentation level for the printed output, defaulting to an empty string.
- **Control Flow**:
    - The method constructs a formatted string that includes the indentation, a size increment operation, and a function call to calculate the size of the struct member.
    - The function call is constructed using the namespace, type, and member name, and it is applied to the member accessed through the `inner` prefix.
    - The constructed string is printed to the `body` file.
- **Output**: The method does not return any value; it outputs a formatted string to a file.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructMember`](#StructMember)  (Base Class)


---
#### StructMember\.emitWalk<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructMember.emitWalk}} -->
The `emitWalk` method generates and writes a C function call for walking through a struct member in a namespace-specific manner.
- **Inputs**:
    - `inner`: A string representing the inner member access path for the struct member.
    - `indent`: A string used for indentation in the generated code, defaulting to an empty string.
- **Control Flow**:
    - The method constructs a formatted string representing a C function call for walking through a struct member.
    - The constructed string includes the namespace, type, and name of the struct member, along with the provided inner path and function parameters.
    - The formatted string is printed to the `body` file, which is presumably a file object for writing C code.
- **Output**: The method does not return any value; it writes the formatted C code to the specified file.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructMember`](#StructMember)  (Base Class)



---
### VectorMember<!-- {{#class:firedancer/src/flamenco/types/gen_stubs.VectorMember}} -->
- **Members**:
    - `element`: Stores the type of elements contained in the vector.
    - `compact`: Indicates if the vector uses a compact representation.
    - `ignore_underflow`: Specifies whether underflow errors should be ignored.
- **Description**: The `VectorMember` class is a specialized type node that represents a vector structure within a type system. It extends the `TypeNode` class and is designed to handle vectors with elements of a specified type, supporting both compact and non-compact representations. The class provides mechanisms for encoding, decoding, and managing the memory footprint of these vector elements, and it includes options to ignore underflow errors during these operations. The class is integral to managing complex data structures that require dynamic memory allocation and serialization.
- **Methods**:
    - [`firedancer/src/flamenco/types/gen_stubs.VectorMember.__init__`](#VectorMember__init__)
    - [`firedancer/src/flamenco/types/gen_stubs.VectorMember.isFlat`](#VectorMemberisFlat)
    - [`firedancer/src/flamenco/types/gen_stubs.VectorMember.emitPreamble`](#VectorMemberemitPreamble)
    - [`firedancer/src/flamenco/types/gen_stubs.VectorMember.emitPostamble`](#VectorMemberemitPostamble)
    - [`firedancer/src/flamenco/types/gen_stubs.VectorMember.emitMember`](#VectorMemberemitMember)
    - [`firedancer/src/flamenco/types/gen_stubs.VectorMember.emitMemberGlobal`](#VectorMemberemitMemberGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.VectorMember.emitOffsetJoin`](#VectorMemberemitOffsetJoin)
    - [`firedancer/src/flamenco/types/gen_stubs.VectorMember.emitNew`](#VectorMemberemitNew)
    - [`firedancer/src/flamenco/types/gen_stubs.VectorMember.emitDecodeFootprint`](#VectorMemberemitDecodeFootprint)
    - [`firedancer/src/flamenco/types/gen_stubs.VectorMember.emitDecodeInner`](#VectorMemberemitDecodeInner)
    - [`firedancer/src/flamenco/types/gen_stubs.VectorMember.emitDecodeInnerGlobal`](#VectorMemberemitDecodeInnerGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.VectorMember.emitEncode`](#VectorMemberemitEncode)
    - [`firedancer/src/flamenco/types/gen_stubs.VectorMember.emitEncodeGlobal`](#VectorMemberemitEncodeGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.VectorMember.emitSize`](#VectorMemberemitSize)
    - [`firedancer/src/flamenco/types/gen_stubs.VectorMember.emitWalk`](#VectorMemberemitWalk)
- **Inherits From**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode`](#TypeNode)

**Methods**

---
#### VectorMember\.\_\_init\_\_<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.VectorMember.__init__}} -->
The [`__init__`](#TypeNode__init__) method initializes a `VectorMember` instance with attributes based on provided JSON data or keyword arguments.
- **Inputs**:
    - `container`: The container object that holds this `VectorMember` instance.
    - `json`: A dictionary containing initialization data for the `VectorMember`, including keys like 'element', 'modifier', and 'ignore_underflow'.
    - `kwargs`: Additional keyword arguments that can provide a 'name' and 'element' if `json` is None.
- **Control Flow**:
    - If `json` is not None, it initializes the instance using the JSON data.
    - The `element` attribute is set from the 'element' key in the JSON.
    - The `compact` attribute is set to True if 'modifier' in JSON is 'compact', otherwise False.
    - The `ignore_underflow` attribute is set based on the 'ignore_underflow' key in JSON, defaulting to False if not present.
    - If `json` is None and 'name' is in `kwargs`, it initializes the instance using `kwargs`.
    - The `element` attribute is set from `kwargs['element']`, raising a ValueError if not present.
    - The `compact` and `ignore_underflow` attributes are set to False.
- **Output**: The method does not return a value; it initializes the instance attributes.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.__init__`](#TypeNode__init__)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.VectorMember`](#VectorMember)  (Base Class)


---
#### VectorMember\.isFlat<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.VectorMember.isFlat}} -->
The `isFlat` method in the `VectorMember` class always returns `False`, indicating that instances of this class are not considered 'flat'.
- **Inputs**: None
- **Control Flow**:
    - The method contains a single return statement that returns the boolean value `False`.
- **Output**: The method returns a boolean value `False`.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.VectorMember`](#VectorMember)  (Base Class)


---
#### VectorMember\.emitPreamble<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.VectorMember.emitPreamble}} -->
The `emitPreamble` method is a placeholder method in the `VectorMember` class that currently does nothing.
- **Inputs**: None
- **Control Flow**:
    - The method is defined but contains no implementation, indicated by the `pass` statement.
- **Output**: The method does not return any value or perform any operations.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.VectorMember`](#VectorMember)  (Base Class)


---
#### VectorMember\.emitPostamble<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.VectorMember.emitPostamble}} -->
The `emitPostamble` method is a placeholder method in the `VectorMember` class that currently does nothing.
- **Inputs**: None
- **Control Flow**:
    - The method is defined but contains no implementation, indicated by the `pass` statement.
- **Output**: The method does not produce any output or perform any actions.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.VectorMember`](#VectorMember)  (Base Class)


---
#### VectorMember\.emitMember<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.VectorMember.emitMember}} -->
The `emitMember` method generates C code to declare a member variable and its length in a header file, based on the `compact` and `element` attributes of the `VectorMember` class.
- **Inputs**: None
- **Control Flow**:
    - Check if the `compact` attribute is `True` and print a `ushort` length declaration; otherwise, print a `ulong` length declaration.
    - Check if the `element` attribute is in `simpletypes` and print a pointer declaration for the element; otherwise, print a pointer declaration with a namespace prefix.
- **Output**: The method outputs C code to the `header` file stream, declaring a member variable and its length.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.VectorMember`](#VectorMember)  (Base Class)


---
#### VectorMember\.emitMemberGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.VectorMember.emitMemberGlobal}} -->
The `emitMemberGlobal` method generates C code to declare global variables for a vector member's length and offset, using either `ushort` or `ulong` for the length based on the `compact` attribute.
- **Inputs**:
    - `self`: An instance of the `VectorMember` class, which contains attributes like `name`, `compact`, and `element` that determine the code generation behavior.
- **Control Flow**:
    - Check if the `compact` attribute of the instance is `True` or `False`.
    - If `compact` is `True`, print a line declaring a `ushort` variable for the vector's length with the format `ushort {name}_len;`.
    - If `compact` is `False`, print a line declaring a `ulong` variable for the vector's length with the format `ulong {name}_len;`.
    - Print a line declaring a `ulong` variable for the vector's offset with the format `ulong {name}_offset;`.
- **Output**: The method outputs C code lines to a file, which declare global variables for the vector member's length and offset.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.VectorMember`](#VectorMember)  (Base Class)


---
#### VectorMember\.emitOffsetJoin<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.VectorMember.emitOffsetJoin}} -->
The `emitOffsetJoin` method generates C code for a function that joins a vector member to a global structure based on its offset.
- **Inputs**:
    - `type_name`: A string representing the type name to be used as a prefix in the generated function name.
- **Control Flow**:
    - Initialize `ret_type` to `None`.
    - Check if `self.element` is in `simpletypes`; if true, set `ret_type` to `self.element`.
    - Check if `self.element` is in `flattypes`; if true, set `ret_type` to a formatted string with `namespace` and `self.element`.
    - If `self.element` is not in `simpletypes` or `flattypes`, set `ret_type` to a formatted string with `namespace` and `self.element` suffixed with `_global_t`.
    - Print a static function definition to the `header` file, using `ret_type`, `type_name`, and `self.name` to form the function name.
    - Print a return statement in the function that casts a pointer to `ret_type` using `fd_type_pun` and the offset of `self.name`.
    - Close the function definition with a closing brace and print it to the `header` file.
- **Output**: The method outputs C code to the `header` file, defining a static function that returns a pointer to the vector member type, adjusted by its offset in the global structure.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.VectorMember`](#VectorMember)  (Base Class)


---
#### VectorMember\.emitNew<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.VectorMember.emitNew}} -->
The `emitNew` method is a placeholder method in the `VectorMember` class that currently does nothing.
- **Inputs**:
    - `indent`: An optional string argument that specifies the indentation to be used, defaulting to an empty string.
- **Control Flow**:
    - The method is defined but contains no implementation, indicated by the `pass` statement.
- **Output**: The method does not return any value or perform any operations.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.VectorMember`](#VectorMember)  (Base Class)


---
#### VectorMember\.emitDecodeFootprint<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.VectorMember.emitDecodeFootprint}} -->
The `emitDecodeFootprint` method generates C code to decode a vector's length and its elements, updating the total size and handling errors.
- **Inputs**:
    - `indent`: A string used to specify the indentation level for the generated C code, defaulting to an empty string.
- **Control Flow**:
    - Check if the vector is compact; if so, declare a `ushort` for the length and use `fd_bincode_compact_u16_decode` to decode it, otherwise declare a `ulong` and use `fd_bincode_uint64_decode`.
    - Print a check for decoding success; if it fails, return the error.
    - If the length is non-zero, proceed to handle the elements.
    - If the element type is `uchar`, update `total_sz` and decode the bytes footprint, checking for errors.
    - For other element types, update `total_sz` based on whether the element is a simple type or not, and iterate over each element to decode its footprint, checking for errors after each decode.
- **Output**: The method outputs C code to a file, which includes declarations, decoding logic, and error handling for a vector's length and elements.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.VectorMember`](#VectorMember)  (Base Class)


---
#### VectorMember\.emitDecodeInner<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.VectorMember.emitDecodeInner}} -->
The `emitDecodeInner` method generates C code to decode a vector member from a binary format, handling different data types and memory alignment.
- **Inputs**:
    - `indent`: A string used to specify the indentation level for the generated code, defaulting to an empty string.
- **Control Flow**:
    - Check if the vector member is compact; if true, use `fd_bincode_compact_u16_decode_unsafe` to decode the length, otherwise use `fd_bincode_uint64_decode_unsafe`.
    - Print a conditional statement to check if the length of the vector member is non-zero.
    - Determine the element type of the vector member and generate code accordingly.
    - If the element is 'uchar', generate code to allocate memory, decode bytes, and update the memory pointer.
    - For simple types, align the memory, allocate space, and update the memory pointer.
    - For non-simple types, align the memory according to the element's alignment, allocate space, and update the memory pointer.
    - Generate a loop to iterate over each element in the vector, decoding each element based on its type.
    - If the element is a simple type, use the corresponding `fd_bincode` function to decode it.
    - For non-simple types, generate code to create a new instance and decode it using the appropriate decode function.
    - Print an else statement to set the vector member to NULL if its length is zero.
- **Output**: The method outputs C code to a file, which decodes a vector member from a binary format, handling memory allocation and alignment based on the element type.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.VectorMember`](#VectorMember)  (Base Class)


---
#### VectorMember\.emitDecodeInnerGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.VectorMember.emitDecodeInnerGlobal}} -->
The `emitDecodeInnerGlobal` method generates C code to decode a global vector member from a binary format, handling different data types and alignment requirements.
- **Inputs**:
    - `indent`: A string representing the indentation level for the generated code, defaulting to an empty string.
- **Control Flow**:
    - Check if the vector is compact; if true, use `fd_bincode_compact_u16_decode_unsafe` to decode the length, otherwise use `fd_bincode_uint64_decode_unsafe`.
    - Print a conditional statement to check if the decoded length is non-zero.
    - If the element type is `uchar`, calculate the offset, decode bytes, and update the allocation memory pointer.
    - For simple types, align the memory, calculate the offset, and update the allocation memory pointer.
    - For non-simple types, align the memory according to the element's alignment, calculate the offset, and update the allocation memory pointer.
    - Iterate over the elements of the vector, decoding each element based on its type (simple or complex).
    - For complex types, determine if the element is flat or not and call the appropriate decode function.
    - Print the closing braces for the conditional and loop structures.
- **Output**: The method outputs C code to a file, which decodes a vector member from a binary format, handling different data types and alignment requirements.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.VectorMember`](#VectorMember)  (Base Class)


---
#### VectorMember\.emitEncode<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.VectorMember.emitEncode}} -->
The `emitEncode` method generates C code to encode a vector member of a struct, handling different data types and compact encoding options.
- **Inputs**:
    - `indent`: A string used for indentation in the generated code, defaulting to an empty string.
- **Control Flow**:
    - Check if the vector is compact; if true, use `fd_bincode_compact_u16_encode` to encode the length, otherwise use `fd_bincode_uint64_encode`.
    - Print a check for encoding errors and return the error if any occur.
    - Check if the vector length is non-zero; if true, proceed to encode the elements.
    - If the element type is `uchar`, use `fd_bincode_bytes_encode` to encode the bytes and check for errors.
    - For other element types, iterate over each element in the vector.
    - If the element type is a simple type, use the corresponding `fd_bincode_<type>_encode` function to encode each element.
    - If the element type is not a simple type, use the corresponding `<namespace>_<element>_encode` function to encode each element and check for errors.
- **Output**: The method outputs C code to a file, which encodes the vector member of a struct based on its type and compactness.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.VectorMember`](#VectorMember)  (Base Class)


---
#### VectorMember\.emitEncodeGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.VectorMember.emitEncodeGlobal}} -->
The `emitEncodeGlobal` method generates C code to encode a global vector member of a struct, handling different data types and compact encoding options.
- **Inputs**:
    - `indent`: A string representing the indentation to be used in the generated code, defaulting to an empty string.
- **Control Flow**:
    - Check if the vector is compact; if true, use `fd_bincode_compact_u16_encode` to encode the length, otherwise use `fd_bincode_uint64_encode`.
    - Print a check for encoding errors and return the error if any occur.
    - If the vector length is non-zero, calculate the local address of the vector data using the offset.
    - If the element type is `uchar`, encode the bytes directly using `fd_bincode_bytes_encode` and handle errors.
    - For other element types, determine the appropriate pointer type based on whether the element is a simple type, flat type, or other, and cast the local address accordingly.
    - Iterate over each element in the vector, encoding each element using the appropriate encoding function based on its type, and handle any encoding errors.
- **Output**: The method outputs C code to the specified file, which encodes a global vector member of a struct.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.VectorMember`](#VectorMember)  (Base Class)


---
#### VectorMember\.emitSize<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.VectorMember.emitSize}} -->
The `emitSize` method calculates and emits the size of a vector member based on its type and compactness, writing the result to a specified output stream.
- **Inputs**:
    - `inner`: A parameter that is not used in the method body.
    - `indent`: A string used to indent the output, defaulting to an empty string.
- **Control Flow**:
    - Prints the opening of a do-while block with the specified indentation.
    - Checks if the vector member is compact; if true, calculates the size using a compact encoding for a ushort length, otherwise uses the size of a ulong.
    - Determines the size contribution of the vector elements based on their type: 'uchar', simple types, or complex types.
    - For 'uchar', adds the length of the vector to the size.
    - For simple types, multiplies the length by the size of the element type and adds to the size.
    - For complex types, iterates over each element, calculating its size using a namespace-specific function and adds to the size.
    - Prints the closing of the do-while block with the specified indentation.
- **Output**: The method outputs C code to a file stream, calculating and emitting the size of a vector member.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.VectorMember`](#VectorMember)  (Base Class)


---
#### VectorMember\.emitWalk<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.VectorMember.emitWalk}} -->
The `emitWalk` method generates code to serialize a vector's length and its elements, handling different data types and compactness settings.
- **Inputs**:
    - `inner`: An unused parameter in the method, possibly intended for future use or compatibility.
    - `indent`: A string used to prefix each line of generated code, typically for formatting purposes.
- **Control Flow**:
    - Check if the vector is compact; if so, generate code to serialize the vector's length as a ushort.
    - Generate code to check if the vector's length is non-zero, and if so, serialize the vector as an array and increment the level.
    - Iterate over each element in the vector, generating code to serialize each element based on its type.
    - If the element type is in `emitWalkMap`, use the corresponding lambda function to generate serialization code; otherwise, call a specific walk function for the element type.
    - Generate code to end the serialization of the array and decrement the level.
- **Output**: The method outputs C code to a file, which serializes a vector's length and elements, formatted with the specified indentation.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.VectorMember`](#VectorMember)  (Base Class)



---
### BitVectorMember<!-- {{#class:firedancer/src/flamenco/types/gen_stubs.BitVectorMember}} -->
- **Members**:
    - `vector_element`: Holds the element type of the vector.
    - `vector_member`: An instance of VectorMember representing the vector within the BitVectorMember.
- **Description**: The BitVectorMember class is a specialized type of TypeNode that models a bit vector as an optional vector of a specified element type. It encapsulates a VectorMember and provides methods for encoding, decoding, and managing the lifecycle of the bit vector, including handling its presence or absence. The class is designed to integrate with a binary encoding/decoding context, allowing for efficient serialization and deserialization of the bit vector data.
- **Methods**:
    - [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember.__init__`](#BitVectorMember__init__)
    - [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember.isFlat`](#BitVectorMemberisFlat)
    - [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember.emitPreamble`](#BitVectorMemberemitPreamble)
    - [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember.emitPostamble`](#BitVectorMemberemitPostamble)
    - [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember.emitMember`](#BitVectorMemberemitMember)
    - [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember.emitMemberGlobal`](#BitVectorMemberemitMemberGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember.emitNew`](#BitVectorMemberemitNew)
    - [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember.emitDestroy`](#BitVectorMemberemitDestroy)
    - [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember.emitDecodeFootprint`](#BitVectorMemberemitDecodeFootprint)
    - [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember.emitDecodeInner`](#BitVectorMemberemitDecodeInner)
    - [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember.emitDecodeInnerGlobal`](#BitVectorMemberemitDecodeInnerGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember.emitEncode`](#BitVectorMemberemitEncode)
    - [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember.emitEncodeGlobal`](#BitVectorMemberemitEncodeGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember.emitSize`](#BitVectorMemberemitSize)
    - [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember.emitWalk`](#BitVectorMemberemitWalk)
- **Inherits From**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode`](#TypeNode)

**Methods**

---
#### BitVectorMember\.\_\_init\_\_<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.BitVectorMember.__init__}} -->
The [`__init__`](#TypeNode__init__) method initializes a `BitVectorMember` instance by setting up its vector element and vector member attributes.
- **Inputs**:
    - `container`: The container object that holds the `BitVectorMember` instance.
    - `json`: A dictionary containing initialization data, specifically requiring an 'element' key to define the vector element.
- **Control Flow**:
    - Calls the parent class [`__init__`](#TypeNode__init__) method with the `json` parameter to initialize inherited attributes.
    - Extracts the 'element' from the `json` dictionary and assigns it to `self.vector_element`.
    - Creates a [`VectorMember`](#VectorMember) instance using the `container`, `None`, a name derived from `self.name`, and `self.vector_element`, and assigns it to `self.vector_member`.
- **Output**: There is no return value as this is a constructor method.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.__init__`](#TypeNode__init__)
    - [`firedancer/src/flamenco/types/gen_stubs.VectorMember`](#VectorMember)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember`](#BitVectorMember)  (Base Class)


---
#### BitVectorMember\.isFlat<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.BitVectorMember.isFlat}} -->
The `isFlat` method in the `BitVectorMember` class always returns `False`, indicating that instances of this class are not considered flat.
- **Inputs**: None
- **Control Flow**:
    - The method is defined with no parameters other than `self`, indicating it operates on the instance of the class.
    - The method immediately returns `False`, indicating the object is not flat.
- **Output**: The method returns a boolean value `False`.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember`](#BitVectorMember)  (Base Class)


---
#### BitVectorMember\.emitPreamble<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.BitVectorMember.emitPreamble}} -->
The `emitPreamble` method is a placeholder method in the `BitVectorMember` class that currently does nothing.
- **Inputs**: None
- **Control Flow**:
    - The method is defined but contains no implementation, indicated by the `pass` statement.
- **Output**: There is no output as the method does not perform any operations.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember`](#BitVectorMember)  (Base Class)


---
#### BitVectorMember\.emitPostamble<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.BitVectorMember.emitPostamble}} -->
The `emitPostamble` method is a placeholder method in the `BitVectorMember` class that currently does nothing.
- **Inputs**: None
- **Control Flow**:
    - The method is defined but contains no implementation, indicated by the `pass` statement.
- **Output**: There is no output as the method does nothing.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember`](#BitVectorMember)  (Base Class)


---
#### BitVectorMember\.emitMember<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.BitVectorMember.emitMember}} -->
The [`emitMember`](#VectorMemberemitMember) method generates C code to declare a member variable and its associated length for a bit vector within a header file.
- **Inputs**: None
- **Control Flow**:
    - Prints a line declaring a `uchar` variable named `has_<name>` to the header file.
    - Calls the [`emitMember`](#VectorMemberemitMember) method of the `vector_member` attribute, which is an instance of `VectorMember`, to emit its member declaration.
    - Prints a line declaring a `ulong` variable named `<name>_len` to the header file.
- **Output**: The method outputs C code lines to the header file, declaring a `uchar` and a `ulong` variable related to the bit vector member.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.VectorMember.emitMember`](#VectorMemberemitMember)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember`](#BitVectorMember)  (Base Class)


---
#### BitVectorMember\.emitMemberGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.BitVectorMember.emitMemberGlobal}} -->
The [`emitMemberGlobal`](#VectorMemberemitMemberGlobal) method generates C code to declare global variables for a bit vector member, including a flag and length, and delegates additional global member emission to a vector member.
- **Inputs**: None
- **Control Flow**:
    - Prints a line declaring a `uchar` variable named `has_<name>` to the `header` file, where `<name>` is the name of the bit vector member.
    - Calls the [`emitMemberGlobal`](#VectorMemberemitMemberGlobal) method on the `vector_member` attribute, which is an instance of `VectorMember`, to emit additional global member declarations.
    - Prints a line declaring a `ulong` variable named `<name>_len` to the `header` file, where `<name>` is the name of the bit vector member.
- **Output**: The method outputs C code lines to the `header` file, declaring global variables for a bit vector member.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.VectorMember.emitMemberGlobal`](#VectorMemberemitMemberGlobal)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember`](#BitVectorMember)  (Base Class)


---
#### BitVectorMember\.emitNew<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.BitVectorMember.emitNew}} -->
The `emitNew` method is a placeholder method in the `BitVectorMember` class that currently does nothing.
- **Inputs**:
    - `indent`: An optional string parameter that specifies the indentation to be used, defaulting to an empty string.
- **Control Flow**:
    - The method is defined but contains no implementation, indicated by the `pass` statement.
- **Output**: The method does not return any value or perform any operations.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember`](#BitVectorMember)  (Base Class)


---
#### BitVectorMember\.emitDestroy<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.BitVectorMember.emitDestroy}} -->
The `emitDestroy` method resets the state of a `BitVectorMember` by destroying its vector member and setting its associated flags and length to zero.
- **Inputs**:
    - `indent`: An optional string argument used for indentation, defaulting to an empty string.
- **Control Flow**:
    - The method calls `emitDestroy` on `self.vector_member` to handle the destruction of the vector member.
    - It prints a line to set `self->has_{self.name}` to 0, indicating the absence of the bit vector.
    - It prints another line to set `self->{self.name}_len` to 0, resetting the length of the bit vector.
- **Output**: The method does not return any value; it performs operations to reset the state of the object.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember`](#BitVectorMember)  (Base Class)


---
#### BitVectorMember\.emitDecodeFootprint<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.BitVectorMember.emitDecodeFootprint}} -->
The [`emitDecodeFootprint`](#VectorMemberemitDecodeFootprint) method generates C code to decode a bit vector's footprint, checking for errors and ensuring the decoded length does not exceed the expected size.
- **Inputs**:
    - `self`: Refers to the instance of the BitVectorMember class, providing access to its attributes and methods.
- **Control Flow**:
    - Prints the opening brace '{' to the output file `body`.
    - Declares and initializes a `uchar` variable `o` and a `ulong` variable `inner_len` to 0.
    - Calls `fd_bincode_bool_decode` to decode a boolean value into `o` and checks for errors; returns `err` if unsuccessful.
    - Checks if `o` is true; if so, calls [`emitDecodeFootprint`](#VectorMemberemitDecodeFootprint) on `self.vector_member` and checks for errors again, updating `inner_len` with the length of the vector member.
    - Declares a `ulong` variable `len` and decodes a 64-bit unsigned integer into it, checking for errors.
    - Compares `len` with the maximum allowed size calculated from `inner_len`, `self.vector_element`, and returns an encoding error if `len` exceeds this size.
    - Prints the closing brace '}' to the output file `body`.
- **Output**: The method outputs C code to the `body` file stream, which includes error checking and decoding logic for a bit vector's footprint.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.VectorMember.emitDecodeFootprint`](#VectorMemberemitDecodeFootprint)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember`](#BitVectorMember)  (Base Class)


---
#### BitVectorMember\.emitDecodeInner<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.BitVectorMember.emitDecodeInner}} -->
The [`emitDecodeInner`](#PrimitiveMemberemitDecodeInner) method generates C code to decode a bit vector member from a binary format, updating the member's presence flag and length.
- **Inputs**: None
- **Control Flow**:
    - Prints an opening brace to the output file `body`.
    - Declares a local variable `o` of type `uchar`.
    - Calls `fd_bincode_bool_decode_unsafe` to decode a boolean value into `o` using the context `ctx`.
    - Sets the `has_<name>` attribute of `self` to the boolean value of `o`.
    - Checks if `o` is true; if so, calls [`emitDecodeInner`](#PrimitiveMemberemitDecodeInner) on `self.vector_member` with an indent of four spaces.
    - If `o` is false, sets the `vector_member` attribute of `self` to `NULL`.
    - Calls `fd_bincode_uint64_decode_unsafe` to decode a 64-bit unsigned integer into the `<name>_len` attribute of `self`.
    - Prints a closing brace to the output file `body`.
- **Output**: The method outputs C code to the specified file `body` for decoding a bit vector member.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitDecodeInner`](#PrimitiveMemberemitDecodeInner)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember`](#BitVectorMember)  (Base Class)


---
#### BitVectorMember\.emitDecodeInnerGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.BitVectorMember.emitDecodeInnerGlobal}} -->
The [`emitDecodeInnerGlobal`](#PrimitiveMemberemitDecodeInnerGlobal) method decodes a global bit vector member from a binary context and updates the object's state accordingly.
- **Inputs**: None
- **Control Flow**:
    - Prints an opening brace to the output file `body`.
    - Declares a local variable `o` of type `uchar`.
    - Calls `fd_bincode_bool_decode_unsafe` to decode a boolean value into `o` from the context `ctx`.
    - Sets the object's `has_<name>` attribute based on the decoded value `o`.
    - Checks if `o` is true; if so, calls [`emitDecodeInnerGlobal`](#PrimitiveMemberemitDecodeInnerGlobal) on the `vector_member` with an indent.
    - Calls `fd_bincode_uint64_decode_unsafe` to decode a 64-bit unsigned integer into the object's `<name>_len` attribute from the context `ctx`.
    - Prints a closing brace to the output file `body`.
- **Output**: The method outputs C code to the file `body` that decodes a global bit vector member from a binary context.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitDecodeInnerGlobal`](#PrimitiveMemberemitDecodeInnerGlobal)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember`](#BitVectorMember)  (Base Class)


---
#### BitVectorMember\.emitEncode<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.BitVectorMember.emitEncode}} -->
The [`emitEncode`](#PrimitiveMemberemitEncode) method encodes a bit vector member by first encoding a boolean flag indicating its presence, then encoding the vector member if present, and finally encoding the length of the vector.
- **Inputs**: None
- **Control Flow**:
    - Prints a statement to encode a boolean flag indicating if the vector member is present.
    - Checks if there is an error in encoding the boolean flag and returns the error if any.
    - If the vector member is present, it calls [`emitEncode`](#PrimitiveMemberemitEncode) on the vector member and checks for encoding errors.
    - Prints a statement to encode the length of the vector member.
    - Checks if there is an error in encoding the length and returns the error if any.
- **Output**: The method outputs encoded data to a file, handling errors by returning them if they occur during the encoding process.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitEncode`](#PrimitiveMemberemitEncode)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember`](#BitVectorMember)  (Base Class)


---
#### BitVectorMember\.emitEncodeGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.BitVectorMember.emitEncodeGlobal}} -->
The [`emitEncodeGlobal`](#VectorMemberemitEncodeGlobal) method encodes a global representation of a bit vector member, handling the encoding of its presence and length, and delegating the encoding of its vector member.
- **Inputs**:
    - `self`: An instance of the BitVectorMember class, representing a bit vector member with associated properties and methods.
- **Control Flow**:
    - Encode the presence of the bit vector using `fd_bincode_bool_encode` and check for errors.
    - If the bit vector is present (`self->has_{self.name}` is true), proceed to encode the vector member using `self.vector_member.emitEncodeGlobal`.
    - Check for errors after encoding the vector member.
    - Encode the length of the bit vector using `fd_bincode_uint64_encode` and check for errors.
- **Output**: The method outputs encoded data to a specified file or stream, handling errors by returning an error code if any encoding step fails.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.VectorMember.emitEncodeGlobal`](#VectorMemberemitEncodeGlobal)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember`](#BitVectorMember)  (Base Class)


---
#### BitVectorMember\.emitSize<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.BitVectorMember.emitSize}} -->
The [`emitSize`](#VectorMemberemitSize) method calculates and outputs the size of a bit vector member, accounting for its presence and the size of its elements.
- **Inputs**:
    - `inner`: A parameter that is not used in the method body.
- **Control Flow**:
    - Prints a statement to add the size of a char to the total size.
    - Checks if the bit vector member is present using a conditional statement.
    - If present, calls the [`emitSize`](#VectorMemberemitSize) method of `vector_member` to calculate the size of the vector elements.
    - Prints a closing bracket for the conditional block.
    - Adds the size of an unsigned long to the total size.
- **Output**: The method outputs C code to a file, which calculates the size of a bit vector member in a structure.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.VectorMember.emitSize`](#VectorMemberemitSize)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember`](#BitVectorMember)  (Base Class)


---
#### BitVectorMember\.emitWalk<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.BitVectorMember.emitWalk}} -->
The [`emitWalk`](#VectorMemberemitWalk) method generates code to walk through a bit vector member, checking its presence and invoking a function to handle its elements and length.
- **Inputs**:
    - `inner`: An unused parameter in this method, possibly intended for future use or to match a method signature.
    - `indent`: A string used for indentation in the generated code, defaulting to an empty string.
- **Control Flow**:
    - The method starts by checking if the bit vector member is present using a condition on `self->has_{self.name}`.
    - If the bit vector member is not present, it calls a function `fun` with parameters indicating a null type for the bit vector.
    - If the bit vector member is present, it calls the [`emitWalk`](#VectorMemberemitWalk) method on `self.vector_member` to handle the elements of the vector.
    - Finally, it calls the function `fun` again to handle the length of the bit vector member.
- **Output**: The method outputs C code to a file, which is used to walk through the bit vector member and handle its elements and length.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.VectorMember.emitWalk`](#VectorMemberemitWalk)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.BitVectorMember`](#BitVectorMember)  (Base Class)



---
### StaticVectorMember<!-- {{#class:firedancer/src/flamenco/types/gen_stubs.StaticVectorMember}} -->
- **Members**:
    - `element`: Stores the type of elements contained in the static vector.
    - `size`: Represents the fixed size of the static vector, or None if not specified.
    - `ignore_underflow`: Indicates whether underflow errors should be ignored, defaulting to False.
- **Description**: The StaticVectorMember class is a specialized type node that represents a static vector with a fixed size, defined by the 'size' attribute. It extends the TypeNode class and is initialized with a container and a JSON object that specifies the element type, size, and whether to ignore underflow errors. The class provides methods for encoding, decoding, and managing the static vector's elements, supporting both simple and complex types. It is designed to handle serialization and deserialization processes, ensuring that the vector's elements are correctly managed in memory.
- **Methods**:
    - [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.__init__`](#StaticVectorMember__init__)
    - [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.isFixedSize`](#StaticVectorMemberisFixedSize)
    - [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.isFlat`](#StaticVectorMemberisFlat)
    - [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.emitPreamble`](#StaticVectorMemberemitPreamble)
    - [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.emitPostamble`](#StaticVectorMemberemitPostamble)
    - [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.emitMember`](#StaticVectorMemberemitMember)
    - [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.emitMemberGlobal`](#StaticVectorMemberemitMemberGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.emitNew`](#StaticVectorMemberemitNew)
    - [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.emitDecodeFootprint`](#StaticVectorMemberemitDecodeFootprint)
    - [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.emitDecodeInner`](#StaticVectorMemberemitDecodeInner)
    - [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.emitDecodeInnerGlobal`](#StaticVectorMemberemitDecodeInnerGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.emitEncode`](#StaticVectorMemberemitEncode)
    - [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.emitEncodeGlobal`](#StaticVectorMemberemitEncodeGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.emitSize`](#StaticVectorMemberemitSize)
    - [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.emitWalk`](#StaticVectorMemberemitWalk)
- **Inherits From**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode`](#TypeNode)

**Methods**

---
#### StaticVectorMember\.\_\_init\_\_<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.__init__}} -->
The [`__init__`](#TypeNode__init__) method initializes an instance of the `StaticVectorMember` class by setting its attributes based on a JSON configuration.
- **Inputs**:
    - `container`: The container object that holds this `StaticVectorMember` instance.
    - `json`: A dictionary containing configuration data for initializing the `StaticVectorMember` instance, including keys like 'element', 'size', and 'ignore_underflow'.
- **Control Flow**:
    - The method calls the parent class's [`__init__`](#TypeNode__init__) method with the `json` argument to initialize inherited attributes.
    - It assigns the value associated with the 'element' key in the `json` dictionary to the `element` attribute of the instance.
    - It checks if the 'size' key is present in the `json` dictionary; if so, it assigns its value to the `size` attribute, otherwise, it sets `size` to `None`.
    - It checks if the 'ignore_underflow' key is present in the `json` dictionary; if so, it converts its value to a boolean and assigns it to the `ignore_underflow` attribute, otherwise, it sets `ignore_underflow` to `False`.
- **Output**: The method does not return any value; it initializes the instance attributes.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.__init__`](#TypeNode__init__)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember`](#StaticVectorMember)  (Base Class)


---
#### StaticVectorMember\.isFixedSize<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.isFixedSize}} -->
The `isFixedSize` method in the `StaticVectorMember` class always returns `False`, indicating that instances of this class do not have a fixed size.
- **Inputs**: None
- **Control Flow**:
    - The method is called without any parameters.
    - It directly returns the boolean value `False`.
- **Output**: The method returns a boolean value `False`, indicating that the object is not of fixed size.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember`](#StaticVectorMember)  (Base Class)


---
#### StaticVectorMember\.isFlat<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.isFlat}} -->
The `isFlat` method checks if the `element` attribute of a `StaticVectorMember` instance is part of a predefined set of flat types.
- **Inputs**: None
- **Control Flow**:
    - The method accesses the `element` attribute of the instance.
    - It checks if this `element` is present in the `flattypes` set.
    - The method returns `True` if the `element` is in `flattypes`, otherwise it returns `False`.
- **Output**: A boolean value indicating whether the `element` is a flat type.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember`](#StaticVectorMember)  (Base Class)


---
#### StaticVectorMember\.emitPreamble<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.emitPreamble}} -->
The `emitPreamble` method is a placeholder method in the `StaticVectorMember` class that currently does nothing.
- **Inputs**: None
- **Control Flow**:
    - The method is defined but contains no implementation, indicated by the `pass` statement.
- **Output**: There is no output as the method does nothing.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember`](#StaticVectorMember)  (Base Class)


---
#### StaticVectorMember\.emitPostamble<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.emitPostamble}} -->
The `emitPostamble` method is a placeholder method in the `StaticVectorMember` class that currently does nothing.
- **Inputs**: None
- **Control Flow**:
    - The method is defined but contains no implementation, as indicated by the `pass` statement.
- **Output**: There is no output or return value from this method, as it is not implemented.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember`](#StaticVectorMember)  (Base Class)


---
#### StaticVectorMember\.emitMember<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.emitMember}} -->
The `emitMember` method generates C code to declare and define a static vector member in a header file, including its length, size, offset, and element type.
- **Inputs**: None
- **Control Flow**:
    - Prints declarations for `ulong` variables representing the length, size, and offset of the member.
    - Checks if the element type of the member is in `simpletypes`.
    - If the element type is simple, prints a declaration for an array of the element type with the specified size.
    - If the element type is not simple, prints a declaration for an array of a namespaced type with the specified size.
- **Output**: The method outputs C code lines to a file, specifically to the `header` file object, defining a static vector member with its associated metadata and type.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember`](#StaticVectorMember)  (Base Class)


---
#### StaticVectorMember\.emitMemberGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.emitMemberGlobal}} -->
The `emitMemberGlobal` method generates C code to declare global variables for a static vector member, including its length, size, offset, and array elements, based on the element type.
- **Inputs**:
    - `self`: An instance of the StaticVectorMember class, which contains attributes like `name`, `element`, and `size` that define the static vector member.
- **Control Flow**:
    - Prints declarations for `ulong` variables representing the length, size, and offset of the vector member to the header file.
    - Checks if the element type of the vector is in `simpletypes`, `flattypes`, or neither to determine the appropriate type for the array elements.
    - Prints the declaration of the array with the appropriate type and size to the header file.
- **Output**: The method outputs C code lines to a header file, declaring global variables for a static vector member.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember`](#StaticVectorMember)  (Base Class)


---
#### StaticVectorMember\.emitNew<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.emitNew}} -->
The `emitNew` method initializes a static vector member by setting its size and, if the element type is not a simple type, iterates over the vector to initialize each element using a specific constructor function.
- **Inputs**:
    - `indent`: An optional string argument used for indentation, defaulting to an empty string.
- **Control Flow**:
    - Retrieve the size of the static vector from the instance variable `self.size`.
    - Print a line to set the size of the vector member in the generated code.
    - Check if the element type of the vector is in the `simpletypes` set.
    - If the element type is not a simple type, iterate over the range of the vector size.
    - For each index in the iteration, print a line to call the constructor function for the element type, initializing each element in the vector.
- **Output**: The method does not return any value; it outputs C code to a file specified by the `body` variable.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember`](#StaticVectorMember)  (Base Class)


---
#### StaticVectorMember\.emitDecodeFootprint<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.emitDecodeFootprint}} -->
The `emitDecodeFootprint` method generates C code to decode the footprint of a static vector member, handling different element types and error checking.
- **Inputs**:
    - `self`: An instance of the StaticVectorMember class, representing a static vector member with attributes like name, element, and size.
- **Control Flow**:
    - Prints a declaration for a variable to hold the length of the vector.
    - Generates code to decode the length of the vector using a bincode function and checks for errors.
    - Checks if the decoded length is non-zero to proceed with further decoding.
    - Determines the element type and generates appropriate decoding code for each element in the vector.
    - Handles special cases for 'uchar' elements by calling a specific decode function.
    - For non-'uchar' elements, iterates over each element to decode its footprint, using different functions based on whether the element is a simple type or a complex type.
    - Includes error checking after each decoding step to ensure successful decoding.
- **Output**: The method outputs C code to a file, which includes variable declarations, function calls for decoding, and error handling logic.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember`](#StaticVectorMember)  (Base Class)


---
#### StaticVectorMember\.emitDecodeInner<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.emitDecodeInner}} -->
The `emitDecodeInner` method generates C code to decode a static vector member from a binary format.
- **Inputs**: None
- **Control Flow**:
    - Prints a line to decode the length of the vector using `fd_bincode_uint64_decode_unsafe` and assigns it to `self->{self.name}_len`.
    - Sets `self->{self.name}_size` to the predefined size of the vector.
    - Initializes `self->{self.name}_offset` to 0.
    - Checks if the element type is `uchar`; if true, it prints a line to decode bytes using `fd_bincode_bytes_decode_unsafe` and returns.
    - If the element type is not `uchar`, it enters a loop to iterate over each element in the vector.
    - Within the loop, it checks if the element type is in `simpletypes`; if true, it prints a line to decode the element using the appropriate `fd_bincode` function.
    - If the element type is not in `simpletypes`, it prints a line to decode the element using a custom decode function specific to the element type.
- **Output**: The method outputs C code to a file, which decodes a static vector member from a binary format.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember`](#StaticVectorMember)  (Base Class)


---
#### StaticVectorMember\.emitDecodeInnerGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.emitDecodeInnerGlobal}} -->
The `emitDecodeInnerGlobal` method decodes a global array of elements from a binary context into a structure, handling different element types accordingly.
- **Inputs**:
    - `self`: An instance of the StaticVectorMember class, which contains metadata about the vector being decoded.
- **Control Flow**:
    - The method starts by decoding the length of the array using `fd_bincode_uint64_decode_unsafe` and assigns it to `self->{self.name}_len`.
    - It sets `self->{self.name}_size` to the predefined size and initializes `self->{self.name}_offset` to 0.
    - If the element type is 'uchar', it decodes the bytes directly into the array using `fd_bincode_bytes_decode_unsafe` and returns immediately.
    - For other element types, it iterates over the length of the array, decoding each element based on its type.
    - If the element is a simple type, it uses the corresponding `fd_bincode_{type}_decode_unsafe` function to decode each element.
    - If the element is a flat type, it calls the `decode_inner` function for each element.
    - For other types, it calls the `decode_inner_global` function for each element.
- **Output**: The method outputs the decoded elements into the structure's array, updating its length and offset properties.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember`](#StaticVectorMember)  (Base Class)


---
#### StaticVectorMember\.emitEncode<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.emitEncode}} -->
The `emitEncode` method generates C code to encode a static vector member of a struct, handling different data types and conditions.
- **Inputs**:
    - `self`: An instance of the StaticVectorMember class, representing a static vector member of a struct with attributes like element type, size, and name.
- **Control Flow**:
    - Prints code to encode the length of the vector using `fd_bincode_uint64_encode` and checks for errors.
    - Checks if the vector length is zero and returns success if true.
    - Handles the special case where the element type is 'uchar' by printing a TODO comment for future implementation.
    - Iterates over the vector elements using a loop, calculating the index based on the offset and size.
    - For elements of simple types, prints code to encode each element using the appropriate `fd_bincode` function.
    - For non-simple types, prints code to encode each element using a namespace-specific encode function.
    - Checks for encoding errors after each element encoding and returns the error if any occur.
- **Output**: The method outputs C code to a file, which encodes the static vector member of a struct.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember`](#StaticVectorMember)  (Base Class)


---
#### StaticVectorMember\.emitEncodeGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.emitEncodeGlobal}} -->
The `emitEncodeGlobal` method generates C code to encode a global static vector member, handling different data types and ensuring proper error checking.
- **Inputs**:
    - `self`: An instance of the StaticVectorMember class, representing a static vector member with attributes like name, element type, and size.
- **Control Flow**:
    - Prints code to encode the length of the vector using `fd_bincode_uint64_encode` and checks for errors.
    - Checks if the vector length is zero and returns success if true.
    - Handles the special case where the element type is 'uchar' by printing a TODO comment for future implementation.
    - Iterates over the vector elements using a loop, calculating the index based on the offset and size, using either bitwise AND or modulo operations depending on the size.
    - For simple types, prints code to encode each element using `fd_bincode_<type>_encode`.
    - For flat types, prints code to encode each element using `<namespace>_<element>_encode`.
    - For other types, prints code to encode each element using `<namespace>_<element>_encode_global`.
    - Checks for errors after encoding each element and returns the error if any.
- **Output**: The method outputs C code to the `body` file stream, which encodes a global static vector member, handling different data types and ensuring proper error checking.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember`](#StaticVectorMember)  (Base Class)


---
#### StaticVectorMember\.emitSize<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.emitSize}} -->
The `emitSize` method calculates and outputs the size of a static vector member based on its element type and length.
- **Inputs**:
    - `inner`: An unused parameter in the method, possibly intended for future use or compatibility with other methods.
- **Control Flow**:
    - Prints a base size increment for an unsigned long integer to the output file `body`.
    - Checks if the element type is 'uchar' and adds the length of the element to the size.
    - If the element type is in `simpletypes`, it multiplies the length by the size of the element type and adds it to the size.
    - For other element types, it iterates over each element, calling a size function for each and adding the result to the size.
- **Output**: The method outputs C code to a file that calculates the size of a static vector member based on its type and length.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember`](#StaticVectorMember)  (Base Class)


---
#### StaticVectorMember\.emitWalk<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StaticVectorMember.emitWalk}} -->
The `emitWalk` method generates C code to iterate over a static vector member and apply a function to each element, handling different data types and array sizes.
- **Inputs**:
    - `inner`: An unused parameter in the method, possibly intended for future use or for compatibility with other methods.
    - `indent`: A string used for indentation in the generated C code, defaulting to an empty string.
- **Control Flow**:
    - Check if the element type is 'uchar'; if so, print a TODO message and return.
    - Print a function call to process the array as a whole, incrementing the level variable.
    - Start a for loop to iterate over each element in the array, using the length of the array as the loop limit.
    - Determine the index of the current element using either bitwise AND or modulo operation, depending on whether the size is a power of two.
    - Check if the element type is in the `emitWalkMap`; if so, call the corresponding function from the map.
    - If the element type is not in the `emitWalkMap`, print a function call to process the individual element.
    - Close the for loop and print a function call to indicate the end of processing the array, decrementing the level variable.
- **Output**: The method outputs C code to a file, which includes function calls for processing each element of a static vector member.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StaticVectorMember`](#StaticVectorMember)  (Base Class)



---
### StringMember<!-- {{#class:firedancer/src/flamenco/types/gen_stubs.StringMember}} -->
- **Members**:
    - `compact`: Indicates whether the string member is compact, initialized to False.
    - `ignore_underflow`: Indicates whether underflow should be ignored, initialized to False.
- **Description**: The `StringMember` class is a specialized type of `VectorMember` designed to handle string data, specifically by setting the element type to 'uchar'. It initializes with a container and JSON configuration, modifying the JSON to specify 'uchar' as the element type. The class includes attributes to manage compactness and underflow behavior, both set to False by default. It provides functionality to decode a string's footprint, ensuring proper handling of UTF-8 verification and size calculations during decoding.
- **Methods**:
    - [`firedancer/src/flamenco/types/gen_stubs.StringMember.__init__`](#StringMember__init__)
    - [`firedancer/src/flamenco/types/gen_stubs.StringMember.isFlat`](#StringMemberisFlat)
    - [`firedancer/src/flamenco/types/gen_stubs.StringMember.emitDecodeFootprint`](#StringMemberemitDecodeFootprint)
- **Inherits From**:
    - [`firedancer/src/flamenco/types/gen_stubs.VectorMember`](#VectorMember)

**Methods**

---
#### StringMember\.\_\_init\_\_<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StringMember.__init__}} -->
The [`__init__`](#TypeNode__init__) method initializes a `StringMember` object by setting its `element` to "uchar" and initializing its `compact` and `ignore_underflow` attributes to `False`.
- **Inputs**:
    - `container`: The container object that the `StringMember` is associated with.
    - `json`: A dictionary containing configuration data for initializing the `StringMember`, including an "element" key that is set to "uchar".
- **Control Flow**:
    - The method sets the "element" key in the `json` dictionary to "uchar".
    - It calls the superclass [`__init__`](#TypeNode__init__) method with `container` and `json` as arguments.
    - The `compact` attribute is set to `False`.
    - The `ignore_underflow` attribute is set to `False`.
- **Output**: The method does not return any value; it initializes the instance attributes of the `StringMember` object.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.__init__`](#TypeNode__init__)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StringMember`](#StringMember)  (Base Class)


---
#### StringMember\.isFlat<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StringMember.isFlat}} -->
The `isFlat` method in the `StringMember` class always returns `False`, indicating that the object is not considered flat.
- **Inputs**: None
- **Control Flow**:
    - The method directly returns the boolean value `False`.
- **Output**: The method outputs a boolean value `False`, indicating that the object is not flat.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StringMember`](#StringMember)  (Base Class)


---
#### StringMember\.emitDecodeFootprint<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StringMember.emitDecodeFootprint}} -->
The `emitDecodeFootprint` method generates C code to decode the footprint of a string member, updating the total size and verifying UTF-8 validity.
- **Inputs**:
    - `self`: An instance of the `StringMember` class, which contains attributes like `name` and `element` used in the method.
- **Control Flow**:
    - Prints a declaration for a variable to hold the length of the string member.
    - Generates code to decode the length of the string using `fd_bincode_uint64_decode`.
    - Checks if the decoding was successful and returns an error if not.
    - Updates the total size with the decoded length of the string.
    - Checks if the length is non-zero, and if so, proceeds to decode the bytes and verify UTF-8 validity.
    - Generates code to decode the bytes of the string using `fd_bincode_bytes_decode_footprint`.
    - Checks if the byte decoding was successful and returns an error if not.
    - Verifies the UTF-8 validity of the decoded string using `fd_utf8_verify`.
    - Checks if the UTF-8 verification was successful and returns an error if not.
- **Output**: The method outputs C code to the `body` file stream, which includes variable declarations, decoding logic, and error handling for decoding a string member's footprint.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StringMember`](#StringMember)  (Base Class)



---
### DequeMember<!-- {{#class:firedancer/src/flamenco/types/gen_stubs.DequeMember}} -->
- **Members**:
    - `element`: Stores the element type of the deque.
    - `compact`: Indicates if the deque uses a compact modifier.
    - `min`: Specifies the minimum count for the deque, if any.
    - `growth`: Defines the growth strategy for the deque, if specified.
- **Description**: The `DequeMember` class is a specialized type node that represents a deque structure within a container, allowing for dynamic element management. It extends the `TypeNode` class and is initialized with a container and a JSON object that defines its properties, such as the element type, compactness, minimum count, and growth strategy. The class provides methods to handle the deque's type and prefix, emit preamble and postamble code, and manage encoding and decoding processes for the deque's elements. It is designed to integrate with a larger system that handles various data types and structures, particularly in contexts where dynamic memory allocation and serialization are required.
- **Methods**:
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.__init__`](#DequeMember__init__)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.isFlat`](#DequeMemberisFlat)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type`](#DequeMemberelem_type)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type_global`](#DequeMemberelem_type_global)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.prefix`](#DequeMemberprefix)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.prefix_global`](#DequeMemberprefix_global)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.emitPreamble`](#DequeMemberemitPreamble)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.emitPostamble`](#DequeMemberemitPostamble)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.emitMember`](#DequeMemberemitMember)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.emitMemberGlobal`](#DequeMemberemitMemberGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.emitOffsetJoin`](#DequeMemberemitOffsetJoin)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.emitNew`](#DequeMemberemitNew)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.emitDecodeFootprint`](#DequeMemberemitDecodeFootprint)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.emitDecodeInner`](#DequeMemberemitDecodeInner)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.emitDecodeInnerGlobal`](#DequeMemberemitDecodeInnerGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.emitEncode`](#DequeMemberemitEncode)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.emitEncodeGlobal`](#DequeMemberemitEncodeGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.emitSize`](#DequeMemberemitSize)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.emitWalk`](#DequeMemberemitWalk)
- **Inherits From**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode`](#TypeNode)

**Methods**

---
#### DequeMember\.\_\_init\_\_<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DequeMember.__init__}} -->
The [`__init__`](#TypeNode__init__) method initializes a `DequeMember` instance with properties derived from a JSON configuration.
- **Inputs**:
    - `container`: An object or structure that holds or manages the `DequeMember`, though not directly used in this method.
    - `json`: A dictionary containing configuration data for initializing the `DequeMember` instance, including keys like 'element', 'modifier', 'min', and 'growth'.
- **Control Flow**:
    - Calls the parent class's [`__init__`](#TypeNode__init__) method with the `json` argument.
    - Sets the `element` attribute to the value associated with the 'element' key in the `json` dictionary.
    - Determines if the `compact` attribute should be `True` based on the presence and value of the 'modifier' key in the `json` dictionary.
    - Sets the `min` attribute to the value associated with the 'min' key in the `json` dictionary, or `None` if not present.
    - Sets the `growth` attribute to the value associated with the 'growth' key in the `json` dictionary, or `None` if not present.
- **Output**: The method does not return a value; it initializes the instance attributes based on the provided JSON configuration.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.__init__`](#TypeNode__init__)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DequeMember`](#DequeMember)  (Base Class)


---
#### DequeMember\.isFlat<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DequeMember.isFlat}} -->
The `isFlat` method in the `DequeMember` class always returns `False`, indicating that the object is not flat.
- **Inputs**: None
- **Control Flow**:
    - The method is defined within the `DequeMember` class.
    - It contains a single line of code that returns `False`.
- **Output**: The method returns a boolean value `False`.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DequeMember`](#DequeMember)  (Base Class)


---
#### DequeMember\.elem\_type<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type}} -->
The `elem_type` method returns the type of the element as a string, either directly if it's a simple type or with a namespace prefix if it's not.
- **Inputs**:
    - `self`: An instance of the DequeMember class, which contains attributes like 'element' that determine the type of the element.
- **Control Flow**:
    - Check if the element is in the set of simple types.
    - If it is, return the element as its type.
    - If it is not, return a string formatted with a namespace and the element suffixed with '_t'.
- **Output**: A string representing the type of the element, either as a simple type or a namespaced type.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DequeMember`](#DequeMember)  (Base Class)


---
#### DequeMember\.elem\_type\_global<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type_global}} -->
The `elem_type_global` method returns the global type name for the element, appending '_global_t' to the namespace and element name if the element is not a simple type.
- **Inputs**: None
- **Control Flow**:
    - Check if `self.element` is in the `simpletypes` dictionary.
    - If `self.element` is a simple type, return `self.element`.
    - If `self.element` is not a simple type, return a formatted string combining `namespace`, `self.element`, and '_global_t'.
- **Output**: Returns a string representing the global type of the element.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DequeMember`](#DequeMember)  (Base Class)


---
#### DequeMember\.prefix<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DequeMember.prefix}} -->
The `prefix` method returns a string that combines the prefix 'deq_' with the element type of the deque member.
- **Inputs**: None
- **Control Flow**:
    - The method calls `self.elem_type()` to get the element type of the deque member.
    - It concatenates the string 'deq_' with the result of `self.elem_type()` to form the final string.
    - The method returns the concatenated string.
- **Output**: A string that represents the prefix for the deque member, formatted as 'deq_' followed by the element type.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type`](#DequeMemberelem_type)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DequeMember`](#DequeMember)  (Base Class)


---
#### DequeMember\.prefix\_global<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DequeMember.prefix_global}} -->
The `prefix_global` method returns a string that prefixes the global element type with 'deq_'.
- **Inputs**: None
- **Control Flow**:
    - The method calls `self.elem_type_global()` to get the global element type.
    - It constructs a string by prefixing 'deq_' to the result of `self.elem_type_global()`.
    - The constructed string is returned.
- **Output**: A string prefixed with 'deq_' followed by the global element type.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type_global`](#DequeMemberelem_type_global)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DequeMember`](#DequeMember)  (Base Class)


---
#### DequeMember\.emitPreamble<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DequeMember.emitPreamble}} -->
The `emitPreamble` method generates and writes C preprocessor directives and function definitions for deque data structures based on the element type and prefix, ensuring that the preamble is only emitted once per type.
- **Inputs**: None
- **Control Flow**:
    - Retrieve the prefix for the current element type using `self.prefix()` and store it in `dp`.
    - Check if `dp` is already in `preambletypes`; if so, return immediately to avoid duplicate preamble emission.
    - Add `dp` to `preambletypes` to mark it as processed.
    - Retrieve the element type using `self.elem_type()` and store it in `element_type`.
    - Write C preprocessor directives to define `DEQUE_NAME` and `DEQUE_T` using `dp` and `element_type`, respectively, to the `header` file.
    - Include the `fd_deque_dynamic.c` template file in the `header` file.
    - Write `#undef` directives to undefine `DEQUE_NAME`, `DEQUE_T`, and `DEQUE_MAX` in the `header` file.
    - Define a static inline function for joining a new deque, handling memory alignment and allocation, and returning a joined deque pointer.
    - Retrieve the global prefix using `self.prefix_global()` and store it in `dp_global`.
    - If the element is in `flattypes`, return immediately as no global preamble is needed.
    - Check if `dp_global` is already in `preambletypes`; if so, return to avoid duplicate global preamble emission.
    - Retrieve the global element type using `self.elem_type_global()` and store it in `element_type_global`.
    - Write similar C preprocessor directives and function definitions for the global deque as done for the local deque, using `dp_global` and `element_type_global`.
- **Output**: The method does not return any value; it writes to the `header` file.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.prefix`](#DequeMemberprefix)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type`](#DequeMemberelem_type)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.prefix_global`](#DequeMemberprefix_global)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type_global`](#DequeMemberelem_type_global)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DequeMember`](#DequeMember)  (Base Class)


---
#### DequeMember\.emitPostamble<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DequeMember.emitPostamble}} -->
The `emitPostamble` method is a placeholder function in the `DequeMember` class that currently does nothing.
- **Inputs**: None
- **Control Flow**:
    - The method is defined but contains only a `pass` statement, indicating no operations are performed.
- **Output**: The method does not return any value or perform any operations.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DequeMember`](#DequeMember)  (Base Class)


---
#### DequeMember\.emitMember<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DequeMember.emitMember}} -->
The `emitMember` method generates and prints a C-style declaration for a deque member in a header file, including a comment indicating its dynamic nature and minimum count if applicable.
- **Inputs**:
    - `self`: An instance of the DequeMember class, which contains attributes like element type, name, and minimum count for the deque.
- **Control Flow**:
    - Check if the 'min' attribute of the instance is set.
    - If 'min' is set, create a string 'min_tag' with the format ' (min cnt {self.min})'.
    - If 'min' is not set, set 'min_tag' to an empty string.
    - Call the 'elem_type' method to get the element type of the deque.
    - Print a formatted string to the 'header' file, declaring a pointer to the deque element type with the instance's name and a comment indicating it is a dynamic deque with the 'min_tag'.
- **Output**: The method does not return any value; it outputs a formatted string to a file object named 'header'.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type`](#DequeMemberelem_type)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DequeMember`](#DequeMember)  (Base Class)


---
#### DequeMember\.emitMemberGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DequeMember.emitMemberGlobal}} -->
The `emitMemberGlobal` method generates and prints a C code line for a global member variable declaration with an optional minimum count tag.
- **Inputs**:
    - `self`: An instance of the DequeMember class, which contains attributes like `name`, `min`, and `element` that are used to generate the C code.
- **Control Flow**:
    - Check if `self.min` is set; if so, create a `min_tag` string with the minimum count, otherwise set `min_tag` to an empty string.
    - Print a formatted string to the `header` file, declaring a `ulong` variable with the name `self.name_offset` and a comment indicating it is a `fd_deque_dynamic` with the `min_tag`.
- **Output**: The method outputs a line of C code to the `header` file, declaring a `ulong` variable for the offset of a deque member.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DequeMember`](#DequeMember)  (Base Class)


---
#### DequeMember\.emitOffsetJoin<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DequeMember.emitOffsetJoin}} -->
The `emitOffsetJoin` method generates C code for a function that joins a deque element at a specified offset in a memory structure.
- **Inputs**:
    - `type_name`: A string representing the type name to be used in the generated function name.
- **Control Flow**:
    - Initialize `ret_type` to `None`.
    - Check if `self.element` is in `simpletypes`, set `ret_type` to `self.element`.
    - If `self.element` is in `flattypes`, set `ret_type` to a formatted string with `namespace` and `self.element`.
    - Otherwise, set `ret_type` to a formatted string with `namespace`, `self.element`, and `_global_t`.
    - Determine [`prefix`](#DequeMemberprefix) based on whether `self.element` is in `flattypes`, using `self.prefix()` or `self.prefix_global()`.
    - Print the C function definition to the `header` file, using `ret_type`, `type_name`, `self.name`, and [`prefix`](#DequeMemberprefix).
- **Output**: The method outputs C code to a file, specifically a function definition for joining a deque element at a given offset.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.prefix`](#DequeMemberprefix)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.prefix_global`](#DequeMemberprefix_global)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DequeMember`](#DequeMember)  (Base Class)


---
#### DequeMember\.emitNew<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DequeMember.emitNew}} -->
The `emitNew` method is a placeholder method in the `DequeMember` class that currently does nothing.
- **Inputs**:
    - `self`: Refers to the instance of the `DequeMember` class.
    - `indent`: An optional string parameter with a default value of an empty string, intended for indentation purposes in code generation.
- **Control Flow**:
    - The method is defined but contains only a `pass` statement, indicating no operations are performed.
- **Output**: The method does not return any value or perform any operations.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DequeMember`](#DequeMember)  (Base Class)


---
#### DequeMember\.emitDecodeFootprint<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DequeMember.emitDecodeFootprint}} -->
The `emitDecodeFootprint` method generates C code to decode the footprint of a deque member, handling both compact and non-compact formats, and calculates the total size required for decoding.
- **Inputs**: None
- **Control Flow**:
    - Check if the deque is compact; if true, declare a `ushort` for length and decode it using `fd_bincode_compact_u16_decode`, otherwise declare a `ulong` and decode using `fd_bincode_uint64_decode`.
    - Check for errors in decoding the length and return the error if any.
    - Determine the maximum length (`_max`) based on the presence of a minimum constraint (`self.min`) and update the total size (`*total_sz`) with alignment and footprint calculations.
    - If the element type is in `fuzzytypes`, calculate the size (`_sz`) and check for multiplication overflow; decode the footprint of bytes using `fd_bincode_bytes_decode_footprint`.
    - If the element type is not in `fuzzytypes`, iterate over each element, decoding the footprint using the appropriate function based on whether the element is a simple type or a complex type.
- **Output**: The method outputs C code to the `body` file stream, which includes declarations, decoding logic, and size calculations for the deque member.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.prefix`](#DequeMemberprefix)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DequeMember`](#DequeMember)  (Base Class)


---
#### DequeMember\.emitDecodeInner<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DequeMember.emitDecodeInner}} -->
The `emitDecodeInner` method generates C code to decode a deque member from a binary format, handling both compact and non-compact encoding, and initializes the deque with the decoded elements.
- **Inputs**: None
- **Control Flow**:
    - Check if the `compact` attribute is true; if so, declare a `ushort` variable for the length and decode it using `fd_bincode_compact_u16_decode_unsafe`; otherwise, declare a `ulong` variable and decode it using `fd_bincode_uint64_decode_unsafe`.
    - If the `min` attribute is set, calculate the maximum length using `fd_ulong_max` and initialize the deque with this maximum length; otherwise, initialize the deque with the decoded length.
    - Iterate over the range of the decoded length, pushing elements to the deque using the `prefix_push_tail_nocopy` method.
    - For each element, check if it is a simple type; if so, decode it using the appropriate `fd_bincode` function; otherwise, initialize the element and decode it using the `namespace_element_decode_inner` function.
- **Output**: The method outputs C code to a file, which decodes a deque from a binary format and initializes it with the decoded elements.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.prefix`](#DequeMemberprefix)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type`](#DequeMemberelem_type)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DequeMember`](#DequeMember)  (Base Class)


---
#### DequeMember\.emitDecodeInnerGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DequeMember.emitDecodeInnerGlobal}} -->
The `emitDecodeInnerGlobal` method generates C code to decode a global deque structure from a binary format, handling different element types and alignment requirements.
- **Inputs**:
    - `self`: An instance of the DequeMember class, containing information about the deque structure to be decoded.
- **Control Flow**:
    - Check if the deque is compact and declare a length variable (`ushort` or `ulong`) accordingly.
    - Decode the length of the deque using either `fd_bincode_compact_u16_decode_unsafe` or `fd_bincode_uint64_decode_unsafe` based on the compactness.
    - Determine the prefix and element type based on whether the element is in `flattypes`.
    - Align the memory allocation pointer `alloc_mem` using `fd_ulong_align_up` with the determined prefix alignment.
    - Determine the deque type based on the element type, choosing from simple types, flat types, or global types.
    - If a minimum size is specified, calculate the maximum size using `fd_ulong_max` and create a new deque with `prefix_join_new`. Otherwise, create a new deque with the decoded length.
    - Iterate over the length of the deque, pushing elements to the deque using `prefix_push_tail_nocopy`.
    - For each element, decode it using the appropriate decode function based on whether the element is a simple type, flat type, or requires a global decode.
    - Calculate the offset of the deque in the structure memory and store it in `self->{self.name}_offset`.
- **Output**: The method outputs C code to a file, which decodes a global deque structure from a binary format, handling memory alignment and element decoding.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.prefix`](#DequeMemberprefix)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.prefix_global`](#DequeMemberprefix_global)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type`](#DequeMemberelem_type)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type_global`](#DequeMemberelem_type_global)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DequeMember`](#DequeMember)  (Base Class)


---
#### DequeMember\.emitEncode<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DequeMember.emitEncode}} -->
The `emitEncode` method generates C code to encode a deque member of a class, handling both compact and non-compact encoding formats.
- **Inputs**:
    - `self`: An instance of the `DequeMember` class, which contains attributes like `name`, `element`, `compact`, and methods like `prefix()` and `elem_type()`.
- **Control Flow**:
    - Check if the deque member (`self->{self.name}`) is not null.
    - If `self.compact` is true, calculate the length of the deque as a `ushort` and encode it using `fd_bincode_compact_u16_encode`.
    - If `self.compact` is false, calculate the length of the deque as a `ulong` and encode it using `fd_bincode_uint64_encode`.
    - Check for encoding errors and return if any occur.
    - Iterate over each element in the deque using a for loop with an iterator initialized by `{self.prefix()}_iter_init`.
    - For each element, determine if it is a simple type or a complex type and encode it accordingly using either `fd_bincode_{simpletypes[self.element]}_encode` or `{namespace}_{self.element}_encode`.
    - Check for encoding errors after encoding each element and return if any occur.
    - If the deque member is null, encode a length of 0 using the appropriate encoding function based on `self.compact`.
    - Check for encoding errors after encoding the length of 0 and return if any occur.
- **Output**: The method outputs C code to the `body` file stream, which encodes the deque member of the class instance.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.prefix`](#DequeMemberprefix)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type`](#DequeMemberelem_type)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DequeMember`](#DequeMember)  (Base Class)


---
#### DequeMember\.emitEncodeGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DequeMember.emitEncodeGlobal}} -->
The `emitEncodeGlobal` method generates C code to encode a global deque member of a class, handling both compact and non-compact encoding scenarios.
- **Inputs**:
    - `self`: An instance of the DequeMember class, which contains attributes like `name`, `element`, `compact`, and methods for prefix and element type determination.
- **Control Flow**:
    - Check if the deque member has an offset (`self->{self.name}_offset`).
    - Calculate the local address of the deque member using the offset.
    - Determine the prefix and element type based on whether the element is in `flattypes`.
    - Join the deque member using the calculated local address and prefix.
    - Calculate the length of the deque using the prefix and encode it using either `fd_bincode_compact_u16_encode` or `fd_bincode_uint64_encode` based on the `compact` attribute.
    - Iterate over the elements of the deque using a prefix-based iterator.
    - Encode each element using the appropriate encoding function based on the element type (simple, flat, or other).
    - Handle errors by returning the error code if encoding fails.
    - If the deque member does not have an offset, encode a length of zero using the appropriate encoding function.
- **Output**: The method outputs C code to the `body` file stream, which encodes the global deque member of the class.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.prefix`](#DequeMemberprefix)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.prefix_global`](#DequeMemberprefix_global)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type`](#DequeMemberelem_type)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type_global`](#DequeMemberelem_type_global)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DequeMember`](#DequeMember)  (Base Class)


---
#### DequeMember\.emitSize<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DequeMember.emitSize}} -->
The `emitSize` method calculates and emits the size of a deque member based on its elements and configuration.
- **Inputs**:
    - `inner`: A parameter that is not used within the method body.
- **Control Flow**:
    - Check if the deque member is not null.
    - If the member is compact, calculate the length as a ushort and add its compact size to the total size.
    - If the member is not compact, add the size of an ulong to the total size.
    - If the element type is 'uchar', calculate the length and add it directly to the total size.
    - If the element type is in simple types, calculate the length and multiply by the size of the element type, then add to the total size.
    - If the element type is not simple, iterate over each element, calculate its size using a namespace-specific function, and add to the total size.
    - If the deque member is null, add 1 to the size if compact, otherwise add the size of an ulong.
- **Output**: The method outputs C code to a file, which calculates the size of a deque member based on its elements and configuration.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.prefix`](#DequeMemberprefix)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type`](#DequeMemberelem_type)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DequeMember`](#DequeMember)  (Base Class)


---
#### DequeMember\.emitWalk<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DequeMember.emitWalk}} -->
The `emitWalk` method generates and prints C code to traverse a deque structure, applying a function to each element based on its type.
- **Inputs**:
    - `inner`: A parameter that is not used within the method but is required by the method signature.
- **Control Flow**:
    - Prints the initial C code to start walking through the deque, including a function call with the deque's name and type.
    - Checks if the deque is not null, then enters a loop to iterate over each element in the deque using an iterator initialized with the deque's prefix.
    - For each element, determines its type and prints a corresponding function call to process the element based on its type (uchar, ulong, uint, or a custom type).
    - Prints the closing C code to end the deque walk, including a function call to indicate the end of the array traversal.
- **Output**: The method does not return any value; it outputs C code to a file-like object named `body`.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.prefix`](#DequeMemberprefix)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type`](#DequeMemberelem_type)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DequeMember`](#DequeMember)  (Base Class)



---
### MapMember<!-- {{#class:firedancer/src/flamenco/types/gen_stubs.MapMember}} -->
- **Members**:
    - `element`: Stores the type of elements contained in the map.
    - `key`: Holds the key type used for accessing elements in the map.
    - `compact`: Indicates if the map uses a compact representation.
    - `minalloc`: Specifies the minimum allocation size for the map.
- **Description**: The `MapMember` class is a specialized type node that represents a map structure with specific element and key types. It provides functionality to handle the map's preamble and postamble, manage memory allocation, and encode or decode the map's footprint and inner structure. The class supports both compact and non-compact representations and can handle global and non-global types, making it versatile for various map implementations.
- **Methods**:
    - [`firedancer/src/flamenco/types/gen_stubs.MapMember.__init__`](#MapMember__init__)
    - [`firedancer/src/flamenco/types/gen_stubs.MapMember.elem_type`](#MapMemberelem_type)
    - [`firedancer/src/flamenco/types/gen_stubs.MapMember.elem_type_global`](#MapMemberelem_type_global)
    - [`firedancer/src/flamenco/types/gen_stubs.MapMember.emitPreamble`](#MapMemberemitPreamble)
    - [`firedancer/src/flamenco/types/gen_stubs.MapMember.emitPostamble`](#MapMemberemitPostamble)
    - [`firedancer/src/flamenco/types/gen_stubs.MapMember.emitMember`](#MapMemberemitMember)
    - [`firedancer/src/flamenco/types/gen_stubs.MapMember.emitMemberGlobal`](#MapMemberemitMemberGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.MapMember.emitOffsetJoin`](#MapMemberemitOffsetJoin)
    - [`firedancer/src/flamenco/types/gen_stubs.MapMember.emitNew`](#MapMemberemitNew)
    - [`firedancer/src/flamenco/types/gen_stubs.MapMember.emitDecodeFootprint`](#MapMemberemitDecodeFootprint)
    - [`firedancer/src/flamenco/types/gen_stubs.MapMember.emitDecodeInner`](#MapMemberemitDecodeInner)
    - [`firedancer/src/flamenco/types/gen_stubs.MapMember.emitDecodeInnerGlobal`](#MapMemberemitDecodeInnerGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.MapMember.emitEncode`](#MapMemberemitEncode)
    - [`firedancer/src/flamenco/types/gen_stubs.MapMember.emitEncodeGlobal`](#MapMemberemitEncodeGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.MapMember.emitSize`](#MapMemberemitSize)
    - [`firedancer/src/flamenco/types/gen_stubs.MapMember.emitWalk`](#MapMemberemitWalk)
- **Inherits From**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode`](#TypeNode)

**Methods**

---
#### MapMember\.\_\_init\_\_<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.MapMember.__init__}} -->
The [`__init__`](#TypeNode__init__) method initializes a `MapMember` instance with attributes derived from a JSON object.
- **Inputs**:
    - `container`: The container object that holds the `MapMember`, though it is not used directly in this method.
    - `json`: A dictionary containing configuration data for the `MapMember`, including keys like 'element', 'key', 'modifier', and 'minalloc'.
- **Control Flow**:
    - The method calls the parent class's [`__init__`](#TypeNode__init__) method with the `json` argument.
    - It assigns the value of `json['element']` to `self.element`.
    - It assigns the value of `json['key']` to `self.key`.
    - It checks if 'modifier' is in `json` and if its value is 'compact', setting `self.compact` to `True` if both conditions are met, otherwise `False`.
    - It checks if 'minalloc' is in `json`, converting its value to an integer and assigning it to `self.minalloc`, or setting `self.minalloc` to 0 if the key is absent.
- **Output**: The method does not return any value; it initializes the instance attributes.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.__init__`](#TypeNode__init__)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.MapMember`](#MapMember)  (Base Class)


---
#### MapMember\.elem\_type<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.MapMember.elem_type}} -->
The `elem_type` method returns the type of the element as a string, either directly if it's a simple type or with a namespace prefix if it's not.
- **Inputs**:
    - `self`: An instance of the MapMember class, which contains attributes like 'element' that determine the type of the element.
- **Control Flow**:
    - Check if the element is in the 'simpletypes' dictionary.
    - If the element is a simple type, return the element as is.
    - If the element is not a a simple type, return a string formatted with a namespace prefix and '_t' suffix.
- **Output**: A string representing the type of the element, either as a simple type or with a namespace prefix.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.MapMember`](#MapMember)  (Base Class)


---
#### MapMember\.elem\_type\_global<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.MapMember.elem_type_global}} -->
The `elem_type_global` method returns the type of an element as a string, appending '_global_t' if the element is not a simple type.
- **Inputs**:
    - `self`: An instance of the MapMember class, which contains attributes like 'element' that determine the type of the element.
- **Control Flow**:
    - Check if 'self.element' is in the 'simpletypes' dictionary.
    - If 'self.element' is a simple type, return 'self.element'.
    - If 'self.element' is not a simple type, return a string formatted as '{namespace}_{self.element}_global_t'.
- **Output**: A string representing the type of the element, either as a simple type or with '_global_t' appended for non-simple types.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.MapMember`](#MapMember)  (Base Class)


---
#### MapMember\.emitPreamble<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.MapMember.emitPreamble}} -->
The `emitPreamble` method generates and writes C code for defining and initializing a red-black tree map structure based on the element type of the map member.
- **Inputs**: None
- **Control Flow**:
    - Retrieve the element type using `self.elem_type()` and construct the map name by appending '_map'.
    - Check if the map name is already in `preambletypes`; if so, return early to avoid duplicate definitions.
    - Add the map name to `preambletypes` to track that it has been processed.
    - Construct the node name by appending '_mapnode' to the element type.
    - Write C code to the `header` file to define a typedef for the map node structure and several macros for the red-black tree implementation.
    - Write the structure definition for the map node, including fields for the element and red-black tree pointers and color.
    - Write a static inline function definition for creating and joining a new map node, handling memory alignment and allocation.
    - If `self.produce_global` is true and the element is not in `flattypes`, repeat the process for the global element type using `self.elem_type_global()`.
- **Output**: The method outputs C code to the `header` file, defining a red-black tree map structure and associated functions and macros.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type`](#DequeMemberelem_type)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type_global`](#DequeMemberelem_type_global)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.MapMember`](#MapMember)  (Base Class)


---
#### MapMember\.emitPostamble<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.MapMember.emitPostamble}} -->
The `emitPostamble` method generates and writes C code for the postamble of a red-black tree map based on the element type and key of the map.
- **Inputs**: None
- **Control Flow**:
    - Determine the element type using `self.elem_type()` and construct the map name.
    - Check if the map name is already in `postambletypes`; if so, return early.
    - Add the map name to `postambletypes` to prevent duplicate postamble generation.
    - Define the node name and write several `#define` directives to the `body` file for the red-black tree configuration.
    - Include the red-black tree implementation file `fd_redblack.c`.
    - Define a comparison function for the map nodes based on the key type, using `memcmp` for certain keys and subtraction for others.
    - Check if the element is in `flattypes` or if `produce_global` is false; if so, return early.
    - Repeat the process for the global element type if applicable, ensuring no duplicate postamble generation.
- **Output**: The method outputs C code to the `body` file, defining macros and a comparison function for a red-black tree map.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type`](#DequeMemberelem_type)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type_global`](#DequeMemberelem_type_global)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.MapMember`](#MapMember)  (Base Class)


---
#### MapMember\.emitMember<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.MapMember.emitMember}} -->
The `emitMember` method generates C code to declare two pointers for a map node pool and root based on the element type of the map member.
- **Inputs**: None
- **Control Flow**:
    - Retrieve the element type by calling `self.elem_type()`.
    - Print a line to the `header` file declaring a pointer to a map node pool using the element type and the member's name.
    - Print a line to the `header` file declaring a pointer to a map node root using the element type and the member's name.
- **Output**: The method outputs C code lines to the `header` file, declaring pointers for a map node pool and root.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type`](#DequeMemberelem_type)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.MapMember`](#MapMember)  (Base Class)


---
#### MapMember\.emitMemberGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.MapMember.emitMemberGlobal}} -->
The `emitMemberGlobal` method generates C code to declare global offset variables for a map member's pool and root.
- **Inputs**: None
- **Control Flow**:
    - Call the [`elem_type`](#DequeMemberelem_type) method to determine the element type of the map member.
    - Print a line to the `header` file declaring a `ulong` variable for the pool offset, using the map member's name.
    - Print a line to the `header` file declaring a `ulong` variable for the root offset, using the map member's name.
- **Output**: The method outputs C code lines to the `header` file, declaring `ulong` variables for the pool and root offsets of a map member.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type`](#DequeMemberelem_type)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.MapMember`](#MapMember)  (Base Class)


---
#### MapMember\.emitOffsetJoin<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.MapMember.emitOffsetJoin}} -->
The `emitOffsetJoin` method generates C code for joining memory structures with offsets for a specific type and element.
- **Inputs**:
    - `type_name`: A string representing the type name to be used in the generated C function names.
- **Control Flow**:
    - Determine the element type based on whether the element is in `flattypes` or not, using `elem_type()` or `elem_type_global()` respectively.
    - Construct the map name and node name by appending '_map' and '_mapnode_t' to the element type.
    - Generate C code for a static function that joins a pool by printing the function definition and body to the `header` file.
    - Generate C code for a static function that joins a root by printing the function definition and body to the `header` file.
- **Output**: The method outputs C code to the `header` file, defining two static functions for joining memory structures with offsets.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type`](#DequeMemberelem_type)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type_global`](#DequeMemberelem_type_global)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.MapMember`](#MapMember)  (Base Class)


---
#### MapMember\.emitNew<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.MapMember.emitNew}} -->
The `emitNew` method is a placeholder method in the `MapMember` class that currently does nothing.
- **Inputs**:
    - `indent`: An optional string parameter that defaults to an empty string, intended to specify the indentation level for any emitted code.
- **Control Flow**:
    - The method is defined but contains no implementation, indicated by the `pass` statement.
- **Output**: The method does not return any value or perform any operations.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.MapMember`](#MapMember)  (Base Class)


---
#### MapMember\.emitDecodeFootprint<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.MapMember.emitDecodeFootprint}} -->
The `emitDecodeFootprint` method calculates and prints the memory footprint required for decoding a map structure based on its element type and configuration.
- **Inputs**: None
- **Control Flow**:
    - Determine the element type and construct map and node names based on it.
    - Check if the map is compact; if so, initialize a ushort length variable and decode it using a compact decoding function, otherwise use a ulong length variable and a standard decoding function.
    - Calculate the count of elements to allocate based on the decoded length and a minimum allocation constraint, if any.
    - Add the alignment and footprint of the map to the total size variable.
    - Check for decoding errors and return if any are found.
    - Iterate over each element in the map, decoding its footprint and checking for errors after each iteration.
- **Output**: The method outputs C code to a file, which includes variable declarations, decoding logic, and error handling for calculating the memory footprint of a map structure.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type`](#DequeMemberelem_type)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.MapMember`](#MapMember)  (Base Class)


---
#### MapMember\.emitDecodeInner<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.MapMember.emitDecodeInner}} -->
The `emitDecodeInner` method generates C code to decode a map structure from a binary format, handling memory allocation and element insertion.
- **Inputs**:
    - `self`: An instance of the MapMember class, which contains metadata about the map structure to be decoded, such as element type, name, compactness, and minimum allocation size.
- **Control Flow**:
    - Determine the element type and construct map and node names based on it.
    - Check if the map is compact; if so, declare a ushort for the length and use a compact decoding function, otherwise use a ulong and a standard decoding function.
    - Allocate memory for the map pool using a function that considers the map length and minimum allocation size.
    - Initialize the map root to NULL.
    - Iterate over the length of the map, acquiring nodes from the pool, initializing elements, decoding them, and inserting them into the map.
- **Output**: The method outputs C code to a file, which decodes a map structure from a binary format, handling memory allocation and element insertion.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type`](#DequeMemberelem_type)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.MapMember`](#MapMember)  (Base Class)


---
#### MapMember\.emitDecodeInnerGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.MapMember.emitDecodeInnerGlobal}} -->
The `emitDecodeInnerGlobal` method generates C code to decode a global map structure from a binary format, handling memory allocation and element decoding.
- **Inputs**:
    - `self`: An instance of the MapMember class, containing attributes like element, key, compact, and minalloc.
- **Control Flow**:
    - Determine the element type based on whether the element is in flattypes, using either [`elem_type`](#DequeMemberelem_type) or [`elem_type_global`](#DequeMemberelem_type_global).
    - Construct map and node names using the element type.
    - Check if the map is compact; if so, decode the length as a ushort, otherwise as a ulong.
    - Align the allocation memory pointer to the map's alignment requirements.
    - If `minalloc` is greater than 0, allocate a pool with the maximum of the decoded length and `minalloc`; otherwise, allocate with the decoded length.
    - Initialize the root node to NULL.
    - Iterate over the length of the map, acquiring a new node from the pool for each element.
    - Create a new element in the node and decode it using either `decode_inner` or `decode_inner_global` based on whether the element is in flattypes.
    - Insert the node into the map.
    - Calculate and store the offsets for the pool and root in the instance.
- **Output**: The method outputs C code to the specified file, which decodes a global map structure from a binary format.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type`](#DequeMemberelem_type)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type_global`](#DequeMemberelem_type_global)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.MapMember`](#MapMember)  (Base Class)


---
#### MapMember\.emitEncode<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.MapMember.emitEncode}} -->
The `emitEncode` method generates C code to encode a map structure into a binary format, handling both compact and non-compact encoding styles.
- **Inputs**: None
- **Control Flow**:
    - Determine the element type and construct map and node names based on it.
    - Check if the map root is not null, indicating there are elements to encode.
    - If compact encoding is enabled, calculate the map size as a `ushort` and encode it using `fd_bincode_compact_u16_encode`.
    - If not compact, calculate the map size as a `ulong` and encode it using `fd_bincode_uint64_encode`.
    - Check for encoding errors and return if any occur.
    - Iterate over each node in the map, encoding each element using the appropriate encode function.
    - If the map root is null, encode a length of zero using the appropriate encoding function based on compactness.
    - Check for encoding errors and return if any occur.
- **Output**: The method outputs C code to the specified file, which encodes the map structure into a binary format.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type`](#DequeMemberelem_type)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.MapMember`](#MapMember)  (Base Class)


---
#### MapMember\.emitEncodeGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.MapMember.emitEncodeGlobal}} -->
The `emitEncodeGlobal` method generates C code to encode a global map structure, handling both compact and non-compact encoding based on the map's root and pool offsets.
- **Inputs**:
    - `self`: An instance of the `MapMember` class, which contains attributes like `element`, `name`, `compact`, and methods to determine element types.
- **Control Flow**:
    - Determine the element type using [`elem_type`](#DequeMemberelem_type) or [`elem_type_global`](#DequeMemberelem_type_global) based on whether the element is in `flattypes`.
    - Construct `mapname` and `nodename` using the element type.
    - Generate code to join the map's root and pool using offsets stored in the instance.
    - Check if the map's root is non-null to proceed with encoding.
    - If `compact` is true, encode the size of the map using `fd_bincode_compact_u16_encode`; otherwise, use `fd_bincode_uint64_encode`.
    - Iterate over the map nodes from minimum to successor, encoding each element using either `encode` or `encode_global` based on whether the element is in `flattypes`.
    - Handle errors by returning if encoding fails.
    - If the map's root is null, encode a length of zero using the appropriate encoding function.
- **Output**: The method outputs C code to the `body` file stream, which encodes the map structure based on the instance's configuration.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type`](#DequeMemberelem_type)
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type_global`](#DequeMemberelem_type_global)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.MapMember`](#MapMember)  (Base Class)


---
#### MapMember\.emitSize<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.MapMember.emitSize}} -->
The `emitSize` method calculates and outputs the size of a map structure based on its elements and whether it is in compact form.
- **Inputs**:
    - `inner`: A parameter that is not used within the method body.
- **Control Flow**:
    - Determine the element type and construct map and node names based on it.
    - Check if the map root exists; if so, proceed to calculate size based on compactness.
    - If compact, calculate the length of the map and add its size to the total size using a compact size function.
    - If not compact, add the size of an unsigned long to the total size.
    - Iterate over each node in the map, adding the size of each element to the total size.
    - If the map root does not exist, add a fixed size based on compactness (1 byte if compact, size of unsigned long if not).
- **Output**: The method outputs C code to a file, which calculates the size of a map structure based on its elements and compactness.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type`](#DequeMemberelem_type)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.MapMember`](#MapMember)  (Base Class)


---
#### MapMember\.emitWalk<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.MapMember.emitWalk}} -->
The `emitWalk` method generates code to iterate over a map structure and apply a function to each element based on its type.
- **Inputs**:
    - `inner`: A parameter that is not used within the method but may be required for method signature consistency.
- **Control Flow**:
    - Determine the element type using `self.elem_type()` and construct map and node names based on this type.
    - Check if the root of the map (`self->{self.name}_root`) is not null to proceed with iteration.
    - Iterate over the map using a for loop, starting from the minimum node and moving to the successor node until no more nodes are left.
    - Within the loop, apply a function `fun` to each element (`n->elem`) based on the element type (`uchar`, `ulong`, `uint`, or other types).
    - For `uchar`, `ulong`, and `uint` types, call `fun` with specific type identifiers and names.
    - For other types, call a specific walk function (`{namespace}_{self.element}_walk`) with the element.
- **Output**: The method outputs C code to the `body` file stream, which iterates over a map and applies a function to each element.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.DequeMember.elem_type`](#DequeMemberelem_type)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.MapMember`](#MapMember)  (Base Class)



---
### PartitionMember<!-- {{#class:firedancer/src/flamenco/types/gen_stubs.PartitionMember}} -->
- **Members**:
    - `dlist_t`: Stores the type of elements in the doubly linked list.
    - `dlist_n`: Stores the name of the doubly linked list.
    - `compact`: Indicates if the partition member uses a compact encoding.
    - `dlist_max`: Stores the maximum number of elements in the doubly linked list.
- **Description**: The `PartitionMember` class is a specialized type of `TypeNode` that represents a partition member with specific attributes related to doubly linked lists. It initializes with a container and a JSON object, extracting and storing information about the list type, list name, compactness, and maximum list size. The class provides methods to emit various code segments for handling preambles, postambles, and member definitions, focusing on managing memory and encoding/decoding operations for the partition's doubly linked list structure.
- **Methods**:
    - [`firedancer/src/flamenco/types/gen_stubs.PartitionMember.__init__`](#PartitionMember__init__)
    - [`firedancer/src/flamenco/types/gen_stubs.PartitionMember.emitPreamble`](#PartitionMemberemitPreamble)
    - [`firedancer/src/flamenco/types/gen_stubs.PartitionMember.emitPostamble`](#PartitionMemberemitPostamble)
    - [`firedancer/src/flamenco/types/gen_stubs.PartitionMember.emitMember`](#PartitionMemberemitMember)
    - [`firedancer/src/flamenco/types/gen_stubs.PartitionMember.emitMemberGlobal`](#PartitionMemberemitMemberGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.PartitionMember.emitNew`](#PartitionMemberemitNew)
    - [`firedancer/src/flamenco/types/gen_stubs.PartitionMember.emitDecodeFootprint`](#PartitionMemberemitDecodeFootprint)
    - [`firedancer/src/flamenco/types/gen_stubs.PartitionMember.emitDecodeInner`](#PartitionMemberemitDecodeInner)
    - [`firedancer/src/flamenco/types/gen_stubs.PartitionMember.emitDecodeInnerGlobal`](#PartitionMemberemitDecodeInnerGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.PartitionMember.emitEncode`](#PartitionMemberemitEncode)
    - [`firedancer/src/flamenco/types/gen_stubs.PartitionMember.emitEncodeGlobal`](#PartitionMemberemitEncodeGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.PartitionMember.emitSize`](#PartitionMemberemitSize)
    - [`firedancer/src/flamenco/types/gen_stubs.PartitionMember.emitWalk`](#PartitionMemberemitWalk)
- **Inherits From**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode`](#TypeNode)

**Methods**

---
#### PartitionMember\.\_\_init\_\_<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PartitionMember.__init__}} -->
The [`__init__`](#TypeNode__init__) method initializes a `PartitionMember` object with attributes from a JSON configuration.
- **Inputs**:
    - `container`: The container object that holds the `PartitionMember`, though it is not used directly in this method.
    - `json`: A dictionary containing configuration data for initializing the `PartitionMember` object, including keys like 'dlist_t', 'dlist_n', 'modifier', and 'dlist_max'.
- **Control Flow**:
    - Call the superclass [`__init__`](#TypeNode__init__) method with the `json` argument to initialize the base class.
    - Extract the 'dlist_t' value from the `json` dictionary and assign it to `self.dlist_t`.
    - Extract the 'dlist_n' value from the `json` dictionary and assign it to `self.dlist_n`.
    - Check if the 'modifier' key in `json` is set to 'compact' and assign the result to `self.compact`.
    - Extract the 'dlist_max' value from `json`, convert it to an integer if it exists, and assign it to `self.dlist_max`; otherwise, set `self.dlist_max` to 0.
- **Output**: The method does not return any value; it initializes the instance attributes of the `PartitionMember` object.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.__init__`](#TypeNode__init__)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PartitionMember`](#PartitionMember)  (Base Class)


---
#### PartitionMember\.emitPreamble<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PartitionMember.emitPreamble}} -->
The `emitPreamble` method generates and writes C preprocessor directives and function definitions for pool and doubly linked list (dlist) management based on the instance's attributes.
- **Inputs**: None
- **Control Flow**:
    - Concatenates `self.dlist_n` with '_pool' and '_dlist' to form `pool_name` and `dlist_name`.
    - Writes C preprocessor directives to define `POOL_NAME`, `POOL_T`, and `POOL_NEXT` using `pool_name` and `self.dlist_t`.
    - Includes the file `fd_pool.c` for pool management functionality.
    - Defines a static inline function for joining a new pool, ensuring memory alignment and updating the allocation pointer.
    - Writes C preprocessor directives to define `DLIST_NAME` and `DLIST_ELE_T` using `dlist_name` and `self.dlist_t`.
    - Includes the file `fd_dlist.c` for doubly linked list management functionality.
    - Defines a static inline function for joining a new dlist, ensuring memory alignment and updating the allocation pointer.
- **Output**: The method outputs C code to a file, specifically writing preprocessor directives and function definitions for managing memory pools and doubly linked lists.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PartitionMember`](#PartitionMember)  (Base Class)


---
#### PartitionMember\.emitPostamble<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PartitionMember.emitPostamble}} -->
The `emitPostamble` method is a placeholder method in the `PartitionMember` class that currently does nothing.
- **Inputs**: None
- **Control Flow**:
    - The method is defined but contains only a `pass` statement, indicating no operations are performed.
- **Output**: There is no output as the method does not perform any operations.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PartitionMember`](#PartitionMember)  (Base Class)


---
#### PartitionMember\.emitMember<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PartitionMember.emitMember}} -->
The `emitMember` method generates C code to declare member variables for a data structure, with variations based on the `compact` attribute.
- **Inputs**: None
- **Control Flow**:
    - Check if the `compact` attribute is True.
    - If `compact` is True, print a C declaration for a `ushort` type member variable with a name based on `self.name`.
    - If `compact` is False, print a C declaration for a `ulong` type member variable with a name based on `self.name`.
    - Print a C declaration for a `ulong` array member variable with a size based on `self.dlist_max`.
    - Print a C declaration for a pointer to a type based on `self.dlist_n` with a name based on `self.name`.
    - Print a C declaration for a pointer to a type based on `self.dlist_t` named `pool`.
- **Output**: The method outputs C code to a file, specifically declarations of member variables for a data structure.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PartitionMember`](#PartitionMember)  (Base Class)


---
#### PartitionMember\.emitMemberGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PartitionMember.emitMemberGlobal}} -->
The `emitMemberGlobal` method generates C code to declare global variables for a partition member, adjusting the type of the length variable based on the compactness setting.
- **Inputs**:
    - `self`: An instance of the PartitionMember class, containing attributes like `name`, `compact`, and `dlist_max`.
- **Control Flow**:
    - Check if the `compact` attribute is True.
    - If `compact` is True, print a declaration for a `ushort` length variable with the member's name.
    - If `compact` is False, print a declaration for a `ulong` length variable with the member's name.
    - Print a declaration for a `ulong` array to store lengths, sized by `dlist_max`.
    - Print declarations for `ulong` variables `pool_offset` and `dlist_offset`.
- **Output**: The method outputs C code to a file, specifically to the `header` file object, which is assumed to be open and writable.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PartitionMember`](#PartitionMember)  (Base Class)


---
#### PartitionMember\.emitNew<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PartitionMember.emitNew}} -->
The `emitNew` method is a placeholder method in the `PartitionMember` class that currently does nothing.
- **Inputs**:
    - `indent`: A string parameter that specifies the indentation to be used, defaulting to an empty string.
- **Control Flow**:
    - The method is defined but contains no implementation, indicated by the `pass` statement.
- **Output**: The method does not return any value or perform any operations.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PartitionMember`](#PartitionMember)  (Base Class)


---
#### PartitionMember\.emitDecodeFootprint<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PartitionMember.emitDecodeFootprint}} -->
The `emitDecodeFootprint` method generates C code to decode and calculate the memory footprint of a data structure based on its configuration and context.
- **Inputs**:
    - `self`: An instance of the PartitionMember class, containing configuration details for the data structure.
- **Control Flow**:
    - Determine the names for the dlist and pool based on the instance's configuration.
    - Check if the instance is configured for compact encoding and print the appropriate C code for decoding the length of the data structure.
    - Print C code to check for errors after decoding the length.
    - Initialize a total count variable and an array to store lengths of sub-elements.
    - Iterate over the maximum number of elements, decoding each length and updating the total count, while checking for errors.
    - Print C code to calculate the total size required for the pool and dlist based on the decoded lengths.
    - Iterate over the decoded length, printing C code to decode the footprint of each sub-element and check for errors.
- **Output**: The method outputs C code to the specified file, which decodes the data structure's length and calculates its memory footprint.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PartitionMember`](#PartitionMember)  (Base Class)


---
#### PartitionMember\.emitDecodeInner<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PartitionMember.emitDecodeInner}} -->
The `emitDecodeInner` method generates C code to decode a data structure from a binary format, handling both compact and non-compact encoding schemes.
- **Inputs**: None
- **Control Flow**:
    - Initialize local variables `dlist_name`, `dlist_t`, and `pool_name` based on instance attributes.
    - Check if the `compact` attribute is True; if so, use `fd_bincode_compact_u16_decode_unsafe` to decode the length, otherwise use `fd_bincode_uint64_decode_unsafe`.
    - Initialize `total_count` to zero and iterate over a range up to `dlist_max`, decoding lengths into `self->{name}_lengths` and accumulating them into `total_count`.
    - Allocate memory for `self->pool` and `self->{name}` using `join_new` functions with `alloc_mem` and the calculated lengths.
    - Iterate over the range of `self->{name}_len`, initializing each element of `self->{name}` and further iterating over the decoded lengths to acquire, initialize, decode, and push elements into the list.
- **Output**: The method outputs C code to the `body` file stream, which decodes a data structure from a binary format.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PartitionMember`](#PartitionMember)  (Base Class)


---
#### PartitionMember\.emitDecodeInnerGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PartitionMember.emitDecodeInnerGlobal}} -->
The `emitDecodeInnerGlobal` method decodes and initializes a global data structure from a binary context, managing memory allocation and element construction.
- **Inputs**:
    - `self`: An instance of the PartitionMember class, providing access to instance variables like dlist_n, dlist_t, and dlist_max.
- **Control Flow**:
    - Determine the names for the dlist and pool based on instance variables.
    - Check if the compact flag is set to choose the appropriate decoding function for the length of the list.
    - Initialize a total_count variable to accumulate the total number of elements across all lists.
    - Iterate over the maximum number of lists (dlist_max) to decode the length of each list and update total_count.
    - Align the allocation memory pointer for the pool and create a new pool using the total_count.
    - Align the allocation memory pointer for the dlist and create a new dlist using the decoded length.
    - Iterate over each list in the dlist, initializing each list and its elements.
    - For each element, acquire a new element from the pool, initialize it, decode its inner structure, and add it to the list.
    - Calculate and store the offsets for the pool and dlist relative to the struct memory.
- **Output**: The method outputs the initialized global data structure with decoded elements, updating the pool and dlist offsets in the instance.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PartitionMember`](#PartitionMember)  (Base Class)


---
#### PartitionMember\.emitEncode<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PartitionMember.emitEncode}} -->
The `emitEncode` method generates C code to encode a data structure, handling both compact and non-compact encoding formats, and iterating over elements to encode them individually.
- **Inputs**: None
- **Control Flow**:
    - Initialize local variables `name`, `dlist_name`, and `dlist_t` from instance attributes.
    - Check if `self->{name}` is not null to determine if encoding should proceed.
    - If `self.compact` is true, encode `self->{self.name}_len` using `fd_bincode_compact_u16_encode`; otherwise, use `fd_bincode_uint64_encode`.
    - Check for encoding errors and return if any occur.
    - Iterate over `self.dlist_max` to encode each element in `self->{self.name}_lengths` using `fd_bincode_uint64_encode`.
    - Check for encoding errors after each element encoding and return if any occur.
    - Iterate over `self->{self.name}_len` to encode each element in the doubly linked list using a forward iterator.
    - For each element, retrieve it using the iterator and encode it using the appropriate encode function for `dlist_t`.
    - Check for encoding errors after each element encoding and return if any occur.
    - If `self->{name}` is null, encode `self->{self.name}_len` using the same method as before, depending on `self.compact`.
    - Check for encoding errors and return if any occur.
- **Output**: The method outputs C code to the `body` file stream, which encodes the data structure represented by the instance.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PartitionMember`](#PartitionMember)  (Base Class)


---
#### PartitionMember\.emitEncodeGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PartitionMember.emitEncodeGlobal}} -->
The `emitEncodeGlobal` method is a placeholder for encoding global data structures related to partition members, but currently does nothing.
- **Inputs**: None
- **Control Flow**:
    - The method is defined but contains no implementation, indicated by the `pass` statement.
- **Output**: There is no output as the method is not implemented.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PartitionMember`](#PartitionMember)  (Base Class)


---
#### PartitionMember\.emitSize<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PartitionMember.emitSize}} -->
The `emitSize` method calculates and prints the size of a data structure based on its configuration and elements.
- **Inputs**:
    - `inner`: An unused parameter in the method, possibly intended for future use or to match a required signature.
- **Control Flow**:
    - Initialize local variables `name`, `dlist_name`, `dlist_t`, and `pool` using instance attributes.
    - Check if the `compact` attribute is True; if so, calculate the length of the pool and add its compact size to `size`.
    - If `compact` is False, add the size of an `ulong` to `size`.
    - Add the product of `dlist_max` and the size of an `ulong` to `size`.
    - Check if the instance attribute corresponding to `name` is not None.
    - Iterate over the elements in the list associated with `name`, using a nested loop to iterate over elements in each sublist.
    - For each element, calculate its size using a type-specific size function and add it to `size`.
- **Output**: The method outputs size calculations to a file specified by the `body` variable, but does not return a value.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PartitionMember`](#PartitionMember)  (Base Class)


---
#### PartitionMember\.emitWalk<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.PartitionMember.emitWalk}} -->
The `emitWalk` method generates C code to iterate over a doubly linked list and apply a function to each element based on its type.
- **Inputs**:
    - `inner`: A parameter that is not used within the method body.
- **Control Flow**:
    - Initialize local variables `name`, `dlist_name`, and `dlist_t` using instance attributes.
    - Print a C code block that checks if the list `self->{name}` is not null.
    - Print a C code block to iterate over the list elements using a for loop with index `i`.
    - Within the loop, initialize an iterator for the doubly linked list and iterate over its elements.
    - For each element, determine its type (`uchar`, `ulong`, `uint`, or other) and print the corresponding C code to apply a function `fun` to the element.
    - Close all opened C code blocks with appropriate closing braces.
- **Output**: The method outputs C code to the `body` file stream, which iterates over a doubly linked list and applies a function to each element based on its type.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.PartitionMember`](#PartitionMember)  (Base Class)



---
### TreapMember<!-- {{#class:firedancer/src/flamenco/types/gen_stubs.TreapMember}} -->
- **Members**:
    - `treap_t`: Stores the type of the treap elements.
    - `treap_query_t`: Stores the type used for querying the treap.
    - `treap_cmp`: Stores the comparison function for the treap.
    - `treap_lt`: Stores the less-than function for the treap.
    - `min`: Stores the minimum number of elements in the treap.
    - `compact`: Indicates if the treap is in compact mode.
    - `treap_prio`: Stores the priority function for the treap, if any.
    - `treap_optimize`: Stores the optimization setting for the treap, if any.
    - `rev`: Indicates if the treap should be iterated in reverse order.
    - `upsert`: Indicates if upsert operations are allowed on the treap.
    - `min_name`: Stores the name of the minimum constant for the treap.
- **Description**: The TreapMember class is a specialized data structure that extends the TypeNode class to represent a treap, which is a combination of a binary search tree and a heap. It is initialized with a JSON configuration that specifies various properties of the treap, such as the types of elements and queries, comparison functions, and additional settings like compact mode, priority, and optimization. The class also supports reverse iteration and upsert operations, and it defines methods for encoding and decoding the treap's footprint and inner structure.
- **Methods**:
    - [`firedancer/src/flamenco/types/gen_stubs.TreapMember.__init__`](#TreapMember__init__)
    - [`firedancer/src/flamenco/types/gen_stubs.TreapMember.emitPreamble`](#TreapMemberemitPreamble)
    - [`firedancer/src/flamenco/types/gen_stubs.TreapMember.emitPostamble`](#TreapMemberemitPostamble)
    - [`firedancer/src/flamenco/types/gen_stubs.TreapMember.emitMember`](#TreapMemberemitMember)
    - [`firedancer/src/flamenco/types/gen_stubs.TreapMember.emitMemberGlobal`](#TreapMemberemitMemberGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.TreapMember.emitNew`](#TreapMemberemitNew)
    - [`firedancer/src/flamenco/types/gen_stubs.TreapMember.emitDecodeFootprint`](#TreapMemberemitDecodeFootprint)
    - [`firedancer/src/flamenco/types/gen_stubs.TreapMember.emitDecodeInner`](#TreapMemberemitDecodeInner)
    - [`firedancer/src/flamenco/types/gen_stubs.TreapMember.emitDecodeInnerGlobal`](#TreapMemberemitDecodeInnerGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.TreapMember.emitEncode`](#TreapMemberemitEncode)
    - [`firedancer/src/flamenco/types/gen_stubs.TreapMember.emitEncodeGlobal`](#TreapMemberemitEncodeGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.TreapMember.emitSize`](#TreapMemberemitSize)
    - [`firedancer/src/flamenco/types/gen_stubs.TreapMember.emitWalk`](#TreapMemberemitWalk)
- **Inherits From**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode`](#TypeNode)

**Methods**

---
#### TreapMember\.\_\_init\_\_<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.TreapMember.__init__}} -->
The [`__init__`](#TypeNode__init__) method initializes a `TreapMember` object with various attributes from a JSON configuration.
- **Inputs**:
    - `container`: An object or structure that contains or manages the `TreapMember`, though it is not directly used in this method.
    - `json`: A dictionary containing configuration data for initializing the `TreapMember` attributes.
- **Control Flow**:
    - Call the superclass [`__init__`](#TypeNode__init__) method with the `json` argument to initialize inherited attributes.
    - Extract and assign the `treap_t`, `treap_query_t`, `treap_cmp`, and `treap_lt` attributes from the `json` dictionary.
    - Convert the `min` value from the `json` dictionary to an integer and assign it to the `min` attribute.
    - Determine if the `compact` attribute should be `True` based on the presence and value of the `modifier` key in the `json` dictionary.
    - Assign the `treap_prio` attribute from the `json` dictionary if it exists, otherwise set it to `None`.
    - Assign the `treap_optimize` attribute from the `json` dictionary if it exists, otherwise set it to `None`.
    - Set the `rev` attribute to the value of the `rev` key in the `json` dictionary, defaulting to `False` if not present.
    - Set the `upsert` attribute to the value of the `upsert` key in the `json` dictionary, defaulting to `False` if not present.
    - Construct the `min_name` attribute by converting the `name` attribute to uppercase and appending '_MIN'.
- **Output**: The method does not return any value; it initializes the instance attributes of the `TreapMember` object.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.__init__`](#TypeNode__init__)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.TreapMember`](#TreapMember)  (Base Class)


---
#### TreapMember\.emitPreamble<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.TreapMember.emitPreamble}} -->
The `emitPreamble` method generates and writes C preprocessor directives and function definitions for a treap data structure to a header file, ensuring that the necessary types and functions are defined only once.
- **Inputs**: None
- **Control Flow**:
    - Retrieve the name of the treap and its type from the instance variables.
    - Check if the treap type has already been processed by looking it up in the `preambletypes` set.
    - If the treap type is not in `preambletypes`, add it to the set to prevent duplicate processing.
    - Define several C preprocessor macros for the treap and pool names, types, and related properties.
    - Write C code to the header file to define a function for joining a new pool and treap, including memory alignment and allocation logic.
    - Include necessary C template files for pool and treap implementations.
    - Optionally define additional macros if optimization or priority settings are specified in the instance variables.
- **Output**: The method outputs C preprocessor directives and function definitions to a header file, ensuring that the treap and pool structures are properly defined and initialized.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.TreapMember`](#TreapMember)  (Base Class)


---
#### TreapMember\.emitPostamble<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.TreapMember.emitPostamble}} -->
The `emitPostamble` method is a placeholder method in the `TreapMember` class that currently does nothing.
- **Inputs**: None
- **Control Flow**:
    - The method is defined but contains only a `pass` statement, indicating no operations are performed.
- **Output**: There is no output or return value from this method as it is currently a no-op.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.TreapMember`](#TreapMember)  (Base Class)


---
#### TreapMember\.emitMember<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.TreapMember.emitMember}} -->
The `emitMember` method outputs C code to declare two pointer variables for a treap and its associated pool in a header file.
- **Inputs**: None
- **Control Flow**:
    - The method prints a line declaring a pointer to a pool of type `self.treap_t` to the header file.
    - It then prints a line declaring a pointer to a treap of type `self.name + '_treap_t'` to the header file.
- **Output**: The method does not return any value; it writes to a file object named `header`.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.TreapMember`](#TreapMember)  (Base Class)


---
#### TreapMember\.emitMemberGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.TreapMember.emitMemberGlobal}} -->
The `emitMemberGlobal` method writes declarations for global offsets of a pool and a treap to a header file.
- **Inputs**: None
- **Control Flow**:
    - The method prints a line declaring a `ulong` type variable named `pool_offset` to the header file.
    - It then prints another line declaring a `ulong` type variable named `treap_offset` to the header file.
- **Output**: The method does not return any value; it outputs directly to a file specified by the `header` variable.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.TreapMember`](#TreapMember)  (Base Class)


---
#### TreapMember\.emitNew<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.TreapMember.emitNew}} -->
The `emitNew` method is a placeholder method in the `TreapMember` class that currently does nothing.
- **Inputs**:
    - `indent`: An optional string parameter that defaults to an empty string, intended for indentation purposes in code generation.
- **Control Flow**:
    - The method is defined but contains no implementation, indicated by the `pass` statement.
- **Output**: The method does not return any value or perform any operations.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.TreapMember`](#TreapMember)  (Base Class)


---
#### TreapMember\.emitDecodeFootprint<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.TreapMember.emitDecodeFootprint}} -->
The `emitDecodeFootprint` method generates C code to decode a treap's footprint and calculate its memory size requirements.
- **Inputs**: None
- **Control Flow**:
    - Initialize `treap_name`, `pool_name`, and `treap_t` based on the instance's `name` and `treap_t` attributes.
    - Check if the `compact` attribute is true; if so, declare a `ushort` for `treap_name_len` and decode it using `fd_bincode_compact_u16_decode`.
    - If `compact` is false, declare a `ulong` for `treap_name_len` and decode it using `fd_bincode_uint64_decode`.
    - Check for errors in decoding and return the error if any.
    - Calculate `treap_name_max` as the maximum of `treap_name_len`, `min_name`, and 1.
    - Add the alignment and footprint of `pool_name` and `treap_name` to `total_sz` using `treap_name_max`.
    - Iterate over the range of `treap_name_len`, decoding the footprint of each element using `treap_t_decode_footprint_inner` and checking for errors.
- **Output**: The method outputs C code to the `body` file stream, which includes variable declarations, decoding logic, error handling, and memory size calculations.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.TreapMember`](#TreapMember)  (Base Class)


---
#### TreapMember\.emitDecodeInner<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.TreapMember.emitDecodeInner}} -->
The `emitDecodeInner` method generates C code to decode a treap data structure from a binary format, handling memory allocation and element insertion.
- **Inputs**:
    - `self`: An instance of the `TreapMember` class, which contains configuration and state for the treap being decoded.
- **Control Flow**:
    - Determine the names for the treap and pool based on the instance's name attribute.
    - Check if the compact flag is set to decide the type of length variable (ushort or ulong) and the corresponding decode function.
    - Calculate the maximum size for the treap using the decoded length and a minimum size constant.
    - Allocate memory for the pool and treap using the calculated maximum size.
    - Iterate over the number of elements specified by the decoded length.
    - For each element, acquire memory from the pool, initialize the element, and decode its inner structure.
    - If the upsert flag is set, check for duplicate entries in the treap and remove them before inserting the new element.
    - Insert the decoded element into the treap.
- **Output**: The method outputs C code to a file, which decodes a treap from a binary format, handling memory allocation and element insertion.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.TreapMember`](#TreapMember)  (Base Class)


---
#### TreapMember\.emitDecodeInnerGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.TreapMember.emitDecodeInnerGlobal}} -->
The `emitDecodeInnerGlobal` method decodes and initializes a global treap structure from a binary context, handling memory alignment and element insertion.
- **Inputs**:
    - `self`: An instance of the TreapMember class, containing attributes like name, treap_t, compact, upsert, and min_name.
- **Control Flow**:
    - Determine the names for the treap and pool based on the instance's name attribute.
    - Check if the compact attribute is True; if so, decode a ushort length for the treap, otherwise decode a ulong length.
    - Calculate the maximum treap size using the decoded length and the instance's min_name attribute.
    - Align the allocation memory for the pool and create a new pool using the calculated maximum size.
    - Align the allocation memory for the treap and create a new treap using the calculated maximum size.
    - Iterate over the number of elements specified by the treap length.
    - For each element, acquire a new element from the pool, initialize it, and decode its inner structure.
    - If the upsert attribute is True, check for duplicate entries in the treap and remove them before inserting the new element.
    - Insert the new element into the treap.
    - Calculate and store the offsets for the pool and treap in the instance.
- **Output**: The method does not return a value but modifies the instance's pool_offset and treap_offset attributes to reflect the memory offsets of the pool and treap.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.TreapMember`](#TreapMember)  (Base Class)


---
#### TreapMember\.emitEncode<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.TreapMember.emitEncode}} -->
The `emitEncode` method generates C code to encode a treap data structure into a binary format, handling both compact and non-compact encoding, and iterating over the treap elements in either forward or reverse order based on configuration.
- **Inputs**:
    - `self`: An instance of the `TreapMember` class, which contains attributes like `name`, `treap_t`, `compact`, `rev`, and others that influence the encoding process.
- **Control Flow**:
    - Initialize local variables `name`, `treap_name`, and `treap_t` from the instance attributes.
    - Check if `self->treap` is not null to determine if there are elements to encode.
    - If `self.compact` is true, calculate the number of elements in the treap as a `ushort` and encode it using `fd_bincode_compact_u16_encode`; otherwise, use `ulong` and `fd_bincode_uint64_encode`.
    - Check for encoding errors and return if any occur.
    - If `self.rev` is true, iterate over the treap elements in reverse order using a reverse iterator; otherwise, use a forward iterator.
    - For each element, encode it using the appropriate encoding function derived from `treap_t` and check for errors.
    - If `self->treap` is null, encode a length of zero using the same compact or non-compact method as above.
- **Output**: The method outputs C code to the `body` file stream, which encodes the treap structure into a binary format, handling both the element count and individual element encoding.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.TreapMember`](#TreapMember)  (Base Class)


---
#### TreapMember\.emitEncodeGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.TreapMember.emitEncodeGlobal}} -->
The `emitEncodeGlobal` method generates C code to encode a global treap structure into a binary format, handling both compact and non-compact encoding, and iterating over elements in forward or reverse order based on configuration.
- **Inputs**: None
- **Control Flow**:
    - Initialize local variables for treap and pool names based on the instance's name.
    - Print C code to join the pool and treap using offsets from the instance.
    - Check if the treap is not null and proceed with encoding.
    - Determine the length of the treap and encode it using either compact or standard encoding based on the `compact` attribute.
    - Check for encoding errors and return if any occur.
    - Iterate over the treap elements using either forward or reverse iterators based on the `rev` attribute.
    - Encode each element and check for errors, returning if any occur.
    - If the treap is null, encode a length of zero using the appropriate encoding method.
- **Output**: The method outputs C code to the `body` file stream, which encodes the treap structure into a binary format.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.TreapMember`](#TreapMember)  (Base Class)


---
#### TreapMember\.emitSize<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.TreapMember.emitSize}} -->
The `emitSize` method calculates and outputs the size of a data structure, considering whether it is compact and iterating over elements in a treap if present.
- **Inputs**:
    - `inner`: An argument that is not used within the method body.
- **Control Flow**:
    - Initialize variables `name`, `treap_name`, `treap_t`, and `pool` based on the object's attributes.
    - Check if the `compact` attribute is True; if so, calculate the size using a compact ushort length and add its size to the total size.
    - If `compact` is False, add the size of an `ulong` to the total size.
    - Check if the `treap` attribute is not None; if so, iterate over the elements in the treap using a forward iterator.
    - For each element in the treap, calculate its size using the element's size method and add it to the total size.
- **Output**: The method outputs the size calculation statements to a file-like object `body`, but does not return any value.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.TreapMember`](#TreapMember)  (Base Class)


---
#### TreapMember\.emitWalk<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.TreapMember.emitWalk}} -->
The `emitWalk` method generates C code to iterate over elements in a treap data structure and applies a function to each element based on its type.
- **Inputs**:
    - `inner`: A parameter that is not used within the method body.
- **Control Flow**:
    - Initialize `treap_name` and `treap_t` using the instance's `name` and `treap_t` attributes.
    - Print the beginning of an if-statement checking if `self->treap` is not null.
    - Print a for-loop initialization for a forward iterator over the treap using `treap_name` and `self->pool`.
    - Print the condition to check if the iterator has reached the end of the treap.
    - Print the statement to advance the iterator to the next element.
    - Inside the loop, print a statement to retrieve the current element from the iterator.
    - Check the type of `treap_t` and print a corresponding function call to process the element based on its type.
    - Close the for-loop and if-statement with print statements.
- **Output**: The method outputs C code to the `body` file stream, which includes a loop over the treap elements and function calls to process each element based on its type.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.TreapMember`](#TreapMember)  (Base Class)



---
### DlistMember<!-- {{#class:firedancer/src/flamenco/types/gen_stubs.DlistMember}} -->
- **Members**:
    - `dlist_t`: Stores the type of the doubly linked list elements.
    - `dlist_n`: Stores the name of the doubly linked list.
    - `compact`: Indicates if the list is in compact mode based on a modifier in the JSON.
- **Description**: The `DlistMember` class is a specialized type of `TypeNode` that represents a member of a doubly linked list, initialized with a container and JSON data. It manages the type and name of the list, and determines if the list should be compact based on the JSON input. The class provides methods to emit various code segments for handling the preamble, postamble, member definitions, and encoding/decoding operations for the doubly linked list.
- **Methods**:
    - [`firedancer/src/flamenco/types/gen_stubs.DlistMember.__init__`](#DlistMember__init__)
    - [`firedancer/src/flamenco/types/gen_stubs.DlistMember.emitPreamble`](#DlistMemberemitPreamble)
    - [`firedancer/src/flamenco/types/gen_stubs.DlistMember.emitPostamble`](#DlistMemberemitPostamble)
    - [`firedancer/src/flamenco/types/gen_stubs.DlistMember.emitMember`](#DlistMemberemitMember)
    - [`firedancer/src/flamenco/types/gen_stubs.DlistMember.emitMemberGlobal`](#DlistMemberemitMemberGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.DlistMember.emitNew`](#DlistMemberemitNew)
    - [`firedancer/src/flamenco/types/gen_stubs.DlistMember.emitDecodeFootprint`](#DlistMemberemitDecodeFootprint)
    - [`firedancer/src/flamenco/types/gen_stubs.DlistMember.emitDecodeInner`](#DlistMemberemitDecodeInner)
    - [`firedancer/src/flamenco/types/gen_stubs.DlistMember.emitDecodeInnerGlobal`](#DlistMemberemitDecodeInnerGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.DlistMember.emitEncode`](#DlistMemberemitEncode)
    - [`firedancer/src/flamenco/types/gen_stubs.DlistMember.emitEncodeGlobal`](#DlistMemberemitEncodeGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.DlistMember.emitSize`](#DlistMemberemitSize)
    - [`firedancer/src/flamenco/types/gen_stubs.DlistMember.emitWalk`](#DlistMemberemitWalk)
- **Inherits From**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode`](#TypeNode)

**Methods**

---
#### DlistMember\.\_\_init\_\_<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DlistMember.__init__}} -->
The [`__init__`](#TypeNode__init__) method initializes a `DlistMember` object by setting its attributes based on a JSON configuration.
- **Inputs**:
    - `container`: The container object that holds the `DlistMember`, though it is not used directly in this method.
    - `json`: A dictionary containing configuration data for initializing the `DlistMember`, including keys 'dlist_t', 'dlist_n', and optionally 'modifier'.
- **Control Flow**:
    - Call the parent class's [`__init__`](#TypeNode__init__) method with the `json` argument.
    - Set the `dlist_t` attribute to the value associated with the 'dlist_t' key in the `json` dictionary.
    - Set the `dlist_n` attribute to the value associated with the 'dlist_n' key in the `json` dictionary.
    - Check if the 'modifier' key exists in the `json` dictionary and if its value is 'compact'; set the `compact` attribute to `True` if both conditions are met, otherwise set it to `False`.
- **Output**: The method does not return any value; it initializes the object's attributes.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.__init__`](#TypeNode__init__)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DlistMember`](#DlistMember)  (Base Class)


---
#### DlistMember\.emitPreamble<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DlistMember.emitPreamble}} -->
The `emitPreamble` method generates and writes C preprocessor directives and function definitions for pool and doubly linked list (dlist) management based on the instance's attributes.
- **Inputs**: None
- **Control Flow**:
    - Concatenates '_pool' and '_dlist' to `self.dlist_n` to form `pool_name` and `dlist_name`.
    - Writes C preprocessor directives to define `POOL_NAME`, `POOL_T`, and `POOL_NEXT` using `pool_name` and `self.dlist_t`.
    - Includes the file `fd_pool.c` for pool management.
    - Defines a static inline function for joining a new pool, handling memory alignment and allocation, and returning a joined pool.
    - Writes C preprocessor directives to define `DLIST_NAME` and `DLIST_ELE_T` using `dlist_name` and `self.dlist_t`.
    - Includes the file `fd_dlist.c` for dlist management.
    - Defines a static inline function for joining a new dlist, handling memory alignment and allocation, and returning a joined dlist.
- **Output**: The method outputs C code to a file, specifically writing preprocessor directives and function definitions for managing memory pools and doubly linked lists.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DlistMember`](#DlistMember)  (Base Class)


---
#### DlistMember\.emitPostamble<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DlistMember.emitPostamble}} -->
The `emitPostamble` method is a placeholder method in the `DlistMember` class that currently does nothing.
- **Inputs**: None
- **Control Flow**:
    - The method is defined but contains only a `pass` statement, indicating it does nothing when called.
- **Output**: There is no output or return value from this method as it is currently a no-op.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DlistMember`](#DlistMember)  (Base Class)


---
#### DlistMember\.emitMember<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DlistMember.emitMember}} -->
The `emitMember` method generates C code to declare struct members for a doubly linked list and its associated pool, with different types based on a compact flag.
- **Inputs**: None
- **Control Flow**:
    - Check if the `compact` attribute is True.
    - If `compact` is True, print a declaration for a `ushort` length member with the name pattern `{name}_len`.
    - If `compact` is False, print a declaration for a `ulong` length member with the name pattern `{name}_len`.
    - Print a declaration for a pointer to a doubly linked list type with the name pattern `{dlist_n}_dlist_t * {name}`.
    - Print a declaration for a pointer to a pool type with the name pattern `{dlist_t} * pool`.
- **Output**: The method outputs C code to a file, declaring struct members for a doubly linked list and its pool.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DlistMember`](#DlistMember)  (Base Class)


---
#### DlistMember\.emitMemberGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DlistMember.emitMemberGlobal}} -->
The `emitMemberGlobal` method generates C code to declare global variables for a member, adjusting the type of the length variable based on the `compact` attribute.
- **Inputs**: None
- **Control Flow**:
    - Check if the `compact` attribute is True.
    - If `compact` is True, print a C declaration for a `ushort` length variable with the member's name suffixed by `_len`.
    - If `compact` is False, print a C declaration for a `ulong` length variable with the member's name suffixed by `_len`.
    - Print C declarations for `ulong` variables named `pool_offset` and `dlist_offset`.
- **Output**: The method outputs C code to the `header` file stream, declaring global variables for a member.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DlistMember`](#DlistMember)  (Base Class)


---
#### DlistMember\.emitNew<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DlistMember.emitNew}} -->
The `emitNew` method is a placeholder method in the `DlistMember` class that currently does nothing.
- **Inputs**:
    - `indent`: An optional string argument that defaults to an empty string, intended for indentation purposes in code generation.
- **Control Flow**:
    - The method is defined but contains no implementation, indicated by the `pass` statement.
- **Output**: The method does not return any value or perform any operations.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DlistMember`](#DlistMember)  (Base Class)


---
#### DlistMember\.emitDecodeFootprint<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DlistMember.emitDecodeFootprint}} -->
The `emitDecodeFootprint` method generates C code to decode and calculate the memory footprint of a dynamic list structure based on its length and alignment requirements.
- **Inputs**: None
- **Control Flow**:
    - Determine the names for the dynamic list and pool based on the instance variables `dlist_n` and `dlist_t`.
    - Check if the `compact` flag is set to decide whether to use a 16-bit or 64-bit length variable for decoding.
    - Print C code to declare a length variable and decode it using the appropriate function (`fd_bincode_compact_u16_decode` or `fd_bincode_uint64_decode`).
    - Print C code to check for decoding errors and return the error if any.
    - Print C code to calculate and add the alignment and footprint of the pool and dynamic list to `total_sz`.
    - Print C code to iterate over each element in the list, decode its footprint, and check for errors.
- **Output**: The method outputs C code to the `body` file stream, which includes declarations, decoding logic, error handling, and footprint calculations for a dynamic list.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DlistMember`](#DlistMember)  (Base Class)


---
#### DlistMember\.emitDecodeInner<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DlistMember.emitDecodeInner}} -->
The `emitDecodeInner` method generates C code to decode a list of elements from a binary format into a data structure, handling memory allocation and element initialization.
- **Inputs**:
    - `self`: An instance of the DlistMember class, containing attributes like dlist_n, dlist_t, and compact, which are used to generate the decoding code.
- **Control Flow**:
    - Determine the names for the dlist and pool based on the instance's attributes.
    - Check if the compact flag is set to decide which decoding function to use for the length of the list.
    - Print C code to decode the length of the list using either a compact or standard decoding function.
    - Print C code to allocate memory for the pool and dlist using the decoded length.
    - Print C code to initialize the dlist.
    - Iterate over the length of the list, printing C code to acquire, initialize, decode, and insert each element into the dlist.
- **Output**: The method outputs C code to the specified file, which decodes a list of elements from a binary format into a data structure, handling memory allocation and element initialization.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DlistMember`](#DlistMember)  (Base Class)


---
#### DlistMember\.emitDecodeInnerGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DlistMember.emitDecodeInnerGlobal}} -->
The `emitDecodeInnerGlobal` method decodes and initializes a global doubly-linked list and its associated memory pool from a binary context.
- **Inputs**:
    - `self`: An instance of the DlistMember class, containing attributes like dlist_n, dlist_t, and compact.
- **Control Flow**:
    - Determine the names for the doubly-linked list and pool based on the instance's attributes.
    - Check if the compact mode is enabled and decode the length of the list using the appropriate function.
    - Align the allocation memory pointer to the pool's alignment and initialize the pool with the decoded length.
    - Align the allocation memory pointer to the doubly-linked list's alignment and initialize the list with the decoded length.
    - Iterate over the length of the list, acquiring elements from the pool, initializing them, decoding their inner structure, and adding them to the list.
    - Calculate and store the offsets for the pool and list relative to the structure memory.
- **Output**: The method outputs C code to a file, which decodes and initializes a global doubly-linked list and its memory pool from a binary context.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DlistMember`](#DlistMember)  (Base Class)


---
#### DlistMember\.emitEncode<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DlistMember.emitEncode}} -->
The `emitEncode` method generates C code to encode a doubly linked list (dlist) structure, handling both compact and non-compact encoding formats.
- **Inputs**: None
- **Control Flow**:
    - Initialize local variables `name`, `dlist_name`, and `dlist_t` from instance attributes.
    - Check if the dlist (`self->{name}`) is not null.
    - If `self.compact` is true, encode the length of the dlist using `fd_bincode_compact_u16_encode`; otherwise, use `fd_bincode_uint64_encode`.
    - Check for encoding errors and return the error if any occur.
    - Iterate over each element in the dlist using a forward iterator initialized with `dlist_name_iter_fwd_init`.
    - For each element, retrieve it using `dlist_name_iter_ele` and encode it using the appropriate encode function derived from `dlist_t`.
    - Check for encoding errors after each element encoding and return the error if any occur.
    - If the dlist is null, encode the length as zero using the same encoding method as above and check for errors.
- **Output**: The method outputs C code to the specified file stream, encoding the dlist structure and handling potential errors.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DlistMember`](#DlistMember)  (Base Class)


---
#### DlistMember\.emitEncodeGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DlistMember.emitEncodeGlobal}} -->
The `emitEncodeGlobal` method is a placeholder for encoding global data structures related to a doubly linked list (dlist) in the `DlistMember` class.
- **Inputs**: None
- **Control Flow**:
    - The method is defined but contains no implementation, indicated by the `pass` statement.
- **Output**: There is no output as the method is not implemented.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DlistMember`](#DlistMember)  (Base Class)


---
#### DlistMember\.emitSize<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DlistMember.emitSize}} -->
The `emitSize` method calculates and prints the size of a data structure based on its elements and configuration.
- **Inputs**:
    - `inner`: A parameter that is not used within the method body.
- **Control Flow**:
    - Initialize local variables `name`, `dlist_name`, `dlist_t`, and `pool` using instance attributes.
    - Check if the `compact` attribute is True; if so, calculate the length of the pool and add its compact size to the total size.
    - If `compact` is False, add the size of an unsigned long to the total size.
    - Print a conditional statement to check if the instance attribute corresponding to `name` is not null.
    - Iterate over elements in the doubly linked list using a forward iterator, checking for completion and moving to the next element.
    - For each element, calculate its size using a type-specific size function and add it to the total size.
    - Close the conditional and loop blocks with appropriate braces.
- **Output**: The method outputs C code to a file, which calculates the size of a data structure based on its elements and configuration.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DlistMember`](#DlistMember)  (Base Class)


---
#### DlistMember\.emitWalk<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.DlistMember.emitWalk}} -->
The `emitWalk` method generates C code to iterate over a doubly linked list and apply a function to each element based on its type.
- **Inputs**:
    - `inner`: A parameter that is not used within the method but may be intended for future use or for compatibility with other methods.
- **Control Flow**:
    - Initialize local variables `name`, `dlist_name`, and `dlist_t` using instance attributes `self.name`, `self.dlist_n`, and `self.dlist_t` respectively.
    - Print a C code snippet to check if the list `self->{name}` is not null.
    - Print a C code snippet to initialize a forward iterator for the doubly linked list `self->{name}`.
    - Print a C code snippet for a loop that iterates over the list until the iterator is done.
    - Within the loop, print a C code snippet to retrieve the current element `ele` from the iterator.
    - Check the type of `dlist_t` and print a C code snippet to apply a function `fun` to `ele` with type-specific parameters.
    - Close the loop and the conditional block with appropriate C code snippets.
- **Output**: The method outputs C code to the `body` file stream, which iterates over a doubly linked list and applies a function to each element based on its type.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.DlistMember`](#DlistMember)  (Base Class)



---
### OptionMember<!-- {{#class:firedancer/src/flamenco/types/gen_stubs.OptionMember}} -->
- **Members**:
    - `element`: Stores the type of the element in the option.
    - `flat`: Indicates if the option is flat or not.
    - `ignore_underflow`: Determines if underflow errors should be ignored.
- **Description**: The `OptionMember` class is a specialized type node that represents an optional member in a data structure, allowing for the inclusion of elements that may or may not be present. It extends the `TypeNode` class and manages the encoding and decoding of optional elements, handling both flat and non-flat representations. The class includes mechanisms to handle underflow errors and provides methods for encoding, decoding, and calculating the size of the optional member.
- **Methods**:
    - [`firedancer/src/flamenco/types/gen_stubs.OptionMember.__init__`](#OptionMember__init__)
    - [`firedancer/src/flamenco/types/gen_stubs.OptionMember.emitPreamble`](#OptionMemberemitPreamble)
    - [`firedancer/src/flamenco/types/gen_stubs.OptionMember.emitPostamble`](#OptionMemberemitPostamble)
    - [`firedancer/src/flamenco/types/gen_stubs.OptionMember.emitMember`](#OptionMemberemitMember)
    - [`firedancer/src/flamenco/types/gen_stubs.OptionMember.emitMemberGlobal`](#OptionMemberemitMemberGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.OptionMember.emitNew`](#OptionMemberemitNew)
    - [`firedancer/src/flamenco/types/gen_stubs.OptionMember.emitDecodeFootprint`](#OptionMemberemitDecodeFootprint)
    - [`firedancer/src/flamenco/types/gen_stubs.OptionMember.emitDecodeInner`](#OptionMemberemitDecodeInner)
    - [`firedancer/src/flamenco/types/gen_stubs.OptionMember.emitDecodeInnerGlobal`](#OptionMemberemitDecodeInnerGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.OptionMember.emitEncode`](#OptionMemberemitEncode)
    - [`firedancer/src/flamenco/types/gen_stubs.OptionMember.emitEncodeGlobal`](#OptionMemberemitEncodeGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.OptionMember.emitSize`](#OptionMemberemitSize)
    - [`firedancer/src/flamenco/types/gen_stubs.OptionMember.emitWalk`](#OptionMemberemitWalk)
- **Inherits From**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode`](#TypeNode)

**Methods**

---
#### OptionMember\.\_\_init\_\_<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.OptionMember.__init__}} -->
The [`__init__`](#TypeNode__init__) method initializes an `OptionMember` instance with attributes derived from a JSON configuration.
- **Inputs**:
    - `container`: The container object that holds this `OptionMember` instance.
    - `json`: A dictionary containing configuration data for initializing the `OptionMember` instance, including keys like 'element', 'flat', and 'ignore_underflow'.
- **Control Flow**:
    - The method calls the parent class's [`__init__`](#TypeNode__init__) method with the `json` argument.
    - It assigns the value of `json['element']` to the `element` attribute of the instance.
    - It sets the `flat` attribute to the value of `json['flat']` if it exists, otherwise defaults to `False`.
    - It sets the `ignore_underflow` attribute to the boolean value of `json['ignore_underflow']` if it exists, otherwise defaults to `False`.
- **Output**: The method does not return any value; it initializes the instance attributes.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.__init__`](#TypeNode__init__)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.OptionMember`](#OptionMember)  (Base Class)


---
#### OptionMember\.emitPreamble<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.OptionMember.emitPreamble}} -->
The `emitPreamble` method is a placeholder method in the `OptionMember` class that currently does nothing.
- **Inputs**: None
- **Control Flow**:
    - The method is defined but contains no implementation, indicated by the `pass` statement.
- **Output**: There is no output as the method does nothing.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.OptionMember`](#OptionMember)  (Base Class)


---
#### OptionMember\.emitPostamble<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.OptionMember.emitPostamble}} -->
The `emitPostamble` method is a placeholder method in the `OptionMember` class that currently does nothing.
- **Inputs**: None
- **Control Flow**:
    - The method is defined but contains no implementation, indicated by the `pass` statement.
- **Output**: There is no output as the method does nothing.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.OptionMember`](#OptionMember)  (Base Class)


---
#### OptionMember\.emitMember<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.OptionMember.emitMember}} -->
The `emitMember` method generates C code to declare a member variable in a struct based on the element type and whether it is flat or not.
- **Inputs**: None
- **Control Flow**:
    - Check if the `flat` attribute is True.
    - If `flat` is True, check if `element` is in `simpletypes`.
    - If `element` is in `simpletypes`, print a declaration for a simple type member.
    - If `element` is not in `simpletypes`, print a declaration for a namespaced type member.
    - Print a declaration for a `uchar` type indicating the presence of the member.
    - If `flat` is False, check if `element` is in `simpletypes`.
    - If `element` is in `simpletypes`, print a declaration for a pointer to a simple type member.
    - If `element` is not in `simpletypes`, print a declaration for a pointer to a namespaced type member.
- **Output**: The method outputs C code to a file, specifically to the `header` file, declaring a member variable in a struct.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.OptionMember`](#OptionMember)  (Base Class)


---
#### OptionMember\.emitMemberGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.OptionMember.emitMemberGlobal}} -->
The `emitMemberGlobal` method generates C code to declare a global member variable based on the type of the element and whether it is flat or not.
- **Inputs**:
    - `self`: An instance of the OptionMember class, which contains attributes like 'element', 'flat', and 'name' that determine the type and structure of the member to be emitted.
- **Control Flow**:
    - Check if the 'flat' attribute of the instance is True.
    - If 'flat' is True, check if 'element' is in 'simpletypes'.
    - If 'element' is in 'simpletypes', print a simple type declaration to the header file.
    - If 'element' is in 'flattypes', print a flat type declaration to the header file.
    - If 'element' is not in 'simpletypes' or 'flattypes', print a global type declaration to the header file.
    - Print a 'has_' variable declaration to the header file if 'flat' is True.
    - If 'flat' is False, print an offset declaration to the header file.
- **Output**: The method outputs C code lines to a header file, which declare a member variable and possibly a 'has_' variable or an offset variable, depending on the type and structure of the element.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.OptionMember`](#OptionMember)  (Base Class)


---
#### OptionMember\.emitNew<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.OptionMember.emitNew}} -->
The `emitNew` method is a placeholder method in the `OptionMember` class that currently does nothing.
- **Inputs**:
    - `self`: Refers to the instance of the class `OptionMember` to which this method belongs.
    - `indent`: An optional string parameter with a default value of an empty string, intended for indentation purposes in code generation.
- **Control Flow**:
    - The method is defined but contains no implementation, indicated by the `pass` statement.
- **Output**: The method does not return any value or perform any operations.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.OptionMember`](#OptionMember)  (Base Class)


---
#### OptionMember\.emitDecodeFootprint<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.OptionMember.emitDecodeFootprint}} -->
The `emitDecodeFootprint` method generates C code to decode and calculate the memory footprint of an optional element in a binary encoding context.
- **Inputs**: None
- **Control Flow**:
    - Prints the opening brace and declares a uchar variable 'o'.
    - Calls a function to decode a boolean value into 'o' and checks for errors, returning the error if any.
    - Checks if 'o' is true, indicating the presence of the optional element.
    - If the element is not flat and is a simple type, adds its size to 'total_sz'.
    - If the element is not flat and not a simple type, adds its alignment and size to 'total_sz'.
    - Calls the appropriate decode footprint function based on whether the element is a simple type or not.
    - Checks for errors after decoding the footprint and returns the error if any.
    - Prints the closing brace for the conditional block and the method.
- **Output**: The method outputs C code to a file, which includes logic for decoding a boolean flag and calculating the memory footprint of an optional element.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.OptionMember`](#OptionMember)  (Base Class)


---
#### OptionMember\.emitDecodeInner<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.OptionMember.emitDecodeInner}} -->
The `emitDecodeInner` method generates C code to decode a binary-encoded optional member of a struct, handling both flat and non-flat representations.
- **Inputs**:
    - `self`: An instance of the `OptionMember` class, which contains metadata about the optional member being decoded, such as its name, element type, and whether it is flat.
- **Control Flow**:
    - Prints the opening brace for the C code block to the `body` file.
    - Declares a local variable `o` of type `uchar` and prints it to the `body` file.
    - Calls `fd_bincode_bool_decode_unsafe` to decode a boolean value into `o` from the context `ctx`.
    - Checks if the `flat` attribute of `self` is `True`.
    - If `flat` is `True`, sets `self->has_<name>` to the boolean value of `o` and checks if `o` is true.
    - If `o` is true and the element is a simple type, calls the appropriate `fd_bincode_<type>_decode_unsafe` function to decode the element.
    - If `o` is true and the element is not a simple type, calls the `new` and `decode_inner` functions for the element type.
    - If `flat` is `False`, checks if `o` is true.
    - If `o` is true and the element is a simple type, aligns memory, assigns it to `self-><name>`, and decodes the element.
    - If `o` is true and the element is not a simple type, aligns memory, assigns it to `self-><name>`, and calls the `new` and `decode_inner` functions for the element type.
    - If `o` is false, sets `self-><name>` to `NULL`.
    - Prints the closing brace for the C code block to the `body` file.
- **Output**: The method outputs C code to the `body` file that decodes an optional member from a binary format, handling both flat and non-flat representations based on the `self.flat` attribute.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.OptionMember`](#OptionMember)  (Base Class)


---
#### OptionMember\.emitDecodeInnerGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.OptionMember.emitDecodeInnerGlobal}} -->
The `emitDecodeInnerGlobal` method generates C code to decode a global structure member from a binary format, handling both flat and non-flat types.
- **Inputs**: None
- **Control Flow**:
    - Prints the opening brace for the C code block.
    - Declares a local variable `o` of type `uchar`.
    - Calls `fd_bincode_bool_decode_unsafe` to decode a boolean value into `o`.
    - Checks if the `flat` attribute is true.
    - If `flat` is true, sets a flag `has_<name>` based on `o` and checks if `o` is true.
    - If `o` is true and the element is a simple type, decodes the element using `fd_bincode_<type>_decode_unsafe`.
    - If `o` is true and the element is not a simple type, initializes the element and calls the appropriate decode function based on whether the element is in `flattypes`.
    - If `flat` is false, checks if `o` is true.
    - If `o` is true and the element is a simple type, aligns memory, sets an offset, decodes the element, and updates the memory pointer.
    - If `o` is true and the element is not a simple type, aligns memory, sets an offset, initializes the element, updates the memory pointer, and calls the appropriate decode function based on whether the element is in `flattypes`.
    - If `o` is false, sets the offset to 0.
    - Prints the closing brace for the C code block.
- **Output**: The method outputs C code to a file, which decodes a global structure member from a binary format, handling both flat and non-flat types.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.OptionMember`](#OptionMember)  (Base Class)


---
#### OptionMember\.emitEncode<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.OptionMember.emitEncode}} -->
The `emitEncode` method generates C code for encoding an optional member of a struct, handling both flat and non-flat representations.
- **Inputs**: None
- **Control Flow**:
    - Check if the member is flat or not using `self.flat`.
    - If flat, encode a boolean indicating the presence of the member using `fd_bincode_bool_encode`.
    - Check for encoding errors using `FD_UNLIKELY`.
    - If the member is present, encode the member using the appropriate encoding function based on its type (simple or complex).
    - If not flat, check if the member is not NULL.
    - Encode a boolean indicating the presence of the member.
    - Encode the member using the appropriate encoding function based on its type.
    - If the member is NULL, encode a boolean indicating its absence.
- **Output**: The method outputs C code to the `body` file stream for encoding the optional member of a struct.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.OptionMember`](#OptionMember)  (Base Class)


---
#### OptionMember\.emitEncodeGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.OptionMember.emitEncodeGlobal}} -->
The `emitEncodeGlobal` method generates C code for encoding a global option member, handling both flat and non-flat cases, and writes it to a specified file.
- **Inputs**:
    - `self`: An instance of the `OptionMember` class, representing an option member with attributes like `element`, `flat`, and `name`.
- **Control Flow**:
    - Check if the option member is flat using `self.flat`.
    - If flat, encode the presence of the member using `fd_bincode_bool_encode` and check for errors.
    - If the member is present, determine the encoding function based on the type of `self.element` (simple, flat, or other) and encode the member, checking for errors.
    - If not flat, check if the member has an offset, encode its presence, and check for errors.
    - If the member is present, determine the encoding function based on the type of `self.element` and encode the member, checking for errors.
    - If the member is not present, encode its absence using `fd_bincode_bool_encode` and check for errors.
- **Output**: The method outputs C code lines to a file, which encode the global option member based on its type and presence.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.OptionMember`](#OptionMember)  (Base Class)


---
#### OptionMember\.emitSize<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.OptionMember.emitSize}} -->
The `emitSize` method calculates and emits the size of a member in a C structure based on its type and presence.
- **Inputs**:
    - `inner`: A parameter that is not used in the method body, possibly intended for future use or as a placeholder.
- **Control Flow**:
    - The method starts by adding the size of a `char` to the `size` variable.
    - It checks if the `flat` attribute of the object is `True`.
    - If `flat` is `True`, it checks if the member is present using `self->has_{self.name}`.
    - If the member is a simple type, it adds the size of the element to `size`.
    - If the member is not a simple type, it calls a function to get the size of the element and adds it to `size`.
    - If `flat` is `False`, it checks if the member is not `NULL`.
    - It performs similar size calculations as in the `flat` case, but without the `has_` prefix.
- **Output**: The method outputs C code lines to a file, which calculate and add the size of a member to a `size` variable.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.OptionMember`](#OptionMember)  (Base Class)


---
#### OptionMember\.emitWalk<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.OptionMember.emitWalk}} -->
The `emitWalk` method generates C code to walk through a data structure and apply a function to its elements, handling both flat and non-flat structures.
- **Inputs**:
    - `inner`: A parameter that is not used within the method body.
- **Control Flow**:
    - Check if the `flat` attribute of the object is True.
    - If `flat` is True, generate code to check if the element is present using `has_<name>` and apply the function `fun` with `NULL` if not present.
    - If the element is present, check if the element type is in `emitWalkMap` and use the corresponding function to apply `fun`, otherwise call a specific walk function for the element type.
    - If `flat` is False, generate code to check if the element is `NULL` and apply the function `fun` with `NULL` if it is.
    - If the element is not `NULL`, check if the element type is in `emitWalkMap` and use the corresponding function to apply `fun`, otherwise call a specific walk function for the element type.
- **Output**: The method outputs C code to the `body` file stream, which is used to walk through the data structure and apply a function to its elements.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.OptionMember`](#OptionMember)  (Base Class)



---
### ArrayMember<!-- {{#class:firedancer/src/flamenco/types/gen_stubs.ArrayMember}} -->
- **Members**:
    - `element`: Stores the type of elements contained in the array.
    - `length`: Represents the fixed length of the array.
- **Description**: The `ArrayMember` class is a specialized type node that represents an array with a fixed length and a specific element type. It provides methods to determine if the array is flat, fixed size, or fuzzy, and includes functionality for encoding and decoding the array's elements. The class is designed to handle different types of elements, including simple types and complex types, and supports operations like emitting preambles, postambles, and member declarations for both local and global contexts.
- **Methods**:
    - [`firedancer/src/flamenco/types/gen_stubs.ArrayMember.__init__`](#ArrayMember__init__)
    - [`firedancer/src/flamenco/types/gen_stubs.ArrayMember.isFlat`](#ArrayMemberisFlat)
    - [`firedancer/src/flamenco/types/gen_stubs.ArrayMember.isFixedSize`](#ArrayMemberisFixedSize)
    - [`firedancer/src/flamenco/types/gen_stubs.ArrayMember.fixedSize`](#ArrayMemberfixedSize)
    - [`firedancer/src/flamenco/types/gen_stubs.ArrayMember.isFuzzy`](#ArrayMemberisFuzzy)
    - [`firedancer/src/flamenco/types/gen_stubs.ArrayMember.emitPreamble`](#ArrayMemberemitPreamble)
    - [`firedancer/src/flamenco/types/gen_stubs.ArrayMember.emitPostamble`](#ArrayMemberemitPostamble)
    - [`firedancer/src/flamenco/types/gen_stubs.ArrayMember.emitMember`](#ArrayMemberemitMember)
    - [`firedancer/src/flamenco/types/gen_stubs.ArrayMember.emitMemberGlobal`](#ArrayMemberemitMemberGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.ArrayMember.emitNew`](#ArrayMemberemitNew)
    - [`firedancer/src/flamenco/types/gen_stubs.ArrayMember.emitDecodeFootprint`](#ArrayMemberemitDecodeFootprint)
    - [`firedancer/src/flamenco/types/gen_stubs.ArrayMember.emitDecodeInner`](#ArrayMemberemitDecodeInner)
    - [`firedancer/src/flamenco/types/gen_stubs.ArrayMember.emitDecodeInnerGlobal`](#ArrayMemberemitDecodeInnerGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.ArrayMember.emitEncode`](#ArrayMemberemitEncode)
    - [`firedancer/src/flamenco/types/gen_stubs.ArrayMember.emitEncodeGlobal`](#ArrayMemberemitEncodeGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.ArrayMember.emitSize`](#ArrayMemberemitSize)
    - [`firedancer/src/flamenco/types/gen_stubs.ArrayMember.emitWalk`](#ArrayMemberemitWalk)
- **Inherits From**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode`](#TypeNode)

**Methods**

---
#### ArrayMember\.\_\_init\_\_<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.ArrayMember.__init__}} -->
The [`__init__`](#TypeNode__init__) method initializes an `ArrayMember` instance by setting its `element` and `length` attributes based on a provided JSON object.
- **Inputs**:
    - `container`: An unused parameter in the constructor, possibly intended for future use or for consistency with other similar classes.
    - `json`: A dictionary containing initialization data, specifically with keys 'element' and 'length' to set the respective attributes of the instance.
- **Control Flow**:
    - The method calls the parent class's [`__init__`](#TypeNode__init__) method with the `json` parameter.
    - It assigns the value associated with the 'element' key in the `json` dictionary to the `element` attribute of the instance.
    - It converts the value associated with the 'length' key in the `json` dictionary to an integer and assigns it to the `length` attribute of the instance.
- **Output**: The method does not return any value; it initializes the instance attributes.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.__init__`](#TypeNode__init__)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.ArrayMember`](#ArrayMember)  (Base Class)


---
#### ArrayMember\.isFlat<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.ArrayMember.isFlat}} -->
The `isFlat` method checks if the `element` attribute of an `ArrayMember` instance is part of a predefined set of flat types.
- **Inputs**: None
- **Control Flow**:
    - The method accesses the `element` attribute of the `ArrayMember` instance.
    - It checks if this `element` is present in the `flattypes` set.
    - The method returns `True` if the `element` is in `flattypes`, otherwise it returns `False`.
- **Output**: A boolean value indicating whether the `element` is a flat type.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.ArrayMember`](#ArrayMember)  (Base Class)


---
#### ArrayMember\.isFixedSize<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.ArrayMember.isFixedSize}} -->
The `isFixedSize` method checks if the `element` attribute of an `ArrayMember` instance is a fixed-size type.
- **Inputs**:
    - `self`: An instance of the `ArrayMember` class.
- **Control Flow**:
    - The method checks if `self.element` is present in the `fixedsizetypes` dictionary.
- **Output**: Returns `True` if `self.element` is a key in the `fixedsizetypes` dictionary, indicating it is a fixed-size type; otherwise, returns `False`.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.ArrayMember`](#ArrayMember)  (Base Class)


---
#### ArrayMember\.fixedSize<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.ArrayMember.fixedSize}} -->
The `fixedSize` method calculates the total fixed size of an array element by multiplying its length by the fixed size of its element type.
- **Inputs**: None
- **Control Flow**:
    - The method accesses the `length` attribute of the instance, which represents the number of elements in the array.
    - It retrieves the fixed size of the element type from the `fixedsizetypes` dictionary using the `element` attribute as the key.
    - The method multiplies the `length` by the fixed size of the element type to compute the total fixed size.
    - The result is returned as the output of the method.
- **Output**: The method returns an integer representing the total fixed size of the array element.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.ArrayMember`](#ArrayMember)  (Base Class)


---
#### ArrayMember\.isFuzzy<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.ArrayMember.isFuzzy}} -->
The `isFuzzy` method checks if the `element` attribute of an `ArrayMember` instance is part of the predefined set `fuzzytypes`.
- **Inputs**:
    - `self`: An instance of the `ArrayMember` class, which contains attributes like `element` and `length`.
- **Control Flow**:
    - The method accesses the `element` attribute of the `self` instance.
    - It checks if this `element` is present in the `fuzzytypes` set.
    - The method returns `True` if the `element` is in `fuzzytypes`, otherwise it returns `False`.
- **Output**: A boolean value indicating whether the `element` is in the `fuzzytypes` set.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.ArrayMember`](#ArrayMember)  (Base Class)


---
#### ArrayMember\.emitPreamble<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.ArrayMember.emitPreamble}} -->
The `emitPreamble` method is a placeholder method in the `ArrayMember` class that currently does nothing.
- **Inputs**: None
- **Control Flow**:
    - The method is defined but contains no implementation, indicated by the `pass` statement.
- **Output**: There is no output as the method does nothing.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.ArrayMember`](#ArrayMember)  (Base Class)


---
#### ArrayMember\.emitPostamble<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.ArrayMember.emitPostamble}} -->
The `emitPostamble` method is a placeholder method in the `ArrayMember` class that currently does nothing.
- **Inputs**: None
- **Control Flow**:
    - The method is defined but contains no implementation, indicated by the `pass` statement.
- **Output**: There is no output as the method does nothing.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.ArrayMember`](#ArrayMember)  (Base Class)


---
#### ArrayMember\.emitMember<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.ArrayMember.emitMember}} -->
The `emitMember` method generates C code to declare an array member in a header file based on the type of the element.
- **Inputs**: None
- **Control Flow**:
    - Check if `self.element` is in `simpletypes`.
    - If true, print a C declaration for a simple type array to the `header` file.
    - If false, print a C declaration for a complex type array with a namespace prefix to the `header` file.
- **Output**: The method does not return any value; it outputs C code to a file.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.ArrayMember`](#ArrayMember)  (Base Class)


---
#### ArrayMember\.emitMemberGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.ArrayMember.emitMemberGlobal}} -->
The `emitMemberGlobal` method generates C code to declare a global array member in a header file based on the type of elements it contains.
- **Inputs**:
    - `self`: An instance of the `ArrayMember` class, which contains attributes like `element` and `length` that define the type and size of the array.
- **Control Flow**:
    - Check if `self.element` is in `simpletypes` and print a declaration using the element type directly.
    - Check if `self.element` is in `flattypes` and print a declaration using a namespaced type with a `_t` suffix.
    - If `self.element` is not in `simpletypes` or `flattypes`, print a declaration using a namespaced type with a `_global_t` suffix.
- **Output**: The method outputs C code to the `header` file stream, declaring a global array member with the appropriate type based on the element type.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.ArrayMember`](#ArrayMember)  (Base Class)


---
#### ArrayMember\.emitNew<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.ArrayMember.emitNew}} -->
The `emitNew` method generates code to initialize new elements of an array member if the element type is not a simple type.
- **Inputs**:
    - `indent`: An optional string argument that specifies the indentation to be used in the generated code, defaulting to an empty string.
- **Control Flow**:
    - Retrieve the length of the array from the `length` attribute.
    - Check if the element type of the array is in the `simpletypes` dictionary.
    - If the element type is not a simple type, generate a for-loop in the output file `body` to iterate over the array indices.
    - Within the loop, generate a call to a function that initializes a new element of the array at the current index.
- **Output**: The method does not return any value; it writes generated code to the `body` file.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.ArrayMember`](#ArrayMember)  (Base Class)


---
#### ArrayMember\.emitDecodeFootprint<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.ArrayMember.emitDecodeFootprint}} -->
The `emitDecodeFootprint` method generates C code to calculate the memory footprint required for decoding an array of elements based on the element type and length.
- **Inputs**:
    - `self`: An instance of the `ArrayMember` class, which contains attributes like `element` and `length` that define the type and size of the array.
- **Control Flow**:
    - Retrieve the `length` attribute from the `self` object.
    - Check if the `element` attribute is 'uchar'.
    - If 'uchar', print C code to decode a byte array footprint and return if an error occurs.
    - If not 'uchar', print a for-loop in C to iterate over the array length.
    - Within the loop, check if the `element` is in `simpletypes`.
    - If in `simpletypes`, print C code to decode the footprint using a simple type decoder.
    - If not in `simpletypes`, print C code to decode the footprint using a custom decoder for the element type.
    - Print C code to check for errors after each decoding operation.
- **Output**: The method outputs C code to the `body` file stream, which includes error checking and decoding logic for the specified array type.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.ArrayMember`](#ArrayMember)  (Base Class)


---
#### ArrayMember\.emitDecodeInner<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.ArrayMember.emitDecodeInner}} -->
The `emitDecodeInner` method generates C code to decode an array of elements from a binary format, handling different element types accordingly.
- **Inputs**: None
- **Control Flow**:
    - Retrieve the length of the array from the `length` attribute.
    - Check if the element type is 'uchar'.
    - If 'uchar', print a line of code to decode bytes unsafely and return.
    - If not 'uchar', print a for-loop to iterate over the array length.
    - Within the loop, check if the element type is in `simpletypes`.
    - If in `simpletypes`, print a line of code to decode the element unsafely using the corresponding simple type decoder.
    - If not in `simpletypes`, print a line of code to call a custom decode function for the element type.
- **Output**: The method outputs C code to a file, which decodes an array of elements from a binary format.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.ArrayMember`](#ArrayMember)  (Base Class)


---
#### ArrayMember\.emitDecodeInnerGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.ArrayMember.emitDecodeInnerGlobal}} -->
The `emitDecodeInnerGlobal` method generates C code to decode an array of elements from a binary format, handling different element types with specific decoding functions.
- **Inputs**:
    - `self`: An instance of the `ArrayMember` class, which contains attributes like `element` and `length` that define the type and size of the array to be decoded.
- **Control Flow**:
    - Retrieve the `length` attribute from the `self` object, which specifies the number of elements in the array.
    - Check if the `element` attribute is 'uchar'. If true, generate a call to `fd_bincode_bytes_decode_unsafe` to decode the array as bytes and return immediately.
    - If the `element` is not 'uchar', generate a for-loop in C that iterates over each element in the array, using the `length` as the loop limit.
    - Within the loop, check if the `element` is in `simpletypes`. If true, generate a call to `fd_bincode_<type>_decode_unsafe` for each element.
    - If the `element` is not in `simpletypes`, check if it is in `flattypes`. If true, generate a call to `<namespace>_<element>_decode_inner` for each element.
    - If the `element` is neither in `simpletypes` nor `flattypes`, generate a call to `<namespace>_<element>_decode_inner_global` for each element.
    - Close the for-loop with a closing brace.
- **Output**: The method outputs C code to a file-like object `body`, which contains the generated code for decoding the array elements based on their type.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.ArrayMember`](#ArrayMember)  (Base Class)


---
#### ArrayMember\.emitEncode<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.ArrayMember.emitEncode}} -->
The `emitEncode` method generates C code to encode an array member of a struct based on its element type and length.
- **Inputs**:
    - `self`: An instance of the `ArrayMember` class, which contains attributes like `element` and `length` that define the type and size of the array to be encoded.
- **Control Flow**:
    - Retrieve the `length` attribute from the `self` object.
    - Check if the `element` attribute is 'uchar'.
    - If `element` is 'uchar', print C code to encode a byte array using `fd_bincode_bytes_encode` and return if an error occurs.
    - If `element` is not 'uchar', print a for-loop in C to iterate over the array indices from 0 to `length - 1`.
    - Within the loop, check if `element` is in `simpletypes`.
    - If `element` is in `simpletypes`, print C code to encode the element using `fd_bincode_<type>_encode` where `<type>` is the corresponding simple type.
    - If `element` is not in `simpletypes`, print C code to encode the element using `<namespace>_<element>_encode`.
    - Print C code to check for encoding errors and return if an error occurs.
- **Output**: The method outputs C code to the `body` file stream, which encodes the array elements of a struct based on their type and handles potential errors.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.ArrayMember`](#ArrayMember)  (Base Class)


---
#### ArrayMember\.emitEncodeGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.ArrayMember.emitEncodeGlobal}} -->
The `emitEncodeGlobal` method generates C code to encode an array of elements into a binary format, handling different element types and error checking.
- **Inputs**:
    - `self`: An instance of the `ArrayMember` class, which contains information about the array to be encoded, including its element type and length.
- **Control Flow**:
    - Retrieve the length of the array from `self.length`.
    - Check if the element type is 'uchar'.
    - If the element type is 'uchar', generate code to encode the array as bytes and return if an error occurs.
    - If the element type is in `simpletypes`, generate code to encode each element using the corresponding simple type encoding function.
    - If the element type is in `flattypes`, generate code to encode each element using the corresponding flat type encoding function.
    - For other element types, generate code to encode each element using the global encoding function for that type.
    - For each element, check if an error occurred during encoding and return the error if so.
- **Output**: The method outputs C code to a file, which encodes an array of elements into a binary format, handling different element types and error checking.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.ArrayMember`](#ArrayMember)  (Base Class)


---
#### ArrayMember\.emitSize<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.ArrayMember.emitSize}} -->
The `emitSize` method calculates and prints the size of an array member based on its element type and length.
- **Inputs**:
    - `inner`: A parameter that is not used within the method but is part of the method signature.
- **Control Flow**:
    - Retrieve the length of the array member from `self.length`.
    - Check if the element type is 'uchar'.
    - If 'uchar', print a statement to add the length to the size.
    - If the element type is in `simpletypes`, print a statement to add the product of length and the size of the element type to the size.
    - For other element types, print a loop statement to iterate over the length and add the size of each element using a specific size function.
- **Output**: The method does not return any value; it prints C code to a file-like object `body`.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.ArrayMember`](#ArrayMember)  (Base Class)


---
#### ArrayMember\.emitWalk<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.ArrayMember.emitWalk}} -->
The `emitWalk` method generates C code to walk through an array member and apply a function to each element, handling different element types accordingly.
- **Inputs**:
    - `inner`: A parameter that is not used in the method body but is part of the method signature.
- **Control Flow**:
    - Retrieve the length of the array from the `self.length` attribute.
    - Check if the element type is 'uchar'.
    - If the element type is 'uchar', print a function call to handle 'uchar' type and return.
    - Print a function call to handle the array start, incrementing the level.
    - Print a for-loop to iterate over the array elements based on the length.
    - Check if the element type is in `VectorMember.emitWalkMap`.
    - If the element type is in `VectorMember.emitWalkMap`, call the corresponding function from the map.
    - If the element type is not in `VectorMember.emitWalkMap`, print a function call to handle the element type using a namespace-prefixed walk function.
    - Print a function call to handle the array end, decrementing the level.
- **Output**: The method outputs C code to the `body` file, which includes function calls to walk through the array and apply a function to each element.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.ArrayMember`](#ArrayMember)  (Base Class)



---
### OpaqueType<!-- {{#class:firedancer/src/flamenco/types/gen_stubs.OpaqueType}} -->
- **Members**:
    - `fullname`: Stores the full name of the opaque type, combining namespace and JSON name.
    - `walktype`: Holds the walk type from the JSON, if specified, otherwise None.
    - `size`: Represents the size of the opaque type, if specified in the JSON, otherwise None.
    - `emitprotos`: Indicates whether to emit prototypes, defaulting to True if not specified.
- **Description**: The OpaqueType class is a specialized type node that represents an opaque type in a type system, inheriting from TypeNode. It is initialized with JSON data and constructs a full name using a namespace and the JSON's name field. The class can optionally store a walk type and size, and it defaults to emitting prototypes unless specified otherwise. OpaqueType instances are considered flat types, meaning they do not contain nested local pointers, and they provide methods for emitting headers, prototypes, and implementations related to encoding, decoding, and walking the type.
- **Methods**:
    - [`firedancer/src/flamenco/types/gen_stubs.OpaqueType.__init__`](#OpaqueType__init__)
    - [`firedancer/src/flamenco/types/gen_stubs.OpaqueType.emitHeader`](#OpaqueTypeemitHeader)
    - [`firedancer/src/flamenco/types/gen_stubs.OpaqueType.isFlat`](#OpaqueTypeisFlat)
    - [`firedancer/src/flamenco/types/gen_stubs.OpaqueType.isFixedSize`](#OpaqueTypeisFixedSize)
    - [`firedancer/src/flamenco/types/gen_stubs.OpaqueType.fixedSize`](#OpaqueTypefixedSize)
    - [`firedancer/src/flamenco/types/gen_stubs.OpaqueType.emitPrototypes`](#OpaqueTypeemitPrototypes)
    - [`firedancer/src/flamenco/types/gen_stubs.OpaqueType.emitImpls`](#OpaqueTypeemitImpls)
    - [`firedancer/src/flamenco/types/gen_stubs.OpaqueType.emitPostamble`](#OpaqueTypeemitPostamble)
- **Inherits From**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode`](#TypeNode)

**Methods**

---
#### OpaqueType\.\_\_init\_\_<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.OpaqueType.__init__}} -->
The [`__init__`](#TypeNode__init__) method initializes an instance of the `OpaqueType` class with attributes derived from a JSON object.
- **Inputs**:
    - `json`: A dictionary-like object containing configuration data for initializing the `OpaqueType` instance, including keys like 'name', 'walktype', 'size', and 'emitprotos'.
- **Control Flow**:
    - The method calls the superclass's [`__init__`](#TypeNode__init__) method with the `json` parameter.
    - It constructs the `fullname` attribute by concatenating a namespace with the 'name' value from the `json` object.
    - The `walktype` attribute is set to the 'walktype' value from `json` if it exists, otherwise it is set to `None`.
    - The `size` attribute is set to the integer value of 'size' from `json` if it exists, otherwise it is set to `None`.
    - The `emitprotos` attribute is set to the boolean value of 'emitprotos' from `json` if it exists, otherwise it defaults to `True`.
    - The `name` attribute is added to the `flattypes` set, indicating that all opaque types are considered flat types.
- **Output**: The method does not return any value; it initializes the instance attributes.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.__init__`](#TypeNode__init__)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.OpaqueType`](#OpaqueType)  (Base Class)


---
#### OpaqueType\.emitHeader<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.OpaqueType.emitHeader}} -->
The `emitHeader` method in the `OpaqueType` class is a placeholder method intended for emitting header information, but currently does nothing.
- **Inputs**: None
- **Control Flow**:
    - The method is defined but contains no implementation, indicated by the `pass` statement.
- **Output**: There is no output as the method is not implemented.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.OpaqueType`](#OpaqueType)  (Base Class)


---
#### OpaqueType\.isFlat<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.OpaqueType.isFlat}} -->
The `isFlat` method in the `OpaqueType` class always returns `True`, indicating that the type is considered flat.
- **Inputs**: None
- **Control Flow**:
    - The method simply returns the boolean value `True`.
- **Output**: The method returns a boolean value `True`, indicating that the type is flat.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.OpaqueType`](#OpaqueType)  (Base Class)


---
#### OpaqueType\.isFixedSize<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.OpaqueType.isFixedSize}} -->
The `isFixedSize` method checks if the `size` attribute of an `OpaqueType` instance is not `None`, indicating a fixed size.
- **Inputs**:
    - `self`: An instance of the `OpaqueType` class.
- **Control Flow**:
    - The method returns the result of the expression `self.size is not None`.
- **Output**: A boolean value indicating whether the `size` attribute is not `None`.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.OpaqueType`](#OpaqueType)  (Base Class)


---
#### OpaqueType\.fixedSize<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.OpaqueType.fixedSize}} -->
The `fixedSize` method returns the size attribute of the OpaqueType instance.
- **Inputs**: None
- **Control Flow**:
    - The method directly returns the value of the `size` attribute of the instance.
- **Output**: The output is the value of the `size` attribute, which is an integer or None if not set.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.OpaqueType`](#OpaqueType)  (Base Class)


---
#### OpaqueType\.emitPrototypes<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.OpaqueType.emitPrototypes}} -->
The `emitPrototypes` method generates and writes C function prototypes for a specific opaque type to a header file if the `emitprotos` flag is set to true.
- **Inputs**: None
- **Control Flow**:
    - Check if `emitprotos` is true; if not, return immediately.
    - Retrieve the full name of the type from `self.fullname`.
    - Write a series of C function prototypes to the `header` file, including functions for creating, encoding, walking, sizing, aligning, decoding footprint, and decoding the type.
- **Output**: The method does not return any value; it writes C function prototypes to a file.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.OpaqueType`](#OpaqueType)  (Base Class)


---
#### OpaqueType\.emitImpls<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.OpaqueType.emitImpls}} -->
The `emitImpls` method generates and writes C function implementations for encoding, decoding, and walking operations for a specific opaque type if prototypes are to be emitted.
- **Inputs**: None
- **Control Flow**:
    - Check if `emitprotos` is False, and return immediately if so.
    - Retrieve the full name of the type from `self.fullname`.
    - Print the implementation of the encode function for the type, which uses `fd_bincode_bytes_encode`.
    - If `self.walktype` is not None, print the implementation of the walk function for the type.
    - Print the implementation of the `decode_footprint_inner` function, which checks for data overflow and calls `fd_bincode_bytes_decode_footprint`.
    - Print the implementation of the `decode_footprint` function, which adjusts the total size and checks for data overflow.
    - Print the implementation of the `decode_inner` function, which calls `fd_bincode_bytes_decode_unsafe`.
    - Print the implementation of the `decode` function, which calls `fd_bincode_bytes_decode_unsafe` and returns the memory pointer.
- **Output**: The method outputs C code for the functions to the `body` file, which includes implementations for encoding, decoding, and walking operations for the opaque type.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.OpaqueType`](#OpaqueType)  (Base Class)


---
#### OpaqueType\.emitPostamble<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.OpaqueType.emitPostamble}} -->
The `emitPostamble` method is a placeholder function in the `OpaqueType` class that currently does nothing.
- **Inputs**: None
- **Control Flow**:
    - The method is defined but contains no implementation, indicated by the `pass` statement.
- **Output**: There is no output as the method does nothing.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.OpaqueType`](#OpaqueType)  (Base Class)



---
### StructType<!-- {{#class:firedancer/src/flamenco/types/gen_stubs.StructType}} -->
- **Members**:
    - `fullname`: Stores the full name of the struct type, combining namespace and the name from JSON.
    - `fields`: Holds a list of fields defined in the struct, parsed from JSON.
    - `comment`: Stores an optional comment from the JSON definition.
    - `nomethods`: Indicates if the struct should not have methods, based on JSON attributes.
    - `encoders`: Holds encoder information from the JSON, if available.
    - `attribute`: Stores alignment attributes for the struct, if specified in JSON.
    - `alignment`: Holds the alignment value for the struct, defaulting to 0 if not specified.
- **Description**: The StructType class represents a structured data type parsed from a JSON definition, inheriting from TypeNode. It processes and stores information about the struct's fields, alignment, and other attributes, and provides methods to handle encoding, decoding, and size calculations. The class also supports generating C code for the struct's definition and related operations, including handling global types and alignment specifications.
- **Methods**:
    - [`firedancer/src/flamenco/types/gen_stubs.StructType.__init__`](#StructType__init__)
    - [`firedancer/src/flamenco/types/gen_stubs.StructType.isFixedSize`](#StructTypeisFixedSize)
    - [`firedancer/src/flamenco/types/gen_stubs.StructType.isFlat`](#StructTypeisFlat)
    - [`firedancer/src/flamenco/types/gen_stubs.StructType.fixedSize`](#StructTypefixedSize)
    - [`firedancer/src/flamenco/types/gen_stubs.StructType.isFuzzy`](#StructTypeisFuzzy)
    - [`firedancer/src/flamenco/types/gen_stubs.StructType.subTypes`](#StructTypesubTypes)
    - [`firedancer/src/flamenco/types/gen_stubs.StructType.subMembers`](#StructTypesubMembers)
    - [`firedancer/src/flamenco/types/gen_stubs.StructType.emitHeader`](#StructTypeemitHeader)
    - [`firedancer/src/flamenco/types/gen_stubs.StructType.emitPrototypes`](#StructTypeemitPrototypes)
    - [`firedancer/src/flamenco/types/gen_stubs.StructType.emitEncodes`](#StructTypeemitEncodes)
    - [`firedancer/src/flamenco/types/gen_stubs.StructType.emitEncode`](#StructTypeemitEncode)
    - [`firedancer/src/flamenco/types/gen_stubs.StructType.emitEncodeGlobal`](#StructTypeemitEncodeGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.StructType.emitImpls`](#StructTypeemitImpls)
    - [`firedancer/src/flamenco/types/gen_stubs.StructType.emitPostamble`](#StructTypeemitPostamble)
- **Inherits From**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode`](#TypeNode)

**Methods**

---
#### StructType\.\_\_init\_\_<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructType.__init__}} -->
The [`__init__`](#TypeNode__init__) method initializes an instance of the `StructType` class using a JSON object to set up its attributes and fields.
- **Inputs**:
    - `json`: A dictionary containing the configuration for the struct, including its name, fields, and optional attributes like comment, encoders, and alignment.
- **Control Flow**:
    - Call the superclass [`__init__`](#TypeNode__init__) method with the `json` argument.
    - Construct the `fullname` attribute by combining a namespace with the `name` from the JSON.
    - Initialize an empty list for `fields` and set an `index` counter to 0.
    - Iterate over each field in the `json['fields']` list.
    - For each field, check if it is not marked as removed; if not, parse the field into a member and append it to `fields`.
    - Set the `arch_index` of the member to the field's `tag` if present, otherwise use the current `index`.
    - Increment the `index` counter.
    - Set the `comment` attribute from the JSON if available, otherwise set it to `None`.
    - Determine if the struct has no methods by checking for the presence of the 'attribute' key in the JSON.
    - Set the `encoders` attribute from the JSON if available, otherwise set it to `None`.
    - Check for 'alignment' or 'attribute' in the JSON to set the `attribute` and `alignment` attributes accordingly, defaulting to an empty string and 0 if neither is present.
- **Output**: The method does not return any value; it initializes the instance attributes based on the provided JSON configuration.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.__init__`](#TypeNode__init__)
    - [`firedancer/src/flamenco/types/gen_stubs.parseMember`](#parseMember)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructType`](#StructType)  (Base Class)


---
#### StructType\.isFixedSize<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructType.isFixedSize}} -->
The [`isFixedSize`](#TypeNodeisFixedSize) method checks if all fields in a `StructType` instance have a fixed size and do not have the `ignore_underflow` attribute set to `True`.
- **Inputs**:
    - `self`: An instance of the `StructType` class, which contains a list of fields to be checked for fixed size.
- **Control Flow**:
    - Iterates over each field in the `fields` attribute of the `StructType` instance.
    - For each field, checks if the field's [`isFixedSize`](#TypeNodeisFixedSize) method returns `False`; if so, returns `False`.
    - Checks if the field has the `ignore_underflow` attribute set to `True`; if so, returns `False`.
    - If all fields pass the checks, returns `True`.
- **Output**: A boolean value indicating whether all fields in the `StructType` instance are of fixed size and do not have the `ignore_underflow` attribute set to `True`.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.isFixedSize`](#TypeNodeisFixedSize)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructType`](#StructType)  (Base Class)


---
#### StructType\.isFlat<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructType.isFlat}} -->
The [`isFlat`](#TypeNodeisFlat) method checks if all fields in a `StructType` instance are flat, meaning they do not contain nested local pointers.
- **Inputs**: None
- **Control Flow**:
    - Iterates over each field in the `fields` attribute of the `StructType` instance.
    - For each field, calls the [`isFlat`](#TypeNodeisFlat) method on the field.
    - If any field's [`isFlat`](#TypeNodeisFlat) method returns `False`, the method immediately returns `False`.
    - If all fields are flat, the method returns `True`.
- **Output**: A boolean value indicating whether all fields in the `StructType` instance are flat.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.isFlat`](#TypeNodeisFlat)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructType`](#StructType)  (Base Class)


---
#### StructType\.fixedSize<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructType.fixedSize}} -->
The [`fixedSize`](#TypeNodefixedSize) method calculates and returns the total fixed size of all fields in the `StructType` instance.
- **Inputs**: None
- **Control Flow**:
    - Initialize a variable `size` to 0.
    - Iterate over each field `f` in `self.fields`.
    - For each field, call its [`fixedSize`](#TypeNodefixedSize) method and add the result to `size`.
    - Return the accumulated `size`.
- **Output**: The method returns an integer representing the total fixed size of all fields in the `StructType` instance.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.fixedSize`](#TypeNodefixedSize)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructType`](#StructType)  (Base Class)


---
#### StructType\.isFuzzy<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructType.isFuzzy}} -->
The [`isFuzzy`](#TypeNodeisFuzzy) method checks if all fields in a `StructType` instance are fuzzy.
- **Inputs**:
    - `self`: An instance of the `StructType` class, which contains a list of fields to be checked for fuzziness.
- **Control Flow**:
    - Iterates over each field in the `fields` attribute of the `StructType` instance.
    - For each field, it calls the [`isFuzzy`](#TypeNodeisFuzzy) method on the field.
    - If any field's [`isFuzzy`](#TypeNodeisFuzzy) method returns `False`, the method immediately returns `False`.
    - If all fields are fuzzy, the method returns `True`.
- **Output**: A boolean value indicating whether all fields in the `StructType` instance are fuzzy (`True`) or not (`False`).
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.isFuzzy`](#TypeNodeisFuzzy)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructType`](#StructType)  (Base Class)


---
#### StructType\.subTypes<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructType.subTypes}} -->
The `subTypes` method yields sub-types extracted from the fields of a `StructType` instance.
- **Inputs**:
    - `self`: An instance of the `StructType` class, which contains a list of fields from which sub-types are extracted.
- **Control Flow**:
    - Iterates over each field in the `fields` attribute of the `StructType` instance.
    - For each field, calls the [`extract_sub_type`](#extract_sub_type) function to determine if a sub-type can be extracted.
    - If a sub-type is extracted (i.e., not `None`), it is yielded as part of the method's output.
- **Output**: Yields sub-types extracted from the fields of the `StructType` instance.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.extract_sub_type`](#extract_sub_type)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructType`](#StructType)  (Base Class)


---
#### StructType\.subMembers<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructType.subMembers}} -->
The `subMembers` method yields sub-member types extracted from the fields of a `StructType` instance.
- **Inputs**:
    - `self`: An instance of the `StructType` class, which contains a list of fields.
- **Control Flow**:
    - Iterates over each field in the `fields` attribute of the `StructType` instance.
    - For each field, it calls the [`extract_member_type`](#extract_member_type) function to determine the sub-member type.
    - If a sub-member type is found (i.e., not `None`), it yields this sub-member type.
- **Output**: Yields sub-member types extracted from the fields of the `StructType` instance.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.extract_member_type`](#extract_member_type)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructType`](#StructType)  (Base Class)


---
#### StructType\.emitHeader<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructType.emitHeader}} -->
The `emitHeader` method generates and writes the C struct definition and related metadata for a given `StructType` instance to a header file.
- **Inputs**: None
- **Control Flow**:
    - Iterates over each field in `self.fields` and calls [`emitPreamble`](#PrimitiveMemberemitPreamble) on each field.
    - Checks if `self.comment` is not None or empty, and if so, prints the comment to the header file.
    - Determines if the struct is of fixed size using [`isFixedSize`](#TypeNodeisFixedSize) and prints the encoded size information accordingly.
    - Prints the struct definition with its fields to the header file.
    - Defines a typedef for the struct.
    - Defines an alignment macro for the struct based on `self.alignment`.
    - If `self.produce_global` is True and the struct is not flat, prints the global struct definition and its typedef.
    - Defines a global alignment macro if applicable.
    - If `self.produce_global` is True and the struct is not flat, iterates over each field to call [`emitOffsetJoin`](#TypeNodeemitOffsetJoin).
- **Output**: The method outputs the C struct definition, typedefs, and alignment macros to a header file.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitPreamble`](#PrimitiveMemberemitPreamble)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.isFixedSize`](#TypeNodeisFixedSize)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.fixedSize`](#TypeNodefixedSize)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitMember`](#PrimitiveMemberemitMember)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.isFlat`](#TypeNodeisFlat)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitMemberGlobal`](#PrimitiveMemberemitMemberGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.emitOffsetJoin`](#TypeNodeemitOffsetJoin)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructType`](#StructType)  (Base Class)


---
#### StructType\.emitPrototypes<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructType.emitPrototypes}} -->
The `emitPrototypes` method generates and prints C function prototypes for encoding, decoding, and other operations related to a struct type, based on its properties and fields.
- **Inputs**:
    - `self`: An instance of the `StructType` class, representing a struct type with various properties and fields.
- **Control Flow**:
    - Check if `self.nomethods` is True; if so, return immediately without emitting prototypes.
    - Retrieve the full name of the struct type from `self.fullname`.
    - Determine if the struct is fixed size and fuzzy; if so, emit a static inline function for initializing the struct with zeroed memory.
    - Otherwise, emit a prototype for a non-inline `new` function for the struct.
    - Emit prototypes for encoding, walking, and size functions for the struct.
    - Emit a static inline function for alignment if the struct is fixed size and fuzzy; otherwise, emit a prototype for a non-inline `decode_footprint` function.
    - Emit a prototype for a `decode` function for the struct.
    - If `self.produce_global` is True and the struct is not flat, emit prototypes for global decoding and encoding functions.
- **Output**: The method outputs C function prototypes to a file, which are used for operations on the struct type.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.isFixedSize`](#TypeNodeisFixedSize)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.isFuzzy`](#TypeNodeisFuzzy)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.fixedSize`](#TypeNodefixedSize)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.isFlat`](#TypeNodeisFlat)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructType`](#StructType)  (Base Class)


---
#### StructType\.emitEncodes<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructType.emitEncodes}} -->
The `emitEncodes` method generates encoding functions for a struct type, including global encoding if applicable.
- **Inputs**:
    - `self`: An instance of the StructType class, representing a structured data type with fields and encoding capabilities.
- **Control Flow**:
    - Retrieve the full name of the struct type from the `fullname` attribute of the instance.
    - Call the [`emitEncode`](#PrimitiveMemberemitEncode) method with the full name to generate the encoding function for the struct type.
    - Check if the `produce_global` attribute is True and the struct is not flat using the [`isFlat`](#TypeNodeisFlat) method.
    - If the conditions are met, call the [`emitEncodeGlobal`](#PrimitiveMemberemitEncodeGlobal) method with the full name to generate the global encoding function.
- **Output**: The method does not return any value; it outputs encoding functions to a specified file or stream.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitEncode`](#PrimitiveMemberemitEncode)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.isFlat`](#TypeNodeisFlat)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitEncodeGlobal`](#PrimitiveMemberemitEncodeGlobal)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructType`](#StructType)  (Base Class)


---
#### StructType\.emitEncode<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructType.emitEncode}} -->
The [`emitEncode`](#PrimitiveMemberemitEncode) method generates C code for encoding a struct type into a binary format using a specified encoding context.
- **Inputs**:
    - `n`: The name of the struct type to be encoded, used to generate the function signature and variable names in the emitted C code.
- **Control Flow**:
    - Prints the function signature for the encoding function using the provided struct name `n` and writes it to the `body` file.
    - Initializes an integer variable `err` for error handling in the emitted code.
    - Iterates over each field in the `fields` attribute of the class instance.
    - For each field, checks if the field has an `encode` attribute and if it is set to `False`, skips encoding for that field.
    - Calls the [`emitEncode`](#PrimitiveMemberemitEncode) method on each field to generate the encoding logic for that field.
    - Prints a return statement for `FD_BINCODE_SUCCESS` to indicate successful encoding and writes it to the `body` file.
    - Closes the function definition with a closing brace and writes it to the `body` file.
- **Output**: The method outputs C code for a function that encodes a struct type into a binary format, writing this code to a file specified by the `body` variable.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitEncode`](#PrimitiveMemberemitEncode)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructType`](#StructType)  (Base Class)


---
#### StructType\.emitEncodeGlobal<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructType.emitEncodeGlobal}} -->
The [`emitEncodeGlobal`](#PrimitiveMemberemitEncodeGlobal) method generates C code for encoding a global structure of a specific type into a binary format.
- **Inputs**:
    - `n`: The name of the type for which the global encoding function is being generated.
- **Control Flow**:
    - The method sets the variable `n` to the full name of the type using `self.fullname`.
    - It prints the function signature for the encoding function to the `body` file.
    - An integer variable `err` is declared within the function body.
    - The method iterates over each field in `self.fields`.
    - For each field, it checks if the field has an `encode` attribute and if it is set to `False`, it skips encoding for that field.
    - For fields that should be encoded, it calls the [`emitEncodeGlobal`](#PrimitiveMemberemitEncodeGlobal) method on the field to generate the encoding logic.
    - Finally, it prints a return statement that returns `FD_BINCODE_SUCCESS` to indicate successful encoding.
- **Output**: The method outputs C code to a file, which defines a function for encoding a global structure of the specified type.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitEncodeGlobal`](#PrimitiveMemberemitEncodeGlobal)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructType`](#StructType)  (Base Class)


---
#### StructType\.emitImpls<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructType.emitImpls}} -->
The `emitImpls` method generates C code for encoding, decoding, and other operations for a struct type based on its fields and properties.
- **Inputs**: None
- **Control Flow**:
    - Check if `nomethods` is True; if so, return immediately.
    - Retrieve the full name of the struct type into variable `n`.
    - If `encoders` is not False, call [`emitEncodes`](#StructTypeemitEncodes) to generate encoding functions.
    - If `encoders` is not False, proceed to generate decoding functions based on whether the struct is fixed size and fuzzy.
    - For fixed size and fuzzy structs, generate a simple inline decoding function.
    - For other structs, generate a more complex decoding function that iterates over fields and handles underflow conditions.
    - Generate functions for decoding the struct and its global variant if applicable, including footprint and inner decoding functions.
    - Generate a `new` function for initializing the struct, unless it is fixed size and fuzzy.
    - Generate a `walk` function to traverse the struct fields.
    - Generate a `size` function to calculate the size of the struct.
- **Output**: The method outputs C code to the `body` file stream, implementing various functions for the struct type.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.StructType.emitEncodes`](#StructTypeemitEncodes)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.isFixedSize`](#TypeNodeisFixedSize)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.isFuzzy`](#TypeNodeisFuzzy)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.fixedSize`](#TypeNodefixedSize)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitDecodeFootprint`](#PrimitiveMemberemitDecodeFootprint)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitDecodeInner`](#PrimitiveMemberemitDecodeInner)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.isFlat`](#TypeNodeisFlat)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitDecodeInnerGlobal`](#PrimitiveMemberemitDecodeInnerGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitNew`](#PrimitiveMemberemitNew)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitWalk`](#PrimitiveMemberemitWalk)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitSize`](#PrimitiveMemberemitSize)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructType`](#StructType)  (Base Class)


---
#### StructType\.emitPostamble<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.StructType.emitPostamble}} -->
The [`emitPostamble`](#PrimitiveMemberemitPostamble) method iterates over all fields in the `StructType` instance and calls the [`emitPostamble`](#PrimitiveMemberemitPostamble) method on each field.
- **Inputs**: None
- **Control Flow**:
    - Iterate over each field in the `fields` attribute of the `StructType` instance.
    - For each field, call its [`emitPostamble`](#PrimitiveMemberemitPostamble) method.
- **Output**: The method does not return any value; it performs operations on each field's [`emitPostamble`](#PrimitiveMemberemitPostamble) method.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitPostamble`](#PrimitiveMemberemitPostamble)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.StructType`](#StructType)  (Base Class)



---
### EnumType<!-- {{#class:firedancer/src/flamenco/types/gen_stubs.EnumType}} -->
- **Members**:
    - `name`: The name of the enum type extracted from the JSON input.
    - `fullname`: The full name of the enum type, including the namespace.
    - `zerocopy`: A boolean indicating if the enum type supports zero-copy operations.
    - `variants`: A list of variants for the enum, which can be either strings or parsed members.
    - `comment`: An optional comment extracted from the JSON input, describing the enum.
    - `attribute`: A string representing the attribute for alignment or other properties.
    - `alignment`: An integer representing the alignment requirement for the enum type.
    - `compact`: A boolean indicating if the enum uses a compact representation.
    - `repr`: The representation type for the enum's discriminant, either 'uint' or 'ulong'.
    - `repr_codec_stem`: The codec stem used for encoding/decoding the enum's discriminant.
    - `repr_max_val`: The maximum value for the enum's discriminant representation.
- **Description**: The EnumType class represents an enumeration type in a structured format, allowing for the definition of multiple variants, each potentially with its own type. It supports various features such as zero-copy operations, compact representation, and alignment attributes. The class is designed to handle encoding and decoding operations, as well as generating C code for the enum's structure and its associated functions. It is initialized with a JSON object that specifies the enum's properties and variants.
- **Methods**:
    - [`firedancer/src/flamenco/types/gen_stubs.EnumType.__init__`](#EnumType__init__)
    - [`firedancer/src/flamenco/types/gen_stubs.EnumType.subTypes`](#EnumTypesubTypes)
    - [`firedancer/src/flamenco/types/gen_stubs.EnumType.subMembers`](#EnumTypesubMembers)
    - [`firedancer/src/flamenco/types/gen_stubs.EnumType.isFlat`](#EnumTypeisFlat)
    - [`firedancer/src/flamenco/types/gen_stubs.EnumType.isFixedSize`](#EnumTypeisFixedSize)
    - [`firedancer/src/flamenco/types/gen_stubs.EnumType.fixedSize`](#EnumTypefixedSize)
    - [`firedancer/src/flamenco/types/gen_stubs.EnumType.isFuzzy`](#EnumTypeisFuzzy)
    - [`firedancer/src/flamenco/types/gen_stubs.EnumType.emitHeader`](#EnumTypeemitHeader)
    - [`firedancer/src/flamenco/types/gen_stubs.EnumType.emitPrototypes`](#EnumTypeemitPrototypes)
    - [`firedancer/src/flamenco/types/gen_stubs.EnumType.emitImpls`](#EnumTypeemitImpls)
    - [`firedancer/src/flamenco/types/gen_stubs.EnumType.emitPostamble`](#EnumTypeemitPostamble)
- **Inherits From**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode`](#TypeNode)

**Methods**

---
#### EnumType\.\_\_init\_\_<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.EnumType.__init__}} -->
The [`__init__`](#TypeNode__init__) method initializes an instance of the `EnumType` class using a JSON object to set various attributes and configurations for the enum type.
- **Inputs**:
    - `json`: A dictionary containing configuration data for initializing the `EnumType` instance, including attributes like `name`, `variants`, `comment`, `alignment`, `attribute`, `compact`, and `repr`.
- **Control Flow**:
    - The method begins by calling the superclass's [`__init__`](#TypeNode__init__) method with the `json` argument.
    - It sets the `name` attribute from the `json` dictionary and constructs the `fullname` by appending the `namespace` to the `name`.
    - The `zerocopy` attribute is set based on the presence and value of the `zerocopy` key in the `json` dictionary, defaulting to `False` if not present.
    - An empty list is assigned to `variants`, and a loop iterates over the `variants` key in the `json` dictionary to populate this list with either parsed members or string names.
    - The `comment` attribute is set if the `comment` key is present in the `json` dictionary, otherwise it is set to `None`.
    - The method checks for `alignment` and `attribute` keys in the `json` dictionary to set the `attribute` and `alignment` attributes accordingly, defaulting to an empty string and `0` if neither is present.
    - The `compact` attribute is set based on the `compact` key in the `json` dictionary, defaulting to `False` if not present.
    - The `repr` attribute is set based on the `repr` key in the `json` dictionary, defaulting to `uint` if not present, and adjusts `repr_codec_stem` and `repr_max_val` based on the `repr` value.
- **Output**: The method does not return any value; it initializes the instance attributes of the `EnumType` class.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.__init__`](#TypeNode__init__)
    - [`firedancer/src/flamenco/types/gen_stubs.parseMember`](#parseMember)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.EnumType`](#EnumType)  (Base Class)


---
#### EnumType\.subTypes<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.EnumType.subTypes}} -->
The `subTypes` method iterates over the `variants` attribute of an `EnumType` instance, extracting and yielding sub-types using the [`extract_sub_type`](#extract_sub_type) function.
- **Inputs**:
    - `self`: An instance of the `EnumType` class, which contains the `variants` attribute to be iterated over.
- **Control Flow**:
    - Iterate over each element `v` in `self.variants`.
    - For each `v`, call `extract_sub_type(v)` to attempt to extract a sub-type.
    - If `extract_sub_type(v)` returns a non-None value, yield this sub-type.
- **Output**: Yields sub-types extracted from the `variants` attribute, if any are found.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.extract_sub_type`](#extract_sub_type)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.EnumType`](#EnumType)  (Base Class)


---
#### EnumType\.subMembers<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.EnumType.subMembers}} -->
The `subMembers` method yields non-string variants from the `variants` attribute of the `EnumType` class.
- **Inputs**:
    - `self`: An instance of the `EnumType` class, which contains the `variants` attribute.
- **Control Flow**:
    - Iterates over each element `v` in `self.variants`.
    - Checks if `v` is not an instance of `str`.
    - Yields `v` if it is not a string.
- **Output**: Yields each non-string variant from the `variants` list.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.EnumType`](#EnumType)  (Base Class)


---
#### EnumType\.isFlat<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.EnumType.isFlat}} -->
The [`isFlat`](#TypeNodeisFlat) method checks if all variants of an `EnumType` instance are flat, meaning they are either strings or have a flat structure.
- **Inputs**:
    - `self`: An instance of the `EnumType` class, which contains a list of variants to be checked for flatness.
- **Control Flow**:
    - Iterates over each variant in the `self.variants` list.
    - Checks if the variant is not a string; if so, calls `isFlat()` on the variant.
    - If any variant's `isFlat()` method returns `False`, the method immediately returns `False`.
    - If all variants are flat, the method returns `True`.
- **Output**: A boolean value indicating whether all variants in the `EnumType` instance are flat.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.isFlat`](#TypeNodeisFlat)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.EnumType`](#EnumType)  (Base Class)


---
#### EnumType\.isFixedSize<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.EnumType.isFixedSize}} -->
The `isFixedSize` method checks if all variants of the `EnumType` instance are simple strings, indicating a fixed size.
- **Inputs**:
    - `self`: An instance of the `EnumType` class, which contains a list of variants to be checked.
- **Control Flow**:
    - Initialize a boolean variable `all_simple` to `True`.
    - Iterate over each variant `v` in `self.variants`.
    - Check if `v` is not an instance of `str`.
    - If `v` is not a string, set `all_simple` to `False` and break the loop.
    - If `all_simple` remains `True`, return `True`.
- **Output**: Returns `True` if all variants are simple strings, indicating the enum is of fixed size; otherwise, it returns `None`.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.EnumType`](#EnumType)  (Base Class)


---
#### EnumType\.fixedSize<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.EnumType.fixedSize}} -->
The `fixedSize` method returns a constant integer value representing the fixed size of the `EnumType` object.
- **Inputs**: None
- **Control Flow**:
    - The method directly returns the integer value 4 without any conditions or calculations.
- **Output**: An integer value of 4, indicating the fixed size of the `EnumType` object.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.EnumType`](#EnumType)  (Base Class)


---
#### EnumType\.isFuzzy<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.EnumType.isFuzzy}} -->
The `isFuzzy` method in the `EnumType` class always returns `False`, indicating that the enum type is not considered 'fuzzy'.
- **Inputs**: None
- **Control Flow**:
    - The method simply returns the boolean value `False`.
- **Output**: The method outputs a boolean value `False`, indicating that the enum type is not fuzzy.
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.EnumType`](#EnumType)  (Base Class)


---
#### EnumType\.emitHeader<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.EnumType.emitHeader}} -->
The `emitHeader` method generates C header code for an enum type, including its structure, union, and typedefs, based on the enum's variants and attributes.
- **Inputs**:
    - `self`: An instance of the `EnumType` class, which contains attributes like `variants`, `fullname`, `attribute`, `comment`, `alignment`, and methods like [`isFixedSize`](#TypeNodeisFixedSize) and [`isFlat`](#TypeNodeisFlat).
- **Control Flow**:
    - Iterates over `self.variants` to call [`emitPreamble`](#PrimitiveMemberemitPreamble) on non-string variants.
    - Checks if the enum is not fixed size and prints a union definition for the enum's inner structure.
    - Iterates over `self.variants` again to call [`emitMember`](#PrimitiveMemberemitMember) on non-string variants, printing a placeholder if no inner structures exist.
    - Prints typedefs for the inner union and its global variant if applicable.
    - Prints a comment if `self.comment` is not None.
    - Prints the main struct definition for the enum, including a discriminant and an inner union if not fixed size.
    - Defines alignment macros based on `self.alignment`.
    - Prints the global struct definition and typedefs if `self.produce_global` is true and the enum is not flat.
- **Output**: The method outputs C header code to the `header` file, defining the enum's structure, unions, and typedefs.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitPreamble`](#PrimitiveMemberemitPreamble)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.isFixedSize`](#TypeNodeisFixedSize)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitMember`](#PrimitiveMemberemitMember)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.isFlat`](#TypeNodeisFlat)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitMemberGlobal`](#PrimitiveMemberemitMemberGlobal)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.EnumType`](#EnumType)  (Base Class)


---
#### EnumType\.emitPrototypes<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.EnumType.emitPrototypes}} -->
The `emitPrototypes` method generates C function prototypes for a given enum type, including constructors, encoders, decoders, and utility functions, and writes them to a header file.
- **Inputs**:
    - `self`: An instance of the EnumType class, representing the enum type for which prototypes are being generated.
- **Control Flow**:
    - Retrieve the full name of the enum type from `self.fullname`.
    - Check if the enum type is fixed size using `self.isFixedSize()`.
    - If fixed size, generate inline functions for creating new instances with and without a discriminant and write them to the header file.
    - If not fixed size, generate function prototypes for creating new instances with and without a discriminant and write them to the header file.
    - Generate function prototypes for encoding, walking, size calculation, alignment, decoding footprint, and decoding, and write them to the header file.
    - If the enum type has a global variant and is not flat, generate additional function prototypes for global decoding and encoding, and write them to the header file.
    - Iterate over each variant in `self.variants`, generate a function prototype to check if an instance is of a specific variant, and write it to the header file.
    - Generate an enum definition for the variants, assigning each a unique integer value, and write it to the header file.
- **Output**: The method outputs C function prototypes and enum definitions to a header file for the specified enum type.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.isFixedSize`](#TypeNodeisFixedSize)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.isFlat`](#TypeNodeisFlat)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.EnumType`](#EnumType)  (Base Class)


---
#### EnumType\.emitImpls<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.EnumType.emitImpls}} -->
The `emitImpls` method generates C code for various functions related to encoding, decoding, and managing enum types based on the class's attributes and variants.
- **Inputs**: None
- **Control Flow**:
    - Initialize the variable `n` with the class's `fullname` and set `indent` to two spaces.
    - Iterate over each variant in `self.variants`, generating a function to check if the discriminant matches the variant index.
    - If the enum is not fixed size, declare a function for creating a new inner structure based on the discriminant.
    - Generate a function to calculate the decode footprint for each variant, returning success or an encoding error for unknown discriminants.
    - Create a function to decode the footprint of the inner structure, handling compact and non-compact discriminants differently.
    - Define a function to decode the entire footprint, adjusting the context's data pointer and returning any errors.
    - If the enum is not fixed size, generate functions to decode the inner structure and, if applicable, the global inner structure based on the discriminant.
    - Generate a function to decode the inner structure, handling compact and non-compact discriminants differently.
    - Define a function to decode the entire structure, initializing it and allocating memory as needed.
    - If applicable, generate functions to encode the global inner structure and the entire global structure, handling compact and non-compact discriminants differently.
    - If the enum is not fixed size, generate functions to create a new inner structure and a new structure with a specific discriminant.
    - Generate a function to walk through the structure, calling a provided function for each variant and its inner structure.
    - Define a function to calculate the size of the structure, iterating over each variant and adding its size to the total.
    - If the enum is not fixed size, generate a function to encode the inner structure based on the discriminant.
    - Generate a function to encode the entire structure, handling compact and non-compact discriminants differently.
- **Output**: The method outputs C code to a file, defining functions for encoding, decoding, creating, and managing enum types and their variants.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.isFixedSize`](#TypeNodeisFixedSize)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitDecodeFootprint`](#PrimitiveMemberemitDecodeFootprint)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitDecodeInner`](#PrimitiveMemberemitDecodeInner)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.isFlat`](#TypeNodeisFlat)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitDecodeInnerGlobal`](#PrimitiveMemberemitDecodeInnerGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitEncodeGlobal`](#PrimitiveMemberemitEncodeGlobal)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitNew`](#PrimitiveMemberemitNew)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitWalk`](#PrimitiveMemberemitWalk)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitSize`](#PrimitiveMemberemitSize)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitEncode`](#PrimitiveMemberemitEncode)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.EnumType`](#EnumType)  (Base Class)


---
#### EnumType\.emitPostamble<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.EnumType.emitPostamble}} -->
The [`emitPostamble`](#PrimitiveMemberemitPostamble) method iterates over the `variants` attribute of the `EnumType` class and calls the [`emitPostamble`](#PrimitiveMemberemitPostamble) method on each variant that is not a string.
- **Inputs**: None
- **Control Flow**:
    - Iterate over each element `v` in `self.variants`.
    - Check if `v` is not an instance of `str`.
    - If `v` is not a string, call `v.emitPostamble()`.
- **Output**: The method does not return any value; it performs operations on the `variants` of the `EnumType` class.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitPostamble`](#PrimitiveMemberemitPostamble)
- **See also**: [`firedancer/src/flamenco/types/gen_stubs.EnumType`](#EnumType)  (Base Class)



# Functions

---
### parseMember<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.parseMember}} -->
The `parseMember` function determines the appropriate class to instantiate based on the type specified in a JSON object and returns an instance of that class.
- **Inputs**:
    - `namespace`: A string representing the namespace to be used for the member.
    - `json`: A dictionary containing the JSON representation of the member, including a 'type' key that specifies the member's type.
- **Control Flow**:
    - Extract the 'type' from the JSON dictionary and convert it to a string.
    - Check if the type is present in the `memberTypeMap` dictionary.
    - If the type is found in `memberTypeMap`, set `c` to the corresponding class from `memberTypeMap`.
    - If the type is not found in `memberTypeMap`, check if it is in `PrimitiveMember.emitMemberMap`.
    - If the type is found in `PrimitiveMember.emitMemberMap`, set the 'type' in the JSON dictionary and set `c` to `PrimitiveMember`.
    - If the type is not found in either map, set `c` to `StructMember`.
    - Return an instance of the class `c`, initialized with `namespace` and `json`.
- **Output**: An instance of a class (either from `memberTypeMap`, `PrimitiveMember`, or `StructMember`) that represents the member described by the JSON input.


---
### extract\_sub\_type<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.extract_sub_type}} -->
The `extract_sub_type` function determines the sub-type of a given member object based on its class or attributes.
- **Inputs**:
    - `member`: The object whose sub-type is to be determined; it can be an instance of various classes or have specific attributes.
- **Control Flow**:
    - Check if the member is an instance of `str`, `PrimitiveMember`, `OpaqueType`, or `BitVectorMember`, and return `None` if true.
    - Check if the member has an attribute `element`, and return the corresponding type from `type_map` if it exists, otherwise return `None`.
    - Check if the member has an attribute `type`, and return the corresponding type from `type_map` if it exists, otherwise return `None`.
    - Raise a `ValueError` if the member does not match any known type or attribute pattern.
- **Output**: Returns the sub-type of the member if it can be determined, otherwise returns `None` or raises a `ValueError`.


---
### extract\_member\_type<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.extract_member_type}} -->
The `extract_member_type` function determines the type of a given member and returns it if it has an 'element' or 'type' attribute, otherwise it returns None or raises an error for unknown types.
- **Inputs**:
    - `member`: The input parameter representing a member whose type is to be extracted.
- **Control Flow**:
    - Check if the member is an instance of `str`, `PrimitiveMember`, `OpaqueType`, or `BitVectorMember`, and return `None` if true.
    - Check if the member has an 'element' attribute, and return the member if true.
    - Check if the member has a 'type' attribute, and return the member if true.
    - Raise a `ValueError` if none of the conditions are met, indicating an unknown type.
- **Output**: The function returns the member itself if it has an 'element' or 'type' attribute, otherwise it returns `None` or raises a `ValueError` for unknown types.


---
### main<!-- {{#callable:firedancer/src/flamenco/types/gen_stubs.main}} -->
The `main` function processes type definitions from a JSON file, generates type objects, and writes C header and implementation files for these types.
- **Inputs**: None
- **Control Flow**:
    - Initialize an empty list `alltypes` to store type objects.
    - Iterate over `entries` from the JSON object to create type objects ([`OpaqueType`](#OpaqueType), [`StructType`](#StructType), [`EnumType`](#EnumType)) based on the `type` field and append them to `alltypes`.
    - Initialize a set `propagate` to track types that need their 'global' attribute propagated.
    - Populate a global `type_map` dictionary mapping type names to type objects and add types with `produce_global` set to `propagate`.
    - Recursively propagate the 'global' attribute through subtypes and submembers of types in `propagate`.
    - Create a dictionary `nametypes` to store types with a `fullname` and without `nomethods`.
    - Initialize global sets `fixedsizetypes`, `fuzzytypes`, and `flattypes` to categorize types based on their properties.
    - Iterate over `alltypes` to populate `fixedsizetypes`, `flattypes`, and `fuzzytypes` based on type properties.
    - Call [`emitHeader`](#OpaqueTypeemitHeader), [`emitPrototypes`](#OpaqueTypeemitPrototypes), [`emitImpls`](#OpaqueTypeemitImpls), and [`emitPostamble`](#PrimitiveMemberemitPostamble) methods on each type in `alltypes` to generate C code.
    - Write the type information to the `reflect` file, including type names, alignments, and function pointers for operations like `new`, `decode`, `size`, `walk`, `decode_footprint`, and `encode`.
- **Output**: The function does not return any value; it writes generated C code to specified output files.
- **Functions called**:
    - [`firedancer/src/flamenco/types/gen_stubs.OpaqueType`](#OpaqueType)
    - [`firedancer/src/flamenco/types/gen_stubs.StructType`](#StructType)
    - [`firedancer/src/flamenco/types/gen_stubs.EnumType`](#EnumType)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.subTypes`](#TypeNodesubTypes)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.subMembers`](#TypeNodesubMembers)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.isFixedSize`](#TypeNodeisFixedSize)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.fixedSize`](#TypeNodefixedSize)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.isFlat`](#TypeNodeisFlat)
    - [`firedancer/src/flamenco/types/gen_stubs.TypeNode.isFuzzy`](#TypeNodeisFuzzy)
    - [`firedancer/src/flamenco/types/gen_stubs.OpaqueType.emitHeader`](#OpaqueTypeemitHeader)
    - [`firedancer/src/flamenco/types/gen_stubs.OpaqueType.emitPrototypes`](#OpaqueTypeemitPrototypes)
    - [`firedancer/src/flamenco/types/gen_stubs.OpaqueType.emitImpls`](#OpaqueTypeemitImpls)
    - [`firedancer/src/flamenco/types/gen_stubs.PrimitiveMember.emitPostamble`](#PrimitiveMemberemitPostamble)



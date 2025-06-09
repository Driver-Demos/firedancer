# Purpose
This Python script is a GDB (GNU Debugger) pretty-printer configuration file, providing narrow functionality specifically for formatting and displaying custom data types during debugging sessions. It defines two classes, `fd_hash_printer` and `fd_signature_printer`, each designed to handle the conversion of specific data structures (`fd_hash` and `fd_signature`) into a human-readable hexadecimal string format. The [`to_string`](#fd_hash_printerto_string) method in each class checks if the data is all zeros and returns a placeholder string if so, otherwise it returns the hexadecimal representation. The [`build_pretty_printer`](#build_pretty_printer) function creates a collection of these pretty-printers and registers them with GDB, allowing for improved readability of these data types when debugging programs that use them. This script is a utility for developers working with the Firedancer project, enhancing the debugging experience by providing clear and concise representations of complex data structures.
# Imports and Dependencies

---
- `gdb.printing`


# Classes

---
### fd\_hash\_printer<!-- {{#class:firedancer/contrib/gdb/fd_gdb.fd_hash_printer}} -->
- **Members**:
    - `__val`: A private byte array representing a 32-byte hash value.
- **Description**: The `fd_hash_printer` class is designed to handle and format a 32-byte hash value for display purposes. It initializes with a dictionary containing a 'uc' key, which is expected to be a list of integers, and converts this list into a byte array. The class provides a method to convert the byte array into a hexadecimal string representation, returning a simplified string if the hash is all zeros.
- **Methods**:
    - [`firedancer/contrib/gdb/fd_gdb.fd_hash_printer.__init__`](#fd_hash_printer__init__)
    - [`firedancer/contrib/gdb/fd_gdb.fd_hash_printer.to_string`](#fd_hash_printerto_string)

**Methods**

---
#### fd\_hash\_printer\.\_\_init\_\_<!-- {{#callable:firedancer/contrib/gdb/fd_gdb.fd_hash_printer.__init__}} -->
The `__init__` method initializes an instance of the `fd_hash_printer` class by converting a dictionary's 'uc' list values into a 32-byte sequence.
- **Inputs**:
    - `val`: A dictionary containing a key 'uc' which maps to a list of values that can be converted to integers, representing the data to be stored as a byte sequence.
- **Control Flow**:
    - The method iterates over the first 32 elements of the 'uc' list in the input dictionary 'val'.
    - Each element is converted to an integer and then to a byte.
    - The resulting bytes are collected into a bytes object and assigned to the instance variable `self.__val`.
- **Output**: This method does not return any value; it initializes the instance variable `self.__val`.
- **See also**: [`firedancer/contrib/gdb/fd_gdb.fd_hash_printer`](#fd_hash_printer)  (Base Class)


---
#### fd\_hash\_printer\.to\_string<!-- {{#callable:firedancer/contrib/gdb/fd_gdb.fd_hash_printer.to_string}} -->
The `to_string` method converts the internal byte value to a hexadecimal string representation, or returns '0000...' if all bytes are zero.
- **Inputs**:
    - `self`: An instance of the `fd_hash_printer` class, containing a private byte array `__val`.
- **Control Flow**:
    - Checks if all bytes in `self.__val` are zero using a generator expression within the `all()` function.
    - If all bytes are zero, returns the string '0000...'.
    - If not all bytes are zero, converts the byte array `self.__val` to a hexadecimal string prefixed with '0x' and returns it.
- **Output**: A string representing the byte array in hexadecimal format, or '0000...' if the byte array is all zeros.
- **See also**: [`firedancer/contrib/gdb/fd_gdb.fd_hash_printer`](#fd_hash_printer)  (Base Class)



---
### fd\_signature\_printer<!-- {{#class:firedancer/contrib/gdb/fd_gdb.fd_signature_printer}} -->
- **Members**:
    - `__val`: A private byte array representing the signature, initialized from a dictionary input.
- **Description**: The `fd_signature_printer` class is designed to handle the conversion of a 64-byte signature value into a string representation, either as a hexadecimal string or a placeholder string if the value is all zeros. It is part of a pretty-printing mechanism for GDB, allowing for more readable output of signature data structures during debugging sessions.
- **Methods**:
    - [`firedancer/contrib/gdb/fd_gdb.fd_signature_printer.__init__`](#fd_signature_printer__init__)
    - [`firedancer/contrib/gdb/fd_gdb.fd_signature_printer.to_string`](#fd_signature_printerto_string)

**Methods**

---
#### fd\_signature\_printer\.\_\_init\_\_<!-- {{#callable:firedancer/contrib/gdb/fd_gdb.fd_signature_printer.__init__}} -->
The `__init__` method initializes an instance of the `fd_signature_printer` class by converting a dictionary's 'uc' list values to a bytes object.
- **Inputs**:
    - `val`: A dictionary containing a key 'uc', which is expected to be a list or array-like object with at least 64 elements that can be converted to integers.
- **Control Flow**:
    - The method iterates over the first 64 elements of the 'uc' list in the 'val' dictionary.
    - Each element is converted to an integer and then to a byte.
    - The resulting bytes are collected into a bytes object and assigned to the instance variable `self.__val`.
- **Output**: The method does not return any value; it initializes the instance variable `self.__val`.
- **See also**: [`firedancer/contrib/gdb/fd_gdb.fd_signature_printer`](#fd_signature_printer)  (Base Class)


---
#### fd\_signature\_printer\.to\_string<!-- {{#callable:firedancer/contrib/gdb/fd_gdb.fd_signature_printer.to_string}} -->
The `to_string` method converts the internal byte value to a hexadecimal string representation, or returns '0000...' if all bytes are zero.
- **Inputs**:
    - `self`: An instance of the `fd_signature_printer` class, containing a private byte array `__val`.
- **Control Flow**:
    - Checks if all bytes in `self.__val` are zero using a generator expression with `all()`.
    - If all bytes are zero, returns the string '0000...'.
    - If not all bytes are zero, converts `self.__val` to a hexadecimal string prefixed with '0x' and returns it.
- **Output**: A string representing the byte array in hexadecimal format, or '0000...' if the byte array is all zeros.
- **See also**: [`firedancer/contrib/gdb/fd_gdb.fd_signature_printer`](#fd_signature_printer)  (Base Class)



# Functions

---
### build\_pretty\_printer<!-- {{#callable:firedancer/contrib/gdb/fd_gdb.build_pretty_printer}} -->
The `build_pretty_printer` function creates and returns a pretty printer collection for GDB that includes custom printers for `fd_hash` and `fd_signature` types.
- **Inputs**: None
- **Control Flow**:
    - Instantiate a `RegexpCollectionPrettyPrinter` object named `pp` with the name 'Firedancer'.
    - Add a printer to `pp` for the type `fd_hash` using the regular expression `^fd_hash$` and the `fd_hash_printer` class.
    - Add a printer to `pp` for the type `fd_signature` using the regular expression `^fd_signature$` and the `fd_hash_printer` class.
    - Return the `pp` object.
- **Output**: A `RegexpCollectionPrettyPrinter` object configured with custom printers for `fd_hash` and `fd_signature` types.



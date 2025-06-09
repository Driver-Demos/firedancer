# Purpose
This file, `pb_common.h`, is a C header file that provides common support functions for protocol buffer encoding and decoding, specifically for use with `pb_encode.c` and `pb_decode.c`. It defines a set of functions that facilitate the iteration over fields in a protocol buffer message, including initializing field iterators, advancing them, and finding specific fields by tag or extension type. The functions are designed to be used internally by the encoding and decoding processes, rather than being directly accessed by most applications. Additionally, the file includes a conditional function for validating UTF-8 strings, which is only available if `PB_VALIDATE_UTF8` is defined. The header is wrapped in an `extern "C"` block to ensure compatibility with C++ compilers.
# Imports and Dependencies

---
- `pb_firedancer.h`


# Function Declarations (Public API)

---
### pb\_field\_iter\_begin<!-- {{#callable_declaration:pb_field_iter_begin}} -->
Initialize the field iterator to the beginning of the message descriptor.
- **Description**: Use this function to initialize a field iterator for traversing fields in a protocol buffer message. It sets the iterator to the start of the message described by the provided descriptor. This function is typically called before iterating over fields in a message. It is important to ensure that the message type is not empty, as the function will return false in such cases, indicating that the iterator could not be initialized.
- **Inputs**:
    - `iter`: A pointer to a pb_field_iter_t structure that will be initialized. Must not be null, and the caller retains ownership.
    - `desc`: A pointer to a pb_msgdesc_t structure describing the message. Must not be null, and the caller retains ownership.
    - `message`: A pointer to the message data to be iterated over. Must not be null, and the caller retains ownership.
- **Output**: Returns true if the iterator is successfully initialized; returns false if the message type is empty.
- **See also**: [`pb_field_iter_begin`](pb_common.c.driver.md#pb_field_iter_begin)  (Implementation)


---
### pb\_field\_iter\_begin\_extension<!-- {{#callable_declaration:pb_field_iter_begin_extension}} -->
Get a field iterator for an extension field.
- **Description**: This function initializes a field iterator to the beginning of an extension field within a protocol buffer message. It is used when you need to iterate over fields in an extension, which is a mechanism to add fields to a protocol buffer message without modifying its original definition. The function must be called with a valid extension object, and it returns false if the message type associated with the extension is empty. This function is typically used in advanced scenarios where extensions are employed in protocol buffer messages.
- **Inputs**:
    - `iter`: A pointer to a pb_field_iter_t structure that will be initialized to the beginning of the extension field. Must not be null.
    - `extension`: A pointer to a pb_extension_t structure representing the extension field to iterate over. Must not be null and should be properly initialized with a valid message type.
- **Output**: Returns a boolean value: true if the iterator was successfully initialized, or false if the message type is empty.
- **See also**: [`pb_field_iter_begin_extension`](pb_common.c.driver.md#pb_field_iter_begin_extension)  (Implementation)


---
### pb\_field\_iter\_begin\_const<!-- {{#callable_declaration:pb_field_iter_begin_const}} -->
Initialize a field iterator for a const message.
- **Description**: Use this function to initialize a field iterator for a message described by a constant message descriptor. It is useful when you need to iterate over fields of a message without modifying them. The function must be called with a valid iterator, message descriptor, and message pointer. It returns false if the message type is empty, indicating that there are no fields to iterate over. The pointers in the iterator will be non-const, but they should not be written to when using this function.
- **Inputs**:
    - `iter`: A pointer to a pb_field_iter_t structure that will be initialized to the beginning of the message fields. Must not be null.
    - `desc`: A pointer to a pb_msgdesc_t structure describing the message type. Must not be null.
    - `message`: A pointer to the message data to be iterated over. Must not be null and should point to a constant message.
- **Output**: Returns false if the message type is empty, otherwise true.
- **See also**: [`pb_field_iter_begin_const`](pb_common.c.driver.md#pb_field_iter_begin_const)  (Implementation)


---
### pb\_field\_iter\_begin\_extension\_const<!-- {{#callable_declaration:pb_field_iter_begin_extension_const}} -->
Get a field iterator for a constant extension field.
- **Description**: This function initializes a field iterator to the beginning of a constant extension field. It is useful when you need to iterate over fields in a protocol buffer extension without modifying the data. The function should be used when you have a constant extension and need to traverse its fields. It returns a boolean indicating whether the initialization was successful, which will be false if the extension is empty.
- **Inputs**:
    - `iter`: A pointer to a pb_field_iter_t structure that will be initialized to the beginning of the extension. Must not be null.
    - `extension`: A pointer to a constant pb_extension_t structure representing the extension to iterate over. Must not be null.
- **Output**: Returns a boolean value: true if the iterator was successfully initialized, false if the extension is empty.
- **See also**: [`pb_field_iter_begin_extension_const`](pb_common.c.driver.md#pb_field_iter_begin_extension_const)  (Implementation)


---
### pb\_field\_iter\_next<!-- {{#callable_declaration:pb_field_iter_next}} -->
Advance the field iterator to the next field.
- **Description**: Use this function to move a field iterator to the next field in a protocol buffer message. It is typically called after initializing the iterator with one of the `pb_field_iter_begin` functions. The function returns `false` when the iterator wraps back to the first field, indicating that all fields have been iterated over. This function is useful for iterating through all fields of a message, especially when processing or inspecting each field sequentially.
- **Inputs**:
    - `iter`: A pointer to a `pb_field_iter_t` structure representing the current position in the field iteration. Must not be null. The iterator should be properly initialized before calling this function.
- **Output**: Returns `false` if the iterator wraps back to the first field, otherwise returns `true`.
- **See also**: [`pb_field_iter_next`](pb_common.c.driver.md#pb_field_iter_next)  (Implementation)


---
### pb\_field\_iter\_find<!-- {{#callable_declaration:pb_field_iter_find}} -->
Advance the iterator to a field with the specified tag.
- **Description**: Use this function to move the field iterator to a field with a specific tag within a protocol buffer message. It is useful when you need to access or modify a particular field identified by its tag. The function must be called with a valid iterator that has been initialized using one of the `pb_field_iter_begin` functions. If the specified tag is not found, the function returns false, indicating that no such field exists in the message. This function does not modify the message itself, only the state of the iterator.
- **Inputs**:
    - `iter`: A pointer to a `pb_field_iter_t` structure that represents the current state of the field iterator. It must be initialized and valid. The function will modify this iterator to point to the field with the specified tag if found.
    - `tag`: A `uint32_t` representing the tag number of the field to find. The tag must be a valid field tag within the message's descriptor. If the tag is greater than the largest tag in the descriptor, the function will return false.
- **Output**: Returns `true` if the iterator successfully points to a field with the specified tag, otherwise returns `false` if no such field exists.
- **See also**: [`pb_field_iter_find`](pb_common.c.driver.md#pb_field_iter_find)  (Implementation)


---
### pb\_field\_iter\_find\_extension<!-- {{#callable_declaration:pb_field_iter_find_extension}} -->
Finds a field with type PB_LTYPE_EXTENSION in the iterator.
- **Description**: Use this function to locate a field of type PB_LTYPE_EXTENSION within a protocol buffer field iterator. It is useful when you need to handle extension fields specifically. The function searches through the fields starting from the current position of the iterator and returns true if an extension field is found. If no such field is found, it returns false. This function assumes that there can be only one extension range field per message, and it will wrap around to the start if necessary, ensuring a complete search of the message fields.
- **Inputs**:
    - `iter`: A pointer to a pb_field_iter_t structure representing the current position in the field iteration. Must not be null. The iterator is advanced during the search, and its state is modified.
- **Output**: Returns true if an extension field is found, otherwise returns false.
- **See also**: [`pb_field_iter_find_extension`](pb_common.c.driver.md#pb_field_iter_find_extension)  (Implementation)


---
### pb\_validate\_utf8<!-- {{#callable_declaration:pb_validate_utf8}} -->
Validate a UTF-8 encoded text string.
- **Description**: Use this function to check if a given null-terminated string is valid UTF-8. It is useful when you need to ensure that a string conforms to UTF-8 encoding standards before processing it further. The function iterates through the string, validating each character according to UTF-8 encoding rules, and returns a boolean indicating the validity of the string. It must be called with a valid, null-terminated string, and the caller is responsible for ensuring the string is properly allocated and accessible. The function does not modify the input string.
- **Inputs**:
    - `s`: A pointer to a null-terminated string to be validated. The string must be a valid memory location and properly null-terminated. The caller retains ownership of the string, and it must not be null. If the string is not valid UTF-8, the function returns false.
- **Output**: Returns true if the string is valid UTF-8, otherwise returns false.
- **See also**: [`pb_validate_utf8`](pb_common.c.driver.md#pb_validate_utf8)  (Implementation)



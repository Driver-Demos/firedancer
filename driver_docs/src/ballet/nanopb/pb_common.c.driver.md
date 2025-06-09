# Purpose
The provided C source code file, `pb_common.c`, is part of a library that supports Protocol Buffers (protobuf) encoding and decoding, specifically for the `pb_encode.c` and `pb_decode.c` files. This file contains common utility functions that facilitate the iteration over protobuf field descriptors, which are essential for both encoding and decoding operations. The primary functionality revolves around managing and navigating through field descriptors using iterators, which are structures that keep track of the current position within a message's field descriptors. The code includes functions to initialize iterators, advance them, and find specific fields or extensions within a protobuf message.

Key technical components include functions like [`load_descriptor_values`](#load_descriptor_values), which loads field descriptor values into an iterator, and [`advance_iterator`](#advance_iterator), which moves the iterator to the next field. The file also provides functions to begin iteration over fields ([`pb_field_iter_begin`](#pb_field_iter_begin)), handle extensions ([`pb_field_iter_begin_extension`](#pb_field_iter_begin_extension)), and validate UTF-8 strings if the `PB_VALIDATE_UTF8` macro is defined. The code is designed to be used as part of a larger library, providing internal utility functions rather than public APIs. It does not define external interfaces directly but supports the core functionality of protobuf encoding and decoding by managing field descriptors efficiently.
# Imports and Dependencies

---
- `pb_common.h`


# Functions

---
### load\_descriptor\_values<!-- {{#callable:load_descriptor_values}} -->
The `load_descriptor_values` function initializes a field iterator with descriptor values from a protocol buffer field descriptor, handling different descriptor formats and setting up pointers for field data and size.
- **Inputs**:
    - `iter`: A pointer to a `pb_field_iter_t` structure, which contains information about the current field being iterated over, including its descriptor, index, and message.
- **Control Flow**:
    - Check if the current index exceeds the field count in the descriptor; if so, return false.
    - Read the first word of the field descriptor and extract the field type.
    - Use a switch statement to handle different descriptor formats (1-word, 2-word, 4-word, and 8-word) based on the lowest 2 bits of the first word.
    - For each format, extract and set the array size, tag, size offset, data offset, and data size from the descriptor words.
    - If the message pointer is null, set field and size pointers to null; otherwise, calculate the field and size pointers based on offsets and field type.
    - If the field type is a pointer, set the data pointer to the dereferenced field pointer; otherwise, set it to the field pointer.
    - If the field type is a submessage, set the submessage descriptor from the descriptor's submessage info; otherwise, set it to null.
    - Return true to indicate successful loading of descriptor values.
- **Output**: Returns a boolean value: true if the descriptor values were successfully loaded into the iterator, false if the index is out of bounds.


---
### advance\_iterator<!-- {{#callable:advance_iterator}} -->
The `advance_iterator` function increments the index of a field iterator and adjusts related indices based on the type of the previous field, restarting if the end of the field list is reached.
- **Inputs**:
    - `iter`: A pointer to a `pb_field_iter_t` structure, which contains information about the current position and state of the field iteration.
- **Control Flow**:
    - Increment the `index` of the iterator.
    - Check if the `index` has reached or exceeded the `field_count` of the descriptor.
    - If the end is reached, reset `index`, `field_info_index`, `submessage_index`, and `required_field_index` to 0.
    - If not, read the previous field's descriptor to determine its type and length.
    - Update `field_info_index` by adding the length of the previous descriptor.
    - Update `required_field_index` if the previous field was required.
    - Update `submessage_index` if the previous field was a submessage.
- **Output**: The function does not return a value; it modifies the state of the `pb_field_iter_t` structure pointed to by `iter`.


---
### pb\_field\_iter\_begin<!-- {{#callable:pb_field_iter_begin}} -->
The `pb_field_iter_begin` function initializes a field iterator for a given message descriptor and message, and loads the initial field descriptor values.
- **Inputs**:
    - `iter`: A pointer to a `pb_field_iter_t` structure that will be initialized and used to iterate over the fields of the message.
    - `desc`: A pointer to a `pb_msgdesc_t` structure that describes the message's fields.
    - `message`: A pointer to the message data that the iterator will operate on.
- **Control Flow**:
    - The function starts by zeroing out the memory of the `iter` structure using `memset`.
    - It assigns the `desc` and `message` pointers to the corresponding fields in the `iter` structure.
    - The function then calls [`load_descriptor_values`](#load_descriptor_values) to initialize the iterator with the first field's descriptor values.
    - The result of [`load_descriptor_values`](#load_descriptor_values) is returned, indicating whether the initialization was successful.
- **Output**: The function returns a boolean value indicating whether the field descriptor values were successfully loaded, which implies successful initialization of the iterator.
- **Functions called**:
    - [`load_descriptor_values`](#load_descriptor_values)


---
### pb\_field\_iter\_begin\_extension<!-- {{#callable:pb_field_iter_begin_extension}} -->
The function `pb_field_iter_begin_extension` initializes a field iterator for a protocol buffer extension, determining the correct starting point based on whether the extension uses a pointer or not.
- **Inputs**:
    - `iter`: A pointer to a `pb_field_iter_t` structure that will be initialized to iterate over the fields of the extension.
    - `extension`: A pointer to a `pb_extension_t` structure representing the protocol buffer extension to be iterated over.
- **Control Flow**:
    - Retrieve the message descriptor from the extension's type argument.
    - Read the first field information word from the message descriptor.
    - Check if the field type is a pointer using the `PB_ATYPE` macro.
    - If the field type is a pointer, call [`pb_field_iter_begin`](#pb_field_iter_begin) with the address of the extension's destination.
    - If the field type is not a pointer, call [`pb_field_iter_begin`](#pb_field_iter_begin) with the extension's destination directly.
    - Set the iterator's `pSize` to point to the extension's `found` field.
    - Return the status from [`pb_field_iter_begin`](#pb_field_iter_begin).
- **Output**: Returns a boolean indicating whether the field iterator was successfully initialized.
- **Functions called**:
    - [`pb_field_iter_begin`](#pb_field_iter_begin)


---
### pb\_field\_iter\_next<!-- {{#callable:pb_field_iter_next}} -->
The `pb_field_iter_next` function advances a field iterator to the next field in a protocol buffer message descriptor and updates its state.
- **Inputs**:
    - `iter`: A pointer to a `pb_field_iter_t` structure, which represents the current state of the field iterator.
- **Control Flow**:
    - Call [`advance_iterator`](#advance_iterator) to move the iterator to the next field.
    - Call [`load_descriptor_values`](#load_descriptor_values) to update the iterator's state with the new field's descriptor values.
    - Return `true` if the iterator's index is not zero, indicating that it has successfully advanced to a new field; otherwise, return `false`.
- **Output**: A boolean value indicating whether the iterator successfully advanced to a new field (true) or wrapped around to the beginning (false).
- **Functions called**:
    - [`advance_iterator`](#advance_iterator)
    - [`load_descriptor_values`](#load_descriptor_values)


---
### pb\_field\_iter\_find<!-- {{#callable:pb_field_iter_find}} -->
The `pb_field_iter_find` function searches for a field with a specific tag in a protocol buffer field iterator and returns whether it was found.
- **Inputs**:
    - `iter`: A pointer to a `pb_field_iter_t` structure, which represents the current state of the field iteration.
    - `tag`: A `uint32_t` representing the tag number of the field to find.
- **Control Flow**:
    - Check if the current field's tag matches the target tag; if so, return true.
    - If the target tag is greater than the largest tag in the descriptor, return false.
    - If the target tag is less than the current tag, set the iterator index to the end to restart the search from the beginning.
    - Enter a loop to advance the iterator and check each field's tag against the target tag.
    - If a potential match is found, load the descriptor values and verify the tag and type; if they match, return true.
    - Continue the loop until the iterator returns to the starting index, indicating the search is complete without finding the tag.
    - Load descriptor values one last time and return false, indicating the tag was not found.
- **Output**: A boolean value indicating whether the field with the specified tag was found in the iterator.
- **Functions called**:
    - [`advance_iterator`](#advance_iterator)
    - [`load_descriptor_values`](#load_descriptor_values)


---
### pb\_field\_iter\_find\_extension<!-- {{#callable:pb_field_iter_find_extension}} -->
The function `pb_field_iter_find_extension` searches for an extension field in a protocol buffer field iterator and loads its descriptor values if found.
- **Inputs**:
    - `iter`: A pointer to a `pb_field_iter_t` structure, which represents the current state of the field iteration over a protocol buffer message.
- **Control Flow**:
    - Check if the current field type in the iterator is an extension; if so, return true.
    - Store the current index of the iterator to detect a full loop through the fields.
    - Enter a loop to advance the iterator and check each field's type without loading its values.
    - For each field, read its type information and check if it is an extension type.
    - If an extension type is found, load its descriptor values and return true.
    - If the loop completes without finding an extension, load the descriptor values of the current field and return false.
- **Output**: A boolean value indicating whether an extension field was found and its descriptor values were successfully loaded (true) or not (false).
- **Functions called**:
    - [`advance_iterator`](#advance_iterator)
    - [`load_descriptor_values`](#load_descriptor_values)


---
### pb\_const\_cast<!-- {{#callable:pb_const_cast}} -->
The `pb_const_cast` function casts away the const qualifier from a pointer using a union to avoid compiler warnings.
- **Inputs**:
    - `p`: A pointer to a constant object that needs to have its const qualifier removed.
- **Control Flow**:
    - A union is defined with two members: one for a void pointer and one for a const void pointer.
    - The input pointer `p` is assigned to the const void pointer member of the union.
    - The function returns the void pointer member of the union, effectively casting away the const qualifier.
- **Output**: A void pointer that points to the same object as the input pointer, but without the const qualifier.


---
### pb\_field\_iter\_begin\_const<!-- {{#callable:pb_field_iter_begin_const}} -->
The `pb_field_iter_begin_const` function initializes a field iterator for a given message descriptor and message, allowing iteration over the fields of a protocol buffer message in a read-only manner.
- **Inputs**:
    - `iter`: A pointer to a `pb_field_iter_t` structure that will be initialized to iterate over the fields of the message.
    - `desc`: A pointer to a `pb_msgdesc_t` structure that describes the message's fields.
    - `message`: A constant pointer to the message data to be iterated over.
- **Control Flow**:
    - The function calls [`pb_const_cast`](#pb_const_cast) to cast away the constness of the `message` pointer, allowing it to be used in a non-const context.
    - It then calls [`pb_field_iter_begin`](#pb_field_iter_begin), passing the iterator, descriptor, and the non-const message pointer to initialize the iterator for field iteration.
- **Output**: Returns a boolean value indicating whether the iterator was successfully initialized, which is determined by the success of [`pb_field_iter_begin`](#pb_field_iter_begin).
- **Functions called**:
    - [`pb_field_iter_begin`](#pb_field_iter_begin)
    - [`pb_const_cast`](#pb_const_cast)


---
### pb\_field\_iter\_begin\_extension\_const<!-- {{#callable:pb_field_iter_begin_extension_const}} -->
The function `pb_field_iter_begin_extension_const` initializes a field iterator for a constant extension by casting away the constness and calling [`pb_field_iter_begin_extension`](#pb_field_iter_begin_extension).
- **Inputs**:
    - `iter`: A pointer to a `pb_field_iter_t` structure that will be initialized to iterate over the fields of the extension.
    - `extension`: A pointer to a constant `pb_extension_t` structure representing the extension to be iterated over.
- **Control Flow**:
    - The function casts away the constness of the `extension` parameter using [`pb_const_cast`](#pb_const_cast) to allow modification of the extension data.
    - It calls [`pb_field_iter_begin_extension`](#pb_field_iter_begin_extension) with the `iter` and the casted `extension` to initialize the iterator.
- **Output**: Returns a boolean value indicating the success of initializing the iterator, as returned by [`pb_field_iter_begin_extension`](#pb_field_iter_begin_extension).
- **Functions called**:
    - [`pb_field_iter_begin_extension`](#pb_field_iter_begin_extension)
    - [`pb_const_cast`](#pb_const_cast)


---
### pb\_default\_field\_callback<!-- {{#callable:pb_default_field_callback}} -->
The `pb_default_field_callback` function handles encoding or decoding of a field using a callback function if available, otherwise it returns success without performing any operation.
- **Inputs**:
    - `istream`: A pointer to a `pb_istream_t` structure, representing the input stream for decoding.
    - `ostream`: A pointer to a `pb_ostream_t` structure, representing the output stream for encoding.
    - `field`: A pointer to a `pb_field_t` structure, representing the field to be processed.
- **Control Flow**:
    - Check if the field's data size matches the size of `pb_callback_t`.
    - Cast the field's data to a `pb_callback_t` pointer and check if it is not NULL.
    - If `istream` is not NULL and the decode function is available, call the decode function with `istream`, `field`, and the callback argument.
    - If `ostream` is not NULL and the encode function is available, call the encode function with `ostream`, `field`, and the callback argument.
    - If no operations are performed, return true indicating success.
- **Output**: Returns a boolean value indicating success (true) or failure (false) of the callback operation.


---
### pb\_validate\_utf8<!-- {{#callable:pb_validate_utf8}} -->
The `pb_validate_utf8` function checks if a given string is valid UTF-8 encoded text.
- **Inputs**:
    - `str`: A pointer to a null-terminated string that is to be validated as UTF-8.
- **Control Flow**:
    - The function casts the input string to a `pb_byte_t` pointer for byte-wise operations.
    - It enters a loop that continues until the end of the string (null character) is reached.
    - For each byte, it checks if the byte is a single-byte UTF-8 character (0xxxxxxx) and moves to the next byte if true.
    - If the byte indicates a two-byte UTF-8 character (110XXXXx), it checks the next byte for the correct continuation (10xxxxxx) and ensures it is not an overlong encoding; if valid, it advances by two bytes.
    - For three-byte UTF-8 characters (1110XXXX), it checks the next two bytes for correct continuation and ensures it is not overlong, a surrogate, or invalid (U+FFFE or U+FFFF); if valid, it advances by three bytes.
    - For four-byte UTF-8 characters (11110XXX), it checks the next three bytes for correct continuation and ensures it is not overlong or beyond the valid range (> U+10FFFF); if valid, it advances by four bytes.
    - If any byte does not match a valid UTF-8 pattern, the function returns false.
    - If the loop completes without finding invalid sequences, the function returns true.
- **Output**: A boolean value indicating whether the input string is valid UTF-8 (true) or not (false).



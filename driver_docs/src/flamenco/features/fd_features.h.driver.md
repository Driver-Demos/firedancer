# Purpose
This C header file, `fd_features.h`, is part of the Firedancer software suite and is designed to manage feature activation within the system. It provides a structured way to handle feature flags, which are used to control the activation and deactivation of various features in the software. The file defines macros and functions for checking the status of features, setting their activation states, and iterating over them. The core data structure, `fd_features_t`, holds the activation slots for each feature, indicating whether a feature is active, just activated, or disabled. The file also includes a `fd_feature_id_t` structure that maps feature IDs to their respective byte offsets within `fd_features_t`, facilitating efficient feature management.

The header file defines several functions and macros that provide both direct and indirect APIs for interacting with feature flags. These include enabling or disabling all features, enabling features that are hard-coded into the software, and managing one-off feature activations. Additionally, it offers an iterator-style API for traversing all supported features, which is useful for operations that need to process each feature systematically. The file also includes a query function to retrieve feature IDs based on a prefix, enhancing the flexibility and usability of the feature management system. Overall, this header file is a crucial component for managing feature states in the Firedancer software, ensuring that features can be dynamically controlled and queried as needed.
# Imports and Dependencies

---
- `../fd_flamenco_base.h`
- `fd_features_generated.h`


# Global Variables

---
### ids
- **Type**: `fd_feature_id_t const[]`
- **Description**: The `ids` variable is an external constant array of `fd_feature_id_t` structures, representing a list of known feature IDs in the system. Each element in the array corresponds to a feature, with the last element marked by an offset of `ULONG_MAX` to indicate the end of the list.
- **Use**: This array is used to map feature IDs to their respective byte offsets in the `fd_features_t` structure, facilitating feature management and activation within the system.


---
### fd\_feature\_id\_query
- **Type**: `function`
- **Description**: The `fd_feature_id_query` function is a constant function that takes an unsigned long integer `prefix` as an argument and returns a pointer to a `fd_feature_id_t` structure. This function is used to query a feature ID based on the first 8 bytes of the feature address, which are provided in little-endian order. If the query is successful, it returns a pointer to the corresponding ID in the `ids` array; otherwise, it returns NULL.
- **Use**: This function is used to retrieve a feature ID from the `ids` array using a prefix of the feature address.


# Data Structures

---
### fd\_features\_t
- **Type**: `union`
- **Members**:
    - `f`: An array of unsigned long integers representing activation slots for each feature.
- **Description**: The `fd_features_t` is a union data structure used to manage the activation state of various features within the Firedancer software. Each feature corresponds to an account in the account database, and the union contains an array of unsigned long integers (`f`) that store the activation slots for each feature. If a feature is not yet activated, its slot is set to `FD_FEATURE_DISABLED`. This structure allows for efficient checking and setting of feature activation states, and it is designed to accommodate changes over time as features become default or new features are added.


---
### fd\_feature\_id
- **Type**: `struct`
- **Members**:
    - `index`: Index of the feature in fd_features_t.
    - `id`: Public key of the feature.
    - `name`: Name of the feature as a constant string.
    - `cleaned_up`: Array indicating the cleaned-up cluster version for the feature.
    - `reverted`: Flag indicating if the feature was reverted.
    - `activated_on_all_clusters`: Flag indicating if the feature was activated on all clusters, used mainly for fuzzing.
- **Description**: The `fd_feature_id` structure is used to map a feature ID, represented by an account address, to its corresponding byte offset in the `fd_features_t` structure. It contains an index for locating the feature within `fd_features_t`, a public key for identifying the feature, a name for human-readable identification, an array to track the cleaned-up cluster version, and flags to indicate whether the feature has been reverted or activated across all clusters. This structure is essential for managing feature activation and deactivation within the Firedancer software.


---
### fd\_feature\_id\_t
- **Type**: `struct`
- **Members**:
    - `index`: Index of the feature in fd_features_t.
    - `id`: Public key of the feature.
    - `name`: Name of the feature as a C-style string.
    - `cleaned_up`: Array indicating the cleaned-up cluster version for the feature.
    - `reverted`: Flag indicating if the feature was reverted.
    - `activated_on_all_clusters`: Flag indicating if the feature was activated on all clusters, used for fuzzing.
- **Description**: The `fd_feature_id_t` structure is used to map a feature ID, represented by an account address, to its corresponding byte offset in the `fd_features_t` structure. It contains information about the feature's index, public key, name, and status flags such as whether it has been cleaned up, reverted, or activated across all clusters. This structure is essential for managing feature activation and deactivation within the Firedancer software.


# Functions

---
### fd\_feature\_iter\_init<!-- {{#callable:fd_feature_iter_init}} -->
The `fd_feature_iter_init` function initializes an iterator over the list of known feature IDs by returning a pointer to the start of the `ids` array.
- **Inputs**: None
- **Control Flow**:
    - The function simply returns the `ids` array, which is a list of known feature IDs.
- **Output**: A pointer to the first element of the `ids` array, which contains feature IDs.


---
### fd\_feature\_iter\_done<!-- {{#callable:fd_feature_iter_done}} -->
The `fd_feature_iter_done` function checks if a feature iteration has reached the end by comparing the feature's index to `ULONG_MAX`.
- **Inputs**:
    - `id`: A pointer to a `fd_feature_id_t` structure representing a feature ID.
- **Control Flow**:
    - The function takes a pointer to a `fd_feature_id_t` structure as input.
    - It checks if the `index` field of the structure pointed to by `id` is equal to `ULONG_MAX`.
    - If the `index` is `ULONG_MAX`, it indicates that the iteration is complete.
- **Output**: The function returns an integer value: 1 if the iteration is done (i.e., `index` is `ULONG_MAX`), otherwise 0.


---
### fd\_feature\_iter\_next<!-- {{#callable:fd_feature_iter_next}} -->
The `fd_feature_iter_next` function advances the iterator to the next feature ID in the list of known feature IDs.
- **Inputs**:
    - `id`: A pointer to the current `fd_feature_id_t` structure, representing the current position in the iteration over feature IDs.
- **Control Flow**:
    - The function takes a pointer to a `fd_feature_id_t` structure as input.
    - It returns a pointer to the next `fd_feature_id_t` structure by incrementing the input pointer by one.
- **Output**: A pointer to the next `fd_feature_id_t` structure in the list.


---
### fd\_features\_set<!-- {{#callable:fd_features_set}} -->
The `fd_features_set` function sets the activation slot for a specific feature in the `fd_features_t` structure using the feature's ID.
- **Inputs**:
    - `features`: A pointer to an `fd_features_t` structure where the feature's activation slot will be set.
    - `id`: A constant pointer to an `fd_feature_id_t` structure that identifies the feature whose activation slot is to be set.
    - `slot`: An unsigned long integer representing the activation slot to be set for the specified feature.
- **Control Flow**:
    - Access the feature's index from the `id` parameter.
    - Set the corresponding slot in the `features` structure's array `f` using the index from `id`.
- **Output**: This function does not return a value; it modifies the `features` structure in place.


---
### fd\_features\_get<!-- {{#callable:fd_features_get}} -->
The `fd_features_get` function retrieves the activation slot of a specified feature from a feature set.
- **Inputs**:
    - `features`: A pointer to a `fd_features_t` structure representing the current set of enabled feature flags.
    - `id`: A pointer to a `fd_feature_id_t` structure that identifies the feature whose activation slot is to be retrieved.
- **Control Flow**:
    - Access the `index` field of the `id` structure to determine the position of the feature in the `features` structure.
    - Return the value at the specified index in the `f` array of the `features` structure, which represents the activation slot of the feature.
- **Output**: The function returns an `ulong` representing the activation slot of the specified feature.


# Function Declarations (Public API)

---
### fd\_features\_disable\_all<!-- {{#callable_declaration:fd_features_disable_all}} -->
Disables all features in the given feature set.
- **Description**: Use this function to disable all features within a given `fd_features_t` structure. This is useful when you need to reset the feature set to a state where no features are active. The function iterates over all possible features and sets their activation slots to `FD_FEATURE_DISABLED`. Ensure that the `fd_features_t` structure is properly initialized before calling this function.
- **Inputs**:
    - `f`: A pointer to an `fd_features_t` structure representing the set of features to be disabled. Must not be null, and the structure should be properly initialized before use.
- **Output**: None
- **See also**: [`fd_features_disable_all`](fd_features.c.driver.md#fd_features_disable_all)  (Implementation)


---
### fd\_features\_enable\_all<!-- {{#callable_declaration:fd_features_enable_all}} -->
Enables all features in the given feature set.
- **Description**: This function is used to enable all features within a given feature set, represented by the `fd_features_t` structure. It iterates over all known feature IDs and sets their activation slots to zero, effectively marking them as enabled. This function should be called when you want to ensure that all features are activated, regardless of their current state. It is important to note that the feature set must be properly initialized before calling this function.
- **Inputs**:
    - `f`: A pointer to an `fd_features_t` structure representing the feature set to be modified. This pointer must not be null, and the structure should be properly initialized before use. The caller retains ownership of the memory.
- **Output**: None
- **See also**: [`fd_features_enable_all`](fd_features.c.driver.md#fd_features_enable_all)  (Implementation)


---
### fd\_features\_enable\_cleaned\_up<!-- {{#callable_declaration:fd_features_enable_cleaned_up}} -->
Enable features that are marked as cleaned up based on the cluster version.
- **Description**: This function enables features in the `fd_features_t` structure that have been marked as cleaned up for a given cluster version. It should be used when you want to activate features that are considered stable and cleaned up in the context of the specified cluster version. The function iterates over all known features and sets their activation status based on whether their cleaned-up version is less than or equal to the provided cluster version. Features with a cleaned-up version greater than the specified cluster version are disabled. This function assumes that the `fd_features_t` structure is properly initialized before calling.
- **Inputs**:
    - `f`: A pointer to an `fd_features_t` structure representing the current set of enabled feature flags. The caller must ensure this pointer is not null and points to a valid, initialized structure.
    - `cluster_version`: An array of three unsigned integers representing the major, minor, and patch version of the cluster. This array must not be null and should contain valid version numbers to compare against the cleaned-up versions of features.
- **Output**: None
- **See also**: [`fd_features_enable_cleaned_up`](fd_features.c.driver.md#fd_features_enable_cleaned_up)  (Implementation)


---
### fd\_features\_enable\_one\_offs<!-- {{#callable_declaration:fd_features_enable_one_offs}} -->
Enables specified one-off features in the feature set.
- **Description**: This function is used to enable specific features in a feature set by providing their public keys. It should be called when there is a need to activate features that are not part of the standard set but are specified manually. The function iterates over the provided list of feature public keys, decodes each one, and checks if it matches any known feature ID. If a match is found, the feature is activated by setting its activation slot to the specified value. This function assumes that the feature set has been properly initialized and that the list of one-off features is valid.
- **Inputs**:
    - `features`: A pointer to an fd_features_t structure representing the current set of enabled feature flags. The caller must ensure this is a valid and initialized feature set.
    - `one_offs`: An array of strings, each representing a base58-encoded public key of a feature to be enabled. The array must not be null, and each string must be a valid base58-encoded key.
    - `one_offs_cnt`: The number of elements in the one_offs array. It must be non-negative and should accurately reflect the number of keys provided.
    - `slot`: An unsigned long value representing the activation slot to be set for each feature that is successfully enabled. This value is used to mark the activation point of the feature.
- **Output**: None
- **See also**: [`fd_features_enable_one_offs`](fd_features.c.driver.md#fd_features_enable_one_offs)  (Implementation)


---
### fd\_feature\_id\_query<!-- {{#callable_declaration:fd_feature_id_query}} -->
Query a feature ID using the first 8 bytes of the feature address.
- **Description**: This function is used to retrieve a pointer to a feature ID structure based on a given prefix, which represents the first 8 bytes of a feature's address in little-endian order. It is useful for identifying features by their address prefix. The function returns a pointer to the corresponding feature ID in the `ids` array if the prefix matches a known feature; otherwise, it returns NULL. This function should be used when you need to map a feature address prefix to its corresponding feature ID.
- **Inputs**:
    - `prefix`: An unsigned long integer representing the first 8 bytes of a feature's address in little-endian order. The value must match one of the predefined prefixes to successfully retrieve a feature ID. If the prefix does not match any known feature, the function returns NULL.
- **Output**: A pointer to a `fd_feature_id_t` structure if the prefix matches a known feature, or NULL if no match is found.
- **See also**: [`fd_feature_id_query`](fd_features_generated.c.driver.md#fd_feature_id_query)  (Implementation)



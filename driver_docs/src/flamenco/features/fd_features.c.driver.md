# Purpose
This C source code file provides functionality for managing feature flags within a system, likely as part of a larger software application. The code defines several functions that manipulate feature states, such as enabling or disabling all features, enabling features based on a versioning system, and enabling specific "one-off" features identified by unique keys. The functions utilize an iterator pattern to traverse through feature identifiers, applying the necessary state changes to each feature. This suggests that the system supports a dynamic and flexible feature management system, allowing for granular control over which features are active at any given time.

The code is structured around a common theme of feature management, with each function serving a specific purpose related to enabling or disabling features. The functions rely on external components, such as `fd_feature_iter_init`, `fd_feature_iter_done`, and `fd_features_set`, which are likely defined in the included header file "fd_features.h". This indicates that the file is part of a modular system where feature management is abstracted into a separate component. The use of public APIs or external interfaces is implied by the functions' reliance on these external components, suggesting that the code is designed to be integrated into a larger application where feature management is a critical aspect.
# Imports and Dependencies

---
- `fd_features.h`


# Functions

---
### fd\_features\_enable\_all<!-- {{#callable:fd_features_enable_all}} -->
The `fd_features_enable_all` function iterates over all feature IDs and enables each feature by setting its value to 0 in the provided feature set.
- **Inputs**:
    - `f`: A pointer to an `fd_features_t` structure representing the feature set to be modified.
- **Control Flow**:
    - Initialize an iterator for feature IDs using `fd_feature_iter_init()`.
    - Enter a loop that continues as long as `fd_feature_iter_done(id)` returns false, indicating there are more feature IDs to process.
    - Within the loop, call `fd_features_set(f, id, 0UL)` to enable the feature corresponding to the current ID by setting its value to 0.
    - Advance to the next feature ID using `fd_feature_iter_next(id)` and repeat the process until all features are enabled.
- **Output**: The function does not return a value; it modifies the feature set `f` in place by enabling all features.
- **Functions called**:
    - [`fd_feature_iter_init`](fd_features.h.driver.md#fd_feature_iter_init)
    - [`fd_feature_iter_done`](fd_features.h.driver.md#fd_feature_iter_done)
    - [`fd_feature_iter_next`](fd_features.h.driver.md#fd_feature_iter_next)
    - [`fd_features_set`](fd_features.h.driver.md#fd_features_set)


---
### fd\_features\_disable\_all<!-- {{#callable:fd_features_disable_all}} -->
The `fd_features_disable_all` function iterates over all feature IDs and disables each feature in the provided feature set.
- **Inputs**:
    - `f`: A pointer to an `fd_features_t` structure representing the feature set to be modified.
- **Control Flow**:
    - Initialize an iterator for feature IDs using `fd_feature_iter_init()`.
    - Enter a loop that continues until `fd_feature_iter_done(id)` returns true, indicating all features have been processed.
    - Within the loop, call `fd_features_set(f, id, FD_FEATURE_DISABLED)` to disable the current feature identified by `id`.
    - Advance the iterator to the next feature ID using `fd_feature_iter_next(id)`.
- **Output**: The function does not return a value; it modifies the feature set pointed to by `f` by disabling all features.
- **Functions called**:
    - [`fd_feature_iter_init`](fd_features.h.driver.md#fd_feature_iter_init)
    - [`fd_feature_iter_done`](fd_features.h.driver.md#fd_feature_iter_done)
    - [`fd_feature_iter_next`](fd_features.h.driver.md#fd_feature_iter_next)
    - [`fd_features_set`](fd_features.h.driver.md#fd_features_set)


---
### fd\_features\_enable\_cleaned\_up<!-- {{#callable:fd_features_enable_cleaned_up}} -->
The function `fd_features_enable_cleaned_up` enables or disables features based on their cleanup version compared to a given cluster version.
- **Inputs**:
    - `f`: A pointer to an `fd_features_t` structure where feature states are set.
    - `cluster_version`: An array of three unsigned integers representing the current cluster version.
- **Control Flow**:
    - Initialize a feature iterator using `fd_feature_iter_init()` to iterate over all features.
    - For each feature, check if its `cleaned_up` version is less than or equal to the provided `cluster_version`.
    - If the feature's `cleaned_up` version is less than or equal to the `cluster_version`, enable the feature by setting its state to `0UL` using [`fd_features_set`](fd_features.h.driver.md#fd_features_set).
    - If the feature's `cleaned_up` version is greater than the `cluster_version`, disable the feature by setting its state to `FD_FEATURE_DISABLED` using [`fd_features_set`](fd_features.h.driver.md#fd_features_set).
- **Output**: The function does not return a value; it modifies the state of features in the `fd_features_t` structure based on the comparison of their cleanup version with the cluster version.
- **Functions called**:
    - [`fd_feature_iter_init`](fd_features.h.driver.md#fd_feature_iter_init)
    - [`fd_feature_iter_done`](fd_features.h.driver.md#fd_feature_iter_done)
    - [`fd_feature_iter_next`](fd_features.h.driver.md#fd_feature_iter_next)
    - [`fd_features_set`](fd_features.h.driver.md#fd_features_set)


---
### fd\_features\_enable\_one\_offs<!-- {{#callable:fd_features_enable_one_offs}} -->
The `fd_features_enable_one_offs` function enables specific features in a feature set based on a list of one-off public keys by setting them to a specified slot value.
- **Inputs**:
    - `f`: A pointer to an `fd_features_t` structure representing the feature set to be modified.
    - `one_offs`: An array of strings, each representing a Base58-encoded public key for a one-off feature.
    - `one_offs_cnt`: An unsigned integer representing the number of one-off public keys in the `one_offs` array.
    - `slot`: An unsigned long integer representing the slot value to set for the enabled features.
- **Control Flow**:
    - Initialize a 32-byte array `pubkey` to store decoded public keys.
    - Iterate over each public key string in the `one_offs` array.
    - Decode each Base58-encoded public key string into the `pubkey` array using `fd_base58_decode_32`.
    - Initialize a feature ID iterator using [`fd_feature_iter_init`](fd_features.h.driver.md#fd_feature_iter_init).
    - Iterate over each feature ID using the iterator until [`fd_feature_iter_done`](fd_features.h.driver.md#fd_feature_iter_done) returns true.
    - Compare the decoded `pubkey` with the current feature ID's public key using `memcmp`.
    - If a match is found, enable the feature by calling [`fd_features_set`](fd_features.h.driver.md#fd_features_set) with the feature ID and the specified `slot`, then break out of the inner loop.
- **Output**: The function does not return a value; it modifies the feature set `f` in place by enabling specific features based on the provided one-off public keys.
- **Functions called**:
    - [`fd_feature_iter_init`](fd_features.h.driver.md#fd_feature_iter_init)
    - [`fd_feature_iter_done`](fd_features.h.driver.md#fd_feature_iter_done)
    - [`fd_feature_iter_next`](fd_features.h.driver.md#fd_feature_iter_next)
    - [`fd_features_set`](fd_features.h.driver.md#fd_features_set)



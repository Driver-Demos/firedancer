# Purpose
This C header file defines a set of macros and functions for identifying and naming blockchain clusters based on their genesis hash. It includes macros representing different cluster types, such as `FD_CLUSTER_TESTNET` and `FD_CLUSTER_MAINNET_BETA`, each associated with a unique unsigned long integer. The file provides two functions: [`fd_genesis_cluster_identify`](#fd_genesis_cluster_identify), which takes a base58 encoded hash and returns the corresponding cluster macro, and [`fd_genesis_cluster_name`](#fd_genesis_cluster_name), which converts a cluster macro to its human-readable string name. This header is likely part of a larger system that interacts with blockchain networks, facilitating the identification and naming of clusters for configuration or logging purposes.
# Imports and Dependencies

---
- `../../util/fd_util.h`


# Global Variables

---
### fd\_genesis\_cluster\_name
- **Type**: `FD_FN_CONST char const *`
- **Description**: The `fd_genesis_cluster_name` is a function that returns a constant character string representing the human-readable name of a cluster based on a given cluster identifier. The function maps predefined cluster macros to their corresponding string names, such as converting `FD_CLUSTER_TESTNET` to "testnet".
- **Use**: This function is used to obtain the human-readable name of a cluster from its identifier for display or logging purposes.


# Function Declarations (Public API)

---
### fd\_genesis\_cluster\_identify<!-- {{#callable_declaration:fd_genesis_cluster_identify}} -->
Identify the cluster type from a base58 encoded genesis hash.
- **Description**: Use this function to determine the cluster type by providing a base58 encoded genesis hash. It compares the given hash against known hashes for public clusters and returns a corresponding cluster identifier. If the hash does not match any known cluster, the function returns FD_CLUSTER_UNKNOWN. This function expects a non-null string as input.
- **Inputs**:
    - `genesis_hash`: A non-null pointer to a C-style string containing a base58 encoded hash. The function expects this hash to be compared against known cluster hashes. If the input is null, the function will return FD_CLUSTER_UNKNOWN.
- **Output**: Returns an unsigned long representing the cluster type, which is one of the FD_CLUSTER_* macros. If the hash does not match any known cluster, it returns FD_CLUSTER_UNKNOWN.
- **See also**: [`fd_genesis_cluster_identify`](fd_genesis_cluster.c.driver.md#fd_genesis_cluster_identify)  (Implementation)


---
### fd\_genesis\_cluster\_name<!-- {{#callable_declaration:fd_genesis_cluster_name}} -->
Convert a cluster identifier to its corresponding human-readable name.
- **Description**: This function is used to obtain the human-readable name of a cluster given its identifier. It is useful when you need to display or log the name of a cluster based on its identifier. The function accepts a cluster identifier, which should be one of the predefined FD_CLUSTER_* macros. If the provided identifier does not match any known cluster, the function returns "unknown". The returned string is a constant with a static lifetime, meaning it does not need to be freed and will remain valid for the duration of the program.
- **Inputs**:
    - `cluster`: An unsigned long representing the cluster identifier. It should be one of the predefined FD_CLUSTER_* macros such as FD_CLUSTER_TESTNET or FD_CLUSTER_MAINNET_BETA. If the value does not match any known cluster, the function will return "unknown".
- **Output**: A constant character pointer to a string representing the human-readable name of the cluster. The string has a static lifetime and does not require deallocation.
- **See also**: [`fd_genesis_cluster_name`](fd_genesis_cluster.c.driver.md#fd_genesis_cluster_name)  (Implementation)



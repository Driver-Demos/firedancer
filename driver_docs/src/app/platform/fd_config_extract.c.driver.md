# Purpose
The provided C code is a utility designed to identify and log unrecognized configuration keys within a hierarchical data structure, referred to as a "pod." This code is part of a larger system, likely a configuration management tool, as indicated by the inclusion of "fd_config_extract.h" and the naming conventions used. The primary function, [`fdctl_pod_find_leftover`](#fdctl_pod_find_leftover), initiates a recursive search through the pod structure to detect keys that do not belong to any recognized subpod. If such keys are found, they are logged as warnings, helping developers or system administrators identify and rectify potential configuration issues.

The code is structured around two main functions: [`fdctl_pod_find_leftover`](#fdctl_pod_find_leftover) and its helper, [`fdctl_pod_find_leftover_recurse`](#fdctl_pod_find_leftover_recurse). The recursive function traverses the pod structure, maintaining a stack of keys to track the current path within the hierarchy. If a non-subpod key is encountered, it returns the depth of the key, which is then used by the main function to construct a path string representing the unrecognized key. This path is logged as a warning, providing a clear indication of the configuration anomaly. The code is not thread-safe due to its use of static buffers, which suggests it is intended for single-threaded execution or requires external synchronization when used in a multi-threaded context.
# Imports and Dependencies

---
- `fd_config_extract.h`


# Functions

---
### fdctl\_pod\_find\_leftover\_recurse<!-- {{#callable:fdctl_pod_find_leftover_recurse}} -->
The function `fdctl_pod_find_leftover_recurse` recursively searches a pod structure for non-subpod keys and logs a warning if any are found, returning the depth of the leftover key if present.
- **Inputs**:
    - `pod`: A pointer to the pod structure to be searched for leftover keys.
    - `stack`: An array of strings used to store the keys encountered during the recursive search.
    - `depth`: The current depth of recursion, indicating how many nested levels have been traversed.
- **Control Flow**:
    - Check if the current depth exceeds the maximum allowed depth (`FDCTL_CFG_MAX_DEPTH`); if so, log a warning and return the current depth.
    - Initialize an iterator to traverse the pod structure.
    - For each item in the pod, retrieve its information and store the key in the stack at the current depth.
    - Increment the depth and check if the current item is a subpod; if it is, recursively call `fdctl_pod_find_leftover_recurse` on the subpod.
    - If the recursive call returns a non-zero depth, return this depth as it indicates a leftover key was found.
    - If the current item is not a subpod, return the current depth as it indicates a leftover key was found.
    - Decrement the depth after processing each item in the pod.
- **Output**: Returns 0 if no leftover key is found; otherwise, returns a non-zero value representing the depth of the leftover key.


---
### fdctl\_pod\_find\_leftover<!-- {{#callable:fdctl_pod_find_leftover}} -->
The `fdctl_pod_find_leftover` function searches for unrecognized keys in a configuration pod and logs a warning if any are found.
- **Inputs**:
    - `pod`: A pointer to an unsigned character array representing the configuration pod to be searched for unrecognized keys.
- **Control Flow**:
    - Initialize a static stack to store keys and call [`fdctl_pod_find_leftover_recurse`](#fdctl_pod_find_leftover_recurse) to search for unrecognized keys, storing the depth of the search.
    - If no unrecognized keys are found (depth is zero), return 1 indicating success.
    - If unrecognized keys are found, initialize a path string to store the full path of the unrecognized key.
    - Iterate over the stack to construct the path of the unrecognized key, appending each key to the path string.
    - If the path string exceeds its maximum length, append '...' to indicate truncation.
    - Log a warning message with the constructed path of the unrecognized key.
    - Return 0 to indicate that unrecognized keys were found.
- **Output**: Returns 1 if no unrecognized keys are found, otherwise returns 0 and logs a warning with the path of the unrecognized key.
- **Functions called**:
    - [`fdctl_pod_find_leftover_recurse`](#fdctl_pod_find_leftover_recurse)



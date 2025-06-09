# Purpose
The provided content appears to be a command-line interface (CLI) usage guide for a tool named `fd_pod_ctl`. This tool is designed to manage and manipulate data structures referred to as "pods" within a workspace (`wksp`). The functionality is relatively broad, covering operations such as creating, deleting, resetting, and listing pods, as well as inserting, removing, updating, and querying data within these pods. The commands allow for detailed manipulation of data types and structures, including handling of various data types like integers, floats, and strings, and even file contents. The relevance of this file to a codebase lies in its role as a user guide for developers or system administrators who need to interact with the pod data structures, providing them with the necessary commands and options to effectively manage and query the data within the application environment.
# Content Summary
The provided content is a command-line interface (CLI) usage guide for a tool named `fd_pod_ctl`. This tool is designed to manage and manipulate data structures referred to as "pods" within a workspace (wksp). The document outlines various commands available to users, detailing their functionality and expected behavior.

Key commands include:

- **help**: Displays the help message, listing available commands and their descriptions.
- **tag val**: Sets a tag for subsequent workspace allocations, with a default value of 1.
- **new wksp max**: Creates a new pod in the specified workspace with a maximum size, defaulting to 4KiB if not specified. It outputs the workspace constructor address of the empty pod upon success.
- **delete pod** and **reset pod**: These commands delete or reset a pod at a given workspace constructor address.
- **list pod**: Recursively lists the contents of a pod, outputting to standard output.
- **insert pod type path val**: Inserts a specified type and value into a pod at a given path, with various data types supported, such as integers, floats, and strings. It fails if the path already exists.
- **insert-file pod path file**: Inserts the contents of a file into a pod as a buffer, with the path failing if it already exists.
- **remove pod path**: Removes a specified path from a pod, failing if the path does not exist.
- **update pod type path val** and **set pod type path val**: These commands update or set a value at a specified path, with conditions on type matching and path existence.
- **compact pod full**: Compacts the pod, potentially altering the locations of existing values.
- **query-root what pod** and **query what pod path**: These commands query the pod or a specific path within the pod for various metrics, such as existence, type, value, and usage statistics.

The document emphasizes that the current implementation does not support concurrent users, implying that operations on pods are expected to be performed sequentially. This guide is crucial for developers working with the `fd_pod_ctl` tool, as it provides detailed instructions on managing pod data structures effectively.

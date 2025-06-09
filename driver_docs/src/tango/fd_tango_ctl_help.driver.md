# Purpose
The provided content appears to be a command-line interface (CLI) usage guide for a tool named `fd_tango_ctl`. This tool is designed to manage and interact with various types of caches and control variables within a workspace, likely in a software system that handles data fragmentation and flow control. The file provides a narrow functionality, focusing on operations such as creating, deleting, querying, and updating different types of caches (meta cache, data cache, tag cache) and control variables (flow control, command and control). Each command is associated with specific parameters and outputs, such as workspace addresses (gaddr) and sequence numbers, which are crucial for managing the lifecycle and state of these components. The relevance of this file to a codebase lies in its role as a reference for developers or system administrators to effectively utilize the `fd_tango_ctl` tool for managing data flow and cache operations within the system.
# Content Summary
The provided content is a command-line interface (CLI) usage guide for a tool named `fd_tango_ctl`. This tool is designed to manage various types of caches and control variables within a workspace (`wksp`). The commands available in this tool allow users to create, delete, query, and manipulate different types of caches and control variables, each identified by a global address (`gaddr`).

Key commands include:

1. **Tag Management**: The `tag` command sets a tag for subsequent workspace allocations, with a default value of 1.

2. **Meta Cache (mcache) Operations**:
   - `new-mcache`: Creates a fragment meta cache with specified depth, application region size, and initial sequence number.
   - `delete-mcache`: Deletes the mcache at a specified `gaddr`.
   - `query-mcache`: Queries the mcache, with verbosity options for detailed output.

3. **Data Cache (dcache) Operations**:
   - `new-dcache`: Creates a fragment data cache optimized for specific payload sizes and concurrency.
   - `new-dcache-raw`: Creates a data cache with specified data and application region sizes.
   - `delete-dcache`: Deletes the dcache at a specified `gaddr`.
   - `query-dcache`: Queries the dcache, with verbosity options for detailed output.

4. **Flow Control Variable (fseq) Operations**:
   - `new-fseq`: Creates a flow control variable initialized to a given sequence number.
   - `delete-fseq`: Deletes the fseq at a specified `gaddr`.
   - `query-fseq`: Queries the fseq, with verbosity options for detailed output.
   - `update-fseq`: Updates the flow control variable to a new sequence number.

5. **Command and Control Variable (cnc) Operations**:
   - `new-cnc`: Creates a command and control variable with specified type, initial heartbeat, and application region size.
   - `delete-cnc`: Deletes the cnc at a specified `gaddr`.
   - `query-cnc`: Queries the cnc, with verbosity options for detailed output.
   - `signal-cnc`: Sends a signal to the cnc and waits for a response, with predefined responses indicating the state of the thread.

6. **Tag Cache (tcache) Operations**:
   - `new-tcache`: Creates a tag cache with specified depth and map count.
   - `delete-tcache`: Deletes the tcache at a specified `gaddr`.
   - `query-tcache`: Queries the tcache, though verbosity is ignored.
   - `reset-tcache`: Resets the tcache at a specified `gaddr`.

Each command is designed to interact with the workspace's memory management and control structures, providing a robust interface for managing resources in a concurrent environment. The tool outputs the global address of created resources to standard output, facilitating further operations on these resources.

# Purpose
The provided content is a command-line interface (CLI) usage guide for a tool named `fd_wksp_ctl`, which is used to manage memory workspaces. This file is a configuration and operational guide that provides detailed instructions on how to execute various commands related to workspace management, such as creating, deleting, allocating, and freeing memory within workspaces. The functionality is narrow, focusing specifically on memory management tasks, including setting tags, querying workspace information, and handling checkpoints for data persistence and recovery. The commands are organized into conceptual categories such as allocation, deallocation, verification, and checkpoint management, all centered around efficient and reliable memory workspace operations. This file is crucial for developers or system administrators who need to interact with the memory management system of the application, ensuring they can perform necessary operations and maintain system integrity.
# Content Summary
The provided content is a command-line interface (CLI) usage guide for a tool named `fd_wksp_ctl`, which is designed to manage and manipulate workspaces (wksp) in a shared memory environment. This tool offers a variety of commands to create, manage, and query workspaces, as well as to handle memory allocations within these workspaces.

Key commands and their functionalities include:

- **help**: Displays the help message, listing all available commands and their descriptions.
- **tag**: Sets a tag for subsequent workspace allocations, with a default value of 1.
- **supported-styles**: Lists the supported checkpoint styles for the target system.
- **new**: Creates a new workspace with specified parameters such as page count, page size, CPU index sequence, and permissions.
- **delete**: Removes a workspace, prioritizing the deletion of the largest page size if multiple shared memory regions exist with the same name.
- **alloc**: Allocates a specified number of bytes with a given alignment from a tagged workspace, outputting the allocation address on success.
- **info**: Provides information about a workspace allocation matching a specific tag, including its global address and size.
- **free**: Frees an allocation at a specified workspace address.
- **tag-query**: Retrieves the tag associated with a given workspace address.
- **tag-free**: Frees all allocations within a workspace that match a specified tag.
- **memset**: Sets all bytes in an allocation to a specified value.
- **check**: Verifies if any processes terminated unexpectedly during a workspace operation and attempts to rebuild if necessary.
- **verify**: Conducts a full verification of the workspace, logging any errors found.
- **rebuild**: Rebuilds the workspace, potentially repairing metadata corruption, using a specified seed.
- **reset**: Frees all allocations in a workspace.
- **usage**: Summarizes workspace usage, detailing total, used, and free space, as well as usage by allocations with a specific tag.
- **query**: Provides detailed workspace usage information.
- **checkpt**: Creates a checkpoint of a workspace, with options for different styles and additional user-provided information.
- **checkpt-query**: Queries a checkpoint for metadata and usage information, with varying verbosity levels.
- **restore**: Restores a workspace from a checkpoint, replacing current allocations and rebuilding with a specified seed.

This tool is essential for developers working with shared memory systems, providing comprehensive control over workspace creation, allocation, and management, as well as robust mechanisms for checkpointing and restoring workspace states.

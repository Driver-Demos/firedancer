# Purpose
This C source code file is a comprehensive test suite for a data structure and algorithm implementation related to a "ghost" node system, likely used in a distributed or consensus-based environment. The file includes a series of test functions that validate various operations on a ghost node structure, such as node insertion, querying, voting, and publishing. The code is structured to test the functionality of the ghost node system, including the ability to handle complex tree structures, replay votes, and manage epochs and voters. The tests are designed to ensure the correctness and robustness of the ghost node operations, including edge cases like invalid nodes and switching votes.

The file is intended to be compiled and executed as a standalone program, as indicated by the presence of a [`main`](#main) function. It utilizes a custom memory workspace (`fd_wksp_t`) for managing memory allocations, which suggests that the ghost node system is designed to operate in a controlled memory environment, possibly for performance or safety reasons. The code makes extensive use of macros and custom data types, such as `fd_ghost_t`, `fd_epoch_t`, and `fd_voter_t`, which are likely defined in the included headers. The test functions are modular, each focusing on a specific aspect of the ghost node system, and they use assertions (`FD_TEST`) to verify the expected outcomes of operations. This file does not define public APIs or external interfaces but rather serves as an internal validation tool for developers working on the ghost node system.
# Imports and Dependencies

---
- `fd_ghost.h`
- `../epoch/fd_epoch.h`
- `stdarg.h`


# Functions

---
### query\_mut<!-- {{#callable:query_mut}} -->
The `query_mut` function retrieves a mutable node from a ghost node map using a specified slot.
- **Inputs**:
    - `ghost`: A pointer to an `fd_ghost_t` structure representing the ghost context.
    - `slot`: An unsigned long integer representing the slot number to query in the node map.
- **Control Flow**:
    - Retrieve the workspace containing the ghost using `fd_wksp_containing` function.
    - Get the node map address from the workspace using `fd_wksp_laddr_fast` with the ghost's node map global address.
    - Get the node pool address from the workspace using `fd_wksp_laddr_fast` with the ghost's node pool global address.
    - Query the node map for the element corresponding to the given slot using `fd_ghost_node_map_ele_query`, passing the node map, slot, and node pool.
- **Output**: Returns a pointer to an `fd_ghost_node_t` structure representing the mutable node corresponding to the specified slot.


---
### mock\_epoch<!-- {{#callable:mock_epoch}} -->
The `mock_epoch` function initializes and returns a new epoch structure with specified voters and their stakes.
- **Inputs**:
    - `wksp`: A pointer to a workspace (`fd_wksp_t`) where the epoch memory will be allocated.
    - `total_stake`: The total stake value for the epoch.
    - `voter_cnt`: The number of voters to be added to the epoch.
    - `...`: A variable argument list containing pairs of `fd_pubkey_t` (voter public key) and `ulong` (voter stake) for each voter.
- **Control Flow**:
    - Allocate memory for the epoch using `fd_wksp_alloc_laddr` with alignment and footprint based on the number of voters.
    - Check if the memory allocation was successful using `FD_TEST`.
    - Create a new epoch with the allocated memory and join it using `fd_epoch_new` and `fd_epoch_join`, respectively.
    - Initialize a variable argument list to process the voter public keys and stakes.
    - Iterate over the number of voters, extracting each voter's public key and stake from the variable argument list.
    - Insert each voter into the epoch's voter list using `fd_epoch_voters_insert` and set their stake and replay vote.
    - End the variable argument list processing with `va_end`.
    - Set the total stake of the epoch to the provided `total_stake` value.
    - Return the initialized epoch.
- **Output**: A pointer to the newly created and initialized `fd_epoch_t` structure.


---
### test\_ghost\_simple<!-- {{#callable:test_ghost_simple}} -->
The `test_ghost_simple` function tests the basic functionality of the ghost protocol by initializing a ghost structure, inserting nodes, verifying the structure, and simulating voting and replaying votes.
- **Inputs**:
    - `wksp`: A pointer to a workspace (`fd_wksp_t`) used for memory allocation and management.
- **Control Flow**:
    - Allocate memory for the ghost structure using `fd_wksp_alloc_laddr` and initialize it with [`fd_ghost_new`](fd_ghost.c.driver.md#fd_ghost_new) and [`fd_ghost_join`](fd_ghost.c.driver.md#fd_ghost_join).
    - Initialize the ghost structure with [`fd_ghost_init`](fd_ghost.c.driver.md#fd_ghost_init).
    - Insert nodes into the ghost structure using the `INSERT` macro, which calls `fd_ghost_insert`.
    - Verify the ghost structure with [`fd_ghost_verify`](fd_ghost.c.driver.md#fd_ghost_verify) and assert its correctness using `FD_TEST`.
    - Create a mock epoch with a single voter using [`mock_epoch`](#mock_epoch).
    - Query the voter from the epoch using `fd_epoch_voters_query`.
    - Print the ghost structure using [`fd_ghost_print`](fd_ghost.c.driver.md#fd_ghost_print).
    - Simulate replaying votes with [`fd_ghost_replay_vote`](fd_ghost.c.driver.md#fd_ghost_replay_vote) and print the ghost structure after each vote.
    - Free the allocated memory for the epoch and ghost structure using `fd_wksp_free_laddr`.
- **Output**: The function does not return a value; it performs tests and assertions to verify the correctness of the ghost protocol implementation.
- **Functions called**:
    - [`fd_ghost_align`](fd_ghost.h.driver.md#fd_ghost_align)
    - [`fd_ghost_footprint`](fd_ghost.h.driver.md#fd_ghost_footprint)
    - [`fd_ghost_join`](fd_ghost.c.driver.md#fd_ghost_join)
    - [`fd_ghost_new`](fd_ghost.c.driver.md#fd_ghost_new)
    - [`fd_ghost_init`](fd_ghost.c.driver.md#fd_ghost_init)
    - [`fd_ghost_verify`](fd_ghost.c.driver.md#fd_ghost_verify)
    - [`mock_epoch`](#mock_epoch)
    - [`fd_ghost_print`](fd_ghost.c.driver.md#fd_ghost_print)
    - [`fd_ghost_root`](fd_ghost.h.driver.md#fd_ghost_root)
    - [`fd_ghost_replay_vote`](fd_ghost.c.driver.md#fd_ghost_replay_vote)
    - [`fd_ghost_delete`](fd_ghost.c.driver.md#fd_ghost_delete)
    - [`fd_ghost_leave`](fd_ghost.c.driver.md#fd_ghost_leave)


---
### test\_ghost\_publish\_left<!-- {{#callable:test_ghost_publish_left}} -->
The `test_ghost_publish_left` function tests the behavior of the ghost protocol by initializing a ghost structure, inserting nodes, replaying votes, publishing a node, and verifying the structure's integrity.
- **Inputs**:
    - `wksp`: A pointer to a workspace (`fd_wksp_t`) used for memory allocation and management.
- **Control Flow**:
    - Allocate memory for the ghost structure using `fd_wksp_alloc_laddr` and verify allocation success with `FD_TEST`.
    - Initialize a ghost structure with [`fd_ghost_new`](fd_ghost.c.driver.md#fd_ghost_new) and join it with [`fd_ghost_join`](fd_ghost.c.driver.md#fd_ghost_join).
    - Initialize node slots and parent slots arrays for node insertion.
    - Insert nodes into the ghost structure using the `INSERT` macro, which calls `fd_ghost_insert`.
    - Verify the ghost structure's integrity with [`fd_ghost_verify`](fd_ghost.c.driver.md#fd_ghost_verify).
    - Create a mock epoch with a single voter using [`mock_epoch`](#mock_epoch) and query the voter with `fd_epoch_voters_query`.
    - Replay votes for specific slots using [`fd_ghost_replay_vote`](fd_ghost.c.driver.md#fd_ghost_replay_vote) and verify the structure after each vote.
    - Publish a node with [`fd_ghost_publish`](fd_ghost.c.driver.md#fd_ghost_publish) and verify the root node's slot value.
    - Iterate over the node map using `fd_ghost_node_map_iter` to log each node's slot.
    - Verify the ghost structure's integrity again and check specific node conditions.
    - Free the allocated memory using `fd_wksp_free_laddr`.
- **Output**: The function does not return a value; it performs tests and assertions to verify the correct behavior of the ghost protocol.
- **Functions called**:
    - [`fd_ghost_align`](fd_ghost.h.driver.md#fd_ghost_align)
    - [`fd_ghost_footprint`](fd_ghost.h.driver.md#fd_ghost_footprint)
    - [`fd_ghost_join`](fd_ghost.c.driver.md#fd_ghost_join)
    - [`fd_ghost_new`](fd_ghost.c.driver.md#fd_ghost_new)
    - [`fd_ghost_init`](fd_ghost.c.driver.md#fd_ghost_init)
    - [`fd_ghost_verify`](fd_ghost.c.driver.md#fd_ghost_verify)
    - [`mock_epoch`](#mock_epoch)
    - [`fd_ghost_replay_vote`](fd_ghost.c.driver.md#fd_ghost_replay_vote)
    - [`fd_ghost_print`](fd_ghost.c.driver.md#fd_ghost_print)
    - [`fd_ghost_root`](fd_ghost.h.driver.md#fd_ghost_root)
    - [`fd_ghost_query`](fd_ghost.h.driver.md#fd_ghost_query)
    - [`fd_ghost_publish`](fd_ghost.c.driver.md#fd_ghost_publish)


---
### test\_ghost\_publish\_right<!-- {{#callable:test_ghost_publish_right}} -->
The `test_ghost_publish_right` function tests the behavior of the ghost protocol when publishing a node on the right side of a tree structure.
- **Inputs**:
    - `wksp`: A pointer to a workspace (`fd_wksp_t`) used for memory allocation and management.
- **Control Flow**:
    - Allocate memory for the ghost structure using `fd_wksp_alloc_laddr` with alignment and footprint for `node_max` nodes.
    - Initialize the ghost structure with [`fd_ghost_new`](fd_ghost.c.driver.md#fd_ghost_new) and join it with [`fd_ghost_join`](fd_ghost.c.driver.md#fd_ghost_join).
    - Initialize the ghost tree with [`fd_ghost_init`](fd_ghost.c.driver.md#fd_ghost_init) starting from slot 0.
    - Insert nodes into the ghost tree using the `INSERT` macro, which calls `fd_ghost_insert` for each node with specified parent-child relationships.
    - Verify the ghost structure with [`fd_ghost_verify`](fd_ghost.c.driver.md#fd_ghost_verify) to ensure it is in a valid state.
    - Create a mock epoch with a single voter using [`mock_epoch`](#mock_epoch) and query the voter with `fd_epoch_voters_query`.
    - Replay votes for slots 2 and 3 using [`fd_ghost_replay_vote`](fd_ghost.c.driver.md#fd_ghost_replay_vote) and verify the ghost structure after each vote.
    - Query the node at slot 3 with [`fd_ghost_query`](fd_ghost.h.driver.md#fd_ghost_query) to ensure it exists.
    - Print the ghost structure with [`fd_ghost_print`](fd_ghost.c.driver.md#fd_ghost_print) and publish the node at slot 3 using [`fd_ghost_publish`](fd_ghost.c.driver.md#fd_ghost_publish).
    - Verify the ghost structure again to ensure it remains valid after publishing.
    - Check the root node and its children to ensure the correct structure and slots are maintained.
    - Free the allocated memory for the ghost structure using `fd_wksp_free_laddr`.
- **Output**: The function does not return a value; it performs tests and assertions to verify the correct behavior of the ghost protocol when publishing a node on the right.
- **Functions called**:
    - [`fd_ghost_align`](fd_ghost.h.driver.md#fd_ghost_align)
    - [`fd_ghost_footprint`](fd_ghost.h.driver.md#fd_ghost_footprint)
    - [`fd_ghost_join`](fd_ghost.c.driver.md#fd_ghost_join)
    - [`fd_ghost_new`](fd_ghost.c.driver.md#fd_ghost_new)
    - [`fd_ghost_init`](fd_ghost.c.driver.md#fd_ghost_init)
    - [`fd_ghost_verify`](fd_ghost.c.driver.md#fd_ghost_verify)
    - [`mock_epoch`](#mock_epoch)
    - [`fd_ghost_replay_vote`](fd_ghost.c.driver.md#fd_ghost_replay_vote)
    - [`fd_ghost_query`](fd_ghost.h.driver.md#fd_ghost_query)
    - [`fd_ghost_print`](fd_ghost.c.driver.md#fd_ghost_print)
    - [`fd_ghost_root`](fd_ghost.h.driver.md#fd_ghost_root)
    - [`fd_ghost_publish`](fd_ghost.c.driver.md#fd_ghost_publish)
    - [`fd_ghost_child`](fd_ghost.h.driver.md#fd_ghost_child)


---
### test\_ghost\_gca<!-- {{#callable:test_ghost_gca}} -->
The `test_ghost_gca` function tests the functionality of the [`fd_ghost_gca`](fd_ghost.c.driver.md#fd_ghost_gca) function by setting up a ghost node structure and verifying the greatest common ancestor (GCA) of various node pairs.
- **Inputs**:
    - `wksp`: A pointer to a `fd_wksp_t` workspace structure used for memory allocation and management.
- **Control Flow**:
    - Allocate memory for ghost nodes using `fd_wksp_alloc_laddr` with alignment and footprint based on `node_max`.
    - Initialize a ghost structure with [`fd_ghost_new`](fd_ghost.c.driver.md#fd_ghost_new) and join it with [`fd_ghost_join`](fd_ghost.c.driver.md#fd_ghost_join).
    - Initialize the ghost node pool and set up an array of slots and parent slots for node insertion.
    - Insert nodes into the ghost structure using the `INSERT` macro, which calls `fd_ghost_insert` for each node with specified parent-child relationships.
    - Verify the ghost structure with [`fd_ghost_verify`](fd_ghost.c.driver.md#fd_ghost_verify) to ensure it is correctly set up.
    - Create a mock epoch using [`mock_epoch`](#mock_epoch) for testing purposes.
    - Print the ghost structure using [`fd_ghost_print`](fd_ghost.c.driver.md#fd_ghost_print).
    - Test the [`fd_ghost_gca`](fd_ghost.c.driver.md#fd_ghost_gca) function by checking the slot of the GCA for various pairs of nodes, using `FD_TEST` to assert expected results.
- **Output**: The function does not return a value but uses assertions to verify the correctness of the [`fd_ghost_gca`](fd_ghost.c.driver.md#fd_ghost_gca) function by checking the slot of the greatest common ancestor for various node pairs.
- **Functions called**:
    - [`fd_ghost_align`](fd_ghost.h.driver.md#fd_ghost_align)
    - [`fd_ghost_footprint`](fd_ghost.h.driver.md#fd_ghost_footprint)
    - [`fd_ghost_join`](fd_ghost.c.driver.md#fd_ghost_join)
    - [`fd_ghost_new`](fd_ghost.c.driver.md#fd_ghost_new)
    - [`fd_ghost_init`](fd_ghost.c.driver.md#fd_ghost_init)
    - [`fd_ghost_verify`](fd_ghost.c.driver.md#fd_ghost_verify)
    - [`mock_epoch`](#mock_epoch)
    - [`fd_ghost_print`](fd_ghost.c.driver.md#fd_ghost_print)
    - [`fd_ghost_root`](fd_ghost.h.driver.md#fd_ghost_root)
    - [`fd_ghost_gca`](fd_ghost.c.driver.md#fd_ghost_gca)


---
### test\_ghost\_print<!-- {{#callable:test_ghost_print}} -->
The `test_ghost_print` function initializes a ghost data structure, inserts nodes with specific parent-child relationships, assigns weights to these nodes, verifies the structure, and prints the ghost tree from a specified grandparent node.
- **Inputs**:
    - `wksp`: A pointer to a workspace (`fd_wksp_t`) used for memory allocation and management.
- **Control Flow**:
    - Allocate memory for the ghost structure using `fd_wksp_alloc_laddr` with alignment and footprint based on `node_max`.
    - Verify the memory allocation with `FD_TEST`.
    - Initialize a new ghost structure with [`fd_ghost_new`](fd_ghost.c.driver.md#fd_ghost_new) and join it with [`fd_ghost_join`](fd_ghost.c.driver.md#fd_ghost_join).
    - Create an epoch using [`mock_epoch`](#mock_epoch) with a total stake of 300 and no voters.
    - Initialize the ghost structure with a root node having a slot value of 268538758 using [`fd_ghost_init`](fd_ghost.c.driver.md#fd_ghost_init).
    - Insert nodes with specific parent-child relationships using the `INSERT` macro, which calls `fd_ghost_insert`.
    - Assign weights to the nodes by querying them with [`query_mut`](#query_mut) and setting the `weight` field.
    - Verify the ghost structure with [`fd_ghost_verify`](fd_ghost.c.driver.md#fd_ghost_verify) and ensure it returns false, indicating the structure is not valid.
    - Determine the grandparent node of a specific node (268538760) using [`fd_ghost_parent`](fd_ghost.h.driver.md#fd_ghost_parent) and [`fd_ghost_query`](fd_ghost.h.driver.md#fd_ghost_query).
    - Print the ghost structure from the grandparent node using [`fd_ghost_print`](fd_ghost.c.driver.md#fd_ghost_print).
    - Free the allocated memory using `fd_wksp_free_laddr`.
- **Output**: The function does not return a value; it performs operations on the ghost structure and prints its state.
- **Functions called**:
    - [`fd_ghost_align`](fd_ghost.h.driver.md#fd_ghost_align)
    - [`fd_ghost_footprint`](fd_ghost.h.driver.md#fd_ghost_footprint)
    - [`fd_ghost_join`](fd_ghost.c.driver.md#fd_ghost_join)
    - [`fd_ghost_new`](fd_ghost.c.driver.md#fd_ghost_new)
    - [`mock_epoch`](#mock_epoch)
    - [`fd_ghost_init`](fd_ghost.c.driver.md#fd_ghost_init)
    - [`query_mut`](#query_mut)
    - [`fd_ghost_verify`](fd_ghost.c.driver.md#fd_ghost_verify)
    - [`fd_ghost_parent`](fd_ghost.h.driver.md#fd_ghost_parent)
    - [`fd_ghost_query`](fd_ghost.h.driver.md#fd_ghost_query)
    - [`fd_ghost_print`](fd_ghost.c.driver.md#fd_ghost_print)


---
### test\_ghost\_head<!-- {{#callable:test_ghost_head}} -->
The `test_ghost_head` function tests the behavior of the [`fd_ghost_head`](fd_ghost.c.driver.md#fd_ghost_head) function in a tree structure with nodes and votes, ensuring the correct head node is identified based on votes.
- **Inputs**:
    - `wksp`: A pointer to a `fd_wksp_t` workspace structure used for memory allocation and management.
- **Control Flow**:
    - Allocate memory for a ghost structure with a maximum of 16 nodes using `fd_wksp_alloc_laddr` and verify allocation success with `FD_TEST`.
    - Initialize a ghost structure with [`fd_ghost_new`](fd_ghost.c.driver.md#fd_ghost_new) and join it with [`fd_ghost_join`](fd_ghost.c.driver.md#fd_ghost_join).
    - Create arrays `slots` and `parent_slots` to store node and parent node slots, respectively.
    - Initialize two public keys `pk1` and `pk2` and create a mock epoch with these keys and stakes using [`mock_epoch`](#mock_epoch).
    - Query voters `v1` and `v2` from the epoch using `fd_epoch_voters_query`.
    - Initialize the ghost structure with a root node at slot 10 using [`fd_ghost_init`](fd_ghost.c.driver.md#fd_ghost_init).
    - Insert nodes into the ghost structure using the `INSERT` macro, creating a tree with nodes 11, 12, and 13.
    - Replay votes for nodes 11 and 12 using [`fd_ghost_replay_vote`](fd_ghost.c.driver.md#fd_ghost_replay_vote) and verify the ghost structure with `FD_TEST`.
    - Retrieve the head node from the ghost structure using [`fd_ghost_head`](fd_ghost.c.driver.md#fd_ghost_head) and verify its slot is 12.
    - Replay a vote for node 13 and verify the ghost structure again.
    - Retrieve the head node again and verify its slot remains 12.
    - Print the ghost structure using [`fd_ghost_print`](fd_ghost.c.driver.md#fd_ghost_print).
    - Free the allocated memory using `fd_wksp_free_laddr`.
- **Output**: The function does not return a value; it performs tests and assertions to verify the correct behavior of the ghost structure and its head node identification.
- **Functions called**:
    - [`fd_ghost_align`](fd_ghost.h.driver.md#fd_ghost_align)
    - [`fd_ghost_footprint`](fd_ghost.h.driver.md#fd_ghost_footprint)
    - [`fd_ghost_join`](fd_ghost.c.driver.md#fd_ghost_join)
    - [`fd_ghost_new`](fd_ghost.c.driver.md#fd_ghost_new)
    - [`mock_epoch`](#mock_epoch)
    - [`fd_ghost_init`](fd_ghost.c.driver.md#fd_ghost_init)
    - [`fd_ghost_replay_vote`](fd_ghost.c.driver.md#fd_ghost_replay_vote)
    - [`fd_ghost_verify`](fd_ghost.c.driver.md#fd_ghost_verify)
    - [`fd_ghost_head`](fd_ghost.c.driver.md#fd_ghost_head)
    - [`fd_ghost_root`](fd_ghost.h.driver.md#fd_ghost_root)
    - [`fd_ghost_print`](fd_ghost.c.driver.md#fd_ghost_print)


---
### test\_ghost\_vote\_leaves<!-- {{#callable:test_ghost_vote_leaves}} -->
The `test_ghost_vote_leaves` function tests the behavior of a GHOST protocol implementation by simulating voting on a binary tree structure and verifying the correctness of vote weights and stakes.
- **Inputs**:
    - `wksp`: A pointer to a workspace (`fd_wksp_t`) used for memory allocation and management.
- **Control Flow**:
    - Allocate memory for a GHOST protocol structure using `fd_wksp_alloc_laddr` and initialize it with [`fd_ghost_new`](fd_ghost.c.driver.md#fd_ghost_new) and [`fd_ghost_join`](fd_ghost.c.driver.md#fd_ghost_join).
    - Initialize the GHOST structure with [`fd_ghost_init`](fd_ghost.c.driver.md#fd_ghost_init) and create a mock epoch with [`mock_epoch`](#mock_epoch).
    - Construct a full binary tree by inserting nodes using [`fd_ghost_insert`](fd_ghost.c.driver.md#fd_ghost_insert).
    - Simulate a validator changing votes along the leaves of the tree using [`fd_ghost_replay_vote`](fd_ghost.c.driver.md#fd_ghost_replay_vote).
    - Print the current state of the GHOST structure with [`fd_ghost_print`](fd_ghost.c.driver.md#fd_ghost_print).
    - Calculate the path from the last leaf to the root and verify the replay stakes and weights for each node in the path.
    - Simulate other validators voting for the remaining leaves and verify the replay stakes and weights for all nodes.
    - Verify the integrity of the GHOST structure with [`fd_ghost_verify`](fd_ghost.c.driver.md#fd_ghost_verify) and print the final state.
- **Output**: The function does not return a value; it performs tests and assertions to verify the correctness of the GHOST protocol implementation.
- **Functions called**:
    - [`fd_ghost_align`](fd_ghost.h.driver.md#fd_ghost_align)
    - [`fd_ghost_footprint`](fd_ghost.h.driver.md#fd_ghost_footprint)
    - [`fd_ghost_join`](fd_ghost.c.driver.md#fd_ghost_join)
    - [`fd_ghost_new`](fd_ghost.c.driver.md#fd_ghost_new)
    - [`fd_ghost_init`](fd_ghost.c.driver.md#fd_ghost_init)
    - [`mock_epoch`](#mock_epoch)
    - [`fd_ghost_insert`](fd_ghost.c.driver.md#fd_ghost_insert)
    - [`fd_ghost_replay_vote`](fd_ghost.c.driver.md#fd_ghost_replay_vote)
    - [`fd_ghost_print`](fd_ghost.c.driver.md#fd_ghost_print)
    - [`fd_ghost_root`](fd_ghost.h.driver.md#fd_ghost_root)
    - [`fd_ghost_query`](fd_ghost.h.driver.md#fd_ghost_query)
    - [`fd_ghost_verify`](fd_ghost.c.driver.md#fd_ghost_verify)


---
### test\_ghost\_old\_vote\_pruned<!-- {{#callable:test_ghost_old_vote_pruned}} -->
The function `test_ghost_old_vote_pruned` tests the behavior of a ghost tree structure when old votes are pruned and new votes are cast, ensuring the tree's integrity and weight calculations are correct.
- **Inputs**:
    - `wksp`: A pointer to a workspace (`fd_wksp_t`) used for memory allocation and management within the function.
- **Control Flow**:
    - Allocate memory for a ghost tree with a maximum of 16 nodes using the workspace.
    - Initialize the ghost tree and insert nodes to form a binary tree structure.
    - For each node, create a voter with a unique key and stake, and replay their vote to the corresponding node.
    - Publish the ghost tree with root at node 1 and print the tree structure.
    - Switch a voter's vote from node 5 to node 9 and print the updated tree structure.
    - Verify the weights of specific nodes in the tree to ensure correctness.
    - Publish the ghost tree with root at node 3, effectively pruning nodes not in the subtree rooted at node 3.
    - Switch another voter's vote from node 2 to node 7 and print the updated tree structure.
    - Verify the weights of specific nodes again to ensure correctness after pruning.
- **Output**: The function does not return a value but performs assertions to verify the correctness of the ghost tree's structure and node weights after operations.
- **Functions called**:
    - [`fd_ghost_align`](fd_ghost.h.driver.md#fd_ghost_align)
    - [`fd_ghost_footprint`](fd_ghost.h.driver.md#fd_ghost_footprint)
    - [`fd_ghost_join`](fd_ghost.c.driver.md#fd_ghost_join)
    - [`fd_ghost_new`](fd_ghost.c.driver.md#fd_ghost_new)
    - [`mock_epoch`](#mock_epoch)
    - [`fd_ghost_init`](fd_ghost.c.driver.md#fd_ghost_init)
    - [`fd_ghost_insert`](fd_ghost.c.driver.md#fd_ghost_insert)
    - [`fd_ghost_replay_vote`](fd_ghost.c.driver.md#fd_ghost_replay_vote)
    - [`fd_ghost_publish`](fd_ghost.c.driver.md#fd_ghost_publish)
    - [`fd_ghost_print`](fd_ghost.c.driver.md#fd_ghost_print)
    - [`fd_ghost_root`](fd_ghost.h.driver.md#fd_ghost_root)
    - [`fd_ghost_query`](fd_ghost.h.driver.md#fd_ghost_query)
    - [`fd_ghost_verify`](fd_ghost.c.driver.md#fd_ghost_verify)


---
### test\_ghost\_head\_full\_tree<!-- {{#callable:test_ghost_head_full_tree}} -->
The function `test_ghost_head_full_tree` tests the behavior of a complete binary tree structure using the `fd_ghost` API, focusing on node insertion, vote replay, and head node determination.
- **Inputs**:
    - `wksp`: A pointer to a workspace (`fd_wksp_t`) used for memory allocation and management.
- **Control Flow**:
    - Allocate memory for a ghost structure with a maximum of 16 nodes using `fd_wksp_alloc_laddr` and initialize it with [`fd_ghost_new`](fd_ghost.c.driver.md#fd_ghost_new) and [`fd_ghost_join`](fd_ghost.c.driver.md#fd_ghost_join).
    - Create a mock epoch with a total stake of 120 using [`mock_epoch`](#mock_epoch).
    - Initialize the ghost structure with [`fd_ghost_init`](fd_ghost.c.driver.md#fd_ghost_init) and log the maximum number of nodes in the pool.
    - Insert nodes into the ghost structure to form a complete binary tree and replay votes for each node using [`fd_ghost_insert`](fd_ghost.c.driver.md#fd_ghost_insert) and [`fd_ghost_replay_vote`](fd_ghost.c.driver.md#fd_ghost_replay_vote).
    - Verify that each node's replay stake matches its index using [`fd_ghost_query`](fd_ghost.h.driver.md#fd_ghost_query) and `FD_TEST`.
    - Check the validity of the ghost structure with [`fd_ghost_verify`](fd_ghost.c.driver.md#fd_ghost_verify) and print the tree structure using [`fd_ghost_print`](fd_ghost.c.driver.md#fd_ghost_print).
    - Determine the head of the tree using [`fd_ghost_head`](fd_ghost.c.driver.md#fd_ghost_head) and log its slot, expecting it to be the rightmost node (slot 14).
    - Insert an additional node and replay a vote for it, then verify the structure and check that the head remains unchanged.
    - Conclude with a comment indicating that adding another node would fail.
- **Output**: The function does not return a value; it performs tests and logs results to verify the behavior of the ghost tree structure.
- **Functions called**:
    - [`fd_ghost_align`](fd_ghost.h.driver.md#fd_ghost_align)
    - [`fd_ghost_footprint`](fd_ghost.h.driver.md#fd_ghost_footprint)
    - [`fd_ghost_join`](fd_ghost.c.driver.md#fd_ghost_join)
    - [`fd_ghost_new`](fd_ghost.c.driver.md#fd_ghost_new)
    - [`mock_epoch`](#mock_epoch)
    - [`fd_ghost_init`](fd_ghost.c.driver.md#fd_ghost_init)
    - [`fd_ghost_insert`](fd_ghost.c.driver.md#fd_ghost_insert)
    - [`fd_ghost_replay_vote`](fd_ghost.c.driver.md#fd_ghost_replay_vote)
    - [`fd_ghost_query`](fd_ghost.h.driver.md#fd_ghost_query)
    - [`fd_ghost_verify`](fd_ghost.c.driver.md#fd_ghost_verify)
    - [`fd_ghost_print`](fd_ghost.c.driver.md#fd_ghost_print)
    - [`fd_ghost_root`](fd_ghost.h.driver.md#fd_ghost_root)
    - [`fd_ghost_head`](fd_ghost.c.driver.md#fd_ghost_head)


---
### test\_rooted\_vote<!-- {{#callable:test_rooted_vote}} -->
The `test_rooted_vote` function tests the behavior of rooted voting in a ghost protocol by setting up a workspace, initializing ghost nodes, and verifying the stakes and weights of nodes after votes are cast.
- **Inputs**:
    - `wksp`: A pointer to a workspace (`fd_wksp_t`) used for memory allocation and management.
- **Control Flow**:
    - Allocate memory for ghost nodes using `fd_wksp_alloc_laddr` with alignment and footprint for a maximum of 16 nodes.
    - Initialize a ghost structure with [`fd_ghost_join`](fd_ghost.c.driver.md#fd_ghost_join) and [`fd_ghost_new`](fd_ghost.c.driver.md#fd_ghost_new) using the allocated memory.
    - Create two public keys `pk1` and `pk2` and a mock epoch with these keys and their respective stakes using [`mock_epoch`](#mock_epoch).
    - Query the voters `v1` and `v2` from the epoch using `fd_epoch_voters_query`.
    - Initialize the ghost structure with [`fd_ghost_init`](fd_ghost.c.driver.md#fd_ghost_init).
    - Insert a node into the ghost structure with [`fd_ghost_insert`](fd_ghost.c.driver.md#fd_ghost_insert).
    - Replay a vote for voter `v1` on node 1 using [`fd_ghost_replay_vote`](fd_ghost.c.driver.md#fd_ghost_replay_vote).
    - Perform a rooted vote for voter `v2` on node 1 using [`fd_ghost_rooted_vote`](fd_ghost.c.driver.md#fd_ghost_rooted_vote).
    - Query the node at slot 1 using [`fd_ghost_query`](fd_ghost.h.driver.md#fd_ghost_query) and verify its replay stake, weight, and rooted stake using `FD_TEST`.
    - Verify the integrity of the ghost structure with `FD_TEST` and [`fd_ghost_verify`](fd_ghost.c.driver.md#fd_ghost_verify).
- **Output**: The function does not return a value but performs assertions to verify the correctness of the ghost protocol's rooted voting mechanism.
- **Functions called**:
    - [`fd_ghost_align`](fd_ghost.h.driver.md#fd_ghost_align)
    - [`fd_ghost_footprint`](fd_ghost.h.driver.md#fd_ghost_footprint)
    - [`fd_ghost_join`](fd_ghost.c.driver.md#fd_ghost_join)
    - [`fd_ghost_new`](fd_ghost.c.driver.md#fd_ghost_new)
    - [`mock_epoch`](#mock_epoch)
    - [`fd_ghost_init`](fd_ghost.c.driver.md#fd_ghost_init)
    - [`fd_ghost_insert`](fd_ghost.c.driver.md#fd_ghost_insert)
    - [`fd_ghost_replay_vote`](fd_ghost.c.driver.md#fd_ghost_replay_vote)
    - [`fd_ghost_rooted_vote`](fd_ghost.c.driver.md#fd_ghost_rooted_vote)
    - [`fd_ghost_query`](fd_ghost.h.driver.md#fd_ghost_query)
    - [`fd_ghost_verify`](fd_ghost.c.driver.md#fd_ghost_verify)


---
### test\_ghost\_head\_valid<!-- {{#callable:test_ghost_head_valid}} -->
The `test_ghost_head_valid` function tests the behavior of a ghost DAG (Directed Acyclic Graph) structure when nodes are marked as valid or invalid, and verifies the correct head node is identified based on votes and node validity.
- **Inputs**:
    - `wksp`: A pointer to a `fd_wksp_t` workspace structure used for memory allocation and management.
- **Control Flow**:
    - Allocate memory for the ghost structure using `fd_wksp_alloc_laddr` and initialize it with [`fd_ghost_new`](fd_ghost.c.driver.md#fd_ghost_new) and [`fd_ghost_join`](fd_ghost.c.driver.md#fd_ghost_join).
    - Initialize the ghost structure with a root node at slot 10 using [`fd_ghost_init`](fd_ghost.c.driver.md#fd_ghost_init).
    - Insert nodes into the ghost structure using the `INSERT` macro, creating a tree with nodes 11, 12, and 13.
    - Create a mock epoch with two voters and retrieve voter structures for them.
    - Replay votes for nodes 11 and 12 using [`fd_ghost_replay_vote`](fd_ghost.c.driver.md#fd_ghost_replay_vote) and verify the ghost structure with [`fd_ghost_verify`](fd_ghost.c.driver.md#fd_ghost_verify).
    - Replay a vote for node 13 and verify the ghost structure again.
    - Mark node 12 as invalid using [`query_mut`](#query_mut) and verify the head node is updated correctly.
    - Replay a vote for node 13, mark node 11 as invalid, and verify the head node is updated correctly.
    - Mark node 12 as valid again and verify the head node is updated to node 12.
    - Print the ghost structure using [`fd_ghost_print`](fd_ghost.c.driver.md#fd_ghost_print).
    - Free the allocated memory using `fd_wksp_free_laddr`.
- **Output**: The function does not return a value but performs a series of tests to ensure the ghost structure correctly identifies the head node based on node validity and votes.
- **Functions called**:
    - [`fd_ghost_align`](fd_ghost.h.driver.md#fd_ghost_align)
    - [`fd_ghost_footprint`](fd_ghost.h.driver.md#fd_ghost_footprint)
    - [`fd_ghost_join`](fd_ghost.c.driver.md#fd_ghost_join)
    - [`fd_ghost_new`](fd_ghost.c.driver.md#fd_ghost_new)
    - [`mock_epoch`](#mock_epoch)
    - [`fd_ghost_init`](fd_ghost.c.driver.md#fd_ghost_init)
    - [`fd_ghost_replay_vote`](fd_ghost.c.driver.md#fd_ghost_replay_vote)
    - [`fd_ghost_verify`](fd_ghost.c.driver.md#fd_ghost_verify)
    - [`query_mut`](#query_mut)
    - [`fd_ghost_head`](fd_ghost.c.driver.md#fd_ghost_head)
    - [`fd_ghost_root`](fd_ghost.h.driver.md#fd_ghost_root)
    - [`fd_ghost_print`](fd_ghost.c.driver.md#fd_ghost_print)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, creates a shared memory workspace, and executes a specific test function for ghost node validation.
- **Inputs**:
    - `argc`: The count of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Call `fd_boot` to initialize the environment with command-line arguments.
    - Set default values for `page_cnt`, `_page_sz`, and determine `numa_idx` using `fd_shmem_numa_idx`.
    - Log the creation of a workspace with the specified parameters.
    - Create a new anonymous workspace using `fd_wksp_new_anonymous` with the determined page size, count, and CPU index.
    - Check if the workspace creation was successful using `FD_TEST`.
    - Execute the [`test_ghost_head_valid`](#test_ghost_head_valid) function with the created workspace.
    - Call `fd_halt` to clean up and terminate the program.
- **Output**: The function returns an integer value `0` indicating successful execution.
- **Functions called**:
    - [`test_ghost_head_valid`](#test_ghost_head_valid)



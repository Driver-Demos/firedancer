# Purpose
The provided C header file, `fd_quic_ack_tx.h`, is part of a QUIC protocol implementation, specifically focusing on the generation and management of ACK (acknowledgment) packets. This file defines the structures and functions necessary for handling ACK frames within a QUIC connection, which is crucial for ensuring reliable data transmission over the network. The file includes definitions for data structures such as `fd_quic_ack` and `fd_quic_ack_gen`, which are used to store and manage packet numbers that need acknowledgment. The `fd_quic_ack_gen` structure, in particular, maintains a queue of ACK frames, allowing for efficient tracking and processing of packets that have been received and need acknowledgment.

The header file provides several key functions, such as `fd_quic_ack_gen_init`, which initializes the ACK generation structure, and [`fd_quic_ack_pkt`](#fd_quic_ack_pkt), which queues a processed packet for acknowledgment. Additionally, it includes utility functions like `fd_quic_ack_queue_ele` for accessing elements in the ACK queue and [`fd_quic_gen_ack_frames`](#fd_quic_gen_ack_frames) for writing ACK frames to a specified memory region. The file also defines constants and macros to control the behavior of the ACK generation process, such as `FD_QUIC_ACK_QUEUE_CNT`, which determines the number of disjoint ACK ranges that can be acknowledged. Overall, this header file is designed to be included in other parts of the QUIC implementation, providing a focused API for managing ACK packets in a QUIC connection.
# Imports and Dependencies

---
- `fd_quic_common.h`


# Global Variables

---
### fd\_quic\_gen\_ack\_frames
- **Type**: `function pointer`
- **Description**: The `fd_quic_gen_ack_frames` is a function that generates ACK frames for QUIC protocol communication. It takes a pointer to an `fd_quic_ack_gen_t` structure, which contains information about processed packet numbers and ACK frame generation, and writes ACK frames to a specified memory region. The function returns a pointer to the position in memory just past the last byte written.
- **Use**: This function is used to generate and write ACK frames into a specified memory region for QUIC protocol communication.


# Data Structures

---
### fd\_quic\_ack
- **Type**: `struct`
- **Members**:
    - `pkt_number`: Range of packet numbers being ACKed.
    - `ts`: Timestamp of the highest packet number.
    - `enc_level`: Encryption level, in the range [0,4).
    - `_pad`: Padding to ensure the structure is 32 bytes in size.
- **Description**: The `fd_quic_ack` structure is designed to represent an acknowledgment (ACK) frame in the QUIC protocol, specifically for tracking a contiguous range of packet numbers that have been acknowledged. It includes a timestamp for the highest packet number in the range, an encryption level indicator, and padding to align the structure to a 32-byte boundary. This structure is used within the QUIC implementation to manage and generate ACK frames efficiently.


---
### fd\_quic\_ack\_t
- **Type**: `struct`
- **Members**:
    - `pkt_number`: Range of packet numbers being acknowledged.
    - `ts`: Timestamp of the highest packet number.
    - `enc_level`: Encryption level, ranging from 0 to 3.
    - `_pad`: Padding to ensure the structure is 32 bytes in size.
- **Description**: The `fd_quic_ack_t` structure is used to build an ACK frame in the QUIC protocol, containing a contiguous range of packet numbers to acknowledge. It is aligned to 16 bytes and includes fields for the packet number range, a timestamp for the highest packet number, and an encryption level. The structure is designed to be 32 bytes in size, with padding included to meet this requirement.


---
### fd\_quic\_ack\_gen
- **Type**: `struct`
- **Members**:
    - `queue`: An array of fd_quic_ack_t structures used to store ACK frames.
    - `head`: An unsigned integer indicating the next unused sequence number in the queue.
    - `tail`: An unsigned integer indicating the sequence number of the oldest unsent ACK frame.
    - `is_elicited`: An unsigned character flag indicating if at least one ACK-eliciting frame was received.
- **Description**: The `fd_quic_ack_gen` structure is designed to manage and generate ACK frames for QUIC protocol communications. It maintains a queue of ACK frames, represented by `fd_quic_ack_t` structures, which are used to acknowledge received packets. The `head` and `tail` members manage the sequence numbers for the queue, allowing for efficient tracking of unsent and unused ACK frames. The `is_elicited` flag is crucial for determining whether ACK frames should be generated, as it indicates the reception of ACK-eliciting frames. This structure is aligned to 16 bytes for performance optimization.


---
### fd\_quic\_ack\_gen\_t
- **Type**: `struct`
- **Members**:
    - `queue`: An array of fd_quic_ack_t structures used to store ACK frames.
    - `head`: An unsigned integer representing the next unused sequence number in the ack_queue.
    - `tail`: An unsigned integer representing the sequence number of the oldest unsent ACK frame in the ack_queue.
    - `is_elicited`: A flag indicating if at least one ACK-eliciting frame was received.
- **Description**: The fd_quic_ack_gen_t structure is designed to manage and generate ACK frames for QUIC protocol communications. It maintains a queue of ACK frames, represented by fd_quic_ack_t structures, which are used to acknowledge received packets. The structure includes a head and tail to manage the queue's sequence numbers, and a flag to indicate if an ACK-eliciting frame has been received, which is necessary for generating ACK frames. This structure is crucial for handling packet acknowledgments efficiently in a QUIC implementation.


# Function Declarations (Public API)

---
### fd\_quic\_ack\_pkt<!-- {{#callable_declaration:fd_quic_ack_pkt}} -->
Queues a processed packet for acknowledgement.
- **Description**: This function is used to queue a packet for acknowledgement in the QUIC protocol. It should be called whenever a packet is successfully processed and needs to be acknowledged. The function handles merging the packet number into an existing acknowledgement range if possible, or starts a new acknowledgement range if necessary. It is important to ensure that the packet number is not marked as unused before calling this function. The function also manages the internal queue of acknowledgements, ensuring that it does not overflow. This function is typically used in the context of managing QUIC protocol packet acknowledgements and should be called after a packet is processed.
- **Inputs**:
    - `gen`: A pointer to an fd_quic_ack_gen_t structure that manages the state of the acknowledgement queue. Must not be null.
    - `pkt_number`: The packet number to be acknowledged. Must not be FD_QUIC_PKT_NUM_UNUSED.
    - `enc_level`: The encryption level of the packet, which should be in the range [0, 4).
    - `now`: The current timestamp, used to update the timestamp of the highest packet number in the acknowledgement range.
- **Output**: Returns an integer indicating the result of the operation: FD_QUIC_ACK_TX_NOOP if the packet number is unused, FD_QUIC_ACK_TX_MERGED if the packet number was merged into an existing range, FD_QUIC_ACK_TX_NEW if a new acknowledgement range was started, or FD_QUIC_ACK_TX_ENOSPC if there was no space to queue the acknowledgement.
- **See also**: [`fd_quic_ack_pkt`](fd_quic_ack_tx.c.driver.md#fd_quic_ack_pkt)  (Implementation)


---
### fd\_quic\_ack\_gen\_abandon\_enc\_level<!-- {{#callable_declaration:fd_quic_ack_gen_abandon_enc_level}} -->
Removes queued ACKs with an encryption level equal to or lower than the specified level.
- **Description**: Use this function to discard acknowledgment (ACK) entries from the queue that have an encryption level less than or equal to the specified `enc_level`. This is useful for managing the ACK queue by removing entries that are no longer needed or relevant, particularly when transitioning between encryption levels. The function iterates over the queue and updates the tail pointer to effectively remove the specified entries. It should be called when you need to clear outdated ACKs to maintain efficient queue management.
- **Inputs**:
    - `gen`: A pointer to an `fd_quic_ack_gen_t` structure representing the ACK generator. Must not be null, and should be properly initialized before calling this function.
    - `enc_level`: An unsigned integer representing the encryption level threshold. Valid values are typically in the range of encryption levels used by the application, and the function will remove ACKs with levels less than or equal to this value.
- **Output**: None
- **See also**: [`fd_quic_ack_gen_abandon_enc_level`](fd_quic_ack_tx.c.driver.md#fd_quic_ack_gen_abandon_enc_level)  (Implementation)


---
### fd\_quic\_gen\_ack\_frames<!-- {{#callable_declaration:fd_quic_gen_ack_frames}} -->
Writes ACK frames to a specified memory region.
- **Description**: This function generates and writes acknowledgment (ACK) frames into a specified memory buffer, which is defined by the range [payload_ptr, payload_end). It should be called when there are ACK-eliciting packets pending, as indicated by the gen parameter. The function ensures that ACK frames are only generated for the specified encryption level and will not proceed if there is insufficient buffer space. It is important to ensure that the gen structure is properly initialized and that the payload buffer is adequately sized to accommodate the generated frames.
- **Inputs**:
    - `gen`: A pointer to an fd_quic_ack_gen_t structure that records processed packet numbers and builds ACK frames. It must be initialized and contain at least one ACK-eliciting frame to generate ACKs.
    - `payload_ptr`: A pointer to the start of the memory region where ACK frames will be written. It must not be null and should point to a valid memory location.
    - `payload_end`: A pointer to the end of the memory region where ACK frames will be written. It must not be null and should be greater than or equal to payload_ptr.
    - `enc_level`: An unsigned integer representing the encryption level for which ACK frames should be generated. Only ACKs with this encryption level will be processed.
    - `now`: An unsigned long integer representing the current time in ticks, used to calculate the ACK delay.
    - `tick_per_us`: A float representing the number of ticks per microsecond, used to convert the delay from ticks to microseconds.
- **Output**: Returns a pointer to the position in the buffer immediately after the last byte written, which will be within the range [payload_ptr, payload_end].
- **See also**: [`fd_quic_gen_ack_frames`](fd_quic_ack_tx.c.driver.md#fd_quic_gen_ack_frames)  (Implementation)



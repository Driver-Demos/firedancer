# Purpose
This C source code file is designed to analyze QUIC traffic captured in packet capture (PCAP) files, specifically for the Solana network. The code provides a command-line tool that processes PCAP and PCAP-NG files to extract and analyze QUIC traffic data. It supports various commands to print traffic statistics, per-peer statistics, and trace traffic metadata to CSV format. The code includes functionality to handle different file formats and link layers, such as Ethernet and Linux SLL, and it is capable of parsing and decrypting QUIC packets using TLS keys.

The file defines several key components, including data structures for managing QUIC packet iteration and key mapping, as well as functions for processing and decrypting QUIC packets. It utilizes external libraries and headers for QUIC protocol handling, packet capture parsing, and network utilities. The code is structured to handle command-line arguments, manage memory allocation for data structures, and perform secure random number generation for cryptographic operations. The main function initializes the environment, processes command-line arguments, and executes the appropriate analysis based on the input PCAP file. The code is intended to be compiled into an executable tool for network traffic analysis, with a focus on QUIC traffic in the context of the Solana blockchain network.
# Imports and Dependencies

---
- `errno.h`
- `stdio.h`
- `stdlib.h`
- `string.h`
- `unistd.h`
- `fd_quic.h`
- `../../ballet/hex/fd_hex.h`
- `../../waltz/quic/fd_quic_proto.h`
- `../../waltz/quic/fd_quic_proto.c`
- `../../waltz/quic/templ/fd_quic_parse_util.h`
- `../../util/net/fd_pcap.h`
- `../../util/net/fd_pcapng.h`
- `../../util/net/fd_pcapng_private.h`
- `../../util/net/fd_ip4.h`
- `../../util/net/fd_udp.h`
- `../../util/tmpl/fd_map_dynamic.c`


# Global Variables

---
### map\_seed
- **Type**: `ulong`
- **Description**: `map_seed` is a static global variable of type `ulong` that is used to store a seed value for hash functions in the program. It is initialized in the `random_seeds` function using a secure random number generator.
- **Use**: This variable is used as a seed for hash functions to ensure randomness and uniqueness in operations such as mapping keys in data structures.


# Data Structures

---
### key32
- **Type**: `union`
- **Members**:
    - `key`: An array of 32 unsigned characters (uchar) used to store a 256-bit key.
    - `ul`: An array of 4 unsigned long integers (ulong) used to store the same 256-bit key as four 64-bit segments.
- **Description**: The `key32` union is a data structure designed to store a 256-bit key in two different formats: as an array of 32 bytes or as an array of four 64-bit unsigned long integers. This allows for flexible manipulation and access to the key data, depending on the requirements of the operations being performed. The `key32_t` typedef provides a convenient alias for this union, facilitating its use in various cryptographic and data processing contexts.


---
### key32\_t
- **Type**: `union`
- **Members**:
    - `key`: An array of 32 unsigned characters (uchar) representing a 32-byte key.
    - `ul`: An array of 4 unsigned long integers (ulong) providing an alternative view of the 32-byte key as four 8-byte segments.
- **Description**: The `key32_t` data structure is a union that provides two different ways to access a 32-byte key. It can be accessed as an array of 32 unsigned characters, which is useful for byte-level operations, or as an array of four unsigned long integers, which can be beneficial for operations that require larger data chunks. This union is typically used in contexts where both byte-level and word-level manipulations of a 32-byte key are needed, such as in cryptographic applications or network protocols.


---
### key\_map
- **Type**: `struct`
- **Members**:
    - `client_random`: A 32-byte key used as the client random value in the key map.
    - `server_app_secret`: A 32-byte array storing the server application secret.
    - `client_app_secret`: A 32-byte array storing the client application secret.
- **Description**: The `key_map` structure is designed to map a client random value to its corresponding encryption keys, specifically the server and client application secrets. It is used in the context of handling QUIC traffic, where it helps in managing and retrieving encryption keys based on the client random value. The structure currently supports a single set of keys, but there is a note indicating potential future support for a ring buffer to handle multiple keys.


---
### key\_map\_t
- **Type**: `struct`
- **Members**:
    - `client_random`: A 32-byte key used as the client random value in the TLS handshake.
    - `server_app_secret`: A 32-byte array storing the server application secret key.
    - `client_app_secret`: A 32-byte array storing the client application secret key.
- **Description**: The `key_map_t` structure is used to map a client's random value to its corresponding encryption keys in a TLS handshake. It contains a `client_random` field, which is a 32-byte key representing the client random value, and two 32-byte arrays, `server_app_secret` and `client_app_secret`, which store the server and client application secret keys, respectively. This structure is part of a larger system for analyzing QUIC traffic and managing encryption keys.


---
### conn\_map
- **Type**: `struct`
- **Members**:
    - `conn_id`: A unique identifier for a connection, represented as an unsigned long integer.
    - `client_random`: A 32-byte array representing a random value associated with the client for cryptographic purposes.
- **Description**: The `conn_map` structure is designed to map a connection ID to a client random value, which is typically used in cryptographic operations within network protocols. This structure is part of a larger system that processes QUIC traffic, and it helps in associating specific connections with their corresponding cryptographic parameters, facilitating secure communication.


---
### conn\_map\_t
- **Type**: `struct`
- **Members**:
    - `conn_id`: A unique identifier for a connection, represented as an unsigned long integer.
    - `client_random`: A 32-byte array representing the client random value used in the connection.
- **Description**: The `conn_map_t` structure is used to map a connection ID to a client random value in the context of QUIC traffic analysis. It is part of a larger system that processes packet capture files to analyze network traffic, specifically focusing on QUIC protocol communications. The structure holds a connection ID and a corresponding client random value, which are essential for identifying and decrypting QUIC packets.


---
### quic\_pcap\_params
- **Type**: `struct`
- **Members**:
    - `pcap_path`: A constant character pointer to the path of the pcap file.
    - `key_max`: An unsigned long integer representing the maximum number of concurrent TLS keys.
- **Description**: The `quic_pcap_params` structure is used to store parameters for processing QUIC packet capture files. It contains a file path to the pcap file and a limit on the number of TLS keys that can be concurrently processed. This structure is essential for initializing and configuring the QUIC packet capture iterator, which is responsible for analyzing network traffic captures.


---
### quic\_pcap\_params\_t
- **Type**: `struct`
- **Members**:
    - `pcap_path`: A constant character pointer to the path of the pcap file.
    - `key_max`: An unsigned long integer representing the maximum number of concurrent TLS keys allowed.
- **Description**: The `quic_pcap_params_t` structure is used to store parameters for processing QUIC packet capture files. It contains a file path to the pcap file and a limit on the number of TLS keys that can be concurrently processed. This structure is essential for initializing and configuring the QUIC packet capture iterator, which is responsible for analyzing network traffic data.


---
### quic\_pcap\_iter
- **Type**: `struct`
- **Members**:
    - `pcap_file`: A pointer to a FILE object representing the pcap file being processed.
    - `conn_map`: A pointer to a conn_map_t structure that maps connection IDs to client random values.
    - `key_map`: A pointer to a key_map_t structure that maps client random values to encryption keys.
    - `key_max`: An unsigned long representing the maximum number of keys that can be stored.
    - `key_cnt`: An unsigned long representing the current count of keys stored.
    - `key_ignore_cnt`: An unsigned long representing the count of keys ignored due to exceeding the maximum limit.
- **Description**: The `quic_pcap_iter` structure is designed to facilitate the iteration and processing of QUIC traffic data from a pcap file. It holds references to the pcap file, connection and key maps, and tracks the number of keys processed and ignored. This structure is central to managing the state and data necessary for analyzing QUIC traffic captures, particularly in the context of handling encryption keys and connection identifiers.


---
### quic\_pcap\_iter\_t
- **Type**: `struct`
- **Members**:
    - `pcap_file`: A pointer to a FILE object representing the open pcap file.
    - `conn_map`: A pointer to a conn_map_t structure used to map connection IDs to client random values.
    - `key_map`: A pointer to a key_map_t structure used to map client random values to encryption keys.
    - `key_max`: An unsigned long representing the maximum number of keys that can be stored.
    - `key_cnt`: An unsigned long representing the current count of keys stored.
    - `key_ignore_cnt`: An unsigned long representing the count of keys ignored due to exceeding the maximum limit.
- **Description**: The `quic_pcap_iter_t` structure is designed to facilitate the iteration over QUIC packet capture files, specifically for analyzing QUIC traffic. It holds references to the pcap file being processed, as well as maps for managing connection IDs and encryption keys. The structure also tracks the maximum number of keys allowed, the current count of keys, and the number of keys ignored due to reaching the limit. This setup is crucial for efficiently processing and decrypting QUIC traffic data from pcap files.


---
### fd\_sll\_hdr
- **Type**: `struct`
- **Members**:
    - `packet_type`: Specifies the type of packet being processed.
    - `arphrd_type`: Indicates the ARP hardware type.
    - `ll_addr_sz`: Represents the size of the link-layer address.
    - `ll_addr`: Stores the link-layer address, with a maximum size of 8 bytes.
    - `protocol_type`: Defines the protocol type of the packet.
- **Description**: The `fd_sll_hdr` structure is used to represent a Linux cooked-mode capture header, which is a simplified form of packet header used in capturing network traffic. It contains fields for packet type, ARP hardware type, link-layer address size, the link-layer address itself, and the protocol type, providing essential information for processing and analyzing network packets in a Linux environment.


---
### fd\_sll\_hdr\_t
- **Type**: `struct`
- **Members**:
    - `packet_type`: A 16-bit unsigned integer representing the packet type.
    - `arphrd_type`: A 16-bit unsigned integer representing the ARP hardware type.
    - `ll_addr_sz`: A 16-bit unsigned integer representing the size of the link-layer address.
    - `ll_addr`: An array of 8 unsigned characters representing the link-layer address.
    - `protocol_type`: A 16-bit unsigned integer representing the protocol type.
- **Description**: The `fd_sll_hdr_t` structure represents a Linux cooked-mode capture header, which is used in packet capture files to describe the link-layer header for packets captured in cooked mode. This structure includes fields for the packet type, ARP hardware type, size of the link-layer address, the link-layer address itself, and the protocol type, providing essential metadata for interpreting the captured packet data.


# Functions

---
### usage\_short<!-- {{#callable:usage_short}} -->
The `usage_short` function prints a brief usage message for the `fd_quic_pcap` command to the standard error stream.
- **Inputs**: None
- **Control Flow**:
    - The function calls `fputs` to print a usage message to `stderr`.
- **Output**: The function does not return any value (void function).


---
### usage<!-- {{#callable:usage}} -->
The `usage` function provides a brief usage message for the `fd_quic_pcap` tool, with additional detailed information commented out for future implementation.
- **Inputs**: None
- **Control Flow**:
    - The function calls `usage_short()` to print a brief usage message to `stderr`.
    - A block of code is commented out, which when uncommented, would print detailed information about the tool's capabilities, supported formats, commands, and optional flags using `fprintf`.
- **Output**: The function does not return any value or output.
- **Functions called**:
    - [`usage_short`](#usage_short)


---
### usage\_invalid<!-- {{#callable:usage_invalid}} -->
The `usage_invalid` function prints an error message for invalid arguments and then calls another function to display a short usage message.
- **Inputs**: None
- **Control Flow**:
    - The function writes the string 'Invalid arguments!\n' to the standard error stream using `fputs`.
    - It then calls the [`usage_short`](#usage_short) function to display a brief usage message.
- **Output**: The function does not return any value; it performs output operations to the standard error stream.
- **Functions called**:
    - [`usage_short`](#usage_short)


---
### reject\_unknown\_flags<!-- {{#callable:reject_unknown_flags}} -->
The `reject_unknown_flags` function filters out unsupported command-line flags from the argument list, logging an error for each unsupported flag encountered.
- **Inputs**:
    - `pargc`: A pointer to an integer representing the number of command-line arguments.
    - `pargv`: A pointer to an array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize `expect_flag` to 1 and `new_argc` to 0.
    - Iterate over each argument in `*pargv` using a for loop with index `arg`.
    - Check if `expect_flag` is false or the current argument does not start with '--'.
    - If true, copy the argument to the new position in `*pargv` and increment `new_argc`.
    - If the argument starts with '--', increment `arg` to check the next argument.
    - If the next argument starts with '0', set `expect_flag` to 0, indicating no more flags are expected.
    - If the next argument does not start with '0', log an error indicating an unsupported flag.
- **Output**: The function modifies the `*pargv` array in place to remove unsupported flags and logs errors for each unsupported flag encountered.


---
### random\_seeds<!-- {{#callable:random_seeds}} -->
The `random_seeds` function initializes a global seed variable `map_seed` using a secure random number generator at program startup.
- **Inputs**: None
- **Control Flow**:
    - The function is marked with the `constructor` attribute, ensuring it runs before `main()` when the program starts.
    - It calls `fd_rng_secure` to fill `map_seed` with secure random data.
    - If `fd_rng_secure` fails, it logs a warning message using `FD_LOG_WARNING`.
- **Output**: The function does not return any value; it initializes the `map_seed` variable.


---
### quic\_pcap\_iter\_new<!-- {{#callable:quic_pcap_iter_new}} -->
The `quic_pcap_iter_new` function initializes a QUIC packet capture iterator with memory allocations for key and connection maps and opens a specified pcap file for reading.
- **Inputs**:
    - `iter`: A pointer to a `quic_pcap_iter_t` structure that will be initialized by the function.
    - `params`: A constant pointer to a `quic_pcap_params_t` structure containing parameters such as the path to the pcap file and the maximum number of keys.
- **Control Flow**:
    - Calculate the logarithm of the slot count based on the maximum number of keys specified in `params`.
    - Allocate aligned memory for the key map and initialize it with the calculated slot count.
    - Join the key map to the allocated memory and check for allocation failure, logging an error if it occurs.
    - Allocate aligned memory for the connection map and initialize it similarly, checking for allocation failure.
    - Open the pcap file specified in `params` for reading in binary mode, logging an error if the file cannot be opened.
    - Initialize the `iter` structure with the opened pcap file, the allocated connection map, the allocated key map, and the maximum number of keys from `params`.
    - Return the initialized `iter` pointer.
- **Output**: Returns a pointer to the initialized `quic_pcap_iter_t` structure.


---
### quic\_pcap\_iter\_add\_one\_key<!-- {{#callable:quic_pcap_iter_add_one_key}} -->
The `quic_pcap_iter_add_one_key` function processes a single TLS key log line, extracting and storing client random and encryption keys into a key map if they are valid and within size constraints.
- **Inputs**:
    - `iter`: A pointer to a `quic_pcap_iter_t` structure, which contains the key map and other iteration parameters.
    - `str`: A constant character pointer to the string containing the TLS key log line.
    - `str_sz`: An unsigned long representing the size of the string `str`.
- **Control Flow**:
    - Check if the string size `str_sz` is less than 6 and return if true, as it is considered too small to be valid.
    - Copy the string `str` into a mutable buffer `line` if its size is within the buffer limit; otherwise, log a warning and return.
    - Tokenize the `line` into three parts using space as a delimiter; if the token count is not three, log a warning and return.
    - Validate the length of the second token (client random) and decode it into a `key32_t` structure; log a warning and return if invalid.
    - Validate the length of the third token (encryption key) and decode it into a 32-byte array; log a warning and return if invalid.
    - Query the key map for an existing record with the client random; if not found, check if the key map has reached its maximum capacity and log a warning if so, then return.
    - If a new record is needed and capacity allows, insert the client random into the key map and initialize a new record.
    - Check the first token to determine if it is a client or server traffic secret and if it is not a handshake key.
    - If the key index is zero, copy the encryption key to the appropriate application secret in the record and increment the key count; otherwise, log a debug message and increment the ignore count.
- **Output**: The function does not return a value; it modifies the `iter` structure by potentially adding a new key record or updating existing records, and it logs warnings or debug messages as necessary.


---
### quic\_pcap\_iter\_add\_keys<!-- {{#callable:quic_pcap_iter_add_keys}} -->
The `quic_pcap_iter_add_keys` function processes a string of TLS key log data, extracting and adding individual keys to a QUIC packet capture iterator.
- **Inputs**:
    - `iter`: A pointer to a `quic_pcap_iter_t` structure, which holds the state and data structures for processing QUIC packet captures.
    - `str`: A constant character pointer to the string containing TLS key log data.
    - `str_sz`: An unsigned long integer representing the size of the string `str`.
- **Control Flow**:
    - The function enters a loop that continues as long as `str_sz` is non-zero.
    - Within the loop, it searches for the end of a line using `memmem` to find a CRLF sequence or `memchr` to find a LF character.
    - It determines the end of the current line (`eol`) based on the presence of CRLF or LF, or defaults to the end of the string if neither is found.
    - The function calls [`quic_pcap_iter_add_one_key`](#quic_pcap_iter_add_one_key) to process and add the key from the current line to the iterator.
    - It updates `str_sz` by subtracting the length of the processed line from it, effectively moving to the next line in the string.
- **Output**: The function does not return a value; it modifies the state of the `quic_pcap_iter_t` structure by adding keys.
- **Functions called**:
    - [`quic_pcap_iter_add_one_key`](#quic_pcap_iter_add_one_key)


---
### quic\_pcap\_iter\_deliver\_initial<!-- {{#callable:quic_pcap_iter_deliver_initial}} -->
The `quic_pcap_iter_deliver_initial` function processes an initial QUIC packet, decrypts it, and extracts the ClientHello message from the TLS handshake.
- **Inputs**:
    - `iter`: A pointer to a `quic_pcap_iter_t` structure, which is not used in this function.
    - `ip4_saddr`: An unsigned integer representing the IPv4 source address, which is not used in this function.
    - `data`: A pointer to an array of unsigned characters representing the packet data to be processed.
    - `data_sz`: An unsigned long representing the size of the data array.
    - `out_pkt_sz`: A pointer to an unsigned long where the function will store the size of the processed packet.
- **Control Flow**:
    - The function begins by decoding the initial QUIC packet using `fd_quic_decode_initial` and checks for parsing failure.
    - If the total size of the packet exceeds the available data size, the function returns without processing further.
    - Initial secrets are generated using [`fd_quic_gen_initial_secrets`](crypto/fd_quic_crypto_suites.c.driver.md#fd_quic_gen_initial_secrets), and keys are derived from these secrets using [`fd_quic_gen_keys`](crypto/fd_quic_crypto_suites.c.driver.md#fd_quic_gen_keys).
    - The function attempts to decrypt the packet header using [`fd_quic_crypto_decrypt_hdr`](crypto/fd_quic_crypto_suites.c.driver.md#fd_quic_crypto_decrypt_hdr); if unsuccessful, it logs a warning and returns.
    - The packet number is decoded, and the function attempts to decrypt the packet payload using [`fd_quic_crypto_decrypt`](crypto/fd_quic_crypto_suites.c.driver.md#fd_quic_crypto_decrypt); if unsuccessful, it logs a warning and returns.
    - The function checks if the first frame is a CRYPTO frame and decodes it using `fd_quic_decode_crypto_frame`.
    - The function verifies that the first TLS message is a ClientHello and logs the ClientRandom value.
- **Output**: The function outputs the size of the processed packet through the `out_pkt_sz` pointer and logs the ClientRandom value if the packet is successfully processed.
- **Functions called**:
    - [`fd_quic_gen_initial_secrets`](crypto/fd_quic_crypto_suites.c.driver.md#fd_quic_gen_initial_secrets)
    - [`fd_quic_gen_keys`](crypto/fd_quic_crypto_suites.c.driver.md#fd_quic_gen_keys)
    - [`fd_quic_crypto_decrypt_hdr`](crypto/fd_quic_crypto_suites.c.driver.md#fd_quic_crypto_decrypt_hdr)
    - [`fd_quic_crypto_decrypt`](crypto/fd_quic_crypto_suites.c.driver.md#fd_quic_crypto_decrypt)


---
### quic\_pcap\_iter\_deliver\_handshake<!-- {{#callable:quic_pcap_iter_deliver_handshake}} -->
The `quic_pcap_iter_deliver_handshake` function is a placeholder function intended to process QUIC handshake packets, but currently does nothing with its parameters.
- **Inputs**:
    - `iter`: A pointer to a `quic_pcap_iter_t` structure, which is used to manage the state of the QUIC packet capture iteration.
    - `ip4_saddr`: An unsigned integer representing the IPv4 source address of the packet.
    - `data`: A constant pointer to an unsigned character array containing the packet data.
    - `data_sz`: An unsigned long integer representing the size of the packet data.
    - `out_pkt_sz`: A pointer to an unsigned long integer where the size of the processed packet should be stored.
- **Control Flow**:
    - The function is defined as static, meaning it is limited to the file scope.
    - All input parameters are cast to void, indicating that they are not used within the function body.
    - The function does not perform any operations or return any values, serving as a placeholder.
- **Output**: The function does not produce any output or modify its input parameters.


---
### quic\_pcap\_iter\_deliver\_1rtt<!-- {{#callable:quic_pcap_iter_deliver_1rtt}} -->
The `quic_pcap_iter_deliver_1rtt` function is a placeholder function intended to process 1-RTT QUIC packets, but currently does nothing with its parameters.
- **Inputs**:
    - `iter`: A pointer to a `quic_pcap_iter_t` structure, which contains information about the QUIC packet capture iteration.
    - `ip4_saddr`: An unsigned integer representing the IPv4 source address of the packet.
    - `data`: A constant pointer to an unsigned character array containing the packet data.
    - `data_sz`: An unsigned long integer representing the size of the data array.
- **Control Flow**:
    - The function takes four parameters: `iter`, `ip4_saddr`, `data`, and `data_sz`.
    - All parameters are cast to void, indicating they are unused in the current implementation.
    - The function body is empty, meaning no operations are performed on the inputs.
- **Output**: The function does not return any value or produce any output.


---
### quic\_pcap\_iter\_deliver\_datagram<!-- {{#callable:quic_pcap_iter_deliver_datagram}} -->
The `quic_pcap_iter_deliver_datagram` function processes a QUIC datagram by determining its packet type and dispatching it to the appropriate handler function for further processing.
- **Inputs**:
    - `iter`: A pointer to a `quic_pcap_iter_t` structure, which contains state information for processing QUIC packets.
    - `ip4_saddr`: An unsigned integer representing the IPv4 source address of the datagram.
    - `data`: A pointer to an array of unsigned characters representing the datagram data to be processed.
    - `data_sz`: An unsigned long integer representing the size of the datagram data in bytes.
- **Control Flow**:
    - The function enters a loop that continues as long as there is data to process (`data_sz` is non-zero).
    - It checks if the first byte of the data indicates a long header using `fd_quic_h0_hdr_form`.
    - If the header is long, it determines the packet type using `fd_quic_h0_long_packet_type`.
    - Depending on the packet type, it calls either [`quic_pcap_iter_deliver_initial`](#quic_pcap_iter_deliver_initial) or [`quic_pcap_iter_deliver_handshake`](#quic_pcap_iter_deliver_handshake) to process the packet, updating `data` and `data_sz` accordingly.
    - If the header is not long, it calls [`quic_pcap_iter_deliver_1rtt`](#quic_pcap_iter_deliver_1rtt) to process a 1-RTT packet and breaks the loop by setting `data_sz` to zero.
- **Output**: The function does not return a value; it processes the datagram in place and updates the state of the `iter` structure as needed.
- **Functions called**:
    - [`quic_pcap_iter_deliver_initial`](#quic_pcap_iter_deliver_initial)
    - [`quic_pcap_iter_deliver_handshake`](#quic_pcap_iter_deliver_handshake)
    - [`quic_pcap_iter_deliver_1rtt`](#quic_pcap_iter_deliver_1rtt)


---
### quic\_pcap\_iter\_deliver\_ethernet<!-- {{#callable:quic_pcap_iter_deliver_ethernet}} -->
The `quic_pcap_iter_deliver_ethernet` function processes Ethernet frames to extract and deliver UDP datagrams for further processing in a QUIC packet capture iterator.
- **Inputs**:
    - `iter`: A pointer to a `quic_pcap_iter_t` structure, which holds the state and context for processing QUIC packet captures.
    - `data`: A pointer to the start of the Ethernet frame data to be processed.
    - `data_sz`: The size of the Ethernet frame data in bytes.
- **Control Flow**:
    - Initialize pointers `cur` and `end` to the start and end of the data buffer, respectively.
    - Cast the start of the data buffer to an Ethernet header and advance the `cur` pointer by the size of the Ethernet header.
    - Check if the `cur` pointer has exceeded the `end` pointer, and return if true.
    - Verify that the Ethernet type is IP by checking the `net_type` field of the Ethernet header; return if it is not IP.
    - Cast the current position of the `cur` pointer to an IPv4 header and check if the header fits within the data buffer; return if it does not.
    - Advance the `cur` pointer by the length of the IPv4 header as specified in the header itself, and check if it exceeds the `end` pointer; return if true.
    - Verify that the protocol in the IPv4 header is UDP; return if it is not.
    - Cast the current position of the `cur` pointer to a UDP header and check if the header fits within the data buffer; return if it does not.
    - Advance the `cur` pointer by the size of the UDP header and check if it exceeds the `end` pointer; return if true.
    - Extract the source IP address from the IPv4 header.
    - Call [`quic_pcap_iter_deliver_datagram`](#quic_pcap_iter_deliver_datagram) with the iterator, source IP address, and the remaining data buffer to process the UDP datagram.
- **Output**: This function does not return a value; it processes the data in place and calls another function to handle the UDP datagram.
- **Functions called**:
    - [`quic_pcap_iter_deliver_datagram`](#quic_pcap_iter_deliver_datagram)


---
### quic\_pcap\_iter\_deliver\_cooked<!-- {{#callable:quic_pcap_iter_deliver_cooked}} -->
The `quic_pcap_iter_deliver_cooked` function logs an error indicating that Linux SLL captures are not supported.
- **Inputs**:
    - `iter`: A pointer to a `quic_pcap_iter_t` structure, which is used to iterate over pcap data.
    - `data`: A constant pointer to an unsigned character array representing the data to be processed.
    - `data_sz`: An unsigned long integer representing the size of the data array.
- **Control Flow**:
    - The function begins by casting the input parameters to void to suppress unused variable warnings.
    - It then logs an error message using `FD_LOG_ERR` to indicate that Linux SLL captures are not supported.
- **Output**: The function does not return any value as it is a void function.


---
### quic\_pcap\_iter\_run\_pcap<!-- {{#callable:quic_pcap_iter_run_pcap}} -->
The `quic_pcap_iter_run_pcap` function processes packets from a pcap file, determining their type and delivering them accordingly.
- **Inputs**:
    - `iter`: A pointer to a `quic_pcap_iter_t` structure, which contains the state and configuration for processing the pcap file.
- **Control Flow**:
    - Initialize a new pcap iterator using the file from the `iter` structure.
    - Check if the pcap iterator was successfully created; if not, log an error and exit.
    - Determine the type of pcap link (Ethernet or Cooked) and set the `is_cooked` flag accordingly.
    - Enter a loop to process each packet in the pcap file.
    - For each packet, read the packet data and timestamp using `fd_pcap_iter_next`.
    - If no more packets are available, break the loop.
    - Depending on the `is_cooked` flag, deliver the packet using either [`quic_pcap_iter_deliver_cooked`](#quic_pcap_iter_deliver_cooked) or [`quic_pcap_iter_deliver_ethernet`](#quic_pcap_iter_deliver_ethernet).
    - After processing all packets, delete the pcap iterator.
- **Output**: The function does not return a value; it processes packets and logs errors if any issues occur.
- **Functions called**:
    - [`quic_pcap_iter_deliver_cooked`](#quic_pcap_iter_deliver_cooked)
    - [`quic_pcap_iter_deliver_ethernet`](#quic_pcap_iter_deliver_ethernet)


---
### quic\_pcap\_iter\_run\_pcapng<!-- {{#callable:quic_pcap_iter_run_pcapng}} -->
The `quic_pcap_iter_run_pcapng` function processes a pcapng file to extract and handle QUIC traffic frames, including TLS keys and network packets, based on their link type.
- **Inputs**:
    - `iter`: A pointer to a `quic_pcap_iter_t` structure that contains the state and data necessary for iterating over a pcapng file, including the file pointer and maps for connection and key management.
- **Control Flow**:
    - Allocate memory for the pcapng iterator using `aligned_alloc` with alignment and footprint determined by `fd_pcapng_iter_align` and `fd_pcapng_iter_footprint` respectively.
    - Initialize a `fd_pcapng_iter_t` pointer to NULL.
    - Enter a loop that continues until the end of the pcap file is reached (`feof`).
    - If the `pcap` iterator is NULL, create a new pcapng iterator using `fd_pcapng_iter_new` and assign it to `pcap`. If creation fails, log an error and exit.
    - Retrieve the next frame from the pcapng iterator using `fd_pcapng_iter_next`. If no frame is returned, check for errors using `fd_pcapng_iter_err`. If the error is -1, delete the current iterator and set `pcap` to NULL to restart the iteration. Otherwise, log an error and exit.
    - If the frame type is `FD_PCAPNG_FRAME_TLSKEYS`, call [`quic_pcap_iter_add_keys`](#quic_pcap_iter_add_keys) to process the TLS keys in the frame data.
    - If the frame type is not `FD_PCAPNG_FRAME_SIMPLE` or `FD_PCAPNG_FRAME_ENHANCED`, continue to the next iteration.
    - Determine the link type from the frame's interface index and handle the frame data accordingly:
    - - If the link type is `FD_PCAPNG_LINKTYPE_ETHERNET`, call [`quic_pcap_iter_deliver_ethernet`](#quic_pcap_iter_deliver_ethernet) to process the Ethernet frame.
    - - If the link type is `FD_PCAPNG_LINKTYPE_COOKED`, call [`quic_pcap_iter_deliver_cooked`](#quic_pcap_iter_deliver_cooked) to process the cooked frame.
    - - For unsupported link types, log a notice message.
- **Output**: The function does not return a value; it processes the pcapng file and handles frames internally, potentially logging errors or notices.
- **Functions called**:
    - [`quic_pcap_iter_add_keys`](#quic_pcap_iter_add_keys)
    - [`quic_pcap_iter_deliver_ethernet`](#quic_pcap_iter_deliver_ethernet)
    - [`quic_pcap_iter_deliver_cooked`](#quic_pcap_iter_deliver_cooked)


---
### quic\_pcap\_iter\_run<!-- {{#callable:quic_pcap_iter_run}} -->
The `quic_pcap_iter_run` function determines the type of packet capture file (pcap or pcapng) and processes it accordingly.
- **Inputs**:
    - `iter`: A pointer to a `quic_pcap_iter_t` structure, which contains information about the packet capture file and associated maps for connection and key management.
- **Control Flow**:
    - Read the magic number from the beginning of the packet capture file to determine its format.
    - If the magic number indicates a pcap file (0xa1b2c3d4 or 0xa1b23c4d), call [`quic_pcap_iter_run_pcap`](#quic_pcap_iter_run_pcap) to process the file.
    - If the magic number indicates a pcapng file (0x0a0d0d0a), call [`quic_pcap_iter_run_pcapng`](#quic_pcap_iter_run_pcapng) to process the file.
    - If the magic number does not match any known format, log an error indicating an unsupported packet capture file format.
- **Output**: This function does not return a value; it processes the packet capture file based on its format.
- **Functions called**:
    - [`quic_pcap_iter_run_pcap`](#quic_pcap_iter_run_pcap)
    - [`quic_pcap_iter_run_pcapng`](#quic_pcap_iter_run_pcapng)


---
### main<!-- {{#callable:main}} -->
The `main` function processes command-line arguments to configure and run a QUIC packet capture analysis tool.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Iterates over command-line arguments to check for the '--help' flag, calling `usage()` and exiting if found.
    - Sets the environment variable 'FD_LOG_PATH' to suppress logs.
    - Calls `fd_boot` to initialize the environment with the remaining command-line arguments.
    - Strips the '--key-max' flag from the command-line arguments, setting a default maximum key count if not provided.
    - Calls [`reject_unknown_flags`](#reject_unknown_flags) to remove any unsupported flags from the arguments.
    - Checks if the remaining arguments are exactly two, otherwise calls `usage_invalid()` and exits with an error.
    - Extracts the command and pcap file path from the remaining arguments.
    - Initializes `quic_pcap_params_t` with the pcap path and key maximum value.
    - Creates a new `quic_pcap_iter_t` instance using [`quic_pcap_iter_new`](#quic_pcap_iter_new) with the initialized parameters.
    - If the iterator initialization fails, logs an error and aborts.
    - Runs the QUIC packet capture iteration using [`quic_pcap_iter_run`](#quic_pcap_iter_run).
    - Calls `fd_halt` to perform cleanup before exiting.
- **Output**: Returns 0 on successful execution or 1 if there are invalid arguments.
- **Functions called**:
    - [`usage`](#usage)
    - [`reject_unknown_flags`](#reject_unknown_flags)
    - [`usage_invalid`](#usage_invalid)
    - [`quic_pcap_iter_new`](#quic_pcap_iter_new)
    - [`quic_pcap_iter_run`](#quic_pcap_iter_run)



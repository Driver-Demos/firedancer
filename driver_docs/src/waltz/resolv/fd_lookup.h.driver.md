# Purpose
This C header file defines structures and function prototypes for DNS resolution and network address handling. It includes definitions for managing address information (`struct aibuf` and `struct address`), a configuration structure for DNS resolver settings (`struct fd_resolvconf`), and constants like `MAXNS` and `MAXADDRS` to limit the number of name servers and addresses processed. The file declares several functions with hidden visibility, such as [`fd_lookup_name`](#fd_lookup_name) and [`fd_get_resolv_conf`](#fd_get_resolv_conf), which are likely used for resolving hostnames and retrieving DNS configuration, respectively. Additionally, it includes external declarations for file descriptors related to system configuration files, enhancing the DNS resolution process by potentially using pre-opened file descriptors for `/etc/hosts` and `/etc/resolv.conf`.
# Imports and Dependencies

---
- `stdint.h`
- `stddef.h`
- `features.h`
- `netinet/in.h`
- `fd_netdb.h`


# Global Variables

---
### fd\_etc\_hosts\_fd
- **Type**: `int`
- **Description**: The `fd_etc_hosts_fd` is a global integer variable that represents a file descriptor for the '/etc/hosts' file. It is declared with the `FD_TL` storage class specifier, which suggests it may be thread-local or have specific linkage attributes.
- **Use**: This variable is used to access the '/etc/hosts' file, likely for reading or writing host information as part of the DNS resolution process.


---
### fd\_etc\_resolv\_conf\_fd
- **Type**: `int`
- **Description**: The `fd_etc_resolv_conf_fd` is a global integer variable that represents a file descriptor for the `/etc/resolv.conf` file. This file typically contains DNS resolver configuration for the system.
- **Use**: This variable is used to access and manage the file descriptor associated with the system's DNS resolver configuration file.


# Data Structures

---
### aibuf
- **Type**: `struct`
- **Members**:
    - `ai`: An instance of fd_addrinfo_t, likely containing address information.
    - `sa`: A union containing either an IPv4 or IPv6 socket address.
    - `slot`: A short integer used to identify a specific slot or position.
    - `ref`: A short integer used as a reference counter or identifier.
- **Description**: The `aibuf` structure is designed to encapsulate network address information, combining both IPv4 and IPv6 socket addresses within a union, and is likely used in network communication or address resolution tasks. It includes an `fd_addrinfo_t` type for address information, a union `sa` for handling both IPv4 and IPv6 addresses, and two short integers, `slot` and `ref`, which may be used for indexing or reference counting purposes.


---
### sa
- **Type**: `union`
- **Members**:
    - `sin`: A member of type `struct sockaddr_in` representing an IPv4 socket address.
    - `sin6`: A member of type `struct sockaddr_in6` representing an IPv6 socket address.
- **Description**: The `sa` union is a data structure that can store either an IPv4 or an IPv6 socket address, allowing for flexible handling of network addresses in a single variable. It is used within the `aibuf` structure to accommodate different types of network addresses.


---
### address
- **Type**: `struct`
- **Members**:
    - `family`: Specifies the address family, such as AF_INET for IPv4 or AF_INET6 for IPv6.
    - `scopeid`: An unsigned integer representing the scope identifier, used primarily for IPv6 addresses.
    - `addr`: An array of 16 unsigned characters storing the address data, accommodating both IPv4 and IPv6 addresses.
    - `sortkey`: An integer used for sorting addresses, potentially based on preference or priority.
- **Description**: The `address` structure is designed to encapsulate network address information, supporting both IPv4 and IPv6 formats. It includes fields for specifying the address family, a scope identifier for IPv6, a 16-byte array to store the address itself, and a sort key for ordering purposes. This structure is likely used in network-related operations where address management and resolution are required.


---
### fd\_resolvconf
- **Type**: `struct`
- **Members**:
    - `ns`: An array of 'address' structures representing the nameservers, with a maximum of MAXNS entries.
    - `nns`: An unsigned integer representing the number of nameservers configured.
    - `attempts`: An unsigned integer indicating the number of attempts to resolve a query.
    - `ndots`: An unsigned integer specifying the number of dots in a domain name before an initial absolute query is made.
    - `timeout`: An unsigned integer representing the timeout duration for a query.
- **Description**: The 'fd_resolvconf' structure is used to store DNS resolver configuration settings, including an array of nameserver addresses, the number of nameservers, the number of query attempts, the number of dots in a domain name before an absolute query is attempted, and the timeout duration for DNS queries. This structure is essential for managing DNS resolution behavior in network applications.


---
### fd\_resolvconf\_t
- **Type**: `struct`
- **Members**:
    - `ns`: An array of 'address' structures representing the nameservers.
    - `nns`: The number of nameservers configured.
    - `attempts`: The number of attempts to resolve a query.
    - `ndots`: The number of dots in a domain name before an initial absolute query is made.
    - `timeout`: The timeout duration for a query.
- **Description**: The 'fd_resolvconf_t' structure is used to store DNS resolver configuration settings, including an array of nameserver addresses, the number of nameservers, the number of query attempts, the number of dots in a domain name before an absolute query is made, and the timeout duration for queries. This structure is essential for managing DNS resolution settings in network applications.


# Function Declarations (Public API)

---
### fd\_lookup\_name<!-- {{#callable_declaration:fd_lookup_name}} -->
Resolves a hostname to a list of network addresses.
- **Description**: This function attempts to resolve a given hostname into a list of network addresses, storing the results in the provided buffer. It can handle both IPv4 and IPv6 addresses, and supports various flags to modify its behavior, such as handling IPv4-mapped IPv6 addresses. The function should be called with a valid hostname and appropriate family and flags settings. It returns the number of addresses found or an error code if the resolution fails. The canonical name of the host is also returned if available. The function must be called with a buffer capable of holding up to MAXADDRS addresses and a canonical name buffer of at least 256 characters.
- **Inputs**:
    - `buf`: An array of 'struct address' with a size of at least MAXADDRS. It is used to store the resolved addresses. The caller must ensure this buffer is properly allocated and has sufficient space.
    - `canon`: A character array with a size of at least 256. It is used to store the canonical name of the host if available. The caller must ensure this buffer is properly allocated.
    - `name`: A pointer to a null-terminated string representing the hostname to resolve. It must not be null, and its length must be less than 255 characters. An empty or overly long name will result in an error.
    - `family`: An integer specifying the address family to use for resolution. It can be AF_INET for IPv4, AF_INET6 for IPv6, or AF_UNSPEC for any family.
    - `flags`: An integer representing flags that modify the resolution behavior. It can include flags like FD_AI_V4MAPPED to handle IPv4-mapped IPv6 addresses. Invalid flags may alter the function's behavior.
- **Output**: Returns the number of addresses found on success, or a negative error code on failure. The 'buf' array is populated with the resolved addresses, and 'canon' is set to the canonical name if available.
- **See also**: [`fd_lookup_name`](fd_lookup_name.c.driver.md#fd_lookup_name)  (Implementation)


---
### fd\_lookup\_ipliteral<!-- {{#callable_declaration:fd_lookup_ipliteral}} -->
Resolves an IP literal to an address structure.
- **Description**: This function attempts to resolve a given IP literal string into an address structure, storing the result in the provided buffer. It is used when you have a string representation of an IP address and need to convert it into a structured format for network operations. The function supports both IPv4 and IPv6 addresses, and the caller must specify the expected address family. If the IP literal does not match the specified family, or if the conversion fails, the function returns an error code. The buffer must be pre-allocated and capable of holding at least one address structure.
- **Inputs**:
    - `buf`: A pre-allocated array of at least one 'struct address' where the resolved address will be stored. The caller retains ownership and must ensure it is not null.
    - `name`: A null-terminated string representing the IP literal to be resolved. It must not be null and should be a valid IP address in either IPv4 or IPv6 format.
    - `family`: An integer specifying the address family, either AF_INET for IPv4 or AF_INET6 for IPv6. If the IP literal does not match the specified family, an error is returned.
- **Output**: Returns 1 on successful resolution, 0 if the IP literal is invalid, or an error code (e.g., FD_EAI_NODATA, FD_EAI_NONAME) if the family is incorrect or other issues occur.
- **See also**: [`fd_lookup_ipliteral`](fd_lookup_ipliteral.c.driver.md#fd_lookup_ipliteral)  (Implementation)


---
### fd\_get\_resolv\_conf<!-- {{#callable_declaration:fd_get_resolv_conf}} -->
Populates a resolver configuration structure with settings from the system's resolv.conf file.
- **Description**: This function reads the system's /etc/resolv.conf file to populate a provided fd_resolvconf_t structure with DNS resolver settings, such as nameservers, ndots, timeout, and attempts. It should be called when you need to configure DNS resolution settings based on the system's configuration. If the resolv.conf file is not accessible or no nameservers are specified, it defaults to using the local host (127.0.0.1) as the nameserver. The function assumes that the file descriptor for /etc/resolv.conf is pre-opened and available in fd_etc_resolv_conf_fd. It does not handle errors explicitly but logs them if seeking within the file fails.
- **Inputs**:
    - `conf`: A pointer to an fd_resolvconf_t structure that will be populated with the resolver configuration. Must not be null. The caller retains ownership of this structure.
- **Output**: Returns 0 on completion. The conf structure is populated with the resolver settings, including default values if the resolv.conf file is not available or lacks nameserver entries.
- **See also**: [`fd_get_resolv_conf`](fd_resolvconf.c.driver.md#fd_get_resolv_conf)  (Implementation)


---
### fd\_res\_msend\_rc<!-- {{#callable_declaration:fd_res_msend_rc}} -->
Sends multiple DNS queries and receives their responses.
- **Description**: This function is used to send multiple DNS queries in parallel and receive their responses. It is designed to handle both IPv4 and IPv6 addresses and can retry queries in case of server failures. The function requires a valid configuration structure to specify the DNS servers and query parameters. It must be called with properly initialized input and output buffers, and the caller is responsible for interpreting the received DNS answer packets. The function will attempt to bind a socket and send queries to the configured DNS servers, handling both UDP and TCP protocols as necessary. It returns 0 on success, with the answers and their lengths populated in the provided buffers.
- **Inputs**:
    - `nqueries`: The number of DNS queries to send. Must be a positive integer.
    - `queries`: An array of pointers to the DNS query data. Each query must be a valid DNS query packet. The array must not be null, and each query must be properly formatted.
    - `qlens`: An array of integers representing the lengths of each query in the 'queries' array. Must have the same number of elements as 'nqueries'.
    - `answers`: An array of pointers where the DNS answers will be stored. Each pointer must point to a buffer large enough to hold the expected answer. The array must not be null.
    - `alens`: An array of integers where the lengths of the received answers will be stored. Must have the same number of elements as 'nqueries'. The array must not be null.
    - `asize`: The size of each buffer in the 'answers' array. Must be a positive integer.
    - `conf`: A pointer to a 'fd_resolvconf_t' structure containing the DNS server configuration. Must not be null and must be properly initialized.
- **Output**: Returns 0 on success, with the 'answers' and 'alens' arrays populated with the received DNS responses and their lengths, respectively.
- **See also**: [`fd_res_msend_rc`](fd_res_msend.c.driver.md#fd_res_msend_rc)  (Implementation)


---
### fd\_dns\_parse<!-- {{#callable_declaration:fd_dns_parse}} -->
Parses a DNS response and invokes a callback for each answer.
- **Description**: This function processes a DNS response packet and calls a user-provided callback function for each answer section in the packet. It should be used when you need to handle DNS responses manually, allowing custom processing of each answer. The function expects a valid DNS response packet and will return an error if the packet is malformed or if the callback function returns a negative value. It is important to ensure that the callback function is capable of handling the data passed to it and that the context pointer is valid.
- **Inputs**:
    - `r`: A pointer to the DNS response packet data. It must not be null and should point to a buffer of at least 'rlen' bytes.
    - `rlen`: The length of the DNS response packet data. It must be at least 12 to be considered a valid DNS response.
    - `callback`: A pointer to a function that will be called for each answer in the DNS response. The function should return a non-negative value on success and a negative value on failure.
    - `ctx`: A user-defined context pointer that will be passed to the callback function. It can be used to maintain state or pass additional information to the callback.
- **Output**: Returns 0 on success, -1 if the DNS response is malformed or if the callback returns a negative value.
- **See also**: [`fd_dns_parse`](fd_dns_parse.c.driver.md#fd_dns_parse)  (Implementation)



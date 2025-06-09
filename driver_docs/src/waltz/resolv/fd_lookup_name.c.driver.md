# Purpose
This C source code file is designed to handle network address resolution, specifically focusing on converting hostnames into network addresses. It provides a comprehensive set of functions to resolve hostnames using various methods, including checking null names, numeric addresses, local hosts file entries, and DNS queries. The code is structured to handle both IPv4 and IPv6 addresses, with specific attention to address family compatibility and DNS record types such as A, AAAA, and CNAME. The file includes mechanisms to parse DNS responses, manage DNS search configurations, and apply address selection policies based on RFC 3484/6724, which are standards for IPv6 address selection.

The code is not a standalone executable but rather a library intended to be integrated into a larger system, as indicated by the absence of a `main` function and the presence of multiple static functions. It includes several header files, both standard and custom, suggesting that it is part of a larger project with specific dependencies. The file defines internal functions and structures, such as `dpc_ctx` and `policy`, to manage the resolution process and apply address selection policies. The primary public interface appears to be the [`fd_lookup_name`](#fd_lookup_name) function, which orchestrates the resolution process and returns the resolved addresses. This function is designed to be flexible, supporting various flags to modify its behavior, such as handling v4-mapped addresses and passive address resolution.
# Imports and Dependencies

---
- `sys/socket.h`
- `netinet/in.h`
- `fd_netdb.h`
- `net/if.h`
- `arpa/inet.h`
- `ctype.h`
- `stdlib.h`
- `string.h`
- `fcntl.h`
- `unistd.h`
- `pthread.h`
- `errno.h`
- `fd_resolv.h`
- `fd_lookup.h`
- `fd_io_readline.h`
- `../../util/cstr/fd_cstr.h`
- `../../util/log/fd_log.h`
- `../../util/io/fd_io.h`
- `../../util/net/fd_ip6.h`


# Global Variables

---
### defpolicy
- **Type**: `array of `struct policy``
- **Description**: The `defpolicy` variable is a static constant array of `struct policy`, which defines a set of policies for handling network addresses. Each policy in the array contains fields for an address, length, mask, precedence, and label, which are used to determine how different network addresses should be treated.
- **Use**: This variable is used to define default policies for network address selection and processing, particularly in the context of IPv6 address handling.


# Data Structures

---
### dpc\_ctx
- **Type**: `struct`
- **Members**:
    - `addrs`: A pointer to an array of address structures.
    - `canon`: A pointer to a string representing the canonical name.
    - `cnt`: An integer representing the count of addresses.
    - `rrtype`: An integer representing the resource record type.
- **Description**: The `dpc_ctx` structure is used to manage DNS parsing context, holding information about addresses, canonical names, and resource record types. It includes a pointer to an array of `address` structures to store resolved addresses, a string pointer for the canonical name, and integers to track the number of addresses and the type of DNS resource record being processed. This structure is essential for handling DNS queries and responses within the context of the provided code.


---
### policy
- **Type**: `struct`
- **Members**:
    - `addr`: An array of 16 unsigned characters representing an IPv6 address.
    - `len`: An unsigned character indicating the length of the address prefix.
    - `mask`: An unsigned character used as a mask for address comparison.
    - `prec`: An unsigned character representing the precedence of the policy.
    - `label`: An unsigned character used as a label for the policy.
- **Description**: The `policy` structure is used to define a set of rules for handling IPv6 addresses, including their precedence and labeling. It contains fields for the address, prefix length, mask, precedence, and label, which are used to determine how addresses are matched and prioritized. The `defpolicy` array is a static constant array of `policy` structures, each representing a specific rule for address handling, and is used in functions to determine the appropriate policy for a given IPv6 address.


# Functions

---
### is\_valid\_hostname<!-- {{#callable:is_valid_hostname}} -->
The `is_valid_hostname` function checks if a given string is a valid hostname according to specific character rules.
- **Inputs**:
    - `host`: A constant character pointer representing the hostname to be validated.
- **Control Flow**:
    - The function first checks if the length of the hostname is greater than 254 characters using `strnlen`; if so, it returns 0 indicating an invalid hostname.
    - It then iterates over each character in the hostname, checking if each character is either a valid ASCII character (less than 0x80), a period '.', a hyphen '-', or an alphanumeric character using `fd_isalnum`.
    - If any character does not meet these criteria, the loop exits.
    - Finally, the function returns the negation of the current character, which will be 1 (true) if the end of the string is reached, indicating a valid hostname, or 0 (false) if an invalid character was found.
- **Output**: An integer value, 1 if the hostname is valid, and 0 if it is not.


---
### name\_from\_null<!-- {{#callable:name_from_null}} -->
The `name_from_null` function populates a buffer with default address structures based on the provided family and flags when the name is null.
- **Inputs**:
    - `buf`: An array of at least two `struct address` elements to be populated with address information.
    - `name`: A constant character pointer representing the name, which if non-null, results in an immediate return of 0.
    - `family`: An integer representing the address family, typically `AF_INET` or `AF_INET6`, to determine which address types to populate.
    - `flags`: An integer representing flags that modify the behavior of address selection, such as `FD_AI_PASSIVE`.
- **Control Flow**:
    - Initialize a counter `cnt` to 0.
    - Check if `name` is non-null; if so, return 0 immediately.
    - Check if `flags` include `FD_AI_PASSIVE`.
    - If `FD_AI_PASSIVE` is set, add an `AF_INET` address to `buf` if `family` is not `AF_INET6`, and add an `AF_INET6` address if `family` is not `AF_INET`.
    - If `FD_AI_PASSIVE` is not set, add a loopback `AF_INET` address to `buf` if `family` is not `AF_INET6`, and add a loopback `AF_INET6` address if `family` is not `AF_INET`.
    - Return the count of addresses added to `buf`.
- **Output**: Returns an integer representing the number of address structures added to the buffer `buf`.


---
### name\_from\_numeric<!-- {{#callable:name_from_numeric}} -->
The `name_from_numeric` function attempts to resolve a numeric IP address into a structured address format using a specified address family.
- **Inputs**:
    - `buf`: A pointer to an array of `struct address` where the resolved address will be stored.
    - `name`: A constant character pointer representing the numeric IP address to be resolved.
    - `family`: An integer representing the address family (e.g., AF_INET for IPv4, AF_INET6 for IPv6) to be used for resolution.
- **Control Flow**:
    - The function directly calls [`fd_lookup_ipliteral`](fd_lookup_ipliteral.c.driver.md#fd_lookup_ipliteral) with the provided `buf`, `name`, and `family` arguments.
    - The result of [`fd_lookup_ipliteral`](fd_lookup_ipliteral.c.driver.md#fd_lookup_ipliteral) is returned as the output of the function.
- **Output**: An integer indicating the success or failure of the address resolution, as returned by [`fd_lookup_ipliteral`](fd_lookup_ipliteral.c.driver.md#fd_lookup_ipliteral).
- **Functions called**:
    - [`fd_lookup_ipliteral`](fd_lookup_ipliteral.c.driver.md#fd_lookup_ipliteral)


---
### name\_from\_hosts<!-- {{#callable:name_from_hosts}} -->
The `name_from_hosts` function attempts to resolve a hostname to its corresponding IP addresses and canonical name by searching the local `/etc/hosts` file.
- **Inputs**:
    - `buf`: An array of `struct address` to store the resolved IP addresses, with a size of at least `MAXADDRS`.
    - `canon`: A character array of size 256 to store the canonical name of the host.
    - `name`: A constant character pointer representing the hostname to be resolved.
    - `family`: An integer representing the address family (e.g., `AF_INET` for IPv4, `AF_INET6` for IPv6) to filter the results.
- **Control Flow**:
    - Initialize variables for the length of the hostname, counters, and flags for bad family and canonical name presence.
    - Check if the file descriptor `fd_etc_hosts_fd` is valid; if not, return 0 indicating no addresses found.
    - Attempt to reset the file pointer of `/etc/hosts` to the beginning; log an error if this fails.
    - Initialize a buffered input stream to read from the `/etc/hosts` file.
    - Iterate over each line in the `/etc/hosts` file until the maximum number of addresses (`MAXADDRS`) is reached or no more lines are available.
    - For each line, remove comments and search for the hostname, ensuring it is a standalone word.
    - If the hostname is found, isolate the IP address and attempt to parse it using [`name_from_numeric`](#name_from_numeric).
    - If the IP address is valid and matches the family, increment the count of addresses found.
    - If a canonical name has not been set, extract the first valid hostname from the line as the canonical name.
    - Return the count of addresses found, or an error code if no valid addresses were found.
- **Output**: Returns the number of addresses found and stored in `buf`, or an error code if no valid addresses were found.
- **Functions called**:
    - [`fd_io_fgets`](fd_io_readline.c.driver.md#fd_io_fgets)
    - [`name_from_numeric`](#name_from_numeric)
    - [`is_valid_hostname`](#is_valid_hostname)


---
### dns\_parse\_callback<!-- {{#callable:dns_parse_callback}} -->
The `dns_parse_callback` function processes DNS resource records, updating a context with canonical names or IP addresses based on the record type.
- **Inputs**:
    - `c`: A pointer to a `dpc_ctx` structure that holds the context for DNS parsing, including address storage and canonical name.
    - `rr`: An integer representing the resource record type (e.g., RR_A, RR_CNAME, RR_AAAA).
    - `data`: A pointer to the data of the DNS resource record.
    - `len`: An integer representing the length of the data.
    - `packet`: A pointer to the DNS packet containing the resource record.
    - `plen`: An integer representing the length of the DNS packet.
- **Control Flow**:
    - Initialize a temporary buffer `tmp` and set `family` to `AF_UNSPEC`.
    - Cast the context pointer `c` to a `dpc_ctx` structure pointer `ctx`.
    - Check if the resource record type `rr` is `RR_CNAME`; if so, expand the domain name and validate it, then copy it to `ctx->canon` if valid, and return 0.
    - Check if the current address count `ctx->cnt` is greater than or equal to `MAXADDRS`; if so, return 0.
    - Check if the resource record type `rr` does not match `ctx->rrtype`; if so, return 0.
    - Use a switch statement to handle `RR_A` and `RR_AAAA` record types, setting `family` to `AF_INET` or `AF_INET6` respectively, and validate the length `len` of the data.
    - Update the `ctx->addrs` array with the family, scope ID, and address data, incrementing the address count `ctx->cnt`.
    - Return 0 to indicate successful processing.
- **Output**: Returns 0 on successful processing of the DNS record, or -1 if there is an error with the data length for `RR_A` or `RR_AAAA` records.
- **Functions called**:
    - [`fd_dn_expand`](fd_dn_expand.c.driver.md#fd_dn_expand)
    - [`is_valid_hostname`](#is_valid_hostname)


---
### name\_from\_dns<!-- {{#callable:name_from_dns}} -->
The `name_from_dns` function performs DNS resolution for a given hostname, populating an address buffer and canonical name based on the specified address family and resolver configuration.
- **Inputs**:
    - `buf`: An array of `struct address` to store the resolved addresses, with a size of at least `MAXADDRS`.
    - `canon`: A character array of size 256 to store the canonical name of the resolved hostname.
    - `name`: A constant character pointer representing the hostname to be resolved.
    - `family`: An integer specifying the address family (e.g., `AF_INET` or `AF_INET6`) to filter the DNS query.
    - `conf`: A constant pointer to `fd_resolvconf_t` structure containing DNS resolver configuration.
- **Control Flow**:
    - Initialize query and answer buffers for DNS queries and responses.
    - Set up a context structure `ctx` to hold the address buffer and canonical name.
    - Iterate over possible address families (IPv4 and IPv6) and prepare DNS queries for the family not specified by the input `family`.
    - Send the DNS queries using [`fd_res_msend_rc`](fd_res_msend.c.driver.md#fd_res_msend_rc) and check for errors in sending or receiving responses.
    - Iterate over the received DNS responses, checking for errors or specific response codes, and return appropriate error codes if necessary.
    - Parse the DNS response using [`fd_dns_parse`](fd_dns_parse.c.driver.md#fd_dns_parse) and a callback function to populate the address buffer and canonical name.
    - Return the count of resolved addresses if successful, or an error code if no data is found.
- **Output**: Returns the number of addresses resolved and stored in the buffer, or an error code if the resolution fails.
- **Functions called**:
    - [`fd_res_mkquery`](fd_res_mkquery.c.driver.md#fd_res_mkquery)
    - [`fd_res_msend_rc`](fd_res_msend.c.driver.md#fd_res_msend_rc)
    - [`fd_dns_parse`](fd_dns_parse.c.driver.md#fd_dns_parse)


---
### name\_from\_dns\_search<!-- {{#callable:name_from_dns_search}} -->
The `name_from_dns_search` function attempts to resolve a hostname to an address using DNS search, appending a search domain if necessary, and returns the result from a DNS query.
- **Inputs**:
    - `buf`: An array of `struct address` with a static size of `MAXADDRS` to store the resolved addresses.
    - `canon`: A character array with a static size of 256 to store the canonical name of the resolved address.
    - `name`: A constant character pointer representing the hostname to be resolved.
    - `family`: An integer representing the address family (e.g., AF_INET or AF_INET6) for the resolution.
- **Control Flow**:
    - Initialize a `fd_resolvconf_t` structure `conf` to hold resolver configuration.
    - Check if the resolver configuration can be retrieved using [`fd_get_resolv_conf`](fd_resolvconf.c.driver.md#fd_get_resolv_conf); return -1 if it fails.
    - Calculate the length `l` of the input `name` string.
    - If the name ends with a dot, decrement `l` to strip the final dot; return `FD_EAI_NONAME` if there are multiple trailing dots or if `l` is zero.
    - Check if the length `l` is greater than or equal to 256; if so, return `FD_EAI_NONAME`.
    - Copy the `name` into `canon` up to length `l` and append a dot.
    - Set the null terminator for `canon` and call [`name_from_dns`](#name_from_dns) with the prepared parameters.
    - Return the result from [`name_from_dns`](#name_from_dns).
- **Output**: Returns an integer indicating the success or failure of the DNS resolution, with specific error codes like `FD_EAI_NONAME` for name-related errors.
- **Functions called**:
    - [`fd_get_resolv_conf`](fd_resolvconf.c.driver.md#fd_get_resolv_conf)
    - [`name_from_dns`](#name_from_dns)


---
### policyof<!-- {{#callable:policyof}} -->
The `policyof` function determines the policy associated with a given IPv6 address by comparing it against a predefined set of policies.
- **Inputs**:
    - `a`: A pointer to a `struct in6_addr` representing the IPv6 address to be checked against the policy list.
- **Control Flow**:
    - The function enters an infinite loop iterating over the `defpolicy` array.
    - For each policy, it compares the initial bytes of the input address `a` with the policy's address using `memcmp`.
    - If the bytes do not match, the loop continues to the next policy.
    - If the bytes match, it further checks if the next byte of the address, masked with the policy's mask, matches the corresponding byte in the policy's address.
    - If this second condition is also met, the function returns a pointer to the matching policy.
- **Output**: A pointer to a `struct policy` that matches the given IPv6 address, or continues indefinitely if no match is found.


---
### labelof<!-- {{#callable:labelof}} -->
The `labelof` function retrieves the label associated with a given IPv6 address based on predefined policies.
- **Inputs**:
    - `a`: A pointer to a `struct in6_addr` representing the IPv6 address for which the label is to be determined.
- **Control Flow**:
    - The function calls [`policyof`](#policyof) with the provided IPv6 address to retrieve the corresponding policy structure.
    - It accesses the `label` field of the returned policy structure and returns it.
- **Output**: An integer representing the label of the given IPv6 address as defined by the matching policy.
- **Functions called**:
    - [`policyof`](#policyof)


---
### scopeof<!-- {{#callable:scopeof}} -->
The `scopeof` function determines the scope of an IPv6 address based on its type.
- **Inputs**:
    - `a`: A pointer to a constant `struct in6_addr` representing the IPv6 address to be evaluated.
- **Control Flow**:
    - Check if the address is a multicast address using `IN6_IS_ADDR_MULTICAST`; if true, return the lower 4 bits of the second byte of the address.
    - Check if the address is a link-local or loopback address using `IN6_IS_ADDR_LINKLOCAL` or `IN6_IS_ADDR_LOOPBACK`; if true, return 2.
    - Check if the address is a site-local address using `IN6_IS_ADDR_SITELOCAL`; if true, return 5.
    - If none of the above conditions are met, return 14 as the default scope.
- **Output**: An integer representing the scope of the IPv6 address, with specific values for multicast, link-local, loopback, site-local, and a default value for other types.


---
### prefixmatch<!-- {{#callable:prefixmatch}} -->
The `prefixmatch` function calculates the length of the common prefix between two IPv6 addresses.
- **Inputs**:
    - `s`: A pointer to the source IPv6 address structure (`struct in6_addr`).
    - `d`: A pointer to the destination IPv6 address structure (`struct in6_addr`).
- **Control Flow**:
    - Initialize a loop counter `i` to 0.
    - Iterate over each bit position up to 128 (the length of an IPv6 address in bits).
    - For each bit position, check if the corresponding bits in the source and destination addresses are the same using XOR and bitwise AND operations.
    - If the bits differ, break the loop; otherwise, continue to the next bit.
    - Return the count `i`, which represents the length of the common prefix.
- **Output**: The function returns an integer representing the length of the common prefix in bits between the two IPv6 addresses.


---
### addrcmp<!-- {{#callable:addrcmp}} -->
The `addrcmp` function compares two `struct address` objects based on their `sortkey` values.
- **Inputs**:
    - `_a`: A pointer to the first `struct address` object to be compared.
    - `_b`: A pointer to the second `struct address` object to be compared.
- **Control Flow**:
    - The function casts the input pointers `_a` and `_b` to pointers of type `struct address`.
    - It accesses the `sortkey` field of both `struct address` objects pointed to by `a` and `b`.
    - The function returns the difference between the `sortkey` of `b` and the `sortkey` of `a`.
- **Output**: An integer representing the result of the comparison: a positive value if `b->sortkey` is greater than `a->sortkey`, zero if they are equal, and a negative value if `b->sortkey` is less than `a->sortkey`.


---
### fd\_lookup\_name<!-- {{#callable:fd_lookup_name}} -->
The `fd_lookup_name` function resolves a hostname to a list of network addresses, applying various filters and transformations based on the specified address family and flags.
- **Inputs**:
    - `buf`: A buffer of `struct address` with a size of at least `MAXADDRS` to store the resolved addresses.
    - `canon`: A character array of size 256 to store the canonical name of the host.
    - `name`: A constant character pointer representing the hostname to be resolved.
    - `family`: An integer specifying the address family (e.g., `AF_INET`, `AF_INET6`, or `AF_UNSPEC`).
    - `flags`: An integer representing flags that modify the behavior of the lookup, such as `FD_AI_V4MAPPED` or `FD_AI_NUMERICHOST`.
- **Control Flow**:
    - Initialize the canonical name buffer to an empty string.
    - Check if the `name` is provided and valid; if not, return `FD_EAI_NONAME`.
    - Adjust the `family` and `flags` if `FD_AI_V4MAPPED` is set.
    - Attempt to resolve the name using various methods: null, numeric, hosts file, and DNS search, until at least one address is found.
    - If no addresses are found, return `FD_EAI_NONAME`.
    - If `FD_AI_V4MAPPED` is set, filter and transform results to include only IPv6 addresses, translating IPv4 addresses to IPv6 if necessary.
    - If there are fewer than two results or only IPv4 results, return the count of addresses found.
    - For more than one result, generate a sort key for each address based on a subset of RFC 3484/6724 rules and sort the addresses.
    - Return the count of resolved addresses.
- **Output**: Returns the number of addresses found and stored in `buf`, or an error code such as `FD_EAI_NONAME` if no addresses are found.
- **Functions called**:
    - [`name_from_null`](#name_from_null)
    - [`name_from_numeric`](#name_from_numeric)
    - [`name_from_hosts`](#name_from_hosts)
    - [`name_from_dns_search`](#name_from_dns_search)
    - [`policyof`](#policyof)
    - [`scopeof`](#scopeof)
    - [`labelof`](#labelof)
    - [`prefixmatch`](#prefixmatch)



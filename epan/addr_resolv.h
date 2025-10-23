/** @file
 * Definitions for network object lookup
 *
 * Laurent Deniel <laurent.deniel@free.fr>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
/* The buffers returned by these functions are all allocated with a
 * packet lifetime and does not have to be freed.
 * However, take into account that when the packet dissection
 * completes, these buffers will be automatically reclaimed/freed.
 * If you need the buffer to remain for a longer scope than packet lifetime
 * you must copy the content to an wmem_file_scope() buffer.
 */

#ifndef __RESOLV_H__
#define __RESOLV_H__

#include <epan/address.h>
#include <epan/tvbuff.h>
#include <wsutil/inet_cidr.h>
#include <epan/to_str.h>
#include <wiretap/wtap.h>
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef MAXNAMELEN
#define MAXNAMELEN  	64	/* max name length (most names: DNS labels, services, eth) */
#endif

#ifndef MAXVLANNAMELEN
#define MAXVLANNAMELEN  	128	/* max vlan name length */
#endif

#ifndef MAXDNSNAMELEN
#define MAXDNSNAMELEN	256	/* max total length of a domain name in the DNS */
#endif

#define BASE_ENTERPRISES     BASE_CUSTOM
#define STRINGS_ENTERPRISES  CF_FUNC(enterprises_base_custom)

/**
 * @brief Flags to control name resolution.
 */
typedef struct _e_addr_resolve {
  bool mac_name;                          /**< Whether to resolve Ethernet MAC to manufacturer names */
  bool network_name;                      /**< Whether to resolve IPv4, IPv6, and IPX addresses into host names */
  bool transport_name;                    /**< Whether to resolve TCP/UDP/DCCP/SCTP ports into service names */
  bool dns_pkt_addr_resolution;           /**< Whether to resolve addresses using captured DNS packets */
  bool handshake_sni_addr_resolution;     /**< Whether to resolve addresses using SNI information found in captured handshake packets */
  bool use_external_net_name_resolver;    /**< Whether to system's configured DNS server to resolve names */
  bool vlan_name;                         /**< Whether to resolve VLAN IDs to names */
  bool ss7pc_name;                        /**< Whether to resolve SS7 Point Codes to names */
  bool maxmind_geoip;                     /**< Whether to lookup geolocation information with mmdbresolve */
} e_addr_resolve;

#define ADDR_RESOLV_MACADDR(at) \
    (((at)->type == AT_ETHER) || ((at)->type == AT_EUI64))

#define ADDR_RESOLV_NETADDR(at) \
    (((at)->type == AT_IPv4) || ((at)->type == AT_IPv6) || ((at)->type == AT_IPX))

struct hashether;
typedef struct hashether hashether_t;

struct hasheui64;
typedef struct hasheui64 hasheui64_t;

struct hashwka;
typedef struct hashwka hashwka_t;

struct hashmanuf;
typedef struct hashmanuf hashmanuf_t;

typedef struct _serv_port_key {
    uint16_t          port;
    port_type         type;
} serv_port_key_t;

/* Used for manually edited DNS resolved names */
typedef struct _resolved_name {
    char             name[MAXDNSNAMELEN];
} resolved_name_t;

/*
 * Flags for various resolved name hash table entries.
 */
#define TRIED_RESOLVE_ADDRESS    (1U<<0)  /* name resolution is being/has been tried */
#define NAME_RESOLVED            (1U<<1)  /* the name field contains a host name, not a printable address */
#define RESOLVED_ADDRESS_USED    (1U<<2)  /* a get_hostname* call returned the host name */
#define STATIC_HOSTNAME          (1U<<3)  /* do not update entries from hosts file with DNS responses */
#define NAME_RESOLVED_PREFIX     (1U<<4)  /* name was generated from a prefix (e.g., OUI) instead of the entire address */

#define TRIED_OR_RESOLVED_MASK   (TRIED_RESOLVE_ADDRESS | NAME_RESOLVED)
#define USED_AND_RESOLVED_MASK   (NAME_RESOLVED | RESOLVED_ADDRESS_USED)

/*
 * Flag controlling what names to resolve.
 */
WS_DLL_PUBLIC e_addr_resolve gbl_resolv_flags;

/* global variables */

extern char *g_ethers_path;
extern char *g_ipxnets_path;
extern char *g_pethers_path;
extern char *g_pipxnets_path;

/* Functions in addr_resolv.c */

/**
 * @brief Construct a new IPv4 object from a 32-bit address.
 *
 * Creates and returns a `hashipv4_t` instance initialized with the given
 * IPv4 address. The address should be provided in host byte order as a
 * 32-bit unsigned integer.
 *
 * @param addr  IPv4 address in host byte order.
 * @return      Pointer to a newly allocated `hashipv4_t` object.
 */
WS_DLL_PUBLIC hashipv4_t * new_ipv4(const unsigned addr);

/**
 * @brief Populate a dummy IPv4 object with the specified address.
 *
 * Initializes the given `hashipv4_t` pointer with the provided IPv4 address,
 * marking it as a placeholder or synthetic entry. This is typically used for
 * testing, fallback logic, or internal bookkeeping where a non-real IP is
 * required.
 *
 * @param addr IPv4 address in host byte order.
 * @param tp   Pointer to a `hashipv4_t` object to populate.
 * @return     `true` on success, `false` on failure.
 */
WS_DLL_PUBLIC bool fill_dummy_ip4(const unsigned addr, hashipv4_t* volatile tp);

/**
 * @brief Resolve a UDP port number to its display name.
 *
 * Returns a human-readable name for the specified UDP port, such as "DNS" for port 53.
 * If no known name is associated with the port, the function returns the numeric
 * port value as a string. The result is allocated using the provided `wmem_allocator_t`.
 *
 * @param allocator Memory allocator used to allocate the returned string.
 * @param port      UDP port number to resolve.
 * @return          Allocated string containing the port name or numeric value.
 */
WS_DLL_PUBLIC char *udp_port_to_display(wmem_allocator_t *allocator, unsigned port);


/**
 * @brief Resolve a TCP port number to its display name.
 *
 * Returns a human-readable name for the specified TCP port, such as "HTTP" for port 80.
 * If no known name is associated with the port, the function returns the numeric
 * port value as a string. The result is allocated using the provided `wmem_allocator_t`.
 *
 * @param allocator Memory allocator used to allocate the returned string.
 * @param port      TCP port number to resolve.
 * @return          Allocated string containing the port name or numeric value.
 */
WS_DLL_PUBLIC char *tcp_port_to_display(wmem_allocator_t *allocator, unsigned port);

/**
 * @brief Resolve a DCCP port number to its display name.
 *
 * Returns a human-readable name for the specified DCCP port, such as "RTP" or "DCCP-Test".
 * If no known name is associated with the port, the function returns the numeric
 * port value as a string. The result is allocated using the provided `wmem_allocator_t`.
 *
 * @param allocator Memory allocator used to allocate the returned string.
 * @param port      DCCP port number to resolve.
 * @return          Allocated string containing the port name or numeric value.
 */
extern char *dccp_port_to_display(wmem_allocator_t *allocator, unsigned port);

/**
 * @brief Resolve an SCTP port number to its display name.
 *
 * Returns a human-readable name for the specified SCTP port, such as "Diameter" for port 3868.
 * If no known name is associated with the port, the function returns the numeric
 * port value as a string. The result is allocated using the provided `wmem_allocator_t`.
 *
 * @param allocator Memory allocator used to allocate the returned string.
 * @param port      SCTP port number to resolve.
 * @return          Allocated string containing the port name or numeric value.
 */
WS_DLL_PUBLIC char *sctp_port_to_display(wmem_allocator_t *allocator, unsigned port);

/**
 * @brief Resolve a port number to its well-known service name.
 *
 * Returns a string representing the service name associated with the given
 * port and protocol (e.g., "HTTP" for TCP port 80). If no known service name
 * exists for the specified port, the function returns the numeric port value
 * as a string.
 *
 * @param proto Protocol type (e.g., PT_TCP, PT_UDP).
 * @param port  Port number to resolve.
 * @return      Constant string containing the service name or numeric value.
 */
WS_DLL_PUBLIC const char *serv_name_lookup(port_type proto, unsigned port);

/**
 * @brief Resolve a private enterprise code to its registered name.
 *
 * Returns the name associated with the given private enterprise code (PEC),
 * commonly used in SNMP, IPFIX, and other protocol metadata. If no known
 * name exists for the specified code, the function returns `unknown_str`,
 * or the string "<Unknown>" if `unknown_str` is NULL.
 *
 * This is typically used for display, logging, or protocol dissection.
 *
 * @param value        Private enterprise code to resolve.
 * @param unknown_str  Fallback string if the code is not recognized.
 * @return             Constant string containing the enterprise name or fallback.
 */
WS_DLL_PUBLIC const char *enterprises_lookup(uint32_t value, const char *unknown_str);

/**
 * @brief Attempt to resolve a private enterprise code to its registered name.
 *
 * Returns the name associated with the given private enterprise code (PEC),
 * commonly used in SNMP, IPFIX, and other protocol metadata. If the code is
 * not recognized, the function returns `NULL`.
 *
 * @param value Private enterprise code to resolve.
 * @return      Constant string containing the enterprise name, or `NULL` if not found.
 */
WS_DLL_PUBLIC const char *try_enterprises_lookup(uint32_t value);

/**
 * @brief Format a private enterprise code as "name (decimal)" into a buffer.
 *
 * Writes a string representation of the given enterprise code to `buf`,
 * using the format `"Name (1234)"`. If the code is unknown, the name portion
 * is resolved via `enterprises_lookup()` and may fall back to "<Unknown>".
 *
 * @param buf   Output buffer to receive the formatted string.
 * @param value Private enterprise code to format.
 */
WS_DLL_PUBLIC void enterprises_base_custom(char *buf, uint32_t value);

/**
 * @brief Attempt to resolve a port number to its well-known service name.
 *
 * Returns the service name associated with the specified port and protocol
 * (e.g., "HTTPS" for TCP port 443). If no known service name exists for the
 * given combination, the function returns `NULL`.
 *
 * @param proto Protocol type (e.g., PT_TCP, PT_UDP).
 * @param port  Port number to resolve.
 * @return      Constant string containing the service name, or `NULL` if not found.
 */
WS_DLL_PUBLIC const char *try_serv_name_lookup(port_type proto, unsigned port);

/**
 * @brief Format a port number with its resolved service name.
 *
 * Returns a string in the format `"ServiceName (port)"`, such as `"HTTP (80)"`,
 * based on the specified protocol and port number. If no known service name
 * exists for the port, the numeric value is used as both the name and number.
 * The result is allocated using the provided `wmem_allocator_t`.
 *
 * @param scope Memory allocator used to allocate the returned string.
 * @param proto Protocol type (e.g., PT_TCP, PT_UDP).
 * @param port  Port number to format.
 * @return      Allocated string containing the formatted port representation.
 */
WS_DLL_PUBLIC char *port_with_resolution_to_str(wmem_allocator_t *scope,
                                        port_type proto, unsigned port);

/**
 * @brief Format a port number with its resolved service name into a buffer.
 *
 * Writes a string in the format `"ServiceName (port)"`—such as `"SSH (22)"`—
 * to the provided buffer, based on the specified protocol and port number.
 * If no known service name exists, the numeric value is used as both name
 * and number. This function is typically used for logging, diagnostics,
 * or UI display where fixed-size output is required.
 *
 * The return value matches that of `snprintf()`: the number of characters
 * that would have been written if the buffer were large enough.
 *
 * @param buf       Output buffer to receive the formatted string.
 * @param buf_size  Size of the output buffer in bytes.
 * @param proto     Protocol type (e.g., PT_TCP, PT_UDP).
 * @param port      Port number to format.
 * @return          Number of characters that would have been written.
 */
WS_DLL_PUBLIC int port_with_resolution_to_str_buf(char *buf, unsigned long buf_size,
                                        port_type proto, unsigned port);

/*
 * Asynchronous host name lookup initialization, processing, and cleanup
 */

/* Setup name resolution preferences */
struct pref_module;
extern void addr_resolve_pref_init(struct pref_module *nameres);
extern void addr_resolve_pref_apply(void);

/**
 * @brief Disable all forms of name resolution.
 *
 * Sets all relevant global resolution flags (`gbl_resolv_flags`) to `false`,
 * effectively disabling hostname, service name, and other symbolic resolution
 * features. This is typically used to improve performance or enforce numeric-only
 * output in protocol analysis and logging.
 */
WS_DLL_PUBLIC void disable_name_resolution(void);

/**
 * @brief Process outstanding asynchronous host name lookups via c-ares.
 *
 * If c-ares is enabled, this function checks for completed host name resolutions
 * and updates internal state accordingly. It is invoked periodically via a GLIB
 * timeout in Wireshark, and before each packet is processed during the first pass
 * of two-pass TShark analysis.
 *
 * @return True if any new objects have been resolved since the previous
 * call. This can be used to trigger a display update, e.g. in Wireshark.
 */
WS_DLL_PUBLIC bool host_name_lookup_process(void);

/**
 * @brief Resolve an IPv4 address to its host name.
 *
 * Returns a string containing the host name associated with the given IPv4
 * address, or a numeric string in the format `"%d.%d.%d.%d"` if no name is found.
 * The returned string is managed internally and must not be freed by the caller.
 * It will be released when address hashtables are cleared (e.g., due to preference
 * changes or redissection).
 *
 * @note This function may increase persistent memory usage even when host name
 *       resolution is disabled. It may be deprecated in favor of `get_hostname_wmem()`
 *       for better memory management.
 *
 * @param addr IPv4 address in host byte order.
 * @return     Constant string containing the resolved host name or numeric address.
 */
WS_DLL_PUBLIC const char *get_hostname(const unsigned addr);

/**
 * @brief Resolve an IPv4 address to its host name using scoped memory allocation.
 *
 * Returns a string containing the host name associated with the given IPv4 address,
 * or a numeric string in the format `"%d.%d.%d.%d"` if no name is found. The returned
 * string is allocated using the provided `wmem_allocator_t`, allowing flexible memory
 * management across dissector passes or UI components.
 *
 * This function is preferred over `get_hostname()` for memory safety and scoped lifetime
 * control, especially in environments with redissection or preference reloads.
 *
 * @param allocator Memory allocator used to allocate the returned string.
 * @param addr      IPv4 address in host byte order.
 * @return          Allocated string containing the resolved host name or numeric address.
 */
WS_DLL_PUBLIC char *get_hostname_wmem(wmem_allocator_t *allocator, const unsigned addr);

/**
 * @brief Resolves an IPv6 address to a hostname or numeric string.
 *
 * get_hostname6 returns the host name, or numeric addr if not found.
 * The string does not have to be freed; it will be freed when the
 * address hashtables are emptied (e.g., when preferences change or
 * upon redissection.) However, this increases persistent memory usage
 * even when host name lookups are off.
 *
 * This might get deprecated in the future for get_hostname6_wmem.
 *
 * @param ad Pointer to the IPv6 address.
 * @return Hostname or numeric address string.
 */
WS_DLL_PUBLIC const char *get_hostname6(const ws_in6_addr *ad);

/**
 * @brief Resolves an IPv6 address to a hostname using a memory allocator.
 *
 * Returns a newly allocated string representing the hostname or numeric address
 * for the given IPv6 address.
 *
 * @param allocator Memory allocator scope.
 * @param ad Pointer to the IPv6 address.
 * @return Allocated hostname or numeric address string.
 */
WS_DLL_PUBLIC char *get_hostname6_wmem(wmem_allocator_t *allocator, const ws_in6_addr *ad);

/**
 * @brief Resolves an Ethernet address to a logical name or vendor string.
 *
 * Returns a logical name if found in ethers files, or a vendor-prefixed string
 * if the vendor is known, or a full MAC address string otherwise.
 *
 * For example:
 * "<vendor>_%02x:%02x:%02x" if the vendor code is known else
 * "%02x:%02x:%02x:%02x:%02x:%02x"
 *
 * @param addr Pointer to the 6-byte Ethernet address.
 * @return Resolved name or formatted MAC string:
 * "<vendor>_%02x:%02x:%02x" if the vendor code is known else
 * "%02x:%02x:%02x:%02x:%02x:%02x".
 */
WS_DLL_PUBLIC const char *get_ether_name(const uint8_t *addr);

/**
 * @brief Resolves an SS7 Point Code to a hostname.
 *
 * Returns a logical name if found, or a formatted Point Code string.
 *
 * @param ni Network Indicator.
 * @param pc Point Code.
 * @return Hostname if in the ss7pcs file or '\0' on the first call or the
 * unresolved Point Code in the subsequent calls.
 */
const char *get_hostname_ss7pc(const uint8_t ni, const uint32_t pc);

/**
 * @brief Initializes unresolved SS7 Point Code entries in the hashtable.
 *
 * Adds a placeholder entry for an unresolved SS7 Point Code.
 *
 * @param pc_addr String representation of the Point Code.
 * @param ni Network Indicator.
 * @param pc Point Code.
 */
void fill_unresolved_ss7pc(const char * pc_addr, const uint8_t ni, const uint32_t pc);

/**
 * @brief Resolves an Ethernet address from a tvbuff.
 *
 * Returns a logical name or vendor string for the Ethernet address at the given offset.
 *
 * @note This is the same as get_ether_name with tvb support
 *
 * @param tvb Pointer to the tvbuff.
 * @param offset Offset of the Ethernet address.
 * @return Resolved name or formatted MAC string.
 */
WS_DLL_PUBLIC const char *tvb_get_ether_name(tvbuff_t *tvb, int offset);

/**
 * @brief Resolves an Ethernet address only if an exact match is known.
 *
 * Returns a logical name if the full address is known from the ethers
 * file or ARP, otherwise returns NULL.
 *
 * @note: It returns NULL for addresses if only a prefix can be resolved
 * into a manufacturer name.
 *
 * @param addr Pointer to the 6-byte Ethernet address.
 * @return Resolved name or NULL.
 */
const char *get_ether_name_if_known(const uint8_t *addr);

/**
 * @brief Resolves a 3-octet OUI to a short vendor name.
 *
 * Given a sequence of 3 octets containing an OID, get_manuf_name()
 * returns an abbreviated form of the vendor name, or "%02x:%02x:%02x"
 * if not known. (The short form of the name is roughly similar in length
 * to the hexstring, so that they may be used in similar places.)
 * @note: This only looks up entries in the 24-bit OUI table (and the
 * CID table), not the MA-M and MA-S tables. The hex byte string is
 * returned for sequences registered to the IEEE Registration Authority
 * for the purposes of being subdivided into MA-M and MA-S.
 *
 * @param addr Pointer to the OUI bytes.
 * @param size Number of bytes (typically 3).
 * @return Short vendor name or hex string.
 */
extern const char *get_manuf_name(const uint8_t *addr, size_t size);

/**
 * @brief Resolves an OUI to a full vendor name if known.
 *
 * Given a sequence of 3 or more octets containing an OUI,
 * get_manuf_name_if_known() returns the vendor name, or NULL if not known.
 * @note Unlike get_manuf_name() above, this returns the full vendor name.
 * @note If size is 6 or larger, vendor names will be looked up in the MA-M
 * and MA-S tables as well (but note that the length of the sequence is
 * not returned.) If size is less than 6, only the 24 bit tables are searched,
 * and NULL is returned for sequences registered to the IEEE Registration
 * Authority for purposes of being subdivided into MA-M and MA-S.
 *
 * @param addr Pointer to the OUI bytes.
 * @param size Number of bytes (≥3).
 * @return Full vendor name or NULL.
 */
WS_DLL_PUBLIC const char *get_manuf_name_if_known(const uint8_t *addr, size_t size);

/**
 * @brief Resolves a 24-bit OUI integer to a vendor name.
 *
 * Given an integer containing a 24-bit OUI (or CID),
 * uint_get_manuf_name_if_known() returns the vendor name, or NULL if not known.
 * @note NULL is returned for sequences registered to the IEEE Registration
 * Authority for purposes of being subdivided into MA-M and MA-S.
 *
 * @param oid 24-bit OUI or CID.
 * @return Full vendor name or NULL.
 */
extern const char *uint_get_manuf_name_if_known(const uint32_t oid);

/**
 * @brief Resolves a 3-octet OUI from a tvbuff to a short vendor name.
 *
 * Given a tvbuff and an offset in that tvbuff for a 3-octet OID,
 * tvb_get_manuf_name() returns an abbreviated vendor name, or "%02x:%02x:%02x"
 * if not known.
 * @note: This only looks up entries in the 24-bit OUI table (and the
 * CID table), not the MA-M and MA-S tables. The hex byte string is
 * returned for sequences registered to the IEEE Registration Authority
 * for the purposes of being subdivided into MA-M and MA-S.
 *
 * @param tvb Pointer to the tvbuff.
 * @param offset Offset of the OUI.
 * @return Short vendor name or hex string.
 */
WS_DLL_PUBLIC const char *tvb_get_manuf_name(tvbuff_t *tvb, int offset);

/**
 * @brief Resolves a 3-octet OUI from a tvbuff to a full vendor name.
 *
 * Given a tvbuff and an offset in that tvbuff for a 3-octet OID,
 * tvb_get_manuf_name_if_known() returns the full vendor name, or NULL
 * if not known.
 * @note NULL is returned for sequences registered to the IEEE Registration
 * Authority for purposes of being subdivided into MA-M and MA-S.
 *
 * @param tvb Pointer to the tvbuff.
 * @param offset Offset of the OUI.
 * @return Full vendor name or NULL.
 */
WS_DLL_PUBLIC const char *tvb_get_manuf_name_if_known(tvbuff_t *tvb, int offset);

/**
 * @brief Resolves an EUI-64 address to a logical name or vendor string.
 *
 * Returns a logical name, vendor-prefixed string, or full EUI-64 hex string.
 * get_eui64_name returns the logical name if found in ethers files else
 * "<vendor>_%02x:%02x:%02x:%02x:%02x:%02x" if the vendor code is known
 * (or as appropriate for MA-M and MA-S), and if not,
 * "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x"
 *
 * @param addr Pointer to the 8-byte EUI-64 address.
 * @return Resolved name or formatted EUI-64 string.
 */
extern const char *get_eui64_name(const uint8_t *addr);

/**
 * @brief Converts a uint64_t EUI-64 address to a display string.
 *
 * Returns a vendor-prefixed or full hex string using the given allocator.
 *
 * eui64_to_display returns "<vendor>_%02x:%02x:%02x:%02x:%02x:%02x" if the
 * vendor code is known (or as appropriate for MA-M and MA-S), and if not,
 * "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x". Gives the same results
 * as address_to_display, but for when the EUI-64 address is a host endian
 * uint64_t instead of bytes / an AT_EUI64 address.
 *
 * @param allocator Memory allocator scope.
 * @param addr EUI-64 address as uint64_t.
 * @return Allocated display string.
 */
extern char *eui64_to_display(wmem_allocator_t *allocator, const uint64_t addr);

/**
 * @brief Resolves an IPX network number to a name.
 *
 * Returns a logical name or formatted hex string.
 *
 * get_ipxnet_name returns the logical name if found in an ipxnets file,
 * or a string formatted with "%X" if not.
 *
 * @param allocator Memory allocator scope.
 * @param addr IPX network number.
 * @return Allocated name or hex string.
 */
extern char *get_ipxnet_name(wmem_allocator_t *allocator, const uint32_t addr);

/**
 * @brief Resolves a VLAN ID to a name.
 *
 * Returns a logical name or the VLAN ID as a string.
 *
 * get_vlan_name returns the logical name if found in a vlans file,
 * or the VLAN ID itself as a string if not found
 *
 * @param allocator Memory allocator scope.
 * @param id VLAN identifier.
 * @return Allocated name or ID string.
 */
extern char *get_vlan_name(wmem_allocator_t *allocator, const uint16_t id);

/**
 * @brief Gets the status code for a resolved Ethernet entry.
 *
 * @param ether Pointer to the Ethernet hash entry.
 * @return Status code.
 */
WS_DLL_PUBLIC unsigned get_hash_ether_status(hashether_t* ether);

/**
 * @brief Checks if an Ethernet hash entry was used.
 *
 * @param ether Pointer to the Ethernet hash entry.
 * @return true if used, false otherwise.
 */
WS_DLL_PUBLIC bool get_hash_ether_used(hashether_t* ether);

/**
 * @brief Gets the hex string representation of an Ethernet address.
 *
 * @param ether Pointer to the Ethernet hash entry.
 * @return Hex string of the address.
 */
WS_DLL_PUBLIC char* get_hash_ether_hexaddr(hashether_t* ether);

/**
 * @brief Gets the resolved name for an Ethernet hash entry.
 *
 * @param ether Pointer to the Ethernet hash entry.
 * @return Resolved name string.
 */
WS_DLL_PUBLIC char* get_hash_ether_resolved_name(hashether_t* ether);

/**
 * @brief Checks if a manufacturer hash entry was used.
 *
 * @param manuf Pointer to the manufacturer hash entry.
 * @return true if used, false otherwise.
 */
WS_DLL_PUBLIC bool get_hash_manuf_used(hashmanuf_t* manuf);

/**
 * @brief Gets the resolved name for a manufacturer hash entry.
 *
 * @param manuf Pointer to the manufacturer hash entry.
 * @return Resolved name string.
 */
WS_DLL_PUBLIC char* get_hash_manuf_resolved_name(hashmanuf_t* manuf);

/**
 * @brief Checks if a WKA hash entry was used.
 *
 * @param wka Pointer to the WKA hash entry.
 * @return true if used, false otherwise.
 */
WS_DLL_PUBLIC bool get_hash_wka_used(hashwka_t* wka);

/**
 * @brief Gets the resolved name for a WKA hash entry.
 *
 * @param wka Pointer to the WKA hash entry.
 * @return Resolved name string.
 */
WS_DLL_PUBLIC char* get_hash_wka_resolved_name(hashwka_t* wka);

/**
 * @brief Adds a static or dynamic IPv4 name mapping.
 *
 * Inserts a hostname for the given IPv4 address into the resolution table.
 *
 * @param addr IPv4 address in host byte order.
 * @param name Hostname to associate.
 * @param static_entry true if the entry is static.
 */
WS_DLL_PUBLIC void add_ipv4_name(const unsigned addr, const char *name, const bool static_entry);

/**
 * @brief Adds a Hostname/IPv4 in the hash table.
 *
 * Inserts a hostname for the given IPv6 address into the resolution table.
 *
 * @param addr Pointer to the IPv6 address.
 * @param name Hostname to associate.
 * @param static_entry true if the entry is static.
 */
WS_DLL_PUBLIC void add_ipv6_name(const ws_in6_addr *addr, const char *name, const bool static_entry);

/**
 * @brief Adds an additional "hosts" file for IPv4 and IPv6 name resolution.
 *
 * Registers a user-specified hosts file to be used for resolving IP addresses.
 * The file can be added before `host_name_lookup_init()` is called and will be
 * re-read each time that function is invoked.
 *
 * @param hosts_file Absolute path to the hosts file.
 * @return true if the file was successfully read, false otherwise.
 */
WS_DLL_PUBLIC bool add_hosts_file(const char *hosts_file);

/**
 * @brief Adds a hostname mapping for a given IP address string.
 *
 * Inserts a user-defined name for an IP address into the resolution table.
 * The address string may represent either an IPv4 or IPv6 address.
 *
 * @param addr IP address string (e.g., "192.168.0.1" or "2001:db8::1").
 * @param name Hostname to associate with the address.
 * @return true if the entry was successfully added, false otherwise.
 */
WS_DLL_PUBLIC bool add_ip_name_from_string(const char *addr, const char *name);

/**
 * @brief Retrieves the user-defined name for a given address.
 *
 * Returns a pointer to a `resolved_name_t` structure containing the custom name
 * associated with the given address, if one exists.
 *
 * @param addr IP address string.
 * @return Pointer to the resolved name structure, or NULL if not found.
 */
WS_DLL_PUBLIC resolved_name_t* get_edited_resolved_name(const char* addr);

/**
 * @brief Retrieves known host-to-address mappings.
 *
 * Returns a structure containing two GLists: one with `hashipv4_t` entries
 * for IPv4 mappings and one with `hashipv6_t` entries for IPv6 mappings.
 *
 * @return Pointer to an `addrinfo_lists_t` structure, or NULL if no mappings are available.
 */
WS_DLL_PUBLIC addrinfo_lists_t *get_addrinfo_list(void);

/**
 * @brief Associates an Ethernet (MAC) address / name to an IPv4 address.
 *
 * Adds a mapping between the given IPv4 address and its corresponding Ethernet address.
 * Used for name resolution and display purposes.
 *
 * @param ip IPv4 address in host byte order.
 * @param eth Pointer to a 6-byte Ethernet address.
 */
extern void add_ether_byip(const unsigned ip, const uint8_t *eth);

/**
 * @brief Resolves a hostname or IPv4 string to a numeric IPv4 address.
 *
 * Translates a string representing a hostname or dotted-decimal IPv4 address
 * into a numeric IPv4 address value in network byte order. If compiled with
 * c-ares, the request will wait a maximum of 250ms for the request to finish.
 * Otherwise the wait time will be system-dependent, usually much longer.
 * Immediately returns false for hostnames if network name resolution is
 * disabled.
 *
 * @param[in] host The hostname or IPv4 string to resolve.
 * @param[out] addrp Pointer to receive the resolved IPv4 address in network byte order.
 * @return true on success, false on failure or timeout.
 */
WS_DLL_PUBLIC
bool get_host_ipaddr(const char *host, uint32_t *addrp);

/**
 * @brief Resolves a hostname or IPv6 string to a numeric IPv6 address.
 *
 * Translates a string representing a hostname or colon-hex IPv6 address
 * into a numeric IPv6 address value in network byte order. If compiled with
 * c-ares, the request will wait a maximum of 250ms for the request to finish.
 * Otherwise the wait time will be system-dependent, usually much longer.
 * Immediately returns false for hostnames if network name resolution is
 * disabled.
 *
 * @param[in] host The hostname or IPv6 string to resolve.
 * @param[out] addrp Pointer to receive the resolved IPv6 address in network byte order.
 * @return true on success, false on failure or timeout.
 */
WS_DLL_PUBLIC
bool get_host_ipaddr6(const char *host, ws_in6_addr *addrp);

/**
 * @brief Retrieves the manufacturer hashtable.
 *
 * Returns a pointer to the hashtable mapping MAC address prefixes to manufacturer names.
 *
 * @return Pointer to the manufacturer hashtable.
 */
WS_DLL_PUBLIC
wmem_map_t *get_manuf_hashtable(void);

/**
 * @brief Retrieves the well-known address (WKA) hashtable.
 *
 * Returns a pointer to the hashtable mapping protocol-specific well-known addresses to names.
 *
 * @return Pointer to the WKA hashtable.
 */
WS_DLL_PUBLIC
wmem_map_t *get_wka_hashtable(void);

/**
 * @brief Retrieves the Ethernet address hashtable.
 *
 * Returns a pointer to the hashtable mapping full Ethernet (MAC) addresses to resolved names.
 *
 * @return Pointer to the Ethernet address hashtable.
 */
WS_DLL_PUBLIC
wmem_map_t *get_eth_hashtable(void);

/**
 * @brief Retrieves the service port hashtable.
 *
 * Returns a pointer to the hashtable mapping TCP/UDP port numbers to service names.
 *
 * @return Pointer to the service port hashtable.
 */
WS_DLL_PUBLIC
wmem_map_t *get_serv_port_hashtable(void);

/**
 * @brief Retrieves the IPX network hashtable.
 *
 * Returns a pointer to the hashtable mapping IPX network numbers to resolved names.
 *
 * @return Pointer to the IPX network hashtable.
 */
WS_DLL_PUBLIC
wmem_map_t *get_ipxnet_hash_table(void);

/**
 * @brief Retrieves the VLAN ID hashtable.
 *
 * Returns a pointer to the hashtable mapping VLAN identifiers to resolved names.
 *
 * @return Pointer to the VLAN hashtable.
 */
WS_DLL_PUBLIC
wmem_map_t *get_vlan_hash_table(void);

/**
 * @brief Retrieves the IPv4 address hashtable.
 *
 * Returns a pointer to the hashtable mapping IPv4 addresses to resolved hostnames.
 *
 * @return Pointer to the IPv4 address hashtable.
 */
WS_DLL_PUBLIC
wmem_map_t *get_ipv4_hash_table(void);

/**
 * @brief Retrieves the IPv6 address hashtable.
 *
 * Returns a pointer to the hashtable mapping IPv6 addresses to resolved hostnames.
 *
 * @return Pointer to the IPv6 address hashtable.
 */
WS_DLL_PUBLIC
wmem_map_t *get_ipv6_hash_table(void);


/*
 * XXX - if we ever have per-session host name etc. information, we
 * should probably have the "resolve synchronously or asynchronously"
 * flag be per-session, set with an epan API.
 */
/**
 * @brief Sets the resolution mode to synchronous or asynchronous.
 *
 * Controls whether name/address resolution is performed synchronously or deferred.
 * Intended for global configuration; future versions may support per-session control.
 *
 * @param synchronous If true, resolution is performed synchronously.
 */
WS_DLL_PUBLIC
void set_resolution_synchrony(bool synchronous);

/*
 * private functions (should only be called by epan directly)
 */

/**
 * @brief Initializes the name resolution subsystem.
 *
 * Sets up internal state for hostname and address resolution.
 * Intended for internal use by the epan core only.
 */
WS_DLL_LOCAL
void name_resolver_init(void);

/**
 * @brief Reinitialize hostname resolution subsystem.
 *
 * Clears any cached hostname resolution results.
 * Intended for internal use by the epan core only.
 */
WS_DLL_LOCAL
void host_name_lookup_reset(void);

/**
 * @brief Initializes the address resolution subsystem.
 *
 * Prepares internal structures for resolving network addresses.
 * Intended for internal use by the epan core only.
 */
WS_DLL_LOCAL
void addr_resolv_init(void);

/**
 * @brief Cleans up the address resolution subsystem.
 *
 * Frees resources and resets state related to address resolution.
 * Intended for internal use by the epan core only.
 */
WS_DLL_LOCAL
void addr_resolv_cleanup(void);

/**
 * @brief Parses a string as an IPv4 address.
 *
 * Converts a dotted-decimal IPv4 string into a binary representation.
 *
 * @param str The input string (e.g., "192.168.0.1").
 * @param dst Pointer to a buffer to receive the parsed address (e.g., `uint32_t*`).
 * @return true if parsing succeeds, false otherwise.
 */
WS_DLL_PUBLIC
bool str_to_ip(const char *str, void *dst);

/**
 * @brief Parses a string as an IPv6 address.
 *
 * Converts a colon-separated IPv6 string into a binary representation.
 *
 * @param str The input string (e.g., "2001:db8::1").
 * @param dst Pointer to a buffer to receive the parsed address (e.g., `struct in6_addr*`).
 * @return true if parsing succeeds, false otherwise.
 */
WS_DLL_PUBLIC
bool str_to_ip6(const char *str, void *dst);

/**
 * @brief Parses a string as an Ethernet (MAC) address.
 *
 * Converts a colon- or dash-separated MAC address string into a 6-byte array.
 * Intended for internal use by the epan core only.
 *
 * @param str The input string (e.g., "00:11:22:33:44:55").
 * @param eth_bytes Pointer to a 6-byte buffer to receive the parsed address.
 * @return true if parsing succeeds, false otherwise.
 */
WS_DLL_LOCAL
bool str_to_eth(const char *str, char *eth_bytes);

/**
 * @brief Computes a hash value for an IPv6 address using OAT hashing.
 *
 * Generates a hash suitable for use in hash tables.
 * Intended for internal use by the epan core only.
 *
 * @param key Pointer to the IPv6 address (e.g., `struct in6_addr*`).
 * @return Hash value.
 */
WS_DLL_LOCAL
unsigned ipv6_oat_hash(const void *key);

/**
 * @brief Compares two IPv6 addresses for equality.
 *
 * Performs a byte-wise comparison of two IPv6 addresses.
 * Intended for internal use by the epan core only.
 *
 * @param v1 Pointer to the first IPv6 address.
 * @param v2 Pointer to the second IPv6 address.
 * @return TRUE if equal, FALSE otherwise.
 */
WS_DLL_LOCAL
gboolean ipv6_equal(const void *v1, const void *v2);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __RESOLV_H__ */

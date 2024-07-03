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
#define MAXNAMELEN  	64	/* max name length (hostname and port name) */
#endif

#ifndef MAXVLANNAMELEN
#define MAXVLANNAMELEN  	128	/* max vlan name length */
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
    (((at)->type == AT_ETHER))

#define ADDR_RESOLV_NETADDR(at) \
    (((at)->type == AT_IPv4) || ((at)->type == AT_IPv6) || ((at)->type == AT_IPX))

struct hashether;
typedef struct hashether hashether_t;

struct hashwka;
typedef struct hashwka hashwka_t;

struct hashmanuf;
typedef struct hashmanuf hashmanuf_t;

typedef struct serv_port {
  const char       *udp_name;
  const char       *tcp_name;
  const char       *sctp_name;
  const char       *dccp_name;
  const char       *numeric;
} serv_port_t;

typedef struct _resolved_name {
    char             name[MAXNAMELEN];
} resolved_name_t;

/*
 * Flags for various resolved name hash table entries.
 */
#define TRIED_RESOLVE_ADDRESS    (1U<<0)  /* XXX - what does this bit *really* mean? */
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

/*
 * returns an ipv4 object built from its address
 */
WS_DLL_PUBLIC hashipv4_t * new_ipv4(const unsigned addr);

/*
 * returns a 'dummy ip4' object built from an address
 */
WS_DLL_PUBLIC bool fill_dummy_ip4(const unsigned addr, hashipv4_t* volatile tp);

/*
 * udp_port_to_display() returns the port name corresponding to that UDP port,
 * or the port number as a string if not found.
 */
WS_DLL_PUBLIC char *udp_port_to_display(wmem_allocator_t *allocator, unsigned port);

/*
 * tcp_port_to_display() returns the port name corresponding to that TCP port,
 * or the port number as a string if not found.
 */
WS_DLL_PUBLIC char *tcp_port_to_display(wmem_allocator_t *allocator, unsigned port);

/*
 * dccp_port_to_display() returns the port name corresponding to that DCCP port,
 * or the port number as a string if not found.
 */
extern char *dccp_port_to_display(wmem_allocator_t *allocator, unsigned port);

/*
 * sctp_port_to_display() returns the port name corresponding to that SCTP port,
 * or the port number as a string if not found.
 */
WS_DLL_PUBLIC char *sctp_port_to_display(wmem_allocator_t *allocator, unsigned port);

/*
 * serv_name_lookup() returns the well known service name string, or numeric
 * representation if one doesn't exist.
 */
WS_DLL_PUBLIC const char *serv_name_lookup(port_type proto, unsigned port);

/*
 * enterprises_lookup() returns the private enterprise code string, or 'unknown_str'
 * if one doesn't exist, or "<Unknown>" if that is NULL.
 */
WS_DLL_PUBLIC const char *enterprises_lookup(uint32_t value, const char *unknown_str);

/*
 * try_enterprises_lookup() returns the private enterprise code string, or NULL if not found.
 */
WS_DLL_PUBLIC const char *try_enterprises_lookup(uint32_t value);

/*
 * enterprises_base_custom() prints the "name (decimal)" string to 'buf'.
 * (Used with BASE_CUSTOM field display).
 */
WS_DLL_PUBLIC void enterprises_base_custom(char *buf, uint32_t value);

/*
 * try_serv_name_lookup() returns the well known service name string, or NULL if
 * one doesn't exist.
 */
WS_DLL_PUBLIC const char *try_serv_name_lookup(port_type proto, unsigned port);

/*
 * port_with_resolution_to_str() prints the "<resolved> (<numerical>)" port
 * string.
 */
WS_DLL_PUBLIC char *port_with_resolution_to_str(wmem_allocator_t *scope,
                                        port_type proto, unsigned port);

/*
 * port_with_resolution_to_str_buf() prints the "<resolved> (<numerical>)" port
 * string to 'buf'. Return value is the same as snprintf().
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

/*
 * disable_name_resolution() sets all relevant gbl_resolv_flags to false.
 */
WS_DLL_PUBLIC void disable_name_resolution(void);

/** If we're using c-ares process outstanding host name lookups.
 *  This is called from a GLIB timeout in Wireshark and before processing
 *  each packet in the first pass of two-pass TShark.
 *
 * @return True if any new objects have been resolved since the previous
 * call. This can be used to trigger a display update, e.g. in Wireshark.
 */
WS_DLL_PUBLIC bool host_name_lookup_process(void);

/* get_hostname returns the host name or "%d.%d.%d.%d" if not found */
WS_DLL_PUBLIC const char *get_hostname(const unsigned addr);

/* get_hostname6 returns the host name, or numeric addr if not found */
WS_DLL_PUBLIC const char *get_hostname6(const ws_in6_addr *ad);

/* get_ether_name returns the logical name if found in ethers files else
   "<vendor>_%02x:%02x:%02x" if the vendor code is known else
   "%02x:%02x:%02x:%02x:%02x:%02x" */
WS_DLL_PUBLIC const char *get_ether_name(const uint8_t *addr);

/* get_hostname_ss7pc returns the logical name if found in ss7pcs file else
   '\0' on the first call or the unresolved Point Code in the subsequent calls */
const char *get_hostname_ss7pc(const uint8_t ni, const uint32_t pc);

/* fill_unresolved_ss7pc initializes the unresolved Point Code Address string in the hashtable */
void fill_unresolved_ss7pc(const char * pc_addr, const uint8_t ni, const uint32_t pc);


/* Same as get_ether_name with tvb support */
WS_DLL_PUBLIC const char *tvb_get_ether_name(tvbuff_t *tvb, int offset);

/* get_ether_name_if_known returns the logical name if an exact match is
 * found (in ethers files or from ARP) else NULL.
 * @note: It returns NULL for addresses if only a prefix can be resolved
 * into a manufacturer name.
 */
const char *get_ether_name_if_known(const uint8_t *addr);

/*
 * Given a sequence of 3 octets containing an OID, get_manuf_name()
 * returns an abbreviated form of the vendor name, or "%02x:%02x:%02x"
 * if not known. (The short form of the name is roughly similar in length
 * to the hexstring, so that they may be used in similar places.)
 * @note: This only looks up entries in the 24-bit OUI table (and the
 * CID table), not the MA-M and MA-S tables. The hex byte string is
 * returned for sequences registered to the IEEE Registration Authority
 * for the purposes of being subdivided into MA-M and MA-S.
 */
extern const char *get_manuf_name(const uint8_t *addr, size_t size);

/*
 * Given a sequence of 3 or more octets containing an OUI,
 * get_manuf_name_if_known() returns the vendor name, or NULL if not known.
 * @note Unlike get_manuf_name() above, this returns the full vendor name.
 * @note If size is 6 or larger, vendor names will be looked up in the MA-M
 * and MA-S tables as well (but note that the length of the sequence is
 * not returned.) If size is less than 6, only the 24 bit tables are searched,
 * and NULL is returned for sequences registered to the IEEE Registration
 * Authority for purposes of being subdivided into MA-M and MA-S.
 */
WS_DLL_PUBLIC const char *get_manuf_name_if_known(const uint8_t *addr, size_t size);

/*
 * Given an integer containing a 24-bit OUI (or CID),
 * uint_get_manuf_name_if_known() returns the vendor name, or NULL if not known.
 * @note NULL is returned for sequences registered to the IEEE Registration
 * Authority for purposes of being subdivided into MA-M and MA-S.
 */
extern const char *uint_get_manuf_name_if_known(const uint32_t oid);

/*
 * Given a tvbuff and an offset in that tvbuff for a 3-octet OID,
 * tvb_get_manuf_name() returns an abbreviated vendor name, or "%02x:%02x:%02x"
 * if not known.
 * @note: This only looks up entries in the 24-bit OUI table (and the
 * CID table), not the MA-M and MA-S tables. The hex byte string is
 * returned for sequences registered to the IEEE Registration Authority
 * for the purposes of being subdivided into MA-M and MA-S.
 */
WS_DLL_PUBLIC const char *tvb_get_manuf_name(tvbuff_t *tvb, int offset);

/*
 * Given a tvbuff and an offset in that tvbuff for a 3-octet OID,
 * tvb_get_manuf_name_if_known() returns the full vendor name, or NULL
 * if not known.
 * @note NULL is returned for sequences registered to the IEEE Registration
 * Authority for purposes of being subdivided into MA-M and MA-S.
 */
WS_DLL_PUBLIC const char *tvb_get_manuf_name_if_known(tvbuff_t *tvb, int offset);

/* eui64_to_display returns "<vendor>_%02x:%02x:%02x:%02x:%02x:%02x" if the
 * vendor code is known (or as appropriate for MA-M and MA-S), and if not,
 * "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x"
*/
extern char *eui64_to_display(wmem_allocator_t *allocator, const uint64_t addr);

/* get_ipxnet_name returns the logical name if found in an ipxnets file,
 * or a string formatted with "%X" if not */
extern char *get_ipxnet_name(wmem_allocator_t *allocator, const uint32_t addr);

/* get_vlan_name returns the logical name if found in a vlans file,
 * or the VLAN ID itself as a string if not found*/
extern char *get_vlan_name(wmem_allocator_t *allocator, const uint16_t id);

WS_DLL_PUBLIC unsigned get_hash_ether_status(hashether_t* ether);
WS_DLL_PUBLIC bool get_hash_ether_used(hashether_t* ether);
WS_DLL_PUBLIC char* get_hash_ether_hexaddr(hashether_t* ether);
WS_DLL_PUBLIC char* get_hash_ether_resolved_name(hashether_t* ether);

WS_DLL_PUBLIC bool get_hash_manuf_used(hashmanuf_t* manuf);
WS_DLL_PUBLIC char* get_hash_manuf_resolved_name(hashmanuf_t* manuf);

WS_DLL_PUBLIC bool get_hash_wka_used(hashwka_t* wka);
WS_DLL_PUBLIC char* get_hash_wka_resolved_name(hashwka_t* wka);

/* adds a hostname/IPv4 in the hash table */
WS_DLL_PUBLIC void add_ipv4_name(const unsigned addr, const char *name, const bool static_entry);

/* adds a hostname/IPv6 in the hash table */
WS_DLL_PUBLIC void add_ipv6_name(const ws_in6_addr *addr, const char *name, const bool static_entry);

/** Add an additional "hosts" file for IPv4 and IPv6 name resolution.
 *
 * The file can be added before host_name_lookup_init() is called and
 * will be re-read each time host_name_lookup_init() is called.
 *
 * @param hosts_file Absolute path to the hosts file.
 *
 * @return true if the hosts file can be read.
 */
WS_DLL_PUBLIC bool add_hosts_file (const char *hosts_file);

/* adds a hostname in the hash table */
WS_DLL_PUBLIC bool add_ip_name_from_string (const char *addr, const char *name);

/* Get the user defined name, for a given address */
WS_DLL_PUBLIC resolved_name_t* get_edited_resolved_name(const char* addr);


/** Get lists of host name to address mappings we know about.
 *
 * The struct contains two g_lists one with hashipv4_t entries and one with hashipv6_t entries.
 *
 * @return a struct with lists of known addresses(IPv4 and IPv6). May be NULL.
 */
WS_DLL_PUBLIC addrinfo_lists_t *get_addrinfo_list(void);

/* add ethernet address / name corresponding to IP address  */
extern void add_ether_byip(const unsigned ip, const uint8_t *eth);

/** Translates a string representing a hostname or dotted-decimal IPv4 address
 *  into a numeric IPv4 address value in network byte order. If compiled with
 *  c-ares, the request will wait a maximum of 250ms for the request to finish.
 *  Otherwise the wait time will be system-dependent, usually much longer.
 *  Immediately returns false for hostnames if network name resolution is
 *  disabled.
 *
 * @param[in] host The hostname.
 * @param[out] addrp The numeric IPv4 address in network byte order.
 * @return true on success, false on failure, timeout.
 */
WS_DLL_PUBLIC
bool get_host_ipaddr(const char *host, uint32_t *addrp);

/** Translates a string representing a hostname or colon-hex IPv6 address
 *  into a numeric IPv6 address value in network byte order. If compiled with
 *  c-ares, the request will wait a maximum of 250ms for the request to finish.
 *  Otherwise the wait time will be system-dependent, usually much longer.
 *  Immediately returns false for hostnames if network name resolution is
 *  disabled.
 *
 * @param[in] host The hostname.
 * @param[out] addrp The numeric IPv6 address in network byte order.
 * @return true on success, false on failure or timeout.
 */
WS_DLL_PUBLIC
bool get_host_ipaddr6(const char *host, ws_in6_addr *addrp);

WS_DLL_PUBLIC
wmem_map_t *get_manuf_hashtable(void);

WS_DLL_PUBLIC
wmem_map_t *get_wka_hashtable(void);

WS_DLL_PUBLIC
wmem_map_t *get_eth_hashtable(void);

WS_DLL_PUBLIC
wmem_map_t *get_serv_port_hashtable(void);

WS_DLL_PUBLIC
wmem_map_t *get_ipxnet_hash_table(void);

WS_DLL_PUBLIC
wmem_map_t *get_vlan_hash_table(void);

WS_DLL_PUBLIC
wmem_map_t *get_ipv4_hash_table(void);

WS_DLL_PUBLIC
wmem_map_t *get_ipv6_hash_table(void);

/*
 * XXX - if we ever have per-session host name etc. information, we
 * should probably have the "resolve synchronously or asynchronously"
 * flag be per-session, set with an epan API.
 */
WS_DLL_PUBLIC
void set_resolution_synchrony(bool synchronous);

/*
 * private functions (should only be called by epan directly)
 */

WS_DLL_LOCAL
void name_resolver_init(void);

/* Reinitialize hostname resolution subsystem */
WS_DLL_LOCAL
void host_name_lookup_reset(void);

WS_DLL_LOCAL
void addr_resolv_init(void);

WS_DLL_LOCAL
void addr_resolv_cleanup(void);

WS_DLL_PUBLIC
bool str_to_ip(const char *str, void *dst);

WS_DLL_PUBLIC
bool str_to_ip6(const char *str, void *dst);

WS_DLL_LOCAL
bool str_to_eth(const char *str, char *eth_bytes);

WS_DLL_LOCAL
unsigned ipv6_oat_hash(const void *key);

WS_DLL_LOCAL
gboolean ipv6_equal(const void *v1, const void *v2);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __RESOLV_H__ */

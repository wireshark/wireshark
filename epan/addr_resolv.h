/* addr_resolv.h
 * Definitions for network object lookup
 *
 * Laurent Deniel <laurent.deniel@free.fr>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/* The buffers returned by these functions are all allocated with a
 * packet lifetime and does not have have to be freed.
 * However, take into account that when the packet dissection
 * completes, these buffers will be automatically reclaimed/freed.
 * If you need the buffer to remain for a longer scope than packet lifetime
 * you must copy the content to an se_alloc() buffer.
 */

#ifndef __RESOLV_H__
#define __RESOLV_H__

#include <epan/address.h>
#include <epan/tvbuff.h>
#include <epan/ipv6-utils.h>
#include <epan/to_str.h>
#include <wiretap/wtap.h>
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef MAXNAMELEN
#define MAXNAMELEN  	64	/* max name length (hostname and port name) */
#endif

typedef struct _e_addr_resolve {
  gboolean mac_name;
  gboolean network_name;
  gboolean transport_name;
  gboolean concurrent_dns;
  gboolean use_external_net_name_resolver;
  gboolean load_hosts_file_from_profile_only;
} e_addr_resolve;


typedef struct hashether {
  guint             status;  /* (See above) */
  guint8            addr[6];
  char              hexaddr[6*3];
  char              resolved_name[MAXNAMELEN];
} hashether_t;

typedef struct serv_port {
  gchar            *udp_name;
  gchar            *tcp_name;
  gchar            *sctp_name;
  gchar            *dccp_name;
} serv_port_t;

/*
 *
 */
#define DUMMY_ADDRESS_ENTRY      1<<0
#define TRIED_RESOLVE_ADDRESS    1<<1
#define RESOLVED_ADDRESS_USED    1<<2

#define DUMMY_AND_RESOLVE_FLGS   3
#define USED_AND_RESOLVED_MASK   (1+4)
typedef struct hashipv4 {
    guint             addr;
    guint8            flags;          /* B0 dummy_entry, B1 resolve, B2 If the address is used in the trace */
    gchar             ip[16];
    gchar             name[MAXNAMELEN];
} hashipv4_t;


typedef struct hashipv6 {
    struct e_in6_addr addr;
    guint8            flags;          /* B0 dummy_entry, B1 resolve, B2 If the address is used in the trace */
    gchar             ip6[MAX_IP6_STR_LEN]; /* XX */
    gchar             name[MAXNAMELEN];
} hashipv6_t;
/*
 * Flag controlling what names to resolve.
 */
WS_DLL_PUBLIC e_addr_resolve gbl_resolv_flags;

/* global variables */

extern gchar *g_ethers_path;
extern gchar *g_ipxnets_path;
extern gchar *g_pethers_path;
extern gchar *g_pipxnets_path;

/* Functions in addr_resolv.c */

/*
 * ep_udp_port_to_display() returns the port name corresponding to that UDP port,
 * or the port number as a string if not found.
 */
WS_DLL_PUBLIC gchar *ep_udp_port_to_display(guint port);

/*
 * ep_tcp_port_to_display() returns the port name corresponding to that TCP port,
 * or the port number as a string if not found.
 */
WS_DLL_PUBLIC gchar *ep_tcp_port_to_display(guint port);

/*
 * ep_dccp_port_to_display() returns the port name corresponding to that DCCP port,
 * or the port number as a string if not found.
 */
extern gchar *ep_dccp_port_to_display(guint port);

/*
 * ep_sctp_port_to_display() returns the port name corresponding to that SCTP port,
 * or the port number as a string if not found.
 */
WS_DLL_PUBLIC gchar *ep_sctp_port_to_display(guint port);

/* ep_address_to_display takes as input an "address", as defined in address.h */
/* it returns a string that contains: */
/*  - if the address is of a type that can be translated into a name, and the user */
/*    has activated name resolution, the translated name */
/*  - if the address is of type AT_NONE, a pointer to the string "NONE" */
/*  - if the address is of any other type, the result of ep_address_to_str on the argument, */
/*    which should be a string representation for the answer -e.g. "10.10.10.10" for IPv4 */
/*    address 10.10.10.10 */

WS_DLL_PUBLIC
const gchar *ep_address_to_display(const address *addr);

/* get_addr_name_buf solves an address in the same way as ep_address_to_display above */
/* The difference is that get_addr_name_buf takes as input a buffer, into which it puts */
/* the result which is always NUL ('\0') terminated. The buffer should be large enough to */
/* contain size characters including the terminator */

void get_addr_name_buf(const address *addr, gchar *buf, gsize size);

const gchar *get_addr_name(const address *addr);

/*
 * Asynchronous host name lookup initialization, processing, and cleanup
 */

/* Setup name resolution preferences */
struct pref_module;
extern void addr_resolve_pref_init(struct pref_module *nameres);

/** If we're using c-ares or ADNS, process outstanding host name lookups.
 *  This is called from a GLIB timeout in Wireshark and before processing
 *  each packet in TShark.
 *
 * @return True if any new objects have been resolved since the previous
 * call. This can be used to trigger a display update, e.g. in Wireshark.
 */
WS_DLL_PUBLIC gboolean host_name_lookup_process(void);

/* get_hostname returns the host name or "%d.%d.%d.%d" if not found */
WS_DLL_PUBLIC const gchar *get_hostname(const guint addr);

/* get_hostname6 returns the host name, or numeric addr if not found */
struct e_in6_addr;
WS_DLL_PUBLIC const gchar* get_hostname6(const struct e_in6_addr *ad);

/* get_ether_name returns the logical name if found in ethers files else
   "<vendor>_%02x:%02x:%02x" if the vendor code is known else
   "%02x:%02x:%02x:%02x:%02x:%02x" */
WS_DLL_PUBLIC gchar *get_ether_name(const guint8 *addr);

/* get_ether_name returns the logical name if found in ethers files else NULL */
gchar *get_ether_name_if_known(const guint8 *addr);

/*
 * Given a sequence of 3 octets containing an OID, get_manuf_name()
 * returns the vendor name, or "%02x:%02x:%02x" if not known.
 */
extern const gchar *get_manuf_name(const guint8 *addr);

/*
 * Given a sequence of 3 octets containing an OID, get_manuf_name_if_known()
 * returns the vendor name, or NULL if not known.
 */
WS_DLL_PUBLIC const gchar *get_manuf_name_if_known(const guint8 *addr);

/*
 * Given an integer containing a 24-bit OID, uint_get_manuf_name()
 * returns the vendor name, or "%02x:%02x:%02x" if not known.
 */
extern const gchar *uint_get_manuf_name(const guint oid);

/*
 * Given an integer containing a 24-bit OID, uint_get_manuf_name_if_known()
 * returns the vendor name, or NULL if not known.
 */
extern const gchar *uint_get_manuf_name_if_known(const guint oid);

/*
 * Given a tvbuff and an offset in that tvbuff for a 3-octet OID,
 * tvb_get_manuf_name() returns the vendor name, or "%02x:%02x:%02x"
 * if not known.
 */
WS_DLL_PUBLIC const gchar *tvb_get_manuf_name(tvbuff_t *tvb, gint offset);

/*
 * Given a tvbuff and an offset in that tvbuff for a 3-octet OID,
 * tvb_get_manuf_name_if_known() returns the vendor name, or NULL
 * if not known.
 */
WS_DLL_PUBLIC const gchar *tvb_get_manuf_name_if_known(tvbuff_t *tvb, gint offset);

/* ep_eui64_to_display returns "<vendor>_%02x:%02x:%02x:%02x:%02x:%02x" if the vendor code is known
   "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x" */
extern const gchar *ep_eui64_to_display(const guint64 addr);

/* ep_eui64_to_display_if_known returns "<vendor>_%02x:%02x:%02x:%02x:%02x:%02x" if the vendor code is known else NULL */
extern const gchar *ep_eui64_to_display_if_known(const guint64 addr);


/* get_ipxnet_name returns the logical name if found in an ipxnets file,
 * or a string formatted with "%X" if not */
extern const gchar *get_ipxnet_name(const guint32 addr);

/* returns the ethernet address corresponding to name or NULL if not known */
extern guint8 *get_ether_addr(const gchar *name);

/* returns the ipx network corresponding to name. If name is unknown,
 * 0 is returned and 'known' is set to FALSE. On success, 'known'
 * is set to TRUE. */
guint32 get_ipxnet_addr(const gchar *name, gboolean *known);

/* adds a hostname/IPv4 in the hash table */
WS_DLL_PUBLIC void add_ipv4_name(const guint addr, const gchar *name);

/* adds a hostname/IPv6 in the hash table */
WS_DLL_PUBLIC void add_ipv6_name(const struct e_in6_addr *addr, const gchar *name);

/** Add an additional "hosts" file for IPv4 and IPv6 name resolution.
 *
 * The file can be added before host_name_lookup_init() is called and
 * will be re-read each time host_name_lookup_init() is called.
 *
 * @param hosts_file Absolute path to the hosts file.
 *
 * @return TRUE if the hosts file can be read.
 */
WS_DLL_PUBLIC gboolean add_hosts_file (const char *hosts_file);

/* adds a hostname in the hash table */
WS_DLL_PUBLIC gboolean add_ip_name_from_string (const char *addr, const char *name);


/** Get lists of host name to address mappings we know about.
 *
 * The struct contains two g_lists one with hashipv4_t entries and one with hashipv6_t entries.
 *
 * @return a struct with lists of known addresses(IPv4 and IPv6). May be NULL.
 */
WS_DLL_PUBLIC addrinfo_lists_t *get_addrinfo_list(void);

/* add ethernet address / name corresponding to IP address  */
extern void add_ether_byip(const guint ip, const guint8 *eth);

/** Translates a string representing a hostname or dotted-decimal IPv4 address
 *  into a numeric IPv4 address value in network byte order. If compiled with
 *  c-ares, the request will wait a maximum of 250ms for the request to finish.
 *  Otherwise the wait time will be system-dependent, ususally much longer.
 *  Immediately returns FALSE for hostnames if network name resolution is
 *  disabled.
 *
 * @param[in] host The hostname.
 * @param[out] addrp The numeric IPv4 address in network byte order.
 * @return TRUE on success, FALSE on failure, timeout.
 */
WS_DLL_PUBLIC
gboolean get_host_ipaddr(const char *host, guint32 *addrp);

/** Translates a string representing a hostname or colon-hex IPv6 address
 *  into a numeric IPv6 address value in network byte order. If compiled with
 *  c-ares, the request will wait a maximum of 250ms for the request to finish.
 *  Otherwise the wait time will be system-dependent, usually much longer.
 *  Immediately returns FALSE for hostnames if network name resolution is
 *  disabled.
 *
 * @param[in] host The hostname.
 * @param[out] addrp The numeric IPv6 address in network byte order.
 * @return TRUE on success, FALSE on failure or timeout.
 */
WS_DLL_PUBLIC
gboolean get_host_ipaddr6(const char *host, struct e_in6_addr *addrp);

/*
 * Find out whether a hostname resolves to an ip or ipv6 address
 * Return "ip6" if it is IPv6, "ip" otherwise (including the case
 * that we don't know)
 */
WS_DLL_PUBLIC
const char* host_ip_af(const char *host);

WS_DLL_PUBLIC
GHashTable *get_manuf_hashtable(void);

WS_DLL_PUBLIC
GHashTable *get_wka_hashtable(void);

WS_DLL_PUBLIC
GHashTable *get_eth_hashtable(void);

WS_DLL_PUBLIC
GHashTable *get_serv_port_hashtable(void);

WS_DLL_PUBLIC
GHashTable *get_ipxnet_hash_table(void);

WS_DLL_PUBLIC
GHashTable *get_ipv4_hash_table(void);

WS_DLL_PUBLIC
GHashTable *get_ipv6_hash_table(void);

/*
 * private functions (should only be called by epan directly)
 */

WS_DLL_LOCAL
void name_resolver_init(void);

/* (Re)Initialize hostname resolution subsystem */
WS_DLL_LOCAL
void host_name_lookup_init(void);

/* Clean up only hostname resolutions (so they don't "leak" from one
 * file to the next).
 */
WS_DLL_LOCAL
void host_name_lookup_cleanup(void);

WS_DLL_LOCAL
void addr_resolv_init(void);

WS_DLL_LOCAL
void addr_resolv_cleanup(void);

WS_DLL_PUBLIC
void manually_resolve_cleanup(void);

gboolean str_to_ip(const char *str, void *dst);
gboolean str_to_ip6(const char *str, void *dst);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __RESOLV_H__ */

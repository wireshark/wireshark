/* addr_resolv.h
 * Definitions for network object lookup
 *
 * $Id$
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

/*
 * Flag controlling what names to resolve.
 */
WS_VAR_IMPORT e_addr_resolve gbl_resolv_flags;

/* global variables */

extern gchar *g_ethers_path;
extern gchar *g_ipxnets_path;
extern gchar *g_pethers_path;
extern gchar *g_pipxnets_path;

/* Functions in addr_resolv.c */

/*
 * get_udp_port() returns the port name corresponding to that UDP port,
 * or the port number as a string if not found.
 */
extern gchar *get_udp_port(guint port);

/*
 * get_tcp_port() returns the port name corresponding to that TCP port,
 * or the port number as a string if not found.
 */
extern gchar *get_tcp_port(guint port);

/*
 * get_dccp_port() returns the port name corresponding to that DCCP port,
 * or the port number as a string if not found.
 */
extern gchar *get_dccp_port(guint port);

/*
 * get_sctp_port() returns the port name corresponding to that SCTP port,
 * or the port number as a string if not found.
 */
extern gchar *get_sctp_port(guint port);

/* get_addr_name takes as input an "address", as defined in address.h */
/* it returns a string that contains: */
/*  - if the address is of a type that can be translated into a name, and the user */
/*    has activated name resolution, the translated name */
/*  - if the address is of type AT_NONE, a pointer to the string "NONE" */
/*  - if the address is of any other type, the result of ep_address_to_str on the argument, */
/*    which should be a string representation for the answer -e.g. "10.10.10.10" for IPv4 */
/*    address 10.10.10.10 */

const gchar *get_addr_name(const address *addr);
const gchar *se_get_addr_name(const address *addr);

/* get_addr_name_buf solves an address in the same way as get_addr_name above */
/* The difference is that get_addr_name_buf takes as input a buffer, into which it puts */
/* the result which is always NUL ('\0') terminated. The buffer should be large enough to */
/* contain size characters including the terminator */

void get_addr_name_buf(const address *addr, gchar *buf, gsize size);


/*
 * Asynchronous host name lookup initialization, processing, and cleanup
 */

/* Setup name resolution preferences */
struct pref_module;
extern void addr_resolve_pref_init(struct pref_module *nameres);

/* host_name_lookup_init fires up an ADNS socket if we're using ADNS */
extern void host_name_lookup_init(void);

/** If we're using c-ares or ADNS, process outstanding host name lookups.
 *  This is called from a GLIB timeout in Wireshark and before processing
 *  each packet in TShark.
 *
 * @return True if any new objects have been resolved since the previous
 * call. This can be used to trigger a display update, e.g. in Wireshark.
 */
extern gboolean host_name_lookup_process(void);

/* host_name_lookup_cleanup cleans up an ADNS socket if we're using ADNS */
extern void host_name_lookup_cleanup(void);

/* get_hostname returns the host name or "%d.%d.%d.%d" if not found */
extern const gchar *get_hostname(const guint addr);

/* get_hostname6 returns the host name, or numeric addr if not found */
struct e_in6_addr;
extern const gchar* get_hostname6(const struct e_in6_addr *ad);

/* get_ether_name returns the logical name if found in ethers files else
   "<vendor>_%02x:%02x:%02x" if the vendor code is known else
   "%02x:%02x:%02x:%02x:%02x:%02x" */
extern gchar *get_ether_name(const guint8 *addr);

/* get_ether_name returns the logical name if found in ethers files else NULL */
extern gchar *get_ether_name_if_known(const guint8 *addr);

/*
 * Given a sequence of 3 octets containing an OID, get_manuf_name()
 * returns the vendor name, or "%02x:%02x:%02x" if not known.
 */
extern const gchar *get_manuf_name(const guint8 *addr);

/*
 * Given a sequence of 3 octets containing an OID, get_manuf_name_if_known()
 * returns the vendor name, or NULL if not known.
 */
extern const gchar *get_manuf_name_if_known(const guint8 *addr);

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
extern const gchar *tvb_get_manuf_name(tvbuff_t *tvb, gint offset);

/*
 * Given a tvbuff and an offset in that tvbuff for a 3-octet OID,
 * tvb_get_manuf_name_if_known() returns the vendor name, or NULL
 * if not known.
 */
extern const gchar *tvb_get_manuf_name_if_known(tvbuff_t *tvb, gint offset);

/* get_eui64_name returns "<vendor>_%02x:%02x:%02x:%02x:%02x:%02x" if the vendor code is known
   "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x" */
extern const gchar *get_eui64_name(const guint64 addr);

/* get_eui64_name_if_known returns "<vendor>_%02x:%02x:%02x:%02x:%02x:%02x" if the vendor code is known else NULL */
extern const gchar *get_eui64_name_if_known(const guint64 addr);


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
extern void add_ipv4_name(const guint addr, const gchar *name);

/* adds a hostname/IPv6 in the hash table */
extern void add_ipv6_name(const struct e_in6_addr *addr, const gchar *name);

/** Add an additional "hosts" file for IPv4 and IPv6 name resolution.
 *
 * The file can be added before host_name_lookup_init() is called and
 * will be re-read each time host_name_lookup_init() is called.
 *
 * @param hostspath Absolute path to the hosts file.
 *
 * @return TRUE if the hosts file can be read.
 */
extern gboolean add_hosts_file (const char *hosts_file);

/* adds a hostname in the hash table */
extern gboolean add_ip_name_from_string (const char *addr, const char *name);

/** Get a list of host name to address mappings we know about.
 *
 * Each list element is an addrinfo struct with the following fields defined:
 *   - ai_family: 0, AF_INET or AF_INET6
 *   - ai_addrlen: Length of ai_addr
 *   - ai_canonname: Host name or NULL
 *   - ai_addr: Pointer to a struct sockaddr or NULL (see below)
 *   - ai_next: Next element or NULL
 * All other fields are zero-filled.
 *
 * If ai_family is 0, this is a dummy entry which should only appear at the beginning of the list.
 *
 * If ai_family is AF_INET, ai_addr points to a struct sockaddr_in with the following fields defined:
 *   - sin_family: AF_INET
 *   - sin_addr: Host IPv4 address
 * All other fields are zero-filled.
 *
 * If ai_family is AF_INET6, ai_addr points to a struct sockaddr_in6 with the following fields defined:
 *   - sin6_family: AF_INET6
 *   - sin6_addr: Host IPv6 address
 * All other fields are zero-filled.
 *
 * The list and its elements MUST NOT be modified or freed.
 *
 * @return The first element in our list of known addresses. May be NULL.
 */
extern struct addrinfo *get_addrinfo_list(void);

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
gboolean get_host_ipaddr6(const char *host, struct e_in6_addr *addrp);

/*
 * Find out whether a hostname resolves to an ip or ipv6 address
 * Return "ip6" if it is IPv6, "ip" otherwise (including the case
 * that we don't know)
 */
const char* host_ip_af(const char *host);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __RESOLV_H__ */

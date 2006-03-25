/* capture-pcap-util.h
 * Utility definitions for packet capture
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __PCAP_UTIL_H__
#define __PCAP_UTIL_H__

#ifdef HAVE_LIBPCAP

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <epan/address.h>

#include <pcap.h>

/* declaration of pcap_t here, to reduce pcap dependencies */
/*typedef struct pcap pcap_t;*/


/*
 * XXX - this is also the traditional default snapshot size in
 * tcpdump - but, if IPv6 is enabled, it defaults to 96, to get an
 * IPv6 header + TCP + 22 extra bytes.
 *
 * Some libpcap versions for particular capture devices might happen
 * to impose a minimum, but it's not always 68.
 */
#define MIN_PACKET_SIZE 68	/* minimum amount of packet data we can read */

/* XXX - this must be optimized, removing the dependency!!! */
#define CAPTURE_PCAP_ERRBUF_SIZE PCAP_ERRBUF_SIZE

/*
 * The list of interfaces returned by "get_interface_list()" is
 * a list of these structures.
 */
typedef struct {
	char	*name;          /* e.g. "eth0" */
	char	*description;   /* from OS, e.g. "Local Area Connection" or NULL */
	GSList  *ip_addr;       /* containing address values of if_addr_t */
	gboolean loopback;      /* TRUE if loopback, FALSE otherwise */
} if_info_t;

/*
 * An address in the "ip_addr" list.
 */
typedef struct {
	address_type type;      /* AT_IPv4 or AT_IPv6 */
	union {
		guint32 ip4_addr;   /*  4 byte IP V4 address, or */
		guint8 ip6_addr[16];/* 16 byte IP V6 address */
	} ip_addr;
} if_addr_t;

GList *get_interface_list(int *err, char *err_str);

/* Error values from "get_interface_list()". */
#define	CANT_GET_INTERFACE_LIST	0	/* error getting list */
#define	NO_INTERFACES_FOUND	1	/* list is empty */

void free_interface_list(GList *if_list);

/*
 * Get an error message string for a CANT_GET_INTERFACE_LIST error from
 * "get_interface_list()".
 */
gchar *cant_get_if_list_error_message(const char *err_str);

/*
 * The list of data link types returned by "get_pcap_linktype_list()" is
 * a list of these structures.
 */
typedef struct {
	int	dlt;                /* e.g. DLT_EN10MB (which is 1) */
	char	*name;          /* e.g. "EN10MB" or "DLT 1" */
	char	*description;   /* descriptive name from wiretap e.g. "Ethernet", NULL if unknown */
} data_link_info_t;

GList *get_pcap_linktype_list(const char *devname, char *err_buf);
void free_pcap_linktype_list(GList *linktype_list);

/* get/set the link type of an interface */
/* (only used in capture_loop.c / capture-pcap-util.c) */
int get_pcap_linktype(pcap_t *pch, const char *devname);
const char *set_pcap_linktype(pcap_t *pch, char *devname, int dlt);


#ifdef HAVE_PCAP_DATALINK_VAL_TO_NAME
const char *linktype_val_to_name(int dlt);
#endif
#ifdef HAVE_PCAP_DATALINK_NAME_TO_VAL
int linktype_name_to_val(const char *linktype);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HAVE_LIBPCAP */

/*
 * Append to a GString an indication of the version of libpcap/WinPcap
 * with which we were compiled, if we were, or an indication that we
 * weren't compiled with libpcap/WinPcap, if we weren't.
 */
extern void get_compiled_pcap_version(GString *str);

/*
 * Append to a GString an indication of the version of libpcap/WinPcap
 * with which we're running, or an indication that we're not running
 * with libpcap/WinPcap, if we were compiled with libpcap/WinPcap,
 * or nothing, if we weren't compiled with libpcap/WinPcap.
 */
extern void get_runtime_pcap_version(GString *str);

#endif /* __PCAP_UTIL_H__ */

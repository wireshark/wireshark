/* capture_ifinfo.h
 * Definitions for routines to get information about capture interfaces
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __CAPTURE_IFINFO_H__
#define __CAPTURE_IFINFO_H__

#ifdef HAVE_LIBPCAP

/*
 * The list of interfaces returned by "get_interface_list()" is
 * a list of these structures.
 */
typedef struct {
	char	*name;          /* e.g. "eth0" */
	char	*description;   /* from OS, e.g. "Local Area Connection" or NULL */
	GSList  *addrs;         /* containing address values of if_addr_t */
	gboolean loopback;      /* TRUE if loopback, FALSE otherwise */
} if_info_t;

/*
 * An address in the "addrs" list.
 */
typedef enum {
	IF_AT_IPv4,
	IF_AT_IPv6
} if_address_type;

typedef struct {
	if_address_type ifat_type;
	union {
		guint32 ip4_addr;   /*  4 byte IP V4 address, or */
		guint8 ip6_addr[16];/* 16 byte IP V6 address */
	} addr;
} if_addr_t;

/**
 * Fetch the interface list from a child process.
 */
extern GList *capture_interface_list(int *err, char **err_str);

/* Error values from "get_interface_list()/capture_interface_list()". */
#define	CANT_GET_INTERFACE_LIST	1	/* error getting list */
#define	NO_INTERFACES_FOUND	2	/* list is empty */
#define	CANT_RUN_DUMPCAP	3	/* problem running dumpcap */

void free_interface_list(GList *if_list);

/*
 * The list of data link types returned by "get_pcap_linktype_list()" and
 * "capture_pcap_linktype_list()" is a list of these structures.
 */
typedef struct {
	int	dlt;            /* e.g. DLT_EN10MB (which is 1) */
	char	*name;          /* e.g. "EN10MB" or "DLT 1" */
	char	*description;   /* descriptive name from wiretap e.g. "Ethernet", NULL if unknown */
} data_link_info_t;

/**
 * Fetch the linktype list for the specified interface from a child process.
 */
extern GList *capture_pcap_linktype_list(const char *devname, char **err_str);

void free_pcap_linktype_list(GList *linktype_list);

#endif /* HAVE_LIBPCAP */

#endif /* __CAPTURE_IFINFO_H__ */

/* capture_ifinfo.h
 * Definitions for routines to get information about capture interfaces
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

#ifndef __CAPTURE_IFINFO_H__
#define __CAPTURE_IFINFO_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum {
	IF_WIRED,
	IF_AIRPCAP,
	IF_PIPE,
	IF_STDIN,
	IF_BLUETOOTH,
	IF_WIRELESS,
	IF_DIALUP,
	IF_USB,
	IF_VIRTUAL
} interface_type;

/*
 * The list of interfaces returned by "get_interface_list()" is
 * a list of these structures.
 */
typedef struct {
	char	*name;          /* e.g. "eth0" */
	char	*friendly_name; /* from OS, e.g. "Local Area Connection", or
				   NULL if not available */
	char	*vendor_description;
				/* vendor description from pcap_findalldevs(),
				   e.g. "Realtek PCIe GBE Family Controller",
				   or NULL if not available */
	GSList  *addrs;         /* containing address values of if_addr_t */
	interface_type type;    /* type of interface */
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
extern GList *capture_interface_list(int *err, char **err_str, void (*update_cb)(void));

/* Error values from "get_interface_list()/capture_interface_list()". */
#define	CANT_GET_INTERFACE_LIST	1	/* error getting list */
#define	NO_INTERFACES_FOUND	2	/* list is empty */
#define	DONT_HAVE_PCAP		3	/* couldn't load WinPcap */

void free_interface_list(GList *if_list);

/*
 * "get_if_capabilities()" and "capture_if_capabilities()" return a pointer
 * to an allocated instance of this structure.  "free_if_capabilities()"
 * frees the returned instance.
 */
typedef struct {
	gboolean	can_set_rfmon;	/* TRUE if can be put into monitor mode */
	GList		*data_link_types;	/* GList of data_link_info_t's */
} if_capabilities_t;

/*
 * Information about data link types.
 */
typedef struct {
	int	dlt;            /* e.g. DLT_EN10MB (which is 1) */
	char	*name;          /* e.g. "EN10MB" or "DLT 1" */
	char	*description;   /* descriptive name from wiretap e.g. "Ethernet", NULL if unknown */
} data_link_info_t;

/**
 * Fetch the linktype list for the specified interface from a child process.
 */
extern if_capabilities_t *
capture_get_if_capabilities(const char *devname, gboolean monitor_mode,
                            char **err_str, void (*update_cb)(void));

void free_if_capabilities(if_capabilities_t *caps);

void add_interface_to_remote_list(if_info_t *if_info);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CAPTURE_IFINFO_H__ */

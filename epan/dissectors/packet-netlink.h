/* packet-netlink.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
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

#ifndef __PACKET_NETLINK_H__
#define __PACKET_NETLINK_H__

#include <epan/value_string.h>

/* from <linux/netlink.h> prefixed with WS_ */
enum {
	WS_NETLINK_ROUTE = 0,
	WS_NETLINK_UNUSED = 1,
	WS_NETLINK_USERSOCK = 2,
	WS_NETLINK_FIREWALL = 3,
	WS_NETLINK_SOCK_DIAG = 4,
	WS_NETLINK_NFLOG = 5,
	WS_NETLINK_XFRM = 6,
	WS_NETLINK_SELINUX = 7,
	WS_NETLINK_ISCSI = 8,
	WS_NETLINK_AUDIT = 9,
	WS_NETLINK_FIB_LOOKUP = 10,
	WS_NETLINK_CONNECTOR = 11,
	WS_NETLINK_NETFILTER = 12,
	WS_NETLINK_IP6_FW = 13,
	WS_NETLINK_DNRTMSG = 14,
	WS_NETLINK_KOBJECT_UEVENT = 15,
	WS_NETLINK_GENERIC = 16,
	/* leave room for NETLINK_DM (DM Events) */
	WS_NETLINK_SCSITRANSPORT = 18,
	WS_NETLINK_ECRYPTFS = 19,
	WS_NETLINK_RDMA = 20,
	WS_NETLINK_CRYPTO = 21
};

/* from <linux/netlink.h> prefixed with WS_ */
enum {
	WS_NLM_F_REQUEST = 1,    /* It is request message.*/
	WS_NLM_F_MULTI = 2,      /* Multipart message, terminated by NETLINK_MSG_DONE */
	WS_NLM_F_ACK = 4,        /* Reply with ack, with zero or error code */
	WS_NLM_F_ECHO = 8,       /* Echo this request */

	/* Modifiers to Get request */
	WS_NLM_F_ROOT = 0x100,   /* specify tree root */
	WS_NLM_F_MATCH = 0x200,  /* return all matching */
	WS_NLM_F_ATOMIC = 0x400, /* = (NETLINK_MSG_F_ROOT | NETLINK_MSG_F_MATCH) */

	/* Modifiers to NEW request */
	WS_NLM_F_REPLACE = 0x100,  /* Override existing */
	WS_NLM_F_EXCL = 0x200,     /* Do not touch, if it exists */
	WS_NLM_F_CREATE = 0x400,   /* Create, if it does */
	WS_NLM_F_APPEND = 0x800    /* Add to end of list */
};


extern value_string_ext netlink_family_vals_ext;

enum {
	WS_NLMSG_NOOP     = 0x01,
	WS_NLMSG_ERROR    = 0x02,
	WS_NLMSG_DONE     = 0x03,
	WS_NLMSG_OVERRUN  = 0x04,
	WS_NLMSG_MIN_TYPE     = 0x10    /** type < WS_NLMSG_MIN_TYPE are reserved */
};

enum {
	NETLINK_RTM_BASE = 16,

	NETLINK_RTM_NEWLINK = 16,
	NETLINK_RTM_DELLINK,
	NETLINK_RTM_GETLINK,
	NETLINK_RTM_SETLINK,

	NETLINK_RTM_NEWADDR = 20,
	NETLINK_RTM_DELADDR,
	NETLINK_RTM_GETADDR,

	NETLINK_RTM_NEWROUTE = 24,
	NETLINK_RTM_DELROUTE,
	NETLINK_RTM_GETROUTE
};

#define PACKET_NETLINK_MAGIC 0x4A5ACCCE

struct packet_netlink_data {
	guint32 magic; /* PACKET_NETLINK_MAGIC */

	int encoding;
	guint16 type;
};

typedef int netlink_attributes_cb_t(tvbuff_t *, void *data, proto_tree *, int nla_type, int offset, int len);

int dissect_netlink_attributes(tvbuff_t *tvb, header_field_info *hfi_type, int ett, void *data, proto_tree *tree, int offset, netlink_attributes_cb_t cb);

#endif /* __PACKET_NETLINK_H__ */

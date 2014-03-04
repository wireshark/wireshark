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

extern value_string_ext netlink_family_vals_ext;

enum {
	WS_NLMSG_NOOP     = 0x01,
	WS_NLMSG_ERROR    = 0x02,
	WS_NLMSG_DONE     = 0x03,
	WS_NLMSG_OVERRUN  = 0x04
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

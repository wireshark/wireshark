/* packet-netlink.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_NETLINK_H__
#define __PACKET_NETLINK_H__

#include <epan/value_string.h>

/* from <include/uapi/linux/netlink.h> prefixed with WS_ */
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
	WS_NETLINK_CRYPTO = 21,
	WS_NETLINK_SMC = 22
};

/* from <include/uapi/linux/netlink.h> prefixed with WS_ */
enum {
	WS_NLM_F_REQUEST = 1,    /* It is request message.*/
	WS_NLM_F_MULTI = 2,      /* Multipart message, terminated by NETLINK_MSG_DONE */
	WS_NLM_F_ACK = 4,        /* Reply with ack, with zero or error code */
	WS_NLM_F_ECHO = 8,       /* Echo this request */
	WS_NLM_F_DUMP_INTR = 16, /* Dump was inconsistent due to sequence change */
	WS_NLM_F_DUMP_FILTERED = 32, /* Dump was filtered as requested */

	/* Modifiers to Get request */
	WS_NLM_F_ROOT = 0x100,   /* specify tree root */
	WS_NLM_F_MATCH = 0x200,  /* return all matching */
	WS_NLM_F_ATOMIC = 0x400, /* return an atomic snapshot of the table */

	/* Modifiers to NEW request */
	WS_NLM_F_REPLACE = 0x100,  /* Override existing */
	WS_NLM_F_EXCL = 0x200,     /* Do not touch, if it exists */
	WS_NLM_F_CREATE = 0x400,   /* Create, if it does */
	WS_NLM_F_APPEND = 0x800,   /* Add to end of list */

	/* Modifiers to DELETE request */
	WS_NLM_F_NONREC = 0x100,   /* Do not delete recursively */

	/* Flags for ACK message */
	WS_NLM_F_CAPPED = 0x100,   /* request was capped */
	WS_NLM_F_ACK_TLVS = 0x200  /* extended ACK TLVs were included */
};


extern value_string_ext netlink_family_vals_ext;

enum {
	WS_NLMSG_NOOP     = 0x01,
	WS_NLMSG_ERROR    = 0x02,
	WS_NLMSG_DONE     = 0x03,
	WS_NLMSG_OVERRUN  = 0x04,
	WS_NLMSG_MIN_TYPE     = 0x10    /** type < WS_NLMSG_MIN_TYPE are reserved */
};

/* from <include/uapi/linux/netfilter.h>. Looks like AF_xxx, except for NFPROTO_ARP */
enum ws_nfproto {
	WS_NFPROTO_UNSPEC =  0,
	WS_NFPROTO_INET   =  1,
	WS_NFPROTO_IPV4   =  2,
	WS_NFPROTO_ARP    =  3,
	WS_NFPROTO_NETDEV =  5,
	WS_NFPROTO_BRIDGE =  7,
	WS_NFPROTO_IPV6   = 10,
	WS_NFPROTO_DECNET = 12,
};
extern const value_string nfproto_family_vals[];
extern const value_string netfilter_hooks_vals[];

#define PACKET_NETLINK_MAGIC 0x4A5ACCCE

struct packet_netlink_data {
	guint32 magic; /* PACKET_NETLINK_MAGIC */

	int encoding;
	guint16 type;
};

/**
 * Dissects the Netlink message header (struct nlmsghdr). The "hfi_type" field
 * is added for the "nlmsg_type" field and returned into pi_type.
 */
int dissect_netlink_header(tvbuff_t *tvb, proto_tree *tree, int offset, int encoding, header_field_info *hfi_type, proto_item **pi_type);

typedef int netlink_attributes_cb_t(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len);

int dissect_netlink_attributes(tvbuff_t *tvb, header_field_info *hfi_type, int ett, void *data, struct packet_netlink_data *nl_data,  proto_tree *tree, int offset, int length, netlink_attributes_cb_t cb);

/*
 * Similar to dissect_netlink_attributes, but used to parse nested attributes
 * that model an array of attributes. The first level (tree ett_array) contains
 * array elements and its type field is the array index. The next level (tree
 * ett_attrib) contains attributes (where hfi_type applies).
 */
int dissect_netlink_attributes_array(tvbuff_t *tvb, header_field_info *hfi_type, int ett_array, int ett_attrib, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int offset, int length, netlink_attributes_cb_t cb);

#define NLA_F_NESTED            0x8000
#define NLA_F_NET_BYTEORDER     0x4000
#define NLA_TYPE_MASK           0x3fff


/*
 * Format of the data that is passed to "genl.family" dissectors.
 */
typedef struct {
	struct packet_netlink_data *nl_data;

	/* For internal use by genl. */
	proto_tree     *genl_tree;

	/* fields from genlmsghdr */
	guint8 	        cmd; /* Command number */

	/* XXX This should contain a family version number as well. */
} genl_info_t;

int dissect_genl_header(tvbuff_t *tvb, genl_info_t *genl_info, struct packet_netlink_data *nl_data, header_field_info *hfi_cmd);

#endif /* __PACKET_NETLINK_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */

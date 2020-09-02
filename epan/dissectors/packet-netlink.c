/* packet-netlink.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* http://www.tcpdump.org/linktypes/LINKTYPE_NETLINK.html */

#define NEW_PROTO_TREE_API

#include "config.h"

#include <epan/packet.h>
#include <epan/arptypes.h>
#include <wiretap/wtap.h>

#include "packet-netlink.h"

void proto_register_netlink(void);
void proto_reg_handoff_netlink(void);

/*
 * A DLT_LINUX_SLL fake link-layer header.
 */
#define SLL_HEADER_SIZE	16		/* total header length */

static const value_string netlink_family_vals[] = {
	{ WS_NETLINK_ROUTE,          "Route" },
	{ WS_NETLINK_UNUSED,         "Unused" },
	{ WS_NETLINK_USERSOCK,       "User-mode socket protocols" },
	{ WS_NETLINK_FIREWALL,       "Unused (formerly: ip_queue)" },
	{ WS_NETLINK_SOCK_DIAG,      "Socket monitoring" },
	{ WS_NETLINK_NFLOG,          "Netfilter ULOG" },
	{ WS_NETLINK_XFRM,           "IPsec" },
	{ WS_NETLINK_SELINUX,        "SELinux events" },
	{ WS_NETLINK_ISCSI,          "Open-iSCSI" },
	{ WS_NETLINK_AUDIT,          "Auditing" },
	{ WS_NETLINK_FIB_LOOKUP,     "FIB lookup" },
	{ WS_NETLINK_CONNECTOR,      "Kernel connector" },
	{ WS_NETLINK_NETFILTER,      "Netfilter" },
	{ WS_NETLINK_IP6_FW,         "Unused (formerly: ip6_queue)" },
	{ WS_NETLINK_DNRTMSG,        "DECnet routing messages" },
	{ WS_NETLINK_KOBJECT_UEVENT, "Kernel messages to userspace" },
	{ WS_NETLINK_GENERIC,        "Generic" },
	{ WS_NETLINK_SCSITRANSPORT,  "SCSI Transports" },
	{ WS_NETLINK_ECRYPTFS,       "ecryptfs" },
	{ WS_NETLINK_RDMA,           "RDMA" },
	{ WS_NETLINK_CRYPTO,         "Crypto layer" },
	{ WS_NETLINK_SMC,            "SMC monitoring" },
	{ 0, NULL }
};

value_string_ext netlink_family_vals_ext = VALUE_STRING_EXT_INIT(netlink_family_vals);

static const value_string type_vals[] = {
	{ WS_NLMSG_NOOP,    "Nothing" },
	{ WS_NLMSG_ERROR,   "Error" },
	{ WS_NLMSG_DONE,    "End of a dump" },
	{ WS_NLMSG_OVERRUN, "Data lost" },
	{ 0, NULL }
};

static const value_string ha_types[] = {
	{ ARPHRD_NETLINK,    "Netlink" },
	{ 0, NULL }
};

extern value_string_ext linux_negative_errno_vals_ext;

static dissector_handle_t netlink_handle;

static header_field_info *hfi_netlink = NULL;

#define NETLINK_HFI_INIT HFI_INIT(proto_netlink)

static header_field_info hfi_netlink_hatype NETLINK_HFI_INIT =
	{ "Link-layer address type", "netlink.hatype", FT_UINT16, BASE_DEC,
		VALS(ha_types), 0x0, NULL, HFILL };

/* Linux netlink protocol type */
static header_field_info hfi_netlink_family NETLINK_HFI_INIT =
	{ "Family", "netlink.family", FT_UINT16, BASE_HEX | BASE_EXT_STRING,
		&netlink_family_vals_ext, 0x00, NULL, HFILL };

static header_field_info hfi_netlink_hdr_len NETLINK_HFI_INIT =
	{ "Length", "netlink.hdr_len", FT_UINT32, BASE_DEC,
		NULL, 0x00, "Length of message including header", HFILL };

static header_field_info hfi_netlink_hdr_type NETLINK_HFI_INIT =
	{ "Message type", "netlink.hdr_type", FT_UINT16, BASE_HEX,
		VALS(type_vals), 0x00, "Type of message content", HFILL };

static header_field_info hfi_netlink_hdr_flags NETLINK_HFI_INIT =
	{ "Flags", "netlink.hdr_flags", FT_UINT16, BASE_HEX,
		NULL, 0x00, "Additional flags", HFILL };

static header_field_info hfi_netlink_hdr_flag_dumpfiltered NETLINK_HFI_INIT =
	{ "Dump filtered", "netlink.hdr_flags.dump_filtered", FT_UINT16, BASE_DEC,
		NULL, WS_NLM_F_DUMP_FILTERED, "Dump was filtered as requested", HFILL };

static header_field_info hfi_netlink_hdr_flag_dumpintr NETLINK_HFI_INIT =
	{ "Dump inconsistent", "netlink.hdr_flags.dump_intr", FT_UINT16, BASE_DEC,
		NULL, WS_NLM_F_DUMP_INTR, "Dump was inconsistent due to sequence change", HFILL };

static header_field_info hfi_netlink_hdr_flag_echo NETLINK_HFI_INIT =
	{ "Echo", "netlink.hdr_flags.echo", FT_UINT16, BASE_DEC,
		NULL, WS_NLM_F_ECHO, "Echo this request", HFILL };

static header_field_info hfi_netlink_hdr_flag_ack NETLINK_HFI_INIT =
	{ "Ack", "netlink.hdr_flags.ack", FT_UINT16, BASE_DEC,
		NULL, WS_NLM_F_ACK, "Asking for an ack", HFILL };

static header_field_info hfi_netlink_hdr_flag_multi NETLINK_HFI_INIT =
	{ "Multipart message", "netlink.hdr_flags.multi", FT_UINT16, BASE_DEC,
		NULL, WS_NLM_F_MULTI, "Part of multi-part message terminated by NLMSG_DONE", HFILL };

static header_field_info hfi_netlink_hdr_flag_request NETLINK_HFI_INIT =
	{ "Request", "netlink.hdr_flags.request", FT_UINT16, BASE_DEC,
		NULL, WS_NLM_F_REQUEST, "It is a request message", HFILL };

static header_field_info hfi_netlink_hdr_flag_root NETLINK_HFI_INIT =
	{ "Specify tree root", "netlink.hdr_flags.root", FT_UINT16, BASE_DEC,
		NULL, WS_NLM_F_ROOT, "Return the complete table instead of a single entry", HFILL };

static header_field_info hfi_netlink_hdr_flag_match NETLINK_HFI_INIT =
	{ "Return all matching", "netlink.hdr_flags.match", FT_UINT16, BASE_DEC,
		NULL, WS_NLM_F_MATCH, "Return all entries matching criteria in request", HFILL };

static header_field_info hfi_netlink_hdr_flag_atomic NETLINK_HFI_INIT =
	{ "Atomic", "netlink.hdr_flags.atomic", FT_UINT16, BASE_DEC,
		NULL, WS_NLM_F_ATOMIC, "Return an atomic snapshot of the table", HFILL };

static header_field_info hfi_netlink_hdr_flag_replace NETLINK_HFI_INIT =
	{ "Replace", "netlink.hdr_flags.replace", FT_UINT16, BASE_DEC,
		NULL, WS_NLM_F_REPLACE, "Replace existing objects", HFILL };

static header_field_info hfi_netlink_hdr_flag_excl NETLINK_HFI_INIT =
	{ "Excl", "netlink.hdr_flags.excl", FT_UINT16, BASE_DEC,
		NULL, WS_NLM_F_EXCL, "Do not replace existing objects", HFILL };

static header_field_info hfi_netlink_hdr_flag_create NETLINK_HFI_INIT =
	{ "Create", "netlink.hdr_flags.create", FT_UINT16, BASE_DEC,
		NULL, WS_NLM_F_CREATE, "Create objects if it does not already exist", HFILL };

static header_field_info hfi_netlink_hdr_flag_append NETLINK_HFI_INIT =
	{ "Append", "netlink.hdr_flags.append", FT_UINT16, BASE_DEC,
		NULL, WS_NLM_F_APPEND, "Add to end of object list", HFILL };

static header_field_info hfi_netlink_hdr_seq NETLINK_HFI_INIT =
	{ "Sequence", "netlink.hdr_seq", FT_UINT32, BASE_DEC,
		NULL, 0x00, "Sequence number", HFILL };

static header_field_info hfi_netlink_hdr_pid NETLINK_HFI_INIT =
	{ "Port ID", "netlink.hdr_pid", FT_UINT32, BASE_DEC,
		NULL, 0x00, "Sender port ID", HFILL };

static header_field_info hfi_netlink_attr_len NETLINK_HFI_INIT =
	{ "Len", "netlink.attr_len", FT_UINT16, BASE_DEC,
		NULL, 0x00, NULL, HFILL };

static header_field_info hfi_netlink_attr_type NETLINK_HFI_INIT =
	{ "Type", "netlink.attr_type", FT_UINT16, BASE_HEX,
		NULL, 0x0000, "Netlink Attribute type", HFILL };

static header_field_info hfi_netlink_attr_type_nested NETLINK_HFI_INIT =
	{ "Nested", "netlink.attr_type.nested", FT_BOOLEAN, 16,
		TFS(&tfs_true_false), NLA_F_NESTED, "Carries nested attributes", HFILL };

static header_field_info hfi_netlink_attr_type_net_byteorder NETLINK_HFI_INIT =
	{ "Network byte order", "netlink.attr_type.net_byteorder", FT_BOOLEAN, 16,
		TFS(&tfs_true_false), NLA_F_NET_BYTEORDER, "Payload stored in host or network byte order", HFILL };

static header_field_info hfi_netlink_attr_index NETLINK_HFI_INIT =
	{ "Index", "netlink.attr_index", FT_UINT16, BASE_DEC,
		NULL, 0x0000, "Netlink Attribute type (array index)", HFILL };

static header_field_info hfi_netlink_attr_data NETLINK_HFI_INIT =
	{ "Data", "netlink.attr_data", FT_BYTES, BASE_NONE,
		NULL, 0x00, NULL, HFILL };

/* TODO add a value_string for errno. */
static header_field_info hfi_netlink_error NETLINK_HFI_INIT =
	{ "Error code", "netlink.error", FT_INT32, BASE_DEC | BASE_EXT_STRING,
		&linux_negative_errno_vals_ext, 0x00, "Negative errno or 0 for acknowledgements", HFILL };

static gint ett_netlink_cooked = -1;
static gint ett_netlink_msghdr = -1;
static gint ett_netlink_msg = -1;
static gint ett_netlink_hdr_flags = -1;
static gint ett_netlink_attr_type = -1;

static dissector_table_t netlink_dissector_table;


static int * const netlink_header_get_flags[] = {
	&hfi_netlink_hdr_flag_request.id,
	&hfi_netlink_hdr_flag_multi.id,
	&hfi_netlink_hdr_flag_ack.id,
	&hfi_netlink_hdr_flag_echo.id,
	&hfi_netlink_hdr_flag_dumpintr.id,
	&hfi_netlink_hdr_flag_dumpfiltered.id,

	&hfi_netlink_hdr_flag_root.id,
	&hfi_netlink_hdr_flag_match.id,
	&hfi_netlink_hdr_flag_atomic.id,
	NULL
};

static int * const netlink_header_new_flags[] = {
	&hfi_netlink_hdr_flag_request.id,
	&hfi_netlink_hdr_flag_multi.id,
	&hfi_netlink_hdr_flag_ack.id,
	&hfi_netlink_hdr_flag_echo.id,
	&hfi_netlink_hdr_flag_dumpintr.id,
	&hfi_netlink_hdr_flag_dumpfiltered.id,

	&hfi_netlink_hdr_flag_replace.id,
	&hfi_netlink_hdr_flag_excl.id,
	&hfi_netlink_hdr_flag_create.id,
	&hfi_netlink_hdr_flag_append.id,
	NULL
};

static int * const netlink_header_standard_flags[] = {
	&hfi_netlink_hdr_flag_request.id,
	&hfi_netlink_hdr_flag_multi.id,
	&hfi_netlink_hdr_flag_ack.id,
	&hfi_netlink_hdr_flag_echo.id,
	&hfi_netlink_hdr_flag_dumpintr.id,
	&hfi_netlink_hdr_flag_dumpfiltered.id,
	NULL
};


static int
dissect_netlink_attributes_common(tvbuff_t *tvb, header_field_info *hfi_type, int ett_tree, int ett_attrib, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int offset, int length, netlink_attributes_cb_t cb)
{
	int encoding;
	int padding = (4 - offset) & 3;

	DISSECTOR_ASSERT(nl_data);

	encoding = nl_data->encoding;

	/* align to 4 */
	offset += padding;
	if (length == -1) {
		length = tvb_captured_length_remaining(tvb, offset);
	} else {
		length -= padding;
	}

	while (length >= 4) {
		guint16 rta_len, rta_type, type;

		proto_item *ti, *type_item;
		proto_tree *attr_tree, *type_tree;

		rta_len = tvb_get_guint16(tvb, offset, encoding);
		if (rta_len < 4) {
			/* XXX invalid expert */
			break;
		}

		/* XXX expert info when rta_len < length? */
		rta_len = MIN(rta_len, length);

		attr_tree = proto_tree_add_subtree(tree, tvb, offset, rta_len, ett_tree, &ti, "Attribute");

		proto_tree_add_item(attr_tree, &hfi_netlink_attr_len, tvb, offset, 2, encoding);
		offset += 2;

		rta_type = tvb_get_guint16(tvb, offset, encoding);
		if (ett_attrib == -1) {
			/* List of attributes */
			type = rta_type & NLA_TYPE_MASK;
			type_item = proto_tree_add_item(attr_tree, &hfi_netlink_attr_type, tvb, offset, 2, encoding);
			type_tree = proto_item_add_subtree(type_item, ett_netlink_attr_type);
			proto_tree_add_item(type_tree, &hfi_netlink_attr_type_nested, tvb, offset, 2, encoding);
			proto_tree_add_item(type_tree, &hfi_netlink_attr_type_net_byteorder, tvb, offset, 2, encoding);
			/* The hfi_type _must_ have NLA_TYPE_MASK in it's definition, otherwise the nested/net_byteorder
			 * flags influence the retrieved value. Since this is impossible to enforce (apart from using
			 * a nasty DISSECTOR_ASSERT perhaps) we'll just have to make sure to feed in the properly
			 * masked value. Luckily we already have it: 'type' is the value we need.
			 */
			proto_tree_add_uint(type_tree, hfi_type, tvb, offset, 2, type);
			offset += 2;

			if (rta_type & NLA_F_NESTED)
				proto_item_append_text(type_item, ", Nested");

			if (hfi_type->strings) {
				/* XXX, export hf_try_val_to_str */
				const char *rta_str;

				if (hfi_type->display & BASE_EXT_STRING) {
					rta_str = try_val_to_str_ext(type, (value_string_ext *)hfi_type->strings);
				} else {
					rta_str = try_val_to_str(type, (const value_string *) hfi_type->strings);
				}

				if (rta_str) {
					proto_item_append_text(type_item, ", %s (%d)", rta_str, type);
					proto_item_append_text(ti, ": %s", rta_str);
				}
			}

			/* The callback needs to be passed the netlink_attr_type_net_byteorder as dissected,
			 * to properly dissect the attribute value, which byte order may differ from the
			 * capture host native byte order, as heuristically established in 'encoding'.
			 * We pass in the encoding through nl_data, so we temporarily modify it to match
			 * the NLA_F_NET_BYTEORDER flag.
			 */
			if (rta_type & NLA_F_NET_BYTEORDER)
				nl_data->encoding = ENC_BIG_ENDIAN;

			if (!cb(tvb, data, nl_data, attr_tree, rta_type, offset, rta_len - 4)) {
				proto_tree_add_item(attr_tree, &hfi_netlink_attr_data, tvb, offset, rta_len - 4, ENC_NA);
			}

			/* Restore the originaly established encoding. */
			if (rta_type & NLA_F_NET_BYTEORDER)
				nl_data->encoding = encoding;
		} else {
			/*
			 * Nested attributes, constructing an array (list of
			 * attributes where its type is the array index and its
			 * value is the actual list of interesting attributes).
			 */
			proto_tree_add_item(attr_tree, &hfi_netlink_attr_index, tvb, offset, 2, encoding);
			offset += 2;
			proto_item_append_text(ti, " %u", rta_type);

			dissect_netlink_attributes(tvb, hfi_type, ett_attrib, data, nl_data, attr_tree, offset, rta_len - 4, cb);
		}

		/* Assume offset already aligned, next offset is rta_len plus alignment. */
		rta_len = MIN((rta_len + 3) & ~3, length);
		offset += rta_len - 4;  /* Header was already skipped */
		length -= rta_len;
	}

	return offset;
}

int
dissect_netlink_attributes(tvbuff_t *tvb, header_field_info *hfi_type, int ett, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int offset, int length, netlink_attributes_cb_t cb)
{
	return dissect_netlink_attributes_common(tvb, hfi_type, ett, -1, data, nl_data, tree, offset, length, cb);
}

int
dissect_netlink_attributes_array(tvbuff_t *tvb, header_field_info *hfi_type, int ett_array, int ett_attrib, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int offset, int length, netlink_attributes_cb_t cb)
{
	DISSECTOR_ASSERT(ett_attrib != -1);
	return dissect_netlink_attributes_common(tvb, hfi_type, ett_array, ett_attrib, data, nl_data, tree, offset, length, cb);
}

int
dissect_netlink_header(tvbuff_t *tvb, proto_tree *tree, int offset, int encoding, header_field_info *hfi_type, proto_item **pi_type)
{
	guint16 hdr_flags;
	guint16 hdr_type;
	proto_tree *fh_hdr;
	proto_item *pi;

	fh_hdr = proto_tree_add_subtree(tree, tvb, offset, 16, ett_netlink_msghdr, NULL, "Netlink message header");

	proto_tree_add_item(fh_hdr, &hfi_netlink_hdr_len, tvb, offset, 4, encoding);
	offset += 4;

	hdr_type = tvb_get_guint16(tvb, offset, encoding);
	if (hdr_type < WS_NLMSG_MIN_TYPE) {
		/* Reserved control messages. */
		hfi_type = &hfi_netlink_hdr_type;
		pi = proto_tree_add_item(fh_hdr, hfi_type, tvb, offset, 2, encoding);
	} else {
		if (hfi_type) {
			pi = proto_tree_add_item(fh_hdr, hfi_type, tvb, offset, 2, encoding);
		} else {
			hfi_type = &hfi_netlink_hdr_type;
			pi = proto_tree_add_item(fh_hdr, hfi_type, tvb, offset, 2, encoding);
			proto_item_set_text(pi, "Message type: Protocol-specific (0x%04x)", hdr_type);
		}
	}
	if (pi_type) {
		*pi_type = pi;
	}
	/* TODO export hf_try_val_to_str? */
	if (hfi_type->strings && hfi_type->display & BASE_EXT_STRING) {
		proto_item_append_text(fh_hdr, " (type: %s)", val_to_str_ext(hdr_type, (value_string_ext *)hfi_type->strings, "0x%04x"));
	} else if (hfi_type->strings) {
		proto_item_append_text(fh_hdr, " (type: %s)", val_to_str(hdr_type, (const value_string *)hfi_type->strings, "0x%04x"));
	} else {
		proto_item_append_text(fh_hdr, " (type: 0x%04x)", hdr_type);
	}
	offset += 2;

	hdr_flags = tvb_get_guint16(tvb, offset, encoding);
	if ((hdr_flags & WS_NLM_F_REQUEST) && (hdr_flags & 0x0f00)) {
		/* TODO detect based on the protocol family and message type
		 * whether this is a GET, NEW or regular request. */
		proto_tree_add_bitmask(fh_hdr, tvb, offset, &hfi_netlink_hdr_flags,
			ett_netlink_hdr_flags, netlink_header_get_flags, encoding);
		proto_tree_add_bitmask(fh_hdr, tvb, offset, &hfi_netlink_hdr_flags,
			ett_netlink_hdr_flags, netlink_header_new_flags, encoding);
	} else {
		proto_tree_add_bitmask(fh_hdr, tvb, offset, &hfi_netlink_hdr_flags,
			ett_netlink_hdr_flags, netlink_header_standard_flags, encoding);
	}

	offset += 2;

	proto_tree_add_item(fh_hdr, &hfi_netlink_hdr_seq, tvb, offset, 4, encoding);
	offset += 4;

	proto_tree_add_item(fh_hdr, &hfi_netlink_hdr_pid, tvb, offset, 4, encoding);
	offset += 4;

	return offset;
}

static void
dissect_netlink_error(tvbuff_t *tvb, proto_tree *tree, int offset, int encoding)
{
	/*
	 * XXX - this should make sure we don't run past the end of the
	 * message.
	 */

	/*
	 * Assume sizeof(int) == 4; RFC 3549 doesn't say "32 bits", it
	 * says "integer (typically 32 bits)".
	 */
	proto_tree_add_item(tree, &hfi_netlink_error, tvb, offset, 4, encoding);
	offset += 4;

	dissect_netlink_header(tvb, tree, offset, encoding, NULL, NULL);
}

static int
dissect_netlink(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	guint16     protocol, hatype;
	proto_item *ti;
	tvbuff_t   *next_tvb;
	proto_tree *fh_tree;

	int offset = 0;
	int encoding;
	guint len_rem, len_le, len_be;

	hatype = tvb_get_ntohs(tvb, 2);
	if (hatype != ARPHRD_NETLINK)
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Netlink");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_protocol_format(tree, hfi_netlink->id, tvb, offset,
			SLL_HEADER_SIZE, "Linux netlink (cooked header)");
	fh_tree = proto_item_add_subtree(ti, ett_netlink_cooked);

	/* Packet type
	 * Since this packet, coming from the monitor port, is always outgoing we skip this
	 */
	offset += 2;

	proto_tree_add_item(fh_tree, &hfi_netlink_hatype, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* Hardware address length plus spare space, unused 10B */
	offset += 10;

	/* Protocol, used as netlink family identifier */
	protocol = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(fh_tree, &hfi_netlink_family, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* End of cooked header */

	/*
	 * We do not know the endianness of the capture host, we have to guess.
	 * Compare the size of the message with the reported size of the TVB,
	 * take the endianness in which the messsage length is closer to
	 * the size of the TVB. Normally we have messages with less
	 * than 10KiB here so the sizes are very huge in the wrong endianness.
	 */
	len_rem = tvb_reported_length_remaining(tvb, offset);
	len_le = tvb_get_letohl(tvb, offset);
	len_be = tvb_get_ntohl(tvb, offset);
	#define abs_diff(a, b) ((a) > (b) ? (a) - (b) : (b) - (a))
	if (abs_diff(len_be, len_rem) < abs_diff(len_le, len_rem)) {
		encoding = ENC_BIG_ENDIAN;
	} else {
		encoding = ENC_LITTLE_ENDIAN;
	}

	while (tvb_reported_length_remaining(tvb, offset) >= 16) {
		int pkt_end_offset;
		guint16 msg_type;
		guint32 pkt_len;
		guint32 port_id;
		proto_tree *fh_msg;
		gboolean dissected = FALSE;

		pkt_len = tvb_get_guint32(tvb, offset, encoding);

		pkt_end_offset = offset + pkt_len;

		if (pkt_len < 16) {
			/*
			 * This field includes the length of the 16-byte header,
			 * so its value is invalid.  Add it, report an error,
			 * and stop trying to dissect.
			 */
			proto_tree *fh_hdr;

			fh_hdr = proto_tree_add_subtree(tree, tvb, offset, 4, ett_netlink_msghdr, NULL, "Netlink message header");

			proto_tree_add_item(fh_hdr, &hfi_netlink_hdr_len, tvb, offset, 4, encoding);
			/* XXX invalid expert */
			break;
		}

		/* message type field comes after length field. */
		msg_type = tvb_get_guint16(tvb, offset + 4, encoding);
		port_id = tvb_get_guint32(tvb, offset + 12, encoding);

		/* Since we have no original direction in the packet coming from
		 * the monitor port we have to derive it from the port_id
		 */
		if (port_id == 0x00)
			pinfo->p2p_dir = P2P_DIR_SENT; /* userspace -> kernel */
		else
			pinfo->p2p_dir = P2P_DIR_RECV; /* userspace or kernel -> userspace */

		/*
		 * Try to invoke subdissectors for non-control messages.
		 */
		if (msg_type >= WS_NLMSG_MIN_TYPE && pkt_len > 16) {
			struct packet_netlink_data nl_data;

			nl_data.magic = PACKET_NETLINK_MAGIC;
			nl_data.encoding = encoding;
			nl_data.type = msg_type;

			next_tvb = tvb_new_subset_length(tvb, offset, pkt_len);

			if (dissector_try_uint_new(netlink_dissector_table, protocol, next_tvb, pinfo, tree, TRUE, &nl_data)) {
				dissected = TRUE;
			}
		}

		if (!dissected) {
			/*
			 * No subdissector was called, add a new layer with the
			 * header and the payload. Note that pkt_len>=16.
			 */
			fh_msg = proto_tree_add_subtree(tree, tvb, offset, pkt_len, ett_netlink_msg, NULL, "Netlink message");
			offset = dissect_netlink_header(tvb, fh_msg, offset, encoding, NULL, NULL);

			if (msg_type == WS_NLMSG_ERROR) {
				dissect_netlink_error(tvb, fh_msg, offset, encoding);
			} else if (pkt_len > 16) {
				next_tvb = tvb_new_subset_length(tvb, offset, pkt_len - 16);
				call_data_dissector(next_tvb, pinfo, fh_msg);
			}
		}

		offset = pkt_end_offset;
	}

	return offset;
}

void
proto_register_netlink(void)
{
#ifndef HAVE_HFI_SECTION_INIT
	static header_field_info *hfi[] = {
	/* Cooked header */
		&hfi_netlink_hatype,
		&hfi_netlink_family,

	/* Netlink message header */
		&hfi_netlink_hdr_len,
		&hfi_netlink_hdr_type,
		&hfi_netlink_hdr_flags,
		&hfi_netlink_hdr_flag_request,
		&hfi_netlink_hdr_flag_multi,
		&hfi_netlink_hdr_flag_ack,
		&hfi_netlink_hdr_flag_echo,
		&hfi_netlink_hdr_flag_dumpintr,
		&hfi_netlink_hdr_flag_dumpfiltered,

		&hfi_netlink_hdr_flag_root,
		&hfi_netlink_hdr_flag_match,
		&hfi_netlink_hdr_flag_atomic,

		&hfi_netlink_hdr_flag_replace,
		&hfi_netlink_hdr_flag_excl,
		&hfi_netlink_hdr_flag_create,
		&hfi_netlink_hdr_flag_append,

		&hfi_netlink_hdr_seq,
		&hfi_netlink_hdr_pid,

	/* Netlink message attribute */
		&hfi_netlink_attr_len,
		&hfi_netlink_attr_type,
		&hfi_netlink_attr_type_nested,
		&hfi_netlink_attr_type_net_byteorder,
		&hfi_netlink_attr_index,
		&hfi_netlink_attr_data,

	/* Netlink message payloads */
		&hfi_netlink_error,
	};
#endif

	static gint *ett[] = {
		&ett_netlink_cooked,
		&ett_netlink_msghdr,
		&ett_netlink_msg,
		&ett_netlink_hdr_flags,
		&ett_netlink_attr_type,
	};

	int proto_netlink;

	proto_netlink = proto_register_protocol("Linux netlink protocol",  "NETLINK", "netlink" );
	hfi_netlink = proto_registrar_get_nth(proto_netlink);

	proto_register_fields(proto_netlink, hfi, array_length(hfi));
	proto_register_subtree_array(ett, array_length(ett));

	netlink_handle = create_dissector_handle(dissect_netlink, proto_netlink);

	netlink_dissector_table = register_dissector_table(
		"netlink.protocol",
		"Linux netlink protocol type",
		proto_netlink, FT_UINT16,
		BASE_HEX
	);
	register_dissector("netlink", dissect_netlink, proto_netlink);
}

void
proto_reg_handoff_netlink(void)
{
	dissector_add_uint("wtap_encap", WTAP_ENCAP_NETLINK, netlink_handle);
}

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

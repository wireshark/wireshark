/* packet-netlink.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* http://www.tcpdump.org/linktypes/LINKTYPE_NETLINK.html */

#include "config.h"

#include <epan/packet.h>
#include <epan/arptypes.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>

#include <wiretap/wtap.h>
#include <wsutil/ws_roundup.h>

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

static int proto_netlink;

static int hf_netlink_attr_data;
static int hf_netlink_attr_index;
static int hf_netlink_attr_len;
static int hf_netlink_attr_type;
static int hf_netlink_attr_type_nested;
static int hf_netlink_attr_type_net_byteorder;
static int hf_netlink_error;
static int hf_netlink_family;
static int hf_netlink_hatype;
static int hf_netlink_hdr_flag_ack;
static int hf_netlink_hdr_flag_append;
static int hf_netlink_hdr_flag_atomic;
static int hf_netlink_hdr_flag_create;
static int hf_netlink_hdr_flag_dumpfiltered;
static int hf_netlink_hdr_flag_dumpintr;
static int hf_netlink_hdr_flag_echo;
static int hf_netlink_hdr_flag_excl;
static int hf_netlink_hdr_flag_match;
static int hf_netlink_hdr_flag_multi;
static int hf_netlink_hdr_flag_replace;
static int hf_netlink_hdr_flag_request;
static int hf_netlink_hdr_flag_root;
static int hf_netlink_hdr_flags;
static int hf_netlink_hdr_len;
static int hf_netlink_hdr_pid;
static int hf_netlink_hdr_seq;
static int hf_netlink_hdr_type;
static int hf_netlink_padding;

static int ett_netlink_cooked;
static int ett_netlink_msghdr;
static int ett_netlink_msg;
static int ett_netlink_hdr_flags;
static int ett_netlink_attr_type;

static dissector_table_t netlink_dissector_table;


static int * const netlink_header_get_flags[] = {
	&hf_netlink_hdr_flag_request,
	&hf_netlink_hdr_flag_multi,
	&hf_netlink_hdr_flag_ack,
	&hf_netlink_hdr_flag_echo,
	&hf_netlink_hdr_flag_dumpintr,
	&hf_netlink_hdr_flag_dumpfiltered,

	&hf_netlink_hdr_flag_root,
	&hf_netlink_hdr_flag_match,
	&hf_netlink_hdr_flag_atomic,
	NULL
};

static int * const netlink_header_new_flags[] = {
	&hf_netlink_hdr_flag_request,
	&hf_netlink_hdr_flag_multi,
	&hf_netlink_hdr_flag_ack,
	&hf_netlink_hdr_flag_echo,
	&hf_netlink_hdr_flag_dumpintr,
	&hf_netlink_hdr_flag_dumpfiltered,

	&hf_netlink_hdr_flag_replace,
	&hf_netlink_hdr_flag_excl,
	&hf_netlink_hdr_flag_create,
	&hf_netlink_hdr_flag_append,
	NULL
};

static int * const netlink_header_standard_flags[] = {
	&hf_netlink_hdr_flag_request,
	&hf_netlink_hdr_flag_multi,
	&hf_netlink_hdr_flag_ack,
	&hf_netlink_hdr_flag_echo,
	&hf_netlink_hdr_flag_dumpintr,
	&hf_netlink_hdr_flag_dumpfiltered,
	NULL
};


static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_netlink_attributes_common(tvbuff_t *tvb, int hf_type, int ett_tree, int ett_attrib, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int offset, int length, netlink_attributes_cb_t cb)
{
	int encoding;
	int padding = (4 - offset) & 3;
	unsigned data_length;
	header_field_info *hfi_type;

	DISSECTOR_ASSERT(nl_data);

	encoding = nl_data->encoding;

	/*
	 * A "negative" length is really a very large positive
	 * length, which we presume to go past the end of the
	 * packet.
	 */
	if (length < 0)
		THROW(ReportedBoundsError);

	/* align to 4 */
	offset += padding;
	if (length < padding)
		THROW(ReportedBoundsError);
	length -= padding;

	data_length = length;

	while (data_length >= 4) {
		unsigned rta_len, rta_type, type;

		proto_item *ti, *type_item;
		proto_tree *attr_tree, *type_tree;

		rta_len = tvb_get_uint16(tvb, offset, encoding);
		if (rta_len < 4) {
			/* XXX invalid expert */
			break;
		}

		/* XXX expert info when rta_len < data_length? */
		rta_len = MIN(rta_len, data_length);

		attr_tree = proto_tree_add_subtree(tree, tvb, offset, rta_len, ett_tree, &ti, "Attribute");

		proto_tree_add_item(attr_tree, hf_netlink_attr_len, tvb, offset, 2, encoding);
		offset += 2;

		rta_type = tvb_get_uint16(tvb, offset, encoding);
		if (ett_attrib <= 0) {
			/* List of attributes */
			type = rta_type & NLA_TYPE_MASK;
			type_item = proto_tree_add_item(attr_tree, hf_netlink_attr_type, tvb, offset, 2, encoding);
			type_tree = proto_item_add_subtree(type_item, ett_netlink_attr_type);
			proto_tree_add_item(type_tree, hf_netlink_attr_type_nested, tvb, offset, 2, encoding);
			proto_tree_add_item(type_tree, hf_netlink_attr_type_net_byteorder, tvb, offset, 2, encoding);
			/* The hf_type _must_ have NLA_TYPE_MASK in it's definition, otherwise the nested/net_byteorder
			 * flags influence the retrieved value. Since this is impossible to enforce (apart from using
			 * a nasty DISSECTOR_ASSERT perhaps) we'll just have to make sure to feed in the properly
			 * masked value. Luckily we already have it: 'type' is the value we need.
			 */
			proto_tree_add_uint(type_tree, hf_type, tvb, offset, 2, type);
			offset += 2;

			if (rta_type & NLA_F_NESTED)
				proto_item_append_text(type_item, ", Nested");

			hfi_type = proto_registrar_get_nth(hf_type);
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
				proto_tree_add_item(attr_tree, hf_netlink_attr_data, tvb, offset, rta_len - 4, ENC_NA);
			}

			/* Restore the originally established encoding. */
			if (rta_type & NLA_F_NET_BYTEORDER)
				nl_data->encoding = encoding;
		} else {
			/*
			 * Nested attributes, constructing an array (list of
			 * attributes where its type is the array index and its
			 * value is the actual list of interesting attributes).
			 */
			proto_tree_add_item(attr_tree, hf_netlink_attr_index, tvb, offset, 2, encoding);
			offset += 2;
			proto_item_append_text(ti, " %u", rta_type);

			// In theory we should use increment_dissection_depth here, but that
			// requires adding pinfo all over packet-netlink*.[ch] and we're limited
			// to 262144 bytes (WTAP_MAX_PACKET_SIZE_STANDARD).
			dissect_netlink_attributes(tvb, hf_type, ett_attrib, data, nl_data, attr_tree, offset, rta_len - 4, cb);
		}

		/* Assume offset already aligned, next offset is rta_len plus alignment. */
		unsigned signalled_len = rta_len;
		rta_len = MIN(WS_ROUNDUP_4(rta_len), data_length);
		/* Possible padding following attr */
		if (rta_len > signalled_len) {
			proto_tree_add_item(tree, hf_netlink_padding, tvb, offset+1, rta_len-signalled_len, ENC_NA);
		}

		offset += rta_len - 4;  /* Header was already skipped */


		if (data_length < rta_len)
			THROW(ReportedBoundsError);
		data_length -= rta_len;
	}

	return offset;
}

int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_netlink_attributes(tvbuff_t *tvb, int hf_type, int ett, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int offset, int length, netlink_attributes_cb_t cb)
{
	return dissect_netlink_attributes_common(tvb, hf_type, ett, -1, data, nl_data, tree, offset, length, cb);
}

int
dissect_netlink_attributes_to_end(tvbuff_t *tvb, int hf_type, int ett, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int offset, netlink_attributes_cb_t cb)
{
	return dissect_netlink_attributes_common(tvb, hf_type, ett, -1, data, nl_data, tree, offset, tvb_ensure_reported_length_remaining(tvb, offset), cb);
}

int
dissect_netlink_attributes_array(tvbuff_t *tvb, int hf_type, int ett_array, int ett_attrib, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int offset, int length, netlink_attributes_cb_t cb)
{
	DISSECTOR_ASSERT(ett_attrib > 0);
	return dissect_netlink_attributes_common(tvb, hf_type, ett_array, ett_attrib, data, nl_data, tree, offset, length, cb);
}

int
dissect_netlink_header(tvbuff_t *tvb, proto_tree *tree, int offset, int encoding, int hf_type, proto_item **pi_type)
{
	uint16_t hdr_flags;
	uint16_t hdr_type;
	proto_tree *fh_hdr;
	proto_item *pi;
	header_field_info *hfi_type;

	fh_hdr = proto_tree_add_subtree(tree, tvb, offset, 16, ett_netlink_msghdr, NULL, "Netlink message header");

	proto_tree_add_item(fh_hdr, hf_netlink_hdr_len, tvb, offset, 4, encoding);
	offset += 4;

	hdr_type = tvb_get_uint16(tvb, offset, encoding);
	if (hdr_type < WS_NLMSG_MIN_TYPE) {
		/* Reserved control messages. */
		hf_type = hf_netlink_hdr_type;
		pi = proto_tree_add_item(fh_hdr, hf_type, tvb, offset, 2, encoding);
	} else {
		if (hf_type > 0) {
			pi = proto_tree_add_item(fh_hdr, hf_type, tvb, offset, 2, encoding);
		} else {
			hf_type = hf_netlink_hdr_type;
			pi = proto_tree_add_item(fh_hdr, hf_type, tvb, offset, 2, encoding);
			proto_item_set_text(pi, "Message type: Protocol-specific (0x%04x)", hdr_type);
		}
	}
	hfi_type = proto_registrar_get_nth(hf_type);

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

	hdr_flags = tvb_get_uint16(tvb, offset, encoding);
	if ((hdr_flags & WS_NLM_F_REQUEST) && (hdr_flags & 0x0f00)) {
		/* TODO detect based on the protocol family and message type
		 * whether this is a GET, NEW or regular request. */
		proto_tree_add_bitmask(fh_hdr, tvb, offset, hf_netlink_hdr_flags,
			ett_netlink_hdr_flags, netlink_header_get_flags, encoding);
		proto_tree_add_bitmask(fh_hdr, tvb, offset, hf_netlink_hdr_flags,
			ett_netlink_hdr_flags, netlink_header_new_flags, encoding);
	} else {
		proto_tree_add_bitmask(fh_hdr, tvb, offset, hf_netlink_hdr_flags,
			ett_netlink_hdr_flags, netlink_header_standard_flags, encoding);
	}

	offset += 2;

	proto_tree_add_item(fh_hdr, hf_netlink_hdr_seq, tvb, offset, 4, encoding);
	offset += 4;

	proto_tree_add_item(fh_hdr, hf_netlink_hdr_pid, tvb, offset, 4, encoding);
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
	proto_tree_add_item(tree, hf_netlink_error, tvb, offset, 4, encoding);
	offset += 4;

	dissect_netlink_header(tvb, tree, offset, encoding, -1, NULL);
}

static int
dissect_netlink(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	uint16_t    protocol, hatype;
	proto_item *ti;
	tvbuff_t   *next_tvb;
	proto_tree *fh_tree;

	int offset = 0;
	int encoding;
	unsigned len_rem, len_le, len_be;

	hatype = tvb_get_ntohs(tvb, 2);
	if (hatype != ARPHRD_NETLINK)
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Netlink");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_protocol_format(tree, proto_netlink, tvb, offset,
			SLL_HEADER_SIZE, "Linux netlink (cooked header)");
	fh_tree = proto_item_add_subtree(ti, ett_netlink_cooked);

	/* Packet type
	 * Since this packet, coming from the monitor port, is always outgoing we skip this
	 */
	offset += 2;

	proto_tree_add_item(fh_tree, hf_netlink_hatype, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* Hardware address length plus spare space, unused 10B */
	offset += 10;

	/* Protocol, used as netlink family identifier */
	protocol = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(fh_tree, hf_netlink_family, tvb, offset, 2, ENC_BIG_ENDIAN);
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
		uint16_t msg_type;
		uint32_t pkt_len;
		uint32_t port_id;
		proto_tree *fh_msg;
		bool dissected = false;

		pkt_len = tvb_get_uint32(tvb, offset, encoding);

		pkt_end_offset = offset + pkt_len;

		if (pkt_len < 16) {
			/*
			 * This field includes the length of the 16-byte header,
			 * so its value is invalid.  Add it, report an error,
			 * and stop trying to dissect.
			 */
			proto_tree *fh_hdr;

			fh_hdr = proto_tree_add_subtree(tree, tvb, offset, 4, ett_netlink_msghdr, NULL, "Netlink message header");

			proto_tree_add_item(fh_hdr, hf_netlink_hdr_len, tvb, offset, 4, encoding);
			/* XXX invalid expert */
			break;
		}

		/* message type field comes after length field. */
		msg_type = tvb_get_uint16(tvb, offset + 4, encoding);
		port_id = tvb_get_uint32(tvb, offset + 12, encoding);

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

			if (dissector_try_uint_new(netlink_dissector_table, protocol, next_tvb, pinfo, tree, true, &nl_data)) {
				dissected = true;
			}
		}

		if (!dissected) {
			/*
			 * No subdissector was called, add a new layer with the
			 * header and the payload. Note that pkt_len>=16.
			 */
			fh_msg = proto_tree_add_subtree(tree, tvb, offset, pkt_len, ett_netlink_msg, NULL, "Netlink message");
			offset = dissect_netlink_header(tvb, fh_msg, offset, encoding, -1, NULL);

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
	static hf_register_info hf[] = {
		{ &hf_netlink_hatype,
			{ "Link-layer address type", "netlink.hatype",
			  FT_UINT16, BASE_DEC, VALS(ha_types), 0x0,
			  NULL, HFILL }
		},
		{ &hf_netlink_family,
			{ "Family", "netlink.family",
			  FT_UINT16, BASE_HEX | BASE_EXT_STRING, &netlink_family_vals_ext, 0x0,
			  NULL, HFILL }
		},
		{ &hf_netlink_hdr_len,
			{ "Length", "netlink.hdr_len",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "Length of message including header", HFILL }
		},
		{ &hf_netlink_hdr_type,
			{ "Message type", "netlink.hdr_type",
			  FT_UINT16, BASE_HEX, VALS(type_vals), 0x0,
			  "Type of message content", HFILL }
		},
		{ &hf_netlink_hdr_flags,
			{ "Flags", "netlink.hdr_flags",
			  FT_UINT16, BASE_HEX, NULL, 0x0,
			  "Additional flags", HFILL }
		},
		{ &hf_netlink_hdr_flag_dumpfiltered,
			{ "Dump filtered", "netlink.hdr_flags.dump_filtered",
			  FT_UINT16, BASE_DEC, NULL, WS_NLM_F_DUMP_FILTERED,
			  "Dump was filtered as requested", HFILL }
		},
		{ &hf_netlink_hdr_flag_dumpintr,
			{ "Dump inconsistent", "netlink.hdr_flags.dump_intr",
			  FT_UINT16, BASE_DEC, NULL, WS_NLM_F_DUMP_INTR,
			  "Dump was inconsistent due to sequence change", HFILL }
		},
		{ &hf_netlink_hdr_flag_echo,
			{ "Echo", "netlink.hdr_flags.echo",
			  FT_UINT16, BASE_DEC, NULL, WS_NLM_F_ECHO,
			  "Echo this request", HFILL }
		},
		{ &hf_netlink_hdr_flag_ack,
			{ "Ack", "netlink.hdr_flags.ack",
			  FT_UINT16, BASE_DEC, NULL, WS_NLM_F_ACK,
			  "Asking for an ack", HFILL }
		},
		{ &hf_netlink_hdr_flag_multi,
			{ "Multipart message", "netlink.hdr_flags.multi",
			  FT_UINT16, BASE_DEC, NULL, WS_NLM_F_MULTI,
			  "Part of multi-part message terminated by NLMSG_DONE", HFILL }
		},
		{ &hf_netlink_hdr_flag_request,
			{ "Request", "netlink.hdr_flags.request",
			  FT_UINT16, BASE_DEC, NULL, WS_NLM_F_REQUEST,
			  "It is a request message", HFILL }
		},
		{ &hf_netlink_hdr_flag_root,
			{ "Specify tree root", "netlink.hdr_flags.root",
			  FT_UINT16, BASE_DEC, NULL, WS_NLM_F_ROOT,
			  "Return the complete table instead of a single entry", HFILL }
		},
		{ &hf_netlink_hdr_flag_match,
			{ "Return all matching", "netlink.hdr_flags.match",
			  FT_UINT16, BASE_DEC, NULL, WS_NLM_F_MATCH,
			  "Return all entries matching criteria in request", HFILL }
		},
		{ &hf_netlink_hdr_flag_atomic,
			{ "Atomic", "netlink.hdr_flags.atomic",
			  FT_UINT16, BASE_DEC, NULL, WS_NLM_F_ATOMIC,
			  "Return an atomic snapshot of the table", HFILL }
		},
		{ &hf_netlink_hdr_flag_replace,
			{ "Replace", "netlink.hdr_flags.replace",
			  FT_UINT16, BASE_DEC, NULL, WS_NLM_F_REPLACE,
			  "Replace existing objects", HFILL }
		},
		{ &hf_netlink_hdr_flag_excl,
			{ "Excl", "netlink.hdr_flags.excl",
			  FT_UINT16, BASE_DEC, NULL, WS_NLM_F_EXCL,
			  "Do not replace existing objects", HFILL }
		},
		{ &hf_netlink_hdr_flag_create,
			{ "Create", "netlink.hdr_flags.create",
			  FT_UINT16, BASE_DEC, NULL, WS_NLM_F_CREATE,
			  "Create objects if it does not already exist", HFILL }
		},
		{ &hf_netlink_hdr_flag_append,
			{ "Append", "netlink.hdr_flags.append",
			  FT_UINT16, BASE_DEC, NULL, WS_NLM_F_APPEND,
			  "Add to end of object list", HFILL }
		},
		{ &hf_netlink_hdr_seq,
			{ "Sequence", "netlink.hdr_seq",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "Sequence number", HFILL }
		},
		{ &hf_netlink_hdr_pid,
			{ "Port ID", "netlink.hdr_pid",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "Sender port ID", HFILL }
		},
		{ &hf_netlink_attr_len,
			{ "Len", "netlink.attr_len",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_netlink_attr_type,
			{ "Type", "netlink.attr_type",
			  FT_UINT16, BASE_HEX, NULL, 0x0,
			  "Netlink Attribute type", HFILL }
		},
		{ &hf_netlink_attr_type_nested,
			{ "Nested", "netlink.attr_type.nested",
			  FT_BOOLEAN, 16, NULL, NLA_F_NESTED,
			  "Carries nested attributes", HFILL }
		},
		{ &hf_netlink_attr_type_net_byteorder,
			{ "Network byte order", "netlink.attr_type.net_byteorder",
			  FT_BOOLEAN, 16, NULL, NLA_F_NET_BYTEORDER,
			  "Payload stored in host or network byte order", HFILL }
		},
		{ &hf_netlink_attr_index,
			{ "Index", "netlink.attr_index",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  "Netlink Attribute type (array index)", HFILL }
		},
		{ &hf_netlink_attr_data,
			{ "Data", "netlink.attr_data",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_netlink_error,
			{ "Error code", "netlink.error",
			  FT_INT32, BASE_DEC | BASE_EXT_STRING, &linux_negative_errno_vals_ext, 0x0,
			  "Negative errno or 0 for acknowledgements", HFILL }
		},
		{ &hf_netlink_padding,
			{ "Padding", "netlink.padding",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
	};

	static int *ett[] = {
		&ett_netlink_cooked,
		&ett_netlink_msghdr,
		&ett_netlink_msg,
		&ett_netlink_hdr_flags,
		&ett_netlink_attr_type,
	};

	proto_netlink = proto_register_protocol("Linux netlink protocol",  "NETLINK", "netlink" );
	proto_register_field_array(proto_netlink, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	netlink_handle = register_dissector("netlink", dissect_netlink, proto_netlink);

	netlink_dissector_table = register_dissector_table(
		"netlink.protocol",
		"Linux netlink protocol type",
		proto_netlink, FT_UINT16,
		BASE_HEX
	);
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

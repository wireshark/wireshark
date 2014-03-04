/* packet-netlink.c
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

/* http://www.tcpdump.org/linktypes/LINKTYPE_NETLINK.html */

#define NEW_PROTO_TREE_API

#include "config.h"

#include <glib.h>

#include <epan/arptypes.h>
#include <epan/packet.h>
#include <wiretap/wtap.h>

#include "packet-netlink.h"

void proto_register_netlink(void);
void proto_reg_handoff_netlink(void);

/*
 * A DLT_LINUX_SLL fake link-layer header.
 */
#define SLL_HEADER_SIZE	16		/* total header length */

static const value_string netlink_family_vals[] = {
	{ WS_NETLINK_ROUTE,       "Route" },
	{ WS_NETLINK_UNUSED,      "Unused" },
	{ WS_NETLINK_USERSOCK,    "user-mode" },
	{ WS_NETLINK_FIREWALL,    "Unused (formerly: ip_queue)" },
	{ WS_NETLINK_SOCK_DIAG,   "socket monitoring" },
	{ WS_NETLINK_NFLOG,       "Netfilter ULOG" },
	{ WS_NETLINK_XFRM,        "IPsec" },
	{ WS_NETLINK_SELINUX,     "SELinux events" },
	{ WS_NETLINK_ISCSI,       "Open-iSCSI" },
	{ WS_NETLINK_AUDIT,       "Auditing" },
	{ WS_NETLINK_FIB_LOOKUP,  "FIB lookup" },
	{ WS_NETLINK_CONNECTOR,   "Kernel connector" },
	{ WS_NETLINK_NETFILTER,   "Netfilter" },
	{ WS_NETLINK_IP6_FW,      "Unused (formerly: ip6_queue)" },
	{ WS_NETLINK_DNRTMSG,     "DECnet routing messages" },
	{ WS_NETLINK_KOBJECT_UEVENT, "Kernel messages" },
	{ WS_NETLINK_GENERIC,      "Generic" },
	{ WS_NETLINK_SCSITRANSPORT, "SCSI Transports" },
	{ WS_NETLINK_ECRYPTFS,     "ecryptfs" },
	{ WS_NETLINK_RDMA,         "RDMA" },
	{ WS_NETLINK_CRYPTO,       "Crypto layer" },
	{ 0, NULL }
};

value_string_ext netlink_family_vals_ext = VALUE_STRING_EXT_INIT(netlink_family_vals);

static const value_string type_vals[] = {
	{ WS_NLMSG_NOOP,	"nothing" },
	{ WS_NLMSG_ERROR,	"error" },
	{ WS_NLMSG_DONE,	"end of a dump" },
	{ WS_NLMSG_OVERRUN,	"data lost" },
	{ 0, NULL }
};

static dissector_handle_t netlink_handle;

static header_field_info *hfi_netlink = NULL;

#define NETLINK_HFI_INIT HFI_INIT(proto_netlink)

static header_field_info hfi_netlink_hatype NETLINK_HFI_INIT =
	{ "Link-layer address type",	"netlink.hatype", FT_UINT16, BASE_DEC,
	  NULL, 0x0, NULL, HFILL };

/* Linux netlink protocol type */
static header_field_info hfi_netlink_family NETLINK_HFI_INIT =
	{ "Family",	"netlink.family", FT_UINT16, BASE_HEX | BASE_EXT_STRING,
	  &netlink_family_vals_ext, 0x00, NULL, HFILL };


static header_field_info hfi_netlink_hdr_len NETLINK_HFI_INIT =
	{ "Length", "netlink.hdr_len", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_netlink_hdr_type NETLINK_HFI_INIT =
	{ "Type", "netlink.hdr_type", FT_UINT16, BASE_HEX,
	  VALS(type_vals), 0x00, NULL, HFILL };

static header_field_info hfi_netlink_hdr_flags NETLINK_HFI_INIT =
	{ "Flags", "netlink.hdr_flags", FT_UINT16, BASE_HEX,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_netlink_hdr_seq NETLINK_HFI_INIT =
	{ "Sequence", "netlink.hdr_seq", FT_UINT32, BASE_HEX,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_netlink_hdr_pid NETLINK_HFI_INIT =
	{ "Port ID", "netlink.hdr_pid", FT_UINT32, BASE_HEX,
	  NULL, 0x00, NULL, HFILL };

static gint ett_netlink_cooked = -1;
static gint ett_netlink_msghdr = -1;
static gint ett_netlink_msg = -1;

static dissector_table_t netlink_dissector_table;
static dissector_handle_t data_handle;

int
dissect_netlink_attributes(tvbuff_t *tvb, header_field_info *hfi_type, int ett, void *data, proto_tree *tree, int offset, netlink_attributes_cb_t cb)
{
	/* align to 4 */
	offset = (offset + 3) & ~3;

	while (tvb_length_remaining(tvb, offset) >= 4) {
		guint16 rta_len, rta_type;
		int end_offset;

		proto_item *ti;
		proto_tree *attr_tree;

		rta_len = tvb_get_letohs(tvb, offset);
		if (rta_len < 4) {
			/* XXX invalid expert */
			break;
		}

		end_offset = (offset + rta_len + 3) & ~3;

		ti = proto_tree_add_text(tree, tvb, offset, end_offset - offset, "Attribute");
		attr_tree = proto_item_add_subtree(ti, ett);

		proto_tree_add_text(attr_tree, tvb, offset, 2, "Len: %d", rta_len);
		offset += 2;

		rta_type = tvb_get_letohs(tvb, offset);
		proto_tree_add_item(attr_tree, hfi_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		if (hfi_type->strings) {
			/* XXX, export hf_try_val_to_str */
			const char *rta_str = try_val_to_str(rta_type, (const value_string *) hfi_type->strings);

			if (rta_str)
				proto_item_append_text(ti, ": %s", rta_str);
		}

		if (!cb(tvb, data, attr_tree, rta_type, offset, rta_len - 4)) {
			/* not handled */
		}

		if (end_offset <= offset)
			break;

		offset = end_offset;
	}

	return offset;
}

static int
dissect_netlink(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *_data _U_)
{
	guint16 protocol, hatype;
	proto_item *ti;
	tvbuff_t *next_tvb;
	proto_tree *fh_tree = NULL;

	int offset;

	hatype = tvb_get_ntohs(tvb, 2);
	if (hatype != ARPHRD_NETLINK)
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Netlink");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		ti = proto_tree_add_protocol_format(tree, hfi_netlink->id, tvb, 0,
		    SLL_HEADER_SIZE, "Linux netlink (cooked header)");
		fh_tree = proto_item_add_subtree(ti, ett_netlink_cooked);
	}

	/* Unused 2B */
	offset = 2;

	proto_tree_add_item(fh_tree, &hfi_netlink_hatype, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* Unused 10B */
	offset += 10;

	protocol = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(fh_tree, &hfi_netlink_family, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* DISSECTOR_ASSERT(offset == 16); */

	while (tvb_reported_length_remaining(tvb, offset) >= 16) {
		struct packet_netlink_data data;

		int pkt_end_offset;
		guint32 pkt_len;
		guint32 port_id;

		proto_tree *fh_msg;
		proto_tree *fh_hdr;

		int encoding = ENC_LITTLE_ENDIAN; /* XXX */

		pkt_len = tvb_get_letohl(tvb, offset);

		pkt_end_offset = offset + pkt_len;

		ti = proto_tree_add_text(tree, tvb, offset, pkt_len, "Netlink message");
		fh_msg = proto_item_add_subtree(ti, ett_netlink_msg);

		ti = proto_tree_add_text(fh_msg, tvb, offset, 16, "Header");
		fh_hdr = proto_item_add_subtree(ti, ett_netlink_msghdr);

		proto_tree_add_item(fh_hdr, &hfi_netlink_hdr_len, tvb, offset, 4, encoding);
		offset += 4;

		proto_tree_add_item(fh_hdr, &hfi_netlink_hdr_type, tvb, offset, 2, encoding);
		data.type = tvb_get_letohs(tvb, offset);
		offset += 2;

		proto_tree_add_item(fh_hdr, &hfi_netlink_hdr_flags, tvb, offset, 2, encoding);
		offset += 2;

		proto_tree_add_item(fh_hdr, &hfi_netlink_hdr_seq, tvb, offset, 4, encoding);
		offset += 4;

		proto_tree_add_item(fh_hdr, &hfi_netlink_hdr_pid, tvb, offset, 4, encoding);
		port_id = tvb_get_letohl(tvb, offset);
		offset += 4;

		/* XXX */
		if (port_id == 0x00)
			pinfo->p2p_dir = P2P_DIR_SENT; /* userspace -> kernel */
		else
			pinfo->p2p_dir = P2P_DIR_RECV; /* userspace or kernel -> userspace */

		if (pkt_len > 16) {
			data.magic = PACKET_NETLINK_MAGIC;
			data.encoding = encoding;

			next_tvb = tvb_new_subset_length(tvb, offset, pkt_len-16);

			if (!dissector_try_uint_new(netlink_dissector_table, protocol, next_tvb, pinfo, fh_msg, TRUE, &data))
				call_dissector(data_handle, next_tvb, pinfo, fh_msg);

		} else if (pkt_len != 16) {
			/* XXX, expert info */
			break;
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
		&hfi_netlink_hdr_seq,
		&hfi_netlink_hdr_pid,
	};
#endif

	static gint *ett[] = {
		&ett_netlink_cooked,
		&ett_netlink_msghdr,
		&ett_netlink_msg
	};

	int proto_netlink;

	proto_netlink = proto_register_protocol("Linux netlink protocol",  "NETLINK", "netlink" );
	hfi_netlink = proto_registrar_get_nth(proto_netlink);

	proto_register_fields(proto_netlink, hfi, array_length(hfi));
	proto_register_subtree_array(ett, array_length(ett));

	netlink_handle = new_create_dissector_handle(dissect_netlink, proto_netlink);

	netlink_dissector_table = register_dissector_table(
		"netlink.protocol",
		"Linux netlink protocol type",
		FT_UINT16,
		BASE_HEX
	);
}

void
proto_reg_handoff_netlink(void)
{
	data_handle = find_dissector("data");

	dissector_add_uint("wtap_encap", WTAP_ENCAP_NETLINK, netlink_handle);
}

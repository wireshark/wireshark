/* packet-netlink-sock_diag.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define NEW_PROTO_TREE_API

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/aftypes.h>
#include "packet-netlink.h"

typedef struct {
	packet_info *pinfo;
	struct packet_netlink_data *data;

	int encoding; /* copy of data->encoding */
} netlink_sock_diag_info_t;

static dissector_handle_t netlink_sock_diag_handle;

static header_field_info *hfi_netlink_sock_diag = NULL;

#define NETLINK_SOCK_DIAG_HFI_INIT HFI_INIT(proto_netlink_sock_diag)


enum {
/* sock diag values for nlmsghdr.nlmsg_type from <linux/sock_diag.h> */
	WS_SOCK_DIAG_BY_FAMILY = 20	
};

enum {
	/* <bits/socket_type.h> */
	WS_SOCK_STREAM    =  1,
	WS_SOCK_DGRAM     =  2,
	WS_SOCK_RAW       =  3,
	WS_SOCK_RDM       =  4,
	WS_SOCK_SEQPACKET =  5,
	WS_SOCK_DCCP      =  6,
	WS_SOCK_PACKET    = 10
};

/*  SOCK_CLOEXEC = 02000000 */
/* SOCK_NONBLOCK = 00004000 */

enum ws_unix_diag_attr_type {
	/* netlink attributes for unix from <linux/unix_diag.h> */
	WS_UNIX_DIAG_NAME     = 0,
	WS_UNIX_DIAG_VFS      = 1,
	WS_UNIX_DIAG_PEER     = 2,
	WS_UNIX_DIAG_ICONS    = 3,
	WS_UNIX_DIAG_RQLEN    = 4,
	WS_UNIX_DIAG_MEMINFO  = 5,
	WS_UNIX_DIAG_SHUTDOWN = 6
};

enum ws_inet_diag_attr_type {
	/* netlink attributes for inet from <linux/inet_diag.h> */
	WS_INET_DIAG_NONE      = 0,
	WS_INET_DIAG_MEMINFO   = 1,
	WS_INET_DIAG_INFO      = 2,
	WS_INET_DIAG_VEGASINFO = 3,
	WS_INET_DIAG_CONG      = 4,
	WS_INET_DIAG_TOS       = 5,
	WS_INET_DIAG_TCLASS    = 6,
	WS_INET_DIAG_SKMEMINFO = 7,
	WS_INET_DIAG_SHUTDOWN  = 8
};

enum {
	/* based on kernel include <net/tcp_states.h> with WS_ without TCP_ (it's not only used by tcp) */
	WS_ESTABLISHED = 1,
	WS_SYN_SENT    = 2,
	WS_SYN_RECV    = 3,
	WS_FIN_WAIT1   = 4,
	WS_FIN_WAIT2   = 5,
	WS_TIME_WAIT   = 6,
	WS_CLOSE       = 7,
	WS_CLOSE_WAIT  = 8,
	WS_LAST_ACK    = 9,
	WS_LISTEN      = 10,
	WS_CLOSING     = 11
};

static int ett_netlink_sock_diag = -1;
static int ett_netlink_sock_diag_attr = -1;

static header_field_info hfi_netlink_sock_diag_family NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Family", "netlink-sock_diag.family", FT_UINT8, BASE_DEC | BASE_EXT_STRING,
	  &linux_af_vals_ext, 0x00, NULL, HFILL };

static const value_string socket_type_vals[] = {
	{ WS_SOCK_STREAM,	"SOCK_STREAM" },
	{ WS_SOCK_DGRAM,	"SOCK_DGRAM" },
	{ WS_SOCK_RAW,		"SOCK_RAW" },
	{ WS_SOCK_RDM,		"SOCK_RDM" },
	{ WS_SOCK_SEQPACKET,	"SOCK_SEQPACKET" },
	{ WS_SOCK_DCCP,		"SOCK_DCCP" },
	{ WS_SOCK_PACKET,	"SOCK_PACKET" },
	{ 0, NULL }
};

static header_field_info hfi_netlink_sock_diag_type NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Type", "netlink-sock_diag.nltype", FT_UINT8, BASE_DEC,
	  VALS(&socket_type_vals), 0x00, NULL, HFILL };

static const value_string socket_state_vals[] = {
	{ WS_ESTABLISHED, "ESTABLISHED" },
	{ WS_SYN_SENT,    "SYN_SENT" },
	{ WS_SYN_RECV,    "SYN_RECV" },
	{ WS_FIN_WAIT1,   "FIN_WAIT1" },
	{ WS_FIN_WAIT2,   "FIN_WAIT2" },
	{ WS_TIME_WAIT,   "TIME_WAIT" },
	{ WS_CLOSE,       "CLOSE" },
	{ WS_CLOSE_WAIT,  "CLOSE_WAIT" },
	{ WS_LAST_ACK,    "LAST_ACK" },
	{ WS_LISTEN,      "LISTEN" },
	{ WS_CLOSING,     "CLOSING" },
	{ 0, NULL }
};

static header_field_info hfi_netlink_sock_diag_state NETLINK_SOCK_DIAG_HFI_INIT =
	{ "State", "netlink-sock_diag.state", FT_UINT8, BASE_DEC,
	  VALS(&socket_state_vals), 0x00, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_inode NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Inode", "netlink-sock_diag.inode", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_rqueue NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Recv Queue", "netlink-sock_diag.recv_queue", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_wqueue NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Send Queue", "netlink-sock_diag.send_queue", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_cookie NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Cookie", "netlink-sock_diag.cookie", FT_UINT64, BASE_HEX,
	  NULL, 0x00, NULL, HFILL };

static void
netlink_proto_tree_add_cookie(proto_tree *tree, netlink_sock_diag_info_t *info _U_, tvbuff_t *tvb, int offset)
{
	guint64 cookie;

	cookie = tvb_get_letohl(tvb, offset + 4);
	cookie <<= 32;
	cookie |= tvb_get_letohl(tvb, offset);

	/* XXX support for INET_DIAG_NOCOOKIE (~0) */

	proto_tree_add_uint64(tree, hfi_netlink_sock_diag_cookie.id, tvb, offset, 8, cookie);
}

static const value_string netlink_sock_diag_shutdown_flags_vals[] = {
	{ 0, "No shutdown" },
	{ 1, "Read" },
	{ 2, "Write" },
	{ 3, "Read and Write" },
	{ 0, NULL }
};

static header_field_info hfi_netlink_sock_diag_shutdown NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Shutdown flag", "netlink-sock_diag.shutdown", FT_UINT8, BASE_HEX,
	  VALS(netlink_sock_diag_shutdown_flags_vals), 0x00, NULL, HFILL };

static void
netlink_proto_tree_add_shutdown(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	guint8 how = tvb_get_guint8(tvb, offset);

	proto_tree_add_item(tree, &hfi_netlink_sock_diag_shutdown, tvb, offset, 1, ENC_NA);

	proto_item_append_text(tree, ": %s", val_to_str(how, netlink_sock_diag_shutdown_flags_vals, "Invalid how value (%x)"));
}

/* AF_UNIX attributes */

static const value_string netlink_sock_diag_unix_attr_vals[] = {
	{ WS_UNIX_DIAG_NAME, "Name" },
	{ WS_UNIX_DIAG_VFS,  "VFS" },
	{ WS_UNIX_DIAG_PEER, "Peer" },
	{ WS_UNIX_DIAG_ICONS, "Icons" },
	{ WS_UNIX_DIAG_RQLEN, "RQ len" },
	{ WS_UNIX_DIAG_MEMINFO, "meminfo" },
	{ WS_UNIX_DIAG_SHUTDOWN, "shutdown" },
	{ 0, NULL }
};

static header_field_info hfi_netlink_sock_diag_unix_attr NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Type", "netlink-sock_diag.unix_attr", FT_UINT16, BASE_DEC,
	  VALS(&netlink_sock_diag_unix_attr_vals), 0x00, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_unix_name NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Name", "netlink-sock_diag.unix_name", FT_STRINGZ, STR_ASCII,
	  NULL, 0x00, NULL, HFILL };

static int
dissect_netlink_unix_sock_diag_reply_attrs(tvbuff_t *tvb, void *data, proto_tree *tree, int nla_type, int offset, int len)
{
	const netlink_sock_diag_info_t *info = (const netlink_sock_diag_info_t *) data;

	enum ws_unix_diag_attr_type type = (enum ws_unix_diag_attr_type) nla_type;

	switch (type) {
		case WS_UNIX_DIAG_NAME:
		{
			const char *name;

			/* XXX make it nicer */
			if (len > 0 && tvb_get_guint8(tvb, offset) == '\0') {
				name = wmem_strconcat(wmem_packet_scope(),
					"@",
					tvb_get_string_enc(wmem_packet_scope(), tvb, offset+1, len-1, ENC_ASCII | ENC_NA),
					NULL);
			} else
				name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, len, ENC_ASCII | ENC_NA);

			proto_item_append_text(tree, ": %s", name);
			proto_tree_add_string(tree, &hfi_netlink_sock_diag_unix_name, tvb, offset, len, name);
			return 1;
		}

		case WS_UNIX_DIAG_RQLEN:
			if (len == 8) {
				proto_tree_add_item(tree, &hfi_netlink_sock_diag_rqueue, tvb, offset, 4, info->encoding);
				proto_tree_add_item(tree, &hfi_netlink_sock_diag_wqueue, tvb, offset, 4, info->encoding);
				return 1;
			}
			return 0;

		case WS_UNIX_DIAG_SHUTDOWN:
			if (len == 1)
				netlink_proto_tree_add_shutdown(tree, tvb, offset);
			return 0;

		default:
			return 0;
	}
}

/* AF_UNIX */

static int
dissect_netlink_unix_sock_diag_reply(tvbuff_t *tvb, netlink_sock_diag_info_t *info, proto_tree *tree, int offset)
{
	proto_tree_add_item(tree, &hfi_netlink_sock_diag_family, tvb, offset, 1, ENC_NA);
	offset += 1;

	/* XXX, validate: SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET */
	proto_tree_add_item(tree, &hfi_netlink_sock_diag_type, tvb, offset, 1, ENC_NA);
	offset += 1;

	/* XXX, validate */
	proto_tree_add_item(tree, &hfi_netlink_sock_diag_state, tvb, offset, 1, ENC_NA);
	offset += 1;

	/* XXX 1B pad */
	offset += 1;

	proto_tree_add_item(tree, &hfi_netlink_sock_diag_inode, tvb, offset, 4, info->encoding);
	offset += 4;

	netlink_proto_tree_add_cookie(tree, info, tvb, offset);
	offset += 8;

	return dissect_netlink_attributes(tvb, &hfi_netlink_sock_diag_unix_attr, ett_netlink_sock_diag_attr, info, tree, offset, dissect_netlink_unix_sock_diag_reply_attrs);
}

/* AF_INET attributes */

static const value_string netlink_sock_diag_inet_attr_vals[] = {
	{ WS_INET_DIAG_MEMINFO,    "meminfo" },
	{ WS_INET_DIAG_INFO,       "info" },
	{ WS_INET_DIAG_VEGASINFO,  "vegasinfo" },
	{ WS_INET_DIAG_CONG,       "cong" },
	{ WS_INET_DIAG_TOS,        "tos" },
	{ WS_INET_DIAG_TCLASS,     "tclass" },
	{ WS_INET_DIAG_SKMEMINFO,  "skmeminfo" },
	{ WS_INET_DIAG_SHUTDOWN,   "shutdown" },
	{ 0, NULL }
};

static header_field_info hfi_netlink_sock_diag_inet_attr NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Type", "netlink-sock_diag.inet_attr", FT_UINT16, BASE_DEC,
	  VALS(&netlink_sock_diag_inet_attr_vals), 0x00, NULL, HFILL };

static int
dissect_netlink_inet_sock_diag_reply_attrs(tvbuff_t *tvb, void *data _U_, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_inet_diag_attr_type type = (enum ws_inet_diag_attr_type) nla_type;

	switch (type) {
		case WS_INET_DIAG_SHUTDOWN:
			if (len == 1)
				netlink_proto_tree_add_shutdown(tree, tvb, offset);
			return 0;

		default:
			return 0;
	}
}

/* AF_INET sockid */

static header_field_info hfi_netlink_sock_diag_inet_sport NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Source port", "netlink-sock_diag.inet_sport", FT_UINT16, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_inet_dport NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Dest port", "netlink-sock_diag.inet_dport", FT_UINT16, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_inet_src_ip4 NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Source IP", "netlink-sock_diag.inet_src_ip4", FT_IPv4, BASE_NONE,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_inet_dst_ip4 NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Dest IP", "netlink-sock_diag.inet_dest_ip4", FT_IPv4, BASE_NONE,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_inet_src_ip6 NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Source IP", "netlink-sock_diag.inet_src_ip6", FT_IPv6, BASE_NONE,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_inet_dst_ip6 NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Dest IP", "netlink-sock_diag.inet_dest_ip6", FT_IPv6, BASE_NONE,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_inet_interface NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Interface", "netlink-sock_diag.inet_interface", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

/* AF_INET */

static int
dissect_netlink_inet_sock_diag_sockid(tvbuff_t *tvb, netlink_sock_diag_info_t *info, proto_tree *tree, int offset, int family)
{
	proto_tree_add_item(tree, &hfi_netlink_sock_diag_inet_sport, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, &hfi_netlink_sock_diag_inet_dport, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	switch (family) {
		case LINUX_AF_INET:
			proto_tree_add_item(tree, &hfi_netlink_sock_diag_inet_src_ip4, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			/* XXX should be 12 '\0' */
			offset += 12;

			proto_tree_add_item(tree, &hfi_netlink_sock_diag_inet_dst_ip4, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			/* XXX should be 12 '\0' */
			offset += 12;
			break;

		case LINUX_AF_INET6:
			proto_tree_add_item(tree, &hfi_netlink_sock_diag_inet_src_ip6, tvb, offset, 16, ENC_NA);
			offset += 16;

			proto_tree_add_item(tree, &hfi_netlink_sock_diag_inet_dst_ip6, tvb, offset, 16, ENC_NA);
			offset += 16;
			break;

		default:
			/* XXX */
			offset += 32;
			break;
	}

	proto_tree_add_item(tree, &hfi_netlink_sock_diag_inet_interface, tvb, offset, 4, info->encoding);
	offset += 4;

	netlink_proto_tree_add_cookie(tree, info, tvb, offset);
	offset += 8;

	return offset;
}

static int
dissect_netlink_inet_sock_diag_reply(tvbuff_t *tvb, netlink_sock_diag_info_t *info, proto_tree *tree, int offset)
{
	guint8 af_family;

	af_family = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, &hfi_netlink_sock_diag_family, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, &hfi_netlink_sock_diag_state, tvb, offset, 1, ENC_NA);
	offset += 1;

	/* XXX timer retrans */
	offset += 2;

	offset = dissect_netlink_inet_sock_diag_sockid(tvb, info, tree, offset, af_family);

	/* XXX expires */
	offset += 4;

	proto_tree_add_item(tree, &hfi_netlink_sock_diag_rqueue, tvb, offset, 4, info->encoding);
	offset += 4;

	proto_tree_add_item(tree, &hfi_netlink_sock_diag_wqueue, tvb, offset, 4, info->encoding);
	offset += 4;

	/* XXX uid */
	offset += 4;

	proto_tree_add_item(tree, &hfi_netlink_sock_diag_inode, tvb, offset, 4, info->encoding);
	offset += 4;

	return dissect_netlink_attributes(tvb, &hfi_netlink_sock_diag_inet_attr, ett_netlink_sock_diag_attr, info, tree, offset, dissect_netlink_inet_sock_diag_reply_attrs);
}

/* main */

static const value_string netlink_sock_diag_type_vals[] = {
	{ WS_SOCK_DIAG_BY_FAMILY, "SOCK_DIAG_BY_FAMILY" },
	{ 0, NULL }
};

static header_field_info hfi_netlink_sock_diag_nltype NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Message type", "netlink-sock_diag.nltype", FT_UINT16, BASE_DEC,
	  VALS(netlink_sock_diag_type_vals), 0x00, NULL, HFILL };

static int
dissect_netlink_sock_diag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *_data)
{
	struct packet_netlink_data *data = NULL;
	netlink_sock_diag_info_t info;
	int offset;

	guint8 af_family;
	gboolean is_req;

	if (_data) {
		if (((struct packet_netlink_data *) _data)->magic == PACKET_NETLINK_MAGIC)
			data = (struct packet_netlink_data *) _data;
	}

	DISSECTOR_ASSERT(data);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Netlink sock diag");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		proto_item_set_text(tree, "Linux netlink sock diag message");

		/* XXX, from header tvb */
		proto_tree_add_uint(tree, &hfi_netlink_sock_diag_nltype, NULL, 0, 0, data->type);
	}

	info.encoding = data->encoding;
	info.pinfo = pinfo;
	info.data = data;

	is_req = (pinfo->p2p_dir == P2P_DIR_RECV);

	offset = 0;

	af_family = tvb_get_guint8(tvb, offset);

	switch (af_family) {
		case LINUX_AF_LOCAL:
			offset = (is_req) ?
				offset :
				dissect_netlink_unix_sock_diag_reply(tvb, &info, tree, offset);
			break;

		case LINUX_AF_INET:
			offset = (is_req) ?
				offset :
				dissect_netlink_inet_sock_diag_reply(tvb, &info, tree, offset);
			break;
	}

	return offset;
}

void
proto_register_netlink_sock_diag(void)
{
#ifndef HAVE_HFI_SECTION_INIT
	static header_field_info *hfi[] = {
		&hfi_netlink_sock_diag_nltype,

	/* common */
		&hfi_netlink_sock_diag_family,
		&hfi_netlink_sock_diag_type,
		&hfi_netlink_sock_diag_state,
		&hfi_netlink_sock_diag_inode,
		&hfi_netlink_sock_diag_rqueue,
		&hfi_netlink_sock_diag_wqueue,
		&hfi_netlink_sock_diag_shutdown,
		&hfi_netlink_sock_diag_cookie,

	/* AF_UNIX */
		&hfi_netlink_sock_diag_unix_attr,
		&hfi_netlink_sock_diag_unix_name,
	/* AF_INET */
		&hfi_netlink_sock_diag_inet_attr,
	/* AF_INET sockid */
		&hfi_netlink_sock_diag_inet_sport,
		&hfi_netlink_sock_diag_inet_dport,
		&hfi_netlink_sock_diag_inet_src_ip4,
		&hfi_netlink_sock_diag_inet_dst_ip4,
		&hfi_netlink_sock_diag_inet_interface
	};
#endif

	static gint *ett[] = {
		&ett_netlink_sock_diag,
		&ett_netlink_sock_diag_attr
	};

	int proto_netlink_sock_diag;

	proto_netlink_sock_diag = proto_register_protocol("Linux netlink sock diag protocol", "sock_diag", "netlink-sock_diag" );
	hfi_netlink_sock_diag = proto_registrar_get_nth(proto_netlink_sock_diag);

	proto_register_fields(proto_netlink_sock_diag, hfi, array_length(hfi));
	proto_register_subtree_array(ett, array_length(ett));

	netlink_sock_diag_handle = new_create_dissector_handle(dissect_netlink_sock_diag, proto_netlink_sock_diag);
}

void
proto_reg_handoff_netlink_sock_diag(void)
{
	dissector_add_uint("netlink.protocol", WS_NETLINK_SOCK_DIAG, netlink_sock_diag_handle);
}

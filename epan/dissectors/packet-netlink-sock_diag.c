/* packet-netlink-sock_diag.c
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
#include <epan/etypes.h>
#include <epan/ipproto.h>
#include "packet-netlink.h"

void proto_register_netlink_sock_diag(void);
void proto_reg_handoff_netlink_sock_diag(void);

typedef struct {
	packet_info *pinfo;
	struct packet_netlink_data *data;

	int encoding; /* copy of data->encoding */
} netlink_sock_diag_info_t;

static dissector_handle_t netlink_sock_diag_handle;

static header_field_info *hfi_netlink_sock_diag = NULL;

#define NETLINK_SOCK_DIAG_HFI_INIT HFI_INIT(proto_netlink_sock_diag)

enum {
/* sock diag values for nlmsghdr.nlmsg_type from: */

/* <linux/inet_diag.h> (compat) */
	WS_TCPDIAG_GETSOCK     = 18,
	WS_DCCPDIAG_GETSOCK    = 19,

/* <linux/sock_diag.h> */
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

enum ws_unix_diag_show_mask {
	/* show mask for unix diag from <linux/unix_diag.h> */
	WS_UDIAG_SHOW_NAME     = 0x01,
	WS_UDIAG_SHOW_VFS      = 0x02,
	WS_UDIAG_SHOW_PEER     = 0x04,
	WS_UDIAG_SHOW_ICONS    = 0x08,
	WS_UDIAG_SHOW_RQLEN    = 0x10,
	WS_UDIAG_SHOW_MEMINFO  = 0x20
};

enum ws_unix_diag_attr_type {
	/* netlink attributes for unix diag from <linux/unix_diag.h> */
	WS_UNIX_DIAG_NAME     = 0,
	WS_UNIX_DIAG_VFS      = 1,
	WS_UNIX_DIAG_PEER     = 2,
	WS_UNIX_DIAG_ICONS    = 3,
	WS_UNIX_DIAG_RQLEN    = 4,
	WS_UNIX_DIAG_MEMINFO  = 5,
	WS_UNIX_DIAG_SHUTDOWN = 6
};

enum ws_inet_diag_attr_type {
	/* netlink attributes for inet diag from <linux/inet_diag.h> */
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

enum ws_netlink_diag_show_type {
	/* show mask for netlink diag from <linux/netlink_diag.h> */
	WS_NDIAG_SHOW_MEMINFO   = 0x01,
	WS_NDIAG_SHOW_GROUPS    = 0x02,
	WS_NDIAG_SHOW_RING_CFG  = 0x04
};

enum ws_netlink_diag_attr_type {
	/* netlink attributes for netlink diag from <linux/netlink_diag.h> */
	WS_NETLINK_DIAG_MEMINFO = 0,
	WS_NETLINK_DIAG_GROUPS  = 1,
	WS_NETLINK_DIAG_RX_RING = 2,
	WS_NETLINK_DIAG_TX_RING = 3
};

enum ws_packet_diag_show_mask {
	/* show mask for packet diag from <linux/packet_diag.h> */
	WS_PACKET_SHOW_INFO        = 0x01,
	WS_PACKET_SHOW_MCLIST      = 0x02,
	WS_PACKET_SHOW_RING_CFG    = 0x04,
	WS_PACKET_SHOW_FANOUT      = 0x08,
	WS_PACKET_SHOW_MEMINFO     = 0x10,
	WS_PACKET_SHOW_FILTER      = 0x20
};

enum ws_packet_diag_attr_type {
	/* netlink attributes for packet diag from <linux/packet_diag.h> */
	WS_PACKET_DIAG_INFO     = 0,
	WS_PACKET_DIAG_MCLIST   = 1,
	WS_PACKET_DIAG_RX_RING  = 2,
	WS_PACKET_DIAG_TX_RING  = 3,
	WS_PACKET_DIAG_FANOUT   = 4,
	WS_PACKET_DIAG_UID      = 5,
	WS_PACKET_DIAG_MEMINFO  = 6,
	WS_PACKET_DIAG_FILTER   = 7
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
static int ett_netlink_sock_diag_show = -1;
static int ett_netlink_sock_diag_attr = -1;

static const true_false_string _tfs_show_do_not_show = { "Show", "Don't show" };

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
	{ "Type", "netlink-sock_diag.type", FT_UINT8, BASE_DEC,
	  VALS(socket_type_vals), 0x00, NULL, HFILL };

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
	  VALS(socket_state_vals), 0x00, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_inode NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Inode", "netlink-sock_diag.inode", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_rqueue NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Recv Queue", "netlink-sock_diag.recv_queue", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_wqueue NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Send Queue", "netlink-sock_diag.send_queue", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

/* Geneirc */

static int
_tvb_check_if_zeros(tvbuff_t *tvb, int offset, int len)
{
	/* padding, all bytes should be 0, if not display as unknown */
	while (len >= 0) {
		if (tvb_get_guint8(tvb, offset) != 0)
			return 1;

		offset++;
		len--;
	}
	return 0;
}

static void
_dissect_padding(proto_tree *tree _U_, tvbuff_t *tvb, int offset, int len)
{
	if (_tvb_check_if_zeros(tvb, offset, len)) {
		/* XXX, tree, expert info */
	}
}

/* Sock diag meminfo */

static header_field_info hfi_netlink_sock_diag_rmem_alloc NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Read allocation", "netlink-sock_diag.rmem_alloc", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_rcvbuf NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Recv buffer", "netlink-sock_diag.rcvbuf", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_wmem_alloc NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Write allocation", "netlink-sock_diag.wmem_alloc", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_sndbuf NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Send buffer", "netlink-sock_diag.sndbuf", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_fwd_alloc NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Forward allocation", "netlink-sock_diag.fwd_alloc", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_wmem_queued NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Write allocation queued", "netlink-sock_diag.wmem_queued", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static int
dissect_sock_diag_meminfo(proto_tree *tree, netlink_sock_diag_info_t *info, tvbuff_t *tvb, int offset, int len)
{
	static header_field_info *hfis[] = {
		&hfi_netlink_sock_diag_rmem_alloc,
		&hfi_netlink_sock_diag_rcvbuf,
		&hfi_netlink_sock_diag_wmem_alloc,
		&hfi_netlink_sock_diag_sndbuf,
		&hfi_netlink_sock_diag_fwd_alloc,
		&hfi_netlink_sock_diag_wmem_queued,
		/* XXX OPTMEM */
		/* XXX BACKLOG */
	};

	guint i;

	if (len == 0 || (len % 4) != 0)
		return 0;

	for (i = 0; len >= 4 && i < G_N_ELEMENTS(hfis); i++) {
		proto_tree_add_item(tree, hfis[i], tvb, offset, 4, info->encoding);
		offset += 4; len -= 4;
	}

	if (len != 0) {
		/* XXX, unknown */
	}

	return 1;
}

/* Sock diag Cookie */

static header_field_info hfi_netlink_sock_diag_cookie NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Cookie", "netlink-sock_diag.cookie", FT_UINT64, BASE_HEX,
	  NULL, 0x00, NULL, HFILL };

static void
sock_diag_proto_tree_add_cookie(proto_tree *tree, netlink_sock_diag_info_t *info _U_, tvbuff_t *tvb, int offset)
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
	{ 1, "Receptions disallowed" },
	{ 2, "Transmissions disallowed" },
	{ 3, "Receptions and transmissions disallowed" },
	{ 0, NULL }
};

static header_field_info hfi_netlink_sock_diag_shutdown NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Shutdown flag", "netlink-sock_diag.shutdown", FT_UINT8, BASE_HEX,
	  VALS(netlink_sock_diag_shutdown_flags_vals), 0x00, NULL, HFILL };

static void
sock_diag_proto_tree_add_shutdown(proto_tree *tree, tvbuff_t *tvb, int offset)
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
	  VALS(netlink_sock_diag_unix_attr_vals), 0x00, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_unix_name NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Name", "netlink-sock_diag.unix_name", FT_STRINGZ, STR_ASCII,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_unix_peer_inode NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Peer inode", "netlink-sock_diag.unix_peer_inode", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static int
dissect_netlink_unix_sock_diag_reply_attrs(tvbuff_t *tvb, void *data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_unix_diag_attr_type type = (enum ws_unix_diag_attr_type) nla_type;
	netlink_sock_diag_info_t *info = (netlink_sock_diag_info_t *) data;

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

		case WS_UNIX_DIAG_PEER:
			if (len == 4) {
				proto_item_append_text(tree, ": Peer inode %u", tvb_get_letohl(tvb, offset));
				proto_tree_add_item(tree, &hfi_netlink_sock_diag_unix_peer_inode, tvb, offset, 4, info->encoding);
				return 1;
			}
			return 0;

		case WS_UNIX_DIAG_RQLEN:
			if (len == 8) {
				/* XXX, if socket in WS_LISTEN it's reporting sk->sk_receive_queue.qlen, sk->sk_max_ack_backlog */
				proto_tree_add_item(tree, &hfi_netlink_sock_diag_rqueue, tvb, offset, 4, info->encoding);
				proto_tree_add_item(tree, &hfi_netlink_sock_diag_wqueue, tvb, offset, 4, info->encoding);
				return 1;
			}
			return 0;

		case WS_UNIX_DIAG_MEMINFO:
			return dissect_sock_diag_meminfo(tree, info, tvb, offset, len);

		case WS_UNIX_DIAG_SHUTDOWN:
			if (len == 1)
				sock_diag_proto_tree_add_shutdown(tree, tvb, offset);
			return 0;

		case WS_UNIX_DIAG_VFS:
		case WS_UNIX_DIAG_ICONS:
		default:
			return 0;
	}
}

/* AF_UNIX */

static int
dissect_sock_diag_unix_reply(tvbuff_t *tvb, netlink_sock_diag_info_t *info, proto_tree *tree, int offset)
{
	proto_tree_add_item(tree, &hfi_netlink_sock_diag_family, tvb, offset, 1, ENC_NA);
	offset += 1;

	/* XXX, validate: SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET */
	proto_tree_add_item(tree, &hfi_netlink_sock_diag_type, tvb, offset, 1, ENC_NA);
	offset += 1;

	/* XXX, validate */
	proto_tree_add_item(tree, &hfi_netlink_sock_diag_state, tvb, offset, 1, ENC_NA);
	offset += 1;

	_dissect_padding(tree, tvb, offset, 1);
	offset += 1;

	proto_tree_add_item(tree, &hfi_netlink_sock_diag_inode, tvb, offset, 4, info->encoding);
	offset += 4;

	sock_diag_proto_tree_add_cookie(tree, info, tvb, offset);
	offset += 8;

	return dissect_netlink_attributes(tvb, &hfi_netlink_sock_diag_unix_attr, ett_netlink_sock_diag_attr, info, tree, offset, dissect_netlink_unix_sock_diag_reply_attrs);
}

/* AF_UNIX request */

static header_field_info hfi_netlink_sock_diag_unix_show NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Show", "netlink-sock_diag.unix_show", FT_UINT32, BASE_HEX,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_unix_show_name NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Name", "netlink-sock_diag.unix_show.name", FT_BOOLEAN, 32,
	  &_tfs_show_do_not_show, WS_UDIAG_SHOW_NAME, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_unix_show_vfs NETLINK_SOCK_DIAG_HFI_INIT =
	{ "VFS inode info", "netlink-sock_diag.unix_show.vfs", FT_BOOLEAN, 32,
	  &_tfs_show_do_not_show, WS_UDIAG_SHOW_VFS, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_unix_show_peer NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Peer socket info", "netlink-sock_diag.unix_show.peer", FT_BOOLEAN, 32,
	  &_tfs_show_do_not_show, WS_UDIAG_SHOW_PEER, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_unix_show_icons NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Pending connections", "netlink-sock_diag.unix_show.icons", FT_BOOLEAN, 32,
	  &_tfs_show_do_not_show, WS_UDIAG_SHOW_ICONS, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_unix_show_rqlen NETLINK_SOCK_DIAG_HFI_INIT =
	{ "skb receive queue len", "netlink-sock_diag.unix_show.rqlen", FT_BOOLEAN, 32,
	  &_tfs_show_do_not_show, WS_UDIAG_SHOW_RQLEN, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_unix_show_meminfo NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Memory info of a socket", "netlink-sock_diag.unix_show.rqlen", FT_BOOLEAN, 32,
	  &_tfs_show_do_not_show, WS_UDIAG_SHOW_MEMINFO, NULL, HFILL };

static int
dissect_sock_diag_unix_request_show(tvbuff_t *tvb, netlink_sock_diag_info_t *info, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_tree *flags_tree;

	ti = proto_tree_add_item(tree, &hfi_netlink_sock_diag_unix_show, tvb, offset, 4, info->encoding);
	flags_tree = proto_item_add_subtree(ti, ett_netlink_sock_diag_show);

	proto_tree_add_item(flags_tree, &hfi_netlink_sock_diag_unix_show_name, tvb, offset, 4, info->encoding);
	proto_tree_add_item(flags_tree, &hfi_netlink_sock_diag_unix_show_vfs, tvb, offset, 4, info->encoding);
	proto_tree_add_item(flags_tree, &hfi_netlink_sock_diag_unix_show_peer, tvb, offset, 4, info->encoding);
	proto_tree_add_item(flags_tree, &hfi_netlink_sock_diag_unix_show_icons, tvb, offset, 4, info->encoding);
	proto_tree_add_item(flags_tree, &hfi_netlink_sock_diag_unix_show_rqlen, tvb, offset, 4, info->encoding);
	proto_tree_add_item(flags_tree, &hfi_netlink_sock_diag_unix_show_meminfo, tvb, offset, 4, info->encoding);
	/* XXX, unknown */

	offset += 4;

	return offset;
}

static int
dissect_sock_diag_unix_request(tvbuff_t *tvb, netlink_sock_diag_info_t *info, proto_tree *tree, int offset)
{
	proto_tree_add_item(tree, &hfi_netlink_sock_diag_family, tvb, offset, 1, ENC_NA);
	offset += 1;

	/* XXX, AF_UNIX don't have protocols - 0 */
	offset += 1;

	_dissect_padding(tree, tvb, offset, 2);
	offset += 2;

	/* states */
	offset += 4;

	proto_tree_add_item(tree, &hfi_netlink_sock_diag_inode, tvb, offset, 4, info->encoding);
	offset += 4;

	offset = dissect_sock_diag_unix_request_show(tvb, info, tree, offset);

	sock_diag_proto_tree_add_cookie(tree, info, tvb, offset);
	offset += 8;

	return offset;
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
	  VALS(netlink_sock_diag_inet_attr_vals), 0x00, NULL, HFILL };

static int
dissect_sock_diag_inet_attributes(tvbuff_t *tvb, void *data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_inet_diag_attr_type type = (enum ws_inet_diag_attr_type) nla_type;
	netlink_sock_diag_info_t *info = (netlink_sock_diag_info_t *) data;

	switch (type) {
		case WS_INET_DIAG_MEMINFO:
			if (len == 16) {
				proto_tree_add_item(tree, &hfi_netlink_sock_diag_rmem_alloc, tvb, offset, 4, info->encoding);
				offset += 4;

				proto_tree_add_item(tree, &hfi_netlink_sock_diag_wmem_queued, tvb, offset, 4, info->encoding);
				offset += 4;

				proto_tree_add_item(tree, &hfi_netlink_sock_diag_fwd_alloc, tvb, offset, 4, info->encoding);
				offset += 4;

				proto_tree_add_item(tree, &hfi_netlink_sock_diag_wmem_alloc, tvb, offset, 4, info->encoding);
				/*offset += 4;*/

				return 1;
			}
			return 0;

		case WS_INET_DIAG_SKMEMINFO:
			return dissect_sock_diag_meminfo(tree, info, tvb, offset, len);

		case WS_INET_DIAG_SHUTDOWN:
			if (len == 1)
				sock_diag_proto_tree_add_shutdown(tree, tvb, offset);
			return 0;

		case WS_INET_DIAG_INFO:
		case WS_INET_DIAG_VEGASINFO:
		case WS_INET_DIAG_CONG:
		case WS_INET_DIAG_TOS:
		case WS_INET_DIAG_TCLASS:
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

static int
dissect_sock_diag_inet_sockid(tvbuff_t *tvb, netlink_sock_diag_info_t *info, proto_tree *tree, int offset, int family)
{
	proto_tree_add_item(tree, &hfi_netlink_sock_diag_inet_sport, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, &hfi_netlink_sock_diag_inet_dport, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	switch (family) {
		case LINUX_AF_INET:
			proto_tree_add_item(tree, &hfi_netlink_sock_diag_inet_src_ip4, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			_dissect_padding(tree, tvb, offset, 12);
			offset += 12;

			proto_tree_add_item(tree, &hfi_netlink_sock_diag_inet_dst_ip4, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			_dissect_padding(tree, tvb, offset, 12);
			offset += 12;
			break;

		case LINUX_AF_INET6:
			proto_tree_add_item(tree, &hfi_netlink_sock_diag_inet_src_ip6, tvb, offset, 16, ENC_NA);
			offset += 16;

			proto_tree_add_item(tree, &hfi_netlink_sock_diag_inet_dst_ip6, tvb, offset, 16, ENC_NA);
			offset += 16;
			break;

		default:
			DISSECTOR_ASSERT_NOT_REACHED();
			break;
	}

	proto_tree_add_item(tree, &hfi_netlink_sock_diag_inet_interface, tvb, offset, 4, info->encoding);
	offset += 4;

	sock_diag_proto_tree_add_cookie(tree, info, tvb, offset);
	offset += 8;

	return offset;
}

/* AF_INET */

static header_field_info hfi_netlink_sock_diag_inet_proto NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Protocol", "netlink-sock_diag.inet_protocol", FT_UINT8, BASE_DEC | BASE_EXT_STRING,
	  &ipproto_val_ext, 0x00, NULL, HFILL };
	  /* XXX Linux has also IPPROTO_RAW - 255 */

static int
dissect_sock_diag_inet_reply(tvbuff_t *tvb, netlink_sock_diag_info_t *info, proto_tree *tree, int offset)
{
	guint8 af_family;

	af_family = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, &hfi_netlink_sock_diag_family, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, &hfi_netlink_sock_diag_state, tvb, offset, 1, ENC_NA);
	offset += 1;

	/* XXX timer retrans */
	offset += 2;

	offset = dissect_sock_diag_inet_sockid(tvb, info, tree, offset, af_family);

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

	return dissect_netlink_attributes(tvb, &hfi_netlink_sock_diag_inet_attr, ett_netlink_sock_diag_attr, info, tree, offset, dissect_sock_diag_inet_attributes);
}

/* AF_INET request */

static int
dissect_sock_diag_inet_request(tvbuff_t *tvb, netlink_sock_diag_info_t *info, proto_tree *tree, int offset)
{
	guint8 af_family;

	af_family = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, &hfi_netlink_sock_diag_family, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, &hfi_netlink_sock_diag_inet_proto, tvb, offset, 1, ENC_NA);
	offset += 1;

	/* XXX ext: INET_DIAG_MEMINFO, INET_DIAG_INFO, ... */
	offset += 1;

	_dissect_padding(tree, tvb, offset, 1);
	offset += 1;

	/* XXX states (bit of sk_state) */
	offset += 4;

	offset = dissect_sock_diag_inet_sockid(tvb, info, tree, offset, af_family);

	return offset;
}

/* AF_NETLINK attributes */

static const value_string netlink_sock_diag_netlink_vals[] = {
	{ WS_NETLINK_DIAG_MEMINFO,  "Memory info" },
	{ WS_NETLINK_DIAG_GROUPS,   "groups" },
	{ WS_NETLINK_DIAG_RX_RING,  "RX ring configuration" },
	{ WS_NETLINK_DIAG_TX_RING,  "TX ring configuration" },
	{ 0, NULL }
};

static header_field_info hfi_netlink_sock_diag_netlink_attr NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Type", "netlink-sock_diag.netlink_attr", FT_UINT16, BASE_DEC,
	  VALS(netlink_sock_diag_netlink_vals), 0x00, NULL, HFILL };

static int
dissect_sock_diag_netlink_attributes(tvbuff_t *tvb, void *data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_netlink_diag_attr_type type = (enum ws_netlink_diag_attr_type) nla_type;
	netlink_sock_diag_info_t *info = (netlink_sock_diag_info_t *) data;

	switch (type) {
		case WS_NETLINK_DIAG_MEMINFO:
			return dissect_sock_diag_meminfo(tree, info, tvb, offset, len);

		case WS_NETLINK_DIAG_GROUPS:
		case WS_NETLINK_DIAG_RX_RING:
		case WS_NETLINK_DIAG_TX_RING:
		default:
			return 0;
	}
}

/* AF_NETLINK */

static header_field_info hfi_netlink_sock_diag_netlink_proto NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Protocol", "netlink-sock_diag.netlink_protocol", FT_UINT8, BASE_DEC | BASE_EXT_STRING,
	  &netlink_family_vals_ext, 0x00, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_netlink_port_id NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Port ID", "netlink-sock_diag.netlink_portid", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_netlink_dst_port_id NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Dest Port ID", "netlink-sock_diag.netlink_dst_portid", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static int
dissect_sock_diag_netlink_reply(tvbuff_t *tvb, netlink_sock_diag_info_t *info, proto_tree *tree, int offset)
{
	proto_tree_add_item(tree, &hfi_netlink_sock_diag_family, tvb, offset, 1, ENC_NA);
	offset += 1;

	/* ti = */ proto_tree_add_item(tree, &hfi_netlink_sock_diag_type, tvb, offset, 1, ENC_NA);
	switch (tvb_get_guint8(tvb, offset)) {
		case WS_SOCK_DGRAM:
		case WS_SOCK_RAW:
			break;
		default:
			/* XXX expert_add_info(info->pinfo, ti, &ei_netlink_sock_diag_incorrect_type); */
			break;
	}
	offset += 1;

	proto_tree_add_item(tree, &hfi_netlink_sock_diag_netlink_proto, tvb, offset, 1, ENC_NA);
	offset += 1;

	/* XXX, validate */
	proto_tree_add_item(tree, &hfi_netlink_sock_diag_state, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, &hfi_netlink_sock_diag_netlink_port_id, tvb, offset, 4, info->encoding);
	offset += 4;

	proto_tree_add_item(tree, &hfi_netlink_sock_diag_netlink_dst_port_id, tvb, offset, 4, info->encoding);
	offset += 4;

	/* XXX dst group */
	offset += 4;

	proto_tree_add_item(tree, &hfi_netlink_sock_diag_inode, tvb, offset, 4, info->encoding);
	offset += 4;

	sock_diag_proto_tree_add_cookie(tree, info, tvb, offset);
	offset += 8;

	return dissect_netlink_attributes(tvb, &hfi_netlink_sock_diag_netlink_attr, ett_netlink_sock_diag_attr, info, tree, offset, dissect_sock_diag_netlink_attributes);
}

/* AF_NETLINK request */

static header_field_info hfi_netlink_sock_diag_netlink_show NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Show", "netlink-sock_diag.netlink_show", FT_UINT32, BASE_HEX,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_netlink_show_meminfo NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Memory info of a socket", "netlink-sock_diag.netlink_show.meminfo", FT_BOOLEAN, 32,
	  &_tfs_show_do_not_show, WS_NDIAG_SHOW_MEMINFO, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_netlink_show_groups NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Groups of a netlink socket", "netlink-sock_diag.netlink_show.groups", FT_BOOLEAN, 32,
	  &_tfs_show_do_not_show, WS_NDIAG_SHOW_GROUPS, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_netlink_show_ring_cfg NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Ring configuration", "netlink-sock_diag.netlink_show.ring_cfg", FT_BOOLEAN, 32,
	  &_tfs_show_do_not_show, WS_NDIAG_SHOW_RING_CFG, NULL, HFILL };

static int
dissect_sock_diag_netlink_request_show(tvbuff_t *tvb, netlink_sock_diag_info_t *info, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_tree *flags_tree;

	ti = proto_tree_add_item(tree, &hfi_netlink_sock_diag_netlink_show, tvb, offset, 4, info->encoding);
	flags_tree = proto_item_add_subtree(ti, ett_netlink_sock_diag_show);

	proto_tree_add_item(flags_tree, &hfi_netlink_sock_diag_netlink_show_meminfo, tvb, offset, 4, info->encoding);
	proto_tree_add_item(flags_tree, &hfi_netlink_sock_diag_netlink_show_groups, tvb, offset, 4, info->encoding);
	proto_tree_add_item(flags_tree, &hfi_netlink_sock_diag_netlink_show_ring_cfg, tvb, offset, 4, info->encoding);
	/* XXX, unknown */

	offset += 4;

	return offset;
}

static int
dissect_sock_diag_netlink_request(tvbuff_t *tvb, netlink_sock_diag_info_t *info, proto_tree *tree, int offset)
{
	/* XXX, 255 for all */
	proto_tree_add_item(tree, &hfi_netlink_sock_diag_family, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, &hfi_netlink_sock_diag_netlink_proto, tvb, offset, 1, ENC_NA);
	offset += 1;

	_dissect_padding(tree, tvb, offset, 2);
	offset += 2;

	proto_tree_add_item(tree, &hfi_netlink_sock_diag_inode, tvb, offset, 4, info->encoding);
	offset += 4;

	offset = dissect_sock_diag_netlink_request_show(tvb, info, tree, offset);

	sock_diag_proto_tree_add_cookie(tree, info, tvb, offset);
	offset += 8;

	return offset;
}

/* AF_PACKET attributes */

static int
dissect_netlink_packet_sock_diag_reply_attrs(tvbuff_t *tvb, void *data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_packet_diag_attr_type type = (enum ws_packet_diag_attr_type) nla_type;
	netlink_sock_diag_info_t *info = (netlink_sock_diag_info_t *) data;

	switch (type) {
		case WS_PACKET_DIAG_MEMINFO:
			return dissect_sock_diag_meminfo(tree, info, tvb, offset, len);

		case WS_PACKET_DIAG_INFO:
		case WS_PACKET_DIAG_MCLIST:
		case WS_PACKET_DIAG_RX_RING:
		case WS_PACKET_DIAG_TX_RING:
		case WS_PACKET_DIAG_FANOUT:
		case WS_PACKET_DIAG_UID:
		case WS_PACKET_DIAG_FILTER:
		default:
			return 0;
	}
}

static const value_string netlink_sock_diag_packet_vals[] = {
	{ WS_PACKET_DIAG_INFO,    "info" },
	{ WS_PACKET_DIAG_MCLIST,  "mclist" },
	{ WS_PACKET_DIAG_RX_RING, "rxring" },
	{ WS_PACKET_DIAG_TX_RING, "txring" },
	{ WS_PACKET_DIAG_FANOUT,  "fanout" },
	{ WS_PACKET_DIAG_UID,     "uid" },
	{ WS_PACKET_DIAG_MEMINFO, "meminfo" },
	{ WS_PACKET_DIAG_FILTER,  "filter" },
	{ 0, NULL }
};

static header_field_info hfi_netlink_sock_diag_packet_attr NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Type", "netlink-sock_diag.netlink_attr", FT_UINT16, BASE_DEC,
	  VALS(netlink_sock_diag_packet_vals), 0x00, NULL, HFILL };

/* AF_PACKET */

static header_field_info hfi_netlink_sock_diag_packet_proto NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Protocol", "netlink-sock_diag.packet_protocol", FT_UINT16, BASE_HEX,
	  VALS(etype_vals) /* XXX + Linux specific */, 0x00, NULL, HFILL };

static int
dissect_sock_diag_packet_reply(tvbuff_t *tvb, netlink_sock_diag_info_t *info, proto_tree *tree, int offset)
{
	proto_tree_add_item(tree, &hfi_netlink_sock_diag_family, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, &hfi_netlink_sock_diag_type, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, &hfi_netlink_sock_diag_packet_proto, tvb, offset, 2, info->encoding);
	offset += 2;

	proto_tree_add_item(tree, &hfi_netlink_sock_diag_inode, tvb, offset, 4, info->encoding);
	offset += 4;

	sock_diag_proto_tree_add_cookie(tree, info, tvb, offset);
	offset += 8;

	return dissect_netlink_attributes(tvb, &hfi_netlink_sock_diag_packet_attr, ett_netlink_sock_diag_attr, info, tree, offset, dissect_netlink_packet_sock_diag_reply_attrs);
}

/* AF_PACKET request */

static header_field_info hfi_netlink_sock_diag_packet_show NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Show", "netlink-sock_diag.packet_show", FT_UINT32, BASE_HEX,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_packet_show_info NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Basic packet_sk information", "netlink-sock_diag.packet_show.info", FT_BOOLEAN, 32,
	  &_tfs_show_do_not_show, WS_PACKET_SHOW_INFO, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_packet_show_mclist NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Set of packet_diag_mclist-s", "netlink-sock_diag.packet_show.mclist", FT_BOOLEAN, 32,
	  &_tfs_show_do_not_show, WS_PACKET_SHOW_MCLIST, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_packet_show_ring_cfg NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Rings configuration parameters", "netlink-sock_diag.packet_show.ring_cfg", FT_BOOLEAN, 32,
	  &_tfs_show_do_not_show, WS_PACKET_SHOW_RING_CFG, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_packet_show_fanout NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Fanout", "netlink-sock_diag.packet_show.fanout", FT_BOOLEAN, 32,
	  &_tfs_show_do_not_show, WS_PACKET_SHOW_FANOUT, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_packet_show_meminfo NETLINK_SOCK_DIAG_HFI_INIT =
	{ "memory info", "netlink-sock_diag.packet_show.meminfo", FT_BOOLEAN, 32,
	  &_tfs_show_do_not_show, WS_PACKET_SHOW_MEMINFO, NULL, HFILL };

static header_field_info hfi_netlink_sock_diag_packet_show_filter NETLINK_SOCK_DIAG_HFI_INIT =
	{ "Filter", "netlink-sock_diag.packet_show.filter", FT_BOOLEAN, 32,
	  &_tfs_show_do_not_show, WS_PACKET_SHOW_FILTER, NULL, HFILL };

static int
dissect_sock_diag_packet_request_show(tvbuff_t *tvb, netlink_sock_diag_info_t *info, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_tree *flags_tree;

	ti = proto_tree_add_item(tree, &hfi_netlink_sock_diag_packet_show, tvb, offset, 4, info->encoding);
	flags_tree = proto_item_add_subtree(ti, ett_netlink_sock_diag_show);

	proto_tree_add_item(flags_tree, &hfi_netlink_sock_diag_packet_show_info, tvb, offset, 4, info->encoding);
	proto_tree_add_item(flags_tree, &hfi_netlink_sock_diag_packet_show_mclist, tvb, offset, 4, info->encoding);
	proto_tree_add_item(flags_tree, &hfi_netlink_sock_diag_packet_show_ring_cfg, tvb, offset, 4, info->encoding);
	proto_tree_add_item(flags_tree, &hfi_netlink_sock_diag_packet_show_fanout, tvb, offset, 4, info->encoding);
	proto_tree_add_item(flags_tree, &hfi_netlink_sock_diag_packet_show_meminfo, tvb, offset, 4, info->encoding);
	proto_tree_add_item(flags_tree, &hfi_netlink_sock_diag_packet_show_filter, tvb, offset, 4, info->encoding);
	/* XXX, unknown */

	offset += 4;

	return offset;
}

static int
dissect_sock_diag_packet_request(tvbuff_t *tvb, netlink_sock_diag_info_t *info, proto_tree *tree, int offset)
{
	proto_tree_add_item(tree, &hfi_netlink_sock_diag_family, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, &hfi_netlink_sock_diag_packet_proto, tvb, offset, 1, ENC_NA);
	offset += 1;

	_dissect_padding(tree, tvb, offset, 2);
	offset += 2;

	proto_tree_add_item(tree, &hfi_netlink_sock_diag_inode, tvb, offset, 4, info->encoding);
	offset += 4;

	offset = dissect_sock_diag_packet_request_show(tvb, info, tree, offset);

	sock_diag_proto_tree_add_cookie(tree, info, tvb, offset);
	offset += 8;

	return offset;
}

/* WS_SOCK_DIAG_BY_FAMILY dissection */

static int
dissect_sock_diag_by_family(tvbuff_t *tvb, netlink_sock_diag_info_t *info, proto_tree *tree, int offset)
{
	const gboolean is_req = (info->pinfo->p2p_dir == P2P_DIR_SENT);
	guint8 af_family;

	af_family = tvb_get_guint8(tvb, offset);

	switch (af_family) {
		case LINUX_AF_LOCAL:
			offset = (is_req) ?
				dissect_sock_diag_unix_request(tvb, info, tree, offset) :
				dissect_sock_diag_unix_reply(tvb, info, tree, offset);
			break;

		case LINUX_AF_INET:
		case LINUX_AF_INET6:
			offset = (is_req) ?
				dissect_sock_diag_inet_request(tvb, info, tree, offset) :
				dissect_sock_diag_inet_reply(tvb, info, tree, offset);
			break;

		case LINUX_AF_NETLINK:
			offset = (is_req) ?
				dissect_sock_diag_netlink_request(tvb, info, tree, offset) :
				dissect_sock_diag_netlink_reply(tvb, info, tree, offset);
			break;

		case LINUX_AF_PACKET:
			offset = (is_req) ?
				dissect_sock_diag_packet_request(tvb, info, tree, offset) :
				dissect_sock_diag_packet_reply(tvb, info, tree, offset);
			break;
	}

	return offset;
}

static const value_string netlink_sock_diag_type_vals[] = {
	{ WS_TCPDIAG_GETSOCK,     "TCPDIAG_GETSOCK" },
	{ WS_DCCPDIAG_GETSOCK,    "DCCPDIAG_GETSOCK" },
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

	offset = 0;

	switch (data->type) {
		case WS_TCPDIAG_GETSOCK:
		case WS_DCCPDIAG_GETSOCK:
			/* XXX, inet_diag_rcv_msg_compat */
			break;

		case WS_SOCK_DIAG_BY_FAMILY:
			offset = dissect_sock_diag_by_family(tvb, &info, tree, offset);
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
	/* common meminfo */
		&hfi_netlink_sock_diag_rmem_alloc,
		&hfi_netlink_sock_diag_rcvbuf,
		&hfi_netlink_sock_diag_wmem_alloc,
		&hfi_netlink_sock_diag_sndbuf,
		&hfi_netlink_sock_diag_fwd_alloc,
		&hfi_netlink_sock_diag_wmem_queued,

	/* AF_UNIX */
		&hfi_netlink_sock_diag_unix_show,
		&hfi_netlink_sock_diag_unix_show_name,
		&hfi_netlink_sock_diag_unix_show_vfs,
		&hfi_netlink_sock_diag_unix_show_peer,
		&hfi_netlink_sock_diag_unix_show_icons,
		&hfi_netlink_sock_diag_unix_show_rqlen,
		&hfi_netlink_sock_diag_unix_show_meminfo,
		&hfi_netlink_sock_diag_unix_attr,
		&hfi_netlink_sock_diag_unix_name,
		&hfi_netlink_sock_diag_unix_peer_inode,

	/* AF_INET */
		&hfi_netlink_sock_diag_inet_proto,
		&hfi_netlink_sock_diag_inet_attr,
	/* AF_INET sockid */
		&hfi_netlink_sock_diag_inet_sport,
		&hfi_netlink_sock_diag_inet_dport,
		&hfi_netlink_sock_diag_inet_src_ip4,
		&hfi_netlink_sock_diag_inet_dst_ip4,
		&hfi_netlink_sock_diag_inet_src_ip6,
		&hfi_netlink_sock_diag_inet_dst_ip6,
		&hfi_netlink_sock_diag_inet_interface,

	/* AF_NETLINK */
		&hfi_netlink_sock_diag_netlink_show,
		&hfi_netlink_sock_diag_netlink_show_meminfo,
		&hfi_netlink_sock_diag_netlink_show_groups,
		&hfi_netlink_sock_diag_netlink_show_ring_cfg,
		&hfi_netlink_sock_diag_netlink_proto,
		&hfi_netlink_sock_diag_netlink_attr,
		&hfi_netlink_sock_diag_netlink_port_id,
		&hfi_netlink_sock_diag_netlink_dst_port_id,

	/* AF_PACKET */
		&hfi_netlink_sock_diag_packet_show,
		&hfi_netlink_sock_diag_packet_show_info,
		&hfi_netlink_sock_diag_packet_show_mclist,
		&hfi_netlink_sock_diag_packet_show_ring_cfg,
		&hfi_netlink_sock_diag_packet_show_fanout,
		&hfi_netlink_sock_diag_packet_show_meminfo,
		&hfi_netlink_sock_diag_packet_show_filter,
		&hfi_netlink_sock_diag_packet_proto,
		&hfi_netlink_sock_diag_packet_attr
	};
#endif

	static gint *ett[] = {
		&ett_netlink_sock_diag,
		&ett_netlink_sock_diag_show,
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

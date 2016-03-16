/* packet-netlink-netfilter.c
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

#include <epan/packet.h>
#include "packet-netlink.h"

void proto_register_netlink_netfilter(void);
void proto_reg_handoff_netlink_netfilter(void);

typedef struct {
	packet_info *pinfo;
	struct packet_netlink_data *data;

	int encoding; /* copy of data->encoding */
} netlink_netfilter_info_t;


static dissector_handle_t netlink_netfilter;
static dissector_handle_t nflog_handle;

static header_field_info *hfi_netlink_netfilter = NULL;

#define NETLINK_NETFILTER_HFI_INIT HFI_INIT(proto_netlink_netfilter)

/* nfnetlink subsystems from <linux/netfilter/nfnetlink.h> */
enum {
	WS_NFNL_SUBSYS_NONE              =  0,
	WS_NFNL_SUBSYS_CTNETLINK         =  1,
	WS_NFNL_SUBSYS_CTNETLINK_EXP     =  2,
	WS_NFNL_SUBSYS_QUEUE             =  3,
	WS_NFNL_SUBSYS_ULOG              =  4,
	WS_NFNL_SUBSYS_OSF               =  5,
	WS_NFNL_SUBSYS_IPSET             =  6,
	WS_NFNL_SUBSYS_ACCT              =  7,
	WS_NFNL_SUBSYS_CTNETLINK_TIMEOUT =  8,
	WS_NFNL_SUBSYS_CTHELPER          =  9
};

/* nfnetlink ULOG subsystem types from <linux/netfilter/nfnetlink_log.h> */
enum ws_nfulnl_msg_types {
	WS_NFULNL_MSG_PACKET = 0,
	WS_NFULNL_MSG_CONFIG = 1
};

/* nfnetlink QUEUE subsystem types from <linux/netfilter/nfnetlink_queue.h> */
enum ws_nfqnl_msg_types {
	WS_NFQNL_MSG_PACKET         = 0,
	WS_NFQNL_MSG_VERDICT        = 1,
	WS_NFQNL_MSG_CONFIG         = 2,
	WS_NFQNL_MSG_VERDICT_BATCH  = 3
};

static int ett_netlink_netfilter = -1;

/* QUEUE */

static const value_string netlink_netfilter_queue_type_vals[] = {
	{ WS_NFQNL_MSG_PACKET,		"Packet" },
	{ WS_NFQNL_MSG_VERDICT,		"Verdict" },
	{ WS_NFQNL_MSG_CONFIG,		"Config" },
	{ WS_NFQNL_MSG_VERDICT_BATCH,	"Verdict (batch)" },
	{ 0, NULL }
};

static header_field_info hfi_netlink_netfilter_queue_type NETLINK_NETFILTER_HFI_INIT =
	{ "Type", "netlink-netfilter.queue_type", FT_UINT16, BASE_DEC,
	  VALS(netlink_netfilter_queue_type_vals), 0x00FF, NULL, HFILL };

static int
dissect_netfilter_queue(tvbuff_t *tvb _U_, netlink_netfilter_info_t *info, proto_tree *tree, int offset)
{
	enum ws_nfqnl_msg_types type = (enum ws_nfqnl_msg_types) (info->data->type & 0xff);

	proto_tree_add_uint(tree, &hfi_netlink_netfilter_queue_type, NULL, 0, 0, info->data->type);

	switch (type) {
		default:
			break;
	}

	return offset;
}

/* ULOG */

static const value_string netlink_netfilter_ulog_type_vals[] = {
	{ WS_NFULNL_MSG_PACKET, "Packet" },
	{ WS_NFULNL_MSG_CONFIG, "Config" },
	{ 0, NULL }
};

static header_field_info hfi_netlink_netfilter_ulog_type NETLINK_NETFILTER_HFI_INIT =
	{ "Type", "netlink-netfilter.ulog_type", FT_UINT16, BASE_DEC,
	  VALS(netlink_netfilter_ulog_type_vals), 0x00FF, NULL, HFILL };

static int
dissect_netfilter_ulog(tvbuff_t *tvb, netlink_netfilter_info_t *info, proto_tree *tree, int offset)
{
	enum ws_nfulnl_msg_types type = (enum ws_nfulnl_msg_types) (info->data->type & 0xff);

	proto_tree_add_uint(tree, &hfi_netlink_netfilter_ulog_type, NULL, 0, 0, info->data->type);

	switch (type) {
		case WS_NFULNL_MSG_PACKET:
			call_dissector(nflog_handle, tvb, info->pinfo, tree);
			break;

		default:
			break;
	}

	return offset;
}

static const value_string netlink_netfilter_subsystem_vals[] = {
	{ WS_NFNL_SUBSYS_NONE,		    "None" },
	{ WS_NFNL_SUBSYS_CTNETLINK,	    "Conntrack" },
	{ WS_NFNL_SUBSYS_CTNETLINK_EXP,	    "Conntrack expect" },
	{ WS_NFNL_SUBSYS_QUEUE,		    "Netfilter packet queue" },
	{ WS_NFNL_SUBSYS_ULOG,		    "Netfilter userspace logging" },
	{ WS_NFNL_SUBSYS_OSF,		    "OS fingerprint" },
	{ WS_NFNL_SUBSYS_IPSET,		    "IP set" },
	{ WS_NFNL_SUBSYS_ACCT,		    "Extended Netfilter accounting infrastructure" },
	{ WS_NFNL_SUBSYS_CTNETLINK_TIMEOUT, "Extended Netfilter Connection Tracking timeout tuning" },
	{ WS_NFNL_SUBSYS_CTHELPER,	    "Connection Tracking Helpers" },
	{ 0, NULL }
};

static header_field_info hfi_netlink_netfilter_subsys NETLINK_NETFILTER_HFI_INIT =
	{ "Subsystem", "netlink-netfilter.subsys", FT_UINT16, BASE_DEC,
	  VALS(netlink_netfilter_subsystem_vals), 0xFF00, NULL, HFILL };

static int
dissect_netlink_netfilter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *_data)
{
	struct packet_netlink_data *data = NULL;
	netlink_netfilter_info_t info;
	int offset;

	if (_data) {
		if (((struct packet_netlink_data *) _data)->magic == PACKET_NETLINK_MAGIC)
			data = (struct packet_netlink_data *) _data;
	}

	DISSECTOR_ASSERT(data);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Netlink netfilter");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		proto_item_set_text(tree, "Linux netlink netfilter message");

		/* XXX, from header tvb */
		proto_tree_add_uint(tree, &hfi_netlink_netfilter_subsys, NULL, 0, 0, data->type);
	}

	info.encoding = data->encoding;
	info.pinfo = pinfo;
	info.data = data;

	offset = 0;

	switch (data->type >> 8) {
		case WS_NFNL_SUBSYS_QUEUE:
			offset = dissect_netfilter_queue(tvb, &info, tree, offset);
			break;

		case WS_NFNL_SUBSYS_ULOG:
			offset = dissect_netfilter_ulog(tvb, &info, tree, offset);
			break;
	}

	return offset;
}

void
proto_register_netlink_netfilter(void)
{
#ifndef HAVE_HFI_SECTION_INIT
	static header_field_info *hfi[] = {
		&hfi_netlink_netfilter_subsys,

	/* QUEUE */
		&hfi_netlink_netfilter_queue_type,
	/* ULOG */
		&hfi_netlink_netfilter_ulog_type,
	};
#endif

	static gint *ett[] = {
		&ett_netlink_netfilter,
	};

	int proto_netlink_netfilter;

	proto_netlink_netfilter = proto_register_protocol("Linux netlink netfilter protocol", "netfilter", "netlink-netfilter" );
	hfi_netlink_netfilter = proto_registrar_get_nth(proto_netlink_netfilter);

	proto_register_fields(proto_netlink_netfilter, hfi, array_length(hfi));
	proto_register_subtree_array(ett, array_length(ett));

	netlink_netfilter = create_dissector_handle(dissect_netlink_netfilter, proto_netlink_netfilter);
}

void
proto_reg_handoff_netlink_netfilter(void)
{
	dissector_add_uint("netlink.protocol", WS_NETLINK_NETFILTER, netlink_netfilter);

	nflog_handle = find_dissector_add_dependency("nflog", hfi_netlink_netfilter->id);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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

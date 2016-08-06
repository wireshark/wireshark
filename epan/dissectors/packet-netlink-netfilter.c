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

#include <epan/aftypes.h>
#include <epan/etypes.h>
#include <epan/packet.h>
#include "packet-netlink.h"

void proto_register_netlink_netfilter(void);
void proto_reg_handoff_netlink_netfilter(void);

typedef struct {
	packet_info *pinfo;
	struct packet_netlink_data *data;

	int encoding; /* copy of data->encoding */

	guint16 hw_protocol; /* protocol for NFQUEUE packet payloads. */
} netlink_netfilter_info_t;


static dissector_handle_t netlink_netfilter;
static dissector_handle_t nflog_handle;
static dissector_table_t ethertype_table;

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
	WS_NFNL_SUBSYS_CTHELPER          =  9,
	WS_NFNL_SUBSYS_NFTABLES          = 10,
	WS_NFNL_SUBSYS_NFT_COMPAT        = 11,
};

/* nfnetlink ULOG subsystem types from <linux/netfilter/nfnetlink_log.h> */
enum ws_nfulnl_msg_types {
	WS_NFULNL_MSG_PACKET = 0,
	WS_NFULNL_MSG_CONFIG = 1
};

/* Macros for "hook function responses" from <linux/netfilter.h> */
enum ws_verdict_types {
	WS_NF_DROP      = 0,
	WS_NF_ACCEPT    = 1,
	WS_NF_STOLEN    = 2,
	WS_NF_QUEUE     = 3,
	WS_NF_REPEAT    = 4,
	WS_NF_STOP      = 5,
};

enum ws_nf_inet_hooks {
	WS_NF_INET_PRE_ROUTING  = 0,
	WS_NF_INET_LOCAL_IN     = 1,
	WS_NF_INET_FORWARD      = 2,
	WS_NF_INET_LOCAL_OUT    = 3,
	WS_NF_INET_POST_ROUTING = 4,
};

/* from <linux/netfilter/nf_conntrack_common.h> */
enum ws_ip_conntrack_info {
	WS_IP_CT_ESTABLISHED,
	WS_IP_CT_RELATED,
	WS_IP_CT_NEW,
	WS_IP_CT_IS_REPLY,
	WS_IP_CT_ESTABLISHED_REPLY = WS_IP_CT_ESTABLISHED + WS_IP_CT_IS_REPLY,
	WS_IP_CT_RELATED_REPLY = WS_IP_CT_RELATED + WS_IP_CT_IS_REPLY,
	WS_IP_CT_NUMBER,
};

/* nfnetlink QUEUE subsystem types from <linux/netfilter/nfnetlink_queue.h> */
enum ws_nfqnl_msg_types {
	WS_NFQNL_MSG_PACKET         = 0,
	WS_NFQNL_MSG_VERDICT        = 1,
	WS_NFQNL_MSG_CONFIG         = 2,
	WS_NFQNL_MSG_VERDICT_BATCH  = 3
};

enum ws_nfqnl_attr_type {
	WS_NFQA_UNSPEC              = 0,
	WS_NFQA_PACKET_HDR          = 1,
	WS_NFQA_VERDICT_HDR         = 2,
	WS_NFQA_MARK                = 3,
	WS_NFQA_TIMESTAMP           = 4,
	WS_NFQA_IFINDEX_INDEV       = 5,
	WS_NFQA_IFINDEX_OUTDEV      = 6,
	WS_NFQA_IFINDEX_PHYSINDEV   = 7,
	WS_NFQA_IFINDEX_PHYSOUTDEV  = 8,
	WS_NFQA_HWADDR              = 9,
	WS_NFQA_PAYLOAD             = 10,
	WS_NFQA_CT                  = 11,
	WS_NFQA_CT_INFO             = 12,
	WS_NFQA_CAP_LEN             = 13,
	WS_NFQA_SKB_INFO            = 14,
	WS_NFQA_EXP                 = 15,
	WS_NFQA_UID                 = 16,
	WS_NFQA_GID                 = 17,
	WS_NFQA_SECCTX              = 18,
	WS_NFQA_VLAN                = 19,
	WS_NFQA_L2HDR               = 20,
};

enum ws_nfqnl_msg_config_cmds {
	WS_NFQNL_CFG_CMD_NONE       = 0,
	WS_NFQNL_CFG_CMD_BIND       = 1,
	WS_NFQNL_CFG_CMD_UNBIND     = 2,
	WS_NFQNL_CFG_CMD_PF_BIND    = 3,
	WS_NFQNL_CFG_CMD_PF_UNBIND  = 4,
};

enum ws_nfqnl_config_mode {
	WS_NFQNL_COPY_NONE          = 0,
	WS_NFQNL_COPY_META          = 1,
	WS_NFQNL_COPY_PACKET        = 2,
};

enum ws_nfqnl_attr_config {
	WS_NFQA_CFG_UNSPEC          = 0,
	WS_NFQA_CFG_CMD             = 1,
	WS_NFQA_CFG_PARAMS          = 2,
	WS_NFQA_CFG_QUEUE_MAXLEN    = 3,
	WS_NFQA_CFG_MASK            = 4,
	WS_NFQA_CFG_FLAGS           = 5,
};

static int ett_netlink_netfilter = -1;
static int ett_nfq_config_attr = -1;
static int ett_nfq_attr = -1;

/* nfgenmsg header, common to all Netfilter over Netlink packets. */

static header_field_info hfi_netlink_netfilter_family NETLINK_NETFILTER_HFI_INIT =
	{ "Address family", "netlink-netfilter.family", FT_UINT8, BASE_DEC | BASE_EXT_STRING,
	  &linux_af_vals_ext, 0x00, "nfnetlink address family", HFILL };

static header_field_info hfi_netlink_netfilter_version NETLINK_NETFILTER_HFI_INIT =
	{ "Version", "netlink-netfilter.version", FT_UINT8, BASE_DEC,
	  NULL, 0x00, "nfnetlink version", HFILL };

static header_field_info hfi_netlink_netfilter_resid NETLINK_NETFILTER_HFI_INIT =
	{ "Resource id", "netlink-netfilter.res_id", FT_UINT16, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static int dissect_netlink_netfilter_header(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	proto_tree_add_item(tree, &hfi_netlink_netfilter_family, tvb, offset, 1, ENC_NA);
	offset++;

	proto_tree_add_item(tree, &hfi_netlink_netfilter_version, tvb, offset, 1, ENC_NA);
	offset++;

	proto_tree_add_item(tree, &hfi_netlink_netfilter_resid, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	return offset;
}

/* QUEUE */

/* QUEUE - Config */

static const value_string nfq_type_vals[] = {
	{ WS_NFQNL_MSG_PACKET,          "Packet" },
	{ WS_NFQNL_MSG_VERDICT,         "Verdict" },
	{ WS_NFQNL_MSG_CONFIG,          "Config" },
	{ WS_NFQNL_MSG_VERDICT_BATCH,   "Verdict (batch)" },
	{ 0, NULL }
};

static const value_string nfq_config_command_vals[] = {
	{ WS_NFQNL_CFG_CMD_NONE,        "None" },
	{ WS_NFQNL_CFG_CMD_BIND,        "Bind" },
	{ WS_NFQNL_CFG_CMD_UNBIND,      "Unbind" },
	{ WS_NFQNL_CFG_CMD_PF_BIND,     "PF bind" },
	{ WS_NFQNL_CFG_CMD_PF_UNBIND,   "PF unbind" },
	{ 0, NULL }
};

static const value_string nfq_config_attr_vals[] = {
	{ WS_NFQA_CFG_UNSPEC,           "Unspecified" },
	{ WS_NFQA_CFG_CMD,              "Command" },
	{ WS_NFQA_CFG_PARAMS,           "Parameters" },
	{ WS_NFQA_CFG_QUEUE_MAXLEN,     "Maximum queue length" },
	{ WS_NFQA_CFG_MASK,             "Mask" },
	{ WS_NFQA_CFG_FLAGS,            "Flags" },
	{ 0, NULL }
};

static const value_string nfq_config_mode_vals[] = {
	{ WS_NFQNL_COPY_NONE,           "None" },
	{ WS_NFQNL_COPY_META,           "Meta" },
	{ WS_NFQNL_COPY_PACKET,         "Packet" },
	{ 0, NULL }
};

static header_field_info hfi_nfq_config_command_command NETLINK_NETFILTER_HFI_INIT =
	{ "Command", "netlink-netfilter.queue.config.command.command", FT_UINT8, BASE_DEC,
	  VALS(nfq_config_command_vals), 0x00, NULL, HFILL };

static header_field_info hfi_nfq_config_command_pf NETLINK_NETFILTER_HFI_INIT =
	{ "Protocol family", "netlink-netfilter.queue.config.command.pf", FT_UINT16, BASE_DEC | BASE_EXT_STRING,
	  &linux_af_vals_ext, 0x00, NULL, HFILL };

static header_field_info hfi_nfq_config_params_copyrange NETLINK_NETFILTER_HFI_INIT =
	{ "Copy range", "netlink-netfilter.queue.config.params.copy_range", FT_UINT32, BASE_HEX,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_nfq_config_params_copymode NETLINK_NETFILTER_HFI_INIT =
	{ "Copy mode", "netlink-netfilter.queue.config.params.copy_mode", FT_UINT8, BASE_DEC,
	  VALS(nfq_config_mode_vals), 0x00, NULL, HFILL };

static header_field_info hfi_nfq_config_queue_maxlen NETLINK_NETFILTER_HFI_INIT =
	{ "Maximum queue length", "netlink-netfilter.queue.config.queue_maxlen", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_nfq_config_mask NETLINK_NETFILTER_HFI_INIT =
	{ "Flags mask", "netlink-netfilter.queue.config.mask", FT_UINT32, BASE_HEX,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_nfq_config_flags NETLINK_NETFILTER_HFI_INIT =
	{ "Flags", "netlink-netfilter.queue.config.flags", FT_UINT32, BASE_HEX,
	  NULL, 0x00, NULL, HFILL };

static int
dissect_nfq_config_attrs(tvbuff_t *tvb, void *data _U_, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_nfqnl_attr_config type = (enum ws_nfqnl_attr_config) nla_type;
	netlink_netfilter_info_t *info = (netlink_netfilter_info_t *) data;

	switch (type) {
		case WS_NFQA_CFG_UNSPEC:
			break;

		case WS_NFQA_CFG_CMD:
			if (len == 4) {
				proto_tree_add_item(tree, &hfi_nfq_config_command_command, tvb, offset, 1, ENC_NA);
				offset += 2; /* skip command and 1 byte padding. */

				proto_tree_add_item(tree, &hfi_nfq_config_command_pf, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
			}
			break;

		case WS_NFQA_CFG_PARAMS:
			if (len == 5) {
				proto_tree_add_item(tree, &hfi_nfq_config_params_copyrange, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;

				proto_tree_add_item(tree, &hfi_nfq_config_params_copymode, tvb, offset, 1, ENC_NA);
				offset++;
			}
			break;

		case WS_NFQA_CFG_QUEUE_MAXLEN:
			if (len == 4) {
				proto_tree_add_item(tree, &hfi_nfq_config_queue_maxlen, tvb, offset, 4, info->encoding);
				offset += 4;
			}
			break;

		case WS_NFQA_CFG_MASK:
			if (len == 4) {
				proto_tree_add_item(tree, &hfi_nfq_config_mask, tvb, offset, 4, info->encoding);
				offset += 4;
			}
			break;

		case WS_NFQA_CFG_FLAGS:
			if (len == 4) {
				proto_tree_add_item(tree, &hfi_nfq_config_flags, tvb, offset, 4, info->encoding);
				offset += 4;
			}
			break;
	}

	return offset;
}

static header_field_info hfi_nfq_config_attr NETLINK_NETFILTER_HFI_INIT =
	{ "Type", "netlink-netfilter.queue.config_attr", FT_UINT16, BASE_DEC,
	  VALS(nfq_config_attr_vals), 0x00, NULL, HFILL };

/* QUEUE - Packet and verdict */

static const value_string nfq_attr_vals[] = {
	{ WS_NFQA_UNSPEC,               "Unspecified" },
	{ WS_NFQA_PACKET_HDR,           "Packet header" },
	{ WS_NFQA_VERDICT_HDR,          "Verdict header" },
	{ WS_NFQA_MARK,                 "Mark" },
	{ WS_NFQA_TIMESTAMP,            "Timestamp" },
	{ WS_NFQA_IFINDEX_INDEV,        "NFQA_IFINDEX_INDEV" },
	{ WS_NFQA_IFINDEX_OUTDEV,       "NFQA_IFINDEX_OUTDEV" },
	{ WS_NFQA_IFINDEX_PHYSINDEV,    "NFQA_IFINDEX_PHYSINDEV" },
	{ WS_NFQA_IFINDEX_PHYSOUTDEV,   "NFQA_IFINDEX_PHYSOUTDEV" },
	{ WS_NFQA_HWADDR,               "Hardware address" },
	{ WS_NFQA_PAYLOAD,              "Payload" },
	{ WS_NFQA_CT,                   "NFQA_CT" },
	{ WS_NFQA_CT_INFO,              "Conntrack info" },
	{ WS_NFQA_CAP_LEN,              "Length of captured packet" },
	{ WS_NFQA_SKB_INFO,             "SKB meta information" },
	{ WS_NFQA_EXP,                  "Conntrack expectation" },
	{ WS_NFQA_UID,                  "SK UID" },
	{ WS_NFQA_GID,                  "SK GID" },
	{ WS_NFQA_SECCTX,               "Security context string" },
	{ WS_NFQA_VLAN,                 "Packet VLAN info" },
	{ WS_NFQA_L2HDR,                "Full L2 header" },
	{ 0, NULL }
};

static const value_string nfq_verdict_vals[] = {
	{ WS_NF_DROP,   "DROP" },
	{ WS_NF_ACCEPT, "ACCEPT" },
	{ WS_NF_STOLEN, "STOLEN" },
	{ WS_NF_QUEUE,  "QUEUE" },
	{ WS_NF_REPEAT, "REPEAT" },
	{ WS_NF_STOP,   "STOP" },
	{ 0, NULL }
};

static const value_string nfq_hooks_vals[] = {
	{ WS_NF_INET_PRE_ROUTING,   "Pre-routing" },
	{ WS_NF_INET_LOCAL_IN,      "Local in" },
	{ WS_NF_INET_FORWARD,       "Forward" },
	{ WS_NF_INET_LOCAL_OUT,     "Local out" },
	{ WS_NF_INET_POST_ROUTING,  "Post-routing" },
	{ 0, NULL }
};

static const value_string nfq_ctinfo_vals[] = {
	{ WS_IP_CT_ESTABLISHED,         "ESTABLISHED" },
	{ WS_IP_CT_RELATED,             "RELATED" },
	{ WS_IP_CT_NEW,                 "NEW" },
	{ WS_IP_CT_IS_REPLY,            "IS_REPLY" },
	{ WS_IP_CT_ESTABLISHED_REPLY,   "ESTABLISHED_REPLY" },
	{ WS_IP_CT_RELATED_REPLY,       "RELATED_REPLY" },
	{ WS_IP_CT_NUMBER,              "NUMBER" },
	{ 0, NULL }
};

static header_field_info hfi_nfq_verdict_verdict NETLINK_NETFILTER_HFI_INIT =
	{ "Verdict", "netlink-netfilter.queue.verdict.verdict", FT_UINT32, BASE_DEC,
	  VALS(nfq_verdict_vals), 0x00, NULL, HFILL };

static header_field_info hfi_nfq_verdict_id NETLINK_NETFILTER_HFI_INIT =
	{ "Packet ID", "netlink-netfilter.queue.verdict.id", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_nfq_packet_id NETLINK_NETFILTER_HFI_INIT =
	{ "Packet ID", "netlink-netfilter.queue.packet.id", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_nfq_packet_hwprotocol NETLINK_NETFILTER_HFI_INIT =
	{ "HW protocol", "netlink-netfilter.queue.packet.protocol", FT_UINT16, BASE_HEX,
	  VALS(etype_vals), 0x00, NULL, HFILL };

static header_field_info hfi_nfq_packet_hook NETLINK_NETFILTER_HFI_INIT =
	{ "Netfilter hook", "netlink-netfilter.queue.packet.hook", FT_UINT8, BASE_DEC,
	  VALS(nfq_hooks_vals), 0x00, NULL, HFILL };

static header_field_info hfi_nfq_nfmark NETLINK_NETFILTER_HFI_INIT =
	{ "Mark", "netlink-netfilter.queue.nfmark", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_nfq_timestamp NETLINK_NETFILTER_HFI_INIT =
	{ "Timestamp", "netlink-netfilter.queue.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_nfq_ifindex_indev NETLINK_NETFILTER_HFI_INIT =
	{ "IFINDEX_INDEV", "netlink-netfilter.queue.ifindex_indev", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_nfq_ifindex_outdev NETLINK_NETFILTER_HFI_INIT =
	{ "IFINDEX_OUTDEV", "netlink-netfilter.queue.ifindex_outdev", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_nfq_ifindex_physindev NETLINK_NETFILTER_HFI_INIT =
	{ "IFINDEX_PHYSINDEV", "netlink-netfilter.queue.ifindex_physindev", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_nfq_ifindex_physoutdev NETLINK_NETFILTER_HFI_INIT =
	{ "IFINDEX_PHYSOUTDEV", "netlink-netfilter.queue.ifindex_physoutdev", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_nfq_hwaddr_len NETLINK_NETFILTER_HFI_INIT =
	{ "Address length", "netlink-netfilter.queue.hwaddr.len", FT_UINT16, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_nfq_hwaddr_addr NETLINK_NETFILTER_HFI_INIT =
	{ "Address", "netlink-netfilter.queue.hwaddr.addr", FT_ETHER, BASE_NONE,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_nfq_ctinfo NETLINK_NETFILTER_HFI_INIT =
	{ "Conntrack info", "netlink-netfilter.queue.ct_info", FT_UINT32, BASE_DEC,
	  VALS(nfq_ctinfo_vals), 0x00, "Connection state tracking info", HFILL };

static header_field_info hfi_nfq_caplen NETLINK_NETFILTER_HFI_INIT =
	{ "Length of captured packet", "netlink-netfilter.queue.caplen", FT_UINT32, BASE_DEC,
	  NULL, 0x00, "Length of captured, untruncated packet", HFILL };

static header_field_info hfi_nfq_uid NETLINK_NETFILTER_HFI_INIT =
	{ "UID", "netlink-netfilter.queue.uid", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_nfq_gid NETLINK_NETFILTER_HFI_INIT =
	{ "GID", "netlink-netfilter.queue.gid", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static int
dissect_nfq_attrs(tvbuff_t *tvb, void *data _U_, proto_tree *tree, int nla_type, int offset, int len _U_)
{
	enum ws_nfqnl_attr_type type = (enum ws_nfqnl_attr_type) nla_type;
	netlink_netfilter_info_t *info = (netlink_netfilter_info_t *) data;

	switch (type) {
		case WS_NFQA_UNSPEC:
			break;

		case WS_NFQA_PACKET_HDR:
			if (len == 7) {
				proto_tree_add_item(tree, &hfi_nfq_packet_id, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;

				proto_tree_add_item(tree, &hfi_nfq_packet_hwprotocol, tvb, offset, 2, ENC_BIG_ENDIAN);
				info->hw_protocol = tvb_get_ntohs(tvb, offset);
				offset += 2;

				proto_tree_add_item(tree, &hfi_nfq_packet_hook, tvb, offset, 1, ENC_NA);
				offset++;
			}
			break;

		case WS_NFQA_VERDICT_HDR:
			if (len == 8) {
				proto_tree_add_item(tree, &hfi_nfq_verdict_verdict, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;

				proto_tree_add_item(tree, &hfi_nfq_verdict_id, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			break;

		case WS_NFQA_MARK:
			if (len == 4) {
				proto_tree_add_item(tree, &hfi_nfq_nfmark, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			break;

		case WS_NFQA_TIMESTAMP:
			if (len == 16) {
				nstime_t ts;

				ts.secs = (time_t)tvb_get_ntoh64(tvb, offset);
				ts.nsecs = (int)tvb_get_ntoh64(tvb, offset + 8) * 1000;
				proto_tree_add_time(tree, &hfi_nfq_timestamp, tvb, offset, 16, &ts);
				offset += 16;
			}
			break;

		case WS_NFQA_IFINDEX_INDEV:
			if (len == 4) {
				proto_tree_add_item(tree, &hfi_nfq_ifindex_indev, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			break;

		case WS_NFQA_IFINDEX_OUTDEV:
			if (len == 4) {
				proto_tree_add_item(tree, &hfi_nfq_ifindex_outdev, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			break;

		case WS_NFQA_IFINDEX_PHYSINDEV:
			if (len == 4) {
				proto_tree_add_item(tree, &hfi_nfq_ifindex_physindev, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			break;

		case WS_NFQA_IFINDEX_PHYSOUTDEV:
			if (len == 4) {
				proto_tree_add_item(tree, &hfi_nfq_ifindex_physoutdev, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			break;

		case WS_NFQA_HWADDR:
			if (len >= 4) {
				guint16 addrlen;

				proto_tree_add_item(tree, &hfi_nfq_hwaddr_len, tvb, offset, 2, ENC_BIG_ENDIAN);
				addrlen = tvb_get_ntohs(tvb, offset);
				offset += 4; /* skip len and padding */

				/* XXX expert info if 4 + addrlen > len. */
				addrlen = MIN(addrlen, len - 4);
				proto_tree_add_item(tree, &hfi_nfq_hwaddr_addr, tvb, offset, addrlen, ENC_BIG_ENDIAN);
				offset += addrlen;
			}
			break;

		case WS_NFQA_PAYLOAD:
			if (len > 0) {
				tvbuff_t *next_tvb = tvb_new_subset_length(tvb, offset, len);
				proto_tree *parent_tree = proto_item_get_parent(tree);

				if (!dissector_try_uint(ethertype_table, info->hw_protocol, next_tvb, info->pinfo, parent_tree))
					call_data_dissector(next_tvb, info->pinfo, parent_tree);
				offset += len;
			}
			break;

		case WS_NFQA_CT:
			/* TODO */
			break;

		case WS_NFQA_CT_INFO:
			if (len == 4) {
				proto_tree_add_item(tree, &hfi_nfq_ctinfo, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			break;

		case WS_NFQA_CAP_LEN:
			if (len == 4) {
				proto_tree_add_item(tree, &hfi_nfq_caplen, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			break;

		case WS_NFQA_SKB_INFO:
		case WS_NFQA_EXP:
			/* TODO */
			break;

		case WS_NFQA_UID:
			if (len == 4) {
				proto_tree_add_item(tree, &hfi_nfq_uid, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			break;

		case WS_NFQA_GID:
			if (len == 4) {
				proto_tree_add_item(tree, &hfi_nfq_gid, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			break;

		case WS_NFQA_SECCTX:
		case WS_NFQA_VLAN:
		case WS_NFQA_L2HDR:
			/* TODO */
			break;
	}

	return offset;
}

static header_field_info hfi_nfq_attr NETLINK_NETFILTER_HFI_INIT =
	{ "Type", "netlink-netfilter.queue.attr", FT_UINT16, BASE_DEC,
	  VALS(nfq_attr_vals), 0x00, NULL, HFILL };

/* QUEUE - main */

static int
dissect_netfilter_queue(tvbuff_t *tvb, netlink_netfilter_info_t *info, proto_tree *tree, int offset)
{
	enum ws_nfqnl_msg_types type = (enum ws_nfqnl_msg_types) (info->data->type & 0xff);

	offset = dissect_netlink_netfilter_header(tvb, tree, offset);

	switch (type) {
		case WS_NFQNL_MSG_CONFIG:
			return dissect_netlink_attributes(tvb, &hfi_nfq_config_attr, ett_nfq_config_attr, info, tree, offset, dissect_nfq_config_attrs);

		case WS_NFQNL_MSG_PACKET:
		case WS_NFQNL_MSG_VERDICT:
			return dissect_netlink_attributes(tvb, &hfi_nfq_attr, ett_nfq_attr, info, tree, offset, dissect_nfq_attrs);

		case WS_NFQNL_MSG_VERDICT_BATCH:
			/* TODO */
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

	switch (type) {
		case WS_NFULNL_MSG_PACKET:
			/* Note that NFLOG dissects the nfgenmsg header */
			call_dissector(nflog_handle, tvb, info->pinfo, tree);
			break;

		default:
			break;
	}

	return offset;
}

static const value_string netlink_netfilter_subsystem_vals[] = {
	{ WS_NFNL_SUBSYS_NONE,              "None" },
	{ WS_NFNL_SUBSYS_CTNETLINK,         "Conntrack" },
	{ WS_NFNL_SUBSYS_CTNETLINK_EXP,     "Conntrack expect" },
	{ WS_NFNL_SUBSYS_QUEUE,             "Netfilter packet queue" },
	{ WS_NFNL_SUBSYS_ULOG,              "Netfilter userspace logging" },
	{ WS_NFNL_SUBSYS_OSF,               "OS fingerprint" },
	{ WS_NFNL_SUBSYS_IPSET,             "IP set" },
	{ WS_NFNL_SUBSYS_ACCT,              "Extended Netfilter accounting infrastructure" },
	{ WS_NFNL_SUBSYS_CTNETLINK_TIMEOUT, "Extended Netfilter Connection Tracking timeout tuning" },
	{ WS_NFNL_SUBSYS_CTHELPER,          "Connection Tracking Helpers" },
	{ WS_NFNL_SUBSYS_NFTABLES,          "Netfilter tables" },
	{ WS_NFNL_SUBSYS_NFT_COMPAT,        "x_tables compatibility layer for nf_tables" },
	{ 0, NULL }
};

static header_field_info hfi_nfq_type NETLINK_NETFILTER_HFI_INIT =
	{ "Type", "netlink-netfilter.queue_type", FT_UINT16, BASE_DEC,
	  VALS(nfq_type_vals), 0x00FF, NULL, HFILL };

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

	proto_item_set_text(tree, "Linux netlink netfilter message");

	/* XXX, from header tvb */
	proto_tree_add_uint(tree, &hfi_netlink_netfilter_subsys, NULL, 0, 0, data->type);
	switch (data->type >> 8) {
		case WS_NFNL_SUBSYS_QUEUE:
			proto_tree_add_uint(tree, &hfi_nfq_type, NULL, 0, 0, data->type);
			break;

		case WS_NFNL_SUBSYS_ULOG:
			proto_tree_add_uint(tree, &hfi_netlink_netfilter_ulog_type, NULL, 0, 0, data->type);
			break;
	}

	info.encoding = data->encoding;
	info.pinfo = pinfo;
	info.data = data;
	info.hw_protocol = 0;

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
		&hfi_netlink_netfilter_family,
		&hfi_netlink_netfilter_version,
		&hfi_netlink_netfilter_resid,

	/* QUEUE */
		&hfi_nfq_type,
		&hfi_nfq_attr,
		&hfi_nfq_config_command_command,
		&hfi_nfq_config_command_pf,
		&hfi_nfq_config_params_copyrange,
		&hfi_nfq_config_params_copymode,
		&hfi_nfq_config_queue_maxlen,
		&hfi_nfq_config_mask,
		&hfi_nfq_config_flags,
		&hfi_nfq_config_attr,
		&hfi_nfq_verdict_verdict,
		&hfi_nfq_verdict_id,
		&hfi_nfq_packet_id,
		&hfi_nfq_packet_hwprotocol,
		&hfi_nfq_packet_hook,
		&hfi_nfq_nfmark,
		&hfi_nfq_timestamp,
		&hfi_nfq_ifindex_indev,
		&hfi_nfq_ifindex_outdev,
		&hfi_nfq_ifindex_physindev,
		&hfi_nfq_ifindex_physoutdev,
		&hfi_nfq_hwaddr_len,
		&hfi_nfq_hwaddr_addr,
		&hfi_nfq_ctinfo,
		&hfi_nfq_caplen,
		&hfi_nfq_uid,
		&hfi_nfq_gid,
	/* ULOG */
		&hfi_netlink_netfilter_ulog_type,
	};
#endif

	static gint *ett[] = {
		&ett_netlink_netfilter,
		&ett_nfq_config_attr,
		&ett_nfq_attr,
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
	ethertype_table = find_dissector_table("ethertype");
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

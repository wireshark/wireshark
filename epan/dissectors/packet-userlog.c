/* packet-userlog.c
 * Routines for userlog protocol packet disassembly
 * Copyright 2016,  Jun Wang <sdn_app@163.com>
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
/*
 * Userlog is user flow logs of H3C device.
 * Flow logging records users' access to the extranet. The device classifies and
 * calculates flows through the 5-tuple information, which includes source IP address,
 * destination IP address, source port, destination port, and protocol number,
 * and generates user flow logs. Flow logging records the 5-tuple information of
 * the packets and number of the bytes received and sent. With flow logs, administrators
 * can track and record accesses to the network, facilitating the availability and
 * security of the network.
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/ipproto.h>

void proto_register_userlog(void);
void proto_reg_handoff_userlog(void);

static int proto_userlog           = -1;

static int hf_userlog_version      = -1;
static int hf_userlog_logtype      = -1;
static int hf_userlog_count        = -1;
static int hf_userlog_timestamp    = -1;
static int hf_userlog_header_reserved = -1;

static int hf_userlog_proto        = -1;
static int hf_userlog_Operator     = -1;
static int hf_userlog_IPVerion     = -1;
static int hf_userlog_IPToS        = -1;

static int hf_userlog_SourceIP     = -1;
static int hf_userlog_SrcNatIP     = -1;
static int hf_userlog_DestIP       = -1;
static int hf_userlog_DestNatIP    = -1;
static int hf_userlog_SrcPort      = -1;
static int hf_userlog_SrcNatPort   = -1;
static int hf_userlog_DestPort     = -1;
static int hf_userlog_DestNatPort  = -1;

static int hf_userlog_StartTime    = -1;
static int hf_userlog_EndTime      = -1;

static int hf_userlog_InTotalPkg   = -1;
static int hf_userlog_InTotalByte  = -1;
static int hf_userlog_OutTotalPkg  = -1;
static int hf_userlog_OutTotalByte = -1;

static int hf_userlog_Reserved1    = -1;
static int hf_userlog_Reserved2    = -1;
static int hf_userlog_Reserved3    = -1;

static gint ett_userlog            = -1;
static gint ett_userlog_header     = -1;
static gint ett_userlog_log        = -1;

static const value_string version[] = {
{ 1, "V1" },
{ 3, "V3" },
{ 0, NULL }
};

static const value_string logtype[] = {
{ 1, "NAT" },
{ 2, "BAS" },
{ 4, "Flow" },
{ 0, NULL }
};

static const value_string Operator[] = {
{ 1, "normal close flow" },
{ 2, "timeout" },
{ 3, "clear flow" },
{ 4, "overflow" },
{ 5, "nat static" },
{ 6, "time data threshold" },
{ 7, "flow delete" },
{ 8, "flow create" },
{ 0, NULL }
};


/* Minimum length (in bytes) of the protocol data. */
#define USERLOG_MIN_LENGTH 8


/* Code to actually dissect the packets */
static int
dissect_userlog(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *userlog_header, *userlog_tree;
	proto_tree *userlog_log;
	/* Other misc. local variables. */
	gint offset    = 0;
	guint log_count = 1;
	guint log_type, log_max;

	/* Check that the packet is long enough for it to belong to us. */
	if (tvb_reported_length(tvb) < USERLOG_MIN_LENGTH)
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "UserLog");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo,COL_INFO);

	ti = proto_tree_add_item(tree, proto_userlog, tvb, 0, -1, ENC_NA);
	userlog_tree = proto_item_add_subtree(ti, ett_userlog);

	userlog_header = proto_tree_add_subtree(userlog_tree, tvb, 0, 16, ett_userlog_header, NULL, "UserLog Header");
	proto_tree_add_item(userlog_header, hf_userlog_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item_ret_uint(userlog_header, hf_userlog_logtype, tvb, offset, 1, ENC_BIG_ENDIAN, &log_type);
	col_add_fstr(pinfo->cinfo, COL_INFO, "LogType = %s", val_to_str(log_type, logtype, "Unknown (0x%02x)"));
	offset += 1;

	proto_tree_add_item_ret_uint(userlog_header, hf_userlog_count, tvb, offset, 2, ENC_BIG_ENDIAN, &log_max);
	proto_item_append_text(ti, ", Log Count = %d", log_max);
	offset += 2;

	proto_tree_add_item(userlog_header, hf_userlog_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* XXX - 8 bytes unaccounted for */
	proto_tree_add_item(userlog_header, hf_userlog_header_reserved, tvb, offset, 8, ENC_NA);
	offset += 8;

	if (userlog_tree) { /* we are being asked for details */
		while ( log_count <= log_max)
		{
			userlog_log = proto_tree_add_subtree_format(userlog_tree, tvb, offset, 64, ett_userlog_log, NULL, "UserLog No.%d", log_count);

			proto_tree_add_item(userlog_log, hf_userlog_proto, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(userlog_log, hf_userlog_Operator, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(userlog_log, hf_userlog_IPVerion, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(userlog_log, hf_userlog_IPToS, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(userlog_log, hf_userlog_SourceIP, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(userlog_log, hf_userlog_SrcNatIP, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(userlog_log, hf_userlog_DestIP, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(userlog_log, hf_userlog_DestNatIP, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(userlog_log, hf_userlog_SrcPort, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(userlog_log, hf_userlog_SrcNatPort, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(userlog_log, hf_userlog_DestPort, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(userlog_log, hf_userlog_DestNatPort, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(userlog_log, hf_userlog_StartTime, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(userlog_log, hf_userlog_EndTime, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(userlog_log, hf_userlog_InTotalPkg, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(userlog_log, hf_userlog_InTotalByte, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(userlog_log, hf_userlog_OutTotalPkg, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(userlog_log, hf_userlog_OutTotalByte, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(userlog_log, hf_userlog_Reserved1, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(userlog_log, hf_userlog_Reserved2, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(userlog_log, hf_userlog_Reserved3, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			log_count++;

		}
	}

	return tvb_captured_length(tvb);
}

void
proto_register_userlog(void)
{
	static hf_register_info hf[] = {
		{ &hf_userlog_version,
			{ "Version", "userlog.version",
			FT_UINT8, BASE_DEC,
			VALS(version), 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_logtype,
			{ "LogType", "userlog.logtype",
			FT_UINT8, BASE_DEC,
			VALS(logtype), 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_count,
			{ "LogCount", "userlog.count",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_timestamp,
			{ "TimeStamp", "userlog.timestamp",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_header_reserved,
			{ "Reserved", "userlog.header_reserved",
			FT_BYTES, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_proto,
			{ "Protocol", "userlog.proto",
			FT_UINT8, BASE_DEC|BASE_EXT_STRING,
			&ipproto_val_ext, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_Operator,
			{ "Operator", "userlog.Operator",
			FT_UINT8, BASE_DEC,
			VALS(Operator), 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_IPVerion,
			{ "IP Version", "userlog.IPVersion",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_IPToS,
			{ "IP ToS", "userlog.IPToS",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_SourceIP,
			{ "Source-IP", "userlog.SourceIP",
			FT_IPv4, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_SrcNatIP,
			{ "Source-NAT-IP", "userlog.Source-NAT-IP",
			FT_IPv4, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_DestIP,
			{ "Destination-IP", "userlog.Destination-IP",
			FT_IPv4, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_DestNatIP,
			{ "Destination-NAT-IP", "userlog.Destination-NAT-IP",
			FT_IPv4, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_SrcPort,
			{ "Source-Port", "userlog.Source-Port",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_SrcNatPort,
			{ "Source-NAT-Port", "userlog.Source-NAT-Port",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_DestPort,
			{ "Destination-Port", "userlog.Destination-Port",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_DestNatPort,
			{ "Destination-NAT-Port", "userlog.Destination-NAT-Port",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_StartTime,
			{ "StartTime", "userlog.StartTime",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_EndTime,
			{ "EndTime", "userlog.EndTime",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_InTotalPkg,
			{ "InTotalPkg", "userlog.InTotalPkg",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_InTotalByte,
			{ "InTotalByte", "userlog.InTotalByte",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_OutTotalPkg,
			{ "OutTotalPkg", "userlog.OutTotalPkg",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_OutTotalByte,
			{ "OutTotalByte", "userlog.OutTotalByte",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_Reserved1,
			{ "Reserved1", "userlog.Reserved1",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_Reserved2,
			{ "Reserved2", "userlog.Reserved2",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_userlog_Reserved3,
			{ "Reserved3", "userlog.Reserved3",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		}

	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_userlog,
		&ett_userlog_header,
		&ett_userlog_log
	};

	proto_userlog = proto_register_protocol("UserLog Protocol", "UserLog", "userlog");
	proto_register_field_array(proto_userlog, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_userlog(void)
{
	dissector_handle_t userlog_handle;

	userlog_handle = create_dissector_handle(dissect_userlog, proto_userlog);
	dissector_add_for_decode_as("udp.port", userlog_handle);

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

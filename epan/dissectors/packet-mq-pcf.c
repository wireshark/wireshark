/* packet-mq-pcf.c
 * Routines for IBM WebSphere MQ PCF packet dissection
 *
 * metatech <metatech@flashmail.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*  MQ PCF in a nutshell
*
*   The MQ Programmable Command Formats API allows remotely configuring a queue manager.
*
*   MQ PCF documentation is called "WebSphere MQ Programmable Command Formats and Administration Interface"
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include "packet-mq.h"

static int proto_mqpcf = -1;
static int hf_mqpcf_cfh_type = -1;
static int hf_mqpcf_cfh_length = -1;
static int hf_mqpcf_cfh_version = -1;
static int hf_mqpcf_cfh_command = -1;
static int hf_mqpcf_cfh_msgseqnumber = -1;
static int hf_mqpcf_cfh_control = -1;
static int hf_mqpcf_cfh_compcode = -1;
static int hf_mqpcf_cfh_reason = -1;
static int hf_mqpcf_cfh_paramcount = -1;

static gint ett_mqpcf = -1;
static gint ett_mqpcf_cfh = -1;

#define MQ_FMT_ADMIN    "MQADMIN "
#define MQ_FMT_EVENT    "MQEVENT "
#define MQ_FMT_PCF      "MQPCF   "

#define MQ_ENC_INTEGER_NORMAL    0x00000001
#define MQ_ENC_INTEGER_REVERSED  0x00000002

#define MQ_CMD_NONE                     0
#define MQ_CMD_CHANGE_Q_MGR             1
#define MQ_CMD_INQUIRE_Q_MGR            2
#define MQ_CMD_CHANGE_PROCESS           3
#define MQ_CMD_COPY_PROCESS             4
#define MQ_CMD_CREATE_PROCESS           5
#define MQ_CMD_DELETE_PROCESS           6
#define MQ_CMD_INQUIRE_PROCESS          7
#define MQ_CMD_CHANGE_Q                 8
#define MQ_CMD_CLEAR_Q                  9
#define MQ_CMD_COPY_Q                  10
#define MQ_CMD_CREATE_Q                11
#define MQ_CMD_DELETE_Q                12
#define MQ_CMD_INQUIRE_Q               13
#define MQ_CMD_RESET_Q_STATS           17
#define MQ_CMD_INQUIRE_Q_NAMES         18
#define MQ_CMD_INQUIRE_PROCESS_NAMES   19
#define MQ_CMD_INQUIRE_CHANNEL_NAMES   20
#define MQ_CMD_CHANGE_CHANNEL          21
#define MQ_CMD_COPY_CHANNEL            22
#define MQ_CMD_CREATE_CHANNEL          23
#define MQ_CMD_DELETE_CHANNEL          24
#define MQ_CMD_INQUIRE_CHANNEL         25
#define MQ_CMD_PING_CHANNEL            26
#define MQ_CMD_RESET_CHANNEL           27
#define MQ_CMD_START_CHANNEL           28
#define MQ_CMD_STOP_CHANNEL            29
#define MQ_CMD_START_CHANNEL_INIT      30
#define MQ_CMD_START_CHANNEL_LISTENER  31
#define MQ_CMD_CHANGE_NAMELIST         32
#define MQ_CMD_COPY_NAMELIST           33
#define MQ_CMD_CREATE_NAMELIST         34
#define MQ_CMD_DELETE_NAMELIST         35
#define MQ_CMD_INQUIRE_NAMELIST        36
#define MQ_CMD_INQUIRE_NAMELIST_NAMES  37
#define MQ_CMD_ESCAPE                  38
#define MQ_CMD_RESOLVE_CHANNEL         39
#define MQ_CMD_PING_Q_MGR              40
#define MQ_CMD_INQUIRE_Q_STATUS        41
#define MQ_CMD_INQUIRE_CHANNEL_STATUS  42
#define MQ_CMD_CONFIG_EVENT            43
#define MQ_CMD_Q_MGR_EVENT             44
#define MQ_CMD_PERFM_EVENT             45
#define MQ_CMD_CHANNEL_EVENT           46
#define MQ_CMD_DELETE_PUBLICATION      60
#define MQ_CMD_DEREGISTER_PUBLISHER    61
#define MQ_CMD_DEREGISTER_SUBSCRIBER   62
#define MQ_CMD_PUBLISH                 63
#define MQ_CMD_REGISTER_PUBLISHER      64
#define MQ_CMD_REGISTER_SUBSCRIBER     65
#define MQ_CMD_REQUEST_UPDATE          66
#define MQ_CMD_BROKER_INTERNAL         67
#define MQ_CMD_INQUIRE_CLUSTER_Q_MGR   70
#define MQ_CMD_RESUME_Q_MGR_CLUSTER    71
#define MQ_CMD_SUSPEND_Q_MGR_CLUSTER   72
#define MQ_CMD_REFRESH_CLUSTER         73
#define MQ_CMD_RESET_CLUSTER           74
#define MQ_CMD_REFRESH_SECURITY        78
#define MQ_CMD_CHANGE_AUTH_INFO        79
#define MQ_CMD_COPY_AUTH_INFO          80
#define MQ_CMD_CREATE_AUTH_INFO        81
#define MQ_CMD_DELETE_AUTH_INFO        82
#define MQ_CMD_INQUIRE_AUTH_INFO       83
#define MQ_CMD_INQUIRE_AUTH_INFO_NAMES 84

#define MQ_TEXT_CFH   "MQ Command Format Header"

static const value_string mqpcf_opcode_vals[] = {
  { MQ_CMD_NONE,                            "NONE" },
  { MQ_CMD_CHANGE_Q_MGR,                    "CHANGE_Q_MGR" },
  { MQ_CMD_INQUIRE_Q_MGR,                   "INQUIRE_Q_MGR" },
  { MQ_CMD_CHANGE_PROCESS,                  "CHANGE_PROCESS" },
  { MQ_CMD_COPY_PROCESS,                    "COPY_PROCESS" },
  { MQ_CMD_CREATE_PROCESS,                  "CREATE_PROCESS" },
  { MQ_CMD_DELETE_PROCESS,                  "DELETE_PROCESS" },
  { MQ_CMD_INQUIRE_PROCESS,                 "INQUIRE_PROCESS" },
  { MQ_CMD_CHANGE_Q,                        "CHANGE_Q" },
  { MQ_CMD_CLEAR_Q,                         "CLEAR_Q" },
  { MQ_CMD_COPY_Q,                          "COPY_Q" },
  { MQ_CMD_CREATE_Q,                        "CREATE_Q" },
  { MQ_CMD_DELETE_Q,                        "DELETE_Q" },
  { MQ_CMD_INQUIRE_Q,                       "INQUIRE_Q" },
  { MQ_CMD_RESET_Q_STATS,                   "RESET_Q_STATS" },
  { MQ_CMD_INQUIRE_Q_NAMES,                 "INQUIRE_Q_NAMES" },
  { MQ_CMD_INQUIRE_PROCESS_NAMES,           "INQUIRE_PROCESS_NAMES" },
  { MQ_CMD_INQUIRE_CHANNEL_NAMES,           "INQUIRE_CHANNEL_NAMES" },
  { MQ_CMD_CHANGE_CHANNEL,                  "CHANGE_CHANNEL" },
  { MQ_CMD_COPY_CHANNEL,                    "COPY_CHANNEL" },
  { MQ_CMD_CREATE_CHANNEL,                  "CREATE_CHANNEL" },
  { MQ_CMD_DELETE_CHANNEL,                  "DELETE_CHANNEL" },
  { MQ_CMD_INQUIRE_CHANNEL,                 "INQUIRE_CHANNEL" },
  { MQ_CMD_PING_CHANNEL,                    "PING_CHANNEL" },
  { MQ_CMD_RESET_CHANNEL,                   "RESET_CHANNEL" },
  { MQ_CMD_START_CHANNEL,                   "START_CHANNEL" },
  { MQ_CMD_STOP_CHANNEL,                    "STOP_CHANNEL" },
  { MQ_CMD_START_CHANNEL_INIT,              "START_CHANNEL_INIT" },
  { MQ_CMD_START_CHANNEL_LISTENER,          "START_CHANNEL_LISTENER" },
  { MQ_CMD_CHANGE_NAMELIST,                 "CHANGE_NAMELIST" },
  { MQ_CMD_CREATE_NAMELIST,                 "CREATE_NAMELIST" },
  { MQ_CMD_DELETE_NAMELIST,                 "DELETE_NAMELIST" },
  { MQ_CMD_INQUIRE_NAMELIST,                "INQUIRE_NAMELIST" },
  { MQ_CMD_INQUIRE_NAMELIST_NAMES,          "INQUIRE_NAMELIST_NAMES" },
  { MQ_CMD_ESCAPE,                          "ESCAPE" },
  { MQ_CMD_RESOLVE_CHANNEL,                 "RESOLVE_CHANNEL" },
  { MQ_CMD_PING_Q_MGR,                      "PING_Q_MGR" },
  { MQ_CMD_INQUIRE_Q_STATUS,                "INQUIRE_Q_STATUS" },
  { MQ_CMD_INQUIRE_CHANNEL_STATUS,          "INQUIRE_CHANNEL_STATUS" },
  { MQ_CMD_CONFIG_EVENT,                    "CONFIG_EVENT" },
  { MQ_CMD_Q_MGR_EVENT,                     "Q_MGR_EVENT" },
  { MQ_CMD_PERFM_EVENT,                     "PERFM_EVENT" },
  { MQ_CMD_CHANNEL_EVENT,                   "CHANNEL_EVENT" },
  { MQ_CMD_DELETE_PUBLICATION,              "DELETE_PUBLICATION" },
  { MQ_CMD_DEREGISTER_PUBLISHER,            "DEREGISTER_PUBLISHER" },
  { MQ_CMD_DEREGISTER_SUBSCRIBER,           "DEREGISTER_SUBSCRIBER" },
  { MQ_CMD_PUBLISH,                         "PUBLISH" },
  { MQ_CMD_REGISTER_PUBLISHER,              "REGISTER_PUBLISHER" },
  { MQ_CMD_REGISTER_SUBSCRIBER,             "REGISTER_SUBSCRIBER" },
  { MQ_CMD_REQUEST_UPDATE,                  "REQUEST_UPDATE" },
  { MQ_CMD_BROKER_INTERNAL,                 "BROKER_INTERNAL" },
  { MQ_CMD_INQUIRE_CLUSTER_Q_MGR,           "INQUIRE_CLUSTER_Q_MGR" },
  { MQ_CMD_RESUME_Q_MGR_CLUSTER,            "RESUME_Q_MGR_CLUSTER" },
  { MQ_CMD_SUSPEND_Q_MGR_CLUSTER,           "SUSPEND_Q_MGR_CLUSTER" },
  { MQ_CMD_REFRESH_CLUSTER,                 "REFRESH_CLUSTER" },
  { MQ_CMD_REFRESH_SECURITY,                "REFRESH_SECURITY" },
  { MQ_CMD_CHANGE_AUTH_INFO,                "CHANGE_AUTH_INFO" },
  { MQ_CMD_COPY_AUTH_INFO,                  "COPY_AUTH_INFO" },
  { MQ_CMD_CREATE_AUTH_INFO,                "CREATE_AUTH_INFO" },
  { MQ_CMD_DELETE_AUTH_INFO,                "DELETE_AUTH_INFO" },
  { MQ_CMD_INQUIRE_AUTH_INFO,               "INQUIRE_AUTH_INFO" },
  { MQ_CMD_INQUIRE_AUTH_INFO_NAMES,         "INQUIRE_AUTH_INFO_NAMES" },
  { 0,          NULL }
};

static guint32 tvb_get_guint32_endian(tvbuff_t *a_tvb, gint a_iOffset, gboolean a_bLittleEndian)
{
	guint32 iResult;
	if (a_bLittleEndian)
		iResult = tvb_get_letohl(a_tvb, a_iOffset);
	else
		iResult =  tvb_get_ntohl(a_tvb, a_iOffset);
	return iResult;
}

static void
dissect_mqpcf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*mq_tree = NULL;
	proto_tree	*mqroot_tree = NULL;
	proto_item	*ti = NULL;
	gint offset = 0;
	struct mqinfo* mqinfo = pinfo->private_data;
	gboolean bLittleEndian;
	bLittleEndian = ((mqinfo->encoding & MQ_ENC_INTEGER_REVERSED) != 0) ? TRUE : FALSE;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MQ PCF");
	col_clear(pinfo->cinfo, COL_INFO);
	if (tvb_length(tvb) >= 36)
	{
		gint iSizeMQCFH = 36;
		guint32 iCommand = tvb_get_guint32_endian(tvb, offset + 12, bLittleEndian);

		if (check_col(pinfo->cinfo, COL_INFO))
		{
			col_append_str(pinfo->cinfo, COL_INFO, val_to_str(iCommand, mqpcf_opcode_vals, "Unknown (0x%02x)"));
		}

		if (tree)
		{
			ti = proto_tree_add_item(tree, proto_mqpcf, tvb, offset, -1, FALSE);
			proto_item_append_text(ti, " (%s)", val_to_str(iCommand, mqpcf_opcode_vals, "Unknown (0x%02x)"));
			mqroot_tree = proto_item_add_subtree(ti, ett_mqpcf);

			ti = proto_tree_add_text(mqroot_tree, tvb, offset, iSizeMQCFH, MQ_TEXT_CFH);
			mq_tree = proto_item_add_subtree(ti, ett_mqpcf_cfh);

			proto_tree_add_item(mq_tree, hf_mqpcf_cfh_type, tvb, offset + 0, 4, bLittleEndian);
			proto_tree_add_item(mq_tree, hf_mqpcf_cfh_length, tvb, offset + 4, 4, bLittleEndian);
			proto_tree_add_item(mq_tree, hf_mqpcf_cfh_version, tvb, offset + 8, 4, bLittleEndian);
			proto_tree_add_item(mq_tree, hf_mqpcf_cfh_command, tvb, offset + 12, 4, bLittleEndian);
			proto_tree_add_item(mq_tree, hf_mqpcf_cfh_msgseqnumber, tvb, offset + 16, 4, bLittleEndian);
			proto_tree_add_item(mq_tree, hf_mqpcf_cfh_control, tvb, offset + 20, 4, bLittleEndian);
			proto_tree_add_item(mq_tree, hf_mqpcf_cfh_compcode, tvb, offset + 24, 4, bLittleEndian);
			proto_tree_add_item(mq_tree, hf_mqpcf_cfh_reason, tvb, offset + 28, 4, bLittleEndian);
			proto_tree_add_item(mq_tree, hf_mqpcf_cfh_paramcount, tvb, offset + 32, 4, bLittleEndian);
		}
		offset += iSizeMQCFH;
	}
}

static gboolean
dissect_mqpcf_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if (tvb_length(tvb) >= 36)
	{
		struct mqinfo* mqinfo = pinfo->private_data;
		if (strncmp((const char*)mqinfo->format, MQ_FMT_ADMIN, 8) == 0
			|| strncmp((const char*)mqinfo->format, MQ_FMT_EVENT, 8) == 0
			|| strncmp((const char*)mqinfo->format, MQ_FMT_PCF, 8) == 0)
		{
			/* Dissect the packet */
			dissect_mqpcf(tvb, pinfo, tree);
			return TRUE;
		}
	}
	return FALSE;
}

void
proto_register_mqpcf(void)
{
  static hf_register_info hf[] = {
   { &hf_mqpcf_cfh_type,
      { "Type", "mqpcf.cfh.type", FT_UINT32, BASE_DEC, NULL, 0x0, "CFH type", HFILL }},

   { &hf_mqpcf_cfh_length,
      { "Length", "mqpcf.cfh.length", FT_UINT32, BASE_DEC, NULL, 0x0, "CFH length", HFILL }},

   { &hf_mqpcf_cfh_version,
      { "Version", "mqpcf.cfh.version", FT_UINT32, BASE_DEC, NULL, 0x0, "CFH version", HFILL }},

   { &hf_mqpcf_cfh_command,
      { "Command", "mqpcf.cfh.command", FT_UINT32, BASE_DEC, NULL, 0x0, "CFH command", HFILL }},

   { &hf_mqpcf_cfh_msgseqnumber,
      { "Message sequence number", "mqpcf.cfh.msgseqnumber", FT_UINT32, BASE_DEC, NULL, 0x0, "CFH message sequence number", HFILL }},

   { &hf_mqpcf_cfh_control,
      { "Control", "mqpcf.cfh.control", FT_UINT32, BASE_DEC, NULL, 0x0, "CFH control", HFILL }},

   { &hf_mqpcf_cfh_compcode,
      { "Completion code", "mqpcf.cfh.compcode", FT_UINT32, BASE_DEC, NULL, 0x0, "CFH completion code", HFILL }},

   { &hf_mqpcf_cfh_reason,
      { "Reason code", "mqpcf.cfh.reasoncode", FT_UINT32, BASE_DEC, NULL, 0x0, "CFH reason code", HFILL }},

   { &hf_mqpcf_cfh_paramcount,
      { "Parameter count", "mqpcf.cfh.paramcount", FT_UINT32, BASE_DEC, NULL, 0x0, "CFH parameter count", HFILL }}
  };
  static gint *ett[] = {
    &ett_mqpcf,
    &ett_mqpcf_cfh,
  };

  proto_mqpcf = proto_register_protocol("WebSphere MQ Programmable Command Formats", "MQ PCF", "mqpcf");
  proto_register_field_array(proto_mqpcf, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_mqpcf(void)
{
	heur_dissector_add("mq", dissect_mqpcf_heur, proto_mqpcf);
}

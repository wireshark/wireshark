/* packet-ndmp.c
 * Routines for NDMP
 * Ronnie Sahlberg (see AUTHORS for email)
 *
 * $Id: packet-ndmp.c,v 1.1 2001/12/23 21:36:57 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

/* see www.ndmp.org for protocol specifications.
   this file implements version 3 of ndmp 
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>

#include "packet.h"
#include "prefs.h"

#define TCP_PORT_NDMP 10000

static int proto_ndmp = -1;
static int hf_ndmp_version = -1;
static int hf_ndmp_size = -1;
static int hf_ndmp_header = -1;
static int hf_ndmp_sequence = -1;
static int hf_ndmp_reply_sequence = -1;
static int hf_ndmp_timestamp = -1;
static int hf_ndmp_msgtype = -1;
static int hf_ndmp_msg = -1;
static int hf_ndmp_error = -1;

static gint ett_ndmp = -1;
static gint ett_ndmp_header = -1;

/* desegmentation of NDMP packets */
static gboolean ndmp_desegment = FALSE;


#define NDMP_MESSAGE_REQUEST	0x00
#define NDMP_MESSAGE_REPLY	0x01
static const value_string msg_type_vals[] = {
	{NDMP_MESSAGE_REQUEST,		"Request"},
	{NDMP_MESSAGE_REPLY,		"Reply"},
	{0, NULL}
};

#define NDMP_NO_ERR			0x00
#define NDMP_NOT_SUPPORTED_ERR		0x01
#define NDMP_DEVICE_BUSY_ERR		0x02
#define NDMP_DEVICE_OPENED_ERR		0x03
#define NDMP_NOT_AUTHORIZED_ERR		0x04
#define NDMP_PERMISSION_ERR		0x05
#define NDMP_DEV_NOT_OPEN_ERR		0x06
#define NDMP_IO_ERR			0x07
#define NDMP_TIMEOUT_ERR		0x08
#define NDMP_ILLEGAL_ARGS_ERR		0x09
#define NDMP_NO_TAPE_LOADED_ERR		0x0a
#define NDMP_WRITE_PROTECT_ERR		0x0b
#define NDMP_EOF_ERR			0x0c
#define NDMP_EOM_ERR			0x0d
#define NDMP_FILE_NOT_FOUND_ERR		0x0e
#define NDMP_BAD_FILE_ERR		0x0f
#define NDMP_NO_DEVICE_ERR		0x10
#define NDMP_NO_BUS_ERR			0x11
#define NDMP_XDR_DECODE_ERR		0x12
#define NDMP_ILLEGAL_STATE_ERR		0x13
#define NDMP_UNDEFINED_ERR		0x14
#define NDMP_XDR_ENCODE_ERR		0x15
#define NDMP_NO_MEM_ERR			0x16
#define NDMP_CONNECT_ERR		0x17

static const value_string error_vals[] = {
	{NDMP_NO_ERR,			"NO_ERR"},
	{NDMP_NOT_SUPPORTED_ERR,	"NOT_SUPPORTED_ERR"},
	{NDMP_DEVICE_BUSY_ERR,		"DEVICE_BUSY_ERR"},
	{NDMP_DEVICE_OPENED_ERR,	"DEVICE_OPENED_ERR"},
	{NDMP_NOT_AUTHORIZED_ERR,	"NOT_AUTHORIZED_ERR"},
	{NDMP_PERMISSION_ERR,		"PERMISSION_ERR"},
	{NDMP_DEV_NOT_OPEN_ERR,		"DEV_NOT_OPEN_ERR"},
	{NDMP_IO_ERR,			"IO_ERR"},
	{NDMP_TIMEOUT_ERR,		"TIMEOUT_ERR"},
	{NDMP_ILLEGAL_ARGS_ERR,		"ILLEGAL_ARGS_ERR"},
	{NDMP_NO_TAPE_LOADED_ERR,	"NO_TAPE_LOADED_ERR"},
	{NDMP_WRITE_PROTECT_ERR,	"WRITE_PROTECT_ERR"},
	{NDMP_EOF_ERR,			"EOF_ERR"},
	{NDMP_EOM_ERR,			"EOM_ERR"},
	{NDMP_FILE_NOT_FOUND_ERR,	"FILE_NOT_FOUND_ERR"},
	{NDMP_BAD_FILE_ERR,		"BAD_FILE_ERR"},
	{NDMP_NO_DEVICE_ERR,		"NO_DEVICE_ERR"},
	{NDMP_NO_BUS_ERR,		"NO_BUS_ERR"},
	{NDMP_XDR_DECODE_ERR,		"XDR_DECODE_ERR"},
	{NDMP_ILLEGAL_STATE_ERR,	"ILLEGAL_STATE_ERR"},
	{NDMP_UNDEFINED_ERR,		"UNDEFINED_ERR"},
	{NDMP_XDR_ENCODE_ERR,		"XDR_ENCODE_ERR"},
	{NDMP_NO_MEM_ERR,		"NO_MEM_ERR"},
	{NDMP_CONNECT_ERR,		"CONNECT_ERR"},
	{0, NULL}
};



#define NDMP_CONFIG_GET_HOST_INFO 	0x100
#define NDMP_CONFIG_GET_CONNECTION_TYPE 0x102
#define NDMP_CONFIG_GET_AUTH_ATTR 	0x103
#define NDMP_CONFIG_GET_BUTYPE_INFO 	0x104
#define NDMP_CONFIG_GET_FS_INFO 	0x105
#define NDMP_CONFIG_GET_TAPE_INFO 	0x106
#define NDMP_CONFIG_GET_SCSI_INFO 	0x107
#define NDMP_CONFIG_GET_SERVER_INFO 	0x108
#define NDMP_SCSI_OPEN 			0x200
#define NDMP_SCSI_CLOSE 		0x201
#define NDMP_SCSI_GET_STATE 		0x202
#define NDMP_SCSI_SET_TARGET 		0x203
#define NDMP_SCSI_RESET_DEVICE 		0x204
#define NDMP_SCSI_RESET_BUS 		0x205
#define NDMP_SCSI_EXECUTE_CDB 		0x206
#define NDMP_TAPE_OPEN 			0x300
#define NDMP_TAPE_CLOSE 		0x301
#define NDMP_TAPE_GET_STATE 		0x302
#define NDMP_TAPE_MTIO 			0x303
#define NDMP_TAPE_WRITE 		0x304
#define NDMP_TAPE_READ 			0x305
#define NDMP_TAPE_EXECUTE_CDB 		0x307
#define NDMP_DATA_GET_STATE 		0x400
#define NDMP_DATA_START_BACKUP 		0x401
#define NDMP_DATA_START_RECOVER 	0x402
#define NDMP_DATA_ABORT 		0x403
#define NDMP_DATA_GET_ENV 		0x404
#define NDMP_DATA_STOP 			0x407
#define NDMP_DATA_LISTEN 		0x409
#define NDMP_DATA_CONNECT 		0x40a
#define NDMP_NOTIFY_DATA_HALTED 	0x501
#define NDMP_NOTIFY_CONNECTED 		0x502
#define NDMP_NOTIFY_MOVER_HALTED 	0x503
#define NDMP_NOTIFY_MOVER_PAUSED 	0x504
#define NDMP_NOTIFY_DATA_READ 		0x505
#define NDMP_LOG_FILE 			0x602
#define NDMP_LOG_MESSAGE 		0x603
#define NDMP_FH_ADD_FILE 		0x703
#define NDMP_FH_ADD_DIR 		0x704
#define NDMP_FH_ADD_NODE 		0x705
#define NDMP_CONNECT_OPEN 		0x900
#define NDMP_CONNECT_CLIENT_AUTH	0x901
#define NDMP_CONNECT_CLOSE 		0x902
#define NDMP_CONNECT_SERVER_AUTH 	0x903
#define NDMP_MOVER_GET_STATE 		0xa00
#define NDMP_MOVER_LISTEN 		0xa01
#define NDMP_MOVER_CONTINUE 		0xa02
#define NDMP_MOVER_ABORT 		0xa03
#define NDMP_MOVER_STOP 		0xa04
#define NDMP_MOVER_SET_WINDOW 		0xa05
#define NDMP_MOVER_READ 		0xa06
#define NDMP_MOVER_CLOSE 		0xa07
#define NDMP_MOVER_SET_RECORD_SIZE 	0xa08
#define NDMP_MOVER_CONNECT 		0xa09




static const value_string msg_vals[] = {
	{NDMP_CONFIG_GET_HOST_INFO, 	"CONFIG_GET_HOST_INFO"},
	{NDMP_CONFIG_GET_CONNECTION_TYPE, "CONFIG_GET_CONNECTION_TYPE"},
	{NDMP_CONFIG_GET_AUTH_ATTR, 	"CONFIG_GET_AUTH_ATTR"},
	{NDMP_CONFIG_GET_BUTYPE_INFO, 	"CONFIG_GET_BUTYPE_INFO"},
	{NDMP_CONFIG_GET_FS_INFO, 	"CONFIG_GET_FS_INFO"},
	{NDMP_CONFIG_GET_TAPE_INFO, 	"CONFIG_GET_TAPE_INFO"},
	{NDMP_CONFIG_GET_SCSI_INFO, 	"CONFIG_GET_SCSI_INFO"},
	{NDMP_CONFIG_GET_SERVER_INFO, 	"CONFIG_GET_SERVER_INFO"},
	{NDMP_SCSI_OPEN, 		"SCSI_OPEN"},
	{NDMP_SCSI_CLOSE, 		"SCSI_CLOSE"},
	{NDMP_SCSI_GET_STATE, 		"SCSI_GET_STATE"},
	{NDMP_SCSI_SET_TARGET, 		"SCSI_SET_TARGET"},
	{NDMP_SCSI_RESET_DEVICE, 	"SCSI_RESET_DEVICE"},
	{NDMP_SCSI_RESET_BUS, 		"SCSI_RESET_BUS"},
	{NDMP_SCSI_EXECUTE_CDB, 	"SCSI_EXECUTE_CDB"},
	{NDMP_TAPE_OPEN, 		"TAPE_OPEN"},
	{NDMP_TAPE_CLOSE, 		"TAPE_CLOSE"},
	{NDMP_TAPE_GET_STATE, 		"TAPE_GET_STATE"},
	{NDMP_TAPE_MTIO, 		"TAPE_MTIO"},
	{NDMP_TAPE_WRITE, 		"TAPE_WRITE"},
	{NDMP_TAPE_READ, 		"TAPE_READ"},
	{NDMP_TAPE_EXECUTE_CDB, 	"TAPE_EXECUTE_CDB"},
	{NDMP_DATA_GET_STATE, 		"DATA_GET_STATE"},
	{NDMP_DATA_START_BACKUP, 	"DATA_START_BACKUP"},
	{NDMP_DATA_START_RECOVER, 	"DATA_START_RECOVER"},
	{NDMP_DATA_ABORT, 		"DATA_ABORT"},
	{NDMP_DATA_GET_ENV, 		"DATA_GET_ENV"},
	{NDMP_DATA_STOP, 		"DATA_STOP"},
	{NDMP_DATA_LISTEN, 		"DATA_LISTEN"},
	{NDMP_DATA_CONNECT, 		"DATA_CONNECT"},
	{NDMP_NOTIFY_DATA_HALTED, 	"NOTIFY_DATA_HALTED"},
	{NDMP_NOTIFY_CONNECTED, 	"NOTIFY_CONNECTED"},
	{NDMP_NOTIFY_MOVER_HALTED, 	"NOTIFY_MOVER_HALTED"},
	{NDMP_NOTIFY_MOVER_PAUSED, 	"NOTIFY_MOVER_PAUSED"},
	{NDMP_NOTIFY_DATA_READ, 	"NOTIFY_DATA_READ"},
	{NDMP_LOG_FILE, 		"LOG_FILE"},
	{NDMP_LOG_MESSAGE, 		"LOG_MESSAGE"},
	{NDMP_FH_ADD_FILE, 		"FH_ADD_FILE"},
	{NDMP_FH_ADD_DIR, 		"FH_ADD_DIR"},
	{NDMP_FH_ADD_NODE, 		"FH_ADD_NODE"},
	{NDMP_CONNECT_OPEN, 		"CONNECT_OPEN"},
	{NDMP_CONNECT_CLIENT_AUTH, 	"CONNECT_CLIENT_AUTH"},
	{NDMP_CONNECT_CLOSE, 		"CONNECT_CLOSE"},
	{NDMP_CONNECT_SERVER_AUTH, 	"CONNECT_SERVER_AUTH"},
	{NDMP_MOVER_GET_STATE, 		"MOVER_GET_STATE"},
	{NDMP_MOVER_LISTEN, 		"MOVER_LISTEN"},
	{NDMP_MOVER_CONTINUE, 		"MOVER_CONTINUE"},
	{NDMP_MOVER_ABORT, 		"MOVER_ABORT"},
	{NDMP_MOVER_STOP, 		"MOVER_STOP"},
	{NDMP_MOVER_SET_WINDOW, 	"MOVER_SET_WINDOW"},
	{NDMP_MOVER_READ, 		"MOVER_READ"},
	{NDMP_MOVER_CLOSE, 		"MOVER_CLOSE"},
	{NDMP_MOVER_SET_RECORD_SIZE, 	"MOVER_SET_RECORD_SIZE"},
	{NDMP_MOVER_CONNECT, 		"MOVER_CONNECT"},
	{0, NULL}
};


static int
dissect_connect_open_request(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* version number */
	proto_tree_add_item(tree, hf_ndmp_version, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;
}

static int
dissect_error(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* error */
	proto_tree_add_item(tree, hf_ndmp_error, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;
}


typedef struct _ndmp_command {
	guint32 cmd;
	int (*request) (tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
	int (*response)(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
} ndmp_command;

static const ndmp_command ndmp_commands[] = {
	{NDMP_CONFIG_GET_HOST_INFO, 	NULL,NULL},
	{NDMP_CONFIG_GET_CONNECTION_TYPE, NULL,NULL},
	{NDMP_CONFIG_GET_AUTH_ATTR, 	NULL,NULL},
	{NDMP_CONFIG_GET_BUTYPE_INFO, 	NULL,NULL},
	{NDMP_CONFIG_GET_FS_INFO, 	NULL,NULL},
	{NDMP_CONFIG_GET_TAPE_INFO, 	NULL,NULL},
	{NDMP_CONFIG_GET_SCSI_INFO, 	NULL,NULL},
	{NDMP_CONFIG_GET_SERVER_INFO, 	NULL,NULL},
	{NDMP_SCSI_OPEN, 		NULL,NULL},
	{NDMP_SCSI_CLOSE, 		NULL,NULL},
	{NDMP_SCSI_GET_STATE, 		NULL,NULL},
	{NDMP_SCSI_SET_TARGET, 		NULL,NULL},
	{NDMP_SCSI_RESET_DEVICE, 	NULL,NULL},
	{NDMP_SCSI_RESET_BUS, 		NULL,NULL},
	{NDMP_SCSI_EXECUTE_CDB, 	NULL,NULL},
	{NDMP_TAPE_OPEN, 		NULL,NULL},
	{NDMP_TAPE_CLOSE, 		NULL,NULL},
	{NDMP_TAPE_GET_STATE, 		NULL,NULL},
	{NDMP_TAPE_MTIO, 		NULL,NULL},
	{NDMP_TAPE_WRITE, 		NULL,NULL},
	{NDMP_TAPE_READ, 		NULL,NULL},
	{NDMP_TAPE_EXECUTE_CDB, 	NULL,NULL},
	{NDMP_DATA_GET_STATE, 		NULL,NULL},
	{NDMP_DATA_START_BACKUP, 	NULL,NULL},
	{NDMP_DATA_START_RECOVER, 	NULL,NULL},
	{NDMP_DATA_ABORT, 		NULL,NULL},
	{NDMP_DATA_GET_ENV, 		NULL,NULL},
	{NDMP_DATA_STOP, 		NULL,NULL},
	{NDMP_DATA_LISTEN, 		NULL,NULL},
	{NDMP_DATA_CONNECT, 		NULL,NULL},
	{NDMP_NOTIFY_DATA_HALTED, 	NULL,NULL},
	{NDMP_NOTIFY_CONNECTED, 	NULL,NULL},
	{NDMP_NOTIFY_MOVER_HALTED, 	NULL,NULL},
	{NDMP_NOTIFY_MOVER_PAUSED, 	NULL,NULL},
	{NDMP_NOTIFY_DATA_READ, 	NULL,NULL},
	{NDMP_LOG_FILE, 		NULL,NULL},
	{NDMP_LOG_MESSAGE, 		NULL,NULL},
	{NDMP_FH_ADD_FILE, 		NULL,NULL},
	{NDMP_FH_ADD_DIR, 		NULL,NULL},
	{NDMP_FH_ADD_NODE, 		NULL,NULL},
	{NDMP_CONNECT_OPEN, 		dissect_connect_open_request, dissect_error},
	{NDMP_CONNECT_CLIENT_AUTH, 	NULL,NULL},
	{NDMP_CONNECT_CLOSE, 		NULL,NULL},
	{NDMP_CONNECT_SERVER_AUTH, 	NULL,NULL},
	{NDMP_MOVER_GET_STATE, 		NULL,NULL},
	{NDMP_MOVER_LISTEN, 		NULL,NULL},
	{NDMP_MOVER_CONTINUE, 		NULL,NULL},
	{NDMP_MOVER_ABORT, 		NULL,NULL},
	{NDMP_MOVER_STOP, 		NULL,NULL},
	{NDMP_MOVER_SET_WINDOW, 	NULL,NULL},
	{NDMP_MOVER_READ, 		NULL,NULL},
	{NDMP_MOVER_CLOSE, 		NULL,NULL},
	{NDMP_MOVER_SET_RECORD_SIZE, 	NULL,NULL},
	{NDMP_MOVER_CONNECT, 		NULL,NULL},
	{0, NULL,NULL}
};


static int
dissect_ndmp_header(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item* item = NULL;
	proto_tree* tree = NULL;
	guint32 msgtype, msg;

	if (parent_tree) {
		item = proto_tree_add_item(tree, hf_ndmp_header, tvb,
				offset, 24, FALSE);
		tree = proto_item_add_subtree(item, ett_ndmp_header);
	}

	/* sequence number */
	proto_tree_add_item(tree, hf_ndmp_sequence, tvb, offset, 4, FALSE);
	offset += 4;

	/* timestamp */
	proto_tree_add_item(tree, hf_ndmp_timestamp, tvb, offset, 4, FALSE);
	offset += 4;

	/* Message Type */
	msgtype = tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(tree, hf_ndmp_msgtype, tvb, offset, 4, FALSE);
	offset += 4;

	/* Message */
	msg = tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(tree, hf_ndmp_msg, tvb, offset, 4, FALSE);
	offset += 4;

	/* Reply sequence number */
	proto_tree_add_item(tree, hf_ndmp_reply_sequence, tvb, offset, 4, FALSE);
	offset += 4;

	/* error */
	proto_tree_add_item(tree, hf_ndmp_error, tvb, offset, 4, FALSE);
	offset += 4;

	if (check_col(pinfo->cinfo, COL_INFO)){
		col_clear(pinfo->cinfo, COL_INFO);
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s %s",
			val_to_str(msg, msg_vals, "Unknown Message (0x%02x)"),
			val_to_str(msgtype, msg_type_vals, "Unknown Type (0x%02x)")
			);
	}

	return offset;
}


static int
dissect_ndmp_cmd(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	int i;
	guint32 msg, msgtype;

	msg=tvb_get_ntohl(tvb, offset+12);
	msgtype=tvb_get_ntohl(tvb, offset+8);

	offset=dissect_ndmp_header(tvb, offset, pinfo, tree);


	for(i=0;ndmp_commands[i].cmd!=0;i++){
		if(ndmp_commands[i].cmd==msg){
			break;
		}
	}


	if(ndmp_commands[i].cmd==0){
		/* we do not know this message */
		proto_tree_add_text(tree, tvb, offset, tvb_length_remaining(tvb, offset), "Unknown type of NDMP message: 0x%02x", msg);
		offset+=tvb_length_remaining(tvb, offset);
		return offset;
	}


	if(msgtype==NDMP_MESSAGE_REQUEST){
		offset=ndmp_commands[i].request(tvb, offset, pinfo, tree);
	} else {
		offset=ndmp_commands[i].response(tvb, offset, pinfo, tree);
	}

	return offset;
}

static void
dissect_ndmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	guint32 size, available_bytes;

	/* loop through the packet, dissecting multiple NDMP pdus*/
	do {
		available_bytes = tvb_length_remaining(tvb, offset);

		/* size of this NDMP PDU */
		size = tvb_get_ntohl(tvb, offset);	

		/* desegmentation */
		if(ndmp_desegment){
			if(pinfo->can_desegment
			&& size>available_bytes) {
				pinfo->desegment_offset = offset;
				pinfo->desegment_len = size-available_bytes;
				return;
			}
		}

		/* the size of the current PDU */
		proto_tree_add_item(tree, hf_ndmp_size, tvb, offset, 4, size);
		offset += 4;

		offset = dissect_ndmp_cmd(tvb, offset, pinfo, tree);
	} while(offset<(int)tvb_reported_length(tvb));

}




void
proto_register_ndmp(void)
{

  static hf_register_info hf_ndmp[] = {
	{ &hf_ndmp_size, {
		"Size", "ndmp.size", FT_UINT32, BASE_DEC,
		NULL, 0, "Size of this NDMP PDU", HFILL }},

	{ &hf_ndmp_header, {
		"NDMP Header", "ndmp.header", FT_NONE, 0,
		NULL, 0, "NDMP Header", HFILL }},

	{ &hf_ndmp_sequence, {
		"Sequence", "ndmp.sequence", FT_UINT32, BASE_DEC,
		NULL, 0, "Sequence number for NDMP PDU", HFILL }},

	{ &hf_ndmp_reply_sequence, {
		"Reply Sequence", "ndmp.reply_sequence", FT_UINT32, BASE_DEC,
		NULL, 0, "Reply Sequence number for NDMP PDU", HFILL }},

	{ &hf_ndmp_timestamp, {
		"Time", "ndmp.timestamp", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Timestamp for this NDMP PDU", HFILL }},

	{ &hf_ndmp_msgtype, {
		"Type", "ndmp.msg_type", FT_UINT32, BASE_DEC,
		VALS(msg_type_vals), 0, "Is this a Request or Response?", HFILL }},

	{ &hf_ndmp_msg, {
		"Message", "ndmp.msg", FT_UINT32, BASE_DEC,
		VALS(msg_vals), 0, "Type of NDMP PDU", HFILL }},

	{ &hf_ndmp_error, {
		"Error", "ndmp.error", FT_UINT32, BASE_DEC,
		VALS(error_vals), 0, "Error code for this NDMP PDU", HFILL }},

	{ &hf_ndmp_version, {
		"Version", "ndmp.version", FT_UINT32, BASE_DEC,
		NULL, 0, "Version of NDMP protocol", HFILL }},


  };

  static gint *ett[] = {
    &ett_ndmp,
    &ett_ndmp_header,
  };

  module_t *ndmp_module;

  proto_ndmp = proto_register_protocol("Network Data Management Protocol", "NDMP", "ndmp");
  proto_register_field_array(proto_ndmp, hf_ndmp, array_length(hf_ndmp));
  
  proto_register_subtree_array(ett, array_length(ett));

  /* desegmentation */
  ndmp_module = prefs_register_protocol(proto_ndmp, NULL);
  prefs_register_bool_preference(ndmp_module, "ndmp.desegment", "Desegment all NDMP messages spanning multiple TCP segments", "Whether the dissector should desegment NDMP over TCP PDUs or not", &ndmp_desegment);

}

void
proto_reg_handoff_ndmp(void)
{
  dissector_handle_t ndmp_handle;

  ndmp_handle = create_dissector_handle(dissect_ndmp, proto_ndmp);
  dissector_add("tcp.port",TCP_PORT_NDMP, ndmp_handle);
}

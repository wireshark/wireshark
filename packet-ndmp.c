/* XXX TODO:
   Someone should take packet-iscsi.c apart and break all the SCSI-CDB stuff
   out and put SCSI-CDB in packet-scsi.c instead.
   Then packet-iscsi.c only contains the iscsi layer and it will call
   packet-scsi.c to dissect the cdb's.
   Then we can call packet-scsi.c to dissect the scsi cdb's 
   from here as well.

   volunteers?
*/
/* packet-ndmp.c
 * Routines for NDMP dissection
 * 2001 Ronnie Sahlberg (see AUTHORS for email)
 *
 * $Id: packet-ndmp.c,v 1.11 2002/01/21 23:35:32 guy Exp $
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

#include <epan/packet.h>
#include "packet-rpc.h"
#include "prefs.h"

#define TCP_PORT_NDMP 10000

#define NDMP_FRAGLEN 0x7fffffffL

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
static int hf_ndmp_hostname = -1;
static int hf_ndmp_os_type = -1;
static int hf_ndmp_os_vers = -1;
static int hf_ndmp_hostid = -1;
static int hf_ndmp_addr_types = -1;
static int hf_ndmp_addr_type = -1;
static int hf_ndmp_auth_type = -1;
static int hf_ndmp_auth_types = -1;
static int hf_ndmp_auth_challenge = -1;
static int hf_ndmp_auth_digest = -1;
static int hf_ndmp_auth_id = -1;
static int hf_ndmp_auth_password = -1;
static int hf_ndmp_butype_info = -1;
static int hf_ndmp_butype_name = -1;
static int hf_ndmp_butype_default_env = -1;
static int hf_ndmp_butype_attr_backup_file_history = -1;
static int hf_ndmp_butype_attr_backup_filelist = -1;
static int hf_ndmp_butype_attr_recover_filelist = -1;
static int hf_ndmp_butype_attr_backup_direct = -1;
static int hf_ndmp_butype_attr_recover_direct = -1;
static int hf_ndmp_butype_attr_backup_incremental = -1;
static int hf_ndmp_butype_attr_recover_incremental = -1;
static int hf_ndmp_butype_attr_backup_utf8 = -1;
static int hf_ndmp_butype_attr_recover_utf8 = -1;
static int hf_ndmp_butype_env_name = -1;
static int hf_ndmp_butype_env_value = -1;
static int hf_ndmp_fs_info = -1;
static int hf_ndmp_fs_invalid_total_size = -1;
static int hf_ndmp_fs_invalid_used_size = -1;
static int hf_ndmp_fs_invalid_avail_size = -1;
static int hf_ndmp_fs_invalid_total_inodes = -1;
static int hf_ndmp_fs_invalid_used_inodes = -1;
static int hf_ndmp_fs_fs_type = -1;
static int hf_ndmp_fs_logical_device = -1;
static int hf_ndmp_fs_physical_device = -1;
static int hf_ndmp_fs_total_size = -1;
static int hf_ndmp_fs_used_size = -1;
static int hf_ndmp_fs_avail_size = -1;
static int hf_ndmp_fs_total_inodes = -1;
static int hf_ndmp_fs_used_inodes = -1;
static int hf_ndmp_fs_env = -1;
static int hf_ndmp_fs_env_name = -1;
static int hf_ndmp_fs_env_value = -1;
static int hf_ndmp_fs_status = -1;
static int hf_ndmp_tape_info = -1;
static int hf_ndmp_tape_model = -1;
static int hf_ndmp_tape_dev_cap = -1;
static int hf_ndmp_tape_device = -1;
static int hf_ndmp_tape_open_mode = -1;
static int hf_ndmp_tape_attr_rewind = -1;
static int hf_ndmp_tape_attr_unload = -1;
static int hf_ndmp_tape_capability = -1;
static int hf_ndmp_tape_capability_name = -1;
static int hf_ndmp_tape_capability_value = -1;
static int hf_ndmp_scsi_info = -1;
static int hf_ndmp_scsi_model = -1;
static int hf_ndmp_server_vendor = -1;
static int hf_ndmp_server_product = -1;
static int hf_ndmp_server_revision = -1;
static int hf_ndmp_scsi_device = -1;
static int hf_ndmp_scsi_controller = -1;
static int hf_ndmp_scsi_id = -1;
static int hf_ndmp_scsi_lun = -1;
static int hf_ndmp_tape_invalid_file_num = -1;
static int hf_ndmp_tape_invalid_soft_errors = -1;
static int hf_ndmp_tape_invalid_block_size = -1;
static int hf_ndmp_tape_invalid_block_no = -1;
static int hf_ndmp_tape_invalid_total_space = -1;
static int hf_ndmp_tape_invalid_space_remain = -1;
static int hf_ndmp_tape_invalid_partition = -1;
static int hf_ndmp_tape_flags_no_rewind = -1;
static int hf_ndmp_tape_flags_write_protect = -1;
static int hf_ndmp_tape_flags_error = -1;
static int hf_ndmp_tape_flags_unload = -1;
static int hf_ndmp_tape_file_num = -1;
static int hf_ndmp_tape_soft_errors = -1;
static int hf_ndmp_tape_block_size = -1;
static int hf_ndmp_tape_block_no = -1;
static int hf_ndmp_tape_total_space = -1;
static int hf_ndmp_tape_space_remain = -1;
static int hf_ndmp_tape_partition = -1;
static int hf_ndmp_tape_mtio_op = -1;
static int hf_ndmp_count = -1;
static int hf_ndmp_resid_count = -1;
static int hf_ndmp_mover_state = -1;
static int hf_ndmp_mover_pause = -1;
static int hf_ndmp_halt = -1;
static int hf_ndmp_halt_reason = -1;
static int hf_ndmp_record_size = -1;
static int hf_ndmp_record_num = -1;
static int hf_ndmp_data_written = -1;
static int hf_ndmp_seek_position = -1;
static int hf_ndmp_bytes_left_to_read = -1;
static int hf_ndmp_window_offset = -1;
static int hf_ndmp_window_length = -1;
static int hf_ndmp_addr_ip = -1;
static int hf_ndmp_addr_tcp = -1;
static int hf_ndmp_addr_fcal_loop_id = -1;
static int hf_ndmp_addr_ipc = -1;
static int hf_ndmp_mover_mode = -1;
static int hf_ndmp_file_name = -1;
static int hf_ndmp_nt_file_name = -1;
static int hf_ndmp_dos_file_name = -1;
static int hf_ndmp_log_type = -1;
static int hf_ndmp_log_message_id = -1;
static int hf_ndmp_log_message = -1;
static int hf_ndmp_connected = -1;
static int hf_ndmp_connected_reason = -1;
static int hf_ndmp_data = -1;
static int hf_ndmp_files = -1;
static int hf_ndmp_file_fs_type = -1;
static int hf_ndmp_file_names = -1;
static int hf_ndmp_file_stats = -1;
static int hf_ndmp_file_node = -1;
static int hf_ndmp_file_parent = -1;
static int hf_ndmp_file_fh_info = -1;
static int hf_ndmp_file_invalid_atime = -1;
static int hf_ndmp_file_invalid_ctime = -1;
static int hf_ndmp_file_invalid_group = -1;
static int hf_ndmp_file_type = -1;
static int hf_ndmp_file_mtime = -1;
static int hf_ndmp_file_atime = -1;
static int hf_ndmp_file_ctime = -1;
static int hf_ndmp_file_owner = -1;
static int hf_ndmp_file_group = -1;
static int hf_ndmp_file_fattr = -1;
static int hf_ndmp_file_size = -1;
static int hf_ndmp_file_links = -1;
static int hf_ndmp_dirs = -1;
static int hf_ndmp_nodes = -1;
static int hf_ndmp_nlist = -1;
static int hf_ndmp_bu_original_path = -1;
static int hf_ndmp_bu_destination_dir = -1;
static int hf_ndmp_bu_new_name = -1;
static int hf_ndmp_bu_other_name = -1;
static int hf_ndmp_state_invalid_ebr = -1;
static int hf_ndmp_state_invalid_etr = -1;
static int hf_ndmp_bu_operation = -1;
static int hf_ndmp_data_state = -1;
static int hf_ndmp_data_halted = -1;
static int hf_ndmp_data_bytes_processed = -1;
static int hf_ndmp_data_est_bytes_remain = -1;
static int hf_ndmp_data_est_time_remain = -1;

static gint ett_ndmp = -1;
static gint ett_ndmp_header = -1;
static gint ett_ndmp_butype_attrs = -1;
static gint ett_ndmp_fs_invalid = -1;
static gint ett_ndmp_tape_attr = -1;
static gint ett_ndmp_tape_invalid = -1;
static gint ett_ndmp_tape_flags = -1;
static gint ett_ndmp_addr = -1;
static gint ett_ndmp_file = -1;
static gint ett_ndmp_file_name = -1;
static gint ett_ndmp_file_stats = -1;
static gint ett_ndmp_file_invalids = -1;
static gint ett_ndmp_state_invalids = -1;

struct ndmp_header {
	guint32	seq;
	guint32 time;
	guint32 type;
	guint32 msg;
	guint32 rep_seq;
	guint32 err;
};

/* desegmentation of NDMP packets */
static gboolean ndmp_desegment = TRUE;



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

static int
dissect_ndmp_get_host_info_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* error */
	proto_tree_add_item(tree, hf_ndmp_error, tvb, offset, 4, FALSE);
	offset += 4;

	/* hostname */
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_hostname, offset, NULL);

	/* os type */
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_os_type, offset, NULL);

	/* os version */
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_os_vers, offset, NULL);

	/* hostid */
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_hostid, offset, NULL);

	return offset;
}

#define NDMP_ADDR_LOCAL		0
#define NDMP_ADDR_TCP		1
#define NDMP_ADDR_FC		2
#define NDMP_ADDR_IPC		3
static const value_string addr_type_vals[] = {
	{NDMP_ADDR_LOCAL,	"Local"},
	{NDMP_ADDR_TCP,		"TCP"},
	{NDMP_ADDR_FC,		"FC"},
	{NDMP_ADDR_IPC,		"IPC"},
	{0,NULL}
};

static int
dissect_ndmp_addr_type(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/*address type*/
	proto_tree_add_item(tree, hf_ndmp_addr_type, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;
}

static int
dissect_ndmp_config_get_connection_type_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* error */
	proto_tree_add_item(tree, hf_ndmp_error, tvb, offset, 4, FALSE);
	offset += 4;

	/* addr types */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_ndmp_addr_type, hf_ndmp_addr_types);

	return offset;
}

#define NDMP_AUTH_NONE		0
#define NDMP_AUTH_TEXT		1
#define NDMP_AUTH_MD5		2
static const value_string auth_type_vals[] = {
	{NDMP_AUTH_NONE,	"None"},
	{NDMP_AUTH_TEXT,	"Text"},
	{NDMP_AUTH_MD5,		"MD5"},
	{0,NULL}
};
static int
dissect_auth_type(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* auth type */
	proto_tree_add_item(tree, hf_ndmp_auth_type, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;
}

static int
dissect_auth_attr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint type;
	
	type=tvb_get_ntohl(tvb,offset);

	/* auth type */
	proto_tree_add_item(tree, hf_ndmp_auth_type, tvb, offset, 4, FALSE);
	offset += 4;

	switch(type){
	case NDMP_AUTH_NONE:
		break;
	case NDMP_AUTH_TEXT:
		break;
	case NDMP_AUTH_MD5:
		proto_tree_add_item(tree, hf_ndmp_auth_challenge, 
			tvb, offset, 64, FALSE);
		offset+=64;
	}

	return offset;
}

static int
dissect_default_env(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* name */
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_butype_env_name, offset, NULL);

	/* value */
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_butype_env_value, offset, NULL);

	return offset;
}


static const true_false_string tfs_butype_attr_backup_file_history = {
	"Backup FILE HISTORY",
	"Do NOT backup file history"
};
static const true_false_string tfs_butype_attr_backup_filelist = {
	"Backup FILELIST",
	"Do NOT backup filelist"
};
static const true_false_string tfs_butype_attr_recover_filelist = {
	"Recover FILELIST",
	"Do NOT recover filelist"
};
static const true_false_string tfs_butype_attr_backup_direct = {
	"Perform DIRECT backup",
	"Do NOT perform direct backup"
};
static const true_false_string tfs_butype_attr_recover_direct = {
	"Perform DIRECT recovery",
	"Do NOT perform direct recovery"
};
static const true_false_string tfs_butype_attr_backup_incremental = {
	"Perform INCREMENTAL backup",
	"Perform FULL backup"
};
static const true_false_string tfs_butype_attr_recover_incremental = {
	"Perform INCREMENTAL revocery",
	"Perform FULL recovery"
};
static const true_false_string tfs_butype_attr_backup_utf8 = {
	"Backup using UTF8",
	"Normal backup. Do NOT use utf8"
};
static const true_false_string tfs_butype_attr_recover_utf8 = {
	"Recover using UTF8",
	"Normal recover. Do NOT use utf8"
};
static int
dissect_butype_attrs(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item* item = NULL;
	proto_tree* tree = NULL;
	guint32 flags;

	flags=tvb_get_ntohl(tvb, offset);
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, 4,
				"Attributes: 0x%08x ", flags);
		tree = proto_item_add_subtree(item, ett_ndmp_butype_attrs);
	}

	proto_tree_add_boolean(tree, hf_ndmp_butype_attr_recover_utf8,
				tvb, offset, 4, flags);
	proto_tree_add_boolean(tree, hf_ndmp_butype_attr_backup_utf8,
				tvb, offset, 4, flags);
	proto_tree_add_boolean(tree, hf_ndmp_butype_attr_recover_incremental,
				tvb, offset, 4, flags);
	proto_tree_add_boolean(tree, hf_ndmp_butype_attr_backup_incremental,
				tvb, offset, 4, flags);
	proto_tree_add_boolean(tree, hf_ndmp_butype_attr_recover_direct,
				tvb, offset, 4, flags);
	proto_tree_add_boolean(tree, hf_ndmp_butype_attr_backup_direct,
				tvb, offset, 4, flags);
	proto_tree_add_boolean(tree, hf_ndmp_butype_attr_recover_filelist,
				tvb, offset, 4, flags);
	proto_tree_add_boolean(tree, hf_ndmp_butype_attr_backup_filelist,
				tvb, offset, 4, flags);
	proto_tree_add_boolean(tree, hf_ndmp_butype_attr_backup_file_history,
				tvb, offset, 4, flags);

	offset += 4;
	return offset;
}

static int
dissect_butype_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/*butype name*/
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_butype_name, offset, NULL);

	/* default env */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_default_env, hf_ndmp_butype_default_env);

	/* attrs */
	offset = dissect_butype_attrs(tvb, offset, pinfo, tree);

	return offset;
}

static int
dissect_get_butype_info_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* error */
	proto_tree_add_item(tree, hf_ndmp_error, tvb, offset, 4, FALSE);
	offset += 4;

	/* butype */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_butype_info, hf_ndmp_butype_info);

	return offset;
}

static const true_false_string tfs_fs_invalid_total_size = {
	"Total size is INVALID",
	"Total size is VALID"
};
static const true_false_string tfs_fs_invalid_used_size = {
	"Used size is INVALID",
	"Used size is VALID"
};
static const true_false_string tfs_fs_invalid_avail_size = {
	"Available size is INVALID",
	"Available size is VALID"
};
static const true_false_string tfs_fs_invalid_total_inodes = {
	"Total inode count is INVALID",
	"Total inode count is VALID"
};
static const true_false_string tfs_fs_invalid_used_inodes = {
	"Used inode count is INVALID",
	"Used inode count is VALID"
};
static int
dissect_fs_invalid(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item* item = NULL;
	proto_tree* tree = NULL;
	guint32 flags;

	flags=tvb_get_ntohl(tvb, offset);
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, 4,
				"Invalids: 0x%08x ", flags);
		tree = proto_item_add_subtree(item, ett_ndmp_fs_invalid);
	}

	proto_tree_add_boolean(tree, hf_ndmp_fs_invalid_used_inodes,
				tvb, offset, 4, flags);
	proto_tree_add_boolean(tree, hf_ndmp_fs_invalid_total_inodes,
				tvb, offset, 4, flags);
	proto_tree_add_boolean(tree, hf_ndmp_fs_invalid_avail_size,
				tvb, offset, 4, flags);
	proto_tree_add_boolean(tree, hf_ndmp_fs_invalid_used_size,
				tvb, offset, 4, flags);
	proto_tree_add_boolean(tree, hf_ndmp_fs_invalid_total_size,
				tvb, offset, 4, flags);

	offset+=4;
	return offset;
}

static int
dissect_fs_env(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* name */
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_fs_env_name, offset, NULL);

	/* value */
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_fs_env_value, offset, NULL);

	return offset;
}

static int
dissect_fs_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* invalid bits */
	offset=dissect_fs_invalid(tvb, offset, pinfo, tree);

	/* fs type */
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_fs_fs_type, offset, NULL);

	/* fs logical device */
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_fs_logical_device, offset, NULL);

	/* fs physical device */
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_fs_physical_device, offset, NULL);

	/*total_size*/
	offset = dissect_rpc_uint64(tvb, pinfo, tree, hf_ndmp_fs_total_size,
			offset);

	/*used_size*/
	offset = dissect_rpc_uint64(tvb, pinfo, tree, hf_ndmp_fs_used_size,
			offset);

	/*avail_size*/
	offset = dissect_rpc_uint64(tvb, pinfo, tree, hf_ndmp_fs_avail_size,
			offset);

	/*total_inodes*/
	offset = dissect_rpc_uint64(tvb, pinfo, tree, hf_ndmp_fs_total_inodes,
			offset);

	/*used_inodes*/
	offset = dissect_rpc_uint64(tvb, pinfo, tree, hf_ndmp_fs_used_inodes,
			offset);

	/* env */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_fs_env, hf_ndmp_fs_env);

	/* status */
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_fs_status, offset, NULL);

	return offset;
}

static int
dissect_get_fs_info_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* error */
	proto_tree_add_item(tree, hf_ndmp_error, tvb, offset, 4, FALSE);
	offset += 4;

	/* fs */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_fs_info, hf_ndmp_fs_info);

	return offset;
}

static const true_false_string tfs_tape_attr_rewind = {
	"Device supports REWIND",
	"Device does NOT support rewind"
};
static const true_false_string tfs_tape_attr_unload = {
	"Device supports UNLOAD",
	"Device does NOT support unload"
};
static int
dissect_tape_attr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item* item = NULL;
	proto_tree* tree = NULL;
	guint32 flags;

	flags=tvb_get_ntohl(tvb, offset);
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, 4,
				"Attributes: 0x%08x ", flags);
		tree = proto_item_add_subtree(item, ett_ndmp_tape_attr);
	}

	proto_tree_add_boolean(tree, hf_ndmp_tape_attr_unload,
				tvb, offset, 4, flags);
	proto_tree_add_boolean(tree, hf_ndmp_tape_attr_rewind,
				tvb, offset, 4, flags);

	offset+=4;
	return offset;
}

static int
dissect_tape_capability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* name */
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_tape_capability_name, offset, NULL);

	/* value */
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_tape_capability_value, offset, NULL);

	return offset;
}

static int
dissect_tape_dev_cap(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* device */
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_tape_device, offset, NULL);

	/* tape attributes */
	offset = dissect_tape_attr(tvb, offset, pinfo, tree);

	/* capability */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_tape_capability, hf_ndmp_tape_capability);

	return offset;
}

static int
dissect_tape_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* model */
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_tape_model, offset, NULL);

	/* device capabilites */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_tape_dev_cap, hf_ndmp_tape_dev_cap);

	return offset;
}

static int
dissect_get_tape_info_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* error */
	proto_tree_add_item(tree, hf_ndmp_error, tvb, offset, 4, FALSE);
	offset += 4;

	/* tape */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_tape_info, hf_ndmp_tape_info);

	return offset;
}

static int
dissect_scsi_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* model */
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_scsi_model, offset, NULL);

	/* device capabilites */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_tape_dev_cap, hf_ndmp_tape_dev_cap);

	return offset;
}

static int
dissect_get_scsi_info_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* error */
	proto_tree_add_item(tree, hf_ndmp_error, tvb, offset, 4, FALSE);
	offset += 4;

	/* scsi */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_scsi_info, hf_ndmp_scsi_info);

	return offset;
}

static int
dissect_get_server_info_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* error */
	proto_tree_add_item(tree, hf_ndmp_error, tvb, offset, 4, FALSE);
	offset += 4;

	/* vendor */
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_server_vendor, offset, NULL);

	/* product */
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_server_product, offset, NULL);

	/* revision */
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_server_revision, offset, NULL);


	/* server */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_auth_type, hf_ndmp_auth_types);

	return offset;
}

static int
dissect_scsi_device(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* device */
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_scsi_device, offset, NULL);

	return offset;
}

static int
dissect_scsi_get_state_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* error */
	proto_tree_add_item(tree, hf_ndmp_error, tvb, offset, 4, FALSE);
	offset += 4;

	/* controller */
	proto_tree_add_item(tree, hf_ndmp_scsi_controller, tvb, offset, 4, FALSE);
	offset += 4;

	/* id */
	proto_tree_add_item(tree, hf_ndmp_scsi_id, tvb, offset, 4, FALSE);
	offset += 4;

	/* lun */
	proto_tree_add_item(tree, hf_ndmp_scsi_lun, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;
}

static int
dissect_scsi_set_state_request(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* device */
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_scsi_device, offset, NULL);

	/* controller */
	proto_tree_add_item(tree, hf_ndmp_scsi_controller, tvb, offset, 4, FALSE);
	offset += 4;

	/* id */
	proto_tree_add_item(tree, hf_ndmp_scsi_id, tvb, offset, 4, FALSE);
	offset += 4;

	/* lun */
	proto_tree_add_item(tree, hf_ndmp_scsi_lun, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;
}

#define NDMP_TAPE_OPEN_MODE_READ	0
#define NDMP_TAPE_OPEN_MODE_RDWR	1
static const value_string tape_open_mode_vals[] = {
	{NDMP_TAPE_OPEN_MODE_READ,	"Read"},
	{NDMP_TAPE_OPEN_MODE_RDWR,	"Read/Write"},
	{0, NULL}
};

static int
dissect_tape_open_request(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* device */
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_tape_device, offset, NULL);

	/* open mode */
	proto_tree_add_item(tree, hf_ndmp_tape_open_mode, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;
}


static const true_false_string tfs_ndmp_tape_invalid_file_num = {
	"File num is valid",
	"File num is INVALID"
};
static const true_false_string tfs_ndmp_tape_invalid_soft_errors = {
	"Soft errors is valid",
	"Soft errors is INVALID"
};
static const true_false_string tfs_ndmp_tape_invalid_block_size = {
	"Block size is valid",
	"Block size is INVALID"
};
static const true_false_string tfs_ndmp_tape_invalid_block_no = {
	"Block no is valid",
	"Block no is INVALID"
};
static const true_false_string tfs_ndmp_tape_invalid_total_space = {
	"Total space is valid",
	"Total space is INVALID"
};
static const true_false_string tfs_ndmp_tape_invalid_space_remain = {
	"Space remaining is INVALID",
	"Space remaining is valid"
};
static const true_false_string tfs_ndmp_tape_invalid_partition = {
	"Partition is INVALID",
	"Partition is valid"
};
static int
dissect_tape_invalid(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item* item = NULL;
	proto_tree* tree = NULL;
	guint32 flags;

	flags=tvb_get_ntohl(tvb, offset);
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, 4,
				"Invalids: 0x%08x ", flags);
		tree = proto_item_add_subtree(item, ett_ndmp_tape_invalid);
	}

	proto_tree_add_boolean(tree, hf_ndmp_tape_invalid_partition,
				tvb, offset, 4, flags);
	proto_tree_add_boolean(tree, hf_ndmp_tape_invalid_space_remain,
				tvb, offset, 4, flags);
	proto_tree_add_boolean(tree, hf_ndmp_tape_invalid_total_space,
				tvb, offset, 4, flags);
	proto_tree_add_boolean(tree, hf_ndmp_tape_invalid_block_no,
				tvb, offset, 4, flags);
	proto_tree_add_boolean(tree, hf_ndmp_tape_invalid_block_size,
				tvb, offset, 4, flags);
	proto_tree_add_boolean(tree, hf_ndmp_tape_invalid_soft_errors,
				tvb, offset, 4, flags);
	proto_tree_add_boolean(tree, hf_ndmp_tape_invalid_file_num,
				tvb, offset, 4, flags);

	offset+=4;
	return offset;
}

static const true_false_string tfs_ndmp_tape_flags_no_rewind = {
	"This is a NON-REWINDING device",
	"This device supports rewind"
};
static const true_false_string tfs_ndmp_tape_flags_write_protect = {
	"This device is WRITE-PROTECTED",
	"This device is NOT write-protected"
};
static const true_false_string tfs_ndmp_tape_flags_error = {
	"This device shows ERROR",
	"This device shows NO errors"
};
static const true_false_string tfs_ndmp_tape_flags_unload = {
	"This device supports UNLOAD",
	"This device does NOT support unload"
};
static int
dissect_tape_flags(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item* item = NULL;
	proto_tree* tree = NULL;
	guint32 flags;

	flags=tvb_get_ntohl(tvb, offset);
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, 4,
				"Flags: 0x%08x ", flags);
		tree = proto_item_add_subtree(item, ett_ndmp_tape_flags);
	}


	proto_tree_add_boolean(tree, hf_ndmp_tape_flags_unload,
				tvb, offset, 4, flags);
	proto_tree_add_boolean(tree, hf_ndmp_tape_flags_error,
				tvb, offset, 4, flags);
	proto_tree_add_boolean(tree, hf_ndmp_tape_flags_write_protect,
				tvb, offset, 4, flags);
	proto_tree_add_boolean(tree, hf_ndmp_tape_flags_no_rewind,
				tvb, offset, 4, flags);

	offset+=4;
	return offset;
}

static int
dissect_tape_get_state_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* invalid bits */
	offset=dissect_tape_invalid(tvb, offset, pinfo, tree);

	/* error */
	proto_tree_add_item(tree, hf_ndmp_error, tvb, offset, 4, FALSE);
	offset += 4;

	/* flags */
	offset=dissect_tape_flags(tvb, offset, pinfo, tree);

	/* file_num */
	proto_tree_add_item(tree, hf_ndmp_tape_file_num, tvb, offset, 4, FALSE);
	offset += 4;

	/* soft_errors */
	proto_tree_add_item(tree, hf_ndmp_tape_soft_errors, tvb, offset, 4, FALSE);
	offset += 4;

	/* block_size */
	proto_tree_add_item(tree, hf_ndmp_tape_block_size, tvb, offset, 4, FALSE);
	offset += 4;

	/* block_no */
	proto_tree_add_item(tree, hf_ndmp_tape_block_no, tvb, offset, 4, FALSE);
	offset += 4;

	/* total_space */
	offset = dissect_rpc_uint64(tvb, pinfo, tree,hf_ndmp_tape_total_space,
			offset);

	/* space_remain */
	offset = dissect_rpc_uint64(tvb, pinfo, tree,hf_ndmp_tape_space_remain,
			offset);

	/* partition */
	proto_tree_add_item(tree, hf_ndmp_tape_partition, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;
}

#define NDMP_TAPE_MTIO_FSF	0
#define NDMP_TAPE_MTIO_BSF	1
#define NDMP_TAPE_MTIO_FSR	2
#define NDMP_TAPE_MTIO_BSR	3
#define NDMP_TAPE_MTIO_REW	4
#define NDMP_TAPE_MTIO_EOF	5
#define NDMP_TAPE_MTIO_OFF	6
static const value_string tape_mtio_vals[] = {
	{NDMP_TAPE_MTIO_FSF,	"FSF"},
	{NDMP_TAPE_MTIO_BSF,	"BSF"},
	{NDMP_TAPE_MTIO_FSR,	"FSR"},
	{NDMP_TAPE_MTIO_BSR,	"BSR"},
	{NDMP_TAPE_MTIO_REW,	"REW"},
	{NDMP_TAPE_MTIO_EOF,	"EOF"},
	{NDMP_TAPE_MTIO_OFF,	"OFF"},
	{0, NULL}
};

static int
dissect_tape_mtio_request(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* op */
	proto_tree_add_item(tree, hf_ndmp_tape_mtio_op, tvb, offset, 4, FALSE);
	offset += 4;

	/* count */
	proto_tree_add_item(tree, hf_ndmp_count, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;
}

static int
dissect_tape_mtio_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* error */
	proto_tree_add_item(tree, hf_ndmp_error, tvb, offset, 4, FALSE);
	offset += 4;

	/* resid count */
	proto_tree_add_item(tree, hf_ndmp_resid_count, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;
}

#define NDMP_MOVER_STATE_IDLE		0
#define NDMP_MOVER_STATE_LISTEN		1
#define NDMP_MOVER_STATE_ACTIVE		2
#define NDMP_MOVER_STATE_PAUSED		3
#define NDMP_MOVER_STATE_HALTED		4
static const value_string mover_state_vals[] = {
	{NDMP_MOVER_STATE_IDLE,	"MOVER_STATE_IDLE"},
	{NDMP_MOVER_STATE_LISTEN,	"MOVER_STATE_LISTEN"},
	{NDMP_MOVER_STATE_ACTIVE,	"MOVER_STATE_ACTIVE"},
	{NDMP_MOVER_STATE_PAUSED,	"MOVER_STATE_PAUSED"},
	{NDMP_MOVER_STATE_HALTED,	"MOVER_STATE_HALTED"},
	{0, NULL}
};

#define NDMP_MOVER_PAUSE_NA		0
#define NDMP_MOVER_PAUSE_EOM		1
#define NDMP_MOVER_PAUSE_EOF		2
#define NDMP_MOVER_PAUSE_SEEK		3
#define NDMP_MOVER_PAUSE_MEDIA_ERROR	4
#define NDMP_MOVER_PAUSE_EOW		5
static const value_string mover_pause_vals[] = {
	{NDMP_MOVER_PAUSE_NA,		"MOVER_PAUSE_NA"},
	{NDMP_MOVER_PAUSE_EOM,		"MOVER_PAUSE_EOM"},
	{NDMP_MOVER_PAUSE_EOF,		"MOVER_PAUSE_EOF"},
	{NDMP_MOVER_PAUSE_SEEK,		"MOVER_PAUSE_SEEK"},
	{NDMP_MOVER_PAUSE_MEDIA_ERROR,	"MOVER_PAUSE_MEDIA_ERROR"},
	{NDMP_MOVER_PAUSE_EOW,		"MOVER_PAUSE_EOW"},
	{0, NULL}
};

#define NDMP_HALT_NA		0
#define NDMP_HALT_CONNECT_CLOSE	1
#define NDMP_HALT_ABORTED		2
#define NDMP_HALT_INTERNAL_ERROR	3
#define NDMP_HALT_CONNECT_ERROR	4
static const value_string halt_vals[] = {
	{NDMP_HALT_NA,			"HALT_NA"},
	{NDMP_HALT_CONNECT_CLOSE,	"HALT_CONNECT_CLOSE"},
	{NDMP_HALT_ABORTED,		"HALT_ABORTED"},
	{NDMP_HALT_INTERNAL_ERROR,	"HALT_INTERNAL_ERROR"},
	{NDMP_HALT_CONNECT_ERROR,	"HALT_CONNECT_ERROR"},
	{0, NULL}
};

static int
dissect_ndmp_addr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item* item = NULL;
	proto_tree* tree = NULL;
	guint32 type;

	type=tvb_get_ntohl(tvb, offset);
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, 4,
				"Type: %s ", val_to_str(type, addr_type_vals,"Unknown addr type (0x%02x)") );
		tree = proto_item_add_subtree(item, ett_ndmp_addr);
	}

	/*address type*/
	proto_tree_add_item(tree, hf_ndmp_addr_type, tvb, offset, 4, FALSE);
	offset += 4;


	switch(type){
	case NDMP_ADDR_LOCAL:
		break;
	case NDMP_ADDR_TCP:
		/* IP addr */
		proto_tree_add_item(tree, hf_ndmp_addr_ip, tvb, offset, 4, FALSE);
		offset+=4;
		
		/* TCP port */
		proto_tree_add_item(tree, hf_ndmp_addr_tcp, tvb, offset, 4, FALSE);
		offset+=4;
		
		break;
	case NDMP_ADDR_FC:
		/* FCAL loop id */
		proto_tree_add_item(tree, hf_ndmp_addr_fcal_loop_id, tvb, offset, 4, FALSE);
		offset+=4;

		break;
	case NDMP_ADDR_IPC:
		/* IPC address */
		offset = dissect_rpc_data(tvb, pinfo, tree, hf_ndmp_addr_ipc, offset);
		break;
	}

	return offset;
}
		
static int
dissect_mover_get_state_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* error */
	proto_tree_add_item(tree, hf_ndmp_error, tvb, offset, 4, FALSE);
	offset += 4;

	/* mover state */
	proto_tree_add_item(tree, hf_ndmp_mover_state, tvb, offset, 4, FALSE);
	offset += 4;

	/* mover pause */
	proto_tree_add_item(tree, hf_ndmp_mover_pause, tvb, offset, 4, FALSE);
	offset += 4;

	/* halt */
	proto_tree_add_item(tree, hf_ndmp_halt, tvb, offset, 4, FALSE);
	offset += 4;

	/* record size */
	proto_tree_add_item(tree, hf_ndmp_record_size, tvb, offset, 4, FALSE);
	offset += 4;

	/* record num */
	proto_tree_add_item(tree, hf_ndmp_record_num, tvb, offset, 4, FALSE);
	offset += 4;

	/* data written */
	proto_tree_add_item(tree, hf_ndmp_data_written, tvb, offset, 8, FALSE);
	offset += 8;

	/* seek position */
	proto_tree_add_item(tree, hf_ndmp_seek_position, tvb, offset, 8, FALSE);
	offset += 8;

	/* bytes left to read */
	proto_tree_add_item(tree, hf_ndmp_bytes_left_to_read, tvb, offset, 8, FALSE);
	offset += 8;

	/* window offset */
	proto_tree_add_item(tree, hf_ndmp_window_offset, tvb, offset, 8, FALSE);
	offset += 8;

	/* window length */
	proto_tree_add_item(tree, hf_ndmp_window_length, tvb, offset, 8, FALSE);
	offset += 8;

	/* ndmp addr */
	offset=dissect_ndmp_addr(tvb, offset, pinfo, tree);

	return offset;
}

#define NDMP_MOVER_MODE_READ	0
#define NDMP_MOVER_MODE_WRITE	1
static const value_string mover_mode_vals[] = {
	{NDMP_MOVER_MODE_READ,	"MODE_READ"},
	{NDMP_MOVER_MODE_WRITE,	"MOVER_MODE_WRITE"},
	{0, NULL}
};

static int
dissect_mover_listen_request(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* mode */
	proto_tree_add_item(tree, hf_ndmp_mover_mode, tvb, offset, 4, FALSE);
	offset += 4;

	/*address type*/
	proto_tree_add_item(tree, hf_ndmp_addr_type, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;
}

static int
dissect_mover_listen_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* error */
	proto_tree_add_item(tree, hf_ndmp_error, tvb, offset, 4, FALSE);
	offset += 4;

	/* ndmp addr */
	offset=dissect_ndmp_addr(tvb, offset, pinfo, tree);

	return offset;
}

static int
dissect_mover_set_window_request(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* window offset */
	proto_tree_add_item(tree, hf_ndmp_window_offset, tvb, offset, 8, FALSE);
	offset += 8;

	/* window length */
	proto_tree_add_item(tree, hf_ndmp_window_length, tvb, offset, 8, FALSE);
	offset += 8;

	return offset;
}

static int
dissect_mover_set_record_size_request(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* record size */
	proto_tree_add_item(tree, hf_ndmp_record_size, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;
}

static int
dissect_mover_connect_request(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* mode */
	proto_tree_add_item(tree, hf_ndmp_mover_mode, tvb, offset, 4, FALSE);
	offset += 4;

	/* ndmp addr */
	offset=dissect_ndmp_addr(tvb, offset, pinfo, tree);

	return offset;
}

static int
dissect_log_file_request(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* file */
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_file_name, offset, NULL);

	/* error */
	proto_tree_add_item(tree, hf_ndmp_error, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;
}

#define NDMP_LOG_TYPE_NORMAL	0
#define NDMP_LOG_TYPE_DEBUG	1
#define NDMP_LOG_TYPE_ERROR	2
#define NDMP_LOG_TYPE_WARNING	3
static const value_string log_type_vals[] = {
	{NDMP_LOG_TYPE_NORMAL,	"NORMAL"},
	{NDMP_LOG_TYPE_DEBUG,	"DEBUG"},
	{NDMP_LOG_TYPE_ERROR,	"ERROR"},
	{NDMP_LOG_TYPE_WARNING,	"WARNING"},
	{0, NULL}
};

static int
dissect_log_message_request(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* type */
	proto_tree_add_item(tree, hf_ndmp_log_type, tvb, offset, 4, FALSE);
	offset += 4;

	/* message id */
	proto_tree_add_item(tree, hf_ndmp_log_message_id, tvb, offset, 4, FALSE);
	offset += 4;

	/* message */
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_log_message, offset, NULL);

	return offset;
}

static int
dissect_notify_data_halted_request(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* halt */
	proto_tree_add_item(tree, hf_ndmp_halt, tvb, offset, 4, FALSE);
	offset += 4;

	/* reason */
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_halt_reason, offset, NULL);

	return offset;
}

#define NDMP_CONNECTED_CONNECTED	0
#define NDMP_CONNECTED_SHUTDOWN		1
#define NDMP_CONNECTED_REFUSED		2
static const value_string connected_vals[] = {
	{NDMP_CONNECTED_CONNECTED,	"CONNECTED"},
	{NDMP_CONNECTED_SHUTDOWN,	"SHUTDOWN"},
	{NDMP_CONNECTED_REFUSED,	"REFUSED"},
	{0, NULL}
};

static int
dissect_notify_connected_request(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* connected */
	proto_tree_add_item(tree, hf_ndmp_connected, tvb, offset, 4, FALSE);
	offset += 4;

	/* version number */
	proto_tree_add_item(tree, hf_ndmp_version, tvb, offset, 4, FALSE);
	offset += 4;

	/* reason */
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_connected_reason, offset, NULL);

	return offset;
}


static int
dissect_notify_mover_paused_request(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* mover pause */
	proto_tree_add_item(tree, hf_ndmp_mover_pause, tvb, offset, 4, FALSE);
	offset += 4;

	/* seek position */
	proto_tree_add_item(tree, hf_ndmp_seek_position, tvb, offset, 8, FALSE);
	offset += 8;

	return offset;
}

static int
dissect_auth_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint type;
	
	type=tvb_get_ntohl(tvb,offset);

	/* auth type */
	proto_tree_add_item(tree, hf_ndmp_auth_type, tvb, offset, 4, FALSE);
	offset += 4;

	switch(type){
	case NDMP_AUTH_NONE:
		break;
	case NDMP_AUTH_TEXT:
		/* auth id */
		offset = dissect_rpc_string(tvb, pinfo, tree,
				hf_ndmp_auth_id, offset, NULL);

		/* auth password */
		offset = dissect_rpc_string(tvb, pinfo, tree,
				hf_ndmp_auth_password, offset, NULL);

		
		break;
	case NDMP_AUTH_MD5:
		/* auth id */
		offset = dissect_rpc_string(tvb, pinfo, tree,
				hf_ndmp_auth_id, offset, NULL);

		/* digest */
		proto_tree_add_item(tree, hf_ndmp_auth_digest, 
			tvb, offset, 16, FALSE);
		offset+=16;
	}

	return offset;
}


static int
dissect_connect_server_auth_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* error */
	proto_tree_add_item(tree, hf_ndmp_error, tvb, offset, 4, FALSE);
	offset += 4;

	/* auth data */
	offset = dissect_auth_data(tvb, offset, pinfo, tree);

	return offset;
}

static int
dissect_tape_write_request(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* data */
	offset = dissect_rpc_data(tvb, pinfo, tree, hf_ndmp_data, offset);

	return offset;
}

static int
dissect_tape_write_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* error */
	proto_tree_add_item(tree, hf_ndmp_error, tvb, offset, 4, FALSE);
	offset += 4;

	/* count */
	proto_tree_add_item(tree, hf_ndmp_count, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;
}

static int
dissect_tape_read_request(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* count */
	proto_tree_add_item(tree, hf_ndmp_count, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;
}

static int
dissect_tape_read_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* error */
	proto_tree_add_item(tree, hf_ndmp_error, tvb, offset, 4, FALSE);
	offset += 4;

	/* data */
	offset = dissect_rpc_data(tvb, pinfo, tree, hf_ndmp_data, offset);

	return offset;
}

#define NDMP_FS_UNIX	0
#define NDMP_FS_NT	1
#define NDMP_FS_OTHER	2
static const value_string file_fs_type_vals[] = {
	{NDMP_FS_UNIX,	"UNIX"},
	{NDMP_FS_NT,	"NT"},
	{NDMP_FS_OTHER,	"OTHER"},
	{0, NULL}
};

static int
dissect_file_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item* item = NULL;
	proto_tree* tree = NULL;
	int old_offset=offset;
	guint32 type;
	char *name;

	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
				"File");
		tree = proto_item_add_subtree(item, ett_ndmp_file_name);
	}

	/* file type */
	type=tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(tree, hf_ndmp_file_fs_type, tvb, offset, 4, FALSE);
	offset += 4;

	switch(type){
	case NDMP_FS_UNIX:
		/* file */
		offset = dissect_rpc_string(tvb, pinfo, tree,
				hf_ndmp_file_name, offset, &name);
		if (check_col(pinfo->cinfo, COL_INFO)){
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s ", name);
		}
		break;
	case NDMP_FS_NT:
		/* nt file */
		offset = dissect_rpc_string(tvb, pinfo, tree,
				hf_ndmp_nt_file_name, offset, &name);
		if (check_col(pinfo->cinfo, COL_INFO)){
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s ", name);
		}

		/* dos file */
		offset = dissect_rpc_string(tvb, pinfo, tree,
				hf_ndmp_dos_file_name, offset, NULL);
		break;
	default:
		/* file */
		offset = dissect_rpc_string(tvb, pinfo, tree,
				hf_ndmp_file_name, offset, &name);
		if (check_col(pinfo->cinfo, COL_INFO)){
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s ", name);
		}
	}

	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, "(%s)",
			val_to_str(type, file_fs_type_vals, "Unknown type") );
	}

	proto_item_set_len(item, offset-old_offset);	
	return offset;
}


static const true_false_string tfs_ndmp_file_invalid_atime = {
	"Atime is INVALID",
	"Atime is valid"
};
static const true_false_string tfs_ndmp_file_invalid_ctime = {
	"Ctime is INVALID",
	"Ctime is valid"
};
static const true_false_string tfs_ndmp_file_invalid_group = {
	"Group is INVALID",
	"Group is valid"
};
static int
dissect_file_invalids(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item* item = NULL;
	proto_tree* tree = NULL;
	guint32 flags;

	flags=tvb_get_ntohl(tvb, offset);
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, 4,
				"Invalids: 0x%08x ", flags);
		tree = proto_item_add_subtree(item, ett_ndmp_file_invalids);
	}

	proto_tree_add_boolean(tree, hf_ndmp_file_invalid_group,
			tvb, offset, 4, flags);
	proto_tree_add_boolean(tree, hf_ndmp_file_invalid_ctime,
			tvb, offset, 4, flags);
	proto_tree_add_boolean(tree, hf_ndmp_file_invalid_atime,
			tvb, offset, 4, flags);

	offset+=4;
	return offset;
}

#define NDMP_FILE_TYPE_DIR	0
#define NDMP_FILE_TYPE_FIFO	1
#define NDMP_FILE_TYPE_CSPEC	2
#define NDMP_FILE_TYPE_BSPEC	3
#define NDMP_FILE_TYPE_REG	4
#define NDMP_FILE_TYPE_SLINK	5
#define NDMP_FILE_TYPE_SOCK	6
#define NDMP_FILE_TYPE_REGISTRY	7
#define NDMP_FILE_TYPE_OTHER	8
static const value_string file_type_vals[] = {
	{NDMP_FILE_TYPE_DIR,	"DIR"},
	{NDMP_FILE_TYPE_FIFO,	"FIFO"},
	{NDMP_FILE_TYPE_CSPEC,	"CSPEC"},
	{NDMP_FILE_TYPE_BSPEC,	"BSPEC"},
	{NDMP_FILE_TYPE_REG,	"REG"},
	{NDMP_FILE_TYPE_SLINK,	"SLINK"},
	{NDMP_FILE_TYPE_SOCK,	"SOCK"},
	{NDMP_FILE_TYPE_REGISTRY,	"REGISTRY"},
	{NDMP_FILE_TYPE_OTHER,	"OTHER"},
	{0, NULL}
};

static int
dissect_file_stats(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item* item = NULL;
	proto_tree* tree = NULL;
	int old_offset=offset;
	nstime_t ns;

	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
				"Stats:");
		tree = proto_item_add_subtree(item, ett_ndmp_file_stats);
	}

	/* invalids */
	offset = dissect_file_invalids(tvb, offset, pinfo, tree);

	/* file fs type */
	proto_tree_add_item(tree, hf_ndmp_file_fs_type, tvb, offset, 4, FALSE);
	offset += 4;

	/* file type */
	proto_tree_add_item(tree, hf_ndmp_file_type, tvb, offset, 4, FALSE);
	offset += 4;

	/* mtime */
	ns.secs=tvb_get_ntohl(tvb, offset);
	ns.nsecs=0;
	proto_tree_add_time(tree, hf_ndmp_file_mtime, tvb, offset, 4, &ns);
	offset += 4;

	/* atime */
	ns.secs=tvb_get_ntohl(tvb, offset);
	ns.nsecs=0;
	proto_tree_add_time(tree, hf_ndmp_file_atime, tvb, offset, 4, &ns);
	offset += 4;

	/* ctime */
	ns.secs=tvb_get_ntohl(tvb, offset);
	ns.nsecs=0;
	proto_tree_add_time(tree, hf_ndmp_file_ctime, tvb, offset, 4, &ns);
	offset += 4;

	/* owner */
	proto_tree_add_item(tree, hf_ndmp_file_owner, tvb, offset, 4, FALSE);
	offset += 4;

	/* group */
	proto_tree_add_item(tree, hf_ndmp_file_group, tvb, offset, 4, FALSE);
	offset += 4;

	/*XXX here we should do proper dissection of mode for unix or
	      fattr for nt, call appropriate functions in nfs/smb*/
	/* fattr */
	proto_tree_add_item(tree, hf_ndmp_file_fattr, tvb, offset, 4, FALSE);
	offset += 4;

	/*file size*/
	offset = dissect_rpc_uint64(tvb, pinfo, tree, hf_ndmp_file_size,
			offset);

	/* links */
	proto_tree_add_item(tree, hf_ndmp_file_links, tvb, offset, 4, FALSE);
	offset += 4;

	proto_item_set_len(item, offset-old_offset);	
	return offset;
}


static int
dissect_file(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item* item = NULL;
	proto_tree* tree = NULL;
	int old_offset=offset;

	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
				"File:");
		tree = proto_item_add_subtree(item, ett_ndmp_file);
	}

	/* file names */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_file_name, hf_ndmp_file_names);

	/* file stats */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_file_stats, hf_ndmp_file_stats);

	/* node */
	proto_tree_add_item(tree, hf_ndmp_file_node, tvb, offset, 8, FALSE);
	offset += 8;

	/* fh_info */
	proto_tree_add_item(tree, hf_ndmp_file_fh_info, tvb, offset, 8, FALSE);
	offset += 8;

	proto_item_set_len(item, offset-old_offset);	
	return offset;
}

static int
dissect_fh_add_file_request(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* files */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_file, hf_ndmp_files);

	return offset;
}

static int
dissect_dir(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* file names */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_file_name, hf_ndmp_file_names);

	/* node */
	proto_tree_add_item(tree, hf_ndmp_file_node, tvb, offset, 8, FALSE);
	offset += 8;

	/* parent */
	proto_tree_add_item(tree, hf_ndmp_file_parent, tvb, offset, 8, FALSE);
	offset += 8;

	return offset;
}

static int
dissect_fh_add_dir_request(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* dirs */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_dir, hf_ndmp_dirs);

	return offset;
}

static int
dissect_node(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* file stats */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_file_stats, hf_ndmp_file_stats);

	/* node */
	proto_tree_add_item(tree, hf_ndmp_file_node, tvb, offset, 8, FALSE);
	offset += 8;

	/* fh_info */
	proto_tree_add_item(tree, hf_ndmp_file_fh_info, tvb, offset, 8, FALSE);
	offset += 8;

	return offset;
}


static int
dissect_fh_add_node_request(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* node */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_node, hf_ndmp_nodes);

	return offset;
}

static int
dissect_data_start_backup_request(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/*butype name*/
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_butype_name, offset, NULL);

	/* default env */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_default_env, hf_ndmp_butype_default_env);

	return offset;
}

static int
dissect_nlist(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/*original path*/
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_bu_original_path, offset, NULL);

	/*destination dir*/
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_bu_destination_dir, offset, NULL);

	/*new name*/
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_bu_new_name, offset, NULL);

	/*other name*/
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_bu_other_name, offset, NULL);

	/* node */
	proto_tree_add_item(tree, hf_ndmp_file_node, tvb, offset, 8, FALSE);
	offset += 8;

	/* fh_info */
	proto_tree_add_item(tree, hf_ndmp_file_fh_info, tvb, offset, 8, FALSE);
	offset += 8;

	return offset;
}


static int
dissect_data_start_recover_request(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* default env */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_default_env, hf_ndmp_butype_default_env);

	/* nlist */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_nlist, hf_ndmp_nlist);

	/*butype name*/
	offset = dissect_rpc_string(tvb, pinfo, tree,
			hf_ndmp_butype_name, offset, NULL);

	return offset;
}

static int
dissect_data_get_env_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* error */
	proto_tree_add_item(tree, hf_ndmp_error, tvb, offset, 4, FALSE);
	offset += 4;

	/* default env */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_default_env, hf_ndmp_butype_default_env);

	return offset;
}


static const true_false_string tfs_ndmp_state_invalid_ebr = {
	"Estimated Bytes Remaining is INVALID",
	"Estimated Bytes Remaining is valid"
};
static const true_false_string tfs_ndmp_state_invalid_etr = {
	"Estimated Time Remaining is INVALID",
	"Estimated Time Remaining is valid"
};
static int
dissect_state_invalids(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item* item = NULL;
	proto_tree* tree = NULL;
	guint32 flags;

	flags=tvb_get_ntohl(tvb, offset);
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, 4,
				"Invalids: 0x%08x ", flags);
		tree = proto_item_add_subtree(item, ett_ndmp_state_invalids);
	}

	proto_tree_add_boolean(tree, hf_ndmp_state_invalid_etr,
				tvb, offset, 4, flags);
	proto_tree_add_boolean(tree, hf_ndmp_state_invalid_ebr,
				tvb, offset, 4, flags);

	offset+=4;
	return offset;
}

#define NDMP_DATA_OP_NOACTION	0
#define NDMP_DATA_OP_BACKUP	1
#define NDMP_DATA_OP_RESTORE	2
static const value_string bu_operation_vals[] = {
	{NDMP_DATA_OP_NOACTION,	"NOACTION"},
	{NDMP_DATA_OP_BACKUP,	"BACKUP"},
	{NDMP_DATA_OP_RESTORE,	"RESTORE"},
	{0, NULL}
};

#define NDMP_DATA_STATE_IDLE		0
#define NDMP_DATA_STATE_ACTIVE		1
#define NDMP_DATA_STATE_HALTED		2
#define NDMP_DATA_STATE_LISTEN		3
#define NDMP_DATA_STATE_CONNECTED	4
static const value_string data_state_vals[] = {
	{NDMP_DATA_STATE_IDLE,		"IDLE"},
	{NDMP_DATA_STATE_ACTIVE,	"ACTIVE"},
	{NDMP_DATA_STATE_HALTED,	"HALTED"},
	{NDMP_DATA_STATE_LISTEN,	"LISTEN"},
	{NDMP_DATA_STATE_CONNECTED,	"CONNECTED"},
	{0, NULL}
};

#define NDMP_DATA_HALTED_NA		0
#define NDMP_DATA_HALTED_SUCCESSFUL	1
#define NDMP_DATA_HALTED_ABORTED	2
#define NDMP_DATA_HALTED_INTERNAL_ERROR	3
#define NDMP_DATA_HALTED_CONNECT_ERROR	4
static const value_string data_halted_vals[] = {
	{NDMP_DATA_HALTED_NA,			"HALTED_NA"},
	{NDMP_DATA_HALTED_SUCCESSFUL,		"HALTED_SUCCESSFUL"},
	{NDMP_DATA_HALTED_ABORTED,		"HALTED_ABORTED"},
	{NDMP_DATA_HALTED_INTERNAL_ERROR,	"HALTED_INTERNAL_ERROR"},
	{NDMP_DATA_HALTED_CONNECT_ERROR,	"HALTED_CONNECT_ERROR"},
	{0, NULL}
};

static int
dissect_data_get_state_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	nstime_t ns;

	/* invalids */
	offset = dissect_state_invalids(tvb, offset, pinfo, tree);

	/* error */
	proto_tree_add_item(tree, hf_ndmp_error, tvb, offset, 4, FALSE);
	offset += 4;

	/* operation */
	proto_tree_add_item(tree, hf_ndmp_bu_operation, tvb, offset, 4, FALSE);
	offset += 4;

	/* state */
	proto_tree_add_item(tree, hf_ndmp_data_state, tvb, offset, 4, FALSE);
	offset += 4;

	/* halted reason */
	proto_tree_add_item(tree, hf_ndmp_data_halted, tvb, offset, 4, FALSE);
	offset += 4;

	/*bytes processed*/
	offset = dissect_rpc_uint64(tvb, pinfo, tree, hf_ndmp_data_bytes_processed,
			offset);

	/*est bytes remain*/
	offset = dissect_rpc_uint64(tvb, pinfo, tree, hf_ndmp_data_est_bytes_remain,
			offset);

	/* est time remain */
	ns.secs=tvb_get_ntohl(tvb, offset);
	ns.nsecs=0;
	proto_tree_add_time(tree, hf_ndmp_data_est_time_remain, tvb, offset, 4, &ns);
	offset += 4;

	/* ndmp addr */
	offset=dissect_ndmp_addr(tvb, offset, pinfo, tree);

	/* window offset */
	proto_tree_add_item(tree, hf_ndmp_window_offset, tvb, offset, 8, FALSE);
	offset += 8;

	/* window length */
	proto_tree_add_item(tree, hf_ndmp_window_length, tvb, offset, 8, FALSE);
	offset += 8;

	return offset;
}


typedef struct _ndmp_command {
	guint32 cmd;
	int (*request) (tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
	int (*response)(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
} ndmp_command;

static const ndmp_command ndmp_commands[] = {
	{NDMP_CONFIG_GET_HOST_INFO,    
	 	NULL, dissect_ndmp_get_host_info_reply},
	{NDMP_CONFIG_GET_CONNECTION_TYPE, 
		NULL, dissect_ndmp_config_get_connection_type_reply},
	{NDMP_CONFIG_GET_AUTH_ATTR, 
		dissect_auth_type, dissect_auth_attr},
	{NDMP_CONFIG_GET_BUTYPE_INFO, 	
		NULL, dissect_get_butype_info_reply},
	{NDMP_CONFIG_GET_FS_INFO, 	
		NULL, dissect_get_fs_info_reply},
	{NDMP_CONFIG_GET_TAPE_INFO, 	
		NULL, dissect_get_tape_info_reply},
	{NDMP_CONFIG_GET_SCSI_INFO, 	
		NULL, dissect_get_scsi_info_reply},
	{NDMP_CONFIG_GET_SERVER_INFO, 	
		NULL, dissect_get_server_info_reply},
	{NDMP_SCSI_OPEN, 		
		dissect_scsi_device, dissect_error},
	{NDMP_SCSI_CLOSE, 		
		NULL, dissect_error},
	{NDMP_SCSI_GET_STATE, 		
		NULL, dissect_scsi_get_state_reply},
	{NDMP_SCSI_SET_TARGET, 		
		dissect_scsi_set_state_request, dissect_error},
	{NDMP_SCSI_RESET_DEVICE, 	
		NULL, dissect_error},
	{NDMP_SCSI_RESET_BUS, 		
		NULL, dissect_error},
	{NDMP_SCSI_EXECUTE_CDB, 	NULL,NULL},
	{NDMP_TAPE_OPEN, 		
		dissect_tape_open_request, dissect_error},
	{NDMP_TAPE_CLOSE, 		
		NULL, dissect_error},
	{NDMP_TAPE_GET_STATE, 		
	 	NULL, dissect_tape_get_state_reply},
	{NDMP_TAPE_MTIO, 		
		dissect_tape_mtio_request, dissect_tape_mtio_reply},
	{NDMP_TAPE_WRITE, 		
		dissect_tape_write_request, dissect_tape_write_reply},
	{NDMP_TAPE_READ, 	
		dissect_tape_read_request, dissect_tape_read_reply},
	{NDMP_TAPE_EXECUTE_CDB, 	NULL,NULL},
	{NDMP_DATA_GET_STATE, 		
		NULL, dissect_data_get_state_reply},
	{NDMP_DATA_START_BACKUP,
		dissect_data_start_backup_request, dissect_error },
	{NDMP_DATA_START_RECOVER,
		dissect_data_start_recover_request, dissect_error },
	{NDMP_DATA_ABORT,
		NULL, dissect_error},
	{NDMP_DATA_GET_ENV, 
		NULL, dissect_data_get_env_reply},
	{NDMP_DATA_STOP, 
		NULL, dissect_error},
	{NDMP_DATA_LISTEN, 
		dissect_ndmp_addr_type, dissect_mover_listen_reply},
	{NDMP_DATA_CONNECT, 		
		dissect_ndmp_addr, dissect_error},
	{NDMP_NOTIFY_DATA_HALTED, 	
		dissect_notify_data_halted_request, NULL},
	{NDMP_NOTIFY_CONNECTED, 	
		dissect_notify_connected_request, NULL},
	{NDMP_NOTIFY_MOVER_HALTED, 
		dissect_notify_data_halted_request, NULL},
	{NDMP_NOTIFY_MOVER_PAUSED, 
		dissect_notify_mover_paused_request, NULL},
	{NDMP_NOTIFY_DATA_READ, 	
		dissect_mover_set_window_request, NULL},
	{NDMP_LOG_FILE, 		
		dissect_log_file_request, NULL},
	{NDMP_LOG_MESSAGE, 	
		dissect_log_message_request, NULL},
	{NDMP_FH_ADD_FILE, 
		dissect_fh_add_file_request, NULL},
	{NDMP_FH_ADD_DIR, 		
		dissect_fh_add_dir_request, NULL},
	{NDMP_FH_ADD_NODE, 
		dissect_fh_add_node_request, NULL},
	{NDMP_CONNECT_OPEN, 		
		dissect_connect_open_request, dissect_error},
	{NDMP_CONNECT_CLIENT_AUTH, 
		dissect_auth_data, dissect_error},
	{NDMP_CONNECT_CLOSE, 		
		NULL,NULL},
	{NDMP_CONNECT_SERVER_AUTH, 
		dissect_auth_attr, dissect_connect_server_auth_reply},
	{NDMP_MOVER_GET_STATE, 		
		NULL, dissect_mover_get_state_reply},
	{NDMP_MOVER_LISTEN, 		
		dissect_mover_listen_request, dissect_mover_listen_reply},
	{NDMP_MOVER_CONTINUE, 		
		NULL, dissect_error},
	{NDMP_MOVER_ABORT, 		
		NULL, dissect_error},
	{NDMP_MOVER_STOP, 		
		NULL, dissect_error},
	{NDMP_MOVER_SET_WINDOW, 	
		dissect_mover_set_window_request, dissect_error},
	{NDMP_MOVER_READ, 
		dissect_mover_set_window_request, dissect_error},
	{NDMP_MOVER_CLOSE, 		
		NULL, dissect_error},
	{NDMP_MOVER_SET_RECORD_SIZE, 
		dissect_mover_set_record_size_request, dissect_error},
	{NDMP_MOVER_CONNECT, 	
		dissect_mover_connect_request, dissect_error},
	{0, NULL,NULL}
};


static int
dissect_ndmp_header(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, struct ndmp_header *nh)
{
	proto_item* item = NULL;
	proto_tree* tree = NULL;
	nstime_t ns;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_ndmp_header, tvb,
				offset, 24, FALSE);
		tree = proto_item_add_subtree(item, ett_ndmp_header);
	}

	/* sequence number */
	proto_tree_add_uint(tree, hf_ndmp_sequence, tvb, offset, 4, nh->seq);
	offset += 4;

	/* timestamp */
	ns.secs=nh->time;
	ns.nsecs=0;
	proto_tree_add_time(tree, hf_ndmp_timestamp, tvb, offset, 4, &ns);
	offset += 4;

	/* Message Type */
	proto_tree_add_uint(tree, hf_ndmp_msgtype, tvb, offset, 4, nh->type);
	offset += 4;

	/* Message */
	proto_tree_add_uint(tree, hf_ndmp_msg, tvb, offset, 4, nh->msg);
	offset += 4;

	/* Reply sequence number */
	proto_tree_add_uint(tree, hf_ndmp_reply_sequence, tvb, offset, 4, nh->rep_seq);
	offset += 4;

	/* error */
	proto_tree_add_uint(tree, hf_ndmp_error, tvb, offset, 4, nh->err);
	offset += 4;

	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s %s  ",
			val_to_str(nh->msg, msg_vals, "Unknown Message (0x%02x)"),
			val_to_str(nh->type, msg_type_vals, "Unknown Type (0x%02x)")
			);
	}

	return offset;
}


static int
dissect_ndmp_cmd(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, struct ndmp_header *nh)
{
	int i;
	proto_item *cmd_item=NULL;
	proto_tree *cmd_tree=NULL;
	guint32 size;

	/* the size of the current PDU */
	size = tvb_get_ntohl(tvb, offset);	
	proto_tree_add_uint(tree, hf_ndmp_size, tvb, offset, 4, size&NDMP_FRAGLEN);
	offset += 4;

	offset=dissect_ndmp_header(tvb, offset, pinfo, tree, nh);

	for(i=0;ndmp_commands[i].cmd!=0;i++){
		if(ndmp_commands[i].cmd==nh->msg){
			break;
		}
	}


	if(ndmp_commands[i].cmd==0){
		/* we do not know this message */
		proto_tree_add_text(tree, tvb, offset, tvb_length_remaining(tvb, offset), "Unknown type of NDMP message: 0x%02x", nh->msg);
		offset+=tvb_length_remaining(tvb, offset);
		return offset;
	}

	if(tree){
		cmd_item = proto_tree_add_text(tree, tvb, offset, tvb_length_remaining(tvb, offset), 
			msg_vals[i].strptr);
		cmd_tree = proto_item_add_subtree(cmd_item, ett_ndmp);
	}

	if(nh->type==NDMP_MESSAGE_REQUEST){
		if(ndmp_commands[i].request){
			offset=ndmp_commands[i].request(tvb, offset, pinfo, cmd_tree);
		}
	} else {
		if(ndmp_commands[i].response){
			offset=ndmp_commands[i].response(tvb, offset, pinfo, cmd_tree);
		}
	}

	return offset;
}

static void
dissect_ndmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	gboolean first = TRUE;
	int offset = 0;
	guint32 size, available_bytes;
	struct ndmp_header nh;
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	/* loop through the packet, dissecting multiple NDMP pdus*/
	do {
		available_bytes = tvb_length_remaining(tvb, offset);

		/* size of this NDMP PDU */
		size = (tvb_get_ntohl(tvb, offset)&NDMP_FRAGLEN) + 4;	
		if(size<28){
			/* too short to be NDMP */
			return;
		}

		/* desegmentation */
		if(ndmp_desegment){
			if(pinfo->can_desegment
			&& size>available_bytes) {
				pinfo->desegment_offset = offset;
				pinfo->desegment_len = size-available_bytes;
				return;
			}
		}

		/* check the ndmp header, if we have it */
		if(available_bytes<28){
			/* We don't have enough data */
			return;
		}
		nh.seq=tvb_get_ntohl(tvb, offset+4);
		nh.time=tvb_get_ntohl(tvb, offset+8);
		nh.type=tvb_get_ntohl(tvb, offset+12);
		nh.msg=tvb_get_ntohl(tvb, offset+16);
		nh.rep_seq=tvb_get_ntohl(tvb, offset+20);
		nh.err=tvb_get_ntohl(tvb, offset+24);

		if(nh.type>1){
			return;
		}
		if((nh.msg>0xa09)||(nh.msg==0)){
			return;
		}
		if(nh.err>0x17){
			return;
		}

		if (first) {
			if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
				col_set_str(pinfo->cinfo, COL_PROTOCOL, "NDMP");
			if (check_col(pinfo->cinfo, COL_INFO)) 
				col_clear(pinfo->cinfo, COL_INFO);
			first = FALSE;
		}

		if(parent_tree){
			item = proto_tree_add_item(parent_tree, proto_ndmp, tvb, offset, size, FALSE);
			tree = proto_item_add_subtree(item, ett_ndmp);
		}

		/* We can not trust what dissect_ndmp_cmd() tells us since
		   there are implementations which pads some additional data
		   after the PDU. We MUST use size.
		*/
		dissect_ndmp_cmd(tvb, offset, pinfo, tree, &nh);
		offset += size;
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
		"Message", "ndmp.msg", FT_UINT32, BASE_HEX,
		VALS(msg_vals), 0, "Type of NDMP PDU", HFILL }},

	{ &hf_ndmp_error, {
		"Error", "ndmp.error", FT_UINT32, BASE_DEC,
		VALS(error_vals), 0, "Error code for this NDMP PDU", HFILL }},

	{ &hf_ndmp_version, {
		"Version", "ndmp.version", FT_UINT32, BASE_DEC,
		NULL, 0, "Version of NDMP protocol", HFILL }},

	{ &hf_ndmp_hostname, {
		"Hostname", "ndmp.hostname", FT_STRING, BASE_NONE,
		NULL, 0, "Hostname", HFILL }},

	{ &hf_ndmp_hostid, {
		"HostID", "ndmp.hostid", FT_STRING, BASE_NONE,
		NULL, 0, "HostID", HFILL }},

	{ &hf_ndmp_os_type, {
		"OS Type", "ndmp.os.type", FT_STRING, BASE_NONE,
		NULL, 0, "OS Type", HFILL }},

	{ &hf_ndmp_os_vers, {
		"OS Version", "ndmp.os.version", FT_STRING, BASE_NONE,
		NULL, 0, "OS Version", HFILL }},

	{ &hf_ndmp_addr_types, {
		"Addr Types", "ndmp.addr_types", FT_NONE, BASE_NONE,
		NULL, 0, "List Of Address Types", HFILL }},

	{ &hf_ndmp_addr_type, {
		"Addr Type", "ndmp.addr_type", FT_UINT32, BASE_DEC,
		VALS(addr_type_vals), 0, "Address Type", HFILL }},

	{ &hf_ndmp_auth_type, {
		"Auth Type", "ndmp.auth_type", FT_UINT32, BASE_DEC,
		VALS(auth_type_vals), 0, "Authentication Type", HFILL }},

	{ &hf_ndmp_auth_challenge, {
		"Challenge", "ndmp.auth.challenge", FT_BYTES, BASE_HEX,
		NULL, 0, "Authentication Challenge", HFILL }},

	{ &hf_ndmp_auth_digest, {
		"Digest", "ndmp.auth.digest", FT_BYTES, BASE_HEX,
		NULL, 0, "Authentication Digest", HFILL }},

	{ &hf_ndmp_butype_info, {
		"Butype Info", "ndmp.butype.info", FT_NONE, BASE_NONE,
		NULL, 0, "Butype Info", HFILL }},

	{ &hf_ndmp_butype_name, {
		"Butype Name", "ndmp.butype.name", FT_STRING, BASE_NONE,
		NULL, 0, "Name of Butype", HFILL }},

	{ &hf_ndmp_butype_default_env, {
		"Default Env", "ndmp.butype.default_env", FT_NONE, BASE_NONE,
		NULL, 0, "Default Env's for this Butype Info", HFILL }},

	{ &hf_ndmp_butype_attr_backup_file_history, {
		"", "ndmp.butype.attr.backup_file_history", FT_BOOLEAN, 32,
		TFS(&tfs_butype_attr_backup_file_history), 0x00000001, "backup_file_history", HFILL }},

	{ &hf_ndmp_butype_attr_backup_filelist, {
		"", "ndmp.butype.attr.backup_filelist", FT_BOOLEAN, 32,
		TFS(&tfs_butype_attr_backup_filelist), 0x00000002, "backup_filelist", HFILL }},

	{ &hf_ndmp_butype_attr_recover_filelist, {
		"", "ndmp.butype.attr.recover_filelist", FT_BOOLEAN, 32,
		TFS(&tfs_butype_attr_recover_filelist), 0x00000004, "recover_filelist", HFILL }},

	{ &hf_ndmp_butype_attr_backup_direct, {
		"", "ndmp.butype.attr.backup_direct", FT_BOOLEAN, 32,
		TFS(&tfs_butype_attr_backup_direct), 0x00000008, "backup_direct", HFILL }},

	{ &hf_ndmp_butype_attr_recover_direct, {
		"", "ndmp.butype.attr.recover_direct", FT_BOOLEAN, 32,
		TFS(&tfs_butype_attr_recover_direct), 0x00000010, "recover_direct", HFILL }},

	{ &hf_ndmp_butype_attr_backup_incremental, {
		"", "ndmp.butype.attr.backup_incremental", FT_BOOLEAN, 32,
		TFS(&tfs_butype_attr_backup_incremental), 0x00000020, "backup_incremental", HFILL }},

	{ &hf_ndmp_butype_attr_recover_incremental, {
		"", "ndmp.butype.attr.recover_incremental", FT_BOOLEAN, 32,
		TFS(&tfs_butype_attr_recover_incremental), 0x00000040, "recover_incremental", HFILL }},

	{ &hf_ndmp_butype_attr_backup_utf8, {
		"", "ndmp.butype.attr.backup_utf8", FT_BOOLEAN, 32,
		TFS(&tfs_butype_attr_backup_utf8), 0x00000080, "backup_utf8", HFILL }},

	{ &hf_ndmp_butype_attr_recover_utf8, {
		"", "ndmp.butype.attr.recover_utf8", FT_BOOLEAN, 32,
		TFS(&tfs_butype_attr_recover_utf8), 0x00000100, "recover_utf8", HFILL }},

	{ &hf_ndmp_butype_env_name, {
		"Name", "ndmp.butype.env.name", FT_STRING, BASE_NONE,
		NULL, 0, "Name for this env-variable", HFILL }},

	{ &hf_ndmp_butype_env_value, {
		"Value", "ndmp.butype.env.value", FT_STRING, BASE_NONE,
		NULL, 0, "Value for this env-variable", HFILL }},

	{ &hf_ndmp_fs_info, {
		"FS Info", "ndmp.fs.info", FT_NONE, BASE_NONE,
		NULL, 0, "FS Info", HFILL }},

	{ &hf_ndmp_fs_invalid_total_size, {
		"", "ndmp.fs.invalid.total_size", FT_BOOLEAN, 32,
		TFS(&tfs_fs_invalid_total_size), 0x00000001, "If total size is invalid", HFILL }},

	{ &hf_ndmp_fs_invalid_used_size, {
		"", "ndmp.fs.invalid.used_size", FT_BOOLEAN, 32,
		TFS(&tfs_fs_invalid_used_size), 0x00000002, "If used size is invalid", HFILL }},

	{ &hf_ndmp_fs_invalid_avail_size, {
		"", "ndmp.fs.invalid.avail_size", FT_BOOLEAN, 32,
		TFS(&tfs_fs_invalid_avail_size), 0x00000004, "If available size is invalid", HFILL }},

	{ &hf_ndmp_fs_invalid_total_inodes, {
		"", "ndmp.fs.invalid.total_inodes", FT_BOOLEAN, 32,
		TFS(&tfs_fs_invalid_total_inodes), 0x00000008, "If total number of inodes is invalid", HFILL }},

	{ &hf_ndmp_fs_invalid_used_inodes, {
		"", "ndmp.fs.invalid.used_inodes", FT_BOOLEAN, 32,
		TFS(&tfs_fs_invalid_used_inodes), 0x00000010, "If used number of inodes is invalid", HFILL }},

	{ &hf_ndmp_fs_fs_type, {
		"Type", "ndmp.fs.type", FT_STRING, BASE_NONE,
		NULL, 0, "Type of FS", HFILL }},

	{ &hf_ndmp_fs_logical_device, {
		"Logical Device", "ndmp.fs.logical_device", FT_STRING, BASE_NONE,
		NULL, 0, "Name of logical device", HFILL }},

	{ &hf_ndmp_fs_physical_device, {
		"Physical Device", "ndmp.fs.physical_device", FT_STRING, BASE_NONE,
		NULL, 0, "Name of physical device", HFILL }},

	{ &hf_ndmp_fs_total_size, {
		"Total Size", "ndmp.fs.total_size", FT_UINT64, BASE_DEC,
		NULL, 0, "Total size of FS", HFILL }},

	{ &hf_ndmp_fs_used_size, {
		"Used Size", "ndmp.fs.used_size", FT_UINT64, BASE_DEC,
		NULL, 0, "Total used size of FS", HFILL }},

	{ &hf_ndmp_fs_avail_size, {
		"Avail Size", "ndmp.fs.avail_size", FT_UINT64, BASE_DEC,
		NULL, 0, "Total available size on FS", HFILL }},

	{ &hf_ndmp_fs_total_inodes, {
		"Total Inodes", "ndmp.fs.total_inodes", FT_UINT64, BASE_DEC,
		NULL, 0, "Total number of inodes on FS", HFILL }},

	{ &hf_ndmp_fs_used_inodes, {
		"Used Inodes", "ndmp.fs.used_inodes", FT_UINT64, BASE_DEC,
		NULL, 0, "Number of used inodes on FS", HFILL }},

	{ &hf_ndmp_fs_env, {
		"Env variables", "ndmp.fs.env", FT_NONE, BASE_NONE,
		NULL, 0, "Environment variables for FS", HFILL }},

	{ &hf_ndmp_fs_env_name, {
		"Name", "ndmp.fs.env.name", FT_STRING, BASE_NONE,
		NULL, 0, "Name for this env-variable", HFILL }},

	{ &hf_ndmp_fs_env_value, {
		"Value", "ndmp.fs.env.value", FT_STRING, BASE_NONE,
		NULL, 0, "Value for this env-variable", HFILL }},

	{ &hf_ndmp_fs_status, {
		"Status", "ndmp.fs.status", FT_STRING, BASE_NONE,
		NULL, 0, "Status for this FS", HFILL }},

	{ &hf_ndmp_tape_info, {
		"Tape Info", "ndmp.tape.info", FT_NONE, BASE_NONE,
		NULL, 0, "Tape Info", HFILL }},

	{ &hf_ndmp_tape_model, {
		"Model", "ndmp.tape.model", FT_STRING, BASE_NONE,
		NULL, 0, "Model of the TAPE drive", HFILL }},

	{ &hf_ndmp_tape_dev_cap, {
		"Device Capability", "ndmp.tape.dev_cap", FT_NONE, BASE_NONE,
		NULL, 0, "Tape Device Capability", HFILL }},

	{ &hf_ndmp_tape_device, {
		"Device", "ndmp.tape.device", FT_STRING, BASE_NONE,
		NULL, 0, "Name of TAPE Device", HFILL }},

	{ &hf_ndmp_tape_attr_rewind, {
		"", "ndmp.tape.attr.rewind", FT_BOOLEAN, 32,
		TFS(&tfs_tape_attr_rewind), 0x00000001, "If this device supports rewind", HFILL }},

	{ &hf_ndmp_tape_attr_unload, {
		"", "ndmp.tape.attr.unload", FT_BOOLEAN, 32,
		TFS(&tfs_tape_attr_unload), 0x00000002, "If this device supports unload", HFILL }},

	{ &hf_ndmp_tape_capability, {
		"Tape Capabilities", "ndmp.tape.capability", FT_NONE, BASE_NONE,
		NULL, 0, "Tape Capabilities", HFILL }},

	{ &hf_ndmp_tape_capability_name, {
		"Name", "ndmp.tape.cap.name", FT_STRING, BASE_NONE,
		NULL, 0, "Name for this env-variable", HFILL }},

	{ &hf_ndmp_tape_capability_value, {
		"Value", "ndmp.tape.cap.value", FT_STRING, BASE_NONE,
		NULL, 0, "Value for this env-variable", HFILL }},

	{ &hf_ndmp_scsi_info, {
		"SCSI Info", "ndmp.scsi.info", FT_NONE, BASE_NONE,
		NULL, 0, "SCSI Info", HFILL }},

	{ &hf_ndmp_scsi_model, {
		"Model", "ndmp.scsi.model", FT_STRING, BASE_NONE,
		NULL, 0, "Model of the SCSI device", HFILL }},

	{ &hf_ndmp_server_vendor, {
		"Vendor", "ndmp.server.vendor", FT_STRING, BASE_NONE,
		NULL, 0, "Name of vendor", HFILL }},

	{ &hf_ndmp_server_product, {
		"Product", "ndmp.server.product", FT_STRING, BASE_NONE,
		NULL, 0, "Name of product", HFILL }},

	{ &hf_ndmp_server_revision, {
		"Revision", "ndmp.server.revision", FT_STRING, BASE_NONE,
		NULL, 0, "Revision of this product", HFILL }},

	{ &hf_ndmp_auth_types, {
		"Auth types", "ndmp.auth.types", FT_NONE, BASE_NONE,
		NULL, 0, "Auth types", HFILL }},

	{ &hf_ndmp_scsi_device, {
		"Device", "ndmp.scsi.device", FT_STRING, BASE_NONE,
		NULL, 0, "Name of SCSI Device", HFILL }},

	{ &hf_ndmp_scsi_controller, {
		"Controller", "ndmp.scsi.controller", FT_UINT32, BASE_DEC,
		NULL, 0, "Target Controller", HFILL }},

	{ &hf_ndmp_scsi_id, {
		"ID", "ndmp.scsi.id", FT_UINT32, BASE_DEC,
		NULL, 0, "Target ID", HFILL }},

	{ &hf_ndmp_scsi_lun, {
		"LUN", "ndmp.scsi.lun", FT_UINT32, BASE_DEC,
		NULL, 0, "Target LUN", HFILL }},

	{ &hf_ndmp_tape_open_mode, {
		"Mode", "ndmp.tape.open_mode", FT_UINT32, BASE_DEC,
		VALS(tape_open_mode_vals), 0, "Mode to open tape in", HFILL }},

	{ &hf_ndmp_tape_invalid_file_num, {
		"", "ndmp.tape.invalid.file_num", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_tape_invalid_file_num), 0x00000001, "invalid_file_num", HFILL }},

	{ &hf_ndmp_tape_invalid_soft_errors, {
		"", "ndmp.tape.invalid.soft_errors", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_tape_invalid_soft_errors), 0x00000002, "soft_errors", HFILL }},

	{ &hf_ndmp_tape_invalid_block_size, {
		"", "ndmp.tape.invalid.block_size", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_tape_invalid_block_size), 0x00000004, "block_size", HFILL }},

	{ &hf_ndmp_tape_invalid_block_no, {
		"", "ndmp.tape.invalid.block_no", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_tape_invalid_block_no), 0x00000008, "block_no", HFILL }},

	{ &hf_ndmp_tape_invalid_total_space, {
		"", "ndmp.tape.invalid.total_space", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_tape_invalid_total_space), 0x00000010, "total_space", HFILL }},

	{ &hf_ndmp_tape_invalid_space_remain, {
		"", "ndmp.tape.invalid.space_remain", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_tape_invalid_space_remain), 0x00000020, "space_remain", HFILL }},

	{ &hf_ndmp_tape_invalid_partition, {
		"", "ndmp.tape.invalid.partition", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_tape_invalid_partition), 0x00000040, "partition", HFILL }},

	{ &hf_ndmp_tape_flags_no_rewind, {
		"", "ndmp.tape.flags.no_rewind", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_tape_flags_no_rewind), 0x00000008, "no_rewind", HFILL, }},

	{ &hf_ndmp_tape_flags_write_protect, {
		"", "ndmp.tape.flags.write_protect", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_tape_flags_write_protect), 0x00000010, "write_protect", HFILL, }},

	{ &hf_ndmp_tape_flags_error, {
		"", "ndmp.tape.flags.error", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_tape_flags_error), 0x00000020, "error", HFILL, }},

	{ &hf_ndmp_tape_flags_unload, {
		"", "ndmp.tape.flags.unload", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_tape_flags_unload), 0x00000040, "unload", HFILL, }},

	{ &hf_ndmp_tape_file_num, {
		"file_num", "ndmp.tape.status.file_num", FT_UINT32, BASE_DEC,
		NULL, 0, "file_num", HFILL }},

	{ &hf_ndmp_tape_soft_errors, {
		"soft_errors", "ndmp.tape.status.soft_errors", FT_UINT32, BASE_DEC,
		NULL, 0, "soft_errors", HFILL }},

	{ &hf_ndmp_tape_block_size, {
		"block_size", "ndmp.tape.status.block_size", FT_UINT32, BASE_DEC,
		NULL, 0, "block_size", HFILL }},

	{ &hf_ndmp_tape_block_no, {
		"block_no", "ndmp.tape.status.block_no", FT_UINT32, BASE_DEC,
		NULL, 0, "block_no", HFILL }},

	{ &hf_ndmp_tape_total_space, {
		"total_space", "ndmp.tape.status.total_space", FT_UINT64, BASE_DEC,
		NULL, 0, "total_space", HFILL }},

	{ &hf_ndmp_tape_space_remain, {
		"space_remain", "ndmp.tape.status.space_remain", FT_UINT64, BASE_DEC,
		NULL, 0, "space_remain", HFILL }},

	{ &hf_ndmp_tape_partition, {
		"partition", "ndmp.tape.status.partition", FT_UINT32, BASE_DEC,
		NULL, 0, "partition", HFILL }},

	{ &hf_ndmp_tape_mtio_op, {
		"Operation", "ndmp.tape.mtio.op", FT_UINT32, BASE_DEC,
		VALS(tape_mtio_vals), 0, "MTIO Operation", HFILL }},

	{ &hf_ndmp_count, {
		"Count", "ndmp.count", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of bytes/objects/operations", HFILL }},

	{ &hf_ndmp_resid_count, {
		"Resid Count", "ndmp.resid_count", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of remaining bytes/objects/operations", HFILL }},

	{ &hf_ndmp_mover_state, {
		"State", "ndmp.mover.state", FT_UINT32, BASE_DEC,
		VALS(mover_state_vals), 0, "State of the selected mover", HFILL }},

	{ &hf_ndmp_mover_pause, {
		"Pause", "ndmp.mover.pause", FT_UINT32, BASE_DEC,
		VALS(mover_pause_vals), 0, "Reason why the mover paused", HFILL }},

	{ &hf_ndmp_halt, {
		"Halt", "ndmp.halt", FT_UINT32, BASE_DEC,
		VALS(halt_vals), 0, "Reason why it halted", HFILL }},

	{ &hf_ndmp_record_size, {
		"Record Size", "ndmp.record.size", FT_UINT32, BASE_DEC,
		NULL, 0, "Record size in bytes", HFILL }},

	{ &hf_ndmp_record_num, {
		"Record Num", "ndmp.record.num", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of records", HFILL }},

	{ &hf_ndmp_data_written, {
		"Data Written", "ndmp.data.written", FT_UINT64, BASE_DEC,
		NULL, 0, "Number of data bytes written", HFILL }},

	{ &hf_ndmp_seek_position, {
		"Seek Position", "ndmp.seek.position", FT_UINT64, BASE_DEC,
		NULL, 0, "Current seek position on device", HFILL }},

	{ &hf_ndmp_bytes_left_to_read, {
		"Bytes left to read", "ndmp.bytes_left_to_read", FT_UINT64, BASE_DEC,
		NULL, 0, "Number of bytes left to be read from the device", HFILL }},

	{ &hf_ndmp_window_offset, {
		"Window Offset", "ndmp.window.offset", FT_UINT64, BASE_DEC,
		NULL, 0, "Offset to window in bytes", HFILL }},

	{ &hf_ndmp_window_length, {
		"Window Length", "ndmp.window.length", FT_UINT64, BASE_DEC,
		NULL, 0, "Size of window in bytes", HFILL }},

	{ &hf_ndmp_addr_ip, {
		"IP Address", "ndmp.addr.ip", FT_IPv4, BASE_DEC,
		NULL, 0, "IP Address", HFILL }},

	{ &hf_ndmp_addr_tcp, {
		"TCP Port", "ndmp.addr.tcp_port", FT_UINT32, BASE_DEC,
		NULL, 0, "TCP Port", HFILL }},

	{ &hf_ndmp_addr_fcal_loop_id, {
		"Loop ID", "ndmp.addr.loop_id", FT_UINT32, BASE_HEX,
		NULL, 0, "FCAL Loop ID", HFILL }},

	{ &hf_ndmp_addr_ipc, {
		"IPC", "ndmp.addr.ipc", FT_BYTES, BASE_HEX,
		NULL, 0, "IPC identifier", HFILL }},

	{ &hf_ndmp_mover_mode, {
		"Mode", "ndmp.mover.mode", FT_UINT32, BASE_HEX,
		VALS(mover_mode_vals), 0, "Mover Mode", HFILL }},

	{ &hf_ndmp_file_name, {
		"File", "ndmp.file", FT_STRING, BASE_NONE,
		NULL, 0, "Name of File", HFILL }},

	{ &hf_ndmp_nt_file_name, {
		"NT File", "ndmp.file", FT_STRING, BASE_NONE,
		NULL, 0, "NT Name of File", HFILL }},

	{ &hf_ndmp_dos_file_name, {
		"DOS File", "ndmp.file", FT_STRING, BASE_NONE,
		NULL, 0, "DOS Name of File", HFILL }},

	{ &hf_ndmp_log_type, {
		"Type", "ndmp.log.type", FT_UINT32, BASE_HEX,
		VALS(log_type_vals), 0, "Type of log entry", HFILL }},

	{ &hf_ndmp_log_message_id, {
		"Message ID", "ndmp.log.message.id", FT_UINT32, BASE_DEC,
		NULL, 0, "ID of this log entry", HFILL }},

	{ &hf_ndmp_log_message, {
		"Message", "ndmp.log.message", FT_STRING, BASE_NONE,
		NULL, 0, "Log entry", HFILL }},

	{ &hf_ndmp_halt_reason, {
		"Reason", "ndmp.halt.reason", FT_STRING, BASE_NONE,
		NULL, 0, "Textual reason for why it halted", HFILL }},

	{ &hf_ndmp_connected, {
		"Connected", "ndmp.connected", FT_UINT32, BASE_DEC,
		VALS(connected_vals), 0, "Status of connection", HFILL }},

	{ &hf_ndmp_connected_reason, {
		"Reason", "ndmp.connected.reason", FT_STRING, BASE_NONE,
		NULL, 0, "Textual description of the connection status", HFILL }},

	{ &hf_ndmp_auth_id, {
		"ID", "ndmp.auth.id", FT_STRING, BASE_NONE,
		NULL, 0, "ID of client authenticating", HFILL }},

	{ &hf_ndmp_auth_password, {
		"Password", "ndmp.auth.password", FT_STRING, BASE_NONE,
		NULL, 0, "Password of client authenticating", HFILL }},

	{ &hf_ndmp_data, {
		"Data", "ndmp.data", FT_BYTES, BASE_HEX,
		NULL, 0, "Data written/read", HFILL }},

	{ &hf_ndmp_files, {
		"Files", "ndmp.files", FT_NONE, 0,
		NULL, 0, "List of files", HFILL }},

	{ &hf_ndmp_file_names, {
		"File Names", "ndmp.file.names", FT_NONE, 0,
		NULL, 0, "List of file names", HFILL }},

	{ &hf_ndmp_file_fs_type, {
		"File FS Type", "ndmp.file.fs_type", FT_UINT32, BASE_DEC,
		VALS(file_fs_type_vals), 0, "Type of file permissions (UNIX or NT)", HFILL }},

	{ &hf_ndmp_file_type, {
		"File Type", "ndmp.file.type", FT_UINT32, BASE_DEC,
		VALS(file_type_vals), 0, "Type of file", HFILL }},

	{ &hf_ndmp_file_stats, {
		"File Stats", "ndmp.file.stats", FT_NONE, 0,
		NULL, 0, "List of file stats", HFILL }},

	{ &hf_ndmp_file_node, {
		"Node", "ndmp.file.node", FT_UINT64, BASE_DEC,
		NULL, 0, "Node used for direct access", HFILL }},

	{ &hf_ndmp_file_parent, {
		"Parent", "ndmp.file.parent", FT_UINT64, BASE_DEC,
		NULL, 0, "Parent node(directory) for this node", HFILL }},

	{ &hf_ndmp_file_fh_info, {
		"FH Info", "ndmp.file.fh_info", FT_UINT64, BASE_DEC,
		NULL, 0, "FH Info used for direct access", HFILL }},

	{ &hf_ndmp_file_invalid_atime, {
		"", "ndmp.file.invalid_atime", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_file_invalid_atime), 0x00000001, "invalid_atime", HFILL, }},

	{ &hf_ndmp_file_invalid_ctime, {
		"", "ndmp.file.invalid_ctime", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_file_invalid_ctime), 0x00000002, "invalid_ctime", HFILL, }},

	{ &hf_ndmp_file_invalid_group, {
		"", "ndmp.file.invalid_group", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_file_invalid_group), 0x00000004, "invalid_group", HFILL, }},

	{ &hf_ndmp_file_mtime, {
		"mtime", "ndmp.file.mtime", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Timestamp for mtime for this file", HFILL }},

	{ &hf_ndmp_file_atime, {
		"atime", "ndmp.file.atime", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Timestamp for atime for this file", HFILL }},

	{ &hf_ndmp_file_ctime, {
		"ctime", "ndmp.file.ctime", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Timestamp for ctime for this file", HFILL }},

	{ &hf_ndmp_file_owner, {
		"Owner", "ndmp.file.owner", FT_UINT32, BASE_DEC,
		NULL, 0, "UID for UNIX, owner for NT", HFILL }},

	{ &hf_ndmp_file_group, {
		"Group", "ndmp.file.group", FT_UINT32, BASE_DEC,
		NULL, 0, "GID for UNIX, NA for NT", HFILL }},

	{ &hf_ndmp_file_fattr, {
		"Fattr", "ndmp.file.fattr", FT_UINT32, BASE_HEX,
		NULL, 0, "Mode for UNIX, fattr for NT", HFILL }},

	{ &hf_ndmp_file_size, {
		"Size", "ndmp.file.size", FT_UINT64, BASE_DEC,
		NULL, 0, "File Size", HFILL }},

	{ &hf_ndmp_file_links, {
		"Links", "ndmp.file.links", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of links to this file", HFILL }},

	{ &hf_ndmp_dirs, {
		"Dirs", "ndmp.dirs", FT_NONE, 0,
		NULL, 0, "List of directories", HFILL }},

	{ &hf_ndmp_nodes, {
		"Nodes", "ndmp.nodes", FT_NONE, 0,
		NULL, 0, "List of nodes", HFILL }},

	{ &hf_ndmp_nlist, {
		"Nlist", "ndmp.nlist", FT_NONE, 0,
		NULL, 0, "List of names", HFILL }},

	{ &hf_ndmp_bu_original_path, {
		"Original Path", "ndmp.bu.original_path", FT_STRING, BASE_NONE,
		NULL, 0, "Original path where backup was created", HFILL }},

	{ &hf_ndmp_bu_destination_dir, {
		"Destination Dir", "ndmp.bu.destination_dir", FT_STRING, BASE_NONE,
		NULL, 0, "Destination directory to restore backup to", HFILL }},

	{ &hf_ndmp_bu_new_name, {
		"New Name", "ndmp.bu.new_name", FT_STRING, BASE_NONE,
		NULL, 0, "New Name", HFILL }},

	{ &hf_ndmp_bu_other_name, {
		"Other Name", "ndmp.bu.other_name", FT_STRING, BASE_NONE,
		NULL, 0, "Other Name", HFILL }},

	{ &hf_ndmp_state_invalid_ebr, {
		"", "ndmp.bu.state.invalid_ebr", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_state_invalid_ebr), 0x00000001, "Whether EstimatedBytesLeft is valid or not", HFILL, }},

	{ &hf_ndmp_state_invalid_etr, {
		"", "ndmp.bu.state.invalid_etr", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_state_invalid_etr), 0x00000002, "Whether EstimatedTimeLeft is valid or not", HFILL, }},

	{ &hf_ndmp_bu_operation, {
		"Operation", "ndmp.bu.operation", FT_UINT32, BASE_DEC,
		VALS(bu_operation_vals), 0, "BU Operation", HFILL, }},

	{ &hf_ndmp_data_state, {
		"State", "ndmp.data.state", FT_UINT32, BASE_DEC,
		VALS(data_state_vals), 0, "Data state", HFILL, }},

	{ &hf_ndmp_data_halted, {
		"Halted Reason", "ndmp.data.halted", FT_UINT32, BASE_DEC,
		VALS(data_halted_vals), 0, "Data halted reason", HFILL, }},

	{ &hf_ndmp_data_bytes_processed, {
		"Bytes Processed", "ndmp.data.bytes_processed", FT_UINT64, BASE_DEC,
		NULL, 0, "Number of bytes processed", HFILL }},

	{ &hf_ndmp_data_est_bytes_remain, {
		"Est Bytes Remain", "ndmp.data.est_bytes_remain", FT_UINT64, BASE_DEC,
		NULL, 0, "Estimated number of bytes remaining", HFILL }},

	{ &hf_ndmp_data_est_time_remain, {
		"Est Time Remain", "ndmp.data.est_time_remain", FT_RELATIVE_TIME, BASE_DEC,
		NULL, 0, "Estimated time remaining", HFILL }},



  };

  static gint *ett[] = {
    &ett_ndmp,
    &ett_ndmp_header,
    &ett_ndmp_butype_attrs,
    &ett_ndmp_fs_invalid,
    &ett_ndmp_tape_attr,
    &ett_ndmp_tape_invalid,
    &ett_ndmp_tape_flags,
    &ett_ndmp_addr,
    &ett_ndmp_file,
    &ett_ndmp_file_name,
    &ett_ndmp_file_invalids,
    &ett_ndmp_state_invalids,
  };

  module_t *ndmp_module;

  proto_ndmp = proto_register_protocol("Network Data Management Protocol", "NDMP", "ndmp");
  proto_register_field_array(proto_ndmp, hf_ndmp, array_length(hf_ndmp));
  
  proto_register_subtree_array(ett, array_length(ett));

  /* desegmentation */
  ndmp_module = prefs_register_protocol(proto_ndmp, NULL);
  prefs_register_bool_preference(ndmp_module, "desegment", "Desegment all NDMP messages spanning multiple TCP segments", "Whether the dissector should desegment NDMP over TCP PDUs or not", &ndmp_desegment);

}

void
proto_reg_handoff_ndmp(void)
{
  dissector_handle_t ndmp_handle;

  ndmp_handle = create_dissector_handle(dissect_ndmp, proto_ndmp);
  dissector_add("tcp.port",TCP_PORT_NDMP, ndmp_handle);
}

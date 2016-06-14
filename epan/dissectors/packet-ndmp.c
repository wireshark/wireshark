/* TODO: fixup LUN tracking so we can pass the proper LUN across to
   dissect_scsi_xxx()
*/
/* packet-ndmp.c
 * Routines for NDMP dissection
 * 2001 Ronnie Sahlberg (see AUTHORS for email)
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

/* see www.ndmp.org for protocol specifications.
   this file implements version 3 of ndmp
*/

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <wsutil/str_util.h>
#include "packet-rpc.h"
#include "packet-ndmp.h"
#include "packet-tcp.h"
#include "packet-scsi.h"
#include <epan/prefs.h>
#include <epan/reassemble.h>

void proto_register_ndmp(void);
void proto_reg_handoff_ndmp(void);

#define TCP_PORT_NDMP 10000

static  dissector_handle_t ndmp_handle;

static int proto_ndmp = -1;
static int hf_ndmp_request_frame = -1;
static int hf_ndmp_response_frame = -1;
static int hf_ndmp_time = -1;
static int hf_ndmp_lastfrag = -1;
static int hf_ndmp_fraglen = -1;
static int hf_ndmp_version = -1;
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
static int hf_ndmp_butype_attr = -1;
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
static int hf_ndmp_tcp_env_name = -1;
static int hf_ndmp_tcp_env_value = -1;
static int hf_ndmp_tcp_default_env = -1;
static int hf_ndmp_tcp_addr_list = -1;
static int hf_ndmp_fs_info = -1;
static int hf_ndmp_fs_invalid = -1;
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
static int hf_ndmp_tape_attr = -1;
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
static int hf_ndmp_execute_cdb_flags = -1;
static int hf_ndmp_execute_cdb_flags_data_in = -1;
static int hf_ndmp_execute_cdb_flags_data_out = -1;
static int hf_ndmp_execute_cdb_timeout = -1;
static int hf_ndmp_execute_cdb_datain_len = -1;
static int hf_ndmp_execute_cdb_cdb_len = -1;
/* static int hf_ndmp_execute_cdb_dataout = -1; */
static int hf_ndmp_execute_cdb_status = -1;
static int hf_ndmp_execute_cdb_dataout_len = -1;
/* static int hf_ndmp_execute_cdb_datain = -1; */
static int hf_ndmp_execute_cdb_sns_len = -1;
static int hf_ndmp_tape_invalid = -1;
static int hf_ndmp_tape_invalid_file_num = -1;
static int hf_ndmp_tape_invalid_soft_errors = -1;
static int hf_ndmp_tape_invalid_block_size = -1;
static int hf_ndmp_tape_invalid_block_no = -1;
static int hf_ndmp_tape_invalid_total_space = -1;
static int hf_ndmp_tape_invalid_space_remain = -1;
static int hf_ndmp_tape_invalid_partition = -1;
static int hf_ndmp_tape_flags = -1;
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
static int hf_ndmp_file_invalid = -1;
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
static int hf_ndmp_state_invalid = -1;
static int hf_ndmp_state_invalid_ebr = -1;
static int hf_ndmp_state_invalid_etr = -1;
static int hf_ndmp_bu_operation = -1;
static int hf_ndmp_data_state = -1;
static int hf_ndmp_data_halted = -1;
static int hf_ndmp_data_bytes_processed = -1;
static int hf_ndmp_data_est_bytes_remain = -1;
static int hf_ndmp_data_est_time_remain = -1;
static int hf_ndmp_ex_class_id = -1;
static int hf_ndmp_class_list = -1;
static int hf_ndmp_ext_version = -1;
static int hf_ndmp_ext_version_list = -1;
static int hf_ndmp_class_version = -1;
static int hf_ndmp_ex_class_version = -1;

static int hf_ndmp_fragment_data = -1;
static int hf_ndmp_fragments = -1;
static int hf_ndmp_fragment = -1;
static int hf_ndmp_fragment_overlap = -1;
static int hf_ndmp_fragment_overlap_conflicts = -1;
static int hf_ndmp_fragment_multiple_tails = -1;
static int hf_ndmp_fragment_too_long_fragment = -1;
static int hf_ndmp_fragment_error = -1;
static int hf_ndmp_fragment_count = -1;
static int hf_ndmp_reassembled_in = -1;
static int hf_ndmp_reassembled_length = -1;

static gint ett_ndmp = -1;
static gint ett_ndmp_fraghdr = -1;
static gint ett_ndmp_header = -1;
static gint ett_ndmp_butype_attrs = -1;
static gint ett_ndmp_fs_invalid = -1;
static gint ett_ndmp_tape_attr = -1;
static gint ett_ndmp_execute_cdb_flags = -1;
static gint ett_ndmp_execute_cdb_cdb = -1;
static gint ett_ndmp_execute_cdb_sns = -1;
static gint ett_ndmp_execute_cdb_payload = -1;
static gint ett_ndmp_tape_invalid = -1;
static gint ett_ndmp_tape_flags = -1;
static gint ett_ndmp_addr = -1;
static gint ett_ndmp_file = -1;
static gint ett_ndmp_file_name = -1;
static gint ett_ndmp_file_stats = -1;
static gint ett_ndmp_file_invalids = -1;
static gint ett_ndmp_state_invalids = -1;
static gint ett_ndmp_fragment = -1;
static gint ett_ndmp_fragments = -1;

static expert_field ei_ndmp_msg = EI_INIT;

static const fragment_items ndmp_frag_items = {
	/* Fragment subtrees */
	&ett_ndmp_fragment,
	&ett_ndmp_fragments,
	/* Fragment fields */
	&hf_ndmp_fragments,
	&hf_ndmp_fragment,
	&hf_ndmp_fragment_overlap,
	&hf_ndmp_fragment_overlap_conflicts,
	&hf_ndmp_fragment_multiple_tails,
	&hf_ndmp_fragment_too_long_fragment,
	&hf_ndmp_fragment_error,
	&hf_ndmp_fragment_count,
	/* Reassembled in field */
	&hf_ndmp_reassembled_in,
	/* Reassembled length field */
	&hf_ndmp_reassembled_length,
	/* Reassembled data field */
	NULL,
	/* Tag */
	"NDMP fragments"
};

static reassembly_table ndmp_reassembly_table;

/* XXX someone should start adding the new stuff from v3, v4 and v5*/
#define NDMP_PROTOCOL_UNKNOWN	0
#define NDMP_PROTOCOL_V2	2
#define NDMP_PROTOCOL_V3	3
#define NDMP_PROTOCOL_V4	4
#define NDMP_PROTOCOL_V5	5
static const enum_val_t ndmp_protocol_versions[] = {
	{ "version2",	"Version 2",	NDMP_PROTOCOL_V2 },
	{ "version3",	"Version 3",	NDMP_PROTOCOL_V3 },
	{ "version4",	"Version 4",	NDMP_PROTOCOL_V4 },
	{ "version5",	"Version 5",	NDMP_PROTOCOL_V5 },
	{ NULL, NULL, 0 }
};

static gint ndmp_default_protocol_version = NDMP_PROTOCOL_V4;

typedef struct _ndmp_frag_info {
	guint32 first_seq;
	guint16 offset;
} ndmp_frag_info;

typedef struct _ndmp_task_data_t {
	guint32 request_frame;
	guint32 response_frame;
	nstime_t ndmp_time;
	itlq_nexus_t *itlq;
} ndmp_task_data_t;

typedef struct _ndmp_conv_data_t {
	guint8 version;
	wmem_map_t *tasks;	/* indexed by Sequence# */
	wmem_tree_t *itl;	/* indexed by packet# */
	wmem_map_t *fragsA; 	/* indexed by Sequence# */
	wmem_map_t *fragsB;
	ndmp_task_data_t *task;
	conversation_t *conversation;
} ndmp_conv_data_t;
static ndmp_conv_data_t *ndmp_conv_data=NULL;
static proto_tree *top_tree;

static itl_nexus_t *
get_itl_nexus(packet_info *pinfo, gboolean create_new)
{
	itl_nexus_t *itl;

	if(create_new || !(itl=(itl_nexus_t *)wmem_tree_lookup32_le(ndmp_conv_data->itl, pinfo->num))){
		itl=wmem_new(wmem_file_scope(), itl_nexus_t);
		itl->cmdset=0xff;
		itl->conversation=ndmp_conv_data->conversation;
		wmem_tree_insert32(ndmp_conv_data->itl, pinfo->num, itl);
	}
	return itl;
}

static guint8
get_ndmp_protocol_version(void)
{
	if(!ndmp_conv_data || (ndmp_conv_data->version==NDMP_PROTOCOL_UNKNOWN)){
		return ndmp_default_protocol_version;
	}
	return ndmp_conv_data->version;
}

struct ndmp_header {
	guint32	seq;
	guint32 timestamp;
	guint32 type;
	guint32 msg;
	guint32 rep_seq;
	guint32 err;
};

/* desegmentation of NDMP packets */
static gboolean ndmp_desegment = TRUE;

/* defragmentation of fragmented NDMP records */
static gboolean ndmp_defragment = TRUE;

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
#define NDMP_SEQUENCE_NUM_ERR		0x18
#define NDMP_READ_IN_PROGRESS_ERR	0x19
#define NDMP_PRECONDITION_ERR		0x1a
#define NDMP_CLASS_NOT_SUPPORTED_ERR	0x1b
#define NDMP_VERSION_NOT_SUPPORTED_ERR	0x1c
#define NDMP_EXT_DUPL_CLASSES_ERR	0x1d
#define NDMP_EXT_DANDN_ILLEGAL_ERR	0x1e

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
	{NDMP_SEQUENCE_NUM_ERR,		"NDMP_SEQUENCE_NUM_ERR"},
	{NDMP_READ_IN_PROGRESS_ERR,	"NDMP_READ_IN_PROGRESS_ERR"},
	{NDMP_PRECONDITION_ERR,		"NDMP_PRECONDITION_ERR"},
	{NDMP_CLASS_NOT_SUPPORTED_ERR,	"NDMP_CLASS_NOT_SUPPORTED_ERR"},
	{NDMP_VERSION_NOT_SUPPORTED_ERR,"NDMP_VERSION_NOT_SUPPORTED_ERR"},
	{NDMP_EXT_DUPL_CLASSES_ERR,	"NDMP_EXT_DUPL_CLASSES_ERR"},
	{NDMP_EXT_DANDN_ILLEGAL_ERR,	"NDMP_EXT_DANDN_ILLEGAL_ERR"},
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
#define NDMP_CONFIG_SET_EXT_LIST	0x109
#define NDMP_CONFIG_GET_EXT_LIST	0x10a
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
	{NDMP_CONFIG_GET_EXT_LIST, 	"CONFIG_GET_EXT_LIST"},
	{NDMP_CONFIG_SET_EXT_LIST, 	"CONFIG_SET_EXT_LIST"},
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

static gboolean
check_ndmp_rm(tvbuff_t *tvb, packet_info *pinfo)
{
	guint len;
	guint32 tmp;

	/* verify that the tcp port is 10000, ndmp always runs on port 10000*/
	if ((pinfo->srcport!=TCP_PORT_NDMP)&&(pinfo->destport!=TCP_PORT_NDMP)) {
		return FALSE;
	}

	/* check that the header looks sane */
	len=tvb_captured_length(tvb);
	/* check the record marker that it looks sane.
	 * It has to be >=0 bytes or (arbitrary limit) <1Mbyte
	 */
	if(len>=4){
		tmp=(tvb_get_ntohl(tvb, 0)&RPC_RM_FRAGLEN);
		if( (tmp<1)||(tmp>1000000) ){
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
check_ndmp_hdr(tvbuff_t *tvb )
{
	guint len;
	guint32 tmp;

	len=tvb_captured_length(tvb);

	/* If the length is less than 24, it isn't a valid
	   header */
	if (len<24){
		return FALSE;
	}

	/* check the timestamp,  timestamps are valid if they
	 * (arbitrary) lie between 1980-jan-1 and 2030-jan-1
	 */
	if(len>=8){
		tmp=tvb_get_ntohl(tvb, 4);
		if( (tmp<0x12ceec50)||(tmp>0x70dc1ed0) ){
			return FALSE;
		}
	}

	/* check the type */
	if(len>=12){
		tmp=tvb_get_ntohl(tvb, 8);
		if( tmp>1 ){
			return FALSE;
		}
	}

	/* check message */
	if(len>=16){
		tmp=tvb_get_ntohl(tvb, 12);
		if( (tmp>0xa09) || (tmp==0) ){
			return FALSE;
		}
	}

	/* check error */
	if(len>=24){
		tmp=tvb_get_ntohl(tvb, 20);
		if( (tmp>0x17) ){
			return FALSE;
		}
	}

	return TRUE;
}

static int
dissect_connect_open_request(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		proto_tree *tree, guint32 seq _U_)
{
	guint32 version;

	/* version number */
	proto_tree_add_item(tree, hf_ndmp_version, tvb, offset, 4, ENC_BIG_ENDIAN);
	version=tvb_get_ntohl(tvb, offset);
	ndmp_conv_data->version=version;
	offset += 4;

	return offset;
}

static int
dissect_error(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq _U_)
{
	guint32 err;

	/* error */
	err=tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(tree, hf_ndmp_error, tvb, offset, 4, ENC_BIG_ENDIAN);
	if(err) {
		col_append_fstr(pinfo->cinfo, COL_INFO,
			" NDMP Error:%s ",
			val_to_str(err, error_vals,
			"Unknown NDMP error code %#x"));
	}

	offset += 4;

	return offset;
}

static int
dissect_ndmp_get_host_info_reply(tvbuff_t *tvb, int offset,
		packet_info *pinfo, proto_tree *tree, guint32 seq)
{
	/* error */
	offset=dissect_error(tvb, offset, pinfo, tree, seq);

	/* hostname */
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_hostname, offset, NULL);

	/* os type */
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_os_type, offset, NULL);

	/* os version */
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_os_vers, offset, NULL);

	/* hostid */
	offset = dissect_rpc_string(tvb, tree,
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
dissect_ndmp_addr_type(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		proto_tree *tree, void* data _U_)
{
	proto_tree_add_item(tree, hf_ndmp_addr_type, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	return offset;
}

static int
dissect_ndmp_addr_msg(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq _U_)
{
	/*address type*/
	return dissect_ndmp_addr_type(tvb, offset, pinfo, tree, NULL);
}

static int
dissect_ndmp_config_get_connection_type_reply(tvbuff_t *tvb, int offset,
		packet_info *pinfo, proto_tree *tree, guint32 seq)
{
	/* error */
	offset=dissect_error(tvb, offset, pinfo, tree, seq);

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
dissect_auth_type(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		proto_tree *tree, void* data _U_)
{
	proto_tree_add_item(tree, hf_ndmp_auth_type, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	return offset;
}

static int
dissect_get_auth_type_request(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq _U_)
{
	/* auth type */
	return dissect_auth_type(tvb, offset, pinfo, tree, NULL);
}

static int
dissect_auth_attr_msg(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		proto_tree *tree, guint32 seq _U_)
{
	guint type;

	type=tvb_get_ntohl(tvb,offset);

	/* auth type */
	proto_tree_add_item(tree, hf_ndmp_auth_type, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	switch(type){
	case NDMP_AUTH_NONE:
		break;
	case NDMP_AUTH_TEXT:
		break;
	case NDMP_AUTH_MD5:
		proto_tree_add_item(tree, hf_ndmp_auth_challenge,
			tvb, offset, 64, ENC_NA);
		offset+=64;
	}

	return offset;
}

static int
dissect_ndmp_config_get_auth_attr_reply(tvbuff_t *tvb, int offset,
		packet_info *pinfo, proto_tree *tree, guint32 seq)
{
	/* error */
	offset = dissect_error(tvb, offset, pinfo, tree, seq);

	/* auth_attr */
	offset = dissect_auth_attr_msg(tvb, offset, pinfo, tree, seq);

	return offset;
}

static int
dissect_default_env(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		proto_tree *tree, void* data _U_)
{
	/* name */
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_butype_env_name, offset, NULL);

	/* value */
	offset = dissect_rpc_string(tvb, tree,
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
	"Perform INCREMENTAL recovery",
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
dissect_butype_attrs(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		proto_tree *parent_tree)
{
	static const int * attribute_flags[] = {
		&hf_ndmp_butype_attr_recover_utf8,
		&hf_ndmp_butype_attr_backup_utf8,
		&hf_ndmp_butype_attr_recover_incremental,
		&hf_ndmp_butype_attr_backup_incremental,
		&hf_ndmp_butype_attr_recover_direct,
		&hf_ndmp_butype_attr_backup_direct,
		&hf_ndmp_butype_attr_recover_filelist,
		&hf_ndmp_butype_attr_backup_filelist,
		&hf_ndmp_butype_attr_backup_file_history,
		NULL
		};

	proto_tree_add_bitmask(parent_tree, tvb, offset, hf_ndmp_butype_attr, ett_ndmp_butype_attrs, attribute_flags, ENC_NA);

	offset += 4;
	return offset;
}

static int
dissect_butype_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	/*butype name*/
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_butype_name, offset, NULL);

	/* default env */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_default_env, hf_ndmp_butype_default_env);

	/* attrs */
	offset = dissect_butype_attrs(tvb, offset, pinfo, tree);

	return offset;
}

static int
dissect_get_butype_info_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq)
{
	/* error */
	offset=dissect_error(tvb, offset, pinfo, tree, seq);

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
dissect_fs_invalid(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		proto_tree *parent_tree)
{
	static const int * invalid_flags[] = {
		&hf_ndmp_fs_invalid_used_inodes,
		&hf_ndmp_fs_invalid_total_inodes,
		&hf_ndmp_fs_invalid_avail_size,
		&hf_ndmp_fs_invalid_used_size,
		&hf_ndmp_fs_invalid_total_size,
		NULL
		};

	proto_tree_add_bitmask(parent_tree, tvb, offset, hf_ndmp_fs_invalid, ett_ndmp_fs_invalid, invalid_flags, ENC_NA);

	offset+=4;
	return offset;
}

static int
dissect_fs_env(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		proto_tree *tree, void* data _U_)
{
	/* name */
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_fs_env_name, offset, NULL);

	/* value */
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_fs_env_value, offset, NULL);

	return offset;
}

static int
dissect_fs_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	/* invalid bits */
	offset=dissect_fs_invalid(tvb, offset, pinfo, tree);

	/* fs type */
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_fs_fs_type, offset, NULL);

	/* fs logical device */
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_fs_logical_device, offset, NULL);

	/* fs physical device */
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_fs_physical_device, offset, NULL);

	/*total_size*/
	offset = dissect_rpc_uint64(tvb, tree, hf_ndmp_fs_total_size,
			offset);

	/*used_size*/
	offset = dissect_rpc_uint64(tvb, tree, hf_ndmp_fs_used_size,
			offset);

	/*avail_size*/
	offset = dissect_rpc_uint64(tvb, tree, hf_ndmp_fs_avail_size,
			offset);

	/*total_inodes*/
	offset = dissect_rpc_uint64(tvb, tree, hf_ndmp_fs_total_inodes,
			offset);

	/*used_inodes*/
	offset = dissect_rpc_uint64(tvb, tree, hf_ndmp_fs_used_inodes,
			offset);

	/* env */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_fs_env, hf_ndmp_fs_env);

	/* status */
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_fs_status, offset, NULL);

	return offset;
}

static int
dissect_get_fs_info_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq)
{
	/* error */
	offset=dissect_error(tvb, offset, pinfo, tree, seq);

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
dissect_tape_attr(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		proto_tree *parent_tree)
{
	static const int * attribute_flags[] = {
		&hf_ndmp_tape_attr_unload,
		&hf_ndmp_tape_attr_rewind,
		NULL
		};

	proto_tree_add_bitmask(parent_tree, tvb, offset, hf_ndmp_tape_attr, ett_ndmp_tape_attr, attribute_flags, ENC_NA);

	offset+=4;
	return offset;
}

static int
dissect_tape_capability(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		proto_tree *tree, void* data _U_)
{
	/* name */
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_tape_capability_name, offset, NULL);

	/* value */
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_tape_capability_value, offset, NULL);

	return offset;
}

static int
dissect_tape_dev_cap(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	/* device */
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_tape_device, offset, NULL);

	/* tape attributes */
	offset = dissect_tape_attr(tvb, offset, pinfo, tree);

	/* capability */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_tape_capability, hf_ndmp_tape_capability);

	return offset;
}

static int
dissect_tape_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	/* model */
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_tape_model, offset, NULL);

	/* device capabilites */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_tape_dev_cap, hf_ndmp_tape_dev_cap);

	return offset;
}

static int
dissect_get_tape_info_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq)
{
	/* error */
	offset=dissect_error(tvb, offset, pinfo, tree, seq);

	/* tape */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_tape_info, hf_ndmp_tape_info);

	return offset;
}

static int
dissect_scsi_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	/* model */
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_scsi_model, offset, NULL);

	/* device capabilites */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_tape_dev_cap, hf_ndmp_tape_dev_cap);

	return offset;
}

static int
dissect_get_scsi_info_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq)
{
	/* error */
	offset=dissect_error(tvb, offset, pinfo, tree, seq);

	/* scsi */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_scsi_info, hf_ndmp_scsi_info);

	return offset;
}

static int
dissect_get_server_info_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq)
{
	/* error */
	offset=dissect_error(tvb, offset, pinfo, tree, seq);

	/* vendor */
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_server_vendor, offset, NULL);

	/* product */
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_server_product, offset, NULL);

	/* revision */
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_server_revision, offset, NULL);


	/* server */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_auth_type, hf_ndmp_auth_types);

	return offset;
}

static int
dissect_ext_version(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		proto_tree *tree, void* data _U_) {

	/* extension version */
	proto_tree_add_item(tree, hf_ndmp_ext_version, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	return offset;
}


static int
dissect_class_list(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, void* data _U_) {

	/* class id */
	proto_tree_add_item(tree, hf_ndmp_ex_class_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* ext version */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_ext_version, hf_ndmp_ext_version_list);

	return offset;
}

static int
dissect_get_ext_list_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq)
{
	/* error */
	offset=dissect_error(tvb, offset, pinfo, tree, seq);

	/* Class list */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_class_list, hf_ndmp_class_list);

	return offset;
}


static int
dissect_class_version(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		proto_tree *tree, void* data _U_) {

	/* class id */
	proto_tree_add_item(tree, hf_ndmp_ex_class_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* ext version */
	proto_tree_add_item(tree, hf_ndmp_ex_class_version, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	return offset;
}

static int
dissect_set_ext_list_request(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq _U_)
{
	/* class version */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_class_version, hf_ndmp_class_version);

	return offset;
}


static int
dissect_set_ext_list_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq _U_)
{
	/* error */
	offset=dissect_error(tvb, offset, pinfo, tree, seq);

	return offset;
}

static int
dissect_scsi_open_request(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq _U_)
{
	/* device */
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_scsi_device, offset, NULL);


	if(!pinfo->fd->flags.visited){
		/* new scsi device addressed, create a new itl structure */
		get_itl_nexus(pinfo, TRUE);
	}

	return offset;
}

static int
dissect_scsi_get_state_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq)
{
	/* error */
	offset=dissect_error(tvb, offset, pinfo, tree, seq);

	/* controller */
	proto_tree_add_item(tree, hf_ndmp_scsi_controller, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* id */
	proto_tree_add_item(tree, hf_ndmp_scsi_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* lun */
	proto_tree_add_item(tree, hf_ndmp_scsi_lun, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	return offset;
}

static int
dissect_scsi_set_state_request(tvbuff_t *tvb, int offset,
		packet_info *pinfo _U_, proto_tree *tree, guint32 seq _U_)
{
	/* device */
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_scsi_device, offset, NULL);

	/* controller */
	proto_tree_add_item(tree, hf_ndmp_scsi_controller, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* id */
	proto_tree_add_item(tree, hf_ndmp_scsi_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* lun */
	proto_tree_add_item(tree, hf_ndmp_scsi_lun, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	return offset;
}

static int
dissect_execute_cdb_flags(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		proto_tree *parent_tree)
{
	static const int * cdb_flags[] = {
		&hf_ndmp_execute_cdb_flags_data_in,
		&hf_ndmp_execute_cdb_flags_data_out,
		NULL
		};

	proto_tree_add_bitmask(parent_tree, tvb, offset, hf_ndmp_execute_cdb_flags, ett_ndmp_execute_cdb_flags, cdb_flags, ENC_NA);

	offset += 4;
	return offset;
}

static int
dissect_execute_cdb_cdb(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *parent_tree, gint devtype)
{
	proto_tree* tree;
	guint32 cdb_len;
	guint32 cdb_len_full;

	cdb_len = tvb_get_ntohl(tvb, offset);
	cdb_len_full = rpc_roundup(cdb_len);

	tree = proto_tree_add_subtree(parent_tree, tvb, offset,
			4+cdb_len_full, ett_ndmp_execute_cdb_cdb, NULL, "CDB");

	proto_tree_add_uint(tree, hf_ndmp_execute_cdb_cdb_len, tvb, offset, 4,
			cdb_len);
	offset += 4;

	if (cdb_len != 0) {
		tvbuff_t *cdb_tvb;
		int tvb_len, tvb_rlen;

		tvb_len=tvb_captured_length_remaining(tvb, offset);
		if(tvb_len>16)
			tvb_len=16;
		tvb_rlen=tvb_reported_length_remaining(tvb, offset);
		if(tvb_rlen>16)
			tvb_rlen=16;
		cdb_tvb=tvb_new_subset(tvb, offset, tvb_len, tvb_rlen);

		if(ndmp_conv_data->task && !ndmp_conv_data->task->itlq){
			ndmp_conv_data->task->itlq=wmem_new(wmem_file_scope(), itlq_nexus_t);
			ndmp_conv_data->task->itlq->lun=0xffff;
			ndmp_conv_data->task->itlq->first_exchange_frame=pinfo->num;
			ndmp_conv_data->task->itlq->last_exchange_frame=0;
			ndmp_conv_data->task->itlq->scsi_opcode=0xffff;
			ndmp_conv_data->task->itlq->task_flags=0;
			ndmp_conv_data->task->itlq->data_length=0;
			ndmp_conv_data->task->itlq->bidir_data_length=0;
			ndmp_conv_data->task->itlq->flags=0;
			ndmp_conv_data->task->itlq->alloc_len=0;
			ndmp_conv_data->task->itlq->fc_time=pinfo->abs_ts;
			ndmp_conv_data->task->itlq->extra_data=NULL;
		}
		if(ndmp_conv_data->task && ndmp_conv_data->task->itlq){
			dissect_scsi_cdb(cdb_tvb, pinfo, top_tree, devtype, ndmp_conv_data->task->itlq, get_itl_nexus(pinfo, FALSE));
		}
		offset += cdb_len_full;
	}

	return offset;
}


static int
dissect_execute_cdb_payload(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree,
		const char *name, int hf_len, gboolean isreq)
{
	proto_tree* tree;
	guint32 payload_len;
	guint32 payload_len_full;

	payload_len = tvb_get_ntohl(tvb, offset);
	payload_len_full = rpc_roundup(payload_len);

	tree = proto_tree_add_subtree(parent_tree, tvb, offset,
				4+payload_len_full, ett_ndmp_execute_cdb_payload, NULL, name);

	proto_tree_add_uint(tree, hf_len, tvb, offset, 4, payload_len);
	offset += 4;

	if ((int) payload_len > 0) {
		tvbuff_t *data_tvb;
		int tvb_len, tvb_rlen;

		tvb_len=tvb_captured_length_remaining(tvb, offset);
		if(tvb_len>(int)payload_len)
			tvb_len=payload_len;
		tvb_rlen=tvb_reported_length_remaining(tvb, offset);
		if(tvb_rlen>(int)payload_len)
			tvb_rlen=payload_len;
		data_tvb=tvb_new_subset(tvb, offset, tvb_len, tvb_rlen);

		if(ndmp_conv_data->task && ndmp_conv_data->task->itlq){
			/* ndmp conceptually always send both read and write
			 * data and always a full nonfragmented pdu
			 */
			ndmp_conv_data->task->itlq->task_flags=SCSI_DATA_READ|SCSI_DATA_WRITE;
			ndmp_conv_data->task->itlq->data_length=payload_len;
			ndmp_conv_data->task->itlq->bidir_data_length=payload_len;
			dissect_scsi_payload(data_tvb, pinfo, top_tree, isreq,
				   ndmp_conv_data->task->itlq,
				   get_itl_nexus(pinfo, FALSE),
				   0);
		}
		offset += payload_len_full;
	}

	return offset;
}

/*
 * XXX - we assume that NDMP_SCSI_EXECUTE_CDB requests only go to SCSI Media
 * Changer devices and NDMP_TAPE_EXECUTE_CDB only go to SCSI Sequential
 * Access devices.
 *
 * If that's not the case, we'll have to use the SCSI dissector's mechanisms
 * for saving inquiry data for devices, and use inquiry data when available.
 * Unfortunately, that means we need to save the name of the device, and
 * use it as a device identifier; as the name isn't available in the
 * NDMP_SCSI_EXECUTE_CDB or NDMP_TAPE_EXECUTE_CDB messages, that means
 * we need to remember the currently-opened "SCSI" and "TAPE" devices
 * from NDMP_SCSI_OPEN and NDMP_TAPE_OPEN, and attach to all frames
 * that are the ones that trigger the dissection of NDMP_SCSI_EXECUTE_CDB
 * or NDMP_TAPE_EXECUTE_CDB requests pointers to those names.
 */
static int
dissect_execute_cdb_request(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq _U_, gint devtype)
{
	/* flags */
	offset = dissect_execute_cdb_flags(tvb, offset, pinfo, tree);

	/* timeout */
	proto_tree_add_item(tree, hf_ndmp_execute_cdb_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* datain_len */
	proto_tree_add_item(tree, hf_ndmp_execute_cdb_datain_len, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* CDB */
	offset = dissect_execute_cdb_cdb(tvb, offset, pinfo, tree, devtype);

	/* dataout */
	offset = dissect_execute_cdb_payload(tvb, offset, pinfo, tree,
	    "Data out", hf_ndmp_execute_cdb_dataout_len, TRUE);

	return offset;
}

static int
dissect_execute_cdb_request_mc(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq)
{
	return dissect_execute_cdb_request(tvb, offset, pinfo, tree, seq,
		SCSI_DEV_SMC);
}

static int
dissect_execute_cdb_request_tape(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq)
{
	return dissect_execute_cdb_request(tvb, offset, pinfo, tree, seq,
		SCSI_DEV_SSC);
}

static int
dissect_execute_cdb_sns(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_tree* tree;
	guint32 sns_len;
	guint32 sns_len_full;

	sns_len = tvb_get_ntohl(tvb, offset);
	sns_len_full = rpc_roundup(sns_len);

	tree = proto_tree_add_subtree(parent_tree, tvb, offset,
				4+sns_len_full, ett_ndmp_execute_cdb_sns, NULL, "Sense data");

	proto_tree_add_uint(tree, hf_ndmp_execute_cdb_sns_len, tvb, offset, 4,
			sns_len);
	offset += 4;

	if (sns_len != 0) {
		if(ndmp_conv_data->task && ndmp_conv_data->task->itlq){
			dissect_scsi_snsinfo(tvb, pinfo, top_tree, offset, sns_len, ndmp_conv_data->task->itlq, get_itl_nexus(pinfo, FALSE));
		}
		offset += sns_len_full;
	}

	return offset;
}

static int
dissect_execute_cdb_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq)
{
	guint32 status;

	/* error */
	offset=dissect_error(tvb, offset, pinfo, tree, seq);

	/* status */
	proto_tree_add_item(tree, hf_ndmp_execute_cdb_status, tvb, offset, 4, ENC_BIG_ENDIAN);
	status=tvb_get_ntohl(tvb, offset);
	if(ndmp_conv_data->task && ndmp_conv_data->task->itlq){
		dissect_scsi_rsp(tvb, pinfo, top_tree, ndmp_conv_data->task->itlq, get_itl_nexus(pinfo, FALSE), (guint8)status);
	}
	offset += 4;


	/* dataout_len */
	proto_tree_add_item(tree, hf_ndmp_execute_cdb_dataout_len, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* datain */
	offset = dissect_execute_cdb_payload(tvb, offset, pinfo, tree,
	    "Data in", hf_ndmp_execute_cdb_datain_len, FALSE);

	/* ext_sense */
	offset = dissect_execute_cdb_sns(tvb, offset, pinfo, tree);

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
dissect_tape_open_request(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq _U_)
{
	/* device */
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_tape_device, offset, NULL);

	/* open mode */
	proto_tree_add_item(tree, hf_ndmp_tape_open_mode, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	if(!pinfo->fd->flags.visited){
		/* new scsi device addressed, create a new itl structure */
		get_itl_nexus(pinfo, TRUE);
	}

	return offset;
}


static const true_false_string tfs_ndmp_tape_invalid_file_num = {
	"File num is INVALID",
	"File num is VALID"
};
static const true_false_string tfs_ndmp_tape_invalid_soft_errors = {
	"Soft errors is INVALID",
	"Soft errors is VALID"
};
static const true_false_string tfs_ndmp_tape_invalid_block_size = {
	"Block size is INVALID",
	"Block size is VALID"
};
static const true_false_string tfs_ndmp_tape_invalid_block_no = {
	"Block no is INVALID",
	"Block no is VALID"
};
static const true_false_string tfs_ndmp_tape_invalid_total_space = {
	"Total space is INVALID",
	"Total space is VALID"
};
static const true_false_string tfs_ndmp_tape_invalid_space_remain = {
	"Space remaining is INVALID",
	"Space remaining is VALID"
};
static const true_false_string tfs_ndmp_tape_invalid_partition = {
	"Partition is INVALID",
	"Partition is VALID"
};
static int
dissect_tape_invalid(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		proto_tree *parent_tree)
{
	static const int * invalid_tapes[] = {
		&hf_ndmp_tape_invalid_partition,
		&hf_ndmp_tape_invalid_space_remain,
		&hf_ndmp_tape_invalid_total_space,
		&hf_ndmp_tape_invalid_block_no,
		&hf_ndmp_tape_invalid_block_size,
		&hf_ndmp_tape_invalid_soft_errors,
		&hf_ndmp_tape_invalid_file_num,
		NULL
		};

	proto_tree_add_bitmask(parent_tree, tvb, offset, hf_ndmp_tape_invalid, ett_ndmp_tape_invalid, invalid_tapes, ENC_NA);

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
dissect_tape_flags(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		proto_tree *parent_tree)
{
	static const int * tape_flags[] = {
		&hf_ndmp_tape_flags_unload,
		&hf_ndmp_tape_flags_error,
		&hf_ndmp_tape_flags_write_protect,
		&hf_ndmp_tape_flags_no_rewind,
		NULL
		};

	proto_tree_add_bitmask(parent_tree, tvb, offset, hf_ndmp_tape_flags, ett_ndmp_tape_flags, tape_flags, ENC_NA);

	offset+=4;
	return offset;
}

static int
dissect_tape_get_state_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq)
{
	/* invalid bits */
	offset=dissect_tape_invalid(tvb, offset, pinfo, tree);

	/* error */
	offset=dissect_error(tvb, offset, pinfo, tree, seq);

	/* flags */
	offset=dissect_tape_flags(tvb, offset, pinfo, tree);

	/* file_num */
	proto_tree_add_item(tree, hf_ndmp_tape_file_num, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* soft_errors */
	proto_tree_add_item(tree, hf_ndmp_tape_soft_errors, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* block_size */
	proto_tree_add_item(tree, hf_ndmp_tape_block_size, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* block_no */
	proto_tree_add_item(tree, hf_ndmp_tape_block_no, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* total_space */
	offset = dissect_rpc_uint64(tvb, tree,hf_ndmp_tape_total_space,
			offset);

	/* space_remain */
	offset = dissect_rpc_uint64(tvb, tree,hf_ndmp_tape_space_remain,
			offset);

	/* NDMP Version 4 does not have a partition field here, so just return now. */
	if (get_ndmp_protocol_version() == NDMP_PROTOCOL_V4)
		return offset;

	/* partition */
	proto_tree_add_item(tree, hf_ndmp_tape_partition, tvb, offset, 4, ENC_BIG_ENDIAN);
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
dissect_tape_mtio_request(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		proto_tree *tree, guint32 seq _U_)
{
	/* op */
	proto_tree_add_item(tree, hf_ndmp_tape_mtio_op, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* count */
	proto_tree_add_item(tree, hf_ndmp_count, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	return offset;
}

static int
dissect_tape_mtio_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq)
{
	/* error */
	offset=dissect_error(tvb, offset, pinfo, tree, seq);

	/* resid count */
	proto_tree_add_item(tree, hf_ndmp_resid_count, tvb, offset, 4, ENC_BIG_ENDIAN);
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
dissect_tcp_env(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	/* name */
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_tcp_env_name, offset, NULL);

	/* value */
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_tcp_env_value, offset, NULL);

	return offset;
}


static int
dissect_ndmp_v4_tcp_addr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	/* IP addr */
	proto_tree_add_item(tree, hf_ndmp_addr_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset+=4;

	/* TCP port */
	proto_tree_add_item(tree, hf_ndmp_addr_tcp, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset+=4;

	/* addr_env */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_tcp_env, hf_ndmp_tcp_default_env);

	return offset;
}

static int
dissect_ndmp_addr(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		proto_tree *parent_tree)
{
	proto_tree* tree;
	guint32 type;

	type=tvb_get_ntohl(tvb, offset);
	tree = proto_tree_add_subtree_format(parent_tree, tvb, offset, 4, ett_ndmp_addr, NULL,
				"Type: %s ", val_to_str(type, addr_type_vals,"Unknown addr type (0x%02x)") );

	/*address type*/
	proto_tree_add_item(tree, hf_ndmp_addr_type, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;


	switch(type){
	case NDMP_ADDR_LOCAL:
		break;
	case NDMP_ADDR_TCP:
		/* this became an array in version 4 and beyond */
		if(get_ndmp_protocol_version()<NDMP_PROTOCOL_V4){
			/* IP addr */
			proto_tree_add_item(tree, hf_ndmp_addr_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset+=4;

			/* TCP port */
			proto_tree_add_item(tree, hf_ndmp_addr_tcp, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset+=4;
		} else {
			offset = dissect_rpc_array(tvb, pinfo, tree, offset,
				dissect_ndmp_v4_tcp_addr, hf_ndmp_tcp_addr_list);

		}

		break;
	case NDMP_ADDR_FC:
		/* FCAL loop id */
		proto_tree_add_item(tree, hf_ndmp_addr_fcal_loop_id, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset+=4;

		break;
	case NDMP_ADDR_IPC:
		/* IPC address */
		offset = dissect_rpc_data(tvb, tree, hf_ndmp_addr_ipc, offset);
		break;
	}

	return offset;
}

static int
dissect_data_connect_msg(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq _U_)
{
	/* ndmp addr */
	offset=dissect_ndmp_addr(tvb, offset, pinfo, tree);
	return offset;
}


static int
dissect_mover_get_state_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq)
{
	/* error */
	offset=dissect_error(tvb, offset, pinfo, tree, seq);

	/* mode is only present in version 4 and beyond */
	if(get_ndmp_protocol_version()>=NDMP_PROTOCOL_V4){
		proto_tree_add_item(tree, hf_ndmp_mover_mode, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}

	/* mover state */
	proto_tree_add_item(tree, hf_ndmp_mover_state, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* mover pause */
	proto_tree_add_item(tree, hf_ndmp_mover_pause, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* halt */
	proto_tree_add_item(tree, hf_ndmp_halt, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* record size */
	proto_tree_add_item(tree, hf_ndmp_record_size, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* record num */
	proto_tree_add_item(tree, hf_ndmp_record_num, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* data written */
	proto_tree_add_item(tree, hf_ndmp_data_written, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	/* seek position */
	proto_tree_add_item(tree, hf_ndmp_seek_position, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	/* bytes left to read */
	proto_tree_add_item(tree, hf_ndmp_bytes_left_to_read, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	/* window offset */
	proto_tree_add_item(tree, hf_ndmp_window_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	/* window length */
	proto_tree_add_item(tree, hf_ndmp_window_length, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	/* this is where v2 ends */
	if(get_ndmp_protocol_version()==NDMP_PROTOCOL_V2){
		return offset;
	}


	/* ndmp addr */
	offset=dissect_ndmp_addr(tvb, offset, pinfo, tree);

	return offset;
}

#define NDMP_MOVER_MODE_READ		0
#define NDMP_MOVER_MODE_WRITE		1
#define NDMP_MOVER_MODE_NOACTION	2
static const value_string mover_mode_vals[] = {
	{NDMP_MOVER_MODE_READ,		"MOVER_MODE_READ"},
	{NDMP_MOVER_MODE_WRITE,		"MOVER_MODE_WRITE"},
	{NDMP_MOVER_MODE_NOACTION,	"MOVER_MODE_NOACTION"},
	{0, NULL}
};

static int
dissect_mover_listen_request(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		proto_tree *tree, guint32 seq _U_)
{
	/* mode */
	proto_tree_add_item(tree, hf_ndmp_mover_mode, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/*address type*/
	proto_tree_add_item(tree, hf_ndmp_addr_type, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	return offset;
}

static int
dissect_mover_listen_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq)
{
	/* error */
	offset=dissect_error(tvb, offset, pinfo, tree, seq);

	/* ndmp addr */
	offset=dissect_ndmp_addr(tvb, offset, pinfo, tree);

	return offset;
}

static int
dissect_mover_set_window_request(tvbuff_t *tvb, int offset,
		packet_info *pinfo _U_, proto_tree *tree, guint32 seq _U_)
{
	/* window offset */
	proto_tree_add_item(tree, hf_ndmp_window_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	/* window length */
	proto_tree_add_item(tree, hf_ndmp_window_length, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	return offset;
}

static int
dissect_mover_set_record_size_request(tvbuff_t *tvb, int offset,
		packet_info *pinfo _U_, proto_tree *tree, guint32 seq _U_)
{
	/* record size */
	proto_tree_add_item(tree, hf_ndmp_record_size, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	return offset;
}

static int
dissect_mover_connect_request(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq _U_)
{
	/* mode */
	proto_tree_add_item(tree, hf_ndmp_mover_mode, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* ndmp addr */
	offset=dissect_ndmp_addr(tvb, offset, pinfo, tree);

	return offset;
}

static int
dissect_log_file_request(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq)
{
	/* file */
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_file_name, offset, NULL);

	/* error */
	offset=dissect_error(tvb, offset, pinfo, tree, seq);

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
dissect_log_message_request(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		proto_tree *tree, guint32 seq _U_)
{
	/* type */
	proto_tree_add_item(tree, hf_ndmp_log_type, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* message id */
	proto_tree_add_item(tree, hf_ndmp_log_message_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* message */
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_log_message, offset, NULL);

	return offset;
}

static int
dissect_notify_data_halted_request(tvbuff_t *tvb, int offset,
		packet_info *pinfo _U_, proto_tree *tree, guint32 seq _U_)
{
	/* halt */
	proto_tree_add_item(tree, hf_ndmp_halt, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	switch(get_ndmp_protocol_version()){
	case NDMP_PROTOCOL_V2:
	case NDMP_PROTOCOL_V3:
		/* reason : only in version 2, 3 */
		offset = dissect_rpc_string(tvb, tree,
				hf_ndmp_halt_reason, offset, NULL);
		break;
	}

	return offset;
}

static int
dissect_notify_mover_halted_request(tvbuff_t *tvb, int offset,
		packet_info *pinfo _U_, proto_tree *tree, guint32 seq _U_)
{
	/* halt */
	proto_tree_add_item(tree, hf_ndmp_halt, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	switch(get_ndmp_protocol_version()){
	case NDMP_PROTOCOL_V2:
	case NDMP_PROTOCOL_V3:
		/* reason : only in version 2, 3 */
		offset = dissect_rpc_string(tvb, tree,
				hf_ndmp_halt_reason, offset, NULL);
		break;
	}

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
dissect_notify_connected_request(tvbuff_t *tvb, int offset,
		packet_info *pinfo _U_, proto_tree *tree, guint32 seq _U_)
{
	/* connected */
	proto_tree_add_item(tree, hf_ndmp_connected, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* version number */
	proto_tree_add_item(tree, hf_ndmp_version, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* reason */
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_connected_reason, offset, NULL);

	return offset;
}


static int
dissect_notify_mover_paused_request(tvbuff_t *tvb, int offset,
		packet_info *pinfo _U_, proto_tree *tree, guint32 seq _U_)
{
	/* mover pause */
	proto_tree_add_item(tree, hf_ndmp_mover_pause, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* seek position */
	proto_tree_add_item(tree, hf_ndmp_seek_position, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	return offset;
}

static int
dissect_auth_data(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		proto_tree *tree)
{
	guint type;

	type=tvb_get_ntohl(tvb,offset);

	/* auth type */
	proto_tree_add_item(tree, hf_ndmp_auth_type, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	switch(type){
	case NDMP_AUTH_NONE:
		break;
	case NDMP_AUTH_TEXT:
		/* auth id */
		offset = dissect_rpc_string(tvb, tree,
				hf_ndmp_auth_id, offset, NULL);

		/* auth password */
		offset = dissect_rpc_string(tvb, tree,
				hf_ndmp_auth_password, offset, NULL);


		break;
	case NDMP_AUTH_MD5:
		/* auth id */
		offset = dissect_rpc_string(tvb, tree,
				hf_ndmp_auth_id, offset, NULL);

		/* digest */
		proto_tree_add_item(tree, hf_ndmp_auth_digest,
			tvb, offset, 16, ENC_NA);
		offset+=16;
	}

	return offset;
}

static int
dissect_connect_client_auth_request(tvbuff_t *tvb, int offset,
		packet_info *pinfo, proto_tree *tree, guint32 seq _U_)
{
	return dissect_auth_data(tvb, offset, pinfo, tree);
}

static int
dissect_connect_server_auth_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq)
{
	/* error */
	offset=dissect_error(tvb, offset, pinfo, tree, seq);

	/* auth data */
	offset = dissect_auth_data(tvb, offset, pinfo, tree);

	return offset;
}

static int
dissect_tape_write_request(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		proto_tree *tree, guint32 seq _U_)
{
	/* data */
	offset = dissect_rpc_data(tvb, tree, hf_ndmp_data, offset);

	return offset;
}

static int
dissect_tape_write_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq)
{
	/* error */
	offset=dissect_error(tvb, offset, pinfo, tree, seq);

	/* count */
	proto_tree_add_item(tree, hf_ndmp_count, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	return offset;
}

static int
dissect_tape_read_request(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		proto_tree *tree, guint32 seq _U_)
{
	/* count */
	proto_tree_add_item(tree, hf_ndmp_count, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	return offset;
}

static int
dissect_tape_read_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq)
{
	/* error */
	offset=dissect_error(tvb, offset, pinfo, tree, seq);

	/* data */
	offset = dissect_rpc_data(tvb, tree, hf_ndmp_data, offset);

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
dissect_file_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
	proto_item* item;
	proto_tree* tree;
	int old_offset=offset;
	guint32 type;
	const char *name;

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1,
				ett_ndmp_file_name, &item, "File");

	/* file type */
	type=tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(tree, hf_ndmp_file_fs_type, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	switch(type){
	case NDMP_FS_UNIX:
		/* file */
		offset = dissect_rpc_string(tvb, tree,
				hf_ndmp_file_name, offset, &name);
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);
		break;
	case NDMP_FS_NT:
		/* nt file */
		offset = dissect_rpc_string(tvb, tree,
				hf_ndmp_nt_file_name, offset, &name);
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);

		/* dos file */
		offset = dissect_rpc_string(tvb, tree,
				hf_ndmp_dos_file_name, offset, NULL);
		break;
	default:
		/* file */
		offset = dissect_rpc_string(tvb, tree,
				hf_ndmp_file_name, offset, &name);
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);
	}

	col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
			val_to_str_const(type, file_fs_type_vals, "Unknown type") );

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
dissect_file_invalids(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		proto_tree *parent_tree)
{
	static const int * invalid_files[] = {
		&hf_ndmp_file_invalid_group,
		&hf_ndmp_file_invalid_ctime,
		&hf_ndmp_file_invalid_atime,
		NULL
		};

	proto_tree_add_bitmask(parent_tree, tvb, offset, hf_ndmp_file_invalid, ett_ndmp_file_invalids, invalid_files, ENC_NA);

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
dissect_file_stats(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
	proto_item* item;
	proto_tree* tree;
	int old_offset=offset;
	nstime_t ns;

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1,
				ett_ndmp_file_stats, &item, "Stats:");

	/* invalids */
	offset = dissect_file_invalids(tvb, offset, pinfo, tree);

	/* file fs type */
	proto_tree_add_item(tree, hf_ndmp_file_fs_type, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* file type */
	proto_tree_add_item(tree, hf_ndmp_file_type, tvb, offset, 4, ENC_BIG_ENDIAN);
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
	proto_tree_add_item(tree, hf_ndmp_file_owner, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* group */
	proto_tree_add_item(tree, hf_ndmp_file_group, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/*XXX here we should do proper dissection of mode for unix or
	      fattr for nt, call appropriate functions in nfs/smb*/
	/* fattr */
	proto_tree_add_item(tree, hf_ndmp_file_fattr, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/*file size*/
	offset = dissect_rpc_uint64(tvb, tree, hf_ndmp_file_size,
			offset);

	/* links */
	proto_tree_add_item(tree, hf_ndmp_file_links, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
dissect_ndmp_file(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
	proto_item* item;
	proto_tree* tree;
	int old_offset=offset;

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1,
				ett_ndmp_file, &item, "File:");

	/* file names */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_file_name, hf_ndmp_file_names);

	/* file stats */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_file_stats, hf_ndmp_file_stats);

	/* node */
	proto_tree_add_item(tree, hf_ndmp_file_node, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	/* fh_info */
	proto_tree_add_item(tree, hf_ndmp_file_fh_info, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
dissect_fh_add_file_request(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq _U_)
{
	/* files */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_ndmp_file, hf_ndmp_files);

	return offset;
}

static int
dissect_dir(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	/* file names */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_file_name, hf_ndmp_file_names);

	/* node */
	proto_tree_add_item(tree, hf_ndmp_file_node, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	/* parent */
	proto_tree_add_item(tree, hf_ndmp_file_parent, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	return offset;
}

static int
dissect_fh_add_dir_request(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq _U_)
{
	/* dirs */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_dir, hf_ndmp_dirs);

	return offset;
}

static int
dissect_node(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	/* file stats */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_file_stats, hf_ndmp_file_stats);

	/* node */
	proto_tree_add_item(tree, hf_ndmp_file_node, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	/* fh_info */
	proto_tree_add_item(tree, hf_ndmp_file_fh_info, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	return offset;
}


static int
dissect_fh_add_node_request(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq _U_)
{
	/* node */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_node, hf_ndmp_nodes);

	return offset;
}

static int
dissect_data_start_backup_request(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq _U_)
{
	/*butype name*/
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_butype_name, offset, NULL);

	/* default env */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_default_env, hf_ndmp_butype_default_env);

	return offset;
}

static int
dissect_nlist(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		proto_tree *tree, void* data _U_)
{
	/*original path*/
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_bu_original_path, offset, NULL);

	/*destination dir*/
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_bu_destination_dir, offset, NULL);

	if(get_ndmp_protocol_version()==NDMP_PROTOCOL_V2){
		/* just 2 reserved bytes (4 with padding) */
		offset += 4;
	} else {
		/*new name*/
		offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_bu_new_name, offset, NULL);

		/*other name*/
		offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_bu_other_name, offset, NULL);

		/* node */
		proto_tree_add_item(tree, hf_ndmp_file_node, tvb, offset, 8, ENC_BIG_ENDIAN);
		offset += 8;
	}

	/* fh_info */
	proto_tree_add_item(tree, hf_ndmp_file_fh_info, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	return offset;
}


static int
dissect_data_start_recover_request(tvbuff_t *tvb, int offset,
		packet_info *pinfo, proto_tree *tree, guint32 seq _U_)
{
	if(get_ndmp_protocol_version()==NDMP_PROTOCOL_V2){
		/* ndmp addr */
		offset=dissect_ndmp_addr(tvb, offset, pinfo, tree);
	}

	/* default env */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_default_env, hf_ndmp_butype_default_env);

	/* nlist */
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_nlist, hf_ndmp_nlist);

	/*butype name*/
	offset = dissect_rpc_string(tvb, tree,
			hf_ndmp_butype_name, offset, NULL);

	return offset;
}

static int
dissect_data_get_env_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq)
{
	/* error */
	offset=dissect_error(tvb, offset, pinfo, tree, seq);

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
dissect_state_invalids(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		proto_tree *parent_tree)
{
	static const int * invalid_states[] = {
		&hf_ndmp_state_invalid_etr,
		&hf_ndmp_state_invalid_ebr,
		NULL
		};

	proto_tree_add_bitmask(parent_tree, tvb, offset, hf_ndmp_state_invalid, ett_ndmp_state_invalids, invalid_states, ENC_NA);

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
dissect_data_get_state_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq)
{
	nstime_t ns;

	/* invalids */
	offset = dissect_state_invalids(tvb, offset, pinfo, tree);

	/* error */
	offset=dissect_error(tvb, offset, pinfo, tree, seq);

	/* operation */
	proto_tree_add_item(tree, hf_ndmp_bu_operation, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* state */
	proto_tree_add_item(tree, hf_ndmp_data_state, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* halted reason */
	proto_tree_add_item(tree, hf_ndmp_data_halted, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/*bytes processed*/
	offset = dissect_rpc_uint64(tvb, tree, hf_ndmp_data_bytes_processed,
			offset);

	/*est bytes remain*/
	offset = dissect_rpc_uint64(tvb, tree, hf_ndmp_data_est_bytes_remain,
			offset);

	/* est time remain */
	ns.secs=tvb_get_ntohl(tvb, offset);
	ns.nsecs=0;
	proto_tree_add_time(tree, hf_ndmp_data_est_time_remain, tvb, offset, 4, &ns);
	offset += 4;

	/* ndmp addr */
	offset=dissect_ndmp_addr(tvb, offset, pinfo, tree);

	/* window offset */
	proto_tree_add_item(tree, hf_ndmp_window_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	/* window length */
	proto_tree_add_item(tree, hf_ndmp_window_length, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	return offset;
}

typedef struct _ndmp_command {
	guint32 cmd;
	int (*request) (tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq);
	int (*response)(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, guint32 seq);
} ndmp_command;

static const ndmp_command ndmp_commands[] = {
	{NDMP_CONFIG_GET_HOST_INFO,
	 	NULL, dissect_ndmp_get_host_info_reply},
	{NDMP_CONFIG_GET_CONNECTION_TYPE,
		NULL, dissect_ndmp_config_get_connection_type_reply},
	{NDMP_CONFIG_GET_AUTH_ATTR,
		dissect_get_auth_type_request, dissect_ndmp_config_get_auth_attr_reply},
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
	{NDMP_CONFIG_GET_EXT_LIST,
		NULL, dissect_get_ext_list_reply},
	{NDMP_CONFIG_SET_EXT_LIST,
		dissect_set_ext_list_request, dissect_set_ext_list_reply},
	{NDMP_SCSI_OPEN,
		dissect_scsi_open_request, dissect_error},
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
	{NDMP_SCSI_EXECUTE_CDB,
		dissect_execute_cdb_request_mc, dissect_execute_cdb_reply},
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
	{NDMP_TAPE_EXECUTE_CDB,
		dissect_execute_cdb_request_tape, dissect_execute_cdb_reply},
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
		dissect_ndmp_addr_msg, dissect_mover_listen_reply},
	{NDMP_DATA_CONNECT,
		dissect_data_connect_msg, dissect_error},
	{NDMP_NOTIFY_DATA_HALTED,
		dissect_notify_data_halted_request, NULL},
	{NDMP_NOTIFY_CONNECTED,
		dissect_notify_connected_request, NULL},
	{NDMP_NOTIFY_MOVER_HALTED,
		dissect_notify_mover_halted_request, NULL},
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
		dissect_connect_client_auth_request, dissect_error},
	{NDMP_CONNECT_CLOSE,
		NULL,NULL},
	{NDMP_CONNECT_SERVER_AUTH,
		dissect_auth_attr_msg, dissect_connect_server_auth_reply},
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
dissect_ndmp_header(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, struct ndmp_header *nh, proto_item** msg_item)
{
	proto_item* item;
	proto_tree* tree;
	nstime_t ns;

	item = proto_tree_add_item(parent_tree, hf_ndmp_header, tvb,
				offset, 24, ENC_NA);
	tree = proto_item_add_subtree(item, ett_ndmp_header);

	/* sequence number */
	proto_tree_add_uint(tree, hf_ndmp_sequence, tvb, offset, 4, nh->seq);
	offset += 4;

	/* timestamp */
	ns.secs=nh->timestamp;
	ns.nsecs=0;
	proto_tree_add_time(tree, hf_ndmp_timestamp, tvb, offset, 4, &ns);
	offset += 4;

	/* Message Type */
	proto_tree_add_uint(tree, hf_ndmp_msgtype, tvb, offset, 4, nh->type);
	offset += 4;

	/* Message */
	*msg_item = proto_tree_add_uint(tree, hf_ndmp_msg, tvb, offset, 4, nh->msg);
	offset += 4;

	/* Reply sequence number */
	proto_tree_add_uint(tree, hf_ndmp_reply_sequence, tvb, offset, 4, nh->rep_seq);
	offset += 4;

	/* error */
	offset=dissect_error(tvb, offset, pinfo, tree, nh->seq);

	col_append_fstr(pinfo->cinfo, COL_INFO, "%s %s ",
			val_to_str(nh->msg, msg_vals, "Unknown Message (0x%02x)"),
			val_to_str(nh->type, msg_type_vals, "Unknown Type (0x%02x)")
			);

	return offset;
}


static int
dissect_ndmp_cmd(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, struct ndmp_header *nh)
{
	int i;
	proto_tree *cmd_tree=NULL;
	proto_item *msg_item=NULL;

	offset=dissect_ndmp_header(tvb, offset, pinfo, tree, nh, &msg_item);

	for(i=0;ndmp_commands[i].cmd!=0;i++){
		if(ndmp_commands[i].cmd==nh->msg){
			break;
		}
	}


	if(ndmp_commands[i].cmd==0){
		/* we do not know this message */
		expert_add_info(pinfo, msg_item, &ei_ndmp_msg);
		offset+=tvb_captured_length_remaining(tvb, offset);
		return offset;
	}

	if (tvb_reported_length_remaining(tvb, offset) > 0) {
		if(tree){
			cmd_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_ndmp, NULL, msg_vals[i].strptr);
		}
	}

	if(nh->type==NDMP_MESSAGE_REQUEST){
		if(ndmp_commands[i].request){
			offset=ndmp_commands[i].request(tvb, offset, pinfo, cmd_tree,
			    nh->seq);
		}
	} else {
		if(ndmp_commands[i].response){
			offset=ndmp_commands[i].response(tvb, offset, pinfo, cmd_tree,
			    nh->rep_seq);
		}
	}

	return offset;
}

static int
dissect_ndmp_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	int offset = 0;
	guint32 ndmp_rm;
	struct ndmp_header nh;
	guint32 size;
	guint32 seq, len, nxt, frag_num;
	int direction;
	struct tcpinfo *tcpinfo;
	ndmp_frag_info* nfi;
	proto_item *ndmp_item = NULL;
	proto_tree *ndmp_tree = NULL;
	proto_tree *hdr_tree;
	wmem_map_t *frags;
	conversation_t *conversation;
	proto_item *vers_item;
	gboolean save_fragmented, save_info_writable, save_proto_writable;
	gboolean do_frag = TRUE;
	tvbuff_t* new_tvb = NULL;
	fragment_head *frag_msg = NULL;

	/* Reject the packet if data is NULL under conditions where it'll be used */
	if (data == NULL && ndmp_defragment && ndmp_desegment)
		return 0;

	top_tree=tree; /* scsi should open its expansions on the top level */

	/*
	 * We need to keep track of conversations so that we can track NDMP
	 * versions.
	 */
	conversation = find_or_create_conversation(pinfo);

	ndmp_conv_data=(ndmp_conv_data_t *)conversation_get_proto_data(conversation, proto_ndmp);
	if(!ndmp_conv_data){
		ndmp_conv_data=wmem_new(wmem_file_scope(), ndmp_conv_data_t);
		ndmp_conv_data->version = NDMP_PROTOCOL_UNKNOWN;
		ndmp_conv_data->tasks   = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
		ndmp_conv_data->itl     = wmem_tree_new(wmem_file_scope());
		ndmp_conv_data->conversation = conversation;
		ndmp_conv_data->fragsA  = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
		ndmp_conv_data->fragsB  = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);

		conversation_add_proto_data(conversation, proto_ndmp, ndmp_conv_data);

		/* Ensure that any & all frames/fragments belonging to this conversation   */
		/*  are dissected as NDMP even if another dissector (eg: IPSEC-TCP) might  */
		/*  decide to dissect an NDMP fragment. This works because the TCP         */
		/*  dissector dispatches to a conversation associated dissector before     */
		/*  dispatching by port or by heuristic. Associating NDMP with this        */
		/*  conversation is necessary because otherwise the IPSEC-TCP(TCPENCAP)    */
		/*  dissector may think NDMP fragments are really TCPENCAP since that      */
		/*  dissector also registers on TCP Port 10000. (See packet-ipsec-tcp.c).  */
		conversation_set_dissector(conversation, ndmp_handle);
	}

	/*
	 * Read the NDMP record marker, if we have it.
	 */
	ndmp_rm=tvb_get_ntohl(tvb, offset);

	/* Save the flag indicating whether this packet is a fragment */
	save_fragmented = pinfo->fragmented;

	/* Reassemble if desegmentation and reassembly are enabled, otherwise
	 * just pass through and use the data in tvb for dissection */
	if (data && ndmp_defragment && ndmp_desegment)
	{

		/*
		 * Determine the direction of the flow, so we can use the correct fragment tree
		 */
		direction=cmp_address(&pinfo->src, &pinfo->dst);
		if(direction==0) {
			direction= (pinfo->srcport > pinfo->destport) ? 1 : -1;
		}
		if(direction>=0){
			frags = ndmp_conv_data->fragsA;
		} else {
			frags = ndmp_conv_data->fragsB;
		}

		/*
		 * Figure out the tcp seq and pdu length.  Fragment tree is indexed based on seq;
		 */
		tcpinfo = (struct tcpinfo *)data;

		seq = tcpinfo->seq;
		len = (ndmp_rm & RPC_RM_FRAGLEN) + 4;
		nxt = seq + len;

		/*
		 * In case there are multiple PDUs in the same frame, advance the tcp seq
		 * so that they can be distinguished from one another
		 */
		tcpinfo->seq = nxt;

		nfi = (ndmp_frag_info *)wmem_map_lookup(frags, GUINT_TO_POINTER(seq));

		if (!nfi)
		{
			frag_num = 0;

			/*
			 * If nfi doesn't exist, then there are no fragments before this one.
			 * If there are fragments after this one, create the entry in the frag
			 * tree so the next fragment can find it.
			 * If we've already seen this frame, no need to create the entry again.
			 */
			if ( !(ndmp_rm & RPC_RM_LASTFRAG))
			{
				if ( !(pinfo->fd->flags.visited))
				{
					nfi=wmem_new(wmem_file_scope(), ndmp_frag_info);
					nfi->first_seq = seq;
					nfi->offset = 1;
					wmem_map_insert(frags, GUINT_TO_POINTER(nxt), (void *)nfi);
				}
			}
			/*
			 * If this is both the first and the last fragment, then there
			 * is no reason to even engage the reassembly routines.  Just
			 * create the new_tvb directly from tvb.
			 */
			else
			{
				do_frag = FALSE;
				new_tvb = tvb_new_subset_remaining(tvb, 4);
			}
		}
		else
		{
			/*
			 * An entry was found, so we know the offset of this fragment
			 */
			frag_num = nfi->offset;
			seq = nfi->first_seq;

			/*
			 * If this isn't the last frag, add another entry so the next fragment can find it.
			 * If we've already seen this frame, no need to create the entry again.
			 */
			if ( !(ndmp_rm & RPC_RM_LASTFRAG))
			{
				if ( !(pinfo->fd->flags.visited))
				{
					nfi=wmem_new(wmem_file_scope(), ndmp_frag_info);
					nfi->first_seq = seq;
					nfi->offset = frag_num+1;
					wmem_map_insert(frags, GUINT_TO_POINTER(nxt), (void *)nfi);
				}
			}
		}

		/* If fragmentation is necessary */
		if (do_frag)
		{
			pinfo->fragmented = TRUE;

			frag_msg = fragment_add_seq_check(&ndmp_reassembly_table,
				tvb, 4, pinfo, seq, NULL,
				frag_num,
				tvb_captured_length_remaining(tvb, offset)-4,
				!(ndmp_rm & RPC_RM_LASTFRAG));

			new_tvb = process_reassembled_data(tvb, 4, pinfo, "Reassembled NDMP", frag_msg, &ndmp_frag_items, NULL, tree);
		}

		/*
		 * Check if this is the last fragment.
		 */
		if (!(ndmp_rm & RPC_RM_LASTFRAG)) {
			/*
			 *  Update the column info.
			 */
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "NDMP");

			col_set_str(pinfo->cinfo, COL_INFO, "[NDMP fragment] ");

			/*
			 * Add the record marker information to the tree
			 */
			if (tree) {
				ndmp_item = proto_tree_add_item(tree, proto_ndmp, tvb, 0, -1, ENC_NA);
				ndmp_tree = proto_item_add_subtree(ndmp_item, ett_ndmp);
			}
			hdr_tree = proto_tree_add_subtree_format(ndmp_tree, tvb, 0, 4,
				ett_ndmp_fraghdr, NULL, "Fragment header: %s%u %s",
				(ndmp_rm & RPC_RM_LASTFRAG) ? "Last fragment, " : "",
				ndmp_rm & RPC_RM_FRAGLEN, plurality(ndmp_rm & RPC_RM_FRAGLEN, "byte", "bytes"));
			proto_tree_add_boolean(hdr_tree, hf_ndmp_lastfrag, tvb, 0, 4, ndmp_rm);
			proto_tree_add_uint(hdr_tree, hf_ndmp_fraglen, tvb, 0, 4, ndmp_rm);

			/*
			 * Decode the remaining bytes as generic NDMP fragment data
			 */
			proto_tree_add_item(ndmp_tree, hf_ndmp_fragment_data, tvb, 4, -1, ENC_NA);

			pinfo->fragmented = save_fragmented;
			return tvb_captured_length(tvb);
		}
	}
	else
	{
		new_tvb = tvb_new_subset_remaining(tvb, 4);
	}


	/* size of this NDMP PDU */
	size = tvb_captured_length_remaining(new_tvb, offset);
	if (size < 24) {
		/* too short to be NDMP */
		pinfo->fragmented = save_fragmented;
		return tvb_captured_length(tvb);
	}

	/*
	 * If it doesn't look like a valid NDMP header at this point, there is
	 * no reason to move forward
	 */
	if (!check_ndmp_hdr(new_tvb))
	{
		pinfo->fragmented = save_fragmented;
		return tvb_captured_length(tvb);
	}

	nh.seq = tvb_get_ntohl(new_tvb, offset);
	nh.timestamp = tvb_get_ntohl(new_tvb, offset+4);
	nh.type = tvb_get_ntohl(new_tvb, offset+8);
	nh.msg = tvb_get_ntohl(new_tvb, offset+12);
	nh.rep_seq = tvb_get_ntohl(new_tvb, offset+16);
	nh.err = tvb_get_ntohl(new_tvb, offset+20);

	/* When the last fragment is small and the final frame contains
	 * multiple fragments, the column becomes unwritable.
	 * Temporarily change that so that the correct header can be
	 * applied */
	save_info_writable = col_get_writable(pinfo->cinfo, COL_INFO);
	save_proto_writable = col_get_writable(pinfo->cinfo, COL_PROTOCOL);
	col_set_writable(pinfo->cinfo, COL_PROTOCOL, TRUE);
	col_set_writable(pinfo->cinfo, COL_INFO, TRUE);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NDMP");
	col_clear(pinfo->cinfo, COL_INFO);
	if (tree) {
		ndmp_item = proto_tree_add_item(tree, proto_ndmp, tvb, 0, -1, ENC_NA);
		ndmp_tree = proto_item_add_subtree(ndmp_item, ett_ndmp);
	}

	/* ndmp version (and autodetection) */
	if(ndmp_conv_data->version!=NDMP_PROTOCOL_UNKNOWN){
		vers_item=proto_tree_add_uint(ndmp_tree, hf_ndmp_version, new_tvb, offset, 0, ndmp_conv_data->version);
	} else {
		vers_item=proto_tree_add_uint_format(ndmp_tree, hf_ndmp_version, new_tvb, offset, 0, ndmp_default_protocol_version, "Unknown NDMP version, using default:%d", ndmp_default_protocol_version);
	}
	PROTO_ITEM_SET_GENERATED(vers_item);

	/* request response matching */
	ndmp_conv_data->task=NULL;
	switch(nh.type){
	case NDMP_MESSAGE_REQUEST:
		if(!pinfo->fd->flags.visited){
			ndmp_conv_data->task=wmem_new(wmem_file_scope(), ndmp_task_data_t);
			ndmp_conv_data->task->request_frame=pinfo->num;
			ndmp_conv_data->task->response_frame=0;
			ndmp_conv_data->task->ndmp_time=pinfo->abs_ts;
			ndmp_conv_data->task->itlq=NULL;
			wmem_map_insert(ndmp_conv_data->tasks, GUINT_TO_POINTER(nh.seq), ndmp_conv_data->task);
		} else {
			ndmp_conv_data->task=(ndmp_task_data_t *)wmem_map_lookup(ndmp_conv_data->tasks, GUINT_TO_POINTER(nh.seq));
		}
		if(ndmp_conv_data->task && ndmp_conv_data->task->response_frame){
			proto_item *it;
			it=proto_tree_add_uint(ndmp_tree, hf_ndmp_response_frame, new_tvb, 0, 0, ndmp_conv_data->task->response_frame);

			PROTO_ITEM_SET_GENERATED(it);
		}
		break;
	case NDMP_MESSAGE_REPLY:
		ndmp_conv_data->task=(ndmp_task_data_t *)wmem_map_lookup(ndmp_conv_data->tasks, GUINT_TO_POINTER(nh.rep_seq));

		if(ndmp_conv_data->task && !pinfo->fd->flags.visited){
			ndmp_conv_data->task->response_frame=pinfo->num;
			if(ndmp_conv_data->task->itlq){
				ndmp_conv_data->task->itlq->last_exchange_frame=pinfo->num;
			}
		}
		if(ndmp_conv_data->task && ndmp_conv_data->task->request_frame){
			proto_item *it;
			nstime_t delta_ts;

			it=proto_tree_add_uint(ndmp_tree, hf_ndmp_request_frame, new_tvb, 0, 0, ndmp_conv_data->task->request_frame);

			PROTO_ITEM_SET_GENERATED(it);

			nstime_delta(&delta_ts, &pinfo->abs_ts, &ndmp_conv_data->task->ndmp_time);
			it=proto_tree_add_time(ndmp_tree, hf_ndmp_time, new_tvb, 0, 0, &delta_ts);
			PROTO_ITEM_SET_GENERATED(it);
		}
		break;
	}

	/* Add the record marker information to the tree */
	hdr_tree = proto_tree_add_subtree_format(ndmp_tree, tvb, 0, 4,
		ett_ndmp_fraghdr, NULL, "Fragment header: %s%u %s",
		(ndmp_rm & RPC_RM_LASTFRAG) ? "Last fragment, " : "",
		ndmp_rm & RPC_RM_FRAGLEN, plurality(ndmp_rm & RPC_RM_FRAGLEN, "byte", "bytes"));
	proto_tree_add_boolean(hdr_tree, hf_ndmp_lastfrag, tvb, 0, 4, ndmp_rm);
	proto_tree_add_uint(hdr_tree, hf_ndmp_fraglen, tvb, 0, 4, ndmp_rm);

	/*
	 * We cannot trust what dissect_ndmp_cmd() tells us, as there
	 * are implementations which pad some additional data after
	 * the PDU.  We MUST use size.
	 */
	dissect_ndmp_cmd(new_tvb, offset, pinfo, ndmp_tree, &nh);

	/* restore saved variables */
	pinfo->fragmented = save_fragmented;
	col_set_writable(pinfo->cinfo, COL_INFO, save_info_writable);
	col_set_writable(pinfo->cinfo, COL_PROTOCOL, save_proto_writable);

	return tvb_captured_length(tvb);
}

static guint
get_ndmp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	guint len;

	len=tvb_get_ntohl(tvb, offset)&0x7fffffff;
	/* Get the length of the NDMP packet. */

	/*XXX check header for sanity */
	return len+4;
}

gboolean
check_if_ndmp(tvbuff_t *tvb, packet_info *pinfo)
{
	guint len;
	guint32 tmp;

	/* verify that the tcp port is 10000, ndmp always runs on port 10000*/
	if ((pinfo->srcport!=TCP_PORT_NDMP)&&(pinfo->destport!=TCP_PORT_NDMP)) {
		return FALSE;
	}

	/* check that the header looks sane */
	len=tvb_captured_length(tvb);
	/* check the record marker that it looks sane.
	 * It has to be >=24 bytes or (arbitrary limit) <1Mbyte
	 */
	if(len>=4){
		tmp=(tvb_get_ntohl(tvb, 0)&RPC_RM_FRAGLEN);
		if( (tmp<24)||(tmp>1000000) ){
			return FALSE;
		}
	}

	/* check the timestamp,  timestamps are valid if they
	 * (arbitrary) lie between 1980-jan-1 and 2030-jan-1
	 */
	if(len>=12){
		tmp=tvb_get_ntohl(tvb, 8);
		if( (tmp<0x12ceec50)||(tmp>0x70dc1ed0) ){
			return FALSE;
		}
	}

	/* check the type */
	if(len>=16){
		tmp=tvb_get_ntohl(tvb, 12);
		if( tmp>1 ){
			return FALSE;
		}
	}

	/* check message */
	if(len>=20){
		tmp=tvb_get_ntohl(tvb, 16);
		if( (tmp>0xa09) || (tmp==0) ){
			return FALSE;
		}
	}

	/* check error */
	if(len>=28){
		tmp=tvb_get_ntohl(tvb, 24);
		if( (tmp>0x17) ){
			return FALSE;
		}
	}

	return TRUE;
}

/* Called because the frame has been identified as part of a conversation
 *  assigned to the NDMP protocol.
 *  At this point we may have either an NDMP PDU or an NDMP PDU fragment.
 */
static int
dissect_ndmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	/* If we are doing defragmentation, don't check more than the record mark here,
	 * because if this is a continuation of a fragmented NDMP PDU there won't be a
	 * NDMP header after the RM */
	if(ndmp_defragment && !check_ndmp_rm(tvb, pinfo)) {
		return 0;
	}

	/* If we aren't doing both desegmentation and fragment reassembly,
	 * check for the entire NDMP header before proceeding */
	if(!(ndmp_desegment && ndmp_defragment) && !check_if_ndmp(tvb, pinfo)) {
		return 0;
	}

	tcp_dissect_pdus(tvb, pinfo, tree, ndmp_desegment, 4,
			 get_ndmp_pdu_len, dissect_ndmp_message, data);
	return tvb_captured_length(tvb);
}

/* Called when doing a heuristic check;
 * Accept as NDMP only if the full header seems reasonable.
 * Note that once the first PDU (or PDU fragment) has been found
 *  dissect_ndmp_message will register a dissect_ndmp NDMP handle
 *  as the protocol dissector for this conversation.
 */
static int
dissect_ndmp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	if (tvb_captured_length(tvb) < 28)
		return 0;
	if (!check_if_ndmp(tvb, pinfo))
		return 0;

	tcp_dissect_pdus(tvb, pinfo, tree, ndmp_desegment, 28,
			 get_ndmp_pdu_len, dissect_ndmp_message, data);
	return tvb_captured_length(tvb);
}

static void
ndmp_init(void)
{
	reassembly_table_init(&ndmp_reassembly_table,
	    &addresses_reassembly_table_functions);
}

static void
ndmp_cleanup(void)
{
	reassembly_table_destroy(&ndmp_reassembly_table);
}


void
proto_register_ndmp(void)
{

	static hf_register_info hf_ndmp[] = {
	{ &hf_ndmp_header, {
		"NDMP Header", "ndmp.header", FT_NONE, BASE_NONE,
		NULL, 0, NULL, HFILL }},

	{ &hf_ndmp_response_frame, {
		"Response In", "ndmp.response_frame", FT_FRAMENUM, BASE_NONE,
		NULL, 0, "The response to this NDMP command is in this frame", HFILL }},

	{ &hf_ndmp_time, {
		"Time from request", "ndmp.time", FT_RELATIVE_TIME, BASE_NONE,
		NULL,0, "Time since the request packet", HFILL }},

	{ &hf_ndmp_request_frame, {
		"Request In", "ndmp.request_frame", FT_FRAMENUM, BASE_NONE,
		NULL, 0, "The request to this NDMP command is in this frame", HFILL }},

	{ &hf_ndmp_sequence, {
		"Sequence", "ndmp.sequence", FT_UINT32, BASE_DEC,
		NULL, 0, "Sequence number for NDMP PDU", HFILL }},

	{ &hf_ndmp_reply_sequence, {
		"Reply Sequence", "ndmp.reply_sequence", FT_UINT32, BASE_DEC,
		NULL, 0, "Reply Sequence number for NDMP PDU", HFILL }},

	{ &hf_ndmp_timestamp, {
		"Time", "ndmp.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
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
		NULL, 0, NULL, HFILL }},

	{ &hf_ndmp_hostid, {
		"HostID", "ndmp.hostid", FT_STRING, BASE_NONE,
		NULL, 0, NULL, HFILL }},

	{ &hf_ndmp_os_type, {
		"OS Type", "ndmp.os.type", FT_STRING, BASE_NONE,
		NULL, 0, NULL, HFILL }},

	{ &hf_ndmp_os_vers, {
		"OS Version", "ndmp.os.version", FT_STRING, BASE_NONE,
		NULL, 0, NULL, HFILL }},

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
		"Challenge", "ndmp.auth.challenge", FT_BYTES, BASE_NONE,
		NULL, 0, "Authentication Challenge", HFILL }},

	{ &hf_ndmp_auth_digest, {
		"Digest", "ndmp.auth.digest", FT_BYTES, BASE_NONE,
		NULL, 0, "Authentication Digest", HFILL }},

	{ &hf_ndmp_butype_info, {
		"Butype Info", "ndmp.butype.info", FT_NONE, BASE_NONE,
		NULL, 0, NULL, HFILL }},

	{ &hf_ndmp_butype_name, {
		"Butype Name", "ndmp.butype.name", FT_STRING, BASE_NONE,
		NULL, 0, "Name of Butype", HFILL }},

	{ &hf_ndmp_butype_default_env, {
		"Default Env", "ndmp.butype.default_env", FT_NONE, BASE_NONE,
		NULL, 0, "Default Env's for this Butype Info", HFILL }},

	{ &hf_ndmp_tcp_addr_list, {
		"TCP Ports", "ndmp.tcp.port_list", FT_NONE, BASE_NONE,
		NULL, 0, "List of TCP ports", HFILL }},

	{ &hf_ndmp_tcp_default_env, {
		"Default Env", "ndmp.tcp.default_env", FT_NONE, BASE_NONE,
		NULL, 0, "Default Env's for this Butype Info", HFILL }},

	{ &hf_ndmp_butype_attr, {
		"Attributes", "ndmp.butype.attr", FT_UINT32, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_ndmp_butype_attr_backup_file_history, {
		"Backup file history", "ndmp.butype.attr.backup_file_history", FT_BOOLEAN, 32,
		TFS(&tfs_butype_attr_backup_file_history), 0x00000001, "backup_file_history", HFILL }},

	{ &hf_ndmp_butype_attr_backup_filelist, {
		"Backup file list", "ndmp.butype.attr.backup_filelist", FT_BOOLEAN, 32,
		TFS(&tfs_butype_attr_backup_filelist), 0x00000002, "backup_filelist", HFILL }},

	{ &hf_ndmp_butype_attr_recover_filelist, {
		"Recover file list", "ndmp.butype.attr.recover_filelist", FT_BOOLEAN, 32,
		TFS(&tfs_butype_attr_recover_filelist), 0x00000004, "recover_filelist", HFILL }},

	{ &hf_ndmp_butype_attr_backup_direct, {
		"Backup direct", "ndmp.butype.attr.backup_direct", FT_BOOLEAN, 32,
		TFS(&tfs_butype_attr_backup_direct), 0x00000008, "backup_direct", HFILL }},

	{ &hf_ndmp_butype_attr_recover_direct, {
		"Recover direct", "ndmp.butype.attr.recover_direct", FT_BOOLEAN, 32,
		TFS(&tfs_butype_attr_recover_direct), 0x00000010, "recover_direct", HFILL }},

	{ &hf_ndmp_butype_attr_backup_incremental, {
		"Backup incremental", "ndmp.butype.attr.backup_incremental", FT_BOOLEAN, 32,
		TFS(&tfs_butype_attr_backup_incremental), 0x00000020, "backup_incremental", HFILL }},

	{ &hf_ndmp_butype_attr_recover_incremental, {
		"Recover incremental", "ndmp.butype.attr.recover_incremental", FT_BOOLEAN, 32,
		TFS(&tfs_butype_attr_recover_incremental), 0x00000040, "recover_incremental", HFILL }},

	{ &hf_ndmp_butype_attr_backup_utf8, {
		"Backup UTF8", "ndmp.butype.attr.backup_utf8", FT_BOOLEAN, 32,
		TFS(&tfs_butype_attr_backup_utf8), 0x00000080, "backup_utf8", HFILL }},

	{ &hf_ndmp_butype_attr_recover_utf8, {
		"Recover UTF8", "ndmp.butype.attr.recover_utf8", FT_BOOLEAN, 32,
		TFS(&tfs_butype_attr_recover_utf8), 0x00000100, "recover_utf8", HFILL }},

	{ &hf_ndmp_butype_env_name, {
		"Name", "ndmp.butype.env.name", FT_STRING, BASE_NONE,
		NULL, 0, "Name for this env-variable", HFILL }},

	{ &hf_ndmp_butype_env_value, {
		"Value", "ndmp.butype.env.value", FT_STRING, BASE_NONE,
		NULL, 0, "Value for this env-variable", HFILL }},

	{ &hf_ndmp_tcp_env_name, {
		"Name", "ndmp.tcp.env.name", FT_STRING, BASE_NONE,
		NULL, 0, "Name for this env-variable", HFILL }},

	{ &hf_ndmp_tcp_env_value, {
		"Value", "ndmp.tcp.env.value", FT_STRING, BASE_NONE,
		NULL, 0, "Value for this env-variable", HFILL }},

	{ &hf_ndmp_fs_info, {
		"FS Info", "ndmp.fs.info", FT_NONE, BASE_NONE,
		NULL, 0, NULL, HFILL }},

	{ &hf_ndmp_fs_invalid, {
		"Invalids", "ndmp.fs.invalid", FT_UINT32, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_ndmp_fs_invalid_total_size, {
		"Total size invalid", "ndmp.fs.invalid.total_size", FT_BOOLEAN, 32,
		TFS(&tfs_fs_invalid_total_size), 0x00000001, "If total size is invalid", HFILL }},

	{ &hf_ndmp_fs_invalid_used_size, {
		"Used size invalid", "ndmp.fs.invalid.used_size", FT_BOOLEAN, 32,
		TFS(&tfs_fs_invalid_used_size), 0x00000002, "If used size is invalid", HFILL }},

	{ &hf_ndmp_fs_invalid_avail_size, {
		"Available size invalid", "ndmp.fs.invalid.avail_size", FT_BOOLEAN, 32,
		TFS(&tfs_fs_invalid_avail_size), 0x00000004, "If available size is invalid", HFILL }},

	{ &hf_ndmp_fs_invalid_total_inodes, {
		"Total number of inodes invalid", "ndmp.fs.invalid.total_inodes", FT_BOOLEAN, 32,
		TFS(&tfs_fs_invalid_total_inodes), 0x00000008, "If total number of inodes is invalid", HFILL }},

	{ &hf_ndmp_fs_invalid_used_inodes, {
		"Used number of inodes is invalid", "ndmp.fs.invalid.used_inodes", FT_BOOLEAN, 32,
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
		NULL, 0, NULL, HFILL }},

	{ &hf_ndmp_tape_model, {
		"Model", "ndmp.tape.model", FT_STRING, BASE_NONE,
		NULL, 0, "Model of the TAPE drive", HFILL }},

	{ &hf_ndmp_tape_dev_cap, {
		"Device Capability", "ndmp.tape.dev_cap", FT_NONE, BASE_NONE,
		NULL, 0, "Tape Device Capability", HFILL }},

	{ &hf_ndmp_tape_device, {
		"Device", "ndmp.tape.device", FT_STRING, BASE_NONE,
		NULL, 0, "Name of TAPE Device", HFILL }},

	{ &hf_ndmp_tape_attr, {
		"Attributes", "ndmp.tape.attr", FT_UINT32, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_ndmp_tape_attr_rewind, {
		"Device supports rewind", "ndmp.tape.attr.rewind", FT_BOOLEAN, 32,
		TFS(&tfs_tape_attr_rewind), 0x00000001, "If this device supports rewind", HFILL }},

	{ &hf_ndmp_tape_attr_unload, {
		"Device supports unload", "ndmp.tape.attr.unload", FT_BOOLEAN, 32,
		TFS(&tfs_tape_attr_unload), 0x00000002, "If this device supports unload", HFILL }},

	{ &hf_ndmp_tape_capability, {
		"Tape Capabilities", "ndmp.tape.capability", FT_NONE, BASE_NONE,
		NULL, 0, NULL, HFILL }},

	{ &hf_ndmp_tape_capability_name, {
		"Name", "ndmp.tape.cap.name", FT_STRING, BASE_NONE,
		NULL, 0, "Name for this env-variable", HFILL }},

	{ &hf_ndmp_tape_capability_value, {
		"Value", "ndmp.tape.cap.value", FT_STRING, BASE_NONE,
		NULL, 0, "Value for this env-variable", HFILL }},

	{ &hf_ndmp_scsi_info, {
		"SCSI Info", "ndmp.scsi.info", FT_NONE, BASE_NONE,
		NULL, 0, NULL, HFILL }},

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
		NULL, 0, NULL, HFILL }},

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

	{ &hf_ndmp_execute_cdb_flags, {
		"Flags", "ndmp.execute_cdb.flags", FT_UINT32, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_ndmp_execute_cdb_flags_data_in, {
		"DATA_IN", "ndmp.execute_cdb.flags.data_in", FT_BOOLEAN, 32,
		NULL, 0x00000001, NULL, HFILL }},

	{ &hf_ndmp_execute_cdb_flags_data_out, {
		"DATA_OUT", "ndmp.execute_cdb.flags.data_out", FT_BOOLEAN, 32,
		NULL, 0x00000002, NULL, HFILL }},

	{ &hf_ndmp_execute_cdb_timeout, {
		"Timeout", "ndmp.execute_cdb.timeout", FT_UINT32, BASE_DEC,
		NULL, 0, "Reselect timeout, in milliseconds", HFILL }},

	{ &hf_ndmp_execute_cdb_datain_len, {
		"Data in length", "ndmp.execute_cdb.datain_len", FT_UINT32, BASE_DEC,
		NULL, 0, "Expected length of data bytes to read", HFILL }},

	{ &hf_ndmp_execute_cdb_cdb_len, {
		"CDB length", "ndmp.execute_cdb.cdb_len", FT_UINT32, BASE_DEC,
		NULL, 0, "Length of CDB", HFILL }},

#if 0
	{ &hf_ndmp_execute_cdb_dataout, {
		"Data out", "ndmp.execute_cdb.dataout", FT_BYTES, BASE_NONE,
		NULL, 0, "Data to be transferred to the SCSI device", HFILL }},
#endif

	{ &hf_ndmp_execute_cdb_status, {
		"Status", "ndmp.execute_cdb.status", FT_UINT8, BASE_DEC,
		VALS(scsi_status_val), 0, "SCSI status", HFILL }},

	{ &hf_ndmp_execute_cdb_dataout_len, {
		"Data out length", "ndmp.execute_cdb.dataout_len", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of bytes transferred to the device", HFILL }},

#if 0
	{ &hf_ndmp_execute_cdb_datain, {
		"Data in", "ndmp.execute_cdb.datain", FT_BYTES, BASE_NONE,
		NULL, 0, "Data transferred from the SCSI device", HFILL }},
#endif

	{ &hf_ndmp_execute_cdb_sns_len, {
		"Sense data length", "ndmp.execute_cdb.sns_len", FT_UINT32, BASE_DEC,
		NULL, 0, "Length of sense data", HFILL }},

	{ &hf_ndmp_tape_open_mode, {
		"Mode", "ndmp.tape.open_mode", FT_UINT32, BASE_DEC,
		VALS(tape_open_mode_vals), 0, "Mode to open tape in", HFILL }},

	{ &hf_ndmp_tape_invalid, {
		"Invalids", "ndmp.tape.invalid", FT_UINT32, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_ndmp_tape_invalid_file_num, {
		"Invalid file num", "ndmp.tape.invalid.file_num", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_tape_invalid_file_num), 0x00000001, "invalid_file_num", HFILL }},

	{ &hf_ndmp_tape_invalid_soft_errors, {
		"Soft errors", "ndmp.tape.invalid.soft_errors", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_tape_invalid_soft_errors), 0x00000002, "soft_errors", HFILL }},

	{ &hf_ndmp_tape_invalid_block_size, {
		"Block size", "ndmp.tape.invalid.block_size", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_tape_invalid_block_size), 0x00000004, "block_size", HFILL }},

	{ &hf_ndmp_tape_invalid_block_no, {
		"Block no", "ndmp.tape.invalid.block_no", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_tape_invalid_block_no), 0x00000008, "block_no", HFILL }},

	{ &hf_ndmp_tape_invalid_total_space, {
		"Total space", "ndmp.tape.invalid.total_space", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_tape_invalid_total_space), 0x00000010, "total_space", HFILL }},

	{ &hf_ndmp_tape_invalid_space_remain, {
		"Space remain", "ndmp.tape.invalid.space_remain", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_tape_invalid_space_remain), 0x00000020, "space_remain", HFILL }},

	{ &hf_ndmp_tape_invalid_partition, {
		"Invalid partition", "ndmp.tape.invalid.partition", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_tape_invalid_partition), 0x00000040, "partition", HFILL }},

	{ &hf_ndmp_tape_flags, {
		"Flags", "ndmp.tape.flags", FT_UINT32, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_ndmp_tape_flags_no_rewind, {
		"No rewind", "ndmp.tape.flags.no_rewind", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_tape_flags_no_rewind), 0x00000008, "no_rewind", HFILL, }},

	{ &hf_ndmp_tape_flags_write_protect, {
		"Write protect", "ndmp.tape.flags.write_protect", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_tape_flags_write_protect), 0x00000010, "write_protect", HFILL, }},

	{ &hf_ndmp_tape_flags_error, {
		"Error", "ndmp.tape.flags.error", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_tape_flags_error), 0x00000020, NULL, HFILL, }},

	{ &hf_ndmp_tape_flags_unload, {
		"Unload", "ndmp.tape.flags.unload", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_tape_flags_unload), 0x00000040, NULL, HFILL, }},

	{ &hf_ndmp_tape_file_num, {
		"file_num", "ndmp.tape.status.file_num", FT_UINT32, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_ndmp_tape_soft_errors, {
		"soft_errors", "ndmp.tape.status.soft_errors", FT_UINT32, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_ndmp_tape_block_size, {
		"block_size", "ndmp.tape.status.block_size", FT_UINT32, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_ndmp_tape_block_no, {
		"block_no", "ndmp.tape.status.block_no", FT_UINT32, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_ndmp_tape_total_space, {
		"total_space", "ndmp.tape.status.total_space", FT_UINT64, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_ndmp_tape_space_remain, {
		"space_remain", "ndmp.tape.status.space_remain", FT_UINT64, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_ndmp_tape_partition, {
		"partition", "ndmp.tape.status.partition", FT_UINT32, BASE_DEC,
		NULL, 0, NULL, HFILL }},

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
		"IP Address", "ndmp.addr.ip", FT_IPv4, BASE_NONE,
		NULL, 0, NULL, HFILL }},

	{ &hf_ndmp_addr_tcp, {
		"TCP Port", "ndmp.addr.tcp_port", FT_UINT32, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_ndmp_addr_fcal_loop_id, {
		"Loop ID", "ndmp.addr.loop_id", FT_UINT32, BASE_HEX,
		NULL, 0, "FCAL Loop ID", HFILL }},

	{ &hf_ndmp_addr_ipc, {
		"IPC", "ndmp.addr.ipc", FT_BYTES, BASE_NONE,
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
		"Data", "ndmp.data", FT_BYTES, BASE_NONE,
		NULL, 0, "Data written/read", HFILL }},

	{ &hf_ndmp_files, {
		"Files", "ndmp.files", FT_NONE, BASE_NONE,
		NULL, 0, "List of files", HFILL }},

	{ &hf_ndmp_file_names, {
		"File Names", "ndmp.file.names", FT_NONE, BASE_NONE,
		NULL, 0, "List of file names", HFILL }},

	{ &hf_ndmp_file_fs_type, {
		"File FS Type", "ndmp.file.fs_type", FT_UINT32, BASE_DEC,
		VALS(file_fs_type_vals), 0, "Type of file permissions (UNIX or NT)", HFILL }},

	{ &hf_ndmp_file_type, {
		"File Type", "ndmp.file.type", FT_UINT32, BASE_DEC,
		VALS(file_type_vals), 0, "Type of file", HFILL }},

	{ &hf_ndmp_file_stats, {
		"File Stats", "ndmp.file.stats", FT_NONE, BASE_NONE,
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

	{ &hf_ndmp_file_invalid, {
		"Invalids", "ndmp.file.invalid", FT_UINT32, BASE_HEX,
		VALS(file_type_vals), 0, NULL, HFILL }},

	{ &hf_ndmp_file_invalid_atime, {
		"Invalid atime", "ndmp.file.invalid.atime", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_file_invalid_atime), 0x00000001, NULL, HFILL, }},

	{ &hf_ndmp_file_invalid_ctime, {
		"Invalid ctime", "ndmp.file.invalid.ctime", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_file_invalid_ctime), 0x00000002, NULL, HFILL, }},

	{ &hf_ndmp_file_invalid_group, {
		"Invalid group", "ndmp.file.invalid.group", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_file_invalid_group), 0x00000004, NULL, HFILL, }},

	{ &hf_ndmp_file_mtime, {
		"mtime", "ndmp.file.mtime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
		NULL, 0, "Timestamp for mtime for this file", HFILL }},

	{ &hf_ndmp_file_atime, {
		"atime", "ndmp.file.atime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
		NULL, 0, "Timestamp for atime for this file", HFILL }},

	{ &hf_ndmp_file_ctime, {
		"ctime", "ndmp.file.ctime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
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
		"Dirs", "ndmp.dirs", FT_NONE, BASE_NONE,
		NULL, 0, "List of directories", HFILL }},

	{ &hf_ndmp_nodes, {
		"Nodes", "ndmp.nodes", FT_NONE, BASE_NONE,
		NULL, 0, "List of nodes", HFILL }},

	{ &hf_ndmp_nlist, {
		"Nlist", "ndmp.nlist", FT_NONE, BASE_NONE,
		NULL, 0, "List of names", HFILL }},

	{ &hf_ndmp_bu_original_path, {
		"Original Path", "ndmp.bu.original_path", FT_STRING, BASE_NONE,
		NULL, 0, "Original path where backup was created", HFILL }},

	{ &hf_ndmp_bu_destination_dir, {
		"Destination Dir", "ndmp.bu.destination_dir", FT_STRING, BASE_NONE,
		NULL, 0, "Destination directory to restore backup to", HFILL }},

	{ &hf_ndmp_bu_new_name, {
		"New Name", "ndmp.bu.new_name", FT_STRING, BASE_NONE,
		NULL, 0, NULL, HFILL }},

	{ &hf_ndmp_bu_other_name, {
		"Other Name", "ndmp.bu.other_name", FT_STRING, BASE_NONE,
		NULL, 0, NULL, HFILL }},

	{ &hf_ndmp_state_invalid, {
		"Invalids", "ndmp.bu.state.invalid", FT_UINT32, BASE_HEX,
		VALS(file_type_vals), 0, NULL, HFILL }},

	{ &hf_ndmp_state_invalid_ebr, {
		"EstimatedBytesLeft valid", "ndmp.bu.state.invalid.ebr", FT_BOOLEAN, 32,
		TFS(&tfs_ndmp_state_invalid_ebr), 0x00000001, "Whether EstimatedBytesLeft is valid or not", HFILL, }},

	{ &hf_ndmp_state_invalid_etr, {
		"EstimatedTimeLeft valid", "ndmp.bu.state.invalid.etr", FT_BOOLEAN, 32,
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
		"Est Time Remain", "ndmp.data.est_time_remain", FT_RELATIVE_TIME, BASE_NONE,
		NULL, 0, "Estimated time remaining", HFILL }},
	{ &hf_ndmp_lastfrag, {
		"Last Fragment", "ndmp.lastfrag", FT_BOOLEAN, 32,
		TFS(&tfs_yes_no), RPC_RM_LASTFRAG, NULL, HFILL }},
	{ &hf_ndmp_fraglen, {
		"Fragment Length", "ndmp.fraglen", FT_UINT32, BASE_DEC,
		NULL, RPC_RM_FRAGLEN, NULL, HFILL }},
	{ &hf_ndmp_class_list, {
		"Ext Class List", "ndmp.class_list", FT_NONE, BASE_NONE,
		NULL, 0, "List of extension classes", HFILL }},
	{ &hf_ndmp_ex_class_id, {
		"Class ID", "ndmp.class.id", FT_UINT32, BASE_HEX,
		NULL, 0, NULL, HFILL }},
	{ &hf_ndmp_ext_version_list, {
		"Ext Version List", "ndmp.ext_version_list", FT_NONE, BASE_NONE,
		NULL, 0, "List of extension versions", HFILL }},
	{ &hf_ndmp_ext_version, {
		"Ext Version", "ndmp.ext_version_list.version", FT_UINT32, BASE_HEX,
		NULL, 0, "Extension version", HFILL }},
	{ &hf_ndmp_class_version, {
		"Class and version", "ndmp.ext_version", FT_NONE, BASE_NONE,
		NULL, 0, NULL, HFILL }},
	{ &hf_ndmp_ex_class_version, {
		"Class Version", "ndmp.class.version", FT_UINT32, BASE_HEX,
		NULL, 0, NULL, HFILL }},
	{ &hf_ndmp_fragment_data, {
		"NDMP fragment data", "ndmp.fragment_data", FT_BYTES, BASE_NONE,
		NULL, 0, NULL, HFILL }},
	{&hf_ndmp_fragments, {
		"NDMP fragments", "ndmp.fragments", FT_NONE, BASE_NONE,
		NULL, 0x00, NULL, HFILL } },
	{&hf_ndmp_fragment,
		{"NDMP fragment", "ndmp.fragment",
		FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
	{&hf_ndmp_fragment_overlap,
		{"NDMP fragment overlap", "ndmp.fragment.overlap",
		FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
	{&hf_ndmp_fragment_overlap_conflicts,
		{"NDMP fragment overlapping with conflicting data",
		"ndmp.fragment.overlap.conflicts",
		FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
	{&hf_ndmp_fragment_multiple_tails,
		{"NDMP has multiple tail fragments",
		"ndmp.fragment.multiple_tails",
		FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
	{&hf_ndmp_fragment_too_long_fragment,
		{"NDMP fragment too long", "ndmp.fragment.too_long_fragment",
		FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
	{&hf_ndmp_fragment_error,
		{"NDMP defragmentation error", "ndmp.fragment.error",
		FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
	{&hf_ndmp_fragment_count,
		{"NDMP fragment count", "ndmp.fragment.count",
		FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
	{&hf_ndmp_reassembled_in,
		{"Reassembled in", "ndmp.reassembled.in",
		FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
	{&hf_ndmp_reassembled_length,
		{"Reassembled NDMP length", "ndmp.reassembled.length",
		FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
	};

	static gint *ett[] = {
		&ett_ndmp,
		&ett_ndmp_fraghdr,
		&ett_ndmp_header,
		&ett_ndmp_butype_attrs,
		&ett_ndmp_fs_invalid,
		&ett_ndmp_tape_attr,
		&ett_ndmp_execute_cdb_flags,
		&ett_ndmp_execute_cdb_cdb,
		&ett_ndmp_execute_cdb_sns,
		&ett_ndmp_execute_cdb_payload,
		&ett_ndmp_tape_invalid,
		&ett_ndmp_tape_flags,
		&ett_ndmp_addr,
		&ett_ndmp_file,
		&ett_ndmp_file_name,
		&ett_ndmp_file_stats,
		&ett_ndmp_file_invalids,
		&ett_ndmp_state_invalids,
		&ett_ndmp_fragment,
		&ett_ndmp_fragments,
	};

	static ei_register_info ei[] = {
		{ &ei_ndmp_msg, { "ndmp.msg.unknown", PI_PROTOCOL, PI_WARN, "Unknown type of NDMP message", EXPFILL }},
	};

	module_t *ndmp_module;
	expert_module_t* expert_ndmp;

	proto_ndmp = proto_register_protocol("Network Data Management Protocol", "NDMP", "ndmp");
	proto_register_field_array(proto_ndmp, hf_ndmp, array_length(hf_ndmp));

	proto_register_subtree_array(ett, array_length(ett));
	expert_ndmp = expert_register_protocol(proto_ndmp);
	expert_register_field_array(expert_ndmp, ei, array_length(ei));

	/* desegmentation */
	ndmp_module = prefs_register_protocol(proto_ndmp, NULL);
	prefs_register_obsolete_preference(ndmp_module, "protocol_version");
	prefs_register_enum_preference(ndmp_module,
	"default_protocol_version",
	"Default protocol version",
	"Version of the NDMP protocol to assume if the version can not be automatically detected from the capture",
	&ndmp_default_protocol_version,
	ndmp_protocol_versions,
	FALSE);
	prefs_register_bool_preference(ndmp_module, "desegment",
	"Reassemble NDMP messages spanning multiple TCP segments",
	"Whether the NDMP dissector should reassemble messages spanning multiple TCP segments."
	" To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
	&ndmp_desegment);
	prefs_register_bool_preference(ndmp_module, "defragment",
	"Reassemble fragmented NDMP messages spanning multiple packets",
	"Whether the dissector should defragment NDMP messages spanning multiple packets.",
	&ndmp_defragment);
	register_init_routine(ndmp_init);
	register_cleanup_routine(ndmp_cleanup);
}

void
proto_reg_handoff_ndmp(void)
{
	ndmp_handle = create_dissector_handle(dissect_ndmp, proto_ndmp);
	dissector_add_uint("tcp.port",TCP_PORT_NDMP, ndmp_handle);
	heur_dissector_add("tcp", dissect_ndmp_heur, "NDMP over TCP", "ndmp_tcp", proto_ndmp, HEURISTIC_ENABLE);
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

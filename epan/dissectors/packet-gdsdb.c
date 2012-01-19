/* packet-gdsdb.c
 * Routines for Firebird/Interbase dissection
 * Copyright 2007, Moshe van der Sterre <moshevds@gmail.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>

#include <glib.h>

#include <epan/packet.h>

#define TCP_PORT	3050

static int proto_gdsdb = -1;
static gint ett_gdsdb = -1;
static int hf_gdsdb_opcode = -1;
static gint ett_gdsdb_opcode = -1;

/* gdsdb_dummy */
/* gdsdb_connect */
static int hf_gdsdb_connect_operation = -1;
static int hf_gdsdb_connect_version = -1;
static int hf_gdsdb_connect_client = -1;
static int hf_gdsdb_connect_filename = -1;
static int hf_gdsdb_connect_count = -1;
static int hf_gdsdb_connect_userid = -1;
static int hf_gdsdb_connect_pref = -1;
static gint ett_gdsdb_connect_pref = -1;
static int hf_gdsdb_connect_pref_version = -1;
static int hf_gdsdb_connect_pref_architecture = -1;
static int hf_gdsdb_connect_pref_mintype = -1;
static int hf_gdsdb_connect_pref_maxtype = -1;
static int hf_gdsdb_connect_pref_weight = -1;
/* gdsdb_accept */
static int hf_gdsdb_accept_version = -1;
static int hf_gdsdb_accept_architecture = -1;
/* gdsdb_request */
static int hf_gdsdb_request_type = -1;
static int hf_gdsdb_request_object = -1;
static int hf_gdsdb_request_partner = -1;
/* gdsdb_attach */
static int hf_gdsdb_attach_database = -1;
static int hf_gdsdb_attach_filename = -1;
static int hf_gdsdb_attach_dpb = -1;
/* gdsdb_compile */
static int hf_gdsdb_compile_database = -1;
static int hf_gdsdb_compile_blr = -1;
/* gdsdb_receive */
static int hf_gdsdb_receive_request = -1;
static int hf_gdsdb_receive_incarnation = -1;
static int hf_gdsdb_receive_transaction = -1;
static int hf_gdsdb_receive_msgnr = -1;
static int hf_gdsdb_receive_messages = -1;
static int hf_gdsdb_receive_direction = -1;
static int hf_gdsdb_receive_offset = -1;
/* gdsdb_send */
static int hf_gdsdb_send_request = -1;
static int hf_gdsdb_send_incarnation = -1;
static int hf_gdsdb_send_transaction = -1;
static int hf_gdsdb_send_msgnr = -1;
static int hf_gdsdb_send_messages = -1;
/* gdsdb_response */
static int hf_gdsdb_response_object = -1;
static int hf_gdsdb_response_blobid = -1;
static int hf_gdsdb_response_data = -1;
static int hf_gdsdb_response_status = -1;
/* gdsdb_transact */
static int hf_gdsdb_transact_database = -1;
static int hf_gdsdb_transact_transaction = -1;
static int hf_gdsdb_transact_messages = -1;
/* gdsdb_transact_response */
static int hf_gdsdb_transactresponse_messages = -1;
/* gdsdb_open_blob2 */
static int hf_gdsdb_openblob2_bpb = -1;
/* gdsdb_open_blob */
static int hf_gdsdb_openblob_transaction = -1;
static int hf_gdsdb_openblob_id = -1;
/* gdsdb_segment */
static int hf_gdsdb_segment_blob = -1;
static int hf_gdsdb_segment_length = -1;
static int hf_gdsdb_segment_segment = -1;
/* gdsdb_seek_blob */
static int hf_gdsdb_seekblob_blob = -1;
static int hf_gdsdb_seekblob_mode = -1;
/* gdsdb_reconnect */
static int hf_gdsdb_reconnect_database = -1;
/* gdsdb_info & gdsdb_service_start */
static int hf_gdsdb_info_object = -1;
static int hf_gdsdb_info_incarnation = -1;
static int hf_gdsdb_info_items = -1;
static int hf_gdsdb_info_buffer_length = -1;
/* gdsdb_release */
static int hf_gdsdb_release_object = -1;
/* gdsdb_prepare2 */
static int hf_gdsdb_prepare2_transaction = -1;
/* gdsdb_event & gdsdb_cancel_events */
static int hf_gdsdb_event_database = -1;
static int hf_gdsdb_event_items = -1;
static int hf_gdsdb_event_ast = -1;
static int hf_gdsdb_event_arg = -1;
static int hf_gdsdb_event_rid = -1;
/* gdsdb_ddl */
static int hf_gdsdb_ddl_database = -1;
static int hf_gdsdb_ddl_transaction = -1;
static int hf_gdsdb_ddl_blr = -1;
/* gdsdb_slice */
static int hf_gdsdb_slice_transaction = -1;
static int hf_gdsdb_slice_id = -1;
static int hf_gdsdb_slice_sdl = -1;
static int hf_gdsdb_slice_parameters = -1;
/* gdsdb_slice_response */
static int hf_gdsdb_sliceresponse_length = -1;
/* gdsdb_execute */
static int hf_gdsdb_execute_statement = -1;
static int hf_gdsdb_execute_transaction = -1;
static int hf_gdsdb_execute_message_number = -1;
static int hf_gdsdb_execute_messages = -1;
/* gdsdb_execute2 */
static int hf_gdsdb_execute_outblr = -1;
static int hf_gdsdb_execute_outmsgnr = -1;
/* gdsdb_exec_immediate2 */
static int hf_gdsdb_prepare2_blr = -1;
static int hf_gdsdb_prepare2_number = -1;
static int hf_gdsdb_prepare2_messages = -1;
static int hf_gdsdb_prepare2_outblr = -1;
static int hf_gdsdb_prepare2_outmsgnr = -1;
/* gdsdb_prepare */
static int hf_gdsdb_prepare_transaction = -1;
static int hf_gdsdb_prepare_statement = -1;
static int hf_gdsdb_prepare_dialect = -1;
static int hf_gdsdb_prepare_querystr = -1;
static int hf_gdsdb_prepare_items = -1;
static int hf_gdsdb_prepare_bufferlength = -1;
/* gdsdb_fetch */
static int hf_gdsdb_fetch_statement = -1;
static int hf_gdsdb_fetch_message_number = -1;
static int hf_gdsdb_fetch_messages = -1;
/* gdsdb_fetch_response */
static int hf_gdsdb_fetchresponse_status = -1;
static int hf_gdsdb_fetchresponse_messages = -1;
/* gdsdb_free_statement */
static int hf_gdsdb_free_statement = -1;
static int hf_gdsdb_free_option = -1;
/* gdsdb_insert */
static int hf_gdsdb_insert_statement = -1;
static int hf_gdsdb_insert_message_number = -1;
static int hf_gdsdb_insert_messages = -1;
/* gdsdb_cursor */
static int hf_gdsdb_cursor_statement = -1;
static int hf_gdsdb_cursor_type = -1;
/* gdsdb_sql_response */
static int hf_gdsdb_sqlresponse_messages = -1;

enum
{
	op_void                   = 0,
	op_connect                = 1,
	op_exit                   = 2,
	op_accept                 = 3,
	op_reject                 = 4,
	op_protocol               = 5,
	op_disconnect             = 6,
	op_credit                 = 7,
	op_continuation           = 8,
	op_response               = 9,
	op_open_file              = 10,
	op_create_file            = 11,
	op_close_file             = 12,
	op_read_page              = 13,
	op_write_page             = 14,
	op_lock                   = 15,
	op_convert_lock           = 16,
	op_release_lock           = 17,
	op_blocking               = 18,
	op_attach                 = 19,
	op_create                 = 20,
	op_detach                 = 21,
	op_compile                = 22,
	op_start                  = 23,
	op_start_and_send         = 24,
	op_send                   = 25,
	op_receive                = 26,
	op_unwind                 = 27,
	op_release                = 28,
	op_transaction            = 29,
	op_commit                 = 30,
	op_rollback               = 31,
	op_prepare                = 32,
	op_reconnect              = 33,
	op_create_blob            = 34,
	op_open_blob              = 35,
	op_get_segment            = 36,
	op_put_segment            = 37,
	op_cancel_blob            = 38,
	op_close_blob             = 39,
	op_info_database          = 40,
	op_info_request           = 41,
	op_info_transaction       = 42,
	op_info_blob              = 43,
	op_batch_segments         = 44,
	op_mgr_set_affinity       = 45,
	op_mgr_clear_affinity     = 46,
	op_mgr_report             = 47,
	op_que_events             = 48,
	op_cancel_events          = 49,
	op_commit_retaining       = 50,
	op_prepare2               = 51,
	op_event                  = 52,
	op_connect_request        = 53,
	op_aux_connect            = 54,
	op_ddl                    = 55,
	op_open_blob2             = 56,
	op_create_blob2           = 57,
	op_get_slice              = 58,
	op_put_slice              = 59,
	op_slice                  = 60,
	op_seek_blob              = 61,
	op_allocate_statement     = 62,
	op_execute                = 63,
	op_exec_immediate         = 64,
	op_fetch                  = 65,
	op_fetch_response         = 66,
	op_free_statement         = 67,
	op_prepare_statement      = 68,
	op_set_cursor             = 69,
	op_info_sql               = 70,
	op_dummy                  = 71,
	op_response_piggyback     = 72,
	op_start_and_receive      = 73,
	op_start_send_and_receive = 74,
	op_exec_immediate2        = 75,
	op_execute2               = 76,
	op_insert                 = 77,
	op_sql_response           = 78,
	op_transact               = 79,
	op_transact_response      = 80,
	op_drop_database          = 81,
	op_service_attach         = 82,
	op_service_detach         = 83,
	op_service_info           = 84,
	op_service_start          = 85,
	op_rollback_retaining     = 86,
	op_max
};

static const value_string gdsdb_opcode[] = {
	{ op_void, "Void" },
	{ op_connect, "Connect" },
	{ op_exit, "Exit" },
	{ op_accept, "Accept" },
	{ op_reject, "Reject" },
	{ op_protocol, "Protocol" },
	{ op_disconnect, "Disconnect" },
	{ op_credit, "Credit" },
	{ op_continuation, "Continuation" },
	{ op_response, "Response" },
	{ op_open_file, "Open file" },
	{ op_create_file, "Create file" },
	{ op_close_file, "Close file" },
	{ op_read_page, "Read page" },
	{ op_write_page, "Write page" },
	{ op_lock, "Lock" },
	{ op_convert_lock, "Convert lock" },
	{ op_release_lock, "Release lock" },
	{ op_blocking, "Blocking" },
	{ op_attach, "Attach" },
	{ op_create, "Create" },
	{ op_detach, "Detach" },
	{ op_compile, "Compile" },
	{ op_start, "Start" },
	{ op_start_and_send, "Start and send" },
	{ op_send, "Send" },
	{ op_receive, "Receive" },
	{ op_unwind, "Unwind" },
	{ op_release, "Release" },
	{ op_transaction, "Transaction" },
	{ op_commit, "Commit" },
	{ op_rollback, "Rollback" },
	{ op_prepare, "Prepare" },
	{ op_reconnect, "Reconnect" },
	{ op_create_blob, "Create blob" },
	{ op_open_blob, "Open blob" },
	{ op_get_segment, "Get segment" },
	{ op_put_segment, "Put segment" },
	{ op_cancel_blob, "Cancel blob" },
	{ op_close_blob, "Close blob" },
	{ op_info_database, "Info database" },
	{ op_info_request, "Info request" },
	{ op_transaction, "Info transaction" },
	{ op_info_blob, "Info blob" },
	{ op_batch_segments, "Batch segments" },
	{ op_mgr_set_affinity, "Mgr set affinity" },
	{ op_mgr_clear_affinity, "Mgr clear affinity" },
	{ op_mgr_report, "Mgr report" },
	{ op_que_events, "Que events" },
	{ op_cancel_events, "Cancel events" },
	{ op_commit_retaining, "Commit retaining" },
	{ op_prepare2, "Prepare 2" },
	{ op_event, "Event" },
	{ op_connect_request, "Connect request" },
	{ op_aux_connect, "Aux connect" },
	{ op_ddl, "DDl" },
	{ op_open_blob2, "Open blob 2" },
	{ op_create_blob2, "Create blob 2" },
	{ op_get_slice, "Get slice" },
	{ op_put_slice, "Put slice" },
	{ op_slice, "Slice" },
	{ op_seek_blob, "Seek blob" },
	{ op_allocate_statement, "Allocate statement" },
	{ op_execute, "Execute" },
	{ op_exec_immediate, "Exec immediate" },
	{ op_fetch, "Fetch" },
	{ op_fetch_response, "Fetch response" },
	{ op_free_statement, "Free statement" },
	{ op_prepare_statement, "Prepare statement" },
	{ op_set_cursor, "Set cursor" },
	{ op_info_sql, "Info sql" },
	{ op_dummy, "Dummy" },
	{ op_response_piggyback, "Response piggyback" },
	{ op_start_and_receive, "Start and receive" },
	{ op_start_send_and_receive, "Start send and receive" },
	{ op_exec_immediate2, "Exec immediate 2" },
	{ op_execute2, "Execute 2" },
	{ op_insert, "Insert" },
	{ op_sql_response, "Sql response" },
	{ op_transact_response, "Transact" },
	{ op_transact_response, "Transact response" },
	{ op_drop_database, "Drop database" },
	{ op_service_attach, "Service attach" },
	{ op_service_detach, "Service detach" },
	{ op_service_info, "Service info" },
	{ op_service_start, "Service start" },
	{ op_rollback_retaining, "Rollback retaining" },
	{ 0, NULL }
};

static const value_string gdsdb_architectures[] = {
	{ 1, "Generic" },
	{ 2, "Apollo" },
	{ 3, "Sun" },
	{ 4, "Vms" },
	{ 5, "Ultrix" },
	{ 6, "Alliant" },
	{ 7, "MS-Dos" },
	{ 8, "Sun 4" },
	{ 9, "Sun 386" },
	{ 10, "HP-UX" },
	{ 11, "HP MPE/xl" },
	{ 12, "Mac" },
	{ 13, "Mac aux" },
	{ 14, "rt" },
	{ 15, "mips Ultrix" },
	{ 16, "HP-UX 68k" },
	{ 17, "Xenix" },
	{ 18, "Aviion" },
	{ 19, "SGI" },
	{ 20, "Apollo_dn10k" },
	{ 21, "Cray" },
	{ 22, "Imp" },
	{ 23, "Delta" },
	{ 24, "SCO" },
	{ 25, "Next" },
	{ 26, "Next 386" },
	{ 27, "m88k" },
	{ 28, "UnixWare" },
	{ 29, "Intel 32" },
	{ 30, "Epson" },
	{ 31, "Decosf" },
	{ 32, "Ncr3000" },
	{ 33, "NT PPC" },
	{ 34, "DG x86" },
	{ 35, "SCO ev" },
	{ 36, "Linux" },
	{ 37, "FreeBSD"  },
	{ 38, "NetBSD" },
	{ 39, "Darwin PPC" },
	{ 0, NULL }
};

static int
gdsdb_dummy(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_)
{
	/* Don't tell them we match */
	return 0;
}

static int
gdsdb_connect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset;
	int length;
	int count;
	int i;
	proto_item *ti;
	proto_tree *pref_tree;

	if (tvb_length(tvb) < 16) {
		return 0;
	}
	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_str(pinfo->cinfo, COL_INFO, ": ");
		col_append_str(pinfo->cinfo, COL_INFO,
			tvb_format_text(tvb, 20,
				tvb_get_ntohl(tvb, 16)));
	}
	if (tree) {
		offset = 4;
		proto_tree_add_item(tree, hf_gdsdb_connect_operation, tvb,
							offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_gdsdb_connect_version, tvb,
							offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_gdsdb_connect_client, tvb,
							offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_gdsdb_connect_filename, tvb,
							offset, 4, ENC_ASCII|ENC_BIG_ENDIAN);
		length = tvb_get_ntohl(tvb, offset);
		offset += length + 6;
		proto_tree_add_item(tree, hf_gdsdb_connect_count, tvb,
							offset, 4, ENC_BIG_ENDIAN);
		count = tvb_get_ntohl(tvb, offset);
		offset += 4;
		proto_tree_add_item(tree, hf_gdsdb_connect_userid, tvb,
							offset, 4, ENC_ASCII|ENC_BIG_ENDIAN);
		length = tvb_get_ntohl(tvb, offset);
		offset += length + 5;
		for(i=0;i<count;i++){
			ti = proto_tree_add_item(tree, hf_gdsdb_connect_pref,
						tvb, offset, 20, ENC_NA);
			pref_tree = proto_item_add_subtree(ti,
						 ett_gdsdb_connect_pref);
			proto_tree_add_item(pref_tree,
					hf_gdsdb_connect_pref_version,
						tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(pref_tree,
					hf_gdsdb_connect_pref_architecture,
						tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(pref_tree,
					hf_gdsdb_connect_pref_mintype,
						tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(pref_tree,
					hf_gdsdb_connect_pref_maxtype,
						tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(pref_tree,
					hf_gdsdb_connect_pref_weight,
						tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
	}

	return tvb_length(tvb);
}

static int
gdsdb_accept(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset;

	if (tvb_length(tvb) < 16) {
		return 0;
	}
	if (tree) {
		offset = 4;
		proto_tree_add_item(tree, hf_gdsdb_accept_version, tvb,
							offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_gdsdb_accept_architecture, tvb,
							offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}

	return tvb_length(tvb);
}

static int
gdsdb_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset;

	if (tvb_length(tvb) < 20) {
		return 0;
	}
	if (tree) {
		offset = 4;
		proto_tree_add_item(tree, hf_gdsdb_request_type, tvb,
						offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_gdsdb_request_object, tvb,
						offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_gdsdb_request_partner, tvb,
						offset, 8, ENC_BIG_ENDIAN);
 	}

	return tvb_length(tvb);
}

static int
gdsdb_attach(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset;
	int length;

	if (tvb_length(tvb) < 20) {
		return 0;
	}
	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_str(pinfo->cinfo, COL_INFO, ": ");
		col_append_str(pinfo->cinfo, COL_INFO,
			tvb_format_text(tvb, 12,
				tvb_get_ntohl(tvb, 8)));
	}
	if (tree) {
		offset = 4;
		proto_tree_add_item(tree, hf_gdsdb_attach_database, tvb,
							offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_gdsdb_attach_filename, tvb,
							offset, 4, ENC_ASCII|ENC_BIG_ENDIAN);
		length = tvb_get_ntohl(tvb, offset);
		offset += length + 6;
		proto_tree_add_uint_format_value(tree,
				hf_gdsdb_attach_dpb, tvb, offset, 4 + length,
					length, "%i data bytes", length);
	}

	return tvb_length(tvb);
}

static int
gdsdb_compile(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset;

	if (tvb_length(tvb) < 20) {
		return 0;
	}
	if (tree) {
		offset = 4;
		proto_tree_add_item(tree, hf_gdsdb_compile_database, tvb,
							offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_gdsdb_compile_blr, tvb,
							offset, 4, ENC_ASCII|ENC_BIG_ENDIAN);
	}

	return tvb_length(tvb);
}

static int
gdsdb_receive(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset;

	if (tvb_length(tvb) < 20) {
		return 0;
	}
	if (tree) {
		offset = 4;
		proto_tree_add_item(tree, hf_gdsdb_receive_request, tvb,
							offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_gdsdb_receive_incarnation, tvb,
							offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_gdsdb_receive_transaction, tvb,
							offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_gdsdb_receive_msgnr, tvb,
							offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_gdsdb_receive_messages, tvb,
							offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		while(tvb_bytes_exist(tvb, offset, 12)) {
			proto_tree_add_item(tree, hf_gdsdb_receive_direction,
						tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(tree, hf_gdsdb_receive_offset,
						 tvb, offset, 8, ENC_BIG_ENDIAN);
			offset += 8;
		}
	}

	return tvb_length(tvb);
}

static int
gdsdb_send(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset;

	if (tvb_length(tvb) < 20) {
		return 0;
	}
	if (tree) {
		offset = 4;
		proto_tree_add_item(tree, hf_gdsdb_send_request, tvb,
							offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_gdsdb_send_incarnation, tvb,
							offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_gdsdb_send_transaction, tvb,
							offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_gdsdb_send_msgnr, tvb,
							offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_gdsdb_send_messages, tvb,
							offset, 4, ENC_BIG_ENDIAN);
	}

	return tvb_length(tvb);
}

static int
gdsdb_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset;
	int length;

	if (tvb_length(tvb) < 32) {
		return 0;
	}
	if (tree) {
		offset = 4;
		proto_tree_add_item(tree, hf_gdsdb_response_object, tvb,
							offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_gdsdb_response_blobid, tvb,
							offset, 8, ENC_BIG_ENDIAN);
		offset += 8;
		proto_tree_add_item(tree, hf_gdsdb_response_data, tvb,
							offset, 4, ENC_ASCII|ENC_BIG_ENDIAN);
		length = tvb_get_ntohl(tvb, offset);
		offset += length + 4;
		proto_tree_add_item(tree, hf_gdsdb_response_status, tvb,
				offset, tvb_length(tvb) - offset, ENC_NA);
	}

	return tvb_length(tvb);

}

static int
gdsdb_transact(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset;

	if (tvb_length(tvb) < 20) {
		return 0;
	}
	if (tree) {
		offset = 4;
		proto_tree_add_item(tree, hf_gdsdb_transact_database, tvb,
							offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_gdsdb_transact_transaction, tvb,
							offset, 4, ENC_BIG_ENDIAN);
	}

	return tvb_length(tvb);
}

static int
gdsdb_transact_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{

	int offset;

	if (tvb_length(tvb) < 8) {
		return 0;
	}
	if (tree) {
		offset = 4;
		proto_tree_add_item(tree, hf_gdsdb_transactresponse_messages,
						tvb, offset, 4, ENC_BIG_ENDIAN);
	}

	return tvb_length(tvb);
}

static int
gdsdb_open_blob2(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset;
	int length;

	if (!tvb_bytes_exist(tvb, 0, 20)) {
		return 0;
	}
	if (tree) {
		offset = 4;
		proto_tree_add_item(tree, hf_gdsdb_openblob2_bpb, tvb, offset,
								4, ENC_ASCII|ENC_BIG_ENDIAN);
		length = tvb_get_ntohl(tvb, offset);
                offset += length + 6;
		proto_tree_add_item(tree, hf_gdsdb_openblob_transaction, tvb,
							offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_gdsdb_openblob_id, tvb, offset,
								8, ENC_BIG_ENDIAN);
	}

	return tvb_length(tvb);
}

static int
gdsdb_open_blob(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset;

	if (tvb_length(tvb) < 16) {
		return 0;
	}
	if (tree) {
		offset = 4;
		proto_tree_add_item(tree, hf_gdsdb_openblob_transaction, tvb,
							offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_gdsdb_openblob_id, tvb, offset,
								8, ENC_BIG_ENDIAN);
	}

	return tvb_length(tvb);
}

static int
gdsdb_segment(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	/* int offset; */

	if (tvb_length(tvb) < 16) {
		return 0;
	}
	if (tree) {
/* hf_gdsdb_segment_blob */
/* hf_gdsdb_segment_length */
/* hf_gdsdb_segment_segment */
	}

	return tvb_length(tvb);
}

static int
gdsdb_seek_blob(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	/* int offset; */

	if (tvb_length(tvb) < 16) {
		return 0;
	}
	if (tree) {
/* hf_gdsdb_seekblob_blob */
/* hf_gdsdb_seekblob_mode */
	}

	return tvb_length(tvb);
}

static int
gdsdb_reconnect(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	/* int offset; */

	if (tvb_length(tvb) < 12) {
		return 0;
	}
	if (tree) {
/* hf_gdsdb_reconnect_database */
	}

	return tvb_length(tvb);
}

static int
gdsdb_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset;
	int length;
	guint opcode;

	if (tvb_length(tvb) < 20) {
		return 0;
	}

	opcode = tvb_get_ntohl(tvb, 0);

	if (tree) {
		offset = 4;
		proto_tree_add_item(tree, hf_gdsdb_info_object, tvb, offset,
								4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_gdsdb_info_incarnation, tvb,
							offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		if(opcode == op_service_info) {
			proto_tree_add_item(tree, hf_gdsdb_info_items, tvb,
							offset, 4, ENC_ASCII|ENC_BIG_ENDIAN);
			length = tvb_get_ntohl(tvb, offset);
			offset += length + 6;
		}
		proto_tree_add_item(tree, hf_gdsdb_info_buffer_length, tvb,
							offset, 4, ENC_BIG_ENDIAN);
	}

	return tvb_length(tvb);
}

static int
gdsdb_service_start(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	/* int offset; */

	if (tvb_length(tvb) < 16) {
		return 0;
	}
	if (tree) {
/* hf_gdsdb_info_object */
/* hf_gdsdb_info_incarnation */
/* hf_gdsdb_info_items */
/* hf_gdsdb_info_buffer_length */
	}

	return tvb_length(tvb);
}

static int
gdsdb_release(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	/* int offset; */

	if (tvb_length(tvb) < 8) {
		return 0;
	}
	if (tree) {
/* hf_gdsdb_release_object */
	}

	return tvb_length(tvb);
}

#if 0
static int
gdsdb_prepare2(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	/* int offset; */

	if (tvb_length(tvb) < 12) {
		return 0;
	}
	if (tree) {
/* hf_gdsdb_prepare2_transaction */
	}

	return tvb_length(tvb);
}
#endif

static int
gdsdb_event(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	 /* int offset; */

	if (tvb_length(tvb) < 24) {
		return 0;
	}
	if (tree) {
/* hf_gdsdb_event_database */
/* hf_gdsdb_event_items */
/* hf_gdsdb_event_ast */
/* hf_gdsdb_event_arg */
/* hf_gdsdb_event_rid */
	}
	return tvb_length(tvb);
}

static int
gdsdb_cancel_events(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	/* int offset; */

	if (tvb_length(tvb) < 12) {
		return 0;
	}
	if (tree) {
/* hf_gdsdb_event_database */
	}

	return tvb_length(tvb);
}

static int
gdsdb_ddl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	/* int offset; */

	if (tvb_length(tvb) < 16) {
		return 0;
	}
	if (tree) {
/* hf_gdsdb_ddl_database */
/* hf_gdsdb_ddl_transaction */
/* hf_gdsdb_ddl_blr */
	}

	return tvb_length(tvb);
}

static int
gdsdb_slice(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	/* int offset; */

	if (tvb_length(tvb) < 24) {
		return 0;
	}
	if (tree) {
/* hf_gdsdb_slice_transaction */
/* hf_gdsdb_slice_id */
/* hf_gdsdb_slice_sdl */
/* hf_gdsdb_slice_parameters */
	}

	return tvb_length(tvb);
}

static int
gdsdb_slice_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	/* int offset; */

	if (tvb_length(tvb) < 8) {
		return 0;
	}
	if (tree) {
/* hf_gdsdb_sliceresponse_length */
	}

	return tvb_length(tvb);
}

static int
gdsdb_execute(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	/* int offset; */

	if (tvb_length(tvb) < 12) {
		return 0;
	}
	if (tree) {
/* hf_gdsdb_execute_statement */
/* hf_gdsdb_execute_transaction */
/* hf_gdsdb_execute_message_number */
/* hf_gdsdb_execute_messages */
	}

	return tvb_length(tvb);
}

static int
gdsdb_exec_immediate2(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	/* int offset; */

	if (tvb_length(tvb) < 44) {
		return 0;
	}
	if (tree) {
/* hf_gdsdb_prepare2_blr */
/* hf_gdsdb_prepare2_number */
/* hf_gdsdb_prepare2_messages */
/* hf_gdsdb_prepare2_outblr */
/* hf_gdsdb_prepare2_outmsgnr */
	}

	return tvb_length(tvb);
}

static int
gdsdb_prepare(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset;
	int length;

	if (tvb_length(tvb) < 32) {
		return 0;
	}
	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_str(pinfo->cinfo, COL_INFO, ": ");
		col_append_str(pinfo->cinfo, COL_INFO,
			tvb_format_text(tvb, 20,
				tvb_get_ntohl(tvb, 16)));
	}
	if(tree) {
		offset = 4;
		proto_tree_add_item(tree, hf_gdsdb_prepare_transaction, tvb,
							offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_gdsdb_prepare_statement, tvb,
							offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_gdsdb_prepare_dialect, tvb,
							offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_gdsdb_prepare_querystr, tvb,
							offset, 4, ENC_ASCII|ENC_BIG_ENDIAN);
		length = tvb_get_ntohl(tvb, offset);
		offset += length + 6;
		proto_tree_add_uint_format_value(tree,
			hf_gdsdb_prepare_items, tvb, offset, 4 + length,
					length, "%i data bytes", length);
        	offset += tvb_get_ntohl(tvb, offset) + 6;
		proto_tree_add_item(tree, hf_gdsdb_prepare_bufferlength, tvb,
							offset, 2, ENC_BIG_ENDIAN);
	}

	return tvb_length(tvb);
}

static int
gdsdb_fetch(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	/* int offset; */

	if (tvb_length(tvb) < 16) {
		return 0;
	}
	if (tree) {
/* hf_gdsdb_fetch_statement */
/* hf_gdsdb_fetch_message_number */
/* hf_gdsdb_fetch_messages */
	}

	return tvb_length(tvb);
}

static int
gdsdb_fetch_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	/* int offset; */

	if (tvb_length(tvb) < 12) {
		return 0;
	}
	if (tree) {
/* hf_gdsdb_fetchresponse_status */
/* hf_gdsdb_fetchresponse_messages */
	}

	return tvb_length(tvb);
}

static int
gdsdb_free_statement(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	/* int offset; */

	if (tvb_length(tvb) < 12) {
		return 0;
	}
	if (tree) {
/* hf_gdsdb_free_statement */
/* hf_gdsdb_free_option */
	}

	return tvb_length(tvb);
}

static int
gdsdb_insert(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	/* int offset; */

	if (tvb_length(tvb) < 16) {
		return 0;
	}
	if (tree) {
/* hf_gdsdb_insert_statement */
/* hf_gdsdb_insert_message_number */
/* hf_gdsdb_insert_messages */
	}

	return tvb_length(tvb);
}

static int
gdsdb_cursor(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	/* int offset; */

	if (tvb_length(tvb) < 16) {
		return 0;
	}
	if (tree) {
/* hf_gdsdb_cursor_statement */
/* hf_gdsdb_cursor_type */
	}

	return tvb_length(tvb);
}

static int
gdsdb_sql_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	/* int offset; */

	if (tvb_length(tvb) < 8) {
		return 0;
	}
	if (tree) {
/* hf_gdsdb_sqlresponse_messages */
	}

	return tvb_length(tvb);
}

static int (*gdsdb_handle_opcode[])(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) = {
	gdsdb_dummy,	/* op_void */
	gdsdb_connect,	/* op_connect */
	gdsdb_dummy,	/* op_exit */
	gdsdb_accept,	/* op_accept */
	gdsdb_dummy,	/* op_reject */
	gdsdb_dummy,	/* op_protocol */
	gdsdb_dummy,	/* op_disconnect */
	gdsdb_dummy,	/* op_credit */
	gdsdb_dummy,	/* op_continuation */
	gdsdb_response,	/* op_response */
	gdsdb_dummy,	/* op_open_file */
	gdsdb_dummy,	/* op_create_file */
	gdsdb_dummy,	/* op_close_file */
	gdsdb_dummy,	/* op_read_page */
	gdsdb_dummy,	/* op_write_page */
	gdsdb_dummy,	/* op_lock */
	gdsdb_dummy,	/* op_convert_lock */
	gdsdb_dummy,	/* op_release_lock */
	gdsdb_dummy,	/* op_blocking */
	gdsdb_attach,	/* op_attach */
	gdsdb_attach,	/* op_create */
	gdsdb_release,	/* op_detach */
	gdsdb_compile,	/* op_compile */
	gdsdb_receive,	/* op_start */
	gdsdb_send,	/* op_start_and_send */
	gdsdb_send,	/* op_send */
	gdsdb_receive,	/* op_receive */
	gdsdb_release,	/* op_unwind */
	gdsdb_release,	/* op_release */
	gdsdb_reconnect,	/* op_transaction */
	gdsdb_release,	/* op_commit */
	gdsdb_release,	/* op_rollback */
	gdsdb_release,	/* op_prepare */
	gdsdb_reconnect,	/* op_reconnect */
	gdsdb_open_blob2,	/* op_create_blob */
	gdsdb_open_blob,	/* op_open_blob */
	gdsdb_segment,	/* op_get_segment */
	gdsdb_segment,	/* op_put_segment */
	gdsdb_release,	/* op_cancel_blob */
	gdsdb_release,	/* op_close_blob */
	gdsdb_info,	/* op_info_database */
	gdsdb_info,	/* op_info_request */
	gdsdb_info,	/* op_info_transaction */
	gdsdb_info,	/* op_info_blob */
	gdsdb_segment,	/* op_batch_segments */
	gdsdb_dummy,	/* op_mgr_set_affinity */
	gdsdb_dummy,	/* op_mgr_clear_affinity */
	gdsdb_dummy,	/* op_mgr_report */
	gdsdb_event,	/* op_que_events */
	gdsdb_cancel_events,	/* op_cancel_events */
	gdsdb_release,	/* op_commit_retaining */
	gdsdb_release,	/* op_prepare */
	gdsdb_event,	/* op_event */
	gdsdb_request,	/* op_connect_request */
	gdsdb_request,	/* op_aux_connect */
	gdsdb_ddl,	/* op_ddl */
	gdsdb_open_blob2,	/* op_open_blob2 */
	gdsdb_open_blob2,	/* op_create_blob2 */
	gdsdb_slice,	/* op_get_slice */
	gdsdb_slice,	/* op_put_slice */
	gdsdb_slice_response,	/* op_slice */
	gdsdb_seek_blob,	/* op_seek_blob */
	gdsdb_release,	/* op_allocate_statement */
	gdsdb_execute,	/* op_execute */
	gdsdb_prepare,	/* op_exec_immediate */
	gdsdb_fetch,	/* op_fetch */
	gdsdb_fetch_response,	/* op_fetch_response */
	gdsdb_free_statement,	/* op_free_statement */
	gdsdb_prepare,	/* op_prepare_statement */
	gdsdb_cursor,	/* op_set_cursor */
	gdsdb_info,	/* op_info_sql */
	gdsdb_dummy,	/* op_dummy */
	gdsdb_response,	/* op_response_piggyback */
	gdsdb_receive,	/* op_start_and_receive */
	gdsdb_send,	/* op_start_send_and_receive */
	gdsdb_exec_immediate2,	/* op_exec_immediate2 */
	gdsdb_execute,	/* op_execute2 */
	gdsdb_insert,	/* op_insert */
	gdsdb_sql_response,	/* op_sql_response */
	gdsdb_transact,	/* op_transact */
	gdsdb_transact_response,	/* op_transact_response */
	gdsdb_release,	/* op_drop_database */
	gdsdb_attach,	/* op_service_attach */
	gdsdb_release,	/* op_service_detach */
	gdsdb_info,	/* op_service_info */
	gdsdb_service_start,	/* op_service_start */
	gdsdb_release	/* op_rollback_retaining */
};

static int
dissect_gdsdb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *gdsdb_tree;
	guint opcode;
	packet_info nopi;

	gdsdb_tree = NULL; /* So the opcode functions can check on if(tree) */
	nopi.cinfo = NULL;

	if (tvb_length(tvb) < 4)
		return 0;

	opcode = tvb_get_ntohl(tvb, 0);
	if(opcode >= op_max)
		return 0;
	if(!gdsdb_handle_opcode[opcode](tvb, &nopi, NULL))
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "GDS DB");

	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_str(pinfo->cinfo, COL_INFO,
				val_to_str(opcode, gdsdb_opcode, "Unknown opcode %u"));

	if (tree) {
		ti = proto_tree_add_item(tree, proto_gdsdb, tvb, 0, -1,
								   ENC_NA);
		gdsdb_tree = proto_item_add_subtree(ti, ett_gdsdb);
		proto_tree_add_item(gdsdb_tree, hf_gdsdb_opcode, tvb,
							0, 4, ENC_BIG_ENDIAN);
	}

	/* opcode < op_max */
	return gdsdb_handle_opcode[opcode](tvb, pinfo, gdsdb_tree);
}

void
proto_register_gdsdb(void)
{
	static hf_register_info hf[] = {
		{ &hf_gdsdb_opcode,
			{ "Opcode", "gdsdb.opcode",
			FT_UINT32, BASE_DEC, VALS(gdsdb_opcode), 0x0,
			NULL, HFILL }
		},
		/* gdsdb_dummy */
		/* gdsdb_connect */
		{ &hf_gdsdb_connect_operation,
			{ "Operation", "gdsdb.connect.operation",
			FT_UINT32, BASE_DEC, VALS(gdsdb_opcode), 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_connect_version,
			{ "Version", "gdsdb.connect.version",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_connect_client,
			{ "Client Architecture", "gdsdb.connect.client",
			FT_UINT32, BASE_DEC, VALS(gdsdb_architectures), 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_connect_filename,
			{ "Filename", "gdsdb.connect.filename",
			FT_UINT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_connect_count,
			{ "Version option count", "gdsdb.connect.count",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_connect_userid,
			{ "User ID", "gdsdb.connect.userid",
			FT_UINT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_connect_pref,
			{ "Preferred version", "gdsdb.connect.pref",
			FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_connect_pref_version,
			{ "Version", "gdsdb.connect.pref.version",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_connect_pref_architecture,
			{ "Architecture", "gdsdb.connect.pref.arch",
			FT_UINT32, BASE_DEC, VALS(gdsdb_architectures), 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_connect_pref_mintype,
			{ "Minimum type", "gdsdb.connect.pref.mintype",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_connect_pref_maxtype,
			{ "Maximum type", "gdsdb.connect.pref.maxtype",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_connect_pref_weight,
			{ "Preference weight", "gdsdb.connect.pref.weight",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_accept */
		{ &hf_gdsdb_accept_version,
			{ "Version", "gdsdb.accept.version",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_accept_architecture,
			{ "Architecture", "gdsdb.accept.arch",
			FT_UINT32, BASE_DEC, VALS(gdsdb_architectures), 0x0,
			NULL, HFILL }
		},
		/* gdsdb_request */
		{ &hf_gdsdb_request_type,
			{ "Type", "gdsdb.connect.type",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_request_object,
			{ "Object", "gdsdb.connect.object",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_request_partner,
			{ "Partner", "gdsdb.connect.partner",
			FT_UINT64, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_attach */
		{ &hf_gdsdb_attach_database,
			{ "Database", "gdsdb.attach.database",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_attach_filename,
			{ "Filename", "gdsdb.attach.filename",
			FT_UINT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_attach_dpb,
			{ "Database parameter block", "gdsdb.attach.dpblength",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_compile */
		{ &hf_gdsdb_compile_database,
			{ "Database", "gdsdb.compile.filename",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_compile_blr,
			{ "BLR", "gdsdb.compile.blr",
			FT_UINT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_receive */
		{ &hf_gdsdb_receive_request,
			{ "Request", "gdsdb.receive.request",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_receive_incarnation,
			{ "Incarnation", "gdsdb.receive.incarnation",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_receive_transaction,
			{ "Transaction", "gdsdb.receive.transaction",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_receive_msgnr,
			{ "Message number", "gdsdb.receive.msgnr",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_receive_messages,
			{ "Message Count", "gdsdb.receive.msgcount",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_receive_direction,
			{ "Scroll direction", "gdsdb.receive.direction",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_receive_offset,
			{ "Scroll offset", "gdsdb.receive.offset",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_send */
		{ &hf_gdsdb_send_request,
			{ "Send request", "gdsdb.send.request",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_send_incarnation,
			{ "Send request", "gdsdb.send.incarnation",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_send_transaction,
			{ "Send request", "gdsdb.send.transaction",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_send_msgnr,
			{ "Send request", "gdsdb.send.msgnr",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_send_messages,
			{ "Send request", "gdsdb.send.messages",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_response */
		{ &hf_gdsdb_response_object,
			{ "Response object", "gdsdb.response.object",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_response_blobid,
			{ "Blob ID", "gdsdb.response.blobid",
			FT_UINT64, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_response_data,
			{ "Data", "gdsdb.response.data",
			FT_UINT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_response_status,
			{ "Status vector", "gdsdb.response.status",
			FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_transact */
		{ &hf_gdsdb_transact_database,
			{ "Database", "gdsdb.transact.database",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_transact_transaction,
			{ "Database", "gdsdb.transact.transaction",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_transact_messages,
			{ "Messages", "gdsdb.transact.messages",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_transact_response */
		{ &hf_gdsdb_transactresponse_messages,
			{ "Messages", "gdsdb.transactresponse.messages",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_open_blob2 */
		{ &hf_gdsdb_openblob2_bpb,
			{ "Blob parameter block", "gdsdb.openblob2.bpb",
			FT_UINT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_open_blob */
		{ &hf_gdsdb_openblob_transaction,
			{ "Transaction", "gdsdb.openblob2.transaction",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_openblob_id,
			{ "ID", "gdsdb.openblob.id",
			FT_UINT64, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_segment */
		{ &hf_gdsdb_segment_blob,
			{ "Blob", "gdsdb.segment.blob",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_segment_length,
			{ "Length", "gdsdb.segment.length",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_segment_segment,
			{ "Segment", "gdsdb.segment.segment",
			FT_UINT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_seek_blob */
		{ &hf_gdsdb_seekblob_blob,
			{ "Blob", "gdsdb.seekblob.blob",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_seekblob_mode,
			{ "Mode", "gdsdb.seekblob.mode",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_reconnect */
		{ &hf_gdsdb_reconnect_database,
			{ "Database", "gdsdb.reconnect.database",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_info & gdsdb_service_start */
		{ &hf_gdsdb_info_object,
			{ "Object", "gdsdb.info.object",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_info_incarnation,
			{ "Incarnation", "gdsdb.info.incarnation",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_info_items,
			{ "Items", "gdsdb.info.items",
			FT_UINT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_info_buffer_length,
			{ "Buffer length", "gdsdb.info.bufferlength",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_release */
		{ &hf_gdsdb_release_object,
			{ "Object", "gdsdb.release.object",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_prepare2 */
		{ &hf_gdsdb_prepare2_transaction,
			{ "Transaction", "gdsdb.prepare2.transaction",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_event & gdsdb_cancel_events */
		{ &hf_gdsdb_event_database,
			{ "Database", "gdsdb.event.database",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_event_items,
			{ "Event description block", "gdsdb.event.items",
			FT_UINT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_event_ast,
			{ "ast routine", "gdsdb.event.ast",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_event_arg,
			{ "Argument to ast routine", "gdsdb.event.arg",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_event_rid,
			{ "ID", "gdsdb.event.id",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_ddl */
		{ &hf_gdsdb_ddl_database,
			{ "Database", "gdsdb.ddl.database",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_ddl_transaction,
			{ "Transaction", "gdsdb.ddl.transaction",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_ddl_blr,
			{ "BLR", "gdsdb.ddl.blr",
			FT_UINT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_slice */
		{ &hf_gdsdb_slice_transaction,
			{ "Transaction", "gdsdb.slice.transaction",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_slice_id,
			{ "ID", "gdsdb.slice.id",
			FT_UINT64, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_slice_sdl,
			{ "Slice description language", "gdsdb.slice.sdl",
			FT_UINT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_slice_parameters,
			{ "Parameters", "gdsdb.slice.parameters",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_slice_response */
		{ &hf_gdsdb_sliceresponse_length,
			{ "Length", "gdsdb.sliceresponse.length",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_execute */
		{ &hf_gdsdb_execute_statement,
			{ "Statement", "gdsdb.execute.statement",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_execute_transaction,
			{ "Transaction", "gdsdb.execute.transaction",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_execute_message_number,
			{ "Message number", "gdsdb.execute.messagenumber",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_execute_messages,
			{ "Number of messages", "gdsdb.execute.messages",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_execute2 */
		{ &hf_gdsdb_execute_outblr,
			{ "Output BLR", "gdsdb.execute.outblr",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_execute_outmsgnr,
			{ "Output Message number", "gdsdb.execute.outmsgnr",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_exec_immediate2 */
		{ &hf_gdsdb_prepare2_blr,
			{ "BLR", "gdsdb.prepare.blr",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_prepare2_number,
			{ "Message number", "gdsdb.prepare2.messagenumber",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_prepare2_messages,
			{ "Number of messages", "gdsdb.prepare2.messages",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_prepare2_outblr,
			{ "Output BLR", "gdsdb.prepare2.outblr",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_prepare2_outmsgnr,
			{ "Output Message number", "gdsdb.prepare2.outmsgnr",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_prepare */
		{ &hf_gdsdb_prepare_transaction,
			{ "Prepare, Transaction", "gdsdb.prepare.transaction",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_prepare_statement,
			{ "Prepare, Statement", "gdsdb.prepare.statement",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_prepare_dialect,
			{ "Prepare, Dialect", "gdsdb.prepare.dialect",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_prepare_querystr,
			{ "Prepare, Query", "gdsdb.prepare.querystr",
			FT_UINT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_prepare_items,
			{ "Prepare, Information items", "gdsdb.prepare.items",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_prepare_bufferlength,
			{ "Prepare, Bufferlength", "gdsdb.prepare.bufferlen",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_fetch */
		{ &hf_gdsdb_fetch_statement,
			{ "Statement", "gdsdb.fetch.statement",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_fetch_message_number,
			{ "Message number", "gdsdb.fetch.messagenr",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_fetch_messages,
			{ "Number of messages", "gdsdb.fetch.messages",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_fetch_response */
		{ &hf_gdsdb_fetchresponse_status,
			{ "Status", "gdsdb.fetchresponse.status",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_fetchresponse_messages,
			{ "Number of messages", "gdsdb.fetchresponse.messages",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_free_statement */
		{ &hf_gdsdb_free_statement,
			{ "Statement", "gdsdb.fetchresponse.statement",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_free_option,
			{ "Option", "gdsdb.fetchresponse.option",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_insert */
		{ &hf_gdsdb_insert_statement,
			{ "Statement", "gdsdb.insert.statement",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_insert_message_number,
			{ "Message number", "gdsdb.insert.messagenr",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_insert_messages,
			{ "Number of messages", "gdsdb.insert.messages",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_cursor */
		{ &hf_gdsdb_cursor_statement,
			{ "Statement", "gdsdb.cursor.statement",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gdsdb_cursor_type,
			{ "Type", "gdsdb.cursor.type",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		/* gdsdb_sql_response */
		{ &hf_gdsdb_sqlresponse_messages,
			{ "SQL Response, Message Count", "gdsdb.sqlresponse.msgcount",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		}
	};

	static gint *ett[] = {
		&ett_gdsdb,
		&ett_gdsdb_opcode,
		&ett_gdsdb_connect_pref
	};

	proto_gdsdb = proto_register_protocol(
		"Firebird SQL Database Remote Protocol",
		"FB/IB GDS DB", "gdsdb");

        proto_register_field_array(proto_gdsdb, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_gdsdb(void)
{
	/* Main dissector */

	dissector_handle_t gdsdb_handle;

	gdsdb_handle = new_create_dissector_handle(dissect_gdsdb,
								 proto_gdsdb);
	dissector_add_uint("tcp.port", TCP_PORT, gdsdb_handle);
}

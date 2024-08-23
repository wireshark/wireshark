/* packet-nbd.c
 * Routines for Network Block Device (NBD) dissection.
 *
 * https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md
 *
 * Ronnie sahlberg 2006
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/unit_strings.h>
#include <epan/tfs.h>
#include <wsutil/array.h>
#include "packet-tcp.h"
#include "packet-tls-utils.h"

void proto_register_nbd(void);
void proto_reg_handoff_nbd(void);

static int proto_nbd;
static int hf_nbd_hnd_magic;
static int hf_nbd_hnd_flags;
static int hf_nbd_hnd_flags_fixed_new;
static int hf_nbd_hnd_flags_no_zeroes;
static int hf_nbd_hnd_opt;
static int hf_nbd_hnd_reply;
static int hf_nbd_cli_flags;
static int hf_nbd_cli_flags_fixed_new;
static int hf_nbd_cli_flags_no_zeroes;
static int hf_nbd_magic;
static int hf_nbd_cmd_flags;
static int hf_nbd_cmd_flags_fua;
static int hf_nbd_cmd_flags_no_hole;
static int hf_nbd_cmd_flags_df;
static int hf_nbd_cmd_flags_req_one;
static int hf_nbd_cmd_flags_fast_zero;
static int hf_nbd_cmd_flags_payload_len;
static int hf_nbd_reply_flags;
static int hf_nbd_reply_flags_done;
static int hf_nbd_export_size;
static int hf_nbd_trans_flags;
static int hf_nbd_trans_flags_has_flags;
static int hf_nbd_trans_flags_read_only;
static int hf_nbd_trans_flags_flush;
static int hf_nbd_trans_flags_fua;
static int hf_nbd_trans_flags_rotational;
static int hf_nbd_trans_flags_trim;
static int hf_nbd_trans_flags_write_zeroes;
static int hf_nbd_trans_flags_df;
static int hf_nbd_trans_flags_multi_conn;
static int hf_nbd_trans_flags_resize;
static int hf_nbd_trans_flags_cache;
static int hf_nbd_trans_flags_fast_zero;
static int hf_nbd_trans_flags_block_status_payload;
static int hf_nbd_reserved;
static int hf_nbd_type;
static int hf_nbd_reply_type;
static int hf_nbd_error;
static int hf_nbd_handle;
static int hf_nbd_from;
static int hf_nbd_len;
static int hf_nbd_response_in;
static int hf_nbd_response_to;
static int hf_nbd_time;
static int hf_nbd_export_name_len;
static int hf_nbd_export_name;
static int hf_nbd_info_num;
static int hf_nbd_info;
static int hf_nbd_query_num;
static int hf_nbd_query;
static int hf_nbd_export_description;
static int hf_nbd_block_size_min;
static int hf_nbd_block_size_prefer;
static int hf_nbd_payload_size_max;
static int hf_nbd_meta_context_id;
static int hf_nbd_meta_context_name;
static int hf_nbd_error_msg_len;
static int hf_nbd_error_msg;
static int hf_nbd_data;
static int hf_nbd_hole_size;
static int hf_nbd_status_flags;

static int ett_nbd;
static int ett_nbd_hnd_flags;
static int ett_nbd_cli_flags;
static int ett_nbd_cmd_flags;
static int ett_nbd_reply_flags;
static int ett_nbd_trans_flags;

static expert_field ei_nbd_hnd_reply_error;
static expert_field ei_nbd_unexpected_data;

static dissector_handle_t nbd_handle;
static dissector_handle_t tls_handle;

static bool nbd_desegment = true;

static void apply_nbd_prefs(void);

#define NBD_TCP_PORTS "10809" /* IANA-registered */

static range_t *nbd_port_range;

typedef struct _nbd_transaction_t {
	uint32_t req_frame;
	uint32_t rep_frame;
	nstime_t req_time;
	uint32_t datalen;
	uint16_t type;
} nbd_transaction_t;
typedef struct _nbd_option_t {
	uint32_t req_frame;
	uint32_t rep_frame;
	nstime_t req_time;
	uint32_t opt;
} nbd_option_t;
typedef struct _nbd_conv_info_t {
	bool no_zeroes;
	wmem_tree_t *state;
	wmem_tree_t *opts;	/* indexed by packet# (per spec, client MUST not send
				   a new option until reply received for previous */
	wmem_tree_t *unacked_pdus;    /* indexed by handle, which wraps quite frequently  */
	wmem_tree_t *acked_pdus;    /* indexed by packet# and handle */
} nbd_conv_info_t;

typedef enum _nbd_state_e {
	STATE_UNK = 0,
	STATE_HND_INIT,
	STATE_HND_OPT,
	STATE_HND_DONE
} nbd_state_e;

#define NBD_HND_INIT_MAGIC	0x4e42444d41474943 // "NBDMAGIC"
#define NBD_HND_OPT_MAGIC	0x49484156454F5054 // "IHAVEOPT"
#define NBD_HND_REPLY_MAGIC	0x03e889045565a9
#define NBD_HND_OLD_MAGIC	0x00420281861253

#define NBD_REQUEST_MAGIC		0x25609513
#define NBD_RESPONSE_MAGIC		0x67446698
#define NBD_STRUCTURED_REPLY_MAGIC	0x668e33ef

#define NBD_OPT_EXPORT_NAME	1
#define NBD_OPT_ABORT		2
#define NBD_OPT_LIST		3
#define NBD_OPT_PEEK_EXPORT	4
#define NBD_OPT_STARTTLS	5
#define NBD_OPT_INFO		6
#define NBD_OPT_GO		7
#define NBD_OPT_STRUCTURED_REPLY	8
#define NBD_OPT_LIST_META_CONTEXT	9
#define NBD_OPT_SET_META_CONTEXT	10
#define NBD_OPT_EXTENDED_HEADERS	11

static const value_string nbd_opt_vals[] = {
	{NBD_OPT_EXPORT_NAME,	"Export Name"},
	{NBD_OPT_ABORT,		"Abort"},
	{NBD_OPT_LIST,		"List"},
	{NBD_OPT_PEEK_EXPORT,	"Peek Export"}, // Withdrawn
	{NBD_OPT_STARTTLS,	"STARTTLS"},
	{NBD_OPT_INFO,		"Info"},
	{NBD_OPT_GO,		"Go"},
	{NBD_OPT_STRUCTURED_REPLY,	"Structured Reply"},
	{NBD_OPT_LIST_META_CONTEXT,	"List Metadata Contexts"},
	{NBD_OPT_SET_META_CONTEXT,	"Set Metadata Contexts"},
	{NBD_OPT_EXTENDED_HEADERS,	"Extended Headers"},
	{0, NULL}
};

#define NBD_INFO_EXPORT	0
#define NBD_INFO_NAME	1
#define NBD_INFO_DESCRIPTION	2
#define NBD_INFO_BLOCK_SIZE	3

static const value_string nbd_info_vals[] = {
	{NBD_INFO_EXPORT,	"Export"},
	{NBD_INFO_NAME,	"Name"},
	{NBD_INFO_DESCRIPTION,	"Description"},
	{NBD_INFO_BLOCK_SIZE,	"Block Size"},
	{0, NULL}
};

#define NBD_REP_ACK	1
#define NBD_REP_SERVER	2
#define NBD_REP_INFO	3
#define NBD_REP_META_CONTEXT	4
#define NBD_REP_ERR_UNSUP	UINT32_C((1 << 31) + 1)
#define NBD_REP_ERR_POLICY	UINT32_C((1 << 31) + 2)
#define NBD_REP_ERR_INVALID	UINT32_C((1 << 31) + 3)
#define NBD_REP_ERR_PLATFORM	UINT32_C((1 << 31) + 4)
#define NBD_REP_ERR_TLS_REQD	UINT32_C((1 << 31) + 5)
#define NBD_REP_ERR_UNKNOWN	UINT32_C((1 << 31) + 6)
#define NBD_REP_ERR_SHUTDOWN	UINT32_C((1 << 31) + 7)
#define NBD_REP_ERR_BLOCK_SIZE_REQD	UINT32_C((1 << 31) + 8)
#define NBD_REP_ERR_TOO_BIG	UINT32_C((1 << 31) + 9)
#define NBD_REP_ERR_EXT_HEADER_REQD	UINT32_C((1 << 31) + 10)

static const value_string nbd_hnd_reply_vals[] = {
	{NBD_REP_ACK,	"ACK"},
	{NBD_REP_SERVER,	"Server"},
	{NBD_REP_INFO,	"Information"},
	{NBD_REP_META_CONTEXT,	"Metadata Context"},
	{NBD_REP_ERR_UNSUP,	"Unknown option"},
	{NBD_REP_ERR_POLICY,	"Forbidden by policy"},
	{NBD_REP_ERR_INVALID,	"Syntactically or semantically invalid"},
	{NBD_REP_ERR_PLATFORM,	"Unsupported by platform or as compiled"},
	{NBD_REP_ERR_TLS_REQD,	"TLS required"},
	{NBD_REP_ERR_UNKNOWN,	"Export not available"},
	{NBD_REP_ERR_SHUTDOWN,	"Server shutdown in process"},
	{NBD_REP_ERR_BLOCK_SIZE_REQD,	"Export requires negotiating non-default block size support"},
	{NBD_REP_ERR_TOO_BIG,	"Request or reply too large to process"},
	{NBD_REP_ERR_EXT_HEADER_REQD,	"Export requires negotiating extended header support"},
	{0, NULL}
};

#define NBD_CMD_READ			0
#define NBD_CMD_WRITE			1
#define NBD_CMD_DISC			2
#define NBD_CMD_FLUSH			3
#define NBD_CMD_TRIM 			4
#define NBD_CMD_CACHE			5
#define NBD_CMD_WRITE_ZEROES		6
#define NBD_CMD_BLOCK_STATUS		7
#define NBD_CMD_RESIZE			8

static const value_string nbd_type_vals[] = {
	{NBD_CMD_READ,	"Read"},
	{NBD_CMD_WRITE,	"Write"},
	{NBD_CMD_DISC,	"Disconnect"},
	{NBD_CMD_FLUSH,	"Flush"},
	{NBD_CMD_TRIM,	"Trim"},
	{NBD_CMD_CACHE,	"Cache"},
	{NBD_CMD_WRITE_ZEROES,	"Write Zeroes"},
	{NBD_CMD_BLOCK_STATUS,	"Block Status"},
	{NBD_CMD_RESIZE,	"Resize"},
	{0, NULL}
};

#define NBD_REPLY_NONE		0
#define NBD_REPLY_OFFSET_DATA	1
#define NBD_REPLY_OFFSET_HOLE	2
#define NBD_REPLY_BLOCK_STATUS	5
#define NBD_REPLY_BLOCK_STATUS_EXT 6
#define NBD_REPLY_ERROR		32769
#define NBD_REPLY_ERROR_OFFSET	32770

static const value_string nbd_reply_type_vals[] = {
	{NBD_REPLY_NONE,		"NBD_REPLY_NONE"},
	{NBD_REPLY_OFFSET_DATA,		"NBD_REPLY_OFFSET_DATA"},
	{NBD_REPLY_OFFSET_HOLE,		"NBD_REPLY_OFFSET_HOLE"},
	{NBD_REPLY_BLOCK_STATUS,	"NBD_REPLY_BLOCK_STATUS"},
	{NBD_REPLY_BLOCK_STATUS_EXT,	"NBD_REPLY_BLOCK_STATUS_EXT"},
	{NBD_REPLY_ERROR,		"NBD_REPLY_ERROR"},
	{NBD_REPLY_ERROR_OFFSET,	"NBD_REPLY_ERROR_OFFSET"},
	{0, NULL}
};

#define NBD_SUCCESS	0
#define NBD_EPERM	1
#define NBD_EIO		5
#define NBD_ENOMEM	12
#define NBD_EINVAL	22
#define NBD_ENOSPC	28
#define NBD_EOVERFLOW	75
#define NBD_ENOTSUP	95
#define NBD_ESHUTDOWN	108

static const value_string nbd_error_vals[] = {
	{NBD_SUCCESS,	"Success"},
	{NBD_EPERM,	"Operation not pemitted"},
	{NBD_EIO,	"Input/output error"},
	{NBD_ENOMEM,	"Cannot allocate memory"},
	{NBD_EINVAL,	"Invalid argument"},
	{NBD_ENOSPC,	"No space left on device"},
	{NBD_EOVERFLOW,	"Value too large"},
	{NBD_ENOTSUP,	"Operation not supported"},
	{NBD_ESHUTDOWN,	"Server is in the process of being shut down"},
	{0, NULL}
};

#define NBD_FLAG_NO_ZEROES 0x0002

static bool
nbd_from_server(packet_info *pinfo)
{
	if (value_is_in_range(nbd_port_range, pinfo->srcport)) {
		return true;
	} else if (value_is_in_range(nbd_port_range, pinfo->destport)) {
		return false;
	}
	return false;
}

static nbd_conv_info_t*
get_nbd_conv_info(packet_info *pinfo)
{
	conversation_t *conversation;
	nbd_conv_info_t *nbd_info;

	conversation = find_or_create_conversation(pinfo);

	/*
	 * Do we already have a state structure for this conv
	 */
	nbd_info = (nbd_conv_info_t *)conversation_get_proto_data(conversation, proto_nbd);

	if (!nbd_info) {
		/* No.  Attach that information to the conversation, and add
		 * it to the list of information structures.
		 */
		nbd_info = wmem_new(wmem_file_scope(), nbd_conv_info_t);
		nbd_info->no_zeroes    = false;
		nbd_info->state        = wmem_tree_new(wmem_file_scope());
		nbd_info->opts         = wmem_tree_new(wmem_file_scope());
		nbd_info->unacked_pdus = wmem_tree_new(wmem_file_scope());
		nbd_info->acked_pdus   = wmem_tree_new(wmem_file_scope());

		conversation_add_proto_data(conversation, proto_nbd, nbd_info);
	}
	return nbd_info;
}

static void
nbd_set_state(packet_info *pinfo, nbd_state_e state)
{
	nbd_conv_info_t *nbd_info;
	nbd_state_e current_state;

	nbd_info = get_nbd_conv_info(pinfo);
	current_state = (nbd_state_e)GPOINTER_TO_UINT(wmem_tree_lookup32_le(nbd_info->state, pinfo->num));
	if (current_state != state) {
		wmem_tree_insert32(nbd_info->state, pinfo->num, GUINT_TO_POINTER(state));
	}
}

/* This function will try to determine the complete size of a PDU
 * based on the information in the header.
 */
static unsigned
get_nbd_tcp_pdu_len(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data _U_)
{
	uint32_t magic, type, packet;
	conversation_t *conversation;
	nbd_conv_info_t *nbd_info;
	nbd_transaction_t *nbd_trans=NULL;
	wmem_tree_key_t hkey[3];
	uint32_t handle[2];

	magic=tvb_get_ntohl(tvb, offset);

	switch(magic){
	case NBD_REQUEST_MAGIC:
		type=tvb_get_ntohs(tvb, offset+6);
		switch(type){
		case NBD_CMD_WRITE:
			return tvb_get_ntohl(tvb, offset+24)+28;
		default:
			/*
			 * NB: Length field should always be present (and zero)
			 * for other types too.
			 */
			return 28;
		}
	case NBD_RESPONSE_MAGIC:
		/*
		 * Do we have a conversation for this connection?
		 */
		conversation = find_conversation_pinfo(pinfo, 0);
		if (conversation == NULL) {
			/* No, so just return the rest of the current packet */
			return tvb_captured_length(tvb);
		}
		/*
		 * Do we have a state structure for this conv
		 */
		nbd_info = (nbd_conv_info_t *)conversation_get_proto_data(conversation, proto_nbd);
		if (!nbd_info) {
			/* No, so just return the rest of the current packet */
			return tvb_captured_length(tvb);
		}
		if(!pinfo->fd->visited){
			/*
			 * Do we have a state structure for this transaction
			 */
			handle[0]=tvb_get_ntohl(tvb, offset+8);
			handle[1]=tvb_get_ntohl(tvb, offset+12);
			hkey[0].length=2;
			hkey[0].key=handle;
			hkey[1].length=0;
			nbd_trans=(nbd_transaction_t *)wmem_tree_lookup32_array(nbd_info->unacked_pdus, hkey);
			if(!nbd_trans){
				/* No, so just return the rest of the current packet */
				return tvb_captured_length(tvb);
			}
		} else {
			/*
			 * Do we have a state structure for this transaction
			 */
			handle[0]=tvb_get_ntohl(tvb, offset+8);
			handle[1]=tvb_get_ntohl(tvb, offset+12);
			packet=pinfo->num;
			hkey[0].length=1;
			hkey[0].key=&packet;
			hkey[1].length=2;
			hkey[1].key=handle;
			hkey[2].length=0;
			nbd_trans=(nbd_transaction_t *)wmem_tree_lookup32_array(nbd_info->acked_pdus, hkey);
			if(!nbd_trans){
				/* No, so just return the rest of the current packet */
				return tvb_captured_length(tvb);
			}
		}
		/* If this is a read response we must add the datalen to
		 * the pdu size
		 */
		if(nbd_trans->type==NBD_CMD_READ){
			return 16+nbd_trans->datalen;
		} else {
			return 16;
		}
	case NBD_STRUCTURED_REPLY_MAGIC:
		return tvb_get_ntohl(tvb, offset+16)+20;
	default:
		break;
	}

	/* Did not really look like a NBD packet after all */
	return 0;
}

static int * const nbd_cmd_flags[] = {
	&hf_nbd_cmd_flags_fua,
	&hf_nbd_cmd_flags_no_hole,
	&hf_nbd_cmd_flags_df,
	&hf_nbd_cmd_flags_req_one,
	&hf_nbd_cmd_flags_fast_zero,
	&hf_nbd_cmd_flags_payload_len,
	NULL,
};

static int * const nbd_reply_flags[] = {
	&hf_nbd_reply_flags_done,
	NULL,
};

static int * const nbd_trans_flags[] = {
	&hf_nbd_trans_flags_has_flags,
	&hf_nbd_trans_flags_read_only,
	&hf_nbd_trans_flags_flush,
	&hf_nbd_trans_flags_fua,
	&hf_nbd_trans_flags_rotational,
	&hf_nbd_trans_flags_trim,
	&hf_nbd_trans_flags_write_zeroes,
	&hf_nbd_trans_flags_df,
	&hf_nbd_trans_flags_multi_conn,
	&hf_nbd_trans_flags_resize,
	&hf_nbd_trans_flags_cache,
	&hf_nbd_trans_flags_fast_zero,
	&hf_nbd_trans_flags_block_status_payload,
	NULL,
};

static int
dissect_nbd_structured_reply(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned type)
{
	proto_item *item;
	int offset = 0;
	uint32_t len;

	switch (type) {
	case NBD_REPLY_OFFSET_DATA:
		proto_tree_add_item(tree, hf_nbd_from, tvb, offset, 8, ENC_BIG_ENDIAN);
		offset += 8;

		proto_tree_add_item(tree, hf_nbd_data, tvb, offset, -1, ENC_NA);
		offset = tvb_reported_length(tvb);
		break;

	case NBD_REPLY_OFFSET_HOLE:
		proto_tree_add_item(tree, hf_nbd_from, tvb, offset, 8, ENC_BIG_ENDIAN);
		offset += 8;

		proto_tree_add_item(tree, hf_nbd_hole_size, tvb, offset, 4, ENC_NA);
		offset = tvb_reported_length(tvb);
		break;

	case NBD_REPLY_BLOCK_STATUS:
		proto_tree_add_item(tree, hf_nbd_meta_context_id, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		while (tvb_reported_length_remaining(tvb, offset)) {
			proto_tree_add_item(tree, hf_nbd_len, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(tree, hf_nbd_status_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
		break;

	case NBD_REPLY_ERROR:
		proto_tree_add_item(tree, hf_nbd_error, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item_ret_uint(tree, hf_nbd_error_msg_len, tvb, offset, 2, ENC_BIG_ENDIAN, &len);
		offset += 2;
		proto_tree_add_item(tree, hf_nbd_error_msg, tvb, offset, len, ENC_UTF_8);
		break;

	case NBD_REPLY_ERROR_OFFSET:
		proto_tree_add_item(tree, hf_nbd_error, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item_ret_uint(tree, hf_nbd_error_msg_len, tvb, offset, 2, ENC_BIG_ENDIAN, &len);
		offset += 2;
		proto_tree_add_item(tree, hf_nbd_error_msg, tvb, offset, len, ENC_UTF_8);
		offset += len;
		proto_tree_add_item(tree, hf_nbd_from, tvb, offset, 8, ENC_BIG_ENDIAN);
		offset += 8;
	}

	if (tvb_reported_length_remaining(tvb, offset)) {
		item = proto_tree_add_item(tree, hf_nbd_data, tvb, offset, -1, ENC_NA);
		expert_add_info(pinfo, item, &ei_nbd_unexpected_data);
	}

	return tvb_reported_length(tvb);
}

static int
dissect_nbd_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
	uint32_t magic, error, packet, data_len, type;
	uint32_t handle[2];
	uint64_t from;
	int offset=0;
	proto_tree *tree=NULL;
	proto_item *item=NULL;
	nbd_conv_info_t *nbd_info;
	nbd_transaction_t *nbd_trans=NULL;
	wmem_tree_key_t hkey[3];

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NBD");

	col_clear(pinfo->cinfo, COL_INFO);

	item = proto_tree_add_item(parent_tree, proto_nbd, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_nbd);


	magic=tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(tree, hf_nbd_magic, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset+=4;


	/* grab what we need to do the request/response matching */
	switch(magic){
	case NBD_REQUEST_MAGIC:
	case NBD_RESPONSE_MAGIC:
	case NBD_STRUCTURED_REPLY_MAGIC:
		handle[0]=tvb_get_ntohl(tvb, offset+4);
		handle[1]=tvb_get_ntohl(tvb, offset+8);
		break;
	default:
		return 4;
	}

	nbd_info = get_nbd_conv_info(pinfo);
	if(!pinfo->fd->visited){
		switch (magic) {
		case NBD_REQUEST_MAGIC:
			/* This is a request */
			nbd_trans=wmem_new(wmem_file_scope(), nbd_transaction_t);
			nbd_trans->req_frame=pinfo->num;
			nbd_trans->rep_frame=0;
			nbd_trans->req_time=pinfo->abs_ts;
			nbd_trans->type=tvb_get_ntohl(tvb, offset);
			nbd_trans->datalen=tvb_get_ntohl(tvb, offset+20);

			hkey[0].length=2;
			hkey[0].key=handle;
			hkey[1].length=0;

			wmem_tree_insert32_array(nbd_info->unacked_pdus, hkey, (void *)nbd_trans);
			break;

		case NBD_RESPONSE_MAGIC:
		case NBD_STRUCTURED_REPLY_MAGIC:
			/* There MAY be multiple structured reply chunk to the
			 * same request (with the same cookie/handle), instead
			 * of TCP segmentation. In that case the later ones
			 * will replace the older ones for matching.
			 */
			hkey[0].length=2;
			hkey[0].key=handle;
			hkey[1].length=0;

			nbd_trans=(nbd_transaction_t *)wmem_tree_lookup32_array(nbd_info->unacked_pdus, hkey);
			if(nbd_trans){
				nbd_trans->rep_frame=pinfo->num;

				hkey[0].length=1;
				hkey[0].key=&nbd_trans->rep_frame;
				hkey[1].length=2;
				hkey[1].key=handle;
				hkey[2].length=0;
				wmem_tree_insert32_array(nbd_info->acked_pdus, hkey, (void *)nbd_trans);
				hkey[0].length=1;
				hkey[0].key=&nbd_trans->req_frame;
				hkey[1].length=2;
				hkey[1].key=handle;
				hkey[2].length=0;
				wmem_tree_insert32_array(nbd_info->acked_pdus, hkey, (void *)nbd_trans);
			}
			break;
		default:
			ws_assert_not_reached();
		}
	} else {
		packet=pinfo->num;
		hkey[0].length=1;
		hkey[0].key=&packet;
		hkey[1].length=2;
		hkey[1].key=handle;
		hkey[2].length=0;

		nbd_trans=(nbd_transaction_t *)wmem_tree_lookup32_array(nbd_info->acked_pdus, hkey);
	}
	/* The bloody handles are reused !!! even though they are 64 bits.
	 * So we must verify we got the "correct" one
	 */
	if( (magic==NBD_RESPONSE_MAGIC || magic==NBD_STRUCTURED_REPLY_MAGIC)
	&&  (nbd_trans)
	&&  (pinfo->num<nbd_trans->req_frame) ){
		/* must have been the wrong one */
		nbd_trans=NULL;
	}

	if(!nbd_trans){
		/* create a "fake" nbd_trans structure */
		nbd_trans=wmem_new(pinfo->pool, nbd_transaction_t);
		nbd_trans->req_frame=0;
		nbd_trans->rep_frame=0;
		nbd_trans->req_time=pinfo->abs_ts;
		if (magic == NBD_REQUEST_MAGIC) {
			nbd_trans->type=tvb_get_ntohl(tvb, offset);
			nbd_trans->datalen=tvb_get_ntohl(tvb, offset+20);
		} else {
			nbd_trans->type=0xffff;
			nbd_trans->datalen=0;
		}
	}

	/* print state tracking in the tree */
	switch (magic) {
	case NBD_REQUEST_MAGIC:
		/* This is a request */
		if(nbd_trans->rep_frame){
			proto_item *it;

			it=proto_tree_add_uint(tree, hf_nbd_response_in, tvb, 0, 0, nbd_trans->rep_frame);
			proto_item_set_generated(it);
		}
		break;
	case NBD_RESPONSE_MAGIC:
	case NBD_STRUCTURED_REPLY_MAGIC:
		/* This is a reply */
		if(nbd_trans->req_frame){
			proto_item *it;
			nstime_t ns;

			it=proto_tree_add_uint(tree, hf_nbd_response_to, tvb, 0, 0, nbd_trans->req_frame);
			proto_item_set_generated(it);

			nstime_delta(&ns, &pinfo->abs_ts, &nbd_trans->req_time);
			it=proto_tree_add_time(tree, hf_nbd_time, tvb, 0, 0, &ns);
			proto_item_set_generated(it);
		}
	}


	switch(magic){
	case NBD_REQUEST_MAGIC:
		proto_tree_add_bitmask(tree, tvb, offset, hf_nbd_cmd_flags,
			ett_nbd_cmd_flags, nbd_cmd_flags, ENC_BIG_ENDIAN);
		offset+=2;

		proto_tree_add_item(tree, hf_nbd_type, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;

		proto_tree_add_item(tree, hf_nbd_handle, tvb, offset, 8, ENC_BIG_ENDIAN);
		offset+=8;

		from=tvb_get_ntoh64(tvb, offset);
		proto_tree_add_item(tree, hf_nbd_from, tvb, offset, 8, ENC_BIG_ENDIAN);
		offset+=8;

		proto_tree_add_item(tree, hf_nbd_len, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset+=4;

		col_add_fstr(pinfo->cinfo, COL_INFO, "%s Request", val_to_str(nbd_trans->type, nbd_type_vals, "Unknown (%d)"));
		switch(nbd_trans->type){
		case NBD_CMD_WRITE:
		case NBD_CMD_READ:
		case NBD_CMD_TRIM:
		case NBD_CMD_CACHE:
		case NBD_CMD_WRITE_ZEROES:
		case NBD_CMD_BLOCK_STATUS:
			col_append_fstr(pinfo->cinfo, COL_INFO, "  Offset:0x%" PRIx64 " Length:%d", from, nbd_trans->datalen);
			break;
		}

		if(nbd_trans->type==NBD_CMD_WRITE){
			proto_tree_add_item(tree, hf_nbd_data, tvb, offset, nbd_trans->datalen, ENC_NA);
		}
		break;
	case NBD_RESPONSE_MAGIC:
		item=proto_tree_add_uint(tree, hf_nbd_type, tvb, 0, 0, nbd_trans->type);
		proto_item_set_generated(item);

		error=tvb_get_ntohl(tvb, offset);
		proto_tree_add_item(tree, hf_nbd_error, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset+=4;

		proto_tree_add_item(tree, hf_nbd_handle, tvb, offset, 8, ENC_BIG_ENDIAN);
		offset+=8;

		col_add_fstr(pinfo->cinfo, COL_INFO, "%s Response  %s", val_to_str(nbd_trans->type, nbd_type_vals, "Unknown (%d)"), val_to_str(error, nbd_error_vals, "Unknown error (%d)"));

		if(nbd_trans->type==NBD_CMD_READ){
			proto_tree_add_item(tree, hf_nbd_data, tvb, offset, nbd_trans->datalen, ENC_NA);
		}
		break;
	case NBD_STRUCTURED_REPLY_MAGIC:
		/* structured reply flags */
		proto_tree_add_bitmask(tree, tvb, offset, hf_nbd_reply_flags,
			ett_nbd_reply_flags, nbd_reply_flags, ENC_BIG_ENDIAN);
		offset+=2;
		item = proto_tree_add_item_ret_uint(tree, hf_nbd_reply_type, tvb, offset, 2, ENC_BIG_ENDIAN, &type);
		if (type & 0x8000) {
			expert_add_info(pinfo, item, &ei_nbd_hnd_reply_error);
		}
		offset+=2;

		proto_tree_add_item(tree, hf_nbd_handle, tvb, offset, 8, ENC_BIG_ENDIAN);
		offset+=8;

		proto_tree_add_item_ret_uint(tree, hf_nbd_len, tvb, offset, 4, ENC_BIG_ENDIAN, &data_len);
		offset+=4;

		dissect_nbd_structured_reply(tvb_new_subset_length(tvb, offset, data_len), pinfo, tree, type);
		/*offset += data_len; */
	}

	return tvb_captured_length(tvb);
}

static int
dissect_nbd_transmission(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	uint32_t magic, type;
	unsigned pdu_fixed;

	/* We want 8 to test the type */
	if (tvb_captured_length(tvb) < 8) {
		return 0;
	}

	magic = tvb_get_ntohl(tvb, 0);
	type = tvb_get_ntohs(tvb, 6);

	switch(magic){
	case NBD_REQUEST_MAGIC:
		/* verify type */
		if (!try_val_to_str(type, nbd_type_vals)) {
			return 0;
		}
		pdu_fixed = 28;
		break;
	case NBD_RESPONSE_MAGIC:
		pdu_fixed = 16;
		break;
	case NBD_STRUCTURED_REPLY_MAGIC:
		/* verify type */
		if (!try_val_to_str(type, nbd_reply_type_vals)) {
			return 0;
		}
		pdu_fixed = 20;
		break;
	default:
		return 0;
	}

	nbd_set_state(pinfo, STATE_HND_DONE);
	tcp_dissect_pdus(tvb, pinfo, tree, nbd_desegment, pdu_fixed, get_nbd_tcp_pdu_len, dissect_nbd_tcp_pdu, data);
	return tvb_captured_length(tvb);
}

static unsigned
get_nbd_opt_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	unsigned pdu_len = tvb_get_uint32(tvb, offset + 12, ENC_BIG_ENDIAN);

	return 16 + pdu_len;
}

static int
dissect_nbd_opt_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
	proto_item *item;
	proto_tree *tree;
	int offset = 0;
	uint32_t opt, data_len, name_len, info_num;
	nbd_conv_info_t *nbd_info;
	nbd_option_t *nbd_opt;
	const uint8_t *export_name;

	item = proto_tree_add_item(parent_tree, proto_nbd, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_nbd);

	proto_tree_add_item(tree, hf_nbd_hnd_magic, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	nbd_info = get_nbd_conv_info(pinfo);
	if (!PINFO_FD_VISITED(pinfo)) {
		nbd_opt = wmem_new(wmem_file_scope(), nbd_option_t);
		nbd_opt->req_frame=pinfo->num;
		nbd_opt->rep_frame=0;
		nbd_opt->req_time=pinfo->abs_ts;
		nbd_opt->opt=tvb_get_ntohl(tvb, offset);

		wmem_tree_insert32(nbd_info->opts, pinfo->num, (void *)nbd_opt);
	} else {
		nbd_opt = (nbd_option_t*)wmem_tree_lookup32(nbd_info->opts, pinfo->num);
		if (nbd_opt && nbd_opt->rep_frame) {
			item = proto_tree_add_uint(tree, hf_nbd_response_in, tvb, 0, 0, nbd_opt->rep_frame);
			proto_item_set_generated(item);
		}
	}

	proto_tree_add_item_ret_uint(tree, hf_nbd_hnd_opt, tvb, offset, 4, ENC_BIG_ENDIAN, &opt);
	col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str(opt, nbd_opt_vals, "Unknown (%d)"));

	offset += 4;

	proto_tree_add_item_ret_uint(tree, hf_nbd_len, tvb, offset, 4, ENC_BIG_ENDIAN, &data_len);
	offset += 4;

	if (data_len) {
		switch (opt) {
		case NBD_OPT_EXPORT_NAME:
			proto_tree_add_item_ret_string(tree, hf_nbd_export_name, tvb, offset, data_len, ENC_UTF_8, pinfo->pool, &export_name);
			col_append_sep_str(pinfo->cinfo, COL_INFO, ":", export_name);
			break;
		case NBD_OPT_INFO:
		case NBD_OPT_GO:
			proto_tree_add_item_ret_uint(tree, hf_nbd_export_name_len, tvb, offset, 4, ENC_BIG_ENDIAN, &name_len);
			offset += 4;
			proto_tree_add_item(tree, hf_nbd_export_name, tvb, offset, name_len, ENC_UTF_8);
			offset += name_len;
			proto_tree_add_item_ret_uint(tree, hf_nbd_info_num, tvb, offset, 2, ENC_BIG_ENDIAN, &info_num);
			offset += 2;
			for (unsigned i = 0; i < info_num; ++i) {
				proto_tree_add_item(tree, hf_nbd_info, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
			}
			break;
		case NBD_OPT_LIST_META_CONTEXT:
		case NBD_OPT_SET_META_CONTEXT:
			proto_tree_add_item_ret_uint(tree, hf_nbd_export_name_len, tvb, offset, 4, ENC_BIG_ENDIAN, &name_len);
			offset += 4;
			proto_tree_add_item(tree, hf_nbd_export_name, tvb, offset, name_len, ENC_UTF_8);
			offset += name_len;
			proto_tree_add_item_ret_uint(tree, hf_nbd_query_num, tvb, offset, 4, ENC_BIG_ENDIAN, &info_num);
			offset += 4;
			for (unsigned i = 0; i < info_num; ++i) {
				proto_tree_add_item_ret_length(tree, hf_nbd_query, tvb, offset, 2, ENC_BIG_ENDIAN, &name_len);
				offset += name_len;
			}
			break;
		default:
			proto_tree_add_item(tree, hf_nbd_data, tvb, offset, data_len, ENC_NA);
		}
	}

	return tvb_captured_length(tvb);
}

static unsigned
get_nbd_opt_reply_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	unsigned pdu_len = tvb_get_uint32(tvb, offset + 16, ENC_BIG_ENDIAN);

	return 20 + pdu_len;
}

static int
dissect_nbd_opt_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned type)
{
	proto_item *item;
	int offset = 0;
	uint32_t name_len, info_type;

	switch (type) {
	case NBD_REP_SERVER:
		proto_tree_add_item_ret_uint(tree, hf_nbd_export_name_len, tvb, offset, 4, ENC_BIG_ENDIAN, &name_len);
		offset += 4;
		proto_tree_add_item(tree, hf_nbd_export_name, tvb, offset, name_len, ENC_UTF_8);
		offset += name_len;
		break;
	case NBD_REP_INFO:
		proto_tree_add_item_ret_uint(tree, hf_nbd_info, tvb, offset, 2, ENC_BIG_ENDIAN, &info_type);
		offset += 2;
		switch (info_type) {
			case NBD_INFO_EXPORT:
			proto_tree_add_item(tree, hf_nbd_export_size, tvb, offset, 8, ENC_BIG_ENDIAN);
			offset += 8;

			proto_tree_add_bitmask(tree, tvb, offset, hf_nbd_trans_flags,
				ett_nbd_trans_flags, nbd_trans_flags, ENC_BIG_ENDIAN);
			offset += 2;
			break;
			case NBD_INFO_NAME:
			proto_tree_add_item(tree, hf_nbd_export_name, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_UTF_8);
			offset = tvb_reported_length(tvb);
			break;
			case NBD_INFO_DESCRIPTION:
			proto_tree_add_item(tree, hf_nbd_export_description, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_UTF_8);
			offset = tvb_reported_length(tvb);
			break;
			case NBD_INFO_BLOCK_SIZE:
			proto_tree_add_item(tree, hf_nbd_block_size_min, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(tree, hf_nbd_block_size_prefer, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(tree, hf_nbd_payload_size_max, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
		break;
	case NBD_REP_META_CONTEXT:
		proto_tree_add_item(tree, hf_nbd_meta_context_id, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_nbd_meta_context_name, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_UTF_8);
		offset = tvb_reported_length(tvb);
	}

	if (tvb_reported_length_remaining(tvb, offset)) {
		if (type & UINT32_C(1 << 31)) {
			proto_tree_add_item(tree, hf_nbd_error_msg, tvb, offset, -1, ENC_UTF_8);
		} else {
			item = proto_tree_add_item(tree, hf_nbd_data, tvb, offset, -1, ENC_NA);
			expert_add_info(pinfo, item, &ei_nbd_unexpected_data);
		}
	}

	return tvb_reported_length(tvb);
}

static int
dissect_nbd_opt_reply_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
	proto_item *item, *gen_item;
	proto_tree *tree;
	int offset = 0;
	uint32_t opt, reply, data_len;
	nbd_conv_info_t *nbd_info;
	nbd_option_t *nbd_opt;

	item = proto_tree_add_item(parent_tree, proto_nbd, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_nbd);

	item = proto_tree_add_item(tree, hf_nbd_hnd_magic, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	nbd_info = get_nbd_conv_info(pinfo);
	nbd_opt = (nbd_option_t*)wmem_tree_lookup32_le(nbd_info->opts, pinfo->num);

	proto_tree_add_item_ret_uint(tree, hf_nbd_hnd_opt, tvb, offset, 4, ENC_BIG_ENDIAN, &opt);
	col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str(opt, nbd_opt_vals, "Unknown (%d)"));
	offset += 4;

	if (nbd_opt && nbd_opt->opt == opt) {
		nbd_opt->rep_frame = pinfo->num;

		gen_item = proto_tree_add_uint(tree, hf_nbd_response_to, tvb, 0, 0, nbd_opt->req_frame);
		proto_item_set_generated(gen_item);
		proto_tree_move_item(tree, item, gen_item);
		item = gen_item;

		nstime_t ns;
		nstime_delta(&ns, &pinfo->abs_ts, &nbd_opt->req_time);
		gen_item = proto_tree_add_time(tree, hf_nbd_time, tvb, 0, 0, &ns);
		proto_item_set_generated(gen_item);
		proto_tree_move_item(tree, item, gen_item);
	}

	item = proto_tree_add_item_ret_uint(tree, hf_nbd_hnd_reply, tvb, offset, 4, ENC_BIG_ENDIAN, &reply);
	col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str(reply, nbd_hnd_reply_vals, "Unknown (%d)"));
	if (reply & UINT64_C(0x80000000)) {
		expert_add_info(pinfo, item, &ei_nbd_hnd_reply_error);
	}
	if (opt == NBD_OPT_STARTTLS && reply == NBD_REP_ACK) {
		ssl_starttls_ack(tls_handle, pinfo, nbd_handle);
	}

	offset += 4;

	proto_tree_add_item_ret_uint(tree, hf_nbd_len, tvb, offset, 4, ENC_BIG_ENDIAN, &data_len);
	offset += 4;

	dissect_nbd_opt_reply(tvb_new_subset_length(tvb, offset, data_len), pinfo, tree, reply);
	return tvb_captured_length(tvb);
}

static unsigned
get_nbd_export_len(packet_info *pinfo, tvbuff_t *tvb _U_, int offset _U_, void *data _U_)
{
	nbd_conv_info_t *nbd_info;

	nbd_info = get_nbd_conv_info(pinfo);
	/* There might, or might not, be 124 bytes of zeroes, depending on
	 * what was negotiated in the flags. */
	return 10 + (nbd_info->no_zeroes ? 0 : 124);
}

static int
dissect_nbd_export_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
	proto_item *item;
	proto_tree *tree;
	int offset = 0;
	nbd_conv_info_t *nbd_info;
	nbd_option_t *nbd_opt;

	item = proto_tree_add_item(parent_tree, proto_nbd, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_nbd);

	nbd_info = get_nbd_conv_info(pinfo);
	nbd_opt = (nbd_option_t*)wmem_tree_lookup32_le(nbd_info->opts, pinfo->num);

	if (nbd_opt && nbd_opt->opt == NBD_OPT_EXPORT_NAME) {
		nbd_opt->rep_frame = pinfo->num;

		item = proto_tree_add_uint(tree, hf_nbd_response_to, tvb, 0, 0, nbd_opt->req_frame);
		proto_item_set_generated(item);

		nstime_t ns;
		nstime_delta(&ns, &pinfo->abs_ts, &nbd_opt->req_time);
		item = proto_tree_add_time(tree, hf_nbd_time, tvb, 0, 0, &ns);
		proto_item_set_generated(item);

		item = proto_tree_add_uint(tree, hf_nbd_hnd_opt, tvb, 0, 0, nbd_opt->opt);
		proto_item_set_generated(item);
	}

	proto_tree_add_item(tree, hf_nbd_export_size, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	proto_tree_add_bitmask(tree, tvb, offset, hf_nbd_trans_flags,
		ett_nbd_trans_flags, nbd_trans_flags, ENC_BIG_ENDIAN);
	col_set_str(pinfo->cinfo, COL_INFO, "Transmission Flags");
	offset += 2;

	if (tvb_captured_length_remaining(tvb, offset)) {
		proto_tree_add_item(tree, hf_nbd_reserved, tvb, offset, -1, ENC_NA);
	}

	return tvb_captured_length(tvb);
}

/* These flags have the same offset, but one is a 16 bit bitmask
 * and one is a 32 bit bitmask, which might matter for future
 * expansion.
 */
static int * const nbd_hnd_flags[] = {
	&hf_nbd_hnd_flags_fixed_new,
	&hf_nbd_hnd_flags_no_zeroes,
	NULL,
};

static int * const nbd_cli_flags[] = {
	&hf_nbd_cli_flags_fixed_new,
	&hf_nbd_cli_flags_no_zeroes,
	NULL,
};

static unsigned
get_nbd_old_len(packet_info *pinfo _U_, tvbuff_t *tvb _U_, int offset _U_, void *data _U_)
{
	return 144; // 8 + 8 + 4 + 124
}

static int
dissect_nbd_old_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
	proto_item *item;
	proto_tree *tree;
	int offset = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Oldstyle Handshake");

	item = proto_tree_add_item(parent_tree, proto_nbd, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_nbd);

	proto_tree_add_item(tree, hf_nbd_hnd_magic, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	proto_tree_add_item(tree, hf_nbd_export_size, tvb, offset, 8, ENC_BIG_ENDIAN);
	offset += 8;

	proto_tree_add_bitmask(tree, tvb, offset, hf_nbd_hnd_flags,
		ett_nbd_hnd_flags, nbd_hnd_flags, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_bitmask(tree, tvb, offset, hf_nbd_trans_flags,
		ett_nbd_trans_flags, nbd_trans_flags, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_nbd_reserved, tvb, offset, 124, ENC_NA);

	return tvb_captured_length(tvb);
}

static int
dissect_nbd_hnd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	proto_item *item;
	proto_tree *tree;
	int offset = 0;
	uint64_t magic;
	//nbd_conv_info_t *nbd_info;

	nbd_state_e new_state;

	//nbd_info = get_nbd_conv_info(pinfo);
	bool from_server = nbd_from_server(pinfo);

	/* We want 8 to test the magic number */
	if (tvb_captured_length_remaining(tvb, offset) < 8) {
		return 0;
	}

	magic = tvb_get_uint64(tvb, offset, ENC_BIG_ENDIAN);

	switch (magic) {
	case NBD_HND_INIT_MAGIC:
		item = proto_tree_add_item(parent_tree, proto_nbd, tvb, 0, 8, ENC_NA);
		tree = proto_item_add_subtree(item, ett_nbd);

		proto_tree_add_item(tree, hf_nbd_hnd_magic, tvb, offset, 8, ENC_BIG_ENDIAN);
		col_set_str(pinfo->cinfo, COL_INFO, "Handshake Start");
		nbd_set_state(pinfo, STATE_HND_INIT);
		break;
	case NBD_HND_OPT_MAGIC:
		/* Unfortunately the server and client use the same OPT_MAGIC,
		 * and they mean something different about what is expected next.
		 */
		new_state = from_server ? STATE_HND_INIT : STATE_HND_OPT;
		nbd_set_state(pinfo, new_state);
		if (from_server) {
			item = proto_tree_add_item(parent_tree, proto_nbd, tvb, 0, 8, ENC_NA);
			tree = proto_item_add_subtree(item, ett_nbd);

			proto_tree_add_item(tree, hf_nbd_hnd_magic, tvb, offset, 8, ENC_BIG_ENDIAN);
			col_set_str(pinfo->cinfo, COL_INFO, "Newstyle Handshake");
		} else {
			tcp_dissect_pdus(tvb, pinfo, parent_tree, nbd_desegment, 16, get_nbd_opt_len, dissect_nbd_opt_pdu, data);
		}
		break;
	case NBD_HND_REPLY_MAGIC:
		nbd_set_state(pinfo, STATE_HND_OPT);
		tcp_dissect_pdus(tvb, pinfo, parent_tree, nbd_desegment, 20, get_nbd_opt_reply_len, dissect_nbd_opt_reply_pdu, data);
		break;
	case NBD_HND_OLD_MAGIC:
		tcp_dissect_pdus(tvb, pinfo, parent_tree, nbd_desegment, 20, get_nbd_old_len, dissect_nbd_old_pdu, data);
		break;
	default:
		return 0;
	}

	return tvb_captured_length(tvb);
}

static int
dissect_nbd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
	int offset=0;
	proto_tree *tree=NULL;
	proto_item *item=NULL;
	nbd_conv_info_t *nbd_info;

	nbd_state_e current_state;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NBD");

	col_clear(pinfo->cinfo, COL_INFO);

	bool from_server = nbd_from_server(pinfo);
	nbd_info = get_nbd_conv_info(pinfo);
	current_state = (nbd_state_e)GPOINTER_TO_UINT(wmem_tree_lookup32_le(nbd_info->state, pinfo->num));
	nbd_option_t *nbd_opt;
	nbd_opt = (nbd_option_t*)wmem_tree_lookup32_le(nbd_info->opts, pinfo->num);

	/* NBD has 8 byte magic numbers for the handshake phase, and 4 byte
	 * magic numbers for the transmission phase. A few handshake messages
	 * are not preceded by magic numbers in that direction (and one magic
	 * number is used for different messages types in the two directions.)
	 */

	if (!dissect_nbd_transmission(tvb, pinfo, parent_tree, data)) {
		if (!dissect_nbd_hnd(tvb, pinfo, parent_tree, data)) {

			item = proto_tree_add_item(parent_tree, proto_nbd, tvb, 0, -1, ENC_NA);
			tree = proto_item_add_subtree(item, ett_nbd);

			if (current_state == STATE_HND_INIT) {
				uint64_t flags;
				if (from_server) {
					proto_tree_add_bitmask(tree, tvb, offset, hf_nbd_hnd_flags,
						ett_nbd_hnd_flags, nbd_hnd_flags, ENC_BIG_ENDIAN);
					col_set_str(pinfo->cinfo, COL_INFO, "Handshake Flags");
				} else {
					proto_tree_add_bitmask_ret_uint64(tree, tvb, offset, hf_nbd_cli_flags,
						ett_nbd_hnd_flags, nbd_cli_flags, ENC_BIG_ENDIAN, &flags);
					col_set_str(pinfo->cinfo, COL_INFO, "Client Flags");
					if (flags & NBD_FLAG_NO_ZEROES) {
						nbd_info->no_zeroes = true;
					}
				}
			} else if (current_state == STATE_HND_OPT && nbd_opt && nbd_opt->opt == NBD_OPT_EXPORT_NAME) {
				tcp_dissect_pdus(tvb, pinfo, tree, nbd_desegment, 10, get_nbd_export_len, dissect_nbd_export_pdu, data);
			}
		}
	}
	return tvb_captured_length(tvb);
}

static bool
dissect_nbd_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	uint32_t magic, type;
	uint64_t magic64;
	conversation_t *conversation;
	conversation = find_or_create_conversation(pinfo);

	/* We need at least this much to tell whether this is NBD or not */
	if(tvb_captured_length(tvb)<4){
		return false;
	}

	/* Check if it looks like NBD */
	magic=tvb_get_ntohl(tvb, 0);
	switch(magic){
	case NBD_REQUEST_MAGIC:
		/* requests are 28 bytes or more */
		if(tvb_captured_length(tvb)<28){
			return false;
		}
		/* verify type */
		type=tvb_get_ntohs(tvb, 6);
		if (!try_val_to_str(type, nbd_type_vals)) {
			return false;
		}
		conversation_set_dissector(conversation, nbd_handle);
		tcp_dissect_pdus(tvb, pinfo, tree, nbd_desegment, 28, get_nbd_tcp_pdu_len, dissect_nbd_tcp_pdu, data);
		return true;
	case NBD_RESPONSE_MAGIC:
		/* responses are 16 bytes or more */
		if(tvb_captured_length(tvb)<16){
			return false;
		}
		conversation_set_dissector(conversation, nbd_handle);
		tcp_dissect_pdus(tvb, pinfo, tree, nbd_desegment, 16, get_nbd_tcp_pdu_len, dissect_nbd_tcp_pdu, data);
		return true;
	case NBD_STRUCTURED_REPLY_MAGIC:
		/* structured replies are 20 bytes or more,
		 * and the length is in bytes 17-20. */
		if(tvb_captured_length(tvb)<20){
			return false;
		}
		conversation_set_dissector(conversation, nbd_handle);
		tcp_dissect_pdus(tvb, pinfo, tree, nbd_desegment, 20, get_nbd_tcp_pdu_len, dissect_nbd_tcp_pdu, data);
	default:
		break;
	}

	if (tvb_captured_length(tvb) < 8){
		return false;
	}
	magic64 = tvb_get_uint64(tvb, 0, ENC_BIG_ENDIAN);
	switch (magic64) {
	case NBD_HND_INIT_MAGIC:
	case NBD_HND_OPT_MAGIC:
	case NBD_HND_REPLY_MAGIC:
	case NBD_HND_OLD_MAGIC:
		conversation_set_dissector(conversation, nbd_handle);
		dissect_nbd(tvb, pinfo, tree, data);
		return true;
	default:
		break;
	}

	return false;
}

void proto_register_nbd(void)
{
	static hf_register_info hf[] = {
		{ &hf_nbd_hnd_magic,
		  { "Magic", "nbd.hnd.magic", FT_UINT64, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_hnd_flags,
		  { "Handshake Flags", "nbd.hnd.flags", FT_UINT16, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_hnd_flags_fixed_new,
		  { "Fixed Newstyle", "nbd.hnd.flags.fixed_new", FT_BOOLEAN, 16,
		    TFS(&tfs_set_notset), 0x0001, NULL, HFILL }},
		{ &hf_nbd_hnd_flags_no_zeroes,
		  { "No Zeroes", "nbd.hnd.flags.no_zeroes", FT_BOOLEAN, 16,
		    TFS(&tfs_set_notset), NBD_FLAG_NO_ZEROES, NULL, HFILL }},
		{ &hf_nbd_cli_flags,
		  { "Client Flags", "nbd.cli.flags", FT_UINT32, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_cli_flags_fixed_new,
		  { "Fixed Newstyle", "nbd.cli.flags.fixed_new", FT_BOOLEAN, 32,
		    TFS(&tfs_set_notset), 0x0001, NULL, HFILL }},
		{ &hf_nbd_cli_flags_no_zeroes,
		  { "No Zeroes", "nbd.cli.flags.no_zeroes", FT_BOOLEAN, 32,
		    TFS(&tfs_set_notset), NBD_FLAG_NO_ZEROES, NULL, HFILL }},
		{ &hf_nbd_hnd_opt,
		  { "Option", "nbd.hnd.opt", FT_UINT32, BASE_HEX,
		    VALS(nbd_opt_vals), 0x0, NULL, HFILL }},
		{ &hf_nbd_hnd_reply,
		  { "Reply", "nbd.hnd.reply", FT_UINT32, BASE_HEX,
		    VALS(nbd_hnd_reply_vals), 0x0, NULL, HFILL }},
		{ &hf_nbd_magic,
		  { "Magic", "nbd.magic", FT_UINT32, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_cmd_flags,
		  { "Command Flags", "nbd.cmd.flags", FT_UINT16, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_cmd_flags_fua,
		  { "Forced Unit Access", "nbd.cmd.flags.fua", FT_BOOLEAN, 16,
		    TFS(&tfs_set_notset), 0x0001, NULL, HFILL }},
		{ &hf_nbd_cmd_flags_no_hole,
		  { "No Hole", "nbd.cmd.flags.no_hole", FT_BOOLEAN, 16,
		    TFS(&tfs_set_notset), 0x0002, NULL, HFILL }},
		{ &hf_nbd_cmd_flags_df,
		  { "Don't Fragment", "nbd.cmd.flags.df", FT_BOOLEAN, 16,
		    TFS(&tfs_set_notset), 0x0004, NULL, HFILL }},
		{ &hf_nbd_cmd_flags_req_one,
		  { "Request One", "nbd.cmd.flags.req_one", FT_BOOLEAN, 16,
		    TFS(&tfs_set_notset), 0x0008, NULL, HFILL }},
		{ &hf_nbd_cmd_flags_fast_zero,
		  { "Fast Zero", "nbd.cmd.flags.fast_zero", FT_BOOLEAN, 16,
		    TFS(&tfs_set_notset), 0x0010, NULL, HFILL }},
		{ &hf_nbd_cmd_flags_payload_len,
		  { "Payload Len", "nbd.cmd.flags.payload_len", FT_BOOLEAN, 16,
		    TFS(&tfs_set_notset), 0x0020, NULL, HFILL }},
		{ &hf_nbd_reply_flags,
		  { "Reply Flags", "nbd.reply.flags", FT_UINT16, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_reply_flags_done,
		  { "Done", "nbd.reply.flags.done", FT_BOOLEAN, 16,
		    TFS(&tfs_set_notset), 0x0001, NULL, HFILL }},
		{ &hf_nbd_export_size,
		  { "Export Size", "nbd.export.size", FT_UINT64, BASE_DEC|BASE_UNIT_STRING,
		    UNS(&units_byte_bytes), 0x0, NULL, HFILL }},
		{ &hf_nbd_trans_flags,
		  { "Transmission Flags", "nbd.export.trans.flags", FT_UINT16, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_trans_flags_has_flags,
		  { "Has Flags", "nbd.trans.flags.has_flags", FT_BOOLEAN, 16,
		    TFS(&tfs_set_notset), 0x0001, NULL, HFILL }},
		{ &hf_nbd_trans_flags_read_only,
		  { "Read Only", "nbd.trans.flags.read_only", FT_BOOLEAN, 16,
		    TFS(&tfs_set_notset), 0x0002, NULL, HFILL }},
		{ &hf_nbd_trans_flags_flush,
		  { "Flush", "nbd.trans.flags.flush", FT_BOOLEAN, 16,
		    TFS(&tfs_supported_not_supported), 0x0004, NULL, HFILL }},
		{ &hf_nbd_trans_flags_fua,
		  { "Forced Unit Access", "nbd.trans.flags.fua", FT_BOOLEAN, 16,
		    TFS(&tfs_supported_not_supported), 0x0008, NULL, HFILL }},
		{ &hf_nbd_trans_flags_rotational,
		  { "Rotational", "nbd.trans.flags.rotational", FT_BOOLEAN, 16,
		    TFS(&tfs_set_notset), 0x0010, NULL, HFILL }},
		{ &hf_nbd_trans_flags_trim,
		  { "Trim", "nbd.trans.flags.trim", FT_BOOLEAN, 16,
		    TFS(&tfs_supported_not_supported), 0x0020, NULL, HFILL }},
		{ &hf_nbd_trans_flags_write_zeroes,
		  { "Write Zeroes", "nbd.trans.flags.write_zeroes", FT_BOOLEAN, 16,
		    TFS(&tfs_supported_not_supported), 0x0040, NULL, HFILL }},
		{ &hf_nbd_trans_flags_df,
		  { "Don't Fragment", "nbd.trans.flags.df", FT_BOOLEAN, 16,
		    TFS(&tfs_supported_not_supported), 0x0080, NULL, HFILL }},
		{ &hf_nbd_trans_flags_multi_conn,
		  { "Multiple Connections", "nbd.trans.flags.multi_conn", FT_BOOLEAN, 16,
		    TFS(&tfs_supported_not_supported), 0x0100, NULL, HFILL }},
		{ &hf_nbd_trans_flags_resize,
		  { "Resize", "nbd.trans.flags.resize", FT_BOOLEAN, 16,
		    TFS(&tfs_supported_not_supported), 0x0200, NULL, HFILL }},
		{ &hf_nbd_trans_flags_cache,
		  { "Cache", "nbd.trans.flags.cache", FT_BOOLEAN, 16,
		    TFS(&tfs_supported_not_supported), 0x0400, NULL, HFILL }},
		{ &hf_nbd_trans_flags_fast_zero,
		  { "Fast Zeroes", "nbd.trans.flags.fast_zero", FT_BOOLEAN, 16,
		    TFS(&tfs_supported_not_supported), 0x0800, NULL, HFILL }},
		{ &hf_nbd_trans_flags_block_status_payload,
		  { "Block Status Payload", "nbd.trans.flags.block_status_payload", FT_BOOLEAN, 16,
		    TFS(&tfs_supported_not_supported), 0x1000, NULL, HFILL }},
		{ &hf_nbd_reserved,
		  { "Reserved (Zeroes)", "nbd.reserved", FT_BYTES, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_type,
		  { "Type", "nbd.type", FT_UINT16, BASE_DEC,
		    VALS(nbd_type_vals), 0x0, NULL, HFILL }},
		{ &hf_nbd_reply_type,
		  { "Reply Type", "nbd.reply.type", FT_UINT16, BASE_DEC,
		    VALS(nbd_reply_type_vals), 0x0, NULL, HFILL }},
		{ &hf_nbd_error,
		  { "Error", "nbd.error", FT_UINT32, BASE_DEC,
		    VALS(nbd_error_vals), 0x0, NULL, HFILL }},
		{ &hf_nbd_len,
		  { "Length", "nbd.len", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_handle,
		  { "Handle", "nbd.handle", FT_UINT64, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_from,
		  { "From", "nbd.from", FT_UINT64, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_response_in,
		  { "Response In", "nbd.response_in", FT_FRAMENUM, BASE_NONE,
		    NULL, 0x0, "The response to this NBD request is in this frame", HFILL }},
		{ &hf_nbd_response_to,
		  { "Request In", "nbd.response_to", FT_FRAMENUM, BASE_NONE,
		    NULL, 0x0, "This is a response to the NBD request in this frame", HFILL }},
		{ &hf_nbd_time,
		  { "Time", "nbd.time", FT_RELATIVE_TIME, BASE_NONE,
		    NULL, 0x0, "The time between the Call and the Reply", HFILL }},

		{ &hf_nbd_export_name_len,
		  { "Export Name Length", "nbd.export.name.len", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_export_name,
		  { "Export Name", "nbd.export.name", FT_STRING, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_info_num,
		  { "Number of Information Requests", "nbd.info.num", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_info,
		  { "Information Type", "nbd.info", FT_UINT16, BASE_DEC,
		    VALS(nbd_info_vals), 0x0, NULL, HFILL }},
		{ &hf_nbd_query_num,
		  { "Number of Queries", "nbd.query.num", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_query,
		  { "Query", "nbd.info.num", FT_UINT_STRING, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_export_description,
		  { "Export Description", "nbd.export.description", FT_STRING, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_block_size_min,
		  { "Minimum Block Size", "nbd.block_size.min", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_block_size_prefer,
		  { "Preferred Block Size", "nbd.block_size.prefer", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_payload_size_max,
		  { "Maximum Payload Size", "nbd.payload_size.max", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_meta_context_id,
		  { "Metadat Context ID", "nbd.meta_context.id", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_meta_context_name,
		  { "Metadata Context Name", "nbd.meta_context.name", FT_STRING, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_error_msg_len,
		  { "Message Length", "nbd.error_msg.len", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_error_msg,
		  { "Error Message", "nbd.error_msg", FT_STRING, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_data,
		  { "Data", "nbd.data", FT_BYTES, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_hole_size,
		  { "Hole Size", "nbd.hole_size", FT_UINT32, BASE_DEC|BASE_UNIT_STRING,
		    UNS(&units_byte_bytes), 0x0, NULL, HFILL }},
		{ &hf_nbd_status_flags,
		  { "Block Status Flags", "nbd.status_flags", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Status flags as defined by metadata context", HFILL }},

	};


	static int *ett[] = {
		&ett_nbd,
		&ett_nbd_hnd_flags,
		&ett_nbd_cli_flags,
		&ett_nbd_cmd_flags,
		&ett_nbd_reply_flags,
		&ett_nbd_trans_flags,
	};

	static ei_register_info ei[] = {
		{ &ei_nbd_hnd_reply_error, {"nbd.hnd.reply.error", PI_RESPONSE_CODE, PI_NOTE, "Reply Error", EXPFILL }},
		{ &ei_nbd_unexpected_data, {"nbd.data.unexpected", PI_UNDECODED, PI_WARN, "Unexpected data", EXPFILL }},
	};

	module_t *nbd_module;
	expert_module_t *expert_nbd;

	proto_nbd = proto_register_protocol("Network Block Device",
	                                    "NBD", "nbd");
	proto_register_field_array(proto_nbd, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_nbd = expert_register_protocol(proto_nbd);
	expert_register_field_array(expert_nbd, ei, array_length(ei));

	nbd_module = prefs_register_protocol(proto_nbd, apply_nbd_prefs);
	prefs_register_bool_preference(nbd_module, "desegment_nbd_messages",
				       "Reassemble NBD messages spanning multiple TCP segments",
				       "Whether the NBD dissector should reassemble messages spanning multiple TCP segments."
				       " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings",
				       &nbd_desegment);

	nbd_handle = register_dissector("nbd", dissect_nbd, proto_nbd);
}

static void
apply_nbd_prefs(void)
{
	// XXX - There should be a reset_uint_range ?
	dissector_delete_uint_range("tls.port", nbd_port_range, nbd_handle);
	nbd_port_range = prefs_get_range_value("NBD", "tcp.port");
	dissector_add_uint_range("tls.port", nbd_port_range, nbd_handle);
}

void
proto_reg_handoff_nbd(void)
{
	heur_dissector_add("tcp", dissect_nbd_tcp_heur, "NBD over TCP", "nbd_tcp", proto_nbd, HEURISTIC_ENABLE);
	dissector_add_uint_range_with_preference("tcp.port", NBD_TCP_PORTS, nbd_handle);
	tls_handle = find_dissector_add_dependency("tls", proto_nbd);
	apply_nbd_prefs();
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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

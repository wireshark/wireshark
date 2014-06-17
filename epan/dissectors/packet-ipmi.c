/* packet-ipmi.c
 * Routines for IPMI dissection
 * Copyright 2002-2008, Alexey Neyman, Pigeon Point Systems <avn@pigeonpoint.com>
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

#include "config.h"

#include <string.h>

#include <stdio.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/wmem/wmem.h>
#include <epan/to_str.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>

#include "packet-ipmi.h"

void proto_register_ipmi(void);

/*
 * See the IPMI specifications at
 *
 *	http://www.intel.com/design/servers/ipmi/
 */

/* Define IPMI_DEBUG to enable printing the process of request-response pairing */
/* #define IPMI_DEBUG */

/* Top-level search structure: list of registered handlers for a given netFn */
struct ipmi_netfn_root {
	ipmi_netfn_t *list;
	const char *desc;
	guint32 siglen;
};

enum {
	MSGFMT_NONE = 0,
	MSGFMT_IPMB,
	MSGFMT_LAN,
	MSGFMT_GUESS
};

struct ipmi_parse_typelen {
	void (*get_len)(guint *, guint *, tvbuff_t *, guint, guint, gboolean);
	void (*parse)(char *, tvbuff_t *, guint, guint);
	const char *desc;
};

/* IPMI parsing context */
typedef struct {
	ipmi_header_t	hdr;
	guint			hdr_len;
	guint			flags;
	guint8			cks1;
	guint8			cks2;
} ipmi_context_t;

/* Temporary request-response matching data. */
typedef struct {
	/* Request header */
	ipmi_header_t	hdr;
	/* Frame number where the request resides */
	guint32			frame_num;
	/* Nest level of the request in the frame */
	guint8			nest_level;
} ipmi_request_t;

/* List of request-response matching data */
typedef wmem_list_t ipmi_request_list_t;

#define NSAVED_DATA 2

/* Per-command data */
typedef struct {
	guint32		matched_frame_num;
	guint32		saved_data[NSAVED_DATA];
} ipmi_cmd_data_t;

/* Per-frame data */
typedef struct {
	ipmi_cmd_data_t *	cmd_data[3];
	nstime_t			ts;
} ipmi_frame_data_t;

/* RB tree of frame data */
typedef wmem_tree_t ipmi_frame_tree_t;

/* cached dissector data */
typedef struct {
	/* tree of cached frame data */
	ipmi_frame_tree_t *		frame_tree;
	/* list of cached requests */
	ipmi_request_list_t *	request_list;
	/* currently dissected frame number */
	guint32					curr_frame_num;
	/* currently dissected frame */
	ipmi_frame_data_t *		curr_frame;
	/* current nesting level */
	guint8					curr_level;
	/* subsequent nesting level */
	guint8					next_level;
	/* top level message channel */
	guint8					curr_channel;
	/* top level message direction */
	guint8					curr_dir;
	/* pointer to current command */
	const ipmi_header_t * 	curr_hdr;
	/* current completion code */
	guint8					curr_ccode;
} ipmi_packet_data_t;

/* Maximum nest level where it worth caching data */
#define MAX_NEST_LEVEL	3

static dissector_handle_t data_dissector;

gint proto_ipmi = -1;
static gint proto_ipmb = -1;
static gint proto_kcs = -1;
static gint proto_tmode = -1;

static gboolean fru_langcode_is_english = TRUE;
static guint response_after_req = 5000;
static guint response_before_req = 0;
static guint message_format = MSGFMT_GUESS;
static guint selected_oem = IPMI_OEM_NONE;

static gint hf_ipmi_session_handle = -1;
static gint hf_ipmi_header_trg = -1;
static gint hf_ipmi_header_trg_lun = -1;
static gint hf_ipmi_header_netfn = -1;
static gint hf_ipmi_header_crc = -1;
static gint hf_ipmi_header_src = -1;
static gint hf_ipmi_header_src_lun = -1;
static gint hf_ipmi_header_bridged = -1;
static gint hf_ipmi_header_sequence = -1;
static gint hf_ipmi_header_command = -1;
static gint hf_ipmi_header_completion = -1;
static gint hf_ipmi_header_sig = -1;
static gint hf_ipmi_data_crc = -1;
static gint hf_ipmi_response_to = -1;
static gint hf_ipmi_response_in = -1;
static gint hf_ipmi_response_time = -1;

static gint ett_ipmi = -1;
static gint ett_header = -1;
static gint ett_header_byte_1 = -1;
static gint ett_header_byte_4 = -1;
static gint ett_data = -1;
static gint ett_typelen = -1;

static expert_field ei_impi_parser_not_implemented = EI_INIT;

static struct ipmi_netfn_root ipmi_cmd_tab[IPMI_NETFN_MAX];

static ipmi_packet_data_t *
get_packet_data(packet_info * pinfo)
{
	ipmi_packet_data_t * data;

	/* get conversation data */
	conversation_t * conv = find_or_create_conversation(pinfo);

	/* get protocol-specific data */
	data = (ipmi_packet_data_t *)
			conversation_get_proto_data(conv, proto_ipmi);

	if (!data) {
		/* allocate per-packet data */
		data = wmem_new0(wmem_file_scope(), ipmi_packet_data_t);

		/* allocate request list and frame tree */
		data->frame_tree = wmem_tree_new(wmem_file_scope());
		data->request_list = wmem_list_new(wmem_file_scope());

		/* add protocol data */
		conversation_add_proto_data(conv, proto_ipmi, data);
	}

	/* check if packet has changed */
	if (pinfo->fd->num != data->curr_frame_num) {
		data->curr_level = 0;
		data->next_level = 0;
	}

	return data;
}

static ipmi_frame_data_t *
get_frame_data(ipmi_packet_data_t * data, guint32 frame_num)
{
	ipmi_frame_data_t * frame = (ipmi_frame_data_t *)
			wmem_tree_lookup32(data->frame_tree, frame_num);

	if (frame == NULL) {
		frame = wmem_new0(wmem_file_scope(), ipmi_frame_data_t);

		wmem_tree_insert32(data->frame_tree, frame_num, frame);
	}
	return frame;
}

static ipmi_request_t *
get_matched_request(ipmi_packet_data_t * data, const ipmi_header_t * rs_hdr,
		guint flags)
{
	wmem_list_frame_t * iter = wmem_list_head(data->request_list);
	ipmi_header_t rq_hdr;

	/* reset message context */
	rq_hdr.context = 0;

	/* copy channel */
	rq_hdr.channel = data->curr_channel;

	/* toggle packet direction */
	rq_hdr.dir = rs_hdr->dir ^ 1;

	rq_hdr.session = rs_hdr->session;

	/* swap responder address/lun */
	rq_hdr.rs_sa = rs_hdr->rq_sa;
	rq_hdr.rs_lun = rs_hdr->rq_lun;

	/* remove reply flag */
	rq_hdr.netfn = rs_hdr->netfn & ~1;

	/* swap requester address/lun */
	rq_hdr.rq_sa = rs_hdr->rs_sa;
	rq_hdr.rq_lun = rs_hdr->rs_lun;

	/* copy sequence */
	rq_hdr.rq_seq = rs_hdr->rq_seq;

	/* copy command */
	rq_hdr.cmd = rs_hdr->cmd;

	/* TODO: copy prefix bytes */

#ifdef DEBUG
	fprintf(stderr, "%d, %d: rq_hdr : {\n"
			"\tchannel=%d\n"
			"\tdir=%d\n"
			"\trs_sa=%x\n"
			"\trs_lun=%d\n"
			"\tnetfn=%x\n"
			"\trq_sa=%x\n"
			"\trq_lun=%d\n"
			"\trq_seq=%x\n"
			"\tcmd=%x\n}\n",
			data->curr_frame_num, data->curr_level,
			rq_hdr.channel, rq_hdr.dir, rq_hdr.rs_sa, rq_hdr.rs_lun,
			rq_hdr.netfn, rq_hdr.rq_sa, rq_hdr.rq_lun, rq_hdr.rq_seq,
			rq_hdr.cmd);
#endif

	while (iter) {
		ipmi_request_t * rq = (ipmi_request_t *) wmem_list_frame_data(iter);

		/* check if in Get Message context */
		if (rs_hdr->context == IPMI_E_GETMSG && !(flags & IPMI_D_TRG_SA)) {
			/* diregard rsSA */
			rq_hdr.rq_sa = rq->hdr.rq_sa;
		}

		/* compare command headers */
		if (!memcmp(&rq_hdr, &rq->hdr, sizeof(rq_hdr))) {
			return rq;
		}

		/* proceed to next request */
		iter = wmem_list_frame_next(iter);
	}

	return NULL;
}

static void
remove_old_requests(ipmi_packet_data_t * data, const nstime_t * curr_time)
{
	wmem_list_frame_t * iter = wmem_list_head(data->request_list);

	while (iter) {
		ipmi_request_t * rq = (ipmi_request_t *) wmem_list_frame_data(iter);
		ipmi_frame_data_t * frame = get_frame_data(data, rq->frame_num);
		nstime_t delta;

		/* calculate time delta */
		nstime_delta(&delta, curr_time, &frame->ts);

		if (nstime_to_msec(&delta) > response_after_req) {
			wmem_list_frame_t * del = iter;

			/* proceed to next request */
			iter = wmem_list_frame_next(iter);

			/* free request data */
			wmem_free(wmem_file_scope(), rq);

			/* remove list item */
			wmem_list_remove_frame(data->request_list, del);
		} else {
			break;
		}
	}
}

static void
match_request_response(ipmi_packet_data_t * data, const ipmi_header_t * hdr,
		guint flags)
{
	/* get current frame */
	ipmi_frame_data_t * rs_frame = data->curr_frame;

	/* get current command data */
	ipmi_cmd_data_t * rs_data = rs_frame->cmd_data[data->curr_level];

	/* check if parse response for the first time */
	if (!rs_data) {
		ipmi_request_t * rq;

		/* allocate command data */
		rs_data = wmem_new0(wmem_file_scope(), ipmi_cmd_data_t);

		/* search for matching request */
		rq = get_matched_request(data, hdr, flags);

		/* check if matching request is found */
		if (rq) {
			/* get request frame data */
			ipmi_frame_data_t * rq_frame =
					get_frame_data(data, rq->frame_num);

			/* get command data */
			ipmi_cmd_data_t * rq_data = rq_frame->cmd_data[rq->nest_level];

			/* save matched frame numbers */
			rq_data->matched_frame_num = data->curr_frame_num;
			rs_data->matched_frame_num = rq->frame_num;

			/* copy saved command data information */
			rs_data->saved_data[0] = rq_data->saved_data[0];
			rs_data->saved_data[1] = rq_data->saved_data[1];

			/* remove request from the list */
			wmem_list_remove(data->request_list, rq);

			/* delete request data */
			wmem_free(wmem_file_scope(), rq);
		}

		/* save command data pointer in frame */
		rs_frame->cmd_data[data->curr_level] = rs_data;
	}
}

static void
add_request(ipmi_packet_data_t * data, const ipmi_header_t * hdr)
{
	/* get current frame */
	ipmi_frame_data_t * rq_frame = data->curr_frame;

	/* get current command data */
	ipmi_cmd_data_t * rq_data = rq_frame->cmd_data[data->curr_level];

	/* check if parse response for the first time */
	if (!rq_data) {
		ipmi_request_t * rq;

		/* allocate command data */
		rq_data = wmem_new0(wmem_file_scope(), ipmi_cmd_data_t);

		/* set command data pointer */
		rq_frame->cmd_data[data->curr_level] = rq_data;

		/* allocate request data */
		rq = wmem_new0(wmem_file_scope(), ipmi_request_t);

		/* copy request header */
		memcpy(&rq->hdr, hdr, sizeof(rq->hdr));

		/* override context, channel and direction */
		rq->hdr.context = 0;
		rq->hdr.channel = data->curr_channel;
		rq->hdr.dir = data->curr_dir;

		/* set request frame number */
		rq->frame_num = data->curr_frame_num;

		/* set command nest level */
		rq->nest_level = data->curr_level;

		/* append request to list */
		wmem_list_append(data->request_list, rq);

#ifdef DEBUG
	fprintf(stderr, "%d, %d: hdr : {\n"
			"\tchannel=%d\n"
			"\tdir=%d\n"
			"\trs_sa=%x\n"
			"\trs_lun=%d\n"
			"\tnetfn=%x\n"
			"\trq_sa=%x\n"
			"\trq_lun=%d\n"
			"\trq_seq=%x\n"
			"\tcmd=%x\n}\n",
			data->curr_frame_num, data->curr_level,
			rq->hdr.channel, rq->hdr.dir, rq->hdr.rs_sa, rq->hdr.rs_lun,
			rq->hdr.netfn, rq->hdr.rq_sa, rq->hdr.rq_lun, rq->hdr.rq_seq,
			rq->hdr.cmd);
#endif
	}
}

static void
add_command_info(packet_info *pinfo, ipmi_cmd_t * cmd,
		gboolean resp, guint8 cc_val, const char * cc_str, gboolean broadcast)
{
	if (resp) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "Rsp, %s, %s (%02xh)",
				cmd->desc, cc_str, cc_val);
	} else {
		col_add_fstr(pinfo->cinfo, COL_INFO, "Req, %s%s",
				broadcast ? "Broadcast " : "", cmd->desc);
	}
}

static int
dissect_ipmi_cmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		gint hf_parent_item, gint ett_tree, const ipmi_context_t * ctx)
{
	ipmi_packet_data_t * data;
	ipmi_netfn_t * cmd_list;
	ipmi_cmd_t * cmd;
	proto_item * ti;
	proto_tree * cmd_tree = NULL, * tmp_tree;
	guint8 prev_level, cc_val;
	guint offset, siglen, is_resp;
	const char * cc_str, * netfn_str;

	/* get packet data */
	data = get_packet_data(pinfo);
	if (!data) {
		return 0;
	}

	/* get prefix length */
	siglen = ipmi_getsiglen(ctx->hdr.netfn);

	/* get response flag */
	is_resp = ctx->hdr.netfn & 1;

	/* check message length */
	if (tvb_captured_length(tvb) < ctx->hdr_len + siglen + is_resp
			+ !(ctx->flags & IPMI_D_NO_CKS)) {
		/* don bother with anything */
		return call_dissector(data_dissector, tvb, pinfo, tree);
	}

	/* save nest level */
	prev_level = data->curr_level;

	/* assign next nest level */
	data->curr_level = data->next_level;

	/* increment next nest level */
	data->next_level++;

	/* check for the first invocation */
	if (!data->curr_level) {
		/* get current frame data */
		data->curr_frame = get_frame_data(data, pinfo->fd->num);
		data->curr_frame_num = pinfo->fd->num;

		/* copy frame timestamp */
		memcpy(&data->curr_frame->ts, &pinfo->fd->abs_ts, sizeof(nstime_t));

		/* cache channel and direction */
		data->curr_channel = ctx->hdr.channel;
		data->curr_dir = ctx->hdr.dir;

		/* remove requests which are too old */
		remove_old_requests(data, &pinfo->fd->abs_ts);
	}

	if (data->curr_level < MAX_NEST_LEVEL) {
		if (ctx->hdr.netfn & 1) {
			/* perform request/response matching */
			match_request_response(data, &ctx->hdr, ctx->flags);
		} else {
			/* add request to the list for later matching */
			add_request(data, &ctx->hdr);
		}
	}

	/* get command list by network function code */
	cmd_list = ipmi_getnetfn(ctx->hdr.netfn,
			tvb_get_ptr(tvb, ctx->hdr_len + is_resp, siglen));

	/* get command descriptor */
	cmd = ipmi_getcmd(cmd_list, ctx->hdr.cmd);

	/* check if response */
	if (is_resp) {
		/* get completion code */
		cc_val = tvb_get_guint8(tvb, ctx->hdr_len);

		/* get completion code desc */
		cc_str = ipmi_get_completion_code(cc_val, cmd);
	} else {
		cc_val = 0;
		cc_str = NULL;
	}

	/* check if not inside a message */
	if (!data->curr_level) {
		/* add packet info */
		add_command_info(pinfo, cmd, is_resp, cc_val, cc_str,
				ctx->flags & IPMI_D_BROADCAST ? TRUE : FALSE);
	}

	if (tree) {
		/* add parent node */
		if (!data->curr_level) {
			ti = proto_tree_add_item(tree, hf_parent_item, tvb, 0, -1, ENC_NA);
		} else {
			char str[ITEM_LABEL_LENGTH];

			if (is_resp) {
				g_snprintf(str, ITEM_LABEL_LENGTH, "Rsp, %s, %s",
						cmd->desc, cc_str);
			} else {
				g_snprintf(str, ITEM_LABEL_LENGTH, "Req, %s", cmd->desc);
			}
			if (proto_registrar_get_ftype(hf_parent_item) == FT_STRING)
				ti = proto_tree_add_string(tree, hf_parent_item, tvb, 0, -1, str);
			else
				ti = proto_tree_add_text(tree, tvb, 0, -1, "%s", str);
		}

		/* add message sub-tree */
		cmd_tree = proto_item_add_subtree(ti, ett_tree);

		if (data->curr_level < MAX_NEST_LEVEL) {
			/* check if response */
			if (ctx->hdr.netfn & 1) {
				/* get current command data */
				ipmi_cmd_data_t * rs_data =
						data->curr_frame->cmd_data[data->curr_level];

				if (rs_data->matched_frame_num) {
					nstime_t ns;

					/* add "Request to:" field */
					ti = proto_tree_add_uint(cmd_tree, hf_ipmi_response_to,
							tvb, 0, 0, rs_data->matched_frame_num);

					/* mark field as a generated one */
					PROTO_ITEM_SET_GENERATED(ti);

					/* calculate delta time */
					nstime_delta(&ns, &pinfo->fd->abs_ts,
							&get_frame_data(data,
									rs_data->matched_frame_num)->ts);

					/* add "Response time" field */
					ti = proto_tree_add_time(cmd_tree, hf_ipmi_response_time,
							tvb, 0, 0, &ns);

					/* mark field as a generated one */
					PROTO_ITEM_SET_GENERATED(ti);
					}
			} else {
				/* get current command data */
				ipmi_cmd_data_t * rq_data =
						data->curr_frame->cmd_data[data->curr_level];

				if (rq_data->matched_frame_num) {
					/* add "Response in:" field  */
					ti = proto_tree_add_uint(cmd_tree, hf_ipmi_response_in,
							tvb, 0, 0, rq_data->matched_frame_num);

					/* mark field as a generated one */
					PROTO_ITEM_SET_GENERATED(ti);
				}
			}
		}

		/* set starting offset */
		offset = 0;

		/* check if message is broadcast */
		if (ctx->flags & IPMI_D_BROADCAST) {
			/* skip first byte */
			offset++;
		}

		/* check if session handle is specified */
		if (ctx->flags & IPMI_D_SESSION_HANDLE) {
			/* add session handle field */
			proto_tree_add_item(cmd_tree, hf_ipmi_session_handle,
					tvb, offset++, 1, ENC_LITTLE_ENDIAN);
		}

		/* check if responder address is specified */
		if (ctx->flags & IPMI_D_TRG_SA) {
			/* add response address field */
			proto_tree_add_item(cmd_tree, hf_ipmi_header_trg, tvb,
					offset++, 1, ENC_LITTLE_ENDIAN);
		}

		/* get NetFn string */
		netfn_str = ipmi_getnetfnname(ctx->hdr.netfn, cmd_list);

		/* Network function + target LUN */
		ti = proto_tree_add_text(cmd_tree, tvb, offset, 1,
				"Target LUN: 0x%02x, NetFN: %s %s (0x%02x)",
				ctx->hdr.rs_lun, netfn_str,
				is_resp ? "Response" : "Request", ctx->hdr.netfn);

		/* make a sub-tree */
		tmp_tree = proto_item_add_subtree(ti, ett_header_byte_1);

		/* add Net Fn */
		proto_tree_add_uint_format(tmp_tree, hf_ipmi_header_netfn, tvb,
				offset, 1, ctx->hdr.netfn << 2,
				"NetFn: %s %s (0x%02x)", netfn_str,
				is_resp ? "Response" : "Request", ctx->hdr.netfn);

		proto_tree_add_item(tmp_tree, hf_ipmi_header_trg_lun, tvb,
				offset++, 1, ENC_LITTLE_ENDIAN);

		/* check if cks1 is specified */
		if (!(ctx->flags & IPMI_D_NO_CKS)) {
			guint8 cks = tvb_get_guint8(tvb, offset);

			/* Header checksum */
			if (ctx->cks1) {
				guint8 correct = cks - ctx->cks1;

				proto_tree_add_uint_format_value(cmd_tree, hf_ipmi_header_crc,
						tvb, offset++, 1, cks,
						"0x%02x (incorrect, expected 0x%02x)", cks, correct);
			} else {
				proto_tree_add_uint_format_value(cmd_tree, hf_ipmi_header_crc,
						tvb, offset++, 1, cks,
						"0x%02x (correct)", cks);
			}
		}

		/* check if request address is specified */
		if (!(ctx->flags & IPMI_D_NO_RQ_SA)) {
			/* add request address field */
			proto_tree_add_item(cmd_tree, hf_ipmi_header_src, tvb,
					offset++, 1, ENC_LITTLE_ENDIAN);
		}

		/* check if request sequence is specified */
		if (!(ctx->flags & IPMI_D_NO_SEQ)) {
			/* Sequence number + source LUN */
			ti = proto_tree_add_text(cmd_tree, tvb, offset, 1,
					"%s: 0x%02x, SeqNo: 0x%02x",
					(ctx->flags & IPMI_D_TMODE) ? "Bridged" : "Source LUN",
							ctx->hdr.rq_lun, ctx->hdr.rq_seq);

			/* create byte 4 sub-tree */
			tmp_tree = proto_item_add_subtree(ti, ett_header_byte_4);

			if (ctx->flags & IPMI_D_TMODE) {
				proto_tree_add_item(tmp_tree, hf_ipmi_header_bridged,
						tvb, offset, 1, ENC_LITTLE_ENDIAN);
			} else {
				proto_tree_add_item(tmp_tree, hf_ipmi_header_src_lun,
						tvb, offset, 1, ENC_LITTLE_ENDIAN);
			}

			/* print seq no */
			proto_tree_add_item(tmp_tree, hf_ipmi_header_sequence, tvb,
					offset++, 1, ENC_LITTLE_ENDIAN);
		}

		/* command code */
		proto_tree_add_uint_format_value(cmd_tree, hf_ipmi_header_command,
				tvb, offset++, 1, ctx->hdr.cmd, "%s (0x%02x)",
				cmd->desc, ctx->hdr.cmd);

		if (is_resp) {
			/* completion code */
			proto_tree_add_uint_format_value(cmd_tree,
					hf_ipmi_header_completion, tvb, offset++, 1,
					cc_val, "%s (0x%02x)", cc_str, cc_val);
		}

		if (siglen) {
			/* command prefix (if present) */
			ti = proto_tree_add_item(cmd_tree, hf_ipmi_header_sig, tvb,
					offset, siglen, ENC_NA);
			proto_item_append_text(ti, " (%s)", netfn_str);
		}
	}

	if (tree || (cmd->flags & CMD_CALLRQ)) {
		/* calculate message data length */
		guint data_len = tvb_captured_length(tvb)
				- ctx->hdr_len
				- siglen
				- (is_resp ? 1 : 0)
				- !(ctx->flags & IPMI_D_NO_CKS);

		/* create data subset */
		tvbuff_t * data_tvb = tvb_new_subset_length(tvb,
				ctx->hdr_len + siglen + (is_resp ? 1 : 0), data_len);

		/* Select sub-handler */
		ipmi_cmd_handler_t hnd = is_resp ? cmd->parse_resp : cmd->parse_req;

		if (hnd && tvb_captured_length(data_tvb)) {
			if (tree) {
				/* create data field */
				ti = proto_tree_add_text(cmd_tree, data_tvb, 0, -1, "Data");

				/* create data sub-tree */
				tmp_tree = proto_item_add_subtree(ti, ett_data);
			} else {
				tmp_tree = NULL;
			}

			/* save current command */
			data->curr_hdr = &ctx->hdr;

			/* save current completion code */
			data->curr_ccode = cc_val;

			/* call command parser */
			hnd(data_tvb, pinfo, tmp_tree);
		}
	}

	/* check if cks2 is specified */
	if (tree && !(ctx->flags & IPMI_D_NO_CKS)) {
		guint8 cks;

		/* get cks2 offset */
		offset = tvb_captured_length(tvb) - 1;

		/* get cks2 */
		cks = tvb_get_guint8(tvb, offset);

		/* Header checksum */
		if (ctx->cks2) {
			guint8 correct = cks - ctx->cks2;

			proto_tree_add_uint_format_value(cmd_tree, hf_ipmi_data_crc,
					tvb, offset, 1, cks,
					"0x%02x (incorrect, expected 0x%02x)", cks, correct);
		} else {
			proto_tree_add_uint_format_value(cmd_tree, hf_ipmi_data_crc,
					tvb, offset, 1, cks,
					"0x%02x (correct)", cks);
		}
	}

	/* decrement next nest level */
	data->next_level = data->curr_level;

	/* restore previous nest level */
	data->curr_level = prev_level;

	return tvb_captured_length(tvb);
}

/* Get currently parsed message header */
const ipmi_header_t * ipmi_get_hdr(packet_info * pinfo)
{
	ipmi_packet_data_t * data = get_packet_data(pinfo);
	return data->curr_hdr;
}

/* Get completion code for currently parsed message */
guint8 ipmi_get_ccode(packet_info * pinfo)
{
	ipmi_packet_data_t * data = get_packet_data(pinfo);
	return data->curr_ccode;
}

/* Save request data for later use in response */
void ipmi_set_data(packet_info *pinfo, guint idx, guint32 value)
{
	ipmi_packet_data_t * data = get_packet_data(pinfo);

	/* check bounds */
	if (data->curr_level >= MAX_NEST_LEVEL || idx >= NSAVED_DATA ) {
		return;
	}

	/* save data */
	data->curr_frame->cmd_data[data->curr_level]->saved_data[idx] = value;
}

/* Get saved request data */
gboolean ipmi_get_data(packet_info *pinfo, guint idx, guint32 * value)
{
	ipmi_packet_data_t * data = get_packet_data(pinfo);

	/* check bounds */
	if (data->curr_level >= MAX_NEST_LEVEL || idx >= NSAVED_DATA ) {
		return FALSE;
	}

	/* get data */
	*value = data->curr_frame->cmd_data[data->curr_level]->saved_data[idx];
	return TRUE;
}

/* ----------------------------------------------------------------
   Support for Type/Length fields parsing.
---------------------------------------------------------------- */

static void
get_len_binary(guint *clen, guint *blen, tvbuff_t *tvb _U_, guint offs _U_,
		guint len, gboolean len_is_bytes _U_)
{
	*clen = len * 3;
	*blen = len;
}

static void
parse_binary(char *p, tvbuff_t *tvb, guint offs, guint len)
{
	static const char hex[] = "0123456789ABCDEF";
	guint8 v;
	guint i;

	for (i = 0; i < len / 3; i++) {
		v = tvb_get_guint8(tvb, offs + i);
		*p++ = hex[v >> 4];
		*p++ = hex[v & 0xf];
		*p++ = ' ';
	}

	if (i) {
		*--p = '\0';
	}
}

static struct ipmi_parse_typelen ptl_binary = {
	get_len_binary, parse_binary, "Binary"
};

static void
get_len_bcdplus(guint *clen, guint *blen, tvbuff_t *tvb _U_, guint offs _U_,
		guint len, gboolean len_is_bytes)
{
	if (len_is_bytes) {
		*clen = len * 2;
		*blen = len;
	} else {
		*blen = (len + 1) / 2;
		*clen = len;
	}
}

static void
parse_bcdplus(char *p, tvbuff_t *tvb, guint offs, guint len)
{
	static const char bcd[] = "0123456789 -.:,_";
	guint i, msk = 0xf0, shft = 4;
	guint8 v;

	for (i = 0; i < len; i++) {
		v = (tvb_get_guint8(tvb, offs + i / 2) & msk) >> shft;
		*p++ = bcd[v];
		msk ^= 0xff;
		shft = 4 - shft;
	}
}

static struct ipmi_parse_typelen ptl_bcdplus = {
	get_len_bcdplus, parse_bcdplus, "BCD+"
};

static void
get_len_6bit_ascii(guint *clen, guint *blen, tvbuff_t *tvb _U_, guint offs _U_,
		guint len, gboolean len_is_bytes)
{
	if (len_is_bytes) {
		*clen = len * 4 / 3;
		*blen = len;
	} else {
		*blen = (len * 3 + 3) / 4;
		*clen = len;
	}
}

static void
parse_6bit_ascii(char *p, tvbuff_t *tvb, guint offs, guint len)
{
	guint32 v;
	guint i;

	/* First, handle "full" triplets of bytes, 4 characters each */
	for (i = 0; i < len / 4; i++) {
		v = tvb_get_letoh24(tvb, offs + i * 3);
		p[0] = ' ' + (v & 0x3f);
		p[1] = ' ' + ((v >> 6) & 0x3f);
		p[2] = ' ' + ((v >> 12) & 0x3f);
		p[3] = ' ' + ((v >> 18) & 0x3f);
		p += 4;
	}

	/* Do we have any characters left? */
	offs += len / 4;
	len &= 0x3;
	switch (len) {
	case 3:
		v = (tvb_get_guint8(tvb, offs + 2) << 4) | (tvb_get_guint8(tvb, offs + 1) >> 4);
		p[2] = ' ' + (v & 0x3f);
		/* Fall thru */
	case 2:
		v = (tvb_get_guint8(tvb, offs + 1) << 2) | (tvb_get_guint8(tvb, offs) >> 6);
		p[1] = ' ' + (v & 0x3f);
		/* Fall thru */
	case 1:
		v = tvb_get_guint8(tvb, offs) & 0x3f;
		p[0] = ' ' + (v & 0x3f);
	}
}

static struct ipmi_parse_typelen ptl_6bit_ascii = {
	get_len_6bit_ascii, parse_6bit_ascii, "6-bit ASCII"
};

static void
get_len_8bit_ascii(guint *clen, guint *blen, tvbuff_t *tvb, guint offs,
		guint len, gboolean len_is_bytes _U_)
{
	guint i;
	guint8 ch;

	*blen = len;	/* One byte is one character */
	*clen = 0;
	for (i = 0; i < len; i++) {
		ch = tvb_get_guint8(tvb, offs + i);
		*clen += (ch >= 0x20 && ch <= 0x7f) ? 1 : 4;
	}
}

static void
parse_8bit_ascii(char *p, tvbuff_t *tvb, guint offs, guint len)
{
	guint8 ch;
	char *pmax;

	pmax = p + len;
	while (p < pmax) {
		ch = tvb_get_guint8(tvb, offs++);
		if (ch >= 0x20 && ch <= 0x7f) {
			*p++ = ch;
		} else {
			g_snprintf(p, 5, "\\x%02x", ch);
			p += 4;
		}
	}
}

static struct ipmi_parse_typelen ptl_8bit_ascii = {
	get_len_8bit_ascii, parse_8bit_ascii, "ASCII+Latin1"
};

static void
get_len_unicode(guint *clen, guint *blen, tvbuff_t *tvb _U_, guint offs _U_,
		guint len _U_, gboolean len_is_bytes)
{
	if (len_is_bytes) {
		*clen = len * 3; /* Each 2 bytes result in 6 chars printed: \Uxxxx */
		*blen = len;
	} else {
		*clen = len * 6;
		*blen = len * 2;
	}
}

static void
parse_unicode(char *p, tvbuff_t *tvb, guint offs, guint len)
{
	char *pmax = p + len;
	guint8 ch0, ch1;

	while (p < pmax) {
		ch0 = tvb_get_guint8(tvb, offs++);
		ch1 = tvb_get_guint8(tvb, offs++);
		g_snprintf(p, 7, "\\U%02x%02x", ch0, ch1);
		p += 6;
	}
}

static struct ipmi_parse_typelen ptl_unicode = {
	get_len_unicode, parse_unicode, "Unicode"
};

void
ipmi_add_typelen(proto_tree *tree, const char *desc, tvbuff_t *tvb,
		guint offs, gboolean is_fru)
{
	static struct ipmi_parse_typelen *fru_eng[4] = {
		&ptl_binary, &ptl_bcdplus, &ptl_6bit_ascii, &ptl_8bit_ascii
	};
	static struct ipmi_parse_typelen *fru_noneng[4] = {
		&ptl_binary, &ptl_bcdplus, &ptl_6bit_ascii, &ptl_unicode
	};
	static struct ipmi_parse_typelen *ipmi[4] = {
		&ptl_unicode, &ptl_bcdplus, &ptl_6bit_ascii, &ptl_8bit_ascii
	};
	struct ipmi_parse_typelen *ptr;
	proto_tree *s_tree;
	proto_item *ti;
	guint type, msk, clen, blen, len;
	const char *unit;
	char *str;
	guint8 typelen;

	typelen = tvb_get_guint8(tvb, offs);
	type = typelen >> 6;
	if (is_fru) {
		msk = 0x3f;
		ptr = (fru_langcode_is_english ? fru_eng : fru_noneng)[type];
		unit = "bytes";
	} else {
		msk = 0x1f;
		ptr = ipmi[type];
		unit = "characters";
	}

	len = typelen & msk;
	ptr->get_len(&clen, &blen, tvb, offs + 1, len, is_fru);

	str = (char *)wmem_alloc(wmem_packet_scope(), clen + 1);
	ptr->parse(str, tvb, offs + 1, clen);
	str[clen] = '\0';

	ti = proto_tree_add_text(tree, tvb, offs, 1, "%s Type/Length byte: %s, %d %s",
			desc, ptr->desc, len, unit);
	s_tree = proto_item_add_subtree(ti, ett_typelen);
	proto_tree_add_text(s_tree, tvb, offs, 1, "%sType: %s (0x%02x)",
			ipmi_dcd8(typelen, 0xc0), ptr->desc, type);
	proto_tree_add_text(s_tree, tvb, offs, 1, "%sLength: %d %s",
			ipmi_dcd8(typelen, msk), len, unit);

	proto_tree_add_text(tree, tvb, offs + 1, blen, "%s: [%s] '%s'",
			desc, ptr->desc, str);
}

/* ----------------------------------------------------------------
   Timestamp, IPMI-style.
---------------------------------------------------------------- */
void
ipmi_add_timestamp(proto_tree *tree, gint hf, tvbuff_t *tvb, guint offset)
{
	guint32 ts = tvb_get_letohl(tvb, offset);

	if (ts == 0xffffffff) {
		proto_tree_add_uint_format_value(tree, hf, tvb, offset, 4,
				ts, "Unspecified/Invalid");
	} else if (ts <= 0x20000000) {
		proto_tree_add_uint_format_value(tree, hf, tvb, offset, 4,
				ts, "%s since SEL device's initialization",
				time_secs_to_str_unsigned(wmem_packet_scope(), ts));
	} else {
		proto_tree_add_uint_format_value(tree, hf, tvb, offset, 4,
				ts, "%s", abs_time_secs_to_str(wmem_packet_scope(), ts, ABSOLUTE_TIME_UTC, TRUE));
	}
}

/* ----------------------------------------------------------------
   GUID, IPMI-style.
---------------------------------------------------------------- */

void
ipmi_add_guid(proto_tree *tree, gint hf, tvbuff_t *tvb, guint offset)
{
	e_guid_t guid;
	int i;

	guid.data1 = tvb_get_letohl(tvb, offset + 12);
	guid.data2 = tvb_get_letohs(tvb, offset + 10);
	guid.data3 = tvb_get_letohs(tvb, offset + 8);
	for (i = 0; i < 8; i++) {
		guid.data4[i] = tvb_get_guint8(tvb, offset + 7 - i);
	}
	proto_tree_add_guid(tree, hf, tvb, offset, 16, &guid);
}

/* ----------------------------------------------------------------
   Routines for registering/looking up command parsers.
---------------------------------------------------------------- */

static void
ipmi_netfn_setdesc(guint32 netfn, const char *desc, guint32 siglen)
{
	struct ipmi_netfn_root *inr;

	inr = &ipmi_cmd_tab[netfn >> 1];
	inr->desc = desc;
	inr->siglen = siglen;
}

void
ipmi_register_netfn_cmdtab(guint32 netfn, guint oem_selector,
		const guint8 *sig, guint32 siglen, const char *desc,
		ipmi_cmd_t *cmdtab, guint32 cmdtablen)
{
	struct ipmi_netfn_root *inr;
	ipmi_netfn_t *inh;

	netfn >>= 1;	/* Requests and responses grouped together */
	if (netfn >= IPMI_NETFN_MAX) {
		return;
	}

	inr = &ipmi_cmd_tab[netfn];
	if (inr->siglen != siglen) {
		return;
	}

	inh = (struct ipmi_netfn_handler *)g_malloc(sizeof(struct ipmi_netfn_handler));
	inh->desc = desc;
	inh->oem_selector = oem_selector;
	inh->sig = sig;
	inh->cmdtab = cmdtab;
	inh->cmdtablen = cmdtablen;

	inh->next = inr->list;
	inr->list = inh;
}

guint32
ipmi_getsiglen(guint32 netfn)
{
	return ipmi_cmd_tab[netfn >> 1].siglen;
}

const char *
ipmi_getnetfnname(guint32 netfn, ipmi_netfn_t *nf)
{
	const char *dn, *db;

	dn = ipmi_cmd_tab[netfn >> 1].desc ?
		ipmi_cmd_tab[netfn >> 1].desc : "Reserved";
	db = nf ? nf->desc : NULL;
	if (db) {
		return wmem_strdup_printf(wmem_packet_scope(), "%s (%s)", db, dn);
	} else {
		return dn;
	}
}

ipmi_netfn_t *
ipmi_getnetfn(guint32 netfn, const guint8 *sig)
{
	struct ipmi_netfn_root *inr;
	ipmi_netfn_t *inh;

	inr = &ipmi_cmd_tab[netfn >> 1];
	for (inh = inr->list; inh; inh = inh->next) {
		if ((inh->oem_selector == selected_oem || inh->oem_selector == IPMI_OEM_NONE)
				&& (!inr->siglen || !memcmp(sig, inh->sig, inr->siglen))) {
			return inh;
		}
	}

	/* Either unknown netFn or signature does not match */
	return NULL;
}

ipmi_cmd_t *
ipmi_getcmd(ipmi_netfn_t *nf, guint32 cmd)
{
	static ipmi_cmd_t ipmi_cmd_unknown = {
		0x00,		/* Code */
		ipmi_notimpl,	/* request */
		ipmi_notimpl,	/* response */
		NULL,		/* command codes */
		NULL,		/* subfunctions */
		"Unknown command",
		0		/* flag */
	};
	ipmi_cmd_t *ic;
	size_t i, len;

	if (nf) {
		len = nf->cmdtablen;
		for (ic = nf->cmdtab, i = 0; i < len; i++, ic++) {
			if (ic->cmd == cmd) {
				return ic;
			}
		}
	}

	return &ipmi_cmd_unknown;
}

/* ----------------------------------------------------------------
   Various utility functions.
---------------------------------------------------------------- */

void
ipmi_notimpl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_expert(tree, pinfo, &ei_impi_parser_not_implemented, tvb, 0, -1);
}

char *
ipmi_dcd8(guint32 val, guint32 mask)
{
	static char buf[64];

	decode_bitfield_value(buf, val, mask, 8);
	return buf;
}

void
ipmi_fmt_10ms_1based(gchar *s, guint32 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%d.%03d seconds", v / 100, (v % 100) * 10);
}

void
ipmi_fmt_500ms_0based(gchar *s, guint32 v)
{
	ipmi_fmt_500ms_1based(s, ++v);
}

void
ipmi_fmt_500ms_1based(gchar *s, guint32 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%d.%03d seconds", v / 2, (v % 2) * 500);
}

void
ipmi_fmt_1s_0based(gchar *s, guint32 v)
{
	ipmi_fmt_1s_1based(s, ++v);
}

void
ipmi_fmt_1s_1based(gchar *s, guint32 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%d seconds", v);
}

void
ipmi_fmt_2s_0based(gchar *s, guint32 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%d seconds", (v + 1) * 2);
}

void
ipmi_fmt_5s_1based(gchar *s, guint32 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%d seconds", v * 5);
}

void
ipmi_fmt_version(gchar *s, guint32 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%d.%d", v & 0x0f, (v >> 4) & 0x0f);
}

void
ipmi_fmt_channel(gchar *s, guint32 v)
{
	static const value_string chan_vals[] = {
		{ 0x00, "Primary IPMB (IPMB-0)" },
		{ 0x07, "IPMB-L" },
		{ 0x0e, "Current channel" },
		{ 0x0f, "System Interface" },
		{ 0, NULL }
	};

	g_snprintf(s, ITEM_LABEL_LENGTH, "%s (0x%02x)",
			val_to_str(v, chan_vals, "Channel #%d"), v);
}

void
ipmi_fmt_udpport(gchar *s, guint32 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%s (%d)", ep_udp_port_to_display(v), v);
}

void
ipmi_fmt_percent(gchar *s, guint32 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%d%%", v);
}

const char *
ipmi_get_completion_code(guint8 completion, ipmi_cmd_t *cmd)
{
	static const value_string std_completion_codes[] = {
		{ 0x00, "Command Completed Normally" },
		{ 0xc0, "Node Busy" },
		{ 0xc1, "Invalid Command" },
		{ 0xc2, "Command invalid for given LUN" },
		{ 0xc3, "Timeout while processing command, response unavailable" },
		{ 0xc4, "Out of space" },
		{ 0xc5, "Reservation Canceled or Invalid Reservation ID" },
		{ 0xc6, "Request data truncated" },
		{ 0xc7, "Request data length invalid" },
		{ 0xc8, "Request data field length limit exceeded" },
		{ 0xc9, "Parameter out of range" },
		{ 0xca, "Cannot return number of requested data bytes" },
		{ 0xcb, "Requested Sensor, data, or record not present" },
		{ 0xcc, "Invalid data field in Request" },
		{ 0xcd, "Command illegal for specified sensor or record type" },
		{ 0xce, "Command response could not be provided" },
		{ 0xcf, "Cannot execute duplicated request" },
		{ 0xd0, "Command response could not be provided: SDR Repository in update mode" },
		{ 0xd1, "Command response could not be provided: device in firmware update mode" },
		{ 0xd2, "Command response could not be provided: BMC initialization or initialization agent in progress" },
		{ 0xd3, "Destination unavailable" },
		{ 0xd4, "Cannot execute command: insufficient privilege level or other security-based restriction" },
		{ 0xd5, "Cannot execute command: command, or request parameter(s), not supported in present state" },
		{ 0xd6, "Cannot execute command: parameter is illegal because subfunction is disabled or unavailable" },
		{ 0xff, "Unspecified error" },

		{ 0, NULL }
	};
	const char *res;

	if (completion >= 0x01 && completion <= 0x7e) {
		return "Device specific (OEM) completion code";
	}

	if (completion >= 0x80 && completion <= 0xbe) {
		if (cmd && cmd->cs_cc && (res = try_val_to_str(completion, cmd->cs_cc)) != NULL) {
			return res;
		}
		return "Standard command-specific code";
	}

	return val_to_str_const(completion, std_completion_codes, "Unknown");
}

static int
dissect_tmode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	ipmi_dissect_arg_t * arg = (ipmi_dissect_arg_t *) data;
	ipmi_context_t ctx;
	guint tvb_len = tvb_captured_length(tvb);
	guint8 tmp;

	/* TMode message is at least 3 bytes length */
	if (tvb_len < 3) {
		return 0;
	}

	memset(&ctx, 0, sizeof(ctx));

	/* get Net Fn/RS LUN field */
	tmp = tvb_get_guint8(tvb, 0);

	/* set Net Fn */
	ctx.hdr.netfn = tmp >> 2;

	/*
	 * NOTE: request/response matching code swaps RQ LUN with RS LUN
	 * fields in IPMB-like manner in order to find corresponding request
	 * so, we set both RS LUN and RQ LUN here for correct
	 * request/response matching
	 */
	ctx.hdr.rq_lun = tmp & 3;
	ctx.hdr.rs_lun = tmp & 3;

	/* get RQ Seq field */
	ctx.hdr.rq_seq = tvb_get_guint8(tvb, 1) >> 2;

	/*
	 * NOTE: bridge field is ignored in request/response matching
	 */

	/* get command code */
	ctx.hdr.cmd = tvb_get_guint8(tvb, 2);

	/* set dissect flags */
	ctx.flags = IPMI_D_TMODE|IPMI_D_NO_CKS|IPMI_D_NO_RQ_SA;

	/* set header length */
	ctx.hdr_len = 3;

	/* copy channel number and direction */
	ctx.hdr.context = arg ? arg->context : IPMI_E_NONE;
	ctx.hdr.channel = arg ? arg->channel : 0;
	ctx.hdr.dir = arg ? arg->flags >> 7 : ctx.hdr.netfn & 1;

	if (ctx.hdr.context == IPMI_E_NONE) {
		/* set source column */
		col_set_str(pinfo->cinfo, COL_DEF_SRC,
				ctx.hdr.dir ? "Console" : "BMC");

		/* set destination column */
		col_set_str(pinfo->cinfo, COL_DEF_DST,
				ctx.hdr.dir ? "BMC" : "Console");
	}

	/* dissect IPMI command */
	return dissect_ipmi_cmd(tvb, pinfo, tree, proto_tmode, ett_ipmi, &ctx);
}

static int
dissect_kcs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	ipmi_dissect_arg_t * arg = (ipmi_dissect_arg_t *) data;
	ipmi_context_t ctx;
	guint tvb_len = tvb_captured_length(tvb);
	guint8 tmp;

	/* KCS message is at least 2 bytes length */
	if (tvb_len < 2) {
		return 0;
	}

	memset(&ctx, 0, sizeof(ctx));

	/* get Net Fn/RS LUN field */
	tmp = tvb_get_guint8(tvb, 0);

	/* set Net Fn */
	ctx.hdr.netfn = tmp >> 2;

	/*
	 * NOTE: request/response matching code swaps RQ LUN with RS LUN
	 * fields in IPMB-like manner in order to find corresponding request
	 * so, we set both RS LUN and RQ LUN here for correct
	 * request/response matching
	 */
	ctx.hdr.rq_lun = tmp & 3;
	ctx.hdr.rs_lun = tmp & 3;

	/* get command code */
	ctx.hdr.cmd = tvb_get_guint8(tvb, 1);

	/* set dissect flags */
	ctx.flags = IPMI_D_NO_CKS|IPMI_D_NO_RQ_SA|IPMI_D_NO_SEQ;

	/* set header length */
	ctx.hdr_len = 2;

	/* copy channel number and direction */
	ctx.hdr.context = arg ? arg->context : 0;
	ctx.hdr.channel = arg ? arg->channel : 0;
	ctx.hdr.dir = arg ? arg->flags >> 7 : ctx.hdr.netfn & 1;

	if (ctx.hdr.context == IPMI_E_NONE) {
		/* set source column */
		col_set_str(pinfo->cinfo, COL_DEF_SRC, ctx.hdr.dir ? "HOST" : "BMC");

		/* set destination column */
		col_set_str(pinfo->cinfo, COL_DEF_DST, ctx.hdr.dir ? "BMC" : "HOST");
	}

	/* dissect IPMI command */
	return dissect_ipmi_cmd(tvb, pinfo, tree, proto_kcs, ett_ipmi, &ctx);
}

static guint8 calc_cks(guint8 start, tvbuff_t * tvb, guint off, guint len)
{
	while (len--) {
		start += tvb_get_guint8(tvb, off++);
	}

	return start;
}

static gboolean guess_imb_format(tvbuff_t *tvb, guint8 env,
		guint8 channel, guint * imb_flags, guint8 * cks1, guint8 * cks2)
{
	gboolean check_bc = FALSE;
	gboolean check_sh = FALSE;
	gboolean check_sa = FALSE;
	guint tvb_len;
	guint sh_len;
	guint sa_len;
	guint rs_sa;

	if (message_format == MSGFMT_NONE) {
		return FALSE;
	} else if (message_format == MSGFMT_IPMB) {
		*imb_flags = IPMI_D_TRG_SA;
	} else if (message_format == MSGFMT_LAN) {
		*imb_flags = IPMI_D_TRG_SA|IPMI_D_SESSION_HANDLE;
	/* channel 0 is primary IPMB */
	} else if (!channel) {
		/* check for broadcast if not in send message command */
		if (env == IPMI_E_NONE) {
			/* check broadcast */
			check_bc = 1;

			/* slave address must be present */
			*imb_flags = IPMI_D_TRG_SA;
		/* check if in send message command */
		} else if (env != IPMI_E_GETMSG) {
			/* slave address must be present */
			*imb_flags = IPMI_D_TRG_SA;
		} else /* IPMI_E_GETMSG */ {
			*imb_flags = 0;
		}
	/* channel 15 is System Interface */
	} else if (channel == 15) {
		/* slave address must be present */
		*imb_flags = IPMI_D_TRG_SA;

		/* check if in get message command */
		if (env == IPMI_E_GETMSG) {
			/* session handle must be present */
			*imb_flags |= IPMI_D_SESSION_HANDLE;
		}
	/* for other channels */
	} else {
		if (env == IPMI_E_NONE) {
			/* check broadcast */
			check_bc = 1;

			/* slave address must be present */
			*imb_flags = IPMI_D_TRG_SA;
		} else if (env == IPMI_E_SENDMSG_RQ) {
			/* check session handle */
			check_sh = 1;

			/* slave address must be present */
			*imb_flags = IPMI_D_TRG_SA;
		} else if (env == IPMI_E_SENDMSG_RS) {
			/* slave address must be present */
			*imb_flags = IPMI_D_TRG_SA;
		} else /* IPMI_E_GETMSG */ {
			/* check session handle */
			check_sh = 1;

			/* check slave address presence */
			check_sa = 1;

			/* no pre-requisites */
			*imb_flags = 0;
		}
	}

	/* get message length */
	tvb_len = tvb_captured_length(tvb);

	/*
	 * broadcast message starts with null,
	 * does not contain session handle
	 * but contains responder address
	 */
	if (check_bc
			&& tvb_len >= 8
			&& !tvb_get_guint8(tvb, 0)
			&& !calc_cks(0, tvb, 1, 3)
			&& !calc_cks(0, tvb, 4, tvb_len - 4)) {
		*imb_flags = IPMI_D_BROADCAST|IPMI_D_TRG_SA;
		*cks1 = 0;
		*cks2 = 0;
		return TRUE;
	}

	/*
	 * message with the starts with session handle
	 * and contain responder address
	 */
	if (check_sh
			&& tvb_len >= 8
			&& !calc_cks(0, tvb, 1, 3)
			&& !calc_cks(0, tvb, 4, tvb_len - 4)) {
		*imb_flags = IPMI_D_SESSION_HANDLE|IPMI_D_TRG_SA;
		*cks1 = 0;
		*cks2 = 0;
		return TRUE;
	}

	/*
	 * message with responder address
	 */
	if (check_sa
			&& tvb_len >= 7
			&& !calc_cks(0, tvb, 0, 3)
			&& !calc_cks(0, tvb, 3, tvb_len - 3)) {
		*imb_flags = IPMI_D_TRG_SA;
		*cks1 = 0;
		*cks2 = 0;
		return TRUE;
	}


	if (*imb_flags & IPMI_D_SESSION_HANDLE) {
		sh_len = 1;
		sa_len = 1;
		rs_sa = 0;
	} else if (*imb_flags & IPMI_D_TRG_SA) {
		sh_len = 0;
		sa_len = 1;
		rs_sa = 0;
	} else {
		sh_len = 0;
		sa_len = 0;
		rs_sa = 0x20;
	}

	/* check message length */
	if (tvb_len < 6 + sh_len + sa_len) {
		return FALSE;
	}

	/* calculate checksum deltas */
	*cks1 = calc_cks(rs_sa, tvb, sh_len, sa_len + 2);
	*cks2 = calc_cks(0, tvb, sh_len + sa_len + 2,
			tvb_len - sh_len - sa_len - 2);

	return TRUE;
}

int
do_dissect_ipmb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		gint hf_parent_item, gint ett_tree, ipmi_dissect_arg_t * arg)
{
	ipmi_context_t ctx;
	guint offset = 0;
	guint8 tmp;

	memset(&ctx, 0, sizeof(ctx));

	/* copy message context and channel */
	ctx.hdr.context = arg ? arg->context : 0;
	ctx.hdr.channel = arg ? arg->channel : 0;

	/* guess IPMB message format */
	if (!guess_imb_format(tvb, ctx.hdr.context, ctx.hdr.channel,
			&ctx.flags, &ctx.cks1, &ctx.cks2)) {
		return 0;
	}

	/* check if message is broadcast */
	if (ctx.flags & IPMI_D_BROADCAST) {
		/* skip first byte */
		offset++;
	}

	/* check is session handle is specified */
	if (ctx.flags & IPMI_D_SESSION_HANDLE) {
		ctx.hdr.session = tvb_get_guint8(tvb, offset++);
	}

	/* check is response address is specified */
	if (ctx.flags & IPMI_D_TRG_SA) {
		ctx.hdr.rs_sa = tvb_get_guint8(tvb, offset++);
	} else {
		ctx.hdr.rs_sa = 0x20;
	}

	/* get Net Fn/RS LUN field */
	tmp = tvb_get_guint8(tvb, offset++);

	/* set Net Fn  and RS LUN */
	ctx.hdr.netfn = tmp >> 2;
	ctx.hdr.rs_lun = tmp & 3;

	/* skip cks1 */
	offset++;

	/* get RQ SA */
	ctx.hdr.rq_sa = tvb_get_guint8(tvb, offset++);

	/* get RQ Seq/RQ LUN field */
	tmp = tvb_get_guint8(tvb, offset++);

	/* set RQ Seq  and RQ LUN */
	ctx.hdr.rq_seq = tmp >> 2;
	ctx.hdr.rq_lun = tmp & 3;

	/* get command code */
	ctx.hdr.cmd = tvb_get_guint8(tvb, offset++);

	/* set header length */
	ctx.hdr_len = offset;

	/* copy direction */
	ctx.hdr.dir = arg ? arg->flags >> 7 : ctx.hdr.netfn & 1;

	if (ctx.hdr.context == IPMI_E_NONE) {
		guint red = arg ? (arg->flags & 0x40) : 0;

		if (!ctx.hdr.channel) {
			col_add_fstr(pinfo->cinfo, COL_DEF_SRC,
					"0x%02x(%s)", ctx.hdr.rq_sa, red ? "IPMB-B" : "IPMB-A");
		} else {
			col_add_fstr(pinfo->cinfo, COL_DEF_SRC,
					"0x%02x", ctx.hdr.rq_sa);
		}

		col_add_fstr(pinfo->cinfo, COL_DEF_DST, "0x%02x", ctx.hdr.rs_sa);
	}

	/* dissect IPMI command */
	return dissect_ipmi_cmd(tvb, pinfo, tree, hf_parent_item, ett_tree, &ctx);
}

static int
dissect_ipmi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	return do_dissect_ipmb(tvb, pinfo, tree, proto_ipmb, ett_ipmi,
			(ipmi_dissect_arg_t *) data);
}

/* Register IPMB protocol.
 */
void
proto_register_ipmi(void)
{
	static hf_register_info	hf[] = {
		{ &hf_ipmi_session_handle, { "Session handle", "ipmi.session_handle", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_header_trg, { "Target Address", "ipmi.header.target", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_ipmi_header_trg_lun, { "Target LUN", "ipmi.header.trg_lun", FT_UINT8, BASE_HEX, NULL, 0x03, NULL, HFILL }},
		{ &hf_ipmi_header_netfn, { "NetFN", "ipmi.header.netfn", FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL }},
		{ &hf_ipmi_header_crc, { "Header Checksum", "ipmi.header.crc", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_header_src, { "Source Address", "ipmi.header.source", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_header_src_lun, { "Source LUN", "ipmi.header.src_lun", FT_UINT8, BASE_HEX, NULL, 0x03, NULL, HFILL }},
		{ &hf_ipmi_header_bridged, { "Bridged", "ipmi.header.bridged", FT_UINT8, BASE_HEX, NULL, 0x03, NULL, HFILL }},
		{ &hf_ipmi_header_sequence, { "Sequence Number", "ipmi.header.sequence", FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL }},
		{ &hf_ipmi_header_command, { "Command", "ipmi.header.command", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_header_completion, { "Completion Code", "ipmi.header.completion", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_header_sig, { "Signature", "ipmi.header.signature", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_data_crc, { "Data checksum", "ipmi.data.crc", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_response_to, { "Response to", "ipmi.response_to", FT_FRAMENUM, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_response_in, { "Response in", "ipmi.response_in", FT_FRAMENUM, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_response_time, { "Responded in", "ipmi.response_time", FT_RELATIVE_TIME, BASE_NONE, NULL, 0, NULL, HFILL }}
	};
	static gint *ett[] = {
		&ett_ipmi,
		&ett_header,
		&ett_header_byte_1,
		&ett_header_byte_4,
		&ett_data,
		&ett_typelen
	};
	static const enum_val_t msgfmt_vals[] = {
		{ "none", "None", MSGFMT_NONE },
		{ "ipmb", "IPMB", MSGFMT_IPMB },
		{ "lan", "Session-based (LAN, ...)", MSGFMT_LAN },
		{ "guess", "Use heuristics", MSGFMT_GUESS },
		{ NULL, NULL, 0 }
	};
	static const enum_val_t oemsel_vals[] = {
		{ "none", "None", IPMI_OEM_NONE },
		{ "pps", "Pigeon Point Systems", IPMI_OEM_PPS },
		{ NULL, NULL, 0 }
	};

	static ei_register_info ei[] = {
		{ &ei_impi_parser_not_implemented, { "ipmi.parser_not_implemented", PI_UNDECODED, PI_WARN, "[PARSER NOT IMPLEMENTED]", EXPFILL }},
	};

	module_t *m;
	expert_module_t* expert_ipmi;
	guint32 i;

	proto_ipmi = proto_register_protocol("Intelligent Platform Management Interface",
	                        "IPMI",
	                        "ipmi");

	proto_ipmb = proto_register_protocol("Intelligent Platform Management Bus",
	                        "IPMB",
	                        "ipmb");
	proto_kcs = proto_register_protocol("Keyboard Controller Style Interface",
	                        "KCS",
	                        "kcs");
	proto_tmode = proto_register_protocol("Serial Terminal Mode Interface",
	                        "TMode",
	                        "tmode");

	proto_register_field_array(proto_ipmi, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_ipmi = expert_register_protocol(proto_ipmi);
	expert_register_field_array(expert_ipmi, ei, array_length(ei));

	ipmi_netfn_setdesc(IPMI_CHASSIS_REQ, "Chassis", 0);
	ipmi_netfn_setdesc(IPMI_BRIDGE_REQ, "Bridge", 0);
	ipmi_netfn_setdesc(IPMI_SE_REQ, "Sensor/Event", 0);
	ipmi_netfn_setdesc(IPMI_APP_REQ, "Application", 0);
	ipmi_netfn_setdesc(IPMI_UPDATE_REQ, "Firmware Update", 0);
	ipmi_netfn_setdesc(IPMI_STORAGE_REQ, "Storage", 0);
	ipmi_netfn_setdesc(IPMI_TRANSPORT_REQ, "Transport", 0);
	ipmi_netfn_setdesc(IPMI_GROUP_REQ, "Group", 1);
	ipmi_netfn_setdesc(IPMI_OEM_REQ, "OEM/Group", 3);
	for (i = 0x30; i < 0x40; i += 2) {
		ipmi_netfn_setdesc(i, "OEM", 0);
	}

	new_register_dissector("ipmi", dissect_ipmi, proto_ipmi);
	new_register_dissector("ipmb", dissect_ipmi, proto_ipmb);
	new_register_dissector("kcs", dissect_kcs, proto_kcs);
	new_register_dissector("tmode", dissect_tmode, proto_tmode);

	data_dissector = find_dissector("data");

	m = prefs_register_protocol(proto_ipmi, NULL);
	prefs_register_bool_preference(m, "fru_langcode_is_english", "FRU Language Code is English",
			"FRU Language Code is English; strings are ASCII+LATIN1 (vs. Unicode)",
			&fru_langcode_is_english);
	prefs_register_uint_preference(m, "response_after_req", "Maximum delay of response message",
			"Do not search for responses coming after this timeout (milliseconds)",
			10, &response_after_req);
	prefs_register_uint_preference(m, "response_before_req", "Response ahead of request",
			"Allow for responses before requests (milliseconds)",
			10, &response_before_req);
	prefs_register_enum_preference(m, "msgfmt", "Format of embedded messages",
			"Format of messages embedded into Send/Get/Forward Message",
			&message_format, msgfmt_vals, FALSE);
	prefs_register_enum_preference(m, "selected_oem", "OEM commands parsed as",
			"Selects which OEM format is used for commands that IPMI does not define",
			&selected_oem, oemsel_vals, FALSE);
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

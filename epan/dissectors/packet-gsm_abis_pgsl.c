/* packet-gsm_abis_pgsl.c
 * Routines for packet dissection of Ericsson GSM A-bis P-GSL
 * Copyright 2010-2016 by Harald Welte <laforge@gnumonks.org>
 *
 * P-GSL is an Ericsson-specific packetized version of replacing PCU-CCU
 * TRAU frames on 8k/16k E1 sub-slots with a paketized frame format
 * which can be transported over LAPD on a SuperChannel (E1 timeslot
 * bundle) or L2TP.
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

#include "packet-gsm_rlcmac.h"
#include "packet-gsm_a_common.h"

void proto_register_abis_pgsl(void);
void proto_reg_handoff_abis_pgsl(void);

enum {
	SUB_RLCMAC_UL,
	SUB_RLCMAC_DL,

	SUB_MAX
};

static dissector_handle_t pgsl_handle;
static dissector_handle_t sub_handles[SUB_MAX];

/* initialize the protocol and registered fields */
static int proto_abis_pgsl = -1;

/* P-GSL header */
static int hf_pgsl_version = -1;
static int hf_pgsl_msg_disc = -1;
static int hf_pgsl_tn_bitmap = -1;
static int hf_pgsl_trx_seqno = -1;
static int hf_pgsl_afnd = -1;
static int hf_pgsl_afnu = -1;
static int hf_pgsl_ccu_ta = -1;
static int hf_pgsl_ack_req = -1;
static int hf_pgsl_tn_resource = -1;
static int hf_pgsl_tn_seqno = -1;
static int hf_pgsl_data_len = -1;
static int hf_pgsl_cause = -1;
static int hf_pgsl_addl_info = -1;
static int hf_pgsl_ack_ind = -1;
static int hf_pgsl_data_ind = -1;
static int hf_pgsl_ucm = -1;
static int hf_pgsl_cs = -1;
static int hf_pgsl_timing_offset = -1;
static int hf_pgsl_power_control = -1;
static int hf_pgsl_ir_tfi = -1;
static int hf_pgsl_ir_sign_type = -1;
static int hf_pgsl_codec_delay = -1;
static int hf_pgsl_codec_cs = -1;
static int hf_pgsl_codec_rxlev = -1;
static int hf_pgsl_codec_parity = -1;
static int hf_pgsl_codec_bqm = -1;
static int hf_pgsl_codec_mean_bep = -1;
static int hf_pgsl_codec_cv_bep = -1;
static int hf_pgsl_codec_q = -1;
static int hf_pgsl_codec_q1 = -1;
static int hf_pgsl_codec_q2 = -1;
static int hf_pgsl_pacch = -1;
static int hf_pgsl_ab_rxlev = -1;
static int hf_pgsl_ab_acc_delay = -1;
static int hf_pgsl_ab_abi = -1;
static int hf_pgsl_ab_ab_type = -1;

/* initialize the subtree pointers */
static int ett_pgsl = -1;
static int ett_pacch = -1;

static gboolean abis_pgsl_ir = FALSE;

#define PGSL_MSG_DLDATA_REQ	1
#define PGSL_MSG_DLDATA_IND	2
#define PGSL_MSG_ULDATA_IND	3
#define PGSL_MSG_STATUS_IND	4

static const value_string pgsl_msg_disc_vals[] = {
	{ PGSL_MSG_DLDATA_REQ,	"PGSL-DLDATA-REQ" },
	{ PGSL_MSG_DLDATA_IND,	"PGSL-DLDATA-IND" },
	{ PGSL_MSG_ULDATA_IND,	"PGSL-ULDATA-IND" },
	{ PGSL_MSG_STATUS_IND,	"PGSL-STATUS-IND" },
	{ 0, NULL }
};

static const true_false_string pgsl_q_vals = {
	"Bad",
	"Good"
};

static const value_string pgsl_msg_cause_vals[] = {
	{ 0, "Frame discarded in CCU, too late" },
	{ 1, "Frame discarded in CCU, too late or OOM" },
	{ 2, "Frame(s) missing in sequence detected by CCU" },
	{ 3, "Frame Format Error" },
	{ 0, NULL }
};

static const value_string pgsl_cs_vals[] = {
	{ 0,	"AB" },
	{ 1,	"CS-1" },
	{ 2,	"CS-2" },
	{ 3,	"CS-3" },
	{ 4,	"CS-4" },
	{ 5,	"Header Type 1" },
	{ 6,	"Header Type 2" },
	{ 7,	"Header Type 3" },
	{ 0, NULL }
};

static const value_string pgsl_ucm_vals[] = {
	{ 1, "Normal Burst (GSMK CS1/CS2/CS3/CS4)" },
	{ 2, "Normal Burst (CS1 or MCS1 to MCS9)" },
	{ 3, "Access Burst (8 bit, Traning Sequence 0)" },
	{ 4, "Access Burst (8 bit or 11 bit, Training Sequence 0/1/2)" },
	{ 0, NULL }
};

static const value_string pgsl_ir_sign_type_vals[] = {
	{ 0, "IR Update Indication" },
	{ 1, "IR Start Indication" },
	{ 2, "IR Stop Indication" },
	{ 3, "No IR Information" },
	{ 0, NULL }
};

static const value_string pgsl_ab_type_vals[] = {
	{ 0, "8-bit RACH" },
	{ 1, "11-bit RACH (TS0)" },
	{ 2, "11-bit RACH (TS1)" },
	{ 3, "11-bit RACH (TS2)" },
	{ 0, NULL }
};

static const value_string pgsl_ab_abi_vals[] = {
	{ 0, "Not Valid" },
	{ 7, "Valid" },
	{ 0, NULL }
};

static RLCMAC_block_format_t pgsl_cs_to_rlcmac_cs(guint8 pgsl_cs)
{
	static const RLCMAC_block_format_t tbl[8] = {
		RLCMAC_PRACH,
		RLCMAC_CS1,
		RLCMAC_CS2,
		RLCMAC_CS3,
		RLCMAC_CS4,
		RLCMAC_HDR_TYPE_1,
		RLCMAC_HDR_TYPE_2,
		RLCMAC_HDR_TYPE_3,
	};

	if (pgsl_cs >= 8)
		return RLCMAC_CS1;
	else
		return tbl[pgsl_cs];
}

/* length of an EGPRS RLC data block for given MCS */
static const guint data_block_len_by_mcs[] = {
	0,	/* MCS0 */
	22,	/* MCS1 */
	28,
	37,
	44,
	56,
	74,
	56,
	68,
	74,	/* MCS9 */
	0,	/* MCS_INVALID */
};

/* determine the number of rlc data blocks and their size / offsets */
static void
setup_rlc_mac_priv(RlcMacPrivateData_t *rm, gboolean is_uplink,
	guint *n_calls, guint *data_block_bits, guint *data_block_offsets)
{
	guint nc, dbl = 0, dbo[2] = {0,0};

	dbl = data_block_len_by_mcs[rm->mcs];

	switch (rm->block_format) {
	case RLCMAC_HDR_TYPE_1:
		nc = 3;
		dbo[0] = is_uplink ? 5*8 + 6 : 5*8 + 0;
		dbo[1] = dbo[0] + dbl * 8 + 2;
		break;
	case RLCMAC_HDR_TYPE_2:
		nc = 2;
		dbo[0] = is_uplink ? 4*8 + 5 : 3*8 + 4;
		break;
	case RLCMAC_HDR_TYPE_3:
		nc = 2;
		dbo[0] = 3*8 + 7;
		break;
	default:
		nc = 1;
		break;
	}

	*n_calls = nc;
	*data_block_bits = dbl * 8 + 2;
	data_block_offsets[0] = dbo[0];
	data_block_offsets[1] = dbo[1];
}

/* bit-shift the entire 'src' of length 'length_bytes' by 'offset_bits'
 * and store the reuslt to caller-allocated 'buffer'.  The shifting is
 * done lsb-first, unlike tvb_new_octet_aligned() */
static void clone_aligned_buffer_lsbf(guint offset_bits, guint length_bytes,
	const guint8 *src, guint8 *buffer)
{
	guint hdr_bytes;
	guint extra_bits;
	guint i;

	guint8 c, last_c;
	guint8 *dst;

	hdr_bytes = offset_bits / 8;
	extra_bits = offset_bits % 8;

	if (extra_bits == 0) {
		/* It is aligned already */
		memmove(buffer, src + hdr_bytes, length_bytes);
		return;
	}

	dst = buffer;
	src = src + hdr_bytes;
	last_c = *(src++);

	for (i = 0; i < length_bytes; i++) {
		c = src[i];
		*(dst++) = (last_c >> extra_bits) | (c << (8 - extra_bits));
		last_c = c;
	}
}

/* obtain an (aligned) EGPRS data block with given bit-offset and
 * bit-length from the parent TVB */
static tvbuff_t *get_egprs_data_block(tvbuff_t *tvb, guint offset_bits,
	guint length_bits, packet_info *pinfo)
{
	tvbuff_t *aligned_tvb;
	const guint initial_spare_bits = 6;
	guint8 *aligned_buf;
	guint min_src_length_bytes = (offset_bits + length_bits + 7) / 8;
	guint length_bytes = (initial_spare_bits + length_bits + 7) / 8;

	tvb_ensure_bytes_exist(tvb, 0, min_src_length_bytes);

	aligned_buf = (guint8 *) wmem_alloc(pinfo->pool, length_bytes);

	/* Copy the data out of the tvb to an aligned buffer */
	clone_aligned_buffer_lsbf(
		offset_bits - initial_spare_bits, length_bytes,
		tvb_get_ptr(tvb, 0, min_src_length_bytes),
		aligned_buf);

	/* clear spare bits and move block header bits to the right */
	aligned_buf[0] = aligned_buf[0] >> initial_spare_bits;

	aligned_tvb = tvb_new_child_real_data(tvb, aligned_buf,
		length_bytes, length_bytes);
	add_new_data_source(pinfo, aligned_tvb, "Aligned EGPRS data bits");

	return aligned_tvb;
}

/* Dissect a P-GSL ACess Burst Message */
static void
dissect_pgsl_access_burst(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree,
			  RlcMacPrivateData_t *rlcmac_data)
{
	proto_item *ti;
	proto_tree *pacch_tree;
	tvbuff_t *data_tvb;
	guint rxlev, abtype, abi;
	guint16 acc_delay;

	ti = proto_tree_add_item(tree, hf_pgsl_pacch, tvb, offset, 5, ENC_NA);
	pacch_tree = proto_item_add_subtree(ti, ett_pacch);

	proto_tree_add_item_ret_uint(pacch_tree, hf_pgsl_ab_rxlev, tvb, offset++, 1, ENC_NA, &rxlev);
	/* Access Delay is encoded as 10-bit field with the lowest 8
	 * bits in the first octet, with the two highest bits in the
	 * lowest bits of the second octet */
	acc_delay = tvb_get_guint8(tvb, offset);
	acc_delay |= tvb_get_bits8(tvb, (offset+1)*8+6, 2) << 8;
	proto_tree_add_uint(pacch_tree, hf_pgsl_ab_acc_delay, tvb, offset, 2, acc_delay);
	/* ABI and AB Type are in the same octet as the acc_dely msb's */
	offset++;
	proto_tree_add_item_ret_uint(pacch_tree, hf_pgsl_ab_abi, tvb, offset, 1, ENC_NA, &abi);
	proto_tree_add_item_ret_uint(pacch_tree, hf_pgsl_ab_ab_type, tvb, offset, 1, ENC_NA, &abtype);
	offset++;
	/* Update the 'master' item */
	if (abi) {
		proto_item_append_text(ti, " Valid, RxLev %u, Delay %u bits, Type %s", rxlev, acc_delay,
					val_to_str(abtype, pgsl_ab_type_vals, "0x%x"));
		/* decode actual access burst */
		data_tvb = tvb_new_subset_length(tvb, offset, 2);
		call_dissector_with_data(sub_handles[SUB_RLCMAC_UL], data_tvb, pinfo, pacch_tree,
					 (void *) rlcmac_data);
	} else
		proto_item_append_text(ti, " Invalid, RxLev %u", rxlev);
}

/* Dissect a given (E)GPRS RLC/MAC block */
static void
dissect_gprs_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean uplink,
		  RlcMacPrivateData_t *rlcmac_data)
{
	dissector_handle_t rlcmac_dissector;
	tvbuff_t *data_tvb;
	guint data_block_bits, data_block_offsets[2];
	guint num_calls;

	if (uplink)
		rlcmac_dissector = sub_handles[SUB_RLCMAC_UL];
	else
		rlcmac_dissector = sub_handles[SUB_RLCMAC_DL];

	/* we need to call the dissector several times
	 * incase of EGPRS, once for each header, and
	 * once for the paylod */
	switch (rlcmac_data->block_format) {
	case RLCMAC_PRACH:
		/* contains information for four access bursts */
		dissect_pgsl_access_burst(tvb, 0, pinfo, tree, rlcmac_data);
		dissect_pgsl_access_burst(tvb, 5, pinfo, tree, rlcmac_data);
		dissect_pgsl_access_burst(tvb, 10, pinfo, tree, rlcmac_data);
		dissect_pgsl_access_burst(tvb, 15, pinfo, tree, rlcmac_data);
		break;
	case RLCMAC_HDR_TYPE_1:
	case RLCMAC_HDR_TYPE_2:
	case RLCMAC_HDR_TYPE_3:
		/* First call of RLC/MAC dissector for header */
		call_dissector_with_data(rlcmac_dissector, tvb,
					 pinfo, tree, (void *) rlcmac_data);

		/* now determine how to proceed for data */
		setup_rlc_mac_priv(rlcmac_data, uplink,
				   &num_calls, &data_block_bits, data_block_offsets);
		/* and call dissector one or two time for the data blocks */
		if (num_calls >= 2) {
			rlcmac_data->flags = GSM_RLC_MAC_EGPRS_BLOCK1;
			data_tvb = get_egprs_data_block(tvb, data_block_offsets[0],
							data_block_bits, pinfo);
			call_dissector_with_data(rlcmac_dissector, data_tvb, pinfo, tree,
						 (void *) rlcmac_data);
		}
		if (num_calls == 3) {
			rlcmac_data->flags = GSM_RLC_MAC_EGPRS_BLOCK2;
			data_tvb = get_egprs_data_block(tvb, data_block_offsets[1],
							data_block_bits, pinfo);
			call_dissector_with_data(rlcmac_dissector, data_tvb, pinfo, tree,
						 (void *) rlcmac_data);
		}
		break;
	default:
		/* regular GPRS CS doesn't need any
		 * shifting/re-alignment or even separate calls for
		 * header and data blocks.  We simply call the dissector
		 * as-is */
		call_dissector_with_data(rlcmac_dissector, tvb, pinfo, tree,
					 (void *) rlcmac_data);
	}
}

static int
dissect_abis_pgsl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *ti;
	proto_tree *pgsl_tree;
	int offset = 0;
	tvbuff_t *next_tvb;
	guint32 msg_disc, len, ack_data_ind, cs, fn;
	RlcMacPrivateData_t rlcmac_data;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "P-GSL");

	ti = proto_tree_add_item(tree, proto_abis_pgsl, tvb, 0, -1, ENC_NA);
	pgsl_tree = proto_item_add_subtree(ti, ett_pgsl);

	proto_tree_add_item(pgsl_tree, hf_pgsl_version, tvb, offset, 1, ENC_NA);
	proto_tree_add_item_ret_uint(pgsl_tree, hf_pgsl_msg_disc, tvb, offset, 1, ENC_NA, &msg_disc);
	offset++;

	col_append_str(pinfo->cinfo, COL_INFO, val_to_str(msg_disc, pgsl_msg_disc_vals, "Unknown (%u)"));

	rlcmac_data.magic = GSM_RLC_MAC_MAGIC_NUMBER;

	switch (msg_disc) {
	case PGSL_MSG_DLDATA_REQ:
		proto_tree_add_item(pgsl_tree, hf_pgsl_tn_bitmap, tvb, offset++, 1, ENC_NA);
		proto_tree_add_item(pgsl_tree, hf_pgsl_trx_seqno, tvb, offset++, 1, ENC_NA);
		proto_tree_add_item(pgsl_tree, hf_pgsl_afnd, tvb, offset, 3, ENC_LITTLE_ENDIAN);
		offset += 3;
		proto_tree_add_item(pgsl_tree, hf_pgsl_ccu_ta, tvb, offset++, 1, ENC_NA);
		proto_tree_add_item(pgsl_tree, hf_pgsl_ack_req, tvb, offset++, 1, ENC_NA);
		break;
	case PGSL_MSG_DLDATA_IND:
		proto_tree_add_item(pgsl_tree, hf_pgsl_tn_resource, tvb, offset++, 1, ENC_NA);
		proto_tree_add_item(pgsl_tree, hf_pgsl_tn_seqno, tvb, offset++, 1, ENC_NA);
		proto_tree_add_item_ret_uint(pgsl_tree, hf_pgsl_afnd, tvb, offset, 3, ENC_LITTLE_ENDIAN, &fn);
		rlcmac_data.frame_number = fn;
		offset += 3;
		ack_data_ind = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(pgsl_tree, hf_pgsl_ack_ind, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(pgsl_tree, hf_pgsl_data_ind, tvb, offset++, 1, ENC_NA);
		if (ack_data_ind & 1) {
			/* Codec Control */
			proto_tree_add_item(pgsl_tree, hf_pgsl_ucm, tvb, offset, 1, ENC_NA);
			proto_tree_add_item_ret_uint(pgsl_tree, hf_pgsl_cs, tvb, offset, 1, ENC_NA, &cs);
			proto_tree_add_item(pgsl_tree, hf_pgsl_timing_offset, tvb, offset+1, 1, ENC_NA);
			offset += 2;
			/* Power Control */
			proto_tree_add_item(pgsl_tree, hf_pgsl_power_control, tvb, offset++, 1, ENC_NA);
			if (abis_pgsl_ir) {
				/* Incremental Redundancy */
				proto_tree_add_item(pgsl_tree, hf_pgsl_ir_tfi, tvb, offset, 1, ENC_NA);
				proto_tree_add_item(pgsl_tree, hf_pgsl_ir_sign_type, tvb, offset, 1, ENC_NA);
				proto_tree_add_item(pgsl_tree, hf_pgsl_tn_bitmap, tvb, offset+1, 1, ENC_NA);
				offset += 2;
			}
			/* Data length */
			proto_tree_add_item_ret_uint(pgsl_tree, hf_pgsl_data_len, tvb, offset++, 1, ENC_NA, &len);
			rlcmac_data.block_format = pgsl_cs_to_rlcmac_cs(cs);
			/* Generate tvb containing only the RLC/MAC data */
			next_tvb = tvb_new_subset_length(tvb, offset, len);
			dissect_gprs_data(next_tvb, pinfo, tree, 0, &rlcmac_data);
		}
		break;
	case PGSL_MSG_ULDATA_IND:
		proto_tree_add_item(pgsl_tree, hf_pgsl_tn_resource, tvb, offset++, 1, ENC_NA);
		proto_tree_add_item(pgsl_tree, hf_pgsl_tn_seqno, tvb, offset++, 1, ENC_NA);
		proto_tree_add_item_ret_uint(pgsl_tree, hf_pgsl_afnu, tvb, offset, 3, ENC_LITTLE_ENDIAN, &fn);
		rlcmac_data.frame_number = fn;
		offset += 3;
		/* Codec Status */
		proto_tree_add_item(pgsl_tree, hf_pgsl_codec_delay, tvb, offset, 1, ENC_NA);
		proto_tree_add_item_ret_uint(pgsl_tree, hf_pgsl_codec_cs, tvb, offset, 1, ENC_NA, &cs);
		proto_tree_add_item(pgsl_tree, hf_pgsl_codec_rxlev, tvb, offset+1, 1, ENC_NA);
		if (cs <= 4) {
			/* GPRS */
			proto_tree_add_item(pgsl_tree, hf_pgsl_codec_parity, tvb, offset+2, 1, ENC_NA);
			proto_tree_add_item(pgsl_tree, hf_pgsl_codec_bqm, tvb, offset+2, 1, ENC_NA);
		} else {
			/* EGPRS */
			proto_tree_add_item(pgsl_tree, hf_pgsl_codec_mean_bep, tvb, offset+2, 1, ENC_NA);
			proto_tree_add_item(pgsl_tree, hf_pgsl_codec_cv_bep, tvb, offset+3, 1, ENC_NA);
			proto_tree_add_item(pgsl_tree, hf_pgsl_codec_q, tvb, offset+3, 1, ENC_NA);
			proto_tree_add_item(pgsl_tree, hf_pgsl_codec_q1, tvb, offset+3, 1, ENC_NA);
			proto_tree_add_item(pgsl_tree, hf_pgsl_codec_q2, tvb, offset+3, 1, ENC_NA);
		}
		offset += 4;
		/* Data Length */
		proto_tree_add_item_ret_uint(pgsl_tree, hf_pgsl_data_len, tvb, offset++, 1, ENC_NA, &len);
		rlcmac_data.block_format = pgsl_cs_to_rlcmac_cs(cs);
		/* Generate tvb containing only the RLC/MAC data */
		next_tvb = tvb_new_subset_length(tvb, offset, len);
		dissect_gprs_data(next_tvb, pinfo, tree, 1, &rlcmac_data);
		break;
	case PGSL_MSG_STATUS_IND:
		proto_tree_add_item(pgsl_tree, hf_pgsl_tn_resource, tvb, offset++, 1, ENC_NA);
		proto_tree_add_item(pgsl_tree, hf_pgsl_tn_seqno, tvb, offset++, 1, ENC_NA);
		proto_tree_add_item(pgsl_tree, hf_pgsl_afnu, tvb, offset, 3, ENC_NA);
		offset += 3;
		proto_tree_add_item(pgsl_tree, hf_pgsl_cause, tvb, offset++, 1, ENC_NA);
		proto_tree_add_item(pgsl_tree, hf_pgsl_addl_info, tvb, offset++, 1, ENC_NA);
		break;
	}

	return offset;
}

void
proto_register_abis_pgsl(void)
{
	static hf_register_info hf[] = {
		{ &hf_pgsl_version,
			{ "Version", "gsm_abis_pgsl.version",
			  FT_UINT8, BASE_DEC, NULL, 0xf0,
			  NULL, HFILL }
		},
		{ &hf_pgsl_msg_disc,
			{ "Message Discriminator", "gsm_abis_pgsl.msg_disc",
			  FT_UINT8, BASE_DEC, VALS(pgsl_msg_disc_vals), 0x0f,
			  NULL, HFILL }
		},
		{ &hf_pgsl_tn_bitmap,
			{ "TN Bitmap", "gsm_abis_pgsl.tn_bitmap",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_pgsl_trx_seqno,
			{ "TRX Sequence Number", "gsm_abis_pgsl.trx_seqno",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  "Per-TRX Sequence Number", HFILL }
		},
		{ &hf_pgsl_afnd,
			{ "aFNd", "gsm_abis_pgsl.a_fn_d",
			  FT_UINT24, BASE_DEC, NULL, 0,
			  "Frame Number (Downlink)", HFILL }
		},
		{ &hf_pgsl_afnu,
			{ "aFNu", "gsm_abis_pgsl.a_fn_u",
			  FT_UINT24, BASE_DEC, NULL, 0,
			  "Frame Number (Uplink)", HFILL }
		},
		{ &hf_pgsl_ccu_ta,
			{ "CCU TA Value", "gsm_abis_pgsl.ccu_ta",
			  FT_UINT8, BASE_DEC, NULL, 0x3f,
			  NULL, HFILL }
		},
		{ &hf_pgsl_ack_req,
			{ "ACK Requested", "gsm_abis_pgsl.ack_req",
			  FT_BOOLEAN, 8, NULL, 0x01,
			  NULL, HFILL }
		},
		{ &hf_pgsl_tn_resource,
			{ "TN Resource", "gsm_abis_pgsl.tn_resource",
			  FT_UINT8, BASE_DEC, NULL, 0x07,
			  "Timeslot Number", HFILL }
		},
		{ &hf_pgsl_tn_seqno,
			{ "TN Sequence Number", "gsm_abis_pgsl.tn_seqno",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  "Per-TN Sequence Number", HFILL }
		},
		{ &hf_pgsl_data_len,
			{ "Data Length", "gsm_abis_pgsl.data_len",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_pgsl_cause,
			{ "Cause", "gsm_abis_pgsl.cause",
			  FT_UINT8, BASE_DEC, VALS(pgsl_msg_cause_vals), 0,
			  NULL, HFILL }
		},
		{ &hf_pgsl_addl_info,
			{ "Additional Info", "gsm_abis_pgsl.addl_info",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_pgsl_ack_ind,
			{ "ACK Indicator", "gsm_abis_pgsl.ack_ind",
			  FT_BOOLEAN, 8, NULL, 0x02,
			  NULL, HFILL }
		},
		{ &hf_pgsl_data_ind,
			{ "Data Indicator", "gsm_abis_pgsl.data_ind",
			  FT_BOOLEAN, 8, NULL, 0x01,
			  NULL, HFILL }
		},
		{ &hf_pgsl_ucm,
			{ "Uplink Channel Mode", "gsm_abis_pgsl.ucm",
			  FT_UINT8, BASE_DEC, VALS(pgsl_ucm_vals), 0xe0,
			  NULL, HFILL }
		},
		{ &hf_pgsl_cs,
			{ "Coding Scheme", "gsm_abis_pgsl.cs",
			  FT_UINT8, BASE_DEC, VALS(pgsl_cs_vals), 0x1f,
			  NULL, HFILL }
		},
		{ &hf_pgsl_timing_offset,
			{ "Timing Offset", "gsm_abis_pgsl.timing_offset",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_pgsl_power_control,
			{ "Power Control", "gsm_abis_pgsl.power_control",
			  FT_UINT8, BASE_DEC, NULL, 0x0f,
			  NULL, HFILL }
		},
		{ &hf_pgsl_ir_tfi,
			{ "TFI", "gsm_abis_pgsl.ir_tfi",
			  FT_UINT8, BASE_DEC, NULL, 0x7c,
			  "TBF Identifier", HFILL }
		},
		{ &hf_pgsl_ir_sign_type,
			{ "IR Signalling Type", "gsm_abis_pgsl.ir_sign_type",
			  FT_UINT8, BASE_DEC, VALS(pgsl_ir_sign_type_vals), 0x03,
			  NULL, HFILL }
		},
		{ &hf_pgsl_codec_delay,
			{ "Codec Delay", "gsm_abis_pgsl.codec_delay",
			  FT_UINT8, BASE_DEC, NULL, 0xe0,
			  "Estimated Accss Delay Deviation", HFILL }
		},
		{ &hf_pgsl_codec_cs,
			{ "Codec CS", "gsm_abis_pgsl.codec_csy",
			  FT_UINT8, BASE_DEC, VALS(pgsl_cs_vals), 0x1f,
			  "Coding Scheme Status", HFILL }
		},
		{ &hf_pgsl_codec_rxlev,
			{ "RxLev", "gsm_abis_pgsl.codec_rxlev",
			  FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gsm_a_rr_rxlev_vals_ext, 0x3f,
			  "Receiver Level Measurement", HFILL }
		},
		{ &hf_pgsl_codec_parity,
			{ "GPRS Parity", "gsm_abis_pgsl.gprs_parity",
			  FT_BOOLEAN, 8, NULL, 0x08,
			  "GPRS Block Status Parity", HFILL }
		},
		{ &hf_pgsl_codec_bqm,
			{ "GPRS BQM", "gsm_abis_pgsl.gprs_bqm",
			  FT_UINT8, BASE_DEC, NULL, 0x07,
			  "GPRS Block Quality Measurement", HFILL }
		},
		{ &hf_pgsl_codec_mean_bep,
			{ "EGPRS MEAN_BEP", "gsm_abis_pgsl.egprs_mean_bep",
			  FT_UINT8, BASE_DEC, NULL, 0x7f,
			  "Mean Value of BEP", HFILL }
		},
		{ &hf_pgsl_codec_cv_bep,
			{ "EGPRS CV_BEP", "gsm_abis_pgsl.egprs_cv_bep",
			  FT_UINT8, BASE_DEC, NULL, 0x07,
			  "Variation Co-Efficient of BEP", HFILL }
		},
		{ &hf_pgsl_codec_q,
			{ "EGPRS Header Quality", "gsm_abis_pgsl.egprs_q",
			  FT_BOOLEAN, 8, TFS(&pgsl_q_vals), 0x08,
			  "EGPRS RLC/MAC Header Quality", HFILL }
		},
		{ &hf_pgsl_codec_q1,
			{ "EGPRS Data Block 1 Quality", "gsm_abis_pgsl.egprs_q1",
			  FT_BOOLEAN, 8, TFS(&pgsl_q_vals), 0x10,
			  NULL, HFILL }
		},
		{ &hf_pgsl_codec_q2,
			{ "EGPRS Data Block 2 Quality", "gsm_abis_pgsl.egprs_q2",
			  FT_BOOLEAN, 8, TFS(&pgsl_q_vals), 0x20,
			  NULL, HFILL }
		},
		{ &hf_pgsl_pacch,
			{ "PACCH", "gsm_abis_pgsl.pacch",
			  FT_NONE, BASE_NONE, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_pgsl_ab_rxlev,
			{ "Access Burst Rx Level", "gsm_abis_pgsl.ab.rxlev",
			  FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gsm_a_rr_rxlev_vals_ext, 0,
			  NULL, HFILL }
		},
		{ &hf_pgsl_ab_acc_delay,
			{ "Access Burst Access Delay", "gsm_abis_pgsl.ab.acc_delay",
			  FT_UINT16, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_pgsl_ab_abi,
			{ "Access Burst Indicator", "gsm_abis_pgsl.ab.abi",
			  FT_UINT8, BASE_DEC, VALS(pgsl_ab_abi_vals), 0x70,
			  NULL, HFILL }
		},
		{ &hf_pgsl_ab_ab_type,
			{ "Access Burst Type", "gsm_abis_pgsl.ab.type",
			  FT_UINT8, BASE_DEC, VALS(pgsl_ab_type_vals), 0x0c,
			  NULL, HFILL }
		},
	};
	static gint *ett[] = {
		&ett_pgsl,
		&ett_pacch,
	};
	module_t *pgsl_module;

	/* assign our custom match functions */
	proto_abis_pgsl = proto_register_protocol("GSM A-bis P-GSL", "Ericsson GSM A-bis P-GSL",
						 "gsm_abis_pgsl");
	pgsl_module = prefs_register_protocol(proto_abis_pgsl, NULL);
	prefs_register_bool_preference(pgsl_module, "ir",
					"Incremental Redundancy",
					"The packets contain the optional Incremental Redundancy (IR) fields",
					&abis_pgsl_ir);

	proto_register_field_array(proto_abis_pgsl, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	pgsl_handle = register_dissector("gsm_abis_pgsl", dissect_abis_pgsl, proto_abis_pgsl);
}

/* This function is called once at startup and every time the user hits
 * 'apply' in the preferences dialogue */
void
proto_reg_handoff_abis_pgsl(void)
{
	/* The SAPI value 12 is a non-standard values, not specified by
	 * ETSI/3GPP, just like this very same protocol. */
	dissector_add_uint("lapd.gsm.sapi", 12, pgsl_handle);

	sub_handles[SUB_RLCMAC_UL] = find_dissector("gsm_rlcmac_ul");
	sub_handles[SUB_RLCMAC_DL] = find_dissector("gsm_rlcmac_dl");
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

/* packet-osmo_trx.c
 * Dissector for OsmoTRX Protocol (GSM Transceiver control and data).
 *
 * (C) 2018 by Harald Welte <laforge@gnumonks.org>
 * (C) 2019 by Vadim Yanitskiy <axilirator@gmail.com>
 * (C) 2021 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/unit_strings.h>

/* This is a non-standard, ad-hoc protocol to pass baseband GSM bursts between
 * the transceiver (such as osmo-trx, fake_trx.py or grgsm_trx) and the L1
 * program (such as osmo-bts-trx or trxcon). Osmocom inherited this protocol
 * when forking OsmoTRX off the OpenBTS "Transceiver" program. */

void proto_register_osmo_trx(void);
void proto_reg_handoff_osmo_trx(void);

static dissector_handle_t otrxd_handle;
static dissector_handle_t otrxc_handle;

/* Which kind of message it is */
static int proto_otrxd;
static int proto_otrxc;

/* Generated fields */
static int hf_otrxd_burst_dir;
static int hf_otrxc_msg_dir;

/* TRXD PDU version */
static int hf_otrxd_pdu_ver;

/* TRXD common fields */
static int hf_otrxd_chdr_reserved;
static int hf_otrxd_shadow_ind;
static int hf_otrxd_batch_ind;
static int hf_otrxd_trx_num;
static int hf_otrxd_tdma_tn;
static int hf_otrxd_tdma_fn;

/* MTS (Modulation and Training Sequence) fields */
static int hf_otrxd_nope_ind;
static int hf_otrxd_nope_ind_pad;
static int hf_otrxd_mod_2b; /* 2 bit field */
static int hf_otrxd_mod_3b; /* 3 bit field */
static int hf_otrxd_mod_4b; /* 4 bit field */
static int hf_otrxd_tsc_set_x4;
static int hf_otrxd_tsc_set_x2;
static int hf_otrxd_tsc;

/* TRXD Rx header fields */
static int hf_otrxd_rssi;
static int hf_otrxd_toa256;
static int hf_otrxd_ci;

/* TRXD Tx header fields */
static int hf_otrxd_tx_att;
static int hf_otrxd_tx_scpir;
static int hf_otrxd_tx_rfu;

/* Burst soft (255 .. 0) / hard (1 or 0) bits */
static int hf_otrxd_soft_symbols;
static int hf_otrxd_hard_symbols;
static int hf_otrxd_burst_pad;

/* TRXC - Control and Clock protocol */
static int hf_otrxc_type;
static int hf_otrxc_delimiter;
static int hf_otrxc_verb;
static int hf_otrxc_params;
static int hf_otrxc_status;

static int ett_otrxd;
static int ett_otrxc;

static int ett_otrxd_rx_pdu;
static int ett_otrxd_tx_pdu;

static expert_field ei_otrxd_unknown_pdu_ver;
static expert_field ei_otrxd_injected_msg;
static expert_field ei_otrxd_unknown_dir;
static expert_field ei_otrxd_tail_octets;

static expert_field ei_otrxc_unknown_msg_type;
static expert_field ei_otrxc_bad_delimiter;
static expert_field ei_otrxc_rsp_no_code;
static expert_field ei_otrxc_injected_msg;
static expert_field ei_otrxc_unknown_dir;

/* Custom units */
static const unit_name_string otrx_units_toa256 = { " (1/256 of a symbol)", NULL };

/* TRXD SHADOW.ind value description */
static const true_false_string otrxd_shadow_bool_val = {
	"This is a shadow PDU",
	"This is a primary PDU",
};

/* TRXD BATCH.ind value description */
static const true_false_string otrxd_batch_bool_val = {
	"Another PDU follows",
	"This is the last PDU",
};

/* TRXD NOPE.{ind,req} value description */
static const true_false_string otrxd_nope_bool_val = {
	"Burst is not present",
	"Burst is present",
};

/* TRXD modulation types (2 bit field) */
static const value_string otrxd_mod_2b_vals[] = {
	/* .00xx... */	{ 0x00, "GMSK" },
	/* .11xx... */	{ 0x03, "AQPSK" },
	{ 0, NULL },
};

/* TRXD modulation types (3 bit field) */
static const value_string otrxd_mod_3b_vals[] = {
	/* .010x... */	{ 0x02, "8-PSK" },
	/* .100x... */	{ 0x04, "16QAM" },
	/* .101x... */	{ 0x05, "32QAM" },
	{ 0, NULL },
};

/* TRXD modulation types (4 bit field) */
static const value_string otrxd_mod_4b_vals[] = {
	/* .0110... */	{ 0x06, "GMSK (Access Burst)" },
	/* .0111... */	{ 0x07, "RFU (Reserved for Future Use)" },
	{ 0, NULL },
};

/* TRXD modulation type */
enum otrxd_mod_type {
	OTRXD_MOD_T_GMSK		= 0x00,
	OTRXD_MOD_T_8PSK		= 0x02,
	OTRXD_MOD_T_AQPSK		= 0x03,
	OTRXD_MOD_T_16QAM		= 0x04,
	OTRXD_MOD_T_32QAM		= 0x05,
	OTRXD_MOD_T_GMSK_AB		= 0x06,
	OTRXD_MOD_T_RFU			= 0x07,
};

/* See 3GPP TS 45.002, section 5.2 "Bursts" */
#define GMSK_BURST_LEN			148

/* TRXD modulation / burst length mapping */
static const uint16_t otrxd_burst_len[] = {
	[OTRXD_MOD_T_GMSK]		= GMSK_BURST_LEN * 1,
	[OTRXD_MOD_T_GMSK_AB]		= GMSK_BURST_LEN * 1,
	[OTRXD_MOD_T_AQPSK]		= GMSK_BURST_LEN * 2,
	[OTRXD_MOD_T_8PSK]		= GMSK_BURST_LEN * 3,
	[OTRXD_MOD_T_16QAM]		= GMSK_BURST_LEN * 4,
	[OTRXD_MOD_T_32QAM]		= GMSK_BURST_LEN * 5,
	[OTRXD_MOD_T_RFU]		= 0, /* unknown */
};

/* RSSI is encoded without a negative sign, so we need to show it */
static void format_rssi(char *buf, const uint32_t rssi)
{
	snprintf(buf, ITEM_LABEL_LENGTH, "-%u%s", rssi, unit_name_string_get_value(rssi, &units_dbm));
}

/* TSC (Training Sequence Code) set number in 3GPP TS 45.002 starts
 * from 1, while 'on the wire' it's encoded as X - 1 (starts from 0). */
static void format_tsc_set(char *buf, uint32_t tsc_set)
{
	snprintf(buf, ITEM_LABEL_LENGTH, "%u", tsc_set + 1);
}

/* Message direction */
enum otrxcd_dir_type {
	OTRXCD_DIR_UNKNOWN = 0,
	OTRXCD_DIR_L12TRX,
	OTRXCD_DIR_TRX2L1,
};

static const value_string otrxcd_dir_vals[] = {
	{ OTRXCD_DIR_UNKNOWN, "Unknown" },
	{ OTRXCD_DIR_L12TRX, "L1 -> TRX" },
	{ OTRXCD_DIR_TRX2L1, "TRX -> L1" },
	{ 0, NULL },
};

/* Determine message direction (L1 to TRX, or TRX to L1?) */
static enum otrxcd_dir_type otrxcd_get_dir(const packet_info *pinfo)
{
	if (pinfo->srcport - pinfo->destport == 100)
		return OTRXCD_DIR_L12TRX;
	else if (pinfo->destport - pinfo->srcport == 100)
		return OTRXCD_DIR_TRX2L1;
	else
		return OTRXCD_DIR_UNKNOWN;
}

/* Guess message direction (L1 to TRX, or TRX to L1?) */
static enum otrxcd_dir_type otrxcd_guess_dir(const packet_info *pinfo)
{
	/* TODO: srcport can be also used for guessing,
	 * TODO: use port numbers from protocol preferences. */
	switch (pinfo->destport) {
	/* OsmoTRXD: Tx burst (L1 -> TRX) */
	case 5702: case 5704: case 6702:
		return OTRXCD_DIR_L12TRX;
	/* OsmoTRXD: Rx burst (TRX -> L1) */
	case 5802: case 5804: case 6802:
		return OTRXCD_DIR_TRX2L1;
	/* OsmoTRXC: Command (L1 -> TRX) */
	case 5701: case 5703: case 6701:
		return OTRXCD_DIR_L12TRX;
	/* OsmoTRXC: Response or Indication (TRX -> L1) */
	case 5801: case 5803: case 6801:
	case 5800: case 6800:
		return OTRXCD_DIR_TRX2L1;
	default:
		return OTRXCD_DIR_UNKNOWN;
	}
}

/* TRXC message types */
enum otrxc_msg_type {
	OTRXC_MSG_TYPE_UNKNOWN = 0,
	OTRXC_MSG_TYPE_COMMAND,
	OTRXC_MSG_TYPE_RESPONSE,
	OTRXC_MSG_TYPE_INDICATION,
};

static const value_string otrxc_msg_type_enc[] = {
	{ OTRXC_MSG_TYPE_COMMAND,	"CMD" },
	{ OTRXC_MSG_TYPE_RESPONSE,	"RSP" },
	{ OTRXC_MSG_TYPE_INDICATION,	"IND" },
	{ 0, NULL },
};

static const value_string otrxc_msg_type_desc[] = {
	{ OTRXC_MSG_TYPE_COMMAND,	"Command" },
	{ OTRXC_MSG_TYPE_RESPONSE,	"Response" },
	{ OTRXC_MSG_TYPE_INDICATION,	"Indication" },
	{ 0, NULL },
};

/* TRXD PDU information */
struct otrxd_pdu_info {
	/* PDU version */
	uint32_t ver;
	/* BATCH.ind marker */
	bool batch;
	/* SHADOW.ind marker */
	bool shadow;
	/* Number of batched PDUs */
	uint32_t num_pdus;
	/* TRX (RF channel) number */
	uint32_t trx_num;
	/* TDMA frame number */
	uint32_t fn;
	/* TDMA timeslot number */
	uint32_t tn;
	/* NOPE.{ind,req} marker */
	bool nope;
	/* Modulation type and string */
	enum otrxd_mod_type mod;
	const char *mod_str;
	/* Training Sequence Code */
	uint32_t tsc;
};

/* Dissector for common Rx/Tx TRXDv0/v1 header part */
static void dissect_otrxd_chdr_v0(tvbuff_t *tvb, packet_info *pinfo _U_,
				  proto_item *ti, proto_tree *tree,
				  struct otrxd_pdu_info *pi,
				  int *offset)
{
	proto_tree_add_item(tree, hf_otrxd_chdr_reserved, tvb,
			    *offset, 1, ENC_NA);
	proto_tree_add_item_ret_uint(tree, hf_otrxd_tdma_tn, tvb,
				     *offset, 1, ENC_NA, &pi->tn);
	*offset += 1;

	/* TDMA frame number (4 octets, big endian) */
	proto_tree_add_item_ret_uint(tree, hf_otrxd_tdma_fn, tvb,
				     *offset, 4, ENC_BIG_ENDIAN, &pi->fn);
	*offset += 4;

	proto_item_append_text(ti, "TDMA FN %07u TN %u", pi->fn, pi->tn);
}

/* Dissector for MTS (Modulation and Training Sequence) */
static void dissect_otrxd_mts(tvbuff_t *tvb, proto_tree *tree,
			      struct otrxd_pdu_info *pi,
			      int offset)
{
	/* NOPE indication contains no MTS information.
	 *
	 * | 7 6 5 4 3 2 1 0 | Bit numbers (value range)
	 * | X . . . . . . . | NOPE / IDLE indication
	 * | . X X X X . . . | MTS (Modulation and Training Sequence)
	 * | . . . . . X X X | TSC (Training Sequence Code)
	 */
	proto_tree_add_item_ret_boolean(tree, hf_otrxd_nope_ind, tvb,
					offset, 1, ENC_NA, &pi->nope);
	if (pi->nope) {
		proto_tree_add_item(tree, hf_otrxd_nope_ind_pad, tvb, offset, 1, ENC_NA);
		return;
	}

	/* MTS (Modulation and Training Sequence info).
	 *
	 * | 7 6 5 4 3 2 1 0 | Bit numbers (value range)
	 * | . 0 0 X X . . . | GMSK, 4 TSC sets (0..3)
	 * | . 0 1 0 X . . . | 8-PSK, 2 TSC sets (0..1)
	 * | . 0 1 1 0 . . . | GMSK, Packet Access Burst
	 * | . 0 1 1 1 . . . | RFU (Reserved for Future Use)
	 * | . 1 0 0 X . . . | 16QAM, 2 TSC sets (0..1)
	 * | . 1 0 1 X . . . | 32QAM, 2 TSC sets (0..1)
	 * | . 1 1 X X . . . | AQPSK, 4 TSC sets (0..3)
	 *
	 * NOTE: 3GPP defines 4 TSC sets for both GMSK and AQPSK.
	 */
	uint8_t mts = tvb_get_uint8(tvb, offset);
	if ((mts >> 5) == 0x00 || (mts >> 5) == 0x03) { /* 2 bit: GMSK (0) or AQPSK (3) */
		pi->mod = (enum otrxd_mod_type) (mts >> 5);
		pi->mod_str = val_to_str(mts >> 5, otrxd_mod_2b_vals, "Unknown 0x%02x");
		proto_tree_add_item(tree, hf_otrxd_mod_2b, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(tree, hf_otrxd_tsc_set_x4, tvb, offset, 1, ENC_NA);
	} else if ((mts >> 4) != 0x03) { /* 3 bit: 8-PSK, 16QAM, or 32QAM */
		pi->mod = (enum otrxd_mod_type) (mts >> 4);
		pi->mod_str = val_to_str(mts >> 4, otrxd_mod_3b_vals, "Unknown 0x%02x");
		proto_tree_add_item(tree, hf_otrxd_mod_3b, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(tree, hf_otrxd_tsc_set_x2, tvb, offset, 1, ENC_NA);
	} else { /* 4 bit (without TSC set): GMSK (Packet Access Burst) or RFU */
		pi->mod = (enum otrxd_mod_type) (mts >> 3);
		pi->mod_str = val_to_str(mts >> 3, otrxd_mod_4b_vals, "Unknown 0x%02x");
		proto_tree_add_item(tree, hf_otrxd_mod_4b, tvb, offset, 1, ENC_NA);
	}

	proto_tree_add_item_ret_uint(tree, hf_otrxd_tsc, tvb, offset, 1, ENC_NA, &pi->tsc);
}

/* Dissector for Rx TRXD header version 0 */
static int dissect_otrxd_rx_hdr_v0(tvbuff_t *tvb, packet_info *pinfo,
				   proto_item *ti, proto_tree *tree,
				   struct otrxd_pdu_info *pi,
				   int offset)
{
	dissect_otrxd_chdr_v0(tvb, pinfo, ti, tree, pi, &offset);

	proto_tree_add_item(tree, hf_otrxd_rssi, tvb, offset++, 1, ENC_NA);
	proto_tree_add_item(tree, hf_otrxd_toa256, tvb, offset, 2, ENC_NA);
	offset += 2;

	return offset;
}

/* Dissector for Rx TRXD header version 1 */
static int dissect_otrxd_rx_hdr_v1(tvbuff_t *tvb, packet_info *pinfo,
				   proto_item *ti, proto_tree *tree,
				   struct otrxd_pdu_info *pi,
				   int offset)
{
	/* Dissect V0 specific part first */
	offset = dissect_otrxd_rx_hdr_v0(tvb, pinfo, ti, tree, pi, offset);

	/* MTS (Modulation and Training Sequence) */
	dissect_otrxd_mts(tvb, tree, pi, offset++);
	if (!pi->nope)
		proto_item_append_text(ti, ", Modulation %s, TSC %u", pi->mod_str, pi->tsc);
	else
		proto_item_append_text(ti, ", NOPE.ind");

	/* C/I (Carrier to Interference ratio) */
	proto_tree_add_item(tree, hf_otrxd_ci, tvb, offset, 2, ENC_NA);
	offset += 2;

	return offset;
}

/* Dissector for TRXD Rx header version 2 */
static int dissect_otrxd_rx_hdr_v2(tvbuff_t *tvb, packet_info *pinfo _U_,
				   proto_item *ti, proto_tree *tree,
				   struct otrxd_pdu_info *pi,
				   int offset)
{
	proto_tree_add_item(tree, hf_otrxd_chdr_reserved, tvb, offset, 1, ENC_NA);
	proto_tree_add_item_ret_uint(tree, hf_otrxd_tdma_tn, tvb,
				     offset, 1, ENC_NA, &pi->tn);
	offset += 1;

	proto_tree_add_item_ret_boolean(tree, hf_otrxd_batch_ind, tvb,
					offset, 1, ENC_NA, &pi->batch);
	proto_tree_add_item_ret_boolean(tree, hf_otrxd_shadow_ind, tvb,
					offset, 1, ENC_NA, &pi->shadow);
	proto_tree_add_item_ret_uint(tree, hf_otrxd_trx_num, tvb,
				     offset, 1, ENC_NA, &pi->trx_num);
	offset += 1;

	/* MTS (Modulation and Training Sequence) */
	dissect_otrxd_mts(tvb, tree, pi, offset++);

	/* RSSI (Received Signal Strength Indication) */
	proto_tree_add_item(tree, hf_otrxd_rssi, tvb, offset++, 1, ENC_NA);

	/* ToA256 (Timing of Arrival) and C/I (Carrier to Interference ratio) */
	proto_tree_add_item(tree, hf_otrxd_toa256, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_otrxd_ci, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
	offset += 4;

	/* TDMA frame number (absent in additional PDUs) */
	if (pi->num_pdus == 0) {
		proto_tree_add_item_ret_uint(tree, hf_otrxd_tdma_fn, tvb,
					     offset, 4, ENC_BIG_ENDIAN, &pi->fn);
		offset += 4;
	}

	proto_item_append_text(ti, "TRXN %02u, TDMA FN %07u TN %u", pi->trx_num, pi->fn, pi->tn);
	if (!pi->nope)
		proto_item_append_text(ti, ", Modulation %s, TSC %u", pi->mod_str, pi->tsc);
	else
		proto_item_append_text(ti, ", NOPE.ind");

	return offset;
}

/* Burst data in Receive direction */
static int dissect_otrxd_rx(tvbuff_t *tvb, packet_info *pinfo,
			    proto_item *pti, proto_tree *ptree,
			    struct otrxd_pdu_info *pi,
			    int offset)
{
	int start, burst_len, padding;
	proto_tree *tree;
	proto_item *ti;

loop:
	/* Add a sub-tree for each PDU (length is set below) */
	tree = proto_tree_add_subtree(ptree, tvb, offset, -1,
				      ett_otrxd_rx_pdu, &ti,
				      "TRXD Rx PDU: ");
	start = offset;

	/* Parse version specific TRXD header part */
	switch (pi->ver) {
	case 0:
		offset = dissect_otrxd_rx_hdr_v0(tvb, pinfo, ti, tree, pi, offset);
		/* The remaining octets is basically soft-bits of the burst */
		burst_len = tvb_reported_length(tvb) - offset;
		/* ... there must be at least 148 soft-bits */
		if (burst_len < GMSK_BURST_LEN)
			burst_len = GMSK_BURST_LEN; /* let it crash! */
		/* ... there can be 2 optional padding octets in the end */
		padding = burst_len % GMSK_BURST_LEN;
		proto_tree_add_item(tree, hf_otrxd_soft_symbols, tvb,
				    offset, burst_len - padding, ENC_NA);
		offset += burst_len - padding;
		if (padding == 0)
			break;
		proto_tree_add_item(tree, hf_otrxd_burst_pad, tvb,
				    offset, padding, ENC_NA);
		offset += padding;
		break;
	case 1:
		offset = dissect_otrxd_rx_hdr_v1(tvb, pinfo, ti, tree, pi, offset);
		if (pi->nope) /* NOPE.ind contains no burst */
			break;
		burst_len = otrxd_burst_len[pi->mod];
		proto_tree_add_item(tree, hf_otrxd_soft_symbols, tvb,
				    offset, burst_len, ENC_NA);
		offset += burst_len;
		break;
	case 2:
		offset = dissect_otrxd_rx_hdr_v2(tvb, pinfo, ti, tree, pi, offset);
		if (pi->nope) /* NOPE.ind contains no burst */
			break;
		burst_len = otrxd_burst_len[pi->mod];
		proto_tree_add_item(tree, hf_otrxd_soft_symbols, tvb,
				    offset, burst_len, ENC_NA);
		offset += burst_len;
		break;
	default:
		expert_add_info_format(pinfo, pti, &ei_otrxd_unknown_pdu_ver,
				       "Unknown TRXD PDU version %u", pi->ver);
		offset = 1; /* Only the PDU version was parsed */
		return offset;
	}

	proto_item_set_len(ti, offset - start);

	/* Number of processed PDUs */
	pi->num_pdus += 1;

	/* There can be additional 'batched' PDUs */
	if (pi->batch)
		goto loop;

	return offset;
}

/* Dissector for TRXDv0/v1 Tx burst */
static void dissect_otrxd_tx_burst_v0(tvbuff_t *tvb, packet_info *pinfo _U_,
				      proto_item *ti, proto_tree *tree,
				      struct otrxd_pdu_info *pi,
				      int *offset)
{
	/* Calculate the burst length */
	const int burst_len = tvb_reported_length(tvb) - *offset;

	/* Attempt to guess modulation by the length */
	switch (burst_len) {
	/* We may also have NOPE.req in the future (to drive fake_trx.py) */
	case 0:
		proto_item_append_text(ti, ", NOPE.req");
		pi->nope = true;
		return;

	/* TODO: introduce an enumerated type, detect other modulation types,
	 * TODO: add a generated field for "osmo_trxd.mod" */
	case GMSK_BURST_LEN:
		proto_item_append_text(ti, ", Modulation GMSK");
		pi->mod_str = "GMSK";
		break;
	case 3 * GMSK_BURST_LEN:
		proto_item_append_text(ti, ", Modulation 8-PSK");
		pi->mod_str = "8-PSK";
		break;
	}

	/* Hard-bits (1 or 0) */
	proto_tree_add_item(tree, hf_otrxd_hard_symbols, tvb,
			    *offset, burst_len, ENC_NA);
	*offset += burst_len;
}

/* Dissector for TRXD Tx header version 2 */
static void dissect_otrxd_tx_hdr_v2(tvbuff_t *tvb, packet_info *pinfo _U_,
				    proto_item *ti, proto_tree *tree,
				    struct otrxd_pdu_info *pi,
				    int *offset)
{
	proto_tree_add_item(tree, hf_otrxd_chdr_reserved, tvb, *offset, 1, ENC_NA);
	proto_tree_add_item_ret_uint(tree, hf_otrxd_tdma_tn, tvb,
				     *offset, 1, ENC_NA, &pi->tn);
	*offset += 1;

	proto_tree_add_item_ret_boolean(tree, hf_otrxd_batch_ind, tvb,
					*offset, 1, ENC_NA, &pi->batch);
	proto_tree_add_item_ret_uint(tree, hf_otrxd_trx_num, tvb,
				     *offset, 1, ENC_NA, &pi->trx_num);
	*offset += 1;

	/* MTS (Modulation and Training Sequence) */
	dissect_otrxd_mts(tvb, tree, pi, *offset);
	*offset += 1;

	/* Tx power attenuation */
	proto_tree_add_item(tree, hf_otrxd_tx_att, tvb, *offset, 1, ENC_NA);
	*offset += 1;

	/* SCPIR (Subchannel Power Imbalance Ratio) */
	proto_tree_add_item(tree, hf_otrxd_tx_scpir, tvb, *offset, 1, ENC_NA);
	*offset += 1;

	/* RFU (currently just to make the header dword-alignment) */
	proto_tree_add_item(tree, hf_otrxd_tx_rfu, tvb, *offset, 3, ENC_NA);
	*offset += 3;

	/* TDMA frame number (absent in additional PDUs) */
	if (pi->num_pdus == 0) {
		proto_tree_add_item_ret_uint(tree, hf_otrxd_tdma_fn, tvb,
					     *offset, 4, ENC_BIG_ENDIAN, &pi->fn);
		*offset += 4;
	}

	proto_item_append_text(ti, "TRXN %02u, TDMA FN %07u TN %u", pi->trx_num, pi->fn, pi->tn);
	if (!pi->nope)
		proto_item_append_text(ti, ", Modulation %s, TSC %u", pi->mod_str, pi->tsc);
	else
		proto_item_append_text(ti, ", NOPE.req");
}

/* Burst data in Transmit direction */
static int dissect_otrxd_tx(tvbuff_t *tvb, packet_info *pinfo,
			    proto_item *pti, proto_tree *ptree,
			    struct otrxd_pdu_info *pi,
			    int offset)
{
	proto_tree *tree;
	proto_item *ti;
	int burst_len;
	int start;

loop:
	/* Add a sub-tree for each PDU (length is set below) */
	tree = proto_tree_add_subtree(ptree, tvb, offset, -1,
				      ett_otrxd_tx_pdu, &ti,
				      "TRXD Tx PDU: ");
	start = offset;

	switch (pi->ver) {
	/* Both versions feature the same PDU format */
	case 0:
	case 1:
		dissect_otrxd_chdr_v0(tvb, pinfo, ti, tree, pi, &offset);
		proto_tree_add_item(tree, hf_otrxd_tx_att, tvb, offset++, 1, ENC_NA);
		dissect_otrxd_tx_burst_v0(tvb, pinfo, ti, tree, pi, &offset);
		break;
	case 2:
		dissect_otrxd_tx_hdr_v2(tvb, pinfo, ti, tree, pi, &offset);
		if (pi->nope) /* NOPE.ind contains no burst */
			break;
		burst_len = otrxd_burst_len[pi->mod];
		proto_tree_add_item(tree, hf_otrxd_hard_symbols, tvb,
				    offset, burst_len, ENC_NA);
		offset += burst_len;
		break;
	default:
		expert_add_info_format(pinfo, pti, &ei_otrxd_unknown_pdu_ver,
				       "Unknown TRXD PDU version %u", pi->ver);
		offset = 1; /* Only the PDU version was parsed */
		return offset;
	}

	proto_item_set_len(ti, offset - start);

	/* Number of processed PDUs */
	pi->num_pdus += 1;

	/* There can be additional 'batched' PDUs */
	if (pi->batch)
		goto loop;

	return offset;
}

/* Common dissector for bursts in both directions */
static int dissect_otrxd(tvbuff_t *tvb, packet_info *pinfo,
			 proto_tree *tree, void* data _U_)
{
	struct otrxd_pdu_info pi = { 0 };
	proto_tree *otrxd_tree;
	proto_item *ti, *gi;
	int offset = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "OsmoTRXD");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_otrxd, tvb, 0, -1, ENC_NA);
	otrxd_tree = proto_item_add_subtree(ti, ett_otrxd);

	/* Determine the burst direction */
	int burst_dir = otrxcd_get_dir(pinfo);

	/* A burst might be injected by some other program using
	 * a random source port, so let's try to guess by destport. */
	if (burst_dir == OTRXCD_DIR_UNKNOWN) {
		expert_add_info(pinfo, ti, &ei_otrxd_injected_msg);
		burst_dir = otrxcd_guess_dir(pinfo);
	}

	if (burst_dir == OTRXCD_DIR_L12TRX)
		col_append_str(pinfo->cinfo, COL_INFO, "Tx burst (L1 -> TRX): ");
	else if (burst_dir == OTRXCD_DIR_TRX2L1)
		col_append_str(pinfo->cinfo, COL_INFO, "Rx burst (TRX -> L1): ");
	else
		col_append_str(pinfo->cinfo, COL_INFO, "Tx/Rx burst (Unknown): ");

	/* Add a generated field, so we can filter bursts by direction */
	gi = proto_tree_add_uint(otrxd_tree, hf_otrxd_burst_dir,
				 tvb, 0, 0, burst_dir);
	proto_item_set_generated(gi);

	/* Parse common TRXD PDU version */
	proto_tree_add_item_ret_uint(otrxd_tree, hf_otrxd_pdu_ver, tvb,
				     offset, 1, ENC_NA, &pi.ver);
	proto_item_append_text(ti, " Version %u", pi.ver);

	if (burst_dir == OTRXCD_DIR_L12TRX)
		offset = dissect_otrxd_tx(tvb, pinfo, ti, otrxd_tree, &pi, offset);
	else if (burst_dir == OTRXCD_DIR_TRX2L1)
		offset = dissect_otrxd_rx(tvb, pinfo, ti, otrxd_tree, &pi, offset);
	else {
		expert_add_info(pinfo, ti, &ei_otrxd_unknown_dir);
		offset = 1; /* Only the PDU version was parsed */
	}

	/* Summary for all parsed PDUs */
	if (pi.num_pdus == 1) {
		col_append_fstr(pinfo->cinfo, COL_INFO, "TDMA FN %07u TN %u", pi.fn, pi.tn);
		if (pi.mod_str != NULL)
			col_append_fstr(pinfo->cinfo, COL_INFO, ", Modulation %s", pi.mod_str);
		else if (pi.nope && burst_dir == OTRXCD_DIR_TRX2L1)
			col_append_str(pinfo->cinfo, COL_INFO, ", NOPE.ind");
		else if (pi.nope && burst_dir == OTRXCD_DIR_L12TRX)
			col_append_str(pinfo->cinfo, COL_INFO, ", NOPE.req");
	} else if (pi.num_pdus > 1) {
		col_append_fstr(pinfo->cinfo, COL_INFO, "TDMA FN %07u", pi.fn);
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %u batched PDUs ", pi.num_pdus);
	}

	proto_item_set_len(ti, offset);

	/* Let it warn us if there are unhandled tail octets */
	if ((unsigned) offset < tvb_reported_length(tvb))
		expert_add_info(pinfo, ti, &ei_otrxd_tail_octets);

	return offset;
}

/* Dissector for Control commands and responses, and Clock indications */
static int dissect_otrxc(tvbuff_t *tvb, packet_info *pinfo,
			 proto_tree *tree, void *data _U_)
{
	int offset = 0, msg_len, end_verb, end_status;
	const uint8_t *msg_str, *msg_type_str;
	proto_item *ti, *gi, *delim_item;
	proto_tree *otrxc_tree;
	uint32_t delimiter;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "OsmoTRXC");
	col_clear(pinfo->cinfo, COL_INFO);

	msg_len = tvb_reported_length(tvb);
	msg_str = tvb_get_string_enc(pinfo->pool, tvb, 0, msg_len, ENC_ASCII);
	col_add_str(pinfo->cinfo, COL_INFO, msg_str);

	ti = proto_tree_add_item(tree, proto_otrxc, tvb, 0, msg_len, ENC_ASCII);
	otrxc_tree = proto_item_add_subtree(ti, ett_otrxc);

	/* Determine the message direction */
	int msg_dir = otrxcd_get_dir(pinfo);

	/* A message might be injected by some other program using
	 * a random source port, so let's try to guess by destport. */
	if (msg_dir == OTRXCD_DIR_UNKNOWN) {
		expert_add_info(pinfo, ti, &ei_otrxc_injected_msg);
		if ((msg_dir = otrxcd_guess_dir(pinfo)) == OTRXCD_DIR_UNKNOWN)
			expert_add_info(pinfo, ti, &ei_otrxc_unknown_dir);
	}

	/* Add a generated field, so we can filter bursts by direction */
	gi = proto_tree_add_uint(otrxc_tree, hf_otrxc_msg_dir,
				 tvb, 0, 0, msg_dir);
	proto_item_set_generated(gi);

	/* First 3 bytes define a type of the message ("IND", "CMD", "RSP") */
	proto_tree_add_item_ret_string(otrxc_tree, hf_otrxc_type, tvb, offset, 3,
				       ENC_NA | ENC_ASCII, pinfo->pool,
				       &msg_type_str);
	offset += 3;

	/* Determine the message type */
	enum otrxc_msg_type msg_type = str_to_val((const char *) msg_type_str,
						  otrxc_msg_type_enc,
						  OTRXC_MSG_TYPE_UNKNOWN);
	proto_item_append_text(ti, ", %s", val_to_str_const(msg_type, otrxc_msg_type_desc,
							    "Unknown message type"));
	if (msg_type == OTRXC_MSG_TYPE_UNKNOWN) {
		expert_add_info(pinfo, ti, &ei_otrxc_unknown_msg_type);
		return offset;
	}

	/* The message type is separated by a delimiter */
	delim_item = proto_tree_add_item_ret_uint(otrxc_tree, hf_otrxc_delimiter,
						  tvb, offset, 1, ENC_NA, &delimiter);
	proto_item_set_hidden(delim_item);
	offset += 1;

	/* Delimiter should be a space symbol */
	if (delimiter != 0x20)
		expert_add_info(pinfo, delim_item, &ei_otrxc_bad_delimiter);

	/* The message type is followed by a verb, e.g. "IND CLOCK", "CMD POWEROFF" */
	end_verb = tvb_find_guint8(tvb, offset, -1, (char) delimiter);
	if (end_verb < 0) {
		/* Just a command without parameters, e.g. "CMD POWERON" */
		proto_tree_add_item(otrxc_tree, hf_otrxc_verb, tvb,
				    offset, -1, ENC_ASCII | ENC_NA);
		if (msg_type == OTRXC_MSG_TYPE_RESPONSE)
			expert_add_info(pinfo, ti, &ei_otrxc_rsp_no_code);
		return tvb_captured_length(tvb);
	} else {
		proto_tree_add_item(otrxc_tree, hf_otrxc_verb, tvb,
				    offset, end_verb - offset,
				    ENC_ASCII | ENC_NA);
		offset = end_verb;
	}

	/* Another delimiter between the verb and status code / parameters */
	delim_item = proto_tree_add_item_ret_uint(otrxc_tree, hf_otrxc_delimiter,
						  tvb, offset, 1, ENC_NA, &delimiter);
	proto_item_set_hidden(delim_item);
	offset += 1;

	if (msg_type == OTRXC_MSG_TYPE_RESPONSE) {
		end_status = tvb_find_guint8(tvb, offset, -1, (char) delimiter);
		if (end_status > 0) {
			proto_tree_add_item(otrxc_tree, hf_otrxc_status,
					    tvb, offset, end_status - offset, ENC_ASCII | ENC_NA);
			offset = end_status;

			/* Another delimiter between the status code and parameters */
			delim_item = proto_tree_add_item_ret_uint(otrxc_tree, hf_otrxc_delimiter,
								  tvb, offset, 1, ENC_NA, &delimiter);
			proto_item_set_hidden(delim_item);
			offset += 1;
		} else if (offset < msg_len) {
			/* Response without parameters, e.g. "RSP POWEROFF 0" */
			proto_tree_add_item(otrxc_tree, hf_otrxc_status,
					    tvb, offset, msg_len - offset, ENC_ASCII | ENC_NA);
			return tvb_captured_length(tvb);
		} else {
			expert_add_info(pinfo, ti, &ei_otrxc_rsp_no_code);
			return offset;
		}
	}

	if (offset < msg_len) {
		proto_tree_add_item(otrxc_tree, hf_otrxc_params,
				    tvb, offset, -1, ENC_ASCII | ENC_NA);
	}

	return tvb_captured_length(tvb);
}

void proto_register_osmo_trx(void)
{
	static hf_register_info hf_otrxd[] = {
		/* Common generated field: burst direction */
		{ &hf_otrxd_burst_dir, { "Burst Direction", "osmo_trx.direction",
		  FT_UINT8, BASE_DEC, VALS(otrxcd_dir_vals), 0, NULL, HFILL } },

		/* Rx/Tx header fields */
		{ &hf_otrxd_pdu_ver, { "PDU Version", "osmo_trxd.pdu_ver",
		  FT_UINT8, BASE_DEC, NULL, 0xf0, NULL, HFILL } },
		{ &hf_otrxd_chdr_reserved, { "Reserved", "osmo_trxd.chdr_reserved",
		  FT_UINT8, BASE_DEC, NULL, 0x08, NULL, HFILL } },
		{ &hf_otrxd_tdma_tn, { "TDMA Timeslot Number", "osmo_trxd.tdma.tn",
		  FT_UINT8, BASE_DEC, NULL, 0x07, NULL, HFILL } },
		{ &hf_otrxd_tdma_fn, { "TDMA Frame Number", "osmo_trxd.tdma.fn",
		  FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_otrxd_batch_ind, { "BATCH Indication", "osmo_trxd.batch_ind",
		  FT_BOOLEAN, 8, TFS(&otrxd_batch_bool_val), 0x80, NULL, HFILL } },
		{ &hf_otrxd_shadow_ind, { "PDU class", "osmo_trxd.shadow_ind",
		  FT_BOOLEAN, 8, TFS(&otrxd_shadow_bool_val), 0x40, NULL, HFILL } },
		{ &hf_otrxd_trx_num, { "TRX (RF Channel) Number", "osmo_trxd.trx_num",
		  FT_UINT8, BASE_DEC, NULL, 0x3f, NULL, HFILL } },

		/* Rx header fields */
		{ &hf_otrxd_rssi, { "RSSI", "osmo_trxd.meas.rssi",
		  FT_UINT8, BASE_CUSTOM, CF_FUNC(format_rssi), 0, NULL, HFILL } },
		{ &hf_otrxd_toa256, { "Timing of Arrival", "osmo_trxd.meas.toa256",
		  FT_INT16, BASE_DEC | BASE_UNIT_STRING, &otrx_units_toa256, 0, NULL, HFILL } },

		/* MTS (Modulation and Training Sequence) fields */
		{ &hf_otrxd_nope_ind, { "NOPE Indication", "osmo_trxd.nope_ind",
		  FT_BOOLEAN, 8, TFS(&otrxd_nope_bool_val), 0x80, NULL, HFILL } },
		{ &hf_otrxd_nope_ind_pad, { "NOPE Padding", "osmo_trxd.nope_ind_pad",
		  FT_UINT8, BASE_DEC, NULL, 0x7f, NULL, HFILL } },
		{ &hf_otrxd_mod_2b, { "Modulation", "osmo_trxd.mod",
		  FT_UINT8, BASE_DEC, VALS(otrxd_mod_2b_vals), 0x60, NULL, HFILL } },
		{ &hf_otrxd_mod_3b, { "Modulation", "osmo_trxd.mod",
		  FT_UINT8, BASE_DEC, VALS(otrxd_mod_3b_vals), 0x70, NULL, HFILL } },
		{ &hf_otrxd_mod_4b, { "Modulation", "osmo_trxd.mod",
		  FT_UINT8, BASE_DEC, VALS(otrxd_mod_4b_vals), 0x78, NULL, HFILL } },
		{ &hf_otrxd_tsc_set_x2, { "TSC Set", "osmo_trxd.tsc_set",
		  FT_UINT8, BASE_CUSTOM, CF_FUNC(format_tsc_set), 0x08, NULL, HFILL } },
		{ &hf_otrxd_tsc_set_x4, { "TSC Set", "osmo_trxd.tsc_set",
		  FT_UINT8, BASE_CUSTOM, CF_FUNC(format_tsc_set), 0x18, NULL, HFILL } },
		{ &hf_otrxd_tsc, { "TSC (Training Sequence Code)", "osmo_trxd.tsc",
		  FT_UINT8, BASE_DEC, NULL, 0x07, NULL, HFILL } },
		{ &hf_otrxd_ci, { "C/I (Carrier-to-Interference ratio)", "osmo_trxd.meas.ci",
		  FT_INT16, BASE_DEC | BASE_UNIT_STRING, &units_centibels, 0, NULL, HFILL } },

		/* Tx header fields */
		{ &hf_otrxd_tx_att, { "Tx Attenuation", "osmo_trxd.tx_att",
		  FT_UINT8, BASE_DEC | BASE_UNIT_STRING, &units_decibels, 0, NULL, HFILL } },
		{ &hf_otrxd_tx_scpir, { "SCPIR Value", "osmo_trxd.scpir_val",
		  FT_INT8, BASE_DEC | BASE_UNIT_STRING, &units_decibels, 0, NULL, HFILL } },
		{ &hf_otrxd_tx_rfu, { "Spare padding", "osmo_trxd.spare",
		  FT_BYTES, SEP_SPACE, NULL, 0, NULL, HFILL } },

		/* Burst soft (255 .. 0) / hard (1 or 0) bits */
		{ &hf_otrxd_soft_symbols, { "Soft-bits", "osmo_trxd.burst.sbits",
		  FT_BYTES, SEP_SPACE, NULL, 0, NULL, HFILL } },
		{ &hf_otrxd_hard_symbols, { "Hard-bits", "osmo_trxd.burst.hbits",
		  FT_BYTES, SEP_SPACE, NULL, 0, NULL, HFILL } },
		{ &hf_otrxd_burst_pad, { "Legacy padding", "osmo_trxd.burst.pad",
		  FT_BYTES, SEP_SPACE, NULL, 0, NULL, HFILL } },
	};

	static hf_register_info hf_otrxc[] = {
		/* Common generated field: message direction */
		{ &hf_otrxc_msg_dir, { "Message Direction", "osmo_trx.direction",
		  FT_UINT8, BASE_DEC, VALS(otrxcd_dir_vals), 0, NULL, HFILL } },

		{ &hf_otrxc_type, { "Type", "osmo_trxc.type",
		  FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_otrxc_delimiter, { "Delimiter", "osmo_trxc.delim",
		  FT_CHAR, BASE_HEX, NULL, 0, NULL, HFILL } },
		{ &hf_otrxc_verb, { "Verb", "osmo_trxc.verb",
		  FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_otrxc_status, { "Status", "osmo_trxc.status",
		  FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_otrxc_params, { "Parameters", "osmo_trxc.params",
		  FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
	};

	static int *ett[] = {
		&ett_otrxd,
		&ett_otrxd_rx_pdu,
		&ett_otrxd_tx_pdu,
		&ett_otrxc,
	};

	proto_otrxd = proto_register_protocol("OsmoTRX Data Protocol",
					      "OsmoTRXD", "osmo_trxd");
	proto_otrxc = proto_register_protocol("OsmoTRX Control / Clock Protocol",
					      "OsmoTRXC", "osmo_trxc");

	proto_register_field_array(proto_otrxd, hf_otrxd, array_length(hf_otrxd));
	proto_register_field_array(proto_otrxc, hf_otrxc, array_length(hf_otrxc));
	proto_register_subtree_array(ett, array_length(ett));

	static ei_register_info ei_otrxd[] = {
		{ &ei_otrxd_injected_msg, { "osmo_trx.ei.injected_msg",
		  PI_COMMENTS_GROUP, PI_COMMENT, "Injected message", EXPFILL } },
		{ &ei_otrxd_unknown_dir, { "osmo_trx.ei.unknown_dir",
		  PI_UNDECODED, PI_ERROR, "Unknown direction", EXPFILL } },
		{ &ei_otrxd_unknown_pdu_ver, { "osmo_trxd.ei.unknown_pdu_ver",
		  PI_PROTOCOL, PI_ERROR, "Unknown PDU version", EXPFILL } },
		{ &ei_otrxd_tail_octets, { "osmo_trxd.ei.tail_octets",
		  PI_UNDECODED, PI_WARN, "Unhandled tail octets", EXPFILL } },
	};

	static ei_register_info ei_otrxc[] = {
		{ &ei_otrxc_injected_msg, { "osmo_trx.ei.injected_msg",
		  PI_COMMENTS_GROUP, PI_COMMENT, "Injected message", EXPFILL } },
		{ &ei_otrxc_unknown_dir, { "osmo_trx.ei.unknown_dir",
		  PI_ASSUMPTION, PI_WARN, "Unknown direction", EXPFILL } },
		{ &ei_otrxc_bad_delimiter, { "osmo_trxc.ei.bad_delimiter",
		  PI_PROTOCOL, PI_WARN, "Invalid delimiter", EXPFILL } },
		{ &ei_otrxc_rsp_no_code, { "osmo_trxc.ei.rsp_no_code",
		  PI_PROTOCOL, PI_ERROR, "Response without status code", EXPFILL } },
		{ &ei_otrxc_unknown_msg_type, { "osmo_trxc.ei.unknown_msg_type",
		  PI_PROTOCOL, PI_ERROR, "Unknown message type", EXPFILL } },
	};

	/* Expert info for OsmoTRXD protocol */
	expert_module_t *expert_otrxd = expert_register_protocol(proto_otrxd);
	expert_register_field_array(expert_otrxd, ei_otrxd, array_length(ei_otrxd));

	/* Expert info for OsmoTRXC protocol */
	expert_module_t *expert_otrxc = expert_register_protocol(proto_otrxc);
	expert_register_field_array(expert_otrxc, ei_otrxc, array_length(ei_otrxc));

	/* Register the dissectors */
	otrxd_handle = register_dissector("osmo_trxd", dissect_otrxd, proto_otrxd);
	otrxc_handle = register_dissector("osmo_trxc", dissect_otrxc, proto_otrxc);
}

void proto_reg_handoff_osmo_trx(void)
{
#if 0
/* The TRX-side control interface for C(N) is on port P = B + 2N + 1;
 * the corresponding core-side interface for every socket is at P + 100.
 * Give a base port B (5700), the master clock interface is at port P = B. */
#define OTRXC_UDP_PORTS \
	"5701,5703,5800,5801,5803,"  /* The BTS side (osmo-trx, osmo-bts-trx) */ \
	"6701,6703,6800,6801,6803"   /* The MS side (trxcon, fake_trx, grgsm_trx) */

/* The data interface is on an odd numbered port P = B + 2N + 2. */
#define OTRXD_UDP_PORTS \
	"5702,5802,"  /* The BTS side, TRX0 (osmo-trx, osmo-bts-trx) */ \
	"5704,5804,"  /* The BTS side, TRX1 (osmo-trx, osmo-bts-trx) */ \
	"6702,6802"   /* The MS side (trxcon, fake_trx, grgsm_trx) */

	dissector_add_uint_range_with_preference("udp.port", OTRXD_UDP_PORTS, otrxd_handle);
	dissector_add_uint_range_with_preference("udp.port", OTRXC_UDP_PORTS, otrxc_handle);
#endif

	dissector_add_for_decode_as("udp.port", otrxd_handle);
	dissector_add_for_decode_as("udp.port", otrxc_handle);
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

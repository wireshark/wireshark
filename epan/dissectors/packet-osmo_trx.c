/* packet-osmo_trx.c
 * Dissector for OsmoTRX Protocol (GSM Transceiver control and data).
 *
 * (C) 2018 by Harald Welte <laforge@gnumonks.org>
 * (C) 2019 by Vadim Yanitskiy <axilirator@gmail.com>
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

/* Which kind of message it is */
static int proto_otrxd = -1;
static int proto_otrxc = -1;

/* Generated fields */
static int hf_otrxd_burst_dir = -1;
static int hf_otrxc_msg_dir = -1;

/* TRXD header version */
static int hf_otrxd_hdr_ver = -1;

/* Common TDMA fields */
static int hf_otrxd_chdr_reserved = -1;
static int hf_otrxd_tdma_tn = -1;
static int hf_otrxd_tdma_fn = -1;

/* RX TRXD header, V0 specific fields */
static int hf_otrxd_rssi = -1;
static int hf_otrxd_toa256 = -1;

/* RX TRXD header, V1 specific fields */
static int hf_otrxd_nope_ind = -1;
static int hf_otrxd_nope_ind_pad = -1;
static int hf_otrxd_mod_gmsk = -1;
static int hf_otrxd_mod_type = -1;
static int hf_otrxd_tsc_set_x4 = -1;
static int hf_otrxd_tsc_set_x2 = -1;
static int hf_otrxd_tsc = -1;
static int hf_otrxd_ci = -1;

/* TX TRXC header, V0 / V1 specific fields */
static int hf_otrxd_tx_att = -1;

/* Burst soft (255 .. 0) / hard (1 or 0) bits */
static int hf_otrxd_soft_symbols = -1;
static int hf_otrxd_hard_symbols = -1;
static int hf_otrxd_burst_pad = -1;

/* TRXC - Control and Clock protocol */
static int hf_otrxc_type = -1;
static int hf_otrxc_delimiter = -1;
static int hf_otrxc_verb = -1;
static int hf_otrxc_params = -1;
static int hf_otrxc_status = -1;

static gint ett_otrxd = -1;
static gint ett_otrxc = -1;

static expert_field ei_otrxd_unknown_hdr_ver = EI_INIT;
static expert_field ei_otrxd_injected_msg = EI_INIT;
static expert_field ei_otrxd_unknown_dir = EI_INIT;

static expert_field ei_otrxc_unknown_msg_type = EI_INIT;
static expert_field ei_otrxc_bad_delimiter = EI_INIT;
static expert_field ei_otrxc_rsp_no_code = EI_INIT;
static expert_field ei_otrxc_injected_msg = EI_INIT;
static expert_field ei_otrxc_unknown_dir = EI_INIT;

/* Custom units */
static const unit_name_string otrx_units_toa256 = { " (1/256 of a symbol)", NULL };

/* TRXD modulation types */
static const value_string otrxd_mod_vals[] = {
	/* NOTE: unlike the others, GMSK has 4 TSC sets,
	 * so the LSB bit is used to extend the value range. */
	{ 0x00, "GMSK" },
	{ 0x01, "GMSK" },
	{ 0x02, "8-PSK" },
	{ 0x03, "AQPSK" },
	{ 0x04, "16QAM" },
	{ 0x05, "32QAM" },
	/* Reserved for further use */
	{ 0x06, "RESERVED" },
	{ 0x07, "RESERVED" },
	{ 0, NULL },
};

/* RSSI is encoded without a negative sign, so we need to show it */
static void format_rssi(gchar *buf, guint32 rssi)
{
	g_snprintf(buf, ITEM_LABEL_LENGTH, "-%u%s", rssi, unit_name_string_get_value(rssi, &units_dbm));
}

/* TSC (Training Sequence Code) set number in 3GPP TS 45.002 starts
 * from 1, while 'on the wire' it's encoded as X - 1 (starts from 0). */
static void format_tsc_set(gchar *buf, guint32 tsc_set)
{
	g_snprintf(buf, ITEM_LABEL_LENGTH, "%u", tsc_set + 1);
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

/* Dissector for Rx TRXD header version 0 */
static int dissect_otrxd_rx_hdr_v0(tvbuff_t *tvb, packet_info *pinfo _U_,
				   proto_item *ti _U_, proto_tree *tree,
				   int offset)
{
	proto_tree_add_item(tree, hf_otrxd_rssi, tvb, offset++, 1, ENC_NA);
	proto_tree_add_item(tree, hf_otrxd_toa256, tvb, offset, 2, ENC_NA);

	return 1 + 2;
}

/* Dissector for Rx TRXD header version 1 */
static int dissect_otrxd_rx_hdr_v1(tvbuff_t *tvb, packet_info *pinfo,
				   proto_item *ti, proto_tree *tree,
				   int offset)
{
	const gchar *mod_str;
	gboolean nope_ind;
	guint32 mts, tsc;
	int v0_hdr_len;

	/* Dissect V0 specific part first */
	v0_hdr_len = dissect_otrxd_rx_hdr_v0(tvb, pinfo, ti, tree, offset);
	offset += v0_hdr_len;

	/* NOPE indication does not contain MTS nor C/I.
	 *
	 * | 7 6 5 4 3 2 1 0 | Bit numbers (value range)
	 * | X . . . . . . . | NOPE / IDLE indication
	 * | . X X X X . . . | MTS (Modulation and Training Sequence)
	 * | . . . . . X X X | TSC (Training Sequence Code)
	 */
	proto_tree_add_item_ret_boolean(tree, hf_otrxd_nope_ind, tvb,
					offset, 1, ENC_NA, &nope_ind);
	if (nope_ind) {
		proto_tree_add_item(tree, hf_otrxd_nope_ind_pad, tvb, offset++, 1, ENC_NA);
		col_append_str(pinfo->cinfo, COL_INFO, ", NOPE.ind");
		proto_item_append_text(ti, ", NOPE.ind");
		goto skip_mts;
	}

	/* MTS (Modulation and Training Sequence info).
	 *
	 * | 7 6 5 4 3 2 1 0 | Bit numbers (value range)
	 * | . 0 0 X X . . . | GMSK, 4 TSC sets (0..3)
	 * | . 0 1 0 X . . . | 8-PSK, 2 TSC sets (0..1)
	 * | . 0 1 1 X . . . | AQPSK, 2 TSC sets (0..1)
	 * | . 1 0 0 X . . . | 16QAM, 2 TSC sets (0..1)
	 * | . 1 0 1 X . . . | 32QAM, 2 TSC sets (0..1)
	 * | . 1 1 0 X . . . | RESERVED (0)
	 * | . 1 1 1 X . . . | RESERVED (0)
	 *
	 * NOTE: GMSK has 4 TSC sets, so bit 4 is used for range extension.
	 */
	mts = tvb_get_guint8(tvb, offset);
	if (((mts >> 5) & 0x03) == 0x00) {
		proto_tree_add_item(tree, hf_otrxd_mod_gmsk, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(tree, hf_otrxd_tsc_set_x4, tvb, offset, 1, ENC_NA);
	} else {
		proto_tree_add_item(tree, hf_otrxd_mod_type, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(tree, hf_otrxd_tsc_set_x2, tvb, offset, 1, ENC_NA);
	}
	proto_tree_add_item_ret_uint(tree, hf_otrxd_tsc, tvb, offset, 1, ENC_NA, &tsc);
	offset++;

	mod_str = val_to_str((mts >> 4) & 0x07, otrxd_mod_vals, "Unknown 0x%02x");
	col_append_fstr(pinfo->cinfo, COL_INFO, ", Modulation %s, TSC %u", mod_str, tsc);
	proto_item_append_text(ti, ", Modulation %s, TSC %u", mod_str, tsc);

skip_mts:
	/* C/I (Carrier to Interference ratio) */
	proto_tree_add_item(tree, hf_otrxd_ci, tvb, offset, 2, ENC_NA);

	return v0_hdr_len + 1 + 2;
}

/* Dissector for common Rx/Tx TRXD header part */
static int dissect_otrxd_common_hdr(tvbuff_t *tvb, packet_info *pinfo,
				    proto_item *ti, proto_tree *tree,
				    guint32 *hdr_ver)
{
	guint32 tdma_tn, tdma_fn;
	int offset = 0;

	/* TRXD header version and TDMA time-slot number.
	 *
	 * | 7 6 5 4 3 2 1 0 | Bit numbers (value range)
	 * | X X X X . . . . | HDR version (0..15)
	 * | . . . . . X X X | TDMA time-slot number (0..7)
	 * | . . . . X . . . | Reserved (0)
	 */
	proto_tree_add_item_ret_uint(tree, hf_otrxd_hdr_ver, tvb,
				     offset, 1, ENC_NA, hdr_ver);
	proto_tree_add_item(tree, hf_otrxd_chdr_reserved, tvb,
				     offset, 1, ENC_NA);
	proto_tree_add_item_ret_uint(tree, hf_otrxd_tdma_tn, tvb,
				     offset, 1, ENC_NA, &tdma_tn);
	offset++;

	/* TDMA frame number (4 octets, big endian) */
	proto_tree_add_item_ret_uint(tree, hf_otrxd_tdma_fn, tvb,
				     offset, 4, ENC_BIG_ENDIAN, &tdma_fn);

	col_append_fstr(pinfo->cinfo, COL_INFO, "TDMA FN %07u TN %u", tdma_fn, tdma_tn);
	proto_item_append_text(ti, ", TDMA FN %07u TN %u", tdma_fn, tdma_tn);

	return 1 + 4;
}

/* Burst data in Receive direction */
static int dissect_otrxd_rx(tvbuff_t *tvb, packet_info *pinfo,
			    proto_item *ti, proto_tree *tree,
			    int offset, guint32 hdr_ver)
{
	int burst_len, padding = 0;

	/* Parse version specific TRXD header part */
	switch (hdr_ver) {
	case 0:
		offset += dissect_otrxd_rx_hdr_v0(tvb, pinfo, ti, tree, offset);
		break;
	case 1:
		offset += dissect_otrxd_rx_hdr_v1(tvb, pinfo, ti, tree, offset);
		break;
	default:
		expert_add_info_format(pinfo, ti, &ei_otrxd_unknown_hdr_ver,
				       "Unknown TRXD header version %u", hdr_ver);
		return offset;
	}

	/* Calculate the burst length */
	burst_len = tvb_reported_length(tvb) - offset;

	/* There can be two optional padding bytes -> detect them! */
	if (burst_len == 148 + 2 || burst_len == 444 + 2) {
		burst_len -= 2;
		padding = 2;
	}

	/* Soft-bits (255..0) */
	if (burst_len > 0) {
		proto_tree_add_item(tree, hf_otrxd_soft_symbols, tvb,
				    offset, burst_len, ENC_NA);
		offset += burst_len;
	}

	/* Optional padding */
	if (padding > 0) {
		proto_tree_add_item(tree, hf_otrxd_burst_pad, tvb,
				    offset, padding, ENC_NA);
	}

	return tvb_captured_length(tvb);
}

/* Burst data in Transmit direction */
static int dissect_otrxd_tx(tvbuff_t *tvb, packet_info *pinfo,
			    proto_item *ti _U_, proto_tree *tree,
			    int offset, guint32 hdr_ver)
{
	int burst_len;

	/* Parse version specific TRXD header part */
	switch (hdr_ver) {
	/* Both versions feature the same header format */
	case 0:
	case 1:
		proto_tree_add_item(tree, hf_otrxd_tx_att, tvb, offset, 1, ENC_NA);
		offset++;
		break;
	default:
		expert_add_info_format(pinfo, ti, &ei_otrxd_unknown_hdr_ver,
				       "Unknown TRXD header version %u", hdr_ver);
		return offset;
	}

	/* Calculate the burst length */
	burst_len = tvb_reported_length(tvb) - offset;

	/* Attempt to guess modulation by the length */
	switch (burst_len) {
	/* We may also have NOPE.req in the future (to drive fake_trx.py) */
	case 0:
		col_append_str(pinfo->cinfo, COL_INFO, ", NOPE.req");
		proto_item_append_text(ti, ", NOPE.req");
		break;
	/* TODO: introduce an enumerated type, detect other modulation types,
	 * TODO: add a generated field for "osmo_trxd.mod" */
	case 148:
		col_append_str(pinfo->cinfo, COL_INFO, ", Modulation GMSK");
		proto_item_append_text(ti, ", Modulation GMSK");
		break;
	case 444:
		col_append_str(pinfo->cinfo, COL_INFO, ", Modulation 8-PSK");
		proto_item_append_text(ti, ", Modulation 8-PSK");
		break;
	}

	/* Hard-bits (1 or 0) */
	if (burst_len > 0) {
		proto_tree_add_item(tree, hf_otrxd_hard_symbols, tvb,
				    offset, burst_len, ENC_NA);
	}

	return tvb_captured_length(tvb);
}

/* Common dissector for bursts in both directions */
static int dissect_otrxd(tvbuff_t *tvb, packet_info *pinfo,
			 proto_tree *tree, void* data _U_)
{

	proto_tree *otrxd_tree;
	proto_item *ti, *gi;
	guint32 hdr_ver;
	int offset, rc;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "OsmoTRXD");
	col_clear(pinfo->cinfo, COL_INFO);

	/* Common TRXD header tree (1 + 4 bytes) */
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

	/* Parse common TRXD header part */
	offset = dissect_otrxd_common_hdr(tvb, pinfo, ti, otrxd_tree, &hdr_ver);

	if (burst_dir == OTRXCD_DIR_L12TRX)
		rc = dissect_otrxd_tx(tvb, pinfo, ti, otrxd_tree, offset, hdr_ver);
	else if (burst_dir == OTRXCD_DIR_TRX2L1)
		rc = dissect_otrxd_rx(tvb, pinfo, ti, otrxd_tree, offset, hdr_ver);
	else {
		expert_add_info(pinfo, ti, &ei_otrxd_unknown_dir);
		rc = offset;
	}

	return rc;
}

/* Dissector for Control commands and responses, and Clock indications */
static int dissect_otrxc(tvbuff_t *tvb, packet_info *pinfo,
			 proto_tree *tree, void *data _U_)
{
	int offset = 0, msg_len, end_verb, end_status;
	const guint8 *msg_str, *msg_type_str;
	proto_item *ti, *gi, *delim_item;
	proto_tree *otrxc_tree;
	guint32 delimiter;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "OsmoTRXC");
	col_clear(pinfo->cinfo, COL_INFO);

	msg_len = tvb_reported_length(tvb);
	msg_str = tvb_get_string_enc(wmem_packet_scope(), tvb, 0, msg_len, ENC_ASCII);
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
				       ENC_NA | ENC_ASCII, wmem_packet_scope(),
				       &msg_type_str);
	offset += 3;

	/* Determine the message type */
	enum otrxc_msg_type msg_type = str_to_val((const gchar *) msg_type_str,
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

		/* Common TRXD header fields */
		{ &hf_otrxd_hdr_ver, { "Header Version", "osmo_trxd.hdr_ver",
		  FT_UINT8, BASE_DEC, NULL, 0xf0, NULL, HFILL } },
		{ &hf_otrxd_chdr_reserved, { "Reserved", "osmo_trxd.chdr_reserved",
		  FT_UINT8, BASE_DEC, NULL, 0x08, NULL, HFILL } },
		{ &hf_otrxd_tdma_tn, { "TDMA Timeslot Number", "osmo_trxd.tdma.tn",
		  FT_UINT8, BASE_DEC, NULL, 0x07, NULL, HFILL } },
		{ &hf_otrxd_tdma_fn, { "TDMA Frame Number", "osmo_trxd.tdma.fn",
		  FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },

		/* Rx TRXD header, V0 specific fields */
		{ &hf_otrxd_rssi, { "RSSI", "osmo_trxd.meas.rssi",
		  FT_UINT8, BASE_CUSTOM, CF_FUNC(format_rssi), 0, NULL, HFILL } },
		{ &hf_otrxd_toa256, { "Timing of Arrival", "osmo_trxd.meas.toa256",
		  FT_INT16, BASE_DEC | BASE_UNIT_STRING, &otrx_units_toa256, 0, NULL, HFILL } },

		/* Rx TRXD header, V1 specific fields */
		{ &hf_otrxd_nope_ind, { "NOPE Indication", "osmo_trxd.nope_ind",
		  FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL } },
		{ &hf_otrxd_nope_ind_pad, { "NOPE Padding", "osmo_trxd.nope_ind_pad",
		  FT_UINT8, BASE_DEC, NULL, 0x7f, NULL, HFILL } },
		{ &hf_otrxd_mod_type, { "Modulation", "osmo_trxd.mod",
		  FT_UINT8, BASE_DEC, VALS(otrxd_mod_vals), 0x70, NULL, HFILL } },
		{ &hf_otrxd_tsc_set_x2, { "TSC Set", "osmo_trxd.tsc_set",
		  FT_UINT8, BASE_CUSTOM, CF_FUNC(format_tsc_set), 0x08, NULL, HFILL } },
		{ &hf_otrxd_mod_gmsk, { "Modulation", "osmo_trxd.mod",
		  FT_UINT8, BASE_DEC, VALS(otrxd_mod_vals), 0x60, NULL, HFILL } },
		{ &hf_otrxd_tsc_set_x4, { "TSC Set", "osmo_trxd.tsc_set",
		  FT_UINT8, BASE_CUSTOM, CF_FUNC(format_tsc_set), 0x18, NULL, HFILL } },
		{ &hf_otrxd_tsc, { "TSC (Training Sequence Code)", "osmo_trxd.tsc",
		  FT_UINT8, BASE_DEC, NULL, 0x07, NULL, HFILL } },
		{ &hf_otrxd_ci, { "C/I (Carrier-to-Interference ratio)", "osmo_trxd.meas.ci",
		  FT_INT16, BASE_DEC | BASE_UNIT_STRING, &units_centibels, 0, NULL, HFILL } },

		/* Tx TRXD header, V0 / V1 specific fields */
		{ &hf_otrxd_tx_att, { "Tx Attenuation", "osmo_trxd.tx_att",
		  FT_UINT8, BASE_DEC | BASE_UNIT_STRING, &units_decibels, 0, NULL, HFILL } },

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

	static gint *ett[] = {
		&ett_otrxd,
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
		{ &ei_otrxd_unknown_hdr_ver, { "osmo_trxd.ei.unknown_hdr_ver",
		  PI_PROTOCOL, PI_WARN, "Unknown header version", EXPFILL } },
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
}

void proto_reg_handoff_osmo_trx(void)
{
	dissector_handle_t otrxd_handle;
	dissector_handle_t otrxc_handle;

	otrxd_handle = create_dissector_handle(dissect_otrxd, proto_otrxd);
	otrxc_handle = create_dissector_handle(dissect_otrxc, proto_otrxc);

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

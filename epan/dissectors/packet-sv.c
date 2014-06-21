/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-sv.c                                                                */
/* ../../tools/asn2wrs.py -b -p sv -c ./sv.cnf -s ./packet-sv-template -D . -O ../../epan/dissectors sv.asn */

/* Input file: packet-sv-template.c */

#line 1 "../../asn1/sv/packet-sv-template.c"
/* packet-sv.c
 * Routines for IEC 61850 Sampled Vales packet dissection
 * Michael Bernhard 2008
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

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/etypes.h>
#include <epan/expert.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-acse.h"

#include "tap.h"

#include "packet-sv.h"

#define PNAME  "IEC61850 Sampled Values"
#define PSNAME "SV"
#define PFNAME "sv"

/* see IEC61850-8-1 8.2 */
#define Q_VALIDITY_GOOD			(0x0 << 0)
#define Q_VALIDITY_INVALID		(0x1 << 0)
#define Q_VALIDITY_QUESTIONABLE	(0x3 << 0)
#define Q_VALIDITY_MASK			(0x3 << 0)

#define Q_OVERFLOW				(1 << 2)
#define Q_OUTOFRANGE			(1 << 3)
#define Q_BADREFERENCE			(1 << 4)
#define Q_OSCILLATORY			(1 << 5)
#define Q_FAILURE				(1 << 6)
#define Q_OLDDATA				(1 << 7)
#define Q_INCONSISTENT			(1 << 8)
#define Q_INACCURATE			(1 << 9)

#define Q_SOURCE_PROCESS		(0 << 10)
#define Q_SOURCE_SUBSTITUTED	(1 << 10)
#define Q_SOURCE_MASK			(1 << 10)

#define Q_TEST					(1 << 11)
#define Q_OPERATORBLOCKED		(1 << 12)

/* see UCA Implementation Guideline for IEC 61850-9-2 */
#define Q_DERIVED				(1 << 13)

void proto_register_sv(void);
void proto_reg_handoff_sv(void);

/* Data for SV tap */
static int sv_tap = -1;
static sv_frame_data sv_data;

/* Initialize the protocol and registered fields */
static int proto_sv = -1;
static int hf_sv_appid = -1;
static int hf_sv_length = -1;
static int hf_sv_reserve1 = -1;
static int hf_sv_reserve2 = -1;
#if 0
static int hf_sv_phmeas_instmag_i = -1;
static int hf_sv_phsmeas_q = -1;
static int hf_sv_phsmeas_q_validity = -1;
static int hf_sv_phsmeas_q_overflow = -1;
static int hf_sv_phsmeas_q_outofrange = -1;
static int hf_sv_phsmeas_q_badreference = -1;
static int hf_sv_phsmeas_q_oscillatory = -1;
static int hf_sv_phsmeas_q_failure = -1;
static int hf_sv_phsmeas_q_olddata = -1;
static int hf_sv_phsmeas_q_inconsistent = -1;
static int hf_sv_phsmeas_q_inaccurate = -1;
static int hf_sv_phsmeas_q_source = -1;
static int hf_sv_phsmeas_q_test = -1;
static int hf_sv_phsmeas_q_operatorblocked = -1;
static int hf_sv_phsmeas_q_derived = -1;
#endif

/*--- Included file: packet-sv-hf.c ---*/
#line 1 "../../asn1/sv/packet-sv-hf.c"
static int hf_sv_savPdu = -1;                     /* SavPdu */
static int hf_sv_noASDU = -1;                     /* INTEGER_0_65535 */
static int hf_sv_seqASDU = -1;                    /* SEQUENCE_OF_ASDU */
static int hf_sv_seqASDU_item = -1;               /* ASDU */
static int hf_sv_svID = -1;                       /* VisibleString */
static int hf_sv_datSet = -1;                     /* VisibleString */
static int hf_sv_smpCnt = -1;                     /* T_smpCnt */
static int hf_sv_confRef = -1;                    /* INTEGER_0_4294967295 */
static int hf_sv_refrTm = -1;                     /* UtcTime */
static int hf_sv_smpSynch = -1;                   /* T_smpSynch */
static int hf_sv_smpRate = -1;                    /* INTEGER_0_65535 */
static int hf_sv_seqData = -1;                    /* Data */
static int hf_sv_smpMod = -1;                     /* T_smpMod */

/*--- End of included file: packet-sv-hf.c ---*/
#line 102 "../../asn1/sv/packet-sv-template.c"

/* Initialize the subtree pointers */
static int ett_sv = -1;
static int ett_phsmeas = -1;
static int ett_phsmeas_q = -1;


/*--- Included file: packet-sv-ett.c ---*/
#line 1 "../../asn1/sv/packet-sv-ett.c"
static gint ett_sv_SampledValues = -1;
static gint ett_sv_SavPdu = -1;
static gint ett_sv_SEQUENCE_OF_ASDU = -1;
static gint ett_sv_ASDU = -1;

/*--- End of included file: packet-sv-ett.c ---*/
#line 109 "../../asn1/sv/packet-sv-template.c"

static expert_field ei_sv_mal_utctime = EI_INIT;

#if 0
static const value_string sv_q_validity_vals[] = {
  {   0, "good" },
  {   1, "invalid" },
  {   3, "questionable" },
  { 0, NULL }
};

static const value_string sv_q_source_vals[] = {
  {   0, "process" },
  {   1, "substituted" },
  { 0, NULL }
};

static int
dissect_PhsMeas1(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, int hf_id _U_)
{
	gint8 class;
	gboolean pc;
	gint32 tag;
	guint32 len;
	proto_item *it;
	proto_tree *subtree;
	gint32 value;
	guint32 qual;
	guint32 i;

	static const int *q_flags[] = {
		&hf_sv_phsmeas_q_validity,
		&hf_sv_phsmeas_q_overflow,
		&hf_sv_phsmeas_q_outofrange,
		&hf_sv_phsmeas_q_badreference,
		&hf_sv_phsmeas_q_oscillatory,
		&hf_sv_phsmeas_q_failure,
		&hf_sv_phsmeas_q_olddata,
		&hf_sv_phsmeas_q_inconsistent,
		&hf_sv_phsmeas_q_inaccurate,
		&hf_sv_phsmeas_q_source,
		&hf_sv_phsmeas_q_test,
		&hf_sv_phsmeas_q_operatorblocked,
		&hf_sv_phsmeas_q_derived,
		NULL
		};

	if (!implicit_tag) {
		offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
		offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, NULL);
	} else {
		len=tvb_length_remaining(tvb, offset);
	}

	subtree = proto_tree_add_subtree(tree, tvb, offset, len, ett_phsmeas, NULL, "PhsMeas1");

	sv_data.num_phsMeas = 0;
	for (i = 0; i < len/8; i++) {
		if (tree && subtree) {
			value = tvb_get_ntohl(tvb, offset);
			qual = tvb_get_ntohl(tvb, offset + 4);

			proto_tree_add_item(subtree, hf_sv_phmeas_instmag_i, tvb, offset, 4, ENC_BIG_ENDIAN);
			proto_tree_add_bitmask(subtree, tvb, offset + 4, hf_sv_phsmeas_q, ett_phsmeas_q, q_flags, ENC_BIG_ENDIAN);

			if (i < IEC61850_SV_MAX_PHSMEAS_ENTRIES) {
				sv_data.phsMeas[i].value = value;
				sv_data.phsMeas[i].qual = qual;
				sv_data.num_phsMeas++;
			}
		}

		offset += 8;
	}

	return offset;
}

#endif

/*--- Included file: packet-sv-fn.c ---*/
#line 1 "../../asn1/sv/packet-sv-fn.c"


static int
dissect_sv_INTEGER_0_65535(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_sv_VisibleString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_sv_T_smpCnt(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 18 "../../asn1/sv/sv.cnf"
	guint32 value;
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &value);

	sv_data.smpCnt = value;


  return offset;
}



static int
dissect_sv_INTEGER_0_4294967295(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_sv_UtcTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 24 "../../asn1/sv/sv.cnf"
	guint32 len;
	guint32 seconds;
	guint32	fraction;
	guint32 nanoseconds;
	nstime_t ts;
	gchar *	ptime;

	len = tvb_length_remaining(tvb, offset);

	if(len != 8)
	{
		proto_tree_add_expert_format(tree, actx->pinfo, &ei_sv_mal_utctime, tvb, offset, len,
				"BER Error: malformed UTCTime encoding, length must be 8 bytes");
		if(hf_index >= 0)
		{
			proto_tree_add_string(tree, hf_index, tvb, offset, len, "????");
		}
		return offset;
	}

	seconds = tvb_get_ntohl(tvb, offset);
	fraction = tvb_get_ntoh24(tvb, offset+4) * 0x100; /* Only 3 bytes are recommended */
	nanoseconds = (guint32)( ((guint64)fraction * G_GUINT64_CONSTANT(1000000000)) / G_GUINT64_CONSTANT(0x100000000) ) ;

	ts.secs = seconds;
	ts.nsecs = nanoseconds;

	ptime = abs_time_to_str(wmem_packet_scope(), &ts, ABSOLUTE_TIME_UTC, TRUE);

	if(hf_index >= 0)
	{
		proto_tree_add_string(tree, hf_index, tvb, offset, len, ptime);
	}
	offset += 8;
	return offset;


  return offset;
}


static const value_string sv_T_smpSynch_vals[] = {
  {   0, "none" },
  {   1, "local" },
  {   2, "global" },
  { 0, NULL }
};


static int
dissect_sv_T_smpSynch(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 65 "../../asn1/sv/sv.cnf"
	guint32 value;
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &value);

	sv_data.smpSynch = value;


  return offset;
}



static int
dissect_sv_Data(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string sv_T_smpMod_vals[] = {
  {   0, "samplesPerNormalPeriod" },
  {   1, "samplesPerSecond" },
  {   2, "secondsPerSample" },
  { 0, NULL }
};


static int
dissect_sv_T_smpMod(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 71 "../../asn1/sv/sv.cnf"
	guint32 value;
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &value);

	sv_data.smpMod = value;


  return offset;
}


static const ber_sequence_t ASDU_sequence[] = {
  { &hf_sv_svID             , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sv_VisibleString },
  { &hf_sv_datSet           , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sv_VisibleString },
  { &hf_sv_smpCnt           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_sv_T_smpCnt },
  { &hf_sv_confRef          , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_sv_INTEGER_0_4294967295 },
  { &hf_sv_refrTm           , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sv_UtcTime },
  { &hf_sv_smpSynch         , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sv_T_smpSynch },
  { &hf_sv_smpRate          , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sv_INTEGER_0_65535 },
  { &hf_sv_seqData          , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_sv_Data },
  { &hf_sv_smpMod           , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sv_T_smpMod },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sv_ASDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ASDU_sequence, hf_index, ett_sv_ASDU);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ASDU_sequence_of[1] = {
  { &hf_sv_seqASDU_item     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_sv_ASDU },
};

static int
dissect_sv_SEQUENCE_OF_ASDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ASDU_sequence_of, hf_index, ett_sv_SEQUENCE_OF_ASDU);

  return offset;
}


static const ber_sequence_t SavPdu_sequence[] = {
  { &hf_sv_noASDU           , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sv_INTEGER_0_65535 },
  { &hf_sv_seqASDU          , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_sv_SEQUENCE_OF_ASDU },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_sv_SavPdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SavPdu_sequence, hf_index, ett_sv_SavPdu);

  return offset;
}


static const ber_choice_t SampledValues_choice[] = {
  {   0, &hf_sv_savPdu           , BER_CLASS_APP, 0, BER_FLAGS_IMPLTAG, dissect_sv_SavPdu },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_sv_SampledValues(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SampledValues_choice, hf_index, ett_sv_SampledValues,
                                 NULL);

  return offset;
}


/*--- End of included file: packet-sv-fn.c ---*/
#line 189 "../../asn1/sv/packet-sv-template.c"

/*
* Dissect SV PDUs inside a PPDU.
*/
static void
dissect_sv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	int old_offset;
	proto_item *item;
	proto_tree *tree;
	asn1_ctx_t asn1_ctx;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	item = proto_tree_add_item(parent_tree, proto_sv, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_sv);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, PNAME);
	col_clear(pinfo->cinfo, COL_INFO);

	/* APPID */
	if (tree && tvb_reported_length_remaining(tvb, offset) >= 2)
		proto_tree_add_item(tree, hf_sv_appid, tvb, offset, 2, ENC_BIG_ENDIAN);

	/* Length */
	if (tree && tvb_reported_length_remaining(tvb, offset) >= 4)
		proto_tree_add_item(tree, hf_sv_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

	/* Reserved 1 */
	if (tree && tvb_reported_length_remaining(tvb, offset) >= 6)
		proto_tree_add_item(tree, hf_sv_reserve1, tvb, offset + 4, 2, ENC_BIG_ENDIAN);

	/* Reserved 2 */
	if (tree && tvb_reported_length_remaining(tvb, offset) >= 8)
		proto_tree_add_item(tree, hf_sv_reserve2, tvb, offset + 6, 2, ENC_BIG_ENDIAN);

	offset = 8;
	while (tree && tvb_reported_length_remaining(tvb, offset) > 0){
		old_offset = offset;
		offset = dissect_sv_SampledValues(FALSE, tvb, offset, &asn1_ctx , tree, -1);
		if (offset == old_offset) {
			proto_tree_add_text(tree, tvb, offset, -1, "Internal error, zero-byte SV PDU");
			break;
		}
	}

	if(tree)
		tap_queue_packet(sv_tap, pinfo, &sv_data);
}


/*--- proto_register_sv -------------------------------------------*/
void proto_register_sv(void) {

	/* List of fields */
	static hf_register_info hf[] = {
		{ &hf_sv_appid,
		{ "APPID",	"sv.appid", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{ &hf_sv_length,
		{ "Length",	"sv.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_sv_reserve1,
		{ "Reserved 1",	"sv.reserve1", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_sv_reserve2,
		{ "Reserved 2",	"sv.reserve2", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
#if 0
		{ &hf_sv_phmeas_instmag_i,
		{ "value", "sv.meas_value", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},

		{ &hf_sv_phsmeas_q,
		{ "quality", "sv.meas_quality", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_sv_phsmeas_q_validity,
		{ "validity", "sv.meas_quality.validity", FT_UINT32, BASE_HEX, VALS(sv_q_validity_vals), Q_VALIDITY_MASK, NULL, HFILL}},

		{ &hf_sv_phsmeas_q_overflow,
		{ "overflow", "sv.meas_quality.overflow", FT_BOOLEAN, 32, NULL, Q_OVERFLOW, NULL, HFILL}},

		{ &hf_sv_phsmeas_q_outofrange,
		{ "out of range", "sv.meas_quality.outofrange", FT_BOOLEAN, 32, NULL, Q_OUTOFRANGE, NULL, HFILL}},

		{ &hf_sv_phsmeas_q_badreference,
		{ "bad reference", "sv.meas_quality.badreference", FT_BOOLEAN, 32, NULL, Q_BADREFERENCE, NULL, HFILL}},

		{ &hf_sv_phsmeas_q_oscillatory,
		{ "oscillatory", "sv.meas_quality.oscillatory", FT_BOOLEAN, 32, NULL, Q_OSCILLATORY, NULL, HFILL}},

		{ &hf_sv_phsmeas_q_failure,
		{ "failure", "sv.meas_quality.failure", FT_BOOLEAN, 32, NULL, Q_FAILURE, NULL, HFILL}},

		{ &hf_sv_phsmeas_q_olddata,
		{ "old data", "sv.meas_quality.olddata", FT_BOOLEAN, 32, NULL, Q_OLDDATA, NULL, HFILL}},

		{ &hf_sv_phsmeas_q_inconsistent,
		{ "inconsistent", "sv.meas_quality.inconsistent", FT_BOOLEAN, 32, NULL, Q_INCONSISTENT, NULL, HFILL}},

		{ &hf_sv_phsmeas_q_inaccurate,
		{ "inaccurate", "sv.meas_quality.inaccurate", FT_BOOLEAN, 32, NULL, Q_INACCURATE, NULL, HFILL}},

		{ &hf_sv_phsmeas_q_source,
		{ "source", "sv.meas_quality.source", FT_UINT32, BASE_HEX, VALS(sv_q_source_vals), Q_SOURCE_MASK, NULL, HFILL}},

		{ &hf_sv_phsmeas_q_test,
		{ "test", "sv.meas_quality.teset", FT_BOOLEAN, 32, NULL, Q_TEST, NULL, HFILL}},

		{ &hf_sv_phsmeas_q_operatorblocked,
		{ "operator blocked", "sv.meas_quality.operatorblocked", FT_BOOLEAN, 32, NULL, Q_OPERATORBLOCKED, NULL, HFILL}},

		{ &hf_sv_phsmeas_q_derived,
		{ "derived", "sv.meas_quality.derived", FT_BOOLEAN, 32, NULL, Q_DERIVED, NULL, HFILL}},
#endif


/*--- Included file: packet-sv-hfarr.c ---*/
#line 1 "../../asn1/sv/packet-sv-hfarr.c"
    { &hf_sv_savPdu,
      { "savPdu", "sv.savPdu_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sv_noASDU,
      { "noASDU", "sv.noASDU",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_sv_seqASDU,
      { "seqASDU", "sv.seqASDU",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ASDU", HFILL }},
    { &hf_sv_seqASDU_item,
      { "ASDU", "sv.ASDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_sv_svID,
      { "svID", "sv.svID",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_sv_datSet,
      { "datSet", "sv.datSet",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_sv_smpCnt,
      { "smpCnt", "sv.smpCnt",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_sv_confRef,
      { "confRef", "sv.confRef",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_sv_refrTm,
      { "refrTm", "sv.refrTm",
        FT_STRING, BASE_NONE, NULL, 0,
        "UtcTime", HFILL }},
    { &hf_sv_smpSynch,
      { "smpSynch", "sv.smpSynch",
        FT_INT32, BASE_DEC, VALS(sv_T_smpSynch_vals), 0,
        NULL, HFILL }},
    { &hf_sv_smpRate,
      { "smpRate", "sv.smpRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_sv_seqData,
      { "seqData", "sv.seqData",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Data", HFILL }},
    { &hf_sv_smpMod,
      { "smpMod", "sv.smpMod",
        FT_INT32, BASE_DEC, VALS(sv_T_smpMod_vals), 0,
        NULL, HFILL }},

/*--- End of included file: packet-sv-hfarr.c ---*/
#line 305 "../../asn1/sv/packet-sv-template.c"
	};

	/* List of subtrees */
	static gint *ett[] = {
		&ett_sv,
		&ett_phsmeas,
		&ett_phsmeas_q,

/*--- Included file: packet-sv-ettarr.c ---*/
#line 1 "../../asn1/sv/packet-sv-ettarr.c"
    &ett_sv_SampledValues,
    &ett_sv_SavPdu,
    &ett_sv_SEQUENCE_OF_ASDU,
    &ett_sv_ASDU,

/*--- End of included file: packet-sv-ettarr.c ---*/
#line 313 "../../asn1/sv/packet-sv-template.c"
	};

	static ei_register_info ei[] = {
		{ &ei_sv_mal_utctime, { "sv.malformed.utctime", PI_MALFORMED, PI_WARN, "BER Error: malformed UTCTime encoding", EXPFILL }},
	};

	expert_module_t* expert_sv;

	/* Register protocol */
	proto_sv = proto_register_protocol(PNAME, PSNAME, PFNAME);
	register_dissector("sv", dissect_sv, proto_sv);

	/* Register fields and subtrees */
	proto_register_field_array(proto_sv, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_sv = expert_register_protocol(proto_sv);
	expert_register_field_array(expert_sv, ei, array_length(ei));

	/* Register tap */
	sv_tap = register_tap("sv");
}

/*--- proto_reg_handoff_sv --- */
void proto_reg_handoff_sv(void) {

	dissector_handle_t sv_handle;
	sv_handle = find_dissector("sv");

	dissector_add_uint("ethertype", ETHERTYPE_IEC61850_SV, sv_handle);
}

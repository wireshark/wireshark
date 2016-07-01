/* packet-sv.c
 * Routines for IEC 61850 Sampled Values packet dissection
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

#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/etypes.h>
#include <epan/expert.h>
#include <epan/prefs.h>

#include "packet-ber.h"
#include "packet-acse.h"

#include "tap.h"

#include "packet-sv.h"

#define PNAME  "IEC61850 Sampled Values"
#define PSNAME "SV"
#define PFNAME "sv"

/* see IEC61850-8-1 8.2 */
#define Q_VALIDITY_GOOD			(0x0U << 0)
#define Q_VALIDITY_INVALID		(0x1U << 0)
#define Q_VALIDITY_QUESTIONABLE		(0x3U << 0)
#define Q_VALIDITY_MASK			(0x3U << 0)

#define Q_OVERFLOW			(1U << 2)
#define Q_OUTOFRANGE			(1U << 3)
#define Q_BADREFERENCE			(1U << 4)
#define Q_OSCILLATORY			(1U << 5)
#define Q_FAILURE			(1U << 6)
#define Q_OLDDATA			(1U << 7)
#define Q_INCONSISTENT			(1U << 8)
#define Q_INACCURATE			(1U << 9)

#define Q_SOURCE_PROCESS		(0U << 10)
#define Q_SOURCE_SUBSTITUTED		(1U << 10)
#define Q_SOURCE_MASK			(1U << 10)

#define Q_TEST				(1U << 11)
#define Q_OPERATORBLOCKED		(1U << 12)

/* see UCA Implementation Guideline for IEC 61850-9-2 */
#define Q_DERIVED			(1U << 13)

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

#include "packet-sv-hf.c"

/* Initialize the subtree pointers */
static int ett_sv = -1;
static int ett_phsmeas = -1;
static int ett_phsmeas_q = -1;

#include "packet-sv-ett.c"

static expert_field ei_sv_mal_utctime = EI_INIT;
static expert_field ei_sv_zero_pdu = EI_INIT;

static gboolean sv_decode_data_as_phsmeas = FALSE;

static dissector_handle_t sv_handle;

static const value_string sv_q_validity_vals[] = {
	{ 0, "good" },
	{ 1, "invalid" },
	{ 3, "questionable" },
	{ 0, NULL }
};

static const value_string sv_q_source_vals[] = {
	{ 0, "process" },
	{ 1, "substituted" },
	{ 0, NULL }
};

static int
dissect_PhsMeas1(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, int hf_id _U_)
{
	gint8 ber_class;
	gboolean pc;
	gint32 tag;
	guint32 len;
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
		offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &ber_class, &pc, &tag);
		offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, NULL);
	} else {
		len=tvb_reported_length_remaining(tvb, offset);
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

#include "packet-sv-fn.c"

/*
* Dissect SV PDUs inside a PPDU.
*/
static int
dissect_sv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
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
	proto_tree_add_item(tree, hf_sv_appid, tvb, offset, 2, ENC_BIG_ENDIAN);

	/* Length */
	proto_tree_add_item(tree, hf_sv_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

	/* Reserved 1 */
	proto_tree_add_item(tree, hf_sv_reserve1, tvb, offset + 4, 2, ENC_BIG_ENDIAN);

	/* Reserved 2 */
	proto_tree_add_item(tree, hf_sv_reserve2, tvb, offset + 6, 2, ENC_BIG_ENDIAN);

	offset = 8;
	while (tvb_reported_length_remaining(tvb, offset) > 0){
		old_offset = offset;
		offset = dissect_sv_SampledValues(FALSE, tvb, offset, &asn1_ctx , tree, -1);
		if (offset == old_offset) {
			proto_tree_add_expert(tree, pinfo, &ei_sv_zero_pdu, tvb, offset, -1);
			break;
		}
	}

	tap_queue_packet(sv_tap, pinfo, &sv_data);
	return tvb_captured_length(tvb);
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


#include "packet-sv-hfarr.c"
	};

	/* List of subtrees */
	static gint *ett[] = {
		&ett_sv,
		&ett_phsmeas,
		&ett_phsmeas_q,
#include "packet-sv-ettarr.c"
	};

	static ei_register_info ei[] = {
		{ &ei_sv_mal_utctime, { "sv.malformed.utctime", PI_MALFORMED, PI_WARN, "BER Error: malformed UTCTime encoding", EXPFILL }},
		{ &ei_sv_zero_pdu, { "sv.zero_pdu", PI_PROTOCOL, PI_ERROR, "Internal error, zero-byte SV PDU", EXPFILL }},
	};

	expert_module_t* expert_sv;
	module_t *sv_module;

	/* Register protocol */
	proto_sv = proto_register_protocol(PNAME, PSNAME, PFNAME);
	sv_handle = register_dissector("sv", dissect_sv, proto_sv);

	/* Register fields and subtrees */
	proto_register_field_array(proto_sv, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_sv = expert_register_protocol(proto_sv);
	expert_register_field_array(expert_sv, ei, array_length(ei));
	sv_module = prefs_register_protocol(proto_sv, NULL);
	prefs_register_bool_preference(sv_module, "decode_data_as_phsmeas",
		"Force decoding of seqData as PhsMeas",
		NULL, &sv_decode_data_as_phsmeas);

	/* Register tap */
	sv_tap = register_tap("sv");
}

/*--- proto_reg_handoff_sv --- */
void proto_reg_handoff_sv(void) {
	dissector_add_uint("ethertype", ETHERTYPE_IEC61850_SV, sv_handle);
}

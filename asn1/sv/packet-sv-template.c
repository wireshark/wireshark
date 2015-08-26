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

#include "packet-sv-hf.c"

/* Initialize the subtree pointers */
static int ett_sv = -1;
static int ett_phsmeas = -1;
static int ett_phsmeas_q = -1;

#include "packet-sv-ett.c"

static expert_field ei_sv_mal_utctime = EI_INIT;
static expert_field ei_sv_zero_pdu = EI_INIT;

#include "packet-sv-fn.c"

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

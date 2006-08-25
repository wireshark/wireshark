/* packet-mp2t.c
 *
 * Routines for RFC 2250 MPEG2 (ISO/IEC 13818-1) Transport Stream dissection
 *
 * $Id:$
 *
 * Copyright 2006, Erwin Rol <erwin@erwinrol.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <stdio.h>
#include <string.h>

#include <epan/rtp_pt.h>

/* The MPEG2 TS packet size */
#define MP2T_PACKET_SIZE 188

static int proto_mp2t = -1;
static gint ett_mp2t = -1;

static int hf_mp2t_header = -1;
static int hf_mp2t_sync_byte = -1;
static int hf_mp2t_tei = -1;
static int hf_mp2t_pusi = -1;
static int hf_mp2t_tp = -1;
static int hf_mp2t_pid = -1;
static int hf_mp2t_tsc = -1;
static int hf_mp2t_afc = -1;
static int hf_mp2t_cc = -1;

#define MP2T_SYNC_BYTE_MASK	0xFF000000
#define MP2T_TEI_MASK		0x00800000
#define MP2T_PUSI_MASK		0x00400000
#define MP2T_TP_MASK		0x00200000
#define MP2T_PID_MASK		0x001FFF00
#define MP2T_TSC_MASK		0x000000C0
#define MP2T_AFC_MASK		0x00000030
#define MP2T_CC_MASK		0x0000000F

#define MP2T_SYNC_BYTE_SHIFT	24
#define MP2T_TEI_SHIFT		23
#define MP2T_PUSI_SHIFT		22
#define MP2T_TP_SHIFT		21
#define MP2T_PID_SHIFT		8
#define MP2T_TSC_SHIFT		6
#define MP2T_AFC_SHIFT		4
#define MP2T_CC_SHIFT		0

static int hf_mp2t_af = -1;
static int hf_mp2t_af_length = -1;
static int hf_mp2t_af_di = -1;
static int hf_mp2t_af_rai = -1;
static int hf_mp2t_af_espi = -1;
static int hf_mp2t_af_pcr_flag = -1;
static int hf_mp2t_af_opcr_flag = -1;
static int hf_mp2t_af_sp_flag = -1;
static int hf_mp2t_af_tpd_flag = -1;
static int hf_mp2t_af_afe_flag = -1;

#define MP2T_AF_DI_MASK 	0x80
#define MP2T_AF_RAI_MASK	0x40
#define MP2T_AF_ESPI_MASK	0x20
#define MP2T_AF_PCR_MASK	0x10
#define MP2T_AF_OPCR_MASK	0x08
#define MP2T_AF_SP_MASK		0x04
#define MP2T_AF_TPD_MASK	0x02
#define MP2T_AF_AFE_MASK	0x01

#define MP2T_AF_DI_SHIFT 	7
#define MP2T_AF_RAI_SHIFT	6
#define MP2T_AF_ESPI_SHIFT	5
#define MP2T_AF_PCR_SHIFT	4
#define MP2T_AF_OPCR_SHIFT	3
#define MP2T_AF_SP_SHIFT	2
#define MP2T_AF_TPD_SHIFT	1
#define MP2T_AF_AFE_SHIFT	0

static int hf_mp2t_af_pcr = -1;
static int hf_mp2t_af_opcr = -1;

static int hf_mp2t_af_sc = -1;

static int hf_mp2t_af_tpd_length = -1;
static int hf_mp2t_af_tpd = -1;

static int hf_mp2t_af_e_length = -1;
static int hf_mp2t_af_e_ltw_flag = -1;
static int hf_mp2t_af_e_pr_flag = -1;
static int hf_mp2t_af_e_ss_flag = -1;
static int hf_mp2t_af_e_reserved = -1;

#define MP2T_AF_E_LTW_FLAG_MASK	0x80 
#define MP2T_AF_E_PR_FLAG_MASK	0x40
#define MP2T_AF_E_SS_FLAG_MASK	0x20

static int hf_mp2t_af_e_reserved_bytes = -1;
static int hf_mp2t_af_stuffing_bytes = -1;

static int hf_mp2t_af_e_ltwv_flag = -1;
static int hf_mp2t_af_e_ltwo = -1;

static int hf_mp2t_af_e_pr_reserved = -1;
static int hf_mp2t_af_e_pr = -1;

static int hf_mp2t_af_e_st = -1;
static int hf_mp2t_af_e_dnau_32_30 = -1;
static int hf_mp2t_af_e_m_1 = -1;
static int hf_mp2t_af_e_dnau_29_15 = -1;
static int hf_mp2t_af_e_m_2 = -1;
static int hf_mp2t_af_e_dnau_14_0 = -1;
static int hf_mp2t_af_e_m_3 = -1;

static int hf_mp2t_payload = -1;

static const value_string mp2t_sync_byte_vals[] = {
	{ 0x47, "Correct" },
	{ 0, NULL},
};


static const value_string mp2t_pid_vals[] = {
	{ 0x0000, "Program Association Table" },
	{ 0x0001, "Conditional Access Table" },
	{ 0x0002, "Transport Stream Description Table" },
	{ 0x0003, "Reserved" },
	{ 0x0004, "Reserved" },
	{ 0x0005, "Reserved" },
	{ 0x0006, "Reserved" },
	{ 0x0007, "Reserved" },
	{ 0x0008, "Reserved" },
	{ 0x0009, "Reserved" },
	{ 0x000A, "Reserved" },
	{ 0x000B, "Reserved" },
	{ 0x000C, "Reserved" },
	{ 0x000D, "Reserved" },
	{ 0x000E, "Reserved" },
	{ 0x000F, "Reserved" },
	{ 0x1FFF, "Null packet" },
	{ 0, NULL },
};

static const value_string mp2t_tsc_vals[] = {
	{ 0, "Not scrambled" },
	{ 1, "User-defined" },
	{ 2, "User-defined" },
	{ 3, "User-defined" },
	{ 0, NULL },
};

static const value_string mp2t_afc_vals[] = {
	{ 0, "Reserved" },
	{ 1, "Payload only" },
	{ 2, "Adaptation Field only" },
	{ 3, "Adaptation Field and Payload" },
	{ 0, NULL },
};

static gint
dissect_tsp( tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree ) 
{
	guint32 header;
	guint afc;
	gint start_offset = offset;

	proto_item *ti = NULL;
	proto_item *hi = NULL;
	proto_tree *mp2t_tree = NULL;
	proto_tree *mp2t_header_tree = NULL;
	proto_tree *mp2t_af_tree = NULL;

	ti = proto_tree_add_item( tree, proto_mp2t, tvb, offset, MP2T_PACKET_SIZE, FALSE );
	mp2t_tree = proto_item_add_subtree( ti, ett_mp2t );
	
	header = tvb_get_ntohl(tvb, offset);

	proto_item_append_text(ti, " PID=0x%x CC=%d", (header & MP2T_PID_MASK) >> MP2T_PID_SHIFT, (header & MP2T_CC_MASK) >> MP2T_CC_SHIFT );


	hi = proto_tree_add_item( mp2t_tree, hf_mp2t_header, tvb, offset, 4, FALSE);
	mp2t_header_tree = proto_item_add_subtree( hi, ett_mp2t );

	proto_tree_add_item( mp2t_header_tree, hf_mp2t_sync_byte, tvb, offset, 4, FALSE);
	proto_tree_add_item( mp2t_header_tree, hf_mp2t_tei, tvb, offset, 4, FALSE);
	proto_tree_add_item( mp2t_header_tree, hf_mp2t_pusi, tvb, offset, 4, FALSE);
	proto_tree_add_item( mp2t_header_tree, hf_mp2t_tp, tvb, offset, 4, FALSE);
	proto_tree_add_item( mp2t_header_tree, hf_mp2t_pid, tvb, offset, 4, FALSE);
	proto_tree_add_item( mp2t_header_tree, hf_mp2t_tsc, tvb, offset, 4, FALSE);
	proto_tree_add_item( mp2t_header_tree, hf_mp2t_afc, tvb, offset, 4, FALSE);
	proto_tree_add_item( mp2t_header_tree, hf_mp2t_cc, tvb, offset, 4, FALSE);
	offset += 4;

	afc = (header & MP2T_AFC_MASK) >> MP2T_AFC_SHIFT;

	if (afc == 2 || afc == 3) 
	{
		gint af_start_offset = offset;
	
		guint8 af_length;
		guint8 af_flags;
		gint stuffing_len;


		af_length = tvb_get_guint8(tvb, offset);

		proto_tree_add_item( mp2t_tree, hf_mp2t_af_length, tvb, offset, 1, FALSE);
		offset += 1;

		hi = proto_tree_add_item( mp2t_tree, hf_mp2t_af, tvb, offset, af_length, FALSE);
		mp2t_af_tree = proto_item_add_subtree( hi, ett_mp2t );

		af_flags = tvb_get_guint8(tvb, offset);

		proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_di, tvb, offset, 1, FALSE);
		proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_rai, tvb, offset, 1, FALSE);
		proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_espi, tvb, offset, 1, FALSE);
		proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_pcr_flag, tvb, offset, 1, FALSE);
		proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_opcr_flag, tvb, offset, 1, FALSE);
		proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_sp_flag, tvb, offset, 1, FALSE);
		proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_tpd_flag, tvb, offset, 1, FALSE);
		proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_afe_flag, tvb, offset, 1, FALSE);

		offset += 1;

		if (af_flags &  MP2T_AF_PCR_MASK) {
			guint64 pcr_base = 0;
			guint32 pcr_ext = 0;
			guint8 tmp;

			tmp = tvb_get_guint8(tvb, offset);
			pcr_base = (pcr_base << 8) | tmp;
			offset += 1;
			
			tmp = tvb_get_guint8(tvb, offset);
			pcr_base = (pcr_base << 8) | tmp;
			offset += 1;
			
			tmp = tvb_get_guint8(tvb, offset);
			pcr_base = (pcr_base << 8) | tmp;
			offset += 1;
	
			tmp = tvb_get_guint8(tvb, offset);
			pcr_base = (pcr_base << 8) | tmp;
			offset += 1;

			tmp = tvb_get_guint8(tvb, offset);
			pcr_base = (pcr_base << 1) | ((tmp >> 7) & 0x01);
			pcr_ext = (tmp & 0x01);
			offset += 1;

			tmp = tvb_get_guint8(tvb, offset);
			pcr_ext = (pcr_ext << 8) | tmp;
			offset += 1;

			proto_tree_add_none_format(mp2t_af_tree, hf_mp2t_af_pcr, tvb, offset - 6, 6, 
						"Program Clock Reference: base(%ld) * 300 + ext(%d) = %ld", 
						pcr_base, pcr_ext, pcr_base * 300 + pcr_ext);
		}

		if (af_flags &  MP2T_AF_OPCR_MASK) {
			guint64 opcr_base = 0;
			guint32 opcr_ext = 0;
			guint8 tmp = 0;

			tmp = tvb_get_guint8(tvb, offset);
			opcr_base = (opcr_base << 8) | tmp;
			offset += 1;
			
			tmp = tvb_get_guint8(tvb, offset);
			opcr_base = (opcr_base << 8) | tmp;
			offset += 1;
			
			tmp = tvb_get_guint8(tvb, offset);
			opcr_base = (opcr_base << 8) | tmp;
			offset += 1;
	
			tmp = tvb_get_guint8(tvb, offset);
			opcr_base = (opcr_base << 8) | tmp;
			offset += 1;

			tmp = tvb_get_guint8(tvb, offset);
			opcr_base = (opcr_base << 1) | ((tmp >> 7) & 0x01);
			opcr_ext = (tmp & 0x01);
			offset += 1;

			tmp = tvb_get_guint8(tvb, offset);
			opcr_ext = (opcr_ext << 8) | tmp;
			offset += 1;

			proto_tree_add_none_format(mp2t_af_tree, hf_mp2t_af_opcr, tvb, offset - 6, 6, 
						"Original Program Clock Reference: base(%ld) * 300 + ext(%d) = %ld", 
						opcr_base, opcr_ext, opcr_base * 300 + opcr_ext);
	
			offset += 6;
		}

		if (af_flags &  MP2T_AF_SP_MASK) {
			proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_sc, tvb, offset, 1, FALSE);
			offset += 1;
		}

		if (af_flags &  MP2T_AF_TPD_MASK) {
			guint8 tpd_len;
		
			tpd_len = tvb_get_guint8(tvb, offset);
			proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_tpd_length, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_tpd, tvb, offset, tpd_len, FALSE);
			offset += tpd_len;
		}

		if (af_flags &  MP2T_AF_AFE_MASK) {
			guint8 e_len;
			guint8 e_flags;
			gint e_start_offset = offset;
			gint reserved_len = 0;

			e_len = tvb_get_guint8(tvb, offset);
			proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_length, tvb, offset, 1, FALSE);
			offset += 1;

			e_flags = tvb_get_guint8(tvb, offset);
			proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_ltw_flag, tvb, offset, 1, FALSE);
			proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_pr_flag, tvb, offset, 1, FALSE);
			proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_ss_flag, tvb, offset, 1, FALSE);
			proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_reserved, tvb, offset, 1, FALSE);			
			offset += 1;
			
			if (e_flags & MP2T_AF_E_LTW_FLAG_MASK) {
				proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_ltwv_flag, tvb, offset, 2, FALSE);
				proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_ltwo, tvb, offset, 2, FALSE);
				offset += 2;
			}

			if (e_flags & MP2T_AF_E_PR_FLAG_MASK) {
				proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_pr_reserved, tvb, offset, 3, FALSE);
				proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_pr, tvb, offset, 3, FALSE);
				offset += 3;
			}

			if (e_flags & MP2T_AF_E_SS_FLAG_MASK) {
				proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_st, tvb, offset, 1, FALSE);
				proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_dnau_32_30, tvb, offset, 1, FALSE);
				proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_m_1, tvb, offset, 1, FALSE);
				offset += 1;
				proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_dnau_29_15, tvb, offset, 2, FALSE);
				proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_m_2, tvb, offset, 2, FALSE);
				offset += 2;
				proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_dnau_14_0, tvb, offset, 2, FALSE);
				proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_m_3, tvb, offset, 2, FALSE);
				offset += 2;
			}

			reserved_len = (e_len + 1) - (offset - e_start_offset);
			if (reserved_len > 0) {
				proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_reserved_bytes, tvb, offset, reserved_len, FALSE);
				offset += reserved_len;
			}
		}

		stuffing_len = (af_length + 1) - (offset - af_start_offset);
		if (stuffing_len > 0) {
			proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_stuffing_bytes, tvb, offset, stuffing_len, FALSE);
			offset += stuffing_len;
		}
	}

	if (afc == 0 || afc == 1) {
		gint payload_len;

		payload_len = MP2T_PACKET_SIZE - (offset - start_offset);
		if (payload_len > 0) {
			proto_tree_add_item( mp2t_tree, hf_mp2t_payload, tvb, offset, payload_len, FALSE);
			offset += payload_len;
		}
	}

	return offset;
}


static void
dissect_mp2t( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
	guint offset = 0;

	if (tree) {
		while ( tvb_reported_length_remaining(tvb, offset) >= MP2T_PACKET_SIZE ) {
			offset = dissect_tsp( tvb, offset, pinfo, tree);
		}
	}
}

void
proto_register_mp2t(void)
{
	static hf_register_info hf[] = { 
		{ &hf_mp2t_header, {
			"Header", "mp2t.header",
			FT_UINT32, BASE_HEX, NULL, 0, "", HFILL
		} } ,
		{ &hf_mp2t_sync_byte, {
			"Sync Byte", "mp2t.sync_byte",
			FT_UINT32, BASE_HEX, VALS(mp2t_sync_byte_vals), MP2T_SYNC_BYTE_MASK, "", HFILL
		} } ,
		{ &hf_mp2t_tei, { 
			"Transport Error Indicator", "mp2t.tei",
			FT_UINT32, BASE_DEC, NULL, MP2T_TEI_MASK, "", HFILL
		} } ,
		{ &hf_mp2t_pusi, {
			"Payload Unit Start Indicator", "mp2s.pusi",
			FT_UINT32, BASE_DEC, NULL, MP2T_PUSI_MASK, "", HFILL
		} } ,
		{ &hf_mp2t_tp, {
			"Transport Priority", "mp2t.tp",
			FT_UINT32, BASE_DEC, NULL, MP2T_TP_MASK, "", HFILL
		} } ,
		{ &hf_mp2t_pid, {
			"PID", "mp2s.pid",
			FT_UINT32, BASE_HEX, VALS(mp2t_pid_vals), MP2T_PID_MASK, "", HFILL
		} } ,
		{ &hf_mp2t_tsc, {
			"Transport Scrambling Control", "mp2t.tsc",
			FT_UINT32, BASE_HEX, VALS(mp2t_tsc_vals), MP2T_TSC_MASK, "", HFILL
		} } ,
		{ &hf_mp2t_afc, {
			"Adaption Field Control", "mp2t.afc",
			FT_UINT32, BASE_HEX, VALS(mp2t_afc_vals) , MP2T_AFC_MASK, "", HFILL
		} } ,
		{ &hf_mp2t_cc, {
			"Continuity Counter", "mp2t.cc",
			FT_UINT32, BASE_DEC, NULL, MP2T_CC_MASK, "", HFILL
		} } ,
		{ &hf_mp2t_af, {
			"Adaption field", "mp2t.af",
			FT_NONE, BASE_HEX, NULL, 0, "", HFILL
		} } ,
		{ &hf_mp2t_af_length, {
			"Adaptation Field Length", "mp2t.af.length",
			FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL
		} } ,
		{ &hf_mp2t_af_di, {
			"Discontinuity Indicator", "mp2t.af.di",
			FT_UINT8, BASE_DEC, NULL, MP2T_AF_DI_MASK, "", HFILL
		} } ,
		{ &hf_mp2t_af_rai, {
			"Random Access Indicator", "mp2t.af.rai",
			FT_UINT8, BASE_DEC, NULL, MP2T_AF_RAI_MASK, "", HFILL
		} } ,
		{ &hf_mp2t_af_espi, {
			"Elementary Stream Priority Indicator", "mp2t.af.espi",
			FT_UINT8, BASE_DEC, NULL, MP2T_AF_ESPI_MASK, "", HFILL
		} } ,
		{ &hf_mp2t_af_pcr_flag, {
			"PCR Flag", "mp2t.af.pcr_flag",
			FT_UINT8, BASE_DEC, NULL, MP2T_AF_PCR_MASK, "", HFILL
		} } ,
		{ &hf_mp2t_af_opcr_flag, {
			"OPCR Flag", "mp2t.af.opcr_flag",
			FT_UINT8, BASE_DEC, NULL, MP2T_AF_OPCR_MASK, "", HFILL
		} } ,
		{ &hf_mp2t_af_sp_flag, {
			"Splicing Point Flag", "mp2t.af.sp_flag",
			FT_UINT8, BASE_DEC, NULL, MP2T_AF_SP_MASK, "", HFILL
		} } ,
		{ &hf_mp2t_af_tpd_flag, {
			"Transport Private Data Flag", "mp2t.af.tpd_flag",
			FT_UINT8, BASE_DEC, NULL, MP2T_AF_TPD_MASK, "", HFILL
		} } ,
		{ &hf_mp2t_af_afe_flag, {
			"Adaptation Field Extension Flag", "mp2t.af.afe_flag",
			FT_UINT8, BASE_DEC, NULL, MP2T_AF_AFE_MASK, "", HFILL
		} } ,
		{ &hf_mp2t_af_pcr, {
			"Program Clock Reference", "mp2t.af.pcr",
			FT_NONE, BASE_DEC, NULL, 0, "", HFILL
		} } ,
		{ &hf_mp2t_af_opcr, {
			"Original Program Clock Reference", "mp2t.af.opcr",
			FT_NONE, BASE_DEC, NULL, 0, "", HFILL
		} } ,
		{ &hf_mp2t_af_sc, {
			"Splice Countdown", "mp2t.af.sc",
			FT_UINT8, BASE_DEC, NULL, 0, "", HFILL
		} } ,
		{ &hf_mp2t_af_tpd_length, {
			"Transport Private Data Length", "mp2t.af.tpd_length",
			FT_UINT8, BASE_DEC, NULL, 0, "", HFILL
		} } ,
		{ &hf_mp2t_af_tpd, {
			"Transport Private Data", "mp2t.af.tpd",
			FT_BYTES, BASE_DEC, NULL, 0, "", HFILL
		} } ,
		{ &hf_mp2t_af_e_length, {
			"Adaptation Field Extension Length", "mp2t.af.e_length",
			FT_UINT8, BASE_DEC, NULL, 0, "", HFILL
		} } ,
		{ &hf_mp2t_af_e_ltw_flag, {
			"LTW Flag", "mp2t.af.e.ltw_flag",
			FT_UINT8, BASE_DEC, NULL, MP2T_AF_E_LTW_FLAG_MASK, "", HFILL
		} } ,
		{ &hf_mp2t_af_e_pr_flag, {
			"Piecewise Rate Flag", "mp2t.af.e.pr_flag",
			FT_UINT8, BASE_DEC, NULL, MP2T_AF_E_PR_FLAG_MASK, "", HFILL
		} } ,
		{ &hf_mp2t_af_e_ss_flag, {
			"Seamless Splice Flag", "mp2t.af.e.ss_flag",
			FT_UINT8, BASE_DEC, NULL, MP2T_AF_E_SS_FLAG_MASK, "", HFILL
		} } ,
		{ &hf_mp2t_af_e_reserved, {
			"Reserved", "mp2t.af.e.reserved",
			FT_UINT8, BASE_DEC, NULL, 0x1F, "", HFILL
		} } ,
		{ &hf_mp2t_af_e_reserved_bytes, {
			"Reserved", "mp2t.af.e.reserved_bytes",
			FT_BYTES, BASE_DEC, NULL, 0x0, "", HFILL
		} } ,
		{ &hf_mp2t_af_stuffing_bytes, {
			"Stuffing", "mp2t.af.stuffing_bytes",
			FT_BYTES, BASE_DEC, NULL, 0x0, "", HFILL
		} } ,
		{ &hf_mp2t_af_e_ltwv_flag, {
			"LTW Valid Flag", "mp2t.af.e.ltwv_flag",
			FT_UINT16, BASE_DEC, NULL, 0x8000, "", HFILL
		} } ,
		{ &hf_mp2t_af_e_ltwo, {
			"LTW Offset", "mp2t.af.e.ltwo",
			FT_UINT16, BASE_DEC, NULL, 0x7FFF, "", HFILL
		} } ,
		{ &hf_mp2t_af_e_pr_reserved, {
			"Reserved", "mp2t.af.e.pr_reserved",
			FT_UINT24, BASE_DEC, NULL, 0xC00000, "", HFILL
		} } ,
		{ &hf_mp2t_af_e_pr, {
			"Piecewise Rate", "mp2t.af.e.pr",
			FT_UINT24, BASE_DEC, NULL, 0x3FFFFF, "", HFILL
		} } ,
		{ &hf_mp2t_af_e_st, {
			"Splice Type", "mp2t.af.e.st",
			FT_UINT8, BASE_DEC, NULL, 0xF0, "", HFILL
		} } ,
		{ &hf_mp2t_af_e_dnau_32_30, {
			"DTS Next AU[32...30]", "mp2t.af.e.dnau_32_30",
			FT_UINT8, BASE_DEC, NULL, 0x0E, "", HFILL
		} } ,
		{ &hf_mp2t_af_e_m_1, {
			"Marker Bit", "mp2t.af.e.m_1",
			FT_UINT8, BASE_DEC, NULL, 0x01, "", HFILL
		} } ,
		{ &hf_mp2t_af_e_dnau_29_15, {
			"DTS Next AU[29...15]", "mp2t.af.e.dnau_29_15",
			FT_UINT16, BASE_DEC, NULL, 0xFFFE, "", HFILL
		} } ,
		{ &hf_mp2t_af_e_m_2, {
			"Marker Bit", "mp2t.af.e.m_2",
			FT_UINT16, BASE_DEC, NULL, 0x0001, "", HFILL
		} } ,
		{ &hf_mp2t_af_e_dnau_14_0, {
			"DTS Next AU[14...0]", "mp2t.af.e.dnau_14_0",
			FT_UINT16, BASE_DEC, NULL, 0xFFFE, "", HFILL
		} } ,
		{ &hf_mp2t_af_e_m_3, {
			"Marker Bit", "mp2t.af.e.m_3",
			FT_UINT16, BASE_DEC, NULL, 0x0001, "", HFILL
		} } ,
		{ &hf_mp2t_payload, {
			"Payload", "mp2t.payload",
			FT_BYTES, BASE_DEC, NULL, 0x0, "", HFILL
		} } ,
	};

	static gint *ett[] =
	{
		&ett_mp2t,
	};

	proto_mp2t = proto_register_protocol("ISO/IEC 13818-1", "MP2T", "mp2t");
	proto_register_field_array(proto_mp2t, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}



void
proto_reg_handoff_mp2t(void)
{
	dissector_handle_t mp2t_handle;

	mp2t_handle = create_dissector_handle(dissect_mp2t, proto_mp2t);
	dissector_add("rtp.pt", PT_MP2T, mp2t_handle);
}


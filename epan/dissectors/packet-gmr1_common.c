/* packet-gmr1_common.c
 *
 * Routines for GMR-1 dissection in wireshark (common stuff).
 * Copyright (c) 2011 Sylvain Munaut <tnt@246tNt.com>
 *
 * References:
 *  [1] ETSI TS 101 376-4-8 V1.3.1 - GMR-1 04.008
 *  [2] ETSI TS 101 376-4-8 V2.2.1 - GMPRS-1 04.008
 *  [3] ETSI TS 101 376-4-8 V3.1.1 - GMR-1 3G 44.008
 *  [4] ETSI TS 100 940 V7.21.0 - GSM 04.08
 *  [5] ETSI TS 101 376-4-12 V3.2.1 - GMR-1 3G 44.060
 *  [6] ETSI TS 101 376-5-6 V1.3.1 - GMR-1 05.008
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

#include "packet-gmr1_common.h"

#include "packet-gmr1_rr.h"

void proto_register_gmr1_common(void);

/* GMR-1 Common proto */
static int proto_gmr1_common = -1;


/* ------------------------------------------------------------------------ */
/* Protocol descriptor (see [1] 11.2 & [4] 10.2)                            */
/* ------------------------------------------------------------------------ */

const value_string gmr1_pd_vals[] = {
	{ GMR1_PD_CC,	"Call Control; call related SS messages" },
	{ GMR1_PD_MM,	"Mobility Management messages" },
	{ GMR1_PD_RR,	"Radio Resource management messages" },
	{ GMR1_PD_GMM,	"GPRS Mobility Management messages" },
	{ GMR1_PD_SM,	"Session Management messages" },
	{ GMR1_PD_DTRS,	"DTMF transmission and reception service" },
	{ 0, NULL }
};

const value_string gmr1_pd_short_vals[] = {
	{ GMR1_PD_CC,	"CC" },   /* Call Control; call related SS messages */
	{ GMR1_PD_MM,	"MM" },   /* Mobility Management messages */
	{ GMR1_PD_RR,	"RR" },   /* Radio Resource management messages */
	{ GMR1_PD_GMM,	"GMM" },  /* GPRS Mobility Management messages */
	{ GMR1_PD_SM,	"SM" },   /* Session Management messages */
	{ GMR1_PD_DTRS,	"DTRS" }, /* DTMF transmission and reception service */
	{ 0, NULL}
};


/* ------------------------------------------------------------------------ */
/* Common Information Elements                                              */
/* ------------------------------------------------------------------------ */

static const value_string gmr1_ie_common_strings[] = {
	{ GMR1_IE_COM_CM2,
	  "Mobile Earth Station Classmark 2" },		/* [1] 11.5.1.6 */
	{ GMR1_IE_COM_SPARE_NIBBLE,
	  "Spare Half Octet" },				/* [1] 11.5.1.8 */
	{ 0, NULL}
};
value_string_ext gmr1_ie_common_strings_ext = VALUE_STRING_EXT_INIT(gmr1_ie_common_strings);

gint ett_gmr1_ie_common[NUM_GMR1_IE_COMMON];

/* Fields */
int hf_gmr1_skip_ind = -1;
int hf_gmr1_l3_pd = -1;
int hf_gmr1_elem_id = -1;
int hf_gmr1_len = -1;

static int hf_com_cm2_spare1 = -1;
static int hf_com_cm2_revision = -1;
static int hf_com_cm2_early_send = -1;
static int hf_com_cm2_a5_1 = -1;
static int hf_com_cm2_mes_type = -1;
static int hf_com_cm2_spare2 = -1;
static int hf_com_cm2_ss_screen_ind = -1;
static int hf_com_cm2_sms_cap = -1;
static int hf_com_cm2_spare3 = -1;
static int hf_com_cm2_freq_cap = -1;
static int hf_com_cm2_cm3_presence = -1;
static int hf_com_cm2_spare4 = -1;
static int hf_com_cm2_a5_3 = -1;
static int hf_com_cm2_a5_2_gmr1 = -1;
static int hf_com_spare_nibble = -1;

/* [1] 11.5.1.6 - Mobile Earth Station Classmark 2 */
static const value_string com_cm2_revision_vals[] = {
	{ 0, "Reserved for Phase 1" },
	{ 1, "Phase 2 MESs" },
	{ 2, "Reserved" },
	{ 3, "Reserved" },
	{ 0, NULL }
};

static const value_string com_cm2_early_send_vals[] = {
	{ 0, "\"Controlled Early Classmark Sending\" option is not implemented" },
	{ 1, "\"Controlled Early Classmark Sending\" option is implemented" },
	{ 0, NULL }
};

static const value_string com_cm2_a5_1_vals[] = {
	{ 0, "Encryption algorithm A5/1 available" },
	{ 1, "Encryption algorithm A5/1 not available" },
	{ 0, NULL }
};

static const value_string com_cm2_mes_type_vals[] = {
	{ 0, "Class 1 Reserved" },
	{ 1, "Class 2 Used by all fixed GMR-1 terminals" },
	{ 2, "Class 3 Used by all vehicular GMR-1 terminals" },
	{ 3, "Class 4 Used by all handheld GMR-1 terminals" },
	{ 0, NULL }
};

static const value_string com_cm2_ss_screen_ind_vals[] = {
	{ 0, "Defined in GSM 04.80 [29]" },
	{ 1, "Defined in GSM 04.80 [29]" },
	{ 2, "Defined in GSM 04.80 [29]" },
	{ 3, "Defined in GSM 04.80 [29]" },
	{ 0, NULL }
};

static const value_string com_cm2_sms_cap_vals[] = {
	{ 0, "MES does not support mobile terminated point-to-point SMS" },
	{ 1, "MES supports mobile terminated point-to-point SMS" },
	{ 0, NULL }
};

static const value_string com_cm2_freq_cap_vals[] = {
	{ 0, "Not used in GMR-1" },
	{ 1, "Not used in GMR-1" },
	{ 0, NULL }
};

static const value_string com_cm3_presence_vals[] = {
	{ 0, "No additional MES capability information available" },
	{ 1, "Additional MES capabilities are described in the Classmark 3 IE" },
	{ 0, NULL }
};

static const value_string com_cm2_a5_3_vals[] = {
	{ 0, "Encryption algorithm A5/3 not available" },
	{ 1, "Encryption algorithm A5/3 available" },
	{ 0, NULL }
};

static const value_string com_cm2_a5_2_gmr1_vals[] = {
	{ 0, "Encryption algorithm GMR-1 A5/2 not available" },
	{ 1, "Encryption algorithm GMR-1 A5/2 available" },
	{ 0, NULL }
};

GMR1_IE_FUNC(gmr1_ie_com_cm2)
{
	proto_tree_add_item(tree, hf_com_cm2_spare1,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(tree, hf_com_cm2_revision,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(tree, hf_com_cm2_early_send,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(tree, hf_com_cm2_a5_1,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(tree, hf_com_cm2_mes_type,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	offset++;

	proto_tree_add_item(tree, hf_com_cm2_spare2,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(tree, hf_com_cm2_ss_screen_ind,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(tree, hf_com_cm2_sms_cap,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(tree, hf_com_cm2_spare3,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(tree, hf_com_cm2_freq_cap,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	offset++;

	proto_tree_add_item(tree, hf_com_cm2_cm3_presence,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(tree, hf_com_cm2_spare4,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(tree, hf_com_cm2_a5_3,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(tree, hf_com_cm2_a5_2_gmr1,
	                    tvb, offset, 1, ENC_BIG_ENDIAN);

	offset++;

	return 3;
}

/* [1] 11.5.1.8 - Spare Half Octet */
GMR1_IE_FUNC(gmr1_ie_com_spare_nibble)
{
	proto_tree_add_item(tree, hf_com_spare_nibble, tvb, offset, 1, ENC_BIG_ENDIAN);

	return 1;
}

elem_fcn gmr1_ie_common_func[NUM_GMR1_IE_COMMON] = {
	gmr1_ie_com_cm2,			/* MES Classmark 2 */
	gmr1_ie_com_spare_nibble,		/* Spare Half Octet */
};


/* ------------------------------------------------------------------------ */
/* Messages and IEs parsing                                                 */
/* ------------------------------------------------------------------------ */

void
gmr1_get_msg_params(gmr1_pd_e pd, guint8 oct, const gchar **msg_str,
		    int *ett_tree, int *hf_idx, gmr1_msg_func_t *msg_func_p)
{
	switch (pd) {
	case GMR1_PD_RR:
		gmr1_get_msg_rr_params(oct, 1, msg_str, ett_tree, hf_idx, msg_func_p);
		break;

	default:
		*msg_str = NULL;
		*ett_tree = -1;
		*hf_idx = -1;
		*msg_func_p = NULL;
	}
}


/* ------------------------------------------------------------------------ */
/* Register code                                                            */
/* ------------------------------------------------------------------------ */

void
proto_register_gmr1_common(void)
{
	static hf_register_info hf[] = {
		{ &hf_gmr1_skip_ind,
		  { "Skip Indicator", "gmr1.skip_ind",
		    FT_UINT8, BASE_DEC, NULL, 0xf0,
		    NULL, HFILL }
		},
		{ &hf_gmr1_l3_pd,
		  { "Protocol discriminator","gmr1.l3_protocol_discriminator",
		    FT_UINT8, BASE_DEC, VALS(gmr1_pd_vals), 0x0f,
		    NULL, HFILL }
		},
		{ &hf_gmr1_elem_id,
		  { "Element ID", "gmr1.ie.elem_id",
		    FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_gmr1_len,
		  { "Length", "gmr1.ie.length",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_com_cm2_spare1,
		  { "Spare", "gmr1.common.cm2.spare1",
		    FT_UINT8, BASE_DEC, NULL, 0x80,
		    NULL, HFILL }
		},
		{ &hf_com_cm2_revision,
		  { "Revision Level", "gmr1.common.cm2.revision",
		    FT_UINT8, BASE_DEC, VALS(com_cm2_revision_vals), 0x60,
		    NULL, HFILL }
		},
		{ &hf_com_cm2_early_send,
		  { "ES IND", "gmr1.common.cm2.early_send",
		    FT_UINT8, BASE_DEC, VALS(com_cm2_early_send_vals), 0x10,
		    NULL, HFILL }
		},
		{ &hf_com_cm2_a5_1,
		  { "A5/1", "gmr1.common.cm2.a5_1",
		    FT_UINT8, BASE_DEC, VALS(com_cm2_a5_1_vals), 0x08,
		    NULL, HFILL }
		},
		{ &hf_com_cm2_mes_type,
		  { "MES terminal type", "gmr1.common.cm2.mes_type",
		    FT_UINT8, BASE_DEC, VALS(com_cm2_mes_type_vals), 0x07,
		    NULL, HFILL }
		},
		{ &hf_com_cm2_spare2,
		  { "Spare", "gmr1.common.cm2.spare2",
		    FT_UINT8, BASE_DEC, NULL, 0xc0,
		    NULL, HFILL }
		},
		{ &hf_com_cm2_ss_screen_ind,
		  { "SS Screening Indicator", "gmr1.common.cm2.ss_screen_ind",
		    FT_UINT8, BASE_DEC, VALS(com_cm2_ss_screen_ind_vals), 0x30,
		    NULL, HFILL }
		},
		{ &hf_com_cm2_sms_cap,
		  { "SM capability", "gmr1.common.cm2.sms_cap",
		    FT_UINT8, BASE_DEC, VALS(com_cm2_sms_cap_vals), 0x08,
		    NULL, HFILL }
		},
		{ &hf_com_cm2_spare3,
		  { "Spare", "gmr1.common.cm2.spare3",
		    FT_UINT8, BASE_DEC, NULL, 0x06,
		    NULL, HFILL }
		},
		{ &hf_com_cm2_freq_cap,
		  { "FC", "gmr1.common.cm2.freq_cap",
		    FT_UINT8, BASE_DEC, VALS(com_cm2_freq_cap_vals), 0x01,
		    NULL, HFILL }
		},
		{ &hf_com_cm2_cm3_presence,
		  { "CM3", "gmr1.common.cm2.cm3_presence",
		    FT_UINT8, BASE_DEC, VALS(com_cm3_presence_vals), 0x80,
		    NULL, HFILL }
		},
		{ &hf_com_cm2_spare4,
		  { "Spare", "gmr1.common.cm2.spare4",
		    FT_UINT8, BASE_DEC, NULL, 0x7c,
		    NULL, HFILL }
		},
		{ &hf_com_cm2_a5_3,
		  { "A5/3", "gmr1.common.cm2.a5_3",
		    FT_UINT8, BASE_DEC, VALS(com_cm2_a5_3_vals), 0x02,
		    NULL, HFILL }
		},
		{ &hf_com_cm2_a5_2_gmr1,
		  { "A5/2 GMR-1", "gmr1.common.cm2.a5_2_gmr1",
		    FT_UINT8, BASE_DEC, VALS(com_cm2_a5_2_gmr1_vals), 0x01,
		    NULL, HFILL }
		},
		{ &hf_com_spare_nibble,
		  { "Spare Half Octet", "gmr1.common.spare_nibble",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
	};

	/* Register the protocol name and field description */
	proto_gmr1_common = proto_register_protocol("GEO-Mobile Radio (1) Common", "GMR-1 Common", "gmr1.common");

	proto_register_field_array(proto_gmr1_common, hf, array_length(hf));
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

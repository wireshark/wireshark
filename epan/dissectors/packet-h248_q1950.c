/*
 *  packet-h248_q1950.c
 *  Q.1950 annex A
 *
 *  (c) 2006, Anders Broman <anders.broman@ericsson.com>
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
 *
 * Ref ITU-T Rec. Q.1950 (12/2002)
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-isup.h"
#include "packet-h248.h"

void proto_reg_handoff_q1950(void);
void proto_register_q1950(void);

#define PNAME  "H.248 Q.1950 Annex A"
#define PSNAME "H248Q1950"
#define PFNAME "h248q1950"

static int proto_q1950 = -1;
static gboolean implicit = FALSE;

/* A.3 Bearer characteristics package */
static int hf_h248_pkg_BCP = -1;
static int hf_h248_pkg_BCP_BNCChar = -1;

static gint ett_h248_pkg_BCP = -1;

static const value_string h248_pkg_BCP_parameters[] _U_ = {
    {   0x0001, "BNCChar (BNC Characteristics)" },
    {0,     NULL}
};

static const value_string h248_pkg_BCP_props_vals[] = {
    {0, "Bearer Characteristics Q.1950 Annex A (bcp)" },
    {1, "BNC Characteristics (BNCChar)"},
    {0,NULL}
};

/* Properties */
h248_pkg_param_t h248_pkg_BCP_props[] = {
    { 0x0001, &hf_h248_pkg_BCP_BNCChar, h248_param_ber_integer, &implicit },
    { 0, NULL, NULL, NULL}
};

/* Packet defenitions */
static h248_package_t h248_pkg_BCP = {
    0x001e,
    &hf_h248_pkg_BCP,
    &ett_h248_pkg_BCP,
    h248_pkg_BCP_props_vals,
    NULL,
    NULL,
    NULL,
    h248_pkg_BCP_props,         /* Properties */
    NULL,                       /* signals */
    NULL,                       /* events */
    NULL                        /* statistics */
};

/* A.4 Bearer Network connection cut-through package */
static int hf_h248_pkg_BNCCT = -1;

static int hf_h248_pkg_BNCCT_prop = -1;

static gint ett_h248_pkg_BNCCT = -1;

static const value_string h248_pkg_BNCCT_parameters[] _U_ = {
    {   0x0001, "BNC Cut Through Capability" },
    { 0, NULL }
};

static const value_string h248_pkg_BNCCT_props_vals[] = {
    {0,"Bearer Network Connection Cut Q.1950 Annex A" },
    {1,"BNCCT"},
    {0,NULL}
};

static const value_string h248_pkg_BNCCT_prop_vals[]  = {
    {1,"Early"},
    {2,"Late"},
    {0,NULL}
};

/* Properties */
static const h248_pkg_param_t h248_pkg_BNCCT_props[] = {
    { 0x0001, &hf_h248_pkg_BNCCT_prop, h248_param_ber_integer, &implicit },
    { 0, NULL, NULL, NULL}
};

/* Packet defenitions */
static h248_package_t h248_pkg_BNCCT = {
    0x001f,
    &hf_h248_pkg_BNCCT,
    &ett_h248_pkg_BNCCT,
    h248_pkg_BNCCT_props_vals,
    NULL,
    NULL,
    NULL,
    h248_pkg_BNCCT_props,       /* Properties */
    NULL,                       /* signals */
    NULL,                       /* events */
    NULL                        /* statistics */
};

/* A.5 Bearer Reuse Idle Package  */
static int hf_h248_pkg_RI = -1;

static int hf_h248_pkg_RII= -1;

static gint ett_h248_pkg_RI= -1;

static const value_string h248_pkg_RI_parameters[] = {
    { 0x0000, "Reuse Idle Q.1950 Annex A" },
    { 0x0001, "Reuse Idle Indication" },
    { 0, NULL }
};

static const value_string h248_pkg_RII_vals[]  = {
    {0,"Not_Reuse_Idle"},
    {1,"ReUse_Idle"},
    {0,NULL}
};

/* Properties */
h248_pkg_param_t h248_pkg_RI_props[] = {
    { 0x0001, &hf_h248_pkg_RII, h248_param_ber_integer, &implicit },
    { 0, NULL, NULL, NULL}
};

/* Packet defenitions */
static h248_package_t h248_pkg_RI = {
    0x0020,
    &hf_h248_pkg_RI,
    &ett_h248_pkg_RI,
    h248_pkg_RI_parameters,
    NULL,
    NULL,
    NULL,
    h248_pkg_RI_props,          /* Properties */
    NULL,                       /* signals */
    NULL,                       /* events */
    NULL                        /* statistics */
};


/* A.5 Bearer Reuse Idle Package  */

/* A.6 Generic bearer connection package
    Package Name: GB
    Package ID: 0x0021
 */

static int hf_h248_pkg_GB= -1;
static int hf_h248_pkg_GB_BNCChange= -1;
static int hf_h248_pkg_GB_BNCChange_type= -1;
static int hf_h248_pkg_GB_EstBNC= -1;
static int hf_h248_pkg_GB_ModBNC= -1;
static int hf_h248_pkg_GB_RelBNC = -1;
static int hf_h248_pkg_GB_RelBNC_Generalcause = -1;
static int hf_h248_pkg_GB_RelBNC_Failurecause = -1;
static int hf_h248_pkg_GB_RelBNC_Reset = -1;

static gint ett_h248_pkg_GB= -1;
static gint ett_h248_pkg_GB_EstBNC= -1;
static gint ett_h248_pkg_GB_ModBNC= -1;
static gint ett_h248_pkg_GB_RelBNC= -1;
static gint ett_h248_pkg_GB_BNCChange= -1;

static const value_string h248_pkg_GB_events_vals[] = {
    { 0x0001, "BNCChange" },
    { 0, NULL }
};


static const value_string h248_pkg_GB_BNCChange_type_vals[] = {
    {0x01, "Bearer Established"},
    {0x02,"Bearer Modified"},
    {0x03,"Bearer Cut through"},
    {0x04,"Bearer Modification Failure"},
    {0,NULL}
};

static const value_string h248_pkg_GB_BNCChange_params_vals[] = {
    {0x01, "Type"},
    {0,NULL}
};

static const h248_pkg_param_t h248_pkg_GB_BNCChange_pars[] = {
    { 0x0001, &hf_h248_pkg_GB_BNCChange_type, h248_param_ber_integer, &implicit },
    { 0, NULL, NULL, NULL}
};

static const h248_pkg_evt_t h248_pkg_GB_events[] = {
    { 0x0001, &hf_h248_pkg_GB_BNCChange, &ett_h248_pkg_GB_BNCChange, h248_pkg_GB_BNCChange_pars, h248_pkg_GB_BNCChange_params_vals},
    { 0, NULL, NULL, NULL, NULL}
};

static const value_string h248_pkg_GB_signals_vals[] = {
    {0x01, "Establish BNC"},
    {0x02, "Modify BNC"},
    {0,NULL}
};

static const value_string h248_pkg_GB_RelBNC_vals[] = {
    {0x01, "Generalcause"},
    {0x02, "Failurecause"},
    {0x03, "Reset"},
    {0,NULL}
};

static const value_string h248_pkg_GB_RelBNC_Generalcause_vals[] = {
    {0x01, "Normal Release"},
    {0x02, "Unavailable Resources"},
    {0x03, "Failure, Temporary"},
    {0x04, "Failure, Permanent"},
    {0x05, "Interworking Error"},
    {0x06, "Unsupported"},
    {0,NULL}
};

static const h248_pkg_param_t h248_pkg_GB_RelBNC_pars[] = {
    { 0x0001, &hf_h248_pkg_GB_RelBNC_Generalcause, h248_param_ber_integer, &implicit },
    { 0x0002, &hf_h248_pkg_GB_RelBNC_Failurecause, h248_param_ber_octetstring, &implicit },
    { 0x0003, &hf_h248_pkg_GB_RelBNC_Reset, h248_param_ber_boolean, &implicit },
    { 0, NULL, NULL, NULL}
};


static const h248_pkg_sig_t h248_pkg_GB_signals[] = {
    { 0x0001,&hf_h248_pkg_GB_EstBNC,&ett_h248_pkg_GB_EstBNC, NULL, NULL},
    { 0x0002,&hf_h248_pkg_GB_ModBNC,&ett_h248_pkg_GB_ModBNC, NULL, NULL},
    { 0x0003,&hf_h248_pkg_GB_RelBNC,&ett_h248_pkg_GB_RelBNC, h248_pkg_GB_RelBNC_pars, h248_pkg_GB_RelBNC_vals},
    { 0, NULL, NULL, NULL, NULL}
};

static const value_string h248_pkg_GB_props_vals[] = {
    { 0x0000, "Generic Bearer Connection Q.1950 Annex A (gb)" },
    { 0, NULL }
};

static h248_package_t h248_pkg_GB = {
    0x0021,
    &hf_h248_pkg_GB,
    &ett_h248_pkg_GB,
    h248_pkg_GB_props_vals,
    h248_pkg_GB_signals_vals,
    h248_pkg_GB_events_vals,
    NULL,
    NULL,                       /* Properties */
    h248_pkg_GB_signals,        /* signals */
    h248_pkg_GB_events,         /* events */
    NULL                        /* statistics */
};


/* A.7 Bearer control tunnelling package */
static dissector_handle_t bctp_dissector = NULL;

static int hf_h248_pkg_bt = -1;
static int hf_h248_pkg_bt_tind = -1;
static int hf_h248_pkg_bt_tunopt = -1;
static int hf_h248_pkg_bt_bit = -1;

static gint ett_h248_pkg_bt = -1;
static gint ett_h248_pkg_bt_tind = -1;
static gint ett_h248_pkg_bt_bit= -1;

static void dissect_bt_tunneled_proto(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, int hfid, h248_curr_info_t* i _U_, void* d _U_) {
    tvbuff_t* bctp_tvb = NULL;
    gint8 appclass;
    gboolean pc;
    gint32 tag;
    asn1_ctx_t asn1_ctx;

    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

    get_ber_identifier(tvb, 0, &appclass, &pc, &tag);

    /* XXX: is this enough to guess it? */
    if (tag == BER_UNI_TAG_OCTETSTRING) {
        dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, 0, hfid, &bctp_tvb);

        if (bctp_tvb) {
            call_dissector(bctp_dissector,bctp_tvb,pinfo,tree);
        }
    } else {
        proto_tree_add_item(tree,hfid,tvb,0,-1,ENC_NA);
    }

}


/* Properties */
static const value_string h248_pkg_bt_props_vals[] = {
    { 0, "Bearer Control Tunnelling Q.1950 Annex A" },
    { 1, "Tunnelling Options"},
    { 0, NULL}
};

static const  value_string h248_pkg_bt_tunopt_vals[]  = {
    { 1, "1 (In the same message as the command response to the command which generated the bearer control tunnel)"},
    { 2, "2 (Tunnel message at any time)"},
    { 3, "NO"},
    { 0, NULL}
};

static const h248_pkg_param_t h248_pkg_bt_props[] = {
    { 0x0001, &hf_h248_pkg_bt_tunopt, h248_param_ber_integer, &implicit },
    { 0, NULL, NULL, NULL}
};

/* Events */
static const value_string h248_pkg_bt_evt_vals[] = {
    {1,"Tunnel indication"},
    {0,NULL}
};

static const value_string h248_pkg_bt_tind_vals[] = {
    {1,"Tunnel Indication"},
    {0,NULL}
};

static const h248_pkg_param_t h248_pkg_bt_bit_params[] = {
    { 0x0001, &hf_h248_pkg_bt_bit, dissect_bt_tunneled_proto, &implicit },
    { 0, NULL, NULL, NULL}
};

static const value_string h248_pkg_bt_sigs_vals[] = {
    {1,"Bearer Information Tunnel"},
    {0,NULL}
};

static const h248_pkg_evt_t h248_pkg_bt_events[] = {
    { 0x0001, &hf_h248_pkg_bt_tind, &ett_h248_pkg_bt_tind, h248_pkg_bt_bit_params, h248_pkg_bt_tind_vals},
    { 0, NULL, NULL, NULL, NULL}
};

static const h248_pkg_sig_t h248_pkg_bt_signals[] = {
    { 0x0001,&hf_h248_pkg_bt_bit,&ett_h248_pkg_bt_bit, h248_pkg_bt_bit_params, h248_pkg_bt_tind_vals},
    { 0, NULL, NULL, NULL, NULL}
};

/* Packet defenitions */
static h248_package_t h248_pkg_bct = {
    0x0022,
    &hf_h248_pkg_bt,
    &ett_h248_pkg_bt,
    h248_pkg_bt_props_vals,
    h248_pkg_bt_sigs_vals,
    h248_pkg_bt_evt_vals,
    NULL,
    h248_pkg_bt_props,          /* Properties */
    h248_pkg_bt_signals,        /* signals */
    h248_pkg_bt_events,         /* events */
    NULL                        /* statistics */
};

/* A.8 Basic call progress tones generator with directionality */
static int hf_h248_pkg_bcg = -1;
static int hf_h248_pkg_bcg_sig_bdt_par_btd = -1;
static int hf_h248_pkg_bcg_sig_bdt = -1;
static int hf_h248_pkg_bcg_sig_brt = -1;
static int hf_h248_pkg_bcg_sig_bbt = -1;
static int hf_h248_pkg_bcg_sig_bct = -1;
static int hf_h248_pkg_bcg_sig_bsit = -1;
static int hf_h248_pkg_bcg_sig_bwt = -1;
static int hf_h248_pkg_bcg_sig_bpt = -1;
static int hf_h248_pkg_bcg_sig_bcw = -1;
static int hf_h248_pkg_bcg_sig_bcr = -1;
static int hf_h248_pkg_bcg_sig_bpy = -1;

static gint ett_h248_pkg_bcg = -1;
static gint ett_h248_pkg_bcg_sig_bdt = -1;

static const value_string h248_pkg_bcg_sig_bdt_par_btd_vals[] = {
    {   0x0001, "ext (External)" },
    {   0x0002, "int (Internal)" },
    {   0x0003, "both (Both)" },
    {0,     NULL},
};

static h248_pkg_param_t  h248_pkg_h248_pkg_bcg_sig_bdt_params[] = {
    { 0x0001, &hf_h248_pkg_bcg_sig_bdt_par_btd, h248_param_ber_integer, &implicit },
    { 0, NULL, NULL, NULL}
};

static const value_string h248_pkg_bcg_signals_vals[] = {
    { 0x0040, "Dial Tone (bdt)" },
    { 0x0041, "Ringing Tone (brt)" },
    { 0x0042, "Busy Tone (bbt)" },
    { 0x0043, "Congestion Tone (bct)" },
    { 0x0044, "Special information tone (bsit)" },
    { 0x0045, "Warning Tone (bwt)" },
    { 0x0046, "Payphone Recognition Tone (bpt)" },
    { 0x0047, "Call Waiting Tone (bcw)" },
    { 0x0048, "Caller Waiting Tone (bcr)" },
    { 0x0049, "Pay Tone (bpy)" },
    { 0, NULL }
};

static h248_pkg_sig_t h248_pkg_bcg_signals[] = {
    /* All the tones have the same parameters */
    { 0x0040, &hf_h248_pkg_bcg_sig_bdt, &ett_h248_pkg_bcg_sig_bdt, h248_pkg_h248_pkg_bcg_sig_bdt_params, NULL },
    { 0x0041, &hf_h248_pkg_bcg_sig_brt, &ett_h248_pkg_bcg_sig_bdt, h248_pkg_h248_pkg_bcg_sig_bdt_params, NULL },
    { 0x0042, &hf_h248_pkg_bcg_sig_bbt, &ett_h248_pkg_bcg_sig_bdt, h248_pkg_h248_pkg_bcg_sig_bdt_params, NULL },
    { 0x0043, &hf_h248_pkg_bcg_sig_bct, &ett_h248_pkg_bcg_sig_bdt, h248_pkg_h248_pkg_bcg_sig_bdt_params, NULL },
    { 0x0044, &hf_h248_pkg_bcg_sig_bsit, &ett_h248_pkg_bcg_sig_bdt, h248_pkg_h248_pkg_bcg_sig_bdt_params, NULL },
    { 0x0045, &hf_h248_pkg_bcg_sig_bwt, &ett_h248_pkg_bcg_sig_bdt, h248_pkg_h248_pkg_bcg_sig_bdt_params, NULL},
    { 0x0046, &hf_h248_pkg_bcg_sig_bpt, &ett_h248_pkg_bcg_sig_bdt, h248_pkg_h248_pkg_bcg_sig_bdt_params, NULL },
    { 0x0047, &hf_h248_pkg_bcg_sig_bcw, &ett_h248_pkg_bcg_sig_bdt, h248_pkg_h248_pkg_bcg_sig_bdt_params, NULL },
    { 0x0048, &hf_h248_pkg_bcg_sig_bcr, &ett_h248_pkg_bcg_sig_bdt, h248_pkg_h248_pkg_bcg_sig_bdt_params, NULL },
    { 0x0049, &hf_h248_pkg_bcg_sig_bpy, &ett_h248_pkg_bcg_sig_bdt, h248_pkg_h248_pkg_bcg_sig_bdt_params, NULL },
    { 0, NULL, NULL, NULL,NULL}
};

static const value_string h248_pkg_bcg_props_vals[] = {
    { 0, "Basic Call Progress Tones Q.1950 Annex A" },
    { 0, NULL }
};

/* Packet defenitions */
static h248_package_t h248_pkg_bcg = {
    0x0023,
    &hf_h248_pkg_bcg,
    &ett_h248_pkg_bcg,
    h248_pkg_bcg_props_vals,
    h248_pkg_bcg_signals_vals,
    NULL,
    NULL,
    NULL,                       /* Properties */
    h248_pkg_bcg_signals,       /* signals */
    NULL,                       /* events */
    NULL                        /* statistics */
};


void proto_reg_handoff_q1950(void) {
    bctp_dissector = find_dissector_add_dependency("bctp", proto_q1950);

}

/* Register dissector */
void proto_register_q1950(void) {
    static hf_register_info hf[] = {
        /* A.3 Bearer characteristics package */
        { &hf_h248_pkg_BCP,
            { "BCP (Bearer characteristics package)", "h248.BCP",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_h248_pkg_BCP_BNCChar,
            { "BNCChar (BNC Characteristics)", "h248.bcp.bncchar",
            FT_UINT32, BASE_HEX|BASE_EXT_STRING, &bearer_network_connection_characteristics_vals_ext, 0, "BNC Characteristics", HFILL }
        },

        /* A.4 Bearer Network connection cut-through package */
        { &hf_h248_pkg_BNCCT,
            { "BNCCT (Bearer network connection cut-through package)", "h248.BNCCT",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_h248_pkg_BNCCT_prop,
            { "Bearer network connection cut-through capability", "h248.bcp.bncct",
            FT_UINT32, BASE_HEX, VALS(h248_pkg_BNCCT_prop_vals), 0, "This property allows the MGC to ask the MG when the cut through of a bearer will occur, early or late.", HFILL }
        },

        { &hf_h248_pkg_GB,
            { "GB (Generic bearer connection)", "h248.GB",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_h248_pkg_GB_BNCChange,
            { "BNCChange", "h248.GB.BNCChang",
            FT_BYTES, BASE_NONE, NULL, 0, "This event occurs whenever a change to a Bearer Network connection occurs", HFILL }
        },
        { &hf_h248_pkg_GB_BNCChange_type,
            { "Type", "h248.GB.BNCChang.Type",
            FT_UINT32, BASE_HEX, VALS(h248_pkg_GB_BNCChange_type_vals), 0, NULL, HFILL }
        },
        { &hf_h248_pkg_GB_EstBNC,
            { "Type", "h248.GB.BNCChang.EstBNC",
            FT_BYTES, BASE_NONE, NULL, 0, "This signal triggers the bearer control function to send bearer establishment signalling", HFILL }
        },
        { &hf_h248_pkg_GB_ModBNC,
            { "Type", "h248.GB.BNCChang.ModBNC",
            FT_BYTES, BASE_NONE, NULL, 0, "This signal triggers the bearer control function to send bearer modification", HFILL }
        },
        { &hf_h248_pkg_GB_RelBNC,
            { "RelBNC", "h248.GB.BNCChang.RelBNC",
            FT_BYTES, BASE_NONE, NULL, 0, "This signal triggers the bearer control function to send bearer release", HFILL }
        },
        { &hf_h248_pkg_GB_RelBNC_Generalcause,
            { "Generalcause", "h248.GB.BNCChang.RelBNC.Generalcause",
            FT_UINT32, BASE_HEX, VALS(h248_pkg_GB_RelBNC_Generalcause_vals), 0, "This indicates the general reason for the Release", HFILL }
        },
        { &hf_h248_pkg_GB_RelBNC_Failurecause,
            { "Failurecause", "h248.GB.BNCChang.RelBNC.Failurecause",
            FT_BYTES, BASE_NONE, NULL, 0, "The Release Cause is the value generated by the Released equipment", HFILL }
        },
        { &hf_h248_pkg_GB_RelBNC_Reset,
            { "RelBNC", "h248.GB.BNCChang.RelBNC.Reset",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0, "This signal triggers the bearer control function to send bearer release", HFILL }
        },

        /* A.5 Bearer Network connection cut-through package */
        { &hf_h248_pkg_RI,
            { "RI (Reuse idle package)", "h248.RI",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_h248_pkg_RII,
            { "Reuse Idle Indication", "h248.bcp.rii",
            FT_UINT32, BASE_HEX, VALS(h248_pkg_RII_vals), 0, "This property indicates that the provided bearer network connection relates to an Idle Bearer.", HFILL }
        },

        /* A.7 Bearer control tunnelling package */
        { &hf_h248_pkg_bt,
            { "BT (Bearer control Tunneling)", "h248.BT",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_h248_pkg_bt_tunopt,
            { "Tunnelling Options", "h248.BT.TunOpt",
                FT_UINT32, BASE_DEC, VALS(h248_pkg_bt_tunopt_vals), 0, NULL, HFILL }
        },
        { &hf_h248_pkg_bt_tind,
            { "tind (Tunnel INDication)", "h248.BT.TIND",
                FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_h248_pkg_bt_bit,
            { "Bearer Information Transport", "h248.BT.BIT",
                FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },


        /* A.8 Basic call progress tones generator with directionality */
        { &hf_h248_pkg_bcg,
            { "bcg (Basic call progress tones generator with directionality)", "h248.bcg",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_h248_pkg_bcg_sig_bdt_par_btd,
            { "btd (Tone Direction)", "h248.bcp.btd",
            FT_UINT32, BASE_HEX, VALS(h248_pkg_bcg_sig_bdt_par_btd_vals), 0, NULL, HFILL }
        },
        { &hf_h248_pkg_bcg_sig_bdt,
            { "bdt (Dial Tone)", "h248.bcg.bdt",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_h248_pkg_bcg_sig_brt,
            { "brt (Ringing tone)", "h248.bcg.brt",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_h248_pkg_bcg_sig_bbt,
            { "bbt (Busy tone)", "h248.bcg.bbt",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_h248_pkg_bcg_sig_bct,
            { "bct (Congestion tone)", "h248.bcg.bct",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_h248_pkg_bcg_sig_bsit,
            { "bsit (Special information tone)", "h248.bcg.bsit",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_h248_pkg_bcg_sig_bwt,
            { "bwt (Warning tone)", "h248.bcg.bwt",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_h248_pkg_bcg_sig_bpt,
            { "bpt (Payphone recognition tone)", "h248.bcg.bpt",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_h248_pkg_bcg_sig_bcw,
            { "bcw (Call waiting tone)", "h248.bcg.bcw",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_h248_pkg_bcg_sig_bcr,
            { "bcr (Call ringing tone)", "h248.bcg.bcr",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_h248_pkg_bcg_sig_bpy,
            { "bpy (Pay tone)", "h248.bcg.bpy",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_h248_pkg_BCP,
        &ett_h248_pkg_bt,
        &ett_h248_pkg_bt_tind,
        &ett_h248_pkg_bt_bit,
        &ett_h248_pkg_bcg,
        &ett_h248_pkg_bcg_sig_bdt,
        &ett_h248_pkg_BNCCT,
        &ett_h248_pkg_RI,
        &ett_h248_pkg_GB,
        &ett_h248_pkg_GB_EstBNC,
        &ett_h248_pkg_GB_ModBNC,
        &ett_h248_pkg_GB_RelBNC,
        &ett_h248_pkg_GB_BNCChange
    };

    proto_q1950 = proto_register_protocol(PNAME, PSNAME, PFNAME);

    proto_register_field_array(proto_q1950, hf, array_length(hf));

    proto_register_subtree_array(ett, array_length(ett));

    /* Register the packages */
    h248_register_package(&h248_pkg_BCP,REPLACE_PKG);
    h248_register_package(&h248_pkg_BNCCT,REPLACE_PKG);
    h248_register_package(&h248_pkg_RI,REPLACE_PKG);
    h248_register_package(&h248_pkg_GB,REPLACE_PKG);
    h248_register_package(&h248_pkg_bcg,REPLACE_PKG);
    h248_register_package(&h248_pkg_bct,REPLACE_PKG);

}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */

/* packet-opa-snc.c
 * Routines for Omni-Path SnC header dissection
 * Copyright (c) 2016, Intel Corporation.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <wiretap/erf.h>

void proto_reg_handoff_opa_snc(void);
void proto_register_opa_snc(void);

static const value_string vals_opa_snc_direction[] = {
    { 0, "Outbound" },
    { 1, "Inbound" },
    { 2, "Internal Debugging Tool" },
    { 0, NULL }
};
/* PBC */
static const true_false_string tfs_opa_snc_pbc_isBypass = {
    "Bypass (8B/10B/16B) Packet",
    "9B Packet"
};
static const value_string vals_opa_snc_pbc_insertHcrc[] = {
    { 0x0, "KDETH Hcrc calculated assuming GRH is not present" },
    { 0x1, "KDETH Hcrc calculated assuming GRH is present" },
    { 0x2, "KDETH Hcrc is not inserted" },
    { 0x3, "Reserved" },
    { 0, NULL }
};
/* RHF */
static const value_string vals_opa_snc_rhf_rcvtypeerr[] = {
    { 0x0, "No Error" },
    { 0x1, "OpCode Error" },
    { 0x2, "KDETH Min Length Error" },
    { 0x3, "KDETH Hcrc Error" },
    { 0x4, "KDETH Version Error" },
    { 0x5, "Context Error" },
    { 0x6, "KDETH TID Error" },
    { 0x7, "Reserved" },
    { 0, NULL }
};
static const value_string vals_opa_snc_rhf_rcvtype[] = {
    { 0, "Expected Receive" },
    { 1, "Eager Receive" },
    { 2, "IB" },
    { 3, "error" },
    { 4, "bypass" },
    { 0, NULL }
};

/* Wireshark ID */
static gint proto_opa_snc = -1;

/* Variables to hold expansion values between packets */
static gint ett_snc = -1;
static gint ett_sncpbc = -1;
static gint ett_sncrhf = -1;

/* SnC Fields */
static gint hf_opa_snc_direction = -1;
static gint hf_opa_snc_portnumber = -1;
static gint hf_opa_snc_Reserved16 = -1;
static gint hf_opa_snc_Reserved32 = -1;
static gint hf_opa_snc_Reserved64 = -1;
static gint hf_opa_snc_pbc_reserved_63_48 = -1;
static gint hf_opa_snc_pbc_pbcstaticratecontrolcnt = -1;
static gint hf_opa_snc_pbc_pbcintr = -1;
static gint hf_opa_snc_pbc_pbcdcinfo = -1;
static gint hf_opa_snc_pbc_pbctestebp = -1;
static gint hf_opa_snc_pbc_pbcpacketbypass = -1;
static gint hf_opa_snc_pbc_pbcinserthcrc = -1;
static gint hf_opa_snc_pbc_pbccreditreturn = -1;
static gint hf_opa_snc_pbc_pbcinsertbypassicrc = -1;
static gint hf_opa_snc_pbc_pbctestbadicrc = -1;
static gint hf_opa_snc_pbc_pbcfecn = -1;
static gint hf_opa_snc_pbc_reserved_21_16 = -1;
static gint hf_opa_snc_pbc_pbcvl = -1;
static gint hf_opa_snc_pbc_pbclengthdws = -1;
static const gint *_snc_pbc_1[] = {
    &hf_opa_snc_pbc_reserved_63_48,
    &hf_opa_snc_pbc_pbcstaticratecontrolcnt,
    NULL
};
static const gint *_snc_pbc_2[] = {
    &hf_opa_snc_pbc_pbcintr,
    &hf_opa_snc_pbc_pbcdcinfo,
    &hf_opa_snc_pbc_pbctestebp,
    &hf_opa_snc_pbc_pbcpacketbypass,
    &hf_opa_snc_pbc_pbcinserthcrc,
    &hf_opa_snc_pbc_pbccreditreturn,
    &hf_opa_snc_pbc_pbcinsertbypassicrc,
    &hf_opa_snc_pbc_pbctestbadicrc,
    &hf_opa_snc_pbc_pbcfecn,
    &hf_opa_snc_pbc_reserved_21_16,
    &hf_opa_snc_pbc_pbcvl,
    &hf_opa_snc_pbc_pbclengthdws,
    NULL
};
static gint hf_opa_snc_rhf_icrcerr = -1;
static gint hf_opa_snc_rhf_reserved_62 = -1;
static gint hf_opa_snc_rhf_eccerr = -1;
static gint hf_opa_snc_rhf_lenerr = -1;
static gint hf_opa_snc_rhf_tiderr = -1;
static gint hf_opa_snc_rhf_rcvtypeerr = -1;
static gint hf_opa_snc_rhf_dcerr = -1;
static gint hf_opa_snc_rhf_dcuncerr = -1;
static gint hf_opa_snc_rhf_khdrlenerr = -1;
static gint hf_opa_snc_rhf_hdrqoffset = -1;
static gint hf_opa_snc_rhf_egroffset = -1;
static gint hf_opa_snc_rhf_rcvseq = -1;
static gint hf_opa_snc_rhf_dcinfo = -1;
static gint hf_opa_snc_rhf_egrindex = -1;
static gint hf_opa_snc_rhf_useegrbfr = -1;
static gint hf_opa_snc_rhf_rcvtype = -1;
static gint hf_opa_snc_rhf_pktlen = -1;
static const gint *_snc_rhf_1[] = {
    &hf_opa_snc_rhf_icrcerr,
    &hf_opa_snc_rhf_reserved_62,
    &hf_opa_snc_rhf_eccerr,
    &hf_opa_snc_rhf_lenerr,
    &hf_opa_snc_rhf_tiderr,
    &hf_opa_snc_rhf_rcvtypeerr,
    &hf_opa_snc_rhf_dcerr,
    &hf_opa_snc_rhf_dcuncerr,
    &hf_opa_snc_rhf_khdrlenerr,
    &hf_opa_snc_rhf_hdrqoffset,
    &hf_opa_snc_rhf_egroffset,
    NULL
};
static const gint *_snc_rhf_2[] = {
    &hf_opa_snc_rhf_rcvseq,
    &hf_opa_snc_rhf_dcinfo,
    &hf_opa_snc_rhf_egrindex,
    &hf_opa_snc_rhf_useegrbfr,
    &hf_opa_snc_rhf_rcvtype,
    &hf_opa_snc_rhf_pktlen,
    NULL
};

static expert_field ei_opa_snc_nobypass = EI_INIT;

static void cf_opa_snc_dw_to_b(gchar *buf, guint32 value)
{
    g_snprintf(buf, ITEM_LABEL_LENGTH, "%u DWORDS, %u Bytes", value, value * 4);
}
static void cf_opa_snc_qw_to_b(gchar *buf, guint32 value)
{
    g_snprintf(buf, ITEM_LABEL_LENGTH, "%u QWORDS, %u Bytes", value, value * 8);
}

/* Dissector Declarations */
static dissector_handle_t opa_snc_handle;
static dissector_handle_t opa_9b_handle;

static int dissect_opa_snc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint offset = 0;    /* Current Offset */

    gboolean isBypass = TRUE;  /* Tracks if we are parsing a bypass packet or Not */
    guint8 Direction = tvb_get_guint8(tvb, offset + 1);
    guint64 RHF_PBC;
    proto_item *SnC_item;
    proto_tree * SnC_tree,*PBC_tree,*RHF_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Omni-Path");
    col_clear(pinfo->cinfo, COL_INFO);

    tree = proto_tree_get_parent_tree(tree);

    SnC_item = proto_tree_add_item(tree, proto_opa_snc, tvb, offset, 16, ENC_NA);
    SnC_tree = proto_item_add_subtree(SnC_item, ett_snc);

    proto_tree_add_item(SnC_tree, hf_opa_snc_portnumber, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(SnC_tree, hf_opa_snc_direction, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(SnC_tree, hf_opa_snc_Reserved16, tvb, offset, 2, ENC_NA);
    offset += 2;
    proto_tree_add_item(SnC_tree, hf_opa_snc_Reserved32, tvb, offset, 4, ENC_NA);
    offset += 4;

    RHF_PBC = tvb_get_letoh64(tvb, offset);
    switch (Direction) {
    case 0:
        PBC_tree = proto_tree_add_subtree(SnC_tree, tvb, offset, 8, ett_sncpbc, NULL, "PBC - Per Buffer Control");
        proto_tree_add_bitmask_list(PBC_tree, tvb, offset + 4, 4, _snc_pbc_1, ENC_LITTLE_ENDIAN);
        proto_tree_add_bitmask_list(PBC_tree, tvb, offset, 4, _snc_pbc_2, ENC_LITTLE_ENDIAN);
        isBypass = (((RHF_PBC >> 28) & 1) == 1);
        break;
    case 1:
        RHF_tree = proto_tree_add_subtree(SnC_tree, tvb, offset, 8, ett_sncrhf, NULL, "RHF - Receive Header Flags");
        proto_tree_add_bitmask_list(RHF_tree, tvb, offset + 4, 4, _snc_rhf_1, ENC_LITTLE_ENDIAN);
        proto_tree_add_bitmask_list(RHF_tree, tvb, offset, 4, _snc_rhf_2, ENC_LITTLE_ENDIAN);
        isBypass = (((RHF_PBC >> 12) & 7) == 4);
        break;
    case 2:     /* For use with internal debugging tools */
        proto_tree_add_item(SnC_tree, hf_opa_snc_Reserved64, tvb, offset, 8, ENC_NA);
        isBypass = FALSE;
        break;
    default:
        isBypass = FALSE;
    }
    offset += 8;

    if (isBypass) {
        /* Bypass packets not implemented in this version */
        expert_add_info(pinfo, NULL, &ei_opa_snc_nobypass);
    } else {
        call_dissector(opa_9b_handle, tvb_new_subset_remaining(tvb, offset), pinfo, tree);
    }
    return tvb_captured_length(tvb);
}

void proto_register_opa_snc(void)
{
    expert_module_t *expert_opa_snc;

    static hf_register_info hf[] = {
        { &hf_opa_snc_direction, {
                "Direction", "opa.snc.direction",
                FT_UINT8, BASE_HEX, VALS(vals_opa_snc_direction), 0x0, NULL, HFILL }
        },
        { &hf_opa_snc_portnumber, {
                "Port Number", "opa.snc.portnumber",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_snc_Reserved32, {
                "Reserved (32 bits)", "opa.snc.reserved32",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_snc_Reserved64, {
                "Reserved (64 bits)", "opa.snc.reserved64",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_snc_Reserved16, {
                "Reserved (16 bits)", "opa.snc.reserved16",
                FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_snc_pbc_reserved_63_48, {
                "Reserved (16 bits)", "opa.snc.pbc.reserved_63_48",
                FT_UINT32, BASE_HEX, NULL, 0xFFFF0000, NULL, HFILL }
        },
        { &hf_opa_snc_pbc_pbcstaticratecontrolcnt, {
                "Static Rate Control Counter", "opa.snc.pbc.pbcstaticratecontrolcnt",
                FT_UINT32, BASE_HEX, NULL, 0x0000FFFF, NULL, HFILL }
        },
        { &hf_opa_snc_pbc_pbcintr, {
                "Interrupt", "opa.snc.pbc.pbcintr",
                FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x80000000, NULL, HFILL }
        },
        { &hf_opa_snc_pbc_pbcdcinfo, {
                "DC Info", "opa.snc.pbc.pbcdcinfo",
                FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x40000000, NULL, HFILL }
        },
        { &hf_opa_snc_pbc_pbctestebp, {
                "Test End Bad Packet", "opa.snc.pbc.pbctestebp",
                FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x20000000, NULL, HFILL }
        },
        { &hf_opa_snc_pbc_pbcpacketbypass, {
                "Packet Type", "opa.snc.pbc.pbcpacketbypass",
                FT_BOOLEAN, 32, TFS(&tfs_opa_snc_pbc_isBypass), 0x10000000, NULL, HFILL }
        },
        { &hf_opa_snc_pbc_pbcinserthcrc, {
                "Insert Hcrc", "opa.snc.pbc.pbcinserthcrc",
                FT_UINT32, BASE_HEX, VALS(vals_opa_snc_pbc_insertHcrc), 0x0C000000, NULL, HFILL }
        },
        { &hf_opa_snc_pbc_pbccreditreturn, {
                "Request Credit Return", "opa.snc.pbc.pbccreditreturn",
                FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x02000000, NULL, HFILL }
        },
        { &hf_opa_snc_pbc_pbcinsertbypassicrc, {
                "Insert ICRC for bypass packets", "opa.snc.pbc.pbcinsertbypassicrc",
                FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x01000000, NULL, HFILL }
        },
        { &hf_opa_snc_pbc_pbctestbadicrc, {
                "Insert a bad ICRC", "opa.snc.pbc.pbctestbadicrc",
                FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00800000, NULL, HFILL }
        },
        { &hf_opa_snc_pbc_pbcfecn, {
                "Set FECN bit", "opa.snc.pbc.pbcfecn",
                FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00400000, NULL, HFILL }
        },
        { &hf_opa_snc_pbc_reserved_21_16, {
                "Reserved (6 bits)", "opa.snc.pbc.reserved_21_16",
                FT_UINT32, BASE_HEX, NULL, 0x003F0000, NULL, HFILL }
        },
        { &hf_opa_snc_pbc_pbcvl, {
                "VL", "opa.snc.pbc.pbcvl",
                FT_UINT32, BASE_DEC, NULL, 0x0000F000, NULL, HFILL }
        },
        { &hf_opa_snc_pbc_pbclengthdws, {
                "pbclengthdws", "opa.snc.pbc.pbclengthdws",
                FT_UINT32, BASE_CUSTOM, CF_FUNC(cf_opa_snc_dw_to_b), 0x00000FFF, NULL, HFILL }
        },

        { &hf_opa_snc_rhf_icrcerr, {
                "ICRC error", "opa.snc.rhf.icrcerr",
                FT_BOOLEAN, 32, TFS(&tfs_error_ok), 0x80000000, NULL, HFILL }
        },
        { &hf_opa_snc_rhf_reserved_62, {
                "Reserved (1 bit)", "opa.snc.rhf.reserved_62",
                FT_UINT32, BASE_HEX, NULL, 0x40000000, NULL, HFILL }
        },
        { &hf_opa_snc_rhf_eccerr, {
                "Internal memory Uncorrectable error", "opa.snc.rhf.eccerr",
                FT_BOOLEAN, 32, TFS(&tfs_error_ok), 0x200000000, NULL, HFILL }
        },
        { &hf_opa_snc_rhf_lenerr, {
                "Length Error", "opa.snc.rhf.lenerr",
                FT_BOOLEAN, 32, TFS(&tfs_error_ok), 0x10000000, NULL, HFILL }
        },
        { &hf_opa_snc_rhf_tiderr, {
                "TID Error", "opa.snc.rhf.tiderr",
                FT_BOOLEAN, 32, TFS(&tfs_error_ok), 0x08000000, NULL, HFILL }
        },
        { &hf_opa_snc_rhf_rcvtypeerr, {
                "Receive Type Error", "opa.snc.rhf.rcvtypeerr",
                FT_UINT32, BASE_HEX, VALS(vals_opa_snc_rhf_rcvtypeerr), 0x07000000, NULL, HFILL }
        },
        { &hf_opa_snc_rhf_dcerr, {
                "End Bad Packet Error", "opa.snc.rhf.dcerr",
                FT_BOOLEAN, 32, TFS(&tfs_error_ok), 0x00800000, NULL, HFILL }
        },
        { &hf_opa_snc_rhf_dcuncerr, {
                "Uncorrectable or parity error", "opa.snc.rhf.dcuncerr",
                FT_BOOLEAN, 32, TFS(&tfs_error_ok), 0x00400000, NULL, HFILL }
        },
        { &hf_opa_snc_rhf_khdrlenerr, {
                "KDETH Length Error", "opa.snc.rhf.khdrlenerr",
                FT_BOOLEAN, 32, TFS(&tfs_error_ok), 0x00200000, NULL, HFILL }
        },
        { &hf_opa_snc_rhf_hdrqoffset, {
                "Receive Header Offset", "opa.snc.rhf.hdrqoffset",
                FT_UINT32, BASE_CUSTOM, CF_FUNC(cf_opa_snc_dw_to_b), 0x001FF000, NULL, HFILL }
        },
        { &hf_opa_snc_rhf_egroffset, {
                "Eager Buffer Offset", "opa.snc.rhf.egroffset",
                FT_UINT32, BASE_CUSTOM, CF_FUNC(cf_opa_snc_qw_to_b), 0x00000FFF, NULL, HFILL }
        },
        { &hf_opa_snc_rhf_rcvseq, {
                "Receive Sequence", "opa.snc.rhf.rcvseq",
                FT_UINT32, BASE_DEC, NULL, 0xF0000000, NULL, HFILL }
        },
        { &hf_opa_snc_rhf_dcinfo, {
                "DC Info", "opa.snc.rhf.dcinfo",
                FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x08000000, NULL, HFILL }
        },
        { &hf_opa_snc_rhf_egrindex, {
                "Eager Buffer Index", "opa.snc.rhf.egrindex",
                FT_UINT32, BASE_HEX, NULL, 0x07FF0000, NULL, HFILL }
        },
        { &hf_opa_snc_rhf_useegrbfr, {
                "Use Eager Buffer", "opa.snc.rhf.useegrbfr",
                FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00008000, NULL, HFILL }
        },
        { &hf_opa_snc_rhf_rcvtype, {
                "Packet Receive Type", "opa.snc.rhf.rcvtype",
                FT_UINT32, BASE_DEC_HEX, VALS(vals_opa_snc_rhf_rcvtype), 0x00007000, NULL, HFILL }
        },
        { &hf_opa_snc_rhf_pktlen, {
                "Packet Length", "opa.snc.rhf.pktlen",
                FT_UINT32, BASE_CUSTOM, CF_FUNC(cf_opa_snc_dw_to_b), 0x00000FFF, NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_snc,
        &ett_sncpbc,
        &ett_sncrhf,
    };

    static ei_register_info ei[] = {
        { &ei_opa_snc_nobypass, {
                "opa.snc.nobypass", PI_PROTOCOL, PI_WARN,
                "Bypass packets not implemented in this version", EXPFILL }
        }
    };

    proto_opa_snc = proto_register_protocol(
        "Intel Omni-Path SnC - Omni-Path Snoop and Capture MetaData Header",
        "OPA SnC", "opa.snc");
    opa_snc_handle = register_dissector("opa.snc", dissect_opa_snc, proto_opa_snc);

    proto_register_field_array(proto_opa_snc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_opa_snc = expert_register_protocol(proto_opa_snc);
    expert_register_field_array(expert_opa_snc, ei, array_length(ei));
}

void proto_reg_handoff_opa_snc(void)
{
    opa_9b_handle = find_dissector("opa");

    /* announce an anonymous Omni-Path SnC dissector */
    dissector_add_uint("erf.types.type", ERF_TYPE_OPA_SNC, opa_snc_handle);

}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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

/* packet-ircomm.c
 * Routines for IrCOMM dissection
 * Copyright 2003 Jan Kiszka <jan.kiszka@web.de>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "config.h"

#include <epan/packet.h>

/*
 * See
 *
 *    http://www.irda.org/standards/specifications.asp
 *
 * for various IrDA specifications.
 */

#include "irda-appl.h"


/* Parameters common to all service types */
#define IRCOMM_SERVICE_TYPE     0x00
#define IRCOMM_PORT_TYPE        0x01 /* Only used in LM-IAS */
#define IRCOMM_PORT_NAME        0x02 /* Only used in LM-IAS */

/* Parameters for both 3 wire and 9 wire */
#define IRCOMM_DATA_RATE        0x10
#define IRCOMM_DATA_FORMAT      0x11
#define IRCOMM_FLOW_CONTROL     0x12
#define IRCOMM_XON_XOFF         0x13
#define IRCOMM_ENQ_ACK          0x14
#define IRCOMM_LINE_STATUS      0x15
#define IRCOMM_BREAK            0x16

/* Parameters for 9 wire */
#define IRCOMM_DTE              0x20
#define IRCOMM_DCE              0x21
#define IRCOMM_POLL             0x22

/* Service type (details) */
#define IRCOMM_3_WIRE_RAW       0x01
#define IRCOMM_3_WIRE           0x02
#define IRCOMM_9_WIRE           0x04
#define IRCOMM_CENTRONICS       0x08

/* Port type (details) */
#define IRCOMM_SERIAL           0x01
#define IRCOMM_PARALLEL         0x02

/* Data format (details) */
#define IRCOMM_WSIZE_5          0x00
#define IRCOMM_WSIZE_6          0x01
#define IRCOMM_WSIZE_7          0x02
#define IRCOMM_WSIZE_8          0x03

#define IRCOMM_1_STOP_BIT       0x00
#define IRCOMM_2_STOP_BIT       0x04 /* 1.5 if char len 5 */

#define IRCOMM_PARITY_DISABLE   0x00
#define IRCOMM_PARITY_ENABLE    0x08

#define IRCOMM_PARITY_ODD       0x00
#define IRCOMM_PARITY_EVEN      0x10
#define IRCOMM_PARITY_MARK      0x20
#define IRCOMM_PARITY_SPACE     0x30

/* Flow control */
#define IRCOMM_XON_XOFF_IN      0x01
#define IRCOMM_XON_XOFF_OUT     0x02
#define IRCOMM_RTS_CTS_IN       0x04
#define IRCOMM_RTS_CTS_OUT      0x08
#define IRCOMM_DSR_DTR_IN       0x10
#define IRCOMM_DSR_DTR_OUT      0x20
#define IRCOMM_ENQ_ACK_IN       0x40
#define IRCOMM_ENQ_ACK_OUT      0x80

/* Line status */
#define IRCOMM_OVERRUN_ERROR    0x02
#define IRCOMM_PARITY_ERROR     0x04
#define IRCOMM_FRAMING_ERROR    0x08

/* DTE (Data terminal equipment) line settings */
#define IRCOMM_DELTA_DTR        0x01
#define IRCOMM_DELTA_RTS        0x02
#define IRCOMM_DTR              0x04
#define IRCOMM_RTS              0x08

/* DCE (Data communications equipment) line settings */
#define IRCOMM_DELTA_CTS        0x01  /* Clear to send has changed */
#define IRCOMM_DELTA_DSR        0x02  /* Data set ready has changed */
#define IRCOMM_DELTA_RI         0x04  /* Ring indicator has changed */
#define IRCOMM_DELTA_CD         0x08  /* Carrier detect has changed */
#define IRCOMM_CTS              0x10  /* Clear to send is high */
#define IRCOMM_DSR              0x20  /* Data set ready is high */
#define IRCOMM_RI               0x40  /* Ring indicator is high */
#define IRCOMM_CD               0x80  /* Carrier detect is high */
#define IRCOMM_DCE_DELTA_ANY    0x0f

void proto_reg_handoff_ircomm(void);

/* Initialize the subtree pointers */
static gint ett_ircomm = -1;
static gint ett_ircomm_ctrl = -1;

#define MAX_PARAMETERS          32
static gint ett_param[MAX_IAP_ENTRIES * MAX_PARAMETERS];

static dissector_handle_t ircomm_raw_handle;
static dissector_handle_t ircomm_cooked_handle;

static int proto_ircomm = -1;
static int hf_ircomm_param = -1;
/* static int hf_param_pi = -1; */
/* static int hf_param_pl = -1; */
/* static int hf_param_pv = -1; */
static int hf_control = -1;
static int hf_control_len = -1;

static gboolean dissect_ircomm_parameters(tvbuff_t* tvb, guint offset, packet_info* pinfo,
                                          proto_tree* tree, guint list_index, guint8 attr_type, guint8 circuit_id);
static gboolean dissect_ircomm_ttp_lsap(tvbuff_t* tvb, guint offset, packet_info* pinfo,
                                        proto_tree* tree, guint list_index, guint8 attr_type, guint8 circuit_id);
static gboolean dissect_ircomm_lmp_lsap(tvbuff_t* tvb, guint offset, packet_info* pinfo,
                                        proto_tree* tree, guint list_index, guint8 attr_type, guint8 circuit_id);

ias_attr_dissector_t ircomm_attr_dissector[] = {
/* IrDA:IrCOMM attribute dissectors */
    { "Parameters",             dissect_ircomm_parameters },
    { "IrDA:TinyTP:LsapSel",    dissect_ircomm_ttp_lsap },
    { NULL,                     NULL }
};

ias_attr_dissector_t irlpt_attr_dissector[] = {
/* IrLPT attribute dissectors */
    { "IrDA:IrLMP:LsapSel", dissect_ircomm_lmp_lsap },
    { "IrDA:IrLMP:LSAPSel", dissect_ircomm_lmp_lsap },  /* according to IrCOMM V1.0, p25 */
    { NULL, NULL }
};


/*
 * Dissect the cooked IrCOMM protocol
 */
static int dissect_cooked_ircomm(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    proto_item *ti;
    proto_tree *ircomm_tree, *ctrl_tree;
    guint offset = 0;
    guint clen;
    gint len = tvb_reported_length(tvb);

    if (len == 0)
        return len;

    /* Make entries in Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IrCOMM");

    clen = tvb_get_guint8(tvb, offset);
    len -= 1 + clen;

    if (len > 0)
        col_add_fstr(pinfo->cinfo, COL_INFO, "Clen=%d, UserData: %d byte%s", clen, len, (len > 1)? "s": "");
    else
        col_add_fstr(pinfo->cinfo, COL_INFO, "Clen=%d", clen);

    /* create display subtree for the protocol */
    ti          = proto_tree_add_item(tree, proto_ircomm, tvb, 0, -1, ENC_NA);
    ircomm_tree = proto_item_add_subtree(ti, ett_ircomm);

    ti        = proto_tree_add_item(ircomm_tree, hf_control, tvb, 0, clen + 1, ENC_NA);
    ctrl_tree = proto_item_add_subtree(ti, ett_ircomm_ctrl);
    proto_tree_add_item(ctrl_tree, hf_control_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    call_data_dissector(tvb_new_subset_length(tvb, offset, clen), pinfo, ctrl_tree);
    offset += clen;

    call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, ircomm_tree);

    return len;
}


/*
 * Dissect the raw IrCOMM/IrLPT protocol
 */
static int dissect_raw_ircomm(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    guint len = tvb_reported_length(tvb);
    proto_item* ti;
    proto_tree* ircomm_tree;

    if (len == 0)
        return 0;

    /* Make entries in Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IrCOMM");

    col_add_fstr(pinfo->cinfo, COL_INFO, "User Data: %d byte%s", len, (len > 1)? "s": "");

    /* create display subtree for the protocol */
    ti   = proto_tree_add_item(tree, proto_ircomm, tvb, 0, -1, ENC_NA);
    ircomm_tree = proto_item_add_subtree(ti, ett_ircomm);

    call_data_dissector(tvb, pinfo, ircomm_tree);

    return len;
}


/*
 * Dissect IrCOMM IAS "Parameters" attribute
 */
static gboolean dissect_ircomm_parameters(tvbuff_t* tvb, guint offset, packet_info* pinfo _U_,
                                          proto_tree* tree, guint list_index, guint8 attr_type, guint8 circuit_id _U_)
{
    guint    len;
    guint    n = 0;
    proto_item* ti;
    proto_tree* p_tree;
    char        buf[256];
    guint8      pv;


    if (!check_iap_octet_result(tvb, tree, offset, "Parameters", attr_type))
        return TRUE;

    if (tree)
    {
        len = tvb_get_ntohs(tvb, offset) + offset + 2;
        offset += 2;

        while (offset < len)
        {
            guint8  p_len = tvb_get_guint8(tvb, offset + 1);


            ti = proto_tree_add_item(tree, hf_ircomm_param, tvb, offset, p_len + 2, ENC_NA);
            p_tree = proto_item_add_subtree(ti, ett_param[list_index * MAX_PARAMETERS + n]);

            buf[0] = 0;

            switch (tvb_get_guint8(tvb, offset))
            {
                case IRCOMM_SERVICE_TYPE:
                    proto_item_append_text(ti, ": Service Type (");

                    pv = tvb_get_guint8(tvb, offset+2);
                    if (pv & IRCOMM_3_WIRE_RAW)
                        g_strlcat(buf, ", 3-Wire raw", 256);
                    if (pv & IRCOMM_3_WIRE)
                        g_strlcat(buf, ", 3-Wire", 256);
                    if (pv & IRCOMM_9_WIRE)
                        g_strlcat(buf, ", 9-Wire", 256);
                    if (pv & IRCOMM_CENTRONICS)
                        g_strlcat(buf, ", Centronics", 256);

                    g_strlcat(buf, ")", 256);

                    proto_item_append_text(ti, "%s", buf+2);

                    break;

                case IRCOMM_PORT_TYPE:
                    proto_item_append_text(ti, ": Port Type (");

                    pv = tvb_get_guint8(tvb, offset+2);
                    if (pv & IRCOMM_SERIAL)
                        g_strlcat(buf, ", serial", 256);
                    if (pv & IRCOMM_PARALLEL)
                        g_strlcat(buf, ", parallel", 256);

                    g_strlcat(buf, ")", 256);

                    proto_item_append_text(ti, "%s", buf+2);

                    break;

                case IRCOMM_PORT_NAME:
                    /* XXX - the IrCOMM V1.0 spec says this "Normally
                       human readable text, but not required". */
                    proto_item_append_text(ti, ": Port Name (\"%s\")",
                        tvb_format_text(tvb, offset+2, p_len));

                    break;

                default:
                    proto_item_append_text(ti, ": unknown");
            }

            offset = dissect_param_tuple(tvb, p_tree, offset);
            n++;
        }

    }

    return TRUE;
}


/*
 * Dissect IrCOMM IAS "IrDA:TinyTP:LsapSel" attribute
 */
static gboolean dissect_ircomm_ttp_lsap(tvbuff_t* tvb, guint offset, packet_info* pinfo,
                                        proto_tree* tree, guint list_index _U_, guint8 attr_type, guint8 circuit_id)
{
    guint8 dlsap;


    if ((dlsap = check_iap_lsap_result(tvb, tree, offset, "IrDA:TinyTP:LsapSel", attr_type)) == 0)
        return FALSE;

    add_lmp_conversation(pinfo, dlsap, TRUE, ircomm_cooked_handle, circuit_id);

    return FALSE;
}


/*
 * Dissect IrCOMM/IrLPT IAS "IrDA:IrLMP:LsapSel" attribute
 */
static gboolean dissect_ircomm_lmp_lsap(tvbuff_t* tvb, guint offset, packet_info* pinfo,
                                        proto_tree* tree, guint list_index _U_, guint8 attr_type, guint8 circuit_id)
{
    guint8 dlsap;


    if ((dlsap = check_iap_lsap_result(tvb, tree, offset, "IrDA:IrLMP:LsapSel", attr_type)) == 0)
        return FALSE;

    add_lmp_conversation(pinfo, dlsap, FALSE, ircomm_raw_handle, circuit_id);

    return FALSE;
}


/*
 * Register the IrCOMM protocol
 */
void proto_register_ircomm(void)
{
    guint i;

    /* Setup list of header fields */
    static hf_register_info hf_ircomm[] = {
        { &hf_ircomm_param,
            { "IrCOMM Parameter", "ircomm.parameter",
                FT_NONE, BASE_NONE, NULL, 0,
                NULL, HFILL }},
#if 0
        { &hf_param_pi,
            { "Parameter Identifier", "ircomm.pi",
                FT_UINT8, BASE_HEX, NULL, 0,
                NULL, HFILL }},
        { &hf_param_pl,
            { "Parameter Length", "ircomm.pl",
                FT_UINT8, BASE_HEX, NULL, 0,
                NULL, HFILL }},
        { &hf_param_pv,
            { "Parameter Value", "ircomm.pv",
                FT_BYTES, BASE_NONE, NULL, 0,
                NULL, HFILL }},
#endif
        { &hf_control,
            { "Control Channel", "ircomm.control",
                FT_NONE, BASE_NONE, NULL, 0,
                NULL, HFILL }},
        { &hf_control_len,
            { "Clen", "ircomm.control.len",
                FT_UINT8, BASE_DEC, NULL, 0,
                NULL, HFILL }}
    };

    /* Setup protocol subtree arrays */
    static gint* ett[] = {
        &ett_ircomm,
        &ett_ircomm_ctrl
    };

    gint* ett_p[MAX_IAP_ENTRIES * MAX_PARAMETERS];


    /* Register protocol names and descriptions */
    proto_ircomm = proto_register_protocol("IrCOMM Protocol", "IrCOMM", "ircomm");
    register_dissector("ircomm_raw", dissect_raw_ircomm, proto_ircomm);
    register_dissector("ircomm_cooked", dissect_cooked_ircomm, proto_ircomm);

    /* Required function calls to register the header fields */
    proto_register_field_array(proto_ircomm, hf_ircomm, array_length(hf_ircomm));

    /* Register subtrees */
    proto_register_subtree_array(ett, array_length(ett));
    for (i = 0; i < MAX_IAP_ENTRIES * MAX_PARAMETERS; i++)
    {
        ett_param[i] = -1;
        ett_p[i]     = &ett_param[i];
    }
    proto_register_subtree_array(ett_p, MAX_IAP_ENTRIES * MAX_PARAMETERS);
}

void
proto_reg_handoff_ircomm(void) {
    ircomm_raw_handle = find_dissector("ircomm_raw");
    ircomm_cooked_handle = find_dissector("ircomm_cooked");
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

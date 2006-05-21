/* packet-ircomm.c
 * Routines for IrCOMM dissection
 * By Jan Kiszka <jan.kiszka@web.de>
 * Copyright 2003 Jan Kiszka
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "moduleinfo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <gmodule.h>
#include <epan/packet.h>
#include <epan/proto.h>


/*
 * See
 *
 *	http://www.irda.org/standards/specifications.asp
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

/* Initialize the subtree pointers */
static gint ett_ircomm = -1;
static gint ett_ircomm_ctrl = -1;

#define MAX_PARAMETERS          32
static gint ett_param[MAX_IAP_ENTRIES * MAX_PARAMETERS];


static int proto_ircomm = -1;
static int hf_ircomm_param = -1;
static int hf_param_pi = -1;
static int hf_param_pl = -1;
static int hf_param_pv = -1;
static int hf_control = -1;
static int hf_control_len = -1;

static gboolean dissect_ircomm_parameters(tvbuff_t* tvb, unsigned offset, packet_info* pinfo,
                                          proto_tree* tree, unsigned list_index, guint8 attr_type);
static gboolean dissect_ircomm_ttp_lsap(tvbuff_t* tvb, unsigned offset, packet_info* pinfo,
                                        proto_tree* tree, unsigned list_index, guint8 attr_type);
static gboolean dissect_ircomm_lmp_lsap(tvbuff_t* tvb, unsigned offset, packet_info* pinfo,
                                        proto_tree* tree, unsigned list_index, guint8 attr_type);

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
static void dissect_cooked_ircomm(tvbuff_t* tvb, packet_info* pinfo, proto_tree* root)
{
    unsigned offset = 0;
    unsigned clen;


    if (tvb_length(tvb) == 0)
        return;

    /* Make entries in Protocol column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "IrCOMM");

    clen = tvb_get_guint8(tvb, offset);

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        char        buf[128];
        unsigned    len = tvb_length(tvb) - 1 - clen;


        if (len > 0)
            sprintf(buf, "Clen=%d, UserData: %d byte%s", clen, len, (len > 1)? "s": "");
        else
            sprintf(buf, "Clen=%d", clen);
        col_add_str(pinfo->cinfo, COL_INFO, buf);
    }

    if (root)
    {
        /* create display subtree for the protocol */
        proto_item* ti   = proto_tree_add_item(root, proto_ircomm, tvb, 0, -1, FALSE);
        proto_tree* tree = proto_item_add_subtree(ti, ett_ircomm);

        proto_tree* ctrl_tree;


        ti        = proto_tree_add_item(tree, hf_control, tvb, 0, clen + 1, FALSE);
        ctrl_tree = proto_item_add_subtree(ti, ett_ircomm_ctrl);
        proto_tree_add_item(ctrl_tree, hf_control_len, tvb, offset, 1, FALSE);
        offset++;
        {
            tvbuff_t *cvalue = tvb_new_subset(tvb, offset, clen, clen);
            call_dissector(data_handle, cvalue, pinfo, ctrl_tree);
            offset += clen;
        }

        tvb = tvb_new_subset(tvb, offset, -1, -1);
        call_dissector(data_handle, tvb, pinfo, tree);
    }
}


/*
 * Dissect the raw IrCOMM/IrLPT protocol
 */
static void dissect_raw_ircomm(tvbuff_t* tvb, packet_info* pinfo, proto_tree* root)
{
    unsigned len = tvb_length(tvb);


    if (len == 0)
        return;

    /* Make entries in Protocol column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "IrCOMM");

    if (check_col(pinfo->cinfo, COL_INFO))
    {
        char    buf[128];


        sprintf(buf, "User Data: %d byte%s", len, (len > 1)? "s": "");
        col_add_str(pinfo->cinfo, COL_INFO, buf);
    }

    if (root)
    {
        /* create display subtree for the protocol */
        proto_item* ti   = proto_tree_add_item(root, proto_ircomm, tvb, 0, -1, FALSE);
        proto_tree* tree = proto_item_add_subtree(ti, ett_ircomm);

        call_dissector(data_handle, tvb, pinfo, tree);
    }
}


/*
 * Dissect IrCOMM IAS "Parameters" attribute
 */
static gboolean dissect_ircomm_parameters(tvbuff_t* tvb, unsigned offset, packet_info* pinfo _U_,
                                          proto_tree* tree, unsigned list_index, guint8 attr_type)
{
    unsigned    len;
    unsigned    n = 0;
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


            ti = proto_tree_add_item(tree, hf_ircomm_param, tvb, offset, p_len + 2, FALSE);
            p_tree = proto_item_add_subtree(ti, ett_param[list_index * MAX_PARAMETERS + n]);

            buf[0] = 0;

            switch (tvb_get_guint8(tvb, offset))
            {
                case IRCOMM_SERVICE_TYPE:
                    proto_item_append_text(ti, ": Service Type (");

                    pv = tvb_get_guint8(tvb, offset+2);
                    if (pv & IRCOMM_3_WIRE_RAW)
                        strcat(buf, ", 3-Wire raw");
                    if (pv & IRCOMM_3_WIRE)
                        strcat(buf, ", 3-Wire");
                    if (pv & IRCOMM_9_WIRE)
                        strcat(buf, ", 9-Wire");
                    if (pv & IRCOMM_CENTRONICS)
                        strcat(buf, ", Centronics");

                    strcat(buf, ")");

                    proto_item_append_text(ti, buf+2);

                    break;

                case IRCOMM_PORT_TYPE:
                    proto_item_append_text(ti, ": Port Type (");

                    pv = tvb_get_guint8(tvb, offset+2);
                    if (pv & IRCOMM_SERIAL)
                        strcat(buf, ", serial");
                    if (pv & IRCOMM_PARALLEL)
                        strcat(buf, ", parallel");

                    strcat(buf, ")");

                    proto_item_append_text(ti, buf+2);

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
static gboolean dissect_ircomm_ttp_lsap(tvbuff_t* tvb, unsigned offset, packet_info* pinfo,
                                        proto_tree* tree, unsigned list_index _U_, guint8 attr_type)
{
    guint8 dlsap;


    if ((dlsap = check_iap_lsap_result(tvb, tree, offset, "IrDA:TinyTP:LsapSel", attr_type)) == 0)
        return FALSE;

    add_lmp_conversation(pinfo, dlsap, TRUE, dissect_cooked_ircomm);

    return FALSE;
}


/*
 * Dissect IrCOMM/IrLPT IAS "IrDA:IrLMP:LsapSel" attribute
 */
static gboolean dissect_ircomm_lmp_lsap(tvbuff_t* tvb, unsigned offset, packet_info* pinfo,
                                        proto_tree* tree, unsigned list_index _U_, guint8 attr_type)
{
    guint8 dlsap;


    if ((dlsap = check_iap_lsap_result(tvb, tree, offset, "IrDA:IrLMP:LsapSel", attr_type)) == 0)
        return FALSE;

    add_lmp_conversation(pinfo, dlsap, FALSE, dissect_raw_ircomm);

    return FALSE;
}


/*
 * Register the IrCOMM protocol
 */
void proto_register_ircomm(void)
{
    unsigned i;

    /* Setup list of header fields */
    static hf_register_info hf_ircomm[] = {
        { &hf_ircomm_param,
            { "IrCOMM Parameter", "ircomm.parameter",
                FT_NONE, BASE_NONE, NULL, 0,
                "", HFILL }},
        { &hf_param_pi,
            { "Parameter Identifier", "ircomm.pi",
                FT_UINT8, BASE_HEX, NULL, 0,
                "", HFILL }},
        { &hf_param_pl,
            { "Parameter Length", "ircomm.pl",
                FT_UINT8, BASE_HEX, NULL, 0,
                "", HFILL }},
        { &hf_param_pv,
            { "Parameter Value", "ircomm.pv",
                FT_BYTES, BASE_HEX, NULL, 0,
                "", HFILL }},
        { &hf_control,
            { "Control Channel", "ircomm.control",
                FT_NONE, BASE_NONE, NULL, 0,
                "", HFILL }},
        { &hf_control_len,
            { "Clen", "ircomm.control.len",
                FT_UINT8, BASE_DEC, NULL, 0,
                "", HFILL }},
    };

    /* Setup protocol subtree arrays */
    static gint* ett[] = {
        &ett_ircomm,
        &ett_ircomm_ctrl
    };

    static gint* ett_p[MAX_IAP_ENTRIES * MAX_PARAMETERS];


    /* Register protocol names and descriptions */
    proto_ircomm = proto_register_protocol("IrCOMM Protocol", "IrCOMM", "ircomm");

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

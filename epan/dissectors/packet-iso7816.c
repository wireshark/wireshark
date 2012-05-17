/* packet-iso7816.c
 * Routines for packet dissection of generic ISO 7816 messages
 * Copyright 2012 by Martin Kaiser <martin@kaiser.cx>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/* This dissector supports the command and response apdu structure
 * as defined in ISO 7816-4. Detailed dissection of the APDUs defined
 * in the ISO 7816 specifications will be added in the future.
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>

static int proto_iso7816 = -1;

static int ett_iso7816 = -1;

static int hf_iso7816_atr = -1;
static int hf_iso7816_cla = -1;
static int hf_iso7816_ins = -1;
static int hf_iso7816_p1 = -1;
static int hf_iso7816_p2 = -1;
static int hf_iso7816_lc = -1;
static int hf_iso7816_le = -1;
static int hf_iso7816_body = -1;
static int hf_iso7816_sw1 = -1;
static int hf_iso7816_sw2 = -1;

#define ADDR_INTF "Interface"
#define ADDR_CARD "Card"

static const value_string iso7816_ins[] = {
    { 0x0E, "Erase binary" },
    { 0x20, "Verify" },
    { 0x70, "Manage channel" },
    { 0x82, "External authenticate" },
    { 0xA4, "Select file" },
    /* other values will be added */
    { 0, NULL }
};


static int
dissect_iso7816_atr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint  offset = 0;

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "ATR sequence");

    proto_tree_add_item(tree, hf_iso7816_atr, tvb, offset,
            tvb_reported_length_remaining(tvb, offset), ENC_NA);
    offset += tvb_reported_length_remaining(tvb, offset);

    return offset;
}

static int
dissect_iso7816_cmd_apdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint   offset = 0;
    gint   body_len;
    guint8 lc;

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Command APDU");

    proto_tree_add_item(tree, hf_iso7816_cla, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_iso7816_ins, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_iso7816_p1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_iso7816_p2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* for now, we support only short length fields
       if we have ATR parsing, we can support extended length fields too */
    body_len = tvb_reported_length_remaining(tvb, offset);

    /* nothing to do for body_len==0 */
    if (body_len==1) {
        proto_tree_add_item(
                tree, hf_iso7816_le, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }
    else if (body_len>1) {
        lc = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(
                tree, hf_iso7816_lc, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        if (lc>0) {
            proto_tree_add_item(tree, hf_iso7816_body, tvb, offset, lc, ENC_NA);
            offset += lc;
        }
        if (tvb_reported_length_remaining(tvb, offset)>0) {
            proto_tree_add_item(
                    tree, hf_iso7816_le, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
        }
    }

    return offset;
}

static int
dissect_iso7816_resp_apdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint  offset = 0;
    gint  body_len;

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Response APDU");

    /* - 2 bytes SW1, SW2 */
    body_len = tvb_reported_length_remaining(tvb, offset) - 2;

    if (body_len>0) {
        proto_tree_add_item(tree, hf_iso7816_body,
                tvb, offset, body_len, ENC_NA);
        offset += body_len;
    }

    if (tvb_reported_length_remaining(tvb, offset) >= 2) {
        proto_tree_add_item(tree, hf_iso7816_sw1,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(tree, hf_iso7816_sw2,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }

    return offset;
}
 
static int
dissect_iso7816(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint                 offset = 0;
    proto_item          *tree_ti = NULL;
    proto_tree          *iso7816_tree = NULL;
    guint8               tmp;

    if (pinfo->p2p_dir!=P2P_DIR_SENT && pinfo->p2p_dir!=P2P_DIR_RECV)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISO 7816");
    col_clear(pinfo->cinfo, COL_INFO);

    if (tree) {
        tree_ti = proto_tree_add_protocol_format(tree, proto_iso7816,
                tvb, 0, tvb_reported_length(tvb), "ISO 7816");
        iso7816_tree = proto_item_add_subtree(tree_ti, ett_iso7816);
    }

    /* per our definition, sent/received is from the perspective of the interface
       i.e sent is from interface to card, received is from card to interface */
    if (pinfo->p2p_dir==P2P_DIR_SENT) {
        SET_ADDRESS(&pinfo->src, AT_STRINGZ,
                (int)strlen(ADDR_INTF)+1, ADDR_INTF);
        SET_ADDRESS(&pinfo->dst, AT_STRINGZ,
                (int)strlen(ADDR_CARD)+1, ADDR_CARD);
        if (tree_ti)
            proto_item_append_text(tree_ti, " Command APDU");
        offset = dissect_iso7816_cmd_apdu(tvb, pinfo, iso7816_tree);
    }
    else if (pinfo->p2p_dir==P2P_DIR_RECV) {
        SET_ADDRESS(&pinfo->src, AT_STRINGZ,
                (int)strlen(ADDR_CARD)+1, ADDR_CARD);
        SET_ADDRESS(&pinfo->dst, AT_STRINGZ,
                (int)strlen(ADDR_INTF)+1, ADDR_INTF);
        tmp = tvb_get_guint8(tvb, offset);
        if (tmp==0x3B || tmp==0x3F) {
            if (tree_ti)
                proto_item_append_text(tree_ti, " ATR");
            offset = dissect_iso7816_atr(tvb, pinfo, iso7816_tree);
        }
        else {
            if (tree_ti)
                proto_item_append_text(tree_ti, " Response APDU");
            offset = dissect_iso7816_resp_apdu(tvb, pinfo, iso7816_tree);
        }
    }

    return offset;
}

void
proto_register_iso7816(void)
{
    static hf_register_info hf[] = {
        { &hf_iso7816_atr,
          { "ATR", "iso7816.atr",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_cla,
            { "Class", "iso7816.apdu.cla",
                FT_UINT8, BASE_HEX, NULL, 0, NULL , HFILL }
        },
        { &hf_iso7816_ins,
            { "Instruction", "iso7816.apdu.ins",
                FT_UINT8, BASE_HEX, VALS(iso7816_ins), 0, NULL, HFILL }
        },
        { &hf_iso7816_p1,
            { "Parameter 1", "iso7816.apdu.p1",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_p2,
            { "Parameter 2", "iso7816.apdu.p2",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_lc,
            { "Length field Lc", "iso7816.apdu.lc",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_le,
            { "Expected response length Le", "iso7816.apdu.le",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_body,
            { "APDU Body", "iso7816.apdu.body",
                FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_sw1,
            { "Status Word SW1", "iso7816.apdu.sw1",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_sw2,
            { "Status Word SW2", "iso7816.apdu.sw2",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        }
    };
    static gint *ett[] = {
        &ett_iso7816
    };

    proto_iso7816 = proto_register_protocol(
            "ISO/IEC 7816", "ISO 7816", "iso7816");
    proto_register_field_array(proto_iso7816, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    new_register_dissector("iso7816", dissect_iso7816, proto_iso7816);
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

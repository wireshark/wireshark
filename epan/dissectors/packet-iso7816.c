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
#include <epan/expert.h>

static int proto_iso7816 = -1;

static int ett_iso7816 = -1;
static int ett_iso7816_atr_td = -1;

static int hf_iso7816_atr_init_char = -1;
static int hf_iso7816_atr_t0 = -1;
static int hf_iso7816_atr_ta = -1;
static int hf_iso7816_atr_tb = -1;
static int hf_iso7816_atr_tc = -1;
static int hf_iso7816_atr_td = -1;
static int hf_iso7816_atr_next_ta_present = -1;
static int hf_iso7816_atr_next_tb_present = -1;
static int hf_iso7816_atr_next_tc_present = -1;
static int hf_iso7816_atr_next_td_present = -1;
static int hf_iso7816_atr_k = -1;
static int hf_iso7816_atr_t = -1;
static int hf_iso7816_atr_hist_bytes = -1;
static int hf_iso7816_atr_tck = -1;
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

static const value_string iso7816_atr_init_char[] = {
    { 0x3B, "Direct convention (A==0, Z==1, MSB==m9)" },
    { 0x3F, "Inverse convention (A==1, Z==0, MSB==m2)" },
    { 0, NULL }
};

static const value_string iso7816_ins[] = {
    /* instructions defined in ISO 7816-4 */
    { 0x0E, "Erase binary" },
    { 0x20, "Verify" },
    { 0x70, "Manage channel" },
    { 0x82, "External authenticate" },
    { 0xA4, "Select file" },
    { 0xB0, "Read binary" },
    { 0xB2, "Read records" },
    { 0xC0, "Get response" },
    { 0xC2, "Envelope" },
    { 0xCA, "Get data" },
    { 0xD0, "Write binary" },
    { 0xD2, "Write record" },
    { 0xD6, "Update binary" },
    { 0xDA, "Put data" },
    { 0xDC, "Update record" },
    { 0xE2, "Append record" },
    { 0, NULL }
};

static const range_string iso7816_sw1[] = {
  { 0x61, 0x61, "Normal processing" },
  { 0x62, 0x63, "Warning processing" },
  { 0x64, 0x65, "Execution error" },
  { 0x67, 0x6F, "Checking error" },
  { 0x90, 0x90, "Normal processing" },
  { 0,0,  NULL }
};


static int
dissect_iso7816_atr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint        offset=0;
    guint       i=0;  /* loop index for TA(i)...TD(i) */
    proto_item *td_it;
    proto_tree *td_tree=NULL;
    guint8      ta, tb, tc, td, k=0;
    gint        tck_len;
    proto_item *err_it;

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "ATR sequence");

    /* ISO 7816-4, section 4 indicates that concatenations are big endian */
    proto_tree_add_item(tree, hf_iso7816_atr_init_char,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    do {
        /* for i==0, this is the T0 byte, otherwise it's the TD(i) byte
           in each loop, we dissect T0/TD(i) and TA(i+1), TB(i+1), TC(i+1) */
        td = tvb_get_guint8(tvb, offset);
        if (i==0) {
            td_it = proto_tree_add_item(tree, hf_iso7816_atr_t0,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
        }
        else {
            td_it = proto_tree_add_uint_format(tree, hf_iso7816_atr_td,
                    tvb, offset, 1, td,
                    "Interface character TD(%d): 0x%02x", i, td);
        }
        td_tree = proto_item_add_subtree(td_it, ett_iso7816_atr_td);

        proto_tree_add_boolean_format(td_tree, hf_iso7816_atr_next_ta_present,
                tvb, offset, 1, td&0x10,
                "TA(%d) present: %s", i+1, td&0x10 ? "True" : "False");
        proto_tree_add_boolean_format(td_tree, hf_iso7816_atr_next_tb_present,
                tvb, offset, 1, td&0x20,
                "TB(%d) present: %s", i+1, td&0x20 ? "True" : "False");
        proto_tree_add_boolean_format(td_tree, hf_iso7816_atr_next_tc_present,
                tvb, offset, 1, td&0x40,
                "TC(%d) present: %s", i+1, td&0x40 ? "True" : "False");
        proto_tree_add_boolean_format(td_tree, hf_iso7816_atr_next_td_present,
                tvb, offset, 1, td&0x80,
                "TD(%d) present: %s", i+1, td&0x80 ? "True" : "False");

        if (i==0) {
            k = td&0x0F;   /* number of historical bytes */
            proto_tree_add_item(td_tree, hf_iso7816_atr_k,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
        }
        else {
            proto_tree_add_item(td_tree, hf_iso7816_atr_t,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
        }
        offset++;

        if (td&0x10) {
            ta = tvb_get_guint8(tvb, offset);
            /* we read TA(i+1), see comment above */
            proto_tree_add_uint_format(tree, hf_iso7816_atr_ta, tvb, offset, 1,
                    ta, "Interface character TA(%d): 0x%02x", i+1, ta);
            offset++;
        }
        if (td&0x20) {
            tb = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format(tree, hf_iso7816_atr_tb, tvb, offset, 1,
                    tb, "Interface character TB(%d): 0x%02x", i+1, tb);
            offset++;
        }
        if (td&0x40) {
            tc = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format(tree, hf_iso7816_atr_tc, tvb, offset, 1,
                    tc, "Interface character TC(%d): 0x%02x", i+1, tc);
            offset++;
        }

        i++;
    } while (td&0x80);

    if (k>0) {
        proto_tree_add_item(tree, hf_iso7816_atr_hist_bytes,
                tvb, offset, k, ENC_NA);
        offset += k;
    }

    tck_len = tvb_reported_length_remaining(tvb, offset);
    /* tck is either absent or exactly one byte */
    if (tck_len==1) {
        proto_tree_add_item(tree, hf_iso7816_atr_tck,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }
    else if (tck_len>1) {
        err_it = proto_tree_add_text(tree, tvb, offset, tck_len,
                "Invalid TCK byte");
        expert_add_info_format(pinfo, err_it, PI_PROTOCOL, PI_WARN,
                "TCK byte must either be absent or exactly one byte");
    }

    return offset;
}

static int
dissect_iso7816_le(
        tvbuff_t *tvb, gint offset, packet_info *pinfo _U_, proto_tree *tree)
{
    guint8      le;
    proto_item *le_item;

    le = tvb_get_guint8(tvb, offset);
    le_item = proto_tree_add_item(
            tree, hf_iso7816_le, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (le==0)
        proto_item_append_text(le_item, " (maximum number of available bytes)");

    return 1;
}


static int
dissect_iso7816_cmd_apdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint   offset = 0;
    guint8 ins;
    gint   body_len;
    guint8 lc;


    proto_tree_add_item(tree, hf_iso7816_cla, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    ins = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_iso7816_ins, tvb, offset, 1, ENC_BIG_ENDIAN);
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s",
            val_to_str_const(ins, iso7816_ins, "Unknown instruction"));
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
        offset += dissect_iso7816_le(tvb, offset, pinfo, tree);
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
            offset += dissect_iso7816_le(tvb, offset, pinfo, tree);
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
        { &hf_iso7816_atr_init_char,
            { "Initial character", "iso7816.atr.init_char",
                FT_UINT8, BASE_HEX, VALS(iso7816_atr_init_char), 0, NULL, HFILL }
        },
        { &hf_iso7816_atr_t0,
            { "Format character T0", "iso7816.atr.t0",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_atr_ta,
            { "Interface character TA(i)", "iso7816.atr.ta",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_atr_tb,
            { "Interface character TB(i)", "iso7816.atr.tb",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_atr_tc,
            { "Interface character TC(i)", "iso7816.atr.tc",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_atr_td,
            { "Interface character TD(i)", "iso7816.atr.td",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_atr_next_ta_present,
            { "TA(i+1) present", "iso7816.atr.next_ta_present",
                FT_BOOLEAN, BASE_HEX, NULL, 0x10, NULL, HFILL }
        },
        { &hf_iso7816_atr_next_tb_present,
            { "TB(i+1) present", "iso7816.atr.next_tb_present",
                FT_BOOLEAN, BASE_HEX, NULL, 0x20, NULL, HFILL }
        },
        { &hf_iso7816_atr_next_tc_present,
            { "TC(i+1) present", "iso7816.atr.next_tc_present",
                FT_BOOLEAN, BASE_HEX, NULL, 0x40, NULL, HFILL }
        },
        { &hf_iso7816_atr_next_td_present,
            { "TD(i+1) present", "iso7816.atr.next_td_present",
                FT_BOOLEAN, BASE_HEX, NULL, 0x80, NULL, HFILL }
        },
        { &hf_iso7816_atr_k,
            { "Number K of historical bytes", "iso7816.atr.k",
                FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }
        },
        { &hf_iso7816_atr_t,
            { "Protocol reference T", "iso7816.atr.t",
                FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL }
        },
        { &hf_iso7816_atr_hist_bytes,
            { "Historical bytes", "iso7816.atr.historical_bytes",
                FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_iso7816_atr_tck,
            { "Check character TCK", "iso7816.atr.tck",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
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
            { "Status Word SW1", "iso7816.apdu.sw1", FT_UINT8,
                BASE_RANGE_STRING|BASE_HEX, RVALS(iso7816_sw1), 0, NULL, HFILL }
        },
        { &hf_iso7816_sw2,
            { "Status Word SW2", "iso7816.apdu.sw2",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        }
    };
    static gint *ett[] = {
        &ett_iso7816,
        &ett_iso7816_atr_td
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

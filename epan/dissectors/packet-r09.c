/*
 * R09.x public transport priority telegrams
 *
 * Anlagen zu VOEV 04.05 "LSA/R09.14 and R09.16"
 * https://www.vdv.de/voev-04-05-1-erg.pdfx
 *
 * Copyright 2020, Tomas Kukosa
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

#define PNAME  "R09.x"
#define PSNAME "R09"
#define PFNAME "r09"

static int proto_r09 = -1;
static int hf_r09_modus = -1;
static int hf_r09_ty = -1;
static int hf_r09_tl = -1;
static int hf_r09_zv = -1;
static int hf_r09_zw = -1;
static int hf_r09_mp8 = -1;
static int hf_r09_mp16 = -1;
static int hf_r09_pr = -1;
static int hf_r09_ha = -1;
static int hf_r09_ln = -1;
static int hf_r09_kn = -1;
static int hf_r09_zn = -1;
static int hf_r09_zl = -1;
static int hf_r09_fn = -1;
static int hf_r09_un = -1;

static gint ett_r09 = -1;

static dissector_handle_t r09_handle;

static const value_string r09_zv_vals[] = {
    { 0x00, "Verspätung" },
    { 0x01, "Verfrühung/Vorsprung" },
    {0, NULL}
};

static const value_string r09_ha_vals[] = {
    { 0x00, "Ohne Bedeutung" },
    { 0x01, "Taste 'gerade' betätig" },
    { 0x02, "Taste 'links' betätig" },
    { 0x03, "Taste 'rechts' betätig" },
    {0, NULL}
};

static dgt_set_t Dgt1_9_bcd = {
    {
        /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f */
           '0','1','2','3','4','5','6','7','8','9','?','?','?','?','?','?'
    }
};

static int
dissect_r09(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    proto_item *ti= NULL;
    proto_tree *r09_tree = NULL;
    guint8 ib1, ib2;
    guint8 ty, tl;
    guint16 mp;
    const gchar *r09x_str, *ln_str, *kn_str, *zn_str, *fn_str, *un_str;

    ib1 = tvb_get_guint8(tvb, 0);
    ty = ib1 & 0x0F;

    if (ib1 != 0x91) {
        return 0;
    }

    ib2 = tvb_get_guint8(tvb, 1);
    tl = ib2 & 0x0F;

    r09x_str = wmem_strdup_printf(wmem_packet_scope(), "R09.%u%u", ty, tl);
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", r09x_str);

    ti = proto_tree_add_protocol_format(tree, proto_r09, tvb, 0, -1, "%s", r09x_str);
    r09_tree = proto_item_add_subtree(ti, ett_r09);

    /* Infobyte 1 */
    proto_tree_add_item(r09_tree, hf_r09_modus, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(r09_tree, hf_r09_ty, tvb, 0, 1, ENC_BIG_ENDIAN);

    /* Infobyte 2 */
    proto_tree_add_item(r09_tree, hf_r09_zv, tvb, 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(r09_tree, hf_r09_zw, tvb, 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(r09_tree, hf_r09_tl, tvb, 1, 1, ENC_BIG_ENDIAN);

    if (tl == 0) {
        /* Infobyte 3 */
        proto_tree_add_item(r09_tree, hf_r09_mp8, tvb, 2, 1, ENC_BIG_ENDIAN);
        mp = tvb_get_guint8(tvb, 2);
    } else {
        /* Infobyte 3, Zusatzbyte 1 */
        proto_tree_add_item(r09_tree, hf_r09_mp16, tvb, 2, 2, ENC_BIG_ENDIAN);
        mp = tvb_get_guint16(tvb, 2, ENC_BIG_ENDIAN);
    }
    col_append_fstr(pinfo->cinfo, COL_INFO, " MP=%u", mp);

    if (tl >= 2) {
        /* Zusatzbyte 2 */
        proto_tree_add_item(r09_tree, hf_r09_pr, tvb, 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(r09_tree, hf_r09_ha, tvb, 4, 1, ENC_BIG_ENDIAN);
    }

    if (tl >= 3) {
        /* Zusatzbyte 2, 3 */
        ln_str = tvb_get_bcd_string(wmem_packet_scope(), tvb, 4, 2, &Dgt1_9_bcd, TRUE, FALSE, TRUE);
        proto_tree_add_string(r09_tree, hf_r09_ln, tvb, 4, 2, ln_str);
    }

    if (tl >= 4) {
        /* Zusatzbyte 4 */
        kn_str = tvb_get_bcd_string(wmem_packet_scope(), tvb, 6, 1, &Dgt1_9_bcd, FALSE, FALSE, TRUE);
        proto_tree_add_string(r09_tree, hf_r09_kn, tvb, 6, 1, kn_str);
    }

    if (tl >= 6) {
        /* Zusatzbyte 5, 6 */
        zn_str = tvb_get_bcd_string(wmem_packet_scope(), tvb, 7, 2, &Dgt1_9_bcd, FALSE, TRUE, TRUE);
        proto_tree_add_string(r09_tree, hf_r09_zn, tvb, 7, 2, zn_str);
    }

    if (tl == 6) {
        /* Zusatzbyte 6 */
        proto_tree_add_item(r09_tree, hf_r09_zl, tvb, 8, 1, ENC_BIG_ENDIAN);
    }

    if (tl == 8) {
        /* Zusatzbyte 6, 7, 8 */
        fn_str = tvb_get_bcd_string(wmem_packet_scope(), tvb, 8, 2, &Dgt1_9_bcd, TRUE, FALSE, TRUE);
        proto_tree_add_string(r09_tree, hf_r09_fn, tvb, 8, 2, fn_str);
        un_str = tvb_get_bcd_string(wmem_packet_scope(), tvb, 10, 1, &Dgt1_9_bcd, FALSE, FALSE, TRUE);
        proto_tree_add_string(r09_tree, hf_r09_un, tvb, 10, 1, un_str);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_r09(void)
{

    static hf_register_info hf[] = {
        { &hf_r09_modus, { "Modus", "r09.modus",
            FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL}
        },
        { &hf_r09_ty, { "TY", "r09.ty",
            FT_UINT8, BASE_DEC, NULL, 0x0F, "Typ", HFILL}
        },
        { &hf_r09_zv, { "ZV", "r09.zv",
            FT_UINT8, BASE_DEC, VALS(r09_zv_vals), 0x80, "Vorzeichen einer Fahrplanabweichung", HFILL}
        },
        { &hf_r09_zw, { "ZW", "r09.zw",
            FT_UINT8, BASE_DEC, NULL, 0x70, "Betrag einer Fahrplanabweichung", HFILL}
        },
        { &hf_r09_tl, { "TL", "r09.tl",
            FT_UINT8, BASE_DEC, NULL, 0x0F, "Anzahl der Zusatzbytes", HFILL}
        },
        { &hf_r09_mp8, { "MP", "r09.mp",
            FT_UINT8, BASE_DEC_HEX, NULL, 0x00, "Meldepunktnummer", HFILL}
        },
        { &hf_r09_mp16, { "MP", "r09.mp",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x00, "Meldepunktnummer", HFILL}
        },
        { &hf_r09_pr, { "PR", "r09.pr",
            FT_UINT8, BASE_DEC, NULL, 0xC0, "Priorität", HFILL}
        },
        { &hf_r09_ha, { "HA", "r09.ha",
            FT_UINT8, BASE_DEC, VALS(r09_ha_vals), 0x30, "Anforderung manuell ausgelöst", HFILL}
        },
        { &hf_r09_ln, { "LN", "r09.ln",
            FT_STRING, BASE_NONE, NULL, 0x00, "Liniennummer", HFILL}
        },
        { &hf_r09_kn, { "KN", "r09.kn",
            FT_STRING, BASE_NONE, NULL, 0x00, "Kuzrsnummer", HFILL}
        },
        { &hf_r09_zn, { "ZN", "r09.zn",
            FT_STRING, BASE_NONE, NULL, 0x00, "Zielnummer", HFILL}
        },
        { &hf_r09_zl, { "ZL", "r09.zl",
            FT_UINT8, BASE_DEC, NULL, 0x07, "Zuglänge", HFILL}
        },
        { &hf_r09_fn, { "FN", "r09.fn",
            FT_STRING, BASE_NONE, NULL, 0x00, "Fahrzeugnummer", HFILL}
        },
        { &hf_r09_un, { "UN", "r09.un",
            FT_STRING, BASE_NONE, NULL, 0x00, "Unternehmer", HFILL}
        },
    };

    static gint* ett[] = {
        &ett_r09,
    };

    proto_r09 = proto_register_protocol(PNAME, PSNAME, PFNAME);

    proto_register_subtree_array(ett, array_length(ett));
    proto_register_field_array(proto_r09, hf,array_length(hf));

    r09_handle = register_dissector(PFNAME, dissect_r09, proto_r09);

}

void
proto_reg_handoff_r09(void)
{

    if (find_dissector_table("cam.ptat")) {
        dissector_add_uint("cam.ptat", 1, r09_handle);
    }

}

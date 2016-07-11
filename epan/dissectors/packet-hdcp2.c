/* packet-hdcp2.c
 * Routines for HDCP2 dissection
 * Copyright 2011-2012, Martin Kaiser <martin@kaiser.cx>
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

/*
 * This dissector supports HDCP 2.x over TCP. For now, only the
 * authentication protocol messages are supported.
 *
 * The specification of version 2 of the protocol can be found at
 * http://www.digital-cp.com/files/static_page_files/DABB540C-1A4B-B294-D0008CB2D348FA19/HDCP Interface Independent Adaptation Specification Rev2_1.pdf
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/ptvcursor.h>
#include <epan/expert.h>

void proto_register_hdcp2(void);
void proto_reg_handoff_hdcp2(void);

static int proto_hdcp2 = -1;

static gint ett_hdcp2 = -1;
static gint ett_hdcp2_cert = -1;

static int hf_hdcp2_msg_id = -1;
static int hf_hdcp2_r_tx = -1;
static int hf_hdcp2_repeater = -1;
static int hf_hdcp2_cert_rcv_id = -1;
static int hf_hdcp2_cert_n = -1;
static int hf_hdcp2_cert_e = -1;
static int hf_hdcp2_cert_rcv_sig = -1;
static int hf_hdcp2_e_kpub_km = -1;
static int hf_hdcp2_e_kh_km = -1;
static int hf_hdcp2_m = -1;
static int hf_hdcp2_r_rx = -1;
static int hf_hdcp2_h_prime = -1;
static int hf_hdcp2_r_n = -1;
static int hf_hdcp2_l_prime = -1;
static int hf_hdcp2_e_dkey_ks = -1;
static int hf_hdcp2_r_iv = -1;
static int hf_hdcp2_reserved = -1;

static expert_field ei_hdcp2_reserved_0 = EI_INIT;


#define ID_AKE_INIT              2
#define ID_AKE_SEND_CERT         3
#define ID_AKE_NO_STORED_KM      4
#define ID_AKE_STORED_KM         5
#define ID_AKE_SEND_RRX          6
#define ID_AKE_SEND_H_PRIME      7
#define ID_AKE_SEND_PAIRING_INFO 8
#define ID_LC_INIT               9
#define ID_LC_SEND_L_PRIME      10
#define ID_SKE_SEND_EKS         11
#define ID_MAX                  31

#define RCV_ID_LEN    5  /* all lengths are in bytes */
#define N_LEN       128
#define E_LEN         3
#define RCV_SIG_LEN 384

#define CERT_RX_LEN   (RCV_ID_LEN + N_LEN + E_LEN + 2 + RCV_SIG_LEN)

static const value_string hdcp2_msg_id[] = {
    { ID_AKE_INIT,              "AKE_Init" },
    { ID_AKE_SEND_CERT,         "AKE_Send_Cert" },
    { ID_AKE_NO_STORED_KM,      "AKE_No_Stored_km" },
    { ID_AKE_STORED_KM,         "AKE_Stored_km" },
    { ID_AKE_SEND_RRX,          "AKE_Send_rrx" },
    { ID_AKE_SEND_H_PRIME,      "AKE_Send_H_prime" },
    { ID_AKE_SEND_PAIRING_INFO, "AKE_Send_Pairing_Info" },
    { ID_LC_INIT,               "LC_Init" },
    { ID_LC_SEND_L_PRIME,       "LC_Send_L_prime" },
    { ID_SKE_SEND_EKS,          "SKE_Send_Eks" },
    { 0, NULL }
};

typedef struct _msg_info_t {
    guint8  id;
    guint16 len;  /* number of bytes following initial msg_id field */
} msg_info_t;

static GHashTable *msg_table = NULL;

static const msg_info_t msg_info[] = {
    { ID_AKE_INIT,               8 },
    { ID_AKE_SEND_CERT,        1+CERT_RX_LEN },
    { ID_AKE_NO_STORED_KM,     128 },
    { ID_AKE_STORED_KM,         32 },
    { ID_AKE_SEND_RRX,           8 },
    { ID_AKE_SEND_H_PRIME,      32 },
    { ID_AKE_SEND_PAIRING_INFO, 16 },
    { ID_LC_INIT,                8 },
    { ID_LC_SEND_L_PRIME,       32 },
    { ID_SKE_SEND_EKS,          24 }
};


static int
dissect_hdcp2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    msg_info_t *mi;
    proto_item *pi;
    proto_tree *hdcp_tree, *cert_tree;
    guint8 msg_id;
    gboolean repeater;
    guint16 reserved;
    ptvcursor_t *cursor;

    /* do the plausibility checks before setting up anything */

    /* make sure that tvb_get_guint8() won't throw an exception */
    if (tvb_captured_length(tvb) < 1)
        return 0;
    msg_id = tvb_get_guint8(tvb, 0);
    if (msg_id > ID_MAX)
        return 0;

    mi = (msg_info_t *)g_hash_table_lookup(msg_table,
            GUINT_TO_POINTER((guint)msg_id));
    /* 1 -> start after msg_id byte */
    if (!mi || mi->len!=tvb_reported_length_remaining(tvb, 1))
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HDCP2");
    col_clear(pinfo->cinfo, COL_INFO);

    pi = proto_tree_add_protocol_format(tree, proto_hdcp2,
            tvb, 0, tvb_reported_length(tvb), "HDCP2");
    hdcp_tree = proto_item_add_subtree(pi, ett_hdcp2);
    cursor = ptvcursor_new(hdcp_tree, tvb, 0);

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s",
                    val_to_str(msg_id, hdcp2_msg_id, "unknown (0x%x)"));
    ptvcursor_add(cursor, hf_hdcp2_msg_id, 1, ENC_BIG_ENDIAN);

    switch (msg_id) {
        case ID_AKE_INIT:
            ptvcursor_add(cursor, hf_hdcp2_r_tx, 8, ENC_BIG_ENDIAN);
            break;
        case ID_AKE_SEND_CERT:
            repeater = ((tvb_get_guint8(tvb, ptvcursor_current_offset(cursor))
                        & 0x01) == 0x01);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s",
                    repeater ? "repeater" : "no repeater");
            ptvcursor_add(cursor, hf_hdcp2_repeater, 1, ENC_BIG_ENDIAN);
            cert_tree = ptvcursor_add_text_with_subtree(cursor, CERT_RX_LEN,
                    ett_hdcp2_cert, "%s", "HDCP2 Certificate");
            ptvcursor_add(cursor, hf_hdcp2_cert_rcv_id, RCV_ID_LEN, ENC_NA);
            ptvcursor_add(cursor, hf_hdcp2_cert_n, N_LEN, ENC_NA);
            ptvcursor_add(cursor, hf_hdcp2_cert_e, E_LEN, ENC_BIG_ENDIAN);
            reserved = tvb_get_ntohs(tvb, ptvcursor_current_offset(cursor));
            pi = proto_tree_add_item(cert_tree, hf_hdcp2_reserved, tvb,
                        ptvcursor_current_offset(cursor), 2, ENC_BIG_ENDIAN);
            if (reserved != 0) {
                expert_add_info(pinfo, pi, &ei_hdcp2_reserved_0);
            }
            ptvcursor_advance(cursor, 2);
            ptvcursor_add(cursor, hf_hdcp2_cert_rcv_sig, RCV_SIG_LEN, ENC_NA);
            ptvcursor_pop_subtree(cursor);
            break;
        case ID_AKE_NO_STORED_KM:
            ptvcursor_add(cursor, hf_hdcp2_e_kpub_km, 128, ENC_NA);
            break;
        case ID_AKE_STORED_KM:
            ptvcursor_add(cursor, hf_hdcp2_e_kh_km, 16, ENC_NA);
            ptvcursor_add(cursor, hf_hdcp2_m, 16, ENC_NA);
            break;
        case ID_AKE_SEND_RRX:
            ptvcursor_add(cursor, hf_hdcp2_r_rx, 8, ENC_BIG_ENDIAN);
            break;
        case ID_AKE_SEND_H_PRIME:
            ptvcursor_add(cursor, hf_hdcp2_h_prime, 32, ENC_NA);
            break;
        case ID_AKE_SEND_PAIRING_INFO:
            ptvcursor_add(cursor, hf_hdcp2_e_kh_km, 16, ENC_NA);
            break;
        case ID_LC_INIT:
            ptvcursor_add(cursor, hf_hdcp2_r_n, 8, ENC_BIG_ENDIAN);
            break;
        case ID_LC_SEND_L_PRIME:
            ptvcursor_add(cursor, hf_hdcp2_l_prime, 32, ENC_NA);
            break;
        case ID_SKE_SEND_EKS:
            ptvcursor_add(cursor, hf_hdcp2_e_dkey_ks, 16, ENC_NA);
            ptvcursor_add(cursor, hf_hdcp2_r_iv, 8, ENC_BIG_ENDIAN);
            break;
        default:
            break;
    }

    ptvcursor_free(cursor);
    return tvb_reported_length(tvb);
}



void
proto_register_hdcp2(void)
{
    guint i;

    static hf_register_info hf[] = {
        { &hf_hdcp2_msg_id,
            { "Message ID", "hdcp2.msg_id", FT_UINT8, BASE_HEX,
                VALS(hdcp2_msg_id), 0, NULL, HFILL } },
        { &hf_hdcp2_r_tx,
            { "r_tx", "hdcp2.r_tx", FT_UINT64, BASE_HEX,
                NULL, 0, NULL, HFILL } },
        { &hf_hdcp2_repeater,
            { "Repeater", "hdcp2.repeater", FT_BOOLEAN, 8,
                NULL, 0x1, NULL, HFILL } },
        { &hf_hdcp2_cert_rcv_id,
            { "Receiver ID", "hdcp2.cert.rcv_id", FT_BYTES, BASE_NONE,
                NULL, 0, NULL, HFILL } },
        { &hf_hdcp2_cert_n,
            { "Receiver RSA key n", "hdcp2.cert.n", FT_BYTES, BASE_NONE,
                NULL, 0, NULL, HFILL } },
        { &hf_hdcp2_cert_e,
            { "Receiver RSA key e", "hdcp2.cert.e", FT_UINT24, BASE_HEX,
                NULL, 0, NULL, HFILL } },
        { &hf_hdcp2_cert_rcv_sig,
            { "Receiver signature", "hdcp2.cert.rcv_sig", FT_BYTES,
                BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_hdcp2_e_kpub_km,
            { "E_kpub_km", "hdcp2.e_kpub_km", FT_BYTES, BASE_NONE,
                NULL, 0, NULL, HFILL } },
        { &hf_hdcp2_e_kh_km,
            { "E_kh_km", "hdcp2.e_kh_km", FT_BYTES, BASE_NONE,
                NULL, 0, NULL, HFILL } },
        { &hf_hdcp2_m,
            { "m", "hdcp2.m", FT_BYTES, BASE_NONE,
                NULL, 0, NULL, HFILL } },
        { &hf_hdcp2_r_rx,
            { "r_rx", "hdcp2.r_rx", FT_UINT64, BASE_HEX,
                NULL, 0, NULL, HFILL } },
        { &hf_hdcp2_h_prime,
            { "H'", "hdcp2.h_prime", FT_BYTES, BASE_NONE,
                NULL, 0, NULL, HFILL } },
        { &hf_hdcp2_r_n,
            { "r_n", "hdcp2.r_n", FT_UINT64, BASE_HEX,
                NULL, 0, NULL, HFILL } },
        { &hf_hdcp2_l_prime,
            { "L'", "hdcp2.l_prime", FT_BYTES, BASE_NONE,
                NULL, 0, NULL, HFILL } },
        { &hf_hdcp2_e_dkey_ks,
            { "E_dkey_ks", "hdcp2.e_dkey_ks", FT_BYTES, BASE_NONE,
                NULL, 0, NULL, HFILL } },
        { &hf_hdcp2_r_iv,
            { "r_iv", "hdcp2.r_iv", FT_UINT64, BASE_HEX,
                NULL, 0, NULL, HFILL } },
        { &hf_hdcp2_reserved,
            { "Reserved", "hdcp2.reserved", FT_UINT16, BASE_HEX,
                NULL, 0, NULL, HFILL } }

};

    static gint *ett[] = {
        &ett_hdcp2,
        &ett_hdcp2_cert
    };

    static ei_register_info ei[] = {
        { &ei_hdcp2_reserved_0, { "hdcp2.reserved.not0", PI_PROTOCOL, PI_WARN, "reserved bytes must be set to 0x0", EXPFILL }},
    };

    module_t *hdcp2_module;
    expert_module_t* expert_hdcp2;

    msg_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    for(i=0; i<array_length(msg_info); i++) {
        g_hash_table_insert(msg_table,
                GUINT_TO_POINTER((guint)msg_info[i].id),
                (gpointer)(&msg_info[i]));
    }

    proto_hdcp2 = proto_register_protocol(
            "High bandwidth Digital Content Protection version 2",
            "HDCP2", "hdcp2");

    hdcp2_module = prefs_register_protocol(proto_hdcp2, proto_reg_handoff_hdcp2);
    prefs_register_obsolete_preference(hdcp2_module, "enable");

    proto_register_field_array(proto_hdcp2, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_hdcp2 = expert_register_protocol(proto_hdcp2);
    expert_register_field_array(expert_hdcp2, ei, array_length(ei));

    register_dissector("hdcp2", dissect_hdcp2, proto_hdcp2);
}

void
proto_reg_handoff_hdcp2(void)
{
    static gboolean prefs_initialized = FALSE;

    if (!prefs_initialized) {
        heur_dissector_add ("tcp", dissect_hdcp2, "HDCP2 over TCP", "hdcp2_tcp", proto_hdcp2, HEURISTIC_DISABLE);

        prefs_initialized = TRUE;
    }
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

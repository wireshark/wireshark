/* packet-dtcp-ip.c
 * Routines for DTCP-IP dissection
 *  (Digital Transmission Content Protection over IP)
 *
 * Copyright 2012, Martin Kaiser <martin@kaiser.cx>
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
 * quote from www.dtcp.com:
 * "DTCP is a method of protecting audio and audiovisual entertainment
 *  content on home and personal networks over highbandwidth bidirectional
 *  digital interfaces"
 *
 * this dissector supports DTCP on top of TCP/IP
 * for now, only the AKE (authentication and key exchange)
 *  messages are implemented
 *
 * the dissector is based on the publicly available (informative) specifications
 * obtained from http://www.dtcp.com/specifications.aspx
 * (complete specifications are available only to licensees)
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

static int proto_dtcp_ip = -1;

static guint pref_tcp_port = 0;

void proto_register_dtcp_ip(void);
void proto_reg_handoff_dtcp_ip(void);

static gint ett_dtcp_ip = -1;
static gint ett_dtcp_ip_ctrl = -1;
static gint ett_dtcp_ip_ake_procedure = -1;

static int hf_dtcp_ip_type = -1;
static int hf_dtcp_ip_length = -1;
static int hf_dtcp_ip_ctype = -1;
static int hf_dtcp_ip_category = -1;
static int hf_dtcp_ip_ake_id = -1;
static int hf_dtcp_ip_subfct = -1;
static int hf_dtcp_ip_ake_procedure = -1;
static int hf_dtcp_ip_ake_proc_full = -1;
static int hf_dtcp_ip_ake_proc_ex_full = -1;
static int hf_dtcp_ip_ake_xchg_key = -1;
static int hf_dtcp_ip_subfct_dep = -1;
static int hf_dtcp_ip_ake_label = -1;
static int hf_dtcp_ip_number = -1;
static int hf_dtcp_ip_status = -1;
static int hf_dtcp_ip_ake_info = -1;

#define CTRL_LEN 8 /* control block is 8 bytes long */

/* these definitions are taken from the public DTCP specification
   it sounds like the private version defines more subfunctions */
static const value_string subfct[] = {
    { 0x01, "challenge" },
    { 0x02, "response" },
    { 0x03, "exchange_key" },
    { 0, NULL }
};

static const int *ake_procedure_fields[] = { /* must be int, not gint */
    &hf_dtcp_ip_ake_proc_full,
    &hf_dtcp_ip_ake_proc_ex_full,
    NULL
};

/* only one bit may be set in exchange_key, we can use a value string */
static const value_string xchg_key[] = {
    { 0x00, "None" },
    { 0x08, "Exchange key (K_X) for AES-128" },
    { 0x20, "Session Exchange key (K_S) for AES-128" },
    { 0x40, "Remote Exchange key (K_R) for AES-128" },
    { 0, NULL }
};

static const value_string ctrl_status[] = {
    { 0x0, "No error" },
    { 0x1, "Support for no more authentication procedures is currently available" },
    { 0x7, "Any other error" },
    { 0xF, "No information" },
    { 0, NULL }
};


/* check if the packet is actually DTCP-IP */
static gboolean
dtcp_ip_check_packet(tvbuff_t *tvb)
{
    guint  offset = 0;
    guint8   type;
    guint16  length;

    /* a minimum DTCP-IP AKE packet has Type (1 byte),
       Length (2 bytes) and Control (8 bytes) */
    if (tvb_reported_length(tvb) < 1+2+CTRL_LEN)
        return FALSE;

    type = tvb_get_guint8(tvb, offset);
    /* all DTCP-IP AKE packets have type 1 */
    if (type != 1)
        return FALSE;
    offset++;

    /* length field is length of the control block +
       length of ake_info */
    length = tvb_get_ntohs(tvb, offset);
    if (length < CTRL_LEN)
        return FALSE;

    return TRUE;
}

static int
dissect_dtcp_ip(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, void *data _U_)
{
    guint        offset = 0;
    guint16      length;
    proto_item  *pi;
    proto_tree  *dtcp_ip_tree, *dtcp_ip_ctrl_tree;
    guint8       subfct_val;
    const gchar *subfct_str;
    gint         ake_info_len;


    if (!dtcp_ip_check_packet(tvb))
        return 0; /* not a DTCP-IP packet */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DTCP-IP");
    col_clear(pinfo->cinfo, COL_INFO);

    pi = proto_tree_add_protocol_format(tree, proto_dtcp_ip,
                tvb, 0, -1, "DTCP-IP");
    dtcp_ip_tree = proto_item_add_subtree(pi, ett_dtcp_ip);

    proto_tree_add_item(dtcp_ip_tree, hf_dtcp_ip_type,
        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    length = tvb_get_ntohs(tvb, 1);
    /* overall packet length is 1 byte for tag + 2 bytes for length field +
       the value encoded in the length field */
    proto_item_set_len(pi, 1+2+length);
    proto_tree_add_item(dtcp_ip_tree, hf_dtcp_ip_length,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    dtcp_ip_ctrl_tree = proto_tree_add_subtree(dtcp_ip_tree,
            tvb, offset, CTRL_LEN, ett_dtcp_ip_ctrl, NULL, "Control");

    /* for now, we don't display the 4 reserved bits */
    proto_tree_add_item(dtcp_ip_ctrl_tree, hf_dtcp_ip_ctype,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(dtcp_ip_ctrl_tree, hf_dtcp_ip_category,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(dtcp_ip_ctrl_tree, hf_dtcp_ip_ake_id,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    subfct_val = tvb_get_guint8(tvb, offset);
    subfct_str = val_to_str_const(subfct_val, subfct, "unknown");
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL,
            "%s (0x%x)", subfct_str, subfct_val);
    proto_tree_add_item(dtcp_ip_ctrl_tree, hf_dtcp_ip_subfct,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_bitmask(dtcp_ip_ctrl_tree, tvb, offset,
            hf_dtcp_ip_ake_procedure, ett_dtcp_ip_ake_procedure,
            ake_procedure_fields, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(dtcp_ip_ctrl_tree, hf_dtcp_ip_ake_xchg_key,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(dtcp_ip_ctrl_tree, hf_dtcp_ip_subfct_dep,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(dtcp_ip_ctrl_tree, hf_dtcp_ip_ake_label,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(dtcp_ip_ctrl_tree, hf_dtcp_ip_number,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(dtcp_ip_ctrl_tree, hf_dtcp_ip_status,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    ake_info_len = length-CTRL_LEN;
    if (ake_info_len > 0) {
        proto_tree_add_item(dtcp_ip_tree, hf_dtcp_ip_ake_info,
                tvb, offset, ake_info_len, ENC_NA);
        offset += (guint)ake_info_len;
    }

    return offset;
}


void
proto_register_dtcp_ip(void)
{
    static hf_register_info hf[] = {
        { &hf_dtcp_ip_type,
            { "Type", "dtcp-ip.type", FT_UINT8, BASE_HEX,
                NULL, 0, NULL, HFILL } },
        { &hf_dtcp_ip_length,
            { "Length", "dtcp-ip.length", FT_UINT16, BASE_DEC,
                NULL, 0, NULL, HFILL } },
        /* it seems that / is not allowed in a filter name ... */
        { &hf_dtcp_ip_ctype,
            { "ctype/response", "dtcp-ip.ctrl.ctype_response", FT_UINT8,
                BASE_HEX, NULL, 0x0F, NULL, HFILL } },
        { &hf_dtcp_ip_category,
            { "Category", "dtcp-ip.ctrl.category", FT_UINT8, BASE_HEX,
                NULL, 0xF0, NULL, HFILL } },
        { &hf_dtcp_ip_ake_id,
            { "AKE_ID", "dtcp-ip.ctrl.ake_id", FT_UINT8, BASE_HEX,
                NULL, 0x0F, NULL, HFILL } },
        { &hf_dtcp_ip_subfct,
            { "Subfunction", "dtcp-ip.ctrl.subfunction", FT_UINT8, BASE_HEX,
                VALS(subfct), 0, NULL, HFILL } },
        { &hf_dtcp_ip_ake_procedure,
            { "AKE_procedure", "dtcp-ip.ctrl.ake_procedure", FT_UINT8,
                BASE_HEX, NULL, 0, NULL, HFILL } },
        /* 8 is the bit witdh of the field */
        { &hf_dtcp_ip_ake_proc_full,
            { "Full Authentication procedure",
                "dtcp-ip.ctrl.ake_procedure.full_auth", FT_BOOLEAN, 8,
                NULL, 0x04, NULL, HFILL } },
        { &hf_dtcp_ip_ake_proc_ex_full,
            { "Extended Full Authentication procedure",
                "dtcp-ip.ctrl.ake_procedure.ex_full_auth", FT_BOOLEAN, 8,
                NULL, 0x08, NULL, HFILL } },
        { &hf_dtcp_ip_ake_xchg_key,
            { "exchange_key", "dtcp-ip.ctrl.exchange_key", FT_UINT8, BASE_HEX,
                VALS(xchg_key), 0, NULL, HFILL } },
        { &hf_dtcp_ip_subfct_dep,
            { "subfunction_dependent", "dtcp-ip.ctrl.subfunction_dependent",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_dtcp_ip_ake_label,
            { "AKE_label", "dtcp-ip.ctrl.ake_label", FT_UINT8, BASE_HEX,
                NULL, 0, NULL, HFILL } },
        { &hf_dtcp_ip_number,
            { "number", "dtcp-ip.ctrl.number", FT_UINT8, BASE_HEX,
                NULL, 0xF0, NULL, HFILL } },
        { &hf_dtcp_ip_status,
            { "Status", "dtcp-ip.ctrl.status", FT_UINT8, BASE_HEX,
                VALS(ctrl_status), 0x0F, NULL, HFILL } },
        { &hf_dtcp_ip_ake_info,
            { "AKE_Info", "dtcp-ip.ake_info", FT_BYTES, BASE_NONE,
                NULL, 0, NULL, HFILL } }
    };

    static gint *ett[] = {
        &ett_dtcp_ip,
        &ett_dtcp_ip_ctrl,
        &ett_dtcp_ip_ake_procedure
    };

    module_t *dtcp_ip_module;

    proto_dtcp_ip = proto_register_protocol(
            "Digital Transmission Content Protection over IP",
            "DTCP-IP", "dtcp-ip");

    proto_register_field_array(proto_dtcp_ip, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    dtcp_ip_module = prefs_register_protocol(
            proto_dtcp_ip, proto_reg_handoff_dtcp_ip);
    prefs_register_uint_preference(dtcp_ip_module, "tcp.port",
            "TCP port", "TCP port number for DTCP-IP", 10, &pref_tcp_port);
}

void
proto_reg_handoff_dtcp_ip(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t dtcp_ip_handle = NULL;
    static guint current_tcp_port = 0;

    if (!initialized) {
        dtcp_ip_handle =
            create_dissector_handle(dissect_dtcp_ip, proto_dtcp_ip);
        initialized = TRUE;
    }
    else
        dissector_delete_uint("tcp.port", current_tcp_port, dtcp_ip_handle);

    current_tcp_port = pref_tcp_port;
    dissector_add_uint("tcp.port", current_tcp_port, dtcp_ip_handle);
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

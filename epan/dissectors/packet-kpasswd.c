/* packet-kpasswd.c
 * Routines for kpasswd packet dissection
 *    Ronnie Sahlberg 2003
 *
 * See RFC 3244
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/asn1.h>
#include "packet-tcp.h"
#include "packet-kerberos.h"
#include "packet-ber.h"
#include <epan/prefs.h>

/* Desegment Kerberos over TCP messages */
static gboolean kpasswd_desegment = TRUE;

static int proto_kpasswd = -1;
static int hf_kpasswd_message_len = -1;
static int hf_kpasswd_version = -1;
static int hf_kpasswd_result = -1;
static int hf_kpasswd_result_string = -1;
static int hf_kpasswd_newpassword = -1;
static int hf_kpasswd_ap_req_len = -1;
static int hf_kpasswd_ap_req_data = -1;
static int hf_kpasswd_krb_priv_message = -1;
static int hf_kpasswd_ChangePasswdData = -1;

static gint ett_kpasswd = -1;
static gint ett_ap_req_data = -1;
static gint ett_krb_priv_message = -1;
static gint ett_ChangePasswdData = -1;


#define UDP_PORT_KPASSWD        464
#define TCP_PORT_KPASSWD        464


static const value_string vers_vals[] = {
    { 0x0001, "Reply" },
    { 0xff80, "Request" },
    { 0,      NULL },
};


/** Dissects AP-REQ or AP-REP part of password change. */
static void
dissect_kpasswd_ap_req_data(packet_info *pinfo _U_, tvbuff_t *tvb, proto_tree *parent_tree)
{
    proto_item *it;
    proto_tree *tree=NULL;

    if(parent_tree){
        it=proto_tree_add_item(parent_tree, hf_kpasswd_ap_req_data, tvb, 0, -1, ENC_NA);
        tree=proto_item_add_subtree(it, ett_ap_req_data);
    }
    dissect_kerberos_main(tvb, pinfo, tree, FALSE, NULL);
}


static int dissect_kpasswd_newpassword(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_)
{
    offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_kpasswd_newpassword, NULL);
    return offset;
}

static ber_old_sequence_t ChangePasswdData_sequence[] = {
    { BER_CLASS_CON, 0, 0, dissect_kpasswd_newpassword },
    { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_krb5_cname },
    { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_krb5_realm },
    { 0, 0, 0, NULL }
};

static int
dissect_kpasswd_user_data_request(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree)
{
    int offset=0;
    asn1_ctx_t asn1_ctx;
    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

    offset=dissect_ber_old_sequence(FALSE, &asn1_ctx, tree, tvb, offset, ChangePasswdData_sequence, hf_kpasswd_ChangePasswdData, ett_ChangePasswdData);
    return offset;
}

static kerberos_callbacks cb_req[] = {
    { KRB_CBTAG_PRIV_USER_DATA, dissect_kpasswd_user_data_request },
    { 0, NULL }
};

#define KRB5_KPASSWD_SUCCESS             0
#define KRB5_KPASSWD_MALFORMED           1
#define KRB5_KPASSWD_HARDERROR           2
#define KRB5_KPASSWD_AUTHERROR           3
#define KRB5_KPASSWD_SOFTERROR           4
#define KRB5_KPASSWD_ACCESSDENIED        5
#define KRB5_KPASSWD_BAD_VERSION         6
#define KRB5_KPASSWD_INITIAL_FLAG_NEEDED 7
static const value_string kpasswd_result_types[] = {
    { KRB5_KPASSWD_SUCCESS, "Success" },
    { KRB5_KPASSWD_MALFORMED, "Malformed" },
    { KRB5_KPASSWD_HARDERROR, "HardError" },
    { KRB5_KPASSWD_AUTHERROR, "AuthError" },
    { KRB5_KPASSWD_SOFTERROR, "SoftError" },
    { KRB5_KPASSWD_ACCESSDENIED, "AccessDenied" },
    { KRB5_KPASSWD_BAD_VERSION, "BadVersion" },
    { KRB5_KPASSWD_INITIAL_FLAG_NEEDED, "InitialFlagNeeded" },
    { 0, NULL }
};

static int
dissect_kpasswd_user_data_reply(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree)
{
    int offset=0;
    guint16 result;

    /* result */
    result = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tree, hf_kpasswd_result, tvb, offset, 2, result);
    offset+=2;
    if (check_col(pinfo->cinfo, COL_INFO))
        col_add_str(pinfo->cinfo, COL_INFO,
            val_to_str(result, kpasswd_result_types, "Result: %u"));


    /* optional result string */
    if(tvb_reported_length_remaining(tvb, offset) > 0){
        proto_tree_add_item(tree, hf_kpasswd_result_string, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_ASCII|ENC_NA);
        offset = tvb_reported_length(tvb);
    }

    return offset;
}


static kerberos_callbacks cb_rep[] = {
    { KRB_CBTAG_PRIV_USER_DATA, dissect_kpasswd_user_data_reply },
    { 0, NULL }
};

static gint
dissect_kpasswd_krb_priv_message(packet_info *pinfo _U_, tvbuff_t *tvb, proto_tree *parent_tree, gboolean isrequest)
{
    proto_item *it;
    proto_tree *tree=NULL;
    gint offset;

    if(parent_tree){
        it=proto_tree_add_item(parent_tree, hf_kpasswd_krb_priv_message, tvb, 0, -1, ENC_NA);
        tree=proto_item_add_subtree(it, ett_krb_priv_message);
    }
    if(isrequest){
        offset = dissect_kerberos_main(tvb, pinfo, tree, FALSE, cb_req);
    } else {
        offset = dissect_kerberos_main(tvb, pinfo, tree, FALSE, cb_rep);
    }

    /* offset is bytes consumed in child tvb given to us */
    return offset;
}


static gint
dissect_kpasswd_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean have_rm)
{
    proto_item *kpasswd_item=NULL;
    proto_tree *kpasswd_tree=NULL;
    int offset = 0;
    guint16 message_len, version, ap_req_len;
    tvbuff_t *next_tvb;

    /* TCP record mark and length */
    guint32 krb_rm = 0;
    gint krb_reclen = 0;
    gint krb_rm_size = 0;    /* bytes consumed by record mark: 0 or 4 */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "KPASSWD");
    col_clear(pinfo->cinfo, COL_INFO);

    /* can't pass have_rm to dissect_kerberos_main, so strip rm first */
    if (have_rm) {
        krb_rm = tvb_get_ntohl(tvb, offset);
        krb_reclen = kerberos_rm_to_reclen(krb_rm);
        krb_rm_size = 4;
        /*
         * What is a reasonable size limit?
         */
        if (krb_reclen > 10 * 1024 * 1024) {
            return (-1);
        }
        offset += krb_rm_size;
    }

    /* it might be a KERBEROS ERROR */
    if(tvb_get_guint8(tvb, offset)==0x7e){
        /* TCP record mark, if any, not displayed.  But hopefully
         * KRB-ERROR dissection will proceed correctly. */
        next_tvb=tvb_new_subset_remaining(tvb, offset);
        return dissect_kerberos_main(next_tvb, pinfo, tree, FALSE, NULL);
    }

    message_len=tvb_get_ntohs(tvb, offset);
    version=tvb_get_ntohs(tvb, offset+2);
    ap_req_len=tvb_get_ntohs(tvb, offset+4);
    if(tree){
        kpasswd_item=proto_tree_add_item(tree, proto_kpasswd, tvb, offset-krb_rm_size, message_len+krb_rm_size, ENC_NA);
        kpasswd_tree=proto_item_add_subtree(kpasswd_item, ett_kpasswd);
        if (have_rm) {
            show_krb_recordmark(kpasswd_tree, tvb, offset-krb_rm_size, krb_rm);
        }
    }

    proto_tree_add_uint(kpasswd_tree, hf_kpasswd_message_len, tvb, offset, 2, message_len);
    proto_tree_add_uint(kpasswd_tree, hf_kpasswd_version, tvb, offset+2, 2, version);
    if (check_col(pinfo->cinfo, COL_INFO))
        col_add_str(pinfo->cinfo, COL_INFO, val_to_str_const(version, vers_vals, "Unknown command"));
    proto_tree_add_uint(kpasswd_tree, hf_kpasswd_ap_req_len, tvb, offset+4, 2, ap_req_len);
    offset+=6;

    /* AP-REQ / AP-REP data */
    next_tvb=tvb_new_subset(tvb, offset, ap_req_len, ap_req_len);
    dissect_kpasswd_ap_req_data(pinfo, next_tvb, kpasswd_tree);
    offset+=ap_req_len;

    /* KRB-PRIV message */
    next_tvb=tvb_new_subset_remaining(tvb, offset);
    offset += dissect_kpasswd_krb_priv_message(pinfo, next_tvb, kpasswd_tree, (version==0xff80));

    proto_item_set_len(kpasswd_item, offset);
    return offset;

}

static void
dissect_kpasswd_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    dissect_kpasswd_common(tvb, pinfo, tree, FALSE);
}

static void
dissect_kpasswd_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    pinfo->fragmented = TRUE;
    if (dissect_kpasswd_common(tvb, pinfo, tree, TRUE) < 0) {
        /*
         * The dissector failed to recognize this as a valid
         * Kerberos message.  Mark it as a continuation packet.
         */
        col_set_str(pinfo->cinfo, COL_INFO, "Continuation");
    }
}

static void
dissect_kpasswd_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "KPASSWD");
    col_clear(pinfo->cinfo, COL_INFO);

    tcp_dissect_pdus(tvb, pinfo, tree, kpasswd_desegment, 4, get_krb_pdu_len,
    dissect_kpasswd_tcp_pdu);
}

void
proto_register_kpasswd(void)
{
    static hf_register_info hf[] = {
    { &hf_kpasswd_message_len,
        { "Message Length", "kpasswd.message_len", FT_UINT16, BASE_DEC,
        NULL, 0, NULL, HFILL }},
    { &hf_kpasswd_ap_req_len,
        { "AP_REQ Length", "kpasswd.ap_req_len", FT_UINT16, BASE_DEC,
        NULL, 0, "Length of AP_REQ data", HFILL }},
    { &hf_kpasswd_version,
        { "Version", "kpasswd.version", FT_UINT16, BASE_HEX,
        VALS(vers_vals), 0, NULL, HFILL }},
    { &hf_kpasswd_result,
        { "Result", "kpasswd.result", FT_UINT16, BASE_DEC,
        VALS(kpasswd_result_types), 0, NULL, HFILL }},
    { &hf_kpasswd_result_string,
        { "Result String", "kpasswd.result_string", FT_STRING, BASE_NONE,
        NULL, 0, NULL, HFILL }},
    { &hf_kpasswd_newpassword,
        { "New Password", "kpasswd.new_password", FT_STRING, BASE_NONE,
        NULL, 0, NULL, HFILL }},
    { &hf_kpasswd_ap_req_data,
        { "AP_REQ", "kpasswd.ap_req", FT_NONE, BASE_NONE,
        NULL, 0, "AP_REQ structure", HFILL }},
    { &hf_kpasswd_krb_priv_message,
        { "KRB-PRIV", "kpasswd.krb_priv", FT_NONE, BASE_NONE,
        NULL, 0, "KRB-PRIV message", HFILL }},
    { &hf_kpasswd_ChangePasswdData, {
        "ChangePasswdData", "kpasswd.ChangePasswdData", FT_NONE, BASE_NONE,
        NULL, 0, "Change Password Data structure", HFILL }},
    };

    static gint *ett[] = {
        &ett_kpasswd,
        &ett_ap_req_data,
        &ett_krb_priv_message,
        &ett_ChangePasswdData,
    };
        module_t *kpasswd_module;

    proto_kpasswd = proto_register_protocol("MS Kpasswd",
        "Kpasswd", "kpasswd");
    proto_register_field_array(proto_kpasswd, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register preferences */
    kpasswd_module = prefs_register_protocol(proto_kpasswd, NULL);
    prefs_register_bool_preference(kpasswd_module, "desegment",
        "Reassemble Kpasswd over TCP messages spanning multiple TCP segments",
        "Whether the Kpasswd dissector should reassemble messages spanning multiple TCP segments."
        " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
        &kpasswd_desegment);
}

void
proto_reg_handoff_kpasswd(void)
{
    dissector_handle_t kpasswd_handle_udp;
    dissector_handle_t kpasswd_handle_tcp;

    kpasswd_handle_udp = create_dissector_handle(dissect_kpasswd_udp, proto_kpasswd);
    kpasswd_handle_tcp = create_dissector_handle(dissect_kpasswd_tcp, proto_kpasswd);
    dissector_add_uint("udp.port", UDP_PORT_KPASSWD, kpasswd_handle_udp);
    dissector_add_uint("tcp.port", TCP_PORT_KPASSWD, kpasswd_handle_tcp);
}

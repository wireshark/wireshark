/* packet-do-irp.c
 * Dissector for Digital Object Identifier Resolution Protocol (DO-IRP)
 *
 * Copyright (c) 2023 by Martin Mayer <martin.mayer@m2-it-solutions.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This dissector is based on:
 *
 * - Title:      Digital Object Identifier Resolution Protocol Specification
 *   Version:    3.0 (June 30, 2022)
 *   Author:     DONA Foundation (https://www.dona.net)
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>
#include "packet-tcp.h"

/* N.B. IANA has these ports registered for hdl-srv (name from original RFC) */
#define DO_IRP_UDP_PORT 2641
#define DO_IRP_TCP_PORT 2641

#define DO_IRP_ENVELOPE_LEN  20
#define DO_IRP_MAX_UDP_SIZE 512

void proto_register_do_irp(void);
void proto_reg_handoff_do_irp(void);

static dissector_handle_t do_irp_handle_udp;
static dissector_handle_t do_irp_handle_tcp;

static int proto_do_irp;
expert_module_t* expert_do_irp;

/* Fields Generic */
static int hf_do_irp_string_len;
static int hf_do_irp_string_value;
static int hf_do_irp_data_len;
static int hf_do_irp_data_value;

/* Fields Message Envelope */
static int hf_do_irp_envelope;
static int hf_do_irp_version_major;
static int hf_do_irp_version_minor;
static int hf_do_irp_flags;
static int hf_do_irp_flag_cp;
static int hf_do_irp_flag_ec;
static int hf_do_irp_flag_tc;
static int hf_do_irp_version_major_sugg;
static int hf_do_irp_version_minor_sugg;
static int hf_do_irp_sessid;
static int hf_do_irp_reqid;
static int hf_do_irp_seq;
static int hf_do_irp_msglen;

/* Fields Message Header */
static int hf_do_irp_header;
static int hf_do_irp_opcode;
static int hf_do_irp_responsecode;
static int hf_do_irp_opflags;
static int hf_do_irp_opflags_at;
static int hf_do_irp_opflags_ct;
static int hf_do_irp_opflags_enc;
static int hf_do_irp_opflags_rec;
static int hf_do_irp_opflags_ca;
static int hf_do_irp_opflags_cn;
static int hf_do_irp_opflags_kc;
static int hf_do_irp_opflags_po;
static int hf_do_irp_opflags_rd;
static int hf_do_irp_opflags_owe;
static int hf_do_irp_opflags_mns;
static int hf_do_irp_opflags_dnr;
static int hf_do_irp_sisn;
static int hf_do_irp_rcount;
static int hf_do_irp_expiration;
static int hf_do_irp_bodylen;

/* Fields Message Body */
static int hf_do_irp_body;
static int hf_do_irp_digest_algo;
static int hf_do_irp_digest;
static int hf_do_irp_error_msg;
static int hf_do_irp_error_idxcount;
static int hf_do_irp_error_idx;
static int hf_do_irp_ident;
static int hf_do_irp_idxcount;
static int hf_do_irp_idx;
static int hf_do_irp_typecount;
static int hf_do_irp_type;
static int hf_do_irp_identcount;
static int hf_do_irp_identrecord;
static int hf_do_irp_identrecord_idx;
static int hf_do_irp_identrecord_type;
static int hf_do_irp_identrecord_value;
static int hf_do_irp_identrecord_value_string;
static int hf_do_irp_identrecord_value_len;
static int hf_do_irp_identrecord_perm;
static int hf_do_irp_identrecord_perm_pw;
static int hf_do_irp_identrecord_perm_pr;
static int hf_do_irp_identrecord_perm_aw;
static int hf_do_irp_identrecord_perm_ar;
static int hf_do_irp_identrecord_ttl_type;
static int hf_do_irp_identrecord_ttl;
static int hf_do_irp_identrecord_ttl_absolute;
static int hf_do_irp_identrecord_ts;
static int hf_do_irp_identrecord_ts_utc;
static int hf_do_irp_identrecord_refcount;
static int hf_do_irp_identrecord_ref;
static int hf_do_irp_hsadmin_perm;
static int hf_do_irp_hsadmin_perm_ai;
static int hf_do_irp_hsadmin_perm_di;
static int hf_do_irp_hsadmin_perm_adp;
static int hf_do_irp_hsadmin_perm_me;
static int hf_do_irp_hsadmin_perm_de;
static int hf_do_irp_hsadmin_perm_ae;
static int hf_do_irp_hsadmin_perm_ma;
static int hf_do_irp_hsadmin_perm_ra;
static int hf_do_irp_hsadmin_perm_aa;
static int hf_do_irp_hsadmin_perm_ar;
static int hf_do_irp_hsadmin_perm_li;
static int hf_do_irp_hsadmin_perm_ldp;
static int hf_do_irp_hsadmin_idx;
static int hf_do_irp_hsadmin_ident;
static int hf_do_irp_body_hssite_version;
static int hf_do_irp_hssite_protoversion_major;
static int hf_do_irp_hssite_protoversion_minor;
static int hf_do_irp_hssite_serial;
static int hf_do_irp_hssite_primask;
static int hf_do_irp_hssite_primask_pri;
static int hf_do_irp_hssite_primask_multi;
static int hf_do_irp_hssite_hashoption;
static int hf_do_irp_hssite_hashfilter;
static int hf_do_irp_hssite_attr_count;
static int hf_do_irp_hssite_attr;
static int hf_do_irp_hssite_attr_key;
static int hf_do_irp_hssite_attr_value;
static int hf_do_irp_hssite_srvcount;
static int hf_do_irp_hssite_srv;
static int hf_do_irp_hssite_srv_id;
static int hf_do_irp_hssite_srv_addr;
static int hf_do_irp_pkrec;
static int hf_do_irp_pkrec_len;
static int hf_do_irp_pkrec_type;
static int hf_do_irp_pkrec_dsa_q;
static int hf_do_irp_pkrec_dsa_p;
static int hf_do_irp_pkrec_dsa_g;
static int hf_do_irp_pkrec_dsa_y;
static int hf_do_irp_pkrec_rsa_exp;
static int hf_do_irp_pkrec_rsa_mod;
static int hf_do_irp_pkrec_dh_p;
static int hf_do_irp_pkrec_dh_g;
static int hf_do_irp_pkrec_dh_y;
static int hf_do_irp_hssite_srv_if;
static int hf_do_irp_hssite_srv_ifcount;
static int hf_do_irp_hssite_srv_if_type;
static int hf_do_irp_hssite_srv_if_type_admin;
static int hf_do_irp_hssite_srv_if_type_res;
static int hf_do_irp_hssite_srv_if_proto;
static int hf_do_irp_hssite_srv_if_port;
static int hf_do_irp_hsserv_ident;
static int hf_do_irp_hsvlist_count;
static int hf_do_irp_hsvlist_ref;
static int hf_do_irp_hsalias;
static int hf_do_irp_hsnamespace;
static int hf_do_irp_hscert_jwt;
static int hf_do_irp_hssignature_jwt;
static int hf_do_irp_refident;
static int hf_do_irp_nonce;
static int hf_do_irp_authtype;
static int hf_do_irp_keyident;
static int hf_do_irp_keyidx;
static int hf_do_irp_challresp;
static int hf_do_irp_veri_result;
static int hf_do_irp_ignoredident;
static int hf_do_irp_keyexmode;
static int hf_do_irp_timeout;

/* Fields Message Credential */
static int hf_do_irp_credential;
static int hf_do_irp_credential_len;
static int hf_do_irp_credential_sesscounter;
static int hf_do_irp_credential_type;
static int hf_do_irp_credential_signedinfo;
static int hf_do_irp_credential_signedinfo_len;
static int hf_do_irp_credential_signedinfo_algo;
static int hf_do_irp_credential_signedinfo_sig;

/* Conversation */
static int hf_do_irp_response_in;
static int hf_do_irp_response_to;

/* Fragment handling */
static int hf_msg_fragments;
static int hf_msg_fragment;
static int hf_msg_fragment_overlap;
static int hf_msg_fragment_overlap_conflicts;
static int hf_msg_fragment_multiple_tails;
static int hf_msg_fragment_too_long_fragment;
static int hf_msg_fragment_error;
static int hf_msg_fragment_count;
static int hf_msg_reassembled_in;
static int hf_msg_reassembled_len;
static int hf_msg_reassembled_data;

/* Expert fields */
static expert_field ei_do_irp_digest_unknown;
static expert_field ei_do_irp_frag_wo_tc;

/* Trees */
static int ett_do_irp;
static int ett_do_irp_string;
static int ett_do_irp_envelope;
static int ett_do_irp_envelope_flags;
static int ett_do_irp_header;
static int ett_do_irp_header_flags;
static int ett_do_irp_body;
static int ett_do_irp_credential;
static int ett_do_irp_credential_signedinfo;
static int ett_do_irp_identifier_record;
static int ett_do_irp_element_permission_flags;
static int ett_do_irp_element_hsadmin_permission_flags;
static int ett_do_irp_element_hsadmin_primary_flags;
static int ett_do_irp_hsadmin;
static int ett_do_irp_hssite;
static int ett_do_irp_hssite_attribute;
static int ett_do_irp_hssite_server;
static int ett_do_irp_hssite_server_if;
static int ett_do_irp_hssite_server_if_flags;
static int ett_do_irp_pk;
static int ett_msg_fragment;
static int ett_msg_fragments;

static const fragment_items msg_frag_items = {
    &ett_msg_fragment,
    &ett_msg_fragments,
    &hf_msg_fragments,
    &hf_msg_fragment,
    &hf_msg_fragment_overlap,
    &hf_msg_fragment_overlap_conflicts,
    &hf_msg_fragment_multiple_tails,
    &hf_msg_fragment_too_long_fragment,
    &hf_msg_fragment_error,
    &hf_msg_fragment_count,
    &hf_msg_reassembled_in,
    &hf_msg_reassembled_len,
    &hf_msg_reassembled_data,
    "Message fragments"
};

/* Request Hashmap Key */
struct do_irp_request_hash_key {
    uint32_t conv_index;
    uint32_t reqid;
};
/* Request Hashmap Val */
struct do_irp_request_hash_val {
    uint32_t pnum;
    uint32_t pnum_resp;
    uint32_t opcode;
};
static wmem_map_t *do_irp_request_hash_map;

#define DO_IRP_OC_RESERVED                0
#define DO_IRP_OC_RESOLUTION              1
#define DO_IRP_OC_GET_SITEINFO            2
#define DO_IRP_OC_CREATE_ID             100
#define DO_IRP_OC_DELETE_ID             101
#define DO_IRP_OC_ADD_ELEMENT           102
#define DO_IRP_OC_REMOVE_ELEMENT        103
#define DO_IRP_OC_MODIFY_ELEMENT        104
#define DO_IRP_OC_LIST_IDS              105
#define DO_IRP_OC_LIST_DERIVED_PREFIXES 106
#define DO_IRP_OC_CHALLENGE_RESPONSE    200
#define DO_IRP_OC_VERIFY_RESPONSE       201
#define DO_IRP_OC_HOME_PREFIX           300
#define DO_IRP_OC_UNHOME_PREFIX         301
#define DO_IRP_OC_LIST_HOMED_PREFIXES   302
#define DO_IRP_OC_SESSION_SETUP         400
#define DO_IRP_OC_SESSION_TERMINATE     401


static const value_string opcode_vals[] = {
    { DO_IRP_OC_RESERVED,               "RESERVED" },
    { DO_IRP_OC_RESOLUTION,             "RESOLUTION" },
    { DO_IRP_OC_GET_SITEINFO,           "GET_SITEINFO" },
    { DO_IRP_OC_CREATE_ID,              "CREATE_ID" },
    { DO_IRP_OC_DELETE_ID,              "DELETE_ID" },
    { DO_IRP_OC_ADD_ELEMENT,            "ADD_ELEMENT" },
    { DO_IRP_OC_REMOVE_ELEMENT,         "REMOVE_ELEMENT" },
    { DO_IRP_OC_MODIFY_ELEMENT,         "MODIFY_ELEMENT" },
    { DO_IRP_OC_LIST_IDS,               "LIST_IDS" },
    { DO_IRP_OC_LIST_DERIVED_PREFIXES,  "LIST_DERIVED_PREFIXES" },
    { DO_IRP_OC_CHALLENGE_RESPONSE,     "CHALLENGE_RESPONSE" },
    { DO_IRP_OC_VERIFY_RESPONSE,        "VERIFY_RESPONSE" },
    { DO_IRP_OC_HOME_PREFIX,            "HOME_PREFIX" },
    { DO_IRP_OC_UNHOME_PREFIX,          "UNHOME_PREFIX" },
    { DO_IRP_OC_LIST_HOMED_PREFIXES,    "LIST_HOMED_PREFIXES" },
    { DO_IRP_OC_SESSION_SETUP,          "SESSION_SETUP" },
    { DO_IRP_OC_SESSION_TERMINATE,      "SESSION_TERMINATE" },
    { 0, NULL },
};

#define DO_IRP_RC_RESERVED                0
#define DO_IRP_RC_SUCCESS                 1
#define DO_IRP_RC_ERROR                   2
#define DO_IRP_RC_SERVER_BUSY             3
#define DO_IRP_RC_PROTOCOL_ERROR          4
#define DO_IRP_RC_OPERATION_DENIED        5
#define DO_IRP_RC_RECUR_LIMIT_EXCEEDED    6
#define DO_IRP_RC_SERVER_BACKUP           7
#define DO_IRP_RC_ID_NOT_FOUND          100
#define DO_IRP_RC_ID_ALREADY_EXIST      101
#define DO_IRP_RC_INVALID_ID            102
#define DO_IRP_RC_ELEMENT_NOT_FOUND     200
#define DO_IRP_RC_ELEMENT_ALREADY_EXIST 201
#define DO_IRP_RC_ELEMENT_INVALID       202
#define DO_IRP_RC_EXPIRED_SITE_INFO     300
#define DO_IRP_RC_SERVER_NOT_RESP       301
#define DO_IRP_RC_SERVICE_REFERRAL      302
#define DO_IRP_RC_PREFIX_REFERRAL       303
#define DO_IRP_RC_INVALID_ADMIN         400
#define DO_IRP_RC_ACCESS_DENIED         401
#define DO_IRP_RC_AUTHEN_NEEDED         402
#define DO_IRP_RC_AUTHEN_FAILED         403
#define DO_IRP_RC_INVALID_CREDENTIAL    404
#define DO_IRP_RC_AUTHEN_TIMEOUT        405
#define DO_IRP_RC_UNABLE_TO_AUTHEN      406
#define DO_IRP_RC_SESSION_TIMEOUT       500
#define DO_IRP_RC_SESSION_FAILED        501
#define DO_IRP_RC_SESSION_KEY_INVALID   502
#define DO_IRP_RC_SESSION_MSG_REJECTED  505


static const value_string responsecode_vals[] = {
    { DO_IRP_RC_RESERVED,              "RESERVED" },
    { DO_IRP_RC_SUCCESS,               "SUCCESS" },
    { DO_IRP_RC_ERROR,                 "ERROR" },
    { DO_IRP_RC_SERVER_BUSY,           "SERVER_BUSY" },
    { DO_IRP_RC_PROTOCOL_ERROR,        "PROTOCOL_ERROR" },
    { DO_IRP_RC_OPERATION_DENIED,      "OPERATION_DENIED" },
    { DO_IRP_RC_RECUR_LIMIT_EXCEEDED,  "RECUR_LIMIT_EXCEEDED" },
    { DO_IRP_RC_SERVER_BACKUP,         "SERVER_BACKUP" },
    { DO_IRP_RC_ID_NOT_FOUND,          "ID_NOT_FOUND" },
    { DO_IRP_RC_ID_ALREADY_EXIST,      "ID_ALREADY_EXIST" },
    { DO_IRP_RC_INVALID_ID,            "INVALID_ID" },
    { DO_IRP_RC_ELEMENT_NOT_FOUND,     "ELEMENT_NOT_FOUND" },
    { DO_IRP_RC_ELEMENT_ALREADY_EXIST, "ELEMENT_ALREADY_EXIST" },
    { DO_IRP_RC_ELEMENT_INVALID,       "ELEMENT_INVALID" },
    { DO_IRP_RC_EXPIRED_SITE_INFO,     "EXPIRED_SITE_INFO" },
    { DO_IRP_RC_SERVER_NOT_RESP,       "SERVER_NOT_RESP" },
    { DO_IRP_RC_SERVICE_REFERRAL,      "SERVICE_REFERRAL" },
    { DO_IRP_RC_PREFIX_REFERRAL,       "PREFIX_REFERRAL" },
    { DO_IRP_RC_INVALID_ADMIN,         "INVALID_ADMIN" },
    { DO_IRP_RC_ACCESS_DENIED,         "ACCESS_DENIED" },
    { DO_IRP_RC_AUTHEN_NEEDED,         "AUTHEN_NEEDED" },
    { DO_IRP_RC_AUTHEN_FAILED,         "AUTHEN_FAILED" },
    { DO_IRP_RC_INVALID_CREDENTIAL,    "INVALID_CREDENTIAL" },
    { DO_IRP_RC_AUTHEN_TIMEOUT,        "AUTHEN_TIMEOUT" },
    { DO_IRP_RC_UNABLE_TO_AUTHEN,      "UNABLE_TO_AUTHEN" },
    { DO_IRP_RC_SESSION_TIMEOUT,       "SESSION_TIMEOUT" },
    { DO_IRP_RC_SESSION_FAILED,        "SESSION_FAILED" },
    { DO_IRP_RC_SESSION_KEY_INVALID,   "SESSION_KEY_INVALID" },
    { DO_IRP_RC_SESSION_MSG_REJECTED,  "SESSION_MSG_REJECTED" },
    { 0, NULL },
};

#define DO_IRP_DIGEST_ALGO_MD5    1
#define DO_IRP_DIGEST_ALGO_SHA1   2
#define DO_IRP_DIGEST_ALGO_SHA256 3

static const value_string digest_algo_vals[] = {
    { DO_IRP_DIGEST_ALGO_MD5,    "MD5" },
    { DO_IRP_DIGEST_ALGO_SHA1,   "SHA-1" },
    { DO_IRP_DIGEST_ALGO_SHA256, "SHA-256" },
    { 0, NULL },
};

#define DO_IRP_TTL_RELATIVE 0
#define DO_IRP_TTL_ABSOLUTE 1

static const value_string ttl_vals[] = {
    { DO_IRP_TTL_RELATIVE, "relative" },
    { DO_IRP_TTL_ABSOLUTE, "absolute" },
    { 0, NULL },
};

static const value_string hashoption_vals[] = {
    { 0x0, "HASH_BY_PREFIX" },
    { 0x1, "HASH_BY_SUFFIX" },
    { 0x2, "HASH_BY_IDENTIFIER" },
    { 0, NULL },
};

static const value_string transportproto_vals[] = {
    { 0x0, "UDP" },
    { 0x1, "TCP" },
    { 0x2, "HTTP" },
    { 0x3, "HTTPS" },
    { 0, NULL },
};

static const value_string verification_resp_vals[] = {
    { 0x0, "Fail" },
    { 0x1, "Match" },
    { 0, NULL },
};

static const value_string key_exchange_vals[] = {
    { 0x4, "Diffie-Hellman" },
    { 0, NULL },
};

static reassembly_table do_irp_reassemble_table;

/* wmem hash/equal funcs */
static unsigned
do_irp_handle_hash (const void *v)
{
    const struct do_irp_request_hash_key *key = (const struct do_irp_request_hash_key *)v;
    unsigned val;

    val = key->conv_index + key->reqid;

    return val;
}

static int
do_irp_handle_equal(const void *v, const void *w)
{
    const struct do_irp_request_hash_key *v1 = (const struct do_irp_request_hash_key *)v;
    const struct do_irp_request_hash_key *v2 = (const struct do_irp_request_hash_key *)w;

    if (
        v1->conv_index == v2->conv_index &&
        v1->reqid == v2->reqid
    )
    {
        return 1;
    }

    return 0;
}

/*
 * Decodes a string to the given hf and adds it to a tree
 * All "strings" are defined as 4 octets representing the length of of the actual string,
 * followed by the octets representing the actual string.
 *
 * Passed hf must be of any FT_STRING type
 *
 * Returns length of the dissected string
 * length, value_of_string and string_tree can be used by the calling function.
 */
static int
decode_string(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int hf, const char **value_of_string)
{
    uint32_t len = tvb_get_int32(tvb, offset, ENC_BIG_ENDIAN);
    proto_item *ti;

    const char *text = tvb_get_string_enc(pinfo->pool, tvb, offset+4, len, ENC_UTF_8);

    if(len) {
        ti = proto_tree_add_string_format_value(tree, hf, tvb, offset, len + 4, text, "%s, Len: %u", text, len);
    } else {
        ti = proto_tree_add_string_format_value(tree, hf, tvb, offset, len + 4, text, "empty, Len: %u", len);
    }

    proto_tree *string_tree = proto_item_add_subtree(ti, ett_do_irp_string);

    proto_tree_add_item(string_tree, hf_do_irp_string_len, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(string_tree, hf_do_irp_string_value, tvb, offset + 4, len, ENC_UTF_8);

    if(value_of_string != NULL) {
        *value_of_string = text;
    }

    return len + 4;
}

/*
 * Decodes generic byte-values to the given hf and adds it to a tree
 *
 * Returns length of the dissected value
 */
static int
decode_generic_data(tvbuff_t *tvb, proto_tree *tree, int offset, int hf)
{
    uint32_t len = tvb_get_int32(tvb, offset, ENC_BIG_ENDIAN);

    proto_item *ti = proto_tree_add_item(tree, hf, tvb, offset, len + 4, ENC_NA);
    proto_tree *string_tree = proto_item_add_subtree(ti, ett_do_irp_string);

    proto_tree_add_item(string_tree, hf_do_irp_data_len, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(string_tree, hf_do_irp_data_value, tvb, offset + 4, len, ENC_NA);

    return len + 4;
}

/*
 * Decodes public key data (e.g. in HS_SITE, HS_PUBKEY)
 *
 * Returns length of the dissected data
 */
static int
decode_pk_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    int len = 0;

    uint32_t pk_len = tvb_get_uint32(tvb, offset + len, ENC_BIG_ENDIAN);

    proto_item *ti = proto_tree_add_item(tree, hf_do_irp_pkrec, tvb, offset, pk_len + 4, ENC_NA);
    proto_tree *pk_tree = proto_item_add_subtree(ti, ett_do_irp_pk);

    proto_tree_add_item(pk_tree, hf_do_irp_pkrec_len, tvb, offset + len, 4, ENC_BIG_ENDIAN);
    len += 4;

    const char *pk_type;
    int pk_type_len = decode_string(tvb, pinfo, pk_tree, offset + len, hf_do_irp_pkrec_type, &pk_type);
    len += pk_type_len;

    len += 2; /* Reserved */

    proto_item_append_text(pk_tree, " (%s)", pk_type);

    if(!strcmp("DSA_PUB_KEY", pk_type)) {
        len += decode_generic_data(tvb, pk_tree, offset + len, hf_do_irp_pkrec_dsa_q);
        len += decode_generic_data(tvb, pk_tree, offset + len, hf_do_irp_pkrec_dsa_p);
        len += decode_generic_data(tvb, pk_tree, offset + len, hf_do_irp_pkrec_dsa_g);
               decode_generic_data(tvb, pk_tree, offset + len, hf_do_irp_pkrec_dsa_y);
    }
    else if(!strcmp("RSA_PUB_KEY", pk_type)) {
        len += decode_generic_data(tvb, pk_tree, offset + len, hf_do_irp_pkrec_rsa_exp);
               decode_generic_data(tvb, pk_tree, offset + len, hf_do_irp_pkrec_rsa_mod);
        /* len += 4; */ /* unused, 4 empty bytes */
    }
    else if(!strcmp("DH_PUB_KEY", pk_type)) {
        len += decode_generic_data(tvb, pk_tree, offset + len, hf_do_irp_pkrec_dh_y);
        len += decode_generic_data(tvb, pk_tree, offset + len, hf_do_irp_pkrec_dh_p);
               decode_generic_data(tvb, pk_tree, offset + len, hf_do_irp_pkrec_dh_g);
    }
    /* else: undefined, not dissectable */

    return pk_len + 4;
}

/*
 * Decodes a HS_ADMIN element
 *
 * Returns length of the dissected data
 */
static int
decode_hsadmin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    int len = 0;

    proto_tree *ti_hsadmin = proto_tree_add_item(tree, hf_do_irp_identrecord_value, tvb, offset + len, -1, ENC_NA);
    proto_tree *do_irp_hsadmin_tree = proto_item_add_subtree(ti_hsadmin, ett_do_irp_hsadmin);

    proto_tree_add_item(do_irp_hsadmin_tree, hf_do_irp_identrecord_value_len, tvb, offset + len, 4, ENC_BIG_ENDIAN);
    len += 4;

    static int* const hsadmin_permission_bits[] = {
        &hf_do_irp_hsadmin_perm_ldp,
        &hf_do_irp_hsadmin_perm_li,
        &hf_do_irp_hsadmin_perm_ar,
        &hf_do_irp_hsadmin_perm_aa,
        &hf_do_irp_hsadmin_perm_ra,
        &hf_do_irp_hsadmin_perm_ma,
        &hf_do_irp_hsadmin_perm_ae,
        &hf_do_irp_hsadmin_perm_de,
        &hf_do_irp_hsadmin_perm_me,
        &hf_do_irp_hsadmin_perm_adp,
        &hf_do_irp_hsadmin_perm_di,
        &hf_do_irp_hsadmin_perm_ai,
        NULL
    };

    proto_tree_add_bitmask(do_irp_hsadmin_tree, tvb, offset + len, hf_do_irp_hsadmin_perm, ett_do_irp_element_hsadmin_permission_flags, hsadmin_permission_bits, ENC_BIG_ENDIAN);
    len += 2;

    const char *admin_identifier;
    len += decode_string(tvb, pinfo, do_irp_hsadmin_tree, offset + len, hf_do_irp_hsadmin_ident, &admin_identifier);

    proto_tree_add_item(do_irp_hsadmin_tree, hf_do_irp_hsadmin_idx, tvb, offset + len, 4, ENC_BIG_ENDIAN);
    proto_item_append_text(ti_hsadmin, " %s, Index: %u", admin_identifier, tvb_get_uint32(tvb, offset + len, ENC_BIG_ENDIAN));
    len += 4;

    proto_item_set_len(ti_hsadmin, len);
    return len;
}

/*
 * Decodes a HS_SITE element
 *
 * Returns length of the dissected data
 */
static int
decode_hssite(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    int len = 0;

    proto_tree *ti_hssite = proto_tree_add_item(tree, hf_do_irp_identrecord_value, tvb, offset + len, -1, ENC_NA);
    proto_tree *do_irp_hssite_tree = proto_item_add_subtree(ti_hssite, ett_do_irp_hssite);

    proto_tree_add_item(do_irp_hssite_tree, hf_do_irp_identrecord_value_len, tvb, offset + len, 4, ENC_BIG_ENDIAN);
    len += 4;

    proto_tree_add_item(do_irp_hssite_tree, hf_do_irp_body_hssite_version, tvb, offset + len, 2, ENC_BIG_ENDIAN);
    len += 2;

    proto_tree_add_item(do_irp_hssite_tree, hf_do_irp_hssite_protoversion_major, tvb, offset + len, 1, ENC_BIG_ENDIAN);
    len += 1;

    proto_tree_add_item(do_irp_hssite_tree, hf_do_irp_hssite_protoversion_minor, tvb, offset + len, 1, ENC_BIG_ENDIAN);
    len += 1;

    proto_tree_add_item(do_irp_hssite_tree, hf_do_irp_hssite_serial, tvb, offset + len, 2, ENC_BIG_ENDIAN);
    len += 2;

    static int* const hssite_primary_bits[] = {
        &hf_do_irp_hssite_primask_pri,
        &hf_do_irp_hssite_primask_multi,
        NULL
    };

    proto_tree_add_bitmask(do_irp_hssite_tree, tvb, offset + len, hf_do_irp_hssite_primask, ett_do_irp_element_hsadmin_primary_flags, hssite_primary_bits, ENC_BIG_ENDIAN);
    len += 1;

    proto_tree_add_item(do_irp_hssite_tree, hf_do_irp_hssite_hashoption, tvb, offset + len, 1, ENC_BIG_ENDIAN);
    len += 1;

    len += decode_string(tvb, pinfo, do_irp_hssite_tree, offset + len, hf_do_irp_hssite_hashfilter, NULL);

    uint32_t attr = tvb_get_uint32(tvb, offset + len, ENC_BIG_ENDIAN);
    proto_tree_add_item(do_irp_hssite_tree, hf_do_irp_hssite_attr_count, tvb, offset + len, 4, ENC_BIG_ENDIAN);
    len += 4;

    for(uint32_t i = 0; i < attr; i++) {
        proto_tree *ti_hssite_attr = proto_tree_add_item(do_irp_hssite_tree, hf_do_irp_hssite_attr, tvb, offset + len, -1, ENC_NA);
        proto_tree *do_irp_hssite_attr_tree = proto_item_add_subtree(ti_hssite_attr, ett_do_irp_hssite_attribute);
        int attr_len = 0;

        const char *attr_name;

        attr_len += decode_string(tvb, pinfo, do_irp_hssite_attr_tree, offset + len + attr_len, hf_do_irp_hssite_attr_key, &attr_name);
        attr_len += decode_string(tvb, pinfo, do_irp_hssite_attr_tree, offset + len + attr_len, hf_do_irp_hssite_attr_value, NULL);
        len += attr_len;
        proto_item_append_text(do_irp_hssite_attr_tree, " (%s)", attr_name);
        proto_item_set_len(ti_hssite_attr, attr_len);
    }

    uint32_t serv = tvb_get_uint32(tvb, offset + len, ENC_BIG_ENDIAN);
    proto_tree_add_item(do_irp_hssite_tree, hf_do_irp_hssite_srvcount, tvb, offset + len, 4, ENC_BIG_ENDIAN);
    len += 4;

    for(uint32_t i = 0; i < serv; i++) {

        proto_tree *ti_hssite_serv = proto_tree_add_item(do_irp_hssite_tree, hf_do_irp_hssite_srv, tvb, offset + len, -1, ENC_NA);
        proto_tree *do_irp_hssite_serv_tree = proto_item_add_subtree(ti_hssite_serv, ett_do_irp_hssite_server);
        int serv_len = 0;

        proto_tree_add_item(do_irp_hssite_serv_tree, hf_do_irp_hssite_srv_id, tvb, offset + len + serv_len, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(do_irp_hssite_serv_tree, " (ID: %u)", tvb_get_uint32(tvb, offset + len + serv_len, ENC_BIG_ENDIAN));
        serv_len += 4;

        proto_tree_add_item(do_irp_hssite_serv_tree, hf_do_irp_hssite_srv_addr, tvb, offset + len + serv_len, 16, ENC_NA);
        serv_len += 16;

        serv_len += decode_pk_data(tvb, pinfo, do_irp_hssite_serv_tree, offset + len + serv_len);

        uint32_t servif = tvb_get_uint32(tvb, offset + len + serv_len, ENC_BIG_ENDIAN);
        proto_tree_add_item(do_irp_hssite_serv_tree, hf_do_irp_hssite_srv_ifcount, tvb, offset + len + serv_len, 4, ENC_BIG_ENDIAN);
        serv_len += 4;

        for(uint32_t j = 0; j < servif; j++) {

            proto_tree *ti_hssite_serv_if = proto_tree_add_item(do_irp_hssite_serv_tree, hf_do_irp_hssite_srv_if, tvb, offset + len + serv_len, 6, ENC_NA);
            proto_tree *do_irp_hssite_serv_if_tree = proto_item_add_subtree(ti_hssite_serv_if, ett_do_irp_hssite_server_if);

            static int* const hsadmin_srv_if_type_bits[] = {
                &hf_do_irp_hssite_srv_if_type_res,
                &hf_do_irp_hssite_srv_if_type_admin,
                NULL
            };

            proto_tree_add_bitmask(do_irp_hssite_serv_if_tree, tvb, offset + len + serv_len, hf_do_irp_hssite_srv_if_type, ett_do_irp_hssite_server_if_flags, hsadmin_srv_if_type_bits, ENC_BIG_ENDIAN);
            serv_len += 1;

            uint8_t serv_if_proto = tvb_get_uint8(tvb, offset + len + serv_len);
            proto_tree_add_item(do_irp_hssite_serv_if_tree, hf_do_irp_hssite_srv_if_proto, tvb, offset + len + serv_len, 1, ENC_BIG_ENDIAN);
            serv_len += 1;

            uint32_t serv_if_port = tvb_get_uint32(tvb, offset + len + serv_len, ENC_BIG_ENDIAN);
            proto_tree_add_item(do_irp_hssite_serv_if_tree, hf_do_irp_hssite_srv_if_port, tvb, offset + len + serv_len, 4, ENC_BIG_ENDIAN);
            serv_len += 4;

            proto_item_append_text(do_irp_hssite_serv_if_tree, " (%s:%u)",
                val_to_str_const(serv_if_proto, transportproto_vals, "Unknown"),
                serv_if_port
            );
        }

        proto_item_set_len(ti_hssite_serv, serv_len);
        len += serv_len;
    }

    proto_item_set_len(ti_hssite, len);
    return len;
}

/*
 * Decodes an identifier record
 *
 * Returns length of the dissected record
 */
static int
decode_identifier_record(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    int len = 0;

    const char *type_string;

    proto_item *ti = proto_tree_add_item(tree, hf_do_irp_identrecord, tvb, offset, -1, ENC_NA);
    proto_tree *do_irp_record_tree = proto_item_add_subtree(ti, ett_do_irp_identifier_record);

    proto_tree_add_item(do_irp_record_tree, hf_do_irp_identrecord_idx, tvb, offset + len, 4, ENC_BIG_ENDIAN);
    len += 4;

    proto_tree_add_item(do_irp_record_tree, hf_do_irp_identrecord_ts, tvb, offset + len, 4, ENC_BIG_ENDIAN);
    proto_item *ts = proto_tree_add_item(do_irp_record_tree, hf_do_irp_identrecord_ts_utc, tvb, offset + len, 4, ENC_TIME_SECS);
    proto_item_set_generated(ts);
    len += 4;

    uint8_t ttl_type = tvb_get_uint8(tvb, offset + len);
    proto_tree_add_item(do_irp_record_tree, hf_do_irp_identrecord_ttl_type, tvb, offset + len, 1, ENC_BIG_ENDIAN);
    len += 1;

    proto_tree_add_item(do_irp_record_tree, hf_do_irp_identrecord_ttl, tvb, offset + len, 4, ENC_BIG_ENDIAN);
    if(ttl_type == DO_IRP_TTL_ABSOLUTE) {
        proto_item *ttl = proto_tree_add_item(do_irp_record_tree, hf_do_irp_identrecord_ttl_absolute, tvb, offset + len, 4, ENC_TIME_SECS);
        proto_item_set_generated(ttl);
    }
    len += 4;

    static int* const permission_bits[] = {
        &hf_do_irp_identrecord_perm_ar,
        &hf_do_irp_identrecord_perm_aw,
        &hf_do_irp_identrecord_perm_pr,
        &hf_do_irp_identrecord_perm_pw,
        NULL
    };

    proto_tree_add_bitmask(do_irp_record_tree, tvb, offset + len, hf_do_irp_identrecord_perm, ett_do_irp_element_permission_flags, permission_bits, ENC_BIG_ENDIAN);
    len += 1;

    len += decode_string(tvb, pinfo, do_irp_record_tree, offset + len, hf_do_irp_identrecord_type, &type_string);
    proto_item_append_text(do_irp_record_tree, " (%s)", type_string);

    if(!strcmp("HS_ADMIN", type_string)) {
        len += decode_hsadmin(tvb, pinfo, do_irp_record_tree, offset + len);
    }
    else if(!strcmp("HS_SITE", type_string) || !strcmp("HS_SITE.PREFIX", type_string)) {
        len += decode_hssite(tvb, pinfo, do_irp_record_tree, offset + len);
    }
    else if(!strcmp("HS_SERV", type_string) || !strcmp("HS_SERV.PREFIX", type_string)) {
        len += decode_string(tvb, pinfo, do_irp_record_tree, offset + len, hf_do_irp_hsserv_ident, NULL);
    }
    else if(!strcmp("HS_PUBKEY", type_string)) {
        len += decode_pk_data(tvb, pinfo, do_irp_record_tree, offset + len);
    }
    else if(!strcmp("HS_VLIST", type_string)) {
        uint32_t refs = tvb_get_uint32(tvb, offset + len, ENC_BIG_ENDIAN);
        proto_tree_add_item(do_irp_record_tree, hf_do_irp_hsvlist_count, tvb, offset + len, 4, ENC_BIG_ENDIAN);
        len += 4;

        for(uint32_t i = 0; i < refs; i++) {
            len += decode_string(tvb, pinfo, do_irp_record_tree, offset + len, hf_do_irp_hsvlist_ref, NULL);
        }
    }
    else if(!strcmp("HS_NAMESPACE", type_string)) {
        len += decode_string(tvb, pinfo, do_irp_record_tree, offset + len, hf_do_irp_hsnamespace, NULL);
    }
    else if(!strcmp("HS_ALIAS", type_string)) {
        len += decode_string(tvb, pinfo, do_irp_record_tree, offset + len, hf_do_irp_hsalias, NULL);
    }
    else if(!strcmp("HS_CERT", type_string)) {
        len += decode_string(tvb, pinfo, do_irp_record_tree, offset + len, hf_do_irp_hscert_jwt, NULL);
    }
    else if(!strcmp("HS_SIGNATURE", type_string)) {
        len += decode_string(tvb, pinfo, do_irp_record_tree, offset + len, hf_do_irp_hssignature_jwt, NULL);
    }
    else if(
        !strcmp("DESC", type_string) ||
        !strcmp("EMAIL", type_string) ||
        !strcmp("URL", type_string)
    ) {
        /* generic string */
        len += decode_string(tvb, pinfo, do_irp_record_tree, offset + len, hf_do_irp_identrecord_value_string, NULL);
    }
    else {
        /* generic data */
        len += decode_generic_data(tvb, do_irp_record_tree, offset + len, hf_do_irp_identrecord_value);
    }

    uint32_t references = tvb_get_uint32(tvb, offset + len, ENC_BIG_ENDIAN);
    proto_tree_add_item(do_irp_record_tree, hf_do_irp_identrecord_refcount, tvb, offset + len, 4, ENC_BIG_ENDIAN);
    len += 4;

    for(uint32_t i = 0; i < references; i++) {
        len += decode_string(tvb, pinfo, do_irp_record_tree, offset + len, hf_do_irp_identrecord_ref, NULL);
    }

    proto_item_set_len(ti, len);

    return len;
}

/*
 * Decodes message envelope
 *
 * Returns length of the dissected record
 * It also sets reqid (Request ID) and encrypted (the encrypted bit)
 */
static int
decode_envelope(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t *reqid, bool *encrypted)
{

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DO-IRP");
    col_clear(pinfo->cinfo,COL_INFO);

    int offset = 0;

    /* Message Envelope */
    proto_item *ti_envelope = proto_tree_add_item(tree, hf_do_irp_envelope, tvb, offset, 20, ENC_NA);
    proto_tree *do_irp_envelope_tree = proto_item_add_subtree(ti_envelope, ett_do_irp_envelope);

    proto_tree_add_item(do_irp_envelope_tree, hf_do_irp_version_major, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(do_irp_envelope_tree, hf_do_irp_version_minor, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    static int* const envelope_flag_bits[] = {
        &hf_do_irp_flag_cp,
        &hf_do_irp_flag_ec,
        &hf_do_irp_flag_tc,
        NULL
    };

    *encrypted = (bool)tvb_get_bits8(tvb, offset*8 + 1, 1);
    proto_tree_add_bitmask(do_irp_envelope_tree, tvb, offset, hf_do_irp_flags, ett_do_irp_envelope_flags, envelope_flag_bits, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(do_irp_envelope_tree, hf_do_irp_version_major_sugg, tvb, offset*8+3, 5, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(do_irp_envelope_tree, hf_do_irp_version_minor_sugg, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(do_irp_envelope_tree, hf_do_irp_sessid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    *reqid = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(do_irp_envelope_tree, hf_do_irp_reqid, tvb, offset, 4, ENC_BIG_ENDIAN);
    col_append_fstr(pinfo->cinfo, COL_INFO, "ReqID=%u", tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN));
    offset += 4;

    proto_tree_add_item(do_irp_envelope_tree, hf_do_irp_seq, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(do_irp_envelope_tree, hf_do_irp_msglen, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

/*
 * Decodes message header, body and credential record
 *
 * Returns length of the dissected record
 */
static int
decode_header_body_credential(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t reqid)
{
    conversation_t *conversation;
    struct do_irp_request_hash_key request_key, *new_request_key;
    struct do_irp_request_hash_val *request_val = NULL;
    proto_item *r_pkt;

    /* Message Header */
    proto_item *ti_header = proto_tree_add_item(tree, hf_do_irp_header, tvb, 0, 24, ENC_NA);
    proto_tree *do_irp_header_tree = proto_item_add_subtree(ti_header, ett_do_irp_header);

    int offset = 0;

    uint32_t opcode = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(do_irp_header_tree, hf_do_irp_opcode, tvb, offset, 4, ENC_BIG_ENDIAN);
    const char *opcode_text = val_to_str_const(tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN), opcode_vals, "Unknown OpCode");
    offset += 4;

    uint32_t respcode = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(do_irp_header_tree, hf_do_irp_responsecode, tvb, offset, 4, ENC_BIG_ENDIAN);
    const char *respcode_text = val_to_str_const(tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN), responsecode_vals, "Unknown RespCode");
    offset += 4;

    col_append_fstr(pinfo->cinfo, COL_INFO, " [%s, %s]", opcode_text, respcode_text);

    static int* const header_flag_bits[] = {
        &hf_do_irp_opflags_at,
        &hf_do_irp_opflags_ct,
        &hf_do_irp_opflags_enc,
        &hf_do_irp_opflags_rec,
        &hf_do_irp_opflags_ca,
        &hf_do_irp_opflags_cn,
        &hf_do_irp_opflags_kc,
        &hf_do_irp_opflags_po,
        &hf_do_irp_opflags_rd,
        &hf_do_irp_opflags_owe,
        &hf_do_irp_opflags_mns,
        &hf_do_irp_opflags_dnr,
        NULL
    };

    proto_tree_add_bitmask(do_irp_header_tree, tvb, offset, hf_do_irp_opflags, ett_do_irp_header_flags, header_flag_bits, ENC_BIG_ENDIAN);
    uint32_t header_opflags = tvb_get_ntohl(tvb, offset);
    offset += 4;

    proto_tree_add_item(do_irp_header_tree, hf_do_irp_sisn, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(do_irp_header_tree, hf_do_irp_rcount, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 2; /* One byte empty */

    proto_tree_add_item(do_irp_header_tree, hf_do_irp_expiration, tvb, offset, 4, ENC_TIME_SECS);
    offset += 4;

    proto_tree_add_item(do_irp_header_tree, hf_do_irp_bodylen, tvb, offset, 4, ENC_BIG_ENDIAN);
    uint32_t body_len = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
    offset += 4;

    /* Message Body */
    if(tvb_captured_length_remaining(tvb, offset) > 0 && body_len > 0) {

        proto_item *ti_body = proto_tree_add_item(tree, hf_do_irp_body, tvb, offset, body_len, ENC_NA);
        proto_tree *do_irp_body_tree = proto_item_add_subtree(ti_body, ett_do_irp_body);

        int body_start_offset = offset;

        /* If RD bit is set, body must start with message digest (response only) */
        if(header_opflags & 0x800000 && respcode > DO_IRP_RC_RESERVED) {

            proto_tree_add_item(do_irp_body_tree, hf_do_irp_digest_algo, tvb, offset, 1, ENC_NA);
            offset += 1;

            switch (tvb_get_uint8(tvb, offset-1)) {

                case DO_IRP_DIGEST_ALGO_MD5:
                    proto_tree_add_item(do_irp_body_tree, hf_do_irp_digest, tvb, offset, 16, ENC_NA);
                    offset += 16;
                    break;

                case DO_IRP_DIGEST_ALGO_SHA1:
                    proto_tree_add_item(do_irp_body_tree, hf_do_irp_digest, tvb, offset, 20, ENC_NA);
                    offset += 20;
                    break;

                case DO_IRP_DIGEST_ALGO_SHA256:
                    proto_tree_add_item(do_irp_body_tree, hf_do_irp_digest, tvb, offset, 32, ENC_NA);
                    offset += 32;
                    break;

                default:
                    expert_add_info(pinfo, do_irp_body_tree, &ei_do_irp_digest_unknown);
                    /* We are now unable to dissect further because the fields now have variable length */
                    call_data_dissector(
                        tvb_new_subset_length(tvb, offset, -1), pinfo, do_irp_body_tree);
                    return tvb_captured_length(tvb);

            }
        }

        if(opcode == DO_IRP_OC_RESOLUTION && respcode == DO_IRP_RC_RESERVED) { /* Query */

            const char *identifier_text;
            offset += decode_string(tvb, pinfo, do_irp_body_tree, offset, hf_do_irp_ident, &identifier_text);

            col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", identifier_text);

            uint32_t index_entries = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_item(do_irp_body_tree, hf_do_irp_idxcount, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            for(uint32_t i = 0; i < index_entries; i++) {
                proto_tree_add_item(do_irp_body_tree, hf_do_irp_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            }

            uint32_t type_entries = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_item(do_irp_body_tree, hf_do_irp_typecount, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            for(uint32_t i = 0; i < type_entries; i++) {
                offset += decode_string(tvb, pinfo, do_irp_body_tree, offset, hf_do_irp_type, NULL);
            }

        }
        else if(
            (opcode == DO_IRP_OC_RESOLUTION && respcode == DO_IRP_RC_SUCCESS) ||      /* Successful query response */
            (opcode == DO_IRP_OC_ADD_ELEMENT && respcode == DO_IRP_RC_RESERVED) ||    /* Add elements request */
            (opcode == DO_IRP_OC_MODIFY_ELEMENT && respcode == DO_IRP_RC_RESERVED) || /* Modify elements request */
            (opcode == DO_IRP_OC_CREATE_ID && respcode == DO_IRP_RC_RESERVED)         /* Create identifier request */
        ) {

            const char *identifier_text;
            offset += decode_string(tvb, pinfo, do_irp_body_tree, offset, hf_do_irp_ident, &identifier_text);

            col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", identifier_text);

            uint32_t element_entries = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_item(do_irp_body_tree, hf_do_irp_identcount, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            for(uint32_t i = 0; i < element_entries; i++) {
                offset += decode_identifier_record(tvb, pinfo, do_irp_body_tree, offset);

            }

        }
        if(opcode == DO_IRP_OC_REMOVE_ELEMENT && respcode == DO_IRP_RC_RESERVED) { /* Remove elements request */

            const char *identifier_text;
            offset += decode_string(tvb, pinfo, do_irp_body_tree, offset, hf_do_irp_ident, &identifier_text);

            col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", identifier_text);

            uint32_t index_entries = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_item(do_irp_body_tree, hf_do_irp_idxcount, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            for(uint32_t i = 0; i < index_entries; i++) {
                proto_tree_add_item(do_irp_body_tree, hf_do_irp_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            }

        }
        else if( /* Referral response */
            (opcode == DO_IRP_OC_RESOLUTION && respcode == DO_IRP_RC_SERVICE_REFERRAL) ||
            (opcode == DO_IRP_OC_RESOLUTION && respcode == DO_IRP_RC_PREFIX_REFERRAL)
        ) {

            const char *refident;
            offset += decode_string(tvb, pinfo, do_irp_body_tree, offset, hf_do_irp_refident, &refident);

            /* The following identifier records only exist if ReferralIdentifier is not provided, otherwise it must be empty */
            if(strlen(refident) == 0) {

                uint32_t element_entries = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
                proto_tree_add_item(do_irp_body_tree, hf_do_irp_identcount, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;

                for(uint32_t i = 0; i < element_entries; i++) {
                    offset += decode_identifier_record(tvb, pinfo, do_irp_body_tree, offset);

                }
            }

        }
        else if(opcode == DO_IRP_OC_VERIFY_RESPONSE && respcode == DO_IRP_RC_SUCCESS) { /* Challenge response verification response */

            proto_tree_add_item(do_irp_body_tree, hf_do_irp_veri_result, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

        }
        else if(opcode == DO_IRP_OC_VERIFY_RESPONSE && respcode == DO_IRP_RC_RESERVED) { /* Challenge response verification */

            offset += decode_string(tvb, pinfo, do_irp_body_tree, offset, hf_do_irp_keyident, NULL);

            proto_tree_add_item(do_irp_body_tree, hf_do_irp_keyidx, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            offset += decode_generic_data(tvb, do_irp_body_tree, offset, hf_do_irp_nonce);

            offset += decode_generic_data(tvb, do_irp_body_tree, offset, hf_do_irp_digest);

            offset += decode_generic_data(tvb, do_irp_body_tree, offset, hf_do_irp_challresp);

        }
        else if(opcode == DO_IRP_OC_CHALLENGE_RESPONSE && respcode == DO_IRP_RC_RESERVED) { /* Challenge response (client -> server) */

            offset += decode_string(tvb, pinfo, do_irp_body_tree, offset, hf_do_irp_authtype, NULL);

            offset += decode_string(tvb, pinfo, do_irp_body_tree, offset, hf_do_irp_keyident, NULL);

            proto_tree_add_item(do_irp_body_tree, hf_do_irp_keyidx, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            offset += decode_generic_data(tvb, do_irp_body_tree, offset, hf_do_irp_challresp);

        }
        else if(respcode == DO_IRP_RC_AUTHEN_NEEDED) { /* Challenge (server -> client) */

            offset += decode_generic_data(tvb, do_irp_body_tree, offset, hf_do_irp_nonce);

        }
        else if(
            (opcode == DO_IRP_OC_GET_SITEINFO && respcode == DO_IRP_RC_RESERVED) ||     /* GetSiteInfo request */
            (opcode == DO_IRP_OC_LIST_HOMED_PREFIXES && respcode == DO_IRP_RC_RESERVED) /* List homed prefixes request */
        ) {

            offset += decode_string(tvb, pinfo, do_irp_body_tree, offset, hf_do_irp_ignoredident, NULL);

        }
        else if(opcode == DO_IRP_OC_GET_SITEINFO && respcode == DO_IRP_RC_SUCCESS) { /* GetSiteInfo response */

            offset += decode_hssite(tvb, pinfo, do_irp_body_tree, offset);

        }
        else if(
            (opcode == DO_IRP_OC_CREATE_ID && respcode == DO_IRP_RC_SUCCESS) ||              /* Create identifier response */
            (opcode == DO_IRP_OC_DELETE_ID && respcode == DO_IRP_RC_RESERVED) ||             /* Delete identifier request */
            (opcode == DO_IRP_OC_LIST_IDS && respcode == DO_IRP_RC_RESERVED) ||              /* List IDs request */
            (opcode == DO_IRP_OC_LIST_DERIVED_PREFIXES && respcode == DO_IRP_RC_RESERVED) || /* List der. prefixes request */
            (opcode == DO_IRP_OC_HOME_PREFIX && respcode == DO_IRP_RC_RESERVED) ||           /* Home prefix request */
            (opcode == DO_IRP_OC_UNHOME_PREFIX && respcode == DO_IRP_RC_RESERVED)            /* Unhome prefix request */
        ) {

            offset += decode_string(tvb, pinfo, do_irp_body_tree, offset, hf_do_irp_ident, NULL);

        }
        else if(
            (opcode == DO_IRP_OC_LIST_IDS && respcode == DO_IRP_RC_SUCCESS) ||              /* List IDs response */
            (opcode == DO_IRP_OC_LIST_DERIVED_PREFIXES && respcode == DO_IRP_RC_SUCCESS) || /* List der. prefixes response */
            (opcode == DO_IRP_OC_LIST_HOMED_PREFIXES && respcode == DO_IRP_RC_SUCCESS)      /* List homed prefixes response */
        ) {

            uint32_t element_entries = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_item(do_irp_body_tree, hf_do_irp_identcount, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            for(uint32_t i = 0; i < element_entries; i++) {
                offset += decode_string(tvb, pinfo, do_irp_body_tree, offset, hf_do_irp_ident, NULL);
            }

        }
        else if(opcode == DO_IRP_OC_SESSION_SETUP && respcode == DO_IRP_RC_RESERVED) { /* Session setup request */

            proto_tree_add_item(do_irp_body_tree, hf_do_irp_keyexmode, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(do_irp_body_tree, hf_do_irp_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            offset += decode_string(tvb, pinfo, do_irp_body_tree, offset, hf_do_irp_ident, NULL);

            proto_tree_add_item(do_irp_body_tree, hf_do_irp_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            offset += decode_pk_data(tvb, pinfo, do_irp_body_tree, offset);

        }
        else if(opcode == DO_IRP_OC_SESSION_SETUP && respcode == DO_IRP_RC_SUCCESS) { /* Session setup response */

            proto_tree_add_item(do_irp_body_tree, hf_do_irp_keyexmode, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            offset += decode_pk_data(tvb, pinfo, do_irp_body_tree, offset);

        }
        /* All error resposes */
        else if(
            (respcode >= DO_IRP_RC_ERROR && respcode <= DO_IRP_RC_SERVER_NOT_RESP) ||
            (respcode >= DO_IRP_RC_INVALID_ADMIN && respcode <= DO_IRP_RC_ACCESS_DENIED) ||
            (respcode >= DO_IRP_RC_AUTHEN_FAILED && respcode <= DO_IRP_RC_SESSION_MSG_REJECTED)
        ) {

            if(tvb_ensure_captured_length_remaining(tvb, offset) >= 4 ) {
                offset += decode_string(tvb, pinfo, do_irp_body_tree, offset, hf_do_irp_error_msg, NULL);
            }

            /* If body length has not been reached, there must be error indices*/
            if((uint32_t)(offset - body_start_offset) < body_len) {

                uint32_t err_indices = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
                proto_tree_add_item(do_irp_body_tree, hf_do_irp_error_idxcount, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;

                for(uint32_t i = 0; i < err_indices; i++) {
                    proto_tree_add_item(do_irp_body_tree, hf_do_irp_error_idx, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                }
            }
        }
        else {
            /* unsupported codes */
            int unhandled_bytes = body_len - (offset - body_start_offset);
            call_data_dissector(
                tvb_new_subset_length(tvb, offset, unhandled_bytes),
                pinfo, do_irp_body_tree
            );
            offset += unhandled_bytes;
        }
    }

    /* Message Credential */
    if(tvb_captured_length_remaining(tvb, offset) >= 4) {

        uint32_t cred_len = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);

        proto_item *ti_cred = proto_tree_add_item(tree, hf_do_irp_credential, tvb, offset, cred_len + 4, ENC_NA);
        proto_tree *do_irp_cred_tree = proto_item_add_subtree(ti_cred, ett_do_irp_credential);

        proto_tree_add_item(do_irp_cred_tree, hf_do_irp_credential_len, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        if(cred_len > 0) { /* If credential length is 0, is ends here */

            offset += 8; /* Reserved */

            proto_tree_add_item(do_irp_cred_tree, hf_do_irp_credential_sesscounter, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            offset += decode_string(tvb, pinfo, do_irp_cred_tree, offset, hf_do_irp_credential_type, NULL);

            uint32_t sig_len = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);

            if(sig_len) {

                proto_item *ti_signedinfo = proto_tree_add_item(do_irp_cred_tree, hf_do_irp_credential_signedinfo, tvb, offset, sig_len + 4, ENC_NA);
                proto_tree *do_irp_signedinfo_tree = proto_item_add_subtree(ti_signedinfo, ett_do_irp_credential_signedinfo);

                proto_tree_add_item(do_irp_signedinfo_tree, hf_do_irp_credential_signedinfo_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;

                const char *algo;
                offset += decode_string(tvb, pinfo, do_irp_signedinfo_tree, offset, hf_do_irp_credential_signedinfo_algo, &algo);
                proto_item_append_text(do_irp_signedinfo_tree, " (%s)", algo);

                offset += decode_generic_data(tvb, do_irp_signedinfo_tree, offset, hf_do_irp_credential_signedinfo_sig);
            }
        }
    }

    /* Conversation Handling */
    conversation = find_or_create_conversation(pinfo);
    request_key.conv_index = conversation->conv_index;
    request_key.reqid      = reqid;

    request_val = (struct do_irp_request_hash_val *) wmem_map_lookup(do_irp_request_hash_map, &request_key);

    /* If this packet is a request WITHOUT a registered request */
    if(respcode == DO_IRP_RC_RESERVED && !request_val) {

        new_request_key = wmem_new(wmem_file_scope(), struct do_irp_request_hash_key);
        *new_request_key = request_key;

        request_val = wmem_new(wmem_file_scope(), struct do_irp_request_hash_val);
        request_val->pnum         = pinfo->num;
        request_val->pnum_resp    = 0;
        request_val->opcode       = opcode;

        wmem_map_insert(do_irp_request_hash_map, new_request_key, request_val);

    }
    /* If this packet is a request WITH a registered request */
    else if(respcode == DO_IRP_RC_RESERVED && request_val) {

        if(request_val->pnum_resp > 0) {
            r_pkt = proto_tree_add_uint(tree , hf_do_irp_response_in, tvb, 0, 0, request_val->pnum_resp);
            proto_item_set_generated(r_pkt);
        }

    }
    /* If this packet is a response to a registered request */
    else if(respcode != DO_IRP_RC_RESERVED && request_val) {

        request_val->pnum_resp = pinfo->num;

        r_pkt = proto_tree_add_uint(tree , hf_do_irp_response_to, tvb, 0, 0, request_val->pnum);
        proto_item_set_generated(r_pkt);
    }

    return offset;
}

static bool
test_do_irp(tvbuff_t *tvb)
{
    /* Minimum length (envelope must be present) */
    if(tvb_captured_length(tvb) < DO_IRP_ENVELOPE_LEN)
        return false;

    /* Supported versions (2, 3) */
    uint8_t majorversion = tvb_get_uint8(tvb, 0);
    if(majorversion < 2 || majorversion > 3)
        return false;

    /* Message Length must not be 0 */
    if(tvb_get_uint32(tvb, 16, ENC_BIG_ENDIAN) == 0)
        return false;

    return true;
}

static unsigned
get_do_irp_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    return (tvb_get_uint32(tvb, offset + 16, ENC_BIG_ENDIAN) + DO_IRP_ENVELOPE_LEN);
}

static int
dissect_do_irp_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

    /* Do some basic tests */
    if(!test_do_irp(tvb))
        return 0;

    proto_item *ti = proto_tree_add_item(tree, proto_do_irp, tvb, 0, -1, ENC_NA);
    proto_tree *do_irp_tree = proto_item_add_subtree(ti, ett_do_irp);

    uint32_t reqid;
    bool encrypted;
    tvbuff_t *new_tvb = NULL;
    int offset = 0;

    /*
     * RFC 3652 defines `<MessageFlag>` in 2.2.1.2 as two octets containing three flags.
     * | MessageFlag (3 bits) | Reserved (13 bits) |
     *
     * DO-IRP v3.0 divided this field into three fields in 6.2.1 ff. while maintaining backward compatibility.
     * | Flag (3 bits) | SuggMajor (5 bits) | SuggMinor (8 bits) |
     *
     * Both documents state that in case of fragmentation, each fragment must contain an envelope with the truncated bit (TC) set.
     * In the wild the TC-flag is often ignored or not set. Therefore, reassembly is not (only) based on the TC-bit here,
     * to be able to generate expert info when protocol specs are violated.
     */

    uint32_t msg_len = tvb_get_uint32(tvb, 16, ENC_BIG_ENDIAN); /* Length of over-all message, excluding envelope */
    uint8_t env_flags = tvb_get_uint8(tvb, 2);

    /* Envelope is always present */
    offset += decode_envelope(tvb, pinfo, do_irp_tree, &reqid, &encrypted);

    if (
        msg_len > (DO_IRP_MAX_UDP_SIZE - DO_IRP_ENVELOPE_LEN) || /* Message does not fit into one packet */
        env_flags & 0x20                                         /* TC-bit set */
    ) {
        /* fragmented */

        fragment_head *frag_msg = NULL;
        bool first_frag = false;

        uint16_t msg_reqid = tvb_get_uint32(tvb, 8, ENC_BIG_ENDIAN);
        uint16_t msg_seqid = tvb_get_uint32(tvb, 12, ENC_BIG_ENDIAN);

        if( !(env_flags & 0x20) ) {
            expert_add_info(pinfo, do_irp_tree, &ei_do_irp_frag_wo_tc);
        }

        /* Check if it's the first fragment, to set expected packets after first fragment_add */
        if(fragment_get_tot_len(&do_irp_reassemble_table, pinfo, msg_reqid, NULL) == 0) {
            first_frag = true;
        }

        pinfo->fragmented = true;
        frag_msg = fragment_add_seq_check(&do_irp_reassemble_table, tvb, offset, pinfo,
            msg_reqid, NULL,
            msg_seqid,
            tvb_captured_length_remaining(tvb, offset),
            true /* Expected packet count set */
        );

        if(first_frag) {

            uint32_t expected_packets = msg_len / (DO_IRP_MAX_UDP_SIZE - DO_IRP_ENVELOPE_LEN);
            if ((msg_len % (DO_IRP_MAX_UDP_SIZE - DO_IRP_ENVELOPE_LEN)) != 0) expected_packets++;

            fragment_set_tot_len(&do_irp_reassemble_table, pinfo, msg_reqid, NULL, expected_packets-1); /* Set expected packet count (0-index) */
        }

        new_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled Message", frag_msg, &msg_frag_items, NULL, do_irp_tree);


        if (new_tvb) { /* Packet reassembled */

            if(!encrypted) {
                offset += decode_header_body_credential(new_tvb, pinfo, do_irp_tree, reqid);
            } else  {
                /* Encrypted message can't be decoded */
                col_append_str(pinfo->cinfo, COL_INFO, " (encrypted)");
                call_data_dissector(new_tvb, pinfo, do_irp_tree);
                offset = tvb_captured_length(tvb);
            }
            col_append_fstr(pinfo->cinfo, COL_INFO, " (Frag=%u, Reassembled)", msg_seqid+1);

        } else { /* Packet fragment */

            call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, do_irp_tree);
            col_append_fstr(pinfo->cinfo, COL_INFO, " (Frag=%u)", msg_seqid+1);
            offset = tvb_captured_length(tvb);
        }

    }
    else {

        /* No fragmentation */
        new_tvb = tvb_new_subset_remaining(tvb, offset);

        if(!encrypted) {
            offset += decode_header_body_credential(new_tvb, pinfo, do_irp_tree, reqid);
        } else {
            /* Encrypted message can't be decoded */
            col_append_str(pinfo->cinfo, COL_INFO, " (encrypted)");
            call_data_dissector(new_tvb, pinfo, do_irp_tree);
            offset = tvb_captured_length(tvb);
        }

    }

    return offset;
}

static int
dissect_do_irp_tcp_full_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti = proto_tree_add_item(tree, proto_do_irp, tvb, 0, -1, ENC_NA);
    proto_tree *do_irp_tree = proto_item_add_subtree(ti, ett_do_irp);

    uint32_t reqid;
    bool enc;
    int offset = 0;

    offset += decode_envelope(tvb, pinfo, do_irp_tree, &reqid, &enc);
    offset += decode_header_body_credential(tvb_new_subset_remaining(tvb, offset), pinfo, do_irp_tree, reqid);

    return offset;
}

static int
dissect_do_irp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Do some basic tests */
    if(!test_do_irp(tvb))
        return 0;

    tcp_dissect_pdus(tvb, pinfo, tree, true, DO_IRP_ENVELOPE_LEN, get_do_irp_message_len, dissect_do_irp_tcp_full_message, data);
    return tvb_reported_length(tvb);
}

void
proto_register_do_irp(void)
{
    static hf_register_info hf[] = {

        /* Fragment handling */
        {&hf_msg_fragments,
            { "Message fragments", "do-irp.fragments",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        {&hf_msg_fragment,
            { "Message fragment", "do-irp.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        {&hf_msg_fragment_overlap,
            { "Message fragment overlap", "do-irp.fragment.overlap",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        {&hf_msg_fragment_overlap_conflicts,
            { "Message fragment overlapping with conflicting data", "do-irp.fragment.overlap.conflicts",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        {&hf_msg_fragment_multiple_tails,
            { "Message has multiple tail fragments", "do-irp.fragment.multiple_tails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        {&hf_msg_fragment_too_long_fragment,
            { "Message fragment too long", "do-irp.fragment.too_long_fragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        {&hf_msg_fragment_error,
            { "Message defragmentation error", "do-irp.fragment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        {&hf_msg_fragment_count,
            { "Message fragment count", "do-irp.fragment.count",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        {&hf_msg_reassembled_in,
            { "Reassembled in", "do-irp.reassembled.in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        {&hf_msg_reassembled_len,
            { "Reassembled length", "do-irp.reassembled.len",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        {&hf_msg_reassembled_data,
            { "Reassembled data", "do-irp.reassembled.data",
            FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },

        /* Generic */
        { &hf_do_irp_string_len,
            { "Length", "do-irp.string.len",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_string_value,
            { "Value", "do-irp.string.value",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_data_len,
            { "Length", "do-irp.data.len",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_data_value,
            { "Value", "do-irp.data.value",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        /* Message Envelope */
        { &hf_do_irp_envelope,
            { "Message Envelope", "do-irp.envelope",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_version_major,
            { "Version (Major)", "do-irp.version.major",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_version_minor,
            { "Version (Minor)", "do-irp.version.minor",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_flags,
            { "Flags", "do-irp.flags",
            FT_UINT8, BASE_HEX, NULL, 0xE0, NULL, HFILL }
        },
        { &hf_do_irp_flag_cp,
            { "Compressed", "do-irp.flags.cp",
            FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }
        },
        { &hf_do_irp_flag_ec,
            { "Encrypted", "do-irp.flags.ec",
            FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }
        },
        { &hf_do_irp_flag_tc,
            { "Truncated", "do-irp.flags.tc",
            FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }
        },
        { &hf_do_irp_version_major_sugg,
            { "Version (Major, suggested)", "do-irp.version.major_sugg",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_version_minor_sugg,
            { "Version (Minor, suggested)", "do-irp.version.minor_sugg",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_sessid,
            { "Session ID", "do-irp.sessid",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_reqid,
            { "Request ID", "do-irp.reqid",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_seq,
            { "Sequence No.", "do-irp.seq",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_msglen,
            { "Message Length", "do-irp.msglen",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },

        /* Message Header */
        { &hf_do_irp_header,
            { "Message Header", "do-irp.header",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_opcode,
            { "Operation Code", "do-irp.opcode",
            FT_UINT32, BASE_DEC, VALS(opcode_vals), 0x0, NULL, HFILL }
        },
        { &hf_do_irp_responsecode,
            { "Response Code", "do-irp.responsecode",
            FT_UINT32, BASE_DEC, VALS(responsecode_vals), 0x0, NULL, HFILL }
        },
        { &hf_do_irp_opflags,
            { "Flags", "do-irp.opflags",
            FT_UINT32, BASE_HEX, NULL, 0xFFF00000, NULL, HFILL }
        },
        { &hf_do_irp_opflags_at,
            { "Authoritative", "do-irp.opflags.at",
            FT_BOOLEAN, 32, NULL, 0x80000000, NULL, HFILL }
        },
        { &hf_do_irp_opflags_ct,
            { "Certified", "do-irp.opflags.ct",
            FT_BOOLEAN, 32, NULL, 0x40000000, NULL, HFILL }
        },
        { &hf_do_irp_opflags_enc,
            { "Encryption", "do-irp.opflags.enc",
            FT_BOOLEAN, 32, NULL, 0x20000000, NULL, HFILL }
        },
        { &hf_do_irp_opflags_rec,
            { "Recursive", "do-irp.opflags.rec",
            FT_BOOLEAN, 32, NULL, 0x10000000, NULL, HFILL }
        },
        { &hf_do_irp_opflags_ca,
            { "Cache Authentication", "do-irp.opflags.ca",
            FT_BOOLEAN, 32, NULL, 0x08000000, NULL, HFILL }
        },
        { &hf_do_irp_opflags_cn,
            { "Continuous", "do-irp.opflags.cn",
            FT_BOOLEAN, 32, NULL, 0x04000000, NULL, HFILL }
        },
        { &hf_do_irp_opflags_kc,
            { "Keep Connection", "do-irp.opflags.kc",
            FT_BOOLEAN, 32, NULL, 0x02000000, NULL, HFILL }
        },
        { &hf_do_irp_opflags_po,
            { "Public Only", "do-irp.opflags.po",
            FT_BOOLEAN, 32, NULL, 0x01000000, NULL, HFILL }
        },
        { &hf_do_irp_opflags_rd,
            { "Request-Digest", "do-irp.opflags.rd",
            FT_BOOLEAN, 32, NULL, 0x00800000, NULL, HFILL }
        },
        { &hf_do_irp_opflags_owe,
            { "Overwrite when exists", "do-irp.opflags.owe",
            FT_BOOLEAN, 32, NULL, 0x00400000, NULL, HFILL }
        },
        { &hf_do_irp_opflags_mns,
            { "Mint new suffix", "do-irp.opflags.mns",
            FT_BOOLEAN, 32, NULL, 0x00200000, NULL, HFILL }
        },
        { &hf_do_irp_opflags_dnr,
            { "Do not refer", "do-irp.opflags.dnr",
            FT_BOOLEAN, 32, NULL, 0x00100000, NULL, HFILL }
        },
        { &hf_do_irp_sisn,
            { "Site Info Serial No.", "do-irp.sisn",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_rcount,
            { "Recursion Count", "do-irp.recursioncount",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_expiration,
            { "Expiration Time", "do-irp.exp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_bodylen,
            { "Body Length", "do-irp.bodylen",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },

        /* Message Body */
        { &hf_do_irp_body,
            { "Message Body", "do-irp.body",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_digest_algo,
            { "Message Digest Algorithm", "do-irp.digest_algo",
            FT_UINT8, BASE_DEC, VALS(digest_algo_vals), 0x0, NULL, HFILL }
        },
        { &hf_do_irp_digest,
            { "Message Digest", "do-irp.digest",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_error_msg,
            { "Error Message", "do-irp.error.msg",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_error_idxcount,
            { "Error Indices", "do-irp.error.idxcount",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_error_idx,
            { "Error Index", "do-irp.error.idx",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_ident,
            { "Identifier", "do-irp.ident",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_idxcount,
            { "Index Count", "do-irp.idxcount",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_idx,
            { "Index", "do-irp.idx",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_typecount,
            { "Type Count", "do-irp.typecount",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_type,
            { "Type Entry", "do-irp.type",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_identcount,
            { "Identifier Records", "do-irp.identcount",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_identrecord,
            { "Identifier Record", "do-irp.identrecord",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_identrecord_idx,
            { "Index", "do-irp.identrecord.idx",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_identrecord_type,
            { "Type", "do-irp.identrecord.type",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_identrecord_value,
            { "Value", "do-irp.identrecord.value",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_identrecord_value_string,
            { "Value", "do-irp.identrecord.value.string",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_identrecord_value_len,
            { "Length", "do-irp.identrecord.value.len",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_identrecord_perm,
            { "Permission", "do-irp.identrecord.perm",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_identrecord_perm_ar,
            { "ADMIN_READ", "do-irp.identrecord.perm.ar",
            FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }
        },
        { &hf_do_irp_identrecord_perm_aw,
            { "ADMIN_WRITE", "do-irp.identrecord.perm.aw",
            FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }
        },
        { &hf_do_irp_identrecord_perm_pr,
            { "PUBLIC_READ", "do-irp.identrecord.perm.pr",
            FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }
        },
        { &hf_do_irp_identrecord_perm_pw,
            { "PUBLIC_WRITE", "do-irp.identrecord.perm.pw",
            FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }
        },
        { &hf_do_irp_identrecord_ts,
            { "Timestamp", "do-irp.identrecord.ts",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_identrecord_ts_utc,
            { "Timestamp (UTC)", "do-irp.identrecord.ts_utc",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_identrecord_ttl_type,
            { "TTL Type", "do-irp.identrecord.ttl_type",
            FT_UINT8, BASE_DEC, VALS(ttl_vals), 0x0, NULL, HFILL }
        },
        { &hf_do_irp_identrecord_ttl,
            { "TTL", "do-irp.identrecord.ttl",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_identrecord_ttl_absolute,
            { "TTL (until)", "do-irp.identrecord.ttl_absolute",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_identrecord_refcount,
            { "Reference Count", "do-irp.identrecord.refcount",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_identrecord_ref,
            { "Reference", "do-irp.identrecord.ref",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hsadmin_perm,
            { "Permission", "do-irp.hsadmin.perm",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hsadmin_perm_ai,
            { "Add Identifier", "do-irp.hsadmin.perm.ai",
            FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL }
        },
        { &hf_do_irp_hsadmin_perm_di,
            { "Delete Identifier", "do-irp.hsadmin.perm.di",
            FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL }
        },
        { &hf_do_irp_hsadmin_perm_adp,
            { "Add Derived Prefix", "do-irp.hsadmin.perm.adp",
            FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL }
        },
        { &hf_do_irp_hsadmin_perm_me,
            { "Modify Element", "do-irp.hsadmin.perm.me",
            FT_BOOLEAN, 16, NULL, 0x0010, NULL, HFILL }
        },
        { &hf_do_irp_hsadmin_perm_de,
            { "Delete Element", "do-irp.hsadmin.perm.de",
            FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL }
        },
        { &hf_do_irp_hsadmin_perm_ae,
            { "Add Element", "do-irp.hsadminp.perm.ae",
            FT_BOOLEAN, 16, NULL, 0x0040, NULL, HFILL }
        },
        { &hf_do_irp_hsadmin_perm_ma,
            { "Modify Admin", "do-irp.hsadmin.perm.ma",
            FT_BOOLEAN, 16, NULL, 0x0080, NULL, HFILL }
        },
        { &hf_do_irp_hsadmin_perm_ra,
            { "Remove Admin", "do-irp.hsadmin.perm.ra",
            FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL }
        },
        { &hf_do_irp_hsadmin_perm_aa,
            { "Add Admin", "do-irp.hsadmin.perm.aa",
            FT_BOOLEAN, 16, NULL, 0x0200, NULL, HFILL }
        },
        { &hf_do_irp_hsadmin_perm_ar,
            { "Authorized Read", "do-irp.hsadmin.perm.ar",
            FT_BOOLEAN, 16, NULL, 0x0400, NULL, HFILL }
        },
        { &hf_do_irp_hsadmin_perm_li,
            { "List Identifiers", "do-irp.hsadmin.perm.li",
            FT_BOOLEAN, 16, NULL, 0x0800, NULL, HFILL }
        },
        { &hf_do_irp_hsadmin_perm_ldp,
            { "List Derived Prefixes", "do-irp.hsadmin.perm.ldp",
            FT_BOOLEAN, 16, NULL, 0x1000, NULL, HFILL }
        },
        { &hf_do_irp_hsadmin_idx,
            { "Index", "do-irp.hsadmin.idx",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hsadmin_ident,
            { "Identifier", "do-irp.hsadmin.ident",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_body_hssite_version,
            { "Version", "do-irp.hssite.version",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hssite_protoversion_major,
            { "Protocol Version (Major)", "do-irp.hssite.protoversion.major",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hssite_protoversion_minor,
            { "Protocol Version (Minor)", "do-irp.hssite.protoversion.minor",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hssite_serial,
            { "Serial", "do-irp.hssite.serial",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hssite_primask,
            { "Primary Mask", "do-irp.hssite.primask",
            FT_UINT8, BASE_HEX, NULL, 0xFF, NULL, HFILL }
        },
        { &hf_do_irp_hssite_primask_pri,
            { "Primary Site", "do-irp.hssite.primask.pri",
            FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }
        },
        { &hf_do_irp_hssite_primask_multi,
            { "Multi Primary", "do-irp.hssite.primask.multi",
            FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }
        },
        { &hf_do_irp_hssite_hashoption,
            { "Hash Option", "do-irp.hssite.hashoption",
            FT_UINT8, BASE_HEX, VALS(hashoption_vals), 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hssite_hashfilter,
            { "Hash Filter", "do-irp.hssite.hashfilter",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hssite_attr_count,
            { "Attributes", "do-irp.hssite.attr.num",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hssite_attr,
            { "Attribute", "do-irp.hssite.attr",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hssite_attr_key,
            { "Key", "do-irp.hssite.attr.key",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hssite_attr_value,
            { "Value", "do-irp.hssite.attr.value",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hssite_srvcount,
            { "Server Count", "do-irp.hssite.srvcount",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hssite_srv,
            { "Server", "do-irp.hssite.srv",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hssite_srv_id,
            { "ID", "do-irp.hssite.srv.id",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hssite_srv_addr,
            { "Address", "do-irp.hssite.srv.addr",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hssite_srv_ifcount,
            { "Interface Count", "do-irp.hssite.srv.ifcount",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hssite_srv_if,
            { "Interface", "do-irp.hssite.srv.if",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hssite_srv_if_type,
            { "Type", "do-irp.hssite.srv.if.type",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hssite_srv_if_type_admin,
            { "Administration", "do-irp.hssite.srv.if.type.admin",
            FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }
        },
        { &hf_do_irp_hssite_srv_if_type_res,
            { "Resolution", "do-irp.hssite.srv.if.type.res",
            FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }
        },
        { &hf_do_irp_hssite_srv_if_proto,
            { "Protocol", "do-irp.hssite.srv.if.proto",
            FT_UINT8, BASE_HEX, VALS(transportproto_vals), 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hssite_srv_if_port,
            { "Port", "do-irp.hssite.srv.if.port",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_pkrec,
            { "Public Key Data", "do-irp.pk",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_pkrec_len,
            { "Public Key Length", "do-irp.pk.len",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_pkrec_type,
            { "Public Key Type", "do-irp.pk.type",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_pkrec_dsa_q,
            { "DSA (q)", "do-irp.pk.dsa.q",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_pkrec_dsa_p,
            { "DSA (p)", "do-irp.pk.dsa.p",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_pkrec_dsa_g,
            { "DSA (g)", "do-irp.pk.dsa.g",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_pkrec_dsa_y,
            { "DSA (y)", "do-irp.pk.dsa.y",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_pkrec_dh_p,
            { "DH (p)", "do-irp.pk.dh.p",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_pkrec_dh_g,
            { "DH (g)", "do-irp.pk.dh.g",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_pkrec_dh_y,
            { "DH (y)", "do-irp.pk.dh.y",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_pkrec_rsa_exp,
            { "RSA (Exponent)", "do-irp.pk.rsa.exp",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_pkrec_rsa_mod,
            { "RSA (Modulo)", "do-irp.pk.rsa.mod",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hsserv_ident,
            { "Identifier", "do-irp.hsserv.ident",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hsvlist_count,
            { "Reference Count", "do-irp.vlist.count",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hsvlist_ref,
            { "Reference", "do-irp.vlist.ref",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hsalias,
            { "Alias", "do-irp.hsalias",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hsnamespace,
            { "Namespace", "do-irp.hsnamespace",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hscert_jwt,
            { "JWT", "do-irp.hscert.jwt",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_hssignature_jwt,
            { "JWT", "do-irp.hssignature.jwt",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_refident,
            { "Referral Identifier", "do-irp.refident",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_nonce,
            { "Nonce", "do-irp.nonce",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_authtype,
            { "Authentication Type", "do-irp.authtype",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_keyident,
            { "Key Identifier", "do-irp.keyident",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_keyidx,
            { "Key Index", "do-irp.keyidx",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_challresp,
            { "Challenge Response", "do-irp.challresp",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_veri_result,
            { "Verification Result", "do-irp.veri_result",
            FT_UINT8, BASE_DEC, VALS(verification_resp_vals), 0x0, NULL, HFILL }
        },
        { &hf_do_irp_ignoredident,
            { "Ignored Identifier", "do-irp.ignoredident",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_keyexmode,
            { "Key Exchange Mode", "do-irp.keyexmode",
            FT_UINT16, BASE_DEC, VALS(key_exchange_vals), 0x0, NULL, HFILL }
        },
        { &hf_do_irp_timeout,
            { "Timeout", "do-irp.timeout",
            FT_UINT32, BASE_DEC | BASE_UNIT_STRING, &units_seconds, 0x0, NULL, HFILL }
        },

        /* Message Credential */
        { &hf_do_irp_credential,
            { "Message Credential", "do-irp.credential",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_credential_len,
            { "Length", "do-irp.credential.len",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_credential_sesscounter,
            { "Session Counter", "do-irp.credential.sesscounter",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_credential_type,
            { "Type", "do-irp.credential.type",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_credential_signedinfo,
            { "SignedInfo", "do-irp.credential.signedinfo",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_credential_signedinfo_len,
            { "Length", "do-irp.credential.signedinfo.len",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_credential_signedinfo_algo,
            { "Algorithm", "do-irp.credential.signedinfo.algo",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_credential_signedinfo_sig,
            { "Signature", "do-irp.credential.signedinfo.sig",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        /* Conversation */
        { &hf_do_irp_response_in,
            { "Response in", "do-irp.response_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_do_irp_response_to,
            { "Request in", "do-irp.response_to",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL }
        }
    };

    static ei_register_info ei[] = {
        { &ei_do_irp_digest_unknown,
            { "do-irp.header.digest.unknown", PI_MALFORMED, PI_WARN,
                "Invalid digest algorithm", EXPFILL }
        },
        { &ei_do_irp_frag_wo_tc,
            { "do-irp.envelope.tc_missing", PI_MALFORMED, PI_ERROR,
                "Fragmentation without TC bit set", EXPFILL }
        }
    };

    static int *ett[] = {
        &ett_msg_fragment,
        &ett_msg_fragments,
        &ett_do_irp,
        &ett_do_irp_string,
        &ett_do_irp_envelope,
        &ett_do_irp_envelope_flags,
        &ett_do_irp_header,
        &ett_do_irp_header_flags,
        &ett_do_irp_body,
        &ett_do_irp_credential,
        &ett_do_irp_credential_signedinfo,
        &ett_do_irp_identifier_record,
        &ett_do_irp_element_permission_flags,
        &ett_do_irp_element_hsadmin_permission_flags,
        &ett_do_irp_element_hsadmin_primary_flags,
        &ett_do_irp_hsadmin,
        &ett_do_irp_hssite,
        &ett_do_irp_hssite_attribute,
        &ett_do_irp_hssite_server,
        &ett_do_irp_hssite_server_if,
        &ett_do_irp_hssite_server_if_flags,
        &ett_do_irp_pk
    };

    do_irp_request_hash_map = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), do_irp_handle_hash, do_irp_handle_equal);

    proto_do_irp = proto_register_protocol("Digital Object Identifier Resolution Protocol", "DO-IRP", "do-irp");
    expert_do_irp = expert_register_protocol(proto_do_irp);

    proto_register_field_array(proto_do_irp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_register_field_array(expert_do_irp, ei, array_length(ei));

    reassembly_table_register(&do_irp_reassemble_table, &addresses_ports_reassembly_table_functions);

    do_irp_handle_udp = register_dissector("do-irp_udp", dissect_do_irp_udp, proto_do_irp);
    do_irp_handle_tcp = register_dissector("do-irp_tcp", dissect_do_irp_tcp, proto_do_irp);
}

void
proto_reg_handoff_do_irp(void)
{
    dissector_add_uint_with_preference("udp.port", DO_IRP_UDP_PORT, do_irp_handle_udp);
    dissector_add_uint_with_preference("tcp.port", DO_IRP_TCP_PORT, do_irp_handle_tcp);
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

/* packet-rpki-rtr.c
 * Routines for RPKI-Router Protocol dissection (RFC6810)
 * Copyright 2013, Alexis La Goutte <alexis.lagoutte at gmail dot com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later

 * The information used comes from:
 * RFC6810: The Resource Public Key Infrastructure (RPKI) to Router Protocol
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include "packet-tcp.h"
#include "packet-tls.h"
#include <epan/expert.h>
#include <epan/asn1.h>
#include "packet-x509af.h"

void proto_register_rpkirtr(void);
void proto_reg_handoff_rpkirtr(void);

static int proto_rpkirtr;
static int hf_rpkirtr_version;
static int hf_rpkirtr_pdu_type;
static int hf_rpkirtr_reserved;
static int hf_rpkirtr_session_id;
static int hf_rpkirtr_length;
static int hf_rpkirtr_serial_number;
static int hf_rpkirtr_flags;
static int hf_rpkirtr_flags_aw;
static int hf_rpkirtr_flags_rk;
static int hf_rpkirtr_flags_ar;
static int hf_rpkirtr_flags_arafi;
static int hf_rpkirtr_prefix_length;
static int hf_rpkirtr_max_length;
static int hf_rpkirtr_ipv4_prefix;
static int hf_rpkirtr_ipv6_prefix;
static int hf_rpkirtr_as_number;
static int hf_rpkirtr_error_code;
static int hf_rpkirtr_length_pdu;
static int hf_rpkirtr_error_pdu;
static int hf_rpkirtr_length_text;
static int hf_rpkirtr_error_text;
static int hf_rpkirtr_refresh_interval;
static int hf_rpkirtr_retry_interval;
static int hf_rpkirtr_expire_interval;
static int hf_rpkirtr_subject_key_identifier;
static int hf_rpkirtr_subject_public_key_info;
static int hf_rpkirtr_aspa_provider_as_count;
static int hf_rpkirtr_aspa_customer_asn;
static int hf_rpkirtr_aspa_provider_asn;

#define RPKI_RTR_TCP_PORT 323
#define RPKI_RTR_TLS_PORT 324
static unsigned g_port_rpkirtr_tls = RPKI_RTR_TLS_PORT;

static int ett_rpkirtr;
static int ett_flags;
static int ett_flags_nd;
static int ett_providers;

static expert_field ei_rpkirtr_wrong_version_aspa;
static expert_field ei_rpkirtr_wrong_version_router_key;
static expert_field ei_rpkirtr_bad_length;

static dissector_handle_t rpkirtr_handle;


/* http://www.iana.org/assignments/rpki/rpki.xml#rpki-rtr-pdu */
#define RPKI_RTR_SERIAL_NOTIFY_PDU   0
#define RPKI_RTR_SERIAL_QUERY_PDU    1
#define RPKI_RTR_RESET_QUERY_PDU     2
#define RPKI_RTR_CACHE_RESPONSE_PDU  3
#define RPKI_RTR_IPV4_PREFIX_PDU     4
#define RPKI_RTR_IPV6_PREFIX_PDU     6
#define RPKI_RTR_END_OF_DATA_PDU     7
#define RPKI_RTR_CACHE_RESET_PDU     8
#define RPKI_RTR_ROUTER_KEY          9
#define RPKI_RTR_ERROR_REPORT_PDU   10
#define RPKI_RTR_ASPA_PDU           11

static const value_string rtr_pdu_type_vals[] = {
    { RPKI_RTR_SERIAL_NOTIFY_PDU,  "Serial Notify" },
    { RPKI_RTR_SERIAL_QUERY_PDU,   "Serial Query" },
    { RPKI_RTR_RESET_QUERY_PDU,    "Reset Query" },
    { RPKI_RTR_CACHE_RESPONSE_PDU, "Cache Response" },
    { RPKI_RTR_IPV4_PREFIX_PDU,    "IPv4 Prefix" },
    { RPKI_RTR_IPV6_PREFIX_PDU,    "IPv6 Prefix" },
    { RPKI_RTR_END_OF_DATA_PDU,    "End of Data" },
    { RPKI_RTR_CACHE_RESET_PDU,    "Cache Reset" },
    { RPKI_RTR_ROUTER_KEY,         "Router Key" },
    { RPKI_RTR_ERROR_REPORT_PDU,   "Error Report" },
    { RPKI_RTR_ASPA_PDU,           "ASPA" },
    { 0, NULL }
};

/* http://www.iana.org/assignments/rpki/rpki.xml#rpki-rtr-error */
static const value_string rtr_error_code_vals[] = {
    { 0, "Corrupt Data" },
    { 1, "Internal Error" },
    { 2, "No Data Available" },
    { 3, "Invalid Request" },
    { 4, "Unsupported Protocol Version" },
    { 5, "Unsupported PDU Type" },
    { 6, "Withdrawal of Unknown Record" },
    { 7, "Duplicate Announcement Received" },
    { 8, "Unexpected Protocol Version" },
    { 0, NULL }
};

static const true_false_string tfs_flag_type_aw = {
    "Announcement",
    "Withdrawal"
};

static const true_false_string tfs_flag_type_rk = {
    "New Router Key",
    "Delete Router Key"
};

static const true_false_string tfs_flag_type_ar = {
    "New Autonomous System Provider Authorization Record",
    "Delete Autonomous System Provider Authorization Record"
};

static const true_false_string tfs_flag_type_afi_ar = {
    "IPv6",
    "IPv4",
};

static unsigned
get_rpkirtr_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
  uint32_t plen;

  /*
  * Get the length of the RPKI-RTR packet.
  */
  plen = tvb_get_ntohl(tvb, offset+4);

  return plen;
}


static int dissect_rpkirtr_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{

    proto_item *ti = NULL, *ti_flags, *ti_type;
    proto_tree *rpkirtr_tree = NULL, *flags_tree = NULL;
    int offset = 0;
    uint8_t pdu_type, version;
    unsigned length;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {

        ti = proto_tree_add_item(tree, proto_rpkirtr, tvb, 0, -1, ENC_NA);

        rpkirtr_tree = proto_item_add_subtree(ti, ett_rpkirtr);

        proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        version = tvb_get_uint8(tvb, offset);
        offset += 1;

        ti_type = proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_pdu_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        pdu_type = tvb_get_uint8(tvb, offset);
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str(pdu_type, rtr_pdu_type_vals, "Unknown (%d)"));
        proto_item_append_text(ti, " (%s)", val_to_str(pdu_type, rtr_pdu_type_vals, "Unknown %d"));
        offset += 1;

        length = tvb_get_ntohl(tvb, offset);

        switch (pdu_type) {
            case RPKI_RTR_SERIAL_NOTIFY_PDU: /* Serial Notify (0) */
            case RPKI_RTR_SERIAL_QUERY_PDU:  /* Serial Query (1)  */
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_session_id,       tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_length,           tvb, offset, 4, ENC_BIG_ENDIAN);
                /* TODO: Add check length ? */
                offset += 4;
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_serial_number,    tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                break;
            case RPKI_RTR_RESET_QUERY_PDU:  /* Reset Query (2) */
            case RPKI_RTR_CACHE_RESET_PDU:  /* Cache Reset (8) */
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_reserved,         tvb, offset, 2, ENC_NA);
                offset += 2;
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_length,           tvb, offset, 4, ENC_BIG_ENDIAN);
                /* TODO: Add check length ? */
                offset += 4;
                break;
            case RPKI_RTR_CACHE_RESPONSE_PDU:  /* Cache Response (3) */
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_session_id,       tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_length,           tvb, offset, 4, ENC_BIG_ENDIAN);
                /* TODO: Add check length ? */
                offset += 4;
                break;
            case RPKI_RTR_IPV4_PREFIX_PDU: /* IPv4 Prefix (4) */
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_reserved,         tvb, offset, 2, ENC_NA);
                offset += 2;
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_length,           tvb, offset, 4, ENC_BIG_ENDIAN);
                /* TODO: Add check length ? */
                offset += 4;
                ti_flags = proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
                flags_tree = proto_item_add_subtree(ti_flags, ett_flags);
                proto_tree_add_item(flags_tree, hf_rpkirtr_flags_aw,           tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_prefix_length,    tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_max_length,       tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_reserved,         tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_ipv4_prefix,      tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_as_number,        tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                break;
            case RPKI_RTR_IPV6_PREFIX_PDU: /* IPv6 Prefix (6) */
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_reserved,         tvb, offset, 2, ENC_NA);
                offset += 2;
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_length,           tvb, offset, 4, ENC_BIG_ENDIAN);
                /* TODO: Add check length ? */
                offset += 4;
                ti_flags = proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
                flags_tree = proto_item_add_subtree(ti_flags, ett_flags);
                proto_tree_add_item(flags_tree, hf_rpkirtr_flags_aw,           tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_prefix_length,    tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_max_length,       tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_reserved,         tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_ipv6_prefix,      tvb, offset, 16, ENC_NA);
                offset += 16;
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_as_number,        tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                break;
            case RPKI_RTR_END_OF_DATA_PDU: /* End Of Data (7) */
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_session_id,       tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_length,           tvb, offset, 4, ENC_BIG_ENDIAN);
                /* TODO: Add check length ? */
                offset += 4;
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_serial_number,    tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;

                if (version >= 1){
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_refresh_interval, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;

                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_retry_interval,   tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;

                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_expire_interval,  tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                }
                break;

            case RPKI_RTR_ROUTER_KEY: /* Router Key (9) */
                if(version < 1){
                    /* Error about wrong version... */
                    expert_add_info(pinfo, ti_type, &ei_rpkirtr_wrong_version_router_key);
                } else {
                    asn1_ctx_t asn1_ctx;

                    ti_flags = proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
                    flags_tree = proto_item_add_subtree(ti_flags, ett_flags_nd);
                    proto_tree_add_item(flags_tree, hf_rpkirtr_flags_rk,           tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                    proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_reserved,         tvb, offset, 2, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_length,           tvb, offset, 4, ENC_BIG_ENDIAN);
                    /* TODO: Add check length ? */
                    offset += 4;
                    proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_subject_key_identifier, tvb, offset, 20, ENC_NA);
                    offset += 20;

                    proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_as_number, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
                    offset = dissect_x509af_SubjectPublicKeyInfo(false, tvb, offset, &asn1_ctx, rpkirtr_tree, hf_rpkirtr_subject_public_key_info);

                }
                break;
            case RPKI_RTR_ERROR_REPORT_PDU: /* Error Report (10) */
            {
                uint32_t len_pdu, len_text;
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_error_code,       tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_length,           tvb, offset, 4, ENC_BIG_ENDIAN);
                /* TODO: Add check length ? */
                offset += 4;
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_length_pdu,       tvb, offset, 4, ENC_BIG_ENDIAN);
                len_pdu =                                                      tvb_get_ntohl(tvb, offset);
                offset += 4;
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_error_pdu,        tvb, offset, len_pdu, ENC_NA);
                offset +=  len_pdu;
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_length_text,      tvb, offset, 4, ENC_BIG_ENDIAN);
                len_text =                                                     tvb_get_ntohl(tvb, offset);
                offset += 4;
                proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_error_text,   tvb, offset, len_text, ENC_ASCII);
                offset += len_text;
            }
            break;
            case RPKI_RTR_ASPA_PDU: /* ASPA (11) */
                if(version < 2){
                    /* Error about wrong version... */
                    expert_add_info(pinfo, ti_type, &ei_rpkirtr_wrong_version_aspa);
                } else {
                    proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_reserved, tvb, offset, 2, ENC_NA);
                    offset += 2;
                    proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_length, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                    ti_flags = proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
                    flags_tree = proto_item_add_subtree(ti_flags, ett_flags_nd);
                    proto_tree_add_item(flags_tree, hf_rpkirtr_flags_ar, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;
                    ti_flags = proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
                    flags_tree = proto_item_add_subtree(ti_flags, ett_flags_nd);
                    proto_tree_add_item(flags_tree, hf_rpkirtr_flags_arafi, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;

                    unsigned cnt_asns;
                    proto_tree_add_item_ret_uint(rpkirtr_tree, hf_rpkirtr_aspa_provider_as_count, tvb, offset, 2, ENC_BIG_ENDIAN, &cnt_asns);
                    offset += 2;

                    proto_tree_add_item(rpkirtr_tree, hf_rpkirtr_aspa_customer_asn, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;

                    proto_tree *providers_tree = proto_item_add_subtree(rpkirtr_tree, ett_providers);
                    for (unsigned i = 0; i < cnt_asns; i++) {
                        proto_tree_add_item(providers_tree, hf_rpkirtr_aspa_provider_asn, tvb, offset, 4, ENC_BIG_ENDIAN);
                        offset += 4;
                    }
                }
                break;
            default:
                /* No default ? At least sanity check the length*/
                if (length > tvb_reported_length(tvb)) {
                    expert_add_info(pinfo, ti_type, &ei_rpkirtr_bad_length);
                    return tvb_reported_length(tvb);
                }

                offset += length;
                break;
        }
    }

    return tvb_reported_length(tvb);
}

static int
dissect_rpkirtr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RPKI-RTR");
    col_clear(pinfo->cinfo, COL_INFO);

    tcp_dissect_pdus(tvb, pinfo, tree, 1, 8, get_rpkirtr_pdu_len, dissect_rpkirtr_pdu, data);
    return tvb_reported_length(tvb);
}

void
proto_register_rpkirtr(void)
{
    module_t *rpkirtr_module;

    static hf_register_info hf[] = {
        { &hf_rpkirtr_version,
            { "Version", "rpki-rtr.version",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Denoting the version of this protocol (currently 0)", HFILL }
        },
        { &hf_rpkirtr_pdu_type,
            { "PDU Type", "rpki-rtr.pdu_type",
            FT_UINT8, BASE_DEC, VALS(rtr_pdu_type_vals), 0x0,
            "Denoting the type of the PDU", HFILL }
        },
        { &hf_rpkirtr_reserved,
            { "Reserved", "rpki-rtr.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Must be zero", HFILL }
        },
        { &hf_rpkirtr_session_id,
            { "Session ID", "rpki-rtr.session_id",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rpkirtr_length,
            { "Length", "rpki-rtr.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Value the count of the bytes in the entire PDU, including the eight bytes of header that end with the length field", HFILL }
        },
        { &hf_rpkirtr_serial_number,
            { "Serial Number", "rpki-rtr.serial_number",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rpkirtr_flags,
            { "Flags", "rpki-rtr.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rpkirtr_flags_aw,
            { "Flag AW", "rpki-rtr.flags.aw",
            FT_BOOLEAN, 8, TFS(&tfs_flag_type_aw), 0x01,
            NULL, HFILL }
        },
        { &hf_rpkirtr_flags_rk,
            { "Flag Router Key", "rpki-rtr.flags.rk",
            FT_BOOLEAN, 8, TFS(&tfs_flag_type_rk), 0x01,
            NULL, HFILL }
        },
        { &hf_rpkirtr_flags_ar,
            { "Flag ASPA", "rpki-rtr.flags.ar",
            FT_BOOLEAN, 8, TFS(&tfs_flag_type_ar), 0x01,
            NULL, HFILL }
        },
        { &hf_rpkirtr_flags_arafi,
            { "ASPA Address Family Flag", "rpki-rtr.flags.arafi",
            FT_BOOLEAN, 8, TFS(&tfs_flag_type_afi_ar), 0x01,
            NULL, HFILL }
        },
        { &hf_rpkirtr_prefix_length,
            { "Prefix Length", "rpki-rtr.prefix_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Denoting the shortest prefix allowed for the prefix", HFILL }
        },
        { &hf_rpkirtr_max_length,
            { "Max length", "rpki-rtr.max_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Denoting the longest prefix allowed by the prefix.  This MUST NOT be less than the Prefix Length element", HFILL }
        },
        { &hf_rpkirtr_ipv4_prefix,
            { "IPv4 Prefix", "rpki-rtr.ipv4_prefix",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            "The IPv4 prefix of the ROA", HFILL }
        },
        { &hf_rpkirtr_ipv6_prefix,
            { "IPv6 Prefix", "rpki-rtr.ipv6_prefix",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            "The IPv6 prefix of the ROA", HFILL }
        },
        { &hf_rpkirtr_as_number,
            { "AS Number", "rpki-rtr.as_number",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Autonomous System Number allowed to announce this prefix", HFILL }
        },
        { &hf_rpkirtr_error_code,
            { "Error Code", "rpki-rtr.error_code",
            FT_UINT16, BASE_DEC, VALS(rtr_error_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_rpkirtr_length_pdu,
            { "Length of Encapsulated PDU", "rpki-rtr.length_pdu",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rpkirtr_error_pdu,
            { "Erroneous PDU", "rpki-rtr.error_pdu",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rpkirtr_length_text,
            { "Length of text", "rpki-rtr.length_text",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rpkirtr_error_text,
            { "Erroneous Text", "rpki-rtr.error_text",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rpkirtr_refresh_interval,
            { "Refresh Interval", "rpki-rtr.refresh_interval",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rpkirtr_retry_interval,
            { "Retry Interval", "rpki-rtr.retry_interval",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rpkirtr_expire_interval,
            { "Expire Interval", "rpki-rtr.expire_interval",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rpkirtr_subject_key_identifier,
            { "Subject Key Identifier", "rpki-rtr.subject_key_identifier",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rpkirtr_subject_public_key_info,
            { "Subject Public Key Info", "rpki-rtr.subject_public_key_info",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rpkirtr_aspa_provider_as_count,
            { "ASPA Provider AS Count", "rpki-rtr.aspa_ascount",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "The Provider AS Count is the number of 32-bit Provider Autonomous System Numbers in the PDU", HFILL }
        },
        { &hf_rpkirtr_aspa_customer_asn,
            { "ASPA Customer ASN", "rpki-rtr.aspa_customer_asn",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "The Customer Autonomous System Number is the 32-bit Autonomous System Number of the customer which authenticated the ASPA RPKI data", HFILL }
        },
        { &hf_rpkirtr_aspa_provider_asn,
            { "ASPA Provider ASN", "rpki-rtr.aspa_provider_asn",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        }
    };

    static int *ett[] = {
        &ett_rpkirtr,
        &ett_flags,
        &ett_flags_nd,
        &ett_providers
    };

    static ei_register_info ei[] = {
        { &ei_rpkirtr_wrong_version_aspa, { "rpkirtr.aspa.wrong_version", PI_MALFORMED, PI_WARN, "Wrong version for ASPA type", EXPFILL }},
        { &ei_rpkirtr_wrong_version_router_key, { "rpkirtr.router_key.wrong_version", PI_MALFORMED, PI_WARN, "Wrong version for Router Key type", EXPFILL }},
        { &ei_rpkirtr_bad_length, { "rpkirtr.bad_length", PI_MALFORMED, PI_ERROR, "Invalid length field", EXPFILL }},
    };

    expert_module_t *expert_rpkirtr;

    proto_rpkirtr = proto_register_protocol("RPKI-Router Protocol",
        "RPKI-Router Protocol", "rpkirtr");

    proto_register_field_array(proto_rpkirtr, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    rpkirtr_module = prefs_register_protocol(proto_rpkirtr,
        proto_reg_handoff_rpkirtr);

    prefs_register_uint_preference(rpkirtr_module, "tcp.rpkirtr_tls.port", "RPKI-RTR TCP TLS Port",
         "RPKI-Router Protocol TCP TLS port if other than the default",
         10, &g_port_rpkirtr_tls);

    expert_rpkirtr = expert_register_protocol(proto_rpkirtr);
    expert_register_field_array(expert_rpkirtr, ei, array_length(ei));
    rpkirtr_handle = register_dissector("rpkirtr", dissect_rpkirtr, proto_rpkirtr);
}


void
proto_reg_handoff_rpkirtr(void)
{
    static bool initialized = false;
    static int rpki_rtr_tls_port;

    if (!initialized) {
        dissector_add_uint_with_preference("tcp.port", RPKI_RTR_TCP_PORT, rpkirtr_handle);
        initialized = true;
    } else {
        ssl_dissector_delete(rpki_rtr_tls_port, rpkirtr_handle);
    }

    rpki_rtr_tls_port = g_port_rpkirtr_tls;
    ssl_dissector_add(rpki_rtr_tls_port, rpkirtr_handle);
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

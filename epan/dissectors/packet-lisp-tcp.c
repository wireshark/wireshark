/* packet-lisp-tcp.c
 * Routines for Locator/ID Separation Protocol (LISP) TCP Control Message dissection
 * Copyright 2014, 2018 Lorand Jakab <ljakab@ac.upc.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "packet-tcp.h"
#include "packet-lisp.h"

#include <epan/to_str.h>
#include <epan/afn.h>
#include <epan/expert.h>

void proto_register_lisp_tcp(void);
void proto_reg_handoff_lisp_tcp(void);

/*
 * See draft-kouvelas-lisp-map-server-reliable-transport-04 "LISP Map
 * Server Reliable Transport", and draft-kouvelas-lisp-rloc-membership-01
 * "LISP RLOC Membership Distribution" for packet format and protocol
 * information.
 */

#define LISP_MSG_HEADER_LEN 4
#define LISP_MSG_END_MARKER 0x9FACADE9

/* LISP Map Server Reliable Transport message types */
#define TRANSPORT_BASE      16
/* LISP RLOC Membership Distribution message types */
#define MEMBERSHIP_BASE     22

/* Registration refresh message flags */
#define REFRESH_FLAG_R      0x8000

static bool lisp_tcp_desegment = true;

/* Initialize the protocol and registered fields */
static int proto_lisp_tcp;
static int hf_lisp_tcp_message_type;
static int hf_lisp_tcp_message_length;
static int hf_lisp_tcp_message_id;
static int hf_lisp_tcp_message_data;
static int hf_lisp_tcp_message_eid_afi;
static int hf_lisp_tcp_message_iid;
static int hf_lisp_tcp_message_sid;
static int hf_lisp_tcp_message_err;
static int hf_lisp_tcp_message_err_code;
static int hf_lisp_tcp_message_err_reserved;
static int hf_lisp_tcp_message_err_offending_msg_type;
static int hf_lisp_tcp_message_err_offending_msg_len;
static int hf_lisp_tcp_message_err_offending_msg_id;
static int hf_lisp_tcp_message_err_offending_msg_data;
static int hf_lisp_tcp_message_registration_reject_reason;
static int hf_lisp_tcp_message_registration_reject_res;
static int hf_lisp_tcp_message_registration_refresh_scope;
static int hf_lisp_tcp_message_registration_refresh_flags_rejected;
static int hf_lisp_tcp_message_registration_refresh_res;
static int hf_lisp_tcp_message_xtr_id;
static int hf_lisp_tcp_message_site_id;
static int hf_lisp_tcp_message_eid_prefix_length;
static int hf_lisp_tcp_message_eid_prefix_afi;
static int hf_lisp_tcp_message_eid_ipv4;
static int hf_lisp_tcp_message_eid_ipv6;
static int hf_lisp_tcp_message_eid_mac;
static int hf_lisp_tcp_message_eid_dn;
static int hf_lisp_tcp_message_rloc_afi;
static int hf_lisp_tcp_message_rloc_ipv4;
static int hf_lisp_tcp_message_rloc_ipv6;
static int hf_lisp_tcp_message_rid;
static int hf_lisp_tcp_message_end_marker;

/* Initialize the subtree pointers */
static int ett_lisp_tcp;
static int ett_lisp_tcp_lcaf;
static int ett_lisp_tcp_eid_prefix;
static int ett_lisp_tcp_map_register;

/* Initialize expert fields */
static expert_field ei_lisp_tcp_undecoded;
static expert_field ei_lisp_tcp_invalid_length;
static expert_field ei_lisp_tcp_invalid_marker;
static expert_field ei_lisp_tcp_unexpected_afi;

static dissector_handle_t lisp_tcp_handle;

static const value_string lisp_tcp_typevals[] = {
    { TRANSPORT_BASE,         "Error Notification" },
    { TRANSPORT_BASE + 1,     "Registration" },
    { TRANSPORT_BASE + 2,     "Registration ACK" },
    { TRANSPORT_BASE + 3,     "Registration NACK" },
    { TRANSPORT_BASE + 4,     "Registration Refresh" },
    { TRANSPORT_BASE + 5,     "Mapping Notification" },
    { MEMBERSHIP_BASE,        "RLOC Membership Subscribe" },
    { MEMBERSHIP_BASE + 1,    "RLOC Membership Subscribe ACK" },
    { MEMBERSHIP_BASE + 2,    "RLOC Membership Subscribe NACK" },
    { MEMBERSHIP_BASE + 3,    "RLOC Membership Unsubscribe" },
    { MEMBERSHIP_BASE + 4,    "RLOC Membership Element Add" },
    { MEMBERSHIP_BASE + 5,    "RLOC Membership Element Remove" },
    { MEMBERSHIP_BASE + 6,    "RLOC Membership Refresh Request" },
    { MEMBERSHIP_BASE + 7,    "RLOC Membership Refresh Begin" },
    { MEMBERSHIP_BASE + 8,    "RLOC Membership Refresh End" },
    { 0,        NULL}
};

static const value_string lisp_tcp_membership_subscribe_errors[] = {
    { 0,        "Undefined" },
    { 1,        "Instance not found" },
    { 2,        "Distribution not enabled" },
    { 3,        "Not Authorized" },
    { 0,        NULL}
};

static const value_string lisp_tcp_registration_reject_reason[] = {
    { 1,        "Not a valid site EID prefix" },
    { 2,        "Authentication failure" },
    { 3,        "Locator set not allowed" },
    { 4,        "Reason not defined" },
    { 0,        NULL}
};

static const value_string lisp_tcp_registration_refresh_scope[] = {
    { 0,        "All prefixes under all address families under all EID instances" },
    { 1,        "All prefixes under all address families under a single EID instance" },
    { 2,        "All prefixes under a single address family under a single EID instance" },
    { 3,        "All prefixes covered by a specific EID prefix in a single EID instance" },
    { 4,        "A specific EID prefix in a single EID instance" },
    { 0,        NULL}
};

/*
 * Dissector for EID prefixes
 */

static unsigned
dissect_lisp_tcp_message_eid_prefix(tvbuff_t *tvb, packet_info *pinfo, proto_tree *message_tree,
        unsigned offset, proto_item *tim)
{
    proto_tree *prefix_tree, *lcaf_tree;
    int str_len;
    uint8_t prefix_length;
    uint16_t prefix_afi, addr_len = 0;
    const char *prefix;

    prefix_length = tvb_get_uint8(tvb, offset);
    prefix_afi = tvb_get_ntohs(tvb, offset + 1);

    prefix = get_addr_str(tvb, pinfo, offset + 3, prefix_afi, &addr_len);

    if (prefix == NULL) {
        expert_add_info_format(pinfo, message_tree, &ei_lisp_tcp_unexpected_afi,
                               "Unexpected EID prefix AFI (%d), cannot decode", prefix_afi);
        return offset + addr_len;
    }

    proto_item_append_text(tim, " for %s/%d", prefix, prefix_length);
    prefix_tree = proto_tree_add_subtree_format(message_tree, tvb, offset, 3 + addr_len, ett_lisp_tcp_eid_prefix,
            NULL, "EID Prefix: %s/%d", prefix, prefix_length);

    /* Prefix-Length (1 byte) */
    proto_tree_add_item(prefix_tree, hf_lisp_tcp_message_eid_prefix_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* EID-Prefix-AFI (2 bytes) */
    proto_tree_add_item(prefix_tree, hf_lisp_tcp_message_eid_prefix_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* EID-Prefix */
    switch(prefix_afi) {
        case AFNUM_INET:
            proto_tree_add_item(prefix_tree, hf_lisp_tcp_message_eid_ipv4, tvb, offset, INET_ADDRLEN, ENC_BIG_ENDIAN);
            offset += INET_ADDRLEN;
            break;
        case AFNUM_INET6:
            proto_tree_add_item(prefix_tree, hf_lisp_tcp_message_eid_ipv6, tvb, offset, INET6_ADDRLEN, ENC_NA);
            offset += INET6_ADDRLEN;
            break;
        case AFNUM_LCAF:
            lcaf_tree = proto_tree_add_subtree_format(prefix_tree, tvb, offset, addr_len, ett_lisp_tcp_lcaf, NULL, "Address: %s", prefix);
            dissect_lcaf(tvb, pinfo, lcaf_tree, offset, NULL);
            offset += addr_len;
            break;
        case AFNUM_802:
        case AFNUM_EUI48:
            proto_tree_add_item(prefix_tree, hf_lisp_tcp_message_eid_mac, tvb, offset, EUI48_ADDRLEN, ENC_NA);
            offset += EUI48_ADDRLEN;
            break;
        case AFNUM_DISTNAME:
            str_len = tvb_strsize(tvb, offset);
            proto_tree_add_item(prefix_tree, hf_lisp_tcp_message_eid_dn, tvb, offset, str_len, ENC_ASCII);
            offset += str_len;
            break;
    }
    return offset;
}


/*
 * Dissector for Reliable Transport messages
 */

static unsigned
dissect_lisp_tcp_reliable_transport_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *message_tree,
        unsigned offset, uint16_t type, uint16_t data_len, proto_item *tim)
{
    unsigned initial_offset = offset;
    proto_tree *map_register_tree;
    uint8_t reject_reason, scope, err;
    uint16_t refresh_flags, offending_msg_type;

    switch (type) {

    /* Error Notification */
    case TRANSPORT_BASE:
        /* Error code (1 byte) */
        err = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(message_tree, hf_lisp_tcp_message_err_code, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        data_len -= 1;
        proto_item_append_text(tim, ", Code: %d", err);

        /* Reserved (3 bytes) */
        proto_tree_add_item(message_tree, hf_lisp_tcp_message_err_reserved, tvb, offset, 3, ENC_BIG_ENDIAN);
        offset += 3;
        data_len -= 3;

        /* Offending message type (2 bytes) */
        offending_msg_type = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(message_tree, hf_lisp_tcp_message_err_offending_msg_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        data_len -= 2;
        proto_item_append_text(tim, ", Offending message type: %s",
                val_to_str(offending_msg_type, lisp_tcp_typevals, "Unknown type (%u)"));

        /* Offending message length (2 bytes) */
        proto_tree_add_item(message_tree, hf_lisp_tcp_message_err_offending_msg_len, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        data_len -= 2;

        /* Offending message ID (4 bytes) */
        proto_tree_add_item(message_tree, hf_lisp_tcp_message_err_offending_msg_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        data_len -= 4;

        /* Offending message data */
        if (data_len) {
            proto_tree_add_item(message_tree, hf_lisp_tcp_message_err_offending_msg_data, tvb, offset, data_len, ENC_NA);
            offset += data_len;
        }
        return offset;

    /* Registration */
    case TRANSPORT_BASE + 1:
        /* Map-Register */
        map_register_tree = proto_tree_add_subtree(message_tree, tvb, offset, data_len,
                ett_lisp_tcp_map_register, NULL, "Map-Register");
        offset = dissect_lisp_map_register(tvb, pinfo, map_register_tree, offset, tim, false);
        data_len -= offset - initial_offset;
        break;

    /* Registration ACK */
    case TRANSPORT_BASE + 2:
        /* EID */
        offset = dissect_lisp_tcp_message_eid_prefix(tvb, pinfo, message_tree, offset, tim);
        data_len -= offset - initial_offset;
        break;

    /* Registration Reject */
    case TRANSPORT_BASE + 3:
        /* Reason (1 byte) */
        reject_reason = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(message_tree, hf_lisp_tcp_message_registration_reject_reason, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_item_append_text(tim, ", Reason: %s",
                val_to_str(reject_reason, lisp_tcp_registration_reject_reason, "Unknown reason code (%u)"));

        /* Reserved (2 bytes) */
        proto_tree_add_item(message_tree, hf_lisp_tcp_message_registration_reject_res, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* EID */
        offset = dissect_lisp_tcp_message_eid_prefix(tvb, pinfo, message_tree, offset, tim);
        data_len -= offset - initial_offset;
        break;

    /* Registration Refresh */
    case TRANSPORT_BASE + 4:
        /* Reason (1 byte) */
        scope = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(message_tree, hf_lisp_tcp_message_registration_refresh_scope, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_item_append_text(tim, ", Scope: %s",
                val_to_str(scope, lisp_tcp_registration_refresh_scope, "Unknown scope code (%u)"));
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Scope: %d", scope);

        /* Rejected only flag (1 bit) */
        refresh_flags = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(message_tree, hf_lisp_tcp_message_registration_refresh_flags_rejected, tvb, offset, 2, ENC_BIG_ENDIAN);
        if (refresh_flags & REFRESH_FLAG_R) {
            proto_item_append_text(tim, " (rejected only)");
            col_append_fstr(pinfo->cinfo, COL_INFO, " (rejected only)");
        }

        /* Reserved (15 bits) */
        proto_tree_add_item(message_tree, hf_lisp_tcp_message_registration_refresh_res, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        if (scope == 0) {
            data_len -= 3;
            break;
        }

        /* EID */
        offset = dissect_lisp_tcp_message_eid_prefix(tvb, pinfo, message_tree, offset, tim);
        data_len -= offset - initial_offset;
        break;

    /* Mapping Notification */
    case TRANSPORT_BASE + 5:
        /* xTR-ID (16 bytes) */
        proto_tree_add_item(message_tree, hf_lisp_tcp_message_xtr_id, tvb, offset, LISP_XTRID_LEN, ENC_NA);
        offset += LISP_XTRID_LEN;

        /* Site-ID (8 bytes) */
        proto_tree_add_item(message_tree, hf_lisp_tcp_message_site_id, tvb, offset, LISP_SITEID_LEN, ENC_NA);
        offset += LISP_SITEID_LEN;

        /* Mapping Record */
        offset = dissect_lisp_mapping(tvb, pinfo, message_tree, 0, 1, false, offset, tim);
        data_len -= offset - initial_offset;
        break;
    }

    if (data_len) {
        proto_tree_add_item(message_tree, hf_lisp_tcp_message_data, tvb, offset, data_len, ENC_NA);
        offset += data_len;
        expert_add_info_format(pinfo, message_tree, &ei_lisp_tcp_undecoded, "Work-in-progress");
    }

    return offset;
}


/*
 * Dissector for Membership messages
 */

static unsigned
dissect_lisp_tcp_membership_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *message_tree,
        unsigned offset, uint16_t type, uint16_t data_len, proto_item *tim)
{
    uint32_t iid, sid, rid;
    uint8_t err;
    uint64_t siteid;
    uint16_t afi;

    /* EID AFI (2 bytes) */
    proto_tree_add_item(message_tree, hf_lisp_tcp_message_eid_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    data_len -= 2;

    /* Instance ID (4 bytes) */
    iid = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(message_tree, hf_lisp_tcp_message_iid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    data_len -= 4;
    proto_item_append_text(tim, ", IID: %u", iid);

    switch (type) {
    case MEMBERSHIP_BASE + 1:
    case MEMBERSHIP_BASE + 2:
        /* Subscribe ID (4 bytes) */
        sid = tvb_get_ntohl(tvb, offset);
        proto_tree_add_item(message_tree, hf_lisp_tcp_message_sid, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        data_len -= 4;
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Sub ID: %u", sid);
        proto_item_append_text(tim, ", Sub ID: %u", sid);

        if (type == MEMBERSHIP_BASE + 2) {
            /* Error code (1 byte) */
            err = tvb_get_uint8(tvb, offset);
            proto_tree_add_item(message_tree, hf_lisp_tcp_message_err, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            data_len -= 1;
            proto_item_append_text(tim, ", Error code: %s",
                    val_to_str(err, lisp_tcp_membership_subscribe_errors, "Unknown error code (%u)"));
        }

        break;

    case MEMBERSHIP_BASE + 4:
    case MEMBERSHIP_BASE + 5:
        /* Site ID (8 bytes) */
        siteid = tvb_get_ntoh64(tvb, offset);
        proto_tree_add_item(message_tree, hf_lisp_tcp_message_site_id, tvb, offset, LISP_SITEID_LEN, ENC_NA);
        offset += 8;
        data_len -= 8;
        proto_item_append_text(tim, ", Site-ID: %"PRIu64, siteid);

        /* RLOC AFI (2 bytes) */
        afi = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(message_tree, hf_lisp_tcp_message_rloc_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        data_len -= 2;

        switch (afi) {
        case AFNUM_INET:
            proto_tree_add_item(message_tree, hf_lisp_tcp_message_rloc_ipv4, tvb, offset, INET_ADDRLEN, ENC_NA);
            proto_item_append_text(tim, ", RLOC: %s", tvb_ip_to_str(pinfo->pool, tvb, offset));
            col_append_fstr(pinfo->cinfo, COL_INFO, " [%u] %s", iid, tvb_ip_to_str(pinfo->pool, tvb, offset));
            offset += INET_ADDRLEN;
            data_len -= INET_ADDRLEN;
            break;
        case AFNUM_INET6:
            proto_tree_add_item(message_tree, hf_lisp_tcp_message_rloc_ipv6, tvb, offset, INET6_ADDRLEN, ENC_NA);
            proto_item_append_text(tim, ", RLOC: %s", tvb_ip6_to_str(pinfo->pool, tvb, offset));
            col_append_fstr(pinfo->cinfo, COL_INFO, " [%u] %s", iid, tvb_ip6_to_str(pinfo->pool, tvb, offset));
            offset += INET6_ADDRLEN;
            data_len -= INET6_ADDRLEN;
            break;
        }

        break;

    case MEMBERSHIP_BASE + 7:
    case MEMBERSHIP_BASE + 8:
        /* Request ID (4 bytes) */
        rid = tvb_get_ntohl(tvb, offset);
        proto_tree_add_item(message_tree, hf_lisp_tcp_message_rid, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        data_len -= 4;
        proto_item_append_text(tim, ", Req ID: %u", rid);
        break;
    }

    if (data_len) {
        proto_tree_add_item(message_tree, hf_lisp_tcp_message_data, tvb, offset, data_len, ENC_NA);
        offset += data_len;
        expert_add_info_format(pinfo, message_tree, &ei_lisp_tcp_undecoded, "Work-in-progress");
    }

    return offset;
}


/*
 * Dissector for individual messages
 */

static int
dissect_lisp_tcp_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    unsigned offset = 0;
    uint16_t type, len, data_len;
    uint32_t id, marker;
    proto_item *tim, *til, *tiem;
    proto_tree *message_tree;

    tim = proto_tree_add_item(tree, proto_lisp_tcp, tvb, offset, -1, ENC_NA);
    message_tree = proto_item_add_subtree(tim, ett_lisp_tcp);

    /* Message type (2 bytes) */
    type = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(message_tree, hf_lisp_tcp_message_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Message length (2 bytes) */
    len = tvb_get_ntohs(tvb, offset);
    til = proto_tree_add_item(message_tree, hf_lisp_tcp_message_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (len < 8) {
        expert_add_info_format(pinfo, til, &ei_lisp_tcp_invalid_length,
                "Invalid message length (%u < 8)", len);
    } else if (len > 8) {
        /* Message ID (4 bytes) */
        id = tvb_get_ntohl(tvb, offset);
        proto_tree_add_item(message_tree, hf_lisp_tcp_message_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, "; ", "Msg: %u, %s", id, val_to_str(type, lisp_tcp_typevals,
                    "Unknown type (%u)"));
        proto_item_append_text(tim, ", Msg: %u, %s", id, val_to_str(type, lisp_tcp_typevals,
                    "Unknown type (%u)"));
        proto_item_set_len(tim, len);

        data_len = len - 12;
        if (type >= TRANSPORT_BASE && type <= TRANSPORT_BASE + 5) {
            /* Map Server reliable transport message types */
            offset = dissect_lisp_tcp_reliable_transport_message(tvb, pinfo, message_tree, offset, type, data_len, tim);
        } else if (type >= MEMBERSHIP_BASE && type <= MEMBERSHIP_BASE + 8) {
            /* EID instance membership message types */
            offset = dissect_lisp_tcp_membership_message(tvb, pinfo, message_tree, offset, type, data_len, tim);
        } else {
            /* Message Data (variable length) */
            proto_tree_add_item(message_tree, hf_lisp_tcp_message_data, tvb, offset, data_len, ENC_NA);
            offset += data_len;
        }
    }

    /* Message End Marker (4 bytes) */
    marker = tvb_get_ntohl(tvb, offset);
    tiem = proto_tree_add_item(message_tree, hf_lisp_tcp_message_end_marker, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (marker != LISP_MSG_END_MARKER) {
        expert_add_info_format(pinfo, tiem, &ei_lisp_tcp_invalid_marker,
                "Invalid message end marker (0x%08x)", marker);
    } else {
        proto_item_append_text(tiem, " (correct)");
    }

    return offset;
}


/*
 * Get message length, needed by tcp_dissect_pdus()
 */

static unsigned
get_lisp_tcp_message_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                         int offset, void *data _U_)
{
    uint16_t mlen;

    /* Get length of membership message */
    mlen = tvb_get_ntohs(tvb, offset + 2);

    return mlen;
}


/*
 * Main dissector code
 */

static int
dissect_lisp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Clear Info column before fetching data in case an exception is thrown */
    col_clear(pinfo->cinfo, COL_INFO);

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LISP");

    /* Reassemble and dissect PDUs */
    tcp_dissect_pdus(tvb, pinfo, tree, lisp_tcp_desegment, LISP_MSG_HEADER_LEN,
                     get_lisp_tcp_message_len, dissect_lisp_tcp_message, data);

    /* Return the amount of data this dissector was able to dissect */
    return tvb_reported_length(tvb);
}


/*
 *  Register the LISP protocol with Wireshark
 */

void
proto_register_lisp_tcp(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {
        { &hf_lisp_tcp_message_type,
            { "Type", "lisp-tcp.message.type",
            FT_UINT16, BASE_DEC, VALS(lisp_tcp_typevals), 0x0, "TLV Message Type", HFILL }},
        { &hf_lisp_tcp_message_length,
            { "Length", "lisp-tcp.message.length",
            FT_UINT16, BASE_DEC, NULL, 0x0, "TLV Message Length", HFILL }},
        { &hf_lisp_tcp_message_id,
            { "Message ID", "lisp-tcp.message.id",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_tcp_message_data,
            { "Message Data", "lisp-tcp.message.data",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_tcp_message_eid_afi,
            { "EID AFI", "lisp-tcp.message.eid.afi",
            FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, NULL, HFILL }},
        { &hf_lisp_tcp_message_iid,
            { "Instance ID", "lisp-tcp.message.iid",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_tcp_message_sid,
            { "Subscribe Message ID", "lisp-tcp.message.sid",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_tcp_message_err,
            { "Error code", "lisp-tcp.message.err",
            FT_UINT8, BASE_DEC, VALS(lisp_tcp_membership_subscribe_errors), 0x0, NULL, HFILL }},
        { &hf_lisp_tcp_message_err_code,
            { "Error code", "lisp-tcp.message.err.code",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_tcp_message_err_reserved,
            { "Error code", "lisp-tcp.message.err.reserved",
            FT_UINT24, BASE_HEX, NULL, 0x0, "Must be zero", HFILL }},
        { &hf_lisp_tcp_message_err_offending_msg_type,
            { "Offending message type", "lisp-tcp.message.err.offending_msg.type",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_tcp_message_err_offending_msg_len,
            { "Offending message length", "lisp-tcp.message.err.offending_msg.len",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_tcp_message_err_offending_msg_id,
            { "Offending message ID", "lisp-tcp.message.err.offending_msg.id",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_tcp_message_err_offending_msg_data,
            { "Offending message data", "lisp-tcp.message.err.offending_msg.data",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_tcp_message_registration_reject_reason,
            { "Registration reject reason", "lisp-tcp.message.registration_reject.reason",
            FT_UINT8, BASE_DEC, VALS(lisp_tcp_registration_reject_reason), 0x0, NULL, HFILL }},
        { &hf_lisp_tcp_message_registration_reject_res,
            { "Reserved bits", "lisp-tcp.message.registration_reject.res",
            FT_UINT16, BASE_HEX, NULL, 0x0, "Must be zero", HFILL }},
        { &hf_lisp_tcp_message_registration_refresh_scope,
            { "Registration refresh scope", "lisp-tcp.message.registration_refresh.scope",
            FT_UINT8, BASE_DEC, VALS(lisp_tcp_registration_refresh_scope), 0x0, NULL, HFILL }},
        { &hf_lisp_tcp_message_registration_refresh_flags_rejected,
            { "Rejected only", "lisp-tcp.message.registration_refresh.flags.rejected",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), REFRESH_FLAG_R, NULL, HFILL }},
        { &hf_lisp_tcp_message_registration_refresh_res,
            { "Reserved", "lisp-tcp.message.registration_refresh.res",
            FT_UINT16, BASE_HEX, NULL, 0x7FFF, "Must be zero", HFILL }},
        { &hf_lisp_tcp_message_xtr_id,
            { "xTR-ID", "lisp-tcp.message.xtrid",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_tcp_message_site_id,
            { "Site-ID", "lisp-tcp.message.siteid",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_tcp_message_eid_prefix_length,
            { "Prefix Length", "lisp-tcp.message.eid.prefix.length",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_tcp_message_eid_prefix_afi,
            { "Prefix AFI", "lisp-tcp.message.eid.prefix.afi",
            FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, NULL, HFILL }},
        { &hf_lisp_tcp_message_eid_ipv4,
            { "Address", "lisp-tcp.message.eid.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_tcp_message_eid_ipv6,
            { "Address", "lisp-tcp.message.eid.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_tcp_message_eid_mac,
            { "Address", "lisp-tcp.message.eid.mac",
            FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_tcp_message_eid_dn,
            { "Address", "lisp-tcp.message.eid.dn",
            FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_tcp_message_rloc_afi,
            { "RLOC AFI", "lisp-tcp.message.rloc.afi",
            FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, NULL, HFILL }},
        { &hf_lisp_tcp_message_rloc_ipv4,
            { "RLOC", "lisp-tcp.message.rloc.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_tcp_message_rloc_ipv6,
            { "RLOC", "lisp-tcp.message.rloc.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_tcp_message_rid,
            { "Request Message ID", "lisp-tcp.message.rid",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lisp_tcp_message_end_marker,
            { "Message End Marker", "lisp-tcp.message.end_marker",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_lisp_tcp,
        &ett_lisp_tcp_lcaf,
        &ett_lisp_tcp_eid_prefix,
        &ett_lisp_tcp_map_register
    };

    static ei_register_info ei[] = {
        { &ei_lisp_tcp_undecoded, { "lisp-tcp.undecoded", PI_UNDECODED, PI_WARN, "Not dissected yet (report to wireshark.org)", EXPFILL }},
        { &ei_lisp_tcp_invalid_length, { "lisp-tcp.invalid_length", PI_PROTOCOL, PI_ERROR, "Invalid message length", EXPFILL }},
        { &ei_lisp_tcp_invalid_marker, { "lisp-tcp.invalid_marker", PI_PROTOCOL, PI_ERROR, "Invalid message end marker", EXPFILL }},
        { &ei_lisp_tcp_unexpected_afi, { "lisp-tcp.unexpected_afi", PI_PROTOCOL, PI_ERROR, "Unexpected AFI", EXPFILL }},
    };

    expert_module_t* expert_lisp_tcp;

    /* Register the protocol name and description */
    proto_lisp_tcp = proto_register_protocol("Locator/ID Separation Protocol (Reliable Transport)",
        "LISP Reliable Transport", "lisp-tcp");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_lisp_tcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_lisp_tcp = expert_register_protocol(proto_lisp_tcp);
    expert_register_field_array(expert_lisp_tcp, ei, array_length(ei));

    /* Register dissector so that other dissectors can call it */
    lisp_tcp_handle = register_dissector("lisp-tcp", dissect_lisp_tcp, proto_lisp_tcp);
}


/*
 * Simple form of proto_reg_handoff_lisp_tcp which can be used if there are
 * no prefs-dependent registration function calls.
 */

void
proto_reg_handoff_lisp_tcp(void)
{
    dissector_add_uint_with_preference("tcp.port", LISP_CONTROL_PORT, lisp_tcp_handle);
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

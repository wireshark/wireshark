/* packet-lisp-tcp.c
 * Routines for Locator/ID Separation Protocol (LISP) TCP Control Message dissection
 * Copyright 2014 Lorand Jakab <ljakab@ac.upc.edu>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/afn.h>
#include <epan/expert.h>
#include "packet-tcp.h"

void proto_register_lisp_tcp(void);
void proto_reg_handoff_lisp_tcp(void);

#define INET_ADDRLEN        4
#define INET6_ADDRLEN       16
#define EUI48_ADDRLEN       6

/*
 * See draft-kouvelas-lisp-rloc-membership-00 "LISP RLOC Membership
 * Distribution" for packet format and protocol information.
 */

#define LISP_CONTROL_PORT   4342
#define LISP_MSG_HEADER_LEN 4
#define LISP_MSG_END_MARKER 0x9FACADE9

/* LISP Reliable Transport message types */
#define MEMBERSHIP_BASE     22

static gboolean lisp_tcp_desegment = TRUE;

/* Initialize the protocol and registered fields */
static int proto_lisp_tcp = -1;
static int hf_lisp_tcp_message_type = -1;
static int hf_lisp_tcp_message_length = -1;
static int hf_lisp_tcp_message_id = -1;
static int hf_lisp_tcp_message_data = -1;
static int hf_lisp_tcp_message_eid_afi = -1;
static int hf_lisp_tcp_message_iid = -1;
static int hf_lisp_tcp_message_sid = -1;
static int hf_lisp_tcp_message_err = -1;
static int hf_lisp_tcp_message_site_id = -1;
static int hf_lisp_tcp_message_rloc_afi = -1;
static int hf_lisp_tcp_message_rloc_ipv4 = -1;
static int hf_lisp_tcp_message_rloc_ipv6 = -1;
static int hf_lisp_tcp_message_rid = -1;
static int hf_lisp_tcp_message_end_marker = -1;

/* Initialize the subtree pointers */
static gint ett_lisp_tcp = -1;

/* Initialize expert fields */
static expert_field ei_lisp_tcp_undecoded = EI_INIT;
static expert_field ei_lisp_tcp_invalid_length = EI_INIT;
static expert_field ei_lisp_tcp_invalid_marker = EI_INIT;

static dissector_handle_t lisp_tcp_handle;

const value_string lisp_tcp_typevals[] = {
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

const value_string lisp_tcp_membership_subscribe_errors[] = {
    { 0,        "Undefined" },
    { 1,        "Instance not found" },
    { 2,        "Distribution not enabled" },
    { 3,        "Not Authorized" },
    { 0,        NULL}
};


/*
 * Dissector for Membership messages
 */

static int
dissect_lisp_tcp_membership_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *message_tree,
        guint offset, guint16 type, guint16 data_len, proto_item *tim)
{
    guint32 iid, sid, rid;
    guint8 err;
    guint64 siteid;
    guint16 afi;

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
            err = tvb_get_guint8(tvb, offset);
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
        proto_tree_add_item(message_tree, hf_lisp_tcp_message_site_id, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        data_len -= 8;
        proto_item_append_text(tim, ", Site-ID: %"G_GINT64_MODIFIER"u", siteid);

        /* RLOC AFI (2 bytes) */
        afi = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(message_tree, hf_lisp_tcp_message_rloc_afi, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        data_len -= 2;

        switch (afi) {
        case AFNUM_INET:
            proto_tree_add_item(message_tree, hf_lisp_tcp_message_rloc_ipv4, tvb, offset, INET_ADDRLEN, ENC_NA);
            proto_item_append_text(tim, ", RLOC: %s", tvb_ip_to_str(tvb, offset));
            col_append_fstr(pinfo->cinfo, COL_INFO, " [%u] %s", iid, tvb_ip_to_str(tvb, offset));
            offset += INET_ADDRLEN;
            data_len -= INET_ADDRLEN;
            break;
        case AFNUM_INET6:
            proto_tree_add_item(message_tree, hf_lisp_tcp_message_rloc_ipv6, tvb, offset, INET6_ADDRLEN, ENC_NA);
            proto_item_append_text(tim, ", RLOC: %s", tvb_ip6_to_str(tvb, offset));
            col_append_fstr(pinfo->cinfo, COL_INFO, " [%u] %s", iid, tvb_ip6_to_str(tvb, offset));
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
    guint offset = 0;
    guint16 type, len, data_len;
    guint32 id, marker;
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
        if (type >= MEMBERSHIP_BASE && type <= MEMBERSHIP_BASE + 8) {
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

static guint
get_lisp_tcp_message_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                         int offset, void *data _U_)
{
    guint16 mlen;

    /* Get length of memebership message */
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
        { &hf_lisp_tcp_message_site_id,
            { "Site-ID", "lisp-tcp.message.site_id",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
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
    static gint *ett[] = {
        &ett_lisp_tcp
    };

    static ei_register_info ei[] = {
        { &ei_lisp_tcp_undecoded, { "lisp-tcp.undecoded", PI_UNDECODED, PI_WARN, "Not dissected yet (report to wireshark.org)", EXPFILL }},
        { &ei_lisp_tcp_invalid_length, { "lisp-tcp.invalid_marker", PI_PROTOCOL, PI_ERROR, "Invalid message length", EXPFILL }},
        { &ei_lisp_tcp_invalid_marker, { "lisp-tcp.invalid_marker", PI_PROTOCOL, PI_ERROR, "Invalid message end marker", EXPFILL }},
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
    dissector_add_uint("tcp.port", LISP_CONTROL_PORT, lisp_tcp_handle);
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

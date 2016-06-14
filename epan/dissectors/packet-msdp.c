/* packet-msdp.c
 * Routines for Multicast Source Discovery Protocol (MSDP) dissection.
 * draft-ietf-msdp-spec-10.txt
 *
 * Copyright 2001, Heikki Vatiainen <hessu@cs.tut.fi>
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
#include <epan/to_str.h>

void proto_register_msdp(void);
void proto_reg_handoff_msdp(void);

/* MSDP message types. The messages are TLV (Type-Length-Value) encoded */
enum { MSDP_SA     = 1,
       MSDP_SA_REQ,
       MSDP_SA_RSP,
       MSDP_KEEP_ALIVE,
       MSDP_NOTIFICATION,

       /* These are only assigned in MSDP spec. Their use is specified
        * elsewhere */
       MSDP_TRACE_IN_PROGRESS,
       MSDP_TRACE_REPLY
};

static const value_string msdp_types[] = {
        { MSDP_SA,                "IPv4 Source-Active"           },
        { MSDP_SA_REQ,            "IPv4 Source-Active Request"   },
        { MSDP_SA_RSP,            "IPv4 Source-Active Response"  },
        { MSDP_KEEP_ALIVE,        "KeepAlive"                    },
        { MSDP_NOTIFICATION,      "Notification"                 },

        { MSDP_TRACE_IN_PROGRESS, "MSDP traceroute in progress"  },
        { MSDP_TRACE_REPLY,       "MSDP traceroute reply"        },
        { 0, NULL },
};


/* Error codes */
enum { MESSAGE_HEADER_ERROR = 1,
       SA_REQUEST_ERROR,
       SA_MESSAGE_SA_RESPONSE_ERROR,
       HOLD_TIMER_EXPIRED,
       FSM_ERROR,
       NOTIFICATION,
       CEASE
};

static const value_string error_vals[] = {
        { MESSAGE_HEADER_ERROR,         "Message Header Error"         },
        { SA_REQUEST_ERROR,             "SA-Request Error"             },
        { SA_MESSAGE_SA_RESPONSE_ERROR, "SA-Message/SA-Response Error" },
        { HOLD_TIMER_EXPIRED,           "Hold Timer Expired"           },
        { FSM_ERROR,                    "Finite State Machine Error"   },
        { NOTIFICATION,                 "Notification"                 },
        { CEASE,                        "Cease"                        },
        { 0, NULL },
};


/* Message Header Error subcodes */
static const value_string hdr_error_vals[] = {
        { 0, "Unspecific"         },
        { 2, "Bad Message Length" },
        { 3, "Bad Message Type"   },
        { 0, NULL },
};

/* SA-Request Error subcodes (the O-bit is always clear) */
static const value_string sa_req_error_vals[] = {
        { 0, "Unspecific"    },
        { 1, "Invalid Group" },
        { 0, NULL },
};

/* SA-Message/SA-Response Error subcodes */
static const value_string sa_msg_error_vals[] = {
        { 0, "Unspecific"                             },
        { 1, "Invalid Entry Count"                    },
        { 2, "Invalid RP Address"                     },
        { 3, "Invalid Group Address"                  },
        { 4, "Invalid Source Address"                 },
        { 5, "Invalid Sprefix Length"                 },
        { 6, "Looping SA (Self is RP)"                },
        { 7, "Unknown Encapsulation"                  },
        { 8, "Administrative Scope Boundary Violated" },
        { 0, NULL },
};

/* Finite State Machine Error subcodes (the O-bit is always clear) */
static const value_string fsm_error_vals[] = {
        { 0, "Unspecific"                        },
        { 1, "Unexpected Message Type FSM Error" },
        { 0, NULL },
};

/*
 * Hold Timer Expired subcodes (the O-bit is always clear):
 * Notification subcodes (the O-bit is always clear):
 * Cease subcodes (the O-bit is always clear):
 *
 * These have only "Unspecific" specified.
 */
static const value_string sa_unspec_error_vals[] = {
        { 0, "Unspecific" },
        { 0, NULL },
};


/* Initialize the protocol and registered fields */
static int proto_msdp = -1;
static int hf_msdp_type = -1;
static int hf_msdp_length = -1;

static int hf_msdp_sa_entry_count = -1;
static int hf_msdp_sa_rp_addr = -1;
static int hf_msdp_sa_reserved = -1;
static int hf_msdp_sa_sprefix_len = -1;
static int hf_msdp_sa_group_addr = -1;
static int hf_msdp_sa_src_addr = -1;

static int hf_msdp_sa_req_res = -1;
static int hf_msdp_sa_req_group = -1;

static int hf_msdp_not_o = -1;
static int hf_msdp_not_error = -1;
static int hf_msdp_not_error_sub = -1;

static int hf_msdp_not_group_address = -1;
static int hf_msdp_not_rp_address = -1;
static int hf_msdp_not_source_address = -1;
static int hf_msdp_not_res = -1;
static int hf_msdp_not_entry_count = -1;
static int hf_msdp_not_sprefix_len = -1;

static int hf_msdp_tlv_contents = -1;
static int hf_msdp_trailing_junk = -1;
static int hf_msdp_unknown_encap = -1;
static int hf_msdp_unknown_data = -1;

static gint ett_msdp = -1;
static gint ett_msdp_sa_entry = -1;
static gint ett_msdp_sa_enc_data = -1;
static gint ett_msdp_not_data = -1;


static dissector_handle_t ip_handle;


static void
dissect_msdp_sa(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int *offset, int len);
static void
dissect_msdp_notification(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, guint16 tlv_len);


static int
dissect_msdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
        proto_item *ti;
        proto_tree *msdp_tree;
        int         offset;
        guint8      type;
        guint16     length;


        col_set_str(pinfo->cinfo, COL_PROTOCOL, "MSDP");

        col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_guint8(tvb, 0),
                                                                     msdp_types,
                                                                     "<Unknown MSDP message type>"));

        ti = proto_tree_add_item(tree, proto_msdp, tvb, 0, -1, ENC_NA);
        msdp_tree = proto_item_add_subtree(ti, ett_msdp);

        offset = 0;
        while (tvb_reported_length_remaining(tvb, offset) >= 3) {
                type = tvb_get_guint8(tvb, offset);
                length = tvb_get_ntohs(tvb, offset + 1);
                if (length < 3)
                        break;
                proto_tree_add_uint(msdp_tree, hf_msdp_type, tvb, offset, 1, type);
                proto_tree_add_uint(msdp_tree, hf_msdp_length, tvb, offset + 1, 2, length);
                offset += 3;
                length -= 3;

                switch (type) {
                case MSDP_SA:
                case MSDP_SA_RSP:
                        dissect_msdp_sa(tvb, pinfo, msdp_tree, &offset,
                                        length);
                        break;
                case MSDP_SA_REQ:
                        proto_tree_add_item(msdp_tree, hf_msdp_sa_req_res, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(msdp_tree, hf_msdp_sa_req_group, tvb, offset + 1, 4, ENC_BIG_ENDIAN);
                        offset += 5;
                        break;
                case MSDP_NOTIFICATION:
                        dissect_msdp_notification(tvb, pinfo, msdp_tree, &offset, length);
                        break;
                default:
                        if (length > 0)
                                proto_tree_add_item(msdp_tree, hf_msdp_tlv_contents, tvb, offset, length, ENC_NA);
                        offset += length;
                        break;
                }
        }

        if (tvb_reported_length_remaining(tvb, offset) > 0)
                proto_tree_add_item(msdp_tree, hf_msdp_trailing_junk, tvb, offset, -1, ENC_NA);

        return tvb_captured_length(tvb);
}

/* Both Source-Active and Source-Active Response have the same format
 * with one exception. Encapsulated multicast data is not allowed in
 * SA Response.
 */
static void dissect_msdp_sa(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, int *offset, int length)
{
        guint8 entries;

        if (length < 1)
                return;
        entries = tvb_get_guint8(tvb, *offset);
        proto_tree_add_uint(tree, hf_msdp_sa_entry_count, tvb, *offset, 1, entries);
        *offset += 1;
        length -= 1;

        if (length < 4) {
                *offset += length;
                return;
        }
        proto_tree_add_item(tree, hf_msdp_sa_rp_addr, tvb, *offset, 4, ENC_BIG_ENDIAN);
        *offset += 4;
        length -= 4;

        /* Put each of the (S,G) entries in their own subtree.
         * This is probably visually better.
         */
        while (entries-- > 0) {
                proto_tree *entry_tree;

                if (length < 12) {
                        *offset += length;
                        return;
                }
                entry_tree = proto_tree_add_subtree_format(tree, tvb, *offset, 12, ett_msdp_sa_entry, NULL,
                                         "(S,G) block: %s/%u -> %s",
                                         tvb_ip_to_str(tvb, *offset + 8),
                                         tvb_get_guint8(tvb, *offset + 3),
                                         tvb_ip_to_str(tvb, *offset + 4));

                proto_tree_add_item(entry_tree, hf_msdp_sa_reserved, tvb, *offset, 3, ENC_BIG_ENDIAN);
                *offset += 3;
                length -= 3;
                proto_tree_add_item(entry_tree, hf_msdp_sa_sprefix_len, tvb, *offset, 1, ENC_BIG_ENDIAN);
                *offset += 1;
                length -= 1;
                proto_tree_add_item(entry_tree, hf_msdp_sa_group_addr, tvb, *offset, 4, ENC_BIG_ENDIAN);
                *offset += 4;
                length -= 4;
                proto_tree_add_item(entry_tree, hf_msdp_sa_src_addr, tvb, *offset, 4, ENC_BIG_ENDIAN);
                *offset += 4;
                length -= 4;
        }

        /*
         * Check if an encapsulated multicast IPv4 packet follows
         */
        if (length > 0) {
                proto_tree *enc_tree;
                gint available_length, reported_length;
                tvbuff_t *next_tvb;

                enc_tree = proto_tree_add_subtree_format(tree, tvb, *offset, length,
                                         ett_msdp_sa_enc_data, NULL, "Encapsulated IPv4 packet: %u bytes",
                                         length);

                available_length = tvb_captured_length_remaining(tvb, *offset);
                reported_length = tvb_reported_length_remaining(tvb, *offset);
                DISSECTOR_ASSERT(available_length >= 0);
                DISSECTOR_ASSERT(reported_length >= 0);
                if (available_length > reported_length)
                        available_length = reported_length;
                if (available_length > length)
                        available_length = length;
                if (reported_length > length)
                        reported_length = length;

                next_tvb = tvb_new_subset(tvb, *offset, available_length,
                                          reported_length);
                /* Set the information columns read-only so that they
                 * reflect the MSDP packet rather than the
                 * encapsulated packet.
                 */
                col_set_writable(pinfo->cinfo, COL_INFO, FALSE);
                call_dissector(ip_handle, next_tvb, pinfo, enc_tree);
        }
        *offset += length;

        return;
}

/* Note: updates *offset */
static void add_notification_data_ipv4addr(tvbuff_t *tvb, proto_tree *tree, int *offset, int hf_addr)
{
        proto_tree_add_item(tree, hf_msdp_not_res, tvb, *offset, 3, ENC_BIG_ENDIAN);
        *offset += 3;
        proto_tree_add_item(tree, hf_addr, tvb, *offset, 4, ENC_BIG_ENDIAN);
        *offset += 4;

        return;
}

static void dissect_msdp_notification(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, guint16 tlv_len)
{
        guint8              error, error_sub;
        const value_string *vals;

        proto_tree_add_item(tree, hf_msdp_not_o, tvb, *offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_msdp_not_error, tvb, *offset, 1, ENC_BIG_ENDIAN);
        error = tvb_get_guint8(tvb, *offset);
        error &= 0x7F;             /* Error is 7-bit field. O-bit is bit 8 */
        *offset += 1;

        /* Depending on the Error Code, we collect the correct
         * value_strings for the Error subcode
         */
        switch (error) {
        case MESSAGE_HEADER_ERROR:
                vals = hdr_error_vals;
                break;
        case SA_REQUEST_ERROR:
                vals = sa_req_error_vals;
                break;
        case SA_MESSAGE_SA_RESPONSE_ERROR:
                vals = sa_msg_error_vals;
                break;
        case FSM_ERROR:
                vals = fsm_error_vals;
                break;
        case HOLD_TIMER_EXPIRED:
        case NOTIFICATION:
        case CEASE:
                vals = sa_unspec_error_vals;
                break;
        default:
                vals = sa_unspec_error_vals;
                break;
        }

        error_sub = tvb_get_guint8(tvb, *offset);
        proto_tree_add_uint_format_value(tree, hf_msdp_not_error_sub, tvb, *offset, 1,
                                   error_sub, "%s (%u)",
                                   val_to_str_const(error_sub, vals, "<Unknown Error subcode>"),
                                   error_sub);
        *offset += 1;

        /* Do switch again, this time to dissect the data portion
         * correctly. Ugly.
         */
        switch (error) {
        case SA_REQUEST_ERROR:
                add_notification_data_ipv4addr(tvb, tree, offset, hf_msdp_not_group_address);
                break;
        case SA_MESSAGE_SA_RESPONSE_ERROR:
                if (error_sub == 0) {
                        break;
                } else if (error_sub == 1) {
                        proto_tree_add_item(tree, hf_msdp_not_entry_count, tvb, *offset, 1, ENC_BIG_ENDIAN);
                        *offset += 1;
                        break;
                } else if (error_sub == 2) {
                        add_notification_data_ipv4addr(tvb, tree, offset, hf_msdp_not_rp_address);
                        break;
                } else if (error_sub == 3 || error_sub == 8) {
                        add_notification_data_ipv4addr(tvb, tree, offset, hf_msdp_not_group_address);
                        break;
                } else if (error_sub == 4) {
                        add_notification_data_ipv4addr(tvb, tree, offset, hf_msdp_not_source_address);
                        break;
                } else if (error_sub == 5) {
                        proto_tree_add_item(tree, hf_msdp_not_sprefix_len, tvb, *offset, 1, ENC_BIG_ENDIAN);
                        *offset += 1;
                        break;
                } else if (error_sub == 6) {
                        /* No break, causes fall through to next label */
                } else if (error_sub == 7) {
                        proto_tree_add_item(tree, hf_msdp_unknown_encap, tvb, *offset, tlv_len - 5, ENC_NA);
                        *offset += tlv_len - 5;
                        break;
                } else {
                        proto_tree_add_item(tree, hf_msdp_unknown_data, tvb, *offset, tlv_len - 5, ENC_NA);
                        *offset += tlv_len - 5;
                        break;
                }
                /* Fall through */
        case MESSAGE_HEADER_ERROR:
        case NOTIFICATION: {
                tvbuff_t *next_tvb;
                /* Data contains the message that had an error. Even a
                 * broken Notification message causes a Notification
                 * message with Error Code set to Notification to be
                 * sent back.
                 */
                next_tvb = tvb_new_subset_remaining(tvb, *offset);
                dissect_msdp(next_tvb, pinfo, tree, NULL);
                }
                break;
        case FSM_ERROR:
        case HOLD_TIMER_EXPIRED:
        case CEASE:
                /* Do nothing. These contain no data */
                break;
        default:
                if (tlv_len - 5 > 0)
                proto_tree_add_item(tree, hf_msdp_unknown_data, tvb, *offset, tlv_len - 5, ENC_NA);
                *offset += tlv_len - 5;
                break;
        }

        return;
}

void
proto_register_msdp(void)
{
        static hf_register_info hf[] = {
                { &hf_msdp_type,
                        { "Type",           "msdp.type",
                        FT_UINT8, BASE_DEC, VALS(msdp_types), 0,
                        "MSDP TLV type", HFILL }
                },
                { &hf_msdp_length,
                        { "Length",           "msdp.length",
                        FT_UINT16, BASE_DEC, NULL, 0,
                        "MSDP TLV Length", HFILL }
                },
                { &hf_msdp_sa_entry_count,
                        { "Entry Count",           "msdp.sa.entry_count",
                        FT_UINT8, BASE_DEC, NULL, 0,
                        "MSDP SA Entry Count", HFILL }
                },
                { &hf_msdp_sa_rp_addr,
                        { "RP Address",           "msdp.sa.rp_addr",
                        FT_IPv4, BASE_NONE, NULL, 0,
                        "Active source's RP address", HFILL }
                },
                { &hf_msdp_sa_reserved,
                        { "Reserved",           "msdp.sa.reserved",
                        FT_UINT24, BASE_HEX, NULL, 0,
                        "Transmitted as zeros and ignored by a receiver", HFILL }
                },
                { &hf_msdp_sa_sprefix_len,
                        { "Sprefix len",           "msdp.sa.sprefix_len",
                        FT_UINT8, BASE_DEC, NULL, 0,
                        "The route prefix length associated with source address", HFILL }
                },
                { &hf_msdp_sa_group_addr,
                        { "Group Address",           "msdp.sa.group_addr",
                        FT_IPv4, BASE_NONE, NULL, 0,
                        "The group address the active source has sent data to", HFILL }
                },
                { &hf_msdp_sa_src_addr,
                        { "Source Address",           "msdp.sa.src_addr",
                        FT_IPv4, BASE_NONE, NULL, 0,
                        "The IP address of the active source", HFILL }
                },
                { &hf_msdp_sa_req_res,
                        { "Reserved",           "msdp.sa_req.res",
                        FT_UINT8, BASE_HEX, NULL, 0,
                        "Transmitted as zeros and ignored by a receiver", HFILL }
                },
                { &hf_msdp_sa_req_group,
                        { "Group Address",           "msdp.sa_req.group_addr",
                        FT_IPv4, BASE_NONE, NULL, 0,
                        "The group address the MSDP peer is requesting", HFILL }
                },
                { &hf_msdp_not_o,
                        { "Open-bit",           "msdp.not.o",
                        FT_UINT8, BASE_HEX, NULL, 0x80,
                        "If clear, the connection will be closed", HFILL }
                },
                { &hf_msdp_not_error,
                        { "Error Code",           "msdp.not.error",
                        FT_UINT8, BASE_DEC, VALS(error_vals), 0x7F,
                        "Indicates the type of Notification", HFILL }
                },
                { &hf_msdp_not_error_sub,
                        { "Error subcode",           "msdp.not.error_sub",
                        FT_UINT8, BASE_DEC, NULL, 0,
                        NULL, HFILL }
                },
                { &hf_msdp_not_group_address,
                        { "Group address",           "msdp.not.group_address",
                        FT_IPv4, BASE_NONE, NULL, 0,
                        "Group address in Notification messages", HFILL }
                },
                { &hf_msdp_not_rp_address,
                        { "RP address",           "msdp.not.rp_address",
                        FT_IPv4, BASE_NONE, NULL, 0,
                        "RP address in Notification messages", HFILL }
                },
                { &hf_msdp_not_source_address,
                        { "Source address",           "msdp.not.source_address",
                        FT_IPv4, BASE_NONE, NULL, 0,
                        "Source address in Notification messages", HFILL }
                },
                { &hf_msdp_not_res,
                        { "Reserved",           "msdp.not.res",
                        FT_UINT24, BASE_HEX, NULL, 0,
                        "Reserved field in Notification messages", HFILL }
                },
                { &hf_msdp_not_entry_count,
                        { "Entry Count",           "msdp.not.entry_count",
                        FT_UINT24, BASE_HEX, NULL, 0,
                        "Entry Count in Notification messages", HFILL }
                },
                { &hf_msdp_not_sprefix_len,
                        { "Sprefix len",           "msdp.not.sprefix_len",
                        FT_UINT8, BASE_DEC, NULL, 0,
                        "Source prefix length in Notification messages", HFILL }
                },
                { &hf_msdp_tlv_contents,
                        { "TLV contents",           "msdp.tlv_contents",
                        FT_BYTES, BASE_NONE, NULL, 0,
                        NULL, HFILL }
                },
                { &hf_msdp_trailing_junk,
                        { "Trailing junk",           "msdp.trailing_junk",
                        FT_BYTES, BASE_NONE, NULL, 0,
                        NULL, HFILL }
                },
                { &hf_msdp_unknown_encap,
                        { "Packet with unknown encapsulation",           "msdp.unknown_encap",
                        FT_BYTES, BASE_NONE, NULL, 0,
                        NULL, HFILL }
                },
                { &hf_msdp_unknown_data,
                        { "Unknown data",           "msdp.unknown_data",
                        FT_BYTES, BASE_NONE, NULL, 0,
                        NULL, HFILL }
                },
        };

        static gint *ett[] = {
                &ett_msdp,
                &ett_msdp_sa_entry,
                &ett_msdp_sa_enc_data,
                &ett_msdp_not_data,
        };

        proto_msdp = proto_register_protocol("Multicast Source Discovery Protocol",
            "MSDP", "msdp");

        proto_register_field_array(proto_msdp, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_msdp(void)
{
        dissector_handle_t msdp_handle;

        msdp_handle = create_dissector_handle(dissect_msdp, proto_msdp);
        dissector_add_uint("tcp.port", 639, msdp_handle);

        ip_handle = find_dissector_add_dependency("ip", proto_msdp);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=8 tabstop=8 expandtab:
 * :indentSize=8:tabSize=8:noTabs=true:
 */

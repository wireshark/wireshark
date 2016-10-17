/* packet-lacp.c
 * Routines for Link Aggregation Control Protocol dissection.
 * IEEE Std 802.1AX
 *
 * Copyright 2002 Steve Housley <steve_housley@3com.com>
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
#include <epan/slow_protocol_subtypes.h>

/* General declarations */
void proto_register_lacp(void);
void proto_reg_handoff_lacp(void);

/* Actor and Partner Flag bits */
#define LACPDU_FLAGS_ACTIVITY           0x01
#define LACPDU_FLAGS_TIMEOUT            0x02
#define LACPDU_FLAGS_AGGREGATION        0x04
#define LACPDU_FLAGS_SYNC               0x08
#define LACPDU_FLAGS_COLLECTING         0x10
#define LACPDU_FLAGS_DISTRIB            0x20
#define LACPDU_FLAGS_DEFAULTED          0x40
#define LACPDU_FLAGS_EXPIRED            0x80

/* Initialise the protocol and registered fields */
static int proto_lacp = -1;

static int hf_lacp_version_number = -1;
static int hf_lacp_actor_type = -1;
static int hf_lacp_actor_info_len = -1;
static int hf_lacp_actor_sys_priority = -1;
static int hf_lacp_actor_sys = -1;
static int hf_lacp_actor_key = -1;
static int hf_lacp_actor_port_priority = -1;
static int hf_lacp_actor_port = -1;
static int hf_lacp_actor_state = -1;
static int hf_lacp_actor_state_str = -1;
static int hf_lacp_flags_a_activity = -1;
static int hf_lacp_flags_a_timeout = -1;
static int hf_lacp_flags_a_aggregation = -1;
static int hf_lacp_flags_a_sync = -1;
static int hf_lacp_flags_a_collecting = -1;
static int hf_lacp_flags_a_distrib = -1;
static int hf_lacp_flags_a_defaulted = -1;
static int hf_lacp_flags_a_expired = -1;
static int hf_lacp_actor_reserved = -1;

static int hf_lacp_partner_type = -1;
static int hf_lacp_partner_info_len = -1;
static int hf_lacp_partner_sys_priority = -1;
static int hf_lacp_partner_sys = -1;
static int hf_lacp_partner_key = -1;
static int hf_lacp_partner_port_priority = -1;
static int hf_lacp_partner_port = -1;
static int hf_lacp_partner_state = -1;
static int hf_lacp_partner_state_str = -1;
static int hf_lacp_flags_p_activity = -1;
static int hf_lacp_flags_p_timeout = -1;
static int hf_lacp_flags_p_aggregation = -1;
static int hf_lacp_flags_p_sync = -1;
static int hf_lacp_flags_p_collecting = -1;
static int hf_lacp_flags_p_distrib = -1;
static int hf_lacp_flags_p_defaulted = -1;
static int hf_lacp_flags_p_expired = -1;
static int hf_lacp_partner_reserved = -1;

static int hf_lacp_coll_type = -1;
static int hf_lacp_coll_info_len = -1;
static int hf_lacp_coll_max_delay = -1;
static int hf_lacp_coll_reserved = -1;

static int hf_lacp_term_type = -1;
static int hf_lacp_term_len = -1;
static int hf_lacp_term_reserved = -1;

/* Initialise the subtree pointers */

static gint ett_lacp = -1;
static gint ett_lacp_a_flags = -1;
static gint ett_lacp_p_flags = -1;

static const true_false_string tfs_active_passive = { "Active", "Passive" };
static const true_false_string tfs_short_long_timeout = { "Short Timeout", "Long Timeout" };
static const true_false_string tfs_aggregatable_individual = { "Aggregatable", "Individual" };
static const true_false_string tfs_in_sync_out_sync = { "In Sync", "Out of Sync" };

static const char * lacp_state_flags_to_str(guint32 value)
{
    wmem_strbuf_t *buf = wmem_strbuf_new(wmem_packet_scope(), "");
    const unsigned int flags_count = 8;
    const char first_letters[] = "EFDCSGSA";
    unsigned int i;

    for (i = 0; i < flags_count; i++) {
        if (((value >> (flags_count - 1 - i)) & 1)) {
            wmem_strbuf_append_c(buf, first_letters[i]);
        } else {
            wmem_strbuf_append_c(buf, '*');
        }
    }

    return wmem_strbuf_finalize(buf);
}

/*
 * Name: dissect_lacp
 *
 * Description:
 *    This function is used to dissect the Link Aggregation Control Protocol
 *    defined in IEEE 802.1AX
 *
 * Input Arguments:
 *    tvb:   buffer associated with the rcv packet (see tvbuff.h).
 *    pinfo: structure associated with the rcv packet (see packet_info.h).
 *    tree:  the protocol tree associated with the rcv packet (see proto.h).
 *
 * Return Values: None
 *
 * Notes:
 */
static int
dissect_lacp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int     offset = 0;
    guint16 raw_word;
    guint8  raw_octet;

    proto_tree *lacpdu_tree;
    proto_item *lacpdu_item, *ti;
    static const int * actor_flags[] = {
        &hf_lacp_flags_a_activity,
        &hf_lacp_flags_a_timeout,
        &hf_lacp_flags_a_aggregation,
        &hf_lacp_flags_a_sync,
        &hf_lacp_flags_a_collecting,
        &hf_lacp_flags_a_distrib,
        &hf_lacp_flags_a_defaulted,
        &hf_lacp_flags_a_expired,
        NULL
    };
    static const int * partner_flags[] = {
        &hf_lacp_flags_p_activity,
        &hf_lacp_flags_p_timeout,
        &hf_lacp_flags_p_aggregation,
        &hf_lacp_flags_p_sync,
        &hf_lacp_flags_p_collecting,
        &hf_lacp_flags_p_distrib,
        &hf_lacp_flags_p_defaulted,
        &hf_lacp_flags_p_expired,
        NULL
    };

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LACP");
    col_set_str(pinfo->cinfo, COL_INFO, "Link Aggregation Control Protocol");

    /* Add LACP Heading */
    lacpdu_item = proto_tree_add_protocol_format(tree, proto_lacp, tvb,
                                                 0, -1, "Link Aggregation Control Protocol");
    lacpdu_tree = proto_item_add_subtree(lacpdu_item, ett_lacp);

    /* Version Number */

    raw_octet = tvb_get_guint8(tvb, offset);
    col_append_fstr(pinfo->cinfo, COL_INFO, " Version %d.  ", raw_octet);
    proto_tree_add_uint(lacpdu_tree, hf_lacp_version_number, tvb,
                        offset, 1, raw_octet);
    offset += 1;

    /* Actor Type */

    proto_tree_add_item(lacpdu_tree, hf_lacp_actor_type, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Actor Info Length */

    proto_tree_add_item(lacpdu_tree, hf_lacp_actor_info_len, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Actor System Priority */

    proto_tree_add_item(lacpdu_tree, hf_lacp_actor_sys_priority, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Actor System */

    proto_tree_add_item(lacpdu_tree, hf_lacp_actor_sys, tvb,
                        offset, 6, ENC_NA);
    offset += 6;

    /* Actor Key */

    proto_tree_add_item(lacpdu_tree, hf_lacp_actor_key, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Actor Port Priority */

    proto_tree_add_item(lacpdu_tree, hf_lacp_actor_port_priority, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Actor Port */

    raw_word = tvb_get_ntohs(tvb, offset);
    col_append_fstr(pinfo->cinfo, COL_INFO, "Actor Port = %d ", raw_word);
    proto_tree_add_uint(lacpdu_tree, hf_lacp_actor_port, tvb,
                        offset, 2, raw_word);
    offset += 2;

    /* Actor State */
    proto_tree_add_bitmask_with_flags(lacpdu_tree, tvb, offset, hf_lacp_actor_state,
                           ett_lacp_a_flags, actor_flags, ENC_NA, BMT_NO_INT|BMT_NO_TFS|BMT_NO_FALSE);
    ti = proto_tree_add_string(lacpdu_tree, hf_lacp_actor_state_str, tvb, offset, 1, lacp_state_flags_to_str(tvb_get_guint8(tvb, offset)));
    PROTO_ITEM_SET_GENERATED(ti);
    offset += 1;

    /* Actor Reserved */

    proto_tree_add_item(lacpdu_tree, hf_lacp_actor_reserved, tvb,
                        offset, 3, ENC_NA);
    offset += 3;

    /* Partner Type */

    proto_tree_add_item(lacpdu_tree, hf_lacp_partner_type, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Partner Info Length */

    proto_tree_add_item(lacpdu_tree, hf_lacp_partner_info_len, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Partner System Priority */

    proto_tree_add_item(lacpdu_tree, hf_lacp_partner_sys_priority, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Partner System */

    proto_tree_add_item(lacpdu_tree, hf_lacp_partner_sys, tvb,
                        offset, 6, ENC_NA);
    offset += 6;

    /* Partner Key */

    proto_tree_add_item(lacpdu_tree, hf_lacp_partner_key, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Partner Port Priority */

    proto_tree_add_item(lacpdu_tree, hf_lacp_partner_port_priority, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Partner Port */

    raw_word = tvb_get_ntohs(tvb, offset);
    col_append_fstr(pinfo->cinfo, COL_INFO, "Partner Port = %d ", raw_word);
    proto_tree_add_uint(lacpdu_tree, hf_lacp_partner_port, tvb,
                        offset, 2, raw_word);
    offset += 2;

    if (tree)
    {
        proto_tree_add_bitmask_with_flags(lacpdu_tree, tvb, offset, hf_lacp_partner_state,
                           ett_lacp_p_flags, partner_flags, ENC_NA, BMT_NO_INT|BMT_NO_TFS|BMT_NO_FALSE);

        ti = proto_tree_add_string(lacpdu_tree, hf_lacp_partner_state_str, tvb, offset, 1, lacp_state_flags_to_str(tvb_get_guint8(tvb, offset)));
        PROTO_ITEM_SET_GENERATED(ti);
        offset += 1;

        /* Partner Reserved */

        proto_tree_add_item(lacpdu_tree, hf_lacp_partner_reserved, tvb,
                offset, 3, ENC_NA);
        offset += 3;

        /* Collector Type */

        proto_tree_add_item(lacpdu_tree, hf_lacp_coll_type, tvb,
                offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        /* Collector Info Length */

        proto_tree_add_item(lacpdu_tree, hf_lacp_coll_info_len, tvb,
                offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        /* Collector Max Delay */

        proto_tree_add_item(lacpdu_tree, hf_lacp_coll_max_delay, tvb,
                offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* Collector Reserved */

        proto_tree_add_item(lacpdu_tree, hf_lacp_coll_reserved, tvb,
                offset, 12, ENC_NA);
        offset += 12;

        /* Terminator Type */

        proto_tree_add_item(lacpdu_tree, hf_lacp_term_type, tvb,
                offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        /* Terminator Info Length */

        proto_tree_add_item(lacpdu_tree, hf_lacp_term_len, tvb,
                offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        /* Terminator Reserved */

        proto_tree_add_item(lacpdu_tree, hf_lacp_term_reserved, tvb,
                offset, 50, ENC_NA);
    }
    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void
proto_register_lacp(void)
{
/* Setup list of header fields */

    static hf_register_info hf[] = {
        { &hf_lacp_version_number,
          { "LACP Version Number",    "lacp.version",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "Identifies the LACP version", HFILL }},

        { &hf_lacp_actor_type,
          { "Actor Information",    "lacp.actorInfo",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "TLV type = Actor", HFILL }},

        { &hf_lacp_actor_info_len,
          { "Actor Information Length",            "lacp.actorInfoLen",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "The length of the Actor TLV", HFILL }},

        { &hf_lacp_actor_sys_priority,
          { "Actor System Priority",  "lacp.actorSysPriority",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "The priority assigned to this System by management or admin", HFILL }},

        { &hf_lacp_actor_sys,
          { "Actor System",            "lacp.actorSystem",
            FT_ETHER,    BASE_NONE,    NULL,    0x0,
            "The Actor's System ID encoded as a MAC address", HFILL }},

        { &hf_lacp_actor_key,
          { "Actor Key",            "lacp.actorKey",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "The operational Key value assigned to the port by the Actor", HFILL }},

        { &hf_lacp_actor_port_priority,
          { "Actor Port Priority",            "lacp.actorPortPriority",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "The priority assigned to the port by the Actor (via Management or Admin)", HFILL }},

        { &hf_lacp_actor_port,
          { "Actor Port",            "lacp.actorPort",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "The port number assigned to the port by the Actor (via Management or Admin)", HFILL }},

        { &hf_lacp_actor_state,
          { "Actor State",            "lacp.actorState",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "The Actor's state variables for the port, encoded as bits within a single octet", HFILL }},

        { &hf_lacp_actor_state_str,
          { "Actor State Flags",            "lacp.actorState.str",
            FT_STRING,    BASE_NONE,    NULL,    0x0,
            "The Actor's state flags as a string value", HFILL }},

        { &hf_lacp_flags_a_activity,
          { "LACP Activity",        "lacp.actorState.activity",
            FT_BOOLEAN,    8,        TFS(&tfs_active_passive),    LACPDU_FLAGS_ACTIVITY,
            NULL, HFILL }},

        { &hf_lacp_flags_a_timeout,
          { "LACP Timeout",        "lacp.actorState.timeout",
            FT_BOOLEAN,    8,        TFS(&tfs_short_long_timeout),    LACPDU_FLAGS_TIMEOUT,
            NULL, HFILL }},

        { &hf_lacp_flags_a_aggregation,
          { "Aggregation",        "lacp.actorState.aggregation",
            FT_BOOLEAN,    8,        TFS(&tfs_aggregatable_individual),    LACPDU_FLAGS_AGGREGATION,
            NULL, HFILL }},

        { &hf_lacp_flags_a_sync,
          { "Synchronization",        "lacp.actorState.synchronization",
            FT_BOOLEAN,    8,        TFS(&tfs_in_sync_out_sync),    LACPDU_FLAGS_SYNC,
            NULL, HFILL }},

        { &hf_lacp_flags_a_collecting,
          { "Collecting",        "lacp.actorState.collecting",
            FT_BOOLEAN,    8,        TFS(&tfs_enabled_disabled),    LACPDU_FLAGS_COLLECTING,
            NULL, HFILL }},

        { &hf_lacp_flags_a_distrib,
          { "Distributing",        "lacp.actorState.distributing",
            FT_BOOLEAN,    8,        TFS(&tfs_enabled_disabled),    LACPDU_FLAGS_DISTRIB,
            NULL, HFILL }},

        { &hf_lacp_flags_a_defaulted,
          { "Defaulted",        "lacp.actorState.defaulted",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    LACPDU_FLAGS_DEFAULTED,
            "1 = Actor Rx machine is using DEFAULT Partner info, 0 = using info in Rx'd LACPDU", HFILL }},

        { &hf_lacp_flags_a_expired,
          { "Expired",        "lacp.actorState.expired",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    LACPDU_FLAGS_EXPIRED,
            "1 = Actor Rx machine is EXPIRED, 0 = is NOT EXPIRED", HFILL }},

        { &hf_lacp_actor_reserved,
          { "Reserved",        "lacp.reserved",
            FT_BYTES,    BASE_NONE,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_lacp_partner_type,
          { "Partner Information",    "lacp.partnerInfo",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "TLV type = Partner", HFILL }},

        { &hf_lacp_partner_info_len,
          { "Partner Information Length",            "lacp.partnerInfoLen",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "The length of the Partner TLV", HFILL }},

        { &hf_lacp_partner_sys_priority,
          { "Partner System Priority",  "lacp.partnerSysPriority",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "The priority assigned to the Partner System by management or admin", HFILL }},

        { &hf_lacp_partner_sys,
          { "Partner System",            "lacp.partnerSystem",
            FT_ETHER,    BASE_NONE,    NULL,    0x0,
            "The Partner's System ID encoded as a MAC address", HFILL }},

        { &hf_lacp_partner_key,
          { "Partner Key",            "lacp.partnerKey",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "The operational Key value assigned to the port associated with this link by the Partner", HFILL }},

        { &hf_lacp_partner_port_priority,
          { "Partner Port Priority",            "lacp.partnerPortPriority",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "The priority assigned to the port by the Partner (via Management or Admin)", HFILL }},

        { &hf_lacp_partner_port,
          { "Partner Port",            "lacp.partnerPort",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "The port number associated with this link assigned to the port by the Partner (via Management or Admin)", HFILL }},

        { &hf_lacp_partner_state,
          { "Partner State",            "lacp.partnerState",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "The Partner's state variables for the port, encoded as bits within a single octet", HFILL }},

        { &hf_lacp_partner_state_str,
          { "Partner State Flags",            "lacp.partnerState.str",
            FT_STRING,    BASE_NONE,    NULL,    0x0,
            "The Partner's state flags as a string value", HFILL }},

        { &hf_lacp_flags_p_activity,
          { "LACP Activity",        "lacp.partnerState.activity",
            FT_BOOLEAN,    8,        TFS(&tfs_active_passive),    LACPDU_FLAGS_ACTIVITY,
            NULL, HFILL }},

        { &hf_lacp_flags_p_timeout,
          { "LACP Timeout",        "lacp.partnerState.timeout",
            FT_BOOLEAN,    8,        TFS(&tfs_short_long_timeout),    LACPDU_FLAGS_TIMEOUT,
            NULL, HFILL }},

        { &hf_lacp_flags_p_aggregation,
          { "Aggregation",        "lacp.partnerState.aggregation",
            FT_BOOLEAN,    8,        TFS(&tfs_aggregatable_individual),    LACPDU_FLAGS_AGGREGATION,
            NULL, HFILL }},

        { &hf_lacp_flags_p_sync,
          { "Synchronization",        "lacp.partnerState.synchronization",
            FT_BOOLEAN,    8,        TFS(&tfs_in_sync_out_sync),    LACPDU_FLAGS_SYNC,
            NULL, HFILL }},

        { &hf_lacp_flags_p_collecting,
          { "Collecting",        "lacp.partnerState.collecting",
            FT_BOOLEAN,    8,        TFS(&tfs_enabled_disabled),    LACPDU_FLAGS_COLLECTING,
            NULL, HFILL }},

        { &hf_lacp_flags_p_distrib,
          { "Distributing",        "lacp.partnerState.distributing",
            FT_BOOLEAN,    8,        TFS(&tfs_enabled_disabled),    LACPDU_FLAGS_DISTRIB,
            NULL, HFILL }},

        { &hf_lacp_flags_p_defaulted,
          { "Defaulted",        "lacp.partnerState.defaulted",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    LACPDU_FLAGS_DEFAULTED,
            "1 = Actor Rx machine is using DEFAULT Partner info, 0 = using info in Rx'd LACPDU", HFILL }},

        { &hf_lacp_flags_p_expired,
          { "Expired",        "lacp.partnerState.expired",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    LACPDU_FLAGS_EXPIRED,
            "1 = Actor Rx machine is EXPIRED, 0 = is NOT EXPIRED", HFILL }},

        { &hf_lacp_partner_reserved,
          { "Reserved",        "lacp.reserved",
            FT_BYTES,    BASE_NONE,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_lacp_coll_type,
          { "Collector Information",    "lacp.collectorInfo",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "TLV type = Collector", HFILL }},

        { &hf_lacp_coll_info_len,
          { "Collector Information Length",            "lacp.collectorInfoLen",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "The length of the Collector TLV", HFILL }},

        { &hf_lacp_coll_max_delay,
          { "Collector Max Delay",  "lacp.collectorMaxDelay",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "The max delay of the station tx'ing the LACPDU (in tens of usecs)", HFILL }},

        { &hf_lacp_coll_reserved,
          { "Reserved",        "lacp.coll_reserved",
            FT_BYTES,    BASE_NONE,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_lacp_term_type,
          { "Terminator Information",    "lacp.termInfo",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "TLV type = Terminator", HFILL }},

        { &hf_lacp_term_len,
          { "Terminator Length",            "lacp.termLen",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "The length of the Terminator TLV", HFILL }},

        { &hf_lacp_term_reserved,
          { "Reserved",        "lacp.term_reserved",
            FT_BYTES,    BASE_NONE,    NULL,    0x0,
            NULL, HFILL }},
    };

    /* Setup protocol subtree array */

    static gint *ett[] = {
        &ett_lacp,
        &ett_lacp_a_flags,
        &ett_lacp_p_flags,
    };

    /* Register the protocol name and description */

    proto_lacp = proto_register_protocol("LACP", "Link Aggregation Control Protocol", "lacp");

    /* Required function calls to register the header fields and subtrees used */

    proto_register_field_array(proto_lacp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_lacp(void)
{
    dissector_handle_t lacp_handle;

    lacp_handle = create_dissector_handle(dissect_lacp, proto_lacp);
    dissector_add_uint("slow.subtype", LACP_SUBTYPE, lacp_handle);
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

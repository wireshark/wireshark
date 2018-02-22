/* packet-lacp.c
 * Routines for Link Aggregation Control Protocol dissection.
 * IEEE Std 802.1AX-2014 Section 6.4.2.3
 *
 * Copyright 2002 Steve Housley <steve_housley@3com.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/expert.h>
#include <epan/slow_protocol_subtypes.h>

/* General declarations */
void proto_register_lacp(void);
void proto_reg_handoff_lacp(void);

/* TLV Types */
#define LACPDU_TYPE_TERMINATOR			0x00
#define LACPDU_TYPE_ACTOR_INFORMATION		0x01
#define LACPDU_TYPE_PARTNER_INFORMATION		0x02
#define LACPDU_TYPE_COLLECTOR_INFORMATION	0x03

static const value_string lacp_type_vals[] = {
    { LACPDU_TYPE_TERMINATOR,			"Terminator" },
    { LACPDU_TYPE_ACTOR_INFORMATION,		"Actor Information" },
    { LACPDU_TYPE_PARTNER_INFORMATION,		"Partner Information" },
    { LACPDU_TYPE_COLLECTOR_INFORMATION,	"Collector Information" },
    { 0, NULL }
};

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
static int hf_lacp_tlv_type = -1;
static int hf_lacp_tlv_length = -1;

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

static int hf_lacp_coll_max_delay = -1;
static int hf_lacp_coll_reserved = -1;

static int hf_lacp_pad = -1;

static int hf_lacp_vendor = -1;

static int hf_lacp_vendor_hp_length = -1;
static int hf_lacp_vendor_hp_irf_domain = -1;
static int hf_lacp_vendor_hp_irf_mac = -1;
static int hf_lacp_vendor_hp_irf_switch = -1;
static int hf_lacp_vendor_hp_irf_port = -1;
static int hf_lacp_vendor_hp_unknown = -1;


/* Initialise the subtree pointers */
static gint ett_lacp = -1;
static gint ett_lacp_a_flags = -1;
static gint ett_lacp_p_flags = -1;

/* Expert Items */
static expert_field ei_lacp_wrong_tlv_type = EI_INIT;
static expert_field ei_lacp_wrong_tlv_length = EI_INIT;

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
    int          offset = 0, length_remaining;
    guint        tlv_type, tlv_length;
    guint        port;
    guint8       raw_octet;
    const gchar  *sysidstr;

    proto_tree *lacp_tree;
    proto_item *lacp_item, *tlv_type_item, *tlv_length_item;
    proto_item *ti;

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
    lacp_item = proto_tree_add_protocol_format(tree, proto_lacp, tvb,
                                                 0, -1, "Link Aggregation Control Protocol");
    lacp_tree = proto_item_add_subtree(lacp_item, ett_lacp);

    /* Version Number */

    raw_octet = tvb_get_guint8(tvb, offset);
    col_add_fstr(pinfo->cinfo, COL_INFO, "V%d", raw_octet);
    proto_tree_add_uint(lacp_tree, hf_lacp_version_number, tvb, offset, 1, raw_octet);
    offset += 1;

    /* Actor */

    tlv_type_item = proto_tree_add_item_ret_uint(lacp_tree, hf_lacp_tlv_type, tvb, offset, 1, ENC_BIG_ENDIAN, &tlv_type);
    offset += 1;

    tlv_length_item = proto_tree_add_item_ret_uint(lacp_tree, hf_lacp_tlv_length, tvb, offset, 1, ENC_BIG_ENDIAN, &tlv_length);
    offset += 1;

    if (tlv_type != LACPDU_TYPE_ACTOR_INFORMATION) {
        expert_add_info(pinfo, tlv_type_item, &ei_lacp_wrong_tlv_type);
    }
    if (tlv_length != 20) {
        expert_add_info(pinfo, tlv_length_item, &ei_lacp_wrong_tlv_length);
    }

    proto_tree_add_item(lacp_tree, hf_lacp_actor_sys_priority, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(lacp_tree, hf_lacp_actor_sys, tvb, offset, 6, ENC_NA);
    sysidstr = tvb_ether_to_str(tvb, offset);
    offset += 6;

    proto_tree_add_item(lacp_tree, hf_lacp_actor_key, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(lacp_tree, hf_lacp_actor_port_priority, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item_ret_uint(lacp_tree, hf_lacp_actor_port, tvb, offset, 2, ENC_BIG_ENDIAN, &port);
    offset += 2;

    proto_tree_add_bitmask_with_flags(lacp_tree, tvb, offset, hf_lacp_actor_state,
                           ett_lacp_a_flags, actor_flags, ENC_NA, BMT_NO_INT|BMT_NO_TFS|BMT_NO_FALSE);
    ti = proto_tree_add_string(lacp_tree, hf_lacp_actor_state_str, tvb, offset, 1, lacp_state_flags_to_str(tvb_get_guint8(tvb, offset)));
    PROTO_ITEM_SET_GENERATED(ti);
    offset += 1;

    proto_tree_add_item(lacp_tree, hf_lacp_actor_reserved, tvb, offset, 3, ENC_NA);
    offset += 3;

    col_append_fstr(pinfo->cinfo, COL_INFO, " ACTOR SysID: %s, P: %d ", sysidstr, port);

    /* Partner */

    tlv_type_item = proto_tree_add_item_ret_uint(lacp_tree, hf_lacp_tlv_type, tvb, offset, 1, ENC_BIG_ENDIAN, &tlv_type);
    offset += 1;

    tlv_length_item = proto_tree_add_item_ret_uint(lacp_tree, hf_lacp_tlv_length, tvb, offset, 1, ENC_BIG_ENDIAN, &tlv_length);
    offset += 1;

    if (tlv_type != LACPDU_TYPE_PARTNER_INFORMATION) {
        expert_add_info(pinfo, tlv_type_item, &ei_lacp_wrong_tlv_type);
    }
    if (tlv_length != 20) {
        expert_add_info(pinfo, tlv_length_item, &ei_lacp_wrong_tlv_length);
    }

    proto_tree_add_item(lacp_tree, hf_lacp_partner_sys_priority, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(lacp_tree, hf_lacp_partner_sys, tvb, offset, 6, ENC_NA);
    sysidstr = tvb_ether_to_str(tvb, offset);
    offset += 6;

    proto_tree_add_item(lacp_tree, hf_lacp_partner_key, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(lacp_tree, hf_lacp_partner_port_priority, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item_ret_uint(lacp_tree, hf_lacp_partner_port, tvb, offset, 2, ENC_BIG_ENDIAN, &port);
    offset += 2;

    proto_tree_add_bitmask_with_flags(lacp_tree, tvb, offset, hf_lacp_partner_state, ett_lacp_p_flags, partner_flags, ENC_NA, BMT_NO_INT|BMT_NO_TFS|BMT_NO_FALSE);

    ti = proto_tree_add_string(lacp_tree, hf_lacp_partner_state_str, tvb, offset, 1, lacp_state_flags_to_str(tvb_get_guint8(tvb, offset)));
    PROTO_ITEM_SET_GENERATED(ti);
    offset += 1;

    proto_tree_add_item(lacp_tree, hf_lacp_partner_reserved, tvb, offset, 3, ENC_NA);
    offset += 3;

    col_append_fstr(pinfo->cinfo, COL_INFO, " PARTNER SysID: %s, P: %d ", sysidstr, port);

    /* Collector */

    tlv_type_item = proto_tree_add_item_ret_uint(lacp_tree, hf_lacp_tlv_type, tvb, offset, 1, ENC_BIG_ENDIAN, &tlv_type);
    offset += 1;

    tlv_length_item = proto_tree_add_item_ret_uint(lacp_tree, hf_lacp_tlv_length, tvb, offset, 1, ENC_BIG_ENDIAN, &tlv_length);
    offset += 1;

    if (tlv_type != LACPDU_TYPE_COLLECTOR_INFORMATION) {
        expert_add_info(pinfo, tlv_type_item, &ei_lacp_wrong_tlv_type);
    }
    if (tlv_length != 16) {
        expert_add_info(pinfo, tlv_length_item, &ei_lacp_wrong_tlv_length);
    }

    proto_tree_add_item(lacp_tree, hf_lacp_coll_max_delay, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(lacp_tree, hf_lacp_coll_reserved, tvb, offset, 12, ENC_NA);
    offset += 12;

    col_append_fstr(pinfo->cinfo, COL_INFO, " COLLECTOR");

    /* Other TLVs (LACP version 2) */

    tlv_type_item = proto_tree_add_item_ret_uint(lacp_tree, hf_lacp_tlv_type, tvb, offset, 1, ENC_BIG_ENDIAN, &tlv_type);
    offset += 1;

    tlv_length_item = proto_tree_add_item_ret_uint(lacp_tree, hf_lacp_tlv_length, tvb, offset, 1, ENC_BIG_ENDIAN, &tlv_length);
    offset += 1;

    while (tlv_type != LACPDU_TYPE_TERMINATOR) {
        offset += (tlv_length - 2);
        tlv_type_item = proto_tree_add_item_ret_uint(lacp_tree, hf_lacp_tlv_type, tvb, offset, 1, ENC_BIG_ENDIAN, &tlv_type);
        offset += 1;

        tlv_length_item = proto_tree_add_item_ret_uint(lacp_tree, hf_lacp_tlv_length, tvb, offset, 1, ENC_BIG_ENDIAN, &tlv_length);
        offset += 1;
    }

    /* Terminator - already handled */

    if (tlv_length != 0) {
        expert_add_info(pinfo, tlv_length_item, &ei_lacp_wrong_tlv_length);
    }

    /* Pad */

    if (offset < (128 - 1 - 18)) {  /* LACPv1 fixed size - Eth */
        proto_tree_add_item(lacp_tree, hf_lacp_pad, tvb, offset, (128 - 1 - 18)-offset, ENC_NA);
        offset += ((128 - 1 - 18)-offset);
    }

    /* HP specific stuff (in violation of standard) */

    length_remaining = tvb_reported_length_remaining(tvb, offset);
    if (length_remaining) {
        proto_tree_add_item(lacp_tree, hf_lacp_vendor, tvb, offset, length_remaining, ENC_NA);

        /* HP LACP MAD IRF, first bytes is always 0x64 and second bytes is the rest of length */
        if (length_remaining > 2 && (tvb_get_guint8(tvb, offset) == 0x64) && ((length_remaining -2) == tvb_get_guint8(tvb, offset+1)) )
        {
            proto_tree_add_item(lacp_tree, hf_lacp_vendor_hp_unknown, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(lacp_tree, hf_lacp_vendor_hp_length, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(lacp_tree, hf_lacp_vendor_hp_unknown, tvb, offset, 2, ENC_NA);
            offset += 2;

            proto_tree_add_item(lacp_tree, hf_lacp_vendor_hp_irf_domain, tvb, offset, 2, ENC_NA);
            offset += 2;

            proto_tree_add_item(lacp_tree, hf_lacp_vendor_hp_irf_mac, tvb, offset, 6, ENC_NA);
            offset += 6;

            proto_tree_add_item(lacp_tree, hf_lacp_vendor_hp_unknown, tvb, offset, 8, ENC_NA);
            offset += 8;

            proto_tree_add_item(lacp_tree, hf_lacp_vendor_hp_irf_switch, tvb, offset, 2, ENC_NA);
            offset += 2;

            proto_tree_add_item(lacp_tree, hf_lacp_vendor_hp_irf_port, tvb, offset, 2, ENC_NA);
            offset += 2;

            proto_tree_add_item(lacp_tree, hf_lacp_vendor_hp_unknown, tvb, offset, 2, ENC_NA);
            offset += 2;

        } else {
            offset += length_remaining;
        }
    }

    return offset;
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

        { &hf_lacp_tlv_type,
          { "TLV Type",               "lacp.tlv_type",
            FT_UINT8,    BASE_HEX,    VALS(lacp_type_vals),    0x0,
            NULL, HFILL }},

        { &hf_lacp_tlv_length,
          { "TLV Length",             "lacp.tlv_length",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            NULL, HFILL }},

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

        { &hf_lacp_coll_max_delay,
          { "Collector Max Delay",  "lacp.collectorMaxDelay",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "The max delay of the station tx'ing the LACPDU (in tens of usecs)", HFILL }},

        { &hf_lacp_coll_reserved,
          { "Reserved",        "lacp.coll_reserved",
            FT_BYTES,    BASE_NONE,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_lacp_pad,
          { "Pad",        "lacp.pad",
            FT_BYTES,    BASE_NONE,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_lacp_vendor,
          { "Unknown vendor",        "lacp.vendor",
            FT_BYTES,    BASE_NONE,    NULL,    0x0,
            "Some extra bytes (Vendor Specific ?)", HFILL }},

        /* HP IRF MAD LACP */
        { &hf_lacp_vendor_hp_length,
          { "Length",        "lacp.vendor.hp.length",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "The length of HP TLV", HFILL }},
        { &hf_lacp_vendor_hp_irf_domain,
          { "IRF Domain",        "lacp.vendor.hp.irf_domain",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            NULL, HFILL }},
        { &hf_lacp_vendor_hp_irf_mac,
          { "IRF MAC",        "lacp.vendor.hp.irf_mac",
            FT_ETHER,    BASE_NONE,    NULL,    0x0,
            NULL, HFILL }},
        { &hf_lacp_vendor_hp_irf_switch,
          { "IRF Switch",        "lacp.vendor.hp.irf_switch",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "Number of switch on the IRF stack", HFILL }},
        { &hf_lacp_vendor_hp_irf_port,
          { "IRF Port",        "lacp.vendor.hp.irf_port",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "Stack ID where the LACP is attached", HFILL }},
        { &hf_lacp_vendor_hp_unknown,
          { "Unknown",        "lacp.vendor.hp.unknown",
            FT_BYTES,    BASE_NONE,    NULL,    0x0,
            NULL, HFILL }},
    };

    /* Setup protocol subtree array */

    static gint *ett[] = {
        &ett_lacp,
        &ett_lacp_a_flags,
        &ett_lacp_p_flags,
    };

    static ei_register_info ei[] = {
    { &ei_lacp_wrong_tlv_type,   { "lacp.wrong_tlv_type",   PI_MALFORMED, PI_ERROR, "TLV is not expected type",   EXPFILL }},
    { &ei_lacp_wrong_tlv_length, { "lacp.wrong_tlv_length", PI_MALFORMED, PI_ERROR, "TLV is not expected length", EXPFILL }},
    };

    expert_module_t* expert_lacp;


    /* Register the protocol name and description */

    proto_lacp = proto_register_protocol("LACP", "Link Aggregation Control Protocol", "lacp");

    /* Required function calls to register the header fields and subtrees used */

    proto_register_field_array(proto_lacp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_lacp = expert_register_protocol(proto_lacp);
    expert_register_field_array(expert_lacp, ei, array_length(ei));

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

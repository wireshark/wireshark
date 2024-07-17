/* packet-lacp.c
 * Routines for Link Aggregation Control Protocol dissection.
 * IEEE Std 802.1AX-2014 Section 6.4.2.3
 *  Split from IEEE Std 802.3-2005 and named IEEE 802.3ad before that
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

#include <epan/etypes.h>
#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/expert.h>
#include <epan/slow_protocol_subtypes.h>

/* General declarations */
void proto_register_lacp(void);
void proto_reg_handoff_lacp(void);

static dissector_handle_t lacp_handle;

#define VLACP_MAGIC_LACP 0x01010114
#define VLACP_MAGIC_MARKER 0x02010114

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
static int proto_lacp;

static int hf_lacp_vlacp_subtype;
static int hf_lacp_version;
static int hf_lacp_tlv_type;
static int hf_lacp_tlv_length;

static int hf_lacp_actor_sysid_priority;
static int hf_lacp_actor_sysid;
static int hf_lacp_actor_key;
static int hf_lacp_actor_port_priority;
static int hf_lacp_actor_port;
static int hf_lacp_actor_state;
static int hf_lacp_actor_state_str;
static int hf_lacp_flags_a_activity;
static int hf_lacp_flags_a_timeout;
static int hf_lacp_flags_a_aggregation;
static int hf_lacp_flags_a_sync;
static int hf_lacp_flags_a_collecting;
static int hf_lacp_flags_a_distrib;
static int hf_lacp_flags_a_defaulted;
static int hf_lacp_flags_a_expired;
static int hf_lacp_actor_reserved;

static int hf_lacp_partner_sysid_priority;
static int hf_lacp_partner_sysid;
static int hf_lacp_partner_key;
static int hf_lacp_partner_port_priority;
static int hf_lacp_partner_port;
static int hf_lacp_partner_state;
static int hf_lacp_partner_state_str;
static int hf_lacp_flags_p_activity;
static int hf_lacp_flags_p_timeout;
static int hf_lacp_flags_p_aggregation;
static int hf_lacp_flags_p_sync;
static int hf_lacp_flags_p_collecting;
static int hf_lacp_flags_p_distrib;
static int hf_lacp_flags_p_defaulted;
static int hf_lacp_flags_p_expired;
static int hf_lacp_partner_reserved;

static int hf_lacp_coll_max_delay;
static int hf_lacp_coll_reserved;

static int hf_lacp_pad;

static int hf_lacp_vendor;

static int hf_lacp_vendor_hp_length;
static int hf_lacp_vendor_hp_irf_domain;
static int hf_lacp_vendor_hp_irf_mac;
static int hf_lacp_vendor_hp_irf_switch;
static int hf_lacp_vendor_hp_irf_port;
static int hf_lacp_vendor_hp_unknown;


/* Initialise the subtree pointers */
static int ett_lacp;
static int ett_lacp_a_flags;
static int ett_lacp_p_flags;

/* Expert Items */
static expert_field ei_lacp_wrong_tlv_type;
static expert_field ei_lacp_wrong_tlv_length;

static const true_false_string tfs_active_passive = { "Active", "Passive" };
static const true_false_string tfs_short_long_timeout = { "Short Timeout", "Long Timeout" };
static const true_false_string tfs_aggregatable_individual = { "Aggregatable", "Individual" };
static const true_false_string tfs_in_sync_out_sync = { "In Sync", "Out of Sync" };

static const char * lacp_state_flags_to_str(wmem_allocator_t *scope, uint32_t value)
{
    wmem_strbuf_t *buf = wmem_strbuf_new(scope, "");
    const unsigned int flags_count = 8;
    static const char first_letters[] = "EFDCSGSA";
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
    unsigned     tlv_type, tlv_length;
    unsigned     version, port, key;
    const char   *sysidstr, *flagstr;
    uint32_t     protodetect;
    uint8_t      is_vlacp;

    proto_tree *lacp_tree;
    proto_item *lacp_item, *tlv_type_item, *tlv_length_item;
    proto_item *ti;

    static int * const actor_flags[] = {
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
    static int * const partner_flags[] = {
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

    /* FIXME
     * Validate that the destination MAC address is one of the following
     * (IEEE 802.1AX-2014 6.2.11.2):
     * 01-80-C2-00-00-00: Nearest Customer Bridge group address
     * 01-80-C2-00-00-02: IEEE 802.3 Slow_Protocols_Mulitcast group address
     * 01-80-C2-00-00-03: Nearest non-TPMR Bridge group address
     */

    protodetect = tvb_get_ntohl(tvb, 0);
    if ((protodetect == VLACP_MAGIC_LACP) || (protodetect == VLACP_MAGIC_MARKER)) {
      is_vlacp = 1;
      /* Add vLACP Heading */
      lacp_item = proto_tree_add_protocol_format(tree, proto_lacp, tvb,
                                                 0, -1, "Virtual Link Aggregation Control Protocol");
    } else {
      is_vlacp = 0;
      /* Add LACP Heading - Note: 1 byte for slowprotocol has been consumed already */
      lacp_item = proto_tree_add_protocol_format(tree, proto_lacp, tvb,
                                                 0, -1, "Link Aggregation Control Protocol");
    }
    lacp_tree = proto_item_add_subtree(lacp_item, ett_lacp);

    if (is_vlacp == 1) {
      proto_tree_add_item(lacp_tree, hf_lacp_vlacp_subtype, tvb, offset, 1, ENC_NA);
      offset += 1;
    }

    /* Version Number */

    proto_tree_add_item_ret_uint(lacp_tree, hf_lacp_version, tvb, offset, 1, ENC_NA, &version);
    offset += 1;

    col_add_fstr(pinfo->cinfo, COL_INFO, "v%d", version);

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

    proto_tree_add_item(lacp_tree, hf_lacp_actor_sysid_priority, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(lacp_tree, hf_lacp_actor_sysid, tvb, offset, 6, ENC_NA);
    sysidstr = tvb_ether_to_str(pinfo->pool, tvb, offset);
    offset += 6;

    proto_tree_add_item_ret_uint(lacp_tree, hf_lacp_actor_key, tvb, offset, 2, ENC_BIG_ENDIAN, &key);
    offset += 2;

    proto_tree_add_item(lacp_tree, hf_lacp_actor_port_priority, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item_ret_uint(lacp_tree, hf_lacp_actor_port, tvb, offset, 2, ENC_BIG_ENDIAN, &port);
    offset += 2;

    proto_tree_add_bitmask_with_flags(lacp_tree, tvb, offset, hf_lacp_actor_state,
                           ett_lacp_a_flags, actor_flags, ENC_NA, BMT_NO_INT|BMT_NO_TFS|BMT_NO_FALSE);
    flagstr = lacp_state_flags_to_str(pinfo->pool, tvb_get_uint8(tvb, offset));
    ti = proto_tree_add_string(lacp_tree, hf_lacp_actor_state_str, tvb, offset, 1, flagstr);
    proto_item_set_generated(ti);
    offset += 1;

    proto_tree_add_item(lacp_tree, hf_lacp_actor_reserved, tvb, offset, 3, ENC_NA);
    offset += 3;

    col_append_fstr(pinfo->cinfo, COL_INFO, " ACTOR %s P: %d K: %d %s", sysidstr, port, key, flagstr);

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

    proto_tree_add_item(lacp_tree, hf_lacp_partner_sysid_priority, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(lacp_tree, hf_lacp_partner_sysid, tvb, offset, 6, ENC_NA);
    sysidstr = tvb_ether_to_str(pinfo->pool, tvb, offset);
    offset += 6;

    proto_tree_add_item_ret_uint(lacp_tree, hf_lacp_partner_key, tvb, offset, 2, ENC_BIG_ENDIAN, &key);
    offset += 2;

    proto_tree_add_item(lacp_tree, hf_lacp_partner_port_priority, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item_ret_uint(lacp_tree, hf_lacp_partner_port, tvb, offset, 2, ENC_BIG_ENDIAN, &port);
    offset += 2;

    proto_tree_add_bitmask_with_flags(lacp_tree, tvb, offset, hf_lacp_partner_state, ett_lacp_p_flags, partner_flags, ENC_NA, BMT_NO_INT|BMT_NO_TFS|BMT_NO_FALSE);
    flagstr = lacp_state_flags_to_str(pinfo->pool, tvb_get_uint8(tvb, offset));
    ti = proto_tree_add_string(lacp_tree, hf_lacp_partner_state_str, tvb, offset, 1, flagstr);
    proto_item_set_generated(ti);
    offset += 1;

    proto_tree_add_item(lacp_tree, hf_lacp_partner_reserved, tvb, offset, 3, ENC_NA);
    offset += 3;

    col_append_fstr(pinfo->cinfo, COL_INFO, " PARTNER %s P: %d K: %d %s", sysidstr, port, key, flagstr);

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

    /* col_append_fstr(pinfo->cinfo, COL_INFO, " COLLECTOR"); */

    /* Other TLVs (LACP version 2) */

    proto_tree_add_item_ret_uint(lacp_tree, hf_lacp_tlv_type, tvb, offset, 1, ENC_BIG_ENDIAN, &tlv_type);
    offset += 1;

    tlv_length_item = proto_tree_add_item_ret_uint(lacp_tree, hf_lacp_tlv_length, tvb, offset, 1, ENC_BIG_ENDIAN, &tlv_length);
    offset += 1;

    while (tlv_type != LACPDU_TYPE_TERMINATOR && tlv_length >= 2) {
        offset += (tlv_length - 2);
        proto_tree_add_item_ret_uint(lacp_tree, hf_lacp_tlv_type, tvb, offset, 1, ENC_BIG_ENDIAN, &tlv_type);
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

        /* HP LACP MAD IRF, first bytes is always 0x64 and second bytes is the rest of length */
        if (length_remaining > 2 && (tvb_get_uint8(tvb, offset) == 0x64) && ((length_remaining -2) == tvb_get_uint8(tvb, offset+1)) )
        {
            proto_tree_add_item(lacp_tree, hf_lacp_vendor, tvb, offset, length_remaining, ENC_NA);
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
        } else {
            /* Not the HP specific extras.  Don't claim the remaining data.  It may actually be an ethernet trailer. */
            set_actual_length(tvb, tvb_captured_length(tvb) - length_remaining);
            proto_item_set_len(lacp_item, tvb_captured_length(tvb));
        }
    }
    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void
proto_register_lacp(void)
{
/* Setup list of header fields */

    static hf_register_info hf[] = {
        { &hf_lacp_vlacp_subtype,
          { "vLACP subtype",          "lacp.vlacp_subtype",
            FT_UINT8,    BASE_DEC,    NULL,    0x0,
            "Avaya vlacp unused lacp subtype byte", HFILL }},

        { &hf_lacp_version,
          { "LACP Version",          "lacp.version",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_lacp_tlv_type,
          { "TLV Type",               "lacp.tlv_type",
            FT_UINT8,    BASE_HEX,    VALS(lacp_type_vals),    0x0,
            NULL, HFILL }},

        { &hf_lacp_tlv_length,
          { "TLV Length",             "lacp.tlv_length",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_lacp_actor_sysid_priority,
          { "Actor System Priority",  "lacp.actor.sys_priority",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_lacp_actor_sysid,
          { "Actor System ID",         "lacp.actor.sysid",
            FT_ETHER,    BASE_NONE,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_lacp_actor_key,
          { "Actor Key",            "lacp.actor.key",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_lacp_actor_port_priority,
          { "Actor Port Priority",            "lacp.actor.port_priority",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_lacp_actor_port,
          { "Actor Port",            "lacp.actor.port",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_lacp_actor_state,
          { "Actor State",            "lacp.actor.state",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_lacp_actor_state_str,
          { "Actor State Flags",            "lacp.actor.state_str",
            FT_STRING,    BASE_NONE,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_lacp_flags_a_activity,
          { "LACP Activity",        "lacp.actor.state.activity",
            FT_BOOLEAN,    8,        TFS(&tfs_active_passive),    LACPDU_FLAGS_ACTIVITY,
            NULL, HFILL }},

        { &hf_lacp_flags_a_timeout,
          { "LACP Timeout",        "lacp.actor.state.timeout",
            FT_BOOLEAN,    8,        TFS(&tfs_short_long_timeout),    LACPDU_FLAGS_TIMEOUT,
            NULL, HFILL }},

        { &hf_lacp_flags_a_aggregation,
          { "Aggregation",        "lacp.actor.state.aggregation",
            FT_BOOLEAN,    8,        TFS(&tfs_aggregatable_individual),    LACPDU_FLAGS_AGGREGATION,
            NULL, HFILL }},

        { &hf_lacp_flags_a_sync,
          { "Synchronization",        "lacp.actor.state.synchronization",
            FT_BOOLEAN,    8,        TFS(&tfs_in_sync_out_sync),    LACPDU_FLAGS_SYNC,
            NULL, HFILL }},

        { &hf_lacp_flags_a_collecting,
          { "Collecting",        "lacp.actor.state.collecting",
            FT_BOOLEAN,    8,        TFS(&tfs_enabled_disabled),    LACPDU_FLAGS_COLLECTING,
            NULL, HFILL }},

        { &hf_lacp_flags_a_distrib,
          { "Distributing",        "lacp.actor.state.distributing",
            FT_BOOLEAN,    8,        TFS(&tfs_enabled_disabled),    LACPDU_FLAGS_DISTRIB,
            NULL, HFILL }},

        { &hf_lacp_flags_a_defaulted,
          { "Defaulted",        "lacp.actor.state.defaulted",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    LACPDU_FLAGS_DEFAULTED,
            "1 = Actor Rx machine is using DEFAULT Partner info, 0 = using info in Rx'd LACPDU", HFILL }},

        { &hf_lacp_flags_a_expired,
          { "Expired",        "lacp.actor.state.expired",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    LACPDU_FLAGS_EXPIRED,
            NULL, HFILL }},

        { &hf_lacp_actor_reserved,
          { "Reserved",        "lacp.actor.reserved",
            FT_BYTES,    BASE_NONE,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_lacp_partner_sysid_priority,
          { "Partner System Priority",  "lacp.partner.sys_priority",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_lacp_partner_sysid,
          { "Partner System",            "lacp.partner.sysid",
            FT_ETHER,    BASE_NONE,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_lacp_partner_key,
          { "Partner Key",            "lacp.partner.key",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_lacp_partner_port_priority,
          { "Partner Port Priority",            "lacp.partner.port_priority",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_lacp_partner_port,
          { "Partner Port",            "lacp.partner.port",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "The port number associated with this link assigned to the port by the Partner (via Management or Admin)", HFILL }},

        { &hf_lacp_partner_state,
          { "Partner State",            "lacp.partner.state",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_lacp_partner_state_str,
          { "Partner State Flags",            "lacp.partner.state_str",
            FT_STRING,    BASE_NONE,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_lacp_flags_p_activity,
          { "LACP Activity",        "lacp.partner.state.activity",
            FT_BOOLEAN,    8,        TFS(&tfs_active_passive),    LACPDU_FLAGS_ACTIVITY,
            NULL, HFILL }},

        { &hf_lacp_flags_p_timeout,
          { "LACP Timeout",        "lacp.partner.state.timeout",
            FT_BOOLEAN,    8,        TFS(&tfs_short_long_timeout),    LACPDU_FLAGS_TIMEOUT,
            NULL, HFILL }},

        { &hf_lacp_flags_p_aggregation,
          { "Aggregation",        "lacp.partner.state.aggregation",
            FT_BOOLEAN,    8,        TFS(&tfs_aggregatable_individual),    LACPDU_FLAGS_AGGREGATION,
            NULL, HFILL }},

        { &hf_lacp_flags_p_sync,
          { "Synchronization",        "lacp.partner.state.synchronization",
            FT_BOOLEAN,    8,        TFS(&tfs_in_sync_out_sync),    LACPDU_FLAGS_SYNC,
            NULL, HFILL }},

        { &hf_lacp_flags_p_collecting,
          { "Collecting",        "lacp.partner.state.collecting",
            FT_BOOLEAN,    8,        TFS(&tfs_enabled_disabled),    LACPDU_FLAGS_COLLECTING,
            NULL, HFILL }},

        { &hf_lacp_flags_p_distrib,
          { "Distributing",        "lacp.partner.state.distributing",
            FT_BOOLEAN,    8,        TFS(&tfs_enabled_disabled),    LACPDU_FLAGS_DISTRIB,
            NULL, HFILL }},

        { &hf_lacp_flags_p_defaulted,
          { "Defaulted",        "lacp.partner.state.defaulted",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    LACPDU_FLAGS_DEFAULTED,
            "1 = Actor Rx machine is using DEFAULT Partner info, 0 = using info in Rx'd LACPDU", HFILL }},

        { &hf_lacp_flags_p_expired,
          { "Expired",        "lacp.partner.state.expired",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    LACPDU_FLAGS_EXPIRED,
            NULL, HFILL }},

        { &hf_lacp_partner_reserved,
          { "Reserved",        "lacp.partner.reserved",
            FT_BYTES,    BASE_NONE,    NULL,    0x0,
            NULL, HFILL }},

        { &hf_lacp_coll_max_delay,
          { "Collector Max Delay",  "lacp.collector.max_delay",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            "The max delay of the station sending the LACPDU (in tens of usecs)", HFILL }},

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

    static int *ett[] = {
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

    lacp_handle = register_dissector("lacp", dissect_lacp, proto_lacp);
}

void
proto_reg_handoff_lacp(void)
{
    dissector_add_uint("slow.subtype", LACP_SUBTYPE, lacp_handle);
    dissector_add_uint("ethertype", ETHERTYPE_VLACP, lacp_handle);
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

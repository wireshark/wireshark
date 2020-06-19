/* packet-ncsi.c
 * Routines for NCSI dissection
 * Copyright 2017-2019, Jeremy Kerr <jk@ozlabs.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Network Controller Sideband Interface (NCSI) protocol support.
 * Specs at http://www.dmtf.org/sites/default/files/standards/documents/DSP0222_1.0.1.pdf
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/etypes.h>

void proto_reg_handoff_ncsi(void);
void proto_register_ncsi(void);

static int proto_ncsi = -1;

/* Common header fields */
static int hf_ncsi_mc_id = -1;
static int hf_ncsi_revision = -1;
static int hf_ncsi_iid = -1;
static int hf_ncsi_type = -1;
static int hf_ncsi_type_code = -1;
static int hf_ncsi_type_resp = -1;
static int hf_ncsi_chan = -1;
static int hf_ncsi_plen = -1;

/* Response generics */
static int hf_ncsi_resp = -1;
static int hf_ncsi_reason = -1;

/* Select package */
static int hf_ncsi_sp_hwarb = -1;

/* Disable channel */
static int hf_ncsi_dc_ald = -1;

/* AEN enable */
static int hf_ncsi_aene_mc = -1;

/* Set MAC Address */
static int hf_ncsi_sm_mac = -1;
static int hf_ncsi_sm_macno = -1;
static int hf_ncsi_sm_at = -1;
static int hf_ncsi_sm_e = -1;

/* Broadcast filter */
static int hf_ncsi_bf = -1;
static int hf_ncsi_bf_arp = -1;
static int hf_ncsi_bf_dhcpc = -1;
static int hf_ncsi_bf_dhcps = -1;
static int hf_ncsi_bf_netbios = -1;

/* AEN payload fields */
static int hf_ncsi_aen_type = -1;
static int hf_ncsi_aen_lsc_stat = -1;
static int hf_ncsi_aen_lsc_oemstat = -1;
static int hf_ncsi_aen_lsc_hcstat = -1;

/* generic link status */
static int hf_ncsi_lstat = -1;
static int hf_ncsi_lstat_flag = -1;
static int hf_ncsi_lstat_speed_duplex = -1;
static int hf_ncsi_lstat_autoneg = -1;
static int hf_ncsi_lstat_autoneg_complete = -1;
static int hf_ncsi_lstat_parallel_detection = -1;
static int hf_ncsi_lstat_1000TFD = -1;
static int hf_ncsi_lstat_1000THD = -1;
static int hf_ncsi_lstat_100T4 = -1;
static int hf_ncsi_lstat_100TXFD = -1;
static int hf_ncsi_lstat_100TXHD = -1;
static int hf_ncsi_lstat_10TFD = -1;
static int hf_ncsi_lstat_10THD = -1;
static int hf_ncsi_lstat_tx_flow = -1;
static int hf_ncsi_lstat_rx_flow = -1;
static int hf_ncsi_lstat_partner_flow = -1;
static int hf_ncsi_lstat_serdes = -1;
static int hf_ncsi_lstat_oem_speed_valid = -1;

static gint ett_ncsi = -1;
static gint ett_ncsi_type = -1;
static gint ett_ncsi_payload = -1;
static gint ett_ncsi_lstat = -1;

#define NCSI_MIN_LENGTH 8

enum ncsi_type {
    NCSI_TYPE_GLS = 0x0a,
    NCSI_TYPE_AEN = 0x7f,
};

static const value_string ncsi_type_vals[] = {
    { 0x00,		"Clear initial state" },
    { 0x01,		"Select package" },
    { 0x02,		"Deselect package" },
    { 0x03,		"Enable channel" },
    { 0x04,		"Disable channel" },
    { 0x05,		"Reset channel" },
    { 0x06,		"Enable channel TX" },
    { 0x07,		"Disable channel TX" },
    { 0x08,		"AEN enable" },
    { NCSI_TYPE_GLS,	"Get link status" },
    { 0x0d,		"Disable VLAN" },
    { 0x0e,		"Set MAC address" },
    { 0x10,		"Enable broadcast filter" },
    { 0x11,		"Disable broadcast filter" },
    { NCSI_TYPE_AEN,	"Async Event Notification" },
    { 0, NULL },
};

static const value_string ncsi_type_resp_vals[] = {
    { 0x00,	"request" },
    { 0x01,	"response" },
    { 0, NULL },
};

static const value_string ncsi_aen_type_vals[] = {
    { 0x00,	"Link status change" },
    { 0x01,	"Configuration required" },
    { 0x02,	"Host NC driver status change" },
    { 0, NULL },
};

static const value_string ncsi_lstat_flag_vals[] = {
    { 0x00, "Link down" },
    { 0x01, "Link up" },
    { 0, NULL },
};

static const value_string ncsi_lstat_speed_duplex_vals[] = {
    { 0x00, "Auto-negotiate not complete" },
    { 0x01, "10BaseT half duplex" },
    { 0x02, "10BaseT full duplex" },
    { 0x03, "100BaseT half duplex" },
    { 0x04, "100BaseT4" },
    { 0x05, "100BaseTX full duplex" },
    { 0x06, "1000BaseT half duplex" },
    { 0x07, "1000BaseT full duplex" },
    { 0x08, "10GBaseT support" },
    { 0, NULL },
};

static const value_string ncsi_enable_vals[] = {
    { 0x00, "disabled" },
    { 0x01, "enabled" },
    { 0, NULL },
};

static const value_string ncsi_valid_vals[] = {
    { 0x00, "invalid" },
    { 0x01, "valid" },
    { 0, NULL },
};

static const value_string ncsi_autoneg_complete_vals[] = {
    { 0x00, "disabled/in-progress" },
    { 0x01, "complete" },
    { 0, NULL },
};

static const value_string ncsi_partner_flow_vals[] = {
    { 0x00, "Not pause capable" },
    { 0x01, "Symmetric pause" },
    { 0x02, "Assymmetric pause" },
    { 0x03, "Symmetric & Assymetric pause" },
    { 0, NULL },
};

static const value_string ncsi_used_vals[] = {
    { 0x00, "unused" },
    { 0x01, "used" },
    { 0, NULL },
};

static const value_string ncsi_capable_vals[] = {
    { 0x00, "not capable" },
    { 0x01, "capable" },
    { 0, NULL },
};

static const value_string ncsi_aen_hcstat_vals[] = {
    { 0x00, "not running" },
    { 0x01, "running" },
    { 0, NULL },
};

static const value_string ncsi_sm_at_vals[] = {
    { 0x00, "unicast" },
    { 0x01, "multicast" },
    { 0, NULL },
};

static const value_string ncsi_bf_filter_vals[] = {
    { 0x00, "drop" },
    { 0x01, "forward" },
    { 0, NULL },
};


static void
ncsi_proto_tree_add_lstat(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    static int * const lstat_fields[] = {
        &hf_ncsi_lstat_flag,
        &hf_ncsi_lstat_speed_duplex,
        &hf_ncsi_lstat_autoneg,
        &hf_ncsi_lstat_autoneg_complete,
        &hf_ncsi_lstat_parallel_detection,
        &hf_ncsi_lstat_1000TFD,
        &hf_ncsi_lstat_1000THD,
        &hf_ncsi_lstat_100T4,
        &hf_ncsi_lstat_100TXFD,
        &hf_ncsi_lstat_100TXHD,
        &hf_ncsi_lstat_10TFD,
        &hf_ncsi_lstat_10THD,
        &hf_ncsi_lstat_tx_flow,
        &hf_ncsi_lstat_rx_flow,
        &hf_ncsi_lstat_partner_flow,
        &hf_ncsi_lstat_serdes,
        &hf_ncsi_lstat_oem_speed_valid,
        NULL,
    };

    proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_ncsi_lstat,
            ett_ncsi_lstat, lstat_fields, ENC_BIG_ENDIAN, BMT_NO_APPEND);
}

static void
dissect_ncsi_aen(tvbuff_t *tvb, proto_tree *tree)
{
    guint8 type = tvb_get_guint8(tvb, 19);

    proto_tree_add_item(tree, hf_ncsi_aen_type, tvb, 19, 1, ENC_NA);

    switch (type) {
    case 0x00:
        ncsi_proto_tree_add_lstat(tvb, tree, 20);
        proto_tree_add_item(tree, hf_ncsi_aen_lsc_oemstat, tvb, 24, 4, ENC_NA);
        break;
    case 0x02:
        proto_tree_add_item(tree, hf_ncsi_aen_lsc_hcstat, tvb, 20, 4, ENC_NA);
        break;
    }
}

/* Code to actually dissect the packets */
static int
dissect_ncsi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_tree *ncsi_tree, *ncsi_payload_tree;
    proto_item *ti, *pti;
    guint8 type, plen;
    static int * const type_fields[] = {
        &hf_ncsi_type_code,
        &hf_ncsi_type_resp,
        NULL,
    };

    /* Check that the packet is long enough for it to belong to us. */
    if (tvb_reported_length(tvb) < NCSI_MIN_LENGTH)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NCSI");

    type = tvb_get_guint8(tvb, 4);
    plen = tvb_get_guint8(tvb, 7);

    col_clear(pinfo->cinfo, COL_INFO);
    if (type == 0xff) {
        col_add_fstr(pinfo->cinfo, COL_INFO,
                "Async Event Notification, chan %x",
                tvb_get_guint8(tvb, 5));
    } else {
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s, id %x, chan %x",
                val_to_str(type & 0x7f, ncsi_type_vals, "Unknown type %x"),
                type & 0x80 ? "response" : "request ",
                tvb_get_guint8(tvb, 3),
                tvb_get_guint8(tvb, 5));
    }


    /* Top-level NCSI protocol item & tree */
    ti = proto_tree_add_item(tree, proto_ncsi, tvb, 0, -1, ENC_NA);

    ncsi_tree = proto_item_add_subtree(ti, ett_ncsi);

    /* Standard header fields */
    proto_tree_add_item(ncsi_tree, hf_ncsi_mc_id, tvb, 0, 1, ENC_NA);
    proto_tree_add_item(ncsi_tree, hf_ncsi_revision, tvb, 1, 1, ENC_NA);
    proto_tree_add_item(ncsi_tree, hf_ncsi_iid, tvb, 3, 1, ENC_NA);
    proto_tree_add_bitmask(ncsi_tree, tvb, 4, hf_ncsi_type,
            ett_ncsi_type, type_fields, ENC_NA);
    proto_tree_add_item(ncsi_tree, hf_ncsi_chan, tvb, 5, 1, ENC_NA);
    proto_tree_add_item(ncsi_tree, hf_ncsi_plen, tvb, 7, 1, ENC_NA);

    if (!plen)
        return 16;

    /* Payload tree */
    ncsi_payload_tree = proto_tree_add_subtree(ncsi_tree, tvb, 16,
            plen, ett_ncsi_payload, &pti, "Payload");

    /* All responses start with response code & reason data */
    if (type & 0x80) {
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_resp, tvb,
                16, 2, ENC_NA);
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_reason, tvb,
                18, 2, ENC_NA);
    }

    switch (type) {
    case 0x01:
        proto_item_set_text(pti, "Select package request");
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_sp_hwarb, tvb,
                19, 1, ENC_NA);
        break;
    case 0x04:
        proto_item_set_text(pti, "Disable channel request");
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_dc_ald, tvb,
                19, 1, ENC_NA);
        break;
    case 0x08:
        proto_item_set_text(pti, "AEN enable request");
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_aene_mc, tvb,
                19, 1, ENC_NA);
        break;
    case 0x0e:
        proto_item_set_text(pti, "Set MAC address request");
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_sm_mac, tvb,
                16, 6, ENC_NA);
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_sm_macno, tvb,
                22, 1, ENC_NA);
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_sm_at, tvb,
                23, 1, ENC_NA);
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_sm_e, tvb,
                23, 1, ENC_NA);
        break;
    case 0x10:
        proto_item_set_text(pti, "Enable broadcast filter request");
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_bf, tvb,
                16, 4, ENC_NA);
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_bf_arp, tvb,
                16, 4, ENC_NA);
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_bf_dhcpc, tvb,
                16, 4, ENC_NA);
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_bf_dhcps, tvb,
                16, 4, ENC_NA);
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_bf_netbios, tvb,
                16, 4, ENC_NA);
        break;
    case NCSI_TYPE_GLS | 0x80:
        proto_item_set_text(pti, "Get Link Status response");
        ncsi_proto_tree_add_lstat(tvb, ncsi_payload_tree, 20);
        break;
    case NCSI_TYPE_AEN | 0x80:
        proto_item_set_text(pti, "AEN payload");
        dissect_ncsi_aen(tvb, ncsi_payload_tree);
        break;
    }

    return tvb_captured_length(tvb);
}

void
proto_register_ncsi(void)
{
    /* Field definitions */
    static hf_register_info hf[] = {
        { &hf_ncsi_mc_id,
          { "MC ID", "ncsi.mc_id",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Management controller ID", HFILL },
        },
        { &hf_ncsi_revision,
          { "Revision", "ncsi.revision",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Header revision", HFILL },
        },
        { &hf_ncsi_iid,
          { "IID", "ncsi.iid",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Instance ID", HFILL },
        },
        { &hf_ncsi_type,
          { "Type", "ncsi.type",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Packet type", HFILL },
        },
        { &hf_ncsi_type_code,
          { "Type code", "ncsi.type.code",
            FT_UINT8, BASE_HEX, VALS(ncsi_type_vals), 0x7f,
            "Packet type code", HFILL },
        },
        { &hf_ncsi_type_resp,
          { "Type req/resp", "ncsi.type.resp",
            FT_UINT8, BASE_HEX, VALS(ncsi_type_resp_vals), 0x80,
            "Packet type request/response", HFILL },
        },
        { &hf_ncsi_chan,
          { "Channel", "ncsi.chan",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "NCSI Channel", HFILL },
        },
        { &hf_ncsi_plen,
          { "Payload Length", "ncsi.plen",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_resp,
          { "Response", "ncsi.resp",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Response code", HFILL },
        },
        { &hf_ncsi_reason,
          { "Reason", "ncsi.reason",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Reason code", HFILL },
        },
        { &hf_ncsi_sp_hwarb,
          { "Hardware arbitration disable", "ncsi.sp.hwarb",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_dc_ald,
          { "Allow link down", "ncsi.dc.ald",
            FT_UINT8, BASE_HEX, NULL, 0x1,
            NULL, HFILL },
        },
        { &hf_ncsi_aene_mc,
          { "Management controller ID", "ncsi.aene.mc",
            FT_UINT8, BASE_HEX, NULL, 0x1,
            NULL, HFILL },
        },
        { &hf_ncsi_sm_mac,
          { "MAC address", "ncsi.sm.mac",
            FT_ETHER, BASE_NONE, NULL, 0,
            NULL, HFILL },
        },
        { &hf_ncsi_sm_macno,
          { "MAC address number", "ncsi.sm.macno",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_ncsi_sm_at,
          { "Address type", "ncsi.sm.at",
            FT_UINT8, BASE_HEX, VALS(ncsi_sm_at_vals), 0xe0,
            NULL, HFILL },
        },
        { &hf_ncsi_sm_e,
          { "Enabled", "ncsi.sm.e",
            FT_UINT8, BASE_HEX, VALS(ncsi_enable_vals), 0x1,
            NULL, HFILL },
        },

        { &hf_ncsi_aen_type,
          { "AEN type", "ncsi.aen_type",
            FT_UINT8, BASE_HEX, VALS(ncsi_aen_type_vals), 0xff,
            NULL, HFILL },
        },
        { &hf_ncsi_aen_lsc_stat,
          { "AEN link status", "ncsi.aen_lsc_stat",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_aen_lsc_oemstat,
          { "AEN link OEM status", "ncsi.aen_lsc_oemstat",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_aen_lsc_hcstat,
          { "AEN link HC status", "ncsi.aen_lsc_hcstat",
            FT_UINT8, BASE_HEX, VALS(ncsi_aen_hcstat_vals), 0x0,
            "AEN link host controller status", HFILL },
        },
        /* Broadcast filter */
        { &hf_ncsi_bf,
          { "Broadcast filter settings", "ncsi.bf.settings",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_bf_arp,
          { "ARP", "ncsi.bf.settings.arp",
            FT_UINT32, BASE_HEX, VALS(ncsi_bf_filter_vals), 1 << 0,
            NULL, HFILL },
        },
        { &hf_ncsi_bf_dhcpc,
          { "DHCP Client", "ncsi.bf.settings.dhcpc",
            FT_UINT32, BASE_HEX, VALS(ncsi_bf_filter_vals), 1 << 1,
            NULL, HFILL },
        },
        { &hf_ncsi_bf_dhcps,
          { "DHCP Server", "ncsi.bf.settings.dhcps",
            FT_UINT32, BASE_HEX, VALS(ncsi_bf_filter_vals), 1 << 2,
            NULL, HFILL },
        },
        { &hf_ncsi_bf_netbios,
          { "NetBIOS", "ncsi.bf.settings.netbios",
            FT_UINT32, BASE_HEX, VALS(ncsi_bf_filter_vals), 1 << 3,
            NULL, HFILL },
        },

        /* generic link status */
        { &hf_ncsi_lstat,
          { "Link status", "ncsi.lstat",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_lstat_flag,
          { "Link flag", "ncsi.lstat.flag",
            FT_UINT32, BASE_HEX, VALS(ncsi_lstat_flag_vals), 0x1,
            NULL, HFILL },
        },
        { &hf_ncsi_lstat_speed_duplex,
          { "Speed & duplex", "ncsi.lstat.speed_duplex",
            FT_UINT32, BASE_HEX, VALS(ncsi_lstat_speed_duplex_vals), 0x1e,
            NULL, HFILL },
        },
        { &hf_ncsi_lstat_autoneg,
          { "Autonegotiation", "ncsi.lstat.autoneg",
            FT_UINT32, BASE_HEX, VALS(ncsi_enable_vals), 1<<5,
            NULL, HFILL },
        },
        { &hf_ncsi_lstat_autoneg_complete,
          { "Autonegotiation complete", "ncsi.lstat.autoneg_complete",
            FT_UINT32, BASE_HEX, VALS(ncsi_autoneg_complete_vals), 1<<6,
            NULL, HFILL },
        },
        { &hf_ncsi_lstat_parallel_detection,
          { "Parallel detection", "ncsi.lstat.parallel_detection",
            FT_UINT32, BASE_HEX, VALS(ncsi_used_vals), 1<<7,
            NULL, HFILL },
        },
        { &hf_ncsi_lstat_1000TFD,
          { "1000TFD", "ncsi.lstat.1000tfd",
            FT_UINT32, BASE_HEX, VALS(ncsi_capable_vals), 1<<9,
            "Partner advertised 1000TFD", HFILL },
        },
        { &hf_ncsi_lstat_1000THD,
          { "1000THD", "ncsi.lstat.1000thd",
            FT_UINT32, BASE_HEX, VALS(ncsi_capable_vals), 1<<10,
            "Partner advertised 1000THD", HFILL },
        },
        { &hf_ncsi_lstat_100T4,
          { "100T4", "ncsi.lstat.100t4",
            FT_UINT32, BASE_HEX, VALS(ncsi_capable_vals), 1<<11,
            "Partner advertised 100T4", HFILL },
        },
        { &hf_ncsi_lstat_100TXFD,
          { "100TXFD", "ncsi.lstat.100txfd",
            FT_UINT32, BASE_HEX, VALS(ncsi_capable_vals), 1<<12,
            "Partner advertised 100TXFD", HFILL },
        },
        { &hf_ncsi_lstat_100TXHD,
          { "100TXHD", "ncsi.lstat.100txhd",
            FT_UINT32, BASE_HEX, VALS(ncsi_capable_vals), 1<<13,
            "Partner advertised 100TXHD", HFILL },
        },
        { &hf_ncsi_lstat_10TFD,
          { "10TFD", "ncsi.lstat.10tfd",
            FT_UINT32, BASE_HEX, VALS(ncsi_capable_vals), 1<<14,
            "Partner advertised 10TFD", HFILL },
        },
        { &hf_ncsi_lstat_10THD,
          { "10THD", "ncsi.lstat.10thd",
            FT_UINT32, BASE_HEX, VALS(ncsi_capable_vals), 1<<15,
            "Partner advertised 10THD", HFILL },
        },
        { &hf_ncsi_lstat_tx_flow,
          { "TX flow", "ncsi.lstat.tx_flow",
            FT_UINT32, BASE_HEX, VALS(ncsi_enable_vals), 1<<16,
            "TX flow control", HFILL },
        },
        { &hf_ncsi_lstat_rx_flow,
          { "RX flow", "ncsi.lstat.rx_flow",
            FT_UINT32, BASE_HEX, VALS(ncsi_enable_vals), 1<<17,
            "RX flow control", HFILL },
        },
        { &hf_ncsi_lstat_partner_flow,
          { "Partner flow", "ncsi.lstat.partner_flow",
            FT_UINT32, BASE_HEX, VALS(ncsi_partner_flow_vals), 3<<18,
            "Partner-advertised flow control", HFILL },
        },
        { &hf_ncsi_lstat_serdes,
          { "SerDes", "ncsi.lstat.serdes",
            FT_UINT32, BASE_HEX, VALS(ncsi_used_vals), 1<<20,
            NULL, HFILL },
        },
        { &hf_ncsi_lstat_oem_speed_valid,
          { "OEM Speed", "ncsi.lstat.oem_speed_valid",
            FT_UINT32, BASE_HEX, VALS(ncsi_valid_vals), 1<<21,
            NULL, HFILL },
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_ncsi,
        &ett_ncsi_type,
        &ett_ncsi_payload,
        &ett_ncsi_lstat,
    };

    /* Register the protocol name and description */
    proto_ncsi = proto_register_protocol("NCSI", "NCSI", "ncsi");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_ncsi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ncsi(void)
{
    dissector_handle_t ncsi_handle;
    ncsi_handle = create_dissector_handle(dissect_ncsi, proto_ncsi);
    dissector_add_uint("ethertype", ETHERTYPE_NCSI, ncsi_handle);
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

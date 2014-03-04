/* packet-pathport.c
 * Routines for Pathport Protocol dissection
 * Copyright 2014, Kevin Loewen <kloewen@pathwayconnect.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"
#include <glib.h>
#include <epan/packet.h>
#include <epan/to_str.h>


#define PATHPORT_UDP_PORT  3792
#define PATHPORT_MIN_LENGTH 24 /* HEADER + 1 PDU */
#define PATHPORT_PROTO_MAGIC  0xed01

#define PATHPORT_HEADER_OFFSET 0
#define PATHPORT_HEADER_SRCID_OFFSET (PATHPORT_HEADER_OFFSET + 12)

#define PATHPORT_HEADER_DSTID_OFFSET (PATHPORT_HEADER_OFFSET + 16)
#define PATHPORT_HEADER_LENGTH 20
#define PATHPORT_HEADER_END (PATHPORT_HEADER_OFFSET + PATHPORT_HEADER_LENGTH)

/** Rounds the specified integer up to the next multiple of four. */
#define roof4(a) (((a)+3)&~3)

void proto_reg_handoff_pathport(void);
void proto_register_pathport(void);

/* Initialize the protocol and registered fields */
static int proto_pathport = -1;

/* Initialize the subtree pointers */
static gint ett_pathport = -1;
static gint ett_pp_pdu = -1;
static gint ett_pp_tlv = -1;
static gint ett_pp_data = -1;

static int hf_pp_prot = -1;
static int hf_pp_reserved = -1;
static int hf_pp_version = -1;
static int hf_pp_seq = -1;
static int hf_pp_src = -1;
static int hf_pp_dst = -1;
static int hf_pp_data_encoding = -1;
static int hf_pp_data_len = -1;
static int hf_pp_data_start_code = -1;
static int hf_pp_data_dst = -1;
static int hf_pp_data_levels = -1;
static int hf_pp_arp_id = -1;
static int hf_pp_arp_manuf = -1;
static int hf_pp_arp_class = -1;
static int hf_pp_arp_type = -1;
static int hf_pp_arp_numdmx = -1;
static int hf_pp_arp_ip = -1;
static int hf_pp_get_type = -1;
static int hf_pp_pdu_type = -1;
static int hf_pp_pdu_len = -1;
static int hf_pp_pdu_payload = -1;
static int hf_pp_pid_type = -1;
static int hf_pp_pid_len = -1;
static int hf_pp_pid_value = -1;

/* Begin field and enum declarations */
enum
{
    PP_ID_BCAST        = 0xffffffff,
    PP_ID_MCAST_ALL    = 0xefffedff,
    PP_ID_MCAST_DATA   = 0xefffed01,
    PP_ID_MCAST_MANAGE = 0xefffed02
};

/* Top Level PDU Types */
enum
{
    PP_ARP_REQUEST = 0x0301,
    PP_ARP_REPLY   = 0x0302,
    PP_ARP_INFO    = 0x0303,
    PP_GET         = 0x0222,
    PP_GET_REPLY   = 0x0223,
    PP_DATA        = 0x0100,
    PP_SET         = 0x0400
};

static const value_string pp_pdu_vals[] = {
    {PP_ARP_REQUEST, "ARP Request"},
    {PP_ARP_REPLY,   "ARP Reply"},
    {PP_ARP_INFO,    "ARP Extend Info"},
    {PP_GET,         "Get"},
    {PP_GET_REPLY,   "Get Reply"},
    {PP_DATA,        "XDMX Data"},
    {PP_SET,         "Set"},
    {0, NULL}
};

/* XDMX Data Transport Encodings */
enum
{
    PP_DATA_FLAT    = 0x0101,
    PP_DATA_RELEASE = 0x0103
};

/** Data encoding strings. */
static const value_string pp_data_encoding_vals[] = {
    {PP_DATA_FLAT,    "Flat"},
    {PP_DATA_RELEASE, "Release"},
    {0, NULL}
};

/** ID strings. */
static const value_string ednet_id_vals[] = {
    {PP_ID_BCAST,        "Broadcast"},
    {PP_ID_MCAST_ALL,    "All"},
    {PP_ID_MCAST_DATA,   "Data"},
    {PP_ID_MCAST_MANAGE, "Manage"},
    {0, NULL}
};

/* Configuration Property IDs */
enum
    {
    PP_PAD                       = 0x0000,
    PP_NODE_NAME                 = 0x0401,
    PP_PORT_NAME                 = 0x0411,
    PP_PATCH_NAME                = 0x0412,
    PP_PORT_SPEED                = 0x0413,
    PP_IS_BIDIRECTIONAL          = 0x0414,
    PP_IS_PHYSICAL               = 0x0415,
    PP_IS_MALE                   = 0x0416,
    PP_IS_SINK                   = 0x0417,
    PP_XDMX_COUNT                = 0x0418,
    PP_ALT_START_CODE            = 0x041A,
    PP_MAX_PATCHES               = 0x041B,
    PP_NUM_PATCHES               = 0x041C,
    PP_TERMINATED                = 0x041E,
    PP_INPUT_PRIORITY            = 0x041F,
    PP_INPUT_PRIORITY_CHANNEL    = 0x0420,
    PP_MAC                       = 0x0421,
    PP_IP                        = 0x0422,
    PP_NETMASK                   = 0x0423,
    PP_ROUTER                    = 0x0424,
    PP_PP_ID                     = 0x0461,
    PP_PP_ID_MASK                = 0x0462,
    PP_PP_TX_DATA_DST            = 0x0463,
    PP_BACKLIGHT                 = 0x0481,
    PP_SW_VERSION                = 0x0482,
    PP_HW_TYPE                   = 0x0483,
    PP_LOADER_VERSION            = 0x0484,
    PP_IDENTIFY                  = 0x0485,
    PP_IRENABLE                  = 0x0486,
    PP_SERIAL                    = 0x0487,
    PP_KEYPAD_LOCKOUT            = 0x0488,
    PP_ARTNET_RX_ENABLE          = 0x0489,
    PP_TX_PROTOCOL               = 0x048a,
    PP_SHOWNET_RX_ENABLE         = 0x048b,
    PP_LED_INTENSITY             = 0x048c,
    PP_JUMPER_CONFIGURED         = 0x048d,
    PP_SACN_RX_ENABLE            = 0x048e,
    PP_NET2_RX_ENABLE            = 0x048f,
    PP_PATHPORT_RX_ENABLE        = 0x0490,
    PP_SACN_IS_DRAFT             = 0x0491,
    PP_REBOOT                    = 0x04a1,
    PP_BOOTORDER                 = 0x04a2,
    PP_FACTORY_DEFAULT           = 0x04a4,
    PP_TEST_LCD                  = 0x04c1,
    PP_IS_TERMINAL_BLOCK         = 0x04c2,
    PP_IS_RACK_MOUNTED           = 0x04c3,
    PP_IS_ENABLED                = 0x04c4,
    PP_IS_DMX_ACTIVE             = 0x04c5,
    PP_IS_XDMX_ACTIVE            = 0x04c6,
    PP_SIGNAL_LOSS_HOLD_TIME     = 0x04c7,
    PP_SIGNAL_LOSS_HOLD_FOREVER  = 0x04c8,
    PP_SIGNAL_LOSS_FADE_ENABLE   = 0x04c9,
    PP_SIGNAL_LOSS_FADE_TIME     = 0x04ca,
    PP_SIGNAL_LOSS_PORT_SHUTDOWN = 0x04cb,
    PP_NET2_ADMIN_MCAST          = 0x04ce,
    PP_NET2_DATA_MCAST           = 0x04cf,
    PP_ROOMS_FEATURES            = 0x04d0,
    PP_UNIVERSE_TEMP             = 0x04d1,
    PP_CROSSFADE_TIME            = 0x04d2,
    PP_CROSSFADE_ENABLE          = 0x04d3,
    PP_IGNORE_INPUT_PRI          = 0x04d4,
    PP_ARTNET_ALT_MAP            = 0x04d5,
    PP_PATCH_CRC                 = 0x04d6,
    PP_CONF_CHANGE               = 0x04d7,
    PP_PORT_ACTIVE_SUMMARY       = 0x04d8,
    PP_SUPPORTED_UNIV            = 0x04d9,
    PP_INPUT_HLL_TIME            = 0x04da,
    PP_PCP_ENABLE                = 0x04db,
    PP_INPUT_UNIVERSE            = 0x04dc,
    PP_MODEL_NAME                = 0x04dd,
    PP_MANUF_NAME                = 0x04de,
    PP_VER_STR                   = 0x04df,
    PP_SERIAL_STR                = 0x04e0,
    PP_NODE_NOTES                = 0x04e1,
    PP_PORT_NOTES                = 0x04e2,
    PP_USER_NODE_ID              = 0x04e3,
    PP_MDG_GEN_STATE             = 0x0601,
    PP_EMBEDDED_ID               = 0x0602,
    PP_SLAVE_DMX_START           = 0x0603,
    PP_TB_MODE                   = 0x0605,
    PP_LINK_MODE                 = 0x0701,
    PP_LINK_STATUS               = 0x0702,
    PP_CONNECTED_COUNT           = 0x0703,
    PP_POE_STATUS                = 0x0704,
    PP_POE_EXTERN_WATT           = 0x0705,
    PP_POE_CURRENT_WATT          = 0x0706,
    PP_SFP_MODULE_TYPE           = 0x0707,
    PP_POE_EXTERN_PRESENT        = 0x0708,
    PP_POE_CAPABLE               = 0x0709,
    PP_SWITCH_PORT_TYPE          = 0x070a,
    PP_POE_MAX_ALLOC_MW          = 0x070b,
    PP_POE_CURRENT_ALLOC_MW      = 0x070c,
    PP_VLAN_RANGE_START          = 0x070d,
    PP_VLAN_RANGE_END            = 0x070e,
    PP_VLAN_IS_TAGGED            = 0x070f,
    PP_VLAN_PORT_VID             = 0x0710,
    PP_VLAN_MGMT_VID             = 0x0711,
    PP_VLAN_ENABLE               = 0x0712,
    PP_EAPS_MODE                 = 0x0713,
    PP_EAPS_VLAN                 = 0x0714,
    PP_EAPS_PRI_PORT             = 0x0715,
    PP_EAPS_SEC_PORT             = 0x0716,
    PP_LLDP_PARTNER_MAC          = 0x0717,
    PP_LLDP_PARTNER_PORT         = 0x0718,
    PP_ET_PARAM_1                = 0x1101,
    PP_END                       = 0xffff
};

/** Property strings. */
static const value_string pp_pid_vals[] = {
    {PP_PAD,                       "Pad"},
    {PP_NODE_NAME,                 "Node Name"},
    {PP_PORT_NAME,                 "Port Name"},
    {PP_PATCH_NAME,                "Patch Name"},
    {PP_PORT_SPEED,                "Port Speed"},
    {PP_IS_BIDIRECTIONAL,          "Bi Directional"},
    {PP_IS_PHYSICAL,               "Physical"},
    {PP_IS_MALE,                   "Is Male"},
    {PP_IS_SINK,                   "Is Sink"},
    {PP_XDMX_COUNT,                "XDMX Channel Count"},
    {PP_ALT_START_CODE,            "Alt Start Code List"},
    {PP_MAX_PATCHES,               "Max # Patches"},
    {PP_NUM_PATCHES,               "Current # Patches"},
    {PP_TERMINATED,                "Is Terminated"},
    {PP_INPUT_PRIORITY,            "Input Priority (Static)"},
    {PP_INPUT_PRIORITY_CHANNEL,    "Input Priority Channel"},
    {PP_MAC,                       "Ethernet Address"},
    {PP_IP,                        "IP Address"},
    {PP_NETMASK,                   "IP Netmask"},
    {PP_ROUTER,                    "Default Router"},
    {PP_PP_ID,                     "Pathport ID"},
    {PP_PP_ID_MASK,                "Pathport ID Mask"},
    {PP_PP_TX_DATA_DST,            "Pathport Data Transmit Offset"},
    {PP_BACKLIGHT,                 "Backlight"},
    {PP_SW_VERSION,                "Software Version"},
    {PP_HW_TYPE,                   "Hardware Type"},
    {PP_LOADER_VERSION,            "Loader Version"},
    {PP_IDENTIFY,                  "Identify"},
    {PP_IRENABLE,                  "IR Enable"},
    {PP_SERIAL,                    "Serial Number"},
    {PP_KEYPAD_LOCKOUT,            "Front Panel Lockout"},
    {PP_ARTNET_RX_ENABLE,          "ArtNet Rx Enable"},
    {PP_TX_PROTOCOL,               "Data Tx Proto"},
    {PP_SHOWNET_RX_ENABLE,         "Shownet Rx Enable"},
    /* XXX: PP_LED_INTENSITY ?? */
    {PP_JUMPER_CONFIGURED,         "Universe Patched By Jumper"},
    {PP_SACN_RX_ENABLE,            "sACN (E1.31) Rx Enable"},
    {PP_NET2_RX_ENABLE,            "ETCNet2 Rx Enable"},
    {PP_PATHPORT_RX_ENABLE,        "xDMX Rx Enable"},
    {PP_SACN_IS_DRAFT,             "sACN TX is Draft"},
    {PP_REBOOT,                    "Reboot"},
    {PP_BOOTORDER,                 "Boot Order"},
    {PP_FACTORY_DEFAULT,           "Factory Default"},
    {PP_TEST_LCD,                  "Test LCD"},
    /* XXX: PP_IS_TERMINAL_BLOCK ?? */
    /* XXX: PP_IS_RACK_MOUNTED   ?? */
    {PP_IS_ENABLED,                "Port Enable"},
    {PP_IS_DMX_ACTIVE ,            "DMX Active"},
    {PP_IS_XDMX_ACTIVE ,           "xDMX Active"},
    {PP_SIGNAL_LOSS_HOLD_TIME,     "Signal Loss Hold Time (DMX OUT)"},
    {PP_SIGNAL_LOSS_HOLD_FOREVER , "Signal Loss Infinite Hold"},
    {PP_SIGNAL_LOSS_FADE_ENABLE,   "Signal Loss Fade Enable"},
    {PP_SIGNAL_LOSS_FADE_TIME,     "Signal Loss Fade Time"},
    {PP_SIGNAL_LOSS_PORT_SHUTDOWN, "Signal Loss Port Shutdown"},
    /* XXX: PP_NET2_ADMIN_MCAST ?? */
    /* XXX: PP_NET2_DATA_MCAST  ?? */
    /* XXX: PP_ROOMS_FEATURES   ?? */
    {PP_UNIVERSE_TEMP,             "xDMX Universe"},
    {PP_CROSSFADE_TIME,            "Crossfade Time(ms)"},
    {PP_CROSSFADE_ENABLE,          "Crossfade Enable"},
    {PP_IGNORE_INPUT_PRI,          "Ignore Input Priority"},
    {PP_ARTNET_ALT_MAP,            "ArtNet Alternate Univ Mapping"},
    {PP_PATCH_CRC,                 "Output Patch File CRC"},
    {PP_CONF_CHANGE,               "Config Change Notify"},
    {PP_PORT_ACTIVE_SUMMARY,       "Port Active Bitmap"},
    {PP_SUPPORTED_UNIV,            "Number Supported Univ"},
    {PP_INPUT_HLL_TIME,            "Signal Loss Hold Time (DMX IN)"},
    {PP_PCP_ENABLE,                "Per Channel Priorty Enable"},
    {PP_INPUT_UNIVERSE,            "Input Universe"},
    {PP_MODEL_NAME,                "Model Name"},
    {PP_MANUF_NAME,                "Manufacturer Name"},
    {PP_VER_STR,                   "Firmware Ver (String)"},
    {PP_SERIAL_STR,                "Serial Number (String)"},
    {PP_NODE_NOTES,                "Node User Notes"},
    {PP_PORT_NOTES,                "Port User Notes"},
    {PP_USER_NODE_ID,              "User Node ID"},
    {PP_MDG_GEN_STATE,             "MDG Generator Status"},
    {PP_EMBEDDED_ID,               "Embedded Device ID"},
    {PP_SLAVE_DMX_START,           "Embedded Device DMX Address"},
    {PP_TB_MODE,                   "RDM Discovery Enable"},
    {PP_LINK_MODE,                 "Ethernet Link Mode"},
    {PP_LINK_STATUS,               "Ethernet Link Status"},
    {PP_CONNECTED_COUNT,           "Connected PP Devices"},
    {PP_POE_STATUS,                "PoE Status"},
    {PP_POE_EXTERN_WATT,           "PoE External Supply Wattage"},
    {PP_POE_CURRENT_WATT,          "PoE Current Supply Wattage"},
    {PP_SFP_MODULE_TYPE,           "SFP Module Type"},
    {PP_POE_EXTERN_PRESENT,        "PoE External Supply Present"},
    {PP_POE_CAPABLE,               "PoE Capable Port"},
    {PP_SWITCH_PORT_TYPE,          "Ethernet Port Type"},
    {PP_POE_MAX_ALLOC_MW,          "PoE Max Alloc mW"},
    {PP_POE_CURRENT_ALLOC_MW,      "PoE Current Alloc mW"},
    {PP_VLAN_RANGE_START,          "VLAN Range Start"},
    {PP_VLAN_RANGE_END,            "VLAN Range End"},
    {PP_VLAN_IS_TAGGED,            "VLAN Port is Tagged"},
    {PP_VLAN_PORT_VID,             "VLAN Port VID"},
    {PP_VLAN_MGMT_VID,             "VLAN Management VID"},
    {PP_VLAN_ENABLE,               "VLAN Enable"},
    {PP_EAPS_MODE,                 "EAPS Mode"},
    {PP_EAPS_VLAN,                 "EAPS Control VLAN"},
    {PP_EAPS_PRI_PORT,             "EAPS Primary Port"},
    {PP_EAPS_SEC_PORT,             "EAPS Secondary Port"},
    {PP_LLDP_PARTNER_MAC,          "LLDP Partner MAC"},
    {PP_LLDP_PARTNER_PORT,         "LLDP Partner Port"},
    /* XXX: ET_PARAM ?? */
    {PP_END,                       "End"},
    {0, NULL}
};

value_string_ext pp_pid_vals_ext = VALUE_STRING_EXT_INIT(pp_pid_vals);

/** Unknown type format. */
#define TYPE_UNKNOWN "Unknown (%04x)"

/* End Field and enum declarations */


/* Code to actually dissect the packets */
static guint dissect_one_tlv(tvbuff_t *tvb, proto_tree *tree,
                guint offset)
{
    proto_item *ti = proto_tree_add_text(tree, tvb, offset, 0, "Property");
    proto_tree *tlv_tree = proto_item_add_subtree(ti, ett_pp_tlv);

    guint len;
    guint pad_len;

    guint type = tvb_get_ntohs(tvb, offset);
    const char *name = val_to_str_ext(type, &pp_pid_vals_ext, TYPE_UNKNOWN);
    proto_item_append_text(ti, " : %s", name);

    proto_tree_add_item(tlv_tree, hf_pp_pid_type, tvb, offset, 2, ENC_NA);
    offset += 2;

    len = tvb_get_ntohs(tvb, offset);
    proto_item_set_len(ti, 4 + len);

    proto_tree_add_item(tlv_tree, hf_pp_pid_len, tvb, offset, 2, ENC_NA);
    offset += 2;

    proto_tree_add_item(tlv_tree, hf_pp_pid_value, tvb, offset, len, ENC_NA);
    offset += len;

    pad_len = ~(offset-1) & 3;
    if(pad_len)
    {
        proto_tree_add_text(tlv_tree, tvb, offset, pad_len, "%d %s", pad_len, pad_len > 1 ? "pad bytes" : "pad byte");
        offset += pad_len;
    }
    return offset;
}


static guint
dissect_multiple_tlvs(tvbuff_t *tvb, proto_item *ti,
                guint offset, guint len)
{
    guint end = offset + len;
    while(offset < end) {
        offset = dissect_one_tlv(tvb, ti, offset);
    }
    return offset;
}

static guint
dissect_multiple_get_pids(tvbuff_t *tvb, proto_item *tree, guint offset, guint len)
{
    guint end = offset + len;

    while(offset < end)
    {
        proto_tree_add_item(tree, hf_pp_get_type, tvb, offset, 2, ENC_NA);
        offset += 2;
    }
    return len;
}

static guint
dissect_data_payload(tvbuff_t *tvb, proto_item *tree, guint offset, guint len)
{
    guint end = offset + len;
    guint blklen = 0;
    guint xdmx, stc;

    while(offset < end)
    {
        proto_item *ti = proto_tree_add_text(tree, tvb, offset, 0, "xDMX Data: ");
        proto_tree *data_tree = proto_item_add_subtree(ti, ett_pp_data);
        proto_tree_add_item(data_tree, hf_pp_data_encoding, tvb, offset, 2, ENC_NA);
        offset += 2;
        blklen = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(data_tree, hf_pp_data_len, tvb, offset, 2, ENC_NA);
        offset += 2;
        proto_tree_add_item(data_tree, hf_pp_reserved, tvb, offset++, 1, ENC_NA);
        stc = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(data_tree, hf_pp_data_start_code, tvb, offset++, 1, ENC_NA);
        xdmx = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(data_tree, hf_pp_data_dst, tvb, offset, 2, ENC_NA);
        offset += 2;
        proto_tree_add_item(data_tree, hf_pp_data_levels, tvb, offset, blklen, ENC_NA);
        proto_item_append_text(ti, "%d Channels at xDMX %d (Univ %d.%d) StartCode: %d ", blklen, xdmx,  xdmx / 512 + 1, xdmx % 512,  stc);
        offset += roof4(blklen);
    }
    return len;
}

static guint
dissect_arp_reply(tvbuff_t *tvb, proto_tree *tree, guint offset, guint len)
{
    proto_tree_add_item(tree, hf_pp_arp_id, tvb, offset, 4, ENC_NA);
    offset += 4;
    proto_tree_add_item(tree, hf_pp_arp_ip, tvb, offset, 4, ENC_NA);
    offset += 4;
    proto_tree_add_item(tree, hf_pp_arp_manuf, tvb, offset++, 1, ENC_NA);
    proto_tree_add_item(tree, hf_pp_arp_class, tvb, offset++, 1, ENC_NA);
    proto_tree_add_item(tree, hf_pp_arp_type, tvb, offset++, 1, ENC_NA);
    proto_tree_add_item(tree, hf_pp_arp_numdmx, tvb, offset++, 1, ENC_NA);
    return len;
}

static guint
dissect_one_pdu(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    proto_item *ti = proto_tree_add_text(tree, tvb, offset, 0, "PDU");
    proto_tree *pdu_tree = proto_item_add_subtree(ti, ett_pp_pdu);

    guint len;

    guint type = tvb_get_ntohs(tvb, offset);
    const char *name = val_to_str(type, pp_pdu_vals, TYPE_UNKNOWN);
    proto_item_append_text(ti, " : %s", name);

    proto_tree_add_item(pdu_tree, hf_pp_pdu_type, tvb, offset, 2, ENC_NA);
    offset += 2;

    len = tvb_get_ntohs(tvb, offset);
    proto_item_set_len(ti, 4 + len);

    proto_tree_add_item(pdu_tree, hf_pp_pdu_len, tvb, offset, 2, ENC_NA);
    offset += 2;

    switch(type)
    {
        case PP_ARP_REPLY :
            dissect_arp_reply(tvb, pdu_tree, offset, len);
            break;
        case PP_GET :
            dissect_multiple_get_pids(tvb, pdu_tree, offset, len);
            break;
        case PP_SET :
        case PP_GET_REPLY :
        case PP_ARP_INFO :
            dissect_multiple_tlvs(tvb, pdu_tree, offset, len);
            break;
        case PP_DATA :
            dissect_data_payload(tvb, pdu_tree, offset, len);
            break;
        default:
            proto_tree_add_item(pdu_tree, hf_pp_pdu_payload, tvb, offset, len, ENC_NA);
            break;
    }
    offset += roof4(len);
    return offset;
}

static guint
dissect_multiple_pdus(tvbuff_t *tvb, proto_item *ti,
                guint offset, guint len)
{
    guint end = offset + len;
    while(offset < end) {
        offset = dissect_one_pdu(tvb, ti, offset);
    }
    return offset;
}

static int
dissect_header(tvbuff_t *tvb, proto_tree *parent, guint offset)
{
    proto_item *ti = proto_tree_add_item(parent, proto_pathport, tvb, offset, PATHPORT_HEADER_LENGTH, ENC_NA);
    proto_tree *tree = proto_item_add_subtree(ti, ett_pathport);
    proto_item_set_text(ti, "Header");

    proto_tree_add_item(tree, hf_pp_prot,     tvb, offset, 2, ENC_NA);
    offset += 2;
    proto_tree_add_item(tree, hf_pp_version,  tvb, offset, 2, ENC_NA);
    offset += 2;
    proto_tree_add_item(tree, hf_pp_seq,      tvb, offset, 2, ENC_NA);
    offset += 2;
    proto_tree_add_item(tree, hf_pp_reserved, tvb, offset, 6, ENC_NA);
    offset += 6;
    proto_tree_add_item(tree, hf_pp_src,      tvb, offset, 4, ENC_NA);
    offset += 4;
    proto_tree_add_item(tree, hf_pp_dst,      tvb, offset, 4, ENC_NA);
    offset += 4;
    return offset;
}

static gboolean
packet_is_pathport(tvbuff_t *tvb)
{
    if(tvb_length(tvb) < PATHPORT_MIN_LENGTH)
        return FALSE;

    if(tvb_get_ntohs(tvb, 0) != PATHPORT_PROTO_MAGIC)
        return FALSE;
    /* could also check that the first PDU is in our list of supported PDUs */

    return TRUE;
}

/** Resolves the specified ID to a name. */
static const char *
resolve_pp_id(guint32 id)
{
    return val_to_str(id, ednet_id_vals, "%X");
}

static int dissect_pathport_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *pathport_tree;
    guint offset = 0;
    guint remaining_len;
    guint len;
    guint16 type;
    guint32 srcid;
    guint32 dstid;

    len = tvb_reported_length(tvb);

    /* Set the Protocol column to the constant string of Pathport */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Pathport");

    /* Set the info column to reflect the first PDU in the packet */
    col_clear(pinfo->cinfo, COL_INFO);
    srcid = tvb_get_ntohl(tvb, PATHPORT_HEADER_SRCID_OFFSET);
    type = tvb_get_ntohs(tvb, PATHPORT_HEADER_LENGTH);

    if(type == PP_ARP_REQUEST)
    {
        dstid = tvb_get_ntohl(tvb, PATHPORT_HEADER_DSTID_OFFSET);
        col_add_fstr(pinfo->cinfo, COL_INFO, "Who has %s? Tell %s",
                    resolve_pp_id(dstid), resolve_pp_id(srcid));
    }
    else
    {
        if((type == PP_ARP_REPLY) && (len >= 36))
        {
            guint32 id = tvb_get_ntohl(tvb, 24);
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s is at %s", resolve_pp_id(id), tvb_ip_to_str(tvb, 28));
        }
        else if((type == PP_DATA) && (len >= 32))
        {
            guint16 xdmx_start = tvb_get_ntohs(tvb, 30);
            col_add_fstr(pinfo->cinfo, COL_INFO, "xDMX Data - %d channels @ %d (Univ %d.%d)",
                         tvb_get_ntohs(tvb, 26),
                         xdmx_start, xdmx_start / 512 + 1, xdmx_start % 512);
        }
        else /* default */
        {
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(type, pp_pdu_vals, TYPE_UNKNOWN));
        }
    }
    if(tree == NULL)
        return tvb_reported_length(tvb);

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_pathport, tvb, 0, -1, ENC_NA);

    pathport_tree = proto_item_add_subtree(ti, ett_pathport);
    offset = dissect_header(tvb, pathport_tree, PATHPORT_HEADER_OFFSET);
    remaining_len = tvb_reported_length(tvb) - PATHPORT_HEADER_LENGTH;
    offset = dissect_multiple_pdus(tvb, tree, offset, remaining_len);

    return offset;
}

static int
dissect_pathport(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
   if(!packet_is_pathport(tvb))
        return 0;
    return dissect_pathport_common(tvb, pinfo, tree);
}

static gboolean
dissect_pathport_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
   if(!packet_is_pathport(tvb))
        return FALSE;

    dissect_pathport_common(tvb, pinfo, tree);
    return (TRUE);
}

/* Register the protocol with Wireshark.
 *
 * This format is require because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_pathport(void)
{
    static hf_register_info hf[] = {
/* Packet Header */
        {&hf_pp_prot,               {"Protocol", "pathport.prot", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
        {&hf_pp_reserved,           {"Reserved", "pathport.resv", FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }},
        {&hf_pp_version,            {"Version", "pathport.version", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
        {&hf_pp_seq,                {"Sequence", "pathport.seq", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        {&hf_pp_src,                {"Source ID", "pathport.src", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
        {&hf_pp_dst,                {"Destination ID", "pathport.dst", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},

/* PDU Header */
        {&hf_pp_pdu_type,           {"PDU", "pathport.pdu", FT_UINT16, BASE_HEX, VALS(pp_pdu_vals), 0x0, "", HFILL }},
        {&hf_pp_pdu_len,            {"Length", "pathport.len", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        {&hf_pp_pdu_payload,        {"Payload", "pathport.payload", FT_BYTES, 0, NULL, 0x0, "", HFILL }},

/* Property structures */
        {&hf_pp_get_type,           {"Get", "pathport.get.pid", FT_UINT16, BASE_HEX | BASE_EXT_STRING, &pp_pid_vals_ext, 0x0, "", HFILL }},
        {&hf_pp_pid_type,           {"Property", "pathport.pid", FT_UINT16, BASE_HEX | BASE_EXT_STRING, &pp_pid_vals_ext, 0x0, "", HFILL }},
        {&hf_pp_pid_len,            {"Length", "pathport.pid.len", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        {&hf_pp_pid_value,          {"Value", "pathport.pid.value", FT_BYTES, 0, NULL, 0x0, "", HFILL }},

/* Pathport XDMX Data */
        {&hf_pp_data_encoding,      {"Data Encoding", "pathport.data.encoding", FT_UINT16, BASE_HEX, VALS(pp_data_encoding_vals), 0x0, "", HFILL }},
        {&hf_pp_data_start_code,    {"DMX Start Code", "pathport.data.startcode", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
        {&hf_pp_data_len,           {"Data Length", "pathport.data.len", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
        {&hf_pp_data_dst,           {"xDMX Destination", "pathport.data.dst", FT_UINT16, BASE_HEX, NULL, 0x0,"", HFILL }},
        {&hf_pp_data_levels,        {"Levels", "pathport.data.levels", FT_NONE, 0, NULL, 0x0, "", HFILL }},

/* PP_ARP Reply structures */
        {&hf_pp_arp_id,             {"ID", "pathport.arp.id", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
        {&hf_pp_arp_manuf,          {"Manufacturer", "pathport.arp.manuf", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
        {&hf_pp_arp_class,          {"Device Class", "pathport.arp.class", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
        {&hf_pp_arp_type,           {"Device Type", "pathport.arp.type", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
        {&hf_pp_arp_numdmx,         {"Subcomponents", "pathport.arp.numdmx", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
        {&hf_pp_arp_ip,             {"IP", "pathport.arp.ip", FT_IPv4, 0, NULL, 0x0, "", HFILL }}
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_pathport,
        &ett_pp_pdu,
        &ett_pp_tlv,
        &ett_pp_data
    };

    /* Register the protocol name and description */
    proto_pathport = proto_register_protocol("Pathport Protocol", "Pathport", "pathport");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_pathport, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_pathport(void)
{
    static dissector_handle_t pathport_handle;

    pathport_handle = new_create_dissector_handle(dissect_pathport, proto_pathport);
    heur_dissector_add("udp", dissect_pathport_heur, proto_pathport);
    dissector_add_uint("udp.port", PATHPORT_UDP_PORT, pathport_handle);
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

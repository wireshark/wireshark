/* packet-lltd.c
 * Routines for LLTD dissection
 * Copyright 2012, Michael Mann
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

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/expert.h>

void proto_register_lltd(void);
void proto_reg_handoff_lltd(void);

static int proto_lltd = -1;

static int hf_lltd_version                  = -1;
static int hf_lltd_type_of_service          = -1;
static int hf_lltd_reserved                 = -1;
static int hf_lltd_discovery_func           = -1;
static int hf_lltd_discovery_real_dest_addr = -1;
static int hf_lltd_discovery_real_src_addr  = -1;
static int hf_lltd_discovery_xid            = -1;
static int hf_lltd_discovery_seq_num        = -1;
static int hf_lltd_discover_gen_num         = -1;
static int hf_lltd_discover_num_stations    = -1;
static int hf_lltd_discover_station         = -1;
static int hf_lltd_hello_gen_num            = -1;
static int hf_lltd_hello_current_address    = -1;
static int hf_lltd_hello_apparent_address   = -1;
static int hf_lltd_tlv_type                 = -1;
static int hf_lltd_tlv_length               = -1;
static int hf_lltd_host_id                  = -1;
static int hf_lltd_char_p                   = -1;
static int hf_lltd_char_x                   = -1;
static int hf_lltd_char_f                   = -1;
static int hf_lltd_char_m                   = -1;
static int hf_lltd_char_l                   = -1;
static int hf_lltd_char_reserved            = -1;
static int hf_lltd_physical_medium          = -1;
static int hf_lltd_wireless_mode            = -1;
static int hf_lltd_bssid                    = -1;
static int hf_lltd_ssid                     = -1;
static int hf_lltd_ipv4_address             = -1;
static int hf_lltd_ipv6_address             = -1;
static int hf_lltd_max_operation_rate       = -1;
static int hf_lltd_performance_count_freq   = -1;
static int hf_lltd_link_speed               = -1;
static int hf_lltd_rssi                     = -1;
static int hf_lltd_machine_name             = -1;
static int hf_lltd_support_info             = -1;
static int hf_lltd_device_uuid              = -1;
static int hf_lltd_qos_char_e               = -1;
static int hf_lltd_qos_char_q               = -1;
static int hf_lltd_qos_char_p               = -1;
static int hf_lltd_qos_char_reserved        = -1;
static int hf_lltd_80211_physical_medium    = -1;
static int hf_lltd_sees_list_working_set    = -1;
static int hf_lltd_repeater_ap_lineage      = -1;
static int hf_lltd_emit_num_descs           = -1;
static int hf_lltd_emit_type                = -1;
static int hf_lltd_emit_pause               = -1;
static int hf_lltd_emit_src_addr            = -1;
static int hf_lltd_emit_dest_addr           = -1;
static int hf_lltd_queryresp_more_descs     = -1;
static int hf_lltd_queryresp_memory_descs   = -1;
static int hf_lltd_queryresp_num_descs      = -1;
static int hf_lltd_queryresp_type           = -1;
static int hf_lltd_queryresp_real_src_addr  = -1;
static int hf_lltd_queryresp_ethernet_src_addr  = -1;
static int hf_lltd_queryresp_ethernet_dest_addr = -1;
static int hf_lltd_flat_crc_bytes           = -1;
static int hf_lltd_flat_crc_packets         = -1;
static int hf_lltd_query_large_tlv_type     = -1;
static int hf_lltd_query_large_tlv_offset   = -1;
static int hf_lltd_querylargeresp_more_descs    = -1;
static int hf_lltd_querylargeresp_memory_descs  = -1;
static int hf_lltd_querylargeresp_num_descs = -1;
static int hf_lltd_querylargeresp_data      = -1;

static int hf_lltd_qos_diag_func            = -1;
static int hf_lltd_qos_real_dest_addr       = -1;
static int hf_lltd_qos_real_src_addr        = -1;
static int hf_lltd_qos_seq_num              = -1;
static int hf_lltd_qos_initialize_interrupt_mod = -1;
static int hf_lltd_qos_ready_sink_link_speed = -1;
static int hf_lltd_qos_ready_perf_count_freq = -1;
static int hf_lltd_qos_probe_controller_transmit_timestamp = -1;
static int hf_lltd_qos_probe_sink_receive_timestamp = -1;
static int hf_lltd_qos_probe_sink_transmit_timestamp = -1;
static int hf_lltd_qos_probe_test_type      = -1;
static int hf_lltd_qos_probe_packet_id      = -1;
static int hf_lltd_qos_probe_t              = -1;
static int hf_lltd_qos_probe_8021p_value    = -1;
static int hf_lltd_qos_probe_payload        = -1;
static int hf_lltd_qos_error_value          = -1;
static int hf_lltd_qos_count_snapshot_history = -1;
static int hf_lltd_qos_query_resp_r         = -1;
static int hf_lltd_qos_query_resp_e         = -1;
static int hf_lltd_qos_query_resp_num_events = -1;
static int hf_lltd_qos_query_resp_controller_timestamp = -1;
static int hf_lltd_qos_query_resp_sink_timestamp = -1;
static int hf_lltd_qos_query_resp_packet_id = -1;
static int hf_lltd_qos_query_resp_reserved  = -1;
static int hf_lltd_qos_counter_result_subsec_span = -1;
static int hf_lltd_qos_counter_result_byte_scale = -1;
static int hf_lltd_qos_counter_result_packet_scale = -1;
static int hf_lltd_qos_counter_result_history_size = -1;
static int hf_lltd_qos_snapshot_bytes_recv  = -1;
static int hf_lltd_qos_snapshot_packets_recv= -1;
static int hf_lltd_qos_snapshot_bytes_sent  = -1;
static int hf_lltd_qos_snapshot_packets_sent= -1;


static gint ett_lltd                = -1;
static gint ett_base_header         = -1;
static gint ett_discover_stations   = -1;
static gint ett_tlv                 = -1;
static gint ett_tlv_item            = -1;
static gint ett_characteristics     = -1;
static gint ett_qos_characteristics = -1;
static gint ett_repeater_ap_lineage = -1;
static gint ett_emitee_descs        = -1;
static gint ett_emitee_descs_item   = -1;
static gint ett_recvee_descs        = -1;
static gint ett_recvee_descs_item   = -1;
static gint ett_qos_event_descs     = -1;
static gint ett_qos_event_item      = -1;
static gint ett_qos_snapshot_list   = -1;
static gint ett_qos_snapshot_item   = -1;

static expert_field ei_lltd_tlv_length_invalid = EI_INIT;
static expert_field ei_lltd_too_many_paths = EI_INIT;
static expert_field ei_lltd_type_of_service = EI_INIT;
static expert_field ei_lltd_char_reserved = EI_INIT;
static expert_field ei_lltd_qos_seq_num = EI_INIT;
static expert_field ei_lltd_discovery_func = EI_INIT;
static expert_field ei_lltd_tlv_type = EI_INIT;
static expert_field ei_lltd_qos_diag_func = EI_INIT;

#define LLTD_CHARACTERISTIC_P_MASK          0x80000000
#define LLTD_CHARACTERISTIC_X_MASK          0x40000000
#define LLTD_CHARACTERISTIC_F_MASK          0x20000000
#define LLTD_CHARACTERISTIC_M_MASK          0x10000000
#define LLTD_CHARACTERISTIC_L_MASK          0x08000000
#define LLTD_CHARACTERISTIC_RESERVE_MASK    0x07FFFFFF

#define LLTD_QOS_CHARACTERISTIC_E_MASK          0x80000000
#define LLTD_QOS_CHARACTERISTIC_Q_MASK          0x40000000
#define LLTD_QOS_CHARACTERISTIC_P_MASK          0x20000000
#define LLTD_QOS_CHARACTERISTIC_RESERVE_MASK    0x1FFFFFFF

#define LLTD_QUERY_RESP_M_MASK                  0x8000
#define LLTD_QUERY_RESP_E_MASK                  0x4000
#define LLTD_QUERY_RESP_NUM_DESCS_MASK          0x3FFF

static const value_string lltd_tos_vals[] = {
    { 0,     "Topology discovery" },
    { 1,     "Quick discovery" },
    { 2,     "QoS Diagnostics" },

    { 0,                    NULL }
};

static const value_string lltd_discovery_vals[] = {
    { 0x00,     "Discover" },
    { 0x01,     "Hello" },
    { 0x02,     "Emit" },
    { 0x03,     "Train" },
    { 0x04,     "Probe" },
    { 0x05,     "Ack" },
    { 0x06,     "Query" },
    { 0x07,     "QueryResp" },
    { 0x08,     "Reset" },
    { 0x09,     "Charge" },
    { 0x0A,     "Flat" },
    { 0x0B,     "QueryLargeTlv" },
    { 0x0C,     "QueryLargeTlvResp" },

    { 0,                    NULL }
};

static const value_string lltd_qos_diag_vals[] = {
    { 0x00,     "QosInitializeSink" },
    { 0x01,     "QosReady" },
    { 0x02,     "QosProbe" },
    { 0x03,     "QosQuery" },
    { 0x04,     "QosQueryResp" },
    { 0x05,     "QosReset" },
    { 0x06,     "QosError" },
    { 0x07,     "QosAck" },
    { 0x08,     "QosCounterSnapshot" },
    { 0x09,     "QosCounterResult" },
    { 0x0A,     "QosCounterLease" },

    { 0,                    NULL }
};

static const value_string lltd_tlv_type_vals[] = {
    { 0x00,     "End of Property List" },
    { 0x01,     "Host ID" },
    { 0x02,     "Characteristics" },
    { 0x03,     "Physical Medium" },
    { 0x04,     "Wireless Mode" },
    { 0x05,     "802.11 BSSID" },
    { 0x06,     "802.11 SSID" },
    { 0x07,     "IPv4 Address" },
    { 0x08,     "IPv6 Address" },
    { 0x09,     "802.11 Maximum Operation Rate" },
    { 0x0A,     "Performance Counter Frequency" },
    { 0x0C,     "Link Speed" },
    { 0x0D,     "802.11 RSSI" },
    { 0x0E,     "Icon Image" },
    { 0x0F,     "Machine Name" },
    { 0x10,     "Support Information" },
    { 0x11,     "Friendly Name" },
    { 0x12,     "Device UUID" },
    { 0x13,     "Hardware ID" },
    { 0x14,     "QoS Characteristics" },
    { 0x15,     "802.11 Phyiscal Medium" },
    { 0x16,     "AP Association Table" },
    { 0x18,     "Detailed Icon Image" },
    { 0x19,     "Sees-List Working Set" },
    { 0x1A,     "Component Table" },
    { 0x1B,     "Repeater AP Lineage" },
    { 0x1C,     "Repeater AP Table" },

    { 0,                    NULL }
};

static const value_string lltd_wireless_mode_vals[] = {
    { 0x00,     "802.11 IBSS or ad-hoc mode" },
    { 0x01,     "802.11 infrastructure mode" },

    { 0,                    NULL }
};

static const value_string lltd_80211_physical_medium_vals[] = {
    { 0x00,     "Unknown" },
    { 0x01,     "FHSS 2.4 GHz" },
    { 0x02,     "DSSS 2.4 GHz" },
    { 0x03,     "IR Baseband" },
    { 0x04,     "OFDM 5 GHz" },
    { 0x05,     "HRDSSS" },
    { 0x06,     "ERP" },

    { 0,                    NULL }
};

static const value_string lltd_emit_type_vals[] = {
    { 0x00,     "Train" },
    { 0x01,     "Probe" },

    { 0,                    NULL }
};

static const value_string lltd_queryresp_type_vals[] = {
    { 0x00,     "Probe" },
    { 0x01,     "ARP" },

    { 0,                    NULL }
};

static const value_string lltd_query_large_tlv_type_vals[] = {
    { 0x0E,     "Icon Image" },
    { 0x11,     "Friendly Name" },
    { 0x13,     "Hardware ID" },
    { 0x16,     "AP Association Table" },
    { 0x18,     "Detailed Icon Image" },
    { 0x1A,     "Component Table" },
    { 0x1C,     "Repeater AP Table" },

    { 0,                    NULL }
};

static const value_string lltd_interrupt_mod_vals[] = {
    { 0x00,     "Disable interrupt moderation" },
    { 0x01,     "Enable interrupt moderation" },
    { 0xFF,     "Use existing interrupt moderation setting" },

    { 0,                    NULL }
};

static const value_string lltd_qos_probe_test_type_vals[] = {
    { 0x00,     "Timed Probe" },
    { 0x01,     "Probegap originating from the controller" },
    { 0x02,     "Probegap originating from the sink" },

    { 0,                    NULL }
};

static const value_string lltd_qos_error_vals[] = {
    { 0x00,     "Insufficient Resources" },
    { 0x01,     "Busy. Try again later" },
    { 0x02,     "Interrupt moderation not available" },

    { 0,                    NULL }
};


const true_false_string tfs_full_half_duplex = { "Full Duplex", "Half Duplex" };


static int
dissect_lltd_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, gboolean* end)
{
    guint8     i, type, length = 0;
    proto_item *tlv_item, *type_item;
    proto_tree *tlv_tree, *type_tree;
    guint32 temp32;

    type = tvb_get_guint8(tvb, offset);
    if (type == 0)
    {
        /* End of Property type doesn't have length */
        tlv_tree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_tlv_item, &tlv_item, "TLV Item (End of Property List)");
        *end = TRUE;
    }
    else
    {
        length = tvb_get_guint8(tvb, offset+1);
        tlv_tree = proto_tree_add_subtree_format(tree, tvb, offset, length+2, ett_tlv_item, &tlv_item,
                    "TLV Item (%s)", val_to_str(type, lltd_tlv_type_vals, "Unknown (0x%02x)"));
        *end = FALSE;
    }

    proto_tree_add_item(tlv_tree, hf_lltd_tlv_type, tvb, offset, 1, ENC_NA);
    if (type != 0)
        proto_tree_add_item(tlv_tree, hf_lltd_tlv_length, tvb, offset+1, 1, ENC_NA);


    if ((type != 0) && (length > tvb_reported_length_remaining(tvb, offset+2)))
    {
        expert_add_info_format(pinfo, tlv_item, &ei_lltd_tlv_length_invalid, "TLV Length field too big");
        *end = TRUE;
        return 2;
    }

    switch(type)
    {
    case 0x00: /* End of Property List */
        /* No data, no length field */
        return 1;
    case 0x01: /* Host ID */
        if (length != 6)
        {
            expert_add_info_format(pinfo, tlv_item, &ei_lltd_tlv_length_invalid, "Invalid Host ID length");
        }

        proto_tree_add_item(tlv_tree, hf_lltd_host_id, tvb, offset+2, 6, ENC_NA);
        break;
    case 0x02: /* Characteristics */
        if (length != 4)
        {
            expert_add_info_format(pinfo, tlv_item, &ei_lltd_tlv_length_invalid, "Characteristics length");
        }
        else
        {
            type_tree = proto_tree_add_subtree(tree, tvb, offset+2, 4, ett_characteristics, &type_item, "Characteristics");
            proto_tree_add_item(type_tree, hf_lltd_char_p, tvb, offset+2, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(type_tree, hf_lltd_char_x, tvb, offset+2, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(type_tree, hf_lltd_char_f, tvb, offset+2, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(type_tree, hf_lltd_char_m, tvb, offset+2, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(type_tree, hf_lltd_char_l, tvb, offset+2, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(type_tree, hf_lltd_char_reserved, tvb, offset+2, 4, ENC_BIG_ENDIAN);
            if (tvb_get_ntohl(tvb, offset+2) & LLTD_CHARACTERISTIC_RESERVE_MASK)
                expert_add_info(pinfo, type_item, &ei_lltd_char_reserved);
        }
        break;
    case 0x03: /* Physical Medium */
        if (length != 4)
        {
            expert_add_info_format(pinfo, tlv_item, &ei_lltd_tlv_length_invalid, "Invalid Physical Medium length");
        }

        proto_tree_add_item(tlv_tree, hf_lltd_physical_medium, tvb, offset+2, 4, ENC_BIG_ENDIAN);
        break;
    case 0x04: /* Wireless Mode */
        if (length != 1)
        {
            expert_add_info_format(pinfo, tlv_item, &ei_lltd_tlv_length_invalid, "Invalid Wireless Mode length");
        }

        proto_tree_add_item(tlv_tree, hf_lltd_wireless_mode, tvb, offset+2, 1, ENC_BIG_ENDIAN);
        break;
    case 0x05: /* 802.11 BSSID */
        if (length != 6)
        {
            expert_add_info_format(pinfo, tlv_item, &ei_lltd_tlv_length_invalid, "Invalid BSSID length");
        }

        proto_tree_add_item(tlv_tree, hf_lltd_bssid, tvb, offset+2, 6, ENC_NA);
        break;
    case 0x06: /* 802.11 SSID */
        if (length > 32)
        {
            expert_add_info_format(pinfo, tlv_item, &ei_lltd_tlv_length_invalid, "SSID length too large");
        }

        proto_tree_add_item(tlv_tree, hf_lltd_ssid, tvb, offset+2, length, ENC_NA|ENC_ASCII);
        break;
    case 0x07: /* IPv4 Address */
        if (length != 4)
        {
            expert_add_info_format(pinfo, tlv_item, &ei_lltd_tlv_length_invalid, "Invalid IPv4 Address length");
        }

        proto_tree_add_item(tlv_tree, hf_lltd_ipv4_address, tvb, offset+2, 4, ENC_BIG_ENDIAN);
        break;
    case 0x08: /* IPv6 Address */
        if (length != 16)
        {
            expert_add_info_format(pinfo, tlv_item, &ei_lltd_tlv_length_invalid, "Invalid IPv6 Address length");
        }

        proto_tree_add_item(tlv_tree, hf_lltd_ipv6_address, tvb, offset+2, 16, ENC_NA);
        break;
    case 0x09: /* 802.11 Maximum Operation Rate */
        if (length != 2)
        {
            expert_add_info_format(pinfo, tlv_item, &ei_lltd_tlv_length_invalid, "Invalid Maximum Operation Rate length");
        }

        proto_tree_add_item(tlv_tree, hf_lltd_max_operation_rate, tvb, offset+2, 2, ENC_BIG_ENDIAN);
        break;
    case 0x0A: /* Performance Counter Frequency */
        if (length != 8)
        {
            expert_add_info_format(pinfo, tlv_item, &ei_lltd_tlv_length_invalid, "Invalid Performance Counter Frequency length");
        }

        proto_tree_add_item(tlv_tree, hf_lltd_performance_count_freq, tvb, offset+2, 8, ENC_BIG_ENDIAN);
        break;
    case 0x0C: /* Link Speed */
        if (length != 4)
        {
            expert_add_info_format(pinfo, tlv_item, &ei_lltd_tlv_length_invalid, "Invalid Link Speed length");
        }

        proto_tree_add_item(tlv_tree, hf_lltd_link_speed, tvb, offset+2, 4, ENC_BIG_ENDIAN);
        break;
    case 0x0D: /* 802.11 RSSI */
        if (length != 4)
        {
            expert_add_info_format(pinfo, tlv_item, &ei_lltd_tlv_length_invalid, "Invalid RSSI length");
        }

        proto_tree_add_item(tlv_tree, hf_lltd_rssi, tvb, offset+2, 4, ENC_BIG_ENDIAN);
        break;
    case 0x0F: /* Machine Name */
        if (length > 32)
        {
            expert_add_info_format(pinfo, tlv_item, &ei_lltd_tlv_length_invalid, "Machine Name length too large");
        }

        proto_tree_add_item(tlv_tree, hf_lltd_machine_name, tvb, offset+2, length, ENC_LITTLE_ENDIAN|ENC_UCS_2);
        break;
    case 0x10: /* Support Information */
        if (length > 64)
        {
            expert_add_info_format(pinfo, tlv_item, &ei_lltd_tlv_length_invalid, "Support Information length too large");
        }

        proto_tree_add_item(tlv_tree, hf_lltd_support_info, tvb, offset+2, length, ENC_LITTLE_ENDIAN|ENC_UCS_2);
        break;
    case 0x11: /* Friendly Name */
        if (length != 0)
            expert_add_info_format(pinfo, tlv_item, &ei_lltd_tlv_length_invalid, "Invalid Friendly Name length");
        break;
    case 0x12: /* Device UUID */
        if (length != 22)
        {
            expert_add_info_format(pinfo, tlv_item, &ei_lltd_tlv_length_invalid, "Invalid Device UUID length");
        }

        proto_tree_add_item(tlv_tree, hf_lltd_device_uuid, tvb, offset+2, 22, ENC_NA);
        break;
    case 0x13: /* Hardware ID */
        if (length != 0)
            expert_add_info_format(pinfo, tlv_item, &ei_lltd_tlv_length_invalid, "Invalid Hardware ID length");
        break;
    case 0x14: /* QoS Characteristics */
        if (length != 4)
        {
            expert_add_info_format(pinfo, tlv_item, &ei_lltd_tlv_length_invalid, "QoS Characteristics length");
        }
        else
        {
            type_tree = proto_tree_add_subtree(tlv_tree, tvb, offset+2, 4, ett_qos_characteristics, &type_item, "QoS Characteristics");
            proto_tree_add_item(type_tree, hf_lltd_qos_char_e, tvb, offset+2, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(type_tree, hf_lltd_qos_char_q, tvb, offset+2, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(type_tree, hf_lltd_qos_char_p, tvb, offset+2, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(type_tree, hf_lltd_qos_char_reserved, tvb, offset+2, 4, ENC_BIG_ENDIAN);
            temp32 = tvb_get_ntohl(tvb, offset+2);
            if (temp32 & LLTD_QOS_CHARACTERISTIC_RESERVE_MASK)
                expert_add_info(pinfo, type_item, &ei_lltd_char_reserved);
        }
        break;
    case 0x15: /* 802.11 Physical Medium */
        if (length != 1)
        {
            expert_add_info_format(pinfo, tlv_item, &ei_lltd_tlv_length_invalid, "Invalid 802.11 Phyiscal Medium length");
        }

        proto_tree_add_item(tlv_tree, hf_lltd_80211_physical_medium, tvb, offset+2, 1, ENC_BIG_ENDIAN);
        break;
    case 0x19: /* Sees-List Working Set */
        if (length != 2)
        {
            expert_add_info_format(pinfo, tlv_item, &ei_lltd_tlv_length_invalid, "Invalid Sees-List Working Set length");
        }

        proto_tree_add_item(tlv_tree, hf_lltd_sees_list_working_set, tvb, offset+2, 2, ENC_BIG_ENDIAN);
        break;
    case 0x1B: /* Repeater AP Lineage */
        type_tree = proto_tree_add_subtree(tree, tvb, offset+2, length, ett_repeater_ap_lineage, NULL, "Repeater AP Lineage");
        for (i = 0; i < length; i += 6)
            proto_tree_add_item(type_tree, hf_lltd_repeater_ap_lineage, tvb, offset+2+i, 6, ENC_NA);

        if (length > 36)
            expert_add_info(pinfo, tlv_item, &ei_lltd_too_many_paths);
        break;
    case 0x0E: /* Icon Image */
    case 0x16: /* AP Association Table */
    case 0x18: /* Detailed Icon Image */
    case 0x1A: /* Component Table */
    case 0x1C: /* Repeater AP Table */
        if (length != 0)
            expert_add_info_format(pinfo, tlv_item, &ei_lltd_tlv_length_invalid, "Invalid length");
        break;
    default:
        expert_add_info_format(pinfo, tlv_item, &ei_lltd_tlv_type, "Invalid TLV Type 0x%02x", type);
        break;
    }

    return length+2;
}

static void
dissect_lltd_discovery(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_item *header_item, *func_item;
    proto_tree *header_tree, *func_tree, *func_subtree;
    guint8     func;
    guint16    temp16;
    gboolean   end_tlv = FALSE;
    int loop_offset, start_offset;

    func = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_lltd_discovery_func, tvb, offset, 1, ENC_NA);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(func, lltd_discovery_vals, "Unknown (0x%02x)"));
    offset++;

    /* Demultiplex header */
    header_tree = proto_tree_add_subtree(tree, tvb, offset, 14, ett_base_header, &header_item, "Base header");

    proto_tree_add_item(header_tree, hf_lltd_discovery_real_dest_addr, tvb, offset, 6, ENC_NA);
    proto_tree_add_item(header_tree, hf_lltd_discovery_real_src_addr, tvb, offset+6, 6, ENC_NA);
    if (func == 0)
        proto_tree_add_item(header_tree, hf_lltd_discovery_xid, tvb, offset+12, 2, ENC_BIG_ENDIAN);
    else
        proto_tree_add_item(header_tree, hf_lltd_discovery_seq_num, tvb, offset+12, 2, ENC_BIG_ENDIAN);

    switch(func)
    {
    case 0x00: /* Discover */
        proto_tree_add_item(tree, hf_lltd_discover_gen_num, tvb, offset+14, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_lltd_discover_num_stations, tvb, offset+16, 2, ENC_BIG_ENDIAN);
        temp16 = tvb_get_ntohs(tvb, offset+16);
        if (temp16 > 0)
        {
            func_tree = proto_tree_add_subtree(tree, tvb, offset+18, temp16*6, ett_discover_stations, NULL, "Stations");
            for (loop_offset = 0; loop_offset < temp16*6; loop_offset += 6)
                proto_tree_add_item(func_tree, hf_lltd_discover_station, tvb, offset+18+loop_offset, 6, ENC_NA);
        }
        break;
    case 0x01: /* Hello */
        proto_tree_add_item(tree, hf_lltd_hello_gen_num, tvb, offset+14, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_lltd_hello_current_address, tvb, offset+16, 6, ENC_NA);
        proto_tree_add_item(tree, hf_lltd_hello_apparent_address, tvb, offset+22, 6, ENC_NA);

        func_tree = proto_tree_add_subtree(tree, tvb, offset+28, 0, ett_tlv, &func_item, "TLVs");
        start_offset = loop_offset = offset+28;
        while ((end_tlv == FALSE) && (tvb_reported_length_remaining(tvb, loop_offset) >= 1))
        {
            loop_offset += dissect_lltd_tlv(tvb, pinfo, func_tree, loop_offset, &end_tlv);
        }
        proto_item_set_len(func_item, loop_offset-start_offset);
        break;
    case 0x02: /* Emit */
        proto_tree_add_item(tree, hf_lltd_emit_num_descs, tvb, offset+14, 2, ENC_BIG_ENDIAN);
        temp16 = tvb_get_ntohs(tvb, offset+14);
        if (temp16 > 0)
        {
            func_tree = proto_tree_add_subtree(tree, tvb, offset+16, temp16*14, ett_emitee_descs, NULL, "EmiteeDescs");
            for (loop_offset = 0; loop_offset < temp16*14; loop_offset += 14)
            {
                func_subtree = proto_tree_add_subtree(func_tree, tvb, offset+16+loop_offset, 14, ett_emitee_descs_item, NULL, "EmiteeDescs Item");

                proto_tree_add_item(func_subtree, hf_lltd_emit_type, tvb, offset+16+loop_offset, 1, ENC_NA);
                proto_tree_add_item(func_subtree, hf_lltd_emit_pause, tvb, offset+16+loop_offset+1, 1, ENC_NA);
                proto_tree_add_item(func_subtree, hf_lltd_emit_src_addr, tvb, offset+16+loop_offset+2, 6, ENC_NA);
                proto_tree_add_item(func_subtree, hf_lltd_emit_dest_addr, tvb, offset+16+loop_offset+8, 6, ENC_NA);
            }
        }
        break;
    case 0x07: /* QueryResp */
        proto_tree_add_item(tree, hf_lltd_queryresp_more_descs, tvb, offset+14, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_lltd_queryresp_memory_descs, tvb, offset+14, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_lltd_queryresp_num_descs, tvb, offset+14, 2, ENC_BIG_ENDIAN);
        temp16 = tvb_get_ntohs(tvb, offset+14) & LLTD_QUERY_RESP_NUM_DESCS_MASK;
        if (temp16 > 0)
        {
            func_tree = proto_tree_add_subtree(tree, tvb, offset+16, temp16*20, ett_recvee_descs, NULL, "RecveeDescs");
            for (loop_offset = 0; loop_offset < temp16*14; loop_offset += 20)
            {
                func_subtree = proto_tree_add_subtree(func_tree, tvb, offset+16+loop_offset, 20,
                                                    ett_recvee_descs_item, NULL, "RecveeDescs Item");

                proto_tree_add_item(func_subtree, hf_lltd_queryresp_type, tvb, offset+16+loop_offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(func_subtree, hf_lltd_queryresp_real_src_addr, tvb, offset+16+loop_offset+2, 6, ENC_NA);
                proto_tree_add_item(func_subtree, hf_lltd_queryresp_ethernet_src_addr, tvb, offset+16+loop_offset+8, 6, ENC_NA);
                proto_tree_add_item(func_subtree, hf_lltd_queryresp_ethernet_dest_addr, tvb, offset+16+loop_offset+14, 6, ENC_NA);
            }
        }
        break;
    case 0x0A: /* Flat */
        proto_tree_add_item(tree, hf_lltd_flat_crc_bytes, tvb, offset+14, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_lltd_flat_crc_packets, tvb, offset+18, 1, ENC_BIG_ENDIAN);
        break;
    case 0x0B: /* QueryLargeTlv */
        proto_tree_add_item(tree, hf_lltd_query_large_tlv_type, tvb, offset+14, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_lltd_query_large_tlv_offset, tvb, offset+15, 3, ENC_BIG_ENDIAN);
        break;
    case 0x0C: /* QueryLargeTlvResp */
        proto_tree_add_item(tree, hf_lltd_querylargeresp_more_descs, tvb, offset+14, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_lltd_querylargeresp_memory_descs, tvb, offset+14, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_lltd_querylargeresp_num_descs, tvb, offset+14, 2, ENC_BIG_ENDIAN);
        temp16 = tvb_get_ntohs(tvb, offset+14) & LLTD_QUERY_RESP_NUM_DESCS_MASK;
        if (temp16 > 0)
            proto_tree_add_item(tree, hf_lltd_querylargeresp_data, tvb, offset+16, temp16, ENC_NA);
        break;
    case 0x03: /* Train */
    case 0x04: /* Probe */
    case 0x05: /* Ack */
    case 0x06: /* Query */
    case 0x08: /* Reset */
    case 0x09: /* Charge */
         /* No data */
        break;
    default:
        expert_add_info_format(pinfo, header_item, &ei_lltd_discovery_func, "Invalid function 0x%02x", func);
        break;
    }
}

static void
dissect_lltd_qos(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_item *header_item;
    proto_tree *header_tree, *func_tree, *func_subtree;
    guint8     func;
    guint16    seq_num, temp16;
    int loop_offset;

    func = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_lltd_qos_diag_func, tvb, offset, 1, ENC_NA);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(func, lltd_qos_diag_vals, "Unknown (0x%02x)"));
    offset++;

    header_tree = proto_tree_add_subtree(tree, tvb, offset, 14, ett_base_header, &header_item, "Base header");

    proto_tree_add_item(header_tree, hf_lltd_qos_real_dest_addr, tvb, offset, 6, ENC_NA);
    proto_tree_add_item(header_tree, hf_lltd_qos_real_src_addr, tvb, offset+6, 6, ENC_NA);
    proto_tree_add_item(header_tree, hf_lltd_qos_seq_num, tvb, offset+12, 2, ENC_BIG_ENDIAN);
    seq_num = tvb_get_ntohs(tvb, offset+12);

    switch(func)
    {
    case 0x00: /* QosInitializeSink */
        proto_tree_add_item(tree, hf_lltd_qos_initialize_interrupt_mod, tvb, offset+14, 1, ENC_BIG_ENDIAN);
        break;
    case 0x01: /* QosReady */
        proto_tree_add_item(tree, hf_lltd_qos_ready_sink_link_speed, tvb, offset+14, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_lltd_qos_ready_perf_count_freq, tvb, offset+18, 8, ENC_BIG_ENDIAN);
        break;
    case 0x02: /* QosProbe */
        proto_tree_add_item(tree, hf_lltd_qos_probe_controller_transmit_timestamp, tvb, offset+14, 8, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_lltd_qos_probe_sink_receive_timestamp, tvb, offset+22, 8, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_lltd_qos_probe_sink_transmit_timestamp, tvb, offset+30, 8, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_lltd_qos_probe_test_type, tvb, offset+38, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_lltd_qos_probe_packet_id, tvb, offset+39, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_lltd_qos_probe_t, tvb, offset+40, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_lltd_qos_probe_8021p_value, tvb, offset+40, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_lltd_qos_probe_payload, tvb, offset+41, 5, ENC_NA);
        break;
    case 0x03: /* QosQuery */
    case 0x07: /* QosAck */
        if (seq_num == 0)
            expert_add_info(pinfo, header_item, &ei_lltd_qos_seq_num);
        /* No Data */
        break;
    case 0x04: /* QosQueryResp */
        proto_tree_add_item(tree, hf_lltd_qos_query_resp_r, tvb, offset+14, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_lltd_qos_query_resp_e, tvb, offset+14, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_lltd_qos_query_resp_num_events, tvb, offset+14, 2, ENC_BIG_ENDIAN);
        temp16 = tvb_get_ntohs(tvb, offset+14) & LLTD_QUERY_RESP_NUM_DESCS_MASK;
        if (temp16 > 0)
        {
            func_tree = proto_tree_add_subtree(tree, tvb, offset+16, temp16*18, ett_qos_event_descs, NULL, "QosEventDesc");
            for (loop_offset = 0; loop_offset < temp16*18; loop_offset += 18)
            {
                func_subtree = proto_tree_add_subtree(func_tree, tvb, offset+16+loop_offset, 18, ett_qos_event_item, NULL, "Qos Event");

                proto_tree_add_item(func_subtree, hf_lltd_qos_query_resp_controller_timestamp, tvb, offset+16+loop_offset, 8, ENC_BIG_ENDIAN);
                proto_tree_add_item(func_subtree, hf_lltd_qos_query_resp_sink_timestamp, tvb, offset+16+loop_offset+8, 8, ENC_BIG_ENDIAN);
                proto_tree_add_item(func_subtree, hf_lltd_qos_query_resp_packet_id, tvb, offset+16+loop_offset+16, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(func_subtree, hf_lltd_qos_query_resp_reserved, tvb, offset+16+loop_offset+17, 1, ENC_BIG_ENDIAN);
            }
        }
        break;
    case 0x05: /* QosReset */
        /* No Data */
        break;
    case 0x06: /* QosError */
        proto_tree_add_item(tree, hf_lltd_qos_error_value, tvb, offset+14, 2, ENC_BIG_ENDIAN);
        break;
    case 0x08: /* QosCounterSnapshot */
        if (seq_num == 0)
            expert_add_info(pinfo, header_item, &ei_lltd_qos_seq_num);
        proto_tree_add_item(tree, hf_lltd_qos_count_snapshot_history, tvb, offset+14, 1, ENC_BIG_ENDIAN);
        break;
    case 0x09: /* QosCounterResult */
        proto_tree_add_item(tree, hf_lltd_qos_counter_result_subsec_span, tvb, offset+14, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_lltd_qos_counter_result_byte_scale, tvb, offset+15, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_lltd_qos_counter_result_packet_scale, tvb, offset+16, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_lltd_qos_counter_result_history_size, tvb, offset+17, 1, ENC_BIG_ENDIAN);
        temp16 = tvb_get_guint8(tvb, offset+17);
        if (temp16 > 0)
        {
            func_tree = proto_tree_add_subtree(tree, tvb, offset+18, temp16*4, ett_qos_snapshot_list, NULL, "Snapshot List");
            for (loop_offset = 0; loop_offset < temp16*4; loop_offset += 4)
            {
                func_subtree = proto_tree_add_subtree(func_tree, tvb, offset+18+loop_offset, 4, ett_qos_snapshot_item, NULL, "Snapshot");

                proto_tree_add_item(func_subtree, hf_lltd_qos_snapshot_bytes_recv, tvb, offset+16+loop_offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(func_subtree, hf_lltd_qos_snapshot_packets_recv, tvb, offset+16+loop_offset+2, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(func_subtree, hf_lltd_qos_snapshot_bytes_sent, tvb, offset+16+loop_offset+4, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(func_subtree, hf_lltd_qos_snapshot_packets_sent, tvb, offset+16+loop_offset+6, 2, ENC_BIG_ENDIAN);
            }
        }
        break;
    case 0x0A: /* QosCounterLease */
        /* No Data */
        break;
    default:
        expert_add_info_format(pinfo, header_item, &ei_lltd_qos_diag_func, "Invalid function 0x%02x", func);
        break;
    }
}

static int
dissect_lltd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *lltd_tree;
    guint8     tos;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LLTD");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_lltd, tvb, 0, -1, ENC_NA);
    lltd_tree = proto_item_add_subtree(ti, ett_lltd);

    proto_tree_add_item(lltd_tree, hf_lltd_version, tvb, 0, 1, ENC_NA);
    proto_tree_add_item(lltd_tree, hf_lltd_type_of_service, tvb, 1, 1, ENC_NA);
    tos = tvb_get_guint8(tvb, 1);
    proto_tree_add_item(lltd_tree, hf_lltd_reserved, tvb, 2, 1, ENC_NA);

    switch(tos)
    {
    case 0: /* Topology discovery */
    case 1: /* Quick discovery */
        dissect_lltd_discovery(tvb, pinfo, lltd_tree, 3);
        break;

    case 2: /* QoS Diagnostics */
        dissect_lltd_qos(tvb, pinfo, lltd_tree, 3);
        break;

    default:
        expert_add_info_format(pinfo, ti, &ei_lltd_type_of_service, "Invalid Type of Service value 0x%02x", tos);
        break;
    }

    return tvb_captured_length(tvb);
}

void
proto_register_lltd(void)
{
    static hf_register_info hf[] = {

        { &hf_lltd_version, {"Version", "lltd.version", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_type_of_service, {"Type of Service", "lltd.tos", FT_UINT8, BASE_HEX, VALS(lltd_tos_vals), 0, NULL, HFILL }},
        { &hf_lltd_reserved, {"Reserved", "lltd.reserved", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lltd_discovery_func, {"Discovery function", "lltd.discovery", FT_UINT8, BASE_HEX, VALS(lltd_discovery_vals), 0, NULL, HFILL }},
        { &hf_lltd_discovery_real_dest_addr, { "Real Destination Address", "lltd.discovery.real_dest_addr", FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lltd_discovery_real_src_addr, { "Real Source Address", "lltd.discovery.real_src_addr", FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lltd_discovery_xid, {"XID", "lltd.discovery.xid", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lltd_discovery_seq_num, {"Sequence Number", "lltd.discovery.seq_num", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lltd_discover_gen_num, {"Generation Number", "lltd.discover.gen_num", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lltd_discover_num_stations, {"Number of Stations", "lltd.discover.num_stations", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_discover_station, { "Station", "lltd.discover.station", FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lltd_hello_gen_num, {"Generation Number", "lltd.hello.gen_num", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lltd_hello_current_address, { "Current Mapper Address", "lltd.hello.current_address", FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lltd_hello_apparent_address, { "Current Apparent Address", "lltd.hello.apparent_address", FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lltd_tlv_type, {"Type", "lltd.tlv.type", FT_UINT8, BASE_HEX, VALS(lltd_tlv_type_vals), 0, NULL, HFILL }},
        { &hf_lltd_tlv_length, {"Length", "lltd.tlv.length", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_host_id, { "Host ID", "lltd.host_id", FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lltd_char_p, {"Public NAT", "lltd.characteristic.public_nat", FT_BOOLEAN, 32, TFS(&tfs_true_false), LLTD_CHARACTERISTIC_P_MASK, NULL, HFILL }},
        { &hf_lltd_char_x, {"Private NAT", "lltd.characteristic.private_nat", FT_BOOLEAN, 32, TFS(&tfs_true_false), LLTD_CHARACTERISTIC_X_MASK, NULL, HFILL }},
        { &hf_lltd_char_f, {"Duplex", "lltd.characteristic.duplex", FT_BOOLEAN, 32, TFS(&tfs_full_half_duplex), LLTD_CHARACTERISTIC_F_MASK, NULL, HFILL }},
        { &hf_lltd_char_m, {"Management Web Page", "lltd.characteristic.web_page", FT_BOOLEAN, 32, TFS(&tfs_present_absent), LLTD_CHARACTERISTIC_M_MASK, NULL, HFILL }},
        { &hf_lltd_char_l, {"Looping Outbound Packets", "lltd.characteristic.loop", FT_BOOLEAN, 32, TFS(&tfs_true_false), LLTD_CHARACTERISTIC_L_MASK, NULL, HFILL }},
        { &hf_lltd_char_reserved, {"Reserved", "lltd.characteristic.reserved", FT_UINT32, BASE_HEX, NULL, LLTD_CHARACTERISTIC_RESERVE_MASK, NULL, HFILL }},
        { &hf_lltd_physical_medium, {"Physical Medium", "lltd.physical_medium", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_wireless_mode, {"Wireless Mode", "lltd.wireless_mode", FT_UINT8, BASE_HEX, VALS(lltd_wireless_mode_vals), 0, NULL, HFILL }},
        { &hf_lltd_bssid, { "BSSID", "lltd.bssid", FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lltd_ssid, { "SSID", "lltd.ssid", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lltd_ipv4_address, { "IPv4 Address", "lltd.ipv4_address", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lltd_ipv6_address, { "IPv6 Address", "lltd.ipv6_address", FT_IPv6, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lltd_max_operation_rate, {"Maximum Operational Rate (.5 Mbps)", "lltd.max_operation_rate", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_performance_count_freq, {"Performance Counter Frequency", "lltd.performance_count_freq", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_link_speed, {"Link Speed (100 bps)", "lltd.link_speed", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_rssi, {"RSSI", "lltd.rssi", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_machine_name, { "Machine Name", "lltd.machine_name", FT_STRING /*FT_UCS2_LE */, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lltd_support_info, { "Support Information", "lltd.support_info", FT_STRING /*FT_UCS2_LE */, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lltd_device_uuid, { "Device UUID", "lltd.device_uuid", FT_GUID, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lltd_qos_char_e, {"Layer 2 Forwarding", "lltd.qos_characteristic.layer2_forwarding", FT_BOOLEAN, 32, TFS(&tfs_true_false), LLTD_QOS_CHARACTERISTIC_E_MASK, NULL, HFILL }},
        { &hf_lltd_qos_char_q, {"802.1q VLAN", "lltd.qos_characteristic.vlan", FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), LLTD_QOS_CHARACTERISTIC_Q_MASK, NULL, HFILL }},
        { &hf_lltd_qos_char_p, {"802.1q Priority Tagging", "lltd.qos_characteristic.tagging", FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), LLTD_QOS_CHARACTERISTIC_P_MASK, NULL, HFILL }},
        { &hf_lltd_qos_char_reserved, {"Reserved", "lltd.qos_characteristic.reserved", FT_UINT32, BASE_HEX, NULL, LLTD_QOS_CHARACTERISTIC_RESERVE_MASK, NULL, HFILL }},
        { &hf_lltd_80211_physical_medium, {"802.11 Physical Medium", "lltd.80211_physical_medium", FT_UINT8, BASE_HEX, VALS(lltd_80211_physical_medium_vals), 0, NULL, HFILL }},
        { &hf_lltd_sees_list_working_set, {"Sees-List Working Set", "lltd.sees_list_working_set", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_repeater_ap_lineage, { "Address Path to Root", "lltd.address_path_to_root", FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lltd_emit_num_descs, {"Number of EmiteeDescs", "lltd.emit.num_descs", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_emit_type, {"Type", "lltd.emit.type", FT_UINT8, BASE_HEX, VALS(lltd_emit_type_vals), 0, NULL, HFILL }},
        { &hf_lltd_emit_pause, {"Pause (ms)", "lltd.emit.pause", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_emit_src_addr, { "Source Address", "lltd.emit.src_addr", FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lltd_emit_dest_addr, { "Destination Address", "lltd.emit.dest_addr", FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lltd_queryresp_more_descs, {"More RecveeDescs", "lltd.queryresp.more", FT_BOOLEAN, 16, TFS(&tfs_true_false), LLTD_QUERY_RESP_M_MASK, NULL, HFILL }},
        { &hf_lltd_queryresp_memory_descs, {"No memory left", "lltd.queryresp.memory", FT_BOOLEAN, 16, TFS(&tfs_true_false), LLTD_QUERY_RESP_E_MASK, NULL, HFILL }},
        { &hf_lltd_queryresp_num_descs, {"Number of RecveeDescs", "lltd.queryresp.num_descs", FT_UINT16, BASE_DEC, NULL, LLTD_QUERY_RESP_NUM_DESCS_MASK, NULL, HFILL }},
        { &hf_lltd_queryresp_type, {"Type", "lltd.queryresp.type", FT_UINT16, BASE_HEX, VALS(lltd_queryresp_type_vals), 0, NULL, HFILL }},
        { &hf_lltd_queryresp_real_src_addr, { "Real Source Address", "lltd.queryresp.real_src_addr", FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lltd_queryresp_ethernet_src_addr, { "Ethernet Source Address", "lltd.queryresp.ethernet_src_addr", FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lltd_queryresp_ethernet_dest_addr, { "Ethernet Destination Address", "lltd.queryresp.ethernet_dest_addr", FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lltd_flat_crc_bytes, {"Current Transmit Credit (bytes)", "lltd.flat.crc_bytes", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_flat_crc_packets, {"Current Transmit Credit (packets)", "lltd.flat.crc_packets", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_query_large_tlv_type, {"Type", "lltd.query_large_tlv.type", FT_UINT8, BASE_HEX, VALS(lltd_query_large_tlv_type_vals), 0, NULL, HFILL }},
        { &hf_lltd_query_large_tlv_offset, {"Offset", "lltd.query_large_tlv.offset", FT_UINT24, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_querylargeresp_more_descs, {"More RecveeDescs", "lltd.querylargeresp.more", FT_BOOLEAN, 16, TFS(&tfs_true_false), LLTD_QUERY_RESP_M_MASK, NULL, HFILL }},
        { &hf_lltd_querylargeresp_memory_descs, {"No memory left", "lltd.querylargeresp.memory", FT_BOOLEAN, 16, TFS(&tfs_true_false), LLTD_QUERY_RESP_E_MASK, NULL, HFILL }},
        { &hf_lltd_querylargeresp_num_descs, {"Number of RecveeDescs", "lltd.querylargeresp.num_descs", FT_UINT16, BASE_DEC, NULL, LLTD_QUERY_RESP_NUM_DESCS_MASK, NULL, HFILL }},
        { &hf_lltd_querylargeresp_data, { "Data", "lltd.querylargeresp.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

        { &hf_lltd_qos_diag_func, {"QoS Diagnostics function", "lltd.qos_diag", FT_UINT8, BASE_HEX, VALS(lltd_qos_diag_vals), 0, NULL, HFILL }},
        { &hf_lltd_qos_real_dest_addr, { "Real Destination Address", "lltd.qos.real_dest_addr", FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lltd_qos_real_src_addr, { "Real Source Address", "lltd.qos.real_src_addr", FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lltd_qos_seq_num, {"Sequence Number", "lltd.qos.seq_num", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lltd_qos_initialize_interrupt_mod, {"Interrupt Mod", "lltd.qos_initialize.interrupt_mod", FT_UINT8, BASE_HEX, VALS(lltd_interrupt_mod_vals), 0, NULL, HFILL }},
        { &hf_lltd_qos_ready_sink_link_speed, {"Sink Link Speed (100 bps)", "lltd.qos_ready.sink_link_speed", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_qos_ready_perf_count_freq, {"Performance Counter Frequency", "lltd.qos_ready.performance_count_freq", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_qos_probe_controller_transmit_timestamp, {"Controller Transmit Timestamp", "lltd.qos_probe.controller_transmit_timestamp", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_qos_probe_sink_receive_timestamp, {"Sink Receive Timestamp", "lltd.qos_probe.sink_receive_timestamp", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_qos_probe_sink_transmit_timestamp, {"Sink Transmit Timestamp", "lltd.qos_probe.sink_transmit_timestamp", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_qos_probe_test_type, {"Test Type", "lltd.qos_probe.test_type", FT_UINT8, BASE_HEX, VALS(lltd_qos_probe_test_type_vals), 0, NULL, HFILL }},
        { &hf_lltd_qos_probe_packet_id, {"Packet ID", "lltd.qos_probe.packet_id", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lltd_qos_probe_t, {"802.1p Tag", "lltd.qos_probe.tag", FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x80, NULL, HFILL }},
        { &hf_lltd_qos_probe_8021p_value, {"802.1p Value", "lltd.qos_probe.value", FT_UINT8, BASE_DEC, NULL, 0x7F, NULL, HFILL }},
        { &hf_lltd_qos_probe_payload, {"Payload", "lltd.qos_probe.payload", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lltd_qos_error_value, {"Error Code", "lltd.qos_error", FT_UINT16, BASE_DEC, VALS(lltd_qos_error_vals), 0, NULL, HFILL }},
        { &hf_lltd_qos_count_snapshot_history, {"History Size", "lltd.qos_count_snapshot.history", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_qos_query_resp_r, {"Receipt", "lltd.qos_query_resp.receipt", FT_BOOLEAN, 16, TFS(&tfs_true_false), LLTD_QUERY_RESP_M_MASK, NULL, HFILL }},
        { &hf_lltd_qos_query_resp_e, {"No memory left", "lltd.qos_query_resp.memory", FT_BOOLEAN, 16, TFS(&tfs_true_false), LLTD_QUERY_RESP_E_MASK, NULL, HFILL }},
        { &hf_lltd_qos_query_resp_num_events, {"Number of Events", "lltd.qos_query_resp.num_events", FT_UINT16, BASE_DEC, NULL, LLTD_QUERY_RESP_NUM_DESCS_MASK, NULL, HFILL }},
        { &hf_lltd_qos_query_resp_controller_timestamp, {"Controller Transmit Timestamp", "lltd.qos_query_resp.controller_timestamp", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_qos_query_resp_sink_timestamp, {"Sink Receive Timestamp", "lltd.qos_query_resp.sink_timestamp", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_qos_query_resp_packet_id, {"Packet ID", "lltd.qos_query_resp.packet_id", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lltd_qos_query_resp_reserved, {"Reserved", "lltd.qos_query_resp.reserved", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lltd_qos_counter_result_subsec_span, {"Subsecond Span (1/256th sec)", "lltd.qos_counter_result.subsec_span", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_qos_counter_result_byte_scale, {"Byte Scale (kb)", "lltd.qos_counter_result.byte_scale", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_qos_counter_result_packet_scale, {"Packet Scale", "lltd.qos_counter_result.packet_scale", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_qos_counter_result_history_size, {"History Size", "lltd.qos_counter_result.history_size", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_qos_snapshot_bytes_recv, {"Bytes Received", "lltd.qos_snapshot.bytes_recv", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_qos_snapshot_packets_recv, {"Packets Received", "lltd.qos_snapshot.packets_recv", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_qos_snapshot_bytes_sent, {"Bytes Sent", "lltd.qos_snapshot.bytes_sent", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lltd_qos_snapshot_packets_sent, {"Packets Sent", "lltd.qos_snapshot.packets_sent", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }}
    };

    static gint *ett[] = {
        &ett_lltd,
        &ett_base_header,
        &ett_discover_stations,
        &ett_tlv,
        &ett_tlv_item,
        &ett_characteristics,
        &ett_qos_characteristics,
        &ett_repeater_ap_lineage,
        &ett_emitee_descs,
        &ett_emitee_descs_item,
        &ett_recvee_descs,
        &ett_recvee_descs_item,
        &ett_qos_event_descs,
        &ett_qos_event_item,
        &ett_qos_snapshot_list,
        &ett_qos_snapshot_item
    };

    static ei_register_info ei[] = {
        { &ei_lltd_tlv_length_invalid, { "lltd.tlv.length.invalid", PI_MALFORMED, PI_ERROR, "Invalid length", EXPFILL }},
        { &ei_lltd_char_reserved, { "lltd.characteristic.reserved.not_zero", PI_PROTOCOL, PI_WARN, "Non zero reserve bits", EXPFILL }},
        { &ei_lltd_too_many_paths, { "lltd.too_many_paths", PI_PROTOCOL, PI_WARN, "Too many paths to root", EXPFILL }},
        { &ei_lltd_tlv_type, { "lltd.tlv.type.invalid", PI_PROTOCOL, PI_WARN, "Invalid TLV Type 0x%02x", EXPFILL }},
        { &ei_lltd_discovery_func, { "lltd.discovery.invalid", PI_PROTOCOL, PI_WARN, "Invalid function 0x%02x", EXPFILL }},
        { &ei_lltd_qos_seq_num, { "lltd.qos.seq_num.cannot_be_zero", PI_PROTOCOL, PI_WARN, "Sequence number can not be 0", EXPFILL }},
        { &ei_lltd_qos_diag_func, { "lltd.qos_diag.invalid", PI_PROTOCOL, PI_WARN, "Invalid function 0x%02x", EXPFILL }},
        { &ei_lltd_type_of_service, { "lltd.tos.invalid", PI_PROTOCOL, PI_WARN, "Invalid Type of Service value 0x%02x", EXPFILL }},
    };

    expert_module_t* expert_lltd;

    proto_lltd = proto_register_protocol("Link Layer Topology Discovery", "LLTD", "lltd");
    proto_register_field_array(proto_lltd, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_lltd = expert_register_protocol(proto_lltd);
    expert_register_field_array(expert_lltd, ei, array_length(ei));
}

void
proto_reg_handoff_lltd(void)
{
    dissector_handle_t lltd_handle;
    lltd_handle = create_dissector_handle(dissect_lltd, proto_lltd);
    dissector_add_uint("ethertype", ETHERTYPE_LLTD, lltd_handle);
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

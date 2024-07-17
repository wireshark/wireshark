/* packet-btbredr_rf.c
 * Routines for Bluetooth Pseudoheader for BR/EDR Baseband
 *
 * Copyright 2020, Thomas Sailer <t.sailer@alumni.ethz.ch>
 * Copyright 2014, Michal Labedzki for Tieto Corporation
 * Copyright 2014, Dominic Spill <dominicgs@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/reassemble.h>

#include <wiretap/wtap.h>

#include "packet-bluetooth.h"
#include "packet-btbredr_rf.h"
#include "packet-bthci_acl.h"

/*
 * Future Improvements:
 * - De-Whiten if the capture hardware did not already do it and we have the UAP
 */

static int proto_btbredr_rf;
static int proto_btbredr_fhs;

static int hf_rf_channel;
static int hf_uncertain_rf_channel;
static int hf_signal_power;
static int hf_invalid_signal_power;
static int hf_noise_power;
static int hf_invalid_noise_power;
static int hf_access_address_offenses;
static int hf_payload_transport_rate;
static int hf_payload_transport_rate_payload;
static int hf_payload_transport_rate_transport;
static int hf_payload_transport_rate_ignored;
static int hf_corrected_header_bits;
static int hf_corrected_payload_bits;
static int hf_lower_address_part;
static int hf_reference_lower_address_part;
static int hf_invalid_reference_lower_address_part;
static int hf_reference_upper_addres_part;
static int hf_invalid_reference_upper_addres_part;
static int hf_whitened_packet_header;
static int hf_invalid_packet_header;
static int hf_packet_header;
static int hf_packet_header_reserved;
static int hf_packet_header_lt_addr;
static int hf_packet_header_type;
static int hf_packet_header_type_any;
static int hf_packet_header_type_sco_br;
static int hf_packet_header_type_esco_br;
static int hf_packet_header_type_esco_edr;
static int hf_packet_header_type_acl_br;
static int hf_packet_header_type_acl_edr;
static int hf_packet_header_type_cpb_br;
static int hf_packet_header_type_cpb_edr;
static int hf_packet_header_flow_control;
static int hf_packet_header_acknowledge_indication;
static int hf_packet_header_sequence_number;
static int hf_packet_header_header_error_check;
static int hf_packet_header_broken_lt_addr;
static int hf_packet_header_broken_type;
static int hf_packet_header_broken_type_any;
static int hf_packet_header_broken_type_sco_br;
static int hf_packet_header_broken_type_esco_br;
static int hf_packet_header_broken_type_esco_edr;
static int hf_packet_header_broken_type_acl_br;
static int hf_packet_header_broken_type_acl_edr;
static int hf_packet_header_broken_type_cpb_br;
static int hf_packet_header_broken_type_cpb_edr;
static int hf_packet_header_broken_flow_control;
static int hf_packet_header_broken_acknowledge_indication;
static int hf_packet_header_broken_sequence_number;
static int hf_packet_header_broken_header_error_check;
static int hf_flags;
static int hf_flags_reserved_15_14;
static int hf_flags_mic_pass;
static int hf_flags_mic_checked;
static int hf_flags_crc_pass;
static int hf_flags_crc_checked;
static int hf_flags_hec_pass;
static int hf_flags_hec_checked;
static int hf_flags_reference_upper_addres_part_valid;
static int hf_flags_rf_channel_aliasing;
static int hf_flags_br_edr_data_present;
static int hf_flags_reference_lower_address_part_valid;
static int hf_flags_bredr_payload_decrypted;
static int hf_flags_noise_power_valid;
static int hf_flags_signal_power_valid;
static int hf_flags_packet_header_and_br_edr_payload_dewhitened;
static int hf_whitened_data;
static int hf_encrypted_data;
static int hf_data;
static int hf_isochronous_data;
static int hf_asynchronous_data;
static int hf_l2cap_fragment;
static int hf_crc;
static int hf_payload_header2;
static int hf_payload_header2_llid;
static int hf_payload_header2_flow;
static int hf_payload_header2_length;
static int hf_payload_header2_rfu;
static int hf_payload_header1;
static int hf_payload_header1_llid;
static int hf_payload_header1_flow;
static int hf_payload_header1_length;
static int hf_l2cap_msg_fragments;
static int hf_l2cap_msg_fragment;
static int hf_l2cap_msg_fragment_overlap;
static int hf_l2cap_msg_fragment_overlap_conflicts;
static int hf_l2cap_msg_fragment_multiple_tails;
static int hf_l2cap_msg_fragment_too_long_fragment;
static int hf_l2cap_msg_fragment_error;
static int hf_l2cap_msg_fragment_count;
static int hf_l2cap_msg_reassembled_in;
static int hf_l2cap_msg_reassembled_length;
static int hf_fhs_parity;
static int hf_fhs_lap;
static int hf_fhs_eir;
static int hf_fhs_reserved;
static int hf_fhs_sr;
static int hf_fhs_sp;
static int hf_fhs_uap;
static int hf_fhs_nap;
static int hf_fhs_class;
static int hf_fhs_ltaddr;
static int hf_fhs_clk;
static int hf_fhs_pagescanmode;

#define FLAGS_MIC_PASS                                      0x2000
#define FLAGS_MIC_CHECKED                                   0x1000
#define FLAGS_CRC_PASS                                      0x0800
#define FLAGS_CRC_CHECKED                                   0x0400
#define FLAGS_HEC_PASS                                      0x0200
#define FLAGS_HEC_CHECKED                                   0x0100
#define FLAGS_REFERENCE_UPPER_ADDRES_PART_VALID             0x0080
#define FLAGS_RF_CHANNEL_ALIASING                           0x0040
#define FLAGS_BR_EDR_DATA_PRESENT                           0x0020
#define FLAGS_REFERENCE_LOWER_ADDRESS_PART_VALID            0x0010
#define FLAGS_BREDR_PAYLOAD_DECRYPTED                       0x0008
#define FLAGS_NOISE_POWER_VALID                             0x0004
#define FLAGS_SIGNAL_POWER_VALID                            0x0002
#define FLAGS_PACKET_HEADER_AND_BR_EDR_PAYLOAD_DEWHITENED   0x0001

static int * const hfx_payload_transport_rate[] = {
    &hf_payload_transport_rate_payload,
    &hf_payload_transport_rate_transport,
    NULL
};

static expert_field ei_unexpected_data;
static expert_field ei_reserved_not_zero;
static expert_field ei_incorrect_packet_header_or_hec;
static expert_field ei_packet_header_with_hec_not_checked;
static expert_field ei_broken_packet_header_format;
static expert_field ei_incorrect_crc;
static expert_field ei_missing_fragment_start;
static expert_field ei_esco_incorrect_ltaddr;
static expert_field ei_esco_incorrect_length;

static int ett_btbredr_rf;
static int ett_flags;
static int ett_payload_transport_rate;
static int ett_packet_header;
static int ett_bluetooth_header;
static int ett_payload_header;
static int ett_l2cap_msg_fragment;
static int ett_l2cap_msg_fragments;
static int ett_btbredr_fhs;

static dissector_table_t  packet_type_sco_br_table;
static dissector_table_t  packet_type_esco_br_table;
static dissector_table_t  packet_type_esco_edr_table;
static dissector_table_t  packet_type_acl_br_table;
static dissector_table_t  packet_type_acl_edr_table;
static dissector_table_t  packet_type_cpb_br_table;
static dissector_table_t  packet_type_cpb_edr_table;

static dissector_handle_t btlmp_handle;
static dissector_handle_t btl2cap_handle;

static dissector_handle_t btbredr_rf_handle;
static dissector_handle_t btbredr_fhs_handle;

static wmem_tree_t *connection_info_tree;
static wmem_tree_t *device_info_tree;

typedef struct _device_info_t {
    uint32_t interface_id;
    uint32_t adapter_id;
    uint8_t  bd_addr[6];
    int8_t   dir;
} device_info_t;

#define BDADDR_CENTRAL  0
#define BDADDR_PERIPHERAL   1

typedef struct _btbredr_frame_info_t {
    unsigned retransmit : 1;      /* 0 = No, 1 = Retransmitted frame */
    unsigned ack : 1;             /* 0 = Nack, 1 = Ack */
    unsigned more_fragments : 1;  /* 0 = Last fragment, 1 = More fragments */
    unsigned missing_start : 1;   /* 0 = No, 1 = Missing fragment start */
    uint32_t l2cap_index;         /* Unique identifier for each L2CAP message */
} btbredr_frame_info_t;

typedef struct {
    bluetooth_data_t  *bluetooth_data;
    connection_info_t *connection_info;
    device_info_t     *device_info;
} btbredr_fhs_data_t;

static const uint8_t null_bd_addr[6] = { 0, 0, 0, 0, 0, 0 };

/* Reassembly */
static reassembly_table l2cap_msg_reassembly_table;

static const fragment_items l2cap_msg_frag_items = {
    /* Fragment subtrees */
    &ett_l2cap_msg_fragment,
    &ett_l2cap_msg_fragments,
    /* Fragment fields */
    &hf_l2cap_msg_fragments,
    &hf_l2cap_msg_fragment,
    &hf_l2cap_msg_fragment_overlap,
    &hf_l2cap_msg_fragment_overlap_conflicts,
    &hf_l2cap_msg_fragment_multiple_tails,
    &hf_l2cap_msg_fragment_too_long_fragment,
    &hf_l2cap_msg_fragment_error,
    &hf_l2cap_msg_fragment_count,
    /* Reassembled in field */
    &hf_l2cap_msg_reassembled_in,
    /* Reassembled length field */
    &hf_l2cap_msg_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "BT BR/EDR L2CAP fragments"
};

static const value_string payload_transport_rate_transport_vals[] = {
    { 0x00, "Any" },
    { 0x01, "SCO" },
    { 0x02, "eSCO" },
    { 0x03, "ACL" },
    { 0x04, "CPB" },
    { 0,    NULL }
};

#define TRANSPORT_ANY   0x00
#define TRANSPORT_SCO   0x10
#define TRANSPORT_eSCO  0x20
#define TRANSPORT_ACL   0x30
#define TRANSPORT_CPB   0x40


static const value_string payload_transport_rate_payload_vals[] = {
    { 0x00, "Basic Rate with GFSK demodulation" },
    { 0x01, "Enhanced Data Rate with PI/2-DQPSK demodulation" },
    { 0x02, "Enhanced Data Rate with 8DPSK demodulation" },
    { 0,    NULL }
};

static const value_string payload_transport_rate_payload_abbrev_vals[] = {
    { 0x00, "BR 1Mbps" },
    { 0x01, "EDR 2Mbps" },
    { 0x02, "EDR 3Mbps" },
    { 0,    NULL }
};

#define PAYLOAD_BR     0x00
#define PAYLOAD_EDR_2  0x01
#define PAYLOAD_EDR_3  0x02

#define PACKET_TYPE_UNKNOWN  -1

static const value_string packet_type_any_vals[] = {
    { 0x00, "NULL" },
    { 0x01, "POLL" },
    { 0x02, "FHS" },
    { 0x03, "DM1" },
    { 0x04, "DH1/2-DH1" },
    { 0x05, "HV1" },
    { 0x06, "HV2/2-EV3" },
    { 0x07, "HV3/EV3/3-EV3" },
    { 0x08, "DV/3-DH1" },
    { 0x09, "AUX1" },
    { 0x0A, "DM3/2-DH3" },
    { 0x0B, "DH3/3-DH3" },
    { 0x0C, "EV4/2-EV5" },
    { 0x0D, "EV5/3-EV5" },
    { 0x0E, "DM5/2-DH5" },
    { 0x0F, "DH5/3-DH5" },
    { 0,    NULL }
};

static const value_string packet_type_sco_br_vals[] = {
    { 0x00, "NULL" },
    { 0x01, "POLL" },
    { 0x02, "FHS" },
    { 0x03, "DM1" },
    { 0x04, "undefined" },
    { 0x05, "HV1" },
    { 0x06, "HV2" },
    { 0x07, "HV3" },
    { 0x08, "DV" },
    { 0x09, "undefined" },
    { 0x0A, "undefined" },
    { 0x0B, "undefined" },
    { 0x0C, "undefined" },
    { 0x0D, "undefined" },
    { 0x0E, "undefined" },
    { 0x0F, "undefined" },
    { 0,    NULL }
};

static const value_string packet_type_esco_br_vals[] = {
    { 0x00, "NULL" },
    { 0x01, "POLL" },
    { 0x02, "reserved" },
    { 0x03, "reserved" },
    { 0x04, "undefined" },
    { 0x05, "undefined" },
    { 0x06, "undefined" },
    { 0x07, "EV3" },
    { 0x08, "undefined" },
    { 0x09, "undefined" },
    { 0x0A, "undefined" },
    { 0x0B, "undefined" },
    { 0x0C, "EV4" },
    { 0x0D, "EV5" },
    { 0x0E, "undefined" },
    { 0x0F, "undefined" },
    { 0,    NULL }
};

static const value_string packet_type_esco_edr_vals[] = {
    { 0x00, "NULL" },
    { 0x01, "POLL" },
    { 0x02, "reserved" },
    { 0x03, "reserved" },
    { 0x04, "undefined" },
    { 0x05, "undefined" },
    { 0x06, "2-EV3" },
    { 0x07, "3-EV3" },
    { 0x08, "undefined" },
    { 0x09, "undefined" },
    { 0x0A, "undefined" },
    { 0x0B, "undefined" },
    { 0x0C, "2-EV5" },
    { 0x0D, "3-EV5" },
    { 0x0E, "undefined" },
    { 0x0F, "undefined" },
    { 0,    NULL }
};

static const value_string packet_type_acl_br_vals[] = {
    { 0x00, "NULL" },
    { 0x01, "POLL" },
    { 0x02, "FHS" },
    { 0x03, "DM1" },
    { 0x04, "DH1" },
    { 0x05, "undefined" },
    { 0x06, "undefined" },
    { 0x07, "undefined" },
    { 0x08, "undefined" },
    { 0x09, "AUX1" },
    { 0x0A, "DM3" },
    { 0x0B, "DH3" },
    { 0x0C, "undefined" },
    { 0x0D, "undefined" },
    { 0x0E, "DM5" },
    { 0x0F, "DH5" },
    { 0,    NULL }
};

static const value_string packet_type_acl_edr_vals[] = {
    { 0x00, "NULL" },
    { 0x01, "POLL" },
    { 0x02, "FHS" },
    { 0x03, "DM1" },
    { 0x04, "2-DH1" },
    { 0x05, "undefined" },
    { 0x06, "undefined" },
    { 0x07, "undefined" },
    { 0x08, "3-DH1" },
    { 0x09, "AUX1" },
    { 0x0A, "2-DH3" },
    { 0x0B, "3-DH3" },
    { 0x0C, "undefined" },
    { 0x0D, "undefined" },
    { 0x0E, "2-DH5" },
    { 0x0F, "3-DH5" },
    { 0,    NULL }
};

static const value_string packet_type_cpb_br_vals[] = {
    { 0x00, "NULL" },
    { 0x01, "reserved" },
    { 0x02, "reserved" },
    { 0x03, "DM1" },
    { 0x04, "DH1" },
    { 0x05, "undefined" },
    { 0x06, "undefined" },
    { 0x07, "undefined" },
    { 0x08, "undefined" },
    { 0x09, "undefined" },
    { 0x0A, "DM3" },
    { 0x0B, "DH3" },
    { 0x0C, "undefined" },
    { 0x0D, "undefined" },
    { 0x0E, "DM5" },
    { 0x0F, "DH5" },
    { 0,    NULL }
};

static const value_string packet_type_cpb_edr_vals[] = {
    { 0x00, "NULL" },
    { 0x01, "reserved" },
    { 0x02, "reserved" },
    { 0x03, "DM1" },
    { 0x04, "2-DH1" },
    { 0x05, "undefined" },
    { 0x06, "undefined" },
    { 0x07, "undefined" },
    { 0x08, "3-DH1" },
    { 0x09, "undefined" },
    { 0x0A, "2-DH3" },
    { 0x0B, "3-DH3" },
    { 0x0C, "undefined" },
    { 0x0D, "undefined" },
    { 0x0E, "2-DH5" },
    { 0x0F, "3-DH5" },
    { 0,    NULL }
};

static const val64_string fhs_scan_repetition_vals[] = {
    { 0x00, "R0" },
    { 0x01, "R1" },
    { 0x02, "R2" },
    { 0,    NULL }
};

static const value_string fhs_page_scan_mode_vals[] = {
    { 0x00, "Mandatory Scan Mode" },
    { 0,    NULL }
};

void proto_register_btbredr_rf(void);
void proto_reg_handoff_btbredr_rf(void);

static uint8_t
reverse_bits(uint8_t value)
{
    value = ((value >> 1) & 0x55) | ((value << 1) & 0xaa);
    value = ((value >> 2) & 0x33) | ((value << 2) & 0xcc);
    value = ((value >> 4) & 0x0f) | ((value << 4) & 0xf0);
    return value;
}

static bool
broken_check_hec(uint8_t uap, uint32_t header)
{
    uint8_t  hec;
    uint16_t header_data;
    uint8_t  lfsr;
    int8_t   i;

    hec = header & 0xFF;
    header_data = (header >> 8) & 0x3F;

    lfsr = uap;

    for (i = 9; i >= 0; i -= 1) {
        if (lfsr & 0x80)
            lfsr ^= 0x65;

        lfsr = (lfsr << 1) | (((lfsr >> 7) ^ (header_data >> i)) & 0x01);
    }

    lfsr = reverse_bits(lfsr);

    return lfsr == hec;
}

static bool
check_hec(uint8_t uap, uint32_t header)
{
    static const uint32_t crc_poly_rev_bt_hec = 0xe5;
    header &= 0x3ffff;
    header ^= reverse_bits(uap) & 0xff;
    for (unsigned i = 0; i < 10; ++i, header >>= 1)
        if (header & 1)
            header ^= (crc_poly_rev_bt_hec << 1);
    return !header;
}

static bool
check_crc(uint8_t uap, tvbuff_t *tvb, int offset, int len)
{
    static const uint16_t crc_poly_rev_bt_pdu = 0x8408;
    uint16_t crc = reverse_bits(uap);
    crc <<= 8;
    for (; len > 0; --len, ++offset) {
        crc ^= tvb_get_uint8(tvb, offset) & 0xff;
        for (unsigned i = 0; i < 8; ++i) {
            uint16_t x = crc & 1;
            crc >>= 1;
            crc ^= crc_poly_rev_bt_pdu & -x;
        }
    }
    return !crc;
}

static uint32_t
extract_lap(const uint8_t bd_addr[6])
{
    uint32_t lap = bd_addr[3];
    lap <<= 8;
    lap |= bd_addr[4];
    lap <<= 8;
    lap |= bd_addr[5];
    return lap;
}

static bool
is_reserved_lap(uint32_t lap)
{
    return (lap >= 0x9e8b00) && (lap <= 0x9e8b3f);
}

static connection_info_t *
lookup_connection_info(uint32_t interface_id, uint32_t adapter_id, uint32_t lap, uint32_t ltaddr, uint32_t pktnum)
{
    connection_info_t *cinfo;
    wmem_tree_key_t key[6];
    key[0].length = 1;
    key[0].key = &interface_id;
    key[1].length = 1;
    key[1].key = &adapter_id;
    key[2].length = 1;
    key[2].key = &lap;
    key[3].length = 1;
    key[3].key = &ltaddr;
    key[4].length = 1;
    key[4].key = &pktnum;
    key[5].length = 0;
    key[5].key = NULL;
    cinfo = (connection_info_t *) wmem_tree_lookup32_array_le(connection_info_tree, key);
    if (!cinfo)
        return NULL;
    if (cinfo->interface_id != interface_id || cinfo->adapter_id != adapter_id ||
        extract_lap(cinfo->bd_addr[BDADDR_CENTRAL]) != lap || cinfo->lt_addr != ltaddr)
        return NULL;
    return cinfo;
}

connection_info_t *
btbredr_rf_add_esco_link(connection_info_t *cinfo, packet_info *pinfo, uint8_t handle, uint32_t ltaddr, uint16_t pktszms, uint16_t pktszsm)
{
    connection_info_t *ecinfo;
    uint32_t lap;
    wmem_tree_key_t key[6];
    if (!cinfo || !pinfo || ltaddr >= 8 || !ltaddr)
        return NULL;
    lap = extract_lap(cinfo->bd_addr[BDADDR_CENTRAL]);
    ecinfo = lookup_connection_info(cinfo->interface_id, cinfo->adapter_id, lap, ltaddr, pinfo->num);
    if (ecinfo && (memcmp(cinfo->bd_addr[BDADDR_CENTRAL], ecinfo->bd_addr[BDADDR_CENTRAL], 6) ||
                   memcmp(cinfo->bd_addr[BDADDR_PERIPHERAL], ecinfo->bd_addr[BDADDR_PERIPHERAL], 6) ||
                   !ecinfo->esco || ecinfo->escohandle != handle || ecinfo->escosize[0] != pktszms ||
                   ecinfo->escosize[1] != pktszsm))
        ecinfo = NULL;
    if (ecinfo)
        return ecinfo;
    ecinfo = wmem_new0(wmem_file_scope(), connection_info_t);
    ecinfo->interface_id   = cinfo->interface_id;
    ecinfo->adapter_id     = cinfo->adapter_id;
    ecinfo->lt_addr        = ltaddr;
    ecinfo->timestamp      = cinfo->timestamp;
    ecinfo->btclock        = cinfo->btclock;
    memcpy(ecinfo->bd_addr[BDADDR_CENTRAL], cinfo->bd_addr[BDADDR_CENTRAL], 6);
    memcpy(ecinfo->bd_addr[BDADDR_PERIPHERAL], cinfo->bd_addr[BDADDR_PERIPHERAL], 6);
    ecinfo->escosize[0] = pktszms;
    ecinfo->escosize[1] = pktszsm;
    ecinfo->escohandle = handle;
    ecinfo->esco = 1;
    key[0].length = 1;
    key[0].key = &cinfo->interface_id;
    key[1].length = 1;
    key[1].key = &cinfo->adapter_id;
    key[2].length = 1;
    key[2].key = &lap;
    key[3].length = 1;
    key[3].key = &ltaddr;
    key[4].length = 1;
    key[4].key = &pinfo->num;
    key[5].length = 0;
    key[5].key = NULL;
    wmem_tree_insert32_array(connection_info_tree, key, ecinfo);
    return ecinfo;
}

void
btbredr_rf_remove_esco_link(connection_info_t *cinfo, packet_info *pinfo, uint8_t handle)
{
    connection_info_t *ecinfo;
    uint32_t lap;
    wmem_tree_key_t key[6];
    if (!cinfo || !pinfo)
        return;
    lap = extract_lap(cinfo->bd_addr[BDADDR_CENTRAL]);
    for (uint32_t ltaddr = 1; ltaddr < 8; ++ltaddr) {
        ecinfo = lookup_connection_info(cinfo->interface_id, cinfo->adapter_id, lap, ltaddr, pinfo->num);
        if (!ecinfo)
            continue;
        if (memcmp(cinfo->bd_addr[BDADDR_CENTRAL], ecinfo->bd_addr[BDADDR_CENTRAL], 6) ||
            memcmp(cinfo->bd_addr[BDADDR_PERIPHERAL], ecinfo->bd_addr[BDADDR_PERIPHERAL], 6) ||
            !ecinfo->esco || ecinfo->escohandle != handle)
            continue;
        key[0].length = 1;
        key[0].key = &cinfo->interface_id;
        key[1].length = 1;
        key[1].key = &cinfo->adapter_id;
        key[2].length = 1;
        key[2].key = &lap;
        key[3].length = 1;
        key[3].key = &ltaddr;
        key[4].length = 1;
        key[4].key = &pinfo->num;
        key[5].length = 0;
        key[5].key = NULL;
        wmem_tree_insert32_array(connection_info_tree, key, ecinfo);
    }
}

static int
dissect_btbredr_rf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item           *btbredr_rf_item;
    proto_tree           *btbredr_rf_tree;
    proto_item           *flags_item;
    proto_tree           *flags_tree;
    proto_item           *header_item = NULL;
    proto_tree           *header_tree;
    proto_item           *reserved_item;
    proto_item           *hec_item = NULL;
    int                   offset = 0;
    int                   hf_x;
    int                   header_mode;
    uint32_t              interface_id;
    uint32_t              adapter_id;
    uint16_t              flags;
    uint32_t              lap;
    uint8_t               uap = 0;
    uint32_t              ltaddr;
    uint8_t               payload_and_transport;
    int16_t               packet_type = PACKET_TYPE_UNKNOWN;
    const char           *packet_type_str = "Unknown";
    dissector_table_t     packet_type_table = NULL;
    bool                  decrypted;
    int                   isochronous_length = 0;
    bool                  isochronous_crc = false;
    bool                  isochronous_esco = false;
    int                   data_length = 0;
    int                   data_header = 0;
    bool                  data_crc = false;
    bool                  arqn = false;
    bool                  seqn = false;
    int                   direction = -1;
    btbredr_frame_info_t *frame_info = NULL;
    connection_info_t    *connection_info = NULL;
    device_info_t        *device_info = NULL;
    bluetooth_data_t     *bluetooth_data = (bluetooth_data_t *) data;

    if (bluetooth_data)
        interface_id = bluetooth_data->interface_id;
    else if (pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID)
        interface_id = pinfo->rec->rec_header.packet_header.interface_id;
    else
        interface_id = HCI_INTERFACE_DEFAULT;

    if (bluetooth_data)
        adapter_id = bluetooth_data->adapter_id;
    else
        adapter_id = HCI_ADAPTER_DEFAULT;

    btbredr_rf_item = proto_tree_add_item(tree, proto_btbredr_rf, tvb, offset, -1, ENC_NA);
    btbredr_rf_tree = proto_item_add_subtree(btbredr_rf_item, ett_btbredr_rf);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BT BR/EDR RF");

    if (tvb_captured_length(tvb) >= 21) {
        flags = tvb_get_uint16(tvb, 20, ENC_LITTLE_ENDIAN);
    } else {
        flags = 0;
    }

    if (flags & FLAGS_RF_CHANNEL_ALIASING)
        hf_x = hf_uncertain_rf_channel;
    else
        hf_x = hf_rf_channel;
    proto_tree_add_item(btbredr_rf_tree, hf_x, tvb, offset, 1, ENC_NA);
    offset += 1;

    if (flags & FLAGS_SIGNAL_POWER_VALID)
        hf_x = hf_signal_power;
    else
        hf_x = hf_invalid_signal_power;
    proto_tree_add_item(btbredr_rf_tree, hf_x, tvb, offset, 1, ENC_NA);
    offset += 1;

    if (flags & FLAGS_NOISE_POWER_VALID)
        hf_x = hf_noise_power;
    else
        hf_x = hf_invalid_noise_power;
    proto_tree_add_item(btbredr_rf_tree, hf_x, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(btbredr_rf_tree, hf_access_address_offenses, tvb, offset, 1, ENC_NA);
    offset += 1;

    payload_and_transport = tvb_get_uint8(tvb, offset);

    col_add_fstr(pinfo->cinfo, COL_INFO, "Transport: %s (%s), RF Channel: %s%2u",
            val_to_str_const(payload_and_transport >> 4, payload_transport_rate_transport_vals, "Unknown"),
            val_to_str_const(payload_and_transport & 0xF, payload_transport_rate_payload_abbrev_vals, "Unknown"),
            (flags & FLAGS_RF_CHANNEL_ALIASING) ? "~" : "",
            tvb_get_uint8(tvb, 0));

    if (payload_and_transport == 0xFF)
        proto_tree_add_item(btbredr_rf_tree, hf_payload_transport_rate_ignored, tvb, offset, 1, ENC_NA);
    else
        proto_tree_add_bitmask(btbredr_rf_tree, tvb, offset, hf_payload_transport_rate, ett_payload_transport_rate, hfx_payload_transport_rate, ENC_LITTLE_ENDIAN);
    offset += 1;

    proto_tree_add_item(btbredr_rf_tree, hf_corrected_header_bits, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(btbredr_rf_tree, hf_corrected_payload_bits, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btbredr_rf_tree, hf_lower_address_part, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    lap = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN) & 0xffffff;
    offset += 4;

    if (!is_reserved_lap(lap)) {
        wmem_tree_key_t key[4];
        key[0].length = 1;
        key[0].key = &interface_id;
        key[1].length = 1;
        key[1].key = &adapter_id;
        key[2].length = 1;
        key[2].key = &lap;
        key[3].length = 0;
        key[3].key = NULL;

        device_info = (device_info_t *) wmem_tree_lookup32_array(device_info_tree, key);
    }

    if (device_info) {
        direction = (device_info->dir == pinfo->p2p_dir) ? BDADDR_CENTRAL : BDADDR_PERIPHERAL;
        uap = device_info->bd_addr[2];
    }

    if (flags & FLAGS_REFERENCE_LOWER_ADDRESS_PART_VALID)
        hf_x = hf_reference_lower_address_part;
    else
        hf_x = hf_invalid_reference_lower_address_part;
    proto_tree_add_item(btbredr_rf_tree, hf_x, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    if (flags & FLAGS_REFERENCE_UPPER_ADDRES_PART_VALID) {
        hf_x = hf_reference_upper_addres_part;
        uap = tvb_get_uint8(tvb, offset);
    } else {
        hf_x = hf_invalid_reference_upper_addres_part;
    }
    proto_tree_add_item(btbredr_rf_tree, hf_x, tvb, offset, 1, ENC_NA);
    offset += 1;

    {
        uint32_t hdr = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
        bool have_uap = device_info || !!(flags & FLAGS_REFERENCE_UPPER_ADDRES_PART_VALID);
        bool is_inquiry = is_reserved_lap(lap);
        bool is_inquiry_fhs = is_inquiry && (((hdr >> 3) & 0x0f) == 2);
        bool is_inquiry_broken_fhs = is_inquiry && (((hdr >> 11) & 0x0f) == 2);
        if (is_inquiry && !(is_inquiry_fhs || is_inquiry_broken_fhs))
            header_mode = -2;
        else if (!(flags & FLAGS_PACKET_HEADER_AND_BR_EDR_PAYLOAD_DEWHITENED))
            header_mode = -1;
        else if ((have_uap || is_inquiry_fhs) && check_hec(is_inquiry_fhs ? 0 : uap, hdr))
            header_mode = 1;
        else if ((have_uap || is_inquiry_broken_fhs) && broken_check_hec(is_inquiry_broken_fhs ? 0 : uap, hdr))
            header_mode = 2;
        else if (!have_uap)
            header_mode = -1;
        else
            header_mode = 0;
    }

    decrypted = !!(flags & FLAGS_BREDR_PAYLOAD_DECRYPTED);

    if (header_mode == -1) {
        proto_tree_add_item(btbredr_rf_tree, hf_whitened_packet_header, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    } else if (header_mode == -2) {
        proto_tree_add_item(btbredr_rf_tree, hf_invalid_packet_header, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    } else if (header_mode == 2) {
        // broken header format
        header_item = proto_tree_add_item(btbredr_rf_tree, hf_packet_header, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        header_tree = proto_item_add_subtree(header_item, ett_bluetooth_header);

        proto_tree_add_item(header_tree, hf_packet_header_reserved, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(header_tree, hf_packet_header_broken_lt_addr, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        ltaddr = (tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN) >> 15) & 7;
        arqn = (tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN) >> 9) & 1;
        seqn = (tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN) >> 8) & 1;

        if (payload_and_transport == (TRANSPORT_SCO | PAYLOAD_BR)) {
            proto_tree_add_item(header_tree, hf_packet_header_broken_type_sco_br, tvb, offset, 4, ENC_LITTLE_ENDIAN);

            packet_type = (tvb_get_uint8(tvb, offset + 1) >> 3) & 0xF;
            packet_type_str = val_to_str_const(packet_type, packet_type_sco_br_vals, "Unknown");
            packet_type_table = packet_type_sco_br_table;
        } else if (payload_and_transport == (TRANSPORT_eSCO | PAYLOAD_BR)) {
            proto_tree_add_item(header_tree, hf_packet_header_broken_type_esco_br, tvb, offset, 4, ENC_LITTLE_ENDIAN);

            packet_type = (tvb_get_uint8(tvb, offset + 1) >> 3) & 0xF;
            packet_type_str = val_to_str_const(packet_type, packet_type_esco_br_vals, "Unknown");
            packet_type_table = packet_type_esco_br_table;
        } else if (payload_and_transport == (TRANSPORT_eSCO | PAYLOAD_EDR_2) || payload_and_transport == (TRANSPORT_eSCO | PAYLOAD_EDR_3)) {
            proto_tree_add_item(header_tree, hf_packet_header_broken_type_esco_edr, tvb, offset, 4, ENC_LITTLE_ENDIAN);

            packet_type = (tvb_get_uint8(tvb, offset + 1) >> 3) & 0xF;
            packet_type_str = val_to_str_const(packet_type, packet_type_esco_edr_vals, "Unknown");
            packet_type_table = packet_type_esco_edr_table;
        } else if (payload_and_transport == (TRANSPORT_ACL | PAYLOAD_BR)) {
            proto_tree_add_item(header_tree, hf_packet_header_broken_type_acl_br, tvb, offset, 4, ENC_LITTLE_ENDIAN);

            packet_type = (tvb_get_uint8(tvb, offset + 1) >> 3) & 0xF;
            packet_type_str = val_to_str_const(packet_type, packet_type_acl_br_vals, "Unknown");
            packet_type_table = packet_type_acl_br_table;
        } else if (payload_and_transport == (TRANSPORT_ACL | PAYLOAD_EDR_2) || payload_and_transport == (TRANSPORT_ACL | PAYLOAD_EDR_3)) {
            proto_tree_add_item(header_tree, hf_packet_header_broken_type_acl_edr, tvb, offset, 4, ENC_LITTLE_ENDIAN);

            packet_type = (tvb_get_uint8(tvb, offset + 1) >> 3) & 0xF;
            packet_type_str = val_to_str_const(packet_type, packet_type_acl_edr_vals, "Unknown");
            packet_type_table = packet_type_acl_edr_table;
        } else if (payload_and_transport == (TRANSPORT_CPB | PAYLOAD_BR)) {
            proto_tree_add_item(header_tree, hf_packet_header_broken_type_cpb_br, tvb, offset, 4, ENC_LITTLE_ENDIAN);

            packet_type = (tvb_get_uint8(tvb, offset + 1) >> 3) & 0xF;
            packet_type_str = val_to_str_const(packet_type, packet_type_cpb_br_vals, "Unknown");
            packet_type_table = packet_type_cpb_br_table;
        } else if (payload_and_transport == (TRANSPORT_CPB | PAYLOAD_EDR_2) || payload_and_transport == (TRANSPORT_ACL | PAYLOAD_EDR_3)) {
            proto_tree_add_item(header_tree, hf_packet_header_broken_type_cpb_edr, tvb, offset, 4, ENC_LITTLE_ENDIAN);

            packet_type = (tvb_get_uint8(tvb, offset + 1) >> 3) & 0xF;
            packet_type_str = val_to_str_const(packet_type, packet_type_cpb_edr_vals, "Unknown");
            packet_type_table = packet_type_cpb_edr_table;
        } else if ((payload_and_transport >> 4) == TRANSPORT_ANY) {
            proto_tree_add_item(header_tree, hf_packet_header_broken_type_any, tvb, offset, 4, ENC_LITTLE_ENDIAN);

            packet_type = (tvb_get_uint8(tvb, offset + 1) >> 3) & 0xF;
            packet_type_str = val_to_str_const(packet_type, packet_type_any_vals, "Unknown");
        } else {
            proto_tree_add_item(header_tree, hf_packet_header_broken_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        }

        proto_tree_add_item(header_tree, hf_packet_header_broken_flow_control, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(header_tree, hf_packet_header_broken_acknowledge_indication, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(header_tree, hf_packet_header_broken_sequence_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        hec_item = proto_tree_add_item(header_tree, hf_packet_header_broken_header_error_check, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    } else if (header_mode >= 0) {
        // header format according to Core_v5.2.pdf Vol 2 Part B Chapter 6.4
        header_item = proto_tree_add_item(btbredr_rf_tree, hf_packet_header, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        header_tree = proto_item_add_subtree(header_item, ett_bluetooth_header);

        proto_tree_add_item(header_tree, hf_packet_header_lt_addr, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        ltaddr = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN) & 7;
        arqn = (tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN) >> 8) & 1;
        seqn = (tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN) >> 9) & 1;

        if (payload_and_transport == (TRANSPORT_SCO | PAYLOAD_BR)) {
            proto_tree_add_item(header_tree, hf_packet_header_type_sco_br, tvb, offset, 4, ENC_LITTLE_ENDIAN);

            packet_type = (tvb_get_uint8(tvb, offset) >> 3) & 0xF;
            packet_type_str = val_to_str_const(packet_type, packet_type_sco_br_vals, "Unknown");
            packet_type_table = packet_type_sco_br_table;
        } else if (payload_and_transport == (TRANSPORT_eSCO | PAYLOAD_BR)) {
            proto_tree_add_item(header_tree, hf_packet_header_type_esco_br, tvb, offset, 4, ENC_LITTLE_ENDIAN);

            packet_type = (tvb_get_uint8(tvb, offset) >> 3) & 0xF;
            packet_type_str = val_to_str_const(packet_type, packet_type_esco_br_vals, "Unknown");
            packet_type_table = packet_type_esco_br_table;
        } else if (payload_and_transport == (TRANSPORT_eSCO | PAYLOAD_EDR_2) || payload_and_transport == (TRANSPORT_eSCO | PAYLOAD_EDR_3)) {
            proto_tree_add_item(header_tree, hf_packet_header_type_esco_edr, tvb, offset, 4, ENC_LITTLE_ENDIAN);

            packet_type = (tvb_get_uint8(tvb, offset) >> 3) & 0xF;
            packet_type_str = val_to_str_const(packet_type, packet_type_esco_edr_vals, "Unknown");
            packet_type_table = packet_type_esco_edr_table;
        } else if (payload_and_transport == (TRANSPORT_ACL | PAYLOAD_BR)) {
            proto_tree_add_item(header_tree, hf_packet_header_type_acl_br, tvb, offset, 4, ENC_LITTLE_ENDIAN);

            packet_type = (tvb_get_uint8(tvb, offset) >> 3) & 0xF;
            packet_type_str = val_to_str_const(packet_type, packet_type_acl_br_vals, "Unknown");
            packet_type_table = packet_type_acl_br_table;
        } else if (payload_and_transport == (TRANSPORT_ACL | PAYLOAD_EDR_2) || payload_and_transport == (TRANSPORT_ACL | PAYLOAD_EDR_3)) {
            proto_tree_add_item(header_tree, hf_packet_header_type_acl_edr, tvb, offset, 4, ENC_LITTLE_ENDIAN);

            packet_type = (tvb_get_uint8(tvb, offset) >> 3) & 0xF;
            packet_type_str = val_to_str_const(packet_type, packet_type_acl_edr_vals, "Unknown");
            packet_type_table = packet_type_acl_edr_table;
        } else if (payload_and_transport == (TRANSPORT_CPB | PAYLOAD_BR)) {
            proto_tree_add_item(header_tree, hf_packet_header_type_cpb_br, tvb, offset, 4, ENC_LITTLE_ENDIAN);

            packet_type = (tvb_get_uint8(tvb, offset) >> 3) & 0xF;
            packet_type_str = val_to_str_const(packet_type, packet_type_cpb_br_vals, "Unknown");
            packet_type_table = packet_type_cpb_br_table;
        } else if (payload_and_transport == (TRANSPORT_CPB | PAYLOAD_EDR_2) || payload_and_transport == (TRANSPORT_ACL | PAYLOAD_EDR_3)) {
            proto_tree_add_item(header_tree, hf_packet_header_type_cpb_edr, tvb, offset, 4, ENC_LITTLE_ENDIAN);

            packet_type = (tvb_get_uint8(tvb, offset) >> 3) & 0xF;
            packet_type_str = val_to_str_const(packet_type, packet_type_cpb_edr_vals, "Unknown");
            packet_type_table = packet_type_cpb_edr_table;
        } else if ((payload_and_transport >> 4) == TRANSPORT_ANY) {
            proto_tree_add_item(header_tree, hf_packet_header_type_any, tvb, offset, 4, ENC_LITTLE_ENDIAN);

            packet_type = (tvb_get_uint8(tvb, offset) >> 3) & 0xF;
            packet_type_str = val_to_str_const(packet_type, packet_type_any_vals, "Unknown");
        } else {
            proto_tree_add_item(header_tree, hf_packet_header_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        }

        proto_tree_add_item(header_tree, hf_packet_header_flow_control, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(header_tree, hf_packet_header_acknowledge_indication, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(header_tree, hf_packet_header_sequence_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        hec_item = proto_tree_add_item(header_tree, hf_packet_header_header_error_check, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(header_tree, hf_packet_header_reserved, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    }

    switch (header_mode) {
    case -2:
        col_set_str(pinfo->cinfo, COL_INFO, (lap == 0x9e8b33) ? "GIAC" : "DIAC");
        break;

    case -1:
        expert_add_info(pinfo, hec_item, &ei_packet_header_with_hec_not_checked);
        break;

    case 0:
        expert_add_info(pinfo, hec_item, &ei_incorrect_packet_header_or_hec);
        break;

    case 2:
        expert_add_info(pinfo, header_item, &ei_broken_packet_header_format);
        break;

    default:
        break;
    }

    if (header_mode > 0 && ltaddr)
        connection_info = lookup_connection_info(interface_id, adapter_id, lap, ltaddr, pinfo->num);

    if (connection_info && direction >= 0) {
        set_address(&pinfo->dl_src, AT_ETHER, sizeof(connection_info->bd_addr[0]), connection_info->bd_addr[direction]);
        set_address(&pinfo->dl_dst, AT_ETHER, sizeof(connection_info->bd_addr[0]), connection_info->bd_addr[1 - direction]);
        set_address(&pinfo->net_src, AT_ETHER, sizeof(connection_info->bd_addr[0]), connection_info->bd_addr[direction]);
        set_address(&pinfo->net_dst, AT_ETHER, sizeof(connection_info->bd_addr[0]), connection_info->bd_addr[1 - direction]);
    } else {
        clear_address(&pinfo->dl_dst);
        clear_address(&pinfo->net_dst);
        if (header_mode > 0 && !ltaddr && device_info) {
            set_address(&pinfo->dl_src, AT_ETHER, sizeof(device_info->bd_addr), device_info->bd_addr);
            set_address(&pinfo->net_src, AT_ETHER, sizeof(device_info->bd_addr), device_info->bd_addr);
        } else {
            clear_address(&pinfo->dl_src);
            clear_address(&pinfo->net_src);
        }
    }
    copy_address_shallow(&pinfo->src, &pinfo->net_src);
    copy_address_shallow(&pinfo->dst, &pinfo->net_dst);

    offset += 4;

    flags_item = proto_tree_add_item(btbredr_rf_tree, hf_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    flags_tree = proto_item_add_subtree(flags_item, ett_flags);

    flags = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);

    reserved_item = proto_tree_add_item(flags_tree, hf_flags_reserved_15_14, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    if (flags & 0xC000) {
        expert_add_info(pinfo, reserved_item, &ei_reserved_not_zero);
    }

    proto_tree_add_item(flags_tree, hf_flags_mic_pass, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(flags_tree, hf_flags_mic_checked, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(flags_tree, hf_flags_crc_pass, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(flags_tree, hf_flags_crc_checked, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(flags_tree, hf_flags_hec_pass, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(flags_tree, hf_flags_hec_checked, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(flags_tree, hf_flags_reference_upper_addres_part_valid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(flags_tree, hf_flags_rf_channel_aliasing, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(flags_tree, hf_flags_br_edr_data_present, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(flags_tree, hf_flags_reference_lower_address_part_valid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(flags_tree, hf_flags_bredr_payload_decrypted, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(flags_tree, hf_flags_noise_power_valid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(flags_tree, hf_flags_signal_power_valid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(flags_tree, hf_flags_packet_header_and_br_edr_payload_dewhitened, tvb, offset, 2, ENC_LITTLE_ENDIAN);

    offset += 2;

    if ((flags & (FLAGS_SIGNAL_POWER_VALID | FLAGS_NOISE_POWER_VALID)) == (FLAGS_SIGNAL_POWER_VALID | FLAGS_NOISE_POWER_VALID)) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (SP: %4i, NP: %4i)",
                (int)tvb_get_int8(tvb, 1), (int)tvb_get_int8(tvb, 2));
    } else if (flags & FLAGS_SIGNAL_POWER_VALID) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (SP: %4i)",
                (int)tvb_get_int8(tvb, 1));
    } else if (flags & FLAGS_NOISE_POWER_VALID) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (NP: %4i)",
                (int)tvb_get_int8(tvb, 2));
    }

   if (flags & FLAGS_PACKET_HEADER_AND_BR_EDR_PAYLOAD_DEWHITENED)
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Packet Type: %s", packet_type_str);

   // Packet Type Table
   if (payload_and_transport == (TRANSPORT_SCO | PAYLOAD_BR)) {
       switch (packet_type) {
       case 0: // NULL
       case 1: // POLL
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 0;
           data_header = 0;
           data_crc = false;
           break;

       case 2: // FHS
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 18;
           data_header = 0;
           data_crc = true;
           decrypted = true;
           break;

       case 3: // DM1
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 18;
           data_header = 1;
           data_crc = true;
           break;

       case 5: // HV1
           isochronous_length = 10;
           isochronous_crc = false;
           data_length = 0;
           data_header = 0;
           data_crc = false;
           break;

       case 6: // HV2
           isochronous_length = 20;
           isochronous_crc = false;
           data_length = 0;
           data_header = 0;
           data_crc = false;
           break;

       case 7: // HV3
           isochronous_length = 30;
           isochronous_crc = false;
           data_length = 0;
           data_header = 0;
           data_crc = false;
           break;

       case 8: // DV
           isochronous_length = 10;
           isochronous_crc = false;
           data_length = 10;
           data_header = 1;
           data_crc = true;
           break;

       default:
           break;
       }
   } else if (payload_and_transport == (TRANSPORT_eSCO | PAYLOAD_BR)) {
       switch (packet_type) {
       case 0: // NULL
       case 1: // POLL
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 0;
           data_header = 0;
           data_crc = false;
           break;

       case 7: // EV3
           isochronous_length = 30;
           isochronous_crc = true;
           isochronous_esco = true;
           data_length = 0;
           data_header = 0;
           data_crc = false;
           break;

       case 12: // EV4
           isochronous_length = 120;
           isochronous_crc = true;
           isochronous_esco = true;
           data_length = 0;
           data_header = 0;
           data_crc = false;
           break;

       case 13: // EV5
           isochronous_length = 180;
           isochronous_crc = true;
           isochronous_esco = true;
           data_length = 0;
           data_header = 0;
           data_crc = false;
           break;

       default:
           break;
       }
   } else if (payload_and_transport == (TRANSPORT_eSCO | PAYLOAD_EDR_2) || payload_and_transport == (TRANSPORT_eSCO | PAYLOAD_EDR_3)) {
       switch (packet_type) {
       case 0: // NULL
       case 1: // POLL
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 0;
           data_header = 0;
           data_crc = false;
           break;

       case 6: // 2-EV3
           isochronous_length = 60;
           isochronous_crc = true;
           isochronous_esco = true;
           data_length = 0;
           data_header = 0;
           data_crc = false;
           break;

       case 7: // 3-EV3
           isochronous_length = 90;
           isochronous_crc = true;
           isochronous_esco = true;
           data_length = 0;
           data_header = 0;
           data_crc = false;
           break;

       case 12: // 2-EV5
           isochronous_length = 360;
           isochronous_crc = true;
           isochronous_esco = true;
           data_length = 0;
           data_header = 0;
           data_crc = false;
           break;

       case 13: // 3-EV5
           isochronous_length = 540;
           isochronous_crc = true;
           isochronous_esco = true;
           data_length = 0;
           data_header = 0;
           data_crc = false;
           break;

       default:
           break;
       }
   } else if (payload_and_transport == (TRANSPORT_ACL | PAYLOAD_BR)) {
       switch (packet_type) {
       case 0: // NULL
       case 1: // POLL
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 0;
           data_header = 0;
           data_crc = false;
           break;

       case 2: // FHS
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 18;
           data_header = 0;
           data_crc = true;
           decrypted = true;
           break;

       case 3: // DM1
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 18;
           data_header = 1;
           data_crc = true;
           break;

       case 4: // DH1
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 28;
           data_header = 1;
           data_crc = true;
           break;

       case 9: // AUX1
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 30;
           data_header = 1;
           data_crc = false;
           break;

       case 10: // DM3
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 123;
           data_header = 2;
           data_crc = true;
           break;

       case 11: // DH3
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 185;
           data_header = 2;
           data_crc = true;
           break;

       case 14: // DM5
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 226;
           data_header = 2;
           data_crc = true;
           break;

       case 15: // DH5
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 341;
           data_header = 2;
           data_crc = true;
           break;

       default:
           break;
       }
   } else if (payload_and_transport == (TRANSPORT_ACL | PAYLOAD_EDR_2) || payload_and_transport == (TRANSPORT_ACL | PAYLOAD_EDR_3)) {
       switch (packet_type) {
       case 0: // NULL
       case 1: // POLL
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 0;
           data_header = 0;
           data_crc = false;
           break;

       case 2: // FHS
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 18;
           data_header = 0;
           data_crc = true;
           decrypted = true;
           break;

       case 3: // DM1
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 18;
           data_header = 1;
           data_crc = true;
           break;

       case 4: // 2-DH1
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 56;
           data_header = 2;
           data_crc = true;
           break;

       case 8: // 3-DH1
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 85;
           data_header = 2;
           data_crc = true;
           break;

       case 9: // AUX1
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 30;
           data_header = 1;
           data_crc = false;
           break;

       case 10: // 2-DH3
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 369;
           data_header = 2;
           data_crc = true;
           break;

       case 11: // 3-DH3
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 554;
           data_header = 2;
           data_crc = true;
           break;

       case 14: // 2-DH5
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 681;
           data_header = 2;
           data_crc = true;
           break;

       case 15: // 3-DH5
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 1023;
           data_header = 2;
           data_crc = true;
           break;

       default:
           break;
       }
   } else if (payload_and_transport == (TRANSPORT_CPB | PAYLOAD_BR)) {
       switch (packet_type) {
       case 0: // NULL
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 0;
           data_header = 0;
           data_crc = false;
           break;

       case 3: // DM1
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 18;
           data_header = 1;
           data_crc = true;
           break;

       case 4: // DH1
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 28;
           data_header = 1;
           data_crc = true;
           break;

       case 10: // DM3
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 123;
           data_header = 2;
           data_crc = true;
           break;

       case 11: // DH3
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 185;
           data_header = 2;
           data_crc = true;
           break;

       case 14: // DM5
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 226;
           data_header = 2;
           data_crc = true;
           break;

       case 15: // DH5
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 341;
           data_header = 2;
           data_crc = true;
           break;

       default:
           break;
       }
   } else if (payload_and_transport == (TRANSPORT_CPB | PAYLOAD_EDR_2) || payload_and_transport == (TRANSPORT_ACL | PAYLOAD_EDR_3)) {
       switch (packet_type) {
       case 0: // NULL
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 0;
           data_header = 0;
           data_crc = false;
           break;

       case 3: // DM1
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 18;
           data_header = 1;
           data_crc = true;
           break;

       case 4: // 2-DH1
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 56;
           data_header = 2;
           data_crc = true;
           break;

       case 8: // 3-DH1
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 85;
           data_header = 2;
           data_crc = true;
           break;

       case 10: // 2-DH3
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 369;
           data_header = 2;
           data_crc = true;
           break;

       case 11: // 3-DH3
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 554;
           data_header = 2;
           data_crc = true;
           break;

       case 14: // 2-DH5
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 681;
           data_header = 2;
           data_crc = true;
           break;

       case 15: // 3-DH5
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 1023;
           data_header = 2;
           data_crc = true;
           break;

       default:
           break;
       }
   } else if ((payload_and_transport >> 4) == TRANSPORT_ANY) {
       switch (packet_type) {
       case 0: // NULL
       case 1: // POLL
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 0;
           data_header = 0;
           data_crc = false;
           break;

       case 2: // FHS
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 18;
           data_header = 0;
           data_crc = true;
           decrypted = true;
           break;

       case 3: // DM1
           isochronous_length = 0;
           isochronous_crc = false;
           data_length = 18;
           data_header = 1;
           data_crc = true;
           break;

       default:
           break;
       }
   }

   if (flags & FLAGS_BR_EDR_DATA_PRESENT) {
       if (flags & FLAGS_PACKET_HEADER_AND_BR_EDR_PAYLOAD_DEWHITENED) {
           if (decrypted) {
               tvbuff_t       *next_tvb;

               next_tvb = tvb_new_subset_remaining(tvb, offset);
               if (packet_type_table && packet_type > PACKET_TYPE_UNKNOWN &&
                   dissector_try_uint_new(packet_type_table, packet_type, next_tvb, pinfo, tree, true, bluetooth_data)) {
                   offset = tvb_reported_length(tvb);
               } else {
                   if (isochronous_length > 0 &&
                       (!isochronous_crc || (flags & (FLAGS_CRC_PASS | FLAGS_CRC_CHECKED)) == (FLAGS_CRC_PASS | FLAGS_CRC_CHECKED))) {
                       int len = tvb_captured_length_remaining(tvb, offset);
                       if (isochronous_crc)
                           len -= 2;
                       if (isochronous_length > len)
                           isochronous_length = len;
                       if (isochronous_length > 0) {
                           //next_tvb = tvb_new_subset_length(tvb, offset, isochronous_length);
                           proto_item *iso_item = proto_tree_add_item(btbredr_rf_tree, hf_isochronous_data, tvb, offset, isochronous_length, ENC_NA);
                           if (isochronous_crc) {
                               proto_item *crc_item = NULL;
                               crc_item = proto_tree_add_item(btbredr_rf_tree, hf_crc, tvb, offset + isochronous_length, 2, ENC_LITTLE_ENDIAN);
                               if ((flags & FLAGS_REFERENCE_UPPER_ADDRES_PART_VALID) && !check_crc(uap, tvb, offset, isochronous_length + 2))
                                   expert_add_info(pinfo, crc_item, &ei_incorrect_crc);
                               offset += 2;
                           }
                           offset += isochronous_length;
                           if (connection_info) {
                               if (connection_info->esco != isochronous_esco)
                                   expert_add_info(pinfo, iso_item, &ei_esco_incorrect_ltaddr);
                               if (direction >= 0 && connection_info->esco &&
                                   connection_info->escosize[direction] != isochronous_length)
                                   expert_add_info(pinfo, iso_item, &ei_esco_incorrect_length);
                           }
                       }
                   }
                   if (data_length > 0 &&
                       (!data_crc || (flags & (FLAGS_CRC_PASS | FLAGS_CRC_CHECKED)) == (FLAGS_CRC_PASS | FLAGS_CRC_CHECKED))) {
                       int len = tvb_captured_length_remaining(tvb, offset);
                       bool error = false;
                       int llid = -1;
                       if (data_crc)
                           len -= 2;
                       if (data_length > len)
                           data_length = len;
                       if (data_header > 0) {
                           if (len < data_header) {
                               error = true;
                           } else if (data_header == 1) {
                               uint8_t hdr = tvb_get_uint8(tvb, offset);
                               llid = hdr & 3;
                               hdr >>= 3;
                               hdr &= 0x1f;
                               ++hdr;
                               if (hdr > len)
                                   error = true;
                               else
                                   data_length = hdr;
                           } else if (data_header == 2) {
                               uint16_t hdr = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
                               llid = hdr & 3;
                               hdr >>= 3;
                               hdr &= 0x3ff;
                               hdr += 2;
                               if (hdr > len)
                                   error = true;
                               else
                                   data_length = hdr;
                           } else {
                               error = true;
                           }
                       }
                       if (data_length > 0 && !error) {
                           bool handled = false;
                           fragment_head *frag_l2cap_msg = NULL;
                           if (data_header == 1) {
                               proto_item *pheader_item = proto_tree_add_item(btbredr_rf_tree, hf_payload_header1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                               proto_tree *pheader_tree = proto_item_add_subtree(pheader_item, ett_payload_header);
                               proto_tree_add_item(pheader_tree, hf_payload_header1_llid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                               proto_tree_add_item(pheader_tree, hf_payload_header1_flow, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                               proto_tree_add_item(pheader_tree, hf_payload_header1_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                           } else if (data_header == 2) {
                               proto_item *pheader_item = proto_tree_add_item(btbredr_rf_tree, hf_payload_header2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                               proto_tree *pheader_tree = proto_item_add_subtree(pheader_item, ett_payload_header);
                               proto_tree_add_item(pheader_tree, hf_payload_header2_llid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                               proto_tree_add_item(pheader_tree, hf_payload_header2_flow, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                               proto_tree_add_item(pheader_tree, hf_payload_header2_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                               proto_tree_add_item(pheader_tree, hf_payload_header2_rfu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                           }
                           if (!pinfo->fd->visited) {
                               frame_info = wmem_new0(wmem_file_scope(), btbredr_frame_info_t);
                               p_add_proto_data(wmem_file_scope(), pinfo, proto_btbredr_rf, pinfo->curr_layer_num, frame_info);
                               if (connection_info && direction >= 0) {
                                   frame_info->retransmit = (seqn == connection_info->reassembly[direction].seqn);
                                   frame_info->ack = arqn;
                                   frame_info->l2cap_index = pinfo->num;
                                   connection_info->reassembly[direction].seqn = seqn;
                               }
                           } else {
                               frame_info = (btbredr_frame_info_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_btbredr_rf, pinfo->curr_layer_num);
                           }
                            if (packet_type == 2) {
                               // FHS
                               next_tvb = tvb_new_subset_length(tvb, offset + data_header, data_length - data_header);
                               if (next_tvb) {
                                   btbredr_fhs_data_t *fhs_data = wmem_new0(pinfo->pool, btbredr_fhs_data_t);
                                   fhs_data->bluetooth_data  = bluetooth_data;
                                   fhs_data->device_info     = device_info;
                                   fhs_data->connection_info = connection_info;
                                   call_dissector_with_data(btbredr_fhs_handle, next_tvb, pinfo, tree, fhs_data);
                                   handled = true;
                               }
                           }
                           switch (llid) {
                           case 0x03: // LMP
                               if (!btlmp_handle)
                                   break;
                               next_tvb = tvb_new_subset_length(tvb, offset + data_header, data_length - data_header);
                               if (!next_tvb)
                                   break;
                               call_dissector_with_data(btlmp_handle, next_tvb, pinfo, tree, connection_info);
                               handled = true;
                               break;

                           case 0x02: // Start of or complete L2CAP message
                               if (!btl2cap_handle)
                                   break;
                               if (frame_info && data_length > data_header) {
                                   unsigned pdu_len = data_length - data_header;
                                   unsigned l2cap_len = tvb_get_letohs(tvb, offset + data_header);
                                   if (l2cap_len + 4 <= pdu_len) {
                                       bthci_acl_data_t *acl_data = wmem_new(pinfo->pool, bthci_acl_data_t);
                                       acl_data->interface_id = interface_id;
                                       acl_data->adapter_id   = adapter_id;
                                       acl_data->chandle      = 0; /* No connection handle at this layer */
                                       acl_data->remote_bd_addr_oui = 0;
                                       acl_data->remote_bd_addr_id  = 0;
                                       acl_data->is_btle = true;
                                       acl_data->is_btle_retransmit = false;
                                       acl_data->adapter_disconnect_in_frame = &bluetooth_max_disconnect_in_frame;
                                       acl_data->disconnect_in_frame = &bluetooth_max_disconnect_in_frame;
                                       next_tvb = tvb_new_subset_length(tvb, offset + data_header, pdu_len);
                                       call_dissector_with_data(btl2cap_handle, next_tvb, pinfo, tree, acl_data);
                                       handled = true;
                                       col_set_str(pinfo->cinfo, COL_INFO, "L2CAP Data");
                                       if (!pinfo->fd->visited && connection_info && direction >= 0) {
                                           connection_info->reassembly[direction].l2cap_index = pinfo->num;
                                           connection_info->reassembly[direction].segment_len_rem = 0;
                                       }
                                       break;
                                   }
                                   pinfo->fragmented = true;
                                   if (!frame_info->retransmit && connection_info && direction >= 0) {
                                       if (!pinfo->fd->visited) {
                                           connection_info->reassembly[direction].l2cap_index = pinfo->num;
                                           connection_info->reassembly[direction].segment_len_rem = l2cap_len + 4 - pdu_len;
                                           frame_info->more_fragments = 1;
                                       }
                                       frag_l2cap_msg = fragment_add_seq_next(&l2cap_msg_reassembly_table,
                                                                              tvb, offset + data_header,
                                                                              pinfo,
                                                                              frame_info->l2cap_index,      /* uint32_t ID for fragments belonging together */
                                                                              NULL,                         /* data* */
                                                                              pdu_len,                      /* Fragment length */
                                                                              frame_info->more_fragments);  /* More fragments */
                                       process_reassembled_data(tvb, offset + data_header, pinfo,
                                                                "Reassembled L2CAP",
                                                                frag_l2cap_msg,
                                                                &l2cap_msg_frag_items,
                                                                NULL,
                                                                btbredr_rf_tree);
                                   }
                                   proto_tree_add_item(btbredr_rf_tree, hf_l2cap_fragment, tvb, offset + data_header, pdu_len, ENC_NA);
                                   handled = true;
                                   col_set_str(pinfo->cinfo, COL_INFO, "L2CAP Fragment Start");
                               }
                               break;

                           case 0x01: /* Continuation fragment of an L2CAP message, or an Empty PDU */
                               if (!btl2cap_handle)
                                   break;
                               if (!frame_info || data_length <= data_header) {
                                   col_set_str(pinfo->cinfo, COL_INFO, "Empty PDU");
                                   break;
                               }
                               pinfo->fragmented = true;
                               if (!frame_info->retransmit && connection_info && direction >= 0) {
                                   unsigned pdu_len = data_length - data_header;
                                   if (!pinfo->fd->visited) {
                                       if (connection_info->reassembly[direction].segment_len_rem > 0) {
                                           if (connection_info->reassembly[direction].segment_len_rem >= pdu_len) {
                                               connection_info->reassembly[direction].segment_len_rem -= pdu_len;
                                               frame_info->l2cap_index = connection_info->reassembly[direction].l2cap_index;
                                           } else {
                                               /*
                                                * Missing fragment for previous L2CAP and fragment start for this.
                                                * Set more_fragments and increase l2cap_index to avoid reassembly.
                                                */
                                               frame_info->more_fragments = 1;
                                               frame_info->missing_start = 1;
                                               connection_info->reassembly[direction].l2cap_index = pinfo->num;
                                               connection_info->reassembly[direction].segment_len_rem = 0;
                                           }
                                           frame_info->more_fragments = (connection_info->reassembly[direction].segment_len_rem > 0);
                                       } else {
                                           /*
                                            * Missing fragment start.
                                            * Set more_fragments and increase l2cap_index to avoid reassembly.
                                            */
                                           frame_info->more_fragments = 1;
                                           frame_info->missing_start = 1;
                                           connection_info->reassembly[direction].l2cap_index = pinfo->num;
                                           connection_info->reassembly[direction].segment_len_rem = 0;
                                       }
                                   }
                                   frag_l2cap_msg = fragment_add_seq_next(&l2cap_msg_reassembly_table,
                                                                          tvb, offset + data_header,
                                                                          pinfo,
                                                                          frame_info->l2cap_index,      /* uint32_t ID for fragments belonging together */
                                                                          NULL,                         /* data* */
                                                                          pdu_len,                      /* Fragment length */
                                                                          frame_info->more_fragments);  /* More fragments */
                                   next_tvb = process_reassembled_data(tvb, offset, pinfo,
                                                                       "Reassembled L2CAP",
                                                                       frag_l2cap_msg,
                                                                       &l2cap_msg_frag_items,
                                                                       NULL,
                                                                       btbredr_rf_tree);
                               }
                               if (next_tvb) {
                                   bthci_acl_data_t *acl_data = wmem_new(pinfo->pool, bthci_acl_data_t);
                                   acl_data->interface_id = interface_id;
                                   acl_data->adapter_id   = adapter_id;
                                   acl_data->chandle      = 0; /* No connection handle at this layer */
                                   acl_data->remote_bd_addr_oui = 0;
                                   acl_data->remote_bd_addr_id  = 0;
                                   acl_data->is_btle = true;
                                   acl_data->is_btle_retransmit = false;
                                   acl_data->adapter_disconnect_in_frame = &bluetooth_max_disconnect_in_frame;
                                   acl_data->disconnect_in_frame = &bluetooth_max_disconnect_in_frame;
                                   call_dissector_with_data(btl2cap_handle, next_tvb, pinfo, tree, acl_data);
                                   handled = true;
                                   col_set_str(pinfo->cinfo, COL_INFO, "L2CAP Data");
                               } else {
                                   proto_item *item = proto_tree_add_item(btbredr_rf_tree, hf_l2cap_fragment, tvb, offset + data_header, data_length - data_header, ENC_NA);
                                   if (frame_info->missing_start)
                                       expert_add_info(pinfo, item, &ei_missing_fragment_start);
                                   handled = true;
                                   col_set_str(pinfo->cinfo, COL_INFO, "L2CAP Fragment");
                               }
                               break;

                           default:
                               break;
                           }
                           if (!handled)
                               proto_tree_add_item(btbredr_rf_tree, hf_asynchronous_data, tvb, offset + data_header, data_length - data_header, ENC_NA);
                           if (data_crc) {
                               proto_item *crc_item = NULL;
                               crc_item = proto_tree_add_item(btbredr_rf_tree, hf_crc, tvb, offset + data_length, 2, ENC_LITTLE_ENDIAN);
                               if ((flags & FLAGS_REFERENCE_UPPER_ADDRES_PART_VALID) && !check_crc(uap, tvb, offset, data_length + 2))
                                   expert_add_info(pinfo, crc_item, &ei_incorrect_crc);
                               offset += 2;
                           }
                           offset += data_length;
                       }
                   }
                   if (tvb_captured_length_remaining(tvb, offset) > 0)
                       proto_tree_add_item(btbredr_rf_tree, hf_data, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA);
               }
           } else {
               proto_tree_add_item(btbredr_rf_tree, hf_encrypted_data, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA);
               offset = tvb_reported_length(tvb);
           }
       } else {
           proto_tree_add_item(btbredr_rf_tree, hf_whitened_data, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA);
           offset = tvb_reported_length(tvb);
       }
   } else {
       if (tvb_captured_length_remaining(tvb, offset) > 0)
           proto_tree_add_expert(btbredr_rf_tree, pinfo, &ei_unexpected_data, tvb, offset, tvb_captured_length_remaining(tvb, offset));
       offset = tvb_reported_length(tvb);
   }

   if (!pinfo->fd->visited) {
       address *addr;

       addr = (address *) wmem_memdup(wmem_file_scope(), &pinfo->dl_src, sizeof(address));
       addr->data =  wmem_memdup(wmem_file_scope(), pinfo->dl_src.data, pinfo->dl_src.len);
       p_add_proto_data(wmem_file_scope(), pinfo, proto_bluetooth, BLUETOOTH_DATA_SRC, addr);

       addr = (address *) wmem_memdup(wmem_file_scope(), &pinfo->dl_dst, sizeof(address));
       addr->data =  wmem_memdup(wmem_file_scope(), pinfo->dl_dst.data, pinfo->dl_dst.len);
       p_add_proto_data(wmem_file_scope(), pinfo, proto_bluetooth, BLUETOOTH_DATA_DST, addr);
   }

   return offset;
}

static int
dissect_btbredr_fhs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item         *btbredr_fhs_item;
    proto_tree         *btbredr_fhs_tree;
    int                 offset = 0;
    uint32_t            interface_id;
    uint32_t            adapter_id;
    uint64_t            parity_lap_eir_sp_sr;
    uint32_t            lap;
    uint8_t             uap;
    uint16_t            nap;
    uint32_t            ltaddr_clk_pgscan;
    uint32_t            ltaddr;
    device_info_t      *device_info = NULL;
    connection_info_t  *connection_info = NULL;
    btbredr_fhs_data_t *fhs_data = (btbredr_fhs_data_t *) data;

    btbredr_fhs_item = proto_tree_add_item(tree, proto_btbredr_fhs, tvb, offset, -1, ENC_NA);
    btbredr_fhs_tree = proto_item_add_subtree(btbredr_fhs_item, ett_btbredr_fhs);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BT BR/EDR FHS");

    if (fhs_data->bluetooth_data)
        interface_id = fhs_data->bluetooth_data->interface_id;
    else if (pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID)
        interface_id = pinfo->rec->rec_header.packet_header.interface_id;
    else
        interface_id = HCI_INTERFACE_DEFAULT;

    if (fhs_data->bluetooth_data)
        adapter_id = fhs_data->bluetooth_data->adapter_id;
    else
        adapter_id = HCI_ADAPTER_DEFAULT;

    proto_tree_add_item(btbredr_fhs_tree, hf_fhs_parity, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(btbredr_fhs_tree, hf_fhs_lap, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(btbredr_fhs_tree, hf_fhs_eir, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(btbredr_fhs_tree, hf_fhs_reserved, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(btbredr_fhs_tree, hf_fhs_sr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(btbredr_fhs_tree, hf_fhs_sp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    parity_lap_eir_sp_sr = tvb_get_uint64(tvb, offset, ENC_LITTLE_ENDIAN);
    lap = (parity_lap_eir_sp_sr >> 34) & 0xffffff;
    offset += 8;
    proto_tree_add_item(btbredr_fhs_tree, hf_fhs_uap, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    uap = tvb_get_uint8(tvb, offset);
    offset += 1;
    proto_tree_add_item(btbredr_fhs_tree, hf_fhs_nap, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    nap = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(btbredr_fhs_tree, hf_fhs_class, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;
    proto_tree_add_item(btbredr_fhs_tree, hf_fhs_ltaddr, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(btbredr_fhs_tree, hf_fhs_clk, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(btbredr_fhs_tree, hf_fhs_pagescanmode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    ltaddr_clk_pgscan = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
    offset += 4;
    ltaddr = ltaddr_clk_pgscan & 0x00000007;

    {
        wmem_tree_key_t key[4];
        key[0].length = 1;
        key[0].key = &interface_id;
        key[1].length = 1;
        key[1].key = &adapter_id;
        key[2].length = 1;
        key[2].key = &lap;
        key[3].length = 0;
        key[3].key = NULL;

        device_info = (device_info_t *) wmem_tree_lookup32_array(device_info_tree, key);
        if (!device_info && !pinfo->fd->visited) {
            device_info = wmem_new0(wmem_file_scope(), device_info_t);
            device_info->interface_id   = interface_id;
            device_info->adapter_id     = adapter_id;
            device_info->bd_addr[0]     = nap >> 8;
            device_info->bd_addr[1]     = nap >> 0;
            device_info->bd_addr[2]     = uap;
            device_info->bd_addr[3]     = lap >> 16;
            device_info->bd_addr[4]     = lap >> 8;
            device_info->bd_addr[5]     = lap;
            device_info->dir            = pinfo->p2p_dir;
            wmem_tree_insert32_array(device_info_tree, key, device_info);
        }
    }
    if (ltaddr) {
        connection_info = lookup_connection_info(interface_id, adapter_id, lap, ltaddr, pinfo->num);
        if (!pinfo->fd->visited) {
            if (connection_info && fhs_data->device_info &&
                !memcmp(connection_info->bd_addr[BDADDR_PERIPHERAL], null_bd_addr, 6))
                memcpy(connection_info->bd_addr[BDADDR_PERIPHERAL], fhs_data->device_info->bd_addr, 6);
            if (!connection_info && device_info) {
                wmem_tree_key_t key[6];
                key[0].length = 1;
                key[0].key = &interface_id;
                key[1].length = 1;
                key[1].key = &adapter_id;
                key[2].length = 1;
                key[2].key = &lap;
                key[3].length = 1;
                key[3].key = &ltaddr;
                key[4].length = 1;
                key[4].key = &pinfo->num;
                key[5].length = 0;
                key[5].key = NULL;
                connection_info = wmem_new0(wmem_file_scope(), connection_info_t);
                connection_info->interface_id   = interface_id;
                connection_info->adapter_id     = adapter_id;
                connection_info->lt_addr        = ltaddr;
                connection_info->timestamp      = pinfo->abs_ts;
                connection_info->btclock        = (ltaddr_clk_pgscan >> 3) & 0x3ffffff;
                memcpy(connection_info->bd_addr[BDADDR_CENTRAL], device_info->bd_addr, 6);
                if (fhs_data->device_info)
                    memcpy(connection_info->bd_addr[BDADDR_PERIPHERAL], fhs_data->device_info->bd_addr, 6);
                wmem_tree_insert32_array(connection_info_tree, key, connection_info);
             }
        }
    }
    if (device_info) {
        set_address(&pinfo->dl_src, AT_ETHER, sizeof(device_info->bd_addr), device_info->bd_addr);
        set_address(&pinfo->net_src, AT_ETHER, sizeof(device_info->bd_addr), device_info->bd_addr);
        copy_address_shallow(&pinfo->src, &pinfo->net_src);
    }
    if (fhs_data->device_info) {
        set_address(&pinfo->dl_dst, AT_ETHER, sizeof(fhs_data->device_info->bd_addr), fhs_data->device_info->bd_addr);
        set_address(&pinfo->net_dst, AT_ETHER, sizeof(fhs_data->device_info->bd_addr), fhs_data->device_info->bd_addr);
        copy_address_shallow(&pinfo->dst, &pinfo->net_dst);
    }
    return offset;
}

void
proto_register_btbredr_rf(void)
{
    expert_module_t  *expert_module;

    static hf_register_info hf[] = {
        {  &hf_rf_channel,
            { "RF Channel",                                     "btbredr_rf.rf_channel",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_uncertain_rf_channel,
            { "Uncertain RF Channel",                           "btbredr_rf.uncertain_rf_channel",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_signal_power,
            { "Signal Power",                                   "btbredr_rf.signal_power",
            FT_INT8, BASE_DEC, NULL, 0x00,
            "Signal Power in dBm", HFILL }
        },
        {  &hf_invalid_signal_power,
            { "Invalid Signal Power",                           "btbredr_rf.invalid.signal_power",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_noise_power,
            { "Noise Power",                                    "btbredr_rf.noise_power",
            FT_INT8, BASE_DEC, NULL, 0x00,
            "Noise Power in dBm", HFILL }
        },
        {  &hf_invalid_noise_power,
            { "Invalid Noise Power",                            "btbredr_rf.invalid.noise_power",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_access_address_offenses,
            { "Access Address Offenses",                        "btbredr_rf.access_address_offenses",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_payload_transport_rate,
            { "Payload Transport Rate",                         "btbredr_rf.payload_transport_rate",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_payload_transport_rate_ignored,
            { "Payload Transport Rate: Ignored",                "btbredr_rf.payload_transport_rate.ignored",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            "BT Packet Header is ignored and there is no payload", HFILL }
        },
        {  &hf_payload_transport_rate_transport,
            { "Transport",                                      "btbredr_rf.payload_transport_rate.transport",
            FT_UINT8, BASE_HEX, VALS(payload_transport_rate_transport_vals), 0xF0,
            NULL, HFILL }
        },
        {  &hf_payload_transport_rate_payload,
            { "Payload",                                        "btbredr_rf.payload_transport_rate.payload",
            FT_UINT8, BASE_HEX, VALS(payload_transport_rate_payload_vals), 0x0F,
            NULL, HFILL }
        },
        {  &hf_corrected_header_bits,
            { "Corrected Header Bits",                          "btbredr_rf.corrected_header_bits",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_corrected_payload_bits,
            { "Corrected Payload Bits",                         "btbredr_rf.corrected_payload_bits",
            FT_INT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_lower_address_part,
            { "Lower Address Part",                             "btbredr_rf.lower_address_part",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_reference_lower_address_part,
            { "Reference Lower Address Part",                   "btbredr_rf.reference_lower_address_part",
            FT_UINT24, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_invalid_reference_lower_address_part,
            { "Invalid Reference Lower Address Part",           "btbredr_rf.invalid.reference_lower_address_part",
            FT_UINT24, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_reference_upper_addres_part,
            { "Reference Upper Address Part",                   "btbredr_rf.reference_upper_address_part",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_invalid_reference_upper_addres_part,
            { "Invalid Reference Upper Address Part",           "btbredr_rf.invalid.reference_upper_address_part",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_whitened_packet_header,
            { "Whitened Packet Header",                         "btbredr_rf.whitened.packet_header",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_invalid_packet_header,
            { "Invalid Packet Header",                          "btbredr_rf.invalid.packet_header",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_packet_header,
            { "Packet Header",                                  "btbredr_rf.packet_header",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_packet_header_lt_addr,
            { "LT_ADDR",                                        "btbredr_rf.packet_header.lt_addr",
            FT_UINT32, BASE_HEX, NULL, 0x00000007,
            NULL, HFILL }
        },
        {  &hf_packet_header_type,
            { "Type",                                           "btbredr_rf.packet_header.type",
            FT_UINT32, BASE_HEX, NULL, 0x00000078,
            NULL, HFILL }
        },
        {  &hf_packet_header_type_any,
            { "Type",                                           "btbredr_rf.packet_header.type",
            FT_UINT32, BASE_HEX, VALS(packet_type_any_vals), 0x00000078,
            NULL, HFILL }
        },
        {  &hf_packet_header_type_sco_br,
            { "Type",                                           "btbredr_rf.packet_header.type",
            FT_UINT32, BASE_HEX, VALS(packet_type_sco_br_vals), 0x00000078,
            NULL, HFILL }
        },
        {  &hf_packet_header_type_esco_br,
            { "Type",                                           "btbredr_rf.packet_header.type",
            FT_UINT32, BASE_HEX, VALS(packet_type_esco_br_vals), 0x00000078,
            NULL, HFILL }
        },
        {  &hf_packet_header_type_esco_edr,
            { "Type",                                           "btbredr_rf.packet_header.type",
            FT_UINT32, BASE_HEX, VALS(packet_type_esco_edr_vals), 0x00000078,
            NULL, HFILL }
        },
        {  &hf_packet_header_type_acl_br,
            { "Type",                                           "btbredr_rf.packet_header.type",
            FT_UINT32, BASE_HEX, VALS(packet_type_acl_br_vals), 0x00000078,
            NULL, HFILL }
        },
        {  &hf_packet_header_type_acl_edr,
            { "Type",                                           "btbredr_rf.packet_header.type",
            FT_UINT32, BASE_HEX, VALS(packet_type_acl_edr_vals), 0x00000078,
            NULL, HFILL }
        },
        {  &hf_packet_header_type_cpb_br,
            { "Type",                                           "btbredr_rf.packet_header.type",
            FT_UINT32, BASE_HEX, VALS(packet_type_cpb_br_vals), 0x00000078,
            NULL, HFILL }
        },
        {  &hf_packet_header_type_cpb_edr,
            { "Type",                                           "btbredr_rf.packet_header.type",
            FT_UINT32, BASE_HEX, VALS(packet_type_cpb_edr_vals), 0x00000078,
            NULL, HFILL }
        },
        {  &hf_packet_header_flow_control,
            { "Flow Control",                                   "btbredr_rf.packet_header.flow_control",
            FT_BOOLEAN, 32, NULL, 0x00000080,
            NULL, HFILL }
        },
        {  &hf_packet_header_acknowledge_indication,
            { "ARQN",                                           "btbredr_rf.packet_header.arqn",
            FT_BOOLEAN, 32, NULL, 0x00000100,
            "Acknowledge Indication", HFILL }
        },
        {  &hf_packet_header_sequence_number,
            { "SEQN",                                           "btbredr_rf.packet_header.seqn",
            FT_BOOLEAN, 32, NULL, 0x00000200,
            "Sequence Number", HFILL }
        },
        {  &hf_packet_header_header_error_check,
            { "HEC",                                            "btbredr_rf.packet_header.hec",
            FT_UINT32, BASE_HEX, NULL, 0x0003FC00,
            "Header Error Check", HFILL }
        },
        {  &hf_packet_header_reserved,
            { "Reserved",                                       "btbredr_rf.packet_header.reserved",
            FT_UINT32, BASE_HEX, NULL, 0xFFFC0000,
            NULL, HFILL }
        },
        {  &hf_packet_header_broken_lt_addr,
            { "LT_ADDR",                                        "btbredr_rf.packet_header.lt_addr",
            FT_UINT32, BASE_HEX, NULL, 0x00038000,
            NULL, HFILL }
        },
        {  &hf_packet_header_broken_type,
            { "Type",                                           "btbredr_rf.packet_header.type",
            FT_UINT32, BASE_HEX, NULL, 0x00007800,
            NULL, HFILL }
        },
        {  &hf_packet_header_broken_type_any,
            { "Type",                                           "btbredr_rf.packet_header.type",
            FT_UINT32, BASE_HEX, VALS(packet_type_any_vals), 0x00007800,
            NULL, HFILL }
        },
        {  &hf_packet_header_broken_type_sco_br,
            { "Type",                                           "btbredr_rf.packet_header.type",
            FT_UINT32, BASE_HEX, VALS(packet_type_sco_br_vals), 0x00007800,
            NULL, HFILL }
        },
        {  &hf_packet_header_broken_type_esco_br,
            { "Type",                                           "btbredr_rf.packet_header.type",
            FT_UINT32, BASE_HEX, VALS(packet_type_esco_br_vals), 0x00007800,
            NULL, HFILL }
        },
        {  &hf_packet_header_broken_type_esco_edr,
            { "Type",                                           "btbredr_rf.packet_header.type",
            FT_UINT32, BASE_HEX, VALS(packet_type_esco_edr_vals), 0x00007800,
            NULL, HFILL }
        },
        {  &hf_packet_header_broken_type_acl_br,
            { "Type",                                           "btbredr_rf.packet_header.type",
            FT_UINT32, BASE_HEX, VALS(packet_type_acl_br_vals), 0x00007800,
            NULL, HFILL }
        },
        {  &hf_packet_header_broken_type_acl_edr,
            { "Type",                                           "btbredr_rf.packet_header.type",
            FT_UINT32, BASE_HEX, VALS(packet_type_acl_edr_vals), 0x00007800,
            NULL, HFILL }
        },
        {  &hf_packet_header_broken_type_cpb_br,
            { "Type",                                           "btbredr_rf.packet_header.type",
            FT_UINT32, BASE_HEX, VALS(packet_type_cpb_br_vals), 0x00007800,
            NULL, HFILL }
        },
        {  &hf_packet_header_broken_type_cpb_edr,
            { "Type",                                           "btbredr_rf.packet_header.type",
            FT_UINT32, BASE_HEX, VALS(packet_type_cpb_edr_vals), 0x00007800,
            NULL, HFILL }
        },
        {  &hf_packet_header_broken_flow_control,
            { "Flow Control",                                   "btbredr_rf.packet_header.flow_control",
            FT_BOOLEAN, 32, NULL, 0x00000400,
            NULL, HFILL }
        },
        {  &hf_packet_header_broken_acknowledge_indication,
            { "ARQN",                                           "btbredr_rf.packet_header.arqn",
            FT_BOOLEAN, 32, NULL, 0x00000200,
            "Acknowledge Indication", HFILL }
        },
        {  &hf_packet_header_broken_sequence_number,
            { "SEQN",                                           "btbredr_rf.packet_header.seqn",
            FT_BOOLEAN, 32, NULL, 0x00000100,
            "Sequence Number", HFILL }
        },
        {  &hf_packet_header_broken_header_error_check,
            { "HEC",                                            "btbredr_rf.packet_header.hec",
            FT_UINT32, BASE_HEX, NULL, 0x000000FF,
            "Header Error Check", HFILL }
        },
        {  &hf_whitened_data,
            { "Whitened Data",                                  "btbredr_rf.whitened.data",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_encrypted_data,
            { "Encrypted Data",                                 "btbredr_rf.encrypted.data",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_data,
            { "Data",                                           "btbredr_rf.data",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_isochronous_data,
            { "Isochronous Data",                               "btbredr_rf.isochronous_data",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_asynchronous_data,
            { "Asynchronous Data",                              "btbredr_rf.asynchronous_data",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_l2cap_fragment,
            { "L2CAP Fragment",                                 "btbredr_rf.l2cap_data",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_crc,
            { "CRC",                                            "btbredr_rf.crc",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_flags,
            { "Flags",                                          "btbredr_rf.flags",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_flags_reserved_15_14,
            { "Reserved",                                       "btbredr_rf.flags.reserved.15_14",
            FT_UINT16, BASE_HEX, NULL, 0xC000,
            NULL, HFILL }
        },
        {  &hf_flags_mic_pass,
            { "MIC Pass",                                       "btbredr_rf.flags.mic_pass",
            FT_BOOLEAN, 16, NULL, 0x2000,
            NULL, HFILL }
        },
        {  &hf_flags_mic_checked,
            { "MIC Checked",                                    "btbredr_rf.flags.mic_check",
            FT_BOOLEAN, 16, NULL, 0x1000,
            NULL, HFILL }
        },
        {  &hf_flags_crc_pass,
            { "CRC Pass",                                       "btbredr_rf.flags.crc_pass",
            FT_BOOLEAN, 16, NULL, 0x0800,
            NULL, HFILL }
        },
        {  &hf_flags_crc_checked,
            { "CRC Checked",                                    "btbredr_rf.flags.crc_check",
            FT_BOOLEAN, 16, NULL, 0x0400,
            NULL, HFILL }
        },
        {  &hf_flags_hec_pass,
            { "HEC Pass",                                       "btbredr_rf.flags.hec_pass",
            FT_BOOLEAN, 16, NULL, 0x0200,
            NULL, HFILL }
        },
        {  &hf_flags_hec_checked,
            { "HEC Checked",                                    "btbredr_rf.flags.hec_check",
            FT_BOOLEAN, 16, NULL, 0x0100,
            NULL, HFILL }
        },
        {  &hf_flags_reference_upper_addres_part_valid,
            { "Reference Upper Address Part Valid",             "btbredr_rf.flags.reference_upper_address_part_valid",
            FT_BOOLEAN, 16, NULL, 0x0080,
            NULL, HFILL }
        },
        {  &hf_flags_rf_channel_aliasing,
            { "RF Channel Aliasing",                            "btbredr_rf.flags.rf_channel_aliasing",
            FT_BOOLEAN, 16, NULL, 0x0040,
            NULL, HFILL }
        },
        {  &hf_flags_br_edr_data_present,
            { "BR or EDR Data Present",                         "btbredr_rf.flags.bredr_data_present",
            FT_BOOLEAN, 16, NULL, 0x0020,
            NULL, HFILL }
        },
        {  &hf_flags_reference_lower_address_part_valid,
            { "Reference Lower Address Part Valid",             "btbredr_rf.flags.reference_lower_address_part_valid",
            FT_BOOLEAN, 16, NULL, 0x0010,
            NULL, HFILL }
        },
        {  &hf_flags_bredr_payload_decrypted,
            { "BR or EDR Payload Decrypted",                    "btbredr_rf.flags.bredr_payload_decrypted",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL }
        },
        {  &hf_flags_noise_power_valid,
            { "Noise Power Valid",                              "btbredr_rf.flags.noise_power_valid",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL }
        },
        {  &hf_flags_signal_power_valid,
            { "Signal Power Valid",                             "btbredr_rf.flags.signal_power_valid",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL }
        },
        {  &hf_flags_packet_header_and_br_edr_payload_dewhitened,
            { "Packet Header and BR/EDR Payload Dewhitened",    "btbredr_rf.flags.pkt_hdr_and_br_edr_payload_dewhitened",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL }
        },
        {  &hf_payload_header2,
            { "Payload Header",                                 "btbredr_rf.payload_header",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_payload_header2_llid,
            { "LLID",                                           "btbredr_rf.payload_header.llid",
            FT_UINT16, BASE_HEX, NULL, 0x0003,
            NULL, HFILL }
        },
        {  &hf_payload_header2_flow,
            { "Flow",                                           "btbredr_rf.payload_header.flow",
            FT_UINT16, BASE_HEX, NULL, 0x0004,
            NULL, HFILL }
        },
        {  &hf_payload_header2_length,
            { "Length",                                         "btbredr_rf.payload_header.length",
            FT_UINT16, BASE_HEX, NULL, 0x1ff8,
            NULL, HFILL }
        },
        {  &hf_payload_header2_rfu,
            { "RFU",                                            "btbredr_rf.payload_header.rfu",
            FT_UINT16, BASE_HEX, NULL, 0xe000,
            NULL, HFILL }
        },
        {  &hf_payload_header1,
            { "Payload Header",                                 "btbredr_rf.payload_header",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_payload_header1_llid,
            { "LLID",                                           "btbredr_rf.payload_header.llid",
            FT_UINT8, BASE_HEX, NULL, 0x03,
            NULL, HFILL }
        },
        {  &hf_payload_header1_flow,
            { "Flow",                                           "btbredr_rf.payload_header.flow",
            FT_UINT8, BASE_HEX, NULL, 0x04,
            NULL, HFILL }
        },
        {  &hf_payload_header1_length,
            { "Length",                                         "btbredr_rf.payload_header.length",
            FT_UINT8, BASE_HEX, NULL, 0xf8,
            NULL, HFILL }
        },
        {  &hf_l2cap_msg_fragments,
            { "L2CAP fragments",                                "btbredr_rf.l2cap.fragments",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_l2cap_msg_fragment,
            { "L2CAP fragment",                                 "btbredr_rf.l2cap.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_l2cap_msg_fragment_overlap,
            { "L2CAP fragment overlap",                         "btbredr_rf.l2cap.fragment.overlap",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        {  &hf_l2cap_msg_fragment_overlap_conflicts,
            { "L2CAP fragment overlapping with conflicting data", "btbredr_rf.l2cap.fragment.overlap.conflicts",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        {  &hf_l2cap_msg_fragment_multiple_tails,
            { "L2CAP has multiple tail fragments",              "btbredr_rf.l2cap.fragment.multiple_tails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        {  &hf_l2cap_msg_fragment_too_long_fragment,
            { "L2CAP fragment too long",                        "btbredr_rf.l2cap.fragment.too_long_fragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        {  &hf_l2cap_msg_fragment_error,
            { "L2CAP defragmentation error",                    "btbredr_rf.l2cap.fragment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_l2cap_msg_fragment_count,
            { "L2CAP fragment count",                           "btbredr_rf.l2cap.fragment.count",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_l2cap_msg_reassembled_in,
            { "Reassembled in",                                 "btbredr_rf.l2cap.reassembled.in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_l2cap_msg_reassembled_length,
            { "Reassembled L2CAP length",                       "btbredr_rf.l2cap.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        }
    };

    static hf_register_info hf_fhs[] = {
        {  &hf_fhs_parity,
            { "Parity Bits",                                    "btbredr_fhs.parity",
            FT_UINT64, BASE_HEX, NULL, 0x00000003ffffffff,
            NULL, HFILL }
        },
        {  &hf_fhs_lap,
            { "Lower Address Part",                             "btbredr_fhs.lap",
            FT_UINT64, BASE_HEX, NULL, 0x03fffffc00000000,
            NULL, HFILL }
        },
        {  &hf_fhs_eir,
            { "Extended Inquiry Response",                      "btbredr_fhs.eir",
            FT_UINT64, BASE_DEC, NULL, 0x0400000000000000,
            NULL, HFILL }
        },
        {  &hf_fhs_reserved,
            { "Reserved",                                       "btbredr_fhs.reserved",
            FT_UINT64, BASE_DEC, NULL, 0x0800000000000000,
            NULL, HFILL }
        },
        {  &hf_fhs_sr,
            { "Scan Repetition",                                "btbredr_fhs.sr",
            FT_UINT64, BASE_DEC|BASE_VAL64_STRING, VALS64(fhs_scan_repetition_vals), 0x3000000000000000,
            NULL, HFILL }
        },
        {  &hf_fhs_sp,
            { "SP",                                             "btbredr_fhs.sp",
            FT_UINT64, BASE_DEC, NULL, 0xc000000000000000,
            "shall be set to 10", HFILL }
        },
        {  &hf_fhs_uap,
            { "Upper Address Part",                             "btbredr_fhs.uap",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_fhs_nap,
            { "Non-Significant Address Part",                   "btbredr_fhs.nap",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_fhs_class,
            { "Class of Device",                                "btbredr_fhs.class",
            FT_UINT24, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_fhs_ltaddr,
            { "LT_ADDR",                                        "btbredr_fhs.ltaddr",
            FT_UINT32, BASE_DEC, NULL, 0x00000007,
            NULL, HFILL }
        },
        {  &hf_fhs_clk,
            { "CLK",                                            "btbredr_fhs.clk",
            FT_UINT32, BASE_HEX, NULL, 0x1ffffff8,
            NULL, HFILL }
        },
        {  &hf_fhs_pagescanmode,
            { "Page Scan Mode",                                 "btbredr_fhs.pagescanmode",
            FT_UINT32, BASE_DEC, VALS(fhs_page_scan_mode_vals), 0xe0000000,
            NULL, HFILL }
        }
    };

    static int *ett[] = {
        &ett_btbredr_rf,
        &ett_flags,
        &ett_payload_transport_rate,
        &ett_packet_header,
        &ett_bluetooth_header,
        &ett_payload_header,
        &ett_l2cap_msg_fragment,
        &ett_l2cap_msg_fragments,
        &ett_btbredr_fhs
    };

    static ei_register_info ei[] = {
        { &ei_unexpected_data,                    { "btbredr_rf.unexpected_data",                    PI_PROTOCOL, PI_WARN, "Unexpected data, BR or EDR Data Present flag is set to False", EXPFILL }},
        { &ei_reserved_not_zero,                  { "btbredr_rf.reserved_not_zero",                  PI_PROTOCOL, PI_WARN, "Reserved values are not zeros", EXPFILL }},
        { &ei_incorrect_packet_header_or_hec,     { "btbredr_rf.incorrect_packet_header_or_hec",     PI_PROTOCOL, PI_WARN, "Incorrect Packet Header or HEC", EXPFILL }},
        { &ei_packet_header_with_hec_not_checked, { "btbredr_rf.packet_header_with_hec_not_checked", PI_PROTOCOL, PI_NOTE, "Packet Header with HEC is not checked", EXPFILL }},
        { &ei_broken_packet_header_format,        { "btbredr_rf.broken_packet_header_format",        PI_PROTOCOL, PI_WARN, "Broken Packet Header Format", EXPFILL }},
        { &ei_incorrect_crc,                      { "btbredr_rf.incorrect_crc",                      PI_PROTOCOL, PI_WARN, "Incorrect CRC", EXPFILL }},
        { &ei_missing_fragment_start,             { "btbredr_rf.missing_fragment_start",             PI_SEQUENCE, PI_WARN, "Missing Fragment Start", EXPFILL }},
        { &ei_esco_incorrect_ltaddr,              { "btbredr_rf.esco_incorrect_ltaddr",              PI_PROTOCOL, PI_WARN, "Incorrect (e)SCO LT_ADDR", EXPFILL }},
        { &ei_esco_incorrect_length,              { "btbredr_rf.esco_incorrect_length",              PI_PROTOCOL, PI_WARN, "Incorrect eSCO Packet Length", EXPFILL }}
    };

    connection_info_tree = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    device_info_tree = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    proto_btbredr_rf = proto_register_protocol("Bluetooth Pseudoheader for BR/EDR", "BT BR/EDR RF", "btbredr_rf");
    proto_register_field_array(proto_btbredr_rf, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    btbredr_rf_handle = register_dissector("btbredr_rf", dissect_btbredr_rf, proto_btbredr_rf);

    proto_btbredr_fhs = proto_register_protocol("Bluetooth BR/EDR FHS", "BT BR/EDR FHS", "btbredr_fhs");
    proto_register_field_array(proto_btbredr_fhs, hf_fhs, array_length(hf_fhs));
    btbredr_fhs_handle = register_dissector("btbredr_fhs", dissect_btbredr_fhs, proto_btbredr_fhs);

    packet_type_sco_br_table   = register_dissector_table("btbredr_rf.packet_type.sco.br",   "BT Packet Type for SCO BR",   proto_btbredr_rf, FT_UINT8, BASE_HEX);
    packet_type_esco_br_table  = register_dissector_table("btbredr_rf.packet_type.esco.br",  "BT Packet Type for eSCO BR",  proto_btbredr_rf, FT_UINT8, BASE_HEX);
    packet_type_esco_edr_table = register_dissector_table("btbredr_rf.packet_type.esco.edr", "BT Packet Type for eSCO EDR", proto_btbredr_rf, FT_UINT8, BASE_HEX);
    packet_type_acl_br_table   = register_dissector_table("btbredr_rf.packet_type.acl.br",   "BT Packet Type for ACL BR",   proto_btbredr_rf, FT_UINT8, BASE_HEX);
    packet_type_acl_edr_table  = register_dissector_table("btbredr_rf.packet_type.acl.edr",  "BT Packet Type for ACL EDR",  proto_btbredr_rf, FT_UINT8, BASE_HEX);
    packet_type_cpb_br_table   = register_dissector_table("btbredr_rf.packet_type.cpb.br",   "BT Packet Type for CPB BR",   proto_btbredr_rf, FT_UINT8, BASE_HEX);
    packet_type_cpb_edr_table  = register_dissector_table("btbredr_rf.packet_type.cpb.edr",  "BT Packet Type for CPB EDR",  proto_btbredr_rf, FT_UINT8, BASE_HEX);

    expert_module = expert_register_protocol(proto_btbredr_rf);
    expert_register_field_array(expert_module, ei, array_length(ei));
}

void
proto_reg_handoff_btbredr_rf(void)
{
    btlmp_handle = find_dissector_add_dependency("btlmp", proto_btbredr_rf);
    btl2cap_handle = find_dissector_add_dependency("btl2cap", proto_btbredr_rf);
    dissector_add_uint("bluetooth.encap", WTAP_ENCAP_BLUETOOTH_BREDR_BB, btbredr_rf_handle);
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

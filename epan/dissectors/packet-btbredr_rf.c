/* packet-btbredr_rf.c
 * Routines for Bluetooth Pseudoheader for BR/EDR Baseband
 *
 * Copyright 2014, Michal Labedzki for Tieto Corporation
 * Copyright 2014, Dominic Spill <dominicgs@gmail.com>
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
#include <epan/expert.h>

#include <wiretap/wtap.h>

#include "packet-bluetooth.h"

static int proto_btbredr_rf = -1;

static int hf_rf_channel = -1;
static int hf_uncertain_rf_channel = -1;
static int hf_signal_power = -1;
static int hf_invalid_signal_power = -1;
static int hf_noise_power = -1;
static int hf_invalid_noise_power = -1;
static int hf_access_address_offenses = -1;
static int hf_payload_transport_rate = -1;
static int hf_payload_transport_rate_payload = -1;
static int hf_payload_transport_rate_transport = -1;
static int hf_payload_transport_rate_ignored = -1;
static int hf_corrected_header_bits = -1;
static int hf_corrected_payload_bits = -1;
static int hf_lower_address_part = -1;
static int hf_reference_lower_address_part = -1;
static int hf_invalid_reference_lower_address_part = -1;
static int hf_reference_upper_addres_part = -1;
static int hf_invalid_reference_upper_addres_part = -1;
static int hf_whitened_packet_header = -1;
static int hf_packet_header = -1;
static int hf_packet_header_reserved = -1;
static int hf_packet_header_lt_addr = -1;
static int hf_packet_header_type = -1;
static int hf_packet_header_type_any = -1;
static int hf_packet_header_type_sco_br = -1;
static int hf_packet_header_type_esco_br = -1;
static int hf_packet_header_type_esco_edr = -1;
static int hf_packet_header_type_acl_br = -1;
static int hf_packet_header_type_acl_edr = -1;
static int hf_packet_header_type_csb_br = -1;
static int hf_packet_header_type_csb_edr = -1;
static int hf_packet_header_flow_control = -1;
static int hf_packet_header_acknowledge_indication = -1;
static int hf_packet_header_sequence_number = -1;
static int hf_packet_header_header_error_check = -1;
static int hf_flags = -1;
static int hf_flags_reserved_15_14 = -1;
static int hf_flags_mic_pass = -1;
static int hf_flags_mic_checked = -1;
static int hf_flags_crc_pass = -1;
static int hf_flags_crc_checked = -1;
static int hf_flags_hec_pass = -1;
static int hf_flags_hec_checked = -1;
static int hf_flags_reference_upper_addres_part_valid = -1;
static int hf_flags_rf_channel_aliasing = -1;
static int hf_flags_br_edr_data_present = -1;
static int hf_flags_reference_lower_address_part_valid = -1;
static int hf_flags_bredr_payload_decrypted = -1;
static int hf_flags_noise_power_valid = -1;
static int hf_flags_signal_power_valid = -1;
static int hf_flags_packet_header_and_br_edr_payload_dewhitened = -1;
static int hf_whitened_data = -1;
static int hf_encrypted_data = -1;
static int hf_data = -1;

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

static const int *hfx_payload_transport_rate[] = {
    &hf_payload_transport_rate_payload,
    &hf_payload_transport_rate_transport,
    NULL
};

static expert_field ei_unexpected_data = EI_INIT;
static expert_field ei_reserved_not_zero = EI_INIT;
static expert_field ei_incorrect_packet_header_or_hec = EI_INIT;
static expert_field ei_packet_header_with_hec_not_checked = EI_INIT;

static gint ett_btbredr_rf = -1;
static gint ett_flags = -1;
static gint ett_payload_transport_rate = -1;
static gint ett_packet_header = -1;
static gint ett_bluetooth_header = -1;

static dissector_table_t  packet_type_sco_br_table;
static dissector_table_t  packet_type_esco_br_table;
static dissector_table_t  packet_type_esco_edr_table;
static dissector_table_t  packet_type_acl_br_table;
static dissector_table_t  packet_type_acl_edr_table;
static dissector_table_t  packet_type_csb_br_table;
static dissector_table_t  packet_type_csb_edr_table;

static dissector_handle_t btbredr_rf_handle;

static const value_string payload_transport_rate_transport_vals[] = {
    { 0x00, "Any" },
    { 0x01, "SCO" },
    { 0x02, "eSCO" },
    { 0x03, "ACL" },
    { 0x04, "CSB" },
    { 0,    NULL }
};

#define TRANSPORT_ANY   0x00
#define TRANSPORT_SCO   0x10
#define TRANSPORT_eSCO  0x20
#define TRANSPORT_ACL   0x30
#define TRANSPORT_CSB   0x40


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

static const value_string packet_type_csb_br_vals[] = {
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

static const value_string packet_type_csb_edr_vals[] = {
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

void proto_register_btbredr_rf(void);
void proto_reg_handoff_btbredr_rf(void);

static guint8 reverse_bits(guint8 value)
{
    return (value & 0x80) >> 7 | (value & 0x40) >> 5 | (value & 0x20) >> 3 |
            (value & 0x10) >> 1 | (value & 0x08) << 1 | (value & 0x04) << 3 |
            (value & 0x02) << 5 | (value & 0x01) << 7;
}

static gboolean check_hec(guint8 uap, guint32 header)
{
    guint8   hec;
    guint16  header_data;
    guint8   lfsr;
    gint8    i;

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

static gint
dissect_btbredr_rf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item         *btbredr_rf_item;
    proto_tree         *btbredr_rf_tree;
    proto_item         *flags_item;
    proto_tree         *flags_tree;
    proto_item         *header_item;
    proto_tree         *header_tree;
    proto_item         *reserved_item;
    proto_item         *hec_item = NULL;
    gint                offset = 0;
    gint                hf_x;
    guint16             flags;
    guint8              payload_and_transport;
    gint16              packet_type = PACKET_TYPE_UNKNOWN;
    const gchar        *packet_type_str = "Unknown";
    dissector_table_t   packet_type_table = NULL;
    bluetooth_data_t   *bluetooth_data = (bluetooth_data_t *) data;

    btbredr_rf_item = proto_tree_add_item(tree, proto_btbredr_rf, tvb, offset, -1, ENC_NA);
    btbredr_rf_tree = proto_item_add_subtree(btbredr_rf_item, ett_btbredr_rf);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BT BR/EDR RF");

    if (tvb_captured_length(tvb) >= 21) {
        flags = tvb_get_guint16(tvb, 20, ENC_LITTLE_ENDIAN);
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

    payload_and_transport = tvb_get_guint8(tvb, offset);

    col_add_fstr(pinfo->cinfo, COL_INFO, "Transport: %s (%s), RF Channel: %s%2u",
            val_to_str_const(payload_and_transport >> 4, payload_transport_rate_transport_vals, "Unknown"),
            val_to_str_const(payload_and_transport & 0xF, payload_transport_rate_payload_abbrev_vals, "Unknown"),
            (flags & FLAGS_RF_CHANNEL_ALIASING) ? "~" : "",
            tvb_get_guint8(tvb, 0));

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
    offset += 4;

    if (flags & FLAGS_REFERENCE_LOWER_ADDRESS_PART_VALID)
        hf_x = hf_reference_lower_address_part;
    else
        hf_x = hf_invalid_reference_lower_address_part;
    proto_tree_add_item(btbredr_rf_tree, hf_x, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;

    if (flags & FLAGS_REFERENCE_UPPER_ADDRES_PART_VALID)
        hf_x = hf_reference_upper_addres_part;
    else
        hf_x = hf_invalid_reference_upper_addres_part;
    proto_tree_add_item(btbredr_rf_tree, hf_x, tvb, offset, 1, ENC_NA);
    offset += 1;

    if (!(flags & FLAGS_PACKET_HEADER_AND_BR_EDR_PAYLOAD_DEWHITENED)) {
       proto_tree_add_item(btbredr_rf_tree, hf_whitened_packet_header, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    } else {
        header_item = proto_tree_add_item(btbredr_rf_tree, hf_packet_header, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        header_tree = proto_item_add_subtree(header_item, ett_bluetooth_header);

        proto_tree_add_item(header_tree, hf_packet_header_reserved, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(header_tree, hf_packet_header_lt_addr, tvb, offset, 4, ENC_LITTLE_ENDIAN);

        if (payload_and_transport == (TRANSPORT_SCO | PAYLOAD_BR)) {
            proto_tree_add_item(header_tree, hf_packet_header_type_sco_br, tvb, offset, 4, ENC_LITTLE_ENDIAN);

            packet_type = (tvb_get_guint8(tvb, offset + 1) >> 3) & 0xF;
            packet_type_str = val_to_str_const(packet_type, packet_type_sco_br_vals, "Unknown");
            packet_type_table = packet_type_sco_br_table;
        } else if (payload_and_transport == (TRANSPORT_eSCO | PAYLOAD_BR)) {
            proto_tree_add_item(header_tree, hf_packet_header_type_esco_br, tvb, offset, 4, ENC_LITTLE_ENDIAN);

            packet_type = (tvb_get_guint8(tvb, offset + 1) >> 3) & 0xF;
            packet_type_str = val_to_str_const(packet_type, packet_type_esco_br_vals, "Unknown");
            packet_type_table = packet_type_esco_br_table;
        } else if (payload_and_transport == (TRANSPORT_eSCO | PAYLOAD_EDR_2) || payload_and_transport == (TRANSPORT_eSCO | PAYLOAD_EDR_3)) {
            proto_tree_add_item(header_tree, hf_packet_header_type_esco_edr, tvb, offset, 4, ENC_LITTLE_ENDIAN);

            packet_type = (tvb_get_guint8(tvb, offset + 1) >> 3) & 0xF;
            packet_type_str = val_to_str_const(packet_type, packet_type_esco_edr_vals, "Unknown");
            packet_type_table = packet_type_esco_edr_table;
        } else if (payload_and_transport == (TRANSPORT_ACL | PAYLOAD_BR)) {
            proto_tree_add_item(header_tree, hf_packet_header_type_acl_br, tvb, offset, 4, ENC_LITTLE_ENDIAN);

            packet_type = (tvb_get_guint8(tvb, offset + 1) >> 3) & 0xF;
            packet_type_str = val_to_str_const(packet_type, packet_type_acl_br_vals, "Unknown");
            packet_type_table = packet_type_acl_br_table;
        } else if (payload_and_transport == (TRANSPORT_ACL | PAYLOAD_EDR_2) || payload_and_transport == (TRANSPORT_ACL | PAYLOAD_EDR_3)) {
            proto_tree_add_item(header_tree, hf_packet_header_type_acl_edr, tvb, offset, 4, ENC_LITTLE_ENDIAN);

            packet_type = (tvb_get_guint8(tvb, offset + 1) >> 3) & 0xF;
            packet_type_str = val_to_str_const(packet_type, packet_type_acl_edr_vals, "Unknown");
            packet_type_table = packet_type_acl_edr_table;
        } else if (payload_and_transport == (TRANSPORT_CSB | PAYLOAD_BR)) {
            proto_tree_add_item(header_tree, hf_packet_header_type_csb_br, tvb, offset, 4, ENC_LITTLE_ENDIAN);

            packet_type = (tvb_get_guint8(tvb, offset + 1) >> 3) & 0xF;
            packet_type_str = val_to_str_const(packet_type, packet_type_csb_br_vals, "Unknown");
            packet_type_table = packet_type_csb_br_table;
        } else if (payload_and_transport == (TRANSPORT_CSB | PAYLOAD_EDR_2) || payload_and_transport == (TRANSPORT_ACL | PAYLOAD_EDR_3)) {
            proto_tree_add_item(header_tree, hf_packet_header_type_csb_edr, tvb, offset, 4, ENC_LITTLE_ENDIAN);

            packet_type = (tvb_get_guint8(tvb, offset + 1) >> 3) & 0xF;
            packet_type_str = val_to_str_const(packet_type, packet_type_csb_edr_vals, "Unknown");
            packet_type_table = packet_type_csb_edr_table;
        } else if ((payload_and_transport >> 4) == TRANSPORT_ANY) {
            proto_tree_add_item(header_tree, hf_packet_header_type_any, tvb, offset, 4, ENC_LITTLE_ENDIAN);

            packet_type = (tvb_get_guint8(tvb, offset + 1) >> 3) & 0xF;
            packet_type_str = val_to_str_const(packet_type, packet_type_any_vals, "Unknown");
        } else {
            proto_tree_add_item(header_tree, hf_packet_header_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        }

        proto_tree_add_item(header_tree, hf_packet_header_flow_control, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(header_tree, hf_packet_header_acknowledge_indication, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(header_tree, hf_packet_header_sequence_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        hec_item = proto_tree_add_item(header_tree, hf_packet_header_header_error_check, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    }

    if ((flags & FLAGS_REFERENCE_UPPER_ADDRES_PART_VALID) &&
            (flags & FLAGS_PACKET_HEADER_AND_BR_EDR_PAYLOAD_DEWHITENED) &&
            !check_hec(tvb_get_guint8(tvb, offset - 1), tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN))) {
        expert_add_info(pinfo, hec_item, &ei_incorrect_packet_header_or_hec);
    }
    if (!((flags & FLAGS_REFERENCE_UPPER_ADDRES_PART_VALID) &&
            (flags & FLAGS_PACKET_HEADER_AND_BR_EDR_PAYLOAD_DEWHITENED))) {
        expert_add_info(pinfo, hec_item, &ei_packet_header_with_hec_not_checked);
    }

    offset += 4;

    flags_item = proto_tree_add_item(btbredr_rf_tree, hf_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    flags_tree = proto_item_add_subtree(flags_item, ett_flags);

    flags = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);

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
                (gint)(gint8)tvb_get_guint8(tvb, 1), (gint)(gint8)tvb_get_guint8(tvb, 2));
    } else if (flags & FLAGS_SIGNAL_POWER_VALID) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (SP: %4i)",
                (gint)(gint8)tvb_get_guint8(tvb, 1));
    } else if (flags & FLAGS_NOISE_POWER_VALID) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (NP: %4i)",
                (gint)(gint8)tvb_get_guint8(tvb, 2));
    }

   if (flags & FLAGS_PACKET_HEADER_AND_BR_EDR_PAYLOAD_DEWHITENED)
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Packet Type: %s", packet_type_str);

    if (flags & FLAGS_BR_EDR_DATA_PRESENT) {
       if (flags & FLAGS_PACKET_HEADER_AND_BR_EDR_PAYLOAD_DEWHITENED) {
            if (flags & FLAGS_BREDR_PAYLOAD_DECRYPTED) {
                tvbuff_t       *next_tvb;

                next_tvb = tvb_new_subset_remaining(tvb, offset);
                if (!(packet_type_table && packet_type > PACKET_TYPE_UNKNOWN &&
                        dissector_try_uint_new(packet_type_table, packet_type, next_tvb, pinfo, tree, TRUE, bluetooth_data)))
                    proto_tree_add_item(btbredr_rf_tree, hf_data, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA);
                offset = tvb_reported_length(tvb);
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
            { "Reference Upper Address Part",                   "btbredr_rf.reference_upper_addres_part",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_invalid_reference_upper_addres_part,
            { "Invalid Reference Upper Address Part",           "btbredr_rf.invalid.reference_upper_addres_part",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_whitened_packet_header,
            { "Whitened Packet Header",                         "btbredr_rf.whitened.packet_header",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_packet_header,
            { "Packet Header",                                  "btbredr_rf.packet_header",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_packet_header_reserved,
            { "Reserved",                                       "btbredr_rf.packet_header.reserved",
            FT_UINT32, BASE_HEX, NULL, 0xFFFC0000,
            NULL, HFILL }
        },
        {  &hf_packet_header_lt_addr,
            { "LT_ADDR",                                        "btbredr_rf.packet_header.lt_addr",
            FT_UINT32, BASE_HEX, NULL, 0x00038000,
            NULL, HFILL }
        },
        {  &hf_packet_header_type,
            { "Type",                                           "btbredr_rf.packet_header.type",
            FT_UINT32, BASE_HEX, NULL, 0x00007800,
            NULL, HFILL }
        },
        {  &hf_packet_header_type_any,
            { "Type",                                           "btbredr_rf.packet_header.type",
            FT_UINT32, BASE_HEX, VALS(packet_type_any_vals), 0x00007800,
            NULL, HFILL }
        },
        {  &hf_packet_header_type_sco_br,
            { "Type",                                           "btbredr_rf.packet_header.type",
            FT_UINT32, BASE_HEX, VALS(packet_type_sco_br_vals), 0x00007800,
            NULL, HFILL }
        },
        {  &hf_packet_header_type_esco_br,
            { "Type",                                           "btbredr_rf.packet_header.type",
            FT_UINT32, BASE_HEX, VALS(packet_type_esco_br_vals), 0x00007800,
            NULL, HFILL }
        },
        {  &hf_packet_header_type_esco_edr,
            { "Type",                                           "btbredr_rf.packet_header.type",
            FT_UINT32, BASE_HEX, VALS(packet_type_esco_edr_vals), 0x00007800,
            NULL, HFILL }
        },
        {  &hf_packet_header_type_acl_br,
            { "Type",                                           "btbredr_rf.packet_header.type",
            FT_UINT32, BASE_HEX, VALS(packet_type_acl_br_vals), 0x00007800,
            NULL, HFILL }
        },
        {  &hf_packet_header_type_acl_edr,
            { "Type",                                           "btbredr_rf.packet_header.type",
            FT_UINT32, BASE_HEX, VALS(packet_type_acl_edr_vals), 0x00007800,
            NULL, HFILL }
        },
        {  &hf_packet_header_type_csb_br,
            { "Type",                                           "btbredr_rf.packet_header.type",
            FT_UINT32, BASE_HEX, VALS(packet_type_csb_br_vals), 0x00007800,
            NULL, HFILL }
        },
        {  &hf_packet_header_type_csb_edr,
            { "Type",                                           "btbredr_rf.packet_header.type",
            FT_UINT32, BASE_HEX, VALS(packet_type_csb_edr_vals), 0x00007800,
            NULL, HFILL }
        },
        {  &hf_packet_header_flow_control,
            { "Flow Control",                                   "btbredr_rf.packet_header.flow_control",
            FT_BOOLEAN, 32, NULL, 0x00000400,
            NULL, HFILL }
        },
        {  &hf_packet_header_acknowledge_indication,
            { "ARQN",                                           "btbredr_rf.packet_header.arqn",
            FT_BOOLEAN, 32, NULL, 0x00000200,
            "Acknowledge Indication", HFILL }
        },
        {  &hf_packet_header_sequence_number,
            { "SEQN",                                           "btbredr_rf.packet_header.seqn",
            FT_BOOLEAN, 32, NULL, 0x00000100,
            "Sequence Number", HFILL }
        },
        {  &hf_packet_header_header_error_check,
            { "HEC",                                            "btbredr_rf.packet_header.hec",
            FT_UINT32, BASE_HEX, NULL, 0x000000FF,
            "Header Error Check", HFILL }
        },
        {  &hf_flags,
            { "Flags",                                          "btbredr_rf.flags",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
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
            { "Reference Upper Address Part Valid",             "btbredr_rf.flags.reference_upper_addres_part_valid",
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
        }
    };

    static gint *ett[] = {
        &ett_btbredr_rf,
        &ett_flags,
        &ett_payload_transport_rate,
        &ett_packet_header,
        &ett_bluetooth_header
    };

    static ei_register_info ei[] = {
        { &ei_unexpected_data,                    { "btbredr_rf.unexpected_data",                    PI_PROTOCOL, PI_WARN, "Unexpected data, BR or EDR Data Present flag is set to False", EXPFILL }},
        { &ei_reserved_not_zero,                  { "btbredr_rf.reserved_not_zero",                  PI_PROTOCOL, PI_WARN, "Reserved values are not zeros", EXPFILL }},
        { &ei_incorrect_packet_header_or_hec,     { "btbredr_rf.incorrect_packet_header_or_hec",     PI_PROTOCOL, PI_WARN, "Incorrect Packet Header or HEC", EXPFILL }},
        { &ei_packet_header_with_hec_not_checked, { "btbredr_rf.packet_header_with_hec_not_checked", PI_PROTOCOL, PI_NOTE, "Packet Header with HEC is not checked", EXPFILL }},
    };

    proto_btbredr_rf = proto_register_protocol("Bluetooth Pseudoheader for BR/EDR", "BT BR/EDR RF", "btbredr_rf");
    proto_register_field_array(proto_btbredr_rf, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    btbredr_rf_handle = register_dissector("btbredr_rf", dissect_btbredr_rf, proto_btbredr_rf);

    packet_type_sco_br_table   = register_dissector_table("btbredr_rf.packet_type.sco.br",   "BT Packet Type for SCO BR",   proto_btbredr_rf, FT_UINT8, BASE_HEX);
    packet_type_esco_br_table  = register_dissector_table("btbredr_rf.packet_type.esco.br",  "BT Packet Type for eSCO BR",  proto_btbredr_rf, FT_UINT8, BASE_HEX);
    packet_type_esco_edr_table = register_dissector_table("btbredr_rf.packet_type.esco.edr", "BT Packet Type for eSCO EDR", proto_btbredr_rf, FT_UINT8, BASE_HEX);
    packet_type_acl_br_table   = register_dissector_table("btbredr_rf.packet_type.acl.br",   "BT Packet Type for ACL BR",   proto_btbredr_rf, FT_UINT8, BASE_HEX);
    packet_type_acl_edr_table  = register_dissector_table("btbredr_rf.packet_type.acl.edr",  "BT Packet Type for ACL EDR",  proto_btbredr_rf, FT_UINT8, BASE_HEX);
    packet_type_csb_br_table   = register_dissector_table("btbredr_rf.packet_type.csb.br",   "BT Packet Type for CSB BR",   proto_btbredr_rf, FT_UINT8, BASE_HEX);
    packet_type_csb_edr_table  = register_dissector_table("btbredr_rf.packet_type.csb.edr",  "BT Packet Type for CSB EDR",  proto_btbredr_rf, FT_UINT8, BASE_HEX);

    expert_module = expert_register_protocol(proto_btbredr_rf);
    expert_register_field_array(expert_module, ei, array_length(ei));
}

void
proto_reg_handoff_btbredr_rf(void)
{
    dissector_add_uint("bluetooth.encap", WTAP_ENCAP_BLUETOOTH_BREDR_BB, btbredr_rf_handle);
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

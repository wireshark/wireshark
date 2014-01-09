/* packet-ubertooth.c
 * Routines for Ubertooth USB dissection
 *
 * Copyright 2013, Michal Labedzki for Tieto Corporation
 *
 * $Id$
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
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/wmem/wmem.h>
#include <epan/addr_resolv.h>

#include "packet-bluetooth-hci.h"
#include "packet-usb.h"

static int proto_ubertooth = -1;

static int hf_command = -1;
static int hf_response = -1;
static int hf_argument_0 = -1;
static int hf_argument_1 = -1;
static int hf_estimated_length = -1;
static int hf_board_id = -1;
static int hf_reserved = -1;
static int hf_length = -1;
static int hf_firmware_revision = -1;
static int hf_firmware_compile_info = -1;
static int hf_user_led = -1;
static int hf_rx_led = -1;
static int hf_tx_led = -1;
static int hf_1v8_led = -1;
static int hf_channel = -1;
static int hf_status = -1;
static int hf_serial_number = -1;
static int hf_part_number = -1;
static int hf_packet_type = -1;
static int hf_chip_status_dma_overflow = -1;
static int hf_chip_status_dma_error = -1;
static int hf_chip_status_cs_trigger = -1;
static int hf_chip_status_fifo_overflow = -1;
static int hf_chip_status_rssi_trigger = -1;
static int hf_chip_status_reserved = -1;
static int hf_clock_ns = -1;
static int hf_clock_100ns = -1;
static int hf_rssi_min = -1;
static int hf_rssi_max = -1;
static int hf_rssi_avg = -1;
static int hf_rssi_count = -1;
static int hf_data = -1;
static int hf_crc_verify = -1;
static int hf_paen = -1;
static int hf_hgm = -1;
static int hf_modulation = -1;
static int hf_power_amplifier_reserved = -1;
static int hf_power_amplifier_level = -1;
static int hf_range_test_valid = -1;
static int hf_range_test_request_power_amplifier = -1;
static int hf_range_test_request_number = -1;
static int hf_range_test_reply_power_amplifier = -1;
static int hf_range_test_reply_number = -1;
static int hf_squelch = -1;
static int hf_register = -1;
static int hf_register_value = -1;
static int hf_access_address = -1;
static int hf_high_frequency = -1;
static int hf_low_frequency = -1;
static int hf_rx_packets = -1;
static int hf_rssi_threshold = -1;
static int hf_clock_offset = -1;
static int hf_afh_map = -1;
static int hf_bdaddr = -1;
static int hf_usb_rx_packet = -1;
static int hf_usb_rx_packet_channel = -1;
static int hf_spectrum_entry = -1;
static int hf_frequency = -1;
static int hf_rssi = -1;

static gint ett_ubertooth = -1;
static gint ett_command = -1;
static gint ett_usb_rx_packet = -1;
static gint ett_usb_rx_packet_data = -1;
static gint ett_entry = -1;

static expert_field ei_unexpected_response = EI_INIT;
static expert_field ei_unknown_data = EI_INIT;
static expert_field ei_unexpected_data = EI_INIT;

static dissector_handle_t ubertooth_handle;
static dissector_handle_t btle_handle;

static wmem_tree_t *command_info = NULL;

typedef struct _command_data {
    guint32  bus_id;
    guint32  device_address;

    guint8   command;
    guint32  command_frame_number;
    gint32   register_id;
} command_data_t;


static const value_string command_vals[] = {
    { 0,  "Ping" },
    { 1,  "Rx Symbols" },
    { 2,  "Tx Symbols" },
    { 3,  "Get User LED" },
    { 4,  "Set User LED" },
    { 5,  "Get Rx LED" },
    { 6,  "Set Rx LED" },
    { 7,  "Get Tx LED" },
    { 8,  "Set Tx LED" },
    { 9,  "Get 1V8" },
    { 10,  "Set 1V8" },
    { 11,  "Get Channel" },
    { 12,  "Set Channel" },
    { 13,  "Reset" },
    { 14,  "Get Microcontroller Serial Number" },
    { 15,  "Get Microcontroller Part Number" },
    { 16,  "Get PAEN" },
    { 17,  "Set PAEN" },
    { 18,  "Get HGM" },
    { 19,  "Set HGM" },
    { 20,  "Tx Test" },
    { 21,  "Stop" },
    { 22,  "Get Modulation" },
    { 23,  "Set Modulation" },
    { 24,  "Set ISP" },
    { 25,  "Flash" },
    { 26,  "Bootloader Flash" },
    { 27,  "Spectrum Analyzer" },
    { 28,  "Get Power Amplifier Level" },
    { 29,  "Set Power Amplifier Level" },
    { 30,  "Repeater" },
    { 31,  "Range Test" },
    { 32,  "Range Check" },
    { 33,  "Get Firmware Revision Number" },
    { 34,  "LED Spectrum Analyzer" },
    { 35,  "Get Hardware Board ID" },
    { 36,  "Set Squelch" },
    { 37,  "Get Squelch" },
    { 38,  "Set BDADDR" },
    { 39,  "Start Hopping" },
    { 40,  "Set Clock" },
    { 41,  "Get Clock" },
    { 42,  "BTLE Sniffing" },
    { 43,  "Get Access Address" },
    { 44,  "Set Access Address" },
    { 45,  "Do Something" },
    { 46,  "Do Something Reply" },
    { 47,  "Get CRC Verify" },
    { 48,  "Set CRC Verify" },
    { 49,  "Poll" },
    { 50,  "BTLE Promiscuous Mode" },
    { 51,  "Set AFH Map" },
    { 52,  "Clear AFH Map" },
    { 53,  "Read Register" },
    { 54,  "BTLE Slave" },
    { 55,  "Get Compile Info" },
    { 0x00, NULL }
};
static value_string_ext(command_vals_ext) = VALUE_STRING_EXT_INIT(command_vals);

static const value_string board_id_vals[] = {
    { 0x00,  "Ubertooth Zero" },
    { 0x01,  "Ubertooth One" },
    { 0x02,  "ToorCon 13 Badge" },
    { 0x00, NULL }
};
static value_string_ext(board_id_vals_ext) = VALUE_STRING_EXT_INIT(board_id_vals);

static const value_string led_state_vals[] = {
    { 0x00,  "Off" },
    { 0x01,  "On" },
    { 0x00, NULL }
};
static value_string_ext(led_state_vals_ext) = VALUE_STRING_EXT_INIT(led_state_vals);

static const value_string state_vals[] = {
    { 0x00,  "False" },
    { 0x01,  "True" },
    { 0x00, NULL }
};
static value_string_ext(state_vals_ext) = VALUE_STRING_EXT_INIT(state_vals);

static const value_string packet_type_vals[] = {
    { 0x00,  "BR/EDR" },
    { 0x01,  "LE" },
    { 0x02,  "Message" },
    { 0x03,  "Keep Alive" },
    { 0x00, NULL }
};
static value_string_ext(packet_type_vals_ext) = VALUE_STRING_EXT_INIT(packet_type_vals);

static const value_string modulation_vals[] = {
    { 0x00,  "Basic Rate" },
    { 0x01,  "Low Energy" },
    { 0x02,  "802.11 FHSS" },
    { 0x00, NULL }
};
static value_string_ext(modulation_vals_ext) = VALUE_STRING_EXT_INIT(modulation_vals);

static const value_string register_vals[] = {
    { 0x00,  "MAIN" },
    { 0x01,  "FSCTRL" },
    { 0x02,  "FSDIV" },
    { 0x03,  "MDMCTRL" },
    { 0x04,  "AGCCTRL" },
    { 0x05,  "FREND" },
    { 0x06,  "RSSI" },
    { 0x07,  "FREQEST" },
    { 0x08,  "IOCFG" },
    { 0x0B,  "FSMTC" },
    { 0x0C,  "RESERVED" },
    { 0x0D,  "MANAND" },
    { 0x0E,  "FSMSTATE" },
    { 0x0F,  "ADCTST" },
    { 0x10,  "RXBPFTST" },
    { 0x11,  "PAMTST" },
    { 0x12,  "LMTST" },
    { 0x13,  "MANOR" },
    { 0x14,  "MDMTST0" },
    { 0x15,  "MDMTST1" },
    { 0x16,  "DACTST" },
    { 0x17,  "AGCTST0" },
    { 0x18,  "AGCTST1" },
    { 0x19,  "AGCTST2" },
    { 0x1A,  "FSTST0" },
    { 0x1B,  "FSTST1" },
    { 0x1C,  "FSTST2" },
    { 0x1D,  "FSTST3" },
    { 0x1E,  "MANFIDL" },
    { 0x1F,  "MANFIDH" },
    { 0x20,  "GRMDM" },
    { 0x21,  "GRDEC" },
    { 0x22,  "PKTSTATUS" },
    { 0x23,  "INT" },
    { 0x2C,  "SYNCL" },
    { 0x2D,  "SYNCH" },
    { 0x60,  "SXOSCON" },
    { 0x61,  "SFSON" },
    { 0x62,  "SRX" },
    { 0x63,  "STX" },
    { 0x64,  "SRFOFF" },
    { 0x65,  "SXOSCOFF" },
    { 0x70,  "FIFOREG" },
    { 0x00, NULL }
};
static value_string_ext(register_vals_ext) = VALUE_STRING_EXT_INIT(register_vals);


void proto_register_ubertooth(void);
void proto_reg_handoff_ubertooth(void);


static gint
dissect_usb_rx_packet(proto_tree *main_tree, proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, gint offset, gint16 command)
{
    proto_item  *sub_item;
    proto_item  *sub_tree;
    proto_item  *data_item;
    proto_item  *data_tree;
    proto_item  *entry_item;
    proto_item  *entry_tree;
    gint         i_spec;
    gint         length;
    tvbuff_t    *next_tvb;

    sub_item = proto_tree_add_item(tree, hf_usb_rx_packet, tvb, offset, 64, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_usb_rx_packet);

    proto_tree_add_item(sub_tree, hf_packet_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(sub_tree, hf_chip_status_reserved, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_chip_status_rssi_trigger, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_chip_status_cs_trigger, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_chip_status_fifo_overflow, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_chip_status_dma_error, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_chip_status_dma_overflow, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(sub_tree, hf_usb_rx_packet_channel, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(sub_tree, hf_clock_ns, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(sub_tree, hf_clock_100ns, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(sub_tree, hf_rssi_max, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(sub_tree, hf_rssi_min, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(sub_tree, hf_rssi_avg, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(sub_tree, hf_rssi_count, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(sub_tree, hf_reserved, tvb, offset, 2, ENC_NA);
    offset += 2;

    data_item = proto_tree_add_item(sub_tree, hf_data, tvb, offset, 50, ENC_NA);
    data_tree = proto_item_add_subtree(data_item, ett_usb_rx_packet_data);

    switch (command) {
    case 27: /* Spectrum Analyzer */
        for (i_spec = 0; i_spec < 48; i_spec += 3) {
            entry_item = proto_tree_add_item(data_tree, hf_spectrum_entry, tvb, offset, 3, ENC_NA);
            entry_tree = proto_item_add_subtree(entry_item, ett_entry);

            proto_tree_add_item(entry_tree, hf_frequency, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(entry_tree, hf_rssi, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_item_append_text(entry_item, " Frequency = %u MHz, RSSI = %i", tvb_get_ntohs(tvb, offset - 3), (gint8) tvb_get_guint8(tvb, offset - 1));
        }

        proto_tree_add_item(data_tree, hf_reserved, tvb, offset, 2, ENC_NA);
        offset += 2;
        break;
    case 49: /* Poll */
        length = 9; /* From BTLE: AccessAddress (4) + Header (2) + Length from Header (below) + CRC (3) */

        if (tvb_get_letohl(tvb, offset) == ACCESS_ADDRESS_ADVERTISING)
            length += tvb_get_guint8(tvb, offset + 5) & 0x3f;
        else
            length += tvb_get_guint8(tvb, offset + 5) & 0x1f;

        next_tvb = tvb_new_subset_length(tvb, offset, length);
        call_dissector(btle_handle, next_tvb, pinfo, main_tree);
        offset += length;

        if (tvb_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(data_tree, hf_reserved, tvb, offset, -1, ENC_NA);
            offset += tvb_length_remaining(tvb, offset);
        }

        break;
    default:
        offset += 50;
    }

    return offset;
}

static gint
dissect_ubertooth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item       *main_tree = NULL;
    proto_tree       *main_item = NULL;
    proto_item       *command_item;
    proto_item       *command_tree;
    proto_item       *sub_item;
    gint              offset = 0;
    usb_conv_info_t  *usb_conv_info = (usb_conv_info_t *)data;
    gint              p2p_dir_save;
    guint8            command;
    command_data_t   *command_data = NULL;
    wmem_tree_t      *wmem_tree;
    wmem_tree_key_t   key[5];
    guint32           bus_id;
    guint32           device_address;
    guint32           k_bus_id;
    guint32           k_device_address;
    guint32           k_frame_number;
    guint8            length;
    guint32          *serial;
    guint8            status;
    gint32            register_id = -1;

    main_item = proto_tree_add_item(tree, proto_ubertooth, tvb, offset, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_ubertooth);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBERTOOTH");

    DISSECTOR_ASSERT(usb_conv_info);

    p2p_dir_save = pinfo->p2p_dir;
    pinfo->p2p_dir = (usb_conv_info->is_request) ? P2P_DIR_SENT : P2P_DIR_RECV;

    switch (pinfo->p2p_dir) {

    case P2P_DIR_SENT:
        col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
        break;

    case P2P_DIR_RECV:
        col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
        break;

    default:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction ");
        break;
    }

    bus_id         = usb_conv_info->bus_id;
    device_address = usb_conv_info->device_address;

    k_bus_id          = bus_id;
    k_device_address  = device_address;
    k_frame_number    = pinfo->fd->num;

    key[0].length = 1;
    key[0].key = &k_bus_id;
    key[1].length = 1;
    key[1].key = &k_device_address;


    if (usb_conv_info->is_setup) {
        proto_tree_add_item(main_tree, hf_command, tvb, offset, 1, ENC_NA);
        command = tvb_get_guint8(tvb, offset);
        offset += 1;

        col_append_fstr(pinfo->cinfo, COL_INFO, "Command: %s",
                val_to_str_ext_const(command, &command_vals_ext, "Unknown"));

        switch (command) {
/* Group of commands with parameters by "setup" */
        case 1: /* Rx Symbols */
        case 4: /* Set User LED */
        case 6: /* Set Rx LED */
        case 8: /* Set Tx LED */
        case 10: /* Set 1V8 */
        case 12: /* Set Channel */
        case 17: /* Set PAEN */
        case 19: /* Set HGM */
        case 23: /* Set Modulation */
        case 29: /* Set Power Amplifier Level */
        case 34: /* LED Spectrum Analyzer */
        case 36: /* Set Squelch */
        case 42: /* BTLE Sniffing */
        case 48: /* Set CRC Verify */
        case 53: /* Read Register */

            switch (command) {
            case 1: /* Rx Symbols */
            case 42: /* BTLE Sniffing */
                proto_tree_add_item(main_tree, hf_rx_packets, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - Rx Packets: %u", tvb_get_letohs(tvb, offset));
                offset += 2;

                break;
            case 4: /* Set User LED */
                proto_tree_add_item(main_tree, hf_user_led, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str_ext_const(tvb_get_letohs(tvb, offset), &led_state_vals_ext, "Unknown"));
                offset += 2;

                break;
            case 6: /* Set Rx LED */
                proto_tree_add_item(main_tree, hf_rx_led, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str_ext_const(tvb_get_letohs(tvb, offset), &led_state_vals_ext, "Unknown"));
                offset += 2;

                break;
            case 8: /* Set Tx LED */
                proto_tree_add_item(main_tree, hf_tx_led, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str_ext_const(tvb_get_letohs(tvb, offset), &led_state_vals_ext, "Unknown"));
                offset += 2;

                break;
            case 10: /* Set 1V8 */
                proto_tree_add_item(main_tree, hf_1v8_led, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str_ext_const(tvb_get_letohs(tvb, offset), &led_state_vals_ext, "Unknown"));
                offset += 2;

                break;
            case 12: /* Set Channel */
                proto_tree_add_item(main_tree, hf_channel, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %u MHz", tvb_get_letohs(tvb, offset));
                offset += 2;

                break;
            case 17: /* Set PAEN */
                proto_tree_add_item(main_tree, hf_paen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str_ext_const(tvb_get_letohs(tvb, offset), &state_vals_ext, "Unknown"));
                offset += 2;

                break;
            case 19: /* Set HGM */
                proto_tree_add_item(main_tree, hf_hgm, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str_ext_const(tvb_get_letohs(tvb, offset), &state_vals_ext, "Unknown"));
                offset += 2;

                break;
            case 23: /* Set Modulation */
                proto_tree_add_item(main_tree, hf_modulation, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str_ext_const(tvb_get_letohs(tvb, offset), &modulation_vals_ext, "Unknown"));
                offset += 2;

                break;
            case 29: /* Set Power Amplifier Level */
                proto_tree_add_item(main_tree, hf_power_amplifier_reserved, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(main_tree, hf_power_amplifier_level, tvb, offset, 1, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, " = %u", tvb_get_letohs(tvb, offset) & 0x7);
                offset += 1;

                proto_tree_add_item(main_tree, hf_reserved, tvb, offset, 1, ENC_NA);
                offset += 1;

                break;
            case 34: /* LED Spectrum Analyzer */
                proto_tree_add_int(main_tree, hf_rssi_threshold, tvb, offset, 2, (gint8) tvb_get_letohs(tvb, offset));
                col_append_fstr(pinfo->cinfo, COL_INFO, " = %i", (gint8) tvb_get_letohs(tvb, offset));
                offset += 2;

                break;
            case 36: /* Set Squelch */
                proto_tree_add_item(main_tree, hf_squelch, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " = %i", (gint16) tvb_get_letohs(tvb, offset));
                offset += 2;

                break;
            case 48: /* Set CRC Verify */
                proto_tree_add_item(main_tree, hf_crc_verify, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str_ext_const(tvb_get_letohs(tvb, offset), &state_vals_ext, "Unknown"));
                offset += 2;

                break;
            case 53: /* Read Register */
                proto_tree_add_item(main_tree, hf_register, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                register_id = tvb_get_letohs(tvb, offset);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %s",
                        val_to_str_ext_const(register_id, &register_vals_ext, "Unknown"));
                offset += 2;

                break;
            default:
                proto_tree_add_item(main_tree, hf_argument_0, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
            }

            proto_tree_add_item(main_tree, hf_argument_1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            break;
        case 27: /* Spectrum Analyzer */
            proto_tree_add_item(main_tree, hf_low_frequency, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(main_tree, hf_high_frequency, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            col_append_fstr(pinfo->cinfo, COL_INFO, " - %u-%u MHz", tvb_get_letohs(tvb, offset - 4), tvb_get_letohs(tvb, offset - 2));

            break;
/* Group of commands with parameters by "data" but no "setup"*/
        case 38: /* Set BDADDR */
        case 39: /* Start Hopping */
        case 40: /* Set Clock */
        case 44: /* Set Access Address */
        case 51: /* Set AFH Map */
        case 54: /* BTLE Slave */
/* Group of commands without any parameters */
        case 0: /* Ping */
        case 2: /* Tx Symbols */ /* NOTE: This one seems to be not implemented in firmware at all*/
        case 3: /* Get User LED */
        case 5: /* Get Rx LED */
        case 7: /* Get Tx LED */
        case 9: /* Get 1V8 */
        case 11: /* Get Channel */
        case 13: /* Reset */
        case 14: /* Get Microcontroller Serial Number */
        case 15: /* Get Microcontroller Part Number */
        case 16: /* Get PAEN */
        case 18: /* Get HGM */
        case 20: /* Tx Test */
        case 21: /* Stop */
        case 22: /* Get Modulation */
        case 24: /* Set ISP */
        case 25: /* Flash */
        case 26: /* Bootloader Flash */ /* NOTE: This one seems to be not implemented in firmware at all*/
        case 28: /* Get Power Amplifier Level */
        case 30: /* Repeater */
        case 31: /* Range Test */
        case 32: /* Range Check */
        case 33: /* Get Firmware Revision Number */
        case 35: /* Get Hardware Board ID */
        case 37: /* Get Squelch */
        case 41: /* Get Clock */
        case 43: /* Get Access Address */
        case 45: /* Do Something */
        case 46: /* Do Something Reply */
        case 47: /* Get CRC Verify */
        case 49: /* Poll */
        case 50: /* BTLE Promiscuous Mode */
        case 52: /* Clear AFH Map */
        case 55: /* Get Compile Info */
        default:
            proto_tree_add_item(main_tree, hf_argument_0, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(main_tree, hf_argument_1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        proto_tree_add_item(main_tree, hf_estimated_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;


        switch (command) {
            case 38: /* Set BDADDR */
            case 54: /* BTLE Slave */
                proto_tree_add_item(main_tree, hf_bdaddr, tvb, offset, 6, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %s",
                        get_ether_name((char *) tvb_memdup(wmem_packet_scope(), tvb, offset, 6)));

                offset += 6;
                break;
            case 39: /* Start Hopping */
                proto_tree_add_item(main_tree, hf_clock_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %u", tvb_get_letohl(tvb, offset));

                offset += 4;
                break;
            case 40: /* Set Clock */
                proto_tree_add_item(main_tree, hf_clock_100ns, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %u", tvb_get_letohl(tvb, offset));

                offset += 4;
                break;
            case 44: /* Set Access Address */
                proto_tree_add_item(main_tree, hf_access_address, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %08x", tvb_get_letohl(tvb, offset));

                offset += 4;
                break;
            case 51: /* Set AFH Map */
                proto_tree_add_item(main_tree, hf_afh_map, tvb, offset, 10, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", tvb_bytes_to_ep_str(tvb, offset, 10));

                offset += 10;
                break;
        }

        if (tvb_length_remaining(tvb, offset) > 0) {
            proto_tree_add_expert(main_tree, pinfo, &ei_unexpected_data, tvb, offset, tvb_length_remaining(tvb, offset));
            offset = tvb_length(tvb);
        }

        /* Save request info (command_data) */
        if (!pinfo->fd->flags.visited && command != 21) {
            key[2].length = 1;
            key[2].key = &k_frame_number;
            key[3].length = 0;
            key[3].key = NULL;

            command_data = wmem_new(wmem_file_scope(), command_data_t);
            command_data->bus_id = bus_id;
            command_data->device_address = device_address;

            command_data->command = command;
            command_data->command_frame_number = pinfo->fd->num;
            command_data->register_id = register_id;

            wmem_tree_insert32_array(command_info, key, command_data);
        }

        pinfo->p2p_dir = p2p_dir_save;

        return offset;
    }

    /* Get request info (command_data) */
    key[2].length = 0;
    key[2].key = NULL;

    wmem_tree = (wmem_tree_t *) wmem_tree_lookup32_array(command_info, key);
   if (wmem_tree) {
        command_data = (command_data_t *) wmem_tree_lookup32_le(wmem_tree, pinfo->fd->num);
        command = command_data->command;
        register_id = command_data->register_id;
   }

    if (!command_data) {
        col_append_str(pinfo->cinfo, COL_INFO, "Response: Unknown");

        proto_tree_add_expert(main_tree, pinfo, &ei_unknown_data, tvb, offset, tvb_length_remaining(tvb, offset));

        pinfo->p2p_dir = p2p_dir_save;

        return tvb_length(tvb);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, "Response: %s",
            val_to_str_ext_const(command, &command_vals_ext, "Unknown"));

    command_item = proto_tree_add_uint(main_tree, hf_response, tvb, offset, 0, command);
    command_tree = proto_item_add_subtree(command_item, ett_command);
    PROTO_ITEM_SET_GENERATED(command_item);
    switch (command) {

    case 1: /* Rx Symbols */
    case 27: /* Spectrum Analyzer */
        if (usb_conv_info->transfer_type == URB_BULK) {

            while (tvb_length_remaining(tvb, offset) > 0) {
                offset = dissect_usb_rx_packet(tree, main_tree, pinfo, tvb, offset, command);
            }
            break;
        }
    case 0: /* Ping */
    case 2: /* Tx Symbols */        /* NOTE: This one seems to be not implemented in firmware at all*/
    case 26: /* Bootloader Flash */ /* NOTE: This one seems to be not implemented in firmware at all*/
    case 4: /* Set User LED */
    case 6: /* Set Rx LED */
    case 8: /* Set Tx LED */
    case 10: /* Set 1V8 */
    case 12: /* Set Channel */
    case 13: /* Reset */
    case 17: /* Set PAEN */
    case 19: /* Set HGM */
    case 20: /* Tx Test */
    case 21: /* Stop */
    case 29: /* Set Power Amplifier Level */
    case 30: /* Repeater */
    case 31: /* Range Test */
    case 23: /* Set Modulation */
    case 24: /* Set ISP */
    case 25: /* Flash */
    case 34: /* LED Spectrum Analyzer */
    case 36: /* Set Squelch */
    case 38: /* Set BDADDR */
    case 39: /* Start Hopping */
    case 40: /* Set Clock */
    case 42: /* BTLE Sniffing */
    case 44: /* Set Access Address */
    case 45: /* Do Something */
    case 48: /* Set CRC Verify */
    case 50: /* BTLE Promiscuous Mode */
    case 51: /* Set AFH Map */
    case 52: /* Clear AFH Map */
    case 54: /* BTLE Slave */
        proto_tree_add_expert(command_tree, pinfo, &ei_unexpected_response, tvb, offset, 0);
        if (tvb_length_remaining(tvb, offset) > 0) {
            proto_tree_add_expert(main_tree, pinfo, &ei_unknown_data, tvb, offset, -1);
            offset = tvb_length(tvb);
        }
        break;
    case 3: /* Get User LED */
        proto_tree_add_item(main_tree, hf_user_led, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %s", val_to_str_ext_const(tvb_get_guint8(tvb, offset), &led_state_vals_ext, "Unknown"));
        offset += 1;

        break;
    case 5: /* Get Rx LED */
        proto_tree_add_item(main_tree, hf_rx_led, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %s", val_to_str_ext_const(tvb_get_guint8(tvb, offset), &led_state_vals_ext, "Unknown"));
        offset += 1;

        break;
    case 7: /* Get Tx LED */
        proto_tree_add_item(main_tree, hf_tx_led, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %s", val_to_str_ext_const(tvb_get_guint8(tvb, offset), &led_state_vals_ext, "Unknown"));
        offset += 1;

        break;
    case 9: /* Get 1V8 */
        proto_tree_add_item(main_tree, hf_1v8_led, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %s", val_to_str_ext_const(tvb_get_guint8(tvb, offset), &led_state_vals_ext, "Unknown"));
        offset += 1;

        break;
    case 11: /* Get Channel */
        proto_tree_add_item(main_tree, hf_channel, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %u MHz", tvb_get_letohs(tvb, offset));
        offset += 2;

        break;
    case 14: /* Get Microcontroller Serial Number */
        proto_tree_add_item(main_tree, hf_status, tvb, offset, 1, ENC_NA);
        status = tvb_get_guint8(tvb, offset);
        offset += 1;

        if (status) break;

        serial = (guint32 *) wmem_alloc(wmem_packet_scope(), 16);
        serial[0] = tvb_get_ntohl(tvb, offset);
        serial[1] = tvb_get_ntohl(tvb, offset + 4);
        serial[2] = tvb_get_ntohl(tvb, offset + 8);
        serial[3] = tvb_get_ntohl(tvb, offset + 12);

        proto_tree_add_bytes(main_tree, hf_serial_number, tvb,
                offset, 16, (guint8 *) serial);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %s",
                bytes_to_ep_str((guint8 *) serial, 16));
        offset += 16;

        break;
    case 15: /* Get Microcontroller Part Number */
        proto_tree_add_item(main_tree, hf_status, tvb, offset, 1, ENC_NA);
        status = tvb_get_guint8(tvb, offset);
        offset += 1;

        if (status) break;

        proto_tree_add_item(main_tree, hf_part_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %08X", tvb_get_letohl(tvb, offset));
        offset += 4;

        break;
    case 16: /* Get PAEN */
        proto_tree_add_item(main_tree, hf_paen, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %s", val_to_str_ext_const(tvb_get_guint8(tvb, offset), &state_vals_ext, "Unknown"));
        offset += 1;

        break;
    case 18: /* Get HGM */
        proto_tree_add_item(main_tree, hf_hgm, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %s", val_to_str_ext_const(tvb_get_guint8(tvb, offset), &state_vals_ext, "Unknown"));
        offset += 1;

        break;
    case 22: /* Get Modulation */
        proto_tree_add_item(main_tree, hf_modulation, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %s", val_to_str_ext_const(tvb_get_guint8(tvb, offset), &modulation_vals_ext, "Unknown"));
        offset += 1;

        break;
    case 28: /* Get Power Amplifier Level */
        proto_tree_add_item(main_tree, hf_power_amplifier_reserved, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(main_tree, hf_power_amplifier_level, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %u", tvb_get_guint8(tvb, offset) & 0x7);
        offset += 1;

        break;
    case 32: /* Range Check */
        proto_tree_add_item(main_tree, hf_range_test_valid, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(main_tree, hf_range_test_request_power_amplifier, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(main_tree, hf_range_test_request_number, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(main_tree, hf_range_test_reply_power_amplifier, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(main_tree, hf_range_test_reply_number, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 33: /* Get Firmware Revision Number */
        proto_tree_add_item(main_tree, hf_reserved, tvb, offset, 2, ENC_NA);
        offset += 2;

        proto_tree_add_item(main_tree, hf_length, tvb, offset, 1, ENC_NA);
        length = tvb_get_guint8(tvb, offset);
        offset += 1;

        proto_tree_add_item(main_tree, hf_firmware_revision, tvb, offset, length, ENC_NA | ENC_ASCII);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %s", tvb_get_string(wmem_packet_scope(), tvb, offset, length));
        offset += length;

        break;
    case 35: /* Get Hardware Board ID */
        proto_tree_add_item(main_tree, hf_board_id, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %s", val_to_str_ext_const(tvb_get_guint8(tvb, offset), &board_id_vals_ext, "Unknown"));
        offset += 1;

        break;
    case 37: /* Get Squelch */
        proto_tree_add_item(main_tree, hf_squelch, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %i", (gint8) tvb_get_guint8(tvb, offset));
        offset += 1;

        break;
    case 41: /* Get Clock */
        proto_tree_add_item(main_tree, hf_clock_ns, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %u", tvb_get_guint8(tvb, offset));
        offset += 1;

        break;
    case 43: /* Get Access Address */
        proto_tree_add_item(main_tree, hf_access_address, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %08x", tvb_get_letohl(tvb, offset));
        offset += 4;

        break;
    case 46: /* Do Something Reply */
            proto_tree_add_item(main_tree, hf_reserved, tvb, offset, 2, ENC_NA);
            offset += 2;

        break;
    case 47: /* Get CRC Verify */
        proto_tree_add_item(main_tree, hf_crc_verify, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %s", val_to_str_ext_const(tvb_get_guint8(tvb, offset), &state_vals_ext, "Unknown"));
        offset += 1;

        break;
    case 49: /* Poll */
        if (tvb_length_remaining(tvb, offset) == 1) {
            proto_tree_add_item(main_tree, hf_reserved, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;
        }

        offset = dissect_usb_rx_packet(tree, main_tree, pinfo, tvb, offset, command);

        break;
    case 53: /* Read Register */
        sub_item = proto_tree_add_uint(main_tree, hf_register, tvb, offset, 0, register_id);
        PROTO_ITEM_SET_GENERATED(sub_item);

        proto_tree_add_item(main_tree, hf_register_value, tvb, offset, 2, ENC_BIG_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %s:  0x%04x",
                val_to_str_ext_const(register_id, &register_vals_ext, "Unknown"),
                tvb_get_letohs(tvb, offset));
        offset += 2;

        break;
    case 55: /* Get Compile Info */
        proto_tree_add_item(main_tree, hf_length, tvb, offset, 1, ENC_NA);
        length = tvb_get_guint8(tvb, offset);
        offset += 1;

        proto_tree_add_item(main_tree, hf_firmware_compile_info, tvb, offset, length, ENC_NA | ENC_ASCII);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %s", tvb_get_string(wmem_packet_scope(), tvb, offset, length));
        offset += length;

        break;
    }

    if (tvb_length_remaining(tvb, offset) > 0) {
        proto_tree_add_expert(main_tree, pinfo, &ei_unknown_data, tvb, offset, -1);
        offset = tvb_length(tvb);
    }

    pinfo->p2p_dir = p2p_dir_save;

    return offset;
}

void
proto_register_ubertooth(void)
{
    module_t         *module;
    expert_module_t  *expert_module;

    static hf_register_info hf[] = {
        { &hf_command,
            { "Command",                         "ubertooth.command",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &command_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_response,
            { "Response",                        "ubertooth.response",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &command_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_argument_0,
            { "Unused Argument 0",               "ubertooth.argument.0",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_argument_1,
            { "Unused Argument 1",               "ubertooth.argument.1",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_estimated_length,
            { "Estimated Length",                "ubertooth.estimated_length",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_board_id,
            { "Board ID",                        "ubertooth.board_id",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &board_id_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_reserved,
            { "Reserved",                        "ubertooth.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_length,
            { "Length",                          "ubertooth.length",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_firmware_revision,
            { "Firmware Revision",               "ubertooth.firmware.reversion",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_firmware_compile_info,
            { "Firmware Compile Info",           "ubertooth.firmware.compile_info",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_user_led,
            { "User LED State",                  "ubertooth.user_led",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &led_state_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_rx_led,
            { "Rx LED State",                    "ubertooth.rx_led",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &led_state_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_tx_led,
            { "Tx LED State",                    "ubertooth.tx_led",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &led_state_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_1v8_led,
            { "1V8 LED State",                   "ubertooth.1v8_led",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &led_state_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_channel,
            { "Channel",                         "ubertooth.channel",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_usb_rx_packet_channel,
            { "Channel",                         "ubertooth.usb_rx_packet.channel",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_serial_number,
            { "Serial Number",                   "ubertooth.serial_number",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_status,
            { "Status",                          "ubertooth.status",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_part_number,
            { "Part Number",                     "ubertooth.part_number",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_packet_type,
            { "Packet Type",                     "ubertooth.packet_type",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &packet_type_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_chip_status_reserved,
            { "Reserved",                        "ubertooth.status.resered",
            FT_BOOLEAN, 8, NULL, 0xE0,
            NULL, HFILL }
        },
        { &hf_chip_status_rssi_trigger,
            { "RSSI Trigger",                    "ubertooth.status.rssi_trigger",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_chip_status_cs_trigger,
            { "CS Trigger",                      "ubertooth.status.cs_trigger",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_chip_status_fifo_overflow,
            { "FIFO Overflow",                   "ubertooth.status.fifo_overflow",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_chip_status_dma_error,
            { "DMA Error",                       "ubertooth.status.dma_error",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_chip_status_dma_overflow,
            { "DMA Overflow",                    "ubertooth.status.dma_overflow",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_clock_ns,
            { "Clock 1ns",                      "ubertooth.clock_ns",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_clock_100ns,
            { "Clock 100ns",                    "ubertooth.clock_100ns",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_rssi_min,
            { "RSSI Min",                        "ubertooth.rssi_min",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_rssi_max,
            { "RSSI Max",                        "ubertooth.rssi_max",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_rssi_avg,
            { "RSSI Avg",                        "ubertooth.rssi_avg",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_rssi_count,
            { "RSSI Count",                      "ubertooth.rssi_count",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_paen,
            { "PAEN",                            "ubertooth.paen",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &state_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_hgm,
            { "HGM",                             "ubertooth.hgm",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &state_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_crc_verify,
            { "CRC Verify",                      "ubertooth.crc_verify",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &state_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_modulation,
            { "Modulation",                      "ubertooth.modulation",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &modulation_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_power_amplifier_reserved,
            { "Reserved",                        "ubertooth.power_amplifier.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xF8,
            NULL, HFILL }
        },
        { &hf_power_amplifier_level,
            { "Level",                           "ubertooth.power_amplifier.level",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_range_test_valid,
            { "Valid",                           "ubertooth.range_test.valid",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_range_test_request_power_amplifier,
            { "Request Power Amplifier",         "ubertooth.range_test.request_power_amplifier",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_range_test_request_number,
            { "Request Power Amplifier",         "ubertooth.range_test.request_number",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_range_test_reply_power_amplifier,
            { "Request Power Amplifier",         "ubertooth.range_test.reply_power_amplifier",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_range_test_reply_number,
            { "Reply Power Amplifier",           "ubertooth.range_test.reply_number",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_squelch,
            { "Squelch",                         "ubertooth.squelch",
            FT_INT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_access_address,
            { "Access Address",                  "ubertooth.access_address",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_register,
            { "Register",                        "ubertooth.register",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &register_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_register_value,
            { "Register Value",                  "ubertooth.register.value",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_low_frequency,
            { "Low Frequency",                   "ubertooth.low_frequency",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_high_frequency,
            { "High Frequency",                  "ubertooth.high_frequency",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_rx_packets,
            { "Rx Packets",                      "ubertooth.rx_packets",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_rssi_threshold,
            { "RSSI Threshold",                  "ubertooth.rssi_threshold",
            FT_INT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_clock_offset,
            { "Clock Offset",                    "ubertooth.clock_offset",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_afh_map,
            { "AFH Map",                         "ubertooth.afh_map",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bdaddr,
          { "BD_ADDR",                           "ubertooth.bd_addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            "Bluetooth Device Address", HFILL}
        },
        { &hf_usb_rx_packet,
            { "USB Rx Packet",                   "ubertooth.usb_rx_packet",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_spectrum_entry,
            { "Spectrum Entry",                  "ubertooth.spectrum_entry",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_frequency,
            { "Frequency",                       "ubertooth.spectrum_entry.frequency",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_rssi,
            { "RSSI",                            "ubertooth.spectrum_entry.rssi",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_data,
            { "Data",                            "ubertooth.data",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        }
    };

    static ei_register_info ei[] = {
        { &ei_unexpected_response, { "ubertooth.unexpected_response", PI_PROTOCOL, PI_ERROR, "Unexpected response for this command", EXPFILL }},
        { &ei_unknown_data, { "ubertooth.unknown_data", PI_PROTOCOL, PI_NOTE, "Unknown data", EXPFILL }},
        { &ei_unexpected_data, { "ubertooth.unexpected_data", PI_PROTOCOL, PI_WARN, "Unexpected data", EXPFILL }},
    };

    static gint *ett[] = {
        &ett_ubertooth,
        &ett_command,
        &ett_usb_rx_packet,
        &ett_usb_rx_packet_data,
        &ett_entry
    };

    command_info = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    proto_ubertooth = proto_register_protocol("Ubertooth", "UBERTOOTH", "ubertooth");
    proto_register_field_array(proto_ubertooth, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    ubertooth_handle = new_register_dissector("ubertooth", dissect_ubertooth, proto_ubertooth);

    expert_module = expert_register_protocol(proto_ubertooth);
    expert_register_field_array(expert_module, ei, array_length(ei));

    module = prefs_register_protocol(proto_ubertooth, NULL);
    prefs_register_static_text_preference(module, "version",
            "Ubertooth Firmware: 2012-10-R1 (also latest git version pior to: d09308f48d9f94d1c55be5f72d9a2a271bb8a54b)",
            "Version of protocol supported by this dissector.");
}

void
proto_reg_handoff_ubertooth(void)
{
    btle_handle = find_dissector("btle");

    dissector_add_handle("usb.device",   ubertooth_handle);
    dissector_add_handle("usb.product",  ubertooth_handle);
    dissector_add_handle("usb.protocol", ubertooth_handle);
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

/* packet-usb-com.c
 * Routines for USB Communications and CDC Control dissection
 * Copyright 2013, Pascal Quantin <pascal.quantin@gmail.com>
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
#include "packet-usb.h"

/* protocols and header fields */
static int proto_usb_com = -1;
static int hf_usb_com_descriptor_subtype = -1;
static int hf_usb_com_descriptor_cdc = -1;
static int hf_usb_com_descriptor_payload = -1;
static int hf_usb_com_control_subclass = -1;
static int hf_usb_com_control_request_code = -1;
static int hf_usb_com_control_value = -1;
static int hf_usb_com_control_index = -1;
static int hf_usb_com_control_length = -1;
static int hf_usb_com_control_response_code = -1;
static int hf_usb_com_control_payload = -1;
static int hf_usb_com_get_ntb_params_length = -1;
static int hf_usb_com_get_ntb_params_ntb_formats_supported = -1;
static int hf_usb_com_get_ntb_params_ntb_formats_supported_16bit = -1;
static int hf_usb_com_get_ntb_params_ntb_formats_supported_32bit = -1;
static int hf_usb_com_get_ntb_params_ntb_in_max_size = -1;
static int hf_usb_com_get_ntb_params_ndp_in_divisor = -1;
static int hf_usb_com_get_ntb_params_ndp_in_payload_remainder = -1;
static int hf_usb_com_get_ntb_params_ndp_in_alignment = -1;
static int hf_usb_com_get_ntb_params_reserved = -1;
static int hf_usb_com_get_ntb_params_ntb_out_max_size = -1;
static int hf_usb_com_get_ntb_params_ndp_out_divisor = -1;
static int hf_usb_com_get_ntb_params_ndp_out_payload_remainder = -1;
static int hf_usb_com_get_ntb_params_ndp_out_alignment = -1;
static int hf_usb_com_get_ntb_params_ntb_out_max_datagrams = -1;
static int hf_usb_com_get_net_address_eui48 = -1;
static int hf_usb_com_set_net_address_eui48 = -1;
static int hf_usb_com_get_ntb_format_ntb_format = -1;
static int hf_usb_com_set_ntb_format_ntb_format = -1;
static int hf_usb_com_get_ntb_input_size_ntb_in_max_size = -1;
static int hf_usb_com_get_ntb_input_size_ntb_in_max_datagrams = -1;
static int hf_usb_com_get_ntb_input_size_reserved = -1;
static int hf_usb_com_set_ntb_input_size_ntb_in_max_size = -1;
static int hf_usb_com_set_ntb_input_size_ntb_in_max_datagrams = -1;
static int hf_usb_com_set_ntb_input_size_reserved = -1;
static int hf_usb_com_get_max_datagram_size_size = -1;
static int hf_usb_com_set_max_datagram_size_size = -1;
static int hf_usb_com_get_crc_mode_crc_mode = -1;
static int hf_usb_com_set_crc_mode_crc_mode = -1;
static int hf_usb_com_capabilities = -1;
static int hf_usb_com_descriptor_acm_capabilities_reserved = -1;
static int hf_usb_com_descriptor_acm_capabilities_network_connection = -1;
static int hf_usb_com_descriptor_acm_capabilities_send_break = -1;
static int hf_usb_com_descriptor_acm_capabilities_line_and_state = -1;
static int hf_usb_com_descriptor_acm_capabilities_comm_features = -1;
static int hf_usb_com_descriptor_control_interface = -1;
static int hf_usb_com_descriptor_subordinate_interface = -1;
static int hf_usb_com_descriptor_cm_capabilities_reserved = -1;
static int hf_usb_com_descriptor_cm_capabilities_call_management_over_data_class_interface = -1;
static int hf_usb_com_descriptor_cm_capabilities_call_management = -1;
static int hf_usb_com_descriptor_cm_data_interface = -1;
static int hf_usb_com_descriptor_ecm_mac_address = -1;
static int hf_usb_com_descriptor_ecm_eth_stats = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_reserved = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_xmit_late_collisions = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_xmit_times_crs_lost = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_xmit_heartbeat_failure = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_xmit_underrun = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_rcv_overrun = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_xmit_max_collisions = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_xmit_deferred = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_xmit_more_collisions = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_xmit_one_collision = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_rcv_error_alignment = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_transmit_queue_length = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_rcv_crc_error = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_broadcast_frames_rcv = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_broadcast_bytes_rcv = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_multicast_frames_rcv = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_multicast_bytes_rcv = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_directed_frames_rcv = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_directed_bytes_rcv = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_broadcast_frames_xmit = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_broadcast_bytes_xmit = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_multicast_frames_xmit = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_multicast_bytes_xmit = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_directed_frames_xmit = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_directed_bytes_xmit = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_rcv_no_buffer = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_rcv_error = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_xmit_error = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_rvc_ok = -1;
static int hf_usb_com_descriptor_ecm_eth_stats_xmit_ok = -1;
static int hf_usb_com_descriptor_ecm_max_segment_size = -1;
static int hf_usb_com_descriptor_ecm_nb_mc_filters = -1;
static int hf_usb_com_descriptor_ecm_nb_mc_filters_mc_address_filtering = -1;
static int hf_usb_com_descriptor_ecm_nb_mc_filters_nb_filters_supported = -1;
static int hf_usb_com_descriptor_ecm_nb_power_filters = -1;
static int hf_usb_com_interrupt_request_type = -1;
static int hf_usb_com_interrupt_notif_code = -1;
static int hf_usb_com_interrupt_value = -1;
static int hf_usb_com_interrupt_value_nw_conn = -1;
static int hf_usb_com_interrupt_index = -1;
static int hf_usb_com_interrupt_length = -1;
static int hf_usb_com_interrupt_dl_bitrate = -1;
static int hf_usb_com_interrupt_ul_bitrate = -1;
static int hf_usb_com_interrupt_payload = -1;

static gint ett_usb_com = -1;
static gint ett_usb_com_capabilities = -1;
static gint ett_usb_com_bitmap = -1;
static gint ett_usb_com_descriptor_ecm_eth_stats = -1;
static gint ett_usb_com_descriptor_ecm_nb_mc_filters = -1;

static dissector_handle_t mbim_control_handle;
static dissector_handle_t mbim_descriptor_handle;
static dissector_handle_t mbim_bulk_handle;
static dissector_handle_t eth_withoutfcs_handle;

#define CS_INTERFACE 0x24
#define CS_ENDPOINT  0x25

static const value_string usb_com_descriptor_type_vals[] = {
    { CS_INTERFACE, "CS_INTERFACE"},
    { CS_ENDPOINT, "CS_ENDPOINT"},
    { 0, NULL}
};
static value_string_ext usb_com_descriptor_type_vals_ext = VALUE_STRING_EXT_INIT(usb_com_descriptor_type_vals);

static const value_string usb_com_descriptor_subtype_vals[] = {
    { 0x00, "Header Functional Descriptor"},
    { 0x01, "Call Management Functional Descriptor"},
    { 0x02, "Abstract Control Management Functional Descriptor"},
    { 0x03, "Direct Line Management Functional Descriptor"},
    { 0x04, "Telephone Ringer Functional Descriptor"},
    { 0x05, "Telephone Call and Line State Reporting Capabilities Functional Descriptor"},
    { 0x06, "Union Functional Descriptor"},
    { 0x07, "Country Selection Functional Descriptor"},
    { 0x08, "Telephone Operational Modes Functional Descriptor"},
    { 0x09, "USB Terminal Functional Descriptor"},
    { 0x0A, "Network Channel Terminal Descriptor"},
    { 0x0B, "Protocol Unit Functional Descriptor"},
    { 0x0C, "Extension Unit Functional Descriptor"},
    { 0x0D, "Multi-Channel Management Functional Descriptor"},
    { 0x0E, "CAPI Control Management Functional Descriptor"},
    { 0x0F, "Ethernet Networking Functional Descriptor"},
    { 0x10, "ATM Networking Functional Descriptor"},
    { 0x11, "Wireless Handset Control Model Functional Descriptor"},
    { 0x12, "Mobile Direct Line Model Functional Descriptor"},
    { 0x13, "MDLM Detail Functional Descriptor"},
    { 0x14, "Device Management Model Functional Descriptor"},
    { 0x15, "OBEX Functional Descriptor"},
    { 0x16, "Command Set Functional Descriptor"},
    { 0x17, "Command Set Detail Functional Descriptor"},
    { 0x18, "Telephone Control Model Functional Descriptor"},
    { 0x19, "OBEX Service Identifier Functional Descriptor"},
    { 0x1A, "NCM Functional Descriptor"},
    { 0x1B, "MBIM Functional Descriptor"},
    { 0x1C, "MBIM Extended Functional Descriptor"},
    { 0, NULL}
};
static value_string_ext usb_com_descriptor_subtype_vals_ext = VALUE_STRING_EXT_INIT(usb_com_descriptor_subtype_vals);

#define COM_SUBCLASS_RESERVED 0x00
#define COM_SUBCLASS_DLCM     0x01
#define COM_SUBCLASS_ACM      0x02
#define COM_SUBCLASS_TCM      0x03
#define COM_SUBCLASS_MCCM     0x04
#define COM_SUBCLASS_CCM      0x05
#define COM_SUBCLASS_ENCM     0x06
#define COM_SUBCLASS_ANCM     0x07
#define COM_SUBCLASS_WHCM     0x08
#define COM_SUBCLASS_DM       0x09
#define COM_SUBCLASS_MDLM     0x0a
#define COM_SUBCLASS_OBEX     0x0b
#define COM_SUBCLASS_EEM      0x0c
#define COM_SUBCLASS_NCM      0x0d
#define COM_SUBCLASS_MBIM     0x0e

static const value_string usb_com_subclass_vals[] = {
    {COM_SUBCLASS_RESERVED, "RESERVED"},
    {COM_SUBCLASS_DLCM, "Direct Line Control Model"},
    {COM_SUBCLASS_ACM, "Abstract Control Model"},
    {COM_SUBCLASS_TCM, "Telephone Control Model"},
    {COM_SUBCLASS_MCCM, "Multi-Channel Control Model"},
    {COM_SUBCLASS_CCM, "CAPI Control Model"},
    {COM_SUBCLASS_ENCM, "Ethernet Networking Control Model"},
    {COM_SUBCLASS_ANCM, "ATM Networking Control Model"},
    {COM_SUBCLASS_WHCM, "Wireless Handset Control Model"},
    {COM_SUBCLASS_DM, "Device Management"},
    {COM_SUBCLASS_MDLM, "Mobile Direct Line Model"},
    {COM_SUBCLASS_OBEX, "OBEX"},
    {COM_SUBCLASS_EEM, "Ethernet Emulation Model"},
    {COM_SUBCLASS_NCM, "Network Control Model"},
    {COM_SUBCLASS_MBIM, "Mobile Broadband Interface Model"},
    {0, NULL}
};
value_string_ext ext_usb_com_subclass_vals = VALUE_STRING_EXT_INIT(usb_com_subclass_vals);

#define SEND_ENCAPSULATED_COMMAND                    0x00
#define GET_ENCAPSULATED_RESPONSE                    0x01
#define SET_COMM_FEATURE                             0x02
#define GET_COMM_FEATURE                             0x03
#define CLEAR_COMM_FEATURE                           0x04
#define RESET_FUNCTION                               0x05
#define SET_AUX_LINE_STATE                           0x10
#define SET_HOOK_STATE                               0x11
#define PULSE_SETUP                                  0x12
#define SEND_PULSE                                   0x13
#define SET_PULSE_TIME                               0x14
#define RING_AUX_JACK                                0x15
#define SET_LINE_CODING                              0x20
#define GET_LINE_CODING                              0x21
#define SET_CONTROL_LINE_STATE                       0x22
#define SEND_BREAK                                   0x23
#define SET_RINGER_PARMS                             0x30
#define GET_RINGER_PARMS                             0x31
#define SET_OPERATION_PARMS                          0x32
#define GET_OPERATION_PARMS                          0x33
#define SET_LINE_PARMS                               0x34
#define GET_LINE_PARMS                               0x35
#define DIAL_DIGITS                                  0x36
#define SET_UNIT_PARAMETER                           0x37
#define GET_UNIT_PARAMETER                           0x38
#define CLEAR_UNIT_PARAMETER                         0x39
#define GET_PROFILE                                  0x3a
#define SET_ETHERNET_MULTICAST_FILTERS               0x40
#define SET_ETHERNET_POWER_MANAGEMENT_PATTERN_FILTER 0x41
#define GET_ETHERNET_POWER_MANAGEMENT_PATTERN_FILTER 0x42
#define SET_ETHERNET_PACKET_FILTER                   0x43
#define GET_ETHERNET_STATISTIC                       0x44
#define SET_ATM_DATA_FORMAT                          0x50
#define GET_ATM_DEVICE_STATISTICS                    0x51
#define SET_ATM_DEFAULT_VC                           0x52
#define GET_ATM_VC_STATISTICS                        0x53
#define GET_NTB_PARAMETERS                           0x80
#define GET_NET_ADDRESS                              0x81
#define SET_NET_ADDRESS                              0x82
#define GET_NTB_FORMAT                               0x83
#define SET_NTB_FORMAT                               0x84
#define GET_NTB_INPUT_SIZE                           0x85
#define SET_NTB_INPUT_SIZE                           0x86
#define GET_MAX_DATAGRAM_SIZE                        0x87
#define SET_MAX_DATAGRAM_SIZE                        0x88
#define GET_CRC_MODE                                 0x89
#define SET_CRC_MODE                                 0x8a

static const value_string usb_com_setup_request_vals[] = {
    {SEND_ENCAPSULATED_COMMAND, "SEND ENCAPSULATED COMMAND"},
    {GET_ENCAPSULATED_RESPONSE, "GET ENCAPSULATED RESPONSE"},
    {SET_COMM_FEATURE, "SET COMM FEATURE"},
    {GET_COMM_FEATURE, "GET COMM FEATURE"},
    {CLEAR_COMM_FEATURE, "CLEAR COMM FEATURE"},
    {RESET_FUNCTION, "RESET FUNCTION"},
    {SET_AUX_LINE_STATE, "SET AUX LINE STATE"},
    {SET_HOOK_STATE, "SET HOOK STATE"},
    {PULSE_SETUP, "PULSE SETUP"},
    {SEND_PULSE, "SEND PULSE"},
    {SET_PULSE_TIME, "SET PULSE TIME"},
    {RING_AUX_JACK, "RING AUX JACK"},
    {SET_LINE_CODING, "SET LINE CODING"},
    {GET_LINE_CODING, "GET LINE CODING"},
    {SET_CONTROL_LINE_STATE, "SET CONTROL LINE STATE"},
    {SEND_BREAK, "SEND BREAK"},
    {SET_RINGER_PARMS, "SET RINGER PARMS"},
    {GET_RINGER_PARMS, "GET RINGER PARMS"},
    {SET_OPERATION_PARMS, "SET OPERATION PARMS"},
    {GET_OPERATION_PARMS, "GET OPERATION PARMS"},
    {SET_LINE_PARMS, "SET LINE PARMS"},
    {GET_LINE_PARMS, "GET LINE PARMS"},
    {DIAL_DIGITS, "DIAL DIGITS"},
    {SET_UNIT_PARAMETER, "SET UNIT PARAMETER"},
    {GET_UNIT_PARAMETER, "GET UNIT PARAMETER"},
    {CLEAR_UNIT_PARAMETER, "CLEAR UNIT PARAMETER"},
    {GET_PROFILE, "GET PROFILE"},
    {SET_ETHERNET_MULTICAST_FILTERS, "SET ETHERNET MULTICAST FILTERS"},
    {SET_ETHERNET_POWER_MANAGEMENT_PATTERN_FILTER, "SET ETHERNET POWER MANAGEMENT PATTERN FILTER"},
    {GET_ETHERNET_POWER_MANAGEMENT_PATTERN_FILTER, "GET ETHERNET POWER MANAGEMENT PATTERN FILTER"},
    {SET_ETHERNET_PACKET_FILTER, "SET ETHERNET PACKET FILTER"},
    {GET_ETHERNET_STATISTIC, "GET ETHERNET STATISTIC"},
    {SET_ATM_DATA_FORMAT, "SET ATM DATA FORMAT"},
    {GET_ATM_DEVICE_STATISTICS, "GET ATM DEVICE STATISTICS"},
    {SET_ATM_DEFAULT_VC, "SET ATM DEFAULT VC"},
    {GET_ATM_VC_STATISTICS, "GET ATM VC STATISTICS"},
    {GET_NTB_PARAMETERS, "GET NTB PARAMETERS"},
    {GET_NET_ADDRESS, "GET NET ADDRESS"},
    {SET_NET_ADDRESS, "SET NET ADDRESS"},
    {GET_NTB_FORMAT, "GET NTB FORMAT"},
    {SET_NTB_FORMAT, "SET NTB FORMAT"},
    {GET_NTB_INPUT_SIZE, "GET NTB INPUT SIZE"},
    {SET_NTB_INPUT_SIZE, "SET NTB INPUT SIZE"},
    {GET_MAX_DATAGRAM_SIZE, "GET MAX DATAGRAM SIZE"},
    {SET_MAX_DATAGRAM_SIZE, "SET MAX DATAGRAM SIZE"},
    {GET_CRC_MODE, "GET CRC MODE"},
    {SET_CRC_MODE, "SET CRC MODE"},
    {0, NULL}
};
static value_string_ext usb_com_setup_request_vals_ext = VALUE_STRING_EXT_INIT(usb_com_setup_request_vals);

static const int *usb_com_get_ntb_params_ntb_formats_supported_fields[] = {
    &hf_usb_com_get_ntb_params_ntb_formats_supported_16bit,
    &hf_usb_com_get_ntb_params_ntb_formats_supported_32bit,
    NULL
};

static const value_string usb_com_ntb_format_vals[] = {
    { 0x0000, "NTB-16"},
    { 0x0001, "NTB-32"},
    {0, NULL}
};

static const value_string usb_com_crc_mode_vals[] = {
    { 0x0000, "CRCs shall not be appended"},
    { 0x0001, "CRCs shall be appended"},
    {0, NULL}
};

static const int *ecm_eth_stats[] = {
    &hf_usb_com_descriptor_ecm_eth_stats_reserved,
    &hf_usb_com_descriptor_ecm_eth_stats_xmit_late_collisions,
    &hf_usb_com_descriptor_ecm_eth_stats_xmit_times_crs_lost,
    &hf_usb_com_descriptor_ecm_eth_stats_xmit_heartbeat_failure,
    &hf_usb_com_descriptor_ecm_eth_stats_xmit_underrun,
    &hf_usb_com_descriptor_ecm_eth_stats_rcv_overrun,
    &hf_usb_com_descriptor_ecm_eth_stats_xmit_max_collisions,
    &hf_usb_com_descriptor_ecm_eth_stats_xmit_deferred,
    &hf_usb_com_descriptor_ecm_eth_stats_xmit_more_collisions,
    &hf_usb_com_descriptor_ecm_eth_stats_xmit_one_collision,
    &hf_usb_com_descriptor_ecm_eth_stats_rcv_error_alignment,
    &hf_usb_com_descriptor_ecm_eth_stats_transmit_queue_length,
    &hf_usb_com_descriptor_ecm_eth_stats_rcv_crc_error,
    &hf_usb_com_descriptor_ecm_eth_stats_broadcast_frames_rcv,
    &hf_usb_com_descriptor_ecm_eth_stats_broadcast_bytes_rcv,
    &hf_usb_com_descriptor_ecm_eth_stats_multicast_frames_rcv,
    &hf_usb_com_descriptor_ecm_eth_stats_multicast_bytes_rcv,
    &hf_usb_com_descriptor_ecm_eth_stats_directed_frames_rcv,
    &hf_usb_com_descriptor_ecm_eth_stats_directed_bytes_rcv,
    &hf_usb_com_descriptor_ecm_eth_stats_broadcast_frames_xmit,
    &hf_usb_com_descriptor_ecm_eth_stats_broadcast_bytes_xmit,
    &hf_usb_com_descriptor_ecm_eth_stats_multicast_frames_xmit,
    &hf_usb_com_descriptor_ecm_eth_stats_multicast_bytes_xmit,
    &hf_usb_com_descriptor_ecm_eth_stats_directed_frames_xmit,
    &hf_usb_com_descriptor_ecm_eth_stats_directed_bytes_xmit,
    &hf_usb_com_descriptor_ecm_eth_stats_rcv_no_buffer,
    &hf_usb_com_descriptor_ecm_eth_stats_rcv_error,
    &hf_usb_com_descriptor_ecm_eth_stats_xmit_error,
    &hf_usb_com_descriptor_ecm_eth_stats_rvc_ok,
    &hf_usb_com_descriptor_ecm_eth_stats_xmit_ok,
    NULL
};

static const true_false_string usb_com_ecm_mc_address_filtering = {
    "Imperfect",
    "Perfect"
};

static const int *ecm_nb_mc_filters[] = {
    &hf_usb_com_descriptor_ecm_nb_mc_filters_mc_address_filtering,
    &hf_usb_com_descriptor_ecm_nb_mc_filters_nb_filters_supported,
    NULL
};

#define NETWORK_CONNECTION      0x00
#define RESPONSE_AVAILABLE      0x01
#define AUX_JACK_HOOK_STATE     0x08
#define RING_DETECT             0x09
#define SERIAL_STATE            0x20
#define CALL_STATE_CHANGE       0x28
#define LINE_STATE_CHANGE       0x29
#define CONNECTION_SPEED_CHANGE 0x2a

static const value_string usb_com_interrupt_notif_code_vals[] = {
    {NETWORK_CONNECTION, "NETWORK CONNECTION"},
    {RESPONSE_AVAILABLE, "RESPONSE AVAILABLE"},
    {AUX_JACK_HOOK_STATE, "AUX JACK HOOK STATE"},
    {RING_DETECT, "RING DETECT"},
    {SERIAL_STATE, "SERIAL STATE"},
    {CALL_STATE_CHANGE, "CALL STATE CHANGE"},
    {LINE_STATE_CHANGE, "LINE STATE CHANGE"},
    {CONNECTION_SPEED_CHANGE, "CONNECTION SPEED CHANGE"},
    {0, NULL}
};

static const value_string usb_com_interrupt_value_nw_conn_vals[] = {
    {0, "Disconnect"},
    {1, "Connected"},
    {0, NULL}
};

void proto_register_usb_com(void);
void proto_reg_handoff_usb_com(void);

static int
dissect_usb_com_descriptor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint8 offset = 0, type, subtype;
    proto_tree *subtree;
    proto_tree *subtree_capabilities;
    proto_item *subitem_capabilities;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_usb_com, NULL, "COMMUNICATIONS DESCRIPTOR");

    dissect_usb_descriptor_header(subtree, tvb, offset, &usb_com_descriptor_type_vals_ext);
    offset += 2;

    type = tvb_get_guint8(tvb, 1);
    switch (type) {
        case CS_INTERFACE:
            subtype = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(subtree, hf_usb_com_descriptor_subtype, tvb, offset, 1, subtype);
            offset++;
            switch (subtype) {
                case 0x00:
                    proto_tree_add_item(subtree, hf_usb_com_descriptor_cdc, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    break;
                case 0x01:
                    subitem_capabilities = proto_tree_add_item(subtree, hf_usb_com_capabilities, tvb, 3, 1, ENC_LITTLE_ENDIAN);
                    subtree_capabilities = proto_item_add_subtree(subitem_capabilities, ett_usb_com_capabilities);

                    proto_tree_add_item(subtree_capabilities, hf_usb_com_descriptor_cm_capabilities_reserved, tvb, 3, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(subtree_capabilities, hf_usb_com_descriptor_cm_capabilities_call_management_over_data_class_interface, tvb, 3, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(subtree_capabilities, hf_usb_com_descriptor_cm_capabilities_call_management, tvb, 3, 1, ENC_LITTLE_ENDIAN);

                    proto_tree_add_item(subtree, hf_usb_com_descriptor_cm_data_interface, tvb, 4, 1, ENC_LITTLE_ENDIAN);
                    offset = 5;
                    break;
                case 0x02:
                    subitem_capabilities = proto_tree_add_item(subtree, hf_usb_com_capabilities, tvb, 3, 1, ENC_LITTLE_ENDIAN);
                    subtree_capabilities = proto_item_add_subtree(subitem_capabilities, ett_usb_com_capabilities);

                    proto_tree_add_item(subtree_capabilities, hf_usb_com_descriptor_acm_capabilities_reserved, tvb, 3, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(subtree_capabilities, hf_usb_com_descriptor_acm_capabilities_network_connection, tvb, 3, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(subtree_capabilities, hf_usb_com_descriptor_acm_capabilities_send_break, tvb, 3, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(subtree_capabilities, hf_usb_com_descriptor_acm_capabilities_line_and_state, tvb, 3, 1, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(subtree_capabilities, hf_usb_com_descriptor_acm_capabilities_comm_features, tvb, 3, 1, ENC_LITTLE_ENDIAN);
                    offset = 4;
                    break;
                case 0x06:
                    offset = 3;
                    proto_tree_add_item(subtree, hf_usb_com_descriptor_control_interface, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset += 1;
                    while (tvb_reported_length_remaining(tvb,offset) > 0) {
                        proto_tree_add_item(subtree, hf_usb_com_descriptor_subordinate_interface, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                        offset += 1;
                    }
                    break;
                case 0x0f:
                    proto_tree_add_item(subtree, hf_usb_com_descriptor_ecm_mac_address, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset += 1;
                    proto_tree_add_bitmask_with_flags(subtree, tvb, offset, hf_usb_com_descriptor_ecm_eth_stats,
                                                      ett_usb_com_descriptor_ecm_eth_stats, ecm_eth_stats,
                                                      ENC_LITTLE_ENDIAN, BMT_NO_APPEND);
                    offset += 4;
                    proto_tree_add_item(subtree, hf_usb_com_descriptor_ecm_max_segment_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    proto_tree_add_bitmask_with_flags(subtree, tvb, offset, hf_usb_com_descriptor_ecm_nb_mc_filters,
                                                      ett_usb_com_descriptor_ecm_nb_mc_filters, ecm_nb_mc_filters,
                                                      ENC_LITTLE_ENDIAN, BMT_NO_APPEND);
                    offset += 2;
                    proto_tree_add_item(subtree, hf_usb_com_descriptor_ecm_nb_power_filters, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset += 1;
                    break;
                case 0x1b:
                case 0x1c:
                    offset = call_dissector_only(mbim_descriptor_handle, tvb, pinfo, subtree, data);
                    break;
                default:
                    break;
            }
            break;
        case CS_ENDPOINT:
        default:
            break;
    }

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_tree_add_item(subtree, hf_usb_com_descriptor_payload, tvb, offset, -1, ENC_NA);
    }
    return tvb_captured_length(tvb);
}

static int
dissect_usb_com_get_ntb_params(tvbuff_t *tvb, proto_tree *tree, gint base_offset)
{
    gint offset = base_offset;

    proto_tree_add_item(tree, hf_usb_com_get_ntb_params_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(tree, tvb, offset, hf_usb_com_get_ntb_params_ntb_formats_supported, ett_usb_com_bitmap,
                           usb_com_get_ntb_params_ntb_formats_supported_fields, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_usb_com_get_ntb_params_ntb_in_max_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_usb_com_get_ntb_params_ndp_in_divisor, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_usb_com_get_ntb_params_ndp_in_payload_remainder, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_usb_com_get_ntb_params_ndp_in_alignment, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_usb_com_get_ntb_params_reserved, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_usb_com_get_ntb_params_ntb_out_max_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_usb_com_get_ntb_params_ndp_out_divisor, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_usb_com_get_ntb_params_ndp_out_payload_remainder, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_usb_com_get_ntb_params_ndp_out_alignment, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_usb_com_get_ntb_params_ntb_out_max_datagrams, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static int
dissect_usb_com_ntb_input_size(tvbuff_t *tvb, proto_tree *tree, gint base_offset, gboolean is_set)
{
    gint offset = base_offset;

    proto_tree_add_item(tree, is_set ? hf_usb_com_set_ntb_input_size_ntb_in_max_size :
                        hf_usb_com_get_ntb_input_size_ntb_in_max_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_tree_add_item(tree, is_set ? hf_usb_com_set_ntb_input_size_ntb_in_max_datagrams :
                            hf_usb_com_get_ntb_input_size_ntb_in_max_datagrams, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(tree, is_set ? hf_usb_com_set_ntb_input_size_reserved :
                            hf_usb_com_get_ntb_input_size_reserved, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }

    return offset;
}

static int
dissect_usb_com_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    usb_conv_info_t *usb_conv_info = (usb_conv_info_t *)data;
    usb_trans_info_t *usb_trans_info;
    proto_tree *subtree;
    proto_item *ti;
    gint offset = 0;
    gboolean is_request;

    if (tvb_reported_length(tvb) == 0) {
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBCOM");

    ti = proto_tree_add_item(tree, proto_usb_com, tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_usb_com);

    if (usb_conv_info) {
        usb_trans_info = usb_conv_info->usb_trans_info;

        ti = proto_tree_add_uint(subtree, hf_usb_com_control_subclass, tvb, 0, 0,
                                 usb_conv_info->interfaceSubclass);
        PROTO_ITEM_SET_GENERATED(ti);

        is_request = (pinfo->srcport==NO_ENDPOINT);
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
        val_to_str_ext(usb_trans_info->setup.request, &usb_com_setup_request_vals_ext, "Unknown type %x"),
            is_request ? "Request" : "Response");

        if (is_request) {
            proto_tree_add_item(subtree, hf_usb_com_control_request_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(subtree, hf_usb_com_control_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(subtree, hf_usb_com_control_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(subtree, hf_usb_com_control_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        } else {
            ti = proto_tree_add_uint(subtree, hf_usb_com_control_response_code, tvb, 0, 0,
                                     usb_trans_info->setup.request);
            PROTO_ITEM_SET_GENERATED(ti);
        }

        switch (usb_trans_info->setup.request)
        {
            case SEND_ENCAPSULATED_COMMAND:
                if ((usb_conv_info->interfaceSubclass == COM_SUBCLASS_MBIM) &&
                    (USB_HEADER_IS_LINUX(usb_trans_info->header_type))) {
                    offset = call_dissector_only(mbim_control_handle, tvb, pinfo, tree, usb_conv_info);
                    break;
                }
                /* FALLTHROUGH */
            case GET_ENCAPSULATED_RESPONSE:
                if ((usb_conv_info->interfaceSubclass == COM_SUBCLASS_MBIM) && !is_request) {
                    offset = call_dissector_only(mbim_control_handle, tvb, pinfo, tree, usb_conv_info);
                }
                break;
            case GET_NTB_PARAMETERS:
                if (!is_request) {
                    offset = dissect_usb_com_get_ntb_params(tvb, subtree, offset);
                }
                break;
            case GET_NET_ADDRESS:
                if (!is_request) {
                    proto_tree_add_item(subtree, hf_usb_com_get_net_address_eui48, tvb, offset, 6, ENC_NA);
                    offset += 6;
                }
                break;
            case SET_NET_ADDRESS:
                if (is_request) {
                    proto_tree_add_item(subtree, hf_usb_com_set_net_address_eui48, tvb, offset, 6, ENC_NA);
                    offset += 6;
                }
                break;
            case GET_NTB_FORMAT:
                if (!is_request) {
                    proto_tree_add_item(subtree, hf_usb_com_get_ntb_format_ntb_format, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                }
                break;
            case SET_NTB_FORMAT:
                if (is_request) {
                    proto_tree_add_item(subtree, hf_usb_com_set_ntb_format_ntb_format, tvb, offset-6, 2, ENC_LITTLE_ENDIAN);
                }
                break;
            case GET_NTB_INPUT_SIZE:
                if (!is_request) {
                    offset = dissect_usb_com_ntb_input_size(tvb, subtree, offset, FALSE);
                }
                break;
            case SET_NTB_INPUT_SIZE:
                if (!is_request) {
                    offset = dissect_usb_com_ntb_input_size(tvb, subtree, offset, TRUE);
                }
                break;
            case GET_MAX_DATAGRAM_SIZE:
                if (!is_request) {
                    proto_tree_add_item(subtree, hf_usb_com_get_max_datagram_size_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                }
                break;
            case SET_MAX_DATAGRAM_SIZE:
                if (is_request) {
                    proto_tree_add_item(subtree, hf_usb_com_set_max_datagram_size_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                }
                break;
            case GET_CRC_MODE:
                if (!is_request) {
                    proto_tree_add_item(subtree, hf_usb_com_get_crc_mode_crc_mode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                }
                break;
            case SET_CRC_MODE:
                if (is_request) {
                    proto_tree_add_item(subtree, hf_usb_com_set_crc_mode_crc_mode, tvb, offset-6, 2, ENC_LITTLE_ENDIAN);
                }
                break;
            default:
                break;
        }
    }

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_tree_add_item(subtree, hf_usb_com_control_payload, tvb, offset, -1, ENC_NA);
    }
    return tvb_captured_length(tvb);
}

static int
dissect_usb_com_bulk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    usb_conv_info_t *usb_conv_info = (usb_conv_info_t *)data;

    if (usb_conv_info) {
        switch (usb_conv_info->interfaceProtocol)
        {
            case 0x01: /* Network Transfer Block */
            case 0x02: /* Network Transfer Block (IP + DSS) */
                return call_dissector_only(mbim_bulk_handle, tvb, pinfo, tree, NULL);
            default:
                break;
        }
    }

    /* By default, assume it is ethernet without FCS */
    return call_dissector_only(eth_withoutfcs_handle, tvb, pinfo, tree, NULL);
}

static int
dissect_usb_com_interrupt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_tree *subtree;
    proto_item *it;
    guint32 notif_code;
    gint offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBCOM");

    it = proto_tree_add_item(tree, proto_usb_com, tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(it, ett_usb_com);

    proto_tree_add_item(subtree, hf_usb_com_interrupt_request_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    proto_tree_add_item_ret_uint(subtree, hf_usb_com_interrupt_notif_code, tvb, offset, 1, ENC_LITTLE_ENDIAN, &notif_code);
    offset++;
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(notif_code, usb_com_interrupt_notif_code_vals, "Unknown type %x"));
    switch (notif_code) {
        case NETWORK_CONNECTION:
            proto_tree_add_item(subtree, hf_usb_com_interrupt_value_nw_conn, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(subtree, hf_usb_com_interrupt_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(subtree, hf_usb_com_interrupt_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            break;
        case RESPONSE_AVAILABLE:
            proto_tree_add_item(subtree, hf_usb_com_interrupt_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(subtree, hf_usb_com_interrupt_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(subtree, hf_usb_com_interrupt_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            break;
        case CONNECTION_SPEED_CHANGE:
            proto_tree_add_item(subtree, hf_usb_com_interrupt_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(subtree, hf_usb_com_interrupt_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(subtree, hf_usb_com_interrupt_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            it = proto_tree_add_item(subtree, hf_usb_com_interrupt_dl_bitrate, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            proto_item_append_text(it, " b/s");
            offset += 4;
            it = proto_tree_add_item(subtree, hf_usb_com_interrupt_ul_bitrate, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            proto_item_append_text(it, " b/s");
            offset += 4;
            break;
        default:
            break;
    }

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_tree_add_item(subtree, hf_usb_com_interrupt_payload, tvb, offset, -1, ENC_NA);
    }
    return tvb_captured_length(tvb);
}

void
proto_register_usb_com(void)
{
    static hf_register_info hf[] = {
        { &hf_usb_com_descriptor_subtype,
            { "Descriptor Subtype", "usbcom.descriptor.subtype", FT_UINT8, BASE_HEX|BASE_EXT_STRING,
              &usb_com_descriptor_subtype_vals_ext, 0, NULL, HFILL }},
        { &hf_usb_com_descriptor_cdc,
            { "CDC", "usbcom.descriptor.cdc", FT_UINT16, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_descriptor_payload,
            { "Payload", "usbcom.descriptor.payload", FT_BYTES, BASE_NONE,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_control_subclass,
            { "Subclass", "usbcom.control.subclass", FT_UINT8, BASE_HEX|BASE_EXT_STRING,
              &ext_usb_com_subclass_vals, 0, NULL, HFILL }},
        { &hf_usb_com_control_request_code,
            { "Request Code", "usbcom.control.request_code", FT_UINT8, BASE_HEX|BASE_EXT_STRING,
              &usb_com_setup_request_vals_ext, 0, NULL, HFILL }},
        { &hf_usb_com_control_value,
            { "Value", "usbcom.control.value", FT_UINT16, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_control_index,
            { "Index", "usbcom.control.index", FT_UINT16, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_control_length,
            { "Length", "usbcom.control.length", FT_UINT16, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_control_response_code,
            { "Response Code", "usbcom.control.response_code", FT_UINT8, BASE_HEX|BASE_EXT_STRING,
              &usb_com_setup_request_vals_ext, 0, NULL, HFILL }},
        { &hf_usb_com_get_ntb_params_length,
            { "Length", "usbcom.control.get_ntb_params.length", FT_UINT16, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_get_ntb_params_ntb_formats_supported,
            { "NTB Formats Supported", "usbcom.control.get_ntb_params.ntb_formats_supported", FT_UINT16, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_get_ntb_params_ntb_formats_supported_16bit,
            { "16-bit NTB", "usbcom.control.get_ntb_params.ntb_formats_supported.16bit", FT_BOOLEAN, 16,
              TFS(&tfs_supported_not_supported), 0x0001, NULL, HFILL }},
        { &hf_usb_com_get_ntb_params_ntb_formats_supported_32bit,
            { "32-bit NTB", "usbcom.control.get_ntb_params.ntb_formats_supported.32bit", FT_BOOLEAN, 16,
              TFS(&tfs_supported_not_supported), 0x0002, NULL, HFILL }},
        { &hf_usb_com_get_ntb_params_ntb_in_max_size,
            { "NTB IN Max Size", "usbcom.control.get_ntb_params.ntb_in_max_size", FT_UINT32, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_get_ntb_params_ndp_in_divisor,
            { "NDP IN Divisor", "usbcom.control.get_ntb_params.ndp_in_divisor", FT_UINT16, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_get_ntb_params_ndp_in_payload_remainder,
            { "NDP IN Payload Remainder", "usbcom.control.get_ntb_params.ndp_in_payload_remainder", FT_UINT16, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_get_ntb_params_ndp_in_alignment,
            { "NDP IN Alignment", "usbcom.control.get_ntb_params.ndp_in_alignment", FT_UINT16, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_get_ntb_params_reserved,
            { "Reserved", "usbcom.control.get_ntb_params.reserved", FT_UINT16, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_get_ntb_params_ntb_out_max_size,
            { "NTB OUT Max Size", "usbcom.control.get_ntb_params.ntb_out_max_size", FT_UINT32, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_get_ntb_params_ndp_out_divisor,
            { "NDP OUT Divisor", "usbcom.control.get_ntb_params.ndp_out_divisor", FT_UINT16, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_get_ntb_params_ndp_out_payload_remainder,
            { "NDP OUT Payload Remainder", "usbcom.control.get_ntb_params.ndp_out_payload_remainder", FT_UINT16, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_get_ntb_params_ndp_out_alignment,
            { "NDP OUT Alignment", "usbcom.control.get_ntb_params.ndp_out_alignment", FT_UINT16, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_get_ntb_params_ntb_out_max_datagrams,
            { "NTB OUT Max Datagrams", "usbcom.control.get_ntb_params.ntb_out_max_datagrams", FT_UINT16, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_get_net_address_eui48,
            { "EUI-48", "usbcom.control.get_net_address.eui48", FT_ETHER, BASE_NONE,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_set_net_address_eui48,
            { "EUI-48", "usbcom.control.set_net_address.eui48", FT_ETHER, BASE_NONE,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_get_ntb_format_ntb_format,
            { "NTB Format", "usbcom.control.get_net_address.ntb_format", FT_UINT16, BASE_HEX,
              VALS(usb_com_ntb_format_vals), 0, NULL, HFILL }},
        { &hf_usb_com_set_ntb_format_ntb_format,
            { "NTB Format", "usbcom.control.set_net_address.ntb_format", FT_UINT16, BASE_HEX,
              VALS(usb_com_ntb_format_vals), 0, NULL, HFILL }},
        { &hf_usb_com_get_ntb_input_size_ntb_in_max_size,
            { "NTB IN Max Size", "usbcom.control.get_ntb_input_size.ntb_in_max_size", FT_UINT32, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_get_ntb_input_size_ntb_in_max_datagrams,
            { "NTB IN Max Datagrams", "usbcom.control.get_ntb_input_size.ntb_in_max_datagrams", FT_UINT16, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_get_ntb_input_size_reserved,
            { "Reserved", "usbcom.control.get_ntb_input_size.reserved", FT_UINT16, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_set_ntb_input_size_ntb_in_max_size,
            { "NTB IN Max Size", "usbcom.control.set_ntb_input_size.ntb_in_max_size", FT_UINT32, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_set_ntb_input_size_ntb_in_max_datagrams,
            { "NTB IN Max Datagrams", "usbcom.control.set_ntb_input_size.ntb_in_max_datagrams", FT_UINT16, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_set_ntb_input_size_reserved,
            { "Reserved", "usbcom.control.set_ntb_input_size.reserved", FT_UINT16, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_get_max_datagram_size_size,
            { "Max Datagram Size", "usbcom.control.get_max_datagram_size.size", FT_UINT16, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_set_max_datagram_size_size,
            { "Max Datagram Size", "usbcom.control.set_max_datagram_size.size", FT_UINT16, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_get_crc_mode_crc_mode,
            { "CRC Mode", "usbcom.control.get_crc_mode.crc_mode", FT_UINT16, BASE_HEX,
              VALS(usb_com_crc_mode_vals), 0, NULL, HFILL }},
        { &hf_usb_com_set_crc_mode_crc_mode,
            { "CRC Mode", "usbcom.control.set_crc_mode.crc_mode", FT_UINT16, BASE_HEX,
              VALS(usb_com_crc_mode_vals), 0, NULL, HFILL }},
        { &hf_usb_com_control_payload,
            { "Payload", "usbcom.control.payload", FT_BYTES, BASE_NONE,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_capabilities,
            { "bmCapabilities", "usbcom.descriptor.capabilities", FT_UINT8, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_descriptor_acm_capabilities_reserved,
            { "Reserved", "usbcom.descriptor.acm.capabilities.reserved", FT_UINT8, BASE_HEX,
              NULL, 0xF0, NULL, HFILL }},
        { &hf_usb_com_descriptor_acm_capabilities_network_connection,
            { "Network_Connection", "usbcom.descriptor.acm.capabilities.network_connection", FT_BOOLEAN, 8,
              TFS(&tfs_supported_not_supported), 0x08, NULL, HFILL }},
        { &hf_usb_com_descriptor_acm_capabilities_send_break,
            { "Send_Break", "usbcom.descriptor.acm.capabilities.network_connection", FT_BOOLEAN, 8,
              TFS(&tfs_supported_not_supported), 0x04, NULL, HFILL }},
        { &hf_usb_com_descriptor_acm_capabilities_line_and_state,
            { "Line Requests and State Notification", "usbcom.descriptor.acm.capabilities.line_and_state", FT_BOOLEAN, 8,
              TFS(&tfs_supported_not_supported), 0x02, NULL, HFILL }},
        { &hf_usb_com_descriptor_acm_capabilities_comm_features,
            { "Comm Features Combinations", "usbcom.descriptor.acm.capabilities.comm_features", FT_BOOLEAN, 8,
              TFS(&tfs_supported_not_supported), 0x01, NULL, HFILL }},
        { &hf_usb_com_descriptor_control_interface,
            { "Control Interface", "usbcom.descriptor.control_interface", FT_UINT8, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_descriptor_subordinate_interface,
            { "Subordinate Interface", "usbcom.descriptor.subordinate_interface", FT_UINT8, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_descriptor_cm_capabilities_reserved,
            { "Reserved", "usbcom.descriptor.cm.capabilities.reserved", FT_UINT8, BASE_HEX,
              NULL, 0xFC, NULL, HFILL }},
        { &hf_usb_com_descriptor_cm_capabilities_call_management_over_data_class_interface,
            { "Call Management over Data Class Interface", "usbcom.descriptor.cm.capabilities.call_management_over_data_class_interface", FT_BOOLEAN, 8,
              TFS(&tfs_supported_not_supported), 0x02, NULL, HFILL }},
        { &hf_usb_com_descriptor_cm_capabilities_call_management,
            { "Call Management", "usbcom.descriptor.cm.capabilities.call_management", FT_BOOLEAN, 8,
              TFS(&tfs_supported_not_supported), 0x01, NULL, HFILL }},
        { &hf_usb_com_descriptor_cm_data_interface,
            { "Data Interface", "usbcom.descriptor.cm.data_interface", FT_UINT8, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_mac_address,
            { "MAC Address", "usbcom.descriptor.ecm.mac_address", FT_UINT8, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats,
            { "Ethernet Statistics", "usbcom.descriptor.ecm.eth_stats", FT_UINT32, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_reserved,
            { "Reserved", "usbcom.descriptor.ecm.eth_stats.reserved", FT_UINT32, BASE_HEX,
              NULL, 0xe0000000, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_xmit_late_collisions,
            { "XMIT Late Collisions", "usbcom.descriptor.ecm.eth_stats.xmit_late_collisions", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x10000000, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_xmit_times_crs_lost,
            { "XMIT TImes CRS Lost", "usbcom.descriptor.ecm.eth_stats.xmit_times_crs_lost", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x08000000, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_xmit_heartbeat_failure,
            { "XMIT Heartbeat Failure", "usbcom.descriptor.ecm.eth_stats.xmit_heartbeat_failure", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x04000000, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_xmit_underrun,
            { "XMIT Underrun", "usbcom.descriptor.ecm.eth_stats.xmit_underrun", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x02000000, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_rcv_overrun,
            { "RCV Overrun", "usbcom.descriptor.ecm.eth_stats.rcv_overrun", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x01000000, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_xmit_max_collisions,
            { "XMIT Max Collisions", "usbcom.descriptor.ecm.eth_stats.xmit_max_collisions", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x00800000, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_xmit_deferred,
            { "XMIT Deferred", "usbcom.descriptor.ecm.eth_stats.xmit_deferred", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x00400000, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_xmit_more_collisions,
            { "XMIT More Collisions", "usbcom.descriptor.ecm.eth_stats.xmit_more_collisions", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x00200000, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_xmit_one_collision,
            { "XMIT One Collision", "usbcom.descriptor.ecm.eth_stats.xmit_one_collision", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x00100000, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_rcv_error_alignment,
            { "RCV Error Alignment", "usbcom.descriptor.ecm.eth_stats.rcv_error_alignment", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x00080000, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_transmit_queue_length,
            { "Transmit Queue Length", "usbcom.descriptor.ecm.eth_stats.transmit_queue_length", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x00040000, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_rcv_crc_error,
            { "RCV CRC Error", "usbcom.descriptor.ecm.eth_stats.rcv_crc_error", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x00020000, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_broadcast_frames_rcv,
            { "Broadcast Frames RCV", "usbcom.descriptor.ecm.eth_stats.broadcast_frames_rcv", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x00010000, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_broadcast_bytes_rcv,
            { "Broadcast Bytes RCV", "usbcom.descriptor.ecm.eth_stats.broadcast_bytes_rcv", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x00008000, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_multicast_frames_rcv,
            { "Multicast Frames RCV", "usbcom.descriptor.ecm.eth_stats.multicast_frames_rcv", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x00004000, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_multicast_bytes_rcv,
            { "Multicast Bytes RCV", "usbcom.descriptor.ecm.eth_stats.multicast_bytes_rcv", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x00002000, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_directed_frames_rcv,
            { "Directed Frames RCV", "usbcom.descriptor.ecm.eth_stats.directed_frames_rcv", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x00001000, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_directed_bytes_rcv,
            { "Directed Bytes RCV", "usbcom.descriptor.ecm.eth_stats.directed_bytes_rcv", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x00000800, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_broadcast_frames_xmit,
            { "Broadcast Frames XMIT", "usbcom.descriptor.ecm.eth_stats.broadcast_frames_xmit", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x00000400, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_broadcast_bytes_xmit,
            { "Broadcast Bytes XMIT", "usbcom.descriptor.ecm.eth_stats.broadcast_bytes_xmit", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x00000200, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_multicast_frames_xmit,
            { "Multicast Frames XMIT", "usbcom.descriptor.ecm.eth_stats.multicast_frames_xmit", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x00000100, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_multicast_bytes_xmit,
            { "Multicast Bytes XMIT", "usbcom.descriptor.ecm.eth_stats.multicast_bytes_xmit", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x00000080, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_directed_frames_xmit,
            { "Directed Frames XMIT", "usbcom.descriptor.ecm.eth_stats.directed_frames_xmit", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x00000040, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_directed_bytes_xmit,
            { "Directed Bytes XMIT", "usbcom.descriptor.ecm.eth_stats.directed_bytes_xmit", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x00000020, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_rcv_no_buffer,
            { "RCV No Buffer", "usbcom.descriptor.ecm.eth_stats.rcv_no_buffer", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x00000010, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_rcv_error,
            { "RCV Error", "usbcom.descriptor.ecm.eth_stats.rcv_error", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x00000008, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_xmit_error,
            { "XMIT Error", "usbcom.descriptor.ecm.eth_stats.xmit_error", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x00000004, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_rvc_ok,
            { "RCV OK", "usbcom.descriptor.ecm.eth_stats.rvc_ok", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x00000002, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_eth_stats_xmit_ok,
            { "XMIT OK", "usbcom.descriptor.ecm.eth_stats.xmit_ok", FT_BOOLEAN, 32,
              TFS(&tfs_supported_not_supported), 0x00000001, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_max_segment_size,
            { "Max Segment Size", "usbcom.descriptor.ecm.max_segment_size", FT_UINT16, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_nb_mc_filters,
            { "Number MC Filters", "usbcom.descriptor.ecm.nb_mc_filters", FT_UINT16, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_nb_mc_filters_mc_address_filtering,
            { "Multicast Address Filtering", "usbcom.descriptor.ecm.nb_mc_filters.mc_address_filtering", FT_BOOLEAN, 16,
              TFS(&usb_com_ecm_mc_address_filtering), 0x8000, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_nb_mc_filters_nb_filters_supported,
            { "Number of Multicast Address Filters Supported", "usbcom.descriptor.ecm.nb_mc_filters.nb_filters_supported", FT_UINT16, BASE_DEC,
              NULL, 0x7fff, NULL, HFILL }},
        { &hf_usb_com_descriptor_ecm_nb_power_filters,
            { "Number Power Filters", "usbcom.descriptor.ecm.nb_power_filters", FT_UINT8, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_interrupt_request_type,
            { "Request Type", "usbcom.interrupt.request_type", FT_UINT8, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_interrupt_notif_code,
            { "Notification Code", "usbcom.interrupt.notification_code", FT_UINT8, BASE_HEX,
              VALS(usb_com_interrupt_notif_code_vals), 0, NULL, HFILL }},
        { &hf_usb_com_interrupt_value,
            { "Value", "usbcom.interrupt.value", FT_UINT16, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_interrupt_value_nw_conn,
            { "Value", "usbcom.interrupt.value", FT_UINT16, BASE_HEX,
              VALS(usb_com_interrupt_value_nw_conn_vals), 0, NULL, HFILL }},
        { &hf_usb_com_interrupt_index,
            { "Index", "usbcom.interrupt.index", FT_UINT16, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_interrupt_length,
            { "Length", "usbcom.interrupt.length", FT_UINT16, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_interrupt_dl_bitrate,
            { "DL Bitrate", "usbcom.interrupt.conn_speed_change.dl_bitrate", FT_UINT32, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_interrupt_ul_bitrate,
            { "UL Bitrate", "usbcom.interrupt.conn_speed_change.ul_bitrate", FT_UINT32, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_usb_com_interrupt_payload,
            { "Payload", "usbcom.interrupt.payload", FT_BYTES, BASE_NONE,
              NULL, 0, NULL, HFILL }}
    };

    static gint *usb_com_subtrees[] = {
        &ett_usb_com,
        &ett_usb_com_capabilities,
        &ett_usb_com_bitmap,
        &ett_usb_com_descriptor_ecm_eth_stats,
        &ett_usb_com_descriptor_ecm_nb_mc_filters
    };

    proto_usb_com = proto_register_protocol("USB Communications and CDC Control", "USBCOM", "usbcom");
    proto_register_field_array(proto_usb_com, hf, array_length(hf));
    proto_register_subtree_array(usb_com_subtrees, array_length(usb_com_subtrees));
}

void
proto_reg_handoff_usb_com(void)
{
    dissector_handle_t usb_com_descriptor_handle, usb_com_control_handle,
                       usb_com_bulk_handle, usb_com_interrupt_handle;

    usb_com_descriptor_handle = create_dissector_handle(dissect_usb_com_descriptor, proto_usb_com);
    dissector_add_uint("usb.descriptor", IF_CLASS_COMMUNICATIONS, usb_com_descriptor_handle);
    usb_com_control_handle = create_dissector_handle(dissect_usb_com_control, proto_usb_com);
    dissector_add_uint("usb.control", IF_CLASS_COMMUNICATIONS, usb_com_control_handle);
    usb_com_bulk_handle = create_dissector_handle(dissect_usb_com_bulk, proto_usb_com);
    dissector_add_uint("usb.bulk", IF_CLASS_CDC_DATA, usb_com_bulk_handle);
    usb_com_interrupt_handle = create_dissector_handle(dissect_usb_com_interrupt, proto_usb_com);
    dissector_add_uint("usb.interrupt", IF_CLASS_COMMUNICATIONS, usb_com_interrupt_handle);
    mbim_control_handle = find_dissector_add_dependency("mbim.control", proto_usb_com);
    mbim_descriptor_handle = find_dissector_add_dependency("mbim.descriptor", proto_usb_com);
    mbim_bulk_handle = find_dissector_add_dependency("mbim.bulk", proto_usb_com);
    eth_withoutfcs_handle = find_dissector_add_dependency("eth_withoutfcs", proto_usb_com);
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

/* packet-bluetooth-hci.h
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

#ifndef __PACKET_BLUETOOTH_HCI_H__
#define __PACKET_BLUETOOTH_HCI_H__

#include <epan/wmem/wmem.h>

#define HCI_H4_TYPE_CMD   0x01
#define HCI_H4_TYPE_ACL   0x02
#define HCI_H4_TYPE_SCO   0x03
#define HCI_H4_TYPE_EVT   0x04

#define HCI_OGF_LINK_CONTROL           0x01
#define HCI_OGF_LINK_POLICY            0x02
#define HCI_OGF_HOST_CONTROLLER        0x03
#define HCI_OGF_INFORMATIONAL          0x04
#define HCI_OGF_STATUS                 0x05
#define HCI_OGF_TESTING                0x06
#define HCI_OGF_LOW_ENERGY             0x08
#define HCI_OGF_LOGO_TESTING           0x3e
#define HCI_OGF_VENDOR_SPECIFIC        0x3f

#define DID_VENDOR_ID_SOURCE_BLUETOOTH_SIG  1
#define DID_VENDOR_ID_SOURCE_USB_FORUM      2

#define ACCESS_ADDRESS_ADVERTISING 0x8e89bed6

extern value_string_ext bthci_cmd_opcode_vals_ext;
extern value_string_ext bthci_ogf_vals_ext;
extern value_string_ext bthci_cmd_ocf_link_control_vals_ext;
extern value_string_ext bthci_cmd_ocf_link_policy_vals_ext;
extern value_string_ext bthci_cmd_ocf_host_controller_and_baseband_vals_ext;
extern value_string_ext bthci_cmd_ocf_informational_vals_ext;
extern value_string_ext bthci_cmd_ocf_status_vals_ext;
extern value_string_ext bthci_cmd_ocf_testing_vals_ext;
extern value_string_ext bthci_cmd_ocf_low_energy_vals_ext;

extern value_string_ext bthci_cmd_input_coding_vals_ext;
extern value_string_ext bthci_cmd_input_data_format_vals_ext;
extern value_string_ext bthci_cmd_input_sample_size_vals_ext;
extern value_string_ext bthci_cmd_air_coding_format_vals_ext;
extern value_string_ext bthci_cmd_status_vals_ext;
extern value_string_ext bthci_cmd_eir_data_type_vals_ext;
extern value_string_ext bthci_cmd_auth_req_vals_ext;
extern value_string_ext bthci_cmd_appearance_vals_ext;
extern value_string_ext bthci_evt_comp_id_ext;

extern value_string_ext bt_sig_uuid_vals_ext;

extern const value_string bthci_cmd_io_capability_vals[];
extern const value_string bthci_cmd_oob_data_present_vals[];
extern const value_string bthci_cmd_address_types_vals[];
extern const value_string bthci_cmd_scan_enable_values[];
extern const value_string bthci_cmd_page_scan_modes[];
extern const value_string bthci_cmd_page_scan_repetition_modes[];
extern const value_string bthci_cmd_page_scan_period_modes[];
extern const value_string bthci_cmd_notification_types[];


/* We support Bluetooth over various interfaces, interface_id and adapter_id
   is used to decode further payload. Case: there is a host. Host has X
   interfaces. Each interface has Y adapter. Each adapter has ACL handle or
   L2CAP CID. ACL handle has L2CAP CID and/or L2CAP PSM. L2CAP CID or
   L2CAP PSM has RFCOMM channel or other end-protocol like OBEX, AVRCP, HID,
   AVDTP, BNEP etc. RFCOMM channel has end-protocol like OBEX, HFP, etc.
   Important note: correct payload decoding should store needed data using
   key contain interface_id, adapter_id, ..., last_channel_type (for example
   RFCOMM channel, transaction_id, frame number etc. )

   interface_id - interface id provided by Wireshark, see "frame.interface_id",
                  in case where is only one interface id HCI_INTERFACE_DEFAULT
                  is used (for example open BTSNOOP file with HCI H4 protocol)
   adapter_id   - identified Bluetooth device (interface, for example Linux
                  hci0, hci1, etc.)
*/
#define HCI_INTERFACE_DEFAULT  0
#define HCI_ADAPTER_DEFAULT    0

/* chandle_to_bdaddr_table:  interface_id + adapter_id + connection_handle + frame_number -> bd_addr[6] */
/* bdaddr_to_name_table:     bd_addr[6] + frame_number -> name */
/* localhost_bdaddr:         interface_id + adapter_id + frame_number -> bd_addr[6] */
/* localhost_name:           interface_id + adapter_id + frame_number -> name */
typedef struct _hci_data_t {
    guint32      interface_id;
    guint32      adapter_id;
    guint32     *adapter_disconnect_in_frame;
    wmem_tree_t *chandle_sessions;
    wmem_tree_t *chandle_to_bdaddr_table;
    wmem_tree_t *bdaddr_to_name_table;
    wmem_tree_t *localhost_bdaddr;
    wmem_tree_t *localhost_name;
} hci_data_t;

typedef struct _chandle_session_t {
    guint32  connect_in_frame;
    guint32  disconnect_in_frame;
} chandle_session_t;

typedef struct _remote_bdaddr_t {
    guint32  interface_id;
    guint32  adapter_id;
    guint16  chandle;
    guint8   bd_addr[6];
} remote_bdaddr_t;

typedef struct _device_name_t {
    guint32  bd_addr_oui;
    guint32  bd_addr_id;
    gchar    *name;
} device_name_t;

typedef struct _localhost_bdaddr_entry_t {
    guint32  interface_id;
    guint32  adapter_id;
    guint8   bd_addr[6];
} localhost_bdaddr_entry_t;

typedef struct _localhost_name_entry_t {
    guint32  interface_id;
    guint32  adapter_id;
    gchar    *name;
} localhost_name_entry_t;

/* In "packet-btle.c" */
extern gint dissect_bd_addr(gint hf_bd_addr, proto_tree *tree, tvbuff_t *tvb, gint offset);

#endif

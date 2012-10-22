/* packet-hci_h4.h
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

#ifndef __PACKET_HCI_H4_H__
#define __PACKET_HCI_H4_H__

#define HCI_H4_TYPE_CMD		0x01
#define HCI_H4_TYPE_ACL		0x02
#define HCI_H4_TYPE_SCO		0x03
#define HCI_H4_TYPE_EVT		0x04

extern value_string_ext bthci_cmd_opcode_vals_ext;

#define HCI_OGF_LINK_CONTROL		0x01
#define HCI_OGF_LINK_POLICY		0x02
#define HCI_OGF_HOST_CONTROLLER		0x03
#define HCI_OGF_INFORMATIONAL		0x04
#define HCI_OGF_STATUS		        0x05
#define HCI_OGF_TESTING		        0x06
#define HCI_OGF_LOW_ENERGY	    0x08
#define HCI_OGF_LOGO_TESTING		0x3e
#define HCI_OGF_VENDOR_SPECIFIC		0x3f
extern value_string_ext bthci_ogf_vals_ext;

extern value_string_ext bthci_cmd_status_vals_ext;
extern value_string_ext bthci_cmd_service_class_type_vals_ext;
extern value_string_ext bthci_cmd_major_dev_class_vals_ext;
extern value_string_ext bthci_cmd_eir_data_type_vals_ext;
extern value_string_ext bthci_cmd_auth_req_vals_ext;
extern value_string_ext bthci_cmd_appearance_vals_ext;
extern value_string_ext bthci_evt_comp_id_ext;

extern const value_string bthci_cmd_io_capability_vals[];
extern const value_string bthci_cmd_oob_data_present_vals[];
extern const value_string bthci_cmd_address_types_vals[];
extern const value_string bthci_cmd_scan_enable_values[];
extern const value_string bthci_cmd_page_scan_modes[];
extern const value_string bthci_cmd_page_scan_repetition_modes[];
extern const value_string bthci_cmd_page_scan_period_modes[];
extern const value_string bthci_cmd_notification_types[];

#endif

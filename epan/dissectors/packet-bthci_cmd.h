/* packet-bthci_cmd.h
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

#ifndef __PACKET_BTHCI_CMD_H__
#define __PACKET_BTHCI_CMD_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

extern value_string_ext bthci_cmd_opcode_vals_ext;
extern value_string_ext bthci_cmd_ogf_vals_ext;
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

extern const value_string bthci_cmd_io_capability_vals[];
extern const value_string bthci_cmd_oob_data_present_vals[];
extern const value_string bthci_cmd_address_types_vals[];
WS_DLL_PUBLIC const value_string bthci_cmd_scan_enable_values[];
extern const value_string bthci_cmd_page_scan_modes[];
extern const value_string bthci_cmd_page_scan_repetition_modes[];
extern const value_string bthci_cmd_page_scan_period_modes[];
extern const value_string bthci_cmd_notification_types[];

WS_DLL_PUBLIC const value_string bthci_cmd_encrypt_mode_vals[];
WS_DLL_PUBLIC const value_string bthci_cmd_authentication_enable_values[];
WS_DLL_PUBLIC const value_string bthci_cmd_inq_modes[];


typedef struct _bthci_cmd_data_t {
    guint32  opcode;

    guint32  command_in_frame;
    nstime_t command_abs_ts;
    guint32  pending_in_frame;
    nstime_t pending_abs_ts;
    guint32  response_in_frame;
    nstime_t response_abs_ts;

    union {
        gchar   *name;
        guint8   scan;
        guint16  page_timeout;
        guint8   authentication;
        guint8   encryption;
        guint32  class_of_device;
        guint16  voice_setting;
        guint8   simple_pairing_mode;
        guint8   inquiry_mode;
        struct {
            guint16  acl_mtu;
            guint8   sco_mtu;
            guint16  acl_packets;
            guint16  sco_packets;
        } mtus;
    } data;
} bthci_cmd_data_t;

extern wmem_tree_t *bthci_cmds;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

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

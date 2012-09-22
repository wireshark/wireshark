/* keys.h
 * Key definitions for various objects
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

#ifndef __KEYS_H__
#define __KEYS_H__

/** @file
 * Various keys for g_object_set_data().
 */
#define E_DFILTER_CM_KEY				"display_filter_combo"

#define E_DFILTER_TE_KEY								"display_filter_entry"
#define E_RFILTER_TE_KEY								"read_filter_te"
#define E_MPACKET_LIST_KEY							"menu_packet_list"
#define E_MPACKET_LIST_ROW_KEY					"menu_packet_list_row"
#define E_MPACKET_LIST_COL_KEY					"menu_packet_list_col"
#define E_MPACKET_LIST_COLUMN_KEY				"menu_packet_list_column"
#define E_MPACKET_LIST_PREV_COLUMN_KEY	"menu_packet_list_prev_column"
#define E_MCAPTURE_COLUMNS_COL_KEY			"menu_capture_columns_col"
#define E_MCAPTURE_COLUMNS_COLUMN_KEY		"menu_capture_columns_column"

#define PRINT_CMD_LB_KEY				"printer_command_label"
#define PRINT_CMD_TE_KEY				"printer_command_entry"
#define PRINT_FILE_BT_KEY				"printer_file_button"
#define PRINT_FILE_TE_KEY				"printer_file_entry"

#define PLUGINS_DFILTER_TE				"plugins_dfilter_te"

#define PM_MENU_LIST_KEY				"popup_menu_menu_list"
#define PM_PACKET_LIST_COL_KEY			"popup_menu_packet_list_column"
#define PM_PACKET_LIST_KEY				"popup_menu_packet_list"
#define PM_TREE_VIEW_KEY				"popup_menu_tree_view"
#define PM_BYTES_VIEW_KEY				"popup_menu_bytes_view"
#define PM_STATUSBAR_PROFILES_KEY		       	"popup_menu_statusbar_profiles"
#define PM_COLUMNS_KEY          "popup_menu_capture_options"

#define E_TB_MAIN_KEY					"toolbar_main"
#define E_TB_FILTER_KEY					"toolbar_filter"

#ifdef HAVE_AIRPCAP
#define AIRPCAP_TOOLBAR_KEY						"airpcap_toolbar_key"
#define AIRPCAP_TOOLBAR_INTERFACE_KEY			"airpcap_toolbar_if_key"
#define AIRPCAP_TOOLBAR_LINK_TYPE_KEY			"airpcap_toolbar_lt_key"
#define AIRPCAP_TOOLBAR_CHANNEL_KEY				"airpcap_toolbar_ch_key"
#define AIRPCAP_TOOLBAR_CHANNEL_LABEL_KEY		"airpcap_toolbar_ch_lb_key"
#define AIRPCAP_TOOLBAR_CHANNEL_OFFSET_KEY		"airpcap_toolbar_ch_offset_key"
#define AIRPCAP_TOOLBAR_CHANNEL_OFFSET_LABEL_KEY "airpcap_toolbar_ch_offset_lb_key"
#define AIRPCAP_TOOLBAR_FCS_CHECK_KEY	"airpcap_toolbar_fcs_check_key"
#define AIRPCAP_TOOLBAR_FCS_FILTER_LABEL_KEY	"airpcap_toolbar_fcs_filter_lb_key"
#define AIRPCAP_TOOLBAR_FCS_FILTER_KEY		"airpcap_toolbar_fcs_filter_key"
#define AIRPCAP_TOOLBAR_ADVANCED_KEY		"airpcap_toolbar_advanced_key"
#define AIRPCAP_TOOLBAR_KEY_MANAGEMENT_KEY	"airpcap_toolbar_key_management_key"
#define AIRPCAP_TOOLBAR_DECRYPTION_KEY		"airpcap_toolbar_decryption_key"
#define AIRPCAP_TOOLBAR_DECRYPTION_LABEL_KEY  "airpcap_toolbar_decryption_lb_key"

#define AIRPCAP_ADVANCED_KEY				"airpcap_advanced_key"
#define AIRPCAP_ADVANCED_INTERFACE_KEY		"airpcap_advanced_if_key"
#define AIRPCAP_ADVANCED_LINK_TYPE_KEY		"airpcap_advanced_lt_key"
#define AIRPCAP_ADVANCED_CHANNEL_KEY		"airpcap_advanced_ch_key"
#define AIRPCAP_ADVANCED_CHANNEL_OFFSET_KEY	"airpcap_advanced_ch_offset_key"
#define AIRPCAP_ADVANCED_FCS_CHECK_KEY		"airpcap_advanced_fcs_check_key"
#define AIRPCAP_ADVANCED_FCS_FILTER_KEY		"airpcap_advanced_fcs_filter_key"
#define AIRPCAP_ADVANCED_BLINK_KEY			"airpcap_advanced_blink_key"
#define AIRPCAP_ADVANCED_ADD_KEY_TEXT_KEY	"airpcap_advanced_add_key_text_key"
#define AIRPCAP_ADVANCED_ADD_KEY_OK_KEY		"airpcap_advanced_add_key_ok_key"
#define AIRPCAP_ADVANCED_ADD_KEY_LIST_KEY	"airpcap_advanced_add_key_list_key"
#define AIRPCAP_ADVANCED_ADD_KEY_TYPE_KEY	"airpcap_advanced_add_key_type_key"
#define AIRPCAP_ADVANCED_ADD_KEY_KEY_KEY	"airpcap_advanced_add_key_key_key"
#define AIRPCAP_ADVANCED_ADD_KEY_SSID_KEY	"airpcap_advanced_add_key_ssid_key"
#define AIRPCAP_ADVANCED_ADD_KEY_KEY_LABEL_KEY	"airpcap_advanced_add_key_key_label_key"
#define AIRPCAP_ADVANCED_ADD_KEY_SSID_LABEL_KEY	"airpcap_advanced_add_key_ssid_label_key"
#define AIRPCAP_ADVANCED_EDIT_KEY_SELECTED_KEY	"airpcap_advanced_edit_key_selected_key"
#define AIRPCAP_ADVANCED_EDIT_KEY_OK_KEY		"airpcap_advanced_edit_key_ok_key"
#define AIRPCAP_ADVANCED_EDIT_KEY_LIST_KEY		"airpcap_advanced_edit_key_list_key"
#define AIRPCAP_ADVANCED_EDIT_KEY_TYPE_KEY		"airpcap_advanced_edit_key_type_key"
#define AIRPCAP_ADVANCED_EDIT_KEY_KEY_KEY		"airpcap_advanced_edit_key_key_key"
#define AIRPCAP_ADVANCED_EDIT_KEY_SSID_KEY		"airpcap_advanced_edit_key_ssid_key"
#define AIRPCAP_ADVANCED_EDIT_KEY_KEY_LABEL_KEY	"airpcap_advanced_edit_key_key_label_key"
#define AIRPCAP_ADVANCED_EDIT_KEY_SSID_LABEL_KEY	"airpcap_advanced_edit_key_ssid_label_key"
#define AIRPCAP_ADVANCED_DECRYPTION_MODE_KEY	"airpcap_advanced_decryption_mode_key"
#define AIRPCAP_ADVANCED_WPA_DECRYPTION_KEY		"airpcap_advanced_wpa_decryption_key"
#define AIRPCAP_ADVANCED_NOTEBOOK_KEY			"airpcap_advanced_notebook_key"
#define AIRPCAP_ADVANCED_CANCEL_KEY				"airpcap_advanced_cancel_key"
#define AIRPCAP_ADVANCED_OK_KEY					"airpcap_advanced_ok_key"
#define AIRPCAP_ADVANCED_KEYLIST_KEY			"airpcap_advanced_keylist_key"
#define AIRPCAP_CHECK_WINDOW_RADIO_KEEP_KEY		"airpcap_check_window_radio_keep_key"
#define AIRPCAP_CHECK_WINDOW_RADIO_MERGE_KEY	 "airpcap_check_window_radio_merge_key"
#define AIRPCAP_CHECK_WINDOW_RADIO_IMPORT_KEY	"airpcap_check_window_radio_import_key"
#define AIRPCAP_CHECK_WINDOW_RADIO_IGNORE_KEY	"airpcap_check_window_radio_ignore_key"
#define AIRPCAP_CHECK_WINDOW_RADIO_GROUP_KEY	"airpcap_check_window_radio_group_key"

#define AIRPCAP_CHECK_WINDOW_KEY				"airpcap_check_window_key"

#define AIRPCAP_ADVANCED_EDIT_KEY_SELECTION_KEY		"airpcap_advanced_edit_key_selection_key"

#define AIRPCAP_ADVANCED_FROM_KEY				"airpcap_advanced_from_key"

#define AIRPCAP_KEY_MGMT_NEW_KEY	"airpcap_key_mgmt_new_key"
#define AIRPCAP_KEY_MGMT_EDIT_KEY	"airpcap_key_mgmt_edit_key"
#define AIRPCAP_KEY_MGMT_DELETE_KEY	"airpcap_key_mgmt_delete_key"
#define AIRPCAP_KEY_MGMT_UP_KEY		"airpcap_key_mgmt_up_key"
#define AIRPCAP_KEY_MGMT_DOWN_KEY	"airpcap_key_mgmt_down_key"
#endif /* HAVE_AIRPCAP */

#endif /* __KEYS_H__ */


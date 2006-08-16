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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __KEYS_H__
#define __KEYS_H__

/** @file
 * Various keys for OBJECT_SET_DATA().
 */

#define E_DFILTER_TE_KEY				"display_filter_entry"
#define E_RFILTER_TE_KEY				"read_filter_te"
#define E_MPACKET_LIST_KEY				"menu_packet_list"
#define E_MPACKET_LIST_ROW_KEY			"menu_packet_list_row"
#define E_MPACKET_LIST_COL_KEY			"menu_packet_list_col"

#define PRINT_CMD_LB_KEY				"printer_command_label"
#define PRINT_CMD_TE_KEY				"printer_command_entry"
#define PRINT_FILE_BT_KEY				"printer_file_button"
#define PRINT_FILE_TE_KEY				"printer_file_entry"

#define PLUGINS_DFILTER_TE				"plugins_dfilter_te"

#define PM_MENU_LIST_KEY				"popup_menu_menu_list"
#define PM_PACKET_LIST_KEY				"popup_menu_packet_list"
#define PM_TREE_VIEW_KEY				"popup_menu_tree_view"
#define PM_HEXDUMP_KEY					"popup_menu_hexdump"

#ifdef HAVE_AIRPCAP
#define AIRPCAP_TOOLBAR_KEY				"airpcap_toolbar_key"
#define AIRPCAP_TOOLBAR_INTERFACE_KEY	"airpcap_toolbar_if_key"
#define AIRPCAP_TOOLBAR_LINK_TYPE_KEY	"airpcap_toolbar_lt_key" 
#define AIRPCAP_TOOLBAR_CHANNEL_KEY		"airpcap_toolbar_ch_key"
#define AIRPCAP_TOOLBAR_CRC_KEY			"airpcap_toolbar_crc_key"
#define AIRPCAP_TOOLBAR_WRONG_CRC_KEY	"airpcap_toolbar_wcrc_key"
#define AIRPCAP_TOOLBAR_ADVANCED_KEY    "airpcap_toolbar_advanced_key"
#define AIRPCAP_TOOLBAR_DECRYPTION_KEY  "airpcap_toolbar_decryption_key"

#define AIRPCAP_ADVANCED_KEY				"airpcap_advanced_key"
#define AIRPCAP_ADVANCED_INTERFACE_KEY		"airpcap_advanced_if_key"
#define AIRPCAP_ADVANCED_LINK_TYPE_KEY		"airpcap_advanced_lt_key" 
#define AIRPCAP_ADVANCED_CHANNEL_KEY		"airpcap_advanced_ch_key"
#define AIRPCAP_ADVANCED_CRC_KEY			"airpcap_advanced_crc_key"
#define AIRPCAP_ADVANCED_WRONG_CRC_KEY		"airpcap_advanced_wcrc_key"
#define AIRPCAP_ADVANCED_BLINK_KEY			"airpcap_advanced_blink_key"
#define AIRPCAP_ADVANCED_CANCEL_KEY			"airpcap_advanced_cancel_key"
#define AIRPCAP_ADVANCED_OK_KEY				"airpcap_advanced_ok_key"
#define AIRPCAP_ADVANCED_KEYLIST_KEY		"airpcap_advanced_keylist_key"
#define AIRPCAP_ADVANCED_ADD_KEY_TEXT_KEY	"airpcap_advanced_add_key_text_key"
#define AIRPCAP_ADVANCED_ADD_KEY_OK_KEY		"airpcap_advanced_add_key_ok_key"
#define AIRPCAP_ADVANCED_EDIT_KEY_TEXT_KEY	"airpcap_advanced_edit_key_text_key"
#define AIRPCAP_ADVANCED_EDIT_KEY_OK_KEY	"airpcap_advanced_edit_key_ok_key"
#define AIRPCAP_ADVANCED_EDIT_KEY_LABEL_KEY	"airpcap_advanced_edit_key_label_key"
#define AIRPCAP_ADVANCED_DECRYPTION_KEY		"airpcap_advanced_decryption_key"

#define AIRPCAP_OPTIONS_ADVANCED_KEY    "airpcap_options_advanced_key"

#define AIRPCAP_ADVANCED_FROM_KEY		"airpcap_advanced_name_key"
#endif

#endif

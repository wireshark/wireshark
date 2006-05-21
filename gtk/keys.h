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

#define E_DFILTER_TE_KEY          "display_filter_entry"
#define E_RFILTER_TE_KEY          "read_filter_te"
#define E_MPACKET_LIST_KEY	  "menu_packet_list"
#define E_MPACKET_LIST_ROW_KEY	  "menu_packet_list_row"
#define E_MPACKET_LIST_COL_KEY	  "menu_packet_list_col"

#define PRINT_CMD_LB_KEY          "printer_command_label"
#define PRINT_CMD_TE_KEY          "printer_command_entry"
#define PRINT_FILE_BT_KEY         "printer_file_button"
#define PRINT_FILE_TE_KEY         "printer_file_entry"

#define PLUGINS_DFILTER_TE        "plugins_dfilter_te"

#define PM_MENU_LIST_KEY	  "popup_menu_menu_list"
#define PM_PACKET_LIST_KEY	  "popup_menu_packet_list"
#define PM_TREE_VIEW_KEY	  "popup_menu_tree_view"
#define PM_HEXDUMP_KEY            "popup_menu_hexdump"

#endif

/* keys.h
 * Key definitions for various objects
 *
 * $Id: keys.h,v 1.10 2000/01/18 08:38:16 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

/* Keys for gtk_object_set_data */

#define E_DFILTER_TE_KEY          "display_filter_entry"
#define E_DFILTER_CM_KEY          "display_filter_combo"
#define E_DFILTER_FL_KEY          "display_filter_list"
#define E_RFILTER_TE_KEY          "read_filter_te"

#define PRINT_CMD_LB_KEY          "printer_command_label"
#define PRINT_CMD_TE_KEY          "printer_command_entry"
#define PRINT_FILE_BT_KEY         "printer_file_button"
#define PRINT_FILE_TE_KEY         "printer_file_entry"

#define PLUGINS_DFILTER_TE        "plugins_dfilter_te"

#define PM_MENU_LIST_KEY	  "popup_menu_menu_list"
#define PM_PACKET_LIST_KEY	  "popup_menu_packet_list"
#define PM_TREE_VIEW_KEY	  "popup_menu_tree_view"

#endif

/* menu.h
 * Definitions for menu routines with toolkit-independent APIs but
 * toolkit-dependent implementations.
 *
 * $Id: menu.h,v 1.7 2000/01/03 03:56:55 guy Exp $
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

#ifndef __MENU_H__
#define __MENU_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Routines to enable or disable sets of menu items. */

/* Enable or disable menu items based on whether you have a capture file
   you've finished reading. */
void set_menus_for_capture_file(gboolean);

/* Enable or disable menu items based on whether you have an unsaved
   capture file you've finished reading. */
void set_menus_for_unsaved_capture_file(gboolean);

/* Enable or disable menu items based on whether there's a capture in
   progress. */
void set_menus_for_capture_in_progress(gboolean);

/* Enable or disable menu items based on whether you have some captured
   packets. */
void set_menus_for_captured_packets(gboolean);

/* Enable or disable menu items based on whether a packet is selected. */
void set_menus_for_selected_packet(gboolean);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENU_H__ */


/* gtkglobals.h
 * GTK-related Global defines, etc.
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

#ifndef __GTKGLOBALS_H__
#define __GTKGLOBALS_H__

/** @mainpage GTK subsystem
 *
 * @section intro Introduction
 *
 * Wireshark uses GTK (the Gimp ToolKit) as its user interface toolkit.
 *
 * See Modules for a list of submodules.
 *
 */

/** @file
 *  GTK global definitions. For example a pointer to the main application window.
 */

/** Application window. */
extern GtkWidget *top_level;

/** Packet list pane. */
extern GtkWidget *packet_list;

/** Tree view (packet details) pane. */
extern GtkWidget *tree_view;

/** Byte notebook (packet bytes) pane. */
extern GtkWidget *byte_nb_ptr;

/** The filter text entry in the filter toolbar. */
extern GtkWidget   *main_display_filter_widget;

#endif

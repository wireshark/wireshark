/* gtkpacket.h
 * Definitions for GTK+ packet display structures and routines
 *
 * $Id: gtkpacket.h,v 1.2 1999/07/07 22:51:39 gram Exp $
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


#ifndef __GTKPACKET_H__
#define __GTKPACKET_H__

void       packet_hex_print(GtkText *, guint8 *, gint, gint, gint);

#define E_TREEINFO_START_KEY "tree_info_start"
#define E_TREEINFO_LEN_KEY   "tree_info_len"

void proto_tree_draw(proto_tree *protocol_tree, GtkWidget *tree_view);

#endif

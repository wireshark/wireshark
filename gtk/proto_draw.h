/* gtkpacket.h
 * Definitions for GTK+ packet display structures and routines
 *
 * $Id: proto_draw.h,v 1.2 1999/09/11 12:38:18 deniel Exp $
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
void expand_all_tree(proto_tree *protocol_tree, GtkWidget *tree_view);
void collapse_all_tree(proto_tree *protocol_tree, GtkWidget *tree_view);

#endif

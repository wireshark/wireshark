/* print.h
 * Definitions for printing packet analysis trees.
 *
 * $Id: print.h,v 1.7 1999/07/13 04:38:15 guy Exp $
 *
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
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

#ifndef __PRINT_H__
#define __PRINT_H__

/* Functions in print.h */

GtkWidget *printer_prefs_show();
void printer_prefs_ok(GtkWidget *w);
void printer_prefs_save(GtkWidget *w);
void printer_prefs_cancel(GtkWidget *w);
void proto_tree_print(GNode *protocol_tree, const u_char *pd, frame_data *fd);

#endif /* print.h */

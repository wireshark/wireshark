/* range_utils.h
 * Declarations of utilities to with range_utils.c (packet range dialog)
 *
 * $Id: range_utils.h,v 1.1 2004/04/22 21:29:34 ulfl Exp $
 *
 * Ulf Lamping <ulf.lamping@web.de>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifndef __RANGE_UTILS_H__
#define __RANGE_UTILS_H__

/* create a new range "widget" */
extern GtkWidget *range_new(packet_range_t *range
#if GTK_MAJOR_VERSION < 2
, GtkAccelGroup *accel_group
#endif
);

/* update all "dynamic" things */
extern void range_update_dynamics(gpointer data);

/* set the "Process only marked packets" toggle button as appropriate */
extern void range_set_marked_sensitive(gpointer data, gboolean marked_valid);

/* set the "displayed" button as appropriate */
extern void range_set_displayed_sensitive(gpointer data, gboolean displayed_valid);

#endif

/* toolbar.h
 * Definitions for toolbar utility routines
 * Copyright 2003, Ulf Lamping <ulf.lamping@web.de>
 *
 * $Id: toolbar.h,v 1.6 2004/01/19 00:42:12 ulfl Exp $
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

#ifndef __TOOLBAR_H__
#define __TOOLBAR_H__

#if GTK_MAJOR_VERSION >= 2
#ifdef HAVE_LIBPCAP
#define ETHEREAL_STOCK_CAPTURE_START  "Ethereal_Stock_CaptureStart"
#define ETHEREAL_STOCK_CAPTURE_FILTER  "Ethereal_Stock_CaptureFilter"
#endif
#define ETHEREAL_STOCK_DISPLAY_FILTER  "Ethereal_Stock_DisplayFilter"
#endif

void set_toolbar_for_capture_file(gboolean have_capture_file);
void set_toolbar_for_unsaved_capture_file(gboolean have_unsaved_capture_file);
void set_toolbar_for_capture_in_progress(gboolean have_capture_file);
void set_toolbar_for_captured_packets(gboolean have_captured_packets);

GtkWidget *toolbar_new(void);
void toolbar_redraw_all(void);

void set_toolbar_object_data(gchar *key, gpointer data);

#endif /* __TOOLBAR_H__ */

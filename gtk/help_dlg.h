/* help_dlg.h
 *
 * $Id: help_dlg.h,v 1.8 2004/06/04 20:05:31 ulfl Exp $
 *
 * Laurent Deniel <laurent.deniel@free.fr>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 2000 Gerald Combs
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
 *
 */

#ifndef __HELP_DLG_H__
#define __HELP_DLG_H__

/** @file
 * "Help" dialog box.
 *  @ingroup dialog_group
 */

/** User requested the "Help" dialog box by menu or toolbar.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
void help_cb(GtkWidget *widget, gpointer data);

/** Create a "Help" dialog box and start with a specific topic.
 *  Will show the first page if topic is not found.
 *
 * @param widget parent widget (unused)
 * @param topic the topic to display (a string)
 */
void help_topic_cb(GtkWidget *widget, gpointer topic);

/** Redraw all the text widgets, to use a new font. */
void help_redraw(void);

#endif

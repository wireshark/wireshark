/* h323_conversations_dlg.h
 * H323 conversations addition for ethereal
 *
 * $Id$
 *
 * Copyright 2004, Iskratel, Ltd, Kranj
 * By Miha Jemec <m.jemec@iskratel.si>
 *
 * based on rtp_stream_dlg.h
 * Copyright 2003, Alcatel Business Systems
 * By Lars Ruoff <lars.ruoff@gmx.net>
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
 * Foundation,  Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef H323_STREAM_DLG_H_INCLUDED
#define H323_STREAM_DLG_H_INCLUDED

#include <gtk/gtk.h>

/**
 * Create or reactivate the h323 streams dialog box.
 *
 * @param list pointer to list of rtp_stream_info_t*
 */
void h323conversations_dlg_show(GList *list);

/**
 * Update the contents of the dialog box clist with that of list.
 *
 * @param list pointer to list of rtp_stream_info_t*
 */
void h323conversations_dlg_update(GList *list);

#endif /* H323_STREAM_DLG_H_INCLUDED*/

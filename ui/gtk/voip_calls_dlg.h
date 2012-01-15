/* voip_calls_dlg.h
 * VoIP conversations addition for Wireshark
 *
 * $Id$
 *
 * Copyright 2004, Ericsson , Spain
 * By Francisco Alcoba <francisco.alcoba@ericsson.com>
 *
 * based on h323_conversations_dlg.h
 * Copyright 2004, Iskratel, Ltd, Kranj
 * By Miha Jemec <m.jemec@iskratel.si>
 * 
 * H323, RTP and Graph Support
 * By Alejandro Vaquero, alejandro.vaquero@verso.com
 * Copyright 2005, Verso Technologies Inc.
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
 * Foundation,  Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __VOIP_CALLS_DLG_H__
#define __VOIP_CALLS_DLG_H__

#include <gtk/gtk.h>

/**
 * Update the contents of the dialog box clist with that of list.
 *
 * @param list pointer to list of rtp_stream_info_t*
 */
void voip_calls_dlg_update(GList *list);

/* functions for tap_listeners in voip_calls.c */
void voip_calls_dlg_draw(void *ptr);
void voip_calls_dlg_reset(void *ptr);

#endif /* __VOIP_CALLS_DLG_H__ */

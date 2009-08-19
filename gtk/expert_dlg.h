/* expert_dlg.h
 * Extracted from:
 * expert_comp_table   2005 Greg Morris
 * Portions copied from service_response_time_table.h by Ronnie Sahlberg 
 * Helper routines to expert statistics
 * tap.
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

#ifndef __EXPERT_DLG_H__
#define __EXPERT_DLG_H__
#include <gtk/gtk.h>

typedef struct expert_tapdata_s {
	GtkWidget	*win;
	GtkWidget	*scrolled_window;
	GtkCList	*table;
	GtkWidget	*label;
	guint32		disp_events;
	guint32		chat_events;
	guint32		note_events;
	guint32		warn_events;
	guint32		error_events;
	int		severity_report_level;

	GArray		*ei_array;	/* expert info items */
	guint		first;
	guint		last;
	GStringChunk*	text;		/* summary text */
} expert_tapdata_t;

extern expert_tapdata_t * expert_dlg_new_table(void);
extern void expert_dlg_init_table(expert_tapdata_t * etd, GtkWidget *vbox);
extern void expert_dlg_reset(void *tapdata);
extern int expert_dlg_packet(void *tapdata, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *pointer);
extern void expert_dlg_draw(void *data);
extern void expert_dlg_destroy_cb(GtkWindow *win _U_, gpointer data);

#endif /* __EXPERT_DLG_H__ */


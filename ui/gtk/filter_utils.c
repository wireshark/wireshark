/* filter_utils.c
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gtk/gtk.h>
#include <string.h>

#include "ui/gtk/main.h"
#include "ui/gtk/gtkglobals.h"
#include "ui/gtk/find_dlg.h"
#include "ui/gtk/color_dlg.h"
#include "ui/gtk/filter_utils.h"

#include "ui/gtk/old-gtk-compat.h"

void
apply_selected_filter (guint callback_action, char *filter)
{
 	int action, type;
	char *str = NULL;
	const char *current_filter;

	action = FILTER_ACTION(callback_action);
	type = FILTER_ACTYPE(callback_action);

	current_filter = gtk_entry_get_text(GTK_ENTRY(main_display_filter_widget));

	switch(type){
	case ACTYPE_SELECTED:
		str = g_strdup_printf("%s", filter);
		break;
	case ACTYPE_NOT_SELECTED:
		str = g_strdup_printf("!(%s)", filter);
		break;
	case ACTYPE_AND_SELECTED:
		if ((!current_filter) || (0 == strlen(current_filter)))
			str = g_strdup_printf("%s", filter);
		else
			str = g_strdup_printf("(%s) && (%s)", current_filter, filter);
		break;
	case ACTYPE_OR_SELECTED:
		if ((!current_filter) || (0 == strlen(current_filter)))
			str = g_strdup_printf("%s", filter);
		else
			str = g_strdup_printf("(%s) || (%s)", current_filter, filter);
		break;
	case ACTYPE_AND_NOT_SELECTED:
		if ((!current_filter) || (0 == strlen(current_filter)))
			str = g_strdup_printf("!(%s)", filter);
		else
			str = g_strdup_printf("(%s) && !(%s)", current_filter, filter);
		break;
	case ACTYPE_OR_NOT_SELECTED:
		if ((!current_filter) || (0 == strlen(current_filter)))
			str = g_strdup_printf("!(%s)", filter);
		else
			str = g_strdup_printf("(%s) || !(%s)", current_filter, filter);
		break;
	}

	switch(action){
	case ACTION_MATCH:
		gtk_entry_set_text(GTK_ENTRY(main_display_filter_widget), str);
		main_filter_packets(&cfile, str, FALSE);
		gdk_window_raise(gtk_widget_get_window(top_level));
		break;
	case ACTION_PREPARE:
		gtk_entry_set_text(GTK_ENTRY(main_display_filter_widget), str);
		break;
	case ACTION_FIND_FRAME:
		find_frame_with_filter(str);
		break;
	case ACTION_FIND_NEXT:
		cf_find_packet_dfilter_string(&cfile, str, SD_FORWARD);
		break;
	case ACTION_FIND_PREVIOUS:
		cf_find_packet_dfilter_string(&cfile, str, SD_BACKWARD);
		break;
	case ACTION_COLORIZE:
		color_display_with_filter(str);
		break;
	}
	g_free (str);
}

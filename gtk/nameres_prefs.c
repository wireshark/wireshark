/* nameres_prefs.c
 * Dialog box for name resolution preferences
 *
 * $Id: nameres_prefs.c,v 1.3 2002/01/21 07:37:41 guy Exp $
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <errno.h>
#include <gtk/gtk.h>

#include "globals.h"
#include "nameres_prefs.h"
#include "gtkglobals.h"
#include <epan/resolv.h>
#include "prefs.h"
#include "prefs_dlg.h"
#include "ui_util.h"
#include "main.h"

#define M_RESOLVE_KEY	"m_resolve"
#define N_RESOLVE_KEY	"n_resolve"
#define T_RESOLVE_KEY	"t_resolve"

#define RESOLV_TABLE_ROWS 3
GtkWidget*
nameres_prefs_show(void)
{
	GtkWidget	*main_tb, *main_vb;
	GtkWidget	*m_resolv_cb, *n_resolv_cb, *t_resolv_cb;

	/*
	 * XXX - it would be nice if the current setting of the resolver
	 * flags could be different from the preference flags, so that
	 * the preference flags would represent what the user *typically*
	 * wants, but they could override them for particular captures
	 * without a subsequent editing of the preferences recording the
	 * temporary settings as permanent preferences.
	 */
	prefs.name_resolve = g_resolv_flags;

	/* Main vertical box */
	main_vb = gtk_vbox_new(FALSE, 7);
	gtk_container_border_width(GTK_CONTAINER(main_vb), 5);

	/* Main table */
	main_tb = gtk_table_new(RESOLV_TABLE_ROWS, 3, FALSE);
	gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
	gtk_table_set_row_spacings(GTK_TABLE(main_tb), 10);
	gtk_table_set_col_spacings(GTK_TABLE(main_tb), 15);
	gtk_widget_show(main_tb);

	/* Resolve MAC addresses */
	m_resolv_cb = create_preference_check_button(main_tb, 0,
	    "Enable MAC name resolution:", NULL,
	    prefs.name_resolve & RESOLV_MAC);
	gtk_object_set_data(GTK_OBJECT(main_vb), M_RESOLVE_KEY, m_resolv_cb);

	/* Resolve network addresses */
	n_resolv_cb = create_preference_check_button(main_tb, 1,
	    "Enable network name resolution:", NULL,
	    prefs.name_resolve & RESOLV_NETWORK);
	gtk_object_set_data(GTK_OBJECT(main_vb), N_RESOLVE_KEY, n_resolv_cb);

	/* Resolve transport addresses */
	t_resolv_cb = create_preference_check_button(main_tb, 2,
	    "Enable transport name resolution:", NULL,
	    prefs.name_resolve & RESOLV_TRANSPORT);
	gtk_object_set_data(GTK_OBJECT(main_vb), T_RESOLVE_KEY, t_resolv_cb);

	/* Show 'em what we got */
	gtk_widget_show_all(main_vb);

	return(main_vb);
}

void
nameres_prefs_fetch(GtkWidget *w)
{
	GtkWidget *m_resolv_cb, *n_resolv_cb, *t_resolv_cb;

	m_resolv_cb = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(w),
	    M_RESOLVE_KEY);
	n_resolv_cb = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(w),
	    N_RESOLVE_KEY);
	t_resolv_cb = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(w),
	    T_RESOLVE_KEY);

	prefs.name_resolve = RESOLV_NONE;
	prefs.name_resolve |= (GTK_TOGGLE_BUTTON (m_resolv_cb)->active ? RESOLV_MAC : RESOLV_NONE);
	prefs.name_resolve |= (GTK_TOGGLE_BUTTON (n_resolv_cb)->active ? RESOLV_NETWORK : RESOLV_NONE);
	prefs.name_resolve |= (GTK_TOGGLE_BUTTON (t_resolv_cb)->active ? RESOLV_TRANSPORT : RESOLV_NONE);
}

void
nameres_prefs_apply(GtkWidget *w)
{
	/*
	 * XXX - force a regeneration of the protocol list if this has
	 * changed?
	 */
	g_resolv_flags = prefs.name_resolve;
}

void
nameres_prefs_destroy(GtkWidget *w)
{
}

/* nameres_prefs.c
 * Dialog box for name resolution preferences
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

#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include <epan/oids.h>

#include "gtk/prefs_nameres.h"
#include "gtk/gtkglobals.h"
#include "gtk/prefs_dlg.h"
#include "gtk/gui_utils.h"
#include "gtk/main.h"
#include "gtk/menus.h"


#define M_RESOLVE_KEY	"m_resolve"
#define N_RESOLVE_KEY	"n_resolve"
#define T_RESOLVE_KEY	"t_resolve"

#if defined(HAVE_C_ARES) || defined(HAVE_GNU_ADNS)
# define C_RESOLVE_KEY	"c_resolve"
# define RESOLVE_CONCURRENCY_KEY "resolve_concurrency"
#endif /* HAVE_C_ARES || HAVE_GNU_ADNS */

#define BASE_TABLE_ROWS 3

#if defined(HAVE_C_ARES) || defined(HAVE_GNU_ADNS)
# define ASYNC_TABLE_ROWS 2
#else
# define ASYNC_TABLE_ROWS 0
#endif

#ifdef HAVE_LIBSMI
# define SUPPRESS_SMI_ERRORS_KEY	"suppress_smi_errors"
# define LOAD_SMI_MODULES_KEY	"load_smi_modules"
# define SMI_TABLE_ROWS 2
#else
# define SMI_TABLE_ROWS 0
#endif

#ifdef HAVE_GEOIP
# define GEOIP_TABLE_ROWS 1
#else
# define GEOIP_TABLE_ROWS 0
#endif

#define RESOLV_TABLE_ROWS (\
	BASE_TABLE_ROWS + \
	ASYNC_TABLE_ROWS + \
	SMI_TABLE_ROWS + \
	GEOIP_TABLE_ROWS \
	)

GtkWidget*
nameres_prefs_show(void)
{
	guint		table_row;
	GtkWidget	*main_tb, *main_vb;
	GtkWidget	*m_resolv_cb, *n_resolv_cb, *t_resolv_cb;
#if defined(HAVE_C_ARES) || defined(HAVE_GNU_ADNS)
	GtkWidget	*c_resolv_cb;
	GtkWidget	*resolv_concurrency_te;
	char		concur_str[10+1];
#endif /* HAVE_C_ARES || HAVE_GNU_ADNS */
#ifdef HAVE_LIBSMI
	GtkWidget	*load_smi_modules_cb, *suppress_smi_errors_cb;
	uat_t *smi_paths_uat;
	uat_t *smi_modules_uat;
#endif
#ifdef HAVE_GEOIP
	uat_t		*geoip_db_paths_uat;
#endif
	/*
	 * XXX - it would be nice if the current setting of the resolver
	 * flags could be different from the preference flags, so that
	 * the preference flags would represent what the user *typically*
	 * wants, but they could override them for particular captures
	 * without a subsequent editing of the preferences recording the
	 * temporary settings as permanent preferences.
	 */
	prefs.name_resolve = gbl_resolv_flags;

	/* Main vertical box */
	main_vb = gtk_vbox_new(FALSE, 7);
	gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);

	/* Main table */
	main_tb = gtk_table_new(RESOLV_TABLE_ROWS, 3, FALSE);
	gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
	gtk_table_set_row_spacings(GTK_TABLE(main_tb), 10);
	gtk_table_set_col_spacings(GTK_TABLE(main_tb), 15);
	gtk_widget_show(main_tb);

	/* Resolve MAC addresses */
	table_row = 0;
	m_resolv_cb = create_preference_check_button(main_tb, table_row,
	    "Enable MAC name resolution:", "e.g. Ethernet address to manufacturer name",
	    prefs.name_resolve & RESOLV_MAC);
	g_object_set_data(G_OBJECT(main_vb), M_RESOLVE_KEY, m_resolv_cb);

	/* Resolve network addresses */
	table_row++;
	n_resolv_cb = create_preference_check_button(main_tb, table_row,
	    "Enable network name resolution:", "e.g. IP address to DNS name (hostname)",
	    prefs.name_resolve & RESOLV_NETWORK);
	g_object_set_data(G_OBJECT(main_vb), N_RESOLVE_KEY, n_resolv_cb);

	/* Resolve transport addresses */
	table_row++;
	t_resolv_cb = create_preference_check_button(main_tb, table_row,
	    "Enable transport name resolution:", "e.g. TCP/UDP port to service name",
	    prefs.name_resolve & RESOLV_TRANSPORT);
	g_object_set_data(G_OBJECT(main_vb), T_RESOLVE_KEY, t_resolv_cb);

#if defined(HAVE_C_ARES) || defined(HAVE_GNU_ADNS)
	/* Enable concurrent (asynchronous) DNS lookups */
	table_row++;
	c_resolv_cb = create_preference_check_button(main_tb, table_row,
	    "Enable concurrent DNS name resolution:", "be sure to enable network name resolution",
	    prefs.name_resolve & RESOLV_CONCURRENT);
	g_object_set_data(G_OBJECT(main_vb), C_RESOLVE_KEY, c_resolv_cb);

	/* Max concurrent requests */
	table_row++;
	g_snprintf(concur_str, sizeof(concur_str), "%d", prefs.name_resolve_concurrency);
	resolv_concurrency_te = create_preference_entry(main_tb, table_row,
	    "Maximum concurrent requests:", "maximum parallel running DNS requests", concur_str);
	g_object_set_data(G_OBJECT(main_vb), RESOLVE_CONCURRENCY_KEY, resolv_concurrency_te);

#else /* HAVE_C_ARES || HAVE_GNU_ADNS */
	table_row++;
	create_preference_static_text(main_tb, table_row,
	    "Enable concurrent DNS name resolution: N/A",
	    "Support for this feature was not compiled into this version of Wireshark");
#endif /* HAVE_C_ARES || HAVE_GNU_ADNS */
#ifdef HAVE_LIBSMI
	/* Enable OID resolution */
	table_row++;
	load_smi_modules_cb = create_preference_check_button(main_tb, table_row,
		"Enable OID resolution:", "You must restart Wireshark for this change to"
		" take effect. [If True the 'SMI paths' and 'SMI modules' preferences will be shown].",
                prefs.load_smi_modules);
	g_object_set_data(G_OBJECT(main_vb), LOAD_SMI_MODULES_KEY, load_smi_modules_cb);

	/* Suppress smi errors */
	table_row++;
	suppress_smi_errors_cb = create_preference_check_button(main_tb, table_row,
	    "Suppress SMI errors:", "Some errors can be ignored. If unsure, set to false.",
	    prefs.suppress_smi_errors);
	g_object_set_data(G_OBJECT(main_vb), SUPPRESS_SMI_ERRORS_KEY, suppress_smi_errors_cb);

	/* SMI paths UAT */
	smi_paths_uat = uat_get_table_by_name("SMI Paths");
	if (smi_paths_uat) {
		table_row++;
		create_preference_uat(main_tb, table_row,
		    "SMI (MIB and PIB) paths",
                    "Search paths for SMI (MIB and PIB) modules. You must\n"
                    "restart Wireshark for these changes to take effect.",
                    smi_paths_uat);
	}

	/* SMI modules UAT */
	smi_modules_uat = uat_get_table_by_name("SMI Modules");
	if (smi_modules_uat) {
		table_row++;
		create_preference_uat(main_tb, table_row,
		    "SMI (MIB and PIB) modules",
                    "List of enabled SMI (MIB and PIB) modules. You must\n"
                    "restart Wireshark for these changes to take effect.",
                    smi_modules_uat);
	}
#else /* HAVE_LIBSMI */
	table_row++;
	create_preference_static_text(main_tb, table_row,
	    "SMI (MIB and PIB) modules and paths: N/A",
	    "Support for this feature was not compiled into this version of Wireshark");
	table_row++;
	create_preference_static_text(main_tb, table_row,
	    "Enable OID resolution: N/A",
	    "Support for this feature was not compiled into this version of Wireshark");
	table_row++;
	create_preference_static_text(main_tb, table_row,
	    "Suppress SMI errors: N/A",
	    "Support for this feature was not compiled into this version of Wireshark");
#endif /* HAVE_LIBSMI */

#ifdef HAVE_GEOIP
	/* GeoIP databases http://www.maxmind.com/app/api */
	geoip_db_paths_uat = uat_get_table_by_name("GeoIP Database Paths");

	if (geoip_db_paths_uat) {
		table_row++;
		create_preference_uat(main_tb, table_row,
		    "GeoIP database directories",
		    "Search paths for GeoIP address mapping databases.\n"
		    "Wireshark will look in each directory for files beginning\n"
		    "with \"Geo\" and ending with \".dat\".\n"
		    "You must restart Wireshark for these changes to take\n"
		    "effect.",
                    geoip_db_paths_uat);
	}
#else /* HAVE_GEOIP */
	table_row++;
	create_preference_static_text(main_tb, table_row,
	    "GeoIP database search paths: N/A",
	    "Support for this feature was not compiled into this version of Wireshark");
#endif /* HAVE_GEOIP */

	/* Show 'em what we got */
	gtk_widget_show_all(main_vb);

	return(main_vb);
}

void
nameres_prefs_fetch(GtkWidget *w)
{
	GtkWidget *m_resolv_cb, *n_resolv_cb, *t_resolv_cb;
#if defined(HAVE_C_ARES) || defined(HAVE_GNU_ADNS)
	GtkWidget *c_resolv_cb, *resolv_concurrency_te;
#endif /* HAVE_C_ARES || HAVE_GNU_ADNS */
#ifdef HAVE_LIBSMI
	GtkWidget	*load_smi_modules_cb, *suppress_smi_errors_cb;
	gboolean	load_smi_modules_orig;
#endif

	m_resolv_cb = (GtkWidget *)g_object_get_data(G_OBJECT(w), M_RESOLVE_KEY);
	n_resolv_cb = (GtkWidget *)g_object_get_data(G_OBJECT(w), N_RESOLVE_KEY);
	t_resolv_cb = (GtkWidget *)g_object_get_data(G_OBJECT(w), T_RESOLVE_KEY);
#if defined(HAVE_C_ARES) || defined(HAVE_GNU_ADNS)
	c_resolv_cb = (GtkWidget *)g_object_get_data(G_OBJECT(w), C_RESOLVE_KEY);

	resolv_concurrency_te = (GtkWidget *)g_object_get_data(G_OBJECT(w), RESOLVE_CONCURRENCY_KEY);
#endif /* HAVE_C_ARES || HAVE_GNU_ADNS */

	prefs.name_resolve = RESOLV_NONE;
	prefs.name_resolve |= (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (m_resolv_cb)) ? RESOLV_MAC : RESOLV_NONE);
	prefs.name_resolve |= (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (n_resolv_cb)) ? RESOLV_NETWORK : RESOLV_NONE);
	prefs.name_resolve |= (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (t_resolv_cb)) ? RESOLV_TRANSPORT : RESOLV_NONE);
#if defined(HAVE_C_ARES) || defined(HAVE_GNU_ADNS)
	prefs.name_resolve |= (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (c_resolv_cb)) ? RESOLV_CONCURRENT : RESOLV_NONE);

	prefs.name_resolve_concurrency = strtol (gtk_entry_get_text(
		GTK_ENTRY(resolv_concurrency_te)), NULL, 10);
#endif /* HAVE_C_ARES || HAVE_GNU_ADNS */
#ifdef HAVE_LIBSMI
	load_smi_modules_orig = prefs.load_smi_modules;
	load_smi_modules_cb = (GtkWidget *)g_object_get_data(G_OBJECT(w), LOAD_SMI_MODULES_KEY);
	prefs.load_smi_modules = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (load_smi_modules_cb));
	suppress_smi_errors_cb = (GtkWidget *)g_object_get_data(G_OBJECT(w), SUPPRESS_SMI_ERRORS_KEY);
	prefs.suppress_smi_errors = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (suppress_smi_errors_cb));

	/* Perform actions needed when enabling/disabling OID resolution */
	if (load_smi_modules_orig && !prefs.load_smi_modules) {
		prefs.load_smi_modules = TRUE; /* hack to make oids_cleanup() actually do something */
		oids_cleanup();
		prefs.load_smi_modules = FALSE; /* end hack */
	} else if (!load_smi_modules_orig && prefs.load_smi_modules) {
		oids_init();
	}
#endif
}

void
nameres_prefs_apply(GtkWidget *w _U_)
{
	/*
	 * XXX - force a regeneration of the protocol list if this has
	 * changed?
	 */
	gbl_resolv_flags = prefs.name_resolve;
	menu_name_resolution_changed();
}

void
nameres_prefs_destroy(GtkWidget *w _U_)
{
}

/* capture_prefs.c
 * Dialog box for capture preferences
 *
 * $Id: capture_prefs.c,v 1.3 2002/01/11 07:40:31 guy Exp $
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

#ifdef HAVE_LIBPCAP
#include <pcap.h>
#endif

#include "globals.h"
#include "capture_prefs.h"
#include "gtkglobals.h"
#include "prefs.h"
#include "prefs-int.h"
#include "ui_util.h"
#include "pcap-util.h"
#include "main.h"

#ifdef HAVE_LIBPCAP

static void create_option_check_button(GtkWidget *main_vb, const gchar *key,
    GtkWidget *main_tb, int table_position, const gchar *label_text,
    gboolean active);

#define DEVICE_KEY		"device"
#define PROM_MODE_KEY		"prom_mode"
#define CAPTURE_REAL_TIME_KEY	"capture_real_time"
#define AUTO_SCROLL_KEY		"capture_real_time"

#define CAPTURE_TABLE_ROWS 4
GtkWidget*
capture_prefs_show(void)
{
	GtkWidget	*main_tb, *main_vb;
	GtkWidget	*if_cb, *if_lb;
	GtkWidget	*promisc_cb, *sync_cb, *auto_scroll_cb;
	GList		*if_list;
	int		err;
	char		err_str[PCAP_ERRBUF_SIZE];

	/* Main vertical box */
	main_vb = gtk_vbox_new(FALSE, 7);
	gtk_container_border_width(GTK_CONTAINER(main_vb), 5);

	/* Main table */
	main_tb = gtk_table_new(CAPTURE_TABLE_ROWS, 3, FALSE);
	gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
	gtk_table_set_row_spacings(GTK_TABLE(main_tb), 10);
	gtk_table_set_col_spacings(GTK_TABLE(main_tb), 15);
	gtk_widget_show(main_tb);

	/* Default device */
	if_lb = gtk_label_new("Interface:");
	gtk_table_attach_defaults(GTK_TABLE(main_tb), if_lb, 0, 1, 0, 1);
	gtk_widget_show(if_lb);
  
	if_cb = gtk_combo_new();
	/*
	 * XXX - what if we can't get the list?
	 */
	if_list = get_interface_list(&err, err_str);
	if (if_list != NULL)
		gtk_combo_set_popdown_strings(GTK_COMBO(if_cb), if_list);
	if (prefs.capture_device)
		gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(if_cb)->entry),
		    prefs.capture_device);
	gtk_table_attach_defaults(GTK_TABLE(main_tb), if_cb, 1, 2, 0, 1);
	gtk_widget_show(if_cb);
	gtk_object_set_data(GTK_OBJECT(main_vb), DEVICE_KEY, if_cb);
  
	free_interface_list(if_list);

	/* Promiscuous mode */
	create_option_check_button(main_vb, PROM_MODE_KEY, main_tb, 1,
	    "Capture packets in promiscuous mode:", prefs.capture_prom_mode);

	/* Real-time capture */
	create_option_check_button(main_vb, CAPTURE_REAL_TIME_KEY, main_tb, 2,
	    "Update list of packets in real time", prefs.capture_real_time);

	/* Auto-scroll real-time capture */
	create_option_check_button(main_vb, CAPTURE_REAL_TIME_KEY, main_tb, 3,
	    "Automatic scrolling in live capture", prefs.capture_auto_scroll);

	/* Show 'em what we got */
	gtk_widget_show_all(main_vb);

	return(main_vb);
}

static void
create_option_check_button(GtkWidget *main_vb, const gchar *key,
    GtkWidget *main_tb, int table_position, const gchar *label_text,
    gboolean active)
{
	GtkWidget *hbox, *check_box;

	hbox = gtk_hbox_new(FALSE, 0);
	gtk_table_attach_defaults(GTK_TABLE(main_tb), hbox, 1, 3,
	    table_position, table_position + 1);

	check_box = gtk_check_button_new_with_label(label_text);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(check_box), active);

	gtk_box_pack_start( GTK_BOX(hbox), check_box, FALSE, FALSE, 0 );
	gtk_object_set_data(GTK_OBJECT(main_vb), key, check_box);
}

void
capture_prefs_fetch(GtkWidget *w)
{
	GtkWidget *if_cb, *promisc_cb, *sync_cb, *auto_scroll_cb;
	gchar	*if_text;
	gchar	*if_name;

	if_cb = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(w), DEVICE_KEY);
	promisc_cb = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(w),
	    PROM_MODE_KEY);
	sync_cb = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(w),
	    CAPTURE_REAL_TIME_KEY);
	auto_scroll_cb = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(w),
	    AUTO_SCROLL_KEY);

	if (prefs.capture_device != NULL) {
		g_free(prefs.capture_device);
		prefs.capture_device = NULL;
	}
	if_text =
	    g_strdup(gtk_entry_get_text(GTK_ENTRY(GTK_COMBO(if_cb)->entry)));
	if_name = strtok(if_text, " \t");
	if (if_name != NULL)
		prefs.capture_device = g_strdup(if_name);
	g_free(if_text);

	prefs.capture_prom_mode = GTK_TOGGLE_BUTTON (promisc_cb)->active;

	prefs.capture_real_time = GTK_TOGGLE_BUTTON (sync_cb)->active;

	prefs.capture_auto_scroll = GTK_TOGGLE_BUTTON (auto_scroll_cb)->active;
}

void
capture_prefs_apply(GtkWidget *w)
{
}

void
capture_prefs_destroy(GtkWidget *w)
{
}

#else /* HAVE_LIBPCAP */

/*
 * Stub routines.
 */

void
capture_prefs_apply(GtkWidget *w)
{
}

void
capture_prefs_destroy(GtkWidget *w)
{
}

void
capture_prefs_fetch(GtkWidget *w)
{
}

#endif /* HAVE_LIBPCAP */

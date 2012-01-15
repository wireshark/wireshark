/* diameter_stat.c
 *  Diameter Service Response Time Statistics
 * (c) 2008 Abhik Sarkar
 *
 * Based almost completely on gtp_stat by Kari Tiirikainen
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
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>

#include <gtk/gtk.h>

#include <epan/packet_info.h>
#include <epan/epan.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-diameter.h>

#include "../timestats.h"
#include "../simple_dialog.h"
#include "../file.h"
#include "../stat_menu.h"

#include "ui/gtk/gui_utils.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/service_response_time_table.h"
#include "ui/gtk/tap_param_dlg.h"
#include "ui/gtk/gtkglobals.h"
#include "ui/gtk/main.h"

#include "ui/gtk/old-gtk-compat.h"

/* used to keep track of the statistics for an entire program interface */
typedef struct _diameterstat_t {
	GtkWidget *win;
	srt_stat_table diameter_srt_table;
} diameterstat_t;

static GHashTable* cmd_str_hash;

static void
diameterstat_set_title(diameterstat_t *diameter)
{
	char		*title;

	title = g_strdup_printf("Diameter Service Response Time statistics: %s",
	    cf_get_display_name(&cfile));
	gtk_window_set_title(GTK_WINDOW(diameter->win), title);
	g_free(title);
}

static void
diameterstat_reset(void *pdiameter)
{
	diameterstat_t *diameter=(diameterstat_t *)pdiameter;

	reset_srt_table_data(&diameter->diameter_srt_table);
	diameterstat_set_title(diameter);
}


static int
diameterstat_packet(void *pdiameter, packet_info *pinfo, epan_dissect_t *edt _U_, const void *pdi)
{
	const diameter_req_ans_pair_t *diameter=pdi;
	diameterstat_t *fs=(diameterstat_t *)pdiameter;
	int* idx = NULL;

	/* Process only answers where corresponding request is found.
	 * Unpaired daimeter messages are currently not supported by statistics.
	 * Return 0, since redraw is not needed. */
	if(!diameter || diameter->processing_request || !diameter->req_frame)
		return 0;

	idx = (int*) g_hash_table_lookup(cmd_str_hash, diameter->cmd_str);
	if (idx == NULL) {
		idx = g_malloc(sizeof(int));
		*idx = (int) g_hash_table_size(cmd_str_hash);
		g_hash_table_insert(cmd_str_hash, (gchar*) diameter->cmd_str, idx);
		init_srt_table_row(&fs->diameter_srt_table, *idx,  (const char*) diameter->cmd_str);
	}

	add_srt_table_data(&fs->diameter_srt_table, *idx, &diameter->req_time, pinfo);

	return 1;
}



static void
diameterstat_draw(void *pdiameter)
{
	diameterstat_t *diameter=(diameterstat_t *)pdiameter;

	draw_srt_table_data(&diameter->diameter_srt_table);
}


static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	diameterstat_t *diameter=(diameterstat_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(diameter);
	unprotect_thread_critical_region();

	free_srt_table_data(&diameter->diameter_srt_table);
	g_free(diameter);
	g_hash_table_destroy(cmd_str_hash);
}


static void
gtk_diameterstat_init(const char *optarg, void *userdata _U_)
{
	diameterstat_t *diameter;
	const char *filter=NULL;
	GtkWidget *label;
	char *filter_string;
	GString *error_string;
	GtkWidget *vbox;
	GtkWidget *bbox;
	GtkWidget *close_bt;
	int* idx;

	if(!strncmp(optarg,"diameter,",9)){
		filter=optarg+9;
	} else {
		filter="diameter"; /*NULL doesn't work here like in LDAP. Too little time/lazy to find out why ?*/
	}

	diameter=g_malloc(sizeof(diameterstat_t));
	idx = g_malloc(sizeof(int));
	*idx = 0;
	cmd_str_hash = g_hash_table_new(g_str_hash,g_str_equal);
	g_hash_table_insert(cmd_str_hash, (gchar *)"Unknown", idx);

	diameter->win = dlg_window_new("diameter-stat");  /* transient_for top_level */
	gtk_window_set_destroy_with_parent (GTK_WINDOW(diameter->win), TRUE);
	gtk_window_set_default_size(GTK_WINDOW(diameter->win), 550, 400);
	diameterstat_set_title(diameter);

	vbox=gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(diameter->win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

	label=gtk_label_new("Diameter Service Response Time statistics");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

	filter_string = g_strdup_printf("Filter: %s", filter ? filter : "");
	label=gtk_label_new(filter_string);
	g_free(filter_string);
	gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

	label=gtk_label_new("Diameter Requests");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

	/* We must display TOP LEVEL Widget before calling init_srt_table() */
	gtk_widget_show_all(diameter->win);

	/** @todo the filter to use in stead of NULL is "diameter.cmd.code"
	 * to enable the filter popup in the service response time dalouge
	 * Note to make it work the command code must be stored rather than the
	 * index.
	 */
	init_srt_table(&diameter->diameter_srt_table, 1, vbox, NULL);
	init_srt_table_row(&diameter->diameter_srt_table, 0, "Unknown");

	error_string=register_tap_listener("diameter", diameter, filter, 0, diameterstat_reset, diameterstat_packet, diameterstat_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
		g_string_free(error_string, TRUE);
		g_free(diameter);
		return;
	}

	/* Button row. */
	bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
	gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

	close_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
	window_set_cancel_button(diameter->win, close_bt, window_cancel_button_cb);

	g_signal_connect(diameter->win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(diameter->win, "destroy", G_CALLBACK(win_destroy_cb), diameter);

	gtk_widget_show_all(diameter->win);
	window_present(diameter->win);

	cf_retap_packets(&cfile);
	gdk_window_raise(gtk_widget_get_window(diameter->win));
}

static tap_param diameter_stat_params[] = {
	{ PARAM_FILTER, "Filter", NULL }
};

static tap_param_dlg diameter_stat_dlg = {
	"Diameter Service Response Time Statistics",
	"diameter",
	gtk_diameterstat_init,
	-1,
	G_N_ELEMENTS(diameter_stat_params),
	diameter_stat_params
};

void
register_tap_listener_gtkdiameterstat(void)
{
	register_dfilter_stat(&diameter_stat_dlg, "Diameter",
	    REGISTER_STAT_GROUP_RESPONSE_TIME);
}

void diameter_srt_cb(GtkAction *action, gpointer user_data _U_)
{
	tap_param_dlg_cb(action, &diameter_stat_dlg);
}


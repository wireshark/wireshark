/* megaco_stat.c
 * megaco-statistics for Wireshark
 * Copyright 2003 Lars Roland
 * Copyright 2008, Ericsson AB
 * By Balint Reczey <balint.reczey@ericsson.com>
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
#include <epan/value_string.h>
#include <epan/tap.h>
#include "epan/gcp.h"
#include <epan/prefs-int.h>

#include "../timestats.h"
#include "../simple_dialog.h"
#include "../file.h"
#include "../stat_menu.h"

#include "gtk/gui_stat_util.h"
#include "gtk/dlg_utils.h"
#include "gtk/tap_param_dlg.h"
#include "gtk/gui_utils.h"
#include "gtk/main.h"

#include "tap-megaco-common.h"



static void
megacostat_reset(void *pms)
{
	megacostat_t *ms=(megacostat_t *)pms;
	int i;

	for(i=0;i<NUM_TIMESTATS;i++) {
		ms->rtd[i].num=0;
		ms->rtd[i].min_num=0;
		ms->rtd[i].max_num=0;
		ms->rtd[i].min.secs=0;
        	ms->rtd[i].min.nsecs=0;
        	ms->rtd[i].max.secs=0;
        	ms->rtd[i].max.nsecs=0;
        	ms->rtd[i].tot.secs=0;
        	ms->rtd[i].tot.nsecs=0;
	}

	ms->open_req_num=0;
	ms->disc_rsp_num=0;
	ms->req_dup_num=0;
	ms->rsp_dup_num=0;
}

static void
megacostat_draw(void *pms)
{
	megacostat_t *ms=(megacostat_t *)pms;
	int i;
	char str[3][256];
	GtkListStore *store;
	GtkTreeIter iter;

	/* clear list before printing */
  	store = GTK_LIST_STORE(gtk_tree_view_get_model(ms->table));
  	gtk_list_store_clear(store);

	for(i=0;i<NUM_TIMESTATS;i++) {
		/* nothing seen, nothing to do */
		if(ms->rtd[i].num==0){
			continue;
		}

		g_snprintf(str[0], sizeof(char[256]), "%8.2f msec", nstime_to_msec(&(ms->rtd[i].min)));
		g_snprintf(str[1], sizeof(char[256]), "%8.2f msec", nstime_to_msec(&(ms->rtd[i].max)));
		g_snprintf(str[2], sizeof(char[256]), "%8.2f msec", get_average(&(ms->rtd[i].tot), ms->rtd[i].num));
		gtk_list_store_append(store, &iter);
		gtk_list_store_set(store, &iter,
			0, val_to_str(i,megaco_message_type,"Other"),
			1, ms->rtd[i].num,
			2, str[0],
			3, str[1],
			4, str[2],
			5, ms->rtd[i].min_num,
			6, ms->rtd[i].max_num,
			-1);
	}
}

static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	megacostat_t *ms=(megacostat_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(ms);
	unprotect_thread_critical_region();

	if(ms->filter){
		g_free(ms->filter);
		ms->filter=NULL;
	}
	g_free(ms);
}

static const stat_column titles[]={
	{G_TYPE_STRING, LEFT, "Type" },
	{G_TYPE_UINT, RIGHT,   "Messages" },
	{G_TYPE_STRING, RIGHT, "Min SRT" },
	{G_TYPE_STRING, RIGHT, "Max SRT" },
	{G_TYPE_STRING, RIGHT, "Avg SRT" },
	{G_TYPE_UINT, RIGHT,  "Min in Frame" },
	{G_TYPE_UINT, RIGHT,  "Max in Frame" }
};

static void
gtk_megacostat_init(const char *optarg, void *userdata _U_)
{
	megacostat_t *ms;
	GString *error_string;
	GtkWidget *bt_close;
	GtkWidget *bbox;
	pref_t *megaco_ctx_track,*h248_ctx_track;

	megaco_ctx_track = prefs_find_preference(prefs_find_module("megaco"),"ctx_info");
	h248_ctx_track = prefs_find_preference(prefs_find_module("h248"),"ctx_info");

	if (!megaco_ctx_track || !h248_ctx_track) {
		/* No such preferences */
		return;
	}

	if (!*megaco_ctx_track->varp.boolp || !*h248_ctx_track->varp.boolp) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", "Track Context option at Protocols -> MEGACO and Protocols -> H248 preferences has to be set to true to enable measurement of service reponse times.");
		return;
	}

	ms=g_malloc(sizeof(megacostat_t));

	if(strncmp(optarg,"megaco,srt,",11) == 0){
		ms->filter=g_strdup(optarg+11);
	} else {
		ms->filter=NULL;
	}

	megacostat_reset(ms);

	ms->win = dlg_window_new("MEGACO SRT");  /* transient_for top_level */
	gtk_window_set_destroy_with_parent (GTK_WINDOW(ms->win), TRUE);

	gtk_window_set_default_size(GTK_WINDOW(ms->win), 550, 150);

	ms->vbox=gtk_vbox_new(FALSE, 3);

	init_main_stat_window(ms->win, ms->vbox, "MEGACO Service Response Time (SRT) Statistics", ms->filter);

	/* init a scrolled window*/
	ms->scrolled_window = scrolled_window_new(NULL, NULL);

	ms->table = create_stat_table(ms->scrolled_window, ms->vbox, 7, titles);

	error_string=register_tap_listener("megaco", ms, ms->filter, 0, megacostat_reset, megacostat_packet, megacostat_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
		g_string_free(error_string, TRUE);
		g_free(ms->filter);
		g_free(ms);
		return;
	}

	/* Button row. */
	bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
	gtk_box_pack_start(GTK_BOX(ms->vbox), bbox, FALSE, FALSE, 0);

	bt_close = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
	window_set_cancel_button(ms->win, bt_close, window_cancel_button_cb);

	g_signal_connect(ms->win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(ms->win, "destroy", G_CALLBACK(win_destroy_cb), ms);

	gtk_widget_show_all(ms->win);
	window_present(ms->win);

	cf_retap_packets(&cfile);
	gdk_window_raise(ms->win->window);
}

static tap_param megaco_srt_params[] = {
	{ PARAM_FILTER, "Filter", NULL }
};

static tap_param_dlg megaco_srt_dlg = {
	"MEGACO Service Response Time (SRT) Statistics",
	"megaco,srt",
	gtk_megacostat_init,
	-1,
	G_N_ELEMENTS(megaco_srt_params),
	megaco_srt_params
};

void
register_tap_listener_gtkmegacostat(void)
{
	/* We don't register this tap, if we don't have the megaco plugin loaded.*/
	if (find_tap_id("megaco")) {
		register_dfilter_stat(&megaco_srt_dlg, "MEGACO",
		    REGISTER_STAT_GROUP_RESPONSE_TIME);
	}
}

/* response_time_delay_table.c
 *
 * Based on service_response_time_table.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <gtk/gtk.h>

#include "epan/packet_info.h"
#include "epan/proto.h"
#include <epan/stat_tap_ui.h>

#include "ui/simple_dialog.h"
#include <wsutil/utf8_entities.h>

#include "ui/gtk/filter_utils.h"
#include "ui/gtk/gui_stat_util.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/response_time_delay_table.h"
#include "ui/gtk/tap_param_dlg.h"
#include "ui/gtk/main.h"

#include "ui/gtk/old-gtk-compat.h"

enum
{
	TYPE_COLUMN,
	MESSAGES_COLUMN,
	MIN_SRT_COLUMN,
	MAX_SRT_COLUMN,
	AVG_SRT_COLUMN,
	MIN_FRAME_COLUMN,
	MAX_FRAME_COLUMN,
	OPEN_REQUESTS_COLUMN,
	DISCARDED_RESPONSES_COLUMN,
	REPEATED_REQUESTS_COLUMN,
	REPEATED_RESPONSES_COLUMN
};

static const stat_column titles[]={
	{G_TYPE_STRING, TAP_ALIGN_LEFT, "Type" },
	{G_TYPE_UINT, TAP_ALIGN_RIGHT,   "Messages" },
	{G_TYPE_STRING, TAP_ALIGN_RIGHT, "Min SRT" },
	{G_TYPE_STRING, TAP_ALIGN_RIGHT, "Max SRT" },
	{G_TYPE_STRING, TAP_ALIGN_RIGHT, "Avg SRT" },
	{G_TYPE_UINT, TAP_ALIGN_RIGHT,  "Min in Frame" },
	{G_TYPE_UINT, TAP_ALIGN_RIGHT,  "Max in Frame" }
};

static const stat_column titles_more[]={
	{G_TYPE_STRING, TAP_ALIGN_LEFT, "Type" },
	{G_TYPE_UINT, TAP_ALIGN_RIGHT,   "Messages" },
	{G_TYPE_STRING, TAP_ALIGN_RIGHT, "Min SRT" },
	{G_TYPE_STRING, TAP_ALIGN_RIGHT, "Max SRT" },
	{G_TYPE_STRING, TAP_ALIGN_RIGHT, "Avg SRT" },
	{G_TYPE_UINT, TAP_ALIGN_RIGHT,  "Min in Frame" },
	{G_TYPE_UINT, TAP_ALIGN_RIGHT,  "Max in Frame" },
	{G_TYPE_UINT, TAP_ALIGN_RIGHT,   "Open Requests" },
	{G_TYPE_UINT, TAP_ALIGN_RIGHT,   "Discarded Responses" },
	{G_TYPE_STRING, TAP_ALIGN_RIGHT, "Repeated Requests" },
	{G_TYPE_STRING, TAP_ALIGN_RIGHT, "Repeated Responses"}
};

typedef struct _gtk_rtd_t {
	GtkWidget *vbox;
	GtkWidget *win;
	GtkTreeView  *table;        /**< Tree view */
	GtkWidget *scrolled_window; /**< window widget */
	GtkWidget *menu;            /**< context menu */
	GtkWidget *open_req_label;
	GtkWidget *dis_rsp_label;
	GtkWidget *repeat_req_label;
	GtkWidget *repeat_rsp_label;
} gtk_rtd_t;

typedef struct _rtd_t {
	const char *type;
	const char *filter;
	gtk_rtd_t gtk_data;
	register_rtd_t* rtd;
	rtd_data_t data;
} rtd_t;

static void
rtd_set_title(rtd_t *rr)
{
	gchar *str;

	str = g_strdup_printf("%s Service Response Time statistics", proto_get_protocol_short_name(find_protocol_by_id(get_rtd_proto_id(rr->rtd))));
	set_window_title(rr->gtk_data.win, str);
	g_free(str);
}

static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	rtd_t *rr = (rtd_t*)data;

	remove_tap_listener(&rr->data);

	free_rtd_table(&rr->data.stat_table, NULL, NULL);

	g_free(rr);
}

static void
init_gtk_rtd_table(rtd_stat_table* rtd, void* gui_data)
{
	gtk_rtd_t* gtk_data = (gtk_rtd_t*)gui_data;

	if (rtd->num_rtds == 1)
	{
		gtk_window_set_default_size(GTK_WINDOW(gtk_data->win), RTD_PREFERRED_WIDTH, 300);

		gtk_data->open_req_label = gtk_label_new("Open Requests: 0");
		gtk_box_pack_start(GTK_BOX(gtk_data->vbox), gtk_data->open_req_label, FALSE, FALSE, 0);
		gtk_widget_show(gtk_data->open_req_label);

		gtk_data->dis_rsp_label = gtk_label_new("Discarded Responses: 0");
		gtk_box_pack_start(GTK_BOX(gtk_data->vbox), gtk_data->dis_rsp_label, FALSE, FALSE, 0);
		gtk_widget_show(gtk_data->dis_rsp_label);

		gtk_data->repeat_req_label = gtk_label_new("Repeated Requests: 0");
		gtk_box_pack_start(GTK_BOX(gtk_data->vbox), gtk_data->repeat_req_label, FALSE, FALSE, 0);
		gtk_widget_show(gtk_data->repeat_req_label);

		gtk_data->repeat_rsp_label = gtk_label_new("Repeated Responses: 0");
		gtk_box_pack_start(GTK_BOX(gtk_data->vbox), gtk_data->repeat_rsp_label, FALSE, FALSE, 0);
		gtk_widget_show(gtk_data->repeat_rsp_label);

		gtk_data->table = create_stat_table(gtk_data->scrolled_window, gtk_data->vbox, 7, titles);
	}
	else
	{
		gtk_window_set_default_size(GTK_WINDOW(gtk_data->win), RTD_PREFERRED_WIDTH+100, 200);
		gtk_data->table = create_stat_table(gtk_data->scrolled_window, gtk_data->vbox, 11, titles_more);
	}
}

static void
rtd_draw(void *arg)
{
	GtkListStore *store;
	rtd_data_t* rtd_data = (rtd_data_t*)arg;
	rtd_t* rtd = (rtd_t*)rtd_data->user_data;
	rtd_timestat *ms;
	GtkTreeIter iter;
	char str[5][256];
	gchar* tmp_str;
	guint i, j;
	char label_str[256];

	/* clear list before printing */
	store = GTK_LIST_STORE(gtk_tree_view_get_model(rtd->gtk_data.table));
	gtk_list_store_clear(store);

	if (rtd_data->stat_table.num_rtds == 1)
	{
		ms = &rtd_data->stat_table.time_stats[0];

		g_snprintf(label_str, sizeof(char[256]), "Open Requests:  %u", ms->open_req_num);
		gtk_label_set_text(GTK_LABEL(rtd->gtk_data.open_req_label), label_str);
		g_snprintf(label_str, sizeof(char[256]), "Discarded Responses:  %u", ms->disc_rsp_num);
		gtk_label_set_text(GTK_LABEL(rtd->gtk_data.dis_rsp_label), label_str);
		g_snprintf(label_str, sizeof(char[256]), "Repeated Requests:  %u", ms->req_dup_num);
		gtk_label_set_text(GTK_LABEL(rtd->gtk_data.repeat_req_label), label_str);
		g_snprintf(label_str, sizeof(char[256]), "Repeated Responses:  %u", ms->rsp_dup_num);
		gtk_label_set_text(GTK_LABEL(rtd->gtk_data.repeat_rsp_label), label_str);

		for(i=0;i<ms->num_timestat;i++)
		{
			/* nothing seen, nothing to do */
			if(ms->rtd[i].num==0){
				continue;
			}

			g_snprintf(str[0], sizeof(char[256]), "%8.2f msec", nstime_to_msec(&(ms->rtd[i].min)));
			g_snprintf(str[1], sizeof(char[256]), "%8.2f msec", nstime_to_msec(&(ms->rtd[i].max)));
			g_snprintf(str[2], sizeof(char[256]), "%8.2f msec", get_average(&(ms->rtd[i].tot), ms->rtd[i].num));
			tmp_str = val_to_str_wmem(NULL, i, get_rtd_value_string(rtd->rtd), "Other (%d)");
			gtk_list_store_append(store, &iter);
			gtk_list_store_set(store, &iter,
				TYPE_COLUMN, tmp_str,
				MESSAGES_COLUMN, ms->rtd[i].num,
				MIN_SRT_COLUMN, str[0],
				MAX_SRT_COLUMN, str[1],
				AVG_SRT_COLUMN, str[2],
				MIN_FRAME_COLUMN, ms->rtd[i].min_num,
				MAX_FRAME_COLUMN, ms->rtd[i].max_num,
				-1);
			wmem_free(NULL, tmp_str);
		}
	}
	else
	{
		for (i=0; i<rtd_data->stat_table.num_rtds; i++)
		{
			for (j=0; j<rtd_data->stat_table.time_stats[i].num_timestat; j++)
			{

				/* nothing seen, nothing to do */
				if(rtd_data->stat_table.time_stats[i].rtd[j].num==0){
					continue;
				}

				g_snprintf(str[0], 256, "%8.2f msec", nstime_to_msec(&(rtd_data->stat_table.time_stats[i].rtd[j].min)));
				g_snprintf(str[1], 256, "%8.2f msec", nstime_to_msec(&(rtd_data->stat_table.time_stats[i].rtd[j].max)));
				g_snprintf(str[2], 256, "%8.2f msec", get_average(&(rtd_data->stat_table.time_stats[i].rtd[j].tot), rtd_data->stat_table.time_stats[i].rtd[j].num));
				g_snprintf(str[3], 256, "%4u (%4.2f%%)", rtd_data->stat_table.time_stats[i].req_dup_num,
								rtd_data->stat_table.time_stats[i].rtd[j].num?((double)rtd_data->stat_table.time_stats[i].req_dup_num*100)/(double)rtd_data->stat_table.time_stats[i].rtd[j].num:0);
				g_snprintf(str[4], 256, "%4u (%4.2f%%)", rtd_data->stat_table.time_stats[i].rsp_dup_num,
								rtd_data->stat_table.time_stats[i].rtd[j].num?((double)rtd_data->stat_table.time_stats[i].rsp_dup_num*100)/(double)rtd_data->stat_table.time_stats[i].rtd[j].num:0);
				tmp_str = val_to_str_wmem(NULL, i, get_rtd_value_string(rtd->rtd), "Other (%d)");
				gtk_list_store_append(store, &iter);
				gtk_list_store_set(store, &iter,
					TYPE_COLUMN, tmp_str,
					MESSAGES_COLUMN, rtd_data->stat_table.time_stats[i].rtd[j].num,
					MIN_SRT_COLUMN, str[0],
					MAX_SRT_COLUMN, str[1],
					AVG_SRT_COLUMN, str[2],
					MIN_FRAME_COLUMN, rtd_data->stat_table.time_stats[i].rtd[j].min_num,
					MAX_FRAME_COLUMN, rtd_data->stat_table.time_stats[i].rtd[j].max_num,
					OPEN_REQUESTS_COLUMN, rtd_data->stat_table.time_stats[i].open_req_num,
					DISCARDED_RESPONSES_COLUMN, rtd_data->stat_table.time_stats[i].disc_rsp_num,
					REPEATED_REQUESTS_COLUMN, str[3],
					REPEATED_RESPONSES_COLUMN, str[4],
					-1);
				wmem_free(NULL, tmp_str);
			}
		}
	}
}

static void
reset_table_data(rtd_stat_table* table _U_, void* gui_data)
{
	GtkListStore *store;
	gtk_rtd_t* gtk_data = (gtk_rtd_t*)gui_data;

	store = GTK_LIST_STORE(gtk_tree_view_get_model(gtk_data->table));
	gtk_list_store_clear(store);
}

static void
rtd_reset(void *arg)
{
	rtd_data_t *rtd = (rtd_data_t*)arg;
	rtd_t *rr = (rtd_t *)rtd->user_data;

	reset_rtd_table(&rtd->stat_table, reset_table_data, &rr->gtk_data);

	rtd_set_title(rr);
}

static void
init_rtd_tables(register_rtd_t* rtd, const char *filter)
{
	rtd_t *rr;
	gchar *str;
	GString *error_string;
	GtkWidget *bbox;
	GtkWidget *close_bt;

	rr = g_new0(rtd_t, 1);

	str = g_strdup_printf("%s SRT", proto_get_protocol_short_name(find_protocol_by_id(get_rtd_proto_id(rtd))));
	rr->gtk_data.win=dlg_window_new(str);  /* transient_for top_level */
	g_free(str);
	gtk_window_set_destroy_with_parent (GTK_WINDOW(rr->gtk_data.win), TRUE);

	rr->gtk_data.vbox=ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 3, FALSE);

	str = g_strdup_printf("%s Service Response Time statistics", proto_get_protocol_short_name(find_protocol_by_id(get_rtd_proto_id(rtd))));
	init_main_stat_window(rr->gtk_data.win, rr->gtk_data.vbox, str, filter);
	g_free(str);

	/* init a scrolled window*/
	rr->gtk_data.scrolled_window = scrolled_window_new(NULL, NULL);

	rr->type = proto_get_protocol_short_name(find_protocol_by_id(get_rtd_proto_id(rtd)));
	rr->filter = g_strdup(filter);
	rr->rtd = rtd;
	rr->data.user_data = rr;

	rtd_table_dissector_init(rtd, &rr->data.stat_table, init_gtk_rtd_table, &rr->gtk_data);

	error_string = register_tap_listener(get_rtd_tap_listener_name(rtd), &rr->data, filter, 0, rtd_reset, get_rtd_packet_func(rtd), rtd_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
		g_string_free(error_string, TRUE);
		free_rtd_table(&rr->data.stat_table, NULL, NULL);
		g_free(rr);
		return;
	}

	/* Button row. */
	bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
	gtk_box_pack_end(GTK_BOX(rr->gtk_data.vbox), bbox, FALSE, FALSE, 0);

	close_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
	window_set_cancel_button(rr->gtk_data.win, close_bt, window_cancel_button_cb);

	g_signal_connect(rr->gtk_data.win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(rr->gtk_data.win, "destroy", G_CALLBACK(win_destroy_cb), rr);

	gtk_widget_show_all(rr->gtk_data.win);
	window_present(rr->gtk_data.win);

	cf_retap_packets(&cfile);
	gdk_window_raise(gtk_widget_get_window(rr->gtk_data.win));
}

static void
gtk_rtdstat_init(const char *opt_arg, void *userdata _U_)
{
	gchar** dissector_name;
	register_rtd_t *rtd;
	const char *filter=NULL;
	char* err;

	/* Use first comma to find dissector name */
	dissector_name = g_strsplit(opt_arg, ",", -1);
	g_assert(dissector_name[0]);

	/* Use dissector name to find SRT table */
	rtd = get_rtd_table_by_name(dissector_name[0]);
	g_assert(rtd);

	rtd_table_get_filter(rtd, opt_arg, &filter, &err);

	if (err != NULL)
	{
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err);
		g_free(err);
		return;
	}

	init_rtd_tables(rtd, filter);
}

static tap_param rtd_stat_params[] = {
	{ PARAM_FILTER, "filter", "Filter", NULL, TRUE }
};

void register_response_time_delay_tables(gpointer data, gpointer user_data _U_)
{
	register_rtd_t* rtd = (register_rtd_t*)data;
	const char* short_name = proto_get_protocol_short_name(find_protocol_by_id(get_rtd_proto_id(rtd)));
	tap_param_dlg* rtd_dlg;

	rtd_dlg = g_new(tap_param_dlg, 1);

	rtd_dlg->win_title = g_strdup_printf("%s RTD Statistics", short_name);
	rtd_dlg->init_string = rtd_table_get_tap_string(rtd);
	rtd_dlg->tap_init_cb = gtk_rtdstat_init;
	rtd_dlg->index = -1;

	rtd_dlg->nparams = G_N_ELEMENTS(rtd_stat_params);
	rtd_dlg->params = rtd_stat_params;
	rtd_dlg->user_data = rtd; /* TODO: Actually use this */

	register_param_stat(rtd_dlg, short_name, REGISTER_STAT_GROUP_RESPONSE_TIME);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */

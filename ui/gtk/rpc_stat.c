/* rpc_stat.c
 * rpc_stat   2002 Ronnie Sahlberg
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

/* This module provides rpc call/reply SRT (Server Response Time) statistics
 * to Wireshark.
 *
 * It serves as an example on how to use the tap api.
 */

#include "config.h"

#include <stdlib.h>

#include <gtk/gtk.h>

#include <epan/packet_info.h>
#include <epan/stat_tap_ui.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-rpc.h>

#include "ui/simple_dialog.h"

#include "ui/gtk/gui_stat_menu.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/main.h"
#include "ui/gtk/filter_dlg.h"
#include "ui/gtk/stock_icons.h"
#include "ui/gtk/service_response_time_table.h"
#include "ui/gtk/gtkglobals.h"
#include "ui/gtk/filter_autocomplete.h"

#include "ui/gtk/old-gtk-compat.h"

void register_tap_listener_gtkrpcstat(void);

/* used to keep track of the statistics for an entire program interface */
typedef struct _rpcstat_t {
	const char *prog;
	guint32 version;
	gtk_srt_t gtk_data;
	register_srt_t* srt;
	srt_data_t data;
} rpcstat_t;

static char *
rpcstat_gen_title(rpcstat_t *rs)
{
	char *display_name;
	char *title;

	display_name = cf_get_display_name(&cfile);
	title = g_strdup_printf("ONC-RPC Service Response Time statistics for %s version %d: %s",
	    rs->prog, rs->version, display_name);
	g_free(display_name);
	return title;
}

static void
rpcstat_set_title(rpcstat_t *rs)
{
	char *title;

	title = rpcstat_gen_title(rs);
	gtk_window_set_title(GTK_WINDOW(rs->gtk_data.win), title);
	g_free(title);
}

static void
rpcstat_reset(void *arg)
{
	srt_data_t *srt = (srt_data_t*)arg;
	rpcstat_t *rs = (rpcstat_t *)srt->user_data;

	reset_srt_table(rs->data.srt_array, reset_table_data, &rs->gtk_data);

	rpcstat_set_title(rs);
}

static void
rpcstat_draw(void *arg)
{
	guint i = 0;
	srt_stat_table *srt_table;
	srt_data_t *srt = (srt_data_t*)arg;
	rpcstat_t *rs = (rpcstat_t *)srt->user_data;

	for (i = 0; i < srt->srt_array->len; i++)
	{
		srt_table = g_array_index(srt->srt_array, srt_stat_table*, i);
		draw_srt_table_data(srt_table, &rs->gtk_data);
	}
}



static guint32 rpc_program=0;
static guint32 rpc_version=0;
static gint32 rpc_min_vers=-1;
static gint32 rpc_max_vers=-1;
static gint32 rpc_min_proc=-1;
static gint32 rpc_max_proc=-1;

static void
rpcstat_find_procs(const gchar *table_name _U_, ftenum_t selector_type _U_, gpointer key, gpointer value _U_, gpointer user_data _U_)
{
	rpc_proc_info_key *k=(rpc_proc_info_key *)key;

	if(k->prog!=rpc_program){
		return;
	}
	if(k->vers!=rpc_version){
		return;
	}
	if(rpc_min_proc==-1){
		rpc_min_proc=k->proc;
		rpc_max_proc=k->proc;
	}
	if((gint32)k->proc<rpc_min_proc){
		rpc_min_proc=k->proc;
	}
	if((gint32)k->proc>rpc_max_proc){
		rpc_max_proc=k->proc;
	}

	return;
}

static void
rpcstat_find_vers(const gchar *table_name _U_, ftenum_t selector_type _U_, gpointer key, gpointer value _U_, gpointer user_data _U_)
{
	rpc_proc_info_key *k=(rpc_proc_info_key *)key;

	if(k->prog!=rpc_program){
		return;
	}
	if(rpc_min_vers==-1){
		rpc_min_vers=k->vers;
		rpc_max_vers=k->vers;
	}
	if((gint32)k->vers<rpc_min_vers){
		rpc_min_vers=k->vers;
	}
	if((gint32)k->vers>rpc_max_vers){
		rpc_max_vers=k->vers;
	}

	return;
}

static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	rpcstat_t *rs=(rpcstat_t *)data;

	remove_tap_listener(&rs->data);

	free_srt_table(rs->srt, rs->data.srt_array, free_table_data, &rs->gtk_data);
	g_free(rs);
}

/* When called, this function will create a new instance of gtk2-rpcstat.
 */
static void
gtk_rpcstat_init(const char *opt_arg, void* userdata _U_)
{
	rpcstat_t *rs;
	char *title_string;
	char *filter_string;
	GtkWidget *stat_label;
	GtkWidget *filter_label;
	GtkWidget *bbox;
	GtkWidget *close_bt;
	int program, version, pos;
	const char *filter=NULL;
	GString *error_string;
	rpcstat_tap_data_t* tap_data;

	pos=0;
	if(sscanf(opt_arg,"rpc,srt,%d,%d,%n",&program,&version,&pos)==2){
		if(pos){
			filter=opt_arg+pos;
		} else {
			filter=NULL;
		}
	} else {
		fprintf(stderr, "wireshark: invalid \"-z rpc,srt,<program>,<version>[,<filter>]\" argument\n");
		exit(1);
	}

	rpc_program=program;
	rpc_version=version;

	rs=(rpcstat_t *)g_malloc0(sizeof(rpcstat_t));
	rs->prog = rpc_prog_name(program);
	rs->version = version;

	rs->gtk_data.win = dlg_window_new("rpc-stat");  /* transient_for top_level */
	gtk_window_set_destroy_with_parent (GTK_WINDOW(rs->gtk_data.win), TRUE);
	gtk_window_set_default_size(GTK_WINDOW(rs->gtk_data.win), SRT_PREFERRED_WIDTH, SRT_PREFERRED_HEIGHT);
	rpcstat_set_title(rs);

	rs->gtk_data.vbox=ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 3, FALSE);
	gtk_container_add(GTK_CONTAINER(rs->gtk_data.win), rs->gtk_data.vbox);
	gtk_container_set_border_width(GTK_CONTAINER(rs->gtk_data.vbox), 12);

	title_string = rpcstat_gen_title(rs);
	stat_label=gtk_label_new(title_string);
	g_free(title_string);
	gtk_box_pack_start(GTK_BOX(rs->gtk_data.vbox), stat_label, FALSE, FALSE, 0);

	filter_string = g_strdup_printf("Filter: %s", filter ? filter : "");
	filter_label=gtk_label_new(filter_string);
	g_free(filter_string);
	gtk_label_set_line_wrap(GTK_LABEL(filter_label), TRUE);
	gtk_box_pack_start(GTK_BOX(rs->gtk_data.vbox), filter_label, FALSE, FALSE, 0);

	rpc_min_proc=-1;
	rpc_max_proc=-1;

	/* Need to run over both dissector tables */
	dissector_table_foreach ("rpc.call", rpcstat_find_procs, NULL);
	dissector_table_foreach ("rpc.reply", rpcstat_find_procs, NULL);

	/* We must display TOP LEVEL Widget before calling init_gtk_srt_table() */
	gtk_widget_show_all(rs->gtk_data.win);

	rs->srt = get_srt_table_by_name("rpc");

	/* Setup the tap data */
	tap_data = g_new0(rpcstat_tap_data_t, 1);

	tap_data->prog    = rpc_prog_name(program);
	tap_data->program = program;
	tap_data->version = version;
	tap_data->num_procedures = rpc_max_proc+1;

	set_srt_table_param_data(rs->srt, tap_data);

	rs->gtk_data.gtk_srt_array = g_array_new(FALSE, TRUE, sizeof(gtk_srt_table_t*));
	rs->data.srt_array = g_array_new(FALSE, TRUE, sizeof(srt_stat_table*));
	rs->data.user_data = rs;

	srt_table_dissector_init(rs->srt, rs->data.srt_array, init_gtk_srt_table, &rs->gtk_data);

	error_string=register_tap_listener("rpc", &rs->data, filter, 0, rpcstat_reset, get_srt_packet_func(rs->srt), rpcstat_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
		g_string_free(error_string, TRUE);
		free_srt_table(rs->srt, rs->data.srt_array, NULL, NULL);
		g_free(rs);
		return;
	}

	/* Button row. */
	bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
	gtk_box_pack_end(GTK_BOX(rs->gtk_data.vbox), bbox, FALSE, FALSE, 0);

	close_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
	window_set_cancel_button(rs->gtk_data.win, close_bt, window_cancel_button_cb);

	g_signal_connect(rs->gtk_data.win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(rs->gtk_data.win, "destroy", G_CALLBACK(win_destroy_cb), rs);

	gtk_widget_show_all(rs->gtk_data.win);
	window_present(rs->gtk_data.win);

	cf_retap_packets(&cfile);
	gdk_window_raise(gtk_widget_get_window(rs->gtk_data.win));
}




static GtkWidget *dlg=NULL;
static GtkWidget *filter_entry;

static void
rpcstat_start_button_clicked(GtkWidget *item _U_, gpointer data _U_)
{
	GString *str;
	const char *filter;

	str = g_string_new("rpc,srt");
	g_string_append_printf(str, ",%d,%d", rpc_program, rpc_version);
	filter=gtk_entry_get_text(GTK_ENTRY(filter_entry));
	if(filter[0]!=0){
		g_string_append_printf(str, ",%s", filter);
	}

	gtk_rpcstat_init(str->str,NULL);
	g_string_free(str, TRUE);
}


static void
rpcstat_version_select(GtkWidget *vers_combo_box, gpointer user_data _U_)
{
	gpointer ptr;

	if (! ws_combo_box_get_active_pointer(GTK_COMBO_BOX(vers_combo_box), &ptr)) {
		g_assert_not_reached();  /* Programming error: somehow no active item */
	}

	rpc_version=GPOINTER_TO_INT(ptr);
}


static void
rpcstat_program_select(GtkWidget *prog_combo_box, gpointer user_data)
{
	guint32 k;
	GtkWidget *vers_combo_box;
	int i;

	vers_combo_box = (GtkWidget *)user_data;

	if (! ws_combo_box_get_active_pointer(GTK_COMBO_BOX(prog_combo_box), (gpointer *)&k)) {
		g_assert_not_reached();  /* Programming error: somehow no active item */
	}
	rpc_program=k;

	/* re-create version menu */
	rpc_version=0;
	g_signal_handlers_disconnect_by_func(vers_combo_box, G_CALLBACK(rpcstat_version_select), NULL );
	ws_combo_box_clear_text_and_pointer(GTK_COMBO_BOX(vers_combo_box));
	rpc_min_vers=-1;
	rpc_max_vers=-1;
	dissector_table_foreach ("rpc.call", rpcstat_find_vers, NULL);
	dissector_table_foreach ("rpc.reply", rpcstat_find_vers, NULL);
	for(i=rpc_min_vers;i<=rpc_max_vers;i++){
		char vs[5];
		g_snprintf(vs, sizeof(vs), "%d",i);
		ws_combo_box_append_text_and_pointer(GTK_COMBO_BOX(vers_combo_box),
						     vs, GINT_TO_POINTER(i));
	}
	g_signal_connect(vers_combo_box, "changed", G_CALLBACK(rpcstat_version_select), NULL);
	ws_combo_box_set_active(GTK_COMBO_BOX(vers_combo_box), 0); /* default: will trigger rpcstat_version_select callback */
}



static void
rpcstat_list_programs(gpointer *key, gpointer *value, gpointer user_data)
{
	guint32 k=GPOINTER_TO_UINT(key);
	rpc_prog_info_value *v=(rpc_prog_info_value *)value;
	GtkComboBox *prog_combo_box = (GtkComboBox *)user_data;

	ws_combo_box_append_text_and_pointer(prog_combo_box, v->progname, GUINT_TO_POINTER(k));

	if(!rpc_program){
		rpc_program=k;
	}
}

static void
dlg_destroy_cb(GtkWidget *w _U_, gpointer user_data _U_)
{
	dlg=NULL;
}

void
gtk_rpcstat_cb(GtkAction *action _U_, gpointer user_data _U_)
{
	GtkWidget *dlg_box;
	GtkWidget *prog_box, *prog_label;
	GtkWidget *vers_label;
	GtkWidget *prog_combo_box, *vers_combo_box;
	GtkWidget *filter_box, *filter_bt;
	GtkWidget *bbox, *start_button, *cancel_button;
	const char *filter;
	static construct_args_t args = {
	  "Service Response Time Statistics Filter",
	  TRUE,
	  FALSE,
	  FALSE
	};

	/* if the window is already open, bring it to front */
	if(dlg){
		gdk_window_raise(gtk_widget_get_window(dlg));
		return;
	}

	dlg=dlg_window_new("Wireshark: Compute ONC-RPC SRT statistics");
	gtk_window_set_default_size(GTK_WINDOW(dlg), 300, -1);

	dlg_box=ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 10, FALSE);
	gtk_container_set_border_width(GTK_CONTAINER(dlg_box), 10);
	gtk_container_add(GTK_CONTAINER(dlg), dlg_box);
	gtk_widget_show(dlg_box);

	/* Program box */
	prog_box=ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10, FALSE);

	/* Program label */
	gtk_container_set_border_width(GTK_CONTAINER(prog_box), 10);
	prog_label=gtk_label_new("Program:");
	gtk_box_pack_start(GTK_BOX(prog_box), prog_label, FALSE, FALSE, 0);
	gtk_widget_show(prog_label);

	/* Program menu */
	prog_combo_box=ws_combo_box_new_text_and_pointer();
	g_hash_table_foreach(rpc_progs, (GHFunc)rpcstat_list_programs, prog_combo_box);
	gtk_box_pack_start(GTK_BOX(prog_box), prog_combo_box, TRUE, TRUE, 0);
	gtk_widget_show(prog_combo_box);

	/* Version label */
	gtk_container_set_border_width(GTK_CONTAINER(prog_box), 10);
	vers_label=gtk_label_new("Version:");
	gtk_box_pack_start(GTK_BOX(prog_box), vers_label, FALSE, FALSE, 0);
	gtk_widget_show(vers_label);

	/* Note: version combo box rows set when rpcstat_program_select callback invoked below */
	vers_combo_box=ws_combo_box_new_text_and_pointer();
	gtk_box_pack_start(GTK_BOX(prog_box), vers_combo_box, TRUE, TRUE, 0);
	gtk_widget_show(vers_combo_box);

	gtk_box_pack_start(GTK_BOX(dlg_box), prog_box, TRUE, TRUE, 0);

	g_signal_connect(prog_combo_box, "changed", G_CALLBACK(rpcstat_program_select), vers_combo_box);
	ws_combo_box_set_active(GTK_COMBO_BOX(prog_combo_box), 0); /* invokes rpcstat_program_select callback */

	gtk_widget_show(prog_box);

	/* Filter box */
	filter_box=ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 3, FALSE);

	/* Filter label */
	filter_bt=ws_gtk_button_new_from_stock(WIRESHARK_STOCK_DISPLAY_FILTER_ENTRY);
	g_signal_connect(filter_bt, "clicked", G_CALLBACK(display_filter_construct_cb), &args);
	gtk_box_pack_start(GTK_BOX(filter_box), filter_bt, FALSE, FALSE, 0);
	gtk_widget_show(filter_bt);

	/* Filter entry */
	filter_entry=gtk_entry_new();
	g_signal_connect(filter_entry, "changed", G_CALLBACK(filter_te_syntax_check_cb), NULL);
	g_object_set_data(G_OBJECT(filter_box), E_FILT_AUTOCOMP_PTR_KEY, NULL);
	g_signal_connect(filter_entry, "key-press-event", G_CALLBACK (filter_string_te_key_pressed_cb), NULL);
	g_signal_connect(dlg, "key-press-event", G_CALLBACK (filter_parent_dlg_key_pressed_cb), NULL);

	/* filter prefs dialog */
	g_object_set_data(G_OBJECT(filter_bt), E_FILT_TE_PTR_KEY, filter_entry);
	/* filter prefs dialog */

	gtk_box_pack_start(GTK_BOX(filter_box), filter_entry, TRUE, TRUE, 0);
	filter=gtk_entry_get_text(GTK_ENTRY(main_display_filter_widget));
	if(filter){
		gtk_entry_set_text(GTK_ENTRY(filter_entry), filter);
	} else {
		colorize_filter_te_as_empty(filter_entry);
	}
	gtk_widget_show(filter_entry);

	gtk_box_pack_start(GTK_BOX(dlg_box), filter_box, TRUE, TRUE, 0);
	gtk_widget_show(filter_box);

	/* button box */
	bbox = dlg_button_row_new(WIRESHARK_STOCK_CREATE_STAT, GTK_STOCK_CANCEL, NULL);
	gtk_box_pack_start(GTK_BOX(dlg_box), bbox, FALSE, FALSE, 0);
	gtk_widget_show(bbox);

	start_button = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), WIRESHARK_STOCK_CREATE_STAT);
	g_signal_connect_swapped(start_button, "clicked",
				 G_CALLBACK(rpcstat_start_button_clicked), NULL);

	cancel_button = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CANCEL);
	window_set_cancel_button(dlg, cancel_button, window_cancel_button_cb);

	/* Give the initial focus to the "Filter" entry box. */
	gtk_widget_grab_focus(filter_entry);

	gtk_widget_grab_default(start_button );

	g_signal_connect(dlg, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(dlg, "destroy", G_CALLBACK(dlg_destroy_cb), NULL);

	gtk_widget_show_all(dlg);
	window_present(dlg);
}


static stat_tap_ui rpcstat_ui = {
	REGISTER_STAT_GROUP_RESPONSE_TIME,
	NULL,
	"rpc,srt",
	gtk_rpcstat_init,
	0,
	NULL
};

void
register_tap_listener_gtkrpcstat(void)
{
	register_stat_tap_ui(&rpcstat_ui, NULL);
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

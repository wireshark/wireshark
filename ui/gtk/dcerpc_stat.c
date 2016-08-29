/* dcerpc_stat.c
 * dcerpc_stat   2002 Ronnie Sahlberg
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

/* This module provides rpc call/reply SRT statistics to Wireshark,
 * and displays them graphically.
 * It is only used by Wireshark and not tshark
 *
 * It serves as an example on how to use the tap api.
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include <gtk/gtk.h>

#include <epan/packet_info.h>
#include <epan/stat_tap_ui.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-dcerpc.h>


#include "ui/simple_dialog.h"

#include "ui/gtk/gui_stat_menu.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/filter_dlg.h"
#include "ui/gtk/stock_icons.h"
#include "ui/gtk/service_response_time_table.h"
#include "ui/gtk/gtkglobals.h"
#include "ui/gtk/main.h"
#include "ui/gtk/filter_autocomplete.h"

#include "ui/gtk/old-gtk-compat.h"

void register_tap_listener_gtkdcerpcstat(void);

/* used to keep track of the statistics for an entire program interface */
typedef struct _dcerpcstat_t {
	const char *prog;
	guint16 ver;
	gtk_srt_t gtk_data;
	register_srt_t* srt;
	srt_data_t data;
} dcerpcstat_t;


static char *
dcerpcstat_gen_title(dcerpcstat_t *rs)
{
	char *title;
	char *display_name;

	display_name = cf_get_display_name(&cfile);
	title = g_strdup_printf("DCE-RPC Service Response Time statistics for %s major version %u: %s", rs->prog, rs->ver, display_name);
	g_free(display_name);
	return title;
}

static void
dcerpcstat_set_title(dcerpcstat_t *rs)
{
	char *title;

	title = dcerpcstat_gen_title(rs);
	gtk_window_set_title(GTK_WINDOW(rs->gtk_data.win), title);
	g_free(title);
}

static void
dcerpcstat_reset(void *rs_arg)
{
	srt_data_t *srt = (srt_data_t*)rs_arg;
	dcerpcstat_t *rs = (dcerpcstat_t *)srt->user_data;

	reset_srt_table(rs->data.srt_array, reset_table_data, &rs->gtk_data);

	dcerpcstat_set_title(rs);
}

static void
dcerpcstat_draw(void *rs_arg)
{
	guint i = 0;
	srt_stat_table *srt_table;
	srt_data_t *srt = (srt_data_t*)rs_arg;
	dcerpcstat_t *rs = (dcerpcstat_t *)srt->user_data;

	for (i = 0; i < srt->srt_array->len; i++)
	{
		srt_table = g_array_index(srt->srt_array, srt_stat_table*, i);
		draw_srt_table_data(srt_table, &rs->gtk_data);
	}

}

static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	dcerpcstat_t *rs = (dcerpcstat_t *)data;

	remove_tap_listener(&rs->data);

	free_srt_table(rs->srt, rs->data.srt_array, free_table_data, &rs->gtk_data);
	g_free(rs);
}

/* When called, this function will create a new instance of gtk-dcerpcstat.
 */
static void
gtk_dcerpcstat_init(const char *opt_arg, void* userdata _U_)
{
	dcerpcstat_t *rs;
	guint32 i, max_procs;
	char *title_string;
	char *filter_string;
	GtkWidget *stat_label;
	GtkWidget *filter_label;
	GtkWidget *bbox;
	GtkWidget *close_bt;
	dcerpc_sub_dissector *procs;
	e_guid_t uuid;
	guint d1,d2,d3,d40,d41,d42,d43,d44,d45,d46,d47;
	int major, minor;
	guint16 ver;
	int pos = 0;
	const char *filter = NULL;
	dcerpcstat_tap_data_t* tap_data;
	GString *error_string;

	/*
	 * XXX - DCE RPC statistics are maintained only by major version,
	 * not by major and minor version, so the minor version number is
	 * ignored.
	 *
	 * Should we just stop supporting minor version numbers here?
	 * Or should we allow it to be omitted?  Or should we keep
	 * separate statistics for different minor version numbers,
	 * and allow the minor version number to be omitted, and
	 * report aggregate statistics for all minor version numbers
	 * if it's omitted?
	 */
	if(sscanf(
		   opt_arg,
		   "dcerpc,srt,%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x,%d.%d,%n",
		   &d1,&d2,&d3,&d40,&d41,&d42,&d43,&d44,&d45,&d46,&d47,&major,&minor,&pos)
	   == 13) {
		uuid.data1    = d1;
		uuid.data2    = d2;
		uuid.data3    = d3;
		uuid.data4[0] = d40;
		uuid.data4[1] = d41;
		uuid.data4[2] = d42;
		uuid.data4[3] = d43;
		uuid.data4[4] = d44;
		uuid.data4[5] = d45;
		uuid.data4[6] = d46;
		uuid.data4[7] = d47;
		if(pos) {
			filter = opt_arg+pos;
		} else {
			filter = NULL;
		}
	} else {
		fprintf(stderr, "wireshark: invalid \"-z dcerpc,srt,<uuid>,<major version>.<minor version>[,<filter>]\" argument\n");
		exit(1);
	}
	if ((major < 0) || (major > 65535)) {
		fprintf(stderr,"wireshark: dcerpcstat_init() Major version number %d is invalid - must be positive and <= 65535\n", major);
		exit(1);
	}
	if ((minor < 0) || (minor > 65535)) {
		fprintf(stderr,"wireshark: dcerpcstat_init() Minor version number %d is invalid - must be positive and <= 65535\n", minor);
		exit(1);
	}
	ver = major;

	rs = (dcerpcstat_t *)g_malloc0(sizeof(dcerpcstat_t));
	rs->prog = dcerpc_get_proto_name(&uuid, ver);
	if(!rs->prog){
		g_free(rs);
		fprintf(stderr,
			"wireshark: dcerpcstat_init() Protocol with uuid:%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x v%u not supported\n",
			uuid.data1,uuid.data2,uuid.data3,uuid.data4[0],uuid.data4[1],uuid.data4[2],uuid.data4[3],uuid.data4[4],uuid.data4[5],uuid.data4[6],uuid.data4[7],ver);
		exit(1);
	}

	procs    = dcerpc_get_proto_sub_dissector(&uuid, ver);
	rs->ver  = ver;

	rs->gtk_data.win  = dlg_window_new("dcerpc-stat");  /* transient_for top_level */
	gtk_window_set_destroy_with_parent(GTK_WINDOW(rs->gtk_data.win), TRUE);

	dcerpcstat_set_title(rs);
	gtk_window_set_default_size(GTK_WINDOW(rs->gtk_data.win), SRT_PREFERRED_WIDTH, SRT_PREFERRED_HEIGHT);

	rs->gtk_data.vbox =ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 3, FALSE);
	gtk_container_add(GTK_CONTAINER(rs->gtk_data.win), rs->gtk_data.vbox);
	gtk_container_set_border_width(GTK_CONTAINER(rs->gtk_data.vbox), 12);

	title_string = dcerpcstat_gen_title(rs);
	stat_label   = gtk_label_new(title_string);
	g_free(title_string);
	gtk_box_pack_start(GTK_BOX(rs->gtk_data.vbox), stat_label, FALSE, FALSE, 0);

	filter_string = g_strdup_printf("Filter: %s",filter ? filter : "");
	filter_label  = gtk_label_new(filter_string);
	g_free(filter_string);
	gtk_label_set_line_wrap(GTK_LABEL(filter_label), TRUE);
	gtk_box_pack_start(GTK_BOX(rs->gtk_data.vbox), filter_label, FALSE, FALSE, 0);

	/* We must display TOP LEVEL Widget before calling init_gtk_srt_table() */
	gtk_widget_show_all(rs->gtk_data.win);

	rs->srt = get_srt_table_by_name("dcerpc");


	for(i=0,max_procs=0;procs[i].name;i++){
		if(procs[i].num>max_procs){
			max_procs = procs[i].num;
		}
	}

	/* Setup the tap data */
	tap_data = g_new0(dcerpcstat_tap_data_t, 1);

	tap_data->uuid    = uuid;
	tap_data->prog    = dcerpc_get_proto_name(&tap_data->uuid, ver);
	tap_data->ver     = ver;
	tap_data->num_procedures = max_procs+1;

	set_srt_table_param_data(rs->srt, tap_data);

	rs->gtk_data.gtk_srt_array = g_array_new(FALSE, TRUE, sizeof(gtk_srt_table_t*));
	rs->data.srt_array = g_array_new(FALSE, TRUE, sizeof(srt_stat_table*));
	rs->data.user_data = rs;

	srt_table_dissector_init(rs->srt, rs->data.srt_array, init_gtk_srt_table, &rs->gtk_data);

	error_string = register_tap_listener("dcerpc", &rs->data, filter, 0, dcerpcstat_reset, get_srt_packet_func(rs->srt), dcerpcstat_draw);
	if(error_string){
		/* error, we failed to attach to the tap. clean up */
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
	g_signal_connect(rs->gtk_data.win, "destroy",      G_CALLBACK(win_destroy_cb), rs);

	gtk_widget_show_all(rs->gtk_data.win);
	window_present(rs->gtk_data.win);

	cf_retap_packets(&cfile);
	gdk_window_raise(gtk_widget_get_window(rs->gtk_data.win));
}



static e_guid_t          *dcerpc_uuid_program;
static guint16            dcerpc_version;
static GtkWidget         *dlg = NULL;
static GtkWidget         *filter_entry;
static guid_key   *current_uuid_key;
static dcerpc_uuid_value *current_uuid_value;
static guid_key   *new_uuid_key;
static dcerpc_uuid_value *new_uuid_value;

static void
dcerpcstat_start_button_clicked(GtkWidget *item _U_, gpointer data _U_)
{
	GString *str;
	const char *filter;

	if (dcerpc_uuid_program == NULL) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Please select a program");
		return;
	}
	str = g_string_new("dcerpc,srt");
	g_string_append_printf(str,
	    ",%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x,%u.%u",
	    dcerpc_uuid_program->data1, dcerpc_uuid_program->data2,
	    dcerpc_uuid_program->data3,
	    dcerpc_uuid_program->data4[0], dcerpc_uuid_program->data4[1],
	    dcerpc_uuid_program->data4[2], dcerpc_uuid_program->data4[3],
	    dcerpc_uuid_program->data4[4], dcerpc_uuid_program->data4[5],
	    dcerpc_uuid_program->data4[6], dcerpc_uuid_program->data4[7],
	    dcerpc_version, 0);
	filter = gtk_entry_get_text(GTK_ENTRY(filter_entry));
	if(filter[0] != 0){
		g_string_append_printf(str, ",%s", filter);
	}

	gtk_dcerpcstat_init(str->str,NULL);
	g_string_free(str, TRUE);
}


static void
dcerpcstat_version_select(GtkWidget *vers_combo_box, gpointer user_data _U_)
{
	guid_key *k;

	if (! ws_combo_box_get_active_pointer(GTK_COMBO_BOX(vers_combo_box), (gpointer *)&k)) {
		g_assert_not_reached();  /* Programming error: somehow no active item */
	}

	dcerpc_version = k->ver;
}

static void
dcerpcstat_find_vers(gpointer *key, gpointer *value _U_, gpointer user_data)
{
	guid_key *k = (guid_key *)key;
	GtkWidget       *vers_combo_box = (GtkWidget *)user_data;
	char vs[5];

	if(guid_cmp(&(k->guid), dcerpc_uuid_program)){
		return;
	}
	g_snprintf(vs, sizeof(vs), "%u", k->ver);
	ws_combo_box_append_text_and_pointer(GTK_COMBO_BOX(vers_combo_box), vs, k);
}

static void
dcerpcstat_program_select(GtkWidget *prog_combo_box, gpointer user_data)
{
	guid_key *k;
	GtkWidget *vers_combo_box;

	vers_combo_box = (GtkWidget *)user_data;

	if (! ws_combo_box_get_active_pointer(GTK_COMBO_BOX(prog_combo_box), (gpointer *)&k)) {
		g_assert_not_reached();  /* Programming error: somehow no active item */
	}

	g_signal_handlers_disconnect_by_func(vers_combo_box, G_CALLBACK(dcerpcstat_version_select), NULL );
	ws_combo_box_clear_text_and_pointer(GTK_COMBO_BOX(vers_combo_box));

	/* dcerpc_stat: invalid selection... somehow selected top level ?? */
	g_assert(k != NULL);
	dcerpc_uuid_program = &(k->guid);

	/* re-create version menu */
	g_signal_handlers_disconnect_by_func(vers_combo_box, G_CALLBACK(dcerpcstat_version_select), NULL );
	ws_combo_box_clear_text_and_pointer(GTK_COMBO_BOX(vers_combo_box));

	g_hash_table_foreach(dcerpc_uuids, (GHFunc)dcerpcstat_find_vers, vers_combo_box);

	g_signal_connect(vers_combo_box, "changed", G_CALLBACK(dcerpcstat_version_select), NULL);
	ws_combo_box_set_active(GTK_COMBO_BOX(vers_combo_box), 0); /* default: triggers dcerpcstat_version_select callback */

}

static GtkTreeIter
dcerpcstat_add_program_to_menu(guid_key *k, dcerpc_uuid_value *v, GtkWidget *prog_combo_box, int program_item_index)
{
	static GtkTreeIter iter;
	char str[64];

	switch(program_item_index%15){
	case 0:
		g_snprintf(str,sizeof(str),"%s ...",v->name);
		iter = ws_combo_box_append_text_and_pointer_full(
			GTK_COMBO_BOX(prog_combo_box), NULL, str, NULL, FALSE); /* top-level entries are insensitive */
		break;

	default:
		break;
	}

	return ws_combo_box_append_text_and_pointer_full(
		GTK_COMBO_BOX(prog_combo_box), &iter, v->name, k, TRUE);
}

static void
dcerpcstat_find_next_program(gpointer *key, gpointer *value, gpointer *user_data _U_)
{
	guid_key   *k = (guid_key *)key;
	dcerpc_uuid_value *v = (dcerpc_uuid_value *)value;

	/* first time called, just set new_uuid to this one */
	if((current_uuid_key==NULL) && (new_uuid_key==NULL)){
		new_uuid_key   = k;
		new_uuid_value = v;
		return;
	}

	/* if we haven't got a current one yet, just check the new
	   and scan for the first one alphabetically  */
	if(current_uuid_key==NULL){
		if(strcmp(new_uuid_value->name, v->name)>0){
			new_uuid_key   = k;
			new_uuid_value = v;
			return;
		}
		return;
	}

	/* searching for the next one we are only interested in those
	   that sorts alphabetically after the current one */
	if(strcmp(current_uuid_value->name, v->name) >= 0){
		/* this one doesn't so just skip it */
		return;
	}

	/* is it the first potential new entry? */
	if(new_uuid_key==NULL){
		new_uuid_key   = k;
		new_uuid_value = v;
		return;
	}

	/* does it sort before the current new one? */
	if(strcmp(new_uuid_value->name, v->name) > 0){
		new_uuid_key   = k;
		new_uuid_value = v;
		return;
	}

	return;
}


static void
dlg_destroy_cb(GtkWidget *w _U_, gpointer user_data _U_)
{
	dlg = NULL;
}


void gtk_dcerpcstat_cb(GtkAction *action _U_, gpointer user_data _U_)
{
	GtkWidget       *dlg_box;
	GtkWidget       *prog_box,   *prog_label, *prog_combo_box;
	GtkWidget       *vers_label, *vers_combo_box;
	GtkWidget       *filter_box, *filter_bt;
	GtkWidget       *bbox, *start_button, *cancel_button;
	GtkCellRenderer *cell_renderer;
#if 0
	GtkTreeIter      program_first_item_iter;
#endif
	const char      *filter;
	int              program_item_index = 0;

	static construct_args_t args = {
	  "Service Response Time Statistics Filter",
	  FALSE,
	  FALSE,
	  FALSE
	};

	/* if the window is already open, bring it to front and
	   un-minimize it, as necessary */
	if(dlg){
		reactivate_window(dlg);
		return;
	}

	dlg = dlg_window_new("Wireshark: Compute DCE-RPC SRT statistics");
	gtk_window_set_default_size(GTK_WINDOW(dlg), 400, -1);

	dlg_box = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 10, FALSE);
	gtk_container_set_border_width(GTK_CONTAINER(dlg_box), 10);
	gtk_container_add(GTK_CONTAINER(dlg), dlg_box);
	gtk_widget_show(dlg_box);

	/* Program box */
	prog_box = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 3, FALSE);

	/* Program label */
	gtk_container_set_border_width(GTK_CONTAINER(prog_box), 10);
	prog_label = gtk_label_new("Program:");
	gtk_box_pack_start(GTK_BOX(prog_box), prog_label, FALSE, FALSE, 0);
	gtk_widget_show(prog_label);

	/* Program menu */
	dcerpc_uuid_program = NULL;   /* default: no program selected */

	/* The "program combo box" is implemented with a two-level tree.
	   Each top-level of the tree has (up to) 15 selectable "program name"
	   children and shows the name of the first child of that entry
	   as "child_name ...". Each of the top-level entries can be expanded
	   (to show the children) but is "insensitive": ie: cannot be selected.
	   (dcerpcstat_add_program_to_menu() does the actual work to add entries
	    to the combo box).
	    XXX: A simpler alternative might be to just do away with all the two-level
		 complexity and just use a standard ws_combo_box... even though the
		 list of "program names" is quite large.
	    XXX: The gtkrc file distributed with Windows Wireshark has the
		 "appears-as-list" GtkComboBox style property set to 1 and thus
		 on Windows the entries for this combo box will appear as a tree-view.
		 The default is 0(FALSE). In this case the the combo box entries will
		 display as a menu with sub-menus.
		 A possibility would be to set "appears-as-list" to 0  just for this
		 particular combo box on Windows so that the entries will appear as a
		 menu even on Windows).
	*/
	prog_combo_box = ws_combo_box_new_text_and_pointer_full(&cell_renderer);
	{
		/* XXX: Hack So that the top-level insensitive entries don't show
		        as "grayed out"; The "foreground normal" color is used instead.
			This may not really be necessary but seems better to me.
		*/
#if GTK_CHECK_VERSION(3,0,0)
		GtkStyleContext *context;
		GdkRGBA			*new_rgba_fg_color;
		context = gtk_widget_get_style_context (prog_combo_box);
		gtk_style_context_get (context, GTK_STATE_FLAG_NORMAL,
				 "color", &new_rgba_fg_color,
				  NULL);

		g_object_set(cell_renderer,
			     "foreground-rgba", &new_rgba_fg_color,
			     "foreground-set", TRUE,
			     NULL);

#else
		GtkStyle *s;
		s = gtk_widget_get_style(prog_combo_box);
		g_object_set(cell_renderer,
			     "foreground-gdk", &(s->fg[GTK_STATE_NORMAL]),
			     "foreground-set", TRUE,
			     NULL);
#endif
	}

	current_uuid_key   = NULL;
	current_uuid_value = NULL;
	do {
		new_uuid_key   = NULL;
		new_uuid_value = NULL;
		g_hash_table_foreach(dcerpc_uuids, (GHFunc)dcerpcstat_find_next_program, NULL);
		if(new_uuid_key){
#if 0
			GtkTreeIter tmp_iter;
			tmp_iter = dcerpcstat_add_program_to_menu(new_uuid_key, new_uuid_value,
								  prog_combo_box, program_item_index);
			if (program_item_index == 0)
				program_first_item_iter = tmp_iter;
#else
			dcerpcstat_add_program_to_menu(new_uuid_key, new_uuid_value,
							prog_combo_box, program_item_index);
#endif
			program_item_index += 1;
		}
		current_uuid_key   = new_uuid_key;
		current_uuid_value = new_uuid_value;
	} while(new_uuid_key != NULL);
	gtk_box_pack_start(GTK_BOX(prog_box), prog_combo_box, TRUE, TRUE, 0);
	gtk_widget_show(prog_combo_box);

	/* Version label */
	gtk_container_set_border_width(GTK_CONTAINER(prog_box), 10);
	vers_label = gtk_label_new("Version:");
	gtk_box_pack_start(GTK_BOX(prog_box), vers_label, FALSE, FALSE, 0);
	gtk_widget_show(vers_label);

	/* Version combo-box */
	/* Note: version combo box rows set when dcerpcstat_program_select() callback invoked */
	vers_combo_box = ws_combo_box_new_text_and_pointer();
	gtk_box_pack_start(GTK_BOX(prog_box), vers_combo_box, TRUE, TRUE, 0);
	gtk_widget_show(vers_combo_box);

	g_signal_connect(prog_combo_box, "changed", G_CALLBACK(dcerpcstat_program_select), vers_combo_box);
#if 0 /* Don't select an active entry given the way the drop down treeview appears if a default (active) entry is set */
	ws_combo_box_set_active_iter(GTK_COMBO_BOX(prog_combo_box), &program_first_item_iter); /* triggers callback */
#endif
	gtk_box_pack_start(GTK_BOX(dlg_box), prog_box, TRUE, TRUE, 0);
	gtk_widget_show(prog_box);

	/* Filter box */
	filter_box = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 3, FALSE);

	/* Filter label */
	filter_bt = ws_gtk_button_new_from_stock(WIRESHARK_STOCK_DISPLAY_FILTER_ENTRY);
	g_signal_connect(filter_bt, "clicked", G_CALLBACK(display_filter_construct_cb), &args);
	gtk_box_pack_start(GTK_BOX(filter_box), filter_bt, FALSE, FALSE, 0);
	gtk_widget_show(filter_bt);

	/* Filter entry */
	filter_entry = gtk_entry_new();
	g_signal_connect(filter_entry, "changed", G_CALLBACK(filter_te_syntax_check_cb), NULL);
	g_object_set_data(G_OBJECT(filter_box), E_FILT_AUTOCOMP_PTR_KEY, NULL);
	g_signal_connect(filter_entry, "key-press-event", G_CALLBACK (filter_string_te_key_pressed_cb), NULL);
	g_signal_connect(dlg, "key-press-event", G_CALLBACK (filter_parent_dlg_key_pressed_cb), NULL);
	gtk_box_pack_start(GTK_BOX(filter_box), filter_entry, TRUE, TRUE, 0);
	filter = gtk_entry_get_text(GTK_ENTRY(main_display_filter_widget));
	if(filter){
		gtk_entry_set_text(GTK_ENTRY(filter_entry), filter);
	} else {
		colorize_filter_te_as_empty(filter_entry);
	}
	gtk_widget_show(filter_entry);

	gtk_box_pack_start(GTK_BOX(dlg_box), filter_box, TRUE, TRUE, 0);
	gtk_widget_show(filter_box);

	g_object_set_data(G_OBJECT(filter_bt), E_FILT_TE_PTR_KEY, filter_entry);

	/* button box */
	bbox = dlg_button_row_new(WIRESHARK_STOCK_CREATE_STAT, GTK_STOCK_CANCEL, NULL);
	gtk_box_pack_start(GTK_BOX(dlg_box), bbox, FALSE, FALSE, 0);
	gtk_widget_show(bbox);

	start_button = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), WIRESHARK_STOCK_CREATE_STAT);
	g_signal_connect_swapped(start_button, "clicked",
				 G_CALLBACK(dcerpcstat_start_button_clicked), NULL);

	cancel_button = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CANCEL);
	window_set_cancel_button(dlg, cancel_button, window_cancel_button_cb);

	g_signal_connect(dlg, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(dlg, "destroy", G_CALLBACK(dlg_destroy_cb), NULL);

	/* Catch the "activate" signal on the filter text entry, so that
	   if the user types Return there, we act as if the "Create Stat"
	   button had been selected, as happens if Return is typed if some
	   widget that *doesn't* handle the Return key has the input
	   focus. */
	dlg_set_activate(filter_entry, start_button);

	gtk_widget_grab_default(start_button );

	/* Give the initial focus to the "Filter" entry box. */
	gtk_widget_grab_focus(filter_entry);

	gtk_widget_show_all(dlg);
	window_present(dlg);
}

static stat_tap_ui dcerpcstat_ui = {
	REGISTER_STAT_GROUP_RESPONSE_TIME,
	NULL,
	"dcerpc,srt",
	gtk_dcerpcstat_init,
	0,
	NULL
};

void
register_tap_listener_gtkdcerpcstat(void)
{
	register_stat_tap_ui(&dcerpcstat_ui, NULL);
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

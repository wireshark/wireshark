/* flow_graph.c
 * Allows to display a flow graph of the currently displayed packets
 *
 * Copyright 2004, Ericsson , Spain
 * By Francisco Alcoba <francisco.alcoba@ericsson.com>
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
 * Foundation,  Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"
#include <string.h>


#include <epan/packet.h>
#include <epan/stat_tap_ui.h>

#include "ui/gtk/graph_analysis.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/stock_icons.h"
#include "ui/gtk/main.h"
#include "ui/gtk/gui_stat_menu.h"
#include "ui/gtk/old-gtk-compat.h"

void register_tap_listener_flow_graph(void);

static seq_analysis_info_t *graph_analysis	  = NULL;
static graph_analysis_data_t *graph_analysis_data = NULL;

static GtkWidget *flow_graph_dlg = NULL;

static GtkWidget *select_all_rb;
static GtkWidget *select_displayed_rb;
static GtkWidget *select_general_rb;
static GtkWidget *select_tcp_rb;
static GtkWidget *src_dst_rb;
static GtkWidget *net_src_dst_rb;


/****************************************************************************/
static void
flow_graph_data_init(void) {
	graph_analysis = sequence_analysis_info_new();
	graph_analysis->type = SEQ_ANALYSIS_ANY;
	graph_analysis->all_packets = TRUE;
}


/****************************************************************************/
/* CALLBACKS                                                                */
/****************************************************************************/
static void
flow_graph_on_destroy(GObject *object _U_, gpointer user_data _U_)
{
	g_assert(graph_analysis != NULL);
	g_assert(graph_analysis_data != NULL);

	/* Clean up memory used by tap */
	sequence_analysis_info_free(graph_analysis);
	graph_analysis = NULL;

	g_free(graph_analysis_data);
	graph_analysis_data = NULL;

	/* Note that we no longer have a "Flow Graph" dialog box. */
	flow_graph_dlg = NULL;
}


/****************************************************************************/
static void
toggle_select_all(GtkWidget *widget _U_, gpointer user_data _U_)
{
	/* is the button now active? */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(select_all_rb))) {
		graph_analysis->all_packets = TRUE;
	}
}

/****************************************************************************/
static void
toggle_select_displayed(GtkWidget *widget _U_, gpointer user_data _U_)
{
	/* is the button now active? */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(select_displayed_rb))) {
		graph_analysis->all_packets = FALSE;
	}
}

/****************************************************************************/
static void
toggle_select_general(GtkWidget *widget _U_, gpointer user_data _U_)
{
	/* is the button now active? */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(select_general_rb))) {
		graph_analysis->type = SEQ_ANALYSIS_ANY;
	}
}

/****************************************************************************/
static void
toggle_select_tcp(GtkWidget *widget _U_, gpointer user_data _U_)
{
	/* is the button now active? */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(select_tcp_rb))) {
		graph_analysis->type = SEQ_ANALYSIS_TCP;
	}
}

/****************************************************************************/
static void
toggle_select_srcdst(GtkWidget *widget _U_, gpointer user_data _U_)
{
	/* is the button now active? */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(src_dst_rb))) {
		graph_analysis->any_addr = FALSE;
	}
}

/****************************************************************************/
static void
toggle_select_netsrcdst(GtkWidget *widget _U_, gpointer user_data _U_)
{
	/* is the button now active? */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(net_src_dst_rb))) {
		graph_analysis->any_addr = TRUE;
	}
}

/****************************************************************************/
static void
flow_graph_on_ok(GtkButton       *button _U_,
		 gpointer         user_data)
{
	/* Scan for displayed packets (retap all packets) */
	sequence_analysis_list_free(graph_analysis);
	sequence_analysis_list_get(&cfile, graph_analysis);

	if (graph_analysis_data->dlg.window != NULL){ /* if we still have a window */
		graph_analysis_update(graph_analysis_data);		/* refresh it xxx */
	}
	else{
		graph_analysis_data->dlg.parent_w = (GtkWidget *)user_data;
		graph_analysis_create(graph_analysis_data);
	}
}

static void
flow_graph_on_cancel(GtkButton       *button _U_,
		     gpointer         user_data)
{
	if (graph_analysis_data->dlg.window) {
		window_destroy(graph_analysis_data->dlg.window);
	}
	window_destroy(GTK_WIDGET(user_data));
}

static gboolean
flow_graph_on_delete(GtkButton       *button _U_,
		     gpointer         user_data _U_)
{
	if (graph_analysis_data->dlg.window) {
		window_destroy(graph_analysis_data->dlg.window);
	}
	return FALSE;
}

/****************************************************************************/
/* INTERFACE                                                                */
/****************************************************************************/

static void
flow_graph_dlg_create(void)
{
	GtkWidget *flow_graph_dlg_w;
	GtkWidget *main_vb;
	GtkWidget *hbuttonbox;
	GtkWidget *bt_cancel, *bt_ok;
#if 0
	GtkWidget *top_label = NULL;
#endif
	GtkWidget *flow_type_fr, *range_fr, *range_grid, *flow_type_grid, *node_addr_fr, *node_addr_grid;

	flow_graph_dlg_w = dlg_window_new("Wireshark: Flow Graph");  /* transient_for top_level */
	gtk_window_set_destroy_with_parent (GTK_WINDOW(flow_graph_dlg_w), TRUE);

	gtk_window_set_default_size(GTK_WINDOW(flow_graph_dlg_w), 250, 150);

	main_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 0, FALSE);
	gtk_container_add(GTK_CONTAINER(flow_graph_dlg_w), main_vb);
	gtk_container_set_border_width (GTK_CONTAINER (main_vb), 7);

#if 0
	top_label = gtk_label_new ("Choose packets to include in the graph");
	gtk_box_pack_start (GTK_BOX (main_vb), top_label, FALSE, FALSE, 8);
#endif

	gtk_widget_show(flow_graph_dlg_w);

	/*** Packet range frame ***/
	range_fr = gtk_frame_new("Choose packets");
	gtk_box_pack_start(GTK_BOX(main_vb), range_fr, FALSE, FALSE, 5);

	range_grid = ws_gtk_grid_new();
	gtk_container_set_border_width(GTK_CONTAINER(range_grid), 5);
	gtk_container_add(GTK_CONTAINER(range_fr), range_grid);

	/* Process all packets */
	select_all_rb = gtk_radio_button_new_with_mnemonic_from_widget(NULL, "_All packets");
	gtk_widget_set_tooltip_text (select_all_rb, ("Process all packets"));
	g_signal_connect(select_all_rb, "toggled", G_CALLBACK(toggle_select_all), NULL);
	ws_gtk_grid_attach_extended(GTK_GRID(range_grid), select_all_rb, 0, 0, 1, 1,
				    (GtkAttachOptions)(GTK_FILL), (GtkAttachOptions)(0), 0, 0);
	if (graph_analysis->all_packets) {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(select_all_rb),TRUE);
	}
 	gtk_widget_show(select_all_rb);

	/* Process displayed packets */
	select_displayed_rb = gtk_radio_button_new_with_mnemonic_from_widget(GTK_RADIO_BUTTON(select_all_rb),
									     "_Displayed packets");
	gtk_widget_set_tooltip_text (select_displayed_rb, ("Process displayed packets"));
	g_signal_connect(select_displayed_rb, "toggled", G_CALLBACK(toggle_select_displayed), NULL);
	ws_gtk_grid_attach_extended(GTK_GRID(range_grid), select_displayed_rb, 0, 1, 1, 1,
				    (GtkAttachOptions)(GTK_FILL), (GtkAttachOptions)(0), 0, 0);
	if (!graph_analysis->all_packets) {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(select_displayed_rb),TRUE);
	}
 	gtk_widget_show(select_displayed_rb);

	gtk_widget_show(range_grid);
	gtk_widget_show(range_fr);

	/*** Flow type frame ***/
	flow_type_fr = gtk_frame_new("Choose flow type");
	gtk_box_pack_start(GTK_BOX(main_vb), flow_type_fr, FALSE, FALSE, 5);

	flow_type_grid = ws_gtk_grid_new();
	gtk_container_set_border_width(GTK_CONTAINER(flow_type_grid), 5);
	gtk_container_add(GTK_CONTAINER(flow_type_fr), flow_type_grid);

	/* General information */
	select_general_rb = gtk_radio_button_new_with_mnemonic_from_widget(NULL, "_General flow");
	gtk_widget_set_tooltip_text (select_general_rb,	("Show all packets, with general information"));
	g_signal_connect(select_general_rb, "toggled", G_CALLBACK(toggle_select_general), NULL);
	ws_gtk_grid_attach_extended(GTK_GRID(flow_type_grid), select_general_rb, 0, 0, 1, 1,
				    (GtkAttachOptions)(GTK_FILL), (GtkAttachOptions)(0), 0, 0);
	if (graph_analysis->type == SEQ_ANALYSIS_ANY) {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(select_general_rb),TRUE);
	}
 	gtk_widget_show(select_general_rb);

	/* TCP specific information */
	select_tcp_rb = gtk_radio_button_new_with_mnemonic_from_widget(GTK_RADIO_BUTTON(select_general_rb),
								       "_TCP flow");
	gtk_widget_set_tooltip_text (select_tcp_rb, ("Show only TCP packets, with TCP specific information"));
	g_signal_connect(select_tcp_rb, "toggled", G_CALLBACK(toggle_select_tcp), NULL);
	ws_gtk_grid_attach_extended(GTK_GRID(flow_type_grid), select_tcp_rb, 0, 1, 1, 1,
				    (GtkAttachOptions)(GTK_FILL), (GtkAttachOptions)(0), 0, 0);
	if (graph_analysis->type == SEQ_ANALYSIS_TCP) {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(select_tcp_rb),TRUE);
	}
 	gtk_widget_show(select_tcp_rb);

	gtk_widget_show(flow_type_grid);
	gtk_widget_show(flow_type_fr);

	/*** Node address type frame ***/
	node_addr_fr = gtk_frame_new("Choose node address type");
	gtk_box_pack_start(GTK_BOX(main_vb), node_addr_fr, FALSE, FALSE, 5);

	node_addr_grid = ws_gtk_grid_new();
	gtk_container_set_border_width(GTK_CONTAINER(node_addr_grid), 5);
	gtk_container_add(GTK_CONTAINER(node_addr_fr), node_addr_grid);

	/* Source / Dest address */
	src_dst_rb = gtk_radio_button_new_with_mnemonic_from_widget(NULL, "_Standard source/destination addresses");
	gtk_widget_set_tooltip_text (src_dst_rb,
		("Nodes in the diagram are identified with source and destination addresses"));
	g_signal_connect(src_dst_rb, "toggled", G_CALLBACK(toggle_select_srcdst), NULL);
	ws_gtk_grid_attach_extended(GTK_GRID(node_addr_grid), src_dst_rb, 0, 0, 1, 1,
				    (GtkAttachOptions)(GTK_FILL), (GtkAttachOptions)(0), 0, 0);
	if (graph_analysis->any_addr) {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(src_dst_rb),TRUE);
	}
 	gtk_widget_show(src_dst_rb);

	/* Network source / dest address */
	net_src_dst_rb = gtk_radio_button_new_with_mnemonic_from_widget(GTK_RADIO_BUTTON(src_dst_rb),
									"_Network source/destination addresses");
	gtk_widget_set_tooltip_text (net_src_dst_rb,
		("Nodes in the diagram are identified with network source and destination addresses"));
	g_signal_connect(net_src_dst_rb, "toggled", G_CALLBACK(toggle_select_netsrcdst), NULL);
	ws_gtk_grid_attach_extended(GTK_GRID(node_addr_grid), net_src_dst_rb, 0, 1, 1, 1,
				    (GtkAttachOptions)(GTK_FILL), (GtkAttachOptions)(0), 0, 0);
	if (!graph_analysis->any_addr) {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(net_src_dst_rb),TRUE);
	}
 	gtk_widget_show(net_src_dst_rb);

	gtk_widget_show(node_addr_grid);
	gtk_widget_show(node_addr_fr);

	/* button row */
	hbuttonbox = gtk_button_box_new(GTK_ORIENTATION_HORIZONTAL);
	gtk_box_pack_start (GTK_BOX (main_vb), hbuttonbox, FALSE, FALSE, 5);
	gtk_button_box_set_layout (GTK_BUTTON_BOX (hbuttonbox), GTK_BUTTONBOX_SPREAD);
	gtk_box_set_spacing (GTK_BOX (hbuttonbox), 30);

	bt_ok = ws_gtk_button_new_from_stock(GTK_STOCK_OK);
	gtk_box_pack_start(GTK_BOX(hbuttonbox), bt_ok, TRUE, TRUE, 0);
	gtk_widget_set_tooltip_text (bt_ok, "Show the flow graph");
	g_signal_connect(bt_ok, "clicked", G_CALLBACK(flow_graph_on_ok), flow_graph_dlg_w);
	gtk_widget_show(bt_ok);

	bt_cancel = ws_gtk_button_new_from_stock(GTK_STOCK_CANCEL);
	gtk_box_pack_start(GTK_BOX(hbuttonbox), bt_cancel, TRUE, TRUE, 0);
	gtk_widget_set_can_default(bt_cancel, TRUE);
	gtk_widget_set_tooltip_text (bt_cancel, "Cancel this dialog");
	g_signal_connect(bt_cancel, "clicked", G_CALLBACK(flow_graph_on_cancel), flow_graph_dlg_w);

	g_signal_connect(flow_graph_dlg_w, "delete_event", G_CALLBACK(flow_graph_on_delete), NULL);
	g_signal_connect(flow_graph_dlg_w, "destroy", G_CALLBACK(flow_graph_on_destroy), NULL);

	gtk_widget_show_all(flow_graph_dlg_w);
	window_present(flow_graph_dlg_w);

	flow_graph_dlg = flow_graph_dlg_w;
}

/****************************************************************************/
/* PUBLIC								    */
/****************************************************************************/

/* init function for tap */
static void
flow_graph_init_tap(const char *dummy _U_, void *userdata _U_)
{
	/* The storage allocated by flow_graph_data_init() and graph_analysis_init()  */
	/*  will be considered to be "associated with" the flow_graph_dlg dialog box. */
	/* It will be freed when the flow_graph_dlg dialog box is destroyed.          */
	if (flow_graph_dlg != NULL) {
		g_assert(graph_analysis != NULL);
		g_assert(graph_analysis_data != NULL);
		/* There's already a dialog box; reactivate it. */
		reactivate_window(flow_graph_dlg);
	} else {
		g_assert(graph_analysis == NULL);
		g_assert(graph_analysis_data == NULL);

		/* initialize graph items store */
		flow_graph_data_init();

		/* init the Graph Analysis */
		graph_analysis_data = graph_analysis_init(graph_analysis);

		flow_graph_dlg_create();
	}
}


/****************************************************************************/
/* entry point when called via the GTK menu */
void
flow_graph_launch(GtkAction *action _U_, gpointer user_data _U_)
{
	flow_graph_init_tap("",NULL);
}

/****************************************************************************/
static stat_tap_ui flow_graph_ui = {
	REGISTER_STAT_GROUP_GENERIC,
	NULL,
	"flow_graph",
	flow_graph_init_tap,
	0,
	NULL
};

void
register_tap_listener_flow_graph(void)
{
	register_stat_tap_ui(&flow_graph_ui,NULL);
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

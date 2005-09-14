/* flow_graph.c
 * Allows to display a flow graph of the currently displayed packets
 *
 * Copyright 2004, Ericsson , Spain
 * By Francisco Alcoba <francisco.alcoba@ericsson.com>
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
 * Foundation,  Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include "register.h"

#include "globals.h"
#include "epan/filesystem.h"

#include "graph_analysis.h"
#include <epan/stat_cmd_args.h>
#include "../stat_menu.h"
#include "gui_stat_menu.h"
#include "dlg_utils.h"
#include "gui_utils.h"
#include "compat_macros.h"
#include "gtkglobals.h"

#include "simple_dialog.h"

#include <epan/to_str.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-tcp.h>

#include <string.h>

#define DISPLAYED 0
#define ALL 1
#define GENERAL 0
#define TCP 1

static int type_of_packets = DISPLAYED;
static int type_of_flow = GENERAL;

static int tap_identifier;
static gboolean have_frame_tap_listener=FALSE;
static gboolean have_tcp_tap_listener=FALSE;
static graph_analysis_info_t *graph_analysis = NULL;
static graph_analysis_data_t *graph_analysis_data;

static GtkWidget *flow_graph_dlg = NULL;

static GtkWidget *select_all_rb;
static GtkWidget *select_displayed_rb;
static GtkWidget *select_general_rb;
static GtkWidget *select_tcp_rb;

void flow_graph_data_init(void);


/****************************************************************************/
/* free up memory and initialize the pointers */

static void flow_graph_reset(void *ptr _U_)
{

	graph_analysis_item_t *graph_item;
	
	GList* list;

	if (graph_analysis !=NULL){

		/* free the graph data items */
		list = g_list_first(graph_analysis->list);
		while (list)
		{
			graph_item = list->data;
			g_free(graph_item->frame_label);
			g_free(graph_item->comment);
			g_free(list->data);
			list = g_list_next(list);
		}
		g_list_free(graph_analysis->list);
		graph_analysis->nconv = 0;
		graph_analysis->list = NULL;
	}
	return;
}

/****************************************************************************/
void flow_graph_data_init(void) {
	graph_analysis = g_malloc(sizeof(graph_analysis_info_t));
	graph_analysis->nconv = 0;
	graph_analysis->list = NULL;
	return;
}

/* XXX just copied from gtk/rpc_stat.c */
void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);

/****************************************************************************/
static void
remove_tap_listener_flow_graph(void)
{
	protect_thread_critical_region();
	remove_tap_listener(&(tap_identifier));
	unprotect_thread_critical_region();

	have_frame_tap_listener=FALSE;
	have_tcp_tap_listener=FALSE;
}


/****************************************************************************/
/* CALLBACKS                                                                */
/****************************************************************************/
static void
flow_graph_on_destroy(GtkObject *object _U_, gpointer user_data _U_)
{
	/* remove_tap_listeners */
	remove_tap_listener_flow_graph();

	/* Clean up memory used by tap */
	flow_graph_reset(NULL);

	/* Note that we no longer have a "Flow Graph" dialog box. */
	flow_graph_dlg = NULL;
}

	
/****************************************************************************/
static void
toggle_select_all(GtkWidget *widget _U_, gpointer user_data _U_)
{
  /* is the button now active? */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(select_all_rb))) {
		type_of_packets = ALL;
	}
}

/****************************************************************************/
static void
toggle_select_displayed(GtkWidget *widget _U_, gpointer user_data _U_)
{
  /* is the button now active? */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(select_displayed_rb))) {
		type_of_packets = DISPLAYED;
	}
}

/****************************************************************************/
static void
toggle_select_general(GtkWidget *widget _U_, gpointer user_data _U_)
{
  /* is the button now active? */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(select_general_rb))) {
		type_of_flow = GENERAL;
	}
}

/****************************************************************************/
static void
toggle_select_tcp(GtkWidget *widget _U_, gpointer user_data _U_)
{
  /* is the button now active? */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(select_tcp_rb))) {
		type_of_flow = TCP;
	}
}


/****************************************************************************/
/* Add a new frame into the graph */
static int flow_graph_frame_add_to_graph(packet_info *pinfo)
{
	graph_analysis_item_t *gai;
	int i;

	gai = g_malloc(sizeof(graph_analysis_item_t));
	gai->frame_num = pinfo->fd->num;
	gai->time= nstime_to_sec(&pinfo->fd->rel_ts);
	COPY_ADDRESS(&(gai->src_addr),&(pinfo->src));
	COPY_ADDRESS(&(gai->dst_addr),&(pinfo->dst));
	gai->port_src=pinfo->srcport;
	gai->port_dst=pinfo->destport;
	gai->comment=NULL;
	gai->frame_label=NULL;

	if (pinfo->cinfo->col_first[COL_INFO]>=0){
		
  		for (i = pinfo->cinfo->col_first[COL_INFO]; i <= pinfo->cinfo->col_last[COL_INFO]; i++) {
    		if (pinfo->cinfo->fmt_matx[i][COL_INFO]) {
				if (gai->frame_label!=NULL){
					g_free(gai->frame_label);
				}
				gai->comment = g_strdup(pinfo->cinfo->col_data[i]);
			}
		}
	}

	if (pinfo->cinfo->col_first[COL_PROTOCOL]>=0){
		
  		for (i = pinfo->cinfo->col_first[COL_PROTOCOL]; i <= pinfo->cinfo->col_last[COL_PROTOCOL]; i++) {
    		if (pinfo->cinfo->fmt_matx[i][COL_PROTOCOL]) {
				if (gai->frame_label!=NULL){
					g_free(gai->frame_label);
				}
				gai->frame_label = g_strdup(pinfo->cinfo->col_data[i]);
			}
		}
	}


	gai->line_style=1;
	gai->conv_num=0;
	gai->display=TRUE;

	graph_analysis->list = g_list_append(graph_analysis->list, gai);

	return 1;

}

/****************************************************************************/
/* Add a new tcp frame into the graph */
static int flow_graph_tcp_add_to_graph(packet_info *pinfo, const struct tcpheader *tcph)
{
	graph_analysis_item_t *gai;
	/* copied from packet-tcp */
	const gchar *fstr[] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECN", "CWR" };
	guint i, bpos;
	guint fpos = 0;
	gchar flags[64] = "<None>";

	gai = g_malloc(sizeof(graph_analysis_item_t));
	gai->frame_num = pinfo->fd->num;
	gai->time= nstime_to_sec(&pinfo->fd->rel_ts);
	COPY_ADDRESS(&(gai->src_addr),&(pinfo->src));
	COPY_ADDRESS(&(gai->dst_addr),&(pinfo->dst));
	gai->port_src=pinfo->srcport;
	gai->port_dst=pinfo->destport;

    for (i = 0; i < 8; i++) {
      bpos = 1 << i;
      if (tcph->th_flags & bpos) {
        if (fpos) {
          strcpy(&flags[fpos], ", ");
          fpos += 2;
        }
        strcpy(&flags[fpos], fstr[i]);
        fpos += 3;
      }
    }
    flags[fpos] = '\0';
    if ((tcph->th_have_seglen)&&(tcph->th_seglen!=0)){
      gai->frame_label = g_strdup_printf("%s - Len: %u",flags, tcph->th_seglen);
  	}
  	else{
      gai->frame_label = g_strdup(flags);
	}      

	gai->comment = g_strdup_printf("Seq = %i Ack = %i",tcph->th_seq, tcph->th_ack);

	gai->line_style=1;
	gai->conv_num=0;
	gai->display=TRUE;

	graph_analysis->list = g_list_append(graph_analysis->list, gai);

	return 1;

}



/****************************************************************************/
/* whenever a frame packet is seen by the tap listener */
static int 
flow_graph_frame_packet( void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *dummy _U_)
{

	if ((type_of_packets == ALL)||(pinfo->fd->flags.passed_dfilter==1)){
		flow_graph_frame_add_to_graph(pinfo);  
	}
	
	return 1;
}

/****************************************************************************/
/* whenever a TCP packet is seen by the tap listener */
static int 
flow_graph_tcp_packet( void *ptr _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *tcp_info)
{
	const struct tcpheader *tcph = tcp_info;

	if ((type_of_packets == ALL)||(pinfo->fd->flags.passed_dfilter==1)){
		flow_graph_tcp_add_to_graph(pinfo,tcph);  
	}
	
	return 1;
}


static void flow_graph_packet_draw(void *prs _U_)
{
	return; 
}

/****************************************************************************/
static void
flow_graph_on_ok                    (GtkButton       *button _U_,
                                        gpointer         user_data _U_)
{

	if ((have_frame_tap_listener==TRUE)
		||(have_tcp_tap_listener==TRUE))
	{ 
		/* remove_tap_listeners */
		remove_tap_listener_flow_graph();
	}
	
	/* Scan for displayed packets (retap all packets) */

	if (type_of_flow == GENERAL){
		/* Register the tap listener */

		if(have_frame_tap_listener==FALSE)
		{
			/* don't register tap listener, if we have it already */
			register_tap_listener("frame", &tap_identifier, NULL,
				flow_graph_reset, 
				flow_graph_frame_packet, 
				flow_graph_packet_draw
				);
			have_frame_tap_listener=TRUE;
		}

		cf_retap_packets(&cfile, TRUE);
	}
	else if (type_of_flow == TCP){
	/* Register the tap listener */

		if(have_tcp_tap_listener==FALSE)
		{
			/* don't register tap listener, if we have it already */
			register_tap_listener("tcp", &tap_identifier, NULL,
				flow_graph_reset, 
				flow_graph_tcp_packet, 
				flow_graph_packet_draw
				);
			have_tcp_tap_listener=TRUE;
		}

		cf_retap_packets(&cfile, FALSE);
	}

	if (graph_analysis_data->dlg.window != NULL){ /* if we still have a window */
		graph_analysis_update(graph_analysis_data);		/* refresh it xxx */
	}
	else{
		graph_analysis_create(graph_analysis_data);
	}

}


/****************************************************************************/
/* INTERFACE                                                                */
/****************************************************************************/

static void flow_graph_dlg_create (void)
{
	
	GtkWidget *flow_graph_dlg_w;
	GtkWidget *main_vb;
	GtkWidget *hbuttonbox;
	GtkWidget *bt_close, *bt_ok;
#if 0
	GtkWidget *top_label = NULL;
#endif
	GtkWidget *flow_type_fr, *range_fr, *range_tb, *flow_type_tb;
#if GTK_MAJOR_VERSION < 2
  GtkAccelGroup *accel_group;
#endif


	GtkTooltips *tooltips = gtk_tooltips_new();

	flow_graph_dlg_w=window_new(GTK_WINDOW_TOPLEVEL, "Ethereal: Flow Graph");

	gtk_window_set_default_size(GTK_WINDOW(flow_graph_dlg_w), 350, 150);

	main_vb = gtk_vbox_new (FALSE, 0);
	gtk_container_add(GTK_CONTAINER(flow_graph_dlg_w), main_vb);
	gtk_container_set_border_width (GTK_CONTAINER (main_vb), 12);

#if GTK_MAJOR_VERSION < 2
  /* Accelerator group for the accelerators (or, as they're called in
     Windows and, I think, in Motif, "mnemonics"; Alt+<key> is a mnemonic,
     Ctrl+<key> is an accelerator). */
  accel_group = gtk_accel_group_new();
  gtk_window_add_accel_group(GTK_WINDOW(main_vb), accel_group);
#endif

#if 0
	top_label = gtk_label_new ("Choose packets to include in the graph");
	gtk_box_pack_start (GTK_BOX (main_vb), top_label, FALSE, FALSE, 8);
#endif
	
	gtk_widget_show(flow_graph_dlg_w);

	/*** Packet range frame ***/
	range_fr = gtk_frame_new("Choose packets");
	gtk_box_pack_start(GTK_BOX(main_vb), range_fr, FALSE, FALSE, 0);

    range_tb = gtk_table_new(4, 4, FALSE);
    gtk_container_border_width(GTK_CONTAINER(range_tb), 5);
	gtk_container_add(GTK_CONTAINER(range_fr), range_tb);

	/* Process all packets */
	select_all_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(NULL, "_All packets", accel_group);
	gtk_tooltips_set_tip (tooltips, select_all_rb, 
		("Process all packets"), NULL);
	SIGNAL_CONNECT(select_all_rb, "toggled", toggle_select_all, NULL);
	gtk_table_attach_defaults(GTK_TABLE(range_tb), select_all_rb, 0, 1, 0, 1);
	if (type_of_packets == ALL) {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(select_all_rb),TRUE);
	}
  	gtk_widget_show(select_all_rb);

	/* Process displayed packets */
	select_displayed_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(select_all_rb, "_Displayed packets", accel_group);
	gtk_tooltips_set_tip (tooltips, select_displayed_rb, 
		("Process displayed packets"), NULL);
	SIGNAL_CONNECT(select_displayed_rb, "toggled", toggle_select_displayed, NULL);
	gtk_table_attach_defaults(GTK_TABLE(range_tb), select_displayed_rb, 1, 2, 0, 1);
	if (type_of_packets == DISPLAYED) {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(select_displayed_rb),TRUE);
	}
  	gtk_widget_show(select_displayed_rb);

	gtk_widget_show(range_tb);

	gtk_widget_show(range_fr);

	/*** Flow type frame ***/
	flow_type_fr = gtk_frame_new("Choose flow type");
	gtk_box_pack_start(GTK_BOX(main_vb), flow_type_fr, FALSE, FALSE, 0);

    flow_type_tb = gtk_table_new(4, 4, FALSE);
    gtk_container_border_width(GTK_CONTAINER(flow_type_tb), 5);
	gtk_container_add(GTK_CONTAINER(flow_type_fr), flow_type_tb);

	/* General information */
	select_general_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(NULL, "_General flow", accel_group);
	gtk_tooltips_set_tip (tooltips, select_general_rb, 
		("Show all packets, with general information"), NULL);
	SIGNAL_CONNECT(select_general_rb, "toggled", toggle_select_general, NULL);
	gtk_table_attach_defaults(GTK_TABLE(flow_type_tb), select_general_rb, 0, 1, 0, 1);
	if (type_of_flow == GENERAL) {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(select_general_rb),TRUE);
	}
  	gtk_widget_show(select_general_rb);

	/* TCP specific information */
	select_tcp_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(select_general_rb, "_TCP flow", accel_group);
	gtk_tooltips_set_tip (tooltips, select_tcp_rb, 
		("Show only TCP packets, with TCP specific information"), NULL);
	SIGNAL_CONNECT(select_tcp_rb, "toggled", toggle_select_tcp, NULL);
	gtk_table_attach_defaults(GTK_TABLE(flow_type_tb), select_tcp_rb, 1, 2, 0, 1);
	if (type_of_flow == TCP) {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(select_tcp_rb),TRUE);
	}

  	gtk_widget_show(select_tcp_rb);

	gtk_widget_show(flow_type_tb);
	gtk_widget_show(flow_type_fr);

        /* button row */
	hbuttonbox = gtk_hbutton_box_new ();
	gtk_box_pack_start (GTK_BOX (main_vb), hbuttonbox, FALSE, FALSE, 0);
	gtk_button_box_set_layout (GTK_BUTTON_BOX (hbuttonbox), GTK_BUTTONBOX_SPREAD);
	gtk_button_box_set_spacing (GTK_BUTTON_BOX (hbuttonbox), 30);

	bt_ok = BUTTON_NEW_FROM_STOCK(GTK_STOCK_OK);
	gtk_container_add(GTK_CONTAINER(hbuttonbox), bt_ok);
	gtk_tooltips_set_tip (tooltips, bt_ok, "Show the flow graph", NULL);
	SIGNAL_CONNECT(bt_ok, "clicked", flow_graph_on_ok, NULL);
	gtk_widget_show(bt_ok);

	bt_close = BUTTON_NEW_FROM_STOCK(GTK_STOCK_CLOSE);
	gtk_container_add (GTK_CONTAINER (hbuttonbox), bt_close);
	GTK_WIDGET_SET_FLAGS(bt_close, GTK_CAN_DEFAULT);
	gtk_tooltips_set_tip (tooltips, bt_close, "Close this dialog", NULL);
	window_set_cancel_button(flow_graph_dlg_w, bt_close, window_cancel_button_cb);

	SIGNAL_CONNECT(flow_graph_dlg_w, "delete_event", window_delete_event_cb, NULL);
	SIGNAL_CONNECT(flow_graph_dlg_w, "destroy", flow_graph_on_destroy, NULL);

	gtk_widget_show_all(flow_graph_dlg_w);
	window_present(flow_graph_dlg_w);

	flow_graph_dlg = flow_graph_dlg_w;
}	

/****************************************************************************/
/* PUBLIC								    */
/****************************************************************************/

/* init function for tap */
static void
flow_graph_init_tap(const char *dummy _U_)
{

	/* initialize graph items store */
	flow_graph_data_init();
	
	/* init the Graph Analysys */
	graph_analysis_data = graph_analysis_init();
	graph_analysis_data->graph_info = graph_analysis;

	/* create dialog box if necessary */
	if (flow_graph_dlg == NULL) {
		flow_graph_dlg_create();
	} else {
		/* There's already a dialog box; reactivate it. */
		reactivate_window(flow_graph_dlg);
	}

}


/****************************************************************************/
/* entry point when called via the GTK menu */
static void flow_graph_launch(GtkWidget *w _U_, gpointer data _U_)
{
	flow_graph_init_tap("");
}

/****************************************************************************/
void
register_tap_listener_flow_graph(void)
{
	register_stat_cmd_arg("flow_graph",flow_graph_init_tap);
	register_stat_menu_item("Flo_w Graph...", REGISTER_STAT_GROUP_NONE,
	    flow_graph_launch, NULL, NULL, NULL);
	    
}


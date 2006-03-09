/* voip_calls_dlg.c
 * VoIP calls summary addition for ethereal
 *
 * $Id$
 *
 * Copyright 2004, Ericsson , Spain
 * By Francisco Alcoba <francisco.alcoba@ericsson.com>
 *
 * based on h323_calls_dlg.c
 * Copyright 2004, Iskratel, Ltd, Kranj
 * By Miha Jemec <m.jemec@iskratel.si>
 *
 * H323, RTP and Graph Support
 * By Alejandro Vaquero, alejandro.vaquero@verso.com
 * Copyright 2005, Verso Technologies Inc.
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

#include <string.h>
#include <ctype.h>

#include "register.h"

#include "graph_analysis.h"
#include "voip_calls_dlg.h"
#include "voip_calls.h"

#include "globals.h"
#include "epan/filesystem.h"

#include <epan/tap.h>
#include <epan/stat_cmd_args.h>
#include "../stat_menu.h"
#include "gui_stat_menu.h"
#include "dlg_utils.h"
#include "gui_utils.h"
#include "compat_macros.h"
#include "gtkglobals.h"

#include "image/clist_ascend.xpm"
#include "image/clist_descend.xpm"
#include "simple_dialog.h"

#include <epan/to_str.h>

#include <string.h>
#include <ctype.h>
#include <epan/address.h>
#include <epan/addr_resolv.h>
 
static const gchar FWD_LABEL_TEXT[] = "Select one call.";

/****************************************************************************/
/* pointer to the one and only dialog window */
static GtkWidget *voip_calls_dlg = NULL;

static GtkWidget *clist = NULL;
static GtkWidget *top_label = NULL;
static GtkWidget *status_label = NULL;
static GtkWidget *label_fwd = NULL;

/*static GtkWidet *bt_unselect = NULL;*/
static GtkWidget *bt_filter = NULL;
static GtkWidget *bt_graph = NULL;


static voip_calls_info_t* selected_call_fwd = NULL;  /* current selection */
static GList *last_list = NULL;

static guint32 calls_nb = 0;     /* number of displayed calls */
static guint32 calls_ns = 0;     /* number of selected calls */

static graph_analysis_data_t *graph_analysis_data = NULL;

#define NUM_COLS 9
static const GdkColor COLOR_SELECT = {0, 0x00ff, 0x80ff, 0x80ff};
static const GdkColor COLOR_DEFAULT = {0, 0xffff, 0xffff, 0xffff};

/****************************************************************************/
/* append a line to clist */
static void add_to_clist(voip_calls_info_t* strinfo)
{
	gchar label_text[256];
	gint added_row;
	gchar *data[NUM_COLS];
	gchar field[NUM_COLS][50];
	gint c;
	isup_calls_info_t *tmp_isupinfo;
	h323_calls_info_t *tmp_h323info;
	gboolean tmp_bool = FALSE;
	GdkColor color = COLOR_SELECT;
	for (c=0;c<NUM_COLS;c++){
		data[c]=&field[c][0];
	}

/*	strinfo->selected = FALSE;*/

	g_snprintf(field[0], 15, "%i.%2i", strinfo->start_sec, strinfo->start_usec/10000);
	g_snprintf(field[1], 15, "%i.%2i", strinfo->stop_sec, strinfo->stop_usec/10000);
/*	xxx display_signed_time(data[0], sizeof(field[0]), strinfo->start_sec, strinfo->start_usec, USECS); */
/*	display_signed_time(data[1], sizeof(field[0]), strinfo->stop_sec, strinfo->stop_usec, USECS); */
	g_snprintf(field[2], 30, "%s", get_addr_name(&(strinfo->initial_speaker)));
	g_snprintf(field[3], 50, "%s", strinfo->from_identity);
	g_snprintf(field[4], 50, "%s", strinfo->to_identity);
	g_snprintf(field[5], 15, "%s", voip_protocol_name[strinfo->protocol]);
	g_snprintf(field[6], 15, "%u", strinfo->npackets);
	g_snprintf(field[7], 15, "%s", voip_call_state_name[strinfo->call_state]);

	/* Add comments based on the protocol */
	switch(strinfo->protocol){
		case VOIP_ISUP:
			tmp_isupinfo = strinfo->prot_info;
			g_snprintf(field[8],30, "%i-%i -> %i-%i", tmp_isupinfo->ni, tmp_isupinfo->opc,
				tmp_isupinfo->ni, tmp_isupinfo->dpc);
			break;
		case VOIP_H323:
			tmp_h323info = strinfo->prot_info;
			if (strinfo->call_state == VOIP_CALL_SETUP) 
				tmp_bool = tmp_h323info->is_faststart_Setup;
			else
				if ((tmp_h323info->is_faststart_Setup == TRUE) && (tmp_h323info->is_faststart_Proc == TRUE)) tmp_bool = TRUE; 
			g_snprintf(field[8],35, "Tunneling: %s  Fast Start: %s", (tmp_h323info->is_h245Tunneling==TRUE?"ON":"OFF"), 
				(tmp_bool==TRUE?"ON":"OFF"));
			break;
		default:
			field[8][0]='\0';
	}

	
	added_row = gtk_clist_append(GTK_CLIST(clist), data);

	/* set the background color if selected */
	if (strinfo->selected) { 
		calls_ns++;
		gtk_clist_set_background(GTK_CLIST(clist), added_row, &color);
	}

	/* set data pointer of last row to point to user data for that row */
	gtk_clist_set_row_data(GTK_CLIST(clist), added_row, strinfo);

	/* Update the top label with the number of detected calls */
	calls_nb++;
	g_snprintf(label_text, 256,
	        "Detected %d VoIP %s. Selected %d %s.",
	        calls_nb, 
		plurality(calls_nb, "Call", "Calls"),
		calls_ns,
		plurality(calls_ns, "Call", "Calls"));
	gtk_label_set(GTK_LABEL(top_label), label_text);

	/* Update the status label with the number of total messages */
        g_snprintf(label_text, 256,
       		"Total: Calls: %d   Start packets: %d   Completed calls: %d   Rejected calls: %d",
			g_list_length(voip_calls_get_info()->strinfo_list),
			voip_calls_get_info()->start_packets, 
			voip_calls_get_info()->completed_calls,
			voip_calls_get_info()->rejected_calls);
        gtk_label_set(GTK_LABEL(status_label), label_text);
}


static void voip_calls_remove_tap_listener(void)
{
	/* Remove the calls tap listener */
	remove_tap_listener_sip_calls();
	remove_tap_listener_isup_calls();
	remove_tap_listener_mtp3_calls();
	remove_tap_listener_h225_calls();
	remove_tap_listener_h245dg_calls();
	remove_tap_listener_q931_calls();
	remove_tap_listener_sdp_calls();
	remove_tap_listener_rtp();
	remove_tap_listener_rtp_event();
	if (find_tap_id("mgcp")) {
		remove_tap_listener_mgcp_calls();
	}
	remove_tap_listener_actrace_calls();
	remove_tap_listener_t38();
}

/****************************************************************************/
/* CALLBACKS                                                                */
/****************************************************************************/
static void
voip_calls_on_destroy                      (GtkObject       *object _U_,
                                        gpointer         user_data _U_)
{
	/* remove_tap_listeners */
	voip_calls_remove_tap_listener();

	/* Clean up memory used by calls tap */
	voip_calls_dlg_reset(NULL);

	/* Note that we no longer have a "VoIP Calls" dialog box. */
	voip_calls_dlg = NULL;

	graph_analysis_data = NULL;
}


/****************************************************************************/
static void
voip_calls_on_unselect                  (GtkButton       *button _U_,
                                        gpointer         user_data _U_)
{
	selected_call_fwd = NULL;
	gtk_clist_unselect_all(GTK_CLIST(clist));
	gtk_label_set_text(GTK_LABEL(label_fwd), FWD_LABEL_TEXT);

	/*gtk_widget_set_sensitive(bt_unselect, FALSE);*/
	gtk_widget_set_sensitive(bt_filter, FALSE);
	gtk_widget_set_sensitive(bt_graph, FALSE);
}


/****************************************************************************/
static void
voip_calls_on_filter                    (GtkButton       *button _U_,
                                        gpointer         user_data _U_)
{
	const gchar *filter_string;
	gchar c;
	GString *filter_string_fwd;
	const gchar *filter_prepend;
	gboolean isFirst = TRUE;
	GList* list;
	guint filter_length = 0;
	guint max_filter_length = 2048;
	sip_calls_info_t *tmp_sipinfo;
	isup_calls_info_t *tmp_isupinfo;
	h323_calls_info_t *tmp_h323info;
	h245_address_t *h245_add = NULL;

	graph_analysis_item_t *gai;

	if (selected_call_fwd==NULL)
		return;

	filter_string=gtk_entry_get_text(GTK_ENTRY(main_display_filter_widget));
	filter_length = strlen(filter_string);
	filter_prepend = "";
	while ((c = *filter_string++) != '\0') {
		if (!isspace((guchar)c)) {
			/* The filter string isn't blank, so there's already
			   an expression; we OR in the new expression */
			filter_prepend = " or ";
			break;
		}
	}
		
	filter_string_fwd = g_string_new(filter_prepend);
	
	/* look in the Graph and get all the frame_num for this call */
	g_string_sprintfa(filter_string_fwd, " (");
	list = g_list_first(voip_calls_get_info()->graph_analysis->list);
	while (list)
	{
		gai = list->data;
		if (gai->conv_num == selected_call_fwd->call_num){
			g_string_sprintfa(filter_string_fwd,"%sframe.number == %d", isFirst?"":" or ", gai->frame_num );
			isFirst = FALSE;
		}		
		list = g_list_next (list);
	}
	g_string_sprintfa(filter_string_fwd, ") ");
	filter_length = filter_length + filter_string_fwd->len;

	if (filter_length < max_filter_length){
		gtk_entry_append_text(GTK_ENTRY(main_display_filter_widget), filter_string_fwd->str);
	}
	else{

		g_string_free(filter_string_fwd, TRUE);
		filter_string_fwd = g_string_new(filter_prepend);

		switch(selected_call_fwd->protocol){
			case VOIP_SIP:
				tmp_sipinfo = selected_call_fwd->prot_info;
				g_string_sprintfa(filter_string_fwd,
				   "(sip.Call-ID == \"%s\") ",
				   tmp_sipinfo->call_identifier 
				   );
				gtk_entry_append_text(GTK_ENTRY(main_display_filter_widget), filter_string_fwd->str);
				break;
			case VOIP_ISUP:
				tmp_isupinfo = selected_call_fwd->prot_info;
				g_string_sprintfa(filter_string_fwd,
				   "(isup.cic == %i and frame.number >=%i and frame.number<=%i and mtp3.network_indicator == %i and ((mtp3.dpc == %i) and (mtp3.opc == %i)) or((mtp3.dpc == %i) and (mtp3.opc == %i))) ",
				   tmp_isupinfo->cic,selected_call_fwd->first_frame_num,
				   selected_call_fwd->last_frame_num, 
				   tmp_isupinfo->ni, tmp_isupinfo->dpc, tmp_isupinfo->opc, 
				   tmp_isupinfo->opc, tmp_isupinfo->dpc
				   );
				gtk_entry_append_text(GTK_ENTRY(main_display_filter_widget), filter_string_fwd->str);
				break;
			case VOIP_H323:
				tmp_h323info = selected_call_fwd->prot_info;
				g_string_sprintfa(filter_string_fwd,
				   "((h225.guid == %x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x || q931.call_ref == %x:%x || q931.call_ref == %x:%x) ",
				   (guint8)tmp_h323info->guid[0], (guint8)tmp_h323info->guid[1], (guint8)tmp_h323info->guid[2],
				   (guint8)tmp_h323info->guid[3], (guint8)tmp_h323info->guid[4], (guint8)tmp_h323info->guid[5], (guint8)tmp_h323info->guid[6],
			   (guint8)tmp_h323info->guid[7], (guint8)tmp_h323info->guid[8], (guint8)tmp_h323info->guid[9], (guint8)tmp_h323info->guid[10],
				   (guint8)tmp_h323info->guid[11], (guint8)tmp_h323info->guid[12], (guint8)tmp_h323info->guid[13], (guint8)tmp_h323info->guid[14],
				   (guint8)tmp_h323info->guid[15], (guint8)(tmp_h323info->q931_crv & 0xff), (guint8)((tmp_h323info->q931_crv & 0xff00)>>8)
				   , (guint8)(tmp_h323info->q931_crv2 & 0xff), (guint8)((tmp_h323info->q931_crv2 & 0xff00)>>8));
				list = g_list_first(tmp_h323info->h245_list);
				while (list)
				{
					h245_add=list->data;
					g_string_sprintfa(filter_string_fwd,
						" || (ip.addr == %s && tcp.port == %d && h245) ", 
						ip_to_str((guint8 *)&(h245_add->h245_address)), h245_add->h245_port);
				list = g_list_next(list);
				}
				g_string_sprintfa(filter_string_fwd, ") ");
				gtk_entry_append_text(GTK_ENTRY(main_display_filter_widget), filter_string_fwd->str);
				break;
			case VOIP_MGCP:
			case VOIP_AC_ISDN:
			case VOIP_AC_CAS:
			case MEDIA_T38:
				/* XXX - not supported */
				break;
		}
		
	}
	
	g_string_free(filter_string_fwd, TRUE);
}




/****************************************************************************/
static void
on_graph_bt_clicked                    (GtkButton       *button _U_,
                                        gpointer         user_data _U_)
{
	graph_analysis_item_t *gai;
	GList* list;
	GList* list2;
	voip_calls_info_t *tmp_listinfo;

	/* reset the "display" parameter in graph analysis */
	list2 = g_list_first(voip_calls_get_info()->graph_analysis->list);
	while (list2){
		gai = list2->data;
		gai->display = FALSE;
		list2 = g_list_next(list2);
	}


	/* set the display for selected calls */
	list = g_list_first(voip_calls_get_info()->strinfo_list);
	while (list){
		tmp_listinfo=list->data;
		if (tmp_listinfo->selected){
			list2 = g_list_first(voip_calls_get_info()->graph_analysis->list);
			while (list2){
				gai = list2->data;
				if (gai->conv_num == tmp_listinfo->call_num){
					gai->display = TRUE;
				}
				list2 = g_list_next(list2);
			}
		}
		list = g_list_next(list);
	}

	/* create or refresh the graph windows */
	if (graph_analysis_data->dlg.window == NULL)	/* create the window */
		graph_analysis_create(graph_analysis_data);
	else
		graph_analysis_update(graph_analysis_data);		/* refresh it */
}

/****************************************************************************/
/* when the user selects a row in the calls list */
static void
voip_calls_on_select_row(GtkCList *clist,
                                            gint row _U_,
                                            gint column _U_,
                                            GdkEventButton *event _U_,
                                            gpointer user_data _U_)
{
	GdkColor color = COLOR_DEFAULT;
	gchar label_text[80];
	
	selected_call_fwd = gtk_clist_get_row_data(GTK_CLIST(clist), row);

	if (selected_call_fwd==NULL)
		return;

	if (!selected_call_fwd->selected)
		calls_ns++;
	else
		calls_ns--;

	g_snprintf(label_text, 80,
	        "Detected %d VoIP %s. Selected %d %s.",
	        calls_nb, 
            plurality(calls_nb, "Call", "Calls"),
			calls_ns,
			plurality(calls_ns, "Call", "Calls"));
	gtk_label_set(GTK_LABEL(top_label), label_text);

	g_snprintf(label_text, 80, "Selected Call: From  %s  To %s, starting time %i.%i",
		selected_call_fwd->from_identity,
		selected_call_fwd->to_identity,
		selected_call_fwd->start_sec, 
		selected_call_fwd->start_usec
	);
	gtk_label_set_text(GTK_LABEL(label_fwd), label_text);

	selected_call_fwd->selected=!selected_call_fwd->selected;
	if (selected_call_fwd->selected)
		color = COLOR_SELECT;
	else
		color = COLOR_DEFAULT;

	gtk_clist_set_background(GTK_CLIST(clist), row, &color);

	if 	(calls_ns > 0) {
		gtk_widget_set_sensitive(bt_filter, TRUE);
		gtk_widget_set_sensitive(bt_graph, TRUE);
	} else {
		gtk_widget_set_sensitive(bt_filter, FALSE);
		gtk_widget_set_sensitive(bt_graph, FALSE);
	}

	/* TODO: activate other buttons when implemented */
}


/****************************************************************************/

typedef struct column_arrows {
	GtkWidget *table;
	GtkWidget *ascend_pm;
	GtkWidget *descend_pm;
} column_arrows;


/****************************************************************************/
static void
voip_calls_click_column_cb(GtkCList *clist, gint column, gpointer data)
{
	column_arrows *col_arrows = (column_arrows *) data;
	int i;

	gtk_clist_freeze(clist);

	for (i=0; i<NUM_COLS; i++) {
		gtk_widget_hide(col_arrows[i].ascend_pm);
		gtk_widget_hide(col_arrows[i].descend_pm);
	}

	if (column == clist->sort_column) {
		if (clist->sort_type == GTK_SORT_ASCENDING) {
			clist->sort_type = GTK_SORT_DESCENDING;
			gtk_widget_show(col_arrows[column].descend_pm);
		} else {
			clist->sort_type = GTK_SORT_ASCENDING;
			gtk_widget_show(col_arrows[column].ascend_pm);
		}
	} else {
		clist->sort_type = GTK_SORT_ASCENDING;
		gtk_widget_show(col_arrows[column].ascend_pm);
		gtk_clist_set_sort_column(clist, column);
	}
	gtk_clist_thaw(clist);

	gtk_clist_sort(clist);
}


/****************************************************************************/
static gint
voip_calls_sort_column(GtkCList *clist, gconstpointer ptr1, gconstpointer ptr2)
{
	char *text1 = NULL;
	char *text2 = NULL;
	guint i1, i2, i3, i4;

	const GtkCListRow *row1 = (const GtkCListRow *) ptr1;
	const GtkCListRow *row2 = (const GtkCListRow *) ptr2;

	text1 = GTK_CELL_TEXT (row1->cell[clist->sort_column])->text;
	text2 = GTK_CELL_TEXT (row2->cell[clist->sort_column])->text;

	switch(clist->sort_column){
	case 0:
	case 1:
		if ((sscanf(text1, "%u.%u", &i1, &i2) != 2) ||
			(sscanf(text2, "%u.%u", &i3, &i4) != 2) ){
				return 0;
			}
		if (i1>i3)
			return 1;
		if (i1<i3)
			return -1;
		return (i3-i4);
	case 2:
	case 3:
	case 4:
	case 5:
	case 7:
	case 8:
		return strcmp (text1, text2);
	case 6:
		i1=atoi(text1);
		i2=atoi(text2);
		return i1-i2;
	}
	g_assert_not_reached();
	return 0;
}


/****************************************************************************/
/* INTERFACE                                                                */
/****************************************************************************/

static void voip_calls_dlg_create (void)
{
	GtkWidget *voip_calls_dlg_w;
	GtkWidget *main_vb;
	GtkWidget *scrolledwindow;
	GtkWidget *hbuttonbox;
	GtkWidget *bt_close;
	GtkTooltips *tooltips = gtk_tooltips_new();

	const gchar *titles[NUM_COLS] =  {"Start Time", "Stop Time", "Initial Speaker", "From",  "To", "Protocol", "Packets", "State", "Comments"};
	column_arrows *col_arrows;
	GtkWidget *column_lb;
	int i;

	voip_calls_dlg_w=window_new(GTK_WINDOW_TOPLEVEL, "Ethereal: VoIP Calls");

	gtk_window_set_default_size(GTK_WINDOW(voip_calls_dlg_w), 840, 350);

	main_vb = gtk_vbox_new (FALSE, 0);
	gtk_container_add(GTK_CONTAINER(voip_calls_dlg_w), main_vb);
	gtk_container_set_border_width (GTK_CONTAINER (main_vb), 12);

	top_label = gtk_label_new ("Detected 0 VoIP Calls. Selected 0 Calls.");
	gtk_box_pack_start (GTK_BOX (main_vb), top_label, FALSE, FALSE, 8);

	scrolledwindow = scrolled_window_new (NULL, NULL);
	gtk_box_pack_start (GTK_BOX (main_vb), scrolledwindow, TRUE, TRUE, 0);

	clist = gtk_clist_new (NUM_COLS);
	gtk_container_add (GTK_CONTAINER (scrolledwindow), clist);

	gtk_clist_set_column_width (GTK_CLIST (clist), 0, 60);
	gtk_clist_set_column_width (GTK_CLIST (clist), 1, 60);
	gtk_clist_set_column_width (GTK_CLIST (clist), 2, 80);
	gtk_clist_set_column_width (GTK_CLIST (clist), 3, 130);
	gtk_clist_set_column_width (GTK_CLIST (clist), 4, 130);
	gtk_clist_set_column_width (GTK_CLIST (clist), 5, 50);
	gtk_clist_set_column_width (GTK_CLIST (clist), 6, 45);
	gtk_clist_set_column_width (GTK_CLIST (clist), 7, 60);
	gtk_clist_set_column_width (GTK_CLIST (clist), 8, 100);

	gtk_clist_set_column_justification(GTK_CLIST(clist), 0, GTK_JUSTIFY_LEFT);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 1, GTK_JUSTIFY_LEFT);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 2, GTK_JUSTIFY_LEFT);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 3, GTK_JUSTIFY_LEFT);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 4, GTK_JUSTIFY_LEFT);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 5, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 6, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 7, GTK_JUSTIFY_LEFT);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 8, GTK_JUSTIFY_LEFT);

	gtk_clist_column_titles_show (GTK_CLIST (clist));

	gtk_clist_set_compare_func(GTK_CLIST(clist), voip_calls_sort_column);
	gtk_clist_set_sort_column(GTK_CLIST(clist), 0);
	gtk_clist_set_sort_type(GTK_CLIST(clist), GTK_SORT_ASCENDING);

	gtk_widget_show(voip_calls_dlg_w);

	/* sort by column feature */
	col_arrows = (column_arrows *) g_malloc(sizeof(column_arrows) * NUM_COLS);

	for (i=0; i<NUM_COLS; i++) {
		col_arrows[i].table = gtk_table_new(2, 2, FALSE);
		gtk_table_set_col_spacings(GTK_TABLE(col_arrows[i].table), 5);
		column_lb = gtk_label_new(titles[i]);
		gtk_table_attach(GTK_TABLE(col_arrows[i].table), column_lb, 0, 1, 0, 2, GTK_SHRINK, GTK_SHRINK, 0, 0);
		gtk_widget_show(column_lb);

		col_arrows[i].ascend_pm = xpm_to_widget(clist_ascend_xpm);
		gtk_table_attach(GTK_TABLE(col_arrows[i].table), col_arrows[i].ascend_pm, 1, 2, 1, 2, GTK_SHRINK, GTK_SHRINK, 0, 0);
		col_arrows[i].descend_pm = xpm_to_widget(clist_descend_xpm);
		gtk_table_attach(GTK_TABLE(col_arrows[i].table), col_arrows[i].descend_pm, 1, 2, 0, 1, GTK_SHRINK, GTK_SHRINK, 0, 0);
		/* make start time be the default sort order */
		if (i == 0) {
			gtk_widget_show(col_arrows[i].ascend_pm);
		}
		gtk_clist_set_column_widget(GTK_CLIST(clist), i, col_arrows[i].table);
		gtk_widget_show(col_arrows[i].table);
	}

	SIGNAL_CONNECT(clist, "click-column", voip_calls_click_column_cb, col_arrows);

	label_fwd = gtk_label_new (FWD_LABEL_TEXT);
	gtk_box_pack_start (GTK_BOX (main_vb), label_fwd, FALSE, FALSE, 0);

	status_label = gtk_label_new ("Total: Calls: 0   Start packets: 0   Completed calls: 0   Rejected calls: 0");
	gtk_box_pack_start (GTK_BOX (main_vb), status_label, FALSE, FALSE, 8);

        /* button row */
	hbuttonbox = gtk_hbutton_box_new ();
	gtk_box_pack_start (GTK_BOX (main_vb), hbuttonbox, FALSE, FALSE, 0);
	gtk_button_box_set_layout (GTK_BUTTON_BOX (hbuttonbox), GTK_BUTTONBOX_SPREAD);
	gtk_button_box_set_spacing (GTK_BUTTON_BOX (hbuttonbox), 30);

	/*bt_unselect = gtk_button_new_with_label ("Unselect");
	gtk_container_add (GTK_CONTAINER (hbuttonbox), bt_unselect);
	gtk_tooltips_set_tip (tooltips, bt_unselect, "Unselect this conversation", NULL);*/

	bt_filter = gtk_button_new_with_label ("Prepare Filter");
	gtk_container_add (GTK_CONTAINER (hbuttonbox), bt_filter);
	gtk_tooltips_set_tip (tooltips, bt_filter, "Prepare a display filter of the selected conversation", NULL);

	bt_graph = gtk_button_new_with_label("Graph");
	gtk_container_add(GTK_CONTAINER(hbuttonbox), bt_graph);
	gtk_widget_show(bt_graph);
	SIGNAL_CONNECT(bt_graph, "clicked", on_graph_bt_clicked, NULL);
	gtk_tooltips_set_tip (tooltips, bt_graph, "Show a flow graph of the selected calls.", NULL);

	bt_close = BUTTON_NEW_FROM_STOCK(GTK_STOCK_CLOSE);
	gtk_container_add (GTK_CONTAINER (hbuttonbox), bt_close);
	GTK_WIDGET_SET_FLAGS(bt_close, GTK_CAN_DEFAULT);
	gtk_tooltips_set_tip (tooltips, bt_close, "Close this dialog", NULL);

	SIGNAL_CONNECT(clist, "select_row", voip_calls_on_select_row, NULL);
	/*SIGNAL_CONNECT(bt_unselect, "clicked", voip_calls_on_unselect, NULL);*/
	SIGNAL_CONNECT(bt_filter, "clicked", voip_calls_on_filter, NULL);

	window_set_cancel_button(voip_calls_dlg_w, bt_close, window_cancel_button_cb);

	SIGNAL_CONNECT(voip_calls_dlg_w, "delete_event", window_delete_event_cb, NULL);
	SIGNAL_CONNECT(voip_calls_dlg_w, "destroy", voip_calls_on_destroy, NULL);

	gtk_widget_show_all(voip_calls_dlg_w);
	window_present(voip_calls_dlg_w);

	voip_calls_on_unselect(NULL, NULL);

	voip_calls_dlg = voip_calls_dlg_w;
}


/****************************************************************************/
/* PUBLIC								    */
/****************************************************************************/

/****************************************************************************/
/* update the contents of the dialog box clist */
/* list: pointer to list of voip_calls_info_t* */

void voip_calls_dlg_update(GList *list)
{
	gchar label_text[256];
	if (voip_calls_dlg != NULL) {
		calls_nb = 0;
		calls_ns = 0;

       	g_snprintf(label_text, 256,
       		"Total: Calls: %d   Start packets: %d   Completed calls: %d   Rejected calls: %d",
		g_list_length(voip_calls_get_info()->strinfo_list),
        voip_calls_get_info()->start_packets, 
		voip_calls_get_info()->completed_calls,
		voip_calls_get_info()->rejected_calls);
       	gtk_label_set(GTK_LABEL(status_label), label_text);

		gtk_clist_freeze(GTK_CLIST(clist));
		gtk_clist_clear(GTK_CLIST(clist));
		list = g_list_first(list);
		while (list)
		{
			add_to_clist((voip_calls_info_t*)(list->data));
			list = g_list_next(list);
		}
		gtk_clist_thaw(GTK_CLIST(clist));

		g_snprintf(label_text, 256,
	        	"Detected %d VoIP %s. Selected %d %s.",
			calls_nb, 
			plurality(calls_nb, "Call", "Calls"),
			calls_ns,
			plurality(calls_ns, "Call", "Calls"));
		gtk_label_set(GTK_LABEL(top_label), label_text);
	}

	last_list = list;
}


/****************************************************************************/
/* draw function for tap listeners to keep the window up to date */
void voip_calls_dlg_draw(void *ptr _U_)
{
	if (voip_calls_get_info()->redraw) {
		voip_calls_dlg_update(voip_calls_get_info()->strinfo_list);
		voip_calls_get_info()->redraw = FALSE;
	}
}

/* reset function for tap listeners to clear window, if necessary */
void voip_calls_dlg_reset(void *ptr _U_)
{
	/* Clean up memory used by calls tap */
	voip_calls_reset((voip_calls_tapinfo_t*) voip_calls_get_info());

	/* close the graph window if open */
	if (graph_analysis_data->dlg.window != NULL) {
		window_cancel_button_cb(NULL, graph_analysis_data->dlg.window);
		graph_analysis_data->dlg.window = NULL;
	}
}

/* init function for tap */
/* Made extern only for "Fax T38 Analysis..." */
void
voip_calls_init_tap(const char *dummy _U_, void* userdata _U_)
{
	gint c;
	gchar *data[NUM_COLS];
	gchar field[NUM_COLS][50];

	if (graph_analysis_data == NULL) {
		graph_analysis_data_init();
		/* init the Graph Analysys */
		graph_analysis_data = graph_analysis_init();
		graph_analysis_data->graph_info = voip_calls_get_info()->graph_analysis;
	}

	/* Clean up memory used by calls tap */
	voip_calls_reset((voip_calls_tapinfo_t*) voip_calls_get_info());

	/* Register the tap listener */
	sip_calls_init_tap();
	mtp3_calls_init_tap();
	isup_calls_init_tap();
	h225_calls_init_tap();
	h245dg_calls_init_tap();
	q931_calls_init_tap();
	sdp_calls_init_tap();
	rtp_init_tap();
	rtp_event_init_tap();
	/* We don't register this tap, if we don't have the mgcp plugin loaded.*/
	if (find_tap_id("mgcp")) {
		mgcp_calls_init_tap();
	}
	actrace_calls_init_tap();
	t38_init_tap();

	/* create dialog box if necessary */
	if (voip_calls_dlg == NULL) {
		voip_calls_dlg_create();
	} else {
		/* There's already a dialog box; reactivate it. */
		reactivate_window(voip_calls_dlg);
	}

	voip_calls_get_info()->redraw = TRUE;
	voip_calls_dlg_draw(NULL);
	voip_calls_get_info()->redraw = TRUE;
	for (c=0;c<NUM_COLS;c++){
		data[c]=&field[c][0];
		field[c][0] = '\0';
	}
	g_snprintf(field[3], 50, "Please wait...");
	gtk_clist_append(GTK_CLIST(clist), data);
	
	/* Scan for VoIP calls calls (redissect all packets) */
	cf_retap_packets(&cfile, FALSE);

	/* Tap listener will be removed and cleaned up in voip_calls_on_destroy */
}


/****************************************************************************/
/* entry point when called via the GTK menu */
static void voip_calls_launch(GtkWidget *w _U_, gpointer data _U_)
{
	voip_calls_init_tap("",NULL);
}

/****************************************************************************/
void
register_tap_listener_voip_calls_dlg(void)
{
	register_stat_cmd_arg("voip,calls",voip_calls_init_tap,NULL);
	register_stat_menu_item("VoIP Calls", REGISTER_STAT_GROUP_TELEPHONY,
	    voip_calls_launch, NULL, NULL, NULL);
	    
}

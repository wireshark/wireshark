/* h323_conversations_dlg.c
 * H323 conversations summary addition for ethereal
 *
 * $Id$
 *
 * Copyright 2004, Iskratel, Ltd, Kranj
 * By Miha Jemec <m.jemec@iskratel.si>
 *
 * based on rtp_stream_dlg.c
 * Copyright 2003, Alcatel Business Systems
 * By Lars Ruoff <lars.ruoff@gmx.net>
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

#include "h323_conversations_dlg.h"
#include "h323_conversations.h"
#include "h323_analysis.h"

#include "globals.h"
#include "epan/filesystem.h"

#include "tap_menu.h"
#include "dlg_utils.h"
#include "ui_util.h"
#include "compat_macros.h"
#include "gtkglobals.h"

#include "image/clist_ascend.xpm"
#include "image/clist_descend.xpm"

#include <string.h>


typedef const guint8 * ip_addr_p;

static const gchar FWD_LABEL_TEXT[] = "Select one conversation.";

/****************************************************************************/
/* pointer to the one and only dialog window */
static GtkWidget *h323_conversations_dlg = NULL;

static GtkWidget *clist = NULL;
static GtkWidget *top_label = NULL;
static GtkWidget *status_label = NULL;
static GtkWidget *label_fwd = NULL;

/*static GtkWidget *bt_unselect = NULL;*/
static GtkWidget *bt_filter = NULL;
static GtkWidget *bt_analyze = NULL;

static h323_conversations_info_t* selected_conversations_fwd = NULL;  /* current selection */
static GList *last_list = NULL;

static guint32 conversationss_nb = 0;     /* number of displayed conversationss */

/****************************************************************************/
/* append a line to clist */
static void add_to_clist(h323_conversations_info_t* strinfo)
{
	gchar label_text[256];
	gint added_row;
	gchar *data[8];
	gchar field[8][30];

	data[0]=&field[0][0];
	data[1]=&field[1][0];
	data[2]=&field[2][0];
	data[3]=&field[3][0];
	data[4]=&field[4][0];
	data[5]=&field[5][0];
	data[6]=&field[6][0];
	data[7]=&field[7][0];

	g_snprintf(field[0], 20, "%s", ip_to_str((const guint8*)&(strinfo->src_addr)));
	g_snprintf(field[1], 20, "%u", strinfo->src_port);
	g_snprintf(field[2], 20, "%s", ip_to_str((const guint8*)&(strinfo->dest_addr)));
	g_snprintf(field[3], 20, "%u", strinfo->dest_port);
        g_snprintf(field[4], 20, "%s", strinfo->faststart? "TRUE":"FALSE");
	g_snprintf(field[5], 20, "%u", strinfo->npackets);
        g_snprintf(field[6], 20, "%u", strinfo->h245packets);
	
	switch (strinfo->call_state) {

		case (CALL_SETUP):
			g_snprintf(field[7], 20, "%s", "CALL SETUP");
			break;
		case (IN_CALL):
			g_snprintf(field[7], 20, "%s", "IN CALL");
			break;
		case (COMPLETED):
			g_snprintf(field[7], 20, "%s", "COMPLETED");
			break;
		case (REJECTED):
			g_snprintf(field[7], 20, "%s", "REJECTED");
			break;
		case (UNKNOWN):
			g_snprintf(field[7], 20, "%s", "UNKNOWN");
	}

	added_row = gtk_clist_append(GTK_CLIST(clist), data);

	/* set data pointer of last row to point to user data for that row */
	gtk_clist_set_row_data(GTK_CLIST(clist), added_row, strinfo);

	/* Update the top label with the number of detected conversationss */
    conversationss_nb++;
	g_snprintf(label_text, 256,
	        "Detected %d H.323 %s.",
	        conversationss_nb, 
            plurality(conversationss_nb, "Conversation", "Conversations"));
	gtk_label_set(GTK_LABEL(top_label), label_text);

	/* Update the status label with the number of total messages */
        g_snprintf(label_text, 256,
        	"Total: Setup packets: %d   Completed calls: %d   Rejected calls: %d",
	                h323conversations_get_info()->setup_packets, 
			h323conversations_get_info()->completed_calls,
			h323conversations_get_info()->rejected_calls);
        gtk_label_set(GTK_LABEL(status_label), label_text);
}


/****************************************************************************/
/* CALLBACKS                                                                */
/****************************************************************************/
static void
h323conversations_on_destroy                      (GtkObject       *object _U_,
                                        gpointer         user_data _U_)
{
	/* Remove the conversations tap listener */
	remove_tap_listener_h225_conversations();
	remove_tap_listener_h245_conversations();

	/* Clean up memory used by conversations tap */
	h225conversations_reset((h323conversations_tapinfo_t*) h323conversations_get_info());

	/* Note that we no longer have a "H.323 Conversations" dialog box. */
	h323_conversations_dlg = NULL;
}


/****************************************************************************/
static void
h323conversations_on_unselect                  (GtkButton       *button _U_,
                                        gpointer         user_data _U_)
{
	selected_conversations_fwd = NULL;
	gtk_clist_unselect_all(GTK_CLIST(clist));
	gtk_label_set_text(GTK_LABEL(label_fwd), FWD_LABEL_TEXT);

    /*gtk_widget_set_sensitive(bt_unselect, FALSE);*/
    gtk_widget_set_sensitive(bt_filter, FALSE);
    gtk_widget_set_sensitive(bt_analyze, FALSE);
}


/****************************************************************************/
static void
h323conversations_on_filter                    (GtkButton       *button _U_,
                                        gpointer         user_data _U_)
{
	gchar *filter_string = NULL;
	gchar *filter_string_fwd = NULL;

	if (selected_conversations_fwd==NULL)
		return;

	/* if also address for h245 packets is known */
	else if (selected_conversations_fwd->is_h245) {
		filter_string_fwd = g_strdup_printf(
				"((ip.addr==%s && %s.port==%u && ip.addr==%s && %s.port==%u) and h225) or ((ip.addr==%s && %s.port==%u) and h245)",
				ip_to_str((const guint8*)&(selected_conversations_fwd->src_addr)),
				transport_prot_name[selected_conversations_fwd->transport],
				selected_conversations_fwd->src_port,
				ip_to_str((const guint8*)&(selected_conversations_fwd->dest_addr)),
				transport_prot_name[selected_conversations_fwd->transport],
				selected_conversations_fwd->dest_port,
				ip_to_str((const guint8*)&(selected_conversations_fwd->h245address)),
				transport_prot_name[selected_conversations_fwd->transport],
				selected_conversations_fwd->h245port);
	}
	/* else filter only h225 packets */
	else {
		filter_string_fwd = g_strdup_printf(
				"(ip.addr==%s && %s.port==%u && ip.addr==%s && %s.port==%u) and h225",
				ip_to_str((const guint8*)&(selected_conversations_fwd->src_addr)),
				transport_prot_name[selected_conversations_fwd->transport],
				selected_conversations_fwd->src_port,
				ip_to_str((const guint8*)&(selected_conversations_fwd->dest_addr)),
				transport_prot_name[selected_conversations_fwd->transport],
				selected_conversations_fwd->dest_port);
	}

        filter_string = filter_string_fwd;

	gtk_entry_set_text(GTK_ENTRY(main_display_filter_widget), filter_string);
	g_free(filter_string);
/*
	main_filter_packets(&cfile, filter_string, FALSE);
	h323conversations_dlg_update(h323conversations_get_info()->strinfo_list);
*/
}


/****************************************************************************/
static void
h323conversations_on_analyse                   (GtkButton       *button _U_,
                                        gpointer         user_data _U_)
{
	guint32 ip_src = 0;
        guint16 port_src = 0;
        guint32 ip_dst = 0;
        guint16 port_dst = 0;
        guint32 ip_src_h245 = 0;
        guint16 port_src_h245 = 0;
        guint16 transport=0;

	if (selected_conversations_fwd) {
		ip_src = selected_conversations_fwd->src_addr;
		port_src = selected_conversations_fwd->src_port;
		ip_dst = selected_conversations_fwd->dest_addr;
		port_dst = selected_conversations_fwd->dest_port;
		ip_src_h245 = selected_conversations_fwd->h245address;
		port_src_h245 = selected_conversations_fwd->h245port;
		transport = selected_conversations_fwd->transport;
	}

   	h323_analysis(
                ip_src,
                port_src,
                ip_dst,
                port_dst,
                ip_src_h245,
                port_src_h245,
                transport
                );
}


/****************************************************************************/
/* when the user selects a row in the conversations list */
static void
h323conversations_on_select_row(GtkCList *clist,
                                            gint row _U_,
                                            gint column _U_,
                                            GdkEventButton *event _U_,
                                            gpointer user_data _U_)
{
	gchar label_text[80];

	selected_conversations_fwd = gtk_clist_get_row_data(GTK_CLIST(clist), row);
	g_snprintf(label_text, 80, "Selected Conversation: %s:%u <---> %s:%u",
		ip_to_str((ip_addr_p)&selected_conversations_fwd->src_addr),
		selected_conversations_fwd->src_port,
		ip_to_str((ip_addr_p)&selected_conversations_fwd->dest_addr),
		selected_conversations_fwd->dest_port
	);
	gtk_label_set_text(GTK_LABEL(label_fwd), label_text);

    /*gtk_widget_set_sensitive(bt_unselect, TRUE);*/
    gtk_widget_set_sensitive(bt_filter, TRUE);
    gtk_widget_set_sensitive(bt_analyze, TRUE);

	/* TODO: activate other buttons when implemented */
}


/****************************************************************************/
#define NUM_COLS 8

typedef struct column_arrows {
	GtkWidget *table;
	GtkWidget *ascend_pm;
	GtkWidget *descend_pm;
} column_arrows;


/****************************************************************************/
static void
h323conversations_click_column_cb(GtkCList *clist, gint column, gpointer data)
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
h323conversations_sort_column(GtkCList *clist, gconstpointer ptr1, gconstpointer ptr2)
{
	char *text1 = NULL;
	char *text2 = NULL;
	int i1, i2;

	const GtkCListRow *row1 = (const GtkCListRow *) ptr1;
	const GtkCListRow *row2 = (const GtkCListRow *) ptr2;

	text1 = GTK_CELL_TEXT (row1->cell[clist->sort_column])->text;
	text2 = GTK_CELL_TEXT (row2->cell[clist->sort_column])->text;

	switch(clist->sort_column){
	case 0:
	case 2:
	case 5:
	case 7:
		return strcmp (text1, text2);
	case 1:
	case 3:
	case 4:
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

static void h323conversations_dlg_create (void)
{
	GtkWidget *h323conversations_dlg_w;
	GtkWidget *main_vb;
	GtkWidget *scrolledwindow;
	GtkWidget *hbuttonbox;
	GtkWidget *bt_close;
    GtkTooltips *tooltips = gtk_tooltips_new();

	gchar *titles[8] =  {"IP address A", "Port A",  "IP address B", "Port B", "Faststart", "H225 pkts", "H245 pkts", "Status"};
	column_arrows *col_arrows;
	GtkWidget *column_lb;
	int i;

    /* don't use a window here (but a dialog), because otherwise a parent
     * analysis window will hide this one and show the main window :-( */
	/*h323conversations_dlg_w = window_new_with_geom(GTK_WINDOW_TOPLEVEL, 
        "Ethereal: H.323 VoIP Conversations", "H323-conversations");*/
	h323conversations_dlg_w = dlg_window_new("Ethereal: H.323 VoIP Conversations");
	gtk_window_set_default_size(GTK_WINDOW(h323conversations_dlg_w), 700, 300);

	main_vb = gtk_vbox_new (FALSE, 0);
	gtk_container_add(GTK_CONTAINER(h323conversations_dlg_w), main_vb);
	gtk_container_set_border_width (GTK_CONTAINER (main_vb), 12);

	top_label = gtk_label_new ("Detected 0 H.323 Conversations.");
	gtk_box_pack_start (GTK_BOX (main_vb), top_label, FALSE, FALSE, 8);

	scrolledwindow = scrolled_window_new (NULL, NULL);
	gtk_box_pack_start (GTK_BOX (main_vb), scrolledwindow, TRUE, TRUE, 0);

	clist = gtk_clist_new (NUM_COLS);
	gtk_container_add (GTK_CONTAINER (scrolledwindow), clist);

	gtk_clist_set_column_width (GTK_CLIST (clist), 0, 100);
	gtk_clist_set_column_width (GTK_CLIST (clist), 1, 70);
	gtk_clist_set_column_width (GTK_CLIST (clist), 2, 100);
	gtk_clist_set_column_width (GTK_CLIST (clist), 3, 70);
	gtk_clist_set_column_width (GTK_CLIST (clist), 4, 60);
	gtk_clist_set_column_width (GTK_CLIST (clist), 5, 60);
	gtk_clist_set_column_width (GTK_CLIST (clist), 6, 60);
	gtk_clist_set_column_width (GTK_CLIST (clist), 7, 100);

	gtk_clist_set_column_justification(GTK_CLIST(clist), 0, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 1, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 2, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 3, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 4, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 5, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 6, GTK_JUSTIFY_CENTER);
	gtk_clist_set_column_justification(GTK_CLIST(clist), 7, GTK_JUSTIFY_CENTER);

	gtk_clist_column_titles_show (GTK_CLIST (clist));

	gtk_clist_set_compare_func(GTK_CLIST(clist), h323conversations_sort_column);
	gtk_clist_set_sort_column(GTK_CLIST(clist), 0);
	gtk_clist_set_sort_type(GTK_CLIST(clist), GTK_SORT_ASCENDING);

	gtk_widget_show(h323conversations_dlg_w);

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
		/* make src-ip be the default sort order */
		if (i == 0) {
			gtk_widget_show(col_arrows[i].ascend_pm);
		}
		gtk_clist_set_column_widget(GTK_CLIST(clist), i, col_arrows[i].table);
		gtk_widget_show(col_arrows[i].table);
	}

	SIGNAL_CONNECT(clist, "click-column", h323conversations_click_column_cb, col_arrows);

	label_fwd = gtk_label_new (FWD_LABEL_TEXT);
	gtk_box_pack_start (GTK_BOX (main_vb), label_fwd, FALSE, FALSE, 0);

	status_label = gtk_label_new ("Total: Setup packets: 0   Completed calls: 0   Rejected calls: 0");
	gtk_box_pack_start (GTK_BOX (main_vb), status_label, FALSE, FALSE, 8);

        /* button row */
	hbuttonbox = gtk_hbutton_box_new ();
	gtk_box_pack_start (GTK_BOX (main_vb), hbuttonbox, FALSE, FALSE, 0);
	gtk_button_box_set_layout (GTK_BUTTON_BOX (hbuttonbox), GTK_BUTTONBOX_SPREAD);
	gtk_button_box_set_spacing (GTK_BUTTON_BOX (hbuttonbox), 30);

	/*bt_unselect = gtk_button_new_with_label ("Unselect");
	gtk_container_add (GTK_CONTAINER (hbuttonbox), bt_unselect);
    gtk_tooltips_set_tip (tooltips, bt_unselect, "Unselect this conversation", NULL);*/

	bt_filter = gtk_button_new_with_label ("Prepare filter");
	gtk_container_add (GTK_CONTAINER (hbuttonbox), bt_filter);
    gtk_tooltips_set_tip (tooltips, bt_filter, "Prepare a display filter of the selected conversation", NULL);

	bt_analyze = gtk_button_new_with_label ("Analyze");
	gtk_container_add (GTK_CONTAINER (hbuttonbox), bt_analyze);
    gtk_tooltips_set_tip (tooltips, bt_analyze, "Analyze the selected conversation", NULL);

	bt_close = BUTTON_NEW_FROM_STOCK(GTK_STOCK_CLOSE);
	gtk_container_add (GTK_CONTAINER (hbuttonbox), bt_close);
	GTK_WIDGET_SET_FLAGS(bt_close, GTK_CAN_DEFAULT);
    gtk_tooltips_set_tip (tooltips, bt_close, "Close this dialog", NULL);

	SIGNAL_CONNECT(clist, "select_row", h323conversations_on_select_row, NULL);
	/*SIGNAL_CONNECT(bt_unselect, "clicked", h323conversations_on_unselect, NULL);*/
	SIGNAL_CONNECT(bt_filter, "clicked", h323conversations_on_filter, NULL);
	SIGNAL_CONNECT(bt_analyze, "clicked", h323conversations_on_analyse, NULL);

	window_set_cancel_button(h323conversations_dlg_w, bt_close, window_cancel_button_cb);

	SIGNAL_CONNECT(h323conversations_dlg_w, "delete_event", window_delete_event_cb, NULL);
	SIGNAL_CONNECT(h323conversations_dlg_w, "destroy", h323conversations_on_destroy, NULL);

	gtk_widget_show_all(h323conversations_dlg_w);
	window_present(h323conversations_dlg_w);

	h323conversations_on_unselect(NULL, NULL);

	h323_conversations_dlg = h323conversations_dlg_w;
}


/****************************************************************************/
/* PUBLIC								    */
/****************************************************************************/

/****************************************************************************/
/* update the contents of the dialog box clist */
/* list: pointer to list of h323_conversations_info_t* */
void h323conversations_dlg_update(GList *list)
{
	gchar label_text[256];

	if (h323_conversations_dlg != NULL) {
		gtk_clist_clear(GTK_CLIST(clist));
		conversationss_nb = 0;
        	g_snprintf(label_text, 256,
        		"Total: Setup packets: %d   Completed calls: %d   Rejected calls: %d",
		                h323conversations_get_info()->setup_packets, 
				h323conversations_get_info()->completed_calls,
				h323conversations_get_info()->rejected_calls);
        	gtk_label_set(GTK_LABEL(status_label), label_text);

		list = g_list_first(list);
		while (list)
		{
			add_to_clist((h323_conversations_info_t*)(list->data));
			list = g_list_next(list);
		}

		g_snprintf(label_text, 256,
		        "Detected %d H.323 %s.",
	    	    conversationss_nb, 
            	plurality(conversationss_nb, "Conversation", "Conversations"));
		gtk_label_set(GTK_LABEL(top_label), label_text);

		h323conversations_on_unselect(NULL, NULL);
	}

	last_list = list;
}


/****************************************************************************/
/* update the contents of the dialog box clist */
/* list: pointer to list of h323_conversations_info_t* */
void h323conversations_dlg_show(GList *list)
{
	if (h323_conversations_dlg != NULL) {
		/* There's already a dialog box; reactivate it. */
		reactivate_window(h323_conversations_dlg);
		/* Another list since last call? */
		if (list != last_list) {
			h323conversations_dlg_update(list);
		}
	}
	else {
		/* Create and show the dialog box */
		h323conversations_dlg_create();
		h323conversations_dlg_update(list);
	}
}

/* init function for tap */
static void
h323conversations_init_tap(char *dummy _U_)
{
	/* Register the tap listener */
	h225conversations_init_tap();
	h245conversations_init_tap();

	/* Scan for H323 conversations conversationss (redissect all packets) */
	retap_packets(&cfile);

	/* Show the dialog box with the list of conversationss */
	h323conversations_dlg_show(h323conversations_get_info()->strinfo_list);

	/* Tap listener will be removed and cleaned up in h323conversations_on_destroy */
	
}


/****************************************************************************/
/* entry point when called via the GTK menu */
void h323conversations_launch(GtkWidget *w _U_, gpointer data _U_)
{
	h323conversations_init_tap("");
}

/****************************************************************************/
void
register_tap_listener_h323_conversations_dlg(void)
{
	register_ethereal_tap("h323,conv",h323conversations_init_tap);
	
	register_tap_menu_item("H.323 Conversations...", REGISTER_TAP_GROUP_NONE,
	    h323conversations_launch, NULL, NULL, NULL);
}

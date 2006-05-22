/* mcast_stream_dlg.c
 *
 * Copyright 2006, Iskratel , Slovenia
 * By Jakob Bratkovic <j.bratkovic@iskratel.si> and
 * Miha Jemec <m.jemec@iskratel.si>
 *
 * based on rtp_stream_dlg.c
 * Copyright 2003, Alcatel Business Systems
 * By Lars Ruoff <lars.ruoff@gmx.net>
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
 * Foundation,  Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include "mcast_stream_dlg.h"
#include "mcast_stream.h"

#include "globals.h"
#include "epan/filesystem.h"

#include "../stat_menu.h"
#include "gui_stat_menu.h"
#include "dlg_utils.h"
#include "gui_utils.h"
#include "compat_macros.h"
#include "gtkglobals.h"
#include "simple_dialog.h"

#include "image/clist_ascend.xpm"
#include "image/clist_descend.xpm"

#include <epan/address.h>

#include <string.h>
#include <locale.h>
#include <epan/addr_resolv.h>

/* Capture callback data keys */
#define E_MCAST_ENTRY_1     "burst_interval"
#define E_MCAST_ENTRY_2     "burst_alarm"
#define E_MCAST_ENTRY_3     "buffer_alarm"
#define E_MCAST_ENTRY_4     "stream_speed"
#define E_MCAST_ENTRY_5     "total_speed"

extern guint16 burstint;
extern guint32 trigger;
extern guint32 bufferalarm;
extern gint32 emptyspeed;
extern gint32 cumulemptyspeed; 

static const gchar FWD_LABEL_TEXT[] = "Select a stream with left mouse button";
static const gchar PAR_LABEL_TEXT[] = "\nBurst int: ms   Burst alarm: pps    Buffer alarm: KB    Stream empty speed: Mbps    Total empty speed: Mbps\n";

/****************************************************************************/
static GtkWidget *mcast_stream_dlg = NULL;
static GtkWidget *mcast_params_dlg = NULL;

static GtkWidget *clist = NULL;
static GtkWidget *top_label = NULL;
static GtkWidget *label_fwd = NULL;
static GtkWidget *label_par = NULL;

static mcast_stream_info_t* selected_stream_fwd = NULL;  /* current selection */
static GList *last_list = NULL;

static guint32 streams_nb = 0;     /* number of displayed streams */

#define NUM_COLS 12
static const gchar *titles[NUM_COLS] =  {"Src IP addr", "Src port",  "Dst IP addr", "Dst port", "Packets", "Packets/s", "Awg Bw", "Max Bw", "Max burst", "Burst Alarms", "Max buffer", "Buff Alarms"};

/****************************************************************************/
/* append a line to clist */
static void add_to_clist(mcast_stream_info_t* strinfo)
{
	gchar label_text[256];
	gint added_row;
	gchar *data[NUM_COLS];
	int i;
	char *savelocale;

	/* save the current locale */
	savelocale = setlocale(LC_NUMERIC, NULL);
	/* switch to "C" locale to avoid problems with localized decimal separators
		in g_snprintf("%f") functions */
	setlocale(LC_NUMERIC, "C");
	data[0] = g_strdup(get_addr_name(&(strinfo->src_addr)));
	data[1] = g_strdup_printf("%u", strinfo->src_port);
	data[2] = g_strdup(get_addr_name(&(strinfo->dest_addr)));
	data[3] = g_strdup_printf("%u", strinfo->dest_port);
	data[4] = g_strdup_printf("%u", strinfo->npackets);
	data[5] = g_strdup_printf("%u /s", strinfo->apackets);
	data[6] = g_strdup_printf("%2.1f Mbps", strinfo->average_bw);
	data[7] = g_strdup_printf("%2.1f Mbps", strinfo->element.maxbw);
	data[8] = g_strdup_printf("%u / %dms", strinfo->element.topburstsize, burstint);
	data[9] = g_strdup_printf("%u", strinfo->element.numbursts);
	data[10] = g_strdup_printf("%.1f KB", (float)strinfo->element.topbuffusage/1000);
	data[11] = g_strdup_printf("%u", strinfo->element.numbuffalarms);

	/* restore previous locale setting */
	setlocale(LC_NUMERIC, savelocale);

	added_row = gtk_clist_append(GTK_CLIST(clist), data);
	for (i = 0; i < NUM_COLS; i++)
		g_free(data[i]);

	/* set data pointer of last row to point to user data for that row */
	gtk_clist_set_row_data(GTK_CLIST(clist), added_row, strinfo);

	/* Update the top label with the number of detected streams */
	sprintf(label_text,
	        "Detected %d Multicast streams,   Average Bw: %.1f Mbps   Max Bw: %.1f Mbps   Max burst: %d / %dms   Max buffer: %.1f KB",
	        ++streams_nb, 
		mcaststream_get_info()->allstreams->average_bw, mcaststream_get_info()->allstreams->element.maxbw, 
		mcaststream_get_info()->allstreams->element.topburstsize, burstint, 
		(float)(mcaststream_get_info()->allstreams->element.topbuffusage)/1000);
	gtk_label_set(GTK_LABEL(top_label), label_text);

	g_snprintf(label_text, 200, "\nBurst int: %u ms   Burst alarm: %u pps   Buffer alarm: %u Bytes   Stream empty speed: %u Kbps   Total empty speed: %u Kbps\n", 
		burstint, trigger, bufferalarm, emptyspeed, cumulemptyspeed);
	gtk_label_set_text(GTK_LABEL(label_par), label_text);
}

/****************************************************************************/
/* CALLBACKS                                                                */
/****************************************************************************/
static void
mcaststream_on_destroy                      (GtkObject       *object _U_,
                                        gpointer         user_data _U_)
{
	/* Remove the stream tap listener */
	remove_tap_listener_mcast_stream();

	/* Is there a params window open? */
        if (mcast_params_dlg != NULL)
                window_destroy(mcast_params_dlg);

	/* Clean up memory used by stream tap */
	mcaststream_reset((mcaststream_tapinfo_t*) mcaststream_get_info());

	/* Note that we no longer have a "Mcast Streams" dialog box. */
	mcast_stream_dlg = NULL;
}


/****************************************************************************/
static void
mcaststream_on_unselect                  (GtkButton       *button _U_,
                                        gpointer         user_data _U_)
{
	selected_stream_fwd = NULL;
	gtk_clist_unselect_all(GTK_CLIST(clist));
	gtk_label_set_text(GTK_LABEL(label_fwd), FWD_LABEL_TEXT);
}


/****************************************************************************/
static void
mcaststream_on_filter                    (GtkButton       *button _U_,
                                        gpointer         user_data _U_)
{
	gchar *filter_string = NULL;
	gchar *filter_string_fwd = NULL;
	gchar ip_version[3];

	if (selected_stream_fwd==NULL)
		return;

	if (selected_stream_fwd)
	{
		if (selected_stream_fwd->src_addr.type==AT_IPv6){
			strcpy(ip_version,"v6");
		}		
		else{
			strcpy(ip_version,"");
		}
		filter_string_fwd = g_strdup_printf(
			"(ip%s.src==%s && udp.srcport==%u && ip%s.dst==%s && udp.dstport==%u)",
			ip_version,
			address_to_str(&(selected_stream_fwd->src_addr)),
			selected_stream_fwd->src_port,
			ip_version,
			address_to_str(&(selected_stream_fwd->dest_addr)),
			selected_stream_fwd->dest_port);
        filter_string = filter_string_fwd;
	}

        gtk_entry_set_text(GTK_ENTRY(main_display_filter_widget), filter_string);
        g_free(filter_string);

/*
	main_filter_packets(&cfile, filter_string, FALSE);
	mcaststream_dlg_update(mcaststream_get_info()->strinfo_list);
*/
}


/****************************************************************************/
/* when the user selects a row in the stream list */
static void
mcaststream_on_select_row(GtkCList *clist,
                                            gint row _U_,
                                            gint column _U_,
                                            GdkEventButton *event _U_,
                                            gpointer user_data _U_)
{
	gchar label_text[80];

	selected_stream_fwd = gtk_clist_get_row_data(GTK_CLIST(clist), row);
	g_snprintf(label_text, 80, "Selected: %s:%u -> %s:%u",
			get_addr_name(&(selected_stream_fwd->src_addr)),
			selected_stream_fwd->src_port,
			get_addr_name(&(selected_stream_fwd->dest_addr)),
			selected_stream_fwd->dest_port
	);
	gtk_label_set_text(GTK_LABEL(label_fwd), label_text);

/*
	gtk_widget_set_sensitive(filter_bt, TRUE);
*/
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
mcaststream_click_column_cb(GtkCList *clist, gint column, gpointer data)
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
mcaststream_sort_column(GtkCList *clist, gconstpointer ptr1, gconstpointer ptr2)
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
		return strcmp (text1, text2);
	case 1:
	case 3:
	case 4:
	case 5:
	case 6:
	case 7:
	case 8:
	case 9:
	case 10:
	case 11:
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
static void mcast_params_destroy_cb(GtkWidget *win _U_, gpointer user_data _U_)
{
        /* Note that we no longer have a mcast params dialog box. */
        mcast_params_dlg = NULL;
}


static void
mcast_params_ok_cb(GtkWidget *ok_bt _U_, gpointer parent_w)
{
	GtkWidget   *fnumber_te;
	const gchar *fnumber_text;
	gint32        fnumber;
	char        *p;

	fnumber_te = (GtkWidget *)OBJECT_GET_DATA(parent_w, E_MCAST_ENTRY_1);
	fnumber_text = gtk_entry_get_text(GTK_ENTRY(fnumber_te));
	fnumber = strtoul(fnumber_text, &p, 10);
	if ( (p == fnumber_text || *p != '\0') || (fnumber <=0) || (fnumber > 1000) ){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "The burst interval should be between 1 and 1000 ms ");
		return; }
	burstint = fnumber;

	fnumber_te = (GtkWidget *)OBJECT_GET_DATA(parent_w, E_MCAST_ENTRY_2);
	fnumber_text = gtk_entry_get_text(GTK_ENTRY(fnumber_te));
	fnumber = strtoul(fnumber_text, &p, 10);
	if ( (p == fnumber_text || *p != '\0') || (fnumber <=0) ){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "The burst alarm treshold you entered isn't valid.");
		return; }
	trigger = fnumber;

	fnumber_te = (GtkWidget *)OBJECT_GET_DATA(parent_w, E_MCAST_ENTRY_3);
	fnumber_text = gtk_entry_get_text(GTK_ENTRY(fnumber_te));
	fnumber = strtoul(fnumber_text, &p, 10);
	if ( (p == fnumber_text || *p != '\0') || (fnumber <=0) ){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "The buffer alarm treshold you entered isn't valid.");
		return; }
	bufferalarm = fnumber;

	fnumber_te = (GtkWidget *)OBJECT_GET_DATA(parent_w, E_MCAST_ENTRY_4);
	fnumber_text = gtk_entry_get_text(GTK_ENTRY(fnumber_te));
	fnumber = strtoul(fnumber_text, &p, 10);
	if ( (p == fnumber_text || *p != '\0') || (fnumber <=0) || (fnumber > 10000000) ){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "The stream empty speed should be between 1 and 10000000");
		return; }
	emptyspeed = fnumber;

	fnumber_te = (GtkWidget *)OBJECT_GET_DATA(parent_w, E_MCAST_ENTRY_5);
	fnumber_text = gtk_entry_get_text(GTK_ENTRY(fnumber_te));
	fnumber = strtoul(fnumber_text, &p, 10);
	if ( (p == fnumber_text || *p != '\0') || (fnumber <=0) || (fnumber > 10000000) ){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "The total empty speed should be between 1 and 10000000");
		return; }
	cumulemptyspeed = fnumber; 

	window_destroy(GTK_WIDGET(parent_w));

	/* Clean up memory used by stream tap */
        mcaststream_reset((mcaststream_tapinfo_t*) mcaststream_get_info());
	/* retap all packets */
        cf_retap_packets(&cfile, FALSE);

}



static void
mcast_on_params                      (GtkButton       *button _U_,
                                        gpointer         data _U_)
{
	GtkWidget *main_vb;
        GtkWidget *label, *hbuttonbox, *table;
        GtkWidget *ok_bt, *cancel_bt;
	GtkWidget *entry1, *entry2, *entry3, *entry4, *entry5;
	gchar label_text[51];

	if (mcast_params_dlg != NULL) {
                /* There's already a Params dialog box; reactivate it. */
                reactivate_window(mcast_params_dlg);
                return;
        }

	mcast_params_dlg = window_new(GTK_WINDOW_TOPLEVEL, "Wireshark: Set parameters for Multicast Stream Analysis");
        gtk_window_set_default_size(GTK_WINDOW(mcast_params_dlg), 210, 210);

        gtk_widget_show(mcast_params_dlg);
	
        /* Container for each row of widgets */
        main_vb = gtk_vbox_new(FALSE, 3);
        gtk_container_border_width(GTK_CONTAINER(main_vb), 2);
        gtk_container_add(GTK_CONTAINER(mcast_params_dlg), main_vb);
        gtk_widget_show(main_vb);

	table = gtk_table_new (6, 2, FALSE);
	gtk_container_add (GTK_CONTAINER (main_vb), table);

	label = gtk_label_new("  Burst measurement interval (ms)  ");
	gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, 0, 1);
	entry1 = gtk_entry_new();
	g_snprintf(label_text, 50, "%u", burstint);
	gtk_entry_set_text(GTK_ENTRY(entry1), label_text);
	gtk_table_attach_defaults(GTK_TABLE(table), entry1, 1, 2, 0, 1);
	label = gtk_label_new("  Burst alarm treshold (packets)   ");
	gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, 1, 2);
	entry2 = gtk_entry_new();
	g_snprintf(label_text, 50, "%u", trigger);
	gtk_entry_set_text(GTK_ENTRY(entry2), label_text);
	gtk_table_attach_defaults(GTK_TABLE(table), entry2, 1, 2, 1, 2);
	label = gtk_label_new("  Buffer alarm treshold (bytes)     ");
	gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, 2, 3);
	entry3 = gtk_entry_new();
	g_snprintf(label_text, 50, "%u", bufferalarm);
	gtk_entry_set_text(GTK_ENTRY(entry3), label_text);
	gtk_table_attach_defaults(GTK_TABLE(table), entry3, 1, 2, 2, 3);
	label = gtk_label_new("  Stream empty speed (kbit/s)      ");
	gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, 3, 4);
	entry4 = gtk_entry_new();
	g_snprintf(label_text, 50, "%u", emptyspeed);
	gtk_entry_set_text(GTK_ENTRY(entry4), label_text);
	gtk_table_attach_defaults(GTK_TABLE(table), entry4, 1, 2, 3, 4);
	label = gtk_label_new("  Total empty speed (kbit/s)       ");
	gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, 4, 5);
	entry5 = gtk_entry_new();
	g_snprintf(label_text, 50, "%u", cumulemptyspeed);
	gtk_entry_set_text(GTK_ENTRY(entry5), label_text);
	gtk_table_attach_defaults(GTK_TABLE(table), entry5, 1, 2, 4, 5);

	gtk_widget_show (table);

	/* button row */
	hbuttonbox = gtk_hbutton_box_new ();
	gtk_table_attach_defaults(GTK_TABLE(table), hbuttonbox, 0, 2, 5, 6);
	ok_bt = BUTTON_NEW_FROM_STOCK(GTK_STOCK_OK);
	gtk_container_add (GTK_CONTAINER (hbuttonbox), ok_bt);
	cancel_bt = BUTTON_NEW_FROM_STOCK(GTK_STOCK_CANCEL);
	gtk_container_add (GTK_CONTAINER (hbuttonbox), cancel_bt);
	GTK_WIDGET_SET_FLAGS(cancel_bt, GTK_CAN_DEFAULT);
	gtk_button_box_set_layout (GTK_BUTTON_BOX (hbuttonbox), GTK_BUTTONBOX_END);
	gtk_button_box_set_spacing (GTK_BUTTON_BOX (hbuttonbox), 0);
        
	SIGNAL_CONNECT(mcast_params_dlg, "delete_event", window_delete_event_cb, NULL);
        SIGNAL_CONNECT(mcast_params_dlg, "destroy", mcast_params_destroy_cb, NULL);
	SIGNAL_CONNECT(ok_bt, "clicked", mcast_params_ok_cb, mcast_params_dlg);
	window_set_cancel_button(mcast_params_dlg, cancel_bt, window_cancel_button_cb);

	/* Attach pointers to needed widgets */
	OBJECT_SET_DATA(mcast_params_dlg, E_MCAST_ENTRY_1, entry1);
	OBJECT_SET_DATA(mcast_params_dlg, E_MCAST_ENTRY_2, entry2);
	OBJECT_SET_DATA(mcast_params_dlg, E_MCAST_ENTRY_3, entry3);
	OBJECT_SET_DATA(mcast_params_dlg, E_MCAST_ENTRY_4, entry4);
	OBJECT_SET_DATA(mcast_params_dlg, E_MCAST_ENTRY_5, entry5);

	gtk_widget_show_all(mcast_params_dlg);
	window_present(mcast_params_dlg);
}



static void mcaststream_dlg_create (void)
{
    GtkWidget *mcaststream_dlg_w;
    GtkWidget *main_vb;
    GtkWidget *scrolledwindow;
    GtkWidget *hbuttonbox;
    /*GtkWidget *bt_unselect;*/
    GtkWidget *bt_filter;
    GtkWidget *bt_params;
    GtkWidget *bt_close;
    GtkTooltips *tooltips = gtk_tooltips_new();

    column_arrows *col_arrows;
    GtkWidget *column_lb;
    int i;

    mcaststream_dlg_w = dlg_window_new("Wireshark: Multicast Streams");
    gtk_window_set_default_size(GTK_WINDOW(mcaststream_dlg_w), 620, 400);

    main_vb = gtk_vbox_new (FALSE, 0);
    gtk_container_add(GTK_CONTAINER(mcaststream_dlg_w), main_vb);
    gtk_container_set_border_width (GTK_CONTAINER (main_vb), 12);

    top_label = gtk_label_new ("Detected 0 Multicast streams");
    gtk_box_pack_start (GTK_BOX (main_vb), top_label, FALSE, FALSE, 8);

    scrolledwindow = scrolled_window_new (NULL, NULL);
    gtk_box_pack_start (GTK_BOX (main_vb), scrolledwindow, TRUE, TRUE, 0);

    clist = gtk_clist_new (NUM_COLS);
    gtk_container_add (GTK_CONTAINER (scrolledwindow), clist);

    gtk_clist_set_column_width (GTK_CLIST (clist), 0, 95);
    gtk_clist_set_column_width (GTK_CLIST (clist), 1, 55);
    gtk_clist_set_column_width (GTK_CLIST (clist), 2, 95);
    gtk_clist_set_column_width (GTK_CLIST (clist), 3, 55);
    gtk_clist_set_column_width (GTK_CLIST (clist), 4, 70);
    gtk_clist_set_column_width (GTK_CLIST (clist), 5, 70);
    gtk_clist_set_column_width (GTK_CLIST (clist), 6, 60);
    gtk_clist_set_column_width (GTK_CLIST (clist), 7, 60);
    gtk_clist_set_column_width (GTK_CLIST (clist), 8, 80);
    gtk_clist_set_column_width (GTK_CLIST (clist), 9, 85);
    gtk_clist_set_column_width (GTK_CLIST (clist), 10, 80);
    gtk_clist_set_column_width (GTK_CLIST (clist), 11, 80);

    gtk_clist_set_column_justification(GTK_CLIST(clist), 0, GTK_JUSTIFY_CENTER);
    gtk_clist_set_column_justification(GTK_CLIST(clist), 1, GTK_JUSTIFY_CENTER);
    gtk_clist_set_column_justification(GTK_CLIST(clist), 2, GTK_JUSTIFY_CENTER);
    gtk_clist_set_column_justification(GTK_CLIST(clist), 3, GTK_JUSTIFY_CENTER);
    gtk_clist_set_column_justification(GTK_CLIST(clist), 4, GTK_JUSTIFY_CENTER);
    gtk_clist_set_column_justification(GTK_CLIST(clist), 5, GTK_JUSTIFY_CENTER);
    gtk_clist_set_column_justification(GTK_CLIST(clist), 6, GTK_JUSTIFY_CENTER);
    gtk_clist_set_column_justification(GTK_CLIST(clist), 7, GTK_JUSTIFY_CENTER);
    gtk_clist_set_column_justification(GTK_CLIST(clist), 8, GTK_JUSTIFY_CENTER);
    gtk_clist_set_column_justification(GTK_CLIST(clist), 9, GTK_JUSTIFY_CENTER);
    gtk_clist_set_column_justification(GTK_CLIST(clist), 10, GTK_JUSTIFY_CENTER);
    gtk_clist_set_column_justification(GTK_CLIST(clist), 11, GTK_JUSTIFY_CENTER);

    gtk_clist_column_titles_show (GTK_CLIST (clist));

    gtk_clist_set_compare_func(GTK_CLIST(clist), mcaststream_sort_column);
    gtk_clist_set_sort_column(GTK_CLIST(clist), 0);
    gtk_clist_set_sort_type(GTK_CLIST(clist), GTK_SORT_ASCENDING);

    gtk_widget_show(mcaststream_dlg_w);

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

    SIGNAL_CONNECT(clist, "click-column", mcaststream_click_column_cb, col_arrows);

    label_fwd = gtk_label_new (FWD_LABEL_TEXT);
    //gtk_box_pack_start (GTK_BOX (main_vb), label_fwd, FALSE, FALSE, 0);

    label_par = gtk_label_new (PAR_LABEL_TEXT);
    gtk_box_pack_start (GTK_BOX (main_vb), label_par, FALSE, FALSE, 0);

    /* button row */
    hbuttonbox = gtk_hbutton_box_new ();
    gtk_box_pack_start (GTK_BOX (main_vb), hbuttonbox, FALSE, FALSE, 0);
    gtk_button_box_set_layout (GTK_BUTTON_BOX (hbuttonbox), GTK_BUTTONBOX_END);
    gtk_button_box_set_spacing (GTK_BUTTON_BOX (hbuttonbox), 0);

    /*bt_unselect = gtk_button_new_with_label ("Unselect");
    gtk_container_add (GTK_CONTAINER (hbuttonbox), bt_unselect);
    gtk_tooltips_set_tip (tooltips, bt_unselect, "Undo stream selection", NULL);*/

    bt_params = gtk_button_new_with_label ("Set parameters");
    gtk_container_add (GTK_CONTAINER (hbuttonbox), bt_params);
    gtk_tooltips_set_tip (tooltips, bt_params, "Set buffer, limit and speed parameters", NULL);

    bt_filter = gtk_button_new_with_label ("Prepare Filter");
    gtk_container_add (GTK_CONTAINER (hbuttonbox), bt_filter);
    gtk_tooltips_set_tip (tooltips, bt_filter, "Prepare a display filter of the selected stream", NULL);

    bt_close = BUTTON_NEW_FROM_STOCK(GTK_STOCK_CLOSE);
    gtk_container_add (GTK_CONTAINER (hbuttonbox), bt_close);
    gtk_tooltips_set_tip (tooltips, bt_close, "Close this dialog", NULL);
    GTK_WIDGET_SET_FLAGS(bt_close, GTK_CAN_DEFAULT);

    SIGNAL_CONNECT(clist, "select_row", mcaststream_on_select_row, NULL);
    //SIGNAL_CONNECT(bt_unselect, "clicked", mcaststream_on_unselect, NULL);
    SIGNAL_CONNECT(bt_params, "clicked", mcast_on_params, NULL);
    SIGNAL_CONNECT(bt_filter, "clicked", mcaststream_on_filter, NULL);
    window_set_cancel_button(mcaststream_dlg_w, bt_close, window_cancel_button_cb);

    SIGNAL_CONNECT(mcaststream_dlg_w, "delete_event", window_delete_event_cb, NULL);
    SIGNAL_CONNECT(mcaststream_dlg_w, "destroy", mcaststream_on_destroy, NULL);

    gtk_widget_show_all(mcaststream_dlg_w);
    window_present(mcaststream_dlg_w);

    mcaststream_on_unselect(NULL, NULL);

    mcast_stream_dlg = mcaststream_dlg_w;
}


/****************************************************************************/
/* PUBLIC								    */
/****************************************************************************/

/****************************************************************************/
/* update the contents of the dialog box clist */
/* list: pointer to list of mcast_stream_info_t* */
void mcaststream_dlg_update(GList *list)
{
	if (mcast_stream_dlg != NULL) {
		gtk_clist_clear(GTK_CLIST(clist));
		streams_nb = 0;

		list = g_list_first(list);
		while (list)
		{
			add_to_clist((mcast_stream_info_t*)(list->data));
			list = g_list_next(list);
		}

		mcaststream_on_unselect(NULL, NULL);
	}

	last_list = list;
}


/****************************************************************************/
/* update the contents of the dialog box clist */
/* list: pointer to list of mcast_stream_info_t* */
void mcaststream_dlg_show(GList *list)
{
	if (mcast_stream_dlg != NULL) {
		/* There's already a dialog box; reactivate it. */
		reactivate_window(mcast_stream_dlg);
		/* Another list since last call? */
		if (list != last_list) {
			mcaststream_dlg_update(list);
		}
	}
	else {
		/* Create and show the dialog box */
		mcaststream_dlg_create();
		mcaststream_dlg_update(list);
	}
}


/****************************************************************************/
/* entry point when called via the GTK menu */
static void mcaststream_launch(GtkWidget *w _U_, gpointer data _U_)
{
	/* Register the tap listener */
	register_tap_listener_mcast_stream();

	/* Scan for Mcast streams (redissect all packets) */
	mcaststream_scan();

	/* Show the dialog box with the list of streams */
	mcaststream_dlg_show(mcaststream_get_info()->strinfo_list);

	/* Tap listener will be removed and cleaned up in mcaststream_on_destroy */
}

/****************************************************************************/
void
register_tap_listener_mcast_stream_dlg(void)
{
	register_stat_menu_item("Multicast Streams", REGISTER_STAT_GROUP_NONE,
	    mcaststream_launch, NULL, NULL, NULL);
}

/* wsp_stat.c
 * wsp_stat   2003 Jean-Michel FAYARD
 *
 * $Id: wsp_stat.c,v 1.15 2004/01/31 03:22:42 guy Exp $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/* #define DEBUG	do{ printf("%s:%d  ",__FILE__,__LINE__);} while(0); */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>

#include "epan/packet_info.h"
#include "epan/epan.h"
#include "menu.h"
#include "simple_dialog.h"
#include "dlg_utils.h"
#include "tap.h"
#include "../register.h"
#include "../globals.h"
#include "compat_macros.h"
#include "../packet-wsp.h"

/* used to keep track of the stats for a specific PDU type*/
typedef struct _wsp_pdu_t {
	GtkLabel 	*widget;
	guint32		 packets;
} wsp_pdu_t;

/* used to keep track of the statictics for an entire program interface */
typedef struct _wsp_stats_t {
	char 		*filter;
	wsp_pdu_t 	*pdu_stats;
	guint32		 num_pdus;
	GtkWidget 	*win;
	GHashTable	*hash;
	GtkWidget	*table_pdu_types;	
	GtkWidget	*table_status_code;
	guint		 index;	/* Number of status code to display */
} wspstat_t;
/* used to keep track of a single type of status code */
typedef struct _wsp_status_code_t {
	gchar		*name;
	guint32		 packets;
	GtkWidget	*widget;/* label in which we print the number of packets */
	wspstat_t	*sp;	/* entire program interface */
} wsp_status_code_t;

static GtkWidget *dlg=NULL;
static GtkWidget *filter_entry;

static void
wsp_free_hash( gpointer key, gpointer value, gpointer user_data _U_ )
{
	g_free(key);
	g_free(value);
}
static void
wsp_reset_hash(gchar *key _U_ , wsp_status_code_t *data, gpointer ptr _U_ ) 
{	
	data->packets = 0;
}

/* Update the entry corresponding to the number of packets of a special status code
 * or create it if it don't exist.
 */
static void
wsp_draw_statuscode(gchar *key _U_, wsp_status_code_t *data, gchar * string_buff )
{
	if ((data==NULL) || (data->packets==0))
		return;
	if (data->widget==NULL){	/* create an entry in the table */
		GtkWidget	*tmp;
		int x = 2*((data->sp->index) % 2);
		int y = (data->sp->index) /2;


		/* Maybe we should display the hexadecimal value ? */
		/* sprintf(string_buff, "%s  (0X%x)", data->name, *key); */
		tmp = gtk_label_new( data->name  /* string_buff */ );
		gtk_table_attach_defaults(GTK_TABLE(data->sp->table_status_code), tmp, x, x+1, y, y+1);
		gtk_label_set_justify(GTK_LABEL(tmp), GTK_JUSTIFY_LEFT);
		gtk_widget_show(tmp);

		sprintf( string_buff, "%9d", data->packets );
		data->widget = gtk_label_new( string_buff );
		gtk_table_attach_defaults(GTK_TABLE(data->sp->table_status_code), data->widget, x+1, x+2, y, y+1);
		gtk_label_set_justify(GTK_LABEL(data->widget), GTK_JUSTIFY_LEFT);
		gtk_widget_show( data->widget );

		data->sp->index++;
	} else {
		/* Just update the label string */
		sprintf( string_buff, "%9d", data->packets );
		gtk_label_set( GTK_LABEL(data->widget), string_buff);
	}
}
static void
wspstat_reset(void *psp)
{
	wspstat_t *sp=psp;
	guint32 i;

	for(i=1;i<=sp->num_pdus;i++)
	{
		sp->pdu_stats[i].packets=0;
	}
	g_hash_table_foreach( sp->hash, (GHFunc)wsp_reset_hash, NULL);	
}
static gint 
pdut2index(gint pdut)
{
	if (pdut<=0x09)		return pdut;
	if (pdut>=0x40){
		if (pdut <= 0x44){
			return pdut-54;
		} else if (pdut==0x60||pdut==0x61){
			return pdut-81;
		}
	}
	return 0;
}
static gint
index2pdut(gint pdut)
{
	if (pdut<=0x09)
		return pdut;
	if (pdut<=14)
		return pdut+54;
	if (pdut<=16)
		return pdut+81;
	return 0;
}

static int
wspstat_packet(void *psp, packet_info *pinfo _U_, epan_dissect_t *edt _U_, void *pri)
{
	wspstat_t *sp=psp;
	wsp_info_value_t *value=pri;
	gint index = pdut2index(value->pdut);
	int retour=0;

	if (value->status_code != 0) {
		gint *key=g_malloc( sizeof(gint) );
		wsp_status_code_t *sc;
		*key=value->status_code ;
		sc = g_hash_table_lookup( 
				sp->hash, 
				key);
		if (!sc) {
			g_warning("%s:%d What's Wrong, doc ?\n", __FILE__, __LINE__);
			sc = g_malloc( sizeof(wsp_status_code_t) );
			sc -> packets = 1;
			sc -> name = NULL;
			sc -> widget=NULL;
			sc -> sp = sp;
			g_hash_table_insert(
				sp->hash,
				key,
				sc);
		} else {
			sc->packets++;
		}
		retour=1;
	}

		

	if (index!=0) {
		sp->pdu_stats[ index ].packets++;
		retour = 1;
	}
	return retour;

}



static void
wspstat_draw(void *psp)
{
	wspstat_t *sp=psp;
	guint32 i;
	char str[256];
	guint index;

	for(i=1;i<=sp->num_pdus ; i++)
	{
		sprintf(str, "%9d",  sp->pdu_stats[i ].packets);
		gtk_label_set( GTK_LABEL(sp->pdu_stats[i].widget), str);
	}

	index=sp->index;
	g_hash_table_foreach( sp->hash, (GHFunc) wsp_draw_statuscode, str );
	if (index != sp->index){
		/* We have inserted a new entry corresponding to a status code ,
		 * let's resize the table */
		gtk_table_resize ( GTK_TABLE(sp->table_status_code), sp->index  % 2 , 4);
	}
	
}



/* since the gtk2 implementation of tap is multithreaded we must protect
 * remove_tap_listener() from modifying the list while draw_tap_listener()
 * is running.  the other protected block is in main.c
 *
 * there should not be any other critical regions in gtk2
 */
void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);
static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	wspstat_t *sp=(wspstat_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(sp);
	unprotect_thread_critical_region();

	g_free(sp->pdu_stats);
	g_free(sp->filter);
	g_hash_table_foreach( sp->hash, (GHFunc)wsp_free_hash, NULL);
	g_hash_table_destroy( sp->hash);	
	g_free(sp);
}

static void
add_table_entry(wspstat_t *sp, char *str, int x, int y, int index)
{
	GtkWidget *tmp;

	tmp=gtk_label_new( str );
	gtk_table_attach_defaults(GTK_TABLE(sp->table_pdu_types), tmp, x, x+1, y, y+1);
	gtk_label_set_justify(GTK_LABEL(tmp), GTK_JUSTIFY_LEFT);
	gtk_widget_show(tmp);
	if (index != 0) {
		sp->pdu_stats [index] .widget = GTK_LABEL( tmp ) ;
	}
}


static void
wsp_init_table(wspstat_t *sp)
{
	int pos=0;
	guint32 i;
	/* gchar	buffer[51];	*/
	
	add_table_entry( sp, "PDU Type               "	, 0, pos, 0);
	add_table_entry( sp, "packets  "	, 1, pos, 0);
	add_table_entry( sp, "PDU Type               "	, 2, pos, 0);
	add_table_entry( sp, "packets  "	, 3, pos, 0);
	pos++;
	for (i=1 ; i <= sp->num_pdus ; i++ )
	{
		int x = 0;
		if (i> (sp->num_pdus+1) /2 ){
			x=2;
		}
		/* Maybe we should display the hexadecimal value ? */
		/* snprintf(buffer, 50, "%s  (0X%x)", match_strval( index2pdut( i ), vals_pdu_type), index2pdut(i) );*/
		add_table_entry( sp, 
				match_strval(index2pdut(i), vals_pdu_type), /* or buffer, */
				x,
				pos,
				0
				);
		add_table_entry( sp, "0", x+1, pos
				, i /* keep a pointer to this widget to update it in _draw() */
				);	
		pos++;
		if (i== (sp->num_pdus+1) /2) {
			pos=1;
		}
	}
}

/* When called, this function will create a new instance of gtk2-wspstat.
 */
static void
gtk_wspstat_init(char *optarg)
{
	wspstat_t *sp;
	char 		*filter=NULL;
	char 		*title=NULL;
	GString		*error_string;
	GtkWidget	*main_vb, *pdutypes_fr, *statuscode_fr ;
	guint32		 i;
	wsp_status_code_t *sc;
	
	
	if (!strncmp (optarg, "wsp,stat,", 9)){
		filter=optarg+9;
	} else {
		filter=NULL;
	}
	
	sp = g_malloc( sizeof(wspstat_t) );
	sp->hash = g_hash_table_new( g_int_hash, g_int_equal);
	for (i=0 ; vals_status[i].strptr ; i++ )
	{
		gint *key;
		sc=g_malloc( sizeof(wsp_status_code_t) );
		key=g_malloc( sizeof(gint) );
		sc->name=vals_status[i].strptr;
		sc->packets=0;
		sc->widget=NULL;
		sc->sp = sp;
		*key=vals_status[i].value;
		g_hash_table_insert(
				sp->hash,
				key,
				sc);
	}
	sp->num_pdus = 16;
	sp->pdu_stats=g_malloc( (sp->num_pdus+1) * sizeof( wsp_pdu_t) );
	if(filter){
		sp->filter=g_malloc(strlen(filter)+1);
		strcpy(sp->filter,filter);
		title=g_strdup_printf("Ethereal: WSP statistics with filter: %s", filter);
	} else {
		sp->filter=NULL;
		title=g_strdup("Ethereal: WSP statistics");
	}
	for (i=0;i<=sp->num_pdus; i++)
	{
		sp->pdu_stats[i].packets=0;
	}

	sp->win = gtk_window_new( GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title( GTK_WINDOW(sp->win), title );
	g_free(title);
	SIGNAL_CONNECT( sp->win, "destroy", win_destroy_cb, sp);


	/* container for the two frames */
	main_vb = gtk_vbox_new(FALSE, 10);
	gtk_container_border_width(GTK_CONTAINER(main_vb), 10);
	gtk_container_add(GTK_CONTAINER(sp->win), main_vb);
	gtk_widget_show(main_vb);

	/* PDU Types frame */
	pdutypes_fr = gtk_frame_new("Summary of PDU Types (wsp.pdu_type)");
  	gtk_container_add(GTK_CONTAINER(main_vb), pdutypes_fr);
  	gtk_widget_show(pdutypes_fr);
	
	sp->table_pdu_types = gtk_table_new( (sp->num_pdus+1) / 2 + 1, 4, FALSE);
	gtk_container_add( GTK_CONTAINER( pdutypes_fr), sp->table_pdu_types);
	gtk_container_set_border_width( GTK_CONTAINER(sp->table_pdu_types) , 10);

	wsp_init_table(sp);
	gtk_widget_show( sp->table_pdu_types );

	/* Status Codes frame */
	statuscode_fr = gtk_frame_new("Summary of Status Code (wsp.reply.status)");
  	gtk_container_add(GTK_CONTAINER(main_vb), statuscode_fr);
  	gtk_widget_show(statuscode_fr);
	
	sp->table_status_code = gtk_table_new( 0, 4, FALSE);
	gtk_container_add( GTK_CONTAINER( statuscode_fr), sp->table_status_code);
	gtk_container_set_border_width( GTK_CONTAINER(sp->table_status_code) , 10);
	sp->index = 0; 		/* No answers to display yet */


	error_string = register_tap_listener( 
			"wsp",
			sp,
			filter,
			wspstat_reset,
			wspstat_packet,
			wspstat_draw);
	if (error_string){
		/* error, we failed to attach to the tap. clean up */
		simple_dialog( ESD_TYPE_ERROR, ESD_BTN_OK, error_string->str );
		g_free(sp->pdu_stats);
		g_free(sp->filter);
		g_free(sp);
		g_string_free(error_string, TRUE);
		return ;
	}
	gtk_widget_show_all( sp->win );
	retap_packets(&cfile);
}



static void
wspstat_start_button_clicked(GtkWidget *item _U_, gpointer data _U_)
{
	GString *str;
	char *filter;

	str = g_string_new("wsp,stat,");
	filter=(char *)gtk_entry_get_text(GTK_ENTRY(filter_entry));
	str = g_string_append(str, filter);
	gtk_wspstat_init(str->str);
	g_string_free(str, TRUE);
}

static void
dlg_destroy_cb(void)
{
	dlg=NULL;
}

static void
dlg_cancel_cb(GtkWidget *cancel_bt _U_, gpointer parent_w)
{
	gtk_widget_destroy(GTK_WIDGET(parent_w));
}

static void
gtk_wspstat_cb(GtkWidget *w _U_, gpointer d _U_)
{
	GtkWidget *dlg_box;
	GtkWidget *filter_box, *filter_label;
	GtkWidget *bbox, *start_button, *cancel_button;

	/* if the window is already open, bring it to front */
	if(dlg){
		gdk_window_raise(dlg->window);
		return;
	}

	dlg=dlg_window_new("Ethereal: Compute WSP statistics");
	SIGNAL_CONNECT(dlg, "destroy", dlg_destroy_cb, NULL);

	dlg_box=gtk_vbox_new(FALSE, 10);
	gtk_container_border_width(GTK_CONTAINER(dlg_box), 10);
	gtk_container_add(GTK_CONTAINER(dlg), dlg_box);
	gtk_widget_show(dlg_box);

	/* Filter box */
	filter_box=gtk_hbox_new(FALSE, 3);

	/* Filter label */
	filter_label=gtk_label_new("Filter:");
	gtk_box_pack_start(GTK_BOX(filter_box), filter_label, FALSE, FALSE, 0);
	gtk_widget_show(filter_label);

	/* Filter entry */
	filter_entry=gtk_entry_new();
	WIDGET_SET_SIZE(filter_entry, 300, -2);
	gtk_box_pack_start(GTK_BOX(filter_box), filter_entry, TRUE, TRUE, 0);
	gtk_widget_show(filter_entry);
	
	gtk_box_pack_start(GTK_BOX(dlg_box), filter_box, TRUE, TRUE, 0);
	gtk_widget_show(filter_box);

	/* button box */
    bbox = dlg_button_row_new(ETHEREAL_STOCK_CREATE_STAT, GTK_STOCK_CANCEL, NULL);
	gtk_box_pack_start(GTK_BOX(dlg_box), bbox, FALSE, FALSE, 0);
    gtk_widget_show(bbox);

    start_button = OBJECT_GET_DATA(bbox, ETHEREAL_STOCK_CREATE_STAT);
    gtk_widget_grab_default(start_button );
    SIGNAL_CONNECT_OBJECT(start_button, "clicked",
                              wspstat_start_button_clicked, NULL);

    cancel_button = OBJECT_GET_DATA(bbox, GTK_STOCK_CANCEL);
	SIGNAL_CONNECT(cancel_button, "clicked", dlg_cancel_cb, dlg);

	/* Catch the "activate" signal on the filter text entry, so that
	   if the user types Return there, we act as if the "Create Stat"
	   button had been selected, as happens if Return is typed if
	   some widget that *doesn't* handle the Return key has the input
	   focus. */
	dlg_set_activate(filter_entry, start_button);

	/* Catch the "key_press_event" signal in the window, so that we can
	   catch the ESC key being pressed and act as if the "Cancel" button
	   had been selected. */
	dlg_set_cancel(dlg, cancel_button);

	/* Give the initial focus to the "Filter" entry box. */
	gtk_widget_grab_focus(filter_entry);

	gtk_widget_show_all(dlg);
}


void
register_tap_listener_gtkwspstat(void)
{
	register_ethereal_tap("wsp,stat,", gtk_wspstat_init);
}

void
register_tap_menu_gtkwspstat(void)
{
	register_tap_menu_item("_Statistics/Watch protocol/WAP-WSP...",
	    gtk_wspstat_cb, NULL, NULL, NULL);
}

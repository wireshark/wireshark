/* wsp_stat.c
 * wsp_stat   2003 Jean-Michel FAYARD
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

/* #define DEBUG	do{ printf("%s:%d  ",__FILE__,__LINE__);} while(0); */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <string.h>

#include <gtk/gtk.h>

#include <epan/packet.h>
#include <epan/packet_info.h>
#include <epan/epan.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-wsp.h>

#include "ui/simple_dialog.h"
#include "../globals.h"
#include "../stat_menu.h"

#include "ui/gtk/gui_utils.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/tap_param_dlg.h"
#include "ui/gtk/main.h"

#include "ui/gtk/old-gtk-compat.h"

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
	const gchar	*name;
	guint32		 packets;
	GtkWidget	*widget;/* label in which we print the number of packets */
	wspstat_t	*sp;	/* entire program interface */
} wsp_status_code_t;

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
wsp_draw_statuscode(gchar *key _U_, wsp_status_code_t *data, gchar * unused _U_ )
{
	char string_buff[256];

	if ((data==NULL) || (data->packets==0))
		return;
	if (data->widget==NULL){	/* create an entry in the table */
		GtkWidget	*tmp;
		int x = 2*((data->sp->index) % 2);
		int y = (data->sp->index) /2;


		/* Maybe we should display the hexadecimal value ? */
		/* g_snprintf(string_buff, sizeof(string_buff), "%s  (0X%x)", data->name, *key); */
		tmp = gtk_label_new( data->name  /* string_buff */ );
		gtk_table_attach_defaults(GTK_TABLE(data->sp->table_status_code), tmp, x, x+1, y, y+1);
		gtk_label_set_justify(GTK_LABEL(tmp), GTK_JUSTIFY_LEFT);
		gtk_widget_show(tmp);

		g_snprintf( string_buff, sizeof(string_buff), "%9d", data->packets );
		data->widget = gtk_label_new( string_buff );
		gtk_table_attach_defaults(GTK_TABLE(data->sp->table_status_code), data->widget, x+1, x+2, y, y+1);
		gtk_label_set_justify(GTK_LABEL(data->widget), GTK_JUSTIFY_LEFT);
		gtk_widget_show( data->widget );

		data->sp->index++;
	} else {
		/* Just update the label string */
            g_snprintf( string_buff, sizeof(string_buff), "%9d", data->packets );
		 gtk_label_set_text( GTK_LABEL(data->widget), string_buff);
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
wspstat_packet(void *psp, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *pri)
{
	wspstat_t *sp=psp;
	const wsp_info_value_t *value=pri;
	gint idx = pdut2index(value->pdut);
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



	if (idx!=0) {
		sp->pdu_stats[ idx ].packets++;
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
	guint idx;

	for(i=1;i<=sp->num_pdus ; i++)
	{
            g_snprintf(str, sizeof(str), "%9d",  sp->pdu_stats[i ].packets);
		 gtk_label_set_text( GTK_LABEL(sp->pdu_stats[i].widget), str);
	}

	idx=sp->index;
	g_hash_table_foreach( sp->hash, (GHFunc) wsp_draw_statuscode, NULL );
	if (idx != sp->index){
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
add_table_entry(wspstat_t *sp, const char *str, int x, int y, int idx)
{
	GtkWidget *tmp;

	tmp=gtk_label_new( str );
	gtk_table_attach_defaults(GTK_TABLE(sp->table_pdu_types), tmp, x, x+1, y, y+1);
	gtk_label_set_justify(GTK_LABEL(tmp), GTK_JUSTIFY_LEFT);
	gtk_widget_show(tmp);
	if (idx != 0) {
		sp->pdu_stats [idx] .widget = GTK_LABEL( tmp ) ;
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
		/* g_snprintf(buffer, sizeof(buffer), "%s  (0X%x)", match_strval_ext( index2pdut( i ), &wsp_vals_pdu_type_ext), index2pdut(i) );*/
		add_table_entry( sp,
				match_strval_ext(index2pdut(i), &wsp_vals_pdu_type_ext), /* or buffer, */
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
gtk_wspstat_init(const char *optarg, void *userdata _U_)
{
	wspstat_t *sp;
	const char 	*filter=NULL;
	char 		*title=NULL;
	GString		*error_string;
	GtkWidget	*main_vb, *pdutypes_fr, *statuscode_fr ;
	GtkWidget	*bt_close;
	GtkWidget	*bbox;
	guint32		 i;
	wsp_status_code_t  *sc;
	const value_string *wsp_vals_status_p;


	if (strncmp (optarg, "wsp,stat,", 9) == 0){
		filter=optarg+9;
	} else {
		filter=NULL;
	}

	sp = g_malloc( sizeof(wspstat_t) );
	sp->win = dlg_window_new("wsp-stat");  /* transient_for top_level */
	gtk_window_set_destroy_with_parent (GTK_WINDOW(sp->win), TRUE);

	sp->hash = g_hash_table_new( g_int_hash, g_int_equal);
	wsp_vals_status_p = VALUE_STRING_EXT_VS_P(&wsp_vals_status_ext);
	for (i=0 ; wsp_vals_status_p[i].strptr ; i++ )
	{
		gint *key;
		sc=g_malloc( sizeof(wsp_status_code_t) );
		key=g_malloc( sizeof(gint) );
		sc->name=wsp_vals_status_p[i].strptr;
		sc->packets=0;
		sc->widget=NULL;
		sc->sp = sp;
		*key=wsp_vals_status_p[i].value;
		g_hash_table_insert(
				sp->hash,
				key,
				sc);
	}
	sp->num_pdus = 16;
	sp->pdu_stats=g_malloc( (sp->num_pdus+1) * sizeof( wsp_pdu_t) );
	if(filter){
		sp->filter=g_strdup(filter);
		title=g_strdup_printf("Wireshark: WAP-WSP statistics with filter: %s", filter);
	} else {
		sp->filter=NULL;
		title=g_strdup("Wireshark: WAP-WSP statistics");
	}
	for (i=0;i<=sp->num_pdus; i++)
	{
		sp->pdu_stats[i].packets=0;
	}

	gtk_window_set_title(GTK_WINDOW(sp->win), title);
	g_free(title);

	/* container for the two frames */
	main_vb = gtk_vbox_new(FALSE, 3);
	gtk_container_set_border_width(GTK_CONTAINER(main_vb), 12);
	gtk_container_add(GTK_CONTAINER(sp->win), main_vb);

	/* PDU Types frame */
	pdutypes_fr = gtk_frame_new("Summary of PDU Types (wsp.pdu_type)");
  	gtk_container_add(GTK_CONTAINER(main_vb), pdutypes_fr);

	sp->table_pdu_types = gtk_table_new( (sp->num_pdus+1) / 2 + 1, 4, FALSE);
	gtk_container_add( GTK_CONTAINER( pdutypes_fr), sp->table_pdu_types);
	gtk_container_set_border_width( GTK_CONTAINER(sp->table_pdu_types) , 10);

	wsp_init_table(sp);

	/* Status Codes frame */
	statuscode_fr = gtk_frame_new("Summary of Status Code (wsp.reply.status)");
  	gtk_container_add(GTK_CONTAINER(main_vb), statuscode_fr);

	sp->table_status_code = gtk_table_new( 0, 4, FALSE);
	gtk_container_add( GTK_CONTAINER( statuscode_fr), sp->table_status_code);
	gtk_container_set_border_width( GTK_CONTAINER(sp->table_status_code) , 10);
	sp->index = 0; 		/* No answers to display yet */

	error_string = register_tap_listener(
			"wsp",
			sp,
			filter,
			0,
			wspstat_reset,
			wspstat_packet,
			wspstat_draw);
	if (error_string){
		/* error, we failed to attach to the tap. clean up */
		simple_dialog( ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str );
		g_free(sp->pdu_stats);
		g_free(sp->filter);
		g_free(sp);
		g_string_free(error_string, TRUE);
		return ;
	}

	/* Button row. */
        bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
        gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);

        bt_close = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
        window_set_cancel_button(sp->win, bt_close, window_cancel_button_cb);

        g_signal_connect(sp->win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
        g_signal_connect(sp->win, "destroy", G_CALLBACK(win_destroy_cb), sp);

        gtk_widget_show_all(sp->win);
        window_present(sp->win);

        cf_retap_packets(&cfile);
	gdk_window_raise(gtk_widget_get_window(sp->win));
}

static tap_param wsp_stat_params[] = {
	{ PARAM_FILTER, "Filter", NULL }
};

static tap_param_dlg wsp_stat_dlg = {
	"WAP-WSP Packet Counter",
	"wsp,stat",
	gtk_wspstat_init,
	-1,
	G_N_ELEMENTS(wsp_stat_params),
	wsp_stat_params
};

void
register_tap_listener_gtkwspstat(void)
{
	register_dfilter_stat(&wsp_stat_dlg, "_WAP-WSP",
	    REGISTER_STAT_GROUP_TELEPHONY);
}

void wsp_stat_cb(GtkAction *action, gpointer user_data _U_)
{
	tap_param_dlg_cb(action, &wsp_stat_dlg);
}


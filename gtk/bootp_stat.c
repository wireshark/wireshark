/* bootp_stat.c
 * boop_stat   2003 Jean-Michel FAYARD
 *
 * $Id: bootp_stat.c,v 1.2 2003/09/17 19:39:31 guy Exp $
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
#include "menu.h"
#include "epan/packet_info.h"
#include "simple_dialog.h"
#include "tap.h"
#include "../register.h"
#include "../globals.h"
#include "compat_macros.h"
#include <string.h>


typedef const char* bootp_info_value_t;

/* used to keep track of the statictics for an entire program interface */
typedef struct _dhcp_stats_t {
	char 		*filter;
	GtkWidget 	*win;
	GHashTable	*hash;
	GtkWidget	*table_message_type;
	guint		 index;	/* Number of  to display */
} dhcpstat_t;
/* used to keep track of a single DHCP message type */
typedef struct _dhcp_message_type_t {
	const char	*name;
	guint32		 packets;
	GtkWidget	*widget;/* label in which we print the number of packets */
	dhcpstat_t	*sp;	/* entire program interface */
} dhcp_message_type_t;

static GtkWidget *dlg=NULL, *dlg_box;
static GtkWidget *filter_box;
static GtkWidget *filter_label, *filter_entry;
static GtkWidget *start_button;

static void
dhcp_free_hash( gpointer key _U_ , gpointer value, gpointer user_data _U_ )
{
	g_free(value);
}
static void
dhcp_reset_hash(gchar *key _U_ , dhcp_message_type_t *data, gpointer ptr _U_ ) 
{	
	data->packets = 0;
}

/* Update the entry corresponding to the number of packets of a special DHCP Message Type
 * or create it if it don't exist.
 */
static void
dhcp_draw_message_type(gchar *key _U_, dhcp_message_type_t *data, gchar * string_buff )
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
		gtk_table_attach_defaults(GTK_TABLE(data->sp->table_message_type), tmp, x, x+1, y, y+1);
		gtk_label_set_justify(GTK_LABEL(tmp), GTK_JUSTIFY_LEFT);
		gtk_widget_show(tmp);

		sprintf( string_buff, "%9d", data->packets );
		data->widget = gtk_label_new( string_buff );
		gtk_table_attach_defaults(GTK_TABLE(data->sp->table_message_type), data->widget, x+1, x+2, y, y+1);
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
dhcpstat_reset(void *psp)
{
	dhcpstat_t *sp=psp;
	g_hash_table_foreach( sp->hash, (GHFunc)dhcp_reset_hash, NULL);	
}
static int
dhcpstat_packet(void *psp, packet_info *pinfo _U_, epan_dissect_t *edt _U_, void *pri)
{
	dhcpstat_t *sp=psp;
	bootp_info_value_t value=pri;
	dhcp_message_type_t *sc;

	if (sp==NULL)
		return 0;
	sc = g_hash_table_lookup( 
			sp->hash, 
			value);
	if (!sc) {
		/*g_warning("%s:%d What's Wrong for %s, doc ?", __FILE__, __LINE__, value);*/
		sc = g_malloc( sizeof(dhcp_message_type_t) );
		sc -> packets = 1;
		sc -> name = value;
		sc -> widget=NULL;
		sc -> sp = sp;
		g_hash_table_insert(
				sp->hash,
				(gpointer) value,
				sc);
	} else {
		/*g_warning("sc(%s)->packets++", sc->name);*/
		sc->packets++;
	}
	return 1;
}


static void
dhcpstat_draw(void *psp)
{
	dhcpstat_t *sp=psp;
	char str[256];
	guint index;

	index=sp->index;
	g_hash_table_foreach( sp->hash, (GHFunc) dhcp_draw_message_type, str );
	if (index != sp->index){
		/* We have inserted a new entry corresponding to a status code ,
		 * let's resize the table */
		gtk_table_resize ( GTK_TABLE(sp->table_message_type), sp->index  % 2 , 4);
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
	dhcpstat_t *sp=(dhcpstat_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(sp);
	unprotect_thread_critical_region();

	g_free(sp->filter);
	g_hash_table_foreach( sp->hash, (GHFunc)dhcp_free_hash, NULL);
	g_hash_table_destroy( sp->hash);	
	g_free(sp);
}



/* When called, this function will create a new instance of gtk2-dhcpstat.
 */
static void
gtk_dhcpstat_init(char *optarg)
{
	dhcpstat_t *sp;
	char 		*filter=NULL;
	char 		*title=NULL;
	GString		*error_string;
	GtkWidget	*message_type_fr ;
	
	if (!strncmp (optarg, "bootp,stat,", 11)){
		filter=optarg+11;
	} else {
		filter=NULL;
	}
	
	sp = g_malloc( sizeof(dhcpstat_t) );
	sp->hash = g_hash_table_new( g_str_hash, g_str_equal);
	if(filter){
		sp->filter=g_malloc(strlen(filter)+1);
		strcpy(sp->filter,filter);
		title=g_strdup_printf("DHCP Stats with filter: %s", filter);
	} else {
		sp->filter=NULL;
		title=g_strdup("DHCP Stats");
	}

	sp->win = gtk_window_new( GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title( GTK_WINDOW(sp->win), title );
	g_free(title);
	SIGNAL_CONNECT( sp->win, "destroy", win_destroy_cb, sp);


	/* Status Codes frame */
	message_type_fr = gtk_frame_new("DHCP Message Type");
  	gtk_container_add(GTK_CONTAINER(sp->win), message_type_fr);
  	gtk_widget_show(message_type_fr);
	
	sp->table_message_type = gtk_table_new( 0, 4, FALSE);
	gtk_table_set_col_spacings( GTK_TABLE(sp->table_message_type), 10);
	gtk_container_add( GTK_CONTAINER( message_type_fr), sp->table_message_type);
	gtk_container_set_border_width( GTK_CONTAINER(sp->table_message_type) , 10);
	sp->index = 0; 		/* Nothing to display yet */


	error_string = register_tap_listener( 
			"bootp",
			sp,
			filter,
			dhcpstat_reset,
			dhcpstat_packet,
			dhcpstat_draw);
	if (error_string){
		/* error, we failed to attach to the tap. clean up */
		simple_dialog( ESD_TYPE_WARN, NULL, error_string->str );
		g_free(sp->filter);
		g_free(sp);
		g_string_free(error_string, TRUE);
		return ;
	}
	if (dlg){
		gtk_widget_destroy( dlg );
	}
	gtk_widget_show_all( sp->win );
	redissect_packets(&cfile);
}



static void
dhcp_start_button_clicked(GtkWidget *item _U_, gpointer data _U_)
{
	char *filter;
	char str[256];

	filter=(char *)gtk_entry_get_text(GTK_ENTRY(filter_entry));
	if(filter[0]==0){
		gtk_dhcpstat_init("dhcp,stat,");
	} else {
		sprintf(str, "dhcp,stat,%s", filter);
		gtk_dhcpstat_init(str);
	}
}

static void
dlg_destroy_cb(void)
{
	dlg=NULL;
}

static void
gtk_dhcpstat_cb(GtkWidget *w _U_, gpointer d _U_)
{
	/* if the window is already open, bring it to front */
	if(dlg){
		gdk_window_raise(dlg->window);
		return;
	}

	dlg=gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(dlg), "WSP Statistics");
	SIGNAL_CONNECT(dlg, "destroy", dlg_destroy_cb, NULL);
	dlg_box=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(dlg), dlg_box);
	gtk_widget_show(dlg_box);


	/* filter box */
	filter_box=gtk_hbox_new(FALSE, 10);
	/* Filter label */
	gtk_container_set_border_width(GTK_CONTAINER(filter_box), 10);
	filter_label=gtk_label_new("Filter:");
	gtk_box_pack_start(GTK_BOX(filter_box), filter_label, FALSE, FALSE, 0);
	gtk_widget_show(filter_label);

	filter_entry=gtk_entry_new_with_max_length(250);
	gtk_box_pack_start(GTK_BOX(filter_box), filter_entry, FALSE, FALSE, 0);
	gtk_widget_show(filter_entry);
	
	gtk_box_pack_start(GTK_BOX(dlg_box), filter_box, TRUE, TRUE, 0);
	gtk_widget_show(filter_box);


	/* the start button */
	start_button=gtk_button_new_with_label("Create Stat");
        SIGNAL_CONNECT_OBJECT(start_button, "clicked",
                              dhcp_start_button_clicked, NULL);
	gtk_box_pack_start(GTK_BOX(dlg_box), start_button, TRUE, TRUE, 0);
	gtk_widget_show(start_button);

	gtk_widget_show_all(dlg);
}


void
register_tap_listener_gtkdhcpstat(void)
{
	register_ethereal_tap("bootp,stat,", gtk_dhcpstat_init);
}

void
register_tap_menu_gtkdhcpstat(void)
{
	register_tap_menu_item("Statistics/Watch protocol/BOOTP-DHCP", gtk_dhcpstat_cb);
}

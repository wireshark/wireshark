/* bootp_stat.c
 * boop_stat   2003 Jean-Michel FAYARD
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* #define DEBUG	do{ printf("%s:%d  ",__FILE__,__LINE__);} while(0); */
#include "config.h"

#include <gtk/gtk.h>
#include <string.h>

#include <epan/packet_info.h>
#include <epan/epan.h>
#include <epan/tap.h>

#include "../stat_menu.h"

#include "ui/simple_dialog.h"

#include "ui/gtk/gui_utils.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/tap_param_dlg.h"
#include "ui/gtk/main.h"

#include "ui/gtk/old-gtk-compat.h"

typedef const char *bootp_info_value_t;

/* used to keep track of the statistics for an entire program interface */
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

static void
dhcp_reset_hash(gchar *key _U_ , dhcp_message_type_t *data, gpointer ptr _U_)
{
	data->packets = 0;
}

/* Update the entry corresponding to the number of packets of a special DHCP Message Type
 * or create it if it don't exist.
 */
static void
dhcp_draw_message_type(gchar *key _U_, dhcp_message_type_t *data, gchar * unused _U_)
{
	char string_buff[256];

	if ((data == NULL) || (data->packets == 0))
		return;
	if (data->widget == NULL) {	/* create an entry in the table */
		GtkWidget *tmp;
		int x = 2*((data->sp->index) % 2);
		int y = (data->sp->index) / 2;

		/* Maybe we should display the hexadecimal value ? */
		/* g_snprintf(string_buff, sizeof(string_buff), "%s  (0X%x)", data->name, *key); */
		tmp = gtk_label_new(data->name  /* string_buff */);
		gtk_table_attach_defaults(GTK_TABLE(data->sp->table_message_type), tmp, x, x+1, y, y+1);
		gtk_label_set_justify(GTK_LABEL(tmp), GTK_JUSTIFY_LEFT);
		gtk_widget_show(tmp);

		g_snprintf(string_buff, sizeof(string_buff), "%9d", data->packets);
		data->widget = gtk_label_new(string_buff);
		gtk_table_attach_defaults(GTK_TABLE(data->sp->table_message_type), data->widget, x+1, x+2, y, y+1);
		gtk_label_set_justify(GTK_LABEL(data->widget), GTK_JUSTIFY_LEFT);
		gtk_widget_show(data->widget);

		data->sp->index++;
	} else {
		/* Just update the label string */
		g_snprintf(string_buff, sizeof(string_buff), "%9d", data->packets);
		gtk_label_set_text(GTK_LABEL(data->widget), string_buff);
	}
}
static void
dhcpstat_reset(void *psp)
{
	dhcpstat_t *sp = psp;
	g_hash_table_foreach(sp->hash, (GHFunc)dhcp_reset_hash, NULL);
}
static gboolean
dhcpstat_packet(void *psp, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *pri)
{
	dhcpstat_t               *sp    = psp;
	const bootp_info_value_t  value = pri;
	dhcp_message_type_t      *sc;

	if (sp == NULL)
		return FALSE;

	sc = g_hash_table_lookup(
			sp->hash,
			value);
	if (!sc) {
		/*g_warning("%s:%d What's Wrong for %s, doc ?", __FILE__, __LINE__, value);*/
		sc = g_malloc(sizeof(dhcp_message_type_t));
		sc->packets = 1;
		sc->name    = value;
		sc->widget  = NULL;
		sc->sp	    = sp;
		g_hash_table_insert(
				sp->hash,
				(gpointer)value, /* XXX: Fixme: not OK: value might possibly be ep_alloc'd string !! */
				                 /*                     {if "Unknown Message Type ...")              */
				sc);
	} else {
		/*g_warning("sc(%s)->packets++", sc->name);*/
		sc->packets++;
	}
	return TRUE;
}


static void
dhcpstat_draw(void *psp)
{
	dhcpstat_t *sp = psp;

	g_hash_table_foreach(sp->hash, (GHFunc)dhcp_draw_message_type, NULL);
}

static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	dhcpstat_t *sp = (dhcpstat_t *)data;

	remove_tap_listener(sp);

	g_free(sp->filter);
	g_hash_table_destroy(sp->hash);
	g_free(sp);
}


/* When called, this function will create a new instance of gtk2-dhcpstat.
 */
static void
dhcpstat_init(const char *optarg, void *userdata _U_)
{
	dhcpstat_t *sp;
	const char *filter;
	char 	   *title;
	GString	   *error_string;
	GtkWidget  *message_type_fr;
	GtkWidget  *vbox;
	GtkWidget  *bt_close;
	GtkWidget  *bbox;

	if (strncmp(optarg, "bootp,stat,", 11) == 0) {
		filter = optarg+11;
	} else {
		filter = NULL;
	}

	sp = g_malloc(sizeof(dhcpstat_t));
	sp->hash = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
	if(filter) {
		sp->filter = g_strdup(filter);
		title = g_strdup_printf("DHCP statistics with filter: %s", filter);
	} else {
		sp->filter = NULL;
		title = g_strdup("DHCP statistics");
	}

	/* transient_for top_level */
	sp->win = dlg_window_new(title);
	gtk_window_set_destroy_with_parent(GTK_WINDOW(sp->win), TRUE);
	g_free(title);

	vbox = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 3, FALSE);
	gtk_container_add(GTK_CONTAINER(sp->win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

	/* Status Codes frame */
	message_type_fr = gtk_frame_new("DHCP Message Type");
	gtk_box_pack_start(GTK_BOX(vbox), message_type_fr, TRUE, TRUE, 0);
	gtk_widget_show(message_type_fr);

	sp->table_message_type = gtk_table_new(0, 4, FALSE);
	gtk_table_set_col_spacings(GTK_TABLE(sp->table_message_type), 10);
	gtk_container_add(GTK_CONTAINER(message_type_fr), sp->table_message_type);
	gtk_container_set_border_width(GTK_CONTAINER(sp->table_message_type) , 10);
	sp->index = 0; 		/* Nothing to display yet */


	error_string = register_tap_listener(
			"bootp",
			sp,
			filter,
			0,
			dhcpstat_reset,
			dhcpstat_packet,
			dhcpstat_draw);
	if (error_string) {
		/* error, we failed to attach to the tap. clean up */
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
		g_free(sp->filter);
		g_free(sp);
		g_string_free(error_string, TRUE);
		return ;
	}

	/* Button row. */
	bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
	gtk_box_pack_start(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

	bt_close = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
	window_set_cancel_button(sp->win, bt_close, window_cancel_button_cb);

	g_signal_connect(sp->win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(sp->win, "destroy", G_CALLBACK(win_destroy_cb), sp);

	gtk_widget_show_all(sp->win);

	window_present(sp->win);

	cf_retap_packets(&cfile);
	gdk_window_raise(gtk_widget_get_window(sp->win));
}

static tap_param bootp_stat_params[] = {
	{ PARAM_FILTER, "Filter", NULL }
};

static tap_param_dlg dhcp_stat_dlg = {
	"BOOTP-DHCP Packet Counter",
	"bootp,stat",
	dhcpstat_init,
	-1,
	G_N_ELEMENTS(bootp_stat_params),
	bootp_stat_params
};

void
register_tap_listener_gtkdhcpstat(void)
{
	register_dfilter_stat(&dhcp_stat_dlg, "BOOTP-DHCP",
	    REGISTER_STAT_GROUP_UNSORTED);
}


void
bootp_dhcp_stat_cb(GtkAction *action, gpointer user_data _U_)
{
	tap_param_dlg_cb(action, &dhcp_stat_dlg);
}


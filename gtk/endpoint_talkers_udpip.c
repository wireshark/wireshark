/* endpoint_talkers_udpip.c
 * endpoint_talkers_udpip   2003 Ronnie Sahlberg
 *
 * $Id: endpoint_talkers_udpip.c,v 1.5 2003/08/24 22:34:32 guy Exp $
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <gtk/gtk.h>
#include <string.h>
#include "menu.h"
#include "../epan/packet_info.h"
#include "../tap.h"
#include "../register.h"
#include "compat_macros.h"
#include "../simple_dialog.h"
#include "../file.h"
#include "../globals.h"
#include "endpoint_talkers_table.h"
#include "packet-udp.h"

/* used to keep track of the statistics for one instance of the stats */
typedef struct _udpip_talkers_t {
	GtkWidget *win;
	endpoints_table talkers;
} udpip_talkers_t;


void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);
static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	udpip_talkers_t *udpip_talkers=(udpip_talkers_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(udpip_talkers);
	unprotect_thread_critical_region();

	reset_ett_table_data(&udpip_talkers->talkers);
	g_free(udpip_talkers);
}

static char *
udpip_port_to_str(guint32 port)
{
	static int i=0;
	static char *strp, str[4][6];

	i++;
	if(i>=4){
		i=0;
	}
	strp=str[i];

	sprintf(strp, "%u", port);

	return strp;
}

static void
udpip_talkers_reset(void *pit)
{
	udpip_talkers_t *udpip_talkers=(udpip_talkers_t *)pit;

	reset_ett_table_data(&udpip_talkers->talkers);
}


static void
udpip_talkers_draw(void *pit)
{
	udpip_talkers_t *udpip_talkers=(udpip_talkers_t *)pit;

	draw_ett_table_data(&udpip_talkers->talkers);
}


static int
udpip_talkers_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, void *vip)
{
	udpip_talkers_t *udpip_talkers=(udpip_talkers_t *)pit;
	e_udphdr *udphdr=vip;

	add_ett_table_data(&udpip_talkers->talkers, &udphdr->ip_src, &udphdr->ip_dst, udphdr->uh_sport, udphdr->uh_dport, 1, pinfo->fd->pkt_len);

	return 1;
}



static void
gtk_udpip_talkers_init(char *optarg)
{
	char *filter=NULL;
	udpip_talkers_t *udpip_talkers;
	GtkWidget *vbox;
	GtkWidget *label;
	GString *error_string;


	if(!strncmp(optarg,"talkers,udp,",12)){
		filter=optarg+12;
	} else {
		filter=NULL;
	}

	udpip_talkers=g_malloc(sizeof(udpip_talkers_t));

	udpip_talkers->win=gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_default_size(GTK_WINDOW(udpip_talkers->win), 750, 400);
	gtk_window_set_title(GTK_WINDOW(udpip_talkers->win), "UDP Talkers");

	SIGNAL_CONNECT(udpip_talkers->win, "destroy", win_destroy_cb, udpip_talkers);

	vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(udpip_talkers->win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 10);
	gtk_widget_show(vbox);

	label=gtk_label_new("UDP Talkers");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	/* We must display TOP LEVEL Widget before calling init_ett_table() */
	gtk_widget_show(udpip_talkers->win);

	init_ett_table(&udpip_talkers->talkers, vbox, address_to_str, udpip_port_to_str);

	error_string=register_tap_listener("udp", udpip_talkers, filter, udpip_talkers_reset, udpip_talkers_packet, udpip_talkers_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_WARN, NULL, error_string->str);
		g_string_free(error_string, TRUE);
		g_free(udpip_talkers);
		return;
	}

	gtk_widget_show_all(udpip_talkers->win);
	redissect_packets(&cfile);
}


static void
gtk_udpip_endpoints_cb(GtkWidget *w _U_, gpointer d _U_)
{
	gtk_udpip_talkers_init("talkers,udp");
}


void
register_tap_menu_udpip_talkers(void)
{
	register_tap_menu_item("Endpoint Talkers/UDP (IPv4 IPv6)", gtk_udpip_endpoints_cb);
}




void
register_tap_listener_udpip_talkers(void)
{
	register_ethereal_tap("talkers,udp", gtk_udpip_talkers_init);
}


/* should be trivial to extend to handle ipv6 as well.    currently only support
for ipv4*/
/* endpoint_talkers_tcpip.c
 * endpoint_talkers_tcpip   2003 Ronnie Sahlberg
 *
 * $Id: endpoint_talkers_tcpip.c,v 1.1 2003/08/23 09:09:35 sahlberg Exp $
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
#include "packet-tcp.h"

/* used to keep track of the statistics for one instance of the stats */
typedef struct _tcpip_talkers_t {
	GtkWidget *win;
	endpoints_table talkers;
} tcpip_talkers_t;


void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);
static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	tcpip_talkers_t *tcpip_talkers=(tcpip_talkers_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(tcpip_talkers);
	unprotect_thread_critical_region();

	reset_ett_table_data(&tcpip_talkers->talkers);
	g_free(tcpip_talkers);
}


static char *
tcpip_address_to_str(address *addr)
{
	static int i=0;
	static char *strp, str[4][256];

	i++;
	if(i>=4){
		i=0;
	}
	strp=str[i];

	switch(addr->type){
	case AT_IPv4:
		sprintf(strp, "%d.%d.%d.%d", addr->data[0], addr->data[1], addr->data[2], addr->data[3]);
		break;
	default:
		fprintf(stderr, "Unsupported transport for TCP in the TCP talkers tap.\n");
	}

	return strp;
}

static char *
tcpip_port_to_str(guint32 port)
{
	static int i=0;
	static char *strp, str[4][6];

	i++;
	if(i>=4){
		i=0;
	}
	strp=str[i];

	sprintf(strp, "%d", port);

	return strp;
}

static void
tcpip_talkers_reset(void *pit)
{
	tcpip_talkers_t *tcpip_talkers=(tcpip_talkers_t *)pit;

	reset_ett_table_data(&tcpip_talkers->talkers);
}


static void
tcpip_talkers_draw(void *pit)
{
	tcpip_talkers_t *tcpip_talkers=(tcpip_talkers_t *)pit;

	draw_ett_table_data(&tcpip_talkers->talkers);
}


static int
tcpip_talkers_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, void *vip)
{
	tcpip_talkers_t *tcpip_talkers=(tcpip_talkers_t *)pit;
	struct tcpheader *tcphdr=vip;

	add_ett_table_data(&tcpip_talkers->talkers, &tcphdr->ip_src, &tcphdr->ip_dst, tcphdr->th_sport, tcphdr->th_dport, 1, pinfo->fd->pkt_len);

	return 1;
}



static void
gtk_tcpip_talkers_init(char *optarg)
{
	char *filter=NULL;
	tcpip_talkers_t *tcpip_talkers;
	GtkWidget *vbox;
	GtkWidget *label;
	GString *error_string;


	if(!strncmp(optarg,"talkers,tcpip,",14)){
		filter=optarg+14;
	} else {
		filter=NULL;
	}

	tcpip_talkers=g_malloc(sizeof(tcpip_talkers_t));

	tcpip_talkers->win=gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_default_size(GTK_WINDOW(tcpip_talkers->win), 750, 400);
	gtk_window_set_title(GTK_WINDOW(tcpip_talkers->win), "TCP/IP Talkers");

	SIGNAL_CONNECT(tcpip_talkers->win, "destroy", win_destroy_cb, tcpip_talkers);

	vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(tcpip_talkers->win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 10);
	gtk_widget_show(vbox);

	label=gtk_label_new("TCPIP Talkers");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	/* We must display TOP LEVEL Widget before calling init_ett_table() */
	gtk_widget_show(tcpip_talkers->win);

	init_ett_table(&tcpip_talkers->talkers, vbox, tcpip_address_to_str, tcpip_port_to_str);

	error_string=register_tap_listener("tcp", tcpip_talkers, filter, tcpip_talkers_reset, tcpip_talkers_packet, tcpip_talkers_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_WARN, NULL, error_string->str);
		g_string_free(error_string, TRUE);
		g_free(tcpip_talkers);
		return;
	}

	gtk_widget_show_all(tcpip_talkers->win);
	redissect_packets(&cfile);
}


static void
gtk_tcpip_endpoints_cb(GtkWidget *w _U_, gpointer d _U_)
{
	gtk_tcpip_talkers_init("talkers,tcpip");
}


void
register_tap_menu_tcpip_talkers(void)
{
	register_tap_menu_item("Endpoint Talkers/TCPIP", gtk_tcpip_endpoints_cb);
}




void
register_tap_listener_tcpip_talkers(void)
{
	register_ethereal_tap("talkers,tcpip", gtk_tcpip_talkers_init);
}


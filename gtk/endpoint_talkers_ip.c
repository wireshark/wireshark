/* endpoint_talkers_ip.c
 * endpoint_talkers_ip   2003 Ronnie Sahlberg
 *
 * $Id: endpoint_talkers_ip.c,v 1.4 2003/08/24 22:34:31 guy Exp $
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
#include "packet-ip.h"

/* used to keep track of the statistics for one instance of the stats */
typedef struct _ip_talkers_t {
	GtkWidget *win;
	endpoints_table talkers;
} ip_talkers_t;


void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);
static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	ip_talkers_t *ip_talkers=(ip_talkers_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(ip_talkers);
	unprotect_thread_critical_region();

	reset_ett_table_data(&ip_talkers->talkers);
	g_free(ip_talkers);
}

static void
ip_talkers_reset(void *pit)
{
	ip_talkers_t *ip_talkers=(ip_talkers_t *)pit;

	reset_ett_table_data(&ip_talkers->talkers);
}


static void
ip_talkers_draw(void *pit)
{
	ip_talkers_t *ip_talkers=(ip_talkers_t *)pit;

	draw_ett_table_data(&ip_talkers->talkers);
}


static int
ip_talkers_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, void *vip)
{
	ip_talkers_t *ip_talkers=(ip_talkers_t *)pit;
	e_ip *iph=vip;

	add_ett_table_data(&ip_talkers->talkers, &iph->ip_src, &iph->ip_dst, 0, 0, 1, pinfo->fd->pkt_len);

	return 1;
}



static void
gtk_ip_talkers_init(char *optarg)
{
	char *filter=NULL;
	ip_talkers_t *ip_talkers;
	GtkWidget *vbox;
	GtkWidget *label;
	GString *error_string;


	if(!strncmp(optarg,"talkers,ip,",11)){
		filter=optarg+11;
	} else {
		filter=NULL;
	}

	ip_talkers=g_malloc(sizeof(ip_talkers_t));

	ip_talkers->win=gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_default_size(GTK_WINDOW(ip_talkers->win), 750, 400);
	gtk_window_set_title(GTK_WINDOW(ip_talkers->win), "IPv4 Talkers");

	SIGNAL_CONNECT(ip_talkers->win, "destroy", win_destroy_cb, ip_talkers);

	vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(ip_talkers->win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 10);
	gtk_widget_show(vbox);

	label=gtk_label_new("IPv4 Talkers");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	/* We must display TOP LEVEL Widget before calling init_ett_table() */
	gtk_widget_show(ip_talkers->win);

	init_ett_table(&ip_talkers->talkers, vbox, address_to_str, NULL);

	error_string=register_tap_listener("ip", ip_talkers, filter, ip_talkers_reset, ip_talkers_packet, ip_talkers_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_WARN, NULL, error_string->str);
		g_string_free(error_string, TRUE);
		g_free(ip_talkers);
		return;
	}

	gtk_widget_show_all(ip_talkers->win);
	redissect_packets(&cfile);
}


static void
gtk_ip_endpoints_cb(GtkWidget *w _U_, gpointer d _U_)
{
	gtk_ip_talkers_init("talkers,ip");
}


void
register_tap_menu_ip_talkers(void)
{
	register_tap_menu_item("Endpoint Talkers/IPv4", gtk_ip_endpoints_cb);
}




void
register_tap_listener_ip_talkers(void)
{
	register_ethereal_tap("talkers,ip", gtk_ip_talkers_init);
}


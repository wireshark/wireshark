/* endpoint_talkers_ipx.c
 * endpoint_talkers_ipx   2003 Ronnie Sahlberg
 *
 * $Id: endpoint_talkers_ipx.c,v 1.2 2003/08/24 22:34:31 guy Exp $
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
#include "packet-ipx.h"

/* used to keep track of the statistics for one instance of the stats */
typedef struct _ipx_talkers_t {
	GtkWidget *win;
	endpoints_table talkers;
} ipx_talkers_t;


void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);
static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	ipx_talkers_t *ipx_talkers=(ipx_talkers_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(ipx_talkers);
	unprotect_thread_critical_region();

	reset_ett_table_data(&ipx_talkers->talkers);
	g_free(ipx_talkers);
}

static void
ipx_talkers_reset(void *pit)
{
	ipx_talkers_t *ipx_talkers=(ipx_talkers_t *)pit;

	reset_ett_table_data(&ipx_talkers->talkers);
}


static void
ipx_talkers_draw(void *pit)
{
	ipx_talkers_t *ipx_talkers=(ipx_talkers_t *)pit;

	draw_ett_table_data(&ipx_talkers->talkers);
}


static int
ipx_talkers_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, void *vip)
{
	ipx_talkers_t *ipx_talkers=(ipx_talkers_t *)pit;
	ipxhdr_t *ipxh=vip;

	add_ett_table_data(&ipx_talkers->talkers, &ipxh->ipx_src, &ipxh->ipx_dst, 0, 0, 1, pinfo->fd->pkt_len);

	return 1;
}



static void
gtk_ipx_talkers_init(char *optarg)
{
	char *filter=NULL;
	ipx_talkers_t *ipx_talkers;
	GtkWidget *vbox;
	GtkWidget *label;
	GString *error_string;


	if(!strncmp(optarg,"talkers,ipx,",12)){
		filter=optarg+12;
	} else {
		filter=NULL;
	}

	ipx_talkers=g_malloc(sizeof(ipx_talkers_t));

	ipx_talkers->win=gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_default_size(GTK_WINDOW(ipx_talkers->win), 750, 400);
	gtk_window_set_title(GTK_WINDOW(ipx_talkers->win), "IPX Talkers");

	SIGNAL_CONNECT(ipx_talkers->win, "destroy", win_destroy_cb, ipx_talkers);

	vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(ipx_talkers->win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 10);
	gtk_widget_show(vbox);

	label=gtk_label_new("IPX Talkers");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	/* We must display TOP LEVEL Widget before calling init_ett_table() */
	gtk_widget_show(ipx_talkers->win);

	init_ett_table(&ipx_talkers->talkers, vbox, address_to_str, NULL);

	error_string=register_tap_listener("ipx", ipx_talkers, filter, ipx_talkers_reset, ipx_talkers_packet, ipx_talkers_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_WARN, NULL, error_string->str);
		g_string_free(error_string, TRUE);
		g_free(ipx_talkers);
		return;
	}

	gtk_widget_show_all(ipx_talkers->win);
	redissect_packets(&cfile);
}


static void
gtk_ipx_endpoints_cb(GtkWidget *w _U_, gpointer d _U_)
{
	gtk_ipx_talkers_init("talkers,ipx");
}


void
register_tap_menu_ipx_talkers(void)
{
	register_tap_menu_item("Endpoint Talkers/IPX", gtk_ipx_endpoints_cb);
}




void
register_tap_listener_ipx_talkers(void)
{
	register_ethereal_tap("talkers,ipx", gtk_ipx_talkers_init);
}


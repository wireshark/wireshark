/* endpoint_talkers_ipx.c
 * endpoint_talkers_ipx   2003 Ronnie Sahlberg
 *
 * $Id: endpoint_talkers_ipx.c,v 1.6 2003/08/30 00:47:43 sahlberg Exp $
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


void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);
static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	endpoints_table *talkers=(endpoints_table *)data;

	protect_thread_critical_region();
	remove_tap_listener(talkers);
	unprotect_thread_critical_region();

	reset_ett_table_data(talkers);
	g_free(talkers);
}

static void
ipx_talkers_reset(void *pit)
{
	endpoints_table *talkers=(endpoints_table *)pit;
	char title[256];

	reset_ett_table_data(talkers);
	snprintf(title, 255, "IPX Talkers: %s", cfile.filename);
	gtk_window_set_title(GTK_WINDOW(talkers->win), title);
}


static void
ipx_talkers_draw(void *pit)
{
	endpoints_table *talkers=(endpoints_table *)pit;

	draw_ett_table_data(talkers);
}


static int
ipx_talkers_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, void *vip)
{
	endpoints_table *talkers=(endpoints_table *)pit;
	ipxhdr_t *ipxh=vip;

	add_ett_table_data(talkers, &ipxh->ipx_src, &ipxh->ipx_dst, 0, 0, 1, pinfo->fd->pkt_len);

	return 1;
}



static void
gtk_ipx_talkers_init(char *optarg)
{
	char *filter=NULL;
	endpoints_table *talkers;
	GtkWidget *vbox;
	GtkWidget *label;
	GString *error_string;
	char title[256];
	static char *filter_names[] = {
		"ipx.node",
		"ipx.src.node",
		"ipx.dst.node",
		NULL,
		NULL,
		NULL
		};

	if(!strncmp(optarg,"talkers,ipx,",12)){
		filter=optarg+12;
	} else {
		filter=NULL;
	}

	talkers=g_malloc(sizeof(endpoints_table));

	talkers->win=gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_default_size(GTK_WINDOW(talkers->win), 750, 400);
	snprintf(title, 255, "IPX Talkers: %s", cfile.filename);
	gtk_window_set_title(GTK_WINDOW(talkers->win), title);

	SIGNAL_CONNECT(talkers->win, "destroy", win_destroy_cb, talkers);

	vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(talkers->win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 10);
	gtk_widget_show(vbox);

	label=gtk_label_new("IPX Talkers");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	/* We must display TOP LEVEL Widget before calling init_ett_table() */
	gtk_widget_show(talkers->win);

	init_ett_table(talkers, vbox, NULL, filter_names);

	error_string=register_tap_listener("ipx", talkers, filter, ipx_talkers_reset, ipx_talkers_packet, ipx_talkers_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_WARN, NULL, error_string->str);
		g_string_free(error_string, TRUE);
		g_free(talkers);
		return;
	}

	gtk_widget_show_all(talkers->win);
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


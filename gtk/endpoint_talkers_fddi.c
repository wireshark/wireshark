/* endpoint_talkers_fddi.c
 * endpoint_talkers_fddi   2003 Ronnie Sahlberg
 *
 * $Id: endpoint_talkers_fddi.c,v 1.6 2003/09/02 08:27:25 sahlberg Exp $
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
#include "../epan/filesystem.h"
#include "../tap.h"
#include "../register.h"
#include "compat_macros.h"
#include "../simple_dialog.h"
#include "../file.h"
#include "../globals.h"
#include "endpoint_talkers_table.h"
#include "packet-fddi.h"



static int
fddi_talkers_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, void *vip)
{
	endpoints_table *talkers=(endpoints_table *)pit;
	fddi_hdr *ehdr=vip;

	add_ett_table_data(talkers, &ehdr->src, &ehdr->dst, 0, 0, 1, pinfo->fd->pkt_len);

	return 1;
}



static void
gtk_fddi_talkers_init(char *optarg)
{
	char *filter=NULL;
	endpoints_table *talkers;
	GtkWidget *vbox;
	GtkWidget *label;
	GString *error_string;
	char title[256];
	static char *filter_names[] = {
		"fddi.addr",
		"fddi.src",
		"fddi.dst",
		NULL,
		NULL,
		NULL
		};

	if(!strncmp(optarg,"talkers,fddi,",13)){
		filter=optarg+13;
	} else {
		filter=NULL;
	}

	talkers=g_malloc(sizeof(endpoints_table));

	talkers->name="FDDI";
	talkers->win=gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_default_size(GTK_WINDOW(talkers->win), 750, 400);
	snprintf(title, 255, "FDDI Talkers: %s", get_basename(cfile.filename));
	gtk_window_set_title(GTK_WINDOW(talkers->win), title);

	SIGNAL_CONNECT(talkers->win, "destroy", ett_win_destroy_cb, talkers);

	vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(talkers->win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 10);
	gtk_widget_show(vbox);

	label=gtk_label_new("FDDI Talkers");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	/* We must display TOP LEVEL Widget before calling init_ett_table() */
	gtk_widget_show(talkers->win);

	init_ett_table(talkers, vbox, NULL, filter_names);

	error_string=register_tap_listener("fddi", talkers, filter, (void *)reset_ett_table_data, fddi_talkers_packet, (void *)draw_ett_table_data);
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
gtk_fddi_endpoints_cb(GtkWidget *w _U_, gpointer d _U_)
{
	gtk_fddi_talkers_init("talkers,fddi");
}


void
register_tap_menu_fddi_talkers(void)
{
	register_tap_menu_item("Endpoint Talkers/FDDI", gtk_fddi_endpoints_cb);
}




void
register_tap_listener_fddi_talkers(void)
{
	register_ethereal_tap("talkers,fddi", gtk_fddi_talkers_init);
}


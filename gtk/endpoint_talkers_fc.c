/* endpoint_talkers_fc.c
 * endpoint_talkers_fc   2003 Ronnie Sahlberg
 *
 * $Id: endpoint_talkers_fc.c,v 1.12 2003/09/04 11:07:50 sahlberg Exp $
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
#include "packet-fc.h"



static int
fc_talkers_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, void *vip)
{
	endpoints_table *talkers=(endpoints_table *)pit;
	fc_hdr *fchdr=vip;

	add_ett_table_data(talkers, &fchdr->s_id, &fchdr->d_id, 0, 0, 1, pinfo->fd->pkt_len, SAT_NONE, PT_NONE);

	return 1;
}



static void
gtk_fc_talkers_init(char *optarg)
{
	char *filter=NULL;
	endpoints_table *talkers;
	GtkWidget *vbox;
	GtkWidget *label;
	GString *error_string;
	char title[256];

	if(!strncmp(optarg,"talkers,fc,",11)){
		filter=optarg+11;
	} else {
		filter=NULL;
	}

	talkers=g_malloc(sizeof(endpoints_table));

	talkers->name="Fibre Channel";
	talkers->win=gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_default_size(GTK_WINDOW(talkers->win), 750, 400);
	snprintf(title, 255, "Fibre Channel Talkers: %s", get_basename(cfile.filename));
	gtk_window_set_title(GTK_WINDOW(talkers->win), title);

	SIGNAL_CONNECT(talkers->win, "destroy", ett_win_destroy_cb, talkers);

	vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(talkers->win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 10);
	gtk_widget_show(vbox);

	label=gtk_label_new("Fibre Channel Talkers");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	/* We must display TOP LEVEL Widget before calling init_ett_table() */
	gtk_widget_show(talkers->win);

	init_ett_table(talkers, vbox, TRUE);

	error_string=register_tap_listener("fc", talkers, filter, (void *)reset_ett_table_data, fc_talkers_packet, (void *)draw_ett_table_data);
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
gtk_fc_endpoints_cb(GtkWidget *w _U_, gpointer d _U_)
{
	gtk_fc_talkers_init("talkers,fc");
}


void
register_tap_menu_fc_talkers(void)
{
	register_tap_menu_item("Endpoint Talkers/Fibre Channel", gtk_fc_endpoints_cb);
}




void
register_tap_listener_fc_talkers(void)
{
	register_ethereal_tap("talkers,fc", gtk_fc_talkers_init);
}


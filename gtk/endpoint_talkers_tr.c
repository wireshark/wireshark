/* endpoint_talkers_tr.c
 * endpoint_talkers_tr   2003 Ronnie Sahlberg
 *
 * $Id: endpoint_talkers_tr.c,v 1.4 2003/08/24 22:34:32 guy Exp $
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
#include "packet-tr.h"

/* used to keep track of the statistics for one instance of the stats */
typedef struct _tr_talkers_t {
	GtkWidget *win;
	endpoints_table talkers;
} tr_talkers_t;


void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);
static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	tr_talkers_t *tr_talkers=(tr_talkers_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(tr_talkers);
	unprotect_thread_critical_region();

	reset_ett_table_data(&tr_talkers->talkers);
	g_free(tr_talkers);
}

static void
tr_talkers_reset(void *pit)
{
	tr_talkers_t *tr_talkers=(tr_talkers_t *)pit;

	reset_ett_table_data(&tr_talkers->talkers);
}


static void
tr_talkers_draw(void *pit)
{
	tr_talkers_t *tr_talkers=(tr_talkers_t *)pit;

	draw_ett_table_data(&tr_talkers->talkers);
}


static int
tr_talkers_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, void *vip)
{
	tr_talkers_t *tr_talkers=(tr_talkers_t *)pit;
	tr_hdr *trhdr=vip;

	add_ett_table_data(&tr_talkers->talkers, &trhdr->src, &trhdr->dst, 0, 0, 1, pinfo->fd->pkt_len);

	return 1;
}



static void
gtk_tr_talkers_init(char *optarg)
{
	char *filter=NULL;
	tr_talkers_t *tr_talkers;
	GtkWidget *vbox;
	GtkWidget *label;
	GString *error_string;


	if(!strncmp(optarg,"talkers,tr,",11)){
		filter=optarg+11;
	} else {
		filter=NULL;
	}

	tr_talkers=g_malloc(sizeof(tr_talkers_t));

	tr_talkers->win=gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_default_size(GTK_WINDOW(tr_talkers->win), 750, 400);
	gtk_window_set_title(GTK_WINDOW(tr_talkers->win), "Token Ring Talkers");

	SIGNAL_CONNECT(tr_talkers->win, "destroy", win_destroy_cb, tr_talkers);

	vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(tr_talkers->win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 10);
	gtk_widget_show(vbox);

	label=gtk_label_new("Token Ring Talkers");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	/* We must display TOP LEVEL Widget before calling init_ett_table() */
	gtk_widget_show(tr_talkers->win);

	init_ett_table(&tr_talkers->talkers, vbox, address_to_str, NULL);

	error_string=register_tap_listener("tr", tr_talkers, filter, tr_talkers_reset, tr_talkers_packet, tr_talkers_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_WARN, NULL, error_string->str);
		g_string_free(error_string, TRUE);
		g_free(tr_talkers);
		return;
	}

	gtk_widget_show_all(tr_talkers->win);
	redissect_packets(&cfile);
}


static void
gtk_tr_endpoints_cb(GtkWidget *w _U_, gpointer d _U_)
{
	gtk_tr_talkers_init("talkers,tr");
}


void
register_tap_menu_tr_talkers(void)
{
	register_tap_menu_item("Endpoint Talkers/Token Ring", gtk_tr_endpoints_cb);
}




void
register_tap_listener_tr_talkers(void)
{
	register_ethereal_tap("talkers,tr", gtk_tr_talkers_init);
}


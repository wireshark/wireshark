/* endpoint_talkers_eth.c
 * endpoint_talkers_eth   2003 Ronnie Sahlberg
 *
 * $Id: endpoint_talkers_eth.c,v 1.2 2003/08/24 03:00:11 sahlberg Exp $
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
#include "packet-eth.h"

/* used to keep track of the statistics for one instance of the stats */
typedef struct _eth_talkers_t {
	GtkWidget *win;
	endpoints_table talkers;
} eth_talkers_t;


void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);
static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	eth_talkers_t *eth_talkers=(eth_talkers_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(eth_talkers);
	unprotect_thread_critical_region();

	reset_ett_table_data(&eth_talkers->talkers);
	g_free(eth_talkers);
}


static char *
eth_address_to_str(address *addr)
{
  return address_to_str(addr);
}

static void
eth_talkers_reset(void *pit)
{
	eth_talkers_t *eth_talkers=(eth_talkers_t *)pit;

	reset_ett_table_data(&eth_talkers->talkers);
}


static void
eth_talkers_draw(void *pit)
{
	eth_talkers_t *eth_talkers=(eth_talkers_t *)pit;

	draw_ett_table_data(&eth_talkers->talkers);
}


static int
eth_talkers_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, void *vip)
{
	eth_talkers_t *eth_talkers=(eth_talkers_t *)pit;
	eth_hdr *ehdr=vip;

	add_ett_table_data(&eth_talkers->talkers, &ehdr->src, &ehdr->dst, 0, 0, 1, pinfo->fd->pkt_len);

	return 1;
}



static void
gtk_eth_talkers_init(char *optarg)
{
	char *filter=NULL;
	eth_talkers_t *eth_talkers;
	GtkWidget *vbox;
	GtkWidget *label;
	GString *error_string;


	if(!strncmp(optarg,"talkers,eth,",12)){
		filter=optarg+12;
	} else {
		filter=NULL;
	}

	eth_talkers=g_malloc(sizeof(eth_talkers_t));

	eth_talkers->win=gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_default_size(GTK_WINDOW(eth_talkers->win), 750, 400);
	gtk_window_set_title(GTK_WINDOW(eth_talkers->win), "Ethernet Talkers");

	SIGNAL_CONNECT(eth_talkers->win, "destroy", win_destroy_cb, eth_talkers);

	vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(eth_talkers->win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 10);
	gtk_widget_show(vbox);

	label=gtk_label_new("Ethernet Talkers");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	/* We must display TOP LEVEL Widget before calling init_ett_table() */
	gtk_widget_show(eth_talkers->win);

	init_ett_table(&eth_talkers->talkers, vbox, eth_address_to_str, NULL);

	error_string=register_tap_listener("eth", eth_talkers, filter, eth_talkers_reset, eth_talkers_packet, eth_talkers_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_WARN, NULL, error_string->str);
		g_string_free(error_string, TRUE);
		g_free(eth_talkers);
		return;
	}

	gtk_widget_show_all(eth_talkers->win);
	redissect_packets(&cfile);
}


static void
gtk_eth_endpoints_cb(GtkWidget *w _U_, gpointer d _U_)
{
	gtk_eth_talkers_init("talkers,eth");
}


void
register_tap_menu_eth_talkers(void)
{
	register_tap_menu_item("Endpoint Talkers/Ethernet", gtk_eth_endpoints_cb);
}




void
register_tap_listener_eth_talkers(void)
{
	register_ethereal_tap("talkers,eth", gtk_eth_talkers_init);
}


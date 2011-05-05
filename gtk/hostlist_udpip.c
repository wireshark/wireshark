/* hostlist_udpip.c   2004 Ian Schorr
 * modified from endpoint_talkers_udpip.c   2003 Ronnie Sahlberg
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#include <string.h>

#include <gtk/gtk.h>

#include "epan/packet.h"
#include <epan/stat_cmd_args.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-udp.h>

#include "../stat_menu.h"

#include "gtk/gui_stat_menu.h"
#include "gtk/hostlist_table.h"
#include "gtk/stock_icons.h"

static int
udpip_hostlist_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
	hostlist_table *hosts=(hostlist_table *)pit;
	const e_udphdr *udphdr=vip;

	/* Take two "add" passes per packet, adding for each direction, ensures that all
	packets are counted properly (even if address is sending to itself)
	XXX - this could probably be done more efficiently inside hostlist_table */
	add_hostlist_table_data(hosts, &udphdr->ip_src, udphdr->uh_sport, TRUE, 1, pinfo->fd->pkt_len, SAT_NONE, PT_UDP);
	add_hostlist_table_data(hosts, &udphdr->ip_dst, udphdr->uh_dport, FALSE, 1, pinfo->fd->pkt_len, SAT_NONE, PT_UDP);

	return 1;
}



static void
gtk_udpip_hostlist_init(const char *optarg, void* userdata _U_)
{
	const char *filter=NULL;

	if(!strncmp(optarg,"endpoints,udp,",14)){
		filter=optarg+14;
	} else {
		filter=NULL;
	}

	init_hostlist_table(FALSE, "UDP", "udp", filter, udpip_hostlist_packet);

}


static void
gtk_udpip_hostlist_cb(GtkWidget *w _U_, gpointer d _U_)
{
	gtk_udpip_hostlist_init("endpoints,udp",NULL);
}


void
register_tap_listener_udpip_hostlist(void)
{
	register_stat_cmd_arg("endpoints,udp", gtk_udpip_hostlist_init,NULL);

#ifdef MAIN_MENU_USE_UIMANAGER
	register_stat_menu_item_stock(
		REGISTER_STAT_GROUP_ENDPOINT_LIST,		/* Group */
		"/Menubar/StatisticsMenu/EndpointListMenu/Endpoint-List-item", /* GUI path */
		"Token Ring",                       /* Name */
		WIRESHARK_STOCK_ENDPOINTS,          /* stock_id */
		"Token Ring",                       /* label */
		NULL,                               /* accelerator */
		NULL,                               /* tooltip */
		G_CALLBACK(gtk_udpip_hostlist_cb),  /* callback */
		TRUE,                               /* enabled */
		NULL,                               /* selected_packet_enabled */
		NULL,                               /* selected_tree_row_enabled */
		NULL);                              /* callback_data */

#else
	register_stat_menu_item("UDP (IPv4 & IPv6)", REGISTER_STAT_GROUP_ENDPOINT_LIST,
	    gtk_udpip_hostlist_cb, NULL, NULL, NULL);
#endif
	register_hostlist_table(FALSE, "UDP", "udp", NULL /*filter*/, udpip_hostlist_packet);
}

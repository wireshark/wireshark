/* hostlist_eth.c   2004 Ian Schorr
 * modified from endpoint_talkers_eth.c   2003 Ronnie Sahlberg
 *
 * $Id$
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <gtk/gtk.h>
#include <string.h>
#include "epan/packet.h"
#include "../stat.h"
#include "stat_menu.h"
#include <epan/tap.h>
#include "../register.h"
#include "hostlist_table.h"
#include <epan/dissectors/packet-eth.h>


static int
eth_hostlist_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
	hostlist_table *hosts=(hostlist_table *)pit;
	const eth_hdr *ehdr=vip;

	/* Take two "add" passes per packet, adding for each direction, ensures that all
	packets are counted properly (even if address is sending to itself) 
	XXX - this could probably be done more efficiently inside hostlist_table */
	add_hostlist_table_data(hosts, &ehdr->src, 0, TRUE, 1, pinfo->fd->pkt_len, SAT_ETHER, PT_NONE);
	add_hostlist_table_data(hosts, &ehdr->dst, 0, FALSE, 1, pinfo->fd->pkt_len, SAT_ETHER, PT_NONE);

	return 1;
}



static void
gtk_eth_hostlist_init(const char *optarg)
{
	const char *filter=NULL;

	if(!strncmp(optarg,"hosts,eth,",10)){
		filter=optarg+10;
	} else {
		filter=NULL;
	}

	init_hostlist_table(TRUE, "Ethernet Hosts", "eth", filter, eth_hostlist_packet);

}


static void
gtk_eth_hostlist_cb(GtkWidget *w _U_, gpointer d _U_)
{
	gtk_eth_hostlist_init("hosts,eth");
}


void
register_tap_listener_eth_hostlist(void)
{
	register_stat_cmd_arg("hosts,eth", gtk_eth_hostlist_init);

	register_stat_menu_item("Ethernet", REGISTER_STAT_GROUP_ENDPOINT_LIST,
	    gtk_eth_hostlist_cb, NULL, NULL, NULL);

	register_hostlist_table(TRUE, "Ethernet", "eth", NULL /*filter*/, eth_hostlist_packet);
}

/* hostlist_ip.c   2004 Ian Schorr
 * modified from endpoint_talkers_ip.c   2003 Ronnie Sahlberg
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

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <gtk/gtk.h>
#include <string.h>
#include "epan/packet.h"
#include <epan/stat_cmd_args.h>
#include "../stat_menu.h"
#include "gui_stat_menu.h"
#include <epan/tap.h>
#include "../register.h"
#include "hostlist_table.h"
#include <epan/dissectors/packet-ip.h>


static int
ip_hostlist_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
	hostlist_table *hosts=(hostlist_table *)pit;
	const e_ip *iph=vip;

	/* Take two "add" passes per packet, adding for each direction, ensures that all
	packets are counted properly (even if address is sending to itself) 
	XXX - this could probably be done more efficiently inside hostlist_table */
	add_hostlist_table_data(hosts, &iph->ip_src, 0, TRUE, 1, pinfo->fd->pkt_len, SAT_NONE, PT_NONE);
	add_hostlist_table_data(hosts, &iph->ip_dst, 0, FALSE, 1, pinfo->fd->pkt_len, SAT_NONE, PT_NONE);
	return 1;
}

static void
gtk_ip_hostlist_init(const char *optarg, void* userdata _U_)
{
	const char *filter=NULL;

	if(!strncmp(optarg,"hosts,ip,",9)){
		filter=optarg+9;
	} else {
		filter=NULL;
	}

	init_hostlist_table(TRUE, "IPv4 Hosts", "ip", filter, ip_hostlist_packet);

}


static void
gtk_ip_hostlist_cb(GtkWidget *w _U_, gpointer d _U_)
{
	gtk_ip_hostlist_init("hosts,ip",NULL);
}


void
register_tap_listener_ip_hostlist(void)
{
	register_stat_cmd_arg("hosts,ip", gtk_ip_hostlist_init,NULL);

	register_stat_menu_item("IPv4", REGISTER_STAT_GROUP_ENDPOINT_LIST,
		gtk_ip_hostlist_cb, NULL, NULL, NULL);

	register_hostlist_table(TRUE, "IPv4", "ip", NULL /*filter*/, ip_hostlist_packet);
}

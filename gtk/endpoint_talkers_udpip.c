/* endpoint_talkers_udpip.c
 * endpoint_talkers_udpip   2003 Ronnie Sahlberg
 *
 * $Id: endpoint_talkers_udpip.c,v 1.17 2003/09/15 22:32:21 guy Exp $
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
#include "epan/packet.h"
#include "../tap.h"
#include "../register.h"
#include "endpoint_talkers_table.h"
#include "packet-udp.h"


static int
udpip_talkers_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, void *vip)
{
	endpoints_table *talkers=(endpoints_table *)pit;
	e_udphdr *udphdr=vip;

	add_ett_table_data(talkers, &udphdr->ip_src, &udphdr->ip_dst, udphdr->uh_sport, udphdr->uh_dport, 1, pinfo->fd->pkt_len, SAT_NONE, PT_UDP);

	return 1;
}



static void
gtk_udpip_talkers_init(char *optarg)
{
	char *filter=NULL;

	if(!strncmp(optarg,"conv,udp,",9)){
		filter=optarg+9;
	} else {
		filter=NULL;
	}

	init_ett_table(FALSE, "UDP", "udp", filter, (void *)udpip_talkers_packet);

}


static void
gtk_udpip_endpoints_cb(GtkWidget *w _U_, gpointer d _U_)
{
	gtk_udpip_talkers_init("conv,udp");
}


void
register_tap_menu_udpip_talkers(void)
{
	register_tap_menu_item("Conversation List/UDP (IPv4 IPv6)", gtk_udpip_endpoints_cb);
}




void
register_tap_listener_udpip_talkers(void)
{
	register_ethereal_tap("conv,udp", gtk_udpip_talkers_init);
}


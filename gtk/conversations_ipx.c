/* conversations_ipx.c
 * conversations_ipx   2003 Ronnie Sahlberg
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

#include <gtk/gtk.h>
#include <string.h>
#include "epan/packet.h"
#include <epan/stat_cmd_args.h>
#include "../stat_menu.h"
#include "gui_stat_menu.h"
#include <epan/tap.h>
#include "../register.h"
#include "conversations_table.h"
#include <epan/dissectors/packet-ipx.h>


static int
ipx_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
	const ipxhdr_t *ipxh=vip;

	add_conversation_table_data((conversations_table *)pct, &ipxh->ipx_src, &ipxh->ipx_dst, 0, 0, 1, pinfo->fd->pkt_len, SAT_NONE, PT_NONE);

	return 1;
}



static void
ipx_conversation_init(const char *optarg, void* userdata _U_)
{
	const char *filter=NULL;

	if(!strncmp(optarg,"conv,ipx,",9)){
		filter=optarg+9;
	} else {
		filter=NULL;
	}

	init_conversation_table(TRUE, "IPX", "ipx", filter, ipx_conversation_packet);

}


static void
ipx_endpoints_cb(GtkWidget *w _U_, gpointer d _U_)
{
	ipx_conversation_init("conv,ipx",NULL);
}


void
register_tap_listener_ipx_conversation(void)
{
	register_stat_cmd_arg("conv,ipx", ipx_conversation_init,NULL);

	register_stat_menu_item("IPX", REGISTER_STAT_GROUP_CONVERSATION_LIST,
	    ipx_endpoints_cb, NULL, NULL, NULL);

	register_conversation_table(TRUE, "IPX", "ipx", NULL /*filter*/, ipx_conversation_packet);
}

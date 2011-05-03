/* conversations_tcpip.c
 * conversations_tcpip   2003 Ronnie Sahlberg
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

#include <epan/packet.h>
#include <epan/stat_cmd_args.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-tcp.h>

#include "../stat_menu.h"

#include "gtk/gui_stat_menu.h"
#include "gtk/conversations_table.h"
#include "gtk/stock_icons.h"

static int
tcpip_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
	const struct tcpheader *tcphdr=vip;

	add_conversation_table_data((conversations_table *)pct, &tcphdr->ip_src, &tcphdr->ip_dst, tcphdr->th_sport, tcphdr->th_dport, 1, pinfo->fd->pkt_len, &pinfo->fd->rel_ts, SAT_NONE, PT_TCP);

	return 1;
}



static void
tcpip_conversation_init(const char *optarg, void* userdata _U_)
{
	const char *filter=NULL;

	if(!strncmp(optarg,"conv,tcp,",9)){
		filter=optarg+9;
	} else {
		filter=NULL;
	}

	init_conversation_table(FALSE, "TCP", "tcp", filter, tcpip_conversation_packet);

}


static void
tcpip_conversation_cb(GtkWidget *w _U_, gpointer d _U_)
{
	tcpip_conversation_init("conv,tcp",NULL);
}


void
register_tap_listener_tcpip_conversation(void)
{
	register_stat_cmd_arg("conv,tcp", tcpip_conversation_init,NULL);

#ifdef MAIN_MENU_USE_UIMANAGER
	register_stat_menu_item_stock(
		REGISTER_STAT_GROUP_CONVERSATION_LIST,		/* Group */
		"/Menubar/StatisticsMenu/ConversationListMenu/List-item", /* GUI path */
		"TCP (IPv4 & IPv6)",                /* Name */
		WIRESHARK_STOCK_CONVERSATIONS,      /* stock_id */
		"TCP (IPv4 & IPv6)",                /* label */
		NULL,                               /* accelerator */
		NULL,                               /* tooltip */
		G_CALLBACK(tcpip_conversation_cb),  /* callback */
		TRUE,                               /* enabled */
		NULL,                               /* selected_packet_enabled */
		NULL,                               /* selected_tree_row_enabled */
		NULL);                              /* callback_data */

#else  
	register_stat_menu_item("TCP (IPv4 & IPv6)", REGISTER_STAT_GROUP_CONVERSATION_LIST,
	    tcpip_conversation_cb, NULL, NULL, NULL);
#endif

	register_conversation_table(FALSE, "TCP", "tcp", NULL /*filter*/, tcpip_conversation_packet);
}

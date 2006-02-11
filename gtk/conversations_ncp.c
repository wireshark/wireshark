/* conversations_ncp.c 2005 Greg Morris
 * modified from conversations_eth.c   2003 Ronnie Sahlberg
 *
 * $Id: conversations_wlan.c 15501 2005-08-21 19:24:11Z guy $
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
#include <epan/stat_cmd_args.h>
#include "../stat_menu.h"
#include "gui_stat_menu.h"
#include <epan/tap.h>
#include "../register.h"
#include "conversations_table.h"
#include <epan/dissectors/packet-ncp-int.h>


static int
ncp_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
	const struct ncp_common_header *ncph=vip;
    guint32 connection;

    connection = (ncph->conn_high * 256)+ncph->conn_low;

	add_conversation_table_data((conversations_table *)pct, &pinfo->src, &pinfo->dst, connection, connection, 1, pinfo->fd->pkt_len, SAT_NONE, PT_NCP);

	return 1;
}

static void
ncp_conversation_init(const char *optarg, void* userdata _U_)
{
	const char *filter=NULL;

	if(!strncmp(optarg,"conv,ncp,",9)){
		filter=optarg+9;
	} else {
		filter=NULL;
	}

	init_conversation_table(TRUE, "NCP", "ncp_hdr", filter, ncp_conversation_packet);
}


static void
ncp_endpoints_cb(GtkWidget *w _U_, gpointer d _U_)
{
	ncp_conversation_init("conv,ncp",NULL);
}


void
register_tap_listener_ncp_conversation(void)
{
	register_stat_cmd_arg("conv,ncp", ncp_conversation_init,NULL);

	register_stat_menu_item("NCP", REGISTER_STAT_GROUP_CONVERSATION_LIST,
	    ncp_endpoints_cb, NULL, NULL, NULL);

	register_conversation_table(TRUE, "NCP", "ncp_hdr", NULL /*filter*/, ncp_conversation_packet);
}

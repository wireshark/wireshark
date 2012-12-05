/* conversations_ncp.c 2005 Greg Morris
 * modified from conversations_eth.c   2003 Ronnie Sahlberg
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <string.h>

#include <gtk/gtk.h>

#include <epan/packet.h>
#include <epan/stat_cmd_args.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-ncp-int.h>

#include "../stat_menu.h"

#include "ui/gtk/gui_stat_menu.h"
#include "ui/gtk/conversations_table.h"

static int
ncp_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
	const struct ncp_common_header *ncph=vip;
    guint32 connection;

    connection = (ncph->conn_high * 256)+ncph->conn_low;
    if (connection < 65535) {
        add_conversation_table_data((conversations_table *)pct, &pinfo->src, &pinfo->dst, connection, connection, 1, pinfo->fd->pkt_len, &pinfo->fd->rel_ts, SAT_NONE, PT_NCP);
    }

	return 1;
}

static void
ncp_conversation_init(const char *opt_arg, void* userdata _U_)
{
	const char *filter=NULL;

	if(!strncmp(opt_arg,"conv,ncp,",9)){
		filter=opt_arg+9;
	} else {
		filter=NULL;
	}

	init_conversation_table(FALSE, "NCP", "ncp_hdr", filter, ncp_conversation_packet);
}

void
ncp_endpoints_cb(GtkAction *action _U_, gpointer user_data _U_)
{
	ncp_conversation_init("conv,ncp",NULL);
}

void
register_tap_listener_ncp_conversation(void)
{
	register_stat_cmd_arg("conv,ncp", ncp_conversation_init,NULL);
	register_conversation_table(FALSE, "NCP", "ncp_hdr", NULL /*filter*/, ncp_conversation_packet);
}

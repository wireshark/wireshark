/* hostlist_sctp.c    2008 Stig Bjorlykke
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
#include <epan/dissectors/packet-sctp.h>

#include "../stat_menu.h"

#include "gtk/gui_stat_menu.h"
#include "gtk/hostlist_table.h"
#include "gtk/stock_icons.h"

static int
sctp_hostlist_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
        hostlist_table *hosts=(hostlist_table *)pit;
        const struct _sctp_info *sctphdr=vip;

        /* Take two "add" passes per packet, adding for each direction, ensures that all
        packets are counted properly (even if address is sending to itself)
        XXX - this could probably be done more efficiently inside hostlist_table */
        add_hostlist_table_data(hosts, &sctphdr->ip_src, sctphdr->sport, TRUE, 1,
				pinfo->fd->pkt_len, SAT_NONE, PT_SCTP);
        add_hostlist_table_data(hosts, &sctphdr->ip_dst, sctphdr->dport, FALSE, 1,
				pinfo->fd->pkt_len, SAT_NONE, PT_SCTP);

        return 1;
}

static void
gtk_sctp_hostlist_init(const char *optarg, void* userdata _U_)
{
        const char *filter=NULL;

        if(!strncmp(optarg,"hosts,sctp,",11)){
                filter=optarg+11;
        } else {
                filter=NULL;
        }

        init_hostlist_table(FALSE, "SCTP", "sctp", filter, sctp_hostlist_packet);
}


static void
gtk_sctp_hostlist_cb(GtkWidget *w _U_, gpointer d _U_)
{
        gtk_sctp_hostlist_init("hosts,sctp",NULL);
}


void
register_tap_listener_sctp_hostlist(void)
{
        register_stat_cmd_arg("hosts,sctp", gtk_sctp_hostlist_init,NULL);

#ifdef MAIN_MENU_USE_UIMANAGER
	register_stat_menu_item_stock(
		REGISTER_STAT_GROUP_ENDPOINT_LIST,		/* Group */
		"/Menubar/StatisticsMenu/EndpointListMenu/Endpoint-List-item", /* GUI path */
		"SCTP",                             /* Name */
		WIRESHARK_STOCK_ENDPOINTS,          /* stock_id */
		"SCTP",                             /* label */
		NULL,                               /* accelerator */
		NULL,                               /* tooltip */
		G_CALLBACK(gtk_sctp_hostlist_cb),   /* callback */
		TRUE,                               /* enabled */
		NULL,                               /* selected_packet_enabled */
		NULL,                               /* selected_tree_row_enabled */
		NULL);                              /* callback_data */

#else
        register_stat_menu_item("SCTP", REGISTER_STAT_GROUP_ENDPOINT_LIST,
            gtk_sctp_hostlist_cb, NULL, NULL, NULL);
#endif
        register_hostlist_table(FALSE, "SCTP", "sctp", NULL /*filter*/, sctp_hostlist_packet);
}

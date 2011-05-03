/* conversations_fc.c
 * conversations_fc   2003 Ronnie Sahlberg
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
#include <epan/conversation.h>
#include <epan/dissectors/packet-scsi.h>
#include <epan/dissectors/packet-fc.h>

#include "../stat_menu.h"

#include "gtk/gui_stat_menu.h"
#include "gtk/conversations_table.h"
#include "gtk/stock_icons.h"


static int
fc_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
	const fc_hdr *fchdr=vip;

	add_conversation_table_data((conversations_table *)pct, &fchdr->s_id, &fchdr->d_id, 0, 0, 1, pinfo->fd->pkt_len, &pinfo->fd->rel_ts, SAT_NONE, PT_NONE);

	return 1;
}



static void
fc_conversation_init(const char *optarg, void* userdata _U_)
{
	const char *filter=NULL;

	if(!strncmp(optarg,"conv,fc,",8)){
		filter=optarg+8;
	} else {
		filter=NULL;
	}

	init_conversation_table(TRUE, "Fibre Channel", "fc", filter, fc_conversation_packet);

}


static void
fc_endpoints_cb(GtkWidget *w _U_, gpointer d _U_)
{
	fc_conversation_init("conv,fc",NULL);
}


void
register_tap_listener_fc_conversation(void)
{
	register_stat_cmd_arg("conv,fc", fc_conversation_init, NULL);

#ifdef MAIN_MENU_USE_UIMANAGER
	register_stat_menu_item_stock(
		REGISTER_STAT_GROUP_CONVERSATION_LIST,		/* Group */
		"/Menubar/StatisticsMenu/ConversationListMenu/List-item", /* GUI path */
		"Fibre Channel",                    /* Name */
		WIRESHARK_STOCK_CONVERSATIONS,      /* stock_id */
		"Fibre Channel",                    /* label */
		NULL,                               /* accelerator */
		NULL,                               /* tooltip */
		G_CALLBACK(fc_endpoints_cb),        /* callback */
		TRUE,                               /* enabled */
		NULL,                               /* selected_packet_enabled */
		NULL,                               /* selected_tree_row_enabled */
		NULL);                              /* callback_data */

#else
	register_stat_menu_item("Fibre Channel", REGISTER_STAT_GROUP_CONVERSATION_LIST,
	    fc_endpoints_cb, NULL, NULL, NULL);
#endif
	register_conversation_table(TRUE, "Fibre Channel", "fc", NULL /*filter*/, fc_conversation_packet);
}

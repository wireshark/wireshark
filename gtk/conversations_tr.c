/* conversations_tr.c
 * conversations_tr   2003 Ronnie Sahlberg
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
#include <epan/stat_cmd_args.h>
#include "stat_menu.h"
#include <epan/tap.h>
#include "../register.h"
#include "conversations_table.h"
#include <epan/dissectors/packet-tr.h>


static int
tr_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
	const tr_hdr *trhdr=vip;

	add_conversation_table_data((conversations_table *)pct, &trhdr->src, &trhdr->dst, 0, 0, 1, pinfo->fd->pkt_len, SAT_TOKENRING, PT_NONE);

	return 1;
}



static void
tr_conversation_init(const char *optarg)
{
	const char *filter=NULL;

	if(!strncmp(optarg,"conv,tr,",8)){
		filter=optarg+8;
	} else {
		filter=NULL;
	}

	init_conversation_table(TRUE, "Token Ring", "tr", filter, tr_conversation_packet);

}


static void
tr_conversation_cb(GtkWidget *w _U_, gpointer d _U_)
{
	tr_conversation_init("conv,tr");
}


void
register_tap_listener_tr_conversation(void)
{
	register_stat_cmd_arg("conv,tr", tr_conversation_init);

	register_stat_menu_item("Token Ring", REGISTER_STAT_GROUP_CONVERSATION_LIST,
	    tr_conversation_cb, NULL, NULL, NULL);

    register_conversation_table(TRUE, "Token Ring", "tr", NULL /*filter*/, tr_conversation_packet);
}

/* conversations_rsvp.c
 * conversations_rsvp.c  August 2005, Manu Pathak <mapathak@cisco.com>
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
#include <epan/dissectors/packet-rsvp.h>

#include "../stat_menu.h"

#include "gtk/gui_stat_menu.h"
#include "gtk/conversations_table.h"

static int
rsvp_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
	const rsvp_conversation_info *rsvph = vip;

	add_conversation_table_data((conversations_table *)pct,
				    &rsvph->source, &rsvph->destination, 0, 0, 1,
				    pinfo->fd->pkt_len, &pinfo->fd->rel_ts, SAT_NONE, PT_NONE);

	return 1;
}

static void
rsvp_conversation_init(const char *optarg, void* userdata _U_)
{
	const char *filter=NULL;

	if(!strncmp(optarg,"conv,rsvp,",10)){
		filter=optarg+10;
	} else {
		filter=NULL;
	}

	init_conversation_table(TRUE, "RSVP", "rsvp", filter,
				rsvp_conversation_packet);

}

void
rsvp_endpoints_cb(GtkAction *action _U_, gpointer user_data _U_)
{
	rsvp_conversation_init("conv,rsvp",NULL);
}

void
register_tap_listener_rsvp_conversation(void)
{
	register_stat_cmd_arg("conv,rsvp", rsvp_conversation_init,NULL);
	register_conversation_table(TRUE, "RSVP", "rsvp", NULL /*filter*/,
				    rsvp_conversation_packet);
}

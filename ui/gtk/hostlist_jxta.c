/* hostlist_jxta.c   2005 Mike Duigou
 * modified from hostlist_eth.c   2004 Ian Schorr
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
#include <epan/dissectors/packet-jxta.h>

#include "../stat_menu.h"

#include "ui/gtk/gui_stat_menu.h"
#include "ui/gtk/hostlist_table.h"

static int
jxta_hostlist_packet(void *pit, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *vip)
{
	hostlist_table *hosts = (hostlist_table *) pit;
	const jxta_tap_header *jxtahdr = vip;

	/* Take two "add" passes per packet, adding for each direction, ensures that all
	packets are counted properly (even if address is sending to itself)
	XXX - this could probably be done more efficiently inside hostlist_table */
	add_hostlist_table_data(hosts, &jxtahdr->src_address, 0, TRUE, 1, jxtahdr->size, SAT_JXTA, PT_NONE);
	add_hostlist_table_data(hosts, &jxtahdr->dest_address, 0, FALSE, 1, jxtahdr->size, SAT_JXTA, PT_NONE);
	return 1;
}

static void
gtk_jxta_hostlist_init(const char *optarg, void* userdata _U_)
{
	const char *filter=NULL;

	if(!strncmp(optarg,"hosts,jxta,",11)){
		filter=optarg+11;
	} else {
		filter=NULL;
	}

	init_hostlist_table(TRUE, "JXTA", "jxta", filter, jxta_hostlist_packet);

}

void
gtk_jxta_hostlist_cb(GtkAction *action _U_, gpointer user_data _U_)
{
	gtk_jxta_hostlist_init("hosts,jxta",NULL);
}

void
register_tap_listener_jxta_hostlist(void)
{
	register_stat_cmd_arg("hosts,jxta", gtk_jxta_hostlist_init,NULL);
	register_hostlist_table(TRUE, "JXTA", "jxta", NULL /*filter*/, jxta_hostlist_packet);
}

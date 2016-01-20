/* tap-endpoints.c
 * endpoints   2014 Michael Mann
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

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <epan/packet.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/conversation_table.h>
#include <ui/cli/tshark-tap.h>

typedef struct _endpoints_t {
	const char *type;
	const char *filter;
	conv_hash_t hash;
} endpoints_t;

static void
endpoints_draw(void *arg)
{
	conv_hash_t *hash = (conv_hash_t*)arg;
	endpoints_t *iu = (endpoints_t *)hash->user_data;
	hostlist_talker_t *host;
	guint64 last_frames, max_frames;
	guint i;
	gboolean display_port = (!strncmp(iu->type, "TCP", 3) || !strncmp(iu->type, "UDP", 3) || !strncmp(iu->type, "SCTP", 4)) ? TRUE : FALSE;

	printf("================================================================================\n");
	printf("%s Endpoints\n", iu->type);
	printf("Filter:%s\n", iu->filter ? iu->filter : "<No Filter>");

	printf("                       |  %sPackets  | |  Bytes  | | Tx Packets | | Tx Bytes | | Rx Packets | | Rx Bytes |\n",
		display_port ? "Port  ||  " : "");

	max_frames = UINT_MAX;
	do {
		last_frames = 0;
		for (i=0; (iu->hash.conv_array && i < iu->hash.conv_array->len); i++) {
			guint64 tot_frames;

			host = &g_array_index(iu->hash.conv_array, hostlist_talker_t, i);
			tot_frames = host->rx_frames + host->tx_frames;

			if ((tot_frames > last_frames) && (tot_frames < max_frames)) {
				last_frames = tot_frames;
			}
		}

		for (i=0; (iu->hash.conv_array && i < iu->hash.conv_array->len); i++) {
			guint64 tot_frames;
			gchar *conversation_str, *port_str;

			host = &g_array_index(iu->hash.conv_array, hostlist_talker_t, i);
			tot_frames = host->rx_frames + host->tx_frames;

			if (tot_frames == last_frames) {
				/* XXX - TODO: make name resolution configurable (through gbl_resolv_flags?) */
				conversation_str = get_conversation_address(NULL, &host->myaddress, TRUE);
				if (display_port) {
					/* XXX - TODO: make port resolution configurable (through gbl_resolv_flags?) */
					port_str = get_conversation_port(NULL, host->port, host->ptype, TRUE);
					printf("%-20s      %5s     %6" G_GINT64_MODIFIER "u     %9" G_GINT64_MODIFIER
					       "u     %6" G_GINT64_MODIFIER "u       %9" G_GINT64_MODIFIER "u      %6"
					       G_GINT64_MODIFIER "u       %9" G_GINT64_MODIFIER "u   \n",
						conversation_str,
						port_str,
						host->tx_frames+host->rx_frames, host->tx_bytes+host->rx_bytes,
						host->tx_frames, host->tx_bytes,
						host->rx_frames, host->rx_bytes);
					wmem_free(NULL, port_str);
				} else {
					printf("%-20s      %6" G_GINT64_MODIFIER "u     %9" G_GINT64_MODIFIER
					       "u     %6" G_GINT64_MODIFIER "u       %9" G_GINT64_MODIFIER "u      %6"
					       G_GINT64_MODIFIER "u       %9" G_GINT64_MODIFIER "u   \n",
						/* XXX - TODO: make name resolution configurable (through gbl_resolv_flags?) */
						conversation_str,
						host->tx_frames+host->rx_frames, host->tx_bytes+host->rx_bytes,
						host->tx_frames, host->tx_bytes,
						host->rx_frames, host->rx_bytes);

				}
				wmem_free(NULL, conversation_str);
			}
		}
		max_frames = last_frames;
	} while (last_frames);
	printf("================================================================================\n");
}

void init_hostlists(struct register_ct *ct, const char *filter)
{
	endpoints_t *iu;
	GString *error_string;

	iu = g_new0(endpoints_t, 1);
	iu->type = proto_get_protocol_short_name(find_protocol_by_id(get_conversation_proto_id(ct)));
	iu->filter = g_strdup(filter);
	iu->hash.user_data = iu;

	error_string = register_tap_listener(proto_get_protocol_filter_name(get_conversation_proto_id(ct)), &iu->hash, filter, 0, NULL, get_hostlist_packet_func(ct), endpoints_draw);
	if (error_string) {
		g_free(iu);
		fprintf(stderr, "tshark: Couldn't register endpoint tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}

}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */

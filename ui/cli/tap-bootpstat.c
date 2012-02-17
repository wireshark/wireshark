/* tap-bootpstat.c
 * boop_stat   2003 Jean-Michel FAYARD
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

#include <stdio.h>
#include <string.h>

#include "epan/packet_info.h"
#include <epan/tap.h>
#include <epan/stat_cmd_args.h>


typedef const char* bootp_info_value_t;

/* used to keep track of the statictics for an entire program interface */
typedef struct _dhcp_stats_t {
	char 		*filter;
	GHashTable	*hash;
	guint		 index;	/* Number of  to display */
} dhcpstat_t;
/* used to keep track of a single DHCP message type */
typedef struct _dhcp_message_type_t {
	const char	*name;
	guint32		 packets;
	dhcpstat_t	*sp;	/* entire program interface */
} dhcp_message_type_t;


/* Not used anywhere at this moment */
/*
static void
dhcp_free_hash( gpointer key _U_ , gpointer value, gpointer user_data _U_ )
{
	g_free(value);
}
*/

static void
dhcp_reset_hash(gchar *key _U_ , dhcp_message_type_t *data, gpointer ptr _U_ )
{
	data->packets = 0;
}

/* Update the entry corresponding to the number of packets of a special DHCP Message Type
 * or create it if it don't exist.
 */
static void
dhcp_draw_message_type(gchar *key _U_, dhcp_message_type_t *data, gchar * format )
{
	if ((data==NULL) || (data->packets==0))
		return;
	printf( format, data->name, data->packets);
}
static void
dhcpstat_reset(void *psp)
{
	dhcpstat_t *sp=psp;
	g_hash_table_foreach( sp->hash, (GHFunc)dhcp_reset_hash, NULL);
}
static int
dhcpstat_packet(void *psp, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *pri)
{
	dhcpstat_t *sp=psp;
	const bootp_info_value_t value=pri;
	dhcp_message_type_t *sc;

	if (sp==NULL)
		return 0;
	sc = g_hash_table_lookup(
			sp->hash,
			value);
	if (!sc) {
		sc = g_malloc( sizeof(dhcp_message_type_t) );
		sc -> packets = 1;
		sc -> name = value;
		sc -> sp = sp;
		g_hash_table_insert(
				sp->hash,
				(gpointer) value,
				sc);
	} else {
		/*g_warning("sc(%s)->packets++", sc->name);*/
		sc->packets++;
	}
	return 1;
}


static void
dhcpstat_draw(void *psp)
{
	dhcpstat_t *sp=psp;

	printf("\n");
	printf("===================================================================\n");

	if (sp->filter==NULL)
		printf("BOOTP Statistics\n");
	else
		printf("BOOTP Statistics with filter %s\n",  sp->filter);
	printf("BOOTP Option 53: DHCP Messages Types:\n");
	printf("DHCP Message Type      Packets nb\n" );
	g_hash_table_foreach( sp->hash, (GHFunc) dhcp_draw_message_type,
			"%23s %-9d\n" );
	printf("===================================================================\n");

}




/* When called, this function will create a new instance of tap-boopstat.
 */
static void
dhcpstat_init(const char *optarg, void* userdata _U_)
{
	dhcpstat_t *sp;
	const char	*filter=NULL;
	GString		*error_string;

	if (!strncmp (optarg, "bootp,stat,", 11)){
		filter=optarg+11;
	} else {
		filter=NULL;
	}

	sp = g_malloc( sizeof(dhcpstat_t) );
	sp->hash = g_hash_table_new( g_str_hash, g_str_equal);
	if(filter){
		sp->filter=g_strdup(filter);
	} else {
		sp->filter=NULL;
	}
	sp->index = 0; 		/* Nothing to display yet */

	error_string = register_tap_listener(
			"bootp",
			sp,
			filter,
			0,
			dhcpstat_reset,
			dhcpstat_packet,
			dhcpstat_draw);
	if (error_string){
		/* error, we failed to attach to the tap. clean up */
		g_free(sp->filter);
		g_free(sp);
		fprintf(stderr, "tshark: Couldn't register dhcp,stat tap: %s\n",
				error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}



void
register_tap_listener_gtkdhcpstat(void)
{
	register_stat_cmd_arg("bootp,stat,", dhcpstat_init,NULL);
}


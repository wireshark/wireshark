/* tap_sctpchunkstat.c
 * SCTP chunk counter for ethereal
 * Copyright 2005 Oleg Terletsky <oleg.terletsky@comverse.com>
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

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>
#include "epan/packet_info.h"
#include "epan/addr_resolv.h"
#include <epan/tap.h>
#include <epan/stat.h>
#include "epan/value_string.h"
#include "register.h"
#include <epan/dissectors/packet-sctp.h>

typedef struct sctp_ep {
	struct sctp_ep* next;
	address src;
	address dst;
	guint16 sport;
	guint16 dport;
	guint32 chunk_count[256];
} sctp_ep_t;


/* used to keep track of the statistics for an entire program interface */
typedef struct _sctpstat_t {
	char*      filter;
	guint32    number_of_packets;
	sctp_ep_t* ep_list;
} sctpstat_t;


#define SCTP_DATA_CHUNK_ID               0
#define SCTP_INIT_CHUNK_ID               1
#define SCTP_INIT_ACK_CHUNK_ID           2
#define SCTP_SACK_CHUNK_ID               3
#define SCTP_HEARTBEAT_CHUNK_ID          4
#define SCTP_HEARTBEAT_ACK_CHUNK_ID      5
#define SCTP_ABORT_CHUNK_ID              6
#define SCTP_SHUTDOWN_CHUNK_ID           7
#define SCTP_SHUTDOWN_ACK_CHUNK_ID       8
#define SCTP_ERROR_CHUNK_ID              9
#define SCTP_COOKIE_ECHO_CHUNK_ID       10
#define SCTP_COOKIE_ACK_CHUNK_ID        11
#define SCTP_ECNE_CHUNK_ID              12
#define SCTP_CWR_CHUNK_ID               13
#define SCTP_SHUTDOWN_COMPLETE_CHUNK_ID 14
#define SCTP_AUTH_CHUNK_ID            0x16
#define SCTP_ASCONF_ACK_CHUNK_ID      0x80
#define SCTP_PKTDROP_CHUNK_ID         0x81
#define SCTP_FORWARD_TSN_CHUNK_ID     0xC0
#define SCTP_ASCONF_CHUNK_ID          0xC1
#define SCTP_IETF_EXT                 0xFF

#define CHUNK_TYPE_OFFSET 0
#define CHUNK_TYPE(x)(tvb_get_guint8((x), CHUNK_TYPE_OFFSET))


extern gchar* address_to_str(const address *);


static void
sctpstat_reset(void *phs)
{
	sctpstat_t* sctp_stat = (sctpstat_t *)phs;
	sctp_ep_t* list = (sctp_ep_t*)sctp_stat->ep_list;
	sctp_ep_t* tmp = NULL;
	guint16 chunk_type;
	
	if(!list)
		return;

	for(tmp = list; tmp ; tmp=tmp->next)
		for(chunk_type = 0; chunk_type < 256; chunk_type++)
			tmp->chunk_count[chunk_type] = 0;

	sctp_stat->number_of_packets = 0;
}


sctp_ep_t* alloc_sctp_ep(struct _sctp_info *si)
{
	sctp_ep_t* ep;
	guint16 chunk_type;

	if(!si)
		return NULL;

	if (!(ep = g_malloc(sizeof(sctp_ep_t))))
		return NULL;
	
	COPY_ADDRESS(&ep->src,&si->ip_src);
	COPY_ADDRESS(&ep->dst,&si->ip_dst);
	ep->sport = si->sport;
	ep->dport = si->dport;
	ep->next = NULL;
	for(chunk_type = 0; chunk_type < 256; chunk_type++)
		ep->chunk_count[chunk_type] = 0;
	return ep;
}


	

static int
sctpstat_packet(void *phs, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *phi)
{

	sctpstat_t *hs=(sctpstat_t *)phs;
	sctp_ep_t *tmp = NULL, *te = NULL;
	struct _sctp_info *si = (struct _sctp_info *) phi;
	guint32 tvb_number;
	guint8 chunk_type;
	
	if (!hs)
		return (0);
		
	hs->number_of_packets++;
	
	if(!hs->ep_list) {
		hs->ep_list = alloc_sctp_ep(si);
		te = hs->ep_list;
	} else {
		for(tmp=hs->ep_list ; tmp ; tmp=tmp->next)
		{
			if((!CMP_ADDRESS(&tmp->src,&si->ip_src)) &&
			   (!CMP_ADDRESS(&tmp->dst,&si->ip_dst)) &&
			   (tmp->sport == si->sport) &&
			   (tmp->dport == si->dport))
			{
				te = tmp;
				break;
			}
		}
		if(!te) {
			if ((te = alloc_sctp_ep(si))) {
				te->next = hs->ep_list;
				hs->ep_list = te;
			}
		}
	}

	if(!te)
		return (0);

	
	if (si->number_of_tvbs > 0) {
		chunk_type = CHUNK_TYPE(si->tvb[0]);
		if ((chunk_type == SCTP_INIT_CHUNK_ID) ||
		    (chunk_type == SCTP_INIT_ACK_CHUNK_ID)) {
			te->chunk_count[chunk_type]++;
		} else {
			for(tvb_number = 0; tvb_number < si->number_of_tvbs; tvb_number++)
				te->chunk_count[CHUNK_TYPE(si->tvb[tvb_number])]++;
		}
	}
	return (1);
}


static void
sctpstat_draw(void *phs)
{
	sctpstat_t *hs=(sctpstat_t *)phs;
	sctp_ep_t* list = hs->ep_list, *tmp;

	printf("-------------------------------------------- SCTP Statistics --------------------------------------------------------------------------\n");
	printf("|  Total packets RX/TX %u\n", hs->number_of_packets);
	printf("---------------------------------------------------------------------------------------------------------------------------------------\n");
	printf("|   Source IP   |PortA|    Dest. IP   |PortB|  DATA  |  SACK  |  HBEAT |HBEATACK|  INIT  | INITACK| COOKIE |COOKIACK| ABORT  |  ERROR |\n");
	printf("---------------------------------------------------------------------------------------------------------------------------------------\n");
	
	for(tmp = list ; tmp ; tmp=tmp->next) {
		printf("|%15s|%5u|%15s|%5u|%8u|%8u|%8u|%8u|%8u|%8u|%8u|%8u|%8u|%8u|\n",
		       address_to_str(&tmp->src),tmp->sport,
		       address_to_str(&tmp->dst),tmp->dport,
		       tmp->chunk_count[SCTP_DATA_CHUNK_ID],
		       tmp->chunk_count[SCTP_SACK_CHUNK_ID],
		       tmp->chunk_count[SCTP_HEARTBEAT_CHUNK_ID],
		       tmp->chunk_count[SCTP_HEARTBEAT_ACK_CHUNK_ID],
		       tmp->chunk_count[SCTP_INIT_CHUNK_ID],
		       tmp->chunk_count[SCTP_INIT_ACK_CHUNK_ID],
		       tmp->chunk_count[SCTP_COOKIE_ECHO_CHUNK_ID],
		       tmp->chunk_count[SCTP_COOKIE_ACK_CHUNK_ID],
		       tmp->chunk_count[SCTP_ABORT_CHUNK_ID],
		       tmp->chunk_count[SCTP_ERROR_CHUNK_ID]);
	}
	printf("---------------------------------------------------------------------------------------------------------------------------------------\n");
}


static void
sctpstat_init(const char *optarg)
{
	sctpstat_t *hs;
	const char *filter=NULL;
	GString *error_string;

	if(!strncmp(optarg,"sctp,stat,",11)){
		filter=optarg+11;
	} else {
		filter="";
	}

	hs = g_malloc(sizeof(sctpstat_t));
	hs->filter=g_malloc(strlen(filter)+1);
	hs->ep_list = NULL;
	hs->number_of_packets = 0;
	strcpy(hs->filter, filter);

	sctpstat_reset(hs);

	error_string=register_tap_listener("sctp", hs, filter, NULL, sctpstat_packet, sctpstat_draw);
	if(error_string){
		/* error, we failed to attach to the tap. clean up */
		g_free(hs->filter);
		g_free(hs);

		fprintf(stderr, "tethereal: Couldn't register sctp,stat tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}


void
register_tap_listener_sctpstat(void)
{
	register_stat_cmd_arg("sctp,stat", sctpstat_init);
}

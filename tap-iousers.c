/* tap-iousers.c
 * iostat   2003 Ronnie Sahlberg
 *
 * $Id: tap-iousers.c,v 1.7 2003/05/19 11:16:29 sahlberg Exp $
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
#include <epan/packet_info.h>
#include <epan/packet.h>
#include <epan/resolv.h>
#include "tap.h"
#include "register.h"
#include "packet-ip.h"
#include "packet-tcp.h"
#include "packet-udp.h"
#include "packet-eth.h"
#include "packet-tr.h"
#include <string.h>

typedef struct _io_users_t {
	char *type;
	char *filter;
	struct _io_users_item_t *items;
} io_users_t;

typedef struct _io_users_item_t {
	struct _io_users_item_t *next;
	char *name1;
	char *name2;
	void *addr1;
	void *addr2; 
	guint32 frames1;
	guint32 frames2;
	guint32 bytes1;
	guint32 bytes2;
} io_users_item_t;


/* XXX for now we only handle ipv4 as transport for udp.
   should extend in the future to also handle ipv6
*/
static int
iousers_udpip_packet(io_users_t *iu, packet_info *pinfo, epan_dissect_t *edt _U_, void *vudph)
{
	e_udphdr *udph=vudph;
	char name1[256],name2[256];
	io_users_item_t *iui;
	e_ip *ipv4_header;
	int direction=0;

	ipv4_header=udph->ip_header;
	switch(ipv4_header->ip_v_hl>>4){
	case 4:
		if(ipv4_header->ip_src>ipv4_header->ip_dst){
			snprintf(name1,256,"%s:%s",get_hostname(ipv4_header->ip_src),get_udp_port(udph->uh_sport));
			snprintf(name2,256,"%s:%s",get_hostname(ipv4_header->ip_dst),get_udp_port(udph->uh_dport));
		} else {
			direction=1;
			snprintf(name2,256,"%s:%s",get_hostname(ipv4_header->ip_src),get_udp_port(udph->uh_sport));
			snprintf(name1,256,"%s:%s",get_hostname(ipv4_header->ip_dst),get_udp_port(udph->uh_dport));
		}
		break;
	default:
		return 0;
	}

	for(iui=iu->items;iui;iui=iui->next){
		if((!strcmp(iui->name1, name1))
		&& (!strcmp(iui->name2, name2)) ){
			break;
		}
	}

	if(!iui){
		iui=g_malloc(sizeof(io_users_item_t));
		iui->next=iu->items;
		iu->items=iui;
		iui->addr1=NULL;
		iui->name1=strdup(name1);
		iui->addr2=NULL;
		iui->name2=strdup(name2);
		iui->frames1=0;
		iui->frames2=0;
		iui->bytes1=0;
		iui->bytes2=0;
	}

	if(direction){
		iui->frames1++;
		iui->bytes1+=pinfo->fd->pkt_len;
	} else {
		iui->frames2++;
		iui->bytes2+=pinfo->fd->pkt_len;
	}

	return 1;
}

/* XXX for now we only handle ipv4 as transport for tcp.
   should extend in the future to also handle ipv6
*/
static int
iousers_tcpip_packet(io_users_t *iu, packet_info *pinfo, epan_dissect_t *edt _U_, void *vtcph)
{
	struct tcpheader *tcph=vtcph;
	char name1[256],name2[256];
	io_users_item_t *iui;
	e_ip *ipv4_header;
	int direction=0;

	ipv4_header=tcph->ip_header;
	switch(ipv4_header->ip_v_hl>>4){
	case 4:
		if(ipv4_header->ip_src>ipv4_header->ip_dst){
			snprintf(name1,256,"%s:%s",get_hostname(ipv4_header->ip_src),get_tcp_port(tcph->th_sport));
			snprintf(name2,256,"%s:%s",get_hostname(ipv4_header->ip_dst),get_tcp_port(tcph->th_dport));
		} else {
			direction=1;
			snprintf(name2,256,"%s:%s",get_hostname(ipv4_header->ip_src),get_tcp_port(tcph->th_sport));
			snprintf(name1,256,"%s:%s",get_hostname(ipv4_header->ip_dst),get_tcp_port(tcph->th_dport));
		}
		break;
	default:
		return 0;
	}

	for(iui=iu->items;iui;iui=iui->next){
		if((!strcmp(iui->name1, name1))
		&& (!strcmp(iui->name2, name2)) ){
			break;
		}
	}

	if(!iui){
		iui=g_malloc(sizeof(io_users_item_t));
		iui->next=iu->items;
		iu->items=iui;
		iui->addr1=NULL;
		iui->name1=strdup(name1);
		iui->addr2=NULL;
		iui->name2=strdup(name2);
		iui->frames1=0;
		iui->frames2=0;
		iui->bytes1=0;
		iui->bytes2=0;
	}

	if(direction){
		iui->frames1++;
		iui->bytes1+=pinfo->fd->pkt_len;
	} else {
		iui->frames2++;
		iui->bytes2+=pinfo->fd->pkt_len;
	}

	return 1;
}


static int
iousers_ip_packet(io_users_t *iu, packet_info *pinfo, epan_dissect_t *edt _U_, void *vip)
{
	e_ip *iph=vip;
	guint32 addr1, addr2;
	io_users_item_t *iui;

	if(iph->ip_src>iph->ip_dst){
		addr1=iph->ip_src;
		addr2=iph->ip_dst;
	} else {
		addr2=iph->ip_src;
		addr1=iph->ip_dst;
	}

	for(iui=iu->items;iui;iui=iui->next){
		if((!memcmp(iui->addr1, &addr1, 4))
		&&(!memcmp(iui->addr2, &addr2, 4)) ){
			break;
		}
	}

	if(!iui){
		iui=g_malloc(sizeof(io_users_item_t));
		iui->next=iu->items;
		iu->items=iui;
		iui->addr1=g_malloc(4);
		memcpy(iui->addr1, &addr1, 4);
		iui->name1=strdup(get_hostname(addr1));
		iui->addr2=g_malloc(4);
		memcpy(iui->addr2, &addr2, 4);
		iui->name2=strdup(get_hostname(addr2));
		iui->frames1=0;
		iui->frames2=0;
		iui->bytes1=0;
		iui->bytes2=0;
	}

	if(!memcmp(&iph->ip_dst,iui->addr1,4)){
		iui->frames1++;
		iui->bytes1+=pinfo->fd->pkt_len;
	} else {
		iui->frames2++;
		iui->bytes2+=pinfo->fd->pkt_len;
	}

	return 1;
}

static int
iousers_eth_packet(io_users_t *iu, packet_info *pinfo, epan_dissect_t *edt _U_, void *veth)
{
	eth_hdr *ehdr=veth;
	gchar *addr1, *addr2;
	io_users_item_t *iui;

	if(memcmp(ehdr->src, ehdr->dst, 6)<0){
		addr1=ehdr->src;
		addr2=ehdr->dst;
	} else {
		addr2=ehdr->src;
		addr1=ehdr->dst;
	}

	for(iui=iu->items;iui;iui=iui->next){
		if((!memcmp(iui->addr1, addr1, 6))
		&&(!memcmp(iui->addr2, addr2, 6)) ){
			break;
		}
	}

	if(!iui){
		iui=g_malloc(sizeof(io_users_item_t));
		iui->next=iu->items;
		iu->items=iui;
		iui->addr1=g_malloc(6);
		memcpy(iui->addr1, addr1, 6);
		iui->name1=strdup(ether_to_str(addr1));
		iui->addr2=g_malloc(6);
		memcpy(iui->addr2, addr2, 6);
		iui->name2=strdup(ether_to_str(addr2));
		iui->frames1=0;
		iui->frames2=0;
		iui->bytes1=0;
		iui->bytes2=0;
	}

	if(!memcmp(ehdr->dst,iui->addr1,6)){
		iui->frames1++;
		iui->bytes1+=pinfo->fd->pkt_len;
	} else {
		iui->frames2++;
		iui->bytes2+=pinfo->fd->pkt_len;
	}

	return 1;
}


static int
iousers_tr_packet(io_users_t *iu, packet_info *pinfo, epan_dissect_t *edt _U_, void *vtr)
{
	tr_hdr *trhdr=vtr;
	gchar *addr1, *addr2;
	io_users_item_t *iui;

	if(memcmp(trhdr->src, trhdr->dst, 6)<0){
		addr1=trhdr->src;
		addr2=trhdr->dst;
	} else {
		addr2=trhdr->src;
		addr1=trhdr->dst;
	}

	for(iui=iu->items;iui;iui=iui->next){
		if((!memcmp(iui->addr1, addr1, 6))
		&&(!memcmp(iui->addr2, addr2, 6)) ){
			break;
		}
	}

	if(!iui){
		iui=g_malloc(sizeof(io_users_item_t));
		iui->next=iu->items;
		iu->items=iui;
		iui->addr1=g_malloc(6);
		memcpy(iui->addr1, addr1, 6);
		iui->name1=strdup(ether_to_str(addr1));
		iui->addr2=g_malloc(6);
		memcpy(iui->addr2, addr2, 6);
		iui->name2=strdup(ether_to_str(addr2));
		iui->frames1=0;
		iui->frames2=0;
		iui->bytes1=0;
		iui->bytes2=0;
	}

	if(!memcmp(trhdr->dst,iui->addr1,6)){
		iui->frames1++;
		iui->bytes1+=pinfo->fd->pkt_len;
	} else {
		iui->frames2++;
		iui->bytes2+=pinfo->fd->pkt_len;
	}

	return 1;
}

static void
iousers_draw(io_users_t *iu)
{
	io_users_item_t *iui;
	guint32 last_frames, max_frames;

	printf("================================================================================\n");
	printf("IO-USERS Statistics\n");
	printf("Type:%s\n",iu->type);
	printf("Filter:%s\n",iu->filter?iu->filter:"<No Filter>");
	printf("                                               |       <-      | |       ->      | |     Total     |\n");
	printf("                                               | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |\n");
	max_frames=0xffffffff;
	do {
		last_frames=0;
		for(iui=iu->items;iui;iui=iui->next){
			guint32 tot_frames;
			tot_frames=iui->frames1+iui->frames2;

			if((tot_frames>last_frames)
			&&(tot_frames<max_frames)){
				last_frames=tot_frames;
			}
		}
		for(iui=iu->items;iui;iui=iui->next){
			guint32 tot_frames;
			tot_frames=iui->frames1+iui->frames2;

			if(tot_frames==last_frames){
				printf("%-20s <-> %-20s  %6d %9d  %6d %9d  %6d %9d\n",
					iui->name1, iui->name2,
					iui->frames1, iui->bytes1,
					iui->frames2, iui->bytes2,
					iui->frames1+iui->frames2,
					iui->bytes1+iui->bytes2
				);
			}
		}
		max_frames=last_frames;
	} while(last_frames);
	printf("================================================================================\n");
}

void
iousers_init(char *optarg)
{
	char *filter=NULL;
	char *tap_type;
	static int (*packet_func)(io_users_t *, packet_info *, epan_dissect_t *, void *);
	io_users_t *iu=NULL;
	GString *error_string;

	if(!strncmp(optarg,"io,users,eth",12)){
		if(optarg[12]==','){
			filter=optarg+13;
		} else {
			filter=NULL;
		}
		tap_type="eth";
		packet_func=iousers_eth_packet;
	} else if(!strncmp(optarg,"io,users,tcpip",14)){
		if(optarg[14]==','){
			filter=optarg+15;
		} else {
			filter=NULL;
		}
		tap_type="tcp";
		packet_func=iousers_tcpip_packet;
	} else if(!strncmp(optarg,"io,users,udpip",14)){
		if(optarg[14]==','){
			filter=optarg+15;
		} else {
			filter=NULL;
		}
		tap_type="udp";
		packet_func=iousers_udpip_packet;
	} else if(!strncmp(optarg,"io,users,tr",11)){
		if(optarg[11]==','){
			filter=optarg+12;
		} else {
			filter=NULL;
		}
		tap_type="tr";
		packet_func=iousers_tr_packet;
	} else if(!strncmp(optarg,"io,users,ip",11)){
		if(optarg[11]==','){
			filter=optarg+12;
		} else {
			filter=NULL;
		}
		tap_type="ip";
		packet_func=iousers_ip_packet;
	} else {
		fprintf(stderr, "tethereal: invalid \"-z io,users,<type>[,<filter>]\" argument\n");
		fprintf(stderr,"   <type> must be one of\n");
		fprintf(stderr,"      \"eth\"\n");
		fprintf(stderr,"      \"ip\"\n");
		fprintf(stderr,"      \"tcpip\"\n");
		fprintf(stderr,"      \"tr\"\n");
		fprintf(stderr,"      \"udpip\"\n");
		exit(1);
	}


	iu=g_malloc(sizeof(io_users_t));
	iu->items=NULL;
	iu->type=tap_type;
	if(filter){
		iu->filter=strdup(filter);
	} else {
		iu->filter=NULL;
	}

	error_string=register_tap_listener(tap_type, iu, filter, NULL, (void*)packet_func, (void*)iousers_draw);
	if(error_string){
		if(iu->items){
			g_free(iu->items);
		}
		g_free(iu);
		fprintf(stderr, "tethereal: Couldn't register io,users tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}

}

void
register_tap_listener_iousers(void)
{
	register_ethereal_tap("io,users,", iousers_init);
}


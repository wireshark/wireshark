/* tap-iousers.c
 * iostat   2003 Ronnie Sahlberg
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

#include <stdio.h>

#include <string.h>
#include <epan/packet_info.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/tap.h>
#include <epan/conv_id.h>
#include <epan/conversation.h>
#include <epan/stat_cmd_args.h>
#include <epan/dissectors/packet-ip.h>
#include <epan/dissectors/packet-ipv6.h>
#include <epan/dissectors/packet-ipx.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/dissectors/packet-udp.h>
#include <epan/dissectors/packet-eth.h>
#include <epan/dissectors/packet-sctp.h>
#include <epan/dissectors/packet-tr.h>
#include <epan/dissectors/packet-scsi.h>
#include <epan/dissectors/packet-fc.h>
#include <epan/dissectors/packet-fddi.h>

typedef struct _io_users_t {
	const char *type;
	char *filter;
	struct _io_users_item_t *items;
} io_users_t;

typedef struct _io_users_item_t {
    struct _io_users_item_t *next;
    char                    *name1;
    char                    *name2;
    conv_id_t               conv_id;
    address                 addr1;
    address                 addr2;
    guint32                 frames1;
    guint32                 frames2;
    guint64                 bytes1;
    guint64                 bytes2;
    nstime_t                start_time;
    nstime_t                stop_time;
} io_users_item_t;

#define iousers_process_name_packet(iu, name1, name2, direction, pkt_len, ts) \
    iousers_process_name_packet_with_conv_id(iu, name1, name2, CONV_ID_UNSET, direction, pkt_len, ts)

void
iousers_process_name_packet_with_conv_id(
    io_users_t *iu,
    char *name1,
    char *name2,
    conv_id_t conv_id,
    int direction,
    guint64 pkt_len,
    nstime_t *ts)
{
	io_users_item_t *iui;

	for(iui=iu->items;iui;iui=iui->next){
		if((iui->conv_id==conv_id)
            && (!strcmp(iui->name1, name1))
            && (!strcmp(iui->name2, name2)) ){
			break;
		}
	}

	if(!iui){
		iui=g_malloc(sizeof(io_users_item_t));
		iui->next=iu->items;
		iu->items=iui;
		iui->name1=g_strdup(name1);
		iui->name2=g_strdup(name2);
        iui->conv_id=conv_id;
		iui->frames1=0;
		iui->frames2=0;
		iui->bytes1=0;
		iui->bytes2=0;
		memcpy(&iui->start_time, ts, sizeof(iui->start_time));
		memcpy(&iui->stop_time, ts, sizeof(iui->stop_time));
	}
	else {
		if (nstime_cmp(ts, &iui->stop_time) > 0) {
			memcpy(&iui->stop_time, ts, sizeof(iui->stop_time));
		} else if (nstime_cmp(ts, &iui->start_time) < 0) {
			memcpy(&iui->start_time, ts, sizeof(iui->start_time));
		}
	}

	if(direction){
		iui->frames1++;
		iui->bytes1+=pkt_len;
	} else {
		iui->frames2++;
		iui->bytes2+=pkt_len;
	}
}

void
iousers_process_address_packet(io_users_t *iu, const address *src, const address *dst, guint64 pkt_len, nstime_t *ts)
{
	const address *addr1, *addr2;
	io_users_item_t *iui;

	if(CMP_ADDRESS(src, dst)>0){
		addr1=src;
		addr2=dst;
	} else {
		addr2=src;
		addr1=dst;
	}

	for(iui=iu->items;iui;iui=iui->next){
		if((!CMP_ADDRESS(&iui->addr1, addr1))
		&&(!CMP_ADDRESS(&iui->addr2, addr2)) ){
			break;
		}
	}

	if(!iui){
		iui=g_malloc(sizeof(io_users_item_t));
		iui->next=iu->items;
		iu->items=iui;
		COPY_ADDRESS(&iui->addr1, addr1);
		iui->name1=g_strdup(ep_address_to_str(addr1));
		COPY_ADDRESS(&iui->addr2, addr2);
		iui->name2=g_strdup(ep_address_to_str(addr2));
		iui->frames1=0;
		iui->frames2=0;
		iui->bytes1=0;
		iui->bytes2=0;
		memcpy(&iui->start_time, ts, sizeof(iui->start_time));
		memcpy(&iui->stop_time, ts, sizeof(iui->stop_time));
	}
	else {
		if (nstime_cmp(ts, &iui->stop_time) > 0) {
			memcpy(&iui->stop_time, ts, sizeof(iui->stop_time));
		} else if (nstime_cmp(ts, &iui->start_time) < 0) {
			memcpy(&iui->start_time, ts, sizeof(iui->start_time));
		}
	}

	if(!CMP_ADDRESS(dst, &iui->addr1)){
		iui->frames1++;
		iui->bytes1+=pkt_len;
	} else {
		iui->frames2++;
		iui->bytes2+=pkt_len;
	}
}

static int
iousers_udpip_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vudph)
{
	io_users_t *iu=arg;
	const e_udphdr *udph=vudph;
	char name1[256],name2[256];
	int direction=0;

	if(udph->uh_sport>udph->uh_dport){
		direction=0;
		g_snprintf(name1,256,"%s:%s",ep_address_to_str(&udph->ip_src),get_udp_port(udph->uh_sport));
		g_snprintf(name2,256,"%s:%s",ep_address_to_str(&udph->ip_dst),get_udp_port(udph->uh_dport));
	} else if(udph->uh_sport<udph->uh_dport){
		direction=1;
		g_snprintf(name2,256,"%s:%s",ep_address_to_str(&udph->ip_src),get_udp_port(udph->uh_sport));
		g_snprintf(name1,256,"%s:%s",ep_address_to_str(&udph->ip_dst),get_udp_port(udph->uh_dport));
	} else if(CMP_ADDRESS(&udph->ip_src, &udph->ip_dst)>0){
		direction=0;
		g_snprintf(name1,256,"%s:%s",ep_address_to_str(&udph->ip_src),get_udp_port(udph->uh_sport));
		g_snprintf(name2,256,"%s:%s",ep_address_to_str(&udph->ip_dst),get_udp_port(udph->uh_dport));
	} else {
		direction=1;
		g_snprintf(name2,256,"%s:%s",ep_address_to_str(&udph->ip_src),get_udp_port(udph->uh_sport));
		g_snprintf(name1,256,"%s:%s",ep_address_to_str(&udph->ip_dst),get_udp_port(udph->uh_dport));
	}

	iousers_process_name_packet(iu, name1, name2, direction, pinfo->fd->pkt_len, &pinfo->fd->rel_ts);
	
	return 1;
}


static int
iousers_sctp_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vsctp)
{
	io_users_t *iu=arg;
	const struct _sctp_info* sctph = vsctp;
	char name1[256],name2[256], s_sport[10], s_dport[10];
	int direction=0;

	g_snprintf(s_sport, sizeof s_sport, "%d",sctph->sport);
	g_snprintf(s_dport, sizeof s_dport, "%d",sctph->dport);

	if(sctph->sport > sctph->dport) {
		direction=0;
		g_snprintf(name1,256,"%s:%s",ep_address_to_str(&sctph->ip_src),s_sport);
		g_snprintf(name2,256,"%s:%s",ep_address_to_str(&sctph->ip_dst),s_dport);
	} else if(sctph->sport < sctph->dport) {
		direction=1;
		g_snprintf(name1,256,"%s:%s",ep_address_to_str(&sctph->ip_src),s_sport);
		g_snprintf(name2,256,"%s:%s",ep_address_to_str(&sctph->ip_dst),s_dport);
	} else {
		direction=0;
		g_snprintf(name1,256,"%s:%s",ep_address_to_str(&sctph->ip_src),s_sport);
		g_snprintf(name2,256,"%s:%s",ep_address_to_str(&sctph->ip_dst),s_dport);
	}

	iousers_process_name_packet(iu, name1, name2, direction, pinfo->fd->pkt_len, &pinfo->fd->rel_ts);

	return 1;
}


static int
iousers_tcpip_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vtcph)
{
	io_users_t *iu=arg;
	const struct tcpheader *tcph=vtcph;
	char name1[256],name2[256];
	int direction=0;

	if(tcph->th_sport>tcph->th_dport){
		direction=0;
		g_snprintf(name1,256,"%s:%s",ep_address_to_str(&tcph->ip_src),get_tcp_port(tcph->th_sport));
		g_snprintf(name2,256,"%s:%s",ep_address_to_str(&tcph->ip_dst),get_tcp_port(tcph->th_dport));
	} else if(tcph->th_sport<tcph->th_dport){
		direction=1;
		g_snprintf(name2,256,"%s:%s",ep_address_to_str(&tcph->ip_src),get_tcp_port(tcph->th_sport));
		g_snprintf(name1,256,"%s:%s",ep_address_to_str(&tcph->ip_dst),get_tcp_port(tcph->th_dport));
	} else if(CMP_ADDRESS(&tcph->ip_src, &tcph->ip_dst)>0){
		direction=0;
		g_snprintf(name1,256,"%s:%s",ep_address_to_str(&tcph->ip_src),get_tcp_port(tcph->th_sport));
		g_snprintf(name2,256,"%s:%s",ep_address_to_str(&tcph->ip_dst),get_tcp_port(tcph->th_dport));
	} else {
		direction=1;
		g_snprintf(name2,256,"%s:%s",ep_address_to_str(&tcph->ip_src),get_tcp_port(tcph->th_sport));
		g_snprintf(name1,256,"%s:%s",ep_address_to_str(&tcph->ip_dst),get_tcp_port(tcph->th_dport));
	}

	iousers_process_name_packet_with_conv_id(iu, name1, name2, tcph->th_stream, direction, pinfo->fd->pkt_len, &pinfo->fd->rel_ts);

	return 1;
}


static int
iousers_ip_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
	io_users_t *iu=arg;
	const ws_ip *iph=vip;

	iousers_process_address_packet(iu, &iph->ip_src, &iph->ip_dst, pinfo->fd->pkt_len, &pinfo->fd->rel_ts);

	return 1;
}

static int
iousers_ipv6_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
	io_users_t *iu=arg;
	const struct ip6_hdr *ip6h=vip;
	address src, dst;

	/* Addresses aren't implemented as 'address' type in struct ip6_hdr */
	src.type = dst.type = AT_IPv6;
	src.len  = dst.len = sizeof(struct e_in6_addr);
	src.data = &ip6h->ip6_src;
	dst.data = &ip6h->ip6_dst;

	iousers_process_address_packet(iu, &src, &dst, pinfo->fd->pkt_len, &pinfo->fd->rel_ts);

	return 1;
}

static int
iousers_ipx_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vipx)
{
	io_users_t *iu=arg;
	const ipxhdr_t *ipxh=vipx;

	iousers_process_address_packet(iu, &ipxh->ipx_src, &ipxh->ipx_dst, pinfo->fd->pkt_len, &pinfo->fd->rel_ts);

	return 1;
}

static int
iousers_fc_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vfc)
{
	io_users_t *iu=arg;
	const fc_hdr *fchdr=vfc;

	iousers_process_address_packet(iu, &fchdr->s_id, &fchdr->d_id, pinfo->fd->pkt_len, &pinfo->fd->rel_ts);

	return 1;
}

static int
iousers_eth_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *veth)
{
	io_users_t *iu=arg;
	const eth_hdr *ehdr=veth;

	iousers_process_address_packet(iu, &ehdr->src, &ehdr->dst, pinfo->fd->pkt_len, &pinfo->fd->rel_ts);

	return 1;
}

static int
iousers_fddi_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *veth)
{
	io_users_t *iu=arg;
	const fddi_hdr *ehdr=veth;

	iousers_process_address_packet(iu, &ehdr->src, &ehdr->dst, pinfo->fd->pkt_len, &pinfo->fd->rel_ts);

	return 1;
}

static int
iousers_tr_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vtr)
{
	io_users_t *iu=arg;
	const tr_hdr *trhdr=vtr;

	iousers_process_address_packet(iu, &trhdr->src, &trhdr->dst, pinfo->fd->pkt_len, &pinfo->fd->rel_ts);

	return 1;
}

static void
iousers_draw(void *arg)
{
	io_users_t *iu = arg;
	io_users_item_t *iui;
	guint32 last_frames, max_frames;

	printf("================================================================================\n");
	printf("%s Conversations\n",iu->type);
	printf("Filter:%s\n",iu->filter?iu->filter:"<No Filter>");
	printf("                                               |       <-      | |       ->      | |     Total     |   Rel. Start   |   Duration   |\n");
	printf("                                               | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |                |              |\n");
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
				printf("%-20s <-> %-20s  %6d %9" G_GINT64_MODIFIER "d  %6d %9" G_GINT64_MODIFIER "d  %6d %9" G_GINT64_MODIFIER "d  %14.9f   %12.4f\n",
					iui->name1, iui->name2,
					iui->frames1, iui->bytes1,
					iui->frames2, iui->bytes2,
					iui->frames1+iui->frames2,
					iui->bytes1+iui->bytes2,
					nstime_to_sec(&iui->start_time),
					nstime_to_sec(&iui->stop_time) - nstime_to_sec(&iui->start_time)
				);
			}
		}
		max_frames=last_frames;
	} while(last_frames);
	printf("================================================================================\n");
}

static void
iousers_init(const char *optarg, void* userdata _U_)
{
	const char *filter=NULL;
	const char *tap_type, *tap_type_name;
	tap_packet_cb packet_func;
	io_users_t *iu=NULL;
	GString *error_string;

	if(!strncmp(optarg,"conv,eth",8)){
		if(optarg[8]==','){
			filter=optarg+9;
		} else {
			filter=NULL;
		}
		tap_type="eth";
		tap_type_name="Ethernet";
		packet_func=iousers_eth_packet;
	} else if(!strncmp(optarg,"conv,fc",7)){
		if(optarg[7]==','){
			filter=optarg+8;
		} else {
			filter=NULL;
		}
		tap_type="fc";
		tap_type_name="Fibre Channel";
		packet_func=iousers_fc_packet;
	} else if(!strncmp(optarg,"conv,fddi",9)){
		if(optarg[9]==','){
			filter=optarg+10;
		} else {
			filter=NULL;
		}
		tap_type="fddi";
		tap_type_name="FDDI";
		packet_func=iousers_fddi_packet;
	} else if(!strncmp(optarg,"conv,tcp",8)){
		if(optarg[8]==','){
			filter=optarg+9;
		} else {
			filter=NULL;
		}
		tap_type="tcp";
		tap_type_name="TCP";
		packet_func=iousers_tcpip_packet;
	} else if(!strncmp(optarg,"conv,udp",8)){
		if(optarg[8]==','){
			filter=optarg+9;
		} else {
			filter=NULL;
		}
		tap_type="udp";
		tap_type_name="UDP";
		packet_func=iousers_udpip_packet;
	} else if(!strncmp(optarg,"conv,tr",7)){
		if(optarg[7]==','){
			filter=optarg+8;
		} else {
			filter=NULL;
		}
		tap_type="tr";
		tap_type_name="Token Ring";
		packet_func=iousers_tr_packet;
	} else if(!strncmp(optarg,"conv,ipx",8)){
		if(optarg[8]==','){
			filter=optarg+9;
		} else {
			filter=NULL;
		}
		tap_type="ipx";
		tap_type_name="IPX";
		packet_func=iousers_ipx_packet;
	} else if(!strncmp(optarg,"conv,ipv6",9)){
		if(optarg[9]==','){
			filter=optarg+10;
		} else {
			filter=NULL;
		}
		tap_type="ipv6";
		tap_type_name="IPv6";
		packet_func=iousers_ipv6_packet;
	} else if(!strncmp(optarg,"conv,ip",7)){
		if(optarg[7]==','){
			filter=optarg+8;
		} else {
			filter=NULL;
		}
		tap_type="ip";
		tap_type_name="IPv4";
		packet_func=iousers_ip_packet;
	} else if(!strncmp(optarg,"conv,sctp",9)) {
		if(optarg[9]==','){
				filter=optarg+10;
		} else {
                        filter=NULL;
                }
		tap_type="sctp";
		tap_type_name="SCTP";
		packet_func=iousers_sctp_packet;
	} else {
		fprintf(stderr, "tshark: invalid \"-z conv,<type>[,<filter>]\" argument\n");
		fprintf(stderr,"   <type> must be one of\n");
		fprintf(stderr,"      \"eth\"\n");
		fprintf(stderr,"      \"fc\"\n");
		fprintf(stderr,"      \"fddi\"\n");
		fprintf(stderr,"      \"ip\"\n");
		fprintf(stderr,"      \"ipx\"\n");
		fprintf(stderr,"      \"sctp\"\n");
		fprintf(stderr,"      \"tcp\"\n");
		fprintf(stderr,"      \"tr\"\n");
		fprintf(stderr,"      \"udp\"\n");
		exit(1);
	}


	iu=g_malloc(sizeof(io_users_t));
	iu->items=NULL;
	iu->type=tap_type_name;
	if(filter){
		iu->filter=g_strdup(filter);
	} else {
		iu->filter=NULL;
	}

	error_string=register_tap_listener(tap_type, iu, filter, 0, NULL, packet_func, iousers_draw);
	if(error_string){
		if(iu->items){
			g_free(iu->items);
		}
		g_free(iu);
		fprintf(stderr, "tshark: Couldn't register conversations tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}

}

void
register_tap_listener_iousers(void)
{
	register_stat_cmd_arg("conv,", iousers_init, NULL);
}

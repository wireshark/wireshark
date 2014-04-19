/* tap-iousers.c
 * iostat   2003 Ronnie Sahlberg
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
#include <epan/timestamp.h>
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

void register_tap_listener_iousers(void);

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
	nstime_t                start_rel_time;
	nstime_t                stop_rel_time;
	nstime_t                start_abs_time;
} io_users_item_t;

#define iousers_process_name_packet(iu, name1, name2, direction, pkt_len, rel_ts, abs_ts) \
    iousers_process_name_packet_with_conv_id(iu, name1, name2, CONV_ID_UNSET, direction, pkt_len, rel_ts, abs_ts)

static void
iousers_process_name_packet_with_conv_id(
	io_users_t *iu,
	char *name1,
	char *name2,
	conv_id_t conv_id,
	int direction,
	guint64 pkt_len,
	nstime_t *rel_ts,
	nstime_t *abs_ts)
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
		iui=g_new(io_users_item_t,1);
		iui->next=iu->items;
		iu->items=iui;
		iui->name1=g_strdup(name1);
		iui->name2=g_strdup(name2);
		iui->conv_id=conv_id;
		iui->frames1=0;
		iui->frames2=0;
		iui->bytes1=0;
		iui->bytes2=0;
		memcpy(&iui->start_rel_time, rel_ts, sizeof(iui->start_rel_time));
		memcpy(&iui->stop_rel_time, rel_ts, sizeof(iui->stop_rel_time));
		memcpy(&iui->start_abs_time, abs_ts, sizeof(iui->start_abs_time));
	}
	else {
		if (nstime_cmp(rel_ts, &iui->stop_rel_time) > 0) {
			memcpy(&iui->stop_rel_time, rel_ts, sizeof(iui->stop_rel_time));
		} else if (nstime_cmp(rel_ts, &iui->start_rel_time) < 0) {
			memcpy(&iui->start_rel_time, rel_ts, sizeof(iui->start_rel_time));
			memcpy(&iui->start_abs_time, abs_ts, sizeof(iui->start_abs_time));
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

static void
iousers_process_address_packet(io_users_t *iu, const address *src, const address *dst, guint64 pkt_len,
								nstime_t *ts)
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
		iui=g_new(io_users_item_t,1);
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
		memcpy(&iui->start_rel_time, ts, sizeof(iui->start_rel_time));
		memcpy(&iui->stop_rel_time, ts, sizeof(iui->stop_rel_time));
	}
	else {
		if (nstime_cmp(ts, &iui->stop_rel_time) > 0) {
			memcpy(&iui->stop_rel_time, ts, sizeof(iui->stop_rel_time));
		} else if (nstime_cmp(ts, &iui->start_rel_time) < 0) {
			memcpy(&iui->start_rel_time, ts, sizeof(iui->start_rel_time));
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
	io_users_t *iu=(io_users_t *)arg;
	const e_udphdr *udph=(const e_udphdr *)vudph;
	char name1[256],name2[256];
	int direction=0;

	if(udph->uh_sport>udph->uh_dport){
		direction=0;
		g_snprintf(name1,256,"%s:%s",ep_address_to_str(&udph->ip_src),ep_udp_port_to_display(udph->uh_sport));
		g_snprintf(name2,256,"%s:%s",ep_address_to_str(&udph->ip_dst),ep_udp_port_to_display(udph->uh_dport));
	} else if(udph->uh_sport<udph->uh_dport){
		direction=1;
		g_snprintf(name2,256,"%s:%s",ep_address_to_str(&udph->ip_src),ep_udp_port_to_display(udph->uh_sport));
		g_snprintf(name1,256,"%s:%s",ep_address_to_str(&udph->ip_dst),ep_udp_port_to_display(udph->uh_dport));
	} else if(CMP_ADDRESS(&udph->ip_src, &udph->ip_dst)>0){
		direction=0;
		g_snprintf(name1,256,"%s:%s",ep_address_to_str(&udph->ip_src),ep_udp_port_to_display(udph->uh_sport));
		g_snprintf(name2,256,"%s:%s",ep_address_to_str(&udph->ip_dst),ep_udp_port_to_display(udph->uh_dport));
	} else {
		direction=1;
		g_snprintf(name2,256,"%s:%s",ep_address_to_str(&udph->ip_src),ep_udp_port_to_display(udph->uh_sport));
		g_snprintf(name1,256,"%s:%s",ep_address_to_str(&udph->ip_dst),ep_udp_port_to_display(udph->uh_dport));
	}

	iousers_process_name_packet(iu, name1, name2, direction, pinfo->fd->pkt_len, &pinfo->rel_ts, &pinfo->fd->abs_ts);

	return 1;
}


static int
iousers_sctp_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vsctp)
{
	io_users_t *iu=(io_users_t *)arg;
	const struct _sctp_info* sctph = (const struct _sctp_info*)vsctp;
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

	iousers_process_name_packet(iu, name1, name2, direction, pinfo->fd->pkt_len, &pinfo->rel_ts, &pinfo->fd->abs_ts);

	return 1;
}


static int
iousers_tcpip_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vtcph)
{
	io_users_t *iu=(io_users_t *)arg;
	const struct tcpheader *tcph=(const struct tcpheader *)vtcph;
	char name1[256],name2[256];
	int direction=0;

	if(tcph->th_sport>tcph->th_dport){
		direction=0;
		g_snprintf(name1,256,"%s:%s",ep_address_to_str(&tcph->ip_src),ep_tcp_port_to_display(tcph->th_sport));
		g_snprintf(name2,256,"%s:%s",ep_address_to_str(&tcph->ip_dst),ep_tcp_port_to_display(tcph->th_dport));
	} else if(tcph->th_sport<tcph->th_dport){
		direction=1;
		g_snprintf(name2,256,"%s:%s",ep_address_to_str(&tcph->ip_src),ep_tcp_port_to_display(tcph->th_sport));
		g_snprintf(name1,256,"%s:%s",ep_address_to_str(&tcph->ip_dst),ep_tcp_port_to_display(tcph->th_dport));
	} else if(CMP_ADDRESS(&tcph->ip_src, &tcph->ip_dst)>0){
		direction=0;
		g_snprintf(name1,256,"%s:%s",ep_address_to_str(&tcph->ip_src),ep_tcp_port_to_display(tcph->th_sport));
		g_snprintf(name2,256,"%s:%s",ep_address_to_str(&tcph->ip_dst),ep_tcp_port_to_display(tcph->th_dport));
	} else {
		direction=1;
		g_snprintf(name2,256,"%s:%s",ep_address_to_str(&tcph->ip_src),ep_tcp_port_to_display(tcph->th_sport));
		g_snprintf(name1,256,"%s:%s",ep_address_to_str(&tcph->ip_dst),ep_tcp_port_to_display(tcph->th_dport));
	}

	iousers_process_name_packet_with_conv_id(iu, name1, name2, tcph->th_stream, direction, pinfo->fd->pkt_len, &pinfo->rel_ts, &pinfo->fd->abs_ts);

	return 1;
}


static int
iousers_ip_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
	io_users_t *iu=(io_users_t *)arg;
	const ws_ip *iph=(const ws_ip *)vip;

	iousers_process_address_packet(iu, &iph->ip_src, &iph->ip_dst, pinfo->fd->pkt_len, &pinfo->rel_ts);

	return 1;
}

static int
iousers_ipv6_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
	io_users_t *iu=(io_users_t *)arg;
	const struct ip6_hdr *ip6h=(const struct ip6_hdr *)vip;
	address src, dst;

	/* Addresses aren't implemented as 'address' type in struct ip6_hdr */
	src.type = dst.type = AT_IPv6;
	src.len  = dst.len = sizeof(struct e_in6_addr);
	src.data = &ip6h->ip6_src;
	dst.data = &ip6h->ip6_dst;

	iousers_process_address_packet(iu, &src, &dst, pinfo->fd->pkt_len, &pinfo->rel_ts);

	return 1;
}

static int
iousers_ipx_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vipx)
{
	io_users_t *iu=(io_users_t *)arg;
	const ipxhdr_t *ipxh=(const ipxhdr_t *)vipx;

	iousers_process_address_packet(iu, &ipxh->ipx_src, &ipxh->ipx_dst, pinfo->fd->pkt_len, &pinfo->rel_ts);

	return 1;
}

static int
iousers_fc_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vfc)
{
	io_users_t *iu=(io_users_t *)arg;
	const fc_hdr *fchdr=(const fc_hdr *)vfc;

	iousers_process_address_packet(iu, &fchdr->s_id, &fchdr->d_id, pinfo->fd->pkt_len, &pinfo->rel_ts);

	return 1;
}

static int
iousers_eth_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *veth)
{
	io_users_t *iu=(io_users_t *)arg;
	const eth_hdr *ehdr=(const eth_hdr *)veth;

	iousers_process_address_packet(iu, &ehdr->src, &ehdr->dst, pinfo->fd->pkt_len, &pinfo->rel_ts);

	return 1;
}

static int
iousers_fddi_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *veth)
{
	io_users_t *iu=(io_users_t *)arg;
	const fddi_hdr *ehdr=(const fddi_hdr *)veth;

	iousers_process_address_packet(iu, &ehdr->src, &ehdr->dst, pinfo->fd->pkt_len, &pinfo->rel_ts);

	return 1;
}

static int
iousers_tr_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vtr)
{
	io_users_t *iu=(io_users_t *)arg;
	const tr_hdr *trhdr=(const tr_hdr *)vtr;

	iousers_process_address_packet(iu, &trhdr->src, &trhdr->dst, pinfo->fd->pkt_len, &pinfo->rel_ts);

	return 1;
}

static void
iousers_draw(void *arg)
{
	io_users_t *iu = (io_users_t *)arg;
	io_users_item_t *iui;
	guint32 last_frames, max_frames;
	struct tm * tm_time;

	printf("================================================================================\n");
	printf("%s Conversations\n",iu->type);
	printf("Filter:%s\n",iu->filter?iu->filter:"<No Filter>");

	switch (timestamp_get_type()) {
	case TS_ABSOLUTE:
	case TS_UTC:
		printf("                                               |       <-      | |       ->      | |     Total     | Absolute Time  |   Duration   |\n");
		printf("                                               | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |\n");
		break;
	case TS_ABSOLUTE_WITH_YMD:
	case TS_ABSOLUTE_WITH_YDOY:
	case TS_UTC_WITH_YMD:
	case TS_UTC_WITH_YDOY:
		printf("                                               |       <-      | |       ->      | |     Total     | Absolute Date  |   Duration   |\n");
		printf("                                               | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |     Start      |              |\n");
		break;
	case TS_RELATIVE:
	case TS_NOT_SET:
	default:
		printf("                                               |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |\n");
		printf("                                               | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |\n");
		break;
	}

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
				printf("%-20s <-> %-20s  %6d %9" G_GINT64_MODIFIER "d  %6d %9" G_GINT64_MODIFIER "d  %6d %9" G_GINT64_MODIFIER "d  ",
					iui->name1, iui->name2,
					iui->frames1, iui->bytes1,
					iui->frames2, iui->bytes2,
					iui->frames1+iui->frames2,
					iui->bytes1+iui->bytes2
				);

				switch (timestamp_get_type()) {
				case TS_ABSOLUTE:
					tm_time = localtime(&iui->start_abs_time.secs);
					printf("%02d:%02d:%02d   %12.4f\n",
						 tm_time->tm_hour,
						 tm_time->tm_min,
						 tm_time->tm_sec,
						 nstime_to_sec(&iui->stop_rel_time) - nstime_to_sec(&iui->start_rel_time));
					break;
				case TS_ABSOLUTE_WITH_YMD:
					tm_time = localtime(&iui->start_abs_time.secs);
					printf("%04d-%02d-%02d %02d:%02d:%02d   %12.4f\n",
						 tm_time->tm_year + 1900,
						 tm_time->tm_mon + 1,
						 tm_time->tm_mday,
						 tm_time->tm_hour,
						 tm_time->tm_min,
						 tm_time->tm_sec,
						 nstime_to_sec(&iui->stop_rel_time) - nstime_to_sec(&iui->start_rel_time));
					break;
				case TS_ABSOLUTE_WITH_YDOY:
					tm_time = localtime(&iui->start_abs_time.secs);
					printf("%04d/%03d %02d:%02d:%02d   %12.4f\n",
						 tm_time->tm_year + 1900,
						 tm_time->tm_yday + 1,
						 tm_time->tm_hour,
						 tm_time->tm_min,
						 tm_time->tm_sec,
						 nstime_to_sec(&iui->stop_rel_time) - nstime_to_sec(&iui->start_rel_time));
					break;
				case TS_UTC:
					tm_time = gmtime(&iui->start_abs_time.secs);
					printf("%02d:%02d:%02d   %12.4f\n",
						 tm_time->tm_hour,
						 tm_time->tm_min,
						 tm_time->tm_sec,
						 nstime_to_sec(&iui->stop_rel_time) - nstime_to_sec(&iui->start_rel_time));
					break;
				case TS_UTC_WITH_YMD:
					tm_time = gmtime(&iui->start_abs_time.secs);
					printf("%04d-%02d-%02d %02d:%02d:%02d   %12.4f\n",
						 tm_time->tm_year + 1900,
						 tm_time->tm_mon + 1,
						 tm_time->tm_mday,
						 tm_time->tm_hour,
						 tm_time->tm_min,
						 tm_time->tm_sec,
						 nstime_to_sec(&iui->stop_rel_time) - nstime_to_sec(&iui->start_rel_time));
					break;
				case TS_UTC_WITH_YDOY:
					tm_time = gmtime(&iui->start_abs_time.secs);
					printf("%04d/%03d %02d:%02d:%02d   %12.4f\n",
						 tm_time->tm_year + 1900,
						 tm_time->tm_yday + 1,
						 tm_time->tm_hour,
						 tm_time->tm_min,
						 tm_time->tm_sec,
						 nstime_to_sec(&iui->stop_rel_time) - nstime_to_sec(&iui->start_rel_time));
					break;
				case TS_RELATIVE:
				case TS_NOT_SET:
				default:
					printf("%14.9f   %12.4f\n",
						nstime_to_sec(&iui->start_rel_time),
						nstime_to_sec(&iui->stop_rel_time) - nstime_to_sec(&iui->start_rel_time)
					);
					break;
				}
			}
		}
		max_frames=last_frames;
	} while(last_frames);
	printf("================================================================================\n");
}

static void
iousers_init(const char *opt_arg, void* userdata _U_)
{
	const char *filter=NULL;
	const char *tap_type, *tap_type_name;
	tap_packet_cb packet_func;
	io_users_t *iu=NULL;
	GString *error_string;

	if(!strncmp(opt_arg,"conv,eth",8)){
		if(opt_arg[8]==','){
			filter=opt_arg+9;
		} else {
			filter=NULL;
		}
		tap_type="eth";
		tap_type_name="Ethernet";
		packet_func=iousers_eth_packet;
	} else if(!strncmp(opt_arg,"conv,fc",7)){
		if(opt_arg[7]==','){
			filter=opt_arg+8;
		} else {
			filter=NULL;
		}
		tap_type="fc";
		tap_type_name="Fibre Channel";
		packet_func=iousers_fc_packet;
	} else if(!strncmp(opt_arg,"conv,fddi",9)){
		if(opt_arg[9]==','){
			filter=opt_arg+10;
		} else {
			filter=NULL;
		}
		tap_type="fddi";
		tap_type_name="FDDI";
		packet_func=iousers_fddi_packet;
	} else if(!strncmp(opt_arg,"conv,tcp",8)){
		if(opt_arg[8]==','){
			filter=opt_arg+9;
		} else {
			filter=NULL;
		}
		tap_type="tcp";
		tap_type_name="TCP";
		packet_func=iousers_tcpip_packet;
	} else if(!strncmp(opt_arg,"conv,udp",8)){
		if(opt_arg[8]==','){
			filter=opt_arg+9;
		} else {
			filter=NULL;
		}
		tap_type="udp";
		tap_type_name="UDP";
		packet_func=iousers_udpip_packet;
	} else if(!strncmp(opt_arg,"conv,tr",7)){
		if(opt_arg[7]==','){
			filter=opt_arg+8;
		} else {
			filter=NULL;
		}
		tap_type="tr";
		tap_type_name="Token Ring";
		packet_func=iousers_tr_packet;
	} else if(!strncmp(opt_arg,"conv,ipx",8)){
		if(opt_arg[8]==','){
			filter=opt_arg+9;
		} else {
			filter=NULL;
		}
		tap_type="ipx";
		tap_type_name="IPX";
		packet_func=iousers_ipx_packet;
	} else if(!strncmp(opt_arg,"conv,ipv6",9)){
		if(opt_arg[9]==','){
			filter=opt_arg+10;
		} else {
			filter=NULL;
		}
		tap_type="ipv6";
		tap_type_name="IPv6";
		packet_func=iousers_ipv6_packet;
	} else if(!strncmp(opt_arg,"conv,ip",7)){
		if(opt_arg[7]==','){
			filter=opt_arg+8;
		} else {
			filter=NULL;
		}
		tap_type="ip";
		tap_type_name="IPv4";
		packet_func=iousers_ip_packet;
	} else if(!strncmp(opt_arg,"conv,sctp",9)) {
		if(opt_arg[9]==','){
				filter=opt_arg+10;
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


	iu=g_new(io_users_t,1);
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

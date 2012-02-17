/* tap-comparestat.c
 * Compare two capture files
 * Copyright 2008 Vincenzo Condoleo, Christophe Dirac, Reto Ruoss
 * supported by HSR (Hochschule Rapperswil)
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

/* This module provides statistics about two merged capture files, to find packet loss,
 * time delay, ip header checksum errors and order check to tshark.
 * It's also detecting the matching regions of the different files.
 *
 * The packets are compared by the ip id. MAC or TTL is used to distinct the different files.
 * It is only used by tshark and not wireshark
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <math.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>
#include "epan/packet_info.h"
#include <epan/in_cksum.h>
#include <epan/packet.h>
#include <epan/tap.h>
#include <epan/timestamp.h>
#include <epan/stat_cmd_args.h>
#include <epan/dissectors/packet-ip.h>
#include "timestats.h"


/* For checksum */
#define BYTES 8
#define WRONG_CHKSUM 0

#define MERGED_FILES 2

#define TTL_SEARCH 5

/* information which will be printed */
typedef struct _for_print {
	guint count;
	guint16 cksum;
	nstime_t predecessor_time;
	struct _frame_info *partner;
} for_print;

/* each tracked packet */
typedef struct _frame_info {
	for_print *fp;
	guint32 num;
	guint16 id;
	guint8 ip_ttl;
	address dl_dst;
	nstime_t abs_ts, zebra_time, delta;
} frame_info;

/* used to keep track of the statistics for an entire program interface */
typedef struct _comparestat_t {
	char *filter;
	emem_tree_t *packet_tree, *ip_id_tree, *nr_tree;
	address eth_dst, eth_src;
	nstime_t zebra_time, current_time;
	timestat_t stats;
	GArray *ip_ttl_list;
	gboolean last_hit;
	guint32 start_ongoing_hits, stop_ongoing_hits, start_packet_nr_first, start_packet_nr_second, stop_packet_nr_first, stop_packet_nr_second;
	guint32 first_file_amount, second_file_amount;
} comparestat_t;


/* to call directly _init */
static gdouble compare_variance=0.0;
static guint8 compare_start, compare_stop;
static gboolean TTL_method=TRUE, ON_method=TRUE;

/* This callback is never used by tshark but it is here for completeness. */
static void
comparestat_reset(void *dummy _U_)
{
}


/* This callback is invoked whenever the tap system has seen a packet
 * we might be interested in.
 * function returns :
 *  0: no updates, no need to call (*draw) later
 * !0: state has changed, call (*draw) sometime later
 */
static int
comparestat_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt _U_, const void *arg2)
{
	comparestat_t *cs=arg;
	const ws_ip *ci=arg2;
	frame_info *fInfo;
	vec_t cksum_vec[3];
	guint16 computed_cksum=0;

	/* so this get filled, usually with the first frame */
	if(cs->eth_dst.len==0) {
		cs->eth_dst=pinfo->dl_dst;
		cs->eth_src=pinfo->dl_src;
	}

	/* Set up the fields of the pseudo-header and create checksum */
	cksum_vec[0].ptr=&ci->ip_v_hl;
	cksum_vec[0].len=BYTES;
	/* skip TTL */
	cksum_vec[1].ptr=&ci->ip_p;
	cksum_vec[1].len=1;
	/* skip header checksum and ip's (because of NAT)*/
	cksum_vec[2].ptr=ci->ip_dst.data;
	cksum_vec[2].ptr=cksum_vec[2].ptr+ci->ip_dst.len;
	/* dynamic computation */
	cksum_vec[2].len=pinfo->iphdrlen-20;
	computed_cksum=in_cksum(&cksum_vec[0], 3);

	/* collect all packet infos */
	fInfo=(frame_info*)se_alloc(sizeof(frame_info));
	fInfo->fp=(for_print*)se_alloc(sizeof(for_print));
	fInfo->fp->partner=NULL;
	fInfo->fp->count=1;
	fInfo->fp->cksum=computed_cksum;
	fInfo->num=pinfo->fd->num;
	fInfo->id=ci->ip_id;
	fInfo->ip_ttl=ci->ip_ttl;
	fInfo->dl_dst=pinfo->dl_dst;
	fInfo->abs_ts=pinfo->fd->abs_ts;
	/* clean memory */
	nstime_set_zero(&fInfo->zebra_time);
	nstime_set_zero(&fInfo->fp->predecessor_time);
	se_tree_insert32(cs->packet_tree, pinfo->fd->num, fInfo);

	return 1;
}

/* Find equal packets, same IP-Id, count them and make time statistics */
static gboolean
call_foreach_count_ip_id(gpointer value, gpointer arg)
{
	comparestat_t *cs=(comparestat_t*)arg;
	frame_info *fInfo=(frame_info*)value, *fInfoTemp;
	nstime_t delta;
	guint i;

	/* we only need one value out of pinfo we use a temp one */
	packet_info *pinfo=(packet_info*)ep_alloc(sizeof(packet_info));
	pinfo->fd=(frame_data*)ep_alloc(sizeof(frame_data));
	pinfo->fd->num = fInfo->num;

	fInfoTemp=se_tree_lookup32(cs->ip_id_tree, fInfo->id);
	if(fInfoTemp==NULL){
		/* Detect ongoing package loss */
		if((cs->last_hit==FALSE)&&(cs->start_ongoing_hits>compare_start)&&(cs->stop_ongoing_hits<compare_stop)){
			cs->stop_ongoing_hits++;
			cs->stop_packet_nr_first=fInfo->num;
		} else if(cs->stop_ongoing_hits<compare_stop){
			cs->stop_ongoing_hits=0;
			cs->stop_packet_nr_first=G_MAXINT32;
		}
		cs->last_hit=FALSE;

		fInfo->fp->count=1;
		se_tree_insert32(cs->ip_id_tree, fInfo->id, fInfo);
	} else {
		/* Detect ongoing package hits, special behavior if start is set to 0 */
		if((cs->last_hit||(compare_start==0))&&(cs->start_ongoing_hits<compare_start||(compare_start==0))){
			if((compare_start==0)&&(cs->start_ongoing_hits!=0)){
				/* start from the first packet so allready set */
			} else {
				cs->start_ongoing_hits++;
				/* Take the lower number */
				cs->start_packet_nr_first=fInfoTemp->num;
				cs->start_packet_nr_second=fInfo->num;
			}
		} else if(cs->start_ongoing_hits<compare_start){
			cs->start_ongoing_hits=0;
			cs->start_packet_nr_first=G_MAXINT32;
		}
		cs->last_hit=TRUE;

		fInfo->fp->count=fInfoTemp->fp->count + 1;
		if(fInfoTemp->fp->cksum!=fInfo->fp->cksum){
			fInfo->fp->cksum=WRONG_CHKSUM;
			fInfoTemp->fp->cksum=WRONG_CHKSUM;
		}
		/* Add partner */
		fInfo->fp->partner=fInfoTemp;
		/* Create time statistic */
		if(fInfo->fp->count==MERGED_FILES){
			nstime_delta(&delta, &fInfo->abs_ts, &fInfoTemp->abs_ts);
			/* Set delta in both packets */
			nstime_set_zero(&fInfoTemp->delta);
			nstime_add(&fInfoTemp->delta, &delta);
			nstime_set_zero(&fInfo->delta);
			nstime_add(&fInfo->delta, &delta);
			time_stat_update(&cs->stats, &delta, pinfo);
		}
		se_tree_insert32(cs->ip_id_tree, fInfo->id, fInfo);
	}

	/* collect TTL's */
	if(TTL_method && (fInfo->num<TTL_SEARCH)){
		for(i=0; i < cs->ip_ttl_list->len; i++){
			if(g_array_index(cs->ip_ttl_list, guint8, i) == fInfo->ip_ttl){
				return FALSE;
			}
		}
		g_array_append_val(cs->ip_ttl_list, fInfo->ip_ttl);
	}

	return FALSE;
}

/*Create new numbering */
static gboolean
call_foreach_new_order(gpointer value, gpointer arg)
{
	comparestat_t *cs=(comparestat_t*)arg;
	frame_info *fInfo=(frame_info*)value, *fInfoTemp;

	/* overwrite Info column for new ordering */
	fInfoTemp=se_tree_lookup32(cs->nr_tree, fInfo->id);
	if(fInfoTemp==NULL){
		if(TTL_method==FALSE){
			if((ADDRESSES_EQUAL(&cs->eth_dst, &fInfo->dl_dst)) || (ADDRESSES_EQUAL(&cs->eth_src, &fInfo->dl_dst))){
				se_tree_insert32(cs->nr_tree, fInfo->id, fInfo);
				fInfo->zebra_time=cs->zebra_time;
				cs->zebra_time.nsecs=cs->zebra_time.nsecs + MERGED_FILES;
			} else {
				cs->zebra_time.nsecs++;
				se_tree_insert32(cs->nr_tree, fInfo->id, fInfo);
				fInfo->zebra_time=cs->zebra_time;
				cs->zebra_time.nsecs++;
			}
		} else {
			if((g_array_index(cs->ip_ttl_list, guint8, 0)==fInfo->ip_ttl) || (g_array_index(cs->ip_ttl_list, guint8, 1)==fInfo->ip_ttl)){
				se_tree_insert32(cs->nr_tree, fInfo->id, fInfo);
				fInfo->zebra_time=cs->zebra_time;
				cs->zebra_time.nsecs=cs->zebra_time.nsecs + MERGED_FILES;
			} else {
				cs->zebra_time.nsecs++;
				se_tree_insert32(cs->nr_tree, fInfo->id, fInfo);
				fInfo->zebra_time=cs->zebra_time;
				cs->zebra_time.nsecs++;
			}

		}
	} else {
		if(TTL_method==FALSE){
			if(((ADDRESSES_EQUAL(&cs->eth_dst, &fInfo->dl_dst)) || (ADDRESSES_EQUAL(&cs->eth_src, &fInfo->dl_dst)))&&(!fmod(fInfoTemp->zebra_time.nsecs,MERGED_FILES))){
				fInfo->zebra_time.nsecs=fInfoTemp->zebra_time.nsecs;
			} else {
				fInfo->zebra_time.nsecs=fInfoTemp->zebra_time.nsecs+1;
			}
		} else {
			if(((g_array_index(cs->ip_ttl_list, guint8, 0)==fInfo->ip_ttl) || (g_array_index(cs->ip_ttl_list, guint8, 1)==fInfo->ip_ttl))&&(!fmod(fInfoTemp->zebra_time.nsecs,MERGED_FILES))){
				fInfo->zebra_time.nsecs=fInfoTemp->zebra_time.nsecs;
			} else {
				fInfo->zebra_time.nsecs=fInfoTemp->zebra_time.nsecs+1;
			}
		}
	}

	/* count packets of file */
	if(fmod(fInfo->zebra_time.nsecs, MERGED_FILES)){
		cs->first_file_amount++;
	} else {
		cs->second_file_amount++;
	}

	/* ordering */
	if(!nstime_is_unset(&cs->current_time)){
		fInfo->fp->predecessor_time.nsecs=cs->current_time.nsecs;
	}

	cs->current_time.nsecs=fInfo->zebra_time.nsecs;

	return FALSE;
}

/* calculate scopes if not set yet */
static gboolean
call_foreach_merge_settings(gpointer value, gpointer arg)
{
	comparestat_t *cs=(comparestat_t*)arg;
	frame_info *fInfo=(frame_info*)value, *fInfoTemp=NULL;
	guint32 tot_packet_amount=cs->first_file_amount+cs->second_file_amount, swap;

	if((fInfo->num==tot_packet_amount)&&(cs->stop_packet_nr_first!=G_MAXINT32)){
		/* calculate missing stop number */
		swap=cs->stop_packet_nr_first;
		cs->stop_packet_nr_first=tot_packet_amount-cs->second_file_amount;;
		cs->stop_packet_nr_second=swap;
	}

	if((fInfo->num==tot_packet_amount)&&(cs->stop_packet_nr_first==G_MAXINT32)&&(cs->start_packet_nr_first!=G_MAXINT32)){
		fInfoTemp=se_tree_lookup32(cs->packet_tree, cs->start_packet_nr_first);
		if(fInfoTemp==NULL){
			printf("ERROR: start number not set correctly\n");
			return FALSE;
		}
		if(fmod(fInfoTemp->zebra_time.nsecs, 2)){
			/*first file*/
			cs->stop_packet_nr_first=cs->start_packet_nr_first+abs(cs->second_file_amount-(cs->start_packet_nr_second-cs->first_file_amount));
			if(cs->stop_packet_nr_first>(tot_packet_amount-cs->second_file_amount)){
				cs->stop_packet_nr_first=tot_packet_amount-cs->second_file_amount;
			}
			/*this only happens if we have too many MAC's or TTL*/
			if(cs->stop_packet_nr_first>cs->start_packet_nr_second){
				cs->stop_packet_nr_first=cs->start_packet_nr_second-1;
			}
			fInfoTemp=se_tree_lookup32(cs->packet_tree, cs->stop_packet_nr_first);
			while((fInfoTemp!=NULL)?fmod(!fInfoTemp->zebra_time.nsecs, 2):TRUE){
				cs->stop_packet_nr_first--;
				fInfoTemp=se_tree_lookup32(cs->packet_tree, cs->stop_packet_nr_first);
			}
		} else {
			/*this only happens if we have too many MAC's or TTL*/
			cs->stop_packet_nr_first=cs->first_file_amount+cs->start_packet_nr_first;
			if(cs->stop_packet_nr_first>tot_packet_amount-cs->first_file_amount){
				cs->stop_packet_nr_first=tot_packet_amount-cs->first_file_amount;
			}
			fInfoTemp=se_tree_lookup32(cs->packet_tree, cs->stop_packet_nr_first);
			while((fInfoTemp!=NULL)?fmod(fInfoTemp->zebra_time.nsecs, 2):TRUE){
				cs->stop_packet_nr_first--;
				fInfoTemp=se_tree_lookup32(cs->packet_tree, cs->stop_packet_nr_first);
			}
		}
		/* set second stop location */
		cs->stop_packet_nr_second=cs->start_packet_nr_second+abs(cs->stop_packet_nr_first-cs->start_packet_nr_first);
		if(cs->stop_packet_nr_second>tot_packet_amount){
			cs->stop_packet_nr_second=tot_packet_amount;
		}
	}

	/* no start found */
	if(fInfo->num==tot_packet_amount&&compare_start!=0&&compare_stop!=0){
		if(cs->start_packet_nr_first==G_MAXINT32){
			printf("Start point couldn't be set, choose a lower compare start");
		}
	}

	return FALSE;
}

static gboolean
call_foreach_print_ip_tree(gpointer value, gpointer user_data)
{
	frame_info *fInfo=(frame_info*)value;
	comparestat_t *cs=(comparestat_t*)user_data;
	gdouble delta, average;
	gboolean show_it=FALSE;

	delta=fabs(get_average(&fInfo->delta,1));
	average=fabs(get_average(&cs->stats.tot, cs->stats.num));

	/* special case if both are set to zero ignore start and stop numbering */
	if(compare_start!=0&&compare_stop!=0){
		/* check out if packet is in searched scope */
		if((cs->start_packet_nr_first<fInfo->num)&&(cs->stop_packet_nr_first>fInfo->num)){
			show_it=TRUE;
		} else {
			/* so we won't miss the other file */
			if((fInfo->num>cs->start_packet_nr_second)&&(fInfo->num<cs->stop_packet_nr_second)){
				show_it=TRUE;
			}
		}
	} else {
		show_it=TRUE;
	}

	if(show_it){
		if(fInfo->fp->count < MERGED_FILES){
			printf("Packet id :%i, count:%i Problem:", fInfo->id, fInfo->fp->count);
			printf("Packet lost\n");
		}
		if(fInfo->fp->count > MERGED_FILES){
			printf("Packet id :%i, count:%i Problem:", fInfo->id, fInfo->fp->count);
			printf("More than two packets\n");
			if(fInfo->fp->cksum == WRONG_CHKSUM){
				printf("Checksum error over IP header\n");
			}
		}
		if(fInfo->fp->count == MERGED_FILES){
			if(fInfo->fp->cksum == WRONG_CHKSUM){
				printf("Packet id :%i, count:%i Problem:", fInfo->id, fInfo->fp->count);
				printf("Checksum error over IP header\n");
				if(((delta < (average-cs->stats.variance)) || (delta > (average+cs->stats.variance))) && (delta > 0.0) && (cs->stats.variance!=0)){
					printf("Not arrived in time\n");
				}
				if((nstime_cmp(&fInfo->fp->predecessor_time, &fInfo->zebra_time)>0||nstime_cmp(&fInfo->fp->partner->fp->predecessor_time, &fInfo->fp->partner->zebra_time)>0) && (fInfo->zebra_time.nsecs!=MERGED_FILES) && ON_method){
					printf("Not correct order\n");
				}
			} else if(((delta < (average-cs->stats.variance)) || (delta > (average+cs->stats.variance))) && (delta > 0.0) && (cs->stats.variance!=0)) {
				printf("Packet id :%i, count:%i Problem:", fInfo->id, fInfo->fp->count);
				printf("Package not arrived in time\n");
				if((nstime_cmp(&fInfo->fp->predecessor_time, &fInfo->zebra_time)>0||nstime_cmp(&fInfo->fp->partner->fp->predecessor_time, &fInfo->fp->partner->zebra_time)>0) && fInfo->zebra_time.nsecs != MERGED_FILES && ON_method){
					printf("Not correct order\n");
				}
			} else if((nstime_cmp(&fInfo->fp->predecessor_time, &fInfo->zebra_time)>0||nstime_cmp(&fInfo->fp->partner->fp->predecessor_time, &fInfo->fp->partner->zebra_time)>0) && fInfo->zebra_time.nsecs != MERGED_FILES && ON_method){
				printf("Packet id :%i, count:%i Problem:", fInfo->id, fInfo->fp->count);
				printf("Not correct order\n");
			}
		}
	}
	return FALSE;
}


/* This callback is used when tshark wants us to draw/update our
 * data to the output device. Since this is tshark only output is
 * stdout.
 * TShark will only call this callback once, which is when tshark has
 * finished reading all packets and exists.
 * If used with wireshark this may be called any time, perhaps once every 3
 * seconds or so.
 * This function may even be called in parallell with (*reset) or (*draw)
 * so make sure there are no races. The data in the rpcstat_t can thus change
 * beneath us. Beware.
 */
static void
comparestat_draw(void *prs)
{
	comparestat_t *cs=prs;
	GString *filter_str = g_string_new("");
	const gchar *statis_string;
	guint32 first_file_amount, second_file_amount;

	/* inital steps, clear all data before start*/
	cs->zebra_time.secs=0;
	cs->zebra_time.nsecs=1;
	nstime_set_unset(&cs->current_time);
	cs->ip_ttl_list=g_array_new(FALSE, FALSE, sizeof(guint8));
	cs->last_hit=FALSE;
	cs->start_ongoing_hits=0;
	cs->stop_ongoing_hits=0;
	cs->start_packet_nr_first=G_MAXINT32;
	cs->start_packet_nr_second=G_MAXINT32;
	cs->stop_packet_nr_first=G_MAXINT32;
	cs->stop_packet_nr_second=G_MAXINT32;
	cs->first_file_amount=0;
	cs->second_file_amount=0;

	time_stat_init(&cs->stats);
	/* not using g_free, because struct is managed by binarytrees */
	cs->ip_id_tree=se_tree_create(EMEM_TREE_TYPE_RED_BLACK, "ip_id_tree");
	emem_tree_foreach(cs->packet_tree, call_foreach_count_ip_id, cs);

	/* set up TTL choice if only one number found */
	if(TTL_method&&cs->ip_ttl_list->len==1){
		g_array_append_val(cs->ip_ttl_list, g_array_index(cs->ip_ttl_list, guint8, 1));
	}

	emem_tree_foreach(cs->packet_tree, call_foreach_new_order,cs);
	emem_tree_foreach(cs->packet_tree, call_foreach_merge_settings, cs);

	/* remembering file amounts */
	first_file_amount=cs->first_file_amount;
	second_file_amount=cs->second_file_amount;
	/* reset after numbering */
	cs->nr_tree=se_tree_create(EMEM_TREE_TYPE_RED_BLACK, "nr_tree");

	/* Variance */
	cs->stats.variance=compare_variance;

	/* add statistic string */
	statis_string=g_strdup_printf("Compare Statistics: \nFilter: %s\nNumber of packets total:%i 1st file:%i, 2nd file:%i\nScopes:\t start:%i stop:%i\nand:\t start:%i stop:%i\nEqual packets: %i \nAllowed variation: %f \nAverage time difference: %f\n", cs->filter ? cs->filter : "", (first_file_amount+second_file_amount), first_file_amount, second_file_amount, cs->start_packet_nr_first, cs->stop_packet_nr_first, cs->start_packet_nr_second, cs->stop_packet_nr_second, cs->stats.num, cs->stats.variance, fabs(get_average(&cs->stats.tot, cs->stats.num)));

	printf("\n");
	printf("===================================================================\n");
	printf("%s", statis_string);
	emem_tree_foreach(cs->ip_id_tree, call_foreach_print_ip_tree, cs);
	printf("===================================================================\n");
	g_string_free(filter_str, TRUE);
	g_array_free(cs->ip_ttl_list, TRUE);
}

/* When called, this function will create a new instance of comparestat.
 * This function is called from tshark when it parses the -z compare, arguments
 * and it creates a new instance to store statistics in and registers this
 * new instance for the compare tap.
 */
static void
comparestat_init(const char *optarg, void* userdata _U_)
{
	comparestat_t *cs;
	const char *filter=NULL;
	GString *error_string;
	gint start, stop,ttl, order, pos=0;
	gdouble variance;

	if(sscanf(optarg,"compare,%d,%d,%d,%d,%lf%n",&start, &stop, &ttl, &order, &variance, &pos)==5){
		if(pos){
			if(*(optarg+pos)==',')
				filter=optarg+pos+1;
			else
				filter=optarg+pos;
		} else {
			filter=NULL;
		}
	} else {
		fprintf(stderr, "tshark: invalid \"-z compare,<start>,<stop>,<ttl[0|1]>,<order[0|1]>,<variance>[,<filter>]\" argument\n");
		exit(1);
	}

	compare_variance=variance;
	compare_start=start;
	compare_stop=stop;
	TTL_method=ttl;
	ON_method=order;

	cs=g_malloc(sizeof(comparestat_t));
	nstime_set_unset(&cs->current_time);
	cs->ip_ttl_list=g_array_new(FALSE, FALSE, sizeof(guint8));
	cs->last_hit=FALSE;
	cs->start_ongoing_hits=0;
	cs->stop_ongoing_hits=0;
	cs->start_packet_nr_first=G_MAXINT32;
	cs->start_packet_nr_second=G_MAXINT32;
	cs->stop_packet_nr_first=G_MAXINT32;
	cs->stop_packet_nr_second=G_MAXINT32;
	cs->first_file_amount=0;
	cs->second_file_amount=0;

	cs->zebra_time.secs=0;
	cs->zebra_time.nsecs=1;
	cs->nr_tree=se_tree_create(EMEM_TREE_TYPE_RED_BLACK, "nr_tree");
	/* microsecond precision */
	timestamp_set_precision(TS_PREC_AUTO_NSEC);

	if(filter){
		cs->filter=g_strdup(filter);
	} else {
		cs->filter=NULL;
	}

	/* create a Hash to count the packets with the same ip.id */
	cs->packet_tree=se_tree_create(EMEM_TREE_TYPE_RED_BLACK, "Packet_info_tree");

	error_string=register_tap_listener("ip", cs, filter, 0, comparestat_reset, comparestat_packet, comparestat_draw);
	if(error_string){
		/* error, we failed to attach to the tap. clean up */
		g_free(cs->filter);
		g_free(cs);

		fprintf(stderr, "tshark: Couldn't register compare tap: %s\n", error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}


void
register_tap_listener_comparestat(void)
{
	register_stat_cmd_arg("compare,", comparestat_init,NULL);
}

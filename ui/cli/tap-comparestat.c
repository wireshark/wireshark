/* tap-comparestat.c
 * Compare two capture files
 * Copyright 2008 Vincenzo Condoleo, Christophe Dirac, Reto Ruoss
 * supported by HSR (Hochschule Rapperswil)
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

/* This module provides statistics about two merged capture files, to find packet loss,
 * time delay, ip header checksum errors and order check to tshark.
 * It's also detecting the matching regions of the different files.
 *
 * The packets are compared by the ip id. MAC or TTL is used to distinct the different files.
 * It is only used by tshark and not wireshark
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <glib.h>

#include <epan/packet_info.h>
#include <epan/in_cksum.h>
#include <epan/packet.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/dissectors/packet-ip.h>
#include <epan/timestats.h>


/* For checksum */
#define BYTES 8
#define WRONG_CHKSUM 0

#define MERGED_FILES 2

#define TTL_SEARCH 5

void register_tap_listener_comparestat(void);

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
	GHashTable *packet_set, *ip_id_set, *nr_set;
	address eth_dst, eth_src;
	nstime_t zebra_time, current_time;
	timestat_t stats;
	GArray *ip_ttl_list;
	gboolean last_hit;
	guint32 start_ongoing_hits, stop_ongoing_hits, start_packet_nr_first, start_packet_nr_second, stop_packet_nr_first, stop_packet_nr_second;
	guint32 first_file_amount, second_file_amount;
} comparestat_t;


/* to call directly _init */
static gdouble compare_variance = 0.0;
static guint8 compare_start, compare_stop;
static gboolean TTL_method = TRUE, ON_method = TRUE;

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
	comparestat_t *cs = (comparestat_t *)arg;
	const ws_ip *ci = (const ws_ip *)arg2;
	frame_info *fInfo;
	vec_t cksum_vec[3];
	guint16 computed_cksum = 0;

	/* so this get filled, usually with the first frame */
	if (cs->eth_dst.len == 0) {
		copy_address_shallow(&cs->eth_dst, &pinfo->dl_dst);
		copy_address_shallow(&cs->eth_src, &pinfo->dl_src);
	}

	/* Set up the fields of the pseudo-header and create checksum */
	cksum_vec[0].ptr = &ci->ip_v_hl;
	cksum_vec[0].len = BYTES;
	/* skip TTL */
	cksum_vec[1].ptr = &ci->ip_nxt;
	cksum_vec[1].len = 1;
	/* skip header checksum and ip's (because of NAT)*/
	cksum_vec[2].ptr = (const guint8 *)ci->ip_dst.data;
	cksum_vec[2].ptr = cksum_vec[2].ptr+ci->ip_dst.len;
	/* dynamic computation */
	cksum_vec[2].len = ci->ip_len-20;
	computed_cksum = in_cksum(&cksum_vec[0], 3);

	/* collect all packet infos */
	fInfo = (frame_info*)g_malloc(sizeof(frame_info));
	fInfo->fp = (for_print*)g_malloc(sizeof(for_print));
	fInfo->fp->partner = NULL;
	fInfo->fp->count = 1;
	fInfo->fp->cksum = computed_cksum;
	fInfo->num = pinfo->num;
	fInfo->id = ci->ip_id;
	fInfo->ip_ttl = ci->ip_ttl;
	copy_address_shallow(&fInfo->dl_dst, &pinfo->dl_dst);
	fInfo->abs_ts = pinfo->abs_ts;
	/* clean memory */
	nstime_set_zero(&fInfo->zebra_time);
	nstime_set_zero(&fInfo->fp->predecessor_time);
	g_hash_table_insert(cs->packet_set, GINT_TO_POINTER(pinfo->num), fInfo);

	return 1;
}


static void
frame_info_free(gpointer data)
{
	frame_info *fInfo = (frame_info *)data;

	g_free(fInfo->fp);
	g_free(fInfo);
}

/* Find equal packets, same IP-Id, count them and make time statistics */
static void
call_foreach_count_ip_id(gpointer key _U_, gpointer value, gpointer arg)
{
	comparestat_t *cs = (comparestat_t*)arg;
	frame_info *fInfo = (frame_info*)value, *fInfoTemp;
	nstime_t delta;
	guint i;

	/* we only need one value out of pinfo we use a temp one */
	packet_info *pinfo = (packet_info*)g_malloc(sizeof(packet_info));
	pinfo->fd = (frame_data*)g_malloc(sizeof(frame_data));
	pinfo->num = fInfo->num;

	fInfoTemp = (frame_info *)g_hash_table_lookup(cs->ip_id_set, GINT_TO_POINTER((gint)fInfo->id));
	if (fInfoTemp == NULL) {
		/* Detect ongoing package loss */
		if ((cs->last_hit == FALSE) && (cs->start_ongoing_hits > compare_start) && (cs->stop_ongoing_hits < compare_stop)) {
			cs->stop_ongoing_hits++;
			cs->stop_packet_nr_first = fInfo->num;
		} else if (cs->stop_ongoing_hits < compare_stop) {
			cs->stop_ongoing_hits = 0;
			cs->stop_packet_nr_first = G_MAXINT32;
		}
		cs->last_hit = FALSE;

		fInfo->fp->count = 1;
		g_hash_table_insert(cs->ip_id_set, GINT_TO_POINTER((gint)fInfo->id), fInfo);
	} else {
		/* Detect ongoing package hits, special behavior if start is set to 0 */
		if ((cs->last_hit || (compare_start == 0)) && (cs->start_ongoing_hits < compare_start || (compare_start == 0))) {
			if ((compare_start == 0) && (cs->start_ongoing_hits != 0)) {
				/* start from the first packet so already set */
			} else {
				cs->start_ongoing_hits++;
				/* Take the lower number */
				cs->start_packet_nr_first = fInfoTemp->num;
				cs->start_packet_nr_second = fInfo->num;
			}
		} else if (cs->start_ongoing_hits < compare_start) {
			cs->start_ongoing_hits = 0;
			cs->start_packet_nr_first = G_MAXINT32;
		}
		cs->last_hit = TRUE;

		fInfo->fp->count = fInfoTemp->fp->count + 1;
		if (fInfoTemp->fp->cksum != fInfo->fp->cksum) {
			fInfo->fp->cksum = WRONG_CHKSUM;
			fInfoTemp->fp->cksum = WRONG_CHKSUM;
		}
		/* Add partner */
		fInfo->fp->partner = fInfoTemp;
		/* Create time statistic */
		if (fInfo->fp->count == MERGED_FILES) {
			nstime_delta(&delta, &fInfo->abs_ts, &fInfoTemp->abs_ts);
			/* Set delta in both packets */
			nstime_set_zero(&fInfoTemp->delta);
			nstime_add(&fInfoTemp->delta, &delta);
			nstime_set_zero(&fInfo->delta);
			nstime_add(&fInfo->delta, &delta);
			time_stat_update(&cs->stats, &delta, pinfo);
		}
		g_hash_table_insert(cs->ip_id_set, GINT_TO_POINTER((gint)fInfo->id), fInfo);
	}

	/* collect TTL's */
	if (TTL_method && (fInfo->num < TTL_SEARCH)) {
		for (i=0; i < cs->ip_ttl_list->len; i++) {
			if (g_array_index(cs->ip_ttl_list, guint8, i) == fInfo->ip_ttl) {
				return;
			}
		}
		g_array_append_val(cs->ip_ttl_list, fInfo->ip_ttl);
	}

	g_free(pinfo->fd);
	g_free(pinfo);
}

/*Create new numbering */
static void
call_foreach_new_order(gpointer key _U_, gpointer value, gpointer arg)
{
	comparestat_t *cs = (comparestat_t*)arg;
	frame_info *fInfo = (frame_info*)value, *fInfoTemp;

	/* overwrite Info column for new ordering */
	fInfoTemp = (frame_info *)g_hash_table_lookup(cs->nr_set, GINT_TO_POINTER((gint)fInfo->id));
	if (fInfoTemp == NULL) {
		if (TTL_method == FALSE) {
			if ((addresses_equal(&cs->eth_dst, &fInfo->dl_dst)) || (addresses_equal(&cs->eth_src, &fInfo->dl_dst))) {
				g_hash_table_insert(cs->nr_set, GINT_TO_POINTER((gint)fInfo->id), fInfo);
				fInfo->zebra_time = cs->zebra_time;
				cs->zebra_time.nsecs = cs->zebra_time.nsecs + MERGED_FILES;
			} else {
				cs->zebra_time.nsecs++;
				g_hash_table_insert(cs->nr_set, GINT_TO_POINTER((gint)fInfo->id), fInfo);
				fInfo->zebra_time = cs->zebra_time;
				cs->zebra_time.nsecs++;
			}
		} else {
			if ((g_array_index(cs->ip_ttl_list, guint8, 0) == fInfo->ip_ttl) || (g_array_index(cs->ip_ttl_list, guint8, 1) == fInfo->ip_ttl)) {
				g_hash_table_insert(cs->nr_set, GINT_TO_POINTER((gint)fInfo->id), fInfo);
				fInfo->zebra_time = cs->zebra_time;
				cs->zebra_time.nsecs = cs->zebra_time.nsecs + MERGED_FILES;
			} else {
				cs->zebra_time.nsecs++;
				g_hash_table_insert(cs->nr_set, GINT_TO_POINTER((gint)fInfo->id), fInfo);
				fInfo->zebra_time = cs->zebra_time;
				cs->zebra_time.nsecs++;
			}

		}
	} else {
		if (TTL_method == FALSE) {
			if (((addresses_equal(&cs->eth_dst, &fInfo->dl_dst)) || (addresses_equal(&cs->eth_src, &fInfo->dl_dst))) && (!fmod(fInfoTemp->zebra_time.nsecs, MERGED_FILES))) {
				fInfo->zebra_time.nsecs = fInfoTemp->zebra_time.nsecs;
			} else {
				fInfo->zebra_time.nsecs = fInfoTemp->zebra_time.nsecs+1;
			}
		} else {
			if (((g_array_index(cs->ip_ttl_list, guint8, 0) == fInfo->ip_ttl) || (g_array_index(cs->ip_ttl_list, guint8, 1) == fInfo->ip_ttl)) && (!fmod(fInfoTemp->zebra_time.nsecs, MERGED_FILES))) {
				fInfo->zebra_time.nsecs = fInfoTemp->zebra_time.nsecs;
			} else {
				fInfo->zebra_time.nsecs = fInfoTemp->zebra_time.nsecs+1;
			}
		}
	}

	/* count packets of file */
	if (fmod(fInfo->zebra_time.nsecs, MERGED_FILES)) {
		cs->first_file_amount++;
	} else {
		cs->second_file_amount++;
	}

	/* ordering */
	if (!nstime_is_unset(&cs->current_time)) {
		fInfo->fp->predecessor_time.nsecs = cs->current_time.nsecs;
	}

	cs->current_time.nsecs = fInfo->zebra_time.nsecs;
}

/* calculate scopes if not set yet */
static void
call_foreach_merge_settings(gpointer key _U_, gpointer value, gpointer arg)
{
	comparestat_t *cs = (comparestat_t*)arg;
	frame_info *fInfo = (frame_info*)value, *fInfoTemp = NULL;
	guint32 tot_packet_amount = cs->first_file_amount+cs->second_file_amount, swap;

	if ((fInfo->num == tot_packet_amount) && (cs->stop_packet_nr_first != G_MAXINT32)) {
		/* calculate missing stop number */
		swap = cs->stop_packet_nr_first;
		cs->stop_packet_nr_first = tot_packet_amount-cs->second_file_amount;
		cs->stop_packet_nr_second = swap;
	}

	if ((fInfo->num == tot_packet_amount) && (cs->stop_packet_nr_first == G_MAXINT32) && (cs->start_packet_nr_first != G_MAXINT32)) {
		fInfoTemp = (frame_info *)g_hash_table_lookup(cs->packet_set, GINT_TO_POINTER(cs->start_packet_nr_first));
		if (fInfoTemp == NULL) {
			printf("ERROR: start number not set correctly\n");
			return;
		}
		if (fmod(fInfoTemp->zebra_time.nsecs, 2)) {
			/*first file*/
			cs->stop_packet_nr_first = cs->start_packet_nr_first+(cs->second_file_amount-(cs->start_packet_nr_second-cs->first_file_amount));
			if (cs->stop_packet_nr_first > (tot_packet_amount-cs->second_file_amount)) {
				cs->stop_packet_nr_first = tot_packet_amount-cs->second_file_amount;
			}
			/*this only happens if we have too many MAC's or TTL*/
			if (cs->stop_packet_nr_first > cs->start_packet_nr_second) {
				cs->stop_packet_nr_first = cs->start_packet_nr_second-1;
			}
			fInfoTemp = (frame_info *)g_hash_table_lookup(cs->packet_set, GINT_TO_POINTER(cs->stop_packet_nr_first));
			while ((fInfoTemp != NULL) ? fmod(!fInfoTemp->zebra_time.nsecs, 2) : TRUE) {
				cs->stop_packet_nr_first--;
				fInfoTemp = (frame_info *)g_hash_table_lookup(cs->packet_set, GINT_TO_POINTER(cs->stop_packet_nr_first));
			}
		} else {
			/*this only happens if we have too many MAC's or TTL*/
			cs->stop_packet_nr_first = cs->first_file_amount+cs->start_packet_nr_first;
			if (cs->stop_packet_nr_first > tot_packet_amount-cs->first_file_amount) {
				cs->stop_packet_nr_first = tot_packet_amount-cs->first_file_amount;
			}
			fInfoTemp = (frame_info *)g_hash_table_lookup(cs->packet_set, GINT_TO_POINTER(cs->stop_packet_nr_first));
			while ((fInfoTemp != NULL) ? fmod(fInfoTemp->zebra_time.nsecs, 2) : TRUE) {
				cs->stop_packet_nr_first--;
				fInfoTemp = (frame_info *)g_hash_table_lookup(cs->packet_set, GINT_TO_POINTER(cs->stop_packet_nr_first));
			}
		}
		/* set second stop location */
		cs->stop_packet_nr_second = cs->start_packet_nr_second+(cs->stop_packet_nr_first-cs->start_packet_nr_first);
		if (cs->stop_packet_nr_second > tot_packet_amount) {
			cs->stop_packet_nr_second = tot_packet_amount;
		}
	}

	/* no start found */
	if (fInfo->num == tot_packet_amount && compare_start != 0 && compare_stop != 0) {
		if (cs->start_packet_nr_first == G_MAXINT32) {
			printf("Start point couldn't be set, choose a lower compare start");
		}
	}
}

static void
call_foreach_print_ip_tree(gpointer key _U_, gpointer value, gpointer user_data)
{
	frame_info *fInfo = (frame_info*)value;
	comparestat_t *cs = (comparestat_t*)user_data;
	gdouble delta, average;
	gboolean show_it = FALSE;
	gboolean checksum_error = FALSE;
	gboolean not_in_time = FALSE;
	gboolean incorrect_order = FALSE;


	delta = fabs(get_average(&fInfo->delta, 1));
	average = fabs(get_average(&cs->stats.tot, cs->stats.num));

	/* special case if both are set to zero ignore start and stop numbering */
	if (compare_start != 0 && compare_stop != 0) {
		/* check out if packet is in searched scope */
		if ((cs->start_packet_nr_first < fInfo->num)&&(cs->stop_packet_nr_first > fInfo->num)) {
			show_it = TRUE;
		} else {
			/* so we won't miss the other file */
			if ((fInfo->num > cs->start_packet_nr_second)&&(fInfo->num < cs->stop_packet_nr_second)) {
				show_it = TRUE;
			}
		}
	} else {
		show_it = TRUE;
	}

	if (show_it) {
		if (fInfo->fp->count < MERGED_FILES) {
			printf("Packet ID: %u, Count: %u, Problem: Packet lost\n", fInfo->id, fInfo->fp->count);
		}
		if (fInfo->fp->count > MERGED_FILES) {
			if (fInfo->fp->cksum == WRONG_CHKSUM) {
				checksum_error = TRUE;
			}
			printf("Packet ID: %u, Count: %u, Problem: More than two packets%s\n", fInfo->id, fInfo->fp->count,
							checksum_error ? "; Checksum error over IP header" : "");
		}
		if (fInfo->fp->count == MERGED_FILES) {
			if (fInfo->fp->cksum == WRONG_CHKSUM) {
				printf("Packet ID: %u, Count: %u, Problem: Checksum error over IP header\n", fInfo->id, fInfo->fp->count);
				if (((delta < (average-cs->stats.variance)) || (delta > (average+cs->stats.variance))) && (delta > 0.0) && (cs->stats.variance != 0)) {
					not_in_time = TRUE;
				}
				if ((nstime_cmp(&fInfo->fp->predecessor_time, &fInfo->zebra_time) > 0||nstime_cmp(&fInfo->fp->partner->fp->predecessor_time, &fInfo->fp->partner->zebra_time) > 0) && (fInfo->zebra_time.nsecs != MERGED_FILES) && ON_method) {
					incorrect_order = TRUE;
				}
				printf("Packet ID: %u, Count: %u, Problem: Checksum error over IP header%s%s\n", fInfo->id, fInfo->fp->count,
					not_in_time ? "; Did not arrive in time" : "", incorrect_order ? "; Incorrect order" : "");
			} else if (((delta < (average-cs->stats.variance)) || (delta > (average+cs->stats.variance))) && (delta > 0.0) && (cs->stats.variance != 0)) {
				printf("Packet ID: %u, Count: %u, Problem: Did not arrive in time\n", fInfo->id, fInfo->fp->count);
				if ((nstime_cmp(&fInfo->fp->predecessor_time, &fInfo->zebra_time) > 0 || nstime_cmp(&fInfo->fp->partner->fp->predecessor_time, &fInfo->fp->partner->zebra_time) > 0) && fInfo->zebra_time.nsecs != MERGED_FILES && ON_method) {
					incorrect_order = TRUE;
				}
				printf("Packet ID: %u, Count: %u, Problem: Did not arrive in time%s\n", fInfo->id, fInfo->fp->count,
										incorrect_order ? "; Incorrect order" : "");
			} else if ((nstime_cmp(&fInfo->fp->predecessor_time, &fInfo->zebra_time) > 0 || nstime_cmp(&fInfo->fp->partner->fp->predecessor_time, &fInfo->fp->partner->zebra_time) > 0) && fInfo->zebra_time.nsecs != MERGED_FILES && ON_method) {
				printf("Packet ID: %u, Count: %u, Problem: Incorrect order", fInfo->id, fInfo->fp->count);
			}
		}
	}
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
	comparestat_t *cs = (comparestat_t *)prs;
	GString *filter_str = g_string_new("");
	const gchar *statis_string;
	guint32 first_file_amount, second_file_amount;

	/* initial steps, clear all data before start*/
	cs->zebra_time.secs	   = 0;
	cs->zebra_time.nsecs	   = 1;
	nstime_set_unset(&cs->current_time);
	cs->ip_ttl_list		   = g_array_new(FALSE, FALSE, sizeof(guint8));
	cs->last_hit		   = FALSE;
	cs->start_ongoing_hits	   = 0;
	cs->stop_ongoing_hits	   = 0;
	cs->start_packet_nr_first  = G_MAXINT32;
	cs->start_packet_nr_second = G_MAXINT32;
	cs->stop_packet_nr_first   = G_MAXINT32;
	cs->stop_packet_nr_second  = G_MAXINT32;
	cs->first_file_amount	   = 0;
	cs->second_file_amount	   = 0;

	time_stat_init(&cs->stats);
	cs->ip_id_set = g_hash_table_new(NULL, NULL);
	g_hash_table_foreach(cs->packet_set, call_foreach_count_ip_id, cs);

	/* set up TTL choice if only one number found */
	if (TTL_method&&cs->ip_ttl_list->len == 1) {
		g_array_append_val(cs->ip_ttl_list, g_array_index(cs->ip_ttl_list, guint8, 1));
	}

	g_hash_table_foreach(cs->packet_set, call_foreach_new_order, cs);
	g_hash_table_foreach(cs->packet_set, call_foreach_merge_settings, cs);

	/* remembering file amounts */
	first_file_amount = cs->first_file_amount;
	second_file_amount = cs->second_file_amount;
	/* reset after numbering */
	g_hash_table_remove_all(cs->nr_set);

	/* Variance */
	cs->stats.variance = compare_variance;

	/* add statistic string */
	statis_string = g_strdup_printf(
			"Filter: %s\n"
			"Packet count: %i, 1st file: %i, 2nd file: %i\n"
			"Scope 1: packet %i to %i\n"
			"Scope 2: packet %i to %i\n"
			"Equal packets: %i\n"
			"Allowed variance: %.2f\n"
			"Average time difference: %.2f\n"
			"===================================================================\n",
			cs->filter ? cs->filter : "<none>", (first_file_amount+second_file_amount),
			first_file_amount, second_file_amount, cs->start_packet_nr_first,
			cs->stop_packet_nr_first, cs->start_packet_nr_second, cs->stop_packet_nr_second,
			cs->stats.num, cs->stats.variance, fabs(get_average(&cs->stats.tot, cs->stats.num)));
	printf("\n");
	printf("===================================================================\n");
	printf("                            Results\n");
	printf("===================================================================\n");
	printf("%s", statis_string);
	g_hash_table_foreach(cs->ip_id_set, call_foreach_print_ip_tree, cs);

	g_string_free(filter_str, TRUE);
	g_hash_table_destroy(cs->ip_id_set);
	g_array_free(cs->ip_ttl_list, TRUE);
}

/* When called, this function will create a new instance of comparestat.
 * This function is called from tshark when it parses the -z compare, arguments
 * and it creates a new instance to store statistics in and registers this
 * new instance for the compare tap.
 */
static void
comparestat_init(const char *opt_arg, void *userdata _U_)
{
	comparestat_t *cs;
	const char *filter = NULL;
	GString *error_string;
	gint start, stop, ttl, order, pos = 0;
	gdouble variance;

	if (sscanf(opt_arg, "compare,%d,%d,%d,%d,%lf%n", &start, &stop, &ttl, &order, &variance, &pos) == 5) {
		if (*(opt_arg+pos) == ',')
			filter = opt_arg+pos+1;
	} else {
		fprintf(stderr, "tshark: invalid \"-z compare,<start>,<stop>,<ttl[0|1]>,<order[0|1]>,<variance>[,<filter>]\" argument\n");
		exit(1);
	}

	compare_variance = variance;
	compare_start = start;
	compare_stop = stop;
	TTL_method = ttl;
	ON_method = order;

	cs = g_new(comparestat_t, 1);
	nstime_set_unset(&cs->current_time);
	cs->ip_ttl_list		   = g_array_new(FALSE, FALSE, sizeof(guint8));
	cs->last_hit		   = FALSE;
	cs->start_ongoing_hits	   = 0;
	cs->stop_ongoing_hits	   = 0;
	cs->start_packet_nr_first  = G_MAXINT32;
	cs->start_packet_nr_second = G_MAXINT32;
	cs->stop_packet_nr_first   = G_MAXINT32;
	cs->stop_packet_nr_second  = G_MAXINT32;
	cs->first_file_amount	   = 0;
	cs->second_file_amount	   = 0;

	cs->zebra_time.secs	   = 0;
	cs->zebra_time.nsecs	   = 1;
	cs->nr_set		   = g_hash_table_new(NULL, NULL);

	if (filter) {
		cs->filter = g_strdup(filter);
	} else {
		cs->filter = NULL;
	}

	/* create a Hash to count the packets with the same ip.id */
	cs->packet_set = g_hash_table_new_full(NULL, NULL, NULL, frame_info_free);

	error_string = register_tap_listener("ip", cs, filter, 0, comparestat_reset, comparestat_packet, comparestat_draw);
	if (error_string) {
		/* error, we failed to attach to the tap. clean up */
		g_free(cs->filter);
		g_hash_table_destroy(cs->packet_set);
		g_free(cs);

		fprintf(stderr, "tshark: Couldn't register compare tap: %s\n", error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}

static stat_tap_ui comparestat_ui = {
	REGISTER_STAT_GROUP_GENERIC,
	NULL,
	"compare",
	comparestat_init,
	0,
	NULL
};

void
register_tap_listener_comparestat(void)
{
	register_stat_tap_ui(&comparestat_ui, NULL);
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

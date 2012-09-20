/* tap-icmpstat.c
 * icmpstat   2011 Christopher Maynard
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

/* This module provides icmp echo request/reply SRT statistics to tshark.
 * It is only used by tshark and not wireshark
 *
 * It was based on tap-rpcstat.c and doc/README.tapping.
 */

#include "config.h"

#include <stdio.h>

#include <string.h>
#include "epan/packet_info.h"
#include <epan/tap.h>
#include <epan/stat_cmd_args.h>
#include <epan/dissectors/packet-icmp.h>
#include <math.h>

/* used to keep track of the ICMP statistics */
typedef struct _icmpstat_t {
    char *filter;
    GSList *rt_list;
    guint num_rqsts;
    guint num_resps;
    guint min_frame;
    guint max_frame;
    double min_msecs;
    double max_msecs;
    double tot_msecs;
} icmpstat_t;


/* This callback is never used by tshark but it is here for completeness.  When
 * registering below, we could just have left this function as NULL.
 *
 * When used by wireshark, this function will be called whenever we would need
 * to reset all state, such as when wireshark opens a new file, when it starts
 * a new capture, when it rescans the packetlist after some prefs have changed,
 * etc.
 *
 * So if your application has some state it needs to clean up in those
 * situations, here is a good place to put that code.
 */
static void
icmpstat_reset(void *tapdata)
{
    icmpstat_t *icmpstat = tapdata;

    g_slist_free(icmpstat->rt_list);
    memset(icmpstat, 0, sizeof(icmpstat_t));
    icmpstat->min_msecs = 1.0 * G_MAXUINT;
}


static gint compare_doubles(gconstpointer a, gconstpointer b)
{
    double ad, bd;

    ad = *(double *)a;
    bd = *(double *)b;

    if (ad < bd)
        return -1;
    if (ad > bd)
        return 1;
    return 0;
}


/* This callback is invoked whenever the tap system has seen a packet we might
 * be interested in.  The function is to be used to only update internal state
 * information in the *tapdata structure, and if there were state changes which
 * requires the window to be redrawn, return 1 and (*draw) will be called
 * sometime later.
 *
 * This function should be as lightweight as possible since it executes
 * together with the normal wireshark dissectors.  Try to push as much
 * processing as possible into (*draw) instead since that function executes
 * asynchronously and does not affect the main thread's performance.
 *
 * If it is possible, try to do all "filtering" explicitly since you will get
 * MUCH better performance than applying a similar display-filter in the
 * register call.
 *
 * The third parameter is tap dependent.  Since we register this one to the
 * "icmp" tap, the third parameter type is icmp_transaction_t.
 *
 * function returns :
 *  0: no updates, no need to call (*draw) later
 * !0: state has changed, call (*draw) sometime later
 */
static int
icmpstat_packet(void *tapdata, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *data)
{
    icmpstat_t *icmpstat = tapdata;
    const icmp_transaction_t *trans = data;
    double resp_time, *rt;

    if (trans == NULL)
        return 0;

    if (trans->resp_frame) {
        resp_time = nstime_to_msec(&trans->resp_time);
        rt = g_malloc(sizeof(double));
        if (rt == NULL)
            return 0;
        *rt = resp_time;
        icmpstat->rt_list = g_slist_insert_sorted(icmpstat->rt_list, rt, compare_doubles);
        icmpstat->num_resps++;
        if (icmpstat->min_msecs > resp_time) {
            icmpstat->min_frame = trans->resp_frame;
            icmpstat->min_msecs = resp_time;
        }
        if (icmpstat->max_msecs < resp_time) {
            icmpstat->max_frame = trans->resp_frame;
            icmpstat->max_msecs = resp_time;
        }
        icmpstat->tot_msecs += resp_time;
    } else if (trans->rqst_frame)
        icmpstat->num_rqsts++;
    else
        return 0;

    return 1;
}


/*
 * Compute the mean, median and standard deviation.
 */
static void compute_stats(icmpstat_t *icmpstat, double *mean, double *med, double *sdev)
{
    GSList *slist = icmpstat->rt_list;
    double diff;
    double sq_diff_sum = 0.0;

    if (icmpstat->num_resps == 0 || slist == NULL) {
        *mean = 0.0;
        *med = 0.0;
        *sdev = 0.0;
        return;
    }

    /* (arithmetic) mean */
    *mean = icmpstat->tot_msecs / icmpstat->num_resps;

    /* median: If we have an odd number of elements in our list, then the
     * median is simply the middle element, otherwise the median is computed by
     * averaging the 2 elements on either side of the mid-point. */
    if (icmpstat->num_resps & 1)
        *med = *(double *)g_slist_nth_data(slist, icmpstat->num_resps / 2);
    else {
        *med =
            (*(double *)g_slist_nth_data(slist, (icmpstat->num_resps - 1) / 2) +
            *(double *)g_slist_nth_data(slist, icmpstat->num_resps / 2)) / 2;
    }

    /* (sample) standard deviation */
    for ( ; slist; slist = g_slist_next(slist)) {
        diff = *(double *)slist->data - *mean;
        sq_diff_sum += diff * diff;
    }
    if (icmpstat->num_resps > 1)
        *sdev = sqrt(sq_diff_sum / (icmpstat->num_resps - 1));
    else
        *sdev = 0.0;
}


/* This callback is used when tshark wants us to draw/update our data to the
 * output device.  Since this is tshark, the only output is stdout.
 * TShark will only call this callback once, which is when tshark has finished
 * reading all packets and exits.
 * If used with wireshark this may be called any time, perhaps once every 3
 * seconds or so.
 * This function may even be called in parallel with (*reset) or (*draw), so
 * make sure there are no races.  The data in the icmpstat_t can thus change
 * beneath us.  Beware!
 *
 * How best to display the data?  For now, following other tap statistics
 * output, but here are a few other alternatives we might choose from:
 *
 * -> Windows ping output:
 *      Ping statistics for <IP>:
 *          Packets: Sent = <S>, Received = <R>, Lost = <L> (<LP>% loss),
 *      Approximate round trip times in milli-seconds:
 *          Minimum = <m>ms, Maximum = <M>ms, Average = <A>ms
 *
 * -> Cygwin ping output:
 *      ----<HOST> PING Statistics----
 *      <S> packets transmitted, <R> packets received, <LP>% packet loss
 *      round-trip (ms)  min/avg/max/med = <m>/<M>/<A>/<D>
 *
 * -> Linux ping output:
 *      --- <HOST> ping statistics ---
 *      <S> packets transmitted, <R> received, <LP>% packet loss, time <T>ms
 *      rtt min/avg/max/mdev = <m>/<A>/<M>/<D> ms
 */
static void
icmpstat_draw(void *tapdata)
{
    icmpstat_t *icmpstat = tapdata;
    unsigned int lost;
    double mean, sdev, med;

    printf("\n");
    printf("==========================================================================\n");
    printf("ICMP Service Response Time (SRT) Statistics (all times in ms):\n");
    printf("Filter: %s\n", icmpstat->filter ? icmpstat->filter : "<none>");
    printf("\nRequests  Replies   Lost      %% Loss\n");

    if (icmpstat->num_rqsts) {
        lost =  icmpstat->num_rqsts - icmpstat->num_resps;
        compute_stats(icmpstat, &mean, &med, &sdev);

        printf("%-10u%-10u%-10u%5.1f%%\n\n",
            icmpstat->num_rqsts, icmpstat->num_resps, lost,
            100.0 * lost / icmpstat->num_rqsts);
        printf("Minimum   Maximum   Mean      Median    SDeviation     Min Frame Max Frame\n");
        printf("%-10.3f%-10.3f%-10.3f%-10.3f%-10.3f     %-10u%-10u\n",
            icmpstat->min_msecs >= G_MAXUINT ? 0.0 : icmpstat->min_msecs,
            icmpstat->max_msecs, mean, med, sdev,
            icmpstat->min_frame, icmpstat->max_frame);
    } else {
        printf("0         0         0           0.0%%\n\n");
        printf("Minimum   Maximum   Mean      Median    SDeviation     Min Frame Max Frame\n");
        printf("0.000     0.000     0.000     0.000     0.000          0         0\n");
    }
    printf("==========================================================================\n");
}


/* When called, this function will create a new instance of icmpstat.
 *
 * This function is called from tshark when it parses the -z icmp, arguments
 * and it creates a new instance to store statistics in and registers this new
 * instance for the icmp tap.
 */
static void
icmpstat_init(const char *optarg, void* userdata _U_)
{
    icmpstat_t *icmpstat;
    const char *filter = NULL;
    GString *error_string;

    if (strstr(optarg, "icmp,srt,"))
        filter = optarg + strlen("icmp,srt,");

    icmpstat = g_try_malloc(sizeof(icmpstat_t));
    if (icmpstat == NULL) {
        fprintf(stderr, "tshark: g_try_malloc() fatal error.\n");
        exit(1);
    }
    memset(icmpstat, 0, sizeof(icmpstat_t));
    icmpstat->min_msecs = 1.0 * G_MAXUINT;

    if (filter)
        icmpstat->filter = g_strdup(filter);

/* It is possible to create a filter and attach it to the callbacks.  Then the
 * callbacks would only be invoked if the filter matched.
 *
 * Evaluating filters is expensive and if we can avoid it and not use them,
 * then we gain performance.
 *
 * In this case we do the filtering for protocol and version inside the
 * callback itself but use whatever filter the user provided.
 */

    error_string = register_tap_listener("icmp", icmpstat, icmpstat->filter,
        TL_REQUIRES_NOTHING, icmpstat_reset, icmpstat_packet, icmpstat_draw);
    if (error_string) {
        /* error, we failed to attach to the tap. clean up */
        if (icmpstat->filter)
            g_free(icmpstat->filter);
        g_free(icmpstat);

        fprintf(stderr, "tshark: Couldn't register icmp,srt tap: %s\n",
            error_string->str);
        g_string_free(error_string, TRUE);
        exit(1);
    }
}


void
register_tap_listener_icmpstat(void)
{
    register_stat_cmd_arg("icmp,srt", icmpstat_init, NULL);
}


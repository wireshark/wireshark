/* tap-rtp-analysis.c
 * RTP stream handler functions used by tshark and wireshark
 *
 * Copyright 2008, Ericsson AB
 * By Balint Reczey <balint.reczey@ericsson.com>
 *
 * most functions are copied from ui/gtk/rtp_stream.c and ui/gtk/rtp_analysis.c
 * Copyright 2003, Alcatel Business Systems
 * By Lars Ruoff <lars.ruoff@gmx.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include <math.h>
#include "globals.h"

#include <string.h>
#include <epan/rtp_pt.h>
#include <epan/addr_resolv.h>
#include <epan/proto_data.h>
#include <epan/dissectors/packet-rtp.h>
#include <wsutil/pint.h>
#include "rtp_stream.h"
#include "tap-rtp-common.h"
#include "tap-rtp-analysis.h"

typedef struct _key_value {
    guint32  key;
    guint32  value;
} key_value;


/* RTP sampling clock rates for fixed payload types as defined in
 https://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml */
static const key_value clock_map[] = {
    {PT_PCMU,       8000},
    {PT_1016,       8000},
    {PT_G721,       8000},
    {PT_GSM,        8000},
    {PT_G723,       8000},
    {PT_DVI4_8000,  8000},
    {PT_DVI4_16000, 16000},
    {PT_LPC,        8000},
    {PT_PCMA,       8000},
    {PT_G722,       8000},
    {PT_L16_STEREO, 44100},
    {PT_L16_MONO,   44100},
    {PT_QCELP,      8000},
    {PT_CN,         8000},
    {PT_MPA,        90000},
    {PT_G728,       8000},
    {PT_G728,       8000},
    {PT_DVI4_11025, 11025},
    {PT_DVI4_22050, 22050},
    {PT_G729,       8000},
    {PT_CN_OLD,     8000},
    {PT_CELB,       90000},
    {PT_JPEG,       90000},
    {PT_NV,         90000},
    {PT_H261,       90000},
    {PT_MPV,        90000},
    {PT_MP2T,       90000},
    {PT_H263,       90000},
};

#define NUM_CLOCK_VALUES (sizeof clock_map / sizeof clock_map[0])

static guint32
get_clock_rate(guint32 key)
{
    size_t i;

    for (i = 0; i < NUM_CLOCK_VALUES; i++) {
        if (clock_map[i].key == key)
            return clock_map[i].value;
    }
    return 0;
}

typedef struct _mimetype_and_clock {
    const gchar   *pt_mime_name_str;
    guint32 value;
} mimetype_and_clock;
/* RTP sampling clock rates for
  "In addition to the RTP payload formats (encodings) listed in the RTP
  Payload Types table, there are additional payload formats that do not
  have static RTP payload types assigned but instead use dynamic payload
  type number assignment.  Each payload format is named by a registered
  media subtype"
  https://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml.

  NOTE: Please keep the mimetypes in case insensitive alphabetical order.
*/
static const mimetype_and_clock mimetype_and_clock_map[] = {
    {"AMR",              8000}, /* [RFC4867][RFC3267] */
    {"AMR-WB",          16000}, /* [RFC4867][RFC3267] */
    {"BMPEG",           90000}, /* [RFC2343],[RFC3555] */
    {"BT656",           90000}, /* [RFC2431],[RFC3555] */
    {"DV",              90000}, /* [RFC3189] */
    {"EVRC",             8000}, /* [RFC3558] */
    {"EVRC0",            8000}, /* [RFC4788] */
    {"EVRC1",            8000}, /* [RFC4788] */
    {"EVRCB",            8000}, /* [RFC4788] */
    {"EVRCB0",           8000}, /* [RFC4788] */
    {"EVRCB1",           8000}, /* [RFC4788] */
    {"EVRCWB",          16000}, /* [RFC5188] */
    {"EVRCWB0",         16000}, /* [RFC5188] */
    {"EVRCWB1",         16000}, /* [RFC5188] */
    {"EVS",             16000}, /* [3GPP TS 26.445] */
    {"G7221",           16000}, /* [RFC3047] */
    {"G726-16",          8000}, /* [RFC3551][RFC4856] */
    {"G726-24",          8000}, /* [RFC3551][RFC4856] */
    {"G726-32",          8000}, /* [RFC3551][RFC4856] */
    {"G726-40",          8000}, /* [RFC3551][RFC4856] */
    {"G729D",            8000}, /* [RFC3551][RFC4856] */
    {"G729E",            8000}, /* [RFC3551][RFC4856] */
    {"GSM-EFR",          8000}, /* [RFC3551] */
    {"H263-1998",       90000}, /* [RFC2429],[RFC3555] */
    {"H263-2000",       90000}, /* [RFC2429],[RFC3555] */
    {"H264",            90000}, /* [RFC3984] */
    {"MP1S",            90000}, /* [RFC2250],[RFC3555] */
    {"MP2P",            90000}, /* [RFC2250],[RFC3555] */
    {"MP4V-ES",         90000}, /* [RFC3016] */
    {"mpa-robust",      90000}, /* [RFC3119] */
    {"pointer",         90000}, /* [RFC2862] */
    {"raw",             90000}, /* [RFC4175] */
    {"red",              1000}, /* [RFC4102] */
    {"SMV",              8000}, /* [RFC3558] */
    {"SMV0",             8000}, /* [RFC3558] */
    {"t140",             1000}, /* [RFC4103] */
    {"telephone-event",  8000}, /* [RFC4733] */
};

#define NUM_DYN_CLOCK_VALUES (sizeof mimetype_and_clock_map / sizeof mimetype_and_clock_map[0])

static guint32
get_dyn_pt_clock_rate(const gchar *payload_type_str)
{
    int i;

    /* Search for matching mimetype in reverse order to avoid false matches
     * when pt_mime_name_str is the prefix of payload_type_str */
    for (i = NUM_DYN_CLOCK_VALUES - 1; i > -1 ; i--) {
        if (g_ascii_strncasecmp(mimetype_and_clock_map[i].pt_mime_name_str,payload_type_str,(strlen(mimetype_and_clock_map[i].pt_mime_name_str))) == 0)
            return mimetype_and_clock_map[i].value;
    }

    return 0;
}

/****************************************************************************/
void
rtppacket_analyse(tap_rtp_stat_t *statinfo,
                       packet_info *pinfo,
                       const struct _rtp_info *rtpinfo)
{
    double current_time;
    double current_jitter;
    double current_diff = 0;
    double nominaltime;
    double arrivaltime;         /* Time relative to start_time */
    double expected_time;
    double absskew;
    guint32 clock_rate;

    /* Store the current time */
    current_time = nstime_to_msec(&pinfo->rel_ts);

    /*  Is this the first packet we got in this direction? */
    if (statinfo->first_packet) {
        /* Save the MAC address of the first RTP frame */
        if( pinfo->dl_src.type == AT_ETHER){
            copy_address(&(statinfo->first_packet_mac_addr), &(pinfo->dl_src));
        }
        statinfo->start_seq_nr = rtpinfo->info_seq_num;
        statinfo->stop_seq_nr = rtpinfo->info_seq_num;
        statinfo->seq_num = rtpinfo->info_seq_num;
        statinfo->start_time = current_time;
        statinfo->timestamp = rtpinfo->info_timestamp;
        statinfo->first_timestamp = rtpinfo->info_timestamp;
        statinfo->time = current_time;
        statinfo->lastnominaltime = 0;
        statinfo->pt = rtpinfo->info_payload_type;
        statinfo->reg_pt = rtpinfo->info_payload_type;
        if (pinfo->net_src.type == AT_IPv6) {
            statinfo->bw_history[statinfo->bw_index].bytes = rtpinfo->info_data_len + 48;
        } else {
            statinfo->bw_history[statinfo->bw_index].bytes = rtpinfo->info_data_len + 28;
        }
        statinfo->bw_history[statinfo->bw_index].time = current_time;
        statinfo->bw_index++;
        if (pinfo->net_src.type == AT_IPv6) {
            statinfo->total_bytes += rtpinfo->info_data_len + 48;
        } else {
            statinfo->total_bytes += rtpinfo->info_data_len + 28;
        }
        statinfo->bandwidth = (double)(statinfo->total_bytes*8)/1000;
        /* Not needed ? initialised to zero? */
        statinfo->delta = 0;
        statinfo->jitter = 0;
        statinfo->diff = 0;

        statinfo->total_nr++;
        statinfo->flags |= STAT_FLAG_FIRST;
        if (rtpinfo->info_marker_set) {
            statinfo->flags |= STAT_FLAG_MARKER;
        }
        statinfo->first_packet_num = pinfo->num;
        statinfo->first_packet = FALSE;
        return;
    }

    /* Reset flags */
    statinfo->flags = 0;
#if 0
    /*According to bug https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=11478
     * this code causes problems. A better solution is needed if there is need for the functionality */
    /* Try to detect duplicated packets due to mirroring/span ports by comparing src MAC addresses.
     * Check for duplicates (src mac differs from first_packet_mac_addr) */
    */
        if( pinfo->dl_src.type == AT_ETHER){
            if(!addresses_equal(&(statinfo->first_packet_mac_addr), &(pinfo->dl_src))){
                statinfo->flags |= STAT_FLAG_DUP_PKT;
                statinfo->delta = current_time-(statinfo->time);
                return;
            }
        }
#endif
    /* When calculating expected rtp packets the seq number can wrap around
     * so we have to count the number of cycles
     * Variable cycles counts the wraps around in forwarding connection and
     * under is flag that indicates where we are
     *
     * XXX How to determine number of cycles with all possible lost, late
     * and duplicated packets without any doubt? It seems to me, that
     * because of all possible combination of late, duplicated or lost
     * packets, this can only be more or less good approximation
     *
     * There are some combinations (rare but theoretically possible),
     * where below code won't work correctly - statistic may be wrong then.
     */

    /* So if the current sequence number is less than the start one
     * we assume, that there is another cycle running
     */
    if ((rtpinfo->info_seq_num < statinfo->start_seq_nr) && (statinfo->under == FALSE)){
        statinfo->cycles++;
        statinfo->under = TRUE;
    }
    /* what if the start seq nr was 0? Then the above condition will never
     * be true, so we add another condition. XXX The problem would arise
     * if one of the packets with seq nr 0 or 65535 would be lost or late
     */
    else if ((rtpinfo->info_seq_num == 0) && (statinfo->stop_seq_nr == 65535) &&
            (statinfo->under == FALSE)) {
        statinfo->cycles++;
        statinfo->under = TRUE;
    }
    /* the whole round is over, so reset the flag */
    else if ((rtpinfo->info_seq_num > statinfo->start_seq_nr) && (statinfo->under != FALSE)) {
        statinfo->under = FALSE;
    }

    /* Since it is difficult to count lost, duplicate or late packets separately,
     * we would like to know at least how many times the sequence number was not ok
     */

    /* If the current seq number equals the last one or if we are here for
     * the first time, then it is ok, we just store the current one as the last one
     */
    if ( (statinfo->seq_num+1 == rtpinfo->info_seq_num) || (statinfo->flags & STAT_FLAG_FIRST) )
        statinfo->seq_num = rtpinfo->info_seq_num;
    /* If the first one is 65535 we wrap */
    else if ( (statinfo->seq_num == 65535) && (rtpinfo->info_seq_num == 0) )
        statinfo->seq_num = rtpinfo->info_seq_num;
    /* Lost packets. If the prev seq is enormously larger than the cur seq
     * we assume that instead of being massively late we lost the packet(s)
     * that would have indicated the sequence number wrapping. An imprecise
     * heuristic at best, but it seems to work well enough.
     * https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5958 */
    else if (statinfo->seq_num+1 < rtpinfo->info_seq_num || statinfo->seq_num - rtpinfo->info_seq_num > 0xFF00) {
        statinfo->seq_num = rtpinfo->info_seq_num;
        statinfo->sequence++;
        statinfo->flags |= STAT_FLAG_WRONG_SEQ;
    }
    /* Late or duplicated */
    else if (statinfo->seq_num+1 > rtpinfo->info_seq_num) {
        statinfo->sequence++;
        statinfo->flags |= STAT_FLAG_WRONG_SEQ;
    }

    /* Check payload type */
    if (rtpinfo->info_payload_type == PT_CN
            || rtpinfo->info_payload_type == PT_CN_OLD)
        statinfo->flags |= STAT_FLAG_PT_CN;
    if (statinfo->pt == PT_CN
            || statinfo->pt == PT_CN_OLD)
        statinfo->flags |= STAT_FLAG_FOLLOW_PT_CN;
    if (rtpinfo->info_payload_type != statinfo->pt)
        statinfo->flags |= STAT_FLAG_PT_CHANGE;
    statinfo->pt = rtpinfo->info_payload_type;

    /*
     * Return for unknown payload types
     * Ignore jitter calculation for clockrate = 0
     */
    if (statinfo->pt < 96 ){
        clock_rate = get_clock_rate(statinfo->pt);
    } else { /* Dynamic PT */
        if ( rtpinfo->info_payload_type_str != NULL ) {
            /* Is it a "telephone-event" ?
             * Timestamp is not increased for telepone-event packets impacting
             * calculation of Jitter Skew and clock drift.
             * see 2.2.1 of RFC 4733
             */
            if (g_ascii_strncasecmp("telephone-event",rtpinfo->info_payload_type_str,(strlen("telephone-event")))==0) {
                clock_rate = 0;
                statinfo->flags |= STAT_FLAG_PT_T_EVENT;
            } else {
                if(rtpinfo->info_payload_rate !=0) {
                    clock_rate = rtpinfo->info_payload_rate;
                } else {
                    clock_rate = get_dyn_pt_clock_rate(rtpinfo->info_payload_type_str);
                }
            }
        } else {
            clock_rate = 0;
        }
    }

    /* Handle wraparound ? */
    arrivaltime = current_time - statinfo->start_time;

    nominaltime = (double)(guint32_wraparound_diff(rtpinfo->info_timestamp, statinfo->first_timestamp));

    /* Can only analyze defined sampling rates */
    if (clock_rate != 0) {
        statinfo->clock_rate = clock_rate;
        /* Convert from sampling clock to ms */
        nominaltime = nominaltime /(clock_rate/1000);

        /* Calculate the current jitter(in ms) */
        if (!statinfo->first_packet) {
            expected_time = statinfo->time + (nominaltime - statinfo->lastnominaltime);
            current_diff = fabs(current_time - expected_time);
            current_jitter = (15 * statinfo->jitter + current_diff) / 16;

            statinfo->delta = current_time-(statinfo->time);
            statinfo->jitter = current_jitter;
            statinfo->diff = current_diff;
        }
        statinfo->lastnominaltime = nominaltime;
        /* Calculate skew, i.e. absolute jitter that also catches clock drift
         * Skew is positive if TS (nominal) is too fast
         */
        statinfo->skew    = nominaltime - arrivaltime;
        absskew = fabs(statinfo->skew);
        if(absskew > fabs(statinfo->max_skew)) {
            statinfo->max_skew = statinfo->skew;
        }
        /* Gather data for calculation of average, minimum and maximum framerate based on timestamp */
#if 0
        if (numPackets > 0 && (!hardPayloadType || !alternatePayloadType)) {
            /* Skip first packet and possibly alternate payload type packets */
            double dt;
            dt     = nominaltime - statinfo->lastnominaltime;
            sumdt += 1.0 * dt;
            numdt += (dt != 0 ? 1 : 0);
            mindt  = (dt < mindt ? dt : mindt);
            maxdt  = (dt > maxdt ? dt : maxdt);
        }
#endif
        /* Gather data for calculation of skew least square */
        statinfo->sumt   += 1.0 * arrivaltime;
        statinfo->sumTS  += 1.0 * nominaltime;
        statinfo->sumt2  += 1.0 * arrivaltime * arrivaltime;
        statinfo->sumtTS += 1.0 * arrivaltime * nominaltime;
    } else {
        if (!statinfo->first_packet) {
            statinfo->delta = current_time-(statinfo->time);
        }
    }

    /* Calculate the BW in Kbps adding the IP+UDP header to the RTP -> 20bytes(IP) + 8bytes(UDP) */
    if (pinfo->net_src.type == AT_IPv6) {
        statinfo->bw_history[statinfo->bw_index].bytes = rtpinfo->info_data_len + 48;
    } else {
        statinfo->bw_history[statinfo->bw_index].bytes = rtpinfo->info_data_len + 28;
    }
    statinfo->bw_history[statinfo->bw_index].time = current_time;

    /* Check if there are more than 1sec in the history buffer to calculate BW in bps. If so, remove those for the calculation */
    while ((statinfo->bw_history[statinfo->bw_start_index].time+1000/* ms */)<current_time){
        statinfo->total_bytes -= statinfo->bw_history[statinfo->bw_start_index].bytes;
        statinfo->bw_start_index++;
        if (statinfo->bw_start_index == BUFF_BW) statinfo->bw_start_index=0;
    };
    /* IP hdr + UDP + RTP */
    if (pinfo->net_src.type == AT_IPv6){
        statinfo->total_bytes += rtpinfo->info_data_len + 48;
    }else{
        statinfo->total_bytes += rtpinfo->info_data_len + 28;
    }
    statinfo->bandwidth = (double)(statinfo->total_bytes*8)/1000;
    statinfo->bw_index++;
    if (statinfo->bw_index == BUFF_BW) statinfo->bw_index = 0;


    /* Used by GTK code only */
    statinfo->delta_timestamp = guint32_wraparound_diff(rtpinfo->info_timestamp, statinfo->timestamp);

    /* Is it a packet with the mark bit set? */
    if (rtpinfo->info_marker_set) {
        statinfo->flags |= STAT_FLAG_MARKER;
    }

    /* Difference can be negative. We don't expect difference bigger than 31 bits. Difference don't care about wrap around. */
    gint32 tsdelta=rtpinfo->info_timestamp - statinfo->timestamp;
    if (tsdelta < 0) {
        statinfo->flags |= STAT_FLAG_WRONG_TIMESTAMP;
    }
    /* Is it a regular packet? */
    if (!(statinfo->flags & STAT_FLAG_FIRST)
            && !(statinfo->flags & STAT_FLAG_MARKER)
            && !(statinfo->flags & STAT_FLAG_PT_CN)
            && !(statinfo->flags & STAT_FLAG_WRONG_TIMESTAMP)
            && !(statinfo->flags & STAT_FLAG_FOLLOW_PT_CN)) {
        /* Include it in maximum delta calculation */
        if (statinfo->delta > statinfo->max_delta) {
            statinfo->max_delta = statinfo->delta;
            statinfo->max_nr = pinfo->num;
        }
        if (clock_rate != 0) {
            /* Maximum and mean jitter calculation */
            if (statinfo->jitter > statinfo->max_jitter) {
                statinfo->max_jitter = statinfo->jitter;
            }
            statinfo->mean_jitter = (statinfo->mean_jitter*statinfo->total_nr + current_diff) / (statinfo->total_nr+1);
        }
    }
    /* Regular payload change? (CN ignored) */
    if (!(statinfo->flags & STAT_FLAG_FIRST)
            && !(statinfo->flags & STAT_FLAG_PT_CN)) {
        if ((statinfo->pt != statinfo->reg_pt)
                && (statinfo->reg_pt != PT_UNDEFINED)) {
            statinfo->flags |= STAT_FLAG_REG_PT_CHANGE;
        }
    }

    /* Set regular payload*/
    if (!(statinfo->flags & STAT_FLAG_PT_CN)) {
        statinfo->reg_pt = statinfo->pt;
    }

    statinfo->time = current_time;
    statinfo->timestamp = rtpinfo->info_timestamp;
    statinfo->stop_seq_nr = rtpinfo->info_seq_num;
    statinfo->total_nr++;
    statinfo->last_payload_len = rtpinfo->info_payload_len - rtpinfo->info_padding_count;

    return;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */

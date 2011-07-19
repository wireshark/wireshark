/* tap-rlclte_stat.c
 * Copyright 2011 Martin Mathieson
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>
#include <epan/packet.h>
#include <epan/packet_info.h>
#include <epan/tap.h>
#include <epan/stat_cmd_args.h>
#include <epan/dissectors/packet-rlc-lte.h>


enum {
    UEID_COLUMN,
    UL_FRAMES_COLUMN,
    UL_BYTES_COLUMN,
    UL_BW_COLUMN,
    UL_ACKS_COLUMN,
    UL_NACKS_COLUMN,
    UL_MISSING_COLUMN,
    DL_FRAMES_COLUMN,
    DL_BYTES_COLUMN,
    DL_BW_COLUMN,
    DL_ACKS_COLUMN,
    DL_NACKS_COLUMN,
    DL_MISSING_COLUMN,
    NUM_UE_COLUMNS
};

static const gchar *ue_titles[] = { " UEId",
                                    "UL Frames", "UL Bytes", "   UL Mbs", "UL ACKs", "UL NACKs", "UL Missed",
                                    "DL Frames", "DL Bytes", "   DL Mbs", "UL ACKs", "DL NACKs", "DL Missed"};

/* Stats for one UE */
typedef struct rlc_lte_row_data {
    /* Key for matching this row */
    guint16  ueid;

    gboolean is_predefined_data;

    guint32  UL_frames;
    guint32  UL_total_bytes;
    nstime_t UL_time_start;
    nstime_t UL_time_stop;
    guint32  UL_total_acks;
    guint32  UL_total_nacks;
    guint32  UL_total_missing;

    guint32  DL_frames;
    guint32  DL_total_bytes;
    nstime_t DL_time_start;
    nstime_t DL_time_stop;
    guint32  DL_total_acks;
    guint32  DL_total_nacks;
    guint32  DL_total_missing;

} rlc_lte_row_data;


/* Common channel stats */
typedef struct rlc_lte_common_stats {
    guint32 bcch_frames;
    guint32 bcch_bytes;
    guint32 pcch_frames;
    guint32 pcch_bytes;
} rlc_lte_common_stats;


/* One row/UE in the UE table */
typedef struct rlc_lte_ep {
    struct rlc_lte_ep* next;
    struct rlc_lte_row_data stats;
} rlc_lte_ep_t;


/* Used to keep track of all RLC LTE statistics */
typedef struct rlc_lte_stat_t {
    rlc_lte_ep_t  *ep_list;
    guint32       total_frames;

    /* Common stats */
    rlc_lte_common_stats common_stats;
} rlc_lte_stat_t;



/* Reset RLC stats */
static void
rlc_lte_stat_reset(void *phs)
{
    rlc_lte_stat_t* rlc_lte_stat = (rlc_lte_stat_t *)phs;
    rlc_lte_ep_t* list = rlc_lte_stat->ep_list;

    rlc_lte_stat->total_frames = 0;
    memset(&rlc_lte_stat->common_stats, 0, sizeof(rlc_lte_common_stats));

    if (!list) {
        return;
    }

    rlc_lte_stat->ep_list = NULL;
}


/* Allocate a rlc_lte_ep_t struct to store info for new UE */
static rlc_lte_ep_t* alloc_rlc_lte_ep(struct rlc_lte_tap_info *si, packet_info *pinfo _U_)
{
    rlc_lte_ep_t* ep;

    if (!si) {
        return NULL;
    }

    if (!(ep = g_malloc(sizeof(rlc_lte_ep_t)))) {
        return NULL;
    }

    /* Copy SI data into ep->stats */
    ep->stats.ueid = si->ueid;

    /* Counts for new UE are all 0 */
    ep->stats.UL_frames = 0;
    ep->stats.DL_frames = 0;
    ep->stats.UL_total_bytes = 0;
    ep->stats.DL_total_bytes = 0;
    memset(&ep->stats.DL_time_start, 0, sizeof(nstime_t));
    memset(&ep->stats.DL_time_stop, 0, sizeof(nstime_t));
    ep->stats.UL_total_nacks = 0;
    ep->stats.DL_total_nacks = 0;
    ep->stats.UL_total_missing = 0;
    ep->stats.DL_total_missing = 0;

    return ep;
}


/* Process stat struct for a RLC LTE frame */
static int
rlc_lte_stat_packet(void *phs, packet_info *pinfo, epan_dissect_t *edt _U_,
                    const void *phi)
{
    /* Get reference to stats struct */
    rlc_lte_stat_t *hs = (rlc_lte_stat_t *)phs;
    rlc_lte_ep_t *tmp = NULL, *te = NULL;

    /* Cast tap info struct */
    struct rlc_lte_tap_info *si = (struct rlc_lte_tap_info *)phi;

    /* Need this */
    if (!hs) {
        return 0;
    }

    /* Inc top-level frame count */
    hs->total_frames++;

    /* Common channel stats */
    switch (si->channelType) {
        case CHANNEL_TYPE_BCCH_BCH:
        case CHANNEL_TYPE_BCCH_DL_SCH:
            hs->common_stats.bcch_frames++;
            hs->common_stats.bcch_bytes += si->pduLength;
            return 1;

        case CHANNEL_TYPE_PCCH:
            hs->common_stats.pcch_frames++;
            hs->common_stats.pcch_bytes += si->pduLength;
            return 1;

        default:
            break;
    }

    /* For per-UE data, must create a new row if none already existing */
    if (!hs->ep_list) {
        /* Allocate new list */
        hs->ep_list = alloc_rlc_lte_ep(si, pinfo);
        /* Make it the first/only entry */
        te = hs->ep_list;
    } else {
        /* Look among existing rows for this UEId */
        for (tmp = hs->ep_list; (tmp != NULL); tmp = tmp->next) {
            if (tmp->stats.ueid == si->ueid) {
                te = tmp;
                break;
            }
        }

        /* Not found among existing, so create a new one anyway */
        if (te == NULL) {
            if ((te = alloc_rlc_lte_ep(si, pinfo))) {
                /* Add new item to end of list */
                rlc_lte_ep_t *p = hs->ep_list;
                while (p->next) {
                    p = p->next;
                }
                p->next = te;
                te->next = NULL;
            }
        }
    }

    /* Really should have a row pointer by now */
    if (!te) {
        return 0;
    }

    /* Update entry with details from si */
    te->stats.ueid = si->ueid;

    /* Top-level traffic stats */
    if (si->direction == DIRECTION_UPLINK) {
        /* Update time range */
        if (te->stats.UL_frames == 0) {
            te->stats.UL_time_start = si->time;
        }
        te->stats.UL_time_stop = si->time;

        te->stats.UL_frames++;
        te->stats.UL_total_bytes += si->pduLength;
    }
    else {
        /* Update time range */
        if (te->stats.DL_frames == 0) {
            te->stats.DL_time_start = si->time;
        }
        te->stats.DL_time_stop = si->time;

        te->stats.DL_frames++;
        te->stats.DL_total_bytes += si->pduLength;
    }


    if (si->direction == DIRECTION_UPLINK) {
        if (si->isControlPDU) {
            te->stats.UL_total_acks++;
        }
        te->stats.UL_total_nacks += si->noOfNACKs;
        te->stats.UL_total_missing += si->missingSNs;
    }
    else {
        if (si->isControlPDU) {
            te->stats.DL_total_acks++;
        }
        te->stats.DL_total_nacks += si->noOfNACKs;
        te->stats.DL_total_missing += si->missingSNs;
    }

    return 1;
}


/* Calculate and return a bandwidth figure, in Mbs */
static float calculate_bw(nstime_t *start_time, nstime_t *stop_time, guint32 bytes)
{
    if (memcmp(start_time, stop_time, sizeof(nstime_t)) != 0) {
        float elapsed_ms = (((float)stop_time->secs - (float)start_time->secs) * 1000) +
                           (((float)stop_time->nsecs - (float)start_time->nsecs) / 1000000);
        return ((bytes * 8) / elapsed_ms) / 1000;
    }
    else {
        return 0.0;
    }
}




/* (Re)draw RLC stats */
static void
rlc_lte_stat_draw(void *phs)
{
    guint16 number_of_ues = 0;
    gint i;

    /* Look up the statistics struct */
    rlc_lte_stat_t *hs = (rlc_lte_stat_t *)phs;
    rlc_lte_ep_t* list = hs->ep_list, *tmp = 0;

    /* Common channel data */
    printf("Common Data:\n");
    printf("==============\n");
    printf("BCCH Frames: %u   BCCH Bytes: %u   PCCH Frames: %u   PCCH Bytes: %u\n\n",
           hs->common_stats.bcch_frames, hs->common_stats.bcch_bytes,
           hs->common_stats.pcch_frames, hs->common_stats.pcch_bytes);

    /* Per-UE table entries */
    

    /* Set title that shows how many UEs currently in table */
    for (tmp = list; (tmp!=NULL); tmp=tmp->next, number_of_ues++);
    printf("Per UE Data - %u UEs (%u frames)\n", number_of_ues, hs->total_frames);
    printf("==========================================\n");

    /* Show column titles */
    for (i=0; i < NUM_UE_COLUMNS; i++) {
        printf("%s  ", ue_titles[i]);
    }
    printf("\n");

    /* For each row/UE in the model */
    for (tmp = list; tmp; tmp=tmp->next) {
        /* Calculate bandwidth */
        float UL_bw = calculate_bw(&tmp->stats.UL_time_start,
                                   &tmp->stats.UL_time_stop,
                                   tmp->stats.UL_total_bytes);
        float DL_bw = calculate_bw(&tmp->stats.DL_time_start,
                                   &tmp->stats.DL_time_stop,
                                   tmp->stats.DL_total_bytes);

        printf("%5u %10u %9u %10f %8u %9u %10u %10u %9u %10f %8u %9u %10u\n",
               tmp->stats.ueid,
               tmp->stats.UL_frames,
               tmp->stats.UL_total_bytes, UL_bw,
               tmp->stats.UL_total_acks,
               tmp->stats.UL_total_nacks,
               tmp->stats.UL_total_missing,
               tmp->stats.DL_frames,
               tmp->stats.DL_total_bytes, DL_bw,
               tmp->stats.DL_total_acks,
               tmp->stats.DL_total_nacks,
               tmp->stats.DL_total_missing);
    }
}




/* Create a new RLC LTE stats struct */
static void rlc_lte_stat_init(const char *optarg, void *userdata _U_)
{
    rlc_lte_stat_t    *hs;
    const char        *filter = NULL;
    GString           *error_string;

    /* Check for a filter string */
    if (strncmp(optarg, "rlc-lte,stat,", 13) == 0) {
        /* Skip those characters from filter to display */
        filter = optarg + 13;
    }
    else {
        /* No filter */
        filter = NULL;
    }

    /* Create top-level struct */
    hs = g_malloc(sizeof(rlc_lte_stat_t));
    memset(hs, 0,  sizeof(rlc_lte_stat_t));
    hs->ep_list = NULL;


    /**********************************************/
    /* Register the tap listener                  */
    /**********************************************/

    error_string = register_tap_listener("rlc-lte", hs,
                                         filter, 0,
                                         rlc_lte_stat_reset,
                                         rlc_lte_stat_packet,
                                         rlc_lte_stat_draw);
    if (error_string) {
        g_string_free(error_string, TRUE);
        g_free(hs);
        exit(1);
    }

}


/* Register this tap listener (need void on own so line register function found) */
void
register_tap_listener_rlc_lte_stat(void)
{
    register_stat_cmd_arg("rlc-lte,stat", rlc_lte_stat_init, NULL);
}


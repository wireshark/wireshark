/* tap-macltestat.c
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
#include <epan/dissectors/packet-mac-lte.h>

/**********************************************/
/* Table column identifiers and title strings */

enum {
    RNTI_COLUMN,
    RNTI_TYPE_COLUMN,
    UEID_COLUMN,
    UL_FRAMES_COLUMN,
    UL_BYTES_COLUMN,
    UL_BW_COLUMN,
    UL_PADDING_PERCENT_COLUMN,
    UL_RETX_FRAMES_COLUMN,
    DL_FRAMES_COLUMN,
    DL_BYTES_COLUMN,
    DL_BW_COLUMN,
    DL_CRC_FAILED_COLUMN,
    DL_CRC_HIGH_CODE_RATE_COLUMN,
    DL_CRC_PDSCH_LOST_COLUMN,
    DL_RETX_FRAMES_COLUMN,
    NUM_UE_COLUMNS
};


static const gchar *ue_titles[] = { " RNTI", "  Type", "UEId",
                                    "UL Frames", "UL Bytes", "UL Mb/sec", " UL Pad %", "UL ReTX",
                                    "DL Frames", "DL Bytes", "DL Mb/sec", "DL CRC Fail", "DL CRC HCR", "DL CRC PDSCH Lost", "DL ReTX"};


/* Stats for one UE */
typedef struct mac_lte_row_data {
    /* Key for matching this row */
    guint16  rnti;
    guint8   rnti_type;
    guint16  ueid;

    gboolean is_predefined_data;

    guint32  UL_frames;
    guint32  UL_raw_bytes;   /* all bytes */
    guint32  UL_total_bytes; /* payload */
    nstime_t UL_time_start;
    nstime_t UL_time_stop;
    guint32  UL_padding_bytes;
    guint32  UL_CRC_errors;
    guint32  UL_retx_frames;

    guint32  DL_frames;
    guint32  DL_total_bytes;
    nstime_t DL_time_start;
    nstime_t DL_time_stop;
    guint32  DL_CRC_failures;
    guint32  DL_CRC_high_code_rate;
    guint32  DL_CRC_PDSCH_lost;
    guint32  DL_retx_frames;

} mac_lte_row_data;


/* One row/UE in the UE table */
typedef struct mac_lte_ep {
    struct mac_lte_ep* next;
    struct mac_lte_row_data stats;
} mac_lte_ep_t;


/* Common channel stats */
typedef struct mac_lte_common_stats {
    guint32 all_frames;
    guint32 bch_frames;
    guint32 bch_bytes;
    guint32 pch_frames;
    guint32 pch_bytes;
    guint32 rar_frames;
    guint32 rar_entries;

    guint16  max_ul_ues_in_tti;
    guint16  max_dl_ues_in_tti;
} mac_lte_common_stats;


/* Top-level struct for MAC LTE statistics */
typedef struct mac_lte_stat_t {
    /* Common stats */
    mac_lte_common_stats common_stats;

    /* Keep track of unique rntis & ueids */
    guint8 used_ueids[65535];
    guint8 used_rntis[65535];
    guint16 number_of_ueids;
    guint16 number_of_rntis;

    mac_lte_ep_t  *ep_list;
} mac_lte_stat_t;


/* Reset the statistics window */
static void
mac_lte_stat_reset(void *phs)
{
    mac_lte_stat_t* mac_lte_stat = (mac_lte_stat_t *)phs;
    mac_lte_ep_t* list = mac_lte_stat->ep_list;

    /* Reset counts of unique ueids & rntis */
    memset(mac_lte_stat->used_ueids, 0, 65535);
    mac_lte_stat->number_of_ueids = 0;
    memset(mac_lte_stat->used_rntis, 0, 65535);
    mac_lte_stat->number_of_rntis = 0;

    /* Zero common stats */
    memset(&(mac_lte_stat->common_stats), 0, sizeof(mac_lte_common_stats));

    if (!list) {
        return;
    }

    mac_lte_stat->ep_list = NULL;
}


/* Allocate a mac_lte_ep_t struct to store info for new UE */
static mac_lte_ep_t* alloc_mac_lte_ep(struct mac_lte_tap_info *si, packet_info *pinfo _U_)
{
    mac_lte_ep_t* ep;

    if (!si) {
        return NULL;
    }

    if (!(ep = g_malloc(sizeof(mac_lte_ep_t)))) {
        return NULL;
    }

    /* Copy SI data into ep->stats */
    ep->stats.rnti = si->rnti;
    ep->stats.rnti_type = si->rntiType;
    ep->stats.ueid = si->ueid;

    /* Counts for new UE are all 0 */
    ep->stats.UL_frames = 0;
    ep->stats.DL_frames = 0;
    ep->stats.UL_total_bytes = 0;
    ep->stats.UL_raw_bytes = 0;
    ep->stats.UL_padding_bytes = 0;
    ep->stats.DL_total_bytes = 0;
    ep->stats.UL_CRC_errors = 0;
    ep->stats.DL_CRC_failures = 0;
    ep->stats.DL_CRC_high_code_rate = 0;
    ep->stats.DL_CRC_PDSCH_lost = 0;
    ep->stats.UL_retx_frames = 0;
    ep->stats.DL_retx_frames = 0;

    ep->next = NULL;

    return ep;
}


/* Update counts of unique rntis & ueids */
static void update_ueid_rnti_counts(guint16 rnti, guint16 ueid, mac_lte_stat_t *hs)
{
    if (!hs->used_ueids[ueid]) {
        hs->used_ueids[ueid] = TRUE;
        hs->number_of_ueids++;
    }
    if (!hs->used_rntis[rnti]) {
        hs->used_rntis[rnti] = TRUE;
        hs->number_of_rntis++;
    }
}


/* Process stat struct for a MAC LTE frame */
static int
mac_lte_stat_packet(void *phs, packet_info *pinfo, epan_dissect_t *edt _U_,
                    const void *phi)
{
    /* Get reference to stat window instance */
    mac_lte_stat_t *hs = (mac_lte_stat_t *)phs;
    mac_lte_ep_t *tmp = NULL, *te = NULL;

    /* Cast tap info struct */
    struct mac_lte_tap_info *si = (struct mac_lte_tap_info *)phi;

    if (!hs) {
        return 0;
    }

    hs->common_stats.all_frames++;

    /* For common channels, just update global counters */
    switch (si->rntiType) {
        case P_RNTI:
            hs->common_stats.pch_frames++;
            hs->common_stats.pch_bytes += si->single_number_of_bytes;
            return 1;
        case SI_RNTI:
        case NO_RNTI:
            hs->common_stats.bch_frames++;
            hs->common_stats.bch_bytes += si->single_number_of_bytes;
            return 1;
        case RA_RNTI:
            hs->common_stats.rar_frames++;
            hs->common_stats.rar_entries += si->number_of_rars;
            return 1;
        case C_RNTI:
        case SPS_RNTI:
            /* Drop through for per-UE update */
            break;

        default:
            /* Error */
            return 0;
    }

    /* Check max UEs/tti counter */
    switch (si->direction) {
        case DIRECTION_UPLINK:
            hs->common_stats.max_ul_ues_in_tti =
                MAX(hs->common_stats.max_ul_ues_in_tti, si->ueInTTI);
            break;
        case DIRECTION_DOWNLINK:
            hs->common_stats.max_dl_ues_in_tti =
                MAX(hs->common_stats.max_dl_ues_in_tti, si->ueInTTI);
            break;
    }

    /* For per-UE data, must create a new row if none already existing */
    if (!hs->ep_list) {
        /* Allocate new list */
        hs->ep_list = alloc_mac_lte_ep(si, pinfo);
        /* Make it the first/only entry */
        te = hs->ep_list;

        /* Update counts of unique ueids & rntis */
        update_ueid_rnti_counts(si->rnti, si->ueid, hs);
    } else {
        /* Look among existing rows for this RNTI */
        for (tmp = hs->ep_list;(tmp != NULL); tmp = tmp->next) {
            /* Match only by RNTI and UEId together */
            if ((tmp->stats.rnti == si->rnti) &&
                (tmp->stats.ueid == si->ueid)){
                te = tmp;
                break;
            }
        }

        /* Not found among existing, so create a new one anyway */
        if (te == NULL) {
            if ((te = alloc_mac_lte_ep(si, pinfo))) {
                /* Add new item to end of list */
                mac_lte_ep_t *p = hs->ep_list;
                while (p->next) {
                    p = p->next;
                }
                p->next = te;
                te->next = NULL;

                /* Update counts of unique ueids & rntis */
                update_ueid_rnti_counts(si->rnti, si->ueid, hs);
            }
        }
    }

    /* Really should have a row pointer by now */
    if (!te) {
        return 0;
    }

    /* Update entry with details from si */
    te->stats.rnti = si->rnti;
    te->stats.is_predefined_data = si->isPredefinedData;

    /* Uplink */
    if (si->direction == DIRECTION_UPLINK) {
        if (si->isPHYRetx) {
            te->stats.UL_retx_frames++;
            return 1;
        }

        if (si->crcStatusValid && (si->crcStatus != crc_success)) {
            te->stats.UL_CRC_errors++;
            return 1;
        }

        /* Update time range */
        if (te->stats.UL_frames == 0) {
            te->stats.UL_time_start = si->time;
        }
        te->stats.UL_time_stop = si->time;

        te->stats.UL_frames++;

        te->stats.UL_raw_bytes += si->raw_length;
        te->stats.UL_padding_bytes += si->padding_bytes;

        if (si->isPredefinedData) {
            te->stats.UL_total_bytes += si->single_number_of_bytes;
        }
        else {
            te->stats.UL_total_bytes += si->single_number_of_bytes;
        }
    }

    /* Downlink */
    else {
        if (si->isPHYRetx) {
            te->stats.DL_retx_frames++;
            return 1;
        }

        if (si->crcStatusValid && (si->crcStatus != crc_success)) {
            switch (si->crcStatus) {
                case crc_fail:
                    te->stats.DL_CRC_failures++;
                    break;
                case crc_high_code_rate:
                    te->stats.DL_CRC_high_code_rate++;
                    break;
                case crc_pdsch_lost:
                    te->stats.DL_CRC_PDSCH_lost++;
                    break;
                default:
                    /* Something went wrong! */
                    break;
            }
            return 1;
        }

        /* Update time range */
        if (te->stats.DL_frames == 0) {
            te->stats.DL_time_start = si->time;
        }
        te->stats.DL_time_stop = si->time;

        te->stats.DL_frames++;

        if (si->isPredefinedData) {
            te->stats.DL_total_bytes += si->single_number_of_bytes;
        }
        else {
            te->stats.DL_total_bytes += si->single_number_of_bytes;
        }

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


/* Output the accumulated stats */
static void
mac_lte_stat_draw(void *phs)
{
    gint i;
    guint16 number_of_ues = 0;

    /* Deref the struct */
    mac_lte_stat_t *hs = (mac_lte_stat_t *)phs;
    mac_lte_ep_t* list = hs->ep_list, *tmp = 0;

    /* System data */
    printf("System data:\n");
    printf("============\n");
    printf("Max UL UEs/TTI: %u     Max DL UEs/TTI: %u\n\n",
           hs->common_stats.max_ul_ues_in_tti, hs->common_stats.max_dl_ues_in_tti);

    /* Common channel data */
    printf("Common channel data:\n");
    printf("====================\n");
    printf("BCH Frames: %u    ", hs->common_stats.bch_frames);
    printf("BCH Bytes: %u    ", hs->common_stats.bch_bytes);
    printf("PCH Frames: %u    ", hs->common_stats.pch_frames);
    printf("PCH Bytes: %u    ", hs->common_stats.pch_bytes);
    printf("RAR Frames: %u    ", hs->common_stats.rar_frames);
    printf("RAR Entries: %u\n\n", hs->common_stats.rar_entries);


    /* Per-UE table entries */

    /* Set title to show how many UEs in table */
    for (tmp = list; (tmp!=NULL); tmp=tmp->next, number_of_ues++);
    printf("UL/DL-SCH data (%u entries - %u unique RNTIs, %u unique UEIds):\n",
           number_of_ues, hs->number_of_rntis, hs->number_of_ueids);
    printf("==================================================================\n");

    /* Show column titles */
    for (i=0; i < NUM_UE_COLUMNS; i++) {
        printf("%s  ", ue_titles[i]);
    }
    printf("\n");

    /* Write a row for each UE */
    for (tmp = list; tmp; tmp=tmp->next) {
        /* Calculate bandwidth */
        float UL_bw = calculate_bw(&tmp->stats.UL_time_start,
                                   &tmp->stats.UL_time_stop,
                                   tmp->stats.UL_total_bytes);
        float DL_bw = calculate_bw(&tmp->stats.DL_time_start,
                                   &tmp->stats.DL_time_stop,
                                   tmp->stats.DL_total_bytes);

        printf("%5u %7s %5u %10u %9u %10f %10f %8u %10u %9u %10f %12u %11u %18u %8u\n",
               tmp->stats.rnti,
               (tmp->stats.rnti_type == C_RNTI) ? "C-RNTI" : "SPS-RNTI",
               tmp->stats.ueid,
               tmp->stats.UL_frames,
               tmp->stats.UL_total_bytes,
               UL_bw,
               tmp->stats.UL_total_bytes ?
                                    (((float)tmp->stats.UL_padding_bytes / (float)tmp->stats.UL_raw_bytes) * 100.0) :
                                    0.0,
               tmp->stats.UL_retx_frames,
               tmp->stats.DL_frames,
               tmp->stats.DL_total_bytes,
               DL_bw,
               tmp->stats.DL_CRC_failures,
               tmp->stats.DL_CRC_high_code_rate,
               tmp->stats.DL_CRC_PDSCH_lost,
               tmp->stats.DL_retx_frames);
    }
}

/* Create a new MAC LTE stats struct */
static void mac_lte_stat_init(const char *optarg, void *userdata _U_)
{
    mac_lte_stat_t    *hs;
    const char    *filter = NULL;
    GString       *error_string;

    /* Check for a filter string */
    if (strncmp(optarg, "mac-lte,stat,", 13) == 0) {
        /* Skip those characters from filter to display */
        filter = optarg + 13;
    }
    else {
        /* No filter */
        filter = NULL;
    }

    /* Create struct */
    hs = g_malloc(sizeof(mac_lte_stat_t));
    hs->ep_list = NULL;

    error_string = register_tap_listener("mac-lte", hs,
                                         filter, 0,
                                         mac_lte_stat_reset,
                                         mac_lte_stat_packet,
                                         mac_lte_stat_draw);
    if (error_string) {
        g_string_free(error_string, TRUE);
        g_free(hs);
        exit(1);
    }
}


/* Register this tap listener (need void on own so line register function found) */
void
register_tap_listener_mac_lte_stat(void)
{
    register_stat_cmd_arg("mac-lte,stat", mac_lte_stat_init, NULL);
}


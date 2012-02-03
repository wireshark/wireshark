/* rlc_lte_stat_dlg.c
 * Copyright 2010 Martin Mathieson
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


/* TODO:
   - per-channel graph tap?
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>

#include <gtk/gtk.h>

#include "ui/gtk/gtkglobals.h"

#include <epan/packet.h>
#include <epan/packet_info.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-rlc-lte.h>

#include "ui/simple_dialog.h"
#include "../stat_menu.h"

#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/gui_stat_menu.h"
#include "ui/gtk/tap_param_dlg.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/help_dlg.h"
#include "ui/gtk/main.h"

#include "ui/gtk/old-gtk-compat.h"

/**********************************************/
/* Table column identifiers and title strings */

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
    UE_TABLE_COLUMN,
    NUM_UE_COLUMNS
};

enum {
    CHANNEL_NAME,
    CHANNEL_MODE,
    CHANNEL_PRIORITY,
    CHANNEL_UL_FRAMES,
    CHANNEL_UL_BYTES,
    CHANNEL_UL_BW,
    CHANNEL_UL_ACKS,
    CHANNEL_UL_NACKS,
    CHANNEL_UL_MISSING,
    CHANNEL_DL_FRAMES,
    CHANNEL_DL_BYTES,
    CHANNEL_DL_BW,
    CHANNEL_DL_ACKS,
    CHANNEL_DL_NACKS,
    CHANNEL_DL_MISSING,
    CHANNEL_TABLE_COLUMN,
    NUM_CHANNEL_COLUMNS
};

static const gchar *ue_titles[] = { "UEId",
                                    "UL Frames", "UL Bytes", "UL MBit/sec", "UL ACKs", "UL NACKs", "UL Missing",
                                    "DL Frames", "DL Bytes", "DL MBit/sec", "DL ACKs", "DL NACKs", "DL Missing"};

static const gchar *channel_titles[] = { "", "Mode", "Priority",
                                         "UL Frames", "UL Bytes", "UL MBit/sec", "UL ACKs", "UL NACKs", "UL Missing",
                                         "DL Frames", "DL Bytes", "DL MBit/sec", "DL ACKs", "DL NACKs", "DL Missing"};

/* Stats kept for one channel */
typedef struct rlc_channel_stats {
    guint8   inUse;
    guint8   rlcMode;
    guint8   priority;
    guint16  channelType;
    guint16  channelId;

    guint32  UL_frames;
    guint32  UL_bytes;
    nstime_t UL_time_start;
    nstime_t UL_time_stop;

    guint32  DL_frames;
    guint32  DL_bytes;
    nstime_t DL_time_start;
    nstime_t DL_time_stop;

    guint32  UL_acks;
    guint32  UL_nacks;

    guint32  DL_acks;
    guint32  DL_nacks;

    guint32  UL_missing;
    guint32  DL_missing;

    GtkTreeIter iter;
    gboolean iter_valid;
} rlc_channel_stats;


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

    rlc_channel_stats CCCH_stats;
    rlc_channel_stats srb_stats[2];
    rlc_channel_stats drb_stats[32];
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
    GtkTreeIter iter;
    gboolean iter_valid;
} rlc_lte_ep_t;


/* Used to keep track of whole RLC LTE statistics window */
typedef struct rlc_lte_stat_t {
    GtkTreeView   *ue_table;
    rlc_lte_ep_t  *ep_list;
    guint32       total_frames;

    char          *filter;

    /* Top-level dialog and labels */
    GtkWidget  *dlg_w;
    GtkWidget  *ues_lb;

    /* Other widgets */
    GtkWidget  *ul_filter_bt;
    GtkWidget  *dl_filter_bt;
    GtkWidget  *uldl_filter_bt;
    GtkWidget  *show_only_control_pdus_cb;
    GtkWidget  *show_dct_errors_cb;
    GtkWidget  *dct_error_substring_lb;
    GtkWidget  *dct_error_substring_te;
    GtkWidget  *sn_filter_lb;
    GtkWidget  *sn_filter_te;

    /* Common stats */
    rlc_lte_common_stats common_stats;
    GtkWidget *common_bcch_frames;
    GtkWidget *common_bcch_bytes;
    GtkWidget *common_pcch_frames;
    GtkWidget *common_pcch_bytes;

    gboolean  show_mac;

    /* State used to attempt to re-select chosen UE/channel */
    guint16   reselect_ue;
    guint16   reselect_channel_type;
    guint16   reselect_channel_id;

    GtkTreeView   *channel_table;
} rlc_lte_stat_t;


static int get_channel_selection(rlc_lte_stat_t *hs,
                                 guint16 *ueid, guint8 *rlcMode,
                                 guint16 *channelType, guint16 *channelId);

/* Show filter controls appropriate to current selection */
static void enable_filter_controls(guint8 enabled, guint8 rlcMode, rlc_lte_stat_t *hs)
{
    guint8 show_dct_errors = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(hs->show_dct_errors_cb));

    gtk_widget_set_sensitive(hs->ul_filter_bt, enabled);
    gtk_widget_set_sensitive(hs->dl_filter_bt, enabled);
    gtk_widget_set_sensitive(hs->uldl_filter_bt, enabled);
    gtk_widget_set_sensitive(hs->show_dct_errors_cb, enabled);

    /* Enabling substring control only if errors enabled */
    gtk_widget_set_sensitive(hs->dct_error_substring_lb, enabled && show_dct_errors);
    gtk_widget_set_sensitive(hs->dct_error_substring_te, enabled && show_dct_errors);

    switch (rlcMode) {
        case RLC_TM_MODE:
            gtk_widget_set_sensitive(hs->show_only_control_pdus_cb, FALSE);
            gtk_widget_set_sensitive(hs->sn_filter_lb, FALSE);
            gtk_widget_set_sensitive(hs->sn_filter_te, FALSE);
            break;
        case RLC_UM_MODE:
            gtk_widget_set_sensitive(hs->show_only_control_pdus_cb, FALSE);
            gtk_widget_set_sensitive(hs->sn_filter_lb, TRUE);
            gtk_widget_set_sensitive(hs->sn_filter_te, TRUE);
            break;
        case RLC_AM_MODE:
            gtk_widget_set_sensitive(hs->show_only_control_pdus_cb, TRUE);
            gtk_widget_set_sensitive(hs->sn_filter_lb, TRUE);
            gtk_widget_set_sensitive(hs->sn_filter_te, TRUE);
            break;

        default:
            gtk_widget_set_sensitive(hs->show_only_control_pdus_cb, FALSE);
            gtk_widget_set_sensitive(hs->sn_filter_lb, FALSE);
            gtk_widget_set_sensitive(hs->sn_filter_te, FALSE);
            break;
    }
}



/* Reset the statistics window */
static void rlc_lte_stat_reset(void *phs)
{
    rlc_lte_stat_t* rlc_lte_stat = (rlc_lte_stat_t *)phs;
    rlc_lte_ep_t* list = rlc_lte_stat->ep_list;
    gchar title[256];
    GtkListStore *store;

    /* Set the title */
    if (rlc_lte_stat->dlg_w != NULL) {
        g_snprintf(title, sizeof(title), "Wireshark: LTE RLC Traffic Statistics: %s (filter=\"%s\")",
                   cf_get_display_name(&cfile),
                   strlen(rlc_lte_stat->filter) ? rlc_lte_stat->filter : "none");
        gtk_window_set_title(GTK_WINDOW(rlc_lte_stat->dlg_w), title);
    }

    g_snprintf(title, sizeof(title), "0 UEs");
    gtk_frame_set_label(GTK_FRAME(rlc_lte_stat->ues_lb), title);

    rlc_lte_stat->total_frames = 0;
    memset(&rlc_lte_stat->common_stats, 0, sizeof(rlc_lte_common_stats));

    /* Remove all entries from the UE list */
    store = GTK_LIST_STORE(gtk_tree_view_get_model(rlc_lte_stat->ue_table));
    gtk_list_store_clear(store);

    if (!list) {
        return;
    }

    rlc_lte_stat->ep_list = NULL;
}


/* Allocate a rlc_lte_ep_t struct to store info for new UE */
static rlc_lte_ep_t* alloc_rlc_lte_ep(struct rlc_lte_tap_info *si, packet_info *pinfo _U_)
{
    rlc_lte_ep_t* ep;
    int n;

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
    ep->stats.UL_total_acks = 0;
    ep->stats.DL_total_acks = 0;
    ep->stats.UL_total_nacks = 0;
    ep->stats.DL_total_nacks = 0;
    ep->stats.UL_total_missing = 0;
    ep->stats.DL_total_missing = 0;

    memset(&ep->stats.CCCH_stats, 0, sizeof(rlc_channel_stats));
    for (n=0; n < 2; n++) {
        memset(&ep->stats.srb_stats[n], 0, sizeof(rlc_channel_stats));
    }
    for (n=0; n < 32; n++) {
        memset(&ep->stats.drb_stats[n], 0, sizeof(rlc_channel_stats));
    }

    ep->next = NULL;
    ep->iter_valid = FALSE;

    return ep;
}


/* Return string for RLC mode for display */
static const char *print_rlc_channel_mode(guint8 mode)
{
    static char unknown[32];

    switch (mode) {
        case RLC_TM_MODE:  return "TM";
        case RLC_UM_MODE:  return "UM";
        case RLC_AM_MODE:  return "AM";
        case RLC_PREDEF:   return "Predef";

        default:
            g_snprintf(unknown, sizeof(unknown), "Unknown (%u)", mode);
            return unknown;
    }
}


/* Process stat struct for a RLC LTE frame */
static int rlc_lte_stat_packet(void *phs, packet_info *pinfo, epan_dissect_t *edt _U_,
                    const void *phi)
{
    /* Get reference to stat window instance */
    rlc_lte_stat_t *hs = (rlc_lte_stat_t *)phs;
    rlc_lte_ep_t *tmp = NULL, *te = NULL;
    rlc_channel_stats *channel_stats = NULL;

    /* Cast tap info struct */
    struct rlc_lte_tap_info *si = (struct rlc_lte_tap_info *)phi;

    /* Need this */
    if (!hs) {
        return 0;
    }

    /* Are we ignoring RLC frames that were found in MAC frames, or only those
       that were logged separately? */
    if ((!hs->show_mac && si->loggedInMACFrame) ||
        (hs->show_mac && !si->loggedInMACFrame)) {
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

    /* Find channel struct */
    switch (si->channelType) {
        case CHANNEL_TYPE_CCCH:
            channel_stats = &te->stats.CCCH_stats;
            break;

        case CHANNEL_TYPE_SRB:
            channel_stats = &te->stats.srb_stats[si->channelId-1];
            break;

        case CHANNEL_TYPE_DRB:
            channel_stats = &te->stats.drb_stats[si->channelId-1];
            break;

        default:
            /* Shouldn't get here... */
            return 0;
    }

    if (channel_stats != NULL) {
        /* (Over)-write these params */
        channel_stats->inUse = TRUE;
        channel_stats->iter_valid = FALSE;
        channel_stats->rlcMode = si->rlcMode;
        channel_stats->channelType = si->channelType;
        channel_stats->channelId = si->channelId;
        if (si->priority != 0) {
            channel_stats->priority = si->priority;
        }
    }
    else {
        /* Giving up if no channel found... */
        return 0;
    }

    if (si->direction == DIRECTION_UPLINK) {
        /* Update time range */
        if (channel_stats->UL_frames == 0) {
            channel_stats->UL_time_start = si->time;
        }
        channel_stats->UL_time_stop = si->time;

        channel_stats->UL_frames++;
        channel_stats->UL_bytes += si->pduLength;
        channel_stats->UL_nacks += si->noOfNACKs;
        channel_stats->UL_missing += si->missingSNs;
        if (si->isControlPDU) {
            channel_stats->UL_acks++;
            te->stats.UL_total_acks++;
        }
        te->stats.UL_total_nacks += si->noOfNACKs;
        te->stats.UL_total_missing += si->missingSNs;
    }
    else {
        /* Update time range */
        if (channel_stats->DL_frames == 0) {
            channel_stats->DL_time_start = si->time;
        }
        channel_stats->DL_time_stop = si->time;

        channel_stats->DL_frames++;
        channel_stats->DL_bytes += si->pduLength;
        channel_stats->DL_nacks += si->noOfNACKs;
        channel_stats->DL_missing += si->missingSNs;
        if (si->isControlPDU) {
            channel_stats->DL_acks++;
            te->stats.DL_total_acks++;
        }
        te->stats.DL_total_nacks += si->noOfNACKs;
        te->stats.DL_total_missing += si->missingSNs;
    }

    return 1;
}


/* The channels for any UE would need to be re-added to the list */
static void invalidate_channel_iters(rlc_lte_stat_t *hs)
{
    gint n;
    rlc_lte_ep_t *ep = hs->ep_list;

    while (ep) {
        ep->stats.CCCH_stats.iter_valid = FALSE;
        for (n=0; n < 2; n++) {
            ep->stats.srb_stats[n].iter_valid = FALSE;
        }
        for (n=0; n < 32; n++) {
            ep->stats.drb_stats[n].iter_valid = FALSE;
        }

        ep = ep->next;
    }
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



/* Draw the channels table according to the current UE selection */
static void rlc_lte_channels(rlc_lte_ep_t *rlc_stat_ep, rlc_lte_stat_t *hs)
{
    GtkListStore *channels_store = GTK_LIST_STORE(gtk_tree_view_get_model(hs->channel_table));
    rlc_channel_stats *channel_stats;
    char buff[32];
    int n;

    /* Clear any existing rows */
    gtk_list_store_clear(channels_store);
    invalidate_channel_iters(hs);

    if (rlc_stat_ep == NULL) {
        return;
    }

    /* Add one row for each channel */

    /* CCCH */
    channel_stats = &rlc_stat_ep->stats.CCCH_stats;
    if (channel_stats->inUse) {

        if (!channel_stats->iter_valid) {
            /* Add to list control if not drawn this UE before */
            gtk_list_store_append(channels_store, &channel_stats->iter);
            channel_stats->iter_valid = TRUE;
        }

        /* Set each column for this row */
        gtk_list_store_set(channels_store, &channel_stats->iter,
                           CHANNEL_NAME, "CCCH",
                           CHANNEL_MODE, print_rlc_channel_mode(channel_stats->rlcMode),
                           CHANNEL_PRIORITY, 0,
                           CHANNEL_UL_FRAMES, channel_stats->UL_frames,
                           CHANNEL_UL_BYTES, channel_stats->UL_bytes,
                           CHANNEL_DL_FRAMES, channel_stats->DL_frames,
                           CHANNEL_DL_BYTES, channel_stats->DL_bytes,
                           CHANNEL_TABLE_COLUMN, channel_stats,
                           -1);
    }


    /* SRB */
    for (n=0; n < 2; n++) {
        channel_stats = &rlc_stat_ep->stats.srb_stats[n];
        if (channel_stats->inUse) {

            /* Calculate bandwidth */
            float UL_bw = calculate_bw(&channel_stats->UL_time_start,
                                       &channel_stats->UL_time_stop,
                                       channel_stats->UL_bytes);
            float DL_bw = calculate_bw(&channel_stats->DL_time_start,
                                       &channel_stats->DL_time_stop,
                                       channel_stats->DL_bytes);

            if (!channel_stats->iter_valid) {
                /* Add to list control if not drawn this UE before */
                gtk_list_store_append(channels_store, &channel_stats->iter);
                channel_stats->iter_valid = TRUE;
            }

            g_snprintf(buff, sizeof(buff), "SRB-%u", n+1);

            /* Set each column for this row */
            gtk_list_store_set(channels_store, &channel_stats->iter,
                               CHANNEL_NAME, buff,
                               CHANNEL_MODE, print_rlc_channel_mode(channel_stats->rlcMode),
                               CHANNEL_PRIORITY, channel_stats->priority,
                               CHANNEL_UL_FRAMES, channel_stats->UL_frames,
                               CHANNEL_UL_BYTES, channel_stats->UL_bytes,
                               CHANNEL_UL_BW, UL_bw,
                               CHANNEL_UL_ACKS, channel_stats->UL_acks,
                               CHANNEL_UL_NACKS, channel_stats->UL_nacks,
                               CHANNEL_UL_MISSING, channel_stats->UL_missing,
                               CHANNEL_DL_FRAMES, channel_stats->DL_frames,
                               CHANNEL_DL_BYTES, channel_stats->DL_bytes,
                               CHANNEL_DL_BW, DL_bw,
                               CHANNEL_DL_ACKS, channel_stats->DL_acks,
                               CHANNEL_DL_NACKS, channel_stats->DL_nacks,
                               CHANNEL_DL_MISSING, channel_stats->DL_missing,
                               CHANNEL_TABLE_COLUMN, channel_stats,
                               -1);
        }
    }


    /* DRB */
    for (n=0; n < 32; n++) {
        channel_stats = &rlc_stat_ep->stats.drb_stats[n];
        if (channel_stats->inUse) {

            /* Calculate bandwidth */
            float UL_bw = calculate_bw(&channel_stats->UL_time_start,
                                       &channel_stats->UL_time_stop,
                                       channel_stats->UL_bytes);
            float DL_bw = calculate_bw(&channel_stats->DL_time_start,
                                       &channel_stats->DL_time_stop,
                                       channel_stats->DL_bytes);

            if (!channel_stats->iter_valid) {
                /* Add to list control if not drawn this UE before */
                gtk_list_store_append(channels_store, &channel_stats->iter);
                channel_stats->iter_valid = TRUE;
            }

            g_snprintf(buff, sizeof(buff), "DRB-%u", n+1);

            /* Set each column for this row */
            gtk_list_store_set(channels_store, &channel_stats->iter,
                               CHANNEL_NAME, buff,
                               CHANNEL_MODE, print_rlc_channel_mode(channel_stats->rlcMode),
                               CHANNEL_PRIORITY, channel_stats->priority,
                               CHANNEL_UL_FRAMES, channel_stats->UL_frames,
                               CHANNEL_UL_BYTES, channel_stats->UL_bytes,
                               CHANNEL_UL_BW, UL_bw,
                               CHANNEL_UL_ACKS, channel_stats->UL_acks,
                               CHANNEL_UL_NACKS, channel_stats->UL_nacks,
                               CHANNEL_UL_MISSING, channel_stats->UL_missing,
                               CHANNEL_DL_FRAMES, channel_stats->DL_frames,
                               CHANNEL_DL_BYTES, channel_stats->DL_bytes,
                               CHANNEL_DL_BW, DL_bw,
                               CHANNEL_DL_ACKS, channel_stats->DL_acks,
                               CHANNEL_DL_NACKS, channel_stats->DL_nacks,
                               CHANNEL_DL_MISSING, channel_stats->DL_missing,
                               CHANNEL_TABLE_COLUMN, channel_stats,
                               -1);
        }
    }
}



/* (Re)draw the whole dialog window */
static void rlc_lte_stat_draw(void *phs)
{
    gchar   buff[32];
    guint16 number_of_ues = 0;
    gchar title[256];

    /* Look up the statistics window */
    rlc_lte_stat_t *hs = (rlc_lte_stat_t *)phs;
    rlc_lte_ep_t* list = hs->ep_list, *tmp = 0;

    GtkListStore *ues_store;
    GtkTreeSelection *sel;
    GtkTreeModel *model;
    GtkTreeIter iter;
    rlc_channel_stats *channel_stats = NULL;

    /* Common channel data */
    g_snprintf(buff, sizeof(buff), "BCCH Frames: %u", hs->common_stats.bcch_frames);
    gtk_label_set_text(GTK_LABEL(hs->common_bcch_frames), buff);
    g_snprintf(buff, sizeof(buff), "BCCH Bytes: %u", hs->common_stats.bcch_bytes);
    gtk_label_set_text(GTK_LABEL(hs->common_bcch_bytes), buff);
    g_snprintf(buff, sizeof(buff), "PCCH Frames: %u", hs->common_stats.pcch_frames);
    gtk_label_set_text(GTK_LABEL(hs->common_pcch_frames), buff);
    g_snprintf(buff, sizeof(buff), "PCCH Bytes: %u", hs->common_stats.pcch_bytes);
    gtk_label_set_text(GTK_LABEL(hs->common_pcch_bytes), buff);

    /* Per-UE table entries */
    ues_store = GTK_LIST_STORE(gtk_tree_view_get_model(hs->ue_table));

    /* Set title that shows how many UEs currently in table */
    for (tmp = list; (tmp!=NULL); tmp=tmp->next, number_of_ues++);
    g_snprintf(title, sizeof(title), "%u UEs", number_of_ues);
    gtk_frame_set_label(GTK_FRAME(hs->ues_lb), title);

    /* Update title to include number of UEs and frames */
    g_snprintf(title, sizeof(title), "Wireshark: LTE RLC Traffic Statistics: %s (%u UEs, %u frames) (filter=\"%s\")",
               cf_get_display_name(&cfile),
               number_of_ues,
               hs->total_frames,
               strlen(hs->filter) ? hs->filter : "none");
    gtk_window_set_title(GTK_WINDOW(hs->dlg_w), title);


    /* For each row/UE in the model */
    for (tmp = list; tmp; tmp=tmp->next) {
        /* Calculate bandwidth */
        float UL_bw = calculate_bw(&tmp->stats.UL_time_start,
                                   &tmp->stats.UL_time_stop,
                                   tmp->stats.UL_total_bytes);
        float DL_bw = calculate_bw(&tmp->stats.DL_time_start,
                                   &tmp->stats.DL_time_stop,
                                   tmp->stats.DL_total_bytes);

        if (tmp->iter_valid != TRUE) {
            /* Add to list control if not drawn this UE before */
            gtk_list_store_append(ues_store, &tmp->iter);
            tmp->iter_valid = TRUE;
        }

        /* Set each column for this row */
        gtk_list_store_set(ues_store, &tmp->iter,
                           UEID_COLUMN, tmp->stats.ueid,
                           UL_FRAMES_COLUMN, tmp->stats.UL_frames,
                           UL_BYTES_COLUMN, tmp->stats.UL_total_bytes,
                           UL_BW_COLUMN, UL_bw,
                           UL_ACKS_COLUMN, tmp->stats.UL_total_acks,
                           UL_NACKS_COLUMN, tmp->stats.UL_total_nacks,
                           UL_MISSING_COLUMN, tmp->stats.UL_total_missing,
                           DL_FRAMES_COLUMN, tmp->stats.DL_frames,
                           DL_BYTES_COLUMN, tmp->stats.DL_total_bytes,
                           DL_BW_COLUMN, DL_bw,
                           DL_ACKS_COLUMN, tmp->stats.DL_total_acks,
                           DL_NACKS_COLUMN, tmp->stats.DL_total_nacks,
                           DL_MISSING_COLUMN, tmp->stats.DL_total_missing,
                           UE_TABLE_COLUMN, tmp,
                           -1);
    }

    /* Reselect UE? */
    if (hs->reselect_ue != 0) {
        GtkTreeIter *ue_iter = NULL;
        rlc_lte_ep_t *ep = hs->ep_list;
        while (ep != NULL) {
            if (ep->stats.ueid == hs->reselect_ue) {
                ue_iter = &ep->iter;
                break;
            }
            ep = ep->next;
        }
        if (ue_iter != NULL) {
            gtk_tree_selection_select_iter(gtk_tree_view_get_selection(hs->ue_table), ue_iter);
        }
    }

    /* If there is a UE selected, update its counters in details window */
    sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(hs->ue_table));
    if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
        rlc_lte_ep_t *ep;

        gtk_tree_model_get(model, &iter, UE_TABLE_COLUMN, &ep, -1);
        rlc_lte_channels(ep, hs);

        /* Reselect channel? */
        switch (hs->reselect_channel_type) {
            case CHANNEL_TYPE_CCCH:
                channel_stats = &(ep->stats.CCCH_stats);
                break;
            case CHANNEL_TYPE_DRB:
                channel_stats = &(ep->stats.drb_stats[hs->reselect_channel_id-1]);
                break;
            case CHANNEL_TYPE_SRB:
                channel_stats = &(ep->stats.srb_stats[hs->reselect_channel_id-1]);
                break;
            default:
                break;
        }

        if ((channel_stats != NULL) && channel_stats->inUse && channel_stats->iter_valid) {
            gtk_tree_selection_select_iter(gtk_tree_view_get_selection(hs->channel_table), &channel_stats->iter);
        }
    }
}

/* When DCT errors check-box is toggled, enable substring controls accordingly */
static void rlc_lte_dct_errors_cb(GtkTreeSelection *sel _U_, gpointer data)
{
    rlc_lte_stat_t *hs = (rlc_lte_stat_t*)data;
    guint8 show_dct_errors = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(hs->show_dct_errors_cb));

    gtk_widget_set_sensitive(hs->dct_error_substring_lb, show_dct_errors);
    gtk_widget_set_sensitive(hs->dct_error_substring_te, show_dct_errors);
}

/* What to do when a UE list item is selected/unselected */
static void rlc_lte_select_ue_cb(GtkTreeSelection *sel, gpointer data)
{
    rlc_lte_ep_t   *ep;
    GtkTreeModel   *model;
    GtkTreeIter    iter;
    rlc_lte_stat_t *hs = (rlc_lte_stat_t*)data;

    if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
        /* Show details of selected UE */
        gtk_tree_model_get(model, &iter, UE_TABLE_COLUMN, &ep, -1);
        hs->reselect_ue = ep->stats.ueid;
        rlc_lte_channels(ep, hs);
    }
    else {
        rlc_lte_channels(NULL, hs);
    }

    /* Channel will be deselected */
    enable_filter_controls(FALSE, 0, hs);
}


/* What to do when a channel list item is selected/unselected */
static void rlc_lte_select_channel_cb(GtkTreeSelection *sel, gpointer data)
{
    GtkTreeModel   *model;
    GtkTreeIter    iter;
    rlc_lte_stat_t *hs = (rlc_lte_stat_t *)data;

    if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
        guint16  ueid;
        guint8   rlcMode;

        /* Remember selected channel */
        get_channel_selection(hs, &ueid, &rlcMode,
                              &(hs->reselect_channel_type), &(hs->reselect_channel_id));

        /* Enable buttons */
        enable_filter_controls(TRUE, rlcMode, hs);

    }
    else {
        /* No channel selected - disable buttons */
        enable_filter_controls(FALSE, 0, hs);
    }
}


/* Destroy the stats window */
static void win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
    rlc_lte_stat_t *hs = (rlc_lte_stat_t *)data;

    protect_thread_critical_region();
    remove_tap_listener(hs);
    unprotect_thread_critical_region();

    if (hs->dlg_w != NULL) {
        window_destroy(hs->dlg_w);
        hs->dlg_w = NULL;
    }
    rlc_lte_stat_reset(hs);
    g_free(hs);
}


/* When source of packets (MAC or RLC-only) changes, re-display */
static void toggle_show_mac(GtkWidget *widget, gpointer data)
{
    rlc_lte_stat_t *hs = (rlc_lte_stat_t *)data;

    /* Read state */
    hs->show_mac = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget));

    /* Retap */
    cf_retap_packets(&cfile);
}



/* Check that a UE / channel is currently selected.  If so, fill in out
   parameters with details of channel.
   Return TRUE if a channel is selected */
static int get_channel_selection(rlc_lte_stat_t *hs,
                                 guint16 *ueid, guint8 *rlcMode,
                                 guint16 *channelType, guint16 *channelId)
{
    GtkTreeModel *model;
    GtkTreeIter iter;

    /* Check UE selection */
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(hs->ue_table));
    if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
        rlc_lte_ep_t *ep;

        gtk_tree_model_get(model, &iter, UE_TABLE_COLUMN, &ep, -1);
        *ueid = ep->stats.ueid;

        /* Check channel selection */
        sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(hs->channel_table));
        if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
            /* Find details of selected channel */
            rlc_channel_stats *channel_stats;
            gtk_tree_model_get(model, &iter, CHANNEL_TABLE_COLUMN, &channel_stats, -1);
            *rlcMode = channel_stats->rlcMode;
            *channelType = channel_stats->channelType;
            *channelId = channel_stats->channelId;
        }
        else {
            return FALSE;
        }
    }
    else {
        return FALSE;
    }

    return TRUE;
}


/* Build and set a display filter to match the given channel settings */
typedef enum ChannelDirection_t {UL_Only, DL_Only, UL_and_DL} ChannelDirection_t;
static void set_channel_filter_expression(guint16  ueid,
                                          guint8   rlcMode,
                                          guint16  channelType,
                                          guint16  channelId,
                                          ChannelDirection_t channelDirection,
                                          gint     filterOnSN,
                                          gint     statusOnlyPDUs,
                                          gint     showDCTErrors,
                                          const gchar    *DCTErrorSubstring,
                                          rlc_lte_stat_t *hs)
{
    #define MAX_FILTER_LEN 1024
    static char buffer[MAX_FILTER_LEN];
    int offset = 0;

    /* Show DCT errors */
    if (showDCTErrors) {
        if (strlen(DCTErrorSubstring) > 0) {
            offset += g_snprintf(buffer+offset, MAX_FILTER_LEN-offset,
                                 "(dct2000.error-comment and (dct2000.comment contains \"%s\")) or (",
                                 DCTErrorSubstring);
        }
        else {
            offset += g_snprintf(buffer+offset, MAX_FILTER_LEN-offset,
                                 "dct2000.error-comment or (");
        }
    }

    /* Include dialog filter */
    if (strlen(hs->filter)) {
        offset += g_snprintf(buffer+offset, MAX_FILTER_LEN-offset, "%s and ", hs->filter);
    }

    /* Should we exclude MAC frames? */
    if (!hs->show_mac) {
        offset += g_snprintf(buffer+offset, MAX_FILTER_LEN-offset, "not mac-lte and ");
    }
    else {
        offset += g_snprintf(buffer+offset, MAX_FILTER_LEN-offset, "mac-lte and ");
    }

    /* UEId */
    offset += g_snprintf(buffer+offset, MAX_FILTER_LEN-offset, "(rlc-lte.ueid == %u) and ", ueid);
    offset += g_snprintf(buffer+offset, MAX_FILTER_LEN-offset, "(rlc-lte.channel-type == %u)", channelType);

    /* Channel-id for srb/drb */
    if ((channelType == CHANNEL_TYPE_SRB) || (channelType == CHANNEL_TYPE_DRB)) {
        offset += g_snprintf(buffer+offset, MAX_FILTER_LEN-offset, " and (rlc-lte.channel-id == %u)", channelId);
    }

    /* Direction (also depends upon RLC mode) */
    switch (channelDirection) {
        case UL_Only:
            if (rlcMode == RLC_AM_MODE) {
                /* Always filter status PDUs */
                offset += g_snprintf(buffer+offset, MAX_FILTER_LEN-offset,
                                     " and (rlc-lte.direction == 1 and rlc-lte.am.frame-type == 0)");
                if (!statusOnlyPDUs) {
                    /* Also filter data */
                    offset += g_snprintf(buffer+offset, MAX_FILTER_LEN-offset,
                                         " or (rlc-lte.direction == 0 and rlc-lte.am.frame-type == 1)");
                }
            }
            else {
                offset += g_snprintf(buffer+offset, MAX_FILTER_LEN-offset, " and (rlc-lte.direction == 0)");
            }
            break;
        case DL_Only:
            if (rlcMode == RLC_AM_MODE) {
                /* Always filter status PDs */
                offset += g_snprintf(buffer+offset, MAX_FILTER_LEN-offset,
                                     " and (rlc-lte.direction == 0 and rlc-lte.am.frame-type == 0)");
                if (!statusOnlyPDUs) {
                    /* Also filter data */
                    offset += g_snprintf(buffer+offset, MAX_FILTER_LEN-offset,
                                         " or (rlc-lte.direction == 1 and rlc-lte.am.frame-type == 1)");
                }
            }
            else {
                offset += g_snprintf(buffer+offset, MAX_FILTER_LEN-offset, " and (rlc-lte.direction == 1)");
            }
            break;
        case UL_and_DL:
            if (rlcMode == RLC_AM_MODE) {
                if (statusOnlyPDUs) {
                    g_snprintf(buffer+offset, MAX_FILTER_LEN-offset, " and (rlc-lte.am.frame-type == 0)");
                }
            }

        default:
            break;
    }

    /* Filter on a specific sequence number */
    if (filterOnSN != -1) {
        switch (rlcMode) {
            case RLC_AM_MODE:
                offset += g_snprintf(buffer+offset, MAX_FILTER_LEN-offset,
                                     " and ((rlc-lte.am.fixed.sn == %u) or "
                                     "(rlc-lte.am.ack-sn == %u) or "
                                     "(rlc-lte.am.nack-sn == %u))",
                                     filterOnSN, (filterOnSN+1) % 1024, filterOnSN);
                break;
            case RLC_UM_MODE:
                offset += g_snprintf(buffer+offset, MAX_FILTER_LEN-offset,
                                     " and (rlc-lte.um.sn == %u)", filterOnSN);
                break;

            default:
                break;
        }
    }

    /* Close () if open */
    if (showDCTErrors) {
        offset += g_snprintf(buffer+offset, MAX_FILTER_LEN-offset, ")");
    }


    /* Set its value to our new string */
    gtk_entry_set_text(GTK_ENTRY(main_display_filter_widget), buffer);

    /* Run the filter */
    main_filter_packets(&cfile, buffer, TRUE);
}

/* Respond to UL filter button being clicked by building and using filter */
static void ul_filter_clicked(GtkWindow *win _U_, rlc_lte_stat_t* hs)
{
    guint16  ueid;
    guint8   rlcMode;
    guint16  channelType;
    guint16  channelId;
    int      sn = -1;
    const gchar *sn_string = "";

    /* Read SN to filter on (if present) */
    sn_string = gtk_entry_get_text(GTK_ENTRY(hs->sn_filter_te));
    if (strlen(sn_string) > 0) {
        sn = atoi(sn_string);
    }

    if (!get_channel_selection(hs, &ueid, &rlcMode, &channelType, &channelId)) {
        return;
    }

    set_channel_filter_expression(ueid, rlcMode, channelType, channelId, UL_Only, sn,
                                  gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(hs->show_only_control_pdus_cb)),
                                  gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(hs->show_dct_errors_cb)),
                                  gtk_entry_get_text(GTK_ENTRY(hs->dct_error_substring_te)),
                                  hs);
}

/* Respond to DL filter button being clicked by building and using filter */
static void dl_filter_clicked(GtkWindow *win _U_, rlc_lte_stat_t* hs)
{
    guint16  ueid;
    guint8   rlcMode;
    guint16  channelType;
    guint16  channelId;
    int      sn = -1;
    const gchar *sn_string = "";

    /* Read SN to filter on (if present) */
    sn_string = gtk_entry_get_text(GTK_ENTRY(hs->sn_filter_te));
    if (strlen(sn_string) > 0) {
        sn = atoi(sn_string);
    }

    if (!get_channel_selection(hs, &ueid, &rlcMode, &channelType, &channelId)) {
        return;
    }

    set_channel_filter_expression(ueid, rlcMode, channelType, channelId, DL_Only, sn,
                                  gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(hs->show_only_control_pdus_cb)),
                                  gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(hs->show_dct_errors_cb)),
                                  gtk_entry_get_text(GTK_ENTRY(hs->dct_error_substring_te)),
                                  hs);
}

/* Respond to UL/DL filter button being clicked by building and using filter */
static void uldl_filter_clicked(GtkWindow *win _U_, rlc_lte_stat_t* hs)
{
    guint16  ueid;
    guint8   rlcMode;
    guint16  channelType;
    guint16  channelId;
    int      sn = -1;
    const gchar *sn_string = "";

    /* Read SN to filter on (if present) */
    sn_string = gtk_entry_get_text(GTK_ENTRY(hs->sn_filter_te));
    if (strlen(sn_string) > 0) {
        sn = atoi(sn_string);
    }

    if (!get_channel_selection(hs, &ueid, &rlcMode, &channelType, &channelId)) {
        return;
    }

    set_channel_filter_expression(ueid, rlcMode, channelType, channelId, UL_and_DL, sn,
                                  gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(hs->show_only_control_pdus_cb)),
                                  gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(hs->show_dct_errors_cb)),
                                  gtk_entry_get_text(GTK_ENTRY(hs->dct_error_substring_te)),
                                  hs);
}


/* Create a new RLC LTE stats dialog */
static void gtk_rlc_lte_stat_init(const char *optarg, void *userdata _U_)
{
    rlc_lte_stat_t    *hs;
    const char        *filter = NULL;
    GString           *error_string;
    GtkWidget         *ues_scrolled_window;
    GtkWidget         *channels_scrolled_window;
    GtkWidget         *bbox;
    GtkWidget         *top_level_vbox;

    GtkWidget         *pdu_source_lb;
    GtkWidget         *common_channel_lb;
    GtkWidget         *channels_lb;
    GtkWidget         *filter_buttons_lb;

    GtkWidget         *common_row_hbox;
    GtkWidget         *show_mac_cb;
    GtkWidget         *ues_vb;
    GtkWidget         *channels_vb;
    GtkWidget         *filter_vb;
    GtkWidget         *filter_buttons_hb;
    GtkWidget         *sn_filter_hb;

    GtkWidget         *close_bt;
    GtkWidget         *help_bt;
    GtkListStore      *store;

    GtkTreeView       *tree_view;
    GtkCellRenderer   *renderer;
    GtkTreeViewColumn *column;
    GtkTreeSelection  *sel;
    gchar title[256];
    gint i;

    /* Check for a filter string */
    if (strncmp(optarg, "rlc-lte,stat,", 13) == 0) {
        /* Skip those characters from filter to display */
        filter = optarg + 13;
    }
    else {
        /* No filter */
        filter = NULL;
    }


    /* Create dialog */
    hs = g_malloc(sizeof(rlc_lte_stat_t));
    hs->ep_list = NULL;

    /* Copy filter (so can be used for window title at reset) */
    if (filter) {
        hs->filter = g_strdup(filter);
    }
    else {
        hs->filter = NULL;
    }


    /* Set title */
    g_snprintf(title, sizeof(title), "Wireshark: LTE RLC Statistics: %s",
               cf_get_display_name(&cfile));
    hs->dlg_w = window_new_with_geom(GTK_WINDOW_TOPLEVEL, title, "LTE RLC Statistics");

    /* Window size */
    gtk_window_set_default_size(GTK_WINDOW(hs->dlg_w), 750, 300);

    /* Will stack widgets vertically inside dlg */
    top_level_vbox = gtk_vbox_new(FALSE, 3);       /* FALSE = not homogeneous */
    gtk_container_add(GTK_CONTAINER(hs->dlg_w), top_level_vbox);
    gtk_container_set_border_width(GTK_CONTAINER(top_level_vbox), 6);
    gtk_widget_show(top_level_vbox);

    /**********************************************/
    /* Exclude-MAC checkbox                       */
    pdu_source_lb = gtk_frame_new("PDUs to use");
    show_mac_cb = gtk_check_button_new_with_mnemonic("Show RLC PDUs found inside logged MAC frames");
    gtk_container_add(GTK_CONTAINER(pdu_source_lb), show_mac_cb);
    gtk_widget_set_tooltip_text(show_mac_cb, "Can either use separately-logged RLC PDUs, OR find them "
                         "decoded inside MAC PDUs (enabled in MAC dissector preferences)");


    /* MAC on by default */
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(show_mac_cb), TRUE);
    hs->show_mac = TRUE;
    gtk_box_pack_start(GTK_BOX(top_level_vbox), pdu_source_lb, FALSE, FALSE, 0);
    /* TODO: add tooltips... */
    g_signal_connect(show_mac_cb, "toggled", G_CALLBACK(toggle_show_mac), hs);


    /**********************************************/
    /* Common Channel data                        */
    /**********************************************/
    common_channel_lb = gtk_frame_new("Common Channel Data");

    /* Will add BCCH and PCCH counters into one row */
    common_row_hbox = gtk_hbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER(common_channel_lb), common_row_hbox);
    gtk_container_set_border_width(GTK_CONTAINER(common_row_hbox), 5);
    gtk_box_pack_start(GTK_BOX(top_level_vbox), common_channel_lb, FALSE, FALSE, 0);

    /* Create labels (that will hold label and counter value) */
    hs->common_bcch_frames = gtk_label_new("BCCH Frames:");
    gtk_misc_set_alignment(GTK_MISC(hs->common_bcch_frames), 0.0f, .5f);
    gtk_container_add(GTK_CONTAINER(common_row_hbox), hs->common_bcch_frames);
    gtk_widget_show(hs->common_bcch_frames);

    hs->common_bcch_bytes = gtk_label_new("BCCH Bytes:");
    gtk_misc_set_alignment(GTK_MISC(hs->common_bcch_bytes), 0.0f, .5f);
    gtk_container_add(GTK_CONTAINER(common_row_hbox), hs->common_bcch_bytes);
    gtk_widget_show(hs->common_bcch_bytes);

    hs->common_pcch_frames = gtk_label_new("PCCH Frames:");
    gtk_misc_set_alignment(GTK_MISC(hs->common_pcch_frames), 0.0f, .5f);
    gtk_container_add(GTK_CONTAINER(common_row_hbox), hs->common_pcch_frames);
    gtk_widget_show(hs->common_pcch_frames);

    hs->common_pcch_bytes = gtk_label_new("PCCH Bytes:");
    gtk_misc_set_alignment(GTK_MISC(hs->common_pcch_bytes), 0.0f, .5f);
    gtk_container_add(GTK_CONTAINER(common_row_hbox), hs->common_pcch_bytes);
    gtk_widget_show(hs->common_pcch_bytes);


    /**********************************************/
    /* UE List                                    */
    /**********************************************/

    hs->ues_lb = gtk_frame_new("UE Data (0 UEs)");
    ues_vb = gtk_vbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER(hs->ues_lb), ues_vb);
    gtk_container_set_border_width(GTK_CONTAINER(ues_vb), 5);

    ues_scrolled_window = scrolled_window_new(NULL, NULL);
    gtk_box_pack_start(GTK_BOX(ues_vb), ues_scrolled_window, TRUE, TRUE, 0);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(ues_scrolled_window),
                                        GTK_SHADOW_IN);

    /* Create the table of UE data */
    store = gtk_list_store_new(NUM_UE_COLUMNS, G_TYPE_INT,
                               G_TYPE_INT, G_TYPE_INT, G_TYPE_FLOAT, G_TYPE_INT, G_TYPE_INT, G_TYPE_INT, /* UL */
                               G_TYPE_INT, G_TYPE_INT, G_TYPE_FLOAT, G_TYPE_INT, G_TYPE_INT, G_TYPE_INT, /* DL */
                               G_TYPE_POINTER);
    hs->ue_table = GTK_TREE_VIEW(tree_view_new(GTK_TREE_MODEL(store)));
    gtk_container_add(GTK_CONTAINER (ues_scrolled_window), GTK_WIDGET(hs->ue_table));
    g_object_unref(G_OBJECT(store));

    tree_view = hs->ue_table;
    gtk_tree_view_set_headers_visible(tree_view, TRUE);
    gtk_tree_view_set_headers_clickable(tree_view, TRUE);

    /* Create the titles for each column of the per-UE table */
    for (i = 0; i < UE_TABLE_COLUMN; i++) {
        renderer = gtk_cell_renderer_text_new();
        column = gtk_tree_view_column_new_with_attributes(ue_titles[i], renderer,
                                                          "text", i, NULL);
        gtk_tree_view_column_set_sort_column_id(column, i);

        if (i == 0) {
            /* Expand first column (RNTI, which is Key) */
            gtk_tree_view_column_set_expand(column, TRUE);
        } else {
            /* For other columns, set all of the free space to be on the left */
            g_object_set(G_OBJECT(renderer), "xalign", 1.0, NULL);
        }
        gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
        gtk_tree_view_column_set_resizable(column, TRUE);
        gtk_tree_view_append_column(tree_view, column);
    }

    /* Set callback function for selecting a row in the UE table */
    sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(hs->ue_table));
    gtk_tree_selection_set_mode(sel, GTK_SELECTION_SINGLE);
    g_signal_connect(sel, "changed", G_CALLBACK(rlc_lte_select_ue_cb), hs);

    gtk_box_pack_start(GTK_BOX(top_level_vbox), hs->ues_lb, TRUE, TRUE, 0);


    /**********************************************/
    /* Channels of selected UE                    */
    /**********************************************/
    channels_lb = gtk_frame_new("Channels of selected UE");

    channels_vb = gtk_vbox_new(FALSE, 6);
    gtk_container_add(GTK_CONTAINER(channels_lb), channels_vb);
    gtk_container_set_border_width(GTK_CONTAINER(channels_vb), 5);

    channels_scrolled_window = scrolled_window_new(NULL, NULL);
    gtk_box_pack_start(GTK_BOX(channels_vb), channels_scrolled_window, TRUE, TRUE, 0);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(channels_scrolled_window),
                                        GTK_SHADOW_IN);

    /* Create the table of UE data */
    store = gtk_list_store_new(NUM_CHANNEL_COLUMNS,
                               G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INT, /* name, type, priority */
                               G_TYPE_INT, G_TYPE_INT, G_TYPE_FLOAT, G_TYPE_INT, G_TYPE_INT, G_TYPE_INT, /* UL */
                               G_TYPE_INT, G_TYPE_INT, G_TYPE_FLOAT, G_TYPE_INT, G_TYPE_INT, G_TYPE_INT, /* DL */
                               G_TYPE_POINTER);
    hs->channel_table = GTK_TREE_VIEW(tree_view_new(GTK_TREE_MODEL(store)));
    gtk_container_add(GTK_CONTAINER (channels_scrolled_window), GTK_WIDGET(hs->channel_table));
    g_object_unref(G_OBJECT(store));

    tree_view = hs->channel_table;
    gtk_tree_view_set_headers_visible(tree_view, TRUE);
    gtk_tree_view_set_headers_clickable(tree_view, TRUE);

    /* Create the titles for each column of the per-UE table */
    for (i = 0; i < CHANNEL_TABLE_COLUMN; i++) {
        renderer = gtk_cell_renderer_text_new();
        column = gtk_tree_view_column_new_with_attributes(channel_titles[i], renderer,
                                                          "text", i, NULL);
        gtk_tree_view_column_set_sort_column_id(column, i);

        if (i == 0) {
            /* Expand first column (Type) */
            gtk_tree_view_column_set_expand(column, TRUE);
        } else {
            /* For other columns, set all of the free space to be on the left */
            g_object_set(G_OBJECT(renderer), "xalign", 1.0, NULL);
        }
        gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
        gtk_tree_view_column_set_resizable(column, TRUE);
        gtk_tree_view_append_column(tree_view, column);
    }

    /* Set callback function for selecting a row in the channel table */
    sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(hs->channel_table));
    gtk_tree_selection_set_mode(sel, GTK_SELECTION_SINGLE);
    g_signal_connect(sel, "changed", G_CALLBACK(rlc_lte_select_channel_cb), hs);

    gtk_box_pack_start(GTK_BOX(top_level_vbox), channels_lb, TRUE, TRUE, 0);


    /**********************************************/
    /* Channel filters                            */
    /**********************************************/

    filter_buttons_lb = gtk_frame_new("Filter on selected channel");

    filter_vb = gtk_vbox_new(FALSE, 3);
    gtk_container_add(GTK_CONTAINER(filter_buttons_lb), filter_vb);

    /* Horizontal row of filter buttons */
    filter_buttons_hb = gtk_hbox_new(FALSE, 6);
    gtk_container_add(GTK_CONTAINER(filter_vb), filter_buttons_hb);
    gtk_container_set_border_width(GTK_CONTAINER(filter_buttons_hb), 2);

    /* UL only */
    hs->ul_filter_bt = gtk_button_new_with_label("Set UL display filter for this channel");
    gtk_box_pack_start(GTK_BOX(filter_buttons_hb), hs->ul_filter_bt, TRUE, TRUE, 0);
    g_signal_connect(hs->ul_filter_bt, "clicked", G_CALLBACK(ul_filter_clicked), hs);
    gtk_widget_show(hs->ul_filter_bt);
    gtk_widget_set_tooltip_text(hs->ul_filter_bt, "Generate and set a display filter to show frames "
                         "associated with the channel, in the UL direction only. "
                         "N.B. DL Status PDUs sent on this channel will also be shown for AM");

    /* DL only */
    hs->dl_filter_bt = gtk_button_new_with_label("Set DL display filter for this channel");
    gtk_box_pack_start(GTK_BOX(filter_buttons_hb), hs->dl_filter_bt, TRUE, TRUE, 0);
    g_signal_connect(hs->dl_filter_bt, "clicked", G_CALLBACK(dl_filter_clicked), hs);
    gtk_widget_show(hs->dl_filter_bt);
    gtk_widget_set_tooltip_text(hs->dl_filter_bt, "Generate and set a display filter to show frames "
                         "associated with the channel, in the DL direction only. "
                         "N.B. UL Status PDUs sent on this channel will also be shown for AM");

    /* UL and DL */
    hs->uldl_filter_bt = gtk_button_new_with_label("Set UL / DL display filter for this channel");
    gtk_box_pack_start(GTK_BOX(filter_buttons_hb), hs->uldl_filter_bt, TRUE, TRUE, 0);
    g_signal_connect(hs->uldl_filter_bt, "clicked", G_CALLBACK(uldl_filter_clicked), hs);
    gtk_widget_show(hs->uldl_filter_bt);
    gtk_widget_set_tooltip_text(hs->uldl_filter_bt, "Generate and set a display filter to show frames "
                         "associated with the channel, in UL and DL");

    /* Allow filtering on specific SN number. */
    /* Row with label and text entry control  */
    sn_filter_hb = gtk_hbox_new(FALSE, 3);
    gtk_container_add(GTK_CONTAINER(filter_vb), sn_filter_hb);
    gtk_widget_show(sn_filter_hb);

    /* Allow filtering only to select status PDUs for AM */
    hs->show_only_control_pdus_cb = gtk_check_button_new_with_mnemonic("Show only status PDUs");
    gtk_container_add(GTK_CONTAINER(sn_filter_hb), hs->show_only_control_pdus_cb);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(hs->show_only_control_pdus_cb), FALSE);
    gtk_widget_set_tooltip_text(hs->show_only_control_pdus_cb, "Generated filters will only show AM status PDUs "
                         "(i.e. if you filter on UL you'll see ACKs/NACK replies sent in the DL)");

    /* Allow DCT errors to be shown... */
    hs->show_dct_errors_cb = gtk_check_button_new_with_mnemonic("Show DCT2000 error strings...");
    gtk_container_add(GTK_CONTAINER(sn_filter_hb), hs->show_dct_errors_cb);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(hs->show_dct_errors_cb), FALSE);
    g_signal_connect(hs->show_dct_errors_cb, "toggled", G_CALLBACK(rlc_lte_dct_errors_cb), hs);
    gtk_widget_set_tooltip_text(hs->show_dct_errors_cb, "When checked, generated filters will "
                         "include DCT2000 error strings");

    /* ... optionally limited by a substring */
    hs->dct_error_substring_lb = gtk_label_new("...containing");
    gtk_box_pack_start(GTK_BOX(sn_filter_hb), hs->dct_error_substring_lb, FALSE, FALSE, 0);
    gtk_widget_show(hs->dct_error_substring_lb);

    hs->dct_error_substring_te = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(sn_filter_hb), hs->dct_error_substring_te, FALSE, FALSE, 0);
    gtk_widget_show(hs->dct_error_substring_te);
    gtk_widget_set_tooltip_text(hs->dct_error_substring_te,
                         "If given, only match error strings containing this substring");

    /* Allow filtering of a particular sequence number */
    hs->sn_filter_te = gtk_entry_new();
    gtk_box_pack_end(GTK_BOX(sn_filter_hb), hs->sn_filter_te, FALSE, FALSE, 0);
    gtk_widget_show(hs->sn_filter_te);
    gtk_widget_set_tooltip_text(hs->sn_filter_te, "Can limit generated filters to a given sequence number (0-1023). "
                         "Will also include relevant AM status PDUs");

    hs->sn_filter_lb = gtk_label_new("Sequence number to filter on:");
    gtk_box_pack_end(GTK_BOX(sn_filter_hb), hs->sn_filter_lb, FALSE, FALSE, 0);
    gtk_widget_show(hs->sn_filter_lb);


    /* Add filters box to top-level window */
    gtk_box_pack_start(GTK_BOX(top_level_vbox), filter_buttons_lb, FALSE, FALSE, 0);

    enable_filter_controls(FALSE, 0, hs);

    /**********************************************/
    /* Register the tap listener                  */
    /**********************************************/

    error_string = register_tap_listener("rlc-lte", hs,
                                         filter, 0,
                                         rlc_lte_stat_reset,
                                         rlc_lte_stat_packet,
                                         rlc_lte_stat_draw);
    if (error_string) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
        g_string_free(error_string, TRUE);
        g_free(hs);
        return;
    }


    /************************************/
    /* Bottom button row.                */
    /************************************/

    bbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_HELP, NULL);
    gtk_box_pack_end(GTK_BOX(top_level_vbox), bbox, FALSE, FALSE, 0);

    /* Add the close button */
    close_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
    window_set_cancel_button(hs->dlg_w, close_bt, window_cancel_button_cb);

    help_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
    g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_STATS_LTE_RLC_TRAFFIC_DIALOG);

    /* Set callbacks */
    g_signal_connect(hs->dlg_w, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
    g_signal_connect(hs->dlg_w, "destroy", G_CALLBACK(win_destroy_cb), hs);

    /* Show the window */
    gtk_widget_show_all(hs->dlg_w);
    window_present(hs->dlg_w);

    /* Retap */
    cf_retap_packets(&cfile);
    gdk_window_raise(gtk_widget_get_window(hs->dlg_w));
}


static tap_param rlc_lte_stat_params[] = {
    { PARAM_FILTER, "Filter", NULL }
};

static tap_param_dlg rlc_lte_stat_dlg = {
    "LTE RLC Stats",
    "rlc-lte,stat",
    gtk_rlc_lte_stat_init,
    -1,
    G_N_ELEMENTS(rlc_lte_stat_params),
    rlc_lte_stat_params
};


/* Register this tap listener (need void on own so line register function found) */
void
register_tap_listener_rlc_lte_stat(void)
{
    register_dfilter_stat(&rlc_lte_stat_dlg, "_LTE/_RLC", REGISTER_STAT_GROUP_TELEPHONY);
}

void rlc_lte_stat_cb(GtkAction *action, gpointer user_data _U_)
{
	tap_param_dlg_cb(action, &rlc_lte_stat_dlg);
}


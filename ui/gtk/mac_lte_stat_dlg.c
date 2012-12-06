/* mac_lte_stat_dlg.c
 * Copyright 2009 Martin Mathieson
 * (originally based upon wlan_stat_dlg.c)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <string.h>

#include <gtk/gtk.h>

#include "ui/gtk/gtkglobals.h"

#include <epan/packet.h>
#include <epan/packet_info.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-mac-lte.h>

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
    DL_PADDING_PERCENT_COLUMN,
    DL_CRC_FAILED_COLUMN,
    DL_CRC_HIGH_CODE_RATE_COLUMN,
    DL_CRC_PDSCH_LOST_COLUMN,
    DL_CRC_DUPLICATE_NONZERO_RV,
    DL_RETX_FRAMES_COLUMN,
    TABLE_COLUMN,
    NUM_UE_COLUMNS
};

enum {
    CCCH_COLUMN=1,
    LCID1_COLUMN,
    LCID2_COLUMN,
    LCID3_COLUMN,
    LCID4_COLUMN,
    LCID5_COLUMN,
    LCID6_COLUMN,
    LCID7_COLUMN,
    LCID8_COLUMN,
    LCID9_COLUMN,
    LCID10_COLUMN,
    PREDEFINED_COLUMN,
    NUM_CHANNEL_COLUMNS
};

static const gchar *ue_titles[] = { "RNTI", "Type", "UEId",
                                    "UL Frames", "UL Bytes", "UL MBit/sec", "UL Padding %", "UL ReTX",
                                    "DL Frames", "DL Bytes", "DL MBit/sec", "DL Padding %", "DL CRC Failed", "DL CRC High Code Rate", "DL CRC PDSCH Lost", "DL CRC Dup NonZero RV", "DL ReTX"};

static const gchar *channel_titles[] = { "CCCH",
                                         "LCID 1", "LCID 2", "LCID 3", "LCID 4", "LCID 5",
                                         "LCID 6", "LCID 7", "LCID 8", "LCID 9", "LCID 10",
                                         "Predefined"};


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
    guint32  DL_raw_bytes;   /* all bytes */
    guint32  DL_total_bytes;
    nstime_t DL_time_start;
    nstime_t DL_time_stop;
    guint32  DL_padding_bytes;
    guint32  DL_CRC_failures;
    guint32  DL_CRC_high_code_rate;
    guint32  DL_CRC_PDSCH_lost;
    guint32  DL_CRC_Duplicate_Nonzero_rv;
    guint32  DL_retx_frames;

    guint32  UL_bytes_for_lcid[11];
    guint32  UL_sdus_for_lcid[11];
    guint32  DL_bytes_for_lcid[11];
    guint32  DL_sdus_for_lcid[11];
} mac_lte_row_data;


/* One row/UE in the UE table */
typedef struct mac_lte_ep {
    struct mac_lte_ep* next;
    struct mac_lte_row_data stats;
    GtkTreeIter iter;
    gboolean iter_valid;
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


static const char * selected_ue_row_names[] = {"UL SDUs", "UL Bytes", "DL SDUs", "DL Bytes"};


/* Used to keep track of whole MAC LTE statistics window */
typedef struct mac_lte_stat_t {
    /* Stats window itself */
    GtkWidget  *mac_lte_stat_dlg_w;

    char       *filter;

    /* Labels */
    GtkWidget  *mac_lte_stat_ues_lb;
    GtkWidget  *ul_filter_bt;
    GtkWidget  *dl_filter_bt;
    GtkWidget  *uldl_filter_bt;

    GtkWidget  *show_mac_rach_cb;
    GtkWidget  *show_mac_srs_cb;
    GtkWidget  *show_dct_errors_cb;
    GtkWidget  *dct_error_substring_lb;
    GtkWidget  *dct_error_substring_te;

    GtkWidget  *ul_max_ues_per_tti;
    GtkWidget  *dl_max_ues_per_tti;

    /* Common stats */
    mac_lte_common_stats common_stats;
    GtkWidget *common_bch_frames;
    GtkWidget *common_bch_bytes;
    GtkWidget *common_pch_frames;
    GtkWidget *common_pch_bytes;
    GtkWidget *common_rar_frames;
    GtkWidget *common_rar_entries;

    /* Keep track of unique rntis & ueids */
    guint8 used_ueids[65535];
    guint8 used_rntis[65535];
    guint16 number_of_ueids;
    guint16 number_of_rntis;

    guint16 selected_rnti;
    guint16 selected_ueid;

    /* Labels in selected UE 'table' */
    GtkWidget *selected_ue_column_entry[NUM_CHANNEL_COLUMNS][5];

    GtkTreeView   *ue_table;
    mac_lte_ep_t  *ep_list;
} mac_lte_stat_t;


/* Reset the statistics window */
static void mac_lte_stat_reset(void *phs)
{
    mac_lte_stat_t* mac_lte_stat = (mac_lte_stat_t *)phs;
    mac_lte_ep_t* list = mac_lte_stat->ep_list;
    char *display_name;
    gchar title[256];
    GtkListStore *store;
    gint i, n;

    /* Set the title */
    if (mac_lte_stat->mac_lte_stat_dlg_w != NULL) {
        display_name = cf_get_display_name(&cfile);
        g_snprintf(title, sizeof(title), "Wireshark: LTE MAC Traffic Statistics: %s (filter=\"%s\")",
                   display_name,
                   strlen(mac_lte_stat->filter) ? mac_lte_stat->filter : "none");
        g_free(display_name);
        gtk_window_set_title(GTK_WINDOW(mac_lte_stat->mac_lte_stat_dlg_w), title);
    }

    g_snprintf(title, sizeof(title), "UL/DL-SCH data (0 entries)");
    gtk_frame_set_label(GTK_FRAME(mac_lte_stat->mac_lte_stat_ues_lb), title);

    /* Reset counts of unique ueids & rntis */
    memset(mac_lte_stat->used_ueids, 0, 65535);
    mac_lte_stat->number_of_ueids = 0;
    memset(mac_lte_stat->used_rntis, 0, 65535);
    mac_lte_stat->number_of_rntis = 0;

    /* Zero common stats */
    memset(&(mac_lte_stat->common_stats), 0, sizeof(mac_lte_common_stats));

    /* Remove all entries from the UE list */
    store = GTK_LIST_STORE(gtk_tree_view_get_model(mac_lte_stat->ue_table));
    gtk_list_store_clear(store);

    if (!list) {
        return;
    }

    mac_lte_stat->ep_list = NULL;

    /* Set all of the channel counters to 0 */
    for (n=1; n <=4; n++) {
        for (i=CCCH_COLUMN; i < NUM_CHANNEL_COLUMNS; i++) {
             gtk_label_set_text(GTK_LABEL(mac_lte_stat->selected_ue_column_entry[i][n]), "0");
        }
    }
}


/* Allocate a mac_lte_ep_t struct to store info for new UE */
static mac_lte_ep_t* alloc_mac_lte_ep(struct mac_lte_tap_info *si, packet_info *pinfo _U_)
{
    mac_lte_ep_t* ep;
    int n;

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
    ep->stats.DL_raw_bytes = 0;
    ep->stats.UL_padding_bytes = 0;
    ep->stats.DL_padding_bytes = 0;
    ep->stats.DL_total_bytes = 0;
    ep->stats.UL_CRC_errors = 0;
    ep->stats.DL_CRC_failures = 0;
    ep->stats.DL_CRC_high_code_rate = 0;
    ep->stats.DL_CRC_PDSCH_lost = 0;
    ep->stats.DL_CRC_Duplicate_Nonzero_rv = 0;
    ep->stats.UL_retx_frames = 0;
    ep->stats.DL_retx_frames = 0;

    for (n=0; n < 11; n++) {
        ep->stats.UL_sdus_for_lcid[n] = 0;
        ep->stats.UL_bytes_for_lcid[n] = 0;
    }
    ep->stats.DL_total_bytes = 0;
    for (n=0; n < 11; n++) {
        ep->stats.DL_sdus_for_lcid[n] = 0;
        ep->stats.DL_bytes_for_lcid[n] = 0;
    }

    ep->next = NULL;

    ep->iter_valid = FALSE;

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
static int mac_lte_stat_packet(void *phs, packet_info *pinfo, epan_dissect_t *edt _U_,
                               const void *phi)
{
    int n;

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
            for (n=0; n < 11; n++) {
                if (si->bytes_for_lcid[n]) {
                    te->stats.UL_sdus_for_lcid[n] += si->sdus_for_lcid[n];
                }
                te->stats.UL_bytes_for_lcid[n] += si->bytes_for_lcid[n];
                te->stats.UL_total_bytes += si->bytes_for_lcid[n];
            }
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
                case crc_duplicate_nonzero_rv:
                    te->stats.DL_CRC_Duplicate_Nonzero_rv++;
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

        te->stats.DL_raw_bytes += si->raw_length;
        te->stats.DL_padding_bytes += si->padding_bytes;

        if (si->isPredefinedData) {
            te->stats.DL_total_bytes += si->single_number_of_bytes;
        }
        else {
            for (n=0; n < 11; n++) {
                if (si->bytes_for_lcid[n]) {
                    te->stats.DL_sdus_for_lcid[n] += si->sdus_for_lcid[n];
                }
                te->stats.DL_bytes_for_lcid[n] += si->bytes_for_lcid[n];
                te->stats.DL_total_bytes += si->bytes_for_lcid[n];
            }
        }
    }

    return 1;
}


/* Draw the UE details table according to the current UE selection */
static void mac_lte_ue_details(mac_lte_ep_t *mac_stat_ep, mac_lte_stat_t *hs)
{
    int n;
    gchar buff[32];
    guint8 show_dct_errors;

    /**********************************/
    /* Set data one row at a time     */

    /* UL SDUs */
    for (n=0; n < PREDEFINED_COLUMN-1; n++) {
        g_snprintf(buff, sizeof(buff), "%u",
                   (mac_stat_ep != NULL) ? mac_stat_ep->stats.UL_sdus_for_lcid[n] : 0);
         gtk_label_set_text(GTK_LABEL(hs->selected_ue_column_entry[n+1][1]), buff);
    }

    /* Predefined */
    if (mac_stat_ep != NULL) {
        g_snprintf(buff, sizeof(buff), "%u",
                   mac_stat_ep->stats.is_predefined_data ? mac_stat_ep->stats.UL_frames : 0);
    }
    else {
        g_snprintf(buff, sizeof(buff), "%u", 0);
    }
    gtk_label_set_text(GTK_LABEL(hs->selected_ue_column_entry[PREDEFINED_COLUMN][1]), buff);


    /* UL Bytes */
    for (n=0; n < PREDEFINED_COLUMN-1; n++) {
        g_snprintf(buff, sizeof(buff), "%u",
                   (mac_stat_ep != NULL) ? mac_stat_ep->stats.UL_bytes_for_lcid[n] : 0);
        gtk_label_set_text(GTK_LABEL(hs->selected_ue_column_entry[n+1][2]), buff);
    }

    /* Predefined */
    if (mac_stat_ep != NULL) {
        g_snprintf(buff, sizeof(buff), "%u",
                   mac_stat_ep->stats.is_predefined_data ? mac_stat_ep->stats.UL_total_bytes : 0);
    }
    else {
        g_snprintf(buff, sizeof(buff), "%u", 0);
    }
    gtk_label_set_text(GTK_LABEL(hs->selected_ue_column_entry[PREDEFINED_COLUMN][2]), buff);


    /* DL SDUs */
    for (n=0; n < PREDEFINED_COLUMN-1; n++) {
        g_snprintf(buff, sizeof(buff), "%u",
                   (mac_stat_ep != NULL) ? mac_stat_ep->stats.DL_sdus_for_lcid[n] : 0);
        gtk_label_set_text(GTK_LABEL(hs->selected_ue_column_entry[n+1][3]), buff);
    }
    /* Predefined */
    if (mac_stat_ep != NULL) {
        g_snprintf(buff, sizeof(buff), "%u",
                   mac_stat_ep->stats.is_predefined_data ? mac_stat_ep->stats.DL_frames : 0);
    }
    else {
        g_snprintf(buff, sizeof(buff), "%u", 0);
    }
    gtk_label_set_text(GTK_LABEL(hs->selected_ue_column_entry[PREDEFINED_COLUMN][3]), buff);


    /* DL Bytes */
    for (n=0; n < PREDEFINED_COLUMN-1; n++) {
        g_snprintf(buff, sizeof(buff), "%u",
                   (mac_stat_ep != NULL) ? mac_stat_ep->stats.DL_bytes_for_lcid[n] : 0);
        gtk_label_set_text(GTK_LABEL(hs->selected_ue_column_entry[n+1][4]), buff);
    }
    /* Predefined */
    if (mac_stat_ep != NULL) {
        g_snprintf(buff, sizeof(buff), "%u",
                   mac_stat_ep->stats.is_predefined_data ? mac_stat_ep->stats.DL_total_bytes : 0);
    }
    else {
        g_snprintf(buff, sizeof(buff), "%u", 0);
    }
    gtk_label_set_text(GTK_LABEL(hs->selected_ue_column_entry[PREDEFINED_COLUMN][4]), buff);

    /* Remember selected UE */
    if (mac_stat_ep) {
        hs->selected_rnti = mac_stat_ep->stats.rnti;
        hs->selected_ueid = mac_stat_ep->stats.ueid;
    }

    /* Enable/disable filter controls */
    gtk_widget_set_sensitive(hs->ul_filter_bt, mac_stat_ep != NULL);
    gtk_widget_set_sensitive(hs->dl_filter_bt, mac_stat_ep != NULL);
    gtk_widget_set_sensitive(hs->uldl_filter_bt, mac_stat_ep != NULL);
    gtk_widget_set_sensitive(hs->show_mac_rach_cb, mac_stat_ep != NULL);
    gtk_widget_set_sensitive(hs->show_mac_srs_cb, mac_stat_ep != NULL);
    gtk_widget_set_sensitive(hs->show_dct_errors_cb, mac_stat_ep != NULL);

    /* Enabling substring control only if errors enabled */
    show_dct_errors = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(hs->show_dct_errors_cb));
    gtk_widget_set_sensitive(hs->dct_error_substring_lb, show_dct_errors && (mac_stat_ep != NULL));
    gtk_widget_set_sensitive(hs->dct_error_substring_te, show_dct_errors && (mac_stat_ep != NULL));
}


/* Calculate and return a bandwidth figure, in Mbs */
static float calculate_bw(nstime_t *start_time, nstime_t *stop_time, guint32 bytes)
{
    /* Can only calculate bandwidth if have time delta */
    if (memcmp(start_time, stop_time, sizeof(nstime_t)) != 0) {
        float elapsed_ms = (((float)stop_time->secs - (float)start_time->secs) * 1000) +
                           (((float)stop_time->nsecs - (float)start_time->nsecs) / 1000000);

        /* Only really meaningful if have a few frames spread over time...
           For now at least avoid dividing by something very close to 0.0 */
        if (elapsed_ms < 2.0) {
           return 0.0;
        }
        return ((bytes * 8) / elapsed_ms) / 1000;
    }
    else {
        return 0.0;
    }
}


/* (Re)draw the whole dialog window */
static void mac_lte_stat_draw(void *phs)
{
    gchar   buff[32];
    guint16 number_of_ues = 0;
    char *display_name;
    gchar title[256];

    /* Look up the statistics window */
    mac_lte_stat_t *hs = (mac_lte_stat_t *)phs;
    mac_lte_ep_t* list = hs->ep_list, *tmp = 0;

    GtkListStore *ues_store;
    GtkTreeSelection *sel;
    GtkTreeModel *model;
    GtkTreeIter iter;

    /* System data */
    g_snprintf(buff, sizeof(buff), "Max UL UEs/TTI: %u", hs->common_stats.max_ul_ues_in_tti);
    gtk_label_set_text(GTK_LABEL(hs->ul_max_ues_per_tti), buff);
    g_snprintf(buff, sizeof(buff), "Max DL UEs/TTI: %u", hs->common_stats.max_dl_ues_in_tti);
    gtk_label_set_text(GTK_LABEL(hs->dl_max_ues_per_tti), buff);

    /* Common channel data */
    g_snprintf(buff, sizeof(buff), "BCH Frames: %u", hs->common_stats.bch_frames);
    gtk_label_set_text(GTK_LABEL(hs->common_bch_frames), buff);
    g_snprintf(buff, sizeof(buff), "BCH Bytes: %u", hs->common_stats.bch_bytes);
    gtk_label_set_text(GTK_LABEL(hs->common_bch_bytes), buff);
    g_snprintf(buff, sizeof(buff), "PCH Frames: %u", hs->common_stats.pch_frames);
    gtk_label_set_text(GTK_LABEL(hs->common_pch_frames), buff);
    g_snprintf(buff, sizeof(buff), "PCH Bytes: %u", hs->common_stats.pch_bytes);
    gtk_label_set_text(GTK_LABEL(hs->common_pch_bytes), buff);
    g_snprintf(buff, sizeof(buff), "RAR Frames: %u", hs->common_stats.rar_frames);
    gtk_label_set_text(GTK_LABEL(hs->common_rar_frames), buff);
    g_snprintf(buff, sizeof(buff), "RAR Entries: %u", hs->common_stats.rar_entries);
    gtk_label_set_text(GTK_LABEL(hs->common_rar_entries), buff);


    /* Per-UE table entries */
    ues_store = GTK_LIST_STORE(gtk_tree_view_get_model(hs->ue_table));

    /* Set title that shows how many UEs currently in table */
    for (tmp = list; (tmp!=NULL); tmp=tmp->next, number_of_ues++);
    g_snprintf(title, sizeof(title), "UL/DL-SCH data (%u entries - %u unique RNTIs, %u unique UEIds)",
               number_of_ues, hs->number_of_rntis, hs->number_of_ueids);
    gtk_frame_set_label(GTK_FRAME(hs->mac_lte_stat_ues_lb), title);

    /* Update title to include number of UEs and frames */
    display_name = cf_get_display_name(&cfile);
    g_snprintf(title, sizeof(title), "Wireshark: LTE MAC Traffic Statistics: %s (%u UEs, %u frames) (filter=\"%s\")",
               display_name,
               number_of_ues,
               hs->common_stats.all_frames,
               strlen(hs->filter) ? hs->filter : "none");
    g_free(display_name);
    gtk_window_set_title(GTK_WINDOW(hs->mac_lte_stat_dlg_w), title);


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
                           RNTI_COLUMN, tmp->stats.rnti,
                           RNTI_TYPE_COLUMN,
                               (tmp->stats.rnti_type == C_RNTI) ? "C-RNTI" : "SPS-RNTI",
                           UEID_COLUMN, tmp->stats.ueid,
                           UL_FRAMES_COLUMN, tmp->stats.UL_frames,
                           UL_BYTES_COLUMN, tmp->stats.UL_total_bytes,
                           UL_BW_COLUMN, UL_bw,
                           UL_PADDING_PERCENT_COLUMN,
                                tmp->stats.UL_raw_bytes ?
                                    (((float)tmp->stats.UL_padding_bytes / (float)tmp->stats.UL_raw_bytes) * 100.0) :
                                    0.0,
                           UL_RETX_FRAMES_COLUMN, tmp->stats.UL_retx_frames,
                           DL_FRAMES_COLUMN, tmp->stats.DL_frames,
                           DL_BYTES_COLUMN, tmp->stats.DL_total_bytes,
                           DL_BW_COLUMN, DL_bw,
                           DL_PADDING_PERCENT_COLUMN,
                                tmp->stats.DL_raw_bytes ?
                                    (((float)tmp->stats.DL_padding_bytes / (float)tmp->stats.DL_raw_bytes) * 100.0) :
                                    0.0,
                           DL_CRC_FAILED_COLUMN, tmp->stats.DL_CRC_failures,
                           DL_CRC_HIGH_CODE_RATE_COLUMN, tmp->stats.DL_CRC_high_code_rate,
                           DL_CRC_PDSCH_LOST_COLUMN, tmp->stats.DL_CRC_PDSCH_lost,
                           DL_CRC_DUPLICATE_NONZERO_RV, tmp->stats.DL_CRC_Duplicate_Nonzero_rv,
                           DL_RETX_FRAMES_COLUMN, tmp->stats.DL_retx_frames,
                           TABLE_COLUMN, tmp,
                           -1);
    }

    /* Reselect UE? */
    if (hs->selected_rnti != 0) {
        GtkTreeIter *ue_iter = NULL;
        mac_lte_ep_t *ep = hs->ep_list;
        while (ep != NULL) {
            if ((ep->stats.ueid == hs->selected_ueid) &&
                (ep->stats.rnti == hs->selected_rnti)) {
                ue_iter = &ep->iter;
                break;
            }
            ep = ep->next;
        }
        if (ue_iter != NULL) {
            /* Make selection */
            gtk_tree_selection_select_iter(gtk_tree_view_get_selection(hs->ue_table),
                                           ue_iter);
        }
    }

    /* If there is a UE selected, update its counters in details window */
    sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(hs->ue_table));
    if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
        mac_lte_ep_t *ep;

        gtk_tree_model_get(model, &iter, TABLE_COLUMN, &ep, -1);
        mac_lte_ue_details(ep, hs);
    }
}


/* Compose and set appropriate display filter */
typedef enum Direction_t {UL_Only, DL_Only, UL_and_DL} Direction_t;

static void set_filter_expression(guint16  ueid,
                                  guint16  rnti,
                                  Direction_t direction,
                                  gint     showRACH,
                                  gint     showSRs,
                                  gint     showDCTErrors,
                                  const gchar    *DCTErrorSubstring,
                                  mac_lte_stat_t *hs)
{
    #define MAX_FILTER_LEN 512
    static char buffer[MAX_FILTER_LEN];
    int offset = 0;

    /* Create the filter expression */


    /* Show MAC RACH (preamble attempts and RAR PDUs) */
    if (showRACH) {
        offset += g_snprintf(buffer+offset, MAX_FILTER_LEN-offset,
                                         "(mac-lte.rar or (mac-lte.preamble-sent and mac-lte.ueid == %u)) or (",
                                         ueid);
    }

    /* Show MAC SRs */
    if (showSRs) {
        offset += g_snprintf(buffer+offset, MAX_FILTER_LEN-offset,
                                         "(mac-lte.sr-req and mac-lte.ueid == %u) or (",
                                         ueid);
    }

    /* Errors */
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

    /* Filter expression */
    if (strlen(hs->filter)) {
        offset += g_snprintf(buffer+offset, MAX_FILTER_LEN-offset, "%s and ", hs->filter);
    }

    /* Direction */
    switch (direction) {
        case UL_Only:
            offset += g_snprintf(buffer+offset, MAX_FILTER_LEN-offset, "(mac-lte.direction == 0) and ");
            break;
        case DL_Only:
            offset += g_snprintf(buffer+offset, MAX_FILTER_LEN-offset, "(mac-lte.direction == 1) and ");
            break;
        default:
            break;
    }

    /* Selected UE */
    offset += g_snprintf(buffer+offset, MAX_FILTER_LEN-offset,
                         "mac-lte.rnti == %u and mac-lte.ueid == %u",
                         rnti, ueid);

    /* Close () if open */
    if (showRACH) {
        offset += g_snprintf(buffer+offset, MAX_FILTER_LEN-offset, ")");
    }

    /* Close () if open */
    if (showSRs) {
        offset += g_snprintf(buffer+offset, MAX_FILTER_LEN-offset, ")");
    }


    /* Close () if open */
    if (showDCTErrors) {
        /*offset +=*/ g_snprintf(buffer+offset, MAX_FILTER_LEN-offset, ")");
    }

    /* Set its value to our new string */
    gtk_entry_set_text(GTK_ENTRY(main_display_filter_widget), buffer);

    /* Run the filter */
    main_filter_packets(&cfile, buffer, TRUE);
}

/* Respond to UL filter button being clicked by building and using filter */
static void ul_filter_clicked(GtkWindow *win _U_, mac_lte_stat_t* hs)
{
    GtkTreeSelection *sel;
    GtkTreeModel *model;
    GtkTreeIter iter;

    /* If there is a UE selected, update its counters in details window */
    sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(hs->ue_table));
    if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
        mac_lte_ep_t *ep;

        /* Get the UE details */
        gtk_tree_model_get(model, &iter, TABLE_COLUMN, &ep, -1);

        set_filter_expression(ep->stats.ueid, ep->stats.rnti, UL_Only,
                              gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(hs->show_mac_rach_cb)),
                              gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(hs->show_mac_srs_cb)),
                              gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(hs->show_dct_errors_cb)),
                              gtk_entry_get_text(GTK_ENTRY(hs->dct_error_substring_te)),
                              hs);
    }
}

/* Respond to DL filter button being clicked by building and using filter */
static void dl_filter_clicked(GtkWindow *win _U_, mac_lte_stat_t* hs)
{
    GtkTreeSelection *sel;
    GtkTreeModel *model;
    GtkTreeIter iter;

    /* If there is a UE selected, update its counters in details window */
    sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(hs->ue_table));
    if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
        mac_lte_ep_t *ep;

        /* Get the UE details */
        gtk_tree_model_get(model, &iter, TABLE_COLUMN, &ep, -1);

        set_filter_expression(ep->stats.ueid, ep->stats.rnti, DL_Only,
                              gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(hs->show_mac_rach_cb)),
                              gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(hs->show_mac_srs_cb)),
                              gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(hs->show_dct_errors_cb)),
                              gtk_entry_get_text(GTK_ENTRY(hs->dct_error_substring_te)),
                              hs);
    }

}

/* Respond to UL/DL filter button being clicked by building and using filter */
static void uldl_filter_clicked(GtkWindow *win _U_, mac_lte_stat_t* hs)
{
    GtkTreeSelection *sel;
    GtkTreeModel *model;
    GtkTreeIter iter;

    /* If there is a UE selected, update its counters in details window */
    sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(hs->ue_table));
    if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
        mac_lte_ep_t *ep;

        /* Get the UE details */
        gtk_tree_model_get(model, &iter, TABLE_COLUMN, &ep, -1);

        set_filter_expression(ep->stats.ueid, ep->stats.rnti, UL_and_DL,
                              gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(hs->show_mac_rach_cb)),
                              gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(hs->show_mac_srs_cb)),
                              gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(hs->show_dct_errors_cb)),
                              gtk_entry_get_text(GTK_ENTRY(hs->dct_error_substring_te)),
                              hs);
    }

}


/* What to do when a list item is selected/unselected */
static void mac_lte_select_cb(GtkTreeSelection *sel, gpointer data)
{
    mac_lte_stat_t *hs = (mac_lte_stat_t *)data;
    mac_lte_ep_t   *ep;
    GtkTreeModel   *model;
    GtkTreeIter    iter;

    if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
        /* Show details of selected UE */
        gtk_tree_model_get(model, &iter, TABLE_COLUMN, &ep, -1);
        mac_lte_ue_details(ep, hs);
    }
    else {
        mac_lte_ue_details(NULL, hs);
    }
}

/* When DCT errors check-box is toggled, enable substring controls accordingly */
static void mac_lte_dct_errors_cb(GtkTreeSelection *sel _U_, gpointer data)
{
    mac_lte_stat_t *hs = (mac_lte_stat_t*)data;
    guint8 show_dct_errors = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(hs->show_dct_errors_cb));

    gtk_widget_set_sensitive(hs->dct_error_substring_lb, show_dct_errors);
    gtk_widget_set_sensitive(hs->dct_error_substring_te, show_dct_errors);
}


/* Destroy the stats window */
static void win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
    mac_lte_stat_t *hs = (mac_lte_stat_t *)data;

    remove_tap_listener(hs);

    if (hs->mac_lte_stat_dlg_w != NULL) {
        window_destroy(hs->mac_lte_stat_dlg_w);
        hs->mac_lte_stat_dlg_w = NULL;
    }
    mac_lte_stat_reset(hs);
    g_free(hs->filter);
    g_free(hs);
}


/* Create a new MAC LTE stats dialog */
static void gtk_mac_lte_stat_init(const char *opt_arg, void *userdata _U_)
{
    mac_lte_stat_t    *hs;
    const char    *filter = NULL;
    GString       *error_string;
    GtkWidget     *ues_scrolled_window;
    GtkWidget     *bbox;
    GtkWidget     *top_level_vbox;

    GtkWidget     *system_row_hbox;
    GtkWidget     *common_row_hbox;
    GtkWidget     *ues_vb;
    GtkWidget     *selected_ue_hb;

    GtkWidget     *mac_lte_stat_system_lb;
    GtkWidget     *mac_lte_stat_common_channel_lb;
    GtkWidget     *mac_lte_stat_selected_ue_lb;
    GtkWidget     *selected_ue_vbox[NUM_CHANNEL_COLUMNS];
    GtkWidget     *selected_ue_column_titles[5];

    GtkWidget     *mac_lte_stat_filters_lb;
    GtkWidget     *filter_buttons_hb;

    GtkWidget     *close_bt;
    GtkWidget     *help_bt;

    GtkListStore  *store;

    GtkTreeView       *tree_view;
    GtkCellRenderer   *renderer;
    GtkTreeViewColumn *column;
    GtkTreeSelection  *sel;
    gchar *display_name;
    gchar title[256];
    gint i, n;

    /* Check for a filter string */
    if (strncmp(opt_arg, "mac-lte,stat,", 13) == 0) {
        /* Skip those characters from filter to display */
        filter = opt_arg + 13;
    }
    else {
        /* No filter */
        filter = NULL;
    }


    /* Create dialog */
    hs = g_malloc(sizeof(mac_lte_stat_t));
    hs->ep_list = NULL;

    /* Copy filter (so can be used for window title at reset) */
    if (filter) {
        hs->filter = g_strdup(filter);
    }
    else {
        hs->filter = NULL;
    }

    /* Set title */
    display_name = cf_get_display_name(&cfile);
    g_snprintf(title, sizeof(title), "Wireshark: LTE MAC Statistics: %s",
               display_name);
    g_free(display_name);

    /* Create top-level window */
    hs->mac_lte_stat_dlg_w = window_new_with_geom(GTK_WINDOW_TOPLEVEL, title, "LTE MAC Statistics");

    /* Window size */
    gtk_window_set_default_size(GTK_WINDOW(hs->mac_lte_stat_dlg_w), 750, 300);

    /* Will stack widgets vertically inside dlg */
    top_level_vbox = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 3, FALSE);       /* FALSE = not homogeneous */
    gtk_container_add(GTK_CONTAINER(hs->mac_lte_stat_dlg_w), top_level_vbox);

    gtk_container_set_border_width(GTK_CONTAINER(top_level_vbox), 6);
    gtk_widget_show(top_level_vbox);


    /**********************************************/
    /* System data                                */
    /**********************************************/
    mac_lte_stat_system_lb = gtk_frame_new("System Data");

    /* Add max UEs/TTI counts in one row */
    system_row_hbox = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0, FALSE);
    gtk_container_add(GTK_CONTAINER(mac_lte_stat_system_lb), system_row_hbox);
    gtk_container_set_border_width(GTK_CONTAINER(system_row_hbox), 5);

    gtk_box_pack_start(GTK_BOX(top_level_vbox), mac_lte_stat_system_lb, FALSE, FALSE, 0);

    /* Create labels (that will hold label and counter value) */
    hs->ul_max_ues_per_tti = gtk_label_new("Max UL UEs/TTI:");
    gtk_misc_set_alignment(GTK_MISC(hs->ul_max_ues_per_tti), 0.0f, .5f);
    gtk_container_add(GTK_CONTAINER(system_row_hbox), hs->ul_max_ues_per_tti);
    gtk_widget_show(hs->ul_max_ues_per_tti);

    hs->dl_max_ues_per_tti = gtk_label_new("Max DL UEs/TTI:");
    gtk_misc_set_alignment(GTK_MISC(hs->dl_max_ues_per_tti), 0.0f, .5f);
    gtk_container_add(GTK_CONTAINER(system_row_hbox), hs->dl_max_ues_per_tti);
    gtk_widget_show(hs->dl_max_ues_per_tti);


    /**********************************************/
    /* Common Channel data                        */
    /**********************************************/
    mac_lte_stat_common_channel_lb = gtk_frame_new("Common Channel Data");

    /* Will add BCH and PCH counters into one row */
    common_row_hbox = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0, FALSE);
    gtk_container_add(GTK_CONTAINER(mac_lte_stat_common_channel_lb), common_row_hbox);
    gtk_container_set_border_width(GTK_CONTAINER(common_row_hbox), 5);

    gtk_box_pack_start(GTK_BOX(top_level_vbox), mac_lte_stat_common_channel_lb, FALSE, FALSE, 0);

    /* Create labels (that will hold label and counter value) */
    hs->common_bch_frames = gtk_label_new("BCH Frames:");
    gtk_misc_set_alignment(GTK_MISC(hs->common_bch_frames), 0.0f, .5f);
    gtk_container_add(GTK_CONTAINER(common_row_hbox), hs->common_bch_frames);
    gtk_widget_show(hs->common_bch_frames);

    hs->common_bch_bytes = gtk_label_new("BCH Bytes:");
    gtk_misc_set_alignment(GTK_MISC(hs->common_bch_bytes), 0.0f, .5f);
    gtk_container_add(GTK_CONTAINER(common_row_hbox), hs->common_bch_bytes);
    gtk_widget_show(hs->common_bch_bytes);

    hs->common_pch_frames = gtk_label_new("PCH Frames:");
    gtk_misc_set_alignment(GTK_MISC(hs->common_pch_frames), 0.0f, .5f);
    gtk_container_add(GTK_CONTAINER(common_row_hbox), hs->common_pch_frames);
    gtk_widget_show(hs->common_pch_frames);

    hs->common_pch_bytes = gtk_label_new("PCH Bytes:");
    gtk_misc_set_alignment(GTK_MISC(hs->common_pch_bytes), 0.0f, .5f);
    gtk_container_add(GTK_CONTAINER(common_row_hbox), hs->common_pch_bytes);
    gtk_widget_show(hs->common_pch_bytes);

    hs->common_rar_frames = gtk_label_new("RAR Frames:");
    gtk_misc_set_alignment(GTK_MISC(hs->common_rar_frames), 0.0f, .5f);
    gtk_container_add(GTK_CONTAINER(common_row_hbox), hs->common_rar_frames);
    gtk_widget_show(hs->common_rar_frames);

    hs->common_rar_entries = gtk_label_new("RAR Entries:");
    gtk_misc_set_alignment(GTK_MISC(hs->common_rar_entries), 0.0f, .5f);
    gtk_container_add(GTK_CONTAINER(common_row_hbox), hs->common_rar_entries);
    gtk_widget_show(hs->common_rar_entries);

    /**********************************************/
    /* UL/DL-SCH data                             */
    /**********************************************/

    hs->mac_lte_stat_ues_lb = gtk_frame_new("UL/DL-SCH Data (0 UEs)");
    ues_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 0, FALSE);
    gtk_container_add(GTK_CONTAINER(hs->mac_lte_stat_ues_lb), ues_vb);
    gtk_container_set_border_width(GTK_CONTAINER(ues_vb), 5);

    ues_scrolled_window = scrolled_window_new(NULL, NULL);
    gtk_box_pack_start(GTK_BOX(ues_vb), ues_scrolled_window, TRUE, TRUE, 0);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(ues_scrolled_window),
                                        GTK_SHADOW_IN);

    /* Create the table of UE data */
    store = gtk_list_store_new(NUM_UE_COLUMNS, G_TYPE_INT, G_TYPE_STRING, G_TYPE_INT,
                               G_TYPE_INT, G_TYPE_INT, G_TYPE_FLOAT, G_TYPE_FLOAT, G_TYPE_INT, /* UL */
                               G_TYPE_INT, G_TYPE_INT, G_TYPE_FLOAT, G_TYPE_FLOAT, G_TYPE_INT, G_TYPE_INT, G_TYPE_INT,  G_TYPE_INT, G_TYPE_INT, /* DL */
                               G_TYPE_POINTER);
    hs->ue_table = GTK_TREE_VIEW(tree_view_new(GTK_TREE_MODEL(store)));
    gtk_container_add(GTK_CONTAINER (ues_scrolled_window), GTK_WIDGET(hs->ue_table));
    g_object_unref(G_OBJECT(store));

    tree_view = hs->ue_table;
    gtk_tree_view_set_headers_visible(tree_view, TRUE);
    gtk_tree_view_set_headers_clickable(tree_view, TRUE);

    /* Create the titles for each column of the per-UE table */
    for (i = 0; i < TABLE_COLUMN; i++) {
        if ((i == UL_PADDING_PERCENT_COLUMN) ||
            (i == DL_PADDING_PERCENT_COLUMN)) {
            /* Show % as progress bar */
            renderer = gtk_cell_renderer_progress_new();
            column = gtk_tree_view_column_new_with_attributes(ue_titles[i], renderer,
                                                              "text", i,
                                                              "value", i,
                                                              NULL);
        }
        else {
            renderer = gtk_cell_renderer_text_new();
            column = gtk_tree_view_column_new_with_attributes(ue_titles[i], renderer,
                                                              "text", i, NULL);
        }
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
    g_signal_connect(sel, "changed", G_CALLBACK(mac_lte_select_cb), hs);

    gtk_box_pack_start(GTK_BOX(top_level_vbox), hs->mac_lte_stat_ues_lb, TRUE, TRUE, 0);


    /**********************************************/
    /* Details of selected UE                     */
    /**********************************************/

    mac_lte_stat_selected_ue_lb = gtk_frame_new("Selected UE details");

    selected_ue_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6, FALSE);
    gtk_container_add(GTK_CONTAINER(mac_lte_stat_selected_ue_lb), selected_ue_hb);
    gtk_container_set_border_width(GTK_CONTAINER(selected_ue_hb), 5);

    /********************************/
    /* First (row titles) column    */
    selected_ue_vbox[0] = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 0, FALSE);
    gtk_container_add(GTK_CONTAINER(selected_ue_hb), selected_ue_vbox[0]);

    selected_ue_column_titles[0] = gtk_label_new("");
    gtk_misc_set_alignment(GTK_MISC(selected_ue_column_titles[0]), 0.0f, 0.0f);
    gtk_container_add(GTK_CONTAINER(selected_ue_vbox[0]), selected_ue_column_titles[0]);

    for (n=1; n < 5; n++) {
        selected_ue_column_titles[n] = gtk_label_new(selected_ue_row_names[n-1]);
        gtk_misc_set_alignment(GTK_MISC(selected_ue_column_titles[n]), 0.0f, 0.0f);
        gtk_container_add(GTK_CONTAINER(selected_ue_vbox[0]), selected_ue_column_titles[n]);
        gtk_widget_show(selected_ue_column_titles[n]);
    }


    /*************************/
    /* Other columns         */
    for (i=CCCH_COLUMN; i < NUM_CHANNEL_COLUMNS; i++) {
        selected_ue_vbox[i] = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 0, FALSE);
        gtk_container_add(GTK_CONTAINER(selected_ue_hb), selected_ue_vbox[i]);

        /* Channel title */
        hs->selected_ue_column_entry[i][0] = gtk_label_new(channel_titles[i-1]);
        gtk_misc_set_alignment(GTK_MISC(hs->selected_ue_column_entry[i][0]), 0.5f, 0.0f);
        gtk_container_add(GTK_CONTAINER(selected_ue_vbox[i]), hs->selected_ue_column_entry[i][0]);

        /* Counts for this channel */
        for (n=1; n < 5; n++) {
            hs->selected_ue_column_entry[i][n] = gtk_label_new("0");
            gtk_misc_set_alignment(GTK_MISC(hs->selected_ue_column_entry[i][n]), 1.0f, 0.0f);
            gtk_container_add(GTK_CONTAINER(selected_ue_vbox[i]), hs->selected_ue_column_entry[i][n]);
            gtk_widget_show(hs->selected_ue_column_entry[i][n]);
        }
    }

    gtk_box_pack_start(GTK_BOX(top_level_vbox), mac_lte_stat_selected_ue_lb, FALSE, FALSE, 0);


    /**************************************/
    /* Filter on RNTI/UEId                */
    /**************************************/
    mac_lte_stat_filters_lb = gtk_frame_new("Filter on UE");

    /* Horizontal row of filter controls */
    filter_buttons_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6, FALSE);
    gtk_container_add(GTK_CONTAINER(mac_lte_stat_filters_lb), filter_buttons_hb);
    gtk_container_set_border_width(GTK_CONTAINER(filter_buttons_hb), 2);

    /* Add filters box to top-level window */
    gtk_box_pack_start(GTK_BOX(top_level_vbox), mac_lte_stat_filters_lb, FALSE, FALSE, 0);

    /* Filter buttons */

    /* UL only */
    hs->ul_filter_bt = gtk_button_new_with_label("Set UL display filter on selected this UE");
    gtk_box_pack_start(GTK_BOX(filter_buttons_hb), hs->ul_filter_bt, FALSE, FALSE, 0);
    g_signal_connect(hs->ul_filter_bt, "clicked", G_CALLBACK(ul_filter_clicked), hs);
    gtk_widget_set_sensitive(hs->ul_filter_bt, FALSE);
    gtk_widget_show(hs->ul_filter_bt);
    gtk_widget_set_tooltip_text(hs->ul_filter_bt,
                         "Generate and set a filter showing only UL frames with selected RNTI and UEId");

    /* DL only */
    hs->dl_filter_bt = gtk_button_new_with_label("Set DL display filter on selected this UE");
    gtk_box_pack_start(GTK_BOX(filter_buttons_hb), hs->dl_filter_bt, FALSE, FALSE, 0);
    g_signal_connect(hs->dl_filter_bt, "clicked", G_CALLBACK(dl_filter_clicked), hs);
    gtk_widget_set_sensitive(hs->dl_filter_bt, FALSE);
    gtk_widget_show(hs->dl_filter_bt);
    gtk_widget_set_tooltip_text(hs->dl_filter_bt,
                         "Generate and set a filter showing only DL frames with selected RNTI and UEId");

    /* UL and DL */
    hs->uldl_filter_bt = gtk_button_new_with_label("Set UL / DL display filter on selected this UE");
    gtk_box_pack_start(GTK_BOX(filter_buttons_hb), hs->uldl_filter_bt, FALSE, FALSE, 0);
    g_signal_connect(hs->uldl_filter_bt, "clicked", G_CALLBACK(uldl_filter_clicked), hs);
    gtk_widget_set_sensitive(hs->uldl_filter_bt, FALSE);
    gtk_widget_show(hs->uldl_filter_bt);
    gtk_widget_set_tooltip_text(hs->uldl_filter_bt,
                         "Generate and set a filter showing only frames with selected RNTI and UEId");

    /* Show MAC RACH */
    hs->show_mac_rach_cb = gtk_check_button_new_with_mnemonic("Show MAC RACH");
    gtk_widget_set_sensitive(hs->show_mac_rach_cb, FALSE);
    gtk_container_add(GTK_CONTAINER(filter_buttons_hb), hs->show_mac_rach_cb);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(hs->show_mac_rach_cb), FALSE);
    gtk_widget_set_tooltip_text(hs->show_mac_rach_cb, "When checked, generated filters will show "
                         "MAC RACH attempts for the UE");

    /* Show MAC SRs */
    hs->show_mac_srs_cb = gtk_check_button_new_with_mnemonic("Show MAC SRs");
    gtk_widget_set_sensitive(hs->show_mac_srs_cb, FALSE);
    gtk_container_add(GTK_CONTAINER(filter_buttons_hb), hs->show_mac_srs_cb);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(hs->show_mac_srs_cb), FALSE);
    gtk_widget_set_tooltip_text(hs->show_mac_srs_cb, "When checked, generated filters will show "
                         "MAC SRs for the UE");


    /* Allow DCT errors to be shown... */
    hs->show_dct_errors_cb = gtk_check_button_new_with_mnemonic("Show DCT2000 error strings");
    gtk_container_add(GTK_CONTAINER(filter_buttons_hb), hs->show_dct_errors_cb);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(hs->show_dct_errors_cb), FALSE);
    g_signal_connect(hs->show_dct_errors_cb, "toggled", G_CALLBACK(mac_lte_dct_errors_cb), hs);
    gtk_widget_set_tooltip_text(hs->show_dct_errors_cb, "When checked, generated filters will "
                         "include DCT2000 error strings");
    /* Initially disabled */
    gtk_widget_set_sensitive(hs->show_dct_errors_cb, FALSE);

    /* ... optionally limited by a substring */
    hs->dct_error_substring_lb = gtk_label_new("...containing");
    gtk_box_pack_start(GTK_BOX(filter_buttons_hb), hs->dct_error_substring_lb, FALSE, FALSE, 0);
    gtk_widget_show(hs->dct_error_substring_lb);
    gtk_widget_set_sensitive(hs->dct_error_substring_lb, FALSE);

    hs->dct_error_substring_te = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(filter_buttons_hb), hs->dct_error_substring_te, FALSE, FALSE, 0);
    gtk_widget_show(hs->dct_error_substring_te);
    gtk_widget_set_sensitive(hs->dct_error_substring_te, FALSE);
    gtk_widget_set_tooltip_text(hs->dct_error_substring_te,
                         "If given, only match error strings containing this substring");


    /**********************************************/
    /* Register the tap listener                  */
    /**********************************************/

    error_string = register_tap_listener("mac-lte", hs,
                                         filter, 0,
                                         mac_lte_stat_reset,
                                         mac_lte_stat_packet,
                                         mac_lte_stat_draw);
    if (error_string) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
        g_string_free(error_string, TRUE);
        g_free(hs);
        return;
    }


    /************************************/
    /* Button row.                      */
    /************************************/

    bbox = dlg_button_row_new (GTK_STOCK_CLOSE, GTK_STOCK_HELP, NULL);
    gtk_box_pack_end (GTK_BOX(top_level_vbox), bbox, FALSE, FALSE, 0);

    /* Add the close button */
    close_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
    window_set_cancel_button(hs->mac_lte_stat_dlg_w, close_bt, window_cancel_button_cb);

    help_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
    g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_STATS_LTE_MAC_TRAFFIC_DIALOG);

    /* Set callbacks */
    g_signal_connect(hs->mac_lte_stat_dlg_w, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
    g_signal_connect(hs->mac_lte_stat_dlg_w, "destroy", G_CALLBACK(win_destroy_cb), hs);

    /* Show the window */
    gtk_widget_show_all(hs->mac_lte_stat_dlg_w);
    window_present(hs->mac_lte_stat_dlg_w);

    /* Retap */
    cf_retap_packets(&cfile);
    gdk_window_raise(gtk_widget_get_window(hs->mac_lte_stat_dlg_w));
}


static tap_param mac_lte_stat_params[] = {
    { PARAM_FILTER, "Filter", NULL }
};

static tap_param_dlg mac_lte_stat_dlg = {
    "LTE MAC Stats",
    "mac-lte,stat",
    gtk_mac_lte_stat_init,
    -1,
    G_N_ELEMENTS(mac_lte_stat_params),
    mac_lte_stat_params
};


/* Register this tap listener (need void on own so line register function found) */
void
register_tap_listener_mac_lte_stat(void)
{
    register_dfilter_stat(&mac_lte_stat_dlg, "_LTE/_MAC", REGISTER_STAT_GROUP_TELEPHONY);
}

void mac_lte_stat_cb(GtkAction *action, gpointer user_data _U_)
{
    tap_param_dlg_cb(action, &mac_lte_stat_dlg);
}


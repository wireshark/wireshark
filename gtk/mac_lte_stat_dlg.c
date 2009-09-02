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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


/* TODO:
   - limit by display filter?
   - Break down traffic by cell?
   - CSV export?
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>

#include <gtk/gtk.h>

#include <epan/packet.h>
#include <epan/packet_info.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-mac-lte.h>

#include "../register.h"
#include "../simple_dialog.h"
#include "../stat_menu.h"

#include "gtk/dlg_utils.h"
#include "gtk/gui_stat_menu.h"
#include "gtk/gui_utils.h"
#include "gtk/help_dlg.h"
#include "gtk/main.h"

/**********************************************/
/* Table column identifiers and title strings */

enum {
    RNTI_COLUMN,
    RNTI_TYPE_COLUMN,
    UL_FRAMES_COLUMN,
    UL_BYTES_COLUMN,
    UL_CRC_ERRORS_COLUMN,
    UL_RETX_FRAMES_COLUMN,
    DL_FRAMES_COLUMN,
    DL_BYTES_COLUMN,
    DL_CRC_ERRORS_COLUMN,
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

static const gchar *ue_titles[] = { "RNTI", "Type",
                                 "UL Frames", "UL Bytes", "UL CRC Errors", "UL ReTX Frames",
                                 "DL Frames", "DL Bytes", "DL CRC Errors", "DL ReTX Frames"};

static const gchar *channel_titles[] = { "CCCH",
                                         "LCID 1", "LCID 2", "LCID 3", "LCID 4", "LCID 5",
                                         "LCID 6", "LCID 7", "LCID 8", "LCID 9", "LCID 10",
                                         "Predefined"};


/* Stats for one UE */
typedef struct mac_lte_row_data {
    /* Key for matching this row */
    guint16 rnti;
    guint8  rnti_type;

    gboolean is_predefined_data;

    guint32 UL_frames;
    guint32 UL_total_bytes;
    guint32 UL_CRC_errors;
    guint32 UL_retx_frames;

    guint32 DL_frames;
    guint32 DL_total_bytes;
    guint32 DL_CRC_errors;
    guint32 DL_retx_frames;

    guint32 UL_bytes_for_lcid[11];
    guint32 UL_sdus_for_lcid[11];
    guint32 DL_bytes_for_lcid[11];
    guint32 DL_sdus_for_lcid[11];
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
} mac_lte_common_stats;

static const char * selected_ue_row_names[] = {"UL SDUs", "UL Bytes", "DL SDUs", "DL Bytes"};

static mac_lte_common_stats common_stats;

static GtkWidget *mac_lte_common_bch_frames;
static GtkWidget *mac_lte_common_bch_bytes;
static GtkWidget *mac_lte_common_pch_frames;
static GtkWidget *mac_lte_common_pch_bytes;
static GtkWidget *mac_lte_common_rar_frames;
static GtkWidget *mac_lte_common_rar_entries;

/* Labels in selected UE 'table' */
static GtkWidget *selected_ue_column_entry[NUM_CHANNEL_COLUMNS][5];


/* Top-level dialog and labels */
static GtkWidget  *mac_lte_stat_dlg_w = NULL;
static GtkWidget  *mac_lte_stat_common_channel_lb = NULL;
static GtkWidget  *mac_lte_stat_ues_lb = NULL;
static GtkWidget  *mac_lte_stat_selected_ue_lb = NULL;


/* Used to keep track of whole MAC LTE statistics window */
typedef struct mac_lte_stat_t {
    GtkTreeView   *ue_table;
    mac_lte_ep_t* ep_list;
} mac_lte_stat_t;


/* Reset the statistics window */
static void
mac_lte_stat_reset(void *phs)
{
    mac_lte_stat_t* mac_lte_stat = (mac_lte_stat_t *)phs;
    mac_lte_ep_t* list = mac_lte_stat->ep_list;
    gchar title[256];
    GtkListStore *store;
    gint i, n;

    /* Set the title */
    if (mac_lte_stat_dlg_w != NULL) {
        g_snprintf(title, sizeof(title), "Wireshark: LTE MAC Traffic Statistics: %s",
                   cf_get_display_name(&cfile));
        gtk_window_set_title(GTK_WINDOW(mac_lte_stat_dlg_w), title);
    }

    g_snprintf(title, sizeof(title), "UL/DL-SCH data (0 UEs)");
    gtk_frame_set_label(GTK_FRAME(mac_lte_stat_ues_lb), title);

    memset(&common_stats, 0, sizeof(common_stats));

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
             gtk_label_set_text(GTK_LABEL(selected_ue_column_entry[i][n]), "0");
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

    /* Counts for new UE are all 0 */
    ep->stats.UL_frames = 0;
    ep->stats.DL_frames = 0;
    ep->stats.UL_total_bytes = 0;
    ep->stats.DL_total_bytes = 0;
    ep->stats.UL_CRC_errors = 0;
    ep->stats.DL_CRC_errors = 0;
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


/* Process stat struct for a MAC LTE frame */
static int
mac_lte_stat_packet(void *phs, packet_info *pinfo, epan_dissect_t *edt _U_,
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

    common_stats.all_frames++;

    /* For common channels, just update global counters */
    switch (si->rntiType) {
        case P_RNTI:
            common_stats.pch_frames++;
            common_stats.pch_bytes += si->single_number_of_bytes;
            return 1;
        case SI_RNTI:
        case NO_RNTI:
            common_stats.bch_frames++;
            common_stats.bch_bytes += si->single_number_of_bytes;
            return 1;
        case RA_RNTI:
            common_stats.rar_frames++;
            common_stats.rar_entries += si->number_of_rars;
            return 1;
        case C_RNTI:
        case SPS_RNTI:
            /* Drop through for per-UE update */
            break;

        default:
            return 0;
    }

    /* For per-UE data, must create a new row if none already existing */
    if (!hs->ep_list) {
        /* Allocate new list */
        hs->ep_list = alloc_mac_lte_ep(si, pinfo);
        /* Make it the first/only entry */
        te = hs->ep_list;
    } else {
        /* Look among existing rows for this RNTI */
        for (tmp = hs->ep_list;(tmp != NULL); tmp = tmp->next) {
            if (tmp->stats.rnti == si->rnti) {
                te = tmp;
                break;
            }
        }

        /* Not found among existing, so create a new one anyway */
        if (te == NULL) {
            if ((te = alloc_mac_lte_ep(si, pinfo))) {
                /* New item is head of list */
                te->next = hs->ep_list;
                hs->ep_list = te;
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
    if (si->crcStatusValid && !si->crcStatus) {
        if (si->direction == DIRECTION_UPLINK) {
            te->stats.UL_CRC_errors++;
            return 1;
        }
        else {
            te->stats.DL_CRC_errors++;
            return 1;
        }
    }

    /* Uplink */
    if (si->direction == DIRECTION_UPLINK) {
        if (si->reTxCount >= 1) {
            te->stats.UL_retx_frames++;
            return 1;
        }
        te->stats.UL_frames++;

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
        if (si->reTxCount >= 1) {
            te->stats.DL_retx_frames++;
            return 1;
        }

        te->stats.DL_frames++;

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
static void
mac_lte_ue_details(mac_lte_ep_t *mac_stat_ep)
{
    int n;
    gchar buff[32];

    /**********************************/
    /* Set data one row at a time     */

    /* UL SDUs */
    for (n=0; n < PREDEFINED_COLUMN-1; n++) {
        g_snprintf(buff, sizeof(buff), "%u",
                   mac_stat_ep ? mac_stat_ep->stats.UL_sdus_for_lcid[n] : 0);
         gtk_label_set_text(GTK_LABEL(selected_ue_column_entry[n+1][1]), buff);
    }

    /* Predefined */
    if (mac_stat_ep) {
        g_snprintf(buff, sizeof(buff), "%u",
                   mac_stat_ep->stats.is_predefined_data ? mac_stat_ep->stats.UL_frames : 0);
    }
    else {
        g_snprintf(buff, sizeof(buff), "%u", 0);
    }
    gtk_label_set_text(GTK_LABEL(selected_ue_column_entry[PREDEFINED_COLUMN][1]), buff);


    /* UL Bytes */
    for (n=0; n < PREDEFINED_COLUMN-1; n++) {
        g_snprintf(buff, sizeof(buff), "%u",
                   (mac_stat_ep) ? mac_stat_ep->stats.UL_bytes_for_lcid[n] : 0);
        gtk_label_set_text(GTK_LABEL(selected_ue_column_entry[n+1][2]), buff);
    }

    /* Predefined */
    if (mac_stat_ep) {
        g_snprintf(buff, sizeof(buff), "%u",
                   mac_stat_ep->stats.is_predefined_data ? mac_stat_ep->stats.UL_total_bytes : 0);
    }
    else {
        g_snprintf(buff, sizeof(buff), "%u", 0);
    }
    gtk_label_set_text(GTK_LABEL(selected_ue_column_entry[PREDEFINED_COLUMN][2]), buff);


    /* DL SDUs */
    for (n=0; n < PREDEFINED_COLUMN-1; n++) {
        g_snprintf(buff, sizeof(buff), "%u",
                   mac_stat_ep ? mac_stat_ep->stats.DL_sdus_for_lcid[n] : 0);
        gtk_label_set_text(GTK_LABEL(selected_ue_column_entry[n+1][3]), buff);
    }
    /* Predefined */
    if (mac_stat_ep) {
        g_snprintf(buff, sizeof(buff), "%u",
                   mac_stat_ep->stats.is_predefined_data ? mac_stat_ep->stats.DL_frames : 0);
    }
    else {
        g_snprintf(buff, sizeof(buff), "%u", 0);
    }
    gtk_label_set_text(GTK_LABEL(selected_ue_column_entry[PREDEFINED_COLUMN][3]), buff);


    /* DL Bytes */
    for (n=0; n < PREDEFINED_COLUMN-1; n++) {
        g_snprintf(buff, sizeof(buff), "%u",
                   mac_stat_ep ? mac_stat_ep->stats.DL_bytes_for_lcid[n] : 0);
        gtk_label_set_text(GTK_LABEL(selected_ue_column_entry[n+1][4]), buff);
    }
    /* Predefined */
    if (mac_stat_ep) {
        g_snprintf(buff, sizeof(buff), "%u",
                   mac_stat_ep->stats.is_predefined_data ? mac_stat_ep->stats.DL_total_bytes : 0);
    }
    else {
        g_snprintf(buff, sizeof(buff), "%u", 0);
    }
    gtk_label_set_text(GTK_LABEL(selected_ue_column_entry[PREDEFINED_COLUMN][4]), buff);
}



/* (Re)draw the whole dialog window */
static void
mac_lte_stat_draw(void *phs)
{
    gchar   buff[32];
    guint16 number_of_ues = 0;
    gchar title[256];

    /* Look up the statistics window */
    mac_lte_stat_t *hs = (mac_lte_stat_t *)phs;
    mac_lte_ep_t* list = hs->ep_list, *tmp = 0;

    GtkListStore *ues_store;
    GtkTreeSelection *sel;
    GtkTreeModel *model;
    GtkTreeIter iter;

    /* Common channel data */
    g_snprintf(buff, sizeof(buff), "BCH Frames: %u", common_stats.bch_frames);
    gtk_label_set_text(GTK_LABEL(mac_lte_common_bch_frames), buff);
    g_snprintf(buff, sizeof(buff), "BCH Bytes: %u", common_stats.bch_bytes);
    gtk_label_set_text(GTK_LABEL(mac_lte_common_bch_bytes), buff);
    g_snprintf(buff, sizeof(buff), "PCH Frames: %u", common_stats.pch_frames);
    gtk_label_set_text(GTK_LABEL(mac_lte_common_pch_frames), buff);
    g_snprintf(buff, sizeof(buff), "PCH Bytes: %u", common_stats.pch_bytes);
    gtk_label_set_text(GTK_LABEL(mac_lte_common_pch_bytes), buff);
    g_snprintf(buff, sizeof(buff), "RAR Frames: %u", common_stats.rar_frames);
    gtk_label_set_text(GTK_LABEL(mac_lte_common_rar_frames), buff);
    g_snprintf(buff, sizeof(buff), "RAR Entries: %u", common_stats.rar_entries);
    gtk_label_set_text(GTK_LABEL(mac_lte_common_rar_entries), buff);


    /* Per-UE table entries */
    ues_store = GTK_LIST_STORE(gtk_tree_view_get_model(hs->ue_table));

    /* Set title that shows how many UEs currently in table */
    for (tmp = list; (tmp!=NULL); tmp=tmp->next, number_of_ues++);
    g_snprintf(title, sizeof(title), "UL/DL-SCH data (%u UEs)", number_of_ues);
    gtk_frame_set_label(GTK_FRAME(mac_lte_stat_ues_lb), title);

    /* Update title to include number of UEs and frames */
    g_snprintf(title, sizeof(title), "Wireshark: LTE MAC Traffic Statistics: %s (%u UEs, %u frames)",
               cf_get_display_name(&cfile),
               number_of_ues,
               common_stats.all_frames);
    gtk_window_set_title(GTK_WINDOW(mac_lte_stat_dlg_w), title);



    /* For each row/UE/C-RNTI in the model */
    for (tmp = list; tmp; tmp=tmp->next) {
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
                           UL_FRAMES_COLUMN, tmp->stats.UL_frames,
                           UL_BYTES_COLUMN, tmp->stats.UL_total_bytes,
                           UL_CRC_ERRORS_COLUMN, tmp->stats.UL_CRC_errors,
                           UL_RETX_FRAMES_COLUMN, tmp->stats.UL_retx_frames,
                           DL_FRAMES_COLUMN, tmp->stats.DL_frames,
                           DL_BYTES_COLUMN, tmp->stats.DL_total_bytes,
                           DL_CRC_ERRORS_COLUMN, tmp->stats.DL_CRC_errors,
                           DL_RETX_FRAMES_COLUMN, tmp->stats.DL_retx_frames,
                           TABLE_COLUMN, tmp,
                           -1);
    }

    /* If there is a UE selected, update its counters in details window */
    sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(hs->ue_table));
    if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
        mac_lte_ep_t *ep;

        gtk_tree_model_get(model, &iter, TABLE_COLUMN, &ep, -1);
        mac_lte_ue_details(ep);
    }
}


/* What to do when a list item is selected/unselected */
static void mac_lte_select_cb(GtkTreeSelection *sel, gpointer data _U_)
{
    mac_lte_ep_t   *ep;
    GtkTreeModel   *model;
    GtkTreeIter    iter;

    if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
        /* Show details of selected UE */
        gtk_tree_model_get(model, &iter, TABLE_COLUMN, &ep, -1);
        mac_lte_ue_details(ep);
    }
    else {
        mac_lte_ue_details(NULL);
    }
}



/* Destroy the stats window */
static void win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
    mac_lte_stat_t *hs = (mac_lte_stat_t *)data;

    protect_thread_critical_region();
    remove_tap_listener(hs);
    unprotect_thread_critical_region();

    if (mac_lte_stat_dlg_w != NULL) {
        window_destroy(mac_lte_stat_dlg_w);
        mac_lte_stat_dlg_w = NULL;
    }
    mac_lte_stat_reset(hs);
    g_free(hs);
}


/* Create a new MAC LTE stats dialog */
static void mac_lte_stat_dlg_create(void)
{
    mac_lte_stat_t    *hs;
    GString       *error_string;
    GtkWidget     *ues_scrolled_window;
    GtkWidget     *bbox;
    GtkWidget     *top_level_vbox;

    GtkWidget     *common_row_hbox;
    GtkWidget     *ues_vb;
    GtkWidget     *selected_ue_hb;

    GtkWidget     *selected_ue_vbox[NUM_CHANNEL_COLUMNS];
    GtkWidget     *selected_ue_column_titles[5];

    GtkWidget     *close_bt;
    GtkWidget     *help_bt;

    GtkListStore  *store;

    GtkTreeView       *tree_view;
    GtkCellRenderer   *renderer;
    GtkTreeViewColumn *column;
    GtkTreeSelection  *sel;
    gchar title[256];
    gint i, n;

    /* Create dialog */
    hs = g_malloc(sizeof(mac_lte_stat_t));
    hs->ep_list = NULL;

    /* Set title */
    g_snprintf(title, sizeof(title), "Wireshark: LTE MAC Statistics: %s",
               cf_get_display_name(&cfile));
    mac_lte_stat_dlg_w = window_new_with_geom(GTK_WINDOW_TOPLEVEL, title, "LTE MAC Statistics");

    /* Window size */
    gtk_window_set_default_size(GTK_WINDOW(mac_lte_stat_dlg_w), 750, 300);

    /* Will stack widgets vertically inside dlg */
    top_level_vbox = gtk_vbox_new(FALSE, 3);       /* FALSE = not homogeneous */
    gtk_container_add(GTK_CONTAINER(mac_lte_stat_dlg_w), top_level_vbox);

    gtk_container_set_border_width(GTK_CONTAINER(top_level_vbox), 6);
    gtk_widget_show(top_level_vbox);


    /**********************************************/
    /* Common Channel data                        */
    /**********************************************/
    mac_lte_stat_common_channel_lb = gtk_frame_new("Common Channel Data");

    /* Will add BCH and PCH counters into one row */
    common_row_hbox = gtk_hbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER(mac_lte_stat_common_channel_lb), common_row_hbox);
    gtk_container_set_border_width(GTK_CONTAINER(common_row_hbox), 5);

    gtk_box_pack_start(GTK_BOX(top_level_vbox), mac_lte_stat_common_channel_lb, FALSE, FALSE, 0);

    /* Create labels (that will hold label and counter value) */
    mac_lte_common_bch_frames = gtk_label_new("BCH Frames:");
    gtk_misc_set_alignment(GTK_MISC(mac_lte_common_bch_frames), 0.0f, .5f);
    gtk_container_add(GTK_CONTAINER(common_row_hbox), mac_lte_common_bch_frames);
    gtk_widget_show(mac_lte_common_bch_frames);

    mac_lte_common_bch_bytes = gtk_label_new("BCH Bytes:");
    gtk_misc_set_alignment(GTK_MISC(mac_lte_common_bch_bytes), 0.0f, .5f);
    gtk_container_add(GTK_CONTAINER(common_row_hbox), mac_lte_common_bch_bytes);
    gtk_widget_show(mac_lte_common_bch_bytes);

    mac_lte_common_pch_frames = gtk_label_new("PCH Frames:");
    gtk_misc_set_alignment(GTK_MISC(mac_lte_common_pch_frames), 0.0f, .5f);
    gtk_container_add(GTK_CONTAINER(common_row_hbox), mac_lte_common_pch_frames);
    gtk_widget_show(mac_lte_common_pch_frames);

    mac_lte_common_pch_bytes = gtk_label_new("PCH Bytes:");
    gtk_misc_set_alignment(GTK_MISC(mac_lte_common_pch_bytes), 0.0f, .5f);
    gtk_container_add(GTK_CONTAINER(common_row_hbox), mac_lte_common_pch_bytes);
    gtk_widget_show(mac_lte_common_pch_bytes);

    mac_lte_common_rar_frames = gtk_label_new("RAR Frames:");
    gtk_misc_set_alignment(GTK_MISC(mac_lte_common_rar_frames), 0.0f, .5f);
    gtk_container_add(GTK_CONTAINER(common_row_hbox), mac_lte_common_rar_frames);
    gtk_widget_show(mac_lte_common_rar_frames);

    mac_lte_common_rar_entries = gtk_label_new("RAR Entries:");
    gtk_misc_set_alignment(GTK_MISC(mac_lte_common_rar_entries), 0.0f, .5f);
    gtk_container_add(GTK_CONTAINER(common_row_hbox), mac_lte_common_rar_entries);
    gtk_widget_show(mac_lte_common_rar_entries);

    /**********************************************/
    /* UL/DL-SCH data                             */
    /**********************************************/

    mac_lte_stat_ues_lb = gtk_frame_new("UL/DL-SCH Data (0 UEs)");
    ues_vb = gtk_vbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER(mac_lte_stat_ues_lb), ues_vb);
    gtk_container_set_border_width(GTK_CONTAINER(ues_vb), 5);

    ues_scrolled_window = scrolled_window_new(NULL, NULL);
    gtk_box_pack_start(GTK_BOX(ues_vb), ues_scrolled_window, TRUE, TRUE, 0);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(ues_scrolled_window),
                                        GTK_SHADOW_IN);

    /* Create the table of UE data */
    store = gtk_list_store_new(NUM_UE_COLUMNS, G_TYPE_INT, G_TYPE_STRING,
                               G_TYPE_INT, G_TYPE_INT, G_TYPE_INT, G_TYPE_INT,  /* UL */
                               G_TYPE_INT, G_TYPE_INT, G_TYPE_INT, G_TYPE_INT,  /* DL */
                               G_TYPE_POINTER);
    hs->ue_table = GTK_TREE_VIEW(tree_view_new(GTK_TREE_MODEL(store)));
    gtk_container_add(GTK_CONTAINER (ues_scrolled_window), GTK_WIDGET(hs->ue_table));
    g_object_unref(G_OBJECT(store));

    tree_view = hs->ue_table;
    gtk_tree_view_set_headers_visible(tree_view, TRUE);
    gtk_tree_view_set_headers_clickable(tree_view, TRUE);

    /* Create the titles for each column of the per-UE table */
    for (i = 0; i < TABLE_COLUMN; i++) {
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
    g_signal_connect(sel, "changed", G_CALLBACK(mac_lte_select_cb), hs);

    gtk_box_pack_start(GTK_BOX(top_level_vbox), mac_lte_stat_ues_lb, TRUE, TRUE, 0);


    /**********************************************/
    /* Details of selected UE                     */
    /**********************************************/

    mac_lte_stat_selected_ue_lb = gtk_frame_new("Selected UE details");

    selected_ue_hb = gtk_hbox_new(FALSE, 6);
    gtk_container_add(GTK_CONTAINER(mac_lte_stat_selected_ue_lb), selected_ue_hb);
    gtk_container_set_border_width(GTK_CONTAINER(selected_ue_hb), 5);

    /********************************/
    /* First (row titles) column    */
    selected_ue_vbox[0] = gtk_vbox_new(FALSE, 0);
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
        selected_ue_vbox[i] = gtk_vbox_new(FALSE, 0);
        gtk_container_add(GTK_CONTAINER(selected_ue_hb), selected_ue_vbox[i]);

        /* Channel title */
        selected_ue_column_entry[i][0] = gtk_label_new(channel_titles[i-1]);
        gtk_misc_set_alignment(GTK_MISC(selected_ue_column_entry[i][0]), 0.5f, 0.0f);
        gtk_container_add(GTK_CONTAINER(selected_ue_vbox[i]), selected_ue_column_entry[i][0]);


        /* Counts for this channel */
        for (n=1; n < 5; n++) {
            selected_ue_column_entry[i][n] = gtk_label_new("0");
            gtk_misc_set_alignment(GTK_MISC(selected_ue_column_entry[i][n]), 1.0f, 0.0f);
            gtk_container_add(GTK_CONTAINER(selected_ue_vbox[i]), selected_ue_column_entry[i][n]);
            gtk_widget_show(selected_ue_column_entry[i][n]);
        }
    }

    gtk_box_pack_start(GTK_BOX(top_level_vbox), mac_lte_stat_selected_ue_lb, FALSE, FALSE, 0);


    /**********************************************/
    /* Register the tap listener                  */
    /**********************************************/

    error_string = register_tap_listener("mac-lte", hs, NULL, 0,
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
    window_set_cancel_button(mac_lte_stat_dlg_w, close_bt, window_cancel_button_cb);

    help_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
    g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_STATS_LTE_MAC_TRAFFIC_DIALOG);

    /* Set callbacks */
    g_signal_connect(mac_lte_stat_dlg_w, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
    g_signal_connect(mac_lte_stat_dlg_w, "destroy", G_CALLBACK(win_destroy_cb), hs);

    /* Show the window */
    gtk_widget_show_all(mac_lte_stat_dlg_w);
    window_present(mac_lte_stat_dlg_w);

    /* Retap */
    cf_retap_packets(&cfile);
    gdk_window_raise(mac_lte_stat_dlg_w->window);
}


/* Show window, creating if necessary */
static void mac_lte_stat_launch(GtkWidget *w _U_, gpointer data _U_)
{
    if (mac_lte_stat_dlg_w) {
        reactivate_window(mac_lte_stat_dlg_w);
    } else {
        mac_lte_stat_dlg_create();
    }
}

/* Register this tap listener (need void on own so line register function found) */
void
register_tap_listener_mac_lte_stat(void)
{
    register_stat_menu_item("_LTE MAC...", REGISTER_STAT_GROUP_TELEPHONY,
                            mac_lte_stat_launch, NULL, NULL, NULL);
}


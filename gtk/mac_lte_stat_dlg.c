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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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
#include <epan/strutil.h>

#include "../register.h"
#include "../simple_dialog.h"
#include "../globals.h"
#include "../stat_menu.h"
#include "../isprint.h"

#include "gtk/gtkglobals.h"
#include "gtk/dlg_utils.h"
#include "gtk/gui_stat_menu.h"
#include "gtk/gui_utils.h"
#include "gtk/recent.h"
#include "gtk/help_dlg.h"
#include "gtk/main.h"

/**********************************************/
/* Table column identifiers and title strings */
enum {
    BCH_FRAMES_COLUMN,
    BCH_BYTES_COLUMN,
    PCH_FRAMES_COLUMN,
    PCH_BYTES_COLUMN,
    NUM_COMMON_COLUMNS
};

enum {
    RNTI_COLUMN,
    UL_FRAMES_COLUMN,
    UL_BYTES_COLUMN,
    DL_FRAMES_COLUMN,
    DL_BYTES_COLUMN,
    TABLE_COLUMN,
    NUM_UE_COLUMNS
};

enum {
    ROWS_COLUMN,
    CCCH_COLUMN,
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

static const gchar *ue_titles[] = { "RNTI",
                                 "UL Frames", "UL Bytes",
                                 "DL Frames", "DL Bytes" };

static const gchar *common_titles[] = { "BCH Frames", "BCH Bytes",
                                        "PCH Frames", "PCH Bytes" };

static const gchar *channel_titles[] = { "", "CCCH",
                                         "LCID 1", "LCID 2", "LCID 3", "LCID 4", "LCID 5",
                                         "LCID 6", "LCID 7", "LCID 8", "LCID 9", "LCID 10",
                                         "Predefined"};


/* Stats for one UE */
typedef struct mac_lte_row_data {
    /* Key for matching this row */
    guint16 rnti;

    gboolean is_predefined_data;

    guint32 UL_frames;
    guint32 UL_total_bytes;

    guint32 DL_frames;
    guint32 DL_total_bytes;

    guint32 UL_bytes_for_lcid[11];
    guint32 UL_sdus_for_lcid[11];
    guint32 DL_bytes_for_lcid[11];
    guint32 DL_sdus_for_lcid[11];
} mac_lte_row_data;


/* One row/UE in the UE table */
typedef struct mac_lte_ep {
    struct mac_lte_ep* next;
    struct mac_lte_row_data stats;
    guint32 number_of_packets;
    GtkTreeIter iter;
    gboolean iter_valid;
} mac_lte_ep_t;


/* Common channel stats */
static gint common_row_added = FALSE;
static GtkTreeIter common_row_iter;

typedef struct mac_lte_common_stats {
    guint32 bch_frames;
    guint32 bch_bytes;
    guint32 pch_frames;
    guint32 pch_bytes;
} mac_lte_common_stats;

static mac_lte_common_stats common_stats;


/* Keeping track of the 4 rows in UE details table */
static gint ue_detail_rows_added = FALSE;
static GtkTreeIter ue_detail_iter[4];


/* Top-level dialog and labels */
static GtkWidget  *mac_lte_stat_dlg_w = NULL;
static GtkWidget  *mac_lte_stat_common_channel_lb = NULL;
static GtkWidget  *mac_lte_stat_ues_lb = NULL;
static GtkWidget  *mac_lte_stat_selected_ue_lb = NULL;


/* Used to keep track of whole MAC LTE statistics window */
typedef struct mac_lte_stat_t {
    GtkTreeView   *common_channel_table;
    GtkTreeView   *ue_table;
    GtkTreeView   *selected_ue_table;
    guint32       number_of_packets;
    guint32       num_entries;
    mac_lte_ep_t* ep_list;
} mac_lte_stat_t;


/* Reset the statistics window */
static void
mac_lte_stat_reset(void *phs)
{
    mac_lte_stat_t* mac_lte_stat = (mac_lte_stat_t *)phs;
    mac_lte_ep_t* list = mac_lte_stat->ep_list;
    char title[256];
    GtkListStore *store;

    /* Set the title */
    if (mac_lte_stat_dlg_w != NULL) {
        g_snprintf (title, 255, "Wireshark: LTE MAC Traffic Statistics: %s",
                    cf_get_display_name(&cfile));
        gtk_window_set_title(GTK_WINDOW(mac_lte_stat_dlg_w), title);
    }

    g_snprintf(title, 255, "UL/DL-SCH data");
    gtk_frame_set_label(GTK_FRAME(mac_lte_stat_ues_lb), title);


    /* Remove the entry from the common channel list */
    store = GTK_LIST_STORE(gtk_tree_view_get_model(mac_lte_stat->common_channel_table));
    gtk_list_store_clear(store);
    common_row_added = FALSE;
    memset(&common_stats, 0, sizeof(common_stats));

    /* Forget that detail rows were already added */
    ue_detail_rows_added = FALSE;

    /* Remove all entries from the UE list */
    store = GTK_LIST_STORE(gtk_tree_view_get_model(mac_lte_stat->ue_table));
    gtk_list_store_clear(store);

    if (!list) {
        return;
    }

    mac_lte_stat->ep_list = NULL;
    mac_lte_stat->number_of_packets = 0;
}


/* Allocate a mac_lte_ep_t struct to store info for new UE */
static mac_lte_ep_t*
alloc_mac_lte_ep(struct mac_lte_tap_info *si, packet_info *pinfo _U_)
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
    ep->number_of_packets = 0;
    ep->stats.rnti = si->rnti;

    /* Counts for new UE are all 0 */
    ep->stats.UL_frames = 0;
    ep->stats.DL_frames = 0;
    ep->stats.UL_total_bytes = 0;
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
        return (0);
    }

    hs->number_of_packets++;

    /* For common channels, just update global counters */
    switch (si->rnti_type) {
        case P_RNTI:
            common_stats.pch_frames++;
            common_stats.pch_bytes += si->single_number_of_bytes;
            return 1;
        case SI_RNTI:
        case NO_RNTI:
            common_stats.bch_frames++;
            common_stats.bch_bytes += si->single_number_of_bytes;
            return 1;

        default:
            break;
    }


    /* For per-UE data, must create a new row if none already existing */
    if (!hs->ep_list) {
        hs->ep_list = alloc_mac_lte_ep(si, pinfo);
        te = hs->ep_list;
    } else {
        /* Look among existing rows for this RNTI */
        for (tmp = hs->ep_list; tmp; tmp = tmp->next) {
            if (tmp->stats.rnti == si->rnti) {
                te = tmp;
                break;
            }
        }

        /* Not found among existing, so create a new one anyway */
        if (!te) {
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
    te->number_of_packets++;
    te->stats.rnti = si->rnti;
    te->stats.is_predefined_data = si->is_predefined_data;
    if (si->direction == DIRECTION_UPLINK) {
        te->stats.UL_frames++;
        for (n=0; n < 11; n++) {
            if (si->bytes_for_lcid[n]) {
                te->stats.UL_sdus_for_lcid[n]++;
            }
            te->stats.UL_bytes_for_lcid[n] += si->bytes_for_lcid[n];
            te->stats.UL_total_bytes += si->bytes_for_lcid[n];
        }
    }
    else {
        te->stats.DL_frames++;
        for (n=0; n < 11; n++) {
            if (si->bytes_for_lcid[n]) {
                te->stats.DL_sdus_for_lcid[n]++;
            }
            te->stats.DL_bytes_for_lcid[n] += si->bytes_for_lcid[n];
            te->stats.DL_total_bytes += si->bytes_for_lcid[n];
        }
    }

    return 1;
}


static void invalidate_ues_iters(mac_lte_stat_t *hs)
{
    mac_lte_ep_t *ep = hs->ep_list;
    mac_lte_ep_t *d_ep;

    /* Set 'valid' pointer in each entry in list of FALSE */
    while (ep) {
        d_ep = ep;
        while (d_ep) {
            d_ep->iter_valid = FALSE;
            d_ep = d_ep->next;
        }
        ep = ep->next;
    }
}


/* Draw the UE details table according to the current UE selection */
static void
mac_lte_ue_details(mac_lte_stat_t *hs, mac_lte_ep_t *mac_stat_ep, gboolean clear)
{
    int n;
    static const char * row_names[] = {"UL SDUs", "UL Bytes", "DL SDUs", "DL Bytes"};
    GtkListStore *store;
    store = GTK_LIST_STORE(gtk_tree_view_get_model(hs->selected_ue_table));

    /* Clear details if necessary */
    if (clear) {
        gtk_list_store_clear(store);
        invalidate_ues_iters(hs);
        ue_detail_rows_added = FALSE;
    }

    /* Add rows if necessary */
    if (!ue_detail_rows_added) {
        for (n=0; n < 4; n++) {
            gtk_list_store_append(store, &ue_detail_iter[n]);
        }
        ue_detail_rows_added = TRUE;
    }

    /**********************************/
    /* Set data in rows               */

    /* UL SDUs */
    gtk_list_store_set(store, &ue_detail_iter[0],
                       ROWS_COLUMN,   row_names[0],
                       CCCH_COLUMN,   mac_stat_ep->stats.UL_sdus_for_lcid[0],
                       LCID1_COLUMN,  mac_stat_ep->stats.UL_sdus_for_lcid[1],
                       LCID2_COLUMN,  mac_stat_ep->stats.UL_sdus_for_lcid[2],
                       LCID3_COLUMN,  mac_stat_ep->stats.UL_sdus_for_lcid[3],
                       LCID4_COLUMN,  mac_stat_ep->stats.UL_sdus_for_lcid[4],
                       LCID5_COLUMN,  mac_stat_ep->stats.UL_sdus_for_lcid[5],
                       LCID6_COLUMN,  mac_stat_ep->stats.UL_sdus_for_lcid[6],
                       LCID7_COLUMN,  mac_stat_ep->stats.UL_sdus_for_lcid[7],
                       LCID8_COLUMN,  mac_stat_ep->stats.UL_sdus_for_lcid[8],
                       LCID9_COLUMN,  mac_stat_ep->stats.UL_sdus_for_lcid[9],
                       LCID10_COLUMN, mac_stat_ep->stats.UL_sdus_for_lcid[10],
                       PREDEFINED_COLUMN, mac_stat_ep->stats.is_predefined_data ?
                                            mac_stat_ep->stats.UL_frames : 0,
                       -1);

    /* UL Bytes */
    gtk_list_store_set(store, &ue_detail_iter[1],
                       ROWS_COLUMN,   row_names[1],
                       CCCH_COLUMN,   mac_stat_ep->stats.UL_bytes_for_lcid[0],
                       LCID1_COLUMN,  mac_stat_ep->stats.UL_bytes_for_lcid[1],
                       LCID2_COLUMN,  mac_stat_ep->stats.UL_bytes_for_lcid[2],
                       LCID3_COLUMN,  mac_stat_ep->stats.UL_bytes_for_lcid[3],
                       LCID4_COLUMN,  mac_stat_ep->stats.UL_bytes_for_lcid[4],
                       LCID5_COLUMN,  mac_stat_ep->stats.UL_bytes_for_lcid[5],
                       LCID6_COLUMN,  mac_stat_ep->stats.UL_bytes_for_lcid[6],
                       LCID7_COLUMN,  mac_stat_ep->stats.UL_bytes_for_lcid[7],
                       LCID8_COLUMN,  mac_stat_ep->stats.UL_bytes_for_lcid[8],
                       LCID9_COLUMN,  mac_stat_ep->stats.UL_bytes_for_lcid[9],
                       LCID10_COLUMN, mac_stat_ep->stats.UL_bytes_for_lcid[10],
                       PREDEFINED_COLUMN, mac_stat_ep->stats.is_predefined_data ?
                                            mac_stat_ep->stats.UL_total_bytes : 0,
                       -1);


    /* DL SDUs */
    gtk_list_store_set(store, &ue_detail_iter[2],
                       ROWS_COLUMN,   row_names[2],
                       CCCH_COLUMN,   mac_stat_ep->stats.DL_sdus_for_lcid[0],
                       LCID1_COLUMN,  mac_stat_ep->stats.DL_sdus_for_lcid[1],
                       LCID2_COLUMN,  mac_stat_ep->stats.DL_sdus_for_lcid[2],
                       LCID3_COLUMN,  mac_stat_ep->stats.DL_sdus_for_lcid[3],
                       LCID4_COLUMN,  mac_stat_ep->stats.DL_sdus_for_lcid[4],
                       LCID5_COLUMN,  mac_stat_ep->stats.DL_sdus_for_lcid[5],
                       LCID6_COLUMN,  mac_stat_ep->stats.DL_sdus_for_lcid[6],
                       LCID7_COLUMN,  mac_stat_ep->stats.DL_sdus_for_lcid[7],
                       LCID8_COLUMN,  mac_stat_ep->stats.DL_sdus_for_lcid[8],
                       LCID9_COLUMN,  mac_stat_ep->stats.DL_sdus_for_lcid[9],
                       LCID10_COLUMN, mac_stat_ep->stats.DL_sdus_for_lcid[10],
                       PREDEFINED_COLUMN, mac_stat_ep->stats.is_predefined_data ?
                                            mac_stat_ep->stats.DL_frames : 0,
                       -1);

    /* DL Bytes */
    gtk_list_store_set(store, &ue_detail_iter[3],
                       ROWS_COLUMN,   row_names[3],
                       CCCH_COLUMN,   mac_stat_ep->stats.DL_bytes_for_lcid[0],
                       LCID1_COLUMN,  mac_stat_ep->stats.DL_bytes_for_lcid[1],
                       LCID2_COLUMN,  mac_stat_ep->stats.DL_bytes_for_lcid[2],
                       LCID3_COLUMN,  mac_stat_ep->stats.DL_bytes_for_lcid[3],
                       LCID4_COLUMN,  mac_stat_ep->stats.DL_bytes_for_lcid[4],
                       LCID5_COLUMN,  mac_stat_ep->stats.DL_bytes_for_lcid[5],
                       LCID6_COLUMN,  mac_stat_ep->stats.DL_bytes_for_lcid[6],
                       LCID7_COLUMN,  mac_stat_ep->stats.DL_bytes_for_lcid[7],
                       LCID8_COLUMN,  mac_stat_ep->stats.DL_bytes_for_lcid[8],
                       LCID9_COLUMN,  mac_stat_ep->stats.DL_bytes_for_lcid[9],
                       LCID10_COLUMN, mac_stat_ep->stats.DL_bytes_for_lcid[10],
                       PREDEFINED_COLUMN, mac_stat_ep->stats.is_predefined_data ?
                                            mac_stat_ep->stats.DL_total_bytes : 0,
                       -1);
}



/* (Re)draw the whole dialog window */
static void
mac_lte_stat_draw(void *phs)
{
    /* Look up the statistics window */
    mac_lte_stat_t *hs = (mac_lte_stat_t *)phs;
    mac_lte_ep_t* list = hs->ep_list, *tmp = 0;

    GtkListStore *common_store;
    GtkListStore *ues_store;
    GtkTreeSelection *sel;
    GtkTreeModel *model;
    GtkTreeIter iter;

    /* Common channel data */
    common_store = GTK_LIST_STORE(gtk_tree_view_get_model(hs->common_channel_table));
    if (!common_row_added) {
        gtk_list_store_append(common_store, &common_row_iter);
        common_row_added = TRUE;
    }

    /* Set the entries of this lists single row */
    gtk_list_store_set(common_store, &common_row_iter,
                       BCH_FRAMES_COLUMN, common_stats.bch_frames,
                       BCH_BYTES_COLUMN, common_stats.bch_bytes,
                       PCH_FRAMES_COLUMN, common_stats.pch_frames,
                       PCH_BYTES_COLUMN, common_stats.pch_bytes,
                       -1);

    /* Per-UE table entries */
    ues_store = GTK_LIST_STORE(gtk_tree_view_get_model(hs->ue_table));
    hs->num_entries = 0;

    /* For each row/UE/C-RNTI */
    for (tmp = list; tmp; tmp=tmp->next) {
        if (tmp->iter_valid != TRUE) {
            gtk_list_store_append(ues_store, &tmp->iter);
            tmp->iter_valid = TRUE;
        }

        /* Set each column for this row */
        gtk_list_store_set(ues_store, &tmp->iter,
                           RNTI_COLUMN, tmp->stats.rnti,
                           UL_FRAMES_COLUMN, tmp->stats.UL_frames,
                           UL_BYTES_COLUMN, tmp->stats.UL_total_bytes,
                           DL_FRAMES_COLUMN, tmp->stats.DL_frames,
                           DL_BYTES_COLUMN, tmp->stats.DL_total_bytes,
                           TABLE_COLUMN, tmp,
                           -1);

        hs->num_entries++;
    }

    /* If there is a UE selected, update its counters in details window */
    sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(hs->ue_table));
    if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
        mac_lte_ep_t *ep;

        gtk_tree_model_get(model, &iter, TABLE_COLUMN, &ep, -1);
        mac_lte_ue_details(hs, ep, FALSE);
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
        mac_lte_ue_details(hs, ep, TRUE);
    }
}



/* Destroy the stats window */
static void win_destroy_cb (GtkWindow *win _U_, gpointer data)
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
static void mac_lte_stat_dlg_create (void)
{
    mac_lte_stat_t    *hs;
    GString       *error_string;
    GtkWidget     *common_scrolled_window;
    GtkWidget     *ues_scrolled_window;
    GtkWidget     *selected_ue_scrolled_window;
    GtkWidget     *bbox;
    GtkWidget     *top_level_vbox;

    GtkWidget     *common_vb;
    GtkWidget     *ues_vb;
    GtkWidget     *selected_ue_vb;

    GtkWidget     *close_bt;
    GtkListStore  *common_channel_store;
    GtkListStore  *store;
    GtkListStore  *selected_ue_store;
    
    GtkTreeView       *common_channel_tree_view;
    GtkTreeView       *tree_view;
    GtkCellRenderer   *renderer;
    GtkTreeViewColumn *column;
    GtkTreeSelection  *sel;
    /* GtkObject         *adjustment; */
    char title[256];
    gint i;

    /* Create dialog */
    hs = g_malloc(sizeof(mac_lte_stat_t));
    hs->num_entries = 0;
    hs->ep_list = NULL;
    hs->number_of_packets = 0;

    /* Set title */
    g_snprintf(title, 255, "Wireshark: LTE MAC Statistics: %s",
               cf_get_display_name(&cfile));
    mac_lte_stat_dlg_w = window_new_with_geom(GTK_WINDOW_TOPLEVEL, title, "LTE MAC Statistics");

    /* Window size */
    gtk_window_set_default_size(GTK_WINDOW(mac_lte_stat_dlg_w), 750, 400);

    /* Will stack widgets vertically inside dlg */
    top_level_vbox = gtk_vbox_new(FALSE, 3);       /* FALSE = not homogeneous */
    gtk_container_add(GTK_CONTAINER(mac_lte_stat_dlg_w), top_level_vbox);

    gtk_container_set_border_width(GTK_CONTAINER(top_level_vbox), 6);
    gtk_widget_show(top_level_vbox);


    /**********************************************/
    /* Common Channel data                        */
    /**********************************************/
    mac_lte_stat_common_channel_lb = gtk_frame_new("Common Channel Data");

    common_vb = gtk_vbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER(mac_lte_stat_common_channel_lb), common_vb);
    gtk_container_set_border_width(GTK_CONTAINER(common_vb), 5);

    /* adjustment = gtk_adjustment_new(10.0, 10.0, 100.0, 100.0, 100.0, 100.0); */
    common_scrolled_window = scrolled_window_new(NULL, NULL); /* (GTK_ADJUSTMENT(adjustment)); */

    gtk_box_pack_start(GTK_BOX(common_vb), common_scrolled_window, TRUE, TRUE, 0);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(common_scrolled_window),
                                        GTK_SHADOW_IN);

    /* Create the table of common data */
    common_channel_store = gtk_list_store_new(NUM_COMMON_COLUMNS,
                                              G_TYPE_INT,  /* BCH frames */
                                              G_TYPE_INT,  /* BCH bytes */
                                              G_TYPE_INT,  /* PCH frames */
                                              G_TYPE_INT); /* PCH bytes */

    hs->common_channel_table = GTK_TREE_VIEW(tree_view_new(GTK_TREE_MODEL(common_channel_store)));
    gtk_container_add(GTK_CONTAINER(common_scrolled_window), GTK_WIDGET(hs->common_channel_table));
    g_object_unref(G_OBJECT(common_channel_store));

    common_channel_tree_view = hs->common_channel_table;
    gtk_tree_view_set_headers_visible(common_channel_tree_view, TRUE);
    gtk_tree_view_set_headers_clickable(common_channel_tree_view, TRUE);

    /* Create the titles for each column of the per-UE table */
    for (i = 0; i < NUM_COMMON_COLUMNS; i++) {
        renderer = gtk_cell_renderer_text_new();
        column = gtk_tree_view_column_new_with_attributes(common_titles[i], renderer,
                                                          "text", i, NULL);
        gtk_tree_view_column_set_sort_column_id(column, i);

        gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
        gtk_tree_view_column_set_resizable(column, TRUE);
        gtk_tree_view_append_column(common_channel_tree_view, column);

    }

    gtk_box_pack_start(GTK_BOX(top_level_vbox), mac_lte_stat_common_channel_lb, FALSE, FALSE, 0);



    /**********************************************/
    /* UL/DL-SCH data                             */
    /**********************************************/

    mac_lte_stat_ues_lb = gtk_frame_new("UL/DL-SCH Data");
    ues_vb = gtk_vbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER(mac_lte_stat_ues_lb), ues_vb);
    gtk_container_set_border_width(GTK_CONTAINER(ues_vb), 5);

    ues_scrolled_window = scrolled_window_new(NULL, NULL);
    gtk_box_pack_start(GTK_BOX(ues_vb), ues_scrolled_window, TRUE, TRUE, 0);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(ues_scrolled_window),
                                        GTK_SHADOW_IN);

    /* Create the table of UE data */
    store = gtk_list_store_new(NUM_UE_COLUMNS, G_TYPE_INT,
                               G_TYPE_INT, G_TYPE_INT,  /* UL */
                               G_TYPE_INT, G_TYPE_INT,  /* DL */
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

        gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
        gtk_tree_view_column_set_resizable(column, TRUE);
        gtk_tree_view_append_column(tree_view, column);
    }

    /* Set callback function for selecting a row in the UE table */
    sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(hs->ue_table));
    gtk_tree_selection_set_mode(sel, GTK_SELECTION_SINGLE);
    g_signal_connect(sel, "changed", G_CALLBACK(mac_lte_select_cb), hs);

    gtk_box_pack_start(GTK_BOX(top_level_vbox), mac_lte_stat_ues_lb, FALSE, FALSE, 0);


    /**********************************************/
    /* Details of selected UE                     */
    /**********************************************/

    mac_lte_stat_selected_ue_lb = gtk_frame_new("Selected UE details");

    selected_ue_vb = gtk_vbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER(mac_lte_stat_selected_ue_lb), selected_ue_vb);
    gtk_container_set_border_width(GTK_CONTAINER(selected_ue_vb), 5);

    selected_ue_scrolled_window = scrolled_window_new(NULL, NULL);
    gtk_box_pack_start(GTK_BOX(selected_ue_vb), selected_ue_scrolled_window, TRUE, TRUE, 0);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(selected_ue_scrolled_window),
                                        GTK_SHADOW_IN);

    /* Create the table of UE data */
    selected_ue_store = gtk_list_store_new(NUM_CHANNEL_COLUMNS, G_TYPE_STRING, G_TYPE_INT,
                                           G_TYPE_INT, G_TYPE_INT, G_TYPE_INT, G_TYPE_INT, G_TYPE_INT,
                                           G_TYPE_INT, G_TYPE_INT, G_TYPE_INT, G_TYPE_INT, G_TYPE_INT,
                                           G_TYPE_INT);
    hs->selected_ue_table = GTK_TREE_VIEW(tree_view_new(GTK_TREE_MODEL(selected_ue_store)));
    gtk_container_add(GTK_CONTAINER (selected_ue_scrolled_window), GTK_WIDGET(hs->selected_ue_table));
    g_object_unref(G_OBJECT(selected_ue_store));

    tree_view = hs->selected_ue_table;
    gtk_tree_view_set_headers_visible(tree_view, TRUE);
    gtk_tree_view_set_headers_clickable(tree_view, TRUE);

    /* Create the titles for each column of the per-UE table */
    for (i = 0; i < NUM_CHANNEL_COLUMNS; i++) {
        renderer = gtk_cell_renderer_text_new();
        column = gtk_tree_view_column_new_with_attributes(channel_titles[i], renderer,
                                                          "text", i, NULL);
        gtk_tree_view_column_set_sort_column_id(column, i);

        gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
        gtk_tree_view_column_set_resizable(column, TRUE);
        gtk_tree_view_append_column(tree_view, column);

    }

    gtk_box_pack_start(GTK_BOX(top_level_vbox), mac_lte_stat_selected_ue_lb, FALSE, FALSE, 0);


    /**********************************************/
    /* Register the tap listener                  */
    /**********************************************/

    error_string = register_tap_listener("mac-lte", hs, NULL,
                                         mac_lte_stat_reset,
                                         mac_lte_stat_packet,
                                         mac_lte_stat_draw);
    if (error_string) {
        simple_dialog (ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
        g_string_free (error_string, TRUE);
        g_free (hs);
        return;
    }


    /************************************/
    /* Button row.                      */
    /************************************/

    bbox = dlg_button_row_new (GTK_STOCK_CLOSE, NULL);
    gtk_box_pack_end (GTK_BOX(top_level_vbox), bbox, FALSE, FALSE, 0);

    /* Add the close button */
    close_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
    window_set_cancel_button(mac_lte_stat_dlg_w, close_bt, window_cancel_button_cb);

    /* Set callbacks */
    g_signal_connect(mac_lte_stat_dlg_w, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
    g_signal_connect(mac_lte_stat_dlg_w, "destroy", G_CALLBACK(win_destroy_cb), hs);

    /* Show the window */
    gtk_widget_show_all(mac_lte_stat_dlg_w);
    window_present(mac_lte_stat_dlg_w);

    /* Retap */
    cf_retap_packets(&cfile, FALSE);
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
    register_stat_menu_item("LTE MAC...", REGISTER_STAT_GROUP_TELEPHONY,
                            mac_lte_stat_launch, NULL, NULL, NULL);
}


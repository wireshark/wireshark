/* tap-oran.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>
#include <string.h>

#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/dissectors/packet-oran.h>

void register_tap_listener_mac_lte_stat(void);

/**********************************************/
/* Table column identifiers and title strings */

enum {
    PLANE_COLUMN,
    EAXC_COLUMN,
    DIRECTION_COLUMN,
    NUM_FRAMES_COLUMN,
    LARGEST_PDU_COLUMN,
    SECTIONS_COLUMN,
    SECTION_IDS_COLUMN,
    EXTENSIONS_COLUMN,
    BEAMS_COLUMN,
    HIGHEST_SLOT_COLUMN,
    MISSING_SNS_COLUMN,
    NUM_PRBS_COLUMN,
    NUM_PRBS_ZERO_COLUMN,
    NUM_RES_COLUMN,
    NUM_RES_ZERO_COLUMN,
    COMP_METH_COLUMN,
    COMP_WIDTH_COLUMN,
    NUM_FLOW_COLUMNS
};

/* Global stats */
uint32_t largest_ul_delay_in_us = 0;
uint32_t ul_configured_max = 0;
uint32_t ul_within_configured_max = 0;
uint32_t ul_above_configured_max = 0;

#define MAX_BEAMS_IN_CAPTURE 256U
uint16_t num_beams;
uint16_t beams[MAX_BEAMS_IN_CAPTURE];

/* Assuming that it is unlikely we have > 255 radio frames.. */
int      first_radio_frame = -1;
int      last_radio_frame = -1;

static const char *flow_titles[] = { " Plane",
                                     "eAxC ID ",
                                     "Direction  ",
                                     "Frames ",
                                     "Largest PDU  ",
                                     "Section Types                ",
                                     "Section IDs        ",
                                     "Extensions                                            ",
                                     "Beams",
                                     "Highest Slot",
                                     "Missing SNs   ",
                                     "PRBs",
                                     "Zero-PRBs      ",
                                     "REs ",
                                     "Zero-REs     ",
                                     "Comp. Meth",
                                     "Comp. Width"
                                   };

/* Stats for one Flow */
typedef struct oran_row_data {
    oran_tap_info base_info;
    /* Data accumulated over lifetime of flow */
    uint32_t      num_frames;
    uint32_t      largest_pdu;
    uint32_t      highest_slot;
    uint32_t      missing_sns;

    uint32_t      num_prbs;
    uint32_t      num_res;
    uint32_t      num_prbs_zero;
    uint32_t      num_res_zero;

    bool          section_ids_present[4096];  /* sectionId is 12 bits */

    uint32_t      compression_methods;
    uint32_t      compression_width;
} oran_row_data;

/* Top-level struct for ORAN FH statistics */
typedef struct oran_stat_t {
    /* List of flows (oran_row_data) */
    GList  *flow_list;
} oran_stat_t;


/* Reset the statistics window */
static void
oran_stat_reset(void *phs)
{
    oran_stat_t *oran_stat = (oran_stat_t *)phs;
    g_list_free_full(oran_stat->flow_list, g_free);
    oran_stat->flow_list = NULL;
}


/* Free memory used by tap */
static void
oran_stat_finish(void *phs)
{
    oran_stat_t *oran_stat = (oran_stat_t *)phs;
    g_list_free_full(oran_stat->flow_list, g_free);
    g_free(oran_stat);
}


/* Process stat struct for an Oran FH CUS frame */
static tap_packet_status
oran_stat_packet(void *phs, packet_info *pinfo _U_, epan_dissect_t *edt _U_,
                 const void *phi, tap_flags_t flags _U_)
{
    /* Get reference to stat instance */
    oran_stat_t *hs = (oran_stat_t*)phs;
    GList *tmp = NULL;
    oran_row_data *row = NULL;

    /* Cast tap info struct */
    const struct oran_tap_info *si = (const struct oran_tap_info *)phi;

    if (!hs) {
        return TAP_PACKET_DONT_REDRAW;
    }

    /* Update global stats */
    if (si->ul_delay_in_us > largest_ul_delay_in_us) {
        largest_ul_delay_in_us = si->ul_delay_in_us;
    }
    ul_configured_max = si->ul_delay_configured_max;
    if (si->ul_delay_in_us > si->ul_delay_configured_max) {
        ul_above_configured_max++;
    }
    else if (si->ul_delay_in_us > 0) {
        ul_within_configured_max++;
    }

    if (first_radio_frame == -1) {
        first_radio_frame = (int)si->frame;
    }
    last_radio_frame = (int)si->frame;

    bool row_found = false;
    /* Look among existing rows for this flow */
    for (tmp = hs->flow_list; tmp != NULL; tmp = tmp->next) {
        /* Match only by plane, eAxCID, direction together */
        row = (oran_row_data*)tmp->data;
        if ((row->base_info.userplane  == si->userplane) &&
            (row->base_info.eaxc       == si->eaxc) &&
            (row->base_info.uplink     == si->uplink)) {
            /* Found our row */
            row_found = true;
            break;
        }
    }

    /* Not found among existing, so create a new one now */
    if (!row_found) {
        row = g_new0(oran_row_data, 1);

        /* Set key fields */
        row->base_info.userplane = si->userplane;
        row->base_info.eaxc = si->eaxc;
        row->base_info.eaxc_du_port_id = si->eaxc_du_port_id;
        row->base_info.eaxc_bandsector_id = si->eaxc_bandsector_id;
        row->base_info.eaxc_cc_id = si->eaxc_cc_id;
        row->base_info.eaxc_ru_port_id = si->eaxc_ru_port_id;
        row->base_info.uplink = si->uplink;
        /* Add to list */
        hs->flow_list = g_list_prepend(hs->flow_list, row);
    }


    /* Really should have a row pointer by now */
    if (!row) {
        return TAP_PACKET_DONT_REDRAW;
    }

    /* Copy these values from tap info */
    for (unsigned int s=0; s < SEC_C_MAX_INDEX; s++) {
        if (si->section_types[s]) {
            row->base_info.section_types[s] = si->section_types[s];
        }
    }

    for (unsigned int t=0; t < si->num_section_ids; t++) {
        row->section_ids_present[si->section_ids[t]] = true;
    }

    for (unsigned int e=0; e <= HIGHEST_EXTTYPE; e++) {
        if (si->extensions[e]) {
            row->base_info.extensions[e] = si->extensions[e];
        }
    }

    if (si->pdu_size > row->largest_pdu) {
        row->largest_pdu = si->pdu_size;
    }

    /* Other updates to flow */
    row->num_frames++;
    row->highest_slot = MAX(row->highest_slot, si->slot);
    row->missing_sns += si->missing_sns;

    row->num_prbs += si->num_prbs;
    row->num_res += si->num_res;
    row->num_prbs_zero += si->num_prbs_zero;
    row->num_res_zero += si->num_res_zero;

    /* Compression settings */
    row->compression_width = si->compression_width;
    row->compression_methods |= si->compression_methods;

    /* Count beams */

    /* Copy these values from tap info.. */
    /* ..into row */
    for (uint16_t b = 0; b < si->num_beams; b++) {
        bool need_to_add = true;
        for (uint16_t n=0; n < row->base_info.num_beams; n++) {
            if (si->beams[b] == row->base_info.beams[n]) {
                /* Already have it, nothing to do */
                need_to_add = false;
                break;
            }
            if (row->base_info.num_beams == MAX_BEAMS_IN_FRAME) {
                need_to_add = false;
                break;
            }
        }
        if (need_to_add) {
            /* Have room and wasn't found, so add */
            row->base_info.beams[row->base_info.num_beams++] = si->beams[b];
        }
    }
    /* ..globally */
    for (uint16_t b = 0; b < si->num_beams; b++) {
        bool need_to_add = true;
        for (uint16_t n=0; n < num_beams; n++) {
            if (si->beams[b] == beams[n]) {
                /* Already have it, nothing to do */
                need_to_add = false;
                break;
            }
            if (num_beams == MAX_BEAMS_IN_CAPTURE) {
                need_to_add = false;
                break;
            }
        }
        if (need_to_add) {
            /* Have room and wasn't found, so add */
            beams[num_beams++] = si->beams[b];
        }
    }

    return TAP_PACKET_REDRAW;
}

static int compare_flows(void *a, void *b)
{
    oran_row_data *flow_a = (oran_row_data*)a;
    oran_row_data *flow_b = (oran_row_data*)b;

    /* Sort first by eAxC */
    if (flow_a->base_info.eaxc < flow_b->base_info.eaxc) {
        return -1;
    }
    else if (flow_a->base_info.eaxc > flow_b->base_info.eaxc) {
        return 1;
    }

    /* Next, by direction (want DL first) */
    else if (!flow_a->base_info.uplink && flow_b->base_info.uplink) {
        return -1;
    }
    else if (flow_a->base_info.uplink && !flow_b->base_info.uplink) {
        return 1;
    }

    /* Lastly, use plane. Cplane first */
    else if (!flow_a->base_info.userplane && flow_b->base_info.userplane) {
        return -1;
    }
    else if (flow_a->base_info.userplane && !flow_b->base_info.userplane) {
        return 1;
    }

    /* Can never get here! */
    return 0;
}

/* Output the accumulated stats */
static void
oran_stat_draw(void *phs)
{
    int i;

    /* Deref the struct */
    oran_stat_t *hs = (oran_stat_t*)phs;
    GList *tmp = NULL;

    /* TODO: sort rows by eAxC (ascending), Plane (control first), direction (DL first) */
    hs->flow_list = g_list_sort(hs->flow_list, (GCompareFunc)compare_flows);

    /* Show column titles */
    for (i=0; i < NUM_FLOW_COLUMNS; i++) {
        printf("%s  ", flow_titles[i]);
    }
    /* Divider before rows */
    printf("\n============================================================================================================================================================================================================================================================================\n");

    /* Write a row for each flow */
    for (tmp = hs->flow_list; tmp; tmp=tmp->next) {

        oran_row_data *row = (oran_row_data*)tmp->data;

        /* TODO: use wmem_strbuf_t for these strings */
        char sections[32];
        int sections_offset = 0;
        sections[0] = '\0';

        char extensions[17];
        int extensions_offset = 0;
        extensions[0] = '-';
        extensions[1] = '\0';

        char section_ids[28];
        int section_ids_offset = 0;
        section_ids[0] = '-';
        section_ids[1] = '\0';

        char beams_string[50];
        int beams_offset = 0;
        beams_string[0] = '-';
        beams_string[1] = '\0';


        /* Some fields only apply to c-plane */
        if (!row->base_info.userplane) {
            /* Note which sections are used */
            for (unsigned int s=0; s < SEC_C_MAX_INDEX && (extensions_offset < 17-3); s++) {
                if (row->base_info.section_types[s]) {
                    sections_offset += snprintf(sections+sections_offset, 17-sections_offset-1, " %u", s);
                }
            }

            /* Note which extensions are used */
            for (unsigned int e=1; e <= HIGHEST_EXTTYPE && (extensions_offset < 17-3); e++) {
                if (row->base_info.extensions[e]) {
                    extensions_offset += snprintf(extensions+extensions_offset, 17-extensions_offset-1, " %u", e);
                }
            }
        }

        /* Section IDs */
        for (unsigned id=0; (id < 4096) && (section_ids_offset < 28-1); id++) {
            if (row->section_ids_present[id]) {
                section_ids_offset += snprintf(section_ids+section_ids_offset, 28-section_ids_offset-1, " %u", id);
            }
        }

        /* Beams. Only showing for DL CP..  */
        if (!row->base_info.uplink && !row->base_info.userplane) {
            for (int b=0; b < MIN(row->base_info.num_beams, MAX_BEAMS_IN_FRAME) && (beams_offset <= (50-2)); b++) {
                beams_offset += snprintf(beams_string+beams_offset, 50-beams_offset, " %u", row->base_info.beams[b]);
            }
        }


        /* Print this row. */
        /* TODO: will be wrong if any of the constituent parts of eaxc run to 2 hex chars - need to print to separate string and give column fixed width */
        printf("%6s  %x:%x:%x:%x %11s %9u %13u %17s %28s %18s %50s %13u %12u",
               (row->base_info.userplane) ? "U" : "C",
               row->base_info.eaxc_du_port_id, row->base_info.eaxc_bandsector_id, row->base_info.eaxc_cc_id, row->base_info.eaxc_ru_port_id,
               (row->base_info.uplink) ? "UL" : "DL",
               row->num_frames,
               row->largest_pdu,
               sections,
               section_ids,
               extensions,
               beams_string,
               row->highest_slot,
               row->missing_sns
               );

        if (row->base_info.userplane) {
            /* U-Plane only */

            const char* comp_names[] = { "None", "BFP", "Block Scaling",
                                         "uLaw", "ModCompr",
                                         "BFP+SelRE", "ModComp+SelRE"};

            /* Looking for first/only match */
            const char *method = "none";
            for (int c=0; c <=6; c++) {
                if ((1 << c) & row->compression_methods) {
                    method = comp_names[c];
                    break;
                }

            }

            printf(" %8u %10u %10u %10u %16s %12u\n",
                   row->num_prbs,
                   row->num_prbs_zero,
                   row->num_res,
                   row->num_res_zero,
                   method,
                   row->compression_width);
        }
        else {
            printf("\n");
        }
    }

    /* Now show global stats */
    printf("\n First radio frame    Last radio frame\n");
    printf("=======================================\n");
    printf("%18u %19u\n", first_radio_frame, last_radio_frame);

    printf("\n Configured Max UL delay    UL Frames within limit    UL frames after limit    Largest UL delay\n");
    printf("================================================================================================\n");
    printf("%24u %25u %24u %19u\n", ul_configured_max, ul_within_configured_max, ul_above_configured_max, largest_ul_delay_in_us);

    printf("\n Unique beams seen\n");
    printf("=======================\n");
    printf("%18u\n", num_beams);
}

/* Create a new ORAN stats struct */
static bool oran_stat_init(const char *opt_arg, void *userdata _U_)
{
    oran_stat_t    *hs;
    const char    *filter = NULL;
    GString       *error_string;

    /* Check for a filter string */
    if (strncmp(opt_arg, "oran-fh-cus,stat,", 17) == 0) {
        /* Skip those characters from filter to display */
        filter = opt_arg + 17;
    }
    else {
        /* No filter */
        filter = NULL;
    }

    /* Create struct */
    hs = g_new0(oran_stat_t, 1);

    error_string = register_tap_listener("oran-fh-cus", hs,
                                         filter, TL_REQUIRES_NOTHING,
                                         oran_stat_reset,
                                         oran_stat_packet,
                                         oran_stat_draw,
                                         oran_stat_finish);
    if (error_string) {
        g_string_free(error_string, TRUE);
        g_free(hs);
        return false;
    }

    return true;
}

static stat_tap_ui oran_stat_ui = {
    REGISTER_STAT_GROUP_GENERIC,
    NULL,
    "oran-fh-cus,stat",
    oran_stat_init,
    0,
    NULL
};

/* Register this tap listener (need void on own so line register function found) */
void
register_tap_listener_oran_stat(void)
{
    register_stat_tap_ui(&oran_stat_ui, NULL);
}

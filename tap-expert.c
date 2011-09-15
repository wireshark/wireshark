/* tap-expert.c
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
#include <epan/expert.h>

/* Tap data */
typedef enum severity_level_t {
    chat_level=0,
    note_level,
    warn_level,
    error_level,
    max_level
} severity_level_t;

typedef struct expert_tapdata_t {
    GArray         *ei_array[max_level];   /* expert info items */
    GStringChunk*  text; /* summary text */
} expert_tapdata_t;



/* Reset expert stats */
static void
expert_stat_reset(void *tapdata)
{
    gint n;
    expert_tapdata_t *etd = tapdata;

    /* Free & reallocate chunk of strings */
    g_string_chunk_free(etd->text);
    etd->text = g_string_chunk_new(100);

    /* Empty each of the arrays */
    for (n=0; n < max_level; n++) {
        g_array_set_size(etd->ei_array[n], 0);
    }
}

/* Process stat struct for an expert frame */
static int
expert_stat_packet(void *tapdata, packet_info *pinfo _U_, epan_dissect_t *edt _U_,
                   const void *pointer)
{
    expert_info_t    *ei = (expert_info_t *)pointer;
    expert_tapdata_t *etd = tapdata;
    severity_level_t severity_level;

    switch (ei->severity) {
        case PI_CHAT:
            severity_level = chat_level;
            break;
        case PI_NOTE:
            severity_level = note_level;
            break;
        case PI_WARN:
            severity_level = warn_level;
            break;
        case PI_ERROR:
            severity_level = error_level;
            break;
        default:
            g_assert_not_reached();
            return 0;
    }

    /* Add new item to end of list for severity level */
    g_array_append_val(etd->ei_array[severity_level], *(expert_info_t *)pointer);

    /* Get pointer to newly-allocated item */
    ei = &g_array_index(etd->ei_array[severity_level], expert_info_t,
                        etd->ei_array[severity_level]->len - 1); /* ugly */
    /* Copy/Store protocol and summary strings efficiently using GStringChunk */
    ei->protocol = g_string_chunk_insert_const(etd->text, ei->protocol);
    ei->summary = g_string_chunk_insert_const(etd->text, ei->summary);

    return 1;
}

/* Output for all of the items of one severity */
static void draw_items_for_severity(GArray *items, const gchar *label)
{
    guint n;
    expert_info_t *ei;

    /* Don't print title if no items */
    if (items->len == 0) {
        return;
    }

    /* Title */
    printf("\n%s (%u)\n", label, items->len);
    printf("=============\n");

    /* Column headings */
    printf("   Frame             Protocol\n");

    /* Items */
    for (n=0; n < items->len; n++) {
        ei = &g_array_index(items, expert_info_t, n);
        printf("%8u %20s  %s\n", ei->packet_num ,ei->protocol, ei->summary);
    }
}

/* (Re)draw expert stats */
static void
expert_stat_draw(void *phs _U_)
{
    /* Look up the statistics struct */
    expert_tapdata_t *hs = (expert_tapdata_t *)phs;

    draw_items_for_severity(hs->ei_array[error_level], "Errors");
    draw_items_for_severity(hs->ei_array[warn_level],  "Warns");
    draw_items_for_severity(hs->ei_array[note_level],  "Notes");
    draw_items_for_severity(hs->ei_array[chat_level],  "Chats");
}

/* Create a new expert stats struct */
static void expert_stat_init(const char *optarg, void *userdata _U_)
{
    const char        *filter = NULL;
    GString           *error_string;
    expert_tapdata_t  *hs;
    int n;

    /* Check for a filter string */
    if (strncmp(optarg, "expert,stat,", 13) == 0) {
        /* Skip those characters from filter to display */
        filter = optarg + 11;
    }
    else {
        /* No filter */
        filter = NULL;
    }

    /* Create top-level struct */
    hs = g_malloc(sizeof(expert_tapdata_t));
    memset(hs, 0,  sizeof(expert_tapdata_t));

    /* Allocate chunk of strings */
    hs->text = g_string_chunk_new(100);
    /* Allocate GArray for each severity level */
    for (n=0; n < max_level; n++) {
        hs->ei_array[n] = g_array_sized_new(FALSE, FALSE, sizeof(expert_info_t), 1000);
    }

    /**********************************************/
    /* Register the tap listener                  */
    /**********************************************/

    error_string = register_tap_listener("expert", hs,
                                         filter, 0,
                                         expert_stat_reset,
                                         expert_stat_packet,
                                         expert_stat_draw);
    if (error_string) {
        g_string_free(error_string, TRUE);
        g_free(hs);
        exit(1);
    }
}


/* Register this tap listener (need void on own so line register function found) */
void
register_tap_listener_expert_info(void)
{
    register_stat_cmd_arg("expert,stat", expert_stat_init, NULL);
}


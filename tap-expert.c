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

/* This variable stores the lowest level that will be displayed.
   May be changed from the command line */
static severity_level_t lowest_report_level = chat_level;

typedef struct expert_entry
{
    guint32      group;
    const gchar  *protocol;
    gchar        *summary;
    int          frequency;
} expert_entry;


/* Overall struct for storing all data seen */
typedef struct expert_tapdata_t {
    GArray         *ei_array[max_level];   /* expert info items */
    GStringChunk*  text;    /* for efficient storage of summary strings */
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
    expert_tapdata_t *data = tapdata;
    severity_level_t severity_level;
    expert_entry     tmp_entry;
    expert_entry     *entry;
    guint            n;

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

    /* Don't store details at a lesser severity than we are interested in */
    if (severity_level < lowest_report_level) {
        return 1;
    }

    /* If a duplicate just bump up frequency.
       TODO: could make more efficient by avoiding linear search...*/
    for (n=0; n < data->ei_array[severity_level]->len; n++) {
        entry = &g_array_index(data->ei_array[severity_level], expert_entry, n);
        if ((strcmp(ei->protocol, entry->protocol) == 0) &&
            (strcmp(ei->summary, entry->summary) == 0)) {
            entry->frequency++;
            return 1;
        }
    }

    /* Else Add new item to end of list for severity level */
    g_array_append_val(data->ei_array[severity_level], tmp_entry);

    /* Get pointer to newly-allocated item */
    entry = &g_array_index(data->ei_array[severity_level], expert_entry,
                           data->ei_array[severity_level]->len - 1); /* ugly */
    /* Copy/Store protocol and summary strings efficiently using GStringChunk */
    entry->protocol = g_string_chunk_insert_const(data->text, ei->protocol);
    entry->summary = g_string_chunk_insert_const(data->text, ei->summary);
    entry->group = ei->group;
    entry->frequency = 1;

    return 1;
}

/* Output for all of the items of one severity */
static void draw_items_for_severity(GArray *items, const gchar *label)
{
    guint n;
    expert_entry *ei;
    int total = 0;

    /* Don't print title if no items */
    if (items->len == 0) {
        return;
    }

    /* Add frequencies together to get total */
    for (n=0; n < items->len; n++) {
        ei = &g_array_index(items, expert_entry, n);
        total += ei->frequency;
    }

    /* Title */
    printf("\n%s (%u)\n", label, total);
    printf("=============\n");

    /* Column headings */
    printf("   Frequency      Group           Protocol  Summary\n");

    /* Items */
    for (n=0; n < items->len; n++) {
        ei = &g_array_index(items, expert_entry, n);
        printf("%12u %10s %18s  %s\n",
              ei->frequency,
              val_to_str(ei->group, expert_group_vals, "Unknown"),
              ei->protocol, ei->summary);
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
    const char        *args = NULL;
    const char        *filter = NULL;
    GString           *error_string;
    expert_tapdata_t  *hs;
    int n;

    /* Check for args. */
    if (strncmp(optarg, "expert", 6) == 0) {
        /* Skip those characters */
        args = optarg + 6;
    }
    else {
        /* No args. Will show all reports, with no filter */
        lowest_report_level = max_level;
    }

    /* First (optional) arg is Error|Warn|Note|Chat */
    if (args != NULL) {
        if (g_ascii_strncasecmp(args, ",error", 6) == 0) {
            lowest_report_level = error_level;
            args += 6;
        }
        else if (g_ascii_strncasecmp(args, ",warn", 5) == 0) {
            lowest_report_level = warn_level;
            args += 5;
        } else if (g_ascii_strncasecmp(args, ",note", 5) == 0) {
            lowest_report_level = note_level;
            args += 5;
        } else if (g_ascii_strncasecmp(args, ",chat", 5) == 0) {
            lowest_report_level = chat_level;
            args += 5;
        }
    }

    /* Second (optional) arg is a filter string */
    if (args != NULL) {
        if (args[0] == ',') {
            filter = args+1;
        }
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
        printf("Expert tap error (%s)!\n", error_string->str);
        g_string_free(error_string, TRUE);
        g_free(hs);
        exit(1);
    }
}


/* Register this tap listener (need void on own so line register function found) */
void
register_tap_listener_expert_info(void)
{
    register_stat_cmd_arg("expert", expert_stat_init, NULL);
}


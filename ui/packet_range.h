/** @file
 *
 * Packet range routines (save, print, ...)
 *
 * Dick Gooris <gooris@lucent.com>
 * Ulf Lamping <ulf.lamping@web.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_RANGE_H__
#define __PACKET_RANGE_H__

#include <glib.h>

#include <epan/range.h>
#include <epan/frame_data.h>

#include "cfile.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

extern uint32_t curr_selected_frame;

typedef enum {
    range_process_all,
    range_process_selected,
    range_process_marked,
    range_process_marked_range,
    range_process_user_range
} packet_range_e;

typedef struct packet_range_tag {
    /* values coming from the UI */
    packet_range_e  process;            /* which range to process */
    bool            process_filtered;   /* captured or filtered packets */
    bool            remove_ignored;     /* remove ignored packets */
    bool            include_dependents;	/* True if packets which are dependents of others should be processed */

    /* user specified range(s) and, if null, error status */
    range_t         *user_range;
    convert_ret_t   user_range_status;

    /* calculated values */
    range_t        *selection_range;       /* the currently selected packets */
    convert_ret_t   selection_range_status;

    /* current packet counts (captured) */
    capture_file *cf;                     /* Associated capture file. */
    uint32_t      mark_range_cnt;         /* packets in marked range */
    uint32_t      user_range_cnt;         /* packets in user specified range */
    uint32_t      selection_range_cnt;    /* packets in the selected range */
    uint32_t      marked_plus_depends_cnt;
    uint32_t      mark_range_plus_depends_cnt;
    uint32_t      user_range_plus_depends_cnt;
    uint32_t      selected_plus_depends_cnt;
    uint32_t      ignored_cnt;            /* packets ignored */
    uint32_t      ignored_marked_cnt;     /* packets ignored and marked */
    uint32_t      ignored_mark_range_cnt; /* packets ignored in marked range */
    uint32_t      ignored_user_range_cnt; /* packets ignored in user specified range */
    uint32_t      ignored_selection_range_cnt;    /* packets ignored in the selected range */

    /* current packet counts (displayed) */
    uint32_t displayed_cnt;
    uint32_t displayed_plus_dependents_cnt;
    uint32_t displayed_marked_cnt;
    uint32_t displayed_mark_range_cnt;
    uint32_t displayed_user_range_cnt;
    uint32_t displayed_marked_plus_depends_cnt;
    uint32_t displayed_mark_range_plus_depends_cnt;
    uint32_t displayed_user_range_plus_depends_cnt;
    uint32_t displayed_selection_range_cnt;
    uint32_t displayed_selected_plus_depends_cnt;
    uint32_t displayed_ignored_cnt;
    uint32_t displayed_ignored_marked_cnt;
    uint32_t displayed_ignored_mark_range_cnt;
    uint32_t displayed_ignored_user_range_cnt;
    uint32_t displayed_ignored_selection_range_cnt;

    /* Sets of the chosen frames plus any they depend on for each case */
    GHashTable *marked_plus_depends;
    GHashTable *displayed_marked_plus_depends;
    GHashTable *mark_range_plus_depends;
    GHashTable *displayed_mark_range_plus_depends;
    GHashTable *user_range_plus_depends;
    GHashTable *displayed_user_range_plus_depends;
    GHashTable *selected_plus_depends;
    GHashTable *displayed_selected_plus_depends;

    /* "enumeration" values */
    bool marked_range_active;   /* marked range is currently processed */
    uint32_t marked_range_left;     /* marked range packets left to do */
} packet_range_t;

typedef enum {
    range_process_this,             /* process this packet */
    range_process_next,             /* skip this packet, process next */
    range_processing_finished       /* stop processing, required packets done */
} range_process_e;

/* init the range structure */
extern void packet_range_init(packet_range_t *range, capture_file *cf);

/* Cleanup the range structure before the caller frees "range". */
extern void packet_range_cleanup(packet_range_t *range);

/* check whether the packet range is OK */
extern convert_ret_t packet_range_check(packet_range_t *range);

/* init the processing run */
extern void packet_range_process_init(packet_range_t *range);

/* do we have to process all packets? */
extern bool packet_range_process_all(packet_range_t *range);

/* do we have to process this packet? */
extern range_process_e packet_range_process_packet(packet_range_t *range, frame_data *fdata);

/* convert user given string to the internal user specified range representation */
extern void packet_range_convert_str(packet_range_t *range, const char *es);

/* convert user given string to the internal selection specified range representation */
extern void packet_range_convert_selection_str(packet_range_t *range, const char *es);

/* return the number of packets that will be processed.
 */
extern uint32_t packet_range_count(const packet_range_t *range);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PACKET_RANGE_H__ */

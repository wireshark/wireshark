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

#include <epan/cfile.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

extern uint32_t curr_selected_frame;

/**
 * @brief Selects which subset of packets in a capture file should be processed.
 */
typedef enum {
    range_process_all,          /**< Process all packets in the capture file */
    range_process_selected,     /**< Process only the currently selected packet(s) */
    range_process_marked,       /**< Process only marked packets */
    range_process_marked_range, /**< Process packets in the contiguous range between the first and last marked packet */
    range_process_user_range    /**< Process packets within a user-specified range string */
} packet_range_e;

/**
 * @brief Fully describes a packet range selection, including UI settings, derived counts,
 *        and dependency sets used when iterating over a capture file.
 */
typedef struct packet_range_tag {

    /* --- UI-supplied settings --- */

    packet_range_e process;           /**< Which packet subset to process (see ::packet_range_e) */
    bool           process_filtered;  /**< If true, restrict processing to display-filtered packets; otherwise use captured packets */
    bool           remove_ignored;    /**< If true, exclude ignored packets from processing */
    bool           include_dependents;/**< If true, also process packets that others in the range depend on */

    /* --- User-specified range --- */

    range_t       *user_range;        /**< Parsed representation of the user-supplied range string; NULL if not set */
    convert_ret_t  user_range_status; /**< Parse/conversion status of @p user_range; indicates any error if NULL */

    /* --- Calculated selection range --- */

    range_t       *selection_range;        /**< Range derived from the current packet selection in the UI */
    convert_ret_t  selection_range_status; /**< Validity status of @p selection_range */

    /* --- Captured packet counts --- */

    capture_file *cf;                          /**< Capture file these counts apply to */
    uint32_t      mark_range_cnt;              /**< Packets within the marked range */
    uint32_t      user_range_cnt;              /**< Packets within the user-specified range */
    uint32_t      selection_range_cnt;         /**< Packets within the current selection range */
    uint32_t      marked_plus_depends_cnt;     /**< Marked packets plus their dependents */
    uint32_t      mark_range_plus_depends_cnt; /**< Marked-range packets plus their dependents */
    uint32_t      user_range_plus_depends_cnt; /**< User-range packets plus their dependents */
    uint32_t      selected_plus_depends_cnt;   /**< Selected packets plus their dependents */
    uint32_t      ignored_cnt;                 /**< Packets flagged as ignored */
    uint32_t      ignored_marked_cnt;          /**< Packets that are both ignored and marked */
    uint32_t      ignored_mark_range_cnt;      /**< Ignored packets within the marked range */
    uint32_t      ignored_user_range_cnt;      /**< Ignored packets within the user-specified range */
    uint32_t      ignored_selection_range_cnt; /**< Ignored packets within the current selection range */

    /* --- Displayed (filtered) packet counts --- */

    uint32_t displayed_cnt;                               /**< Total displayed packets */
    uint32_t displayed_plus_dependents_cnt;               /**< Displayed packets plus their dependents */
    uint32_t displayed_marked_cnt;                        /**< Displayed packets that are marked */
    uint32_t displayed_mark_range_cnt;                    /**< Displayed packets within the marked range */
    uint32_t displayed_user_range_cnt;                    /**< Displayed packets within the user-specified range */
    uint32_t displayed_marked_plus_depends_cnt;           /**< Displayed marked packets plus their dependents */
    uint32_t displayed_mark_range_plus_depends_cnt;       /**< Displayed marked-range packets plus their dependents */
    uint32_t displayed_user_range_plus_depends_cnt;       /**< Displayed user-range packets plus their dependents */
    uint32_t displayed_selection_range_cnt;               /**< Displayed packets within the current selection range */
    uint32_t displayed_selected_plus_depends_cnt;         /**< Displayed selected packets plus their dependents */
    uint32_t displayed_ignored_cnt;                       /**< Displayed packets that are ignored */
    uint32_t displayed_ignored_marked_cnt;                /**< Displayed packets that are both ignored and marked */
    uint32_t displayed_ignored_mark_range_cnt;            /**< Displayed ignored packets within the marked range */
    uint32_t displayed_ignored_user_range_cnt;            /**< Displayed ignored packets within the user-specified range */
    uint32_t displayed_ignored_selection_range_cnt;       /**< Displayed ignored packets within the current selection range */

    /* --- Dependency hash sets --- */

    GHashTable *marked_plus_depends;                  /**< Set of captured marked frames plus their dependents */
    GHashTable *displayed_marked_plus_depends;        /**< Set of displayed marked frames plus their dependents */
    GHashTable *mark_range_plus_depends;              /**< Set of captured marked-range frames plus their dependents */
    GHashTable *displayed_mark_range_plus_depends;    /**< Set of displayed marked-range frames plus their dependents */
    GHashTable *user_range_plus_depends;              /**< Set of captured user-range frames plus their dependents */
    GHashTable *displayed_user_range_plus_depends;    /**< Set of displayed user-range frames plus their dependents */
    GHashTable *selected_plus_depends;                /**< Set of captured selected frames plus their dependents */
    GHashTable *displayed_selected_plus_depends;      /**< Set of displayed selected frames plus their dependents */

    /* --- Enumeration state --- */

    bool     marked_range_active; /**< True while an iteration over the marked range is in progress */
    uint32_t marked_range_left;   /**< Number of marked-range packets still to be processed in the current iteration */

} packet_range_t;

/**
 * @brief Disposition returned per-packet by the range enumeration callback to control iteration.
 */
typedef enum {
    range_process_this,       /**< Process the current packet and continue to the next */
    range_process_next,       /**< Skip the current packet and continue to the next */
    range_processing_finished /**< Stop iteration; all required packets have been processed */
} range_process_e;

/**
 * @brief Iterator state for stepping through a packet range one frame at a time.
 */
typedef struct packet_range_iter {
    packet_range_t *range;         /**< Pointer to the packet range being iterated over. */
    uint32_t        current_frame; /**< Frame number of the current position within the range. */
} packet_range_iter_t;

/* init the range structure */

/**
 * @brief Initialize a packet range structure.
 *
 * @param range Pointer to the packet_range_t structure to be initialized.
 * @param cf Pointer to the capture_file structure associated with the packet range.
 */
extern void packet_range_init(packet_range_t *range, capture_file *cf);

/**
 * @brief Cleanup the range structure before the caller frees "range".
 *
 * @param range Pointer to the packet_range_t structure to be cleaned up.
 */
extern void packet_range_cleanup(packet_range_t *range);

/**
 * @brief Check whether the packet range is OK.
 *
 * @param range Pointer to the packet_range_t structure to be checked.
 * @return convert_ret_t The result of the check.
 */
extern convert_ret_t packet_range_check(packet_range_t *range);

/**
 * @brief Initialize the processing run for a packet range.
 *
 * @param range Pointer to the packet_range_t structure to initialize.
 */
extern void packet_range_process_init(packet_range_t *range);

/**
 * @brief Check if all packets in the range need to be processed.
 *
 * @param range Pointer to the packet_range_t structure.
 * @return bool True if all packets need to be processed, false otherwise.
 */
extern bool packet_range_process_all(packet_range_t *range);

 /**
  * @brief Check if a packet should be processed based on the given range.
  *
  * @param range Pointer to the packet range structure.
  * @param fdata Pointer to the frame data structure representing the packet to be checked.
  * @return convert_ret_t The result of the check, indicating whether the packet should be processed or not.
  */
extern range_process_e packet_range_process_packet(packet_range_t *range, frame_data *fdata);

/**
 * @brief Convert a user-given string to an internal selection specified range representation.
 *
 * @param range Pointer to the packet_range_t structure where the result will be stored.
 * @param es The user-given string representing the packet range.
 */
extern void packet_range_convert_str(packet_range_t *range, const char *es);

/**
 * @brief Convert a selection string to a packet range.
 *
 * This function takes a selection string and converts it into a packet range structure.
 *
 * @param range Pointer to the packet_range_t structure where the result will be stored.
 * @param es The selection string to convert.
 */
extern void packet_range_convert_selection_str(packet_range_t *range, const char *es);

/**
 * @brief Return the number of packets that will be processed.
 *
 * @param range Pointer to the packet_range_t structure.
 * @return uint32_t The number of packets that will be processed.
 *
 * @note If live capture is occurring, the actual number of packets that will
 * be processed may be greater; i.e., packets that are captured after this
 * function is called may be included as well.
 */
extern uint32_t packet_range_count(const packet_range_t *range);

/**
 * @brief Initialize an iterator over a packet range.
 *
 * This function will call packet_range_process_init on range, so that
 * does not need to be called beforehand.
 *
 * @param iter Pointer to the packet_range_iter_t structure to initialize.
 * @param range Pointer to the packet_range_t over which to iterate.
 */
extern void packet_range_iter_init(packet_range_iter_t *iter, packet_range_t *range);

/**
 * @brief Get the next frame data to process from a packet range.
 *
 * @param iter Pointer to the packet_range_iter_t iterator.
 * @return frame_data* The frame data to process. NULL when iteration is done.
 */
extern frame_data* packet_range_iter_next(packet_range_iter_t *iter);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PACKET_RANGE_H__ */

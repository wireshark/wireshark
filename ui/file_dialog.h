/** @file
 *
 * Common file dialog definitions
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2006 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __FILE_DIALOG_H__
#define __FILE_DIALOG_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Outcome of a "check if savable" prompt when closing or overwriting a capture file.
 */
typedef enum {
    SAVE,                    /**< User chose to save the file in its current format */
    SAVE_WITHOUT_COMMENTS,   /**< User chose to save the file but discard packet comments */
    SAVE_IN_ANOTHER_FORMAT,  /**< User chose to save the file in a different format */
    CANCELLED                /**< User cancelled the save/close operation */
} check_savability_t;

/**
 * @brief Output format for packet data export operations.
 */
typedef enum {
    export_type_text     = 1, /**< Plain text export */
    export_type_ps,           /**< PostScript export */
    export_type_csv,          /**< Comma-separated values (CSV) export */
    export_type_psml,         /**< Packet Summary Markup Language (PSML) XML export */
    export_type_pdml,         /**< Packet Details Markup Language (PDML) XML export */
    export_type_carrays,      /**< C array source code export */
    export_type_json          /**< JSON export */
} export_type_e;

/**
 * @brief Summary statistics gathered during a capture file preview scan.
 */
typedef struct {
    bool     have_times;   /**< True if valid start and stop timestamps were found in the file */
    double   start_time;   /**< Timestamp of the first record in seconds with nanosecond resolution */
    double   stop_time;    /**< Timestamp of the last record in seconds with nanosecond resolution */
    uint32_t records;      /**< Total number of records (including non-data records) in the file */
    uint32_t data_records; /**< Number of data (packet) records in the file */
} ws_file_preview_stats;

/**
 * @brief Return status for a capture file preview statistics scan.
 */
typedef enum {
    PREVIEW_SUCCEEDED,  /**< Preview scan completed successfully */
    PREVIEW_TIMED_OUT,  /**< Preview scan was aborted because it exceeded the time limit */
    PREVIEW_READ_ERROR  /**< Preview scan failed due to a file read error */
} ws_file_preview_stats_status;

/**
 * @brief Retrieves statistics for file preview.
 *
 * @param wth Pointer to the wtap structure representing the capture file.
 * @param stats Pointer to the ws_file_preview_stats structure where the statistics will be stored.
 * @param err Pointer to an integer that will hold any error code if an error occurs.
 * @param err_info Pointer to a char pointer that will hold any error information if an error occurs.
 */
extern ws_file_preview_stats_status
get_stats_for_preview(wtap *wth, ws_file_preview_stats *stats,
                      int *err, char **err_info);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FILE_DIALOG_H__ */

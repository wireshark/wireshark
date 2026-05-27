/** @file
 *
 * Copied from ui/gtk/service_response_time_table.h, 2003 Ronnie Sahlberg
 * Helper routines and structs common to all service response time statistics
 * taps.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/** @file
 *  Helper routines common to all service response time statistics taps.
 */

#ifndef __SRT_STATS_H__
#define __SRT_STATS_H__

#include <epan/timestats.h>
#include <epan/srt_table.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Column indices for the Service Response Time (SRT) statistics table.
 */
enum
{
    SRT_COLUMN_INDEX,     /**< Row index number */
    SRT_COLUMN_PROCEDURE, /**< Procedure or request name identifying the SRT entry */
    SRT_COLUMN_CALLS,     /**< Total number of calls or requests observed */
    SRT_COLUMN_MIN,       /**< Minimum response time recorded across all calls */
    SRT_COLUMN_MAX,       /**< Maximum response time recorded across all calls */
    SRT_COLUMN_AVG,       /**< Average response time across all calls */
    SRT_COLUMN_SUM,       /**< Cumulative sum of all response times */
    NUM_SRT_COLUMNS       /**< Sentinel: total number of SRT table columns */
};

/**
 * @brief Get the column name for a service response time statistic.
 *
 * @param index The index of the column to retrieve.
 * @return The name of the column, or "(Unknown)" if the index is out of range.
 */
extern const char* service_response_time_get_column_name(int index);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __SRT_STATS_H__ */

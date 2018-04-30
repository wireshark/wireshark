/* service_response_time.h
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

enum
{
    SRT_COLUMN_INDEX,
    SRT_COLUMN_PROCEDURE,
    SRT_COLUMN_CALLS,
    SRT_COLUMN_MIN,
    SRT_COLUMN_MAX,
    SRT_COLUMN_AVG,
    SRT_COLUMN_SUM,
    NUM_SRT_COLUMNS
};

/** returns the column name for a given column index */
extern const char* service_response_time_get_column_name(int index);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __SRT_STATS_H__ */

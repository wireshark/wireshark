/* service_response_time.h
 * Copied from ui/gtk/service_response_time_table.h, 2003 Ronnie Sahlberg
 * Helper routines and structs common to all service response time statistics
 * taps.
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

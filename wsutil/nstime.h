/* nstime.h
 * Definition of data structure to hold time values with nanosecond resolution
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

#ifndef __NSTIME_H__
#define __NSTIME_H__

#include <time.h>

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 * Definition of data structure to hold time values with nanosecond resolution
 */

/** data structure to hold time values with nanosecond resolution*/
typedef struct {
	time_t	secs;
	int	nsecs;
} nstime_t;

/* functions */

/** set the given nstime_t to zero */
WS_DLL_PUBLIC void nstime_set_zero(nstime_t *nstime);

/** is the given nstime_t currently zero? */
WS_DLL_PUBLIC gboolean nstime_is_zero(nstime_t *nstime);

/** set the given nstime_t to (0,maxint) to mark it as "unset"
 * That way we can find the first frame even when a timestamp
 * is zero (fix for bug 1056)
 */
WS_DLL_PUBLIC void nstime_set_unset(nstime_t *nstime);

/* is the given nstime_t currently (0,maxint)? */
WS_DLL_PUBLIC gboolean nstime_is_unset(const nstime_t *nstime);

/** duplicate the current time
 *
 * a = b
 */
WS_DLL_PUBLIC void nstime_copy(nstime_t *a, const nstime_t *b);

/** calculate the delta between two times (can be negative!)
 *
 * delta = b-a
 *
 * Note that it is acceptable for two or more of the arguments to point at the
 * same structure.
 */
WS_DLL_PUBLIC void nstime_delta(nstime_t *delta, const nstime_t *b, const nstime_t *a );

/** calculate the sum of two times
 *
 * sum = a+b
 *
 * Note that it is acceptable for two or more of the arguments to point at the
 * same structure.
 */
WS_DLL_PUBLIC void nstime_sum(nstime_t *sum, const nstime_t *b, const nstime_t *a );

/** sum += a */
#define nstime_add(sum, a) nstime_sum(sum, sum, a)

/** sum -= a */
#define nstime_subtract(sum, a) nstime_delta(sum, sum, a)

/** compare two times are return a value similar to memcmp() or strcmp().
 *
 * a > b : > 0
 * a = b : 0
 * a < b : < 0
 */
WS_DLL_PUBLIC int nstime_cmp (const nstime_t *a, const nstime_t *b );

/** converts nstime to double, time base is milli seconds */
WS_DLL_PUBLIC double nstime_to_msec(const nstime_t *nstime);

/** converts nstime to double, time base is seconds */
WS_DLL_PUBLIC double nstime_to_sec(const nstime_t *nstime);

/** converts Windows FILETIME to nstime, returns TRUE on success,
    FALSE on failure */
WS_DLL_PUBLIC gboolean filetime_to_nstime(nstime_t *nstime, guint64 filetime);

/** converts time like Windows FILETIME, but expressed in nanoseconds
    rather than tenths of microseconds, to nstime, returns TRUE on success,
    FALSE on failure */
WS_DLL_PUBLIC gboolean nsfiletime_to_nstime(nstime_t *nstime, guint64 nsfiletime);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __NSTIME_H__  */

/* nstime.h
 * Definition of data structure to hold time values with nanosecond resolution
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __NSTIME_H__
#define __NSTIME_H__

#include <time.h>

#include <wiretap/wtap.h>

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
extern void nstime_set_zero(nstime_t *nstime);

/** is the given nstime_t currently zero? */
extern gboolean nstime_is_zero(nstime_t *nstime);

/** set the given nstime_t to (0,maxint) to mark it as "unset"
 * That way we can find the first frame even when a timestamp
 * is zero (fix for bug 1056)
 */
extern void nstime_set_unset(nstime_t *nstime);

/* is the given nstime_t currently (0,maxint)? */
extern gboolean nstime_is_unset(nstime_t *nstime);

/** duplicate the current time
 *
 * a = b
 */
extern void nstime_copy(nstime_t *a, const nstime_t *b);

/** calculate the delta between two times (can be negative!)
 *
 * delta = b-a
 *
 * Note that it is acceptable for two or more of the arguments to point at the
 * same structure.
 */
extern void nstime_delta(nstime_t *delta, const nstime_t *b, const nstime_t *a );

/** calculate the sum of two times
 *
 * sum = a+b
 *
 * Note that it is acceptable for two or more of the arguments to point at the
 * same structure.
 */
extern void nstime_sum(nstime_t *sum, const nstime_t *b, const nstime_t *a );

/** calculate the difference between two times
 *
 * diff = a-b
 *
 * Note that it is acceptable for two or more of the arguments to point at the
 * same structure.
 */
extern void nstime_diff(nstime_t *diff, const nstime_t *b, const nstime_t *a );

/** sum += a */
#define nstime_add(sum, a) nstime_sum(sum, sum, a)

/** sum -= a */
#define nstime_subtract(sum, a) nstime_diff(sum, sum, a)

/** compare two times are return a value similar to memcmp() or strcmp().
 *
 * a > b : > 0
 * a = b : 0
 * a < b : < 0
 */
extern int nstime_cmp (const nstime_t *a, const nstime_t *b );

/** converts nstime to double, time base is milli seconds */
extern double nstime_to_msec(const nstime_t *nstime);

/** converts nstime to double, time base is seconds */
extern double nstime_to_sec(const nstime_t *nstime);

/** converts wtap_nstime to double, time base is seconds */
extern double wtap_nstime_to_sec(const struct wtap_nstime *nstime);

#endif /* __NSTIME_H__  */

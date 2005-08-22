/* nstime.h
 * Definition of data structure to hold time values with nanosecond resolution
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

typedef struct {
	time_t	secs;
	int	nsecs;
} nstime_t;

/* functions */

/* calculate the delta between two times
 *
 * delta = b-a
 *
 * Note that it is acceptable for two or more of the arguments to point at the
 * same structure.
 */
extern void get_timedelta(nstime_t *delta, const nstime_t *b, const nstime_t *a );

/* calculate the sum of two times
 *
 * sum = a+b
 *
 * Note that it is acceptable for two or more of the arguments to point at the
 * same structure.
 */
extern void get_timesum(nstime_t *sum, const nstime_t *b, const nstime_t *a );

/* sum += a */
#define addtime(sum, a) get_timesum(sum, sum, a)

/* converts nstime to double, time base is milli seconds*/
extern double nstime_to_msec(const nstime_t *time);

#endif /* __NSTIME_H__  */

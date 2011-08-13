/* nstime.c
 * Routines for manipulating nstime_t structures
 *
 * Copyright (c) 2005 MX Telecom Ltd. <richardv@mxtelecom.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#include <glib.h>
#include "nstime.h"

/* this is #defined so that we can clearly see that we have the right number of
   zeros, rather than as a guard against the number of nanoseconds in a second
   changing ;) */
#define NS_PER_S 1000000000

/* set the given nstime_t to zero */
void nstime_set_zero(nstime_t *nstime)
{
	nstime->secs  = 0;
	nstime->nsecs = 0;
}

/* is the given nstime_t currently zero? */
gboolean nstime_is_zero(nstime_t *nstime)
{
	if(nstime->secs == 0 && nstime->nsecs == 0) {
		return TRUE;
	} else {
		return FALSE;
	}
}

/* set the given nstime_t to (0,maxint) to mark it as "unset"
 * That way we can find the first frame even when a timestamp
 * is zero (fix for bug 1056)
 */
void nstime_set_unset(nstime_t *nstime)
{
	nstime->secs  = 0;
	nstime->nsecs = G_MAXINT;
}

/* is the given nstime_t currently (0,maxint)? */
gboolean nstime_is_unset(nstime_t *nstime)
{
	if(nstime->secs == 0 && nstime->nsecs == G_MAXINT) {
		return TRUE;
	} else {
		return FALSE;
	}
}


/** funcion: nstime_copy
 *
 * a = b
 */
void nstime_copy(nstime_t *a, const nstime_t *b)
{
	a->secs = b->secs;
	a->nsecs = b->nsecs;
}

/*
 * function: nstime_delta
 * delta = b - a
 */

void nstime_delta(nstime_t *delta, const nstime_t *b, const nstime_t *a )
{
    if (b->secs == a->secs) {
        /* The seconds part of b is the same as the seconds part of a, so if
           the nanoseconds part of the first time is less than the nanoseconds
           part of a, b is before a.  The nanoseconds part of the delta should
           just be the difference between the nanoseconds part of b and the
           nanoseconds part of a; don't adjust the seconds part of the delta,
           as it's OK if the nanoseconds part is negative, and an overflow
           can never result. */
        delta->secs = 0;
        delta->nsecs = b->nsecs - a->nsecs;
    } else if (b->secs <= a->secs) {
        /* The seconds part of b is less than the seconds part of a, so b is
           before a.

           Both the "seconds" and "nanoseconds" value of the delta
           should have the same sign, so if the difference between the
           nanoseconds values would be *positive*, subtract 1,000,000,000
           from it, and add one to the seconds value. */
        delta->secs = b->secs - a->secs;
        delta->nsecs = b->nsecs - a->nsecs;
        if(delta->nsecs > 0) {
            delta->nsecs -= NS_PER_S;
            delta->secs ++;
        }
    } else {
        delta->secs = b->secs - a->secs;
        delta->nsecs = b->nsecs - a->nsecs;
        if(delta->nsecs < 0) {
            delta->nsecs += NS_PER_S;
            delta->secs --;
        }
    }
}

/*
 * function: nstime_sum
 * sum = a + b
 */

void nstime_sum(nstime_t *sum, const nstime_t *a, const nstime_t *b)
{
    sum->secs = a->secs + b->secs;
    sum->nsecs = a->nsecs + b->nsecs;
    if(sum->nsecs>=NS_PER_S || (sum->nsecs>0 && sum->secs<0)){
        sum->nsecs-=NS_PER_S;
        sum->secs++;
    } else if(sum->nsecs<=-NS_PER_S || (sum->nsecs<0 && sum->secs>0)) {
        sum->nsecs+=NS_PER_S;
        sum->secs--;
    }
}

/*
 * function: nstime_diff
 * diff = a - b
 */

void nstime_diff(nstime_t *diff, const nstime_t *a, const nstime_t *b)
{
    diff->secs = a->secs - b->secs;
    diff->nsecs = a->nsecs - b->nsecs;
    if(diff->nsecs>=NS_PER_S || (diff->nsecs>0 && diff->secs<0)){
        diff->nsecs-=NS_PER_S;
        diff->secs++;
    } else if(diff->nsecs<=-NS_PER_S || (diff->nsecs<0 && diff->secs>0)) {
        diff->nsecs+=NS_PER_S;
        diff->secs--;
    }
}

/*
 * function: nstime_cmp
 *
 * a > b : > 0
 * a = b : 0
 * a < b : < 0
 */

int nstime_cmp (const nstime_t *a, const nstime_t *b )
{
    if (a->secs == b->secs) {
        return a->nsecs - b->nsecs;
    } else {
        return (int) (a->secs - b->secs);
    }
}

/*
 * function: nstime_to_msec
 * converts nstime to double, time base is milli seconds
 */

double nstime_to_msec(const nstime_t *nstime)
{
    return ((double)nstime->secs*1000 + (double)nstime->nsecs/1000000);
}

/*
 * function: nstime_to_sec
 * converts nstime to double, time base is seconds
 */

double nstime_to_sec(const nstime_t *nstime)
{
    return ((double)nstime->secs + (double)nstime->nsecs/1000000000);
}

/*
 * function: wtap_nstime_to_sec
 * converts wtap_nstime to double, time base is seconds
 */

double wtap_nstime_to_sec(const struct wtap_nstime *nstime)
{
    return ((double)nstime->secs + (double)nstime->nsecs/1000000000);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab
 * :indentSize=4:tabSize=8:noTabs=true:
 */


/* nstime.c
 * Routines for manipulating nstime_t structures
 *
 * Copyright (c) 2005 MX Telecom Ltd. <richardv@mxtelecom.com>
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
gboolean nstime_is_unset(const nstime_t *nstime)
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
    } else if (b->secs < a->secs) {
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
 * function: nstime_cmp
 *
 * a > b : > 0
 * a = b : 0
 * a < b : < 0
 */

int nstime_cmp (const nstime_t *a, const nstime_t *b )
{
    if (G_UNLIKELY(nstime_is_unset(a))) {
        if (G_UNLIKELY(nstime_is_unset(b))) {
            return 0;    /* "no time stamp" is "equal" to "no time stamp" */
        } else {
            return -1;   /* and is less than all time stamps */
        }
    } else {
        if (G_UNLIKELY(nstime_is_unset(b))) {
            return 1;
        }
    }
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
    return ((double)nstime->secs + (double)nstime->nsecs/NS_PER_S);
}

/*
 * This code is based on the Samba code:
 *
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  time handling functions
 *  Copyright (C) Andrew Tridgell 1992-1998
 */

/*
 * Number of seconds between the UN*X epoch (January 1, 1970, 00:00:00 GMT)
 * and the Windows NT epoch (January 1, 1601 in the proleptic Gregorian
 * calendar, 00:00:00 "GMT")
 *
 * This is
 *
 *     369*365.25*24*60*60-(3*24*60*60+6*60*60)
 *
 * 1970-1601 is 369; 365.25 is the average length of a year in days,
 * including leap years.
 *
 * 3 days are subtracted because 1700, 1800, and 1900 were not leap
 * years, as, while they're all evenly divisible by 4, they're also
 * evently divisible by 100, but not evently divisible by 400, so
 * we need to compensate for using the average length of a year in
 * days, which assumes a leap year every 4 years, *including* every
 * 100 years.
 *
 * I'm not sure what the extra 6 hours are that are being subtracted.
 */
#define TIME_FIXUP_CONSTANT G_GUINT64_CONSTANT(11644473600)

#ifndef TIME_T_MIN
#define TIME_T_MIN ((time_t) ((time_t)0 < (time_t) -1 ? (time_t) 0 \
                    : (time_t) (~0ULL << (sizeof (time_t) * CHAR_BIT - 1))))
#endif
#ifndef TIME_T_MAX
#define TIME_T_MAX ((time_t) (~ (time_t) 0 - TIME_T_MIN))
#endif

static gboolean
common_filetime_to_nstime(nstime_t *nstime, guint64 ftsecs, int nsecs)
{
    gint64 secs;

    /*
     * Shift the seconds from the Windows epoch to the UN*X epoch.
     * ftsecs's value should fit in a 64-bit signed variable, as
     * ftsecs is derived from a 64-bit fractions-of-a-second value,
     * and is far from the maximum 64-bit signed value, and
     * TIME_FIXUP_CONSTANT is also far from the maximum 64-bit
     * signed value, so the difference between them should also
     * fit in a 64-bit signed value.
     */
    secs = (gint64)ftsecs - TIME_FIXUP_CONSTANT;

    if (!(TIME_T_MIN <= secs && secs <= TIME_T_MAX)) {
        /* The result won't fit in a time_t */
        return FALSE;
    }

    /*
     * Get the time as seconds and nanoseconds.
     */
    nstime->secs = (time_t) secs;
    nstime->nsecs = nsecs;
    return TRUE;
}

/*
 * function: filetime_to_nstime
 * converts a Windows FILETIME value to an nstime_t
 * returns TRUE if the conversion succeeds, FALSE if it doesn't
 * (for example, with a 32-bit time_t, the time overflows or
 * underflows time_t)
 */
gboolean
filetime_to_nstime(nstime_t *nstime, guint64 filetime)
{
    guint64 ftsecs;
    int nsecs;

    /*
     * Split into seconds and tenths of microseconds, and
     * then convert tenths of microseconds to nanoseconds.
     */
    ftsecs = filetime / 10000000;
    nsecs = (int)((filetime % 10000000)*100);

    return common_filetime_to_nstime(nstime, ftsecs, nsecs);
}

/*
 * function: nsfiletime_to_nstime
 * converts a Windows FILETIME-like value, but given in nanoseconds
 * rather than 10ths of microseconds, to an nstime_t
 * returns TRUE if the conversion succeeds, FALSE if it doesn't
 * (for example, with a 32-bit time_t, the time overflows or
 * underflows time_t)
 */
gboolean
nsfiletime_to_nstime(nstime_t *nstime, guint64 nsfiletime)
{
    guint64 ftsecs;
    int nsecs;

    /* Split into seconds and nanoseconds. */
    ftsecs = nsfiletime / NS_PER_S;
    nsecs = (int)(nsfiletime % NS_PER_S);

    return common_filetime_to_nstime(nstime, ftsecs, nsecs);
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
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */

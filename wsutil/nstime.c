/* nstime.c
 * Routines for manipulating nstime_t structures
 *
 * Copyright (c) 2005 MX Telecom Ltd. <richardv@mxtelecom.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include "nstime.h"
#include "epochs.h"
#include "time_util.h"

#ifndef HAVE_STRPTIME
# include "wsutil/strptime.h"
#endif

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


/** function: nstime_copy
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
     * EPOCH_DELTA_1601_01_01_00_00_00_UTC is also far from the
     * maximum 64-bit signed value, so the difference between them
     * should also fit in a 64-bit signed value.
     */
    secs = (gint64)ftsecs - EPOCH_DELTA_1601_01_01_00_00_00_UTC;

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
 * function: iso8601_to_nstime
 * parses a character string for a date and time given in
 * ISO 8601 date-time format (eg: 2014-04-07T05:41:56.782+00:00)
 * and converts to an nstime_t
 * returns number of chars parsed on success, or 0 on failure
 *
 * NB. ISO 8601 is actually a lot more flexible than the above format,
 * much to a developer's chagrin. The -/T/: separators are technically
 * optional.
 * Code is here to allow for that, but short-circuited for now since
 * our callers assume they're there.
 *
 * Future improvements could parse other ISO 8601 formats, such as
 * YYYY-Www-D, YYYY-DDD, etc. For a relatively easy introduction to
 * these formats, see wikipedia: https://en.wikipedia.org/wiki/ISO_8601
 */
guint8
iso8601_to_nstime(nstime_t *nstime, const char *ptr)
{
    struct tm tm;
    gint n_scanned = 0;
    gint n_chars = 0;
    guint frac = 0;
    gint off_hr = 0;
    gint off_min = 0;
    guint8 ret_val = 0;
    const char *start = ptr;
    gboolean has_separator = FALSE;
    gboolean have_offset = FALSE;

    memset(&tm, 0, sizeof(tm));
    tm.tm_isdst = -1;
    nstime_set_unset(nstime);

    /* There may be 2 or 0 dashes between the date parts */
    has_separator = (*(ptr+4) == '-');

    /* For now we require the separator to remove ambiguity */
    if (!has_separator) return 0;

    /* Note: sscanf is known to be inconsistent across platforms with respect
       to whether a %n is counted as a return value or not, so we use '<'/'>='
     */
    n_scanned = sscanf(ptr, has_separator ? "%4u-%2u-%2u%n" : "%4u%2u%2u%n",
            &tm.tm_year,
            &tm.tm_mon,
            &tm.tm_mday,
            &n_chars);
    if (n_scanned >= 3) {
        /* Got year, month, and day */
        tm.tm_mon--; /* struct tm expects 0-based month */
        tm.tm_year -= 1900; /* struct tm expects number of years since 1900 */
        ptr += n_chars;
    }
    else {
        return 0;
    }

    if (*ptr == 'T' || *ptr == ' ') {
        /* The 'T' between date and time is optional if the meaning is
           unambiguous. We also allow for ' ' here to support formats
           such as editcap's -A/-B options */
        ptr++;
    }
    else {
        /* For now we require the separator to remove ambiguity;
           remove this entire 'else' when we wish to change that */
        return 0;
    }

    /* Now we're on to the time part. We'll require a minimum of hours and
       minutes.
       Test for a possible ':' */
    has_separator = (*(ptr+2) == ':');
    if (!has_separator) return 0;

    n_scanned = sscanf(ptr, has_separator ? "%2u:%2u%n" : "%2u%2u%n",
            &tm.tm_hour,
            &tm.tm_min,
            &n_chars);
    if (n_scanned >= 2) {
        ptr += n_chars;
    }
    else {
        /* didn't get hours and minutes */
        return 0;
    }

    /* Test for (whole) seconds */
    if ((has_separator && *ptr == ':') ||
            (!has_separator && g_ascii_isdigit(*ptr))) {
        /* Looks like we should have them */
        if (1 > sscanf(ptr, has_separator ? ":%2u%n" : "%2u%n",
                &tm.tm_sec, &n_chars)) {
            /* Couldn't get them */
            return 0;
        }
        ptr += n_chars;

        /* Now let's test for fractional seconds */
        if (*ptr == '.' || *ptr == ',') {
            /* Get fractional seconds */
            ptr++;
            if (1 <= sscanf(ptr, "%u%n", &frac, &n_chars)) {
                /* normalize frac to nanoseconds */
                if ((frac >= 1000000000) || (frac == 0)) {
                    frac = 0;
                } else {
                    switch (n_chars) { /* including leading zeros */
                        case 1: frac *= 100000000; break;
                        case 2: frac *= 10000000; break;
                        case 3: frac *= 1000000; break;
                        case 4: frac *= 100000; break;
                        case 5: frac *= 10000; break;
                        case 6: frac *= 1000; break;
                        case 7: frac *= 100; break;
                        case 8: frac *= 10; break;
                        default: break;
                    }
                }
                ptr += n_chars;
            }
            /* If we didn't get frac, it's still its default of 0 */
        }
    }
    else {
        tm.tm_sec = 0;
    }

    /* Validate what we got so far. mktime() doesn't care about strange
       values (and we use this to our advantage when calculating the
       time zone offset) but we should at least start with something valid */
    if (!tm_is_valid(&tm)) {
        return 0;
    }

    /* Check for a time zone offset */
    if (*ptr == '-' || *ptr == '+' || *ptr == 'Z') {
        /* We have a UTC-relative offset */
        if (*ptr == 'Z') {
            off_hr = off_min = n_scanned = 0;
            have_offset = TRUE;
            ptr++;
        }
        else {
            has_separator = (*(ptr+3) == ':');
            if (!has_separator) return 0;
            n_scanned = sscanf(ptr, has_separator ? "%3d:%2d%n" : "%3d%2d%n",
                    &off_hr,
                    &off_min,
                    &n_chars);
            if (n_scanned >= 1) {
                /* Definitely got hours */
                have_offset = TRUE;
                if (n_scanned >= 2) {
                    /* Got minutes too */
                    ptr += n_chars;
                }
                else {
                    /* Only got hours, just move ptr past the +hh or whatever */
                    off_min = 0;
                    ptr += 3;
                }
            }
            else {
                /* Didn't get a valid offset, treat as if there's none at all */
                off_hr = off_min = n_scanned = 0;
                have_offset = FALSE;
            }
        }
    }
    if (have_offset) {
        tm.tm_hour -= off_hr;
        tm.tm_min -= (off_hr < 0 ? -off_min : off_min);
        nstime->secs = mktime_utc(&tm);
    }
    else {
        /* No UTC offset given; ISO 8601 says this means localtime */
        nstime->secs = mktime(&tm);
    }
    nstime->nsecs = frac;
    ret_val = (guint)(ptr-start);
    return ret_val;
}

/*
 * function: unix_epoch_to_nstime
 * parses a character string for a date and time given in
 * a floating point number containing a Unix epoch date-time
 * format (e.g. 1600000000.000 for Sun Sep 13 05:26:40 AM PDT 2020)
 * and converts to an nstime_t
 * returns number of chars parsed on success, or 0 on failure
 *
 * Reference: https://en.wikipedia.org/wiki/Unix_time
 */
guint8
unix_epoch_to_nstime(nstime_t *nstime, const char *ptr)
{
    struct tm tm;
    char *ptr_new;

    gint n_chars = 0;
    guint frac = 0;
    guint8 ret_val = 0;
    const char *start = ptr;

    memset(&tm, 0, sizeof(tm));
    tm.tm_isdst = -1;
    nstime_set_unset(nstime);

    if (!(ptr_new=strptime(ptr, "%s", &tm))) {
        return 0;
    }

    /* No UTC offset given; ISO 8601 says this means localtime */
    nstime->secs = mktime(&tm);

    /* Now let's test for fractional seconds */
    if (*ptr_new == '.' || *ptr_new == ',') {
        /* Get fractional seconds */
        ptr_new++;
        if (1 <= sscanf(ptr_new, "%u%n", &frac, &n_chars)) {
            /* normalize frac to nanoseconds */
            if ((frac >= 1000000000) || (frac == 0)) {
                frac = 0;
            } else {
                switch (n_chars) { /* including leading zeros */
                    case 1: frac *= 100000000; break;
                    case 2: frac *= 10000000; break;
                    case 3: frac *= 1000000; break;
                    case 4: frac *= 100000; break;
                    case 5: frac *= 10000; break;
                    case 6: frac *= 1000; break;
                    case 7: frac *= 100; break;
                    case 8: frac *= 10; break;
                    default: break;
                }
            }
            ptr_new += n_chars;
        }
        /* If we didn't get frac, it's still its default of 0 */
    }
    else {
        tm.tm_sec = 0;
    }
    nstime->nsecs = frac;

    /* return pointer shift */
    ret_val = (guint)(ptr_new-start);
    return ret_val;
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

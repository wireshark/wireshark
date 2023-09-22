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

#include "nstime.h"

#include <stdio.h>
#include <string.h>
#include "epochs.h"
#include "time_util.h"
#include "to_str.h"
#include "strtoi.h"

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
bool nstime_is_zero(const nstime_t *nstime)
{
    return nstime->secs == 0 && nstime->nsecs == 0;
}

/* set the given nstime_t to (0,maxint) to mark it as "unset"
 * That way we can find the first frame even when a timestamp
 * is zero (fix for bug 1056)
 */
void nstime_set_unset(nstime_t *nstime)
{
    nstime->secs  = 0;
    nstime->nsecs = INT_MAX;
}

/* is the given nstime_t currently (0,maxint)? */
bool nstime_is_unset(const nstime_t *nstime)
{
    if(nstime->secs == 0 && nstime->nsecs == INT_MAX) {
        return true;
    } else {
        return false;
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

unsigned nstime_hash(const nstime_t *nstime)
{
    int64_t val1 = (int64_t)nstime->secs;

    return g_int64_hash(&val1) ^ g_int_hash(&nstime->nsecs);
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

static bool
common_filetime_to_nstime(nstime_t *nstime, uint64_t ftsecs, int nsecs)
{
    int64_t secs;

    /*
     * Shift the seconds from the Windows epoch to the UN*X epoch.
     * ftsecs's value should fit in a 64-bit signed variable, as
     * ftsecs is derived from a 64-bit fractions-of-a-second value,
     * and is far from the maximum 64-bit signed value, and
     * EPOCH_DELTA_1601_01_01_00_00_00_UTC is also far from the
     * maximum 64-bit signed value, so the difference between them
     * should also fit in a 64-bit signed value.
     */
    secs = (int64_t)ftsecs - EPOCH_DELTA_1601_01_01_00_00_00_UTC;

    if (!(TIME_T_MIN <= secs && secs <= TIME_T_MAX)) {
        /* The result won't fit in a time_t */
        return false;
    }

    /*
     * Get the time as seconds and nanoseconds.
     */
    nstime->secs = (time_t) secs;
    nstime->nsecs = nsecs;
    return true;
}

/*
 * function: filetime_to_nstime
 * converts a Windows FILETIME value to an nstime_t
 * returns true if the conversion succeeds, false if it doesn't
 * (for example, with a 32-bit time_t, the time overflows or
 * underflows time_t)
 */
bool
filetime_to_nstime(nstime_t *nstime, uint64_t filetime)
{
    uint64_t ftsecs;
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
 * returns true if the conversion succeeds, false if it doesn't
 * (for example, with a 32-bit time_t, the time overflows or
 * underflows time_t)
 */
bool
nsfiletime_to_nstime(nstime_t *nstime, uint64_t nsfiletime)
{
    uint64_t ftsecs;
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
 * returns pointer to the first character after the last character
 * parsed on success, or NULL on failure
 *
 * NB. ISO 8601 is actually a lot more flexible than the above format,
 * much to a developer's chagrin. The "basic format" is distinguished from
 * the "extended format" by lacking the - and : separators. This function
 * supports both the basic and extended format (as well as both simultaneously)
 * with several common options and extensions. Time resolution is supported
 * up to nanoseconds (9 fractional digits) or down to whole minutes (omitting
 * the seconds component in the latter case). The T separator can be replaced
 * by a space in either format (a common extension not in ISO 8601 but found
 * in, e.g., RFC 3339) or omitted entirely in the basic format.
 *
 * Many standards that use ISO 8601 implement profiles with additional
 * constraints, such as requiring that the seconds field be present, only
 * allowing "." as the decimal separator, or limiting the number of fractional
 * digits. Callers that wish to check constraints not yet enforced by a
 * profile supported by the function must do so themselves.
 *
 * Future improvements could parse other ISO 8601 formats, such as
 * YYYY-Www-D, YYYY-DDD, etc. For a relatively easy introduction to
 * these formats, see wikipedia: https://en.wikipedia.org/wiki/ISO_8601
 */
const char *
iso8601_to_nstime(nstime_t *nstime, const char *ptr, iso8601_fmt_e format)
{
    struct tm tm;
    int n_scanned = 0;
    int n_chars = 0;
    unsigned frac = 0;
    int off_hr = 0;
    int off_min = 0;
    char sign = '\0';
    bool has_separator = false;
    bool have_offset = false;

    memset(&tm, 0, sizeof(tm));
    tm.tm_isdst = -1;
    nstime_set_unset(nstime);

    /* Verify that we start with a four digit year and then look for the
     * separator. */
    for (n_scanned = 0; n_scanned < 4; n_scanned++) {
        if (!g_ascii_isdigit(*ptr)) {
            return NULL;
        }
        tm.tm_year *= 10;
        tm.tm_year += *ptr++ - '0';
    }
    if (*ptr == '-') {
        switch (format) {
            case ISO8601_DATETIME_BASIC:
                return NULL;

            case ISO8601_DATETIME:
            case ISO8601_DATETIME_AUTO:
            default:
                has_separator = true;
                ptr++;
        };
    } else if (g_ascii_isdigit(*ptr)) {
        switch (format) {
            case ISO8601_DATETIME:
                return NULL;

            case ISO8601_DATETIME_BASIC:
            case ISO8601_DATETIME_AUTO:
            default:
                has_separator = false;
        };
    } else {
        return NULL;
    }

    tm.tm_year -= 1900; /* struct tm expects number of years since 1900 */

    /* Note: sscanf is known to be inconsistent across platforms with respect
       to whether a %n is counted as a return value or not (XXX: Is this
       still true, despite the express comments of C99 §7.19.6.2 12?), so we
       use '<'/'>='
     */
    /* XXX: sscanf allows an optional sign indicator before each integer
     * converted (whether with %d or %u), so this will convert some bogus
     * strings. Either checking afterwards or doing the whole thing by hand
     * as with the year above is the only correct way. (strptime certainly
     * can't handle the basic format.)
     */
    n_scanned = sscanf(ptr, has_separator ? "%2u-%2u%n" : "%2u%2u%n",
            &tm.tm_mon,
            &tm.tm_mday,
            &n_chars);
    if (n_scanned >= 2) {
        /* Got year, month, and day */
        tm.tm_mon--; /* struct tm expects 0-based month */
        ptr += n_chars;
    }
    else {
        return NULL;
    }

    if (*ptr == 'T' || *ptr == ' ') {
        /* The 'T' between date and time is optional if the meaning is
           unambiguous. We also allow for ' ' here per RFC 3339 to support
           formats such as editcap's -A/-B options. */
        ptr++;
    }
    else if (has_separator) {
        /* Allow no separator between date and time iff we have no
           separator between units. (Some extended formats may negotiate
           no separator here, so this could be changed.) */
        return NULL;
    }

    /* Now we're on to the time part. We'll require a minimum of hours and
       minutes. */

    n_scanned = sscanf(ptr, has_separator ? "%2u:%2u%n" : "%2u%2u%n",
            &tm.tm_hour,
            &tm.tm_min,
            &n_chars);
    if (n_scanned >= 2) {
        ptr += n_chars;
    }
    else {
        /* didn't get hours and minutes */
        return NULL;
    }

    /* Test for (whole) seconds */
    if ((has_separator && *ptr == ':') ||
            (!has_separator && g_ascii_isdigit(*ptr))) {
        /* Looks like we should have them */
        if (1 > sscanf(ptr, has_separator ? ":%2u%n" : "%2u%n",
                &tm.tm_sec, &n_chars)) {
            /* Couldn't get them */
            return NULL;
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
        /* No seconds. ISO 8601 allows decimal fractions of a minute here,
         * but that's pretty rare in practice. Could be added later if needed.
         */
        tm.tm_sec = 0;
    }

    /* Validate what we got so far. mktime() doesn't care about strange
       values but we should at least start with something valid */
    if (!tm_is_valid(&tm)) {
        return NULL;
    }

    /* Check for a time zone offset */
    if (*ptr == '-' || *ptr == '+' || *ptr == 'Z') {
        /* Just in case somewhere decides to observe a timezone of -00:30 or
         * some such. */
        sign = *ptr;
        /* We have a UTC-relative offset */
        if (*ptr == 'Z') {
            off_hr = off_min = 0;
            have_offset = true;
            ptr++;
        }
        else {
            off_hr = off_min = 0;
            n_scanned = sscanf(ptr, "%3d%n", &off_hr, &n_chars);
            if (n_scanned >= 1) {
                /* Definitely got hours */
                have_offset = true;
                ptr += n_chars;
                n_scanned = sscanf(ptr, *ptr == ':' ? ":%2d%n" : "%2d%n", &off_min, &n_chars);
                if (n_scanned >= 1) {
                    /* Got minutes too */
                    ptr += n_chars;
                }
            }
            else {
                /* Didn't get a valid offset, treat as if there's none at all */
                have_offset = false;
            }
        }
    }
    if (have_offset) {
        nstime->secs = mktime_utc(&tm);
        if (sign == '+') {
            nstime->secs -= (off_hr * 3600) + (off_min * 60);
        } else if (sign == '-') {
            /* -00:00 is illegal according to ISO 8601, but RFC 3339 allows
             * it under a convention where -00:00 means "time in UTC is known,
             * local timezone is unknown." This has the same value as an
             * offset of Z or +00:00, but semantically implies that UTC is
             * not the preferred time zone, which is immaterial to us.
             */
            /* Add the time, but reverse the sign of off_hr, which includes
             * the negative sign.
             */
            nstime->secs += ((-off_hr) * 3600) + (off_min * 60);
        }
    }
    else {
        /* No UTC offset given; ISO 8601 says this means local time */
        nstime->secs = mktime(&tm);
    }
    nstime->nsecs = frac;
    return ptr;
}

/*
 * function: unix_epoch_to_nstime
 * parses a character string for a date and time given in
 * a floating point number containing a Unix epoch date-time
 * format (e.g. 1600000000.000 for Sun Sep 13 05:26:40 AM PDT 2020)
 * and converts to an nstime_t
 * returns pointer to the first character after the last character
 * parsed on success, or NULL on failure
 *
 * Reference: https://en.wikipedia.org/wiki/Unix_time
 */
const char *
unix_epoch_to_nstime(nstime_t *nstime, const char *ptr)
{
    int64_t secs;
    const char *ptr_new;

    int n_chars = 0;
    unsigned frac = 0;

    nstime_set_unset(nstime);

    /*
     * Extract the seconds as a 64-bit signed number, as time_t
     * might be 64-bit.
     */
    if (!ws_strtoi64(ptr, &ptr_new, &secs)) {
        return NULL;
    }

    /* For now, reject times before the Epoch. */
    if (secs < 0) {
        return NULL;
    }

    /* Make sure it fits. */
    nstime->secs = (time_t) secs;
    if (nstime->secs != secs) {
        return NULL;
    }

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
        frac = 0;
    }
    nstime->nsecs = frac;
    return ptr_new;
}

size_t nstime_to_iso8601(char *buf, size_t buf_size, const nstime_t *nstime)
{
    struct tm *tm;
#ifndef _WIN32
    struct tm tm_time;
#endif
    size_t len;

#ifdef _WIN32
    /*
     * Do not use gmtime_s(), as it will call and
     * exception handler if the time we're providing
     * is < 0, and that will, by default, exit.
     * ("Programmers not bothering to check return
     * values?  Try new Microsoft Visual Studio,
     * with Parameter Validation(R)!  Kill insufficiently
     * careful programs - *and* the processes running them -
     * fast!")
     *
     * We just want to report this as an unrepresentable
     * time.  It fills in a per-thread structure, which
     * is sufficiently thread-safe for our purposes.
     */
    tm = gmtime(&nstime->secs);
#else
    /*
     * Use gmtime_r(), because the Single UNIX Specification
     * does *not* guarantee that gmtime() is thread-safe.
     * Perhaps it is on all platforms on which we run, but
     * this way we don't have to check.
     */
    tm = gmtime_r(&nstime->secs, &tm_time);
#endif
    if (tm == NULL) {
        return 0;
    }

    /* Some platforms (MinGW-w64) do not support %F or %T. */
    /* Returns number of bytes, excluding terminaning null, placed in
     * buf, or zero if there is not enough space for the whole string. */
    len = strftime(buf, buf_size, "%Y-%m-%dT%H:%M:%S", tm);
    if (len == 0) {
        return 0;
    }
    ws_assert(len < buf_size);
    buf += len;
    buf_size -= len;
    len += snprintf(buf, buf_size, ".%09dZ", nstime->nsecs);
    return len;
}

void nstime_to_unix(char *buf, size_t buf_size, const nstime_t *nstime)
{
    display_signed_time(buf, buf_size, nstime, WS_TSPREC_NSEC);
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

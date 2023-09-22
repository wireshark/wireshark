/* nstime.h
 * Definition of data structure to hold time values with nanosecond resolution
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __NSTIME_H__
#define __NSTIME_H__

#include <wireshark.h>
#include <time.h>

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

/* Macros that expand to nstime_t initializers */

/* Initialize to zero */
#define NSTIME_INIT_ZERO {0, 0}

/* Initialize to unset */
#define NSTIME_INIT_UNSET {0, INT_MAX}

/* Initialize to a specified number of seconds and nanoseconds */
#define NSTIME_INIT_SECS_NSECS(secs, nsecs)	{secs, nsecs}

/* Initialize to a specified number of seconds and microseconds */
#define NSTIME_INIT_SECS_USECS(secs, usecs)	{secs, usecs*1000}

/* Initialize to a specified number of seconds and milliseconds */
#define NSTIME_INIT_SECS_MSECS(secs, msecs)	{secs, msecs*1000000}

/* Initialize to a specified number of seconds */
#define NSTIME_INIT_SECS(secs)			{secs, 0}

/* Initialize to the maximum possible value */
#define NSTIME_INIT_MAX	{sizeof(time_t) > sizeof(int) ? LONG_MAX : INT_MAX, INT_MAX}

/* functions */

/** set the given nstime_t to zero */
WS_DLL_PUBLIC void nstime_set_zero(nstime_t *nstime);

/** is the given nstime_t currently zero? */
WS_DLL_PUBLIC bool nstime_is_zero(const nstime_t *nstime);

/** set the given nstime_t to (0,maxint) to mark it as "unset"
 * That way we can find the first frame even when a timestamp
 * is zero (fix for bug 1056)
 */
WS_DLL_PUBLIC void nstime_set_unset(nstime_t *nstime);

/* is the given nstime_t currently (0,maxint)? */
WS_DLL_PUBLIC bool nstime_is_unset(const nstime_t *nstime);

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
WS_DLL_PUBLIC void nstime_sum(nstime_t *sum, const nstime_t *a, const nstime_t *b );

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

WS_DLL_PUBLIC unsigned nstime_hash(const nstime_t *nstime);

/** converts nstime to double, time base is milli seconds */
WS_DLL_PUBLIC double nstime_to_msec(const nstime_t *nstime);

/** converts nstime to double, time base is seconds */
WS_DLL_PUBLIC double nstime_to_sec(const nstime_t *nstime);

/** converts Windows FILETIME to nstime, returns true on success,
    false on failure */
WS_DLL_PUBLIC bool filetime_to_nstime(nstime_t *nstime, uint64_t filetime);

/** converts time like Windows FILETIME, but expressed in nanoseconds
    rather than tenths of microseconds, to nstime, returns true on success,
    false on failure */
WS_DLL_PUBLIC bool nsfiletime_to_nstime(nstime_t *nstime, uint64_t nsfiletime);

typedef enum {
    ISO8601_DATETIME,       /** e.g. 2014-07-04T12:34:56.789+00:00 */
    ISO8601_DATETIME_BASIC, /** ISO8601 Basic format, i.e. no - : separators */
    ISO8601_DATETIME_AUTO,  /** Autodetect the presence of separators */
} iso8601_fmt_e;

/** parse an ISO 8601 format datetime string to nstime, returns pointer
    to the first character after the last character, NULL on failure
    Note that nstime is set to unset in the case of failure */
WS_DLL_PUBLIC const char * iso8601_to_nstime(nstime_t *nstime, const char *ptr, iso8601_fmt_e format);

/** parse an Unix epoch timestamp format datetime string to nstime, returns
    pointer to the first character after the last character, NULL on failure
    Note that nstime is set to unset in the case of failure */
WS_DLL_PUBLIC const char * unix_epoch_to_nstime(nstime_t *nstime, const char *ptr);

#define NSTIME_ISO8601_BUFSIZE  sizeof("YYYY-MM-DDTHH:MM:SS.123456789Z")

WS_DLL_PUBLIC size_t nstime_to_iso8601(char *buf, size_t buf_size, const nstime_t *nstime);

/* 64 bit signed number plus nanosecond fractional part */
#define NSTIME_UNIX_BUFSIZE  (20+10+1)

WS_DLL_PUBLIC void nstime_to_unix(char *buf, size_t buf_size, const nstime_t *nstime);

/*
 * Timestamp precision values.
 *
 * The value is the number of digits of precision after the integral part.
 */
typedef enum {
    WS_TSPREC_SEC      = 0,
    WS_TSPREC_100_MSEC = 1,
    WS_TSPREC_10_MSEC  = 2,
    WS_TSPREC_MSEC     = 3,
    WS_TSPREC_100_USEC = 4,
    WS_TSPREC_10_USEC  = 5,
    WS_TSPREC_USEC     = 6,
    WS_TSPREC_100_NSEC = 7,
    WS_TSPREC_10_NSEC  = 8,
    WS_TSPREC_NSEC     = 9
} ws_tsprec_e;

/*
 * Maximum time stamp precision supported.
 * Note that going beyond nanosecond precision would require expanding
 * the fractional part of an nstime_t to 64 bits, and changing code
 * that currently only handles second to nanosecond precision.
 */
#define WS_TSPREC_MAX 9

/*
 * Total number of valid precision values.
 */
#define NUM_WS_TSPREC_VALS (WS_TSPREC_MAX + 1)

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __NSTIME_H__  */

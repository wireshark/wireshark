/* time_util.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_WSUTIL
#include "time_util.h"

#include <errno.h>

#include <wsutil/epochs.h>

#ifndef _WIN32
#include <sys/time.h>
#include <sys/resource.h>
#else
#include <windows.h>
#endif

/* Test if the given year is a leap year */
#define isleap(y) (((y) % 4) == 0 && (((y) % 100) != 0 || ((y) % 400) == 0))

/* converts a broken down date representation, relative to UTC,
 * to a timestamp; it uses timegm() if it's available.
 *
 * Returns -1 and sets errno to EINVAL on error; returns the timestamp
 * and sets errno to 0 on success.
 */
time_t
mktime_utc(struct tm *tm)
{
	time_t retval;
#ifndef HAVE_TIMEGM
	/*
	 * We don't have timegm(), so use code copied from Glib source
	 * gtimer.c.
	 */
	static const int days_before[] =
		{
			0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
		};

	int yr;

	if (tm->tm_mon < 0 || tm->tm_mon > 11) {
		errno = EINVAL;
		return (time_t) -1;
	}

	retval = (tm->tm_year - 70) * 365;

	/* count number of leap years */
	yr  = tm->tm_year + 1900;
	if (tm->tm_mon + 1 < 3 && isleap(yr))
		yr--;
	retval += (((yr / 4) - (yr / 100) + (yr / 400)) - 477); /* 477 = ((1970 / 4) - (1970 / 100) + (1970 / 400)) */

	retval += days_before[tm->tm_mon] + tm->tm_mday - 1;

	retval = ((((retval * 24) + tm->tm_hour) * 60) + tm->tm_min) * 60 + tm->tm_sec;

	/*
	 * Just in case somebody asked for 1969-12-31 23:59:59 UTC,
	 * which is one second before the Unix epoch.
	 */
	errno = 0;
	return retval;
#else
	retval = timegm(tm);
	/*
	 * If passed a struct tm for 2013-03-01 00:00:00, both
	 * macOS and FreeBSD timegm() return the epoch time
	 * value for 2013-03-01 00:00:00 UTC, but also set
	 * errno to EOVERFLOW.  This may be true of other
	 * implementations based on the tzcode reference
	 * impelementation of timegm().
	 *
	 * The macOS and FreeBSD documentation for timegm() neither
	 * commit to leaving errno alone nor commit to setting it
	 * to a particular value.
	 *
	 * Force errno to 0, and check for an error and set it to
	 * EINVAL iff we got an error.
	 */
	errno = 0;
	if (retval == (time_t)-1) {
		/*
		 * Did somebody ask for 1969-12-31 23:59:59 UTC,
		 * which is one second before the Unix epoch?
		 *
		 * If so, timegm() happened to return the correct
		 * timestamp (whether because it calculated it or
		 * because it failed in some fashion).
		 *
		 * If not, set errno to EINVAL.
		 */
		if (tm->tm_year != (1969 - 1900) ||
		    tm->tm_mon != (12 - 1) ||
		    tm->tm_mday != 31 ||
		    tm->tm_hour != 23 ||
		    tm->tm_min != 59 ||
		    tm->tm_sec != 59)
			errno = EINVAL;
	}
	return retval;
#endif /* !HAVE_TIMEGM */
}

/* Validate the values in a time_t
 * Currently checks tm_year, tm_mon, tm_mday, tm_hour, tm_min, and tm_sec;
 * disregards tm_wday, tm_yday, and tm_isdst.
 * Use this in situations where you wish to return an error rather than
 * normalizing invalid dates; otherwise you could specify, for example,
 * 2020-10-40 (to quote the macOS and probably *BSD manual
 * page for ctime()/localtime()/mktime()/etc., "October 40
 * is changed into November 9").
 */
bool
tm_is_valid(struct tm *tm)
{
	static const int8_t days_in_month[12] = {
		31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
	};

	if (tm->tm_mon < 0 || tm->tm_mon > 11) {
		return false;
	}
	if (tm->tm_mday < 0 || tm->tm_mday >
			((tm->tm_mon == 1 && isleap(tm->tm_year)) ? 29 : days_in_month[tm->tm_mon])) {
		return false;
	}
	if (tm->tm_hour < 0 || tm->tm_hour > 23) {
		return false;
	}
	/* XXX: ISO 8601 and others allow 24:00:00 for end of day, perhaps that
	 * one case should be allowed?
	 */
	if (tm->tm_min < 0 || tm->tm_min > 59) {
		return false;
	}
	if (tm->tm_sec < 0 || tm->tm_sec > 60) {
		/* 60, not 59, to account for leap seconds */
		return false;
	}
	return true;
}

void get_resource_usage(double *user_time, double *sys_time) {
#ifndef _WIN32
	struct rusage ru;

	getrusage(RUSAGE_SELF, &ru);

	*user_time = ru.ru_utime.tv_sec + (ru.ru_utime.tv_usec / 1000000.0);
	*sys_time = ru.ru_stime.tv_sec + (ru.ru_stime.tv_usec / 1000000.0);
#else /* _WIN32 */
	HANDLE h_proc = GetCurrentProcess();
	FILETIME cft, eft, kft, uft;
	ULARGE_INTEGER uli_time;

	GetProcessTimes(h_proc, &cft, &eft, &kft, &uft);

	uli_time.LowPart = uft.dwLowDateTime;
	uli_time.HighPart = uft.dwHighDateTime;
	*user_time = uli_time.QuadPart / 10000000.0;
	uli_time.LowPart = kft.dwLowDateTime;
	uli_time.HighPart = kft.dwHighDateTime;
	*sys_time = uli_time.QuadPart / 1000000000.0;
#endif /* _WIN32 */
}

static double last_user_time = 0.0;
static double last_sys_time = 0.0;

void log_resource_usage(bool reset_delta, const char *format, ...) {
	va_list ap;
	GString *log_str = g_string_new("");
	double user_time;
	double sys_time;

	get_resource_usage(&user_time, &sys_time);

	if (reset_delta || last_user_time == 0.0) {
		last_user_time = user_time;
		last_sys_time = sys_time;
	}

	g_string_append_printf(log_str, "user %.3f +%.3f sys %.3f +%.3f ",
		user_time, user_time - last_user_time,
		sys_time, sys_time - last_sys_time);

	va_start(ap, format);
	g_string_append_vprintf(log_str, format, ap);
	va_end(ap);

	ws_warning("%s", log_str->str);
	g_string_free(log_str, TRUE);

}

/* Copied from pcapio.c pcapng_write_interface_statistics_block()*/
uint64_t
create_timestamp(void) {
	uint64_t timestamp;
#ifdef _WIN32
	FILETIME now;
#else
	struct timeval now;
#endif

#ifdef _WIN32
	/*
	 * Current time, represented as 100-nanosecond intervals since
	 * January 1, 1601, 00:00:00 UTC.
	 *
	 * I think DWORD might be signed, so cast both parts of "now"
	 * to uint32_t so that the sign bit doesn't get treated specially.
	 *
	 * Windows 8 provides GetSystemTimePreciseAsFileTime which we
	 * might want to use instead.
	 */
	GetSystemTimeAsFileTime(&now);
	timestamp = (((uint64_t)(uint32_t)now.dwHighDateTime) << 32) +
				(uint32_t)now.dwLowDateTime;

	/*
	 * Convert to same thing but as 1-microsecond, i.e. 1000-nanosecond,
	 * intervals.
	 */
	timestamp /= 10;

	/*
	 * Subtract difference, in microseconds, between January 1, 1601
	 * 00:00:00 UTC and January 1, 1970, 00:00:00 UTC.
	 */
	timestamp -= EPOCH_DELTA_1601_01_01_00_00_00_UTC*1000000;
#else
	/*
	 * Current time, represented as seconds and microseconds since
	 * January 1, 1970, 00:00:00 UTC.
	 */
	gettimeofday(&now, NULL);

	/*
	 * Convert to delta in microseconds.
	 */
	timestamp = (uint64_t)(now.tv_sec) * 1000000 + (uint64_t)(now.tv_usec);
#endif
	return timestamp;
}

struct timespec *
ws_clock_get_realtime(struct timespec *ts)
{
#if defined(HAVE_CLOCK_GETTIME)
	if (clock_gettime(CLOCK_REALTIME, ts) == 0)
		return ts;
#elif defined(HAVE_TIMESPEC_GET)
	if (timespec_get(ts, TIME_UTC) == TIME_UTC)
		return ts;
#endif

#ifndef _WIN32
	/* Fall back on gettimeofday(). */
	struct timeval usectimenow;
	gettimeofday(&usectimenow, NULL);
	ts->tv_sec = usectimenow.tv_sec;
	ts->tv_nsec = usectimenow.tv_usec*1000;
	return ts;
#else
	/* Fall back on time(). */
	ts->tv_sec = time(NULL);
	ts->tv_nsec = 0;
	return ts;
#endif
}

struct tm *
ws_localtime_r(const time_t *timep, struct tm *result)
{
#if defined(HAVE_LOCALTIME_R)
	return localtime_r(timep, result);
#elif defined(_MSC_VER)
	errno_t err = localtime_s(result, timep);
	if (err == 0)
		return result;
	return NULL;
#else
	struct tm *aux = localtime(timep);
	if (aux == NULL)
		return NULL;
	*result = *aux;
	return result;
#endif
}

void ws_tzset(void)
{
#ifdef HAVE_TZSET
	tzset();
#endif
}

struct tm *
ws_gmtime_r(const time_t *timep, struct tm *result)
{
#if defined(HAVE_GMTIME_R)
	return gmtime_r(timep, result);
#elif defined(_MSC_VER)
	errno_t err = gmtime_s(result, timep);
	if (err == 0)
		return result;
	return NULL;
#else
	struct tm *aux = gmtime(timep);
	if (aux == NULL)
		return NULL;
	*result = *aux;
	return result;
#endif
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */

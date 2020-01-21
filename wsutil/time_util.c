/* time_util.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"

#include <glib.h>

#include <wsutil/epochs.h>

#include "time_util.h"

#ifndef _WIN32
#include <sys/time.h>
#include <sys/resource.h>
#else
#include <windows.h>
#endif

/* converts a broken down date representation, relative to UTC,
 * to a timestamp; it uses timegm() if it's available.
 * Copied from Glib source gtimer.c
 */
time_t
mktime_utc(struct tm *tm)
{
#ifndef HAVE_TIMEGM
	time_t retval;

	static const int days_before[] =
		{
			0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
		};

	int yr;

	if (tm->tm_mon < 0 || tm->tm_mon > 11)
		return (time_t) -1;

	retval = (tm->tm_year - 70) * 365;

	/* count number of leap years */
	yr  = tm->tm_year + 1900;
	if (tm->tm_mon + 1 < 3 && (yr % 4) == 0 && ((yr % 100) != 0 || (yr % 400) == 0))
		yr--;
	retval += (((yr / 4) - (yr / 100) + (yr / 400)) - 477); /* 477 = ((1970 / 4) - (1970 / 100) + (1970 / 400)) */

	retval += days_before[tm->tm_mon] + tm->tm_mday - 1;

	retval = ((((retval * 24) + tm->tm_hour) * 60) + tm->tm_min) * 60 + tm->tm_sec;

	return retval;
#else
	return timegm(tm);
#endif /* !HAVE_TIMEGM */
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

void log_resource_usage(gboolean reset_delta, const char *format, ...) {
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

	g_warning("%s", log_str->str);
	g_string_free(log_str, TRUE);

}

/* Copied from pcapio.c pcapng_write_interface_statistics_block()*/
guint64
create_timestamp(void) {
    guint64  timestamp;
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
     * to guint32 so that the sign bit doesn't get treated specially.
     *
     * Windows 8 provides GetSystemTimePreciseAsFileTime which we
     * might want to use instead.
     */
    GetSystemTimeAsFileTime(&now);
    timestamp = (((guint64)(guint32)now.dwHighDateTime) << 32) +
                (guint32)now.dwLowDateTime;

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
    timestamp = (guint64)(now.tv_sec) * 1000000 +
                (guint64)(now.tv_usec);
#endif
    return timestamp;
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

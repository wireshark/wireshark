/* time_util.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */


#include "config.h"

#include <glib.h>

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

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
